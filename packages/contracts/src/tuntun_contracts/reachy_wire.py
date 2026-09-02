from __future__ import annotations

import base64
import binascii
import hmac
from typing import Annotated, Final, Literal
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from pydantic import Field, field_validator

from tuntun_contracts.base import (
    JCS_MAX_SAFE_INTEGER,
    Commitment,
    ContractModel,
    canonical_bytes,
    canonical_mapping_bytes,
    validate_canonical_base64,
)
from tuntun_contracts.commitments import commit_private

MAX_CONTROL_PAYLOAD_BYTES: Final = 131_072
MAX_CONTROL_PAYLOAD_B64_BYTES: Final = ((MAX_CONTROL_PAYLOAD_BYTES + 2) // 3) * 4
MAX_CONTROL_FRAME_JSON_BYTES: Final = 196_608
_EMPTY_SIGNATURE_B64: Final = base64.b64encode(bytes(64)).decode("ascii")
_ED25519_KEY_ID_PATTERN: Final = r"^ed25519:[a-z0-9][a-z0-9._-]{0,63}:v[1-9][0-9]{0,8}$"

Direction = Literal["edge_to_core", "core_to_edge"]
FrameKind = Literal["request", "response", "event"]
FramePurpose = Literal[
    "reachy.command.v1",
    "reachy.health.v1",
    "reachy.stop_all.v1",
    "reachy.camera_grant.v1",
    "reachy.event.v1",
    "reachy.media_control.v1",
]


class DeviceChallengeV1(ContractModel):
    schema_version: Literal["tuntun.reachy-device-challenge.v1"]
    challenge_b64: str
    server_nonce_b64: str
    endpoint_generation: Annotated[int, Field(ge=1, le=JCS_MAX_SAFE_INTEGER)]

    @field_validator("challenge_b64", "server_nonce_b64")
    @classmethod
    def canonical_nonce(cls, value: str) -> str:
        return validate_canonical_base64(value, expected_bytes=32, label="device challenge nonce")


class DeviceProofV1(ContractModel):
    schema_version: Literal["tuntun.reachy-device-proof.v1"]
    client_nonce_b64: str
    signature_b64: Annotated[
        str,
        Field(
            min_length=88,
            max_length=88,
            pattern=r"^[A-Za-z0-9+/]{86}==$",
        ),
    ]

    @field_validator("client_nonce_b64")
    @classmethod
    def canonical_client_nonce(cls, value: str) -> str:
        return validate_canonical_base64(value, expected_bytes=32, label="device proof nonce")

    @field_validator("signature_b64")
    @classmethod
    def canonical_signature(cls, value: str) -> str:
        return validate_canonical_base64(value, expected_bytes=64, label="device proof signature")


class ChallengeAcceptedV1(ContractModel):
    schema_version: Literal["tuntun.reachy-challenge-accepted.v1"]
    connection_nonce_b64: str

    @field_validator("connection_nonce_b64")
    @classmethod
    def canonical_connection_nonce(cls, value: str) -> str:
        return validate_canonical_base64(value, expected_bytes=32, label="connection nonce")


class ControlFrameV1(ContractModel):
    schema_version: Literal["tuntun.reachy-control-frame.v1"]
    direction: Direction
    kind: FrameKind
    connection_nonce_b64: str
    sequence: Annotated[int, Field(ge=1, le=JCS_MAX_SAFE_INTEGER)]
    correlation_id: UUID
    purpose: FramePurpose
    payload_b64: Annotated[str, Field(max_length=MAX_CONTROL_PAYLOAD_B64_BYTES)]

    @field_validator("connection_nonce_b64")
    @classmethod
    def canonical_frame_nonce(cls, value: str) -> str:
        return validate_canonical_base64(value, expected_bytes=32, label="connection nonce")

    @field_validator("payload_b64")
    @classmethod
    def canonical_payload(cls, value: str) -> str:
        _decode_base64_canonical_bounded(
            value,
            max_bytes=MAX_CONTROL_PAYLOAD_BYTES,
            label="control frame payload",
        )
        return value


class SignedControlFrameV1(ControlFrameV1):
    payload_commitment: Commitment
    signing_key_id: Annotated[
        str,
        Field(min_length=12, max_length=83, pattern=_ED25519_KEY_ID_PATTERN),
    ]
    signature_b64: Annotated[
        str,
        Field(
            min_length=88,
            max_length=88,
            pattern=r"^[A-Za-z0-9+/]{86}==$",
        ),
    ]

    @field_validator("signature_b64")
    @classmethod
    def canonical_frame_signature(cls, value: str) -> str:
        return validate_canonical_base64(value, expected_bytes=64, label="control frame signature")


def sign_control_frame(
    private_key: Ed25519PrivateKey,
    hmac_root: bytes,
    *,
    signing_key_id: str,
    hmac_key_id: str,
    direction: Direction,
    kind: FrameKind,
    connection_nonce: bytes,
    sequence: int,
    correlation_id: UUID,
    purpose: FramePurpose,
    payload: bytes,
) -> SignedControlFrameV1:
    signer = _trusted_private_key(private_key)
    trusted_hmac_root = _trusted_hmac_root(hmac_root)
    if type(connection_nonce) is not bytes or len(connection_nonce) != 32:
        raise ValueError("connection nonce must be 32 bytes")
    if type(payload) is not bytes:
        raise TypeError("control frame payload must be bytes")
    if len(payload) > MAX_CONTROL_PAYLOAD_BYTES:
        raise ValueError("control frame payload too large")
    body = ControlFrameV1(
        schema_version="tuntun.reachy-control-frame.v1",
        direction=direction,
        kind=kind,
        connection_nonce_b64=base64.b64encode(bytes(connection_nonce)).decode("ascii"),
        sequence=sequence,
        correlation_id=correlation_id,
        purpose=purpose,
        payload_b64=base64.b64encode(payload).decode("ascii"),
    )
    commitment = _payload_commitment(trusted_hmac_root, hmac_key_id, body)
    unsigned = SignedControlFrameV1(
        **body.model_dump(mode="python"),
        payload_commitment=commitment,
        signing_key_id=signing_key_id,
        signature_b64=_EMPTY_SIGNATURE_B64,
    )
    signature = signer.sign(_signature_bytes(unsigned))
    return unsigned.model_copy(
        update={"signature_b64": base64.b64encode(signature).decode("ascii")}
    )


def authenticate_control_frame(
    public_key: Ed25519PublicKey,
    hmac_root: bytes,
    frame: SignedControlFrameV1,
    *,
    expected_signing_key_id: str,
    expected_hmac_key_id: str,
    expected_direction: Direction,
    expected_nonce: bytes,
) -> None:
    verifier = _trusted_public_key(public_key)
    trusted_hmac_root = _trusted_hmac_root(hmac_root)
    trusted_frame = _require_exact_signed_frame(frame)
    if type(expected_nonce) is not bytes or len(expected_nonce) != 32:
        raise ValueError("expected connection nonce must be 32 bytes")
    expected_nonce_b64 = base64.b64encode(bytes(expected_nonce)).decode("ascii")
    if (
        type(expected_signing_key_id) is not str
        or not hmac.compare_digest(trusted_frame.signing_key_id, expected_signing_key_id)
        or type(expected_hmac_key_id) is not str
        or not hmac.compare_digest(trusted_frame.payload_commitment.key_id, expected_hmac_key_id)
    ):
        raise PermissionError("control_frame_key_binding_invalid")
    if trusted_frame.direction != expected_direction or not hmac.compare_digest(
        trusted_frame.connection_nonce_b64, expected_nonce_b64
    ):
        raise PermissionError("control_frame_session_binding_invalid")

    body = _control_body(trusted_frame)
    expected_commitment = _payload_commitment(
        trusted_hmac_root,
        trusted_frame.payload_commitment.key_id,
        body,
    )
    if (
        trusted_frame.payload_commitment.algorithm != expected_commitment.algorithm
        or not hmac.compare_digest(
            trusted_frame.payload_commitment.value_b64,
            expected_commitment.value_b64,
        )
    ):
        raise PermissionError("control_frame_commitment_invalid")
    _verify_signature(verifier, trusted_frame)


def decode_control_payload(frame: SignedControlFrameV1) -> bytes:
    trusted_frame = _require_exact_signed_frame(frame)
    return _decode_base64_canonical_bounded(
        trusted_frame.payload_b64,
        max_bytes=MAX_CONTROL_PAYLOAD_BYTES,
        label="control frame payload",
    )


def verify_control_frame(
    public_key: Ed25519PublicKey,
    hmac_root: bytes,
    frame: SignedControlFrameV1,
    *,
    expected_signing_key_id: str,
    expected_hmac_key_id: str,
    expected_direction: Direction,
    expected_nonce: bytes,
) -> bytes:
    authenticate_control_frame(
        public_key,
        hmac_root,
        frame,
        expected_signing_key_id=expected_signing_key_id,
        expected_hmac_key_id=expected_hmac_key_id,
        expected_direction=expected_direction,
        expected_nonce=expected_nonce,
    )
    return decode_control_payload(frame)


def _payload_commitment(
    hmac_root: bytes,
    hmac_key_id: str,
    body: ControlFrameV1,
) -> Commitment:
    return commit_private(
        hmac_root,
        hmac_key_id,
        f"reachy.frame.{body.direction}.{body.kind}.{body.purpose}",
        canonical_bytes(body),
    )


def _signature_bytes(frame: SignedControlFrameV1) -> bytes:
    _require_exact_signed_frame(frame)
    return canonical_mapping_bytes(frame.model_dump(mode="python", exclude={"signature_b64"}))


def _control_body(frame: SignedControlFrameV1) -> ControlFrameV1:
    return ControlFrameV1.model_validate(
        frame.model_dump(
            mode="python",
            exclude={"payload_commitment", "signing_key_id", "signature_b64"},
        )
    )


def _verify_signature(public_key: Ed25519PublicKey, frame: SignedControlFrameV1) -> None:
    try:
        signature = _decode_base64_canonical_bounded(
            frame.signature_b64,
            max_bytes=64,
            label="control frame signature",
            expected_bytes=64,
        )
        public_key.verify(signature, _signature_bytes(frame))
    except (InvalidSignature, TypeError, ValueError) as error:
        raise PermissionError("control_frame_signature_invalid") from error


def _decode_base64_canonical_bounded(
    value: str,
    *,
    max_bytes: int,
    label: str,
    expected_bytes: int | None = None,
) -> bytes:
    if type(value) is not str:
        raise TypeError(f"{label} must be a string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError(f"{label} must be canonical base64") from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"{label} must be canonical base64")
    if expected_bytes is not None and len(decoded) != expected_bytes:
        raise ValueError(f"{label} must encode exactly {expected_bytes} bytes")
    if len(decoded) > max_bytes:
        raise ValueError(f"{label} too large")
    return decoded


def _trusted_hmac_root(value: bytes) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise ValueError("HMAC root must be 32 bytes")
    return bytes(value)


def _trusted_private_key(private_key: object) -> Ed25519PrivateKey:
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("Ed25519 private key required")
    try:
        raw_private_key = private_key.private_bytes(
            Encoding.Raw,
            PrivateFormat.Raw,
            NoEncryption(),
        )
        if type(raw_private_key) is not bytes or len(raw_private_key) != 32:
            raise ValueError
        return Ed25519PrivateKey.from_private_bytes(raw_private_key)
    except Exception:
        raise ValueError("invalid Ed25519 private key") from None


def _trusted_public_key(public_key: object) -> Ed25519PublicKey:
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("Ed25519 public key required")
    try:
        raw_public_key = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        if type(raw_public_key) is not bytes or len(raw_public_key) != 32:
            raise ValueError
        return Ed25519PublicKey.from_public_bytes(raw_public_key)
    except Exception:
        raise ValueError("invalid Ed25519 public key") from None


def _require_exact_signed_frame(frame: SignedControlFrameV1) -> SignedControlFrameV1:
    if type(frame) is not SignedControlFrameV1:
        raise TypeError("exact SignedControlFrameV1 required")
    return frame


__all__ = (
    "ChallengeAcceptedV1",
    "ControlFrameV1",
    "DeviceChallengeV1",
    "DeviceProofV1",
    "Direction",
    "FrameKind",
    "FramePurpose",
    "MAX_CONTROL_FRAME_JSON_BYTES",
    "MAX_CONTROL_PAYLOAD_BYTES",
    "SignedControlFrameV1",
    "authenticate_control_frame",
    "decode_control_payload",
    "sign_control_frame",
    "verify_control_frame",
)
