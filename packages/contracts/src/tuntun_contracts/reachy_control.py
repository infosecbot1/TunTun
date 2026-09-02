from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Final
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from tuntun_contracts.base import canonical_bytes
from tuntun_contracts.commitments import commit_private
from tuntun_contracts.events import EventEnvelope, SignedEventEnvelope

_CLOCK_SKEW: Final = timedelta(seconds=30)
_EMPTY_SIGNATURE_B64: Final = base64.b64encode(bytes(64)).decode("ascii")
_SHA256_HEX: Final = frozenset("0123456789abcdef")
_ED25519_KEY_ID_PATTERN: Final = re.compile(r"^ed25519:[a-z0-9][a-z0-9._-]{0,63}:v[1-9][0-9]{0,8}$")
_PAIRING_ID_PATTERN: Final = re.compile(r"^[A-Za-z0-9_.:-]{8,128}$")


def sign_envelope(
    private_key: Ed25519PrivateKey,
    signing_key_id: str,
    hmac_root: bytes,
    envelope: EventEnvelope,
) -> SignedEventEnvelope:
    _require_payload_commitment(envelope, hmac_root)
    signing_input = SignedEventEnvelope(
        envelope=envelope,
        signing_key_id=signing_key_id,
        signature_b64=_EMPTY_SIGNATURE_B64,
    ).signing_bytes()
    signature_b64 = base64.b64encode(private_key.sign(signing_input)).decode("ascii")
    return SignedEventEnvelope(
        envelope=envelope,
        signing_key_id=signing_key_id,
        signature_b64=signature_b64,
    )


def verify_envelope(
    public_key: Ed25519PublicKey,
    expected_signing_key_id: str,
    hmac_keys: Mapping[str, bytes],
    signed: SignedEventEnvelope,
    expected_household_id: UUID,
    expected_device_id: UUID,
    now: datetime,
) -> EventEnvelope:
    envelope = signed.envelope
    if (
        type(signed.signing_key_id) is not str
        or type(expected_signing_key_id) is not str
        or not hmac.compare_digest(signed.signing_key_id, expected_signing_key_id)
    ):
        raise ValueError("unknown or revoked signing key")
    if envelope.household_id != expected_household_id or envelope.device_id != expected_device_id:
        raise ValueError("event scope mismatch")

    normalized_now = _normalize_utc(now, "timestamp must be timezone-aware")
    normalized_occurred_at = _normalize_utc(
        envelope.occurred_at,
        "timestamp must be timezone-aware",
    )
    if not (normalized_now - _CLOCK_SKEW <= normalized_occurred_at <= normalized_now + _CLOCK_SKEW):
        raise ValueError("stale event timestamp")

    hmac_root = hmac_keys.get(envelope.payload_commitment.key_id)
    if hmac_root is None:
        raise ValueError("unknown or revoked HMAC key")
    _require_payload_commitment(envelope, hmac_root)
    _verify_signature(public_key, signed)
    return envelope


@dataclass(frozen=True, slots=True)
class PairingMaterial:
    """Runtime-only pairing binding metadata; not a registered serialized contract."""

    server_key_id: str
    server_public_key_sha256: str
    tls_key_id: str
    tls_key_generation: int
    signing_key_id: str
    signing_key_generation: int
    signing_public_key_sha256: str
    hmac_key_id: str
    hmac_key_generation: int
    hmac_key_sha256: str
    endpoint_generation: int
    certificate_generation: int
    server_key_generation: int
    trust_digest_generation: int
    household_ca_sha256: str
    server_leaf_sha256: str
    client_certificate_sha256: str

    def __post_init__(self) -> None:
        identifier_specs = (
            (self.server_key_id, _ED25519_KEY_ID_PATTERN),
            (self.signing_key_id, _ED25519_KEY_ID_PATTERN),
            (self.tls_key_id, _PAIRING_ID_PATTERN),
            (self.hmac_key_id, _PAIRING_ID_PATTERN),
        )
        identifiers = tuple(identifier for identifier, _pattern in identifier_specs)
        if any(type(identifier) is not str or not identifier for identifier in identifiers):
            raise ValueError("pairing identifiers must be non-empty strings")
        if any(pattern.fullmatch(identifier) is None for identifier, pattern in identifier_specs):
            raise ValueError("pairing identifiers must use closed grammar")
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("pairing identifiers must be distinct")
        for generation in (
            self.tls_key_generation,
            self.signing_key_generation,
            self.hmac_key_generation,
            self.endpoint_generation,
            self.certificate_generation,
            self.server_key_generation,
            self.trust_digest_generation,
        ):
            if type(generation) is not int or generation < 1:
                raise ValueError("pairing generations must be positive")
        for digest in (
            self.server_public_key_sha256,
            self.signing_public_key_sha256,
            self.hmac_key_sha256,
            self.household_ca_sha256,
            self.server_leaf_sha256,
            self.client_certificate_sha256,
        ):
            _require_sha256_hex(digest, "pairing digest must be lower-case SHA-256")


@dataclass(frozen=True, slots=True)
class HmacKeyEpoch:
    key_id: str
    generation: int
    sha256: str
    value: bytes = field(repr=False)
    active_from: datetime
    accept_until: datetime

    def __post_init__(self) -> None:
        if type(self.key_id) is not str or not self.key_id:
            raise ValueError("HMAC key id must be a non-empty string")
        if _PAIRING_ID_PATTERN.fullmatch(self.key_id) is None:
            raise ValueError("HMAC key id must use closed grammar")
        if type(self.generation) is not int or self.generation < 1:
            raise ValueError("HMAC key generation must be positive")
        _require_sha256_hex(self.sha256, "HMAC key digest must be lower-case SHA-256")
        _require_hmac_root(self.value)
        active_from = _normalize_utc(
            self.active_from,
            "HMAC key epoch bounds must be timezone-aware",
        )
        accept_until = _normalize_utc(
            self.accept_until,
            "HMAC key epoch bounds must be timezone-aware",
        )
        if accept_until < active_from:
            raise ValueError("HMAC key epoch accept_until before active_from")
        object.__setattr__(self, "active_from", active_from)
        object.__setattr__(self, "accept_until", accept_until)


class RotationKeyring:
    __slots__ = ("_epochs",)

    def __init__(self, epochs: Iterable[HmacKeyEpoch]) -> None:
        accepted_epochs: list[HmacKeyEpoch] = []
        seen_ids: set[str] = set()
        for epoch in epochs:
            if not isinstance(epoch, HmacKeyEpoch):
                raise TypeError("HMAC key epoch required")
            if epoch.key_id in seen_ids:
                raise ValueError("duplicate HMAC key epoch id")
            if not hmac.compare_digest(hashlib.sha256(epoch.value).hexdigest(), epoch.sha256):
                raise PermissionError("pairing_key_digest_mismatch")
            seen_ids.add(epoch.key_id)
            accepted_epochs.append(epoch)
        self._epochs = tuple(accepted_epochs)

    def accepted(self, now: datetime) -> dict[str, bytes]:
        normalized_now = _normalize_utc(now, "timestamp must be timezone-aware")
        return {
            epoch.key_id: epoch.value
            for epoch in self._epochs
            if epoch.active_from <= normalized_now <= epoch.accept_until
        }


def _require_payload_commitment(envelope: EventEnvelope, hmac_root: bytes) -> None:
    root = _require_hmac_root(hmac_root)
    expected = commit_private(
        root,
        envelope.payload_commitment.key_id,
        envelope.event_type.value,
        canonical_bytes(envelope.payload),
    )
    if not hmac.compare_digest(expected.value_b64, envelope.payload_commitment.value_b64):
        raise ValueError("invalid payload commitment")


def _require_hmac_root(value: bytes) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise ValueError("HMAC root must be 32 bytes")
    return value


def _require_sha256_hex(value: str, message: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in _SHA256_HEX for character in value)
    ):
        raise ValueError(message)


def _normalize_utc(value: datetime, message: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(message)
    return value.astimezone(UTC)


def _verify_signature(
    public_key: Ed25519PublicKey,
    signed: SignedEventEnvelope,
) -> None:
    try:
        signature = base64.b64decode(signed.signature_b64, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("invalid envelope signature") from error
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != signed.signature_b64:
        raise ValueError("invalid envelope signature")
    try:
        public_key.verify(signature, signed.signing_bytes())
    except (InvalidSignature, TypeError, ValueError) as error:
        raise ValueError("invalid envelope signature") from error


__all__ = (
    "HmacKeyEpoch",
    "PairingMaterial",
    "RotationKeyring",
    "sign_envelope",
    "verify_envelope",
)
