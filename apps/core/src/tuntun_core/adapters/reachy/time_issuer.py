from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from tuntun_contracts.reachy_time import CoreTimeProofV1


class AuthorityHealth(Protocol):
    @property
    def generation(self) -> int: ...


class CoreTimeAuthority(Protocol):
    async def require_synchronized_no_step(self) -> AuthorityHealth: ...


class CoreTimeSequenceStore(Protocol):
    async def reserve_next(
        self,
        endpoint_generation: int,
        authority_health_generation: int,
        client_certificate_sha256: str,
        signing_key_id: str,
    ) -> int: ...


class CoreTimeEndpoint(Protocol):
    @property
    def generation(self) -> int: ...

    @property
    def client_certificate_sha256(self) -> str: ...

    @property
    def server_key_id(self) -> str: ...

    @property
    def server_public_key_sha256(self) -> str: ...


class Clock(Protocol):
    def now(self) -> datetime: ...


@dataclass(frozen=True, slots=True)
class _EndpointSnapshot:
    generation: int
    client_certificate_sha256: str
    server_key_id: str
    server_public_key_sha256: str


class CoreTimeProofIssuer:
    """Issue one signed, nonce-bound Core time proof for the isolated bootstrap route."""

    def __init__(
        self,
        *,
        authority: CoreTimeAuthority,
        sequences: CoreTimeSequenceStore,
        signer: Ed25519PrivateKey,
        endpoint: CoreTimeEndpoint,
        clock: Clock,
    ) -> None:
        self._authority = authority
        self._sequences = sequences
        self._endpoint = endpoint
        self._clock = clock
        self._endpoint_snapshot = self._capture_endpoint()
        self._signer = self._snapshot_signer(signer)
        self._require_current_server_signer()

    async def issue(
        self,
        nonce: bytes,
        *,
        client_certificate_sha256: str,
    ) -> CoreTimeProofV1:
        if type(nonce) is not bytes or len(nonce) != 32:
            raise ValueError("secure_time_nonce_size")
        endpoint = self._require_unchanged_endpoint()
        expected_client = endpoint.client_certificate_sha256
        observed_client = self._require_sha256(
            client_certificate_sha256,
            "secure_time_client_certificate_sha256_invalid",
        )
        if not hmac.compare_digest(observed_client, expected_client):
            raise PermissionError("secure_time_client_certificate_binding")

        health = await self._authority.require_synchronized_no_step()
        self._require_unchanged_endpoint()
        authority_generation = self._positive_int(
            getattr(health, "generation", None),
            "secure_time_authority_generation_invalid",
        )
        sequence = self._positive_int(
            await self._sequences.reserve_next(
                endpoint.generation,
                authority_generation,
                observed_client,
                endpoint.server_key_id,
            ),
            "secure_time_sequence_invalid",
        )
        self._require_unchanged_endpoint()
        core_utc = self._normalize_utc(self._clock.now())
        self._require_unchanged_endpoint()
        unsigned = CoreTimeProofV1(
            schema_version="tuntun.core-time-proof.v1",
            endpoint_generation=endpoint.generation,
            time_sequence=sequence,
            request_nonce_b64=base64.b64encode(nonce).decode("ascii"),
            core_utc=core_utc,
            authority_health_generation=authority_generation,
            signing_key_id=endpoint.server_key_id,
            signature_b64=base64.b64encode(bytes(64)).decode("ascii"),
        )
        self._require_unchanged_endpoint()
        signature = self._signer.sign(unsigned.signing_payload())
        self._require_unchanged_endpoint()
        return unsigned.model_copy(
            update={"signature_b64": base64.b64encode(signature).decode("ascii")}
        )

    def _require_current_server_signer(self) -> None:
        raw_public = self._signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        observed = hashlib.sha256(raw_public).hexdigest()
        expected = self._endpoint_snapshot.server_public_key_sha256
        if not hmac.compare_digest(observed, expected):
            raise PermissionError("secure_time_server_signer_binding")

    def _capture_endpoint(self) -> _EndpointSnapshot:
        return _EndpointSnapshot(
            generation=self._positive_int(
                self._endpoint.generation,
                "secure_time_endpoint_generation_invalid",
            ),
            client_certificate_sha256=self._require_sha256(
                self._endpoint.client_certificate_sha256,
                "secure_time_endpoint_client_certificate_sha256_invalid",
            ),
            server_key_id=self._require_key_id(self._endpoint.server_key_id),
            server_public_key_sha256=self._require_sha256(
                self._endpoint.server_public_key_sha256,
                "secure_time_endpoint_server_public_key_sha256_invalid",
            ),
        )

    def _require_unchanged_endpoint(self) -> _EndpointSnapshot:
        current = self._capture_endpoint()
        if current != self._endpoint_snapshot:
            raise PermissionError("secure_time_endpoint_changed")
        return current

    @staticmethod
    def _snapshot_signer(value: object) -> Ed25519PrivateKey:
        if not isinstance(value, Ed25519PrivateKey):
            raise TypeError("secure_time_ed25519_signer_required")
        try:
            raw_private = value.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        except (TypeError, ValueError) as error:
            raise TypeError("secure_time_ed25519_signer_required") from error
        if type(raw_private) is not bytes or len(raw_private) != 32:
            raise TypeError("secure_time_ed25519_signer_required")
        return Ed25519PrivateKey.from_private_bytes(raw_private)

    @staticmethod
    def _require_sha256(value: object, error: str) -> str:
        if (
            type(value) is not str
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError(error)
        return value

    @staticmethod
    def _require_key_id(value: object) -> str:
        if type(value) is not str or not value:
            raise ValueError("secure_time_server_key_id_invalid")
        return value

    @staticmethod
    def _positive_int(value: object, error: str) -> int:
        if type(value) is not int or value < 1:
            raise ValueError(error)
        return value

    @staticmethod
    def _normalize_utc(value: datetime) -> datetime:
        if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("secure_time_clock_utc_required")
        return value.astimezone(UTC)


__all__ = ("CoreTimeProofIssuer",)
