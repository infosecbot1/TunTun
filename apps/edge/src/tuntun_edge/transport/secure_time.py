from __future__ import annotations

import base64
import binascii
import contextlib
import errno
import fcntl
import hashlib
import hmac
import os
import re
import stat
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import Annotated, Final, Literal, Protocol, Self
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import AwareDatetime, Field, field_validator
from tuntun_contracts.base import ContractModel, canonical_bytes, parse_contract_json
from tuntun_contracts.reachy_time import CoreTimeProofV1, CoreTimeRequestV1

MAX_SECURE_TIME_STATE_BYTES: Final = 16_384
MAX_CORE_TIME_PROOF_BYTES: Final = 8_192
MAX_CANONICAL_PROOF_B64_LENGTH: Final = ((MAX_CORE_TIME_PROOF_BYTES + 2) // 3) * 4
SECURE_TIME_BOOT_DEADLINE_SECONDS: Final = 2.0
SECURE_TIME_STATE_NAME: Final = "secure-time-state.json"
SECURE_TIME_LOCK_NAME: Final = ".secure-time-state.lock"
SECURE_TIME_PUBLISH_FAULT_STAGES: Final = (
    "before_temp_open",
    "after_temp_open",
    "after_temp_write",
    "after_file_fsync",
    "before_parent_fsync",
    "after_parent_fsync_before_replace",
    "after_replace_before_parent_fsync",
    "after_parent_fsync",
    "after_final_verify",
)

_CLOEXEC: Final = getattr(os, "O_CLOEXEC", 0)
_NOFOLLOW: Final = getattr(os, "O_NOFOLLOW", 0)
_NONBLOCK: Final = getattr(os, "O_NONBLOCK", 0)
_DIRECTORY: Final = getattr(os, "O_DIRECTORY", 0)
_READ_FLAGS: Final = os.O_RDONLY | _CLOEXEC | _NOFOLLOW | _NONBLOCK
_DIRECTORY_FLAGS: Final = os.O_RDONLY | _DIRECTORY | _CLOEXEC | _NOFOLLOW
_LOCK_FLAGS: Final = os.O_RDWR | os.O_CREAT | _CLOEXEC | _NOFOLLOW
_WRITE_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _CLOEXEC | _NOFOLLOW
_READ_CHUNK_BYTES: Final = 64
_HEX_SHA256_PATTERN: Final = re.compile(r"^[a-f0-9]{64}$")
_IPV4_OCTET_PATTERN: Final = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])"
_CANONICAL_RFC1918_IPV4_PATTERN: Final = re.compile(
    "^("
    rf"10[.]{_IPV4_OCTET_PATTERN}[.]{_IPV4_OCTET_PATTERN}[.]{_IPV4_OCTET_PATTERN}"
    rf"|172[.](?:1[6-9]|2[0-9]|3[0-1])[.]{_IPV4_OCTET_PATTERN}"
    rf"[.]{_IPV4_OCTET_PATTERN}"
    rf"|192[.]168[.]{_IPV4_OCTET_PATTERN}[.]{_IPV4_OCTET_PATTERN}"
    ")$"
)
_SIGNING_KEY_ID_PATTERN: Final = re.compile(r"^ed25519:[a-z0-9][a-z0-9._-]{0,63}:v[1-9][0-9]{0,8}$")
_UTC_DATETIME_SCHEMA_EXTRA: Final = {
    "x-tuntun-field-safety": {
        "canonical_serialization_offset": "Z",
        "constraint": "utc-offset-zero-datetime",
        "required_utc_offset_seconds": 0,
        "runtime_authoritative": True,
    }
}
_MAX_SIGNED_FORWARD_STEP: Final = timedelta(days=31)
_MAX_AUTHORITY_GENERATION_FORWARD_STEP: Final = 1
_ROLLBACK_SKEW_TOLERANCE: Final = timedelta(seconds=0)

Monotonic = Callable[[], float]
SecureTimeBootMode = Literal["qualified_rtc", "signed_core_bootstrap"]


class SecureTimeEndpoint(Protocol):
    @property
    def generation(self) -> int: ...

    @property
    def trust_digest_generation(self) -> int: ...

    @property
    def core_ipv4(self) -> str: ...

    @property
    def port(self) -> int: ...

    @property
    def server_leaf_sha256(self) -> str: ...

    @property
    def server_key_id(self) -> str: ...

    @property
    def server_public_key_sha256(self) -> str: ...


class SecureTimeCapabilityReport(Protocol):
    @property
    def source(self) -> Literal["synthetic", "hardware"]: ...

    @property
    def rtc_available(self) -> bool: ...

    @property
    def rtc_cold_boot_retains_utc(self) -> bool: ...

    @property
    def rtc_max_drift_seconds_30d(self) -> float | None: ...

    @property
    def rtc_qualified(self) -> bool: ...


class SecureTimeRouteNeighborVerifier(Protocol):
    def require_current_route_neighbor(
        self,
        endpoint: SecureTimeEndpoint,
        *,
        deadline_monotonic: float,
    ) -> None: ...


class SecureTimeLeafVerifier(Protocol):
    def require_ed25519_public_key(
        self,
        server_leaf_der: bytes,
        *,
        endpoint: SecureTimeEndpoint,
        deadline_monotonic: float,
    ) -> bytes: ...

    def require_time_within_commissioned_leafs(
        self,
        value: datetime,
        *,
        endpoint: SecureTimeEndpoint,
        server_leaf_der: bytes,
        deadline_monotonic: float,
    ) -> None: ...


class SecureTimeBootstrapChannel(Protocol):
    async def request_time(
        self,
        request_canonical_json: bytes,
        *,
        deadline_monotonic: float,
    ) -> bytes: ...

    async def close(self, *, deadline_monotonic: float) -> None: ...


class SecureTimeBootstrap(Protocol):
    def random_nonce(self, size: int) -> bytes: ...

    async def open_exact_pinned_time_channel(
        self,
        *,
        numeric_ipv4: str,
        port: int,
        expected_leaf_sha256: str,
        expected_endpoint_generation: int,
        expected_server_key_id: str,
        expected_server_public_key_sha256: str,
        deadline_monotonic: float,
    ) -> SecureTimeBootstrapChannel: ...


class SecureTimeSystemClock(Protocol):
    def now_utc(self) -> datetime: ...

    def set_utc(self, value: datetime, *, deadline_monotonic: float) -> None: ...


class SecureTimeServerLeafStore(Protocol):
    def require_server_leaf_der(self) -> bytes: ...


class SecureTimeStrictTlsProbe(Protocol):
    async def verify_fresh_connection_and_close(self, *, deadline_monotonic: float) -> None: ...


class SecureTimeFirewall(Protocol):
    def install_emergency_table(self) -> None: ...


class SecureTimeStateV1(ContractModel):
    schema_version: Literal["tuntun.reachy-secure-time-state.v1"]
    endpoint_generation: Annotated[int, Field(ge=1)]
    authority_health_generation: Annotated[int, Field(ge=1)]
    time_sequence: Annotated[int, Field(ge=1)]
    core_utc: Annotated[AwareDatetime, Field(json_schema_extra=_UTC_DATETIME_SCHEMA_EXTRA)]
    proof_sha256: Annotated[
        str,
        Field(
            min_length=64,
            max_length=64,
            pattern=r"^[a-f0-9]{64}$",
        ),
    ]
    canonical_proof_sha256: Annotated[
        str,
        Field(
            min_length=64,
            max_length=64,
            pattern=r"^[a-f0-9]{64}$",
        ),
    ]
    canonical_proof_b64: Annotated[
        str,
        Field(
            min_length=4,
            max_length=MAX_CANONICAL_PROOF_B64_LENGTH,
            pattern=r"^[A-Za-z0-9+/]+={0,2}$",
        ),
    ]

    @field_validator("core_utc")
    @classmethod
    def require_utc_offset_zero(cls, value: datetime) -> datetime:
        if value.utcoffset() != timedelta(0):
            raise ValueError("core_utc must use UTC offset zero")
        return value

    @field_validator("canonical_proof_b64")
    @classmethod
    def require_canonical_proof_b64(cls, value: str) -> str:
        _decode_base64_canonical_bounded(
            value,
            max_bytes=MAX_CORE_TIME_PROOF_BYTES,
            label="canonical_proof",
        )
        return value


class SecureTimeGate:
    def __init__(
        self,
        *,
        report: SecureTimeCapabilityReport,
        state: SecureTimeStateRepository,
        bootstrap: SecureTimeBootstrap,
        system_clock: SecureTimeSystemClock,
        monotonic: Monotonic = time.monotonic,
        route_neighbor_verifier: SecureTimeRouteNeighborVerifier,
        leaf_verifier: SecureTimeLeafVerifier,
        observer: Callable[[str], None] | None = None,
    ) -> None:
        self._report = report
        self._state = state
        self._bootstrap = bootstrap
        self._system_clock = system_clock
        self._monotonic = monotonic
        self._route_neighbor_verifier = route_neighbor_verifier
        self._leaf_verifier = leaf_verifier
        self._observer = observer

    async def establish_before_strict_tls(
        self,
        endpoint: SecureTimeEndpoint,
        server_leaf_der: bytes,
        *,
        deadline_monotonic: float,
    ) -> SecureTimeBootMode:
        _require_deadline(self._monotonic, deadline_monotonic, "secure_time_boot")
        _require_canonical_rfc1918_ipv4(endpoint.core_ipv4)
        if _report_has_hardware_qualified_rtc(self._report):
            return self._accept_qualified_rtc(endpoint, server_leaf_der, deadline_monotonic)
        previous = self._state.require_previous()
        if previous is not None:
            return self._restore_committed_signed_time(
                previous,
                endpoint,
                server_leaf_der,
                deadline_monotonic,
            )
        return await self._bootstrap_signed_core_time(
            endpoint,
            server_leaf_der,
            deadline_monotonic,
        )

    def _accept_qualified_rtc(
        self,
        endpoint: SecureTimeEndpoint,
        server_leaf_der: bytes,
        deadline_monotonic: float,
    ) -> SecureTimeBootMode:
        public_key_bytes = self._require_bound_leaf_public_key(
            endpoint,
            server_leaf_der,
            deadline_monotonic,
        )
        _require_exact_digest(
            endpoint.server_public_key_sha256,
            public_key_bytes,
            "secure_time_server_public_key_mismatch",
        )
        current_utc = _require_utc_datetime(self._system_clock.now_utc(), "secure_time_rtc")
        self._state.require_rtc_not_rolled_back(current_utc)
        self._leaf_verifier.require_time_within_commissioned_leafs(
            current_utc,
            endpoint=endpoint,
            server_leaf_der=server_leaf_der,
            deadline_monotonic=deadline_monotonic,
        )
        _require_deadline(self._monotonic, deadline_monotonic, "secure_time_qualified_rtc")
        return "qualified_rtc"

    def _restore_committed_signed_time(
        self,
        state: SecureTimeStateV1,
        endpoint: SecureTimeEndpoint,
        server_leaf_der: bytes,
        deadline_monotonic: float,
    ) -> SecureTimeBootMode:
        canonical_proof = _canonical_proof_bytes_from_state(state)
        proof = _parse_canonical_proof(canonical_proof)
        _require_state_matches_proof(state, proof, canonical_proof)
        public_key_bytes = self._require_bound_leaf_public_key(
            endpoint,
            server_leaf_der,
            deadline_monotonic,
        )
        self._verify_signed_proof(
            proof,
            endpoint=endpoint,
            server_leaf_der=server_leaf_der,
            public_key_bytes=public_key_bytes,
            expected_nonce=None,
            deadline_monotonic=deadline_monotonic,
        )
        _require_deadline(self._monotonic, deadline_monotonic, "secure_time_restore")
        self._observe("restored_signed_time_verified")
        self._system_clock.set_utc(proof.core_utc, deadline_monotonic=deadline_monotonic)
        _require_deadline(self._monotonic, deadline_monotonic, "secure_time_restore_clock")
        return "signed_core_bootstrap"

    async def _bootstrap_signed_core_time(
        self,
        endpoint: SecureTimeEndpoint,
        server_leaf_der: bytes,
        deadline_monotonic: float,
    ) -> SecureTimeBootMode:
        self._route_neighbor_verifier.require_current_route_neighbor(
            endpoint,
            deadline_monotonic=deadline_monotonic,
        )
        public_key_bytes = self._require_bound_leaf_public_key(
            endpoint,
            server_leaf_der,
            deadline_monotonic,
        )
        nonce = self._bootstrap.random_nonce(32)
        if type(nonce) is not bytes or len(nonce) != 32:
            raise ValueError("secure time nonce must be exactly 32 bytes")
        _require_deadline(self._monotonic, deadline_monotonic, "secure_time_nonce")
        channel = await self._bootstrap.open_exact_pinned_time_channel(
            numeric_ipv4=endpoint.core_ipv4,
            port=endpoint.port,
            expected_leaf_sha256=endpoint.server_leaf_sha256,
            expected_endpoint_generation=endpoint.generation,
            expected_server_key_id=endpoint.server_key_id,
            expected_server_public_key_sha256=endpoint.server_public_key_sha256,
            deadline_monotonic=deadline_monotonic,
        )
        try:
            _require_deadline(self._monotonic, deadline_monotonic, "secure_time_channel_open")
            request = CoreTimeRequestV1(
                schema_version="tuntun.core-time-request.v1",
                request_nonce_b64=base64.b64encode(nonce).decode("ascii"),
            )
            proof_raw = await channel.request_time(
                canonical_bytes(request),
                deadline_monotonic=deadline_monotonic,
            )
            _require_deadline(self._monotonic, deadline_monotonic, "secure_time_request")
            proof = _parse_canonical_proof(proof_raw)
            self._verify_signed_proof(
                proof,
                endpoint=endpoint,
                server_leaf_der=server_leaf_der,
                public_key_bytes=public_key_bytes,
                expected_nonce=nonce,
                deadline_monotonic=deadline_monotonic,
            )
            previous = self._state.require_previous()
            _require_proof_freshness(proof, previous)
            self._leaf_verifier.require_time_within_commissioned_leafs(
                proof.core_utc,
                endpoint=endpoint,
                server_leaf_der=server_leaf_der,
                deadline_monotonic=deadline_monotonic,
            )
            _require_deadline(self._monotonic, deadline_monotonic, "secure_time_proof")
            self._observe("signed_time_verified")
            self._system_clock.set_utc(proof.core_utc, deadline_monotonic=deadline_monotonic)
            _require_deadline(self._monotonic, deadline_monotonic, "secure_time_clock")
            proof_sha256 = hashlib.sha256(proof.signing_payload()).hexdigest()
            self._state.replace_atomic(
                proof,
                proof_sha256,
                expected_previous=previous,
                deadline_monotonic=deadline_monotonic,
                monotonic=self._monotonic,
            )
            self._observe("time_state_fsynced")
            _require_deadline(self._monotonic, deadline_monotonic, "secure_time_state")
            await channel.close(deadline_monotonic=deadline_monotonic)
            _require_deadline(self._monotonic, deadline_monotonic, "secure_time_channel_close")
        except BaseException:
            with contextlib.suppress(BaseException):
                await channel.close(deadline_monotonic=deadline_monotonic)
            raise
        return "signed_core_bootstrap"

    def _require_bound_leaf_public_key(
        self,
        endpoint: SecureTimeEndpoint,
        server_leaf_der: bytes,
        deadline_monotonic: float,
    ) -> bytes:
        if type(server_leaf_der) is not bytes or not server_leaf_der:
            raise ValueError("secure_time_server_leaf_der_invalid")
        _require_exact_digest(
            endpoint.server_leaf_sha256,
            server_leaf_der,
            "secure_time_server_leaf_digest_mismatch",
        )
        if _SIGNING_KEY_ID_PATTERN.fullmatch(endpoint.server_key_id) is None:
            raise PermissionError("secure_time_signing_key_id_invalid")
        public_key_bytes = self._leaf_verifier.require_ed25519_public_key(
            server_leaf_der,
            endpoint=endpoint,
            deadline_monotonic=deadline_monotonic,
        )
        if type(public_key_bytes) is not bytes or len(public_key_bytes) != 32:
            raise PermissionError("secure_time_server_public_key_invalid")
        _require_exact_digest(
            endpoint.server_public_key_sha256,
            public_key_bytes,
            "secure_time_server_public_key_mismatch",
        )
        return public_key_bytes

    def _verify_signed_proof(
        self,
        proof: CoreTimeProofV1,
        *,
        endpoint: SecureTimeEndpoint,
        server_leaf_der: bytes,
        public_key_bytes: bytes,
        expected_nonce: bytes | None,
        deadline_monotonic: float,
    ) -> None:
        _require_endpoint_binding(proof, endpoint)
        proof_nonce = _decode_base64_exact(
            proof.request_nonce_b64, expected_bytes=32, label="nonce"
        )
        if expected_nonce is not None and not hmac.compare_digest(proof_nonce, expected_nonce):
            raise PermissionError("secure_time_nonce_mismatch")
        signature = _decode_base64_exact(
            proof.signature_b64,
            expected_bytes=64,
            label="signature",
        )
        _require_deadline(self._monotonic, deadline_monotonic, "secure_time_before_signature")
        try:
            Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
                signature,
                proof.signing_payload(),
            )
        except (InvalidSignature, ValueError) as error:
            raise PermissionError("secure_time_invalid_signature") from error
        _require_utc_datetime(proof.core_utc, "secure_time_proof")
        self._leaf_verifier.require_time_within_commissioned_leafs(
            proof.core_utc,
            endpoint=endpoint,
            server_leaf_der=server_leaf_der,
            deadline_monotonic=deadline_monotonic,
        )
        _require_deadline(self._monotonic, deadline_monotonic, "secure_time_after_signature")

    def _observe(self, event: str) -> None:
        if self._observer is not None:
            self._observer(event)


class SecureTimeBootLifecycle:
    def __init__(
        self,
        *,
        gate: SecureTimeGate,
        endpoint: SecureTimeEndpoint,
        leaf_store: SecureTimeServerLeafStore,
        strict_tls_probe: SecureTimeStrictTlsProbe,
        firewall: SecureTimeFirewall,
        monotonic: Monotonic = time.monotonic,
        observer: Callable[[str], None] | None = None,
    ) -> None:
        self._gate = gate
        self._endpoint = endpoint
        self._leaf_store = leaf_store
        self._strict_tls_probe = strict_tls_probe
        self._firewall = firewall
        self._monotonic = monotonic
        self._observer = observer
        self._ready = False
        self._mode: SecureTimeBootMode | None = None

    @property
    def ready(self) -> bool:
        return self._ready

    @property
    def mode(self) -> SecureTimeBootMode | None:
        return self._mode

    async def start_before_reachy_transport(self) -> None:
        self._ready = False
        self._mode = None
        deadline_monotonic = self._monotonic() + SECURE_TIME_BOOT_DEADLINE_SECONDS
        self._firewall.install_emergency_table()
        try:
            _require_deadline(self._monotonic, deadline_monotonic, "secure_time_start")
            server_leaf_der = self._leaf_store.require_server_leaf_der()
            mode = await self._gate.establish_before_strict_tls(
                self._endpoint,
                server_leaf_der,
                deadline_monotonic=deadline_monotonic,
            )
            _require_deadline(self._monotonic, deadline_monotonic, "secure_time_before_mtls")
            await self._strict_tls_probe.verify_fresh_connection_and_close(
                deadline_monotonic=deadline_monotonic,
            )
            _require_deadline(self._monotonic, deadline_monotonic, "secure_time_strict_mtls")
        except BaseException:
            self._ready = False
            self._mode = None
            with contextlib.suppress(BaseException):
                self._firewall.install_emergency_table()
            raise
        self._mode = mode
        self._ready = True
        self._observe("edge_ready")

    def require_ready(self) -> None:
        if not self._ready:
            raise PermissionError("secure_time_not_ready")

    def _observe(self, event: str) -> None:
        if self._observer is not None:
            self._observer(event)


class SecureTimeStateRepository:
    def __init__(self, root: Path) -> None:
        self._directory = _OwnedDirectory(root, create=True)
        self.root = self._directory.path
        self.path = self.root / SECURE_TIME_STATE_NAME
        self._fault_stage: str | None = None

    @property
    def directory_fd(self) -> int:
        return self._directory.fd

    @property
    def mode(self) -> int:
        identity = os.stat(SECURE_TIME_STATE_NAME, dir_fd=self.directory_fd, follow_symlinks=False)
        return stat.S_IMODE(identity.st_mode)

    def close(self) -> None:
        self._directory.close()

    def reopen(self) -> SecureTimeStateRepository:
        return SecureTimeStateRepository(self.root)

    def inject_crash_at(self, stage: str) -> None:
        if stage not in SECURE_TIME_PUBLISH_FAULT_STAGES:
            raise ValueError("unknown secure time publish fault stage")
        self._fault_stage = stage

    def require_previous(self) -> SecureTimeStateV1 | None:
        try:
            raw = _read_owner_file(
                self._directory,
                SECURE_TIME_STATE_NAME,
                max_bytes=MAX_SECURE_TIME_STATE_BYTES,
            )
        except FileNotFoundError:
            return None
        return parse_contract_json(
            SecureTimeStateV1,
            raw,
            max_bytes=MAX_SECURE_TIME_STATE_BYTES,
            require_canonical=True,
        )

    def require_rtc_not_rolled_back(self, current_utc: datetime) -> None:
        current_utc = _require_utc_datetime(current_utc, "secure_time_rtc")
        previous = self.require_previous()
        if previous is not None and current_utc < previous.core_utc - _ROLLBACK_SKEW_TOLERANCE:
            raise PermissionError("secure_time_rtc_rollback")

    def replace_atomic(
        self,
        proof: CoreTimeProofV1,
        proof_sha256: str,
        *,
        expected_previous: SecureTimeStateV1 | None,
        deadline_monotonic: float,
        monotonic: Monotonic = time.monotonic,
    ) -> SecureTimeStateV1:
        if not hmac.compare_digest(
            proof_sha256, hashlib.sha256(proof.signing_payload()).hexdigest()
        ):
            raise ValueError("secure_time_proof_commitment_mismatch")
        state = SecureTimeStateV1(
            schema_version="tuntun.reachy-secure-time-state.v1",
            endpoint_generation=proof.endpoint_generation,
            authority_health_generation=proof.authority_health_generation,
            time_sequence=proof.time_sequence,
            core_utc=proof.core_utc,
            proof_sha256=proof_sha256,
            canonical_proof_sha256=hashlib.sha256(canonical_bytes(proof)).hexdigest(),
            canonical_proof_b64=base64.b64encode(canonical_bytes(proof)).decode("ascii"),
        )
        payload = canonical_bytes(state)
        if not 1 <= len(payload) <= MAX_SECURE_TIME_STATE_BYTES:
            raise ValueError("secure time state size invalid")
        with _exclusive_lock(
            self._directory,
            SECURE_TIME_LOCK_NAME,
            deadline_monotonic=deadline_monotonic,
            monotonic=monotonic,
        ):
            _require_deadline(monotonic, deadline_monotonic, "secure_time_state_lock")
            current = self.require_previous()
            if expected_previous is None:
                if current is not None:
                    raise PermissionError("secure_time_state_cas_failed")
            elif current != expected_previous:
                raise PermissionError("secure_time_state_cas_failed")
            self._atomic_write(
                SECURE_TIME_STATE_NAME,
                payload,
                MAX_SECURE_TIME_STATE_BYTES,
                deadline_monotonic=deadline_monotonic,
                monotonic=monotonic,
            )
        return state

    def _atomic_write(
        self,
        target_name: str,
        payload: bytes,
        max_bytes: int,
        *,
        deadline_monotonic: float,
        monotonic: Monotonic,
    ) -> None:
        if not 1 <= len(payload) <= max_bytes:
            raise ValueError("secure time state size invalid")
        temp_name = f".secure-time-state.{os.getpid()}.{uuid4().hex}.tmp"
        descriptor = -1
        replaced = False
        temp_identity: _FileIdentity | None = None
        try:
            self._fault("before_temp_open")
            _require_deadline(monotonic, deadline_monotonic, "secure_time_publish")
            descriptor = os.open(temp_name, _WRITE_FLAGS, 0o600, dir_fd=self.directory_fd)
            self._fault("after_temp_open")
            os.fchmod(descriptor, 0o600)
            _write_all(descriptor, payload)
            self._fault("after_temp_write")
            written = os.fstat(descriptor)
            _require_owner_regular(
                written,
                expected_mode=0o600,
                require_single_link=True,
                expected_size=len(payload),
                directory_device=self._directory.identity.device,
            )
            os.fsync(descriptor)
            temp_identity = _FileIdentity.from_stat(written)
            self._fault("after_file_fsync")
            _require_deadline(monotonic, deadline_monotonic, "secure_time_file_fsync")
            os.close(descriptor)
            descriptor = -1
            named_temp = os.stat(temp_name, dir_fd=self.directory_fd, follow_symlinks=False)
            if not temp_identity.same_file_and_size(named_temp):
                raise PermissionError("secure time temporary file changed before publish")
            self._fault("before_parent_fsync")
            self._directory.fsync()
            self._fault("after_parent_fsync_before_replace")
            _require_deadline(monotonic, deadline_monotonic, "secure_time_parent_fsync")
            os.replace(
                temp_name,
                target_name,
                src_dir_fd=self.directory_fd,
                dst_dir_fd=self.directory_fd,
            )
            replaced = True
            self._fault("after_replace_before_parent_fsync")
            self._directory.fsync()
            self._fault("after_parent_fsync")
            published = os.stat(target_name, dir_fd=self.directory_fd, follow_symlinks=False)
            if not temp_identity.same_file_and_size(published):
                raise PermissionError("secure time published identity mismatch")
            if _read_owner_file(self._directory, target_name, max_bytes=max_bytes) != payload:
                raise PermissionError("secure time final byte verification failed")
            self._fault("after_final_verify")
            _require_deadline(monotonic, deadline_monotonic, "secure_time_final_verify")
        finally:
            if descriptor >= 0 and temp_identity is None:
                with contextlib.suppress(OSError):
                    temp_identity = _FileIdentity.from_stat(os.fstat(descriptor))
            if descriptor >= 0:
                os.close(descriptor)
            if not replaced and temp_identity is not None:
                _unlink_if_identity_matches(self._directory, temp_name, temp_identity)

    def _fault(self, stage: str) -> None:
        if self._fault_stage == stage:
            self._fault_stage = None
            raise OSError(f"scripted secure time publish fault at {stage}")


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    inode: int
    size: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> _FileIdentity:
        return cls(value.st_dev, value.st_ino, value.st_size)

    def same_file_and_size(self, value: os.stat_result) -> bool:
        return self == type(self).from_stat(value)


@dataclass(frozen=True, slots=True)
class _DirectoryIdentity:
    device: int
    inode: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> _DirectoryIdentity:
        return cls(value.st_dev, value.st_ino)


class _OwnedDirectory:
    def __init__(self, path: Path, *, create: bool) -> None:
        self.path = _absolute_lexical_path(path)
        self._fd = _open_private_directory(self.path, create=create)
        identity = os.fstat(self._fd)
        _require_private_directory(identity)
        self.identity = _DirectoryIdentity.from_stat(identity)

    @property
    def fd(self) -> int:
        if self._fd < 0:
            raise OSError(errno.EBADF, os.strerror(errno.EBADF))
        return self._fd

    def close(self) -> None:
        descriptor = self._fd
        self._fd = -1
        if descriptor >= 0:
            os.close(descriptor)

    def fsync(self) -> None:
        os.fsync(self.fd)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        _error_type: type[BaseException] | None,
        _error: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()


def _report_has_hardware_qualified_rtc(report: SecureTimeCapabilityReport) -> bool:
    return (
        report.source == "hardware"
        and report.rtc_available
        and report.rtc_cold_boot_retains_utc
        and report.rtc_qualified
        and report.rtc_max_drift_seconds_30d is not None
        and report.rtc_max_drift_seconds_30d <= 5.0
    )


def _parse_canonical_proof(raw: bytes) -> CoreTimeProofV1:
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_CORE_TIME_PROOF_BYTES:
        raise ValueError("secure time proof size invalid")
    return parse_contract_json(
        CoreTimeProofV1,
        raw,
        max_bytes=MAX_CORE_TIME_PROOF_BYTES,
        require_canonical=True,
    )


def _canonical_proof_bytes_from_state(state: SecureTimeStateV1) -> bytes:
    canonical_proof = _decode_base64_canonical_bounded(
        state.canonical_proof_b64,
        max_bytes=MAX_CORE_TIME_PROOF_BYTES,
        label="canonical_proof",
    )
    if not hmac.compare_digest(
        hashlib.sha256(canonical_proof).hexdigest(),
        state.canonical_proof_sha256,
    ):
        raise PermissionError("secure_time_canonical_proof_commitment_mismatch")
    return canonical_proof


def _require_state_matches_proof(
    state: SecureTimeStateV1,
    proof: CoreTimeProofV1,
    canonical_proof: bytes,
) -> None:
    if canonical_bytes(proof) != canonical_proof:
        raise PermissionError("secure_time_canonical_proof_mismatch")
    if not hmac.compare_digest(
        state.proof_sha256,
        hashlib.sha256(proof.signing_payload()).hexdigest(),
    ):
        raise PermissionError("secure_time_proof_commitment_mismatch")
    if (
        state.endpoint_generation != proof.endpoint_generation
        or state.authority_health_generation != proof.authority_health_generation
        or state.time_sequence != proof.time_sequence
        or state.core_utc != proof.core_utc
    ):
        raise PermissionError("secure_time_committed_proof_state_mismatch")


def _require_endpoint_binding(proof: CoreTimeProofV1, endpoint: SecureTimeEndpoint) -> None:
    if proof.endpoint_generation != endpoint.generation:
        raise PermissionError("secure_time_endpoint_generation_mismatch")
    if proof.authority_health_generation != endpoint.trust_digest_generation:
        raise PermissionError("secure_time_authority_generation_mismatch")
    if proof.signing_key_id != endpoint.server_key_id:
        raise PermissionError("secure_time_signing_key_mismatch")
    if _SIGNING_KEY_ID_PATTERN.fullmatch(proof.signing_key_id) is None:
        raise PermissionError("secure_time_signing_key_id_invalid")


def _require_proof_freshness(
    proof: CoreTimeProofV1,
    previous: SecureTimeStateV1 | None,
) -> None:
    if previous is None:
        return
    if proof.endpoint_generation < previous.endpoint_generation:
        raise PermissionError("secure_time_endpoint_generation_rollback")
    if proof.authority_health_generation < previous.authority_health_generation:
        raise PermissionError("secure_time_authority_rollback")
    if (
        proof.authority_health_generation
        > previous.authority_health_generation + _MAX_AUTHORITY_GENERATION_FORWARD_STEP
    ):
        raise PermissionError("secure_time_authority_excessive_forward_step")
    if proof.time_sequence <= previous.time_sequence:
        raise PermissionError("secure_time_replayed_time_sequence")
    if proof.core_utc < previous.core_utc - _ROLLBACK_SKEW_TOLERANCE:
        raise PermissionError("secure_time_rollback")
    if proof.core_utc > previous.core_utc + _MAX_SIGNED_FORWARD_STEP:
        raise PermissionError("secure_time_excessive_forward_step")


def _require_exact_digest(expected_hex: str, value: bytes, message: str) -> None:
    if type(expected_hex) is not str or _HEX_SHA256_PATTERN.fullmatch(expected_hex) is None:
        raise PermissionError(message)
    actual_hex = hashlib.sha256(value).hexdigest()
    if not hmac.compare_digest(expected_hex, actual_hex):
        raise PermissionError(message)


def _require_canonical_rfc1918_ipv4(value: str) -> None:
    if type(value) is not str or _CANONICAL_RFC1918_IPV4_PATTERN.fullmatch(value) is None:
        raise PermissionError("secure_time_numeric_rfc1918_ipv4_required")


def _decode_base64_canonical_bounded(value: str, *, max_bytes: int, label: str) -> bytes:
    if type(value) is not str:
        raise ValueError(f"secure time {label} must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError(f"secure time {label} must be canonical base64") from error
    if not 1 <= len(decoded) <= max_bytes or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"secure time {label} must be bounded canonical base64")
    return decoded


def _decode_base64_exact(value: str, *, expected_bytes: int, label: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError(f"secure time {label} must be canonical base64") from error
    if len(decoded) != expected_bytes or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"secure time {label} must encode exactly {expected_bytes} bytes")
    return decoded


def _require_utc_datetime(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{label} must use UTC offset zero")
    return value.astimezone(UTC)


def _require_deadline(monotonic: Monotonic, deadline_monotonic: float, label: str) -> None:
    if monotonic() > deadline_monotonic:
        raise TimeoutError(f"{label} deadline exceeded")


def _absolute_lexical_path(path: Path) -> Path:
    raw = os.fspath(path)
    if type(raw) is not str or "\x00" in raw or raw == "":
        raise PermissionError("unsafe secure time filesystem path")
    absolute = Path(os.path.abspath(raw))
    if absolute == Path("/") or any(part in {".", ".."} for part in absolute.parts):
        raise PermissionError("unsafe secure time filesystem path")
    return absolute


def _open_private_directory(path: Path, *, create: bool) -> int:
    parts = path.parts
    descriptor = os.open("/", _DIRECTORY_FLAGS & ~_NOFOLLOW)
    try:
        for index, component in enumerate(parts[1:]):
            if not _safe_component(component):
                raise PermissionError("unsafe secure time filesystem path")
            final = index == len(parts[1:]) - 1
            if create and final:
                with contextlib.suppress(FileExistsError):
                    os.mkdir(component, 0o700, dir_fd=descriptor)
            named = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISDIR(named.st_mode):
                raise PermissionError("unsafe secure time filesystem path")
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            try:
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                    raise PermissionError("unsafe secure time filesystem path")
                if final:
                    _require_private_directory(opened)
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _safe_component(value: str) -> bool:
    return (
        type(value) is str
        and value not in {"", ".", ".."}
        and "/" not in value
        and "\x00" not in value
    )


def _require_private_directory(identity: os.stat_result) -> None:
    if not stat.S_ISDIR(identity.st_mode):
        raise PermissionError("secure time directory is not a directory")
    if identity.st_uid != os.geteuid() or stat.S_IMODE(identity.st_mode) != 0o700:
        raise PermissionError("secure time directory is not owner-only")


def _stat_owner_file(
    directory: _OwnedDirectory,
    name: str,
    *,
    max_bytes: int,
) -> os.stat_result:
    if not _safe_component(name):
        raise PermissionError("unsafe secure time filesystem path")
    identity = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
    _require_owner_regular(
        identity,
        expected_mode=0o600,
        require_single_link=True,
        max_bytes=max_bytes,
        directory_device=directory.identity.device,
    )
    return identity


def _read_owner_file(directory: _OwnedDirectory, name: str, *, max_bytes: int) -> bytes:
    before = _stat_owner_file(directory, name, max_bytes=max_bytes)
    expected = _FileIdentity.from_stat(before)
    descriptor = os.open(name, _READ_FLAGS, dir_fd=directory.fd)
    try:
        opened = os.fstat(descriptor)
        if not expected.same_file_and_size(opened):
            raise PermissionError("secure time owner file changed during read")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining > 0:
            chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, remaining))
            if not chunk:
                raise ValueError("secure time owner file changed during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("secure time owner file changed during read")
        after = os.fstat(descriptor)
        named_after = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
        if not expected.same_file_and_size(after) or not expected.same_file_and_size(named_after):
            raise PermissionError("secure time owner file changed during read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _require_owner_regular(
    identity: os.stat_result,
    *,
    expected_mode: int,
    require_single_link: bool,
    max_bytes: int | None = None,
    expected_size: int | None = None,
    directory_device: int | None = None,
) -> None:
    if not stat.S_ISREG(identity.st_mode):
        raise PermissionError("secure time owner file is not regular")
    if identity.st_uid != os.geteuid() or stat.S_IMODE(identity.st_mode) != expected_mode:
        raise PermissionError("secure time owner file is not owner-only")
    if require_single_link and identity.st_nlink != 1:
        raise PermissionError("secure time owner file must have one link")
    if directory_device is not None and identity.st_dev != directory_device:
        raise PermissionError("secure time owner file must stay on one device")
    if max_bytes is not None and not 1 <= identity.st_size <= max_bytes:
        raise ValueError("secure time owner file size invalid")
    if expected_size is not None and identity.st_size != expected_size:
        raise ValueError("secure time owner file size invalid")


@contextlib.contextmanager
def _exclusive_lock(
    directory: _OwnedDirectory,
    name: str,
    *,
    deadline_monotonic: float,
    monotonic: Monotonic,
) -> Iterator[None]:
    descriptor = os.open(name, _LOCK_FLAGS, 0o600, dir_fd=directory.fd)
    try:
        identity = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
        _require_owner_regular(
            identity,
            expected_mode=0o600,
            require_single_link=True,
            directory_device=directory.identity.device,
        )
        if (identity.st_dev, identity.st_ino) != (named.st_dev, named.st_ino):
            raise PermissionError("secure time lock identity changed")
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if monotonic() >= deadline_monotonic:
                    raise TimeoutError("secure time repository lock deadline") from None
                sleep_seconds = max(0.0, min(0.01, deadline_monotonic - monotonic()))
                if sleep_seconds:
                    time.sleep(sleep_seconds)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    total = 0
    while total < len(payload):
        written = os.write(descriptor, view[total:])
        if written <= 0:
            raise OSError("short secure time owner-file write")
        total += written


def _unlink_if_identity_matches(
    directory: _OwnedDirectory,
    name: str,
    identity: _FileIdentity,
) -> None:
    try:
        candidate = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if identity.same_file_and_size(candidate):
        os.unlink(name, dir_fd=directory.fd)
        directory.fsync()
