from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Literal, cast
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import Field, ValidationError
from tuntun_contracts.base import ContractModel, canonical_bytes, parse_contract_json
from tuntun_contracts.reachy_time import CoreTimeProofV1, CoreTimeRequestV1
from tuntun_edge.reachy.probe import CapabilityReport
from tuntun_edge.transport.secure_time import (
    MAX_SECURE_TIME_STATE_BYTES,
    SECURE_TIME_PUBLISH_FAULT_STAGES,
    SECURE_TIME_STATE_NAME,
    SecureTimeBootLifecycle,
    SecureTimeEndpoint,
    SecureTimeGate,
    SecureTimeStateRepository,
    SecureTimeStateV1,
)

NOW = datetime(2026, 8, 27, 1, 2, 3, 4, tzinfo=UTC)
BOOT_ATTEMPT_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
NEXT_BOOT_ATTEMPT_ID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
RESTORE_ATTEMPT_ID = "cccccccc-cccc-cccc-cccc-cccccccccccc"


@dataclass(frozen=True, slots=True)
class FakeEndpoint:
    generation: int
    trust_digest_generation: int
    core_ipv4: str
    port: int
    server_leaf_sha256: str
    server_key_id: str
    server_public_key_sha256: str


class FakeMonotonic:
    def __init__(self) -> None:
        self.value = 100.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class FakeSystemClock:
    def __init__(self, now: datetime, events: list[str]) -> None:
        self._now = now
        self.deadlines: list[float] = []
        self.events = events

    def now_utc(self) -> datetime:
        return self._now

    def set_utc(self, value: datetime, *, deadline_monotonic: float) -> None:
        self.deadlines.append(deadline_monotonic)
        self._now = value
        self.events.append("clock_set")


class FakeRouteNeighborVerifier:
    def __init__(self, events: list[str], *, fail: bool = False) -> None:
        self.events = events
        self.fail = fail
        self.deadlines: list[float] = []

    def require_current_route_neighbor(
        self,
        endpoint: SecureTimeEndpoint,
        *,
        deadline_monotonic: float,
    ) -> None:
        self.deadlines.append(deadline_monotonic)
        if self.fail:
            raise PermissionError("route_neighbor_not_verified")
        assert endpoint.core_ipv4 == "192.168.10.10"
        self.events.append("route_neighbor_verified")


class FakeLeafVerifier:
    def __init__(
        self,
        events: list[str],
        *,
        public_key_bytes: bytes,
        server_not_before: datetime = NOW - timedelta(minutes=1),
        server_not_after: datetime = NOW + timedelta(minutes=10),
        client_not_before: datetime = NOW - timedelta(minutes=1),
        client_not_after: datetime = NOW + timedelta(minutes=10),
        returned_public_key_bytes: bytes | None = None,
    ) -> None:
        self.events = events
        self.public_key_bytes = public_key_bytes
        self.returned_public_key_bytes = (
            public_key_bytes if returned_public_key_bytes is None else returned_public_key_bytes
        )
        self.server_not_before = server_not_before
        self.server_not_after = server_not_after
        self.client_not_before = client_not_before
        self.client_not_after = client_not_after
        self.deadlines: list[float] = []

    def require_ed25519_public_key(
        self,
        server_leaf_der: bytes,
        *,
        endpoint: SecureTimeEndpoint,
        deadline_monotonic: float,
    ) -> bytes:
        self.deadlines.append(deadline_monotonic)
        assert server_leaf_der
        assert endpoint.server_key_id == "ed25519:reachy-time:v7"
        self.events.append("leaf_pin_verified")
        return self.returned_public_key_bytes

    def require_time_within_commissioned_leafs(
        self,
        value: datetime,
        *,
        endpoint: SecureTimeEndpoint,
        server_leaf_der: bytes,
        deadline_monotonic: float,
    ) -> None:
        self.deadlines.append(deadline_monotonic)
        assert server_leaf_der
        assert endpoint.generation == 7
        if not self.server_not_before <= value <= self.server_not_after:
            raise PermissionError("secure_time_outside_server_leaf_validity")
        if not self.client_not_before <= value <= self.client_not_after:
            raise PermissionError("secure_time_outside_client_leaf_validity")


class FakeBootstrapChannel:
    def __init__(self, case: SecureTimeCase) -> None:
        self.case = case
        self.closed = False
        self.promoted = False
        self.deadlines: list[float] = []
        self.time_requests: list[CoreTimeRequestV1] = []

    async def request_time(
        self, request_canonical_json: bytes, *, deadline_monotonic: float
    ) -> bytes:
        self.deadlines.append(deadline_monotonic)
        self.case.events.append("time_request_sent")
        request = parse_contract_json(
            CoreTimeRequestV1,
            request_canonical_json,
            max_bytes=8_192,
            require_canonical=True,
        )
        self.time_requests.append(request)
        if self.case.failure == "cancelled":
            raise asyncio.CancelledError()
        if self.case.failure == "bootstrap_rtt_exceeded":
            self.case.monotonic.advance(2.1)
        proof = self.case.proof_for_request(request)
        if self.case.failure == "malformed_canonical_proof":
            return json.dumps(proof.model_dump(mode="json"), indent=2).encode("utf-8")
        return canonical_bytes(proof)

    async def close(self, *, deadline_monotonic: float) -> None:
        self.deadlines.append(deadline_monotonic)
        self.closed = True
        self.case.events.append("bootstrap_closed")


class FakeBootstrap:
    def __init__(self, case: SecureTimeCase) -> None:
        self.case = case
        self.connections = 0
        self.nonces: list[bytes] = []
        self.deadlines: list[float] = []
        self.last_channel: FakeBootstrapChannel | None = None
        self.dns_queries: list[str] = []
        self.udp_123_attempts: list[str] = []
        self.bootstrap_application_frames: list[bytes] = []

    def random_nonce(self, size: int) -> bytes:
        if size != 32:
            raise AssertionError("secure time nonce must be exactly 32 bytes")
        nonce = b"\x01" * 32
        self.nonces.append(nonce)
        self.case.events.append("nonce_generated")
        return nonce

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
    ) -> FakeBootstrapChannel:
        self.deadlines.append(deadline_monotonic)
        if any(character.isalpha() for character in numeric_ipv4):
            self.dns_queries.append(numeric_ipv4)
            raise PermissionError("secure_time_numeric_ipv4_required")
        assert port == 7443
        assert expected_leaf_sha256 == self.case.endpoint.server_leaf_sha256
        assert expected_endpoint_generation == self.case.endpoint.generation
        assert expected_server_key_id == self.case.endpoint.server_key_id
        assert expected_server_public_key_sha256 == self.case.endpoint.server_public_key_sha256
        self.connections += 1
        self.case.events.append("pinned_time_channel")
        channel = FakeBootstrapChannel(self.case)
        self.last_channel = channel
        return channel


class FakeStrictMtlsProbe:
    def __init__(self, case: SecureTimeCase) -> None:
        self.case = case
        self.calls = 0
        self.deadlines: list[float] = []
        self.bootstrap_was_closed_before_strict = False

    async def verify_fresh_connection_and_close(self, *, deadline_monotonic: float) -> None:
        self.deadlines.append(deadline_monotonic)
        self.calls += 1
        self.bootstrap_was_closed_before_strict = (
            self.case.bootstrap.last_channel is None or self.case.bootstrap.last_channel.closed
        )
        self.case.events.append("strict_mtls_validity_verified")
        if self.case.failure == "strict_reconnect_validity_failure":
            raise PermissionError("strict_reconnect_validity_failure")
        if self.case.failure == "strict_reconnect_deadline_exceeded":
            self.case.monotonic.advance(2.1)


class FakeFirewall:
    def __init__(self, events: list[str]) -> None:
        self.installed_table_kind: str | None = None
        self.events = events

    def install_emergency_table(self) -> None:
        self.installed_table_kind = "emergency_default_drop"
        if "emergency_firewall" not in self.events:
            self.events.append("emergency_firewall")


class FakeLeafStore:
    def __init__(self, case: SecureTimeCase) -> None:
        self.case = case

    def require_server_leaf_der(self) -> bytes:
        return self.case.server_leaf_der


class SecureTimeCase:
    def __init__(
        self,
        tmp_path: Path,
        *,
        rtc_qualified: bool = False,
        source: Literal["hardware", "synthetic"] = "hardware",
        failure: str | None = None,
        previous: CoreTimeProofV1 | None = None,
        cold_boot_utc: datetime = datetime(1970, 1, 1, tzinfo=UTC),
        private_key: Ed25519PrivateKey | None = None,
        proof_time_sequence: int = 11,
    ) -> None:
        tmp_path.mkdir(parents=True, exist_ok=True)
        self.events: list[str] = []
        self.failure = failure
        self.proof_time_sequence = proof_time_sequence
        self.monotonic = FakeMonotonic()
        self.private_key = Ed25519PrivateKey.generate() if private_key is None else private_key
        self.public_key_bytes = self.private_key.public_key().public_bytes(
            Encoding.Raw,
            PublicFormat.Raw,
        )
        self.server_leaf_der = b"synthetic-server-leaf-v1:" + self.public_key_bytes
        public_key_for_endpoint = self.public_key_bytes
        if failure == "wrong_public_key":
            public_key_for_endpoint = b"\x02" * 32
        leaf_sha256 = hashlib.sha256(self.server_leaf_der).hexdigest()
        if failure == "wrong_leaf":
            leaf_sha256 = "f" * 64
        core_ipv4 = "192.168.10.10"
        if failure == "hostname_endpoint":
            core_ipv4 = "reachy.local"
        self.endpoint = FakeEndpoint(
            generation=7,
            trust_digest_generation=5 if failure != "core_authority_excessive_forward_step" else 3,
            core_ipv4=core_ipv4,
            port=7443,
            server_leaf_sha256=leaf_sha256,
            server_key_id="ed25519:reachy-time:v7",
            server_public_key_sha256=hashlib.sha256(public_key_for_endpoint).hexdigest(),
        )
        self.report = capability_report(rtc_qualified=rtc_qualified, source=source)
        self.repository = SecureTimeStateRepository(tmp_path / "secure-time")
        if failure == "crash_after_commit_before_strict":
            self.repository.inject_crash_at("after_parent_fsync")
        if previous is not None:
            self.write_previous(previous)
        server_not_before = NOW - timedelta(minutes=1)
        server_not_after = NOW + timedelta(minutes=10)
        client_not_before = NOW - timedelta(minutes=1)
        client_not_after = NOW + timedelta(minutes=10)
        if failure == "time_outside_server_leaf_validity":
            server_not_after = NOW - timedelta(seconds=1)
        if failure == "time_outside_client_leaf_validity":
            client_not_after = NOW - timedelta(seconds=1)
        self.clock = FakeSystemClock(cold_boot_utc, self.events)
        self.route_neighbor = FakeRouteNeighborVerifier(
            self.events,
            fail=failure == "route_neighbor_failure",
        )
        self.leaf_verifier = FakeLeafVerifier(
            self.events,
            public_key_bytes=self.public_key_bytes,
            server_not_before=server_not_before,
            server_not_after=server_not_after,
            client_not_before=client_not_before,
            client_not_after=client_not_after,
        )
        self.bootstrap = FakeBootstrap(self)
        self.strict_mtls = FakeStrictMtlsProbe(self)
        self.firewall = FakeFirewall(self.events)
        self.lifecycle = SecureTimeBootLifecycle(
            gate=SecureTimeGate(
                report=self.report,
                state=self.repository,
                bootstrap=self.bootstrap,
                system_clock=self.clock,
                monotonic=self.monotonic,
                route_neighbor_verifier=self.route_neighbor,
                leaf_verifier=self.leaf_verifier,
                observer=self.events.append,
            ),
            endpoint=self.endpoint,
            leaf_store=FakeLeafStore(self),
            strict_tls_probe=self.strict_mtls,
            firewall=self.firewall,
            monotonic=self.monotonic,
            observer=self.events.append,
        )

    async def boot(self) -> str:
        await self.lifecycle.start_before_reachy_transport()
        return cast(str, self.lifecycle.mode)

    @property
    def edge_ready(self) -> bool:
        return self.lifecycle.ready

    @property
    def application_control_frames(self) -> list[bytes]:
        return []

    @property
    def bootstrap_application_frames(self) -> list[bytes]:
        return self.bootstrap.bootstrap_application_frames

    @property
    def udp_123_attempts(self) -> list[str]:
        return self.bootstrap.udp_123_attempts

    @property
    def dns_queries(self) -> list[str]:
        return self.bootstrap.dns_queries

    @property
    def installed_table_kind(self) -> str | None:
        return self.firewall.installed_table_kind

    def proof_for_request(self, request: CoreTimeRequestV1) -> CoreTimeProofV1:
        nonce = base64.b64decode(request.request_nonce_b64, validate=True)
        if self.failure == "wrong_nonce":
            nonce = b"\x02" * 32
        endpoint_generation = (
            self.endpoint.generation + 1
            if self.failure == "wrong_endpoint_generation"
            else self.endpoint.generation
        )
        signing_key_id = (
            "ed25519:wrong-time:v7"
            if self.failure == "wrong_signing_key"
            else self.endpoint.server_key_id
        )
        authority_generation = self.endpoint.trust_digest_generation
        core_utc = NOW
        time_sequence = self.proof_time_sequence
        if self.failure == "core_authority_rollback":
            authority_generation = 4
        if self.failure == "replayed_time_sequence":
            time_sequence = 10
        if self.failure == "signed_time_rollback":
            core_utc = NOW - timedelta(seconds=5)
        if self.failure == "tampered_forward_time":
            core_utc = NOW + timedelta(days=32)
        signing_key = self.private_key
        if self.failure == "invalid_signature":
            signing_key = Ed25519PrivateKey.generate()
        return signed_proof(
            signing_key,
            nonce=nonce,
            endpoint_generation=endpoint_generation,
            authority_health_generation=authority_generation,
            signing_key_id=signing_key_id,
            core_utc=core_utc,
            time_sequence=time_sequence,
        )

    def write_previous(self, proof: CoreTimeProofV1) -> None:
        pending = self.repository.replace_atomic(
            proof,
            hashlib.sha256(proof.signing_payload()).hexdigest(),
            expected_previous=None,
            deadline_monotonic=self.monotonic() + 2.0,
            boot_attempt_id=BOOT_ATTEMPT_ID,
            monotonic=self.monotonic,
        )
        self.repository.mark_strict_mtls_ready(
            expected_current=pending,
            boot_attempt_id=BOOT_ATTEMPT_ID,
            deadline_monotonic=self.monotonic() + 2.0,
            monotonic=self.monotonic,
        )


def capability_report(
    *,
    rtc_qualified: bool,
    source: Literal["hardware", "synthetic"] = "hardware",
) -> CapabilityReport:
    return CapabilityReport.model_validate(
        {
            "schema_version": "tuntun.reachy-capability-report.v1",
            "source": source,
            "probe_version": "0.1.0",
            "sdk_version": "1.2.3",
            "daemon_version": "4.5.6",
            "input_rate_hz": 16000,
            "input_channels": 1,
            "output_rate_hz": 16000,
            "output_channels": 1,
            "aec_available": True,
            "doa_available": False,
            "daemon_ports": (8000, 8001),
            "secure_key_storage_available": True,
            "managed_app_lock_available": True,
            "competing_controller_detectable": True,
            "stop_during_playback_tested": True,
            "rtc_available": rtc_qualified,
            "rtc_cold_boot_retains_utc": rtc_qualified,
            "rtc_max_drift_seconds_30d": 4.9 if rtc_qualified else None,
            "rtc_qualified": rtc_qualified,
        }
    )


def signed_proof(
    private_key: Ed25519PrivateKey,
    *,
    nonce: bytes = b"\x01" * 32,
    endpoint_generation: int = 7,
    authority_health_generation: int = 5,
    signing_key_id: str = "ed25519:reachy-time:v7",
    core_utc: datetime = NOW,
    time_sequence: int = 11,
) -> CoreTimeProofV1:
    unsigned_payload = {
        "schema_version": "tuntun.core-time-proof.v1",
        "endpoint_generation": endpoint_generation,
        "time_sequence": time_sequence,
        "request_nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "core_utc": core_utc,
        "authority_health_generation": authority_health_generation,
        "signing_key_id": signing_key_id,
        "signature_b64": base64.b64encode(b"\x00" * 64).decode("ascii"),
    }
    unsigned = CoreTimeProofV1.model_validate(unsigned_payload)
    signature = private_key.sign(unsigned.signing_payload())
    return CoreTimeProofV1.model_validate(
        unsigned_payload | {"signature_b64": base64.b64encode(signature).decode("ascii")}
    )


def secure_time_case(
    tmp_path: Path,
    *,
    rtc_qualified: bool = False,
    source: Literal["hardware", "synthetic"] = "hardware",
    failure: str | None = None,
    previous: CoreTimeProofV1 | None = None,
    cold_boot_utc: datetime = datetime(1970, 1, 1, tzinfo=UTC),
    private_key: Ed25519PrivateKey | None = None,
    proof_time_sequence: int = 11,
) -> SecureTimeCase:
    return SecureTimeCase(
        tmp_path,
        rtc_qualified=rtc_qualified,
        source=source,
        failure=failure,
        previous=previous,
        cold_boot_utc=cold_boot_utc,
        private_key=private_key,
        proof_time_sequence=proof_time_sequence,
    )


def canonical_proof_b64(proof: CoreTimeProofV1) -> str:
    return base64.b64encode(canonical_bytes(proof)).decode("ascii")


def canonical_proof_sha256(proof: CoreTimeProofV1) -> str:
    return hashlib.sha256(canonical_bytes(proof)).hexdigest()


class LegacySecureTimeStateForTest(ContractModel):
    schema_version: Literal["tuntun.reachy-secure-time-state.v1"]
    endpoint_generation: Annotated[int, Field(ge=1)]
    authority_health_generation: Annotated[int, Field(ge=1)]
    time_sequence: Annotated[int, Field(ge=1)]
    core_utc: datetime
    proof_sha256: Annotated[str, Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")]
    canonical_proof_sha256: Annotated[
        str,
        Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$"),
    ]
    canonical_proof_b64: Annotated[str, Field(min_length=4)]


def proof_from_state(state: SecureTimeStateV1) -> CoreTimeProofV1:
    return parse_contract_json(
        CoreTimeProofV1,
        base64.b64decode(state.canonical_proof_b64, validate=True),
        max_bytes=8_192,
        require_canonical=True,
    )


def overwrite_current_state(
    repository: SecureTimeStateRepository, state: SecureTimeStateV1
) -> None:
    path = repository.root / SECURE_TIME_STATE_NAME
    path.write_bytes(canonical_bytes(state))
    path.chmod(0o600)


def write_legacy_current_state(
    repository: SecureTimeStateRepository,
    proof: CoreTimeProofV1,
) -> None:
    legacy = LegacySecureTimeStateForTest(
        schema_version="tuntun.reachy-secure-time-state.v1",
        endpoint_generation=proof.endpoint_generation,
        authority_health_generation=proof.authority_health_generation,
        time_sequence=proof.time_sequence,
        core_utc=proof.core_utc,
        proof_sha256=hashlib.sha256(proof.signing_payload()).hexdigest(),
        canonical_proof_sha256=canonical_proof_sha256(proof),
        canonical_proof_b64=canonical_proof_b64(proof),
    )
    path = repository.root / SECURE_TIME_STATE_NAME
    path.write_bytes(canonical_bytes(legacy))
    path.chmod(0o600)


def assert_canonical_uuid(value: str | None) -> str:
    assert isinstance(value, str)
    assert str(UUID(value)) == value
    return value


@pytest.mark.asyncio
async def test_lost_clock_bootstraps_signed_core_time_before_strict_mtls(
    tmp_path: Path,
) -> None:
    case = secure_time_case(
        tmp_path,
        rtc_qualified=False,
        cold_boot_utc=datetime(1970, 1, 1, tzinfo=UTC),
    )

    mode = await case.boot()

    assert mode == "signed_core_bootstrap"
    assert case.events == [
        "emergency_firewall",
        "route_neighbor_verified",
        "leaf_pin_verified",
        "nonce_generated",
        "pinned_time_channel",
        "time_request_sent",
        "signed_time_verified",
        "clock_set",
        "time_state_fsynced",
        "bootstrap_closed",
        "strict_mtls_validity_verified",
        "strict_mtls_ready",
        "edge_ready",
    ]
    assert case.bootstrap_application_frames == []
    assert case.application_control_frames == []
    assert case.udp_123_attempts == []
    assert case.dns_queries == []
    assert case.strict_mtls.calls == 1
    assert case.strict_mtls.bootstrap_was_closed_before_strict is True
    assert case.bootstrap.last_channel is not None
    assert case.bootstrap.last_channel.promoted is False
    proof = case.proof_for_request(case.bootstrap.last_channel.time_requests[0])
    state = case.repository.require_previous()
    assert state is not None
    assert state.restore_status == "strict_mtls_ready"
    assert_canonical_uuid(state.boot_attempt_id)
    assert state.restore_attempt_id is None
    assert state.time_sequence == 11
    assert state.endpoint_generation == 7
    assert state.authority_health_generation == 5
    assert state.core_utc == NOW
    assert state.proof_sha256 == hashlib.sha256(proof.signing_payload()).hexdigest()
    assert state.canonical_proof_sha256 == canonical_proof_sha256(proof)
    assert state.canonical_proof_sha256 != state.proof_sha256
    assert proof_from_state(state) == proof
    deadlines = (
        case.route_neighbor.deadlines
        + case.leaf_verifier.deadlines
        + case.bootstrap.deadlines
        + case.bootstrap.last_channel.deadlines
        + case.clock.deadlines
        + case.strict_mtls.deadlines
    )
    assert deadlines
    assert set(deadlines) == {102.0}


@pytest.mark.asyncio
async def test_crash_after_commit_restores_canonical_proof_without_bootstrap(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    first = secure_time_case(
        tmp_path,
        rtc_qualified=False,
        failure="crash_after_commit_before_strict",
        private_key=private_key,
    )

    with pytest.raises(OSError, match="after_parent_fsync"):
        await first.boot()

    committed = first.repository.require_previous()
    assert committed is not None
    assert committed.restore_status == "pending_strict_mtls"
    committed_boot_attempt_id = assert_canonical_uuid(committed.boot_attempt_id)
    assert committed.restore_attempt_id is None
    committed_proof = proof_from_state(committed)
    assert committed.proof_sha256 == hashlib.sha256(committed_proof.signing_payload()).hexdigest()
    assert committed.canonical_proof_sha256 == canonical_proof_sha256(committed_proof)
    assert first.strict_mtls.calls == 0

    restarted = secure_time_case(
        tmp_path,
        rtc_qualified=False,
        cold_boot_utc=datetime(1970, 1, 1, tzinfo=UTC),
        private_key=private_key,
    )

    assert await restarted.boot() == "signed_core_bootstrap"
    assert restarted.bootstrap.nonces == []
    assert restarted.bootstrap.connections == 0
    assert restarted.strict_mtls.calls == 1
    assert restarted.clock.now_utc() == NOW
    restored_state = restarted.repository.require_previous()
    assert restored_state is not None
    assert restored_state.restore_status == "strict_mtls_ready"
    assert restored_state.boot_attempt_id != committed_boot_attempt_id
    assert restored_state.restore_attempt_id is None
    assert restored_state.canonical_proof_sha256 == committed.canonical_proof_sha256
    assert restored_state.time_sequence == committed.time_sequence
    assert restarted.events == [
        "emergency_firewall",
        "restore_consumed",
        "route_neighbor_verified",
        "leaf_pin_verified",
        "restored_committed_proof",
        "clock_set",
        "strict_mtls_validity_verified",
        "strict_mtls_ready",
        "edge_ready",
    ]


@pytest.mark.asyncio
async def test_clean_success_previous_state_fetches_new_proof_and_revalidates_route_neighbor(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    first = secure_time_case(tmp_path, rtc_qualified=False, private_key=private_key)
    assert await first.boot() == "signed_core_bootstrap"
    first_state = first.repository.require_previous()
    assert first_state is not None
    assert first_state.restore_status == "strict_mtls_ready"
    assert first_state.time_sequence == 11

    second = secure_time_case(
        tmp_path,
        rtc_qualified=False,
        private_key=private_key,
        proof_time_sequence=12,
    )

    assert await second.boot() == "signed_core_bootstrap"

    assert "route_neighbor_verified" in second.events
    assert "nonce_generated" in second.events
    assert "pinned_time_channel" in second.events
    assert "restored_committed_proof" not in second.events
    second_state = second.repository.require_previous()
    assert second_state is not None
    assert second_state.restore_status == "strict_mtls_ready"
    assert second_state.time_sequence == 12
    assert second_state.canonical_proof_sha256 != first_state.canonical_proof_sha256


@pytest.mark.asyncio
async def test_qualified_rtc_terminalizes_pending_window_before_later_unqualified_boot(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    first = secure_time_case(
        tmp_path,
        rtc_qualified=False,
        failure="crash_after_commit_before_strict",
        private_key=private_key,
    )
    with pytest.raises(OSError, match="after_parent_fsync"):
        await first.boot()
    pending = first.repository.require_previous()
    assert pending is not None
    assert pending.restore_status == "pending_strict_mtls"

    qualified = secure_time_case(
        tmp_path,
        rtc_qualified=True,
        cold_boot_utc=NOW,
        private_key=private_key,
    )
    assert await qualified.boot() == "qualified_rtc"

    assert qualified.bootstrap.connections == 0
    assert "restored_committed_proof" not in qualified.events
    assert "strict_mtls_ready" in qualified.events
    terminal = qualified.repository.require_previous()
    assert terminal is not None
    assert terminal.restore_status == "strict_mtls_ready"
    assert terminal.boot_attempt_id != pending.boot_attempt_id
    assert terminal.restore_attempt_id is None
    assert terminal.canonical_proof_sha256 == pending.canonical_proof_sha256

    later = secure_time_case(
        tmp_path,
        rtc_qualified=False,
        private_key=private_key,
        proof_time_sequence=terminal.time_sequence + 1,
    )
    assert await later.boot() == "signed_core_bootstrap"

    assert "restored_committed_proof" not in later.events
    assert "nonce_generated" in later.events
    assert "pinned_time_channel" in later.events
    assert later.bootstrap.connections == 1
    later_state = later.repository.require_previous()
    assert later_state is not None
    assert later_state.restore_status == "strict_mtls_ready"
    assert later_state.time_sequence == terminal.time_sequence + 1


@pytest.mark.asyncio
async def test_restore_consumed_state_is_not_restored_again_after_restore_failure(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    first = secure_time_case(
        tmp_path,
        rtc_qualified=False,
        failure="crash_after_commit_before_strict",
        private_key=private_key,
    )
    with pytest.raises(OSError, match="after_parent_fsync"):
        await first.boot()
    pending = first.repository.require_previous()
    assert pending is not None
    assert pending.restore_status == "pending_strict_mtls"

    failed_restore = secure_time_case(
        tmp_path,
        rtc_qualified=False,
        failure="route_neighbor_failure",
        private_key=private_key,
    )
    with pytest.raises(PermissionError, match="route_neighbor_not_verified"):
        await failed_restore.boot()
    consumed = failed_restore.repository.require_previous()
    assert consumed is not None
    assert consumed.restore_status == "restore_consumed"
    assert consumed.restore_attempt_id is not None

    final = secure_time_case(
        tmp_path,
        rtc_qualified=False,
        private_key=private_key,
        proof_time_sequence=consumed.time_sequence + 1,
    )
    assert await final.boot() == "signed_core_bootstrap"

    assert "restored_committed_proof" not in final.events
    assert "nonce_generated" in final.events
    assert "pinned_time_channel" in final.events
    final_state = final.repository.require_previous()
    assert final_state is not None
    assert final_state.time_sequence == consumed.time_sequence + 1


@pytest.mark.asyncio
async def test_restore_route_neighbor_drift_denies_before_clock_and_strict(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    first = secure_time_case(
        tmp_path,
        rtc_qualified=False,
        failure="crash_after_commit_before_strict",
        private_key=private_key,
    )
    with pytest.raises(OSError, match="after_parent_fsync"):
        await first.boot()

    restarted = secure_time_case(
        tmp_path,
        rtc_qualified=False,
        failure="route_neighbor_failure",
        private_key=private_key,
    )
    with pytest.raises(PermissionError, match="route_neighbor_not_verified"):
        await restarted.boot()

    assert "restore_consumed" in restarted.events
    assert "route_neighbor_verified" not in restarted.events
    assert "clock_set" not in restarted.events
    assert "strict_mtls_validity_verified" not in restarted.events
    assert restarted.edge_ready is False
    state = restarted.repository.require_previous()
    assert state is not None
    assert state.restore_status == "restore_consumed"


@pytest.mark.asyncio
async def test_legacy_secure_time_state_is_clean_previous_and_forces_fresh_bootstrap(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    case = secure_time_case(
        tmp_path,
        rtc_qualified=False,
        private_key=private_key,
        proof_time_sequence=8,
    )
    legacy_proof = signed_proof(
        private_key,
        time_sequence=7,
        core_utc=NOW - timedelta(seconds=1),
    )
    write_legacy_current_state(case.repository, legacy_proof)

    assert await case.boot() == "signed_core_bootstrap"

    assert "restored_committed_proof" not in case.events
    assert "route_neighbor_verified" in case.events
    assert "nonce_generated" in case.events
    assert "pinned_time_channel" in case.events
    state = case.repository.require_previous()
    assert state is not None
    assert state.restore_status == "strict_mtls_ready"
    assert state.time_sequence == 8


@pytest.mark.asyncio
async def test_strict_mtls_failure_marks_failed_with_same_deadline_and_stays_fail_closed(
    tmp_path: Path,
) -> None:
    case = secure_time_case(
        tmp_path,
        rtc_qualified=False,
        failure="strict_reconnect_validity_failure",
    )

    with pytest.raises(PermissionError, match="strict_reconnect_validity_failure"):
        await case.boot()

    assert case.edge_ready is False
    assert case.installed_table_kind == "emergency_default_drop"
    assert "edge_ready" not in case.events
    assert "strict_mtls_failed" in case.events
    state = case.repository.require_previous()
    assert state is not None
    assert state.restore_status == "strict_mtls_failed"
    assert_canonical_uuid(state.boot_attempt_id)
    assert state.restore_attempt_id is None
    deadlines = (
        case.route_neighbor.deadlines
        + case.leaf_verifier.deadlines
        + case.bootstrap.deadlines
        + (case.bootstrap.last_channel.deadlines if case.bootstrap.last_channel else [])
        + case.clock.deadlines
        + case.strict_mtls.deadlines
    )
    assert set(deadlines) == {102.0}


@pytest.mark.asyncio
async def test_strict_mtls_failed_status_write_respects_elapsed_boot_deadline(
    tmp_path: Path,
) -> None:
    case = secure_time_case(
        tmp_path,
        rtc_qualified=False,
        failure="strict_reconnect_deadline_exceeded",
    )

    with pytest.raises(TimeoutError, match="strict_mtls"):
        await case.boot()

    assert case.edge_ready is False
    assert case.installed_table_kind == "emergency_default_drop"
    assert "edge_ready" not in case.events
    state = case.repository.require_previous()
    assert state is not None
    assert state.restore_status == "pending_strict_mtls"


@pytest.mark.asyncio
async def test_restore_rejects_canonical_proof_commitment_tamper_without_bootstrap(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    first = secure_time_case(
        tmp_path,
        rtc_qualified=False,
        failure="crash_after_commit_before_strict",
        private_key=private_key,
    )
    with pytest.raises(OSError, match="after_parent_fsync"):
        await first.boot()
    state = first.repository.require_previous()
    assert state is not None
    assert state.restore_status == "pending_strict_mtls"
    proof = proof_from_state(state)
    tampered_proof = CoreTimeProofV1.model_validate(
        proof.model_dump(mode="python")
        | {"signature_b64": base64.b64encode(b"\x00" * 64).decode("ascii")}
    )
    overwrite_current_state(
        first.repository,
        state.model_copy(update={"canonical_proof_b64": canonical_proof_b64(tampered_proof)}),
    )

    restarted = secure_time_case(tmp_path, rtc_qualified=False, private_key=private_key)
    with pytest.raises(PermissionError, match="canonical_proof"):
        await restarted.boot()

    assert restarted.bootstrap.nonces == []
    assert restarted.bootstrap.connections == 0
    assert restarted.strict_mtls.calls == 0
    assert restarted.edge_ready is False


@pytest.mark.asyncio
async def test_restore_rejects_signature_tamper_even_when_canonical_commitment_matches(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    first = secure_time_case(
        tmp_path,
        rtc_qualified=False,
        failure="crash_after_commit_before_strict",
        private_key=private_key,
    )
    with pytest.raises(OSError, match="after_parent_fsync"):
        await first.boot()
    state = first.repository.require_previous()
    assert state is not None
    assert state.restore_status == "pending_strict_mtls"
    proof = proof_from_state(state)
    tampered_proof = CoreTimeProofV1.model_validate(
        proof.model_dump(mode="python")
        | {"signature_b64": base64.b64encode(b"\x00" * 64).decode("ascii")}
    )
    overwrite_current_state(
        first.repository,
        state.model_copy(
            update={
                "canonical_proof_b64": canonical_proof_b64(tampered_proof),
                "canonical_proof_sha256": canonical_proof_sha256(tampered_proof),
            }
        ),
    )

    restarted = secure_time_case(tmp_path, rtc_qualified=False, private_key=private_key)
    with pytest.raises(PermissionError, match="invalid_signature"):
        await restarted.boot()

    assert restarted.bootstrap.nonces == []
    assert restarted.bootstrap.connections == 0
    assert restarted.strict_mtls.calls == 0
    assert restarted.edge_ready is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure,match",
    (
        (None, "invalid_signature"),
        ("time_outside_server_leaf_validity", "server_leaf"),
    ),
)
async def test_restore_rejects_endpoint_key_mismatch_or_expired_leaf_without_bootstrap(
    tmp_path: Path,
    failure: str | None,
    match: str,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    first = secure_time_case(
        tmp_path,
        rtc_qualified=False,
        failure="crash_after_commit_before_strict",
        private_key=private_key,
    )
    with pytest.raises(OSError, match="after_parent_fsync"):
        await first.boot()

    restarted = secure_time_case(
        tmp_path,
        rtc_qualified=False,
        failure=failure,
        private_key=Ed25519PrivateKey.generate() if failure is None else private_key,
    )
    with pytest.raises(PermissionError, match=match):
        await restarted.boot()

    assert restarted.bootstrap.nonces == []
    assert restarted.bootstrap.connections == 0
    assert restarted.strict_mtls.calls == 0
    assert restarted.edge_ready is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    (
        "replayed_time_sequence",
        "signed_time_rollback",
        "tampered_forward_time",
        "core_authority_rollback",
        "core_authority_excessive_forward_step",
        "time_outside_server_leaf_validity",
        "time_outside_client_leaf_validity",
        "wrong_endpoint_generation",
        "wrong_nonce",
        "wrong_signing_key",
        "wrong_leaf",
        "wrong_public_key",
        "invalid_signature",
        "malformed_canonical_proof",
        "bootstrap_rtt_exceeded",
        "strict_reconnect_validity_failure",
        "strict_reconnect_deadline_exceeded",
        "route_neighbor_failure",
        "hostname_endpoint",
    ),
)
async def test_time_rollback_forward_or_binding_failure_never_reaches_app_mtls(
    tmp_path: Path,
    failure: str,
) -> None:
    previous: CoreTimeProofV1 | None = None
    if failure in {
        "replayed_time_sequence",
        "signed_time_rollback",
        "core_authority_rollback",
        "core_authority_excessive_forward_step",
    }:
        previous = signed_proof(
            Ed25519PrivateKey.generate(),
            core_utc=NOW,
            time_sequence=10,
            authority_health_generation=5
            if failure != "core_authority_excessive_forward_step"
            else 1,
        )
    case = secure_time_case(tmp_path, rtc_qualified=False, failure=failure, previous=previous)

    with pytest.raises((PermissionError, RuntimeError, TimeoutError, ValueError, ValidationError)):
        await case.boot()

    assert case.edge_ready is False
    assert case.application_control_frames == []
    assert case.installed_table_kind == "emergency_default_drop"
    if failure in {"wrong_leaf", "wrong_public_key", "route_neighbor_failure", "hostname_endpoint"}:
        assert case.bootstrap.nonces == []
        assert case.bootstrap.connections == 0
    if failure not in {"strict_reconnect_validity_failure", "strict_reconnect_deadline_exceeded"}:
        assert case.strict_mtls.calls == 0


@pytest.mark.asyncio
async def test_cancellation_preserves_cancelled_error_and_never_marks_ready(tmp_path: Path) -> None:
    case = secure_time_case(tmp_path, rtc_qualified=False, failure="cancelled")

    with pytest.raises(asyncio.CancelledError):
        await case.boot()

    assert case.edge_ready is False
    assert case.firewall.installed_table_kind == "emergency_default_drop"
    assert case.strict_mtls.calls == 0


@pytest.mark.asyncio
async def test_rtc_path_requires_real_unplugged_cold_boot_qualification(tmp_path: Path) -> None:
    unqualified = secure_time_case(
        tmp_path / "unqualified",
        rtc_qualified=False,
        cold_boot_utc=datetime(1970, 1, 1, tzinfo=UTC),
    )
    assert await unqualified.boot() == "signed_core_bootstrap"
    assert unqualified.bootstrap.connections == 1

    synthetic_claim = secure_time_case(
        tmp_path / "synthetic",
        rtc_qualified=True,
        source="synthetic",
    )
    assert await synthetic_claim.boot() == "signed_core_bootstrap"
    assert synthetic_claim.bootstrap.connections == 1

    qualified = secure_time_case(tmp_path / "qualified", rtc_qualified=True, cold_boot_utc=NOW)
    assert await qualified.boot() == "qualified_rtc"
    assert qualified.bootstrap.connections == 0
    assert qualified.strict_mtls.calls == 1
    assert "strict_mtls_validity_verified" in qualified.events

    previous = signed_proof(Ed25519PrivateKey.generate(), core_utc=NOW)
    rolled_back = secure_time_case(
        tmp_path / "rolled-back",
        rtc_qualified=True,
        previous=previous,
        cold_boot_utc=NOW - timedelta(seconds=5),
    )
    with pytest.raises(PermissionError, match="rollback"):
        await rolled_back.boot()
    assert rolled_back.bootstrap.connections == 0
    assert rolled_back.strict_mtls.calls == 0

    expired_leaf = secure_time_case(
        tmp_path / "expired-leaf",
        rtc_qualified=True,
        failure="time_outside_server_leaf_validity",
        cold_boot_utc=NOW,
    )
    with pytest.raises(PermissionError, match="server_leaf"):
        await expired_leaf.boot()
    assert expired_leaf.bootstrap.connections == 0
    assert expired_leaf.strict_mtls.calls == 0


def test_state_repository_is_owner_only_canonical_atomic_and_cas_guarded(tmp_path: Path) -> None:
    repository = SecureTimeStateRepository(tmp_path / "secure-time")
    proof = signed_proof(Ed25519PrivateKey.generate())
    proof_sha256 = hashlib.sha256(proof.signing_payload()).hexdigest()

    repository.replace_atomic(
        proof,
        proof_sha256,
        expected_previous=None,
        deadline_monotonic=102.0,
        boot_attempt_id=BOOT_ATTEMPT_ID,
        monotonic=lambda: 100.0,
    )

    path = tmp_path / "secure-time" / "secure-time-state.json"
    assert stat.S_IMODE((tmp_path / "secure-time").stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    state = repository.require_previous()
    assert state == SecureTimeStateV1(
        schema_version="tuntun.reachy-secure-time-state.v1",
        restore_status="pending_strict_mtls",
        boot_attempt_id=BOOT_ATTEMPT_ID,
        restore_attempt_id=None,
        endpoint_generation=proof.endpoint_generation,
        authority_health_generation=proof.authority_health_generation,
        time_sequence=proof.time_sequence,
        core_utc=proof.core_utc,
        proof_sha256=proof_sha256,
        canonical_proof_sha256=canonical_proof_sha256(proof),
        canonical_proof_b64=canonical_proof_b64(proof),
    )
    assert path.read_bytes() == canonical_bytes(state)

    stale = state
    next_proof = signed_proof(Ed25519PrivateKey.generate(), time_sequence=12)
    repository.replace_atomic(
        next_proof,
        hashlib.sha256(next_proof.signing_payload()).hexdigest(),
        expected_previous=stale,
        deadline_monotonic=102.0,
        boot_attempt_id=NEXT_BOOT_ATTEMPT_ID,
        monotonic=lambda: 100.0,
    )
    with pytest.raises(PermissionError, match="cas"):
        stale_reject_proof = signed_proof(Ed25519PrivateKey.generate(), time_sequence=13)
        repository.replace_atomic(
            stale_reject_proof,
            hashlib.sha256(stale_reject_proof.signing_payload()).hexdigest(),
            expected_previous=stale,
            deadline_monotonic=102.0,
            boot_attempt_id=RESTORE_ATTEMPT_ID,
            monotonic=lambda: 100.0,
        )


@pytest.mark.parametrize(
    "stage,committed",
    (
        ("after_file_fsync", False),
        ("after_replace_before_parent_fsync", True),
    ),
)
def test_state_repository_crash_windows_are_fail_closed_and_reopenable(
    tmp_path: Path,
    stage: str,
    committed: bool,
) -> None:
    assert stage in SECURE_TIME_PUBLISH_FAULT_STAGES
    repository = SecureTimeStateRepository(tmp_path / "secure-time")
    proof = signed_proof(Ed25519PrivateKey.generate())
    repository.inject_crash_at(stage)

    with pytest.raises(OSError, match="secure time publish fault"):
        repository.replace_atomic(
            proof,
            hashlib.sha256(proof.signing_payload()).hexdigest(),
            expected_previous=None,
            deadline_monotonic=102.0,
            boot_attempt_id=BOOT_ATTEMPT_ID,
            monotonic=lambda: 100.0,
        )

    reopened = SecureTimeStateRepository(tmp_path / "secure-time")
    if committed:
        assert reopened.require_previous() is not None
    else:
        assert reopened.require_previous() is None


def test_state_repository_rejects_symlink_hardlink_oversize_and_noncanonical_state(
    tmp_path: Path,
) -> None:
    root = tmp_path / "secure-time"
    repository = SecureTimeStateRepository(root)
    current = root / "secure-time-state.json"
    current.symlink_to(tmp_path / "elsewhere.json")
    with pytest.raises(PermissionError):
        repository.require_previous()
    current.unlink()

    current.write_bytes(b"{\n}")
    current.chmod(0o600)
    with pytest.raises(ValueError):
        repository.require_previous()
    current.unlink()

    current.write_bytes(b"{" + b'"x":' + (b'"a"' * MAX_SECURE_TIME_STATE_BYTES) + b"}")
    current.chmod(0o600)
    with pytest.raises(ValueError):
        repository.require_previous()
    current.unlink()

    proof = signed_proof(Ed25519PrivateKey.generate())
    repository.replace_atomic(
        proof,
        hashlib.sha256(proof.signing_payload()).hexdigest(),
        expected_previous=None,
        deadline_monotonic=102.0,
        boot_attempt_id=BOOT_ATTEMPT_ID,
        monotonic=lambda: 100.0,
    )
    os.link(current, root / "second-link.json")
    with pytest.raises(PermissionError):
        repository.require_previous()


def test_state_repository_requires_exact_private_directory_and_deadline_lock(
    tmp_path: Path,
) -> None:
    bad_root = tmp_path / "bad"
    bad_root.mkdir(0o755)
    bad_root.chmod(0o755)
    with pytest.raises(PermissionError):
        SecureTimeStateRepository(bad_root)

    repository = SecureTimeStateRepository(tmp_path / "secure-time")
    lock_path = tmp_path / "secure-time" / ".secure-time-state.lock"
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        import fcntl

        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        proof = signed_proof(Ed25519PrivateKey.generate())
        lock_calls = 0

        def lock_monotonic() -> float:
            nonlocal lock_calls
            lock_calls += 1
            return 100.0 + (lock_calls * 0.02)

        with pytest.raises(TimeoutError, match="lock"):
            repository.replace_atomic(
                proof,
                hashlib.sha256(proof.signing_payload()).hexdigest(),
                expected_previous=None,
                deadline_monotonic=100.01,
                boot_attempt_id=BOOT_ATTEMPT_ID,
                monotonic=lock_monotonic,
            )
    finally:
        os.close(lock_fd)


def test_secure_time_state_model_is_strict_closed_and_bounded() -> None:
    proof = signed_proof(Ed25519PrivateKey.generate())
    state = SecureTimeStateV1(
        schema_version="tuntun.reachy-secure-time-state.v1",
        restore_status="pending_strict_mtls",
        boot_attempt_id=BOOT_ATTEMPT_ID,
        restore_attempt_id=None,
        endpoint_generation=proof.endpoint_generation,
        authority_health_generation=proof.authority_health_generation,
        time_sequence=proof.time_sequence,
        core_utc=proof.core_utc,
        proof_sha256=hashlib.sha256(proof.signing_payload()).hexdigest(),
        canonical_proof_sha256=canonical_proof_sha256(proof),
        canonical_proof_b64=canonical_proof_b64(proof),
    )
    assert state.model_config["extra"] == "forbid"
    assert state.model_config["frozen"] is True
    assert state.model_config["strict"] is True
    assert SecureTimeStateV1.model_json_schema()["properties"]["core_utc"][
        "x-tuntun-field-safety"
    ] == {
        "canonical_serialization_offset": "Z",
        "constraint": "utc-offset-zero-datetime",
        "required_utc_offset_seconds": 0,
        "runtime_authoritative": True,
    }
    with pytest.raises(ValidationError):
        SecureTimeStateV1.model_validate(state.model_dump() | {"extra": True})
    with pytest.raises(ValidationError):
        SecureTimeStateV1.model_validate(state.model_dump() | {"proof_sha256": "A" * 64})
    with pytest.raises(ValidationError):
        SecureTimeStateV1.model_validate(state.model_dump() | {"canonical_proof_sha256": "A" * 64})
    with pytest.raises(ValidationError):
        SecureTimeStateV1.model_validate(
            state.model_dump() | {"canonical_proof_b64": canonical_proof_b64(proof) + "\n"}
        )
    with pytest.raises(ValidationError):
        SecureTimeStateV1.model_validate(state.model_dump() | {"time_sequence": 0})
    with pytest.raises(ValidationError, match="boot_attempt_id is required"):
        SecureTimeStateV1.model_validate(
            state.model_dump()
            | {
                "restore_status": "pending_strict_mtls",
                "boot_attempt_id": None,
                "restore_attempt_id": None,
            }
        )
    with pytest.raises(ValidationError, match="restore_attempt_id is required"):
        SecureTimeStateV1.model_validate(
            state.model_dump()
            | {
                "restore_status": "restore_consumed",
                "boot_attempt_id": BOOT_ATTEMPT_ID,
                "restore_attempt_id": None,
            }
        )
    with pytest.raises(ValidationError, match="only allowed"):
        SecureTimeStateV1.model_validate(
            state.model_dump()
            | {
                "restore_status": "strict_mtls_ready",
                "boot_attempt_id": BOOT_ATTEMPT_ID,
                "restore_attempt_id": RESTORE_ATTEMPT_ID,
            }
        )
    with pytest.raises(ValidationError, match="legacy_clean"):
        SecureTimeStateV1.model_validate(
            state.model_dump()
            | {
                "restore_status": "legacy_clean",
                "boot_attempt_id": BOOT_ATTEMPT_ID,
                "restore_attempt_id": None,
            }
        )
    with pytest.raises(ValidationError):
        SecureTimeStateV1.model_validate(
            state.model_dump()
            | {"core_utc": datetime(2026, 8, 27, 9, tzinfo=timezone(timedelta(hours=8)))}
        )
