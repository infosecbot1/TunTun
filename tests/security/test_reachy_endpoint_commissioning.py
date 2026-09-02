from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any, Literal

import pytest
import tuntun_edge.transport as transport_exports
import tuntun_edge.transport.commissioning as commissioning_module
from pydantic import ValidationError
from tuntun_contracts.base import ContractModel, ContractParseError, canonical_bytes
from tuntun_contracts.reachy_operator import ReachyAcceptedCapabilityV1, ReachyOperatorStateV1
from tuntun_edge.transport import commissioning_repository as repository_module
from tuntun_edge.transport.commissioning import (
    CommissioningStateV1,
    GeneratedReachyMaterialV1,
    IssuedClientMaterialV1,
    LocalPhysicalProof,
    PreparedCoreMaterialV1,
    ReachyCommissioningRequestV1,
    ReachyCommissioningService,
    ReachyCoreEndpointV1,
    SyntheticCoreCommissioningIssuer,
    SyntheticReachyPrivateMaterialGenerator,
    _SyntheticLocalPhysicalEvidence,
    _SyntheticLocalPhysicalProofIssuer,
)
from tuntun_edge.transport.commissioning_repository import (
    COMMISSIONING_PUBLISH_FAULT_STAGES,
    MAX_COMMISSIONING_STATE_BYTES,
    CommissioningRepository,
    OwnerOnlyArtifactStore,
    ReachyOperatorAcceptancePublisher,
    ReachyOperatorStateRepository,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _uuid(generation: int) -> str:
    return f"00000000-0000-4000-8000-{generation:012d}"


def _key_ids(endpoint: ReachyCoreEndpointV1) -> tuple[str, str, str, str]:
    return (
        endpoint.server_key_id,
        endpoint.client_tls_key_id,
        endpoint.device_signing_key_id,
        endpoint.hmac_key_id,
    )


def _certificate_digests(endpoint: ReachyCoreEndpointV1) -> tuple[str, str]:
    return (endpoint.server_leaf_sha256, endpoint.client_certificate_sha256)


def _state_digest(state: CommissioningStateV1) -> str:
    return hashlib.sha256(canonical_bytes(state)).hexdigest()


def _request(
    generation: int = 1,
    *,
    core_ipv4: str = "192.168.50.10",
    core_link_address: str = "02:00:5e:00:53:01",
) -> ReachyCommissioningRequestV1:
    return ReachyCommissioningRequestV1(
        schema_version="tuntun.reachy-commissioning-request.v1",
        commissioning_uuid=_uuid(generation),
        core_ipv4=core_ipv4,
        core_link_address=core_link_address,
        port=7443,
        boot_identity_sha256=_digest(f"boot-{generation}"),
        capability_evidence_sha256=_digest(f"capability-{generation}"),
        dhcp_reservation_receipt_sha256=_digest(f"dhcp-{generation}"),
    )


def _endpoint(
    generation: int = 1,
    *,
    core_ipv4: str = "192.168.50.10",
    overrides: dict[str, object] | None = None,
) -> ReachyCoreEndpointV1:
    values: dict[str, object] = {
        "schema_version": "tuntun.reachy-core-endpoint.v1",
        "commissioning_uuid": _uuid(generation),
        "generation": generation,
        "certificate_generation": generation,
        "server_key_generation": generation,
        "trust_digest_generation": generation,
        "client_tls_key_generation": generation,
        "device_signing_key_generation": generation,
        "hmac_key_generation": generation,
        "core_ipv4": core_ipv4,
        "core_link_address": "02:00:5e:00:53:01",
        "port": 7443,
        "household_ca_sha256": _digest(f"ca-{generation}"),
        "server_leaf_sha256": _digest(f"server-leaf-{generation}"),
        "server_key_id": f"reachy-server-g{generation}",
        "server_public_key_sha256": _digest(f"server-public-{generation}"),
        "server_ip_sans": (core_ipv4,),
        "client_certificate_sha256": _digest(f"client-cert-{generation}"),
        "client_tls_key_id": f"reachy-client-tls-g{generation}",
        "client_tls_public_key_sha256": _digest(f"client-public-{generation}"),
        "device_signing_key_id": f"reachy-device-sign-g{generation}",
        "device_signing_public_key_sha256": _digest(f"device-public-{generation}"),
        "hmac_key_id": f"reachy-frame-hmac-g{generation}",
        "hmac_key_sha256": _digest(f"hmac-root-{generation}"),
        "hmac_agreement_public_key_sha256": _digest(f"hmac-public-{generation}"),
        "dhcp_reservation_receipt_sha256": _digest(f"dhcp-{generation}"),
        "boot_identity_sha256": _digest(f"boot-{generation}"),
        "capability_evidence_sha256": _digest(f"capability-{generation}"),
    }
    if overrides is not None:
        values.update(overrides)
        if "core_ipv4" in overrides and "server_ip_sans" not in overrides:
            values["server_ip_sans"] = (overrides["core_ipv4"],)
    return ReachyCoreEndpointV1.model_validate(values)


def _state(
    generation: int = 1,
    *,
    previous: CommissioningStateV1 | None = None,
    status: Literal["active", "revoked"] = "active",
    endpoint_overrides: dict[str, object] | None = None,
) -> CommissioningStateV1:
    endpoint = _endpoint(generation, overrides=endpoint_overrides)
    if previous is None and status == "active":
        revoked_key_ids: tuple[str, ...] = ()
        revoked_certificate_sha256: tuple[str, ...] = ()
    elif status == "revoked":
        revoked_key_ids = _key_ids(endpoint)
        revoked_certificate_sha256 = _certificate_digests(endpoint)
    else:
        assert previous is not None
        revoked_key_ids = _key_ids(previous.endpoint)
        revoked_certificate_sha256 = _certificate_digests(previous.endpoint)
    return CommissioningStateV1(
        schema_version="tuntun.reachy-commissioning-state.v1",
        status=status,
        endpoint=endpoint,
        revoked_key_ids=revoked_key_ids,
        revoked_certificate_sha256=revoked_certificate_sha256,
    )


def _write_owner_file(path: Path, payload: bytes, mode: int = 0o600) -> None:
    path.write_bytes(payload)
    path.chmod(mode)


class _RawPath:
    def __init__(self, value: str) -> None:
        self._value = value

    def __fspath__(self) -> str:
        return self._value


def _physical_evidence() -> _SyntheticLocalPhysicalEvidence:
    return _SyntheticLocalPhysicalEvidence(
        local_tty=True,
        ssh_host_key_verified=True,
        one_time_code_verified=True,
        dhcp_reservations_verified=True,
    )


def _proof_for(
    issuer: _SyntheticLocalPhysicalProofIssuer,
    *,
    operation: Literal["commission", "recommission", "revoke"],
    request: ReachyCommissioningRequestV1 | None = None,
    current: CommissioningStateV1 | None = None,
) -> LocalPhysicalProof:
    return issuer.issue(
        _physical_evidence(),
        operation=operation,
        request=request,
        current=current,
    )


def _accepted_capability(username: str = "tuntunops") -> ReachyAcceptedCapabilityV1:
    return ReachyAcceptedCapabilityV1(
        capability_report_sha256=_digest("capability-report"),
        acceptance_receipt_sha256=_digest("acceptance-receipt"),
        sdk_version="1.2.3",
        daemon_version="4.5.6",
        ssh_username=username,
        python_executable="/venvs/apps_venv/bin/python3",
        python_version="3.12",
        python_abi="cp312",
        selected_wheel_tag="py3-none-any",
        target_tag_set_sha256=_digest("target-tags"),
        runtime_inventory_sha256=_digest("runtime-inventory"),
    )


def _operator_state(
    commissioning_state: CommissioningStateV1,
    *,
    accepted: bool = True,
) -> ReachyOperatorStateV1:
    return ReachyOperatorStateV1(
        schema_version="tuntun.reachy-operator-state.v1",
        commissioning_generation=commissioning_state.endpoint.generation,
        commissioning_state_sha256=_state_digest(commissioning_state),
        ssh_username="tuntunops",
        reachy_ipv4="192.168.50.20",
        core_ipv4=commissioning_state.endpoint.core_ipv4,
        pinned_ssh_host_key_sha256=_digest("ssh-host-key"),
        dhcp_receipt_sha256=commissioning_state.endpoint.dhcp_reservation_receipt_sha256,
        accepted_capability=_accepted_capability() if accepted else None,
    )


def test_endpoint_models_are_contract_models_with_no_peer_interface_authority() -> None:
    assert issubclass(ReachyCoreEndpointV1, ContractModel)
    assert issubclass(CommissioningStateV1, ContractModel)
    assert issubclass(ReachyCommissioningRequestV1, ContractModel)
    assert not {
        "reachy_ingress_interface",
        "core_interface",
        "mdns_name",
        "discovery_name",
    } & set(ReachyCoreEndpointV1.model_fields)


@pytest.mark.parametrize("raw_component", (".", ".."))
def test_repository_rejects_raw_dot_path_components_before_normalization(
    tmp_path: Path,
    raw_component: str,
) -> None:
    raw_path = _RawPath(f"{tmp_path}/{raw_component}/commissioning")

    with pytest.raises(PermissionError, match="unsafe commissioning filesystem path"):
        CommissioningRepository(raw_path)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "address",
    (
        "192.168.001.010",
        "10.0.0.01",
        "172.016.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "100.64.0.1",
        "172.15.255.255",
        "172.32.0.1",
        "203.0.113.10",
        "192.168.50.10 ",
    ),
)
def test_endpoint_rejects_noncanonical_or_non_rfc1918_core_ipv4(address: str) -> None:
    with pytest.raises(ValidationError, match="RFC1918"):
        _endpoint(core_ipv4=address)


@pytest.mark.parametrize(
    "link_address",
    (
        "00:00:00:00:00:00",
        "ff:ff:ff:ff:ff:ff",
        "01:00:5e:00:53:01",
        "33:33:00:00:00:01",
        "03:00:5e:00:53:01",
    ),
)
def test_endpoint_rejects_zero_broadcast_and_group_mac_addresses(link_address: str) -> None:
    with pytest.raises(ValidationError, match="unicast"):
        _request(core_link_address=link_address)
    with pytest.raises(ValidationError, match="unicast"):
        _endpoint(overrides={"core_link_address": link_address})


def test_endpoint_binds_exact_single_numeric_ip_san_and_matching_generations() -> None:
    endpoint = _endpoint()
    assert endpoint.core_ipv4 == "192.168.50.10"
    assert endpoint.server_ip_sans == ("192.168.50.10",)

    for server_ip_sans in ((), ("192.168.50.10", "192.168.50.10"), ("192.168.50.11",)):
        with pytest.raises(ValidationError, match="exact numeric Mac IP SAN"):
            _endpoint(overrides={"server_ip_sans": server_ip_sans})

    for generation_field in (
        "certificate_generation",
        "server_key_generation",
        "trust_digest_generation",
        "client_tls_key_generation",
        "device_signing_key_generation",
        "hmac_key_generation",
    ):
        with pytest.raises(ValidationError, match="mixed generations"):
            _endpoint(overrides={generation_field: 2})


def test_commissioning_state_revocation_inventory_is_closed_bounded_unique() -> None:
    first = _state(1)
    second = _state(2, previous=first)
    assert second.revoked_key_ids == _key_ids(first.endpoint)
    assert second.revoked_certificate_sha256 == _certificate_digests(first.endpoint)

    with pytest.raises(ValidationError, match="initial generation cannot revoke material"):
        CommissioningStateV1(
            schema_version="tuntun.reachy-commissioning-state.v1",
            status="active",
            endpoint=first.endpoint,
            revoked_key_ids=(first.endpoint.server_key_id,),
            revoked_certificate_sha256=(),
        )
    with pytest.raises(ValidationError, match="exactly four"):
        CommissioningStateV1(
            schema_version="tuntun.reachy-commissioning-state.v1",
            status="active",
            endpoint=second.endpoint,
            revoked_key_ids=second.revoked_key_ids[:3],
            revoked_certificate_sha256=second.revoked_certificate_sha256,
        )
    with pytest.raises(ValidationError, match="unique"):
        CommissioningStateV1(
            schema_version="tuntun.reachy-commissioning-state.v1",
            status="active",
            endpoint=second.endpoint,
            revoked_key_ids=(second.revoked_key_ids[0],) * 4,
            revoked_certificate_sha256=second.revoked_certificate_sha256,
        )
    with pytest.raises(ValidationError):
        CommissioningStateV1(
            schema_version="tuntun.reachy-commissioning-state.v1",
            status="active",
            endpoint=second.endpoint,
            revoked_key_ids=second.revoked_key_ids,
            revoked_certificate_sha256=("not-a-digest",),
        )


@pytest.mark.parametrize(
    "mutation",
    ("symlink", "hardlink", "wrong_mode", "oversize", "duplicate_key", "noncanonical"),
)
def test_repository_rejects_hostile_owner_state_files(tmp_path: Path, mutation: str) -> None:
    repository = CommissioningRepository(tmp_path / "commissioning")
    state = _state(1)
    repository.replace_atomic(state)

    if mutation == "symlink":
        target = repository.root / "displaced-state.json"
        repository.path.rename(target)
        repository.path.symlink_to(target.name)
        expected_error: type[BaseException] = PermissionError
    elif mutation == "hardlink":
        os.link(repository.path, repository.root / "linked-state.json")
        expected_error = PermissionError
    elif mutation == "wrong_mode":
        repository.path.chmod(0o644)
        expected_error = PermissionError
    elif mutation == "oversize":
        _write_owner_file(repository.path, b"{" + (b" " * MAX_COMMISSIONING_STATE_BYTES))
        expected_error = ValueError
    elif mutation == "duplicate_key":
        _write_owner_file(
            repository.path,
            b'{"schema_version":"x","schema_version":"x"}',
        )
        expected_error = ContractParseError
    else:
        _write_owner_file(
            repository.path,
            json.dumps(state.model_dump(mode="json"), indent=2).encode("utf-8"),
        )
        expected_error = ContractParseError

    with pytest.raises(expected_error):
        repository.require_current()


def test_repository_rejects_named_inode_swap_after_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = CommissioningRepository(tmp_path / "commissioning")
    first = _state(1)
    second = _state(2, previous=first, endpoint_overrides={"core_ipv4": "192.168.50.11"})
    repository.replace_atomic(first)
    replacement = repository.root / "replacement-state.json"
    _write_owner_file(replacement, canonical_bytes(second))
    displaced = repository.root / "displaced-state.json"
    named_stats = 0
    swapped = False
    real_stat = repository_module.OS_MODULE.stat

    def swap_on_second_named_stat(
        path: int | str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        nonlocal named_stats
        nonlocal swapped
        if path == repository.path.name and dir_fd is not None and not follow_symlinks:
            named_stats += 1
            if named_stats == 2 and not swapped:
                os.replace(repository.path, displaced)
                os.replace(replacement, repository.path)
                swapped = True
        return real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(repository_module.OS_MODULE, "stat", swap_on_second_named_stat)

    with pytest.raises(PermissionError, match="changed during read"):
        repository.require_current()
    assert swapped


@pytest.mark.parametrize("mutation", ("growth", "truncation"))
def test_repository_rejects_state_growth_or_truncation_during_exact_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    repository = CommissioningRepository(tmp_path / "commissioning")
    repository.replace_atomic(_state(1))
    mutated = False
    real_read = repository_module.OS_MODULE.read

    def mutate_after_first_payload_read(descriptor: int, byte_count: int) -> bytes:
        nonlocal mutated
        chunk = real_read(descriptor, byte_count)
        if chunk and not mutated:
            if mutation == "growth":
                with repository.path.open("ab") as handle:
                    handle.write(b" ")
            else:
                with repository.path.open("r+b") as handle:
                    handle.truncate(len(chunk))
            mutated = True
        return bytes(chunk)

    monkeypatch.setattr(repository_module.OS_MODULE, "read", mutate_after_first_payload_read)

    with pytest.raises(ValueError, match="changed during read|size invalid"):
        repository.require_current()


def test_repository_rejects_owner_mode_change_during_descriptor_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = CommissioningRepository(tmp_path / "commissioning")
    repository.replace_atomic(_state(1))
    mutated = False
    real_read = repository_module.OS_MODULE.read

    def chmod_after_first_payload_read(descriptor: int, byte_count: int) -> bytes:
        nonlocal mutated
        chunk = real_read(descriptor, byte_count)
        if chunk and not mutated:
            repository.path.chmod(0o644)
            mutated = True
        return bytes(chunk)

    monkeypatch.setattr(repository_module.OS_MODULE, "read", chmod_after_first_payload_read)

    with pytest.raises(PermissionError, match="owner-only|changed during read"):
        repository.require_current()


@pytest.mark.parametrize("stage", COMMISSIONING_PUBLISH_FAULT_STAGES)
def test_atomic_publish_faults_leave_only_old_or_new_complete_state(
    tmp_path: Path,
    stage: str,
) -> None:
    repository = CommissioningRepository(tmp_path / "commissioning")
    first = _state(1)
    second = _state(2, previous=first, endpoint_overrides={"core_ipv4": "192.168.50.11"})
    repository.replace_atomic(first)

    repository.inject_crash_at(stage)
    with pytest.raises(OSError, match=stage):
        repository.replace_atomic(second, expected_current=first)

    visible = repository.reopen().require_current()
    assert visible in {first, second}
    assert canonical_bytes(visible) in {canonical_bytes(first), canonical_bytes(second)}
    assert not any(
        name.startswith(".commissioning-state.") and name.endswith(".tmp")
        for name in os.listdir(repository.root)
    )


def test_repository_rejects_named_lock_replacement_after_flock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = CommissioningRepository(tmp_path / "commissioning")
    first = _state(1)
    second = _state(2, previous=first, endpoint_overrides={"core_ipv4": "192.168.50.11"})
    repository.replace_atomic(first)
    replaced = False
    real_flock = fcntl.flock

    def replace_named_lock_after_acquire(descriptor: int, operation: int) -> None:
        nonlocal replaced
        real_flock(descriptor, operation)
        if operation & fcntl.LOCK_EX and operation & fcntl.LOCK_NB and not replaced:
            lock_path = repository.root / repository_module.COMMISSIONING_LOCK_NAME
            displaced = repository.root / "displaced-commissioning-state.lock"
            os.replace(lock_path, displaced)
            lock_path.write_bytes(b"")
            lock_path.chmod(0o600)
            replaced = True

    monkeypatch.setattr(fcntl, "flock", replace_named_lock_after_acquire)

    with pytest.raises(PermissionError, match="commissioning lock identity changed"):
        repository.replace_atomic(second, expected_current=first)

    assert replaced
    assert repository.require_current() == first


def test_repository_requires_exact_current_endpoint_cas_for_next_generation(
    tmp_path: Path,
) -> None:
    repository = CommissioningRepository(tmp_path / "commissioning")
    first = _state(1)
    same_generation_replacement = _state(
        1,
        endpoint_overrides={"core_ipv4": "192.168.50.12"},
    )
    next_generation = _state(2, previous=first, endpoint_overrides={"core_ipv4": "192.168.50.11"})
    repository.replace_atomic(first)
    _write_owner_file(repository.path, canonical_bytes(same_generation_replacement))

    with pytest.raises(PermissionError, match="commissioning_current_endpoint_cas_failed"):
        repository.replace_atomic(next_generation, expected_current=first)

    assert repository.require_current() == same_generation_replacement


def test_repository_requires_exact_current_cas_for_generation_one_replacement(
    tmp_path: Path,
) -> None:
    repository = CommissioningRepository(tmp_path / "commissioning")
    first = _state(1)
    same_generation_replacement = _state(
        1,
        endpoint_overrides={"core_ipv4": "192.168.50.12"},
    )
    repository.replace_atomic(first)

    with pytest.raises(PermissionError, match="commissioning_current_endpoint_cas_required"):
        repository.replace_atomic(same_generation_replacement, expected_generation=1)

    assert repository.require_current() == first


def test_repository_rejects_unrelated_or_incomplete_recommission_tombstones(
    tmp_path: Path,
) -> None:
    repository = CommissioningRepository(tmp_path / "commissioning")
    first = _state(1)
    repository.replace_atomic(first)
    next_endpoint = _endpoint(2, core_ipv4="192.168.50.11")

    for revoked_key_ids, revoked_certificate_sha256 in (
        (
            (
                first.endpoint.server_key_id,
                first.endpoint.client_tls_key_id,
                first.endpoint.device_signing_key_id,
                "unrelated-key-id",
            ),
            _certificate_digests(first.endpoint),
        ),
        (
            _key_ids(first.endpoint),
            (first.endpoint.server_leaf_sha256, _digest("unrelated-certificate")),
        ),
    ):
        state = CommissioningStateV1(
            schema_version="tuntun.reachy-commissioning-state.v1",
            status="active",
            endpoint=next_endpoint,
            revoked_key_ids=revoked_key_ids,
            revoked_certificate_sha256=revoked_certificate_sha256,
        )

        with pytest.raises(PermissionError, match="commissioning_revocation_inventory_mismatch"):
            repository.replace_atomic(state, expected_current=first)


def test_repository_rejects_revocation_that_changes_current_endpoint(
    tmp_path: Path,
) -> None:
    repository = CommissioningRepository(tmp_path / "commissioning")
    first = _state(1)
    repository.replace_atomic(first)
    wrong_endpoint_revocation = _state(
        1,
        status="revoked",
        endpoint_overrides={"core_ipv4": "192.168.50.11"},
    )

    with pytest.raises(PermissionError, match="commissioning_revocation_endpoint_mismatch"):
        repository.replace_atomic(wrong_endpoint_revocation, expected_current=first)

    assert repository.require_current() == first


class RecordingAcceptancePublisher:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.fail_next = False

    def clear_before_recommission(self, state: CommissioningStateV1) -> None:
        self.events.append(f"acceptance.clear.recommission.{state.endpoint.generation}")
        if self.fail_next:
            self.fail_next = False
            raise OSError("scripted acceptance clear failure")

    def clear_before_revoke(self, state: CommissioningStateV1) -> None:
        self.events.append(f"acceptance.clear.revoke.{state.endpoint.generation}")
        if self.fail_next:
            self.fail_next = False
            raise OSError("scripted acceptance clear failure")


class RecordingRepository(CommissioningRepository):
    def __init__(self, root: Path, events: list[str]) -> None:
        super().__init__(root)
        self.events = events

    def replace_atomic(
        self,
        state: CommissioningStateV1,
        *,
        expected_generation: int | None = None,
        expected_current: CommissioningStateV1 | None = None,
        assurance: object | None = None,
    ) -> None:
        self.events.append(f"repository.publish.{state.endpoint.generation}.{state.status}")
        super().replace_atomic(
            state,
            expected_generation=expected_generation,
            expected_current=expected_current,
            assurance=assurance,
        )


class AmbiguousPublicationRepository(RecordingRepository):
    def __init__(self, root: Path, events: list[str]) -> None:
        super().__init__(root, events)
        self.fail_current_read_after_publish_error = False

    def replace_atomic(
        self,
        state: CommissioningStateV1,
        *,
        expected_generation: int | None = None,
        expected_current: CommissioningStateV1 | None = None,
        assurance: object | None = None,
    ) -> None:
        try:
            super().replace_atomic(
                state,
                expected_generation=expected_generation,
                expected_current=expected_current,
                assurance=assurance,
            )
        except OSError:
            self.fail_current_read_after_publish_error = True
            raise

    def require_current(self) -> CommissioningStateV1:
        if self.fail_current_read_after_publish_error:
            raise OSError("scripted ambiguous commissioning read failure")
        return super().require_current()


class RecordingGenerator(SyntheticReachyPrivateMaterialGenerator):
    def __init__(
        self,
        key_store: OwnerOnlyArtifactStore,
        certificate_store: OwnerOnlyArtifactStore,
        events: list[str],
    ) -> None:
        super().__init__(key_store=key_store, certificate_store=certificate_store)
        self.events = events

    def generate(
        self,
        *,
        request: ReachyCommissioningRequestV1,
        generation: int,
        core_hmac_agreement_public_key_b64: str,
    ) -> GeneratedReachyMaterialV1:
        self.events.append(f"generator.generate.{generation}")
        return super().generate(
            request=request,
            generation=generation,
            core_hmac_agreement_public_key_b64=core_hmac_agreement_public_key_b64,
        )


class RecordingIssuer(SyntheticCoreCommissioningIssuer):
    def __init__(
        self,
        events: list[str],
        *,
        state_store: OwnerOnlyArtifactStore | None = None,
    ) -> None:
        super().__init__(state_store=state_store)
        self.events = events
        self.fail_next_begin = False
        self.fail_next_activation = False

    def begin_generation(
        self,
        *,
        request: ReachyCommissioningRequestV1,
        generation: int,
    ) -> PreparedCoreMaterialV1:
        self.events.append(f"issuer.begin.{generation}")
        if self.fail_next_begin:
            self.fail_next_begin = False
            raise OSError("scripted issuer begin failure")
        return super().begin_generation(request=request, generation=generation)

    def complete_generation(
        self,
        *,
        prepared: PreparedCoreMaterialV1,
        reachy_material: GeneratedReachyMaterialV1,
    ) -> IssuedClientMaterialV1:
        self.events.append(f"issuer.complete.{prepared.generation}")
        return super().complete_generation(prepared=prepared, reachy_material=reachy_material)

    def activate_staged_generation(
        self,
        *,
        generation: int,
        endpoint: ReachyCoreEndpointV1,
    ) -> None:
        self.events.append(f"issuer.activate.{generation}")
        if self.fail_next_activation:
            self.fail_next_activation = False
            raise OSError("scripted activation failure")
        super().activate_staged_generation(generation=generation, endpoint=endpoint)

    def revoke_generation(self, *, endpoint: ReachyCoreEndpointV1) -> None:
        self.events.append(f"issuer.revoke.{endpoint.generation}")
        super().revoke_generation(endpoint=endpoint)


class ForgedHardwareStringIssuer(RecordingIssuer):
    assurance_source: Literal["hardware"] = "hardware"


def _service_case(
    tmp_path: Path,
) -> tuple[
    ReachyCommissioningService,
    RecordingRepository,
    RecordingGenerator,
    RecordingIssuer,
    RecordingAcceptancePublisher,
    _SyntheticLocalPhysicalProofIssuer,
    OwnerOnlyArtifactStore,
    OwnerOnlyArtifactStore,
    OwnerOnlyArtifactStore,
    list[str],
]:
    events: list[str] = []
    repository = RecordingRepository(tmp_path / "commissioning", events)
    key_store = OwnerOnlyArtifactStore(tmp_path / "private")
    certificate_store = OwnerOnlyArtifactStore(tmp_path / "certificates")
    issuer_state_store = OwnerOnlyArtifactStore(tmp_path / "issuer-state")
    generator = RecordingGenerator(key_store, certificate_store, events)
    issuer = RecordingIssuer(events, state_store=issuer_state_store)
    acceptance = RecordingAcceptancePublisher(events)
    proof_issuer = _SyntheticLocalPhysicalProofIssuer()
    service = ReachyCommissioningService(
        repository=repository,
        generator=generator,
        issuer=issuer,
        acceptance_publisher=acceptance,
        local_proof_verifier=proof_issuer.consumer,
    )
    return (
        service,
        repository,
        generator,
        issuer,
        acceptance,
        proof_issuer,
        key_store,
        certificate_store,
        issuer_state_store,
        events,
    )


def test_service_clears_accepted_capability_before_recommission_material_or_mutation(
    tmp_path: Path,
) -> None:
    (
        service,
        repository,
        _generator,
        _issuer,
        acceptance,
        proof_issuer,
        _keys,
        _certs,
        _issuer_store,
        events,
    ) = _service_case(tmp_path)
    request1 = _request(1)
    first = service.commission_local(
        _proof_for(proof_issuer, operation="commission", request=request1),
        request1,
    )
    events.clear()

    acceptance.fail_next = True
    request2 = _request(2, core_ipv4="192.168.50.11")
    with pytest.raises(OSError, match="acceptance clear"):
        service.recommission_local(
            _proof_for(
                proof_issuer,
                operation="recommission",
                request=request2,
                current=first,
            ),
            request2,
        )

    assert repository.require_current() == first
    assert events == ["acceptance.clear.recommission.1"]

    second = service.recommission_local(
        _proof_for(proof_issuer, operation="recommission", request=request2, current=first),
        request2,
    )
    assert events.index("acceptance.clear.recommission.1") < events.index("issuer.begin.2")
    assert events.index("acceptance.clear.recommission.1") < events.index("generator.generate.2")
    assert events.index("acceptance.clear.recommission.1") < events.index(
        "repository.publish.2.active"
    )
    assert second.revoked_key_ids == _key_ids(first.endpoint)
    assert second.revoked_certificate_sha256 == _certificate_digests(first.endpoint)


def test_recommission_keeps_only_immediate_tombstones_and_rejects_old_generation(
    tmp_path: Path,
) -> None:
    (
        service,
        repository,
        _generator,
        _issuer,
        _acceptance,
        proof_issuer,
        _keys,
        _certs,
        _issuer_store,
        _events,
    ) = _service_case(tmp_path)
    request1 = _request(1)
    first = service.commission_local(
        _proof_for(proof_issuer, operation="commission", request=request1),
        request1,
    )
    request2 = _request(2, core_ipv4="192.168.50.11")
    second = service.recommission_local(
        _proof_for(proof_issuer, operation="recommission", request=request2, current=first),
        request2,
    )
    request3 = _request(3, core_ipv4="192.168.50.12")
    third = service.recommission_local(
        _proof_for(proof_issuer, operation="recommission", request=request3, current=second),
        request3,
    )

    assert third.revoked_key_ids == _key_ids(second.endpoint)
    assert third.revoked_certificate_sha256 == _certificate_digests(second.endpoint)
    assert first.endpoint.server_key_id not in third.revoked_key_ids
    with pytest.raises(PermissionError, match="commissioning_material_revoked"):
        repository.require_usable(first.endpoint)


def test_service_revoke_clears_acceptance_before_revoked_state_publish(
    tmp_path: Path,
) -> None:
    (
        service,
        repository,
        _generator,
        _issuer,
        _acceptance,
        proof_issuer,
        _keys,
        _certs,
        _issuer_store,
        events,
    ) = _service_case(tmp_path)
    request1 = _request(1)
    current = service.commission_local(
        _proof_for(proof_issuer, operation="commission", request=request1),
        request1,
    )
    events.clear()

    revoked = service.revoke_local(_proof_for(proof_issuer, operation="revoke", current=current))

    assert revoked.status == "revoked"
    assert revoked.revoked_key_ids == _key_ids(current.endpoint)
    assert events.index("acceptance.clear.revoke.1") < events.index("repository.publish.1.revoked")
    assert events.index("repository.publish.1.revoked") < events.index("issuer.revoke.1")
    with pytest.raises(PermissionError, match="commissioning_revoked"):
        service.resume_current_activation()
    with pytest.raises(PermissionError, match="commissioning_material_revoked"):
        repository.require_usable(current.endpoint)


def test_restart_resumes_only_the_atomically_visible_generation_after_activation_failure(
    tmp_path: Path,
) -> None:
    (
        service,
        repository,
        _generator,
        issuer,
        acceptance,
        proof_issuer,
        key_store,
        certificate_store,
        issuer_store,
        events,
    ) = _service_case(tmp_path)
    issuer.fail_next_activation = True
    request1 = _request(1)

    with pytest.raises(OSError, match="activation"):
        service.commission_local(
            _proof_for(proof_issuer, operation="commission", request=request1),
            request1,
        )

    visible = repository.reopen().require_current()
    fresh_issuer = RecordingIssuer(events, state_store=issuer_store)
    fresh_generator = RecordingGenerator(key_store, certificate_store, events)
    restarted = ReachyCommissioningService(
        repository=repository.reopen(),
        generator=fresh_generator,
        issuer=fresh_issuer,
        acceptance_publisher=acceptance,
        local_proof_verifier=_SyntheticLocalPhysicalProofIssuer().consumer,
    )
    assert restarted.resume_current_activation() == visible
    assert fresh_issuer.active_generation == visible.endpoint.generation


def test_private_material_stays_behind_artifact_port_and_state_contains_only_commitments(
    tmp_path: Path,
) -> None:
    (
        service,
        _repository,
        generator,
        _issuer,
        _acceptance,
        proof_issuer,
        key_store,
        cert_store,
        _issuer_store,
        _events,
    ) = _service_case(tmp_path)

    request1 = _request(1)
    state = service.commission_local(
        _proof_for(proof_issuer, operation="commission", request=request1),
        request1,
    )
    public_material = generator.generated_material[-1]
    state_bytes = canonical_bytes(state)

    assert set(type(public_material).model_fields) == {
        "schema_version",
        "generation",
        "client_tls_key_id",
        "client_tls_csr_pem",
        "client_tls_public_key_sha256",
        "device_signing_key_id",
        "device_signing_public_key_b64",
        "device_signing_public_key_sha256",
        "hmac_key_id",
        "hmac_agreement_public_key_b64",
        "hmac_agreement_public_key_sha256",
        "hmac_key_sha256",
    }
    assert "private" not in public_material.model_dump_json().lower()
    assert "symmetric" not in public_material.model_dump_json().lower()
    assert b"PRIVATE KEY" not in state_bytes
    assert key_store.read(state.endpoint.client_tls_key_id) not in state_bytes
    assert key_store.read(state.endpoint.device_signing_key_id) not in state_bytes
    assert key_store.read(state.endpoint.hmac_key_id) not in state_bytes
    assert cert_store.read(state.endpoint.client_tls_key_id).startswith(
        b"-----BEGIN CERTIFICATE-----"
    )
    for key_id in (
        state.endpoint.client_tls_key_id,
        state.endpoint.device_signing_key_id,
        state.endpoint.hmac_key_id,
    ):
        identity = os.stat(key_id, dir_fd=key_store.directory_fd, follow_symlinks=False)
        assert stat.S_IMODE(identity.st_mode) == 0o600


def test_local_physical_proof_is_one_shot_and_request_generation_bound(
    tmp_path: Path,
) -> None:
    (
        service,
        _repository,
        _generator,
        _issuer,
        _acceptance,
        proof_issuer,
        _keys,
        _certs,
        _issuer_store,
        _events,
    ) = _service_case(tmp_path)
    request1 = _request(1)
    first = service.commission_local(
        _proof_for(proof_issuer, operation="commission", request=request1),
        request1,
    )
    request2 = _request(2, core_ipv4="192.168.50.11")
    wrong_request = _request(2, core_ipv4="192.168.50.12")
    bound_proof = _proof_for(
        proof_issuer,
        operation="recommission",
        request=request2,
        current=first,
    )

    with pytest.raises(PermissionError, match="local_physical_proof_request_mismatch"):
        service.recommission_local(bound_proof, wrong_request)

    second = service.recommission_local(bound_proof, request2)
    with pytest.raises(PermissionError, match="local_physical_proof_consumed"):
        service.recommission_local(bound_proof, _request(3, core_ipv4="192.168.50.13"))
    assert second.endpoint.generation == 2


def test_revoked_generation_recommission_requires_fresh_revoked_current_proof(
    tmp_path: Path,
) -> None:
    (
        service,
        _repository,
        _generator,
        _issuer,
        _acceptance,
        proof_issuer,
        _keys,
        _certs,
        _issuer_store,
        _events,
    ) = _service_case(tmp_path)
    request1 = _request(1)
    first = service.commission_local(
        _proof_for(proof_issuer, operation="commission", request=request1),
        request1,
    )
    request2 = _request(2, core_ipv4="192.168.50.11")
    stale_active_proof = _proof_for(
        proof_issuer,
        operation="recommission",
        request=request2,
        current=first,
    )
    revoked = service.revoke_local(_proof_for(proof_issuer, operation="revoke", current=first))

    with pytest.raises(PermissionError, match="local_physical_proof_current_mismatch"):
        service.recommission_local(stale_active_proof, request2)

    second = service.recommission_local(
        _proof_for(proof_issuer, operation="recommission", request=request2, current=revoked),
        request2,
    )
    assert second.status == "active"
    assert second.endpoint.generation == first.endpoint.generation + 1
    assert second.revoked_key_ids == _key_ids(first.endpoint)
    assert second.revoked_certificate_sha256 == _certificate_digests(first.endpoint)


def test_raw_mutation_entrypoints_are_internal_only() -> None:
    assert not hasattr(ReachyCommissioningService, "commission")
    assert not hasattr(ReachyCommissioningService, "recommission")
    assert not hasattr(ReachyCommissioningService, "revoke_current")


def test_service_instance_has_no_direct_commissioning_transition_callable(
    tmp_path: Path,
) -> None:
    (
        service,
        repository,
        _generator,
        _issuer,
        _acceptance,
        _proof_issuer,
        _keys,
        _certs,
        _issuer_store,
        events,
    ) = _service_case(tmp_path)

    with pytest.raises(AttributeError):
        direct_transition: Any = object.__getattribute__(service, "_replace")
        direct_transition(current=None, request=_request(1))

    assert not repository.has_current()
    assert events == []


def test_commissioning_module_does_not_expose_transition_authorization_surfaces() -> None:
    leaked_transition_surfaces = {
        "_ACTIVE_LOCAL_TRANSITION_AUTHORIZATIONS",
        "_LOCAL_TRANSITION_AUTHORIZATION_MARKER",
        "_LocalPhysicalTransitionAuthorization",
        "_consume_local_transition_authorization",
        "_replace_commissioning_state",
        "_revoke_commissioning_state",
    }

    assert not {name for name in leaked_transition_surfaces if hasattr(commissioning_module, name)}


def test_shape_valid_unverified_proof_cannot_mint_authorization_and_publish_generation(
    tmp_path: Path,
) -> None:
    (
        _service,
        repository,
        generator,
        issuer,
        _acceptance,
        _proof_issuer,
        _keys,
        _certs,
        _issuer_store,
        events,
    ) = _service_case(tmp_path)
    request = _request(1)
    authorization_type_name = "_LocalPhysicalTransitionAuthorization"
    marker_name = "_LOCAL_TRANSITION_AUTHORIZATION_MARKER"
    replace_name = "_replace_commissioning_state"
    fake_proof = LocalPhysicalProof(
        schema_version="tuntun.reachy-local-physical-proof.v1",
        proof_id=_uuid(41),
        operation="commission",
        request_sha256=hashlib.sha256(canonical_bytes(request)).hexdigest(),
        current_state_sha256=None,
        current_generation=None,
        target_generation=1,
        verifier_mac_sha256=_digest("unauthenticated-local-physical-proof"),
    )

    with pytest.raises((AttributeError, PermissionError)):
        authorization_type: Any = getattr(commissioning_module, authorization_type_name)
        authorization = authorization_type._from_consumed_proof(
            getattr(commissioning_module, marker_name),
            proof=fake_proof,
            operation="commission",
            request=request,
            current=None,
        )
        getattr(commissioning_module, replace_name)(
            repository=repository,
            generator=generator,
            issuer=issuer,
            current=None,
            request=request,
            authorization=authorization,
        )

    assert not repository.has_current()
    assert events == []


def test_authorization_registry_cannot_activate_forgery_and_publish_generation(
    tmp_path: Path,
) -> None:
    (
        _service,
        repository,
        generator,
        issuer,
        _acceptance,
        _proof_issuer,
        _keys,
        _certs,
        _issuer_store,
        events,
    ) = _service_case(tmp_path)
    request = _request(1)
    authorization_type_name = "_LocalPhysicalTransitionAuthorization"
    marker_name = "_LOCAL_TRANSITION_AUTHORIZATION_MARKER"
    registry_name = "_ACTIVE_LOCAL_TRANSITION_AUTHORIZATIONS"
    replace_name = "_replace_commissioning_state"

    with pytest.raises((AttributeError, PermissionError)):
        authorization_type: Any = getattr(commissioning_module, authorization_type_name)
        forged_internal = authorization_type.__new__(authorization_type)
        forged_internal.proof_id = _uuid(42)
        forged_internal.operation = "commission"
        forged_internal.request_sha256 = hashlib.sha256(canonical_bytes(request)).hexdigest()
        forged_internal.current_state_sha256 = None
        forged_internal.current_generation = None
        forged_internal.target_generation = 1
        forged_internal._marker = getattr(commissioning_module, marker_name)
        forged_internal._consumed = False
        getattr(commissioning_module, registry_name).add(forged_internal)
        getattr(commissioning_module, replace_name)(
            repository=repository,
            generator=generator,
            issuer=issuer,
            current=None,
            request=request,
            authorization=forged_internal,
        )

    assert not repository.has_current()
    assert events == []


def test_forged_transition_authorization_cannot_publish_generation(
    tmp_path: Path,
) -> None:
    (
        _service,
        repository,
        generator,
        issuer,
        _acceptance,
        _proof_issuer,
        _keys,
        _certs,
        _issuer_store,
        events,
    ) = _service_case(tmp_path)
    request = _request(1)

    class ForgedTransitionAuthorization:
        operation = "commission"
        proof_id = _uuid(1)
        request_sha256 = hashlib.sha256(canonical_bytes(request)).hexdigest()
        current_state_sha256 = None
        current_generation = None
        target_generation = 1

    replace_name = "_replace_commissioning_state"
    with pytest.raises((AttributeError, PermissionError)):
        getattr(commissioning_module, replace_name)(
            repository=repository,
            generator=generator,
            issuer=issuer,
            current=None,
            request=request,
            authorization=ForgedTransitionAuthorization(),
        )

    assert not repository.has_current()
    assert events == []


def test_service_instance_exposes_no_proofless_unverified_mutation_helpers(
    tmp_path: Path,
) -> None:
    service, *_ = _service_case(tmp_path)
    forbidden = {
        "_commission_unverified",
        "_recommission_unverified",
        "_revoke_current_unverified",
    }

    for name in forbidden:
        assert not hasattr(service, name)
    assert not [
        name
        for name in dir(service)
        if name.endswith("_unverified")
        and any(operation in name for operation in ("commission", "recommission", "revoke"))
    ]


def test_synthetic_commissioning_material_is_not_runtime_usable(
    tmp_path: Path,
) -> None:
    (
        service,
        repository,
        _generator,
        _issuer,
        _acceptance,
        proof_issuer,
        _keys,
        _certs,
        _issuer_store,
        _events,
    ) = _service_case(tmp_path)
    request1 = _request(1)
    state = service.commission_local(
        _proof_for(proof_issuer, operation="commission", request=request1),
        request1,
    )

    with pytest.raises(PermissionError, match="commissioning_assurance_not_runtime_usable"):
        repository.require_usable(state.endpoint)


def test_repository_rejects_caller_authored_hardware_assurance_forgery(
    tmp_path: Path,
) -> None:
    repository = CommissioningRepository(tmp_path / "commissioning")
    state = _state(1)

    with pytest.raises(PermissionError, match="commissioning_assurance_capability_required"):
        repository.replace_atomic(state, assurance=object())

    assert not repository.has_current()

    forged_kwargs: dict[str, Any] = {"assurance_source": "hardware"}
    with pytest.raises(TypeError, match="assurance_source"):
        repository.replace_atomic(state, **forged_kwargs)


def test_issuer_string_cannot_mint_hardware_runtime_assurance(tmp_path: Path) -> None:
    events: list[str] = []
    repository = RecordingRepository(tmp_path / "commissioning", events)
    key_store = OwnerOnlyArtifactStore(tmp_path / "private")
    certificate_store = OwnerOnlyArtifactStore(tmp_path / "certificates")
    issuer_store = OwnerOnlyArtifactStore(tmp_path / "issuer-state")
    generator = RecordingGenerator(key_store, certificate_store, events)
    issuer = ForgedHardwareStringIssuer(events, state_store=issuer_store)
    proof_issuer = _SyntheticLocalPhysicalProofIssuer()
    service = ReachyCommissioningService(
        repository=repository,
        generator=generator,
        issuer=issuer,
        acceptance_publisher=RecordingAcceptancePublisher(events),
        local_proof_verifier=proof_issuer.consumer,
    )
    request1 = _request(1)
    state = service.commission_local(
        _proof_for(proof_issuer, operation="commission", request=request1),
        request1,
    )

    with pytest.raises(PermissionError, match="commissioning_assurance_not_runtime_usable"):
        repository.require_usable(state.endpoint)


def test_synthetic_helpers_and_proof_issuance_are_not_package_runtime_exports() -> None:
    hidden_exports = {
        "SyntheticCoreCommissioningIssuer",
        "SyntheticReachyPrivateMaterialGenerator",
        "LocalPhysicalEvidence",
        "LocalPhysicalProofVerifier",
        "_SyntheticLocalPhysicalEvidence",
        "_SyntheticLocalPhysicalProofIssuer",
    }

    assert not hidden_exports & set(transport_exports.__all__)
    for name in hidden_exports:
        assert not hasattr(transport_exports, name)


def test_ambiguous_publish_error_preserves_staged_material_for_recovery(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    repository = AmbiguousPublicationRepository(tmp_path / "commissioning", events)
    key_store = OwnerOnlyArtifactStore(tmp_path / "private")
    certificate_store = OwnerOnlyArtifactStore(tmp_path / "certificates")
    issuer_store = OwnerOnlyArtifactStore(tmp_path / "issuer-state")
    generator = RecordingGenerator(key_store, certificate_store, events)
    issuer = RecordingIssuer(events, state_store=issuer_store)
    proof_issuer = _SyntheticLocalPhysicalProofIssuer()
    service = ReachyCommissioningService(
        repository=repository,
        generator=generator,
        issuer=issuer,
        acceptance_publisher=RecordingAcceptancePublisher(events),
        local_proof_verifier=proof_issuer.consumer,
    )
    repository.inject_crash_at("after_replace_before_parent_fsync")
    request1 = _request(1)

    with pytest.raises(OSError, match="after_replace_before_parent_fsync"):
        service.commission_local(
            _proof_for(proof_issuer, operation="commission", request=request1),
            request1,
        )

    material = generator.generated_material[-1]
    assert key_store.read(material.client_tls_key_id)
    assert key_store.read(material.device_signing_key_id)
    assert key_store.read(material.hmac_key_id)
    assert certificate_store.read(material.client_tls_key_id).startswith(
        b"-----BEGIN CERTIFICATE-----"
    )
    assert material.generation in issuer.staged_generations
    repository.fail_current_read_after_publish_error = False
    assert repository.require_current().endpoint.generation == material.generation


def test_operator_acceptance_clearer_persists_none_before_recommission_restart(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    commissioning_repository = RecordingRepository(tmp_path / "commissioning", events)
    key_store = OwnerOnlyArtifactStore(tmp_path / "private")
    certificate_store = OwnerOnlyArtifactStore(tmp_path / "certificates")
    issuer_store = OwnerOnlyArtifactStore(tmp_path / "issuer-state")
    operator_repository = ReachyOperatorStateRepository(tmp_path / "operator-state")
    generator = RecordingGenerator(key_store, certificate_store, events)
    issuer = RecordingIssuer(events, state_store=issuer_store)
    proof_issuer = _SyntheticLocalPhysicalProofIssuer()
    service = ReachyCommissioningService(
        repository=commissioning_repository,
        generator=generator,
        issuer=issuer,
        acceptance_publisher=ReachyOperatorAcceptancePublisher(operator_repository),
        local_proof_verifier=proof_issuer.consumer,
    )
    request1 = _request(1)
    first = service.commission_local(
        _proof_for(proof_issuer, operation="commission", request=request1),
        request1,
    )
    operator_repository.replace_atomic(_operator_state(first))
    issuer.fail_next_begin = True
    request2 = _request(2, core_ipv4="192.168.50.11")

    with pytest.raises(OSError, match="issuer begin"):
        service.recommission_local(
            _proof_for(
                proof_issuer,
                operation="recommission",
                request=request2,
                current=first,
            ),
            request2,
        )

    restarted_operator = ReachyOperatorStateRepository(tmp_path / "operator-state")
    cleared = restarted_operator.require_current()
    assert cleared.accepted_capability is None
    assert cleared.commissioning_generation == first.endpoint.generation
    assert cleared.commissioning_state_sha256 == _state_digest(first)
    assert commissioning_repository.require_current() == first


def test_operator_acceptance_clearer_persists_none_before_revoke_restart(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    commissioning_repository = RecordingRepository(tmp_path / "commissioning", events)
    key_store = OwnerOnlyArtifactStore(tmp_path / "private")
    certificate_store = OwnerOnlyArtifactStore(tmp_path / "certificates")
    issuer_store = OwnerOnlyArtifactStore(tmp_path / "issuer-state")
    operator_repository = ReachyOperatorStateRepository(tmp_path / "operator-state")
    generator = RecordingGenerator(key_store, certificate_store, events)
    issuer = RecordingIssuer(events, state_store=issuer_store)
    proof_issuer = _SyntheticLocalPhysicalProofIssuer()
    service = ReachyCommissioningService(
        repository=commissioning_repository,
        generator=generator,
        issuer=issuer,
        acceptance_publisher=ReachyOperatorAcceptancePublisher(operator_repository),
        local_proof_verifier=proof_issuer.consumer,
    )
    request1 = _request(1)
    first = service.commission_local(
        _proof_for(proof_issuer, operation="commission", request=request1),
        request1,
    )
    operator_repository.replace_atomic(_operator_state(first))
    commissioning_repository.inject_crash_at("before_temp_open")

    with pytest.raises(OSError, match="before_temp_open"):
        service.revoke_local(_proof_for(proof_issuer, operation="revoke", current=first))

    restarted_operator = ReachyOperatorStateRepository(tmp_path / "operator-state")
    cleared = restarted_operator.require_current()
    assert cleared.accepted_capability is None
    assert cleared.commissioning_generation == first.endpoint.generation
    assert cleared.commissioning_state_sha256 == _state_digest(first)
    assert commissioning_repository.require_current() == first
