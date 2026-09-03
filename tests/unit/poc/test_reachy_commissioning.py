from __future__ import annotations

import asyncio
import base64
import errno
import fcntl
import hashlib
import inspect
import json
import os
import pickle
import pwd
import socket
import stat
import struct
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta, timezone
from ipaddress import IPv4Address
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
import tuntun_core.adapters.reachy.commissioning as commissioning_module
import tuntun_core.config.secure_paths as secure_paths_module
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from jsonschema import Draft202012Validator, FormatChecker
from pydantic import ValidationError
from tuntun_contracts.base import canonical_bytes
from tuntun_contracts.poc.framing import PttInputMode
from tuntun_core.adapters.reachy.commissioning import (
    ReachyA05CommissioningRepository,
    ReachyA05CommissioningStateV1,
    ReachyA05DeploymentBinding,
    ReachyA05RemoteStateV1,
    ReachyA05RepositoryError,
    ReachyA05RevokedStateExpectation,
    ReachyA05RevokedTombstoneV1,
    ReachyA05RuntimeBinding,
    ReachyA05StateExpectation,
    ReachyA05StateStatus,
    render_operator_state_schema,
    render_remote_state_schema,
)
from tuntun_edge.diagnostics.capability import render_capability_schema

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
OPERATOR_SCHEMA_PATH = REPOSITORY_ROOT / "docs/evidence/reachy-a05-operator-state.schema.json"
REMOTE_SCHEMA_PATH = REPOSITORY_ROOT / "docs/evidence/reachy-a05-remote-state.schema.json"


def ssh_string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def openssh_ed25519_identity(
    private_seed: bytes,
    *,
    embedded_public_key: bytes | None = None,
) -> tuple[bytes, bytes]:
    derived_public_key = (
        Ed25519PrivateKey.from_private_bytes(private_seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    public_key = derived_public_key if embedded_public_key is None else embedded_public_key
    public_blob = ssh_string(b"ssh-ed25519") + ssh_string(public_key)
    private_block = (
        struct.pack(">II", 0x10203040, 0x10203040)
        + ssh_string(b"ssh-ed25519")
        + ssh_string(public_key)
        + ssh_string(private_seed + public_key)
        + ssh_string(b"")
    )
    padding_length = 8 - (len(private_block) % 8)
    private_block += bytes(range(1, padding_length + 1))
    payload = (
        b"openssh-key-v1\x00"
        + ssh_string(b"none")
        + ssh_string(b"none")
        + ssh_string(b"")
        + struct.pack(">I", 1)
        + ssh_string(public_blob)
        + ssh_string(private_block)
    )
    encoded = base64.b64encode(payload)
    wrapped = b"\n".join(encoded[index : index + 70] for index in range(0, len(encoded), 70))
    header = b"".join((b"-----BEGIN OPENSSH PRIVATE ", b"KEY-----\n"))
    footer = b"".join((b"\n-----END OPENSSH PRIVATE ", b"KEY-----\n"))
    return (
        header + wrapped + footer,
        public_blob,
    )


IDENTITY_ARTIFACT, IDENTITY_PUBLIC_KEY_BLOB = openssh_ed25519_identity(b"I" * 32)
ALTERNATE_IDENTITY_ARTIFACT, ALTERNATE_IDENTITY_PUBLIC_KEY_BLOB = openssh_ed25519_identity(
    b"J" * 32
)
HOST_IDENTITY_ARTIFACT, HOST_PUBLIC_KEY_BLOB = openssh_ed25519_identity(b"H" * 32)
PINNED_HOST_KEY_BLOB = ssh_string(b"ssh-ed25519") + ssh_string(b"H" * 32)
ALTERNATE_PINNED_HOST_KEY_BLOB = ssh_string(b"ssh-ed25519") + ssh_string(b"K" * 32)


def known_hosts_artifact(ipv4: str, public_blob: bytes) -> bytes:
    return ipv4.encode("ascii") + b" ssh-ed25519 " + base64.b64encode(public_blob) + b"\n"


KNOWN_HOSTS_ARTIFACT = known_hosts_artifact("192.168.50.22", PINNED_HOST_KEY_BLOB)


def valid_runtime(**updates: object) -> ReachyA05RuntimeBinding:
    values: dict[str, object] = {
        "python_executable": "/venvs/apps_venv/bin/python3",
        "python_version": "3.12.8",
        "python_abi": "cp312",
        "selected_wheel_tag": "py3-none-any",
        "target_tag_set_sha256": "1" * 64,
        "sdk_version": "1.2.3",
        "sdk_artifact_sha256": "2" * 64,
        "daemon_version": "4.5.6",
        "daemon_artifact_sha256": "3" * 64,
        "runtime_inventory_sha256": "4" * 64,
    }
    values.update(updates)
    return ReachyA05RuntimeBinding.model_validate(values)


def valid_deployment(**updates: object) -> ReachyA05DeploymentBinding:
    issued_at = datetime(2026, 8, 31, 8, 0, tzinfo=UTC)
    values: dict[str, object] = {
        "commissioning_id": UUID("12345678-1234-4678-9234-567812345678"),
        "state_generation": 1,
        "status": ReachyA05StateStatus.COMMISSIONED,
        "issued_at": issued_at,
        "expires_at": issued_at + timedelta(hours=24),
        "boot_identity_sha256": "5" * 64,
        "capability_report_sha256": "6" * 64,
        "ptt_input_mode": PttInputMode.REACHY_LOCAL,
        "runtime": valid_runtime(),
        "ssh_principal": "owner",
        "remote_home": "/home/owner",
        "remote_root": "/home/owner/.local/share/tuntun/reachy-a05",
        "dispatcher_path": (
            "/home/owner/.local/share/tuntun/reachy-a05/bootstrap/reachy_a05_forced_dispatcher.py"
        ),
        "dispatcher_protocol_version": "tuntun.reachy-a05-dispatcher.v1",
        "dispatcher_sha256": "7" * 64,
        "authorized_key_line_sha256": "8" * 64,
        "staged_bundle_sha256": None,
        "active_bundle_sha256": None,
    }
    values.update(updates)
    return ReachyA05DeploymentBinding.model_validate(values)


def valid_commissioning_state(
    **updates: object,
) -> ReachyA05CommissioningStateV1:
    values: dict[str, object] = {
        "schema_version": "tuntun.reachy-a05-operator-state.v1",
        "record_kind": "bound",
        "deployment": valid_deployment(),
        "reachy_ipv4": IPv4Address("192.168.50.22"),
        "ssh_port": 22,
        "identity_path": "/Users/owner/.local/share/tuntun/reachy-a05/identity",
        "known_hosts_path": ("/Users/owner/.local/share/tuntun/reachy-a05/known_hosts"),
        "identity_public_key_type": "ssh-ed25519",
        "pinned_host_key_type": "ssh-ed25519",
        "identity_public_key_sha256": hashlib.sha256(IDENTITY_PUBLIC_KEY_BLOB).hexdigest(),
        "pinned_host_key_sha256": hashlib.sha256(PINNED_HOST_KEY_BLOB).hexdigest(),
        "identity_file_sha256": hashlib.sha256(IDENTITY_ARTIFACT).hexdigest(),
        "known_hosts_file_sha256": hashlib.sha256(KNOWN_HOSTS_ARTIFACT).hexdigest(),
    }
    values.update(updates)
    return ReachyA05CommissioningStateV1.model_validate(values)


def valid_remote_state(**updates: object) -> ReachyA05RemoteStateV1:
    values: dict[str, object] = {
        "schema_version": "tuntun.reachy-a05-remote-state.v1",
        "deployment": valid_deployment(),
    }
    values.update(updates)
    return ReachyA05RemoteStateV1.model_validate(values)


def valid_expectation(
    state: ReachyA05CommissioningStateV1 | None = None,
    **updates: object,
) -> ReachyA05StateExpectation:
    state = state or valid_commissioning_state()
    deployment = state.deployment
    values: dict[str, object] = {
        "commissioning_id": deployment.commissioning_id,
        "state_generation": deployment.state_generation,
        "boot_identity_sha256": deployment.boot_identity_sha256,
        "capability_report_sha256": deployment.capability_report_sha256,
        "runtime_inventory_sha256": deployment.runtime.runtime_inventory_sha256,
        "dispatcher_sha256": deployment.dispatcher_sha256,
        "authorized_key_line_sha256": deployment.authorized_key_line_sha256,
        "state_sha256": hashlib.sha256(canonical_bytes(state)).hexdigest(),
    }
    values.update(updates)
    return ReachyA05StateExpectation.model_validate(values)


def fixed_repository_time() -> datetime:
    return datetime(2026, 8, 31, 9, 0, tzinfo=UTC)


def private_repository(
    tmp_path: Path,
    *,
    clock: Callable[[], datetime] | None = None,
) -> ReachyA05CommissioningRepository:
    root = tmp_path / "private-state"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)

    write_private_artifacts(root)
    return ReachyA05CommissioningRepository(
        root,
        clock=fixed_repository_time if clock is None else clock,
    )


def write_private_artifacts(root: Path) -> None:
    for name, content in (
        ("identity", IDENTITY_ARTIFACT),
        ("known_hosts", KNOWN_HOSTS_ARTIFACT),
    ):
        path = root / name
        path.write_bytes(content)
        os.chmod(path, 0o600)


def state_for_repository(
    repository: ReachyA05CommissioningRepository,
    **updates: object,
) -> ReachyA05CommissioningStateV1:
    values: dict[str, object] = {
        "identity_path": str(repository.root / "identity"),
        "known_hosts_path": str(repository.root / "known_hosts"),
    }
    values.update(updates)
    return valid_commissioning_state(**values)


def substituted_security_state(
    state: ReachyA05CommissioningStateV1,
    substitution: str,
) -> ReachyA05CommissioningStateV1:
    values = state.model_dump()
    deployment = values["deployment"]
    assert isinstance(deployment, dict)
    runtime = deployment["runtime"]
    assert isinstance(runtime, dict)
    if substitution == "target":
        values["reachy_ipv4"] = "192.168.50.23"
        values["known_hosts_file_sha256"] = hashlib.sha256(
            known_hosts_artifact("192.168.50.23", PINNED_HOST_KEY_BLOB)
        ).hexdigest()
    elif substitution == "remote_layout":
        deployment.update(
            {
                "ssh_principal": "other",
                "remote_home": "/home/other",
                "remote_root": "/home/other/.local/share/tuntun/reachy-a05",
                "dispatcher_path": (
                    "/home/other/.local/share/tuntun/reachy-a05/bootstrap/"
                    "reachy_a05_forced_dispatcher.py"
                ),
            }
        )
    elif substitution == "runtime":
        runtime["sdk_version"] = "1.2.4"
    elif substitution == "ptt_input_mode":
        deployment["ptt_input_mode"] = PttInputMode.CORE_TERMINAL_TOGGLE
    elif substitution == "key_commitments":
        values["identity_public_key_sha256"] = hashlib.sha256(
            ALTERNATE_IDENTITY_PUBLIC_KEY_BLOB
        ).hexdigest()
        values["pinned_host_key_sha256"] = hashlib.sha256(
            ALTERNATE_PINNED_HOST_KEY_BLOB
        ).hexdigest()
        values["identity_file_sha256"] = hashlib.sha256(ALTERNATE_IDENTITY_ARTIFACT).hexdigest()
        values["known_hosts_file_sha256"] = hashlib.sha256(
            known_hosts_artifact("192.168.50.22", ALTERNATE_PINNED_HOST_KEY_BLOB)
        ).hexdigest()
    elif substitution == "content_address":
        deployment["status"] = ReachyA05StateStatus.ACTIVE
        deployment["active_bundle_sha256"] = "d" * 64
    else:
        raise AssertionError(f"unknown substitution: {substitution}")
    return ReachyA05CommissioningStateV1.model_validate(values)


def terminal_recovery_candidate(
    repository: ReachyA05CommissioningRepository,
    current: ReachyA05CommissioningStateV1,
    status: ReachyA05StateStatus,
    **state_updates: object,
) -> ReachyA05CommissioningStateV1:
    deployment_values = current.deployment.model_dump()
    deployment_values.update(
        state_generation=current.deployment.state_generation + 1,
        status=status,
        issued_at=current.deployment.expires_at,
        expires_at=current.deployment.expires_at + timedelta(hours=24),
        staged_bundle_sha256=None,
        active_bundle_sha256=None,
    )
    values: dict[str, object] = {
        **current.model_dump(),
        "deployment": ReachyA05DeploymentBinding.model_validate(deployment_values),
    }
    values.update(state_updates)
    return ReachyA05CommissioningStateV1.model_validate(values)


def publish_removed_state(
    repository: ReachyA05CommissioningRepository,
) -> ReachyA05CommissioningStateV1:
    return publish_state_with_status(repository, ReachyA05StateStatus.REMOVED)


def publish_state_with_status(
    repository: ReachyA05CommissioningRepository,
    target_status: ReachyA05StateStatus,
) -> ReachyA05CommissioningStateV1:
    current = publish_initial_state(repository)
    if target_status is ReachyA05StateStatus.COMMISSIONED:
        return current
    for status in (
        ReachyA05StateStatus.STAGED,
        ReachyA05StateStatus.ACTIVE,
        ReachyA05StateStatus.REMOVED,
    ):
        deployment = deployment_for_status(
            generation=current.deployment.state_generation + 1,
            status=status,
        )
        candidate = state_for_repository(repository, deployment=deployment)
        repository.replace_atomic(
            candidate,
            expected_generation=current.deployment.state_generation,
            expected_current=valid_expectation(current),
            matching_remote_state=valid_remote_state(deployment=deployment),
        )
        current = candidate
        if status is target_status:
            return current
    raise ValueError("target status is not a live commissioning status")


def revoked_tombstone(
    current: ReachyA05CommissioningStateV1,
) -> ReachyA05RevokedTombstoneV1:
    return ReachyA05RevokedTombstoneV1.model_validate(
        {
            "schema_version": "tuntun.reachy-a05-operator-state.v1",
            "record_kind": "revoked",
            "commissioning_id": current.deployment.commissioning_id,
            "state_generation": current.deployment.state_generation + 1,
            "status": ReachyA05StateStatus.REVOKED,
            "revoked_at": fixed_repository_time(),
            "prior_deployment_sha256": hashlib.sha256(
                canonical_bytes(current.deployment)
            ).hexdigest(),
            "revocation_proof_sha256": "d" * 64,
        }
    )


def revoked_expectation(
    tombstone: ReachyA05RevokedTombstoneV1,
) -> ReachyA05RevokedStateExpectation:
    return ReachyA05RevokedStateExpectation.model_validate(
        {
            "commissioning_id": tombstone.commissioning_id,
            "state_generation": tombstone.state_generation,
            "prior_deployment_sha256": tombstone.prior_deployment_sha256,
            "revocation_proof_sha256": tombstone.revocation_proof_sha256,
            "state_sha256": hashlib.sha256(canonical_bytes(tombstone)).hexdigest(),
        }
    )


def publish_initial_state(
    repository: ReachyA05CommissioningRepository,
) -> ReachyA05CommissioningStateV1:
    state = state_for_repository(repository)
    repository.replace_atomic(
        state,
        expected_generation=0,
        matching_remote_state=valid_remote_state(deployment=state.deployment),
    )
    return state


def deployment_for_status(
    *,
    generation: int,
    status: ReachyA05StateStatus,
    issued_at: datetime | None = None,
) -> ReachyA05DeploymentBinding:
    issued_at = issued_at or datetime(2026, 8, 31, 8, 0, tzinfo=UTC)
    return valid_deployment(
        state_generation=generation,
        status=status,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(hours=24),
        staged_bundle_sha256="b" * 64 if status is ReachyA05StateStatus.STAGED else None,
        active_bundle_sha256="b" * 64 if status is ReachyA05StateStatus.ACTIVE else None,
    )


@pytest.mark.parametrize(
    "status",
    (
        ReachyA05StateStatus.STAGED,
        ReachyA05StateStatus.ACTIVE,
        ReachyA05StateStatus.REMOVED,
    ),
)
def test_initial_seed_requires_generation_one_commissioned(
    tmp_path: Path,
    status: ReachyA05StateStatus,
) -> None:
    repository = private_repository(tmp_path)
    deployment = deployment_for_status(generation=1, status=status)
    candidate = state_for_repository(repository, deployment=deployment)

    with pytest.raises(ReachyA05RepositoryError, match="transition"):
        repository.replace_atomic(
            candidate,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=deployment),
        )


@pytest.mark.parametrize(
    ("current_status", "candidate_status"),
    (
        (ReachyA05StateStatus.COMMISSIONED, ReachyA05StateStatus.COMMISSIONED),
        (ReachyA05StateStatus.COMMISSIONED, ReachyA05StateStatus.ACTIVE),
        (ReachyA05StateStatus.COMMISSIONED, ReachyA05StateStatus.REMOVED),
        (ReachyA05StateStatus.STAGED, ReachyA05StateStatus.COMMISSIONED),
        (ReachyA05StateStatus.STAGED, ReachyA05StateStatus.REMOVED),
        (ReachyA05StateStatus.ACTIVE, ReachyA05StateStatus.STAGED),
        (ReachyA05StateStatus.REMOVED, ReachyA05StateStatus.ACTIVE),
    ),
)
def test_ordinary_lifecycle_rejects_self_backward_and_skipped_transitions(
    tmp_path: Path,
    current_status: ReachyA05StateStatus,
    candidate_status: ReachyA05StateStatus,
) -> None:
    repository = private_repository(tmp_path)
    current = publish_initial_state(repository)
    for next_status in (
        ReachyA05StateStatus.STAGED,
        ReachyA05StateStatus.ACTIVE,
        ReachyA05StateStatus.REMOVED,
    ):
        if current.deployment.status is current_status:
            break
        deployment = deployment_for_status(
            generation=current.deployment.state_generation + 1,
            status=next_status,
        )
        candidate = state_for_repository(repository, deployment=deployment)
        repository.replace_atomic(
            candidate,
            expected_generation=current.deployment.state_generation,
            expected_current=valid_expectation(current),
            matching_remote_state=valid_remote_state(deployment=deployment),
        )
        current = candidate
    assert current.deployment.status is current_status
    candidate_deployment = deployment_for_status(
        generation=current.deployment.state_generation + 1,
        status=candidate_status,
    )
    candidate = state_for_repository(repository, deployment=candidate_deployment)

    with pytest.raises(ReachyA05RepositoryError, match="transition"):
        repository.replace_atomic(
            candidate,
            expected_generation=current.deployment.state_generation,
            expected_current=valid_expectation(current),
            matching_remote_state=valid_remote_state(deployment=candidate_deployment),
        )


def test_staged_to_active_transfers_the_exact_staged_digest(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    staged = publish_state_with_status(repository, ReachyA05StateStatus.STAGED)
    active_values = deployment_for_status(
        generation=staged.deployment.state_generation + 1,
        status=ReachyA05StateStatus.ACTIVE,
    ).model_dump()
    active_values["active_bundle_sha256"] = "c" * 64
    active_deployment = ReachyA05DeploymentBinding.model_validate(active_values)
    assert active_deployment.active_bundle_sha256 != staged.deployment.staged_bundle_sha256
    candidate = state_for_repository(repository, deployment=active_deployment)

    with pytest.raises(ReachyA05RepositoryError, match="content address"):
        repository.replace_atomic(
            candidate,
            expected_generation=staged.deployment.state_generation,
            expected_current=valid_expectation(staged),
            matching_remote_state=valid_remote_state(deployment=active_deployment),
        )

    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(staged)


def test_ordinary_successor_issued_at_cannot_precede_current(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    current = publish_initial_state(repository)
    regressed_time = current.deployment.issued_at - timedelta(microseconds=1)
    deployment = deployment_for_status(
        generation=2,
        status=ReachyA05StateStatus.STAGED,
        issued_at=regressed_time,
    )
    candidate = state_for_repository(repository, deployment=deployment)

    with pytest.raises(ReachyA05RepositoryError, match="issued_at"):
        repository.replace_atomic(
            candidate,
            expected_generation=1,
            expected_current=valid_expectation(current),
            matching_remote_state=valid_remote_state(deployment=deployment),
        )

    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(current)


def test_ordinary_successor_allows_equal_issued_at_boundary(tmp_path: Path) -> None:
    repository = private_repository(tmp_path)
    current = publish_initial_state(repository)
    deployment = deployment_for_status(
        generation=2,
        status=ReachyA05StateStatus.STAGED,
        issued_at=current.deployment.issued_at,
    )
    candidate = state_for_repository(repository, deployment=deployment)

    repository.replace_atomic(
        candidate,
        expected_generation=1,
        expected_current=valid_expectation(current),
        matching_remote_state=valid_remote_state(deployment=deployment),
    )

    assert repository.require_current(expectation=valid_expectation(candidate)) == candidate


def test_private_states_are_closed_immutable_and_json_round_trip() -> None:
    commissioning = valid_commissioning_state()
    remote = valid_remote_state(deployment=commissioning.deployment)

    assert (
        ReachyA05CommissioningStateV1.model_validate_json(commissioning.model_dump_json())
        == commissioning
    )
    assert ReachyA05RemoteStateV1.model_validate_json(remote.model_dump_json()) == remote
    assert commissioning.deployment == remote.deployment
    with pytest.raises(ValidationError):
        commissioning.ssh_port = 2222
    with pytest.raises(ValidationError):
        ReachyA05RemoteStateV1.model_validate(
            {
                **remote.model_dump(),
                "unexpected": "rejected",
            }
        )


def test_full_bound_state_cannot_encode_revoked_status() -> None:
    with pytest.raises(ValidationError):
        valid_deployment(status=ReachyA05StateStatus.REVOKED)


def test_revoked_tombstone_is_content_minimized_and_schema_discriminated() -> None:
    current = valid_commissioning_state(
        deployment=deployment_for_status(
            generation=4,
            status=ReachyA05StateStatus.REMOVED,
        )
    )
    tombstone = revoked_tombstone(current)
    encoded = canonical_bytes(tombstone)

    for forbidden in (
        str(current.reachy_ipv4),
        current.deployment.ssh_principal,
        current.deployment.remote_home,
        current.identity_path,
        current.known_hosts_path,
        current.identity_public_key_sha256,
        current.pinned_host_key_sha256,
        current.deployment.dispatcher_path,
        current.deployment.runtime.python_executable,
    ):
        assert forbidden.encode() not in encoded
    schema = json.loads(render_operator_state_schema())
    assert schema["discriminator"]["propertyName"] == "record_kind"
    Draft202012Validator(schema).validate(json.loads(encoded))


def test_removed_to_revoked_publishes_minimal_tombstone_atomically(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    removed = publish_removed_state(repository)
    tombstone = revoked_tombstone(removed)
    (repository.root / "identity").unlink()
    (repository.root / "known_hosts").unlink()

    repository.publish_revoked_tombstone(
        tombstone,
        expected_current=valid_expectation(removed),
        remote_absence_proof_sha256=tombstone.revocation_proof_sha256,
    )

    restored = repository.require_current(expectation=revoked_expectation(tombstone))
    assert restored == tombstone


def test_revocation_rejects_preexisting_unverified_reserved_temp(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    removed = publish_removed_state(repository)
    tombstone = revoked_tombstone(removed)
    (repository.root / "identity").unlink()
    (repository.root / "known_hosts").unlink()
    foreign_temp = repository.root / f".operator-state.g99.{'f' * 64}.tmp"
    foreign_temp.write_bytes(canonical_bytes(removed))
    os.chmod(foreign_temp, 0o600)

    with pytest.raises(ReachyA05RepositoryError, match="reserved temp"):
        repository.publish_revoked_tombstone(
            tombstone,
            expected_current=valid_expectation(removed),
            remote_absence_proof_sha256=tombstone.revocation_proof_sha256,
        )

    assert foreign_temp.read_bytes() == canonical_bytes(removed)
    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(removed)


def test_revocation_cannot_predate_the_deployment_it_revokes(tmp_path: Path) -> None:
    repository = private_repository(tmp_path)
    removed = publish_removed_state(repository)
    tombstone_values = revoked_tombstone(removed).model_dump()
    tombstone_values["revoked_at"] = removed.deployment.issued_at - timedelta(microseconds=1)
    tombstone = ReachyA05RevokedTombstoneV1.model_validate(tombstone_values)
    (repository.root / "identity").unlink()
    (repository.root / "known_hosts").unlink()

    with pytest.raises(ReachyA05RepositoryError, match="revoked_at"):
        repository.publish_revoked_tombstone(
            tombstone,
            expected_current=valid_expectation(removed),
            remote_absence_proof_sha256=tombstone.revocation_proof_sha256,
        )

    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(removed)


def test_revocation_allows_equal_deployment_timestamp_boundary(tmp_path: Path) -> None:
    repository = private_repository(tmp_path)
    removed = publish_removed_state(repository)
    tombstone_values = revoked_tombstone(removed).model_dump()
    tombstone_values["revoked_at"] = removed.deployment.issued_at
    tombstone = ReachyA05RevokedTombstoneV1.model_validate(tombstone_values)
    (repository.root / "identity").unlink()
    (repository.root / "known_hosts").unlink()

    repository.publish_revoked_tombstone(
        tombstone,
        expected_current=valid_expectation(removed),
        remote_absence_proof_sha256=tombstone.revocation_proof_sha256,
    )

    assert repository.require_current(expectation=revoked_expectation(tombstone)) == tombstone


def test_revoked_tombstone_is_nonexpiring_and_remote_schema_remains_live_only(
    tmp_path: Path,
) -> None:
    current_time = [fixed_repository_time()]
    repository = private_repository(tmp_path, clock=lambda: current_time[0])
    removed = publish_removed_state(repository)
    tombstone = revoked_tombstone(removed)
    (repository.root / "identity").unlink()
    (repository.root / "known_hosts").unlink()
    repository.publish_revoked_tombstone(
        tombstone,
        expected_current=valid_expectation(removed),
        remote_absence_proof_sha256=tombstone.revocation_proof_sha256,
    )

    current_time[0] += timedelta(days=3650)

    assert repository.require_current(expectation=revoked_expectation(tombstone)) == tombstone
    with pytest.raises(ValidationError):
        ReachyA05RemoteStateV1.model_validate(tombstone.model_dump())
    assert "ReachyA05RevokedTombstoneV1" not in json.loads(render_remote_state_schema()).get(
        "$defs", {}
    )

    resurrected_deployment = valid_deployment(
        state_generation=tombstone.state_generation + 1,
        status=ReachyA05StateStatus.COMMISSIONED,
    )
    resurrected = state_for_repository(repository, deployment=resurrected_deployment)
    with pytest.raises(ReachyA05RepositoryError, match="transition"):
        repository.replace_atomic(
            resurrected,
            expected_generation=tombstone.state_generation,
            expected_current=revoked_expectation(tombstone),
            matching_remote_state=valid_remote_state(deployment=resurrected_deployment),
        )


def test_revoked_read_fails_closed_on_unverified_reserved_temp(tmp_path: Path) -> None:
    repository = private_repository(tmp_path)
    removed = publish_removed_state(repository)
    tombstone = revoked_tombstone(removed)
    (repository.root / "identity").unlink()
    (repository.root / "known_hosts").unlink()
    repository.publish_revoked_tombstone(
        tombstone,
        expected_current=valid_expectation(removed),
        remote_absence_proof_sha256=tombstone.revocation_proof_sha256,
    )
    foreign_temp = repository.root / ".operator-state.foreign.tmp"
    foreign_temp.write_bytes(canonical_bytes(removed))
    os.chmod(foreign_temp, 0o600)

    with pytest.raises(ReachyA05RepositoryError, match="reserved temp"):
        repository.require_current(expectation=revoked_expectation(tombstone))

    assert foreign_temp.read_bytes() == canonical_bytes(removed)


def test_revocation_requires_removed_credentials_and_exact_remote_absence_proof(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    removed = publish_removed_state(repository)
    tombstone = revoked_tombstone(removed)

    with pytest.raises(ReachyA05RepositoryError, match="artifacts must be removed"):
        repository.publish_revoked_tombstone(
            tombstone,
            expected_current=valid_expectation(removed),
            remote_absence_proof_sha256=tombstone.revocation_proof_sha256,
        )

    (repository.root / "identity").unlink()
    (repository.root / "known_hosts").unlink()
    with pytest.raises(ReachyA05RepositoryError, match="proof commitment"):
        repository.publish_revoked_tombstone(
            tombstone,
            expected_current=valid_expectation(removed),
            remote_absence_proof_sha256="e" * 64,
        )

    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(removed)


@pytest.mark.parametrize("recreated_name", ("identity", "known_hosts"))
def test_current_revoked_state_rejects_recreated_credential_artifact(
    tmp_path: Path,
    recreated_name: str,
) -> None:
    repository = private_repository(tmp_path)
    removed = publish_removed_state(repository)
    tombstone = revoked_tombstone(removed)
    (repository.root / "identity").unlink()
    (repository.root / "known_hosts").unlink()
    repository.publish_revoked_tombstone(
        tombstone,
        expected_current=valid_expectation(removed),
        remote_absence_proof_sha256=tombstone.revocation_proof_sha256,
    )
    recreated = repository.root / recreated_name
    recreated.write_bytes(b"recreated-credential-material")
    os.chmod(recreated, 0o600)

    with pytest.raises(ReachyA05RepositoryError, match="must be removed"):
        repository.require_current(expectation=revoked_expectation(tombstone))


@pytest.mark.parametrize(
    ("python_version", "python_abi"),
    (("3.11.9", "cp312"), ("3.12.8", "cp311")),
)
def test_runtime_rejects_mismatched_supported_interpreter_pair(
    python_version: str,
    python_abi: str,
) -> None:
    with pytest.raises(ValidationError):
        valid_runtime(python_version=python_version, python_abi=python_abi)


@pytest.mark.parametrize(
    "python_version",
    (
        "3.11",
        "3.11.9rc1",
        "3.11.9+local",
        "3.11.9.1",
        "03.11.9",
        "3.011.9",
        "3.11.09",
        "3.11.9\n",
    ),
)
def test_runtime_model_and_schemas_reject_noncanonical_interpreter_versions(
    python_version: str,
) -> None:
    with pytest.raises(ValidationError):
        valid_runtime(python_version=python_version, python_abi="cp311")

    for rendered_schema, state in (
        (render_operator_state_schema(), valid_commissioning_state()),
        (render_remote_state_schema(), valid_remote_state()),
    ):
        schema = json.loads(rendered_schema)
        validator = Draft202012Validator(schema)
        encoded = state.model_dump(mode="json")
        encoded["deployment"]["runtime"]["python_version"] = python_version
        encoded["deployment"]["runtime"]["python_abi"] = "cp311"
        assert list(validator.iter_errors(encoded))


@pytest.mark.parametrize(
    ("field", "unsafe_path"),
    (
        ("python_executable", "/venvs/owner build/bin/python3"),
        ("python_executable", '/venvs/owner"build/bin/python3'),
        ("python_executable", "/venvs/owner$build/bin/python3"),
        ("python_executable", "/venvs/owner`build/bin/python3"),
        ("remote_home", "/home/owner build"),
        ("remote_home", '/home/owner"build'),
        ("remote_home", "/home/owner\\build"),
        ("remote_home", "/home/owner\tbuild"),
    ),
)
def test_forced_command_paths_reject_shell_and_control_metacharacters(
    field: str,
    unsafe_path: str,
) -> None:
    with pytest.raises(ValidationError):
        if field == "python_executable":
            valid_runtime(python_executable=unsafe_path)
        else:
            unsafe_root = f"{unsafe_path}/.local/share/tuntun/reachy-a05"
            valid_deployment(
                remote_home=unsafe_path,
                remote_root=unsafe_root,
                dispatcher_path=f"{unsafe_root}/bootstrap/reachy_a05_forced_dispatcher.py",
            )


@pytest.mark.parametrize("digest", ("1" * 64 + "\n", "1" * 63))
def test_private_state_model_and_schema_require_exact_sha256_length(digest: str) -> None:
    with pytest.raises(ValidationError):
        valid_runtime(target_tag_set_sha256=digest)

    schema = json.loads(render_operator_state_schema())
    encoded = valid_commissioning_state().model_dump(mode="json")
    encoded["deployment"]["runtime"]["target_tag_set_sha256"] = digest
    assert list(Draft202012Validator(schema).iter_errors(encoded))


@pytest.mark.parametrize(
    "address",
    (
        "8.8.8.8",
        "172.15.1.2",
        "192.169.1.2",
        "10.0.0.999",
        "192.168.050.022",
        "999.999.999.999",
        "192.168.50.22\n",
        "192.168.50.22\r",
    ),
)
def test_commissioning_target_model_and_schema_reject_noncanonical_or_unsafe_address(
    address: str,
) -> None:
    with pytest.raises(ValidationError):
        valid_commissioning_state(reachy_ipv4=address)

    schema = json.loads(render_operator_state_schema())
    encoded = valid_commissioning_state().model_dump(mode="json")
    encoded["reachy_ipv4"] = address
    assert list(Draft202012Validator(schema).iter_errors(encoded))


def test_commissioning_target_schema_accepts_exact_canonical_rfc1918_address() -> None:
    schema = json.loads(render_operator_state_schema())
    encoded = valid_commissioning_state().model_dump(mode="json")

    Draft202012Validator(schema).validate(encoded)


@pytest.mark.parametrize(
    "private_alabel",
    (
        "xn--fa-hia",
        "build-xn--fa-hia-release",
        "BUILD-XN--FA-HIA-RELEASE",
    ),
)
def test_commissioning_version_tokens_reject_alabel_marker_in_model_and_schemas(
    private_alabel: str,
) -> None:
    for field in ("sdk_version", "daemon_version"):
        with pytest.raises(ValidationError):
            valid_runtime(**{field: private_alabel})

        for rendered_schema, state in (
            (render_operator_state_schema(), valid_commissioning_state()),
            (render_remote_state_schema(), valid_remote_state()),
        ):
            encoded = state.model_dump(mode="json")
            encoded["deployment"]["runtime"][field] = private_alabel
            assert list(Draft202012Validator(json.loads(rendered_schema)).iter_errors(encoded))


@pytest.mark.parametrize("line_break", ("\n", "\r", "\r\n"))
@pytest.mark.parametrize(
    "field_path",
    (
        ("deployment", "runtime", "sdk_version"),
        ("deployment", "runtime", "daemon_version"),
        ("deployment", "runtime", "python_executable"),
        ("deployment", "remote_home"),
        ("deployment", "remote_root"),
        ("deployment", "dispatcher_path"),
        ("deployment", "ssh_principal"),
    ),
)
def test_operator_and_remote_schema_lexical_fields_match_crlf_rejection(
    field_path: tuple[str, ...],
    line_break: str,
) -> None:
    for rendered_schema, state, model in (
        (
            render_operator_state_schema(),
            valid_commissioning_state(),
            ReachyA05CommissioningStateV1,
        ),
        (render_remote_state_schema(), valid_remote_state(), ReachyA05RemoteStateV1),
    ):
        encoded = state.model_dump(mode="json")
        target = encoded
        for component in field_path[:-1]:
            target = target[component]
        field = field_path[-1]
        target[field] += line_break
        with pytest.raises(ValidationError):
            model.model_validate(encoded)
        assert list(Draft202012Validator(json.loads(rendered_schema)).iter_errors(encoded))


@pytest.mark.parametrize("line_break", ("\n", "\r", "\r\n"))
@pytest.mark.parametrize("field", ("identity_path", "known_hosts_path"))
def test_operator_only_absolute_paths_match_crlf_rejection(
    field: str,
    line_break: str,
) -> None:
    encoded = valid_commissioning_state().model_dump(mode="json")
    encoded[field] += line_break
    with pytest.raises(ValidationError):
        ReachyA05CommissioningStateV1.model_validate(encoded)

    schema = json.loads(render_operator_state_schema())
    assert list(Draft202012Validator(schema).iter_errors(encoded))


@pytest.mark.parametrize("address", (3232248342, b"\xc0\xa8\x32\x16"))
def test_commissioning_target_rejects_nontextual_ipv4_encodings(
    address: object,
) -> None:
    with pytest.raises(ValidationError):
        valid_commissioning_state(reachy_ipv4=address)


def test_deployment_rejects_root_ssh_principal() -> None:
    with pytest.raises(ValidationError):
        valid_deployment(ssh_principal="root")


def test_all_private_paths_reject_noncanonical_absolute_lexical_forms() -> None:
    with pytest.raises(ValidationError):
        valid_runtime(python_executable="/venvs/apps_venv/../python3")
    with pytest.raises(ValidationError):
        valid_deployment(remote_home="/home/owner/../other")
    with pytest.raises(ValidationError):
        valid_commissioning_state(
            known_hosts_path=("/Users/owner/.local/share/tuntun/reachy-a05//known_hosts")
        )


def test_deployment_rejects_nonfixed_remote_root_or_dispatcher_path() -> None:
    with pytest.raises(ValidationError):
        valid_deployment(remote_root="/srv/tuntun/reachy-a05")
    with pytest.raises(ValidationError):
        valid_deployment(
            dispatcher_path=("/home/owner/.local/share/tuntun/reachy-a05/bootstrap/other.py")
        )


@pytest.mark.parametrize(
    "freshness",
    (timedelta(0), timedelta(seconds=-1), timedelta(hours=24, seconds=1)),
)
def test_deployment_rejects_nonpositive_or_over_24_hour_freshness(
    freshness: timedelta,
) -> None:
    issued_at = datetime(2026, 8, 31, 8, 0, tzinfo=UTC)
    with pytest.raises(ValidationError):
        valid_deployment(issued_at=issued_at, expires_at=issued_at + freshness)


def test_staged_and_active_states_bind_one_exact_content_address() -> None:
    staged = valid_deployment(
        status=ReachyA05StateStatus.STAGED,
        staged_bundle_sha256="b" * 64,
    )
    active = valid_deployment(
        status=ReachyA05StateStatus.ACTIVE,
        active_bundle_sha256="c" * 64,
    )

    assert staged.staged_bundle_sha256 == "b" * 64
    assert staged.active_bundle_sha256 is None
    assert active.staged_bundle_sha256 is None
    assert active.active_bundle_sha256 == "c" * 64


@pytest.mark.parametrize(
    ("status", "staged", "active"),
    (
        (ReachyA05StateStatus.COMMISSIONED, "b" * 64, None),
        (ReachyA05StateStatus.STAGED, None, None),
        (ReachyA05StateStatus.STAGED, "b" * 64, "c" * 64),
        (ReachyA05StateStatus.ACTIVE, None, None),
        (ReachyA05StateStatus.ACTIVE, "b" * 64, "c" * 64),
        (ReachyA05StateStatus.REMOVED, None, "c" * 64),
        (ReachyA05StateStatus.REVOKED, "b" * 64, None),
    ),
)
def test_deployment_rejects_status_generation_mismatch(
    status: ReachyA05StateStatus,
    staged: str | None,
    active: str | None,
) -> None:
    with pytest.raises(ValidationError):
        valid_deployment(
            status=status,
            staged_bundle_sha256=staged,
            active_bundle_sha256=active,
        )


@pytest.mark.parametrize(
    "input_mode",
    (PttInputMode.REACHY_LOCAL, PttInputMode.CORE_TERMINAL_TOGGLE),
)
def test_deployment_binds_exact_ptt_input_mode(input_mode: PttInputMode) -> None:
    deployment = valid_deployment(ptt_input_mode=input_mode)

    assert deployment.ptt_input_mode is input_mode
    encoded = deployment.model_dump(mode="json")
    assert encoded["ptt_input_mode"] == input_mode.value


def test_deployment_rejects_missing_or_unknown_ptt_input_mode() -> None:
    encoded = valid_deployment(ptt_input_mode=PttInputMode.REACHY_LOCAL).model_dump(mode="json")
    encoded.pop("ptt_input_mode")
    with pytest.raises(ValidationError):
        ReachyA05DeploymentBinding.model_validate(encoded)
    encoded["ptt_input_mode"] = "caller-selected"
    with pytest.raises(ValidationError):
        ReachyA05DeploymentBinding.model_validate(encoded)


def test_commissioning_key_and_known_hosts_paths_must_be_distinct() -> None:
    identity_path = "/Users/owner/.local/share/tuntun/reachy-a05/identity"
    with pytest.raises(ValidationError):
        valid_commissioning_state(
            identity_path=identity_path,
            known_hosts_path=identity_path,
        )


def test_commissioning_client_and_host_key_roles_must_be_distinct() -> None:
    shared_key_sha256 = hashlib.sha256(IDENTITY_PUBLIC_KEY_BLOB).hexdigest()

    with pytest.raises(ValidationError):
        valid_commissioning_state(
            identity_public_key_sha256=shared_key_sha256,
            pinned_host_key_sha256=shared_key_sha256,
        )


def test_repository_defense_rejects_same_client_and_host_public_key(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    shared_known_hosts = known_hosts_artifact("192.168.50.22", IDENTITY_PUBLIC_KEY_BLOB)
    known_hosts_path = repository.root / "known_hosts"
    known_hosts_path.write_bytes(shared_known_hosts)
    os.chmod(known_hosts_path, 0o600)
    valid_state = state_for_repository(repository)
    shared_key_sha256 = hashlib.sha256(IDENTITY_PUBLIC_KEY_BLOB).hexdigest()
    forged_state = valid_state.model_copy(
        update={
            "pinned_host_key_sha256": shared_key_sha256,
            "known_hosts_file_sha256": hashlib.sha256(shared_known_hosts).hexdigest(),
        }
    )

    with pytest.raises(ReachyA05RepositoryError, match="artifact"):
        repository.replace_atomic(
            forged_state,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=forged_state.deployment),
        )

    assert not (repository.root / "operator-state.json").exists()


def test_private_state_schema_renderers_are_deterministic_checked_and_valid() -> None:
    operator_rendered = render_operator_state_schema()
    remote_rendered = render_remote_state_schema()

    assert operator_rendered == render_operator_state_schema()
    assert remote_rendered == render_remote_state_schema()
    assert OPERATOR_SCHEMA_PATH.read_bytes() == operator_rendered
    assert REMOTE_SCHEMA_PATH.read_bytes() == remote_rendered
    operator_schema = json.loads(operator_rendered)
    remote_schema = json.loads(remote_rendered)
    assert operator_schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert operator_schema["$id"] == (
        "https://tuntun.local/schemas/evidence/reachy-a05-operator-state.schema.json"
    )
    assert remote_schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert remote_schema["$id"] == (
        "https://tuntun.local/schemas/evidence/reachy-a05-remote-state.schema.json"
    )
    for schema, state, closed_model in (
        (operator_schema, valid_commissioning_state(), "ReachyA05CommissioningStateV1"),
        (remote_schema, valid_remote_state(), None),
    ):
        Draft202012Validator.check_schema(schema)
        if closed_model is None:
            assert schema["additionalProperties"] is False
        else:
            assert schema["discriminator"]["propertyName"] == "record_kind"
            assert schema["$defs"][closed_model]["additionalProperties"] is False
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(
            state.model_dump(mode="json")
        )


def test_private_state_schemas_truthfully_require_runtime_semantic_validation() -> None:
    operator_schema = json.loads(render_operator_state_schema())
    remote_schema = json.loads(render_remote_state_schema())

    for schema in (operator_schema, remote_schema):
        assert schema["x-tuntun-validation-scope"] == "structural"
        assert schema["x-tuntun-runtime-semantic-validation-required"] is True
        assert "model parsing" in schema["description"]


def test_structural_schema_does_not_claim_cross_field_semantic_proof() -> None:
    schema = json.loads(render_operator_state_schema())
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    baseline = valid_commissioning_state().model_dump(mode="json")
    overlong_freshness = json.loads(json.dumps(baseline))
    overlong_freshness["deployment"]["expires_at"] = "2026-09-02T08:00:00Z"
    drifted_remote_layout = json.loads(json.dumps(baseline))
    drifted_remote_layout["deployment"]["remote_root"] = "/srv/tuntun/reachy-a05"
    drifted_remote_layout["deployment"]["dispatcher_path"] = (
        "/srv/tuntun/reachy-a05/bootstrap/reachy_a05_forced_dispatcher.py"
    )
    duplicate_local_paths = json.loads(json.dumps(baseline))
    duplicate_local_paths["known_hosts_path"] = duplicate_local_paths["identity_path"]

    for structurally_valid_but_semantically_invalid in (
        overlong_freshness,
        drifted_remote_layout,
        duplicate_local_paths,
    ):
        assert not list(validator.iter_errors(structurally_valid_but_semantically_invalid))
        with pytest.raises(ValidationError):
            ReachyA05CommissioningStateV1.model_validate_json(
                json.dumps(structurally_valid_but_semantically_invalid)
            )


def test_private_identifiers_exist_only_in_private_state_schema() -> None:
    private_property_names = {
        "identity_path",
        "known_hosts_path",
        "pinned_host_key_sha256",
        "reachy_ipv4",
        "ssh_principal",
    }

    def property_names(value: object) -> set[str]:
        if isinstance(value, dict):
            names = set(value.get("properties", {}))
            return names.union(*(property_names(child) for child in value.values()))
        if isinstance(value, list):
            return set().union(*(property_names(child) for child in value))
        return set()

    operator_properties = property_names(json.loads(render_operator_state_schema()))
    remote_properties = property_names(json.loads(render_remote_state_schema()))
    sanitized_properties = property_names(json.loads(render_capability_schema()))

    assert private_property_names <= operator_properties | remote_properties
    assert sanitized_properties.isdisjoint(private_property_names)


def test_remote_schema_rejects_semantically_unsafe_structural_state() -> None:
    validator = Draft202012Validator(json.loads(render_remote_state_schema()))
    baseline = valid_remote_state().model_dump(mode="json")
    noncanonical_path = json.loads(json.dumps(baseline))
    noncanonical_path["deployment"]["runtime"]["python_executable"] = "/venvs/apps_venv/../python3"
    mismatched_runtime = json.loads(json.dumps(baseline))
    mismatched_runtime["deployment"]["runtime"]["python_abi"] = "cp311"
    mismatched_status = json.loads(json.dumps(baseline))
    mismatched_status["deployment"]["status"] = "staged"

    assert list(validator.iter_errors(noncanonical_path))
    assert list(validator.iter_errors(mismatched_runtime))
    assert list(validator.iter_errors(mismatched_status))


def test_production_repository_resolves_login_database_not_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    login_home = tmp_path / "login-home"
    login_home.mkdir(mode=0o700)
    hostile_home = tmp_path / "environment-home"
    monkeypatch.setenv("HOME", str(hostile_home))
    monkeypatch.setattr(
        "tuntun_core.adapters.reachy.commissioning.pwd.getpwuid",
        lambda uid: SimpleNamespace(pw_dir=str(login_home), pw_uid=uid),
    )

    repository = ReachyA05CommissioningRepository.from_login_home()

    assert repository.root == login_home / ".local/share/tuntun/reachy-a05"
    assert not hostile_home.exists()


def test_repository_publishes_canonical_owner_only_state_and_reads_it(
    tmp_path: Path,
) -> None:
    root = tmp_path / "private-state"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    write_private_artifacts(root)
    repository = ReachyA05CommissioningRepository(root, clock=fixed_repository_time)
    state = state_for_repository(repository)
    remote = valid_remote_state(deployment=state.deployment)
    repository.replace_atomic(
        state,
        expected_generation=0,
        matching_remote_state=remote,
    )
    restored = repository.require_current(expectation=valid_expectation(state))

    assert restored == state
    state_path = root / "operator-state.json"
    lock_path = root / "operator-state.lock"
    assert state_path.read_bytes() == canonical_bytes(state)
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(lock_path.stat().st_mode) == 0o600


def test_spawn_lease_exposes_only_private_snapshot_paths_and_cleans_them(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)

    with repository.acquire_spawn_lease(expectation=valid_expectation(state)) as lease:
        identity_path = Path(lease.identity_path)
        known_hosts_path = Path(lease.known_hosts_path)
        snapshot_root = identity_path.parent
        assert lease.state == state
        assert lease.state.deployment.ptt_input_mode is PttInputMode.REACHY_LOCAL
        assert lease.revalidate() == state
        assert not hasattr(lease, "pass_fds")
        assert not hasattr(lease, "identity_fd_path")
        assert not hasattr(lease, "known_hosts_fd_path")
        assert identity_path.name == "identity"
        assert known_hosts_path == snapshot_root / "known_hosts"
        assert snapshot_root.parent == repository.root
        assert snapshot_root.name.startswith(".spawn-lease.")
        assert stat.S_IMODE(snapshot_root.stat().st_mode) == 0o700
        assert stat.S_IMODE(identity_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(known_hosts_path.stat().st_mode) == 0o600
        assert identity_path.read_bytes() == IDENTITY_ARTIFACT
        assert known_hosts_path.read_bytes() == KNOWN_HOSTS_ARTIFACT
        assert repr(lease) == "ReachyA05SpawnLease(<opaque>)"
        assert state.reachy_ipv4 not in repr(lease)
        assert state.identity_path not in repr(lease)

    assert not identity_path.exists()
    assert not known_hosts_path.exists()
    assert not snapshot_root.exists()
    with pytest.raises(RuntimeError, match="closed"):
        lease.revalidate()


def test_spawn_lease_exposes_installed_openssh_safe_options_for_special_paths(
    tmp_path: Path,
) -> None:
    root = tmp_path / 'private "space%\\root'
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    write_private_artifacts(root)
    repository = ReachyA05CommissioningRepository(root, clock=fixed_repository_time)
    state = publish_initial_state(repository)

    with repository.acquire_spawn_lease(expectation=valid_expectation(state)) as lease:
        assert lease.identity_config_option.startswith('IdentityFile="')
        assert lease.known_hosts_config_option.startswith('UserKnownHostsFile="')
        assert "%%" in lease.identity_config_option
        assert '\\"' in lease.identity_config_option
        assert "\\\\" in lease.identity_config_option
        result = subprocess.run(
            [
                "/usr/bin/ssh",
                "-G",
                "-F",
                "/dev/null",
                "-o",
                lease.identity_config_option,
                "-o",
                lease.known_hosts_config_option,
                "127.0.0.1",
            ],
            capture_output=True,
            text=True,
            check=False,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
        assert result.returncode == 0, result.stderr
        rendered = dict(
            line.split(" ", 1)
            for line in result.stdout.splitlines()
            if line.startswith(("identityfile ", "userknownhostsfile "))
        )
        assert rendered["identityfile"] == lease.identity_path.replace("%", "%%")
        assert rendered["userknownhostsfile"] == lease.known_hosts_path


@pytest.mark.parametrize("keyword", ("IdentityFile", "UserKnownHostsFile"))
@pytest.mark.parametrize("dollar", ("$", "${HOME}"))
def test_openssh_config_option_rejects_environment_expansion_content_free(
    keyword: str,
    dollar: str,
) -> None:
    private_path = f"/private/secret{dollar}payload"

    with pytest.raises(ValueError, match="OpenSSH path is invalid") as caught:
        commissioning_module._openssh_config_option(keyword, private_path)

    assert "secret" not in str(caught.value)
    assert "payload" not in str(caught.value)
    assert "HOME" not in str(caught.value)


@pytest.mark.parametrize("control", ("\x00", "\n", "\r", "\x1f", "\x7f"))
def test_openssh_config_option_rejects_controls_content_free(control: str) -> None:
    private_path = f"/private/secret{control}payload"

    with pytest.raises(ValueError, match="OpenSSH path is invalid") as caught:
        commissioning_module._openssh_config_option("IdentityFile", private_path)

    assert "secret" not in str(caught.value)
    assert "payload" not in str(caught.value)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork ownership contract")
def test_spawn_lease_child_cleanup_cannot_remove_parent_snapshot(tmp_path: Path) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)
    manager = repository.acquire_spawn_lease(expectation=valid_expectation(state))
    lease = manager.__enter__()
    snapshot_root = Path(lease.identity_path).parent
    child = os.fork()
    if child == 0:
        exit_status = 0
        try:
            try:
                lease.revalidate()
            except ReachyA05RepositoryError:
                pass
            else:
                exit_status = 2
            child_exit = SystemExit(0)
            if manager.__exit__(SystemExit, child_exit, None):
                exit_status = 3
        except BaseException:
            exit_status = 4
        os._exit(exit_status)

    try:
        _, wait_status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(wait_status) == 0
        assert snapshot_root.exists()
        assert lease.revalidate() == state
        contender = os.open(repository.root / "operator-state.lock", os.O_RDWR | os.O_CLOEXEC)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(contender)
    finally:
        manager.__exit__(None, None, None)

    assert not snapshot_root.exists()


def _restore_trace_after_interrupt(previous_trace: object) -> None:
    sys.settrace(previous_trace)
    if previous_trace is not None and previous_trace.__class__.__module__ == "coverage":
        restart = getattr(previous_trace, "start", None)
        if callable(restart):
            restart()


def _interrupt_after_cleanup_state_transition(
    function: Callable[..., object],
    callback: Callable[[], None],
) -> None:
    source, first_line = inspect.getsourcelines(function)
    marker_index = next(
        index
        for index, line in enumerate(source)
        if line.strip() in {"self._closing = True", "self._closed = True"}
    )
    target_line = next(
        first_line + index
        for index in range(marker_index + 1, len(source))
        if source[index].strip() and not source[index].lstrip().startswith("#")
    )
    interrupted = False

    def interrupt_once(frame: object, event: str, argument: object) -> object:
        del argument
        nonlocal interrupted
        if (
            not interrupted
            and event == "line"
            and getattr(frame, "f_code", None) is function.__code__
            and getattr(frame, "f_lineno", None) == target_line
        ):
            interrupted = True
            raise KeyboardInterrupt
        return interrupt_once

    previous_trace = sys.gettrace()
    sys.settrace(interrupt_once)
    try:
        with pytest.raises(KeyboardInterrupt):
            callback()
    finally:
        _restore_trace_after_interrupt(previous_trace)
    assert interrupted


class _TraceRestorationProbe:
    def __init__(self) -> None:
        self._closing = False
        self.reached_after_marker = False

    def close(self) -> None:
        self._closing = True
        self.reached_after_marker = True


def test_interrupt_trace_helper_restores_existing_trace() -> None:
    probe = _TraceRestorationProbe()
    outer_trace = sys.gettrace()

    def previous_trace(frame: object, event: str, argument: object) -> object:
        del frame, event, argument
        return previous_trace

    sys.settrace(previous_trace)
    try:
        _interrupt_after_cleanup_state_transition(_TraceRestorationProbe.close, probe.close)
        assert sys.gettrace() is previous_trace
    finally:
        _restore_trace_after_interrupt(outer_trace)


@pytest.mark.parametrize("owner", ("lease", "snapshot"))
def test_spawn_cleanup_state_transition_interruption_is_resumable(
    tmp_path: Path,
    owner: str,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)
    manager = repository.acquire_spawn_lease(expectation=valid_expectation(state))
    lease = manager.__enter__()
    snapshot_root = Path(lease.identity_path).parent
    if owner == "lease":
        function = commissioning_module.ReachyA05SpawnLease._close
    else:
        function = commissioning_module._OwnedSpawnSnapshot.close

    def callback() -> None:
        if owner == "lease":
            lease._close(primary_error=None)
        else:
            lease._snapshot.close(primary_error=None)

    _interrupt_after_cleanup_state_transition(function, callback)
    assert snapshot_root.exists()
    callback()
    assert not snapshot_root.exists()
    context_error = RuntimeError("test context termination")
    assert not manager.__exit__(RuntimeError, context_error, None)


def test_spawn_snapshot_mode_is_independent_of_process_umask(tmp_path: Path) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)
    old_umask = os.umask(0o777)
    try:
        with repository.acquire_spawn_lease(expectation=valid_expectation(state)) as lease:
            snapshot_root = Path(lease.identity_path).parent
            assert stat.S_IMODE(snapshot_root.stat().st_mode) == 0o700
            assert stat.S_IMODE(Path(lease.identity_path).stat().st_mode) == 0o600
            assert stat.S_IMODE(Path(lease.known_hosts_path).stat().st_mode) == 0o600
    finally:
        os.umask(old_umask)

    assert not list(repository.root.glob(".spawn-lease.*"))


def test_spawn_snapshot_recovers_restrictive_umask_directory_chmod_interruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)
    original_chmod = os.chmod
    interrupted = False

    def interrupt_snapshot_chmod(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        mode: int,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        nonlocal interrupted
        if not interrupted and type(path) is str and path.startswith(".spawn-lease."):
            interrupted = True
            raise KeyboardInterrupt
        original_chmod(path, mode, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "chmod", interrupt_snapshot_chmod)
    old_umask = os.umask(0o777)
    try:
        with (
            pytest.raises(KeyboardInterrupt),
            repository.acquire_spawn_lease(expectation=valid_expectation(state)),
        ):
            pytest.fail("interrupted snapshot directory normalization was accepted")
    finally:
        os.umask(old_umask)

    assert interrupted
    assert not list(repository.root.glob(".spawn-lease.*"))
    with repository.acquire_spawn_lease(expectation=valid_expectation(state)) as lease:
        assert lease.revalidate() == state


def test_spawn_snapshot_recovers_restrictive_umask_leaf_fchmod_interruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)
    original_fchmod = os.fchmod
    calls = 0

    def interrupt_identity_fchmod(descriptor: int, mode: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise KeyboardInterrupt
        original_fchmod(descriptor, mode)

    monkeypatch.setattr(os, "fchmod", interrupt_identity_fchmod)
    old_umask = os.umask(0o777)
    try:
        with (
            pytest.raises(KeyboardInterrupt),
            repository.acquire_spawn_lease(expectation=valid_expectation(state)),
        ):
            pytest.fail("interrupted snapshot leaf normalization was accepted")
    finally:
        os.umask(old_umask)

    assert calls >= 2
    assert not list(repository.root.glob(".spawn-lease.*"))
    with repository.acquire_spawn_lease(expectation=valid_expectation(state)) as lease:
        assert lease.revalidate() == state


def test_initial_commissioning_is_independent_of_process_umask(tmp_path: Path) -> None:
    repository = private_repository(tmp_path)
    old_umask = os.umask(0o777)
    try:
        state = publish_initial_state(repository)
    finally:
        os.umask(old_umask)

    assert repository.require_current(expectation=valid_expectation(state)) == state
    assert stat.S_IMODE((repository.root / "operator-state.lock").stat().st_mode) == 0o600
    assert stat.S_IMODE((repository.root / "operator-state.json").stat().st_mode) == 0o600


def test_initial_commissioning_recovers_candidate_fchmod_interruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    original_fchmod = os.fchmod
    calls = 0

    def interrupt_candidate_fchmod(descriptor: int, mode: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise KeyboardInterrupt
        original_fchmod(descriptor, mode)

    monkeypatch.setattr(os, "fchmod", interrupt_candidate_fchmod)
    old_umask = os.umask(0o777)
    try:
        with pytest.raises(KeyboardInterrupt):
            publish_initial_state(repository)
    finally:
        os.umask(old_umask)

    assert calls >= 2
    assert not list(repository.root.glob(".operator-state.*.tmp"))
    state = publish_initial_state(repository)
    assert repository.require_current(expectation=valid_expectation(state)) == state


def test_initial_lock_creation_transition_interruption_is_recoverable(tmp_path: Path) -> None:
    repository = private_repository(tmp_path)
    function = commissioning_module.ReachyA05CommissioningRepository._locked_root.__wrapped__
    source, first_line = inspect.getsourcelines(function)
    target_line = first_line + next(
        index for index, line in enumerate(source) if "lock_owner_pid = os.getpid()" in line
    )
    interrupted = False

    def interrupt_once(frame: object, event: str, argument: object) -> object:
        del argument
        nonlocal interrupted
        if (
            not interrupted
            and event == "line"
            and getattr(frame, "f_code", None) is function.__code__
            and getattr(frame, "f_lineno", None) == target_line
        ):
            interrupted = True
            raise KeyboardInterrupt
        return interrupt_once

    old_umask = os.umask(0o777)
    previous_trace = sys.gettrace()
    sys.settrace(interrupt_once)
    try:
        with pytest.raises(KeyboardInterrupt):
            publish_initial_state(repository)
    finally:
        _restore_trace_after_interrupt(previous_trace)
        os.umask(old_umask)

    assert interrupted
    assert stat.S_IMODE((repository.root / "operator-state.lock").stat().st_mode) == 0o600
    state = publish_initial_state(repository)
    assert repository.require_current(expectation=valid_expectation(state)) == state


def test_spawn_lease_rejects_pickle_without_invalidating_original(tmp_path: Path) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)

    with repository.acquire_spawn_lease(expectation=valid_expectation(state)) as lease:
        with pytest.raises(TypeError, match="noncopyable"):
            pickle.dumps(lease)
        assert lease.revalidate() == state
        assert Path(lease.identity_path).exists()


@pytest.mark.parametrize(
    ("artifact_name", "artifact_content"),
    (
        ("operator-state.json", None),
        ("identity", IDENTITY_ARTIFACT),
        ("known_hosts", KNOWN_HOSTS_ARTIFACT),
    ),
)
def test_spawn_authority_lease_detects_named_inode_replacement_before_spawn(
    tmp_path: Path,
    artifact_name: str,
    artifact_content: bytes | None,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)

    with (
        pytest.raises((PermissionError, ReachyA05RepositoryError)),
        repository.acquire_spawn_lease(expectation=valid_expectation(state)) as lease,
    ):
        replacement = repository.root / f"{artifact_name}.replacement"
        replacement.write_bytes(
            canonical_bytes(state) if artifact_content is None else artifact_content
        )
        os.chmod(replacement, 0o600)
        os.replace(replacement, repository.root / artifact_name)
        lease.revalidate()


def test_spawn_authority_lease_detects_lock_inode_replacement_before_spawn(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)

    with (
        pytest.raises((PermissionError, ReachyA05RepositoryError)),
        repository.acquire_spawn_lease(expectation=valid_expectation(state)) as lease,
    ):
        replacement = repository.root / "operator-state.lock.replacement"
        replacement.write_bytes(b"")
        os.chmod(replacement, 0o600)
        os.replace(replacement, repository.root / "operator-state.lock")
        lease.revalidate()


@pytest.mark.parametrize(
    "error",
    (
        RuntimeError("caller failure"),
        asyncio.CancelledError(),
        KeyboardInterrupt(),
        SystemExit(2),
    ),
)
def test_spawn_lease_closes_exact_descriptors_on_error_or_cancellation(
    tmp_path: Path,
    error: BaseException,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)
    snapshot_paths: tuple[Path, Path]

    with (
        pytest.raises(type(error)),
        repository.acquire_spawn_lease(expectation=valid_expectation(state)) as lease,
    ):
        snapshot_paths = Path(lease.identity_path), Path(lease.known_hosts_path)
        raise error

    for path in snapshot_paths:
        assert not path.exists()
    assert not snapshot_paths[0].parent.exists()


def test_spawn_cleanup_never_retries_an_ambiguously_closed_fd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)
    original_close = os.close
    replacement: list[int] = []
    later_descriptors: tuple[int, ...] = ()
    snapshot_root: Path | None = None

    with (
        pytest.raises(PermissionError, match="spawn authority (?:snapshot|descriptor) cleanup"),
        repository.acquire_spawn_lease(expectation=valid_expectation(state)) as lease,
    ):
        snapshot_root = Path(lease.identity_path).parent
        ordered = (
            lease._snapshot.identity_descriptor,
            lease._snapshot.known_hosts_descriptor,
            lease._snapshot.directory_descriptor,
            lease._state_owner.borrow(),
            lease._identity_owner.borrow(),
            lease._known_hosts_owner.borrow(),
        )
        ambiguous_descriptor = ordered[0]
        later_descriptors = ordered[1:]

        def ambiguous_close(descriptor: int) -> None:
            if descriptor == ambiguous_descriptor and not replacement:
                original_close(descriptor)
                replacement.append(os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC))
                assert replacement[0] == descriptor
                raise KeyboardInterrupt
            original_close(descriptor)

        monkeypatch.setattr(os, "close", ambiguous_close)

    assert snapshot_root is not None
    assert not snapshot_root.exists()
    for descriptor in later_descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    assert len(replacement) == 1
    os.fstat(replacement[0])
    original_close(replacement[0])


def test_spawn_cleanup_recovers_unlink_interruption_and_preserves_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)
    original_unlink = os.unlink
    interrupted = False
    snapshot_root: Path | None = None

    with (
        pytest.raises(KeyboardInterrupt),
        repository.acquire_spawn_lease(expectation=valid_expectation(state)) as lease,
    ):
        snapshot_root = Path(lease.identity_path).parent

        def interrupted_unlink(path: str, *, dir_fd: int | None = None) -> None:
            nonlocal interrupted
            if not interrupted:
                interrupted = True
                raise KeyboardInterrupt
            original_unlink(path, dir_fd=dir_fd)

        monkeypatch.setattr(os, "unlink", interrupted_unlink)

    assert interrupted
    assert snapshot_root is not None
    assert not snapshot_root.exists()


def test_spawn_cleanup_recovers_rmdir_interruption_and_preserves_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)
    original_rmdir = os.rmdir
    interrupted = False
    snapshot_root: Path | None = None

    with (
        pytest.raises(KeyboardInterrupt),
        repository.acquire_spawn_lease(expectation=valid_expectation(state)) as lease,
    ):
        snapshot_root = Path(lease.identity_path).parent

        def interrupted_rmdir(path: str, *, dir_fd: int | None = None) -> None:
            nonlocal interrupted
            if not interrupted:
                interrupted = True
                raise KeyboardInterrupt
            original_rmdir(path, dir_fd=dir_fd)

        monkeypatch.setattr(os, "rmdir", interrupted_rmdir)

    assert interrupted
    assert snapshot_root is not None
    assert not snapshot_root.exists()


def test_spawn_snapshot_reopen_failure_is_content_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)
    original_open = os.open
    observed_name: str | None = None

    def fail_snapshot_reopen(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal observed_name
        if observed_name is None and type(path) is str and path.startswith(".spawn-lease."):
            observed_name = path
            raise OSError(errno.EIO, "injected snapshot reopen", path)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", fail_snapshot_reopen)
    with (
        pytest.raises(PermissionError, match="unsafe Reachy spawn authority snapshot") as caught,
        repository.acquire_spawn_lease(expectation=valid_expectation(state)),
    ):
        pytest.fail("snapshot reopen failure was accepted")

    assert observed_name is not None
    assert observed_name not in str(caught.value)
    assert not list(repository.root.glob(".spawn-lease.*"))


def test_spawn_snapshot_creation_recovers_mkdir_interruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)
    original_mkdir = os.mkdir
    interrupted = False

    def interrupted_mkdir(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal interrupted
        original_mkdir(path, mode, dir_fd=dir_fd)
        if not interrupted and type(path) is str and path.startswith(".spawn-lease."):
            interrupted = True
            raise KeyboardInterrupt

    monkeypatch.setattr(os, "mkdir", interrupted_mkdir)
    with (
        pytest.raises(KeyboardInterrupt),
        repository.acquire_spawn_lease(expectation=valid_expectation(state)),
    ):
        pytest.fail("interrupted snapshot mkdir was accepted")

    assert interrupted
    assert not list(repository.root.glob(".spawn-lease.*"))


@pytest.mark.parametrize("target", ("source", "snapshot"))
def test_spawn_lease_rejects_same_length_in_place_artifact_drift(
    tmp_path: Path,
    target: str,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)

    with (
        pytest.raises(ReachyA05RepositoryError, match="commitment mismatch"),
        repository.acquire_spawn_lease(expectation=valid_expectation(state)) as lease,
    ):
        path = repository.root / "identity" if target == "source" else Path(lease.identity_path)
        original = path.read_bytes()
        with path.open("r+b", buffering=0) as artifact:
            artifact.write(bytes([original[0] ^ 1]) + original[1:])
            os.fsync(artifact.fileno())
        lease.revalidate()


def test_spawn_lease_revalidation_rejects_snapshot_namespace_drift(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)
    rejected_before_spawn = False
    extra: Path | None = None

    with (
        pytest.raises(PermissionError, match="spawn authority snapshot"),
        repository.acquire_spawn_lease(expectation=valid_expectation(state)) as lease,
    ):
        extra = Path(lease.identity_path).parent / "unexpected"
        extra.write_bytes(b"foreign evidence")
        os.chmod(extra, 0o600)
        try:
            lease.revalidate()
        except PermissionError:
            rejected_before_spawn = True
            raise

    assert rejected_before_spawn
    assert extra is not None
    assert extra.exists()


def test_spawn_lease_revalidation_rejects_second_reserved_snapshot(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)
    foreign = repository.root / f".spawn-lease.{'f' * 32}"

    with (
        pytest.raises(PermissionError, match="spawn authority snapshot"),
        repository.acquire_spawn_lease(expectation=valid_expectation(state)) as lease,
    ):
        foreign.mkdir(mode=0o700)
        os.chmod(foreign, 0o700)
        lease.revalidate()

    assert foreign.exists()


def test_spawn_lease_holds_repository_lock_until_snapshot_cleanup(tmp_path: Path) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)

    with repository.acquire_spawn_lease(expectation=valid_expectation(state)):
        contender = os.open(repository.root / "operator-state.lock", os.O_RDWR | os.O_CLOEXEC)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(contender)

    contender = os.open(repository.root / "operator-state.lock", os.O_RDWR | os.O_CLOEXEC)
    try:
        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(contender, fcntl.LOCK_UN)
    finally:
        os.close(contender)


def test_spawn_lease_reconciles_only_an_exact_stale_private_snapshot(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)
    stale = repository.root / f".spawn-lease.{'a' * 32}"
    stale.mkdir(mode=0o700)
    os.chmod(stale, 0o700)
    for name, content in (("identity", b"stale"), ("known_hosts", b"stale")):
        path = stale / name
        path.write_bytes(content)
        os.chmod(path, 0o600)

    with repository.acquire_spawn_lease(expectation=valid_expectation(state)) as lease:
        assert not stale.exists()
        assert Path(lease.identity_path).exists()

    malformed = repository.root / ".spawn-lease.foreign"
    malformed.mkdir(mode=0o700)
    os.chmod(malformed, 0o700)
    with (
        pytest.raises(PermissionError, match="spawn authority snapshot"),
        repository.acquire_spawn_lease(expectation=valid_expectation(state)),
    ):
        pytest.fail("unsafe reserved snapshot was accepted")
    assert malformed.exists()


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS OpenSSH descriptor contract")
def test_spawn_snapshot_paths_work_with_installed_macos_openssh(
    tmp_path: Path,
) -> None:
    ssh = Path("/usr/bin/ssh")
    sshd = Path("/usr/sbin/sshd")
    if not ssh.is_file() or not sshd.is_file():
        pytest.skip("installed macOS OpenSSH client and daemon are required")

    root = tmp_path / 'private "space%\\root'
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    write_private_artifacts(root)
    repository = ReachyA05CommissioningRepository(root, clock=fixed_repository_time)
    host_key = tmp_path / "host_key"
    host_key.write_bytes(HOST_IDENTITY_ARTIFACT)
    os.chmod(host_key, 0o600)
    known_hosts = known_hosts_artifact("192.168.50.22", HOST_PUBLIC_KEY_BLOB)
    (repository.root / "known_hosts").write_bytes(known_hosts)
    os.chmod(repository.root / "known_hosts", 0o600)
    state = state_for_repository(
        repository,
        pinned_host_key_sha256=hashlib.sha256(HOST_PUBLIC_KEY_BLOB).hexdigest(),
        known_hosts_file_sha256=hashlib.sha256(known_hosts).hexdigest(),
    )
    repository.replace_atomic(
        state,
        expected_generation=0,
        matching_remote_state=valid_remote_state(deployment=state.deployment),
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(("127.0.0.1", 0))
        except PermissionError:
            pytest.skip("sandbox does not allow the installed-OpenSSH loopback proof")
        port = probe.getsockname()[1]
    server = subprocess.Popen(
        [
            str(sshd),
            "-D",
            "-e",
            "-f",
            "/dev/null",
            "-h",
            str(host_key),
            "-o",
            "ListenAddress=127.0.0.1",
            "-o",
            f"Port={port}",
            "-o",
            f"PidFile={tmp_path / 'sshd.pid'}",
            "-o",
            "AuthorizedKeysFile=none",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "PubkeyAuthentication=yes",
            "-o",
            "UsePAM=no",
            "-o",
            "StrictModes=no",
            "-o",
            "LogLevel=ERROR",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if server.poll() is not None:
                stderr = server.stderr.read() if server.stderr is not None else ""
                pytest.fail(f"loopback sshd exited before listening: {stderr}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.02)
        else:
            pytest.fail("loopback sshd did not listen")

        with repository.acquire_spawn_lease(expectation=valid_expectation(state)) as lease:
            lease.revalidate()
            identity_path = Path(lease.identity_path)
            known_hosts_path = Path(lease.known_hosts_path)
            client = subprocess.Popen(
                [
                    str(ssh),
                    "-vvv",
                    "-4",
                    "-T",
                    "-F",
                    "/dev/null",
                    "-p",
                    str(port),
                    "-o",
                    lease.identity_config_option,
                    "-o",
                    "IdentitiesOnly=yes",
                    "-o",
                    "IdentityAgent=none",
                    "-o",
                    "StrictHostKeyChecking=yes",
                    "-o",
                    lease.known_hosts_config_option,
                    "-o",
                    "GlobalKnownHostsFile=/dev/null",
                    "-o",
                    "HostKeyAlias=192.168.50.22",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "PreferredAuthentications=publickey",
                    "-o",
                    "NumberOfPasswordPrompts=0",
                    "-o",
                    "ConnectTimeout=2",
                    "--",
                    f"{pwd.getpwuid(os.geteuid()).pw_name}@127.0.0.1",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            )
            assert identity_path.exists()
            assert known_hosts_path.exists()
            _, client_stderr = client.communicate(timeout=8)
            assert client.returncode != 0
            assert "Bad file descriptor" not in client_stderr
            assert "no such identity" not in client_stderr
            assert "Host key verification failed" not in client_stderr
            assert "Offering public key" in client_stderr
            lease.revalidate()
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)


def test_repository_rejects_nonprivate_root_without_creating_files(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    os.chmod(repository.root, 0o755)
    state = state_for_repository(repository)

    with pytest.raises(PermissionError, match="unsafe application path"):
        repository.replace_atomic(
            state,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=state.deployment),
        )

    assert not (repository.root / "operator-state.json").exists()
    assert not (repository.root / "operator-state.lock").exists()


def test_bound_state_schema_requires_artifact_file_commitments() -> None:
    assert {
        "identity_public_key_type",
        "pinned_host_key_type",
        "identity_file_sha256",
        "known_hosts_file_sha256",
    } <= set(ReachyA05CommissioningStateV1.model_fields)


@pytest.mark.parametrize(
    ("artifact_name", "artifact_content", "state_updates"),
    (
        ("identity", b"not-an-openssh-private-key\n", {}),
        (
            "known_hosts",
            b"192.168.50.23 ssh-ed25519 " + base64.b64encode(PINNED_HOST_KEY_BLOB) + b"\n",
            {},
        ),
        (
            "known_hosts",
            KNOWN_HOSTS_ARTIFACT + KNOWN_HOSTS_ARTIFACT,
            {},
        ),
        ("identity", IDENTITY_ARTIFACT, {"identity_public_key_sha256": "f" * 64}),
        ("known_hosts", KNOWN_HOSTS_ARTIFACT, {"pinned_host_key_sha256": "f" * 64}),
    ),
)
def test_repository_rejects_artifacts_without_exact_semantic_ssh_commitments(
    tmp_path: Path,
    artifact_name: str,
    artifact_content: bytes,
    state_updates: dict[str, object],
) -> None:
    repository = private_repository(tmp_path)
    artifact_path = repository.root / artifact_name
    artifact_path.write_bytes(artifact_content)
    os.chmod(artifact_path, 0o600)
    hash_field = (
        "identity_file_sha256" if artifact_name == "identity" else "known_hosts_file_sha256"
    )
    state = state_for_repository(
        repository,
        **{
            hash_field: hashlib.sha256(artifact_content).hexdigest(),
            **state_updates,
        },
    )

    with pytest.raises(ReachyA05RepositoryError, match="artifact"):
        repository.replace_atomic(
            state,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=state.deployment),
        )

    assert not (repository.root / "operator-state.json").exists()


def test_repository_rejects_identity_whose_public_key_is_not_derived_from_seed(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    forged_identity, forged_public_blob = openssh_ed25519_identity(
        b"F" * 32,
        embedded_public_key=b"G" * 32,
    )
    identity_path = repository.root / "identity"
    identity_path.write_bytes(forged_identity)
    os.chmod(identity_path, 0o600)
    state = state_for_repository(
        repository,
        identity_public_key_sha256=hashlib.sha256(forged_public_blob).hexdigest(),
        identity_file_sha256=hashlib.sha256(forged_identity).hexdigest(),
    )

    with pytest.raises(ReachyA05RepositoryError, match="artifact semantics"):
        repository.replace_atomic(
            state,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=state.deployment),
        )

    assert not (repository.root / "operator-state.json").exists()


def test_v1_rejects_unparsed_non_ed25519_host_key_shapes_in_model_and_schema() -> None:
    with pytest.raises(ValidationError):
        valid_commissioning_state(pinned_host_key_type="ecdsa-sha2-nistp256")

    encoded = valid_commissioning_state().model_dump(mode="json")
    encoded["pinned_host_key_type"] = "ecdsa-sha2-nistp256"
    encoded["pinned_host_key_sha256"] = hashlib.sha256(
        ssh_string(b"ecdsa-sha2-nistp256") + b"malformed-tail"
    ).hexdigest()
    assert list(
        Draft202012Validator(json.loads(render_operator_state_schema())).iter_errors(encoded)
    )


def test_repository_rejects_missing_identity_and_known_hosts_artifacts(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    state = state_for_repository(repository)
    (repository.root / "identity").unlink()
    (repository.root / "known_hosts").unlink()

    with pytest.raises(ReachyA05RepositoryError, match="artifact"):
        repository.replace_atomic(
            state,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=state.deployment),
        )

    assert not (repository.root / "operator-state.json").exists()


def test_repository_rejects_symlinked_root_ancestry(
    tmp_path: Path,
) -> None:
    actual_root = tmp_path / "actual" / "private-state"
    actual_root.mkdir(parents=True, mode=0o700)
    os.chmod(actual_root, 0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path / "actual", target_is_directory=True)
    repository = ReachyA05CommissioningRepository(alias / "private-state")
    state = state_for_repository(repository)

    with pytest.raises(PermissionError, match="unsafe application path"):
        repository.replace_atomic(
            state,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=state.deployment),
        )

    assert not list(actual_root.iterdir())


def test_repository_rejects_root_reported_with_wrong_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    root_metadata = repository.root.stat()

    def reported_owner_with_root_substitution(metadata: os.stat_result) -> int:
        if (metadata.st_dev, metadata.st_ino) == (
            root_metadata.st_dev,
            root_metadata.st_ino,
        ):
            return os.geteuid() + 1
        return metadata.st_uid

    monkeypatch.setattr(
        secure_paths_module,
        "_reported_owner",
        reported_owner_with_root_substitution,
    )
    state = state_for_repository(repository)

    with pytest.raises(PermissionError, match="unsafe application path"):
        repository.replace_atomic(
            state,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=state.deployment),
        )


@pytest.mark.parametrize("unsafe_kind", ("permissive", "symlink", "directory"))
def test_repository_rejects_unsafe_state_file_kind_or_mode(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)
    state_path = repository.root / "operator-state.json"
    if unsafe_kind == "permissive":
        os.chmod(state_path, 0o644)
    elif unsafe_kind == "symlink":
        backing = repository.root / "operator-state.backing"
        state_path.replace(backing)
        state_path.symlink_to(backing.name)
    elif unsafe_kind == "directory":
        state_path.unlink()
        state_path.mkdir(mode=0o700)
    else:
        raise AssertionError(f"unknown unsafe kind: {unsafe_kind}")

    with pytest.raises(PermissionError, match="commissioning state file"):
        repository.require_current(
            expectation=valid_expectation(state),
        )


@pytest.mark.parametrize("unsafe_kind", ("permissive", "symlink", "directory"))
def test_repository_rejects_unsafe_lock_file_kind_or_mode(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)
    lock_path = repository.root / "operator-state.lock"
    if unsafe_kind == "permissive":
        os.chmod(lock_path, 0o644)
    elif unsafe_kind == "symlink":
        backing = repository.root / "operator-state.lock.backing"
        lock_path.replace(backing)
        lock_path.symlink_to(backing.name)
    elif unsafe_kind == "directory":
        lock_path.unlink()
        lock_path.mkdir(mode=0o700)
    else:
        raise AssertionError(f"unknown unsafe kind: {unsafe_kind}")

    with pytest.raises(PermissionError):
        repository.require_current(
            expectation=valid_expectation(state),
        )


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin extended-ACL witness")
@pytest.mark.parametrize(
    "target_name",
    ("operator-state.lock", "operator-state.json", "identity", "known_hosts"),
)
def test_repository_rejects_real_darwin_extended_acl_on_private_file(
    tmp_path: Path,
    target_name: str,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)
    target = repository.root / target_name
    subprocess.run(
        ["chmod", "+a", "everyone allow read", str(target)],
        check=True,
        capture_output=True,
    )

    with pytest.raises(PermissionError):
        repository.require_current(expectation=valid_expectation(state))


@pytest.mark.parametrize(
    "target_name",
    ("operator-state.lock", "operator-state.json", "identity", "known_hosts", "temp"),
)
def test_every_private_regular_file_descriptor_rejects_targeted_acl(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_name: str,
) -> None:
    repository = private_repository(tmp_path)
    state = state_for_repository(repository)
    if target_name == "temp":
        candidate_sha256 = hashlib.sha256(canonical_bytes(state)).hexdigest()
        target = repository.root / f".operator-state.g1.{candidate_sha256}.tmp"
        target.write_bytes(canonical_bytes(state))
        os.chmod(target, 0o600)
    else:
        state = publish_initial_state(repository)
        target = repository.root / target_name
    target_identity = (target.stat().st_dev, target.stat().st_ino)
    real_inspector = secure_paths_module._descriptor_has_unsafe_acl

    def targeted_inspector(
        descriptor: int,
        *,
        reject_default_acl: bool = True,
    ) -> bool:
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == target_identity:
            return True
        return real_inspector(descriptor, reject_default_acl=reject_default_acl)

    monkeypatch.setattr(
        secure_paths_module,
        "_descriptor_has_unsafe_acl",
        targeted_inspector,
    )

    with pytest.raises(PermissionError):
        if target_name == "temp":
            repository.replace_atomic(
                state,
                expected_generation=0,
                matching_remote_state=valid_remote_state(deployment=state.deployment),
            )
        else:
            repository.require_current(expectation=valid_expectation(state))


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin extended-ACL witness")
def test_repository_rejects_real_darwin_extended_acl_on_candidate_temp(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    state = state_for_repository(repository)
    candidate_sha256 = hashlib.sha256(canonical_bytes(state)).hexdigest()
    target = repository.root / f".operator-state.g1.{candidate_sha256}.tmp"
    target.write_bytes(canonical_bytes(state))
    os.chmod(target, 0o600)
    subprocess.run(
        ["chmod", "+a", "everyone allow read", str(target)],
        check=True,
        capture_output=True,
    )

    with pytest.raises(PermissionError):
        repository.replace_atomic(
            state,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=state.deployment),
        )


@pytest.mark.parametrize("inspection_result", (True, OSError("injected ACL failure")))
def test_repository_rejects_unsafe_or_uninspectable_acl_on_regular_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    inspection_result: bool | OSError,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)
    real_inspector = secure_paths_module._descriptor_has_unsafe_acl

    def inspect_regular_file(
        descriptor: int,
        *,
        reject_default_acl: bool = True,
    ) -> bool:
        if stat.S_ISREG(os.fstat(descriptor).st_mode):
            if isinstance(inspection_result, OSError):
                raise inspection_result
            return inspection_result
        return real_inspector(descriptor, reject_default_acl=reject_default_acl)

    monkeypatch.setattr(
        secure_paths_module,
        "_descriptor_has_unsafe_acl",
        inspect_regular_file,
    )

    with pytest.raises(PermissionError):
        repository.require_current(expectation=valid_expectation(state))


def test_repository_rejects_state_file_reported_with_wrong_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)
    state_metadata = (repository.root / "operator-state.json").stat()
    real_fstat = os.fstat

    def fstat_with_wrong_state_owner(descriptor: int) -> os.stat_result:
        metadata = real_fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) != (
            state_metadata.st_dev,
            state_metadata.st_ino,
        ):
            return metadata
        values = list(metadata)
        values[4] = os.geteuid() + 1
        return os.stat_result(values)

    monkeypatch.setattr(commissioning_module.os, "fstat", fstat_with_wrong_state_owner)

    with pytest.raises(PermissionError, match="commissioning state file"):
        repository.require_current(
            expectation=valid_expectation(state),
        )


def test_repository_rejects_lock_file_reported_with_wrong_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)
    lock_metadata = (repository.root / "operator-state.lock").stat()
    real_fstat = os.fstat

    def fstat_with_wrong_lock_owner(descriptor: int) -> os.stat_result:
        metadata = real_fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) != (
            lock_metadata.st_dev,
            lock_metadata.st_ino,
        ):
            return metadata
        values = list(metadata)
        values[4] = os.geteuid() + 1
        return os.stat_result(values)

    monkeypatch.setattr(commissioning_module.os, "fstat", fstat_with_wrong_lock_owner)

    with pytest.raises(PermissionError, match="commissioning state file"):
        repository.require_current(
            expectation=valid_expectation(state),
        )


@pytest.mark.parametrize("drift", ("mode", "owner", "link_count"))
def test_repository_rejects_unsafe_named_metadata_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)
    real_stat = os.stat

    def stat_with_named_drift(
        path: str | bytes | int | os.PathLike[str] | os.PathLike[bytes],
        *args: object,
        **kwargs: object,
    ) -> os.stat_result:
        metadata = real_stat(path, *args, **kwargs)
        if path != "operator-state.json" or kwargs.get("dir_fd") is None:
            return metadata
        values = list(metadata)
        if drift == "mode":
            values[0] = stat.S_IFREG | 0o644
        elif drift == "owner":
            values[4] = os.geteuid() + 1
        elif drift == "link_count":
            values[3] = 2
        else:
            raise AssertionError(f"unknown drift: {drift}")
        return os.stat_result(values)

    monkeypatch.setattr(commissioning_module.os, "stat", stat_with_named_drift)

    with pytest.raises(PermissionError, match="commissioning state file"):
        repository.require_current(
            expectation=valid_expectation(state),
        )


@pytest.mark.parametrize("invalid_encoding", ("oversized", "noncanonical"))
def test_repository_rejects_oversized_or_noncanonical_state(
    tmp_path: Path,
    invalid_encoding: str,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)
    state_path = repository.root / "operator-state.json"
    if invalid_encoding == "oversized":
        state_path.write_bytes(b"x" * 32_769)
    elif invalid_encoding == "noncanonical":
        state_path.write_text(
            json.dumps(state.model_dump(mode="json"), indent=2),
            encoding="utf-8",
        )
    else:
        raise AssertionError(f"unknown encoding: {invalid_encoding}")
    os.chmod(state_path, 0o600)

    with pytest.raises(ReachyA05RepositoryError):
        repository.require_current(
            expectation=valid_expectation(state),
        )


def test_repository_rejects_state_outside_current_time_window(
    tmp_path: Path,
) -> None:
    current_time = [fixed_repository_time()]
    repository = private_repository(tmp_path, clock=lambda: current_time[0])
    state = publish_initial_state(repository)
    current_time[0] = state.deployment.expires_at

    with pytest.raises(ReachyA05RepositoryError, match="stale"):
        repository.require_current(expectation=valid_expectation(state))


def test_repository_uses_its_clock_and_rejects_exact_expiry_boundary(
    tmp_path: Path,
) -> None:
    root = tmp_path / "private-state"
    root.mkdir(mode=0o700)
    write_private_artifacts(root)
    current_time = [datetime(2026, 8, 31, 9, 0, tzinfo=UTC)]
    repository = ReachyA05CommissioningRepository(
        root,
        clock=lambda: current_time[0],
    )
    state = state_for_repository(repository)
    repository.replace_atomic(
        state,
        expected_generation=0,
        matching_remote_state=valid_remote_state(deployment=state.deployment),
    )
    current_time[0] = state.deployment.expires_at

    with pytest.raises(ReachyA05RepositoryError, match="stale"):
        repository.require_current(expectation=valid_expectation(state))


@pytest.mark.parametrize(
    ("offset_from_boundary", "boundary", "accepted"),
    (
        (timedelta(microseconds=-1), "issued", False),
        (timedelta(0), "issued", True),
        (timedelta(microseconds=-1), "expiry", True),
        (timedelta(0), "expiry", False),
    ),
)
def test_repository_pins_exact_issued_and_expiry_microsecond_boundaries(
    tmp_path: Path,
    offset_from_boundary: timedelta,
    boundary: str,
    accepted: bool,
) -> None:
    current_time = [fixed_repository_time()]
    repository = private_repository(tmp_path, clock=lambda: current_time[0])
    state = publish_initial_state(repository)
    reference = state.deployment.issued_at if boundary == "issued" else state.deployment.expires_at
    current_time[0] = reference + offset_from_boundary

    if accepted:
        assert repository.require_current(expectation=valid_expectation(state)) == state
    else:
        with pytest.raises(ReachyA05RepositoryError, match="stale"):
            repository.require_current(expectation=valid_expectation(state))


def test_repository_rechecks_clock_after_temp_fsync_before_publication(
    tmp_path: Path,
) -> None:
    root = tmp_path / "private-state"
    root.mkdir(mode=0o700)
    write_private_artifacts(root)
    issued_at = datetime(2026, 8, 31, 8, 0, tzinfo=UTC)
    expires_at = issued_at + timedelta(hours=1)
    readings = iter((expires_at - timedelta(microseconds=1), expires_at))
    repository = ReachyA05CommissioningRepository(root, clock=lambda: next(readings))
    state = state_for_repository(
        repository,
        deployment=valid_deployment(issued_at=issued_at, expires_at=expires_at),
    )

    with pytest.raises(ReachyA05RepositoryError, match="stale"):
        repository.replace_atomic(
            state,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=state.deployment),
        )

    assert not (root / "operator-state.json").exists()
    assert not list(root.glob(".operator-state.*.tmp"))


def test_repository_rejects_update_when_current_expires_on_second_clock_sample(
    tmp_path: Path,
) -> None:
    current_time = [fixed_repository_time()]
    readings: Iterator[datetime] | None = None

    def advancing_clock() -> datetime:
        return current_time[0] if readings is None else next(readings)

    repository = private_repository(tmp_path, clock=advancing_clock)
    initial = publish_initial_state(repository)
    next_deployment = valid_deployment(
        state_generation=2,
        status=ReachyA05StateStatus.STAGED,
        issued_at=initial.deployment.expires_at - timedelta(hours=1),
        expires_at=initial.deployment.expires_at + timedelta(hours=23),
        staged_bundle_sha256="b" * 64,
    )
    candidate = state_for_repository(repository, deployment=next_deployment)
    readings = iter(
        (
            initial.deployment.expires_at - timedelta(microseconds=1),
            initial.deployment.expires_at,
        )
    )

    with pytest.raises(ReachyA05RepositoryError, match="stale"):
        repository.replace_atomic(
            candidate,
            expected_generation=1,
            expected_current=valid_expectation(initial),
            matching_remote_state=valid_remote_state(deployment=next_deployment),
        )

    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(initial)
    assert not list(repository.root.glob(".operator-state.*.tmp"))


@pytest.mark.parametrize(
    "invalid_time",
    (
        "2026-08-31T09:00:00Z",
        datetime(2026, 8, 31, 9, 0),
        datetime(2026, 8, 31, 17, 0, tzinfo=timezone(timedelta(hours=8))),
    ),
)
def test_repository_rejects_non_datetime_naive_or_non_utc_clock_results(
    tmp_path: Path,
    invalid_time: object,
) -> None:
    root = tmp_path / "private-state"
    root.mkdir(mode=0o700)
    repository = ReachyA05CommissioningRepository(root, clock=lambda: invalid_time)  # type: ignore[arg-type,return-value]
    state = state_for_repository(repository)

    with pytest.raises(TypeError, match="timezone-aware UTC datetime"):
        repository.replace_atomic(
            state,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=state.deployment),
        )

    assert not (root / "operator-state.json").exists()


def test_repository_samples_clock_only_while_exclusive_lock_is_held(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "private-state"
    root.mkdir(mode=0o700)
    write_private_artifacts(root)
    lock_held = False
    clock_calls = 0
    real_flock = fcntl.flock

    def tracked_flock(descriptor: int, operation: int) -> None:
        nonlocal lock_held
        real_flock(descriptor, operation)
        if operation == fcntl.LOCK_EX:
            lock_held = True
        elif operation == fcntl.LOCK_UN:
            lock_held = False

    def observed_clock() -> datetime:
        nonlocal clock_calls
        assert lock_held is True
        clock_calls += 1
        return fixed_repository_time()

    monkeypatch.setattr(commissioning_module.fcntl, "flock", tracked_flock)
    repository = ReachyA05CommissioningRepository(root, clock=observed_clock)
    state = state_for_repository(repository)
    repository.replace_atomic(
        state,
        expected_generation=0,
        matching_remote_state=valid_remote_state(deployment=state.deployment),
    )
    repository.require_current(expectation=valid_expectation(state))

    assert clock_calls == 3
    assert lock_held is False


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("boot_identity_sha256", "b" * 64),
        ("capability_report_sha256", "c" * 64),
        ("runtime_inventory_sha256", "d" * 64),
        ("dispatcher_sha256", "e" * 64),
        ("authorized_key_line_sha256", "f" * 64),
    ),
)
def test_repository_rejects_live_commitment_mismatch(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)

    with pytest.raises(ReachyA05RepositoryError, match="commitment mismatch"):
        repository.require_current(
            expectation=valid_expectation(state, **{field: value}),
        )


def test_repository_rejects_local_and_remote_semantic_mismatch(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    state = state_for_repository(repository)
    mismatched_remote = valid_remote_state(
        deployment=valid_deployment(capability_report_sha256="b" * 64)
    )

    with pytest.raises(ReachyA05RepositoryError, match="local and remote"):
        repository.replace_atomic(
            state,
            expected_generation=0,
            matching_remote_state=mismatched_remote,
        )

    assert not (repository.root / "operator-state.json").exists()


def test_repository_rejects_existing_state_on_create_cas(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    initial = publish_initial_state(repository)
    candidate = state_for_repository(
        repository,
        deployment=valid_deployment(capability_report_sha256="b" * 64),
    )

    with pytest.raises(ReachyA05RepositoryError, match="CAS mismatch"):
        repository.replace_atomic(
            candidate,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=candidate.deployment),
        )

    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(initial)


def test_repository_update_requires_exact_prior_state_expectation(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    initial = publish_initial_state(repository)
    next_deployment = valid_deployment(
        state_generation=2,
        status=ReachyA05StateStatus.STAGED,
        staged_bundle_sha256="b" * 64,
    )
    candidate = state_for_repository(repository, deployment=next_deployment)

    with pytest.raises(ValueError, match="requires a prior-state expectation"):
        repository.replace_atomic(
            candidate,
            expected_generation=1,
            matching_remote_state=valid_remote_state(deployment=next_deployment),
        )

    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(initial)


@pytest.mark.parametrize(
    "substitution",
    (
        "target",
        "remote_layout",
        "runtime",
        "ptt_input_mode",
        "key_commitments",
        "content_address",
    ),
)
def test_repository_update_cas_binds_exact_prior_state_not_only_generation(
    tmp_path: Path,
    substitution: str,
) -> None:
    repository = private_repository(tmp_path)
    expected_prior = publish_initial_state(repository)
    substituted_prior = substituted_security_state(expected_prior, substitution)
    state_path = repository.root / "operator-state.json"
    state_path.write_bytes(canonical_bytes(substituted_prior))
    os.chmod(state_path, 0o600)
    next_deployment = valid_deployment(
        state_generation=2,
        status=ReachyA05StateStatus.STAGED,
        staged_bundle_sha256="b" * 64,
    )
    candidate = state_for_repository(repository, deployment=next_deployment)

    with pytest.raises(ReachyA05RepositoryError, match="commitment mismatch"):
        repository.replace_atomic(
            candidate,
            expected_generation=1,
            expected_current=valid_expectation(expected_prior),
            matching_remote_state=valid_remote_state(deployment=next_deployment),
        )

    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(
        substituted_prior
    )


def test_repository_rejects_stale_candidate_without_publishing_state(
    tmp_path: Path,
) -> None:
    stale_time = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
    repository = private_repository(tmp_path, clock=lambda: stale_time)
    state = state_for_repository(repository)

    with pytest.raises(ReachyA05RepositoryError, match="stale"):
        repository.replace_atomic(
            state,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=state.deployment),
        )

    assert not (repository.root / "operator-state.json").exists()
    assert not list(repository.root.glob(".operator-state.*.tmp"))
    assert stat.S_IMODE((repository.root / "operator-state.lock").stat().st_mode) == 0o600


def test_repository_fails_closed_when_current_cas_generation_is_expired(
    tmp_path: Path,
) -> None:
    current_time = [fixed_repository_time()]
    repository = private_repository(tmp_path, clock=lambda: current_time[0])
    initial = publish_initial_state(repository)
    issued_at = initial.deployment.expires_at
    next_deployment = valid_deployment(
        state_generation=2,
        status=ReachyA05StateStatus.STAGED,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(hours=24),
        staged_bundle_sha256="b" * 64,
    )
    candidate = state_for_repository(repository, deployment=next_deployment)
    current_time[0] = issued_at + timedelta(minutes=1)

    with pytest.raises(ReachyA05RepositoryError, match="stale"):
        repository.replace_atomic(
            candidate,
            expected_generation=1,
            expected_current=valid_expectation(initial),
            matching_remote_state=valid_remote_state(deployment=next_deployment),
        )

    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(initial)
    assert not list(repository.root.glob(".operator-state.*.tmp"))


@pytest.mark.parametrize(
    ("current_status", "terminal_status"),
    (
        (ReachyA05StateStatus.COMMISSIONED, ReachyA05StateStatus.REMOVED),
        (ReachyA05StateStatus.COMMISSIONED, ReachyA05StateStatus.REVOKED),
        (ReachyA05StateStatus.STAGED, ReachyA05StateStatus.REMOVED),
        (ReachyA05StateStatus.STAGED, ReachyA05StateStatus.REVOKED),
        (ReachyA05StateStatus.ACTIVE, ReachyA05StateStatus.REMOVED),
        (ReachyA05StateStatus.ACTIVE, ReachyA05StateStatus.REVOKED),
        (ReachyA05StateStatus.REMOVED, ReachyA05StateStatus.REVOKED),
    ),
)
def test_terminal_recovery_allows_only_approved_expired_transitions(
    tmp_path: Path,
    current_status: ReachyA05StateStatus,
    terminal_status: ReachyA05StateStatus,
) -> None:
    current_time = [fixed_repository_time()]
    repository = private_repository(tmp_path, clock=lambda: current_time[0])
    current = publish_state_with_status(repository, current_status)
    if terminal_status is ReachyA05StateStatus.REVOKED:
        candidate: ReachyA05CommissioningStateV1 | ReachyA05RevokedTombstoneV1 = revoked_tombstone(
            current
        )
        (repository.root / "identity").unlink()
        (repository.root / "known_hosts").unlink()
        matching_remote = None
        remote_absence_proof = candidate.revocation_proof_sha256
        expectation: ReachyA05StateExpectation | ReachyA05RevokedStateExpectation = (
            revoked_expectation(candidate)
        )
    else:
        candidate = terminal_recovery_candidate(repository, current, terminal_status)
        matching_remote = valid_remote_state(deployment=candidate.deployment)
        remote_absence_proof = None
        expectation = valid_expectation(candidate)
    current_time[0] = current.deployment.expires_at

    repository.recover_stale_terminal(
        candidate,
        expected_current=valid_expectation(current),
        matching_recovery_remote_state=matching_remote,
        remote_absence_proof_sha256=remote_absence_proof,
    )

    assert repository.require_current(expectation=expectation) == candidate


def test_terminal_recovery_rejects_regressed_candidate_and_revocation_times(
    tmp_path: Path,
) -> None:
    issued_at = datetime(2026, 8, 31, 8, 0, tzinfo=UTC)
    expires_at = issued_at + timedelta(hours=1)
    current_time = [issued_at + timedelta(minutes=30)]
    repository = private_repository(tmp_path, clock=lambda: current_time[0])
    current = state_for_repository(
        repository,
        deployment=valid_deployment(issued_at=issued_at, expires_at=expires_at),
    )
    repository.replace_atomic(
        current,
        expected_generation=0,
        matching_remote_state=valid_remote_state(deployment=current.deployment),
    )
    current_time[0] = expires_at

    candidate_values = terminal_recovery_candidate(
        repository,
        current,
        ReachyA05StateStatus.REMOVED,
    ).deployment.model_dump()
    candidate_values.update(
        issued_at=issued_at - timedelta(microseconds=1),
        expires_at=expires_at + timedelta(hours=23) - timedelta(microseconds=1),
    )
    regressed_candidate = state_for_repository(
        repository,
        deployment=ReachyA05DeploymentBinding.model_validate(candidate_values),
    )
    with pytest.raises(ReachyA05RepositoryError, match="issued_at"):
        repository.recover_stale_terminal(
            regressed_candidate,
            expected_current=valid_expectation(current),
            matching_recovery_remote_state=valid_remote_state(
                deployment=regressed_candidate.deployment
            ),
        )

    tombstone_values = revoked_tombstone(current).model_dump()
    tombstone_values["revoked_at"] = issued_at - timedelta(microseconds=1)
    regressed_tombstone = ReachyA05RevokedTombstoneV1.model_validate(tombstone_values)
    (repository.root / "identity").unlink()
    (repository.root / "known_hosts").unlink()
    with pytest.raises(ReachyA05RepositoryError, match="revoked_at"):
        repository.recover_stale_terminal(
            regressed_tombstone,
            expected_current=valid_expectation(current),
            matching_recovery_remote_state=None,
            remote_absence_proof_sha256=regressed_tombstone.revocation_proof_sha256,
        )

    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(current)


def test_terminal_revocation_recovery_rejects_preexisting_reserved_temp(
    tmp_path: Path,
) -> None:
    current_time = [fixed_repository_time()]
    repository = private_repository(tmp_path, clock=lambda: current_time[0])
    current = publish_initial_state(repository)
    tombstone = revoked_tombstone(current)
    (repository.root / "identity").unlink()
    (repository.root / "known_hosts").unlink()
    foreign_temp = repository.root / ".operator-state.unverified.tmp"
    foreign_temp.write_bytes(canonical_bytes(current))
    os.chmod(foreign_temp, 0o600)
    current_time[0] = current.deployment.expires_at

    with pytest.raises(ReachyA05RepositoryError, match="reserved temp"):
        repository.recover_stale_terminal(
            tombstone,
            expected_current=valid_expectation(current),
            matching_recovery_remote_state=None,
            remote_absence_proof_sha256=tombstone.revocation_proof_sha256,
        )

    assert foreign_temp.read_bytes() == canonical_bytes(current)
    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(current)


def test_terminal_removed_recovery_rejects_preexisting_reserved_temp(
    tmp_path: Path,
) -> None:
    current_time = [fixed_repository_time()]
    repository = private_repository(tmp_path, clock=lambda: current_time[0])
    current = publish_initial_state(repository)
    candidate = terminal_recovery_candidate(
        repository,
        current,
        ReachyA05StateStatus.REMOVED,
    )
    foreign_temp = repository.root / ".operator-state.unverified.tmp"
    foreign_temp.write_bytes(canonical_bytes(current))
    os.chmod(foreign_temp, 0o600)
    current_time[0] = current.deployment.expires_at

    with pytest.raises(ReachyA05RepositoryError, match="reserved temp"):
        repository.recover_stale_terminal(
            candidate,
            expected_current=valid_expectation(current),
            matching_recovery_remote_state=valid_remote_state(deployment=candidate.deployment),
        )

    assert foreign_temp.read_bytes() == canonical_bytes(current)
    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(current)


def test_terminal_removed_post_publication_temp_is_post_commit_uncertainty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_time = [fixed_repository_time()]
    repository = private_repository(tmp_path, clock=lambda: current_time[0])
    current = publish_initial_state(repository)
    candidate = terminal_recovery_candidate(
        repository,
        current,
        ReachyA05StateStatus.REMOVED,
    )
    foreign_temp = repository.root / ".operator-state.post-publication.tmp"
    real_write = ReachyA05CommissioningRepository._write_atomic

    def write_then_inject(
        self: ReachyA05CommissioningRepository,
        root: object,
        state: object,
        **kwargs: object,
    ) -> tuple[int, int]:
        published = real_write(self, root, state, **kwargs)  # type: ignore[arg-type]
        foreign_temp.write_bytes(canonical_bytes(current))
        os.chmod(foreign_temp, 0o600)
        return published

    monkeypatch.setattr(
        ReachyA05CommissioningRepository,
        "_write_atomic",
        write_then_inject,
    )
    current_time[0] = current.deployment.expires_at

    with pytest.raises(commissioning_module.ReachyA05PostCommitError) as captured:
        repository.recover_stale_terminal(
            candidate,
            expected_current=valid_expectation(current),
            matching_recovery_remote_state=valid_remote_state(deployment=candidate.deployment),
        )

    assert captured.value.candidate_generation == candidate.deployment.state_generation
    assert (
        captured.value.candidate_state_sha256
        == hashlib.sha256(canonical_bytes(candidate)).hexdigest()
    )
    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(candidate)
    with pytest.raises(ReachyA05RepositoryError, match="reserved temp"):
        repository.require_current(expectation=valid_expectation(candidate))
    assert (
        repository.reconcile_commit_unknown(
            captured.value,
            candidate=candidate,
            expected_current=valid_expectation(current),
        )
        is commissioning_module.ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
    )


def test_terminal_removed_predecessor_temp_reconciles_exactly_and_idempotently(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_time = [fixed_repository_time()]
    repository = private_repository(tmp_path, clock=lambda: current_time[0])
    current = publish_initial_state(repository)
    candidate = terminal_recovery_candidate(
        repository,
        current,
        ReachyA05StateStatus.REMOVED,
    )
    real_unlink = os.unlink
    injected = False

    def fail_predecessor_unlink(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal injected
        if not injected and str(path).startswith(".operator-state."):
            injected = True
            raise OSError("injected removed predecessor unlink failure")
        real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(commissioning_module.os, "unlink", fail_predecessor_unlink)
    current_time[0] = current.deployment.expires_at
    with pytest.raises(commissioning_module.ReachyA05PostCommitError) as captured:
        repository.recover_stale_terminal(
            candidate,
            expected_current=valid_expectation(current),
            matching_recovery_remote_state=valid_remote_state(deployment=candidate.deployment),
        )

    monkeypatch.setattr(commissioning_module.os, "unlink", real_unlink)
    for _ in range(2):
        assert (
            repository.reconcile_commit_unknown(
                captured.value,
                candidate=candidate,
                expected_current=valid_expectation(current),
            )
            is commissioning_module.ReachyA05CommitReconciliation.COMMITTED
        )
    assert repository.require_current(expectation=valid_expectation(candidate)) == candidate
    assert not list(repository.root.glob(".operator-state.*.tmp"))


def test_terminal_removed_exact_candidate_temp_requires_recovery_before_retry(
    tmp_path: Path,
) -> None:
    current_time = [fixed_repository_time()]
    repository = private_repository(tmp_path, clock=lambda: current_time[0])
    current = publish_initial_state(repository)
    candidate = terminal_recovery_candidate(
        repository,
        current,
        ReachyA05StateStatus.REMOVED,
    )
    candidate_raw = canonical_bytes(candidate)
    candidate_sha256 = hashlib.sha256(candidate_raw).hexdigest()
    candidate_temp = repository.root / f".operator-state.g2.{candidate_sha256}.tmp"
    candidate_temp.write_bytes(candidate_raw)
    os.chmod(candidate_temp, 0o600)
    current_time[0] = current.deployment.expires_at

    with pytest.raises(ReachyA05RepositoryError, match="reserved temp"):
        repository.recover_stale_terminal(
            candidate,
            expected_current=valid_expectation(current),
            matching_recovery_remote_state=valid_remote_state(deployment=candidate.deployment),
        )

    assert (
        repository.recover_exact_candidate_update_temp(
            candidate=candidate,
            expected_current=valid_expectation(current),
        )
        is commissioning_module.ReachyA05CommitReconciliation.NOT_COMMITTED
    )
    repository.recover_stale_terminal(
        candidate,
        expected_current=valid_expectation(current),
        matching_recovery_remote_state=valid_remote_state(deployment=candidate.deployment),
    )

    assert repository.require_current(expectation=valid_expectation(candidate)) == candidate
    assert not candidate_temp.exists()


@pytest.mark.parametrize(
    ("current_status", "candidate_status"),
    (
        (ReachyA05StateStatus.REMOVED, ReachyA05StateStatus.REMOVED),
        (ReachyA05StateStatus.COMMISSIONED, ReachyA05StateStatus.COMMISSIONED),
        (ReachyA05StateStatus.COMMISSIONED, ReachyA05StateStatus.STAGED),
        (ReachyA05StateStatus.COMMISSIONED, ReachyA05StateStatus.ACTIVE),
    ),
)
def test_terminal_recovery_rejects_nonterminal_repeat_and_revoked_resurrection(
    tmp_path: Path,
    current_status: ReachyA05StateStatus,
    candidate_status: ReachyA05StateStatus,
) -> None:
    current_time = [fixed_repository_time()]
    repository = private_repository(tmp_path, clock=lambda: current_time[0])
    current = publish_state_with_status(repository, current_status)
    deployment_values = current.deployment.model_dump()
    deployment_values.update(
        state_generation=current.deployment.state_generation + 1,
        status=candidate_status,
        issued_at=current.deployment.expires_at,
        expires_at=current.deployment.expires_at + timedelta(hours=24),
        staged_bundle_sha256="b" * 64 if candidate_status is ReachyA05StateStatus.STAGED else None,
        active_bundle_sha256="c" * 64 if candidate_status is ReachyA05StateStatus.ACTIVE else None,
    )
    candidate = state_for_repository(
        repository,
        deployment=ReachyA05DeploymentBinding.model_validate(deployment_values),
    )
    current_time[0] = current.deployment.expires_at

    with pytest.raises(ReachyA05RepositoryError, match="terminal recovery"):
        repository.recover_stale_terminal(
            candidate,
            expected_current=valid_expectation(current),
            matching_recovery_remote_state=valid_remote_state(deployment=candidate.deployment),
        )

    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(current)


@pytest.mark.parametrize(
    "drift",
    ("target", "remote_layout", "runtime", "local_keys", "dispatcher"),
)
def test_terminal_recovery_preserves_all_target_runtime_key_and_dispatcher_bindings(
    tmp_path: Path,
    drift: str,
) -> None:
    current_time = [fixed_repository_time()]
    repository = private_repository(tmp_path, clock=lambda: current_time[0])
    current = publish_initial_state(repository)
    candidate = terminal_recovery_candidate(
        repository,
        current,
        ReachyA05StateStatus.REMOVED,
    )
    values = candidate.model_dump()
    deployment = values["deployment"]
    assert isinstance(deployment, dict)
    runtime = deployment["runtime"]
    assert isinstance(runtime, dict)
    if drift == "target":
        values["reachy_ipv4"] = "192.168.50.23"
    elif drift == "remote_layout":
        deployment.update(
            ssh_principal="other",
            remote_home="/home/other",
            remote_root="/home/other/.local/share/tuntun/reachy-a05",
            dispatcher_path=(
                "/home/other/.local/share/tuntun/reachy-a05/bootstrap/"
                "reachy_a05_forced_dispatcher.py"
            ),
        )
    elif drift == "runtime":
        runtime["runtime_inventory_sha256"] = "d" * 64
    elif drift == "local_keys":
        values["identity_public_key_sha256"] = "e" * 64
        values["pinned_host_key_sha256"] = "f" * 64
    elif drift == "dispatcher":
        deployment["dispatcher_sha256"] = "0" * 64
        deployment["authorized_key_line_sha256"] = "1" * 64
    else:
        raise AssertionError(f"unknown drift: {drift}")
    drifted = ReachyA05CommissioningStateV1.model_validate(values)
    current_time[0] = current.deployment.expires_at

    with pytest.raises(ReachyA05RepositoryError, match="binding drift"):
        repository.recover_stale_terminal(
            drifted,
            expected_current=valid_expectation(current),
            matching_recovery_remote_state=valid_remote_state(deployment=drifted.deployment),
        )


def test_terminal_recovery_requires_expired_prior_and_fresh_matching_remote_evidence(
    tmp_path: Path,
) -> None:
    current_time = [fixed_repository_time()]
    repository = private_repository(tmp_path, clock=lambda: current_time[0])
    current = publish_initial_state(repository)
    candidate = terminal_recovery_candidate(
        repository,
        current,
        ReachyA05StateStatus.REMOVED,
    )

    with pytest.raises(ReachyA05RepositoryError, match="not expired"):
        repository.recover_stale_terminal(
            candidate,
            expected_current=valid_expectation(current),
            matching_recovery_remote_state=valid_remote_state(deployment=candidate.deployment),
        )

    current_time[0] = candidate.deployment.expires_at
    with pytest.raises(ReachyA05RepositoryError, match="stale"):
        repository.recover_stale_terminal(
            candidate,
            expected_current=valid_expectation(current),
            matching_recovery_remote_state=valid_remote_state(deployment=candidate.deployment),
        )

    current_time[0] = current.deployment.expires_at
    mismatched_remote = valid_remote_state(
        deployment=valid_deployment(
            state_generation=2,
            status=ReachyA05StateStatus.REMOVED,
            issued_at=candidate.deployment.issued_at,
            expires_at=candidate.deployment.expires_at,
            capability_report_sha256="d" * 64,
        )
    )
    with pytest.raises(ReachyA05RepositoryError, match="recovery evidence"):
        repository.recover_stale_terminal(
            candidate,
            expected_current=valid_expectation(current),
            matching_recovery_remote_state=mismatched_remote,
        )


def test_terminal_recovery_requires_exact_full_prior_commitment(
    tmp_path: Path,
) -> None:
    current_time = [fixed_repository_time()]
    repository = private_repository(tmp_path, clock=lambda: current_time[0])
    current = publish_initial_state(repository)
    candidate = revoked_tombstone(current)
    (repository.root / "identity").unlink()
    (repository.root / "known_hosts").unlink()
    current_time[0] = current.deployment.expires_at

    with pytest.raises(ReachyA05RepositoryError, match="commitment mismatch"):
        repository.recover_stale_terminal(
            candidate,
            expected_current=valid_expectation(current, state_sha256="0" * 64),
            matching_recovery_remote_state=None,
            remote_absence_proof_sha256=candidate.revocation_proof_sha256,
        )

    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(current)


def test_repository_rejects_state_with_nonfixed_local_artifact_paths(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    state = valid_commissioning_state()

    with pytest.raises(ReachyA05RepositoryError, match="local artifact paths"):
        repository.replace_atomic(
            state,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=state.deployment),
        )

    assert not (repository.root / "operator-state.json").exists()


def test_state_expectation_accepts_canonical_full_state_commitment() -> None:
    state = valid_commissioning_state()
    expectation = ReachyA05StateExpectation.model_validate(
        {
            **valid_expectation().model_dump(),
            "state_sha256": hashlib.sha256(canonical_bytes(state)).hexdigest(),
        }
    )

    assert expectation.state_sha256 == hashlib.sha256(canonical_bytes(state)).hexdigest()


@pytest.mark.parametrize(
    "substitution",
    ("target", "remote_layout", "runtime", "key_commitments", "content_address"),
)
def test_repository_rejects_any_security_relevant_state_substitution(
    tmp_path: Path,
    substitution: str,
) -> None:
    repository = private_repository(tmp_path)
    expected = publish_initial_state(repository)
    substituted = substituted_security_state(expected, substitution)
    state_path = repository.root / "operator-state.json"
    state_path.write_bytes(canonical_bytes(substituted))
    os.chmod(state_path, 0o600)

    with pytest.raises(ReachyA05RepositoryError, match="commitment mismatch"):
        repository.require_current(
            expectation=valid_expectation(expected),
        )


def test_repository_revalidates_named_lock_inode_after_acquiring_flock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    replacement = repository.root / "replacement.lock"
    replacement.write_bytes(b"")
    os.chmod(replacement, 0o600)
    real_flock = fcntl.flock
    drift_injected = False

    def flock_with_drift(descriptor: int, operation: int) -> None:
        nonlocal drift_injected
        real_flock(descriptor, operation)
        if operation == fcntl.LOCK_EX and not drift_injected:
            drift_injected = True
            os.replace(replacement, repository.root / "operator-state.lock")

    monkeypatch.setattr(commissioning_module.fcntl, "flock", flock_with_drift)
    state = state_for_repository(repository)

    with pytest.raises(PermissionError, match="commissioning state file"):
        repository.replace_atomic(
            state,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=state.deployment),
        )

    assert drift_injected is True
    assert not (repository.root / "operator-state.json").exists()


def test_repository_revalidates_named_lock_after_yielded_critical_section(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)
    replacement = repository.root / "replacement.lock"
    replacement.write_bytes(b"")
    os.chmod(replacement, 0o600)
    real_require_expectation = ReachyA05CommissioningRepository._require_expectation

    def require_expectation_with_lock_drift(
        observed: ReachyA05CommissioningStateV1,
        expectation: ReachyA05StateExpectation,
    ) -> None:
        real_require_expectation(observed, expectation)
        os.replace(replacement, repository.root / "operator-state.lock")

    monkeypatch.setattr(
        ReachyA05CommissioningRepository,
        "_require_expectation",
        staticmethod(require_expectation_with_lock_drift),
    )

    with pytest.raises(PermissionError, match="commissioning state file"):
        repository.require_current(expectation=valid_expectation(state))


def test_atomic_namespace_primitives_are_real_on_the_tmp_filesystem(
    tmp_path: Path,
) -> None:
    directory_descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        (tmp_path / "first").write_bytes(b"first")
        (tmp_path / "second").write_bytes(b"second")

        commissioning_module._rename_noreplace(directory_descriptor, "first", "published")
        assert not (tmp_path / "first").exists()
        assert (tmp_path / "published").read_bytes() == b"first"
        with pytest.raises(FileExistsError):
            commissioning_module._rename_noreplace(
                directory_descriptor,
                "second",
                "published",
            )
        commissioning_module._rename_exchange(
            directory_descriptor,
            "second",
            "published",
        )

        assert (tmp_path / "second").read_bytes() == b"first"
        assert (tmp_path / "published").read_bytes() == b"second"
    finally:
        os.close(directory_descriptor)


def test_initial_publication_resumes_exact_durable_candidate_temp(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    candidate = state_for_repository(repository)
    raw = canonical_bytes(candidate)
    digest = hashlib.sha256(raw).hexdigest()
    temporary_path = repository.root / f".operator-state.g1.{digest}.tmp"
    temporary_path.write_bytes(raw)
    os.chmod(temporary_path, 0o600)
    with temporary_path.open("rb") as staged:
        os.fsync(staged.fileno())

    repository.replace_atomic(
        candidate,
        expected_generation=0,
        matching_remote_state=valid_remote_state(deployment=candidate.deployment),
    )

    assert (repository.root / "operator-state.json").read_bytes() == raw
    assert not temporary_path.exists()


def test_initial_publication_never_deletes_or_publishes_foreign_candidate_temp(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    candidate = state_for_repository(repository)
    digest = hashlib.sha256(canonical_bytes(candidate)).hexdigest()
    temporary_path = repository.root / f".operator-state.g1.{digest}.tmp"
    temporary_path.write_bytes(b"{}")
    os.chmod(temporary_path, 0o600)

    with pytest.raises(ReachyA05RepositoryError, match="candidate"):
        repository.replace_atomic(
            candidate,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=candidate.deployment),
        )

    assert temporary_path.read_bytes() == b"{}"
    assert not (repository.root / "operator-state.json").exists()


def test_initial_publication_noreplace_preserves_injected_predecessor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    candidate = state_for_repository(repository)
    predecessor = substituted_security_state(candidate, "runtime")
    real_noreplace = getattr(commissioning_module, "_rename_noreplace", None)
    injected = False

    def noreplace_with_predecessor(
        directory_descriptor: int,
        source: str,
        destination: str,
    ) -> None:
        nonlocal injected
        assert callable(real_noreplace)
        if not injected:
            injected = True
            state_path = repository.root / destination
            state_path.write_bytes(canonical_bytes(predecessor))
            os.chmod(state_path, 0o600)
        real_noreplace(directory_descriptor, source, destination)

    monkeypatch.setattr(
        commissioning_module,
        "_rename_noreplace",
        noreplace_with_predecessor,
        raising=False,
    )

    with pytest.raises(ReachyA05RepositoryError, match="CAS mismatch"):
        repository.replace_atomic(
            candidate,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=candidate.deployment),
        )

    assert injected is True
    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(predecessor)
    assert not list(repository.root.glob(".operator-state.*.tmp"))


def test_update_exchange_rolls_back_injected_predecessor_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    initial = publish_initial_state(repository)
    predecessor = substituted_security_state(initial, "runtime")
    predecessor_path = repository.root / "replacement.json"
    predecessor_path.write_bytes(canonical_bytes(predecessor))
    os.chmod(predecessor_path, 0o600)
    next_deployment = valid_deployment(
        state_generation=2,
        status=ReachyA05StateStatus.STAGED,
        staged_bundle_sha256="b" * 64,
    )
    candidate = state_for_repository(repository, deployment=next_deployment)
    real_exchange = getattr(commissioning_module, "_rename_exchange", None)
    injected = False

    def exchange_with_predecessor_swap(
        directory_descriptor: int,
        source: str,
        destination: str,
    ) -> None:
        nonlocal injected
        assert callable(real_exchange)
        if not injected:
            injected = True
            os.replace(predecessor_path, repository.root / "operator-state.json")
        real_exchange(directory_descriptor, source, destination)

    monkeypatch.setattr(
        commissioning_module,
        "_rename_exchange",
        exchange_with_predecessor_swap,
        raising=False,
    )

    with pytest.raises(ReachyA05RepositoryError, match="publication predecessor mismatch"):
        repository.replace_atomic(
            candidate,
            expected_generation=1,
            expected_current=valid_expectation(initial),
            matching_remote_state=valid_remote_state(deployment=next_deployment),
        )

    assert injected is True
    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(predecessor)
    assert not list(repository.root.glob(".operator-state.*.tmp"))


def test_parent_fsync_failure_is_commit_unknown_and_exactly_reconciled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    initial = publish_initial_state(repository)
    next_deployment = valid_deployment(
        state_generation=2,
        status=ReachyA05StateStatus.STAGED,
        staged_bundle_sha256="b" * 64,
    )
    candidate = state_for_repository(repository, deployment=next_deployment)
    candidate_sha256 = hashlib.sha256(canonical_bytes(candidate)).hexdigest()
    real_fsync = os.fsync
    parent_fsyncs = 0

    def fail_first_postpublication_parent_fsync(descriptor: int) -> None:
        nonlocal parent_fsyncs
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            parent_fsyncs += 1
            if parent_fsyncs == 2:
                raise OSError("injected parent fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(
        commissioning_module.os,
        "fsync",
        fail_first_postpublication_parent_fsync,
    )

    with pytest.raises(commissioning_module.ReachyA05CommitUnknown) as captured:
        repository.replace_atomic(
            candidate,
            expected_generation=1,
            expected_current=valid_expectation(initial),
            matching_remote_state=valid_remote_state(deployment=next_deployment),
        )

    uncertainty = captured.value
    assert uncertainty.candidate_generation == 2
    assert uncertainty.candidate_state_sha256 == candidate_sha256
    assert set(uncertainty.__dict__) == {
        "candidate_generation",
        "candidate_state_sha256",
    }
    assert "192.168" not in str(uncertainty)
    assert "/Users/" not in str(uncertainty)
    evidence = list(repository.root.glob(".operator-state.*.tmp"))
    assert len(evidence) == 1
    assert evidence[0].read_bytes() == canonical_bytes(initial)
    with pytest.raises(ReachyA05RepositoryError, match="reserved temp"):
        repository.replace_atomic(
            candidate,
            expected_generation=1,
            expected_current=valid_expectation(initial),
            matching_remote_state=valid_remote_state(deployment=next_deployment),
        )

    def forbidden_publication_retry(*args: object, **kwargs: object) -> None:
        del args, kwargs
        pytest.fail("commit reconciliation must not retry namespace publication")

    monkeypatch.setattr(commissioning_module, "_rename_noreplace", forbidden_publication_retry)
    monkeypatch.setattr(commissioning_module, "_rename_exchange", forbidden_publication_retry)

    outcome = repository.reconcile_commit_unknown(
        uncertainty,
        candidate=candidate,
        expected_current=valid_expectation(initial),
    )

    assert outcome is commissioning_module.ReachyA05CommitReconciliation.COMMITTED
    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(candidate)
    assert not list(repository.root.glob(".operator-state.*.tmp"))


def test_commit_reconciliation_distinguishes_exact_prior_and_indeterminate_state(
    tmp_path: Path,
) -> None:
    prior_parent = tmp_path / "prior"
    prior_parent.mkdir()
    prior_repository = private_repository(prior_parent)
    initial = publish_initial_state(prior_repository)
    candidate_deployment = valid_deployment(
        state_generation=2,
        status=ReachyA05StateStatus.STAGED,
        staged_bundle_sha256="b" * 64,
    )
    candidate = state_for_repository(prior_repository, deployment=candidate_deployment)
    uncertainty = commissioning_module.ReachyA05CommitUnknown(
        candidate_generation=2,
        candidate_state_sha256=hashlib.sha256(canonical_bytes(candidate)).hexdigest(),
    )

    assert (
        prior_repository.reconcile_commit_unknown(
            uncertainty,
            candidate=candidate,
            expected_current=valid_expectation(initial),
        )
        is commissioning_module.ReachyA05CommitReconciliation.NOT_COMMITTED
    )

    absent_parent = tmp_path / "absent"
    absent_parent.mkdir()
    absent_repository = private_repository(absent_parent)
    absent_candidate = state_for_repository(absent_repository)
    absent_uncertainty = commissioning_module.ReachyA05CommitUnknown(
        candidate_generation=1,
        candidate_state_sha256=hashlib.sha256(canonical_bytes(absent_candidate)).hexdigest(),
    )
    assert (
        absent_repository.reconcile_commit_unknown(
            absent_uncertainty,
            candidate=absent_candidate,
        )
        is commissioning_module.ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
    )


@pytest.mark.parametrize("observed_kind", ("third_valid", "malformed"))
def test_commit_reconciliation_rejects_third_or_malformed_named_state(
    tmp_path: Path,
    observed_kind: str,
) -> None:
    repository = private_repository(tmp_path)
    candidate = state_for_repository(repository)
    if observed_kind == "third_valid":
        third = substituted_security_state(candidate, "runtime")
        repository.replace_atomic(
            third,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=third.deployment),
        )
    elif observed_kind == "malformed":
        state_path = repository.root / "operator-state.json"
        state_path.write_bytes(b"{}")
        os.chmod(state_path, 0o600)
    else:
        raise AssertionError(f"unknown observed kind: {observed_kind}")
    uncertainty = commissioning_module.ReachyA05CommitUnknown(
        candidate_generation=1,
        candidate_state_sha256=hashlib.sha256(canonical_bytes(candidate)).hexdigest(),
    )

    assert (
        repository.reconcile_commit_unknown(
            uncertainty,
            candidate=candidate,
        )
        is commissioning_module.ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
    )


def test_commit_reconciliation_persistent_parent_fsync_failure_is_indeterminate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    initial = publish_initial_state(repository)
    next_deployment = valid_deployment(
        state_generation=2,
        status=ReachyA05StateStatus.STAGED,
        staged_bundle_sha256="b" * 64,
    )
    candidate = state_for_repository(repository, deployment=next_deployment)
    real_fsync = os.fsync
    parent_fsyncs = 0

    def fail_parent_fsync(descriptor: int) -> None:
        nonlocal parent_fsyncs
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            parent_fsyncs += 1
            if parent_fsyncs >= 2:
                raise OSError("persistent parent fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(commissioning_module.os, "fsync", fail_parent_fsync)
    with pytest.raises(commissioning_module.ReachyA05CommitUnknown) as captured:
        repository.replace_atomic(
            candidate,
            expected_generation=1,
            expected_current=valid_expectation(initial),
            matching_remote_state=valid_remote_state(deployment=next_deployment),
        )

    assert (
        repository.reconcile_commit_unknown(
            captured.value,
            candidate=candidate,
            expected_current=valid_expectation(initial),
        )
        is commissioning_module.ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
    )


@pytest.mark.parametrize("remove_then_raise", (False, True))
def test_displaced_predecessor_unlink_failure_is_post_commit_not_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    remove_then_raise: bool,
) -> None:
    repository = private_repository(tmp_path)
    initial = publish_initial_state(repository)
    next_deployment = valid_deployment(
        state_generation=2,
        status=ReachyA05StateStatus.STAGED,
        staged_bundle_sha256="b" * 64,
    )
    candidate = state_for_repository(repository, deployment=next_deployment)
    real_exchange = commissioning_module._rename_exchange
    real_unlink = os.unlink
    exchange_calls = 0
    unlink_injected = False

    def recording_exchange(
        directory_descriptor: int,
        source: str,
        destination: str,
    ) -> None:
        nonlocal exchange_calls
        exchange_calls += 1
        real_exchange(directory_descriptor, source, destination)

    def failing_evidence_unlink(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal unlink_injected
        if not unlink_injected and str(path).startswith(".operator-state."):
            unlink_injected = True
            if remove_then_raise:
                real_unlink(path, dir_fd=dir_fd)
            raise OSError("injected post-commit unlink ambiguity")
        real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(commissioning_module, "_rename_exchange", recording_exchange)
    monkeypatch.setattr(commissioning_module.os, "unlink", failing_evidence_unlink)

    with pytest.raises(commissioning_module.ReachyA05PostCommitError) as captured:
        repository.replace_atomic(
            candidate,
            expected_generation=1,
            expected_current=valid_expectation(initial),
            matching_remote_state=valid_remote_state(deployment=next_deployment),
        )

    assert captured.value.candidate_generation == 2
    assert set(captured.value.__dict__) == {
        "candidate_generation",
        "candidate_state_sha256",
    }
    assert "192.168" not in str(captured.value)
    assert "/Users/" not in str(captured.value)
    assert exchange_calls == 1
    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(candidate)
    evidence = list(repository.root.glob(".operator-state.*.tmp"))
    assert bool(evidence) is not remove_then_raise


def test_revoked_post_commit_error_requires_exact_reconciliation_before_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    removed = publish_removed_state(repository)
    tombstone = revoked_tombstone(removed)
    (repository.root / "identity").unlink()
    (repository.root / "known_hosts").unlink()
    real_unlink = os.unlink
    injected = False

    def fail_predecessor_unlink(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal injected
        if not injected and str(path).startswith(".operator-state."):
            injected = True
            raise OSError("injected predecessor unlink failure")
        real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(commissioning_module.os, "unlink", fail_predecessor_unlink)
    with pytest.raises(commissioning_module.ReachyA05PostCommitError) as captured:
        repository.publish_revoked_tombstone(
            tombstone,
            expected_current=valid_expectation(removed),
            remote_absence_proof_sha256=tombstone.revocation_proof_sha256,
        )

    monkeypatch.setattr(commissioning_module.os, "unlink", real_unlink)
    with pytest.raises(ReachyA05RepositoryError, match="reserved temp"):
        repository.require_current(expectation=revoked_expectation(tombstone))

    assert (
        repository.reconcile_commit_unknown(
            captured.value,
            candidate=tombstone,
            expected_current=valid_expectation(removed),
        )
        is commissioning_module.ReachyA05CommitReconciliation.COMMITTED
    )
    assert repository.require_current(expectation=revoked_expectation(tombstone)) == tombstone
    assert not list(repository.root.glob(".operator-state.*.tmp"))


def test_post_unlink_parent_fsync_failure_reconciles_without_predecessor_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    initial = publish_initial_state(repository)
    deployment = valid_deployment(
        state_generation=2,
        status=ReachyA05StateStatus.STAGED,
        staged_bundle_sha256="b" * 64,
    )
    candidate = state_for_repository(repository, deployment=deployment)
    real_fsync = os.fsync
    parent_fsyncs = 0

    def fail_post_unlink_parent_fsync(descriptor: int) -> None:
        nonlocal parent_fsyncs
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            parent_fsyncs += 1
            if parent_fsyncs == 3:
                raise OSError("injected post-unlink parent fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(
        commissioning_module.os,
        "fsync",
        fail_post_unlink_parent_fsync,
    )
    with pytest.raises(commissioning_module.ReachyA05PostCommitError) as captured:
        repository.replace_atomic(
            candidate,
            expected_generation=1,
            expected_current=valid_expectation(initial),
            matching_remote_state=valid_remote_state(deployment=deployment),
        )

    monkeypatch.setattr(commissioning_module.os, "fsync", real_fsync)
    assert not list(repository.root.glob(".operator-state.*.tmp"))
    assert (
        repository.reconcile_commit_unknown(
            captured.value,
            candidate=candidate,
            expected_current=valid_expectation(initial),
        )
        is commissioning_module.ReachyA05CommitReconciliation.COMMITTED
    )


def test_exact_initial_candidate_temp_has_a_nonpublishing_recovery_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_time = [fixed_repository_time()]
    repository = private_repository(tmp_path, clock=lambda: current_time[0])
    stale_issued_at = current_time[0] - timedelta(hours=25)
    stale_deployment = valid_deployment(
        issued_at=stale_issued_at,
        expires_at=stale_issued_at + timedelta(hours=24),
    )
    stale_candidate = state_for_repository(repository, deployment=stale_deployment)
    stale_raw = canonical_bytes(stale_candidate)
    stale_sha256 = hashlib.sha256(stale_raw).hexdigest()
    stale_temp = repository.root / f".operator-state.g1.{stale_sha256}.tmp"
    stale_temp.write_bytes(stale_raw)
    os.chmod(stale_temp, 0o600)
    with stale_temp.open("rb") as staged:
        os.fsync(staged.fileno())

    with pytest.raises(ReachyA05RepositoryError, match="stale"):
        repository.replace_atomic(
            stale_candidate,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=stale_deployment),
        )
    assert stale_temp.exists()

    fresh_deployment = valid_deployment(
        issued_at=current_time[0],
        expires_at=current_time[0] + timedelta(hours=24),
    )
    fresh_candidate = state_for_repository(repository, deployment=fresh_deployment)
    with pytest.raises(ReachyA05RepositoryError, match="reserved temp"):
        repository.replace_atomic(
            fresh_candidate,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=fresh_deployment),
        )

    real_fsync = os.fsync
    real_unlink = os.unlink
    events: list[str] = []

    def recording_fsync(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            events.append("parent-fsync")
        real_fsync(descriptor)

    def recording_unlink(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
    ) -> None:
        events.append("unlink")
        real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(commissioning_module.os, "fsync", recording_fsync)
    monkeypatch.setattr(commissioning_module.os, "unlink", recording_unlink)
    outcome = repository.recover_exact_candidate_initial_temp(candidate=stale_candidate)

    assert outcome is commissioning_module.ReachyA05CommitReconciliation.NOT_COMMITTED
    assert events == ["parent-fsync", "unlink", "parent-fsync"]
    assert not stale_temp.exists()
    assert not (repository.root / "operator-state.json").exists()
    assert "does not publish" in (repository.recover_exact_candidate_initial_temp.__doc__ or "")

    monkeypatch.setattr(commissioning_module.os, "fsync", real_fsync)
    monkeypatch.setattr(commissioning_module.os, "unlink", real_unlink)
    repository.replace_atomic(
        fresh_candidate,
        expected_generation=0,
        matching_remote_state=valid_remote_state(deployment=fresh_deployment),
    )
    assert (
        repository.require_current(expectation=valid_expectation(fresh_candidate))
        == fresh_candidate
    )


@pytest.mark.parametrize("obstruction", ("commitment-mismatch", "foreign", "multiple"))
def test_initial_temp_recovery_preserves_unverified_reserved_evidence(
    tmp_path: Path,
    obstruction: str,
) -> None:
    repository = private_repository(tmp_path)
    candidate = state_for_repository(repository)
    candidate_raw = canonical_bytes(candidate)
    candidate_sha256 = hashlib.sha256(candidate_raw).hexdigest()
    candidate_temp = repository.root / f".operator-state.g1.{candidate_sha256}.tmp"
    candidate_temp.write_bytes(
        b"X" + candidate_raw[1:] if obstruction == "commitment-mismatch" else candidate_raw
    )
    os.chmod(candidate_temp, 0o600)
    foreign_temp = repository.root / ".operator-state.foreign.tmp"
    if obstruction in {"foreign", "multiple"}:
        foreign_temp.write_bytes(b"foreign-evidence")
        os.chmod(foreign_temp, 0o600)
    if obstruction == "foreign":
        candidate_temp.unlink()

    assert (
        repository.recover_exact_candidate_initial_temp(candidate=candidate)
        is commissioning_module.ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
    )
    if obstruction != "foreign":
        assert candidate_temp.exists()
    if obstruction in {"foreign", "multiple"}:
        assert foreign_temp.read_bytes() == b"foreign-evidence"
    assert not (repository.root / "operator-state.json").exists()


def test_initial_temp_recovery_detects_state_creation_before_unlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    candidate = state_for_repository(repository)
    candidate_raw = canonical_bytes(candidate)
    candidate_sha256 = hashlib.sha256(candidate_raw).hexdigest()
    candidate_temp = repository.root / f".operator-state.g1.{candidate_sha256}.tmp"
    candidate_temp.write_bytes(candidate_raw)
    os.chmod(candidate_temp, 0o600)
    real_fsync = os.fsync
    injected = False

    def create_state_after_pre_unlink_fsync(descriptor: int) -> None:
        nonlocal injected
        real_fsync(descriptor)
        if not injected and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            injected = True
            state_path = repository.root / "operator-state.json"
            state_path.write_bytes(candidate_raw)
            os.chmod(state_path, 0o600)

    monkeypatch.setattr(
        commissioning_module.os,
        "fsync",
        create_state_after_pre_unlink_fsync,
    )

    assert (
        repository.recover_exact_candidate_initial_temp(candidate=candidate)
        is commissioning_module.ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
    )
    assert injected is True
    assert candidate_temp.read_bytes() == candidate_raw
    assert (repository.root / "operator-state.json").read_bytes() == candidate_raw


def test_initial_temp_recovery_detects_state_creation_after_unlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    candidate = state_for_repository(repository)
    candidate_raw = canonical_bytes(candidate)
    candidate_sha256 = hashlib.sha256(candidate_raw).hexdigest()
    candidate_temp = repository.root / f".operator-state.g1.{candidate_sha256}.tmp"
    candidate_temp.write_bytes(candidate_raw)
    os.chmod(candidate_temp, 0o600)
    real_unlink = os.unlink
    injected = False

    def create_state_after_unlink(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal injected
        real_unlink(path, dir_fd=dir_fd)
        if not injected and str(path).startswith(".operator-state."):
            injected = True
            state_path = repository.root / "operator-state.json"
            state_path.write_bytes(candidate_raw)
            os.chmod(state_path, 0o600)

    monkeypatch.setattr(commissioning_module.os, "unlink", create_state_after_unlink)

    assert (
        repository.recover_exact_candidate_initial_temp(candidate=candidate)
        is commissioning_module.ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
    )
    assert injected is True
    assert not candidate_temp.exists()
    assert (repository.root / "operator-state.json").read_bytes() == candidate_raw


def test_initial_temp_recovery_retries_after_post_unlink_fsync_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    candidate = state_for_repository(repository)
    candidate_raw = canonical_bytes(candidate)
    candidate_sha256 = hashlib.sha256(candidate_raw).hexdigest()
    candidate_temp = repository.root / f".operator-state.g1.{candidate_sha256}.tmp"
    candidate_temp.write_bytes(candidate_raw)
    os.chmod(candidate_temp, 0o600)
    real_fsync = os.fsync
    parent_fsyncs = 0

    def fail_second_parent_fsync(descriptor: int) -> None:
        nonlocal parent_fsyncs
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            parent_fsyncs += 1
            if parent_fsyncs == 2:
                raise OSError("injected initial-temp recovery parent fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(commissioning_module.os, "fsync", fail_second_parent_fsync)
    assert (
        repository.recover_exact_candidate_initial_temp(candidate=candidate)
        is commissioning_module.ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
    )
    assert not candidate_temp.exists()
    assert not (repository.root / "operator-state.json").exists()

    monkeypatch.setattr(commissioning_module.os, "fsync", real_fsync)
    assert (
        repository.recover_exact_candidate_initial_temp(candidate=candidate)
        is commissioning_module.ReachyA05CommitReconciliation.NOT_COMMITTED
    )


@pytest.mark.parametrize(
    ("generation", "status"),
    (
        (1, ReachyA05StateStatus.STAGED),
        (2, ReachyA05StateStatus.STAGED),
    ),
)
def test_initial_temp_recovery_accepts_only_generation_one_commissioned_candidate(
    tmp_path: Path,
    generation: int,
    status: ReachyA05StateStatus,
) -> None:
    repository = private_repository(tmp_path)
    deployment = valid_deployment(
        state_generation=generation,
        status=status,
        staged_bundle_sha256="b" * 64,
    )
    candidate = state_for_repository(repository, deployment=deployment)

    with pytest.raises(ValueError, match="initial temp recovery"):
        repository.recover_exact_candidate_initial_temp(candidate=candidate)


def test_exact_update_candidate_temp_has_a_nonpublishing_recovery_path(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    initial = publish_initial_state(repository)
    deployment = valid_deployment(
        state_generation=2,
        status=ReachyA05StateStatus.STAGED,
        staged_bundle_sha256="b" * 64,
    )
    candidate = state_for_repository(repository, deployment=deployment)
    candidate_raw = canonical_bytes(candidate)
    candidate_sha256 = hashlib.sha256(candidate_raw).hexdigest()
    candidate_temp = repository.root / f".operator-state.g2.{candidate_sha256}.tmp"
    candidate_temp.write_bytes(candidate_raw)
    os.chmod(candidate_temp, 0o600)
    with candidate_temp.open("rb") as staged:
        os.fsync(staged.fileno())

    outcome = repository.recover_exact_candidate_update_temp(
        candidate=candidate,
        expected_current=valid_expectation(initial),
    )

    assert outcome is commissioning_module.ReachyA05CommitReconciliation.NOT_COMMITTED
    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(initial)
    assert not candidate_temp.exists()
    assert "does not publish" in (repository.recover_exact_candidate_update_temp.__doc__ or "")

    repository.replace_atomic(
        candidate,
        expected_generation=1,
        expected_current=valid_expectation(initial),
        matching_remote_state=valid_remote_state(deployment=deployment),
    )
    assert (repository.root / "operator-state.json").read_bytes() == candidate_raw


@pytest.mark.parametrize(
    "temporary_name",
    (
        f".operator-state.g99.{'f' * 64}.tmp",
        f".operator-state.g1.{'e' * 64}.tmp",
        ".operator-state.collision.tmp",
    ),
)
def test_live_read_fails_closed_on_any_unreconciled_reserved_temp(
    tmp_path: Path,
    temporary_name: str,
) -> None:
    repository = private_repository(tmp_path)
    initial = publish_initial_state(repository)
    temporary = repository.root / temporary_name
    temporary.write_bytes(canonical_bytes(initial))
    os.chmod(temporary, 0o600)

    with pytest.raises(ReachyA05RepositoryError, match="reserved temp"):
        repository.require_current(expectation=valid_expectation(initial))

    assert temporary.read_bytes() == canonical_bytes(initial)


def test_live_update_fails_closed_on_unrelated_valid_reserved_temp(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    initial = publish_initial_state(repository)
    deployment = deployment_for_status(
        generation=2,
        status=ReachyA05StateStatus.STAGED,
    )
    candidate = state_for_repository(repository, deployment=deployment)
    foreign = repository.root / f".operator-state.g99.{'f' * 64}.tmp"
    foreign.write_bytes(canonical_bytes(initial))
    os.chmod(foreign, 0o600)

    with pytest.raises(ReachyA05RepositoryError, match="reserved temp"):
        repository.replace_atomic(
            candidate,
            expected_generation=1,
            expected_current=valid_expectation(initial),
            matching_remote_state=valid_remote_state(deployment=deployment),
        )

    assert foreign.read_bytes() == canonical_bytes(initial)
    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(initial)


def test_post_publication_reserved_temp_is_classified_as_post_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    initial = publish_initial_state(repository)
    deployment = deployment_for_status(
        generation=2,
        status=ReachyA05StateStatus.STAGED,
    )
    candidate = state_for_repository(repository, deployment=deployment)
    foreign = repository.root / ".operator-state.post-publication.tmp"
    real_write = ReachyA05CommissioningRepository._write_atomic

    def write_then_inject(
        self: ReachyA05CommissioningRepository,
        root: object,
        state: object,
        **kwargs: object,
    ) -> tuple[int, int]:
        published = real_write(self, root, state, **kwargs)  # type: ignore[arg-type]
        foreign.write_bytes(canonical_bytes(initial))
        os.chmod(foreign, 0o600)
        return published

    monkeypatch.setattr(
        ReachyA05CommissioningRepository,
        "_write_atomic",
        write_then_inject,
    )

    with pytest.raises(commissioning_module.ReachyA05PostCommitError) as captured:
        repository.replace_atomic(
            candidate,
            expected_generation=1,
            expected_current=valid_expectation(initial),
            matching_remote_state=valid_remote_state(deployment=deployment),
        )

    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(candidate)
    assert foreign.read_bytes() == canonical_bytes(initial)
    assert (
        repository.reconcile_commit_unknown(
            captured.value,
            candidate=candidate,
            expected_current=valid_expectation(initial),
        )
        is commissioning_module.ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
    )


def test_exact_update_temp_collision_requires_explicit_recovery_before_retry(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    initial = publish_initial_state(repository)
    deployment = deployment_for_status(
        generation=2,
        status=ReachyA05StateStatus.STAGED,
    )
    candidate = state_for_repository(repository, deployment=deployment)
    candidate_raw = canonical_bytes(candidate)
    candidate_sha256 = hashlib.sha256(candidate_raw).hexdigest()
    candidate_temp = repository.root / f".operator-state.g2.{candidate_sha256}.tmp"
    candidate_temp.write_bytes(candidate_raw)
    os.chmod(candidate_temp, 0o600)

    with pytest.raises(ReachyA05RepositoryError, match="reserved temp"):
        repository.replace_atomic(
            candidate,
            expected_generation=1,
            expected_current=valid_expectation(initial),
            matching_remote_state=valid_remote_state(deployment=deployment),
        )

    assert (
        repository.recover_exact_candidate_update_temp(
            candidate=candidate,
            expected_current=valid_expectation(initial),
        )
        is commissioning_module.ReachyA05CommitReconciliation.NOT_COMMITTED
    )
    repository.replace_atomic(
        candidate,
        expected_generation=1,
        expected_current=valid_expectation(initial),
        matching_remote_state=valid_remote_state(deployment=deployment),
    )
    assert repository.require_current(expectation=valid_expectation(candidate)) == candidate


def test_exact_update_temp_recovery_retries_after_post_unlink_fsync_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    initial = publish_initial_state(repository)
    deployment = valid_deployment(
        state_generation=2,
        status=ReachyA05StateStatus.STAGED,
        staged_bundle_sha256="b" * 64,
    )
    candidate = state_for_repository(repository, deployment=deployment)
    candidate_raw = canonical_bytes(candidate)
    candidate_sha256 = hashlib.sha256(candidate_raw).hexdigest()
    candidate_temp = repository.root / f".operator-state.g2.{candidate_sha256}.tmp"
    candidate_temp.write_bytes(candidate_raw)
    os.chmod(candidate_temp, 0o600)
    real_fsync = os.fsync
    injected = False

    def fail_post_unlink_parent_fsync(descriptor: int) -> None:
        nonlocal injected
        if not injected and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            injected = True
            raise OSError("injected update-temp recovery parent fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(commissioning_module.os, "fsync", fail_post_unlink_parent_fsync)
    assert (
        repository.recover_exact_candidate_update_temp(
            candidate=candidate,
            expected_current=valid_expectation(initial),
        )
        is commissioning_module.ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
    )
    assert not candidate_temp.exists()

    monkeypatch.setattr(commissioning_module.os, "fsync", real_fsync)
    assert (
        repository.recover_exact_candidate_update_temp(
            candidate=candidate,
            expected_current=valid_expectation(initial),
        )
        is commissioning_module.ReachyA05CommitReconciliation.NOT_COMMITTED
    )
    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(initial)


def test_exact_update_temp_recovery_preserves_foreign_reserved_evidence(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    initial = publish_initial_state(repository)
    deployment = valid_deployment(
        state_generation=2,
        status=ReachyA05StateStatus.STAGED,
        staged_bundle_sha256="b" * 64,
    )
    candidate = state_for_repository(repository, deployment=deployment)
    candidate_raw = canonical_bytes(candidate)
    candidate_sha256 = hashlib.sha256(candidate_raw).hexdigest()
    candidate_temp = repository.root / f".operator-state.g2.{candidate_sha256}.tmp"
    candidate_temp.write_bytes(candidate_raw)
    os.chmod(candidate_temp, 0o600)
    foreign_temp = repository.root / ".operator-state.foreign.tmp"
    foreign_temp.write_bytes(b"foreign-evidence")
    os.chmod(foreign_temp, 0o600)

    assert (
        repository.recover_exact_candidate_update_temp(
            candidate=candidate,
            expected_current=valid_expectation(initial),
        )
        is commissioning_module.ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
    )
    assert candidate_temp.read_bytes() == candidate_raw
    assert foreign_temp.read_bytes() == b"foreign-evidence"


def test_post_commit_unlock_failure_has_separate_committed_classification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    candidate = state_for_repository(repository)
    real_flock = fcntl.flock
    injected = False

    def fail_unlock_after_unlocking(descriptor: int, operation: int) -> None:
        nonlocal injected
        real_flock(descriptor, operation)
        if operation == fcntl.LOCK_UN and not injected:
            injected = True
            raise OSError("injected unlock failure")

    monkeypatch.setattr(commissioning_module.fcntl, "flock", fail_unlock_after_unlocking)

    with pytest.raises(commissioning_module.ReachyA05PostCommitError):
        repository.replace_atomic(
            candidate,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=candidate.deployment),
        )

    assert injected is True
    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(candidate)


def test_post_commit_candidate_close_failure_has_separate_committed_classification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    candidate = state_for_repository(repository)
    real_close = os.close
    injected = False
    nonempty_regular_closes = 0

    def fail_candidate_close_after_closing(descriptor: int) -> None:
        nonlocal injected, nonempty_regular_closes
        metadata = os.fstat(descriptor)
        if stat.S_ISREG(metadata.st_mode) and metadata.st_size > 0:
            nonempty_regular_closes += 1
        real_close(descriptor)
        if nonempty_regular_closes == 5 and not injected:
            injected = True
            raise OSError("injected candidate close failure")

    monkeypatch.setattr(commissioning_module.os, "close", fail_candidate_close_after_closing)

    with pytest.raises(commissioning_module.ReachyA05PostCommitError):
        repository.replace_atomic(
            candidate,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=candidate.deployment),
        )

    assert injected is True
    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(candidate)


def test_repository_documents_detected_race_boundary_without_claiming_same_uid_immunity() -> None:
    documentation = ReachyA05CommissioningRepository.__doc__ or ""

    assert "detected or cooperating races" in documentation
    assert "continuously malicious same-UID mutation" in documentation


def test_atomic_replace_rejects_state_path_inode_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    initial = publish_initial_state(repository)
    replacement = state_for_repository(
        repository, deployment=valid_deployment(capability_report_sha256="d" * 64)
    )
    replacement_path = repository.root / "replacement.json"
    replacement_path.write_bytes(canonical_bytes(replacement))
    os.chmod(replacement_path, 0o600)
    next_deployment = valid_deployment(
        state_generation=2,
        status=ReachyA05StateStatus.STAGED,
        staged_bundle_sha256="b" * 64,
    )
    next_state = state_for_repository(repository, deployment=next_deployment)
    real_fsync = os.fsync
    drift_injected = False

    def fsync_with_drift(descriptor: int) -> None:
        nonlocal drift_injected
        metadata = os.fstat(descriptor)
        if stat.S_ISREG(metadata.st_mode) and metadata.st_size > 0 and not drift_injected:
            drift_injected = True
            os.replace(
                repository.root / "replacement.json",
                repository.root / "operator-state.json",
            )
        real_fsync(descriptor)

    monkeypatch.setattr(commissioning_module.os, "fsync", fsync_with_drift)

    with pytest.raises((PermissionError, ReachyA05RepositoryError)):
        repository.replace_atomic(
            next_state,
            expected_generation=1,
            expected_current=valid_expectation(initial),
            matching_remote_state=valid_remote_state(deployment=next_deployment),
        )

    assert drift_injected is True
    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(replacement)
    assert not list(repository.root.glob(".operator-state.*.tmp"))


def test_atomic_replace_revalidates_prior_content_after_temp_fsync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    initial = publish_initial_state(repository)
    substituted_prior = substituted_security_state(initial, "runtime")
    next_deployment = valid_deployment(
        state_generation=2,
        status=ReachyA05StateStatus.STAGED,
        staged_bundle_sha256="b" * 64,
    )
    candidate = state_for_repository(repository, deployment=next_deployment)
    real_fsync = os.fsync
    drift_injected = False

    def fsync_with_in_place_drift(descriptor: int) -> None:
        nonlocal drift_injected
        metadata = os.fstat(descriptor)
        if stat.S_ISREG(metadata.st_mode) and metadata.st_size > 0 and not drift_injected:
            drift_injected = True
            state_path = repository.root / "operator-state.json"
            state_path.write_bytes(canonical_bytes(substituted_prior))
            os.chmod(state_path, 0o600)
        real_fsync(descriptor)

    monkeypatch.setattr(commissioning_module.os, "fsync", fsync_with_in_place_drift)

    with pytest.raises(ReachyA05RepositoryError, match="commitment mismatch"):
        repository.replace_atomic(
            candidate,
            expected_generation=1,
            expected_current=valid_expectation(initial),
            matching_remote_state=valid_remote_state(deployment=next_deployment),
        )

    assert drift_injected is True
    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(
        substituted_prior
    )
    assert not list(repository.root.glob(".operator-state.*.tmp"))


def test_atomic_replace_rejects_valid_content_from_post_validation_inode_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    state = state_for_repository(repository)
    attacker_name = "attacker-state.json"
    attacker_path = repository.root / attacker_name
    attacker_path.write_bytes(canonical_bytes(state))
    os.chmod(attacker_path, 0o600)
    real_noreplace = commissioning_module._rename_noreplace
    drift_injected = False

    def noreplace_with_temp_inode_swap(
        directory_descriptor: int,
        source: str,
        destination: str,
    ) -> None:
        nonlocal drift_injected
        if not drift_injected:
            drift_injected = True
            os.replace(
                attacker_name,
                source,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
        real_noreplace(directory_descriptor, source, destination)

    monkeypatch.setattr(
        commissioning_module,
        "_rename_noreplace",
        noreplace_with_temp_inode_swap,
    )

    with pytest.raises((PermissionError, ReachyA05RepositoryError)):
        repository.replace_atomic(
            state,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=state.deployment),
        )

    assert drift_injected is True
    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(state)
    assert not list(repository.root.glob(".operator-state.*.tmp"))


def test_state_read_rejects_named_inode_replacement_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_initial_state(repository)
    state_path = repository.root / "operator-state.json"
    original_metadata = state_path.stat()
    replacement = state_for_repository(
        repository,
        deployment=valid_deployment(capability_report_sha256="d" * 64),
    )
    replacement_path = repository.root / "replacement.json"
    replacement_path.write_bytes(canonical_bytes(replacement))
    os.chmod(replacement_path, 0o600)
    real_read = os.read
    drift_injected = False

    def read_with_drift(descriptor: int, count: int) -> bytes:
        nonlocal drift_injected
        chunk = real_read(descriptor, count)
        metadata = os.fstat(descriptor)
        if (
            chunk
            and not drift_injected
            and (metadata.st_dev, metadata.st_ino)
            == (original_metadata.st_dev, original_metadata.st_ino)
        ):
            drift_injected = True
            os.replace(replacement_path, state_path)
        return chunk

    monkeypatch.setattr(commissioning_module.os, "read", read_with_drift)

    with pytest.raises(PermissionError, match="commissioning state file"):
        repository.require_current(
            expectation=valid_expectation(state),
        )

    assert drift_injected is True
    assert state_path.read_bytes() == canonical_bytes(replacement)


def test_atomic_replace_failure_preserves_current_state_and_removes_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    initial = publish_initial_state(repository)
    next_deployment = valid_deployment(
        state_generation=2,
        status=ReachyA05StateStatus.STAGED,
        staged_bundle_sha256="b" * 64,
    )
    candidate = state_for_repository(repository, deployment=next_deployment)

    def failing_exchange(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise OSError("injected publication failure")

    monkeypatch.setattr(commissioning_module, "_rename_exchange", failing_exchange)

    with pytest.raises(OSError, match="injected publication failure"):
        repository.replace_atomic(
            candidate,
            expected_generation=1,
            expected_current=valid_expectation(initial),
            matching_remote_state=valid_remote_state(deployment=next_deployment),
        )

    assert (repository.root / "operator-state.json").read_bytes() == canonical_bytes(initial)
    assert not list(repository.root.glob(".operator-state.*.tmp"))


def test_prepublication_parent_fsync_failure_never_mutates_state_namespace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    state = state_for_repository(repository)
    real_fsync = os.fsync
    real_noreplace = commissioning_module._rename_noreplace
    rename_called = False

    def fail_first_parent_fsync(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("injected prepublication parent fsync failure")
        real_fsync(descriptor)

    def record_noreplace(
        directory_descriptor: int,
        source: str,
        destination: str,
    ) -> None:
        nonlocal rename_called
        rename_called = True
        real_noreplace(directory_descriptor, source, destination)

    monkeypatch.setattr(commissioning_module.os, "fsync", fail_first_parent_fsync)
    monkeypatch.setattr(commissioning_module, "_rename_noreplace", record_noreplace)

    with pytest.raises(OSError, match="prepublication parent fsync"):
        repository.replace_atomic(
            state,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=state.deployment),
        )

    assert rename_called is False
    assert not (repository.root / "operator-state.json").exists()
    assert not list(repository.root.glob(".operator-state.*.tmp"))


def test_candidate_corruption_immediately_after_file_fsync_is_never_published(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    state = state_for_repository(repository)
    real_fsync = os.fsync
    injected = False

    def corrupt_after_file_fsync(descriptor: int) -> None:
        nonlocal injected
        real_fsync(descriptor)
        metadata = os.fstat(descriptor)
        if not injected and stat.S_ISREG(metadata.st_mode) and metadata.st_size > 0:
            injected = True
            os.pwrite(descriptor, b"X", 0)

    monkeypatch.setattr(commissioning_module.os, "fsync", corrupt_after_file_fsync)

    with pytest.raises(ReachyA05RepositoryError) as captured:
        repository.replace_atomic(
            state,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=state.deployment),
        )

    assert type(captured.value) is ReachyA05RepositoryError
    assert injected is True
    assert not (repository.root / "operator-state.json").exists()
    assert not list(repository.root.glob(".operator-state.*.tmp"))


def test_candidate_corruption_after_validation_is_rechecked_before_rename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    state = state_for_repository(repository)
    candidate_raw = canonical_bytes(state)
    candidate_sha256 = hashlib.sha256(candidate_raw).hexdigest()
    candidate_temp = repository.root / f".operator-state.g1.{candidate_sha256}.tmp"
    real_require_bound_artifacts = ReachyA05CommissioningRepository._require_bound_artifacts
    artifact_checks = 0

    def validate_then_corrupt(
        self: ReachyA05CommissioningRepository,
        root: object,
        candidate: ReachyA05CommissioningStateV1,
    ) -> None:
        nonlocal artifact_checks
        real_require_bound_artifacts(self, root, candidate)  # type: ignore[arg-type]
        artifact_checks += 1
        if artifact_checks == 2:
            with candidate_temp.open("r+b", buffering=0) as staged:
                staged.write(b"X")

    monkeypatch.setattr(
        ReachyA05CommissioningRepository,
        "_require_bound_artifacts",
        validate_then_corrupt,
    )

    with pytest.raises(ReachyA05RepositoryError) as captured:
        repository.replace_atomic(
            state,
            expected_generation=0,
            matching_remote_state=valid_remote_state(deployment=state.deployment),
        )

    assert type(captured.value) is ReachyA05RepositoryError
    assert artifact_checks == 2
    assert not (repository.root / "operator-state.json").exists()
    assert not list(repository.root.glob(".operator-state.*.tmp"))


def test_atomic_replace_fsyncs_file_before_rename_and_parent_after(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    state = state_for_repository(repository)
    real_fsync = os.fsync
    real_noreplace = commissioning_module._rename_noreplace
    events: list[str] = []

    def recording_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if stat.S_ISDIR(metadata.st_mode):
            events.append("parent-fsync")
        elif metadata.st_size > 0:
            events.append("file-fsync")
        real_fsync(descriptor)

    def recording_noreplace(
        directory_descriptor: int,
        source: str,
        destination: str,
    ) -> None:
        events.append("noreplace")
        real_noreplace(directory_descriptor, source, destination)

    monkeypatch.setattr(commissioning_module.os, "fsync", recording_fsync)
    monkeypatch.setattr(commissioning_module, "_rename_noreplace", recording_noreplace)

    repository.replace_atomic(
        state,
        expected_generation=0,
        matching_remote_state=valid_remote_state(deployment=state.deployment),
    )

    assert events == ["file-fsync", "parent-fsync", "noreplace", "parent-fsync"]
