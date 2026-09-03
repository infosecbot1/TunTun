from __future__ import annotations

import base64
import hashlib
import os
import struct
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from tuntun_contracts.base import canonical_bytes
from tuntun_contracts.poc.framing import PttInputMode
from tuntun_core.adapters.reachy.commissioning import (
    ReachyA05CommissioningRepository,
    ReachyA05CommissioningStateV1,
    ReachyA05DeploymentBinding,
    ReachyA05RemoteStateV1,
    ReachyA05RuntimeBinding,
    ReachyA05StateExpectation,
    ReachyA05StateStatus,
)

COMMISSIONING_ID = UUID("12345678-1234-4678-9234-567812345678")


def ssh_string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def openssh_ed25519_identity(private_seed: bytes) -> tuple[bytes, bytes]:
    public_key = (
        Ed25519PrivateKey.from_private_bytes(private_seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
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
    return header + wrapped + footer, public_blob


IDENTITY_ARTIFACT, IDENTITY_PUBLIC_KEY_BLOB = openssh_ed25519_identity(b"I" * 32)
PINNED_HOST_KEY_BLOB = ssh_string(b"ssh-ed25519") + ssh_string(b"H" * 32)


def known_hosts_artifact(ipv4: str, public_blob: bytes = PINNED_HOST_KEY_BLOB) -> bytes:
    return ipv4.encode("ascii") + b" ssh-ed25519 " + base64.b64encode(public_blob) + b"\n"


KNOWN_HOSTS_ARTIFACT = known_hosts_artifact("192.168.50.22")


def digest(value: str | bytes) -> str:
    raw = value if isinstance(value, bytes) else value.encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def fixed_repository_time() -> datetime:
    return datetime(2026, 8, 31, 9, 0, tzinfo=UTC)


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
        "commissioning_id": COMMISSIONING_ID,
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


def deployment_for_status(
    *,
    generation: int,
    status: ReachyA05StateStatus,
    issued_at: datetime | None = None,
    ptt_input_mode: PttInputMode = PttInputMode.REACHY_LOCAL,
) -> ReachyA05DeploymentBinding:
    issued_at = issued_at or datetime(2026, 8, 31, 8, 0, tzinfo=UTC)
    return valid_deployment(
        state_generation=generation,
        status=status,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(hours=24),
        ptt_input_mode=ptt_input_mode,
        staged_bundle_sha256="b" * 64 if status is ReachyA05StateStatus.STAGED else None,
        active_bundle_sha256="b" * 64 if status is ReachyA05StateStatus.ACTIVE else None,
    )


def valid_commissioning_state(**updates: object) -> ReachyA05CommissioningStateV1:
    values: dict[str, object] = {
        "schema_version": "tuntun.reachy-a05-operator-state.v1",
        "record_kind": "bound",
        "deployment": valid_deployment(),
        "reachy_ipv4": IPv4Address("192.168.50.22"),
        "ssh_port": 22,
        "identity_path": "/Users/owner/.local/share/tuntun/reachy-a05/identity",
        "known_hosts_path": "/Users/owner/.local/share/tuntun/reachy-a05/known_hosts",
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


def valid_expectation(state: ReachyA05CommissioningStateV1) -> ReachyA05StateExpectation:
    deployment = state.deployment
    return ReachyA05StateExpectation.model_validate(
        {
            "commissioning_id": deployment.commissioning_id,
            "state_generation": deployment.state_generation,
            "boot_identity_sha256": deployment.boot_identity_sha256,
            "capability_report_sha256": deployment.capability_report_sha256,
            "runtime_inventory_sha256": deployment.runtime.runtime_inventory_sha256,
            "dispatcher_sha256": deployment.dispatcher_sha256,
            "authorized_key_line_sha256": deployment.authorized_key_line_sha256,
            "state_sha256": hashlib.sha256(canonical_bytes(state)).hexdigest(),
        }
    )


def write_private_artifacts(root: Path) -> None:
    for name, content in (
        ("identity", IDENTITY_ARTIFACT),
        ("known_hosts", KNOWN_HOSTS_ARTIFACT),
    ):
        path = root / name
        path.write_bytes(content)
        os.chmod(path, 0o600)


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
