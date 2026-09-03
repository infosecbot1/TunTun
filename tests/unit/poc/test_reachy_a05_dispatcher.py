from __future__ import annotations

import contextlib
import fcntl
import hashlib
import io
import json
import os
import pwd
import stat
import sys
import threading
import time
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from struct import Struct
from types import SimpleNamespace
from typing import Any
from uuid import UUID

import pytest
from tuntun_contracts.base import canonical_bytes
from tuntun_contracts.poc.framing import PttInputMode
from tuntun_core.adapters.reachy.commissioning import (  # type: ignore[import-untyped]
    ReachyA05DeploymentBinding,
    ReachyA05RemoteStateV1,
    ReachyA05RuntimeBinding,
    ReachyA05StateStatus,
)

import scripts.reachy_a05_forced_dispatcher as dispatcher

PREFIX = Struct(">I")
COMMISSIONING_ID = UUID("60000000-0000-4000-8000-000000000001")
OPERATION_ID = UUID("61000000-0000-4000-8000-000000000001")
TURN_ID = UUID("62000000-0000-4000-8000-000000000001")


def _digest(raw: bytes | str) -> str:
    payload = raw if isinstance(raw, bytes) else raw.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _frame(value: Mapping[str, object]) -> bytes:
    body = _canonical(value)
    return PREFIX.pack(len(body)) + body


def _decode_frame(raw: bytes) -> dict[str, object]:
    assert len(raw) >= PREFIX.size
    declared_length = PREFIX.unpack(raw[: PREFIX.size])[0]
    body = raw[PREFIX.size :]
    assert declared_length == len(body)
    assert 1 <= declared_length <= 4096
    decoded = json.loads(body)
    assert isinstance(decoded, dict)
    assert _canonical(decoded) == body
    return decoded


def _runtime() -> ReachyA05RuntimeBinding:
    return ReachyA05RuntimeBinding.model_validate(
        {
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
    )


def _deployment(
    root: Path,
    *,
    state_generation: int = 1,
    status: ReachyA05StateStatus = ReachyA05StateStatus.COMMISSIONED,
    staged_bundle_sha256: str | None = None,
    active_bundle_sha256: str | None = None,
) -> ReachyA05DeploymentBinding:
    issued_at = datetime.now(UTC).replace(microsecond=0)
    remote_home = root.parents[3]
    return ReachyA05DeploymentBinding.model_validate(
        {
            "commissioning_id": COMMISSIONING_ID,
            "state_generation": state_generation,
            "status": status,
            "issued_at": issued_at,
            "expires_at": issued_at + timedelta(hours=24),
            "boot_identity_sha256": "5" * 64,
            "capability_report_sha256": "6" * 64,
            "ptt_input_mode": PttInputMode.REACHY_LOCAL,
            "runtime": _runtime(),
            "ssh_principal": "owner",
            "remote_home": str(remote_home),
            "remote_root": str(root),
            "dispatcher_path": str(root / "bootstrap" / "reachy_a05_forced_dispatcher.py"),
            "dispatcher_protocol_version": "tuntun.reachy-a05-dispatcher.v1",
            "dispatcher_sha256": dispatcher.current_dispatcher_sha256(),
            "authorized_key_line_sha256": "8" * 64,
            "staged_bundle_sha256": staged_bundle_sha256,
            "active_bundle_sha256": active_bundle_sha256,
        }
    )


def _remote_state(
    root: Path,
    *,
    state_generation: int = 1,
    status: ReachyA05StateStatus = ReachyA05StateStatus.COMMISSIONED,
    staged_bundle_sha256: str | None = None,
    active_bundle_sha256: str | None = None,
) -> ReachyA05RemoteStateV1:
    return ReachyA05RemoteStateV1(
        schema_version="tuntun.reachy-a05-remote-state.v1",
        deployment=_deployment(
            root,
            state_generation=state_generation,
            status=status,
            staged_bundle_sha256=staged_bundle_sha256,
            active_bundle_sha256=active_bundle_sha256,
        ),
    )


def _owner_write(path: Path, raw: bytes, *, mode: int = 0o600) -> None:
    path.write_bytes(raw)
    path.chmod(mode)


def _fresh_root(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    root = home / ".local" / "share" / "tuntun" / "reachy-a05"
    root.mkdir(parents=True)
    root.chmod(0o700)
    _owner_write(root / "remote-state.json", canonical_bytes(_remote_state(root)))
    _owner_write(root / ".remote-state.lock", b"")
    return root


def _request(
    verb: str,
    *,
    expected_generation: int,
    payload: Mapping[str, object] | None = None,
    commissioning_id: UUID = COMMISSIONING_ID,
    operation_id: UUID = OPERATION_ID,
) -> dict[str, object]:
    return {
        "version": 1,
        "operation_id": str(operation_id),
        "verb": verb,
        "commissioning_id": str(commissioning_id),
        "expected_state_generation": expected_generation,
        "payload": {} if payload is None else dict(payload),
    }


def _artifact(
    path: str,
    raw: bytes,
    *,
    executable: bool = False,
) -> tuple[dict[str, object], bytes]:
    return (
        {
            "path": path,
            "size": len(raw),
            "sha256": _digest(raw),
            "executable": executable,
        },
        raw,
    )


def _bundle_payload(
    *,
    entrypoint: tuple[str, ...] = ("bin/python", "-m", "tuntun_edge.cli.ptt"),
    extra_artifacts: list[tuple[dict[str, object], bytes]] | None = None,
) -> tuple[dict[str, object], str, bytes]:
    runtime_artifacts = [
        _artifact("bin/python", b"#!/usr/bin/env python3\n", executable=True),
        _artifact("tuntun_edge/__init__.py", b""),
        _artifact("tuntun_edge/cli/__init__.py", b""),
        _artifact("tuntun_edge/cli/ptt.py", b"def main():\n    return None\n"),
    ]
    if extra_artifacts is not None:
        runtime_artifacts.extend(extra_artifacts)
    runtime_records = [record for record, _raw in runtime_artifacts]
    manifest = {
        "schema_version": "tuntun.reachy-a05-bundle-manifest.v1",
        "entrypoint": list(entrypoint),
        "artifacts": runtime_records,
    }
    manifest_raw = _canonical(manifest)
    manifest_artifact = _artifact("manifest.json", manifest_raw)
    artifacts = [manifest_artifact, *runtime_artifacts]
    records = [record for record, _raw in artifacts]
    bundle_descriptor = {
        "schema_version": "tuntun.reachy-a05-bundle.v1",
        "manifest_sha256": _digest(manifest_raw),
        "artifacts": records,
    }
    bundle_sha256 = _digest(_canonical(bundle_descriptor))
    return (
        {"bundle_sha256": bundle_sha256, "artifacts": records},
        bundle_sha256,
        b"".join(raw for _record, raw in artifacts),
    )


def _send(
    root: Path,
    request: Mapping[str, object],
    *,
    artifact_bytes: bytes = b"",
    environ: Mapping[str, str] | None = None,
    exec_handoff: dispatcher.ExecHandoff | None = None,
) -> dict[str, object]:
    raw = dispatcher.dispatch_frame(
        _frame(request) + artifact_bytes,
        remote_root=root,
        environ={} if environ is None else environ,
        exec_handoff=exec_handoff,
    )
    return _decode_frame(raw)


def _read_state(root: Path) -> dict[str, Any]:
    raw = (root / "remote-state.json").read_bytes()
    decoded = json.loads(raw)
    assert isinstance(decoded, dict)
    assert canonical_bytes(ReachyA05RemoteStateV1.model_validate_json(raw)) == raw
    return decoded


def test_status_ignores_stale_generation_but_authenticates_and_returns_commitments(
    tmp_path: Path,
) -> None:
    root = _fresh_root(tmp_path)

    response = _send(root, _request("status", expected_generation=999))

    assert response == {
        "version": 1,
        "operation_id": str(OPERATION_ID),
        "ok": True,
        "state_generation": 1,
        "status": "commissioned",
        "payload": {
            "active_bundle_sha256": None,
            "authorized_key_line_sha256": "8" * 64,
            "boot_identity_sha256": "5" * 64,
            "capability_report_sha256": "6" * 64,
            "dispatcher_protocol_version": "tuntun.reachy-a05-dispatcher.v1",
            "dispatcher_sha256": dispatcher.current_dispatcher_sha256(),
            "runtime_inventory_sha256": "4" * 64,
            "staged_bundle_sha256": None,
        },
    }

    with pytest.raises(dispatcher.DispatcherRejected):
        _send(
            root,
            _request(
                "status",
                expected_generation=1,
                commissioning_id=UUID("60000000-0000-4000-8000-000000000002"),
            ),
        )

    with pytest.raises(dispatcher.DispatcherRejected):
        _send(root, _request("status", expected_generation=1, payload={"extra": True}))


def test_dispatch_protocol_rejects_shell_and_noncanonical_or_ambiguous_frames(
    tmp_path: Path,
) -> None:
    root = _fresh_root(tmp_path)
    status = _request("status", expected_generation=1)

    with pytest.raises(dispatcher.DispatcherRejected):
        dispatcher.dispatch_frame(
            _frame(status),
            remote_root=root,
            environ={"SSH_ORIGINAL_COMMAND": "id"},
        )

    with pytest.raises(dispatcher.DispatcherRejected):
        dispatcher.dispatch_frame(_frame(status) + b"x", remote_root=root, environ={})

    with pytest.raises(dispatcher.DispatcherRejected):
        dispatcher.dispatch_frame(PREFIX.pack(65_537), remote_root=root, environ={})

    noncanonical = (
        b'{"version":1,"operation_id":"61000000-0000-4000-8000-000000000001",'
        b'"verb":"status","commissioning_id":"60000000-0000-4000-8000-000000000001",'
        b'"expected_state_generation":1,"payload":{}}'
    )
    with pytest.raises(dispatcher.DispatcherRejected):
        dispatcher.dispatch_frame(PREFIX.pack(len(noncanonical)) + noncanonical, remote_root=root)

    duplicate = (
        b'{"commissioning_id":"60000000-0000-4000-8000-000000000001",'
        b'"expected_state_generation":1,'
        b'"operation_id":"61000000-0000-4000-8000-000000000001",'
        b'"payload":{},"verb":"status","verb":"stage","version":1}'
    )
    with pytest.raises(dispatcher.DispatcherRejected):
        dispatcher.dispatch_frame(PREFIX.pack(len(duplicate)) + duplicate, remote_root=root)

    with pytest.raises(dispatcher.DispatcherRejected):
        _send(root, {**status, "unexpected": True})

    with pytest.raises(dispatcher.DispatcherRejected):
        _send(root, _request("shell", expected_generation=1))


def test_stage_activate_and_remove_are_content_addressed_atomic_and_cas_idempotent(
    tmp_path: Path,
) -> None:
    root = _fresh_root(tmp_path)
    stage_payload, bundle_sha256, artifact_bytes = _bundle_payload()

    staged = _send(
        root,
        _request("stage", expected_generation=1, payload=stage_payload),
        artifact_bytes=artifact_bytes,
    )

    assert staged["ok"] is True
    assert staged["state_generation"] == 2
    assert staged["status"] == "staged"
    assert staged["payload"] == {
        "active_bundle_sha256": None,
        "staged_bundle_sha256": bundle_sha256,
    }
    generation = root / "generations" / bundle_sha256
    assert generation.is_dir()
    assert (generation / "manifest.json").read_bytes()
    assert stat.S_IMODE((generation / "bin" / "python").stat().st_mode) == 0o700
    assert not (root / ".staging").exists()
    assert _read_state(root)["deployment"]["staged_bundle_sha256"] == bundle_sha256

    restaged = _send(
        root,
        _request("stage", expected_generation=1, payload=stage_payload),
        artifact_bytes=artifact_bytes,
    )
    assert restaged["state_generation"] == 2
    assert _read_state(root)["deployment"]["state_generation"] == 2

    activated = _send(
        root,
        _request("activate", expected_generation=2, payload={"bundle_sha256": bundle_sha256}),
    )
    assert activated["state_generation"] == 3
    assert activated["status"] == "active"
    assert activated["payload"] == {
        "active_bundle_sha256": bundle_sha256,
        "staged_bundle_sha256": None,
    }

    removed = _send(
        root,
        _request("remove", expected_generation=3, payload={"bundle_sha256": bundle_sha256}),
    )
    assert removed["state_generation"] == 4
    assert removed["status"] == "removed"
    assert removed["payload"] == {
        "active_bundle_sha256": None,
        "staged_bundle_sha256": None,
        "verified_absent": bundle_sha256,
    }
    assert not generation.exists()

    reremoved = _send(
        root,
        _request("remove", expected_generation=3, payload={"bundle_sha256": bundle_sha256}),
    )
    assert reremoved["state_generation"] == 4
    assert _read_state(root)["deployment"]["state_generation"] == 4


def test_stage_rejects_hostile_paths_symlink_staging_package_index_and_huge_sizes(
    tmp_path: Path,
) -> None:
    root = _fresh_root(tmp_path)
    hostile_payload, _hostile_bundle, hostile_bytes = _bundle_payload(
        extra_artifacts=[_artifact("../escape", b"not yours")]
    )

    with pytest.raises(dispatcher.DispatcherRejected):
        _send(
            root,
            _request("stage", expected_generation=1, payload=hostile_payload),
            artifact_bytes=hostile_bytes,
        )
    assert not (tmp_path / "escape").exists()

    symlink_target = tmp_path / "outside-staging"
    symlink_target.mkdir()
    (root / ".staging").symlink_to(symlink_target, target_is_directory=True)
    safe_payload, _safe_bundle, safe_bytes = _bundle_payload()
    with pytest.raises(dispatcher.DispatcherRejected):
        _send(
            root,
            _request("stage", expected_generation=1, payload=safe_payload),
            artifact_bytes=safe_bytes,
        )
    assert not any(symlink_target.iterdir())
    os.unlink(root / ".staging")

    pip_payload, _pip_bundle, pip_bytes = _bundle_payload(entrypoint=("bin/python", "-m", "pip"))
    with pytest.raises(dispatcher.DispatcherRejected):
        _send(
            root,
            _request("stage", expected_generation=1, payload=pip_payload),
            artifact_bytes=pip_bytes,
        )

    huge_artifact = {
        "path": "huge.bin",
        "size": 2**63,
        "sha256": _digest(b""),
        "executable": False,
    }
    with pytest.raises(dispatcher.DispatcherRejected):
        _send(
            root,
            _request(
                "stage",
                expected_generation=1,
                payload={"bundle_sha256": "a" * 64, "artifacts": [huge_artifact]},
            ),
        )
    assert not (root / "generations" / ("a" * 64)).exists()


def test_state_validation_rejects_permissive_or_symlinked_owned_files(tmp_path: Path) -> None:
    root = _fresh_root(tmp_path)
    root.chmod(0o755)
    with pytest.raises(dispatcher.DispatcherRejected):
        _send(root, _request("status", expected_generation=1))

    root.chmod(0o700)
    (root / "remote-state.json").chmod(0o640)
    with pytest.raises(dispatcher.DispatcherRejected):
        _send(root, _request("status", expected_generation=1))

    _owner_write(root / "remote-state.json", canonical_bytes(_remote_state(root)))
    outside = tmp_path / "replacement-state.json"
    _owner_write(
        outside,
        canonical_bytes(
            _remote_state(
                root,
                state_generation=99,
                status=ReachyA05StateStatus.REMOVED,
            )
        ),
    )
    (root / "remote-state.json").unlink()
    (root / "remote-state.json").symlink_to(outside)
    with pytest.raises(dispatcher.DispatcherRejected):
        _send(root, _request("status", expected_generation=1))


@pytest.mark.parametrize(
    ("field_path", "invalid_value"),
    [
        (("deployment", "ssh_principal"), "Owner"),
        (("deployment", "runtime", "python_executable"), "/venvs/with space/python"),
        (("deployment", "runtime", "sdk_version"), "xn--private-label"),
        (("deployment", "runtime", "python_abi"), "cp311"),
    ],
)
def test_state_validation_exactly_mirrors_canonical_commissioning_constraints(
    tmp_path: Path,
    field_path: tuple[str, ...],
    invalid_value: str,
) -> None:
    root = _fresh_root(tmp_path)
    state = json.loads(canonical_bytes(_remote_state(root)))
    target = state
    for component in field_path[:-1]:
        target = target[component]
    target[field_path[-1]] = invalid_value
    _owner_write(root / "remote-state.json", _canonical(state))

    with pytest.raises(dispatcher.DispatcherRejected):
        _send(root, _request("status", expected_generation=1))


def test_state_validation_rejects_future_issued_authority(tmp_path: Path) -> None:
    root = _fresh_root(tmp_path)
    state = json.loads(canonical_bytes(_remote_state(root)))
    issued_at = datetime.now(UTC) + timedelta(hours=1)
    state["deployment"]["issued_at"] = issued_at.isoformat().replace("+00:00", "Z")
    state["deployment"]["expires_at"] = (
        (issued_at + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    )
    _owner_write(root / "remote-state.json", _canonical(state))

    with pytest.raises(dispatcher.DispatcherRejected):
        _send(root, _request("status", expected_generation=1))


@pytest.mark.parametrize("mutation", ["noncanonical-time", "revoked-remote-status"])
def test_state_validation_rejects_noncanonical_remote_authority(
    tmp_path: Path,
    mutation: str,
) -> None:
    root = _fresh_root(tmp_path)
    state = json.loads(canonical_bytes(_remote_state(root)))
    if mutation == "noncanonical-time":
        state["deployment"]["issued_at"] = state["deployment"]["issued_at"].replace(
            ".000000Z", "+00:00"
        )
    else:
        state["deployment"]["status"] = "revoked"
    _owner_write(root / "remote-state.json", _canonical(state))

    with pytest.raises(dispatcher.DispatcherRejected):
        _send(root, _request("status", expected_generation=1))


def test_real_dispatcher_binds_nonroot_effective_account_to_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fresh_root(tmp_path)
    deployment = json.loads(canonical_bytes(_remote_state(root)))["deployment"]
    home = str(root.parents[3])

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        pwd,
        "getpwuid",
        lambda _uid: SimpleNamespace(pw_name="owner", pw_dir=home),
    )
    with pytest.raises(dispatcher.DispatcherRejected):
        dispatcher._require_process_identity(deployment, root)

    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(
        pwd,
        "getpwuid",
        lambda _uid: SimpleNamespace(pw_name="different", pw_dir=home),
    )
    with pytest.raises(dispatcher.DispatcherRejected):
        dispatcher._require_process_identity(deployment, root)

    monkeypatch.setattr(
        pwd,
        "getpwuid",
        lambda _uid: SimpleNamespace(pw_name="owner", pw_dir=home),
    )
    dispatcher._require_process_identity(deployment, root)


@pytest.mark.parametrize(
    "hostile_path",
    [
        "nested/name\nwith-break",
        "nested/naïve.py",
        "nested/\u202ename.py",
        "/absolute.py",
        "a/../../escape.py",
        "/".join(["deep"] * 17 + ["payload.py"]),
    ],
)
def test_stage_rejects_nonportable_or_deep_artifact_paths(
    tmp_path: Path,
    hostile_path: str,
) -> None:
    root = _fresh_root(tmp_path)
    payload, _bundle, artifact_bytes = _bundle_payload(
        extra_artifacts=[_artifact(hostile_path, b"hostile")]
    )

    with contextlib.suppress(dispatcher.DispatcherRejected):
        _send(
            root,
            _request("stage", expected_generation=1, payload=payload),
            artifact_bytes=artifact_bytes,
        )


def test_stage_recovers_same_operation_partial_staging_residue(tmp_path: Path) -> None:
    root = _fresh_root(tmp_path)
    payload, bundle_sha256, artifact_bytes = _bundle_payload()
    staging = root / ".staging"
    staging.mkdir(mode=0o700)
    partial = staging / f"{OPERATION_ID}.{bundle_sha256}"
    partial.mkdir(mode=0o700)
    _owner_write(partial / "partial", b"interrupted")

    response = _send(
        root,
        _request("stage", expected_generation=1, payload=payload),
        artifact_bytes=artifact_bytes,
    )

    assert response["state_generation"] == 2
    assert response["status"] == "staged"
    assert not partial.exists()
    assert (root / "generations" / bundle_sha256).is_dir()


def test_stage_ancestor_replacement_cannot_write_outside_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fresh_root(tmp_path)
    outside = tmp_path / "outside-stage"
    outside.mkdir(mode=0o700)
    payload, _bundle, artifact_bytes = _bundle_payload(
        extra_artifacts=[_artifact("escape-parent/payload", b"must-stay-contained")]
    )
    original = dispatcher._ensure_owner_directory_path
    swapped = False

    def replace_after_check(path: Path) -> None:
        nonlocal swapped
        original(path)
        if path.name == "escape-parent" and not swapped:
            path.rmdir()
            path.symlink_to(outside, target_is_directory=True)
            swapped = True

    monkeypatch.setattr(dispatcher, "_ensure_owner_directory_path", replace_after_check)
    with contextlib.suppress(dispatcher.DispatcherRejected):
        _send(
            root,
            _request("stage", expected_generation=1, payload=payload),
            artifact_bytes=artifact_bytes,
        )

    assert not (outside / "payload").exists()


def test_stage_staging_parent_replacement_cannot_create_outside_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fresh_root(tmp_path)
    outside = tmp_path / "outside-staging-parent"
    outside.mkdir(mode=0o700)
    moved = root / ".staging-moved"
    payload, _bundle, artifact_bytes = _bundle_payload()
    original = dispatcher._ensure_owner_directory_path
    swapped = False

    def replace_staging_after_check(path: Path) -> None:
        nonlocal swapped
        original(path)
        if path.name == ".staging" and not swapped:
            path.rename(moved)
            path.symlink_to(outside, target_is_directory=True)
            swapped = True

    monkeypatch.setattr(dispatcher, "_ensure_owner_directory_path", replace_staging_after_check)
    with pytest.raises(dispatcher.DispatcherRejected):
        _send(
            root,
            _request("stage", expected_generation=1, payload=payload),
            artifact_bytes=artifact_bytes,
        )

    assert not any(outside.iterdir())


def test_stage_generation_parent_replacement_cannot_promote_outside_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fresh_root(tmp_path)
    outside = tmp_path / "outside-generations-parent"
    outside.mkdir(mode=0o700)
    moved = root / "generations-moved"
    generations = root / "generations"
    payload, _bundle, artifact_bytes = _bundle_payload()
    original_rename = os.rename
    swapped = False

    def replace_generations_before_rename(
        source: Any,
        destination: Any,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        nonlocal swapped
        if Path(destination).parent == generations and not swapped:
            original_rename(generations, moved)
            generations.symlink_to(outside, target_is_directory=True)
            swapped = True
        original_rename(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr(os, "rename", replace_generations_before_rename)
    with contextlib.suppress(dispatcher.DispatcherRejected):
        _send(
            root,
            _request("stage", expected_generation=1, payload=payload),
            artifact_bytes=artifact_bytes,
        )

    assert not any(outside.iterdir())


def test_remove_directory_replacement_cannot_delete_outside_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    victim = tmp_path / "victim"
    victim.mkdir(mode=0o700)
    _owner_write(victim / "owned", b"inside")
    moved = tmp_path / "moved-victim"
    outside = tmp_path / "outside-remove"
    outside.mkdir(mode=0o700)
    sentinel = outside / "must-survive"
    _owner_write(sentinel, b"outside")
    original = Path.iterdir
    swapped = False

    def replace_before_walk(path: Path):  # type: ignore[no-untyped-def]
        nonlocal swapped
        if path == victim and not swapped:
            path.rename(moved)
            path.symlink_to(outside, target_is_directory=True)
            swapped = True
        return original(path)

    monkeypatch.setattr(Path, "iterdir", replace_before_walk)
    with contextlib.suppress(dispatcher.DispatcherRejected, OSError):
        dispatcher._safe_remove_tree(victim)

    assert sentinel.read_bytes() == b"outside"


def test_active_bundle_rejects_unmanifested_empty_directories(tmp_path: Path) -> None:
    root = _fresh_root(tmp_path)
    stage_payload, bundle_sha256, artifact_bytes = _bundle_payload()
    _send(
        root,
        _request("stage", expected_generation=1, payload=stage_payload),
        artifact_bytes=artifact_bytes,
    )
    _send(
        root,
        _request("activate", expected_generation=2, payload={"bundle_sha256": bundle_sha256}),
    )
    extra = root / "generations" / bundle_sha256 / "unmanifested-empty"
    extra.mkdir(mode=0o700)

    with pytest.raises(dispatcher.DispatcherRejected):
        _send(
            root,
            _request(
                "run_ptt",
                expected_generation=3,
                payload={"turn_id": str(TURN_ID), "input_mode": "reachy_local"},
            ),
            exec_handoff=lambda _argv, _fd: None,
        )


def test_generation_inventory_walk_is_descriptor_anchored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generation = tmp_path / "generation"
    nested = generation / "package"
    nested.mkdir(parents=True, mode=0o700)
    generation.chmod(0o700)
    _owner_write(generation / "manifest.json", b"manifest")
    _owner_write(nested / "module.py", b"module")

    def reject_path_walk(_path: Path):  # type: ignore[no-untyped-def]
        raise AssertionError("path-based generation walk is forbidden")

    monkeypatch.setattr(Path, "iterdir", reject_path_walk)
    monkeypatch.setattr(Path, "rglob", reject_path_walk)

    dispatcher._reject_unmanifested_generation_entries(
        generation,
        {"manifest.json", "package/module.py"},
    )


def test_manifest_artifact_count_is_bounded_before_filesystem_walk() -> None:
    records: dispatcher.JsonValue = [
        {
            "path": f"artifact-{index:02d}",
            "size": 0,
            "sha256": _digest(b""),
            "executable": False,
        }
        for index in range(dispatcher.MAX_ARTIFACTS)
    ]

    with pytest.raises(dispatcher.DispatcherRejected):
        dispatcher._require_artifact_records(records)


def test_main_converts_unexpected_runtime_failures_to_content_free_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_read(_stdin: object) -> object:
        raise OSError("sensitive-path-sentinel")

    monkeypatch.setattr(dispatcher, "_read_request_from_stdin", fail_read)
    stdout = io.BytesIO()
    stderr = io.StringIO()

    assert (
        dispatcher.main(argv=["dispatcher"], stdin=io.BytesIO(), stdout=stdout, stderr=stderr) == 1
    )
    assert stdout.getvalue() == b""
    assert stderr.getvalue() == "reachy-a05-dispatcher-rejected\n"


def test_main_rejects_delayed_trailing_bytes_on_one_shot_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fresh_root(tmp_path)
    read_fd, write_fd = os.pipe()
    reader = os.fdopen(read_fd, "rb", buffering=0)

    def write_delayed_tail() -> None:
        with os.fdopen(write_fd, "wb", buffering=0) as writer:
            writer.write(_frame(_request("status", expected_generation=1)))
            time.sleep(0.1)
            writer.write(b"trailing-byte")

    monkeypatch.setattr(dispatcher, "_resolve_remote_root", lambda _root: root)
    monkeypatch.setattr(
        dispatcher,
        "_require_process_identity",
        lambda _deployment, _root: None,
    )
    writer_thread = threading.Thread(target=write_delayed_tail)
    writer_thread.start()
    stdout = io.BytesIO()
    stderr = io.StringIO()
    try:
        result = dispatcher.main(
            argv=["dispatcher"],
            stdin=reader,
            stdout=stdout,
            stderr=stderr,
        )
    finally:
        writer_thread.join(timeout=2)
        reader.close()

    assert not writer_thread.is_alive()
    assert result == 1
    assert stdout.getvalue() == b""
    assert stderr.getvalue() == "reachy-a05-dispatcher-rejected\n"


def test_state_publish_rejects_and_preserves_unexpected_current_state(tmp_path: Path) -> None:
    root = _fresh_root(tmp_path)
    with dispatcher._LockedRoot(root) as locked:
        expected = dispatcher._read_state_locked(locked.root_fd, root)
        candidate = json.loads(_canonical(expected))
        candidate["deployment"]["state_generation"] = 2
        competitor = json.loads(_canonical(expected))
        competitor["deployment"]["state_generation"] = 3
        _owner_write(root / "remote-state.json", _canonical(competitor))

        with pytest.raises(dispatcher.DispatcherRejected):
            dispatcher._publish_state(
                locked.root_fd,
                root,
                candidate,
                expected_current=expected,
            )

    assert (root / "remote-state.json").read_bytes() == _canonical(competitor)


def test_state_publish_atomically_rejects_a_change_after_precheck(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fresh_root(tmp_path)
    expected = _read_state(root)
    candidate = json.loads(_canonical(expected))
    candidate["deployment"]["state_generation"] = 2
    competitor = json.loads(_canonical(expected))
    competitor["deployment"]["state_generation"] = 3
    original_read = dispatcher._read_state_locked
    read_count = 0

    def replace_after_observation(root_fd: int, observed_root: Path) -> dict[str, Any]:
        nonlocal read_count
        observed = original_read(root_fd, observed_root)
        read_count += 1
        if read_count == 1:
            _owner_write(root / "remote-state.json", _canonical(competitor))
        return observed

    monkeypatch.setattr(dispatcher, "_read_state_locked", replace_after_observation)

    with dispatcher._LockedRoot(root) as locked, pytest.raises(dispatcher.DispatcherRejected):
        dispatcher._publish_state(
            locked.root_fd,
            root,
            candidate,
            expected_current=expected,
        )

    assert (root / "remote-state.json").read_bytes() == _canonical(competitor)


def test_remove_does_not_delete_a_generation_before_state_cas(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fresh_root(tmp_path)
    stage_payload, bundle_sha256, artifact_bytes = _bundle_payload()
    _send(
        root,
        _request("stage", expected_generation=1, payload=stage_payload),
        artifact_bytes=artifact_bytes,
    )
    _send(
        root,
        _request("activate", expected_generation=2, payload={"bundle_sha256": bundle_sha256}),
    )
    expected = _read_state(root)
    competitor = json.loads(_canonical(expected))
    competitor["deployment"]["state_generation"] = 4
    original_read = dispatcher._read_state_locked
    read_count = 0

    def replace_after_publish_precheck(root_fd: int, observed_root: Path) -> dict[str, Any]:
        nonlocal read_count
        observed = original_read(root_fd, observed_root)
        read_count += 1
        if read_count == 2:
            _owner_write(root / "remote-state.json", _canonical(competitor))
        return observed

    monkeypatch.setattr(dispatcher, "_read_state_locked", replace_after_publish_precheck)

    with pytest.raises(dispatcher.DispatcherRejected):
        _send(
            root,
            _request(
                "remove",
                expected_generation=3,
                payload={"bundle_sha256": bundle_sha256},
            ),
        )

    assert (root / "generations" / bundle_sha256).is_dir()
    assert (root / "remote-state.json").read_bytes() == _canonical(competitor)


def test_verify_absent_rejects_a_generation_still_referenced_by_state(tmp_path: Path) -> None:
    root = _fresh_root(tmp_path)
    stage_payload, bundle_sha256, artifact_bytes = _bundle_payload()
    _send(
        root,
        _request("stage", expected_generation=1, payload=stage_payload),
        artifact_bytes=artifact_bytes,
    )
    _send(
        root,
        _request("activate", expected_generation=2, payload={"bundle_sha256": bundle_sha256}),
    )
    dispatcher._safe_remove_generation(root, bundle_sha256)

    with pytest.raises(dispatcher.DispatcherRejected):
        _send(
            root,
            _request(
                "verify_absent",
                expected_generation=3,
                payload={"bundle_sha256": bundle_sha256},
            ),
        )


def test_verify_absent_scans_staging_through_an_anchored_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fresh_root(tmp_path)
    staging = root / ".staging"
    staging.mkdir(mode=0o700)
    original_scandir = os.scandir

    def require_descriptor(path: Any) -> Any:
        assert type(path) is int
        return original_scandir(path)

    monkeypatch.setattr(os, "scandir", require_descriptor)

    response = _send(
        root,
        _request(
            "verify_absent",
            expected_generation=1,
            payload={"bundle_sha256": "a" * 64},
        ),
    )
    assert response["payload"] == {
        "active_bundle_sha256": None,
        "staged_bundle_sha256": None,
        "verified_absent": "a" * 64,
    }

    with pytest.raises(dispatcher.DispatcherRejected):
        _send(
            root,
            _request(
                "verify_absent",
                expected_generation=2,
                payload={"bundle_sha256": "a" * 64},
            ),
        )


def test_verify_absent_rejects_generation_directory_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fresh_root(tmp_path)
    generations = root / "generations"
    generations.mkdir(mode=0o700)
    moved = root / "generations-moved"
    bundle_sha256 = "a" * 64
    original_entry_exists = dispatcher._entry_exists_at
    checked = False

    def replace_after_first_check(parent_fd: int, name: str) -> bool:
        nonlocal checked
        result = original_entry_exists(parent_fd, name)
        if name == bundle_sha256 and not checked:
            generations.rename(moved)
            generations.mkdir(mode=0o700)
            (generations / bundle_sha256).mkdir(mode=0o700)
            checked = True
        return result

    monkeypatch.setattr(dispatcher, "_entry_exists_at", replace_after_first_check)

    with pytest.raises(dispatcher.DispatcherRejected):
        _send(
            root,
            _request(
                "verify_absent",
                expected_generation=1,
                payload={"bundle_sha256": bundle_sha256},
            ),
        )


def test_run_ptt_returns_ready_frame_then_execs_only_validated_active_generation(
    tmp_path: Path,
) -> None:
    root = _fresh_root(tmp_path)
    stage_payload, bundle_sha256, artifact_bytes = _bundle_payload()
    _send(
        root,
        _request("stage", expected_generation=1, payload=stage_payload),
        artifact_bytes=artifact_bytes,
    )
    _send(
        root,
        _request("activate", expected_generation=2, payload={"bundle_sha256": bundle_sha256}),
    )
    handoffs: list[tuple[str, ...]] = []

    def record_handoff(argv: tuple[str, ...], _executable_fd: int) -> None:
        handoffs.append(argv)

    ready = _send(
        root,
        _request(
            "run_ptt",
            expected_generation=3,
            payload={"turn_id": str(TURN_ID), "input_mode": "reachy_local"},
        ),
        exec_handoff=record_handoff,
    )

    assert ready["state_generation"] == 3
    assert ready["status"] == "active"
    assert ready["payload"] == {"input_mode": "reachy_local", "ready": True}
    assert handoffs == [
        (
            str(root / "generations" / bundle_sha256 / "bin" / "python"),
            "-m",
            "tuntun_edge.cli.ptt",
            "--turn-id",
            str(TURN_ID),
            "--input-mode",
            "reachy_local",
        )
    ]

    (root / "generations" / bundle_sha256 / "manifest.json").write_bytes(b"tampered")
    with pytest.raises(dispatcher.DispatcherRejected):
        _send(
            root,
            _request(
                "run_ptt",
                expected_generation=3,
                payload={"turn_id": str(TURN_ID), "input_mode": "reachy_local"},
            ),
            exec_handoff=record_handoff,
        )


def test_run_ptt_rejects_executable_replaced_after_bundle_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fresh_root(tmp_path)
    stage_payload, bundle_sha256, artifact_bytes = _bundle_payload()
    _send(
        root,
        _request("stage", expected_generation=1, payload=stage_payload),
        artifact_bytes=artifact_bytes,
    )
    _send(
        root,
        _request("activate", expected_generation=2, payload={"bundle_sha256": bundle_sha256}),
    )
    generation = root / "generations" / bundle_sha256
    executable = generation / "bin" / "python"
    original_validate = dispatcher._validate_bundle_directory

    def replace_after_validation(path: Path, *, expected_bundle: str | None = None) -> object:
        manifest = original_validate(path, expected_bundle=expected_bundle)
        if path == generation:
            executable.unlink()
            _owner_write(executable, b"#!/bin/sh\nexec false\n", mode=0o700)
        return manifest

    monkeypatch.setattr(dispatcher, "_validate_bundle_directory", replace_after_validation)

    with pytest.raises(dispatcher.DispatcherRejected):
        _send(
            root,
            _request(
                "run_ptt",
                expected_generation=3,
                payload={"turn_id": str(TURN_ID), "input_mode": "reachy_local"},
            ),
            exec_handoff=lambda _argv, _fd: None,
        )


def test_exec_handoff_rejects_path_replacement_after_descriptor_validation(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "python"
    executable_raw = b"#!/usr/bin/env python3\n"
    tmp_path.chmod(0o700)
    _owner_write(executable, executable_raw, mode=0o700)
    generation_fd = os.open(tmp_path, os.O_RDONLY)
    executable_fd = os.open(executable, os.O_RDONLY)
    argv = (str(executable), "-m", "tuntun_edge.cli.ptt")
    handoff = dispatcher._ExecutableHandoff(
        argv=argv,
        entrypoint_module="tuntun_edge.cli.ptt",
        manifest_bytes=b"{}",
        generation_path=tmp_path,
        generation_fd=generation_fd,
        generation_identity=dispatcher._FileIdentity.from_stat(os.fstat(generation_fd)),
        executable_fd=executable_fd,
        executable_identity=dispatcher._FileIdentity.from_stat(os.fstat(executable_fd)),
        executable_sha256=_digest(executable_raw),
    )
    executable.unlink()
    _owner_write(executable, b"#!/bin/sh\nexec false\n", mode=0o700)

    with pytest.raises(dispatcher.DispatcherRejected):
        dispatcher._exec_handoff(handoff)


def test_exec_handoff_executes_validated_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fresh_root(tmp_path)
    stage_payload, bundle_sha256, artifact_bytes = _bundle_payload()
    _send(
        root,
        _request("stage", expected_generation=1, payload=stage_payload),
        artifact_bytes=artifact_bytes,
    )
    _send(
        root,
        _request("activate", expected_generation=2, payload={"bundle_sha256": bundle_sha256}),
    )
    request = dispatcher._parse_request_body(
        _canonical(
            _request(
                "run_ptt",
                expected_generation=3,
                payload={"turn_id": str(TURN_ID), "input_mode": "reachy_local"},
            )
        )
    )
    outcome = dispatcher._dispatch_request(
        request,
        remote_root=root,
        environ={},
        artifact_stream=io.BytesIO(),
        closed_artifact_stream=True,
        enforce_process_identity=False,
    )
    assert outcome.handoff is not None
    handoff = outcome.handoff
    executable_fd = handoff.executable_fd
    argv = handoff.argv
    observed: list[object] = []
    observed_environment: dict[str, str] = {}
    observed_cwd: list[Path] = []
    snapshot_fds: list[int] = []

    class ExecObserved(RuntimeError):
        pass

    def observe_execve(path: object, exec_argv: object, environ: object) -> None:
        observed.extend((path, exec_argv))
        assert isinstance(environ, dict)
        observed_environment.update(environ)
        observed_cwd.append(Path.cwd())
        raise ExecObserved

    monkeypatch.setenv("PYTHONPATH", "/private/tmp/attacker-imports")
    monkeypatch.setenv("PYTHONHOME", "/private/tmp/attacker-home")
    monkeypatch.setenv("PIP_INDEX_URL", "https://attacker.invalid/simple")
    monkeypatch.setattr(dispatcher, "_execve_supports_fd", lambda: True)
    snapshot_path = tmp_path / "sealed-imports.zip"
    _owner_write(snapshot_path, b"sealed-imports")

    def fake_seal(entries: tuple[tuple[str, bytes], ...]) -> int:
        assert "tuntun_edge/cli/ptt.py" in {path for path, _raw in entries}
        snapshot_fd = os.open(snapshot_path, os.O_RDONLY)
        snapshot_fds.append(snapshot_fd)
        return snapshot_fd

    monkeypatch.setattr(dispatcher, "_seal_import_snapshot", fake_seal)
    monkeypatch.setattr(os, "execve", observe_execve)

    with pytest.raises(ExecObserved):
        dispatcher._exec_handoff(handoff)

    assert len(snapshot_fds) == 1
    assert observed == [
        executable_fd,
        (f"/proc/self/fd/{executable_fd}", *argv[1:]),
    ]
    assert observed_cwd == [Path("/")]
    assert observed_environment == dispatcher._closed_exec_environment(
        import_snapshot_fd=snapshot_fds[0],
    )
    assert observed_environment["PYTHONPATH"] == f"/proc/self/fd/{snapshot_fds[0]}"
    assert "PYTHONHOME" not in observed_environment
    assert "PIP_INDEX_URL" not in observed_environment


def test_exec_handoff_rejects_module_replaced_after_dispatch_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fresh_root(tmp_path)
    stage_payload, bundle_sha256, artifact_bytes = _bundle_payload()
    _send(
        root,
        _request("stage", expected_generation=1, payload=stage_payload),
        artifact_bytes=artifact_bytes,
    )
    _send(
        root,
        _request("activate", expected_generation=2, payload={"bundle_sha256": bundle_sha256}),
    )
    generation = root / "generations" / bundle_sha256
    module = generation / "tuntun_edge" / "cli" / "ptt.py"
    original_validate = dispatcher._validate_bundle_directory
    replaced = False

    def replace_module_after_validation(
        path: Path,
        *,
        expected_bundle: str | None = None,
    ) -> dispatcher.JsonObject:
        nonlocal replaced
        manifest = original_validate(path, expected_bundle=expected_bundle)
        if path == generation and not replaced:
            module.unlink()
            _owner_write(module, b"raise RuntimeError('replacement')\n")
            replaced = True
        return manifest

    monkeypatch.setattr(
        dispatcher,
        "_validate_bundle_directory",
        replace_module_after_validation,
    )
    request = dispatcher._parse_request_body(
        _canonical(
            _request(
                "run_ptt",
                expected_generation=3,
                payload={"turn_id": str(TURN_ID), "input_mode": "reachy_local"},
            )
        )
    )
    outcome = dispatcher._dispatch_request(
        request,
        remote_root=root,
        environ={},
        artifact_stream=io.BytesIO(),
        closed_artifact_stream=True,
        enforce_process_identity=False,
    )
    assert outcome.handoff is not None
    monkeypatch.setattr(dispatcher, "_execve_supports_fd", lambda: True)
    monkeypatch.setattr(
        os,
        "execve",
        lambda *_args: pytest.fail("tampered module reached exec"),
    )

    with pytest.raises(dispatcher.DispatcherRejected):
        dispatcher._exec_handoff(outcome.handoff)


def test_exec_handoff_rejects_module_replaced_after_final_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fresh_root(tmp_path)
    stage_payload, bundle_sha256, artifact_bytes = _bundle_payload()
    _send(
        root,
        _request("stage", expected_generation=1, payload=stage_payload),
        artifact_bytes=artifact_bytes,
    )
    _send(
        root,
        _request("activate", expected_generation=2, payload={"bundle_sha256": bundle_sha256}),
    )
    generation = root / "generations" / bundle_sha256
    module = generation / "tuntun_edge" / "cli" / "ptt.py"
    original_validate = dispatcher._validate_bundle_directory
    validation_count = 0

    def replace_module_after_final_validation(
        path: Path,
        *,
        expected_bundle: str | None = None,
    ) -> dispatcher.JsonObject:
        nonlocal validation_count
        manifest = original_validate(path, expected_bundle=expected_bundle)
        if path == generation:
            validation_count += 1
            if validation_count == 2:
                module.unlink()
                _owner_write(module, b"raise RuntimeError('tight replacement')\n")
        return manifest

    monkeypatch.setattr(
        dispatcher,
        "_validate_bundle_directory",
        replace_module_after_final_validation,
    )
    request = dispatcher._parse_request_body(
        _canonical(
            _request(
                "run_ptt",
                expected_generation=3,
                payload={"turn_id": str(TURN_ID), "input_mode": "reachy_local"},
            )
        )
    )
    outcome = dispatcher._dispatch_request(
        request,
        remote_root=root,
        environ={},
        artifact_stream=io.BytesIO(),
        closed_artifact_stream=True,
        enforce_process_identity=False,
    )
    assert outcome.handoff is not None
    monkeypatch.setattr(dispatcher, "_execve_supports_fd", lambda: True)
    monkeypatch.setattr(
        os,
        "execve",
        lambda *_args: pytest.fail("post-final-validation replacement reached exec"),
    )

    with pytest.raises(dispatcher.DispatcherRejected):
        dispatcher._exec_handoff(outcome.handoff)


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "memfd_create"),
    reason="Linux memfd seals are verified in the Python 3.11 contract job",
)
def test_import_snapshot_memfd_is_write_sealed() -> None:
    snapshot_fd = dispatcher._seal_import_snapshot(
        (
            ("tuntun_edge/__init__.py", b""),
            ("tuntun_edge/cli/__init__.py", b""),
            ("tuntun_edge/cli/ptt.py", b"VALUE = 1\n"),
        )
    )
    try:
        seals = fcntl.fcntl(snapshot_fd, dispatcher._LINUX_F_GET_SEALS)
        required = (
            dispatcher._LINUX_F_SEAL_SEAL
            | dispatcher._LINUX_F_SEAL_SHRINK
            | dispatcher._LINUX_F_SEAL_GROW
            | dispatcher._LINUX_F_SEAL_WRITE
        )
        assert seals & required == required
        with pytest.raises(OSError):
            os.pwrite(snapshot_fd, b"replacement", 0)
    finally:
        os.close(snapshot_fd)
