from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from uuid import UUID

import pytest
import tuntun_core.adapters.reachy.ssh_forced as ssh_forced_module
from tuntun_contracts.poc.framing import PttInputMode
from tuntun_core.adapters.reachy.commissioning import ReachyA05StateStatus
from tuntun_core.adapters.reachy.ssh_forced import (
    CLOSED_SSH_ENV,
    SSH_OPTION_VALUES,
    DispatchVerb,
    SshBridgeError,
    SshBridgeErrorCode,
    SshDispatcherResponse,
    SshForcedCommandProcess,
    SshLoopbackContractTarget,
    _drain_stderr,
    build_pinned_ssh_argv,
    decode_dispatcher_response,
    encode_dispatcher_request,
)

from tests.fixtures.reachy_a05_commissioning import (
    COMMISSIONING_ID,
    deployment_for_status,
    digest,
    private_repository,
    publish_state_with_status,
    valid_expectation,
)

OPERATION_ID = UUID("41000000-0000-4000-8000-000000000001")
TURN_ID = UUID("42000000-0000-4000-8000-000000000001")


def _owner_write(path: Path, body: bytes, *, mode: int = 0o600) -> None:
    path.write_bytes(body)
    path.chmod(mode)


def _status_payload_for(
    *,
    status: ReachyA05StateStatus,
    generation: int,
    staged_bundle_sha256: str | None = None,
    active_bundle_sha256: str | None = None,
) -> dict[str, object]:
    deployment = deployment_for_status(generation=generation, status=status)
    return {
        "boot_identity_sha256": deployment.boot_identity_sha256,
        "capability_report_sha256": deployment.capability_report_sha256,
        "runtime_inventory_sha256": deployment.runtime.runtime_inventory_sha256,
        "dispatcher_sha256": deployment.dispatcher_sha256,
        "dispatcher_protocol_version": deployment.dispatcher_protocol_version,
        "authorized_key_line_sha256": deployment.authorized_key_line_sha256,
        "staged_bundle_sha256": (
            staged_bundle_sha256
            if staged_bundle_sha256 is not None
            else deployment.staged_bundle_sha256
        ),
        "active_bundle_sha256": (
            active_bundle_sha256
            if active_bundle_sha256 is not None
            else deployment.active_bundle_sha256
        ),
    }


class _FakeStdin:
    def __init__(self) -> None:
        self.writes: list[bytes] = []
        self.events: list[str] = []
        self.closed = False

    def write(self, data: bytes) -> None:
        if self.closed:
            raise BrokenPipeError
        self.events.append("write")
        self.writes.append(data)

    async def drain(self) -> None:
        self.events.append("drain")

    def close(self) -> None:
        self.closed = True
        self.events.append("stdin.close")

    async def wait_closed(self) -> None:
        self.events.append("stdin.wait_closed")


class _BytesStdout:
    def __init__(self, body: bytes = b"") -> None:
        self.body = bytearray(body)
        self.fail_once = False

    async def readexactly(self, count: int) -> bytes:
        if self.fail_once:
            self.fail_once = False
            raise asyncio.IncompleteReadError(partial=b"", expected=count)
        if len(self.body) < count:
            partial = bytes(self.body)
            self.body.clear()
            raise asyncio.IncompleteReadError(partial=partial, expected=count)
        result = bytes(self.body[:count])
        del self.body[:count]
        return result

    async def read(self, count: int = -1) -> bytes:
        if not self.body:
            return b""
        if count < 0:
            count = len(self.body)
        result = bytes(self.body[:count])
        del self.body[:count]
        return result


class _CloseAwareStdout(_BytesStdout):
    def __init__(self, body: bytes, stdin: _FakeStdin) -> None:
        super().__init__(body)
        self.stdin = stdin

    async def readexactly(self, count: int) -> bytes:
        assert "stdin.close" in self.stdin.events
        return await super().readexactly(count)


def _decode_wire_request(raw: bytes) -> dict[str, object]:
    (declared_length,) = ssh_forced_module.DISPATCH_PREFIX.unpack(
        raw[: ssh_forced_module.DISPATCH_PREFIX.size]
    )
    body_start = ssh_forced_module.DISPATCH_PREFIX.size
    body_end = body_start + declared_length
    return json.loads(raw[body_start:body_end])


class _RequestAwareStdout(_BytesStdout):
    def __init__(
        self,
        stdin: _FakeStdin,
        responder: Callable[[dict[str, object]], bytes],
    ) -> None:
        super().__init__()
        self._stdin = stdin
        self._responder = responder
        self._primed = False

    async def readexactly(self, count: int) -> bytes:
        if not self.body and not self._primed:
            self._primed = True
            self.body.extend(self._responder(_decode_wire_request(self._stdin.writes[-1])))
        return await super().readexactly(count)


class _FakeProcess:
    def __init__(self, stdout: _BytesStdout | None = None) -> None:
        self.stdin = _FakeStdin()
        self.stdout = stdout or _BytesStdout()
        self.stderr = _BytesStdout(b"remote stderr that must never surface")
        self.pid = 99551
        self.returncode: int | None = None
        self.wait_calls = 0

    async def wait(self) -> int:
        self.wait_calls += 1
        if self.returncode is None:
            raise TimeoutError
        return self.returncode


class _FloodingStderr:
    def __init__(self, chunk_count: int) -> None:
        self.chunk_count = chunk_count
        self.read_calls = 0

    async def read(self, _count: int = -1) -> bytes:
        self.read_calls += 1
        if self.chunk_count <= 0:
            return b""
        self.chunk_count -= 1
        return b"x" * 1024


def _ready_response(
    *,
    operation_id: UUID = OPERATION_ID,
    state_generation: int = 3,
) -> bytes:
    return SshDispatcherResponse(
        version=1,
        operation_id=operation_id,
        ok=True,
        state_generation=state_generation,
        status="active",
        payload={"ready": True, "input_mode": PttInputMode.REACHY_LOCAL.value},
    ).to_wire_bytes()


def _status_response(
    *,
    operation_id: UUID,
    status: ReachyA05StateStatus,
    generation: int,
    staged_bundle_sha256: str | None = None,
    active_bundle_sha256: str | None = None,
    payload: dict[str, object] | None = None,
) -> bytes:
    return SshDispatcherResponse(
        version=1,
        operation_id=operation_id,
        ok=True,
        state_generation=generation,
        status=status.value,
        payload=(
            _status_payload_for(
                status=status,
                generation=generation,
                staged_bundle_sha256=staged_bundle_sha256,
                active_bundle_sha256=active_bundle_sha256,
            )
            if payload is None
            else payload
        ),
    ).to_wire_bytes()


def _stage_payload_and_artifacts() -> tuple[dict[str, object], bytes]:
    manifest = b'{"schema_version":"tuntun.reachy-a05-bundle-manifest.v1"}'
    edge = b"def main():\n    return None\n"
    records = [
        {
            "path": "manifest.json",
            "size": len(manifest),
            "sha256": digest(manifest),
            "executable": False,
        },
        {
            "path": "tuntun_edge/cli/ptt.py",
            "size": len(edge),
            "sha256": digest(edge),
            "executable": False,
        },
    ]
    return {"bundle_sha256": "6" * 64, "artifacts": records}, manifest + edge


@pytest.mark.asyncio
async def test_spawn_consumes_commissioning_lease_and_keeps_snapshot_until_close(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_state_with_status(repository, ReachyA05StateStatus.ACTIVE)
    fake_process = _FakeProcess()
    captured: dict[str, object] = {}

    async def factory(*argv: str, **kwargs: object) -> _FakeProcess:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return fake_process

    process = await SshForcedCommandProcess.spawn(
        repository,
        expectation=valid_expectation(state),
        process_factory=factory,
    )

    assert captured["argv"] == build_pinned_ssh_argv(process.target)
    expected_options: list[str] = []
    for option in SSH_OPTION_VALUES:
        expected_options.extend(("-o", option.format(target=process.target)))
    assert captured["argv"] == (
        "/usr/bin/ssh",
        "-4",
        "-T",
        "-F",
        "/dev/null",
        "-p",
        "22",
        *expected_options,
        "--",
        "owner@192.168.50.22",
    )
    assert process.target.commissioning_id == state.deployment.commissioning_id
    assert process.target.state_generation == state.deployment.state_generation
    assert process.target.host == state.reachy_ipv4
    assert process.target.user == state.deployment.ssh_principal
    assert process.target.port == 22
    assert process.target.status is ReachyA05StateStatus.ACTIVE
    assert process.target.ptt_input_mode is PttInputMode.REACHY_LOCAL
    assert process.target.identity_file.parent.name.startswith(".spawn-lease.")
    assert process.target.known_hosts_file.parent == process.target.identity_file.parent
    assert process.target.identity_file.exists()
    assert process.target.known_hosts_file.exists()
    assert not hasattr(process.target, "state_identity")
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["stdin"] is subprocess.PIPE
    assert kwargs["stdout"] is subprocess.PIPE
    assert kwargs["stderr"] is subprocess.PIPE
    assert kwargs["start_new_session"] is True
    assert kwargs["env"] == CLOSED_SSH_ENV
    assert "shell" not in kwargs
    assert "preexec_fn" not in kwargs
    snapshot_root = process.target.identity_file.parent
    fake_process.returncode = 0
    await process.close()
    assert not snapshot_root.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "keyword"),
    (
        ("identity_config_option", "IdentityFile"),
        ("known_hosts_config_option", "UserKnownHostsFile"),
    ),
)
async def test_build_pinned_ssh_argv_requires_config_options_match_target_paths(
    tmp_path: Path,
    field: str,
    keyword: str,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_state_with_status(repository, ReachyA05StateStatus.ACTIVE)
    fake_process = _FakeProcess()

    async def factory(*_argv: str, **_kwargs: object) -> _FakeProcess:
        return fake_process

    process = await SshForcedCommandProcess.spawn(
        repository,
        expectation=valid_expectation(state),
        process_factory=factory,
    )
    try:
        bad_target = replace(
            process.target,
            **{field: f"{keyword}={process.target.identity_file.parent / 'other-file'}"},
        )
        with pytest.raises(SshBridgeError) as error:
            build_pinned_ssh_argv(bad_target)
    finally:
        fake_process.returncode = 0
        await process.close()

    assert error.value.code is SshBridgeErrorCode.UNSAFE_ARGV


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad_user",
    ("", "Owner", "owner,root", "-oProxyCommand=sh", "root"),
)
async def test_build_pinned_ssh_argv_rejects_non_canonical_usernames(
    tmp_path: Path,
    bad_user: str,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_state_with_status(repository, ReachyA05StateStatus.ACTIVE)
    fake_process = _FakeProcess()

    async def factory(*_argv: str, **_kwargs: object) -> _FakeProcess:
        return fake_process

    process = await SshForcedCommandProcess.spawn(
        repository,
        expectation=valid_expectation(state),
        process_factory=factory,
    )
    try:
        with pytest.raises(SshBridgeError) as error:
            build_pinned_ssh_argv(replace(process.target, user=bad_user))
    finally:
        fake_process.returncode = 0
        await process.close()

    assert error.value.code is SshBridgeErrorCode.UNSAFE_ARGV


@pytest.mark.asyncio
async def test_stage_dispatch_writes_request_frame_then_manifest_ordered_artifacts(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_state_with_status(repository, ReachyA05StateStatus.COMMISSIONED)
    generation = state.deployment.state_generation
    payload, artifact_bytes = _stage_payload_and_artifacts()
    fake_process = _FakeProcess(
        _BytesStdout(
            SshDispatcherResponse(
                version=1,
                operation_id=OPERATION_ID,
                ok=True,
                state_generation=generation + 1,
                status="staged",
                payload={
                    "active_bundle_sha256": None,
                    "staged_bundle_sha256": payload["bundle_sha256"],
                },
            ).to_wire_bytes()
        )
    )

    async def factory(*_argv: str, **_kwargs: object) -> _FakeProcess:
        return fake_process

    process = await SshForcedCommandProcess.spawn(
        repository,
        expectation=valid_expectation(state),
        process_factory=factory,
    )

    response = await process.dispatch(
        DispatchVerb.STAGE,
        operation_id=OPERATION_ID,
        expected_generation=generation,
        payload=payload,
        artifact_bytes=artifact_bytes,
    )

    assert response.payload == {
        "active_bundle_sha256": None,
        "staged_bundle_sha256": payload["bundle_sha256"],
    }
    assert fake_process.stdin.writes == [
        encode_dispatcher_request(
            verb=DispatchVerb.STAGE,
            operation_id=OPERATION_ID,
            commissioning_id=COMMISSIONING_ID,
            expected_generation=generation,
            payload=payload,
        )
        + artifact_bytes
    ]
    assert fake_process.stdin.events[:4] == ["write", "drain", "stdin.close", "stdin.wait_closed"]
    fake_process.returncode = 0
    await process.close()


@pytest.mark.asyncio
async def test_activate_dispatch_accepts_real_dispatcher_generation_increment(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_state_with_status(repository, ReachyA05StateStatus.STAGED)
    generation = state.deployment.state_generation
    bundle_sha256 = state.deployment.staged_bundle_sha256
    assert bundle_sha256 is not None
    fake_process = _FakeProcess(
        _BytesStdout(
            SshDispatcherResponse(
                version=1,
                operation_id=OPERATION_ID,
                ok=True,
                state_generation=generation + 1,
                status="active",
                payload={
                    "active_bundle_sha256": bundle_sha256,
                    "staged_bundle_sha256": None,
                },
            ).to_wire_bytes()
        )
    )

    async def factory(*_argv: str, **_kwargs: object) -> _FakeProcess:
        return fake_process

    process = await SshForcedCommandProcess.spawn(
        repository,
        expectation=valid_expectation(state),
        process_factory=factory,
    )

    try:
        response = await process.dispatch(
            DispatchVerb.ACTIVATE,
            operation_id=OPERATION_ID,
            expected_generation=generation,
            payload={"bundle_sha256": bundle_sha256},
        )
    finally:
        fake_process.returncode = 0
        await process.close()

    assert response.state_generation == generation + 1
    assert response.status == "active"
    assert response.payload == {
        "active_bundle_sha256": bundle_sha256,
        "staged_bundle_sha256": None,
    }


@pytest.mark.asyncio
async def test_remove_dispatch_accepts_real_dispatcher_generation_increment(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_state_with_status(repository, ReachyA05StateStatus.ACTIVE)
    generation = state.deployment.state_generation
    bundle_sha256 = state.deployment.active_bundle_sha256
    assert bundle_sha256 is not None
    fake_process = _FakeProcess(
        _BytesStdout(
            SshDispatcherResponse(
                version=1,
                operation_id=OPERATION_ID,
                ok=True,
                state_generation=generation + 1,
                status="removed",
                payload={
                    "active_bundle_sha256": None,
                    "staged_bundle_sha256": None,
                    "verified_absent": bundle_sha256,
                },
            ).to_wire_bytes()
        )
    )

    async def factory(*_argv: str, **_kwargs: object) -> _FakeProcess:
        return fake_process

    process = await SshForcedCommandProcess.spawn(
        repository,
        expectation=valid_expectation(state),
        process_factory=factory,
    )

    try:
        response = await process.dispatch(
            DispatchVerb.REMOVE,
            operation_id=OPERATION_ID,
            expected_generation=generation,
            payload={"bundle_sha256": bundle_sha256},
        )
    finally:
        fake_process.returncode = 0
        await process.close()

    assert response.state_generation == generation + 1
    assert response.status == "removed"
    assert response.payload == {
        "active_bundle_sha256": None,
        "staged_bundle_sha256": None,
        "verified_absent": bundle_sha256,
    }


@pytest.mark.asyncio
async def test_spawn_revalidates_state_and_key_identity_immediately_before_exec(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_state_with_status(repository, ReachyA05StateStatus.ACTIVE)
    replacement = repository.root / "replacement-id"
    _owner_write(replacement, b"private-key\n")
    replacement.replace(repository.root / "identity")
    factory_called = False

    async def factory(*_argv: str, **_kwargs: object) -> _FakeProcess:
        nonlocal factory_called
        factory_called = True
        return _FakeProcess()

    with pytest.raises(SshBridgeError) as error:
        await SshForcedCommandProcess.spawn(
            repository,
            expectation=valid_expectation(state),
            process_factory=factory,
        )

    assert error.value.code is SshBridgeErrorCode.UNSAFE_STATE
    assert factory_called is False


@pytest.mark.asyncio
async def test_dispatcher_request_response_are_canonical_bounded_and_generation_bound(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_state_with_status(repository, ReachyA05StateStatus.ACTIVE)
    generation = state.deployment.state_generation
    fake_process = _FakeProcess(_BytesStdout(_ready_response(state_generation=generation)))

    async def factory(*_argv: str, **_kwargs: object) -> _FakeProcess:
        return fake_process

    process = await SshForcedCommandProcess.spawn(
        repository,
        expectation=valid_expectation(state),
        process_factory=factory,
    )

    response = await process.dispatch(
        DispatchVerb.RUN_PTT,
        operation_id=OPERATION_ID,
        expected_generation=generation,
        payload={"turn_id": str(TURN_ID), "input_mode": PttInputMode.REACHY_LOCAL.value},
    )

    assert response.payload == {"input_mode": "reachy_local", "ready": True}
    assert "stdin.close" not in fake_process.stdin.events
    raw_request = fake_process.stdin.writes[0]
    request = encode_dispatcher_request(
        verb=DispatchVerb.RUN_PTT,
        operation_id=OPERATION_ID,
        commissioning_id=COMMISSIONING_ID,
        expected_generation=generation,
        payload={"turn_id": str(TURN_ID), "input_mode": PttInputMode.REACHY_LOCAL.value},
    )
    assert raw_request == request

    mismatched = SshDispatcherResponse(
        version=1,
        operation_id=UUID("41000000-0000-4000-8000-000000000002"),
        ok=True,
        state_generation=generation,
        status="active",
        payload={},
    ).to_wire_bytes()
    with pytest.raises(SshBridgeError) as error:
        decode_dispatcher_response(
            mismatched,
            operation_id=OPERATION_ID,
            expected_generation=generation,
        )
    assert error.value.code is SshBridgeErrorCode.DISPATCH_PROTOCOL
    fake_process.returncode = 0
    await process.close()


def test_decode_dispatcher_response_binds_idempotent_mutation_to_requested_bundle() -> None:
    generation = 3
    requested_bundle = "b" * 64
    wrong_bundle = "c" * 64
    raw = SshDispatcherResponse(
        version=1,
        operation_id=OPERATION_ID,
        ok=True,
        state_generation=generation,
        status="active",
        payload={"active_bundle_sha256": wrong_bundle, "staged_bundle_sha256": None},
    ).to_wire_bytes()

    with pytest.raises(SshBridgeError) as error:
        decode_dispatcher_response(
            raw,
            operation_id=OPERATION_ID,
            expected_generation=generation,
            verb=DispatchVerb.ACTIVATE,
            request_payload={"bundle_sha256": requested_bundle},
        )

    assert error.value.code is SshBridgeErrorCode.DISPATCH_PROTOCOL


def test_decode_dispatcher_response_rejects_unbounded_mutating_generation_jump() -> None:
    generation = 3
    bundle_sha256 = "b" * 64
    raw = SshDispatcherResponse(
        version=1,
        operation_id=OPERATION_ID,
        ok=True,
        state_generation=generation + 2,
        status="staged",
        payload={"active_bundle_sha256": None, "staged_bundle_sha256": bundle_sha256},
    ).to_wire_bytes()

    with pytest.raises(SshBridgeError) as error:
        decode_dispatcher_response(
            raw,
            operation_id=OPERATION_ID,
            expected_generation=generation,
            verb=DispatchVerb.STAGE,
            request_payload={"bundle_sha256": bundle_sha256},
        )

    assert error.value.code is SshBridgeErrorCode.DISPATCH_PROTOCOL


@pytest.mark.asyncio
async def test_non_run_ptt_dispatch_half_closes_stdin_before_response_and_rejects_tail(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_state_with_status(repository, ReachyA05StateStatus.ACTIVE)
    generation = state.deployment.state_generation
    fake_process = _FakeProcess()
    fake_process.stdout = _CloseAwareStdout(
        _status_response(
            operation_id=OPERATION_ID,
            status=ReachyA05StateStatus.ACTIVE,
            generation=generation,
            active_bundle_sha256=state.deployment.active_bundle_sha256,
        ),
        fake_process.stdin,
    )

    async def factory(*_argv: str, **_kwargs: object) -> _FakeProcess:
        return fake_process

    process = await SshForcedCommandProcess.spawn(
        repository,
        expectation=valid_expectation(state),
        process_factory=factory,
    )

    response = await process.dispatch(
        DispatchVerb.STATUS,
        operation_id=OPERATION_ID,
        expected_generation=generation,
        payload={},
    )

    assert response.status == "active"
    assert fake_process.stdin.events[:4] == ["write", "drain", "stdin.close", "stdin.wait_closed"]
    with pytest.raises(SshBridgeError) as error:
        await process.write(b"x")
    assert error.value.code is SshBridgeErrorCode.CLOSED
    fake_process.returncode = 0
    await process.close()


@pytest.mark.asyncio
async def test_verify_absent_dispatch_remains_expected_generation_bound(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_state_with_status(repository, ReachyA05StateStatus.ACTIVE)
    generation = state.deployment.state_generation
    response_bytes = SshDispatcherResponse(
        version=1,
        operation_id=OPERATION_ID,
        ok=True,
        state_generation=generation + 1,
        status="active",
        payload={
            "active_bundle_sha256": state.deployment.active_bundle_sha256,
            "staged_bundle_sha256": None,
            "verified_absent": "6" * 64,
        },
    ).to_wire_bytes()
    fake_process = _FakeProcess(_BytesStdout(response_bytes))

    async def factory(*_argv: str, **_kwargs: object) -> _FakeProcess:
        return fake_process

    process = await SshForcedCommandProcess.spawn(
        repository,
        expectation=valid_expectation(state),
        process_factory=factory,
    )

    with pytest.raises(SshBridgeError) as error:
        await process.dispatch(
            DispatchVerb.VERIFY_ABSENT,
            operation_id=OPERATION_ID,
            expected_generation=generation,
            payload={"bundle_sha256": "6" * 64},
        )

    assert error.value.code is SshBridgeErrorCode.DISPATCH_PROTOCOL
    assert error.value.reconciliation is None
    assert fake_process.stdin.events[:4] == ["write", "drain", "stdin.close", "stdin.wait_closed"]
    fake_process.returncode = 0
    await process.close()


@pytest.mark.asyncio
async def test_uncertain_mutation_attempts_status_reconciliation_before_failing_closed(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_state_with_status(repository, ReachyA05StateStatus.STAGED)
    generation = state.deployment.state_generation
    status_operation_id = ssh_forced_module.derive_status_reconciliation_operation_id(
        OPERATION_ID,
        DispatchVerb.ACTIVATE,
    )
    status_response = _status_response(
        operation_id=status_operation_id,
        status=ReachyA05StateStatus.ACTIVE,
        generation=generation + 1,
        active_bundle_sha256=state.deployment.staged_bundle_sha256,
    )
    mutating_stdout = _BytesStdout()
    mutating_stdout.fail_once = True
    mutating_process = _FakeProcess(mutating_stdout)
    status_process = _FakeProcess(_BytesStdout(status_response))
    processes = [mutating_process, status_process]

    async def factory(*_argv: str, **_kwargs: object) -> _FakeProcess:
        return processes.pop(0)

    process = await SshForcedCommandProcess.spawn(
        repository,
        expectation=valid_expectation(state),
        process_factory=factory,
    )

    with pytest.raises(SshBridgeError) as error:
        await process.dispatch(
            DispatchVerb.ACTIVATE,
            operation_id=OPERATION_ID,
            expected_generation=generation,
            payload={"active_bundle_sha256": state.deployment.staged_bundle_sha256},
        )

    assert error.value.code is SshBridgeErrorCode.UNCERTAIN_DISPATCH
    assert error.value.reconciliation is not None
    assert (
        error.value.reconciliation.result
        is ssh_forced_module.SshDispatchReconciliationResult.COMMITTED
    )
    assert error.value.reconciliation.status_operation_id == status_operation_id
    assert not processes
    assert len(mutating_process.stdin.writes) == 1
    assert b'"verb":"activate"' in mutating_process.stdin.writes[0]
    assert len(status_process.stdin.writes) == 1
    assert b'"verb":"status"' in status_process.stdin.writes[0]
    assert f'"operation_id":"{status_operation_id}"'.encode() in status_process.stdin.writes[0]
    assert f'"operation_id":"{OPERATION_ID}"'.encode() not in status_process.stdin.writes[0]
    mutating_process.returncode = 0
    await process.close()


@pytest.mark.asyncio
async def test_uncertain_remove_status_removed_without_verify_absent_is_indeterminate(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_state_with_status(repository, ReachyA05StateStatus.ACTIVE)
    generation = state.deployment.state_generation
    bundle_sha256 = state.deployment.active_bundle_sha256
    assert bundle_sha256 is not None
    status_operation_id = ssh_forced_module.derive_status_reconciliation_operation_id(
        OPERATION_ID,
        DispatchVerb.REMOVE,
    )
    status_response = _status_response(
        operation_id=status_operation_id,
        status=ReachyA05StateStatus.REMOVED,
        generation=generation + 1,
        active_bundle_sha256=None,
        staged_bundle_sha256=None,
    )
    mutating_stdout = _BytesStdout()
    mutating_stdout.fail_once = True
    mutating_process = _FakeProcess(mutating_stdout)
    status_process = _FakeProcess(_BytesStdout(status_response))
    processes = [mutating_process, status_process]

    async def factory(*_argv: str, **_kwargs: object) -> _FakeProcess:
        if not processes:
            raise RuntimeError("no verify process available")
        return processes.pop(0)

    process = await SshForcedCommandProcess.spawn(
        repository,
        expectation=valid_expectation(state),
        process_factory=factory,
    )

    with pytest.raises(SshBridgeError) as error:
        await process.dispatch(
            DispatchVerb.REMOVE,
            operation_id=OPERATION_ID,
            expected_generation=generation,
            payload={"bundle_sha256": bundle_sha256},
        )

    assert error.value.code is SshBridgeErrorCode.UNCERTAIN_DISPATCH
    assert error.value.reconciliation is not None
    assert (
        error.value.reconciliation.result
        is ssh_forced_module.SshDispatchReconciliationResult.INDETERMINATE
    )
    assert not processes
    assert len(status_process.stdin.writes) == 1
    assert b'"verb":"status"' in status_process.stdin.writes[0]
    mutating_process.returncode = 0
    await process.close()


@pytest.mark.asyncio
async def test_uncertain_remove_commits_only_after_fresh_verify_absent(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_state_with_status(repository, ReachyA05StateStatus.ACTIVE)
    generation = state.deployment.state_generation
    bundle_sha256 = state.deployment.active_bundle_sha256
    assert bundle_sha256 is not None
    status_operation_id = ssh_forced_module.derive_status_reconciliation_operation_id(
        OPERATION_ID,
        DispatchVerb.REMOVE,
    )
    status_response = _status_response(
        operation_id=status_operation_id,
        status=ReachyA05StateStatus.REMOVED,
        generation=generation + 1,
        active_bundle_sha256=None,
        staged_bundle_sha256=None,
    )
    mutating_stdout = _BytesStdout()
    mutating_stdout.fail_once = True
    mutating_process = _FakeProcess(mutating_stdout)
    status_process = _FakeProcess(_BytesStdout(status_response))
    verify_process = _FakeProcess()

    def verify_responder(request: dict[str, object]) -> bytes:
        return SshDispatcherResponse(
            version=1,
            operation_id=UUID(str(request["operation_id"])),
            ok=True,
            state_generation=generation + 1,
            status="removed",
            payload={
                "active_bundle_sha256": None,
                "staged_bundle_sha256": None,
                "verified_absent": bundle_sha256,
            },
        ).to_wire_bytes()

    verify_process.stdout = _RequestAwareStdout(verify_process.stdin, verify_responder)
    processes = [mutating_process, status_process, verify_process]

    async def factory(*_argv: str, **_kwargs: object) -> _FakeProcess:
        return processes.pop(0)

    process = await SshForcedCommandProcess.spawn(
        repository,
        expectation=valid_expectation(state),
        process_factory=factory,
    )

    with pytest.raises(SshBridgeError) as error:
        await process.dispatch(
            DispatchVerb.REMOVE,
            operation_id=OPERATION_ID,
            expected_generation=generation,
            payload={"bundle_sha256": bundle_sha256},
        )

    assert error.value.code is SshBridgeErrorCode.UNCERTAIN_DISPATCH
    assert error.value.reconciliation is not None
    assert (
        error.value.reconciliation.result
        is ssh_forced_module.SshDispatchReconciliationResult.COMMITTED
    )
    assert not processes
    assert len(status_process.stdin.writes) == 1
    assert len(verify_process.stdin.writes) == 1
    verify_request = _decode_wire_request(verify_process.stdin.writes[0])
    assert verify_request["verb"] == "verify_absent"
    assert verify_request["expected_state_generation"] == generation + 1
    assert verify_request["payload"] == {"bundle_sha256": bundle_sha256}
    assert verify_request["operation_id"] not in {
        str(OPERATION_ID),
        str(status_operation_id),
    }
    mutating_process.returncode = 0
    await process.close()


@pytest.mark.asyncio
async def test_uncertain_mutation_requires_typed_status_payload_before_reconcile(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_state_with_status(repository, ReachyA05StateStatus.STAGED)
    generation = state.deployment.state_generation
    status_operation_id = ssh_forced_module.derive_status_reconciliation_operation_id(
        OPERATION_ID,
        DispatchVerb.ACTIVATE,
    )
    malformed_status_payload: dict[str, object] = {
        "boot_identity_sha256": "5" * 64,
        "capability_evidence_sha256": "6" * 64,
        "runtime_inventory_sha256": "4" * 64,
        "dispatcher_sha256": "7" * 64,
    }
    status_response = _status_response(
        operation_id=status_operation_id,
        status=ReachyA05StateStatus.ACTIVE,
        generation=generation + 1,
        payload=malformed_status_payload,
    )
    mutating_stdout = _BytesStdout()
    mutating_stdout.fail_once = True
    mutating_process = _FakeProcess(mutating_stdout)
    status_process = _FakeProcess(_BytesStdout(status_response))
    processes = [mutating_process, status_process]

    async def factory(*_argv: str, **_kwargs: object) -> _FakeProcess:
        return processes.pop(0)

    process = await SshForcedCommandProcess.spawn(
        repository,
        expectation=valid_expectation(state),
        process_factory=factory,
    )

    with pytest.raises(SshBridgeError) as error:
        await process.dispatch(
            DispatchVerb.ACTIVATE,
            operation_id=OPERATION_ID,
            expected_generation=generation,
            payload={"active_bundle_sha256": state.deployment.staged_bundle_sha256},
        )

    assert error.value.code is SshBridgeErrorCode.UNCERTAIN_DISPATCH
    assert error.value.reconciliation is not None
    assert (
        error.value.reconciliation.result
        is ssh_forced_module.SshDispatchReconciliationResult.INDETERMINATE
    )
    mutating_process.returncode = 0
    await process.close()


@pytest.mark.asyncio
async def test_uncertain_mutation_binds_status_to_exact_dispatcher_protocol_version(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_state_with_status(repository, ReachyA05StateStatus.STAGED)
    generation = state.deployment.state_generation
    status_operation_id = ssh_forced_module.derive_status_reconciliation_operation_id(
        OPERATION_ID,
        DispatchVerb.ACTIVATE,
    )
    status_payload = _status_payload_for(
        status=ReachyA05StateStatus.ACTIVE,
        generation=generation + 1,
        active_bundle_sha256=state.deployment.staged_bundle_sha256,
    )
    status_payload["dispatcher_protocol_version"] = "tuntun.reachy-a05-dispatcher.v0"
    status_response = _status_response(
        operation_id=status_operation_id,
        status=ReachyA05StateStatus.ACTIVE,
        generation=generation + 1,
        payload=status_payload,
    )
    mutating_stdout = _BytesStdout()
    mutating_stdout.fail_once = True
    mutating_process = _FakeProcess(mutating_stdout)
    status_process = _FakeProcess(_BytesStdout(status_response))
    processes = [mutating_process, status_process]

    async def factory(*_argv: str, **_kwargs: object) -> _FakeProcess:
        return processes.pop(0)

    process = await SshForcedCommandProcess.spawn(
        repository,
        expectation=valid_expectation(state),
        process_factory=factory,
    )

    with pytest.raises(SshBridgeError) as error:
        await process.dispatch(
            DispatchVerb.ACTIVATE,
            operation_id=OPERATION_ID,
            expected_generation=generation,
            payload={"active_bundle_sha256": state.deployment.staged_bundle_sha256},
        )

    assert error.value.code is SshBridgeErrorCode.UNCERTAIN_DISPATCH
    assert error.value.reconciliation is not None
    assert (
        error.value.reconciliation.result
        is ssh_forced_module.SshDispatchReconciliationResult.INDETERMINATE
    )
    mutating_process.returncode = 0
    await process.close()


@pytest.mark.asyncio
async def test_uncertain_run_ptt_status_reconciliation_never_resumes_stdio(
    tmp_path: Path,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_state_with_status(repository, ReachyA05StateStatus.ACTIVE)
    generation = state.deployment.state_generation
    status_operation_id = ssh_forced_module.derive_status_reconciliation_operation_id(
        OPERATION_ID,
        DispatchVerb.RUN_PTT,
    )
    status_response = _status_response(
        operation_id=status_operation_id,
        status=ReachyA05StateStatus.ACTIVE,
        generation=generation,
        active_bundle_sha256=state.deployment.active_bundle_sha256,
    )
    mutating_stdout = _BytesStdout()
    mutating_stdout.fail_once = True
    mutating_process = _FakeProcess(mutating_stdout)
    status_process = _FakeProcess(_BytesStdout(status_response))
    processes = [mutating_process, status_process]

    async def factory(*_argv: str, **_kwargs: object) -> _FakeProcess:
        return processes.pop(0)

    process = await SshForcedCommandProcess.spawn(
        repository,
        expectation=valid_expectation(state),
        process_factory=factory,
    )

    with pytest.raises(SshBridgeError) as error:
        await process.dispatch(
            DispatchVerb.RUN_PTT,
            operation_id=OPERATION_ID,
            expected_generation=generation,
            payload={"turn_id": str(TURN_ID), "input_mode": PttInputMode.REACHY_LOCAL.value},
        )

    assert error.value.code is SshBridgeErrorCode.UNCERTAIN_DISPATCH
    assert error.value.reconciliation is not None
    assert (
        error.value.reconciliation.result
        is ssh_forced_module.SshDispatchReconciliationResult.NOT_RESUMABLE
    )
    assert len(mutating_process.stdin.writes) == 1
    assert len(status_process.stdin.writes) == 1
    mutating_process.returncode = 0
    await process.close()


@pytest.mark.asyncio
async def test_loopback_contract_spawn_does_not_sleep_before_first_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = tmp_path / "identity"
    known_hosts = tmp_path / "known_hosts"
    _owner_write(identity, b"loopback identity\n")
    _owner_write(known_hosts, b"loopback known-hosts\n")
    target = SshLoopbackContractTarget(
        user="owner",
        port=2222,
        identity_file=identity,
        known_hosts_file=known_hosts,
        commissioning_id=COMMISSIONING_ID,
        state_generation=3,
        file_commitments={
            "identity_file_sha256": digest(identity.read_bytes()),
            "known_hosts_file_sha256": digest(known_hosts.read_bytes()),
        },
    )
    fake_process = _FakeProcess()

    async def factory(*_argv: str, **_kwargs: object) -> _FakeProcess:
        return fake_process

    async def sleep_is_not_startup_evidence(_delay: float) -> None:
        raise AssertionError("loopback startup must be proven by the first dispatch")

    monkeypatch.setattr(asyncio, "sleep", sleep_is_not_startup_evidence)

    process = await SshForcedCommandProcess.spawn_target_for_loopback_contract(
        target,
        process_factory=factory,
    )

    assert process.target.host == "127.0.0.1"
    fake_process.returncode = 0
    await process.close()


@pytest.mark.asyncio
async def test_stderr_drain_keeps_discarding_after_classifier_bound() -> None:
    stderr = _FloodingStderr(chunk_count=12)

    summary = await _drain_stderr(stderr)

    assert summary.classification == "truncated"
    assert summary.byte_count == 4096
    assert stderr.read_calls == 13


@pytest.mark.asyncio
async def test_close_escalates_validated_process_group_and_redacts_stderr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_state_with_status(repository, ReachyA05StateStatus.ACTIVE)
    fake_process = _FakeProcess()
    signals: list[int] = []

    async def factory(*_argv: str, **_kwargs: object) -> _FakeProcess:
        return fake_process

    monkeypatch.setattr(os, "getpgid", lambda pid: pid)

    def killpg(_pid: int, sig: int) -> None:
        signals.append(sig)
        if sig == signal.SIGKILL:
            fake_process.returncode = -sig

    monkeypatch.setattr(os, "killpg", killpg)

    process = await SshForcedCommandProcess.spawn(
        repository,
        expectation=valid_expectation(state),
        process_factory=factory,
    )
    await process.close()
    await process.close()

    assert fake_process.stdin.events[:2] == ["stdin.close", "stdin.wait_closed"]
    assert signals == [signal.SIGTERM, signal.SIGKILL]
    assert process.stderr_summary.classification == "present"
    assert "remote stderr" not in repr(process.stderr_summary)


@pytest.mark.asyncio
async def test_close_surfaces_failure_when_process_survives_sigkill(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = private_repository(tmp_path)
    state = publish_state_with_status(repository, ReachyA05StateStatus.ACTIVE)
    fake_process = _FakeProcess()
    signals: list[int] = []

    async def factory(*_argv: str, **_kwargs: object) -> _FakeProcess:
        return fake_process

    monkeypatch.setattr(os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(os, "killpg", lambda _pid, sig: signals.append(sig))

    process = await SshForcedCommandProcess.spawn(
        repository,
        expectation=valid_expectation(state),
        process_factory=factory,
    )

    with pytest.raises(SshBridgeError) as error:
        await process.close()

    assert error.value.code is SshBridgeErrorCode.PROCESS_FAILED
    assert signals == [signal.SIGTERM, signal.SIGKILL]
    assert process.stderr_summary.classification == "present"
