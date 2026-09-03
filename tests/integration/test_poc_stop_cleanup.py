from __future__ import annotations

import asyncio
import os
import signal
import sys
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import pytest
from tuntun_contracts.poc.framing import (
    ControlFrame,
    FrameDecoder,
    PttControl,
    PttErrorReason,
    PttInputMode,
    PttSafetyReceipt,
    PttSessionOutcome,
    encode_control_frame,
)
from tuntun_core.adapters.reachy.commissioning import (
    ReachyA05CommissioningRepository,
    ReachyA05CommissioningStateV1,
    ReachyA05StateStatus,
)
from tuntun_core.adapters.reachy.ssh_forced import (
    ProcessFactory,
    SshDispatcherResponse,
    SshForcedCommandProcess,
)
from tuntun_core.adapters.reachy.ssh_ptt import SshPttBridge

from tests.fixtures.reachy_a05_commissioning import (
    private_repository,
    publish_state_with_status,
    valid_expectation,
)

OPERATION_ID = UUID("71000000-0000-4000-8000-000000000001")
TURN_ID = UUID("72000000-0000-4000-8000-000000000001")


def _active_repository(
    tmp_path: Path,
) -> tuple[ReachyA05CommissioningRepository, ReachyA05CommissioningStateV1]:
    repository = private_repository(tmp_path)
    state = publish_state_with_status(repository, ReachyA05StateStatus.ACTIVE)
    return repository, state


class _FakeStdin:
    def __init__(self) -> None:
        self.writes: list[bytes] = []
        self.events: list[str] = []

    def write(self, data: bytes) -> None:
        self.events.append("write")
        self.writes.append(data)

    async def drain(self) -> None:
        self.events.append("drain")

    def close(self) -> None:
        self.events.append("stdin.close")

    async def wait_closed(self) -> None:
        self.events.append("stdin.wait_closed")


class _BytesStdout:
    def __init__(self, body: bytes) -> None:
        self.body = bytearray(body)

    async def readexactly(self, count: int) -> bytes:
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


class _FakeProcess:
    def __init__(self, stdout: bytes) -> None:
        self.stdin = _FakeStdin()
        self.stdout = _BytesStdout(stdout)
        self.stderr = _BytesStdout(b"cleanup stderr secret")
        self.pid = 99771
        self.returncode: int | None = None

    async def wait(self) -> int:
        if self.returncode is None:
            raise TimeoutError
        return self.returncode


def _ready_response(*, state_generation: int) -> bytes:
    return SshDispatcherResponse(
        version=1,
        operation_id=OPERATION_ID,
        ok=True,
        state_generation=state_generation,
        status="active",
        payload={"ready": True, "input_mode": PttInputMode.REACHY_LOCAL.value},
    ).to_wire_bytes()


def _receipt(*, complete: bool = True) -> bytes:
    return encode_control_frame(
        sequence=0,
        control=PttControl.safety_receipt(
            TURN_ID,
            PttSafetyReceipt(
                turn_id=TURN_ID,
                new_capture_rejected=True,
                recording_stopped=True,
                playback_stopped=True,
                motion_stopped=complete,
                audio_reactive_disabled=True,
                owned_buffers_cleared=True,
            ),
        ),
    )


def _decode_control(raw: bytes) -> ControlFrame:
    decoder = FrameDecoder()
    frames = decoder.feed(raw)
    decoder.finish()
    assert len(frames) == 1
    frame = frames[0]
    assert isinstance(frame, ControlFrame)
    return frame


@pytest.mark.asyncio
async def test_stop_cleanup_precedes_stdin_close_and_process_group_escalation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, state = _active_repository(tmp_path)
    generation = state.deployment.state_generation
    fake_process = _FakeProcess(_ready_response(state_generation=generation) + _receipt())
    signals: list[int] = []

    async def factory(*_argv: str, **_kwargs: object) -> _FakeProcess:
        return fake_process

    def killpg(_pid: int, sig: int) -> None:
        signals.append(sig)
        if sig == signal.SIGKILL:
            fake_process.returncode = -sig

    monkeypatch.setattr(os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(os, "killpg", killpg)
    bridge = await SshPttBridge.connect(
        repository,
        turn_id=TURN_ID,
        input_mode=PttInputMode.REACHY_LOCAL,
        operation_id=OPERATION_ID,
        expectation=valid_expectation(state),
        process_factory=factory,
    )

    await bridge.close(reason=PttErrorReason.TURN_CANCELLED)

    abort = _decode_control(fake_process.stdin.writes[1])
    ack = _decode_control(fake_process.stdin.writes[2])
    assert abort.control == PttControl.abort(TURN_ID, PttErrorReason.TURN_CANCELLED)
    assert ack.control == PttControl.safety_ack(TURN_ID, accepted=True)
    assert fake_process.stdin.events.index("stdin.close") > fake_process.stdin.events.index(
        "write",
        2,
    )
    assert signals == [signal.SIGTERM, signal.SIGKILL]
    assert bridge.final_outcome is PttSessionOutcome.CANCELLED


@pytest.mark.asyncio
async def test_missing_cleanup_receipt_fails_closed_without_stderr_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, state = _active_repository(tmp_path)
    generation = state.deployment.state_generation
    fake_process = _FakeProcess(_ready_response(state_generation=generation))

    async def factory(*_argv: str, **_kwargs: object) -> _FakeProcess:
        return fake_process

    def killpg(_pid: int, sig: int) -> None:
        if sig == signal.SIGKILL:
            fake_process.returncode = -sig

    monkeypatch.setattr(os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(os, "killpg", killpg)

    bridge = await SshPttBridge.connect(
        repository,
        turn_id=TURN_ID,
        input_mode=PttInputMode.REACHY_LOCAL,
        operation_id=OPERATION_ID,
        expectation=valid_expectation(state),
        process_factory=factory,
    )

    await bridge.close(reason=PttErrorReason.TURN_CANCELLED)

    assert bridge.final_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert "cleanup stderr secret" not in repr(bridge.stderr_summary)


@pytest.mark.asyncio
async def test_real_child_process_group_ignoring_sigterm_is_killed(
    tmp_path: Path,
) -> None:
    repository, state = _active_repository(tmp_path)

    async def factory(*_argv: str, **kwargs: Any) -> asyncio.subprocess.Process:
        return await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            (
                "import signal, time\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "time.sleep(60)\n"
            ),
            stdin=kwargs["stdin"],
            stdout=kwargs["stdout"],
            stderr=kwargs["stderr"],
            start_new_session=kwargs["start_new_session"],
            env=kwargs["env"],
        )

    process = await SshForcedCommandProcess.spawn(
        repository,
        expectation=valid_expectation(state),
        process_factory=cast(ProcessFactory, factory),
    )

    await process.close()

    assert process.returncode == -signal.SIGKILL
