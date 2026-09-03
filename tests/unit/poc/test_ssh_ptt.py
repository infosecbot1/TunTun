from __future__ import annotations

import asyncio
import os
import signal
from pathlib import Path
from uuid import UUID

import pytest
from tuntun_contracts.poc.framing import (
    PREFIX,
    ControlFrame,
    FrameDecoder,
    FrameKind,
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
    SshDispatcherResponse,
)
from tuntun_core.adapters.reachy.ssh_ptt import SshPttBridge, SshPttBridgeError

from tests.fixtures.reachy_a05_commissioning import (
    private_repository,
    publish_state_with_status,
    valid_expectation,
)

OPERATION_ID = UUID("51000000-0000-4000-8000-000000000001")
TURN_ID = UUID("52000000-0000-4000-8000-000000000001")


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


class _AckFailingStdin(_FakeStdin):
    def write(self, data: bytes) -> None:
        if b'"kind":"safety_ack"' in data:
            self.events.append("ack.write_failed")
            raise BrokenPipeError
        super().write(data)


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


class _CancelOnReadStdout(_BytesStdout):
    async def read(self, count: int = -1) -> bytes:
        if self.body:
            return await super().read(count)
        raise asyncio.CancelledError


class _FakeProcess:
    def __init__(self, stdout: bytes) -> None:
        self.stdin = _FakeStdin()
        self.stdout = _BytesStdout(stdout)
        self.stderr = _BytesStdout(b"edge secret stderr")
        self.pid = 99661
        self.returncode: int | None = None
        self.wait_calls = 0

    async def wait(self) -> int:
        self.wait_calls += 1
        if self.returncode is None:
            raise TimeoutError
        return self.returncode


class _AckFailingProcess(_FakeProcess):
    def __init__(self, stdout: bytes) -> None:
        super().__init__(stdout)
        self.stdin = _AckFailingStdin()


class _CancelOnReadProcess(_FakeProcess):
    def __init__(self, stdout: bytes) -> None:
        super().__init__(stdout)
        self.stdout = _CancelOnReadStdout(stdout)


def _exit_after_sigkill(
    monkeypatch: pytest.MonkeyPatch,
    fake_process: _FakeProcess,
    signals: list[int] | None = None,
) -> None:
    def killpg(_pid: int, sig: int) -> None:
        if signals is not None:
            signals.append(sig)
        if sig == signal.SIGKILL:
            fake_process.returncode = -sig

    monkeypatch.setattr(os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(os, "killpg", killpg)


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


def _complete_receipt() -> PttSafetyReceipt:
    return PttSafetyReceipt(
        turn_id=TURN_ID,
        new_capture_rejected=True,
        recording_stopped=True,
        playback_stopped=True,
        motion_stopped=True,
        audio_reactive_disabled=True,
        owned_buffers_cleared=True,
    )


def _decode_control_frame(raw: bytes) -> ControlFrame:
    decoder = FrameDecoder()
    frames = decoder.feed(raw)
    decoder.finish()
    assert len(frames) == 1
    frame = frames[0]
    assert isinstance(frame, ControlFrame)
    return frame


@pytest.mark.asyncio
async def test_ptt_bridge_sends_run_ptt_then_switches_stdio_to_wire_frames(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    edge_ready = encode_control_frame(
        sequence=0,
        control=PttControl.session_ready(TURN_ID, PttInputMode.REACHY_LOCAL),
    )
    repository, state = _active_repository(tmp_path)
    generation = state.deployment.state_generation
    fake_process = _FakeProcess(_ready_response(state_generation=generation) + edge_ready)

    async def factory(*_argv: str, **_kwargs: object) -> _FakeProcess:
        return fake_process

    bridge = await SshPttBridge.connect(
        repository,
        turn_id=TURN_ID,
        input_mode=PttInputMode.REACHY_LOCAL,
        operation_id=OPERATION_ID,
        expectation=valid_expectation(state),
        process_factory=factory,
    )
    session_open = encode_control_frame(
        sequence=0,
        control=PttControl.session_open(TURN_ID, PttInputMode.REACHY_LOCAL),
    )

    await bridge.send(session_open)
    received = await bridge.receive(65_536)

    assert b'"verb":"run_ptt"' in fake_process.stdin.writes[0]
    assert b'"operation_id":"51000000-0000-4000-8000-000000000001"' in fake_process.stdin.writes[0]
    assert fake_process.stdin.writes[1] == session_open
    assert received == edge_ready
    assert bridge.final_outcome is None
    _exit_after_sigkill(monkeypatch, fake_process)
    await bridge.close(reason=PttErrorReason.TURN_CANCELLED)


@pytest.mark.asyncio
async def test_ptt_bridge_rejects_malformed_frame_and_sends_protocol_abort_before_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bad_frame = PREFIX.pack(b"BAD!", 1, FrameKind.CONTROL, 0, 0, 1, TURN_ID.bytes) + b"x"
    repository, state = _active_repository(tmp_path)
    generation = state.deployment.state_generation
    fake_process = _FakeProcess(_ready_response(state_generation=generation) + bad_frame)

    async def factory(*_argv: str, **_kwargs: object) -> _FakeProcess:
        return fake_process

    bridge = await SshPttBridge.connect(
        repository,
        turn_id=TURN_ID,
        input_mode=PttInputMode.REACHY_LOCAL,
        operation_id=OPERATION_ID,
        expectation=valid_expectation(state),
        process_factory=factory,
    )
    _exit_after_sigkill(monkeypatch, fake_process)

    with pytest.raises(SshPttBridgeError):
        await bridge.receive(65_536)

    abort = _decode_control_frame(fake_process.stdin.writes[-1])
    assert abort.control == PttControl.abort(TURN_ID, PttErrorReason.PROTOCOL_REJECTED)
    assert "stdin.close" in fake_process.stdin.events
    assert "edge secret stderr" not in repr(bridge.stderr_summary)


@pytest.mark.asyncio
async def test_ptt_bridge_local_validation_error_fails_closed_and_tears_down(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, state = _active_repository(tmp_path)
    generation = state.deployment.state_generation
    fake_process = _FakeProcess(_ready_response(state_generation=generation))
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

    with pytest.raises(SshPttBridgeError):
        await bridge.receive(0)

    assert "stdin.close" in fake_process.stdin.events
    assert signals == [signal.SIGTERM, signal.SIGKILL]
    assert bridge.final_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE


@pytest.mark.asyncio
async def test_ptt_bridge_close_acknowledges_receipt_before_process_teardown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = encode_control_frame(
        sequence=0,
        control=PttControl.safety_receipt(TURN_ID, _complete_receipt()),
    )
    repository, state = _active_repository(tmp_path)
    generation = state.deployment.state_generation
    fake_process = _FakeProcess(_ready_response(state_generation=generation) + receipt)
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
    await bridge.close(reason=PttErrorReason.TURN_CANCELLED)

    abort = _decode_control_frame(fake_process.stdin.writes[1])
    ack = _decode_control_frame(fake_process.stdin.writes[2])
    close_index = fake_process.stdin.events.index("stdin.close")
    assert abort.control == PttControl.abort(TURN_ID, PttErrorReason.TURN_CANCELLED)
    assert ack.control == PttControl.safety_ack(TURN_ID, accepted=True)
    assert fake_process.stdin.events.index("write", 2) < close_index
    assert signals == [signal.SIGTERM, signal.SIGKILL]
    assert bridge.final_outcome is PttSessionOutcome.CANCELLED


@pytest.mark.asyncio
async def test_ptt_bridge_failed_safety_ack_is_cleanup_incomplete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = encode_control_frame(
        sequence=0,
        control=PttControl.safety_receipt(TURN_ID, _complete_receipt()),
    )
    repository, state = _active_repository(tmp_path)
    generation = state.deployment.state_generation
    fake_process = _AckFailingProcess(_ready_response(state_generation=generation) + receipt)

    async def factory(*_argv: str, **_kwargs: object) -> _AckFailingProcess:
        return fake_process

    _exit_after_sigkill(monkeypatch, fake_process)
    bridge = await SshPttBridge.connect(
        repository,
        turn_id=TURN_ID,
        input_mode=PttInputMode.REACHY_LOCAL,
        operation_id=OPERATION_ID,
        expectation=valid_expectation(state),
        process_factory=factory,
    )

    await bridge.close(reason=PttErrorReason.TURN_CANCELLED)

    assert "ack.write_failed" in fake_process.stdin.events
    assert bridge.final_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE


@pytest.mark.asyncio
async def test_ptt_bridge_cancelled_cleanup_closes_process_without_masking_cancellation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, state = _active_repository(tmp_path)
    generation = state.deployment.state_generation
    fake_process = _CancelOnReadProcess(_ready_response(state_generation=generation))
    signals: list[int] = []

    async def factory(*_argv: str, **_kwargs: object) -> _CancelOnReadProcess:
        return fake_process

    def killpg(_pid: int, sig: int) -> None:
        signals.append(sig)

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

    with pytest.raises(asyncio.CancelledError) as cancelled:
        await bridge.close(reason=PttErrorReason.TURN_CANCELLED)

    assert signals == [signal.SIGTERM, signal.SIGKILL]
    assert "stdin.close" in fake_process.stdin.events
    assert bridge.final_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert any("additional SSH process close failure" in note for note in cancelled.value.__notes__)


@pytest.mark.asyncio
async def test_ptt_bridge_close_failure_cannot_later_look_successful(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = encode_control_frame(
        sequence=0,
        control=PttControl.safety_receipt(TURN_ID, _complete_receipt()),
    )
    repository, state = _active_repository(tmp_path)
    generation = state.deployment.state_generation
    fake_process = _FakeProcess(_ready_response(state_generation=generation) + receipt)
    signals: list[int] = []

    async def factory(*_argv: str, **_kwargs: object) -> _FakeProcess:
        return fake_process

    monkeypatch.setattr(os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(os, "killpg", lambda _pid, sig: signals.append(sig))
    bridge = await SshPttBridge.connect(
        repository,
        turn_id=TURN_ID,
        input_mode=PttInputMode.REACHY_LOCAL,
        operation_id=OPERATION_ID,
        expectation=valid_expectation(state),
        process_factory=factory,
    )

    with pytest.raises(SshPttBridgeError):
        await bridge.close(reason=PttErrorReason.TURN_CANCELLED)
    await bridge.close(reason=PttErrorReason.TURN_CANCELLED)

    assert signals == [signal.SIGTERM, signal.SIGKILL]
    assert bridge.final_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE


@pytest.mark.asyncio
async def test_ptt_bridge_negative_or_missing_receipt_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incomplete = _complete_receipt().model_copy(update={"motion_stopped": False})
    receipt = encode_control_frame(
        sequence=0,
        control=PttControl.safety_receipt(TURN_ID, incomplete),
    )
    repository, state = _active_repository(tmp_path)
    generation = state.deployment.state_generation
    fake_process = _FakeProcess(_ready_response(state_generation=generation) + receipt)

    async def factory(*_argv: str, **_kwargs: object) -> _FakeProcess:
        return fake_process

    bridge = await SshPttBridge.connect(
        repository,
        turn_id=TURN_ID,
        input_mode=PttInputMode.REACHY_LOCAL,
        operation_id=OPERATION_ID,
        expectation=valid_expectation(state),
        process_factory=factory,
    )
    _exit_after_sigkill(monkeypatch, fake_process)
    await bridge.close(reason=PttErrorReason.TURN_CANCELLED)

    ack = _decode_control_frame(fake_process.stdin.writes[2])
    assert ack.control == PttControl.safety_ack(TURN_ID, accepted=False)
    assert bridge.final_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
