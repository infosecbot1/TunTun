from __future__ import annotations

import asyncio
import gc
import subprocess
import sys
import time
from collections import Counter, deque
from collections.abc import Coroutine
from dataclasses import dataclass
from typing import Any, Literal
from uuid import UUID

import pytest
from tuntun_contracts.poc.framing import (
    MAX_FEED_BYTES,
    TRANSPORT_AUDIO_FORMAT,
    ControlFrame,
    ControlKind,
    FrameDecoder,
    PcmFrame,
    PttControl,
    PttInputMode,
    PttSafetyReceipt,
    PttSessionOutcome,
    encode_control_frame,
    encode_pcm_frame,
)
from tuntun_core.adapters.poc.fake_voice import FakeVoiceScript, fake_voice_pipeline
from tuntun_core.services.poc import session_supervisor as supervisor_module
from tuntun_core.services.poc.ports import CorePttEvent
from tuntun_core.services.poc.session_supervisor import CorePttSessionSupervisor
from tuntun_edge.poc.reachy_ptt import ReachyPttSession

TURN_ID = UUID("81000000-0000-4000-8000-000000000001")


def _committed_send_result() -> object | None:
    try:
        from tuntun_core.services.poc.ports import PttSendCommit
    except ImportError:
        return None
    return PttSendCommit.COMMITTED


class _Endpoint:
    def __init__(self) -> None:
        self.inbound: asyncio.Queue[bytes] = asyncio.Queue(maxsize=2)
        self.peer: _Endpoint | None = None
        self.closed = False
        self.close_calls = 0
        self.sent_frames: list[ControlFrame | PcmFrame] = []
        self.decoder = FrameDecoder()
        self.fragment_writes = False
        self.fail_on_playback_pcm = False

    async def receive(self, max_bytes: int) -> bytes:
        data = await self.inbound.get()
        assert len(data) <= max_bytes
        return data

    async def send(self, frame: bytes, *, priority: bool = False) -> object | None:
        del priority
        for decoded in self.decoder.feed(frame):
            self.sent_frames.append(decoded)
            if self.fail_on_playback_pcm and isinstance(decoded, PcmFrame):
                raise OSError("injected playback transport failure")
        peer = self.peer
        assert peer is not None
        if self.fragment_writes and len(frame) > 2:
            await peer.inbound.put(frame[:2])
            await peer.inbound.put(frame[2:])
            return _committed_send_result()
        await peer.inbound.put(frame)
        return _committed_send_result()

    async def close(self) -> None:
        self.close_calls += 1
        self.closed = True
        peer = self.peer
        assert peer is not None
        await peer.inbound.put(b"")


def _complete_safety_receipt() -> PttSafetyReceipt:
    return PttSafetyReceipt(
        turn_id=TURN_ID,
        new_capture_rejected=True,
        recording_stopped=True,
        playback_stopped=True,
        motion_stopped=True,
        audio_reactive_disabled=True,
        owned_buffers_cleared=True,
    )


class _BlockingReceiveBridge:
    def __init__(self, initial_frames: tuple[bytes, ...] = ()) -> None:
        self.decoder = FrameDecoder()
        self.sent_frames: list[ControlFrame | PcmFrame] = []
        self.closed = False
        self._inbound = deque(initial_frames)

    async def receive(self, max_bytes: int) -> bytes:
        assert max_bytes == MAX_FEED_BYTES
        if self._inbound:
            return self._inbound.popleft()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async def send(self, frame: bytes, *, priority: bool = False) -> object | None:
        del priority
        self.sent_frames.extend(self.decoder.feed(frame))
        return _committed_send_result()

    async def close(self) -> None:
        self.closed = True


class _SilentAfterPlaybackTransportFailureBridge:
    def __init__(self) -> None:
        self.decoder = FrameDecoder()
        self.sent_frames: list[ControlFrame | PcmFrame] = []
        self.closed = False
        self._edge_sequence = 0
        self._inbound: asyncio.Queue[bytes] = asyncio.Queue()
        self._inbound.put_nowait(
            encode_control_frame(
                sequence=self._next_edge_sequence(),
                control=PttControl.session_ready(TURN_ID, PttInputMode.CORE_TERMINAL_TOGGLE),
            )
        )

    def _next_edge_sequence(self) -> int:
        sequence = self._edge_sequence
        self._edge_sequence += 1
        return sequence

    async def receive(self, max_bytes: int) -> bytes:
        assert max_bytes == MAX_FEED_BYTES
        return await self._inbound.get()

    async def send(self, frame: bytes, *, priority: bool = False) -> object | None:
        del priority
        decoded_frames = self.decoder.feed(frame)
        self.sent_frames.extend(decoded_frames)
        for decoded in decoded_frames:
            if not isinstance(decoded, ControlFrame):
                continue
            if decoded.control.kind is ControlKind.PTT_START:
                self._inbound.put_nowait(
                    encode_control_frame(
                        sequence=self._next_edge_sequence(),
                        control=PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT),
                    )
                )
                self._inbound.put_nowait(
                    encode_pcm_frame(
                        turn_id=TURN_ID,
                        sequence=self._next_edge_sequence(),
                        pcm=FakeVoiceScript().capture_pcm,
                    )
                )
            elif decoded.control.kind is ControlKind.PTT_SUBMIT:
                self._inbound.put_nowait(
                    encode_control_frame(
                        sequence=self._next_edge_sequence(),
                        control=PttControl.capture_end(TURN_ID),
                    )
                )
        if any(isinstance(decoded, PcmFrame) for decoded in decoded_frames):
            raise OSError("injected playback transport failure")
        return _committed_send_result()

    async def close(self) -> None:
        self.closed = True


class _StopDuringProviderBridge:
    def __init__(self) -> None:
        self.decoder = FrameDecoder()
        self.sent_frames: list[ControlFrame | PcmFrame] = []
        self.closed = False
        self._edge_sequence = 0
        self._inbound: asyncio.Queue[bytes] = asyncio.Queue()
        self._inbound.put_nowait(
            encode_control_frame(
                sequence=self._next_edge_sequence(),
                control=PttControl.session_ready(TURN_ID, PttInputMode.CORE_TERMINAL_TOGGLE),
            )
        )

    def _next_edge_sequence(self) -> int:
        sequence = self._edge_sequence
        self._edge_sequence += 1
        return sequence

    def queue_stop_and_receipt(self) -> None:
        self._inbound.put_nowait(
            encode_control_frame(
                sequence=self._next_edge_sequence(),
                control=PttControl.stop(TURN_ID),
            )
        )
        self._inbound.put_nowait(
            encode_control_frame(
                sequence=self._next_edge_sequence(),
                control=PttControl.safety_receipt(TURN_ID, _complete_safety_receipt()),
            )
        )

    async def receive(self, max_bytes: int) -> bytes:
        assert max_bytes == MAX_FEED_BYTES
        return await self._inbound.get()

    async def send(self, frame: bytes, *, priority: bool = False) -> object | None:
        del priority
        decoded_frames = self.decoder.feed(frame)
        self.sent_frames.extend(decoded_frames)
        for decoded in decoded_frames:
            if not isinstance(decoded, ControlFrame):
                continue
            if decoded.control.kind is ControlKind.PTT_START:
                self._inbound.put_nowait(
                    encode_control_frame(
                        sequence=self._next_edge_sequence(),
                        control=PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT),
                    )
                )
                self._inbound.put_nowait(
                    encode_pcm_frame(
                        turn_id=TURN_ID,
                        sequence=self._next_edge_sequence(),
                        pcm=FakeVoiceScript().capture_pcm,
                    )
                )
            elif decoded.control.kind is ControlKind.PTT_SUBMIT:
                self._inbound.put_nowait(
                    encode_control_frame(
                        sequence=self._next_edge_sequence(),
                        control=PttControl.capture_end(TURN_ID),
                    )
                )
        return _committed_send_result()

    async def close(self) -> None:
        self.closed = True


class _CaptureEndRaceBridge:
    def __init__(self, submit_gate: asyncio.Event) -> None:
        self.decoder = FrameDecoder()
        self.sent_frames: list[ControlFrame | PcmFrame] = []
        self.closed = False
        self._submit_gate = submit_gate
        self._edge_sequence = 0
        self._inbound: asyncio.Queue[bytes] = asyncio.Queue()
        self._inbound.put_nowait(
            encode_control_frame(
                sequence=self._next_edge_sequence(),
                control=PttControl.session_ready(TURN_ID, PttInputMode.CORE_TERMINAL_TOGGLE),
            )
        )

    def _next_edge_sequence(self) -> int:
        sequence = self._edge_sequence
        self._edge_sequence += 1
        return sequence

    async def receive(self, max_bytes: int) -> bytes:
        assert max_bytes == MAX_FEED_BYTES
        return await self._inbound.get()

    async def send(self, frame: bytes, *, priority: bool = False) -> object | None:
        del priority
        decoded_frames = self.decoder.feed(frame)
        self.sent_frames.extend(decoded_frames)
        for decoded in decoded_frames:
            if not isinstance(decoded, ControlFrame):
                continue
            if decoded.control.kind is ControlKind.PTT_START:
                self._inbound.put_nowait(
                    encode_control_frame(
                        sequence=self._next_edge_sequence(),
                        control=PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT),
                    )
                )
                self._inbound.put_nowait(
                    encode_pcm_frame(
                        turn_id=TURN_ID,
                        sequence=self._next_edge_sequence(),
                        pcm=FakeVoiceScript().capture_pcm,
                    )
                )
                self._submit_gate.set()
            elif decoded.control.kind is ControlKind.PTT_SUBMIT:
                self._inbound.put_nowait(
                    encode_control_frame(
                        sequence=self._next_edge_sequence(),
                        control=PttControl.capture_end(TURN_ID),
                    )
                )
            elif decoded.control.kind is ControlKind.PLAYBACK_END:
                self._inbound.put_nowait(
                    encode_control_frame(
                        sequence=self._next_edge_sequence(),
                        control=PttControl.safety_receipt(TURN_ID, _complete_safety_receipt()),
                    )
                )
        return _committed_send_result()

    async def close(self) -> None:
        self.closed = True


class _CancelSensitiveCaptureBridge:
    def __init__(self) -> None:
        self.decoder = FrameDecoder()
        self.sent_frames: list[ControlFrame | PcmFrame] = []
        self.closed = False
        self.receive_started = asyncio.Event()
        self.release_receive = asyncio.Event()
        self.cancelled_receive = False
        self._receive_count = 0
        self._tail: asyncio.Queue[bytes] = asyncio.Queue()
        self._tail.put_nowait(
            encode_pcm_frame(turn_id=TURN_ID, sequence=2, pcm=FakeVoiceScript().capture_pcm)
        )
        self._tail.put_nowait(
            encode_control_frame(sequence=3, control=PttControl.capture_end(TURN_ID))
        )

    async def receive(self, max_bytes: int) -> bytes:
        assert max_bytes == MAX_FEED_BYTES
        self._receive_count += 1
        if self._receive_count == 1:
            return encode_control_frame(
                sequence=0,
                control=PttControl.session_ready(TURN_ID, PttInputMode.CORE_TERMINAL_TOGGLE),
            )
        if self._receive_count == 2:
            self.receive_started.set()
            try:
                await self.release_receive.wait()
            except asyncio.CancelledError:
                self.cancelled_receive = True
                raise
            return encode_control_frame(
                sequence=1,
                control=PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT),
            )
        return await self._tail.get()

    async def send(self, frame: bytes, *, priority: bool = False) -> object | None:
        del priority
        decoded_frames = self.decoder.feed(frame)
        self.sent_frames.extend(decoded_frames)
        for decoded in decoded_frames:
            if not isinstance(decoded, ControlFrame):
                continue
            if decoded.control.kind is ControlKind.PTT_SUBMIT:
                self.release_receive.set()
            elif decoded.control.kind is ControlKind.PLAYBACK_END:
                self._tail.put_nowait(
                    encode_control_frame(
                        sequence=4,
                        control=PttControl.safety_receipt(TURN_ID, _complete_safety_receipt()),
                    )
                )
        return _committed_send_result()

    async def close(self) -> None:
        self.closed = True


class _ImmediateCancelAndFrameErrorBridge:
    def __init__(self) -> None:
        self.decoder = FrameDecoder()
        self.sent_frames: list[ControlFrame | PcmFrame] = []
        self.closed = False
        self._error_gate = asyncio.Event()
        self._inbound = deque(
            (
                encode_control_frame(
                    sequence=0,
                    control=PttControl.session_ready(TURN_ID, PttInputMode.CORE_TERMINAL_TOGGLE),
                ),
            )
        )

    async def receive(self, max_bytes: int) -> bytes:
        assert max_bytes == MAX_FEED_BYTES
        if self._inbound:
            return self._inbound.popleft()
        await self._error_gate.wait()
        raise OSError("injected simultaneous frame failure")

    async def send(self, frame: bytes, *, priority: bool = False) -> object | None:
        del priority
        decoded_frames = self.decoder.feed(frame)
        self.sent_frames.extend(decoded_frames)
        for decoded in decoded_frames:
            if not isinstance(decoded, ControlFrame):
                continue
            if decoded.control.kind is ControlKind.PTT_START:
                self._error_gate.set()
            elif decoded.control.kind is ControlKind.ABORT:
                self._inbound.append(
                    encode_control_frame(
                        sequence=1,
                        control=PttControl.safety_receipt(TURN_ID, _complete_safety_receipt()),
                    )
                )
        return _committed_send_result()

    async def close(self) -> None:
        self.closed = True


def _duplex(
    *, fragment_core: bool = False, fragment_edge: bool = False
) -> tuple[_Endpoint, _Endpoint]:
    core = _Endpoint()
    edge = _Endpoint()
    core.peer = edge
    edge.peer = core
    core.fragment_writes = fragment_core
    edge.fragment_writes = fragment_edge
    return core, edge


class _Input:
    def __init__(self, events: list[CorePttEvent]) -> None:
        self._events = deque(events)
        self.closed = False

    async def receive(self) -> CorePttEvent:
        while not self._events:
            await asyncio.sleep(0)
        return self._events.popleft()

    async def close(self) -> None:
        self.closed = True


class _SubmitOnGateInput:
    def __init__(self, gate: asyncio.Event) -> None:
        self._gate = gate
        self._started = False
        self._submitted = False
        self.closed = False

    async def receive(self) -> CorePttEvent:
        if not self._started:
            self._started = True
            return CorePttEvent.START
        if self._submitted:
            await asyncio.Event().wait()
            raise AssertionError("unreachable")
        await self._gate.wait()
        self._submitted = True
        return CorePttEvent.SUBMIT

    async def close(self) -> None:
        self.closed = True


class _SpuriousEventDuringReceiveInput:
    def __init__(self, bridge: _CancelSensitiveCaptureBridge) -> None:
        self._bridge = bridge
        self._calls = 0
        self.closed = False

    async def receive(self) -> CorePttEvent:
        self._calls += 1
        if self._calls == 1:
            return CorePttEvent.START
        if self._calls == 2:
            await self._bridge.receive_started.wait()
            return CorePttEvent.SUBMIT
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async def close(self) -> None:
        self.closed = True


class _NeverStop:
    async def wait_for_stop(self) -> None:
        await asyncio.Event().wait()


class _CaptureInput:
    def __init__(self) -> None:
        self.starts = 0
        self.submits = 0

    async def wait_for_start(self) -> None:
        self.starts += 1

    async def wait_for_submit(self) -> None:
        self.submits += 1


class _Clock:
    def now(self) -> float:
        return asyncio.get_running_loop().time()

    async def sleep_until(self, deadline: float) -> None:
        await asyncio.sleep(max(0.0, deadline - self.now()))


class _Spawner:
    def start(
        self,
        operation: Coroutine[Any, Any, bool],
        *,
        name: str,
    ) -> asyncio.Task[bool]:
        return asyncio.create_task(operation, name=name)


class _Buffer:
    def __init__(self) -> None:
        self.data = bytearray()
        self.clear_calls = 0

    def append(self, data: bytes) -> None:
        self.data.extend(data)

    def take(self, max_bytes: int) -> bytes:
        result = bytes(self.data[:max_bytes])
        del self.data[:max_bytes]
        return result

    def clear(self) -> bool:
        self.clear_calls += 1
        self.data.clear()
        return True

    def is_empty(self) -> bool:
        return not self.data


class _Media:
    def __init__(
        self,
        capture: tuple[bytes, ...],
        events: list[str],
        *,
        fail_playback_write: bool = False,
    ) -> None:
        self.capture = deque(capture)
        self.events = events
        self.playback: list[bytes] = []
        self.fail_playback_write = fail_playback_write

    async def open_capture(self, *, output_format: object, max_frame_bytes: int) -> None:
        assert output_format == TRANSPORT_AUDIO_FORMAT
        assert max_frame_bytes == 6_400
        self.events.append("capture")

    async def read_capture(self) -> bytes | None:
        if self.capture:
            return self.capture.popleft()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async def close_capture(self) -> bool:
        return True

    async def open_playback(self, *, input_format: object) -> None:
        assert input_format == TRANSPORT_AUDIO_FORMAT
        self.events.append("playback")

    async def write_playback(self, pcm: bytes) -> None:
        if self.fail_playback_write:
            raise OSError("injected playback media failure")
        self.playback.append(pcm)

    async def close_playback(self) -> bool:
        return True

    async def stop_recording(self) -> bool:
        return True

    async def stop_playback(self) -> bool:
        return True

    async def stop_motion(self) -> bool:
        return True

    async def disable_audio_reactive(self) -> bool:
        return True


@dataclass(slots=True)
class _RunResult:
    core_outcome: PttSessionOutcome
    edge_outcome: PttSessionOutcome
    core_bridge: _Endpoint
    edge_bridge: _Endpoint
    media: _Media
    input_port: _Input | None
    fake_events: list[str]


def _controls(frames: list[ControlFrame | PcmFrame]) -> Counter[str]:
    return Counter(frame.control.kind.value for frame in frames if isinstance(frame, ControlFrame))


async def _run_direct_turn(
    *,
    mode: PttInputMode,
    language: Literal["en", "hi", "hinglish"] = "en",
    input_events: list[CorePttEvent] | None = None,
    fragment_core: bool = False,
    fragment_edge: bool = False,
    fail_stage: str | None = None,
    fail_playback_send: bool = False,
    fail_playback_write: bool = False,
) -> _RunResult:
    core_bridge, edge_bridge = _duplex(fragment_core=fragment_core, fragment_edge=fragment_edge)
    core_bridge.fail_on_playback_pcm = fail_playback_send
    media_events: list[str] = []
    fake_events: list[str] = []
    script = FakeVoiceScript(
        utterance=f"private sentinel {language}",
        language=language,
        response=f"reply sentinel {language}",
        capture_pcm=b"\x01\x00\x02\x00\x03\x00\x04\x00",
        fail_stage=fail_stage,
    )
    pipeline, cancellation = fake_voice_pipeline(script, events=fake_events)
    input_port = (
        _Input(
            input_events if input_events is not None else [CorePttEvent.START, CorePttEvent.SUBMIT]
        )
        if mode is PttInputMode.CORE_TERMINAL_TOGGLE
        else None
    )
    edge_capture = _CaptureInput() if mode is PttInputMode.REACHY_LOCAL else None
    capture_chunks = (
        (b"\x01",) if fail_stage == "capture" else (b"\x01\x00\x02\x00", b"\x03\x00\x04\x00")
    )
    media = _Media(
        capture_chunks,
        media_events,
        fail_playback_write=fail_playback_write,
    )
    edge = ReachyPttSession(
        turn_id=TURN_ID,
        input_mode=mode,
        media=media,
        transport=edge_bridge,
        capture_input=edge_capture,
        stop_input=_NeverStop() if mode is PttInputMode.REACHY_LOCAL else None,
        capture_buffer=_Buffer(),
        playback_buffer=_Buffer(),
        clock=_Clock(),
        task_spawner=_Spawner(),
    )
    core = CorePttSessionSupervisor(
        input_mode=mode,
        bridge=core_bridge,
        pipeline=pipeline,
        provider_cancellation=cancellation,
        input_port=input_port,
        clock=pipeline.clock,
    )

    core_task = asyncio.create_task(core.run(TURN_ID))
    edge_task = asyncio.create_task(edge.run())
    core_outcome, edge_outcome = await asyncio.gather(core_task, edge_task)
    return _RunResult(
        core_outcome=core_outcome,
        edge_outcome=edge_outcome,
        core_bridge=core_bridge,
        edge_bridge=edge_bridge,
        media=edge._media,  # type: ignore[attr-defined]
        input_port=input_port,
        fake_events=fake_events,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", tuple(PttInputMode))
async def test_direct_core_edge_loop_completes_for_terminal_and_reachy_local_modes(
    mode: PttInputMode,
) -> None:
    result = await _run_direct_turn(
        mode=mode,
        fragment_core=True,
        fragment_edge=True,
        input_events=[CorePttEvent.START, CorePttEvent.SUBMIT],
    )

    assert result.core_outcome is PttSessionOutcome.COMPLETED
    assert result.edge_outcome is PttSessionOutcome.COMPLETED
    core_controls = _controls(result.core_bridge.sent_frames)
    edge_controls = _controls(result.edge_bridge.sent_frames)
    assert core_controls["session_open"] == 1
    assert edge_controls["session_ready"] == 1
    assert edge_controls["capture_start"] == 1
    assert edge_controls["capture_end"] == 1
    assert core_controls["playback_start"] == 1
    assert core_controls["playback_end"] == 1
    assert edge_controls["safety_receipt"] == 1
    assert core_controls["safety_ack"] == 1
    if mode is PttInputMode.CORE_TERMINAL_TOGGLE:
        assert core_controls["ptt_start"] == 1
        assert core_controls["ptt_submit"] == 1
        assert result.input_port is not None and result.input_port.closed


@pytest.mark.asyncio
async def test_direct_loop_latches_rapid_submit_while_edge_is_still_arming() -> None:
    result = await _run_direct_turn(
        mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        input_events=[CorePttEvent.START, CorePttEvent.SUBMIT],
    )

    sent = [
        frame.control.kind
        for frame in result.core_bridge.sent_frames
        if isinstance(frame, ControlFrame)
    ]
    assert sent.index(ControlKind.PTT_SUBMIT) < sent.index(ControlKind.PLAYBACK_START)
    assert result.core_outcome is PttSessionOutcome.COMPLETED


@pytest.mark.asyncio
async def test_direct_loop_rejects_both_or_neither_capture_owner() -> None:
    pipeline, cancellation = fake_voice_pipeline(FakeVoiceScript())

    with pytest.raises(ValueError, match="invalid-core-ptt-supervisor"):
        CorePttSessionSupervisor(
            input_mode=PttInputMode.CORE_TERMINAL_TOGGLE,
            bridge=_duplex()[0],
            pipeline=pipeline,
            provider_cancellation=cancellation,
            input_port=None,
            clock=pipeline.clock,
        )
    with pytest.raises(ValueError, match="invalid-core-ptt-supervisor"):
        CorePttSessionSupervisor(
            input_mode=PttInputMode.REACHY_LOCAL,
            bridge=_duplex()[0],
            pipeline=pipeline,
            provider_cancellation=cancellation,
            input_port=_Input([CorePttEvent.START]),
            clock=pipeline.clock,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("fail_stage", "outcome"),
    [
        ("capture", PttSessionOutcome.CAPTURE_FAILED),
        ("stt", PttSessionOutcome.PROVIDER_FAILED),
        ("llm", PttSessionOutcome.PROVIDER_FAILED),
        ("tts", PttSessionOutcome.PROVIDER_FAILED),
        ("conversion", PttSessionOutcome.PROVIDER_FAILED),
        ("playback", PttSessionOutcome.PLAYBACK_FAILED),
    ],
)
async def test_faults_fail_closed_and_cleanup_owned_tasks(
    fail_stage: str,
    outcome: PttSessionOutcome,
) -> None:
    result = await _run_direct_turn(
        mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        fail_stage=None if fail_stage == "playback" else fail_stage,
        fail_playback_write=fail_stage == "playback",
    )

    assert result.core_outcome is outcome
    assert result.edge_outcome is outcome
    assert result.core_bridge.closed
    assert result.input_port is not None and result.input_port.closed
    if fail_stage in {"stt", "llm", "tts", "conversion"}:
        assert "provider.cancel" in result.fake_events


@pytest.mark.asyncio
async def test_edge_stop_during_provider_cancels_before_playback_or_provider_release() -> None:
    bridge = _StopDuringProviderBridge()
    fake_events: list[str] = []
    pipeline, cancellation = fake_voice_pipeline(FakeVoiceScript(), events=fake_events)
    provider_entered = asyncio.Event()
    release_provider = asyncio.Event()
    original_complete = cancellation.complete

    async def blocking_complete(request: object) -> object:
        fake_events.append("llm.blocked")
        provider_entered.set()
        try:
            await release_provider.wait()
        except asyncio.CancelledError:
            fake_events.append("llm.cancelled")
            raise
        return await original_complete(request)  # type: ignore[arg-type]

    cancellation.complete = blocking_complete  # type: ignore[method-assign]
    input_port = _Input([CorePttEvent.START, CorePttEvent.SUBMIT])
    core = CorePttSessionSupervisor(
        input_mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        bridge=bridge,
        pipeline=pipeline,
        provider_cancellation=cancellation,
        input_port=input_port,
        clock=pipeline.clock,
    )
    core_task = asyncio.create_task(core.run(TURN_ID))
    try:
        await asyncio.wait_for(provider_entered.wait(), timeout=0.3)
        bridge.queue_stop_and_receipt()
        done, _pending = await asyncio.wait({core_task}, timeout=0.25)
        assert core_task in done
        assert core_task.result() is PttSessionOutcome.CANCELLED
        sent_kinds = [
            frame.control.kind for frame in bridge.sent_frames if isinstance(frame, ControlFrame)
        ]
        assert ControlKind.PLAYBACK_START not in sent_kinds
        assert all(not isinstance(frame, PcmFrame) for frame in bridge.sent_frames)
        assert "provider.cancel" in fake_events
        assert "tts" not in fake_events
    finally:
        release_provider.set()
        if not core_task.done():
            await asyncio.wait_for(core_task, timeout=0.4)


@pytest.mark.asyncio
async def test_playback_transport_failure_receipt_wait_is_bounded() -> None:
    bridge = _SilentAfterPlaybackTransportFailureBridge()
    pipeline, cancellation = fake_voice_pipeline(FakeVoiceScript())
    input_port = _Input([CorePttEvent.START, CorePttEvent.SUBMIT])
    core = CorePttSessionSupervisor(
        input_mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        bridge=bridge,
        pipeline=pipeline,
        provider_cancellation=cancellation,
        input_port=input_port,
        clock=pipeline.clock,
    )

    outcome = await asyncio.wait_for(core.run(TURN_ID), timeout=0.4)

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert bridge.closed
    assert input_port.closed
    sent_controls = [
        frame.control.kind for frame in bridge.sent_frames if isinstance(frame, ControlFrame)
    ]
    assert ControlKind.ABORT not in sent_controls
    assert ControlKind.PLAYBACK_START in sent_controls


@pytest.mark.asyncio
async def test_terminal_submit_and_capture_end_finished_together_preserves_frame() -> None:
    submit_gate = asyncio.Event()
    bridge = _CaptureEndRaceBridge(submit_gate)
    pipeline, cancellation = fake_voice_pipeline(FakeVoiceScript())
    input_port = _SubmitOnGateInput(submit_gate)
    core = CorePttSessionSupervisor(
        input_mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        bridge=bridge,
        pipeline=pipeline,
        provider_cancellation=cancellation,
        input_port=input_port,
        clock=pipeline.clock,
    )

    outcome = await asyncio.wait_for(core.run(TURN_ID), timeout=0.4)

    assert outcome is PttSessionOutcome.COMPLETED
    assert bridge.closed
    sent_controls = [
        frame.control.kind for frame in bridge.sent_frames if isinstance(frame, ControlFrame)
    ]
    assert sent_controls.count(ControlKind.PTT_SUBMIT) == 1
    assert sent_controls.count(ControlKind.PLAYBACK_END) == 1


@pytest.mark.asyncio
async def test_terminal_event_does_not_cancel_pending_transport_receive() -> None:
    bridge = _CancelSensitiveCaptureBridge()
    pipeline, cancellation = fake_voice_pipeline(FakeVoiceScript())
    input_port = _SpuriousEventDuringReceiveInput(bridge)
    core = CorePttSessionSupervisor(
        input_mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        bridge=bridge,
        pipeline=pipeline,
        provider_cancellation=cancellation,
        input_port=input_port,
        clock=pipeline.clock,
    )

    outcome = await asyncio.wait_for(core.run(TURN_ID), timeout=0.4)

    assert outcome is PttSessionOutcome.COMPLETED
    assert bridge.closed
    assert input_port.closed
    assert not bridge.cancelled_receive


@pytest.mark.asyncio
async def test_terminal_cancel_consumes_simultaneous_frame_error_before_return() -> None:
    bridge = _ImmediateCancelAndFrameErrorBridge()
    pipeline, cancellation = fake_voice_pipeline(FakeVoiceScript())
    input_port = _Input([CorePttEvent.START, CorePttEvent.CANCEL])
    core = CorePttSessionSupervisor(
        input_mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        bridge=bridge,
        pipeline=pipeline,
        provider_cancellation=cancellation,
        input_port=input_port,
        clock=pipeline.clock,
    )
    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()
    contexts: list[object] = []

    def capture_unhandled_task(
        _loop: asyncio.AbstractEventLoop,
        context: dict[str, object],
    ) -> None:
        if context.get("message") == "Task exception was never retrieved":
            contexts.append(context)

    loop.set_exception_handler(capture_unhandled_task)
    try:
        outcome = await asyncio.wait_for(core.run(TURN_ID), timeout=0.4)
        await asyncio.sleep(0)
        gc.collect()
        await asyncio.sleep(0)
    finally:
        loop.set_exception_handler(previous_handler)

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert bridge.closed
    assert contexts == []


@pytest.mark.asyncio
async def test_handshake_wait_has_hard_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(supervisor_module, "_HANDSHAKE_SECONDS", 0.05)
    monkeypatch.setattr(supervisor_module, "_PROVIDER_CLOSE_SECONDS", 0.01)
    monkeypatch.setattr(supervisor_module, "_PROVIDER_JOIN_SECONDS", 0.02)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_ACK_SECONDS", 0.05)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_TOTAL_SECONDS", 0.08)
    monkeypatch.setattr(supervisor_module, "_BRIDGE_CLOSE_SECONDS", 0.08)
    bridge = _BlockingReceiveBridge()
    pipeline, cancellation = fake_voice_pipeline(FakeVoiceScript())
    input_port = _Input([CorePttEvent.START])
    core = CorePttSessionSupervisor(
        input_mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        bridge=bridge,
        pipeline=pipeline,
        provider_cancellation=cancellation,
        input_port=input_port,
        clock=pipeline.clock,
    )

    outcome = await asyncio.wait_for(core.run(TURN_ID), timeout=0.4)

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert bridge.closed
    assert any(
        isinstance(frame, ControlFrame) and frame.control.kind is ControlKind.ABORT
        for frame in bridge.sent_frames
    )


@pytest.mark.asyncio
async def test_capture_wait_has_hard_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(supervisor_module, "_CAPTURE_TRANSITION_SECONDS", 0.05)
    monkeypatch.setattr(supervisor_module, "_PROVIDER_CLOSE_SECONDS", 0.01)
    monkeypatch.setattr(supervisor_module, "_PROVIDER_JOIN_SECONDS", 0.02)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_ACK_SECONDS", 0.05)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_TOTAL_SECONDS", 0.08)
    monkeypatch.setattr(supervisor_module, "_BRIDGE_CLOSE_SECONDS", 0.08)
    bridge = _BlockingReceiveBridge(
        (
            encode_control_frame(
                sequence=0,
                control=PttControl.session_ready(TURN_ID, PttInputMode.CORE_TERMINAL_TOGGLE),
            ),
        )
    )
    pipeline, cancellation = fake_voice_pipeline(FakeVoiceScript())
    input_port = _Input([CorePttEvent.START])
    core = CorePttSessionSupervisor(
        input_mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        bridge=bridge,
        pipeline=pipeline,
        provider_cancellation=cancellation,
        input_port=input_port,
        clock=pipeline.clock,
    )

    outcome = await asyncio.wait_for(core.run(TURN_ID), timeout=0.4)

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert bridge.closed
    assert any(
        isinstance(frame, ControlFrame) and frame.control.kind is ControlKind.ABORT
        for frame in bridge.sent_frames
    )


@pytest.mark.asyncio
async def test_fifty_turn_bilingual_hinglish_scenario_reconnects_only_between_turns() -> None:
    languages: tuple[Literal["en", "hi", "hinglish"], ...] = ("en", "hi", "hinglish")
    aggregate_core = Counter[str]()
    aggregate_edge = Counter[str]()

    for index in range(50):
        result = await _run_direct_turn(
            mode=PttInputMode.CORE_TERMINAL_TOGGLE,
            language=languages[index % len(languages)],
        )
        assert result.core_outcome is PttSessionOutcome.COMPLETED
        assert result.edge_outcome is PttSessionOutcome.COMPLETED
        assert result.core_bridge.close_calls == 1
        aggregate_core.update(_controls(result.core_bridge.sent_frames))
        aggregate_edge.update(_controls(result.edge_bridge.sent_frames))

    assert aggregate_core["session_open"] == 50
    assert aggregate_core["ptt_start"] == 50
    assert aggregate_core["ptt_submit"] == 50
    assert aggregate_core["playback_start"] == 50
    assert aggregate_core["playback_end"] == 50
    assert aggregate_core["safety_ack"] == 50
    assert aggregate_edge["session_ready"] == 50
    assert aggregate_edge["capture_start"] == 50
    assert aggregate_edge["capture_end"] == 50
    assert aggregate_edge["safety_receipt"] == 50


@pytest.mark.asyncio
async def test_stdio_simulator_transport_retries_short_pipe_writes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tuntun_edge.poc import simulator

    written = bytearray()
    attempts: list[bytes] = []

    def short_write(fd: int, data: bytes) -> int:
        assert fd == 12345
        attempts.append(bytes(data))
        count = min(2, len(data))
        written.extend(data[:count])
        return count

    monkeypatch.setattr(simulator.os, "write", short_write)

    await simulator.StdioPttTransport(stdout_fd=12345).send(b"abcdef")

    assert bytes(written) == b"abcdef"
    assert attempts == [b"abcdef", b"cdef", b"ef"]


def test_standalone_simulator_exits_after_no_core_frame_with_stdin_open() -> None:
    started = time.monotonic()
    process = subprocess.Popen(
        [
            sys.executable,
            "-u",
            "-m",
            "tuntun_edge.cli.main",
            "simulate-ptt",
            "--turn-id",
            str(TURN_ID),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        process.wait(timeout=10.0)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate(timeout=2.0)
        pytest.fail(
            "simulate-ptt did not exit within the 5s watchdog + 4s teardown envelope "
            f"while stdin remained open; stdout={stdout!r} stderr={stderr!r}"
        )
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=2.0)

    elapsed = time.monotonic() - started
    stdout, stderr = process.communicate(timeout=2.0)
    if process.stdin is not None:
        process.stdin.close()

    assert process.returncode == 1
    assert elapsed < 10.0
    assert stderr == b""
    assert stdout
