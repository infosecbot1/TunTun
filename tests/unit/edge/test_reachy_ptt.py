from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from collections import deque
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from tuntun_contracts.poc.framing import (
    MAX_FEED_BYTES,
    MAX_PCM_BYTES,
    MAX_TRANSPORT_PCM_FRAME_BYTES,
    TRANSPORT_AUDIO_FORMAT,
    ControlFrame,
    ControlKind,
    ErrorPayload,
    FrameDecoder,
    FrameErrorCode,
    FrameProtocolError,
    GuardDisposition,
    PcmFrame,
    PttControl,
    PttDuplexGuard,
    PttErrorReason,
    PttInputMode,
    PttSafetyReceipt,
    PttSessionOutcome,
    PttStopSource,
    SafetyPayload,
    StreamDirection,
    WireFrame,
    encode_control_frame,
    encode_pcm_frame,
)
from tuntun_contracts.speech import AudioFormat
from tuntun_edge.poc.ports import CleanupTaskSpawner
from tuntun_edge.poc.reachy_ptt import ReachyPttSession

TURN_ID = UUID("12345678-1234-5678-1234-567812345678")


class FakeTransport:
    def __init__(self) -> None:
        self.receive_calls = 0
        self.sent: list[bytes] = []
        self.close_calls = 0

    async def receive(self, max_bytes: int) -> bytes:
        self.receive_calls += 1
        return b""

    async def send(self, frame: bytes) -> None:
        self.sent.append(frame)

    async def close(self) -> None:
        self.close_calls += 1


class BlockingWriterTransport(FakeTransport):
    def __init__(self) -> None:
        super().__init__()
        self.first_send_started = asyncio.Event()
        self.release_first_send = asyncio.Event()
        self.frames: list[ControlFrame | PcmFrame] = []

    async def send(self, frame: bytes) -> None:
        if not self.frames:
            self.first_send_started.set()
            await self.release_first_send.wait()
        await super().send(frame)
        decoded = FrameDecoder().feed(frame)
        assert len(decoded) == 1
        self.frames.append(decoded[0])


class ControlledWriterFailureTransport(FakeTransport):
    def __init__(self, outcome: str) -> None:
        super().__init__()
        self.outcome = outcome
        self.send_started = asyncio.Event()
        self.release_send = asyncio.Event()
        self.send_cancelled = False

    async def send(self, frame: bytes) -> None:
        self.send_started.set()
        try:
            await self.release_send.wait()
        except asyncio.CancelledError:
            self.send_cancelled = True
            raise
        if self.outcome == "raise":
            raise OSError("injected ambiguous writer failure")
        await super().send(frame)


class WriterHarnessSession(ReachyPttSession):
    async def _accept_guarded(
        self,
        direction: StreamDirection,
        frame: WireFrame,
    ) -> GuardDisposition:
        return GuardDisposition.ACCEPTED


class GuardRejectingWriterSession(ReachyPttSession):
    async def _accept_guarded(
        self,
        direction: StreamDirection,
        frame: WireFrame,
    ) -> GuardDisposition:
        raise FrameProtocolError(FrameErrorCode.INVALID_ORDER)


class ScriptedHappyTransport(FakeTransport):
    def __init__(
        self,
        mode: PttInputMode,
        events: list[str],
        playback_pcm: bytes | tuple[bytes, ...],
        *,
        auto_submit: bool = True,
        complete_playback: bool = True,
    ) -> None:
        super().__init__()
        self.mode = mode
        self.events = events
        self.playback_chunks = (playback_pcm,) if isinstance(playback_pcm, bytes) else playback_pcm
        self.auto_submit = auto_submit
        self.complete_playback = complete_playback
        self.inbound: asyncio.Queue[bytes] = asyncio.Queue()
        self.edge_decoder = FrameDecoder()
        self.edge_frames: list[ControlFrame | PcmFrame] = []
        self.core_sequence = 0
        self._queue_control(PttControl.session_open(TURN_ID, mode))

    def _encoded_control(self, control: PttControl) -> bytes:
        result = encode_control_frame(sequence=self.core_sequence, control=control)
        self.core_sequence += 1
        return result

    def _queue_control(self, control: PttControl) -> None:
        self.inbound.put_nowait(self._encoded_control(control))

    def queue_heartbeat(self) -> None:
        self._queue_control(PttControl.heartbeat(TURN_ID))

    def queue_core_abort(self) -> None:
        self._queue_control(PttControl.abort(TURN_ID, PttErrorReason.TURN_CANCELLED))

    def _before_queue_playback(self) -> None:
        pass

    def _queue_safety_ack(self, *, accepted: bool) -> None:
        self._queue_control(PttControl.safety_ack(TURN_ID, accepted=accepted))

    async def receive(self, max_bytes: int) -> bytes:
        self.receive_calls += 1
        result = await self.inbound.get()
        assert len(result) <= max_bytes
        return result

    async def send(self, frame: bytes) -> None:
        await super().send(frame)
        decoded = self.edge_decoder.feed(frame)
        assert len(decoded) == 1
        item = decoded[0]
        self.edge_frames.append(item)
        if isinstance(item, PcmFrame):
            self.events.append(f"sent:pcm:{len(item.pcm)}")
            return

        kind = item.control.kind
        self.events.append(f"sent:{kind.value}")
        if kind is ControlKind.SESSION_READY and self.mode is PttInputMode.CORE_TERMINAL_TOGGLE:
            controls = self._encoded_control(PttControl.ptt_start(TURN_ID))
            if self.auto_submit:
                controls += self._encoded_control(PttControl.ptt_submit(TURN_ID))
            self.inbound.put_nowait(controls)
        elif kind is ControlKind.CAPTURE_END:
            self._before_queue_playback()
            playback = self._encoded_control(
                PttControl.playback_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)
            )
            if self.complete_playback:
                for pcm in self.playback_chunks:
                    playback += encode_pcm_frame(
                        turn_id=TURN_ID,
                        sequence=self.core_sequence,
                        pcm=pcm,
                    )
                    self.core_sequence += 1
                playback += self._encoded_control(PttControl.playback_end(TURN_ID))
            self.inbound.put_nowait(playback)
        elif kind is ControlKind.SAFETY_RECEIPT:
            assert isinstance(item.control.payload, SafetyPayload)
            self._queue_safety_ack(accepted=item.control.payload.receipt.is_complete())

    async def close(self) -> None:
        await super().close()
        self.inbound.put_nowait(b"")


class BlockingFailingPcmTransport(ScriptedHappyTransport):
    def __init__(self, events: list[str]) -> None:
        super().__init__(PttInputMode.CORE_TERMINAL_TOGGLE, events, b"")
        self.pcm_send_started = asyncio.Event()
        self.fail_send = asyncio.Event()
        self.pcm_send_cancelled = False

    async def send(self, frame: bytes) -> None:
        decoded = FrameDecoder().feed(frame)
        assert len(decoded) == 1
        if isinstance(decoded[0], PcmFrame):
            self.pcm_send_started.set()
            try:
                await self.fail_send.wait()
            except asyncio.CancelledError:
                self.pcm_send_cancelled = True
                raise
            raise OSError("injected ambiguous send failure")
        await super().send(frame)

    def queue_core_abort(self) -> None:
        self._queue_control(PttControl.abort(TURN_ID, PttErrorReason.TURN_CANCELLED))

    def queue_protocol_poison(self) -> None:
        self.inbound.put_nowait(b"NOPE" + b"\x00" * 28)


class SilentAckTransport(FakeTransport):
    def __init__(self) -> None:
        super().__init__()
        self.inbound: asyncio.Queue[bytes] = asyncio.Queue()
        self.edge_decoder = FrameDecoder()
        self.edge_frames: list[ControlFrame | PcmFrame] = []
        self.core_sequence = 0

    async def receive(self, max_bytes: int) -> bytes:
        self.receive_calls += 1
        result = await self.inbound.get()
        assert len(result) <= max_bytes
        return result

    async def send(self, frame: bytes) -> None:
        await super().send(frame)
        decoded = self.edge_decoder.feed(frame)
        assert len(decoded) == 1
        item = decoded[0]
        self.edge_frames.append(item)
        if isinstance(item, ControlFrame) and item.control.kind is ControlKind.SAFETY_RECEIPT:
            self.inbound.put_nowait(
                encode_control_frame(
                    sequence=self.core_sequence,
                    control=PttControl.safety_ack(TURN_ID, accepted=True),
                )
            )
            self.core_sequence += 1

    async def close(self) -> None:
        await super().close()
        self.inbound.put_nowait(b"")


class FailingCloseTransport(SilentAckTransport):
    async def close(self) -> None:
        self.close_calls += 1
        raise OSError("injected ambiguous transport-close failure")


class BlockingCloseTransport(FakeTransport):
    def __init__(self) -> None:
        super().__init__()
        self.close_started = asyncio.Event()
        self.close_cancelled = False

    async def close(self) -> None:
        self.close_calls += 1
        self.close_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.close_cancelled = True
            raise


class BlockingReadyTransport(SilentAckTransport):
    def __init__(self) -> None:
        super().__init__()
        self.ready_send_started = asyncio.Event()
        self.release_ready = asyncio.Event()
        self.ready_send_cancelled = False

    async def send(self, frame: bytes) -> None:
        decoded = FrameDecoder().feed(frame)
        assert len(decoded) == 1
        item = decoded[0]
        if isinstance(item, ControlFrame) and item.control.kind is ControlKind.SESSION_READY:
            self.ready_send_started.set()
            try:
                await self.release_ready.wait()
            except asyncio.CancelledError:
                self.ready_send_cancelled = True
                raise
        await super().send(frame)


class HostileEqualityResult:
    def __init__(self) -> None:
        self.comparisons = 0

    def __eq__(self, other: object) -> bool:
        self.comparisons += 1
        raise RuntimeError("hostile equality must not be invoked")


class ReceiveOutcomeTransport(SilentAckTransport):
    _OUTCOME_MARKER = b"test-receive-outcome"

    def __init__(self, receive_outcome: str) -> None:
        super().__init__()
        self.receive_outcome = receive_outcome
        self.ready_sent = asyncio.Event()
        self.receipt_sent = asyncio.Event()
        self.hostile_result = HostileEqualityResult()
        self.core_sequence = 1
        self.inbound.put_nowait(
            encode_control_frame(
                sequence=0,
                control=PttControl.session_open(TURN_ID, PttInputMode.CORE_TERMINAL_TOGGLE),
            )
        )

    async def receive(self, max_bytes: int) -> bytes:
        self.receive_calls += 1
        result = await self.inbound.get()
        if result == self._OUTCOME_MARKER:
            if self.receive_outcome == "raise":
                raise OSError("injected receive failure")
            if self.receive_outcome == "non_bytes":
                return "not-bytes"  # type: ignore[return-value]
            if self.receive_outcome == "oversized":
                return b"x" * (MAX_FEED_BYTES + 1)
            if self.receive_outcome == "hostile_eq":
                return self.hostile_result  # type: ignore[return-value]
            return b""
        assert len(result) <= max_bytes
        return result

    async def send(self, frame: bytes) -> None:
        await super().send(frame)
        item = self.edge_frames[-1]
        if isinstance(item, ControlFrame) and item.control.kind is ControlKind.SESSION_READY:
            self.ready_sent.set()
            self.inbound.put_nowait(self._OUTCOME_MARKER)
        elif isinstance(item, ControlFrame) and item.control.kind is ControlKind.SAFETY_RECEIPT:
            self.receipt_sent.set()


class ReceiptPolicyTransport(ScriptedHappyTransport):
    def __init__(
        self,
        *,
        ack: bool | None,
        receipt_behavior: str = "send",
    ) -> None:
        super().__init__(
            PttInputMode.CORE_TERMINAL_TOGGLE,
            [],
            b"\x18\x00" * 40,
        )
        self.ack = ack
        self.receipt_behavior = receipt_behavior
        self.receipt_send_started = asyncio.Event()
        self.release_receipt = asyncio.Event()
        self.receipt_send_attempts = 0
        self.receipt_send_cancelled = False

    def _queue_safety_ack(self, *, accepted: bool) -> None:
        if self.ack is not None:
            self._queue_control(PttControl.safety_ack(TURN_ID, accepted=self.ack))

    async def send(self, frame: bytes) -> None:
        decoded = FrameDecoder().feed(frame)
        assert len(decoded) == 1
        item = decoded[0]
        if isinstance(item, ControlFrame) and item.control.kind is ControlKind.SAFETY_RECEIPT:
            self.receipt_send_attempts += 1
            self.receipt_send_started.set()
            if self.receipt_behavior == "raise":
                raise OSError("injected receipt send failure")
            if self.receipt_behavior == "block":
                try:
                    await self.release_receipt.wait()
                except asyncio.CancelledError:
                    self.receipt_send_cancelled = True
                    raise
        await super().send(frame)


class PoisonEmergencyTransport(FakeTransport):
    def __init__(self, *, truncated_eof: bool) -> None:
        super().__init__()
        self.truncated_eof = truncated_eof
        self.inbound: asyncio.Queue[bytes] = asyncio.Queue()
        self.edge_decoder = FrameDecoder()
        self.edge_frames: list[ControlFrame | PcmFrame] = []
        self.ready_sent = asyncio.Event()
        self.error_sent = asyncio.Event()
        self.inbound.put_nowait(
            encode_control_frame(
                sequence=0,
                control=PttControl.session_open(TURN_ID, PttInputMode.CORE_TERMINAL_TOGGLE),
            )
        )

    async def receive(self, max_bytes: int) -> bytes:
        self.receive_calls += 1
        result = await self.inbound.get()
        assert len(result) <= max_bytes
        return result

    async def send(self, frame: bytes) -> None:
        await super().send(frame)
        decoded = self.edge_decoder.feed(frame)
        assert len(decoded) == 1
        item = decoded[0]
        self.edge_frames.append(item)
        if not isinstance(item, ControlFrame):
            return
        if item.control.kind is ControlKind.SESSION_READY:
            self.ready_sent.set()
        elif item.control.kind is ControlKind.ERROR:
            self.error_sent.set()

    def inject_poison(self) -> None:
        if self.truncated_eof:
            self.inbound.put_nowait(b"TTPT")
            self.inbound.put_nowait(b"")
        else:
            self.inbound.put_nowait(b"NOPE" + b"\x00" * 28)

    async def close(self) -> None:
        await super().close()
        self.inbound.put_nowait(b"")


class FakeMedia:
    def __init__(self) -> None:
        self.cleanup_calls: list[str] = []

    async def open_capture(self, *, output_format: AudioFormat, max_frame_bytes: int) -> None:
        assert output_format == TRANSPORT_AUDIO_FORMAT
        assert max_frame_bytes == 6_400

    async def read_capture(self) -> bytes | None:
        return None

    async def close_capture(self) -> bool:
        return True

    async def open_playback(self, *, input_format: AudioFormat) -> None:
        assert input_format == TRANSPORT_AUDIO_FORMAT

    async def write_playback(self, pcm: bytes) -> None:
        pass

    async def close_playback(self) -> bool:
        return True

    async def stop_recording(self) -> bool:
        self.cleanup_calls.append("recording")
        return True

    async def stop_playback(self) -> bool:
        self.cleanup_calls.append("playback")
        return True

    async def stop_motion(self) -> bool:
        self.cleanup_calls.append("motion")
        return True

    async def disable_audio_reactive(self) -> bool:
        self.cleanup_calls.append("audio_reactive")
        return True


class HappyTurnMedia(FakeMedia):
    def __init__(self, events: list[str], capture_chunks: tuple[bytes, ...]) -> None:
        super().__init__()
        self.events = events
        self.capture_chunks = deque(capture_chunks)
        self.playback: list[bytes] = []

    async def open_capture(self, *, output_format: AudioFormat, max_frame_bytes: int) -> None:
        await super().open_capture(
            output_format=output_format,
            max_frame_bytes=max_frame_bytes,
        )
        self.events.append("media:open_capture")

    async def read_capture(self) -> bytes | None:
        self.events.append("media:read_capture")
        return self.capture_chunks.popleft() if self.capture_chunks else None

    async def close_capture(self) -> bool:
        self.events.append("media:close_capture")
        return True

    async def open_playback(self, *, input_format: AudioFormat) -> None:
        await super().open_playback(input_format=input_format)
        self.events.append("media:open_playback")

    async def write_playback(self, pcm: bytes) -> None:
        self.events.append(f"media:playback:{len(pcm)}")
        self.playback.append(pcm)

    async def close_playback(self) -> bool:
        self.events.append("media:close_playback")
        return True


class OrdinaryOperationRecordingMedia(FakeMedia):
    def __init__(self) -> None:
        super().__init__()
        self.capture_open_calls = 0
        self.playback_write_calls = 0

    async def open_capture(self, *, output_format: AudioFormat, max_frame_bytes: int) -> None:
        self.capture_open_calls += 1
        await super().open_capture(
            output_format=output_format,
            max_frame_bytes=max_frame_bytes,
        )

    async def write_playback(self, pcm: bytes) -> None:
        self.playback_write_calls += 1
        await super().write_playback(pcm)


class FakeBuffer:
    def __init__(self, initial: bytes = b"") -> None:
        self.data = bytearray(initial)
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


class StartupFailingBuffer(FakeBuffer):
    def __init__(self, failure: str) -> None:
        super().__init__(b"stale-audio")
        self.failure = failure

    def clear(self) -> bool:
        if self.failure == "clear":
            self.clear_calls += 1
            raise OSError("injected buffer-clear failure")
        return super().clear()

    def is_empty(self) -> bool:
        if self.failure == "is_empty":
            raise OSError("injected buffer-empty verification failure")
        return super().is_empty()


class FaultingPlaybackBuffer(FakeBuffer):
    def __init__(self, failure: str) -> None:
        super().__init__()
        self.failure = failure

    def append(self, data: bytes) -> None:
        if self.failure == "append_raise":
            raise OSError("injected playback-buffer append failure")
        super().append(data)

    def take(self, max_bytes: int) -> bytes:
        if self.failure == "take_raise":
            raise OSError("injected playback-buffer take failure")
        result = super().take(max_bytes)
        if self.failure == "take_non_bytes":
            return "not-pcm"  # type: ignore[return-value]
        if self.failure == "take_empty":
            return b""
        if self.failure == "take_odd":
            return b"\x00"
        if self.failure == "take_short":
            return result[:-2]
        if self.failure == "take_changed":
            return b"\x7f" * len(result)
        return result


class AppendRecordingBuffer(FakeBuffer):
    def __init__(self) -> None:
        super().__init__()
        self.append_calls = 0

    def append(self, data: bytes) -> None:
        self.append_calls += 1
        super().append(data)


class DeadlineCaptureMedia(FakeMedia):
    def __init__(self, pcm: bytes) -> None:
        super().__init__()
        self.pcm = pcm
        self.read_started = asyncio.Event()
        self.release_read = asyncio.Event()

    async def read_capture(self) -> bytes:
        self.read_started.set()
        await self.release_read.wait()
        return self.pcm


class CaptureDeadlineHarnessSession(ReachyPttSession):
    def __init__(
        self, *, advance_after_first_pcm_to: float | None = None, **arguments: object
    ) -> None:
        super().__init__(**arguments)  # type: ignore[arg-type]
        self.advance_after_first_pcm_to = advance_after_first_pcm_to
        self.outbound_pcm: list[bytes] = []
        self.outbound_deadlines: list[float | None] = []

    async def _enqueue_normal(
        self,
        *,
        control: PttControl | None = None,
        pcm: bytes | None = None,
        absolute_deadline: float | None = None,
    ) -> None:
        assert control is None
        assert pcm is not None
        self.outbound_pcm.append(pcm)
        self.outbound_deadlines.append(absolute_deadline)
        if len(self.outbound_pcm) == 1 and self.advance_after_first_pcm_to is not None:
            clock = self._clock
            assert isinstance(clock, FakeClock)
            clock.current = self.advance_after_first_pcm_to


class DeadlineGuardSession(ReachyPttSession):
    def __init__(self, **arguments: object) -> None:
        super().__init__(**arguments)  # type: ignore[arg-type]
        self.guard_accept_calls = 0

    async def _accept_guarded(
        self,
        direction: StreamDirection,
        frame: WireFrame,
    ) -> GuardDisposition:
        self.guard_accept_calls += 1
        return GuardDisposition.ACCEPTED


class ClockFaultingGuardSession(DeadlineGuardSession):
    async def _accept_guarded(
        self,
        direction: StreamDirection,
        frame: WireFrame,
    ) -> GuardDisposition:
        disposition = await super()._accept_guarded(direction, frame)
        clock = self._clock
        assert isinstance(clock, InvalidNowClock)
        clock.failure = "raise"
        return disposition


class CaptureControlDeadlineSession(ReachyPttSession):
    def __init__(
        self,
        *,
        capture_accepted_at: float,
        submitted_at: float,
        **arguments: object,
    ) -> None:
        super().__init__(**arguments)  # type: ignore[arg-type]
        self.capture_accepted_at = capture_accepted_at
        self.submitted_at = submitted_at
        self.operation_deadlines: dict[str, float] = {}
        self.control_deadlines: dict[ControlKind, float | None] = {}

    async def _within_deadline(
        self,
        operation: Coroutine[Any, Any, Any],
        deadline: float,
        *,
        name: str,
        retry_factory: Callable[[], Coroutine[Any, Any, Any]] | None = None,
    ) -> Any:
        del retry_factory
        self.operation_deadlines[name] = deadline
        return await operation

    async def _enqueue_normal(
        self,
        *,
        control: PttControl | None = None,
        pcm: bytes | None = None,
        absolute_deadline: float | None = None,
    ) -> None:
        assert control is not None
        assert pcm is None
        self.control_deadlines[control.kind] = absolute_deadline
        if control.kind is ControlKind.CAPTURE_START:
            self._capture_started_at = self.capture_accepted_at

    async def _capture_until_submit(
        self,
        submit_operation: Coroutine[Any, Any, object],
        capture_deadline: float,
    ) -> bool:
        submit_operation.close()
        assert self.submitted_at < capture_deadline
        self._ptt_submitted_at = self.submitted_at
        return True


class MainBodyFailureSession(ReachyPttSession):
    def __init__(self, *, failure: str, **arguments: object) -> None:
        super().__init__(**arguments)  # type: ignore[arg-type]
        self.failure = failure
        self.main_body_entered = asyncio.Event()
        self.release_failure = asyncio.Event()

    async def _wait_event_or_cleanup(
        self,
        event: asyncio.Event,
        deadline: float,
        *,
        name: str,
    ) -> bool:
        if name != "reachy-ptt-session-open":
            return await super()._wait_event_or_cleanup(event, deadline, name=name)
        self.main_body_entered.set()
        await self.release_failure.wait()
        if self.failure == "timeout":
            raise TimeoutError
        raise RuntimeError("injected main-body failure")


class FakeClock:
    def __init__(self, now: float = 10.0) -> None:
        self.current = now
        self.deadlines: list[float] = []
        self._waiters: list[tuple[float, asyncio.Event]] = []

    def now(self) -> float:
        return self.current

    async def sleep_until(self, deadline: float) -> None:
        self.deadlines.append(deadline)
        if self.current >= deadline:
            return
        event = asyncio.Event()
        self._waiters.append((deadline, event))
        await event.wait()

    def advance_to(self, value: float) -> None:
        self.current = value
        for deadline, event in self._waiters:
            if value >= deadline:
                event.set()


class FaultingSleepClock(FakeClock):
    def __init__(self, fault: str, *, fault_call: int = 1, now: float = 10.0) -> None:
        super().__init__(now)
        self.fault = fault
        self.fault_call = fault_call
        self.sleep_calls = 0

    async def sleep_until(self, deadline: float) -> None:
        self.sleep_calls += 1
        if self.sleep_calls == self.fault_call:
            self.deadlines.append(deadline)
            if self.fault == "raise":
                raise OSError("injected clock sleeper failure")
            if self.fault == "cancel":
                raise asyncio.CancelledError
            return
        await super().sleep_until(deadline)


class InvalidNowClock(FakeClock):
    def __init__(self) -> None:
        super().__init__()
        self.failure: str | None = None

    def now(self) -> float:
        if self.failure == "raise":
            raise OSError("injected clock read failure")
        if self.failure == "nan":
            return float("nan")
        if self.failure == "inf":
            return float("inf")
        if self.failure == "backward":
            return self.current - 1.0
        if self.failure == "overflow_int":
            return 10**10000  # type: ignore[return-value]
        if self.failure == "inexact_int":
            return 2**100 + 1  # type: ignore[return-value]
        return super().now()


class AdversarialCleanupSleeperClock(InvalidNowClock):
    def __init__(self, sleeper_behavior: str) -> None:
        super().__init__()
        self.sleeper_behavior = sleeper_behavior
        self.sleep_calls = 0
        self.sleep_started = asyncio.Event()
        self.sleep_cancelled = False

    async def sleep_until(self, deadline: float) -> None:
        self.sleep_calls += 1
        self.sleep_started.set()
        if self.sleeper_behavior == "hang":
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.sleep_cancelled = True
                raise
        if self.sleeper_behavior == "raise":
            raise OSError("injected post-fault sleeper failure")
        if self.sleeper_behavior == "early":
            return
        raise AssertionError(f"unexpected sleeper behavior: {self.sleeper_behavior}")


class DeadlineCancellationBarrierClock(InvalidNowClock):
    def __init__(self) -> None:
        super().__init__()
        self.deadline_cancel_started = asyncio.Event()
        self.release_deadline_cancel = asyncio.Event()

    async def sleep_until(self, deadline: float) -> None:
        try:
            await super().sleep_until(deadline)
        except asyncio.CancelledError:
            self.deadline_cancel_started.set()
            await self.release_deadline_cancel.wait()
            raise


class FakeCleanupTaskSpawner(CleanupTaskSpawner):
    def __init__(self) -> None:
        self.names: list[str] = []

    def start(
        self,
        operation: Coroutine[Any, Any, bool],
        *,
        name: str,
    ) -> asyncio.Task[bool]:
        self.names.append(name)
        return asyncio.create_task(operation, name=name)


class FirstExitBarrierLock:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self.first_exit = asyncio.Event()
        self.release_first_exit = asyncio.Event()
        self.exit_count = 0

    async def __aenter__(self) -> None:
        await self._lock.acquire()

    async def acquire(self) -> bool:
        return await self._lock.acquire()

    def release(self) -> None:
        self._lock.release()

    async def __aexit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        self.exit_count += 1
        self._lock.release()
        if self.exit_count == 1:
            self.first_exit.set()
            await self.release_first_exit.wait()


class ChildCreationRecordingSession(ReachyPttSession):
    def __init__(self, **arguments: object) -> None:
        super().__init__(**arguments)  # type: ignore[arg-type]
        self.children_created_after_latch: list[str] = []

    def _create_runtime_task(
        self,
        operation: Coroutine[Any, Any, object],
        *,
        name: str,
    ) -> asyncio.Task[object]:
        runtime_children = {
            "reachy-ptt-writer",
            "reachy-ptt-playback",
            "reachy-ptt-reader",
            "reachy-ptt-stop-input",
            "reachy-ptt-heartbeat-watchdog",
            "reachy-ptt-turn-watchdog",
        }
        if self._cleanup_started_at is not None and name in runtime_children:
            self.children_created_after_latch.append(name)
        return super()._create_runtime_task(operation, name=name)


class OutcomeMedia(FakeMedia):
    def __init__(self, outcomes: dict[str, object]) -> None:
        super().__init__()
        self.outcomes = outcomes

    async def _outcome(self, name: str) -> bool:
        self.cleanup_calls.append(name)
        result = self.outcomes[name]
        if isinstance(result, BaseException):
            raise result
        return result  # type: ignore[return-value]

    async def stop_recording(self) -> bool:
        return await self._outcome("recording")

    async def stop_playback(self) -> bool:
        return await self._outcome("playback")

    async def stop_motion(self) -> bool:
        return await self._outcome("motion")

    async def disable_audio_reactive(self) -> bool:
        return await self._outcome("audio_reactive")


class BlockingCleanupMedia(FakeMedia):
    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.running = 0
        self.cancelled = 0
        self.completed = 0

    async def _block(self, name: str) -> bool:
        self.cleanup_calls.append(name)
        self.running += 1
        if self.running == 4:
            self.started.set()
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            self.cancelled += 1
            raise
        else:
            self.completed += 1
            return True

    async def stop_recording(self) -> bool:
        return await self._block("recording")

    async def stop_playback(self) -> bool:
        return await self._block("playback")

    async def stop_motion(self) -> bool:
        return await self._block("motion")

    async def disable_audio_reactive(self) -> bool:
        return await self._block("audio_reactive")


class OneFailureCleanupTaskSpawner(FakeCleanupTaskSpawner):
    def __init__(self, failed_name: str) -> None:
        super().__init__()
        self.failed_name = failed_name

    def start(
        self,
        operation: Coroutine[Any, Any, bool],
        *,
        name: str,
    ) -> asyncio.Task[bool]:
        self.names.append(name)
        if name == self.failed_name:
            raise RuntimeError("injected task spawn failure")
        return asyncio.create_task(operation, name=name)


class SynchronousFactoryFailureMedia(FakeMedia):
    def stop_motion(self) -> Coroutine[Any, Any, bool]:  # type: ignore[override]
        raise RuntimeError("injected synchronous cleanup factory failure")


class ImmediateCaptureInput:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def wait_for_start(self) -> None:
        self.events.append("input:start")

    async def wait_for_submit(self) -> None:
        self.events.append("input:submit")


class ControlledCaptureInput(ImmediateCaptureInput):
    def __init__(self, events: list[str]) -> None:
        super().__init__(events)
        self.submit = asyncio.Event()

    async def wait_for_submit(self) -> None:
        await self.submit.wait()
        self.events.append("input:submit")


class BlockingStartCaptureInput(ImmediateCaptureInput):
    def __init__(self, events: list[str]) -> None:
        super().__init__(events)
        self.started = asyncio.Event()

    async def wait_for_start(self) -> None:
        self.started.set()
        await asyncio.Event().wait()


class BlockingStopInput:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.cancelled = False

    async def wait_for_stop(self) -> None:
        self.started.set()
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise


class FailingStopInput:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def wait_for_stop(self) -> None:
        self.started.set()
        await self.release.wait()
        raise OSError("injected independent-stop failure")


class StopReleasesCaptureMedia(HappyTurnMedia):
    def __init__(self, events: list[str]) -> None:
        super().__init__(events, ())
        self.read_started = asyncio.Event()
        self.recording_stopped = asyncio.Event()

    async def read_capture(self) -> bytes | None:
        self.events.append("media:read_capture")
        self.read_started.set()
        await self.recording_stopped.wait()
        return None

    async def stop_recording(self) -> bool:
        self.recording_stopped.set()
        return await super().stop_recording()


class CaptureCloseFailureMedia(HappyTurnMedia):
    async def close_capture(self) -> bool:
        self.events.append("media:close_capture")
        return False


class CaptureStageFailureMedia(HappyTurnMedia):
    def __init__(self, events: list[str], failure: str) -> None:
        super().__init__(events, (b"\x12\x00" * 40,))
        self.failure = failure

    async def open_capture(self, *, output_format: AudioFormat, max_frame_bytes: int) -> None:
        if self.failure == "open_raise":
            self.events.append("media:open_capture")
            raise OSError("injected capture-open failure")
        await super().open_capture(
            output_format=output_format,
            max_frame_bytes=max_frame_bytes,
        )

    async def read_capture(self) -> bytes | None:
        if self.failure.startswith("read_"):
            self.events.append("media:read_capture")
            if self.failure == "read_raise":
                raise OSError("injected capture-read failure")
            if self.failure == "read_none":
                return None
            if self.failure == "read_non_bytes":
                return "not-pcm"  # type: ignore[return-value]
            if self.failure == "read_empty":
                return b""
            if self.failure == "read_odd":
                return b"\x00"
        return await super().read_capture()

    async def close_capture(self) -> bool:
        if self.failure.startswith("close_"):
            self.events.append("media:close_capture")
            if self.failure == "close_raise":
                raise OSError("injected capture-close failure")
            if self.failure == "close_non_bool":
                return 1  # type: ignore[return-value]
            return False
        return await super().close_capture()


class BlockingCaptureStageMedia(HappyTurnMedia):
    def __init__(self, events: list[str], blocked_stage: str) -> None:
        super().__init__(events, ())
        self.blocked_stage = blocked_stage
        self.stage_started = asyncio.Event()
        self.stage_cancelled = False

    async def _block(self) -> None:
        self.stage_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.stage_cancelled = True
            raise

    async def open_capture(self, *, output_format: AudioFormat, max_frame_bytes: int) -> None:
        await super().open_capture(
            output_format=output_format,
            max_frame_bytes=max_frame_bytes,
        )
        if self.blocked_stage == "open":
            await self._block()

    async def read_capture(self) -> bytes | None:
        self.events.append("media:read_capture")
        if self.blocked_stage == "read":
            await self._block()
        return b"\x07\x00" * 40

    async def close_capture(self) -> bool:
        self.events.append("media:close_capture")
        if self.blocked_stage == "close":
            await self._block()
        return True


class StopReleasesPlaybackOpenMedia(HappyTurnMedia):
    def __init__(self, events: list[str]) -> None:
        super().__init__(events, (b"\x09\x00" * 40,))
        self.playback_open_started = asyncio.Event()
        self.release_playback_open = asyncio.Event()

    async def open_playback(self, *, input_format: AudioFormat) -> None:
        await FakeMedia.open_playback(self, input_format=input_format)
        self.events.append("media:open_playback")
        self.playback_open_started.set()
        await self.release_playback_open.wait()

    async def stop_playback(self) -> bool:
        self.release_playback_open.set()
        return await super().stop_playback()


class BlockingPlaybackOpenMedia(HappyTurnMedia):
    def __init__(self, events: list[str]) -> None:
        super().__init__(events, (b"\x0c\x00" * 40,))
        self.playback_open_started = asyncio.Event()
        self.playback_open_cancelled = False
        self.close_playback_calls = 0

    async def open_playback(self, *, input_format: AudioFormat) -> None:
        await FakeMedia.open_playback(self, input_format=input_format)
        self.events.append("media:open_playback")
        self.playback_open_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.playback_open_cancelled = True
            self.events.append("media:open_playback_cancelled")
            raise

    async def close_playback(self) -> bool:
        self.close_playback_calls += 1
        return await super().close_playback()


class PlaybackStageFailureMedia(HappyTurnMedia):
    def __init__(self, events: list[str], failure: str) -> None:
        super().__init__(events, (b"\x13\x00" * 40,))
        self.failure = failure

    async def open_playback(self, *, input_format: AudioFormat) -> None:
        self.events.append("media:open_playback")
        if self.failure == "open_raise":
            raise OSError("injected playback-open failure")
        await FakeMedia.open_playback(self, input_format=input_format)

    async def write_playback(self, pcm: bytes) -> None:
        self.events.append(f"media:playback:{len(pcm)}")
        if self.failure == "write_raise":
            raise OSError("injected playback-write failure")
        self.playback.append(pcm)

    async def close_playback(self) -> bool:
        self.events.append("media:close_playback")
        if self.failure == "close_raise":
            raise OSError("injected playback-close failure")
        if self.failure == "close_false":
            return False
        if self.failure == "close_non_bool":
            return 1  # type: ignore[return-value]
        return True


class BlockingPlaybackStageMedia(HappyTurnMedia):
    def __init__(self, events: list[str], blocked_stage: str) -> None:
        super().__init__(events, (b"\x14\x00" * 40,))
        self.blocked_stage = blocked_stage
        self.stage_started = asyncio.Event()
        self.stage_cancelled = False

    async def _block(self) -> None:
        self.stage_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.stage_cancelled = True
            raise

    async def open_playback(self, *, input_format: AudioFormat) -> None:
        await super().open_playback(input_format=input_format)
        if self.blocked_stage == "open":
            await self._block()

    async def write_playback(self, pcm: bytes) -> None:
        await super().write_playback(pcm)
        if self.blocked_stage == "write":
            await self._block()

    async def close_playback(self) -> bool:
        self.events.append("media:close_playback")
        if self.blocked_stage == "close":
            await self._block()
        return True


class IncompleteReceiptMedia(HappyTurnMedia):
    async def stop_motion(self) -> bool:
        self.cleanup_calls.append("motion")
        return False


class BlockingReceiptCleanupMedia(HappyTurnMedia):
    def __init__(self) -> None:
        super().__init__([], (b"\x19\x00" * 40,))
        self.cleanup_started = asyncio.Event()
        self.running = 0

    async def _block_cleanup(self, name: str) -> bool:
        self.cleanup_calls.append(name)
        self.running += 1
        if self.running == 4:
            self.cleanup_started.set()
        await asyncio.Event().wait()
        return True

    async def stop_recording(self) -> bool:
        return await self._block_cleanup("recording")

    async def stop_playback(self) -> bool:
        return await self._block_cleanup("playback")

    async def stop_motion(self) -> bool:
        return await self._block_cleanup("motion")

    async def disable_audio_reactive(self) -> bool:
        return await self._block_cleanup("audio_reactive")


class MultiChunkCaptureMedia(HappyTurnMedia):
    def __init__(self, events: list[str], chunks: tuple[bytes, ...]) -> None:
        super().__init__(events, chunks)
        self.read_count = 0
        self.three_reads = asyncio.Event()
        self.exhausted_read_cancelled = False

    async def read_capture(self) -> bytes | None:
        if not self.capture_chunks:
            self.events.append("media:read_capture")
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.exhausted_read_cancelled = True
                raise
        result = await super().read_capture()
        self.read_count += 1
        if self.read_count == 3:
            self.three_reads.set()
        return result


class SubmitAfterThreeReadsInput(ImmediateCaptureInput):
    def __init__(self, events: list[str], media: MultiChunkCaptureMedia) -> None:
        super().__init__(events)
        self.media = media

    async def wait_for_submit(self) -> None:
        await self.media.three_reads.wait()
        for _ in range(10):
            await asyncio.sleep(0)
        self.events.append("input:submit")


class CancellationOrderCaptureMedia(HappyTurnMedia):
    def __init__(self, events: list[str]) -> None:
        super().__init__(events, ())
        self.read_started = asyncio.Event()

    async def read_capture(self) -> bytes | None:
        self.events.append("media:read_capture")
        self.read_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.events.append("media:read_capture_cancelled")
            raise


class LatePoisonMedia(BlockingCleanupMedia):
    def __init__(self, events: list[str]) -> None:
        super().__init__()
        self.events = events
        self.read_started = asyncio.Event()

    async def open_capture(self, *, output_format: AudioFormat, max_frame_bytes: int) -> None:
        await FakeMedia.open_capture(
            self,
            output_format=output_format,
            max_frame_bytes=max_frame_bytes,
        )
        self.events.append("media:open_capture")

    async def read_capture(self) -> bytes | None:
        self.events.append("media:read_capture")
        self.read_started.set()
        await asyncio.Event().wait()
        return None


class LatePoisonTransport(ScriptedHappyTransport):
    def __init__(self, events: list[str]) -> None:
        super().__init__(PttInputMode.REACHY_LOCAL, events, b"")

    def inject_poison(self) -> None:
        self.inbound.put_nowait(b"NOPE" + b"\x00" * 28)


class AckTailPoisonTransport(ScriptedHappyTransport):
    def __init__(self, events: list[str], tail_kind: str) -> None:
        super().__init__(PttInputMode.REACHY_LOCAL, events, b"")
        self.tail_kind = tail_kind

    def _queue_safety_ack(self, *, accepted: bool) -> None:
        ack = self._encoded_control(PttControl.safety_ack(TURN_ID, accepted=accepted))
        if self.tail_kind == "truncated":
            tail = b"TTPT"
        else:
            tail = self._encoded_control(PttControl.heartbeat(TURN_ID))
        self.inbound.put_nowait(ack + tail)


def session_arguments() -> dict[str, object]:
    return {
        "turn_id": TURN_ID,
        "input_mode": PttInputMode.CORE_TERMINAL_TOGGLE,
        "media": FakeMedia(),
        "transport": FakeTransport(),
        "capture_input": None,
        "stop_input": None,
        "capture_buffer": FakeBuffer(),
        "playback_buffer": FakeBuffer(),
        "clock": FakeClock(),
        "task_spawner": FakeCleanupTaskSpawner(),
    }


@pytest.mark.parametrize(
    ("capture_input", "stop_input"),
    ((None, object()), (object(), None), (None, None)),
)
def test_reachy_local_mode_requires_both_local_input_owners(
    capture_input: object | None,
    stop_input: object | None,
) -> None:
    arguments = session_arguments()
    arguments.update(
        input_mode=PttInputMode.REACHY_LOCAL,
        capture_input=capture_input,
        stop_input=stop_input,
    )

    with pytest.raises(ValueError):
        ReachyPttSession(**arguments)  # type: ignore[arg-type]


def test_terminal_mode_rejects_an_edge_capture_owner() -> None:
    arguments = session_arguments()
    arguments["capture_input"] = object()

    with pytest.raises(ValueError):
        ReachyPttSession(**arguments)  # type: ignore[arg-type]


@pytest.mark.parametrize("stop_input", (None, object()))
def test_terminal_mode_allows_an_optional_independent_stop(stop_input: object | None) -> None:
    arguments = session_arguments()
    arguments["stop_input"] = stop_input

    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    assert session.input_mode is PttInputMode.CORE_TERMINAL_TOGGLE


@pytest.mark.asyncio
async def test_independent_stop_failure_is_local_cleanup_failure_not_protocol_poison() -> None:
    stop_input = FailingStopInput()
    transport = SilentAckTransport()
    transport.inbound.put_nowait(
        encode_control_frame(
            sequence=0,
            control=PttControl.session_open(TURN_ID, PttInputMode.CORE_TERMINAL_TOGGLE),
        )
    )
    transport.core_sequence = 1
    arguments = session_arguments()
    arguments.update(stop_input=stop_input, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await asyncio.wait_for(stop_input.started.wait(), timeout=0.2)
        controls: list[ControlKind] = []
        for _attempt in range(20):
            controls = [
                frame.control.kind
                for frame in transport.edge_frames
                if isinstance(frame, ControlFrame)
            ]
            if ControlKind.SESSION_READY in controls:
                break
            await asyncio.sleep(0)
        assert ControlKind.SESSION_READY in controls

        stop_input.release.set()
        outcome = await asyncio.wait_for(run_task, timeout=0.5)

        assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert session._cleanup_source is PttStopSource.WATCHDOG
        assert session._semantic_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert session._guard_poisoned is False
        assert session._protocol_poisoned.is_set() is False
        outbound = [
            frame.control for frame in transport.edge_frames if isinstance(frame, ControlFrame)
        ]
        assert [control.kind for control in outbound] == [
            ControlKind.SESSION_READY,
            ControlKind.ERROR,
            ControlKind.SAFETY_RECEIPT,
        ]
        error = outbound[1].payload
        assert isinstance(error, ErrorPayload)
        assert error.reason_code is PttErrorReason.CLEANUP_INCOMPLETE
        assert transport.close_calls == 1
        await asyncio.sleep(0)
        assert not {
            task.get_name()
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
        }
    finally:
        stop_input.release.set()
        if not run_task.done():
            await session.stop(PttStopSource.SUPERVISOR_INPUT)
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


def test_session_rejects_aliased_owned_audio_buffers() -> None:
    arguments = session_arguments()
    shared = object()
    arguments["capture_buffer"] = shared
    arguments["playback_buffer"] = shared

    with pytest.raises(ValueError):
        ReachyPttSession(**arguments)  # type: ignore[arg-type]


@pytest.mark.asyncio
@pytest.mark.parametrize("stale_side", ("capture", "playback"))
async def test_normal_run_clears_stale_owned_audio_before_new_turn(stale_side: str) -> None:
    events: list[str] = []
    captured = b"\x31\x00" * 40
    playback = b"\x32\x00" * 40
    capture_buffer = FakeBuffer(b"stale-capture" if stale_side == "capture" else b"")
    playback_buffer = FakeBuffer(b"stale-playback" if stale_side == "playback" else b"")
    media = HappyTurnMedia(events, (captured,))
    transport = ScriptedHappyTransport(
        PttInputMode.CORE_TERMINAL_TOGGLE,
        events,
        playback,
    )
    arguments = session_arguments()
    arguments.update(
        capture_buffer=capture_buffer,
        media=media,
        playback_buffer=playback_buffer,
        transport=transport,
    )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    outcome = await session.run()

    assert outcome is PttSessionOutcome.COMPLETED
    assert (
        b"".join(frame.pcm for frame in transport.edge_frames if isinstance(frame, PcmFrame))
        == captured
    )
    assert media.playback == [playback]
    assert capture_buffer.clear_calls == 2
    assert playback_buffer.clear_calls == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ("clear", "is_empty"))
async def test_startup_buffer_verification_failure_is_local_only_and_fails_closed(
    failure: str,
) -> None:
    transport = SilentAckTransport()
    media = FakeMedia()
    failing_buffer = StartupFailingBuffer(failure)
    other_buffer = FakeBuffer(b"other-stale-audio")
    arguments = session_arguments()
    arguments.update(
        capture_buffer=failing_buffer,
        media=media,
        playback_buffer=other_buffer,
        transport=transport,
    )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")

    async def stop_obsolete_runtime() -> None:
        for _attempt in range(20):
            if run_task.done():
                return
            if session._reader_task is not None:
                await session.stop(PttStopSource.SUPERVISOR_INPUT)
                return
            await asyncio.sleep(0)

    stop_task = asyncio.create_task(
        stop_obsolete_runtime(),
        name="test-stop-obsolete-reachy-runtime",
    )
    try:
        outcome = await asyncio.wait_for(run_task, timeout=0.5)
        await stop_task
        cleanup_identity = session._cleanup_task
        assert cleanup_identity is not None
        receipt = await session.stop(PttStopSource.SUPERVISOR_INPUT)

        assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert session._cleanup_source is PttStopSource.WATCHDOG
        assert session._semantic_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert cleanup_identity.result() is receipt
        assert receipt.owned_buffers_cleared is False
        assert sorted(media.cleanup_calls) == [
            "audio_reactive",
            "motion",
            "playback",
            "recording",
        ]
        assert transport.receive_calls == 0
        assert transport.sent == []
        assert transport.close_calls == 0
    finally:
        if not run_task.done():
            await session.stop(PttStopSource.SUPERVISOR_INPUT)
            run_task.cancel()
        if not stop_task.done():
            stop_task.cancel()
        await asyncio.gather(run_task, stop_task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    (
        "append_raise",
        "take_raise",
        "take_non_bytes",
        "take_empty",
        "take_odd",
        "take_short",
        "take_changed",
    ),
)
async def test_playback_buffer_fault_is_local_playback_failure_not_protocol_poison(
    failure: str,
) -> None:
    events: list[str] = []
    playback = b"\x33\x00" * 40
    media = HappyTurnMedia(events, (b"\x34\x00" * 40,))
    transport = ScriptedHappyTransport(
        PttInputMode.CORE_TERMINAL_TOGGLE,
        events,
        playback,
    )
    arguments = session_arguments()
    arguments.update(
        media=media,
        playback_buffer=FaultingPlaybackBuffer(failure),
        transport=transport,
    )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    outcome = await session.run()

    assert outcome is PttSessionOutcome.PLAYBACK_FAILED
    assert session._semantic_outcome is PttSessionOutcome.PLAYBACK_FAILED
    assert session._guard_poisoned is False
    assert session._protocol_poisoned.is_set() is False
    assert media.playback == []
    errors = [
        frame.control.payload
        for frame in transport.edge_frames
        if isinstance(frame, ControlFrame) and frame.control.kind is ControlKind.ERROR
    ]
    assert len(errors) == 1
    assert isinstance(errors[0], ErrorPayload)
    assert errors[0].reason_code is PttErrorReason.PLAYBACK_FAILED
    assert transport.close_calls == 1
    await asyncio.sleep(0)
    assert not {
        task.get_name()
        for task in asyncio.all_tasks()
        if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
    }


@pytest.mark.asyncio
async def test_stop_before_run_is_local_only_cached_and_permanently_terminal() -> None:
    arguments = session_arguments()
    transport = FakeTransport()
    media = FakeMedia()
    capture_buffer = FakeBuffer(b"captured")
    playback_buffer = FakeBuffer(b"played")
    spawner = FakeCleanupTaskSpawner()
    arguments.update(
        transport=transport,
        media=media,
        capture_buffer=capture_buffer,
        playback_buffer=playback_buffer,
        task_spawner=spawner,
    )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    first = await session.stop(PttStopSource.SUPERVISOR_INPUT)
    second = await session.stop(PttStopSource.WATCHDOG)

    assert first is second
    assert first.turn_id == TURN_ID
    assert first.is_complete()
    assert capture_buffer.clear_calls == 1
    assert playback_buffer.clear_calls == 1
    assert media.cleanup_calls == ["recording", "playback", "motion", "audio_reactive"]
    assert spawner.names == ["recording", "playback", "motion", "audio_reactive"]
    assert transport.receive_calls == 0
    assert transport.sent == []
    assert transport.close_calls == 0
    with pytest.raises(RuntimeError):
        await session.run()
    assert transport.receive_calls == 0
    assert transport.sent == []
    assert transport.close_calls == 0


@pytest.mark.asyncio
async def test_cleanup_receipt_requires_positive_observation_for_every_fact() -> None:
    arguments = session_arguments()
    media = OutcomeMedia(
        {
            "recording": False,
            "playback": RuntimeError("injected playback stop failure"),
            "motion": True,
            "audio_reactive": 1,
        }
    )
    capture_buffer = FakeBuffer(b"captured")
    playback_buffer = FakeBuffer(b"played")

    def failed_clear() -> bool:
        playback_buffer.clear_calls += 1
        return False

    playback_buffer.clear = failed_clear  # type: ignore[method-assign]
    arguments.update(
        media=media,
        capture_buffer=capture_buffer,
        playback_buffer=playback_buffer,
    )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    receipt = await session.stop(PttStopSource.SUPERVISOR_INPUT)

    assert receipt.new_capture_rejected is True
    assert receipt.recording_stopped is False
    assert receipt.playback_stopped is False
    assert receipt.motion_stopped is True
    assert receipt.audio_reactive_disabled is False
    assert receipt.owned_buffers_cleared is False
    assert capture_buffer.clear_calls == 1
    assert playback_buffer.clear_calls == 1


@pytest.mark.asyncio
async def test_cleanup_deadline_marks_hung_observations_false_and_cancels_them() -> None:
    arguments = session_arguments()
    clock = FakeClock()
    media = BlockingCleanupMedia()
    arguments.update(media=media, clock=clock)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    stop_task = asyncio.create_task(session.stop(PttStopSource.WATCHDOG))
    await media.started.wait()
    clock.advance_to(12.0)
    for _attempt in range(10):
        if media.cancelled == 4:
            break
        await asyncio.sleep(0)
    media.release.set()
    receipt = await stop_task

    assert clock.deadlines == [12.0]
    assert receipt.recording_stopped is False
    assert receipt.playback_stopped is False
    assert receipt.motion_stopped is False
    assert receipt.audio_reactive_disabled is False
    assert media.cancelled == 4
    assert media.completed == 0
    assert not {
        task.get_name()
        for task in asyncio.all_tasks()
        if task is not asyncio.current_task()
        and task.get_name() in {"recording", "playback", "motion", "audio_reactive"}
    }


@pytest.mark.asyncio
async def test_cleanup_observations_completing_at_exact_t_plus_two_remain_false() -> None:
    clock = FakeClock()
    media = BlockingCleanupMedia()
    arguments = session_arguments()
    arguments.update(clock=clock, media=media)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    stop_task = asyncio.create_task(
        session.stop(PttStopSource.WATCHDOG),
        name="test-reachy-ptt-stop",
    )
    try:
        await asyncio.wait_for(media.started.wait(), timeout=0.2)
        clock.current = 12.0
        media.release.set()

        receipt = await asyncio.wait_for(stop_task, timeout=0.2)

        assert receipt.recording_stopped is False
        assert receipt.playback_stopped is False
        assert receipt.motion_stopped is False
        assert receipt.audio_reactive_disabled is False
        assert receipt.is_complete() is False
        assert media.completed == 4
    finally:
        media.release.set()
        if not stop_task.done():
            stop_task.cancel()
        await asyncio.gather(stop_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_cleanup_spawner_failure_uses_fallback_without_suppressing_siblings() -> None:
    arguments = session_arguments()
    media = FakeMedia()
    spawner = OneFailureCleanupTaskSpawner("motion")
    arguments.update(media=media, task_spawner=spawner)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    receipt = await session.stop(PttStopSource.SUPERVISOR_INPUT)

    assert receipt.is_complete()
    assert media.cleanup_calls == ["recording", "playback", "motion", "audio_reactive"]
    assert spawner.names == ["recording", "playback", "motion", "audio_reactive"]


@pytest.mark.asyncio
async def test_synchronous_cleanup_factory_failure_does_not_suppress_siblings() -> None:
    arguments = session_arguments()
    media = SynchronousFactoryFailureMedia()
    arguments["media"] = media
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    receipt = await session.stop(PttStopSource.SUPERVISOR_INPUT)

    assert receipt.recording_stopped is True
    assert receipt.playback_stopped is True
    assert receipt.motion_stopped is False
    assert receipt.audio_reactive_disabled is True
    assert media.cleanup_calls == ["recording", "playback", "audio_reactive"]


@pytest.mark.asyncio
async def test_cancelled_stop_caller_waits_for_cleanup_then_reraises_and_caches() -> None:
    arguments = session_arguments()
    media = BlockingCleanupMedia()
    arguments["media"] = media
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    caller = asyncio.create_task(session.stop(PttStopSource.SUPERVISOR_INPUT))
    await media.started.wait()
    caller.cancel()
    await asyncio.sleep(0)
    assert not caller.done()
    media.release.set()
    with pytest.raises(asyncio.CancelledError):
        await caller

    receipt = await session.stop(PttStopSource.WATCHDOG)
    assert receipt.is_complete()
    assert media.completed == 4


@pytest.mark.asyncio
async def test_stop_cancellation_while_waiting_lifecycle_lock_cannot_bypass_cleanup() -> None:
    media = BlockingCleanupMedia()
    transport = FakeTransport()
    arguments = session_arguments()
    arguments.update(media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    await session._lifecycle_lock.acquire()
    lock_held = True
    caller = asyncio.create_task(
        session.stop(PttStopSource.SUPERVISOR_INPUT),
        name="test-reachy-ptt-stop",
    )
    try:
        await asyncio.sleep(0)
        caller.cancel()
        await asyncio.sleep(0)
        caller.cancel()
        await asyncio.sleep(0)

        assert caller.done() is False
        assert session._cleanup_started_at is None

        session._lifecycle_lock.release()
        lock_held = False
        await asyncio.wait_for(media.started.wait(), timeout=0.2)
        assert caller.done() is False
        media.release.set()

        with pytest.raises(asyncio.CancelledError):
            await caller
        receipt = await session.stop(PttStopSource.WATCHDOG)

        assert receipt.is_complete()
        assert sorted(media.cleanup_calls) == [
            "audio_reactive",
            "motion",
            "playback",
            "recording",
        ]
        assert media.cancelled == 0
        assert media.completed == 4
        assert transport.receive_calls == 0
        assert transport.sent == []
        assert transport.close_calls == 0
    finally:
        media.release.set()
        if lock_held:
            session._lifecycle_lock.release()
        if not caller.done():
            caller.cancel()
        await asyncio.gather(caller, return_exceptions=True)


@pytest.mark.asyncio
async def test_terminal_turn_rechunks_capture_and_completes_one_guarded_duplex_session() -> None:
    events: list[str] = []
    capture_pcm = b"\x01\x00" * 3_501
    playback_pcm = b"\x02\x00" * 80
    media = HappyTurnMedia(events, (capture_pcm,))
    transport = ScriptedHappyTransport(
        PttInputMode.CORE_TERMINAL_TOGGLE,
        events,
        playback_pcm,
    )
    arguments = session_arguments()
    capture_buffer = FakeBuffer()
    playback_buffer = FakeBuffer()
    arguments.update(
        media=media,
        transport=transport,
        capture_buffer=capture_buffer,
        playback_buffer=playback_buffer,
    )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    outcome = await session.run()

    assert outcome is PttSessionOutcome.COMPLETED
    assert [frame.sequence for frame in transport.edge_frames] == list(
        range(len(transport.edge_frames))
    )
    assert [len(frame.pcm) for frame in transport.edge_frames if isinstance(frame, PcmFrame)] == [
        6_400,
        602,
    ]
    assert events.index("media:open_capture") < events.index("sent:capture_start")
    assert events.index("media:close_capture") < events.index("sent:capture_end")
    assert media.playback == [playback_pcm]
    assert (
        sum(
            isinstance(frame, ControlFrame) and frame.control.kind is ControlKind.SAFETY_RECEIPT
            for frame in transport.edge_frames
        )
        == 1
    )
    assert transport.close_calls == 1
    assert capture_buffer.clear_calls == 2
    assert playback_buffer.clear_calls == 2
    with pytest.raises(RuntimeError):
        await session.run()


@pytest.mark.asyncio
async def test_reachy_local_turn_uses_only_proved_local_capture_and_stop_inputs() -> None:
    events: list[str] = []
    capture_pcm = b"\x03\x00" * 40
    playback_pcm = b"\x04\x00" * 40
    media = HappyTurnMedia(events, (capture_pcm,))
    transport = ScriptedHappyTransport(PttInputMode.REACHY_LOCAL, events, playback_pcm)
    capture_input = ImmediateCaptureInput(events)
    stop_input = BlockingStopInput()
    arguments = session_arguments()
    arguments.update(
        input_mode=PttInputMode.REACHY_LOCAL,
        media=media,
        transport=transport,
        capture_input=capture_input,
        stop_input=stop_input,
    )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    outcome = await session.run()

    assert outcome is PttSessionOutcome.COMPLETED
    assert events.index("input:start") < events.index("media:open_capture")
    assert events.index("input:submit") < events.index("media:close_capture")
    assert media.playback == [playback_pcm]
    assert stop_input.cancelled is True
    assert all(
        not isinstance(frame, ControlFrame)
        or frame.control.kind not in {ControlKind.PTT_START, ControlKind.PTT_SUBMIT}
        for frame in transport.edge_frames
    )


@pytest.mark.asyncio
async def test_reachy_local_stop_preempts_capture_and_precedes_truthful_receipt() -> None:
    events: list[str] = []
    media = StopReleasesCaptureMedia(events)
    transport = ScriptedHappyTransport(PttInputMode.REACHY_LOCAL, events, b"")
    stop_input = BlockingStopInput()
    arguments = session_arguments()
    arguments.update(
        input_mode=PttInputMode.REACHY_LOCAL,
        media=media,
        transport=transport,
        capture_input=ImmediateCaptureInput(events),
        stop_input=stop_input,
    )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run())
    await media.read_started.wait()

    stop_input.release.set()
    outcome = await run_task

    assert outcome is PttSessionOutcome.CANCELLED
    controls = [
        frame.control.kind for frame in transport.edge_frames if isinstance(frame, ControlFrame)
    ]
    assert controls.count(ControlKind.STOP) == 1
    assert controls.count(ControlKind.SAFETY_RECEIPT) == 1
    assert controls.index(ControlKind.STOP) < controls.index(ControlKind.SAFETY_RECEIPT)
    assert ControlKind.CAPTURE_END not in controls


@pytest.mark.asyncio
async def test_capture_close_failure_sends_guarded_error_before_receipt() -> None:
    events: list[str] = []
    media = CaptureCloseFailureMedia(events, (b"\x05\x00" * 40,))
    transport = ScriptedHappyTransport(PttInputMode.REACHY_LOCAL, events, b"")
    arguments = session_arguments()
    arguments.update(
        input_mode=PttInputMode.REACHY_LOCAL,
        media=media,
        transport=transport,
        capture_input=ImmediateCaptureInput(events),
        stop_input=BlockingStopInput(),
    )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    outcome = await session.run()

    assert outcome is PttSessionOutcome.CAPTURE_FAILED
    controls = [frame.control for frame in transport.edge_frames if isinstance(frame, ControlFrame)]
    assert [control.kind for control in controls[-2:]] == [
        ControlKind.ERROR,
        ControlKind.SAFETY_RECEIPT,
    ]
    assert isinstance(controls[-2].payload, ErrorPayload)
    assert controls[-2].payload.reason_code is PttErrorReason.CAPTURE_FAILED


@pytest.mark.asyncio
async def test_failed_active_send_drains_waiting_receipt_and_finishes_teardown() -> None:
    events: list[str] = []
    transport = BlockingFailingPcmTransport(events)
    media = HappyTurnMedia(events, (b"\x06\x00" * 40,))
    arguments = session_arguments()
    arguments.update(media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await transport.pcm_send_started.wait()
        transport.queue_core_abort()
        for _ in range(20):
            if len(media.cleanup_calls) == 4:
                break
            await asyncio.sleep(0)
        assert len(media.cleanup_calls) == 4
        for _ in range(20):
            if session._terminal_queue:
                break
            await asyncio.sleep(0)
        assert len(session._terminal_queue) == 1

        transport.fail_send.set()
        done, _pending = await asyncio.wait({run_task}, timeout=0.2)
        assert run_task in done
        assert run_task.result() is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert transport.close_calls == 1
        assert not session._terminal_queue
        await asyncio.sleep(0)
        assert not {
            task.get_name()
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
        }
    finally:
        if not run_task.done():
            cleanup_task = session._cleanup_task
            if cleanup_task is not None:
                cleanup_task.cancel()
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("blocked_stage", ("open", "read"))
async def test_cleanup_cancels_owned_capture_worker_without_post_latch_effects(
    blocked_stage: str,
) -> None:
    events: list[str] = []
    media = BlockingCaptureStageMedia(events, blocked_stage)
    transport = ScriptedHappyTransport(PttInputMode.REACHY_LOCAL, events, b"")
    stop_input = BlockingStopInput()
    capture_buffer = FakeBuffer()
    arguments = session_arguments()
    arguments.update(
        input_mode=PttInputMode.REACHY_LOCAL,
        media=media,
        transport=transport,
        capture_input=ImmediateCaptureInput(events),
        stop_input=stop_input,
        capture_buffer=capture_buffer,
    )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await media.stage_started.wait()
        stop_input.release.set()

        done, _pending = await asyncio.wait({run_task}, timeout=0.2)
        assert run_task in done
        assert run_task.result() is PttSessionOutcome.CANCELLED
        assert media.stage_cancelled is True
        assert session._capture_gate is False
        assert capture_buffer.is_empty()
        controls = [
            frame.control.kind for frame in transport.edge_frames if isinstance(frame, ControlFrame)
        ]
        stop_index = controls.index(ControlKind.STOP)
        assert ControlKind.CAPTURE_END not in controls[stop_index + 1 :]
        assert not any(
            isinstance(frame, PcmFrame) for frame in transport.edge_frames[stop_index + 1 :]
        )
        await asyncio.sleep(0)
        assert not {
            task.get_name()
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
        }
    finally:
        if not run_task.done():
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_cleanup_preempts_handshake_wait_without_advancing_handshake_clock() -> None:
    transport = SilentAckTransport()
    stop_input = BlockingStopInput()
    arguments = session_arguments()
    arguments.update(
        input_mode=PttInputMode.REACHY_LOCAL,
        transport=transport,
        capture_input=ImmediateCaptureInput([]),
        stop_input=stop_input,
    )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await stop_input.started.wait()
        stop_input.release.set()

        done, _pending = await asyncio.wait({run_task}, timeout=0.2)
        assert run_task in done
        assert run_task.result() is PttSessionOutcome.CANCELLED
        assert [
            frame.control.kind for frame in transport.edge_frames if isinstance(frame, ControlFrame)
        ] == [ControlKind.STOP, ControlKind.SAFETY_RECEIPT]
        assert session._clock_faulted is False
    finally:
        if not run_task.done():
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_session_ready_send_cannot_cross_original_t0_plus_five() -> None:
    clock = FakeClock()
    transport = BlockingReadyTransport()
    arguments = session_arguments()
    arguments.update(clock=clock, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        for _ in range(20):
            if transport.receive_calls:
                break
            await asyncio.sleep(0)
        assert transport.receive_calls > 0
        clock.current = 14.9
        transport.inbound.put_nowait(
            encode_control_frame(
                sequence=0,
                control=PttControl.session_open(TURN_ID, PttInputMode.CORE_TERMINAL_TOGGLE),
            )
        )
        await transport.ready_send_started.wait()

        clock.advance_to(15.0)
        done, _pending = await asyncio.wait({run_task}, timeout=0.2)

        assert run_task in done
        assert run_task.result() is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert transport.ready_send_cancelled is True
        assert not transport.edge_frames
        assert transport.close_calls == 1
    finally:
        transport.release_ready.set()
        if not run_task.done():
            await session.stop(PttStopSource.SUPERVISOR_INPUT)
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_no_session_open_at_exact_t0_plus_five_is_session_timeout() -> None:
    clock = FakeClock()
    transport = SilentAckTransport()
    arguments = session_arguments()
    arguments.update(clock=clock, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        for _ in range(20):
            if 15.0 in clock.deadlines:
                break
            await asyncio.sleep(0)
        assert 15.0 in clock.deadlines

        clock.advance_to(15.0)
        outcome = await run_task

        assert outcome is PttSessionOutcome.SESSION_TIMEOUT
        controls = [
            frame.control for frame in transport.edge_frames if isinstance(frame, ControlFrame)
        ]
        assert ControlKind.SESSION_READY not in {control.kind for control in controls}
        errors = [control.payload for control in controls if control.kind is ControlKind.ERROR]
        assert len(errors) == 1
        assert isinstance(errors[0], ErrorPayload)
        assert errors[0].reason_code is PttErrorReason.SESSION_TIMEOUT
    finally:
        if not run_task.done():
            await session.stop(PttStopSource.SUPERVISOR_INPUT)
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("complete_receipt", "ack", "expect_poison"),
    ((True, False, False), (False, False, False), (False, True, True)),
)
async def test_session_ack_truth_table_is_fail_closed_without_duplicate_receipt(
    complete_receipt: bool,
    ack: bool,
    expect_poison: bool,
) -> None:
    transport = ReceiptPolicyTransport(ack=ack)
    media: HappyTurnMedia
    if complete_receipt:
        media = HappyTurnMedia([], (b"\x1a\x00" * 40,))
    else:
        media = IncompleteReceiptMedia([], (b"\x1a\x00" * 40,))
    arguments = session_arguments()
    arguments.update(media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    outcome = await session.run()

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert transport.receipt_send_attempts == 1
    assert (
        sum(
            isinstance(frame, ControlFrame) and frame.control.kind is ControlKind.SAFETY_RECEIPT
            for frame in transport.edge_frames
        )
        == 1
    )
    assert session._guard_poisoned is expect_poison
    assert session._ack_accepted is (ack if not expect_poison else None)


@pytest.mark.asyncio
@pytest.mark.parametrize("ack_timing", ("missing", "exact_deadline"))
async def test_missing_or_exact_deadline_ack_is_cleanup_incomplete(
    ack_timing: str,
) -> None:
    clock = FakeClock()
    transport = ReceiptPolicyTransport(ack=None)
    media = HappyTurnMedia([], (b"\x1b\x00" * 40,))
    arguments = session_arguments()
    arguments.update(clock=clock, media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await transport.receipt_send_started.wait()
        cleanup_started_at = session._cleanup_started_at
        assert cleanup_started_at is not None
        deadline = cleanup_started_at + 3.5
        for _ in range(20):
            if deadline in clock.deadlines:
                break
            await asyncio.sleep(0)
        assert deadline in clock.deadlines
        if ack_timing == "exact_deadline":
            transport._queue_control(PttControl.safety_ack(TURN_ID, accepted=True))
        clock.advance_to(deadline)

        outcome = await run_task

        assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert transport.receipt_send_attempts == 1
        assert (
            sum(
                isinstance(frame, ControlFrame) and frame.control.kind is ControlKind.SAFETY_RECEIPT
                for frame in transport.edge_frames
            )
            == 1
        )
    finally:
        if not run_task.done():
            await session.stop(PttStopSource.SUPERVISOR_INPUT)
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_receipt_send_failure_attempts_no_second_receipt() -> None:
    transport = ReceiptPolicyTransport(ack=None, receipt_behavior="raise")
    media = HappyTurnMedia([], (b"\x1c\x00" * 40,))
    arguments = session_arguments()
    arguments.update(media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    outcome = await session.run()

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert transport.receipt_send_attempts == 1
    assert not any(
        isinstance(frame, ControlFrame) and frame.control.kind is ControlKind.SAFETY_RECEIPT
        for frame in transport.edge_frames
    )


@pytest.mark.asyncio
async def test_receipt_send_timeout_uses_absolute_t0_plus_2_5_bound() -> None:
    clock = FakeClock()
    transport = ReceiptPolicyTransport(ack=None, receipt_behavior="block")
    media = BlockingReceiptCleanupMedia()
    arguments = session_arguments()
    arguments.update(clock=clock, media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await media.cleanup_started.wait()
        cleanup_started_at = session._cleanup_started_at
        assert cleanup_started_at == 10.0
        clock.advance_to(12.0)
        await transport.receipt_send_started.wait()

        clock.advance_to(12.5)
        outcome = await run_task

        assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert transport.receipt_send_attempts == 1
        assert transport.receipt_send_cancelled is True
        assert transport.close_calls == 1
    finally:
        transport.release_receipt.set()
        if not run_task.done():
            await session.stop(PttStopSource.SUPERVISOR_INPUT)
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_cancelled_runtime_stop_waits_through_writer_lock_and_finishes_cleanup() -> None:
    transport = SilentAckTransport()
    media = FakeMedia()
    arguments = session_arguments()
    arguments.update(media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    stop_task: asyncio.Task[object] | None = None
    lock_held = False
    try:
        for _ in range(20):
            if session._reader_task is not None:
                break
            await asyncio.sleep(0)
        assert session._reader_task is not None
        await session._writer_lock.acquire()
        lock_held = True
        stop_task = asyncio.create_task(
            session.stop(PttStopSource.SUPERVISOR_INPUT),
            name="test-reachy-ptt-stop",
        )
        for _ in range(5):
            await asyncio.sleep(0)

        stop_task.cancel()
        await asyncio.sleep(0)
        assert stop_task.done() is False
        assert session._cleanup_started_at is None

        session._writer_lock.release()
        lock_held = False
        with pytest.raises(asyncio.CancelledError):
            await stop_task
        outcome = await run_task

        assert outcome is PttSessionOutcome.CANCELLED
        assert sorted(media.cleanup_calls) == [
            "audio_reactive",
            "motion",
            "playback",
            "recording",
        ]
        controls = [
            frame.control.kind for frame in transport.edge_frames if isinstance(frame, ControlFrame)
        ]
        assert controls == [ControlKind.STOP, ControlKind.SAFETY_RECEIPT]
        cached = await session.stop(PttStopSource.SUPERVISOR_INPUT)
        assert session._cleanup_task is not None
        assert cached is session._cleanup_task.result()
        assert transport.close_calls == 1
    finally:
        if lock_held:
            session._writer_lock.release()
        if stop_task is not None and not stop_task.done():
            stop_task.cancel()
            await asyncio.gather(stop_task, return_exceptions=True)
        if not run_task.done():
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("caller_kind", ("stop", "run"))
async def test_cleanup_request_task_creation_failure_latches_inline_and_resists_cancellation(
    monkeypatch: pytest.MonkeyPatch,
    caller_kind: str,
) -> None:
    original_create_task = asyncio.create_task
    creation_failed = asyncio.Event()

    def fail_cleanup_request_task(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        if name == "reachy-ptt-cleanup-request" and not creation_failed.is_set():
            creation_failed.set()
            coroutine.close()
            raise RuntimeError("injected cleanup-request creation failure")
        if context is None:
            return original_create_task(coroutine, name=name)
        return original_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(asyncio, "create_task", fail_cleanup_request_task)
    media = FakeMedia()
    transport = SilentAckTransport()
    arguments = session_arguments()
    arguments.update(media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    writer_lock_held = False
    caller_task: asyncio.Task[Any] | None = None
    try:
        for _attempt in range(20):
            if session._reader_task is not None:
                break
            await asyncio.sleep(0)
        assert session._reader_task is not None
        cleanup_identity = session._cleanup_task
        assert cleanup_identity is not None

        await session._writer_lock.acquire()
        writer_lock_held = True
        if caller_kind == "stop":
            caller_task = asyncio.create_task(
                session.stop(PttStopSource.SUPERVISOR_INPUT),
                name="test-reachy-ptt-stop",
            )
        else:
            caller_task = run_task
            run_task.cancel()
        await asyncio.wait_for(creation_failed.wait(), timeout=0.2)

        assert caller_task.done() is False
        assert session._cleanup_started_at is None
        caller_task.cancel()
        await asyncio.sleep(0)
        caller_task.cancel()
        await asyncio.sleep(0)
        assert caller_task.done() is False
        assert session._cleanup_started_at is None

        session._writer_lock.release()
        writer_lock_held = False
        with pytest.raises(asyncio.CancelledError):
            await caller_task

        if caller_kind == "stop":
            assert await run_task is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert session._final_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert session._cleanup_source is PttStopSource.SUPERVISOR_INPUT
        assert session._semantic_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        receipt = await session.stop(PttStopSource.WATCHDOG)
        assert session._cleanup_task is cleanup_identity
        assert cleanup_identity.result() is receipt
        assert receipt.is_complete()
        assert sorted(media.cleanup_calls) == [
            "audio_reactive",
            "motion",
            "playback",
            "recording",
        ]
        assert transport.close_calls == 1
        await asyncio.sleep(0)
        assert not {
            task.get_name()
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
        }
    finally:
        if writer_lock_held:
            session._writer_lock.release()
        if caller_task is not None and not caller_task.done():
            caller_task.cancel()
        if not run_task.done():
            await session.stop(PttStopSource.SUPERVISOR_INPUT)
            run_task.cancel()
        await asyncio.gather(
            *(task for task in (caller_task, run_task) if task is not None),
            return_exceptions=True,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failed_owner",
    (
        "reachy-ptt-task-join",
        "reachy-ptt-task-join-deadline",
        "reachy-ptt-transport-close",
        "reachy-ptt-transport-close-deadline",
    ),
)
async def test_teardown_owner_creation_failure_uses_fresh_bounded_fallback(
    monkeypatch: pytest.MonkeyPatch,
    failed_owner: str,
) -> None:
    original_create_task = asyncio.create_task
    failure_count = 0

    def fail_one_teardown_owner(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        nonlocal failure_count
        if name == failed_owner and failure_count == 0:
            failure_count += 1
            raise RuntimeError("injected teardown-owner creation failure")
        if context is None:
            return original_create_task(coroutine, name=name)
        return original_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(asyncio, "create_task", fail_one_teardown_owner)
    media = FakeMedia()
    stop_input = BlockingStopInput()
    transport = SilentAckTransport()
    arguments = session_arguments()
    arguments.update(media=media, stop_input=stop_input, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        for _attempt in range(20):
            if session._reader_task is not None:
                break
            await asyncio.sleep(0)
        assert session._reader_task is not None
        await asyncio.wait_for(stop_input.started.wait(), timeout=0.2)
        cleanup_identity = session._cleanup_task
        assert cleanup_identity is not None

        receipt = await asyncio.wait_for(
            session.stop(PttStopSource.SUPERVISOR_INPUT),
            timeout=0.5,
        )
        outcome = await asyncio.wait_for(run_task, timeout=0.5)

        assert failure_count == 1
        assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert session._final_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert session._cleanup_task is cleanup_identity
        assert cleanup_identity.result() is receipt
        assert receipt.is_complete()
        assert sorted(media.cleanup_calls) == [
            "audio_reactive",
            "motion",
            "playback",
            "recording",
        ]
        assert stop_input.cancelled is True
        assert transport.close_calls == 1
        await asyncio.sleep(0)
        assert not {
            task.get_name()
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
        }
    finally:
        if not run_task.done():
            await session.stop(PttStopSource.SUPERVISOR_INPUT)
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_teardown_does_not_retry_ambiguous_transport_close_failure() -> None:
    transport = FailingCloseTransport()
    arguments = session_arguments()
    arguments["transport"] = transport
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        for _attempt in range(20):
            if session._reader_task is not None:
                break
            await asyncio.sleep(0)
        assert session._reader_task is not None

        await asyncio.wait_for(
            session.stop(PttStopSource.SUPERVISOR_INPUT),
            timeout=0.5,
        )
        outcome = await asyncio.wait_for(run_task, timeout=0.5)

        assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert transport.close_calls == 1
        await asyncio.sleep(0)
        assert not {
            task.get_name()
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
        }
    finally:
        if not run_task.done():
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_repeated_run_cancellation_cannot_escape_before_cleanup_latch_and_join() -> None:
    transport = SilentAckTransport()
    arguments = session_arguments()
    arguments["transport"] = transport
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    await session._writer_lock.acquire()
    try:
        for _ in range(20):
            if transport.receive_calls:
                break
            await asyncio.sleep(0)
        assert transport.receive_calls == 1

        run_task.cancel()
        for _ in range(100):
            waiters = session._writer_lock._waiters  # type: ignore[attr-defined]
            if waiters and any(not waiter.done() for waiter in waiters):
                break
            await asyncio.sleep(0)
        waiters = session._writer_lock._waiters  # type: ignore[attr-defined]
        assert waiters and any(not waiter.done() for waiter in waiters)
        assert run_task.done() is False
        assert session._cleanup_started_at is None

        run_task.cancel()
        for _ in range(5):
            await asyncio.sleep(0)

        assert run_task.done() is False
        assert session._cleanup_started_at is None
    finally:
        session._writer_lock.release()

    with pytest.raises(asyncio.CancelledError):
        await run_task

    assert session._cleanup_started_at is not None
    assert transport.close_calls == 1
    controls = [
        frame.control.kind for frame in transport.edge_frames if isinstance(frame, ControlFrame)
    ]
    assert controls == [ControlKind.STOP, ControlKind.SAFETY_RECEIPT]
    await asyncio.sleep(0)
    assert not {
        task.get_name()
        for task in asyncio.all_tasks()
        if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "expected_outcome"),
    (
        ("runtime", PttSessionOutcome.CLEANUP_INCOMPLETE),
        ("timeout", PttSessionOutcome.SESSION_TIMEOUT),
    ),
)
async def test_cancellation_inside_run_error_handler_waits_for_shared_cleanup(
    failure: str,
    expected_outcome: PttSessionOutcome,
) -> None:
    transport = SilentAckTransport()
    arguments = session_arguments()
    arguments["transport"] = transport
    session = MainBodyFailureSession(failure=failure, **arguments)
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    await session.main_body_entered.wait()
    await session._writer_lock.acquire()
    try:
        session.release_failure.set()
        for _ in range(100):
            waiters = session._writer_lock._waiters  # type: ignore[attr-defined]
            if waiters and any(not waiter.done() for waiter in waiters):
                break
            await asyncio.sleep(0)
        waiters = session._writer_lock._waiters  # type: ignore[attr-defined]
        assert waiters and any(not waiter.done() for waiter in waiters)

        run_task.cancel()
        await asyncio.sleep(0)
        run_task.cancel()
        for _ in range(5):
            await asyncio.sleep(0)

        assert run_task.done() is False
        assert session._cleanup_started_at is None
    finally:
        session._writer_lock.release()

    with pytest.raises(asyncio.CancelledError):
        await run_task

    assert session._cleanup_source is PttStopSource.WATCHDOG
    assert session._semantic_outcome is expected_outcome
    assert transport.close_calls == 1
    await asyncio.sleep(0)
    assert not {
        task.get_name()
        for task in asyncio.all_tasks()
        if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
    }


@pytest.mark.asyncio
async def test_concurrent_runtime_stops_share_one_receipt_and_cleanup() -> None:
    transport = SilentAckTransport()
    media = FakeMedia()
    arguments = session_arguments()
    arguments.update(media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        for _ in range(20):
            if session._reader_task is not None:
                break
            await asyncio.sleep(0)
        assert session._reader_task is not None
        stop_tasks = [
            asyncio.create_task(
                session.stop(PttStopSource.SUPERVISOR_INPUT),
                name=f"test-reachy-ptt-stop-{index}",
            )
            for index in range(3)
        ]

        receipts = await asyncio.gather(*stop_tasks)
        outcome = await run_task
        repeated = await session.stop(PttStopSource.SUPERVISOR_INPUT)

        assert outcome is PttSessionOutcome.CANCELLED
        assert all(receipt is receipts[0] for receipt in receipts)
        assert repeated is receipts[0]
        assert len(media.cleanup_calls) == 4
        controls = [
            frame.control.kind for frame in transport.edge_frames if isinstance(frame, ControlFrame)
        ]
        assert controls == [ControlKind.STOP, ControlKind.SAFETY_RECEIPT]
        assert transport.close_calls == 1
    finally:
        if not run_task.done():
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_simultaneous_cleanup_sources_preserve_first_latch_and_shared_identity() -> None:
    events: list[str] = []
    media = LatePoisonMedia(events)
    transport = ScriptedHappyTransport(
        PttInputMode.CORE_TERMINAL_TOGGLE,
        events,
        b"",
        auto_submit=False,
    )
    arguments = session_arguments()
    arguments.update(media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    winner_gate = asyncio.Event()
    loser_gate = asyncio.Event()
    identities: dict[str, asyncio.Future[PttSafetyReceipt] | None] = {}

    async def local_stop_winner() -> PttSafetyReceipt:
        await winner_gate.wait()
        try:
            return await session.stop(PttStopSource.SUPERVISOR_INPUT)
        finally:
            identities["local_stop"] = session._cleanup_task

    async def late_submit() -> None:
        await loser_gate.wait()
        try:
            await session._dispatch_core_frame(
                ControlFrame(
                    turn_id=TURN_ID,
                    sequence=2,
                    control=PttControl.ptt_submit(TURN_ID),
                )
            )
        finally:
            identities["submit"] = session._cleanup_task

    async def late_core_abort() -> None:
        await loser_gate.wait()
        try:
            await session._dispatch_core_frame(
                ControlFrame(
                    turn_id=TURN_ID,
                    sequence=3,
                    control=PttControl.abort(TURN_ID, PttErrorReason.TURN_CANCELLED),
                )
            )
        finally:
            identities["core_abort"] = session._cleanup_task

    async def late_eof() -> None:
        await loser_gate.wait()
        try:
            await session._request_cleanup(
                PttStopSource.PEER_EOF,
                PttSessionOutcome.PEER_CLOSED,
            )
        finally:
            identities["eof"] = session._cleanup_task

    async def late_watchdog() -> None:
        await loser_gate.wait()
        try:
            await session._request_cleanup(
                PttStopSource.WATCHDOG,
                PttSessionOutcome.SESSION_TIMEOUT,
            )
        finally:
            identities["watchdog"] = session._cleanup_task

    async def late_malformed_input() -> None:
        await loser_gate.wait()
        try:
            transport.inbound.put_nowait(b"NOPE" + b"\x00" * 28)
            await session._protocol_poisoned.wait()
        finally:
            identities["malformed"] = session._cleanup_task

    winner_task = asyncio.create_task(local_stop_winner(), name="test-local-stop-winner")
    loser_tasks = [
        asyncio.create_task(late_submit(), name="test-late-submit"),
        asyncio.create_task(late_core_abort(), name="test-late-core-abort"),
        asyncio.create_task(late_eof(), name="test-late-eof"),
        asyncio.create_task(late_watchdog(), name="test-late-watchdog"),
        asyncio.create_task(late_malformed_input(), name="test-late-malformed"),
    ]
    try:
        await media.read_started.wait()
        cleanup_identity = session._cleanup_task
        assert cleanup_identity is not None

        winner_gate.set()
        for _attempt in range(10):
            await asyncio.sleep(0)
            if session._cleanup_started_at is not None:
                break
        assert session._cleanup_started_at is not None
        assert session._cleanup_source is PttStopSource.SUPERVISOR_INPUT
        assert session._semantic_outcome is PttSessionOutcome.CANCELLED

        loser_gate.set()
        await asyncio.wait_for(session._protocol_poisoned.wait(), timeout=0.2)
        loser_results = await asyncio.gather(*loser_tasks, return_exceptions=True)

        assert loser_results == [None, None, None, None, None]
        assert session._cleanup_source is PttStopSource.SUPERVISOR_INPUT
        assert session._semantic_outcome is PttSessionOutcome.CANCELLED
        assert session._capture_gate is False
        assert session._playback_gate is False
        assert session._terminal is True
        assert set(identities) == {
            "submit",
            "core_abort",
            "eof",
            "watchdog",
            "malformed",
        }
        assert all(identity is cleanup_identity for identity in identities.values())

        await media.started.wait()
        assert sorted(media.cleanup_calls) == [
            "audio_reactive",
            "motion",
            "playback",
            "recording",
        ]
        assert media.cancelled == 0
        media.release.set()

        winner_receipt = await winner_task
        outcome = await run_task

        assert identities["local_stop"] is cleanup_identity
        assert cleanup_identity.result() is winner_receipt
        assert winner_receipt.is_complete()
        assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert media.completed == 4
        receipts = [
            frame
            for frame in transport.edge_frames
            if isinstance(frame, ControlFrame) and frame.control.kind is ControlKind.SAFETY_RECEIPT
        ]
        receipt_drafts = [
            draft
            for draft in session._terminal_drafts
            if draft.control is not None and draft.control.kind is ControlKind.SAFETY_RECEIPT
        ]
        assert len(receipts) <= 1
        assert len(receipt_drafts) <= 1
        assert not receipts or session._receipt_attempted is True
        assert transport.close_calls == 1
        await asyncio.sleep(0)
        assert not {
            task.get_name()
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
        }
    finally:
        winner_gate.set()
        loser_gate.set()
        media.release.set()
        for task in (winner_task, run_task, *loser_tasks):
            if not task.done():
                task.cancel()
        await asyncio.gather(winner_task, run_task, *loser_tasks, return_exceptions=True)


@pytest.mark.asyncio
async def test_concurrent_and_repeated_run_losers_have_no_effects() -> None:
    transport = SilentAckTransport()
    arguments = session_arguments()
    arguments.update(transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    winning_run = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        for _ in range(20):
            if session._reader_task is not None:
                break
            await asyncio.sleep(0)
        assert session._reader_task is not None
        cleanup_identity = session._cleanup_task
        reader_identity = session._reader_task
        receive_calls = transport.receive_calls

        with pytest.raises(RuntimeError, match="PTT session is terminal"):
            await session.run()

        assert session._cleanup_task is cleanup_identity
        assert session._reader_task is reader_identity
        assert transport.receive_calls == receive_calls
        await session.stop(PttStopSource.SUPERVISOR_INPUT)
        assert await winning_run is PttSessionOutcome.CANCELLED
        close_calls = transport.close_calls

        with pytest.raises(RuntimeError, match="PTT session is terminal"):
            await session.run()
        assert transport.close_calls == close_calls
    finally:
        if not winning_run.done():
            winning_run.cancel()
            await asyncio.gather(winning_run, return_exceptions=True)


@pytest.mark.asyncio
async def test_stop_between_cleanup_install_and_child_creation_starts_no_late_child() -> None:
    transport = SilentAckTransport()
    arguments = session_arguments()
    arguments.update(transport=transport)
    session = ChildCreationRecordingSession(**arguments)
    barrier = FirstExitBarrierLock()
    session._lifecycle_lock = barrier  # type: ignore[assignment]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    stop_task: asyncio.Task[object] | None = None
    try:
        await barrier.first_exit.wait()
        stop_task = asyncio.create_task(
            session.stop(PttStopSource.SUPERVISOR_INPUT),
            name="test-reachy-ptt-stop",
        )
        for _ in range(20):
            if session._cleanup_started_at is not None:
                break
            await asyncio.sleep(0)
        assert session._cleanup_started_at is not None

        barrier.release_first_exit.set()
        done, _pending = await asyncio.wait({stop_task, run_task}, timeout=0.2)

        assert done == {stop_task, run_task}
        receipt = stop_task.result()
        assert run_task.result() is PttSessionOutcome.CANCELLED
        assert session._cleanup_task is not None
        assert receipt is session._cleanup_task.result()
        assert session.children_created_after_latch == []
        assert transport.close_calls == 1
    finally:
        barrier.release_first_exit.set()
        if stop_task is not None and not stop_task.done():
            stop_task.cancel()
            await asyncio.gather(stop_task, return_exceptions=True)
        if not run_task.done():
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("watchdog", ("heartbeat", "turn"))
async def test_absolute_watchdogs_preempt_a_blocked_turn(watchdog: str) -> None:
    events: list[str] = []
    clock = FakeClock()
    arguments = session_arguments()
    if watchdog == "heartbeat":
        transport = ScriptedHappyTransport(
            PttInputMode.CORE_TERMINAL_TOGGLE,
            events,
            b"",
            auto_submit=False,
        )
        media: FakeMedia = BlockingCaptureStageMedia(events, "read")
        start_input = None
        arguments.update(media=media, transport=transport, clock=clock)
    else:
        transport = ScriptedHappyTransport(PttInputMode.REACHY_LOCAL, events, b"")
        media = FakeMedia()
        start_input = BlockingStartCaptureInput(events)
        arguments.update(
            input_mode=PttInputMode.REACHY_LOCAL,
            media=media,
            transport=transport,
            clock=clock,
            capture_input=start_input,
            stop_input=BlockingStopInput(),
        )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        if watchdog == "heartbeat":
            assert isinstance(media, BlockingCaptureStageMedia)
            await media.stage_started.wait()
            clock.advance_to(15.0)
        else:
            assert start_input is not None
            await start_input.started.wait()
            async with session._guard_lock:
                clock.current = 319.0
                session._last_valid_core_frame = 319.0
            assert session._last_valid_core_frame == 319.0
            clock.advance_to(320.0)

        done, _pending = await asyncio.wait({run_task}, timeout=0.2)
        assert run_task in done
        assert run_task.result() is PttSessionOutcome.SESSION_TIMEOUT
        errors = [
            frame.control.payload
            for frame in transport.edge_frames
            if isinstance(frame, ControlFrame) and frame.control.kind is ControlKind.ERROR
        ]
        assert len(errors) == 1
        assert isinstance(errors[0], ErrorPayload)
        assert errors[0].reason_code is PttErrorReason.SESSION_TIMEOUT
        if watchdog == "heartbeat":
            assert isinstance(media, BlockingCaptureStageMedia)
            assert media.stage_cancelled is True
        if watchdog == "turn":
            assert 320.0 in clock.deadlines
    finally:
        if not run_task.done():
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_310_second_turn_watchdog_covers_post_capture_playback_wait() -> None:
    events: list[str] = []
    clock = FakeClock()
    media = StopReleasesPlaybackOpenMedia(events)
    transport = ScriptedHappyTransport(
        PttInputMode.CORE_TERMINAL_TOGGLE,
        events,
        b"\x08\x00" * 40,
    )
    arguments = session_arguments()
    arguments.update(media=media, transport=transport, clock=clock)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await media.playback_open_started.wait()
        async with session._guard_lock:
            clock.current = 319.0
            session._last_valid_core_frame = 319.0
        assert clock.current == 319.0
        assert session._last_valid_core_frame == 319.0

        clock.advance_to(320.0)
        outcome = await run_task

        assert outcome is PttSessionOutcome.SESSION_TIMEOUT
        assert 320.0 in clock.deadlines
    finally:
        if not run_task.done():
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failed_task_name", "expected_close_calls"),
    (
        ("reachy-ptt-cleanup", 0),
        ("reachy-ptt-writer", 1),
        ("reachy-ptt-playback", 1),
        ("reachy-ptt-reader", 1),
        ("reachy-ptt-stop-input", 1),
        ("reachy-ptt-heartbeat-watchdog", 1),
        ("reachy-ptt-turn-watchdog", 1),
    ),
)
async def test_runtime_task_creation_failure_rolls_back_with_inline_local_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    failed_task_name: str,
    expected_close_calls: int,
) -> None:
    original_create_task = asyncio.create_task
    failed = False

    def fail_one_task(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        nonlocal failed
        if name == failed_task_name and not failed:
            failed = True
            coroutine.close()
            raise RuntimeError("injected runtime task creation failure")
        if context is None:
            return original_create_task(coroutine, name=name)
        return original_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(asyncio, "create_task", fail_one_task)
    media = FakeMedia()
    transport = FakeTransport()
    capture_buffer = FakeBuffer(b"capture")
    playback_buffer = FakeBuffer(b"playback")
    arguments = session_arguments()
    arguments.update(
        media=media,
        transport=transport,
        capture_buffer=capture_buffer,
        playback_buffer=playback_buffer,
    )
    if failed_task_name == "reachy-ptt-stop-input":
        arguments.update(
            input_mode=PttInputMode.REACHY_LOCAL,
            capture_input=ImmediateCaptureInput([]),
            stop_input=BlockingStopInput(),
        )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    outcome = await session.run()

    assert failed is True
    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert set(media.cleanup_calls) == {
        "recording",
        "playback",
        "motion",
        "audio_reactive",
    }
    assert capture_buffer.is_empty()
    assert playback_buffer.is_empty()
    assert transport.close_calls == expected_close_calls
    await asyncio.sleep(0)
    assert not {
        task.get_name()
        for task in asyncio.all_tasks()
        if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failed_owner",
    (
        "reachy-ptt-startup-task-join",
        "reachy-ptt-startup-task-join-deadline",
        "reachy-ptt-transport-close",
        "reachy-ptt-transport-close-deadline",
    ),
)
async def test_startup_rollback_owner_creation_failure_uses_fresh_bounded_fallback(
    monkeypatch: pytest.MonkeyPatch,
    failed_owner: str,
) -> None:
    original_create_task = asyncio.create_task
    failed_names: set[str] = set()

    def fail_runtime_child_and_one_rollback_owner(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        should_fail = name == "reachy-ptt-turn-watchdog" or name == failed_owner
        if should_fail and name not in failed_names:
            assert name is not None
            failed_names.add(name)
            raise RuntimeError("injected startup rollback owner failure")
        if context is None:
            return original_create_task(coroutine, name=name)
        return original_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(
        asyncio,
        "create_task",
        fail_runtime_child_and_one_rollback_owner,
    )
    transport = FakeTransport()
    arguments = session_arguments()
    arguments["transport"] = transport
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    original_join = session._join_tasks
    join_calls = 0

    async def record_join(tasks: list[asyncio.Task[Any]]) -> None:
        nonlocal join_calls
        join_calls += 1
        await original_join(tasks)

    session._join_tasks = record_join  # type: ignore[method-assign]

    outcome = await session.run()

    assert failed_names == {"reachy-ptt-turn-watchdog", failed_owner}
    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert join_calls == 1
    assert transport.close_calls == 1
    await asyncio.sleep(0)
    assert not {
        task.get_name()
        for task in asyncio.all_tasks()
        if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
    }


@pytest.mark.asyncio
async def test_startup_rollback_uses_bounded_direct_fallback_if_both_owners_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_create_task = asyncio.create_task
    failed_names: list[str] = []
    targets = {
        "reachy-ptt-turn-watchdog",
        "reachy-ptt-startup-rollback",
        "reachy-ptt-startup-rollback-fallback",
    }

    def fail_runtime_child_and_both_rollback_owners(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        if name in targets:
            assert name is not None
            failed_names.append(name)
            raise RuntimeError("injected persistent startup-rollback owner failure")
        if context is None:
            return original_create_task(coroutine, name=name)
        return original_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(
        asyncio,
        "create_task",
        fail_runtime_child_and_both_rollback_owners,
    )
    loop = asyncio.get_running_loop()
    original_loop_create_task = loop.create_task

    def fail_adopted_rollback_owner(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        if name == "reachy-ptt-startup-rollback-fallback":
            failed_names.append(name)
            raise RuntimeError("injected adopted startup-rollback owner failure")
        if context is None:
            return original_loop_create_task(coroutine, name=name)
        return original_loop_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(loop, "create_task", fail_adopted_rollback_owner)
    media = FakeMedia()
    transport = FakeTransport()
    arguments = session_arguments()
    arguments.update(media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    outcome = await session.run()

    assert failed_names == [
        "reachy-ptt-turn-watchdog",
        "reachy-ptt-startup-rollback",
        "reachy-ptt-startup-rollback-fallback",
    ]
    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert sorted(media.cleanup_calls) == [
        "audio_reactive",
        "motion",
        "playback",
        "recording",
    ]
    assert transport.close_calls == 1
    cleanup_identity = session._cleanup_task
    assert cleanup_identity is not None
    assert cleanup_identity.done()
    await asyncio.sleep(0)
    assert not {
        task.get_name()
        for task in asyncio.all_tasks()
        if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
    }


@pytest.mark.asyncio
async def test_double_owner_failure_does_not_expose_startup_rollback_to_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_create_task = asyncio.create_task
    loop = asyncio.get_running_loop()
    original_loop_create_task = loop.create_task
    failed_names: list[str] = []

    def fail_runtime_child_and_primary_rollback_owner(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        if name in {"reachy-ptt-turn-watchdog", "reachy-ptt-startup-rollback"}:
            assert name is not None
            failed_names.append(name)
            raise RuntimeError("injected primary rollback-owner failure")
        if context is None:
            return original_create_task(coroutine, name=name)
        return original_create_task(coroutine, name=name, context=context)

    def fail_adopted_rollback_owner(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        if name == "reachy-ptt-startup-rollback-fallback":
            failed_names.append(name)
            raise RuntimeError("injected adopted rollback-owner failure")
        if context is None:
            return original_loop_create_task(coroutine, name=name)
        return original_loop_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(asyncio, "create_task", fail_runtime_child_and_primary_rollback_owner)
    monkeypatch.setattr(loop, "create_task", fail_adopted_rollback_owner)
    media = BlockingCleanupMedia()
    transport = FakeTransport()
    arguments = session_arguments()
    arguments.update(media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = original_loop_create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await asyncio.wait_for(media.started.wait(), timeout=0.2)
        run_task.cancel()
        await asyncio.sleep(0)
        run_task.cancel()
        await asyncio.sleep(0)

        assert run_task.done() is False

        media.release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(run_task, timeout=0.2)

        assert failed_names == [
            "reachy-ptt-turn-watchdog",
            "reachy-ptt-startup-rollback",
            "reachy-ptt-startup-rollback-fallback",
        ]
        assert transport.close_calls == 1
        cleanup_identity = session._cleanup_task
        assert cleanup_identity is not None
        assert cleanup_identity.done()
        assert cleanup_identity.result().is_complete()
    finally:
        media.release.set()
        run_task.cancel()
        await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_run_cancellation_waits_for_bounded_startup_rollback_and_cached_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_create_task = asyncio.create_task
    child_failed = False

    def fail_turn_watchdog(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        nonlocal child_failed
        if name == "reachy-ptt-turn-watchdog" and not child_failed:
            child_failed = True
            raise RuntimeError("injected runtime-child creation failure")
        if context is None:
            return original_create_task(coroutine, name=name)
        return original_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(asyncio, "create_task", fail_turn_watchdog)
    clock = FakeClock()
    media = BlockingCleanupMedia()
    transport = BlockingCloseTransport()
    arguments = session_arguments()
    arguments.update(clock=clock, media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await asyncio.wait_for(media.started.wait(), timeout=0.2)
        run_task.cancel()
        await asyncio.sleep(0)
        run_task.cancel()
        await asyncio.sleep(0)
        assert run_task.done() is False

        media.release.set()
        await asyncio.wait_for(transport.close_started.wait(), timeout=0.2)
        assert run_task.done() is False
        assert transport.close_calls == 1

        clock.advance_to(14.0)
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(run_task, timeout=0.2)

        assert child_failed is True
        assert transport.close_cancelled is True
        assert transport.close_calls == 1
        cleanup_identity = session._cleanup_task
        assert cleanup_identity is not None
        receipt = cleanup_identity.result()
        assert receipt.is_complete()
        assert await session.stop(PttStopSource.WATCHDOG) is receipt
        assert sorted(media.cleanup_calls) == [
            "audio_reactive",
            "motion",
            "playback",
            "recording",
        ]
        await asyncio.sleep(0)
        assert not {
            task.get_name()
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
        }
    finally:
        media.release.set()
        clock.advance_to(14.0)
        owned = [
            task
            for task in (
                run_task,
                session._cleanup_task,
                *session._owned_runtime_tasks(),
            )
            if isinstance(task, asyncio.Task)
        ]
        for task in owned:
            if not task.done():
                task.cancel()
        await asyncio.gather(*owned, return_exceptions=True)


@pytest.mark.asyncio
async def test_startup_rollback_observes_local_cleanup_by_t_plus_two_while_joining_to_four() -> (
    None
):
    clock = FakeClock()
    media = BlockingCleanupMedia()
    transport = FakeTransport()
    arguments = session_arguments()
    arguments.update(clock=clock, media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    session._cleanup_started_at = 10.0
    prior_started = asyncio.Event()

    async def prior_child() -> None:
        prior_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await clock.sleep_until(14.0)

    session._reader_task = asyncio.create_task(prior_child(), name="reachy-ptt-reader")
    await prior_started.wait()
    rollback_task = asyncio.create_task(
        session._rollback_runtime_startup(close_transport=True),
        name="test-reachy-ptt-rollback",
    )
    try:
        await asyncio.wait_for(media.started.wait(), timeout=0.2)

        assert set(media.cleanup_calls) == {
            "recording",
            "playback",
            "motion",
            "audio_reactive",
        }
        assert clock.current == 10.0
        assert rollback_task.done() is False

        clock.advance_to(12.0)
        for _ in range(20):
            if media.cancelled == 4:
                break
            await asyncio.sleep(0)
        assert media.cancelled == 4
        assert rollback_task.done() is False

        clock.advance_to(14.0)
        await rollback_task

        assert session._reader_task.done()
        assert transport.close_calls == 0
        assert session._cleanup_task is not None
        receipt = session._cleanup_task.result()
        assert receipt.recording_stopped is False
        assert receipt.playback_stopped is False
        assert receipt.motion_stopped is False
        assert receipt.audio_reactive_disabled is False
    finally:
        if not rollback_task.done():
            clock.advance_to(14.0)
            await asyncio.gather(rollback_task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("receive_outcome", "expected_semantic", "expected_reason"),
    (
        ("eof", PttSessionOutcome.PEER_CLOSED, PttErrorReason.PEER_CLOSED),
        ("raise", PttSessionOutcome.PEER_CLOSED, PttErrorReason.PEER_CLOSED),
        (
            "non_bytes",
            PttSessionOutcome.CLEANUP_INCOMPLETE,
            PttErrorReason.CLEANUP_INCOMPLETE,
        ),
        (
            "oversized",
            PttSessionOutcome.CLEANUP_INCOMPLETE,
            PttErrorReason.CLEANUP_INCOMPLETE,
        ),
    ),
)
async def test_receive_closure_and_adapter_failures_do_not_poison_protocol(
    receive_outcome: str,
    expected_semantic: PttSessionOutcome,
    expected_reason: PttErrorReason,
) -> None:
    clock = FakeClock()
    transport = ReceiveOutcomeTransport(receive_outcome)
    arguments = session_arguments()
    arguments.update(clock=clock, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await transport.receipt_sent.wait()
        cleanup_started_at = session._cleanup_started_at
        assert cleanup_started_at is not None
        clock.advance_to(cleanup_started_at + 3.5)
        outcome = await run_task

        assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert session._semantic_outcome is expected_semantic
        assert session._guard_poisoned is False
        assert session._ack_received.is_set() is False
        controls = [
            frame.control for frame in transport.edge_frames if isinstance(frame, ControlFrame)
        ]
        assert [control.kind for control in controls] == [
            ControlKind.SESSION_READY,
            ControlKind.ERROR,
            ControlKind.SAFETY_RECEIPT,
        ]
        assert isinstance(controls[1].payload, ErrorPayload)
        assert controls[1].payload.reason_code is expected_reason
        assert transport.close_calls == 1
    finally:
        if not run_task.done():
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_receive_type_validation_precedes_hostile_equality_and_eof() -> None:
    clock = FakeClock()
    transport = ReceiveOutcomeTransport("hostile_eq")
    arguments = session_arguments()
    arguments.update(clock=clock, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await asyncio.wait_for(transport.ready_sent.wait(), timeout=0.2)
        for _attempt in range(20):
            reader = session._reader_task
            if reader is not None and reader.done():
                break
            await asyncio.sleep(0)
        reader = session._reader_task
        assert reader is not None
        assert reader.done()
        if session._cleanup_started_at is None:
            await session._request_cleanup(
                PttStopSource.SUPERVISOR_INPUT,
                PttSessionOutcome.CANCELLED,
            )
        await asyncio.wait_for(transport.receipt_sent.wait(), timeout=0.2)
        cleanup_started_at = session._cleanup_started_at
        assert cleanup_started_at is not None
        clock.advance_to(cleanup_started_at + 3.5)

        outcome = await asyncio.wait_for(run_task, timeout=0.2)

        assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert session._cleanup_source is PttStopSource.PEER_EOF
        assert session._semantic_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert session._guard_poisoned is False
        assert session._protocol_poisoned.is_set() is False
        assert transport.hostile_result.comparisons == 0
        errors = [
            frame.control.payload
            for frame in transport.edge_frames
            if isinstance(frame, ControlFrame) and frame.control.kind is ControlKind.ERROR
        ]
        assert len(errors) == 1
        assert isinstance(errors[0], ErrorPayload)
        assert errors[0].reason_code is PttErrorReason.CLEANUP_INCOMPLETE
        assert transport.close_calls == 1
    finally:
        if not run_task.done():
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_idle_protocol_poison_sends_emergency_error_before_truthful_receipt() -> None:
    transport = PoisonEmergencyTransport(truncated_eof=False)
    media = BlockingCleanupMedia()
    arguments = session_arguments()
    arguments.update(media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await transport.ready_sent.wait()
        for _ in range(20):
            if not session._active_send:
                break
            await asyncio.sleep(0)
        assert session._active_send is False
        transport.inject_poison()
        await media.started.wait()
        error_wait = asyncio.create_task(transport.error_sent.wait())
        done, _pending = await asyncio.wait({error_wait}, timeout=0.2)
        assert error_wait in done
        assert all(
            not isinstance(frame, ControlFrame)
            or frame.control.kind is not ControlKind.SAFETY_RECEIPT
            for frame in transport.edge_frames
        )

        media.release.set()
        outcome = await run_task

        assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        controls = [
            frame.control for frame in transport.edge_frames if isinstance(frame, ControlFrame)
        ]
        assert [control.kind for control in controls] == [
            ControlKind.SESSION_READY,
            ControlKind.ERROR,
            ControlKind.SAFETY_RECEIPT,
        ]
        assert isinstance(controls[1].payload, ErrorPayload)
        assert controls[1].payload.reason_code is PttErrorReason.PROTOCOL_REJECTED
        assert [frame.sequence for frame in transport.edge_frames] == [0, 1, 2]
        assert transport.receive_calls == 2
        assert transport.close_calls == 1
    finally:
        media.release.set()
        if not run_task.done():
            cleanup_task = session._cleanup_task
            if cleanup_task is not None:
                cleanup_task.cancel()
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_poison_drops_unsent_guarded_cleanup_before_emergency_pair() -> None:
    media = FakeMedia()
    transport = SilentAckTransport()
    arguments = session_arguments()
    arguments.update(media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    session._guard = PttDuplexGuard(
        turn_id=TURN_ID,
        input_mode=PttInputMode.CORE_TERMINAL_TOGGLE,
    )
    decoder = FrameDecoder()
    session._decoder = decoder
    coordinator = asyncio.create_task(
        session._cleanup_coordinator(),
        name="reachy-ptt-cleanup",
    )
    session._cleanup_task = coordinator
    writer: asyncio.Task[None] | None = None
    try:
        await session._request_cleanup(
            PttStopSource.SUPERVISOR_INPUT,
            PttSessionOutcome.CANCELLED,
        )
        for _attempt in range(20):
            if session._terminal_queue:
                break
            await asyncio.sleep(0)
        assert len(session._terminal_queue) == 1
        queued = session._terminal_queue[0]
        assert queued.bypass_guard is False
        assert queued.control == PttControl.stop(TURN_ID)
        assert session._active_send is False

        await session._poison_protocol(decoder)
        writer = asyncio.create_task(session._writer_loop(), name="reachy-ptt-writer")
        session._writer_task = writer
        receipt = await asyncio.wait_for(coordinator, timeout=0.5)

        assert receipt.is_complete()
        assert session._cleanup_source is PttStopSource.SUPERVISOR_INPUT
        assert session._semantic_outcome is PttSessionOutcome.CANCELLED
        assert session._final_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert session._guard_poisoned is True
        assert session._receipt_attempted is True
        assert [
            frame.control.kind for frame in transport.edge_frames if isinstance(frame, ControlFrame)
        ] == [ControlKind.ERROR, ControlKind.SAFETY_RECEIPT]
        assert [frame.sequence for frame in transport.edge_frames] == [0, 1]
        assert sorted(media.cleanup_calls) == [
            "audio_reactive",
            "motion",
            "playback",
            "recording",
        ]
        assert transport.close_calls == 1
        await asyncio.sleep(0)
        assert not {
            task.get_name()
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
        }
    finally:
        for task in (coordinator, writer):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(
            *(task for task in (coordinator, writer) if task is not None),
            return_exceptions=True,
        )


@pytest.mark.asyncio
async def test_truncated_eof_uses_poison_emergency_path_without_ack_read() -> None:
    transport = PoisonEmergencyTransport(truncated_eof=True)
    arguments = session_arguments()
    arguments.update(transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await transport.ready_sent.wait()
        for _ in range(20):
            if not session._active_send:
                break
            await asyncio.sleep(0)
        assert session._active_send is False
        transport.inject_poison()
        done, _pending = await asyncio.wait({run_task}, timeout=0.2)
        assert run_task in done
        assert run_task.result() is PttSessionOutcome.CLEANUP_INCOMPLETE
        controls = [
            frame.control.kind for frame in transport.edge_frames if isinstance(frame, ControlFrame)
        ]
        assert controls == [
            ControlKind.SESSION_READY,
            ControlKind.ERROR,
            ControlKind.SAFETY_RECEIPT,
        ]
        assert transport.receive_calls == 3
    finally:
        if not run_task.done():
            cleanup_task = session._cleanup_task
            if cleanup_task is not None:
                cleanup_task.cancel()
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_protocol_poison_during_active_send_suppresses_emergency_output() -> None:
    events: list[str] = []
    transport = BlockingFailingPcmTransport(events)
    media = HappyTurnMedia(events, (b"\x0a\x00" * 40,))
    arguments = session_arguments()
    arguments.update(media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await transport.pcm_send_started.wait()
        transport.queue_protocol_poison()

        outcome = await run_task

        assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert transport.pcm_send_cancelled is True
        assert all(
            not isinstance(frame, ControlFrame)
            or frame.control.kind not in {ControlKind.ERROR, ControlKind.SAFETY_RECEIPT}
            for frame in transport.edge_frames
        )
        assert transport.close_calls == 1
        await asyncio.sleep(0)
        assert not {
            task.get_name()
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
        }
    finally:
        if not run_task.done():
            cleanup_task = session._cleanup_task
            if cleanup_task is not None:
                cleanup_task.cancel()
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_cleanup_wakes_queue_full_blocked_producer_without_a_writer() -> None:
    session = ReachyPttSession(**session_arguments())  # type: ignore[arg-type]
    producers = [
        asyncio.create_task(
            session._enqueue_normal(pcm=b"\x0b\x00"),
            name=f"test-normal-producer-{index}",
        )
        for index in range(65)
    ]
    try:
        for _ in range(100):
            if session._normal_queue.qsize() == 64:
                await asyncio.sleep(0)
                break
            await asyncio.sleep(0)
        assert session._normal_queue.qsize() == 64
        assert sum(not producer.done() for producer in producers) == 65

        await session._request_cleanup(
            PttStopSource.SUPERVISOR_INPUT,
            PttSessionOutcome.CANCELLED,
        )
        done, pending = await asyncio.wait(producers, timeout=0.2)

        assert not pending
        assert len(done) == 65
        failures = [producer.exception() for producer in producers]
        assert all(type(failure) is RuntimeError for failure in failures)
        assert {str(failure) for failure in failures} == {"PTT frame was not sent"}
        assert session._normal_queue.empty()
    finally:
        for producer in producers:
            if not producer.done():
                producer.cancel()
        await asyncio.gather(*producers, return_exceptions=True)


@pytest.mark.asyncio
async def test_writer_preserves_fifo_while_backpressuring_the_sixty_fifth_queued_draft() -> None:
    transport = BlockingWriterTransport()
    arguments = session_arguments()
    arguments["transport"] = transport
    session = WriterHarnessSession(**arguments)  # type: ignore[arg-type]
    writer_task = asyncio.create_task(session._writer_loop(), name="reachy-ptt-writer")
    session._writer_task = writer_task
    producers = [
        asyncio.create_task(
            session._enqueue_normal(pcm=index.to_bytes(2, "big")),
            name=f"test-fifo-producer-{index}",
        )
        for index in range(66)
    ]
    try:
        await transport.first_send_started.wait()
        for _ in range(100):
            if session._normal_queue.qsize() == 64:
                break
            await asyncio.sleep(0)

        assert session._normal_queue.qsize() == 64
        assert session._blocked_normal_producers == 1
        assert all(not producer.done() for producer in producers)

        transport.release_first_send.set()
        assert await asyncio.gather(*producers) == [None] * 66

        assert [frame.sequence for frame in transport.frames] == list(range(66))
        assert [frame.pcm for frame in transport.frames if isinstance(frame, PcmFrame)] == [
            index.to_bytes(2, "big") for index in range(66)
        ]
    finally:
        async with session._writer_lock:
            session._writer_stopping = True
            session._writer_wakeup.set()
        await asyncio.gather(writer_task, return_exceptions=True)
        for producer in producers:
            if not producer.done():
                producer.cancel()
        await asyncio.gather(*producers, return_exceptions=True)


@pytest.mark.asyncio
async def test_cleanup_drops_queued_normal_drafts_before_sequence_allocation() -> None:
    transport = BlockingWriterTransport()
    arguments = session_arguments()
    arguments["transport"] = transport
    session = WriterHarnessSession(**arguments)  # type: ignore[arg-type]
    writer_task = asyncio.create_task(session._writer_loop(), name="reachy-ptt-writer")
    session._writer_task = writer_task
    producers = [
        asyncio.create_task(
            session._enqueue_normal(pcm=index.to_bytes(2, "big")),
            name=f"test-preempted-producer-{index}",
        )
        for index in range(3)
    ]
    terminal_task: asyncio.Task[None] | None = None
    try:
        await transport.first_send_started.wait()
        for _ in range(100):
            if session._normal_queue.qsize() == 2:
                break
            await asyncio.sleep(0)
        assert session._normal_queue.qsize() == 2

        await session._request_cleanup(
            PttStopSource.SUPERVISOR_INPUT,
            PttSessionOutcome.CANCELLED,
        )
        terminal_task = asyncio.create_task(
            session._enqueue_terminal(PttControl.stop(TURN_ID)),
            name="test-terminal-stop",
        )
        await asyncio.sleep(0)
        transport.release_first_send.set()

        results = await asyncio.gather(*producers, return_exceptions=True)
        await terminal_task

        assert results[0] is None
        assert all(type(result) is RuntimeError for result in results[1:])
        assert {str(result) for result in results[1:]} == {"PTT frame was not sent"}
        assert [frame.sequence for frame in transport.frames] == [0, 1]
        assert isinstance(transport.frames[0], PcmFrame)
        assert isinstance(transport.frames[1], ControlFrame)
        assert transport.frames[1].control.kind is ControlKind.STOP
        assert session._edge_sequence == 2
        assert session._normal_queue.empty()
    finally:
        transport.release_first_send.set()
        async with session._writer_lock:
            session._writer_stopping = True
            session._writer_wakeup.set()
        await asyncio.gather(writer_task, return_exceptions=True)
        for producer in producers:
            if not producer.done():
                producer.cancel()
        if terminal_task is not None and not terminal_task.done():
            terminal_task.cancel()
        await asyncio.gather(*producers, return_exceptions=True)
        if terminal_task is not None:
            await asyncio.gather(terminal_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_capture_error_receipt_race_emits_complete_contiguous_terminal_frames() -> None:
    transport = BlockingWriterTransport()
    arguments = session_arguments()
    arguments["transport"] = transport
    session = WriterHarnessSession(**arguments)  # type: ignore[arg-type]
    writer_task = asyncio.create_task(session._writer_loop(), name="reachy-ptt-writer")
    session._writer_task = writer_task
    capture_pcm = asyncio.create_task(
        session._enqueue_normal(pcm=b"\x01\x00"),
        name="test-active-capture-pcm",
    )
    capture_end: asyncio.Task[None] | None = None
    terminal_tasks: list[asyncio.Task[None]] = []
    try:
        await transport.first_send_started.wait()
        capture_end = asyncio.create_task(
            session._enqueue_normal(control=PttControl.capture_end(TURN_ID)),
            name="test-racing-capture-end",
        )
        for _ in range(100):
            if session._normal_queue.qsize() == 1:
                break
            await asyncio.sleep(0)
        assert session._normal_queue.qsize() == 1

        await session._request_cleanup(
            PttStopSource.PROTOCOL_REJECTED,
            PttSessionOutcome.CAPTURE_FAILED,
        )
        receipt = PttSafetyReceipt(
            turn_id=TURN_ID,
            new_capture_rejected=True,
            recording_stopped=True,
            playback_stopped=True,
            motion_stopped=True,
            audio_reactive_disabled=True,
            owned_buffers_cleared=True,
        )
        terminal_tasks = [
            asyncio.create_task(
                session._enqueue_terminal(PttControl.error(TURN_ID, PttErrorReason.CAPTURE_FAILED)),
                name="test-racing-error",
            ),
            asyncio.create_task(
                session._enqueue_terminal(PttControl.safety_receipt(TURN_ID, receipt)),
                name="test-racing-receipt",
            ),
        ]
        await asyncio.sleep(0)
        transport.release_first_send.set()

        assert await capture_pcm is None
        capture_end_result = await asyncio.gather(capture_end, return_exceptions=True)
        assert len(capture_end_result) == 1
        assert type(capture_end_result[0]) is RuntimeError
        assert str(capture_end_result[0]) == "PTT frame was not sent"
        assert await asyncio.gather(*terminal_tasks) == [None, None]

        assert [frame.sequence for frame in transport.frames] == [0, 1, 2]
        assert isinstance(transport.frames[0], PcmFrame)
        assert [
            frame.control.kind for frame in transport.frames[1:] if isinstance(frame, ControlFrame)
        ] == [ControlKind.ERROR, ControlKind.SAFETY_RECEIPT]
        assert len(transport.sent) == 3
        assert all(len(FrameDecoder().feed(encoded)) == 1 for encoded in transport.sent)
    finally:
        transport.release_first_send.set()
        async with session._writer_lock:
            session._writer_stopping = True
            session._writer_wakeup.set()
        await asyncio.gather(writer_task, return_exceptions=True)
        for task in (capture_pcm, capture_end, *terminal_tasks):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(
            *(task for task in (capture_pcm, capture_end, *terminal_tasks) if task is not None),
            return_exceptions=True,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("rejection", ("guard", "encode"))
async def test_pre_send_rejection_consumes_no_sequence_and_closes_writer(
    rejection: str,
) -> None:
    transport = FakeTransport()
    arguments = session_arguments()
    arguments["transport"] = transport
    session_type = GuardRejectingWriterSession if rejection == "guard" else WriterHarnessSession
    session = session_type(**arguments)  # type: ignore[arg-type]
    writer_task = asyncio.create_task(session._writer_loop(), name="reachy-ptt-writer")
    session._writer_task = writer_task
    invalid_pcm = b"\x00\x00" if rejection == "guard" else b"\x00"

    result = await asyncio.gather(
        session._enqueue_normal(pcm=invalid_pcm),
        return_exceptions=True,
    )
    await writer_task

    assert len(result) == 1
    assert type(result[0]) is RuntimeError
    assert str(result[0]) == "PTT frame was not sent"
    assert session._edge_sequence == 0
    assert transport.sent == []
    assert session._transport_writable is False
    assert session._cleanup_started_at is not None
    with pytest.raises(RuntimeError, match="^PTT transport is unwritable$"):
        await session._enqueue_terminal(PttControl.stop(TURN_ID))


@pytest.mark.asyncio
async def test_terminal_lane_deduplicates_active_cleanup_and_bounds_waiting_drafts() -> None:
    transport = BlockingWriterTransport()
    arguments = session_arguments()
    arguments["transport"] = transport
    session = WriterHarnessSession(**arguments)  # type: ignore[arg-type]
    writer_task = asyncio.create_task(session._writer_loop(), name="reachy-ptt-writer")
    session._writer_task = writer_task
    receipt = PttSafetyReceipt(
        turn_id=TURN_ID,
        new_capture_rejected=True,
        recording_stopped=True,
        playback_stopped=True,
        motion_stopped=True,
        audio_reactive_disabled=True,
        owned_buffers_cleared=True,
    )
    first_stop = asyncio.create_task(
        session._enqueue_terminal(PttControl.stop(TURN_ID)),
        name="test-first-terminal-stop",
    )
    duplicate_stop: asyncio.Task[None] | None = None
    error_task: asyncio.Task[None] | None = None
    receipt_task: asyncio.Task[None] | None = None
    try:
        await transport.first_send_started.wait()
        duplicate_stop = asyncio.create_task(
            session._enqueue_terminal(PttControl.stop(TURN_ID)),
            name="test-duplicate-terminal-stop",
        )
        error_task = asyncio.create_task(
            session._enqueue_terminal(PttControl.error(TURN_ID, PttErrorReason.CLEANUP_INCOMPLETE)),
            name="test-terminal-error",
        )
        for _ in range(100):
            if len(session._terminal_queue) == 1:
                break
            await asyncio.sleep(0)

        assert len(session._terminal_queue) == 1
        receipt_task = asyncio.create_task(
            session._enqueue_terminal(PttControl.safety_receipt(TURN_ID, receipt)),
            name="test-terminal-receipt",
        )
        for _ in range(100):
            if len(session._terminal_queue) == 2:
                break
            await asyncio.sleep(0)
        assert len(session._terminal_queue) == 2
        with pytest.raises(RuntimeError, match="^PTT terminal lane is full$"):
            await session._enqueue_terminal(PttControl.cancel(TURN_ID))

        transport.release_first_send.set()
        assert await asyncio.gather(
            first_stop,
            duplicate_stop,
            error_task,
            receipt_task,
        ) == [None, None, None, None]

        controls = [
            frame.control.kind for frame in transport.frames if isinstance(frame, ControlFrame)
        ]
        assert controls == [ControlKind.STOP, ControlKind.ERROR, ControlKind.SAFETY_RECEIPT]
        assert [frame.sequence for frame in transport.frames] == [0, 1, 2]
    finally:
        transport.release_first_send.set()
        async with session._writer_lock:
            session._writer_stopping = True
            session._writer_wakeup.set()
        await asyncio.gather(writer_task, return_exceptions=True)
        for task in (first_stop, duplicate_stop, error_task, receipt_task):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(
            *(task for task in (first_stop, duplicate_stop, error_task, receipt_task) if task),
            return_exceptions=True,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ("timeout", "cancel", "raise"))
async def test_send_failure_permanently_closes_writer_without_advancing_sequence(
    failure: str,
) -> None:
    clock = FakeClock()
    transport = ControlledWriterFailureTransport(failure)
    arguments = session_arguments()
    arguments.update(clock=clock, transport=transport)
    session = WriterHarnessSession(**arguments)  # type: ignore[arg-type]
    writer_task = asyncio.create_task(session._writer_loop(), name="reachy-ptt-writer")
    session._writer_task = writer_task
    producer = asyncio.create_task(
        session._enqueue_normal(pcm=b"\x02\x00"),
        name="test-failing-writer-producer",
    )
    await transport.send_started.wait()

    if failure == "timeout":
        clock.advance_to(10.5)
    elif failure == "cancel":
        writer_task.cancel()
    else:
        transport.release_send.set()

    writer_result = await asyncio.gather(writer_task, return_exceptions=True)
    producer_result = await asyncio.gather(producer, return_exceptions=True)

    assert len(writer_result) == 1
    if failure == "cancel":
        assert isinstance(writer_result[0], asyncio.CancelledError)
    else:
        assert writer_result == [None]
    assert len(producer_result) == 1
    assert type(producer_result[0]) is RuntimeError
    assert str(producer_result[0]) == "PTT frame was not sent"
    assert transport.send_cancelled is (failure in {"timeout", "cancel"})
    assert session._transport_writable is False
    assert session._edge_sequence == 0
    assert transport.sent == []
    with pytest.raises(RuntimeError, match="^PTT transport is unwritable$"):
        await session._enqueue_terminal(PttControl.stop(TURN_ID))


@pytest.mark.asyncio
async def test_poison_emergency_pair_shares_cleanup_t_plus_2_5_deadline() -> None:
    clock = FakeClock()
    transport = PoisonEmergencyTransport(truncated_eof=False)
    media = BlockingCleanupMedia()
    arguments = session_arguments()
    arguments.update(clock=clock, transport=transport, media=media)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await asyncio.wait_for(transport.ready_sent.wait(), timeout=0.2)
        for _ in range(20):
            if not session._active_send:
                break
            await asyncio.sleep(0)
        assert session._active_send is False
        transport.inject_poison()
        await asyncio.wait_for(transport.error_sent.wait(), timeout=0.2)
        await asyncio.wait_for(media.started.wait(), timeout=0.2)
        assert session._cleanup_started_at == 10.0

        clock.advance_to(12.5)
        outcome = await run_task

        assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        controls = [
            frame.control.kind for frame in transport.edge_frames if isinstance(frame, ControlFrame)
        ]
        assert controls == [ControlKind.SESSION_READY, ControlKind.ERROR]
        assert session._receipt_attempted is True
        assert transport.close_calls == 1
    finally:
        media.release.set()
        if not run_task.done():
            cleanup_task = session._cleanup_task
            if cleanup_task is not None:
                cleanup_task.cancel()
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_operation_at_exact_deadline_never_starts() -> None:
    clock = FakeClock()
    arguments = session_arguments()
    arguments["clock"] = clock
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    started = False

    async def operation() -> None:
        nonlocal started
        started = True

    with pytest.raises(TimeoutError):
        await session._within_deadline(operation(), clock.now(), name="exact-deadline")

    assert started is False


@pytest.mark.asyncio
async def test_operation_completing_at_exact_deadline_loses_even_if_sleeper_has_not_woken() -> None:
    clock = FakeClock()
    arguments = session_arguments()
    arguments["clock"] = clock
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    started = asyncio.Event()
    release = asyncio.Event()

    async def operation() -> str:
        started.set()
        await release.wait()
        return "too-late"

    bounded = asyncio.create_task(
        session._within_deadline(operation(), 11.0, name="exact-completion"),
        name="test-exact-completion",
    )
    await started.wait()
    clock.current = 11.0
    release.set()

    with pytest.raises(TimeoutError):
        await bounded


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("fault", "expected_error"),
    (("early", RuntimeError), ("raise", OSError), ("cancel", RuntimeError)),
)
async def test_within_deadline_rejects_broken_clock_sleeper_contract(
    fault: str,
    expected_error: type[BaseException],
) -> None:
    clock = FaultingSleepClock(fault)
    arguments = session_arguments()
    arguments["clock"] = clock
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    operation_cancelled = False

    async def operation() -> None:
        nonlocal operation_cancelled
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            operation_cancelled = True
            raise

    with pytest.raises(expected_error):
        await session._within_deadline(operation(), 11.0, name="broken-clock")

    assert operation_cancelled is True
    assert session._clock_faulted is True
    assert session._cleanup_requested.is_set()
    assert session._semantic_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert session._final_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert session._capture_gate is False
    assert session._playback_gate is False


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ("early", "raise", "cancel"))
async def test_cleanup_sleeper_fault_preserves_operation_until_original_loop_deadline(
    fault: str,
) -> None:
    clock = FaultingSleepClock(fault)
    session = ReachyPttSession(**(session_arguments() | {"clock": clock}))  # type: ignore[arg-type]
    session._clock_now()
    operation_started = asyncio.Event()
    operation_cancelled = False

    async def blocked_cleanup() -> None:
        nonlocal operation_cancelled
        operation_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            operation_cancelled = True
            raise

    bounded = asyncio.create_task(
        session._within_deadline(
            blocked_cleanup(),
            10.03,
            name="broken-cleanup-clock",
            cleanup_only=True,
        )
    )
    await operation_started.wait()
    for _attempt in range(10):
        if session._clock_faulted:
            break
        await asyncio.sleep(0)

    assert session._clock_faulted is True
    assert bounded.done() is False
    assert operation_cancelled is False

    with pytest.raises(TimeoutError):
        await asyncio.wait_for(bounded, timeout=0.15)
    assert operation_cancelled is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("fault", "expected_error"),
    (("early", RuntimeError), ("raise", OSError), ("cancel", RuntimeError)),
)
async def test_capture_deadline_sleeper_fault_latches_cleanup_before_later_effects(
    fault: str,
    expected_error: type[BaseException],
) -> None:
    clock = FaultingSleepClock(fault)
    capture_buffer = AppendRecordingBuffer()
    media = DeadlineCaptureMedia(b"\x43\x00")
    arguments = session_arguments()
    arguments.update(clock=clock, capture_buffer=capture_buffer, media=media)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    with pytest.raises(expected_error):
        await session._capture_until_submit(asyncio.Event().wait(), 11.0)

    assert session._clock_faulted is True
    assert session._cleanup_requested.is_set()
    assert session._semantic_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert capture_buffer.append_calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ("watch", "capture"))
@pytest.mark.parametrize(
    ("fault", "expected_error"),
    (("early", RuntimeError), ("raise", OSError), ("cancel", RuntimeError)),
)
async def test_simultaneous_cleanup_and_completed_sleeper_still_latches_clock_fault(
    path: str,
    fault: str,
    expected_error: type[BaseException],
) -> None:
    clock = FaultingSleepClock(fault)
    arguments = session_arguments()
    arguments["clock"] = clock
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    session._cleanup_requested.set()

    with pytest.raises(expected_error):
        if path == "watch":
            await session._sleep_until_or_cleanup(11.0, name="simultaneous-clock")
        else:
            await session._capture_until_submit(asyncio.Event().wait(), 11.0)

    assert session._clock_faulted is True
    assert session._semantic_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ("early", "raise", "cancel"))
async def test_turn_watchdog_clock_fault_is_cleanup_incomplete_not_timeout(fault: str) -> None:
    clock = FaultingSleepClock(fault)
    arguments = session_arguments()
    arguments["clock"] = clock
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    await session._watch_turn(11.0)

    assert session._cleanup_source is PttStopSource.WATCHDOG
    assert session._semantic_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert session._clock_faulted is True


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ("early", "raise", "cancel"))
async def test_heartbeat_clock_fault_fails_closed_without_busy_spin(fault: str) -> None:
    clock = FaultingSleepClock(fault, fault_call=2)
    arguments = session_arguments()
    arguments["clock"] = clock
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    session._session_open.set()
    session._last_valid_core_frame = 10.0
    watcher = asyncio.create_task(
        session._watch_heartbeat(15.0),
        name="test-heartbeat-broken-clock",
    )

    try:
        await asyncio.wait_for(session._cleanup_requested.wait(), timeout=0.2)
        await watcher

        assert session._cleanup_source is PttStopSource.WATCHDOG
        assert session._semantic_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert clock.sleep_calls == 2
    finally:
        watcher.cancel()
        await asyncio.gather(watcher, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ("early", "raise", "cancel"))
async def test_heartbeat_handshake_clock_fault_is_cleanup_incomplete(fault: str) -> None:
    clock = FaultingSleepClock(fault)
    arguments = session_arguments()
    arguments["clock"] = clock
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    await session._watch_heartbeat(15.0)

    assert session._cleanup_source is PttStopSource.WATCHDOG
    assert session._semantic_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE


@pytest.mark.asyncio
@pytest.mark.parametrize("trigger", ("core_abort", "local_stop"))
@pytest.mark.parametrize("timing", ("exact", "predeadline_blocked"))
async def test_turn_deadline_arbitrates_cleanup_by_trigger_timestamp(
    trigger: str,
    timing: str,
) -> None:
    clock = FakeClock(now=319.9 if timing == "predeadline_blocked" else 320.0)
    transport = SilentAckTransport()
    stop_input = BlockingStopInput()
    arguments = session_arguments()
    arguments.update(clock=clock, transport=transport)
    if trigger == "local_stop":
        arguments.update(
            input_mode=PttInputMode.REACHY_LOCAL,
            capture_input=ImmediateCaptureInput([]),
            stop_input=stop_input,
        )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    session._run_started_at = 10.0
    worker: asyncio.Task[None]
    if timing == "predeadline_blocked":
        await session._writer_lock.acquire()
    try:
        if trigger == "core_abort":
            session._guard = PttDuplexGuard(
                turn_id=TURN_ID,
                input_mode=PttInputMode.CORE_TERMINAL_TOGGLE,
            )
            session._decoder = FrameDecoder()
            transport.inbound.put_nowait(
                encode_control_frame(
                    sequence=0,
                    control=PttControl.abort(TURN_ID, PttErrorReason.TURN_CANCELLED),
                )
            )
            worker = asyncio.create_task(session._reader_loop(), name="test-turn-core-abort")
        else:
            worker = asyncio.create_task(session._watch_stop_input(), name="test-turn-local-stop")
            await stop_input.started.wait()
            stop_input.release.set()

        if timing == "predeadline_blocked":
            for _ in range(100):
                waiters = session._writer_lock._waiters  # type: ignore[attr-defined]
                if waiters and any(not waiter.done() for waiter in waiters):
                    break
                await asyncio.sleep(0)
            waiters = session._writer_lock._waiters  # type: ignore[attr-defined]
            assert waiters and any(not waiter.done() for waiter in waiters)
            clock.current = 320.0
            session._writer_lock.release()

        await asyncio.wait_for(session._cleanup_requested.wait(), timeout=0.2)
        if timing == "exact":
            assert session._cleanup_source is PttStopSource.WATCHDOG
            assert session._semantic_outcome is PttSessionOutcome.SESSION_TIMEOUT
        else:
            expected_source = (
                PttStopSource.CORE_ABORT
                if trigger == "core_abort"
                else PttStopSource.SUPERVISOR_INPUT
            )
            assert session._cleanup_source is expected_source
            assert session._semantic_outcome is PttSessionOutcome.CANCELLED
    finally:
        if timing == "predeadline_blocked" and session._writer_lock.locked():
            session._writer_lock.release()
        if "worker" in locals():
            worker.cancel()
            await asyncio.gather(worker, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    ("raise", "nan", "inf", "backward", "overflow_int", "inexact_int"),
)
async def test_invalid_clock_read_closes_active_gates_and_fails_cleanup_closed(
    failure: str,
) -> None:
    clock = InvalidNowClock()
    capture_buffer = FakeBuffer(b"stale-capture")
    playback_buffer = FakeBuffer(b"stale-playback")
    arguments = session_arguments()
    arguments.update(
        clock=clock,
        capture_buffer=capture_buffer,
        playback_buffer=playback_buffer,
    )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    session._run_started_at = clock.now()
    session._last_clock_value = session._run_started_at
    session._capture_gate = True
    session._playback_gate = True
    clock.failure = failure

    await session._request_cleanup(
        PttStopSource.SUPERVISOR_INPUT,
        PttSessionOutcome.CANCELLED,
    )

    assert session._cleanup_requested.is_set()
    assert session._cleanup_source is PttStopSource.WATCHDOG
    assert session._semantic_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert session._capture_gate is False
    assert session._playback_gate is False
    assert capture_buffer.is_empty()
    assert playback_buffer.is_empty()


@pytest.mark.asyncio
async def test_clock_fault_during_frame_acceptance_exits_reader_without_another_receive() -> None:
    clock = InvalidNowClock()

    class FaultOnFirstReceiveTransport(FakeTransport):
        async def receive(self, max_bytes: int) -> bytes:
            self.receive_calls += 1
            if self.receive_calls > 1:
                raise AssertionError("reader admitted another receive after clock fault")
            clock.failure = "raise"
            return encode_control_frame(
                sequence=0,
                control=PttControl.session_open(
                    TURN_ID,
                    PttInputMode.CORE_TERMINAL_TOGGLE,
                ),
            )

    transport = FaultOnFirstReceiveTransport()
    arguments = session_arguments()
    arguments.update(clock=clock, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    session._run_started_at = clock.now()
    session._last_clock_value = session._run_started_at
    session._guard = PttDuplexGuard(
        turn_id=TURN_ID,
        input_mode=PttInputMode.CORE_TERMINAL_TOGGLE,
    )
    session._decoder = FrameDecoder()

    await asyncio.wait_for(session._reader_loop(), timeout=0.2)

    assert transport.receive_calls == 1
    assert session._session_open.is_set() is False
    assert session._clock_faulted is True
    assert session._cleanup_requested.is_set()
    assert session._semantic_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE


@pytest.mark.asyncio
async def test_reader_does_not_start_receive_after_clock_admission_faulted() -> None:
    clock = InvalidNowClock()
    transport = FakeTransport()
    arguments = session_arguments()
    arguments.update(clock=clock, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    session._decoder = FrameDecoder()
    session._last_clock_value = clock.now()
    clock.failure = "raise"
    session._clock_now()

    await session._reader_loop()

    assert transport.receive_calls == 0


@pytest.mark.asyncio
async def test_external_clock_fault_cancels_an_active_blocked_receive() -> None:
    clock = InvalidNowClock()

    class BlockingReceiveTransport(FakeTransport):
        def __init__(self) -> None:
            super().__init__()
            self.started = asyncio.Event()
            self.cancelled = asyncio.Event()

        async def receive(self, max_bytes: int) -> bytes:
            self.receive_calls += 1
            self.started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.cancelled.set()
                raise
            raise AssertionError("unreachable")

    transport = BlockingReceiveTransport()
    arguments = session_arguments()
    arguments.update(clock=clock, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    session._decoder = FrameDecoder()
    session._last_clock_value = clock.now()
    reader = asyncio.create_task(session._reader_loop(), name="reachy-ptt-reader")
    session._reader_task = reader
    await transport.started.wait()

    clock.failure = "raise"
    session._clock_now()
    await asyncio.wait_for(transport.cancelled.wait(), timeout=0.2)
    await asyncio.gather(reader, return_exceptions=True)

    assert transport.receive_calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ("raise", "nan", "inf"))
async def test_invalid_initial_clock_runs_local_only_cleanup_before_runtime_effects(
    failure: str,
) -> None:
    clock = InvalidNowClock()
    clock.failure = failure
    media = FakeMedia()
    transport = FakeTransport()
    arguments = session_arguments()
    arguments.update(clock=clock, media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    outcome = await session.run()

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert sorted(media.cleanup_calls) == [
        "audio_reactive",
        "motion",
        "playback",
        "recording",
    ]
    assert transport.receive_calls == 0
    assert transport.sent == []
    assert transport.close_calls == 0
    assert session._reader_task is None
    assert session._writer_task is None


@pytest.mark.asyncio
@pytest.mark.parametrize("operation_kind", ("capture_open", "playback_write"))
async def test_clock_faulted_deadline_never_starts_an_ordinary_media_operation(
    operation_kind: str,
) -> None:
    clock = InvalidNowClock()
    media = OrdinaryOperationRecordingMedia()
    arguments = session_arguments()
    arguments.update(clock=clock, media=media)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    session._last_clock_value = clock.now()
    clock.failure = "raise"
    if operation_kind == "capture_open":
        operation = media.open_capture(
            output_format=TRANSPORT_AUDIO_FORMAT,
            max_frame_bytes=MAX_TRANSPORT_PCM_FRAME_BYTES,
        )
    else:
        operation = media.write_playback(b"\x42\x00")

    with pytest.raises(RuntimeError, match="clock fault"):
        await session._within_deadline(
            operation,
            11.0,
            name=f"test-clock-fault-{operation_kind}",
        )

    assert media.capture_open_calls == 0
    assert media.playback_write_calls == 0
    assert session._cleanup_requested.is_set()
    assert session._semantic_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE


@pytest.mark.asyncio
async def test_clock_fault_still_allows_an_explicit_local_cleanup_observation() -> None:
    clock = InvalidNowClock()
    media = OrdinaryOperationRecordingMedia()
    arguments = session_arguments()
    arguments.update(clock=clock, media=media)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    session._last_clock_value = clock.now()
    clock.failure = "raise"
    session._clock_now()

    result = await session._within_deadline(
        media.stop_recording(),
        11.0,
        name="test-clock-fault-local-cleanup",
        cleanup_only=True,
    )

    assert result is True
    assert media.cleanup_calls == ["recording"]


@pytest.mark.asyncio
@pytest.mark.parametrize("sleeper_behavior", ("hang", "early", "raise"))
@pytest.mark.parametrize("operation_kind", ("task_join", "transport_close"))
async def test_post_clock_fault_cleanup_only_deadlines_use_a_bounded_loop_fallback(
    sleeper_behavior: str,
    operation_kind: str,
) -> None:
    clock = AdversarialCleanupSleeperClock(sleeper_behavior)
    transport = BlockingCloseTransport()
    arguments = session_arguments()
    arguments.update(clock=clock, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    session._last_clock_value = clock.now()
    clock.failure = "raise"
    session._clock_now()
    operation_started = asyncio.Event()
    operation_cancelled = False

    async def block_task_join() -> None:
        nonlocal operation_cancelled
        operation_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            operation_cancelled = True
            raise

    operation = block_task_join() if operation_kind == "task_join" else transport.close()

    with pytest.raises(TimeoutError):
        await asyncio.wait_for(
            session._within_deadline(
                operation,
                10.01,
                name=f"test-post-fault-{operation_kind}",
                cleanup_only=True,
            ),
            timeout=0.2,
        )

    assert operation_started.is_set() or transport.close_started.is_set()
    assert operation_cancelled or transport.close_cancelled
    assert clock.sleep_calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("sleeper_behavior", ("hang", "early", "raise"))
async def test_post_clock_fault_cleanup_observation_has_a_bounded_loop_fallback(
    monkeypatch: pytest.MonkeyPatch,
    sleeper_behavior: str,
) -> None:
    monkeypatch.setattr(
        "tuntun_edge.poc.reachy_ptt._CLEANUP_OBSERVATION_SECONDS",
        0.01,
    )
    clock = AdversarialCleanupSleeperClock(sleeper_behavior)
    media = BlockingCleanupMedia()
    arguments = session_arguments()
    arguments.update(clock=clock, media=media)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    session._last_clock_value = clock.now()
    clock.failure = "raise"
    session._clock_now()

    receipt = await asyncio.wait_for(session._observe_local_cleanup(), timeout=0.2)

    assert sorted(media.cleanup_calls) == [
        "audio_reactive",
        "motion",
        "playback",
        "recording",
    ]
    assert media.cancelled == 4
    assert media.completed == 0
    assert receipt.is_complete() is False
    assert clock.sleep_calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("operation_kind", ("task_join", "transport_close"))
async def test_mid_cleanup_clock_fault_switches_join_and_close_to_loop_deadline(
    operation_kind: str,
) -> None:
    clock = AdversarialCleanupSleeperClock("hang")
    transport = BlockingCloseTransport()
    arguments = session_arguments()
    arguments.update(clock=clock, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    session._clock_now()
    operation_started = asyncio.Event()
    operation_cancelled = False

    async def block_task_join() -> None:
        nonlocal operation_cancelled
        operation_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            operation_cancelled = True
            raise

    operation = block_task_join() if operation_kind == "task_join" else transport.close()
    cleanup_task = asyncio.create_task(
        session._within_deadline(
            operation,
            10.05,
            name=f"test-mid-fault-{operation_kind}",
            cleanup_only=True,
        )
    )
    try:
        await clock.sleep_started.wait()
        assert operation_started.is_set() or transport.close_started.is_set()
        clock.failure = "raise"
        session._clock_now()

        done, _pending = await asyncio.wait({cleanup_task}, timeout=0.12)

        assert cleanup_task in done
        with pytest.raises(TimeoutError):
            cleanup_task.result()
        assert operation_cancelled or transport.close_cancelled
        assert clock.sleep_cancelled is True
    finally:
        cleanup_task.cancel()
        await asyncio.gather(cleanup_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_mid_cleanup_clock_fault_switches_observations_to_loop_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "tuntun_edge.poc.reachy_ptt._CLEANUP_OBSERVATION_SECONDS",
        0.05,
    )
    clock = AdversarialCleanupSleeperClock("hang")
    media = BlockingCleanupMedia()
    arguments = session_arguments()
    arguments.update(clock=clock, media=media)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    session._cleanup_started_at = session._clock_now()
    observation_task = asyncio.create_task(session._observe_local_cleanup())
    try:
        await media.started.wait()
        await clock.sleep_started.wait()
        clock.failure = "raise"
        session._clock_now()

        done, _pending = await asyncio.wait({observation_task}, timeout=0.12)

        assert observation_task in done
        receipt = observation_task.result()
        assert receipt.is_complete() is False
        assert media.cancelled == 4
        assert clock.sleep_cancelled is True
    finally:
        observation_task.cancel()
        await asyncio.gather(observation_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_mid_cleanup_clock_fault_preserves_only_the_original_remaining_budget() -> None:
    clock = AdversarialCleanupSleeperClock("hang")
    session = ReachyPttSession(**(session_arguments() | {"clock": clock}))  # type: ignore[arg-type]
    session._clock_now()

    async def blocked_join() -> None:
        await asyncio.Event().wait()

    cleanup_task = asyncio.create_task(
        session._within_deadline(
            blocked_join(),
            10.12,
            name="test-mid-fault-remaining-budget",
            cleanup_only=True,
        )
    )
    try:
        await clock.sleep_started.wait()
        await asyncio.sleep(0.08)
        clock.failure = "raise"
        session._clock_now()

        done, _pending = await asyncio.wait({cleanup_task}, timeout=0.08)

        assert cleanup_task in done
        with pytest.raises(TimeoutError):
            cleanup_task.result()
        assert clock.sleep_cancelled is True
    finally:
        cleanup_task.cancel()
        await asyncio.gather(cleanup_task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation_kind", ("task_join", "transport_close"))
@pytest.mark.parametrize("failure_site", ("deadline_owner", "operation_owner"))
async def test_within_deadline_caps_persistent_cleanup_owner_allocation_failure(
    monkeypatch: pytest.MonkeyPatch,
    operation_kind: str,
    failure_site: str,
) -> None:
    original_create_task = asyncio.create_task
    task_name = f"test-persistent-{operation_kind}"
    failed_names: list[str] = []
    operations: list[Coroutine[Any, Any, None]] = []

    async def blocked_operation() -> None:
        await asyncio.Event().wait()

    def operation_factory() -> Coroutine[Any, Any, None]:
        operation = blocked_operation()
        operations.append(operation)
        return operation

    def fail_both_owner_attempts(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        is_target = name in {
            task_name,
            f"{task_name}-fallback",
        }
        is_deadline = name in {
            f"{task_name}-deadline",
            f"{task_name}-fallback-deadline",
        }
        if (failure_site == "operation_owner" and is_target) or (
            failure_site == "deadline_owner" and is_deadline
        ):
            assert name is not None
            failed_names.append(name)
            coroutine.close()
            raise RuntimeError("injected persistent task-allocation failure")
        if context is None:
            return original_create_task(coroutine, name=name)
        return original_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(asyncio, "create_task", fail_both_owner_attempts)
    session = ReachyPttSession(**session_arguments())  # type: ignore[arg-type]

    with pytest.raises(RuntimeError, match="persistent task-allocation"):
        await session._within_deadline(
            operation_factory(),
            11.0,
            name=task_name,
            retry_factory=operation_factory,
            cleanup_only=True,
        )

    suffix = "-deadline" if failure_site == "deadline_owner" else ""
    assert failed_names == [task_name + suffix, f"{task_name}-fallback{suffix}"]
    assert len(operations) == 2
    assert all(getattr(operation, "cr_frame", object()) is None for operation in operations)


@pytest.mark.asyncio
async def test_within_deadline_rolls_back_operation_if_deadline_task_creation_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_create_task = asyncio.create_task
    failed = False

    def fail_deadline_task(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        nonlocal failed
        if name == "test-atomic-deadline-deadline" and not failed:
            failed = True
            coroutine.close()
            raise RuntimeError("injected deadline-task creation failure")
        if context is None:
            return original_create_task(coroutine, name=name)
        return original_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(asyncio, "create_task", fail_deadline_task)
    session = ReachyPttSession(**session_arguments())  # type: ignore[arg-type]

    async def operation() -> None:
        await asyncio.Event().wait()

    try:
        with pytest.raises(RuntimeError, match="^injected deadline-task creation failure$"):
            await session._within_deadline(
                operation(),
                11.0,
                name="test-atomic-deadline",
            )
        await asyncio.sleep(0)

        assert failed is True
        assert not {
            task.get_name()
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name() == "test-atomic-deadline"
        }
    finally:
        leaked = [
            task
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name() == "test-atomic-deadline"
        ]
        for task in leaked:
            task.cancel()
        await asyncio.gather(*leaked, return_exceptions=True)


@pytest.mark.asyncio
async def test_deadline_owner_is_allocated_before_any_eager_operation_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_create_task = asyncio.create_task
    synchronous_effects = 0

    def fail_deadline_after_simulated_eager_operation(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        nonlocal synchronous_effects
        if name == "test-eager-order":
            synchronous_effects += 1
        if name == "test-eager-order-deadline":
            raise RuntimeError("injected deadline-owner creation failure")
        if context is None:
            return original_create_task(coroutine, name=name)
        return original_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(asyncio, "create_task", fail_deadline_after_simulated_eager_operation)
    session = ReachyPttSession(**session_arguments())  # type: ignore[arg-type]

    async def operation() -> None:
        await asyncio.Event().wait()

    with pytest.raises(RuntimeError, match="^injected deadline-owner creation failure$"):
        await session._within_deadline(
            operation(),
            11.0,
            name="test-eager-order",
        )

    assert synchronous_effects == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("wait_kind", "failed_task_name", "owned_prefix"),
    (
        ("event", "test-atomic-event-cleanup", "test-atomic-event"),
        ("sleep", "test-atomic-sleep-cleanup", "test-atomic-sleep"),
    ),
)
async def test_pair_wait_rolls_back_first_task_when_second_creation_fails(
    monkeypatch: pytest.MonkeyPatch,
    wait_kind: str,
    failed_task_name: str,
    owned_prefix: str,
) -> None:
    original_create_task = asyncio.create_task
    failed = False

    def fail_second_task(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        nonlocal failed
        if name == failed_task_name and not failed:
            failed = True
            coroutine.close()
            raise RuntimeError("injected pair-task creation failure")
        if context is None:
            return original_create_task(coroutine, name=name)
        return original_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(asyncio, "create_task", fail_second_task)
    session = ReachyPttSession(**session_arguments())  # type: ignore[arg-type]
    try:
        with pytest.raises(RuntimeError, match="^injected pair-task creation failure$"):
            if wait_kind == "event":
                await session._wait_event_or_cleanup(
                    asyncio.Event(),
                    11.0,
                    name=owned_prefix,
                )
            else:
                await session._sleep_until_or_cleanup(11.0, name=owned_prefix)
        await asyncio.sleep(0)

        assert failed is True
        assert not {
            task.get_name()
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name().startswith(owned_prefix)
        }
    finally:
        leaked = [
            task
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name().startswith(owned_prefix)
        ]
        for task in leaked:
            task.cancel()
        await asyncio.gather(*leaked, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failed_task_name", "transport_factory"),
    (
        (
            "reachy-ptt-ack-poison-wait",
            lambda: ReceiptPolicyTransport(ack=None),
        ),
        (
            "reachy-ptt-poison-wait",
            lambda: ScriptedHappyTransport(
                PttInputMode.CORE_TERMINAL_TOGGLE,
                [],
                b"\x29\x00" * 40,
            ),
        ),
    ),
)
async def test_cleanup_pair_task_creation_failure_is_conservative_and_orphan_free(
    monkeypatch: pytest.MonkeyPatch,
    failed_task_name: str,
    transport_factory: Any,
) -> None:
    original_create_task = asyncio.create_task
    failed = False

    def fail_cleanup_pair_task(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        nonlocal failed
        if name == failed_task_name and not failed:
            failed = True
            coroutine.close()
            raise RuntimeError("injected cleanup-pair creation failure")
        if context is None:
            return original_create_task(coroutine, name=name)
        return original_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(asyncio, "create_task", fail_cleanup_pair_task)
    transport = transport_factory()
    media = HappyTurnMedia([], (b"\x2a\x00" * 40,))
    arguments = session_arguments()
    arguments.update(media=media, transport=transport)

    class YieldBeforePoisonWaitSession(ReachyPttSession):
        async def _wait_cleanup_evidence_or_poison(
            self,
            observation_task: asyncio.Task[PttSafetyReceipt],
            effect_join_task: asyncio.Task[bool],
        ) -> tuple[PttSafetyReceipt, bool] | None:
            await asyncio.sleep(0)
            return await super()._wait_cleanup_evidence_or_poison(
                observation_task,
                effect_join_task,
            )

    session_type = (
        YieldBeforePoisonWaitSession
        if failed_task_name == "reachy-ptt-poison-wait"
        else ReachyPttSession
    )
    session = session_type(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        result = await asyncio.gather(run_task, return_exceptions=True)
        await asyncio.sleep(0)

        assert failed is True
        assert result == [PttSessionOutcome.CLEANUP_INCOMPLETE]
        assert transport.close_calls == 1
        assert sorted(media.cleanup_calls) == [
            "audio_reactive",
            "motion",
            "playback",
            "recording",
        ]
        assert not {
            task.get_name()
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
        }
    finally:
        leaked = [
            task
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
        ]
        for task in leaked:
            task.cancel()
        await asyncio.gather(*leaked, return_exceptions=True)


@pytest.mark.asyncio
async def test_poison_wait_creation_failure_preserves_in_flight_cleanup_observations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_create_task = asyncio.create_task
    failure_observed = asyncio.Event()

    def fail_poison_wait(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        if name == "reachy-ptt-poison-wait" and not failure_observed.is_set():
            failure_observed.set()
            coroutine.close()
            raise RuntimeError("injected poison-wait creation failure")
        if context is None:
            return original_create_task(coroutine, name=name)
        return original_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(asyncio, "create_task", fail_poison_wait)
    media = BlockingCleanupMedia()
    transport = ScriptedHappyTransport(
        PttInputMode.CORE_TERMINAL_TOGGLE,
        [],
        b"\x2a\x00" * 40,
    )
    arguments = session_arguments()
    arguments.update(media=media, transport=transport)

    class WaitForCleanupEntrySession(ReachyPttSession):
        async def _wait_cleanup_evidence_or_poison(
            self,
            observation_task: asyncio.Task[PttSafetyReceipt],
            effect_join_task: asyncio.Task[bool],
        ) -> tuple[PttSafetyReceipt, bool] | None:
            await media.started.wait()
            return await super()._wait_cleanup_evidence_or_poison(
                observation_task,
                effect_join_task,
            )

    session = WaitForCleanupEntrySession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await failure_observed.wait()
        await asyncio.sleep(0)

        assert sorted(media.cleanup_calls) == [
            "audio_reactive",
            "motion",
            "playback",
            "recording",
        ]
        assert media.cancelled == 0
        assert not run_task.done()

        media.release.set()
        assert await run_task is PttSessionOutcome.CLEANUP_INCOMPLETE
        receipt = session._cleanup_task.result()  # type: ignore[union-attr]
        assert receipt.is_complete()
        assert media.completed == 4
        assert transport.close_calls == 1
        await asyncio.sleep(0)
        assert not {
            task.get_name()
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
        }
    finally:
        media.release.set()
        if not run_task.done():
            await session.stop(PttStopSource.SUPERVISOR_INPUT)
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failed_task_name",
    (
        "reachy-ptt-heartbeat-open-cleanup",
        "reachy-ptt-heartbeat-cleanup",
        "reachy-ptt-turn-watchdog-cleanup",
    ),
)
async def test_watchdog_pair_creation_failure_latches_conservative_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    failed_task_name: str,
) -> None:
    original_create_task = asyncio.create_task
    failed = False

    def fail_watchdog_pair_task(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        nonlocal failed
        if name == failed_task_name and not failed:
            failed = True
            coroutine.close()
            raise RuntimeError("injected watchdog-pair creation failure")
        if context is None:
            return original_create_task(coroutine, name=name)
        return original_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(asyncio, "create_task", fail_watchdog_pair_task)
    arguments = session_arguments()
    if failed_task_name == "reachy-ptt-heartbeat-cleanup":
        events: list[str] = []
        transport: FakeTransport = ScriptedHappyTransport(
            PttInputMode.CORE_TERMINAL_TOGGLE,
            events,
            b"",
            auto_submit=False,
        )
        arguments.update(
            transport=transport,
            media=BlockingCaptureStageMedia(events, "read"),
        )
    else:
        transport = SilentAckTransport()
        arguments["transport"] = transport
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        done, _pending = await asyncio.wait({run_task}, timeout=0.2)

        assert failed is True
        assert run_task in done
        assert run_task.result() is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert transport.close_calls == 1
        await asyncio.sleep(0)
        assert not {
            task.get_name()
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
        }
    finally:
        if not run_task.done():
            await session.stop(PttStopSource.SUPERVISOR_INPUT)
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case", "failed_task_name", "failed_occurrence"),
    (
        ("heartbeat_open_first", "reachy-ptt-heartbeat-open", 1),
        ("heartbeat_open_second", "reachy-ptt-heartbeat-open-cleanup", 1),
        ("heartbeat_sleep_first", "reachy-ptt-heartbeat", 1),
        ("heartbeat_sleep_second", "reachy-ptt-heartbeat-cleanup", 1),
        ("turn_sleep_first", "reachy-ptt-turn-watchdog", 2),
        ("turn_sleep_second", "reachy-ptt-turn-watchdog-cleanup", 1),
        ("session_open_first", "reachy-ptt-session-open", 1),
        ("session_open_second", "reachy-ptt-session-open-cleanup", 1),
    ),
)
async def test_runtime_wait_task_creation_failure_uses_watchdog_cleanup_identity(
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    failed_task_name: str,
    failed_occurrence: int,
) -> None:
    original_create_task = asyncio.create_task
    occurrences = 0
    failed = False

    def fail_runtime_wait_task(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        nonlocal failed, occurrences
        if name == failed_task_name:
            occurrences += 1
            if occurrences == failed_occurrence:
                failed = True
                coroutine.close()
                raise RuntimeError("injected runtime-wait creation failure")
        if context is None:
            return original_create_task(coroutine, name=name)
        return original_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(asyncio, "create_task", fail_runtime_wait_task)
    media = FakeMedia()
    arguments = session_arguments()
    if case.startswith("heartbeat_sleep"):
        events: list[str] = []
        transport: FakeTransport = ScriptedHappyTransport(
            PttInputMode.CORE_TERMINAL_TOGGLE,
            events,
            b"",
            auto_submit=False,
        )
        media = BlockingCaptureStageMedia(events, "read")
    else:
        transport = SilentAckTransport()
    arguments.update(media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        done, _pending = await asyncio.wait({run_task}, timeout=0.2)

        assert failed is True
        assert run_task in done
        assert run_task.result() is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert session._cleanup_source is PttStopSource.WATCHDOG
        assert session._semantic_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        cleanup_identity = session._cleanup_task
        assert cleanup_identity is not None
        first_receipt = cleanup_identity.result()
        second_receipt = await session.stop(PttStopSource.SUPERVISOR_INPUT)
        assert second_receipt is first_receipt
        assert session._cleanup_task is cleanup_identity
        assert sorted(media.cleanup_calls) == [
            "audio_reactive",
            "motion",
            "playback",
            "recording",
        ]
        assert transport.close_calls == 1
        await asyncio.sleep(0)
        assert not {
            task.get_name()
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
        }
    finally:
        if not run_task.done():
            await session.stop(PttStopSource.SUPERVISOR_INPUT)
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_one_shot_cleanup_deadline_creation_failure_preserves_observations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_create_task = asyncio.create_task
    failed = False

    def fail_cleanup_deadline(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        nonlocal failed
        if name == "reachy-ptt-cleanup-deadline" and not failed:
            failed = True
            coroutine.close()
            raise RuntimeError("injected cleanup-deadline creation failure")
        if context is None:
            return original_create_task(coroutine, name=name)
        return original_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(asyncio, "create_task", fail_cleanup_deadline)
    media = BlockingCleanupMedia()
    spawner = FakeCleanupTaskSpawner()
    arguments = session_arguments()
    arguments.update(media=media, task_spawner=spawner)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    session._cleanup_started_at = 10.0
    session._clear_result = True
    observation_names = {"recording", "playback", "motion", "audio_reactive"}
    original_followup = session._create_followup_task

    async def yield_before_deadline_creation(
        operation: Coroutine[Any, Any, Any],
        *,
        name: str,
        adopted: tuple[asyncio.Task[Any], ...],
    ) -> asyncio.Task[Any]:
        if name == "reachy-ptt-cleanup-deadline":
            await media.started.wait()
        return await original_followup(operation, name=name, adopted=adopted)

    session._create_followup_task = yield_before_deadline_creation  # type: ignore[method-assign]
    try:
        observation_task = asyncio.create_task(session._observe_local_cleanup())
        await media.started.wait()
        for _attempt in range(10):
            if failed:
                break
            await asyncio.sleep(0)
        assert failed is True
        media.release.set()
        receipt = await observation_task
        await asyncio.sleep(0)

        assert set(spawner.names) == observation_names
        assert receipt.recording_stopped is True
        assert receipt.playback_stopped is True
        assert receipt.motion_stopped is True
        assert receipt.audio_reactive_disabled is True
        assert media.cancelled == 0
        assert media.completed == 4
        assert not {
            task.get_name()
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name() in observation_names
        }
    finally:
        leaked = [
            task
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name() in observation_names
        ]
        for task in leaked:
            task.cancel()
        await asyncio.gather(*leaked, return_exceptions=True)


@pytest.mark.asyncio
async def test_repeated_cleanup_deadline_creation_failure_cancels_observations_and_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_create_task = asyncio.create_task
    failed_names: list[str] = []

    def fail_cleanup_deadlines(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        if name in {
            "reachy-ptt-cleanup-deadline",
            "reachy-ptt-cleanup-deadline-fallback",
        }:
            failed_names.append(name)
            coroutine.close()
            raise RuntimeError("injected repeated cleanup-deadline creation failure")
        if context is None:
            return original_create_task(coroutine, name=name)
        return original_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(asyncio, "create_task", fail_cleanup_deadlines)
    media = BlockingCleanupMedia()
    arguments = session_arguments()
    arguments["media"] = media
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    session._cleanup_started_at = 10.0
    session._clear_result = True

    receipt = await session._observe_local_cleanup()
    await asyncio.sleep(0)

    assert failed_names == [
        "reachy-ptt-cleanup-deadline",
        "reachy-ptt-cleanup-deadline-fallback",
    ]
    assert receipt.recording_stopped is False
    assert receipt.playback_stopped is False
    assert receipt.motion_stopped is False
    assert receipt.audio_reactive_disabled is False
    assert media.cancelled in {0, 4}
    assert media.completed == 0
    assert not {
        task.get_name()
        for task in asyncio.all_tasks()
        if task is not asyncio.current_task()
        and task.get_name() in {"recording", "playback", "motion", "audio_reactive"}
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failed_task_name",
    (
        "reachy-ptt-cleanup-observations",
        "reachy-ptt-cleanup-observations-both",
        "reachy-ptt-effect-join-owner",
    ),
)
async def test_cleanup_coordinator_child_creation_failure_is_conservative_and_atomic(
    monkeypatch: pytest.MonkeyPatch,
    failed_task_name: str,
) -> None:
    original_create_task = asyncio.create_task
    failed = False

    def fail_coordinator_child(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        nonlocal failed
        observation_both = failed_task_name == "reachy-ptt-cleanup-observations-both" and name in {
            "reachy-ptt-cleanup-observations",
            "reachy-ptt-cleanup-observations-fallback",
        }
        if observation_both or (name == failed_task_name and not failed):
            failed = True
            coroutine.close()
            raise RuntimeError("injected coordinator-child creation failure")
        if context is None:
            return original_create_task(coroutine, name=name)
        return original_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(asyncio, "create_task", fail_coordinator_child)
    media = HappyTurnMedia([], (b"\x2b\x00" * 40,))
    transport = ScriptedHappyTransport(
        PttInputMode.CORE_TERMINAL_TOGGLE,
        [],
        b"\x2c\x00" * 40,
    )
    arguments = session_arguments()
    arguments.update(media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        result = await asyncio.gather(run_task, return_exceptions=True)
        await asyncio.sleep(0)

        assert failed is True
        assert result == [PttSessionOutcome.CLEANUP_INCOMPLETE]
        assert sorted(media.cleanup_calls) == [
            "audio_reactive",
            "motion",
            "playback",
            "recording",
        ]
        assert transport.close_calls == 1
        assert not {
            task.get_name()
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
        }
    finally:
        leaked = [
            task
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
        ]
        for task in leaked:
            task.cancel()
        await asyncio.gather(*leaked, return_exceptions=True)


@pytest.mark.asyncio
async def test_capture_cleanup_wait_creation_failure_cancels_turn_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_create_task = asyncio.create_task
    failed = False

    def fail_capture_cleanup_wait(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        nonlocal failed
        if name == "reachy-ptt-cleanup-wait" and not failed:
            failed = True
            coroutine.close()
            raise RuntimeError("injected capture-cleanup-wait creation failure")
        if context is None:
            return original_create_task(coroutine, name=name)
        return original_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(asyncio, "create_task", fail_capture_cleanup_wait)
    media = HappyTurnMedia([], (b"\x2d\x00" * 40,))
    transport = ScriptedHappyTransport(
        PttInputMode.CORE_TERMINAL_TOGGLE,
        [],
        b"",
        auto_submit=False,
    )
    arguments = session_arguments()
    arguments.update(media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    outcome = await session.run()
    await asyncio.sleep(0)

    assert failed is True
    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert session._cleanup_source is PttStopSource.WATCHDOG
    assert session._semantic_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert transport.close_calls == 1
    assert not {
        task.get_name()
        for task in asyncio.all_tasks()
        if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
    }


@pytest.mark.asyncio
async def test_capture_cleanup_wait_failure_delegates_blocked_turn_to_t4_teardown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_create_task = asyncio.create_task
    failed = False
    prestarted_turn: asyncio.Task[None] | None = None

    def fail_capture_cleanup_wait(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        nonlocal failed
        if name == "reachy-ptt-turn":
            coroutine.close()
            assert prestarted_turn is not None
            return prestarted_turn
        if name == "reachy-ptt-cleanup-wait" and not failed:
            failed = True
            coroutine.close()
            raise RuntimeError("injected capture-cleanup-wait creation failure")
        if context is None:
            return original_create_task(coroutine, name=name)
        return original_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(asyncio, "create_task", fail_capture_cleanup_wait)
    clock = FakeClock()
    transport = FakeTransport()
    started = asyncio.Event()
    cancellation_seen = asyncio.Event()
    release = asyncio.Event()

    class CancellationResistantTurnSession(ReachyPttSession):
        async def _capture_terminal_turn(self, turn_deadline: float) -> None:
            del turn_deadline
            started.set()
            while not release.is_set():
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    cancellation_seen.set()

    arguments = session_arguments()
    arguments.update(clock=clock, transport=transport)
    session = CancellationResistantTurnSession(**arguments)  # type: ignore[arg-type]
    prestarted_turn = original_create_task(
        session._capture_terminal_turn(320.0),
        name="reachy-ptt-turn-prestarted",
    )
    await asyncio.wait_for(started.wait(), timeout=0.2)
    capture_owner = asyncio.create_task(
        session._run_capture_until_cleanup(320.0),
        name="test-reachy-ptt-capture-owner",
    )
    teardown_task: asyncio.Task[None] | None = None
    try:
        await asyncio.wait_for(cancellation_seen.wait(), timeout=0.2)

        done, _pending = await asyncio.wait({capture_owner}, timeout=0.05)
        assert failed is True
        assert capture_owner in done
        assert session._turn_task is not None
        assert not session._turn_task.done()

        teardown_task = asyncio.create_task(session._teardown_runtime())
        for _attempt in range(10):
            if 14.0 in clock.deadlines:
                break
            await asyncio.sleep(0)
        assert 14.0 in clock.deadlines
        clock.advance_to(14.0)
        release.set()
        await asyncio.wait_for(teardown_task, timeout=0.2)

        assert session._final_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert transport.close_calls == 0
        await asyncio.sleep(0)
        assert not {
            task.get_name()
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
        }
    finally:
        release.set()
        for task in (capture_owner, teardown_task, session._turn_task):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(
            *(task for task in (capture_owner, teardown_task, session._turn_task) if task),
            return_exceptions=True,
        )


@pytest.mark.asyncio
async def test_pre_run_stop_task_creation_failure_uses_cached_local_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_create_task = asyncio.create_task
    failed = False

    def fail_primary_stop_task(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        nonlocal failed
        if name == "reachy-ptt-cleanup" and not failed:
            failed = True
            coroutine.close()
            raise RuntimeError("injected pre-run cleanup-task creation failure")
        if context is None:
            return original_create_task(coroutine, name=name)
        return original_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(asyncio, "create_task", fail_primary_stop_task)
    media = FakeMedia()
    transport = FakeTransport()
    arguments = session_arguments()
    arguments.update(media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    first = await session.stop(PttStopSource.SUPERVISOR_INPUT)
    second = await session.stop(PttStopSource.WATCHDOG)

    assert failed is True
    assert first is second
    assert first.is_complete()
    assert media.cleanup_calls == ["recording", "playback", "motion", "audio_reactive"]
    assert transport.receive_calls == 0
    assert transport.sent == []
    assert transport.close_calls == 0
    with pytest.raises(RuntimeError, match="^PTT session is terminal$"):
        await session.run()


@pytest.mark.asyncio
async def test_pre_run_stop_repeated_owner_failure_still_runs_one_shared_local_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_create_task = asyncio.create_task
    loop = asyncio.get_running_loop()
    original_loop_create_task = loop.create_task
    failed_names: set[str] = set()

    def fail_both_pre_run_cleanup_owners(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        if name in {"reachy-ptt-cleanup", "reachy-ptt-cleanup-fallback"}:
            assert name is not None
            failed_names.add(name)
            raise RuntimeError("injected pre-run cleanup-owner failure")
        if context is None:
            return original_create_task(coroutine, name=name)
        return original_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(asyncio, "create_task", fail_both_pre_run_cleanup_owners)

    def fail_adopted_pre_run_cleanup_owner(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        if name == "reachy-ptt-cleanup-inline-fallback":
            failed_names.add(name)
            raise RuntimeError("injected adopted pre-run cleanup-owner failure")
        if context is None:
            return original_loop_create_task(coroutine, name=name)
        return original_loop_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(loop, "create_task", fail_adopted_pre_run_cleanup_owner)
    media = BlockingCleanupMedia()
    transport = FakeTransport()
    arguments = session_arguments()
    arguments.update(media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    first = asyncio.create_task(
        session.stop(PttStopSource.SUPERVISOR_INPUT),
        name="test-pre-run-stop-first",
    )
    second: asyncio.Task[PttSafetyReceipt] | None = None
    try:
        await asyncio.wait_for(media.started.wait(), timeout=0.2)
        cleanup_identity = session._cleanup_task
        assert cleanup_identity is not None
        second = asyncio.create_task(
            session.stop(PttStopSource.WATCHDOG),
            name="test-pre-run-stop-second",
        )

        first.cancel()
        await asyncio.sleep(0)
        first.cancel()
        await asyncio.sleep(0)
        assert first.done() is False

        media.release.set()
        with pytest.raises(asyncio.CancelledError):
            await first
        receipt = await second
        cached = await session.stop(PttStopSource.WATCHDOG)

        assert failed_names == {
            "reachy-ptt-cleanup",
            "reachy-ptt-cleanup-fallback",
            "reachy-ptt-cleanup-inline-fallback",
        }
        assert session._cleanup_task is cleanup_identity
        assert cleanup_identity.result() is receipt
        assert cached is receipt
        assert receipt.is_complete()
        assert sorted(media.cleanup_calls) == [
            "audio_reactive",
            "motion",
            "playback",
            "recording",
        ]
        assert media.cancelled == 0
        assert media.completed == 4
        assert transport.receive_calls == 0
        assert transport.sent == []
        assert transport.close_calls == 0
        with pytest.raises(RuntimeError, match="^PTT session is terminal$"):
            await session.run()
    finally:
        media.release.set()
        for task in (first, second):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(
            *(task for task in (first, second) if task is not None),
            return_exceptions=True,
        )


@pytest.mark.asyncio
async def test_core_frame_at_exact_prior_heartbeat_deadline_cannot_revive_session() -> None:
    events: list[str] = []
    clock = FakeClock()
    media = BlockingCaptureStageMedia(events, "read")
    transport = ScriptedHappyTransport(
        PttInputMode.CORE_TERMINAL_TOGGLE,
        events,
        b"",
        auto_submit=False,
    )
    arguments = session_arguments()
    arguments.update(clock=clock, media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await media.stage_started.wait()
        assert session._last_valid_core_frame == 10.0
        clock.current = 15.0
        transport.queue_heartbeat()

        done, _pending = await asyncio.wait({run_task}, timeout=0.2)

        assert run_task in done
        assert run_task.result() is PttSessionOutcome.SESSION_TIMEOUT
        assert session._last_valid_core_frame == 10.0
        errors = [
            frame.control.payload
            for frame in transport.edge_frames
            if isinstance(frame, ControlFrame) and frame.control.kind is ControlKind.ERROR
        ]
        assert len(errors) == 1
        assert isinstance(errors[0], ErrorPayload)
        assert errors[0].reason_code is PttErrorReason.SESSION_TIMEOUT
    finally:
        if not run_task.done():
            await session.stop(PttStopSource.SUPERVISOR_INPUT)
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_teardown_at_exact_t_plus_four_starts_no_bounded_await() -> None:
    clock = FakeClock()
    transport = FakeTransport()
    arguments = session_arguments()
    arguments.update(clock=clock, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    await session._request_cleanup(
        PttStopSource.WATCHDOG,
        PttSessionOutcome.SESSION_TIMEOUT,
    )
    clock.current = 14.0

    await session._teardown_runtime()

    assert transport.close_calls == 0
    assert clock.deadlines == []
    assert session._final_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE


@pytest.mark.asyncio
async def test_blocked_playback_cannot_block_reader_from_core_abort_and_ack() -> None:
    events: list[str] = []
    media = BlockingPlaybackOpenMedia(events)
    transport = ScriptedHappyTransport(
        PttInputMode.CORE_TERMINAL_TOGGLE,
        events,
        b"\x0d\x00" * 40,
    )
    arguments = session_arguments()
    arguments.update(media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await media.playback_open_started.wait()
        transport.queue_core_abort()

        done, _pending = await asyncio.wait({run_task}, timeout=0.2)
        assert run_task in done
        assert run_task.result() is PttSessionOutcome.CANCELLED
        assert media.playback_open_cancelled is True
        assert events.index("media:open_playback_cancelled") < events.index("sent:safety_receipt")
        assert media.playback == []
        assert media.close_playback_calls == 0
        assert transport.close_calls == 1
        await asyncio.sleep(0)
        assert not {
            task.get_name()
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
        }
    finally:
        if not run_task.done():
            cleanup_task = session._cleanup_task
            if cleanup_task is not None:
                cleanup_task.cancel()
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_playback_preserves_order_and_exact_bytes_across_multiple_pcm_frames() -> None:
    events: list[str] = []
    playback_chunks = (
        b"\x21\x00" * 7,
        b"\x22\x00" * 3_200,
        b"\x23\x00" * 11,
    )
    media = HappyTurnMedia(events, (b"\x20\x00" * 40,))
    transport = ScriptedHappyTransport(
        PttInputMode.CORE_TERMINAL_TOGGLE,
        events,
        playback_chunks,
    )
    arguments = session_arguments()
    arguments.update(media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    outcome = await session.run()

    assert outcome is PttSessionOutcome.COMPLETED
    assert media.playback == list(playback_chunks)
    assert b"".join(media.playback) == b"".join(playback_chunks)
    playback_events = [event for event in events if event.startswith("media:playback:")]
    assert playback_events == [f"media:playback:{len(chunk)}" for chunk in playback_chunks]


@pytest.mark.asyncio
async def test_full_playback_queue_fails_closed_and_drains_without_media_effects() -> None:
    events: list[str] = []
    media = HappyTurnMedia(events, ())
    playback_buffer = FakeBuffer()
    arguments = session_arguments()
    arguments.update(media=media, playback_buffer=playback_buffer)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    session._playback_gate = True
    session._playback_deadline = 100.0

    for sequence in range(64):
        await session._dispatch_core_frame(
            PcmFrame(turn_id=TURN_ID, sequence=sequence, pcm=b"\x24\x00")
        )
    assert session._playback_queue.qsize() == 64

    await session._dispatch_core_frame(PcmFrame(turn_id=TURN_ID, sequence=64, pcm=b"\x25\x00"))

    assert session._semantic_outcome is PttSessionOutcome.PLAYBACK_FAILED
    assert session._cleanup_started_at == 10.0
    assert session._playback_gate is False
    assert session._playback_queue.empty()
    assert playback_buffer.is_empty()
    assert media.playback == []
    assert "media:open_playback" not in events


@pytest.mark.asyncio
async def test_late_playback_start_pcm_and_end_after_cleanup_have_zero_media_effects() -> None:
    events: list[str] = []
    media = HappyTurnMedia(events, ())
    playback_buffer = FakeBuffer(b"old-playback")
    arguments = session_arguments()
    arguments.update(media=media, playback_buffer=playback_buffer)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    await session._request_cleanup(
        PttStopSource.SUPERVISOR_INPUT,
        PttSessionOutcome.CANCELLED,
    )

    await session._dispatch_core_frame(
        ControlFrame(
            turn_id=TURN_ID,
            sequence=0,
            control=PttControl.playback_start(TURN_ID, TRANSPORT_AUDIO_FORMAT),
        )
    )
    await session._dispatch_core_frame(PcmFrame(turn_id=TURN_ID, sequence=1, pcm=b"\x26\x00"))
    await session._dispatch_core_frame(
        ControlFrame(
            turn_id=TURN_ID,
            sequence=2,
            control=PttControl.playback_end(TURN_ID),
        )
    )

    assert session._playback_gate is False
    assert session._playback_queue.empty()
    assert playback_buffer.is_empty()
    assert media.playback == []
    assert "media:open_playback" not in events
    assert "media:close_playback" not in events


@pytest.mark.asyncio
@pytest.mark.parametrize("blocked_stage", ("write", "close"))
async def test_cleanup_cancels_blocked_playback_effect_without_orphan(
    blocked_stage: str,
) -> None:
    events: list[str] = []
    media = BlockingPlaybackStageMedia(events, blocked_stage)
    transport = ScriptedHappyTransport(
        PttInputMode.CORE_TERMINAL_TOGGLE,
        events,
        b"\x27\x00" * 40,
    )
    arguments = session_arguments()
    arguments.update(media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await asyncio.wait_for(media.stage_started.wait(), timeout=0.2)
        transport.queue_core_abort()

        outcome = await run_task

        assert outcome is PttSessionOutcome.CANCELLED
        assert media.stage_cancelled is True
        assert transport.close_calls == 1
        await asyncio.sleep(0)
        assert not {
            task.get_name()
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name().startswith("reachy-ptt-")
        }
    finally:
        if not run_task.done():
            cleanup_task = session._cleanup_task
            if cleanup_task is not None:
                cleanup_task.cancel()
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_local_capture_preserves_and_rechunks_all_bytes_until_submit() -> None:
    events: list[str] = []
    chunks = (
        b"\x0e\x00" * 3_501,
        b"\x0f\x00" * 2,
        b"\x10\x00" * 3_200,
    )
    media = MultiChunkCaptureMedia(events, chunks)
    capture_input = SubmitAfterThreeReadsInput(events, media)
    transport = ScriptedHappyTransport(PttInputMode.REACHY_LOCAL, events, b"\x11\x00")
    arguments = session_arguments()
    arguments.update(
        input_mode=PttInputMode.REACHY_LOCAL,
        media=media,
        transport=transport,
        capture_input=capture_input,
        stop_input=BlockingStopInput(),
    )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        done, _pending = await asyncio.wait({run_task}, timeout=0.2)
        assert run_task in done
        assert run_task.result() is PttSessionOutcome.COMPLETED
        capture_frames = [
            frame.pcm for frame in transport.edge_frames if isinstance(frame, PcmFrame)
        ]
        assert b"".join(capture_frames) == b"".join(chunks)
        assert all(0 < len(pcm) <= 6_400 and len(pcm) % 2 == 0 for pcm in capture_frames)
        assert media.read_count == 3
        assert events.index("input:submit") < events.index("media:close_capture")
    finally:
        if not run_task.done():
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failed_task_name",
    ("reachy-ptt-capture-cleanup", "reachy-ptt-capture-deadline"),
)
async def test_capture_subtask_creation_failure_rolls_back_earlier_tasks_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    failed_task_name: str,
) -> None:
    original_create_task = asyncio.create_task
    failed = False

    def fail_one_capture_task(
        coroutine: Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        context: Any = None,
    ) -> asyncio.Task[Any]:
        nonlocal failed
        if name == failed_task_name and not failed:
            failed = True
            coroutine.close()
            raise RuntimeError("injected capture-subtask creation failure")
        if context is None:
            return original_create_task(coroutine, name=name)
        return original_create_task(coroutine, name=name, context=context)

    monkeypatch.setattr(asyncio, "create_task", fail_one_capture_task)
    events: list[str] = []
    media = HappyTurnMedia(events, (b"\x28\x00" * 40,))
    transport = ScriptedHappyTransport(
        PttInputMode.CORE_TERMINAL_TOGGLE,
        events,
        b"",
        auto_submit=False,
    )
    arguments = session_arguments()
    arguments.update(media=media, transport=transport)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    capture_task_names = {
        "reachy-ptt-capture-submit",
        "reachy-ptt-capture-cleanup",
        "reachy-ptt-capture-deadline",
    }
    try:
        outcome = await session.run()
        await asyncio.sleep(0)

        assert failed is True
        assert outcome is PttSessionOutcome.CAPTURE_FAILED
        assert "media:read_capture" not in events
        assert transport.close_calls == 1
        assert not {
            task.get_name()
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name() in capture_task_names
        }
    finally:
        leaked = [
            task
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and task.get_name() in capture_task_names
        ]
        for task in leaked:
            task.cancel()
        await asyncio.gather(*leaked, return_exceptions=True)


@pytest.mark.asyncio
async def test_local_stop_cancels_active_capture_before_safety_receipt() -> None:
    events: list[str] = []
    media = CancellationOrderCaptureMedia(events)
    transport = ScriptedHappyTransport(PttInputMode.REACHY_LOCAL, events, b"")
    stop_input = BlockingStopInput()
    arguments = session_arguments()
    arguments.update(
        input_mode=PttInputMode.REACHY_LOCAL,
        media=media,
        transport=transport,
        capture_input=ImmediateCaptureInput(events),
        stop_input=stop_input,
    )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await media.read_started.wait()
        stop_input.release.set()

        outcome = await run_task

        assert outcome is PttSessionOutcome.CANCELLED
        assert events.index("media:read_capture_cancelled") < events.index("sent:safety_receipt")
    finally:
        if not run_task.done():
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_poison_after_normal_cleanup_control_switches_to_emergency_pair() -> None:
    events: list[str] = []
    media = LatePoisonMedia(events)
    transport = LatePoisonTransport(events)
    stop_input = BlockingStopInput()
    arguments = session_arguments()
    arguments.update(
        input_mode=PttInputMode.REACHY_LOCAL,
        media=media,
        transport=transport,
        capture_input=ImmediateCaptureInput(events),
        stop_input=stop_input,
    )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await media.read_started.wait()
        stop_input.release.set()
        for _ in range(50):
            if "sent:stop" in events and not session._active_send:
                break
            await asyncio.sleep(0)
        assert "sent:stop" in events
        assert session._active_send is False

        transport.inject_poison()
        for _ in range(50):
            if session._guard_poisoned:
                break
            await asyncio.sleep(0)
        assert session._guard_poisoned is True
        media.release.set()
        outcome = await run_task

        assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        controls = [
            frame.control.kind for frame in transport.edge_frames if isinstance(frame, ControlFrame)
        ]
        assert controls[-3:] == [
            ControlKind.STOP,
            ControlKind.ERROR,
            ControlKind.SAFETY_RECEIPT,
        ]
        assert [frame.sequence for frame in transport.edge_frames] == list(
            range(len(transport.edge_frames))
        )
        assert session._ack_received.is_set() is False
    finally:
        media.release.set()
        if not run_task.done():
            cleanup_task = session._cleanup_task
            if cleanup_task is not None:
                cleanup_task.cancel()
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("tail_kind", ("truncated", "extra_frame"))
async def test_ack_with_any_tail_poison_forces_incomplete_without_duplicate_receipt(
    tail_kind: str,
) -> None:
    events: list[str] = []
    transport = AckTailPoisonTransport(events, tail_kind)
    media = CancellationOrderCaptureMedia(events)
    stop_input = BlockingStopInput()
    arguments = session_arguments()
    arguments.update(
        input_mode=PttInputMode.REACHY_LOCAL,
        media=media,
        transport=transport,
        capture_input=ImmediateCaptureInput(events),
        stop_input=stop_input,
    )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await media.read_started.wait()
        stop_input.release.set()

        outcome = await run_task

        assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        controls = [
            frame.control.kind for frame in transport.edge_frames if isinstance(frame, ControlFrame)
        ]
        assert controls.count(ControlKind.SAFETY_RECEIPT) == 1
        assert ControlKind.ERROR not in controls
        assert session._ack_received.is_set() is False
        assert session._guard_poisoned is True
    finally:
        if not run_task.done():
            cleanup_task = session._cleanup_task
            if cleanup_task is not None:
                cleanup_task.cancel()
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "input_mode",
    (PttInputMode.REACHY_LOCAL, PttInputMode.CORE_TERMINAL_TOGGLE),
)
async def test_submit_before_any_pcm_cancels_read_and_reports_capture_failed(
    input_mode: PttInputMode,
) -> None:
    events: list[str] = []
    media = CancellationOrderCaptureMedia(events)
    transport = ScriptedHappyTransport(
        input_mode,
        events,
        b"",
        auto_submit=input_mode is PttInputMode.REACHY_LOCAL,
    )
    capture_input = (
        ControlledCaptureInput(events) if input_mode is PttInputMode.REACHY_LOCAL else None
    )
    arguments = session_arguments()
    arguments.update(
        input_mode=input_mode,
        media=media,
        transport=transport,
        capture_input=capture_input,
        stop_input=(BlockingStopInput() if input_mode is PttInputMode.REACHY_LOCAL else None),
    )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await media.read_started.wait()
        if input_mode is PttInputMode.REACHY_LOCAL:
            assert capture_input is not None
            capture_input.submit.set()
        else:
            transport._queue_control(PttControl.ptt_submit(TURN_ID))
        done, _pending = await asyncio.wait({run_task}, timeout=0.2)

        assert run_task in done
        assert run_task.result() is PttSessionOutcome.CAPTURE_FAILED
        assert "media:read_capture_cancelled" in events
        controls = [
            frame.control for frame in transport.edge_frames if isinstance(frame, ControlFrame)
        ]
        assert ControlKind.CAPTURE_END not in {control.kind for control in controls}
        errors = [control.payload for control in controls if control.kind is ControlKind.ERROR]
        assert len(errors) == 1
        assert isinstance(errors[0], ErrorPayload)
        assert errors[0].reason_code is PttErrorReason.CAPTURE_FAILED
        assert session._guard_poisoned is False
    finally:
        if not run_task.done():
            await session.stop(PttStopSource.SUPERVISOR_INPUT)
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    (
        "open_raise",
        "read_raise",
        "read_none",
        "read_non_bytes",
        "read_empty",
        "read_odd",
        "close_raise",
        "close_false",
        "close_non_bool",
    ),
)
@pytest.mark.parametrize(
    "input_mode",
    (PttInputMode.REACHY_LOCAL, PttInputMode.CORE_TERMINAL_TOGGLE),
)
async def test_capture_stage_failures_are_semantic_not_protocol_poison(
    input_mode: PttInputMode,
    failure: str,
) -> None:
    events: list[str] = []
    media = CaptureStageFailureMedia(events, failure)
    transport = ScriptedHappyTransport(input_mode, events, b"")
    arguments = session_arguments()
    arguments.update(
        input_mode=input_mode,
        media=media,
        transport=transport,
        capture_input=(
            ImmediateCaptureInput(events) if input_mode is PttInputMode.REACHY_LOCAL else None
        ),
        stop_input=(BlockingStopInput() if input_mode is PttInputMode.REACHY_LOCAL else None),
    )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    outcome = await session.run()

    assert outcome is PttSessionOutcome.CAPTURE_FAILED
    assert session._guard_poisoned is False
    controls = [frame.control for frame in transport.edge_frames if isinstance(frame, ControlFrame)]
    assert ControlKind.CAPTURE_END not in {control.kind for control in controls}
    errors = [control.payload for control in controls if control.kind is ControlKind.ERROR]
    assert len(errors) == 1
    assert isinstance(errors[0], ErrorPayload)
    assert errors[0].reason_code is PttErrorReason.CAPTURE_FAILED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "input_mode",
    (PttInputMode.REACHY_LOCAL, PttInputMode.CORE_TERMINAL_TOGGLE),
)
async def test_native_capture_read_over_ceiling_fails_before_buffer_copy(
    input_mode: PttInputMode,
) -> None:
    events: list[str] = []
    capture_buffer = AppendRecordingBuffer()
    media = HappyTurnMedia(events, (b"\x35\x00" * ((MAX_PCM_BYTES // 2) + 1),))
    transport = ScriptedHappyTransport(input_mode, events, b"")
    arguments = session_arguments()
    arguments.update(
        capture_buffer=capture_buffer,
        capture_input=(
            ImmediateCaptureInput(events) if input_mode is PttInputMode.REACHY_LOCAL else None
        ),
        input_mode=input_mode,
        media=media,
        stop_input=(BlockingStopInput() if input_mode is PttInputMode.REACHY_LOCAL else None),
        transport=transport,
    )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    outcome = await session.run()

    assert outcome is PttSessionOutcome.CAPTURE_FAILED
    assert session._guard_poisoned is False
    assert capture_buffer.append_calls == 0
    assert not any(isinstance(frame, PcmFrame) for frame in transport.edge_frames)
    controls = [frame.control for frame in transport.edge_frames if isinstance(frame, ControlFrame)]
    assert ControlKind.CAPTURE_END not in {control.kind for control in controls}
    errors = [control.payload for control in controls if control.kind is ControlKind.ERROR]
    assert len(errors) == 1
    assert isinstance(errors[0], ErrorPayload)
    assert errors[0].reason_code is PttErrorReason.CAPTURE_FAILED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "input_mode",
    (PttInputMode.REACHY_LOCAL, PttInputMode.CORE_TERMINAL_TOGGLE),
)
async def test_native_capture_read_at_exact_ceiling_is_rechunked_without_loss(
    input_mode: PttInputMode,
) -> None:
    events: list[str] = []
    captured = b"\x36\x00" * (MAX_PCM_BYTES // 2)
    capture_buffer = AppendRecordingBuffer()
    media = HappyTurnMedia(events, (captured,))
    transport = ScriptedHappyTransport(input_mode, events, b"\x37\x00" * 40)
    arguments = session_arguments()
    arguments.update(
        capture_buffer=capture_buffer,
        capture_input=(
            ImmediateCaptureInput(events) if input_mode is PttInputMode.REACHY_LOCAL else None
        ),
        input_mode=input_mode,
        media=media,
        stop_input=(BlockingStopInput() if input_mode is PttInputMode.REACHY_LOCAL else None),
        transport=transport,
    )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    outcome = await session.run()

    outbound_pcm = [frame.pcm for frame in transport.edge_frames if isinstance(frame, PcmFrame)]
    assert outcome is PttSessionOutcome.COMPLETED
    assert capture_buffer.append_calls == 1
    assert b"".join(outbound_pcm) == captured
    assert all(0 < len(chunk) <= 6_400 and len(chunk) % 2 == 0 for chunk in outbound_pcm)


@pytest.mark.asyncio
async def test_capture_read_ready_at_exact_deadline_is_rejected_before_buffering() -> None:
    clock = FakeClock(now=10.0)
    media = DeadlineCaptureMedia(b"\x38\x00" * 40)
    capture_buffer = AppendRecordingBuffer()
    arguments = session_arguments()
    arguments.update(clock=clock, media=media, capture_buffer=capture_buffer)
    session = CaptureDeadlineHarnessSession(**arguments)
    submit = asyncio.Event()
    capture_task = asyncio.create_task(
        session._capture_until_submit(submit.wait(), 100.0),
        name="test-capture-exact-deadline",
    )

    await media.read_started.wait()
    clock.current = 100.0
    media.release_read.set()

    assert await capture_task is False
    assert capture_buffer.append_calls == 0
    assert session.outbound_pcm == []
    assert session._semantic_outcome is PttSessionOutcome.CAPTURE_FAILED


@pytest.mark.asyncio
async def test_capture_rechunk_stops_when_first_send_reaches_absolute_deadline() -> None:
    clock = FakeClock(now=99.9)
    captured = b"\x39\x00" * (MAX_PCM_BYTES // 2)
    media = DeadlineCaptureMedia(captured)
    media.release_read.set()
    capture_buffer = AppendRecordingBuffer()
    arguments = session_arguments()
    arguments.update(clock=clock, media=media, capture_buffer=capture_buffer)
    session = CaptureDeadlineHarnessSession(
        advance_after_first_pcm_to=100.0,
        **arguments,
    )
    submit = asyncio.Event()

    completed = await session._capture_until_submit(submit.wait(), 100.0)

    assert completed is False
    assert capture_buffer.append_calls == 1
    assert session.outbound_pcm == [captured[:MAX_TRANSPORT_PCM_FRAME_BYTES]]
    assert session.outbound_deadlines == [100.0]
    assert session._semantic_outcome is PttSessionOutcome.CAPTURE_FAILED


@pytest.mark.asyncio
async def test_expired_queued_pcm_draft_fails_before_guard_or_transport_effect() -> None:
    clock = FakeClock(now=100.0)
    transport = FakeTransport()
    arguments = session_arguments()
    arguments.update(clock=clock, transport=transport)
    session = DeadlineGuardSession(**arguments)
    writer_task = asyncio.create_task(session._writer_loop(), name="test-deadline-writer")

    try:
        with pytest.raises(RuntimeError, match="not sent"):
            await session._enqueue_normal(pcm=b"\x40\x00", absolute_deadline=100.0)

        assert session.guard_accept_calls == 0
        assert transport.sent == []
    finally:
        writer_task.cancel()
        await asyncio.gather(writer_task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("fault_phase", ("send_start", "pre_transport", "blocked_send"))
async def test_clock_fault_never_allows_an_outbound_draft_to_succeed(
    fault_phase: str,
) -> None:
    clock = InvalidNowClock()
    transport: FakeTransport
    if fault_phase == "blocked_send":
        transport = ControlledWriterFailureTransport("success")
    else:
        transport = FakeTransport()
    arguments = session_arguments()
    arguments.update(clock=clock, transport=transport)
    session_type = (
        ClockFaultingGuardSession if fault_phase == "pre_transport" else DeadlineGuardSession
    )
    session = session_type(**arguments)
    session._last_clock_value = clock.now()
    writer_task = asyncio.create_task(session._writer_loop(), name="test-clock-fault-writer")
    if fault_phase == "send_start":
        clock.failure = "raise"
    producer_task = asyncio.create_task(
        session._enqueue_normal(pcm=b"\x41\x00"),
        name="test-clock-fault-producer",
    )

    try:
        if fault_phase == "blocked_send":
            assert isinstance(transport, ControlledWriterFailureTransport)
            await transport.send_started.wait()
            clock.failure = "raise"
            session._clock_now()
            await asyncio.sleep(0)
            transport.release_send.set()

        result = await asyncio.gather(producer_task, return_exceptions=True)

        assert len(result) == 1
        assert type(result[0]) is RuntimeError
        assert session._edge_sequence == 0
        assert session._transport_writable is False
        assert session._clock_faulted is True
        assert session._cleanup_source is PttStopSource.WATCHDOG
        assert session._semantic_outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert transport.sent == []
        if isinstance(transport, ControlledWriterFailureTransport):
            assert transport.send_cancelled is True
        with pytest.raises(RuntimeError, match="unwritable"):
            await session._enqueue_terminal(PttControl.stop(TURN_ID))
    finally:
        if isinstance(transport, ControlledWriterFailureTransport):
            transport.release_send.set()
        producer_task.cancel()
        writer_task.cancel()
        await asyncio.gather(producer_task, writer_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_clock_fault_while_send_deadline_owner_is_joined_fails_the_draft() -> None:
    clock = DeadlineCancellationBarrierClock()
    transport = FakeTransport()
    arguments = session_arguments()
    arguments.update(clock=clock, transport=transport)
    session = DeadlineGuardSession(**arguments)
    session._last_clock_value = clock.now()
    writer_task = asyncio.create_task(session._writer_loop(), name="test-clock-fault-writer")
    producer_task = asyncio.create_task(
        session._enqueue_normal(pcm=b"\x42\x00"),
        name="test-clock-fault-producer",
    )

    try:
        await clock.deadline_cancel_started.wait()
        assert len(transport.sent) == 1
        clock.failure = "raise"
        session._clock_now()
        clock.release_deadline_cancel.set()

        result = await asyncio.gather(producer_task, return_exceptions=True)

        assert len(result) == 1
        assert type(result[0]) is RuntimeError
        assert session._edge_sequence == 0
        assert session._transport_writable is False
        assert session._clock_faulted is True
        with pytest.raises(RuntimeError, match="unwritable"):
            await session._enqueue_terminal(PttControl.stop(TURN_ID))
    finally:
        clock.release_deadline_cancel.set()
        producer_task.cancel()
        writer_task.cancel()
        await asyncio.gather(producer_task, writer_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_capture_controls_and_close_share_absolute_media_deadline() -> None:
    clock = FakeClock(now=10.0)
    arguments = session_arguments()
    arguments.update(clock=clock)
    session = CaptureControlDeadlineSession(
        capture_accepted_at=12.0,
        submitted_at=101.9,
        **arguments,
    )
    session._ptt_started_at = 10.0
    session._ptt_started.set()

    await session._capture_terminal_turn(turn_deadline=320.0)

    assert session.control_deadlines == {
        ControlKind.CAPTURE_START: 12.0,
        ControlKind.CAPTURE_END: 102.0,
    }
    assert session.operation_deadlines["reachy-ptt-capture-open"] == 12.0
    assert session.operation_deadlines["reachy-ptt-capture-close"] == 102.0


@pytest.mark.asyncio
async def test_playback_deadline_uses_zero_run_timestamp_as_turn_anchor() -> None:
    clock = FakeClock(now=305.0)
    arguments = session_arguments()
    arguments.update(clock=clock)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    session._run_started_at = 0.0
    session._playback_started_at = 305.0
    frame = ControlFrame(
        turn_id=TURN_ID,
        sequence=0,
        control=PttControl.playback_start(TURN_ID, TRANSPORT_AUDIO_FORMAT),
    )

    await session._dispatch_core_frame(frame)

    assert session._playback_deadline == 310.0


@pytest.mark.asyncio
@pytest.mark.parametrize("anchor", ("open", "capture", "close"))
async def test_capture_stage_deadlines_use_original_trigger_timestamps(
    anchor: str,
) -> None:
    events: list[str] = []
    clock = FakeClock()
    if anchor == "open":
        media = BlockingCaptureStageMedia(events, "open")
        auto_submit = False
    elif anchor == "capture":
        media = BlockingCaptureStageMedia(events, "read")
        auto_submit = False
    else:
        media = BlockingCaptureStageMedia(events, "close")
        auto_submit = True
    transport = ScriptedHappyTransport(
        PttInputMode.CORE_TERMINAL_TOGGLE,
        events,
        b"",
        auto_submit=auto_submit,
    )
    arguments = session_arguments()
    arguments.update(media=media, transport=transport, clock=clock)

    if anchor == "open":

        class DelayedStartDispatchSession(ReachyPttSession):
            async def _dispatch_core_frame(self, frame: object) -> None:
                await super()._dispatch_core_frame(frame)  # type: ignore[arg-type]
                if isinstance(frame, ControlFrame) and frame.control.kind is ControlKind.PTT_START:
                    while self._active_send:
                        await asyncio.sleep(0)
                    clock.current = 12.0

        session = DelayedStartDispatchSession(**arguments)  # type: ignore[arg-type]
    else:

        class DelayedAdmissionSession(ReachyPttSession):
            async def _enqueue_normal(
                self,
                *,
                control: PttControl | None = None,
                pcm: bytes | None = None,
                absolute_deadline: float | None = None,
            ) -> None:
                await super()._enqueue_normal(
                    control=control,
                    pcm=pcm,
                    absolute_deadline=absolute_deadline,
                )
                if (
                    anchor == "capture"
                    and control is not None
                    and control.kind is ControlKind.CAPTURE_START
                ):
                    clock.current = 100.0
                elif anchor == "close" and pcm is not None:
                    clock.current = 12.0

        session = DelayedAdmissionSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        done, _pending = await asyncio.wait({run_task}, timeout=0.2)

        assert run_task in done
        assert run_task.result() is PttSessionOutcome.CAPTURE_FAILED
        assert media.stage_started.is_set() is False
        errors = [
            frame.control.payload
            for frame in transport.edge_frames
            if isinstance(frame, ControlFrame) and frame.control.kind is ControlKind.ERROR
        ]
        assert len(errors) == 1
        assert isinstance(errors[0], ErrorPayload)
        assert errors[0].reason_code is PttErrorReason.CAPTURE_FAILED
    finally:
        if not run_task.done():
            await session.stop(PttStopSource.SUPERVISOR_INPUT)
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ("open", "read", "close"))
@pytest.mark.parametrize(
    "input_mode",
    (PttInputMode.REACHY_LOCAL, PttInputMode.CORE_TERMINAL_TOGGLE),
)
async def test_capture_stage_timeouts_are_capture_failed_in_both_modes(
    input_mode: PttInputMode,
    stage: str,
) -> None:
    events: list[str] = []
    clock = FakeClock()
    media = BlockingCaptureStageMedia(events, stage)
    capture_input = (
        ControlledCaptureInput(events)
        if input_mode is PttInputMode.REACHY_LOCAL and stage == "read"
        else ImmediateCaptureInput(events)
        if input_mode is PttInputMode.REACHY_LOCAL
        else None
    )
    transport = ScriptedHappyTransport(
        input_mode,
        events,
        b"",
        auto_submit=stage != "read",
    )
    arguments = session_arguments()
    arguments.update(
        input_mode=input_mode,
        media=media,
        transport=transport,
        capture_input=capture_input,
        stop_input=(BlockingStopInput() if input_mode is PttInputMode.REACHY_LOCAL else None),
        clock=clock,
    )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await media.stage_started.wait()
        if stage == "read":
            async with session._guard_lock:
                clock.current = 96.0
                session._last_valid_core_frame = 96.0
            assert session._last_valid_core_frame == 96.0
            clock.advance_to(100.0)
        else:
            clock.advance_to(12.0)

        outcome = await run_task

        assert outcome is PttSessionOutcome.CAPTURE_FAILED
        assert media.stage_cancelled is True
        assert session._guard_poisoned is False
        errors = [
            frame.control.payload
            for frame in transport.edge_frames
            if isinstance(frame, ControlFrame) and frame.control.kind is ControlKind.ERROR
        ]
        assert len(errors) == 1
        assert isinstance(errors[0], ErrorPayload)
        assert errors[0].reason_code is PttErrorReason.CAPTURE_FAILED
    finally:
        if not run_task.done():
            await session.stop(PttStopSource.SUPERVISOR_INPUT)
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    ("open_raise", "write_raise", "close_raise", "close_false", "close_non_bool"),
)
@pytest.mark.parametrize(
    "input_mode",
    (PttInputMode.REACHY_LOCAL, PttInputMode.CORE_TERMINAL_TOGGLE),
)
async def test_playback_stage_failures_are_semantic_not_protocol_poison(
    input_mode: PttInputMode,
    failure: str,
) -> None:
    events: list[str] = []
    media = PlaybackStageFailureMedia(events, failure)
    transport = ScriptedHappyTransport(input_mode, events, b"\x15\x00" * 40)
    arguments = session_arguments()
    arguments.update(
        input_mode=input_mode,
        media=media,
        transport=transport,
        capture_input=(
            ImmediateCaptureInput(events) if input_mode is PttInputMode.REACHY_LOCAL else None
        ),
        stop_input=(BlockingStopInput() if input_mode is PttInputMode.REACHY_LOCAL else None),
    )
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]

    outcome = await session.run()

    assert outcome is PttSessionOutcome.PLAYBACK_FAILED
    assert session._guard_poisoned is False
    errors = [
        frame.control.payload
        for frame in transport.edge_frames
        if isinstance(frame, ControlFrame) and frame.control.kind is ControlKind.ERROR
    ]
    assert len(errors) == 1
    assert isinstance(errors[0], ErrorPayload)
    assert errors[0].reason_code is PttErrorReason.PLAYBACK_FAILED


@pytest.mark.asyncio
async def test_playback_deadline_uses_guard_acceptance_timestamp() -> None:
    events: list[str] = []
    clock = FakeClock()
    media = BlockingPlaybackStageMedia(events, "open")
    transport = ScriptedHappyTransport(
        PttInputMode.CORE_TERMINAL_TOGGLE,
        events,
        b"\x16\x00" * 40,
        complete_playback=False,
    )
    arguments = session_arguments()
    arguments.update(media=media, transport=transport, clock=clock)

    class DelayedPlaybackDispatchSession(ReachyPttSession):
        async def _dispatch_core_frame(self, frame: object) -> None:
            if isinstance(frame, ControlFrame) and frame.control.kind is ControlKind.PLAYBACK_START:
                while self._active_send:
                    await asyncio.sleep(0)
                clock.current = 100.0
            await super()._dispatch_core_frame(frame)  # type: ignore[arg-type]

    session = DelayedPlaybackDispatchSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        done, _pending = await asyncio.wait({run_task}, timeout=0.2)

        assert run_task in done
        assert run_task.result() is PttSessionOutcome.PLAYBACK_FAILED
        assert media.stage_started.is_set() is False
        assert session._guard_poisoned is False
    finally:
        if not run_task.done():
            await session.stop(PttStopSource.SUPERVISOR_INPUT)
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)


def test_edge_cli_has_exact_parameter_free_ptt_surface() -> None:
    from tuntun_edge.cli.main import app
    from typer.main import get_command

    command = get_command(app)

    assert app.info.no_args_is_help is True
    assert app._add_completion is False
    assert command.params == []
    assert list(command.commands) == ["ptt", "managed", "reachy"]  # type: ignore[attr-defined]
    assert command.commands["ptt"].params == []  # type: ignore[attr-defined]


def test_edge_ptt_placeholder_is_content_free_and_rejects_runtime_overrides() -> None:
    from tuntun_edge.cli.main import app
    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(app, ["ptt"])

    assert result.exit_code == 1
    assert result.stdout == ""
    assert result.stderr == "reachy-ptt-unavailable\n"

    for arguments in (["ptt", "--mode", "reachy_local"], ["ptt", "--motion"]):
        rejected = runner.invoke(app, arguments)
        assert rejected.exit_code == 2
        assert rejected.stdout == ""
        assert "reachy-ptt-unavailable" not in rejected.stderr


def test_edge_cli_help_stays_outside_binary_mode() -> None:
    from tuntun_edge.cli.main import app
    from typer.testing import CliRunner

    runner = CliRunner()
    for arguments in (["--help"], ["ptt", "--help"]):
        result = runner.invoke(app, arguments)
        assert result.exit_code == 0
        assert "Usage:" in result.stdout
        assert result.stderr == ""


def test_installed_edge_script_runs_without_pythonpath(tmp_path: Path) -> None:
    executable = Path(sys.executable).with_name("tuntun-edge")
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)

    assert executable.is_file()
    result = subprocess.run(
        (str(executable), "ptt"),
        check=False,
        capture_output=True,
        cwd=tmp_path,
        env=environment,
        timeout=5,
    )

    assert result.returncode == 1
    assert result.stdout == b""
    assert result.stderr == b"reachy-ptt-unavailable\n"


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ("open", "write", "close"))
async def test_playback_stage_timeouts_are_playback_failed(stage: str) -> None:
    events: list[str] = []
    clock = FakeClock()
    media = BlockingPlaybackStageMedia(events, stage)
    transport = ScriptedHappyTransport(
        PttInputMode.CORE_TERMINAL_TOGGLE,
        events,
        b"\x17\x00" * 40,
    )
    arguments = session_arguments()
    arguments.update(media=media, transport=transport, clock=clock)
    session = ReachyPttSession(**arguments)  # type: ignore[arg-type]
    run_task = asyncio.create_task(session.run(), name="test-reachy-ptt-run")
    try:
        await media.stage_started.wait()
        async with session._guard_lock:
            clock.current = 96.0
            session._last_valid_core_frame = 96.0
        assert session._last_valid_core_frame == 96.0
        clock.advance_to(100.0)

        outcome = await run_task

        assert outcome is PttSessionOutcome.PLAYBACK_FAILED
        assert media.stage_cancelled is True
        assert session._guard_poisoned is False
        errors = [
            frame.control.payload
            for frame in transport.edge_frames
            if isinstance(frame, ControlFrame) and frame.control.kind is ControlKind.ERROR
        ]
        assert len(errors) == 1
        assert isinstance(errors[0], ErrorPayload)
        assert errors[0].reason_code is PttErrorReason.PLAYBACK_FAILED
    finally:
        if not run_task.done():
            await session.stop(PttStopSource.SUPERVISOR_INPUT)
            run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)
