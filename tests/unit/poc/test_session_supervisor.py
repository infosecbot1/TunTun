from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Iterable
from typing import cast
from uuid import UUID

import pytest
from tuntun_contracts.poc.framing import (
    MAX_FEED_BYTES,
    TRANSPORT_AUDIO_FORMAT,
    AckPayload,
    ControlFrame,
    ControlKind,
    ErrorPayload,
    FrameDecoder,
    GuardDisposition,
    PcmFrame,
    PttControl,
    PttDuplexGuard,
    PttErrorReason,
    PttInputMode,
    PttSafetyReceipt,
    PttSessionOutcome,
    StreamDirection,
    WireFrame,
    encode_control_frame,
    encode_pcm_frame,
)
from tuntun_contracts.speech import SpeechChunk
from tuntun_core.services.poc import deadlines as deadline_module
from tuntun_core.services.poc import session_supervisor as supervisor_module
from tuntun_core.services.poc.ports import CapturedTurn, CorePttEvent, PttSendCommit
from tuntun_core.services.poc.session_supervisor import CorePttSessionSupervisor

TURN_ID = UUID("30000000-0000-4000-8000-000000000001")
REQUEST_ID = UUID("31000000-0000-4000-8000-000000000001")
CAPTURE_PCM = b"\x01\x00\x02\x00"
PLAYBACK_PCM = b"\x03\x00\x04\x00"


class _FatalProbe(BaseException):
    pass


def _committed() -> PttSendCommit:
    return PttSendCommit.COMMITTED


def _uncommitted() -> PttSendCommit:
    return PttSendCommit.UNCOMMITTED


class _Clock:
    def __init__(self) -> None:
        self.current = 0.0
        self.sleepers: list[tuple[float, asyncio.Event]] = []

    def now(self) -> float:
        return self.current

    async def sleep_until(self, deadline: float) -> None:
        release = asyncio.Event()
        self.sleepers.append((deadline, release))
        await release.wait()

    def expire(self, deadline: float) -> None:
        self.current = deadline
        released = False
        for scheduled, event in self.sleepers:
            if scheduled == deadline:
                event.set()
                released = True
        assert released


async def _suppress_task_cancellation(
    entered: asyncio.Event,
    cancelled: asyncio.Event,
    release: asyncio.Event,
) -> None:
    entered.set()
    while not release.is_set():
        try:
            await release.wait()
        except asyncio.CancelledError:
            cancelled.set()


class _Input:
    def __init__(self, events: Iterable[CorePttEvent]) -> None:
        self._events: asyncio.Queue[CorePttEvent] = asyncio.Queue()
        for event in events:
            self._events.put_nowait(event)
        self.closed = 0
        self.receive_calls = 0

    async def receive(self) -> CorePttEvent:
        self.receive_calls += 1
        return await self._events.get()

    async def close(self) -> None:
        self.closed += 1

    def put(self, event: CorePttEvent) -> None:
        self._events.put_nowait(event)


class _Pipeline:
    def __init__(
        self,
        clock: _Clock,
        chunks: Iterable[object] | None = None,
    ) -> None:
        self.clock = clock
        self._chunks = tuple(
            chunks
            if chunks is not None
            else (
                SpeechChunk(
                    request_id=REQUEST_ID,
                    sequence=0,
                    pcm=PLAYBACK_PCM,
                    final=False,
                ),
                SpeechChunk(
                    request_id=REQUEST_ID,
                    sequence=1,
                    pcm=b"",
                    final=True,
                ),
            )
        )
        self.captures: list[bytes] = []
        self.calls = 0
        self.finalized = 0

    async def run(self, captured: CapturedTurn) -> AsyncIterator[SpeechChunk]:
        self.calls += 1
        pcm = captured.claim_pcm()
        self.captures.append(bytes(pcm))
        try:
            for chunk in self._chunks:
                yield cast(SpeechChunk, chunk)
        finally:
            pcm[:] = b"\x00" * len(pcm)
            pcm.clear()
            captured.clear()
            self.finalized += 1

    async def observe_quarantine(self, *, deadline: float) -> bool:
        return True


class _BlockingPipeline(_Pipeline):
    def __init__(self, clock: _Clock) -> None:
        super().__init__(clock)
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.owned_pcm: bytearray | None = None

    async def run(self, captured: CapturedTurn) -> AsyncIterator[SpeechChunk]:
        self.calls += 1
        pcm = captured.claim_pcm()
        self.owned_pcm = pcm
        self.captures.append(bytes(pcm))
        self.entered.set()
        try:
            await self.release.wait()
            yield SpeechChunk(
                request_id=REQUEST_ID,
                sequence=0,
                pcm=PLAYBACK_PCM,
                final=False,
            )
            yield SpeechChunk(request_id=REQUEST_ID, sequence=1, pcm=b"", final=True)
        finally:
            pcm[:] = b"\x00" * len(pcm)
            pcm.clear()
            captured.clear()
            self.finalized += 1


class _CancellationSuppressingResultPipeline(_Pipeline):
    def __init__(self, clock: _Clock) -> None:
        super().__init__(clock)
        self.entered = asyncio.Event()
        self.cancelled = asyncio.Event()
        self.release = asyncio.Event()

    async def run(self, captured: CapturedTurn) -> AsyncIterator[SpeechChunk]:
        pcm = captured.claim_pcm()
        self.entered.set()
        try:
            while not self.release.is_set():
                try:
                    await self.release.wait()
                except asyncio.CancelledError:
                    self.cancelled.set()
            yield SpeechChunk(
                request_id=REQUEST_ID,
                sequence=0,
                pcm=PLAYBACK_PCM,
                final=False,
            )
            yield SpeechChunk(request_id=REQUEST_ID, sequence=1, pcm=b"", final=True)
        finally:
            pcm[:] = b"\x00" * len(pcm)
            pcm.clear()
            captured.clear()
            self.finalized += 1


class _PartialPlaybackPipeline(_Pipeline):
    def __init__(self, clock: _Clock, pcm: bytes) -> None:
        super().__init__(clock)
        self._pcm = pcm
        self.blocked_after_chunk = asyncio.Event()
        self.release = asyncio.Event()

    async def run(self, captured: CapturedTurn) -> AsyncIterator[SpeechChunk]:
        self.calls += 1
        capture = captured.claim_pcm()
        self.captures.append(bytes(capture))
        try:
            yield SpeechChunk(
                request_id=REQUEST_ID,
                sequence=0,
                pcm=self._pcm,
                final=False,
            )
            self.blocked_after_chunk.set()
            await self.release.wait()
            yield SpeechChunk(request_id=REQUEST_ID, sequence=1, pcm=b"", final=True)
        finally:
            capture[:] = b"\x00" * len(capture)
            capture.clear()
            captured.clear()
            self.finalized += 1


class _GatedInvalidPipeline(_BlockingPipeline):
    async def run(self, captured: CapturedTurn) -> AsyncIterator[SpeechChunk]:
        self.calls += 1
        pcm = captured.claim_pcm()
        self.owned_pcm = pcm
        self.captures.append(bytes(pcm))
        self.entered.set()
        try:
            await self.release.wait()
            yield SpeechChunk(request_id=REQUEST_ID, sequence=0, pcm=b"", final=True)
        finally:
            pcm[:] = b"\x00" * len(pcm)
            pcm.clear()
            captured.clear()
            self.finalized += 1


class _CancelledIteratorPipeline(_Pipeline):
    async def run(self, captured: CapturedTurn) -> AsyncIterator[SpeechChunk]:
        self.calls += 1
        pcm = captured.claim_pcm()
        self.captures.append(bytes(pcm))
        try:
            raise asyncio.CancelledError
            yield SpeechChunk(request_id=REQUEST_ID, sequence=0, pcm=b"", final=True)
        finally:
            pcm[:] = b"\x00" * len(pcm)
            pcm.clear()
            captured.clear()
            self.finalized += 1


class _IteratorCloseFailurePipeline(_Pipeline):
    def __init__(
        self,
        clock: _Clock,
        *,
        body_error: BaseException | None,
        close_error: BaseException,
        first_chunk: SpeechChunk | None = None,
    ) -> None:
        super().__init__(clock)
        self.body_error = body_error
        self.close_error = close_error
        self.first_chunk = first_chunk
        self.entered = asyncio.Event()
        self.close_calls = 0

    def run(self, captured: CapturedTurn) -> AsyncIterator[SpeechChunk]:
        self.calls += 1
        pcm = captured.claim_pcm()
        self.captures.append(bytes(pcm))
        pipeline = self

        class _Stream:
            def __init__(self) -> None:
                self._yielded = False

            def __aiter__(self) -> _Stream:
                return self

            async def __anext__(self) -> SpeechChunk:
                pipeline.entered.set()
                if pipeline.first_chunk is not None and not self._yielded:
                    self._yielded = True
                    return pipeline.first_chunk
                if pipeline.body_error is None:
                    await asyncio.Event().wait()
                    raise AssertionError("unreachable")
                raise pipeline.body_error

            async def aclose(self) -> None:
                pipeline.close_calls += 1
                pcm[:] = b"\x00" * len(pcm)
                pcm.clear()
                captured.clear()
                pipeline.finalized += 1
                raise pipeline.close_error

        return _Stream()


class _SplitIteratorPipeline(_Pipeline):
    def __init__(self, clock: _Clock) -> None:
        super().__init__(clock)
        self.inner_close_calls = 0
        self.outer_close_calls = 0
        self.inner_pcm: bytearray | None = None

    def run(self, captured: CapturedTurn) -> AsyncIterator[SpeechChunk]:
        pipeline = self
        pcm = captured.claim_pcm()
        self.inner_pcm = pcm

        class _Inner:
            def __init__(self) -> None:
                self._yielded = False

            def __aiter__(self) -> _Inner:
                return self

            async def __anext__(self) -> SpeechChunk:
                if self._yielded:
                    raise StopAsyncIteration
                self._yielded = True
                return cast(SpeechChunk, object())

            async def aclose(self) -> None:
                pipeline.inner_close_calls += 1
                pcm[:] = b"\x00" * len(pcm)
                pcm.clear()
                captured.clear()

        inner = _Inner()

        class _Outer:
            def __aiter__(self) -> _Inner:
                return inner

            async def aclose(self) -> None:
                pipeline.outer_close_calls += 1

        return cast(AsyncIterator[SpeechChunk], _Outer())


class _Cancellation:
    def __init__(self) -> None:
        self.calls = 0
        self.turn_ids: list[UUID] = []

    async def close_active_transport(self, *, turn_id: UUID) -> None:
        self.calls += 1
        self.turn_ids.append(turn_id)


class _BlockingCancellation(_Cancellation):
    def __init__(self) -> None:
        super().__init__()
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def close_active_transport(self, *, turn_id: UUID) -> None:
        await super().close_active_transport(turn_id=turn_id)
        self.entered.set()
        await self.release.wait()


class _DelayedCancellation(_Cancellation):
    def __init__(self, delay: float) -> None:
        super().__init__()
        self.delay = delay

    async def close_active_transport(self, *, turn_id: UUID) -> None:
        await super().close_active_transport(turn_id=turn_id)
        await asyncio.sleep(self.delay)


class _CancelledCancellation(_Cancellation):
    async def close_active_transport(self, *, turn_id: UUID) -> None:
        await super().close_active_transport(turn_id=turn_id)
        raise asyncio.CancelledError


class _SynchronousFailingCancellation:
    def __init__(self, error: BaseException) -> None:
        self.error = error
        self.calls = 0

    def close_active_transport(self, *, turn_id: UUID) -> Awaitable[None]:
        self.calls += 1
        raise self.error


class _Bridge:
    def __init__(
        self,
        *,
        mode: PttInputMode,
        rapid_submit: bool = False,
        block_pcm: bool = False,
        receipt_complete: bool = True,
        auto_ready: bool = True,
        poison_after_open: bool = False,
        eof_after_open: bool = False,
        block_session_open: bool = False,
        receipt_on_abort: bool = True,
    ) -> None:
        self.mode = mode
        self.rapid_submit = rapid_submit
        self.incoming: asyncio.Queue[bytes] = asyncio.Queue()
        self.decoder = FrameDecoder()
        self.sent: list[WireFrame] = []
        self.edge_sequence = 0
        self.closed = 0
        self.receive_limits: list[int] = []
        self.capture_started = False
        self.block_pcm = block_pcm
        self.receipt_complete = receipt_complete
        self.receipt_sent = False
        self.auto_ready = auto_ready
        self.poison_after_open = poison_after_open
        self.eof_after_open = eof_after_open
        self.block_session_open = block_session_open
        self.receipt_on_abort = receipt_on_abort
        self.pcm_send_entered = asyncio.Event()
        self.pcm_permits = asyncio.Semaphore(0)
        self.pcm_send_calls = 0
        self.session_open_sent = asyncio.Event()
        self.session_open_permit = asyncio.Event()
        self.send_priorities: list[bool] = []
        self.output_fenced = False

    def _edge_control(self, control: PttControl) -> None:
        self.incoming.put_nowait(encode_control_frame(sequence=self.edge_sequence, control=control))
        self.edge_sequence += 1

    def _edge_capture(self) -> None:
        if self.capture_started:
            return
        self.capture_started = True
        self._edge_control(PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT))

    def _edge_capture_end(self) -> None:
        self.incoming.put_nowait(
            encode_pcm_frame(
                turn_id=TURN_ID,
                sequence=self.edge_sequence,
                pcm=CAPTURE_PCM,
            )
        )
        self.edge_sequence += 1
        self._edge_control(PttControl.capture_end(TURN_ID))

    def _receipt(self) -> None:
        if self.receipt_sent:
            return
        self.receipt_sent = True
        self._edge_control(
            PttControl.safety_receipt(
                TURN_ID,
                PttSafetyReceipt(
                    turn_id=TURN_ID,
                    new_capture_rejected=True,
                    recording_stopped=True,
                    playback_stopped=True,
                    motion_stopped=True,
                    audio_reactive_disabled=True,
                    owned_buffers_cleared=self.receipt_complete,
                ),
            )
        )

    def edge_cancel(self) -> None:
        self._edge_control(PttControl.cancel(TURN_ID))
        self._receipt()

    async def receive(self, max_bytes: int) -> bytes:
        self.receive_limits.append(max_bytes)
        return await self.incoming.get()

    async def send(self, frame: bytes, *, priority: bool = False) -> PttSendCommit:
        preview = FrameDecoder().feed(frame)
        assert len(preview) == 1
        wire = preview[0]
        if self.output_fenced:
            return _uncommitted()
        if isinstance(wire, ControlFrame) and wire.control.kind is ControlKind.SESSION_OPEN:
            self.session_open_sent.set()
            if self.block_session_open:
                await self.session_open_permit.wait()
        if isinstance(wire, PcmFrame) and self.block_pcm:
            self.pcm_send_calls += 1
            self.pcm_send_entered.set()
            await self.pcm_permits.acquire()
        if self.output_fenced:
            return _uncommitted()
        decoded = self.decoder.feed(frame)
        assert len(decoded) == 1
        wire = decoded[0]
        self.sent.append(wire)
        self.send_priorities.append(priority)
        if not isinstance(wire, ControlFrame):
            return _committed()
        kind = wire.control.kind
        if kind is ControlKind.SESSION_OPEN:
            if self.poison_after_open:
                self.incoming.put_nowait(b"X" * 32)
                return _committed()
            if self.eof_after_open:
                self.incoming.put_nowait(b"")
                return _committed()
            if not self.auto_ready:
                return _committed()
            self._edge_control(PttControl.session_ready(TURN_ID, self.mode))
            if self.mode is PttInputMode.REACHY_LOCAL:
                self._edge_capture()
                self._edge_capture_end()
        elif kind is ControlKind.PTT_START and not self.rapid_submit:
            self._edge_capture()
        elif kind is ControlKind.PTT_SUBMIT:
            self._edge_capture()
            self._edge_capture_end()
        elif kind is ControlKind.PLAYBACK_END or (
            kind is ControlKind.ABORT and self.receipt_on_abort
        ):
            self._receipt()
        return _committed()

    def close(self) -> Awaitable[None]:
        self.output_fenced = True

        async def finish_close() -> None:
            self.closed += 1
            self.incoming.put_nowait(b"")

        return finish_close()


class _CancelledReceiveBridge(_Bridge):
    _SENTINEL = b"cancelled-receive"

    async def receive(self, max_bytes: int) -> bytes:
        self.receive_limits.append(max_bytes)
        chunk = await self.incoming.get()
        if chunk == self._SENTINEL:
            raise asyncio.CancelledError
        return chunk

    def cancel_receive(self) -> None:
        self.incoming.put_nowait(self._SENTINEL)


class _CancelledPcmSendBridge(_Bridge):
    async def send(self, frame: bytes, *, priority: bool = False) -> PttSendCommit:
        decoded = FrameDecoder().feed(frame)
        if decoded and isinstance(decoded[0], PcmFrame):
            raise asyncio.CancelledError
        return await super().send(frame, priority=priority)


class _SynchronousCancelledCloseBridge(_CancelledReceiveBridge):
    def close(self) -> Awaitable[None]:
        self.output_fenced = True
        raise asyncio.CancelledError


class _SynchronousFatalCloseBridge(_Bridge):
    def __init__(self, fatal: BaseException) -> None:
        super().__init__(mode=PttInputMode.REACHY_LOCAL)
        self.fatal = fatal

    def close(self) -> Awaitable[None]:
        self.output_fenced = True
        raise self.fatal


class _AsynchronousFailingCloseBridge(_Bridge):
    def close(self) -> Awaitable[None]:
        self.output_fenced = True

        async def finish_close() -> None:
            private_close_state = bytearray(b"private-close-state")
            if private_close_state:
                raise RuntimeError("private-bridge-close-failure")

        return finish_close()


class _DelayedCloseBridge(_Bridge):
    def __init__(self, *, mode: PttInputMode, delay: float) -> None:
        super().__init__(mode=mode)
        self.delay = delay
        self.close_started_at: float | None = None
        self.close_finished_at: float | None = None

    def close(self) -> Awaitable[None]:
        self.output_fenced = True
        self.close_started_at = asyncio.get_running_loop().time()

        async def finish_close() -> None:
            await asyncio.sleep(self.delay)
            self.closed += 1
            self.close_finished_at = asyncio.get_running_loop().time()
            self.incoming.put_nowait(b"")

        return finish_close()


class _HangingCloseBridge(_Bridge):
    def __init__(
        self,
        *,
        mode: PttInputMode,
        swallow_cancellation: bool = False,
        eof_after_open: bool = False,
    ) -> None:
        super().__init__(mode=mode, eof_after_open=eof_after_open)
        self.swallow_cancellation = swallow_cancellation
        self.close_entered = asyncio.Event()
        self.close_release = asyncio.Event()
        self.close_finalized = asyncio.Event()
        self.close_cancellations = 0

    def close(self) -> Awaitable[None]:
        self.output_fenced = True

        async def finish_close() -> None:
            self.closed += 1
            self.close_entered.set()
            try:
                while not self.close_release.is_set():
                    try:
                        await self.close_release.wait()
                    except asyncio.CancelledError:
                        self.close_cancellations += 1
                        if not self.swallow_cancellation:
                            raise
            finally:
                self.close_finalized.set()

        return finish_close()


class _HangingCloseInput(_Input):
    def __init__(self, events: Iterable[CorePttEvent]) -> None:
        super().__init__(events)
        self.close_entered = asyncio.Event()
        self.close_release = asyncio.Event()
        self.close_finalized = asyncio.Event()
        self.close_cancellations = 0

    async def close(self) -> None:
        self.closed += 1
        self.close_entered.set()
        try:
            await self.close_release.wait()
        except asyncio.CancelledError:
            self.close_cancellations += 1
            raise
        finally:
            self.close_finalized.set()


class _SynchronousFailingCloseInput(_Input):
    def close(self) -> Awaitable[None]:
        raise RuntimeError("private-input-close-failure")


class _SynchronousFailingReceiveInput(_Input):
    def receive(self) -> Awaitable[CorePttEvent]:
        self.receive_calls += 1
        raise RuntimeError("private-input-receive-failure")


class _FatalCloseInput(_Input):
    def __init__(self, events: Iterable[CorePttEvent], fatal: BaseException) -> None:
        super().__init__(events)
        self.fatal = fatal

    async def close(self) -> None:
        self.closed += 1
        raise self.fatal


class _FatalReceiveBridge(_Bridge):
    def __init__(self, fatal: BaseException) -> None:
        super().__init__(mode=PttInputMode.REACHY_LOCAL)
        self.fatal = fatal

    async def receive(self, max_bytes: int) -> bytes:
        self.receive_limits.append(max_bytes)
        raise self.fatal


class _LateFatalReceiveBridge(_Bridge):
    def __init__(self, fatal: BaseException) -> None:
        super().__init__(mode=PttInputMode.REACHY_LOCAL)
        self.fatal = fatal
        self.receive_cancelled = asyncio.Event()
        self.receive_release = asyncio.Event()

    async def receive(self, max_bytes: int) -> bytes:
        self.receive_limits.append(max_bytes)
        try:
            return await self.incoming.get()
        except asyncio.CancelledError:
            self.receive_cancelled.set()
            await self.receive_release.wait()
            raise self.fatal from None

    def close(self) -> Awaitable[None]:
        self.output_fenced = True

        async def finish_close() -> None:
            self.closed += 1

        return finish_close()


class _CountingBlockingPipeline(_BlockingPipeline):
    def __init__(self, clock: _Clock) -> None:
        super().__init__(clock)
        self.quarantine_observations = 0

    async def observe_quarantine(self, *, deadline: float) -> bool:
        self.quarantine_observations += 1
        return True


class _TeardownProbePipeline(_Pipeline):
    def __init__(self, clock: _Clock) -> None:
        super().__init__(
            clock,
            (SpeechChunk(request_id=REQUEST_ID, sequence=0, pcm=b"", final=True),),
        )
        self.quarantine_started = asyncio.Event()

    async def observe_quarantine(self, *, deadline: float) -> bool:
        self.quarantine_started.set()
        return True


class _CancelledSecondInput(_Input):
    def __init__(self) -> None:
        super().__init__(())

    async def receive(self) -> CorePttEvent:
        self.receive_calls += 1
        if self.receive_calls == 1:
            return CorePttEvent.START
        raise asyncio.CancelledError


class _CancellationSuppressingInput(_Input):
    def __init__(self) -> None:
        super().__init__((CorePttEvent.START,))
        self.blocked = asyncio.Event()
        self.cancelled = asyncio.Event()
        self.release = asyncio.Event()

    async def receive(self) -> CorePttEvent:
        self.receive_calls += 1
        if self.receive_calls == 1:
            return await self._events.get()
        self.blocked.set()
        while not self.release.is_set():
            try:
                await self.release.wait()
            except asyncio.CancelledError:
                self.cancelled.set()
        return CorePttEvent.SUBMIT


class _CancellationSuppressingReceiveBridge(_Bridge):
    def __init__(self) -> None:
        super().__init__(mode=PttInputMode.CORE_TERMINAL_TOGGLE, rapid_submit=True)
        self.receive_cancelled = asyncio.Event()
        self.receive_release = asyncio.Event()
        self.close_started = asyncio.Event()

    async def receive(self, max_bytes: int) -> bytes:
        self.receive_limits.append(max_bytes)
        try:
            return await self.incoming.get()
        except asyncio.CancelledError:
            self.receive_cancelled.set()
            await self.receive_release.wait()
            return b""

    def close(self) -> Awaitable[None]:
        self.output_fenced = True

        async def finish_close() -> None:
            self.closed += 1
            self.close_started.set()

        return finish_close()


class _SynchronousFailingPipeline(_Pipeline):
    def __init__(self, clock: _Clock) -> None:
        super().__init__(clock)
        self.captured: CapturedTurn | None = None

    def run(self, captured: CapturedTurn) -> AsyncIterator[SpeechChunk]:
        self.calls += 1
        self.captured = captured
        raise RuntimeError("private-synchronous-pipeline-failure")


class _GroupedFailurePipeline(_Pipeline):
    async def run(self, captured: CapturedTurn) -> AsyncIterator[SpeechChunk]:
        self.calls += 1
        pcm = captured.claim_pcm()
        self.captures.append(bytes(pcm))
        try:
            raise BaseExceptionGroup(
                "private-provider-group",
                [
                    asyncio.CancelledError("private-provider-cancellation"),
                    RuntimeError("private-provider-error"),
                ],
            )
            yield SpeechChunk(request_id=REQUEST_ID, sequence=0, pcm=b"", final=True)
        finally:
            pcm[:] = b"\x00" * len(pcm)
            pcm.clear()
            captured.clear()
            self.finalized += 1


class _GroupedCleanupIncompletePipeline(_Pipeline):
    async def run(self, captured: CapturedTurn) -> AsyncIterator[SpeechChunk]:
        self.calls += 1
        pcm = captured.claim_pcm()
        self.captures.append(bytes(pcm))
        try:
            raise BaseExceptionGroup(
                "private-provider-group",
                [
                    RuntimeError("private-provider-error"),
                    ExceptionGroup(
                        "private-cleanup-group",
                        [deadline_module.DeadlineCleanupIncomplete()],
                    ),
                ],
            )
            yield SpeechChunk(request_id=REQUEST_ID, sequence=0, pcm=b"", final=True)
        finally:
            pcm[:] = b"\x00" * len(pcm)
            pcm.clear()
            captured.clear()
            self.finalized += 1


class _IncompleteQuarantinePipeline(_Pipeline):
    def __init__(self, clock: _Clock) -> None:
        super().__init__(
            clock,
            (SpeechChunk(request_id=REQUEST_ID, sequence=0, pcm=b"", final=True),),
        )
        self.quarantine_observations = 0

    async def observe_quarantine(self, *, deadline: float) -> bool:
        self.quarantine_observations += 1
        return False


class _CleanupIncompleteCloseGroupPipeline(_Pipeline):
    def run(self, captured: CapturedTurn) -> AsyncIterator[SpeechChunk]:
        self.calls += 1
        pcm = captured.claim_pcm()
        self.captures.append(bytes(pcm))
        pcm[:] = b"\x00" * len(pcm)
        pcm.clear()
        captured.clear()
        pipeline = self

        class _Stream:
            def __aiter__(self) -> _Stream:
                return self

            async def __anext__(self) -> SpeechChunk:
                raise deadline_module.DeadlineCleanupIncomplete

            async def aclose(self) -> None:
                pipeline.finalized += 1
                raise BaseExceptionGroup(
                    "private-close-group",
                    [
                        asyncio.CancelledError("private-close-cancellation"),
                        RuntimeError("private-close-error"),
                    ],
                )

        return _Stream()


class _SameTickCommittedPcmPoisonBridge(_Bridge):
    async def send(self, frame: bytes, *, priority: bool = False) -> PttSendCommit:
        result = await super().send(frame, priority=priority)
        decoded = FrameDecoder().feed(frame)
        if decoded and isinstance(decoded[0], PcmFrame):
            self.incoming.put_nowait(b"X" * 32)
            await asyncio.sleep(0)
        return result


class _HeartbeatDuringFinalAckBridge(_Bridge):
    supervisor: CorePttSessionSupervisor | None = None

    async def send(self, frame: bytes, *, priority: bool = False) -> PttSendCommit:
        candidate = FrameDecoder().feed(frame)
        result = await super().send(frame, priority=priority)
        if (
            candidate
            and isinstance(candidate[0], ControlFrame)
            and candidate[0].control.kind is ControlKind.SAFETY_ACK
        ):
            assert self.supervisor is not None
            await self.supervisor._lane.heartbeat_due()  # noqa: SLF001
        return result


class _EdgeCancelBeforeAckCommitBridge(_Bridge):
    def __init__(self, *, clock: _Clock, mode: PttInputMode) -> None:
        super().__init__(mode=mode)
        self._clock = clock

    async def send(self, frame: bytes, *, priority: bool = False) -> PttSendCommit:
        candidate = FrameDecoder().feed(frame)
        if (
            candidate
            and isinstance(candidate[0], ControlFrame)
            and candidate[0].control.kind is ControlKind.SAFETY_ACK
        ):
            self._clock.current += 1.0
            self._edge_control(PttControl.cancel(TURN_ID))
            for _ in range(5):
                await asyncio.sleep(0)
        return await super().send(frame, priority=priority)


class _LateCapturePcmBeforeAckCommitBridge(_Bridge):
    supervisor: CorePttSessionSupervisor | None = None

    def __init__(self) -> None:
        super().__init__(mode=PttInputMode.CORE_TERMINAL_TOGGLE)
        self.pending_pcm_observed = False

    async def send(self, frame: bytes, *, priority: bool = False) -> PttSendCommit:
        candidate = FrameDecoder().feed(frame)
        control_kind = (
            candidate[0].control.kind
            if candidate and isinstance(candidate[0], ControlFrame)
            else None
        )
        if control_kind is ControlKind.SAFETY_ACK:
            self.incoming.put_nowait(
                encode_pcm_frame(
                    turn_id=TURN_ID,
                    sequence=self.edge_sequence,
                    pcm=CAPTURE_PCM,
                )
            )
            self.edge_sequence += 1
            assert self.supervisor is not None
            for _ in range(100):
                transaction = self.supervisor._guard_transaction  # noqa: SLF001
                if transaction is not None and any(
                    isinstance(incoming, PcmFrame) for incoming, _ in transaction.inbound
                ):
                    self.pending_pcm_observed = True
                    break
                await asyncio.sleep(0)
        result = await super().send(frame, priority=priority)
        if control_kind is ControlKind.PTT_START:
            self._edge_control(PttControl.cancel(TURN_ID))
            self._receipt()
        return result


class _UncommittedFinalAckWithInboundBridge(_Bridge):
    def __init__(self) -> None:
        super().__init__(mode=PttInputMode.REACHY_LOCAL)
        self.attempted_ack: ControlFrame | None = None

    async def send(self, frame: bytes, *, priority: bool = False) -> PttSendCommit:
        candidate = FrameDecoder().feed(frame)
        if (
            candidate
            and isinstance(candidate[0], ControlFrame)
            and candidate[0].control.kind is ControlKind.SAFETY_ACK
        ):
            self.attempted_ack = candidate[0]
            self._edge_control(PttControl.cancel(TURN_ID))
            self.incoming.put_nowait(b"")
            await asyncio.Event().wait()
        return await super().send(frame, priority=priority)


class _PostCommitCancelBridge(_Bridge):
    async def send(self, frame: bytes, *, priority: bool = False) -> PttSendCommit:
        candidate = FrameDecoder().feed(frame)
        result = await super().send(frame, priority=priority)
        if (
            candidate
            and isinstance(candidate[0], ControlFrame)
            and candidate[0].control.kind is ControlKind.SAFETY_ACK
        ):
            asyncio.get_running_loop().call_soon(
                self._edge_control,
                PttControl.cancel(TURN_ID),
            )
        return result


class _TerminalCancelDuringFinalAckBridge(_Bridge):
    def __init__(self, input_port: _Input) -> None:
        super().__init__(mode=PttInputMode.CORE_TERMINAL_TOGGLE, rapid_submit=True)
        self._input_port = input_port

    async def send(self, frame: bytes, *, priority: bool = False) -> PttSendCommit:
        candidate = FrameDecoder().feed(frame)
        result = await super().send(frame, priority=priority)
        if (
            candidate
            and isinstance(candidate[0], ControlFrame)
            and candidate[0].control.kind is ControlKind.SAFETY_ACK
        ):
            self._input_port.put(CorePttEvent.CANCEL)
            await asyncio.sleep(0)
        return result


class _EofAfterFinalAckCommitBridge(_Bridge):
    async def send(self, frame: bytes, *, priority: bool = False) -> PttSendCommit:
        candidate = FrameDecoder().feed(frame)
        result = await super().send(frame, priority=priority)
        if (
            candidate
            and isinstance(candidate[0], ControlFrame)
            and candidate[0].control.kind is ControlKind.SAFETY_ACK
        ):
            self.incoming.put_nowait(b"")
        return result


class _CancellationSuppressingSendCloseBridge(_Bridge):
    def __init__(self) -> None:
        super().__init__(mode=PttInputMode.REACHY_LOCAL)
        self.send_entered = asyncio.Event()
        self.send_cancelled = asyncio.Event()
        self.send_release = asyncio.Event()
        self.close_entered = asyncio.Event()
        self.close_cancelled = asyncio.Event()
        self.close_release = asyncio.Event()

    async def send(self, frame: bytes, *, priority: bool = False) -> PttSendCommit:
        decoded = FrameDecoder().feed(frame)
        if decoded and isinstance(decoded[0], PcmFrame):
            self.send_entered.set()
            while not self.send_release.is_set():
                try:
                    await self.send_release.wait()
                except asyncio.CancelledError:
                    self.send_cancelled.set()
            if self.output_fenced:
                return _uncommitted()
        return await super().send(frame, priority=priority)

    def close(self) -> Awaitable[None]:
        self.output_fenced = True

        async def finish_close() -> None:
            self.closed += 1
            self.close_entered.set()
            while not self.close_release.is_set():
                try:
                    await self.close_release.wait()
                except asyncio.CancelledError:
                    self.close_cancelled.set()

        return finish_close()


class _JumpClock(_Clock):
    def __init__(self) -> None:
        super().__init__()
        self.calls: list[float] = []
        self.jump = asyncio.Event()

    async def sleep_until(self, deadline: float) -> None:
        self.calls.append(deadline)
        if deadline == 1.0:
            await self.jump.wait()
            self.current = 10.0
            return
        if deadline <= self.current:
            return
        await asyncio.Event().wait()


class _CancelledHeartbeatClock(_Clock):
    def __init__(self) -> None:
        super().__init__()
        self.heartbeat_cancelled = asyncio.Event()

    async def sleep_until(self, deadline: float) -> None:
        if deadline == 1.0:
            self.heartbeat_cancelled.set()
            raise asyncio.CancelledError
        await super().sleep_until(deadline)


class _FailingNowClock(_Clock):
    def now(self) -> float:
        raise RuntimeError("private-clock-failure")


class _ConcurrentCleanupBridge(_Bridge):
    def __init__(self, gate: asyncio.Event) -> None:
        super().__init__(mode=PttInputMode.REACHY_LOCAL)
        self.gate = gate
        self.abort_entered = asyncio.Event()
        self.abort_started_at: float | None = None
        self.abort_saw_provider_close = False

    async def send(self, frame: bytes, *, priority: bool = False) -> PttSendCommit:
        decoded = FrameDecoder().feed(frame)
        if (
            decoded
            and isinstance(decoded[0], ControlFrame)
            and decoded[0].control.kind is ControlKind.ABORT
        ):
            self.abort_started_at = asyncio.get_running_loop().time()
            self.abort_saw_provider_close = any(
                task.get_name() == "core-ptt-provider-close" for task in asyncio.all_tasks()
            )
            self.abort_entered.set()
            await self.gate.wait()
        return await super().send(frame, priority=priority)


class _ConcurrentCleanupCancellation(_Cancellation):
    def __init__(self, gate: asyncio.Event) -> None:
        super().__init__()
        self.gate = gate
        self.close_entered = asyncio.Event()
        self.close_started_at: float | None = None
        self.close_saw_abort = False

    async def close_active_transport(self, *, turn_id: UUID) -> None:
        await super().close_active_transport(turn_id=turn_id)
        self.close_started_at = asyncio.get_running_loop().time()
        self.close_saw_abort = any(
            task.get_name() == "core-ptt-abort-send" for task in asyncio.all_tasks()
        )
        self.close_entered.set()
        await self.gate.wait()


class _FailingStartBridge(_Bridge):
    async def send(self, frame: bytes, *, priority: bool = False) -> PttSendCommit:
        decoded = FrameDecoder().feed(frame)
        if (
            decoded
            and isinstance(decoded[0], ControlFrame)
            and decoded[0].control.kind is ControlKind.PTT_START
        ):
            raise RuntimeError("private-bridge-failure")
        return await super().send(frame, priority=priority)


def _supervisor(
    *,
    mode: PttInputMode,
    clock: _Clock,
    bridge: _Bridge,
    pipeline: _Pipeline,
    input_port: _Input | None,
    cancellation: _Cancellation | None = None,
) -> CorePttSessionSupervisor:
    return CorePttSessionSupervisor(
        input_mode=mode,
        input_port=input_port,
        bridge=bridge,
        pipeline=pipeline,
        provider_cancellation=cancellation if cancellation is not None else _Cancellation(),
        clock=clock,
    )


async def _bounded_outcome(
    run: asyncio.Task[PttSessionOutcome],
    *,
    timeout: float = 0.5,
) -> PttSessionOutcome:
    done, _ = await asyncio.wait({run}, timeout=timeout)
    if run not in done:
        run.cancel()
        await asyncio.gather(run, return_exceptions=True)
        raise AssertionError("supervisor-did-not-finish")
    try:
        return run.result()
    except asyncio.CancelledError:
        raise AssertionError("adapter-cancellation-escaped") from None


async def _wait_for_full_normal_lane(supervisor: CorePttSessionSupervisor) -> None:
    async def wait_until_full() -> None:
        while len(supervisor._lane._normal) != 64:  # noqa: SLF001 - bounded-lane probe
            await asyncio.sleep(0)

    await asyncio.wait_for(wait_until_full(), timeout=5)


async def _wait_for_control_kind(bridge: _Bridge, kind: ControlKind) -> None:
    async def wait_until_sent() -> None:
        while not any(
            isinstance(frame, ControlFrame) and frame.control.kind is kind for frame in bridge.sent
        ):
            await asyncio.sleep(0)

    await asyncio.wait_for(wait_until_sent(), timeout=1)


@pytest.mark.parametrize(
    "mode,input_port",
    [
        (PttInputMode.CORE_TERMINAL_TOGGLE, None),
        (PttInputMode.REACHY_LOCAL, _Input(())),
    ],
)
def test_supervisor_rejects_ambiguous_input_ownership(
    mode: PttInputMode,
    input_port: _Input | None,
) -> None:
    clock = _Clock()
    bridge = _Bridge(mode=mode)

    with pytest.raises(ValueError, match="^invalid-core-ptt-supervisor$"):
        _supervisor(
            mode=mode,
            clock=clock,
            bridge=bridge,
            pipeline=_Pipeline(clock),
            input_port=input_port,
        )


def test_supervisor_requires_the_pipeline_and_supervisor_to_share_one_clock() -> None:
    clock = _Clock()

    with pytest.raises(ValueError, match="^invalid-core-ptt-supervisor$"):
        _supervisor(
            mode=PttInputMode.REACHY_LOCAL,
            clock=clock,
            bridge=_Bridge(mode=PttInputMode.REACHY_LOCAL),
            pipeline=_Pipeline(_Clock()),
            input_port=None,
        )


@pytest.mark.asyncio
async def test_capture_deadline_is_anchored_to_an_exact_zero_start_timestamp() -> None:
    clock = _Clock()
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=_Pipeline(clock),
        input_port=None,
    )
    supervisor._interrupt = asyncio.Event()  # noqa: SLF001 - deadline anchor probe
    supervisor._signal = supervisor_module._Signal.NONE  # noqa: SLF001 - deadline anchor probe
    supervisor._capture_started = asyncio.Event()  # noqa: SLF001 - deadline anchor probe
    supervisor._capture_ended = asyncio.Event()  # noqa: SLF001 - deadline anchor probe
    supervisor._capture_started_at = 0.0  # noqa: SLF001 - exact monotonic origin
    supervisor._capture_started.set()  # noqa: SLF001 - deadline anchor probe
    clock.current = 10.0
    capture = asyncio.create_task(supervisor._local_capture(1_000.0))  # noqa: SLF001
    try:

        async def wait_for_capture_deadline() -> None:
            while not any(deadline == 90.0 for deadline, _ in clock.sleepers):
                await asyncio.sleep(0)

        await asyncio.wait_for(wait_for_capture_deadline(), timeout=1)

        assert any(deadline == 90.0 for deadline, _ in clock.sleepers)
    finally:
        capture.cancel()
        await asyncio.gather(capture, return_exceptions=True)


@pytest.mark.asyncio
async def test_terminal_toggle_happy_path_is_one_shot_and_sole_writer_sequences_frames() -> None:
    clock = _Clock()
    bridge = _Bridge(mode=PttInputMode.CORE_TERMINAL_TOGGLE, rapid_submit=True)
    input_port = _Input((CorePttEvent.START, CorePttEvent.SUBMIT))
    pipeline = _Pipeline(clock)
    supervisor = _supervisor(
        mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        clock=clock,
        bridge=bridge,
        pipeline=pipeline,
        input_port=input_port,
    )

    outcome = await asyncio.wait_for(supervisor.run(TURN_ID), timeout=1)

    assert outcome is PttSessionOutcome.COMPLETED
    assert pipeline.captures == [CAPTURE_PCM]
    assert pipeline.finalized == 1
    assert input_port.closed == 1
    assert bridge.closed == 1
    assert bridge.receive_limits and set(bridge.receive_limits) == {MAX_FEED_BYTES}
    assert [frame.sequence for frame in bridge.sent] == list(range(len(bridge.sent)))
    assert [frame.control.kind for frame in bridge.sent if isinstance(frame, ControlFrame)] == [
        ControlKind.SESSION_OPEN,
        ControlKind.PTT_START,
        ControlKind.PTT_SUBMIT,
        ControlKind.PLAYBACK_START,
        ControlKind.PLAYBACK_END,
        ControlKind.SAFETY_ACK,
    ]
    assert [frame.pcm for frame in bridge.sent if isinstance(frame, PcmFrame)] == [PLAYBACK_PCM]

    with pytest.raises(RuntimeError, match="^core-ptt-session-already-run$"):
        await supervisor.run(TURN_ID)
    assert len(bridge.sent) == 7


@pytest.mark.asyncio
async def test_reachy_local_happy_path_never_emits_core_ptt_controls() -> None:
    clock = _Clock()
    bridge = _Bridge(mode=PttInputMode.REACHY_LOCAL)
    pipeline = _Pipeline(clock)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=pipeline,
        input_port=None,
    )

    outcome = await asyncio.wait_for(supervisor.run(TURN_ID), timeout=1)

    assert outcome is PttSessionOutcome.COMPLETED
    assert pipeline.captures == [CAPTURE_PCM]
    kinds = [frame.control.kind for frame in bridge.sent if isinstance(frame, ControlFrame)]
    assert ControlKind.PTT_START not in kinds
    assert ControlKind.PTT_SUBMIT not in kinds
    assert kinds == [
        ControlKind.SESSION_OPEN,
        ControlKind.PLAYBACK_START,
        ControlKind.PLAYBACK_END,
        ControlKind.SAFETY_ACK,
    ]


@pytest.mark.asyncio
async def test_final_ack_drops_a_coalesced_heartbeat_without_downgrading_success() -> None:
    clock = _Clock()
    bridge = _HeartbeatDuringFinalAckBridge(mode=PttInputMode.REACHY_LOCAL)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock),
        input_port=None,
    )
    bridge.supervisor = supervisor

    outcome = await asyncio.wait_for(supervisor.run(TURN_ID), timeout=1)

    assert outcome is PttSessionOutcome.COMPLETED
    kinds = [frame.control.kind for frame in bridge.sent if isinstance(frame, ControlFrame)]
    assert kinds[-1] is ControlKind.SAFETY_ACK
    assert kinds.count(ControlKind.SAFETY_ACK) == 1
    assert ControlKind.ABORT not in kinds
    assert ControlKind.HEARTBEAT not in kinds


@pytest.mark.asyncio
async def test_late_capture_pcm_before_final_ack_commit_is_discarded_without_poison() -> None:
    clock = _Clock()
    bridge = _LateCapturePcmBeforeAckCommitBridge()
    supervisor = _supervisor(
        mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock),
        input_port=_Input((CorePttEvent.START,)),
    )
    bridge.supervisor = supervisor

    outcome = await asyncio.wait_for(supervisor.run(TURN_ID), timeout=1)

    assert outcome is PttSessionOutcome.CANCELLED
    assert bridge.pending_pcm_observed is True
    assert supervisor._signal is not supervisor_module._Signal.PROTOCOL_POISONED  # noqa: SLF001
    kinds = [frame.control.kind for frame in bridge.sent if isinstance(frame, ControlFrame)]
    assert kinds[-1] is ControlKind.SAFETY_ACK
    assert kinds.count(ControlKind.SAFETY_ACK) == 1


@pytest.mark.asyncio
async def test_latched_uncommitted_final_ack_restores_pre_ack_inbound_guard() -> None:
    clock = _Clock()
    bridge = _UncommittedFinalAckWithInboundBridge()
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock),
        input_port=None,
    )

    outcome = await asyncio.wait_for(supervisor.run(TURN_ID), timeout=1)

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert bridge.attempted_ack is not None
    assert supervisor._final_ack_committed.is_set() is False  # noqa: SLF001
    assert supervisor._guard.state == "receipt_received"  # noqa: SLF001
    accepted = supervisor._guard.accept(  # noqa: SLF001 - prove rollback/replay state
        StreamDirection.CORE_TO_EDGE,
        bridge.attempted_ack,
        now=clock.current,
    )
    assert accepted.disposition is GuardDisposition.ACCEPTED
    assert supervisor._guard.finish() is PttSessionOutcome.CANCELLED  # noqa: SLF001


@pytest.mark.asyncio
async def test_edge_cancel_after_final_ack_commit_is_protocol_poison() -> None:
    clock = _Clock()
    bridge = _PostCommitCancelBridge(mode=PttInputMode.REACHY_LOCAL)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock),
        input_port=None,
    )

    outcome = await asyncio.wait_for(supervisor.run(TURN_ID), timeout=1)

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert supervisor._final_ack_committed.is_set() is True  # noqa: SLF001
    assert supervisor._signal is supervisor_module._Signal.PROTOCOL_POISONED  # noqa: SLF001
    kinds = [frame.control.kind for frame in bridge.sent if isinstance(frame, ControlFrame)]
    assert kinds[-1] is ControlKind.SAFETY_ACK
    assert kinds.count(ControlKind.SAFETY_ACK) == 1


@pytest.mark.asyncio
async def test_edge_cancel_before_final_ack_commit_is_accepted_in_receipt_phase() -> None:
    clock = _Clock()
    bridge = _EdgeCancelBeforeAckCommitBridge(
        clock=clock,
        mode=PttInputMode.REACHY_LOCAL,
    )
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock),
        input_port=None,
    )

    outcome = await asyncio.wait_for(supervisor.run(TURN_ID), timeout=1)

    assert outcome is PttSessionOutcome.CANCELLED
    assert supervisor._signal is not supervisor_module._Signal.PROTOCOL_POISONED  # noqa: SLF001
    kinds = [frame.control.kind for frame in bridge.sent if isinstance(frame, ControlFrame)]
    assert kinds[-1] is ControlKind.SAFETY_ACK
    assert kinds.count(ControlKind.SAFETY_ACK) == 1
    assert ControlKind.ABORT not in kinds


@pytest.mark.asyncio
async def test_terminal_cancel_observed_during_final_ack_cannot_enqueue_post_ack_abort() -> None:
    clock = _Clock()
    input_port = _Input((CorePttEvent.START, CorePttEvent.SUBMIT))
    bridge = _TerminalCancelDuringFinalAckBridge(input_port)
    supervisor = _supervisor(
        mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock),
        input_port=input_port,
    )

    outcome = await asyncio.wait_for(supervisor.run(TURN_ID), timeout=1)

    assert outcome is PttSessionOutcome.COMPLETED
    kinds = [frame.control.kind for frame in bridge.sent if isinstance(frame, ControlFrame)]
    assert kinds[-1] is ControlKind.SAFETY_ACK
    assert kinds.count(ControlKind.SAFETY_ACK) == 1
    assert ControlKind.ABORT not in kinds


@pytest.mark.asyncio
async def test_clean_eof_after_final_ack_commit_is_expected_session_close() -> None:
    clock = _Clock()
    bridge = _EofAfterFinalAckCommitBridge(mode=PttInputMode.REACHY_LOCAL)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock),
        input_port=None,
    )

    outcome = await asyncio.wait_for(supervisor.run(TURN_ID), timeout=1)

    assert outcome is PttSessionOutcome.COMPLETED
    kinds = [frame.control.kind for frame in bridge.sent if isinstance(frame, ControlFrame)]
    assert kinds[-1] is ControlKind.SAFETY_ACK
    assert kinds.count(ControlKind.SAFETY_ACK) == 1


@pytest.mark.asyncio
async def test_supervisor_rejects_scalar_spoofed_provider_chunks_before_playback() -> None:
    clock = _Clock()
    bridge = _Bridge(mode=PttInputMode.REACHY_LOCAL)
    spoofed = SpeechChunk.model_construct(
        request_id=REQUEST_ID,
        sequence=0.0,
        pcm=PLAYBACK_PCM,
        final=False,
    )
    pipeline = _Pipeline(
        clock,
        (
            spoofed,
            SpeechChunk(request_id=REQUEST_ID, sequence=1, pcm=b"", final=True),
        ),
    )
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=pipeline,
        input_port=None,
    )

    outcome = await asyncio.wait_for(supervisor.run(TURN_ID), timeout=1)

    assert outcome is PttSessionOutcome.PROVIDER_FAILED
    kinds = [frame.control.kind for frame in bridge.sent if isinstance(frame, ControlFrame)]
    assert ControlKind.PLAYBACK_START not in kinds
    assert ControlKind.ABORT in kinds


@pytest.mark.asyncio
async def test_mixed_provider_base_exception_group_runs_receipted_content_free_cleanup() -> None:
    clock = _Clock()
    bridge = _Bridge(mode=PttInputMode.REACHY_LOCAL)
    cancellation = _Cancellation()
    pipeline = _GroupedFailurePipeline(clock)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=pipeline,
        input_port=None,
        cancellation=cancellation,
    )

    outcome = await _bounded_outcome(asyncio.create_task(supervisor.run(TURN_ID)))

    assert outcome is PttSessionOutcome.PROVIDER_FAILED
    kinds = [frame.control.kind for frame in bridge.sent if isinstance(frame, ControlFrame)]
    assert ControlKind.ABORT in kinds
    assert ControlKind.SAFETY_ACK in kinds
    assert cancellation.calls == 1
    assert pipeline.finalized == 1


@pytest.mark.asyncio
async def test_grouped_cleanup_incomplete_runs_receipted_fail_closed_cleanup() -> None:
    clock = _Clock()
    bridge = _Bridge(mode=PttInputMode.REACHY_LOCAL)
    cancellation = _Cancellation()
    pipeline = _GroupedCleanupIncompletePipeline(clock)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=pipeline,
        input_port=None,
        cancellation=cancellation,
    )

    outcome = await _bounded_outcome(asyncio.create_task(supervisor.run(TURN_ID)))

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    kinds = [frame.control.kind for frame in bridge.sent if isinstance(frame, ControlFrame)]
    assert ControlKind.ABORT in kinds
    assert ControlKind.SAFETY_ACK in kinds
    assert cancellation.calls == 1
    assert pipeline.finalized == 1


@pytest.mark.asyncio
async def test_pipeline_quarantine_incompleteness_overrides_ordinary_provider_failure() -> None:
    clock = _Clock()
    pipeline = _IncompleteQuarantinePipeline(clock)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=pipeline,
        input_port=None,
    )

    outcome = await _bounded_outcome(asyncio.create_task(supervisor.run(TURN_ID)))

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert pipeline.quarantine_observations == 1


@pytest.mark.asyncio
async def test_pipeline_cleanup_incompleteness_survives_grouped_iterator_close_failure() -> None:
    clock = _Clock()
    pipeline = _CleanupIncompleteCloseGroupPipeline(clock)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=pipeline,
        input_port=None,
    )

    outcome = await _bounded_outcome(asyncio.create_task(supervisor.run(TURN_ID)))

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert pipeline.finalized == 1


@pytest.mark.asyncio
async def test_bounded_observer_contains_group_raised_while_cancelling_late_task() -> None:
    clock = _Clock()
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=_Pipeline(clock),
        input_port=None,
    )
    entered = asyncio.Event()

    async def grouped_after_cancellation() -> None:
        entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            raise BaseExceptionGroup(
                "private-cleanup-group",
                [
                    asyncio.CancelledError("private-cleanup-cancellation"),
                    RuntimeError("private-cleanup-error"),
                ],
            ) from None

    task = asyncio.create_task(grouped_after_cancellation())
    await entered.wait()

    observed = await supervisor._observe_task_until(  # noqa: SLF001
        task,
        deadline=asyncio.get_running_loop().time(),
        cancelled_ok=False,
    )

    assert not observed


@pytest.mark.asyncio
async def test_playback_normal_lane_blocks_at_64_without_dropping_or_reordering() -> None:
    clock = _Clock()
    bridge = _Bridge(mode=PttInputMode.REACHY_LOCAL, block_pcm=True)
    chunks = tuple(
        SpeechChunk(
            request_id=REQUEST_ID,
            sequence=sequence,
            pcm=bytes((sequence % 251, 0)) * 3_200,
            final=False,
        )
        for sequence in range(66)
    ) + (SpeechChunk(request_id=REQUEST_ID, sequence=66, pcm=b"", final=True),)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock, chunks),
        input_port=None,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await bridge.pcm_send_entered.wait()

    await _wait_for_full_normal_lane(supervisor)

    assert len(supervisor._lane._normal) == 64  # noqa: SLF001 - bounded-lane contract
    assert not run.done()

    for _ in range(49):
        bridge.pcm_permits.release()

    async def wait_for_fifty_sends() -> None:
        while bridge.pcm_send_calls < 50:
            await asyncio.sleep(0)

    await asyncio.wait_for(wait_for_fifty_sends(), timeout=1)
    assert bridge.pcm_send_calls == 50
    clock.current = 1.001
    for _ in range(17):
        bridge.pcm_permits.release()
    assert await asyncio.wait_for(run, timeout=1) is PttSessionOutcome.COMPLETED
    sent_pcm = [frame.pcm for frame in bridge.sent if isinstance(frame, PcmFrame)]
    assert sent_pcm == [bytes((sequence % 251, 0)) * 3_200 for sequence in range(66)]


@pytest.mark.asyncio
async def test_terminal_cancel_during_provider_preempts_work_and_clears_owned_pcm() -> None:
    clock = _Clock()
    bridge = _Bridge(mode=PttInputMode.CORE_TERMINAL_TOGGLE)
    input_port = _Input((CorePttEvent.START, CorePttEvent.SUBMIT))
    pipeline = _BlockingPipeline(clock)
    cancellation = _Cancellation()
    supervisor = _supervisor(
        mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        clock=clock,
        bridge=bridge,
        pipeline=pipeline,
        input_port=input_port,
        cancellation=cancellation,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await pipeline.entered.wait()

    input_port.put(CorePttEvent.CANCEL)

    assert await asyncio.wait_for(run, timeout=1) is PttSessionOutcome.CANCELLED
    assert pipeline.finalized == 1
    assert pipeline.owned_pcm == bytearray()
    assert cancellation.calls == 1
    assert cancellation.turn_ids == [TURN_ID]
    kinds = [frame.control.kind for frame in bridge.sent if isinstance(frame, ControlFrame)]
    assert ControlKind.ABORT in kinds
    assert ControlKind.PLAYBACK_START not in kinds
    assert supervisor._tasks == set()  # noqa: SLF001 - owned-task cleanup contract


@pytest.mark.asyncio
async def test_late_cancellation_suppressing_provider_result_is_wiped_when_it_settles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(supervisor_module, "_PROVIDER_CLOSE_SECONDS", 0.005)
    monkeypatch.setattr(supervisor_module, "_PROVIDER_JOIN_SECONDS", 0.005)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_ACK_SECONDS", 0.02)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_TOTAL_SECONDS", 0.03)
    monkeypatch.setattr(supervisor_module, "_BRIDGE_CLOSE_SECONDS", 0.03)
    clock = _Clock()
    input_port = _Input((CorePttEvent.START, CorePttEvent.SUBMIT))
    pipeline = _CancellationSuppressingResultPipeline(clock)
    supervisor = _supervisor(
        mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.CORE_TERMINAL_TOGGLE),
        pipeline=pipeline,
        input_port=input_port,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await pipeline.entered.wait()

    input_port.put(CorePttEvent.CANCEL)
    outcome = await asyncio.wait_for(run, timeout=0.2)
    provider = supervisor._provider_task  # noqa: SLF001 - late-result ownership probe
    assert provider is not None
    assert not provider.done()
    assert pipeline.cancelled.is_set()

    pipeline.release.set()
    playback = await asyncio.wait_for(provider, timeout=0.2)
    await asyncio.sleep(0)

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert playback.error is None
    assert playback.value == bytearray()
    assert supervisor._provider_task is None  # noqa: SLF001 - released ownership contract
    assert pipeline.finalized == 1


@pytest.mark.asyncio
async def test_cancel_after_partial_provider_pcm_wipes_the_aggregate_playback_buffer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_playback = b"\x7d\x00" * 1_600
    wiped_values: list[bytes] = []
    real_wipe = supervisor_module._wipe

    def recording_wipe(buffer: bytearray) -> None:
        wiped_values.append(bytes(buffer))
        real_wipe(buffer)

    monkeypatch.setattr(supervisor_module, "_wipe", recording_wipe)
    clock = _Clock()
    bridge = _Bridge(mode=PttInputMode.CORE_TERMINAL_TOGGLE)
    input_port = _Input((CorePttEvent.START, CorePttEvent.SUBMIT))
    pipeline = _PartialPlaybackPipeline(clock, private_playback)
    supervisor = _supervisor(
        mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        clock=clock,
        bridge=bridge,
        pipeline=pipeline,
        input_port=input_port,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await pipeline.blocked_after_chunk.wait()

    input_port.put(CorePttEvent.CANCEL)

    assert await asyncio.wait_for(run, timeout=1) is PttSessionOutcome.CANCELLED
    assert private_playback in wiped_values
    assert pipeline.finalized == 1
    assert supervisor._tasks == set()  # noqa: SLF001 - owned-task cleanup contract


@pytest.mark.asyncio
async def test_external_cancellation_finishes_bounded_cleanup_then_reraises() -> None:
    clock = _Clock()
    bridge = _Bridge(mode=PttInputMode.REACHY_LOCAL)
    pipeline = _BlockingPipeline(clock)
    cancellation = _Cancellation()
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=pipeline,
        input_port=None,
        cancellation=cancellation,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await pipeline.entered.wait()

    run.cancel()

    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(run, timeout=1)
    assert pipeline.finalized == 1
    assert pipeline.owned_pcm == bytearray()
    assert cancellation.calls == 1
    kinds = [frame.control.kind for frame in bridge.sent if isinstance(frame, ControlFrame)]
    assert ControlKind.ABORT in kinds
    assert ControlKind.SAFETY_ACK in kinds
    assert supervisor._tasks == set()  # noqa: SLF001 - owned-task cleanup contract


@pytest.mark.asyncio
async def test_synchronous_input_close_factory_failure_is_content_free_cleanup_incomplete() -> None:
    clock = _Clock()
    input_port = _SynchronousFailingCloseInput(
        (CorePttEvent.START, CorePttEvent.SUBMIT),
    )
    supervisor = _supervisor(
        mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.CORE_TERMINAL_TOGGLE),
        pipeline=_Pipeline(clock),
        input_port=input_port,
    )

    outcome = await supervisor.run(TURN_ID)

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert supervisor._tasks == set()  # noqa: SLF001 - failed factory owns no task


@pytest.mark.asyncio
async def test_synchronous_input_receive_factory_failure_leaves_no_capture_wait_task() -> None:
    clock = _Clock()
    input_port = _SynchronousFailingReceiveInput(())
    supervisor = _supervisor(
        mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.CORE_TERMINAL_TOGGLE),
        pipeline=_Pipeline(clock),
        input_port=input_port,
    )
    supervisor._capture_started = asyncio.Event()  # noqa: SLF001 - isolated race setup
    before = set(asyncio.all_tasks())

    with pytest.raises(RuntimeError, match="^private-input-receive-failure$"):
        await supervisor._capture_or_input(deadline=1.0)  # noqa: SLF001

    await asyncio.sleep(0)
    leaked = {task for task in asyncio.all_tasks() if task not in before and not task.done()}
    try:
        assert leaked == set()
    finally:
        for task in leaked:
            task.cancel()
        await asyncio.gather(*leaked, return_exceptions=True)


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("private-provider-close-failure"),
        asyncio.CancelledError("private-provider-close-cancellation"),
    ],
    ids=["exception", "cancellation"],
)
@pytest.mark.asyncio
async def test_synchronous_provider_close_factory_failure_is_content_free_cleanup_incomplete(
    error: BaseException,
) -> None:
    clock = _Clock()
    cancellation = _SynchronousFailingCancellation(error)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=_Pipeline(
            clock,
            (SpeechChunk(request_id=REQUEST_ID, sequence=0, pcm=b"", final=True),),
        ),
        input_port=None,
        cancellation=cast(_Cancellation, cancellation),
    )

    outcome = await _bounded_outcome(asyncio.create_task(supervisor.run(TURN_ID)))

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert cancellation.calls == 1
    assert supervisor._tasks == set()  # noqa: SLF001 - failed factory owns no task


@pytest.mark.asyncio
async def test_synchronous_provider_close_scalar_fatal_is_propagated_exactly() -> None:
    fatal = _FatalProbe("private-provider-close-fatal")
    clock = _Clock()
    cancellation = _SynchronousFailingCancellation(fatal)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=_Pipeline(
            clock,
            (SpeechChunk(request_id=REQUEST_ID, sequence=0, pcm=b"", final=True),),
        ),
        input_port=None,
        cancellation=cast(_Cancellation, cancellation),
    )

    with pytest.raises(_FatalProbe) as failure:
        await supervisor.run(TURN_ID)

    assert failure.value is fatal
    assert cancellation.calls == 1


@pytest.mark.asyncio
async def test_synchronous_bridge_close_cancellation_is_a_content_free_cleanup_fault() -> None:
    clock = _Clock()
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_SynchronousCancelledCloseBridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=_Pipeline(clock),
        input_port=None,
    )

    outcome = await _bounded_outcome(asyncio.create_task(supervisor.run(TURN_ID)))

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert supervisor._tasks == set()  # noqa: SLF001 - failed factory owns no task


@pytest.mark.asyncio
async def test_synchronous_bridge_close_scalar_fatal_is_propagated_exactly() -> None:
    fatal = _FatalProbe("private-bridge-close-fatal")
    clock = _Clock()
    bridge = _SynchronousFatalCloseBridge(fatal)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock),
        input_port=None,
    )

    with pytest.raises(_FatalProbe) as failure:
        await supervisor.run(TURN_ID)

    assert failure.value is fatal
    assert bridge.output_fenced


@pytest.mark.asyncio
async def test_completed_bridge_close_failure_is_not_retained_by_supervisor() -> None:
    clock = _Clock()
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_AsynchronousFailingCloseBridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=_Pipeline(clock),
        input_port=None,
    )

    assert await supervisor.run(TURN_ID) is PttSessionOutcome.CLEANUP_INCOMPLETE

    assert supervisor._bridge_close_task is None  # noqa: SLF001 - no traceback retention
    assert supervisor._tasks == set()  # noqa: SLF001 - all terminal outcomes observed


@pytest.mark.asyncio
async def test_hard_stop_latches_before_synchronous_bridge_close_cancellation() -> None:
    clock = _Clock()
    bridge = _SynchronousCancelledCloseBridge(mode=PttInputMode.REACHY_LOCAL)
    pipeline = _BlockingPipeline(clock)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=pipeline,
        input_port=None,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await pipeline.entered.wait()

    bridge.cancel_receive()

    assert await _bounded_outcome(run) is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert supervisor._signal is supervisor_module._Signal.ADAPTER_FAILED  # noqa: SLF001
    assert supervisor._interrupt.is_set()  # noqa: SLF001 - hard-stop latch contract
    assert bridge.output_fenced


@pytest.mark.asyncio
async def test_external_cancellation_during_internal_cleanup_cannot_preempt_receipt_ack() -> None:
    clock = _Clock()
    abort_release = asyncio.Event()
    bridge = _ConcurrentCleanupBridge(abort_release)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(
            clock,
            (SpeechChunk(request_id=REQUEST_ID, sequence=0, pcm=b"", final=True),),
        ),
        input_port=None,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await bridge.abort_entered.wait()

    run.cancel("cleanup-cancel")
    done, _ = await asyncio.wait({run}, timeout=0.05)

    assert run not in done
    abort_release.set()
    with pytest.raises(asyncio.CancelledError) as cancellation:
        await asyncio.wait_for(run, timeout=1)
    assert cancellation.value.args == ("cleanup-cancel",)
    kinds = [frame.control.kind for frame in bridge.sent if isinstance(frame, ControlFrame)]
    assert ControlKind.ABORT in kinds
    assert ControlKind.SAFETY_ACK in kinds
    assert supervisor._tasks == set()  # noqa: SLF001 - shielded cleanup owns every task


@pytest.mark.asyncio
async def test_second_external_cancellation_cannot_preempt_final_teardown_or_replace_first_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(supervisor_module, "_PROVIDER_CLOSE_SECONDS", 0.005)
    monkeypatch.setattr(supervisor_module, "_PROVIDER_JOIN_SECONDS", 0.01)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_ACK_SECONDS", 0.02)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_TOTAL_SECONDS", 0.03)
    monkeypatch.setattr(supervisor_module, "_BRIDGE_CLOSE_SECONDS", 0.03)
    clock = _Clock()
    bridge = _HangingCloseBridge(mode=PttInputMode.REACHY_LOCAL)
    pipeline = _BlockingPipeline(clock)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=pipeline,
        input_port=None,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await pipeline.entered.wait()

    run.cancel("first-cancel")
    await bridge.close_entered.wait()
    run.cancel("second-cancel")
    await asyncio.sleep(0)

    assert not run.done()
    done, _ = await asyncio.wait({run}, timeout=0.2)
    assert run in done
    with pytest.raises(asyncio.CancelledError) as cancellation:
        await run
    assert cancellation.value.args in ((), ("first-cancel",))
    assert cancellation.value.args != ("second-cancel",)
    await asyncio.wait_for(bridge.close_finalized.wait(), timeout=0.2)
    await asyncio.sleep(0)
    assert bridge.close_finalized.is_set()
    assert supervisor._tasks == set()  # noqa: SLF001 - teardown retains all ownership


@pytest.mark.asyncio
async def test_reader_scalar_fatal_is_contained_and_propagated_without_loop_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(supervisor_module, "_CLEANUP_ACK_SECONDS", 0.02)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_TOTAL_SECONDS", 0.05)
    monkeypatch.setattr(supervisor_module, "_BRIDGE_CLOSE_SECONDS", 0.05)
    fatal = _FatalProbe("private-reader-fatal")
    clock = _Clock()
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_FatalReceiveBridge(fatal),
        pipeline=_Pipeline(clock),
        input_port=None,
    )
    loop = asyncio.get_running_loop()
    loop_errors: list[dict[str, object]] = []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: loop_errors.append(context))
    run = asyncio.create_task(supervisor.run(TURN_ID))
    try:
        done, _ = await asyncio.wait({run}, timeout=0.2)
        assert run in done
        with pytest.raises(_FatalProbe) as failure:
            await run
        assert failure.value is fatal
        await asyncio.sleep(0)
    finally:
        if not run.done():
            run.cancel()
            await asyncio.gather(run, return_exceptions=True)
        loop.set_exception_handler(previous_handler)

    assert loop_errors == []


@pytest.mark.asyncio
async def test_late_reader_scalar_fatal_is_detached_without_post_run_retention(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(supervisor_module, "_PROVIDER_CLOSE_SECONDS", 0.005)
    monkeypatch.setattr(supervisor_module, "_PROVIDER_JOIN_SECONDS", 0.01)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_ACK_SECONDS", 0.02)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_TOTAL_SECONDS", 0.03)
    monkeypatch.setattr(supervisor_module, "_BRIDGE_CLOSE_SECONDS", 0.03)
    fatal = _FatalProbe("private-late-reader-fatal")
    clock = _Clock()
    bridge = _LateFatalReceiveBridge(fatal)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(
            clock,
            (SpeechChunk(request_id=REQUEST_ID, sequence=0, pcm=b"", final=True),),
        ),
        input_port=None,
    )

    outcome = await _bounded_outcome(asyncio.create_task(supervisor.run(TURN_ID)))

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert bridge.receive_cancelled.is_set()
    bridge.receive_release.set()
    for _ in range(200):
        if not supervisor._tasks:  # noqa: SLF001 - late callback settled
            break
        await asyncio.sleep(0)
    assert supervisor._tasks == set()  # noqa: SLF001
    assert supervisor._child_fatal is None  # noqa: SLF001 - terminal supervisor stores no late error
    assert fatal.__traceback__ is None
    assert fatal.__cause__ is None
    assert fatal.__context__ is None


@pytest.mark.asyncio
async def test_owner_cancellation_precedes_fatal_input_close_and_finishes_teardown() -> None:
    fatal = _FatalProbe("private-input-close-fatal")
    clock = _Clock()
    input_port = _FatalCloseInput(
        (CorePttEvent.START, CorePttEvent.SUBMIT),
        fatal,
    )
    bridge = _Bridge(
        mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        rapid_submit=True,
    )
    pipeline = _CountingBlockingPipeline(clock)
    supervisor = _supervisor(
        mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        clock=clock,
        bridge=bridge,
        pipeline=pipeline,
        input_port=input_port,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await pipeline.entered.wait()

    run.cancel("first-owner-cancel")

    with pytest.raises(asyncio.CancelledError) as cancellation:
        await asyncio.wait_for(run, timeout=1)
    assert cancellation.value.args in ((), ("first-owner-cancel",))
    assert input_port.closed == 1
    assert bridge.closed == 1
    assert pipeline.quarantine_observations == 1


@pytest.mark.asyncio
async def test_teardown_starts_all_cleanup_siblings_before_joining_runtime_tasks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(supervisor_module, "_PROVIDER_CLOSE_SECONDS", 0.02)
    monkeypatch.setattr(supervisor_module, "_PROVIDER_JOIN_SECONDS", 0.04)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_ACK_SECONDS", 0.1)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_TOTAL_SECONDS", 0.2)
    monkeypatch.setattr(supervisor_module, "_BRIDGE_CLOSE_SECONDS", 0.2)
    clock = _Clock()
    bridge = _CancellationSuppressingReceiveBridge()
    input_port = _HangingCloseInput((CorePttEvent.START, CorePttEvent.SUBMIT))
    pipeline = _TeardownProbePipeline(clock)
    supervisor = _supervisor(
        mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        clock=clock,
        bridge=bridge,
        pipeline=pipeline,
        input_port=input_port,
    )
    deadline_started = asyncio.Event()
    real_deadline_observer = deadline_module.DeadlineGuard.observe_quarantine

    async def observe_deadline_quarantine(
        guard: deadline_module.DeadlineGuard,
        *,
        deadline: float,
    ) -> bool:
        if guard is supervisor._deadlines:  # noqa: SLF001 - exact teardown guard
            deadline_started.set()
        return await real_deadline_observer(guard, deadline=deadline)

    monkeypatch.setattr(
        deadline_module.DeadlineGuard,
        "observe_quarantine",
        observe_deadline_quarantine,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await asyncio.wait_for(bridge.receive_cancelled.wait(), timeout=1)

    try:
        await asyncio.wait_for(
            asyncio.gather(
                bridge.close_started.wait(),
                input_port.close_entered.wait(),
                pipeline.quarantine_started.wait(),
                deadline_started.wait(),
            ),
            timeout=0.05,
        )
    finally:
        bridge.receive_release.set()
        input_port.close_release.set()
        await asyncio.gather(run, return_exceptions=True)


@pytest.mark.parametrize(
    "corrupted_deadline",
    [float("inf"), 1.0e12],
    ids=("nonfinite", "far-future"),
)
@pytest.mark.asyncio
async def test_teardown_clamps_corrupted_cleanup_deadline_for_owned_tasks(
    corrupted_deadline: float,
) -> None:
    clock = _Clock()
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=_Pipeline(clock),
        input_port=None,
    )
    entered = asyncio.Event()
    cancelled = asyncio.Event()
    release = asyncio.Event()
    owned = asyncio.create_task(_suppress_task_cancellation(entered, cancelled, release))
    await entered.wait()
    supervisor._turn_id = TURN_ID  # noqa: SLF001 - direct final-teardown fixture
    supervisor._lane = supervisor_module._OutboundLane(TURN_ID)  # noqa: SLF001
    supervisor._guard = PttDuplexGuard(turn_id=TURN_ID, input_mode=PttInputMode.REACHY_LOCAL)  # noqa: SLF001
    supervisor._guard_transaction = None  # noqa: SLF001
    supervisor._guard_lock = asyncio.Lock()  # noqa: SLF001
    supervisor._decoder = FrameDecoder()  # noqa: SLF001
    supervisor._tasks.add(owned)  # noqa: SLF001 - corrupted teardown-state regression
    supervisor._cleanup_loop_deadline = corrupted_deadline  # noqa: SLF001

    try:
        complete = await asyncio.wait_for(supervisor._teardown(), timeout=0.2)  # noqa: SLF001
        assert complete is False
        assert cancelled.is_set()
        assert owned in supervisor._tasks  # noqa: SLF001 - live task remains owned
    finally:
        release.set()
        await asyncio.gather(owned, return_exceptions=True)

    supervisor._tasks.discard(owned)  # noqa: SLF001 - local direct-teardown fixture cleanup


@pytest.mark.asyncio
async def test_provider_aggregate_deadline_cancels_pipeline_and_returns_provider_failure() -> None:
    clock = _Clock()
    bridge = _Bridge(mode=PttInputMode.REACHY_LOCAL)
    pipeline = _BlockingPipeline(clock)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=pipeline,
        input_port=None,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await pipeline.entered.wait()
    while not any(deadline == 120.0 for deadline, _ in clock.sleepers):
        await asyncio.sleep(0)

    clock.expire(120.0)

    assert await asyncio.wait_for(run, timeout=1) is PttSessionOutcome.PROVIDER_FAILED
    assert pipeline.finalized == 1
    assert pipeline.owned_pcm == bytearray()


@pytest.mark.parametrize(
    "case",
    ["body-fatal-close-ordinary", "body-fatal-close-incomplete", "body-incomplete-close-fatal"],
)
@pytest.mark.asyncio
async def test_provider_iterator_close_preserves_scalar_fatal_precedence(case: str) -> None:
    clock = _Clock()
    body_fatal = _FatalProbe("private-body-fatal")
    close_fatal = _FatalProbe("private-close-fatal")
    body_error: BaseException = body_fatal
    close_error: BaseException = RuntimeError("private-close-error")
    expected = body_fatal
    if case == "body-fatal-close-incomplete":
        close_error = deadline_module.DeadlineCleanupIncomplete()
    elif case == "body-incomplete-close-fatal":
        body_error = deadline_module.DeadlineCleanupIncomplete()
        close_error = close_fatal
        expected = close_fatal
    pipeline = _IteratorCloseFailurePipeline(
        clock,
        body_error=body_error,
        close_error=close_error,
    )
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=pipeline,
        input_port=None,
    )

    with pytest.raises(_FatalProbe) as failure:
        await supervisor.run(TURN_ID)

    assert failure.value is expected
    assert pipeline.close_calls == 1
    assert pipeline.finalized == 1


@pytest.mark.parametrize("chain", ["cause", "context"])
@pytest.mark.asyncio
async def test_spontaneous_provider_cancellation_with_cleanup_incomplete_chain_is_fail_closed(
    chain: str,
) -> None:
    clock = _Clock()
    body_error = asyncio.CancelledError("private-provider-cancellation")
    if chain == "cause":
        body_error.__cause__ = deadline_module.DeadlineCleanupIncomplete()
    else:
        body_error.__context__ = deadline_module.DeadlineCleanupIncomplete()
    pipeline = _IteratorCloseFailurePipeline(
        clock,
        body_error=body_error,
        close_error=RuntimeError("private-close-error"),
    )
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=pipeline,
        input_port=None,
    )

    outcome = await _bounded_outcome(asyncio.create_task(supervisor.run(TURN_ID)))

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert pipeline.close_calls == 1


@pytest.mark.asyncio
async def test_cleanup_incomplete_boundary_drops_private_iterator_traceback_references() -> None:
    clock = _Clock()
    private_pcm = b"\x7d\x00" * 4
    pipeline = _IteratorCloseFailurePipeline(
        clock,
        body_error=RuntimeError("private-provider-body"),
        close_error=deadline_module.DeadlineCleanupIncomplete(),
        first_chunk=SpeechChunk(
            request_id=REQUEST_ID,
            sequence=0,
            pcm=private_pcm,
            final=False,
        ),
    )
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=pipeline,
        input_port=None,
    )
    captured = CapturedTurn.take_ownership(
        turn_id=TURN_ID,
        audio_format=TRANSPORT_AUDIO_FORMAT,
        pcm=bytearray(CAPTURE_PCM),
    )

    with pytest.raises(deadline_module.DeadlineCleanupIncomplete) as failure:
        await supervisor._collect_playback(captured)  # noqa: SLF001

    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    traceback = failure.value.__traceback__
    boundary_seen = False
    while traceback is not None:
        frame_name = traceback.tb_frame.f_code.co_name
        assert frame_name != "_collect_playback_owned"
        if frame_name == "_collect_playback":
            boundary_seen = True
            local_values = tuple(traceback.tb_frame.f_locals.values())
            assert not any(type(value) is bytes and value == private_pcm for value in local_values)
            assert not any(
                isinstance(value, SpeechChunk) and value.pcm == private_pcm
                for value in local_values
            )
            assert all(value is not pipeline.body_error for value in local_values)
            assert all(value is not pipeline.close_error for value in local_values)
            assert "private-provider-body" not in repr(local_values)
        traceback = traceback.tb_next
    assert boundary_seen


@pytest.mark.asyncio
async def test_collect_playback_closes_distinct_iterator_owner() -> None:
    clock = _Clock()
    pipeline = _SplitIteratorPipeline(clock)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=pipeline,
        input_port=None,
    )
    captured = CapturedTurn.take_ownership(
        turn_id=TURN_ID,
        audio_format=TRANSPORT_AUDIO_FORMAT,
        pcm=bytearray(CAPTURE_PCM),
    )

    with pytest.raises(supervisor_module.CorePttSessionError):
        await supervisor._collect_playback(captured)  # noqa: SLF001

    assert pipeline.inner_close_calls == 1
    assert pipeline.outer_close_calls == 1
    assert pipeline.inner_pcm == bytearray()


@pytest.mark.asyncio
async def test_scalar_fatal_boundary_drops_private_iterator_traceback_references() -> None:
    clock = _Clock()
    private_pcm = b"\x7e\x00" * 4
    fatal = _FatalProbe("private-provider-fatal")
    pipeline = _IteratorCloseFailurePipeline(
        clock,
        body_error=fatal,
        close_error=RuntimeError("private-close-error"),
        first_chunk=SpeechChunk(
            request_id=REQUEST_ID,
            sequence=0,
            pcm=private_pcm,
            final=False,
        ),
    )
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=pipeline,
        input_port=None,
    )
    captured = CapturedTurn.take_ownership(
        turn_id=TURN_ID,
        audio_format=TRANSPORT_AUDIO_FORMAT,
        pcm=bytearray(CAPTURE_PCM),
    )

    with pytest.raises(_FatalProbe) as failure:
        await supervisor._collect_playback(captured)  # noqa: SLF001

    assert failure.value is fatal
    traceback = failure.value.__traceback__
    while traceback is not None:
        frame_name = traceback.tb_frame.f_code.co_name
        assert frame_name != "_collect_playback_owned"
        if frame_name == "_collect_playback":
            local_values = tuple(traceback.tb_frame.f_locals.values())
            assert not any(type(value) is bytes and value == private_pcm for value in local_values)
            assert not any(
                isinstance(value, SpeechChunk) and value.pcm == private_pcm
                for value in local_values
            )
        traceback = traceback.tb_next


@pytest.mark.parametrize(
    "close_kind",
    ["cleanup-incomplete", "cleanup-group", "scalar-fatal", "fatal-group"],
)
@pytest.mark.asyncio
async def test_provider_deadline_classifies_iterator_close_outcome(close_kind: str) -> None:
    clock = _Clock()
    close_error: BaseException
    expected_fatal: _FatalProbe | None = None
    if close_kind == "cleanup-incomplete":
        close_error = deadline_module.DeadlineCleanupIncomplete()
    elif close_kind == "cleanup-group":
        close_error = BaseExceptionGroup(
            "private-close-group",
            [
                asyncio.CancelledError("private-close-cancellation"),
                ExceptionGroup(
                    "private-cleanup-group",
                    [deadline_module.DeadlineCleanupIncomplete()],
                ),
            ],
        )
    elif close_kind == "scalar-fatal":
        expected_fatal = _FatalProbe("private-close-fatal")
        close_error = expected_fatal
    else:
        close_error = BaseExceptionGroup(
            "private-close-group",
            [_FatalProbe("private-grouped-fatal")],
        )
    pipeline = _IteratorCloseFailurePipeline(
        clock,
        body_error=None,
        close_error=close_error,
    )
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=pipeline,
        input_port=None,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await pipeline.entered.wait()
    while not any(deadline == 120.0 for deadline, _ in clock.sleepers):
        await asyncio.sleep(0)

    clock.expire(120.0)

    if expected_fatal is not None:
        with pytest.raises(_FatalProbe) as failure:
            await run
        assert failure.value is expected_fatal
    else:
        expected_outcome = (
            PttSessionOutcome.CLEANUP_INCOMPLETE
            if close_kind in {"cleanup-incomplete", "cleanup-group"}
            else PttSessionOutcome.PROVIDER_FAILED
        )
        assert await asyncio.wait_for(run, timeout=1) is expected_outcome
    assert pipeline.close_calls == 1
    assert pipeline.finalized == 1


@pytest.mark.parametrize("close_kind", ["cleanup-incomplete", "scalar-fatal"])
@pytest.mark.asyncio
async def test_external_owner_cancellation_wins_over_provider_iterator_close(
    close_kind: str,
) -> None:
    clock = _Clock()
    close_error: BaseException = (
        deadline_module.DeadlineCleanupIncomplete()
        if close_kind == "cleanup-incomplete"
        else _FatalProbe("private-close-fatal")
    )
    pipeline = _IteratorCloseFailurePipeline(
        clock,
        body_error=None,
        close_error=close_error,
    )
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=pipeline,
        input_port=None,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await pipeline.entered.wait()

    run.cancel("exact-owner-cancel")

    with pytest.raises(asyncio.CancelledError) as cancellation:
        await asyncio.wait_for(run, timeout=1)
    assert cancellation.value.args in ((), ("exact-owner-cancel",))
    assert pipeline.close_calls == 1
    assert pipeline.finalized == 1


@pytest.mark.asyncio
async def test_abort_is_sent_while_provider_transport_close_is_still_running() -> None:
    clock = _Clock()
    bridge = _Bridge(mode=PttInputMode.REACHY_LOCAL)
    cancellation = _BlockingCancellation()
    invalid_pipeline = _Pipeline(
        clock,
        (SpeechChunk(request_id=REQUEST_ID, sequence=0, pcm=b"", final=True),),
    )
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=invalid_pipeline,
        input_port=None,
        cancellation=cancellation,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await cancellation.entered.wait()

    await _wait_for_control_kind(bridge, ControlKind.ABORT)
    kinds = [frame.control.kind for frame in bridge.sent if isinstance(frame, ControlFrame)]
    assert ControlKind.ABORT in kinds
    assert not run.done()

    cancellation.release.set()
    assert await asyncio.wait_for(run, timeout=1) is PttSessionOutcome.PROVIDER_FAILED


@pytest.mark.asyncio
async def test_abort_may_commit_after_provider_close_epoch_within_cleanup_epoch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(supervisor_module, "_PROVIDER_CLOSE_SECONDS", 0.01)
    monkeypatch.setattr(supervisor_module, "_PROVIDER_JOIN_SECONDS", 0.02)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_ACK_SECONDS", 0.15)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_TOTAL_SECONDS", 0.2)
    gate = asyncio.Event()
    clock = _Clock()
    bridge = _ConcurrentCleanupBridge(gate)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(
            clock,
            (SpeechChunk(request_id=REQUEST_ID, sequence=0, pcm=b"", final=True),),
        ),
        input_port=None,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await bridge.abort_entered.wait()

    await asyncio.sleep(0.03)
    gate.set()

    assert await asyncio.wait_for(run, timeout=1) is PttSessionOutcome.PROVIDER_FAILED


@pytest.mark.asyncio
async def test_abort_and_provider_close_are_both_scheduled_before_cleanup_yields() -> None:
    clock = _Clock()
    gate = asyncio.Event()
    bridge = _ConcurrentCleanupBridge(gate)
    cancellation = _ConcurrentCleanupCancellation(gate)
    invalid_pipeline = _GatedInvalidPipeline(clock)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=invalid_pipeline,
        input_port=None,
        cancellation=cancellation,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await invalid_pipeline.entered.wait()
    await supervisor._lane._condition.acquire()  # noqa: SLF001 - cleanup contention probe
    try:
        invalid_pipeline.release.set()

        async def wait_for_cleanup_start() -> None:
            while not supervisor._cleanup_started:  # noqa: SLF001 - cleanup contention probe
                await asyncio.sleep(0)

        await asyncio.wait_for(wait_for_cleanup_start(), timeout=1)
        assert supervisor._cleanup_started  # noqa: SLF001 - cleanup contention probe
        scheduled = {task.get_name() for task in asyncio.all_tasks()}
        assert "core-ptt-abort-send" in scheduled
        assert "core-ptt-provider-close" in scheduled
    finally:
        supervisor._lane._condition.release()  # noqa: SLF001 - cleanup contention probe

    await bridge.abort_entered.wait()
    await cancellation.close_entered.wait()

    assert bridge.abort_saw_provider_close
    assert cancellation.close_saw_abort
    assert bridge.abort_started_at is not None
    assert cancellation.close_started_at is not None

    gate.set()
    assert await asyncio.wait_for(run, timeout=1) is PttSessionOutcome.PROVIDER_FAILED


@pytest.mark.asyncio
async def test_partial_receipt_is_acknowledged_false_and_fails_closed() -> None:
    clock = _Clock()
    bridge = _Bridge(mode=PttInputMode.REACHY_LOCAL, receipt_complete=False)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock),
        input_port=None,
    )

    outcome = await asyncio.wait_for(supervisor.run(TURN_ID), timeout=1)

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    ack = next(
        frame
        for frame in bridge.sent
        if isinstance(frame, ControlFrame) and frame.control.kind is ControlKind.SAFETY_ACK
    )
    assert isinstance(ack.control.payload, AckPayload)
    assert ack.control.payload.accepted is False


@pytest.mark.asyncio
async def test_decoder_poison_emits_no_abort_ack_or_other_post_poison_frame() -> None:
    clock = _Clock()
    bridge = _Bridge(mode=PttInputMode.REACHY_LOCAL, poison_after_open=True)
    cancellation = _Cancellation()
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock),
        input_port=None,
        cancellation=cancellation,
    )

    outcome = await asyncio.wait_for(supervisor.run(TURN_ID), timeout=1)

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert len(bridge.sent) == 1
    only = bridge.sent[0]
    assert isinstance(only, ControlFrame)
    assert only.control.kind is ControlKind.SESSION_OPEN
    assert cancellation.calls == 1
    assert bridge.closed == 1


@pytest.mark.parametrize("poison_kind", ["malformed", "wrong_sequence"])
@pytest.mark.asyncio
async def test_poison_atomically_stops_a_full_pcm_backlog_at_the_writer_boundary(
    poison_kind: str,
) -> None:
    clock = _Clock()
    bridge = _Bridge(mode=PttInputMode.REACHY_LOCAL, block_pcm=True)
    chunks = tuple(
        SpeechChunk(
            request_id=REQUEST_ID,
            sequence=sequence,
            pcm=bytes((sequence % 251, 0)) * 3_200,
            final=False,
        )
        for sequence in range(66)
    ) + (SpeechChunk(request_id=REQUEST_ID, sequence=66, pcm=b"", final=True),)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock, chunks),
        input_port=None,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await bridge.pcm_send_entered.wait()
    await _wait_for_full_normal_lane(supervisor)
    assert len(supervisor._lane._normal) == 64  # noqa: SLF001 - full-backlog race
    sent_before_poison = tuple(bridge.sent)

    poison = (
        b"X" * 32
        if poison_kind == "malformed"
        else encode_control_frame(
            sequence=bridge.edge_sequence + 1,
            control=PttControl.heartbeat(TURN_ID),
        )
    )
    bridge.incoming.put_nowait(poison)
    for _ in range(100):
        if supervisor._signal is supervisor_module._Signal.PROTOCOL_POISONED:  # noqa: SLF001
            break
        await asyncio.sleep(0)
    assert supervisor._signal is supervisor_module._Signal.PROTOCOL_POISONED  # noqa: SLF001

    try:
        assert await asyncio.wait_for(run, timeout=1) is PttSessionOutcome.CLEANUP_INCOMPLETE
        assert tuple(bridge.sent) == sent_before_poison
    finally:
        for _ in range(100):
            bridge.pcm_permits.release()


@pytest.mark.asyncio
async def test_peer_eof_closes_immediately_as_cleanup_incomplete_without_wire_retry() -> None:
    clock = _Clock()
    bridge = _Bridge(mode=PttInputMode.REACHY_LOCAL, eof_after_open=True)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock),
        input_port=None,
    )

    outcome = await asyncio.wait_for(supervisor.run(TURN_ID), timeout=0.2)

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert [frame.control.kind for frame in bridge.sent if isinstance(frame, ControlFrame)] == [
        ControlKind.SESSION_OPEN
    ]
    assert bridge.closed == 1


@pytest.mark.parametrize("close_target", ["bridge", "bridge_unusable_swallow", "input"])
@pytest.mark.asyncio
async def test_every_close_path_is_bounded_by_its_frozen_cleanup_epoch(
    monkeypatch: pytest.MonkeyPatch,
    close_target: str,
) -> None:
    monkeypatch.setattr(supervisor_module, "_PROVIDER_CLOSE_SECONDS", 0.005)
    monkeypatch.setattr(supervisor_module, "_PROVIDER_JOIN_SECONDS", 0.01)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_ACK_SECONDS", 0.02)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_TOTAL_SECONDS", 0.03)
    monkeypatch.setattr(supervisor_module, "_BRIDGE_CLOSE_SECONDS", 0.03)
    clock = _Clock()
    input_port: _Input | None = None
    if close_target == "input":
        mode = PttInputMode.CORE_TERMINAL_TOGGLE
        input_port = _HangingCloseInput((CorePttEvent.START, CorePttEvent.SUBMIT))
        bridge: _Bridge = _Bridge(mode=mode)
        close_entered = input_port.close_entered
        close_release = input_port.close_release
        close_finalized = input_port.close_finalized
    else:
        mode = PttInputMode.REACHY_LOCAL
        hanging_bridge = _HangingCloseBridge(
            mode=mode,
            swallow_cancellation=close_target == "bridge_unusable_swallow",
            eof_after_open=close_target == "bridge_unusable_swallow",
        )
        bridge = hanging_bridge
        close_entered = hanging_bridge.close_entered
        close_release = hanging_bridge.close_release
        close_finalized = hanging_bridge.close_finalized
    supervisor = _supervisor(
        mode=mode,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock),
        input_port=input_port,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await close_entered.wait()

    done, _ = await asyncio.wait({run}, timeout=0.2)
    finished_within_bound = run in done
    if not finished_within_bound:
        close_release.set()
        await asyncio.gather(run, return_exceptions=True)

    assert finished_within_bound
    assert run.result() is PttSessionOutcome.CLEANUP_INCOMPLETE
    if close_target == "bridge_unusable_swallow":
        assert not close_finalized.is_set()
        assert supervisor._tasks  # noqa: SLF001 - live close remains owned
        close_release.set()
        for _ in range(100):
            if not supervisor._tasks:  # noqa: SLF001
                break
            await asyncio.sleep(0)
    assert close_finalized.is_set()
    assert supervisor._tasks == set()  # noqa: SLF001 - no unowned close orphan


@pytest.mark.asyncio
async def test_transport_close_has_its_own_nonrenewable_epoch_after_safety_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(supervisor_module, "_PROVIDER_CLOSE_SECONDS", 0.22)
    monkeypatch.setattr(supervisor_module, "_PROVIDER_JOIN_SECONDS", 0.23)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_ACK_SECONDS", 0.24)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_TOTAL_SECONDS", 0.25)
    monkeypatch.setattr(supervisor_module, "_BRIDGE_CLOSE_SECONDS", 0.18, raising=False)
    clock = _Clock()
    bridge = _DelayedCloseBridge(mode=PttInputMode.REACHY_LOCAL, delay=0.12)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(
            clock,
            (SpeechChunk(request_id=REQUEST_ID, sequence=0, pcm=b"", final=True),),
        ),
        input_port=None,
        cancellation=_DelayedCancellation(0.16),
    )
    started = asyncio.get_running_loop().time()

    outcome = await supervisor.run(TURN_ID)

    elapsed = asyncio.get_running_loop().time() - started
    assert outcome is PttSessionOutcome.PROVIDER_FAILED
    assert bridge.close_started_at is not None
    assert bridge.close_finished_at is not None
    assert bridge.close_finished_at - bridge.close_started_at >= 0.12
    assert elapsed < 0.55


@pytest.mark.asyncio
async def test_late_transport_epoch_is_not_truncated_by_core_cleanup_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(supervisor_module, "_PROVIDER_CLOSE_SECONDS", 0.02)
    monkeypatch.setattr(supervisor_module, "_PROVIDER_JOIN_SECONDS", 0.025)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_ACK_SECONDS", 0.028)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_TOTAL_SECONDS", 0.03)
    monkeypatch.setattr(supervisor_module, "_BRIDGE_CLOSE_SECONDS", 0.025)
    clock = _FailingNowClock()
    bridge = _DelayedCloseBridge(mode=PttInputMode.REACHY_LOCAL, delay=0.02)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock),
        input_port=None,
        cancellation=_DelayedCancellation(0.015),
    )

    outcome = await supervisor.run(TURN_ID)

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert bridge.close_started_at is not None
    assert bridge.close_finished_at is not None
    assert bridge.close_finished_at - bridge.close_started_at >= 0.02


@pytest.mark.asyncio
async def test_spontaneous_receive_cancellation_is_an_adapter_fault() -> None:
    clock = _Clock()
    bridge = _CancelledReceiveBridge(mode=PttInputMode.REACHY_LOCAL)
    pipeline = _BlockingPipeline(clock)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=pipeline,
        input_port=None,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await pipeline.entered.wait()

    bridge.cancel_receive()

    assert await _bounded_outcome(run) is PttSessionOutcome.CLEANUP_INCOMPLETE


@pytest.mark.asyncio
async def test_spontaneous_send_cancellation_is_an_adapter_fault() -> None:
    clock = _Clock()
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_CancelledPcmSendBridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=_Pipeline(clock),
        input_port=None,
    )

    outcome = await _bounded_outcome(asyncio.create_task(supervisor.run(TURN_ID)))

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE


@pytest.mark.asyncio
async def test_spontaneous_input_cancellation_is_an_adapter_fault() -> None:
    clock = _Clock()
    supervisor = _supervisor(
        mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.CORE_TERMINAL_TOGGLE),
        pipeline=_Pipeline(clock),
        input_port=_CancelledSecondInput(),
    )

    outcome = await _bounded_outcome(asyncio.create_task(supervisor.run(TURN_ID)))

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE


@pytest.mark.asyncio
async def test_spontaneous_provider_close_cancellation_is_a_cleanup_fault() -> None:
    clock = _Clock()
    invalid_pipeline = _Pipeline(
        clock,
        (SpeechChunk(request_id=REQUEST_ID, sequence=0, pcm=b"", final=True),),
    )
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=invalid_pipeline,
        input_port=None,
        cancellation=_CancelledCancellation(),
    )

    outcome = await _bounded_outcome(asyncio.create_task(supervisor.run(TURN_ID)))

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE


@pytest.mark.asyncio
async def test_spontaneous_pipeline_iterator_cancellation_is_a_provider_fault() -> None:
    clock = _Clock()
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=_CancelledIteratorPipeline(clock),
        input_port=None,
    )

    outcome = await _bounded_outcome(asyncio.create_task(supervisor.run(TURN_ID)))

    assert outcome is PttSessionOutcome.PROVIDER_FAILED


@pytest.mark.asyncio
async def test_spontaneous_heartbeat_clock_cancellation_is_a_clock_fault() -> None:
    clock = _CancelledHeartbeatClock()
    pipeline = _BlockingPipeline(clock)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=pipeline,
        input_port=None,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await clock.heartbeat_cancelled.wait()

    assert await _bounded_outcome(run) is PttSessionOutcome.CLEANUP_INCOMPLETE


@pytest.mark.asyncio
async def test_exact_session_ready_deadline_expires_and_runs_receipted_cleanup() -> None:
    clock = _Clock()
    bridge = _Bridge(mode=PttInputMode.REACHY_LOCAL, auto_ready=False)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock),
        input_port=None,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await bridge.session_open_sent.wait()
    while not any(deadline == 5.0 for deadline, _ in clock.sleepers):
        await asyncio.sleep(0)

    clock.expire(5.0)

    assert await asyncio.wait_for(run, timeout=1) is PttSessionOutcome.SESSION_TIMEOUT
    kinds = [frame.control.kind for frame in bridge.sent if isinstance(frame, ControlFrame)]
    assert kinds == [ControlKind.SESSION_OPEN, ControlKind.ABORT, ControlKind.SAFETY_ACK]


@pytest.mark.asyncio
async def test_early_clock_sleeper_poison_closes_without_post_poison_output() -> None:
    clock = _Clock()
    bridge = _Bridge(mode=PttInputMode.REACHY_LOCAL, auto_ready=False)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock),
        input_port=None,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await bridge.session_open_sent.wait()
    while not any(deadline == 5.0 for deadline, _ in clock.sleepers):
        await asyncio.sleep(0)

    clock.current = 4.999
    next(event for deadline, event in clock.sleepers if deadline == 5.0).set()

    assert await asyncio.wait_for(run, timeout=1) is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert [frame.control.kind for frame in bridge.sent if isinstance(frame, ControlFrame)] == [
        ControlKind.SESSION_OPEN
    ]


@pytest.mark.asyncio
async def test_protocol_poison_while_pcm_send_is_blocked_cancels_writer_without_more_output() -> (
    None
):
    clock = _Clock()
    bridge = _Bridge(mode=PttInputMode.REACHY_LOCAL, block_pcm=True)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock),
        input_port=None,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await bridge.pcm_send_entered.wait()
    sent_before_poison = tuple(bridge.sent)

    bridge.incoming.put_nowait(b"X" * 32)

    assert await asyncio.wait_for(run, timeout=1) is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert tuple(bridge.sent) == sent_before_poison
    kinds = [frame.control.kind for frame in bridge.sent if isinstance(frame, ControlFrame)]
    assert ControlKind.ABORT not in kinds
    assert ControlKind.SAFETY_ACK not in kinds
    assert supervisor._playback == bytearray()  # noqa: SLF001 - mutable-buffer cleanup contract


@pytest.mark.asyncio
async def test_exact_ninety_second_playback_is_rejected_to_preserve_drain_headroom() -> None:
    clock = _Clock()
    bridge = _Bridge(mode=PttInputMode.REACHY_LOCAL)
    frame = b"\x01\x00" * 3_200
    chunks = tuple(
        SpeechChunk(
            request_id=REQUEST_ID,
            sequence=sequence,
            pcm=frame,
            final=False,
        )
        for sequence in range(450)
    ) + (SpeechChunk(request_id=REQUEST_ID, sequence=450, pcm=b"", final=True),)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock, chunks),
        input_port=None,
    )

    outcome = await asyncio.wait_for(supervisor.run(TURN_ID), timeout=1)

    assert outcome is PttSessionOutcome.PROVIDER_FAILED
    kinds = [frame.control.kind for frame in bridge.sent if isinstance(frame, ControlFrame)]
    assert ControlKind.PLAYBACK_START not in kinds
    assert ControlKind.ABORT in kinds


@pytest.mark.asyncio
async def test_heartbeat_deadlines_coalesce_while_writer_is_backpressured() -> None:
    clock = _Clock()
    bridge = _Bridge(
        mode=PttInputMode.REACHY_LOCAL,
        block_session_open=True,
    )
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock),
        input_port=None,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await bridge.session_open_sent.wait()

    for deadline in (1.0, 2.0, 3.0):
        while not any(scheduled == deadline for scheduled, _ in clock.sleepers):
            await asyncio.sleep(0)
        clock.expire(deadline)
    bridge.session_open_permit.set()

    assert await asyncio.wait_for(run, timeout=1) is PttSessionOutcome.COMPLETED
    kinds = [frame.control.kind for frame in bridge.sent if isinstance(frame, ControlFrame)]
    assert kinds.count(ControlKind.HEARTBEAT) == 1
    assert [frame.sequence for frame in bridge.sent] == list(range(len(bridge.sent)))


@pytest.mark.asyncio
async def test_heartbeat_clock_jump_skips_missed_intervals_without_a_catch_up_burst() -> None:
    clock = _JumpClock()
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=_Pipeline(clock),
        input_port=None,
    )
    supervisor._turn_id = TURN_ID  # noqa: SLF001 - isolated scheduler probe
    supervisor._lane = supervisor_module._OutboundLane(TURN_ID)  # noqa: SLF001
    supervisor._interrupt = asyncio.Event()  # noqa: SLF001 - isolated scheduler probe
    supervisor._signal = supervisor_module._Signal.NONE  # noqa: SLF001 - scheduler probe
    heartbeat = asyncio.create_task(supervisor._heartbeat())  # noqa: SLF001
    try:
        for _ in range(100):
            if clock.calls == [1.0]:
                break
            await asyncio.sleep(0)
        assert clock.calls == [1.0]

        clock.jump.set()
        for _ in range(100):
            if 11.0 in clock.calls:
                break
            await asyncio.sleep(0)

        assert clock.calls == [1.0, 11.0]
    finally:
        heartbeat.cancel()
        await asyncio.gather(heartbeat, return_exceptions=True)


@pytest.mark.asyncio
async def test_exact_capture_open_deadline_fails_closed() -> None:
    clock = _Clock()
    bridge = _Bridge(
        mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        rapid_submit=True,
    )
    supervisor = _supervisor(
        mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock),
        input_port=_Input((CorePttEvent.START,)),
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    while not any(deadline == 2.0 for deadline, _ in clock.sleepers):
        await asyncio.sleep(0)

    clock.expire(2.0)

    assert await asyncio.wait_for(run, timeout=1) is PttSessionOutcome.CAPTURE_FAILED
    kinds = [frame.control.kind for frame in bridge.sent if isinstance(frame, ControlFrame)]
    assert kinds == [
        ControlKind.SESSION_OPEN,
        ControlKind.PTT_START,
        ControlKind.ABORT,
        ControlKind.SAFETY_ACK,
    ]


@pytest.mark.parametrize("invalid", [object(), b"X" * (MAX_FEED_BYTES + 1)])
@pytest.mark.asyncio
async def test_bridge_adapter_receive_fault_is_not_decoder_poison_but_closes_without_retry(
    invalid: object,
) -> None:
    clock = _Clock()
    bridge = _Bridge(mode=PttInputMode.REACHY_LOCAL)
    pipeline = _BlockingPipeline(clock)
    cancellation = _Cancellation()
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=pipeline,
        input_port=None,
        cancellation=cancellation,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await pipeline.entered.wait()

    bridge.incoming.put_nowait(cast(bytes, invalid))

    assert await asyncio.wait_for(run, timeout=1) is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert pipeline.finalized == 1
    kinds = [frame.control.kind for frame in bridge.sent if isinstance(frame, ControlFrame)]
    assert ControlKind.ABORT not in kinds
    assert ControlKind.SAFETY_ACK not in kinds
    assert cancellation.calls == 1


@pytest.mark.asyncio
async def test_writer_failure_interrupts_pending_control_send_without_hanging() -> None:
    clock = _Clock()
    bridge = _FailingStartBridge(mode=PttInputMode.CORE_TERMINAL_TOGGLE)
    supervisor = _supervisor(
        mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock),
        input_port=_Input((CorePttEvent.START,)),
    )

    outcome = await asyncio.wait_for(supervisor.run(TURN_ID), timeout=0.2)

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert bridge.closed == 1


@pytest.mark.asyncio
async def test_cleanup_receipt_wait_uses_one_shared_t0_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(supervisor_module, "_PROVIDER_CLOSE_SECONDS", 0.2)
    monkeypatch.setattr(supervisor_module, "_PROVIDER_JOIN_SECONDS", 0.24)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_ACK_SECONDS", 0.3)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_TOTAL_SECONDS", 0.6)
    clock = _Clock()
    bridge = _Bridge(
        mode=PttInputMode.REACHY_LOCAL,
        receipt_on_abort=False,
    )
    cancellation = _BlockingCancellation()
    invalid_pipeline = _Pipeline(
        clock,
        (SpeechChunk(request_id=REQUEST_ID, sequence=0, pcm=b"", final=True),),
    )
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=invalid_pipeline,
        input_port=None,
        cancellation=cancellation,
    )
    started = asyncio.get_running_loop().time()

    outcome = await supervisor.run(TURN_ID)

    elapsed = asyncio.get_running_loop().time() - started
    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert elapsed < 0.45


@pytest.mark.asyncio
async def test_terminal_input_race_quarantines_an_indefinitely_cancellation_suppressing_loser(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deadline_module, "_CANCEL_OBSERVE_SECONDS", 0.01, raising=False)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_TOTAL_SECONDS", 0.03)
    clock = _Clock()
    input_port = _CancellationSuppressingInput()
    bridge = _Bridge(mode=PttInputMode.CORE_TERMINAL_TOGGLE, rapid_submit=True)
    supervisor = _supervisor(
        mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock),
        input_port=input_port,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await input_port.blocked.wait()
    bridge._edge_capture()  # noqa: SLF001 - release the deterministic capture/input race
    await input_port.cancelled.wait()

    done, _ = await asyncio.wait({run}, timeout=0.2)
    finished_within_bound = run in done
    if not finished_within_bound:
        input_port.release.set()
        await asyncio.gather(run, return_exceptions=True)

    assert finished_within_bound
    assert run.result() is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert supervisor._deadlines._quarantine  # noqa: SLF001 - input loser stays owned
    input_port.release.set()
    for _ in range(100):
        if not supervisor._deadlines._quarantine:  # noqa: SLF001
            break
        await asyncio.sleep(0)
    assert supervisor._deadlines._quarantine == set()  # noqa: SLF001


@pytest.mark.asyncio
async def test_external_cancellation_wins_over_incomplete_input_child_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deadline_module, "_CANCEL_OBSERVE_SECONDS", 0.01, raising=False)
    monkeypatch.setattr(supervisor_module, "_PROVIDER_CLOSE_SECONDS", 0.005)
    monkeypatch.setattr(supervisor_module, "_PROVIDER_JOIN_SECONDS", 0.01)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_ACK_SECONDS", 0.02)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_TOTAL_SECONDS", 0.03)
    monkeypatch.setattr(supervisor_module, "_BRIDGE_CLOSE_SECONDS", 0.03)
    clock = _Clock()
    input_port = _CancellationSuppressingInput()
    supervisor = _supervisor(
        mode=PttInputMode.CORE_TERMINAL_TOGGLE,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.CORE_TERMINAL_TOGGLE, rapid_submit=True),
        pipeline=_Pipeline(clock),
        input_port=input_port,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await input_port.blocked.wait()

    run.cancel("first-external-cancel")
    await input_port.cancelled.wait()
    done, _ = await asyncio.wait({run}, timeout=0.2)
    try:
        assert run in done
        with pytest.raises(asyncio.CancelledError) as cancellation:
            await run
        assert cancellation.value.args in ((), ("first-external-cancel",))
        assert supervisor._deadlines._quarantine  # noqa: SLF001 - loser remains owned
    finally:
        input_port.release.set()
        for _ in range(100):
            if not supervisor._deadlines._quarantine:  # noqa: SLF001
                break
            await asyncio.sleep(0)
    assert supervisor._deadlines._quarantine == set()  # noqa: SLF001


@pytest.mark.asyncio
async def test_task_completion_after_absolute_cleanup_deadline_is_rejected() -> None:
    clock = _Clock()
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=_Pipeline(clock),
        input_port=None,
    )
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 0.005
    task = supervisor._track(  # noqa: SLF001 - exact completion-time qualification probe
        asyncio.create_task(asyncio.sleep(0.02))
    )
    await task

    assert not await supervisor._observe_task_until(  # noqa: SLF001
        task,
        deadline=deadline,
        cancelled_ok=False,
    )


@pytest.mark.asyncio
async def test_task_completion_at_absolute_cleanup_deadline_is_rejected() -> None:
    clock = _Clock()
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=_Pipeline(clock),
        input_port=None,
    )
    task = supervisor._track(  # noqa: SLF001 - inclusive deadline qualification probe
        asyncio.create_task(asyncio.sleep(0))
    )
    await task
    deadline = asyncio.get_running_loop().time() + 1.0
    supervisor._completion_times[task] = deadline  # noqa: SLF001 - exact tie probe

    assert not await supervisor._observe_task_until(  # noqa: SLF001
        task,
        deadline=deadline,
        cancelled_ok=False,
    )


@pytest.mark.asyncio
async def test_task_completed_before_deadline_stays_valid_when_observed_later() -> None:
    clock = _Clock()
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=_Pipeline(clock),
        input_port=None,
    )
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 0.03
    task = supervisor._track(  # noqa: SLF001 - exact completion-time qualification probe
        asyncio.create_task(asyncio.sleep(0))
    )
    await task
    await asyncio.sleep(0.04)

    assert await supervisor._observe_task_until(  # noqa: SLF001
        task,
        deadline=deadline,
        cancelled_ok=False,
    )


@pytest.mark.asyncio
async def test_playback_queue_admission_is_interruptible_at_the_absolute_playback_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(supervisor_module, "_PROVIDER_CLOSE_SECONDS", 0.2)
    monkeypatch.setattr(supervisor_module, "_PROVIDER_JOIN_SECONDS", 0.4)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_ACK_SECONDS", 0.6)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_TOTAL_SECONDS", 1.0)
    clock = _Clock()
    bridge = _Bridge(mode=PttInputMode.REACHY_LOCAL, block_pcm=True)
    chunks = tuple(
        SpeechChunk(
            request_id=REQUEST_ID,
            sequence=sequence,
            pcm=bytes((sequence % 251, 0)) * 3_200,
            final=False,
        )
        for sequence in range(66)
    ) + (SpeechChunk(request_id=REQUEST_ID, sequence=66, pcm=b"", final=True),)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock, chunks),
        input_port=None,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await bridge.pcm_send_entered.wait()
    try:

        async def wait_for_blocked_admission() -> None:
            while not (
                len(supervisor._lane._normal) == 64  # noqa: SLF001
                and any(deadline == 90.0 for deadline, _ in clock.sleepers)
            ):
                await asyncio.sleep(0)

        await asyncio.wait_for(wait_for_blocked_admission(), timeout=5)

        assert len(supervisor._lane._normal) == 64  # noqa: SLF001 - blocked admission
        assert any(deadline == 90.0 for deadline, _ in clock.sleepers)
        clock.expire(90.0)
        assert await _bounded_outcome(run, timeout=2) is PttSessionOutcome.PLAYBACK_FAILED
    finally:
        for _ in range(100):
            bridge.pcm_permits.release()
        if not run.done():
            run.cancel()
            await asyncio.gather(run, return_exceptions=True)


@pytest.mark.asyncio
async def test_cancel_during_active_uncommitted_pcm_preserves_priority_abort_and_ack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(supervisor_module, "_PROVIDER_CLOSE_SECONDS", 0.01)
    monkeypatch.setattr(supervisor_module, "_PROVIDER_JOIN_SECONDS", 0.02)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_ACK_SECONDS", 0.03)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_TOTAL_SECONDS", 0.04)
    clock = _Clock()
    bridge = _Bridge(mode=PttInputMode.REACHY_LOCAL, block_pcm=True)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock),
        input_port=None,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await bridge.pcm_send_entered.wait()

    bridge.edge_cancel()

    assert await _bounded_outcome(run) is PttSessionOutcome.CANCELLED
    assert not any(isinstance(frame, PcmFrame) for frame in bridge.sent)
    controls = [frame for frame in bridge.sent if isinstance(frame, ControlFrame)]
    kinds = [frame.control.kind for frame in controls]
    assert ControlKind.ABORT in kinds
    assert ControlKind.SAFETY_ACK in kinds
    for index, frame in enumerate(bridge.sent):
        if isinstance(frame, ControlFrame) and frame.control.kind in {
            ControlKind.ABORT,
            ControlKind.SAFETY_ACK,
        }:
            assert bridge.send_priorities[index] is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("edge_controls", "expected_outcome", "expected_reason"),
    (
        (
            (
                PttControl.cancel(TURN_ID),
                PttControl.error(TURN_ID, PttErrorReason.PROVIDER_FAILED),
            ),
            PttSessionOutcome.CANCELLED,
            PttErrorReason.TURN_CANCELLED,
        ),
        (
            (
                PttControl.error(TURN_ID, PttErrorReason.PROVIDER_FAILED),
                PttControl.cancel(TURN_ID),
            ),
            PttSessionOutcome.PROVIDER_FAILED,
            PttErrorReason.PROVIDER_FAILED,
        ),
    ),
)
async def test_first_edge_cleanup_reason_is_preserved_for_abort(
    edge_controls: tuple[PttControl, PttControl],
    expected_outcome: PttSessionOutcome,
    expected_reason: PttErrorReason,
) -> None:
    clock = _Clock()
    bridge = _Bridge(mode=PttInputMode.REACHY_LOCAL, block_pcm=True)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock),
        input_port=None,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await bridge.pcm_send_entered.wait()

    for control in edge_controls:
        bridge._edge_control(control)  # noqa: SLF001 - deterministic duplex ordering
    bridge._receipt()  # noqa: SLF001 - complete the cleanup handshake

    assert await _bounded_outcome(run) is expected_outcome
    abort = next(
        frame
        for frame in bridge.sent
        if isinstance(frame, ControlFrame) and frame.control.kind is ControlKind.ABORT
    )
    assert isinstance(abort.control.payload, ErrorPayload)
    assert abort.control.payload.reason_code is expected_reason


@pytest.mark.asyncio
async def test_latched_cancel_is_not_remapped_to_playback_failure_while_queue_is_full(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(supervisor_module, "_PROVIDER_CLOSE_SECONDS", 0.01)
    monkeypatch.setattr(supervisor_module, "_PROVIDER_JOIN_SECONDS", 0.02)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_ACK_SECONDS", 0.03)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_TOTAL_SECONDS", 0.04)
    clock = _Clock()
    bridge = _Bridge(mode=PttInputMode.REACHY_LOCAL, block_pcm=True)
    chunks = tuple(
        SpeechChunk(
            request_id=REQUEST_ID,
            sequence=sequence,
            pcm=bytes((sequence % 251, 0)) * 3_200,
            final=False,
        )
        for sequence in range(66)
    ) + (SpeechChunk(request_id=REQUEST_ID, sequence=66, pcm=b"", final=True),)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock, chunks),
        input_port=None,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await bridge.pcm_send_entered.wait()
    await _wait_for_full_normal_lane(supervisor)
    assert len(supervisor._lane._normal) == 64  # noqa: SLF001

    bridge.edge_cancel()

    assert await _bounded_outcome(run) is PttSessionOutcome.CANCELLED
    abort = next(
        frame
        for frame in bridge.sent
        if isinstance(frame, ControlFrame) and frame.control.kind is ControlKind.ABORT
    )
    assert isinstance(abort.control.payload, ErrorPayload)
    assert abort.control.payload.reason_code is PttErrorReason.TURN_CANCELLED


@pytest.mark.asyncio
async def test_same_tick_poison_allows_only_one_committed_pcm_for_edge_late_discard() -> None:
    clock = _Clock()
    bridge = _SameTickCommittedPcmPoisonBridge(mode=PttInputMode.REACHY_LOCAL)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock),
        input_port=None,
    )

    outcome = await _bounded_outcome(asyncio.create_task(supervisor.run(TURN_ID)))

    assert outcome is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert len([frame for frame in bridge.sent if isinstance(frame, PcmFrame)]) == 1
    kinds = [frame.control.kind for frame in bridge.sent if isinstance(frame, ControlFrame)]
    assert kinds == [ControlKind.SESSION_OPEN, ControlKind.PLAYBACK_START]
    assert bridge.closed == 1


@pytest.mark.asyncio
async def test_cancellation_suppressing_send_and_close_are_fenced_bounded_and_retained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deadline_module, "_CANCEL_OBSERVE_SECONDS", 0.005, raising=False)
    monkeypatch.setattr(supervisor_module, "_PROVIDER_CLOSE_SECONDS", 0.005)
    monkeypatch.setattr(supervisor_module, "_PROVIDER_JOIN_SECONDS", 0.01)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_ACK_SECONDS", 0.02)
    monkeypatch.setattr(supervisor_module, "_CLEANUP_TOTAL_SECONDS", 0.03)
    monkeypatch.setattr(supervisor_module, "_BRIDGE_CLOSE_SECONDS", 0.03)
    clock = _Clock()
    bridge = _CancellationSuppressingSendCloseBridge()
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=bridge,
        pipeline=_Pipeline(clock),
        input_port=None,
    )
    run = asyncio.create_task(supervisor.run(TURN_ID))
    await asyncio.wait_for(bridge.send_entered.wait(), timeout=1)

    bridge.incoming.put_nowait(b"X" * 32)
    await bridge.send_cancelled.wait()
    await bridge.close_entered.wait()
    done, _ = await asyncio.wait({run}, timeout=0.2)
    finished_within_bound = run in done
    if not finished_within_bound:
        bridge.send_release.set()
        bridge.close_release.set()
        await asyncio.gather(run, return_exceptions=True)

    assert finished_within_bound
    assert run.result() is PttSessionOutcome.CLEANUP_INCOMPLETE
    assert bridge.output_fenced
    assert bridge.close_cancelled.is_set()
    assert supervisor._tasks  # noqa: SLF001 - live adapter work remains owned
    try:
        assert supervisor._guard_transaction is None  # noqa: SLF001 - speculative state discarded
        assert not any(isinstance(frame, PcmFrame) for frame in bridge.sent)
    finally:
        bridge.send_release.set()
        bridge.close_release.set()
        for _ in range(200):
            if not supervisor._tasks:  # noqa: SLF001
                break
            await asyncio.sleep(0)
    assert supervisor._tasks == set()  # noqa: SLF001 - released ownership contract
    assert supervisor._guard_transaction is None  # noqa: SLF001 - late completion cannot restore it
    assert not any(isinstance(frame, PcmFrame) for frame in bridge.sent)


@pytest.mark.asyncio
async def test_synchronous_pipeline_factory_failure_clears_the_unclaimed_capture() -> None:
    clock = _Clock()
    pipeline = _SynchronousFailingPipeline(clock)
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=pipeline,
        input_port=None,
    )

    outcome = await _bounded_outcome(asyncio.create_task(supervisor.run(TURN_ID)))

    assert outcome is PttSessionOutcome.PROVIDER_FAILED
    assert pipeline.captured is not None
    with pytest.raises(Exception, match="^captured-turn-unavailable$"):
        pipeline.captured.claim_pcm()


@pytest.mark.parametrize("tie", ["interrupt", "deadline"])
@pytest.mark.asyncio
async def test_provider_completion_tie_wipes_the_unclaimed_success_buffer_once(
    tie: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock()
    supervisor = _supervisor(
        mode=PttInputMode.REACHY_LOCAL,
        clock=clock,
        bridge=_Bridge(mode=PttInputMode.REACHY_LOCAL),
        pipeline=_Pipeline(clock),
        input_port=None,
    )
    supervisor._interrupt = asyncio.Event()  # noqa: SLF001 - deterministic tie probe
    supervisor._signal = supervisor_module._Signal.CLEANUP  # noqa: SLF001
    supervisor._requested_outcome = PttSessionOutcome.CANCELLED  # noqa: SLF001
    playback = bytearray(b"private-playback")

    async def complete() -> bytearray:
        return playback

    provider = asyncio.create_task(complete())
    await provider
    supervisor._provider_task = provider  # noqa: SLF001 - exact owned-result tie
    wipe_calls: list[int] = []
    real_wipe = supervisor_module._wipe  # noqa: SLF001 - exact cleanup-count probe

    def counting_wipe(buffer: bytearray) -> None:
        if buffer is playback:
            wipe_calls.append(len(buffer))
        real_wipe(buffer)

    monkeypatch.setattr(supervisor_module, "_wipe", counting_wipe)
    deadline = 5.0
    if tie == "interrupt":
        supervisor._interrupt.set()  # noqa: SLF001
    else:
        clock.current = deadline

    with pytest.raises(
        (deadline_module.DeadlineExceeded, supervisor_module._SessionFailure)  # noqa: SLF001
    ):
        await supervisor._wait_task(provider, deadline=deadline)  # noqa: SLF001

    supervisor._wipe_completed_provider_result(provider)  # noqa: SLF001 - finalizer replay
    assert playback == bytearray()
    assert wipe_calls == [16]
