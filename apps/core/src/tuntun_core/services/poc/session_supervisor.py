"""One-shot in-memory Core supervisor for the disposable Reachy PTT turn."""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Coroutine
from contextlib import suppress
from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from math import isfinite
from sys import exception as active_exception
from typing import Any, cast
from uuid import UUID
from weakref import WeakKeyDictionary

from tuntun_contracts.poc.framing import (
    MAX_DIRECTION_BYTES,
    MAX_FEED_BYTES,
    MAX_MEDIA_SAMPLES,
    MAX_TRANSPORT_PCM_FRAME_BYTES,
    TRANSPORT_AUDIO_FORMAT,
    ControlFrame,
    ControlKind,
    ErrorPayload,
    FrameDecoder,
    FrameProtocolError,
    GuardDisposition,
    PcmFrame,
    PttControl,
    PttDuplexGuard,
    PttErrorReason,
    PttInputMode,
    PttSessionOutcome,
    SafetyPayload,
    StreamDirection,
    WireFrame,
    encode_control_frame,
    encode_pcm_frame,
)
from tuntun_contracts.speech import SpeechChunk

from .deadlines import (
    DeadlineCleanupIncomplete,
    DeadlineClockError,
    DeadlineExceeded,
    DeadlineGuard,
    _capture,
    _detach_exception,
    _Outcome,
    masks_cleanup_incomplete,
)
from .ports import (
    CapturedTurn,
    CorePttEvent,
    CorePttInputPort,
    MonotonicClock,
    ProviderCancellationPort,
    PttBridgePort,
    PttSendCommit,
    VoiceTurnPort,
)

_HANDSHAKE_SECONDS = 5.0
_CAPTURE_TRANSITION_SECONDS = 2.0
_CAPTURE_SECONDS = 90.0
_PROVIDER_SECONDS = 120.0
_PLAYBACK_SECONDS = 90.0
_PLAYBACK_CONTENT_SAMPLES = 16_000 * 85
_TURN_SECONDS = 310.0
_HEARTBEAT_SECONDS = 1.0
_PROVIDER_CLOSE_SECONDS = 0.5
_PROVIDER_JOIN_SECONDS = 1.0
_CLEANUP_ACK_SECONDS = 3.5
_CLEANUP_TOTAL_SECONDS = 4.0
_BRIDGE_CLOSE_SECONDS = 3.0
_NORMAL_QUEUE_ITEMS = 64
_PRIORITY_QUEUE_ITEMS = 2
_TRANSACTION_INBOUND_ITEMS = 64


def _finite_absolute_deadline(
    deadline: object,
    *,
    fallback: float,
    max_seconds: float | None = None,
) -> float:
    if type(deadline) not in (int, float):
        return fallback
    typed_deadline = cast(int | float, deadline)
    try:
        value = float(typed_deadline)
    except (OverflowError, ValueError):
        return fallback
    if (
        not isfinite(value)
        or (type(deadline) is int and value != deadline)
        or (max_seconds is not None and value - fallback > max_seconds)
    ):
        return fallback
    return value


class CorePttSessionError(RuntimeError):
    """Content-free supervisor misuse or failure."""


class _AdmissionClosed(CorePttSessionError):
    def __init__(self) -> None:
        super().__init__("core-ptt-admission-closed")


class _Signal(StrEnum):
    NONE = "none"
    CLEANUP = "cleanup"
    PEER_CLOSED = "peer_closed"
    ADAPTER_FAILED = "adapter_failed"
    PROTOCOL_POISONED = "protocol_poisoned"
    WRITER_FAILED = "writer_failed"
    CLOCK_FAILED = "clock_failed"


@dataclass(slots=True)
class _SessionFailure(Exception):
    outcome: PttSessionOutcome
    reason: PttErrorReason
    poisoned: bool = False


@dataclass(slots=True)
class _Draft:
    control: PttControl | None
    pcm: bytes | None
    sent: asyncio.Future[None]
    priority: bool = False


@dataclass(slots=True)
class _GuardTransaction:
    before: PttDuplexGuard
    inbound: list[tuple[WireFrame, float]]
    pre_ack_inbound: PttDuplexGuard | None


class _OutboundLane:
    """Bounded FIFO media lane with cleanup priority and coalesced heartbeat."""

    def __init__(self, turn_id: UUID) -> None:
        self._turn_id = turn_id
        self._condition = asyncio.Condition()
        self._normal: deque[_Draft] = deque()
        self._priority: deque[_Draft] = deque()
        self._heartbeat_due = False
        self._admitting = True
        self._poisoned = False
        self._stopped = False

    @staticmethod
    def _reject(draft: _Draft) -> None:
        if not draft.sent.done():
            draft.sent.set_exception(_AdmissionClosed())
            draft.sent.exception()

    async def put_normal(self, draft: _Draft) -> None:
        async with self._condition:
            while (
                self._admitting and not self._stopped and len(self._normal) >= _NORMAL_QUEUE_ITEMS
            ):
                await self._condition.wait()
            if not self._admitting or self._stopped or self._poisoned:
                raise _AdmissionClosed
            self._normal.append(draft)
            self._condition.notify_all()

    async def put_priority(self, draft: _Draft) -> None:
        async with self._condition:
            while not self._stopped and len(self._priority) >= _PRIORITY_QUEUE_ITEMS:
                await self._condition.wait()
            if self._stopped or self._poisoned:
                raise _AdmissionClosed
            self._priority.append(draft)
            self._condition.notify_all()

    async def heartbeat_due(self) -> None:
        async with self._condition:
            if self._admitting and not self._stopped and not self._poisoned:
                self._heartbeat_due = True
                self._condition.notify_all()

    async def latch_cleanup(self, *, poisoned: bool) -> None:
        async with self._condition:
            self._admitting = False
            self._heartbeat_due = False
            while self._normal:
                self._reject(self._normal.popleft())
            if poisoned:
                self._poisoned = True
                while self._priority:
                    self._reject(self._priority.popleft())
            self._condition.notify_all()

    async def next(self) -> _Draft | None:
        async with self._condition:
            while True:
                if self._priority:
                    draft = self._priority.popleft()
                    self._condition.notify_all()
                    return draft
                if self._heartbeat_due and not self._poisoned:
                    self._heartbeat_due = False
                    return _Draft(
                        control=PttControl.heartbeat(self._turn_id),
                        pcm=None,
                        sent=asyncio.get_running_loop().create_future(),
                    )
                if self._normal:
                    draft = self._normal.popleft()
                    self._condition.notify_all()
                    return draft
                if self._stopped or self._poisoned:
                    return None
                await self._condition.wait()

    async def stop(self) -> None:
        async with self._condition:
            self._stopped = True
            self._admitting = False
            self._heartbeat_due = False
            while self._normal:
                self._reject(self._normal.popleft())
            while self._priority:
                self._reject(self._priority.popleft())
            self._condition.notify_all()


_OUTCOME_REASON = {
    PttSessionOutcome.CANCELLED: PttErrorReason.TURN_CANCELLED,
    PttSessionOutcome.CAPTURE_FAILED: PttErrorReason.CAPTURE_FAILED,
    PttSessionOutcome.PROVIDER_FAILED: PttErrorReason.PROVIDER_FAILED,
    PttSessionOutcome.PLAYBACK_FAILED: PttErrorReason.PLAYBACK_FAILED,
    PttSessionOutcome.PEER_CLOSED: PttErrorReason.PEER_CLOSED,
    PttSessionOutcome.PROTOCOL_REJECTED: PttErrorReason.PROTOCOL_REJECTED,
    PttSessionOutcome.SESSION_TIMEOUT: PttErrorReason.SESSION_TIMEOUT,
    PttSessionOutcome.CLEANUP_INCOMPLETE: PttErrorReason.CLEANUP_INCOMPLETE,
}

_REASON_OUTCOME = {reason: outcome for outcome, reason in _OUTCOME_REASON.items()}


def _wipe(buffer: bytearray) -> None:
    buffer[:] = b"\x00" * len(buffer)
    with suppress(BufferError):
        buffer.clear()


def _cancellation_requested() -> bool:
    task = asyncio.current_task()
    return task is not None and task.cancelling() > 0


def _is_scalar_fatal(error: BaseException) -> bool:
    return not isinstance(error, (Exception, asyncio.CancelledError, BaseExceptionGroup))


def _strict_speech_chunk(value: object) -> SpeechChunk | None:
    if type(value) is not SpeechChunk:
        return None
    try:
        dumped = value.model_dump(mode="python", warnings="error")
        validated = SpeechChunk.model_validate(dumped, strict=True)
    except Exception:
        return None
    if dumped != validated.model_dump(mode="python"):
        return None
    return validated


async def _close_iterator(iterator: object) -> None:
    closer = getattr(iterator, "aclose", None)
    if closer is not None:
        await closer()


class CorePttSessionSupervisor:
    """Own every task and mutable buffer for exactly one Core PTT session."""

    def __init__(
        self,
        *,
        input_mode: PttInputMode,
        input_port: CorePttInputPort | None,
        bridge: PttBridgePort,
        pipeline: VoiceTurnPort,
        provider_cancellation: ProviderCancellationPort,
        clock: MonotonicClock,
    ) -> None:
        terminal_input = input_mode is PttInputMode.CORE_TERMINAL_TOGGLE
        if (
            type(input_mode) is not PttInputMode
            or terminal_input is not (input_port is not None)
            or (input_port is not None and not isinstance(input_port, CorePttInputPort))
            or not isinstance(bridge, PttBridgePort)
            or not isinstance(pipeline, VoiceTurnPort)
            or not isinstance(provider_cancellation, ProviderCancellationPort)
            or not isinstance(clock, MonotonicClock)
            or pipeline.clock is not clock
        ):
            raise ValueError("invalid-core-ptt-supervisor")
        self._input_mode = input_mode
        self._input = input_port
        self._bridge = bridge
        self._pipeline = pipeline
        self._provider_cancellation = provider_cancellation
        self._deadlines = DeadlineGuard(clock)
        self._started = False
        self._bridge_closed = False
        self._bridge_close_complete = True
        self._bridge_close_task: asyncio.Task[_Outcome[None]] | None = None
        self._bridge_close_fatal: BaseException | None = None
        self._bridge_close_started_at: float | None = None
        self._bridge_close_deadline: float | None = None
        self._capture = bytearray()
        self._playback = bytearray()
        self._tasks: set[asyncio.Task[Any]] = set()
        self._completion_times: WeakKeyDictionary[asyncio.Future[Any], float | None] = (
            WeakKeyDictionary()
        )
        self._provider_task: asyncio.Task[_Outcome[bytearray]] | None = None
        self._provider_result_wiped = False
        self._late_provider_cleanup_registered = False
        self._child_fatal: BaseException | None = None
        self._child_failed = False
        self._accept_child_failures = True

    async def run(self, turn_id: UUID) -> PttSessionOutcome:
        if self._started:
            raise RuntimeError("core-ptt-session-already-run")
        self._started = True
        if type(turn_id) is not UUID:
            raise ValueError("invalid-core-ptt-turn")

        self._turn_id = turn_id
        self._lane = _OutboundLane(turn_id)
        self._guard = PttDuplexGuard(turn_id=turn_id, input_mode=self._input_mode)
        self._guard_transaction: _GuardTransaction | None = None
        self._guard_lock = asyncio.Lock()
        self._decoder = FrameDecoder()
        self._ready = asyncio.Event()
        self._capture_started = asyncio.Event()
        self._capture_ended = asyncio.Event()
        self._receipt = asyncio.Event()
        self._interrupt = asyncio.Event()
        self._signal = _Signal.NONE
        self._requested_outcome = PttSessionOutcome.CANCELLED
        self._cleanup_outcome_latched = False
        self._receipt_complete: bool | None = None
        self._capture_started_at: float | None = None
        self._cleanup_started = False
        self._normal_output_closed = asyncio.Event()
        self._all_output_closed = asyncio.Event()
        self._finalizing = asyncio.Event()
        self._final_ack_committed = asyncio.Event()
        cancelled: asyncio.CancelledError | None = None
        primary_fatal: BaseException | None = None
        teardown_fatal: BaseException | None = None
        outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
        try:
            total_deadline = self._deadlines.deadline_after(_TURN_SECONDS)
            self._spawn(self._writer(), "core-ptt-writer")
            self._spawn(self._reader(), "core-ptt-reader")
            self._spawn(self._heartbeat(), "core-ptt-heartbeat")
            outcome = await self._run_turn(total_deadline)
        except asyncio.CancelledError as error:
            if _cancellation_requested():
                cancelled = error
                outcome, cancelled = await self._cleanup_despite_cancellation(
                    _SessionFailure(
                        PttSessionOutcome.CANCELLED,
                        PttErrorReason.TURN_CANCELLED,
                    ),
                    first=cancelled,
                )
            else:
                outcome, cancelled = await self._cleanup_despite_cancellation(
                    _SessionFailure(
                        PttSessionOutcome.CLEANUP_INCOMPLETE,
                        PttErrorReason.CLEANUP_INCOMPLETE,
                    ),
                    first=cancelled,
                )
        except _SessionFailure as failure:
            outcome, cancelled = await self._cleanup_despite_cancellation(
                failure,
                first=cancelled,
            )
        except (DeadlineClockError, FrameProtocolError):
            outcome, cancelled = await self._cleanup_despite_cancellation(
                _SessionFailure(
                    PttSessionOutcome.PROTOCOL_REJECTED,
                    PttErrorReason.PROTOCOL_REJECTED,
                    poisoned=True,
                ),
                first=cancelled,
            )
        except BaseExceptionGroup:
            outcome, cancelled = await self._cleanup_despite_cancellation(
                _SessionFailure(
                    PttSessionOutcome.CLEANUP_INCOMPLETE,
                    PttErrorReason.CLEANUP_INCOMPLETE,
                ),
                first=cancelled,
            )
        except Exception:
            outcome, cancelled = await self._cleanup_despite_cancellation(
                _SessionFailure(
                    PttSessionOutcome.CLEANUP_INCOMPLETE,
                    PttErrorReason.CLEANUP_INCOMPLETE,
                ),
                first=cancelled,
            )
        except BaseException as error:
            primary_fatal = error
            try:
                outcome, cancelled = await self._cleanup_despite_cancellation(
                    _SessionFailure(
                        PttSessionOutcome.CLEANUP_INCOMPLETE,
                        PttErrorReason.CLEANUP_INCOMPLETE,
                    ),
                    first=cancelled,
                )
            except asyncio.CancelledError as cleanup_cancellation:
                if cancelled is None:
                    cancelled = cleanup_cancellation
            except BaseException as cleanup_error:
                _detach_exception(cleanup_error)
                outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
        finally:
            teardown_task = asyncio.create_task(
                _capture(self._teardown()),
                name="core-ptt-final-teardown",
            )
            teardown_outcome, cancelled = await self._finish_despite_cancellation(
                teardown_task,
                first=cancelled,
            )
            teardown_complete = teardown_outcome.value is True
            if teardown_outcome.error is not None:
                if _is_scalar_fatal(teardown_outcome.error):
                    teardown_fatal = teardown_outcome.error
                teardown_complete = False
            if not teardown_complete and cancelled is None:
                outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
        self._accept_child_failures = False
        bridge_close_task = self._bridge_close_task
        if bridge_close_task is not None and bridge_close_task.done():
            self._bridge_close_task = None
            if not bridge_close_task.cancelled():
                try:
                    bridge_close_outcome = bridge_close_task.result()
                except BaseException as bridge_close_error:
                    _detach_exception(bridge_close_error)
                else:
                    if bridge_close_outcome.error is not None:
                        _detach_exception(bridge_close_outcome.error)
        child_fatal = self._child_fatal
        self._child_fatal = None
        if cancelled is not None:
            for displaced in (primary_fatal, child_fatal, teardown_fatal):
                if displaced is not None:
                    _detach_exception(displaced)
            _detach_exception(cancelled)
            raise cancelled from None
        fatal = primary_fatal if primary_fatal is not None else child_fatal
        if fatal is None:
            fatal = teardown_fatal
        for displaced in (primary_fatal, child_fatal, teardown_fatal):
            if displaced is not None and displaced is not fatal:
                _detach_exception(displaced)
        if fatal is not None:
            _detach_exception(fatal)
            raise fatal from None
        return outcome

    async def _cleanup_despite_cancellation(
        self,
        failure: _SessionFailure,
        *,
        first: asyncio.CancelledError | None,
    ) -> tuple[PttSessionOutcome, asyncio.CancelledError | None]:
        cleanup_task = self._track(
            asyncio.create_task(
                self._cleanup(failure),
                name="core-ptt-session-cleanup",
            )
        )
        while not cleanup_task.done():
            try:
                await asyncio.shield(cleanup_task)
            except asyncio.CancelledError as error:
                if first is None:
                    first = error
            except BaseException as error:
                if first is None and _is_scalar_fatal(error):
                    self._record_child_failure(error)
                return PttSessionOutcome.CLEANUP_INCOMPLETE, first
        if cleanup_task.cancelled():
            return PttSessionOutcome.CLEANUP_INCOMPLETE, first
        try:
            return cleanup_task.result(), first
        except BaseException as error:
            if first is None and _is_scalar_fatal(error):
                self._record_child_failure(error)
            return PttSessionOutcome.CLEANUP_INCOMPLETE, first

    @staticmethod
    async def _finish_despite_cancellation[T](
        task: asyncio.Task[T],
        *,
        first: asyncio.CancelledError | None,
    ) -> tuple[T, asyncio.CancelledError | None]:
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError as error:
                if first is None:
                    first = error
        return task.result(), first

    def _spawn(
        self,
        coroutine: Coroutine[Any, Any, object],
        name: str,
    ) -> asyncio.Task[_Outcome[object]]:
        task: asyncio.Task[_Outcome[object]] = asyncio.create_task(
            _capture(coroutine),
            name=name,
        )
        return self._track(task, report_child=True)

    def _track[T](
        self,
        task: asyncio.Task[T],
        *,
        report_child: bool = False,
    ) -> asyncio.Task[T]:
        self._register_completion_time(task)
        self._tasks.add(task)

        def settled(completed: asyncio.Task[T]) -> None:
            self._tasks.discard(completed)
            if completed.cancelled():
                return
            try:
                result = completed.result()
            except asyncio.CancelledError:
                return
            except BaseException as error:
                if report_child:
                    self._record_child_failure(error)
                else:
                    _detach_exception(error)
                return
            if (
                report_child
                and isinstance(result, _Outcome)
                and result.error is not None
                and not isinstance(result.error, asyncio.CancelledError)
            ):
                self._record_child_failure(result.error)

        task.add_done_callback(settled)
        return task

    def _record_child_failure(self, error: BaseException) -> None:
        _detach_exception(error)
        if not self._accept_child_failures:
            return
        if _is_scalar_fatal(error):
            if self._child_fatal is None:
                self._child_fatal = error
        else:
            self._child_failed = True
        self._normal_output_closed.set()
        self._all_output_closed.set()
        self._interrupt.set()

    def _register_completion_time(self, task: asyncio.Future[Any]) -> None:
        if task in self._completion_times:
            return
        self._completion_times[task] = None
        loop = asyncio.get_running_loop()

        def record_completion(completed: asyncio.Future[Any]) -> None:
            self._completion_times[completed] = loop.time()

        task.add_done_callback(record_completion)

    async def _run_turn(self, total_deadline: float) -> PttSessionOutcome:
        handshake_deadline = min(
            self._deadlines.deadline_after(_HANDSHAKE_SECONDS),
            total_deadline,
        )
        try:
            await self._send_control(
                PttControl.session_open(self._turn_id, self._input_mode),
                deadline=handshake_deadline,
            )
            await self._wait_event(self._ready, deadline=handshake_deadline)
        except DeadlineExceeded:
            raise _SessionFailure(
                PttSessionOutcome.SESSION_TIMEOUT,
                PttErrorReason.SESSION_TIMEOUT,
            ) from None

        if self._input_mode is PttInputMode.CORE_TERMINAL_TOGGLE:
            await self._terminal_capture(total_deadline)
            self._spawn(self._monitor_terminal_cancel(), "core-ptt-input-monitor")
        else:
            await self._local_capture(total_deadline)

        capture = self._capture
        self._capture = bytearray()
        try:
            captured = CapturedTurn.take_ownership(
                turn_id=self._turn_id,
                audio_format=TRANSPORT_AUDIO_FORMAT,
                pcm=capture,
            )
        except Exception:
            _wipe(capture)
            raise _SessionFailure(
                PttSessionOutcome.CAPTURE_FAILED,
                PttErrorReason.CAPTURE_FAILED,
            ) from None

        provider_deadline = min(
            self._deadlines.deadline_after(_PROVIDER_SECONDS),
            total_deadline,
        )
        self._provider_task = asyncio.create_task(
            _capture(self._collect_playback(captured)),
            name="core-ptt-provider",
        )
        self._register_completion_time(self._provider_task)
        playback_claimed = False
        try:
            provider_outcome = await self._wait_task(
                self._provider_task,
                deadline=provider_deadline,
            )
            if provider_outcome.error is not None:
                raise provider_outcome.error
            if type(provider_outcome.value) is not bytearray:
                raise CorePttSessionError("provider-playback-rejected")
            playback = provider_outcome.value
            playback_claimed = True
        except DeadlineCleanupIncomplete:
            raise _SessionFailure(
                PttSessionOutcome.CLEANUP_INCOMPLETE,
                PttErrorReason.CLEANUP_INCOMPLETE,
            ) from None
        except DeadlineExceeded:
            raise _SessionFailure(
                PttSessionOutcome.PROVIDER_FAILED,
                PttErrorReason.PROVIDER_FAILED,
            ) from None
        except asyncio.CancelledError:
            if _cancellation_requested():
                raise
            raise _SessionFailure(
                PttSessionOutcome.PROVIDER_FAILED,
                PttErrorReason.PROVIDER_FAILED,
            ) from None
        except _SessionFailure:
            raise
        except BaseExceptionGroup as error:
            if masks_cleanup_incomplete(error):
                raise _SessionFailure(
                    PttSessionOutcome.CLEANUP_INCOMPLETE,
                    PttErrorReason.CLEANUP_INCOMPLETE,
                ) from None
            raise _SessionFailure(
                PttSessionOutcome.PROVIDER_FAILED,
                PttErrorReason.PROVIDER_FAILED,
            ) from None
        except Exception:
            raise _SessionFailure(
                PttSessionOutcome.PROVIDER_FAILED,
                PttErrorReason.PROVIDER_FAILED,
            ) from None
        finally:
            if self._provider_task is not None and self._provider_task.done():
                if not playback_claimed:
                    self._wipe_completed_provider_result(self._provider_task)
                self._provider_task = None
        self._playback = playback
        await self._play(playback, total_deadline)

        cleanup_deadline = min(
            self._deadlines.deadline_after(_CLEANUP_ACK_SECONDS),
            total_deadline,
        )
        try:
            await self._wait_event(self._receipt, deadline=cleanup_deadline)
            complete = self._receipt_complete is True
            await self._prepare_final_ack()
            await self._send_control(
                PttControl.safety_ack(self._turn_id, accepted=complete),
                priority=True,
                deadline=cleanup_deadline,
            )
        except (DeadlineExceeded, _AdmissionClosed):
            raise _SessionFailure(
                PttSessionOutcome.CLEANUP_INCOMPLETE,
                PttErrorReason.CLEANUP_INCOMPLETE,
            ) from None
        if self._receipt_complete is None:
            raise _SessionFailure(
                PttSessionOutcome.CLEANUP_INCOMPLETE,
                PttErrorReason.CLEANUP_INCOMPLETE,
            )
        try:
            return self._guard.finish()
        except FrameProtocolError:
            raise _SessionFailure(
                PttSessionOutcome.PROTOCOL_REJECTED,
                PttErrorReason.PROTOCOL_REJECTED,
                poisoned=True,
            ) from None

    async def _terminal_capture(self, total_deadline: float) -> None:
        first = await self._next_input(deadline=total_deadline)
        if first is CorePttEvent.CANCEL:
            raise _SessionFailure(PttSessionOutcome.CANCELLED, PttErrorReason.TURN_CANCELLED)
        if first is not CorePttEvent.START:
            raise _SessionFailure(
                PttSessionOutcome.CAPTURE_FAILED,
                PttErrorReason.CAPTURE_FAILED,
            )
        open_deadline = min(
            self._deadlines.deadline_after(_CAPTURE_TRANSITION_SECONDS),
            total_deadline,
        )
        try:
            await self._send_control(
                PttControl.ptt_start(self._turn_id),
                deadline=open_deadline,
            )
        except DeadlineExceeded:
            raise _SessionFailure(
                PttSessionOutcome.CAPTURE_FAILED,
                PttErrorReason.CAPTURE_FAILED,
            ) from None
        submitted = False
        close_deadline: float | None = None
        while not self._capture_started.is_set():
            event = await self._capture_or_input(deadline=open_deadline)
            if event is None:
                break
            if event is CorePttEvent.CANCEL:
                raise _SessionFailure(PttSessionOutcome.CANCELLED, PttErrorReason.TURN_CANCELLED)
            if event is not CorePttEvent.SUBMIT or submitted:
                raise _SessionFailure(
                    PttSessionOutcome.CAPTURE_FAILED,
                    PttErrorReason.CAPTURE_FAILED,
                )
            close_deadline = min(
                self._deadlines.deadline_after(_CAPTURE_TRANSITION_SECONDS),
                total_deadline,
            )
            try:
                await self._send_control(
                    PttControl.ptt_submit(self._turn_id),
                    deadline=close_deadline,
                )
            except DeadlineExceeded:
                raise _SessionFailure(
                    PttSessionOutcome.CAPTURE_FAILED,
                    PttErrorReason.CAPTURE_FAILED,
                ) from None
            submitted = True

        capture_deadline = self._capture_deadline(total_deadline)
        if not submitted:
            event = await self._next_input(deadline=capture_deadline)
            if event is CorePttEvent.CANCEL:
                raise _SessionFailure(PttSessionOutcome.CANCELLED, PttErrorReason.TURN_CANCELLED)
            if event is not CorePttEvent.SUBMIT:
                raise _SessionFailure(
                    PttSessionOutcome.CAPTURE_FAILED,
                    PttErrorReason.CAPTURE_FAILED,
                )
            close_deadline = min(
                self._deadlines.deadline_after(_CAPTURE_TRANSITION_SECONDS),
                capture_deadline,
            )
            try:
                await self._send_control(
                    PttControl.ptt_submit(self._turn_id),
                    deadline=close_deadline,
                )
            except DeadlineExceeded:
                raise _SessionFailure(
                    PttSessionOutcome.CAPTURE_FAILED,
                    PttErrorReason.CAPTURE_FAILED,
                ) from None
        if close_deadline is None:
            raise _SessionFailure(
                PttSessionOutcome.CAPTURE_FAILED,
                PttErrorReason.CAPTURE_FAILED,
            )
        try:
            await self._wait_event(self._capture_ended, deadline=close_deadline)
        except DeadlineExceeded:
            raise _SessionFailure(
                PttSessionOutcome.CAPTURE_FAILED,
                PttErrorReason.CAPTURE_FAILED,
            ) from None

    async def _local_capture(self, total_deadline: float) -> None:
        try:
            await self._wait_event(self._capture_started, deadline=total_deadline)
            capture_deadline = self._capture_deadline(total_deadline)
            await self._wait_event(self._capture_ended, deadline=capture_deadline)
        except DeadlineExceeded:
            raise _SessionFailure(
                PttSessionOutcome.CAPTURE_FAILED,
                PttErrorReason.CAPTURE_FAILED,
            ) from None

    def _capture_deadline(self, total_deadline: float) -> float:
        if self._capture_started_at is None:
            raise _SessionFailure(
                PttSessionOutcome.CAPTURE_FAILED,
                PttErrorReason.CAPTURE_FAILED,
            )
        return min(self._capture_started_at + _CAPTURE_SECONDS, total_deadline)

    async def _next_input(self, *, deadline: float) -> CorePttEvent:
        if self._input is None:
            raise _SessionFailure(
                PttSessionOutcome.CAPTURE_FAILED,
                PttErrorReason.CAPTURE_FAILED,
            )
        receive = asyncio.create_task(self._input.receive())
        try:
            result = await self._wait_task(receive, deadline=deadline)
        except DeadlineExceeded:
            raise _SessionFailure(
                PttSessionOutcome.SESSION_TIMEOUT,
                PttErrorReason.SESSION_TIMEOUT,
            ) from None
        except asyncio.CancelledError:
            if _cancellation_requested():
                raise
            raise _SessionFailure(
                PttSessionOutcome.CLEANUP_INCOMPLETE,
                PttErrorReason.CLEANUP_INCOMPLETE,
            ) from None
        finally:
            cleanup_complete = receive.done() or await self._deadlines.cancel_many(receive)
            if not cleanup_complete and not isinstance(
                active_exception(),
                asyncio.CancelledError,
            ):
                raise _SessionFailure(
                    PttSessionOutcome.CLEANUP_INCOMPLETE,
                    PttErrorReason.CLEANUP_INCOMPLETE,
                ) from None
        if type(result) is not CorePttEvent:
            raise _SessionFailure(
                PttSessionOutcome.CAPTURE_FAILED,
                PttErrorReason.CAPTURE_FAILED,
            )
        return result

    async def _monitor_terminal_cancel(self) -> None:
        if self._input is None:
            return
        try:
            event = await self._input.receive()
            if self._finalizing.is_set():
                return
            self._latch_requested_outcome(
                PttSessionOutcome.CANCELLED
                if event is CorePttEvent.CANCEL
                else PttSessionOutcome.CAPTURE_FAILED
            )
            self._set_signal(_Signal.CLEANUP)
        except asyncio.CancelledError:
            if _cancellation_requested():
                raise
            if self._finalizing.is_set():
                return
            self._set_signal(_Signal.ADAPTER_FAILED)
        except BaseExceptionGroup:
            if self._finalizing.is_set():
                return
            self._set_signal(_Signal.ADAPTER_FAILED)
        except Exception:
            if self._finalizing.is_set():
                return
            self._set_signal(_Signal.ADAPTER_FAILED)

    async def _capture_or_input(self, *, deadline: float) -> CorePttEvent | None:
        if self._input is None:
            return None
        capture: asyncio.Task[bool] | None = None
        user_input: asyncio.Task[CorePttEvent] | None = None
        try:
            capture = asyncio.create_task(self._capture_started.wait())
            user_input = asyncio.create_task(self._input.receive())

            async def race() -> CorePttEvent | None:
                if capture is None or user_input is None:
                    raise CorePttSessionError("invalid-capture-input-race")
                done, _ = await asyncio.wait(
                    {capture, user_input},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if user_input in done:
                    return user_input.result()
                return None

            return await self._wait_operation(race(), deadline=deadline)
        except DeadlineExceeded:
            raise _SessionFailure(
                PttSessionOutcome.CAPTURE_FAILED,
                PttErrorReason.CAPTURE_FAILED,
            ) from None
        finally:
            owned = tuple(task for task in (capture, user_input) if task is not None)
            cleanup_complete = not owned or await self._deadlines.cancel_many(*owned)
            if not cleanup_complete and not isinstance(
                active_exception(),
                asyncio.CancelledError,
            ):
                raise _SessionFailure(
                    PttSessionOutcome.CLEANUP_INCOMPLETE,
                    PttErrorReason.CLEANUP_INCOMPLETE,
                ) from None

    async def _collect_playback(self, captured: CapturedTurn) -> bytearray:
        operation = self._collect_playback_owned(captured)
        failure: BaseException | None = None
        try:
            return await operation
        except BaseException as error:
            failure = error
        del operation
        captured = cast(CapturedTurn, None)
        if isinstance(failure, DeadlineCleanupIncomplete):
            failure = None
            raise DeadlineCleanupIncomplete from None
        if failure is None:
            raise CorePttSessionError("provider-playback-rejected")
        _detach_exception(failure)
        raise failure from None

    async def _collect_playback_owned(self, captured: CapturedTurn) -> bytearray:
        stream: AsyncIterator[SpeechChunk] | None = None
        iterator: AsyncIterator[SpeechChunk] | None = None
        destination = bytearray()
        request_id: UUID | None = None
        sequence = 0
        final_seen = False
        body_failure: BaseException | None = None
        close_failures: list[BaseException] = []
        raw_candidate: object | None = None
        candidate: SpeechChunk | None = None
        try:
            stream = self._pipeline.run(captured)
            iterator = aiter(stream)
            while True:
                try:
                    raw_candidate = await anext(iterator)
                except StopAsyncIteration:
                    break
                candidate = _strict_speech_chunk(raw_candidate)
                if (
                    candidate is None
                    or final_seen
                    or candidate.sequence != sequence
                    or type(candidate.pcm) is not bytes
                ):
                    raise CorePttSessionError("provider-playback-rejected")
                if request_id is None:
                    request_id = candidate.request_id
                if candidate.request_id != request_id:
                    raise CorePttSessionError("provider-playback-rejected")
                sequence += 1
                if candidate.final:
                    if candidate.pcm:
                        raise CorePttSessionError("provider-playback-rejected")
                    final_seen = True
                    continue
                if (
                    not candidate.pcm
                    or len(candidate.pcm) > MAX_TRANSPORT_PCM_FRAME_BYTES
                    or len(candidate.pcm) % 2
                    or len(destination) + len(candidate.pcm) > MAX_DIRECTION_BYTES
                ):
                    raise CorePttSessionError("provider-playback-rejected")
                destination.extend(candidate.pcm)
                if (
                    len(destination) // 2 > MAX_MEDIA_SAMPLES
                    or len(destination) // 2 > _PLAYBACK_CONTENT_SAMPLES
                ):
                    raise CorePttSessionError("provider-playback-rejected")
                raw_candidate = None
                candidate = None
            if not final_seen or not destination:
                raise CorePttSessionError("provider-playback-rejected")
        except BaseException as error:
            body_failure = error
            _wipe(destination)
        finally:
            close_targets = (
                (iterator, stream)
                if iterator is not None and stream is not None and iterator is not stream
                else (iterator if iterator is not None else stream,)
            )
            for close_target in close_targets:
                if close_target is None:
                    continue
                try:
                    await _close_iterator(close_target)
                except BaseException as error:
                    close_failures.append(error)
            captured.clear()

        fatal_failure: BaseException | None = None
        failures = tuple(
            failure for failure in (body_failure, *close_failures) if failure is not None
        )
        for failure in failures:
            if _is_scalar_fatal(failure):
                fatal_failure = failure
                break
        if fatal_failure is not None:
            _wipe(destination)
            body_failure = None
            close_failures.clear()
            failures = ()
            raw_candidate = None
            candidate = None
            iterator = None
            stream = None
            _detach_exception(fatal_failure)
            raise fatal_failure from None
        if any(masks_cleanup_incomplete(failure) for failure in failures):
            _wipe(destination)
            body_failure = None
            close_failures.clear()
            failures = ()
            raw_candidate = None
            candidate = None
            iterator = None
            stream = None
            raise DeadlineCleanupIncomplete from None
        selected_failure = failures[0] if failures else None
        if selected_failure is not None:
            _wipe(destination)
            body_failure = None
            close_failures.clear()
            failures = ()
            raw_candidate = None
            candidate = None
            iterator = None
            stream = None
            _detach_exception(selected_failure)
            raise selected_failure from None
        return destination

    async def _play(self, playback: bytearray, total_deadline: float) -> None:
        playback_deadline = min(
            self._deadlines.deadline_after(_PLAYBACK_SECONDS),
            total_deadline,
        )
        try:
            await self._send_control(
                PttControl.playback_start(self._turn_id, TRANSPORT_AUDIO_FORMAT),
                deadline=playback_deadline,
            )
            pending: list[asyncio.Future[None]] = []
            for offset in range(0, len(playback), MAX_TRANSPORT_PCM_FRAME_BYTES):
                pending.append(
                    await self._queue_pcm(
                        bytes(playback[offset : offset + MAX_TRANSPORT_PCM_FRAME_BYTES]),
                        deadline=playback_deadline,
                    )
                )
            for sent in pending:
                await self._wait_operation(asyncio.shield(sent), deadline=playback_deadline)
            await self._send_control(
                PttControl.playback_end(self._turn_id),
                deadline=playback_deadline,
            )
        except DeadlineCleanupIncomplete:
            raise _SessionFailure(
                PttSessionOutcome.CLEANUP_INCOMPLETE,
                PttErrorReason.CLEANUP_INCOMPLETE,
            ) from None
        except _AdmissionClosed:
            if self._interrupt.is_set():
                self._raise_interrupt()
            raise _SessionFailure(
                PttSessionOutcome.PLAYBACK_FAILED,
                PttErrorReason.PLAYBACK_FAILED,
            ) from None
        except BaseExceptionGroup:
            raise _SessionFailure(
                PttSessionOutcome.CLEANUP_INCOMPLETE,
                PttErrorReason.CLEANUP_INCOMPLETE,
            ) from None
        except (DeadlineExceeded, Exception) as error:
            if isinstance(error, _SessionFailure):
                raise
            raise _SessionFailure(
                PttSessionOutcome.PLAYBACK_FAILED,
                PttErrorReason.PLAYBACK_FAILED,
            ) from None
        finally:
            _wipe(playback)
            self._playback = bytearray()

    async def _queue_pcm(self, pcm: bytes, *, deadline: float) -> asyncio.Future[None]:
        sent = asyncio.get_running_loop().create_future()
        await self._wait_operation(
            self._lane.put_normal(_Draft(control=None, pcm=pcm, sent=sent, priority=False)),
            deadline=deadline,
        )
        return sent

    async def _send_control(
        self,
        control: PttControl,
        *,
        priority: bool = False,
        deadline: float | None = None,
    ) -> None:
        sent = asyncio.get_running_loop().create_future()
        draft = _Draft(control=control, pcm=None, sent=sent, priority=priority)
        if priority:
            await self._lane.put_priority(draft)
        else:
            await self._lane.put_normal(draft)
        if deadline is None:
            await sent
        else:
            await self._wait_operation(asyncio.shield(sent), deadline=deadline)

    async def _wait_operation[T](self, operation: Awaitable[T], *, deadline: float) -> T:
        interrupt = asyncio.create_task(self._interrupt.wait())
        work = asyncio.ensure_future(operation)

        async def race() -> T:
            done, _ = await asyncio.wait({work, interrupt}, return_when=asyncio.FIRST_COMPLETED)
            if interrupt in done:
                self._raise_interrupt()
            return work.result()

        try:
            return await self._deadlines.run(race(), deadline=deadline)
        finally:
            cleanup_complete = await self._deadlines.cancel_many(work, interrupt)
            if not cleanup_complete and not isinstance(
                active_exception(),
                asyncio.CancelledError,
            ):
                raise DeadlineCleanupIncomplete

    async def _wait_event(self, event: asyncio.Event, *, deadline: float) -> None:
        await self._wait_operation(event.wait(), deadline=deadline)

    async def _wait_task[T](self, task: asyncio.Task[T], *, deadline: float) -> T:
        try:
            return await self._wait_operation(asyncio.shield(task), deadline=deadline)
        except BaseException:
            if task is self._provider_task:
                self._wipe_completed_provider_result(task)
            raise

    def _wipe_completed_provider_result[T](self, task: asyncio.Future[T]) -> None:
        if self._provider_result_wiped or not task.done() or task.cancelled():
            return
        try:
            result = task.result()
        except BaseException:
            return
        payload: object | None = result
        if isinstance(payload, _Outcome):
            if payload.error is not None:
                _detach_exception(payload.error)
                return
            payload = payload.value
        if type(payload) is bytearray:
            _wipe(payload)
            self._provider_result_wiped = True

    def _register_late_provider_cleanup(
        self,
        task: asyncio.Task[_Outcome[bytearray]],
    ) -> None:
        if self._late_provider_cleanup_registered:
            return
        self._late_provider_cleanup_registered = True

        def settled(done: asyncio.Future[_Outcome[bytearray]]) -> None:
            self._wipe_completed_provider_result(done)
            if self._provider_task is done:
                self._provider_task = None

        task.add_done_callback(settled)

    def _raise_interrupt(self) -> None:
        if self._child_fatal is not None:
            fatal = self._child_fatal
            self._child_fatal = None
            _detach_exception(fatal)
            raise fatal from None
        if self._child_failed:
            raise _SessionFailure(
                PttSessionOutcome.CLEANUP_INCOMPLETE,
                PttErrorReason.CLEANUP_INCOMPLETE,
            )
        if self._signal is _Signal.PROTOCOL_POISONED:
            raise _SessionFailure(
                PttSessionOutcome.PROTOCOL_REJECTED,
                PttErrorReason.PROTOCOL_REJECTED,
                poisoned=True,
            )
        if self._signal is _Signal.PEER_CLOSED:
            raise _SessionFailure(
                PttSessionOutcome.PEER_CLOSED,
                PttErrorReason.PEER_CLOSED,
            )
        if self._signal is _Signal.ADAPTER_FAILED:
            raise _SessionFailure(
                PttSessionOutcome.CLEANUP_INCOMPLETE,
                PttErrorReason.CLEANUP_INCOMPLETE,
            )
        if self._signal in {_Signal.WRITER_FAILED, _Signal.CLOCK_FAILED}:
            raise _SessionFailure(
                PttSessionOutcome.CLEANUP_INCOMPLETE,
                PttErrorReason.CLEANUP_INCOMPLETE,
                poisoned=self._signal is _Signal.CLOCK_FAILED,
            )
        raise _SessionFailure(
            self._requested_outcome,
            _OUTCOME_REASON.get(self._requested_outcome, PttErrorReason.CLEANUP_INCOMPLETE),
        )

    async def _writer(self) -> None:
        sequence = 0
        active: _Draft | None = None
        active_send: asyncio.Task[PttSendCommit] | None = None
        active_latch: asyncio.Task[bool] | None = None
        try:
            while True:
                draft = await self._lane.next()
                if draft is None:
                    return
                active = draft
                if not self._draft_allowed(draft):
                    self._lane._reject(draft)
                    active = None
                    continue
                if draft.control is not None:
                    frame: WireFrame = ControlFrame(
                        turn_id=self._turn_id,
                        sequence=sequence,
                        control=draft.control,
                    )
                    encoded = encode_control_frame(sequence=sequence, control=draft.control)
                elif draft.pcm is not None:
                    frame = PcmFrame(
                        turn_id=self._turn_id,
                        sequence=sequence,
                        pcm=draft.pcm,
                    )
                    encoded = encode_pcm_frame(
                        turn_id=self._turn_id,
                        sequence=sequence,
                        pcm=draft.pcm,
                    )
                else:
                    raise CorePttSessionError("invalid-outbound-draft")
                final_ack = (
                    draft.control is not None and draft.control.kind is ControlKind.SAFETY_ACK
                )
                async with self._guard_lock:
                    if not self._draft_allowed(draft):
                        self._lane._reject(draft)
                        active = None
                        continue
                    before = deepcopy(self._guard)
                    outbound_at = self._deadlines.now()
                    guarded = self._guard.accept(
                        StreamDirection.CORE_TO_EDGE,
                        frame,
                        now=outbound_at,
                    )
                    transaction = _GuardTransaction(
                        before=before,
                        inbound=[],
                        pre_ack_inbound=deepcopy(before) if final_ack else None,
                    )
                    self._guard_transaction = transaction
                if guarded.disposition is not GuardDisposition.ACCEPTED:
                    async with self._guard_lock:
                        if self._guard_transaction is transaction:
                            self._guard = transaction.before
                            self._guard_transaction = None
                    self._lane._reject(draft)
                    active = None
                    continue
                operation = self._bridge.send(encoded, priority=draft.priority)

                async def admit(
                    candidate: Awaitable[PttSendCommit] = operation,
                    is_final_ack: bool = final_ack,
                ) -> PttSendCommit:
                    resolution = await candidate
                    if (
                        is_final_ack
                        and type(resolution) is PttSendCommit
                        and resolution is PttSendCommit.COMMITTED
                    ):
                        self._final_ack_committed.set()
                    return resolution

                send_task = self._track(
                    asyncio.create_task(
                        admit(),
                        name="core-ptt-wire-send",
                    )
                )
                active_send = send_task
                output_latched = asyncio.create_task(
                    (
                        self._all_output_closed.wait()
                        if draft.priority
                        else self._normal_output_closed.wait()
                    ),
                    name="core-ptt-output-latch",
                )
                active_latch = output_latched
                try:
                    done, _ = await asyncio.wait(
                        {send_task, output_latched},
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    latched = output_latched in done
                    if (
                        latched
                        and not send_task.done()
                        and not await self._deadlines.cancel_many(send_task)
                    ):
                        self._lane._reject(draft)
                        self._set_signal(_Signal.WRITER_FAILED)
                        active = None
                        active_send = None
                        return
                    if send_task.cancelled():
                        resolution = PttSendCommit.UNCOMMITTED if latched else None
                    else:
                        try:
                            candidate = send_task.result()
                        except (asyncio.CancelledError, Exception):
                            resolution = None
                        else:
                            resolution = candidate if type(candidate) is PttSendCommit else None
                    active_send = None
                    if resolution is None or (
                        resolution is PttSendCommit.UNCOMMITTED and not latched
                    ):
                        self._lane._reject(draft)
                        self._set_signal(_Signal.WRITER_FAILED)
                        active = None
                        return
                    if resolution is PttSendCommit.UNCOMMITTED:
                        async with self._guard_lock:
                            if self._guard_transaction is not transaction:
                                raise CorePttSessionError("invalid-guard-transaction")
                            restored = transaction.pre_ack_inbound
                            if restored is None:
                                restored = transaction.before
                                for incoming, observed_at in transaction.inbound:
                                    restored.accept(
                                        StreamDirection.EDGE_TO_CORE,
                                        incoming,
                                        now=observed_at,
                                    )
                            self._guard = restored
                            self._guard_transaction = None
                        self._lane._reject(draft)
                        active = None
                        continue
                    async with self._guard_lock:
                        if self._guard_transaction is not transaction:
                            raise CorePttSessionError("invalid-guard-transaction")
                        if transaction.pre_ack_inbound is not None:
                            committed = transaction.pre_ack_inbound
                            committed_at = self._deadlines.now()
                            committed_ack = committed.accept(
                                StreamDirection.CORE_TO_EDGE,
                                frame,
                                now=committed_at,
                            )
                            if committed_ack.disposition is not GuardDisposition.ACCEPTED:
                                raise CorePttSessionError("invalid-final-ack-transaction")
                            self._guard = committed
                        self._guard_transaction = None
                    sequence += 1
                    if guarded.disposition is GuardDisposition.ACCEPTED:
                        if not draft.sent.done():
                            draft.sent.set_result(None)
                    else:
                        self._lane._reject(draft)
                    active = None
                finally:
                    await self._deadlines.cancel_many(output_latched)
                    active_latch = None
        except asyncio.CancelledError:
            if _cancellation_requested():
                raise
            if active is not None:
                self._lane._reject(active)
            self._set_signal(_Signal.WRITER_FAILED)
        except (FrameProtocolError, DeadlineClockError):
            if active is not None:
                self._lane._reject(active)
            self._set_signal(_Signal.CLOCK_FAILED)
        except BaseExceptionGroup:
            if active is not None:
                self._lane._reject(active)
            self._set_signal(_Signal.WRITER_FAILED)
        except Exception:
            if active is not None:
                self._lane._reject(active)
            self._set_signal(_Signal.WRITER_FAILED)
        finally:
            try:
                pending: list[asyncio.Future[Any]] = []
                if active_send is not None:
                    pending.append(active_send)
                if active_latch is not None:
                    pending.append(active_latch)
                if pending:
                    await self._deadlines.cancel_many(*pending)
            finally:
                await self._discard_guard_transaction()

    async def _discard_guard_transaction(self) -> None:
        async with self._guard_lock:
            transaction = self._guard_transaction
            self._guard_transaction = None
        if transaction is not None:
            transaction.inbound.clear()
            transaction.pre_ack_inbound = None

    def _draft_allowed(self, draft: _Draft) -> bool:
        return not self._all_output_closed.is_set() and (
            draft.priority or not self._normal_output_closed.is_set()
        )

    async def _reader(self) -> None:
        try:
            while True:
                chunk = await self._bridge.receive(MAX_FEED_BYTES)
                if type(chunk) is not bytes or len(chunk) > MAX_FEED_BYTES:
                    self._set_signal(_Signal.ADAPTER_FAILED)
                    return
                if not chunk:
                    try:
                        self._decoder.finish()
                    except FrameProtocolError:
                        self._set_signal(_Signal.PROTOCOL_POISONED)
                    else:
                        if self._final_ack_committed.is_set():
                            return
                        self._set_signal(_Signal.PEER_CLOSED)
                    return
                for frame in self._decoder.feed(chunk):
                    now = self._deadlines.now()
                    async with self._guard_lock:
                        transaction = self._guard_transaction
                        if (
                            transaction is not None
                            and len(transaction.inbound) >= _TRANSACTION_INBOUND_ITEMS
                        ):
                            raise CorePttSessionError("guard-transaction-overflow")
                        inbound_guard = (
                            transaction.pre_ack_inbound
                            if transaction is not None
                            and transaction.pre_ack_inbound is not None
                            and not self._final_ack_committed.is_set()
                            else self._guard
                        )
                        guarded = inbound_guard.accept(
                            StreamDirection.EDGE_TO_CORE,
                            frame,
                            now=now,
                        )
                        if transaction is not None:
                            transaction.inbound.append((frame, now))
                        if isinstance(frame, ControlFrame) and frame.control.kind in {
                            ControlKind.STOP,
                            ControlKind.CANCEL,
                            ControlKind.ERROR,
                        }:
                            self._normal_output_closed.set()
                    if guarded.disposition is GuardDisposition.ACCEPTED:
                        self._dispatch(frame, now=now)
        except asyncio.CancelledError:
            if _cancellation_requested():
                raise
            self._set_signal(_Signal.ADAPTER_FAILED)
        except (FrameProtocolError, DeadlineClockError):
            self._decoder.abort()
            self._set_signal(_Signal.PROTOCOL_POISONED)
        except BaseExceptionGroup:
            self._set_signal(_Signal.ADAPTER_FAILED)
        except Exception:
            self._set_signal(_Signal.ADAPTER_FAILED)

    def _dispatch(self, frame: WireFrame, *, now: float) -> None:
        if isinstance(frame, PcmFrame):
            self._capture.extend(frame.pcm)
            return
        kind = frame.control.kind
        if kind is ControlKind.SESSION_READY:
            self._ready.set()
        elif kind is ControlKind.CAPTURE_START:
            self._capture_started_at = now
            self._capture_started.set()
        elif kind is ControlKind.CAPTURE_END:
            self._capture_ended.set()
        elif kind is ControlKind.SAFETY_RECEIPT:
            safety_payload = cast(SafetyPayload, frame.control.payload)
            self._receipt_complete = safety_payload.receipt.is_complete()
            self._receipt.set()
        elif kind in {ControlKind.STOP, ControlKind.CANCEL}:
            self._latch_requested_outcome(PttSessionOutcome.CANCELLED)
            if not self._finalizing.is_set():
                self._set_signal(_Signal.CLEANUP)
        elif kind is ControlKind.ERROR:
            error_payload = cast(ErrorPayload, frame.control.payload)
            self._latch_requested_outcome(
                _REASON_OUTCOME.get(
                    error_payload.reason_code,
                    PttSessionOutcome.CLEANUP_INCOMPLETE,
                )
            )
            if not self._finalizing.is_set():
                self._set_signal(_Signal.CLEANUP)

    def _latch_requested_outcome(self, outcome: PttSessionOutcome) -> None:
        if not self._cleanup_outcome_latched:
            self._requested_outcome = outcome
            self._cleanup_outcome_latched = True

    async def _heartbeat(self) -> None:
        try:
            deadline = self._deadlines.deadline_after(_HEARTBEAT_SECONDS)
            while True:
                await self._deadlines.clock.sleep_until(deadline)
                if self._deadlines.now() < deadline:
                    raise DeadlineClockError
                await self._lane.heartbeat_due()
                observed = self._deadlines.now()
                missed = int((observed - deadline) // _HEARTBEAT_SECONDS) + 1
                deadline += max(1, missed) * _HEARTBEAT_SECONDS
        except asyncio.CancelledError:
            if _cancellation_requested():
                raise
            self._set_signal(_Signal.CLOCK_FAILED)
        except BaseExceptionGroup:
            self._set_signal(_Signal.CLOCK_FAILED)
        except Exception:
            self._set_signal(_Signal.CLOCK_FAILED)

    def _set_signal(self, signal: _Signal) -> None:
        self._normal_output_closed.set()
        hard_stop = signal in {
            _Signal.PEER_CLOSED,
            _Signal.ADAPTER_FAILED,
            _Signal.PROTOCOL_POISONED,
            _Signal.WRITER_FAILED,
            _Signal.CLOCK_FAILED,
        }
        if hard_stop:
            self._all_output_closed.set()
        if (
            self._signal is _Signal.NONE
            or signal is _Signal.PROTOCOL_POISONED
            or (self._signal is _Signal.CLEANUP and hard_stop)
        ):
            self._signal = signal
        self._spawn(
            self._lane.latch_cleanup(poisoned=hard_stop),
            "core-ptt-output-latch-cleanup",
        )
        self._interrupt.set()
        if hard_stop:
            self._begin_bridge_close_once()

    async def _cleanup(self, failure: _SessionFailure) -> PttSessionOutcome:
        if self._cleanup_started:
            return PttSessionOutcome.CLEANUP_INCOMPLETE
        self._cleanup_started = True
        loop = asyncio.get_running_loop()
        cleanup_t0 = loop.time()
        self._cleanup_loop_deadline = cleanup_t0 + _CLEANUP_TOTAL_SECONDS
        poisoned = failure.poisoned or self._signal is _Signal.PROTOCOL_POISONED
        transport_unusable = (
            self._signal
            in {
                _Signal.PEER_CLOSED,
                _Signal.ADAPTER_FAILED,
                _Signal.WRITER_FAILED,
            }
            or self._all_output_closed.is_set()
        )
        self._normal_output_closed.set()
        if poisoned or transport_unusable:
            self._all_output_closed.set()
        if self._provider_task is not None and not self._provider_task.done():
            self._provider_task.cancel()

        cleanup_complete = True
        provider_close_fatal: BaseException | None = None
        abort_sent: asyncio.Task[None] | None = None
        if not poisoned and not transport_unusable:
            abort_sent = self._track(
                asyncio.create_task(
                    self._send_control(
                        PttControl.abort(self._turn_id, failure.reason),
                        priority=True,
                    ),
                    name="core-ptt-abort-send",
                )
            )
        provider_close: asyncio.Task[None] | None = None
        try:
            provider_close_operation = self._provider_cancellation.close_active_transport(
                turn_id=self._turn_id
            )

            async def finish_provider_close(
                candidate: Awaitable[None] = provider_close_operation,
            ) -> None:
                await candidate

            provider_close = self._track(
                asyncio.create_task(
                    finish_provider_close(),
                    name="core-ptt-provider-close",
                )
            )
        except BaseException as error:
            cleanup_complete = False
            if _is_scalar_fatal(error):
                provider_close_fatal = error
            else:
                _detach_exception(error)
        await self._lane.latch_cleanup(poisoned=poisoned)

        if provider_close is not None:
            try:
                if not await self._observe_task_until(
                    provider_close,
                    deadline=cleanup_t0 + _PROVIDER_CLOSE_SECONDS,
                    cancelled_ok=False,
                ):
                    cleanup_complete = False
            except BaseException as error:
                cleanup_complete = False
                if provider_close_fatal is None and _is_scalar_fatal(error):
                    provider_close_fatal = error
                else:
                    _detach_exception(error)
        if abort_sent is not None and not await self._observe_task_until(
            abort_sent,
            deadline=cleanup_t0 + _CLEANUP_ACK_SECONDS,
            cancelled_ok=False,
        ):
            cleanup_complete = False

        if self._provider_task is not None and not await self._observe_task_until(
            self._provider_task,
            deadline=cleanup_t0 + _PROVIDER_JOIN_SECONDS,
            cancelled_ok=True,
        ):
            cleanup_complete = False

        if poisoned or transport_unusable:
            await self._close_bridge_once(deadline=None)
            if provider_close_fatal is not None:
                fatal = provider_close_fatal
                provider_close_fatal = None
                _detach_exception(fatal)
                raise fatal from None
            return PttSessionOutcome.CLEANUP_INCOMPLETE

        ack_deadline = cleanup_t0 + _CLEANUP_ACK_SECONDS
        try:
            remaining = ack_deadline - loop.time()
            if remaining <= 0:
                raise TimeoutError
            await asyncio.wait_for(self._receipt.wait(), timeout=remaining)
            accepted = self._receipt_complete is True
            await self._prepare_final_ack()
            ack_sent = self._track(
                asyncio.create_task(
                    self._send_control(
                        PttControl.safety_ack(self._turn_id, accepted=accepted),
                        priority=True,
                    ),
                    name="core-ptt-ack-send",
                )
            )
            if not await self._observe_task_until(
                ack_sent,
                deadline=ack_deadline,
                cancelled_ok=False,
            ):
                raise TimeoutError
            cleanup_complete = cleanup_complete and accepted
        except Exception:
            cleanup_complete = False

        if provider_close_fatal is not None:
            fatal = provider_close_fatal
            provider_close_fatal = None
            _detach_exception(fatal)
            raise fatal from None
        if not cleanup_complete:
            return PttSessionOutcome.CLEANUP_INCOMPLETE
        try:
            return self._guard.finish()
        except FrameProtocolError:
            return PttSessionOutcome.CLEANUP_INCOMPLETE

    async def _prepare_final_ack(self) -> None:
        """Fence non-final output and terminal input before the one final ACK."""

        self._finalizing.set()
        self._normal_output_closed.set()
        await self._lane.latch_cleanup(poisoned=False)

    async def _observe_task_until[T](
        self,
        task: asyncio.Task[T],
        *,
        deadline: float,
        cancelled_ok: bool,
    ) -> bool:
        self._register_completion_time(task)
        remaining = max(0.0, deadline - asyncio.get_running_loop().time())
        if not task.done():
            done, _ = await asyncio.wait({task}, timeout=remaining)
            if task not in done:
                task.cancel()
                await asyncio.sleep(0)
                if task.done() and not task.cancelled():
                    with suppress(BaseException):
                        task.result()
                return False
        await asyncio.sleep(0)
        completed_at = self._completion_times.get(task)
        completed_in_time = completed_at is not None and completed_at < deadline
        if task.cancelled():
            return cancelled_ok and completed_in_time
        try:
            result = task.result()
        except asyncio.CancelledError:
            return cancelled_ok and completed_in_time
        except BaseException as error:
            if _is_scalar_fatal(error):
                raise
            return False
        if isinstance(result, _Outcome) and result.error is not None:
            if isinstance(result.error, asyncio.CancelledError):
                return cancelled_ok and completed_in_time
            if _is_scalar_fatal(result.error):
                raise result.error
            return False
        return completed_in_time

    @staticmethod
    def _task_value[T](task: asyncio.Task[_Outcome[T]]) -> T | None:
        outcome = task.result()
        if outcome.error is not None:
            raise outcome.error
        return outcome.value

    async def _close_bridge_once(self, *, deadline: float | None) -> bool:
        close_task = self._begin_bridge_close_once()
        if close_task is None:
            if self._bridge_close_fatal is not None:
                fatal = self._bridge_close_fatal
                self._bridge_close_fatal = None
                _detach_exception(fatal)
                raise fatal from None
            return self._bridge_close_complete
        close_deadline = self._bridge_close_deadline
        if close_deadline is None:
            self._bridge_close_complete = False
            return False
        if deadline is not None:
            close_deadline = min(close_deadline, deadline)
        try:
            self._bridge_close_complete = await self._observe_task_until(
                close_task,
                deadline=close_deadline,
                cancelled_ok=False,
            )
        except asyncio.CancelledError:
            close_task.cancel()
            raise
        except BaseException:
            self._bridge_close_complete = False
            raise
        finally:
            if close_task.done() and self._bridge_close_task is close_task:
                self._bridge_close_task = None
        return self._bridge_close_complete

    def _begin_bridge_close_once(self) -> asyncio.Task[_Outcome[None]] | None:
        if self._bridge_closed:
            return self._bridge_close_task
        self._bridge_closed = True
        loop = asyncio.get_running_loop()
        self._bridge_close_started_at = loop.time()
        self._bridge_close_deadline = self._bridge_close_started_at + _BRIDGE_CLOSE_SECONDS
        try:
            close_operation = self._bridge.close()

            async def finish_close(
                candidate: Awaitable[None] = close_operation,
            ) -> None:
                await candidate

            close_task: asyncio.Task[_Outcome[None]] = self._track(
                asyncio.create_task(
                    _capture(finish_close()),
                    name="core-ptt-bridge-close",
                )
            )
        except BaseException as error:
            self._bridge_close_complete = False
            if _is_scalar_fatal(error):
                self._bridge_close_fatal = error
            else:
                _detach_exception(error)
            return None
        self._bridge_close_task = close_task

        def release_late_close(completed: asyncio.Task[_Outcome[None]]) -> None:
            if self._accept_child_failures or self._bridge_close_task is not completed:
                return
            self._bridge_close_task = None
            if completed.cancelled():
                return
            try:
                outcome = completed.result()
            except BaseException as error:
                _detach_exception(error)
                return
            if outcome.error is not None:
                _detach_exception(outcome.error)

        close_task.add_done_callback(release_late_close)
        return close_task

    async def _teardown(self) -> bool:
        _wipe(self._capture)
        _wipe(self._playback)
        self._begin_bridge_close_once()
        await self._discard_guard_transaction()
        bridge_close = asyncio.create_task(
            _capture(self._close_bridge_once(deadline=None)),
            name="core-ptt-bridge-close-once",
        )
        await self._lane.stop()
        loop = asyncio.get_running_loop()
        deadline = getattr(
            self,
            "_cleanup_loop_deadline",
            loop.time() + _CLEANUP_TOTAL_SECONDS,
        )
        deadline = _finite_absolute_deadline(
            deadline,
            fallback=loop.time(),
            max_seconds=_CLEANUP_TOTAL_SECONDS,
        )
        self._cleanup_loop_deadline = deadline
        current = asyncio.current_task()
        owned = [
            task
            for task in self._tasks
            if task is not current and task is not self._bridge_close_task
        ]
        if self._provider_task is not None:
            owned.append(cast(asyncio.Task[object], self._provider_task))
        for task in owned:
            if not task.done():
                task.cancel()

        close_complete = True
        fatal_error: BaseException | None = None

        def record_teardown_error(error: BaseException) -> None:
            nonlocal close_complete, fatal_error
            close_complete = False
            if fatal_error is None and _is_scalar_fatal(error):
                fatal_error = error

        async def observe(task: asyncio.Task[Any]) -> bool:
            try:
                return await self._observe_task_until(
                    task,
                    deadline=deadline,
                    cancelled_ok=False,
                )
            except BaseException as error:
                record_teardown_error(error)
                return False

        input_close: asyncio.Task[_Outcome[None]] | None = None
        if self._input is not None:
            try:
                input_close_operation = self._input.close()

                async def finish_input_close(
                    candidate: Awaitable[None] = input_close_operation,
                ) -> None:
                    await candidate

                input_close = self._track(
                    asyncio.create_task(
                        _capture(finish_input_close()),
                        name="core-ptt-input-close",
                    )
                )
            except BaseException as error:
                record_teardown_error(error)

        pipeline_cleanup_complete = False
        pipeline_cleanup: asyncio.Task[_Outcome[bool]] | None = None
        try:
            pipeline_cleanup_operation = self._pipeline.observe_quarantine(deadline=deadline)

            async def finish_pipeline_cleanup(
                candidate: Awaitable[bool] = pipeline_cleanup_operation,
            ) -> bool:
                return await candidate

            pipeline_cleanup = self._track(
                asyncio.create_task(
                    _capture(finish_pipeline_cleanup()),
                    name="core-ptt-pipeline-quarantine",
                )
            )
        except BaseException as error:
            record_teardown_error(error)

        deadline_cleanup = self._track(
            asyncio.create_task(
                _capture(self._deadlines.observe_quarantine(deadline=deadline)),
                name="core-ptt-deadline-quarantine",
            )
        )

        if owned:
            remaining = max(0.0, deadline - loop.time())
            await asyncio.wait(owned, timeout=remaining)
            await asyncio.sleep(0)
        runtime_live = {task for task in owned if not task.done()}

        if input_close is not None and not await observe(input_close):
            close_complete = False
        if pipeline_cleanup is not None and await observe(pipeline_cleanup):
            try:
                pipeline_cleanup_complete = self._task_value(pipeline_cleanup) is True
            except BaseException as error:
                record_teardown_error(error)

        deadline_cleanup_complete = False
        if await observe(deadline_cleanup):
            try:
                deadline_cleanup_complete = self._task_value(deadline_cleanup) is True
            except BaseException as error:
                record_teardown_error(error)
        try:
            bridge_outcome = await bridge_close
            if bridge_outcome.error is not None:
                raise bridge_outcome.error
            if bridge_outcome.value is not True:
                close_complete = False
        except BaseException as error:
            record_teardown_error(error)
        live = {task for task in self._tasks if not task.done()}
        self._tasks.intersection_update(live)
        if self._provider_task is not None and self._provider_task.done():
            self._wipe_completed_provider_result(self._provider_task)
            self._provider_task = None
        elif self._provider_task is not None:
            self._register_late_provider_cleanup(self._provider_task)
        self._decoder.abort()
        if fatal_error is not None:
            _detach_exception(fatal_error)
            raise fatal_error from None
        return (
            close_complete
            and pipeline_cleanup_complete
            and deadline_cleanup_complete
            and not runtime_live
            and not live
            and self._provider_task is None
        )
