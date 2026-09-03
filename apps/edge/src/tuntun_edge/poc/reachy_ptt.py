"""Robot-local supervisor for one disposable Reachy push-to-talk turn."""

from __future__ import annotations

import asyncio
import math
from collections import deque
from collections.abc import Callable, Coroutine
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, TypeVar
from uuid import UUID

from tuntun_contracts.poc.framing import (
    MAX_FEED_BYTES,
    MAX_PCM_BYTES,
    MAX_TRANSPORT_PCM_FRAME_BYTES,
    TRANSPORT_AUDIO_FORMAT,
    AckPayload,
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
    StreamDirection,
    WireFrame,
    encode_control_frame,
    encode_pcm_frame,
)

from tuntun_edge.poc.ports import (
    CleanupTaskSpawner,
    EdgeCaptureInputPort,
    EdgeStopInputPort,
    EdgeTransportPort,
    MonotonicClock,
    MutableAudioBuffer,
    ReachyLocalMediaPort,
)

_T = TypeVar("_T")
_NORMAL_QUEUE_ITEMS = 64
_SEND_SECONDS = 0.5
_HANDSHAKE_SECONDS = 5.0
_CAPTURE_OPERATION_SECONDS = 2.0
_CAPTURE_SECONDS = 90.0
_PLAYBACK_SECONDS = 90.0
_TURN_SECONDS = 310.0
_CLEANUP_OBSERVATION_SECONDS = 2.0
_RECEIPT_SEND_SECONDS = 2.5
_ACK_SECONDS = 3.5
_TEARDOWN_SECONDS = 4.0


@dataclass(slots=True)
class _OutboundDraft:
    completion: asyncio.Future[None]
    control: PttControl | None = None
    pcm: bytes | None = None
    bypass_guard: bool = False
    absolute_deadline: float | None = None


@dataclass(slots=True)
class _PlaybackDraft:
    kind: ControlKind
    pcm: bytes | None = None


class ReachyPttSession:
    """Own one immutable, supervised Edge push-to-talk turn."""

    def __init__(
        self,
        *,
        turn_id: UUID,
        input_mode: PttInputMode,
        media: ReachyLocalMediaPort,
        transport: EdgeTransportPort,
        capture_input: EdgeCaptureInputPort | None,
        stop_input: EdgeStopInputPort | None,
        capture_buffer: MutableAudioBuffer,
        playback_buffer: MutableAudioBuffer,
        clock: MonotonicClock,
        task_spawner: CleanupTaskSpawner,
    ) -> None:
        if input_mode is PttInputMode.REACHY_LOCAL:
            if capture_input is None or stop_input is None:
                raise ValueError("invalid PTT input ownership")
        elif input_mode is PttInputMode.CORE_TERMINAL_TOGGLE:
            if capture_input is not None:
                raise ValueError("invalid PTT input ownership")
        else:
            raise ValueError("invalid PTT input mode")
        if capture_buffer is playback_buffer:
            raise ValueError("owned audio buffers must be distinct")

        self._turn_id = turn_id
        self._input_mode = input_mode
        self._media = media
        self._transport = transport
        self._capture_input = capture_input
        self._stop_input = stop_input
        self._capture_buffer = capture_buffer
        self._playback_buffer = playback_buffer
        self._clock = clock
        self._task_spawner = task_spawner
        self._lifecycle_lock = asyncio.Lock()
        self._writer_lock = asyncio.Lock()
        self._guard_lock = asyncio.Lock()
        self._run_claimed = False
        self._terminal = False
        self._cleanup_task: asyncio.Future[PttSafetyReceipt] | None = None
        self._cleanup_started_at: float | None = None
        self._clear_result = False
        self._cleanup_requested = asyncio.Event()
        self._cleanup_source: PttStopSource | None = None
        self._semantic_outcome = PttSessionOutcome.COMPLETED
        self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
        self._guard: PttDuplexGuard | None = None
        self._decoder: FrameDecoder | None = None
        self._guard_poisoned = False
        self._protocol_poisoned = asyncio.Event()
        self._poison_suppress_output = False
        self._normal_queue: asyncio.Queue[_OutboundDraft] = asyncio.Queue()
        self._normal_slots = asyncio.Semaphore(_NORMAL_QUEUE_ITEMS)
        self._blocked_normal_producers = 0
        self._terminal_queue: deque[_OutboundDraft] = deque(maxlen=2)
        self._terminal_drafts: list[_OutboundDraft] = []
        self._writer_wakeup = asyncio.Event()
        self._writer_stopping = False
        self._transport_writable = True
        self._active_send = False
        self._edge_sequence = 0
        self._receipt_attempted = False
        self._session_open = asyncio.Event()
        self._session_open_accepted_before_cleanup = False
        self._ptt_started = asyncio.Event()
        self._ptt_submitted = asyncio.Event()
        self._ptt_started_at: float | None = None
        self._ptt_submitted_at: float | None = None
        self._capture_started_at: float | None = None
        self._playback_started_at: float | None = None
        self._ack_received = asyncio.Event()
        self._ack_accepted: bool | None = None
        self._capture_gate = False
        self._playback_gate = False
        self._playback_deadline: float | None = None
        self._playback_queue: asyncio.Queue[_PlaybackDraft] = asyncio.Queue(
            maxsize=_NORMAL_QUEUE_ITEMS
        )
        self._run_started_at: float | None = None
        self._last_valid_core_frame: float | None = None
        self._last_clock_value: float | None = None
        self._clock_faulted = False
        self._last_clock_loop_time: float | None = None
        self._clock_fault_generation = 0
        self._clock_fault_event = asyncio.Event()
        self._clock_sensitive_tasks: set[asyncio.Task[Any]] = set()
        self._last_accepted_core_frame: tuple[int, float] | None = None
        self._dispatch_triggered_at: float | None = None
        self._reader_task: asyncio.Task[None] | None = None
        self._writer_task: asyncio.Task[None] | None = None
        self._playback_task: asyncio.Task[None] | None = None
        self._stop_input_task: asyncio.Task[None] | None = None
        self._turn_task: asyncio.Task[None] | None = None
        self._effect_join_task: asyncio.Task[bool] | None = None
        self._heartbeat_task: asyncio.Task[None] | None = None
        self._turn_watchdog_task: asyncio.Task[None] | None = None

    @property
    def input_mode(self) -> PttInputMode:
        return self._input_mode

    def _fail_clock_closed(self) -> float:
        fallback = self._last_clock_value
        if fallback is None:
            fallback = self._run_started_at
        if fallback is None or not math.isfinite(fallback):
            fallback = 0.0
        self._last_clock_value = fallback
        if self._last_clock_loop_time is None:
            with suppress(RuntimeError):
                self._last_clock_loop_time = asyncio.get_running_loop().time()
        self._clock_faulted = True
        self._clock_fault_generation += 1
        self._clock_fault_event.set()
        current_task: asyncio.Task[Any] | None = None
        with suppress(RuntimeError):
            current_task = asyncio.current_task()
        if (
            self._reader_task is not None
            and self._reader_task is not current_task
            and not self._reader_task.done()
        ):
            self._reader_task.cancel()
        for task in tuple(self._clock_sensitive_tasks):
            if not task.done():
                task.cancel()
        if self._cleanup_started_at is None:
            self._latch_cleanup_locked(
                PttStopSource.WATCHDOG,
                PttSessionOutcome.CLEANUP_INCOMPLETE,
                triggered_at=fallback,
            )
        self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
        self._transport_writable = False
        self._writer_stopping = True
        self._wake_blocked_normal_producers_locked()
        self._fail_queued_drafts_locked()
        self._writer_wakeup.set()
        return fallback

    def _clock_now(self) -> float:
        if self._clock_faulted:
            assert self._last_clock_value is not None
            return self._last_clock_value
        try:
            raw_value = self._clock.now()
        except BaseException:
            return self._fail_clock_closed()
        if type(raw_value) not in {int, float}:
            return self._fail_clock_closed()
        try:
            value = float(raw_value)
        except BaseException:
            return self._fail_clock_closed()
        if type(raw_value) is int and int(value) != raw_value:
            return self._fail_clock_closed()
        if not math.isfinite(value):
            return self._fail_clock_closed()
        previous = self._last_clock_value
        if previous is not None and value < previous:
            return self._fail_clock_closed()
        if self._last_clock_loop_time is None or previous is None or value > previous:
            with suppress(RuntimeError):
                self._last_clock_loop_time = asyncio.get_running_loop().time()
        self._last_clock_value = value
        return value

    async def _sleep_to_post_fault_cleanup_deadline(self, deadline: float) -> None:
        loop = asyncio.get_running_loop()
        loop_anchor = self._last_clock_loop_time
        if loop_anchor is None:
            loop_anchor = loop.time()
            self._last_clock_loop_time = loop_anchor
        assert self._last_clock_value is not None
        loop_deadline = loop_anchor + max(0.0, deadline - self._last_clock_value)
        await asyncio.sleep(max(0.0, loop_deadline - loop.time()))

    def _validate_clock_sleeper_completion(
        self,
        task: asyncio.Task[Any],
        deadline: float,
        *,
        allow_post_fault_cleanup: bool = False,
    ) -> None:
        try:
            task.result()
        except asyncio.CancelledError:
            if not self._clock_faulted:
                self._fail_clock_closed()
            raise RuntimeError("clock sleeper cancelled itself") from None
        except BaseException:
            if not self._clock_faulted:
                self._fail_clock_closed()
            raise
        current = self._clock_now()
        if allow_post_fault_cleanup and self._clock_faulted:
            return
        if current < deadline:
            self._fail_clock_closed()
            raise RuntimeError("clock sleeper returned before its deadline")

    async def _sleep_until_deadline(self, deadline: float, *, cleanup_only: bool) -> None:
        if not cleanup_only:
            await self._clock.sleep_until(deadline)
            return
        if self._clock_faulted:
            await self._sleep_to_post_fault_cleanup_deadline(deadline)
            return
        sleeper_task = self._create_runtime_task(
            self._clock.sleep_until(deadline),
            name="reachy-ptt-cleanup-clock-sleeper",
        )
        fault_task = await self._create_followup_task(
            self._clock_fault_event.wait(),
            name="reachy-ptt-cleanup-clock-fault",
            adopted=(sleeper_task,),
        )
        try:
            done, _pending = await asyncio.wait(
                (sleeper_task, fault_task),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if self._clock_faulted or fault_task in done:
                if not sleeper_task.done():
                    sleeper_task.cancel()
                await asyncio.gather(sleeper_task, return_exceptions=True)
                await self._sleep_to_post_fault_cleanup_deadline(deadline)
                return
            try:
                self._validate_clock_sleeper_completion(sleeper_task, deadline)
            except BaseException:
                if not self._clock_faulted:
                    raise
                await self._sleep_to_post_fault_cleanup_deadline(deadline)
        finally:
            for task in (sleeper_task, fault_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(sleeper_task, fault_task, return_exceptions=True)

    @staticmethod
    def _create_runtime_task(operation: Coroutine[Any, Any, _T], *, name: str) -> asyncio.Task[_T]:
        try:
            return asyncio.create_task(operation, name=name)
        except BaseException:
            operation.close()
            raise

    @staticmethod
    def _create_adopted_loop_task(
        operation: Coroutine[Any, Any, _T], *, name: str
    ) -> asyncio.Task[_T]:
        try:
            return asyncio.get_running_loop().create_task(operation, name=name)
        except BaseException:
            operation.close()
            raise

    @staticmethod
    def _create_direct_task(operation: Coroutine[Any, Any, _T], *, name: str) -> asyncio.Task[_T]:
        try:
            return asyncio.Task(operation, name=name)
        except BaseException:
            operation.close()
            raise

    async def _create_followup_task(
        self,
        operation: Coroutine[Any, Any, _T],
        *,
        name: str,
        adopted: tuple[asyncio.Task[Any], ...],
    ) -> asyncio.Task[_T]:
        try:
            return self._create_runtime_task(operation, name=name)
        except BaseException:
            for task in adopted:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*adopted, return_exceptions=True)
            raise

    def _clear_owned_buffers(self) -> bool:
        cleared = True
        for buffer in (self._capture_buffer, self._playback_buffer):
            try:
                observed = buffer.clear()
                empty = buffer.is_empty()
            except BaseException:
                cleared = False
            else:
                cleared = cleared and observed is True and empty is True
        return cleared

    def _start_cleanup_observation(
        self,
        name: str,
        operation_factory: Callable[[], Coroutine[Any, Any, bool]],
    ) -> asyncio.Task[bool] | None:
        try:
            operation = operation_factory()
        except BaseException:
            return None
        try:
            return self._task_spawner.start(operation, name=name)
        except BaseException:
            operation.close()
        try:
            fallback = operation_factory()
        except BaseException:
            return None
        try:
            return asyncio.create_task(fallback, name=name)
        except BaseException:
            fallback.close()
            return None

    async def _observe_local_cleanup(self) -> PttSafetyReceipt:
        operations: tuple[tuple[str, Callable[[], Coroutine[Any, Any, bool]]], ...] = (
            ("recording", self._media.stop_recording),
            ("playback", self._media.stop_playback),
            ("motion", self._media.stop_motion),
            ("audio_reactive", self._media.disable_audio_reactive),
        )
        positive_by_name = {name: False for name, _operation in operations}
        cleanup_started_at = self._cleanup_started_at
        if cleanup_started_at is None:
            raise RuntimeError("cleanup deadline is absent")
        deadline = cleanup_started_at + _CLEANUP_OBSERVATION_SECONDS
        if self._clock_now() >= deadline:
            return self._build_cleanup_receipt(positive_by_name)
        tasks: dict[str, asyncio.Task[bool]] = {}
        for name, operation in operations:
            if self._clock_now() >= deadline:
                break
            observation_task = self._start_cleanup_observation(name, operation)
            if observation_task is not None:
                tasks[name] = observation_task
        if not tasks:
            return self._build_cleanup_receipt(positive_by_name)
        try:
            deadline_task = self._create_runtime_task(
                self._sleep_until_deadline(deadline, cleanup_only=True),
                name="reachy-ptt-cleanup-deadline",
            )
        except BaseException:
            try:
                deadline_task = self._create_runtime_task(
                    self._sleep_until_deadline(deadline, cleanup_only=True),
                    name="reachy-ptt-cleanup-deadline-fallback",
                )
            except BaseException:
                for task in tasks.values():
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks.values(), return_exceptions=True)
                return self._build_cleanup_receipt(positive_by_name)
        task_names = {task: name for name, task in tasks.items()}
        pending = set(task_names)
        try:
            while pending:
                done, _still_pending = await asyncio.wait(
                    (*pending, deadline_task), return_when=asyncio.FIRST_COMPLETED
                )
                if deadline_task in done or self._clock_now() >= deadline:
                    for task in pending:
                        task.cancel()
                    await asyncio.gather(*pending, return_exceptions=True)
                    pending.clear()
                    break
                completed_observations = pending.intersection(done)
                for completed_task in completed_observations:
                    pending.discard(completed_task)
                    try:
                        positive_by_name[task_names[completed_task]] = (
                            completed_task.result() is True
                        )
                    except BaseException:
                        positive_by_name[task_names[completed_task]] = False
        finally:
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            if not deadline_task.done():
                deadline_task.cancel()
            await asyncio.gather(deadline_task, return_exceptions=True)
        return self._build_cleanup_receipt(positive_by_name)

    def _build_cleanup_receipt(self, positive_by_name: dict[str, bool]) -> PttSafetyReceipt:
        return PttSafetyReceipt(
            turn_id=self._turn_id,
            new_capture_rejected=True,
            recording_stopped=positive_by_name["recording"],
            playback_stopped=positive_by_name["playback"],
            motion_stopped=positive_by_name["motion"],
            audio_reactive_disabled=positive_by_name["audio_reactive"],
            owned_buffers_cleared=self._clear_result,
        )

    def _conservative_cleanup_receipt(self) -> PttSafetyReceipt:
        return self._build_cleanup_receipt(
            {
                "recording": False,
                "playback": False,
                "motion": False,
                "audio_reactive": False,
            }
        )

    @staticmethod
    async def _join_tasks(tasks: list[asyncio.Task[Any]]) -> None:
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _within_deadline(
        self,
        operation: Coroutine[Any, Any, _T],
        deadline: float,
        *,
        name: str,
        retry_factory: Callable[[], Coroutine[Any, Any, _T]] | None = None,
        cleanup_only: bool = False,
    ) -> _T:
        started_at = self._clock_now()
        if self._clock_faulted and not cleanup_only:
            operation.close()
            raise RuntimeError("clock fault closed ordinary operation admission")
        if started_at >= deadline:
            operation.close()
            raise TimeoutError
        fault_generation = self._clock_fault_generation
        try:
            deadline_task = self._create_runtime_task(
                self._sleep_until_deadline(deadline, cleanup_only=cleanup_only),
                name=f"{name}-deadline",
            )
        except BaseException:
            operation.close()
            if retry_factory is None:
                raise
            self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
            return await self._within_deadline(
                retry_factory(),
                deadline,
                name=f"{name}-fallback",
                cleanup_only=cleanup_only,
            )
        fault_task: asyncio.Task[bool] | None = None
        if not cleanup_only:
            try:
                fault_task = self._create_runtime_task(
                    self._clock_fault_event.wait(),
                    name=f"{name}-clock-fault",
                )
            except BaseException:
                deadline_task.cancel()
                await asyncio.gather(deadline_task, return_exceptions=True)
                operation.close()
                if retry_factory is None:
                    raise
                self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
                return await self._within_deadline(
                    retry_factory(),
                    deadline,
                    name=f"{name}-fallback",
                    cleanup_only=cleanup_only,
                )
        try:
            operation_task = self._create_runtime_task(operation, name=name)
        except BaseException:
            deadline_task.cancel()
            if fault_task is not None:
                fault_task.cancel()
            await asyncio.gather(
                deadline_task,
                *(task for task in (fault_task,) if task is not None),
                return_exceptions=True,
            )
            if retry_factory is None:
                raise
            self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
            return await self._within_deadline(
                retry_factory(),
                deadline,
                name=f"{name}-fallback",
                cleanup_only=cleanup_only,
            )
        if not cleanup_only:
            self._clock_sensitive_tasks.add(operation_task)
        try:
            waiters: list[asyncio.Task[Any]] = [operation_task, deadline_task]
            if fault_task is not None:
                waiters.append(fault_task)
            done, _pending = await asyncio.wait(
                waiters,
                return_when=asyncio.FIRST_COMPLETED,
            )
            current = self._clock_now()
            if not cleanup_only and (
                self._clock_faulted
                or self._clock_fault_generation != fault_generation
                or fault_task in done
            ):
                operation_task.cancel()
                await asyncio.gather(operation_task, return_exceptions=True)
                raise RuntimeError("clock fault interrupted ordinary operation")
            if deadline_task in done:
                self._validate_clock_sleeper_completion(
                    deadline_task,
                    deadline,
                    allow_post_fault_cleanup=cleanup_only,
                )
                operation_task.cancel()
                await asyncio.gather(operation_task, return_exceptions=True)
                raise TimeoutError
            if current >= deadline:
                operation_task.cancel()
                await asyncio.gather(operation_task, return_exceptions=True)
                raise TimeoutError
            deadline_task.cancel()
            if fault_task is not None:
                fault_task.cancel()
            await asyncio.gather(
                deadline_task,
                *(task for task in (fault_task,) if task is not None),
                return_exceptions=True,
            )
            if not cleanup_only and (
                self._clock_faulted or self._clock_fault_generation != fault_generation
            ):
                raise RuntimeError("clock fault interrupted ordinary operation")
            return operation_task.result()
        except BaseException:
            if not operation_task.done():
                operation_task.cancel()
            if not deadline_task.done():
                deadline_task.cancel()
            if fault_task is not None and not fault_task.done():
                fault_task.cancel()
            await asyncio.gather(
                operation_task,
                deadline_task,
                *(task for task in (fault_task,) if task is not None),
                return_exceptions=True,
            )
            raise
        finally:
            self._clock_sensitive_tasks.discard(operation_task)

    async def _wait_event(self, event: asyncio.Event, deadline: float, *, name: str) -> None:
        await self._within_deadline(event.wait(), deadline, name=name)

    async def _wait_event_or_cleanup(
        self, event: asyncio.Event, deadline: float, *, name: str
    ) -> bool:
        event_task = self._create_runtime_task(
            self._wait_event(event, deadline, name=name), name=name
        )
        cleanup_task = await self._create_followup_task(
            self._cleanup_requested.wait(),
            name=f"{name}-cleanup",
            adopted=(event_task,),
        )
        try:
            done, _pending = await asyncio.wait(
                (event_task, cleanup_task), return_when=asyncio.FIRST_COMPLETED
            )
            if cleanup_task in done:
                return False
            event_task.result()
            return True
        finally:
            for task in (event_task, cleanup_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(event_task, cleanup_task, return_exceptions=True)

    async def _sleep_until_or_cleanup(self, deadline: float, *, name: str) -> bool:
        deadline_task = self._create_runtime_task(self._clock.sleep_until(deadline), name=name)
        cleanup_task = await self._create_followup_task(
            self._cleanup_requested.wait(),
            name=f"{name}-cleanup",
            adopted=(deadline_task,),
        )
        try:
            done, _pending = await asyncio.wait(
                (deadline_task, cleanup_task), return_when=asyncio.FIRST_COMPLETED
            )
            if deadline_task in done:
                self._validate_clock_sleeper_completion(deadline_task, deadline)
                return True
            return False
        finally:
            for task in (deadline_task, cleanup_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(deadline_task, cleanup_task, return_exceptions=True)

    def _guard_instance(self) -> PttDuplexGuard:
        if self._guard is None:
            raise RuntimeError("PTT guard is absent")
        return self._guard

    async def _accept_guarded(
        self, direction: StreamDirection, frame: WireFrame
    ) -> GuardDisposition:
        async with self._guard_lock:
            now = self._clock_now()
            cleanup_latched = self._cleanup_requested.is_set()
            prior_core_frame = self._last_valid_core_frame
            turn_expired = (
                direction is StreamDirection.CORE_TO_EDGE
                and not cleanup_latched
                and self._run_started_at is not None
                and now >= self._run_started_at + _TURN_SECONDS
            )
            heartbeat_expired = (
                direction is StreamDirection.CORE_TO_EDGE
                and not cleanup_latched
                and not turn_expired
                and prior_core_frame is not None
                and now >= prior_core_frame + _HANDSHAKE_SECONDS
            )
            handshake_open_expired = (
                direction is StreamDirection.CORE_TO_EDGE
                and not cleanup_latched
                and not turn_expired
                and prior_core_frame is None
                and self._run_started_at is not None
                and isinstance(frame, ControlFrame)
                and frame.control.kind is ControlKind.SESSION_OPEN
                and now >= self._run_started_at + _HANDSHAKE_SECONDS
            )
            suppress_dispatch = (
                self._clock_faulted
                or turn_expired
                or heartbeat_expired
                or handshake_open_expired
            )
            guarded = (
                None
                if self._clock_faulted
                else self._guard_instance().accept(direction, frame, now=now)
            )
            if (
                not suppress_dispatch
                and guarded is not None
                and guarded.disposition is GuardDisposition.ACCEPTED
                and isinstance(frame, ControlFrame)
            ):
                if (
                    direction is StreamDirection.CORE_TO_EDGE
                    and frame.control.kind is ControlKind.PTT_START
                ):
                    self._ptt_started_at = now
                elif (
                    direction is StreamDirection.CORE_TO_EDGE
                    and frame.control.kind is ControlKind.PTT_SUBMIT
                ):
                    self._ptt_submitted_at = now
                elif (
                    direction is StreamDirection.CORE_TO_EDGE
                    and frame.control.kind is ControlKind.PLAYBACK_START
                ):
                    self._playback_started_at = now
                elif (
                    direction is StreamDirection.EDGE_TO_CORE
                    and frame.control.kind is ControlKind.CAPTURE_START
                ):
                    self._capture_started_at = now
                if direction is StreamDirection.CORE_TO_EDGE:
                    self._last_accepted_core_frame = (id(frame), now)
            if (
                direction is StreamDirection.CORE_TO_EDGE
                and not cleanup_latched
                and not suppress_dispatch
            ):
                self._last_valid_core_frame = now
            if suppress_dispatch:
                disposition = GuardDisposition.LATE_DISCARDED
            else:
                assert guarded is not None
                disposition = guarded.disposition
        if turn_expired or heartbeat_expired or handshake_open_expired:
            await self._request_cleanup(
                PttStopSource.WATCHDOG,
                PttSessionOutcome.SESSION_TIMEOUT,
                triggered_at=now,
            )
        return disposition

    async def _enqueue_normal(
        self,
        *,
        control: PttControl | None = None,
        pcm: bytes | None = None,
        absolute_deadline: float | None = None,
    ) -> None:
        completion: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        draft = _OutboundDraft(
            completion=completion,
            control=control,
            pcm=pcm,
            absolute_deadline=absolute_deadline,
        )
        async with self._writer_lock:
            if (
                self._cleanup_started_at is not None
                or self._writer_stopping
                or not self._transport_writable
            ):
                raise RuntimeError("normal PTT admission is closed")
            self._blocked_normal_producers += 1
        try:
            await self._normal_slots.acquire()
        except BaseException:
            async with self._writer_lock:
                self._blocked_normal_producers -= 1
            raise
        async with self._writer_lock:
            self._blocked_normal_producers -= 1
            if (
                self._cleanup_started_at is not None
                or self._writer_stopping
                or not self._transport_writable
            ):
                self._normal_slots.release()
                raise RuntimeError("PTT frame was not sent")
            self._normal_queue.put_nowait(draft)
            self._writer_wakeup.set()
        await completion

    async def _enqueue_terminal(self, control: PttControl, *, bypass_guard: bool = False) -> None:
        async with self._writer_lock:
            if not self._transport_writable or self._writer_stopping:
                raise RuntimeError("PTT transport is unwritable")
            shared = next(
                (
                    draft.completion
                    for draft in self._terminal_drafts
                    if draft.control == control and draft.bypass_guard is bypass_guard
                ),
                None,
            )
            if shared is None:
                if len(self._terminal_queue) >= 2:
                    raise RuntimeError("PTT terminal lane is full")
                shared = asyncio.get_running_loop().create_future()
                draft = _OutboundDraft(
                    completion=shared,
                    control=control,
                    bypass_guard=bypass_guard,
                )
                self._terminal_drafts.append(draft)
                self._terminal_queue.append(draft)
                self._writer_wakeup.set()
        await asyncio.shield(shared)

    @staticmethod
    def _complete_draft_failure(draft: _OutboundDraft) -> None:
        if not draft.completion.done():
            draft.completion.set_exception(RuntimeError("PTT frame was not sent"))

    def _fail_queued_drafts_locked(self) -> None:
        while self._terminal_queue:
            self._complete_draft_failure(self._terminal_queue.popleft())
        while True:
            try:
                draft = self._normal_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            self._normal_slots.release()
            self._complete_draft_failure(draft)

    def _drop_unsent_guarded_terminal_drafts_locked(self) -> None:
        retained: list[_OutboundDraft] = []
        dropped_ids: set[int] = set()
        while self._terminal_queue:
            draft = self._terminal_queue.popleft()
            if draft.bypass_guard:
                retained.append(draft)
            else:
                dropped_ids.add(id(draft))
                self._complete_draft_failure(draft)
        self._terminal_queue.extend(retained)
        if dropped_ids:
            self._terminal_drafts[:] = [
                draft for draft in self._terminal_drafts if id(draft) not in dropped_ids
            ]

    def _wake_blocked_normal_producers_locked(self) -> None:
        for _ in range(self._blocked_normal_producers):
            self._normal_slots.release()

    async def _send_draft(self, draft: _OutboundDraft, sequence: int) -> None:
        if (draft.control is None) is (draft.pcm is None):
            raise RuntimeError("invalid outbound PTT draft")
        send_started = self._clock_now()
        if self._clock_faulted:
            raise RuntimeError("clock fault closed outbound admission")
        deadline = send_started + _SEND_SECONDS
        if draft.absolute_deadline is not None:
            deadline = min(deadline, draft.absolute_deadline)
        if self._cleanup_started_at is not None:
            deadline = min(deadline, self._cleanup_started_at + _RECEIPT_SEND_SECONDS)
        if send_started >= deadline:
            raise TimeoutError
        if draft.control is not None:
            frame: WireFrame = ControlFrame(
                turn_id=self._turn_id, sequence=sequence, control=draft.control
            )
            if not draft.bypass_guard:
                await self._accept_guarded(StreamDirection.EDGE_TO_CORE, frame)
            encoded = encode_control_frame(sequence=sequence, control=draft.control)
        else:
            assert draft.pcm is not None
            frame = PcmFrame(turn_id=self._turn_id, sequence=sequence, pcm=draft.pcm)
            if not draft.bypass_guard:
                await self._accept_guarded(StreamDirection.EDGE_TO_CORE, frame)
            encoded = encode_pcm_frame(turn_id=self._turn_id, sequence=sequence, pcm=draft.pcm)
        before_transport = self._clock_now()
        if self._clock_faulted:
            raise RuntimeError("clock fault closed outbound admission")
        if before_transport >= deadline:
            raise TimeoutError
        await self._within_deadline(self._transport.send(encoded), deadline, name="reachy-ptt-send")

    async def _writer_loop(self) -> None:
        while True:
            await self._writer_wakeup.wait()
            while True:
                async with self._writer_lock:
                    if self._terminal_queue:
                        draft = self._terminal_queue.popleft()
                    else:
                        try:
                            draft = self._normal_queue.get_nowait()
                        except asyncio.QueueEmpty:
                            self._writer_wakeup.clear()
                            if self._writer_stopping:
                                return
                            break
                        self._normal_slots.release()
                        if self._cleanup_started_at is not None:
                            self._complete_draft_failure(draft)
                            continue
                    sequence = self._edge_sequence
                    self._active_send = True
                send_failed = False
                try:
                    await self._send_draft(draft, sequence)
                except asyncio.CancelledError:
                    send_failed = True
                    async with self._writer_lock:
                        self._transport_writable = False
                        self._wake_blocked_normal_producers_locked()
                        self._fail_queued_drafts_locked()
                    self._complete_draft_failure(draft)
                    raise
                except BaseException:
                    send_failed = True
                    async with self._writer_lock:
                        self._transport_writable = False
                        self._wake_blocked_normal_producers_locked()
                        self._fail_queued_drafts_locked()
                    self._complete_draft_failure(draft)
                else:
                    async with self._writer_lock:
                        self._edge_sequence += 1
                    if not draft.completion.done():
                        draft.completion.set_result(None)
                finally:
                    async with self._writer_lock:
                        self._active_send = False
                if send_failed:
                    await self._request_cleanup(
                        PttStopSource.PEER_EOF,
                        PttSessionOutcome.CLEANUP_INCOMPLETE,
                    )
                    return

    def _queue_playback_locked(self, draft: _PlaybackDraft) -> bool:
        try:
            self._playback_queue.put_nowait(draft)
        except asyncio.QueueFull:
            return False
        return True

    def _drain_playback_locked(self) -> None:
        while True:
            try:
                self._playback_queue.get_nowait()
            except asyncio.QueueEmpty:
                return

    async def _playback_loop(self) -> None:
        while True:
            draft = await self._playback_queue.get()
            async with self._writer_lock:
                if self._cleanup_started_at is not None:
                    continue
                deadline = self._playback_deadline
            if deadline is None:
                await self._request_cleanup(
                    PttStopSource.PROTOCOL_REJECTED,
                    PttSessionOutcome.PLAYBACK_FAILED,
                )
                return
            try:
                if draft.kind is ControlKind.PLAYBACK_START:
                    await self._within_deadline(
                        self._media.open_playback(input_format=TRANSPORT_AUDIO_FORMAT),
                        deadline,
                        name="reachy-ptt-playback-open",
                    )
                elif draft.kind is ControlKind.PLAYBACK_END:
                    closed = await self._within_deadline(
                        self._media.close_playback(),
                        deadline,
                        name="reachy-ptt-playback-close",
                    )
                    outcome = (
                        PttSessionOutcome.COMPLETED
                        if closed is True
                        else PttSessionOutcome.PLAYBACK_FAILED
                    )
                    await self._request_cleanup(PttStopSource.SUPERVISOR_INPUT, outcome)
                    return
                else:
                    if draft.pcm is None:
                        raise RuntimeError("invalid playback draft")
                    await self._within_deadline(
                        self._media.write_playback(draft.pcm),
                        deadline,
                        name="reachy-ptt-playback-write",
                    )
            except asyncio.CancelledError:
                raise
            except BaseException:
                await self._request_cleanup(
                    PttStopSource.PROTOCOL_REJECTED,
                    PttSessionOutcome.PLAYBACK_FAILED,
                )
                return

    async def _dispatch_core_frame(self, frame: WireFrame) -> None:
        triggered_at = self._dispatch_triggered_at
        if triggered_at is None:
            triggered_at = self._clock_now()
        if isinstance(frame, PcmFrame):
            playback_failed = False
            queued = False
            async with self._writer_lock:
                if not self._playback_gate or self._cleanup_started_at is not None:
                    return
                try:
                    self._playback_buffer.append(frame.pcm)
                    pcm = self._playback_buffer.take(len(frame.pcm))
                    if type(pcm) is not bytes or pcm != frame.pcm:
                        raise ValueError("invalid playback-buffer output")
                    queued = self._queue_playback_locked(
                        _PlaybackDraft(kind=ControlKind.HEARTBEAT, pcm=pcm)
                    )
                except BaseException:
                    playback_failed = True
            if playback_failed or not queued:
                await self._request_cleanup(
                    PttStopSource.PROTOCOL_REJECTED,
                    PttSessionOutcome.PLAYBACK_FAILED,
                    triggered_at=triggered_at,
                )
            return
        control = frame.control
        if control.kind is ControlKind.SESSION_OPEN:
            run_started_at = self._run_started_at
            handshake_deadline = (
                None if run_started_at is None else run_started_at + _HANDSHAKE_SECONDS
            )
            if (
                self._cleanup_started_at is None
                and (handshake_deadline is None or triggered_at < handshake_deadline)
            ):
                self._session_open_accepted_before_cleanup = True
                self._session_open.set()
        elif control.kind is ControlKind.PTT_START:
            self._ptt_started.set()
        elif control.kind is ControlKind.PTT_SUBMIT:
            self._ptt_submitted.set()
        elif control.kind is ControlKind.PLAYBACK_START:
            async with self._writer_lock:
                if self._cleanup_started_at is not None:
                    return
                playback_started_at = self._playback_started_at
                if playback_started_at is None:
                    queued = False
                else:
                    run_started_at = self._run_started_at
                    if run_started_at is None:
                        run_started_at = playback_started_at
                    self._playback_deadline = min(
                        playback_started_at + _PLAYBACK_SECONDS,
                        run_started_at + _TURN_SECONDS,
                    )
                    self._playback_gate = True
                    queued = self._queue_playback_locked(
                        _PlaybackDraft(kind=ControlKind.PLAYBACK_START)
                    )
            if not queued:
                await self._request_cleanup(
                    PttStopSource.PROTOCOL_REJECTED,
                    PttSessionOutcome.PLAYBACK_FAILED,
                    triggered_at=triggered_at,
                )
        elif control.kind is ControlKind.PLAYBACK_END:
            async with self._writer_lock:
                self._playback_gate = False
                queued = self._cleanup_started_at is None and self._queue_playback_locked(
                    _PlaybackDraft(kind=ControlKind.PLAYBACK_END)
                )
            if not queued:
                await self._request_cleanup(
                    PttStopSource.PROTOCOL_REJECTED,
                    PttSessionOutcome.PLAYBACK_FAILED,
                    triggered_at=triggered_at,
                )
        elif control.kind is ControlKind.SAFETY_ACK:
            if not isinstance(control.payload, AckPayload):
                raise RuntimeError("invalid safety acknowledgement")
            self._ack_accepted = control.payload.accepted
            self._ack_received.set()
        elif control.kind in {ControlKind.ABORT, ControlKind.ERROR}:
            outcome = PttSessionOutcome.CANCELLED
            if isinstance(control.payload, ErrorPayload):
                outcome = {
                    PttErrorReason.PROTOCOL_REJECTED: PttSessionOutcome.PROTOCOL_REJECTED,
                    PttErrorReason.TURN_CANCELLED: PttSessionOutcome.CANCELLED,
                    PttErrorReason.CAPTURE_FAILED: PttSessionOutcome.CAPTURE_FAILED,
                    PttErrorReason.PROVIDER_FAILED: PttSessionOutcome.PROVIDER_FAILED,
                    PttErrorReason.PLAYBACK_FAILED: PttSessionOutcome.PLAYBACK_FAILED,
                    PttErrorReason.CLEANUP_INCOMPLETE: PttSessionOutcome.CLEANUP_INCOMPLETE,
                    PttErrorReason.PEER_CLOSED: PttSessionOutcome.PEER_CLOSED,
                    PttErrorReason.SESSION_TIMEOUT: PttSessionOutcome.SESSION_TIMEOUT,
                }[control.payload.reason_code]
            await self._request_cleanup(
                PttStopSource.CORE_ABORT,
                outcome,
                triggered_at=triggered_at,
            )

    async def _reader_loop(self) -> None:
        decoder = self._decoder
        if decoder is None:
            raise RuntimeError("PTT decoder is absent")
        while True:
            if self._clock_faulted:
                return
            try:
                data = await self._transport.receive(MAX_FEED_BYTES)
            except asyncio.CancelledError:
                raise
            except BaseException:
                await self._request_cleanup(PttStopSource.PEER_EOF, PttSessionOutcome.PEER_CLOSED)
                return
            if type(data) is not bytes or len(data) > MAX_FEED_BYTES:
                await self._request_cleanup(
                    PttStopSource.PEER_EOF,
                    PttSessionOutcome.CLEANUP_INCOMPLETE,
                )
                return
            if data == b"":
                try:
                    decoder.finish()
                except BaseException:
                    await self._poison_protocol(decoder)
                else:
                    await self._request_cleanup(
                        PttStopSource.PEER_EOF, PttSessionOutcome.PEER_CLOSED
                    )
                return
            try:
                frames = decoder.feed(data)
                ack_indexes = [
                    index
                    for index, frame in enumerate(frames)
                    if isinstance(frame, ControlFrame)
                    and frame.control.kind is ControlKind.SAFETY_ACK
                ]
                if ack_indexes:
                    if len(ack_indexes) != 1 or ack_indexes[0] != len(frames) - 1:
                        raise FrameProtocolError(FrameErrorCode.INVALID_ORDER)
                    decoder.finish()
                for frame in frames:
                    disposition = await self._accept_guarded(StreamDirection.CORE_TO_EDGE, frame)
                    if self._clock_faulted:
                        return
                    if disposition is GuardDisposition.ACCEPTED:
                        accepted = self._last_accepted_core_frame
                        accepted_at = (
                            accepted[1]
                            if accepted is not None and accepted[0] == id(frame)
                            else self._clock_now()
                        )
                        self._last_accepted_core_frame = None
                        self._dispatch_triggered_at = accepted_at
                        try:
                            await self._dispatch_core_frame(frame)
                        finally:
                            self._dispatch_triggered_at = None
                if ack_indexes:
                    return
            except asyncio.CancelledError:
                raise
            except BaseException:
                await self._poison_protocol(decoder)
                return

    def _latch_cleanup_locked(
        self,
        source: PttStopSource,
        outcome: PttSessionOutcome,
        *,
        triggered_at: float,
    ) -> bool:
        if self._cleanup_started_at is not None:
            return False
        if self._clock_faulted:
            source = PttStopSource.WATCHDOG
            outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
        elif (
            self._run_started_at is not None
            and triggered_at >= self._run_started_at + _TURN_SECONDS
        ):
            source = PttStopSource.WATCHDOG
            outcome = PttSessionOutcome.SESSION_TIMEOUT
        self._cleanup_started_at = triggered_at
        self._cleanup_source = source
        self._semantic_outcome = outcome
        self._terminal = True
        self._capture_gate = False
        self._playback_gate = False
        current_task = asyncio.current_task()
        for task in (self._turn_task, self._playback_task):
            if task is not None and task is not current_task and not task.done():
                task.cancel()
        self._drain_playback_locked()
        self._clear_result = self._clear_owned_buffers()
        self._wake_blocked_normal_producers_locked()
        while True:
            try:
                draft = self._normal_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            self._normal_slots.release()
            self._complete_draft_failure(draft)
        self._cleanup_requested.set()
        self._writer_wakeup.set()
        return True

    async def _poison_protocol(self, decoder: FrameDecoder) -> None:
        triggered_at = self._clock_now()
        decoder.abort()
        async with self._guard_lock:
            if self._guard is not None:
                self._guard.abort()
        async with self._writer_lock:
            if self._guard_poisoned:
                return
            self._guard_poisoned = True
            self._protocol_poisoned.set()
            self._poison_suppress_output = (
                self._active_send or self._receipt_attempted or not self._transport_writable
            )
            self._drop_unsent_guarded_terminal_drafts_locked()
            self._latch_cleanup_locked(
                PttStopSource.PROTOCOL_REJECTED,
                PttSessionOutcome.PROTOCOL_REJECTED,
                triggered_at=triggered_at,
            )

    async def _request_cleanup(
        self,
        source: PttStopSource,
        outcome: PttSessionOutcome,
        *,
        triggered_at: float | None = None,
    ) -> None:
        if triggered_at is None:
            triggered_at = self._clock_now()
        async with self._writer_lock:
            self._latch_cleanup_locked(source, outcome, triggered_at=triggered_at)

    def _owned_runtime_tasks(self) -> list[asyncio.Task[None]]:
        return [
            task
            for task in (
                self._reader_task,
                self._writer_task,
                self._playback_task,
                self._stop_input_task,
                self._turn_task,
                self._heartbeat_task,
                self._turn_watchdog_task,
            )
            if task is not None and task is not asyncio.current_task()
        ]

    def _cancel_runtime_tasks(self) -> list[asyncio.Task[None]]:
        tasks = self._owned_runtime_tasks()
        for task in tasks:
            task.cancel()
        return tasks

    @staticmethod
    async def _join_cancelled_runtime_tasks(tasks: list[asyncio.Task[None]]) -> None:
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _join_runtime_tasks(self) -> None:
        await self._join_cancelled_runtime_tasks(self._cancel_runtime_tasks())

    async def _gather_effect_tasks(self) -> None:
        tasks = [
            task
            for task in (self._turn_task, self._playback_task)
            if task is not None and task is not asyncio.current_task()
        ]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _join_effects_before_receipt(self) -> bool:
        cleanup_started_at = self._cleanup_started_at
        if cleanup_started_at is None:
            return False
        try:
            await self._within_deadline(
                self._gather_effect_tasks(),
                cleanup_started_at + _CLEANUP_OBSERVATION_SECONDS,
                name="reachy-ptt-effect-join",
                cleanup_only=True,
            )
        except BaseException:
            return False
        return all(task is None or task.done() for task in (self._turn_task, self._playback_task))

    async def _teardown_runtime(self) -> None:
        cleanup_started_at = self._cleanup_started_at
        if cleanup_started_at is None:
            return
        deadline = cleanup_started_at + _TEARDOWN_SECONDS
        if self._clock_now() >= deadline:
            self._writer_stopping = True
            self._writer_wakeup.set()
            self._transport_writable = False
            self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
            for task in self._owned_runtime_tasks():
                task.cancel()
            if self._decoder is not None:
                self._decoder.abort()
            return
        async with self._writer_lock:
            self._writer_stopping = True
            self._writer_wakeup.set()
        if self._clock_now() >= deadline:
            self._transport_writable = False
            self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
            for task in self._owned_runtime_tasks():
                task.cancel()
            if self._decoder is not None:
                self._decoder.abort()
            return
        runtime_tasks = self._cancel_runtime_tasks()
        try:
            await self._within_deadline(
                self._transport.close(),
                deadline,
                name="reachy-ptt-transport-close",
                retry_factory=self._transport.close,
                cleanup_only=True,
            )
        except BaseException:
            self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
        if self._clock_now() >= deadline:
            self._transport_writable = False
            self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
            if self._decoder is not None:
                self._decoder.abort()
            return
        try:
            await self._within_deadline(
                self._join_cancelled_runtime_tasks(runtime_tasks),
                deadline,
                name="reachy-ptt-task-join",
                retry_factory=lambda: self._join_cancelled_runtime_tasks(runtime_tasks),
                cleanup_only=True,
            )
        except BaseException:
            self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
        if self._decoder is not None:
            self._decoder.abort()

    def _normal_cleanup_control(self) -> PttControl | None:
        if self._cleanup_source is PttStopSource.CORE_ABORT:
            return None
        if self._semantic_outcome is PttSessionOutcome.COMPLETED:
            return None
        if self._semantic_outcome is PttSessionOutcome.CANCELLED:
            return PttControl.stop(self._turn_id)
        reason = {
            PttSessionOutcome.PEER_CLOSED: PttErrorReason.PEER_CLOSED,
            PttSessionOutcome.PROTOCOL_REJECTED: PttErrorReason.PROTOCOL_REJECTED,
            PttSessionOutcome.CAPTURE_FAILED: PttErrorReason.CAPTURE_FAILED,
            PttSessionOutcome.PROVIDER_FAILED: PttErrorReason.PROVIDER_FAILED,
            PttSessionOutcome.PLAYBACK_FAILED: PttErrorReason.PLAYBACK_FAILED,
            PttSessionOutcome.CLEANUP_INCOMPLETE: PttErrorReason.CLEANUP_INCOMPLETE,
            PttSessionOutcome.SESSION_TIMEOUT: PttErrorReason.SESSION_TIMEOUT,
        }[self._semantic_outcome]
        return PttControl.error(self._turn_id, reason)

    async def _coordinate_poison_cleanup(
        self,
        observation_task: asyncio.Task[PttSafetyReceipt],
        effect_join_task: asyncio.Task[bool],
    ) -> PttSafetyReceipt:
        async with self._writer_lock:
            can_attempt = (
                self._transport_writable
                and not self._poison_suppress_output
                and not self._receipt_attempted
            )
            if can_attempt:
                self._receipt_attempted = True
        error_sent = False
        if can_attempt:
            try:
                await self._enqueue_terminal(
                    PttControl.error(self._turn_id, PttErrorReason.PROTOCOL_REJECTED),
                    bypass_guard=True,
                )
            except BaseException:
                self._transport_writable = False
            else:
                error_sent = True
        receipt, _effects_joined = await asyncio.gather(observation_task, effect_join_task)
        if error_sent and self._transport_writable:
            try:
                await self._enqueue_terminal(
                    PttControl.safety_receipt(self._turn_id, receipt),
                    bypass_guard=True,
                )
            except BaseException:
                self._transport_writable = False
        self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
        await self._teardown_runtime()
        return receipt

    async def _wait_cleanup_evidence_or_poison(
        self,
        observation_task: asyncio.Task[PttSafetyReceipt],
        effect_join_task: asyncio.Task[bool],
    ) -> tuple[PttSafetyReceipt, bool] | None:
        poison_task = await self._create_followup_task(
            self._protocol_poisoned.wait(),
            name="reachy-ptt-poison-wait",
            adopted=(effect_join_task,),
        )
        pending: set[asyncio.Task[Any]] = {observation_task, effect_join_task}
        try:
            while pending:
                done, _still_pending = await asyncio.wait(
                    (*pending, poison_task), return_when=asyncio.FIRST_COMPLETED
                )
                if poison_task in done:
                    return None
                pending.difference_update(done)
            return observation_task.result(), effect_join_task.result()
        finally:
            if not poison_task.done():
                poison_task.cancel()
            await asyncio.gather(poison_task, return_exceptions=True)

    async def _wait_ack_or_poison(self, deadline: float) -> bool:
        ack_task = self._create_runtime_task(
            self._wait_event(
                self._ack_received,
                deadline,
                name="reachy-ptt-safety-ack",
            ),
            name="reachy-ptt-safety-ack-owner",
        )
        poison_task = await self._create_followup_task(
            self._protocol_poisoned.wait(),
            name="reachy-ptt-ack-poison-wait",
            adopted=(ack_task,),
        )
        try:
            done, _pending = await asyncio.wait(
                (ack_task, poison_task), return_when=asyncio.FIRST_COMPLETED
            )
            if poison_task in done:
                return False
            ack_task.result()
            return True
        finally:
            for task in (ack_task, poison_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(ack_task, poison_task, return_exceptions=True)

    async def _cleanup_coordinator(self) -> PttSafetyReceipt:
        await self._cleanup_requested.wait()
        observation_owner_failed = False
        try:
            observation_task = self._create_runtime_task(
                self._observe_local_cleanup(), name="reachy-ptt-cleanup-observations"
            )
        except BaseException:
            observation_owner_failed = True
            try:
                observation_task = self._create_runtime_task(
                    self._observe_local_cleanup(),
                    name="reachy-ptt-cleanup-observations-fallback",
                )
            except BaseException:
                try:
                    observation_task = self._create_direct_task(
                        self._observe_local_cleanup(),
                        name="reachy-ptt-cleanup-observations-direct-fallback",
                    )
                except BaseException:
                    receipt = self._conservative_cleanup_receipt()
                    self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
                    await self._teardown_runtime()
                    return receipt
        try:
            self._effect_join_task = self._create_runtime_task(
                self._join_effects_before_receipt(),
                name="reachy-ptt-effect-join-owner",
            )
        except BaseException:
            try:
                receipt = await observation_task
            except BaseException:
                receipt = self._conservative_cleanup_receipt()
            self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
            await self._teardown_runtime()
            return receipt
        effect_join_task = self._effect_join_task
        cleanup_started_at = self._cleanup_started_at
        if cleanup_started_at is None:
            raise RuntimeError("cleanup deadline is absent")
        if self._guard_poisoned:
            return await self._coordinate_poison_cleanup(observation_task, effect_join_task)
        cleanup_control = self._normal_cleanup_control()
        if cleanup_control is not None and not self._guard_poisoned and self._transport_writable:
            try:
                await self._enqueue_terminal(cleanup_control)
            except BaseException:
                if not self._guard_poisoned:
                    self._transport_writable = False
        try:
            evidence = await self._wait_cleanup_evidence_or_poison(
                observation_task, effect_join_task
            )
        except BaseException:
            self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
            try:
                receipt = await observation_task
            except BaseException:
                receipt = self._conservative_cleanup_receipt()
            await self._teardown_runtime()
            return receipt
        if evidence is None:
            return await self._coordinate_poison_cleanup(observation_task, effect_join_task)
        receipt, effects_joined = evidence
        receipt_sent = False
        switch_to_poison = False
        async with self._writer_lock:
            if self._guard_poisoned:
                switch_to_poison = True
                can_attempt = False
            elif self._transport_writable:
                can_attempt = not self._receipt_attempted
                self._receipt_attempted = True
            else:
                can_attempt = False
        if switch_to_poison:
            return await self._coordinate_poison_cleanup(observation_task, effect_join_task)
        if can_attempt:
            try:
                await self._enqueue_terminal(PttControl.safety_receipt(self._turn_id, receipt))
            except BaseException:
                self._transport_writable = False
            else:
                receipt_sent = True
        if receipt_sent:
            if not self._session_open_accepted_before_cleanup:
                if not receipt.is_complete() or not effects_joined:
                    self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
                elif self._semantic_outcome is not PttSessionOutcome.COMPLETED:
                    self._final_outcome = self._semantic_outcome
                else:
                    self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
            else:
                try:
                    ack_was_valid = await self._wait_ack_or_poison(
                        cleanup_started_at + _ACK_SECONDS
                    )
                except BaseException:
                    self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
                else:
                    guard_finished = False
                    try:
                        async with self._guard_lock:
                            guarded_outcome = self._guard_instance().finish()
                    except BaseException:
                        guarded_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
                    else:
                        guard_finished = True
                    if (
                        not ack_was_valid
                        or self._guard_poisoned
                        or not guard_finished
                        or not receipt.is_complete()
                        or not effects_joined
                        or self._ack_accepted is not True
                    ):
                        self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
                    elif self._semantic_outcome is not PttSessionOutcome.COMPLETED:
                        self._final_outcome = self._semantic_outcome
                    else:
                        self._final_outcome = guarded_outcome
        else:
            self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
        if observation_owner_failed:
            self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
        await self._teardown_runtime()
        return receipt

    async def _await_cleanup(self, task: asyncio.Future[PttSafetyReceipt]) -> PttSafetyReceipt:
        cancelled = False
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                cancelled = True
        receipt = task.result()
        if cancelled:
            raise asyncio.CancelledError
        return receipt

    async def _capture_until_submit(
        self,
        submit_operation: Coroutine[Any, Any, object],
        capture_deadline: float,
    ) -> bool:
        owned_tasks: list[asyncio.Task[Any]] = []
        read_task: asyncio.Task[bytes | None] | None = None
        useful_pcm = False
        try:
            submit_task = self._create_runtime_task(
                submit_operation, name="reachy-ptt-capture-submit"
            )
            owned_tasks.append(submit_task)
            cleanup_task = self._create_runtime_task(
                self._cleanup_requested.wait(), name="reachy-ptt-capture-cleanup"
            )
            owned_tasks.append(cleanup_task)
            deadline_task = self._create_runtime_task(
                self._clock.sleep_until(capture_deadline),
                name="reachy-ptt-capture-deadline",
            )
            owned_tasks.append(deadline_task)
            while True:
                if deadline_task.done():
                    self._validate_clock_sleeper_completion(deadline_task, capture_deadline)
                    await self._request_cleanup(
                        PttStopSource.PROTOCOL_REJECTED,
                        PttSessionOutcome.CAPTURE_FAILED,
                    )
                    return False
                if cleanup_task.done():
                    return False
                if self._clock_now() >= capture_deadline:
                    await self._request_cleanup(
                        PttStopSource.PROTOCOL_REJECTED,
                        PttSessionOutcome.CAPTURE_FAILED,
                    )
                    return False
                if submit_task.done():
                    submit_task.result()
                    if useful_pcm:
                        return True
                read_task = self._create_runtime_task(
                    self._media.read_capture(), name="reachy-ptt-capture-read"
                )
                waiters: set[asyncio.Task[Any]] = {
                    read_task,
                    cleanup_task,
                    deadline_task,
                }
                if not submit_task.done():
                    waiters.add(submit_task)
                done, _pending = await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
                if deadline_task in done:
                    self._validate_clock_sleeper_completion(deadline_task, capture_deadline)
                    await self._request_cleanup(
                        PttStopSource.PROTOCOL_REJECTED,
                        PttSessionOutcome.CAPTURE_FAILED,
                    )
                    return False
                if cleanup_task in done:
                    return False
                if self._clock_now() >= capture_deadline:
                    await self._request_cleanup(
                        PttStopSource.PROTOCOL_REJECTED,
                        PttSessionOutcome.CAPTURE_FAILED,
                    )
                    return False
                submit_finished = submit_task.done()
                if submit_finished:
                    submit_task.result()
                if not read_task.done():
                    if submit_finished:
                        # Give an already-runnable read one scheduling boundary.
                        # A still-blocked read must not delay an empty submit.
                        await asyncio.sleep(0)
                    if submit_finished and not read_task.done():
                        if useful_pcm:
                            return True
                        await self._request_cleanup(
                            PttStopSource.PROTOCOL_REJECTED,
                            PttSessionOutcome.CAPTURE_FAILED,
                        )
                        return False
                    done, _pending = await asyncio.wait(
                        (read_task, cleanup_task),
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    if cleanup_task in done:
                        return False
                    if self._clock_now() >= capture_deadline:
                        await self._request_cleanup(
                            PttStopSource.PROTOCOL_REJECTED,
                            PttSessionOutcome.CAPTURE_FAILED,
                        )
                        return False
                pcm = read_task.result()
                read_task = None
                if self._clock_now() >= capture_deadline:
                    await self._request_cleanup(
                        PttStopSource.PROTOCOL_REJECTED,
                        PttSessionOutcome.CAPTURE_FAILED,
                    )
                    return False
                if pcm is None:
                    if useful_pcm and submit_finished:
                        return True
                    await self._request_cleanup(
                        PttStopSource.PROTOCOL_REJECTED,
                        PttSessionOutcome.CAPTURE_FAILED,
                    )
                    return False
                if type(pcm) is not bytes or not pcm or len(pcm) > MAX_PCM_BYTES or len(pcm) % 2:
                    await self._request_cleanup(
                        PttStopSource.PROTOCOL_REJECTED,
                        PttSessionOutcome.CAPTURE_FAILED,
                    )
                    return False
                expired = False
                async with self._writer_lock:
                    if self._cleanup_started_at is not None:
                        return False
                    if self._clock_now() >= capture_deadline:
                        expired = True
                    else:
                        self._capture_buffer.append(pcm)
                if expired:
                    await self._request_cleanup(
                        PttStopSource.PROTOCOL_REJECTED,
                        PttSessionOutcome.CAPTURE_FAILED,
                    )
                    return False
                while True:
                    expired = False
                    async with self._writer_lock:
                        if self._cleanup_started_at is not None:
                            return False
                        if self._clock_now() >= capture_deadline:
                            expired = True
                        elif self._capture_buffer.is_empty():
                            break
                        else:
                            chunk = self._capture_buffer.take(MAX_TRANSPORT_PCM_FRAME_BYTES)
                    if expired:
                        await self._request_cleanup(
                            PttStopSource.PROTOCOL_REJECTED,
                            PttSessionOutcome.CAPTURE_FAILED,
                        )
                        return False
                    if (
                        type(chunk) is not bytes
                        or not chunk
                        or len(chunk) % 2
                        or len(chunk) > MAX_TRANSPORT_PCM_FRAME_BYTES
                    ):
                        await self._request_cleanup(
                            PttStopSource.PROTOCOL_REJECTED,
                            PttSessionOutcome.CAPTURE_FAILED,
                        )
                        return False
                    await self._enqueue_normal(pcm=chunk, absolute_deadline=capture_deadline)
                useful_pcm = True
                if submit_task.done():
                    submit_task.result()
                    return True
        finally:
            tasks = [*owned_tasks]
            if read_task is not None:
                tasks.append(read_task)
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _capture_terminal_turn(self, turn_deadline: float) -> None:
        await self._wait_event(self._ptt_started, turn_deadline, name="reachy-ptt-start")
        started_at = self._ptt_started_at
        if started_at is None:
            raise RuntimeError("capture start trigger timestamp is absent")
        open_deadline = min(started_at + _CAPTURE_OPERATION_SECONDS, turn_deadline)
        await self._within_deadline(
            self._media.open_capture(
                output_format=TRANSPORT_AUDIO_FORMAT,
                max_frame_bytes=MAX_TRANSPORT_PCM_FRAME_BYTES,
            ),
            open_deadline,
            name="reachy-ptt-capture-open",
        )
        async with self._writer_lock:
            if self._cleanup_started_at is not None:
                return
            self._capture_gate = True
        await self._enqueue_normal(
            control=PttControl.capture_start(self._turn_id, TRANSPORT_AUDIO_FORMAT),
            absolute_deadline=open_deadline,
        )
        capture_started_at = self._capture_started_at
        if capture_started_at is None:
            raise RuntimeError("capture timestamp is absent")
        capture_deadline = min(capture_started_at + _CAPTURE_SECONDS, turn_deadline)
        if not await self._capture_until_submit(self._ptt_submitted.wait(), capture_deadline):
            return
        self._capture_gate = False
        submitted_at = self._ptt_submitted_at
        if submitted_at is None:
            raise RuntimeError("capture submit timestamp is absent")
        close_deadline = min(
            submitted_at + _CAPTURE_OPERATION_SECONDS,
            capture_deadline,
            turn_deadline,
        )
        closed = await self._within_deadline(
            self._media.close_capture(),
            close_deadline,
            name="reachy-ptt-capture-close",
        )
        if closed is not True:
            await self._request_cleanup(
                PttStopSource.PROTOCOL_REJECTED,
                PttSessionOutcome.CAPTURE_FAILED,
            )
            return
        await self._enqueue_normal(
            control=PttControl.capture_end(self._turn_id),
            absolute_deadline=close_deadline,
        )

    async def _capture_local_turn(self, turn_deadline: float) -> None:
        capture_input = self._capture_input
        if capture_input is None:
            raise RuntimeError("Reachy-local capture input is absent")
        await self._within_deadline(
            capture_input.wait_for_start(), turn_deadline, name="reachy-ptt-local-start"
        )
        self._ptt_started_at = self._clock_now()
        started_at = self._ptt_started_at
        open_deadline = min(started_at + _CAPTURE_OPERATION_SECONDS, turn_deadline)
        await self._within_deadline(
            self._media.open_capture(
                output_format=TRANSPORT_AUDIO_FORMAT,
                max_frame_bytes=MAX_TRANSPORT_PCM_FRAME_BYTES,
            ),
            open_deadline,
            name="reachy-ptt-capture-open",
        )
        async with self._writer_lock:
            if self._cleanup_started_at is not None:
                return
            self._capture_gate = True
        await self._enqueue_normal(
            control=PttControl.capture_start(self._turn_id, TRANSPORT_AUDIO_FORMAT),
            absolute_deadline=open_deadline,
        )
        capture_started_at = self._capture_started_at
        if capture_started_at is None:
            raise RuntimeError("capture timestamp is absent")
        capture_deadline = min(capture_started_at + _CAPTURE_SECONDS, turn_deadline)

        async def wait_for_submit() -> None:
            await capture_input.wait_for_submit()
            self._ptt_submitted_at = self._clock_now()

        if not await self._capture_until_submit(wait_for_submit(), capture_deadline):
            return
        self._capture_gate = False
        submitted_at = self._ptt_submitted_at
        if submitted_at is None:
            raise RuntimeError("capture submit timestamp is absent")
        close_deadline = min(
            submitted_at + _CAPTURE_OPERATION_SECONDS,
            capture_deadline,
            turn_deadline,
        )
        closed = await self._within_deadline(
            self._media.close_capture(),
            close_deadline,
            name="reachy-ptt-capture-close",
        )
        if closed is not True:
            await self._request_cleanup(
                PttStopSource.PROTOCOL_REJECTED,
                PttSessionOutcome.CAPTURE_FAILED,
            )
            return
        await self._enqueue_normal(
            control=PttControl.capture_end(self._turn_id),
            absolute_deadline=close_deadline,
        )

    async def _watch_stop_input(self) -> None:
        stop_input = self._stop_input
        if stop_input is None:
            return
        try:
            await stop_input.wait_for_stop()
        except asyncio.CancelledError:
            raise
        except BaseException:
            triggered_at = self._clock_now()
            await self._request_cleanup(
                PttStopSource.WATCHDOG,
                PttSessionOutcome.CLEANUP_INCOMPLETE,
                triggered_at=triggered_at,
            )
        else:
            triggered_at = self._clock_now()
            await self._request_cleanup(
                PttStopSource.SUPERVISOR_INPUT,
                PttSessionOutcome.CANCELLED,
                triggered_at=triggered_at,
            )

    async def _watch_heartbeat(self, handshake_deadline: float) -> None:
        try:
            await self._watch_heartbeat_until_cleanup(handshake_deadline)
        except asyncio.CancelledError:
            raise
        except BaseException:
            await self._request_cleanup(
                PttStopSource.WATCHDOG,
                PttSessionOutcome.CLEANUP_INCOMPLETE,
            )

    async def _watch_heartbeat_until_cleanup(self, handshake_deadline: float) -> None:
        try:
            opened = await self._wait_event_or_cleanup(
                self._session_open,
                handshake_deadline,
                name="reachy-ptt-heartbeat-open",
            )
        except TimeoutError:
            return
        if not opened:
            return
        while True:
            async with self._guard_lock:
                last_valid = self._last_valid_core_frame
            if last_valid is None:
                return
            deadline = last_valid + _HANDSHAKE_SECONDS
            if not await self._sleep_until_or_cleanup(deadline, name="reachy-ptt-heartbeat"):
                return
            async with self._guard_lock:
                current_last_valid = self._last_valid_core_frame
                expired = (
                    current_last_valid is not None
                    and self._clock_now() >= current_last_valid + _HANDSHAKE_SECONDS
                )
            if expired:
                await self._request_cleanup(
                    PttStopSource.WATCHDOG,
                    PttSessionOutcome.SESSION_TIMEOUT,
                )
                return

    async def _watch_turn(self, turn_deadline: float) -> None:
        try:
            expired = await self._sleep_until_or_cleanup(
                turn_deadline, name="reachy-ptt-turn-watchdog"
            )
        except asyncio.CancelledError:
            raise
        except BaseException:
            await self._request_cleanup(
                PttStopSource.WATCHDOG,
                PttSessionOutcome.CLEANUP_INCOMPLETE,
            )
            return
        if expired:
            await self._request_cleanup(
                PttStopSource.WATCHDOG,
                PttSessionOutcome.SESSION_TIMEOUT,
            )

    async def _run_capture_until_cleanup(self, turn_deadline: float) -> None:
        async with self._writer_lock:
            if self._cleanup_started_at is not None:
                return
            if self._input_mode is PttInputMode.CORE_TERMINAL_TOGGLE:
                operation = self._capture_terminal_turn(turn_deadline)
            else:
                operation = self._capture_local_turn(turn_deadline)
            try:
                self._turn_task = asyncio.create_task(operation, name="reachy-ptt-turn")
            except BaseException:
                operation.close()
                raise
            turn_task = self._turn_task
        try:
            cleanup_wait = self._create_runtime_task(
                self._cleanup_requested.wait(), name="reachy-ptt-cleanup-wait"
            )
        except BaseException:
            await self._request_cleanup(
                PttStopSource.WATCHDOG,
                PttSessionOutcome.CLEANUP_INCOMPLETE,
            )
            return
        try:
            done, _pending = await asyncio.wait(
                (turn_task, cleanup_wait), return_when=asyncio.FIRST_COMPLETED
            )
            if cleanup_wait not in done:
                try:
                    turn_task.result()
                except asyncio.CancelledError:
                    raise
                except BaseException:
                    await self._request_cleanup(
                        PttStopSource.PROTOCOL_REJECTED,
                        PttSessionOutcome.CAPTURE_FAILED,
                    )
        finally:
            if not cleanup_wait.done():
                cleanup_wait.cancel()
            await asyncio.gather(cleanup_wait, return_exceptions=True)

    async def _rollback_runtime_startup(self, *, close_transport: bool) -> None:
        async with self._writer_lock:
            if self._cleanup_started_at is None:
                self._cleanup_started_at = self._clock_now()
            self._terminal = True
            self._capture_gate = False
            self._playback_gate = False
            self._writer_stopping = True
            self._clear_result = self._clear_owned_buffers()
            self._wake_blocked_normal_producers_locked()
            self._fail_queued_drafts_locked()
            self._cleanup_requested.set()
            self._writer_wakeup.set()
        owned = [
            task
            for task in (
                self._cleanup_task,
                self._writer_task,
                self._reader_task,
                self._playback_task,
                self._stop_input_task,
                self._heartbeat_task,
                self._turn_watchdog_task,
                self._turn_task,
                self._effect_join_task,
            )
            if isinstance(task, asyncio.Task) and task is not asyncio.current_task()
        ]
        for task in owned:
            task.cancel()
        cleanup_started_at = self._cleanup_started_at
        assert cleanup_started_at is not None
        teardown_deadline = cleanup_started_at + _TEARDOWN_SECONDS
        if self._clock_now() < cleanup_started_at + _CLEANUP_OBSERVATION_SECONDS:
            receipt = await self._observe_local_cleanup()
        else:
            receipt = self._build_cleanup_receipt(
                {
                    "recording": False,
                    "playback": False,
                    "motion": False,
                    "audio_reactive": False,
                }
            )
        if owned and self._clock_now() < teardown_deadline:
            with suppress(BaseException):
                await self._within_deadline(
                    self._join_tasks(owned),
                    teardown_deadline,
                    name="reachy-ptt-startup-task-join",
                    retry_factory=lambda: self._join_tasks(owned),
                    cleanup_only=True,
                )
        if close_transport and self._clock_now() < teardown_deadline:
            with suppress(BaseException):
                await self._within_deadline(
                    self._transport.close(),
                    teardown_deadline,
                    name="reachy-ptt-transport-close",
                    retry_factory=self._transport.close,
                    cleanup_only=True,
                )
        if self._decoder is not None:
            self._decoder.abort()
        self._transport_writable = False
        self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
        completed_receipt = asyncio.get_running_loop().create_future()
        completed_receipt.set_result(receipt)
        self._cleanup_task = completed_receipt

    async def _run_startup_rollback_resisting_cancellation(self, *, close_transport: bool) -> bool:
        operation = self._rollback_runtime_startup(close_transport=close_transport)
        try:
            rollback_task = self._create_runtime_task(
                operation,
                name="reachy-ptt-startup-rollback",
            )
        except BaseException:
            try:
                rollback_task = self._create_adopted_loop_task(
                    self._rollback_runtime_startup(close_transport=close_transport),
                    name="reachy-ptt-startup-rollback-fallback",
                )
            except BaseException:
                try:
                    rollback_task = self._create_direct_task(
                        self._rollback_runtime_startup(close_transport=close_transport),
                        name="reachy-ptt-startup-rollback-direct-fallback",
                    )
                except BaseException:
                    await self._rollback_runtime_startup(close_transport=close_transport)
                    return False
        cancelled = False
        while not rollback_task.done():
            try:
                await asyncio.shield(rollback_task)
            except asyncio.CancelledError:
                cancelled = True
        rollback_task.result()
        return cancelled

    async def _latch_cleanup_inline_resisting_cancellation(
        self,
        source: PttStopSource,
        outcome: PttSessionOutcome,
        triggered_at: float,
    ) -> bool:
        cancelled = False
        acquired = False
        while not acquired:
            try:
                await self._writer_lock.acquire()
            except asyncio.CancelledError:
                cancelled = True
            else:
                acquired = True
        try:
            self._latch_cleanup_locked(source, outcome, triggered_at=triggered_at)
        finally:
            self._writer_lock.release()
        return cancelled

    async def _latch_cleanup_resisting_cancellation(
        self,
        source: PttStopSource,
        outcome: PttSessionOutcome = PttSessionOutcome.CANCELLED,
    ) -> bool:
        triggered_at = self._clock_now()
        try:
            request_task = self._create_runtime_task(
                self._request_cleanup(source, outcome, triggered_at=triggered_at),
                name="reachy-ptt-cleanup-request",
            )
        except BaseException:
            return await self._latch_cleanup_inline_resisting_cancellation(
                source,
                PttSessionOutcome.CLEANUP_INCOMPLETE,
                triggered_at,
            )
        cancelled = False
        while not request_task.done():
            try:
                await asyncio.shield(request_task)
            except asyncio.CancelledError:
                cancelled = True
        request_task.result()
        return cancelled

    async def _finish_run_cleanup_resisting_cancellation(
        self,
        cleanup_task: asyncio.Future[PttSafetyReceipt],
        source: PttStopSource,
        outcome: PttSessionOutcome,
    ) -> bool:
        cancelled = await self._latch_cleanup_resisting_cancellation(source, outcome)
        try:
            await self._await_cleanup(cleanup_task)
        except asyncio.CancelledError:
            cancelled = True
        return cancelled

    async def _acquire_lifecycle_lock_resisting_cancellation(self) -> bool:
        cancelled = False
        while True:
            try:
                await self._lifecycle_lock.acquire()
            except asyncio.CancelledError:
                cancelled = True
            else:
                return cancelled

    async def stop(self, source: PttStopSource) -> PttSafetyReceipt:
        cancelled = await self._acquire_lifecycle_lock_resisting_cancellation()
        try:
            if self._cleanup_task is None:
                self._terminal = True
                self._cleanup_started_at = self._clock_now()
                self._cleanup_source = source
                self._clear_result = self._clear_owned_buffers()
                cleanup_operation = self._observe_local_cleanup()
                try:
                    self._cleanup_task = self._create_runtime_task(
                        cleanup_operation, name="reachy-ptt-cleanup"
                    )
                except BaseException:
                    fallback_operation = self._observe_local_cleanup()
                    try:
                        self._cleanup_task = self._create_runtime_task(
                            fallback_operation, name="reachy-ptt-cleanup-fallback"
                        )
                    except BaseException:
                        adopted_operation = self._observe_local_cleanup()
                        try:
                            self._cleanup_task = self._create_adopted_loop_task(
                                adopted_operation,
                                name="reachy-ptt-cleanup-inline-fallback",
                            )
                        except BaseException:
                            try:
                                self._cleanup_task = self._create_direct_task(
                                    self._observe_local_cleanup(),
                                    name="reachy-ptt-cleanup-direct-fallback",
                                )
                            except BaseException:
                                receipt = self._conservative_cleanup_receipt()
                                completed_receipt = asyncio.get_running_loop().create_future()
                                completed_receipt.set_result(receipt)
                                self._cleanup_task = completed_receipt
                runtime_cleanup = False
            else:
                runtime_cleanup = self._run_claimed and self._cleanup_started_at is None
            task = self._cleanup_task
        finally:
            self._lifecycle_lock.release()
        if runtime_cleanup:
            cancelled_during_latch = await self._latch_cleanup_resisting_cancellation(source)
            cancelled = cancelled or cancelled_during_latch
        try:
            receipt = await self._await_cleanup(task)
        except asyncio.CancelledError:
            cancelled = True
            receipt = task.result()
        if cancelled:
            raise asyncio.CancelledError
        return receipt

    async def run(self) -> PttSessionOutcome:
        async with self._lifecycle_lock:
            if self._terminal or self._run_claimed:
                raise RuntimeError("PTT session is terminal")
            self._run_claimed = True
            self._run_started_at = self._clock_now()
            if self._clock_faulted:
                cancelled = await self._run_startup_rollback_resisting_cancellation(
                    close_transport=False
                )
                if cancelled:
                    raise asyncio.CancelledError
                return self._final_outcome
            self._clear_result = self._clear_owned_buffers()
            if not self._clear_result:
                self._cleanup_started_at = self._run_started_at
                self._cleanup_source = PttStopSource.WATCHDOG
                self._semantic_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
                cancelled = await self._run_startup_rollback_resisting_cancellation(
                    close_transport=False
                )
                if cancelled:
                    raise asyncio.CancelledError from None
                return self._final_outcome
            self._guard = PttDuplexGuard(turn_id=self._turn_id, input_mode=self._input_mode)
            self._decoder = FrameDecoder()
            cleanup_operation = self._cleanup_coordinator()
            try:
                self._cleanup_task = self._create_runtime_task(
                    cleanup_operation, name="reachy-ptt-cleanup"
                )
            except BaseException:
                cancelled = await self._run_startup_rollback_resisting_cancellation(
                    close_transport=False
                )
                if cancelled:
                    raise asyncio.CancelledError from None
                return self._final_outcome
            cleanup_task = self._cleanup_task
            run_started_at = self._run_started_at
            if run_started_at is None:
                raise RuntimeError("PTT run deadline is absent")
            turn_deadline = run_started_at + _TURN_SECONDS
            handshake_deadline = run_started_at + _HANDSHAKE_SECONDS
            try:
                self._writer_task = self._create_runtime_task(
                    self._writer_loop(), name="reachy-ptt-writer"
                )
                self._playback_task = self._create_runtime_task(
                    self._playback_loop(), name="reachy-ptt-playback"
                )
                self._reader_task = self._create_runtime_task(
                    self._reader_loop(), name="reachy-ptt-reader"
                )
                if self._stop_input is not None:
                    self._stop_input_task = self._create_runtime_task(
                        self._watch_stop_input(), name="reachy-ptt-stop-input"
                    )
                self._heartbeat_task = self._create_runtime_task(
                    self._watch_heartbeat(handshake_deadline),
                    name="reachy-ptt-heartbeat-watchdog",
                )
                self._turn_watchdog_task = self._create_runtime_task(
                    self._watch_turn(turn_deadline), name="reachy-ptt-turn-watchdog"
                )
            except BaseException:
                cancelled = await self._run_startup_rollback_resisting_cancellation(
                    close_transport=True
                )
                if cancelled:
                    raise asyncio.CancelledError from None
                return self._final_outcome
        assert cleanup_task is not None
        cancelled = False
        cleanup_source = PttStopSource.SUPERVISOR_INPUT
        cleanup_outcome = PttSessionOutcome.CANCELLED
        try:
            opened = await self._wait_event_or_cleanup(
                self._session_open,
                handshake_deadline,
                name="reachy-ptt-session-open",
            )
            if opened:
                await self._enqueue_normal(
                    control=PttControl.session_ready(self._turn_id, self._input_mode),
                    absolute_deadline=handshake_deadline,
                )
                await self._run_capture_until_cleanup(turn_deadline)
            await self._await_cleanup(cleanup_task)
        except asyncio.CancelledError:
            cancelled = True
        except TimeoutError:
            cleanup_source = PttStopSource.WATCHDOG
            cleanup_outcome = PttSessionOutcome.SESSION_TIMEOUT
        except BaseException:
            cleanup_source = PttStopSource.WATCHDOG
            cleanup_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
        if not cleanup_task.done() or cancelled:
            cancelled = (
                await self._finish_run_cleanup_resisting_cancellation(
                    cleanup_task,
                    cleanup_source,
                    cleanup_outcome,
                )
                or cancelled
            )
        if cancelled:
            raise asyncio.CancelledError
        return self._final_outcome
