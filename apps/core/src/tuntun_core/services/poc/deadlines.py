"""Fail-closed absolute deadlines in the injected monotonic-clock domain."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from contextlib import suppress
from dataclasses import dataclass
from inspect import iscoroutine
from math import isfinite
from sys import exception as active_exception
from typing import Any, TypeVar, cast
from weakref import ReferenceType, ref

from .ports import MonotonicClock

_T = TypeVar("_T")
_CANCEL_OBSERVE_SECONDS = 0.05
_MAX_CLEANUP_OBSERVE_SECONDS = 4.0
_EXCEPTION_SCAN_LIMIT = 64
_CAUSE_DESCRIPTOR: Any = vars(BaseException)["__cause__"]
_CONTEXT_DESCRIPTOR: Any = vars(BaseException)["__context__"]
_TRACEBACK_DESCRIPTOR: Any = vars(BaseException)["__traceback__"]
_SUPPRESS_CONTEXT_DESCRIPTOR: Any = vars(BaseException)["__suppress_context__"]
_GROUP_MEMBERS_DESCRIPTOR: Any = vars(BaseExceptionGroup)["exceptions"]


@dataclass(frozen=True, slots=True)
class _Outcome[T]:
    value: T | None = None
    error: BaseException | None = None


@dataclass(frozen=True, slots=True)
class _CleanupReport:
    complete: bool
    fatal_error: BaseException | None = None
    cleanup_incomplete: bool = False


@dataclass(frozen=True, slots=True)
class _SettledEvidence:
    completed_at: float | None
    fatal: bool = False
    cleanup_incomplete: bool = False
    passive: bool = False


@dataclass(frozen=True, slots=True)
class _CleanupDeadline:
    absolute: float
    valid: bool


class DeadlineExceeded(TimeoutError):
    """A content-free signal that an inclusive absolute deadline expired."""

    def __init__(self) -> None:
        super().__init__("deadline-exceeded")


class DeadlineClockError(RuntimeError):
    """A content-free signal that the injected clock broke its contract."""

    def __init__(self) -> None:
        super().__init__("deadline-clock-invalid")


class DeadlineCleanupIncomplete(RuntimeError):
    """A content-free signal that cancelled deadline work did not settle in time."""

    def __init__(self) -> None:
        super().__init__("deadline-cleanup-incomplete")


async def _claim_entry_cancellation() -> asyncio.CancelledError | None:
    """Claim an owner cancellation without trusting unrelated active exceptions."""

    task = asyncio.current_task()
    if task is None or task.cancelling() == 0:
        return None
    cancellation_already_active = isinstance(active_exception(), asyncio.CancelledError)
    try:
        await asyncio.sleep(0)
    except asyncio.CancelledError as delivered:
        if cancellation_already_active:
            return asyncio.CancelledError()
        return delivered
    return asyncio.CancelledError()


def masks_cleanup_incomplete(error: BaseException) -> bool:
    """Find cleanup incompleteness in a bounded group/chain scan, failing closed on overflow."""

    pending = [error]
    seen: set[int] = set()
    inspected = 0
    while pending:
        current = pending.pop()
        identity = id(current)
        if identity in seen:
            continue
        if inspected >= _EXCEPTION_SCAN_LIMIT:
            return True
        inspected += 1
        seen.add(identity)
        if isinstance(current, DeadlineCleanupIncomplete):
            return True
        if isinstance(current, BaseExceptionGroup):
            members = cast(
                tuple[BaseException, ...],
                _GROUP_MEMBERS_DESCRIPTOR.__get__(current, BaseExceptionGroup),
            )
            if len(members) > _EXCEPTION_SCAN_LIMIT - inspected:
                return True
            pending.extend(reversed(members))
        context = cast(
            BaseException | None,
            _CONTEXT_DESCRIPTOR.__get__(current, BaseException),
        )
        cause = cast(
            BaseException | None,
            _CAUSE_DESCRIPTOR.__get__(current, BaseException),
        )
        if context is not None:
            pending.append(context)
        if cause is not None:
            pending.append(cause)
    return False


async def _capture[T](operation: Awaitable[T]) -> _Outcome[T]:
    try:
        return _Outcome(value=await operation)
    except BaseException as error:
        return _Outcome(error=error)


async def _capture_asyncio_future[T](operation: asyncio.Future[T]) -> _Outcome[T]:
    """Observe a Future through base descriptors so subclass hooks cannot forge wakeups."""

    loop = asyncio.get_running_loop()
    relay: asyncio.Future[_Outcome[T]] = loop.create_future()

    def finish(completed: asyncio.Future[T]) -> None:
        try:
            if (
                completed is not operation
                or _trusted_done(operation) is not True
                or asyncio.Future.done(relay)
            ):
                return
            try:
                if _trusted_cancelled(operation) is True:
                    _trusted_result(operation)
                terminal_error = _trusted_exception(operation)
                if terminal_error is not None:
                    outcome = _Outcome[T](error=terminal_error)
                else:
                    outcome = _Outcome(value=cast(T, _trusted_result(operation)))
            except BaseException as error:
                outcome = _Outcome[T](error=error)
            asyncio.Future.set_result(relay, outcome)
        except BaseException:
            return

    try:
        if _trusted_done(operation) is True:
            finish(operation)
        elif not _trusted_add_done_callback(operation, finish):
            return _Outcome(error=DeadlineCleanupIncomplete())
    except BaseException as error:
        return _Outcome(error=error)
    try:
        return await relay
    except BaseException as error:
        return _Outcome(error=error)


def _cleanup_error_priority(error: BaseException) -> tuple[BaseException | None, bool]:
    """Classify only safety-significant cleanup evidence."""

    if not isinstance(error, (Exception, asyncio.CancelledError, BaseExceptionGroup)):
        return error, False
    return None, masks_cleanup_incomplete(error)


def _is_scalar_fatal(error: BaseException) -> bool:
    return not isinstance(error, (Exception, asyncio.CancelledError, BaseExceptionGroup))


def _detach_exception(error: BaseException) -> bool:
    """Drop reachable chains without invoking exception-subclass attribute hooks."""

    pending = [error]
    seen: set[int] = set()
    inspected = 0
    complete = True
    while pending:
        current = pending.pop()
        identity = id(current)
        if identity in seen:
            continue
        seen.add(identity)
        if inspected >= _EXCEPTION_SCAN_LIMIT:
            complete = False
            continue
        inspected += 1
        if isinstance(current, BaseExceptionGroup):
            members = cast(
                tuple[BaseException, ...],
                _GROUP_MEMBERS_DESCRIPTOR.__get__(current, BaseExceptionGroup),
            )
            remaining = _EXCEPTION_SCAN_LIMIT - inspected
            if len(members) > remaining:
                complete = False
            pending.extend(reversed(members[:remaining]))
        context = cast(
            BaseException | None,
            _CONTEXT_DESCRIPTOR.__get__(current, BaseException),
        )
        cause = cast(
            BaseException | None,
            _CAUSE_DESCRIPTOR.__get__(current, BaseException),
        )
        if context is not None:
            pending.append(context)
        if cause is not None:
            pending.append(cause)
        _CAUSE_DESCRIPTOR.__set__(current, None)
        _CONTEXT_DESCRIPTOR.__set__(current, None)
        _TRACEBACK_DESCRIPTOR.__set__(current, None)
        _SUPPRESS_CONTEXT_DESCRIPTOR.__set__(current, True)
    return complete


def _coerce_cleanup_deadline(
    deadline: object,
    *,
    default_seconds: float | None = None,
) -> _CleanupDeadline:
    loop = asyncio.get_running_loop()
    now = loop.time()
    if deadline is None:
        if default_seconds is None:
            return _CleanupDeadline(now, False)
        return _CleanupDeadline(now + default_seconds, True)
    if type(deadline) not in (int, float):
        return _CleanupDeadline(now, False)
    typed_deadline = cast(int | float, deadline)
    try:
        absolute = float(typed_deadline)
    except (OverflowError, ValueError):
        return _CleanupDeadline(now, False)
    if (
        not isfinite(absolute)
        or (type(deadline) is int and absolute != deadline)
        or absolute - now > _MAX_CLEANUP_OBSERVE_SECONDS
    ):
        return _CleanupDeadline(now, False)
    return _CleanupDeadline(absolute, True)


def _current_task_cancelling() -> int:
    task = asyncio.current_task()
    return 0 if task is None else task.cancelling()


def _consume_current_task_cancellations_since(baseline: int) -> bool:
    task = asyncio.current_task()
    consumed = False
    while task is not None and task.cancelling() > baseline:
        task.uncancel()
        consumed = True
    return consumed


def _completed_outcome[T](task: asyncio.Future[_Outcome[T]]) -> _Outcome[T]:
    try:
        return cast(_Outcome[T], _trusted_result(task))
    except BaseException as error:
        return _Outcome(error=error)


def _detach_or_cleanup_incomplete(error: BaseException) -> None:
    if not _detach_exception(error):
        raise DeadlineCleanupIncomplete from None


def _cleanup_errors_priority(
    errors: tuple[BaseException, ...],
) -> tuple[BaseException | None, bool]:
    fatal_error: BaseException | None = None
    cleanup_incomplete = False
    for cleanup_error in errors:
        candidate_fatal, candidate_incomplete = _cleanup_error_priority(cleanup_error)
        if fatal_error is None and candidate_fatal is not None:
            fatal_error = candidate_fatal
        cleanup_incomplete = cleanup_incomplete or candidate_incomplete
    return fatal_error, cleanup_incomplete


def _cleanup_outcomes_report(
    tasks: tuple[asyncio.Future[Any], ...],
    *,
    complete: bool,
) -> _CleanupReport:
    """Return only safety-significant terminal cleanup evidence."""

    fatal_error: BaseException | None = None
    cleanup_incomplete = False
    for task in tasks:
        if not task.done() or task.cancelled():
            continue
        try:
            outcome = task.result()
        except BaseException:
            continue
        if not isinstance(outcome, _Outcome) or outcome.error is None:
            continue
        candidate_fatal, candidate_incomplete = _cleanup_error_priority(outcome.error)
        if fatal_error is None and candidate_fatal is not None:
            fatal_error = candidate_fatal
        cleanup_incomplete = cleanup_incomplete or candidate_incomplete
    return _CleanupReport(
        complete=complete,
        fatal_error=fatal_error,
        cleanup_incomplete=cleanup_incomplete,
    )


def _trusted_done(task: object) -> bool | None:
    """Read asyncio-owned state without invoking Future-subclass hooks."""

    if isinstance(task, asyncio.Task):
        return asyncio.Task.done(task)
    if isinstance(task, asyncio.Future):
        return asyncio.Future.done(task)
    return None


def _trusted_cancelled(task: object) -> bool | None:
    if isinstance(task, asyncio.Task):
        return asyncio.Task.cancelled(task)
    if isinstance(task, asyncio.Future):
        return asyncio.Future.cancelled(task)
    return None


def _trusted_exception(task: object) -> BaseException | None:
    if isinstance(task, asyncio.Task):
        return asyncio.Task.exception(task)
    if isinstance(task, asyncio.Future):
        return asyncio.Future.exception(task)
    raise asyncio.InvalidStateError


def _trusted_result(task: object) -> Any:
    if isinstance(task, asyncio.Task):
        return asyncio.Task.result(task)
    if isinstance(task, asyncio.Future):
        return asyncio.Future.result(task)
    raise asyncio.InvalidStateError


def _trusted_add_done_callback(
    task: object,
    callback: Any,
) -> bool:
    if isinstance(task, asyncio.Task):
        asyncio.Task.add_done_callback(task, callback)
        return True
    if isinstance(task, asyncio.Future):
        asyncio.Future.add_done_callback(task, callback)
        return True
    return False


class DeadlineGuard:
    """Validate one clock domain and race operations against absolute deadlines."""

    __slots__ = (
        "_clock",
        "_completion_times",
        "_fallback_quarantine",
        "_last_now",
        "_passive_quarantine",
        "_quarantine",
        "_retention_generation",
        "_settled_tombstones",
        "_tombstone_sequence",
    )

    def __init__(self, clock: MonotonicClock) -> None:
        if not isinstance(clock, MonotonicClock):
            raise ValueError("invalid-deadline-clock")
        self._clock = clock
        self._last_now: float | None = None
        self._quarantine: set[asyncio.Future[Any]] = set()
        self._fallback_quarantine: dict[int, asyncio.Future[Any]] = {}
        self._passive_quarantine: set[int] = set()
        self._settled_tombstones: dict[int, _SettledEvidence] = {}
        self._tombstone_sequence = 0
        self._retention_generation = 0
        self._completion_times: dict[
            int,
            tuple[
                ReferenceType[asyncio.Future[Any]],
                float | None,
                int,
            ],
        ] = {}

    @property
    def clock(self) -> MonotonicClock:
        return self._clock

    def _register_completion_time(
        self,
        task: asyncio.Future[Any],
    ) -> BaseException | None:
        identity = id(task)
        existing = self._completion_times.get(identity)
        if existing is not None and self._completion_owner(existing) is task:
            return None

        if _trusted_done(task) is None:
            return DeadlineCleanupIncomplete()

        def forget(_: ReferenceType[asyncio.Future[Any]]) -> None:
            self._completion_times.pop(identity, None)

        try:
            owner = ref(task, forget)
        except TypeError:
            return DeadlineCleanupIncomplete()
        self._tombstone_sequence += 1
        token = self._tombstone_sequence
        self._completion_times[identity] = (owner, None, token)
        loop = asyncio.get_running_loop()

        def record_completion(completed: asyncio.Future[Any]) -> None:
            try:
                current = self._completion_times.get(identity)
                if (
                    completed is not task
                    or current is None
                    or self._completion_owner(current) is not task
                    or _trusted_done(task) is not True
                ):
                    return
                completed_at = loop.time()
                self._completion_times[identity] = (current[0], completed_at, token)
                if self._is_retained(task):
                    passive = identity in self._passive_quarantine
                    evidence = self._settled_evidence(
                        task,
                        completed_at=completed_at,
                        passive=passive,
                    )
                    self._discard_retained(task)
                    self._settled_tombstones[token] = evidence
                else:
                    existing_evidence = self._settled_tombstones.get(token)
                    if existing_evidence is not None and existing_evidence.completed_at is None:
                        self._settled_tombstones[token] = self._settled_evidence(
                            task,
                            completed_at=completed_at,
                            passive=existing_evidence.passive,
                        )
                    else:
                        self._observe_terminal(task, passive=False)
            except BaseException:
                # Callback failures must never escape through the event loop. A
                # missing completion timestamp is handled conservatively by the
                # bounded observer that still owns ``task``.
                return

        try:
            if not _trusted_add_done_callback(task, record_completion):
                return DeadlineCleanupIncomplete()
        except BaseException as error:
            return error
        return None

    @staticmethod
    def _observe_terminal(
        task: asyncio.Future[Any],
        *,
        passive: bool,
    ) -> _CleanupReport:
        if _trusted_done(task) is not True:
            return _CleanupReport(complete=False, cleanup_incomplete=True)
        if _trusted_cancelled(task) is True:
            try:
                _trusted_result(task)
            except BaseException as error:
                fatal_error, cleanup_incomplete = _cleanup_error_priority(error)
                return _CleanupReport(
                    complete=True,
                    fatal_error=fatal_error,
                    cleanup_incomplete=cleanup_incomplete,
                )
            return _CleanupReport(complete=True)
        try:
            terminal_error = _trusted_exception(task)
            result = None if terminal_error is not None else _trusted_result(task)
        except asyncio.CancelledError:
            return _CleanupReport(complete=True)
        except BaseException as error:
            fatal_error, cleanup_incomplete = _cleanup_error_priority(error)
            return _CleanupReport(
                complete=True,
                fatal_error=fatal_error,
                cleanup_incomplete=cleanup_incomplete,
            )
        if terminal_error is None and isinstance(result, _Outcome):
            terminal_error = result.error
        elif terminal_error is None and passive and isinstance(result, BaseException):
            terminal_error = result
        if terminal_error is None:
            return _CleanupReport(complete=True)
        fatal_error, cleanup_incomplete = _cleanup_error_priority(terminal_error)
        return _CleanupReport(
            complete=True,
            fatal_error=fatal_error,
            cleanup_incomplete=cleanup_incomplete,
        )

    def _settled_evidence(
        self,
        task: asyncio.Future[Any],
        *,
        completed_at: float | None,
        passive: bool,
    ) -> _SettledEvidence:
        report = self._observe_terminal(task, passive=passive)
        fatal_error = report.fatal_error
        if fatal_error is not None:
            _detach_exception(fatal_error)
        return _SettledEvidence(
            completed_at=completed_at,
            fatal=fatal_error is not None,
            cleanup_incomplete=report.cleanup_incomplete or not report.complete,
            passive=passive,
        )

    @staticmethod
    def _completion_owner(
        entry: tuple[
            ReferenceType[asyncio.Future[Any]],
            float | None,
            int,
        ],
    ) -> asyncio.Future[Any] | None:
        return entry[0]()

    def _completion_time(self, task: asyncio.Future[Any]) -> float | None:
        current = self._completion_times.get(id(task))
        if current is None or self._completion_owner(current) is not task:
            return None
        return current[1]

    def _completion_token(self, task: asyncio.Future[Any]) -> int | None:
        current = self._completion_times.get(id(task))
        if current is None or self._completion_owner(current) is not task:
            return None
        return current[2]

    def _is_retained(self, task: asyncio.Future[Any]) -> bool:
        try:
            if task in self._quarantine:
                return True
        except BaseException:
            pass
        return self._fallback_quarantine.get(id(task)) is task

    def _discard_retained(self, task: asyncio.Future[Any]) -> None:
        with suppress(BaseException):
            self._quarantine.discard(task)
        identity = id(task)
        self._passive_quarantine.discard(identity)
        if self._fallback_quarantine.get(identity) is task:
            self._fallback_quarantine.pop(identity, None)

    def _quarantine_snapshot(self) -> tuple[asyncio.Future[Any], ...]:
        return (*self._quarantine, *self._fallback_quarantine.values())

    def _retain(self, task: asyncio.Future[Any], *, passive: bool = False) -> None:
        if self._is_retained(task):
            if passive:
                self._passive_quarantine.add(id(task))
            return
        self._register_completion_time(task)
        self._retention_generation += 1
        if passive:
            self._passive_quarantine.add(id(task))
        try:
            self._quarantine.add(task)
        except BaseException:
            self._fallback_quarantine[id(task)] = task

    def retain_passive(self, task: asyncio.Future[Any]) -> None:
        """Keep observing an untrusted-awaitable owner without cancelling it."""

        self._retain(task, passive=True)

    async def _cancel_all_until(
        self,
        *tasks: asyncio.Future[Any],
        deadline: float,
        deadline_valid: bool = True,
    ) -> _CleanupReport:
        """Fan cancellation out before observing any owned sibling."""

        normalized_deadline = _coerce_cleanup_deadline(deadline)
        deadline = normalized_deadline.absolute
        unique: list[asyncio.Future[Any]] = []
        seen: set[int] = set()
        for task in tasks:
            identity = id(task)
            if identity not in seen:
                seen.add(identity)
                unique.append(task)

        complete = deadline_valid and normalized_deadline.valid
        fatal_error: BaseException | None = None
        cleanup_incomplete = False

        def record_failure(error: BaseException) -> None:
            nonlocal complete, fatal_error, cleanup_incomplete
            complete = False
            candidate_fatal, candidate_incomplete = _cleanup_error_priority(error)
            if fatal_error is None and candidate_fatal is not None:
                fatal_error = candidate_fatal
            cleanup_incomplete = cleanup_incomplete or candidate_incomplete

        cancellation_baseline = _current_task_cancelling()

        for task in unique:
            registration_error = self._register_completion_time(task)
            if registration_error is not None:
                record_failure(registration_error)

        for task in unique:
            if _trusted_done(task) is not True:
                try:
                    task.cancel()
                except BaseException as error:
                    record_failure(error)
        if _consume_current_task_cancellations_since(cancellation_baseline):
            record_failure(DeadlineCleanupIncomplete())

        pending = [task for task in unique if _trusted_done(task) is not True]
        if pending:
            loop = asyncio.get_running_loop()
            while pending:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                try:
                    await asyncio.sleep(min(0.001, remaining))
                except asyncio.CancelledError as error:
                    _consume_current_task_cancellations_since(cancellation_baseline)
                    record_failure(error)
                    continue
                pending = [task for task in pending if _trusted_done(task) is not True]
        try:
            await asyncio.sleep(0)
        except asyncio.CancelledError as error:
            _consume_current_task_cancellations_since(cancellation_baseline)
            record_failure(error)

        for task in unique:
            if _trusted_done(task) is not True:
                self._retain(task)
                complete = False
                continue

            terminal_report = self._observe_terminal(task, passive=False)
            if fatal_error is None and terminal_report.fatal_error is not None:
                fatal_error = terminal_report.fatal_error
            cleanup_incomplete = cleanup_incomplete or terminal_report.cleanup_incomplete
            if not terminal_report.complete:
                complete = False
            identity = id(task)
            passive = identity in self._passive_quarantine
            token = self._completion_token(task)
            if self._is_retained(task):
                self._discard_retained(task)
            completed_at = self._completion_time(task)
            if completed_at is None or completed_at >= deadline:
                complete = False
                if token is None:
                    cleanup_incomplete = True
                else:
                    self._settled_tombstones[token] = self._settled_evidence(
                        task,
                        completed_at=completed_at,
                        passive=passive,
                    )
        return _CleanupReport(
            complete=complete,
            fatal_error=fatal_error,
            cleanup_incomplete=cleanup_incomplete,
        )

    async def cancel_and_observe[T](
        self,
        task: asyncio.Future[T],
        *,
        deadline: float | None = None,
    ) -> bool:
        """Cancel one owned future and observe it only to a real-loop absolute bound."""

        try:
            return await self._cancel_and_observe_owned(task, deadline=deadline)
        except BaseException as error:
            self = cast(DeadlineGuard, None)
            task = cast(asyncio.Future[T], None)
            deadline = None
            _detach_or_cleanup_incomplete(error)
            raise error from None

    async def _cancel_and_observe_owned[T](
        self,
        task: asyncio.Future[T],
        *,
        deadline: float | None = None,
    ) -> bool:
        """Apply one bounded cancellation while the public boundary owns arguments."""

        report, cancellation = await self._cancel_and_report(task, deadline=deadline)
        if cancellation is not None:
            raise cancellation
        if report.fatal_error is not None:
            raise report.fatal_error
        return report.complete and not report.cleanup_incomplete

    async def _cancel_and_report[T](
        self,
        task: asyncio.Future[T],
        *,
        deadline: float | None = None,
    ) -> tuple[_CleanupReport, asyncio.CancelledError | None]:
        """Return bounded cancellation evidence without deciding owner precedence."""

        normalized_deadline = _coerce_cleanup_deadline(
            deadline,
            default_seconds=_CANCEL_OBSERVE_SECONDS,
        )
        absolute = normalized_deadline.absolute
        first_cancellation = await _claim_entry_cancellation()
        cleanup_task = asyncio.create_task(
            self._cancel_all_until(
                task,
                deadline=absolute,
                deadline_valid=normalized_deadline.valid,
            ),
            name="deadline-cancel-one-cleanup",
        )
        report, cleanup_cancellation = await self._finish_cleanup_despite_cancellation(
            cleanup_task,
            first=first_cancellation,
        )
        return report, (
            first_cancellation if first_cancellation is not None else cleanup_cancellation
        )

    async def observe_quarantine(self, *, deadline: float) -> bool:
        """Observe retained work to a strict bound without cancelling passive owners."""

        try:
            return await self._observe_quarantine_owned(deadline=deadline)
        except BaseException as error:
            self = cast(DeadlineGuard, None)
            deadline = cast(float, None)
            _detach_or_cleanup_incomplete(error)
            raise error from None

    async def _observe_quarantine_owned(self, *, deadline: float) -> bool:
        """Observe one quarantine snapshot behind the scrubbed public boundary."""

        normalized_deadline = _coerce_cleanup_deadline(deadline)
        deadline = normalized_deadline.absolute
        retention_generation = self._retention_generation
        snapshot = self._quarantine_snapshot()
        active = tuple(task for task in snapshot if id(task) not in self._passive_quarantine)
        passive = tuple(task for task in snapshot if id(task) in self._passive_quarantine)
        first_cancellation = await _claim_entry_cancellation()

        async def cleanup() -> _CleanupReport:
            active_report = await self._cancel_all_until(
                *active,
                deadline=deadline,
                deadline_valid=normalized_deadline.valid,
            )
            passive_complete = True
            loop = asyncio.get_running_loop()
            pending = [task for task in passive if _trusted_done(task) is not True]
            while pending:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                await asyncio.sleep(min(0.001, remaining))
                pending = [task for task in pending if _trusted_done(task) is not True]
            await asyncio.sleep(0)
            for task in passive:
                if _trusted_done(task) is not True:
                    passive_complete = False
                    continue
                token = self._completion_token(task)
                completed_at = self._completion_time(task)
                if token is None:
                    passive_complete = False
                    continue
                if token not in self._settled_tombstones:
                    evidence = self._settled_evidence(
                        task,
                        completed_at=completed_at,
                        passive=True,
                    )
                    self._discard_retained(task)
                    self._settled_tombstones[token] = evidence
                if completed_at is None or completed_at >= deadline:
                    passive_complete = False
            return _CleanupReport(
                complete=active_report.complete and passive_complete,
                fatal_error=active_report.fatal_error,
                cleanup_incomplete=active_report.cleanup_incomplete,
            )

        cleanup_task = asyncio.create_task(
            cleanup(),
            name="deadline-observe-quarantine-cleanup",
        )
        report, cleanup_cancellation = await self._finish_cleanup_despite_cancellation(
            cleanup_task,
            first=first_cancellation,
        )
        if first_cancellation is not None:
            _detach_exception(first_cancellation)
            raise first_cancellation from None
        if cleanup_cancellation is not None:
            _detach_exception(cleanup_cancellation)
            raise cleanup_cancellation from None
        if report.fatal_error is not None:
            _detach_exception(report.fatal_error)
            raise report.fatal_error from None

        tombstones = tuple(self._settled_tombstones.items())
        for _, evidence in tombstones:
            if evidence.fatal:
                raise DeadlineCleanupIncomplete from None

        acknowledged = (
            normalized_deadline.valid
            and report.complete
            and not report.cleanup_incomplete
            and self._retention_generation == retention_generation
            and not self._quarantine_snapshot()
            and all(
                not evidence.cleanup_incomplete
                and evidence.completed_at is not None
                and evidence.completed_at < deadline
                for _, evidence in tombstones
            )
        )
        if acknowledged:
            for identity, evidence in tombstones:
                if self._settled_tombstones.get(identity) is evidence:
                    self._settled_tombstones.pop(identity, None)
        return acknowledged

    async def cancel_many(self, *tasks: asyncio.Future[Any]) -> bool:
        """Cancel owned futures under one real-loop cancellation-observation deadline."""

        try:
            return await self._cancel_many_owned(tasks)
        except BaseException as error:
            self = cast(DeadlineGuard, None)
            tasks = ()
            _detach_or_cleanup_incomplete(error)
            raise error from None

    async def _cancel_many_owned(
        self,
        tasks: tuple[asyncio.Future[Any], ...],
    ) -> bool:
        """Apply one fan-out cancellation behind the scrubbed public boundary."""

        first_cancellation = await _claim_entry_cancellation()

        async def cleanup() -> _CleanupReport:
            deadline = asyncio.get_running_loop().time() + _CANCEL_OBSERVE_SECONDS
            return await self._cancel_all_until(*tasks, deadline=deadline)

        cleanup_task = asyncio.create_task(cleanup(), name="deadline-cancel-many-cleanup")
        report, cleanup_cancellation = await self._finish_cleanup_despite_cancellation(
            cleanup_task,
            first=first_cancellation,
        )
        if first_cancellation is not None:
            raise first_cancellation
        if cleanup_cancellation is not None:
            raise cleanup_cancellation
        if report.fatal_error is not None:
            raise report.fatal_error
        return report.complete and not report.cleanup_incomplete

    @staticmethod
    async def _finish_cleanup_despite_cancellation(
        task: asyncio.Task[_CleanupReport],
        *,
        first: asyncio.CancelledError | None,
    ) -> tuple[_CleanupReport, asyncio.CancelledError | None]:
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError as error:
                owner = asyncio.current_task()
                if owner is not None and owner.cancelling() > 0 and first is None:
                    if not task.done():
                        first = error
                    else:
                        claimed = await _claim_entry_cancellation()
                        first = claimed if claimed is not None else asyncio.CancelledError()
        try:
            return task.result(), first
        except BaseException as error:
            if first is not None:
                _detach_exception(first)
                raise first from None
            if isinstance(error, asyncio.CancelledError):
                return _CleanupReport(complete=False, cleanup_incomplete=True), None
            raise

    async def _discard[T](
        self,
        operation: Awaitable[T],
        *,
        deadline: float,
        owner_cancellation: asyncio.CancelledError | None = None,
    ) -> _CleanupReport:
        """Dispose of work that cannot safely be admitted to the event loop."""

        normalized_deadline = _coerce_cleanup_deadline(deadline)
        deadline = normalized_deadline.absolute
        first_cancellation = (
            owner_cancellation
            if owner_cancellation is not None
            else await _claim_entry_cancellation()
        )

        async def dispose() -> _CleanupReport:
            setup_errors: list[BaseException] = []
            terminal_errors: list[BaseException] = []
            discarded_future: asyncio.Future[Any] | None = None
            cancel_report = _CleanupReport(complete=True)
            if isinstance(operation, asyncio.Future):
                if _trusted_done(operation) is not True:
                    self.retain_passive(operation)
                    return _CleanupReport(
                        complete=False,
                        cleanup_incomplete=True,
                    )
                return self._observe_terminal(operation, passive=True)
            if iscoroutine(operation):
                try:
                    operation.close()
                except BaseException as error:
                    setup_errors.append(error)
                if operation.cr_frame is not None:
                    try:
                        discarded_future = asyncio.ensure_future(operation)
                    except BaseException as error:
                        setup_errors.append(error)
            else:
                try:
                    discarded_future = asyncio.ensure_future(operation)
                except BaseException as error:
                    setup_errors.append(error)
            if discarded_future is not None:
                cancel_report = await self._cancel_all_until(
                    discarded_future,
                    deadline=deadline,
                    deadline_valid=normalized_deadline.valid,
                )
                if _trusted_done(discarded_future) is True:
                    try:
                        _trusted_result(discarded_future)
                    except BaseException as error:
                        terminal_errors.append(error)
            setup_fatal, setup_incomplete = _cleanup_errors_priority(tuple(setup_errors))
            terminal_fatal, terminal_incomplete = _cleanup_errors_priority(tuple(terminal_errors))
            setup_errors.clear()
            terminal_errors.clear()
            discarded_future = None
            return _CleanupReport(
                complete=cancel_report.complete,
                fatal_error=(
                    setup_fatal
                    if setup_fatal is not None
                    else (
                        cancel_report.fatal_error
                        if cancel_report.fatal_error is not None
                        else terminal_fatal
                    )
                ),
                cleanup_incomplete=(
                    setup_incomplete or cancel_report.cleanup_incomplete or terminal_incomplete
                ),
            )

        cleanup_task = asyncio.create_task(dispose(), name="deadline-discard-cleanup")
        report, cleanup_cancellation = await self._finish_cleanup_despite_cancellation(
            cleanup_task,
            first=first_cancellation,
        )
        if first_cancellation is not None:
            raise first_cancellation
        if first_cancellation is None and cleanup_cancellation is not None:
            raise cleanup_cancellation
        return report

    def now(self) -> float:
        signal: str | None = None
        try:
            candidate = self._clock.now()
        except BaseException as error:
            if _is_scalar_fatal(error):
                raise
            signal = "cleanup-incomplete" if masks_cleanup_incomplete(error) else "clock-error"
            candidate = 0.0
        if signal == "cleanup-incomplete":
            raise DeadlineCleanupIncomplete from None
        if signal == "clock-error":
            raise DeadlineClockError from None
        if type(candidate) not in (int, float):
            raise DeadlineClockError
        try:
            value = float(candidate)
        except (OverflowError, ValueError):
            raise DeadlineClockError from None
        if (
            not isfinite(value)
            or (type(candidate) is int and value != candidate)
            or (self._last_now is not None and value < self._last_now)
        ):
            raise DeadlineClockError
        self._last_now = value
        return value

    def deadline_after(self, seconds: float) -> float:
        if type(seconds) not in (int, float):
            raise ValueError("invalid-deadline-duration")
        try:
            duration = float(seconds)
        except (OverflowError, ValueError):
            raise ValueError("invalid-deadline-duration") from None
        if (
            not isfinite(duration)
            or duration <= 0
            or (type(seconds) is int and duration != seconds)
        ):
            raise ValueError("invalid-deadline-duration")
        deadline = self.now() + duration
        if not isfinite(deadline):
            raise DeadlineClockError
        return deadline

    async def run(self, operation: Awaitable[_T], *, deadline: float) -> _T:
        """Return only work completed strictly before ``deadline``."""

        try:
            return await self._run_public_owned(operation, deadline=deadline)
        except BaseException as error:
            self = cast(DeadlineGuard, None)
            operation = cast(Awaitable[_T], None)
            deadline = cast(float, None)
            _detach_or_cleanup_incomplete(error)
            raise error from None

    async def _run_public_owned(
        self,
        operation: Awaitable[_T],
        *,
        deadline: float,
    ) -> _T:
        """Apply public deadline semantics behind the scrubbed argument boundary."""

        signal: str | None = None
        owner = asyncio.current_task()
        if operation is owner:
            external_cancellation = await _claim_entry_cancellation()
            if external_cancellation is not None:
                operation = cast(Awaitable[_T], None)
                _detach_exception(external_cancellation)
                raise external_cancellation from None
            operation = cast(Awaitable[_T], None)
            raise DeadlineCleanupIncomplete from None
        try:
            return await self._run_owned(operation, deadline=deadline)
        except asyncio.CancelledError as error:
            task = asyncio.current_task()
            if task is not None and task.cancelling() > 0:
                operation = cast(Awaitable[_T], None)
                _detach_exception(error)
            raise
        except DeadlineCleanupIncomplete:
            signal = "cleanup-incomplete"
        except DeadlineClockError:
            signal = "clock-error"
        except DeadlineExceeded:
            signal = "deadline-exceeded"
        except BaseException as error:
            if not _is_scalar_fatal(error):
                raise
            operation = cast(Awaitable[_T], None)
            _detach_exception(error)
            raise error from None
        operation = cast(Awaitable[_T], None)
        if signal == "cleanup-incomplete":
            raise DeadlineCleanupIncomplete from None
        if signal == "clock-error":
            raise DeadlineClockError from None
        raise DeadlineExceeded from None

    async def _run_owned(self, operation: Awaitable[_T], *, deadline: float) -> _T:
        """Run one operation while retaining ownership through bounded cleanup."""

        loop = asyncio.get_running_loop()
        entry_cancellation = await _claim_entry_cancellation()
        if entry_cancellation is not None:
            await self._discard(
                operation,
                deadline=loop.time() + _CANCEL_OBSERVE_SECONDS,
                owner_cancellation=entry_cancellation,
            )
            raise entry_cancellation

        valid = False
        absolute = 0.0
        if type(deadline) in (int, float):
            try:
                absolute = float(deadline)
                valid = isfinite(absolute) and not (type(deadline) is int and absolute != deadline)
            except (OverflowError, ValueError):
                pass
        if not valid:
            report = await self._discard(
                operation,
                deadline=loop.time() + _CANCEL_OBSERVE_SECONDS,
            )
            if report.fatal_error is not None:
                raise report.fatal_error
            if report.cleanup_incomplete or not report.complete:
                raise DeadlineCleanupIncomplete
            raise DeadlineClockError

        try:
            observed = self.now()
        except BaseException as admission_error:
            report = await self._discard(
                operation,
                deadline=loop.time() + _CANCEL_OBSERVE_SECONDS,
            )
            if _is_scalar_fatal(admission_error):
                raise admission_error
            if report.fatal_error is not None:
                raise report.fatal_error from None
            if (
                masks_cleanup_incomplete(admission_error)
                or report.cleanup_incomplete
                or not report.complete
            ):
                raise DeadlineCleanupIncomplete from None
            raise admission_error
        if observed >= absolute:
            report = await self._discard(
                operation,
                deadline=loop.time() + _CANCEL_OBSERVE_SECONDS,
            )
            if report.fatal_error is not None:
                raise report.fatal_error
            if report.cleanup_incomplete or not report.complete:
                raise DeadlineCleanupIncomplete
            raise DeadlineExceeded

        operation_started = False
        owned_future = operation if isinstance(operation, (asyncio.Future, asyncio.Task)) else None

        async def capture() -> _Outcome[_T]:
            nonlocal operation_started
            operation_started = True
            if owned_future is not None:
                return await _capture_asyncio_future(owned_future)
            return await _capture(operation)

        async def capture_timer() -> _Outcome[None]:
            try:
                sleeper = self._clock.sleep_until(absolute)
            except BaseException as error:
                return _Outcome(error=error)
            return await _capture(cast(Awaitable[None], sleeper))

        work = asyncio.ensure_future(capture())
        timer: asyncio.Future[_Outcome[None]] | None = None
        first_cancellation: asyncio.CancelledError | None = None
        try:
            timer_task = asyncio.ensure_future(capture_timer())
            timer = timer_task
            raced: set[asyncio.Future[Any]] = {work, timer_task}
            done, _ = await asyncio.wait(
                raced,
                return_when=asyncio.FIRST_COMPLETED,
            )

            timer_outcome = _completed_outcome(timer_task) if timer_task in done else None
            work_outcome = _completed_outcome(work) if work in done else None
            for candidate in (timer_outcome, work_outcome):
                if (
                    candidate is not None
                    and candidate.error is not None
                    and _is_scalar_fatal(candidate.error)
                ):
                    raise candidate.error
            observed = self.now()
            if timer_task in done:
                if timer_outcome is None:
                    raise DeadlineClockError
                if timer_outcome.error is not None:
                    if masks_cleanup_incomplete(timer_outcome.error):
                        raise DeadlineCleanupIncomplete
                    raise DeadlineClockError
                if timer_outcome.value is not None:
                    raise DeadlineClockError
                if observed < absolute:
                    raise DeadlineClockError
                raise DeadlineExceeded

            if observed >= absolute:
                raise DeadlineExceeded
            if work_outcome is None:
                raise DeadlineCleanupIncomplete
            if work_outcome.error is not None:
                if isinstance(work_outcome.error, asyncio.CancelledError):
                    raise DeadlineCleanupIncomplete from None
                raise work_outcome.error
            return work_outcome.value  # type: ignore[return-value]
        except asyncio.CancelledError as error:
            task = asyncio.current_task()
            if task is not None and task.cancelling() > 0:
                first_cancellation = error
            raise
        finally:
            primary_failure = active_exception()

            async def cleanup() -> _CleanupReport:
                cleanup_deadline = loop.time() + _CANCEL_OBSERVE_SECONDS
                if owned_future is None:
                    active: tuple[asyncio.Future[Any], ...] = (
                        (work,) if timer is None else (timer, work)
                    )
                    cancel_report = await self._cancel_all_until(
                        *active,
                        deadline=cleanup_deadline,
                    )
                    outcome_report = _cleanup_outcomes_report(
                        active,
                        complete=cancel_report.complete,
                    )
                else:
                    active = () if timer is None else (timer,)
                    cancel_report = await self._cancel_all_until(
                        *active,
                        deadline=cleanup_deadline,
                    )
                    if _trusted_done(work) is True:
                        outcome_report = _cleanup_outcomes_report(
                            (work,),
                            complete=True,
                        )
                    else:
                        self.retain_passive(work)
                        outcome_report = _CleanupReport(
                            complete=False,
                            cleanup_incomplete=True,
                        )
                report = _CleanupReport(
                    complete=cancel_report.complete and outcome_report.complete,
                    fatal_error=(
                        cancel_report.fatal_error
                        if cancel_report.fatal_error is not None
                        else outcome_report.fatal_error
                    ),
                    cleanup_incomplete=(
                        cancel_report.cleanup_incomplete or outcome_report.cleanup_incomplete
                    ),
                )
                if not operation_started and owned_future is None:
                    discard_report = await self._discard(operation, deadline=cleanup_deadline)
                    report = _CleanupReport(
                        complete=report.complete and discard_report.complete,
                        fatal_error=(
                            report.fatal_error
                            if report.fatal_error is not None
                            else discard_report.fatal_error
                        ),
                        cleanup_incomplete=(
                            report.cleanup_incomplete or discard_report.cleanup_incomplete
                        ),
                    )
                if self._quarantine_snapshot() or self._settled_tombstones:
                    report = _CleanupReport(
                        complete=False,
                        fatal_error=report.fatal_error,
                        cleanup_incomplete=True,
                    )
                return report

            cleanup_task = asyncio.create_task(cleanup(), name="deadline-owned-cleanup")
            report, cleanup_cancellation = await self._finish_cleanup_despite_cancellation(
                cleanup_task,
                first=first_cancellation,
            )
            if first_cancellation is None and cleanup_cancellation is not None:
                raise cleanup_cancellation
            if first_cancellation is None:
                if primary_failure is not None and _is_scalar_fatal(primary_failure):
                    pass
                elif report.fatal_error is not None:
                    raise report.fatal_error
                elif (
                    (primary_failure is not None and masks_cleanup_incomplete(primary_failure))
                    or report.cleanup_incomplete
                    or not report.complete
                ):
                    raise DeadlineCleanupIncomplete
