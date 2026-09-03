from __future__ import annotations

import asyncio
import gc
import sys
from collections.abc import Awaitable, Coroutine
from contextlib import suppress
from typing import Any, cast
from weakref import ref

import pytest
from tuntun_core.services.poc import deadlines as deadline_module
from tuntun_core.services.poc.deadlines import (
    DeadlineCleanupIncomplete,
    DeadlineClockError,
    DeadlineExceeded,
    DeadlineGuard,
    masks_cleanup_incomplete,
)


class _FatalProbe(BaseException):
    pass


class _HookedFatal(BaseException):
    def __setattr__(self, name: str, value: object) -> None:
        if name in {"__cause__", "__context__", "__traceback__", "__suppress_context__"}:
            raise RuntimeError(f"private-hook-{name}")
        super().__setattr__(name, value)


class _Clock:
    def __init__(self, *, now: float = 0.0, wake_at: float | None = None) -> None:
        self.current = now
        self.wake_at = wake_at
        self.sleep_entered = asyncio.Event()
        self.release_sleep = asyncio.Event()

    def now(self) -> float:
        return self.current

    async def sleep_until(self, deadline: float) -> None:
        self.sleep_entered.set()
        await self.release_sleep.wait()
        self.current = deadline if self.wake_at is None else self.wake_at


async def _forever(finalized: asyncio.Event) -> None:
    try:
        await asyncio.Event().wait()
    finally:
        finalized.set()


async def _raise_private_operation_error() -> None:
    raise RuntimeError("private-operation-error")


async def _raise_private_operation_cancellation() -> None:
    raise asyncio.CancelledError("private-operation-cancellation")


async def _raise(error: BaseException) -> None:
    raise error


async def _replace_cancellation(error: BaseException, entered: asyncio.Event) -> None:
    entered.set()
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        raise error from None


async def _replace_cancellation_with_private_buffer(
    error: BaseException,
    entered: asyncio.Event,
    private_buffer: bytearray,
) -> None:
    entered.set()
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        assert private_buffer
        raise error from None


async def _delay_replacement_after_cancellation(
    error: BaseException,
    entered: asyncio.Event,
    cancelled: asyncio.Event,
    release: asyncio.Event,
) -> None:
    entered.set()
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        cancelled.set()
        await release.wait()
        raise error from None


async def _chain_cleanup_incomplete_on_cancellation(entered: asyncio.Event) -> None:
    entered.set()
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError as error:
        error.__cause__ = DeadlineCleanupIncomplete()
        raise


def _coroutine(value: Any) -> Coroutine[Any, Any, Any]:
    async def return_value() -> Any:
        return value

    return return_value()


def _started_coroutine_whose_close_raises(
    error: BaseException | None = None,
) -> Coroutine[Any, Any, None]:
    close_error = error if error is not None else RuntimeError("private-close-failure")

    async def close_failure() -> None:
        try:
            await asyncio.Event().wait()
        finally:
            raise close_error

    operation = close_failure()
    operation.send(None)
    return operation


class _MisleadingCloseAwaitable:
    def __init__(self, *, async_close: bool) -> None:
        self.async_close = async_close
        self.close_calls = 0
        self.started = False

    def __await__(self) -> Any:
        self.started = True

        async def wait_forever() -> None:
            await asyncio.Event().wait()

        return wait_forever().__await__()

    def close(self) -> Awaitable[None] | None:
        self.close_calls += 1
        if not self.async_close:
            raise RuntimeError("private-close-failure")

        async def misleading_close() -> None:
            await asyncio.Event().wait()

        return misleading_close()


async def _swallow_one_cancellation(finalized: asyncio.Event) -> None:
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        pass
    finally:
        finalized.set()


async def _suppress_cancellation_until_released(
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


class _CancellationSuppressingClock(_Clock):
    def __init__(self) -> None:
        super().__init__()
        self.cancelled = asyncio.Event()

    async def sleep_until(self, deadline: float) -> None:
        self.sleep_entered.set()
        while not self.release_sleep.is_set():
            try:
                await self.release_sleep.wait()
            except asyncio.CancelledError:
                self.cancelled.set()


class _GroupedSleeperClock(_Clock):
    async def sleep_until(self, deadline: float) -> None:
        raise BaseExceptionGroup(
            "private-clock-group",
            [
                asyncio.CancelledError("private-clock-cancellation"),
                RuntimeError("private-clock-error"),
            ],
        )


class _GroupedNowClock(_Clock):
    def now(self) -> float:
        raise BaseExceptionGroup(
            "private-clock-group",
            [
                asyncio.CancelledError("private-clock-cancellation"),
                RuntimeError("private-clock-error"),
            ],
        )


class _SynchronousSleeperFailureClock(_Clock):
    def sleep_until(self, deadline: float) -> None:  # type: ignore[override]
        raise RuntimeError("private-sleeper-failure")


class _SynchronousSleeperCancellationClock(_Clock):
    def sleep_until(self, deadline: float) -> None:  # type: ignore[override]
        raise asyncio.CancelledError("private-sleeper-cancellation")


class _SynchronousNowCancellationClock(_Clock):
    def now(self) -> float:
        raise asyncio.CancelledError("private-now-cancellation")


class _NowErrorClock(_Clock):
    def __init__(self, error: BaseException) -> None:
        super().__init__()
        self.error = error

    def now(self) -> float:
        raise self.error


class _SynchronousSleeperErrorClock(_Clock):
    def __init__(self, error: BaseException) -> None:
        super().__init__()
        self.error = error

    def sleep_until(self, deadline: float) -> None:  # type: ignore[override]
        raise self.error


class _AsynchronousSleeperErrorClock(_Clock):
    def __init__(self, error: BaseException) -> None:
        super().__init__()
        self.error = error

    async def sleep_until(self, deadline: float) -> None:
        raise self.error


class _CancellationReplacingSleeperClock(_Clock):
    def __init__(self, error: BaseException) -> None:
        super().__init__()
        self.error = error
        self.cancelled = asyncio.Event()

    async def sleep_until(self, deadline: float) -> None:
        self.sleep_entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled.set()
            raise self.error from None


class _CancelRaisesFuture(asyncio.Future[str]):
    def __init__(self, error: BaseException) -> None:
        super().__init__()
        self.error = error
        self.cancel_calls = 0
        self.cancel_entered = asyncio.Event()

    def cancel(self, msg: object | None = None) -> bool:
        self.cancel_calls += 1
        self.cancel_entered.set()
        raise self.error


class _UnhashableFuture(asyncio.Future[str]):
    __hash__ = None  # type: ignore[assignment]


class _AddCallbackRaisesFuture(asyncio.Future[str]):
    def add_done_callback(self, fn: Any, *, context: object | None = None) -> None:
        raise RuntimeError("private-hostile-add-callback")


class _DoneRaisesFuture(asyncio.Future[str]):
    def __init__(self) -> None:
        super().__init__()
        self.cancel_calls = 0

    def done(self) -> bool:
        raise RuntimeError("private-hostile-done")

    def cancel(self, msg: object | None = None) -> bool:
        self.cancel_calls += 1
        return asyncio.Future.cancel(self, msg)


class _CancelledRaisesFuture(asyncio.Future[str]):
    def cancelled(self) -> bool:
        raise RuntimeError("private-hostile-cancelled")


class _ExceptionRaisesAfterSettlingFuture(asyncio.Future[str]):
    def cancel(self, msg: object | None = None) -> bool:
        self.set_result("settled")
        return False

    def exception(self) -> BaseException | None:
        raise KeyboardInterrupt("private-hostile-exception")


class _FalseDoneFuture(asyncio.Future[str]):
    def __init__(self) -> None:
        super().__init__()
        self.cancel_calls = 0

    def done(self) -> bool:
        return True

    def cancel(self, msg: object | None = None) -> bool:
        self.cancel_calls += 1
        return asyncio.Future.cancel(self, msg)


class _ImmediateFalseCallbackFuture(asyncio.Future[str]):
    def __init__(self) -> None:
        super().__init__()
        self.callback_calls = 0

    def add_done_callback(self, fn: Any, *, context: object | None = None) -> None:
        self.callback_calls += 1
        fn(self)


class _ForeignAsyncCallbackFuture(asyncio.Future[str]):
    def __init__(self) -> None:
        super().__init__()
        self.callback_calls = 0

    def add_done_callback(self, fn: Any, *, context: object | None = None) -> None:
        self.callback_calls += 1
        asyncio.get_running_loop().call_soon(fn, object(), context=context)


class _SilentCallbackFuture(asyncio.Future[str]):
    def __init__(self) -> None:
        super().__init__()
        self.callback_calls = 0

    def add_done_callback(self, fn: Any, *, context: object | None = None) -> None:
        self.callback_calls += 1


class _UnweakrefableFutureLike:
    __slots__ = ("_asyncio_future_blocking", "cancel_calls")

    def __init__(self) -> None:
        self._asyncio_future_blocking = False
        self.cancel_calls = 0

    def get_loop(self) -> asyncio.AbstractEventLoop:
        return asyncio.get_running_loop()

    def add_done_callback(self, fn: Any, *, context: object | None = None) -> None:
        del fn, context

    def remove_done_callback(self, fn: Any) -> int:
        del fn
        return 0

    def done(self) -> bool:
        return False

    def cancelled(self) -> bool:
        return False

    def cancel(self, msg: object | None = None) -> bool:
        del msg
        self.cancel_calls += 1
        return False

    def result(self) -> str:
        raise asyncio.InvalidStateError

    def exception(self) -> BaseException | None:
        raise asyncio.InvalidStateError

    def __await__(self) -> Any:
        yield self
        return "settled"


class _CancelRaisesAfterSettlingFuture(asyncio.Future[str]):
    def __init__(self, first: BaseException, second: BaseException) -> None:
        super().__init__()
        self.first = first
        self.second = second

    def cancel(self, msg: object | None = None) -> bool:
        self.set_exception(self.second)
        raise self.first


class _UncalledHostileNowClock(_Clock):
    def __init__(self) -> None:
        super().__init__()
        self.now_calls = 0
        self.sleep_calls = 0

    def now(self) -> float:
        self.now_calls += 1
        raise AssertionError("active cancellation reached injected clock")

    async def sleep_until(self, deadline: float) -> None:
        self.sleep_calls += 1
        raise AssertionError("active cancellation reached injected sleeper")


class _ExplodingDeadline:
    def __init__(self) -> None:
        self.float_calls = 0

    def __float__(self) -> float:
        self.float_calls += 1
        raise RuntimeError("private-deadline")


class _HostileFloat(float):
    def __new__(cls) -> _HostileFloat:
        return float.__new__(cls, 1_000_000.0)

    def __sub__(self, other: object) -> float:
        del other
        raise RuntimeError("private-hostile-deadline-sub")


class _SelfCancellingCancelFuture(asyncio.Future[str]):
    def __init__(self) -> None:
        super().__init__()
        self.cancel_calls = 0

    def cancel(self, msg: object | None = None) -> bool:
        del msg
        self.cancel_calls += 1
        current = asyncio.current_task()
        assert current is not None
        current.cancel("private-cleanup-self-cancel")
        return False


class _SelfCancellingSleeperClock(_Clock):
    async def sleep_until(self, deadline: float) -> None:
        del deadline
        current = asyncio.current_task()
        assert current is not None
        current.cancel("private-timer-self-cancel")


def test_cleanup_incomplete_scan_bypasses_exception_subclass_hooks() -> None:
    hooks: list[str] = []

    class HookedError(RuntimeError):
        @property
        def __cause__(self) -> BaseException | None:
            hooks.append("cause")
            raise AssertionError("exception hook executed")

        @property
        def __context__(self) -> BaseException | None:
            hooks.append("context")
            raise AssertionError("exception hook executed")

    class HookedGroup(BaseExceptionGroup):
        @property
        def exceptions(self) -> tuple[BaseException, ...]:
            hooks.append("exceptions")
            raise AssertionError("exception hook executed")

    assert not masks_cleanup_incomplete(HookedError())
    assert masks_cleanup_incomplete(HookedGroup("private-group", [DeadlineCleanupIncomplete()]))
    assert hooks == []


def _private_traceback_error(message: str) -> RuntimeError:
    private_marker = bytearray(f"private-traceback-{message}".encode())
    try:
        assert private_marker
        raise RuntimeError(message)
    except RuntimeError as error:
        assert error.__traceback__ is not None
        return error


async def _raise_oversized_private_group() -> None:
    members = [
        RuntimeError(f"private-overflow-member-{index}")
        for index in range(deadline_module._EXCEPTION_SCAN_LIMIT + 1)  # noqa: SLF001
    ]
    raise ExceptionGroup("private-overflow-group", members)


def test_detach_exception_clears_exception_group_members_and_chains() -> None:
    member = _private_traceback_error("private-member")
    chained = _private_traceback_error("private-chained")
    chained.__cause__ = _private_traceback_error("private-cause")
    chained.__context__ = _private_traceback_error("private-context")
    group = ExceptionGroup("private-group", [member, chained])

    deadline_module._detach_exception(group)  # noqa: SLF001 - privacy sanitizer regression

    assert group.__cause__ is None
    assert group.__context__ is None
    assert group.__traceback__ is None
    for error in (member, chained):
        assert error.__cause__ is None
        assert error.__context__ is None
        assert error.__traceback__ is None


def test_detach_exception_bounds_oversized_group_traversal() -> None:
    member = RuntimeError("private-repeated-member")
    group = ExceptionGroup(
        "private-oversized-group",
        [member] * (deadline_module._EXCEPTION_SCAN_LIMIT * 100),  # noqa: SLF001
    )
    traced_lines = 0
    target_code = deadline_module._detach_exception.__code__  # noqa: SLF001
    previous_trace = sys.gettrace()

    def count_target_lines(frame: Any, event: str, arg: object) -> Any:
        del arg
        nonlocal traced_lines
        if frame.f_code is target_code and event == "line":
            traced_lines += 1
        return count_target_lines

    sys.settrace(count_target_lines)
    try:
        assert not deadline_module._detach_exception(group)  # noqa: SLF001
    finally:
        sys.settrace(previous_trace)

    assert traced_lines <= deadline_module._EXCEPTION_SCAN_LIMIT * 20  # noqa: SLF001


@pytest.mark.asyncio
async def test_oversized_exception_group_becomes_content_free_cleanup_failure() -> None:
    guard = DeadlineGuard(_Clock())

    with pytest.raises(
        DeadlineCleanupIncomplete,
        match="^deadline-cleanup-incomplete$",
    ) as failure:
        await guard.run(_raise_oversized_private_group(), deadline=5.0)

    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert "private-overflow" not in repr(failure.value)


@pytest.mark.asyncio
async def test_deadline_guard_returns_only_a_result_strictly_before_deadline() -> None:
    clock = _Clock(now=10.0)
    guard = DeadlineGuard(clock)

    assert guard.deadline_after(5.0) == 15.0
    assert await guard.run(_coroutine("ok"), deadline=15.0) == "ok"


@pytest.mark.asyncio
async def test_deadline_guard_treats_the_exact_deadline_as_expired_and_cancels_work() -> None:
    clock = _Clock()
    guard = DeadlineGuard(clock)
    finalized = asyncio.Event()
    operation = asyncio.create_task(guard.run(_forever(finalized), deadline=5.0))
    await clock.sleep_entered.wait()

    clock.release_sleep.set()

    with pytest.raises(DeadlineExceeded, match="^deadline-exceeded$"):
        await operation
    assert finalized.is_set()


@pytest.mark.asyncio
async def test_timer_cleanup_preserves_cleanup_incomplete_from_cancelled_work() -> None:
    clock = _Clock()
    guard = DeadlineGuard(clock)
    entered = asyncio.Event()
    run = asyncio.create_task(
        guard.run(
            _replace_cancellation(DeadlineCleanupIncomplete(), entered),
            deadline=5.0,
        )
    )
    await entered.wait()
    await clock.sleep_entered.wait()

    clock.release_sleep.set()

    with pytest.raises(
        DeadlineCleanupIncomplete,
        match="^deadline-cleanup-incomplete$",
    ) as error:
        await run
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert guard._quarantine == set()  # noqa: SLF001 - all owned work settled


@pytest.mark.asyncio
async def test_timer_cleanup_does_not_promote_ordinary_error_from_cancelled_work() -> None:
    clock = _Clock()
    guard = DeadlineGuard(clock)
    entered = asyncio.Event()
    run = asyncio.create_task(
        guard.run(
            _replace_cancellation(RuntimeError("private-cleanup-error"), entered),
            deadline=5.0,
        )
    )
    await entered.wait()
    await clock.sleep_entered.wait()

    clock.release_sleep.set()

    with pytest.raises(DeadlineExceeded, match="^deadline-exceeded$") as error:
        await run
    assert error.value.__cause__ is None
    assert "private-cleanup-error" not in repr(error.value)


@pytest.mark.asyncio
async def test_timer_cleanup_preserves_scalar_fatal_from_cancelled_work() -> None:
    clock = _Clock()
    guard = DeadlineGuard(clock)
    entered = asyncio.Event()
    fatal = KeyboardInterrupt("private-cleanup-fatal")

    async def expire() -> None:
        await entered.wait()
        await clock.sleep_entered.wait()
        clock.release_sleep.set()

    expiry = asyncio.create_task(expire())
    with pytest.raises(KeyboardInterrupt) as error:
        await guard.run(
            _replace_cancellation(fatal, entered),
            deadline=5.0,
        )
    await expiry
    assert error.value is fatal


@pytest.mark.parametrize(
    "cleanup_error",
    (
        ExceptionGroup(
            "private-cleanup-group",
            [RuntimeError("private-cleanup-error"), DeadlineCleanupIncomplete()],
        ),
        BaseExceptionGroup(
            "private-cleanup-base-group",
            [asyncio.CancelledError("private-cleanup-cancel"), DeadlineCleanupIncomplete()],
        ),
    ),
)
@pytest.mark.asyncio
async def test_timer_cleanup_preserves_grouped_cleanup_incomplete_from_cancelled_work(
    cleanup_error: BaseException,
) -> None:
    clock = _Clock()
    guard = DeadlineGuard(clock)
    entered = asyncio.Event()
    run = asyncio.create_task(
        guard.run(
            _replace_cancellation(cleanup_error, entered),
            deadline=5.0,
        )
    )
    await entered.wait()
    await clock.sleep_entered.wait()

    clock.release_sleep.set()

    with pytest.raises(
        DeadlineCleanupIncomplete,
        match="^deadline-cleanup-incomplete$",
    ) as error:
        await run
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


@pytest.mark.asyncio
async def test_timer_cleanup_contains_fatal_only_group_from_cancelled_work() -> None:
    clock = _Clock()
    guard = DeadlineGuard(clock)
    entered = asyncio.Event()
    run = asyncio.create_task(
        guard.run(
            _replace_cancellation(
                BaseExceptionGroup(
                    "private-cleanup-base-group",
                    [KeyboardInterrupt("private-cleanup-fatal")],
                ),
                entered,
            ),
            deadline=5.0,
        )
    )
    await entered.wait()
    await clock.sleep_entered.wait()

    clock.release_sleep.set()

    with pytest.raises(DeadlineExceeded, match="^deadline-exceeded$") as error:
        await run
    assert error.value.__cause__ is None
    assert "private-cleanup" not in repr(error.value)


@pytest.mark.asyncio
async def test_external_cancellation_precedes_cleanup_incomplete_from_cancelled_work() -> None:
    clock = _Clock()
    guard = DeadlineGuard(clock)
    entered = asyncio.Event()
    run = asyncio.create_task(
        guard.run(
            _replace_cancellation(DeadlineCleanupIncomplete(), entered),
            deadline=5.0,
        )
    )
    await entered.wait()
    await clock.sleep_entered.wait()

    run.cancel("owner-cancel")

    with pytest.raises(asyncio.CancelledError) as cancellation:
        await run
    assert cancellation.value.args == ("owner-cancel",)
    assert guard._quarantine == set()  # noqa: SLF001 - all owned work settled


@pytest.mark.parametrize(
    "cleanup_error",
    (DeadlineCleanupIncomplete(), KeyboardInterrupt("private-cleanup-fatal")),
    ids=("cleanup-incomplete", "fatal"),
)
@pytest.mark.asyncio
async def test_owner_cancellation_during_cleanup_join_precedes_child_cleanup_outcome(
    cleanup_error: BaseException,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deadline_module, "_CANCEL_OBSERVE_SECONDS", 0.1, raising=False)
    clock = _Clock()
    guard = DeadlineGuard(clock)
    entered = asyncio.Event()
    child_cancelled = asyncio.Event()
    child_release = asyncio.Event()
    run = asyncio.create_task(
        guard.run(
            _delay_replacement_after_cancellation(
                cleanup_error,
                entered,
                child_cancelled,
                child_release,
            ),
            deadline=5.0,
        )
    )
    await entered.wait()
    await clock.sleep_entered.wait()
    clock.release_sleep.set()
    await child_cancelled.wait()

    run.cancel("owner-during-cleanup")
    child_release.set()

    with pytest.raises(asyncio.CancelledError) as cancellation:
        await run
    assert cancellation.value.args == ("owner-during-cleanup",)
    assert guard._quarantine == set()  # noqa: SLF001 - all owned work settled


@pytest.mark.asyncio
async def test_deadline_guard_rejects_an_early_sleeper_and_cancels_work() -> None:
    clock = _Clock(wake_at=4.999)
    guard = DeadlineGuard(clock)
    finalized = asyncio.Event()
    operation = asyncio.create_task(guard.run(_forever(finalized), deadline=5.0))
    await clock.sleep_entered.wait()

    clock.release_sleep.set()

    with pytest.raises(DeadlineClockError, match="^deadline-clock-invalid$"):
        await operation
    assert finalized.is_set()


@pytest.mark.parametrize("phase", ["now", "sleeper-factory", "sleeper-result"])
@pytest.mark.parametrize("grouped", [False, True], ids=("direct", "grouped"))
@pytest.mark.asyncio
async def test_clock_cleanup_incomplete_is_never_downgraded_to_clock_error(
    phase: str,
    grouped: bool,
) -> None:
    evidence: BaseException = DeadlineCleanupIncomplete()
    if grouped:
        evidence = ExceptionGroup(
            "private-clock-group",
            [RuntimeError("private-clock-error"), evidence],
        )
    if phase == "now":
        clock: _Clock = _NowErrorClock(evidence)
    elif phase == "sleeper-factory":
        clock = _SynchronousSleeperErrorClock(evidence)
    else:
        clock = _AsynchronousSleeperErrorClock(evidence)
    operation = _coroutine("private-result")

    with pytest.raises(DeadlineCleanupIncomplete, match="^deadline-cleanup-incomplete$") as error:
        await DeadlineGuard(clock).run(operation, deadline=5.0)

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert operation.cr_frame is None


@pytest.mark.parametrize(
    "cleanup_kind",
    ["ordinary", "fatal-group", "cleanup-incomplete", "cleanup-group", "scalar-fatal"],
)
@pytest.mark.asyncio
async def test_successful_work_classifies_cancelled_sleeper_outcome(cleanup_kind: str) -> None:
    expected_fatal: _FatalProbe | None = None
    cleanup_error: BaseException = RuntimeError("private-timer-cleanup")
    if cleanup_kind == "fatal-group":
        cleanup_error = BaseExceptionGroup(
            "private-timer-group",
            [_FatalProbe("private-grouped-fatal")],
        )
    elif cleanup_kind == "cleanup-incomplete":
        cleanup_error = DeadlineCleanupIncomplete()
    elif cleanup_kind == "cleanup-group":
        cleanup_error = ExceptionGroup(
            "private-timer-group",
            [RuntimeError("private-timer-error"), DeadlineCleanupIncomplete()],
        )
    elif cleanup_kind == "scalar-fatal":
        expected_fatal = _FatalProbe("private-timer-fatal")
        cleanup_error = expected_fatal
    clock = _CancellationReplacingSleeperClock(cleanup_error)
    guard = DeadlineGuard(clock)

    if expected_fatal is not None:
        with pytest.raises(_FatalProbe) as failure:
            await guard.run(_coroutine("public-result"), deadline=5.0)
        assert failure.value is expected_fatal
    elif cleanup_kind in {"cleanup-incomplete", "cleanup-group"}:
        with pytest.raises(
            DeadlineCleanupIncomplete,
            match="^deadline-cleanup-incomplete$",
        ) as failure:
            await guard.run(_coroutine("public-result"), deadline=5.0)
        assert failure.value.__cause__ is None
        assert failure.value.__context__ is None
    else:
        assert await guard.run(_coroutine("public-result"), deadline=5.0) == "public-result"
    assert clock.cancelled.is_set()


@pytest.mark.parametrize("timer_cleanup", ["cleanup-incomplete", "later-fatal"])
@pytest.mark.asyncio
async def test_work_scalar_fatal_precedes_later_sleeper_cleanup(timer_cleanup: str) -> None:
    primary = _FatalProbe("private-work-fatal")
    cleanup_error: BaseException = (
        DeadlineCleanupIncomplete()
        if timer_cleanup == "cleanup-incomplete"
        else _FatalProbe("private-later-timer-fatal")
    )
    clock = _CancellationReplacingSleeperClock(cleanup_error)

    with pytest.raises(_FatalProbe) as failure:
        await DeadlineGuard(clock).run(_raise(primary), deadline=5.0)

    assert failure.value is primary
    assert clock.cancelled.is_set()


@pytest.mark.parametrize("timer_phase", ["sync-factory", "async-result"])
@pytest.mark.parametrize("work_cleanup", ["cleanup-incomplete", "later-fatal"])
@pytest.mark.asyncio
async def test_timer_scalar_fatal_precedes_later_work_cleanup(
    timer_phase: str,
    work_cleanup: str,
) -> None:
    primary = _FatalProbe("private-timer-fatal")
    replacement: BaseException = (
        DeadlineCleanupIncomplete()
        if work_cleanup == "cleanup-incomplete"
        else _FatalProbe("private-later-work-fatal")
    )
    clock: _Clock = (
        _SynchronousSleeperErrorClock(primary)
        if timer_phase == "sync-factory"
        else _AsynchronousSleeperErrorClock(primary)
    )
    entered = asyncio.Event()

    with pytest.raises(_FatalProbe) as failure:
        await DeadlineGuard(clock).run(
            _replace_cancellation(replacement, entered),
            deadline=5.0,
        )

    assert failure.value is primary


@pytest.mark.parametrize(
    "cleanup_error",
    [
        RuntimeError("private-later-cleanup"),
        DeadlineCleanupIncomplete(),
        _FatalProbe("private-later-fatal"),
    ],
    ids=("ordinary", "cleanup-incomplete", "scalar-fatal"),
)
@pytest.mark.asyncio
async def test_scalar_fatal_traceback_drops_owned_operation_and_cleanup(
    cleanup_error: BaseException,
) -> None:
    primary = _FatalProbe("primary-timer-fatal")
    entered = asyncio.Event()
    private_buffer = bytearray(b"private-operation-buffer")
    operation = _replace_cancellation_with_private_buffer(
        cleanup_error,
        entered,
        private_buffer,
    )

    with pytest.raises(_FatalProbe) as failure:
        await DeadlineGuard(_SynchronousSleeperErrorClock(primary)).run(
            operation,
            deadline=5.0,
        )

    assert failure.value is primary
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    traceback = failure.value.__traceback__
    run_locals: dict[str, object] | None = None
    while traceback is not None:
        assert traceback.tb_frame.f_code.co_name != "_run_owned"
        if traceback.tb_frame.f_code.co_name == "run":
            run_locals = dict(traceback.tb_frame.f_locals)
        traceback = traceback.tb_next
    assert run_locals is not None
    assert run_locals["self"] is None
    assert run_locals["operation"] is None
    assert run_locals["deadline"] is None
    assert "private-operation-buffer" not in repr(run_locals)
    assert "private-later" not in repr(run_locals)


@pytest.mark.asyncio
async def test_operation_error_traceback_drops_deadline_private_frames_and_arguments() -> None:
    guard = DeadlineGuard(_Clock())
    operation_error = RuntimeError("private-operation-error")
    operation = _raise(operation_error)

    with pytest.raises(RuntimeError) as failure:
        await guard.run(operation, deadline=5.0)

    assert failure.value is operation_error
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    traceback = failure.value.__traceback__
    run_locals: dict[str, object] | None = None
    while traceback is not None:
        assert traceback.tb_frame.f_code.co_name not in {
            "_capture",
            "_run_owned",
            "_run_public_owned",
        }
        if traceback.tb_frame.f_code.co_name == "run":
            run_locals = dict(traceback.tb_frame.f_locals)
        traceback = traceback.tb_next
    assert run_locals is not None
    assert run_locals["self"] is None
    assert run_locals["operation"] is None
    assert run_locals["deadline"] is None


@pytest.mark.asyncio
async def test_scalar_fatal_privacy_detachment_bypasses_subclass_hooks() -> None:
    fatal = _HookedFatal("exact-fatal")

    with pytest.raises(_HookedFatal) as failure:
        await DeadlineGuard(_SynchronousSleeperErrorClock(fatal)).run(
            _coroutine("private-operation"),
            deadline=5.0,
        )

    assert failure.value is fatal
    assert failure.value.args == ("exact-fatal",)
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    frame_names: list[str] = []
    traceback = failure.value.__traceback__
    while traceback is not None:
        frame_names.append(traceback.tb_frame.f_code.co_name)
        traceback = traceback.tb_next
    assert "_run_owned" not in frame_names


@pytest.mark.parametrize("discard_kind", ["cleanup-incomplete", "later-fatal"])
@pytest.mark.asyncio
async def test_initial_clock_scalar_fatal_precedes_operation_disposal(discard_kind: str) -> None:
    primary = _FatalProbe("private-clock-fatal")
    disposal_error: BaseException = (
        DeadlineCleanupIncomplete()
        if discard_kind == "cleanup-incomplete"
        else _FatalProbe("private-later-disposal-fatal")
    )
    operation = _started_coroutine_whose_close_raises(disposal_error)

    with pytest.raises(_FatalProbe) as failure:
        await DeadlineGuard(_NowErrorClock(primary)).run(operation, deadline=5.0)

    assert failure.value is primary
    assert operation.cr_frame is None


@pytest.mark.parametrize(
    "deadline",
    [float("nan"), 0.0],
    ids=("invalid", "expired"),
)
@pytest.mark.asyncio
async def test_borrowed_future_is_retained_without_invoking_hostile_cancel(
    deadline: float,
) -> None:
    guard = DeadlineGuard(_Clock())
    victim = _CancelRaisesFuture(RuntimeError("private-hostile-cancel"))

    with pytest.raises(
        DeadlineCleanupIncomplete,
        match="^deadline-cleanup-incomplete$",
    ) as failure:
        await guard.run(victim, deadline=deadline)

    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert "private-hostile-cancel" not in repr(failure.value)
    assert not victim.done()
    assert victim.cancel_calls == 0
    assert victim in guard._quarantine  # noqa: SLF001 - live work stays owned
    assert not await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.01)

    victim.set_result("settled")
    await asyncio.sleep(0)
    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.01)
    assert guard._quarantine == set()  # noqa: SLF001 - ownership released after settlement


@pytest.mark.parametrize("kind", ["direct", "cause", "context", "group"])
@pytest.mark.asyncio
async def test_hostile_future_cancel_preserves_cleanup_incomplete_evidence(
    kind: str,
) -> None:
    if kind == "direct":
        cancel_error: BaseException = DeadlineCleanupIncomplete()
    elif kind == "group":
        cancel_error = ExceptionGroup(
            "private-cancel-group",
            [RuntimeError("private-cancel-error"), DeadlineCleanupIncomplete()],
        )
    else:
        cancel_error = RuntimeError("private-hostile-cancel")
        if kind == "cause":
            cancel_error.__cause__ = DeadlineCleanupIncomplete()
        else:
            cancel_error.__context__ = DeadlineCleanupIncomplete()
    guard = DeadlineGuard(_Clock())
    victim = _CancelRaisesFuture(cancel_error)

    assert not await guard.cancel_and_observe(
        victim,
        deadline=asyncio.get_running_loop().time(),
    )
    assert victim.cancel_calls == 1
    assert victim in guard._quarantine  # noqa: SLF001 - live work stays owned
    victim.set_result("settled")
    await asyncio.sleep(0)
    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.01)


@pytest.mark.parametrize("kind", ["unhashable", "callback"])
@pytest.mark.asyncio
async def test_hostile_future_protocol_hooks_fail_closed(kind: str) -> None:
    victim: asyncio.Future[str] = (
        _UnhashableFuture() if kind == "unhashable" else _AddCallbackRaisesFuture()
    )
    guard = DeadlineGuard(_Clock())

    with pytest.raises(
        DeadlineCleanupIncomplete,
        match="^deadline-cleanup-incomplete$",
    ) as failure:
        await guard.run(victim, deadline=float("nan"))

    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert not victim.done()
    victim.set_result("settled")
    await asyncio.sleep(0)
    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.01)


@pytest.mark.parametrize(
    "kind",
    ["done", "cancelled", "exception"],
    ids=("done", "cancelled", "exception"),
)
@pytest.mark.asyncio
async def test_asyncio_future_status_overrides_cannot_forge_cleanup(
    kind: str,
) -> None:
    victim: asyncio.Future[str]
    if kind == "done":
        victim = _DoneRaisesFuture()
    elif kind == "cancelled":
        victim = _CancelledRaisesFuture()
    else:
        victim = _ExceptionRaisesAfterSettlingFuture()
    guard = DeadlineGuard(_Clock())

    with pytest.raises(
        DeadlineCleanupIncomplete,
        match="^deadline-cleanup-incomplete$",
    ) as failure:
        await guard.run(victim, deadline=float("nan"))

    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert not asyncio.Future.done(victim)
    victim.set_result("settled")
    await asyncio.sleep(0)
    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.01)


@pytest.mark.asyncio
async def test_false_done_override_cannot_trigger_borrowed_future_cancellation() -> None:
    victim = _FalseDoneFuture()
    guard = DeadlineGuard(_Clock())

    with pytest.raises(DeadlineCleanupIncomplete, match="^deadline-cleanup-incomplete$"):
        await guard.run(victim, deadline=float("nan"))

    assert victim.cancel_calls == 0
    assert not asyncio.Future.done(victim)
    victim.set_result("settled")
    await asyncio.sleep(0)
    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.01)


@pytest.mark.parametrize(
    "kind",
    ["synchronous-forgery", "foreign-argument", "silent-drop"],
    ids=("synchronous-forgery", "foreign-argument", "silent-drop"),
)
@pytest.mark.asyncio
async def test_asyncio_future_callback_overrides_cannot_forge_completion_time(
    kind: str,
) -> None:
    victim: asyncio.Future[str]
    if kind == "synchronous-forgery":
        victim = _ImmediateFalseCallbackFuture()
    elif kind == "foreign-argument":
        victim = _ForeignAsyncCallbackFuture()
    else:
        victim = _SilentCallbackFuture()
    loop_errors: list[dict[str, object]] = []
    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: loop_errors.append(context))
    guard = DeadlineGuard(_Clock())
    try:
        with pytest.raises(
            DeadlineCleanupIncomplete,
            match="^deadline-cleanup-incomplete$",
        ):
            await guard.run(victim, deadline=float("nan"))
        victim.set_result("settled")
        await asyncio.sleep(0)
        assert await guard.observe_quarantine(deadline=loop.time() + 0.01)
    finally:
        loop.set_exception_handler(previous_handler)

    assert not asyncio.Future.cancelled(victim)
    assert victim.callback_calls == 0
    assert loop_errors == []


@pytest.mark.asyncio
async def test_valid_deadline_observes_future_subclass_without_virtual_callback_hooks() -> None:
    victim = _ForeignAsyncCallbackFuture()
    loop_errors: list[dict[str, object]] = []
    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: loop_errors.append(context))
    guard = DeadlineGuard(_Clock())
    run = asyncio.create_task(guard.run(victim, deadline=5.0))
    try:
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        victim.set_result("settled")
        result = await run
        await asyncio.sleep(0)
    finally:
        loop.set_exception_handler(previous_handler)

    assert result == "settled"
    assert victim.callback_calls == 0
    assert loop_errors == []


@pytest.mark.asyncio
async def test_untrusted_generic_future_protocol_is_retained_without_raw_hook_failure() -> None:
    victim = _UnweakrefableFutureLike()
    guard = DeadlineGuard(_Clock())

    with pytest.raises(
        DeadlineCleanupIncomplete,
        match="^deadline-cleanup-incomplete$",
    ) as failure:
        await guard.run(cast(Awaitable[str], victim), deadline=float("nan"))

    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert victim.cancel_calls == 1
    assert guard._is_retained(victim)  # noqa: SLF001 - opaque owner remains retained


@pytest.mark.asyncio
async def test_cancel_many_attempts_all_siblings_after_hostile_cancel_failure() -> None:
    guard = DeadlineGuard(_Clock())
    victim = _CancelRaisesFuture(RuntimeError("private-hostile-cancel"))
    finalized = asyncio.Event()
    sibling = asyncio.create_task(_forever(finalized))
    await asyncio.sleep(0)

    assert not await guard.cancel_many(victim, sibling)

    assert sibling.cancelled()
    assert finalized.is_set()
    assert victim.cancel_calls == 1
    assert victim in guard._quarantine  # noqa: SLF001 - live work stays owned
    victim.set_result("settled")
    await asyncio.sleep(0)
    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.01)


@pytest.mark.parametrize(
    "cancel_error",
    [RuntimeError("private-hostile-cancel"), _FatalProbe("private-hostile-fatal")],
    ids=("ordinary", "scalar-fatal"),
)
@pytest.mark.asyncio
async def test_owner_cancellation_precedes_hostile_future_cancel_failure(
    monkeypatch: pytest.MonkeyPatch,
    cancel_error: BaseException,
) -> None:
    monkeypatch.setattr(deadline_module, "_CANCEL_OBSERVE_SECONDS", 0.01, raising=False)
    guard = DeadlineGuard(_Clock())
    victim = _CancelRaisesFuture(cancel_error)
    run = asyncio.create_task(guard.cancel_and_observe(victim))
    await victim.cancel_entered.wait()

    run.cancel("owner-cancel")
    with pytest.raises(asyncio.CancelledError) as failure:
        await run

    assert failure.value.args == ("owner-cancel",)
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert victim in guard._quarantine  # noqa: SLF001 - owner cancellation keeps ownership
    victim.set_result("settled")
    await asyncio.sleep(0)
    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.01)


@pytest.mark.asyncio
async def test_scalar_fatal_from_hostile_cancel_is_preserved_after_retention() -> None:
    guard = DeadlineGuard(_Clock())
    fatal = _FatalProbe("hostile-cancel-fatal")
    victim = _CancelRaisesFuture(fatal)

    with pytest.raises(_FatalProbe) as failure:
        await guard.cancel_and_observe(
            victim,
            deadline=asyncio.get_running_loop().time(),
        )

    assert failure.value is fatal
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    traceback = failure.value.__traceback__
    cancel_locals: dict[str, object] | None = None
    while traceback is not None:
        assert traceback.tb_frame.f_code.co_name not in {
            "_cancel_all_until",
            "_cancel_and_report",
            "_cancel_and_observe_owned",
            "_finish_cleanup_despite_cancellation",
        }
        if traceback.tb_frame.f_code.co_name == "cancel_and_observe":
            cancel_locals = dict(traceback.tb_frame.f_locals)
        traceback = traceback.tb_next
    assert cancel_locals is not None
    assert cancel_locals["self"] is None
    assert cancel_locals["task"] is None
    assert cancel_locals["deadline"] is None
    assert victim in guard._quarantine  # noqa: SLF001 - fatal still retains live work
    with pytest.raises(_FatalProbe) as drain_failure:
        await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.01)
    assert drain_failure.value is fatal
    victim.set_result("settled")
    await asyncio.sleep(0)
    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.01)


@pytest.mark.asyncio
async def test_first_scalar_cancel_failure_precedes_later_terminal_scalar() -> None:
    first = _FatalProbe("first-cancel-fatal")
    second = _FatalProbe("second-result-fatal")
    victim = _CancelRaisesAfterSettlingFuture(first, second)

    with pytest.raises(_FatalProbe) as failure:
        await DeadlineGuard(_Clock()).cancel_and_observe(
            victim,
            deadline=asyncio.get_running_loop().time(),
        )

    assert failure.value is first
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert victim.done()


@pytest.mark.parametrize(
    "deadline",
    [float("nan"), 0.0, 5.0],
    ids=("invalid", "expired", "valid"),
)
@pytest.mark.asyncio
async def test_deadline_guard_never_cancels_its_current_owner(deadline: float) -> None:
    owner = asyncio.current_task()
    assert owner is not None

    with pytest.raises(
        DeadlineCleanupIncomplete,
        match="^deadline-cleanup-incomplete$",
    ) as failure:
        await DeadlineGuard(_Clock()).run(owner, deadline=deadline)

    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert owner.cancelling() == 0


@pytest.mark.asyncio
async def test_expired_deadline_never_cancels_preexisting_task_that_awaits_owner() -> None:
    guard = DeadlineGuard(_Clock())
    victim_started = asyncio.Event()
    victim_holder: list[asyncio.Task[None]] = []

    async def owner() -> None:
        current = asyncio.current_task()
        assert current is not None

        async def await_owner() -> None:
            victim_started.set()
            await current

        victim = asyncio.create_task(await_owner())
        victim_holder.append(victim)
        await victim_started.wait()
        await asyncio.sleep(0)
        await guard.run(victim, deadline=0.0)

    run = asyncio.create_task(owner())

    with pytest.raises(
        DeadlineCleanupIncomplete,
        match="^deadline-cleanup-incomplete$",
    ):
        await run

    victim = victim_holder[0]
    await asyncio.sleep(0)
    assert run.cancelling() == 0
    assert victim.cancelling() == 0
    assert victim.done()


@pytest.mark.asyncio
async def test_external_cancellation_never_cancels_preexisting_task_that_awaits_owner() -> None:
    clock = _Clock()
    guard = DeadlineGuard(clock)
    victim_started = asyncio.Event()
    victim_holder: list[asyncio.Task[None]] = []

    async def owner() -> None:
        current = asyncio.current_task()
        assert current is not None

        async def await_owner() -> None:
            victim_started.set()
            try:
                await current
            except asyncio.CancelledError:
                return

        victim = asyncio.create_task(await_owner())
        victim_holder.append(victim)
        await victim_started.wait()
        await asyncio.sleep(0)
        await guard.run(victim, deadline=5.0)

    run = asyncio.create_task(owner())
    await clock.sleep_entered.wait()
    run.cancel("exact-owner-cancel")

    with pytest.raises(asyncio.CancelledError) as cancellation:
        await run

    victim = victim_holder[0]
    await victim
    # A third-party Task already awaiting the owner can consume asyncio's
    # cancellation message. The guard must not inject a second cancellation.
    assert cancellation.value.args in ((), ("exact-owner-cancel",))
    assert run.cancelling() == 1
    assert victim.cancelling() == 0
    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.1)


@pytest.mark.asyncio
async def test_active_owner_cancellation_precedes_self_operation_rejection() -> None:
    guard = DeadlineGuard(_Clock())
    entered = asyncio.Event()

    async def owner() -> None:
        try:
            entered.set()
            await asyncio.Event().wait()
        finally:
            current = asyncio.current_task()
            assert current is not None
            await guard.run(current, deadline=5.0)

    task = asyncio.create_task(owner())
    await entered.wait()
    task.cancel("exact-owner-cancel")

    with pytest.raises(asyncio.CancelledError) as failure:
        await task

    assert failure.value.args in ((), ("exact-owner-cancel",))
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None


@pytest.mark.asyncio
async def test_consumed_owner_cancellation_precedes_self_operation_rejection() -> None:
    guard = DeadlineGuard(_Clock())

    async def owner() -> None:
        current = asyncio.current_task()
        assert current is not None
        current.cancel("consumed-owner-cancel")
        try:
            await asyncio.sleep(0)
        except asyncio.CancelledError as consumed:
            assert consumed.args == ("consumed-owner-cancel",)
        await guard.run(current, deadline=5.0)

    task = asyncio.create_task(owner())
    with pytest.raises(asyncio.CancelledError) as failure:
        await task

    assert failure.value.args == ()
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None


@pytest.mark.parametrize("clock", [_GroupedSleeperClock(), _GroupedNowClock()])
@pytest.mark.asyncio
async def test_deadline_guard_sanitizes_mixed_clock_failure_groups(clock: _Clock) -> None:
    operation = _coroutine("private-result")

    with pytest.raises(DeadlineClockError, match="^deadline-clock-invalid$") as error:
        await DeadlineGuard(clock).run(operation, deadline=5.0)

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert operation.cr_frame is None


@pytest.mark.asyncio
async def test_deadline_guard_sanitizes_synchronous_sleeper_factory_failure() -> None:
    operation = _coroutine("private-result")

    with pytest.raises(DeadlineClockError, match="^deadline-clock-invalid$") as error:
        await DeadlineGuard(_SynchronousSleeperFailureClock()).run(
            operation,
            deadline=5.0,
        )

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert operation.cr_frame is None


@pytest.mark.asyncio
async def test_deadline_guard_sanitizes_synchronous_sleeper_factory_cancellation() -> None:
    operation = _coroutine("private-result")

    with pytest.raises(DeadlineClockError, match="^deadline-clock-invalid$") as error:
        await DeadlineGuard(_SynchronousSleeperCancellationClock()).run(
            operation,
            deadline=5.0,
        )

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert operation.cr_frame is None


@pytest.mark.asyncio
async def test_deadline_guard_sanitizes_synchronous_now_cancellation() -> None:
    operation = _coroutine("private-result")

    with pytest.raises(DeadlineClockError, match="^deadline-clock-invalid$") as error:
        await DeadlineGuard(_SynchronousNowCancellationClock()).run(
            operation,
            deadline=5.0,
        )

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert operation.cr_frame is None


@pytest.mark.asyncio
async def test_cancel_observation_rejects_settlement_at_its_inclusive_deadline() -> None:
    guard = DeadlineGuard(_Clock())
    entered = asyncio.Event()
    cancelled = asyncio.Event()
    release = asyncio.Event()
    task = asyncio.create_task(_suppress_cancellation_until_released(entered, cancelled, release))
    await entered.wait()
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 0.02
    loop.call_at(deadline, release.set)

    assert not await guard.cancel_and_observe(task, deadline=deadline)
    assert cancelled.is_set()
    await task


@pytest.mark.asyncio
async def test_quarantine_observation_rejects_settlement_at_its_inclusive_deadline() -> None:
    guard = DeadlineGuard(_Clock())
    entered = asyncio.Event()
    cancelled = asyncio.Event()
    release = asyncio.Event()
    task = asyncio.create_task(_suppress_cancellation_until_released(entered, cancelled, release))
    await entered.wait()
    assert not await guard.cancel_and_observe(
        task,
        deadline=asyncio.get_running_loop().time(),
    )
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 0.02
    loop.call_at(deadline, release.set)

    assert not await guard.observe_quarantine(deadline=deadline)
    assert cancelled.is_set()
    await task
    drained = await guard.observe_quarantine(deadline=loop.time() + 0.1)
    assert drained, (
        guard._quarantine_snapshot(),  # noqa: SLF001 - diagnostic ownership state
        guard._settled_tombstones,  # noqa: SLF001 - diagnostic strict evidence
        guard._retention_generation,  # noqa: SLF001 - diagnostic generation
    )


@pytest.mark.parametrize(
    "deadline",
    [float("nan"), float("inf"), 10**1_000, 1.0e12, True, _HostileFloat()],
    ids=("nan", "infinity", "oversized-int", "far-future-float", "bool", "hostile-subclass"),
)
@pytest.mark.asyncio
async def test_cancel_and_observe_invalid_cleanup_deadline_uses_immediate_bound(
    deadline: object,
) -> None:
    entered = asyncio.Event()
    cancelled = asyncio.Event()
    release = asyncio.Event()
    task = asyncio.create_task(_suppress_cancellation_until_released(entered, cancelled, release))
    await entered.wait()
    guard = DeadlineGuard(_Clock())

    try:
        complete = await asyncio.wait_for(
            guard.cancel_and_observe(task, deadline=deadline),  # type: ignore[arg-type]
            timeout=0.2,
        )
        assert complete is False
        assert cancelled.is_set()
        assert task in guard._quarantine  # noqa: SLF001 - live work remains owned
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
        await asyncio.sleep(0)

    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.1)


@pytest.mark.parametrize(
    "deadline",
    [float("nan"), float("inf"), 10**1_000, 1.0e12, True, _HostileFloat()],
    ids=("nan", "infinity", "oversized-int", "far-future-float", "bool", "hostile-subclass"),
)
@pytest.mark.asyncio
async def test_observe_quarantine_invalid_cleanup_deadline_uses_immediate_bound(
    deadline: object,
) -> None:
    entered = asyncio.Event()
    cancelled = asyncio.Event()
    release = asyncio.Event()
    task = asyncio.create_task(_suppress_cancellation_until_released(entered, cancelled, release))
    await entered.wait()
    guard = DeadlineGuard(_Clock())
    assert not await guard.cancel_and_observe(task, deadline=asyncio.get_running_loop().time())

    try:
        complete = await asyncio.wait_for(
            guard.observe_quarantine(deadline=deadline),  # type: ignore[arg-type]
            timeout=0.2,
        )
        assert complete is False
        assert task in guard._quarantine  # noqa: SLF001 - live work remains owned
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
        await asyncio.sleep(0)

    assert cancelled.is_set()
    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.1)


@pytest.mark.parametrize(
    "deadline",
    [float("nan"), float("inf"), 10**1_000, 1.0e12, True, _HostileFloat()],
    ids=("nan", "infinity", "oversized-int", "far-future-float", "bool", "hostile-subclass"),
)
@pytest.mark.asyncio
async def test_cancel_and_observe_invalid_cleanup_deadline_fails_closed_for_settled_work(
    deadline: object,
) -> None:
    settled: asyncio.Future[str] = asyncio.get_running_loop().create_future()
    settled.set_result("private-result")

    complete = await DeadlineGuard(_Clock()).cancel_and_observe(
        settled,
        deadline=deadline,  # type: ignore[arg-type]
    )

    assert complete is False


@pytest.mark.parametrize(
    "deadline",
    [float("nan"), float("inf"), 10**1_000, 1.0e12, True, _HostileFloat()],
    ids=("nan", "infinity", "oversized-int", "far-future-float", "bool", "hostile-subclass"),
)
@pytest.mark.asyncio
async def test_observe_quarantine_invalid_cleanup_deadline_fails_closed_when_empty(
    deadline: object,
) -> None:
    complete = await DeadlineGuard(_Clock()).observe_quarantine(
        deadline=deadline,  # type: ignore[arg-type]
    )

    assert complete is False


@pytest.mark.asyncio
async def test_settled_quarantine_keeps_strict_tombstone_until_later_deadline() -> None:
    guard = DeadlineGuard(_Clock())
    entered = asyncio.Event()
    release = asyncio.Event()
    task = asyncio.create_task(
        _suppress_cancellation_until_released(entered, asyncio.Event(), release)
    )
    await entered.wait()
    loop = asyncio.get_running_loop()

    assert not await guard.cancel_and_observe(task, deadline=loop.time())
    boundary = loop.time()
    release.set()
    await task
    await asyncio.sleep(0)

    assert not await guard.observe_quarantine(deadline=boundary)
    assert await guard.observe_quarantine(deadline=loop.time() + 0.01)


@pytest.mark.asyncio
async def test_late_completion_callback_repairs_untimed_settlement_tombstone() -> None:
    guard = DeadlineGuard(_Clock())
    loop = asyncio.get_running_loop()
    task: asyncio.Future[None] = loop.create_future()
    guard._retain(task)  # noqa: SLF001 - deterministic callback-ordering probe
    task.set_result(None)

    token = guard._completion_token(task)  # noqa: SLF001 - deterministic token probe
    assert token is not None
    guard._discard_retained(task)  # noqa: SLF001 - simulate bounded observer race
    guard._settled_tombstones[token] = guard._settled_evidence(  # noqa: SLF001
        task,
        completed_at=None,
        passive=False,
    )

    await asyncio.sleep(0)

    evidence = guard._settled_tombstones[token]  # noqa: SLF001
    assert evidence.completed_at is not None
    assert await guard.observe_quarantine(deadline=loop.time() + 0.01)


@pytest.mark.asyncio
async def test_passive_quarantine_never_cancels_retained_observer() -> None:
    guard = DeadlineGuard(_Clock())
    entered = asyncio.Event()
    release = asyncio.Event()

    async def observer() -> None:
        entered.set()
        await release.wait()

    task = asyncio.create_task(observer())
    guard.retain_passive(task)
    await entered.wait()

    assert not await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.01)
    assert not task.done()
    assert task.cancelling() == 0

    release.set()
    await task
    await asyncio.sleep(0)
    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.1)


@pytest.mark.asyncio
async def test_passive_quarantine_sanitizes_late_fatal_outcome() -> None:
    guard = DeadlineGuard(_Clock())
    release = asyncio.Event()
    fatal = _FatalProbe("passive-observer-fatal")
    fatal_ref = ref(fatal)
    fatal_holder = [fatal]

    async def observer() -> deadline_module._Outcome[None]:  # noqa: SLF001
        await release.wait()
        return deadline_module._Outcome(error=fatal_holder[0])  # noqa: SLF001

    task = asyncio.create_task(observer())
    guard.retain_passive(task)
    release.set()
    await task
    await asyncio.sleep(0)

    with pytest.raises(
        DeadlineCleanupIncomplete,
        match="^deadline-cleanup-incomplete$",
    ) as failure:
        await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.1)
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    del task
    del observer
    fatal_holder.clear()
    del fatal
    await asyncio.sleep(0)
    gc.collect()
    assert fatal_ref() is None


@pytest.mark.asyncio
async def test_passive_cleanup_tombstone_does_not_retain_private_task_result() -> None:
    guard = DeadlineGuard(_Clock())

    async def observer() -> deadline_module._Outcome[None]:  # noqa: SLF001
        private = RuntimeError("private-passive-secret")
        private.__context__ = DeadlineCleanupIncomplete()
        return deadline_module._Outcome(error=private)  # noqa: SLF001

    task = asyncio.create_task(observer())
    task_ref = ref(task)
    guard.retain_passive(task)
    await task
    await asyncio.sleep(0)

    assert not await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.1)
    del task
    await asyncio.sleep(0)
    gc.collect()

    assert task_ref() is None


@pytest.mark.asyncio
async def test_active_cleanup_incomplete_tombstone_cannot_be_acknowledged() -> None:
    guard = DeadlineGuard(_Clock())

    async def observer() -> deadline_module._Outcome[None]:  # noqa: SLF001
        return deadline_module._Outcome(  # noqa: SLF001
            error=DeadlineCleanupIncomplete()
        )

    task = asyncio.create_task(observer())
    guard._retain(task)  # noqa: SLF001 - exercise active retained ownership
    await task
    await asyncio.sleep(0)

    assert not await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.1)


@pytest.mark.asyncio
async def test_quarantine_observation_rejects_concurrent_retention_generation() -> None:
    guard = DeadlineGuard(_Clock())
    loop = asyncio.get_running_loop()
    retained: asyncio.Future[None] = loop.create_future()
    loop.call_soon(guard._retain, retained)  # noqa: SLF001 - deterministic race probe
    loop.call_soon(retained.set_result, None)

    assert not await guard.observe_quarantine(deadline=loop.time())

    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert guard._quarantine == set()  # noqa: SLF001 - released ownership contract


def test_deadline_guard_rejects_nonfinite_and_reversing_clock_values() -> None:
    clock = _Clock(now=2.0)
    guard = DeadlineGuard(clock)
    assert guard.now() == 2.0

    clock.current = 1.0
    with pytest.raises(DeadlineClockError, match="^deadline-clock-invalid$"):
        guard.now()

    for invalid in (float("inf"), float("nan")):
        with pytest.raises(DeadlineClockError, match="^deadline-clock-invalid$"):
            DeadlineGuard(_Clock(now=invalid)).now()


@pytest.mark.asyncio
async def test_deadline_guard_reraises_external_cancellation_after_clearing_children() -> None:
    clock = _Clock()
    guard = DeadlineGuard(clock)
    finalized = asyncio.Event()
    operation = asyncio.create_task(guard.run(_forever(finalized), deadline=5.0))
    await clock.sleep_entered.wait()

    operation.cancel()

    with pytest.raises(asyncio.CancelledError):
        await operation
    assert finalized.is_set()


@pytest.mark.asyncio
async def test_deadline_guard_rejects_unrepresentable_deadline_and_closes_operation() -> None:
    clock = _Clock()
    guard = DeadlineGuard(clock)
    operation = _coroutine("private-value")

    with pytest.raises(DeadlineClockError, match="^deadline-clock-invalid$"):
        await guard.run(operation, deadline=10**1_000)

    assert operation.cr_frame is None


@pytest.mark.asyncio
async def test_deadline_guard_rejects_wrong_type_without_calling_conversion_hooks() -> None:
    operation = _coroutine("private-value")
    deadline = _ExplodingDeadline()

    with pytest.raises(DeadlineClockError, match="^deadline-clock-invalid$") as error:
        await DeadlineGuard(_Clock()).run(operation, deadline=deadline)  # type: ignore[arg-type]

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert deadline.float_calls == 0
    assert operation.cr_frame is None


@pytest.mark.parametrize(
    ("clock", "deadline", "error"),
    [
        (_Clock(now=5.0), 5.0, DeadlineExceeded),
        (_Clock(now=float("inf")), 5.0, DeadlineClockError),
    ],
)
@pytest.mark.asyncio
async def test_deadline_guard_closes_work_rejected_before_it_starts(
    clock: _Clock,
    deadline: float,
    error: type[Exception],
) -> None:
    guard = DeadlineGuard(clock)
    operation = _coroutine("private-value")

    with pytest.raises(error):
        await guard.run(operation, deadline=deadline)

    assert operation.cr_frame is None


@pytest.mark.parametrize("async_close", [False, True])
@pytest.mark.asyncio
async def test_invalid_deadline_ignores_misleading_custom_close_and_settles_awaitable(
    async_close: bool,
) -> None:
    operation = _MisleadingCloseAwaitable(async_close=async_close)

    with pytest.raises(DeadlineClockError, match="^deadline-clock-invalid$"):
        await asyncio.wait_for(
            DeadlineGuard(_Clock()).run(operation, deadline=float("nan")),
            timeout=0.1,
        )

    assert operation.close_calls == 0
    assert not operation.started


@pytest.mark.asyncio
async def test_explicit_cancel_api_settles_already_started_future_and_task() -> None:
    guard = DeadlineGuard(_Clock())
    future: asyncio.Future[str] = asyncio.get_running_loop().create_future()
    finalized = asyncio.Event()
    task = asyncio.create_task(_forever(finalized))
    await asyncio.sleep(0)

    assert await guard.cancel_and_observe(future)
    assert await guard.cancel_and_observe(task)

    assert future.cancelled()
    assert task.cancelled()
    assert finalized.is_set()


@pytest.mark.asyncio
async def test_explicit_cancel_api_joins_task_that_swallows_one_cancellation() -> None:
    finalized = asyncio.Event()
    task = asyncio.create_task(_swallow_one_cancellation(finalized))
    await asyncio.sleep(0)

    assert await asyncio.wait_for(
        DeadlineGuard(_Clock()).cancel_and_observe(task),
        timeout=0.1,
    )

    assert task.done()
    assert not task.cancelled()
    assert finalized.is_set()


@pytest.mark.asyncio
async def test_invalid_deadline_contains_a_started_coroutine_close_failure() -> None:
    operation = _started_coroutine_whose_close_raises()

    with pytest.raises(DeadlineClockError, match="^deadline-clock-invalid$"):
        await DeadlineGuard(_Clock()).run(operation, deadline=float("nan"))

    assert operation.cr_frame is None


@pytest.mark.parametrize("cleanup_outcome", ["cleanup-incomplete", "fatal"])
@pytest.mark.asyncio
async def test_invalid_deadline_preserves_safety_outcome_from_coroutine_close(
    cleanup_outcome: str,
) -> None:
    close_error: BaseException = (
        DeadlineCleanupIncomplete()
        if cleanup_outcome == "cleanup-incomplete"
        else KeyboardInterrupt("private-close-fatal")
    )
    operation = _started_coroutine_whose_close_raises(close_error)
    caught: BaseException | None = None

    try:
        await DeadlineGuard(_Clock()).run(operation, deadline=float("nan"))
    except BaseException as error:
        caught = error

    if cleanup_outcome == "cleanup-incomplete":
        assert type(caught) is DeadlineCleanupIncomplete
        assert caught.__cause__ is None
        assert caught.__context__ is None
    else:
        assert caught is close_error
    assert operation.cr_frame is None


@pytest.mark.parametrize(
    ("clock", "deadline"),
    ((_Clock(), float("nan")), (_Clock(now=5.0), 5.0)),
    ids=("invalid", "exact-expired"),
)
@pytest.mark.asyncio
async def test_pre_admission_task_cancellation_cleanup_incomplete_is_preserved(
    clock: _Clock,
    deadline: float,
) -> None:
    entered = asyncio.Event()
    task = asyncio.create_task(
        _replace_cancellation(DeadlineCleanupIncomplete(), entered),
        name="deadline-pre-admission-cleanup-incomplete",
    )
    await entered.wait()

    guard = DeadlineGuard(clock)
    with pytest.raises(
        DeadlineCleanupIncomplete,
        match="^deadline-cleanup-incomplete$",
    ) as error:
        await guard.run(task, deadline=deadline)

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert not task.done()
    assert task.cancelling() == 0
    task.cancel()
    terminal = (await asyncio.gather(task, return_exceptions=True))[0]
    assert type(terminal) is DeadlineCleanupIncomplete
    await asyncio.sleep(0)
    assert not await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.1)


@pytest.mark.asyncio
async def test_pre_admission_cancelled_task_cannot_hide_chained_cleanup_incomplete() -> None:
    entered = asyncio.Event()
    task = asyncio.create_task(
        _chain_cleanup_incomplete_on_cancellation(entered),
        name="deadline-pre-admission-chained-cleanup-incomplete",
    )
    await entered.wait()

    guard = DeadlineGuard(_Clock())
    with pytest.raises(
        DeadlineCleanupIncomplete,
        match="^deadline-cleanup-incomplete$",
    ) as error:
        await guard.run(task, deadline=float("nan"))

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert not task.done()
    assert task.cancelling() == 0
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    assert task.cancelled()
    await asyncio.sleep(0)
    assert not await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.1)


@pytest.mark.asyncio
async def test_deadline_guard_quarantines_indefinitely_cancellation_suppressing_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deadline_module, "_CANCEL_OBSERVE_SECONDS", 0.01, raising=False)
    entered = asyncio.Event()
    cancelled = asyncio.Event()
    release = asyncio.Event()
    task = asyncio.create_task(
        _suppress_cancellation_until_released(entered, cancelled, release),
        name="deadline-hostile-operation",
    )
    await entered.wait()
    guard = DeadlineGuard(_Clock())
    run = asyncio.create_task(guard.run(task, deadline=float("nan")))

    done, _ = await asyncio.wait({run}, timeout=0.2)
    finished_within_bound = run in done
    if not finished_within_bound:
        release.set()
        await asyncio.gather(run, return_exceptions=True)

    assert finished_within_bound
    assert type(run.exception()).__name__ == "DeadlineCleanupIncomplete"
    assert not cancelled.is_set()
    assert task.cancelling() == 0
    assert task in guard._quarantine  # noqa: SLF001 - owned-task quarantine contract

    release.set()
    await asyncio.wait_for(task, timeout=0.1)
    await asyncio.sleep(0)
    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.1)


@pytest.mark.asyncio
async def test_borrowed_work_is_retained_without_cancellation_before_owner_cancel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deadline_module, "_CANCEL_OBSERVE_SECONDS", 0.1, raising=False)
    entered = asyncio.Event()
    cancelled = asyncio.Event()
    release = asyncio.Event()
    victim = asyncio.create_task(
        _suppress_cancellation_until_released(entered, cancelled, release),
        name="deadline-pre-admission-victim",
    )
    await entered.wait()
    clock = _Clock()
    guard = DeadlineGuard(clock)
    owner = asyncio.create_task(
        guard.run(victim, deadline=5.0),
        name="deadline-pre-admission-owner",
    )
    await clock.sleep_entered.wait()

    owner.cancel("external-during-discard")
    try:
        with pytest.raises(asyncio.CancelledError) as cancellation:
            await asyncio.wait_for(owner, timeout=0.3)
        assert cancellation.value.args == ("external-during-discard",)
        assert not victim.done()
        assert not cancelled.is_set()
        assert victim.cancelling() == 0
        assert guard._quarantine  # noqa: SLF001 - passive observer ownership invariant
    finally:
        release.set()
        await asyncio.gather(victim, return_exceptions=True)
        await asyncio.sleep(0)

    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.1)


@pytest.mark.parametrize(
    ("clock", "deadline"),
    [
        (_Clock(), float("nan")),
        (_Clock(now=5.0), 5.0),
    ],
    ids=("invalid", "exact-expired"),
)
@pytest.mark.asyncio
async def test_pre_admission_discard_preserves_already_active_cancellation(
    clock: _Clock,
    deadline: float,
) -> None:
    guard = DeadlineGuard(clock)
    operation = _coroutine("private-result")
    entered = asyncio.Event()

    async def owner() -> None:
        try:
            entered.set()
            await asyncio.Event().wait()
        finally:
            await guard.run(operation, deadline=deadline)

    task = asyncio.create_task(owner())
    await entered.wait()
    task.cancel("external-active")

    with pytest.raises(asyncio.CancelledError) as cancellation:
        await task

    assert cancellation.value.args in ((), ("external-active",))
    assert operation.cr_frame is None


@pytest.mark.asyncio
async def test_active_cancellation_passively_retains_borrowed_task() -> None:
    clock = _Clock()
    guard = DeadlineGuard(clock)
    finalized = asyncio.Event()
    victim = asyncio.create_task(_forever(finalized), name="deadline-active-cancel-victim")
    await asyncio.sleep(0)
    entered = asyncio.Event()

    async def owner() -> None:
        try:
            entered.set()
            await asyncio.Event().wait()
        finally:
            await guard.run(victim, deadline=5.0)

    run = asyncio.create_task(owner(), name="deadline-active-cancel-owner")
    await entered.wait()
    run.cancel("external-active")
    clock.release_sleep.set()

    with pytest.raises(asyncio.CancelledError) as cancellation:
        await run

    assert cancellation.value.args in ((), ("external-active",))
    assert not finalized.is_set()
    assert not victim.done()
    assert victim.cancelling() == 0
    assert victim in guard._quarantine  # noqa: SLF001 - borrowed work retained passively
    victim.cancel()
    await asyncio.gather(victim, return_exceptions=True)
    await asyncio.sleep(0)
    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.1)


@pytest.mark.asyncio
async def test_valid_deadline_active_cancellation_closes_coroutine_without_reading_clock() -> None:
    clock = _UncalledHostileNowClock()
    guard = DeadlineGuard(clock)
    operation = _coroutine("private-result")
    entered = asyncio.Event()

    async def owner() -> None:
        try:
            entered.set()
            await asyncio.Event().wait()
        finally:
            await guard.run(operation, deadline=5.0)

    run = asyncio.create_task(owner())
    await entered.wait()
    run.cancel("external-active")

    with pytest.raises(asyncio.CancelledError) as cancellation:
        await run

    assert cancellation.value.args in ((), ("external-active",))
    assert operation.cr_frame is None
    assert clock.now_calls == 0


@pytest.mark.asyncio
async def test_active_cancellation_precedes_malformed_operation_disposal_failure() -> None:
    clock = _UncalledHostileNowClock()
    guard = DeadlineGuard(clock)
    entered = asyncio.Event()

    async def owner() -> None:
        try:
            entered.set()
            await asyncio.Event().wait()
        finally:
            await guard.run(
                cast(Awaitable[object], object()),
                deadline=5.0,
            )

    run = asyncio.create_task(owner())
    await entered.wait()
    run.cancel("exact-owner-cancel")

    with pytest.raises(asyncio.CancelledError) as cancellation:
        await run
    assert cancellation.value.args in ((), ("exact-owner-cancel",))
    assert clock.now_calls == 0
    assert clock.sleep_calls == 0


@pytest.mark.asyncio
async def test_valid_deadline_active_cancellation_retains_hostile_running_future(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deadline_module, "_CANCEL_OBSERVE_SECONDS", 0.01, raising=False)
    clock = _UncalledHostileNowClock()
    guard = DeadlineGuard(clock)
    entered = asyncio.Event()
    cancelled = asyncio.Event()
    release = asyncio.Event()
    victim = asyncio.create_task(
        _suppress_cancellation_until_released(entered, cancelled, release),
        name="deadline-active-cancel-hostile-victim",
    )
    await entered.wait()
    owner_entered = asyncio.Event()

    async def owner() -> None:
        try:
            owner_entered.set()
            await asyncio.Event().wait()
        finally:
            await guard.run(victim, deadline=5.0)

    run = asyncio.create_task(owner())
    await owner_entered.wait()
    run.cancel("external-active")

    try:
        with pytest.raises(asyncio.CancelledError) as cancellation:
            await asyncio.wait_for(run, timeout=0.2)
        assert cancellation.value.args in ((), ("external-active",))
        assert victim in guard._quarantine  # noqa: SLF001 - ownership retained while live
        assert not cancelled.is_set()
        assert victim.cancelling() == 0
        assert clock.now_calls == 0
    finally:
        release.set()
        await asyncio.gather(victim, return_exceptions=True)
        await asyncio.sleep(0)

    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.1)


@pytest.mark.asyncio
async def test_pending_cancellation_preempts_valid_deadline_clock_and_operation_admission() -> None:
    clock = _UncalledHostileNowClock()
    guard = DeadlineGuard(clock)
    operation_started = False

    async def operation() -> None:
        nonlocal operation_started
        operation_started = True

    candidate = operation()

    async def owner() -> None:
        task = asyncio.current_task()
        assert task is not None
        task.cancel("pending-before-run")
        await guard.run(candidate, deadline=5.0)

    run = asyncio.create_task(owner())
    with pytest.raises(asyncio.CancelledError) as cancellation:
        await run

    assert cancellation.value.args == ("pending-before-run",)
    assert operation_started is False
    assert candidate.cr_frame is None
    assert clock.now_calls == 0
    assert clock.sleep_calls == 0
    assert guard._quarantine == set()  # noqa: SLF001 - all owned work settled


@pytest.mark.asyncio
async def test_consumed_cancellation_count_still_preempts_discard_safety_outcome() -> None:
    clock = _UncalledHostileNowClock()
    guard = DeadlineGuard(clock)
    operation = _started_coroutine_whose_close_raises(KeyboardInterrupt("private-close-fatal"))

    async def owner() -> None:
        task = asyncio.current_task()
        assert task is not None
        task.cancel("consumed-before-run")
        with suppress(asyncio.CancelledError):
            await asyncio.sleep(0)
        assert task.cancelling() == 1
        await guard.run(operation, deadline=5.0)

    run = asyncio.create_task(owner())
    with pytest.raises(asyncio.CancelledError) as cancellation:
        await run

    assert cancellation.value.args == ()
    assert operation.cr_frame is None
    assert clock.now_calls == 0
    assert clock.sleep_calls == 0
    assert guard._quarantine == set()  # noqa: SLF001 - all owned work settled


@pytest.mark.asyncio
async def test_pre_admission_discard_does_not_treat_spontaneous_cancellation_as_external(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deadline_module, "_CANCEL_OBSERVE_SECONDS", 0.01, raising=False)
    entered = asyncio.Event()
    cancelled = asyncio.Event()
    release = asyncio.Event()
    victim = asyncio.create_task(
        _suppress_cancellation_until_released(entered, cancelled, release),
        name="deadline-spontaneous-discard-victim",
    )
    await entered.wait()
    guard = DeadlineGuard(_Clock())

    async def owner() -> None:
        try:
            raise asyncio.CancelledError("private-spontaneous-outer")
        finally:
            await guard.run(victim, deadline=float("nan"))

    run = asyncio.create_task(owner())
    try:
        with pytest.raises(
            DeadlineCleanupIncomplete,
            match="^deadline-cleanup-incomplete$",
        ) as error:
            await asyncio.wait_for(run, timeout=0.2)
        assert error.value.__cause__ is None
        assert error.value.__suppress_context__ is True
        assert "private-spontaneous-outer" not in repr(error.value)
        assert run.cancelling() == 0
        assert not cancelled.is_set()
        assert victim.cancelling() == 0
        assert victim in guard._quarantine  # noqa: SLF001 - ownership invariant
    finally:
        release.set()
        await asyncio.gather(victim, return_exceptions=True)
        await asyncio.sleep(0)

    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.1)


@pytest.mark.asyncio
async def test_deadline_guard_bounds_cancellation_suppressing_clock_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deadline_module, "_CANCEL_OBSERVE_SECONDS", 0.01, raising=False)
    clock = _CancellationSuppressingClock()
    guard = DeadlineGuard(clock)
    run = asyncio.create_task(guard.run(_coroutine("private-result"), deadline=5.0))
    await clock.sleep_entered.wait()

    done, _ = await asyncio.wait({run}, timeout=0.2)
    finished_within_bound = run in done
    if not finished_within_bound:
        clock.release_sleep.set()
        await asyncio.gather(run, return_exceptions=True)

    assert finished_within_bound
    assert type(run.exception()).__name__ == "DeadlineCleanupIncomplete"
    assert clock.cancelled.is_set()
    assert guard._quarantine  # noqa: SLF001 - clock task remains owned while live

    clock.release_sleep.set()
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert guard._quarantine == set()  # noqa: SLF001 - released ownership contract


@pytest.mark.asyncio
async def test_cleanup_incomplete_drops_private_operation_exception_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deadline_module, "_CANCEL_OBSERVE_SECONDS", 0.01, raising=False)
    clock = _CancellationSuppressingClock()
    guard = DeadlineGuard(clock)
    run = asyncio.create_task(guard.run(_raise_private_operation_error(), deadline=5.0))
    await clock.sleep_entered.wait()

    try:
        with pytest.raises(
            DeadlineCleanupIncomplete,
            match="^deadline-cleanup-incomplete$",
        ) as error:
            await asyncio.wait_for(run, timeout=0.2)
        assert error.value.__cause__ is None
        assert error.value.__context__ is None
        assert clock.cancelled.is_set()
        assert guard._quarantine  # noqa: SLF001 - live clock remains owned
    finally:
        clock.release_sleep.set()
        await asyncio.gather(run, return_exceptions=True)
        await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.1)

    assert guard._quarantine == set()  # noqa: SLF001 - released ownership contract


@pytest.mark.asyncio
async def test_cleanup_incomplete_traceback_drops_discarded_private_operation() -> None:
    guard = DeadlineGuard(_Clock())
    entered = asyncio.Event()
    private_group = ExceptionGroup(
        "private-provider-group",
        [RuntimeError("private-provider-error"), DeadlineCleanupIncomplete()],
    )
    operation = asyncio.create_task(
        _replace_cancellation(private_group, entered),
        name="deadline-private-group-operation",
    )
    await entered.wait()

    with pytest.raises(
        DeadlineCleanupIncomplete,
        match="^deadline-cleanup-incomplete$",
    ) as failure:
        await guard.run(operation, deadline=float("nan"))

    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    traceback = failure.value.__traceback__
    run_locals: dict[str, object] | None = None
    while traceback is not None:
        assert traceback.tb_frame.f_code.co_name != "_run_owned"
        if traceback.tb_frame.f_code.co_name == "run":
            run_locals = dict(traceback.tb_frame.f_locals)
        traceback = traceback.tb_next
    assert run_locals is not None
    assert run_locals["operation"] is None
    assert "private-provider" not in repr(run_locals)


@pytest.mark.asyncio
async def test_cleanup_incomplete_traceback_drops_borrowed_private_operation() -> None:
    guard = DeadlineGuard(_Clock())
    entered = asyncio.Event()
    operation = asyncio.create_task(
        _replace_cancellation(RuntimeError("private-provider-error"), entered),
        name="deadline-private-error-operation",
    )
    await entered.wait()

    with pytest.raises(
        DeadlineCleanupIncomplete,
        match="^deadline-cleanup-incomplete$",
    ) as failure:
        await guard.run(operation, deadline=float("nan"))

    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    traceback = failure.value.__traceback__
    run_locals: dict[str, object] | None = None
    while traceback is not None:
        assert traceback.tb_frame.f_code.co_name != "_run_owned"
        if traceback.tb_frame.f_code.co_name == "run":
            run_locals = dict(traceback.tb_frame.f_locals)
        traceback = traceback.tb_next
    assert run_locals is not None
    assert run_locals["operation"] is None
    assert "private-provider" not in repr(run_locals)
    operation.cancel()
    await asyncio.gather(operation, return_exceptions=True)
    await asyncio.sleep(0)
    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.1)


@pytest.mark.asyncio
async def test_deadline_exceeded_traceback_drops_cancelled_private_operation_outcome() -> None:
    clock = _Clock()
    guard = DeadlineGuard(clock)
    entered = asyncio.Event()
    run = asyncio.create_task(
        guard.run(
            _replace_cancellation(RuntimeError("private-timeout-cleanup"), entered),
            deadline=5.0,
        )
    )
    await entered.wait()
    await clock.sleep_entered.wait()
    clock.release_sleep.set()

    with pytest.raises(DeadlineExceeded, match="^deadline-exceeded$") as failure:
        await run

    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    traceback = failure.value.__traceback__
    run_locals: dict[str, object] | None = None
    while traceback is not None:
        assert traceback.tb_frame.f_code.co_name != "_run_owned"
        if traceback.tb_frame.f_code.co_name == "run":
            run_locals = dict(traceback.tb_frame.f_locals)
        traceback = traceback.tb_next
    assert run_locals is not None
    assert run_locals["operation"] is None
    assert "private-timeout-cleanup" not in repr(run_locals)


@pytest.mark.asyncio
async def test_external_cancellation_traceback_drops_displaced_private_operation_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deadline_module, "_CANCEL_OBSERVE_SECONDS", 0.1, raising=False)
    clock = _CancellationSuppressingClock()
    guard = DeadlineGuard(clock)
    run = asyncio.create_task(
        guard.run(_raise_private_operation_error(), deadline=5.0),
        name="deadline-private-error-owner",
    )
    await clock.cancelled.wait()

    run.cancel("owner-during-cleanup")
    clock.release_sleep.set()

    with pytest.raises(asyncio.CancelledError) as cancellation:
        await run
    assert cancellation.value.args == ("owner-during-cleanup",)
    assert cancellation.value.__cause__ is None
    assert cancellation.value.__context__ is None
    traceback = cancellation.value.__traceback__
    run_locals: dict[str, object] | None = None
    while traceback is not None:
        assert traceback.tb_frame.f_code.co_name != "_run_owned"
        if traceback.tb_frame.f_code.co_name == "run":
            run_locals = dict(traceback.tb_frame.f_locals)
        traceback = traceback.tb_next
    if run_locals is not None:
        assert run_locals["operation"] is None
    assert "private-operation-error" not in repr(run_locals)


@pytest.mark.asyncio
async def test_cleanup_incomplete_dominates_spontaneous_operation_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deadline_module, "_CANCEL_OBSERVE_SECONDS", 0.01, raising=False)
    clock = _CancellationSuppressingClock()
    guard = DeadlineGuard(clock)
    run = asyncio.create_task(guard.run(_raise_private_operation_cancellation(), deadline=5.0))
    await clock.sleep_entered.wait()

    try:
        with pytest.raises(
            DeadlineCleanupIncomplete,
            match="^deadline-cleanup-incomplete$",
        ) as error:
            await asyncio.wait_for(run, timeout=0.2)
        assert error.value.__cause__ is None
        assert error.value.__context__ is None
        assert run.cancelling() == 0
        assert clock.cancelled.is_set()
        assert guard._quarantine  # noqa: SLF001 - live clock remains owned
    finally:
        clock.release_sleep.set()
        await asyncio.gather(run, return_exceptions=True)
        await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.1)

    assert guard._quarantine == set()  # noqa: SLF001 - released ownership contract


@pytest.mark.asyncio
async def test_second_external_cancellation_cannot_preempt_deadline_cleanup_or_replace_first_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deadline_module, "_CANCEL_OBSERVE_SECONDS", 0.01, raising=False)
    clock = _CancellationSuppressingClock()
    guard = DeadlineGuard(clock)
    finalized = asyncio.Event()
    operation = asyncio.create_task(_forever(finalized))
    run = asyncio.create_task(guard.run(operation, deadline=5.0))
    await clock.sleep_entered.wait()

    run.cancel("first-cancel")
    await clock.cancelled.wait()
    run.cancel("second-cancel")
    await asyncio.sleep(0)

    finished_immediately = run.done()
    if not run.done():
        await asyncio.wait({run}, timeout=0.2)
    retained_live_clock = bool(guard._quarantine)  # noqa: SLF001
    clock.release_sleep.set()
    operation.cancel()
    await asyncio.gather(operation, return_exceptions=True)
    with pytest.raises(asyncio.CancelledError) as cancellation:
        await run
    quarantine_drained = await guard.observe_quarantine(
        deadline=asyncio.get_running_loop().time() + 0.1
    )

    assert not finished_immediately
    assert run.done()
    assert cancellation.value.args in ((), ("first-cancel",))
    assert cancellation.value.args != ("second-cancel",)
    assert finalized.is_set()
    assert retained_live_clock
    assert quarantine_drained
    assert guard._quarantine == set()  # noqa: SLF001 - released ownership contract


@pytest.mark.asyncio
async def test_second_external_cancellation_cannot_preempt_cancel_many_or_replace_first_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deadline_module, "_CANCEL_OBSERVE_SECONDS", 0.01, raising=False)
    guard = DeadlineGuard(_Clock())
    owner_entered = asyncio.Event()
    victim_entered = asyncio.Event()
    victim_cancelled = asyncio.Event()
    victim_release = asyncio.Event()
    victim = asyncio.create_task(
        _suppress_cancellation_until_released(
            victim_entered,
            victim_cancelled,
            victim_release,
        )
    )
    await victim_entered.wait()

    async def owner() -> None:
        try:
            owner_entered.set()
            await asyncio.Event().wait()
        finally:
            await guard.cancel_many(victim)

    run = asyncio.create_task(owner())
    await owner_entered.wait()
    run.cancel("first-cancel")
    await victim_cancelled.wait()
    run.cancel("second-cancel")
    await asyncio.sleep(0)

    finished_immediately = run.done()
    if not run.done():
        await asyncio.wait({run}, timeout=0.2)
    retained_victim = victim in guard._quarantine  # noqa: SLF001
    victim_release.set()
    await asyncio.gather(victim, return_exceptions=True)
    with pytest.raises(asyncio.CancelledError) as cancellation:
        await run
    quarantine_drained = await guard.observe_quarantine(
        deadline=asyncio.get_running_loop().time() + 0.1
    )

    assert not finished_immediately
    assert cancellation.value.args in ((), ("first-cancel",))
    assert cancellation.value.args != ("second-cancel",)
    assert retained_victim
    assert quarantine_drained
    assert guard._quarantine == set()  # noqa: SLF001 - released ownership contract


@pytest.mark.asyncio
async def test_cancel_many_fans_out_cancellation_before_observing_any_sibling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deadline_module, "_CANCEL_OBSERVE_SECONDS", 0.03, raising=False)
    guard = DeadlineGuard(_Clock())
    first_entered = asyncio.Event()
    first_cancelled = asyncio.Event()
    first_release = asyncio.Event()
    second_entered = asyncio.Event()
    second_cancelled = asyncio.Event()
    second_release = asyncio.Event()
    first = asyncio.create_task(
        _suppress_cancellation_until_released(
            first_entered,
            first_cancelled,
            first_release,
        )
    )
    second = asyncio.create_task(
        _suppress_cancellation_until_released(
            second_entered,
            second_cancelled,
            second_release,
        )
    )
    await first_entered.wait()
    await second_entered.wait()
    cleanup = asyncio.create_task(guard.cancel_many(first, second))

    try:
        await first_cancelled.wait()
        await asyncio.sleep(0)
        assert second_cancelled.is_set()
    finally:
        first_release.set()
        second_release.set()
        await asyncio.gather(first, second, return_exceptions=True)
        await cleanup


@pytest.mark.asyncio
async def test_deadline_run_cancels_timer_and_work_before_observing_either(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deadline_module, "_CANCEL_OBSERVE_SECONDS", 0.03, raising=False)
    clock = _CancellationSuppressingClock()
    guard = DeadlineGuard(clock)
    work_entered = asyncio.Event()
    work_cancelled = asyncio.Event()
    work_release = asyncio.Event()
    run = asyncio.create_task(
        guard.run(
            _suppress_cancellation_until_released(
                work_entered,
                work_cancelled,
                work_release,
            ),
            deadline=5.0,
        )
    )
    await work_entered.wait()
    await clock.sleep_entered.wait()
    run.cancel("external-cancel")

    try:
        await clock.cancelled.wait()
        await asyncio.sleep(0)
        assert work_cancelled.is_set()
    finally:
        clock.release_sleep.set()
        work_release.set()
        with pytest.raises(asyncio.CancelledError):
            await run


@pytest.mark.parametrize(
    "api",
    ["cancel-and-observe", "cancel-many", "observe-quarantine"],
)
@pytest.mark.asyncio
async def test_pending_owner_cancellation_precedes_unrelated_active_child_cancellation(
    api: str,
) -> None:
    guard = DeadlineGuard(_Clock())
    finalized = asyncio.Event()
    victim = asyncio.create_task(_forever(finalized))
    await asyncio.sleep(0)
    if api == "observe-quarantine":
        guard._retain(victim)  # noqa: SLF001 - exercise active quarantine ownership

    async def owner() -> None:
        current = asyncio.current_task()
        assert current is not None
        try:
            raise asyncio.CancelledError("private-unrelated-child-cancel")
        finally:
            current.cancel("owner-cancel")
            if api == "cancel-and-observe":
                await guard.cancel_and_observe(victim)
            elif api == "cancel-many":
                await guard.cancel_many(victim)
            else:
                await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.1)

    run = asyncio.create_task(owner())
    with pytest.raises(asyncio.CancelledError) as cancellation:
        await run

    assert cancellation.value.args in ((), ("owner-cancel",))
    assert "private-unrelated-child-cancel" not in repr(cancellation.value)
    assert finalized.is_set()
    assert victim.cancelled()


@pytest.mark.asyncio
async def test_second_cancellation_delivered_during_entry_claim_cannot_replace_first() -> None:
    guard = DeadlineGuard(_Clock())
    finalized = asyncio.Event()
    victim = asyncio.create_task(_forever(finalized))
    entered = asyncio.Event()

    async def owner() -> None:
        current = asyncio.current_task()
        assert current is not None
        try:
            entered.set()
            await asyncio.Event().wait()
        finally:
            asyncio.get_running_loop().call_soon(current.cancel, "second-cancel")
            await guard.cancel_many(victim)

    run = asyncio.create_task(owner())
    await entered.wait()
    run.cancel("first-cancel")

    with pytest.raises(asyncio.CancelledError) as cancellation:
        await run

    assert cancellation.value.args in ((), ("first-cancel",))
    assert cancellation.value.args != ("second-cancel",)
    assert finalized.is_set()
    assert victim.cancelled()


@pytest.mark.parametrize(
    "api",
    ["cancel-and-observe", "cancel-many", "observe-quarantine"],
)
@pytest.mark.asyncio
async def test_consumed_owner_cancellation_never_adopts_unrelated_active_child_cancellation(
    api: str,
) -> None:
    guard = DeadlineGuard(_Clock())
    finalized = asyncio.Event()
    victim = asyncio.create_task(_forever(finalized))
    await asyncio.sleep(0)
    if api == "observe-quarantine":
        guard._retain(victim)  # noqa: SLF001 - exercise active quarantine ownership

    async def owner() -> None:
        current = asyncio.current_task()
        assert current is not None
        current.cancel("consumed-owner-cancel")
        try:
            await asyncio.sleep(0)
        except asyncio.CancelledError as consumed:
            assert consumed.args == ("consumed-owner-cancel",)
        assert current.cancelling() == 1
        try:
            raise asyncio.CancelledError("private-unrelated-child-cancel")
        except asyncio.CancelledError:
            if api == "cancel-and-observe":
                await guard.cancel_and_observe(victim)
            elif api == "cancel-many":
                await guard.cancel_many(victim)
            else:
                await guard.observe_quarantine(
                    deadline=asyncio.get_running_loop().time() + 0.1,
                )

    run = asyncio.create_task(owner())
    with pytest.raises(asyncio.CancelledError) as cancellation:
        await run

    assert cancellation.value.args == ()
    assert "private-unrelated-child-cancel" not in repr(cancellation.value)
    assert finalized.is_set()
    assert victim.cancelled()


@pytest.mark.asyncio
async def test_hostile_cancel_hook_self_cancelling_cleanup_still_fans_out_siblings() -> None:
    guard = DeadlineGuard(_Clock())
    hostile = _SelfCancellingCancelFuture()
    sibling_finalized = asyncio.Event()
    sibling = asyncio.create_task(_forever(sibling_finalized))
    await asyncio.sleep(0)

    complete = await asyncio.wait_for(
        guard.cancel_many(hostile, sibling),
        timeout=0.2,
    )

    assert complete is False
    assert hostile.cancel_calls == 1
    assert hostile in guard._quarantine  # noqa: SLF001 - live hostile work remains owned
    assert sibling.cancelled()
    assert sibling_finalized.is_set()
    hostile.set_result("settled")
    await asyncio.sleep(0)
    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.01)


@pytest.mark.asyncio
async def test_self_cancelled_work_task_is_cleanup_incomplete_not_public_cancellation() -> None:
    async def self_cancel_before_return() -> str:
        current = asyncio.current_task()
        assert current is not None
        current.cancel("private-work-self-cancel")
        return "private-result"

    with pytest.raises(
        DeadlineCleanupIncomplete,
        match="^deadline-cleanup-incomplete$",
    ) as failure:
        await DeadlineGuard(_Clock()).run(self_cancel_before_return(), deadline=5.0)

    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None


@pytest.mark.asyncio
async def test_self_cancelled_timer_task_is_clock_error_not_public_cancellation() -> None:
    with pytest.raises(DeadlineClockError, match="^deadline-clock-invalid$") as failure:
        await DeadlineGuard(_SelfCancellingSleeperClock()).run(
            _coroutine("private-result"),
            deadline=5.0,
        )

    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None


@pytest.mark.asyncio
async def test_cancel_many_scalar_fatal_traceback_drops_owned_tasks() -> None:
    guard = DeadlineGuard(_Clock())
    fatal = _FatalProbe("private-cancel-many-fatal")
    victim = _CancelRaisesFuture(fatal)

    with pytest.raises(_FatalProbe) as failure:
        await guard.cancel_many(victim)

    assert failure.value is fatal
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    traceback = failure.value.__traceback__
    cancel_locals: dict[str, object] | None = None
    while traceback is not None:
        assert traceback.tb_frame.f_code.co_name not in {
            "_cancel_all_until",
            "_cancel_many_owned",
            "_finish_cleanup_despite_cancellation",
        }
        if traceback.tb_frame.f_code.co_name == "cancel_many":
            cancel_locals = dict(traceback.tb_frame.f_locals)
        traceback = traceback.tb_next
    assert cancel_locals is not None
    assert cancel_locals["self"] is None
    assert cancel_locals["tasks"] == ()
    assert "private-cancel-many-fatal" not in repr(cancel_locals)
    assert victim in guard._quarantine  # noqa: SLF001 - live work remains owned

    victim.set_result("settled")
    await asyncio.sleep(0)
    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.01)


@pytest.mark.asyncio
async def test_observe_quarantine_scalar_fatal_traceback_drops_snapshot() -> None:
    guard = DeadlineGuard(_Clock())
    fatal = _FatalProbe("private-observe-fatal")
    victim = _CancelRaisesFuture(fatal)
    guard._retain(victim)  # noqa: SLF001 - exercise active quarantine ownership

    with pytest.raises(_FatalProbe) as failure:
        await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.01)

    assert failure.value is fatal
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    traceback = failure.value.__traceback__
    observe_locals: dict[str, object] | None = None
    while traceback is not None:
        assert traceback.tb_frame.f_code.co_name not in {
            "_cancel_all_until",
            "_finish_cleanup_despite_cancellation",
            "_observe_quarantine_owned",
        }
        if traceback.tb_frame.f_code.co_name == "observe_quarantine":
            observe_locals = dict(traceback.tb_frame.f_locals)
        traceback = traceback.tb_next
    assert observe_locals is not None
    assert observe_locals["self"] is None
    assert observe_locals["deadline"] is None
    assert "private-observe-fatal" not in repr(observe_locals)
    assert victim in guard._quarantine  # noqa: SLF001 - live work remains owned

    victim.set_result("settled")
    await asyncio.sleep(0)
    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.01)


@pytest.mark.asyncio
async def test_consumed_cancellation_precedes_cancel_and_observe_result() -> None:
    guard = DeadlineGuard(_Clock())
    finalized = asyncio.Event()
    victim = asyncio.create_task(_forever(finalized))
    await asyncio.sleep(0)
    owner = asyncio.current_task()
    assert owner is not None
    owner.cancel("consumed-before-cancel-one")
    try:
        with pytest.raises(asyncio.CancelledError) as delivered:
            await asyncio.sleep(0)
        assert delivered.value.args == ("consumed-before-cancel-one",)
        assert owner.cancelling() == 1

        with pytest.raises(asyncio.CancelledError) as failure:
            await guard.cancel_and_observe(victim)

        assert failure.value.args == ()
        assert failure.value.__cause__ is None
        assert failure.value.__context__ is None
        assert victim.cancelled()
        assert finalized.is_set()
    finally:
        while owner.cancelling():
            owner.uncancel()
        if not victim.done():
            victim.cancel()
        await asyncio.gather(victim, return_exceptions=True)


@pytest.mark.asyncio
async def test_consumed_cancellation_precedes_cancel_many_result() -> None:
    guard = DeadlineGuard(_Clock())
    first_finalized = asyncio.Event()
    second_finalized = asyncio.Event()
    first = asyncio.create_task(_forever(first_finalized))
    second = asyncio.create_task(_forever(second_finalized))
    await asyncio.sleep(0)
    owner = asyncio.current_task()
    assert owner is not None
    owner.cancel("consumed-before-cancel-many")
    try:
        with pytest.raises(asyncio.CancelledError) as delivered:
            await asyncio.sleep(0)
        assert delivered.value.args == ("consumed-before-cancel-many",)
        assert owner.cancelling() == 1

        with pytest.raises(asyncio.CancelledError) as failure:
            await guard.cancel_many(first, second)

        assert failure.value.args == ()
        assert failure.value.__cause__ is None
        assert failure.value.__context__ is None
        assert first.cancelled()
        assert second.cancelled()
        assert first_finalized.is_set()
        assert second_finalized.is_set()
    finally:
        while owner.cancelling():
            owner.uncancel()
        for task in (first, second):
            if not task.done():
                task.cancel()
        await asyncio.gather(first, second, return_exceptions=True)


@pytest.mark.asyncio
async def test_consumed_cancellation_precedes_observe_quarantine_result() -> None:
    guard = DeadlineGuard(_Clock())
    finalized = asyncio.Event()
    victim = asyncio.create_task(_forever(finalized))
    await asyncio.sleep(0)
    guard._retain(victim)  # noqa: SLF001 - exercise active quarantine ownership
    owner = asyncio.current_task()
    assert owner is not None
    owner.cancel("consumed-before-observe")
    try:
        with pytest.raises(asyncio.CancelledError) as delivered:
            await asyncio.sleep(0)
        assert delivered.value.args == ("consumed-before-observe",)
        assert owner.cancelling() == 1

        with pytest.raises(asyncio.CancelledError) as failure:
            await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.1)

        assert failure.value.args == ()
        assert failure.value.__cause__ is None
        assert failure.value.__context__ is None
        assert victim.cancelled()
        assert finalized.is_set()
        traceback = failure.value.__traceback__
        observe_locals: dict[str, object] | None = None
        while traceback is not None:
            assert traceback.tb_frame.f_code.co_name not in {
                "_finish_cleanup_despite_cancellation",
                "_observe_quarantine_owned",
            }
            if traceback.tb_frame.f_code.co_name == "observe_quarantine":
                observe_locals = dict(traceback.tb_frame.f_locals)
            traceback = traceback.tb_next
        assert observe_locals is not None
        assert observe_locals["self"] is None
        assert observe_locals["deadline"] is None
    finally:
        while owner.cancelling():
            owner.uncancel()
        if not victim.done():
            victim.cancel()
        await asyncio.gather(victim, return_exceptions=True)


@pytest.mark.parametrize(
    "api",
    ["cancel-and-observe", "cancel-many", "observe-quarantine"],
)
@pytest.mark.asyncio
async def test_pending_entry_cancellation_preserves_exact_cause_before_cleanup_fatal(
    api: str,
) -> None:
    guard = DeadlineGuard(_Clock())
    fatal = _FatalProbe(f"private-{api}-cleanup-fatal")
    victim = _CancelRaisesFuture(fatal)
    if api == "observe-quarantine":
        guard._retain(victim)  # noqa: SLF001 - exercise active quarantine ownership

    async def owner() -> None:
        current = asyncio.current_task()
        assert current is not None
        current.cancel("pending-entry-cancel")
        if api == "cancel-and-observe":
            await guard.cancel_and_observe(victim)
        elif api == "cancel-many":
            await guard.cancel_many(victim)
        else:
            await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.01)

    run = asyncio.create_task(owner())
    with pytest.raises(asyncio.CancelledError) as failure:
        await run

    assert failure.value.args == ("pending-entry-cancel",)
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert victim.cancel_calls == 1
    assert victim in guard._quarantine  # noqa: SLF001 - live work remains owned

    victim.set_result("settled")
    await asyncio.sleep(0)
    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.01)


@pytest.mark.parametrize(
    "api",
    ["cancel-and-observe", "cancel-many", "observe-quarantine"],
)
@pytest.mark.asyncio
async def test_child_cancellation_is_not_misclassified_as_owner_cancellation(api: str) -> None:
    guard = DeadlineGuard(_Clock())
    victim = _CancelRaisesFuture(asyncio.CancelledError("private-child-cancel"))
    if api == "observe-quarantine":
        guard._retain(victim)  # noqa: SLF001 - exercise active quarantine ownership

    if api == "cancel-and-observe":
        complete = await guard.cancel_and_observe(victim)
    elif api == "cancel-many":
        complete = await guard.cancel_many(victim)
    else:
        complete = await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.01)

    owner = asyncio.current_task()
    assert owner is not None
    assert owner.cancelling() == 0
    assert complete is False
    assert victim.cancel_calls == 1
    assert victim in guard._quarantine  # noqa: SLF001 - live work remains owned

    victim.set_result("settled")
    await asyncio.sleep(0)
    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.01)


@pytest.mark.parametrize(
    "api",
    ["cancel-and-observe", "cancel-many", "observe-quarantine"],
)
@pytest.mark.asyncio
async def test_consumed_owner_cancellation_sanitizes_active_child_cancellation(api: str) -> None:
    guard = DeadlineGuard(_Clock())
    victim = _CancelRaisesFuture(asyncio.CancelledError("private-child-cancel"))
    if api == "observe-quarantine":
        guard._retain(victim)  # noqa: SLF001 - exercise active quarantine ownership

    async def owner() -> None:
        current = asyncio.current_task()
        assert current is not None
        current.cancel("consumed-owner-cancel")
        try:
            await asyncio.sleep(0)
        except asyncio.CancelledError as consumed:
            assert consumed.args == ("consumed-owner-cancel",)

        try:
            raise asyncio.CancelledError("private-active-child-cancel")
        finally:
            if api == "cancel-and-observe":
                await guard.cancel_and_observe(victim)
            elif api == "cancel-many":
                await guard.cancel_many(victim)
            else:
                await guard.observe_quarantine(
                    deadline=asyncio.get_running_loop().time() + 0.01,
                )

    run = asyncio.create_task(owner())
    with pytest.raises(asyncio.CancelledError) as failure:
        await run

    assert failure.value.args == ()
    assert "private-active-child-cancel" not in repr(failure.value)
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert victim.cancel_calls == 1
    assert victim in guard._quarantine  # noqa: SLF001 - live work remains owned

    victim.set_result("settled")
    await asyncio.sleep(0)
    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.01)
