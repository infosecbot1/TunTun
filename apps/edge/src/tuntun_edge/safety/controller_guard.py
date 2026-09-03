from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable, Coroutine
from typing import Any, Protocol, TypeVar

from tuntun_contracts.reachy import SafetyReceipt

_ResultT = TypeVar("_ResultT")


class ControllerSource(Protocol):
    async def active_controllers(self) -> set[str]: ...


class EdgeSafety(Protocol):
    async def close_media(self) -> None: ...

    async def stop_playback(self) -> None: ...

    async def stop_motion(self) -> None: ...

    async def enter_error_safe(self, reason: str) -> None: ...


class _TaskFactoryUnavailable(RuntimeError):
    pass


class ControllerGuard:
    def __init__(
        self,
        *,
        source: ControllerSource,
        safety: EdgeSafety,
        expected: str,
        operation_timeout: float = 0.250,
    ) -> None:
        if type(expected) is not str or not expected:
            raise ValueError("controller expected identity invalid")
        if type(operation_timeout) not in {int, float} or operation_timeout <= 0:
            raise ValueError("controller operation timeout invalid")
        self._source = source
        self._safety = safety
        self._expected = expected
        self._timeout = float(operation_timeout)
        self.error_safe_latched = False
        self.last_receipt = SafetyReceipt(
            turn_id=None,
            playback_stopped=False,
            motion_stopped=False,
            buffers_cleared=False,
        )
        self.last_failure_codes: tuple[str, ...] = ()
        self.last_caller_cancellations = 0
        self.task_factory_failure_points: tuple[str, ...] = ()
        self.process_restart_required = False
        self._background: set[asyncio.Task[Any]] = set()
        self._abandon_timeout = min(max(self._timeout, 0.001), 1.0)

    async def poll(self) -> bool:
        if self.process_restart_required:
            self.error_safe_latched = True
            self.last_failure_codes = tuple(
                dict.fromkeys((*self.last_failure_codes, "controller_process_restart_required"))
            )
            return False
        caller_cancellations = 0
        inventory_failure_code: str | None = None
        active: set[str]
        try:
            inventory_task = self._spawn_owned_task(
                self._source.active_controllers,
                name="controller-inventory",
            )
        except _TaskFactoryUnavailable:
            self.process_restart_required = True
            inventory_failure_code = "controller_inventory:factory_unavailable"
            active = set()
        else:
            self._retain_background(inventory_task)
            try:
                done, pending = await asyncio.wait({inventory_task}, timeout=self._timeout)
            except asyncio.CancelledError:
                caller_cancellations += 1
                caller_cancellations = _preserved_cancellation_count(caller_cancellations)
                observed, extra_cancellations = await _cancel_and_observe_preserving_cancellation(
                    inventory_task,
                    timeout=self._abandon_timeout,
                    already_observed_cancellations=_current_cancelling_count(),
                )
                caller_cancellations = _preserved_cancellation_count(
                    caller_cancellations + extra_cancellations
                )
                if not observed:
                    self.process_restart_required = True
                inventory_failure_code = "controller_inventory:caller_cancelled"
                active = set()
            else:
                if pending:
                    (
                        observed,
                        extra_cancellations,
                    ) = await _cancel_and_observe_preserving_cancellation(
                        inventory_task,
                        timeout=self._abandon_timeout,
                        already_observed_cancellations=_current_cancelling_count(),
                    )
                    if extra_cancellations:
                        caller_cancellations = _preserved_cancellation_count(
                            caller_cancellations + extra_cancellations
                        )
                    if not observed:
                        self.process_restart_required = True
                    inventory_failure_code = "controller_inventory:timeout"
                    active = set()
                else:
                    try:
                        active = _strict_controller_ids(inventory_task.result())
                    except ValueError:
                        inventory_failure_code = "controller_inventory:invalid"
                        active = set()
                    except BaseException as error:
                        inventory_failure_code = f"controller_inventory:{type(error).__name__}"
                        active = set()
        if active == {self._expected}:
            return True
        self.error_safe_latched = True
        try:
            barrier = self._spawn_owned_task(
                self._close_all_error_safe,
                name="competing-controller-safety",
            )
        except _TaskFactoryUnavailable:
            self.process_restart_required = True
            failures: tuple[str, ...] = ("competing_controller_safety:factory_unavailable",)
            if inventory_failure_code is not None:
                failures = (inventory_failure_code, *failures)
            self.last_failure_codes = failures
            self.last_caller_cancellations = caller_cancellations
            if caller_cancellations:
                raise asyncio.CancelledError from None
            return False
        self._retain_background(barrier)
        while not barrier.done():
            try:
                await asyncio.shield(barrier)
            except asyncio.CancelledError:
                caller_cancellations += 1
                caller_cancellations = _preserved_cancellation_count(caller_cancellations)
                continue
        barrier.result()
        if inventory_failure_code is not None:
            self.last_failure_codes = (inventory_failure_code, *self.last_failure_codes)
        self.last_caller_cancellations = caller_cancellations
        if caller_cancellations:
            raise asyncio.CancelledError
        return False

    async def _close_all_error_safe(self) -> None:
        self.error_safe_latched = True
        operations: dict[str, asyncio.Task[Any]] = {}
        failures: list[str] = []
        for name, factory in (
            ("close_media", self._safety.close_media),
            ("stop_playback", self._safety.stop_playback),
            ("stop_motion", self._safety.stop_motion),
            ("error_safe", lambda: self._safety.enter_error_safe("competing_controller")),
        ):
            try:
                task = self._spawn_owned_task(factory, name=name)
            except _TaskFactoryUnavailable:
                self.process_restart_required = True
                failures.append(f"{name}:factory_unavailable")
            else:
                operations[name] = task
                self._retain_background(task)
        done: set[asyncio.Task[Any]] = set()
        pending: set[asyncio.Task[Any]] = set()
        if operations:
            done, pending = await asyncio.wait(set(operations.values()), timeout=self._timeout)
        ok = {name: False for name in ("close_media", "stop_playback", "stop_motion", "error_safe")}
        for task in pending:
            if not await _cancel_and_observe(task, timeout=self._abandon_timeout):
                self.process_restart_required = True
        for name, task in operations.items():
            if task not in done:
                failures.append(f"{name}:timeout")
                continue
            try:
                task.result()
            except BaseException as error:
                failures.append(f"{name}:{type(error).__name__}")
            else:
                ok[name] = True
        self.last_receipt = SafetyReceipt(
            turn_id=None,
            playback_stopped=ok["stop_playback"] and ok["error_safe"],
            motion_stopped=ok["stop_motion"] and ok["error_safe"],
            buffers_cleared=ok["close_media"] and ok["error_safe"],
        )
        self.last_failure_codes = tuple(failures)

    def _spawn_owned_task(
        self,
        factory: Callable[[], Coroutine[Any, Any, _ResultT]],
        *,
        name: str,
    ) -> asyncio.Task[_ResultT]:
        coroutine = factory()
        try:
            return asyncio.create_task(coroutine, name=name)
        except BaseException as error:
            _close_unstarted(coroutine)
            if not isinstance(error, Exception):
                raise
            self.task_factory_failure_points = tuple(
                dict.fromkeys((*self.task_factory_failure_points, name))
            )
        fallback = factory()
        try:
            return asyncio.Task(fallback, loop=asyncio.get_running_loop(), name=name)
        except BaseException as error:
            _close_unstarted(fallback)
            if not isinstance(error, Exception):
                raise
            raise _TaskFactoryUnavailable(f"{name}:factory_unavailable") from error

    def _retain_background(self, task: asyncio.Task[Any]) -> None:
        self._background.add(task)

        def observed(completed: asyncio.Task[Any]) -> None:
            self._background.discard(completed)
            with contextlib.suppress(BaseException):
                completed.result()

        task.add_done_callback(observed)


def _strict_controller_ids(value: object) -> set[str]:
    if type(value) is not set or not 1 <= len(value) <= 32:
        raise ValueError("controller inventory invalid")
    for identifier in value:
        if (
            type(identifier) is not str
            or not 1 <= len(identifier) <= 128
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in identifier)
        ):
            raise ValueError("controller inventory invalid")
    return set(value)


def _close_unstarted(awaitable: object) -> None:
    close = getattr(awaitable, "close", None)
    if callable(close):
        with contextlib.suppress(BaseException):
            close()


async def _cancel_and_observe(task: asyncio.Task[Any], *, timeout: float) -> bool:
    if not task.done():
        task.cancel()
    done, _pending = await asyncio.wait({task}, timeout=timeout)
    if task not in done:
        return False
    with contextlib.suppress(BaseException):
        task.result()
    return True


async def _cancel_and_observe_preserving_cancellation(
    task: asyncio.Task[Any],
    *,
    timeout: float,
    already_observed_cancellations: int = 0,
) -> tuple[bool, int]:
    if not task.done():
        task.cancel()
    caller_cancellations = 0
    observed_cancelling = already_observed_cancellations
    deadline = asyncio.get_running_loop().time() + timeout
    while not task.done():
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            return False, caller_cancellations
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=remaining)
        except TimeoutError:
            return False, caller_cancellations
        except asyncio.CancelledError:
            current_cancelling = _current_cancelling_count()
            if current_cancelling <= observed_cancelling:
                if task.done():
                    with contextlib.suppress(BaseException):
                        task.result()
                    return True, caller_cancellations
                continue
            caller_cancellations += current_cancelling - observed_cancelling
            observed_cancelling = current_cancelling
            continue
    with contextlib.suppress(BaseException):
        task.result()
    return True, caller_cancellations


def _current_cancelling_count() -> int:
    current = asyncio.current_task()
    if current is None:
        return 0
    return current.cancelling()


def _preserved_cancellation_count(observed: int) -> int:
    return max(observed, _current_cancelling_count())
