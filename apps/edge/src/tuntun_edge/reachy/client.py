from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable, Coroutine
from datetime import datetime
from typing import Any, Protocol, TypeVar
from uuid import UUID

from tuntun_contracts.base import canonical_bytes, parse_contract_json
from tuntun_contracts.reachy import (
    ReachyCommand,
    ReachyHealth,
    ReachyReceipt,
    ReachyState,
    SafetyReceipt,
    StopAllReceiptBundleV1,
)
from tuntun_contracts.reachy_wire import MAX_CONTROL_PAYLOAD_BYTES

from tuntun_edge.reachy.gestures import validate_gesture

_ResultT = TypeVar("_ResultT")


class DaemonMotion(Protocol):
    async def running_ids(self) -> tuple[str, ...]: ...

    async def stop(self, movement_id: str) -> None: ...

    async def stop_playback(self) -> None: ...

    async def play_stream(self, stream_id: UUID) -> None: ...

    async def set_state(self, state: ReachyState) -> None: ...

    async def gesture(self, gesture_id: str) -> None: ...

    async def connected(self) -> bool: ...

    async def queue_depth(self) -> int: ...


class MediaBuffers(Protocol):
    async def clear(self) -> None: ...


class Clock(Protocol):
    def now(self) -> datetime: ...


class _TaskFactoryUnavailable(RuntimeError):
    pass


class ReachyClient:
    MAX_RUNNING_MOVEMENTS = 32

    def __init__(
        self,
        daemon: DaemonMotion,
        buffers: MediaBuffers,
        clock: Clock,
        *,
        operation_timeout: float = 0.050,
    ) -> None:
        if type(operation_timeout) not in {int, float} or operation_timeout <= 0:
            raise ValueError("reachy operation timeout invalid")
        self._daemon = daemon
        self._buffers = buffers
        self._clock = clock
        self._state = ReachyState.IDLE
        self._operation_timeout = float(operation_timeout)
        self._abandon_timeout = min(max(self._operation_timeout, 0.001), 1.0)
        self._background: set[asyncio.Task[Any]] = set()
        self.last_safety_failure_codes: tuple[str, ...] = ()
        self.last_caller_cancellations = 0
        self.task_factory_failure_points: tuple[str, ...] = ()
        self.process_restart_required = False

    @property
    def state(self) -> ReachyState:
        return self._state

    def latch_error_safe(self, reason: str) -> None:
        if type(reason) is not str or not reason:
            raise ValueError("error safe reason required")
        self._state = ReachyState.ERROR_SAFE

    async def health(self) -> ReachyHealth:
        failures: list[str] = []
        connected_ok, connected = await self._bounded(
            "health_connected",
            self._daemon.connected,
            failures,
        )
        queue_ok, queue_depth = await self._bounded(
            "health_queue_depth",
            self._daemon.queue_depth,
            failures,
        )
        if connected_ok and type(connected) is not bool:
            connected_ok = False
            failures.append("health_connected:invalid")
        if queue_ok and (type(queue_depth) is not int or queue_depth < 0):
            queue_ok = False
            failures.append("health_queue_depth:invalid")
        if not connected_ok or not queue_ok:
            self._state = ReachyState.ERROR_SAFE
            self.last_safety_failure_codes = tuple(failures)
            return ReachyHealth(
                state=self._state,
                daemon_connected=False,
                queue_depth=0,
            )
        daemon_connected: bool = connected if type(connected) is bool else False
        queue_depth_value: int = queue_depth if type(queue_depth) is int else 0
        return ReachyHealth(
            state=self._state,
            daemon_connected=daemon_connected,
            queue_depth=queue_depth_value,
        )

    async def control(self, purpose: str, payload: bytes) -> bytes:
        if purpose == "reachy.command.v1":
            command = parse_contract_json(
                ReachyCommand,
                payload,
                max_bytes=MAX_CONTROL_PAYLOAD_BYTES,
                require_canonical=True,
            )
            receipt, safety = await self.execute(command)
            if safety is not None:
                raise RuntimeError("stop_all requires reachy.stop_all.v1")
            return canonical_bytes(receipt)
        if purpose == "reachy.stop_all.v1":
            command = parse_contract_json(
                ReachyCommand,
                payload,
                max_bytes=MAX_CONTROL_PAYLOAD_BYTES,
                require_canonical=True,
            )
            receipt, safety = await self.execute(command)
            if type(safety) is not SafetyReceipt:
                raise RuntimeError("reachy_safety_receipt_contract_mismatch")
            return canonical_bytes(
                StopAllReceiptBundleV1(command_receipt=receipt, safety_receipt=safety)
            )
        if purpose == "reachy.health.v1":
            if payload != b'{"request":"health"}':
                raise ValueError("reachy health request payload invalid")
            return canonical_bytes(await self.health())
        raise PermissionError("unsupported_reachy_control_purpose")

    async def media(self, frame: bytes) -> None:
        if type(frame) is not bytes or not frame:
            raise ValueError("reachy media frame invalid")

    async def execute(self, command: ReachyCommand) -> tuple[ReachyReceipt, SafetyReceipt | None]:
        if type(command) is not ReachyCommand:
            raise TypeError("reachy command must be exact ReachyCommand")
        if self._clock.now() > command.expires_at:
            return (
                ReachyReceipt(
                    command_id=command.command_id,
                    accepted=False,
                    reason_code="expired",
                ),
                None,
            )
        try:
            safety: SafetyReceipt | None = None
            failures: list[str] = []
            if command.kind == "state":
                if type(command.state) is not ReachyState:
                    raise ValueError("reachy state command payload invalid")
                state_ok, _result = await self._bounded(
                    "execute_set_state",
                    lambda: self._daemon.set_state(command.state),  # type: ignore[arg-type]
                    failures,
                )
                if not state_ok:
                    raise RuntimeError("reachy_execute_set_state_failed")
                self._state = command.state
            elif command.kind == "playback":
                if type(command.media_stream_id) is not UUID:
                    raise ValueError("reachy playback command payload invalid")
                playback_ok, _result = await self._bounded(
                    "execute_play_stream",
                    lambda: self._daemon.play_stream(command.media_stream_id),  # type: ignore[arg-type]
                    failures,
                )
                if not playback_ok:
                    raise RuntimeError("reachy_execute_play_stream_failed")
            elif command.kind == "gesture":
                gesture_id = validate_gesture(command.gesture_id)  # type: ignore[arg-type]
                gesture_ok, _result = await self._bounded(
                    "execute_gesture",
                    lambda: self._daemon.gesture(gesture_id),
                    failures,
                )
                if not gesture_ok:
                    raise RuntimeError("reachy_execute_gesture_failed")
            else:
                safety = await self.stop_all(command.turn_id)
            accepted = safety is None or (
                safety.playback_stopped and safety.motion_stopped and safety.buffers_cleared
            )
            return (
                ReachyReceipt(
                    command_id=command.command_id,
                    accepted=accepted,
                    reason_code="accepted" if accepted else "safety_incomplete",
                ),
                safety,
            )
        except Exception:
            self._state = ReachyState.ERROR_SAFE
            if "failures" in locals() and failures:
                self.last_safety_failure_codes = tuple(failures)
            return (
                ReachyReceipt(
                    command_id=command.command_id,
                    accepted=False,
                    reason_code="edge_execution_failed",
                ),
                None,
            )

    async def stop_all(self, turn_id: UUID | None) -> SafetyReceipt:
        if turn_id is not None and type(turn_id) is not UUID:
            raise TypeError("turn_id must be an exact UUID")
        self.latch_error_safe("stop_all")
        try:
            barrier = self._spawn_owned_task(
                lambda: self._stop_all_once(turn_id), name="edge-stop-all"
            )
        except _TaskFactoryUnavailable:
            self.process_restart_required = True
            self.last_safety_failure_codes = ("stop_all_owner:factory_unavailable",)
            return SafetyReceipt(
                turn_id=turn_id,
                playback_stopped=False,
                motion_stopped=False,
                buffers_cleared=False,
            )
        self._retain_background(barrier)
        caller_cancellations = 0
        while not barrier.done():
            try:
                await asyncio.shield(barrier)
            except asyncio.CancelledError:
                caller_cancellations += 1
                continue
        receipt = barrier.result()
        self.last_caller_cancellations = caller_cancellations
        if caller_cancellations:
            raise asyncio.CancelledError
        return receipt

    async def _stop_all_once(self, turn_id: UUID | None) -> SafetyReceipt:
        self._state = ReachyState.ERROR_SAFE
        failures: list[str] = []
        operations: dict[str, asyncio.Task[Any]] = {}
        for name, factory in (
            ("running_ids_before", self._daemon.running_ids),
            ("stop_playback", self._daemon.stop_playback),
            ("clear_buffers", self._buffers.clear),
            ("enter_error_safe", lambda: self._daemon.set_state(ReachyState.ERROR_SAFE)),
        ):
            try:
                task = self._spawn_owned_task(factory, name=name)
            except _TaskFactoryUnavailable:
                self.process_restart_required = True
                failures.append(f"{name}:factory_unavailable")
            else:
                operations[name] = task
                self._retain_background(task)
        first_results = await self._collect_operations(operations, failures)
        playback_ok = first_results.get("stop_playback", False)
        buffers_ok = first_results.get("clear_buffers", False)
        error_safe_ok = first_results.get("enter_error_safe", False)
        snapshot_ok = first_results.get("running_ids_before", False)
        movement_ids: tuple[str, ...] = ()
        if snapshot_ok:
            try:
                movement_ids = self._strict_movement_ids(operations["running_ids_before"].result())
            except ValueError:
                failures.append("running_ids_before:invalid")
                snapshot_ok = False

        stop_tasks: dict[str, asyncio.Task[Any]] = {}
        for movement_id in movement_ids:
            name = f"stop_motion:{movement_id}"
            try:
                task = self._spawn_owned_task(
                    self._stop_motion_factory(movement_id),
                    name=name,
                )
            except _TaskFactoryUnavailable:
                self.process_restart_required = True
                failures.append(f"{name}:factory_unavailable")
            else:
                stop_tasks[name] = task
                self._retain_background(task)
        stop_results = await self._collect_operations(stop_tasks, failures)

        remaining_ok, remaining = await self._bounded(
            "running_ids_after", self._daemon.running_ids, failures
        )
        if remaining_ok:
            try:
                remaining_ids = self._strict_movement_ids(remaining)
            except ValueError:
                failures.append("running_ids_after:invalid")
                remaining_ok = False
                remaining_ids = ("inventory_unavailable",)
        else:
            remaining_ids = ("inventory_unavailable",)
        motion_ok = (
            snapshot_ok
            and remaining_ok
            and not remaining_ids
            and all(
                stop_results.get(f"stop_motion:{movement_id}", False)
                for movement_id in movement_ids
            )
        )
        idle_restored = False
        if playback_ok and motion_ok and buffers_ok and error_safe_ok:
            idle_restored, _result = await self._bounded(
                "restore_idle",
                lambda: self._daemon.set_state(ReachyState.IDLE),
                failures,
            )
        receipt = SafetyReceipt(
            turn_id=turn_id,
            playback_stopped=playback_ok and error_safe_ok and idle_restored,
            motion_stopped=motion_ok and error_safe_ok and idle_restored,
            buffers_cleared=buffers_ok and error_safe_ok and idle_restored,
        )
        if receipt.playback_stopped and receipt.motion_stopped and receipt.buffers_cleared:
            self._state = ReachyState.IDLE
        else:
            self._state = ReachyState.ERROR_SAFE
        self.last_safety_failure_codes = tuple(failures)
        return receipt

    async def _bounded(
        self,
        name: str,
        factory: Callable[[], Coroutine[Any, Any, _ResultT]],
        failures: list[str],
    ) -> tuple[bool, _ResultT | None]:
        try:
            task = self._spawn_owned_task(factory, name=name)
        except _TaskFactoryUnavailable:
            self.process_restart_required = True
            failures.append(f"{name}:factory_unavailable")
            return False, None
        self._retain_background(task)
        results = await self._collect_operations({name: task}, failures)
        if not results[name]:
            return False, None
        return True, task.result()

    async def _collect_operations(
        self,
        operations: dict[str, asyncio.Task[Any]],
        failures: list[str],
    ) -> dict[str, bool]:
        done: set[asyncio.Task[Any]] = set()
        pending: set[asyncio.Task[Any]] = set()
        if operations:
            done, pending = await asyncio.wait(
                set(operations.values()), timeout=self._operation_timeout
            )
        for task in pending:
            if not await _cancel_and_observe(task, timeout=self._abandon_timeout):
                self.process_restart_required = True
        results: dict[str, bool] = {}
        for name, task in operations.items():
            if task not in done:
                failures.append(f"{name}:timeout")
                results[name] = False
                continue
            try:
                task.result()
            except BaseException as error:
                failures.append(f"{name}:{type(error).__name__}")
                results[name] = False
            else:
                results[name] = True
        return results

    @classmethod
    def _strict_movement_ids(cls, value: object) -> tuple[str, ...]:
        if type(value) is not tuple or len(value) > cls.MAX_RUNNING_MOVEMENTS:
            raise ValueError("movement inventory invalid")
        for movement_id in value:
            if (
                type(movement_id) is not str
                or not 1 <= len(movement_id) <= 128
                or any(ord(character) < 0x20 or ord(character) == 0x7F for character in movement_id)
            ):
                raise ValueError("movement inventory invalid")
        if len(value) != len(set(value)):
            raise ValueError("movement inventory invalid")
        return tuple(value)

    def _stop_motion_factory(self, movement_id: str) -> Callable[[], Coroutine[Any, Any, None]]:
        async def stop_motion() -> None:
            await self._daemon.stop(movement_id)

        return stop_motion

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
