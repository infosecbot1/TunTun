from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Any, Literal, TypeVar
from uuid import UUID

from tuntun_core.domain.conversation import Transition
from tuntun_core.services.sessions.turn_coordinator import (
    CoordinatorState,
    TurnCoordinator,
)

_OperationResultT = TypeVar("_OperationResultT")
_OperationKind = Literal["finish", "cancel"]
_MAX_RETAINED_OPERATIONS = 4


@dataclass(frozen=True, slots=True)
class SessionAdmission:
    household_id: UUID
    turn_id: UUID


class SessionRejected(RuntimeError):
    def __init__(
        self,
        *,
        reason: Literal["busy", "safety_blocked"],
        retry_after_ms: int | None,
    ) -> None:
        self.reason = reason
        self.retry_after_ms = retry_after_ms
        super().__init__(f"session_rejected:{reason}")


class SessionManager:
    """The singleton admission boundary for household conversation turns."""

    def __init__(self, coordinator: TurnCoordinator) -> None:
        if type(coordinator) is not TurnCoordinator:
            raise TypeError("coordinator must be an exact TurnCoordinator")
        self._coordinator = coordinator
        self._active: SessionAdmission | None = None
        self._deferred: SessionAdmission | None = None
        self._deferred_for_turn: UUID | None = None
        self._operations: dict[tuple[UUID, _OperationKind], asyncio.Task[Any]] = {}
        self._lock = asyncio.Lock()

    @property
    def active(self) -> SessionAdmission | None:
        self._synchronize_release()
        return self._active

    @property
    def deferred_wake(self) -> SessionAdmission | None:
        return self._deferred

    @property
    def inflight_operation_count(self) -> int:
        return len(self._operations)

    async def open(self, household_id: UUID, turn_id: UUID) -> SessionAdmission:
        _require_uuid(household_id, name="household_id")
        _require_uuid(turn_id, name="turn_id")
        async with self._lock:
            self._synchronize_release()
            if self._coordinator.state is CoordinatorState.SAFETY_BLOCKED:
                raise SessionRejected(
                    reason="safety_blocked",
                    retry_after_ms=None,
                )
            await self._admit_deferred_if_safe_locked(self._deferred_for_turn)
            if self._active is not None:
                raise SessionRejected(reason="busy", retry_after_ms=1_000)
            try:
                await self._coordinator.start(turn_id)
            except RuntimeError as error:
                raise self._current_rejection() from error
            admission = SessionAdmission(household_id=household_id, turn_id=turn_id)
            self._active = admission
            return admission

    async def finish(self, turn_id: UUID) -> bool:
        _require_uuid(turn_id, name="turn_id")
        cancellation = self._operations.get((turn_id, "cancel"))
        if cancellation is not None:
            await asyncio.shield(cancellation)
            return False
        operation = self._operations.get((turn_id, "finish"))
        if operation is None:
            self._synchronize_release()
            if self._active is None or self._active.turn_id != turn_id:
                return False
            try:
                operation = self._spawn_operation(
                    turn_id,
                    "finish",
                    lambda: self._finish_and_finalize(turn_id),
                    name=f"session_finish:{turn_id}",
                )
            except BaseException:
                return await self._finish_and_finalize(turn_id)
        result = await asyncio.shield(operation)
        if type(result) is not bool:
            raise RuntimeError("invalid manager finish result")
        return result

    async def _finish_and_finalize(self, turn_id: UUID) -> bool:
        finished = await self._coordinator.finish(turn_id)
        async with self._lock:
            self._synchronize_release()
            if finished:
                await self._admit_deferred_if_safe_locked(turn_id)
        return finished

    async def cancel(self, turn_id: UUID, reason: str) -> None:
        _require_uuid(turn_id, name="turn_id")
        operation = self._operations.get((turn_id, "cancel"))
        if operation is None:
            self._synchronize_release()
            if self._active is None or self._active.turn_id != turn_id:
                return
            try:
                operation = self._spawn_operation(
                    turn_id,
                    "cancel",
                    lambda: self._cancel_and_finalize(turn_id, reason),
                    name=f"session_cancel:{turn_id}",
                )
            except BaseException:
                await self._cancel_and_finalize(turn_id, reason)
                return
        await asyncio.shield(operation)

    async def _cancel_and_finalize(self, turn_id: UUID, reason: str) -> None:
        await self._coordinator.cancel(turn_id, reason)
        async with self._lock:
            self._synchronize_release()
            await self._admit_deferred_if_safe_locked(turn_id)

    async def queue_deferred_wake_from_transition(
        self,
        transition: Transition,
        *,
        active_turn_id: UUID,
        household_id: UUID,
        deferred_turn_id: UUID,
    ) -> bool:
        if type(transition) is not Transition:
            raise TypeError("transition must be an exact Transition")
        _require_uuid(active_turn_id, name="active_turn_id")
        _require_uuid(household_id, name="household_id")
        _require_uuid(deferred_turn_id, name="deferred_turn_id")
        if "queue_wake_after_safe_idle" not in transition.effects:
            return False
        if deferred_turn_id == active_turn_id:
            raise ValueError("deferred turn must be fresh")
        async with self._lock:
            self._synchronize_release()
            if (
                self._active is None
                or self._active.turn_id != active_turn_id
                or self._active.household_id != household_id
                or not self._coordinator.is_current(active_turn_id)
            ):
                raise RuntimeError("stale active turn")
            if not self._coordinator.accepts_results(active_turn_id):
                raise RuntimeError("turn no longer accepts results")
            if self._deferred is not None:
                return False
            self._deferred = SessionAdmission(
                household_id=household_id,
                turn_id=deferred_turn_id,
            )
            self._deferred_for_turn = active_turn_id
            return True

    async def admit_deferred_if_safe(self) -> SessionAdmission | None:
        async with self._lock:
            self._synchronize_release()
            return await self._admit_deferred_if_safe_locked(self._deferred_for_turn)

    async def _admit_deferred_if_safe_locked(
        self,
        released_turn_id: UUID | None,
    ) -> SessionAdmission | None:
        if (
            self._active is not None
            or self._deferred is None
            or self._deferred_for_turn != released_turn_id
            or self._coordinator.state is not CoordinatorState.IDLE
        ):
            return None
        deferred = self._deferred
        await self._coordinator.start(deferred.turn_id)
        self._active = deferred
        self._deferred = None
        self._deferred_for_turn = None
        return deferred

    def _synchronize_release(self) -> None:
        if self._active is not None and not self._coordinator.is_current(self._active.turn_id):
            self._active = None

    def _current_rejection(self) -> SessionRejected:
        if self._coordinator.state is CoordinatorState.SAFETY_BLOCKED:
            return SessionRejected(
                reason="safety_blocked",
                retry_after_ms=None,
            )
        return SessionRejected(reason="busy", retry_after_ms=1_000)

    def _spawn_operation(
        self,
        turn_id: UUID,
        kind: _OperationKind,
        factory: Callable[[], Coroutine[Any, Any, _OperationResultT]],
        *,
        name: str,
    ) -> asyncio.Task[_OperationResultT]:
        if len(self._operations) >= _MAX_RETAINED_OPERATIONS:
            raise RuntimeError("session_operation_capacity")
        coroutine = factory()
        try:
            operation = asyncio.create_task(coroutine, name=name)
        except BaseException as error:
            self._coordinator.health.record_task_factory_failure(
                name.split(":", 1)[0],
                error,
            )
            coroutine.close()
            fallback = factory()
            try:
                operation = asyncio.Task(
                    fallback,
                    loop=asyncio.get_running_loop(),
                    name=name,
                )
            except BaseException:
                fallback.close()
                raise
        operation_key = (turn_id, kind)
        self._operations[operation_key] = operation
        operation.add_done_callback(
            lambda completed: self._observe_operation(operation_key, completed)
        )
        return operation

    def _observe_operation(
        self,
        operation_key: tuple[UUID, _OperationKind],
        operation: asyncio.Task[Any],
    ) -> None:
        if self._operations.get(operation_key) is operation:
            self._operations.pop(operation_key, None)
        try:
            operation.result()
        except asyncio.CancelledError:
            pass
        except BaseException as error:
            self._coordinator.health.record_barrier_exception(error)


def _require_uuid(value: object, *, name: str) -> None:
    if type(value) is not UUID:
        raise TypeError(f"{name} must be an exact UUID")
