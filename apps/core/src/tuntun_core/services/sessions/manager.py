from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Literal, TypeVar
from uuid import UUID

from tuntun_core.domain.conversation import Transition
from tuntun_core.services.personalized_turn_context import ActiveSessionContext
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
    context_session_id: UUID | None = None
    one_turn_context: bool = True

    def __post_init__(self) -> None:
        _require_uuid(self.household_id, name="household_id")
        _require_uuid(self.turn_id, name="turn_id")
        if self.context_session_id is None:
            object.__setattr__(self, "context_session_id", self.turn_id)
        else:
            _require_uuid(self.context_session_id, name="context_session_id")
        if type(self.one_turn_context) is not bool:
            raise TypeError("one_turn_context must be an exact bool")


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
        self._lease_condition = asyncio.Condition(self._lock)
        self._context_leases: dict[UUID, int] = {}
        self._context_lease_sessions: dict[UUID, UUID] = {}
        self._turn_context_sessions: dict[UUID, UUID] = {}
        self._known_context_sessions: set[UUID] = set()
        self._context_session_households: dict[UUID, UUID] = {}
        self._one_turn_context_turns: set[UUID] = set()
        self._ending_turns: set[UUID] = set()
        self._ending_context_sessions: set[UUID] = set()
        self._ended_context_sessions: set[UUID] = set()
        self._notified_context_sessions: set[UUID] = set()
        self._session_end_handlers: tuple[Callable[[UUID], Awaitable[None]], ...] = ()

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

    def track_task(self, turn_id: UUID, task: asyncio.Task[Any]) -> None:
        self._coordinator.track_task(turn_id, task)

    def untrack_task(self, turn_id: UUID, task: asyncio.Task[Any]) -> None:
        self._coordinator.untrack_task(turn_id, task)

    def accepts_results(self, turn_id: UUID) -> bool:
        return self._coordinator.accepts_results(turn_id)

    def register_session_ended_handler(
        self,
        handler: Callable[[UUID], Awaitable[None]],
    ) -> None:
        if not callable(handler):
            raise TypeError("session ended handler must be callable")
        self._session_end_handlers = (*self._session_end_handlers, handler)

    @asynccontextmanager
    async def active_context_lease(self, turn_id: UUID) -> AsyncIterator[ActiveSessionContext]:
        _require_uuid(turn_id, name="turn_id")
        async with self._lock:
            self._synchronize_release()
            if self._active is None:
                raise RuntimeError("session_context_unavailable")
            context_session_id = _admission_context_session_id(self._active)
            if (
                self._active.turn_id != turn_id
                or turn_id in self._ending_turns
                or context_session_id in self._ending_context_sessions
                or context_session_id in self._ended_context_sessions
                or not self._coordinator.accepts_results(turn_id)
            ):
                raise RuntimeError("session_context_unavailable")
            session = ActiveSessionContext(
                id=context_session_id,
                household_id=self._active.household_id,
            )
            self._context_leases[turn_id] = self._context_leases.get(turn_id, 0) + 1
            self._context_lease_sessions[turn_id] = context_session_id
        try:
            yield session
        finally:
            async with self._lock:
                remaining = self._context_leases.get(turn_id, 0) - 1
                if remaining > 0:
                    self._context_leases[turn_id] = remaining
                else:
                    self._context_leases.pop(turn_id, None)
                    self._context_lease_sessions.pop(turn_id, None)
                self._lease_condition.notify_all()

    async def open(
        self,
        household_id: UUID,
        turn_id: UUID,
        *,
        context_session_id: UUID | None = None,
    ) -> SessionAdmission:
        _require_uuid(household_id, name="household_id")
        _require_uuid(turn_id, name="turn_id")
        one_turn_context = context_session_id is None
        context_id = turn_id if context_session_id is None else context_session_id
        _require_uuid(context_id, name="context_session_id")
        async with self._lock:
            self._synchronize_release()
            if (
                context_id in self._ending_context_sessions
                or context_id in self._ended_context_sessions
            ):
                raise RuntimeError("context_session_unavailable")
            existing_household_id = self._context_session_households.get(context_id)
            if existing_household_id is not None and existing_household_id != household_id:
                raise RuntimeError("context_session_unavailable")
            if self._ending_context_sessions:
                raise SessionRejected(reason="busy", retry_after_ms=1_000)
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
            admission = SessionAdmission(
                household_id=household_id,
                turn_id=turn_id,
                context_session_id=context_id,
                one_turn_context=one_turn_context,
            )
            self._active = admission
            self._turn_context_sessions[turn_id] = context_id
            self._known_context_sessions.add(context_id)
            self._context_session_households[context_id] = household_id
            if one_turn_context:
                self._one_turn_context_turns.add(turn_id)
            return admission

    async def finish(self, turn_id: UUID) -> bool:
        _require_uuid(turn_id, name="turn_id")
        cancellation = self._operations.get((turn_id, "cancel"))
        if cancellation is not None:
            await asyncio.shield(cancellation)
            return False
        operation = self._operations.get((turn_id, "finish"))
        if operation is None:
            fallback = False
            async with self._lock:
                operation = self._operations.get((turn_id, "finish"))
                if operation is None:
                    self._synchronize_release()
                    if self._active is None or self._active.turn_id != turn_id:
                        return False
                    self._ending_turns.add(turn_id)
                    try:
                        operation = self._spawn_operation(
                            turn_id,
                            "finish",
                            lambda: self._finish_and_finalize(turn_id),
                            name=f"session_finish:{turn_id}",
                        )
                    except BaseException:
                        fallback = True
            if fallback:
                return await self._finish_and_finalize(turn_id)
        if operation is None:
            return False
        result = await asyncio.shield(operation)
        if type(result) is not bool:
            raise RuntimeError("invalid manager finish result")
        return result

    async def _finish_and_finalize(self, turn_id: UUID) -> bool:
        finished = False
        context_session_id, one_turn_context = await self._turn_context_for_finalize(turn_id)
        try:
            finished = await self._coordinator.finish(turn_id)
            if finished:
                await self._wait_for_context_leases(turn_id)
                if context_session_id is not None and one_turn_context:
                    await self._notify_context_session_ended_once(context_session_id)
            return finished
        finally:
            async with self._lock:
                self._ending_turns.discard(turn_id)
                self._lease_condition.notify_all()
                self._synchronize_release()
                if finished:
                    self._cleanup_turn_context_locked(turn_id)
                    await self._admit_deferred_if_safe_locked(turn_id)

    async def cancel(self, turn_id: UUID, reason: str) -> None:
        _require_uuid(turn_id, name="turn_id")
        operation = self._operations.get((turn_id, "cancel"))
        if operation is None:
            fallback = False
            async with self._lock:
                operation = self._operations.get((turn_id, "cancel"))
                if operation is None:
                    self._synchronize_release()
                    if self._active is None or self._active.turn_id != turn_id:
                        return
                    self._ending_turns.add(turn_id)
                    try:
                        operation = self._spawn_operation(
                            turn_id,
                            "cancel",
                            lambda: self._cancel_and_finalize(turn_id, reason),
                            name=f"session_cancel:{turn_id}",
                        )
                    except BaseException:
                        fallback = True
            if fallback:
                await self._cancel_and_finalize(turn_id, reason)
                return
        if operation is None:
            return
        await asyncio.shield(operation)

    async def _cancel_and_finalize(self, turn_id: UUID, reason: str) -> None:
        released = False
        context_session_id, one_turn_context = await self._turn_context_for_finalize(turn_id)
        try:
            await self._coordinator.cancel(turn_id, reason)
            released = not self._coordinator.is_current(turn_id)
            if released:
                await self._wait_for_context_leases(turn_id)
                if context_session_id is not None and one_turn_context:
                    await self._notify_context_session_ended_once(context_session_id)
        finally:
            async with self._lock:
                self._ending_turns.discard(turn_id)
                self._lease_condition.notify_all()
                self._synchronize_release()
                if released:
                    self._cleanup_turn_context_locked(turn_id)
                    await self._admit_deferred_if_safe_locked(turn_id)

    async def end(self, turn_id: UUID) -> bool:
        return await self.finish(turn_id)

    async def end_context_session(self, context_session_id: UUID) -> bool:
        _require_uuid(context_session_id, name="context_session_id")
        async with self._lock:
            if context_session_id in self._ended_context_sessions:
                return False
            if context_session_id not in self._known_context_sessions:
                raise RuntimeError("context_session_unavailable")
            self._ending_context_sessions.add(context_session_id)
            self._lease_condition.notify_all()
        try:
            await self._wait_for_context_session_idle(context_session_id)
            await self._notify_context_session_ended_once(context_session_id)
            return True
        finally:
            async with self._lock:
                self._ending_context_sessions.discard(context_session_id)
                self._ended_context_sessions.add(context_session_id)
                self._lease_condition.notify_all()

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
            context_session_id = _admission_context_session_id(self._active)
            if (
                context_session_id in self._ending_context_sessions
                or context_session_id in self._ended_context_sessions
            ):
                raise RuntimeError("context_session_unavailable")
            self._deferred = SessionAdmission(
                household_id=household_id,
                turn_id=deferred_turn_id,
                context_session_id=context_session_id,
                one_turn_context=self._active.one_turn_context,
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
        context_session_id = _admission_context_session_id(deferred)
        if (
            context_session_id in self._ending_context_sessions
            or context_session_id in self._ended_context_sessions
        ):
            self._deferred = None
            self._deferred_for_turn = None
            return None
        await self._coordinator.start(deferred.turn_id)
        self._active = deferred
        self._turn_context_sessions[deferred.turn_id] = context_session_id
        self._known_context_sessions.add(context_session_id)
        self._context_session_households[context_session_id] = deferred.household_id
        if deferred.one_turn_context:
            self._one_turn_context_turns.add(deferred.turn_id)
        self._deferred = None
        self._deferred_for_turn = None
        return deferred

    def _synchronize_release(self) -> None:
        if (
            self._active is not None
            and not self._coordinator.is_current(self._active.turn_id)
            and self._active.turn_id not in self._ending_turns
            and self._context_leases.get(self._active.turn_id, 0) == 0
        ):
            self._active = None

    async def _wait_for_context_leases(self, turn_id: UUID) -> None:
        async with self._lease_condition:
            while self._context_leases.get(turn_id, 0) > 0:
                await self._lease_condition.wait()

    async def _wait_for_context_session_idle(self, context_session_id: UUID) -> None:
        async with self._lease_condition:
            while self._context_session_has_live_turn_or_lease(context_session_id):
                await self._lease_condition.wait()

    def _context_session_has_live_turn_or_lease(self, context_session_id: UUID) -> bool:
        if self._active is not None and (
            _admission_context_session_id(self._active) == context_session_id
        ):
            return True
        for turn_id in self._ending_turns:
            if self._turn_context_sessions.get(turn_id) == context_session_id:
                return True
        return context_session_id in self._context_lease_sessions.values()

    async def _turn_context_for_finalize(self, turn_id: UUID) -> tuple[UUID | None, bool]:
        async with self._lock:
            return (
                self._turn_context_sessions.get(turn_id),
                turn_id in self._one_turn_context_turns,
            )

    def _cleanup_turn_context_locked(self, turn_id: UUID) -> None:
        self._turn_context_sessions.pop(turn_id, None)
        self._one_turn_context_turns.discard(turn_id)

    async def _notify_context_session_ended_once(self, context_session_id: UUID) -> None:
        async with self._lock:
            if context_session_id in self._notified_context_sessions:
                return
            self._notified_context_sessions.add(context_session_id)
        await self._notify_session_ended(context_session_id)

    async def _notify_session_ended(self, session_id: UUID) -> None:
        primary_error: BaseException | None = None
        for handler in self._session_end_handlers:
            try:
                await handler(session_id)
            except asyncio.CancelledError as error:
                self._coordinator.health.record_barrier_exception(error)
                if not isinstance(primary_error, asyncio.CancelledError):
                    primary_error = asyncio.CancelledError("session_end_handler_cancelled")
            except BaseException as error:
                self._coordinator.health.record_barrier_exception(error)
                if primary_error is None:
                    primary_error = RuntimeError("session_end_handler_failed")
        if primary_error is not None:
            raise primary_error

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


def _admission_context_session_id(admission: SessionAdmission) -> UUID:
    if admission.context_session_id is None:
        raise RuntimeError("context_session_unavailable")
    return admission.context_session_id
