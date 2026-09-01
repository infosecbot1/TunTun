from __future__ import annotations

import asyncio
import math
from collections import defaultdict, deque
from collections.abc import Callable, Coroutine
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol, TypeVar
from uuid import UUID

from tuntun_contracts.budget import BudgetReconciliationRequest, TransportProof
from tuntun_contracts.ports import BudgetPort, ClockPort, ReachyPort
from tuntun_contracts.reachy import SafetyReceipt

_TaskResultT = TypeVar("_TaskResultT")
_MAX_TRACKED_ATTEMPTS = 8
_CANCELLATION_REASONS = frozenset(
    {
        "cancel",
        "disconnect",
        "physical_stop",
        "privacy",
        "privacy_shield",
        "shutdown",
        "stop",
        "timeout",
        "watchdog",
        "workflow_cancelled",
        "workflow_cancelled_during_finish",
        "workflow_observed_external_cancel",
        "workflow_timeout",
    }
)


class CoordinatorState(StrEnum):
    IDLE = "idle"
    ACTIVE = "active"
    CANCELLING = "cancelling"
    SAFETY_BLOCKED = "safety_blocked"


@dataclass(frozen=True, slots=True)
class SafetyBlockedRecord:
    turn_id: UUID
    reason: str
    attempts: int
    failure_codes: tuple[str, ...]
    observed_at: datetime | None


class SafetyBlockedError(RuntimeError):
    """The active turn cannot be released without a verified safety recovery."""


class OwnerRecoveryPort(Protocol):
    async def require_fresh_local_owner(
        self,
        proof: object,
        *,
        action: str,
        turn_id: UUID,
    ) -> None: ...


class CancellationHealthRecorder:
    """Bounded, content-free cancellation diagnostics for readiness and tests."""

    def __init__(self, *, capacity: int = 32) -> None:
        if type(capacity) is not int or not 1 <= capacity <= 256:
            raise ValueError("invalid cancellation health capacity")
        self._blocked: deque[SafetyBlockedRecord] = deque(maxlen=capacity)
        self._barrier_errors: deque[str] = deque(maxlen=capacity)
        self._task_factory_failures: deque[str] = deque(maxlen=capacity)

    def record_safety_blocked(self, record: SafetyBlockedRecord) -> None:
        if type(record) is not SafetyBlockedRecord:
            raise TypeError("record must be an exact SafetyBlockedRecord")
        self._blocked.append(record)

    def record_barrier_exception(self, error: BaseException) -> None:
        self._barrier_errors.append(type(error).__name__)

    def record_task_factory_failure(self, name: str, error: BaseException) -> None:
        del error
        self._task_factory_failures.append(name)

    @property
    def safety_blocks(self) -> tuple[SafetyBlockedRecord, ...]:
        return tuple(self._blocked)

    @property
    def detached_barrier_errors(self) -> tuple[str, ...]:
        return tuple(self._barrier_errors)

    @property
    def task_factory_failure_points(self) -> tuple[str, ...]:
        return tuple(self._task_factory_failures)


class TurnCoordinator:
    """Own exactly one household turn through its complete safety barrier."""

    def __init__(
        self,
        budget: BudgetPort,
        reachy: ReachyPort,
        clock: ClockPort,
        *,
        health: CancellationHealthRecorder | None = None,
        owner_recovery: OwnerRecoveryPort | None = None,
        safety_retry_limit: int = 3,
        safety_attempt_timeout: float = 0.250,
        tracked_join_timeout: float = 1.0,
        reconciliation_timeout: float = 2.0,
    ) -> None:
        if type(safety_retry_limit) is not int or not 1 <= safety_retry_limit <= 3:
            raise ValueError("invalid safety retry boundary")
        if not _valid_timeout(safety_attempt_timeout, maximum=0.500):
            raise ValueError("invalid safety attempt timeout")
        if not _valid_timeout(tracked_join_timeout, maximum=5.0):
            raise ValueError("invalid tracked join timeout")
        if not _valid_timeout(reconciliation_timeout, maximum=10.0):
            raise ValueError("invalid reconciliation timeout")
        self._budget = budget
        self._reachy = reachy
        self._clock = clock
        self._health = health or CancellationHealthRecorder()
        self._owner_recovery = owner_recovery
        self._safety_retry_limit = safety_retry_limit
        self._safety_attempt_timeout = float(safety_attempt_timeout)
        self._tracked_join_timeout = float(tracked_join_timeout)
        self._reconciliation_timeout = float(reconciliation_timeout)

        self._active: UUID | None = None
        self._state = CoordinatorState.IDLE
        self._tasks: dict[UUID, set[asyncio.Task[Any]]] = defaultdict(set)
        self._attempts: dict[UUID, set[tuple[UUID, UUID]]] = defaultdict(set)
        self._reconciliation_proofs: dict[UUID, tuple[TransportProof, ...]] = {}
        self._reconciliation_tasks: dict[UUID, set[asyncio.Task[Any]]] = defaultdict(set)
        self._safety_blocked_record: SafetyBlockedRecord | None = None
        self._process_restart_required = False
        self._background: set[asyncio.Task[Any]] = set()
        self._lock = asyncio.Lock()
        self._cancelling: dict[UUID, asyncio.Task[None]] = {}
        self.cancel_started = asyncio.Event()

    @property
    def state(self) -> CoordinatorState:
        return self._state

    @property
    def safety_blocked_record(self) -> SafetyBlockedRecord | None:
        return self._safety_blocked_record

    @property
    def health(self) -> CancellationHealthRecorder:
        return self._health

    @property
    def requires_process_restart(self) -> bool:
        return self._process_restart_required

    async def start(self, turn_id: UUID) -> None:
        _require_uuid(turn_id, name="turn_id")
        async with self._lock:
            if self._state is CoordinatorState.SAFETY_BLOCKED:
                raise RuntimeError("household safety blocked; owner recovery required")
            if self._state is not CoordinatorState.IDLE or self._active is not None:
                raise RuntimeError("household conversation busy")
            self._active = turn_id
            self._state = CoordinatorState.ACTIVE
            self.cancel_started.clear()

    def track_task(self, turn_id: UUID, task: asyncio.Task[Any]) -> None:
        _require_uuid(turn_id, name="turn_id")
        if not isinstance(task, asyncio.Task):
            raise TypeError("task must be an asyncio.Task")
        self._require_registration_open(turn_id)
        self._tasks[turn_id].add(task)

    def untrack_task(self, turn_id: UUID, task: asyncio.Task[Any]) -> None:
        _require_uuid(turn_id, name="turn_id")
        if not isinstance(task, asyncio.Task):
            raise TypeError("task must be an asyncio.Task")
        if not task.done():
            raise RuntimeError("cannot untrack live task")
        tracked = self._tasks.get(turn_id)
        if tracked is None:
            return
        tracked.discard(task)
        if not tracked:
            self._tasks.pop(turn_id, None)

    def track_reservation(
        self,
        turn_id: UUID,
        reservation_id: UUID,
        attempt_id: UUID,
    ) -> None:
        _require_uuid(turn_id, name="turn_id")
        _require_uuid(reservation_id, name="reservation_id")
        _require_uuid(attempt_id, name="attempt_id")
        self._require_registration_open(turn_id)
        attempts = self._attempts[turn_id]
        pair = (reservation_id, attempt_id)
        if pair in attempts:
            raise RuntimeError("duplicate tracked reservation")
        if len(attempts) >= _MAX_TRACKED_ATTEMPTS:
            raise RuntimeError("turn_budget_attempt_limit")
        attempts.add(pair)

    def complete_reservation(
        self,
        turn_id: UUID,
        reservation_id: UUID,
        attempt_id: UUID,
    ) -> None:
        """Forget a pair only after its exact durable settle/release commit."""

        _require_uuid(turn_id, name="turn_id")
        _require_uuid(reservation_id, name="reservation_id")
        _require_uuid(attempt_id, name="attempt_id")
        if turn_id != self._active or self._state is not CoordinatorState.ACTIVE:
            raise RuntimeError("stale turn")
        attempts = self._attempts.get(turn_id)
        pair = (reservation_id, attempt_id)
        if attempts is None or pair not in attempts:
            raise RuntimeError("unknown tracked reservation")
        attempts.remove(pair)
        if not attempts:
            self._attempts.pop(turn_id, None)

    def is_current(self, turn_id: UUID) -> bool:
        """Return whether this turn still owns cleanup and release responsibility."""

        _require_uuid(turn_id, name="turn_id")
        return self._active == turn_id

    def accepts_results(self, turn_id: UUID) -> bool:
        """Reject late provider/workflow results once cancellation is published."""

        _require_uuid(turn_id, name="turn_id")
        return self._active == turn_id and self._state is CoordinatorState.ACTIVE

    def active_turn_id(self) -> UUID | None:
        """Return only the opaque identifier needed by the safety stop loop."""

        return self._active

    def tracked_attempts(self, turn_id: UUID) -> frozenset[tuple[UUID, UUID]]:
        """Return a content-free health projection of attempt identifiers."""

        _require_uuid(turn_id, name="turn_id")
        return frozenset(self._attempts.get(turn_id, ()))

    async def finish(self, turn_id: UUID) -> bool:
        """Run the normal full safety barrier and release exactly once."""

        _require_uuid(turn_id, name="turn_id")
        async with self._lock:
            if turn_id != self._active or self._state is not CoordinatorState.ACTIVE:
                return False
            if self._attempts.get(turn_id):
                raise RuntimeError("turn_has_unsettled_budget_attempts")
            self._state = CoordinatorState.CANCELLING
            barrier = self._create_barrier(turn_id, "normal_finish")
        await asyncio.shield(barrier)
        return True

    async def cancel(self, turn_id: UUID, reason: str) -> None:
        _require_uuid(turn_id, name="turn_id")
        async with self._lock:
            if turn_id != self._active:
                return
            safe_reason = _safe_cancellation_reason(reason)
            if self._state is CoordinatorState.SAFETY_BLOCKED:
                raise SafetyBlockedError("turn_safety_blocked:owner_recovery_required")
            barrier = self._cancelling.get(turn_id)
            if barrier is None:
                if self._state is not CoordinatorState.ACTIVE:
                    raise RuntimeError("turn cancellation owner missing")
                self._state = CoordinatorState.CANCELLING
                barrier = self._create_barrier(turn_id, safe_reason)
                self.cancel_started.set()
        await asyncio.shield(barrier)

    async def recover_safety_block(self, turn_id: UUID, proof: object) -> None:
        _require_uuid(turn_id, name="turn_id")
        async with self._lock:
            if self._process_restart_required:
                raise SafetyBlockedError("turn_safety_blocked:process_restart_required")
            if turn_id != self._active or self._state is not CoordinatorState.SAFETY_BLOCKED:
                raise RuntimeError("turn is not safety blocked")
            if self._owner_recovery is None:
                raise PermissionError("fresh_local_owner_recovery_required")
        await self._owner_recovery.require_fresh_local_owner(
            proof,
            action="turn.safety_recover",
            turn_id=turn_id,
        )
        async with self._lock:
            if self._process_restart_required:
                raise SafetyBlockedError("turn_safety_blocked:process_restart_required")
            if turn_id != self._active or self._state is not CoordinatorState.SAFETY_BLOCKED:
                raise RuntimeError("turn is not safety blocked")
            self._state = CoordinatorState.CANCELLING
            barrier = self._create_barrier(turn_id, "verified_owner_recovery")
        await asyncio.shield(barrier)

    def _require_registration_open(self, turn_id: UUID) -> None:
        if turn_id != self._active or self._state is CoordinatorState.IDLE:
            raise RuntimeError("stale turn")
        if self._state is not CoordinatorState.ACTIVE or turn_id in self._cancelling:
            raise RuntimeError("turn cancellation in progress")

    def _create_barrier(self, turn_id: UUID, reason: str) -> asyncio.Task[None]:
        try:
            barrier = self._spawn_owned(
                lambda: self._run_cancellation_barrier(turn_id, reason),
                name=f"outer_barrier:{turn_id}",
            )
        except BaseException as error:
            self._latch_factory_failure(turn_id, reason)
            raise SafetyBlockedError("turn_safety_blocked:process_restart_required") from error
        self._cancelling[turn_id] = barrier
        barrier.add_done_callback(lambda completed: self._observe_barrier_done(turn_id, completed))
        return barrier

    def _spawn_owned(
        self,
        factory: Callable[[], Coroutine[Any, Any, _TaskResultT]],
        *,
        name: str,
    ) -> asyncio.Task[_TaskResultT]:
        coroutine = factory()
        try:
            return asyncio.create_task(coroutine, name=name)
        except BaseException as error:
            self._health.record_task_factory_failure(name.split(":", 1)[0], error)
            coroutine.close()
            fallback = factory()
            try:
                return asyncio.Task(
                    fallback,
                    loop=asyncio.get_running_loop(),
                    name=name,
                )
            except BaseException:
                fallback.close()
                raise

    def _latch_factory_failure(self, turn_id: UUID, reason: str) -> None:
        self._state = CoordinatorState.SAFETY_BLOCKED
        record = SafetyBlockedRecord(
            turn_id=turn_id,
            reason=reason,
            attempts=0,
            failure_codes=("outer_barrier_factory_unavailable",),
            observed_at=self._safe_now(),
        )
        self._safety_blocked_record = record
        self._process_restart_required = True
        self._health.record_safety_blocked(record)

    def _observe_barrier_done(self, turn_id: UUID, task: asyncio.Task[None]) -> None:
        if self._cancelling.get(turn_id) is task:
            self._cancelling.pop(turn_id, None)
        try:
            task.result()
        except asyncio.CancelledError as error:
            self._health.record_barrier_exception(error)
        except BaseException as error:
            self._health.record_barrier_exception(error)

    def _retain_background(
        self,
        task: asyncio.Task[_TaskResultT],
    ) -> asyncio.Task[_TaskResultT]:
        self._background.add(task)

        def observed(completed: asyncio.Task[_TaskResultT]) -> None:
            self._background.discard(completed)
            try:
                completed.result()
            except asyncio.CancelledError:
                pass
            except BaseException as error:
                self._health.record_barrier_exception(error)

        task.add_done_callback(observed)
        return task

    async def _run_cancellation_barrier(self, turn_id: UUID, reason: str) -> None:
        barrier_verified = False
        failure_codes: tuple[str, ...] = ()
        try:
            tasks = tuple(self._tasks.get(turn_id, ()))
            first_reachy_attempt_started = asyncio.get_running_loop().create_future()

            try:
                safety = self._retain_background(
                    self._spawn_owned(
                        lambda: self._retry_reachy_safety(
                            turn_id,
                            first_reachy_attempt_started,
                        ),
                        name=f"reachy_safety:{turn_id}",
                    )
                )
            except BaseException as error:
                self._process_restart_required = True
                failure_codes = ("reachy_safety_factory_unavailable",)
                raise SafetyBlockedError("turn_safety_blocked:process_restart_required") from error
            started_or_safety_done, _ = await asyncio.wait(
                {first_reachy_attempt_started, safety},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if first_reachy_attempt_started not in started_or_safety_done:
                first_reachy_attempt_started.cancel()
                self._process_restart_required = True
                failure_codes = ("reachy_safety_factory_unavailable",)
                with suppress(BaseException):
                    await asyncio.shield(safety)
                raise SafetyBlockedError("turn_safety_blocked:process_restart_required")

            for task in tasks:
                task.cancel()
            task_join = self._retain_background(
                self._spawn_owned(
                    lambda: self._join_tracked(turn_id, tasks),
                    name=f"tracked_task_join:{turn_id}",
                )
            )

            reconciliation: asyncio.Task[tuple[Any, ...]] | None = None
            reconciliation_error: BaseException | None = None
            if self._live_reconciliation_tasks(turn_id):
                reconciliation_error = SafetyBlockedError(
                    "turn_safety_blocked:prior_reconciliation_live"
                )
            else:
                try:
                    request = self._reconciliation_request(turn_id, reason)
                    reconciliation = self._retain_reconciliation(
                        turn_id,
                        self._retain_background(
                            self._spawn_owned(
                                lambda: self._budget.reconcile_turn(request),
                                name=f"budget_reconciliation:{turn_id}",
                            )
                        ),
                    )
                except BaseException as error:
                    reconciliation_error = error

            try:
                safety_verified, safety_failures = await asyncio.shield(safety)
                failure_codes = (*failure_codes, *safety_failures)
            except BaseException as error:
                safety_verified = False
                failure_codes = (*failure_codes, f"reachy_safety:{type(error).__name__}")

            try:
                stubborn_tasks = await asyncio.shield(task_join)
            except BaseException as error:
                stubborn_tasks = tasks
                failure_codes = (*failure_codes, f"tracked_tasks:{type(error).__name__}")

            if reconciliation is not None:
                done, pending = await asyncio.wait(
                    {reconciliation},
                    timeout=self._reconciliation_timeout,
                )
                if pending:
                    reconciliation.cancel()
                    reconciliation_error = TimeoutError("budget_reconciliation_timeout")
                else:
                    try:
                        reconciliation.result()
                    except BaseException as error:
                        reconciliation_error = error

            if not safety_verified:
                raise SafetyBlockedError("turn_safety_blocked:owner_recovery_required")
            if stubborn_tasks:
                failure_codes = (*failure_codes, "tracked_tasks:timeout")
                raise SafetyBlockedError("turn_safety_blocked:tracked_task_restart_required")
            if reconciliation_error is not None:
                failure_codes = (
                    *failure_codes,
                    f"reconciliation:{type(reconciliation_error).__name__}",
                )
                if isinstance(reconciliation_error, TimeoutError):
                    raise SafetyBlockedError(
                        "turn_safety_blocked:reconciliation_timeout"
                    ) from reconciliation_error
                if isinstance(reconciliation_error, asyncio.CancelledError):
                    raise SafetyBlockedError(
                        "turn_safety_blocked:reconciliation_cancelled"
                    ) from reconciliation_error
                raise reconciliation_error
            if self._live_reconciliation_tasks(turn_id):
                failure_codes = (*failure_codes, "reconciliation:still_live")
                raise SafetyBlockedError("turn_safety_blocked:prior_reconciliation_live")
            barrier_verified = True
        finally:
            async with self._lock:
                if self._cancelling.get(turn_id) is asyncio.current_task():
                    self._cancelling.pop(turn_id, None)
                if barrier_verified:
                    self._release_turn(turn_id)
                else:
                    self._latch_barrier_failure(turn_id, reason, failure_codes)

    def _reconciliation_request(
        self,
        turn_id: UUID,
        reason: str,
    ) -> BudgetReconciliationRequest:
        proofs = self._reconciliation_proofs.get(turn_id)
        if proofs is None:
            observed_at = self._clock.now()
            proofs = tuple(
                TransportProof(
                    reservation_id=reservation_id,
                    attempt_id=attempt_id,
                    disposition="unknown",
                    evidence_code=f"turn_cancelled:{reason}",
                    observed_at=observed_at,
                )
                for reservation_id, attempt_id in sorted(
                    self._attempts.get(turn_id, ()),
                    key=lambda item: (str(item[0]), str(item[1])),
                )
            )
            self._reconciliation_proofs[turn_id] = proofs
        return BudgetReconciliationRequest(turn_id=turn_id, proofs=proofs)

    def _retain_reconciliation(
        self,
        turn_id: UUID,
        task: asyncio.Task[_TaskResultT],
    ) -> asyncio.Task[_TaskResultT]:
        self._reconciliation_tasks[turn_id].add(task)

        def discard(completed: asyncio.Task[_TaskResultT]) -> None:
            tracked = self._reconciliation_tasks.get(turn_id)
            if tracked is None:
                return
            tracked.discard(completed)
            if not tracked:
                self._reconciliation_tasks.pop(turn_id, None)

        task.add_done_callback(discard)
        return task

    def _live_reconciliation_tasks(self, turn_id: UUID) -> tuple[asyncio.Task[Any], ...]:
        tracked = self._reconciliation_tasks.get(turn_id)
        if not tracked:
            return ()
        live = tuple(task for task in tracked if not task.done())
        if not live:
            self._reconciliation_tasks.pop(turn_id, None)
        return live

    async def _join_tracked(
        self,
        turn_id: UUID,
        tasks: tuple[asyncio.Task[Any], ...],
    ) -> tuple[asyncio.Task[Any], ...]:
        if not tasks:
            self._tasks.pop(turn_id, None)
            return ()
        done, pending = await asyncio.wait(
            set(tasks),
            timeout=self._tracked_join_timeout,
        )
        if done:
            await asyncio.gather(*done, return_exceptions=True)
        if pending:
            self._tasks[turn_id] = set(pending)
            for task in pending:
                task.cancel()
                self._retain_background(task)
        else:
            self._tasks.pop(turn_id, None)
        return tuple(pending)

    async def _retry_reachy_safety(
        self,
        turn_id: UUID,
        first_attempt_started: asyncio.Future[None],
    ) -> tuple[bool, tuple[str, ...]]:
        failures: list[str] = []
        for attempt in range(1, self._safety_retry_limit + 1):
            operation = self._retain_background(
                self._spawn_owned(
                    lambda: self._invoke_reachy_stop(
                        turn_id,
                        first_attempt_started,
                    ),
                    name=f"reachy_attempt:{turn_id}",
                )
            )
            done, pending = await asyncio.wait(
                {operation},
                timeout=self._safety_attempt_timeout,
            )
            for task in pending:
                task.cancel()
            if operation not in done:
                failures.append(f"reachy:timeout:{attempt}")
                continue
            try:
                receipt = operation.result()
            except BaseException as error:
                failures.append(f"reachy:error:{type(error).__name__}:{attempt}")
                continue
            if type(receipt) is not SafetyReceipt:
                failures.append(f"reachy:malformed_receipt:{attempt}")
                continue
            if receipt.turn_id != turn_id:
                failures.append(f"reachy:wrong_turn:{attempt}")
                continue
            false_fields = tuple(
                field
                for field in ("playback_stopped", "motion_stopped", "buffers_cleared")
                if getattr(receipt, field) is not True
            )
            if false_fields:
                failures.extend(f"reachy:{field}_false:{attempt}" for field in false_fields)
                continue
            return True, tuple(failures)
        return False, tuple(failures)

    async def _invoke_reachy_stop(
        self,
        turn_id: UUID,
        first_attempt_started: asyncio.Future[None],
    ) -> SafetyReceipt:
        if not first_attempt_started.done():
            first_attempt_started.set_result(None)
        return await self._reachy.stop_all(turn_id)

    def _release_turn(self, turn_id: UUID) -> None:
        self._active = None
        self._state = CoordinatorState.IDLE
        self._safety_blocked_record = None
        self._process_restart_required = False
        self._tasks.pop(turn_id, None)
        self._attempts.pop(turn_id, None)
        self._reconciliation_proofs.pop(turn_id, None)
        self._reconciliation_tasks.pop(turn_id, None)

    def _latch_barrier_failure(
        self,
        turn_id: UUID,
        reason: str,
        failure_codes: tuple[str, ...],
    ) -> None:
        self._state = CoordinatorState.SAFETY_BLOCKED
        record = SafetyBlockedRecord(
            turn_id=turn_id,
            reason=reason,
            attempts=self._safety_retry_limit,
            failure_codes=failure_codes or ("barrier_interrupted",),
            observed_at=self._safe_now(),
        )
        self._safety_blocked_record = record
        self._health.record_safety_blocked(record)

    def _safe_now(self) -> datetime | None:
        try:
            return self._clock.now()
        except BaseException:
            return None


def _valid_timeout(value: object, *, maximum: float) -> bool:
    if type(value) is int:
        numeric = float(value)
    elif type(value) is float:
        numeric = value
    else:
        return False
    return math.isfinite(numeric) and 0 < numeric <= maximum


def _require_uuid(value: object, *, name: str) -> None:
    if type(value) is not UUID:
        raise TypeError(f"{name} must be an exact UUID")


def _safe_cancellation_reason(reason: object) -> str:
    if type(reason) is str and reason in _CANCELLATION_REASONS:
        return reason
    return "invalid_reason"
