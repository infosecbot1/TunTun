from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from tuntun_contracts.budget import BudgetReconciliationRequest
from tuntun_contracts.reachy import SafetyReceipt
from tuntun_core.services.sessions.turn_coordinator import (
    CancellationHealthRecorder,
    CoordinatorState,
    SafetyBlockedError,
    SafetyBlockedRecord,
    TurnCoordinator,
)
from tuntun_testing.fake_clock import FakeClock


class _BudgetFake:
    def __init__(self) -> None:
        self.reconciliations: list[BudgetReconciliationRequest] = []

    async def reconcile_turn(
        self,
        request: BudgetReconciliationRequest,
    ) -> tuple[()]:
        self.reconciliations.append(request)
        return ()


class _ReachyFake:
    def __init__(self) -> None:
        self.stopped_turns: list[UUID | None] = []

    async def stop_all(self, turn_id: UUID | None) -> SafetyReceipt:
        self.stopped_turns.append(turn_id)
        return SafetyReceipt(
            turn_id=turn_id,
            playback_stopped=True,
            motion_stopped=True,
            buffers_cleared=True,
        )


class _GatedReachy(_ReachyFake):
    def __init__(self) -> None:
        super().__init__()
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def stop_all(self, turn_id: UUID | None) -> SafetyReceipt:
        self.stopped_turns.append(turn_id)
        self.entered.set()
        await self.release.wait()
        return SafetyReceipt(
            turn_id=turn_id,
            playback_stopped=True,
            motion_stopped=True,
            buffers_cleared=True,
        )


class _RaisingBudget(_BudgetFake):
    async def reconcile_turn(
        self,
        request: BudgetReconciliationRequest,
    ) -> tuple[()]:
        self.reconciliations.append(request)
        raise RuntimeError("reconciliation failed")


class _FailsOnceBudget(_BudgetFake):
    async def reconcile_turn(
        self,
        request: BudgetReconciliationRequest,
    ) -> tuple[()]:
        self.reconciliations.append(request)
        if len(self.reconciliations) == 1:
            raise RuntimeError("reconciliation failed")
        return ()


class _SelfCancellingBudget(_BudgetFake):
    async def reconcile_turn(
        self,
        request: BudgetReconciliationRequest,
    ) -> tuple[()]:
        self.reconciliations.append(request)
        raise asyncio.CancelledError


class _HangingOnceBudget(_BudgetFake):
    def __init__(self) -> None:
        super().__init__()
        self.first_entered = asyncio.Event()
        self.first_cancelled = asyncio.Event()
        self.first_completed = asyncio.Event()
        self.release_first = asyncio.Event()

    async def reconcile_turn(
        self,
        request: BudgetReconciliationRequest,
    ) -> tuple[()]:
        self.reconciliations.append(request)
        if len(self.reconciliations) != 1:
            return ()
        self.first_entered.set()
        try:
            await self.release_first.wait()
        except asyncio.CancelledError:
            self.first_cancelled.set()
            await self.release_first.wait()
        self.first_completed.set()
        return ()


class _OwnerRecoveryFake:
    def __init__(self, expected_proof: object) -> None:
        self.expected_proof = expected_proof
        self.calls: list[tuple[object, str, UUID]] = []

    async def require_fresh_local_owner(
        self,
        proof: object,
        *,
        action: str,
        turn_id: UUID,
    ) -> None:
        self.calls.append((proof, action, turn_id))
        if proof is not self.expected_proof:
            raise PermissionError("fresh_local_owner_recovery_required")


class _SafetyCaseReachy:
    def __init__(self, effect: str) -> None:
        self.effect = effect
        self.calls = 0

    async def stop_all(self, turn_id: UUID | None) -> Any:
        self.calls += 1
        if self.effect == "raise":
            raise RuntimeError("reachy failed")
        if self.effect == "malformed":
            return object()
        if self.effect == "wrong_turn":
            return SafetyReceipt(
                turn_id=uuid4(),
                playback_stopped=True,
                motion_stopped=True,
                buffers_cleared=True,
            )
        values = {
            "playback_stopped": True,
            "motion_stopped": True,
            "buffers_cleared": True,
        }
        if self.effect in values:
            values[self.effect] = False
        receipt = SafetyReceipt(turn_id=turn_id, **values)
        if self.effect == "subclass":

            class ReceiptSubclass(SafetyReceipt):
                pass

            return ReceiptSubclass(**receipt.model_dump())
        return receipt


class _TimeoutReachy:
    def __init__(self) -> None:
        self.calls = 0

    async def stop_all(self, turn_id: UUID | None) -> SafetyReceipt:
        del turn_id
        self.calls += 1
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


class _BrokenClock:
    def now(self) -> datetime:
        raise RuntimeError("clock unavailable")

    def monotonic(self) -> float:
        return 0.0


def _coordinator(
    *,
    budget: _BudgetFake | None = None,
    reachy: _ReachyFake | None = None,
) -> TurnCoordinator:
    return TurnCoordinator(
        budget=budget or _BudgetFake(),
        reachy=reachy or _ReachyFake(),
        clock=FakeClock(datetime(2026, 8, 27, tzinfo=UTC)),
    )


@pytest.mark.asyncio
async def test_cancel_conservatively_settles_every_tracked_attempt() -> None:
    budget = _BudgetFake()
    reachy = _ReachyFake()
    coordinator = _coordinator(budget=budget, reachy=reachy)
    turn_id = uuid4()
    first = (uuid4(), uuid4())
    second = (uuid4(), uuid4())
    await coordinator.start(turn_id)
    coordinator.track_reservation(turn_id, *first)
    coordinator.track_reservation(turn_id, *second)

    await coordinator.cancel(turn_id, "privacy")

    assert reachy.stopped_turns == [turn_id]
    assert len(budget.reconciliations) == 1
    request = budget.reconciliations[0]
    assert request.turn_id == turn_id
    assert {
        (proof.reservation_id, proof.attempt_id, proof.disposition) for proof in request.proofs
    } == {(*first, "unknown"), (*second, "unknown")}
    assert coordinator.state is CoordinatorState.IDLE
    assert coordinator.active_turn_id() is None


@pytest.mark.asyncio
async def test_finish_rejects_unsettled_attempt_and_retains_turn() -> None:
    reachy = _ReachyFake()
    coordinator = _coordinator(reachy=reachy)
    turn_id = uuid4()
    attempt = (uuid4(), uuid4())
    await coordinator.start(turn_id)
    coordinator.track_reservation(turn_id, *attempt)

    with pytest.raises(RuntimeError, match="turn_has_unsettled_budget_attempts"):
        await coordinator.finish(turn_id)

    assert coordinator.active_turn_id() == turn_id
    assert reachy.stopped_turns == []
    coordinator.complete_reservation(turn_id, *attempt)
    assert await coordinator.finish(turn_id) is True
    assert await coordinator.finish(turn_id) is False
    assert reachy.stopped_turns == [turn_id]


@pytest.mark.asyncio
async def test_start_rejects_a_competing_turn() -> None:
    coordinator = _coordinator()
    first = uuid4()
    await coordinator.start(first)

    with pytest.raises(RuntimeError, match="household conversation busy"):
        await coordinator.start(uuid4())

    assert coordinator.active_turn_id() == first


@pytest.mark.asyncio
async def test_cancel_sanitizes_private_or_unknown_reason_text_and_still_stops() -> None:
    budget = _BudgetFake()
    reachy = _ReachyFake()
    coordinator = _coordinator(budget=budget, reachy=reachy)
    turn_id = uuid4()
    await coordinator.start(turn_id)
    coordinator.track_reservation(turn_id, uuid4(), uuid4())

    private_reason = "my child said a private sentence"
    await coordinator.cancel(turn_id, private_reason)

    assert reachy.stopped_turns == [turn_id]
    assert len(budget.reconciliations) == 1
    assert all(
        proof.evidence_code == "turn_cancelled:invalid_reason"
        for proof in budget.reconciliations[0].proofs
    )
    assert private_reason not in repr(coordinator.health.safety_blocks)
    assert coordinator.state is CoordinatorState.IDLE


@pytest.mark.asyncio
async def test_ninth_budget_attempt_is_rejected_before_cancellation() -> None:
    coordinator = _coordinator()
    turn_id = uuid4()
    await coordinator.start(turn_id)
    for _ in range(8):
        coordinator.track_reservation(turn_id, uuid4(), uuid4())

    with pytest.raises(RuntimeError, match="turn_budget_attempt_limit"):
        coordinator.track_reservation(turn_id, uuid4(), uuid4())

    assert len(coordinator.tracked_attempts(turn_id)) == 8


@pytest.mark.asyncio
async def test_duplicate_and_unknown_budget_attempts_are_rejected() -> None:
    coordinator = _coordinator()
    turn_id = uuid4()
    attempt = (uuid4(), uuid4())
    await coordinator.start(turn_id)
    coordinator.track_reservation(turn_id, *attempt)

    with pytest.raises(RuntimeError, match="duplicate tracked reservation"):
        coordinator.track_reservation(turn_id, *attempt)
    with pytest.raises(RuntimeError, match="unknown tracked reservation"):
        coordinator.complete_reservation(turn_id, uuid4(), uuid4())


@pytest.mark.asyncio
async def test_reconciliation_failure_cannot_skip_reachy_stop_or_release() -> None:
    budget = _RaisingBudget()
    reachy = _ReachyFake()
    coordinator = _coordinator(budget=budget, reachy=reachy)
    turn_id = uuid4()
    attempt = (uuid4(), uuid4())
    await coordinator.start(turn_id)
    coordinator.track_reservation(turn_id, *attempt)

    with pytest.raises(RuntimeError, match="reconciliation failed"):
        await coordinator.cancel(turn_id, "privacy")

    assert reachy.stopped_turns == [turn_id]
    assert coordinator.state is CoordinatorState.SAFETY_BLOCKED
    assert coordinator.active_turn_id() == turn_id
    assert coordinator.tracked_attempts(turn_id) == frozenset({attempt})
    with pytest.raises(RuntimeError, match="household safety blocked"):
        await coordinator.start(uuid4())


@pytest.mark.asyncio
async def test_internal_reconciliation_cancellation_is_a_safety_failure() -> None:
    budget = _SelfCancellingBudget()
    coordinator = _coordinator(budget=budget)
    turn_id = uuid4()
    await coordinator.start(turn_id)

    with pytest.raises(SafetyBlockedError, match="reconciliation_cancelled"):
        await coordinator.cancel(turn_id, "privacy")

    assert coordinator.state is CoordinatorState.SAFETY_BLOCKED
    assert coordinator.active_turn_id() == turn_id


@pytest.mark.asyncio
async def test_verified_owner_recovery_retries_the_exact_attempt_set() -> None:
    budget = _FailsOnceBudget()
    reachy = _ReachyFake()
    proof = object()
    owner = _OwnerRecoveryFake(proof)
    coordinator = TurnCoordinator(
        budget=budget,
        reachy=reachy,
        clock=FakeClock(datetime(2026, 8, 27, tzinfo=UTC)),
        owner_recovery=owner,
    )
    turn_id = uuid4()
    attempt = (uuid4(), uuid4())
    await coordinator.start(turn_id)
    coordinator.track_reservation(turn_id, *attempt)
    with pytest.raises(RuntimeError, match="reconciliation failed"):
        await coordinator.cancel(turn_id, "privacy")

    with pytest.raises(PermissionError, match="fresh_local_owner"):
        await coordinator.recover_safety_block(turn_id, object())
    assert coordinator.state is CoordinatorState.SAFETY_BLOCKED
    await coordinator.recover_safety_block(turn_id, proof)

    attempt_sets = [
        {(item.reservation_id, item.attempt_id) for item in request.proofs}
        for request in budget.reconciliations
    ]
    assert attempt_sets == [{attempt}, {attempt}]
    assert budget.reconciliations[0].proofs == budget.reconciliations[1].proofs
    assert coordinator.state is CoordinatorState.IDLE
    assert coordinator.active_turn_id() is None
    assert owner.calls[-1] == (proof, "turn.safety_recover", turn_id)


@pytest.mark.asyncio
async def test_cancelled_waiter_cannot_cancel_the_owned_barrier() -> None:
    reachy = _GatedReachy()
    budget = _BudgetFake()
    coordinator = _coordinator(budget=budget, reachy=reachy)
    turn_id = uuid4()
    await coordinator.start(turn_id)

    leader = asyncio.create_task(coordinator.cancel(turn_id, "privacy"))
    await asyncio.wait_for(reachy.entered.wait(), timeout=1)
    follower = asyncio.create_task(coordinator.cancel(turn_id, "privacy"))
    leader.cancel()
    with pytest.raises(asyncio.CancelledError):
        await leader
    assert coordinator.active_turn_id() == turn_id
    assert follower.done() is False

    reachy.release.set()
    await asyncio.wait_for(follower, timeout=1)
    assert reachy.stopped_turns == [turn_id]
    assert len(budget.reconciliations) == 1
    assert coordinator.active_turn_id() is None


@pytest.mark.asyncio
async def test_physical_stop_invokes_reachy_before_cancelling_tracked_work() -> None:
    order: list[str] = []

    class OrderedReachy(_ReachyFake):
        async def stop_all(self, turn_id: UUID | None) -> SafetyReceipt:
            order.append("reachy_stop_entered")
            await asyncio.sleep(0)
            return await super().stop_all(turn_id)

    async def tracked_work() -> None:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            order.append("tracked_task_cancelled")
            raise

    coordinator = _coordinator(reachy=OrderedReachy())
    turn_id = uuid4()
    await coordinator.start(turn_id)
    task = asyncio.create_task(tracked_work())
    coordinator.track_task(turn_id, task)
    await asyncio.sleep(0)

    await coordinator.cancel(turn_id, "physical_stop")

    assert order[:2] == ["reachy_stop_entered", "tracked_task_cancelled"]


@pytest.mark.asyncio
async def test_late_work_registration_is_rejected_after_cancel_publication() -> None:
    reachy = _GatedReachy()
    coordinator = _coordinator(reachy=reachy)
    turn_id = uuid4()
    await coordinator.start(turn_id)

    cancellation = asyncio.create_task(coordinator.cancel(turn_id, "privacy"))
    await asyncio.wait_for(reachy.entered.wait(), timeout=1)
    late_task = asyncio.create_task(asyncio.sleep(0))
    with pytest.raises(RuntimeError, match="turn cancellation in progress"):
        coordinator.track_task(turn_id, late_task)
    with pytest.raises(RuntimeError, match="turn cancellation in progress"):
        coordinator.track_reservation(turn_id, uuid4(), uuid4())
    with pytest.raises(RuntimeError, match="stale turn"):
        coordinator.complete_reservation(turn_id, uuid4(), uuid4())
    await late_task
    reachy.release.set()
    await cancellation


@pytest.mark.asyncio
async def test_result_acceptance_closes_when_cancellation_is_published() -> None:
    reachy = _GatedReachy()
    coordinator = _coordinator(reachy=reachy)
    turn_id = uuid4()
    await coordinator.start(turn_id)

    assert coordinator.is_current(turn_id)
    assert coordinator.accepts_results(turn_id)

    cancellation = asyncio.create_task(coordinator.cancel(turn_id, "privacy"))
    await asyncio.wait_for(coordinator.cancel_started.wait(), timeout=1)

    assert coordinator.is_current(turn_id)
    assert coordinator.accepts_results(turn_id) is False

    reachy.release.set()
    await cancellation
    assert coordinator.is_current(turn_id) is False
    assert coordinator.accepts_results(turn_id) is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "effect",
    (
        "raise",
        "malformed",
        "wrong_turn",
        "subclass",
        "playback_stopped",
        "motion_stopped",
        "buffers_cleared",
    ),
)
async def test_inexact_safety_proof_latches_active_turn(effect: str) -> None:
    reachy = _SafetyCaseReachy(effect)
    coordinator = TurnCoordinator(
        budget=_BudgetFake(),
        reachy=reachy,
        clock=FakeClock(datetime(2026, 8, 27, tzinfo=UTC)),
        safety_retry_limit=2,
        safety_attempt_timeout=0.05,
    )
    turn_id = uuid4()
    await coordinator.start(turn_id)

    with pytest.raises(SafetyBlockedError, match="turn_safety_blocked"):
        await coordinator.cancel(turn_id, "privacy")

    assert reachy.calls == 2
    assert coordinator.state is CoordinatorState.SAFETY_BLOCKED
    assert coordinator.active_turn_id() == turn_id
    assert coordinator.safety_blocked_record is not None
    assert coordinator.safety_blocked_record.attempts == 2
    await asyncio.sleep(0)
    if effect == "raise":
        assert "RuntimeError" in coordinator.health.detached_barrier_errors


@pytest.mark.asyncio
async def test_safety_timeout_retries_are_bounded_and_latch() -> None:
    reachy = _TimeoutReachy()
    coordinator = TurnCoordinator(
        budget=_BudgetFake(),
        reachy=reachy,
        clock=FakeClock(datetime(2026, 8, 27, tzinfo=UTC)),
        safety_retry_limit=2,
        safety_attempt_timeout=0.02,
    )
    turn_id = uuid4()
    await coordinator.start(turn_id)

    with pytest.raises(SafetyBlockedError, match="turn_safety_blocked"):
        await coordinator.cancel(turn_id, "privacy")

    assert reachy.calls == 2
    assert coordinator.state is CoordinatorState.SAFETY_BLOCKED
    assert coordinator.safety_blocked_record is not None
    assert coordinator.safety_blocked_record.failure_codes == (
        "reachy:timeout:1",
        "reachy:timeout:2",
    )


@pytest.mark.asyncio
async def test_live_task_cannot_be_untracked_to_evade_the_barrier() -> None:
    coordinator = _coordinator()
    turn_id = uuid4()
    await coordinator.start(turn_id)
    task = asyncio.create_task(asyncio.sleep(0))
    coordinator.track_task(turn_id, task)

    with pytest.raises(RuntimeError, match="cannot untrack live task"):
        coordinator.untrack_task(turn_id, task)
    await task
    coordinator.untrack_task(turn_id, task)
    await coordinator.cancel(turn_id, "privacy")


@pytest.mark.asyncio
async def test_tracked_task_timeout_remains_blocked_until_task_is_terminal() -> None:
    release = asyncio.Event()

    async def cancellation_resistant_work() -> None:
        try:
            await release.wait()
        except asyncio.CancelledError:
            await release.wait()

    proof = object()
    owner = _OwnerRecoveryFake(proof)
    coordinator = TurnCoordinator(
        budget=_BudgetFake(),
        reachy=_ReachyFake(),
        clock=FakeClock(datetime(2026, 8, 27, tzinfo=UTC)),
        owner_recovery=owner,
        tracked_join_timeout=0.02,
    )
    turn_id = uuid4()
    await coordinator.start(turn_id)
    task = asyncio.create_task(cancellation_resistant_work())
    coordinator.track_task(turn_id, task)

    with pytest.raises(SafetyBlockedError, match="tracked_task_restart_required"):
        await coordinator.cancel(turn_id, "privacy")
    assert coordinator.requires_process_restart is False
    assert coordinator.active_turn_id() == turn_id

    release.set()
    await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), timeout=1)
    await coordinator.recover_safety_block(turn_id, proof)
    assert coordinator.state is CoordinatorState.IDLE


@pytest.mark.asyncio
async def test_reconciliation_timeout_is_observed_and_retried_by_recovery() -> None:
    budget = _HangingOnceBudget()
    proof = object()
    coordinator = TurnCoordinator(
        budget=budget,
        reachy=_ReachyFake(),
        clock=FakeClock(datetime(2026, 8, 27, tzinfo=UTC)),
        owner_recovery=_OwnerRecoveryFake(proof),
        reconciliation_timeout=0.02,
    )
    turn_id = uuid4()
    attempt = (uuid4(), uuid4())
    await coordinator.start(turn_id)
    coordinator.track_reservation(turn_id, *attempt)

    with pytest.raises(SafetyBlockedError, match="reconciliation_timeout"):
        await coordinator.cancel(turn_id, "privacy")
    await asyncio.wait_for(budget.first_cancelled.wait(), timeout=1)
    with pytest.raises(SafetyBlockedError, match="prior_reconciliation_live"):
        await coordinator.recover_safety_block(turn_id, proof)
    assert coordinator.state is CoordinatorState.SAFETY_BLOCKED
    assert coordinator.active_turn_id() == turn_id
    budget.release_first.set()
    await asyncio.wait_for(budget.first_completed.wait(), timeout=1)
    await coordinator.recover_safety_block(turn_id, proof)

    attempt_sets = [
        {(item.reservation_id, item.attempt_id) for item in request.proofs}
        for request in budget.reconciliations
    ]
    assert attempt_sets == [{attempt}, {attempt}]
    assert coordinator.state is CoordinatorState.IDLE


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure_point",
    (
        "outer_barrier",
        "reachy_safety",
        "tracked_task_join",
        "budget_reconciliation",
        "reachy_attempt",
    ),
)
async def test_single_task_factory_failure_uses_owned_fallback(
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    real_create_task = asyncio.create_task
    failed = False

    def fail_once(coroutine: Any, *, name: str | None = None) -> asyncio.Task[Any]:
        nonlocal failed
        if not failed and name is not None and name.startswith(failure_point):
            failed = True
            raise RuntimeError("injected task factory failure")
        return real_create_task(coroutine, name=name)

    monkeypatch.setattr(asyncio, "create_task", fail_once)
    coordinator = _coordinator()
    turn_id = uuid4()
    await coordinator.start(turn_id)

    await coordinator.cancel(turn_id, "privacy")

    assert coordinator.state is CoordinatorState.IDLE
    assert coordinator.health.task_factory_failure_points == (failure_point,)


@pytest.mark.asyncio
async def test_unavailable_outer_owner_latches_restart_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator = _coordinator()
    turn_id = uuid4()
    await coordinator.start(turn_id)

    def fail_create_task(coroutine: Any, *, name: str | None = None) -> None:
        del coroutine, name
        raise RuntimeError("create_task unavailable")

    def fail_direct_task(
        coroutine: Any,
        *,
        loop: asyncio.AbstractEventLoop,
        name: str | None = None,
    ) -> None:
        del coroutine, loop, name
        raise RuntimeError("Task unavailable")

    with monkeypatch.context() as context:
        context.setattr(asyncio, "create_task", fail_create_task)
        context.setattr(asyncio, "Task", fail_direct_task)
        with pytest.raises(SafetyBlockedError, match="process_restart_required"):
            await coordinator.cancel(turn_id, "privacy")

    assert coordinator.requires_process_restart is True
    assert coordinator.active_turn_id() == turn_id
    assert coordinator.safety_blocked_record is not None
    assert coordinator.safety_blocked_record.attempts == 0
    with pytest.raises(SafetyBlockedError, match="process_restart_required"):
        await coordinator.recover_safety_block(turn_id, object())


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_point", ("reachy_safety", "reachy_attempt"))
async def test_unavailable_inner_safety_owner_latches_restart_only(
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    real_create_task = asyncio.create_task
    real_direct_task = asyncio.Task

    def fail_create_task(
        coroutine: Any,
        *,
        name: str | None = None,
    ) -> asyncio.Task[Any]:
        if name is not None and name.startswith(failure_point):
            raise RuntimeError("create_task unavailable")
        return real_create_task(coroutine, name=name)

    def fail_direct_task(
        coroutine: Any,
        *,
        loop: asyncio.AbstractEventLoop,
        name: str | None = None,
    ) -> asyncio.Task[Any]:
        if name is not None and name.startswith(failure_point):
            raise RuntimeError("Task unavailable")
        return real_direct_task(coroutine, loop=loop, name=name)

    coordinator = _coordinator()
    turn_id = uuid4()
    await coordinator.start(turn_id)
    with monkeypatch.context() as context:
        context.setattr(asyncio, "create_task", fail_create_task)
        context.setattr(asyncio, "Task", fail_direct_task)
        with pytest.raises(SafetyBlockedError, match="process_restart_required"):
            await coordinator.cancel(turn_id, "physical_stop")

    assert coordinator.requires_process_restart is True
    assert coordinator.state is CoordinatorState.SAFETY_BLOCKED
    assert coordinator.active_turn_id() == turn_id


@pytest.mark.asyncio
async def test_clock_failure_still_stops_reachy_and_records_no_timestamp() -> None:
    reachy = _ReachyFake()
    coordinator = TurnCoordinator(
        budget=_BudgetFake(),
        reachy=reachy,
        clock=_BrokenClock(),
    )
    turn_id = uuid4()
    coordinator_attempt = (uuid4(), uuid4())
    await coordinator.start(turn_id)
    coordinator.track_reservation(turn_id, *coordinator_attempt)

    with pytest.raises(RuntimeError, match="clock unavailable"):
        await coordinator.cancel(turn_id, "privacy")

    assert reachy.stopped_turns == [turn_id]
    assert coordinator.state is CoordinatorState.SAFETY_BLOCKED
    assert coordinator.safety_blocked_record is not None
    assert coordinator.safety_blocked_record.observed_at is None


def test_health_recorder_is_bounded_and_content_free() -> None:
    health = CancellationHealthRecorder(capacity=2)
    errors = (
        ValueError("private one"),
        KeyError("private two"),
        RuntimeError("private three"),
    )
    for error in errors:
        health.record_barrier_exception(error)

    assert health.detached_barrier_errors == ("KeyError", "RuntimeError")
    assert all("private" not in item for item in health.detached_barrier_errors)

    turn_id = uuid4()
    first = SafetyBlockedRecord(turn_id, "privacy", 1, ("first",), None)
    second = SafetyBlockedRecord(turn_id, "privacy", 2, ("second",), None)
    third = SafetyBlockedRecord(turn_id, "privacy", 3, ("third",), None)
    for record in (first, second, third):
        health.record_safety_blocked(record)
    assert health.safety_blocks == (second, third)


@pytest.mark.parametrize("capacity", (0, True, 257))
def test_health_recorder_rejects_invalid_capacity(capacity: object) -> None:
    with pytest.raises(ValueError, match="invalid cancellation health capacity"):
        CancellationHealthRecorder(capacity=capacity)  # type: ignore[arg-type]


def test_health_recorder_rejects_private_record_subclasses() -> None:
    class PrivateRecord(SafetyBlockedRecord):
        pass

    record = PrivateRecord(uuid4(), "privacy", 1, ("failure",), None)
    with pytest.raises(TypeError, match="exact SafetyBlockedRecord"):
        CancellationHealthRecorder().record_safety_blocked(record)


@pytest.mark.parametrize(
    ("keyword", "value"),
    [
        ("safety_retry_limit", 0),
        ("safety_retry_limit", 4),
        ("safety_attempt_timeout", float("nan")),
        ("tracked_join_timeout", 0),
        ("reconciliation_timeout", float("inf")),
    ],
)
def test_constructor_rejects_unsafe_retry_and_timeout_bounds(
    keyword: str,
    value: object,
) -> None:
    arguments: dict[str, object] = {
        "budget": _BudgetFake(),
        "reachy": _ReachyFake(),
        "clock": FakeClock(datetime(2026, 8, 27, tzinfo=UTC)),
        keyword: value,
    }
    with pytest.raises(ValueError, match="invalid"):
        TurnCoordinator(**arguments)  # type: ignore[arg-type]
