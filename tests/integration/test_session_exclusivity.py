from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from tuntun_contracts.budget import BudgetReconciliationRequest
from tuntun_contracts.reachy import SafetyReceipt
from tuntun_core.bootstrap.lifecycle import shutdown
from tuntun_core.domain.conversation import TurnEvent, TurnState, transition
from tuntun_core.services.sessions.idempotency import (
    IdempotencyCapacityError,
    IdempotencyStore,
)
from tuntun_core.services.sessions.manager import SessionManager, SessionRejected
from tuntun_core.services.sessions.turn_coordinator import SafetyBlockedError, TurnCoordinator
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


class _SafetyBlockingReachy(_ReachyFake):
    async def stop_all(self, turn_id: UUID | None) -> SafetyReceipt:
        self.stopped_turns.append(turn_id)
        return SafetyReceipt(
            turn_id=turn_id,
            playback_stopped=False,
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


def _coordinator(reachy: _ReachyFake | None = None) -> TurnCoordinator:
    return TurnCoordinator(
        budget=_BudgetFake(),
        reachy=reachy or _ReachyFake(),
        clock=FakeClock(datetime(2026, 8, 27, tzinfo=UTC)),
    )


@pytest.mark.asyncio
async def test_manager_admits_only_one_household_turn_and_returns_typed_busy() -> None:
    coordinator = _coordinator()
    manager = SessionManager(coordinator)
    household_id = uuid4()
    first_turn = uuid4()

    admission = await manager.open(household_id, first_turn)

    assert admission.household_id == household_id
    assert admission.turn_id == first_turn
    with pytest.raises(SessionRejected) as rejected:
        await manager.open(uuid4(), uuid4())
    assert rejected.value.reason == "busy"
    assert rejected.value.retry_after_ms == 1_000
    assert manager.active == admission


@pytest.mark.asyncio
async def test_manager_releases_only_after_full_finish() -> None:
    reachy = _ReachyFake()
    coordinator = _coordinator(reachy)
    manager = SessionManager(coordinator)
    first = await manager.open(uuid4(), uuid4())

    assert await manager.finish(first.turn_id) is True
    assert reachy.stopped_turns == [first.turn_id]
    assert manager.active is None

    second = await manager.open(uuid4(), uuid4())
    assert coordinator.is_current(second.turn_id)


@pytest.mark.asyncio
async def test_concurrent_manager_open_has_exactly_one_winner() -> None:
    manager = SessionManager(_coordinator())
    household_ids = (uuid4(), uuid4())
    turn_ids = (uuid4(), uuid4())

    results = await asyncio.gather(
        *(
            manager.open(household_id, turn_id)
            for household_id, turn_id in zip(household_ids, turn_ids, strict=True)
        ),
        return_exceptions=True,
    )

    admissions = [result for result in results if not isinstance(result, BaseException)]
    rejections = [result for result in results if isinstance(result, SessionRejected)]
    assert len(admissions) == 1
    assert len(rejections) == 1
    assert rejections[0].reason == "busy"


@pytest.mark.asyncio
async def test_shutdown_is_idle_safe_and_cancels_an_active_turn() -> None:
    reachy = _ReachyFake()
    coordinator = _coordinator(reachy)

    await shutdown(coordinator)
    assert reachy.stopped_turns == []

    turn_id = uuid4()
    await coordinator.start(turn_id)
    await shutdown(coordinator)

    assert reachy.stopped_turns == [turn_id]
    assert coordinator.active_turn_id() is None


@pytest.mark.asyncio
async def test_manager_cancel_synchronizes_its_admission() -> None:
    manager = SessionManager(_coordinator())
    admission = await manager.open(uuid4(), uuid4())

    await manager.cancel(admission.turn_id, "privacy")

    assert manager.active is None


@pytest.mark.asyncio
async def test_speaking_wake_is_admitted_only_after_prior_safe_idle() -> None:
    reachy = _ReachyFake()
    coordinator = _coordinator(reachy)
    manager = SessionManager(coordinator)
    household_id = uuid4()
    active = await manager.open(household_id, uuid4())
    deferred_turn_id = uuid4()
    wake_transition = transition(TurnState.SPEAKING, TurnEvent.WAKE)

    queued = await manager.queue_deferred_wake_from_transition(
        wake_transition,
        active_turn_id=active.turn_id,
        household_id=household_id,
        deferred_turn_id=deferred_turn_id,
    )

    assert queued is True
    assert manager.active == active
    assert coordinator.is_current(deferred_turn_id) is False
    await manager.cancel(active.turn_id, "physical_stop")
    assert reachy.stopped_turns == [active.turn_id]
    assert manager.active is not None
    assert manager.active.turn_id == deferred_turn_id
    assert coordinator.is_current(deferred_turn_id)


@pytest.mark.asyncio
async def test_repeated_deferred_wakes_coalesce_to_the_first_request() -> None:
    manager = SessionManager(_coordinator())
    household_id = uuid4()
    active = await manager.open(household_id, uuid4())
    wake_transition = transition(TurnState.SPEAKING, TurnEvent.WAKE)
    first_deferred = uuid4()

    assert await manager.queue_deferred_wake_from_transition(
        wake_transition,
        active_turn_id=active.turn_id,
        household_id=household_id,
        deferred_turn_id=first_deferred,
    )
    assert not await manager.queue_deferred_wake_from_transition(
        wake_transition,
        active_turn_id=active.turn_id,
        household_id=household_id,
        deferred_turn_id=uuid4(),
    )
    await manager.cancel(active.turn_id, "physical_stop")

    assert manager.active is not None
    assert manager.active.turn_id == first_deferred


@pytest.mark.asyncio
async def test_deferred_wake_rejects_reusing_the_active_turn_identifier() -> None:
    manager = SessionManager(_coordinator())
    household_id = uuid4()
    active = await manager.open(household_id, uuid4())

    with pytest.raises(ValueError, match="deferred turn must be fresh"):
        await manager.queue_deferred_wake_from_transition(
            transition(TurnState.SPEAKING, TurnEvent.WAKE),
            active_turn_id=active.turn_id,
            household_id=household_id,
            deferred_turn_id=active.turn_id,
        )


@pytest.mark.asyncio
async def test_non_wake_transition_never_queues_deferred_work() -> None:
    manager = SessionManager(_coordinator())
    household_id = uuid4()
    active = await manager.open(household_id, uuid4())

    assert not await manager.queue_deferred_wake_from_transition(
        transition(TurnState.IDLE, TurnEvent.WAKE),
        active_turn_id=active.turn_id,
        household_id=household_id,
        deferred_turn_id=uuid4(),
    )
    assert manager.deferred_wake is None


@pytest.mark.asyncio
async def test_deferred_wake_is_rejected_after_cancellation_publication() -> None:
    reachy = _GatedReachy()
    coordinator = _coordinator(reachy)
    manager = SessionManager(coordinator)
    household_id = uuid4()
    active = await manager.open(household_id, uuid4())
    cancellation = asyncio.create_task(manager.cancel(active.turn_id, "privacy"))
    await asyncio.wait_for(coordinator.cancel_started.wait(), timeout=1)

    try:
        with pytest.raises(RuntimeError, match="turn no longer accepts results"):
            await manager.queue_deferred_wake_from_transition(
                transition(TurnState.SPEAKING, TurnEvent.WAKE),
                active_turn_id=active.turn_id,
                household_id=household_id,
                deferred_turn_id=uuid4(),
            )
    finally:
        reachy.release.set()
        await cancellation

    assert manager.deferred_wake is None


@pytest.mark.asyncio
async def test_cancelled_manager_waiter_cannot_skip_deferred_wake_admission() -> None:
    reachy = _GatedReachy()
    coordinator = _coordinator(reachy)
    manager = SessionManager(coordinator)
    household_id = uuid4()
    active = await manager.open(household_id, uuid4())
    deferred_turn_id = uuid4()
    assert await manager.queue_deferred_wake_from_transition(
        transition(TurnState.SPEAKING, TurnEvent.WAKE),
        active_turn_id=active.turn_id,
        household_id=household_id,
        deferred_turn_id=deferred_turn_id,
    )

    waiter = asyncio.create_task(manager.cancel(active.turn_id, "physical_stop"))
    await asyncio.wait_for(reachy.entered.wait(), timeout=1)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    reachy.release.set()

    async def wait_for_deferred_admission() -> None:
        while not coordinator.is_current(deferred_turn_id):
            await asyncio.sleep(0)

    await asyncio.wait_for(wait_for_deferred_admission(), timeout=1)
    assert manager.active is not None
    assert manager.active.turn_id == deferred_turn_id
    await manager.cancel(deferred_turn_id, "shutdown")


@pytest.mark.asyncio
async def test_tracked_manager_waiter_can_terminate_before_owned_finalization() -> None:
    reachy = _GatedReachy()
    coordinator = _coordinator(reachy)
    manager = SessionManager(coordinator)
    household_id = uuid4()
    active = await manager.open(household_id, uuid4())
    deferred_turn_id = uuid4()
    assert await manager.queue_deferred_wake_from_transition(
        transition(TurnState.SPEAKING, TurnEvent.WAKE),
        active_turn_id=active.turn_id,
        household_id=household_id,
        deferred_turn_id=deferred_turn_id,
    )

    waiter = asyncio.create_task(manager.cancel(active.turn_id, "physical_stop"))
    coordinator.track_task(active.turn_id, waiter)
    await asyncio.wait_for(reachy.entered.wait(), timeout=1)
    with pytest.raises(asyncio.CancelledError):
        await waiter
    reachy.release.set()

    async def wait_for_deferred_admission() -> None:
        while not coordinator.is_current(deferred_turn_id):
            await asyncio.sleep(0)

    await asyncio.wait_for(wait_for_deferred_admission(), timeout=1)
    await manager.cancel(deferred_turn_id, "shutdown")


@pytest.mark.asyncio
async def test_cancelled_finish_waiter_cannot_skip_deferred_wake_admission() -> None:
    reachy = _GatedReachy()
    coordinator = _coordinator(reachy)
    manager = SessionManager(coordinator)
    household_id = uuid4()
    active = await manager.open(household_id, uuid4())
    deferred_turn_id = uuid4()
    assert await manager.queue_deferred_wake_from_transition(
        transition(TurnState.SPEAKING, TurnEvent.WAKE),
        active_turn_id=active.turn_id,
        household_id=household_id,
        deferred_turn_id=deferred_turn_id,
    )

    waiter = asyncio.create_task(manager.finish(active.turn_id))
    await asyncio.wait_for(reachy.entered.wait(), timeout=1)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    reachy.release.set()

    async def wait_for_deferred_admission() -> None:
        while not coordinator.is_current(deferred_turn_id):
            await asyncio.sleep(0)

    await asyncio.wait_for(wait_for_deferred_admission(), timeout=1)
    await manager.cancel(deferred_turn_id, "shutdown")


@pytest.mark.asyncio
async def test_manager_operation_factory_failure_uses_owned_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_create_task = asyncio.create_task
    failed = False

    def fail_manager_once(
        coroutine: object,
        *,
        name: str | None = None,
    ) -> asyncio.Task[object]:
        nonlocal failed
        if not failed and name is not None and name.startswith("session_cancel"):
            failed = True
            raise RuntimeError("injected task factory failure")
        return real_create_task(coroutine, name=name)  # type: ignore[arg-type]

    monkeypatch.setattr(asyncio, "create_task", fail_manager_once)
    coordinator = _coordinator()
    manager = SessionManager(coordinator)
    active = await manager.open(uuid4(), uuid4())

    await manager.cancel(active.turn_id, "privacy")

    assert coordinator.active_turn_id() is None
    assert coordinator.health.task_factory_failure_points == ("session_cancel",)


@pytest.mark.asyncio
async def test_cancel_storm_coalesces_to_one_owned_manager_operation() -> None:
    reachy = _GatedReachy()
    coordinator = _coordinator(reachy)
    manager = SessionManager(coordinator)
    active = await manager.open(uuid4(), uuid4())

    callers = tuple(
        asyncio.create_task(manager.cancel(active.turn_id, "physical_stop"))
        for _ in range(64)
    )
    await asyncio.wait_for(reachy.entered.wait(), timeout=1)
    await asyncio.sleep(0)

    try:
        assert manager.inflight_operation_count == 1
        assert reachy.stopped_turns == [active.turn_id]
    finally:
        reachy.release.set()
        await asyncio.gather(*callers, return_exceptions=True)
    assert manager.inflight_operation_count == 0


@pytest.mark.asyncio
async def test_finish_joins_existing_cancel_operation_and_returns_false() -> None:
    reachy = _GatedReachy()
    coordinator = _coordinator(reachy)
    manager = SessionManager(coordinator)
    active = await manager.open(uuid4(), uuid4())

    cancellation = asyncio.create_task(manager.cancel(active.turn_id, "physical_stop"))
    await asyncio.wait_for(reachy.entered.wait(), timeout=1)
    finishing = asyncio.create_task(manager.finish(active.turn_id))
    await asyncio.sleep(0)

    assert manager.inflight_operation_count == 1
    reachy.release.set()
    await cancellation
    assert await finishing is False
    assert reachy.stopped_turns == [active.turn_id]


@pytest.mark.asyncio
async def test_cancel_is_not_suppressed_by_a_concurrent_failed_finish() -> None:
    budget = _BudgetFake()
    reachy = _ReachyFake()
    coordinator = TurnCoordinator(
        budget=budget,
        reachy=reachy,
        clock=FakeClock(datetime(2026, 8, 27, tzinfo=UTC)),
    )
    manager = SessionManager(coordinator)
    active = await manager.open(uuid4(), uuid4())
    coordinator.track_reservation(active.turn_id, uuid4(), uuid4())

    await coordinator._lock.acquire()  # noqa: SLF001 - deterministic race injection
    finishing = asyncio.create_task(manager.finish(active.turn_id))
    await asyncio.sleep(0)
    cancellation = asyncio.create_task(manager.cancel(active.turn_id, "physical_stop"))
    await asyncio.sleep(0)
    try:
        inflight_count = manager.inflight_operation_count
    finally:
        coordinator._lock.release()  # noqa: SLF001 - deterministic race injection

    finish_result, cancel_result = await asyncio.gather(
        finishing,
        cancellation,
        return_exceptions=True,
    )
    assert inflight_count == 2
    assert isinstance(finish_result, RuntimeError)
    assert str(finish_result) == "turn_has_unsettled_budget_attempts"
    assert cancel_result is None
    assert reachy.stopped_turns == [active.turn_id]
    assert len(budget.reconciliations) == 1
    assert coordinator.active_turn_id() is None


@pytest.mark.asyncio
async def test_stale_turn_storm_creates_no_manager_operations() -> None:
    manager = SessionManager(_coordinator())
    stale_turns = tuple(uuid4() for _ in range(64))

    assert await asyncio.gather(*(manager.finish(turn_id) for turn_id in stale_turns)) == [
        False
    ] * 64
    await asyncio.gather(*(manager.cancel(turn_id, "cancel") for turn_id in stale_turns))
    assert manager.inflight_operation_count == 0


@pytest.mark.asyncio
async def test_manager_operation_capacity_falls_through_to_fail_closed_cancel() -> None:
    reachy = _ReachyFake()
    coordinator = _coordinator(reachy)
    manager = SessionManager(coordinator)
    active = await manager.open(uuid4(), uuid4())
    blocker = asyncio.Event()
    retained = tuple(asyncio.create_task(blocker.wait()) for _ in range(4))
    for task in retained:
        manager._operations[(uuid4(), "finish")] = task  # noqa: SLF001 - capacity injection

    try:
        await manager.cancel(active.turn_id, "physical_stop")
    finally:
        for task in retained:
            task.cancel()
        await asyncio.gather(*retained, return_exceptions=True)
        manager._operations.clear()  # noqa: SLF001 - capacity injection cleanup

    assert reachy.stopped_turns == [active.turn_id]
    assert coordinator.active_turn_id() is None


@pytest.mark.asyncio
async def test_unavailable_manager_operation_owner_still_latches_restart_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator = _coordinator()
    manager = SessionManager(coordinator)
    active = await manager.open(uuid4(), uuid4())

    def fail_create_task(coroutine: object, *, name: str | None = None) -> None:
        del coroutine, name
        raise RuntimeError("create_task unavailable")

    def fail_direct_task(
        coroutine: object,
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
            await manager.cancel(active.turn_id, "privacy")

    assert coordinator.requires_process_restart is True
    assert coordinator.active_turn_id() == active.turn_id


@pytest.mark.asyncio
async def test_manager_maps_real_safety_block_to_typed_rejection() -> None:
    coordinator = _coordinator(_SafetyBlockingReachy())
    manager = SessionManager(coordinator)
    active = await manager.open(uuid4(), uuid4())

    with pytest.raises(SafetyBlockedError, match="turn_safety_blocked"):
        await manager.cancel(active.turn_id, "privacy")

    with pytest.raises(SessionRejected) as rejected:
        await manager.open(uuid4(), uuid4())

    assert rejected.value.reason == "safety_blocked"
    assert rejected.value.retry_after_ms is None


def test_idempotency_claim_is_operation_scoped_and_bounded() -> None:
    store = IdempotencyStore(max_entries=2)

    assert store.claim("turn.start", "key-1") is True
    assert store.claim("turn.start", "key-1") is False
    assert store.claim("turn.finish", "key-1") is True
    with pytest.raises(IdempotencyCapacityError, match="idempotency_store_full"):
        store.claim("turn.start", "key-2")


def test_idempotency_claim_is_atomic_across_threads() -> None:
    store = IdempotencyStore(max_entries=64)
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = tuple(executor.map(lambda _: store.claim("turn.start", "same-key"), range(64)))

    assert results.count(True) == 1
    assert results.count(False) == 63
    assert store.size == 1


@pytest.mark.parametrize("capacity", (0, True, 65_537))
def test_idempotency_store_rejects_invalid_capacity(capacity: object) -> None:
    with pytest.raises(ValueError, match="invalid idempotency capacity"):
        IdempotencyStore(max_entries=capacity)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("operation", "key"),
    [("", "key"), ("turn.start", ""), ("private payload", "key"), ("turn.start", "x" * 257)],
)
def test_idempotency_claim_rejects_unbounded_or_content_bearing_keys(
    operation: str,
    key: str,
) -> None:
    store = IdempotencyStore()
    with pytest.raises(ValueError, match="invalid idempotency"):
        store.claim(operation, key)


@pytest.mark.asyncio
async def test_public_boundaries_reject_non_exact_runtime_types() -> None:
    coordinator = _coordinator()
    manager = SessionManager(coordinator)
    with pytest.raises(TypeError, match="household_id"):
        await manager.open(str(uuid4()), uuid4())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="turn_id"):
        await coordinator.start(str(uuid4()))  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="turn_id"):
        coordinator.accepts_results(str(uuid4()))  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="coordinator"):
        await shutdown(object())  # type: ignore[arg-type]
