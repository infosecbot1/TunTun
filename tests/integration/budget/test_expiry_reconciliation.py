from __future__ import annotations

import asyncio
import gc
import warnings
from collections.abc import Coroutine
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from tuntun_contracts.budget import BudgetReconciliationRequest, LlmUsageUnits, TransportProof
from tuntun_contracts.reachy import SafetyReceipt
from tuntun_core.bootstrap.lifecycle import (
    BudgetReconciliationSupervisor,
    CoreProcessLease,
    StartupTurnRecovery,
)
from tuntun_core.services.budget.reconciler import ExpiredBudgetReconciler

pytest_plugins = ("tests.fixtures.provider_egress",)


_EVENT_WAIT_TIMEOUT_SECONDS = 5.0


def _global_safety_receipt() -> SafetyReceipt:
    return SafetyReceipt(
        turn_id=None,
        playback_stopped=True,
        motion_stopped=True,
        buffers_cleared=True,
    )


def _owner_only_lock_path(tmp_path: Path) -> Path:
    state_root = tmp_path / "production-state"
    state_root.mkdir(mode=0o700)
    state_root.chmod(0o700)
    return state_root / "core-process.lock"


def _assert_lease_released(lock_path: Path) -> None:
    lease = CoreProcessLease.acquire(lock_path)
    lease.release_after_shutdown()


def _lease_is_reacquirable(lock_path: Path) -> bool:
    try:
        lease = CoreProcessLease.acquire(lock_path)
    except RuntimeError as error:
        if str(error) != "core_process_lease_held":
            raise
        return False
    lease.release_after_shutdown()
    return True


async def _wait_for_event(
    event: asyncio.Event,
    timeout: float = _EVENT_WAIT_TIMEOUT_SECONDS,
) -> None:
    async with asyncio.timeout(timeout):
        await event.wait()


def _loop_bound_task(
    coroutine: Coroutine[Any, Any, Any],
    *,
    name: str,
) -> asyncio.Task[Any]:
    return asyncio.Task(coroutine, loop=asyncio.get_running_loop(), name=name)


async def _session_row(factory: Any, session_id: object) -> tuple[str, bool]:
    async with factory() as uow:

        def load(transaction: Any) -> tuple[str, bool]:
            row = transaction.exec_driver_sql(
                "SELECT state,closed_at IS NOT NULL FROM sessions WHERE id=?",
                (str(session_id),),
            ).one()
            return str(row[0]), bool(row[1])

        result = await uow.run_sync(load)
        await uow.rollback()
    return result


class _PassingReachySafety:
    def __init__(self) -> None:
        self.calls: list[object] = []

    async def stop_all(self, turn_id: object) -> SafetyReceipt:
        self.calls.append(turn_id)
        return _global_safety_receipt()


class _RejectingTaskFactory:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(
        self,
        loop: asyncio.AbstractEventLoop,
        coroutine: Coroutine[Any, Any, Any],
        **kwargs: Any,
    ) -> asyncio.Task[Any]:
        del loop, coroutine, kwargs
        self.calls += 1
        raise RuntimeError("synthetic_create_task_rejected")


class _NoopClock:
    def now(self) -> datetime:
        return datetime(2026, 8, 27, 1, 2, 3, 4, tzinfo=UTC)


class _NoopDriver:
    def exec_driver_sql(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs


class _NoopUnitOfWork:
    async def __aenter__(self) -> _NoopUnitOfWork:
        return self

    async def __aexit__(self, *args: Any) -> None:
        del args

    async def run_sync(self, operation: Any) -> Any:
        return operation(_NoopDriver())

    async def commit(self) -> None:
        return None

    async def rollback(self) -> None:
        return None


class _NoopUnitOfWorkFactory:
    def __call__(self) -> _NoopUnitOfWork:
        return _NoopUnitOfWork()


class _BlockingPeriodicReconciler(ExpiredBudgetReconciler):
    def __init__(self) -> None:
        super().__init__(
            _NoopUnitOfWorkFactory(),
            _NoopClock(),
            object(),
            interval_seconds=60.0,
        )
        self.batch_started = asyncio.Event()
        self.release_batch = asyncio.Event()
        self.batch_calls = 0

    async def reconcile_batch(self) -> int:
        self.batch_calls += 1
        self.batch_started.set()
        await self.release_batch.wait()
        return 0


class _DelayedReachySafety:
    def __init__(self, events: list[str]) -> None:
        self._events = events
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def stop_all(self, turn_id: object) -> SafetyReceipt:
        self._events.append("safety_start")
        self.started.set()
        assert turn_id is None
        await self.release.wait()
        self._events.append("safety_verified")
        return _global_safety_receipt()


class _FailingReachySafety:
    async def stop_all(self, turn_id: object) -> SafetyReceipt:
        assert turn_id is None
        raise RuntimeError("synthetic_startup_safety_failure")


class _LeaseReleasingReachySafety:
    def __init__(self, lease: CoreProcessLease) -> None:
        self._lease = lease

    async def stop_all(self, turn_id: object) -> SafetyReceipt:
        assert turn_id is None
        self._lease.release_after_shutdown()
        return _global_safety_receipt()


class _CancellationObservingReachySafety:
    def __init__(self, *, block_cancel_finish: bool = False) -> None:
        self._block_cancel_finish = block_cancel_finish
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.cancelled = asyncio.Event()
        self.finished = asyncio.Event()

    async def stop_all(self, turn_id: object) -> SafetyReceipt:
        assert turn_id is None
        self.started.set()
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            self.cancelled.set()
            if self._block_cancel_finish:
                while not self.release.is_set():
                    with suppress(asyncio.CancelledError):
                        await self.release.wait()
            raise
        finally:
            self.finished.set()
        return _global_safety_receipt()


class _RestartRecordingReconciler:
    def __init__(self, delegate: ExpiredBudgetReconciler, events: list[str]) -> None:
        self._delegate = delegate
        self._events = events
        self.restart_drain_started = asyncio.Event()

    async def drain_restart_open_attempts(self, cutoff: object) -> None:
        self._events.append("restart_drain_start")
        self.restart_drain_started.set()
        await self._delegate.drain_restart_open_attempts(cutoff)
        self._events.append("restart_drain_finished")


class _SupervisorReconciler:
    def __init__(
        self,
        *,
        initial_drain_error: BaseException | None = None,
        worker_fault: str | None = None,
    ) -> None:
        self._initial_drain_error = initial_drain_error
        self._worker_fault = worker_fault
        self.restart_drains = 0
        self.initial_drains = 0
        self.worker_started = asyncio.Event()
        self.fail_worker = asyncio.Event()

    async def drain_restart_open_attempts(self, cutoff: object) -> None:
        del cutoff
        self.restart_drains += 1

    async def drain_before_ready(self) -> None:
        self.initial_drains += 1
        if self._initial_drain_error is not None:
            raise self._initial_drain_error

    async def run_periodically(self, stop: asyncio.Event) -> None:
        self.worker_started.set()
        if self._worker_fault == "raise":
            await self.fail_worker.wait()
            raise RuntimeError("synthetic_periodic_failure")
        await stop.wait()


class _BlockingInitialDrainReconciler(_SupervisorReconciler):
    def __init__(self) -> None:
        super().__init__()
        self.initial_drain_started = asyncio.Event()
        self.initial_drain_cancelled = asyncio.Event()
        self.release_initial_drain = asyncio.Event()
        self.initial_drain_finished = asyncio.Event()

    async def drain_before_ready(self) -> None:
        self.initial_drains += 1
        self.initial_drain_started.set()
        cancelled = False
        while not self.release_initial_drain.is_set():
            try:
                await self.release_initial_drain.wait()
            except asyncio.CancelledError:
                self.initial_drain_cancelled.set()
                cancelled = True
        self.initial_drain_finished.set()
        if cancelled:
            raise asyncio.CancelledError


class _BlockingWorkerReconciler(_SupervisorReconciler):
    def __init__(self) -> None:
        super().__init__()
        self.release_worker = asyncio.Event()
        self.worker_cancelled = asyncio.Event()
        self.worker_finished = asyncio.Event()

    async def run_periodically(self, stop: asyncio.Event) -> None:
        del stop
        self.worker_started.set()
        cancelled = False
        while not self.release_worker.is_set():
            try:
                await self.release_worker.wait()
            except asyncio.CancelledError:
                self.worker_cancelled.set()
                cancelled = True
        self.worker_finished.set()
        if cancelled:
            raise asyncio.CancelledError


class _ReentrantStopDrainReconciler(_SupervisorReconciler):
    def __init__(self, lock_path: Path) -> None:
        super().__init__()
        self._lock_path = lock_path
        self.supervisor: BudgetReconciliationSupervisor | None = None
        self.stop_error: str | None = None
        self.lease_reacquirable_during_start: bool | None = None

    async def drain_before_ready(self) -> None:
        self.initial_drains += 1
        assert self.supervisor is not None
        try:
            await self.supervisor.stop()
        except RuntimeError as error:
            self.stop_error = str(error)
        self.lease_reacquirable_during_start = _lease_is_reacquirable(self._lock_path)


@pytest.mark.asyncio
async def test_periodic_reconciler_finishes_current_batch_and_stops_before_interval() -> None:
    reconciler = _BlockingPeriodicReconciler()
    stop = asyncio.Event()
    worker = asyncio.create_task(reconciler.run_periodically(stop))
    try:
        await _wait_for_event(reconciler.batch_started)
        assert reconciler.batch_calls == 1

        stop.set()
        reconciler.release_batch.set()

        await asyncio.wait_for(worker, timeout=5.0)
        assert reconciler.batch_calls == 1
    finally:
        stop.set()
        reconciler.release_batch.set()
        if not worker.done():
            worker.cancel()
        with suppress(BaseException):
            await worker


@pytest.mark.asyncio
@pytest.mark.parametrize("claimed", (False, True))
async def test_expired_proven_unsent_shapes_release_without_ledger(
    production_provider_gateway_case,
    claimed,
) -> None:
    case = await production_provider_gateway_case()
    if claimed:
        await case.begin_claim()
    await case.expire()
    assert await case.reconcile_expired() == 1
    reservation, call, ledger_count = await case.proof_rows()
    assert reservation[:2] == ("released", "finished")
    assert ledger_count == 0
    assert call is None if not claimed else call[:2] == ("cancelled", "finished")


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ("marked_sent", "network_invocation_starting"))
async def test_expired_sent_shapes_settle_conservatively_and_close_call(
    production_provider_gateway_case,
    phase,
) -> None:
    case = await production_provider_gateway_case()
    if phase == "marked_sent":
        await case.mark_sent()
    else:
        await case.mark_network_invocation_starting()
    await case.expire()
    assert await case.reconcile_expired() == 1
    reservation, call, ledger_count = await case.proof_rows()
    ledger = await case.ledger_row()
    assert reservation[:2] == ("settled", "finished")
    assert call == ("ambiguous", "finished", 1)
    assert ledger_count == 1
    assert ledger.conservative_estimate_used == 1
    assert ledger.charged_micros_sgd == case.exact_snapshot_price


@pytest.mark.asyncio
async def test_recovery_uses_persisted_exact_success_receipt_not_reservation(
    production_provider_gateway_case,
) -> None:
    case = await production_provider_gateway_case(
        usage_ceiling=LlmUsageUnits(category="llm", input_tokens=1, output_tokens=0),
        reported_usage=LlmUsageUnits(category="llm", input_tokens=2, output_tokens=0),
    )
    await case.invoke()
    await case.expire()
    await case.reconcile_expired()
    ledger = await case.ledger_row()
    assert ledger.charged_micros_sgd > case.exact_snapshot_price
    assert ledger.conservative_estimate_used == 0
    assert ledger.estimate_overrun == 1


@pytest.mark.asyncio
async def test_direct_release_rejects_durable_sent_proof(
    production_provider_gateway_case,
) -> None:
    case = await production_provider_gateway_case()
    await case.mark_sent()
    before = await case.proof_rows()
    proof = TransportProof(
        reservation_id=case.route.budget_reservation_id,
        attempt_id=case.route.attempt_id,
        disposition="never_sent",
        observed_at=case.clock.now(),
        evidence_code="synthetic_connect_failure",
    )
    with pytest.raises(PermissionError, match="sent_reservation_requires_settlement"):
        await case.budget_guard.release_unsent(
            case.route.budget_reservation_id,
            case.route.attempt_id,
            proof,
        )
    assert await case.proof_rows() == before


@pytest.mark.asyncio
async def test_malformed_phase_pair_is_quarantined_without_partial_terminalization(
    production_provider_gateway_case,
) -> None:
    case = await production_provider_gateway_case()
    await case.tamper_transport_phase_mismatch()
    await case.expire()
    before = await case.proof_rows()
    with pytest.raises(PermissionError, match="budget_transport_proof_quarantined"):
        await case.reconcile_expired()
    assert await case.proof_rows() == before


@pytest.mark.asyncio
async def test_empty_in_memory_proofs_discover_durable_turn_binding(
    production_provider_gateway_case,
) -> None:
    case = await production_provider_gateway_case()
    await case.mark_sent()
    settlements = await case.budget_guard.reconcile_turn(
        BudgetReconciliationRequest(turn_id=case.route.turn_id, proofs=())
    )
    assert len(settlements) == 1
    assert (await case.proof_rows())[0][0] == "settled"
    assert (
        await case.budget_guard.reconcile_turn(
            BudgetReconciliationRequest(turn_id=case.route.turn_id, proofs=())
        )
        == ()
    )
    assert await case.ledger_count() == 1


@pytest.mark.asyncio
async def test_restart_reconciles_unexpired_prior_open_attempt_once(
    production_provider_gateway_case,
) -> None:
    case = await production_provider_gateway_case()
    await case.mark_network_invocation_starting()
    assert await case.reconcile_restart(case.clock.now()) == 1
    assert await case.reconcile_restart(case.clock.now()) == 0
    reservation, call, ledger_count = await case.proof_rows()
    assert reservation[:2] == ("settled", "finished")
    assert call == ("ambiguous", "finished", 1)
    assert ledger_count == 1


@pytest.mark.asyncio
async def test_startup_recovery_waits_for_verified_global_stop_before_restart_drain(
    production_provider_gateway_case,
    tmp_path: Path,
) -> None:
    case = await production_provider_gateway_case(seed_response_scope=True)
    await case.mark_network_invocation_starting()
    before = await case.proof_rows()
    events: list[str] = []
    reachy = _DelayedReachySafety(events)
    reconciler = _RestartRecordingReconciler(
        ExpiredBudgetReconciler(case.factory, case.clock, case.budget_guard),
        events,
    )
    lock_path = _owner_only_lock_path(tmp_path)
    lease = CoreProcessLease.acquire(lock_path)
    recovery = StartupTurnRecovery(
        reachy,
        reconciler,
        case.factory,
        case.clock,
        lease,
        attempt_timeout=0.5,
    )
    recovery_task = asyncio.create_task(recovery.recover_before_ready())
    try:
        await _wait_for_event(reachy.started)
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(reconciler.restart_drain_started.wait(), timeout=0.02)
        assert await case.proof_rows() == before

        reachy.release.set()
        await asyncio.wait_for(recovery_task, timeout=0.5)

        assert events[:3] == ["safety_start", "safety_verified", "restart_drain_start"]
        recovery.require_ready()
    finally:
        reachy.release.set()
        if not recovery_task.done():
            recovery_task.cancel()
        with suppress(BaseException):
            await recovery_task
        lease.release_after_shutdown()


@pytest.mark.asyncio
async def test_startup_safety_failure_leaves_attempts_and_sessions_recoverable(
    production_provider_gateway_case,
    tmp_path: Path,
) -> None:
    case = await production_provider_gateway_case(seed_response_scope=True)
    await case.mark_network_invocation_starting()
    before_proof = await case.proof_rows()
    before_session = await _session_row(case.factory, case.route.session_id)
    lock_path = _owner_only_lock_path(tmp_path)
    lease = CoreProcessLease.acquire(lock_path)
    recovery = StartupTurnRecovery(
        _FailingReachySafety(),
        ExpiredBudgetReconciler(case.factory, case.clock, case.budget_guard),
        case.factory,
        case.clock,
        lease,
        retry_limit=1,
        attempt_timeout=0.01,
    )
    try:
        with pytest.raises(RuntimeError, match="startup_turn_recovery_unhealthy"):
            await recovery.recover_before_ready()

        assert await case.proof_rows() == before_proof
        assert await _session_row(case.factory, case.route.session_id) == before_session
        with pytest.raises(RuntimeError, match="startup_turn_recovery_unhealthy"):
            recovery.require_ready()
    finally:
        lease.release_after_shutdown()


def test_competing_core_process_lease_blocks_before_recovery(tmp_path: Path) -> None:
    lock_path = _owner_only_lock_path(tmp_path)
    lease = CoreProcessLease.acquire(lock_path)
    try:
        with pytest.raises(RuntimeError, match="core_process_lease_held"):
            CoreProcessLease.acquire(lock_path)
    finally:
        lease.release_after_shutdown()


def test_core_process_lease_rejects_unsafe_parent_mode(tmp_path: Path) -> None:
    state_root = tmp_path / "unsafe-production-state"
    state_root.mkdir(mode=0o755)
    state_root.chmod(0o755)
    with pytest.raises(PermissionError, match="core_process_lease_directory_not_owner_only"):
        CoreProcessLease.acquire(state_root / "core-process.lock")


def test_core_process_lease_rejects_unsafe_existing_lock_file_mode(tmp_path: Path) -> None:
    lock_path = _owner_only_lock_path(tmp_path)
    lock_path.write_text("", encoding="utf-8")
    lock_path.chmod(0o644)
    with pytest.raises(PermissionError, match="core_process_lease_file_not_owner_only"):
        CoreProcessLease.acquire(lock_path)


def test_core_process_lease_rejects_symlink_lock_file(tmp_path: Path) -> None:
    lock_path = _owner_only_lock_path(tmp_path)
    target = lock_path.with_name("target.lock")
    target.write_text("", encoding="utf-8")
    lock_path.symlink_to(target)
    with pytest.raises(PermissionError, match="core_process_lease_symlink_rejected"):
        CoreProcessLease.acquire(lock_path)


@pytest.mark.asyncio
async def test_released_process_lease_blocks_recovery_effects_and_readiness(
    production_provider_gateway_case,
    tmp_path: Path,
) -> None:
    case = await production_provider_gateway_case(seed_response_scope=True)
    await case.mark_network_invocation_starting()
    before_proof = await case.proof_rows()
    before_session = await _session_row(case.factory, case.route.session_id)
    lock_path = _owner_only_lock_path(tmp_path)
    lease = CoreProcessLease.acquire(lock_path)
    recovery = StartupTurnRecovery(
        _LeaseReleasingReachySafety(lease),
        ExpiredBudgetReconciler(case.factory, case.clock, case.budget_guard),
        case.factory,
        case.clock,
        lease,
    )
    try:
        with pytest.raises(RuntimeError, match="startup_turn_recovery_unhealthy"):
            await recovery.recover_before_ready()

        assert await case.proof_rows() == before_proof
        assert await _session_row(case.factory, case.route.session_id) == before_session
        with pytest.raises(RuntimeError, match="startup_turn_recovery_unhealthy"):
            recovery.require_ready()
    finally:
        lease.release_after_shutdown()


@pytest.mark.asyncio
async def test_initial_budget_drain_failure_releases_process_lease_and_blocks_readiness(
    production_provider_gateway_case,
    tmp_path: Path,
) -> None:
    case = await production_provider_gateway_case(seed_response_scope=True)
    lock_path = _owner_only_lock_path(tmp_path)
    lease = CoreProcessLease.acquire(lock_path)
    reconciler = _SupervisorReconciler(initial_drain_error=RuntimeError("synthetic_drain_fail"))
    recovery = StartupTurnRecovery(
        _PassingReachySafety(),
        reconciler,
        case.factory,
        case.clock,
        lease,
    )
    supervisor = BudgetReconciliationSupervisor(reconciler, recovery)
    try:
        with pytest.raises(RuntimeError, match="budget_reconciliation_unhealthy"):
            await supervisor.start()

        with pytest.raises(RuntimeError, match="budget_reconciliation_unhealthy"):
            supervisor.require_ready()
        with pytest.raises(RuntimeError, match="startup_turn_recovery_unhealthy"):
            recovery.require_ready()
        _assert_lease_released(lock_path)
    finally:
        lease.release_after_shutdown()


@pytest.mark.asyncio
async def test_failed_start_cleanup_uses_task_fallback_and_releases_process_lease(
    tmp_path: Path,
) -> None:
    lock_path = _owner_only_lock_path(tmp_path)
    lease = CoreProcessLease.acquire(lock_path)
    reconciler = _SupervisorReconciler(initial_drain_error=RuntimeError("synthetic_drain_fail"))
    recovery = StartupTurnRecovery(
        _PassingReachySafety(),
        reconciler,
        _NoopUnitOfWorkFactory(),
        _NoopClock(),
        lease,
    )
    supervisor = BudgetReconciliationSupervisor(reconciler, recovery)
    loop = asyncio.get_running_loop()
    previous_factory = loop.get_task_factory()
    rejecting_factory = _RejectingTaskFactory()
    loop.set_task_factory(rejecting_factory)
    try:
        caught: BaseException | None = None
        try:
            await supervisor.start()
        except BaseException as error:
            caught = error
        finally:
            loop.set_task_factory(previous_factory)

        lease_released = _lease_is_reacquirable(lock_path)
        supervisor_ready = True
        try:
            supervisor.require_ready()
        except RuntimeError:
            supervisor_ready = False
        recovery_ready = True
        try:
            recovery.require_ready()
        except RuntimeError:
            recovery_ready = False
        lease.release_after_shutdown()

        assert isinstance(caught, RuntimeError)
        assert "budget_reconciliation_unhealthy" in str(caught)
        assert rejecting_factory.calls >= 2
        assert not supervisor_ready
        assert not recovery_ready
        assert lease_released
    finally:
        loop.set_task_factory(previous_factory)
        lease.release_after_shutdown()


@pytest.mark.asyncio
async def test_cancelled_start_cleanup_uses_task_fallback_and_observes_startup_work(
    tmp_path: Path,
) -> None:
    lock_path = _owner_only_lock_path(tmp_path)
    lease = CoreProcessLease.acquire(lock_path)
    reachy = _CancellationObservingReachySafety(block_cancel_finish=True)
    reconciler = _SupervisorReconciler()
    recovery = StartupTurnRecovery(
        reachy,
        reconciler,
        _NoopUnitOfWorkFactory(),
        _NoopClock(),
        lease,
        attempt_timeout=0.5,
    )
    supervisor = BudgetReconciliationSupervisor(reconciler, recovery)
    loop = asyncio.get_running_loop()
    previous_factory = loop.get_task_factory()
    rejecting_factory = _RejectingTaskFactory()
    start_task = _loop_bound_task(supervisor.start(), name="rejecting-factory-start")
    loop.set_task_factory(rejecting_factory)
    try:
        await _wait_for_event(reachy.started)
        start_task.cancel()
        await _wait_for_event(reachy.cancelled)
        assert not _lease_is_reacquirable(lock_path)

        reachy.release.set()
        start_error: BaseException | None = None
        try:
            async with asyncio.timeout(0.5):
                await start_task
        except BaseException as error:
            start_error = error
        loop.set_task_factory(previous_factory)
        lease_released = _lease_is_reacquirable(lock_path)
        lease.release_after_shutdown()

        assert isinstance(start_error, asyncio.CancelledError)
        assert reachy.finished.is_set()
        assert rejecting_factory.calls >= 2
        assert lease_released
    finally:
        reachy.release.set()
        loop.set_task_factory(previous_factory)
        if not start_task.done():
            start_task.cancel()
        with suppress(BaseException):
            await start_task
        lease.release_after_shutdown()


@pytest.mark.asyncio
async def test_stop_cleanup_uses_task_fallback_to_join_live_start_before_lease_release(
    tmp_path: Path,
) -> None:
    lock_path = _owner_only_lock_path(tmp_path)
    lease = CoreProcessLease.acquire(lock_path)
    reconciler = _BlockingInitialDrainReconciler()
    recovery = StartupTurnRecovery(
        _PassingReachySafety(),
        reconciler,
        _NoopUnitOfWorkFactory(),
        _NoopClock(),
        lease,
    )
    supervisor = BudgetReconciliationSupervisor(reconciler, recovery)
    loop = asyncio.get_running_loop()
    previous_factory = loop.get_task_factory()
    rejecting_factory = _RejectingTaskFactory()
    loop.set_task_factory(rejecting_factory)
    start_task = _loop_bound_task(supervisor.start(), name="rejecting-factory-live-start")
    stop_task: asyncio.Task[Any] | None = None
    try:
        await _wait_for_event(reconciler.initial_drain_started)
        stop_task = _loop_bound_task(supervisor.stop(), name="rejecting-factory-stop-start")
        await asyncio.sleep(0)

        stop_done_early = stop_task.done()
        lease_released_early = _lease_is_reacquirable(lock_path)
        if not stop_done_early:
            await _wait_for_event(reconciler.initial_drain_cancelled)

        reconciler.release_initial_drain.set()
        stop_error: BaseException | None = None
        try:
            async with asyncio.timeout(0.5):
                await stop_task
        except BaseException as error:
            stop_error = error
        start_error: BaseException | None = None
        try:
            async with asyncio.timeout(0.5):
                await start_task
        except BaseException as error:
            start_error = error
        loop.set_task_factory(previous_factory)
        lease_released = _lease_is_reacquirable(lock_path)
        lease.release_after_shutdown()

        assert not stop_done_early
        assert not lease_released_early
        assert reconciler.initial_drain_cancelled.is_set()
        assert stop_error is None
        assert isinstance(start_error, asyncio.CancelledError)
        assert rejecting_factory.calls >= 3
        assert lease_released
    finally:
        reconciler.release_initial_drain.set()
        loop.set_task_factory(previous_factory)
        if stop_task is not None and not stop_task.done():
            stop_task.cancel()
            with suppress(BaseException):
                await stop_task
        if not start_task.done():
            start_task.cancel()
        with suppress(BaseException):
            await start_task
        lease.release_after_shutdown()


@pytest.mark.asyncio
async def test_stop_cleanup_uses_task_fallback_to_join_live_worker_before_lease_release(
    tmp_path: Path,
) -> None:
    lock_path = _owner_only_lock_path(tmp_path)
    lease = CoreProcessLease.acquire(lock_path)
    reconciler = _BlockingWorkerReconciler()
    recovery = StartupTurnRecovery(
        _PassingReachySafety(),
        reconciler,
        _NoopUnitOfWorkFactory(),
        _NoopClock(),
        lease,
    )
    supervisor = BudgetReconciliationSupervisor(reconciler, recovery)
    loop = asyncio.get_running_loop()
    previous_factory = loop.get_task_factory()
    rejecting_factory = _RejectingTaskFactory()
    loop.set_task_factory(rejecting_factory)
    stop_task: asyncio.Task[Any] | None = None
    try:
        await supervisor.start()
        await _wait_for_event(reconciler.worker_started)
        stop_task = _loop_bound_task(supervisor.stop(), name="rejecting-factory-stop-worker")
        await asyncio.sleep(0)

        stop_done_early = stop_task.done()
        worker_finished_early = reconciler.worker_finished.is_set()
        lease_released_early = _lease_is_reacquirable(lock_path)

        reconciler.release_worker.set()
        stop_error: BaseException | None = None
        try:
            async with asyncio.timeout(0.5):
                await stop_task
        except BaseException as error:
            stop_error = error
        loop.set_task_factory(previous_factory)
        lease_released = _lease_is_reacquirable(lock_path)
        lease.release_after_shutdown()

        assert not stop_done_early
        assert not worker_finished_early
        assert not lease_released_early
        assert stop_error is None
        assert reconciler.worker_finished.is_set()
        assert rejecting_factory.calls >= 3
        assert lease_released
    finally:
        reconciler.release_worker.set()
        loop.set_task_factory(previous_factory)
        if stop_task is not None and not stop_task.done():
            stop_task.cancel()
            with suppress(BaseException):
                await stop_task
        with suppress(BaseException):
            await supervisor.stop()
        lease.release_after_shutdown()


@pytest.mark.asyncio
async def test_cleanup_task_construction_failure_fails_closed_without_coroutine_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock_path = _owner_only_lock_path(tmp_path)
    lease = CoreProcessLease.acquire(lock_path)
    reconciler = _SupervisorReconciler()
    recovery = StartupTurnRecovery(
        _PassingReachySafety(),
        reconciler,
        _NoopUnitOfWorkFactory(),
        _NoopClock(),
        lease,
        retry_limit=0,
    )
    supervisor = BudgetReconciliationSupervisor(reconciler, recovery)
    loop = asyncio.get_running_loop()
    previous_factory = loop.get_task_factory()
    rejecting_factory = _RejectingTaskFactory()
    original_task_type = asyncio.Task

    class _RejectingLoopBoundTask:
        @classmethod
        def __class_getitem__(cls, item: object) -> object:
            return original_task_type[item]

        def __new__(
            cls,
            coroutine: Coroutine[Any, Any, Any],
            *args: Any,
            **kwargs: Any,
        ) -> asyncio.Task[Any]:
            del coroutine, args, kwargs
            raise RuntimeError("synthetic_task_constructor_rejected")

    loop.set_task_factory(rejecting_factory)
    monkeypatch.setattr(asyncio, "Task", _RejectingLoopBoundTask)
    try:
        caught: BaseException | None = None
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always", RuntimeWarning)
            try:
                await supervisor.start()
            except BaseException as error:
                caught = error
            gc.collect()
        loop.set_task_factory(previous_factory)
        monkeypatch.undo()

        assert isinstance(caught, RuntimeError)
        assert "synthetic_task_constructor_rejected" in str(caught)
        assert not any("was never awaited" in str(item.message) for item in captured)
        with pytest.raises(RuntimeError, match="budget_reconciliation_unhealthy"):
            supervisor.require_ready()
        with pytest.raises(RuntimeError, match="startup_turn_recovery_unhealthy"):
            recovery.require_ready()
        assert not _lease_is_reacquirable(lock_path)
    finally:
        loop.set_task_factory(previous_factory)
        monkeypatch.undo()
        lease.release_after_shutdown()


@pytest.mark.asyncio
async def test_stop_joins_live_initial_drain_before_releasing_process_lease(
    production_provider_gateway_case,
    tmp_path: Path,
) -> None:
    case = await production_provider_gateway_case(seed_response_scope=True)
    lock_path = _owner_only_lock_path(tmp_path)
    lease = CoreProcessLease.acquire(lock_path)
    reconciler = _BlockingInitialDrainReconciler()
    recovery = StartupTurnRecovery(
        _PassingReachySafety(),
        reconciler,
        case.factory,
        case.clock,
        lease,
    )
    supervisor = BudgetReconciliationSupervisor(reconciler, recovery)
    start_task = asyncio.create_task(supervisor.start())
    stop_tasks: list[asyncio.Task[None]] = []
    try:
        await _wait_for_event(reconciler.initial_drain_started)
        stop_tasks = [
            asyncio.create_task(supervisor.stop()),
            asyncio.create_task(supervisor.stop()),
        ]
        await asyncio.sleep(0)

        assert not _lease_is_reacquirable(lock_path)
        await _wait_for_event(reconciler.initial_drain_cancelled)
        assert not any(task.done() for task in stop_tasks)
        assert not _lease_is_reacquirable(lock_path)

        reconciler.release_initial_drain.set()
        await asyncio.wait_for(asyncio.gather(*stop_tasks), timeout=0.5)
        assert start_task.done()
        with pytest.raises(asyncio.CancelledError):
            await start_task
        assert reconciler.initial_drain_finished.is_set()
        _assert_lease_released(lock_path)
    finally:
        reconciler.release_initial_drain.set()
        for task in stop_tasks:
            if not task.done():
                task.cancel()
        with suppress(BaseException):
            await asyncio.gather(*stop_tasks)
        if not start_task.done():
            start_task.cancel()
        with suppress(BaseException):
            await start_task
        lease.release_after_shutdown()


@pytest.mark.asyncio
async def test_stop_joins_live_startup_recovery_before_releasing_process_lease(
    production_provider_gateway_case,
    tmp_path: Path,
) -> None:
    case = await production_provider_gateway_case(seed_response_scope=True)
    lock_path = _owner_only_lock_path(tmp_path)
    lease = CoreProcessLease.acquire(lock_path)
    reachy = _CancellationObservingReachySafety(block_cancel_finish=True)
    reconciler = _SupervisorReconciler()
    recovery = StartupTurnRecovery(
        reachy,
        reconciler,
        case.factory,
        case.clock,
        lease,
        attempt_timeout=0.5,
    )
    supervisor = BudgetReconciliationSupervisor(reconciler, recovery)
    start_task = asyncio.create_task(supervisor.start())
    stop_task: asyncio.Task[None] | None = None
    try:
        await _wait_for_event(reachy.started)
        stop_task = asyncio.create_task(supervisor.stop())
        await _wait_for_event(reachy.cancelled)

        assert not _lease_is_reacquirable(lock_path)
        assert not stop_task.done()

        reachy.release.set()
        await asyncio.wait_for(stop_task, timeout=0.5)
        assert start_task.done()
        with pytest.raises(asyncio.CancelledError):
            await start_task
        assert reachy.finished.is_set()
        _assert_lease_released(lock_path)
    finally:
        reachy.release.set()
        if stop_task is not None and not stop_task.done():
            stop_task.cancel()
            with suppress(BaseException):
                await stop_task
        if not start_task.done():
            start_task.cancel()
        with suppress(BaseException):
            await start_task
        lease.release_after_shutdown()


@pytest.mark.asyncio
async def test_cancelled_stop_joins_live_initial_drain_before_releasing_process_lease(
    production_provider_gateway_case,
    tmp_path: Path,
) -> None:
    case = await production_provider_gateway_case(seed_response_scope=True)
    lock_path = _owner_only_lock_path(tmp_path)
    lease = CoreProcessLease.acquire(lock_path)
    reconciler = _BlockingInitialDrainReconciler()
    recovery = StartupTurnRecovery(
        _PassingReachySafety(),
        reconciler,
        case.factory,
        case.clock,
        lease,
    )
    supervisor = BudgetReconciliationSupervisor(reconciler, recovery)
    start_task = asyncio.create_task(supervisor.start())
    stop_task: asyncio.Task[None] | None = None
    try:
        await _wait_for_event(reconciler.initial_drain_started)
        stop_task = asyncio.create_task(supervisor.stop())
        await _wait_for_event(reconciler.initial_drain_cancelled)

        stop_task.cancel()
        await asyncio.sleep(0)

        assert not stop_task.done()
        assert not start_task.done()
        assert not _lease_is_reacquirable(lock_path)

        reconciler.release_initial_drain.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(stop_task, timeout=0.5)
        assert start_task.done()
        with pytest.raises(asyncio.CancelledError):
            await start_task
        assert reconciler.initial_drain_finished.is_set()
        _assert_lease_released(lock_path)
    finally:
        reconciler.release_initial_drain.set()
        if stop_task is not None and not stop_task.done():
            stop_task.cancel()
            with suppress(BaseException):
                await stop_task
        if not start_task.done():
            start_task.cancel()
        with suppress(BaseException):
            await start_task
        lease.release_after_shutdown()


@pytest.mark.asyncio
async def test_cancelled_stop_waits_for_live_worker_before_releasing_process_lease(
    production_provider_gateway_case,
    tmp_path: Path,
) -> None:
    case = await production_provider_gateway_case(seed_response_scope=True)
    lock_path = _owner_only_lock_path(tmp_path)
    lease = CoreProcessLease.acquire(lock_path)
    reconciler = _BlockingWorkerReconciler()
    recovery = StartupTurnRecovery(
        _PassingReachySafety(),
        reconciler,
        case.factory,
        case.clock,
        lease,
    )
    supervisor = BudgetReconciliationSupervisor(reconciler, recovery)
    stop_task: asyncio.Task[None] | None = None
    try:
        await supervisor.start()
        await _wait_for_event(reconciler.worker_started)
        stop_task = asyncio.create_task(supervisor.stop())
        await asyncio.sleep(0)
        assert not stop_task.done()

        stop_task.cancel()
        await asyncio.sleep(0)

        assert not stop_task.done()
        assert not reconciler.worker_finished.is_set()
        assert not _lease_is_reacquirable(lock_path)

        reconciler.release_worker.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(stop_task, timeout=0.5)
        assert reconciler.worker_finished.is_set()
        _assert_lease_released(lock_path)
    finally:
        reconciler.release_worker.set()
        if stop_task is not None and not stop_task.done():
            stop_task.cancel()
            with suppress(BaseException):
                await stop_task
        with suppress(BaseException):
            await supervisor.stop()
        lease.release_after_shutdown()


@pytest.mark.asyncio
async def test_reentrant_stop_from_start_deflects_without_releasing_process_lease(
    production_provider_gateway_case,
    tmp_path: Path,
) -> None:
    case = await production_provider_gateway_case(seed_response_scope=True)
    lock_path = _owner_only_lock_path(tmp_path)
    lease = CoreProcessLease.acquire(lock_path)
    reconciler = _ReentrantStopDrainReconciler(lock_path)
    recovery = StartupTurnRecovery(
        _PassingReachySafety(),
        reconciler,
        case.factory,
        case.clock,
        lease,
    )
    supervisor = BudgetReconciliationSupervisor(reconciler, recovery)
    reconciler.supervisor = supervisor
    try:
        with pytest.raises(RuntimeError, match="budget_reconciliation_unhealthy"):
            await supervisor.start()

        assert reconciler.stop_error == "budget_reconciliation_stop_from_start_task"
        assert reconciler.lease_reacquirable_during_start is False
        assert not reconciler.worker_started.is_set()
        with pytest.raises(RuntimeError, match="budget_reconciliation_unhealthy"):
            supervisor.require_ready()
        _assert_lease_released(lock_path)
    finally:
        lease.release_after_shutdown()


@pytest.mark.asyncio
async def test_start_cancellation_observes_global_stop_before_releasing_process_lease(
    production_provider_gateway_case,
    tmp_path: Path,
) -> None:
    case = await production_provider_gateway_case(seed_response_scope=True)
    lock_path = _owner_only_lock_path(tmp_path)
    lease = CoreProcessLease.acquire(lock_path)
    reachy = _CancellationObservingReachySafety()
    reconciler = _SupervisorReconciler()
    recovery = StartupTurnRecovery(
        reachy,
        reconciler,
        case.factory,
        case.clock,
        lease,
        attempt_timeout=0.5,
    )
    supervisor = BudgetReconciliationSupervisor(reconciler, recovery)
    start_task = asyncio.create_task(supervisor.start())
    try:
        await _wait_for_event(reachy.started)
        start_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(start_task, timeout=0.5)

        await _wait_for_event(reachy.cancelled)
        assert reachy.finished.is_set()
        with pytest.raises(RuntimeError, match="budget_reconciliation_unhealthy"):
            supervisor.require_ready()
        with pytest.raises(RuntimeError, match="startup_turn_recovery_unhealthy"):
            recovery.require_ready()
        _assert_lease_released(lock_path)
    finally:
        reachy.release.set()
        if not start_task.done():
            start_task.cancel()
        with suppress(BaseException):
            await start_task
        lease.release_after_shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize("worker_fault", ("raise", "cancel"))
async def test_unexpected_periodic_worker_terminal_withdraws_readiness(
    production_provider_gateway_case,
    tmp_path: Path,
    worker_fault: str,
) -> None:
    case = await production_provider_gateway_case(seed_response_scope=True)
    lock_path = _owner_only_lock_path(tmp_path)
    lease = CoreProcessLease.acquire(lock_path)
    reconciler = _SupervisorReconciler(worker_fault=worker_fault)
    recovery = StartupTurnRecovery(
        _PassingReachySafety(),
        reconciler,
        case.factory,
        case.clock,
        lease,
    )
    supervisor = BudgetReconciliationSupervisor(reconciler, recovery)
    try:
        await supervisor.start()
        supervisor.require_ready()
        await _wait_for_event(reconciler.worker_started)
        if worker_fault == "raise":
            reconciler.fail_worker.set()
        else:
            worker = supervisor._worker
            assert worker is not None
            worker.cancel()
        await _wait_for_event(supervisor.worker_stopped)

        with pytest.raises(RuntimeError, match="budget_reconciliation_unhealthy"):
            supervisor.require_ready()
    finally:
        with suppress(BaseException):
            await supervisor.stop()


@pytest.mark.asyncio
async def test_supervisor_healthy_startup_and_stop_releases_process_lease(
    production_provider_gateway_case,
    tmp_path: Path,
) -> None:
    case = await production_provider_gateway_case(seed_response_scope=True)
    lock_path = _owner_only_lock_path(tmp_path)
    lease = CoreProcessLease.acquire(lock_path)
    reconciler = _SupervisorReconciler()
    recovery = StartupTurnRecovery(
        _PassingReachySafety(),
        reconciler,
        case.factory,
        case.clock,
        lease,
    )
    supervisor = BudgetReconciliationSupervisor(reconciler, recovery)
    try:
        await supervisor.start()
        supervisor.require_ready()
        await _wait_for_event(reconciler.worker_started)
        await supervisor.stop()

        with pytest.raises(RuntimeError, match="budget_reconciliation_unhealthy"):
            supervisor.require_ready()
        _assert_lease_released(lock_path)
    finally:
        lease.release_after_shutdown()


@pytest.mark.asyncio
async def test_production_lifecycle_reconciles_before_readiness(
    production_container,
) -> None:
    container = production_container
    try:
        await container.budget_lifecycle.start()
        container.budget_lifecycle.require_ready()
        async with container.core.sqlcipher_uow_factory() as uow:

            def recovered(transaction) -> tuple[int, tuple[str, str] | None]:
                open_count = transaction.exec_driver_sql(
                    "SELECT count(*) FROM budget_reservations WHERE state IN ('reserved','sent')",
                ).scalar_one()
                session = transaction.exec_driver_sql(
                    "SELECT state,closed_at FROM sessions WHERE id=?",
                    (str(container.context.route.session_id),),
                ).fetchone()
                return int(open_count), None if session is None else tuple(session)

            open_count, session = await uow.run_sync(recovered)
            await uow.rollback()
        assert open_count == 0
        assert session is not None
        assert session[0] == "cancelled" and session[1] is not None
        assert container.reachy.calls == [None]
        assert container.readiness_dependencies.count(container.budget_lifecycle) == 1
    finally:
        await container.budget_lifecycle.stop()


def test_production_container_has_one_supervised_reconciler(production_container) -> None:
    assert (
        production_container.budget_reconciler is production_container.budget_lifecycle.reconciler
    )
    assert (
        production_container.startup_turn_recovery
        is production_container.budget_lifecycle.startup_recovery
    )
    assert (
        production_container.startup_turn_recovery.process_lease
        is production_container.core_process_lease
    )
    assert (
        production_container.readiness_dependencies.count(production_container.budget_lifecycle)
        == 1
    )
