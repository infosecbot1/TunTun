from __future__ import annotations

import asyncio
from contextlib import suppress
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
async def test_periodic_reconciler_uses_clockport_without_wait_extension(
    production_provider_gateway_case,
) -> None:
    case = await production_provider_gateway_case()
    reconciler = ExpiredBudgetReconciler(
        case.factory,
        case.clock,
        case.budget_guard,
        interval_seconds=0.001,
    )
    stop = asyncio.Event()
    worker = asyncio.create_task(reconciler.run_periodically(stop))
    await asyncio.sleep(0.005)
    stop.set()
    await asyncio.wait_for(worker, timeout=0.1)


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
        await asyncio.wait_for(reachy.started.wait(), timeout=0.1)
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
        await asyncio.wait_for(reconciler.initial_drain_started.wait(), timeout=0.1)
        stop_tasks = [
            asyncio.create_task(supervisor.stop()),
            asyncio.create_task(supervisor.stop()),
        ]
        await asyncio.sleep(0)

        assert not _lease_is_reacquirable(lock_path)
        await asyncio.wait_for(reconciler.initial_drain_cancelled.wait(), timeout=0.1)
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
        await asyncio.wait_for(reachy.started.wait(), timeout=0.1)
        stop_task = asyncio.create_task(supervisor.stop())
        await asyncio.wait_for(reachy.cancelled.wait(), timeout=0.1)

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
        await asyncio.wait_for(reconciler.initial_drain_started.wait(), timeout=0.1)
        stop_task = asyncio.create_task(supervisor.stop())
        await asyncio.wait_for(reconciler.initial_drain_cancelled.wait(), timeout=0.1)

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
        await asyncio.wait_for(reconciler.worker_started.wait(), timeout=0.1)
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
        await asyncio.wait_for(reachy.started.wait(), timeout=0.1)
        start_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(start_task, timeout=0.5)

        await asyncio.wait_for(reachy.cancelled.wait(), timeout=0.1)
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
        await asyncio.wait_for(reconciler.worker_started.wait(), timeout=0.1)
        if worker_fault == "raise":
            reconciler.fail_worker.set()
        else:
            worker = supervisor._worker
            assert worker is not None
            worker.cancel()
        await asyncio.wait_for(supervisor.worker_stopped.wait(), timeout=0.1)

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
        await asyncio.wait_for(reconciler.worker_started.wait(), timeout=0.1)
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
