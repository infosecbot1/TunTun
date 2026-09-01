from __future__ import annotations

import asyncio

import pytest
from tuntun_contracts.budget import BudgetReconciliationRequest, LlmUsageUnits, TransportProof
from tuntun_core.services.budget.reconciler import ExpiredBudgetReconciler

pytest_plugins = ("tests.fixtures.provider_egress",)


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
