from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from pydantic import ValidationError
from tuntun_contracts.budget import (
    BudgetReconciliationRequest,
    BudgetSettlementRequest,
    LlmUsageUnits,
    TransportProof,
)
from tuntun_core.services.providers.gateway import ProviderUsageUnknownError

pytest_plugins = ("tests.fixtures.provider_egress",)


def _transport_proof(case, disposition: str, **overrides) -> TransportProof:
    return TransportProof(
        reservation_id=overrides.get("reservation_id", case.route.budget_reservation_id),
        attempt_id=overrides.get("attempt_id", case.route.attempt_id),
        disposition=disposition,
        observed_at=case.clock.now(),
        evidence_code=overrides.get("evidence_code", "synthetic_turn_reconciliation"),
    )


async def _duplicate_reconcile_results(guard, request):
    original_release = guard._release_proven_unsent
    release_arrivals = 0
    release_both = asyncio.Event()

    async def gated_release(reservation_id, attempt_id):
        nonlocal release_arrivals
        release_arrivals += 1
        if release_arrivals == 2:
            release_both.set()
        await asyncio.wait_for(release_both.wait(), timeout=1)
        return await original_release(reservation_id, attempt_id)

    guard._release_proven_unsent = gated_release
    try:
        return await asyncio.gather(
            guard.reconcile_turn(request),
            guard.reconcile_turn(request),
            return_exceptions=True,
        )
    finally:
        guard._release_proven_unsent = original_release


@pytest.mark.asyncio
@pytest.mark.parametrize("claimed", (False, True))
async def test_proven_unsent_shapes_cannot_settle_and_reconcile_releases_without_ledger(
    production_provider_gateway_case,
    claimed,
) -> None:
    case = await production_provider_gateway_case(valid_usage=True)
    if claimed:
        await case.begin_claim()
    before = await case.proof_rows()
    with pytest.raises(PermissionError, match="proven_unsent_requires_release"):
        await case.settle()
    assert await case.proof_rows() == before
    settlements = await case.budget_guard.reconcile_turn(
        BudgetReconciliationRequest(turn_id=case.route.turn_id, proofs=())
    )
    assert settlements == ()
    reservation, call, ledger_count = await case.proof_rows()
    assert reservation[:2] == ("released", "finished")
    assert ledger_count == 0
    if claimed:
        assert call[:2] == ("cancelled", "finished")
    else:
        assert call is None


@pytest.mark.asyncio
@pytest.mark.parametrize("claimed", (False, True))
async def test_unknown_proof_releases_durable_proven_unsent_attempts_without_ledger(
    production_provider_gateway_case,
    claimed,
) -> None:
    case = await production_provider_gateway_case(valid_usage=True)
    if claimed:
        await case.begin_claim()
    proof = _transport_proof(case, "unknown")

    settlements = await case.budget_guard.reconcile_turn(
        BudgetReconciliationRequest(turn_id=case.route.turn_id, proofs=(proof,))
    )

    assert settlements == ()
    reservation, call, ledger_count = await case.proof_rows()
    assert reservation[:2] == ("released", "finished")
    assert ledger_count == 0
    if claimed:
        assert call[:2] == ("cancelled", "finished")
    else:
        assert call is None


@pytest.mark.asyncio
@pytest.mark.parametrize("sent_phase", ("marked_sent", "network_invocation_starting"))
async def test_stale_never_sent_proof_for_durable_sent_attempt_settles_once(
    production_provider_gateway_case,
    sent_phase,
) -> None:
    case = await production_provider_gateway_case()
    if sent_phase == "marked_sent":
        await case.mark_sent()
    else:
        await case.mark_network_invocation_starting()
    proof = _transport_proof(case, "never_sent")

    settlements = await case.budget_guard.reconcile_turn(
        BudgetReconciliationRequest(turn_id=case.route.turn_id, proofs=(proof,))
    )

    assert len(settlements) == 1
    settlement = settlements[0]
    assert settlement.charged_micros_sgd == case.exact_snapshot_price
    assert settlement.conservative_estimate_used is True
    assert settlement.estimate_overrun is False
    assert settlement.cloud_egress_frozen is False
    reservation, call, ledger_count = await case.proof_rows()
    assert reservation[:2] == ("settled", "finished")
    assert call == ("ambiguous", "finished", 1)
    assert ledger_count == 1

    assert (
        await case.budget_guard.reconcile_turn(
            BudgetReconciliationRequest(turn_id=case.route.turn_id, proofs=(proof,))
        )
        == ()
    )
    assert await case.ledger_count() == 1


@pytest.mark.asyncio
async def test_reconcile_turn_rejects_forged_proof_before_state_classification(
    production_provider_gateway_case,
) -> None:
    case = await production_provider_gateway_case(valid_usage=True)
    proof = _transport_proof(case, "unknown", reservation_id=uuid4())
    before = await case.proof_rows()

    with pytest.raises(PermissionError, match="reservation_turn_mismatch"):
        await case.budget_guard.reconcile_turn(
            BudgetReconciliationRequest(turn_id=case.route.turn_id, proofs=(proof,))
        )

    assert await case.proof_rows() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("claimed", (False, True))
async def test_duplicate_reconcile_releases_proven_unsent_once_without_errors(
    production_provider_gateway_case,
    claimed,
) -> None:
    case = await production_provider_gateway_case(valid_usage=True)
    if claimed:
        await case.begin_claim()
    request = BudgetReconciliationRequest(turn_id=case.route.turn_id, proofs=())

    results = await _duplicate_reconcile_results(case.budget_guard, request)

    errors = [result for result in results if isinstance(result, BaseException)]
    assert errors == []
    assert results == [(), ()]
    reservation, call, ledger_count = await case.proof_rows()
    assert reservation[:2] == ("released", "finished")
    assert ledger_count == 0
    if claimed:
        assert call[:2] == ("cancelled", "finished")
    else:
        assert call is None


@pytest.mark.asyncio
@pytest.mark.parametrize("sent_phase", ("marked_sent", "network_invocation_starting"))
async def test_duplicate_reconcile_settles_sent_attempt_once_without_errors(
    production_provider_gateway_case,
    sent_phase,
) -> None:
    case = await production_provider_gateway_case()
    if sent_phase == "marked_sent":
        await case.mark_sent()
    else:
        await case.mark_network_invocation_starting()
    request = BudgetReconciliationRequest(turn_id=case.route.turn_id, proofs=())

    results = await _duplicate_reconcile_results(case.budget_guard, request)

    errors = [result for result in results if isinstance(result, BaseException)]
    assert errors == []
    assert sum(len(result) for result in results) == 1
    reservation, call, ledger_count = await case.proof_rows()
    assert reservation[:2] == ("settled", "finished")
    assert call == ("ambiguous", "finished", 1)
    assert ledger_count == 1


def test_settlement_contract_has_no_caller_actual_amount() -> None:
    for legacy in (
        {"actual_micros_sgd": 0, "provider_usage_present": True},
        {"actual_micros_sgd": 1, "provider_usage_present": True},
        {"actual_micros_sgd": 10**30, "provider_usage_present": True},
    ):
        with pytest.raises(ValidationError):
            BudgetSettlementRequest(reservation_id=uuid4(), attempt_id=uuid4(), **legacy)


@pytest.mark.asyncio
async def test_successful_exact_usage_is_computed_server_side_and_never_clipped(
    production_provider_gateway_case,
) -> None:
    case = await production_provider_gateway_case(
        usage_ceiling=LlmUsageUnits(category="llm", input_tokens=1, output_tokens=0),
        reported_usage=LlmUsageUnits(category="llm", input_tokens=2, output_tokens=0),
    )
    await case.invoke()
    result = await case.settle()
    ledger = await case.ledger_row()
    assert result.charged_micros_sgd > case.exact_snapshot_price
    assert result.conservative_estimate_used is False
    assert result.estimate_overrun is True
    assert result.cloud_egress_frozen is True
    assert ledger.charged_micros_sgd == result.charged_micros_sgd
    assert ledger.conservative_estimate_used == 0
    assert case.freeze_receipt.reason_code == "estimate_overrun"
    assert await case.owner_alert_count() == 1


@pytest.mark.asyncio
async def test_successful_exact_settlement_uses_verified_actual_below_reserve(
    production_provider_gateway_case,
) -> None:
    case = await production_provider_gateway_case(
        usage_ceiling=LlmUsageUnits(category="llm", input_tokens=2, output_tokens=0),
        reported_usage=LlmUsageUnits(category="llm", input_tokens=1, output_tokens=0),
    )
    await case.invoke()
    result = await case.settle()
    assert result.conservative_estimate_used is False
    assert result.charged_micros_sgd < case.exact_snapshot_price


@pytest.mark.asyncio
async def test_silent_ignored_ledger_insert_rolls_back_terminalization(
    production_provider_gateway_case,
) -> None:
    case = await production_provider_gateway_case(valid_usage=True)
    await case.invoke()
    before = await case.proof_rows()
    trigger = await case.install_ledger_ignore_trigger()
    try:
        with pytest.raises(PermissionError, match="budget_ledger_insert_failed"):
            await case.settle()
    finally:
        await case.drop_trigger(trigger)
    assert await case.proof_rows() == before
    await case.settle()
    assert await case.ledger_count() == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("marker", "error"),
    (
        ("freeze", "budget_cloud_egress_freeze_insert_failed"),
        ("owner_alert", "budget_owner_alert_insert_failed"),
    ),
)
async def test_silent_ignored_estimate_overrun_marker_rolls_back_settlement(
    production_provider_gateway_case,
    marker,
    error,
) -> None:
    case = await production_provider_gateway_case(
        usage_ceiling=LlmUsageUnits(category="llm", input_tokens=1, output_tokens=0),
        reported_usage=LlmUsageUnits(category="llm", input_tokens=2, output_tokens=0),
    )
    await case.invoke()
    before = await case.proof_rows()
    trigger = await case.install_budget_marker_ignore_trigger(marker)
    try:
        with pytest.raises(PermissionError, match=error):
            await case.settle()
    finally:
        await case.drop_trigger(trigger)
    assert await case.proof_rows() == before
    assert await case.budget_marker_counts() == (0, 0)
    assert case.cloud_egress_frozen is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("marker", "error"),
    (
        ("freeze", "budget_cloud_egress_freeze_insert_failed"),
        ("owner_alert", "budget_owner_alert_insert_failed"),
    ),
)
async def test_silent_ignored_unknown_overage_marker_fails_without_freezing(
    production_provider_gateway_case,
    marker,
    error,
) -> None:
    case = await production_provider_gateway_case(valid_usage=False)
    with pytest.raises(ProviderUsageUnknownError):
        await case.invoke()
    before = await case.proof_rows()
    trigger = await case.install_budget_marker_ignore_trigger(marker)
    try:
        with pytest.raises(PermissionError, match=error):
            await case.settle()
    finally:
        await case.drop_trigger(trigger)
    assert await case.proof_rows() == before
    assert await case.budget_marker_counts() == (0, 0)
    assert case.cloud_egress_frozen is False


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_outcome", ("failed", "cancelled", "ambiguous"))
async def test_non_success_terminal_call_has_no_usage_receipt_and_charges_reserve(
    production_provider_gateway_case,
    provider_outcome,
) -> None:
    case = await production_provider_gateway_case(
        usage_ceiling=LlmUsageUnits(category="llm", input_tokens=2, output_tokens=0),
    )
    await case.mark_network_invocation_starting()
    await case.finish(provider_outcome)
    result = await case.settle()
    ledger = await case.ledger_row()
    assert result.conservative_estimate_used is True
    assert result.charged_micros_sgd == case.exact_snapshot_price
    assert ledger.usage_json == "null"
    assert ledger.provider_usage_receipt_json is None


@pytest.mark.asyncio
async def test_substituted_pricing_digest_rolls_back_and_freezes(
    production_provider_gateway_case,
) -> None:
    case = await production_provider_gateway_case(valid_usage=True)
    await case.invoke()
    await case.tamper_pricing_source_digest()
    before = await case.proof_rows()
    with pytest.raises(PermissionError, match="budget_pricing_snapshot_invalid"):
        await case.settle()
    assert await case.proof_rows() == before
    assert case.freeze_receipt.overage_known is False
    assert await case.owner_alert_count() == 1


@pytest.mark.asyncio
async def test_success_with_missing_usage_freezes_unknown_overage(
    production_provider_gateway_case,
) -> None:
    case = await production_provider_gateway_case(valid_usage=False)
    with pytest.raises(ProviderUsageUnknownError):
        await case.invoke()
    before = await case.proof_rows()
    with pytest.raises(PermissionError, match="unknown_overage"):
        await case.settle()
    assert await case.proof_rows() == before
    assert case.freeze_receipt.overage_known is False
    assert await case.ledger_count() == 0
    assert await case.owner_alert_count() == 1


@pytest.mark.asyncio
async def test_catalog_removal_after_reserve_uses_immutable_signed_snapshot(
    production_provider_gateway_case,
) -> None:
    case = await production_provider_gateway_case(valid_usage=True)
    await case.invoke()
    reservation = await case.reservation_row()
    await case.drop_live_catalog_after_reserve()
    result = await case.settle()
    ledger = await case.ledger_row()
    assert ledger.charged_micros_sgd == result.charged_micros_sgd
    assert ledger.pricing_version == reservation.pricing_version
    assert ledger.fx_version == reservation.fx_version


@pytest.mark.asyncio
async def test_actual_charge_crossing_hard_cap_is_truthful_and_atomically_freezes(
    production_provider_gateway_case,
) -> None:
    case = await production_provider_gateway_case(
        usage_ceiling=LlmUsageUnits(category="llm", input_tokens=1, output_tokens=0),
        reported_usage=LlmUsageUnits(category="llm", input_tokens=2, output_tokens=0),
        hard_limit=10,
    )
    await case.invoke()
    result = await case.settle()
    ledger = await case.ledger_row()
    assert case.exact_snapshot_price < 10 < result.charged_micros_sgd
    assert result.cloud_egress_frozen is True
    assert case.freeze_receipt.reason_code == "hard_cap_actual_exceeded"
    assert ledger.hard_cap_exceeded == 1
