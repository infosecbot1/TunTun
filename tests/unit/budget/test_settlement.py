from __future__ import annotations

from uuid import uuid4

import pytest
from pydantic import ValidationError
from tuntun_contracts.budget import (
    BudgetReconciliationRequest,
    BudgetSettlementRequest,
    LlmUsageUnits,
)
from tuntun_core.services.providers.gateway import ProviderUsageUnknownError

pytest_plugins = ("tests.fixtures.provider_egress",)


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
