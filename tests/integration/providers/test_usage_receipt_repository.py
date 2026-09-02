from __future__ import annotations

import inspect
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from tuntun_contracts.budget import LlmUsageUnits
from tuntun_core.services.budget.evidence import BudgetEvidenceQuarantined, BudgetEvidenceService
from tuntun_core.services.providers.gateway import ProviderUsageUnknownError
from tuntun_testing.fake_clock import FakeClock

pytest_plugins = ("tests.fixtures.provider_egress",)


@pytest.mark.asyncio
async def test_production_gateway_persists_exact_attested_receipt_before_return(
    production_provider_gateway_case,
) -> None:
    case = await production_provider_gateway_case(valid_usage=True)
    result = await case.invoke()
    assert result.provider_usage_receipt_id is not None
    assert case.events.index("usage_receipt_committed") < case.events.index(
        "gateway_result_returned"
    )
    row = await case.provider_call_row()
    assert row.outcome == "succeeded" and row.transport_phase == "finished"
    assert row.provider_usage_json == case.evidence.canonical_receipt(
        case.receipt(result.provider_usage_receipt_id)
    )
    assert row.provider_usage_receipt_key_id == case.receipt_commitment.key_id
    assert row.provider_usage_receipt_hmac_b64 == case.receipt_commitment.value_b64
    restarted = await case.restart_budget_guard()
    settlement = await restarted.settle(case.settlement_request)
    assert settlement.charged_micros_sgd == case.exact_snapshot_price
    assert settlement.conservative_estimate_used is False


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ("snapshot", "hmac", "policy"))
async def test_pricing_evidence_tamper_blocks_before_network(
    production_provider_gateway_case,
    fault,
) -> None:
    case = await production_provider_gateway_case(valid_usage=True)
    await case.tamper_pricing_evidence(fault)
    with pytest.raises(BudgetEvidenceQuarantined, match="budget_pricing_snapshot_invalid"):
        await case.invoke()
    assert "network_invoked" not in case.events
    assert await case.ledger_count() == 0


@pytest.mark.asyncio
async def test_zero_reported_usage_is_unknown_and_never_persisted_as_exact(
    production_provider_gateway_case,
) -> None:
    case = await production_provider_gateway_case(
        reported_usage=LlmUsageUnits(category="llm", input_tokens=0, output_tokens=0),
    )
    with pytest.raises(ProviderUsageUnknownError, match="unknown_overage"):
        await case.invoke()
    row = await case.provider_call_row()
    assert row.outcome == "succeeded" and row.transport_phase == "finished"
    assert row.provider_usage_json is None
    assert row.provider_usage_receipt_key_id is None
    assert row.provider_usage_receipt_hmac_b64 is None
    await case.assert_unknown_overage_freezes_without_ledger()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault", ("receipt_json", "outer_key", "outer_hmac", "attempt", "provider", "model")
)
async def test_receipt_substitution_or_partial_persistence_rolls_back_and_freezes(
    production_provider_gateway_case,
    fault,
) -> None:
    case = await production_provider_gateway_case(valid_usage=True)
    await case.invoke()
    before = await case.proof_rows()
    await case.tamper_receipt(fault)
    with pytest.raises(PermissionError, match="unknown_overage"):
        await case.settle()
    assert await case.proof_rows() == before
    assert case.cloud_egress_frozen and not case.freeze_receipt.overage_known


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "identifier",
    (
        None,
        b"raw",
        "",
        "x" * 257,
        "bad\nvalue",
        "bad\u0085value",
        "bad\u202evalue",
        "e\u0301",
        "\ud800",
    ),
)
async def test_hostile_provider_response_identifier_never_reaches_receipt(
    production_provider_gateway_case,
    identifier,
) -> None:
    case = await production_provider_gateway_case(
        valid_usage=True,
        provider_response_identifier=identifier,
    )
    with pytest.raises(ProviderUsageUnknownError, match="unknown_overage"):
        await case.invoke()
    row = await case.provider_call_row()
    assert row.outcome == "succeeded" and row.transport_phase == "finished"
    assert (
        row.provider_usage_json,
        row.provider_usage_receipt_key_id,
        row.provider_usage_receipt_hmac_b64,
    ) == (None, None, None)
    with pytest.raises(PermissionError, match="unknown_overage"):
        await case.settle()
    assert case.cloud_egress_frozen and not case.freeze_receipt.overage_known


def test_attestation_timestamp_is_internal() -> None:
    assert (
        "observed_at"
        not in inspect.signature(
            BudgetEvidenceService.attest_provider_usage,
        ).parameters
    )


def test_non_utc_clock_attestation_verifies_and_serializes_as_canonical_utc(route) -> None:
    evidence = BudgetEvidenceService(
        b"e" * 32,
        "budget-evidence-v1",
        FakeClock(datetime(2026, 8, 27, 0, 0, tzinfo=timezone(timedelta(hours=8)))),
    )
    receipt = evidence.attest_provider_usage(
        call_id=uuid4(),
        route=route,
        category="llm",
        accounting_basis="provider_reported_exact",
        billable_usage=LlmUsageUnits(category="llm", input_tokens=1, output_tokens=1),
        provider_response_identifier="resp_non_utc",
    )
    canonical = evidence.require_attested_receipt(receipt)
    assert '"observed_at":"2026-08-26T16:00:00.000000Z"' in canonical
    assert evidence.canonical_receipt(receipt) == canonical
