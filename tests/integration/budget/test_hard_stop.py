from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from tuntun_contracts.budget import BudgetReservationRequest, LlmUsageUnits
from tuntun_core.services.budget.guard import BudgetGuard

pytest_plugins = ("tests.fixtures.provider_egress",)


@pytest.mark.asyncio
async def test_fifty_concurrent_reservations_never_cross_hard_cap(
    async_uow_factory,
    route_clock,
    catalog,
    provider_reviews,
    budget_evidence,
) -> None:
    guard = BudgetGuard(
        async_uow_factory,
        route_clock,
        catalog,
        provider_reviews,
        budget_evidence,
        hard_limit=150_000_000,
    )
    household_id, turn_id = uuid4(), uuid4()

    async def reserve(index: int):
        del index
        return await guard.reserve(
            BudgetReservationRequest(
                household_id=household_id,
                turn_id=turn_id,
                request_id=uuid4(),
                attempt_id=uuid4(),
                provider="openai",
                model="gpt-5.6-sol",
                category="llm",
                usage_ceiling=LlmUsageUnits(
                    category="llm",
                    input_tokens=100_000,
                    output_tokens=100_000,
                ),
                month_key="2026-08",
            )
        )

    outcomes = await asyncio.gather(*(reserve(index) for index in range(50)))
    async with async_uow_factory() as uow:
        committed = await uow.run_sync(
            lambda db: db.exec_driver_sql(
                "SELECT COALESCE(sum(CASE WHEN state='settled' THEN charged_micros_sgd "
                "ELSE reserved_micros_sgd END),0) FROM budget_reservations "
                "WHERE state IN ('reserved','sent','settled')",
            ).fetchone()[0]
        )
        await uow.rollback()
    assert committed <= 150_000_000
    assert any(item.outcome == "deny_hard_limit" for item in outcomes)
