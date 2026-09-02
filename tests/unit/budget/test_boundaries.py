from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError
from tuntun_contracts.budget import (
    BudgetReservationRequest,
    LlmUsageUnits,
    SttUsageUnits,
    TransportProof,
    WebSearchUsageUnits,
)
from tuntun_core.services.budget.guard import BudgetGuard
from tuntun_core.services.providers.call_repository import ProviderCallRepository
from tuntun_core.services.providers.review import (
    RuntimeProviderIdentity,
    SqlcipherCurrentProviderReviews,
)

pytest_plugins = ("tests.fixtures.provider_egress",)


@pytest.mark.asyncio
async def test_budget_guard_uses_configured_reservation_expiry_seconds(
    async_uow_factory,
    clock,
    catalog,
    provider_reviews,
    budget_evidence,
) -> None:
    guard = BudgetGuard(
        async_uow_factory,
        clock,
        catalog,
        provider_reviews,
        budget_evidence,
        hard_limit=150_000_000,
        reservation_expiry_seconds=45,
    )

    reservation = await guard.reserve(
        BudgetReservationRequest(
            household_id=uuid4(),
            turn_id=uuid4(),
            request_id=uuid4(),
            attempt_id=uuid4(),
            provider="openai",
            model="gpt-5.6-sol",
            category="llm",
            usage_ceiling=LlmUsageUnits(category="llm", input_tokens=1, output_tokens=0),
            month_key="2026-08",
        )
    )

    assert reservation.expires_at == clock.now() + timedelta(seconds=45)


@pytest.mark.parametrize("expiry_seconds", (0, 901, -1, True))
def test_budget_guard_rejects_unsafe_reservation_expiry_seconds(
    async_uow_factory,
    clock,
    catalog,
    provider_reviews,
    budget_evidence,
    expiry_seconds,
) -> None:
    with pytest.raises(ValueError, match="reservation_expiry_seconds"):
        BudgetGuard(
            async_uow_factory,
            clock,
            catalog,
            provider_reviews,
            budget_evidence,
            hard_limit=150_000_000,
            reservation_expiry_seconds=expiry_seconds,
        )


@pytest.mark.asyncio
async def test_exact_hard_cap_allowed_and_one_micro_above_denied(
    async_uow_factory,
    clock,
    catalog,
    provider_reviews,
    budget_evidence,
) -> None:
    guard = BudgetGuard(
        async_uow_factory,
        clock,
        catalog,
        provider_reviews,
        budget_evidence,
        hard_limit=150_000_000,
    )
    household_id, turn_id = uuid4(), uuid4()
    first = await guard.reserve(
        BudgetReservationRequest(
            household_id=household_id,
            turn_id=turn_id,
            request_id=uuid4(),
            attempt_id=uuid4(),
            provider="openai",
            model="gpt-5.6-sol",
            category="llm",
            usage_ceiling=LlmUsageUnits(category="llm", input_tokens=4, output_tokens=4_999_999),
            month_key="2026-08",
        )
    )
    second = await guard.reserve(
        BudgetReservationRequest(
            household_id=household_id,
            turn_id=turn_id,
            request_id=uuid4(),
            attempt_id=uuid4(),
            provider="openai",
            model="gpt-5.6-sol",
            category="llm",
            usage_ceiling=LlmUsageUnits(category="llm", input_tokens=1, output_tokens=0),
            month_key="2026-08",
        )
    )
    denied = await guard.reserve(
        BudgetReservationRequest(
            household_id=household_id,
            turn_id=turn_id,
            request_id=uuid4(),
            attempt_id=uuid4(),
            provider="openai",
            model="gpt-5.6-sol",
            category="llm",
            usage_ceiling=LlmUsageUnits(category="llm", input_tokens=1, output_tokens=0),
            month_key="2026-08",
        )
    )
    assert (first.amount_micros_sgd, second.amount_micros_sgd) == (149_999_994, 6)
    assert (first.outcome, second.outcome, denied.outcome) == (
        "allow_soft_warning",
        "allow",
        "deny_hard_limit",
    )


@pytest.mark.parametrize("supplied", (0, 1, -1, 10**30))
def test_caller_cannot_supply_or_understate_reservation_amount(supplied) -> None:
    with pytest.raises(ValidationError, match="worst_case_micros_sgd"):
        BudgetReservationRequest(
            household_id=uuid4(),
            turn_id=uuid4(),
            request_id=uuid4(),
            attempt_id=uuid4(),
            provider="openai",
            model="gpt-5.6-sol",
            category="llm",
            usage_ceiling=LlmUsageUnits(category="llm", input_tokens=1, output_tokens=0),
            month_key="2026-08",
            worst_case_micros_sgd=supplied,
        )


@pytest.mark.parametrize(
    "usage",
    (
        {"category": "llm", "input_tokens": 0, "output_tokens": 0},
        {"category": "llm", "input_tokens": -1, "output_tokens": 0},
        {"category": "llm", "input_tokens": 10_000_001, "output_tokens": 0},
    ),
)
def test_zero_negative_or_overflowed_usage_ceiling_is_rejected(usage) -> None:
    with pytest.raises(ValidationError):
        BudgetReservationRequest(
            household_id=uuid4(),
            turn_id=uuid4(),
            request_id=uuid4(),
            attempt_id=uuid4(),
            provider="openai",
            model="gpt-5.6-sol",
            category="llm",
            usage_ceiling=usage,
            month_key="2026-08",
        )


@pytest.mark.asyncio
async def test_missing_real_provider_review_denies_without_reservation_insert(
    async_uow_factory,
    clock,
    catalog,
    budget_evidence,
) -> None:
    class RuntimeIdentities:
        def require_current(self, provider: str) -> RuntimeProviderIdentity:
            assert provider == "openai"
            return RuntimeProviderIdentity(
                project_id_commitment_sha256="a" * 64,
                credential_kind="project_service_account",
                admin_key_present=False,
            )

    guard = BudgetGuard(
        async_uow_factory,
        clock,
        catalog,
        SqlcipherCurrentProviderReviews(RuntimeIdentities()),
        budget_evidence,
        hard_limit=150_000_000,
    )
    request = BudgetReservationRequest(
        household_id=uuid4(),
        turn_id=uuid4(),
        request_id=uuid4(),
        attempt_id=uuid4(),
        provider="openai",
        model="gpt-5.6-sol",
        category="llm",
        usage_ceiling=LlmUsageUnits(category="llm", input_tokens=1, output_tokens=1),
        month_key="2026-08",
    )
    with pytest.raises(PermissionError, match="provider_review_not_current"):
        await guard.reserve(request)
    async with async_uow_factory() as uow:
        count = await uow.run_sync(
            lambda db: int(
                db.exec_driver_sql(
                    "SELECT count(*) FROM budget_reservations WHERE attempt_id=?",
                    (str(request.attempt_id),),
                ).scalar_one()
            )
        )
        await uow.rollback()
    assert count == 0


@pytest.mark.asyncio
async def test_web_search_budget_shape_is_dormant_and_inserts_nothing(
    async_uow_factory,
    clock,
    catalog,
    provider_reviews,
    budget_evidence,
) -> None:
    guard = BudgetGuard(
        async_uow_factory,
        clock,
        catalog,
        provider_reviews,
        budget_evidence,
        hard_limit=150_000_000,
    )
    request = BudgetReservationRequest(
        household_id=uuid4(),
        turn_id=uuid4(),
        request_id=uuid4(),
        attempt_id=uuid4(),
        provider="openai",
        model="gpt-5.6-sol",
        category="web_search",
        usage_ceiling=WebSearchUsageUnits(
            category="web_search",
            input_tokens=1,
            output_tokens=1,
            web_search_calls=1,
        ),
        month_key="2026-08",
    )
    with pytest.raises(PermissionError, match="budget_category_not_activated"):
        await guard.reserve(request)
    async with async_uow_factory() as uow:
        count = await uow.run_sync(
            lambda db: int(
                db.exec_driver_sql(
                    "SELECT count(*) FROM budget_reservations WHERE attempt_id=?",
                    (str(request.attempt_id),),
                ).scalar_one()
            )
        )
        await uow.rollback()
    assert count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("target", "error"),
    (
        ("reservation", "budget_reservation_insert_failed"),
        ("turn_binding", "budget_turn_binding_insert_failed"),
    ),
)
async def test_silent_ignored_budget_insert_rolls_back_reservation_and_binding(
    async_uow_factory,
    clock,
    catalog,
    provider_reviews,
    budget_evidence,
    target,
    error,
) -> None:
    guard = BudgetGuard(
        async_uow_factory,
        clock,
        catalog,
        provider_reviews,
        budget_evidence,
        hard_limit=150_000_000,
    )
    request = BudgetReservationRequest(
        household_id=uuid4(),
        turn_id=uuid4(),
        request_id=uuid4(),
        attempt_id=uuid4(),
        provider="openai",
        model="gpt-5.6-sol",
        category="llm",
        usage_ceiling=LlmUsageUnits(category="llm", input_tokens=1, output_tokens=1),
        month_key="2026-08",
    )
    trigger_name = f"test_budget_{target}_ignore_{request.attempt_id.hex}"
    if target == "reservation":
        trigger_sql = (
            f"CREATE TRIGGER {trigger_name} BEFORE INSERT ON budget_reservations "
            f"WHEN NEW.attempt_id='{request.attempt_id}' "
            "BEGIN SELECT RAISE(IGNORE); END"
        )
    else:
        trigger_sql = (
            f"CREATE TRIGGER {trigger_name} BEFORE INSERT ON runtime_settings "
            "WHEN NEW.key LIKE 'budget.turn.%' "
            "BEGIN SELECT RAISE(IGNORE); END"
        )

    def install_trigger(db) -> None:
        db.exec_driver_sql(trigger_sql)

    async with async_uow_factory() as uow:
        await uow.run_sync(install_trigger)
        await uow.commit()
    try:
        with pytest.raises(PermissionError, match=error):
            await guard.reserve(request)
    finally:

        def drop_trigger(db) -> None:
            db.exec_driver_sql(f"DROP TRIGGER IF EXISTS {trigger_name}")

        async with async_uow_factory() as uow:
            await uow.run_sync(drop_trigger)
            await uow.commit()
    async with async_uow_factory() as uow:

        def counts(db) -> tuple[int, int]:
            reservations = db.exec_driver_sql(
                "SELECT count(*) FROM budget_reservations WHERE attempt_id=?",
                (str(request.attempt_id),),
            ).scalar_one()
            bindings = db.exec_driver_sql(
                "SELECT count(*) FROM runtime_settings "
                "WHERE key LIKE 'budget.turn.%' "
                "AND json_extract(value_json,'$.attempt_id')=?",
                (str(request.attempt_id),),
            ).scalar_one()
            return int(reservations), int(bindings)

        persisted = await uow.run_sync(counts)
        await uow.rollback()
    assert persisted == (0, 0)


@pytest.mark.asyncio
async def test_silent_ignored_soft_warning_marker_rolls_back_reservation_and_binding(
    async_uow_factory,
    clock,
    catalog,
    provider_reviews,
    budget_evidence,
) -> None:
    guard = BudgetGuard(
        async_uow_factory,
        clock,
        catalog,
        provider_reviews,
        budget_evidence,
        hard_limit=150_000_000,
        soft_limit=1,
    )
    request = BudgetReservationRequest(
        household_id=uuid4(),
        turn_id=uuid4(),
        request_id=uuid4(),
        attempt_id=uuid4(),
        provider="openai",
        model="gpt-5.6-sol",
        category="llm",
        usage_ceiling=LlmUsageUnits(category="llm", input_tokens=1, output_tokens=0),
        month_key="2026-08",
    )
    warning_key = f"budget.soft_warning.{request.month_key}"
    trigger_name = f"test_budget_soft_warning_ignore_{request.attempt_id.hex}"
    trigger_sql = (
        f"CREATE TRIGGER {trigger_name} BEFORE INSERT ON runtime_settings "
        f"WHEN NEW.key='{warning_key}' "
        "BEGIN SELECT RAISE(IGNORE); END"
    )

    async with async_uow_factory() as uow:

        def install_trigger(db) -> None:
            db.exec_driver_sql(trigger_sql)

        await uow.run_sync(install_trigger)
        await uow.commit()
    try:
        with pytest.raises(PermissionError, match="budget_soft_warning_insert_failed"):
            await guard.reserve(request)
    finally:
        async with async_uow_factory() as uow:

            def drop_trigger(db) -> None:
                db.exec_driver_sql(f"DROP TRIGGER IF EXISTS {trigger_name}")

            await uow.run_sync(drop_trigger)
            await uow.commit()

    async with async_uow_factory() as uow:

        def counts(db) -> tuple[int, int, int]:
            reservations = db.exec_driver_sql(
                "SELECT count(*) FROM budget_reservations WHERE attempt_id=?",
                (str(request.attempt_id),),
            ).scalar_one()
            bindings = db.exec_driver_sql(
                "SELECT count(*) FROM runtime_settings "
                "WHERE key LIKE 'budget.turn.%' "
                "AND json_extract(value_json,'$.attempt_id')=?",
                (str(request.attempt_id),),
            ).scalar_one()
            warnings = db.exec_driver_sql(
                "SELECT count(*) FROM runtime_settings WHERE key=?",
                (warning_key,),
            ).scalar_one()
            return int(reservations), int(bindings), int(warnings)

        persisted = await uow.run_sync(counts)
        await uow.rollback()
    assert persisted == (0, 0, 0)


@pytest.mark.asyncio
async def test_sent_attempt_cannot_be_released(
    async_uow_factory,
    clock,
    catalog,
    provider_reviews,
    budget_evidence,
    redaction_receipt_repository,
    route,
    consumption,
) -> None:
    guard = BudgetGuard(
        async_uow_factory,
        clock,
        catalog,
        provider_reviews,
        budget_evidence,
        hard_limit=150_000_000,
    )
    reservation_request = BudgetReservationRequest(
        household_id=uuid4(),
        turn_id=uuid4(),
        request_id=uuid4(),
        attempt_id=uuid4(),
        provider="openai",
        model="gpt-transcribe",
        category="stt",
        usage_ceiling=SttUsageUnits(category="stt", audio_millis=60_000),
        month_key="2026-08",
    )
    reservation = await guard.reserve(reservation_request)
    claimed_route = route.model_copy(
        update={
            "request_id": reservation.request_id,
            "attempt_id": reservation.attempt_id,
            "budget_reservation_id": reservation.reservation_id,
            "purpose": "cloud_stt",
            "provider": "openai",
            "model": "gpt-transcribe",
        }
    )
    claimed_consumption = consumption.model_copy(
        update={
            "request_id": reservation.request_id,
            "attempt_id": reservation.attempt_id,
            "purpose": "cloud_stt",
            "provider": "openai",
            "model": "gpt-transcribe",
            "request_commitment": claimed_route.request_commitment,
        }
    )
    await ProviderCallRepository(
        async_uow_factory,
        clock,
        redaction_receipt_repository,
    ).begin(claimed_route, claimed_consumption, None)
    await guard.mark_sent(reservation.reservation_id, reservation.attempt_id)
    proof = TransportProof(
        reservation_id=reservation.reservation_id,
        attempt_id=reservation.attempt_id,
        disposition="never_sent",
        observed_at=clock.now(),
        evidence_code="socket_connect_failed",
    )
    with pytest.raises(PermissionError, match="sent_reservation_requires_settlement"):
        await guard.release_unsent(reservation.reservation_id, reservation.attempt_id, proof)
