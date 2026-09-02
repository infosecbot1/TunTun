# tests/integration/providers/test_call_proof_repository.py
import pytest
from sqlalchemy.exc import IntegrityError
from tuntun_core.services.providers.call_repository import ProviderCallRepository
from tuntun_core.services.storage_time import utc_storage

pytest_plugins = ("tests.fixtures.provider_egress",)


# Test-only BudgetPort seam. Task 05 replaces this with BudgetGuard; keeping the
# helper here prevents a backwards task dependency while still proving the SQL pair.
@pytest.fixture
def task04_sql_mark_sent(async_uow_factory, clock):
    async def mark_sent(reservation_id, attempt_id):
        now = utc_storage(clock.now())

        def mark(db):
            call = db.exec_driver_sql(
                "SELECT count(*) FROM provider_calls WHERE budget_reservation_id=? "
                "AND attempt_id=? AND outcome='started' AND gateway_ordering_version=1 "
                "AND transport_phase='claim_begun' AND provider_usage_json IS NULL "
                "AND provider_usage_receipt_key_id IS NULL "
                "AND provider_usage_receipt_hmac_b64 IS NULL",
                (str(reservation_id), str(attempt_id)),
            ).scalar_one()
            if call != 1:
                raise PermissionError("task04_mark_sent_proof_mismatch")
            reservation = db.exec_driver_sql(
                "UPDATE budget_reservations SET state='sent',transport_phase='marked_sent' "
                "WHERE id=? AND attempt_id=? AND outcome IN ('allow','allow_soft_warning') "
                "AND state='reserved' AND gateway_ordering_version=1 "
                "AND transport_phase='claim_begun' AND expires_at>?",
                (str(reservation_id), str(attempt_id), now),
            )
            paired_call = db.exec_driver_sql(
                "UPDATE provider_calls SET transport_phase='marked_sent' WHERE "
                "budget_reservation_id=? AND attempt_id=? AND outcome='started' "
                "AND gateway_ordering_version=1 AND transport_phase='claim_begun'",
                (str(reservation_id), str(attempt_id)),
            )
            if reservation.rowcount != 1 or paired_call.rowcount != 1:
                raise PermissionError("task04_mark_sent_proof_mismatch")

        async with async_uow_factory() as uow:
            await uow.run_sync(mark)
            await uow.commit()

    return mark_sent


async def proof_rows(factory, route):
    def select_rows(db):
        reservation = db.exec_driver_sql(
            "SELECT state,gateway_ordering_version,transport_phase "
            "FROM budget_reservations WHERE id=? AND attempt_id=?",
            (str(route.budget_reservation_id), str(route.attempt_id)),
        ).fetchone()
        call = db.exec_driver_sql(
            "SELECT id,gateway_ordering_version,transport_phase,outcome "
            "FROM provider_calls WHERE budget_reservation_id=? AND attempt_id=?",
            (str(route.budget_reservation_id), str(route.attempt_id)),
        ).fetchone()
        return tuple(row if row is None else tuple(row) for row in (reservation, call))

    async with factory() as uow:
        rows = await uow.run_sync(select_rows)
        await uow.rollback()
    return rows


@pytest.mark.asyncio
async def test_claim_and_network_boundaries_are_atomic_and_survive_restart(
    async_uow_factory,
    clock,
    route,
    consumption,
    redaction_receipt_id,
    redaction_receipt_repository,
    task04_sql_mark_sent,
):
    calls = ProviderCallRepository(
        async_uow_factory,
        clock,
        redaction_receipt_repository,
    )
    call_id = await calls.begin(route, consumption, redaction_receipt_id)
    restarted_calls = ProviderCallRepository(
        async_uow_factory,
        clock,
        redaction_receipt_repository,
    )
    assert await proof_rows(async_uow_factory, route) == (
        ("reserved", 1, "claim_begun"),
        (str(call_id), 1, "claim_begun", "started"),
    )
    await task04_sql_mark_sent(
        route.budget_reservation_id,
        route.attempt_id,
    )
    assert await proof_rows(async_uow_factory, route) == (
        ("sent", 1, "marked_sent"),
        (str(call_id), 1, "marked_sent", "started"),
    )
    await restarted_calls.mark_network_invocation_starting(call_id)
    assert await proof_rows(async_uow_factory, route) == (
        ("sent", 1, "network_invocation_starting"),
        (str(call_id), 1, "network_invocation_starting", "started"),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    ("missing", "swapped", "wrong_purpose", "wrong_output_commitment", "wrong_sensitivity"),
)
async def test_reasoning_receipt_binding_fails_before_call_claim(
    provider_call_binding_case, mutation
) -> None:
    case = provider_call_binding_case(purpose="cloud_reasoning", receipt_mutation=mutation)
    with pytest.raises(PermissionError, match="redaction_receipt_binding_mismatch"):
        await case.begin()
    assert await case.persisted_proof_rows() == (("reserved", 1, "not_claimed"), None)


@pytest.mark.asyncio
async def test_tts_requires_exact_dlp_receipt_binding(
    provider_call_binding_case,
) -> None:
    valid = provider_call_binding_case(purpose="cloud_tts", receipt_mutation="valid")
    await valid.begin()
    assert await valid.persisted_redaction_receipt_id() == valid.receipt.receipt_id
    wrong = provider_call_binding_case(
        purpose="cloud_tts", receipt_mutation="wrong_output_commitment"
    )
    with pytest.raises(PermissionError, match="redaction_receipt_binding_mismatch"):
        await wrong.begin()


@pytest.mark.asyncio
async def test_stt_requires_null_receipt_and_persists_null_fk(
    provider_call_binding_case,
) -> None:
    rejected = provider_call_binding_case(purpose="cloud_stt", receipt_mutation="present")
    with pytest.raises(PermissionError, match="redaction_receipt_forbidden"):
        await rejected.begin()
    accepted = provider_call_binding_case(purpose="cloud_stt", receipt_mutation="missing")
    await accepted.begin()
    assert await accepted.persisted_redaction_receipt_id() is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    (
        "after_reservation_update",
        "after_call_insert",
        "before_call_insert_ignore",
    ),
)
async def test_claim_fault_rolls_back_both_proof_rows(call_repository_fault_case, fault):
    case = call_repository_fault_case(fault)
    # ProviderCallRepository intentionally converts claim-time integrity errors
    # to one content-free public denial while the transaction rolls back both rows.
    with pytest.raises(PermissionError, match="provider_call_claim_conflict"):
        await case.begin()
    assert await case.persisted_proof_rows() == (("reserved", 1, "not_claimed"), None)


@pytest.mark.asyncio
async def test_network_phase_cannot_advance_only_one_half(call_repository_fault_case):
    case = call_repository_fault_case("after_network_reservation_update")
    await case.begin()
    await case.mark_sent()
    with pytest.raises(IntegrityError, match="injected network fault"):
        await case.mark_network_invocation_starting()
    assert await case.persisted_phases() == ("marked_sent", "marked_sent")


@pytest.mark.asyncio
async def test_finish_rejects_proven_unsent_claim(call_repository_fault_case):
    case = call_repository_fault_case(None)
    call_id = await case.begin()
    before = await case.persisted_proof_rows()
    with pytest.raises(PermissionError, match="provider_call_unsent_requires_release"):
        await case.finish(call_id, "failed")
    assert await case.persisted_proof_rows() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ("after_call_finish", "reservation_finish_cas_lost"))
async def test_finish_requires_and_atomically_closes_both_proof_halves(
    call_repository_fault_case,
    fault,
):
    case = call_repository_fault_case(fault)
    call_id = await case.begin()
    await case.mark_sent()
    before = await case.persisted_proof_rows()
    expected = (
        "injected finish fault"
        if fault == "after_call_finish"
        else "provider_reservation_finish_race"
    )
    error_type = IntegrityError if fault == "after_call_finish" else PermissionError
    with pytest.raises(error_type, match=expected):
        await case.finish(call_id, "failed")
    assert await case.persisted_proof_rows() == before
    case.clear_fault()
    await case.finish(call_id, "failed")
    reservation, call = await case.persisted_proof_rows()
    assert reservation[2] == call[2] == "finished"
    assert call[3] == "failed"
    assert case.provider_call_finished_at is not None


@pytest.mark.asyncio
async def test_finish_exact_retry_is_idempotent_but_changed_outcome_conflicts(
    call_repository_fault_case,
) -> None:
    case = call_repository_fault_case(None)
    call_id = await case.begin()
    await case.mark_sent()
    await case.finish(call_id, "failed")
    terminal = await case.persisted_proof_rows()
    await case.finish(call_id, "failed")
    assert await case.persisted_proof_rows() == terminal
    with pytest.raises(PermissionError, match="provider_call_finish_conflict"):
        await case.finish(call_id, "ambiguous")
    assert await case.persisted_proof_rows() == terminal
