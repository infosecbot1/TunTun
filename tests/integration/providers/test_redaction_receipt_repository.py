# tests/integration/providers/test_redaction_receipt_repository.py
import json

import pytest
from tuntun_core.services.providers.redaction_repository import RedactionReceiptRepository

pytest_plugins = ("tests.fixtures.provider_egress",)


@pytest.mark.asyncio
async def test_receipt_record_is_content_minimized_and_restart_visible(
    async_uow_factory, route_clock, finalized_redaction_receipt
) -> None:
    repository = RedactionReceiptRepository(async_uow_factory, route_clock)
    await repository.record(finalized_redaction_receipt)

    def select_row(db):
        return tuple(
            db.exec_driver_sql(
                "SELECT purpose,input_hmac_key_id,input_hmac_b64,output_hmac_key_id,"
                "output_hmac_b64,removed_categories_json,removed_count,policy_version,"
                "maximum_sensitivity,occurred_at FROM redaction_receipts WHERE id=?",
                (str(finalized_redaction_receipt.receipt_id),),
            ).one()
        )

    async with async_uow_factory() as uow:
        row = await uow.run_sync(select_row)
        await uow.rollback()
    assert row[0] == finalized_redaction_receipt.purpose
    assert tuple(row[3:5]) == (
        finalized_redaction_receipt.output_commitment.key_id,
        finalized_redaction_receipt.output_commitment.value_b64,
    )
    assert row[-1].endswith("Z") and len(row[-1]) == 27
    serialized = json.dumps(tuple(row), sort_keys=True)
    assert "person@example.test" not in serialized
    assert "sanitized provider body" not in serialized


@pytest.mark.asyncio
async def test_exact_receipt_retry_is_idempotent_but_conflict_fails_closed(
    redaction_receipt_repository, finalized_redaction_receipt
) -> None:
    await redaction_receipt_repository.record(finalized_redaction_receipt)
    await redaction_receipt_repository.record(finalized_redaction_receipt)
    conflicting = finalized_redaction_receipt.model_copy(
        update={"policy_version": "different-policy"}
    )
    with pytest.raises(PermissionError, match="redaction_receipt_conflict"):
        await redaction_receipt_repository.record(conflicting)
