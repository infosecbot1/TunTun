import hmac
import json
from datetime import UTC, datetime
from types import TracebackType
from typing import Protocol, Self
from uuid import UUID

from tuntun_contracts.base import Commitment, Sensitivity
from tuntun_contracts.ports import ClockPort
from tuntun_contracts.provider import RedactionReceipt
from tuntun_core.services.transactions.protocols import (
    AsyncUnitOfWorkProtocol,
    UnitOfWorkProtocol,
)


class AsyncUnitOfWorkContext(AsyncUnitOfWorkProtocol, Protocol):
    async def __aenter__(self) -> Self: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool: ...


class AsyncUnitOfWorkFactory(Protocol):
    def __call__(self) -> AsyncUnitOfWorkContext: ...


def _utc_storage(value: datetime) -> str:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise TypeError("stored timestamp must be timezone-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class RedactionReceiptRepository:
    def __init__(
        self,
        uow_factory: AsyncUnitOfWorkFactory,
        clock: ClockPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock

    async def record(self, receipt: RedactionReceipt) -> None:
        occurred_at = _utc_storage(self._clock.now())
        categories_json = json.dumps(
            list(receipt.removed_categories),
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        )
        expected = (
            receipt.purpose,
            receipt.input_commitment.key_id,
            receipt.input_commitment.value_b64,
            receipt.output_commitment.key_id,
            receipt.output_commitment.value_b64,
            categories_json,
            receipt.removed_count,
            receipt.policy_version,
            receipt.maximum_sensitivity.value,
        )

        def insert(transaction: UnitOfWorkProtocol) -> int:
            return transaction.exec_driver_sql(
                "INSERT INTO redaction_receipts "
                "(id,purpose,input_hmac_key_id,input_hmac_b64,output_hmac_key_id,"
                "output_hmac_b64,removed_categories_json,removed_count,policy_version,"
                "maximum_sensitivity,occurred_at) VALUES (?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(id) DO NOTHING",
                (str(receipt.receipt_id), *expected, occurred_at),
            ).rowcount

        def select_existing(
            transaction: UnitOfWorkProtocol,
        ) -> tuple[object, ...] | None:
            row = transaction.exec_driver_sql(
                "SELECT purpose,input_hmac_key_id,input_hmac_b64,"
                "output_hmac_key_id,output_hmac_b64,removed_categories_json,"
                "removed_count,policy_version,maximum_sensitivity "
                "FROM redaction_receipts WHERE id=?",
                (str(receipt.receipt_id),),
            ).fetchone()
            return None if row is None else tuple(row)

        async with self._uow_factory() as uow:
            inserted = await uow.run_sync(insert)
            if inserted == 1:
                await uow.commit()
                return
            if inserted != 0:
                raise RuntimeError("redaction receipt insert returned invalid rowcount")
            existing = await uow.run_sync(select_existing)
            await uow.rollback()
        if existing is not None and existing == expected:
            return
        raise PermissionError("redaction_receipt_conflict")

    def require_bound_in_transaction(
        self,
        transaction: UnitOfWorkProtocol,
        *,
        receipt_id: UUID,
        purpose: str,
        output_commitment: Commitment,
        maximum_sensitivity: Sensitivity,
    ) -> None:
        row = transaction.exec_driver_sql(
            "SELECT purpose,output_hmac_key_id,output_hmac_b64,maximum_sensitivity "
            "FROM redaction_receipts WHERE id=?",
            (str(receipt_id),),
        ).fetchone()
        if row is None:
            raise PermissionError("redaction_receipt_binding_mismatch")
        expected = (
            purpose,
            output_commitment.key_id,
            output_commitment.value_b64,
            maximum_sensitivity.value,
        )
        if len(row) != len(expected) or any(
            type(actual) is not str or not hmac.compare_digest(actual, wanted)
            for actual, wanted in zip(row, expected, strict=True)
        ):
            raise PermissionError("redaction_receipt_binding_mismatch")
