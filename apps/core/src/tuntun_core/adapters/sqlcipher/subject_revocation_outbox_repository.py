from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast, runtime_checkable
from uuid import UUID, uuid4

from sqlalchemy import Engine
from tuntun_core.services.identity.subject_revocation import SubjectRevocationEvent
from tuntun_core.services.storage_time import parse_utc_storage, utc_storage
from tuntun_core.services.transactions.identity_uow import IdentityUnitOfWorkFactory
from tuntun_core.services.transactions.protocols import AsyncUnitOfWorkProtocol, UnitOfWorkProtocol


@runtime_checkable
class _EngineBackedFactory(Protocol):
    _engine: Engine


class _RowMappingSource(Protocol):
    @property
    def _mapping(self) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class OutboxClaim:
    event: SubjectRevocationEvent
    lease_owner: UUID
    fencing_token: int
    leased_until: datetime


def _row_value(row: Mapping[str, object] | _RowMappingSource, key: str) -> object:
    if isinstance(row, Mapping):
        return row[key]
    return row._mapping[key]


def _row_to_dict(row: object | None) -> dict[str, object] | None:
    if row is None:
        return None
    return dict(cast(_RowMappingSource, row)._mapping)


def _optional_datetime(value: object) -> datetime | None:
    if value is None:
        return None
    return parse_utc_storage(str(value))


def _event_from_row(row: Mapping[str, object] | _RowMappingSource) -> SubjectRevocationEvent:
    return SubjectRevocationEvent(
        id=UUID(str(_row_value(row, "id"))),
        event_key=str(_row_value(row, "event_key")),
        subject_id=UUID(str(_row_value(row, "subject_id"))),
        new_authority_generation=int(str(_row_value(row, "new_authority_generation"))),
        state=str(_row_value(row, "state")),
        occurred_at=parse_utc_storage(str(_row_value(row, "occurred_at"))),
        claimed_at=_optional_datetime(_row_value(row, "claimed_at")),
        lease_owner=None
        if _row_value(row, "lease_owner") is None
        else UUID(str(_row_value(row, "lease_owner"))),
        lease_expires_at=_optional_datetime(_row_value(row, "lease_expires_at")),
        fencing_token=int(str(_row_value(row, "fencing_token"))),
        completed_at=_optional_datetime(_row_value(row, "completed_at")),
        attempt_count=int(str(_row_value(row, "attempt_count"))),
        last_error=None
        if _row_value(row, "last_error") is None
        else str(_row_value(row, "last_error")),
        reconciliation_receipt_id=None
        if _row_value(row, "reconciliation_receipt_id") is None
        else UUID(str(_row_value(row, "reconciliation_receipt_id"))),
    )


async def _enqueue_revocation_event_in_uow(
    uow: AsyncUnitOfWorkProtocol,
    *,
    event_key: str,
    subject_id: UUID,
    new_authority_generation: int,
    occurred_at: datetime,
) -> SubjectRevocationEvent | None:
    event_id = uuid4()

    def insert(transaction: UnitOfWorkProtocol) -> int:
        return transaction.exec_driver_sql(
            "INSERT INTO subject_revocation_outbox "
            "(id,event_key,subject_id,new_authority_generation,state,occurred_at,"
            "attempt_count,fencing_token) "
            "VALUES (?,?,?,?, 'pending', ?,0,0) "
            "ON CONFLICT(event_key) DO NOTHING",
            (
                str(event_id),
                event_key,
                str(subject_id),
                new_authority_generation,
                utc_storage(occurred_at),
            ),
        ).rowcount

    changed = await uow.run_sync(insert)
    if changed != 1:
        return None
    return SubjectRevocationEvent(
        id=event_id,
        event_key=event_key,
        subject_id=subject_id,
        new_authority_generation=new_authority_generation,
        state="pending",
        occurred_at=occurred_at.astimezone(UTC),
    )


class SubjectRevocationOutboxUnitOfWorkFacade:
    """Task-1 typed UoW facade for atomic subject-revocation enqueue."""

    def __init__(self, uow: AsyncUnitOfWorkProtocol) -> None:
        self._uow = uow

    async def enqueue_in_uow(
        self,
        uow: AsyncUnitOfWorkProtocol,
        *,
        event_key: str,
        subject_id: UUID,
        new_authority_generation: int,
        occurred_at: datetime,
    ) -> SubjectRevocationEvent | None:
        if uow is not self._uow:
            raise RuntimeError("subject_revocation_outbox_uow_scope_mismatch")
        return await _enqueue_revocation_event_in_uow(
            self._uow,
            event_key=event_key,
            subject_id=subject_id,
            new_authority_generation=new_authority_generation,
            occurred_at=occurred_at,
        )


class SubjectRevocationOutboxRepository:
    """Durable async facade; all SQL executes through the foundation worker."""

    def __init__(self, uow_factory: IdentityUnitOfWorkFactory) -> None:
        self._uow_factory = uow_factory

    async def enqueue_in_uow(
        self,
        uow: AsyncUnitOfWorkProtocol,
        *,
        event_key: str,
        subject_id: UUID,
        new_authority_generation: int,
        occurred_at: datetime,
    ) -> SubjectRevocationEvent | None:
        return await _enqueue_revocation_event_in_uow(
            uow,
            event_key=event_key,
            subject_id=subject_id,
            new_authority_generation=new_authority_generation,
            occurred_at=occurred_at.astimezone(UTC),
        )

    async def recover_expired(self, now: datetime) -> int:
        async with self._uow_factory() as uow:
            changed = await uow.run_sync(
                lambda transaction: (
                    transaction.exec_driver_sql(
                        "UPDATE subject_revocation_outbox "
                        "SET state='pending',claimed_at=NULL,lease_owner=NULL,"
                        "lease_expires_at=NULL,last_error='expired_lease_recovered' "
                        "WHERE state='processing' AND lease_expires_at<=?",
                        (utc_storage(now),),
                    ).rowcount
                )
            )
            await uow.commit()
        return int(changed)

    async def claim_next(self, now: datetime, lease_owner: UUID) -> OutboxClaim | None:
        lease_expires_at = now + timedelta(seconds=30)
        async with self._uow_factory() as uow:
            row = await uow.run_sync(
                lambda transaction: _row_to_dict(
                    transaction.exec_driver_sql(
                        "UPDATE subject_revocation_outbox "
                        "SET state='processing',claimed_at=?,lease_owner=?,lease_expires_at=?,"
                        "attempt_count=attempt_count+1,"
                        "fencing_token=fencing_token+1,last_error=NULL "
                        "WHERE id=(SELECT id FROM subject_revocation_outbox "
                        "WHERE state='pending' ORDER BY occurred_at,id LIMIT 1) "
                        "RETURNING *",
                        (utc_storage(now), str(lease_owner), utc_storage(lease_expires_at)),
                    ).fetchone()
                )
            )
            await uow.commit()
        if row is None:
            return None
        event = _event_from_row(row)
        return OutboxClaim(event, lease_owner, event.fencing_token, lease_expires_at)

    async def renew(
        self,
        event_id: UUID,
        lease_owner: UUID,
        fencing_token: int,
        now: datetime,
    ) -> bool:
        leased_until = now + timedelta(seconds=30)
        async with self._uow_factory() as uow:
            changed = await uow.run_sync(
                lambda transaction: (
                    transaction.exec_driver_sql(
                        "UPDATE subject_revocation_outbox SET lease_expires_at=? "
                        "WHERE id=? AND state='processing' AND lease_owner=? "
                        "AND fencing_token=? AND lease_expires_at>?",
                        (
                            utc_storage(leased_until),
                            str(event_id),
                            str(lease_owner),
                            fencing_token,
                            utc_storage(now),
                        ),
                    ).rowcount
                )
            )
            await uow.commit()
        return changed == 1

    async def complete(
        self,
        event_id: UUID,
        receipt_id: UUID,
        lease_owner: UUID,
        fencing_token: int,
        now: datetime,
    ) -> None:
        async with self._uow_factory() as uow:
            changed = await uow.run_sync(
                lambda transaction: (
                    transaction.exec_driver_sql(
                        "UPDATE subject_revocation_outbox "
                        "SET state='completed',completed_at=?,"
                        "lease_owner=NULL,lease_expires_at=NULL,"
                        "reconciliation_receipt_id=?,last_error=NULL "
                        "WHERE id=? AND state='processing' AND lease_owner=? "
                        "AND fencing_token=? AND lease_expires_at>?",
                        (
                            utc_storage(now),
                            str(receipt_id),
                            str(event_id),
                            str(lease_owner),
                            fencing_token,
                            utc_storage(now),
                        ),
                    ).rowcount
                )
            )
            if changed != 1:
                raise RuntimeError("subject_revocation_claim_lost")
            await uow.commit()

    async def retry_pending(
        self,
        event_id: UUID,
        lease_owner: UUID,
        fencing_token: int,
        reason_code: str,
        now: datetime,
    ) -> None:
        if len(reason_code) > 128:
            raise ValueError("revocation reason code too long")
        async with self._uow_factory() as uow:
            changed = await uow.run_sync(
                lambda transaction: (
                    transaction.exec_driver_sql(
                        "UPDATE subject_revocation_outbox "
                        "SET state='pending',claimed_at=NULL,"
                        "lease_owner=NULL,lease_expires_at=NULL,"
                        "last_error=? WHERE id=? AND state='processing' "
                        "AND lease_owner=? AND fencing_token=? AND lease_expires_at>?",
                        (
                            reason_code,
                            str(event_id),
                            str(lease_owner),
                            fencing_token,
                            utc_storage(now),
                        ),
                    ).rowcount
                )
            )
            if changed != 1:
                raise RuntimeError("subject_revocation_claim_lost")
            await uow.commit()

    async def defer_until(
        self,
        event_id: UUID,
        lease_owner: UUID,
        fencing_token: int,
        leased_until: datetime,
        now: datetime,
    ) -> None:
        async with self._uow_factory() as uow:
            changed = await uow.run_sync(
                lambda transaction: (
                    transaction.exec_driver_sql(
                        "UPDATE subject_revocation_outbox "
                        "SET lease_expires_at=?,last_error='deferred_live_effect_lease' "
                        "WHERE id=? AND state='processing' AND lease_owner=? "
                        "AND fencing_token=? AND lease_expires_at>?",
                        (
                            utc_storage(leased_until),
                            str(event_id),
                            str(lease_owner),
                            fencing_token,
                            utc_storage(now),
                        ),
                    ).rowcount
                )
            )
            if changed != 1:
                raise RuntimeError("subject_revocation_claim_lost")
            await uow.commit()

    async def earliest_live_expiry(self) -> datetime | None:
        async with self._uow_factory() as uow:
            value = await uow.run_sync(
                lambda transaction: transaction.exec_driver_sql(
                    "SELECT min(lease_expires_at) FROM subject_revocation_outbox "
                    "WHERE state='processing'"
                ).scalar_one_or_none()
            )
            await uow.rollback()
        if value is None:
            return None
        return parse_utc_storage(str(value))

    async def lease_expires_at(self, event_id: UUID) -> datetime | None:
        async with self._uow_factory() as uow:
            value = await uow.run_sync(
                lambda transaction: transaction.exec_driver_sql(
                    "SELECT lease_expires_at FROM subject_revocation_outbox WHERE id=?",
                    (str(event_id),),
                ).scalar_one_or_none()
            )
            await uow.rollback()
        if value is None:
            return None
        return parse_utc_storage(str(value))

    async def pending_count(self) -> int:
        async with self._uow_factory() as uow:
            value = await uow.run_sync(
                lambda transaction: transaction.exec_driver_sql(
                    "SELECT count(*) FROM subject_revocation_outbox WHERE state!='completed'"
                ).scalar_one()
            )
            await uow.rollback()
        return int(value)

    async def state(self, event_id: UUID) -> str:
        async with self._uow_factory() as uow:
            value = await uow.run_sync(
                lambda transaction: transaction.exec_driver_sql(
                    "SELECT state FROM subject_revocation_outbox WHERE id=?",
                    (str(event_id),),
                ).scalar_one_or_none()
            )
            await uow.rollback()
        if value is None:
            raise KeyError(event_id)
        return str(value)

    async def last_error(self, event_id: UUID) -> str | None:
        async with self._uow_factory() as uow:
            row = await uow.run_sync(
                lambda transaction: (
                    None
                    if (
                        row := transaction.exec_driver_sql(
                            "SELECT last_error FROM subject_revocation_outbox WHERE id=?",
                            (str(event_id),),
                        ).fetchone()
                    )
                    is None
                    else (row[0],)
                )
            )
            await uow.rollback()
        if row is None:
            raise KeyError(event_id)
        return None if row[0] is None else str(row[0])

    def takeover_count(self, event_id: UUID) -> int:
        if not isinstance(self._uow_factory, _EngineBackedFactory):
            raise RuntimeError("subject_revocation_takeover_count_requires_engine_backed_uow")
        with self._uow_factory._engine.connect() as connection:
            value = connection.exec_driver_sql(
                "SELECT attempt_count FROM subject_revocation_outbox WHERE id=?",
                (str(event_id),),
            ).scalar_one()
        return max(0, int(value) - 1)
