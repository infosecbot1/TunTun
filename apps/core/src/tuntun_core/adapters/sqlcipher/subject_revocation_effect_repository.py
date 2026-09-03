from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal, Protocol, cast
from uuid import UUID, uuid5

from tuntun_core.services.storage_time import parse_utc_storage, utc_storage
from tuntun_core.services.transactions.identity_uow import IdentityUnitOfWorkFactory
from tuntun_core.services.transactions.protocols import AsyncUnitOfWorkProtocol


class _RowMappingSource(Protocol):
    @property
    def _mapping(self) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class DownstreamEffectReceipt:
    id: UUID
    idempotency_key: UUID
    event_id: UUID
    family: str
    subject_id: UUID
    through_generation: int
    disposition: str


@dataclass(frozen=True, slots=True)
class EffectClaim:
    status: Literal["acquired", "busy", "completed"]
    id: UUID
    idempotency_key: UUID
    fencing_token: int | None
    leased_until: datetime | None
    downstream: DownstreamEffectReceipt | None = None


def _row_value(row: Mapping[str, object] | _RowMappingSource, key: str) -> object:
    if isinstance(row, Mapping):
        return row[key]
    return row._mapping[key]


def _row_to_dict(row: object | None) -> dict[str, object] | None:
    if row is None:
        return None
    return dict(cast(_RowMappingSource, row)._mapping)


class SubjectRevocationEffectUnitOfWorkFacade:
    """Task-1 typed UoW facade for atomic stale-effect recovery."""

    def __init__(self, uow: AsyncUnitOfWorkProtocol) -> None:
        self._uow = uow

    async def recover_stale(self, now: datetime) -> int:
        changed = await self._uow.run_sync(
            lambda transaction: (
                transaction.exec_driver_sql(
                    "UPDATE subject_revocation_effects "
                    "SET state='pending',lease_owner=NULL,leased_until=NULL,"
                    "last_error='stale_lease_recovered' "
                    "WHERE state='applying' AND leased_until<=?",
                    (utc_storage(now),),
                ).rowcount
            )
        )
        return int(changed)


class SubjectRevocationEffectRepository:
    """Durable per-event/family leases and receipts; no subject content is stored."""

    def __init__(self, uow_factory: IdentityUnitOfWorkFactory) -> None:
        self._uow_factory = uow_factory

    async def claim(
        self,
        idempotency_key: UUID,
        *,
        event_id: UUID,
        family: str,
        subject_id: UUID,
        through_generation: int,
        lease_owner: UUID,
        now: datetime,
    ) -> EffectClaim:
        row_id = uuid5(idempotency_key, "effect-row")
        leased_until = now + timedelta(seconds=30)
        verified_row: dict[str, object] | None = None
        async with self._uow_factory() as uow:
            await uow.run_sync(
                lambda transaction: (
                    transaction.exec_driver_sql(
                        "INSERT INTO subject_revocation_effects "
                        "(id,event_id,family,idempotency_key,state,attempt_count,"
                        "fencing_token,created_at) VALUES (?,?,?,?, 'pending',0,0,?) "
                        "ON CONFLICT(idempotency_key) DO NOTHING",
                        (
                            str(row_id),
                            str(event_id),
                            family,
                            str(idempotency_key),
                            utc_storage(now),
                        ),
                    ).rowcount
                )
            )
            acquired = await uow.run_sync(
                lambda transaction: _row_to_dict(
                    transaction.exec_driver_sql(
                        "UPDATE subject_revocation_effects "
                        "SET state='applying',lease_owner=?,leased_until=?,"
                        "attempt_count=attempt_count+1,"
                        "fencing_token=fencing_token+1,last_error=NULL "
                        "WHERE idempotency_key=? AND "
                        "(state='pending' OR (state='applying' AND leased_until<=?)) "
                        "RETURNING id,fencing_token",
                        (
                            str(lease_owner),
                            utc_storage(leased_until),
                            str(idempotency_key),
                            utc_storage(now),
                        ),
                    ).fetchone()
                )
            )
            row = await uow.run_sync(
                lambda transaction: _row_to_dict(
                    transaction.exec_driver_sql(
                        "SELECT effect.id,effect.event_id,effect.family,effect.state,"
                        "effect.fencing_token,effect.leased_until,effect.downstream_receipt_id,"
                        "effect.disposition,event.subject_id,event.new_authority_generation "
                        "FROM subject_revocation_effects AS effect "
                        "JOIN subject_revocation_outbox AS event ON event.id=effect.event_id "
                        "WHERE effect.idempotency_key=?",
                        (str(idempotency_key),),
                    ).fetchone()
                )
            )
            if row is None:
                raise RuntimeError("revocation_effect_idempotency_scope_mismatch")
            if (
                str(_row_value(row, "event_id")) != str(event_id)
                or str(_row_value(row, "family")) != family
                or str(_row_value(row, "subject_id")) != str(subject_id)
                or int(str(_row_value(row, "new_authority_generation"))) - 1 != through_generation
            ):
                raise RuntimeError("revocation_effect_idempotency_scope_mismatch")
            await uow.commit()
            verified_row = row
        if verified_row is None:
            raise RuntimeError("revocation_effect_idempotency_scope_mismatch")
        effect_id = UUID(str(_row_value(verified_row, "id")))
        if acquired is not None:
            return EffectClaim(
                "acquired",
                effect_id,
                idempotency_key,
                int(str(_row_value(acquired, "fencing_token"))),
                leased_until,
            )
        if _row_value(verified_row, "state") == "completed":
            receipt_id = _row_value(verified_row, "downstream_receipt_id")
            disposition = _row_value(verified_row, "disposition")
            if receipt_id is None or disposition is None:
                raise RuntimeError("revocation_effect_completed_receipt_missing")
            receipt = DownstreamEffectReceipt(
                UUID(str(receipt_id)),
                idempotency_key,
                UUID(str(_row_value(verified_row, "event_id"))),
                str(_row_value(verified_row, "family")),
                UUID(str(_row_value(verified_row, "subject_id"))),
                int(str(_row_value(verified_row, "new_authority_generation"))) - 1,
                str(disposition),
            )
            return EffectClaim("completed", effect_id, idempotency_key, None, None, receipt)
        leased = _row_value(verified_row, "leased_until")
        if leased is None:
            raise RuntimeError("revocation_effect_live_lease_missing")
        return EffectClaim(
            "busy",
            effect_id,
            idempotency_key,
            None,
            parse_utc_storage(str(leased)),
        )

    async def completed(self, idempotency_key: UUID) -> DownstreamEffectReceipt | None:
        async with self._uow_factory() as uow:
            row = await uow.run_sync(
                lambda transaction: _row_to_dict(
                    transaction.exec_driver_sql(
                        "SELECT effect.downstream_receipt_id,effect.disposition,effect.event_id,"
                        "effect.family,event.subject_id,event.new_authority_generation "
                        "FROM subject_revocation_effects AS effect "
                        "JOIN subject_revocation_outbox AS event ON event.id=effect.event_id "
                        "WHERE effect.idempotency_key=? AND effect.state='completed'",
                        (str(idempotency_key),),
                    ).fetchone()
                )
            )
            await uow.rollback()
        if row is None:
            return None
        return DownstreamEffectReceipt(
            UUID(str(_row_value(row, "downstream_receipt_id"))),
            idempotency_key,
            UUID(str(_row_value(row, "event_id"))),
            str(_row_value(row, "family")),
            UUID(str(_row_value(row, "subject_id"))),
            int(str(_row_value(row, "new_authority_generation"))) - 1,
            str(_row_value(row, "disposition")),
        )

    async def renew(
        self,
        idempotency_key: UUID,
        lease_owner: UUID,
        fencing_token: int,
        now: datetime,
    ) -> bool:
        leased_until = now + timedelta(seconds=30)
        async with self._uow_factory() as uow:
            changed = await uow.run_sync(
                lambda transaction: (
                    transaction.exec_driver_sql(
                        "UPDATE subject_revocation_effects SET leased_until=? "
                        "WHERE idempotency_key=? AND state='applying' AND lease_owner=? "
                        "AND fencing_token=? AND leased_until>?",
                        (
                            utc_storage(leased_until),
                            str(idempotency_key),
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
        idempotency_key: UUID,
        lease_owner: UUID,
        fencing_token: int,
        downstream: DownstreamEffectReceipt,
        now: datetime,
    ) -> None:
        async with self._uow_factory() as uow:
            scope = await uow.run_sync(
                lambda transaction: _row_to_dict(
                    transaction.exec_driver_sql(
                        "SELECT effect.id,effect.event_id,effect.family,event.subject_id,"
                        "event.new_authority_generation "
                        "FROM subject_revocation_effects AS effect "
                        "JOIN subject_revocation_outbox AS event ON event.id=effect.event_id "
                        "WHERE effect.idempotency_key=?",
                        (str(idempotency_key),),
                    ).fetchone()
                )
            )
            if scope is None:
                raise RuntimeError("revocation_effect_claim_lost")
            expected = (
                str(idempotency_key),
                str(_row_value(scope, "event_id")),
                str(_row_value(scope, "family")),
                str(_row_value(scope, "subject_id")),
                int(str(_row_value(scope, "new_authority_generation"))) - 1,
            )
            actual = (
                str(downstream.idempotency_key),
                str(downstream.event_id),
                downstream.family,
                str(downstream.subject_id),
                downstream.through_generation,
            )
            if actual != expected:
                raise RuntimeError("revocation_downstream_receipt_scope_mismatch")
            changed = await uow.run_sync(
                lambda transaction: (
                    transaction.exec_driver_sql(
                        "UPDATE subject_revocation_effects "
                        "SET state='completed',lease_owner=NULL,leased_until=NULL,"
                        "downstream_receipt_id=?,disposition=?,completed_at=? "
                        "WHERE idempotency_key=? AND state='applying' AND lease_owner=? "
                        "AND fencing_token=? AND leased_until>?",
                        (
                            str(downstream.id),
                            downstream.disposition,
                            utc_storage(now),
                            str(idempotency_key),
                            str(lease_owner),
                            fencing_token,
                            utc_storage(now),
                        ),
                    ).rowcount
                )
            )
            if changed != 1:
                raise RuntimeError("revocation_effect_claim_lost")
            await uow.commit()

    async def abandon(
        self,
        idempotency_key: UUID,
        lease_owner: UUID,
        fencing_token: int,
        reason_code: str,
        now: datetime,
    ) -> None:
        async with self._uow_factory() as uow:
            changed = await uow.run_sync(
                lambda transaction: (
                    transaction.exec_driver_sql(
                        "UPDATE subject_revocation_effects "
                        "SET state='pending',lease_owner=NULL,leased_until=NULL,last_error=? "
                        "WHERE idempotency_key=? AND state='applying' AND lease_owner=? "
                        "AND fencing_token=? AND leased_until>?",
                        (
                            reason_code[:128],
                            str(idempotency_key),
                            str(lease_owner),
                            fencing_token,
                            utc_storage(now),
                        ),
                    ).rowcount
                )
            )
            if changed != 1:
                raise RuntimeError("revocation_effect_claim_lost")
            await uow.commit()

    async def recover_stale(self, now: datetime) -> int:
        async with self._uow_factory() as uow:
            changed = await SubjectRevocationEffectUnitOfWorkFacade(uow).recover_stale(now)
            await uow.commit()
        return int(changed)

    async def state(self, effect_id: UUID) -> str:
        async with self._uow_factory() as uow:
            value = await uow.run_sync(
                lambda transaction: transaction.exec_driver_sql(
                    "SELECT state FROM subject_revocation_effects WHERE id=?",
                    (str(effect_id),),
                ).scalar_one_or_none()
            )
            await uow.rollback()
        if value is None:
            raise KeyError(effect_id)
        return str(value)

    async def lease_owner(self, effect_id: UUID) -> UUID | None:
        async with self._uow_factory() as uow:
            row = await uow.run_sync(
                lambda transaction: (
                    None
                    if (
                        row := transaction.exec_driver_sql(
                            "SELECT lease_owner FROM subject_revocation_effects WHERE id=?",
                            (str(effect_id),),
                        ).fetchone()
                    )
                    is None
                    else (row[0],)
                )
            )
            await uow.rollback()
        if row is None:
            raise KeyError(effect_id)
        if row[0] is None:
            return None
        return UUID(str(row[0]))

    @staticmethod
    def fixed_key(event_id: UUID, family: str) -> UUID:
        return uuid5(event_id, family)
