from __future__ import annotations

from collections.abc import Iterable
from contextlib import AbstractAsyncContextManager
from typing import Protocol
from uuid import UUID

from sqlalchemy.exc import IntegrityError
from tuntun_contracts.events import EventEnvelope, StopRequestedPayload, WakeDetectedPayload
from tuntun_core.services.storage_time import utc_storage
from tuntun_core.services.transactions.protocols import AsyncUnitOfWorkProtocol, UnitOfWorkProtocol


class UnitOfWorkFactory(Protocol):
    def __call__(self) -> AbstractAsyncContextManager[AsyncUnitOfWorkProtocol]: ...


class PersistentSequenceStore:
    def __init__(self, uow_factory: UnitOfWorkFactory) -> None:
        self._uow_factory = uow_factory

    async def accept(self, event: EventEnvelope) -> None:
        _require_exact_event(event)
        occurred_at = utc_storage(event.occurred_at)

        def persist(transaction: UnitOfWorkProtocol) -> None:
            updated = transaction.exec_driver_sql(
                "UPDATE devices SET last_sequence=? "
                "WHERE id=? AND household_id=? AND revoked_at IS NULL AND last_sequence<?",
                (
                    event.device_sequence,
                    str(event.device_id),
                    str(event.household_id),
                    event.device_sequence,
                ),
            ).rowcount
            if updated != 1:
                raise ValueError("replayed device sequence")
            inserted = transaction.exec_driver_sql(
                "INSERT INTO event_receipts("
                "id,household_id,device_id,event_type,correlation_id,device_sequence,"
                "payload_hmac_key_id,payload_hmac_b64,decision,occurred_at"
                ") VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    str(event.event_id),
                    str(event.household_id),
                    str(event.device_id),
                    event.event_type.value,
                    str(event.correlation_id),
                    event.device_sequence,
                    event.payload_commitment.key_id,
                    event.payload_commitment.value_b64,
                    "accepted",
                    occurred_at,
                ),
            ).rowcount
            if inserted != 1:
                raise ValueError("duplicate event receipt")

        async with self._uow_factory() as uow:
            try:
                await uow.run_sync(persist)
            except IntegrityError as error:
                raise ValueError("duplicate event receipt") from error
            await uow.commit()


def _require_exact_event(event: EventEnvelope) -> None:
    if type(event) is not EventEnvelope:
        raise TypeError("event must be an exact EventEnvelope")
    identifiers: tuple[UUID | None, ...] = (
        event.event_id,
        event.household_id,
        event.device_id,
        event.session_id,
        event.correlation_id,
        event.causation_id,
        _payload_turn_id(event),
    )
    _require_exact_uuid_identifiers(identifiers)


def _payload_turn_id(event: EventEnvelope) -> UUID | None:
    payload = event.payload
    if type(payload) is WakeDetectedPayload or type(payload) is StopRequestedPayload:
        return payload.turn_id
    return None


def _require_exact_uuid_identifiers(identifiers: Iterable[UUID | None]) -> None:
    if any(identifier is not None and type(identifier) is not UUID for identifier in identifiers):
        raise TypeError("event identifiers must be exact UUIDs")
