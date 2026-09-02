from __future__ import annotations

import asyncio
from collections.abc import Iterable
from contextlib import AbstractAsyncContextManager
from datetime import datetime
from typing import Literal, Protocol
from uuid import UUID

import pytest
from tuntun_contracts.base import Sensitivity, canonical_bytes
from tuntun_contracts.commitments import commit_private
from tuntun_contracts.events import EventEnvelope, EventType, StopRequestedPayload
from tuntun_core.adapters.reachy.sequence_store import PersistentSequenceStore
from tuntun_core.services.storage_time import utc_storage
from tuntun_core.services.transactions.protocols import AsyncUnitOfWorkProtocol, UnitOfWorkProtocol

pytest_plugins = ("tests.fixtures.provider_routes",)

HOUSEHOLD_ID = UUID("00000000-0000-0000-0000-000000000901")
OTHER_HOUSEHOLD_ID = UUID("00000000-0000-0000-0000-000000000902")
DEVICE_ID = UUID("00000000-0000-0000-0000-000000000903")
PAYLOAD_TURN_ID = UUID("00000000-0000-0000-0000-000000000904")
HMAC_ROOT = bytes(range(32))
HMAC_KEY_ID = "reachy-hmac-v1"
StopSource = Literal["edge_keyword", "physical_input", "owner_console", "watchdog"]


class EventEnvelopeSubclass(EventEnvelope):
    pass


class UnitOfWorkFactory(Protocol):
    def __call__(self) -> AbstractAsyncContextManager[AsyncUnitOfWorkProtocol]: ...


class Clock(Protocol):
    def now(self) -> datetime: ...


@pytest.fixture
def async_uow_factory(route_uow_factory: UnitOfWorkFactory) -> UnitOfWorkFactory:
    return route_uow_factory


@pytest.fixture
def clock(route_clock: Clock) -> Clock:
    return route_clock


def _make_event(
    clock: Clock,
    sequence: int,
    *,
    event_id: UUID | None = None,
    household_id: UUID = HOUSEHOLD_ID,
    device_id: UUID = DEVICE_ID,
    source: StopSource = "edge_keyword",
) -> EventEnvelope:
    payload = StopRequestedPayload(
        kind="safety.stop_requested",
        turn_id=PAYLOAD_TURN_ID,
        source=source,
    )
    return EventEnvelope(
        schema_version="1.0",
        event_id=event_id or UUID(int=10_000 + sequence),
        event_type=EventType.STOP_REQUESTED,
        household_id=household_id,
        device_id=device_id,
        session_id=None,
        correlation_id=UUID(int=20_000 + sequence),
        causation_id=None,
        device_sequence=sequence,
        occurred_at=clock.now(),
        sensitivity=Sensitivity.HOUSEHOLD,
        payload_commitment=commit_private(
            HMAC_ROOT,
            HMAC_KEY_ID,
            EventType.STOP_REQUESTED.value,
            canonical_bytes(payload),
        ),
        payload=payload,
    )


async def _seed_device(
    uow_factory: UnitOfWorkFactory,
    clock: Clock,
    *,
    household_id: UUID = HOUSEHOLD_ID,
    device_id: UUID = DEVICE_ID,
    last_sequence: int = 0,
    revoked: bool = False,
) -> None:
    now = utc_storage(clock.now())
    revoked_at = now if revoked else None

    def insert(transaction: UnitOfWorkProtocol) -> None:
        transaction.exec_driver_sql(
            "INSERT INTO households(id,display_label_ciphertext,timezone,created_at) "
            "VALUES(?,?,?,?)",
            (str(household_id), b"synthetic", "Asia/Singapore", now),
        )
        transaction.exec_driver_sql(
            "INSERT INTO devices("
            "id,household_id,kind,certificate_fingerprint,signing_public_key,"
            "signing_key_id,last_sequence,paired_at,revoked_at"
            ") VALUES(?,?,?,?,?,?,?,?,?)",
            (
                str(device_id),
                str(household_id),
                "reachy",
                f"synthetic-fingerprint-{device_id}",
                b"x" * 32,
                "ed25519:reachy-edge:v1",
                last_sequence,
                now,
                revoked_at,
            ),
        )

    async with uow_factory() as uow:
        await uow.run_sync(insert)
        await uow.commit()


async def _device_last_sequence(uow_factory: UnitOfWorkFactory, device_id: UUID = DEVICE_ID) -> int:
    async with uow_factory() as uow:
        value = await uow.run_sync(
            lambda transaction: transaction.exec_driver_sql(
                "SELECT last_sequence FROM devices WHERE id=?",
                (str(device_id),),
            ).scalar_one()
        )
        await uow.rollback()
    assert type(value) is int
    return value


async def _receipt_rows(uow_factory: UnitOfWorkFactory) -> list[dict[str, object]]:
    def select(transaction: UnitOfWorkProtocol) -> list[dict[str, object]]:
        rows = transaction.exec_driver_sql(
            "SELECT id,household_id,device_id,event_type,correlation_id,device_sequence,"
            "payload_hmac_key_id,payload_hmac_b64,decision,occurred_at "
            "FROM event_receipts ORDER BY device_sequence,id"
        )
        return [dict(row._mapping) for row in rows]

    async with uow_factory() as uow:
        result = await uow.run_sync(select)
        await uow.rollback()
    return result


async def _event_receipt_columns(uow_factory: UnitOfWorkFactory) -> tuple[str, ...]:
    def select(transaction: UnitOfWorkProtocol) -> tuple[str, ...]:
        rows = transaction.exec_driver_sql("PRAGMA table_info(event_receipts)")
        return tuple(str(row._mapping["name"]) for row in rows)

    async with uow_factory() as uow:
        result = await uow.run_sync(select)
        await uow.rollback()
    return result


def _string_values(rows: Iterable[dict[str, object]]) -> tuple[str, ...]:
    return tuple(value for row in rows for value in row.values() if type(value) is str)


@pytest.mark.asyncio
async def test_accept_requires_exact_event_envelope(
    async_uow_factory: UnitOfWorkFactory,
    clock: Clock,
) -> None:
    await _seed_device(async_uow_factory, clock)
    event = _make_event(clock, 1)
    subclassed = EventEnvelopeSubclass.model_construct(**event.__dict__)

    with pytest.raises(TypeError, match="event must be an exact EventEnvelope"):
        await PersistentSequenceStore(async_uow_factory).accept(subclassed)

    assert await _device_last_sequence(async_uow_factory) == 0
    assert await _receipt_rows(async_uow_factory) == []


@pytest.mark.asyncio
async def test_accept_requires_closed_uuid_identifiers(
    async_uow_factory: UnitOfWorkFactory,
    clock: Clock,
) -> None:
    await _seed_device(async_uow_factory, clock)
    forged = _make_event(clock, 1).model_copy(update={"device_id": str(DEVICE_ID)})

    with pytest.raises(TypeError, match="event identifiers must be exact UUIDs"):
        await PersistentSequenceStore(async_uow_factory).accept(forged)

    assert await _device_last_sequence(async_uow_factory) == 0
    assert await _receipt_rows(async_uow_factory) == []


@pytest.mark.asyncio
async def test_accept_requires_closed_payload_uuid_identifiers(
    async_uow_factory: UnitOfWorkFactory,
    clock: Clock,
) -> None:
    await _seed_device(async_uow_factory, clock)
    event = _make_event(clock, 1)
    payload = event.payload
    assert isinstance(payload, StopRequestedPayload)
    forged = event.model_copy(
        update={"payload": payload.model_copy(update={"turn_id": str(PAYLOAD_TURN_ID)})}
    )

    with pytest.raises(TypeError, match="event identifiers must be exact UUIDs"):
        await PersistentSequenceStore(async_uow_factory).accept(forged)

    assert await _device_last_sequence(async_uow_factory) == 0
    assert await _receipt_rows(async_uow_factory) == []


@pytest.mark.asyncio
async def test_sequence_is_persistent_and_strictly_increasing(
    async_uow_factory: UnitOfWorkFactory,
    clock: Clock,
) -> None:
    await _seed_device(async_uow_factory, clock, last_sequence=40)

    await PersistentSequenceStore(async_uow_factory).accept(_make_event(clock, 41))

    with pytest.raises(ValueError, match="replayed device sequence"):
        await PersistentSequenceStore(async_uow_factory).accept(_make_event(clock, 41))
    await PersistentSequenceStore(async_uow_factory).accept(_make_event(clock, 42))

    assert await _device_last_sequence(async_uow_factory) == 42
    assert [row["device_sequence"] for row in await _receipt_rows(async_uow_factory)] == [41, 42]


@pytest.mark.asyncio
async def test_sequence_rejects_zero_as_replay(
    async_uow_factory: UnitOfWorkFactory,
    clock: Clock,
) -> None:
    await _seed_device(async_uow_factory, clock)

    with pytest.raises(ValueError, match="replayed device sequence"):
        await PersistentSequenceStore(async_uow_factory).accept(_make_event(clock, 0))

    assert await _device_last_sequence(async_uow_factory) == 0
    assert await _receipt_rows(async_uow_factory) == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "revoked,household_id",
    [(True, HOUSEHOLD_ID), (False, OTHER_HOUSEHOLD_ID)],
)
async def test_sequence_rejects_revoked_or_wrong_household_device(
    async_uow_factory: UnitOfWorkFactory,
    clock: Clock,
    *,
    revoked: bool,
    household_id: UUID,
) -> None:
    await _seed_device(async_uow_factory, clock, revoked=revoked)

    with pytest.raises(ValueError, match="replayed device sequence"):
        await PersistentSequenceStore(async_uow_factory).accept(
            _make_event(clock, 1, household_id=household_id)
        )

    assert await _device_last_sequence(async_uow_factory) == 0
    assert await _receipt_rows(async_uow_factory) == []


@pytest.mark.asyncio
async def test_concurrent_duplicate_sequence_accepts_once(
    async_uow_factory: UnitOfWorkFactory,
    clock: Clock,
) -> None:
    await _seed_device(async_uow_factory, clock)
    first = _make_event(clock, 1, event_id=UUID(int=30_001))
    second = _make_event(clock, 1, event_id=UUID(int=30_002))

    results = await asyncio.gather(
        PersistentSequenceStore(async_uow_factory).accept(first),
        PersistentSequenceStore(async_uow_factory).accept(second),
        return_exceptions=True,
    )

    accepted = [result for result in results if result is None]
    replay_errors = [result for result in results if isinstance(result, ValueError)]
    assert len(accepted) == 1
    assert [str(error) for error in replay_errors] == ["replayed device sequence"]
    assert await _device_last_sequence(async_uow_factory) == 1
    rows = await _receipt_rows(async_uow_factory)
    assert len(rows) == 1
    assert rows[0]["id"] in {str(first.event_id), str(second.event_id)}


@pytest.mark.asyncio
async def test_duplicate_event_id_rolls_back_sequence_advance(
    async_uow_factory: UnitOfWorkFactory,
    clock: Clock,
) -> None:
    await _seed_device(async_uow_factory, clock, last_sequence=40)
    event_id = UUID("00000000-0000-0000-0000-000000009999")

    await PersistentSequenceStore(async_uow_factory).accept(
        _make_event(clock, 41, event_id=event_id)
    )
    with pytest.raises(ValueError, match="duplicate event receipt"):
        await PersistentSequenceStore(async_uow_factory).accept(
            _make_event(clock, 42, event_id=event_id)
        )

    assert await _device_last_sequence(async_uow_factory) == 41
    rows = await _receipt_rows(async_uow_factory)
    assert len(rows) == 1
    assert rows[0]["id"] == str(event_id)
    assert rows[0]["device_sequence"] == 41


@pytest.mark.asyncio
async def test_receipt_persistence_is_content_free(
    async_uow_factory: UnitOfWorkFactory,
    clock: Clock,
) -> None:
    await _seed_device(async_uow_factory, clock)
    event = _make_event(clock, 1, source="owner_console")

    await PersistentSequenceStore(async_uow_factory).accept(event)

    columns = await _event_receipt_columns(async_uow_factory)
    raw_content_columns = set(columns) - {"payload_hmac_key_id", "payload_hmac_b64"}
    assert all("payload" not in column for column in raw_content_columns)
    assert all("audio" not in column and "media" not in column for column in columns)
    rows = await _receipt_rows(async_uow_factory)
    assert rows == [
        {
            "id": str(event.event_id),
            "household_id": str(event.household_id),
            "device_id": str(event.device_id),
            "event_type": EventType.STOP_REQUESTED.value,
            "correlation_id": str(event.correlation_id),
            "device_sequence": 1,
            "payload_hmac_key_id": HMAC_KEY_ID,
            "payload_hmac_b64": event.payload_commitment.value_b64,
            "decision": "accepted",
            "occurred_at": utc_storage(event.occurred_at),
        }
    ]
    payload = event.payload
    assert isinstance(payload, StopRequestedPayload)
    assert payload.source not in _string_values(rows)
    assert str(payload.turn_id) not in _string_values(rows)
