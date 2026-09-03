from __future__ import annotations

import asyncio
import base64
import os
import sqlite3
import stat
from collections.abc import AsyncIterator, Iterator
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
import tuntun_contracts.reachy_wire as reachy_wire
import tuntun_edge.transport.duplex_state as edge_duplex_module
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import ValidationError
from sqlalchemy import Engine
from tuntun_contracts.base import (
    ContractParseError,
    canonical_bytes,
    parse_contract_json,
)
from tuntun_contracts.reachy_wire import (
    DeviceChallengeV1,
    FramePurpose,
    SignedControlFrameV1,
    decode_control_payload,
    sign_control_frame,
    verify_control_frame,
)
from tuntun_core.adapters.reachy.duplex_state import CoreDuplexState
from tuntun_core.adapters.sqlcipher.async_unit_of_work import AsyncUnitOfWorkFactory
from tuntun_core.adapters.sqlcipher.engine import create_sqlcipher_engine
from tuntun_core.services.storage_time import utc_storage
from tuntun_core.services.transactions.protocols import (
    AsyncUnitOfWorkProtocol,
    UnitOfWorkProtocol,
)
from tuntun_edge.transport.duplex_state import EdgeDuplexState

HOUSEHOLD_ID = UUID("00000000-0000-0000-0000-000000001001")
DEVICE_ID = UUID("00000000-0000-0000-0000-000000001002")
SIGNING_KEY_ID = "ed25519:reachy-edge:v1"
HMAC_KEY_ID = "reachy-frame-hmac:v1"
CONTROL_PURPOSE: FramePurpose = "reachy.health.v1"
COMMAND_PURPOSE: FramePurpose = "reachy.command.v1"
EVENT_PURPOSE: FramePurpose = "reachy.event.v1"
PAYLOAD = b'{"request":"health"}'
TERMINAL_CORRELATION_RETENTION_LIMIT = 4_096
PENDING_CORRELATION_LIMIT = 256


class Clock(Protocol):
    def now(self) -> datetime: ...


class UnitOfWorkFactory(Protocol):
    def __call__(self) -> AbstractAsyncContextManager[AsyncUnitOfWorkProtocol]: ...


@dataclass(frozen=True, slots=True)
class CoreDatabase:
    engine: Engine
    path: Path
    key: bytes


@dataclass(frozen=True, slots=True)
class FrozenClock:
    value: datetime

    def now(self) -> datetime:
        return self.value


@dataclass(frozen=True, slots=True)
class NaiveClock:
    value: datetime

    def now(self) -> datetime:
        return self.value


@dataclass(frozen=True, slots=True)
class FrameCrypto:
    private_key: Ed25519PrivateKey
    hmac_root: bytes
    connection_nonce: bytes

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    def signed_frame(self, *, sequence: int = 41) -> SignedControlFrameV1:
        return sign_control_frame(
            self.private_key,
            self.hmac_root,
            signing_key_id=SIGNING_KEY_ID,
            hmac_key_id=HMAC_KEY_ID,
            direction="edge_to_core",
            kind="request",
            connection_nonce=self.connection_nonce,
            sequence=sequence,
            correlation_id=UUID("00000000-0000-0000-0000-000000001003"),
            purpose=CONTROL_PURPOSE,
            payload=PAYLOAD,
        )


@pytest.fixture
def frame_crypto() -> FrameCrypto:
    return FrameCrypto(
        private_key=Ed25519PrivateKey.generate(),
        hmac_root=bytes(range(32)),
        connection_nonce=bytes(range(32, 64)),
    )


@pytest.fixture
def core_database(tmp_path: Path) -> Iterator[CoreDatabase]:
    private_dir = Path(os.path.realpath(tmp_path)) / "core-private"
    private_dir.mkdir(mode=0o700)
    database_path = private_dir / "foundation.db"
    key = bytes(range(32))
    config = Config("apps/core/alembic.ini")
    config.attributes["sqlcipher_path"] = database_path
    config.attributes["sqlcipher_key"] = key
    command.upgrade(config, "head")
    engine = create_sqlcipher_engine(database_path, key)
    try:
        yield CoreDatabase(engine=engine, path=database_path, key=key)
    finally:
        engine.dispose()
        for candidate in (
            database_path,
            Path(f"{database_path}-wal"),
            Path(f"{database_path}-shm"),
        ):
            candidate.unlink(missing_ok=True)


@pytest_asyncio.fixture
async def async_uow_factory(core_database: CoreDatabase) -> AsyncIterator[AsyncUnitOfWorkFactory]:
    factory = AsyncUnitOfWorkFactory(core_database.engine)
    try:
        yield factory
    finally:
        await factory.aclose()


@pytest.fixture
def clock() -> Clock:
    return FrozenClock(datetime(2026, 8, 27, 1, 2, 3, 4, tzinfo=UTC))


async def _seed_core_device(
    uow_factory: UnitOfWorkFactory,
    clock: Clock,
    *,
    last_sequence: int = 0,
) -> None:
    now = utc_storage(clock.now())

    def insert(transaction: UnitOfWorkProtocol) -> None:
        transaction.exec_driver_sql(
            "INSERT INTO households(id,display_label_ciphertext,timezone,created_at) "
            "VALUES(?,?,?,?)",
            (str(HOUSEHOLD_ID), b"synthetic", "Asia/Singapore", now),
        )
        transaction.exec_driver_sql(
            "INSERT INTO devices("
            "id,household_id,kind,certificate_fingerprint,signing_public_key,"
            "signing_key_id,last_sequence,paired_at"
            ") VALUES(?,?,?,?,?,?,?,?)",
            (
                str(DEVICE_ID),
                str(HOUSEHOLD_ID),
                "reachy",
                "synthetic-duplex-fingerprint",
                b"x" * 32,
                SIGNING_KEY_ID,
                last_sequence,
                now,
            ),
        )

    async with uow_factory() as uow:
        await uow.run_sync(insert)
        await uow.commit()


async def _core_scalar(
    uow_factory: UnitOfWorkFactory,
    statement: str,
    parameters: tuple[object, ...],
) -> object | None:
    def select(transaction: UnitOfWorkProtocol) -> object | None:
        row = transaction.exec_driver_sql(statement, parameters).fetchone()
        return None if row is None else row[0]

    async with uow_factory() as uow:
        value = await uow.run_sync(select)
        await uow.rollback()
        return value


async def _core_rows(
    uow_factory: UnitOfWorkFactory,
    statement: str,
    parameters: tuple[object, ...] = (),
) -> tuple[tuple[object, ...], ...]:
    def select(transaction: UnitOfWorkProtocol) -> tuple[tuple[object, ...], ...]:
        return tuple(tuple(row) for row in transaction.exec_driver_sql(statement, parameters))

    async with uow_factory() as uow:
        rows = await uow.run_sync(select)
        await uow.rollback()
        return rows


def _edge_path(tmp_path: Path) -> Path:
    return Path(os.path.realpath(tmp_path)) / "private" / "duplex.sqlite3"


def _edge_state(tmp_path: Path, clock: Clock) -> EdgeDuplexState:
    path = _edge_path(tmp_path)
    return EdgeDuplexState(path, clock, trusted_root=path.parent)


def _edge_scalar(path: Path, statement: str, parameters: tuple[object, ...] = ()) -> object | None:
    with sqlite3.connect(path) as db:
        row = db.execute(statement, parameters).fetchone()
    return None if row is None else row[0]


def _edge_columns(path: Path, table: str) -> frozenset[str]:
    with sqlite3.connect(path) as db:
        return frozenset(row[1] for row in db.execute(f"PRAGMA table_info({table!r})"))


def _retention_uuid(index: int) -> UUID:
    return UUID(int=0x10000000000000000000000000000000 + index)


def _storage_timestamp(index: int) -> str:
    return f"2026-08-27T01:02:03.{index:06d}Z"


async def _seed_core_terminal_pressure(
    uow_factory: UnitOfWorkFactory,
    *,
    terminal_count: int,
    pending_id: UUID,
) -> None:
    def insert(transaction: UnitOfWorkProtocol) -> None:
        transaction.exec_driver_sql(
            "INSERT INTO reachy_core_tx_sequences(device_id,last_sequence) VALUES(?,?)",
            (str(DEVICE_ID), 8_000),
        )
        transaction.exec_driver_sql(
            "INSERT INTO reachy_duplex_correlations("
            "device_id,correlation_id,purpose,request_direction,state,"
            "first_sequence,last_sequence,created_at,updated_at"
            ") VALUES(?,?,?,?,?,?,?,?,?)",
            (
                str(DEVICE_ID),
                str(pending_id),
                COMMAND_PURPOSE,
                "core_to_edge",
                "pending",
                8_001,
                8_001,
                _storage_timestamp(0),
                _storage_timestamp(0),
            ),
        )
        for index in range(terminal_count):
            sequence = index + 1
            transaction.exec_driver_sql(
                "INSERT INTO reachy_duplex_correlations("
                "device_id,correlation_id,purpose,request_direction,state,"
                "first_sequence,last_sequence,created_at,updated_at"
                ") VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    str(DEVICE_ID),
                    str(_retention_uuid(index)),
                    CONTROL_PURPOSE,
                    "core_to_edge",
                    "completed" if index % 2 else "abandoned",
                    sequence,
                    sequence,
                    _storage_timestamp(index + 1),
                    _storage_timestamp(index + 1),
                ),
            )

    async with uow_factory() as uow:
        await uow.run_sync(insert)
        await uow.commit()


async def _seed_core_pending_pressure(
    uow_factory: UnitOfWorkFactory,
    *,
    pending_count: int,
) -> tuple[UUID, ...]:
    pending_ids = tuple(_retention_uuid(10_000 + index) for index in range(pending_count))

    def insert(transaction: UnitOfWorkProtocol) -> None:
        transaction.exec_driver_sql(
            "INSERT INTO reachy_core_tx_sequences(device_id,last_sequence) VALUES(?,?)",
            (str(DEVICE_ID), 8_000),
        )
        for index, correlation_id in enumerate(pending_ids):
            transaction.exec_driver_sql(
                "INSERT INTO reachy_duplex_correlations("
                "device_id,correlation_id,purpose,request_direction,state,"
                "first_sequence,last_sequence,created_at,updated_at"
                ") VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    str(DEVICE_ID),
                    str(correlation_id),
                    COMMAND_PURPOSE,
                    "core_to_edge",
                    "pending",
                    index + 1,
                    index + 1,
                    _storage_timestamp(index),
                    _storage_timestamp(index),
                ),
            )

    async with uow_factory() as uow:
        await uow.run_sync(insert)
        await uow.commit()
    return pending_ids


def _seed_edge_terminal_pressure(
    path: Path,
    *,
    terminal_count: int,
    pending_id: UUID,
) -> None:
    with sqlite3.connect(path) as db:
        db.execute(
            "INSERT INTO edge_duplex_sequences(direction,last_sequence) VALUES(?,?)",
            ("edge_to_core", 8_000),
        )
        db.execute(
            "INSERT INTO edge_duplex_sequences(direction,last_sequence) VALUES(?,?)",
            ("core_to_edge", 7_000),
        )
        db.execute(
            "INSERT INTO edge_duplex_correlations("
            "correlation_id,purpose,request_direction,state,"
            "first_sequence,last_sequence,created_at,updated_at"
            ") VALUES(?,?,?,?,?,?,?,?)",
            (
                str(pending_id),
                COMMAND_PURPOSE,
                "edge_to_core",
                "pending",
                8_001,
                8_001,
                _storage_timestamp(0),
                _storage_timestamp(0),
            ),
        )
        db.executemany(
            "INSERT INTO edge_duplex_correlations("
            "correlation_id,purpose,request_direction,state,"
            "first_sequence,last_sequence,created_at,updated_at"
            ") VALUES(?,?,?,?,?,?,?,?)",
            (
                (
                    str(_retention_uuid(index)),
                    CONTROL_PURPOSE,
                    "edge_to_core",
                    "completed" if index % 2 else "abandoned",
                    index + 1,
                    index + 1,
                    _storage_timestamp(index + 1),
                    _storage_timestamp(index + 1),
                )
                for index in range(terminal_count)
            ),
        )


def _seed_edge_pending_pressure(path: Path, *, pending_count: int) -> tuple[UUID, ...]:
    pending_ids = tuple(_retention_uuid(20_000 + index) for index in range(pending_count))
    with sqlite3.connect(path) as db:
        db.execute(
            "INSERT INTO edge_duplex_sequences(direction,last_sequence) VALUES(?,?)",
            ("edge_to_core", 8_000),
        )
        db.executemany(
            "INSERT INTO edge_duplex_correlations("
            "correlation_id,purpose,request_direction,state,"
            "first_sequence,last_sequence,created_at,updated_at"
            ") VALUES(?,?,?,?,?,?,?,?)",
            (
                (
                    str(correlation_id),
                    COMMAND_PURPOSE,
                    "edge_to_core",
                    "pending",
                    index + 1,
                    index + 1,
                    _storage_timestamp(index),
                    _storage_timestamp(index),
                )
                for index, correlation_id in enumerate(pending_ids)
            ),
        )
    return pending_ids


def test_signed_frame_binds_every_control_field_and_payload(frame_crypto: FrameCrypto) -> None:
    frame = frame_crypto.signed_frame()
    raw = canonical_bytes(frame)
    parsed = parse_contract_json(
        SignedControlFrameV1,
        raw,
        max_bytes=200_000,
        require_canonical=True,
    )
    assert parsed == frame
    assert (
        verify_control_frame(
            frame_crypto.public_key,
            frame_crypto.hmac_root,
            parsed,
            expected_signing_key_id=SIGNING_KEY_ID,
            expected_hmac_key_id=HMAC_KEY_ID,
            expected_direction="edge_to_core",
            expected_nonce=frame_crypto.connection_nonce,
        )
        == PAYLOAD
    )

    mutations = (
        frame.model_copy(update={"direction": "core_to_edge"}),
        frame.model_copy(update={"kind": "response"}),
        frame.model_copy(
            update={"connection_nonce_b64": base64.b64encode(b"n" * 32).decode("ascii")}
        ),
        frame.model_copy(update={"sequence": 42}),
        frame.model_copy(update={"correlation_id": uuid4()}),
        frame.model_copy(update={"purpose": "reachy.command.v1"}),
        frame.model_copy(
            update={"payload_b64": base64.b64encode(b'{"request":"other"}').decode("ascii")}
        ),
        frame.model_copy(update={"signing_key_id": "ed25519:reachy-edge:v2"}),
        frame.model_copy(
            update={
                "payload_commitment": frame.payload_commitment.model_copy(
                    update={"key_id": "reachy-frame-hmac:v2"}
                )
            }
        ),
    )
    for mutation in mutations:
        with pytest.raises(PermissionError):
            verify_control_frame(
                frame_crypto.public_key,
                frame_crypto.hmac_root,
                mutation,
                expected_signing_key_id=SIGNING_KEY_ID,
                expected_hmac_key_id=HMAC_KEY_ID,
                expected_direction="edge_to_core",
                expected_nonce=frame_crypto.connection_nonce,
            )


def test_wire_contracts_fail_closed_for_hostile_json_and_oversized_payload(
    frame_crypto: FrameCrypto,
) -> None:
    challenge = DeviceChallengeV1(
        schema_version="tuntun.reachy-device-challenge.v1",
        challenge_b64=base64.b64encode(b"c" * 32).decode("ascii"),
        server_nonce_b64=base64.b64encode(b"s" * 32).decode("ascii"),
        endpoint_generation=1,
    )
    assert (
        parse_contract_json(
            DeviceChallengeV1,
            canonical_bytes(challenge),
            max_bytes=8_192,
            require_canonical=True,
        )
        == challenge
    )

    raw = canonical_bytes(frame_crypto.signed_frame())
    duplicate = raw.replace(b"{", b'{"schema_version":"shadow",', 1)
    for mutation in (
        b" " + raw,
        duplicate,
        raw.replace(b'"sequence":41', b'"sequence":true'),
    ):
        with pytest.raises((ContractParseError, ValidationError)):
            parse_contract_json(
                SignedControlFrameV1,
                mutation,
                max_bytes=200_000,
                require_canonical=True,
            )

    with pytest.raises(ValueError, match="payload too large"):
        sign_control_frame(
            frame_crypto.private_key,
            frame_crypto.hmac_root,
            signing_key_id=SIGNING_KEY_ID,
            hmac_key_id=HMAC_KEY_ID,
            direction="edge_to_core",
            kind="request",
            connection_nonce=frame_crypto.connection_nonce,
            sequence=1,
            correlation_id=uuid4(),
            purpose=CONTROL_PURPOSE,
            payload=b"x" * 131_073,
        )

    oversized = frame_crypto.signed_frame().model_copy(
        update={"payload_b64": base64.b64encode(b"x" * 131_073).decode("ascii")}
    )
    with pytest.raises(ValueError, match="payload too large"):
        decode_control_payload(oversized)


def test_signed_control_frame_json_cap_covers_the_max_payload(
    frame_crypto: FrameCrypto,
) -> None:
    frame_json_limit = getattr(reachy_wire, "MAX_CONTROL_FRAME_JSON_BYTES", None)
    assert isinstance(frame_json_limit, int)

    frame = sign_control_frame(
        frame_crypto.private_key,
        frame_crypto.hmac_root,
        signing_key_id="ed25519:reachy-edge-with-long-enough-id:v123456789",
        hmac_key_id="reachy-frame-hmac-with-long-enough-key-id:v123456789",
        direction="core_to_edge",
        kind="request",
        connection_nonce=frame_crypto.connection_nonce,
        sequence=9_007_199_254_740_991,
        correlation_id=UUID("ffffffff-ffff-ffff-ffff-ffffffffffff"),
        purpose="reachy.media_control.v1",
        payload=b"x" * reachy_wire.MAX_CONTROL_PAYLOAD_BYTES,
    )
    raw = canonical_bytes(frame)

    assert len(raw) <= frame_json_limit
    assert (
        parse_contract_json(
            SignedControlFrameV1,
            raw,
            max_bytes=frame_json_limit,
            require_canonical=True,
        )
        == frame
    )


def test_wire_rejects_untrusted_key_shapes_and_frame_subclasses(
    frame_crypto: FrameCrypto,
) -> None:
    frame = frame_crypto.signed_frame()

    class SignedControlFrameSubclass(SignedControlFrameV1):
        pass

    subclassed = SignedControlFrameSubclass.model_validate(frame.model_dump(mode="python"))
    with pytest.raises(TypeError, match="exact SignedControlFrameV1"):
        verify_control_frame(
            frame_crypto.public_key,
            frame_crypto.hmac_root,
            subclassed,
            expected_signing_key_id=SIGNING_KEY_ID,
            expected_hmac_key_id=HMAC_KEY_ID,
            expected_direction="edge_to_core",
            expected_nonce=frame_crypto.connection_nonce,
        )
    with pytest.raises(TypeError, match="Ed25519 private key"):
        sign_control_frame(
            b"not-a-key",  # type: ignore[arg-type]
            frame_crypto.hmac_root,
            signing_key_id=SIGNING_KEY_ID,
            hmac_key_id=HMAC_KEY_ID,
            direction="edge_to_core",
            kind="request",
            connection_nonce=frame_crypto.connection_nonce,
            sequence=1,
            correlation_id=uuid4(),
            purpose=CONTROL_PURPOSE,
            payload=PAYLOAD,
        )
    with pytest.raises(ValueError, match="HMAC root"):
        verify_control_frame(
            frame_crypto.public_key,
            b"short",
            frame,
            expected_signing_key_id=SIGNING_KEY_ID,
            expected_hmac_key_id=HMAC_KEY_ID,
            expected_direction="edge_to_core",
            expected_nonce=frame_crypto.connection_nonce,
        )


@pytest.mark.asyncio
async def test_core_duplex_sequences_correlations_survive_restart_and_reject_replay(
    async_uow_factory: UnitOfWorkFactory,
    clock: Clock,
) -> None:
    await _seed_core_device(async_uow_factory, clock, last_sequence=40)
    core = CoreDuplexState(async_uow_factory, DEVICE_ID, clock)
    correlation_id = uuid4()

    core_sequence = await core.reserve_outbound(correlation_id, CONTROL_PURPOSE, "request")
    await core.accept_inbound(41, correlation_id, CONTROL_PURPOSE, "response")
    await core.complete(correlation_id)

    restarted = CoreDuplexState(async_uow_factory, DEVICE_ID, clock)
    assert (
        await restarted.reserve_outbound(uuid4(), CONTROL_PURPOSE, "request") == core_sequence + 1
    )
    assert (
        await _core_scalar(
            async_uow_factory,
            "SELECT last_sequence FROM devices WHERE id=?",
            (str(DEVICE_ID),),
        )
        == 41
    )
    assert await _core_rows(
        async_uow_factory,
        "SELECT purpose,request_direction,state,first_sequence,last_sequence "
        "FROM reachy_duplex_correlations WHERE device_id=? AND correlation_id=?",
        (str(DEVICE_ID), str(correlation_id)),
    ) == ((CONTROL_PURPOSE, "core_to_edge", "completed", 1, 41),)

    with pytest.raises(PermissionError, match="replayed_sequence"):
        await restarted.accept_inbound(41, uuid4(), CONTROL_PURPOSE, "request")
    with pytest.raises(PermissionError, match="sequence_gap"):
        await restarted.accept_inbound(43, uuid4(), CONTROL_PURPOSE, "request")
    await restarted.accept_inbound(42, uuid4(), EVENT_PURPOSE, "event")


@pytest.mark.asyncio
async def test_core_duplex_rolls_back_failed_correlation_transitions(
    async_uow_factory: UnitOfWorkFactory,
    clock: Clock,
) -> None:
    await _seed_core_device(async_uow_factory, clock)
    core = CoreDuplexState(async_uow_factory, DEVICE_ID, clock)

    with pytest.raises(PermissionError, match="correlation_not_pending"):
        await core.reserve_outbound(uuid4(), CONTROL_PURPOSE, "response")

    assert (
        await _core_scalar(
            async_uow_factory,
            "SELECT last_sequence FROM reachy_core_tx_sequences WHERE device_id=?",
            (str(DEVICE_ID),),
        )
        is None
    )
    assert await core.reserve_outbound(uuid4(), CONTROL_PURPOSE, "request") == 1


@pytest.mark.asyncio
async def test_core_duplex_serializes_concurrent_sequence_allocation(
    async_uow_factory: UnitOfWorkFactory,
    clock: Clock,
) -> None:
    await _seed_core_device(async_uow_factory, clock)
    core = CoreDuplexState(async_uow_factory, DEVICE_ID, clock)
    sequences = await asyncio.gather(
        *(core.reserve_outbound(uuid4(), CONTROL_PURPOSE, "request") for _ in range(16))
    )
    assert sorted(sequences) == list(range(1, 17))


@pytest.mark.asyncio
async def test_core_disconnect_abandons_without_payload_replay(
    async_uow_factory: UnitOfWorkFactory,
    clock: Clock,
) -> None:
    await _seed_core_device(async_uow_factory, clock)
    core = CoreDuplexState(async_uow_factory, DEVICE_ID, clock)
    correlation_id = uuid4()

    await core.reserve_outbound(correlation_id, COMMAND_PURPOSE, "request")
    await core.accept_response(correlation_id, COMMAND_PURPOSE, b"do not persist me")
    await core.abandon_connection("heartbeat_lost")

    assert await core.pending_for_replay() == ()
    assert "payload" not in {
        row[1]
        for row in await _core_rows(
            async_uow_factory,
            "PRAGMA table_info('reachy_duplex_correlations')",
        )
    }
    with pytest.raises(PermissionError, match="correlation_not_pending"):
        await core.accept_response(correlation_id, COMMAND_PURPOSE, b"old")


@pytest.mark.asyncio
async def test_core_duplex_prunes_only_terminal_correlations_without_resetting_sequences(
    async_uow_factory: UnitOfWorkFactory,
    clock: Clock,
) -> None:
    await _seed_core_device(async_uow_factory, clock, last_sequence=7_000)
    pending_id = uuid4()
    await _seed_core_terminal_pressure(
        async_uow_factory,
        terminal_count=TERMINAL_CORRELATION_RETENTION_LIMIT + 2,
        pending_id=pending_id,
    )
    core = CoreDuplexState(async_uow_factory, DEVICE_ID, clock)

    assert await core.reserve_outbound(uuid4(), CONTROL_PURPOSE, "request") == 8_001

    assert (
        await _core_scalar(
            async_uow_factory,
            "SELECT COUNT(*) FROM reachy_duplex_correlations "
            "WHERE device_id=? AND state!='pending'",
            (str(DEVICE_ID),),
        )
        == TERMINAL_CORRELATION_RETENTION_LIMIT
    )
    assert (
        await _core_scalar(
            async_uow_factory,
            "SELECT state FROM reachy_duplex_correlations WHERE device_id=? AND correlation_id=?",
            (str(DEVICE_ID), str(pending_id)),
        )
        == "pending"
    )
    assert (
        await _core_scalar(
            async_uow_factory,
            "SELECT last_sequence FROM reachy_core_tx_sequences WHERE device_id=?",
            (str(DEVICE_ID),),
        )
        == 8_001
    )
    assert (
        await _core_scalar(
            async_uow_factory,
            "SELECT last_sequence FROM devices WHERE id=?",
            (str(DEVICE_ID),),
        )
        == 7_000
    )
    assert (
        await _core_scalar(
            async_uow_factory,
            "SELECT state FROM reachy_duplex_correlations WHERE device_id=? AND correlation_id=?",
            (str(DEVICE_ID), str(_retention_uuid(0))),
        )
        is None
    )


@pytest.mark.asyncio
async def test_core_duplex_bounds_pending_correlations_without_consuming_sequence(
    async_uow_factory: UnitOfWorkFactory,
    clock: Clock,
) -> None:
    await _seed_core_device(async_uow_factory, clock)
    pending_ids = await _seed_core_pending_pressure(
        async_uow_factory,
        pending_count=PENDING_CORRELATION_LIMIT,
    )
    core = CoreDuplexState(async_uow_factory, DEVICE_ID, clock)

    with pytest.raises(PermissionError, match="pending_correlation_limit"):
        await core.reserve_outbound(uuid4(), COMMAND_PURPOSE, "request")
    assert (
        await _core_scalar(
            async_uow_factory,
            "SELECT last_sequence FROM reachy_core_tx_sequences WHERE device_id=?",
            (str(DEVICE_ID),),
        )
        == 8_000
    )

    await core.complete(pending_ids[0])
    assert await core.reserve_outbound(uuid4(), COMMAND_PURPOSE, "request") == 8_001


def test_edge_duplex_creates_owner_only_full_sync_sqlite_store(
    tmp_path: Path,
    clock: Clock,
) -> None:
    path = _edge_path(tmp_path)
    state = EdgeDuplexState(path, clock, trusted_root=path.parent)
    assert type(state) is EdgeDuplexState
    assert stat.S_IMODE(path.parent.lstat().st_mode) == 0o700
    assert stat.S_IMODE(path.lstat().st_mode) == 0o600
    assert _edge_scalar(path, "PRAGMA journal_mode") == "delete"
    assert _edge_scalar(path, "PRAGMA synchronous") == 2
    assert _edge_columns(path, "edge_duplex_correlations").isdisjoint({"payload", "payload_b64"})


@pytest.mark.parametrize(
    "fault", ("relative_path", "unsafe_root_mode", "symlink_root", "symlink_file")
)
def test_edge_duplex_rejects_untrusted_store_paths(
    tmp_path: Path,
    clock: Clock,
    fault: str,
) -> None:
    root = Path(os.path.realpath(tmp_path)) / "private"
    path = root / "duplex.sqlite3"
    if fault == "relative_path":
        with pytest.raises(PermissionError, match="trusted path"):
            EdgeDuplexState(Path("duplex.sqlite3"), clock, trusted_root=root)
        return
    if fault == "unsafe_root_mode":
        root.mkdir(mode=0o755)
        with pytest.raises(PermissionError, match="ownership_or_mode"):
            EdgeDuplexState(path, clock, trusted_root=root)
        return
    if fault == "symlink_root":
        real = Path(os.path.realpath(tmp_path)) / "real-root"
        real.mkdir(mode=0o700)
        root.symlink_to(real)
        with pytest.raises(PermissionError, match="trusted path"):
            EdgeDuplexState(path, clock, trusted_root=root)
        return
    root.mkdir(mode=0o700)
    target = Path(os.path.realpath(tmp_path)) / "elsewhere.sqlite3"
    target.write_bytes(b"")
    os.chmod(target, 0o600)
    path.symlink_to(target)
    with pytest.raises(PermissionError, match="trusted path"):
        EdgeDuplexState(path, clock, trusted_root=root)


def test_edge_duplex_rejects_corrupt_restart(
    tmp_path: Path,
    clock: Clock,
) -> None:
    path = _edge_path(tmp_path)
    path.parent.mkdir(mode=0o700)
    path.write_bytes(b"not sqlite")
    os.chmod(path, 0o600)
    with pytest.raises(PermissionError, match="corrupt"):
        EdgeDuplexState(path, clock, trusted_root=path.parent)


@pytest.mark.asyncio
async def test_edge_duplex_detects_named_path_swap_during_sqlite_connect(
    tmp_path: Path,
    clock: Clock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path(os.path.realpath(tmp_path)) / "private"
    path = root / "duplex.sqlite3"
    replacement = root / "replacement.sqlite3"
    edge = EdgeDuplexState(path, clock, trusted_root=root)
    EdgeDuplexState(replacement, clock, trusted_root=root)
    original_connect = sqlite3.connect
    swapped = False

    def swapping_connect(
        database: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *args: Any,
        **kwargs: Any,
    ) -> sqlite3.Connection:
        nonlocal swapped
        if not swapped and Path(os.fsdecode(os.fspath(database))) == path:
            swapped = True
            os.replace(replacement, path)
        return cast(sqlite3.Connection, original_connect(database, *args, **kwargs))

    monkeypatch.setattr(sqlite3, "connect", swapping_connect)

    with pytest.raises(PermissionError, match="store_replaced"):
        await edge.reserve_outbound(uuid4(), CONTROL_PURPOSE, "request")
    assert swapped


@pytest.mark.asyncio
async def test_edge_duplex_runs_integrity_check_at_startup_and_bounded_maintenance(
    tmp_path: Path,
    clock: Clock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    integrity_checks: list[str] = []
    original_connect = sqlite3.connect

    def record_statement(statement: str) -> None:
        if statement.strip().lower() == "pragma integrity_check":
            integrity_checks.append(statement)

    def counting_connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        connection = cast(sqlite3.Connection, original_connect(*args, **kwargs))
        connection.set_trace_callback(record_statement)
        return connection

    monkeypatch.setattr(sqlite3, "connect", counting_connect)
    monkeypatch.setattr(
        edge_duplex_module, "_EDGE_INTEGRITY_CHECK_WRITE_INTERVAL", 2, raising=False
    )
    edge = _edge_state(tmp_path, clock)

    assert len(integrity_checks) == 1
    await edge.reserve_outbound(uuid4(), CONTROL_PURPOSE, "request")
    assert len(integrity_checks) == 1
    await edge.reserve_outbound(uuid4(), CONTROL_PURPOSE, "request")
    assert len(integrity_checks) == 2


@pytest.mark.asyncio
async def test_edge_duplex_sequences_correlations_survive_restart_and_reject_replay(
    tmp_path: Path,
    clock: Clock,
) -> None:
    path = _edge_path(tmp_path)
    edge = EdgeDuplexState(path, clock, trusted_root=path.parent)
    correlation_id = uuid4()

    edge_sequence = await edge.reserve_outbound(correlation_id, CONTROL_PURPOSE, "request")
    await edge.accept_inbound(1, correlation_id, CONTROL_PURPOSE, "response")
    await edge.complete(correlation_id)

    restarted = EdgeDuplexState(path, clock, trusted_root=path.parent)
    assert await restarted.reserve_event_envelope_sequence(uuid4()) == edge_sequence + 1
    assert (
        _edge_scalar(
            path,
            "SELECT last_sequence FROM edge_duplex_sequences WHERE direction='core_to_edge'",
        )
        == 1
    )
    assert (
        _edge_scalar(
            path,
            "SELECT state FROM edge_duplex_correlations WHERE correlation_id=?",
            (str(correlation_id),),
        )
        == "completed"
    )

    with pytest.raises(PermissionError, match="replayed_sequence"):
        await restarted.accept_inbound(1, uuid4(), CONTROL_PURPOSE, "request")
    with pytest.raises(PermissionError, match="sequence_gap"):
        await restarted.accept_inbound(3, uuid4(), CONTROL_PURPOSE, "request")
    await restarted.accept_inbound(2, uuid4(), EVENT_PURPOSE, "event")


@pytest.mark.asyncio
async def test_edge_duplex_rolls_back_failed_receive_and_never_persists_payloads(
    tmp_path: Path,
    clock: Clock,
) -> None:
    path = _edge_path(tmp_path)
    edge = EdgeDuplexState(path, clock, trusted_root=path.parent)

    with pytest.raises(PermissionError, match="correlation_not_pending"):
        await edge.accept_inbound(1, uuid4(), CONTROL_PURPOSE, "response")

    assert (
        _edge_scalar(
            path,
            "SELECT last_sequence FROM edge_duplex_sequences WHERE direction='core_to_edge'",
        )
        is None
    )
    correlation_id = uuid4()
    await edge.reserve_outbound(correlation_id, COMMAND_PURPOSE, "request")
    await edge.accept_response(correlation_id, COMMAND_PURPOSE, b"secret payload")
    await edge.abandon_connection("disconnect")

    assert await edge.pending_for_replay() == ()
    assert b"secret payload" not in path.read_bytes()
    with pytest.raises(PermissionError, match="correlation_not_pending"):
        await edge.accept_response(correlation_id, COMMAND_PURPOSE, b"old")


@pytest.mark.asyncio
async def test_edge_duplex_prunes_only_terminal_correlations_without_resetting_sequences(
    tmp_path: Path,
    clock: Clock,
) -> None:
    path = _edge_path(tmp_path)
    edge = EdgeDuplexState(path, clock, trusted_root=path.parent)
    pending_id = uuid4()
    _seed_edge_terminal_pressure(
        path,
        terminal_count=TERMINAL_CORRELATION_RETENTION_LIMIT + 2,
        pending_id=pending_id,
    )

    assert await edge.reserve_outbound(uuid4(), CONTROL_PURPOSE, "request") == 8_001

    assert (
        _edge_scalar(
            path,
            "SELECT COUNT(*) FROM edge_duplex_correlations WHERE state!='pending'",
        )
        == TERMINAL_CORRELATION_RETENTION_LIMIT
    )
    assert (
        _edge_scalar(
            path,
            "SELECT state FROM edge_duplex_correlations WHERE correlation_id=?",
            (str(pending_id),),
        )
        == "pending"
    )
    assert (
        _edge_scalar(
            path,
            "SELECT last_sequence FROM edge_duplex_sequences WHERE direction='edge_to_core'",
        )
        == 8_001
    )
    assert (
        _edge_scalar(
            path,
            "SELECT last_sequence FROM edge_duplex_sequences WHERE direction='core_to_edge'",
        )
        == 7_000
    )
    assert (
        _edge_scalar(
            path,
            "SELECT state FROM edge_duplex_correlations WHERE correlation_id=?",
            (str(_retention_uuid(0)),),
        )
        is None
    )


@pytest.mark.asyncio
async def test_edge_duplex_bounds_pending_correlations_without_consuming_sequence(
    tmp_path: Path,
    clock: Clock,
) -> None:
    path = _edge_path(tmp_path)
    edge = EdgeDuplexState(path, clock, trusted_root=path.parent)
    pending_ids = _seed_edge_pending_pressure(
        path,
        pending_count=PENDING_CORRELATION_LIMIT,
    )

    with pytest.raises(PermissionError, match="pending_correlation_limit"):
        await edge.reserve_outbound(uuid4(), COMMAND_PURPOSE, "request")
    assert (
        _edge_scalar(
            path,
            "SELECT last_sequence FROM edge_duplex_sequences WHERE direction='edge_to_core'",
        )
        == 8_000
    )

    await edge.complete(pending_ids[0])
    assert await edge.reserve_outbound(uuid4(), COMMAND_PURPOSE, "request") == 8_001


@pytest.mark.asyncio
async def test_edge_duplex_rejects_naive_timestamps_before_persistence(tmp_path: Path) -> None:
    path = _edge_path(tmp_path)
    edge = EdgeDuplexState(
        path, NaiveClock(datetime(2026, 8, 27, 1, 2, 3)), trusted_root=path.parent
    )
    with pytest.raises(TypeError, match="timezone-aware"):
        await edge.reserve_outbound(uuid4(), CONTROL_PURPOSE, "request")
    assert (
        _edge_scalar(
            path,
            "SELECT last_sequence FROM edge_duplex_sequences WHERE direction='edge_to_core'",
        )
        is None
    )


@pytest.mark.asyncio
async def test_edge_duplex_serializes_concurrent_sequence_allocation(
    tmp_path: Path,
    clock: Clock,
) -> None:
    edge = _edge_state(tmp_path, clock)
    sequences = await asyncio.gather(
        *(edge.reserve_outbound(uuid4(), CONTROL_PURPOSE, "request") for _ in range(16))
    )
    assert sorted(sequences) == list(range(1, 17))
