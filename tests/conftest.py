from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol, cast
from uuid import UUID

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine
from tuntun_contracts.audit import AuditDraft, AuditReceipt
from tuntun_contracts.base import Commitment
from tuntun_contracts.ports import ClockPort
from tuntun_core.adapters.sqlcipher.engine import create_sqlcipher_engine
from tuntun_core.adapters.sqlcipher.unit_of_work import UnitOfWork
from tuntun_core.services.audit.ledger import AuditLedger, AuditSegment
from tuntun_core.services.audit.verifier import AuditVerification, AuditVerifier
from tuntun_testing.fake_clock import FakeClock  # type: ignore[import-untyped]


class AuditTestClock(ClockPort, Protocol):
    @property
    def calls(self) -> tuple[str, ...]: ...


@dataclass(frozen=True, slots=True)
class AuditedDatabase:
    engine: Engine
    path: Path
    key: bytes


def create_database(path: Path) -> AuditedDatabase:
    key = bytes(range(32))
    config = Config("apps/core/alembic.ini")
    config.attributes["sqlcipher_path"] = path
    config.attributes["sqlcipher_key"] = key
    command.upgrade(config, "0001_foundation")
    return AuditedDatabase(create_sqlcipher_engine(path, key), path, key)


def draft(index: int, *, action_code: str = "foundation.fixture") -> AuditDraft:
    return AuditDraft(
        event_id=UUID(int=700 + index),
        occurred_at=datetime(2026, 8, 27, tzinfo=UTC) + timedelta(microseconds=index),
        actor_pseudonym="synthetic-guest",
        action_code=action_code,
        outcome="allow",
        reason_code=f"fixture-{index}",
        correlation_id=UUID(int=800 + index),
        payload_commitment=Commitment(
            algorithm="HMAC-SHA-256",
            key_id="audit-v1",
            value_b64="A" * 43 + "=",
        ),
    )


def audit_clock() -> AuditTestClock:
    return cast(
        AuditTestClock,
        FakeClock(datetime(2026, 8, 27, 12, 34, 56, 789123, tzinfo=UTC)),
    )


def append(
    database: AuditedDatabase,
    key_id: str,
    key: bytes,
    index: int,
    clock: ClockPort,
) -> AuditReceipt:
    with UnitOfWork(database.engine) as uow:
        receipt = AuditLedger(key_id, key, clock).append(uow, draft(index))
        uow.commit()
    return receipt


def dispose_database(database: AuditedDatabase) -> None:
    database.engine.dispose()
    for candidate in database_files(database):
        candidate.unlink(missing_ok=True)


def database_files(database: AuditedDatabase) -> tuple[Path, ...]:
    return (
        database.path,
        Path(f"{database.path}-wal"),
        Path(f"{database.path}-shm"),
    )


class AuditFixture:
    def __init__(self, database: AuditedDatabase, clock: AuditTestClock) -> None:
        self.database = database
        self.clock = clock
        self.keys = {"audit-v1": b"K" * 32}

    def append_with_key(self, key_id: str, key: bytes, index: int) -> AuditReceipt:
        self.keys[key_id] = key
        return append(self.database, key_id, key, index, self.clock)

    def append_index(self, index: int) -> AuditReceipt:
        return self.append_with_key("audit-v1", b"K" * 32, index)

    def seal(self, first_ordinal: int, last_ordinal: int) -> AuditSegment:
        with UnitOfWork(self.database.engine) as uow:
            segment = AuditLedger("audit-v1", b"K" * 32, self.clock).seal(
                uow,
                first_ordinal,
                last_ordinal,
            )
            uow.commit()
        return segment

    def segment_sealed_at(self, segment_id: str) -> str:
        with self.database.engine.connect() as connection:
            value = connection.exec_driver_sql(
                "SELECT sealed_at FROM audit_segments WHERE id = ?",
                (segment_id,),
            ).scalar_one()
        return str(value)

    def canonical_body(self, ordinal: int) -> str:
        with self.database.engine.connect() as connection:
            value = connection.exec_driver_sql(
                "SELECT canonical_body_json FROM audit_receipts WHERE ordinal = ?",
                (ordinal,),
            ).scalar_one()
        return str(value)

    def verify(self, keys: dict[str, bytes] | None = None) -> AuditVerification:
        with self.database.engine.connect() as connection:
            return AuditVerifier(self.keys if keys is None else keys).verify(connection)

    def replace_canonical_body_offline(self, mutation: str) -> None:
        bodies = {
            "duplicate_key": '{"event_id":"x","event_id":"y"}',
            "noncanonical_whitespace": '{ "event_id" : "x" }',
            "overdeep_json": "[" * 33 + "0" + "]" * 33,
            "flat_json_overflow": "[" + ",".join("0" for _ in range(16_385)) + "]",
            "body_over_64k": '"' + "x" * 65_537 + '"',
        }
        try:
            body = bodies[mutation]
        except KeyError as error:
            raise AssertionError(f"unknown audit mutation: {mutation}") from error
        if self.verify().count == 0:
            self.append_index(1)
        with self.database.engine.begin() as connection:
            connection.exec_driver_sql("DROP TRIGGER IF EXISTS audit_receipts_no_update")
            connection.exec_driver_sql(
                "UPDATE audit_receipts SET canonical_body_json = ? WHERE ordinal = 1",
                (body,),
            )

    def replace_receipt_column_offline(
        self,
        column: str,
        value: object,
        *,
        ordinal: int = 1,
    ) -> None:
        allowed = {
            "ordinal",
            "previous_public_hash_hex",
            "public_hash_hex",
            "hmac_key_id",
            "hmac_b64",
            "canonical_body_json",
            "occurred_at",
        }
        if column not in allowed:
            raise AssertionError(f"unsupported receipt mutation: {column}")
        if self.verify().count == 0:
            self.append_index(1)
        with self.database.engine.begin() as connection:
            connection.exec_driver_sql("DROP TRIGGER IF EXISTS audit_receipts_no_update")
            connection.exec_driver_sql("PRAGMA ignore_check_constraints = ON")
            connection.exec_driver_sql(
                f"UPDATE audit_receipts SET {column} = ? WHERE ordinal = ?",
                (value, ordinal),
            )

    def delete_receipt_offline(self, ordinal: int) -> None:
        with self.database.engine.begin() as connection:
            connection.exec_driver_sql("DROP TRIGGER IF EXISTS audit_receipts_no_delete")
            connection.exec_driver_sql(
                "DELETE FROM audit_receipts WHERE ordinal = ?",
                (ordinal,),
            )

    def replace_segment_column_offline(self, column: str, value: object) -> None:
        allowed = {
            "id",
            "first_ordinal",
            "last_ordinal",
            "receipt_count",
            "terminal_public_hash_hex",
            "terminal_hmac_b64",
            "hmac_key_id",
            "sealed_at",
        }
        if column not in allowed:
            raise AssertionError(f"unsupported segment mutation: {column}")
        with self.database.engine.begin() as connection:
            connection.exec_driver_sql("PRAGMA ignore_check_constraints = ON")
            connection.exec_driver_sql(
                f"UPDATE audit_segments SET {column} = ?",
                (value,),
            )


@pytest.fixture
def audited_database(tmp_path: Path) -> Iterator[AuditedDatabase]:
    database = create_database(tmp_path / "audited.db")
    clock = audit_clock()
    append(database, "audit-v1", b"K" * 32, 1, clock)
    append(database, "audit-v1", b"K" * 32, 2, clock)
    try:
        yield database
    finally:
        dispose_database(database)


@pytest.fixture
def audit_fixture(tmp_path: Path) -> Iterator[AuditFixture]:
    database = create_database(tmp_path / "audit-fixture.db")
    fixture = AuditFixture(database, audit_clock())
    try:
        yield fixture
    finally:
        dispose_database(database)
