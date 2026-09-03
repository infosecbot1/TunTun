from __future__ import annotations

import ast
import json
import os
import sqlite3
import stat
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Column, Integer, MetaData, Table, create_engine, event, text
from sqlcipher3 import dbapi2 as sqlcipher3  # type: ignore[import-untyped]
from tuntun_core.adapters.sqlcipher import connection as connection_module
from tuntun_core.adapters.sqlcipher import engine as engine_module
from tuntun_core.adapters.sqlcipher import migrations as migration_module
from tuntun_core.adapters.sqlcipher.connection import open_sqlcipher
from tuntun_core.adapters.sqlcipher.engine import create_sqlcipher_engine
from tuntun_core.adapters.sqlcipher.foundation_0001 import (
    FOUNDATION_0001_METADATA,
    FOUNDATION_TABLE_NAMES,
)
from tuntun_core.adapters.sqlcipher.migrations import encrypted_backup, upgrade_encrypted
from tuntun_core.adapters.sqlcipher.models import metadata

KEY = bytes(range(32))
WRONG_KEY = bytes(reversed(range(32)))
EXPECTED_TABLES = {
    "alembic_version",
    "households",
    "devices",
    "sessions",
    "event_receipts",
    "idempotency_receipts",
    "audit_receipts",
    "audit_segments",
    "redaction_receipts",
    "provider_calls",
    "provider_response_receipts",
    "provider_prices",
    "budget_reservations",
    "cost_ledger",
    "runtime_settings",
    "reachy_core_tx_sequences",
    "reachy_duplex_correlations",
}
EXPECTED_TRIGGERS = {"audit_receipts_no_update", "audit_receipts_no_delete"}
TASK1_TABLES = {
    "subjects",
    "current_owner_authority",
    "consent_receipts",
    "guest_disclosure_challenges",
    "guest_session_consent_receipts",
    "enrollment_sessions",
    "biometric_templates",
    "subject_revocation_outbox",
    "subject_revocation_effects",
}
EXPECTED_HEAD_TABLES = EXPECTED_TABLES | TASK1_TABLES
MAX_QUOTE_MICROS_SGD = 1_000_000_000_000

assert len(EXPECTED_TABLES) == 17
assert len(EXPECTED_HEAD_TABLES) == 26


def _private_path(tmp_path: Path, name: str) -> Path:
    root = Path(os.path.realpath(tmp_path)) / "private"
    root.mkdir(mode=0o700, exist_ok=True)
    root.chmod(0o700)
    return root / name


def _config(path: Path, key: bytes = KEY) -> Config:
    config = Config("apps/core/alembic.ini")
    config.attributes["sqlcipher_path"] = path
    config.attributes["sqlcipher_key"] = key
    return config


def _non_sqlite_tables(db: sqlcipher3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        if not str(row[0]).startswith("sqlite_")
    }


def _triggers(db: sqlcipher3.Connection) -> set[str]:
    return {
        str(row[0]) for row in db.execute("SELECT name FROM sqlite_master WHERE type='trigger'")
    }


def _inject_unreleased_initialization_failure(
    monkeypatch: pytest.MonkeyPatch,
    opener_owner: object,
    target: Path,
) -> list[bool]:
    release_allowed = [False]
    real_open = connection_module.open_sqlcipher
    real_base_close = connection_module.QualifiedSQLCipherConnection._close_sqlcipher_base

    def fail_target_close(connection: object) -> None:
        guard = connection._path_guard  # type: ignore[attr-defined]
        if guard is not None and guard.path == target and not release_allowed[0]:
            raise RuntimeError("injected retained initialization close failure")
        real_base_close(connection)  # type: ignore[arg-type]

    def fail_target_open(path: Path, key: bytes) -> sqlcipher3.Connection:
        if path != target:
            return real_open(path, key)
        real_checkpoint = connection_module._initialization_checkpoint

        def fail_at_integrity(name: str) -> None:
            real_checkpoint(name)
            if name == "integrity":
                raise RuntimeError("injected destination initialization failure")

        connection_module._initialization_checkpoint = fail_at_integrity
        try:
            return real_open(path, key)
        finally:
            connection_module._initialization_checkpoint = real_checkpoint

    monkeypatch.setattr(
        connection_module.QualifiedSQLCipherConnection,
        "_close_sqlcipher_base",
        fail_target_close,
    )
    monkeypatch.setattr(opener_owner, "open_sqlcipher", fail_target_open)
    return release_allowed


def _inject_unreleased_prebind_failure(
    monkeypatch: pytest.MonkeyPatch,
    target: Path,
) -> list[bool]:
    release_allowed = [False]
    prebind_connections: set[int] = set()
    real_bind = connection_module.QualifiedSQLCipherConnection._bind_path_guard
    real_base_close = connection_module.QualifiedSQLCipherConnection._close_sqlcipher_base

    def fail_target_bind(
        connection: object,
        guard: connection_module.DatabasePathGuard,
    ) -> None:
        if guard.path == target:
            prebind_connections.add(id(connection))
            raise RuntimeError("injected pre-bind initialization failure")
        real_bind(connection, guard)  # type: ignore[arg-type]

    def fail_target_close(connection: object) -> None:
        if id(connection) in prebind_connections and not release_allowed[0]:
            raise RuntimeError("injected retained pre-bind close failure")
        real_base_close(connection)  # type: ignore[arg-type]

    monkeypatch.setattr(
        connection_module.QualifiedSQLCipherConnection,
        "_bind_path_guard",
        fail_target_bind,
    )
    monkeypatch.setattr(
        connection_module.QualifiedSQLCipherConnection,
        "_close_sqlcipher_base",
        fail_target_close,
    )
    return release_allowed


def _release_quarantined_connection(
    error: connection_module.SQLCipherCleanupError,
    target: Path,
    release_allowed: list[bool],
) -> None:
    failed_connection = error.connection
    main, sidecars = failed_connection.storage_identities()  # type: ignore[attr-defined]
    expected = {
        target: (main.device, main.inode),
        **{
            Path(f"{target}{suffix}"): (identity.device, identity.inode)
            for suffix, identity in sidecars
        },
    }
    assert set(expected) == {target, Path(f"{target}-wal"), Path(f"{target}-shm")}
    state = connection_module._registry_snapshot(target)
    assert state is not None
    assert (state.active, state.initializing, state.failed_closes) == (0, 1, 1)
    for candidate, identity in expected.items():
        value = candidate.stat()
        assert (value.st_dev, value.st_ino) == identity

    release_allowed[0] = True
    failed_connection.close()
    assert connection_module._registry_snapshot(target) is None
    for candidate, identity in expected.items():
        if candidate.exists():
            value = candidate.stat()
            assert (value.st_dev, value.st_ino) == identity
            candidate.unlink()


def _release_prebind_quarantine(
    error: connection_module.SQLCipherCleanupError,
    target: Path,
    release_allowed: list[bool],
) -> None:
    guard = error.guard
    assert guard is not None
    assert error.connection._path_guard is None  # type: ignore[attr-defined]
    assert guard.sidecar_identities == ()
    expected = (guard.main_identity.device, guard.main_identity.inode)
    value = target.stat()
    assert (value.st_dev, value.st_ino) == expected
    state = connection_module._registry_snapshot(target)
    assert state is not None
    assert (state.active, state.initializing, state.failed_closes) == (0, 1, 0)
    notes = getattr(error, "__notes__", ())
    assert "initialization path guard remains quarantined" in notes

    release_allowed[0] = True
    error.connection.close()
    state = connection_module._registry_snapshot(target)
    assert state is not None
    assert (state.active, state.initializing, state.failed_closes) == (0, 1, 0)
    assert (target.stat().st_dev, target.stat().st_ino) == expected
    with connection_module._hold_open_lock():
        guard.rollback_connect_failure_locked()
    assert connection_module._registry_snapshot(target) is None
    value = target.stat()
    assert (value.st_dev, value.st_ino) == expected
    target.unlink()


def _valid_price(identifier: str) -> dict[str, object]:
    return {
        "id": identifier,
        "provider": "openai",
        "model": "gpt-5.6-sol",
        "category": "llm",
        "currency": "USD",
        "tier_basis": "flat",
        "tier_min": 0,
        "tier_max": 0,
        "input_rate": 4_000_000,
        "output_rate": 20_000_000,
        "audio_rate": 0,
        "search_rate": 0,
        "basis": "provider_reported_exact",
        "missing_policy": "freeze_unknown_overage",
        "fx_rate": 1_500_000,
        "pricing_version": "openai-2026-08-27",
        "source_url": "https://developers.openai.com/api/docs/pricing",
        "price_sha": "a" * 64,
        "fx_version": "bootstrap-safety-factor-2026-08-27",
        "fx_sha": "b" * 64,
        "effective_at": "2026-08-27T00:00:00.000000Z",
        "expires_at": "2026-09-27T00:00:00.000000Z",
    }


PRICE_SQL = """INSERT INTO provider_prices
    (id,provider,model,category,native_currency,tier_basis,
     tier_min_input_tokens,tier_max_input_tokens,input_micro_usd_per_million,
     output_micro_usd_per_million,audio_micro_usd_per_minute,
     web_search_micro_usd_per_call,primary_accounting_basis,
     missing_evidence_policy,fx_micros_sgd,pricing_version,price_source_url,
     price_source_sha256,fx_version,fx_source_sha256,effective_at,expires_at)
    VALUES (:id,:provider,:model,:category,:currency,:tier_basis,:tier_min,:tier_max,
     :input_rate,:output_rate,:audio_rate,:search_rate,:basis,:missing_policy,:fx_rate,
     :pricing_version,:source_url,:price_sha,:fx_version,:fx_sha,:effective_at,:expires_at)"""


def _valid_reservation(identifier: str, attempt_id: str) -> dict[str, object]:
    return {
        "id": identifier,
        "request_id": "00000000-0000-0000-0000-000000000502",
        "attempt_id": attempt_id,
        "month_key": "2026-08",
        "category": "llm",
        "provider": "openai",
        "model": "gpt-5.6-sol",
        "outcome": "allow",
        "reserved": 100,
        "charged": None,
        "usage": json.dumps({"category": "llm", "input_tokens": 10, "output_tokens": 5}),
        "snapshot": json.dumps(
            {
                "provider": "openai",
                "pricing_version": "openai-2026-08-27",
                "tiers": [{"minimum": 0, "maximum": 0, "input_rate": 4_000_000}],
            }
        ),
        "pricing_version": "openai-2026-08-27",
        "price_sha": "a" * 64,
        "basis": "provider_reported_exact",
        "missing_policy": "freeze_unknown_overage",
        "fx_version": "bootstrap-safety-factor-2026-08-27",
        "fx_sha": "b" * 64,
        "commitment_key": "pricing-v1",
        "commitment_hmac": "A" * 43 + "=",
        "overrun": 0,
        "state": "reserved",
        "phase": "not_claimed",
        "created_at": "2026-08-27T01:02:03.000004Z",
        "expires_at": "2026-08-27T01:17:03.000004Z",
        "settled_at": None,
        "reconciled_at": None,
    }


def _settled_reservation(identifier: str, attempt_id: str) -> dict[str, object]:
    return _valid_reservation(identifier, attempt_id) | {
        "charged": 100,
        "state": "settled",
        "phase": "finished",
        "settled_at": "2026-08-27T01:03:03.000004Z",
        "reconciled_at": "2026-08-27T01:04:03.000004Z",
    }


RESERVATION_SQL = """INSERT INTO budget_reservations
    (id,request_id,attempt_id,month_key,category,provider,model,outcome,
     reserved_micros_sgd,charged_micros_sgd,usage_ceiling_json,price_snapshot_json,
     pricing_version,price_source_sha256,primary_accounting_basis,
     missing_evidence_policy,fx_version,fx_source_sha256,pricing_commitment_key_id,
     pricing_commitment_hmac_b64,estimate_overrun,state,gateway_ordering_version,
     transport_phase,created_at,expires_at,settled_at,reconciled_at)
    VALUES (:id,:request_id,:attempt_id,:month_key,:category,:provider,:model,:outcome,
     :reserved,:charged,:usage,:snapshot,:pricing_version,:price_sha,:basis,
     :missing_policy,:fx_version,:fx_sha,:commitment_key,:commitment_hmac,:overrun,
     :state,1,:phase,:created_at,:expires_at,:settled_at,:reconciled_at)"""

PROVIDER_CALL_SQL = """INSERT INTO provider_calls
    (id,request_id,attempt_id,authorization_id,budget_reservation_id,purpose,
     provider,model,request_hmac_key_id,request_hmac_b64,response_hmac_key_id,
     response_hmac_b64,category,outcome,gateway_ordering_version,transport_phase,
     provider_usage_json,provider_usage_receipt_key_id,
     provider_usage_receipt_hmac_b64,started_at,finished_at)
    VALUES (:id,:request_id,:attempt_id,:authorization_id,:reservation_id,:purpose,
     :provider,:model,:request_key,:request_hmac,:response_key,:response_hmac,
     :category,:outcome,1,:phase,:usage,:usage_key,:usage_hmac,:started_at,:finished_at)"""


def _valid_call(
    reservation: dict[str, object],
    *,
    identifier: str,
    authorization_id: str,
    purpose: str = "cloud_reasoning",
) -> dict[str, object]:
    return {
        "id": identifier,
        "request_id": reservation["request_id"],
        "attempt_id": reservation["attempt_id"],
        "authorization_id": authorization_id,
        "reservation_id": reservation["id"],
        "purpose": purpose,
        "provider": reservation["provider"],
        "model": reservation["model"],
        "request_key": "provider-request-v1",
        "request_hmac": "A" * 43 + "=",
        "response_key": None,
        "response_hmac": None,
        "category": reservation["category"],
        "outcome": "started",
        "phase": "claim_begun",
        "usage": None,
        "usage_key": None,
        "usage_hmac": None,
        "started_at": "2026-08-27T01:02:03.000004Z",
        "finished_at": None,
    }


LEDGER_SQL = """INSERT INTO cost_ledger
    (id,reservation_id,month_key,reserved_micros_sgd,charged_micros_sgd,
     usage_json,provider_usage_receipt_json,provider_usage_receipt_key_id,
     provider_usage_receipt_hmac_b64,accounting_basis,
     reservation_primary_accounting_basis,reservation_missing_evidence_policy,
     conservative_estimate_used,estimate_overrun,hard_cap_exceeded,
     pricing_version,price_source_sha256,fx_version,fx_source_sha256,settled_at)
    VALUES (:id,:reservation_id,:month_key,:reserved,:charged,:usage,:receipt,
     :receipt_key,:receipt_hmac,:basis,:reservation_basis,:reservation_missing_policy,
     :conservative,:overrun,:hard_cap,:pricing_version,:price_sha,:fx_version,
     :fx_sha,:settled_at)"""

PROVIDER_RESPONSE_SQL = """INSERT INTO provider_response_receipts
    (id,request_id,attempt_id,authorization_id,household_id,subject_id,session_id,
     turn_id,provider,model,output_schema_version,response_hmac_key_id,
     response_hmac_b64,receipt_hmac_key_id,receipt_hmac_b64,produced_at)
    VALUES (:id,:request_id,:attempt_id,:authorization_id,:household_id,:subject_id,
     :session_id,:turn_id,:provider,:model,'assistant-turn-v1',:response_key,
     :response_hmac,:receipt_key,:receipt_hmac,:produced_at)"""


def _valid_ledger(
    reservation: dict[str, object],
    *,
    identifier: str,
) -> dict[str, object]:
    return {
        "id": identifier,
        "reservation_id": reservation["id"],
        "month_key": reservation["month_key"],
        "reserved": reservation["reserved"],
        "charged": reservation["charged"],
        "usage": "{}",
        "receipt": None,
        "receipt_key": None,
        "receipt_hmac": None,
        "basis": None,
        "reservation_basis": reservation["basis"],
        "reservation_missing_policy": reservation["missing_policy"],
        "conservative": 1,
        "overrun": reservation["overrun"],
        "hard_cap": 0,
        "pricing_version": reservation["pricing_version"],
        "price_sha": reservation["price_sha"],
        "fx_version": reservation["fx_version"],
        "fx_sha": reservation["fx_sha"],
        "settled_at": reservation["settled_at"],
    }


def test_foundation_upgrade_downgrade_upgrade(tmp_path: Path) -> None:
    path = _private_path(tmp_path, "foundation.db")
    config = _config(path)

    command.upgrade(config, "0001_foundation")
    db = open_sqlcipher(path, KEY)
    assert _non_sqlite_tables(db) == EXPECTED_TABLES
    assert _triggers(db) == EXPECTED_TRIGGERS
    assert db.execute("SELECT version_num FROM alembic_version").fetchall() == [
        ("0001_foundation",)
    ]
    db.execute(
        """INSERT INTO audit_receipts
        (id,ordinal,previous_public_hash_hex,public_hash_hex,hmac_key_id,hmac_b64,
         canonical_body_json,occurred_at) VALUES (?,?,?,?,?,?,?,?)""",
        (
            "00000000-0000-0000-0000-000000000001",
            1,
            None,
            "a" * 64,
            "audit-v1",
            "A" * 43 + "=",
            "{}",
            "2026-08-27T01:02:03.000004Z",
        ),
    )
    with pytest.raises(sqlcipher3.IntegrityError, match="append-only"):
        db.execute("UPDATE audit_receipts SET ordinal=2")
    with pytest.raises(sqlcipher3.IntegrityError, match="append-only"):
        db.execute("DELETE FROM audit_receipts")
    db.close()

    command.downgrade(config, "base")
    db = open_sqlcipher(path, KEY)
    assert _non_sqlite_tables(db) == {"alembic_version"}
    assert _triggers(db) == set()
    assert db.execute("SELECT version_num FROM alembic_version").fetchall() == []
    db.close()

    command.upgrade(config, "head")
    db = open_sqlcipher(path, KEY)
    assert _non_sqlite_tables(db) == EXPECTED_HEAD_TABLES
    assert _triggers(db) == EXPECTED_TRIGGERS
    db.close()


def test_revision_0001_ignores_tables_added_to_future_application_metadata(
    tmp_path: Path,
) -> None:
    future = Table("future_phase_table", metadata, Column("id", Integer, primary_key=True))
    try:
        path = _private_path(tmp_path, "frozen-0001.db")
        command.upgrade(_config(path), "0001_foundation")
        db = open_sqlcipher(path, KEY)
        assert _non_sqlite_tables(db) == EXPECTED_TABLES
        db.close()
        assert "future_phase_table" not in FOUNDATION_0001_METADATA.tables
        assert set(FOUNDATION_0001_METADATA.tables) == FOUNDATION_TABLE_NAMES
        assert all(
            metadata.tables[name] is not FOUNDATION_0001_METADATA.tables[name]
            for name in FOUNDATION_TABLE_NAMES
        )
    finally:
        metadata.remove(future)


def test_revision_source_uses_only_its_frozen_table_collection() -> None:
    source = Path("apps/core/migrations/versions/0001_foundation.py")
    imports = {
        node.module
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8")))
        if isinstance(node, ast.ImportFrom)
    }
    assert "tuntun_core.adapters.sqlcipher.foundation_0001" in imports
    assert "tuntun_core.adapters.sqlcipher.models" not in imports
    assert set(FOUNDATION_0001_METADATA.tables) == FOUNDATION_TABLE_NAMES


def test_upgrade_ddl_is_atomic_when_revision_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _private_path(tmp_path, "failed-upgrade.db")
    original_create_all = MetaData.create_all

    def create_then_fail(self: MetaData, *args: object, **kwargs: object) -> None:
        original_create_all(self, *args, **kwargs)  # type: ignore[arg-type]
        raise RuntimeError("injected revision failure")

    monkeypatch.setattr(MetaData, "create_all", create_then_fail)
    with pytest.raises(RuntimeError, match="injected revision failure"):
        command.upgrade(_config(path), "head")

    db = open_sqlcipher(path, KEY)
    assert _non_sqlite_tables(db) <= {"alembic_version"}
    if "alembic_version" in _non_sqlite_tables(db):
        assert db.execute("SELECT version_num FROM alembic_version").fetchall() == []
    assert _triggers(db) == set()
    db.close()


def test_downgrade_ddl_is_atomic_when_revision_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _private_path(tmp_path, "failed-downgrade.db")
    config = _config(path)
    command.upgrade(config, "head")
    original_drop_all = MetaData.drop_all

    def drop_then_fail(self: MetaData, *args: object, **kwargs: object) -> None:
        original_drop_all(self, *args, **kwargs)  # type: ignore[arg-type]
        raise RuntimeError("injected downgrade failure")

    monkeypatch.setattr(MetaData, "drop_all", drop_then_fail)
    with pytest.raises(RuntimeError, match="injected downgrade failure"):
        command.downgrade(config, "base")

    db = open_sqlcipher(path, KEY)
    assert _non_sqlite_tables(db) == EXPECTED_HEAD_TABLES
    assert _triggers(db) == EXPECTED_TRIGGERS
    assert db.execute("SELECT version_num FROM alembic_version").fetchall() == [
        ("0003_biometric_template_enrollment_binding",)
    ]
    db.close()


def test_enrollment_template_binding_columns_are_migrated(
    tmp_path: Path,
) -> None:
    path = _private_path(tmp_path, "biometric-template-binding.db")
    command.upgrade(_config(path), "head")
    db = open_sqlcipher(path, KEY)

    template_columns = {
        str(row[1]): tuple(row) for row in db.execute("PRAGMA table_info('biometric_templates')")
    }
    enrollment_columns = {
        str(row[1]): tuple(row) for row in db.execute("PRAGMA table_info('enrollment_sessions')")
    }
    foreign_keys = {
        (str(row[2]), str(row[3]), str(row[4]))
        for row in db.execute("PRAGMA foreign_key_list('biometric_templates')")
    }
    template_indexes = {
        str(row[1]) for row in db.execute("PRAGMA index_list('biometric_templates')")
    }
    enrollment_indexes = {
        str(row[1]): tuple(row) for row in db.execute("PRAGMA index_list('enrollment_sessions')")
    }
    enrollment_schema = str(
        db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='enrollment_sessions'"
        ).fetchone()[0]
    )

    assert "enrollment_session_id" in template_columns
    assert template_columns["enrollment_session_id"][2] == "VARCHAR(36)"
    assert "synthetic_template_id" in enrollment_columns
    assert enrollment_columns["synthetic_template_id"][2] == "VARCHAR(36)"
    assert "synthetic_template_id IS NULL OR length(synthetic_template_id)=36" in (
        enrollment_schema
    )
    assert (
        "enrollment_sessions",
        "enrollment_session_id",
        "id",
    ) in foreign_keys
    assert "ix_biometric_templates_enrollment_session" in template_indexes
    assert "ux_enrollment_sessions_synthetic_template_id" in enrollment_indexes
    assert enrollment_indexes["ux_enrollment_sessions_synthetic_template_id"][2] == 1
    db.close()

    command.downgrade(_config(path), "0002_profiles_consent_enrollment")
    db = open_sqlcipher(path, KEY)
    downgraded_template_columns = {
        str(row[1]): tuple(row) for row in db.execute("PRAGMA table_info('biometric_templates')")
    }
    downgraded_enrollment_columns = {
        str(row[1]): tuple(row) for row in db.execute("PRAGMA table_info('enrollment_sessions')")
    }
    assert "enrollment_session_id" not in downgraded_template_columns
    assert "synthetic_template_id" not in downgraded_enrollment_columns
    assert db.execute("SELECT version_num FROM alembic_version").fetchall() == [
        ("0002_profiles_consent_enrollment",)
    ]
    db.close()

    command.upgrade(_config(path), "head")
    db = open_sqlcipher(path, KEY)
    reupgraded_template_columns = {
        str(row[1]): tuple(row) for row in db.execute("PRAGMA table_info('biometric_templates')")
    }
    reupgraded_enrollment_columns = {
        str(row[1]): tuple(row) for row in db.execute("PRAGMA table_info('enrollment_sessions')")
    }
    assert "enrollment_session_id" in reupgraded_template_columns
    assert "synthetic_template_id" in reupgraded_enrollment_columns
    assert db.execute("SELECT version_num FROM alembic_version").fetchall() == [
        ("0003_biometric_template_enrollment_binding",)
    ]
    db.close()


def test_offline_and_unkeyed_migration_modes_are_forbidden(tmp_path: Path) -> None:
    path = _private_path(tmp_path, "forbidden-modes.db")
    with pytest.raises(RuntimeError, match="offline/plaintext migration mode is forbidden"):
        command.upgrade(_config(path), "head", sql=True)

    config = Config("apps/core/alembic.ini")
    with pytest.raises(RuntimeError, match="SQLCipher path and key are required"):
        command.upgrade(config, "head")

    plaintext = _private_path(tmp_path, "plaintext.db")
    plaintext_engine = create_engine(f"sqlite:///{plaintext}")
    try:
        with plaintext_engine.connect() as connection:
            supplied = _config(plaintext)
            supplied.attributes["sqlalchemy_connection"] = connection
            with pytest.raises(RuntimeError, match="qualified SQLCipher"):
                command.upgrade(supplied, "head")
    finally:
        plaintext_engine.dispose()
    assert _non_sqlite_tables(sqlite3.connect(plaintext)) == set()
    assert not path.exists()


def test_sqlalchemy_engine_uses_encrypted_null_pool_connections(tmp_path: Path) -> None:
    path = _private_path(tmp_path, "engine.db")
    sentinel = "engine-private-sentinel"
    engine = create_sqlcipher_engine(path, KEY)
    try:
        with engine.begin() as db:
            db.execute(text("CREATE TABLE engine_probe(value TEXT NOT NULL)"))
            db.execute(text("INSERT INTO engine_probe VALUES (:value)"), {"value": sentinel})
        with engine.connect() as db:
            assert db.execute(text("SELECT value FROM engine_probe")).scalar_one() == sentinel
    finally:
        engine.dispose()

    assert connection_module._registry_snapshot(path) is None
    assert not path.read_bytes().startswith(b"SQLite format 3\x00")
    assert sentinel.encode() not in path.read_bytes()
    with pytest.raises(sqlcipher3.DatabaseError):
        open_sqlcipher(path, WRONG_KEY)


def test_engine_supports_one_explicit_writer_begin_and_atomic_rollback(
    tmp_path: Path,
) -> None:
    path = _private_path(tmp_path, "explicit-writer.db")
    engine = create_sqlcipher_engine(path, KEY)
    statements: list[str] = []

    def record_statement(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", record_statement)
    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            connection.exec_driver_sql("CREATE TABLE explicit_writer_probe(value INTEGER)")
            connection.exec_driver_sql("INSERT INTO explicit_writer_probe VALUES (1)")
            transaction.rollback()
        with engine.connect() as connection:
            assert (
                connection.exec_driver_sql(
                    "SELECT count(*) FROM sqlite_master "
                    "WHERE type='table' AND name='explicit_writer_probe'"
                ).scalar_one()
                == 0
            )
        assert sum(statement == "BEGIN IMMEDIATE" for statement in statements) == 1
    finally:
        engine.dispose()


def test_read_only_sqlalchemy_transaction_does_not_reserve_the_writer_slot(
    tmp_path: Path,
) -> None:
    path = _private_path(tmp_path, "read-only-engine.db")
    engine = create_sqlcipher_engine(path, KEY)
    reader = engine.connect()
    writer = open_sqlcipher(path, KEY)
    writer.execute("PRAGMA busy_timeout=0")
    try:
        assert reader.exec_driver_sql("SELECT count(*) FROM sqlite_master").scalar_one() >= 0
        assert reader.in_transaction()
        writer.execute("BEGIN IMMEDIATE")
        writer.execute("ROLLBACK")
    finally:
        writer.close()
        reader.close()
        engine.dispose()


def test_existing_database_is_backed_up_encrypted_before_upgrade(tmp_path: Path) -> None:
    source = _private_path(tmp_path, "source.db")
    backup = _private_path(tmp_path, "backup.db")
    sentinel = "backup-private-sentinel"
    command.upgrade(_config(source), "head")
    db = open_sqlcipher(source, KEY)
    db.execute(
        "INSERT INTO runtime_settings(key,value_json,version,updated_at) VALUES (?,?,?,?)",
        ("probe", json.dumps({"value": sentinel}), 1, "2026-08-27T01:02:03.000004Z"),
    )
    db.close()

    upgrade_encrypted(source, KEY, backup)

    assert backup.is_file()
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    for candidate in (backup, Path(f"{backup}-wal"), Path(f"{backup}-shm")):
        if candidate.exists():
            raw = candidate.read_bytes()
            assert not raw.startswith(b"SQLite format 3\x00")
            assert sentinel.encode() not in raw
    with pytest.raises(sqlite3.DatabaseError):
        sqlite3.connect(backup).execute("SELECT name FROM sqlite_master").fetchall()
    with pytest.raises(sqlcipher3.DatabaseError):
        open_sqlcipher(backup, WRONG_KEY)
    copied = open_sqlcipher(backup, KEY)
    assert json.loads(
        copied.execute("SELECT value_json FROM runtime_settings WHERE key='probe'").fetchone()[0]
    ) == {"value": sentinel}
    copied.close()


def test_backup_requires_existing_source_and_exclusive_destination(tmp_path: Path) -> None:
    missing = _private_path(tmp_path, "missing.db")
    destination = _private_path(tmp_path, "destination.db")
    with pytest.raises(FileNotFoundError):
        encrypted_backup(missing, destination, KEY)
    assert not missing.exists()
    assert not destination.exists()

    empty = _private_path(tmp_path, "empty.db")
    empty.touch(mode=0o600)
    with pytest.raises(RuntimeError, match="source database is empty"):
        encrypted_backup(empty, destination, KEY)
    assert empty.stat().st_size == 0
    assert not destination.exists()

    source = _private_path(tmp_path, "source.db")
    db = open_sqlcipher(source, KEY)
    db.execute("CREATE TABLE marker(value INTEGER NOT NULL)")
    db.close()
    destination.write_bytes(b"do-not-replace")
    destination.chmod(0o600)
    with pytest.raises(FileExistsError):
        encrypted_backup(source, destination, KEY)
    assert destination.read_bytes() == b"do-not-replace"


def test_destination_reservation_close_report_removes_its_exclusive_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _private_path(tmp_path, "reservation-close-source.db")
    destination = _private_path(tmp_path, "reservation-close-backup.db")
    db = open_sqlcipher(source, KEY)
    db.execute("CREATE TABLE source_marker(value INTEGER NOT NULL)")
    db.close()
    real_close = os.close
    injected = False
    injected_fd: int | None = None
    injected_close_attempts = 0

    def reporting_close(fd: int) -> None:
        nonlocal injected, injected_close_attempts, injected_fd
        if fd == injected_fd:
            injected_close_attempts += 1
            real_close(fd)
            return
        opened = os.fstat(fd)
        target = destination.stat() if destination.exists() else None
        if (
            not injected
            and target is not None
            and (opened.st_dev, opened.st_ino) == (target.st_dev, target.st_ino)
        ):
            injected = True
            injected_fd = fd
            injected_close_attempts = 1
            real_close(fd)
            raise OSError("injected reservation close report")
        real_close(fd)

    monkeypatch.setattr(
        "tuntun_core.adapters.sqlcipher.migrations.os.close",
        reporting_close,
    )
    with pytest.raises(OSError, match="injected reservation close report"):
        encrypted_backup(source, destination, KEY)
    assert injected
    assert injected_close_attempts == 1
    assert not destination.exists()
    assert not Path(f"{destination}-wal").exists()
    assert not Path(f"{destination}-shm").exists()
    assert connection_module._registry_snapshot(source) is None
    assert connection_module._registry_snapshot(destination) is None


def test_destination_reservation_pins_inode_across_creation_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = _private_path(tmp_path, "reservation-handoff.db")
    real_close = os.close
    real_dup = os.dup
    real_identity = migration_module._identity
    original_identity: tuple[int, int] | None = None
    replacement_identity: tuple[int, int] | None = None
    retained_descriptor: int | None = None
    swapped = False

    def original_generation_is_pinned() -> bool:
        if retained_descriptor is None:
            return False
        try:
            os.fstat(retained_descriptor)
        except OSError:
            return False
        return True

    def simulate_recycled_inode(value: os.stat_result) -> tuple[int, int]:
        actual = real_identity(value)
        if (
            replacement_identity is not None
            and actual == replacement_identity
            and not original_generation_is_pinned()
        ):
            assert original_identity is not None
            return original_identity
        return actual

    def retain_generation(fd: int) -> int:
        nonlocal retained_descriptor
        retained_descriptor = real_dup(fd)
        return retained_descriptor

    def replace_during_creation_close(fd: int) -> None:
        nonlocal original_identity, replacement_identity, swapped
        opened = os.fstat(fd)
        target = destination.stat() if destination.exists() else None
        is_target = target is not None and real_identity(opened) == real_identity(target)
        real_close(fd)
        if is_target and not swapped:
            original_identity = real_identity(opened)
            destination.unlink()
            destination.write_bytes(b"replacement-must-survive")
            destination.chmod(0o600)
            replacement_identity = real_identity(destination.stat())
            swapped = True

    monkeypatch.setattr(migration_module, "_identity", simulate_recycled_inode)
    monkeypatch.setattr(migration_module.os, "dup", retain_generation)
    monkeypatch.setattr(migration_module.os, "close", replace_during_creation_close)
    reservation: migration_module._ReservedDestination | None = None
    try:
        with pytest.raises(PermissionError, match="unsafe database path"):
            reservation = migration_module._ReservedDestination.create(destination)
    finally:
        if reservation is not None:
            reservation.close()

    assert swapped
    assert destination.read_bytes() == b"replacement-must-survive"
    destination.unlink()


def test_destination_reservation_consumes_pinned_close_after_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = _private_path(tmp_path, "reservation-pinned-close.db")
    reservation = migration_module._ReservedDestination.create(destination)
    connection = open_sqlcipher(destination, KEY)
    reservation.bind(connection)
    connection.close()
    assert reservation.main_descriptor is not None
    descriptors = (
        reservation.main_descriptor,
        *reservation.sidecar_descriptors.values(),
    )
    primary = RuntimeError("primary backup failure")
    reservation.remove(primary)
    target = reservation.main_descriptor
    real_close = os.close
    target_close_attempts = 0

    def close_then_report(fd: int) -> None:
        nonlocal target_close_attempts
        if fd == target:
            target_close_attempts += 1
            real_close(fd)
            raise OSError("injected pinned descriptor close report")
        real_close(fd)

    monkeypatch.setattr(migration_module.os, "close", close_then_report)
    assert reservation.close(primary) is primary

    assert target_close_attempts == 1
    assert migration_module._CLEANUP_NOTE in getattr(primary, "__notes__", ())
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_failed_backup_removes_only_its_partial_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _private_path(tmp_path, "source.db")
    destination = _private_path(tmp_path, "partial.db")
    db = open_sqlcipher(source, KEY)
    db.execute("CREATE TABLE source_marker(value INTEGER NOT NULL)")
    db.close()

    def failing_copy(source_db: object, destination_db: object) -> None:
        del source_db
        destination_db.execute(  # type: ignore[attr-defined]
            "CREATE TABLE partial_marker(value INTEGER NOT NULL)"
        )
        destination_db.commit()  # type: ignore[attr-defined]
        _, sidecars = destination_db.storage_identities()  # type: ignore[attr-defined]
        assert {suffix for suffix, _ in sidecars} == {"-wal", "-shm"}
        assert all(Path(f"{destination}{suffix}").is_file() for suffix, _ in sidecars)
        raise RuntimeError("injected backup failure")

    monkeypatch.setattr(migration_module, "_copy_encrypted_pages", failing_copy)
    with pytest.raises(RuntimeError, match="injected backup failure"):
        encrypted_backup(source, destination, KEY)
    assert not destination.exists()
    assert not Path(f"{destination}-wal").exists()
    assert not Path(f"{destination}-shm").exists()
    assert connection_module._registry_snapshot(source) is None
    assert connection_module._registry_snapshot(destination) is None


def test_backup_initialization_close_failure_quarantines_its_live_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _private_path(tmp_path, "cleanup-error-source.db")
    destination = _private_path(tmp_path, "cleanup-error-backup.db")
    db = open_sqlcipher(source, KEY)
    db.execute("CREATE TABLE source_marker(value INTEGER NOT NULL)")
    db.close()
    release_allowed = _inject_unreleased_initialization_failure(
        monkeypatch,
        migration_module,
        destination,
    )

    with pytest.raises(connection_module.SQLCipherCleanupError) as captured:
        encrypted_backup(source, destination, KEY)

    assert isinstance(captured.value.initialization_error, RuntimeError)
    assert "destination initialization failure" in str(captured.value.initialization_error)
    _release_quarantined_connection(captured.value, destination, release_allowed)
    assert connection_module._registry_snapshot(source) is None


def test_backup_prebind_cleanup_error_quarantines_its_separate_path_guard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _private_path(tmp_path, "prebind-source.db")
    destination = _private_path(tmp_path, "prebind-backup.db")
    db = open_sqlcipher(source, KEY)
    db.execute("CREATE TABLE source_marker(value INTEGER NOT NULL)")
    db.close()
    release_allowed = _inject_unreleased_prebind_failure(monkeypatch, destination)

    with pytest.raises(connection_module.SQLCipherCleanupError) as captured:
        encrypted_backup(source, destination, KEY)

    assert "pre-bind initialization failure" in str(captured.value.initialization_error)
    _release_prebind_quarantine(captured.value, destination, release_allowed)
    assert connection_module._registry_snapshot(source) is None


def test_failed_backup_preserves_primary_error_when_destination_close_reports_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _private_path(tmp_path, "close-source.db")
    destination = _private_path(tmp_path, "close-partial.db")
    db = open_sqlcipher(source, KEY)
    db.execute("CREATE TABLE source_marker(value INTEGER NOT NULL)")
    db.close()

    def failing_copy(source_db: object, destination_db: object) -> None:
        del source_db, destination_db
        raise RuntimeError("primary backup failure")

    real_close = connection_module.QualifiedSQLCipherConnection.close

    def reporting_close(connection: object) -> None:
        guard = connection._path_guard  # type: ignore[attr-defined]
        closing_path = guard.path if guard is not None else None
        real_close(connection)  # type: ignore[arg-type]
        if closing_path == destination:
            raise RuntimeError("injected destination close report")

    monkeypatch.setattr(migration_module, "_copy_encrypted_pages", failing_copy)
    monkeypatch.setattr(
        connection_module.QualifiedSQLCipherConnection,
        "close",
        reporting_close,
    )
    with pytest.raises(RuntimeError, match="primary backup failure") as raised:
        encrypted_backup(source, destination, KEY)
    assert "injected destination close report" not in str(raised.value)
    assert migration_module._CLEANUP_NOTE in getattr(raised.value, "__notes__", ())
    assert not destination.exists()
    assert not Path(f"{destination}-wal").exists()
    assert not Path(f"{destination}-shm").exists()
    assert connection_module._registry_snapshot(source) is None
    assert connection_module._registry_snapshot(destination) is None


def test_successful_copy_surfaces_destination_close_failure_and_cleans_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _private_path(tmp_path, "close-success-source.db")
    destination = _private_path(tmp_path, "close-success-backup.db")
    db = open_sqlcipher(source, KEY)
    db.execute("CREATE TABLE source_marker(value INTEGER NOT NULL)")
    db.close()
    real_close = connection_module.QualifiedSQLCipherConnection.close

    def reporting_close(connection: object) -> None:
        guard = connection._path_guard  # type: ignore[attr-defined]
        closing_path = guard.path if guard is not None else None
        real_close(connection)  # type: ignore[arg-type]
        if closing_path == destination:
            raise RuntimeError("injected destination close report")

    monkeypatch.setattr(
        connection_module.QualifiedSQLCipherConnection,
        "close",
        reporting_close,
    )
    with pytest.raises(RuntimeError, match="injected destination close report"):
        encrypted_backup(source, destination, KEY)
    assert not destination.exists()
    assert not Path(f"{destination}-wal").exists()
    assert not Path(f"{destination}-shm").exists()
    assert connection_module._registry_snapshot(source) is None
    assert connection_module._registry_snapshot(destination) is None


def test_final_backup_fsync_failure_removes_exact_partial_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _private_path(tmp_path, "fsync-source.db")
    destination = _private_path(tmp_path, "fsync-partial.db")
    db = open_sqlcipher(source, KEY)
    db.execute("CREATE TABLE source_marker(value INTEGER NOT NULL)")
    db.close()
    copied = False
    real_copy = migration_module._copy_encrypted_pages
    real_fsync = os.fsync

    def tracked_copy(source_db: object, destination_db: object) -> None:
        nonlocal copied
        real_copy(source_db, destination_db)  # type: ignore[arg-type]
        copied = True

    def failing_fsync(fd: int) -> None:
        if copied and destination.exists():
            target = destination.stat()
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) == (target.st_dev, target.st_ino):
                raise OSError("injected final backup fsync failure")
        real_fsync(fd)

    monkeypatch.setattr(migration_module, "_copy_encrypted_pages", tracked_copy)
    monkeypatch.setattr(
        "tuntun_core.adapters.sqlcipher.migrations.os.fsync",
        failing_fsync,
    )
    with pytest.raises(OSError, match="injected final backup fsync failure"):
        encrypted_backup(source, destination, KEY)
    assert not destination.exists()
    assert not Path(f"{destination}-wal").exists()
    assert not Path(f"{destination}-shm").exists()
    assert connection_module._registry_snapshot(source) is None
    assert connection_module._registry_snapshot(destination) is None


def test_cleanup_fsync_failure_preserves_primary_backup_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _private_path(tmp_path, "cleanup-fsync-source.db")
    destination = _private_path(tmp_path, "cleanup-fsync-partial.db")
    db = open_sqlcipher(source, KEY)
    db.execute("CREATE TABLE source_marker(value INTEGER NOT NULL)")
    db.close()
    copy_failed = False
    real_fsync = os.fsync

    def failing_copy(source_db: object, destination_db: object) -> None:
        nonlocal copy_failed
        del source_db
        destination_db.execute(  # type: ignore[attr-defined]
            "CREATE TABLE partial_marker(value INTEGER NOT NULL)"
        )
        destination_db.commit()  # type: ignore[attr-defined]
        copy_failed = True
        raise RuntimeError("primary backup failure")

    def failing_cleanup_fsync(fd: int) -> None:
        if copy_failed and stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("injected cleanup directory fsync failure")
        real_fsync(fd)

    monkeypatch.setattr(migration_module, "_copy_encrypted_pages", failing_copy)
    monkeypatch.setattr(
        "tuntun_core.adapters.sqlcipher.migrations.os.fsync",
        failing_cleanup_fsync,
    )
    with pytest.raises(RuntimeError, match="primary backup failure") as raised:
        encrypted_backup(source, destination, KEY)
    assert "injected cleanup directory fsync failure" not in str(raised.value)
    assert migration_module._CLEANUP_NOTE in getattr(raised.value, "__notes__", ())
    assert not destination.exists()
    assert not Path(f"{destination}-wal").exists()
    assert not Path(f"{destination}-shm").exists()
    assert connection_module._registry_snapshot(source) is None
    assert connection_module._registry_snapshot(destination) is None


def test_backup_cleanup_never_unlinks_a_replaced_sidecar(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = _private_path(tmp_path, "replacement-backup.db")
    reservation = migration_module._ReservedDestination.create(destination)
    connection = open_sqlcipher(destination, KEY)
    real_open = os.open
    pinned_sidecar_descriptors: list[int] = []
    sidecar_open_allowed = True

    def track_sidecar_open(
        path: str | bytes,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path in {destination.name + "-wal", destination.name + "-shm"}:
            assert sidecar_open_allowed, "repeat bind reopened a pinned sidecar"
        if dir_fd is None:
            descriptor = real_open(path, flags, mode)
        else:
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if path in {destination.name + "-wal", destination.name + "-shm"}:
            pinned_sidecar_descriptors.append(descriptor)
        return descriptor

    monkeypatch.setattr(migration_module.os, "open", track_sidecar_open)
    reservation.bind(connection)
    _, sidecars = connection.storage_identities()
    assert {suffix for suffix, _ in sidecars} == {"-wal", "-shm"}
    sidecar_open_allowed = False
    reservation.bind(connection)
    connection.close()

    replacement = Path(f"{destination}-wal")
    replacement.write_bytes(b"replacement-must-survive")
    replacement.chmod(0o600)
    replacement_identity = migration_module._identity(replacement.stat())
    original_identity = {
        suffix: (identity.device, identity.inode) for suffix, identity in sidecars
    }["-wal"]
    real_identity = migration_module._identity

    def original_sidecar_generation_is_pinned() -> bool:
        for descriptor in pinned_sidecar_descriptors:
            try:
                opened = os.fstat(descriptor)
            except OSError:
                continue
            if real_identity(opened) == original_identity:
                return True
        return False

    def simulate_recycled_sidecar_inode(value: os.stat_result) -> tuple[int, int]:
        actual = real_identity(value)
        if actual == replacement_identity and not original_sidecar_generation_is_pinned():
            return original_identity
        return actual

    # Linux can recycle the just-deleted WAL inode immediately. Model that on
    # every platform so cleanup must identify the pinned file generation, not
    # trust a stale device/inode pair alone.
    monkeypatch.setattr(migration_module, "_identity", simulate_recycled_sidecar_inode)
    primary = RuntimeError("primary backup failure")
    reservation.remove(primary)
    reservation.close(primary)

    assert not destination.exists()
    assert replacement.read_bytes() == b"replacement-must-survive"
    assert migration_module._CLEANUP_NOTE in getattr(primary, "__notes__", ())
    for descriptor in pinned_sidecar_descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    replacement.unlink()


def test_standalone_backup_revalidates_its_open_source_after_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _private_path(tmp_path, "source-replaced-during-backup.db")
    parked = _private_path(tmp_path, "parked-source.db")
    destination = _private_path(tmp_path, "source-replaced-backup.db")
    replacement_bytes = b"replacement-must-survive"
    db = open_sqlcipher(source, KEY)
    db.execute("CREATE TABLE source_marker(value INTEGER NOT NULL)")
    db.close()
    real_copy = migration_module._copy_encrypted_pages

    def copy_then_replace(source_db: object, destination_db: object) -> None:
        real_copy(source_db, destination_db)  # type: ignore[arg-type]
        source.rename(parked)
        source.write_bytes(replacement_bytes)
        source.chmod(0o600)

    monkeypatch.setattr(migration_module, "_copy_encrypted_pages", copy_then_replace)
    with pytest.raises(PermissionError, match="unsafe database path"):
        encrypted_backup(source, destination, KEY)

    assert source.read_bytes() == replacement_bytes
    assert parked.is_file()
    assert not destination.exists()
    assert not Path(f"{destination}-wal").exists()
    assert not Path(f"{destination}-shm").exists()
    assert connection_module._registry_snapshot(source) is None
    assert connection_module._registry_snapshot(destination) is None


def test_upgrade_refuses_existing_database_without_preupgrade_backup(tmp_path: Path) -> None:
    source = _private_path(tmp_path, "existing.db")
    db = open_sqlcipher(source, KEY)
    db.execute("CREATE TABLE preexisting_marker(value INTEGER NOT NULL)")
    db.close()

    with pytest.raises(RuntimeError, match="requires encrypted pre-migration backup"):
        upgrade_encrypted(source, KEY, None)

    db = open_sqlcipher(source, KEY)
    assert _non_sqlite_tables(db) == {"preexisting_marker"}
    db.close()


@pytest.mark.parametrize("supply_backup", (False, True))
def test_upgrade_rejects_a_preexisting_empty_database_without_mutating_it(
    tmp_path: Path,
    supply_backup: bool,
) -> None:
    source = _private_path(tmp_path, "empty-existing.db")
    backup = _private_path(tmp_path, "empty-existing-backup.db")
    source.touch(mode=0o600)

    with pytest.raises(RuntimeError, match="existing database is empty"):
        upgrade_encrypted(source, KEY, backup if supply_backup else None)

    assert source.stat().st_size == 0
    assert stat.S_IMODE(source.stat().st_mode) == 0o600
    assert not backup.exists()
    assert not Path(f"{source}-wal").exists()
    assert not Path(f"{source}-shm").exists()
    assert connection_module._registry_snapshot(source) is None


def test_upgrade_rechecks_a_database_created_during_fresh_path_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _private_path(tmp_path, "fresh-race.db")
    real_inspect = migration_module._existing_database_identity
    first = True

    def racing_inspect(candidate: Path) -> tuple[Path, tuple[int, int], int]:
        nonlocal first
        if first:
            first = False
            db = open_sqlcipher(candidate, KEY)
            db.execute("CREATE TABLE preexisting_marker(value INTEGER NOT NULL)")
            db.close()
            raise FileNotFoundError(candidate)
        return real_inspect(candidate)

    monkeypatch.setattr(migration_module, "_existing_database_identity", racing_inspect)
    with pytest.raises(RuntimeError, match="requires encrypted pre-migration backup"):
        upgrade_encrypted(path, KEY, None)
    db = open_sqlcipher(path, KEY)
    assert _non_sqlite_tables(db) == {"preexisting_marker"}
    db.close()


def test_upgrade_rejects_identity_replacement_before_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _private_path(tmp_path, "identity-race.db")
    backup = _private_path(tmp_path, "identity-race-backup.db")
    original = open_sqlcipher(path, KEY)
    original.execute("CREATE TABLE original_marker(value INTEGER NOT NULL)")
    original.close()
    real_inspect = migration_module._existing_database_identity
    replaced = False

    def replacing_inspect(candidate: Path) -> tuple[Path, tuple[int, int], int]:
        nonlocal replaced
        inspected = real_inspect(candidate)
        if not replaced:
            replaced = True
            candidate.rename(candidate.with_name("qualified-original.db"))
            replacement = open_sqlcipher(candidate, KEY)
            replacement.execute("CREATE TABLE replacement_marker(value INTEGER NOT NULL)")
            replacement.close()
        return inspected

    monkeypatch.setattr(migration_module, "_existing_database_identity", replacing_inspect)
    with pytest.raises(PermissionError, match="unsafe database path"):
        upgrade_encrypted(path, KEY, backup)
    assert not backup.exists()
    replacement = open_sqlcipher(path, KEY)
    assert _non_sqlite_tables(replacement) == {"replacement_marker"}
    replacement.close()


def test_existing_upgrade_rejects_a_commit_observed_across_its_backup_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _private_path(tmp_path, "writer-race.db")
    backup = _private_path(tmp_path, "writer-race-backup.db")
    command.upgrade(_config(path), "head")
    real_copy = migration_module._copy_encrypted_pages

    def copy_then_write(source_db: object, destination_db: object) -> None:
        real_copy(source_db, destination_db)  # type: ignore[arg-type]
        writer = open_sqlcipher(path, KEY)
        writer.execute(
            "INSERT INTO runtime_settings(key,value_json,version,updated_at) VALUES (?,?,?,?)",
            ("raced", "{}", 1, "2026-08-27T01:02:03.000004Z"),
        )
        writer.close()

    monkeypatch.setattr(migration_module, "_copy_encrypted_pages", copy_then_write)
    with pytest.raises(RuntimeError, match="database changed during encrypted backup"):
        upgrade_encrypted(path, KEY, backup)

    current = open_sqlcipher(path, KEY)
    assert current.execute(
        "SELECT count(*) FROM runtime_settings WHERE key='raced'"
    ).fetchone() == (1,)
    current.close()
    snapshot = open_sqlcipher(backup, KEY)
    assert snapshot.execute(
        "SELECT count(*) FROM runtime_settings WHERE key='raced'"
    ).fetchone() == (0,)
    snapshot.close()


def test_existing_upgrade_holds_the_sqlite_writer_lock_through_alembic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _private_path(tmp_path, "writer-lock.db")
    backup = _private_path(tmp_path, "writer-lock-backup.db")
    command.upgrade(_config(path), "head")
    real_upgrade = command.upgrade
    writer = open_sqlcipher(path, KEY)
    writer.execute("PRAGMA busy_timeout=0")

    def assert_locked_then_upgrade(config: Config, revision: str) -> None:
        with pytest.raises(sqlcipher3.OperationalError, match="locked"):
            writer.execute(
                """INSERT INTO runtime_settings
                   (key,value_json,version,updated_at) VALUES (?,?,?,?)""",
                ("must-block", "{}", 1, "2026-08-27T01:02:03.000004Z"),
            )
        real_upgrade(config, revision)

    monkeypatch.setattr(
        command,
        "upgrade",
        assert_locked_then_upgrade,
    )
    try:
        upgrade_encrypted(path, KEY, backup)
    finally:
        writer.close()

    db = open_sqlcipher(path, KEY)
    assert db.execute(
        "SELECT count(*) FROM runtime_settings WHERE key='must-block'"
    ).fetchone() == (0,)
    db.close()


def test_failed_fresh_migration_removes_its_exact_main_and_sidecars(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _private_path(tmp_path, "fresh-migration-failure.db")
    real_upgrade = command.upgrade

    def failing_upgrade(config: Config, revision: str) -> None:
        real_upgrade(config, revision)
        assert path.is_file()
        assert Path(f"{path}-wal").is_file()
        assert Path(f"{path}-shm").is_file()
        raise RuntimeError("injected migration failure")

    monkeypatch.setattr(command, "upgrade", failing_upgrade)
    with pytest.raises(RuntimeError, match="injected migration failure"):
        upgrade_encrypted(path, KEY, None)

    assert not path.exists()
    assert not Path(f"{path}-wal").exists()
    assert not Path(f"{path}-shm").exists()
    assert connection_module._registry_snapshot(path) is None


def test_fresh_migration_initialization_close_failure_quarantines_its_live_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _private_path(tmp_path, "fresh-cleanup-error.db")
    release_allowed = _inject_unreleased_initialization_failure(
        monkeypatch,
        engine_module,
        path,
    )

    with pytest.raises(connection_module.SQLCipherCleanupError) as captured:
        upgrade_encrypted(path, KEY, None)

    assert isinstance(captured.value.initialization_error, RuntimeError)
    assert "destination initialization failure" in str(captured.value.initialization_error)
    _release_quarantined_connection(captured.value, path, release_allowed)


def test_fresh_migration_prebind_cleanup_error_quarantines_its_separate_path_guard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _private_path(tmp_path, "fresh-prebind-error.db")
    release_allowed = _inject_unreleased_prebind_failure(monkeypatch, path)

    with pytest.raises(connection_module.SQLCipherCleanupError) as captured:
        upgrade_encrypted(path, KEY, None)

    assert "pre-bind initialization failure" in str(captured.value.initialization_error)
    _release_prebind_quarantine(captured.value, path, release_allowed)


def test_failed_fresh_migration_cleanup_preserves_a_replaced_sidecar(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _private_path(tmp_path, "fresh-migration-replacement.db")
    replacement = Path(f"{path}-wal")
    real_upgrade = command.upgrade
    real_close = connection_module.QualifiedSQLCipherConnection.close
    migration_failed = False
    replacement_created = False

    def failing_upgrade(config: Config, revision: str) -> None:
        nonlocal migration_failed
        real_upgrade(config, revision)
        assert Path(f"{path}-wal").is_file()
        assert Path(f"{path}-shm").is_file()
        migration_failed = True
        raise RuntimeError("injected migration failure")

    def replacing_after_close(connection: object) -> None:
        nonlocal replacement_created
        guard = connection._path_guard  # type: ignore[attr-defined]
        closing_path = guard.path if guard is not None else None
        real_close(connection)  # type: ignore[arg-type]
        if migration_failed and not replacement_created and closing_path == path:
            replacement.write_bytes(b"replacement-must-survive")
            replacement.chmod(0o600)
            replacement_created = True

    monkeypatch.setattr(command, "upgrade", failing_upgrade)
    monkeypatch.setattr(
        connection_module.QualifiedSQLCipherConnection,
        "close",
        replacing_after_close,
    )
    with pytest.raises(RuntimeError, match="injected migration failure") as raised:
        upgrade_encrypted(path, KEY, None)

    assert replacement_created
    assert not path.exists()
    assert replacement.read_bytes() == b"replacement-must-survive"
    assert migration_module._CLEANUP_NOTE in getattr(raised.value, "__notes__", ())
    assert connection_module._registry_snapshot(path) is None
    replacement.unlink()


def test_budget_and_provider_attempt_ids_are_the_idempotency_boundary(
    tmp_path: Path,
) -> None:
    path = _private_path(tmp_path, "attempts.db")
    command.upgrade(_config(path), "head")
    db = open_sqlcipher(path, KEY)
    first = _valid_reservation(
        "00000000-0000-0000-0000-000000000501",
        "00000000-0000-0000-0000-000000000503",
    )
    second = _valid_reservation(
        "00000000-0000-0000-0000-000000000504",
        "00000000-0000-0000-0000-000000000505",
    )
    db.execute(RESERVATION_SQL, first)
    db.execute(RESERVATION_SQL, second)
    with pytest.raises(sqlcipher3.IntegrityError):
        db.execute(
            RESERVATION_SQL,
            _valid_reservation(
                "00000000-0000-0000-0000-000000000506",
                str(first["attempt_id"]),
            ),
        )

    call_sql = """INSERT INTO provider_calls
        (id,request_id,attempt_id,authorization_id,budget_reservation_id,purpose,
         provider,model,request_hmac_key_id,request_hmac_b64,category,outcome,
         gateway_ordering_version,transport_phase,started_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""
    base_call = (
        "00000000-0000-0000-0000-000000000601",
        first["request_id"],
        first["attempt_id"],
        "00000000-0000-0000-0000-000000000602",
        first["id"],
        "cloud_reasoning",
        "openai",
        "gpt-5.6-sol",
        "provider-request-v1",
        "A" * 43 + "=",
        "llm",
        "started",
        1,
        "claim_begun",
        "2026-08-27T01:02:03.000004Z",
    )
    db.execute(call_sql, base_call)
    with pytest.raises(sqlcipher3.IntegrityError):
        db.execute(call_sql, ("00000000-0000-0000-0000-000000000603", *base_call[1:]))
    mismatched = (
        "00000000-0000-0000-0000-000000000604",
        second["request_id"],
        first["attempt_id"],
        "00000000-0000-0000-0000-000000000605",
        second["id"],
        *base_call[5:],
    )
    with pytest.raises(sqlcipher3.IntegrityError):
        db.execute(call_sql, mismatched)
    assert "ix_budget_month_state_cost" in {
        str(row[1]) for row in db.execute("PRAGMA index_list('budget_reservations')")
    }
    assert "ix_provider_calls_request" in {
        str(row[1]) for row in db.execute("PRAGMA index_list('provider_calls')")
    }
    db.close()


def test_provider_call_cannot_drift_from_its_authorized_reservation(tmp_path: Path) -> None:
    path = _private_path(tmp_path, "call-evidence.db")
    command.upgrade(_config(path), "head")
    db = open_sqlcipher(path, KEY)
    reservation = _valid_reservation(
        "00000000-0000-0000-0000-000000000511",
        "00000000-0000-0000-0000-000000000512",
    )
    db.execute(RESERVATION_SQL, reservation)
    call = _valid_call(
        reservation,
        identifier="00000000-0000-0000-0000-000000000611",
        authorization_id="00000000-0000-0000-0000-000000000612",
    )
    mutations = (
        {"request_id": "00000000-0000-0000-0000-000000000599"},
        {"provider": "qwen"},
        {"model": "qwen3.7-plus"},
        {"category": "web_search", "purpose": "web_search"},
    )
    for mutation in mutations:
        with pytest.raises(sqlcipher3.IntegrityError):
            db.execute(PROVIDER_CALL_SQL, call | mutation)
    db.execute(PROVIDER_CALL_SQL, call)
    db.close()


def test_provider_response_cannot_drift_from_its_provider_call(tmp_path: Path) -> None:
    path = _private_path(tmp_path, "response-evidence.db")
    command.upgrade(_config(path), "head")
    db = open_sqlcipher(path, KEY)
    reservation = _valid_reservation(
        "00000000-0000-0000-0000-000000000521",
        "00000000-0000-0000-0000-000000000522",
    )
    call = _valid_call(
        reservation,
        identifier="00000000-0000-0000-0000-000000000621",
        authorization_id="00000000-0000-0000-0000-000000000622",
    ) | {
        "response_key": "provider-response-v1",
        "response_hmac": "A" * 43 + "=",
    }
    db.execute(RESERVATION_SQL, reservation)
    db.execute(PROVIDER_CALL_SQL, call)
    household_id = "00000000-0000-0000-0000-000000000101"
    device_id = "00000000-0000-0000-0000-000000000102"
    session_id = "00000000-0000-0000-0000-000000000103"
    timestamp = "2026-08-27T01:02:03.000004Z"
    db.execute(
        "INSERT INTO households(id,display_label_ciphertext,created_at) VALUES (?,?,?)",
        (household_id, b"ciphertext", timestamp),
    )
    db.execute(
        """INSERT INTO devices
           (id,household_id,kind,certificate_fingerprint,signing_public_key,
            signing_key_id,paired_at)
           VALUES (?,?,?,?,?,?,?)""",
        (device_id, household_id, "reachy_mini", "fingerprint", b"key", "key-v1", timestamp),
    )
    db.execute(
        """INSERT INTO sessions
           (id,household_id,device_id,state,opened_at,last_activity_at)
           VALUES (?,?,?,?,?,?)""",
        (session_id, household_id, device_id, "active", timestamp, timestamp),
    )
    response = {
        "id": "00000000-0000-0000-0000-000000000631",
        "request_id": call["request_id"],
        "attempt_id": call["attempt_id"],
        "authorization_id": call["authorization_id"],
        "household_id": household_id,
        "subject_id": None,
        "session_id": session_id,
        "turn_id": "00000000-0000-0000-0000-000000000632",
        "provider": call["provider"],
        "model": call["model"],
        "response_key": "provider-response-v1",
        "response_hmac": "A" * 43 + "=",
        "receipt_key": "provider-receipt-v1",
        "receipt_hmac": "B" * 43 + "=",
        "produced_at": timestamp,
    }
    mutations = (
        {"request_id": "00000000-0000-0000-0000-000000000699"},
        {"attempt_id": "00000000-0000-0000-0000-000000000698"},
        {"authorization_id": "00000000-0000-0000-0000-000000000697"},
        {"provider": "qwen"},
        {"model": "qwen3.7-plus"},
        {"response_key": "different-response-key"},
        {"response_hmac": "C" * 43 + "="},
    )
    for mutation in mutations:
        with pytest.raises(sqlcipher3.IntegrityError):
            db.execute(PROVIDER_RESPONSE_SQL, response | mutation)
    db.execute(PROVIDER_RESPONSE_SQL, response)
    db.close()


def test_cost_ledger_cannot_drift_from_its_settled_reservation(tmp_path: Path) -> None:
    path = _private_path(tmp_path, "ledger-evidence.db")
    command.upgrade(_config(path), "head")
    db = open_sqlcipher(path, KEY)
    reservation = _settled_reservation(
        "00000000-0000-0000-0000-000000000531",
        "00000000-0000-0000-0000-000000000532",
    )
    db.execute(RESERVATION_SQL, reservation)
    ledger = _valid_ledger(
        reservation,
        identifier="00000000-0000-0000-0000-000000000731",
    ) | {
        "receipt": "{}",
        "receipt_key": "provider-usage-v1",
        "receipt_hmac": "A" * 43 + "=",
        "basis": reservation["basis"],
        "conservative": 0,
    }
    mutations = (
        {"month_key": "2026-09"},
        {"reserved": 99},
        {"charged": 99},
        {"pricing_version": "different-pricing-version"},
        {"price_sha": "c" * 64},
        {"fx_version": "different-fx-version"},
        {"fx_sha": "d" * 64},
        {"settled_at": "2026-08-27T01:05:03.000004Z"},
        {"basis": "request_bound_exact"},
        {"reservation_basis": "request_bound_exact"},
        {"reservation_missing_policy": "conservative_full_reservation"},
    )
    for mutation in mutations:
        candidate = ledger | mutation
        charged = candidate["charged"]
        reserved = candidate["reserved"]
        assert isinstance(charged, int)
        assert isinstance(reserved, int)
        candidate["overrun"] = int(charged > reserved)
        with pytest.raises(sqlcipher3.IntegrityError):
            db.execute(LEDGER_SQL, candidate)
    db.execute(LEDGER_SQL, ledger)

    fallback_reservation = _settled_reservation(
        "00000000-0000-0000-0000-000000000533",
        "00000000-0000-0000-0000-000000000534",
    )
    db.execute(RESERVATION_SQL, fallback_reservation)
    db.execute(
        LEDGER_SQL,
        _valid_ledger(
            fallback_reservation,
            identifier="00000000-0000-0000-0000-000000000732",
        ),
    )
    db.close()


def test_cost_ledger_binds_reservation_policy_for_conservative_receipts(tmp_path: Path) -> None:
    path = _private_path(tmp_path, "ledger-policy.db")
    command.upgrade(_config(path), "head")
    db = open_sqlcipher(path, KEY)
    search_reservation = _settled_reservation(
        "00000000-0000-0000-0000-000000000535",
        "00000000-0000-0000-0000-000000000536",
    ) | {
        "category": "web_search",
        "missing_policy": "conservative_full_reservation",
        "usage": json.dumps(
            {
                "category": "web_search",
                "input_tokens": 1,
                "output_tokens": 1,
                "web_search_calls": 1,
            },
            separators=(",", ":"),
        ),
    }
    db.execute(RESERVATION_SQL, search_reservation)
    conservative = _valid_ledger(
        search_reservation,
        identifier="00000000-0000-0000-0000-000000000733",
    ) | {
        "receipt": "{}",
        "receipt_key": "provider-usage-v1",
        "receipt_hmac": "A" * 43 + "=",
        "basis": "conservative_full_reservation",
        "conservative": 1,
    }
    db.execute(LEDGER_SQL, conservative)

    freeze_reservation = _settled_reservation(
        "00000000-0000-0000-0000-000000000537",
        "00000000-0000-0000-0000-000000000538",
    )
    db.execute(RESERVATION_SQL, freeze_reservation)
    exact_reservation = _settled_reservation(
        "00000000-0000-0000-0000-000000000539",
        "00000000-0000-0000-0000-000000000540",
    )
    db.execute(RESERVATION_SQL, exact_reservation)

    invalid = (
        _valid_ledger(
            freeze_reservation,
            identifier="00000000-0000-0000-0000-000000000734",
        )
        | {
            "receipt": "{}",
            "receipt_key": "provider-usage-v1",
            "receipt_hmac": "A" * 43 + "=",
            "basis": "conservative_full_reservation",
            "conservative": 1,
        },
        _valid_ledger(
            exact_reservation,
            identifier="00000000-0000-0000-0000-000000000735",
        )
        | {
            "receipt": "{}",
            "receipt_key": "provider-usage-v1",
            "receipt_hmac": "A" * 43 + "=",
            "basis": "provider_reported_exact",
            "conservative": 1,
        },
        _valid_ledger(
            exact_reservation,
            identifier="00000000-0000-0000-0000-000000000736",
        )
        | {
            "receipt": "{}",
            "receipt_key": "provider-usage-v1",
            "receipt_hmac": "A" * 43 + "=",
            "basis": None,
            "conservative": 0,
        },
        _valid_ledger(
            exact_reservation,
            identifier="00000000-0000-0000-0000-000000000737",
        )
        | {"usage": "{}", "conservative": 0},
        _valid_ledger(
            exact_reservation,
            identifier="00000000-0000-0000-0000-000000000738",
        )
        | {
            "receipt": "{}",
            "receipt_key": "provider-usage-v1",
            "receipt_hmac": "A" * 43 + "=",
            "basis": "provider_reported_exact",
            "reservation_basis": "request_bound_exact",
            "conservative": 0,
        },
    )
    for candidate in invalid:
        with pytest.raises(sqlcipher3.IntegrityError):
            db.execute(LEDGER_SQL, candidate)
    db.close()


@pytest.mark.parametrize(
    "mutation",
    (
        {"price_sha": "A" * 64},
        {"input_rate": 1_000_000_001},
        {
            "effective_at": "2026-09-27T00:00:00.000000Z",
            "expires_at": "2026-08-27T00:00:00.000000Z",
        },
        {"basis": "request_bound_exact"},
        {"missing_policy": "conservative_full_reservation"},
        {"audio_rate": 1},
        {"tier_basis": "flat", "tier_max": 1},
        {"tier_basis": "llm_input_tokens", "tier_min": 256_001, "tier_max": 256_000},
        {"source_url": "http://127.0.0.1/price"},
    ),
)
def test_provider_prices_reject_unbounded_or_incoherent_rows(
    tmp_path: Path,
    mutation: dict[str, object],
) -> None:
    path = _private_path(tmp_path, "price-constraints.db")
    command.upgrade(_config(path), "head")
    db = open_sqlcipher(path, KEY)
    with pytest.raises(sqlcipher3.IntegrityError):
        db.execute(
            PRICE_SQL,
            _valid_price("00000000-0000-0000-0000-000000000401") | mutation,
        )
    db.close()


def test_provider_price_categories_and_tiers_are_closed_and_unique(tmp_path: Path) -> None:
    path = _private_path(tmp_path, "price-categories.db")
    command.upgrade(_config(path), "head")
    db = open_sqlcipher(path, KEY)
    db.execute(PRICE_SQL, _valid_price("00000000-0000-0000-0000-000000000401"))
    with pytest.raises(sqlcipher3.IntegrityError):
        db.execute(PRICE_SQL, _valid_price("00000000-0000-0000-0000-000000000402"))

    tts = _valid_price("00000000-0000-0000-0000-000000000403") | {
        "model": "tts-1",
        "category": "tts",
        "input_rate": 15_000_000,
        "output_rate": 0,
        "basis": "request_bound_exact",
    }
    db.execute(PRICE_SQL, tts)
    search = _valid_price("00000000-0000-0000-0000-000000000404") | {
        "category": "web_search",
        "search_rate": 10_000,
        "missing_policy": "conservative_full_reservation",
        "pricing_version": "openai-web-search-2026-08-27",
    }
    db.execute(PRICE_SQL, search)
    for identifier, field in (
        ("00000000-0000-0000-0000-000000000405", "input_rate"),
        ("00000000-0000-0000-0000-000000000406", "output_rate"),
        ("00000000-0000-0000-0000-000000000407", "search_rate"),
    ):
        with pytest.raises(sqlcipher3.IntegrityError):
            db.execute(PRICE_SQL, search | {"id": identifier, field: 0})

    qwen_low = _valid_price("00000000-0000-0000-0000-000000000408") | {
        "provider": "qwen",
        "model": "qwen3.7-plus",
        "pricing_version": "qwen3.7-plus-sg-2026-08-28",
        "source_url": "https://www.alibabacloud.com/help/en/model-studio/model-pricing",
        "tier_basis": "llm_input_tokens",
        "tier_min": 0,
        "tier_max": 256_000,
        "input_rate": 400_000,
        "output_rate": 1_600_000,
    }
    qwen_high = qwen_low | {
        "id": "00000000-0000-0000-0000-000000000409",
        "tier_min": 256_001,
        "tier_max": 1_000_000,
        "input_rate": 1_200_000,
        "output_rate": 4_800_000,
    }
    db.execute(PRICE_SQL, qwen_low)
    db.execute(PRICE_SQL, qwen_high)
    with pytest.raises(sqlcipher3.IntegrityError):
        db.execute(
            PRICE_SQL,
            qwen_low | {"id": "00000000-0000-0000-0000-000000000410"},
        )
    db.close()


@pytest.mark.parametrize(
    "mutation",
    (
        {"snapshot": None},
        {"basis": None},
        {"reserved": MAX_QUOTE_MICROS_SGD + 1},
        {"month_key": "2026-00"},
        {"state": "settled", "charged": None, "settled_at": None},
        {"state": "settled", "charged": 101, "settled_at": "2026-08-27T01:03:03.000004Z"},
        {"missing_policy": "conservative_full_reservation"},
    ),
)
def test_budget_reservations_reject_partial_unbounded_or_false_proofs(
    tmp_path: Path,
    mutation: dict[str, object],
) -> None:
    path = _private_path(tmp_path, "reservation-constraints.db")
    command.upgrade(_config(path), "head")
    db = open_sqlcipher(path, KEY)
    row = _valid_reservation(
        "00000000-0000-0000-0000-000000000501",
        "00000000-0000-0000-0000-000000000503",
    )
    with pytest.raises(sqlcipher3.IntegrityError):
        db.execute(RESERVATION_SQL, row | mutation)
    db.close()


def test_budget_denials_usage_receipts_and_ledger_proofs_are_closed(tmp_path: Path) -> None:
    path = _private_path(tmp_path, "budget-proof.db")
    command.upgrade(_config(path), "head")
    db = open_sqlcipher(path, KEY)
    quoted = _settled_reservation(
        "00000000-0000-0000-0000-000000000501",
        "00000000-0000-0000-0000-000000000503",
    )
    db.execute(RESERVATION_SQL, quoted)
    quoted_for_failed_ledger = _settled_reservation(
        "00000000-0000-0000-0000-000000000508",
        "00000000-0000-0000-0000-000000000509",
    )
    db.execute(RESERVATION_SQL, quoted_for_failed_ledger)
    denied = _valid_reservation(
        "00000000-0000-0000-0000-000000000504",
        "00000000-0000-0000-0000-000000000505",
    ) | {
        "outcome": "deny_unknown_price",
        "reserved": 0,
        "snapshot": None,
        "pricing_version": None,
        "price_sha": None,
        "basis": None,
        "missing_policy": None,
        "fx_version": None,
        "fx_sha": None,
        "commitment_key": None,
        "commitment_hmac": None,
        "state": "denied",
    }
    db.execute(RESERVATION_SQL, denied)
    with pytest.raises(sqlcipher3.IntegrityError):
        db.execute(
            RESERVATION_SQL,
            denied
            | {
                "id": "00000000-0000-0000-0000-000000000506",
                "attempt_id": "00000000-0000-0000-0000-000000000507",
                "snapshot": "{}",
            },
        )

    call_sql = """INSERT INTO provider_calls
        (id,request_id,attempt_id,authorization_id,budget_reservation_id,purpose,
         provider,model,request_hmac_key_id,request_hmac_b64,category,outcome,
         gateway_ordering_version,transport_phase,provider_usage_json,
         provider_usage_receipt_key_id,provider_usage_receipt_hmac_b64,started_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""
    partial_usage = (
        "00000000-0000-0000-0000-000000000601",
        quoted["request_id"],
        quoted["attempt_id"],
        "00000000-0000-0000-0000-000000000602",
        quoted["id"],
        "cloud_reasoning",
        "openai",
        "gpt-5.6-sol",
        "provider-request-v1",
        "A" * 43 + "=",
        "llm",
        "succeeded",
        1,
        "finished",
        "{}",
        None,
        None,
        "2026-08-27T01:02:03.000004Z",
    )
    with pytest.raises(sqlcipher3.IntegrityError):
        db.execute(call_sql, partial_usage)

    ledger_sql = """INSERT INTO cost_ledger
        (id,reservation_id,month_key,reserved_micros_sgd,charged_micros_sgd,
         usage_json,provider_usage_receipt_json,provider_usage_receipt_key_id,
         provider_usage_receipt_hmac_b64,accounting_basis,
         reservation_primary_accounting_basis,reservation_missing_evidence_policy,
         conservative_estimate_used,estimate_overrun,hard_cap_exceeded,
         pricing_version,price_source_sha256,fx_version,fx_source_sha256,settled_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""
    ledger_base = (
        "00000000-0000-0000-0000-000000000701",
        quoted["id"],
        "2026-08",
        100,
        100,
        "{}",
        None,
        None,
        None,
        None,
        quoted["basis"],
        quoted["missing_policy"],
        1,
        0,
        0,
        "openai-2026-08-27",
        "a" * 64,
        "bootstrap-safety-factor-2026-08-27",
        "b" * 64,
        "2026-08-27T01:03:03.000004Z",
    )
    db.execute(ledger_sql, ledger_base)
    with pytest.raises(sqlcipher3.IntegrityError):
        db.execute(
            ledger_sql,
            (
                "00000000-0000-0000-0000-000000000702",
                quoted_for_failed_ledger["id"],
                *ledger_base[2:6],
                "{}",
                None,
                None,
                "provider_reported_exact",
                quoted_for_failed_ledger["basis"],
                quoted_for_failed_ledger["missing_policy"],
                0,
                0,
                0,
                *ledger_base[15:],
            ),
        )
    with pytest.raises(sqlcipher3.IntegrityError):
        db.execute(
            ledger_sql,
            (
                "00000000-0000-0000-0000-000000000703",
                quoted_for_failed_ledger["id"],
                "2026-08",
                100,
                101,
                "{}",
                "{}",
                "provider-usage-v1",
                "A" * 43 + "=",
                "provider_reported_exact",
                quoted_for_failed_ledger["basis"],
                quoted_for_failed_ledger["missing_policy"],
                0,
                0,
                0,
                *ledger_base[15:],
            ),
        )
    for month_key, reserved in (("2026-09", 100), ("2026-08", 99)):
        with pytest.raises(sqlcipher3.IntegrityError):
            db.execute(
                ledger_sql,
                (
                    "00000000-0000-0000-0000-000000000704",
                    quoted_for_failed_ledger["id"],
                    month_key,
                    reserved,
                    99,
                    "{}",
                    None,
                    None,
                    None,
                    None,
                    quoted_for_failed_ledger["basis"],
                    quoted_for_failed_ledger["missing_policy"],
                    1,
                    0,
                    0,
                    *ledger_base[15:],
                ),
            )
    db.close()


def test_authoritative_budget_quote_usage_and_overrun_columns_are_migrated(
    tmp_path: Path,
) -> None:
    path = _private_path(tmp_path, "budget-columns.db")
    command.upgrade(_config(path), "head")
    db = open_sqlcipher(path, KEY)

    def columns(table: str) -> dict[str, tuple[object, ...]]:
        return {str(row[1]): tuple(row) for row in db.execute(f"PRAGMA table_info('{table}')")}

    prices = columns("provider_prices")
    reservations = columns("budget_reservations")
    calls = columns("provider_calls")
    ledger = columns("cost_ledger")
    assert {
        "provider",
        "tier_basis",
        "tier_min_input_tokens",
        "tier_max_input_tokens",
        "input_micro_usd_per_million",
        "output_micro_usd_per_million",
        "audio_micro_usd_per_minute",
        "web_search_micro_usd_per_call",
        "primary_accounting_basis",
        "missing_evidence_policy",
        "pricing_version",
        "price_source_url",
        "price_source_sha256",
        "fx_version",
        "fx_source_sha256",
    } <= set(prices)
    assert {
        "reserved_micros_sgd",
        "charged_micros_sgd",
        "usage_ceiling_json",
        "price_snapshot_json",
        "primary_accounting_basis",
        "missing_evidence_policy",
        "pricing_version",
        "price_source_sha256",
        "fx_version",
        "fx_source_sha256",
        "pricing_commitment_key_id",
        "pricing_commitment_hmac_b64",
        "estimate_overrun",
        "gateway_ordering_version",
        "transport_phase",
        "reconciled_at",
    } <= set(reservations)
    assert {
        "provider_usage_json",
        "provider_usage_receipt_key_id",
        "provider_usage_receipt_hmac_b64",
        "gateway_ordering_version",
        "transport_phase",
    } <= set(calls)
    assert {
        "month_key",
        "reserved_micros_sgd",
        "charged_micros_sgd",
        "provider_usage_receipt_json",
        "provider_usage_receipt_key_id",
        "provider_usage_receipt_hmac_b64",
        "accounting_basis",
        "reservation_primary_accounting_basis",
        "reservation_missing_evidence_policy",
        "conservative_estimate_used",
        "estimate_overrun",
        "hard_cap_exceeded",
        "pricing_version",
        "price_source_sha256",
        "fx_version",
        "fx_source_sha256",
    } <= set(ledger)
    assert all(
        reservations[name][3] == 1
        for name in (
            "reserved_micros_sgd",
            "usage_ceiling_json",
            "estimate_overrun",
            "gateway_ordering_version",
            "transport_phase",
        )
    )
    assert all(
        calls[name][3] == 0
        for name in (
            "provider_usage_json",
            "provider_usage_receipt_key_id",
            "provider_usage_receipt_hmac_b64",
        )
    )
    assert all(
        ledger[name][3] == 1
        for name in (
            "month_key",
            "reserved_micros_sgd",
            "charged_micros_sgd",
            "reservation_primary_accounting_basis",
            "reservation_missing_evidence_policy",
            "conservative_estimate_used",
            "estimate_overrun",
            "hard_cap_exceeded",
        )
    )
    db.close()


def test_metadata_uses_bounded_types_and_contains_no_private_content_columns() -> None:
    assert EXPECTED_TABLES - {"alembic_version"} == FOUNDATION_TABLE_NAMES
    assert len(FOUNDATION_0001_METADATA.tables) == 16
    forbidden = {"transcript", "frame", "prompt", "memory", "credential", "secret"}
    for table in FOUNDATION_0001_METADATA.tables.values():
        for column in table.columns:
            lowered = column.name.lower()
            assert not any(token in lowered for token in forbidden)
            assert "audio" not in lowered or lowered == "audio_micro_usd_per_minute"
            if column.name.endswith("_at"):
                assert getattr(column.type, "length", None) == 27
        sql = " ".join(
            str(constraint.sqltext)
            for constraint in table.constraints
            if hasattr(constraint, "sqltext")
        )
        for column in table.columns:
            if column.name.endswith("_json"):
                assert f"json_valid({column.name})" in sql
    assert {
        column.name
        for column in FOUNDATION_0001_METADATA.tables["reachy_core_tx_sequences"].columns
    } == {"device_id", "last_sequence"}
    assert {
        column.name
        for column in FOUNDATION_0001_METADATA.tables["reachy_duplex_correlations"].columns
    } == {
        "device_id",
        "correlation_id",
        "purpose",
        "request_direction",
        "state",
        "first_sequence",
        "last_sequence",
        "created_at",
        "updated_at",
    }


def test_every_integer_column_requires_the_sqlite_integer_storage_class() -> None:
    for table in FOUNDATION_0001_METADATA.tables.values():
        check_sql = "".join(
            "".join(str(constraint.sqltext).lower().split())
            for constraint in table.constraints
            if hasattr(constraint, "sqltext")
        )
        for column in table.columns:
            if isinstance(column.type, Integer):
                assert f"typeof({column.name})='integer'" in check_sql, (
                    f"{table.name}.{column.name} accepts non-integer SQLite storage classes"
                )


def test_representative_integer_columns_reject_real_values(tmp_path: Path) -> None:
    path = _private_path(tmp_path, "integer-affinity.db")
    command.upgrade(_config(path), "head")
    db = open_sqlcipher(path, KEY)

    with pytest.raises(sqlcipher3.IntegrityError):
        db.execute(
            PRICE_SQL,
            _valid_price("00000000-0000-0000-0000-000000000451") | {"input_rate": 1.5},
        )
    with pytest.raises(sqlcipher3.IntegrityError):
        db.execute(
            RESERVATION_SQL,
            _valid_reservation(
                "00000000-0000-0000-0000-000000000551",
                "00000000-0000-0000-0000-000000000552",
            )
            | {"reserved": 1.5},
        )
    with pytest.raises(sqlcipher3.IntegrityError):
        db.execute(
            "INSERT INTO runtime_settings(key,value_json,version,updated_at) VALUES (?,?,?,?)",
            ("real-version", "{}", 1.5, "2026-08-27T01:02:03.000004Z"),
        )
    db.close()


def test_foundation_reserves_content_free_reachy_duplex_state(tmp_path: Path) -> None:
    path = _private_path(tmp_path, "duplex.db")
    command.upgrade(_config(path), "0001_foundation")
    db = open_sqlcipher(path, KEY)
    assert {row[1] for row in db.execute("PRAGMA table_info('reachy_core_tx_sequences')")} == {
        "device_id",
        "last_sequence",
    }
    assert {row[1] for row in db.execute("PRAGMA table_info('reachy_duplex_correlations')")} == {
        "device_id",
        "correlation_id",
        "purpose",
        "request_direction",
        "state",
        "first_sequence",
        "last_sequence",
        "created_at",
        "updated_at",
    }
    sql = " ".join(
        str(row[0])
        for row in db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name LIKE 'reachy_%'"
        )
    ).lower()
    assert not any(token in sql for token in ("payload", "transcript", "content"))
    db.close()
