from __future__ import annotations

import base64
import inspect
from datetime import UTC, datetime, timedelta, timezone
from getpass import getuser
from pathlib import Path
from typing import cast
from uuid import UUID

import pytest
from sqlalchemy import text
from tuntun_contracts.audit import AuditDraft
from tuntun_contracts.base import Commitment
from tuntun_core.adapters.sqlcipher.unit_of_work import UnitOfWork
from tuntun_core.services.audit.ledger import AsyncAuditLedger, AuditLedger, compute_chain_values

from tests.conftest import AuditedDatabase, AuditFixture, database_files, draft


class _FixedClock:
    def __init__(self, instant: datetime) -> None:
        self.instant = instant
        self.calls = 0

    def now(self) -> datetime:
        self.calls += 1
        return self.instant

    def monotonic(self) -> float:
        return 0.0


def test_chain_formula_is_deterministic_and_purpose_separated() -> None:
    audit_draft = AuditDraft(
        event_id=UUID(int=1),
        occurred_at=datetime(2026, 8, 27, tzinfo=UTC),
        actor_pseudonym="synthetic-guest",
        action_code="foundation.init",
        outcome="allow",
        reason_code="initialized",
        correlation_id=UUID(int=2),
        payload_commitment=Commitment(
            algorithm="HMAC-SHA-256",
            key_id="audit-v1",
            value_b64="A" * 43 + "=",
        ),
    )

    first = compute_chain_values(None, audit_draft, "audit-v1", b"K" * 32)
    second = compute_chain_values(None, audit_draft, "audit-v1", b"K" * 32)

    assert first == second
    assert len(first.public_hash_hex) == 64
    assert first.hmac_b64 != first.public_hash_hex


def test_chain_formula_rejects_empty_previous_hash() -> None:
    with pytest.raises(ValueError, match="public hash"):
        compute_chain_values("", draft(1), "audit-v1", b"K" * 32)


def test_audit_storage_validators_reject_noncanonical_values() -> None:
    from tuntun_core.services.audit.ledger import _format_utc_text, _validate_hmac_b64

    with pytest.raises(ValueError, match="canonical base64"):
        _validate_hmac_b64(b"A" * 44)
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        _validate_hmac_b64(base64.b64encode(b"short").decode("ascii"))
    with pytest.raises(ValueError, match="timezone-aware"):
        _format_utc_text(datetime(2026, 8, 27))


@pytest.mark.parametrize(
    "key_id",
    ("short", "audit key", "audit-v1-\N{SNOWMAN}", "a" * 129),
)
def test_audit_ledger_rejects_noncanonical_hmac_key_ids(key_id: str) -> None:
    with pytest.raises(ValueError, match="HMAC key ID"):
        AuditLedger(key_id, b"K" * 32, _FixedClock(datetime(2026, 8, 27, tzinfo=UTC)))


def test_rotation_and_segment_sealing_require_all_retained_keys(
    audit_fixture: AuditFixture,
) -> None:
    audit_fixture.append_with_key("audit-v1", b"K" * 32, 1)
    audit_fixture.append_with_key("audit-v2", b"R" * 32, 2)

    segment = audit_fixture.seal(1, 2)

    assert (segment.first_ordinal, segment.last_ordinal, segment.receipt_count) == (1, 2, 2)
    assert audit_fixture.verify({"audit-v1": b"K" * 32, "audit-v2": b"R" * 32}).valid is True
    assert audit_fixture.verify({"audit-v2": b"R" * 32}).reason == "missing-hmac-key"


def test_segment_seal_uses_the_injected_clock_exactly(audit_fixture: AuditFixture) -> None:
    audit_fixture.append_index(1)
    audit_fixture.append_index(2)

    segment = audit_fixture.seal(1, 2)

    expected = datetime(2026, 8, 27, 12, 34, 56, 789123, tzinfo=UTC)
    assert segment.sealed_at == expected
    assert audit_fixture.segment_sealed_at(segment.segment_id) == "2026-08-27T12:34:56.789123Z"
    assert audit_fixture.clock.calls == ("now",)


def test_segment_seal_rejects_naive_clock(audit_fixture: AuditFixture) -> None:
    audit_fixture.append_index(1)
    clock = _FixedClock(datetime(2026, 8, 27, 12, 34, 56, 789123))

    with UnitOfWork(audit_fixture.database.engine) as uow:
        with pytest.raises(ValueError, match="timezone-aware"):
            AuditLedger("audit-v1", b"K" * 32, clock).seal(uow, 1, 1)
        uow.rollback()

    assert clock.calls == 1
    assert audit_fixture.verify().valid is True


def test_segment_seal_rejects_noncontiguous_ranges(audit_fixture: AuditFixture) -> None:
    audit_fixture.append_index(1)

    with UnitOfWork(audit_fixture.database.engine) as uow:
        with pytest.raises(ValueError, match="not contiguous"):
            AuditLedger("audit-v1", b"K" * 32, audit_fixture.clock).seal(uow, 1, 2)
        uow.rollback()


def test_segment_seal_rejects_huge_sparse_range_without_materializing(
    audit_fixture: AuditFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tuntun_core.services.audit.ledger as ledger_module

    audit_fixture.append_index(1)

    def fail_range(*args: object) -> range:
        del args
        raise AssertionError("seal must not materialize the requested ordinal range")

    monkeypatch.setattr(ledger_module, "range", fail_range, raising=False)

    with UnitOfWork(audit_fixture.database.engine) as uow:
        with pytest.raises(ValueError, match="not contiguous"):
            AuditLedger("audit-v1", b"K" * 32, audit_fixture.clock).seal(uow, 1, 10**12)
        uow.rollback()


@pytest.mark.parametrize(
    ("first_ordinal", "last_ordinal"),
    (
        (1.0, 1),
        (True, 1),
        (1, False),
        (0, 1),
        (2, 1),
        (1, 10**100),
    ),
)
def test_segment_seal_rejects_noninteger_or_invalid_requested_bounds(
    audit_fixture: AuditFixture,
    first_ordinal: object,
    last_ordinal: object,
) -> None:
    audit_fixture.append_index(1)

    with UnitOfWork(audit_fixture.database.engine) as uow:
        with pytest.raises(ValueError, match="not contiguous"):
            AuditLedger("audit-v1", b"K" * 32, audit_fixture.clock).seal(
                uow,
                cast(int, first_ordinal),
                cast(int, last_ordinal),
            )
        uow.rollback()


def test_segment_seal_rejects_restored_real_middle_ordinal(
    audit_fixture: AuditFixture,
) -> None:
    audit_fixture.append_index(1)
    audit_fixture.append_index(2)
    audit_fixture.append_index(3)
    audit_fixture.replace_receipt_column_offline("ordinal", 2.5, ordinal=2)

    with UnitOfWork(audit_fixture.database.engine) as uow:
        with pytest.raises(ValueError, match="not contiguous"):
            AuditLedger("audit-v1", b"K" * 32, audit_fixture.clock).seal(uow, 1, 3)
        uow.rollback()


def test_segment_seal_normalizes_aware_clock_to_utc(audit_fixture: AuditFixture) -> None:
    audit_fixture.append_index(1)
    clock = _FixedClock(
        datetime(2026, 8, 27, 20, 34, 56, 789123, tzinfo=timezone(timedelta(hours=8))),
    )

    with UnitOfWork(audit_fixture.database.engine) as uow:
        segment = AuditLedger("audit-v1", b"K" * 32, clock).seal(uow, 1, 1)
        uow.commit()

    assert segment.sealed_at == datetime(2026, 8, 27, 12, 34, 56, 789123, tzinfo=UTC)
    assert audit_fixture.segment_sealed_at(segment.segment_id) == "2026-08-27T12:34:56.789123Z"
    assert clock.calls == 1


def test_initialization_audit_record_excludes_host_identity(
    audit_fixture: AuditFixture,
) -> None:
    init_draft = draft(10, action_code="foundation.init.0.1.0.dev0").model_copy(
        update={"reason_code": "schema.0001_foundation"},
    )

    with UnitOfWork(audit_fixture.database.engine) as uow:
        AuditLedger("audit-v1", b"K" * 32, audit_fixture.clock).append(uow, init_draft)
        uow.commit()

    canonical_body = audit_fixture.canonical_body(1)
    assert '"action_code":"foundation.init.0.1.0.dev0"' in canonical_body
    assert '"reason_code":"schema.0001_foundation"' in canonical_body
    assert getuser() not in canonical_body
    assert str(Path.cwd()) not in canonical_body


def test_audit_receipt_rolls_back_with_owning_unit_of_work(
    audited_database: AuditedDatabase,
) -> None:
    household_id = "00000000-0000-0000-0000-000000000601"

    with (
        pytest.raises(RuntimeError, match="synthetic kill point"),
        UnitOfWork(audited_database.engine) as uow,
    ):
        uow.execute(
            text(
                "INSERT INTO households"
                "(id, display_label_ciphertext, timezone, created_at) "
                "VALUES(:id, :label, 'Asia/Singapore', :now)"
            ),
            {
                "id": household_id,
                "label": b"ciphertext",
                "now": "2026-08-27T01:02:03.000004Z",
            },
        )
        AuditLedger("audit-v1", b"K" * 32, _FixedClock(datetime(2026, 8, 27, tzinfo=UTC))).append(
            uow,
            draft(99),
        )
        raise RuntimeError("synthetic kill point")

    with audited_database.engine.connect() as connection:
        household_count = connection.execute(
            text("SELECT count(*) FROM households WHERE id = :id"),
            {"id": household_id},
        ).scalar_one()
        audit_count = connection.execute(
            text("SELECT count(*) FROM audit_receipts WHERE ordinal = 3"),
        ).scalar_one()

    assert household_count == 0
    assert audit_count == 0


def test_encrypted_audit_files_do_not_store_plaintext_synthetic_values(
    audited_database: AuditedDatabase,
) -> None:
    forbidden = (
        b"SQLite format 3",
        b"synthetic-guest",
        b"foundation.fixture",
        b"fixture-1",
        b"fixture-2",
    )

    for database_file in database_files(audited_database):
        if not database_file.exists():
            continue
        raw = database_file.read_bytes()
        for sentinel in forbidden:
            assert sentinel not in raw


def test_audit_service_depends_only_on_project_owned_transaction_protocol() -> None:
    import tuntun_core.services.audit.ledger as ledger_module

    source = inspect.getsource(ledger_module)
    assert "tuntun_core.adapters" not in source
    assert "tuntun_core.services.transactions.protocols" in source


def test_async_audit_ledger_satisfies_audit_port_binding() -> None:
    from tuntun_core.services.audit.ledger import _bind_audit_port

    ledger = AsyncAuditLedger(
        AuditLedger("audit-v1", b"K" * 32, _FixedClock(datetime(2026, 8, 27, tzinfo=UTC)))
    )

    assert _bind_audit_port(ledger) is ledger


def test_audit_fixtures_are_defined_in_root_conftest_only() -> None:
    root_conftest = Path("tests/conftest.py")
    source = root_conftest.read_text()

    assert "def audited_database" in source
    assert "def audit_fixture" in source
    assert "tests.audit_support" not in source
    assert not Path("tests/audit_support.py").exists()
    assert not Path("tests/unit/audit/conftest.py").exists()
    assert not Path("tests/integration/audit/conftest.py").exists()
    assert "tests.audit_support" not in Path("tests/security/conftest.py").read_text()


def test_verifier_uses_bounded_body_prefix_and_constant_time_comparison() -> None:
    import tuntun_core.services.audit.verifier as verifier_module

    source = inspect.getsource(verifier_module.AuditVerifier.verify)
    assert "length(CAST(canonical_body_json AS BLOB))" in source
    assert "substr(CAST(canonical_body_json AS BLOB)" in source
    assert "canonical_body_json FROM audit_receipts" not in source
    assert "hmac.compare_digest" in inspect.getsource(verifier_module)
