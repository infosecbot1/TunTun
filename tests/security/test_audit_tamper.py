from __future__ import annotations

import base64
from collections.abc import Iterable, Iterator, Mapping
from typing import cast

import pytest
from sqlalchemy.engine import Connection
from tuntun_core.services.audit.ledger import _format_utc_text, compute_chain_values
from tuntun_core.services.audit.verifier import AuditVerifier

from tests.conftest import AuditedDatabase, AuditFixture, draft


class _Mappings:
    def __init__(self, rows: Iterable[Mapping[str, object]]) -> None:
        self._rows = tuple(rows)

    def __iter__(self) -> Iterator[Mapping[str, object]]:
        return iter(self._rows)

    def first(self) -> Mapping[str, object] | None:
        return self._rows[0] if self._rows else None


class _Result:
    def __init__(
        self,
        *,
        rows: Iterable[Mapping[str, object]] = (),
        scalars: Iterable[object] = (),
    ) -> None:
        self._rows = tuple(rows)
        self._scalars = tuple(scalars)

    def mappings(self) -> _Mappings:
        return _Mappings(self._rows)

    def scalars(self) -> Iterator[object]:
        return iter(self._scalars)


class _VerifierConnection:
    def __init__(
        self,
        *,
        receipts: Iterable[Mapping[str, object]],
        segments: Iterable[Mapping[str, object]] = (),
        segment_ordinals: Iterable[object] = (),
        terminal: Mapping[str, object] | None = None,
    ) -> None:
        self._receipts = tuple(receipts)
        self._segments = tuple(segments)
        self._segment_ordinals = tuple(segment_ordinals)
        self._terminal = terminal

    def execute(self, statement: object, parameters: object | None = None) -> _Result:
        del parameters
        sql = str(statement)
        if "length(CAST(canonical_body_json AS BLOB))" in sql:
            return _Result(rows=self._receipts)
        if "FROM audit_segments" in sql:
            return _Result(rows=self._segments)
        if "SELECT ordinal" in sql:
            return _Result(scalars=self._segment_ordinals)
        if "WHERE ordinal = :ordinal" in sql:
            return _Result(rows=() if self._terminal is None else (self._terminal,))
        raise AssertionError(f"unexpected verifier query: {sql}")


def _connection(fake: _VerifierConnection) -> Connection:
    return cast(Connection, fake)


def _receipt_rows(count: int) -> tuple[dict[str, object], ...]:
    rows: list[dict[str, object]] = []
    previous: str | None = None
    for index in range(1, count + 1):
        audit_draft = draft(index)
        values = compute_chain_values(previous, audit_draft, "audit-v1", b"K" * 32)
        body = values.canonical_body_json.encode("utf-8")
        rows.append(
            {
                "ordinal": index,
                "previous_public_hash_hex": previous,
                "public_hash_hex": values.public_hash_hex,
                "hmac_key_id": "audit-v1",
                "hmac_b64": values.hmac_b64,
                "occurred_at": _format_utc_text(audit_draft.occurred_at),
                "canonical_body_type": "text",
                "canonical_body_byte_count": len(body),
                "canonical_body_json_prefix": body,
            }
        )
        previous = values.public_hash_hex
    return tuple(rows)


def _segment_row(receipts: tuple[Mapping[str, object], ...]) -> dict[str, object]:
    terminal = receipts[-1]
    return {
        "id": "11111111-1111-4111-8111-111111111111",
        "first_ordinal": 1,
        "last_ordinal": len(receipts),
        "receipt_count": len(receipts),
        "terminal_public_hash_hex": terminal["public_hash_hex"],
        "terminal_hmac_b64": terminal["hmac_b64"],
        "hmac_key_id": terminal["hmac_key_id"],
        "sealed_at": "2026-08-27T00:00:00.000000Z",
    }


def test_database_triggers_reject_audit_update_and_delete(
    audited_database: AuditedDatabase,
) -> None:
    connection = audited_database.engine.raw_connection()
    try:
        with pytest.raises(Exception, match="append-only"):
            connection.execute("UPDATE audit_receipts SET canonical_body_json='{}'")
        with pytest.raises(Exception, match="append-only"):
            connection.execute("DELETE FROM audit_receipts")
    finally:
        connection.close()


def test_verifier_detects_offline_ciphertext_tamper(
    audited_database: AuditedDatabase,
) -> None:
    with audited_database.engine.connect() as connection:
        result = AuditVerifier({"audit-v1": b"K" * 32}).verify(connection)

    assert result.valid is True
    assert result.count == 2


def test_verifier_detects_offline_occurred_at_tamper(audit_fixture: AuditFixture) -> None:
    audit_fixture.append_index(1)
    audit_fixture.replace_receipt_column_offline(
        "occurred_at",
        "2026-08-27T00:00:00.000000Z",
    )

    result = audit_fixture.verify({"audit-v1": b"K" * 32})

    assert result.valid is False
    assert result.reason == "occurred-at-mismatch"


def test_verifier_rejects_real_valued_restored_receipt_ordinal(
    audit_fixture: AuditFixture,
) -> None:
    audit_fixture.append_index(1)
    audit_fixture.replace_receipt_column_offline("ordinal", 1.5)

    result = audit_fixture.verify({"audit-v1": b"K" * 32})

    assert result.valid is False
    assert result.reason == "invalid-receipt-row"


def test_verifier_detects_restored_receipt_ordinal_gap(audit_fixture: AuditFixture) -> None:
    audit_fixture.append_index(1)
    audit_fixture.replace_receipt_column_offline("ordinal", 2)

    result = audit_fixture.verify({"audit-v1": b"K" * 32})

    assert result.valid is False
    assert result.reason == "ordinal-or-link-mismatch"


@pytest.mark.parametrize(
    ("column", "value", "reason"),
    (
        ("hmac_key_id", "audit key", "invalid-hmac-key"),
        ("hmac_key_id", "a" * 129, "invalid-hmac-key"),
        ("hmac_b64", "not-base64", "invalid-hmac"),
        ("hmac_b64", base64.b64encode(b"R" * 32).decode("ascii"), "hash-or-hmac-mismatch"),
        ("public_hash_hex", "z" * 64, "invalid-receipt-row"),
        ("canonical_body_json", b"{}", "invalid-canonical-body"),
    ),
)
def test_verifier_fails_closed_on_malformed_restored_receipt_rows(
    audit_fixture: AuditFixture,
    column: str,
    value: object,
    reason: str,
) -> None:
    audit_fixture.append_index(1)
    audit_fixture.replace_receipt_column_offline(column, value)

    result = audit_fixture.verify({"audit-v1": b"K" * 32})

    assert result.valid is False
    assert result.reason == reason


def test_verifier_fails_closed_on_malformed_restored_occurred_at_type(
    audit_fixture: AuditFixture,
) -> None:
    audit_fixture.append_index(1)
    audit_fixture.replace_receipt_column_offline("occurred_at", b"not-text")

    result = audit_fixture.verify({"audit-v1": b"K" * 32})

    assert result.valid is False
    assert result.reason == "invalid-receipt-row"


def test_verifier_fails_closed_when_retained_key_material_is_malformed(
    audit_fixture: AuditFixture,
) -> None:
    audit_fixture.append_index(1)

    result = audit_fixture.verify({"audit-v1": b"short"})

    assert result.valid is False
    assert result.reason == "invalid-hmac-key"


def test_verifier_fails_closed_when_segment_key_material_is_malformed(
    audit_fixture: AuditFixture,
) -> None:
    audit_fixture.append_index(1)
    audit_fixture.append_index(2)
    audit_fixture.seal(1, 2)
    audit_fixture.replace_segment_column_offline("hmac_key_id", "audit-v2")

    result = audit_fixture.verify({"audit-v1": b"K" * 32, "audit-v2": b"short"})

    assert result.valid is False
    assert result.reason == "invalid-hmac-key"


def test_verifier_fails_closed_when_sealed_terminal_receipt_is_removed_offline(
    audit_fixture: AuditFixture,
) -> None:
    audit_fixture.append_index(1)
    audit_fixture.append_index(2)
    audit_fixture.seal(1, 2)
    audit_fixture.delete_receipt_offline(2)

    result = audit_fixture.verify({"audit-v1": b"K" * 32})

    assert result.valid is False
    assert result.reason == "invalid-segment-range"


@pytest.mark.parametrize(
    ("column", "value", "reason"),
    (
        ("first_ordinal", 0, "invalid-segment-range"),
        ("first_ordinal", 1.5, "invalid-segment-range"),
        ("last_ordinal", 3, "invalid-segment-range"),
        ("receipt_count", 2.5, "invalid-segment-range"),
        ("terminal_public_hash_hex", "b" * 64, "segment-terminal-mismatch"),
        ("terminal_hmac_b64", "not-base64", "invalid-segment-row"),
        ("hmac_key_id", "audit key", "invalid-hmac-key"),
        ("hmac_key_id", "audit-v2", "missing-hmac-key"),
        ("id", "not-a-uuid", "invalid-segment-row"),
        ("sealed_at", "not-a-timestamp", "invalid-segment-row"),
    ),
)
def test_verifier_fails_closed_on_malformed_restored_segments(
    audit_fixture: AuditFixture,
    column: str,
    value: object,
    reason: str,
) -> None:
    audit_fixture.append_index(1)
    audit_fixture.append_index(2)
    audit_fixture.seal(1, 2)
    audit_fixture.replace_segment_column_offline(column, value)

    result = audit_fixture.verify({"audit-v1": b"K" * 32})

    assert result.valid is False
    assert result.reason == reason


@pytest.mark.parametrize(
    "mutation",
    (
        "duplicate_key",
        "noncanonical_whitespace",
        "overdeep_json",
        "flat_json_overflow",
        "body_over_64k",
    ),
)
def test_verifier_fails_closed_on_malformed_persisted_canonical_body(
    audit_fixture: AuditFixture,
    mutation: str,
) -> None:
    audit_fixture.replace_canonical_body_offline(mutation)

    result = audit_fixture.verify({"audit-v1": b"K" * 32})

    assert result.valid is False
    assert result.reason == "invalid-canonical-body"


def test_verifier_copies_only_valid_key_map_entries() -> None:
    receipts = _receipt_rows(1)
    keys = cast(Mapping[str, bytes], {object(): b"invalid", "audit-v1": b"K" * 32})

    result = AuditVerifier(keys).verify(_connection(_VerifierConnection(receipts=receipts)))

    assert result.valid is True
    assert result.count == 1


def test_verifier_fails_closed_on_driver_body_size_type() -> None:
    row = dict(_receipt_rows(1)[0])
    row["canonical_body_byte_count"] = 1.5

    result = AuditVerifier({"audit-v1": b"K" * 32}).verify(
        _connection(_VerifierConnection(receipts=(row,)))
    )

    assert result.valid is False
    assert result.reason == "invalid-canonical-body"


def test_verifier_fails_closed_on_truncated_body_prefix() -> None:
    row = dict(_receipt_rows(1)[0])
    body_size = row["canonical_body_byte_count"]
    assert type(body_size) is int
    row["canonical_body_byte_count"] = body_size + 1

    result = AuditVerifier({"audit-v1": b"K" * 32}).verify(
        _connection(_VerifierConnection(receipts=(row,)))
    )

    assert result.valid is False
    assert result.reason == "invalid-canonical-body"


def test_verifier_fails_closed_on_driver_segment_ordinal_type() -> None:
    receipts = _receipt_rows(2)

    result = AuditVerifier({"audit-v1": b"K" * 32}).verify(
        _connection(
            _VerifierConnection(
                receipts=receipts,
                segments=(_segment_row(receipts),),
                segment_ordinals=(1.5, 2),
                terminal=receipts[-1],
            )
        )
    )

    assert result.valid is False
    assert result.reason == "invalid-segment-range"


def test_verifier_fails_closed_on_driver_segment_range_gap() -> None:
    receipts = _receipt_rows(2)

    result = AuditVerifier({"audit-v1": b"K" * 32}).verify(
        _connection(
            _VerifierConnection(
                receipts=receipts,
                segments=(_segment_row(receipts),),
                segment_ordinals=(1,),
                terminal=receipts[-1],
            )
        )
    )

    assert result.valid is False
    assert result.reason == "invalid-segment-range"


def test_verifier_fails_closed_when_segment_terminal_disappears() -> None:
    receipts = _receipt_rows(2)

    result = AuditVerifier({"audit-v1": b"K" * 32}).verify(
        _connection(
            _VerifierConnection(
                receipts=receipts,
                segments=(_segment_row(receipts),),
                segment_ordinals=(1, 2),
                terminal=None,
            )
        )
    )

    assert result.valid is False
    assert result.reason == "invalid-segment-range"


def test_verifier_fails_closed_on_invalid_terminal_second_read() -> None:
    receipts = _receipt_rows(2)
    terminal = dict(receipts[-1])
    terminal["public_hash_hex"] = "z" * 64

    result = AuditVerifier({"audit-v1": b"K" * 32}).verify(
        _connection(
            _VerifierConnection(
                receipts=receipts,
                segments=(_segment_row(receipts),),
                segment_ordinals=(1, 2),
                terminal=terminal,
            )
        )
    )

    assert result.valid is False
    assert result.reason == "invalid-receipt-row"
