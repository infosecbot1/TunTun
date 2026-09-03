from __future__ import annotations

import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection
from tuntun_contracts.audit import AuditDraft
from tuntun_contracts.base import parse_contract_json

from .ledger import (
    MAX_AUDIT_ORDINAL,
    _format_utc_text,
    _storage_int,
    _storage_text,
    _validate_hmac_b64,
    _validate_hmac_key,
    _validate_hmac_key_id,
    _validate_public_hash_hex,
    compute_chain_values,
)

_MAX_CANONICAL_BODY_BYTES = 65_536
_CANONICAL_BODY_PREFIX_BYTES = _MAX_CANONICAL_BODY_BYTES + 1


@dataclass(frozen=True, slots=True)
class AuditVerification:
    valid: bool
    count: int
    terminal_public_hash_hex: str | None
    reason: str


def _validate_uuid_text(value: object) -> str:
    uuid_text = _storage_text(value)
    try:
        parsed = UUID(uuid_text)
    except (TypeError, ValueError) as error:
        raise ValueError("audit segment ID is invalid") from error
    if str(parsed) != uuid_text:
        raise ValueError("audit segment ID must be canonical UUID text")
    return uuid_text


def _validate_utc_storage_text(value: object) -> str:
    timestamp = _storage_text(value)
    if len(timestamp) != 27 or timestamp[10] != "T" or timestamp[19] != "." or timestamp[-1] != "Z":
        raise ValueError("audit timestamp must be canonical UTC text")
    try:
        parsed = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as error:
        raise ValueError("audit timestamp must be parseable UTC text") from error
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != timestamp:
        raise ValueError("audit timestamp must be exact canonical UTC text")
    return timestamp


class AuditVerifier:
    def __init__(self, keys: Mapping[str, bytes]) -> None:
        valid_keys: dict[str, bytes] = {}
        invalid_key_ids: set[str] = set()
        for key_id, key in keys.items():
            if type(key_id) is not str:
                continue
            try:
                valid_keys[_validate_hmac_key_id(key_id)] = _validate_hmac_key(key)
            except ValueError:
                invalid_key_ids.add(key_id)
        self.keys: Mapping[str, bytes] = MappingProxyType(valid_keys)
        self._invalid_key_ids = frozenset(invalid_key_ids)

    def verify(self, connection: Connection) -> AuditVerification:
        previous: str | None = None
        count = 0
        for row in connection.execute(
            text(
                "SELECT ordinal, previous_public_hash_hex, public_hash_hex, hmac_key_id, "
                "hmac_b64, occurred_at, "
                "typeof(canonical_body_json) AS canonical_body_type, "
                "length(CAST(canonical_body_json AS BLOB)) AS canonical_body_byte_count, "
                "substr(CAST(canonical_body_json AS BLOB), 1, :body_prefix_limit) "
                "AS canonical_body_json_prefix "
                "FROM audit_receipts "
                "ORDER BY ordinal"
            ),
            {"body_prefix_limit": _CANONICAL_BODY_PREFIX_BYTES},
        ).mappings():
            count += 1
            try:
                ordinal = _storage_int(row["ordinal"])
                public_hash_hex = _validate_public_hash_hex(_storage_text(row["public_hash_hex"]))
                previous_public_hash = row["previous_public_hash_hex"]
                if previous_public_hash is not None:
                    previous_public_hash = _validate_public_hash_hex(
                        _storage_text(previous_public_hash)
                    )
            except (TypeError, ValueError):
                return AuditVerification(False, count - 1, previous, "invalid-receipt-row")
            if ordinal != count or previous_public_hash != previous:
                return AuditVerification(False, count - 1, previous, "ordinal-or-link-mismatch")
            try:
                key_id = _validate_hmac_key_id(_storage_text(row["hmac_key_id"]))
            except ValueError:
                return AuditVerification(False, count - 1, previous, "invalid-hmac-key")
            if key_id in self._invalid_key_ids:
                return AuditVerification(False, count - 1, previous, "invalid-hmac-key")
            key = self.keys.get(key_id)
            if key is None:
                return AuditVerification(False, count - 1, previous, "missing-hmac-key")
            try:
                hmac_b64 = _validate_hmac_b64(row["hmac_b64"])
            except ValueError:
                return AuditVerification(False, count - 1, previous, "invalid-hmac")
            try:
                body_size = _storage_int(row["canonical_body_byte_count"])
                canonical_body = row["canonical_body_json_prefix"]
            except (TypeError, ValueError):
                return AuditVerification(False, count - 1, previous, "invalid-canonical-body")
            if (
                row["canonical_body_type"] != "text"
                or type(canonical_body) is not bytes
                or not 1 <= body_size <= _MAX_CANONICAL_BODY_BYTES
            ):
                return AuditVerification(False, count - 1, previous, "invalid-canonical-body")
            if len(canonical_body) != body_size:
                return AuditVerification(False, count - 1, previous, "invalid-canonical-body")
            try:
                draft = parse_contract_json(
                    AuditDraft,
                    canonical_body,
                    max_bytes=_MAX_CANONICAL_BODY_BYTES,
                    require_canonical=True,
                )
            except (TypeError, UnicodeError, ValueError):
                return AuditVerification(False, count - 1, previous, "invalid-canonical-body")
            try:
                occurred_at = _storage_text(row["occurred_at"])
            except ValueError:
                return AuditVerification(False, count - 1, previous, "invalid-receipt-row")
            if occurred_at != _format_utc_text(draft.occurred_at):
                return AuditVerification(False, count - 1, previous, "occurred-at-mismatch")
            try:
                values = compute_chain_values(previous, draft, key_id, key)
            except (TypeError, ValueError):
                return AuditVerification(False, count - 1, previous, "invalid-receipt-row")
            if not hmac.compare_digest(
                values.public_hash_hex, public_hash_hex
            ) or not hmac.compare_digest(values.hmac_b64, hmac_b64):
                return AuditVerification(False, count - 1, previous, "hash-or-hmac-mismatch")
            previous = values.public_hash_hex

        for segment in connection.execute(
            text(
                "SELECT id, first_ordinal, last_ordinal, receipt_count, "
                "terminal_public_hash_hex, terminal_hmac_b64, hmac_key_id, sealed_at "
                "FROM audit_segments "
                "ORDER BY first_ordinal"
            ),
        ).mappings():
            try:
                _validate_uuid_text(segment["id"])
                _validate_utc_storage_text(segment["sealed_at"])
            except (KeyError, TypeError, ValueError):
                return AuditVerification(False, count, previous, "invalid-segment-row")
            try:
                first_ordinal = _storage_int(segment["first_ordinal"])
                last_ordinal = _storage_int(segment["last_ordinal"])
                receipt_count = _storage_int(segment["receipt_count"])
            except (TypeError, ValueError):
                return AuditVerification(False, count, previous, "invalid-segment-range")
            if (
                first_ordinal < 1
                or first_ordinal > last_ordinal
                or last_ordinal > MAX_AUDIT_ORDINAL
                or last_ordinal > count
                or receipt_count != last_ordinal - first_ordinal + 1
            ):
                return AuditVerification(False, count, previous, "invalid-segment-range")
            try:
                expected_ordinal = first_ordinal
                segment_receipt_count = 0
                for ordinal in connection.execute(
                    text(
                        "SELECT ordinal "
                        "FROM audit_receipts "
                        "WHERE ordinal BETWEEN :first AND :last "
                        "ORDER BY ordinal"
                    ),
                    {"first": first_ordinal, "last": last_ordinal},
                ).scalars():
                    if _storage_int(ordinal) != expected_ordinal:
                        return AuditVerification(False, count, previous, "invalid-segment-range")
                    expected_ordinal += 1
                    segment_receipt_count += 1
            except ValueError:
                return AuditVerification(False, count, previous, "invalid-segment-range")
            if segment_receipt_count != receipt_count:
                return AuditVerification(False, count, previous, "invalid-segment-range")
            try:
                segment_key_id = _validate_hmac_key_id(_storage_text(segment["hmac_key_id"]))
                segment_public_hash = _validate_public_hash_hex(
                    _storage_text(segment["terminal_public_hash_hex"])
                )
                segment_hmac = _validate_hmac_b64(segment["terminal_hmac_b64"])
            except ValueError as error:
                reason = (
                    "invalid-hmac-key" if "HMAC key ID" in str(error) else "invalid-segment-row"
                )
                return AuditVerification(False, count, previous, reason)
            if segment_key_id in self._invalid_key_ids:
                return AuditVerification(False, count, previous, "invalid-hmac-key")
            if segment_key_id not in self.keys:
                return AuditVerification(False, count, previous, "missing-hmac-key")
            terminal = (
                connection.execute(
                    text(
                        "SELECT public_hash_hex, hmac_b64, hmac_key_id "
                        "FROM audit_receipts "
                        "WHERE ordinal = :ordinal"
                    ),
                    {"ordinal": last_ordinal},
                )
                .mappings()
                .first()
            )
            if terminal is None:
                return AuditVerification(False, count, previous, "invalid-segment-range")
            try:
                terminal_public_hash = _validate_public_hash_hex(
                    _storage_text(terminal["public_hash_hex"])
                )
                terminal_hmac = _validate_hmac_b64(terminal["hmac_b64"])
                terminal_key_id = _validate_hmac_key_id(_storage_text(terminal["hmac_key_id"]))
            except ValueError:
                return AuditVerification(False, count, previous, "invalid-receipt-row")
            if (
                not hmac.compare_digest(terminal_public_hash, segment_public_hash)
                or not hmac.compare_digest(terminal_hmac, segment_hmac)
                or terminal_key_id != segment_key_id
            ):
                return AuditVerification(False, count, previous, "segment-terminal-mismatch")
        return AuditVerification(True, count, previous, "ok")
