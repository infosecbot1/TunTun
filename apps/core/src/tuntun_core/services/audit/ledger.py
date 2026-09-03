from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import text
from tuntun_contracts.audit import AuditDraft, AuditReceipt
from tuntun_contracts.base import canonical_bytes
from tuntun_contracts.ports import AuditPort, ClockPort
from tuntun_core.services.transactions.protocols import (
    AsyncUnitOfWorkProtocol,
    UnitOfWorkProtocol,
)

PURPOSE = b"tuntun:audit:v1\x00"
MAX_AUDIT_ORDINAL = 9_000_000_000_000_000
_KEY_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-")
_LOWER_HEX_CHARS = frozenset("0123456789abcdef")


@dataclass(frozen=True, slots=True)
class ChainValues:
    public_hash_hex: str
    hmac_b64: str
    canonical_body_json: str


@dataclass(frozen=True, slots=True)
class AuditSegment:
    segment_id: str
    first_ordinal: int
    last_ordinal: int
    receipt_count: int
    terminal_public_hash_hex: str
    terminal_hmac_b64: str
    hmac_key_id: str
    sealed_at: datetime


def _validate_hmac_key_id(key_id: str) -> str:
    if (
        type(key_id) is not str
        or not 8 <= len(key_id) <= 128
        or any(character not in _KEY_ID_CHARS for character in key_id)
    ):
        raise ValueError("audit HMAC key ID is required")
    return key_id


def _validate_hmac_key(key: bytes) -> bytes:
    if type(key) is not bytes or len(key) < 32:
        raise ValueError("audit HMAC key must be at least 32 bytes")
    return key


def _validate_public_hash_hex(value: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in _LOWER_HEX_CHARS for character in value)
    ):
        raise ValueError("audit public hash must be lowercase SHA-256 hex")
    return value


def _validate_hmac_b64(value: object) -> str:
    if type(value) is not str:
        raise ValueError("audit HMAC must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("audit HMAC must be canonical base64") from error
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("audit HMAC must encode exactly 32 bytes")
    return value


def _require_hmac_material(key_id: str, key: bytes) -> None:
    _validate_hmac_key_id(key_id)
    _validate_hmac_key(key)


def _storage_int(value: object) -> int:
    if type(value) is not int:
        raise ValueError("audit integer storage value is invalid")
    return value


def _storage_text(value: object) -> str:
    if type(value) is not str:
        raise ValueError("audit text storage value is invalid")
    return value


def _format_utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("audit timestamps must be timezone-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def compute_chain_values(
    previous_public_hash_hex: str | None,
    draft: AuditDraft,
    key_id: str,
    key: bytes,
) -> ChainValues:
    _require_hmac_material(key_id, key)
    body = canonical_bytes(draft)
    previous = (
        bytes.fromhex(_validate_public_hash_hex(previous_public_hash_hex))
        if previous_public_hash_hex is not None
        else b""
    )
    public_hash = hashlib.sha256(previous + body).digest()
    mac = hmac.new(key, PURPOSE + public_hash + body, hashlib.sha256).digest()
    return ChainValues(
        public_hash.hex(),
        base64.b64encode(mac).decode("ascii"),
        body.decode("utf-8"),
    )


class AuditLedger:
    def __init__(self, key_id: str, key: bytes, clock: ClockPort) -> None:
        _require_hmac_material(key_id, key)
        self.key_id = key_id
        self.key = key
        self.clock = clock

    def append(self, uow: UnitOfWorkProtocol, draft: AuditDraft) -> AuditReceipt:
        row = (
            uow.execute(
                text(
                    "SELECT ordinal, public_hash_hex "
                    "FROM audit_receipts "
                    "ORDER BY ordinal DESC "
                    "LIMIT 1"
                ),
            )
            .mappings()
            .first()
        )
        if row is None:
            ordinal = 1
            previous = None
        else:
            previous_ordinal = _storage_int(row["ordinal"])
            if not 1 <= previous_ordinal < MAX_AUDIT_ORDINAL:
                raise ValueError("audit ordinal storage value is invalid")
            ordinal = previous_ordinal + 1
            previous = _validate_public_hash_hex(_storage_text(row["public_hash_hex"]))
        values = compute_chain_values(previous, draft, self.key_id, self.key)
        receipt_id = uuid4()
        uow.execute(
            text(
                "INSERT INTO audit_receipts"
                "(id, ordinal, previous_public_hash_hex, public_hash_hex, hmac_key_id, "
                "hmac_b64, canonical_body_json, occurred_at) "
                "VALUES(:id, :ordinal, :previous, :public, :key_id, :mac, :body, :occurred)"
            ),
            {
                "id": str(receipt_id),
                "ordinal": ordinal,
                "previous": previous,
                "public": values.public_hash_hex,
                "key_id": self.key_id,
                "mac": values.hmac_b64,
                "body": values.canonical_body_json,
                "occurred": _format_utc_text(draft.occurred_at),
            },
        )
        return AuditReceipt(
            receipt_id=receipt_id,
            ordinal=ordinal,
            public_hash_hex=values.public_hash_hex,
            hmac_key_id=self.key_id,
            hmac_b64=values.hmac_b64,
            occurred_at=draft.occurred_at,
        )

    def seal(
        self,
        uow: UnitOfWorkProtocol,
        first_ordinal: int,
        last_ordinal: int,
    ) -> AuditSegment:
        if (
            type(first_ordinal) is not int
            or type(last_ordinal) is not int
            or first_ordinal < 1
            or first_ordinal > last_ordinal
            or last_ordinal > MAX_AUDIT_ORDINAL
        ):
            raise ValueError("segment range is not contiguous")
        expected_count = last_ordinal - first_ordinal + 1
        expected_ordinal = first_ordinal
        receipt_count = 0
        terminal = None
        try:
            for row in (
                uow.execute(
                    text(
                        "SELECT ordinal, public_hash_hex, hmac_b64, hmac_key_id "
                        "FROM audit_receipts "
                        "WHERE ordinal BETWEEN :first AND :last "
                        "ORDER BY ordinal"
                    ),
                    {"first": first_ordinal, "last": last_ordinal},
                )
                .mappings()
            ):
                if _storage_int(row["ordinal"]) != expected_ordinal:
                    raise ValueError("segment range is not contiguous")
                terminal = row
                receipt_count += 1
                expected_ordinal += 1
        except ValueError as error:
            raise ValueError("segment range is not contiguous") from error
        if terminal is None or receipt_count != expected_count:
            raise ValueError("segment range is not contiguous")
        terminal_public_hash = _validate_public_hash_hex(_storage_text(terminal["public_hash_hex"]))
        terminal_hmac = _validate_hmac_b64(terminal["hmac_b64"])
        terminal_key_id = _validate_hmac_key_id(_storage_text(terminal["hmac_key_id"]))
        segment_id = str(uuid4())
        sealed_at = self.clock.now()
        if sealed_at.tzinfo is None or sealed_at.utcoffset() is None:
            raise ValueError("audit seal clock must be timezone-aware")
        sealed_at = sealed_at.astimezone(UTC)
        uow.execute(
            text(
                "INSERT INTO audit_segments"
                "(id, first_ordinal, last_ordinal, receipt_count, terminal_public_hash_hex, "
                "terminal_hmac_b64, hmac_key_id, sealed_at, exported_at) "
                "VALUES(:id, :first, :last, :count, :public, :mac, :key_id, :sealed, NULL)"
            ),
            {
                "id": segment_id,
                "first": first_ordinal,
                "last": last_ordinal,
                "count": receipt_count,
                "public": terminal_public_hash,
                "mac": terminal_hmac,
                "key_id": terminal_key_id,
                "sealed": sealed_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            },
        )
        return AuditSegment(
            segment_id,
            first_ordinal,
            last_ordinal,
            receipt_count,
            terminal_public_hash,
            terminal_hmac,
            terminal_key_id,
            sealed_at,
        )


class AsyncAuditLedger:
    def __init__(self, ledger: AuditLedger) -> None:
        self._ledger = ledger

    async def append(
        self,
        uow: AsyncUnitOfWorkProtocol,
        draft: AuditDraft,
    ) -> AuditReceipt:
        return await uow.run_sync(lambda transaction: self._ledger.append(transaction, draft))

    async def seal(
        self,
        uow: AsyncUnitOfWorkProtocol,
        first_ordinal: int,
        last_ordinal: int,
    ) -> AuditSegment:
        return await uow.run_sync(
            lambda transaction: self._ledger.seal(transaction, first_ordinal, last_ordinal)
        )


def _bind_audit_port(
    ledger: AsyncAuditLedger,
) -> AuditPort[AsyncUnitOfWorkProtocol]:
    return ledger
