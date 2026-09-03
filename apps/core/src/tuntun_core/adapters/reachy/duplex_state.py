from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from datetime import datetime
from typing import Literal, Protocol, TypeVar
from uuid import UUID

from sqlalchemy.exc import IntegrityError
from tuntun_contracts.base import JCS_MAX_SAFE_INTEGER
from tuntun_contracts.reachy_wire import Direction, FrameKind, FramePurpose
from tuntun_core.services.storage_time import utc_storage
from tuntun_core.services.transactions.protocols import AsyncUnitOfWorkProtocol, UnitOfWorkProtocol

_PURPOSES: frozenset[str] = frozenset(
    (
        "reachy.command.v1",
        "reachy.health.v1",
        "reachy.stop_all.v1",
        "reachy.camera_grant.v1",
        "reachy.event.v1",
        "reachy.media_control.v1",
    )
)
_KINDS: frozenset[str] = frozenset(("request", "response", "event"))
_PENDING_CORRELATION_LIMIT: int = 256
_TERMINAL_CORRELATION_RETENTION_LIMIT: int = 4_096

_ResultT = TypeVar("_ResultT")


class UnitOfWorkFactory(Protocol):
    def __call__(self) -> AbstractAsyncContextManager[AsyncUnitOfWorkProtocol]: ...


class Clock(Protocol):
    def now(self) -> datetime: ...


class CoreDuplexState:
    """Durable core-side control sequence and correlation state.

    Core-to-edge transmit sequence lives in reachy_core_tx_sequences. Edge-to-core
    receive sequence remains the authoritative devices.last_sequence value.
    """

    def __init__(self, uow_factory: UnitOfWorkFactory, device_id: UUID, clock: Clock) -> None:
        if type(device_id) is not UUID:
            raise TypeError("device_id must be an exact UUID")
        self._uow_factory = uow_factory
        self._device_id = str(device_id)
        self._clock = clock

    async def reserve_outbound(
        self,
        correlation_id: UUID,
        purpose: FramePurpose,
        kind: FrameKind,
    ) -> int:
        _require_exact_uuid(correlation_id, "correlation_id")
        _require_purpose(purpose)
        _require_kind(kind)
        now = utc_storage(self._clock.now())

        def reserve(transaction: UnitOfWorkProtocol) -> int:
            _require_current_device(transaction, self._device_id)
            row = transaction.exec_driver_sql(
                "SELECT last_sequence FROM reachy_core_tx_sequences WHERE device_id=?",
                (self._device_id,),
            ).fetchone()
            previous = 0 if row is None else _bounded_sequence(row[0])
            sequence = previous + 1
            _require_sequence_bounds(sequence)
            if row is None:
                changed = transaction.exec_driver_sql(
                    "INSERT INTO reachy_core_tx_sequences(device_id,last_sequence) VALUES(?,?)",
                    (self._device_id, sequence),
                ).rowcount
            else:
                changed = transaction.exec_driver_sql(
                    "UPDATE reachy_core_tx_sequences SET last_sequence=? "
                    "WHERE device_id=? AND last_sequence=?",
                    (sequence, self._device_id, previous),
                ).rowcount
            if changed != 1:
                raise PermissionError("sequence_allocation_conflict")
            self._advance_correlation(
                transaction,
                correlation_id,
                purpose,
                kind,
                "core_to_edge",
                sequence,
                now,
            )
            return sequence

        return await self._commit_sync(reserve)

    async def accept_inbound(
        self,
        sequence: int,
        correlation_id: UUID,
        purpose: FramePurpose,
        kind: FrameKind,
    ) -> None:
        _require_sequence(sequence)
        _require_exact_uuid(correlation_id, "correlation_id")
        _require_purpose(purpose)
        _require_kind(kind)
        now = utc_storage(self._clock.now())

        def accept(transaction: UnitOfWorkProtocol) -> None:
            previous = _device_last_sequence(transaction, self._device_id)
            if sequence <= previous:
                raise PermissionError("replayed_sequence_or_correlation")
            if sequence != previous + 1:
                raise PermissionError("sequence_gap")
            changed = transaction.exec_driver_sql(
                "UPDATE devices SET last_sequence=? "
                "WHERE id=? AND revoked_at IS NULL AND last_sequence=?",
                (sequence, self._device_id, previous),
            ).rowcount
            if changed != 1:
                raise PermissionError("replayed_sequence_or_correlation")
            self._advance_correlation(
                transaction,
                correlation_id,
                purpose,
                kind,
                "edge_to_core",
                sequence,
                now,
            )

        await self._commit_sync(accept)

    async def accept_response(
        self,
        correlation_id: UUID,
        purpose: FramePurpose,
        payload: bytes,
    ) -> None:
        _require_exact_uuid(correlation_id, "correlation_id")
        _require_purpose(purpose)
        _require_payload_bytes(payload)

        def accept(transaction: UnitOfWorkProtocol) -> None:
            row = transaction.exec_driver_sql(
                "SELECT 1 FROM reachy_duplex_correlations "
                "WHERE device_id=? AND correlation_id=? AND purpose=? "
                "AND request_direction='core_to_edge' AND state='pending'",
                (self._device_id, str(correlation_id), purpose),
            ).fetchone()
            if row is None:
                raise PermissionError("correlation_not_pending")

        await self._commit_sync(accept)

    async def complete(self, correlation_id: UUID) -> None:
        await self._terminal(correlation_id, "completed")

    async def abandon_correlation(self, correlation_id: UUID, reason: str) -> None:
        _require_reason(reason)
        await self._terminal(correlation_id, "abandoned")

    async def abandon_connection(self, reason: str) -> None:
        _require_reason(reason)
        now = utc_storage(self._clock.now())

        def abandon(transaction: UnitOfWorkProtocol) -> None:
            transaction.exec_driver_sql(
                "UPDATE reachy_duplex_correlations SET state='abandoned',updated_at=? "
                "WHERE device_id=? AND state='pending'",
                (now, self._device_id),
            )

        await self._commit_sync(abandon)

    async def pending_for_replay(self) -> tuple[()]:
        return ()

    async def _terminal(
        self,
        correlation_id: UUID,
        state: Literal["completed", "abandoned"],
    ) -> None:
        _require_exact_uuid(correlation_id, "correlation_id")
        now = utc_storage(self._clock.now())

        def finish(transaction: UnitOfWorkProtocol) -> None:
            changed = transaction.exec_driver_sql(
                "UPDATE reachy_duplex_correlations SET state=?,updated_at=? "
                "WHERE device_id=? AND correlation_id=? AND state='pending'",
                (state, now, self._device_id, str(correlation_id)),
            ).rowcount
            if changed != 1:
                raise PermissionError("correlation_not_pending")

        await self._commit_sync(finish)

    def _advance_correlation(
        self,
        transaction: UnitOfWorkProtocol,
        correlation_id: UUID,
        purpose: FramePurpose,
        kind: FrameKind,
        direction: Direction,
        sequence: int,
        now: str,
    ) -> None:
        key = (self._device_id, str(correlation_id))
        row = transaction.exec_driver_sql(
            "SELECT purpose,request_direction,state FROM reachy_duplex_correlations "
            "WHERE device_id=? AND correlation_id=?",
            key,
        ).fetchone()
        if kind in {"request", "event"}:
            if row is not None:
                raise PermissionError("replayed_sequence_or_correlation")
            pending = transaction.exec_driver_sql(
                "SELECT COUNT(*) FROM reachy_duplex_correlations "
                "WHERE device_id=? AND state='pending'",
                (self._device_id,),
            ).fetchone()
            if pending is None or type(pending[0]) is not int:
                raise PermissionError("reachy_duplex_store_corrupt")
            if pending[0] >= _PENDING_CORRELATION_LIMIT:
                raise PermissionError("pending_correlation_limit")
            changed = transaction.exec_driver_sql(
                "INSERT INTO reachy_duplex_correlations("
                "device_id,correlation_id,purpose,request_direction,state,"
                "first_sequence,last_sequence,created_at,updated_at"
                ") VALUES(?,?,?,?,?,?,?,?,?)",
                (*key, purpose, direction, "pending", sequence, sequence, now, now),
            ).rowcount
            if changed != 1:
                raise PermissionError("replayed_sequence_or_correlation")
            return
        if kind != "response":
            raise ValueError("unsupported control frame kind")
        opposite = _opposite_direction(direction)
        if row is None or tuple(row) != (purpose, opposite, "pending"):
            raise PermissionError("correlation_not_pending")
        changed = transaction.exec_driver_sql(
            "UPDATE reachy_duplex_correlations SET last_sequence=?,updated_at=? "
            "WHERE device_id=? AND correlation_id=? AND state='pending'",
            (sequence, now, *key),
        ).rowcount
        if changed != 1:
            raise PermissionError("correlation_not_pending")

    async def _commit_sync(
        self,
        operation: Callable[[UnitOfWorkProtocol], _ResultT],
    ) -> _ResultT:
        try:
            async with self._uow_factory() as uow:
                value = await uow.run_sync(operation)
                await uow.run_sync(self._prune_terminal_correlations)
                await uow.commit()
                return value
        except IntegrityError as error:
            raise PermissionError("replayed_sequence_or_correlation") from error

    def _prune_terminal_correlations(self, transaction: UnitOfWorkProtocol) -> None:
        transaction.exec_driver_sql(
            "DELETE FROM reachy_duplex_correlations "
            "WHERE rowid IN ("
            "SELECT rowid FROM reachy_duplex_correlations "
            "WHERE device_id=? AND state IN ('completed','abandoned') "
            "ORDER BY updated_at DESC,last_sequence DESC,correlation_id DESC "
            "LIMIT -1 OFFSET ?"
            ")",
            (self._device_id, _TERMINAL_CORRELATION_RETENTION_LIMIT),
        )


def _require_current_device(transaction: UnitOfWorkProtocol, device_id: str) -> None:
    row = transaction.exec_driver_sql(
        "SELECT 1 FROM devices WHERE id=? AND kind='reachy' AND revoked_at IS NULL",
        (device_id,),
    ).fetchone()
    if row is None:
        raise PermissionError("reachy_device_not_current")


def _device_last_sequence(transaction: UnitOfWorkProtocol, device_id: str) -> int:
    row = transaction.exec_driver_sql(
        "SELECT last_sequence FROM devices WHERE id=? AND kind='reachy' AND revoked_at IS NULL",
        (device_id,),
    ).fetchone()
    if row is None:
        raise PermissionError("reachy_device_not_current")
    return _bounded_sequence(row[0])


def _bounded_sequence(value: object) -> int:
    if type(value) is not int:
        raise ValueError("stored sequence must be an integer")
    _require_sequence_bounds(value)
    return value


def _require_sequence(value: int) -> None:
    if type(value) is not int:
        raise TypeError("sequence must be an exact integer")
    _require_sequence_bounds(value)
    if value < 1:
        raise ValueError("sequence must be positive")


def _require_sequence_bounds(value: int) -> None:
    if not 0 <= value <= JCS_MAX_SAFE_INTEGER:
        raise ValueError("sequence outside JCS safe integer domain")


def _require_exact_uuid(value: UUID, label: str) -> None:
    if type(value) is not UUID:
        raise TypeError(f"{label} must be an exact UUID")


def _require_purpose(value: str) -> None:
    if type(value) is not str or value not in _PURPOSES:
        raise ValueError("unsupported control frame purpose")


def _require_kind(value: str) -> None:
    if type(value) is not str or value not in _KINDS:
        raise ValueError("unsupported control frame kind")


def _require_reason(value: str) -> None:
    if type(value) is not str or not 1 <= len(value.encode("utf-8")) <= 128:
        raise ValueError("duplex terminal reason invalid")


def _require_payload_bytes(value: bytes) -> None:
    if type(value) is not bytes:
        raise TypeError("control response payload must be bytes")


def _opposite_direction(direction: Direction) -> Direction:
    if direction == "edge_to_core":
        return "core_to_edge"
    if direction == "core_to_edge":
        return "edge_to_core"
    raise ValueError("unsupported control frame direction")


__all__ = ("CoreDuplexState",)
