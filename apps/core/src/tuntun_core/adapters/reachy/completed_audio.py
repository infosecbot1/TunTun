from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import timedelta
from typing import Protocol
from uuid import UUID, uuid4

from tuntun_contracts.ports import TurnInput
from tuntun_core.services.storage_time import utc_storage
from tuntun_core.services.transactions.protocols import AsyncUnitOfWorkProtocol, UnitOfWorkProtocol

_CLAIM_OPERATION = "reachy.completed_audio.consume"
_CLAIM_TTL = timedelta(days=7)
_MAX_CHUNK_BYTES = 65_536
_MAX_TURN_BYTES = 8_388_608
_MIN_DURATION_MS = 1
_MAX_DURATION_MS = 90_000


class ClockPort(Protocol):
    def now(self) -> object: ...


class UnitOfWorkFactory(Protocol):
    def __call__(self) -> AbstractAsyncContextManager[AsyncUnitOfWorkProtocol]: ...


@dataclass(frozen=True, slots=True)
class CompletedAudioStream:
    turn_id: UUID
    household_id: UUID
    device_id: UUID
    duration_ms: int
    chunks: AsyncIterator[bytes]

    def __post_init__(self) -> None:
        if type(self.turn_id) is not UUID:
            raise TypeError("turn_id must be an exact UUID")
        if type(self.household_id) is not UUID:
            raise TypeError("household_id must be an exact UUID")
        if type(self.device_id) is not UUID:
            raise TypeError("device_id must be an exact UUID")
        if type(self.duration_ms) is not int:
            raise TypeError("duration_ms must be an exact int")


class CompletedAudioSource(Protocol):
    async def open_completed(self, turn: TurnInput) -> CompletedAudioStream: ...

    async def close_completed(self, stream: CompletedAudioStream) -> None: ...


class PersistentTurnAudioClaims:
    def __init__(self, uow_factory: UnitOfWorkFactory, clock: ClockPort) -> None:
        self._uow_factory = uow_factory
        self._clock = clock

    async def claim_once(self, turn: TurnInput) -> None:
        if type(turn) is not TurnInput:
            raise TypeError("turn must be an exact TurnInput")
        observed = self._clock.now()
        if not hasattr(observed, "tzinfo"):
            raise TypeError("clock returned invalid time")
        now = utc_storage(observed)  # type: ignore[arg-type]
        expires_at = utc_storage(observed + _CLAIM_TTL)  # type: ignore[operator,arg-type]

        def persist(transaction: UnitOfWorkProtocol) -> int:
            rowcount = transaction.exec_driver_sql(
                "INSERT INTO idempotency_receipts("
                "id,operation,scope,idempotency_key,state,"
                "first_seen_at,last_seen_at,expires_at"
                ") VALUES(?,?,?,?,?,?,?,?) "
                "ON CONFLICT(operation,scope,idempotency_key) DO NOTHING",
                (
                    str(uuid4()),
                    _CLAIM_OPERATION,
                    str(turn.household_id),
                    str(turn.turn_id),
                    "claimed",
                    now,
                    now,
                    expires_at,
                ),
            ).rowcount
            if type(rowcount) is not int:
                raise RuntimeError("completed audio claim rowcount unavailable")
            return rowcount

        async with self._uow_factory() as uow:
            inserted = await uow.run_sync(persist)
            if inserted != 1:
                raise PermissionError("completed_turn_audio_already_consumed")
            await uow.commit()


class BoundedCompletedTurnAudio:
    """RAM-only consume-once bridge for completed Reachy turn audio."""

    def __init__(self, source: CompletedAudioSource, claims: PersistentTurnAudioClaims) -> None:
        self._source = source
        self._claims = claims

    async def consume_once(self, turn: TurnInput) -> bytes:
        if type(turn) is not TurnInput:
            raise TypeError("turn must be an exact TurnInput")
        stream = await self._source.open_completed(turn)
        buffer = bytearray()
        primary_error: BaseException | None = None
        try:
            self._require_stream_binding(turn, stream)
            await self._claims.claim_once(turn)
            async for chunk in stream.chunks:
                if type(chunk) is not bytes or not chunk or len(chunk) > _MAX_CHUNK_BYTES:
                    raise ValueError("completed audio chunk outside bound")
                if len(chunk) > _MAX_TURN_BYTES - len(buffer):
                    raise ValueError("completed audio turn outside bound")
                buffer.extend(chunk)
            if not buffer:
                raise ValueError("completed audio is empty")
            return bytes(buffer)
        except BaseException as error:
            primary_error = error
            raise
        finally:
            try:
                await self._source.close_completed(stream)
            except BaseException as close_error:
                if primary_error is None:
                    raise
                primary_error.add_note(
                    f"additional completed audio cleanup failure: {type(close_error).__name__}"
                )
            buffer[:] = b"\x00" * len(buffer)
            buffer.clear()

    @staticmethod
    def _require_stream_binding(turn: TurnInput, stream: CompletedAudioStream) -> None:
        if type(stream) is not CompletedAudioStream:
            raise PermissionError("completed_turn_audio_binding_or_duration_invalid")
        if (
            stream.turn_id != turn.turn_id
            or stream.household_id != turn.household_id
            or stream.device_id != turn.device_id
            or not _MIN_DURATION_MS <= stream.duration_ms <= _MAX_DURATION_MS
        ):
            raise PermissionError("completed_turn_audio_binding_or_duration_invalid")
