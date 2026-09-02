from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import replace
from uuid import uuid4

import pytest
from tuntun_contracts.ports import TurnInput
from tuntun_core.adapters.reachy.completed_audio import (
    BoundedCompletedTurnAudio,
    CompletedAudioStream,
    PersistentTurnAudioClaims,
)

pytest_plugins = ("tests.fixtures.provider_routes",)


class _CompletedAudioSource:
    def __init__(self, stream: CompletedAudioStream) -> None:
        self.stream = stream
        self.expected_bytes = b"".join(
            chunk for chunk in getattr(stream.chunks, "_chunks", ()) if type(chunk) is bytes
        )
        self.opened: list[TurnInput] = []
        self.closed: list[CompletedAudioStream] = []
        self.open_streams = 0

    async def open_completed(self, turn: TurnInput) -> CompletedAudioStream:
        self.opened.append(turn)
        self.open_streams += 1
        return self.stream

    async def close_completed(self, stream: CompletedAudioStream) -> None:
        self.closed.append(stream)
        self.open_streams -= 1


class _Chunks:
    def __init__(self, chunks: tuple[object, ...]) -> None:
        self._chunks = chunks

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk  # type: ignore[misc]


class _BlockingChunks:
    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.cancelled = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        self.entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        yield b"unreachable"


def _turn() -> TurnInput:
    return TurnInput(turn_id=uuid4(), household_id=uuid4(), device_id=uuid4())


def _stream(turn: TurnInput, chunks: object, *, duration_ms: int = 40) -> CompletedAudioStream:
    return CompletedAudioStream(
        turn_id=turn.turn_id,
        household_id=turn.household_id,
        device_id=turn.device_id,
        duration_ms=duration_ms,
        chunks=chunks,  # type: ignore[arg-type]
    )


def _claims(route_uow_factory, route_clock) -> PersistentTurnAudioClaims:
    return PersistentTurnAudioClaims(route_uow_factory, route_clock)


@pytest.mark.asyncio
async def test_completed_audio_is_exact_bounded_and_consume_once(
    route_uow_factory,
    route_clock,
) -> None:
    turn = _turn()
    source = _CompletedAudioSource(_stream(turn, _Chunks((b"RIFF", b"audio"))))
    adapter = BoundedCompletedTurnAudio(source, _claims(route_uow_factory, route_clock))

    assert await adapter.consume_once(turn) == b"RIFFaudio"
    with pytest.raises(PermissionError, match="completed_turn_audio_already_consumed"):
        await adapter.consume_once(turn)

    assert source.opened == [turn, turn]
    assert source.closed == [source.stream, source.stream]
    assert source.open_streams == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stream_update",
    (
        {"device_id": uuid4()},
        {"duration_ms": 0},
        {"duration_ms": 90_001},
    ),
)
async def test_binding_or_duration_mismatch_denies_and_closes_without_claiming(
    stream_update: dict[str, object],
    route_uow_factory,
    route_clock,
) -> None:
    turn = _turn()
    valid = _stream(turn, _Chunks((b"RIFF",)))
    source = _CompletedAudioSource(replace(valid, **stream_update))
    adapter = BoundedCompletedTurnAudio(source, _claims(route_uow_factory, route_clock))

    with pytest.raises(PermissionError, match="completed_turn_audio_binding_or_duration_invalid"):
        await adapter.consume_once(turn)
    assert source.closed == [source.stream]

    source.stream = valid
    assert await adapter.consume_once(turn) == b"RIFF"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("chunks", "message"),
    (
        ((_Chunks((b"",)), "completed audio chunk outside bound")),
        ((_Chunks(("text",)), "completed audio chunk outside bound")),
        ((_Chunks((b"x" * 65_537,)), "completed audio chunk outside bound")),
        (
            (_Chunks(((b"x" * 65_536,) * 128) + (b"y",))),
            "completed audio turn outside bound",
        ),
    ),
)
async def test_chunk_and_total_bounds_are_checked_before_content_is_returned(
    chunks: object,
    message: str,
    route_uow_factory,
    route_clock,
) -> None:
    turn = _turn()
    source = _CompletedAudioSource(_stream(turn, chunks))
    adapter = BoundedCompletedTurnAudio(source, _claims(route_uow_factory, route_clock))

    with pytest.raises(ValueError, match=message):
        await adapter.consume_once(turn)
    assert source.open_streams == 0
    with pytest.raises(PermissionError, match="completed_turn_audio_already_consumed"):
        await adapter.consume_once(turn)


@pytest.mark.asyncio
async def test_cancellation_during_chunk_read_closes_stream_and_consumes_claim(
    route_uow_factory,
    route_clock,
) -> None:
    turn = _turn()
    chunks = _BlockingChunks()
    source = _CompletedAudioSource(_stream(turn, chunks))
    adapter = BoundedCompletedTurnAudio(source, _claims(route_uow_factory, route_clock))
    task = asyncio.create_task(adapter.consume_once(turn))
    await asyncio.wait_for(chunks.entered.wait(), timeout=15)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert chunks.cancelled is True
    assert source.closed == [source.stream]
    assert source.open_streams == 0
    with pytest.raises(PermissionError, match="completed_turn_audio_already_consumed"):
        await adapter.consume_once(turn)
