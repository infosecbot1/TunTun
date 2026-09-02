from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from tuntun_contracts.ports import TurnInput
from tuntun_core.adapters.reachy.completed_audio import (
    BoundedCompletedTurnAudio,
    CompletedAudioStream,
    PersistentTurnAudioClaims,
)
from tuntun_core.workflows.conversation import LinearConversationEngine, TurnRequest

pytest_plugins = ("tests.fixtures.provider_routes",)


class _Source:
    def __init__(self, stream: CompletedAudioStream) -> None:
        self.stream = stream

    async def open_completed(self, turn: TurnInput) -> CompletedAudioStream:
        del turn
        return self.stream

    async def close_completed(self, stream: CompletedAudioStream) -> None:
        del stream


class _Chunks:
    def __init__(self, chunk: bytes) -> None:
        self.chunk = chunk

    async def __aiter__(self):
        yield self.chunk


class _SentinelPorts:
    def __init__(self, transcript: str, answer: str) -> None:
        self.transcript = transcript
        self.answer = answer

    async def start(self, turn_id: UUID) -> None:
        del turn_id

    async def transcribe(self, wav_bytes: bytes) -> str:
        del wav_bytes
        return self.transcript

    async def guest_identity(self) -> str:
        return "guest"

    async def generate(self, transcript: str, identity: str) -> str:
        assert transcript == self.transcript
        assert identity == "guest"
        return self.answer

    async def synthesize(self, answer: str) -> bytes:
        assert answer == self.answer
        return b"pcm"

    async def play(self, turn_id: UUID, pcm: bytes) -> None:
        del turn_id, pcm

    async def finish(self, turn_id: UUID) -> None:
        del turn_id


@pytest.mark.asyncio
async def test_linear_engine_drops_ephemeral_audio_transcript_and_answer_sentinels() -> None:
    turn_id = uuid4()
    transcript = "synthetic-private-transcript-sentinel"
    answer = "synthetic-private-answer-sentinel"
    engine = LinearConversationEngine(_SentinelPorts(transcript, answer))

    await engine.run(TurnRequest(turn_id=turn_id, wav_bytes=b"private-audio-sentinel"))

    retained = repr(engine.ephemeral) + repr(engine.cleanup_reason_codes)
    assert engine.ephemeral.contains(turn_id) is False
    assert "private-audio-sentinel" not in retained
    assert transcript not in retained
    assert answer not in retained


@pytest.mark.asyncio
async def test_completed_audio_claims_store_only_content_free_receipts(
    route_uow_factory,
    route_clock,
) -> None:
    sentinel = b"private-audio-db-sentinel"
    turn = TurnInput(turn_id=uuid4(), household_id=uuid4(), device_id=uuid4())
    source = _Source(
        CompletedAudioStream(
            turn_id=turn.turn_id,
            household_id=turn.household_id,
            device_id=turn.device_id,
            duration_ms=10,
            chunks=_Chunks(sentinel),
        )
    )
    adapter = BoundedCompletedTurnAudio(
        source,
        PersistentTurnAudioClaims(route_uow_factory, route_clock),
    )

    audio = await adapter.consume_once(turn)
    assert audio == sentinel
    del audio

    async with route_uow_factory() as uow:
        rows = await uow.run_sync(
            lambda transaction: tuple(
                "|".join(str(column) for column in row)
                for row in transaction.exec_driver_sql(
                    "SELECT operation,scope,idempotency_key,state FROM idempotency_receipts"
                ).tuples()
            )
        )
        await uow.rollback()
    serialized = repr(rows).encode("utf-8")
    assert sentinel not in serialized
    assert b"synthetic-private-transcript-sentinel" not in serialized
