from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from tuntun_core.workflows.conversation import LinearConversationEngine, TurnRequest
from tuntun_testing.scenario import guest_hinglish_scenario


@pytest.mark.asyncio
async def test_guest_turn_orders_effects_and_clears_content() -> None:
    scenario = guest_hinglish_scenario()
    workflow = LinearConversationEngine(scenario.ports)
    turn_id = uuid4()

    outcome = await workflow.run(TurnRequest(turn_id=turn_id, wav_bytes=scenario.wav_bytes))

    assert outcome.spoken is True
    assert scenario.events == [
        "session.start",
        "stt.reserve",
        "stt.authorize",
        "stt.call",
        "identity.guest",
        "reasoning.sanitize",
        "reasoning.reserve",
        "reasoning.authorize",
        "reasoning.call",
        "tts.dlp",
        "tts.reserve",
        "tts.authorize",
        "tts.call",
        "reachy.play",
        "turn.clear",
    ]
    assert workflow.ephemeral.contains(turn_id) is False


@pytest.mark.asyncio
async def test_late_result_gate_prevents_playback_and_clears_content() -> None:
    scenario = guest_hinglish_scenario()
    turn_id = uuid4()
    accepts_results = True

    class RevokingPorts:
        async def start(self, turn_id: UUID) -> None:
            await scenario.ports.start(turn_id)

        async def transcribe(self, wav_bytes: bytes) -> object:
            return await scenario.ports.transcribe(wav_bytes)

        async def guest_identity(self) -> str:
            return await scenario.ports.guest_identity()

        async def generate(self, transcript: object, identity: str) -> str:
            return await scenario.ports.generate(transcript, identity)

        async def synthesize(self, answer: str) -> bytes:
            nonlocal accepts_results
            pcm = await scenario.ports.synthesize(answer)
            accepts_results = False
            return pcm

        async def play(self, turn_id: UUID, pcm: bytes) -> None:
            await scenario.ports.play(turn_id, pcm)

        async def finish(self, turn_id: UUID) -> None:
            await scenario.ports.finish(turn_id)

    workflow = LinearConversationEngine(
        RevokingPorts(),
        accepts_results=lambda active_turn_id: accepts_results and active_turn_id == turn_id,
    )

    outcome = await workflow.run(TurnRequest(turn_id=turn_id, wav_bytes=scenario.wav_bytes))

    assert outcome.spoken is False
    assert "reachy.play" not in scenario.events
    assert scenario.events[-1] == "turn.clear"
    assert workflow.ephemeral.contains(turn_id) is False
