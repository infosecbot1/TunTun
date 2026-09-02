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


class _StageGatePorts:
    def __init__(self, *, initially_accepting: bool, revoke_after: str | None) -> None:
        self.accepting = initially_accepting
        self.revoke_after = revoke_after
        self.events: list[str] = []

    def _record(self, stage: str) -> None:
        self.events.append(stage)
        if self.revoke_after == stage:
            self.accepting = False

    async def start(self, turn_id: UUID) -> None:
        del turn_id
        self._record("start")

    async def transcribe(self, wav_bytes: bytes) -> str:
        assert wav_bytes == b"synthetic-wav"
        self._record("transcribe")
        return "private transcript"

    async def guest_identity(self) -> str:
        self._record("identity")
        return "Guest"

    async def generate(self, transcript: str, identity: str) -> str:
        assert (transcript, identity) == ("private transcript", "Guest")
        self._record("generate")
        return "private answer"

    async def synthesize(self, answer: str) -> bytes:
        assert answer == "private answer"
        self._record("synthesize")
        return b"pcm"

    async def play(self, turn_id: UUID, pcm: bytes) -> None:
        del turn_id
        assert pcm == b"pcm"
        self._record("play")

    async def finish(self, turn_id: UUID) -> None:
        del turn_id
        self._record("finish")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("initially_accepting", "revoke_after", "expected_events"),
    (
        (False, None, ["start", "finish"]),
        (True, "transcribe", ["start", "transcribe", "finish"]),
        (True, "identity", ["start", "transcribe", "identity", "finish"]),
        (True, "generate", ["start", "transcribe", "identity", "generate", "finish"]),
        (
            True,
            "synthesize",
            ["start", "transcribe", "identity", "generate", "synthesize", "finish"],
        ),
    ),
)
async def test_acceptance_gate_runs_before_each_downstream_content_stage(
    initially_accepting: bool,
    revoke_after: str | None,
    expected_events: list[str],
) -> None:
    turn_id = uuid4()
    ports = _StageGatePorts(
        initially_accepting=initially_accepting,
        revoke_after=revoke_after,
    )
    workflow = LinearConversationEngine(
        ports,
        accepts_results=lambda active_turn_id: (
            active_turn_id == turn_id and ports.accepting
        ),
    )

    outcome = await workflow.run(TurnRequest(turn_id=turn_id, wav_bytes=b"synthetic-wav"))

    assert outcome.spoken is False
    assert ports.events == expected_events
    assert workflow.ephemeral.contains(turn_id) is False
