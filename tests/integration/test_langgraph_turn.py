from __future__ import annotations

import asyncio
from uuid import UUID, uuid4

import pytest
from tuntun_core.workflows.conversation import LinearConversationEngine, TurnOutcome, TurnRequest
from tuntun_core.workflows.langgraph_adapter import LangGraphConversationEngine
from tuntun_testing.scenario import guest_hinglish_scenario


@pytest.mark.asyncio
async def test_langgraph_executes_same_effects_as_linear_and_clears_all_state() -> None:
    linear_case = guest_hinglish_scenario(turn_index=1)
    graph_case = guest_hinglish_scenario(turn_index=1)
    linear = LinearConversationEngine(
        linear_case.ports,
        context_provider=linear_case.context_provider,
    )
    graph = LangGraphConversationEngine(
        graph_case.ports,
        context_provider=graph_case.context_provider,
    )
    linear_turn = uuid4()
    graph_turn = uuid4()

    linear_result = await linear.run(TurnRequest(linear_turn, linear_case.wav_bytes))
    graph_result = await graph.run(TurnRequest(graph_turn, graph_case.wav_bytes))

    assert linear_result == graph_result == TurnOutcome(spoken=True)
    assert graph_case.events == linear_case.events
    assert graph_case.events[-2:] == ["reachy.play", "turn.clear"]
    assert graph.ephemeral.contains(graph_turn) is False
    assert graph.ephemeral.count() == 0
    assert graph.lifecycle.count() == 0
    assert graph.checkpoint_count() == 0
    assert graph.cancellation_count() == 0


class _BlockingPorts:
    def __init__(self, *, block_finish: bool = False) -> None:
        self.transcribe_entered = asyncio.Event()
        self.release_transcribe = asyncio.Event()
        self.finish_entered = asyncio.Event()
        self.release_finish = asyncio.Event()
        self.block_finish = block_finish
        self.events: list[str] = []

    async def start(self, turn_id: UUID) -> None:
        del turn_id
        self.events.append("start")

    async def transcribe(self, wav_bytes: bytes) -> object:
        assert wav_bytes == b"private-audio"
        self.events.append("transcribe")
        self.transcribe_entered.set()
        await self.release_transcribe.wait()
        return type("Transcript", (), {"text": "private-transcript"})()

    async def generate(self, context: object) -> str:
        del context
        self.events.append("generate")
        return "private-answer"

    async def synthesize(self, answer: str) -> bytes:
        assert answer == "private-answer"
        self.events.append("synthesize")
        return b"private-pcm"

    async def play(self, turn_id: UUID, pcm: bytes) -> None:
        del turn_id, pcm
        self.events.append("play")

    async def finish(self, turn_id: UUID) -> None:
        del turn_id
        self.events.append("finish")
        self.finish_entered.set()
        if self.block_finish:
            await self.release_finish.wait()


class _ContextProvider:
    async def prepare(self, turn_id: UUID, transcript: object) -> object:
        del turn_id, transcript
        return object()


@pytest.mark.asyncio
async def test_external_cancellation_finishes_and_clears_graph_ephemeral_and_lifecycle() -> None:
    ports = _BlockingPorts()
    engine = LangGraphConversationEngine(ports, context_provider=_ContextProvider())
    turn_id = uuid4()
    running = asyncio.create_task(
        engine.run(TurnRequest(turn_id=turn_id, wav_bytes=b"private-audio"))
    )
    await ports.transcribe_entered.wait()

    checkpoint_bytes = repr(engine._checkpointer.storage).encode()  # noqa: SLF001
    assert b"private-audio" not in checkpoint_bytes
    assert b"private-transcript" not in checkpoint_bytes

    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running

    assert ports.events == ["start", "transcribe", "finish"]
    assert engine.ephemeral.contains(turn_id) is False
    assert engine.ephemeral.count() == 0
    assert engine.lifecycle.count() == 0
    assert engine.checkpoint_count() == 0
    assert engine.cancellation_count() == 0


@pytest.mark.asyncio
async def test_repeated_cancellation_cannot_abandon_finish_or_store_cleanup() -> None:
    ports = _BlockingPorts(block_finish=True)
    engine = LangGraphConversationEngine(ports, context_provider=_ContextProvider())
    turn_id = uuid4()
    running = asyncio.create_task(
        engine.run(TurnRequest(turn_id=turn_id, wav_bytes=b"private-audio"))
    )
    await ports.transcribe_entered.wait()

    running.cancel()
    await ports.finish_entered.wait()
    running.cancel()
    await asyncio.sleep(0)
    assert running.done() is False
    ports.release_finish.set()

    with pytest.raises(asyncio.CancelledError):
        await running
    assert ports.events == ["start", "transcribe", "finish"]
    assert engine.ephemeral.count() == 0
    assert engine.lifecycle.count() == 0
    assert engine.checkpoint_count() == 0
    assert engine.cancellation_count() == 0


@pytest.mark.asyncio
async def test_private_cancel_flag_blocks_late_content_effects_and_is_cleared() -> None:
    ports = _BlockingPorts()
    engine = LangGraphConversationEngine(ports, context_provider=_ContextProvider())
    turn_id = uuid4()
    running = asyncio.create_task(
        engine.run(TurnRequest(turn_id=turn_id, wav_bytes=b"private-audio"))
    )
    await ports.transcribe_entered.wait()

    await engine.cancel(turn_id)
    ports.release_transcribe.set()
    outcome = await running

    assert outcome == TurnOutcome(spoken=False)
    assert ports.events == ["start", "transcribe", "finish"]
    assert engine.ephemeral.count() == 0
    assert engine.lifecycle.count() == 0
    assert engine.checkpoint_count() == 0
    assert engine.cancellation_count() == 0


@pytest.mark.asyncio
async def test_closed_result_gate_still_runs_start_and_finish_but_no_content_node() -> None:
    case = guest_hinglish_scenario(turn_index=2)
    engine = LangGraphConversationEngine(
        case.ports,
        context_provider=case.context_provider,
        accepts_results=lambda _: False,
    )

    outcome = await engine.run(TurnRequest(uuid4(), case.wav_bytes))

    assert outcome == TurnOutcome(spoken=False)
    assert case.events == ["session.start", "turn.clear"]
    assert engine.ephemeral.count() == 0
    assert engine.lifecycle.count() == 0
    assert engine.checkpoint_count() == 0
    assert engine.cancellation_count() == 0
