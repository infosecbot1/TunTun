from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from tuntun_core.services.personalized_turn_context import TranscribedTurn
from tuntun_core.workflows import langgraph_adapter
from tuntun_core.workflows.contract_workflow import ContractConversationWorkflow
from tuntun_core.workflows.conversation import TurnRequest
from tuntun_core.workflows.ephemeral_turn_context import EphemeralTurnContext
from tuntun_core.workflows.langgraph_adapter import (
    NODE_ORDER,
    LangGraphConversationEngine,
    build_graph,
)
from tuntun_core.workflows.state import GraphState
from tuntun_core.workflows.turn_lifecycle import TurnLifecycleRegistry
from tuntun_testing.scenario import guest_hinglish_scenario


class _FailingPorts:
    def __init__(
        self,
        fail_at: str,
        *,
        error_type: type[Exception] = RuntimeError,
        fail_finish: bool = False,
    ) -> None:
        self.fail_at = fail_at
        self.error_type = error_type
        self.fail_finish = fail_finish
        self.events: list[str] = []

    def _record(self, name: str) -> None:
        self.events.append(name)
        if name == self.fail_at:
            raise self.error_type("private-content-must-not-survive")

    async def start(self, turn_id: UUID) -> None:
        del turn_id
        self._record("start")

    async def transcribe(self, wav_bytes: bytes) -> TranscribedTurn:
        del wav_bytes
        self._record("transcribe")
        return TranscribedTurn(text="private-transcript", stt_language="en")

    async def generate(self, context: object) -> str:
        del context
        self._record("generate")
        return "private-answer"

    async def synthesize(self, answer: str) -> bytes:
        del answer
        self._record("synthesize")
        return b"private-pcm"

    async def play(self, turn_id: UUID, pcm: bytes) -> None:
        del turn_id, pcm
        self._record("play")

    async def finish(self, turn_id: UUID) -> None:
        del turn_id
        self.events.append("finish")
        if self.fail_finish:
            raise RuntimeError("private-finish-detail")


class _ContextProvider:
    async def prepare(self, turn_id: UUID, transcript: object) -> object:
        del turn_id, transcript
        return object()


class _RecordingSaver(InMemorySaver):
    def __init__(self) -> None:
        super().__init__()
        self.serialized_checkpoints: list[bytes] = []
        self.serialized_writes: list[bytes] = []
        self.phases: list[str] = []

    def put(
        self,
        config: Any,
        checkpoint: Any,
        metadata: Any,
        new_versions: Any,
    ) -> Any:
        kind, payload = self.serde.dumps_typed(checkpoint)
        self.serialized_checkpoints.append(kind.encode("ascii") + b":" + payload)
        phase = checkpoint.get("channel_values", {}).get("phase")
        if type(phase) is str:
            self.phases.append(phase)
        return super().put(config, checkpoint, metadata, new_versions)

    def put_writes(
        self,
        config: Any,
        writes: Any,
        task_id: str,
        task_path: str = "",
    ) -> None:
        for channel, value in writes:
            kind, payload = self.serde.dumps_typed(value)
            self.serialized_writes.append(
                channel.encode("utf-8") + b":" + kind.encode("ascii") + b":" + payload
            )
        super().put_writes(config, writes, task_id, task_path)


@pytest.mark.asyncio
async def test_every_serialized_checkpoint_is_content_free() -> None:
    case = guest_hinglish_scenario(turn_index=3)
    turn_id = uuid4()
    ephemeral: EphemeralTurnContext[dict[str, object]] = EphemeralTurnContext()
    lifecycle = TurnLifecycleRegistry()
    saver = _RecordingSaver()
    ephemeral.put(turn_id, {"wav": case.wav_bytes})
    lifecycle.begin(turn_id)
    graph = build_graph(
        case.ports,
        case.context_provider,
        ephemeral,
        lifecycle,
        lambda _: False,
        checkpointer=saver,
    )

    await graph.ainvoke(
        GraphState(
            turn_id=turn_id,
            phase="new",
            cancelled=False,
            content_commitments=(),
        ),
        config={"configurable": {"thread_id": str(turn_id)}, "callbacks": []},
    )

    observed = tuple(dict.fromkeys(phase for phase in saver.phases if phase in NODE_ORDER))
    assert observed == NODE_ORDER
    assert len(saver.serialized_checkpoints) >= len(NODE_ORDER)
    for payload in saver.serialized_checkpoints:
        for sentinel in (
            case.wav_bytes,
            b"synthetic-namaste-hello",
            b"synthetic-guest-context",
            b"synthetic-namaste-welcome",
            UUID("00000000-0000-0000-0000-000000000902").bytes,
        ):
            assert sentinel not in payload

    await saver.adelete_thread(str(turn_id))
    ephemeral.clear(turn_id)
    lifecycle.clear(turn_id)


@pytest.mark.asyncio
async def test_node_error_pending_writes_are_content_free() -> None:
    turn_id = uuid4()
    ephemeral: EphemeralTurnContext[dict[str, object]] = EphemeralTurnContext()
    lifecycle = TurnLifecycleRegistry()
    saver = _RecordingSaver()
    ports = _FailingPorts("generate")
    ephemeral.put(turn_id, {"wav": b"private-audio"})
    lifecycle.begin(turn_id)
    graph = build_graph(
        ports,
        _ContextProvider(),
        ephemeral,
        lifecycle,
        lambda _: False,
        checkpointer=saver,
    )

    with pytest.raises(RuntimeError, match="graph_node_failed") as raised:
        await graph.ainvoke(
            GraphState(
                turn_id=turn_id,
                phase="new",
                cancelled=False,
                content_commitments=(),
            ),
            config={"configurable": {"thread_id": str(turn_id)}, "callbacks": []},
        )

    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    serialized = tuple(saver.serialized_checkpoints + saver.serialized_writes)
    await saver.adelete_thread(str(turn_id))
    ephemeral.clear(turn_id)
    lifecycle.clear(turn_id)
    assert serialized
    for payload in serialized:
        assert b"private-content-must-not-survive" not in payload
        assert b"private-audio" not in payload


@pytest.mark.asyncio
async def test_external_tracing_is_rejected_before_graph_or_content_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = guest_hinglish_scenario(turn_index=4)
    engine = LangGraphConversationEngine(
        case.ports,
        context_provider=case.context_provider,
    )
    monkeypatch.setattr(
        langgraph_adapter,
        "_external_tracing_enabled",
        lambda: True,
        raising=False,
    )

    with pytest.raises(RuntimeError, match="external_graph_tracing_disabled"):
        await engine.run(TurnRequest(turn_id=uuid4(), wav_bytes=case.wav_bytes))

    assert case.events == []
    assert engine.ephemeral.count() == 0
    assert engine.lifecycle.count() == 0
    assert engine.checkpoint_count() == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("terminal", ("start", "transcribe", "generate", "synthesize", "play"))
async def test_graph_drops_every_store_after_each_node_failure(terminal: str) -> None:
    ports = _FailingPorts(terminal)
    engine = LangGraphConversationEngine(ports, context_provider=_ContextProvider())
    turn_id = uuid4()

    with pytest.raises(RuntimeError, match="private-content-must-not-survive"):
        await engine.run(TurnRequest(turn_id=turn_id, wav_bytes=b"private-audio"))

    expected_finish = ["finish"]
    assert ports.events[-1:] == expected_finish
    assert engine.ephemeral.contains(turn_id) is False
    assert engine.ephemeral.count() == 0
    assert engine.lifecycle.count() == 0
    assert engine.checkpoint_count() == 0
    assert engine.cancellation_count() == 0
    retained = repr(engine) + repr(engine.cleanup_reason_codes)
    for sentinel in ("private-audio", "private-transcript", "private-answer", "private-pcm"):
        assert sentinel not in retained


@pytest.mark.asyncio
@pytest.mark.parametrize("error_type", (TimeoutError, PermissionError))
async def test_timeout_and_privacy_denial_clear_every_graph_store(
    error_type: type[Exception],
) -> None:
    ports = _FailingPorts("generate", error_type=error_type)
    engine = LangGraphConversationEngine(ports, context_provider=_ContextProvider())
    turn_id = uuid4()

    with pytest.raises(error_type, match="private-content-must-not-survive"):
        await engine.run(TurnRequest(turn_id=turn_id, wav_bytes=b"private-audio"))

    assert ports.events[-1] == "finish"
    assert engine.ephemeral.count() == 0
    assert engine.lifecycle.count() == 0
    assert engine.checkpoint_count() == 0
    assert engine.cancellation_count() == 0


@pytest.mark.asyncio
async def test_cleanup_failures_use_fixed_codes_and_do_not_replace_primary_error() -> None:
    ports = _FailingPorts("generate", fail_finish=True)
    engine = LangGraphConversationEngine(ports, context_provider=_ContextProvider())

    def fail_before_clear(turn_id: UUID) -> None:
        del turn_id
        raise RuntimeError("private-ephemeral-cleanup-detail")

    engine.ephemeral.clear = fail_before_clear

    with pytest.raises(RuntimeError, match="private-content-must-not-survive") as raised:
        await engine.run(TurnRequest(turn_id=uuid4(), wav_bytes=b"private-audio"))

    assert raised.value.__notes__[-2:] == [
        "additional graph cleanup failure: RuntimeError",
        "additional graph cleanup failure: RuntimeError",
    ]
    assert "private-ephemeral-cleanup-detail" not in repr(raised.value.__notes__)
    assert "private-finish-detail" not in repr(raised.value.__notes__)
    assert engine.cleanup_reason_codes == [
        "ephemeral_clear_failed",
        "turn_finish_failed",
    ]
    assert "private" not in repr(engine.cleanup_reason_codes)
    assert engine.ephemeral.count() == 0
    assert engine.lifecycle.count() == 0
    assert engine.checkpoint_count() == 0


@pytest.mark.asyncio
async def test_checkpoint_delete_failure_uses_independent_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ports = _FailingPorts("generate")
    engine = LangGraphConversationEngine(ports, context_provider=_ContextProvider())

    async def fail_before_delete(thread_id: str) -> None:
        del thread_id
        raise RuntimeError("private-checkpoint-cleanup-detail")

    monkeypatch.setattr(engine._checkpointer, "adelete_thread", fail_before_delete)

    with pytest.raises(RuntimeError, match="private-content-must-not-survive") as raised:
        await engine.run(TurnRequest(turn_id=uuid4(), wav_bytes=b"private-audio"))

    assert raised.value.__notes__[-1:] == ["additional graph cleanup failure: RuntimeError"]
    assert "private-checkpoint-cleanup-detail" not in repr(raised.value.__notes__)
    assert engine.cleanup_reason_codes == ["checkpoint_delete_failed"]
    assert engine.ephemeral.count() == 0
    assert engine.lifecycle.count() == 0
    assert engine.checkpoint_count() == 0


@pytest.mark.asyncio
async def test_lifecycle_clear_failure_uses_independent_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ports = _FailingPorts("generate")
    engine = LangGraphConversationEngine(ports, context_provider=_ContextProvider())

    def fail_before_clear(turn_id: UUID) -> None:
        del turn_id
        raise RuntimeError("private-lifecycle-cleanup-detail")

    monkeypatch.setattr(engine.lifecycle, "clear", fail_before_clear)

    with pytest.raises(RuntimeError, match="private-content-must-not-survive") as raised:
        await engine.run(TurnRequest(turn_id=uuid4(), wav_bytes=b"private-audio"))

    assert raised.value.__notes__[-1:] == ["additional graph cleanup failure: RuntimeError"]
    assert "private-lifecycle-cleanup-detail" not in repr(raised.value.__notes__)
    assert engine.cleanup_reason_codes == ["lifecycle_clear_failed"]
    assert engine.ephemeral.count() == 0
    assert engine.lifecycle.count() == 0
    assert engine.checkpoint_count() == 0


def test_public_workflow_has_no_cancel_and_lock_has_no_persistent_checkpointer() -> None:
    assert not hasattr(ContractConversationWorkflow, "cancel")
    lock = Path("uv.lock").read_text(encoding="utf-8")
    assert 'name = "langgraph-checkpoint-sqlite"' not in lock
    assert 'name = "langgraph-checkpoint-postgres"' not in lock


def test_graph_adapter_has_no_store_repository_or_telemetry_dependency() -> None:
    source = Path("apps/core/src/tuntun_core/workflows/langgraph_adapter.py").read_text(
        encoding="utf-8"
    )
    for forbidden in (
        "InMemoryStore",
        "langgraph.store",
        "MessagesState",
        "add_messages",
        "import langsmith",
        "from langsmith",
        "tuntun_core.adapters",
    ):
        assert forbidden not in source


def test_hostile_external_tracing_environment_is_detected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LANGSMITH_TRACING", "true")

    assert langgraph_adapter._external_tracing_enabled() is True
