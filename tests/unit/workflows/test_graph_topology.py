from __future__ import annotations

from typing import Any, cast
from uuid import uuid4

import pytest
from tuntun_core.bootstrap.container import build_workflow
from tuntun_core.workflows.ephemeral_turn_context import EphemeralTurnContext
from tuntun_core.workflows.langgraph_adapter import NODE_ORDER, build_graph
from tuntun_core.workflows.nodes import build_nodes
from tuntun_core.workflows.state import GraphState
from tuntun_core.workflows.turn_lifecycle import TurnLifecycleRegistry
from tuntun_testing.scenario import guest_hinglish_scenario


def test_graph_has_exact_reviewed_linear_order() -> None:
    assert NODE_ORDER == (
        "ingress",
        "transcribe",
        "resolve_identity",
        "authorize_recall",
        "retrieve_context",
        "sanitize_and_reserve",
        "generate",
        "validate",
        "synthesize",
        "propose_memories",
        "audit_and_finish",
    )
    scenario = guest_hinglish_scenario()
    graph = build_graph(
        scenario.ports,
        scenario.context_provider,
        EphemeralTurnContext(),
        TurnLifecycleRegistry(),
        lambda _: False,
    )

    assert tuple(name for name in graph.nodes if name in NODE_ORDER) == NODE_ORDER


def test_ephemeral_and_lifecycle_count_helpers_disclose_no_content() -> None:
    ephemeral: EphemeralTurnContext[dict[str, object]] = EphemeralTurnContext()
    lifecycle = TurnLifecycleRegistry()

    assert ephemeral.count() == 0
    assert lifecycle.count() == 0
    assert "_items" not in repr(ephemeral)
    assert "_items" not in repr(lifecycle)


def test_composition_rejects_unknown_selector_before_using_dependencies() -> None:
    with pytest.raises(ValueError, match="unknown workflow"):
        build_workflow(
            cast(Any, object()),
            cast(Any, object()),
            cast(Any, object()),
            context_provider=cast(Any, object()),
            workflow_name=cast(Any, "unknown"),
        )


class _LateClosingPorts:
    def __init__(self, closed: dict[str, bool], close_at: str) -> None:
        self._closed = closed
        self._close_at = close_at

    def _close(self, operation: str) -> None:
        if operation == self._close_at:
            self._closed["value"] = True

    async def transcribe(self, wav_bytes: bytes) -> object:
        assert wav_bytes == b"private-audio"
        self._close("transcribe")
        return object()

    async def generate(self, context: object) -> str:
        assert context is _PRIVATE_CONTEXT
        self._close("generate")
        return "private-answer"

    async def synthesize(self, answer: str) -> bytes:
        assert answer == "private-answer"
        self._close("synthesize")
        return b"private-pcm"


class _LateClosingContextProvider:
    def __init__(self, closed: dict[str, bool], close_at: str) -> None:
        self._closed = closed
        self._close_at = close_at

    async def prepare(self, turn_id: object, transcript: object) -> object:
        del turn_id
        assert transcript is _PRIVATE_TRANSCRIPT
        if self._close_at == "resolve_identity":
            self._closed["value"] = True
        return _PRIVATE_CONTEXT


_PRIVATE_TRANSCRIPT = object()
_PRIVATE_CONTEXT = object()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("node_name", "initial_context"),
    (
        ("transcribe", {"wav": b"private-audio"}),
        ("resolve_identity", {"transcript": _PRIVATE_TRANSCRIPT}),
        ("generate", {"provider_context": _PRIVATE_CONTEXT}),
        ("synthesize", {"answer": "private-answer"}),
    ),
)
async def test_content_node_rechecks_result_gate_after_await(
    node_name: str,
    initial_context: dict[str, object],
) -> None:
    closed = {"value": False}
    turn_id = uuid4()
    ephemeral: EphemeralTurnContext[dict[str, object]] = EphemeralTurnContext()
    lifecycle = TurnLifecycleRegistry()

    ephemeral.put(turn_id, dict(initial_context))
    lifecycle.begin(turn_id)
    nodes = build_nodes(
        cast(Any, _LateClosingPorts(closed, node_name)),
        _LateClosingContextProvider(closed, node_name),
        ephemeral,
        lifecycle,
        lambda _: closed["value"],
    )

    state = await nodes[node_name](
        GraphState(
            turn_id=turn_id,
            phase="new",
            cancelled=False,
            content_commitments=(),
        )
    )

    assert state.cancelled is True
    assert ephemeral.get(turn_id) == {}
