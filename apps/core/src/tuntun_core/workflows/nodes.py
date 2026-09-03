from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, cast
from uuid import UUID

from tuntun_core.services.personalized_turn_context import ProviderTurnContext
from tuntun_core.workflows.conversation import WorkflowPorts
from tuntun_core.workflows.ephemeral_turn_context import EphemeralTurnContext
from tuntun_core.workflows.state import GraphPhase, GraphState
from tuntun_core.workflows.turn_lifecycle import TurnLifecycleRegistry

Node = Callable[[GraphState], Awaitable[GraphState]]
_NODE_ERROR_KEY = "_graph_node_error"


class GraphNodeFailure(RuntimeError):
    """Fixed content-free error allowed to cross the checkpointer boundary."""


async def _content_free_await[T](
    context: dict[str, object],
    operation: Callable[[], Awaitable[T]],
) -> T:
    failure: GraphNodeFailure | None = None
    try:
        return await operation()
    except Exception as error:
        context[_NODE_ERROR_KEY] = error
        failure = GraphNodeFailure("graph_node_failed")
    assert failure is not None
    raise failure


def recover_node_error(context: dict[str, object]) -> BaseException | None:
    error = context.pop(_NODE_ERROR_KEY, None)
    return error if isinstance(error, BaseException) else None


def _advance(state: GraphState, phase: GraphPhase, *, cancelled: bool | None = None) -> GraphState:
    return GraphState(
        turn_id=state.turn_id,
        phase=phase,
        cancelled=state.cancelled if cancelled is None else cancelled,
        content_commitments=state.content_commitments,
    )


def build_nodes(
    ports: WorkflowPorts,
    context_provider: Any,
    ephemeral: EphemeralTurnContext[dict[str, object]],
    lifecycle: TurnLifecycleRegistry,
    is_cancelled: Callable[[UUID], bool],
) -> dict[str, Node]:
    def enter(state: GraphState, phase: GraphPhase) -> GraphState:
        if state.cancelled or is_cancelled(state.turn_id):
            return _advance(state, phase, cancelled=True)
        return _advance(state, phase)

    async def ingress(state: GraphState) -> GraphState:
        state = _advance(state, "ingress")
        if not state.cancelled:
            lifecycle.mark_start_attempted(state.turn_id)
            context = ephemeral.get(state.turn_id)
            await _content_free_await(context, lambda: ports.start(state.turn_id))
            state = enter(state, "ingress")
        return state

    async def transcribe(state: GraphState) -> GraphState:
        state = enter(state, "transcribe")
        if not state.cancelled:
            context = ephemeral.get(state.turn_id)
            transcript = await _content_free_await(
                context,
                lambda: ports.transcribe(cast(bytes, context["wav"])),
            )
            state = enter(state, "transcribe")
            context.pop("wav", None)
            if not state.cancelled:
                context["transcript"] = transcript
        return state

    async def resolve_identity(state: GraphState) -> GraphState:
        state = enter(state, "resolve_identity")
        if not state.cancelled:
            context = ephemeral.get(state.turn_id)
            provider_context = await _content_free_await(
                context,
                lambda: context_provider.prepare(
                    state.turn_id,
                    context["transcript"],
                ),
            )
            state = enter(state, "resolve_identity")
            context.pop("transcript", None)
            if not state.cancelled:
                context["provider_context"] = provider_context
        return state

    async def generate(state: GraphState) -> GraphState:
        state = enter(state, "generate")
        if not state.cancelled:
            context = ephemeral.get(state.turn_id)
            answer = await _content_free_await(
                context,
                lambda: ports.generate(cast(ProviderTurnContext, context["provider_context"])),
            )
            state = enter(state, "generate")
            context.pop("provider_context", None)
            if not state.cancelled:
                context["answer"] = answer
        return state

    async def synthesize(state: GraphState) -> GraphState:
        state = enter(state, "synthesize")
        if not state.cancelled:
            context = ephemeral.get(state.turn_id)
            pcm = await _content_free_await(
                context,
                lambda: ports.synthesize(cast(str, context["answer"])),
            )
            state = enter(state, "synthesize")
            context.pop("answer", None)
            if not state.cancelled:
                context["pcm"] = pcm
        return state

    async def audit_and_finish(state: GraphState) -> GraphState:
        state = enter(state, "audit_and_finish")
        if not state.cancelled:
            context = ephemeral.get(state.turn_id)
            await _content_free_await(
                context,
                lambda: ports.play(state.turn_id, cast(bytes, context["pcm"])),
            )
            context.pop("pcm", None)
            lifecycle.mark_played(state.turn_id)
        return state

    def phase_only(phase: GraphPhase) -> Node:
        async def node(state: GraphState) -> GraphState:
            return enter(state, phase)

        return node

    return {
        "ingress": ingress,
        "transcribe": transcribe,
        "resolve_identity": resolve_identity,
        "authorize_recall": phase_only("authorize_recall"),
        "retrieve_context": phase_only("retrieve_context"),
        "sanitize_and_reserve": phase_only("sanitize_and_reserve"),
        "generate": generate,
        "validate": phase_only("validate"),
        "synthesize": synthesize,
        "propose_memories": phase_only("propose_memories"),
        "audit_and_finish": audit_and_finish,
    }


__all__ = ["GraphNodeFailure", "Node", "build_nodes", "recover_node_error"]
