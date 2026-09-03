from __future__ import annotations

import asyncio
import os
from collections.abc import Callable, Coroutine
from typing import Any, Final, cast
from uuid import UUID

from langchain_core.tracers.context import _tracing_v2_is_enabled
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from tuntun_core.workflows.conversation import (
    ProviderEgressBoundary,
    TurnOutcome,
    TurnRequest,
    WorkflowPorts,
    _require_provider_egress,
)
from tuntun_core.workflows.ephemeral_turn_context import EphemeralTurnContext
from tuntun_core.workflows.nodes import GraphNodeFailure, build_nodes, recover_node_error
from tuntun_core.workflows.state import GraphState
from tuntun_core.workflows.turn_lifecycle import TurnLifecycleRegistry

NODE_ORDER: Final = (
    "ingress",
    "transcribe",
    "resolve_identity",
    "authorize_recall",
    "retrieve_context",
    "sanitize_and_reserve",
    "authorize_provider_egress",
    "generate",
    "validate",
    "synthesize",
    "propose_memories",
    "audit_and_finish",
)
_EXTERNAL_TRACING_ENV: Final = (
    "LANGSMITH_TRACING",
    "LANGSMITH_TRACING_V2",
    "LANGCHAIN_TRACING",
    "LANGCHAIN_TRACING_V2",
    "LANGCHAIN_HANDLER",
)


def _external_tracing_enabled() -> bool:
    for name in _EXTERNAL_TRACING_ENV:
        value = os.environ.get(name)
        if value is not None and value not in {"", "0", "false", "False"}:
            return True
    try:
        return bool(_tracing_v2_is_enabled())
    except BaseException:
        return True


def _require_uuid(value: object) -> UUID:
    if type(value) is not UUID:
        raise TypeError("turn_id must be an exact UUID")
    return value


def build_graph(
    ports: WorkflowPorts,
    context_provider: Any,
    ephemeral: EphemeralTurnContext[dict[str, object]],
    lifecycle: TurnLifecycleRegistry,
    is_cancelled: Callable[[UUID], bool],
    *,
    provider_egress: ProviderEgressBoundary | None,
    checkpointer: InMemorySaver | None = None,
) -> Any:
    checked_provider_egress = _require_provider_egress(provider_egress)
    saver = checkpointer if checkpointer is not None else InMemorySaver()
    builder = StateGraph(GraphState)
    nodes = build_nodes(
        ports,
        context_provider,
        ephemeral,
        lifecycle,
        is_cancelled,
        provider_egress=checked_provider_egress,
    )
    for name in NODE_ORDER:
        builder.add_node(name, cast(Any, nodes[name]))
    builder.add_edge(START, NODE_ORDER[0])
    for source, target in zip(NODE_ORDER, NODE_ORDER[1:], strict=False):
        builder.add_edge(source, target)
    builder.add_edge(NODE_ORDER[-1], END)
    return builder.compile(checkpointer=saver, store=None, name="tuntun-conversation-v1")


async def _await_owned(
    operation: Coroutine[Any, Any, None],
) -> tuple[BaseException | None, bool]:
    """Finish one cleanup awaitable despite repeated cancellation of its caller."""

    task: asyncio.Task[None] = asyncio.create_task(operation)
    cancellation_observed = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            if task.done():
                break
            cancellation_observed = True
            continue
        except BaseException:
            break
    try:
        task.result()
    except BaseException as error:
        return error, cancellation_observed
    return None, cancellation_observed


class LangGraphConversationEngine:
    """Private replaceable orchestrator whose checkpoints never own turn content."""

    def __init__(
        self,
        ports: WorkflowPorts,
        context_provider: Any,
        *,
        provider_egress: ProviderEgressBoundary | None = None,
        accepts_results: Callable[[UUID], bool] | None = None,
    ) -> None:
        if context_provider is None:
            raise TypeError("personalized context_provider required")
        checked_provider_egress = _require_provider_egress(provider_egress)
        self._ports = ports
        self._context_provider = context_provider
        self._provider_egress = checked_provider_egress
        self._accepts_results = accepts_results or (lambda _: True)
        self.ephemeral: EphemeralTurnContext[dict[str, object]] = EphemeralTurnContext()
        self.lifecycle = TurnLifecycleRegistry()
        self._cancelled: set[UUID] = set()
        self._active: set[UUID] = set()
        self.cleanup_reason_codes: list[str] = []
        self._checkpointer = InMemorySaver()
        self._graph = build_graph(
            ports,
            context_provider,
            self.ephemeral,
            self.lifecycle,
            self._is_cancelled,
            provider_egress=checked_provider_egress,
            checkpointer=self._checkpointer,
        )

    @property
    def context_provider(self) -> Any:
        return self._context_provider

    def _is_cancelled(self, turn_id: UUID) -> bool:
        return turn_id in self._cancelled or not self._accepts_results(turn_id)

    def checkpoint_count(self) -> int:
        return (
            len(self._checkpointer.storage)
            + len(self._checkpointer.writes)
            + len(self._checkpointer.blobs)
        )

    def cancellation_count(self) -> int:
        return len(self._cancelled)

    async def run(self, turn: TurnRequest) -> TurnOutcome:
        if type(turn) is not TurnRequest:
            raise TypeError("turn must be an exact TurnRequest")
        if _external_tracing_enabled():
            raise RuntimeError("external_graph_tracing_disabled")
        turn_id = _require_uuid(turn.turn_id)
        if turn_id in self._active:
            raise RuntimeError("turn graph already active")

        primary_error: BaseException | None = None
        lifecycle_begun = False
        ephemeral_written = False
        self._active.add(turn_id)
        try:
            self.lifecycle.begin(turn_id)
            lifecycle_begun = True
            self.ephemeral.put(turn_id, {"wav": turn.wav_bytes})
            ephemeral_written = True
            config = {
                "configurable": {"thread_id": str(turn_id)},
                "callbacks": [],
            }
            result = await self._graph.ainvoke(
                GraphState(
                    turn_id=turn_id,
                    phase="new",
                    cancelled=False,
                    content_commitments=(),
                ),
                config=config,
            )
            state = GraphState.model_validate(result, strict=True)
            _started, played = self.lifecycle.snapshot(turn_id)
            return TurnOutcome(spoken=not state.cancelled and played)
        except BaseException as error:
            primary_error = error
            if isinstance(error, GraphNodeFailure):
                try:
                    recovered = recover_node_error(self.ephemeral.get(turn_id))
                except BaseException as recovery_error:
                    error.add_note(
                        f"graph node error recovery failed: {type(recovery_error).__name__}"
                    )
                else:
                    if recovered is not None:
                        primary_error = recovered
                        raise recovered from None
            raise
        finally:
            cleanup_errors: list[BaseException] = []
            cancellation_observed = False
            if ephemeral_written:
                try:
                    self.ephemeral.clear(turn_id)
                except BaseException as error:
                    cleanup_errors.append(error)
                    self.cleanup_reason_codes.append("ephemeral_clear_failed")
                    try:
                        self.ephemeral.discard(turn_id)
                    except BaseException as fallback_error:
                        cleanup_errors.append(fallback_error)
                        self.cleanup_reason_codes.append("ephemeral_discard_failed")
            checkpoint_error, cancelled_during_delete = await _await_owned(
                self._checkpointer.adelete_thread(str(turn_id))
            )
            cancellation_observed = cancellation_observed or cancelled_during_delete
            if checkpoint_error is not None:
                cleanup_errors.append(checkpoint_error)
                self.cleanup_reason_codes.append("checkpoint_delete_failed")
                try:
                    self._checkpointer.delete_thread(str(turn_id))
                except BaseException as fallback_error:
                    cleanup_errors.append(fallback_error)
                    self.cleanup_reason_codes.append("checkpoint_discard_failed")

            started = False
            if lifecycle_begun:
                try:
                    started, _played = self.lifecycle.snapshot(turn_id)
                except BaseException as error:
                    cleanup_errors.append(error)
            if started:
                finish_error, cancelled_during_finish = await _await_owned(
                    self._ports.finish(turn_id)
                )
                cancellation_observed = cancellation_observed or cancelled_during_finish
                if finish_error is not None:
                    cleanup_errors.append(finish_error)
                    self.cleanup_reason_codes.append("turn_finish_failed")

            self._cancelled.discard(turn_id)
            self._active.discard(turn_id)
            if lifecycle_begun:
                try:
                    self.lifecycle.clear(turn_id)
                except BaseException as error:
                    cleanup_errors.append(error)
                    self.cleanup_reason_codes.append("lifecycle_clear_failed")
                    try:
                        self.lifecycle.discard(turn_id)
                    except BaseException as fallback_error:
                        cleanup_errors.append(fallback_error)
                        self.cleanup_reason_codes.append("lifecycle_discard_failed")

            if cleanup_errors:
                if primary_error is not None:
                    for cleanup_error in cleanup_errors:
                        primary_error.add_note(
                            f"additional graph cleanup failure: {type(cleanup_error).__name__}"
                        )
                else:
                    first, *additional = cleanup_errors
                    for cleanup_error in additional:
                        first.add_note(
                            f"additional graph cleanup failure: {type(cleanup_error).__name__}"
                        )
                    raise first
            if cancellation_observed and primary_error is None:
                raise asyncio.CancelledError

    async def cancel(self, turn_id: UUID) -> None:
        checked_turn_id = _require_uuid(turn_id)
        if checked_turn_id not in self._active:
            return
        self._cancelled.add(checked_turn_id)
        error, cancellation_observed = await _await_owned(
            self._checkpointer.adelete_thread(str(checked_turn_id))
        )
        if error is not None:
            self.cleanup_reason_codes.append("checkpoint_delete_failed")
            try:
                self._checkpointer.delete_thread(str(checked_turn_id))
            except BaseException:
                self.cleanup_reason_codes.append("checkpoint_discard_failed")
        if cancellation_observed:
            raise asyncio.CancelledError

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(active={len(self._active)}, "
            f"cancelled={self.cancellation_count()}, checkpoints={self.checkpoint_count()})"
        )


__all__ = ["NODE_ORDER", "LangGraphConversationEngine", "build_graph"]
