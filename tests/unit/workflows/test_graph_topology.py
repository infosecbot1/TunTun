from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from tuntun_core.bootstrap.container import build_workflow
from tuntun_core.workflows.conversation import (
    SYNTHETIC_NO_PROVIDER_TRANSPORT,
    LinearConversationEngine,
    ProviderEgressAuthorizer,
    TurnRequest,
)
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
        "authorize_provider_egress",
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
        provider_egress=SYNTHETIC_NO_PROVIDER_TRANSPORT,
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


class _WorkflowCoordinator:
    def accepts_results(self, turn_id: UUID) -> bool:
        del turn_id
        return True


def test_provider_capable_workflow_construction_requires_egress_boundary() -> None:
    with pytest.raises(TypeError, match="provider egress boundary required"):
        build_workflow(
            _LinearProviderPorts(),
            cast(Any, object()),
            cast(Any, _WorkflowCoordinator()),
            context_provider=_LateClosingContextProvider({"value": False}, "never"),
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
_AUTHORIZED_CONTEXT = object()
_WORKFLOW_HOUSEHOLD_ID = uuid4()
_WORKFLOW_SUBJECT_ID = uuid4()
_WORKFLOW_SESSION_ID = uuid4()
_WORKFLOW_RECEIPT_ID = uuid4()
_WORKFLOW_AUTHORIZATION = object()


@dataclass(frozen=True, slots=True)
class _WorkflowConsentEvidence:
    receipt_id: UUID


@dataclass(frozen=True, slots=True)
class _WorkflowRouteDraft:
    household_id: UUID
    subject_id: UUID | None
    session_id: UUID
    required_consent_purposes: tuple[str, ...]
    consent_receipt_ids: tuple[UUID, ...] = ()

    def with_consent_receipt_ids(self, receipt_ids: tuple[UUID, ...]) -> _WorkflowRouteDraft:
        return replace(self, consent_receipt_ids=receipt_ids)

    def to_route_authorization_request(self) -> _WorkflowRouteDraft:
        return self


class _WorkflowClock:
    def __init__(self) -> None:
        self.observed_at = datetime(2026, 1, 1, tzinfo=UTC)

    def now(self) -> datetime:
        return self.observed_at


class _WorkflowConsentEvidenceReader:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.calls: list[tuple[UUID, UUID | None, UUID, tuple[str, ...], datetime]] = []

    async def require(
        self,
        household_id: UUID,
        subject_id: UUID | None,
        session_id: UUID,
        purposes: tuple[str, ...],
        now: datetime,
    ) -> tuple[_WorkflowConsentEvidence, ...]:
        self.events.append("consent")
        self.calls.append((household_id, subject_id, session_id, purposes, now))
        return (_WorkflowConsentEvidence(_WORKFLOW_RECEIPT_ID),)


class _WorkflowRouteAuthorizer:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.requests: list[_WorkflowRouteDraft] = []

    async def authorize(self, request: object) -> object:
        self.events.append("authorize")
        assert type(request) is _WorkflowRouteDraft
        self.requests.append(request)
        return _WORKFLOW_AUTHORIZATION


class _WorkflowRouteDraftFactory:
    def __init__(self) -> None:
        self.events: list[str] = []

    async def provider_route_draft(self, context: object) -> _WorkflowRouteDraft:
        self.events.append("draft")
        assert context is _PRIVATE_CONTEXT
        return _WorkflowRouteDraft(
            household_id=_WORKFLOW_HOUSEHOLD_ID,
            subject_id=_WORKFLOW_SUBJECT_ID,
            session_id=_WORKFLOW_SESSION_ID,
            required_consent_purposes=("cloud_reasoning",),
        )


class _NoneWorkflowRouteDraftFactory(_WorkflowRouteDraftFactory):
    async def provider_route_draft(self, context: object) -> None:
        self.events.append("draft")
        assert context is _PRIVATE_CONTEXT
        return None


class _WorkflowRouteAuthorizationBinder:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def bind_route_authorization(
        self,
        context: object,
        authorization: object,
    ) -> object:
        self.events.append("bind")
        assert context is _PRIVATE_CONTEXT
        assert authorization is _WORKFLOW_AUTHORIZATION
        return _AUTHORIZED_CONTEXT


class _LinearProviderPorts:
    def __init__(self) -> None:
        self.generated = False
        self.finished = False

    async def start(self, turn_id: UUID) -> None:
        del turn_id

    async def transcribe(self, wav_bytes: bytes) -> object:
        assert wav_bytes == b"private-audio"
        return _PRIVATE_TRANSCRIPT

    async def generate(self, context: object) -> str:
        del context
        self.generated = True
        return "private-answer"

    async def synthesize(self, answer: str) -> bytes:
        assert answer == "private-answer"
        return b"private-pcm"

    async def play(self, turn_id: UUID, pcm: bytes) -> None:
        del turn_id
        assert pcm == b"private-pcm"

    async def finish(self, turn_id: UUID) -> None:
        del turn_id
        self.finished = True


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
        provider_egress=SYNTHETIC_NO_PROVIDER_TRANSPORT,
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


@pytest.mark.asyncio
async def test_provider_egress_node_attaches_current_consent_before_authorizing() -> None:
    turn_id = uuid4()
    ephemeral: EphemeralTurnContext[dict[str, object]] = EphemeralTurnContext()
    ephemeral.put(turn_id, {"provider_context": _PRIVATE_CONTEXT})
    lifecycle = TurnLifecycleRegistry()
    route_drafts = _WorkflowRouteDraftFactory()
    consent_evidence = _WorkflowConsentEvidenceReader(route_drafts.events)
    route_authorizer = _WorkflowRouteAuthorizer(route_drafts.events)
    provider_egress = ProviderEgressAuthorizer(
        route_drafts=route_drafts,
        consent_evidence=consent_evidence,
        route_authorizer=route_authorizer,
        binder=_WorkflowRouteAuthorizationBinder(route_drafts.events),
        clock=_WorkflowClock(),
    )

    nodes = build_nodes(
        cast(Any, object()),
        cast(Any, object()),
        ephemeral,
        lifecycle,
        lambda _: False,
        provider_egress=provider_egress,
    )

    state = await nodes["authorize_provider_egress"](
        GraphState(
            turn_id=turn_id,
            phase="sanitize_and_reserve",
            cancelled=False,
            content_commitments=(),
        )
    )

    assert state.phase == "authorize_provider_egress"
    assert ephemeral.get(turn_id) == {"provider_context": _AUTHORIZED_CONTEXT}
    assert route_drafts.events == ["draft", "consent", "authorize", "bind"]
    assert consent_evidence.calls == [
        (
            _WORKFLOW_HOUSEHOLD_ID,
            _WORKFLOW_SUBJECT_ID,
            _WORKFLOW_SESSION_ID,
            ("cloud_reasoning",),
            provider_egress.clock.observed_at,
        )
    ]
    assert route_authorizer.requests[0].consent_receipt_ids == (_WORKFLOW_RECEIPT_ID,)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "provider_egress",
    (
        ProviderEgressAuthorizer(
            route_drafts=cast(Any, object()),
            consent_evidence=_WorkflowConsentEvidenceReader([]),
            route_authorizer=_WorkflowRouteAuthorizer([]),
            binder=_WorkflowRouteAuthorizationBinder([]),
            clock=_WorkflowClock(),
        ),
        ProviderEgressAuthorizer(
            route_drafts=_WorkflowRouteDraftFactory(),
            consent_evidence=cast(Any, object()),
            route_authorizer=_WorkflowRouteAuthorizer([]),
            binder=_WorkflowRouteAuthorizationBinder([]),
            clock=_WorkflowClock(),
        ),
        ProviderEgressAuthorizer(
            route_drafts=_WorkflowRouteDraftFactory(),
            consent_evidence=_WorkflowConsentEvidenceReader([]),
            route_authorizer=cast(Any, object()),
            binder=_WorkflowRouteAuthorizationBinder([]),
            clock=_WorkflowClock(),
        ),
        ProviderEgressAuthorizer(
            route_drafts=_WorkflowRouteDraftFactory(),
            consent_evidence=_WorkflowConsentEvidenceReader([]),
            route_authorizer=_WorkflowRouteAuthorizer([]),
            binder=cast(Any, object()),
            clock=_WorkflowClock(),
        ),
    ),
)
async def test_provider_capable_workflow_missing_route_hook_cannot_reach_generate(
    provider_egress: ProviderEgressAuthorizer,
) -> None:
    ports = _LinearProviderPorts()
    engine = LinearConversationEngine(
        ports,
        context_provider=_LateClosingContextProvider({"value": False}, "never"),
        provider_egress=provider_egress,
    )

    with pytest.raises((AttributeError, TypeError)):
        await engine.run(TurnRequest(uuid4(), b"private-audio"))

    assert ports.generated is False
    assert ports.finished is True


@pytest.mark.asyncio
async def test_provider_capable_workflow_none_draft_cannot_bypass_authorization() -> None:
    events: list[str] = []
    provider_egress = ProviderEgressAuthorizer(
        route_drafts=_NoneWorkflowRouteDraftFactory(),
        consent_evidence=_WorkflowConsentEvidenceReader(events),
        route_authorizer=_WorkflowRouteAuthorizer(events),
        binder=_WorkflowRouteAuthorizationBinder(events),
        clock=_WorkflowClock(),
    )
    ports = _LinearProviderPorts()
    engine = LinearConversationEngine(
        ports,
        context_provider=_LateClosingContextProvider({"value": False}, "never"),
        provider_egress=provider_egress,
    )

    with pytest.raises(PermissionError, match="provider_route_draft_required"):
        await engine.run(TurnRequest(uuid4(), b"private-audio"))

    assert ports.generated is False
    assert ports.finished is True
