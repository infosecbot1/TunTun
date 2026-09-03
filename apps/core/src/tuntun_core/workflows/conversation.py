from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final, Literal, Protocol, cast
from uuid import UUID

from tuntun_core.services.personalized_turn_context import ProviderTurnContext, TranscribedTurn
from tuntun_core.services.providers.route_authorization import (
    ConsentEvidenceReader,
    ConsentReceiptAttachable,
    attach_current_consent_receipts,
)
from tuntun_core.workflows.ephemeral_turn_context import EphemeralTurnContext


@dataclass(frozen=True, slots=True)
class TurnRequest:
    turn_id: UUID
    wav_bytes: bytes

    def __post_init__(self) -> None:
        if type(self.turn_id) is not UUID:
            raise TypeError("turn_id must be an exact UUID")
        if type(self.wav_bytes) is not bytes:
            raise TypeError("wav_bytes must be exact bytes")


@dataclass(frozen=True, slots=True)
class TurnOutcome:
    spoken: bool

    def __post_init__(self) -> None:
        if type(self.spoken) is not bool:
            raise TypeError("spoken must be an exact bool")


class WorkflowPorts(Protocol):
    async def start(self, turn_id: UUID) -> None: ...

    async def transcribe(self, wav_bytes: bytes) -> TranscribedTurn: ...

    async def generate(self, context: ProviderTurnContext) -> str: ...

    async def synthesize(self, answer: str) -> bytes: ...

    async def play(self, turn_id: UUID, pcm: bytes) -> None: ...

    async def finish(self, turn_id: UUID) -> None: ...


class ContextWorkflowPorts(Protocol):
    async def start(self, turn_id: UUID) -> None: ...

    async def transcribe(self, wav_bytes: bytes) -> object: ...

    async def guest_identity(self) -> str: ...

    async def generate(self, context: Any) -> str: ...

    async def synthesize(self, answer: str) -> bytes: ...

    async def play(self, turn_id: UUID, pcm: bytes) -> None: ...

    async def finish(self, turn_id: UUID) -> None: ...


class LegacyWorkflowPorts(Protocol):
    async def start(self, turn_id: UUID) -> None: ...

    async def transcribe(self, wav_bytes: bytes) -> object: ...

    async def guest_identity(self) -> str: ...

    async def generate(self, transcript: Any, identity: str) -> str: ...

    async def synthesize(self, answer: str) -> bytes: ...

    async def play(self, turn_id: UUID, pcm: bytes) -> None: ...

    async def finish(self, turn_id: UUID) -> None: ...


class ProviderRouteDraft(ConsentReceiptAttachable, Protocol):
    def to_route_authorization_request(self) -> object: ...


class ProviderRouteDraftSource(Protocol):
    async def provider_route_draft(self, context: ProviderTurnContext) -> ProviderRouteDraft: ...


class ProviderRouteAuthorizer(Protocol):
    async def authorize(self, request: object) -> object: ...


class ProviderRouteAuthorizationBinder(Protocol):
    async def bind_route_authorization(
        self,
        context: ProviderTurnContext,
        authorization: object,
    ) -> ProviderTurnContext: ...


class ProviderEgressClock(Protocol):
    def now(self) -> datetime: ...


@dataclass(frozen=True, slots=True)
class SyntheticNoProviderTransport:
    mode: Literal["synthetic_no_provider_transport"] = "synthetic_no_provider_transport"


@dataclass(frozen=True, slots=True)
class ProviderEgressAuthorizer:
    route_drafts: ProviderRouteDraftSource
    consent_evidence: ConsentEvidenceReader
    route_authorizer: ProviderRouteAuthorizer
    binder: ProviderRouteAuthorizationBinder
    clock: ProviderEgressClock

    async def authorize(self, context: ProviderTurnContext) -> ProviderTurnContext:
        draft = await self.route_drafts.provider_route_draft(context)
        if draft is None:
            raise PermissionError("provider_route_draft_required")
        draft_with_consent = cast(
            ProviderRouteDraft,
            await attach_current_consent_receipts(
                draft,
                self.consent_evidence,
                self.clock.now(),
            ),
        )
        authorization = await self.route_authorizer.authorize(
            draft_with_consent.to_route_authorization_request()
        )
        return await self.binder.bind_route_authorization(context, authorization)


ProviderEgressBoundary = ProviderEgressAuthorizer | SyntheticNoProviderTransport
SYNTHETIC_NO_PROVIDER_TRANSPORT: Final = SyntheticNoProviderTransport()


def _require_provider_egress(value: object) -> ProviderEgressBoundary:
    if type(value) in {ProviderEgressAuthorizer, SyntheticNoProviderTransport}:
        return cast(ProviderEgressBoundary, value)
    raise TypeError("provider egress boundary required")


async def authorize_provider_egress(
    provider_egress: ProviderEgressBoundary,
    context: ProviderTurnContext,
) -> ProviderTurnContext:
    if type(provider_egress) is SyntheticNoProviderTransport:
        return context
    if type(provider_egress) is ProviderEgressAuthorizer:
        return await provider_egress.authorize(context)
    raise TypeError("provider egress boundary required")


def _always_accepts_results(turn_id: UUID) -> bool:
    del turn_id
    return True


class LinearConversationEngine:
    """Private deterministic orchestrator for the simulated Guest slice."""

    def __init__(
        self,
        ports: Any,
        *,
        context_provider: Any | None = None,
        provider_egress: ProviderEgressBoundary | None = None,
        allow_legacy_guest_identity: bool = False,
        accepts_results: Callable[[UUID], bool] = _always_accepts_results,
    ) -> None:
        if context_provider is None and allow_legacy_guest_identity is not True:
            raise TypeError("personalized context_provider required")
        self._ports = ports
        self._context_provider = context_provider
        self._provider_egress = _require_provider_egress(provider_egress)
        self._allow_legacy_guest_identity = allow_legacy_guest_identity
        self._accepts_results = accepts_results
        self.ephemeral: EphemeralTurnContext[dict[str, object]] = EphemeralTurnContext()
        self.cleanup_reason_codes: list[str] = []

    @property
    def context_provider(self) -> Any | None:
        return self._context_provider

    def _accepts_turn_results(self, turn_id: UUID) -> bool:
        return self._accepts_results(turn_id)

    async def run(self, turn: TurnRequest) -> TurnOutcome:
        if type(turn) is not TurnRequest:
            raise TypeError("turn must be an exact TurnRequest")
        start_attempted = False
        primary_error: BaseException | None = None
        self.ephemeral.put(turn.turn_id, {"wav": turn.wav_bytes})
        try:
            start_attempted = True
            await self._ports.start(turn.turn_id)
            if not self._accepts_turn_results(turn.turn_id):
                return TurnOutcome(spoken=False)
            transcript = await self._ports.transcribe(turn.wav_bytes)
            if not self._accepts_turn_results(turn.turn_id):
                return TurnOutcome(spoken=False)
            self.ephemeral.put(turn.turn_id, {"transcript": transcript})
            if self._context_provider is None:
                if self._allow_legacy_guest_identity is not True:
                    raise RuntimeError("personalized context_provider required")
                identity = await self._ports.guest_identity()
                if not self._accepts_turn_results(turn.turn_id):
                    return TurnOutcome(spoken=False)
                answer = await self._ports.generate(transcript, identity)
            else:
                context = await self._context_provider.prepare(turn.turn_id, transcript)
                if not self._accepts_turn_results(turn.turn_id):
                    return TurnOutcome(spoken=False)
                context = await authorize_provider_egress(self._provider_egress, context)
                if not self._accepts_turn_results(turn.turn_id):
                    return TurnOutcome(spoken=False)
                answer = await self._ports.generate(context)
            if not self._accepts_turn_results(turn.turn_id):
                return TurnOutcome(spoken=False)
            self.ephemeral.put(turn.turn_id, {"answer": answer})
            pcm = await self._ports.synthesize(answer)
            if not self._accepts_turn_results(turn.turn_id):
                return TurnOutcome(spoken=False)
            await self._ports.play(turn.turn_id, pcm)
            return TurnOutcome(spoken=True)
        except BaseException as error:
            primary_error = error
            raise
        finally:
            cleanup_error: BaseException | None = None
            try:
                self.ephemeral.clear(turn.turn_id)
            except BaseException as error:
                cleanup_error = error
            if start_attempted:
                try:
                    await self._ports.finish(turn.turn_id)
                except BaseException as error:
                    if cleanup_error is None:
                        cleanup_error = error
            if cleanup_error is not None:
                self.cleanup_reason_codes.append("turn_cleanup_failed")
                if primary_error is None:
                    raise cleanup_error
