from __future__ import annotations

from collections import deque
from collections.abc import AsyncIterator, Callable, Iterable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, cast
from uuid import UUID

from tuntun_contracts.actions import ActionBinding, ActionReceipt, ValidatedActionProposal
from tuntun_contracts.audit import AuditDraft, AuditReceipt
from tuntun_contracts.base import Commitment
from tuntun_contracts.budget import (
    BudgetAccountingContext,
    BudgetReconciliationRequest,
    BudgetReservation,
    BudgetReservationRequest,
    BudgetSettlement,
    BudgetSettlementRequest,
    LlmUsageUnits,
    SttUsageUnits,
    TransportProof,
    TtsUsageUnits,
)
from tuntun_contracts.identity import IdentityDecision, IdentityRequest
from tuntun_contracts.memory import (
    ApprovedMemory,
    DecideMemoryProposal,
    MemoryProposal,
    MemoryProposalDraft,
    MemoryQuery,
    MemoryRecord,
    ProposalContext,
)
from tuntun_contracts.policy import (
    AuthContext,
    AuthenticationChallenge,
    AuthenticationRequest,
    AuthenticationResponse,
    AuthGrant,
    PolicyDecision,
    PolicyRequest,
)
from tuntun_contracts.ports import AsyncTransactionBoundary
from tuntun_contracts.provider import (
    ProviderResponse,
    RouteAuthorization,
    RouteAuthorizationRequest,
    RouteConsumption,
    SanitizedProviderRequest,
)
from tuntun_contracts.speech import (
    AuthorizedSynthesisRequest,
    AuthorizedTranscriptionRequest,
    SpeechChunk,
    TranscriptResult,
)


@dataclass(frozen=True, slots=True)
class ReturnValue:
    value: object


@dataclass(frozen=True, slots=True)
class RaiseError:
    error: BaseException


Outcome = ReturnValue | RaiseError


@dataclass(frozen=True, slots=True)
class ExpectedCall:
    operation: str
    args: tuple[object, ...]
    outcome: Outcome


@dataclass(frozen=True, slots=True)
class ObservedCall:
    operation: str
    args: tuple[object, ...]


class ScriptExhaustionError(AssertionError):
    pass


class UnexpectedCallError(AssertionError):
    pass


class _ScriptedFake:
    def __init__(
        self,
        expectations: Iterable[ExpectedCall],
        observer: Callable[[ObservedCall], None] | None = None,
    ) -> None:
        self._expectations = deque(expectations)
        self._calls: list[ObservedCall] = []
        self._observer = observer

    @property
    def calls(self) -> tuple[ObservedCall, ...]:
        return tuple(self._calls)

    def _take(self, operation: str, args: tuple[object, ...]) -> object:
        if not self._expectations:
            raise UnexpectedCallError("unexpected-call")
        expected = self._expectations[0]
        if expected.operation != operation or expected.args != args:
            raise UnexpectedCallError("unexpected-call")
        self._expectations.popleft()
        observed = ObservedCall(operation=operation, args=args)
        self._calls.append(observed)
        if self._observer is not None:
            self._observer(observed)
        if isinstance(expected.outcome, RaiseError):
            raise expected.outcome.error
        return expected.outcome.value

    def assert_exhausted(self) -> None:
        if self._expectations:
            raise ScriptExhaustionError("script-not-exhausted")

    def __repr__(self) -> str:
        return f"{type(self).__name__}(remaining={len(self._expectations)})"


class FakeSpeechToText(_ScriptedFake):
    async def transcribe(
        self,
        request: AuthorizedTranscriptionRequest,
        audio: AsyncIterator[bytes],
    ) -> TranscriptResult:
        received = bytearray()
        try:
            async for chunk in audio:
                if not isinstance(chunk, bytes):
                    raise TypeError("invalid-audio-chunk")
                if len(received) + len(chunk) > request.audio_bytes:
                    raise ValueError("audio-bound-exceeded")
                received.extend(chunk)
            if len(received) != request.audio_bytes:
                raise ValueError("audio-size-mismatch")
            return cast(
                TranscriptResult,
                self._take("stt.transcribe", (request, bytes(received))),
            )
        finally:
            received[:] = b"\x00" * len(received)
            received.clear()


class FakeTextToSpeech(_ScriptedFake):
    def __init__(
        self,
        expectations: Iterable[ExpectedCall],
        observer: Callable[[ObservedCall], None] | None = None,
    ) -> None:
        super().__init__(expectations, observer)
        self._next_stream_id = 0
        self._incomplete_streams: set[int] = set()

    def synthesize(
        self,
        request: AuthorizedSynthesisRequest,
    ) -> AsyncIterator[SpeechChunk]:
        items = cast(tuple[SpeechChunk | RaiseError, ...], self._take("tts.synthesize", (request,)))
        stream_id = self._next_stream_id
        self._next_stream_id += 1
        self._incomplete_streams.add(stream_id)
        return self._stream(stream_id, items)

    async def _stream(
        self,
        stream_id: int,
        items: tuple[SpeechChunk | RaiseError, ...],
    ) -> AsyncIterator[SpeechChunk]:
        terminal = False
        try:
            for item in items:
                if isinstance(item, RaiseError):
                    terminal = True
                    raise item.error
                if not isinstance(item, SpeechChunk):
                    terminal = True
                    raise TypeError("invalid-speech-chunk")
                yield item
            terminal = True
        finally:
            if terminal:
                self._incomplete_streams.discard(stream_id)

    def assert_exhausted(self) -> None:
        super().assert_exhausted()
        if self._incomplete_streams:
            raise ScriptExhaustionError("stream-not-exhausted")


class FakeLanguageModel(_ScriptedFake):
    async def complete(self, request: SanitizedProviderRequest) -> ProviderResponse:
        return cast(ProviderResponse, self._take("llm.complete", (request,)))


class FakeIdentityFusion(_ScriptedFake):
    async def resolve(self, request: IdentityRequest) -> IdentityDecision:
        return cast(IdentityDecision, self._take("identity.resolve", (request,)))


class FakeMemoryRepository(_ScriptedFake):
    async def create(
        self,
        memory: ApprovedMemory,
        expected_absent: bool = True,
    ) -> MemoryRecord:
        return cast(MemoryRecord, self._take("memory.create", (memory, expected_absent)))

    async def replace(
        self,
        memory_id: UUID,
        expected_version: int,
        memory: ApprovedMemory,
    ) -> MemoryRecord:
        return cast(
            MemoryRecord,
            self._take("memory.replace", (memory_id, expected_version, memory)),
        )

    async def delete(
        self,
        memory_id: UUID,
        expected_version: int,
        auth: AuthContext,
        approved_proposal_id: UUID,
    ) -> None:
        result = self._take(
            "memory.delete",
            (memory_id, expected_version, auth, approved_proposal_id),
        )
        if result is not None:
            raise TypeError("invalid-void-outcome")

    async def query(self, query: MemoryQuery) -> tuple[MemoryRecord, ...]:
        return cast(tuple[MemoryRecord, ...], self._take("memory.query", (query,)))


class FakeMemoryProposalService(_ScriptedFake):
    async def stage(
        self,
        draft: MemoryProposalDraft,
        context: ProposalContext,
    ) -> MemoryProposal:
        return cast(MemoryProposal, self._take("proposal.stage", (draft, context)))

    async def decide(
        self,
        command: DecideMemoryProposal,
        auth: AuthContext,
    ) -> MemoryProposal:
        return cast(MemoryProposal, self._take("proposal.decide", (command, auth)))


class FakePolicyEngine(_ScriptedFake):
    async def decide(self, request: PolicyRequest) -> PolicyDecision:
        return cast(PolicyDecision, self._take("policy.decide", (request,)))


class FakeAuthentication(_ScriptedFake):
    async def start(self, request: AuthenticationRequest) -> AuthenticationChallenge:
        return cast(AuthenticationChallenge, self._take("auth.start", (request,)))

    async def verify(self, response: AuthenticationResponse) -> AuthGrant:
        return cast(AuthGrant, self._take("auth.verify", (response,)))

    async def consume(self, grant_id: UUID, binding: ActionBinding) -> AuthContext:
        return cast(AuthContext, self._take("auth.consume", (grant_id, binding)))


class FakeActionProvider(_ScriptedFake):
    async def execute(
        self,
        proposal: ValidatedActionProposal,
        auth: AuthContext,
    ) -> ActionReceipt:
        return cast(ActionReceipt, self._take("action.execute", (proposal, auth)))


class FakeAudit(_ScriptedFake):
    async def append(
        self,
        uow: AsyncTransactionBoundary,
        draft: AuditDraft,
    ) -> AuditReceipt:
        return cast(AuditReceipt, self._take("audit.append", (uow, draft)))


class FakeBudget(_ScriptedFake):
    async def reserve(self, request: BudgetReservationRequest) -> BudgetReservation:
        return cast(BudgetReservation, self._take("budget.reserve", (request,)))

    async def mark_sent(self, reservation_id: UUID, attempt_id: UUID) -> None:
        result = self._take("budget.mark_sent", (reservation_id, attempt_id))
        if result is not None:
            raise TypeError("invalid-void-outcome")

    async def require_accounting_context(
        self,
        route: RouteAuthorization,
        consumption: RouteConsumption,
    ) -> BudgetAccountingContext:
        return cast(
            BudgetAccountingContext,
            self._take("budget.require_accounting_context", (route, consumption)),
        )

    async def settle(self, request: BudgetSettlementRequest) -> BudgetSettlement:
        return cast(BudgetSettlement, self._take("budget.settle", (request,)))

    async def release_unsent(
        self,
        reservation_id: UUID,
        attempt_id: UUID,
        proof: TransportProof,
    ) -> None:
        result = self._take("budget.release_unsent", (reservation_id, attempt_id, proof))
        if result is not None:
            raise TypeError("invalid-void-outcome")

    async def reconcile_turn(
        self,
        request: BudgetReconciliationRequest,
    ) -> tuple[BudgetSettlement, ...]:
        return cast(
            tuple[BudgetSettlement, ...],
            self._take("budget.reconcile_turn", (request,)),
        )


class FakeRouteAuthorizer(_ScriptedFake):
    async def authorize(self, request: RouteAuthorizationRequest) -> RouteAuthorization:
        return cast(RouteAuthorization, self._take("route.authorize", (request,)))

    async def consume(
        self,
        authorization_id: UUID,
        consumption: RouteConsumption,
    ) -> None:
        result = self._take("route.consume", (authorization_id, consumption))
        if result is not None:
            raise TypeError("invalid-void-outcome")


FakeIdentity = FakeIdentityFusion
FakeMemory = FakeMemoryRepository
FakePolicy = FakePolicyEngine


_CATEGORY_BY_PURPOSE = {
    "cloud_stt": "stt",
    "cloud_reasoning": "llm",
    "cloud_tts": "tts",
}


class RecordingBudget:
    def __init__(self, clock: Any) -> None:
        self.clock = clock
        self.reservation_ids: list[UUID] = []
        self.terminal_pairs: set[tuple[UUID, UUID]] = set()
        self.released_pairs: set[tuple[UUID, UUID]] = set()
        self.conservative_settlements: list[UUID] = []
        self._attempt_to_reservation: dict[UUID, UUID] = {}
        self._sent: set[tuple[UUID, UUID]] = set()
        self._exact_usage: set[UUID] = set()

    async def reserve(self, request: BudgetReservationRequest) -> BudgetReservation:
        reservation_id = UUID(int=len(self.reservation_ids) + 10_001)
        self.reservation_ids.append(reservation_id)
        self._attempt_to_reservation[request.attempt_id] = reservation_id
        return BudgetReservation(
            reservation_id=reservation_id,
            request_id=request.request_id,
            attempt_id=request.attempt_id,
            outcome="allow",
            amount_micros_sgd=1,
            pricing_commitment=Commitment(
                algorithm="HMAC-SHA-256",
                key_id="pricing-v1",
                value_b64="A" * 43 + "=",
            ),
            expires_at=self.clock.now() + timedelta(seconds=30),
        )

    async def mark_sent(self, reservation_id: UUID, attempt_id: UUID) -> None:
        self._sent.add((reservation_id, attempt_id))

    async def require_accounting_context(
        self,
        route: RouteAuthorization,
        consumption: RouteConsumption,
    ) -> BudgetAccountingContext:
        del consumption
        if route.purpose == "cloud_stt":
            return BudgetAccountingContext(
                category="stt",
                usage_ceiling=SttUsageUnits(category="stt", audio_millis=route.max_input_units),
                primary_accounting_basis="provider_reported_exact",
                missing_evidence_policy="freeze_unknown_overage",
            )
        if route.purpose == "cloud_tts":
            return BudgetAccountingContext(
                category="tts",
                usage_ceiling=TtsUsageUnits(category="tts", characters=route.max_input_units),
                primary_accounting_basis="request_bound_exact",
                missing_evidence_policy="freeze_unknown_overage",
            )
        return BudgetAccountingContext(
            category="llm",
            usage_ceiling=LlmUsageUnits(category="llm", input_tokens=1, output_tokens=1),
            primary_accounting_basis="provider_reported_exact",
            missing_evidence_policy="freeze_unknown_overage",
        )

    async def settle(self, request: BudgetSettlementRequest) -> BudgetSettlement:
        pair = (request.reservation_id, request.attempt_id)
        self.terminal_pairs.add(pair)
        conservative = request.attempt_id not in self._exact_usage
        if conservative and request.reservation_id not in self.conservative_settlements:
            self.conservative_settlements.append(request.reservation_id)
        return BudgetSettlement(
            reservation_id=request.reservation_id,
            charged_micros_sgd=1,
            conservative_estimate_used=conservative,
            estimate_overrun=False,
            cloud_egress_frozen=False,
        )

    async def release_unsent(
        self,
        reservation_id: UUID,
        attempt_id: UUID,
        proof: TransportProof,
    ) -> None:
        pair = (reservation_id, attempt_id)
        if pair in self._sent or proof.disposition != "never_sent":
            raise PermissionError("reservation_not_releasable")
        self.released_pairs.add(pair)
        self.terminal_pairs.add(pair)

    async def reconcile_turn(
        self,
        request: BudgetReconciliationRequest,
    ) -> tuple[BudgetSettlement, ...]:
        return ()

    def record_exact_usage(self, attempt_id: UUID) -> None:
        self._exact_usage.add(attempt_id)


class RecordingRouteAuthorizer:
    def __init__(self, clock: Any) -> None:
        self.clock = clock
        self.attempt_ids: list[UUID] = []

    async def authorize(self, request: RouteAuthorizationRequest) -> RouteAuthorization:
        self.attempt_ids.append(request.attempt_id)
        return RouteAuthorization(
            authorization_id=UUID(int=len(self.attempt_ids) + 20_001),
            request_id=request.request_id,
            attempt_id=request.attempt_id,
            purpose=request.purpose,
            household_id=request.household_id,
            subject_id=request.subject_id,
            session_id=request.session_id,
            turn_id=request.turn_id,
            provider=request.provider,
            model=request.model,
            request_commitment=request.request_commitment,
            max_input_bytes=request.max_input_bytes,
            max_input_units=request.max_input_units,
            privacy_receipt_id=request.privacy_receipt_id,
            consent_receipt_ids=request.consent_receipt_ids,
            budget_reservation_id=request.budget_reservation_id,
            maximum_sensitivity=request.maximum_sensitivity,
            expires_at=self.clock.now() + timedelta(seconds=30),
        )

    async def consume(
        self,
        authorization_id: UUID,
        consumption: RouteConsumption,
    ) -> None:
        del authorization_id, consumption


class RecordingTurnAttempts:
    def __init__(self, budget: RecordingBudget) -> None:
        self.budget = budget
        self.tracked: list[tuple[UUID, UUID, UUID]] = []
        self.completed: list[tuple[UUID, UUID, UUID]] = []

    def track_reservation(
        self,
        turn_id: UUID,
        reservation_id: UUID,
        attempt_id: UUID,
    ) -> None:
        item = (turn_id, reservation_id, attempt_id)
        if item in self.tracked:
            raise RuntimeError("duplicate tracked reservation")
        self.tracked.append(item)

    def complete_reservation(
        self,
        turn_id: UUID,
        reservation_id: UUID,
        attempt_id: UUID,
    ) -> None:
        item = (turn_id, reservation_id, attempt_id)
        if item not in self.tracked:
            raise RuntimeError("unknown tracked reservation")
        if item not in self.completed:
            self.completed.append(item)

    def all_completions_after_budget_commit(self, budget: RecordingBudget) -> bool:
        return all(
            (reservation_id, attempt_id) in budget.terminal_pairs
            for _, reservation_id, attempt_id in self.completed
        )
