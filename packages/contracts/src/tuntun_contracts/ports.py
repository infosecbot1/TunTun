# packages/contracts/src/tuntun_contracts/ports.py
from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Literal, Protocol, TypeVar, runtime_checkable
from uuid import UUID

from pydantic import AwareDatetime

from .actions import ActionBinding, ActionReceipt, ValidatedActionProposal
from .audit import AuditDraft, AuditReceipt
from .base import ContractModel
from .budget import (
    BudgetAccountingContext,
    BudgetReconciliationRequest,
    BudgetReservation,
    BudgetReservationRequest,
    BudgetSettlement,
    BudgetSettlementRequest,
    TransportProof,
)
from .identity import IdentityDecision, IdentityRequest
from .memory import (
    ApprovedMemory,
    DecideMemoryProposal,
    MemoryProposal,
    MemoryProposalDraft,
    MemoryQuery,
    MemoryRecord,
    ProposalContext,
)
from .policy import (
    AuthContext,
    AuthenticationChallenge,
    AuthenticationRequest,
    AuthenticationResponse,
    AuthGrant,
    PolicyDecision,
    PolicyRequest,
)
from .provider import (
    ProviderResponse,
    RouteAuthorization,
    RouteAuthorizationRequest,
    RouteConsumption,
    SanitizedProviderRequest,
)
from .reachy import (
    ReachyCommand,
    ReachyHealth,
    ReachyReceipt,
    SafetyReceipt,
    StopSignal,
)
from .speech import (
    AudioFormat,
    AuthorizedSynthesisRequest,
    AuthorizedTranscriptionRequest,
    SpeechChunk,
    TranscriptResult,
)


class TurnInput(ContractModel):
    turn_id: UUID
    household_id: UUID
    device_id: UUID


class TurnOutput(ContractModel):
    turn_id: UUID
    outcome: Literal["completed", "cancelled", "denied", "failed"]


@runtime_checkable
class ClockPort(Protocol):
    def now(self) -> AwareDatetime: ...

    def monotonic(self) -> float: ...


@runtime_checkable
class ReachyPort(Protocol):
    async def send(self, command: ReachyCommand) -> ReachyReceipt: ...

    async def health(self) -> ReachyHealth: ...

    async def stop_all(self, turn_id: UUID | None) -> SafetyReceipt: ...


@runtime_checkable
class StopInputPort(Protocol):
    async def receive(self) -> StopSignal: ...


@runtime_checkable
class AudioConverterPort(Protocol):
    def convert(
        self,
        audio: AsyncIterator[bytes],
        source: AudioFormat,
        target: AudioFormat,
    ) -> AsyncIterator[bytes]: ...


@runtime_checkable
class SpeechToTextPort(Protocol):
    async def transcribe(
        self,
        request: AuthorizedTranscriptionRequest,
        audio: AsyncIterator[bytes],
    ) -> TranscriptResult: ...


@runtime_checkable
class TextToSpeechPort(Protocol):
    def synthesize(
        self,
        request: AuthorizedSynthesisRequest,
    ) -> AsyncIterator[SpeechChunk]: ...


@runtime_checkable
class LanguageModelPort(Protocol):
    async def complete(self, request: SanitizedProviderRequest) -> ProviderResponse: ...


@runtime_checkable
class IdentityFusionPort(Protocol):
    async def resolve(self, request: IdentityRequest) -> IdentityDecision: ...


@runtime_checkable
class MemoryRepositoryPort(Protocol):
    async def create(
        self,
        memory: ApprovedMemory,
        expected_absent: bool = True,
    ) -> MemoryRecord: ...

    async def replace(
        self,
        memory_id: UUID,
        expected_version: int,
        memory: ApprovedMemory,
    ) -> MemoryRecord: ...

    async def delete(
        self,
        memory_id: UUID,
        expected_version: int,
        auth: AuthContext,
        approved_proposal_id: UUID,
    ) -> None: ...

    async def query(self, query: MemoryQuery) -> tuple[MemoryRecord, ...]: ...


@runtime_checkable
class MemoryProposalServicePort(Protocol):
    async def stage(
        self,
        draft: MemoryProposalDraft,
        context: ProposalContext,
    ) -> MemoryProposal: ...

    async def decide(
        self,
        command: DecideMemoryProposal,
        auth: AuthContext,
    ) -> MemoryProposal: ...


@runtime_checkable
class PolicyEnginePort(Protocol):
    async def decide(self, request: PolicyRequest) -> PolicyDecision: ...


@runtime_checkable
class AuthenticationPort(Protocol):
    async def start(self, request: AuthenticationRequest) -> AuthenticationChallenge: ...

    async def verify(self, response: AuthenticationResponse) -> AuthGrant: ...

    async def consume(self, grant_id: UUID, binding: ActionBinding) -> AuthContext: ...


@runtime_checkable
class ActionProviderPort(Protocol):
    async def execute(
        self,
        proposal: ValidatedActionProposal,
        auth: AuthContext,
    ) -> ActionReceipt: ...


@runtime_checkable
class AsyncTransactionBoundary(Protocol):
    async def commit(self) -> None: ...

    async def rollback(self) -> None: ...


_AuditBoundaryT_contra = TypeVar(
    "_AuditBoundaryT_contra",
    bound=AsyncTransactionBoundary,
    contravariant=True,
)


@runtime_checkable
class AuditPort(Protocol[_AuditBoundaryT_contra]):
    async def append(
        self,
        uow: _AuditBoundaryT_contra,
        draft: AuditDraft,
    ) -> AuditReceipt: ...


@runtime_checkable
class BudgetPort(Protocol):
    async def reserve(self, request: BudgetReservationRequest) -> BudgetReservation: ...

    async def mark_sent(self, reservation_id: UUID, attempt_id: UUID) -> None: ...

    async def require_accounting_context(
        self,
        route: RouteAuthorization,
        consumption: RouteConsumption,
    ) -> BudgetAccountingContext: ...

    async def settle(self, request: BudgetSettlementRequest) -> BudgetSettlement: ...

    async def release_unsent(
        self,
        reservation_id: UUID,
        attempt_id: UUID,
        proof: TransportProof,
    ) -> None: ...

    async def reconcile_turn(
        self,
        request: BudgetReconciliationRequest,
    ) -> tuple[BudgetSettlement, ...]: ...


@runtime_checkable
class RouteAuthorizerPort(Protocol):
    async def authorize(self, request: RouteAuthorizationRequest) -> RouteAuthorization: ...

    async def consume(
        self,
        authorization_id: UUID,
        consumption: RouteConsumption,
    ) -> None: ...


@runtime_checkable
class ConversationWorkflow(Protocol):
    async def run(self, turn: TurnInput) -> TurnOutput: ...
