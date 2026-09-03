from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol
from uuid import UUID, uuid4

from evals.cases.child_safety_schema import ChildSafetyCaseV1, ProtectedClaimV1
from evals.run_bilingual_personas import CandidateTurnExecution
from evals.scorers.corpus_bound import (
    ProviderBoundaryEvidence,
    ProviderResponseReceiptVerifier,
    ProviderUsageReceiptVerifier,
    TurnEvaluation,
    normalize_provider_capture,
)

ChildInputMode = Literal["en", "hi", "hinglish"]


class ChildCandidate(Protocol):
    prompt_bundle_sha256: str

    async def execute_child_turn(self, turn: ChildCandidateTurn) -> CandidateTurnExecution: ...


@dataclass(frozen=True, slots=True)
class ChildCandidateTurn:
    session_id: UUID
    turn_id: UUID
    request_id: UUID
    user_text: str
    input_mode: ChildInputMode

    def __post_init__(self) -> None:
        if type(self.session_id) is not UUID:
            raise TypeError("session_id must be an exact UUID")
        if type(self.turn_id) is not UUID:
            raise TypeError("turn_id must be an exact UUID")
        if type(self.request_id) is not UUID:
            raise TypeError("request_id must be an exact UUID")
        if type(self.user_text) is not str or not self.user_text:
            raise ValueError("user_text is required")
        if self.input_mode not in {"en", "hi", "hinglish"}:
            raise ValueError("input_mode invalid")


class ChildTurnEvaluator(Protocol):
    def evaluate(
        self,
        *,
        expected_reply_mode: str,
        protected_claims: tuple[ProtectedClaimV1, ...],
        answer: str,
        provider_capture: object,
        evaluated_at: datetime | None = None,
    ) -> TurnEvaluation: ...


@dataclass(frozen=True, slots=True)
class ChildCaseResult:
    provider_capture: ProviderBoundaryEvidence
    evaluation: TurnEvaluation


class ChildSafetyRunner:
    def __init__(
        self,
        candidate: ChildCandidate,
        evaluator: ChildTurnEvaluator,
        usage_receipt_verifier: ProviderUsageReceiptVerifier,
        response_receipt_verifier: ProviderResponseReceiptVerifier,
        *,
        uuid_factory: Callable[[], UUID] = uuid4,
        clock: Callable[[], datetime] = lambda: datetime.now(tz=UTC),
    ) -> None:
        _require_sha256(candidate.prompt_bundle_sha256, name="prompt_bundle_sha256")
        if response_receipt_verifier is None:
            raise PermissionError("provider response receipt verifier is required")
        self._candidate = candidate
        self._evaluator = evaluator
        self._usage_receipt_verifier = usage_receipt_verifier
        self._response_receipt_verifier = response_receipt_verifier
        self._uuid_factory = uuid_factory
        self._clock = clock
        self._issued_session_ids: set[UUID] = set()
        self._issued_turn_ids: set[UUID] = set()
        self._issued_request_ids: set[UUID] = set()
        self.prompt_bundle_sha256 = candidate.prompt_bundle_sha256

    async def run_case(self, case: ChildSafetyCaseV1) -> ChildCaseResult:
        if type(case) is not ChildSafetyCaseV1:
            raise TypeError("case must be an exact ChildSafetyCaseV1")
        evaluated_at = _require_aware_utc_datetime(
            self._clock(),
            name="evaluation clock",
        )
        session_id = self._issue_uuid(self._issued_session_ids, "session_id")
        turn_id = self._issue_uuid(self._issued_turn_ids, "turn_id")
        request_id = self._issue_uuid(self._issued_request_ids, "request_id")
        turn = ChildCandidateTurn(
            session_id=session_id,
            turn_id=turn_id,
            request_id=request_id,
            user_text=case.user_text,
            input_mode=case.input_mode,
        )
        execution = await self._candidate.execute_child_turn(turn)
        if type(execution) is not CandidateTurnExecution:
            raise TypeError("child candidate must return an exact CandidateTurnExecution")
        if execution.prompt_bundle_sha256 != self.prompt_bundle_sha256:
            raise ValueError("candidate prompt bundle changed within eval run")
        capture = normalize_provider_capture(
            execution.boundary_evidence,
            evaluated_at=evaluated_at,
            usage_receipt_verifier=self._usage_receipt_verifier,
            response_receipt_verifier=self._response_receipt_verifier,
        )
        self._require_issued_handles(
            capture,
            session_id=session_id,
            turn_id=turn_id,
            request_id=request_id,
        )
        if execution.provider_messages_sha256 != capture.turn_context.provider_messages_sha256:
            raise PermissionError("provider message hash does not match turn context")
        if capture.turn_context.prompt_bundle_sha256 != execution.prompt_bundle_sha256:
            raise PermissionError("provider message prompt bundle does not match execution")
        answer = capture.answer_text
        evaluation = self._evaluator.evaluate(
            expected_reply_mode={"en": "en", "hi": "hi", "hinglish": "hinglish"}[case.input_mode],
            protected_claims=case.protected_claims,
            answer=answer,
            provider_capture=capture,
            evaluated_at=evaluated_at,
        )
        return ChildCaseResult(provider_capture=capture, evaluation=evaluation)

    def _issue_uuid(self, issued: set[UUID], name: str) -> UUID:
        value = self._uuid_factory()
        if type(value) is not UUID:
            raise TypeError(f"{name} factory must return an exact UUID")
        if value in issued:
            raise PermissionError(f"issued opaque {name} was reused")
        issued.add(value)
        return value

    def _require_issued_handles(
        self,
        capture: ProviderBoundaryEvidence,
        *,
        session_id: UUID,
        turn_id: UUID,
        request_id: UUID,
    ) -> None:
        route = capture.request.route
        if (
            route.session_id != session_id
            or route.turn_id != turn_id
            or route.request_id != request_id
            or capture.request.request_id != request_id
            or capture.response.request_id != request_id
        ):
            raise PermissionError("candidate route did not use issued opaque handles")


def _require_sha256(value: object, *, name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{name} must be a SHA-256 hex digest")
    return value


def _require_aware_utc_datetime(value: object, *, name: str) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError(f"{name} must be an aware UTC datetime")
    return value
