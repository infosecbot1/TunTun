from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Literal, Protocol, cast
from uuid import UUID, uuid4

from evals.cases.bilingual_schema import BilingualPersonaCaseV1, ReplyMode
from evals.cases.child_safety_schema import ProtectedClaimV1
from evals.scorers.corpus_bound import (
    ProviderBoundaryEvidence,
    ProviderResponseReceiptVerifier,
    ProviderUsageReceiptVerifier,
    ResolvedRole,
    TurnEvaluation,
    normalize_provider_capture,
)
from evals.scorers.relevance import is_relevant

IdentityEvidence = Literal["synthetic_verified", "synthetic_ambiguous"]
SttLanguage = Literal["en", "hi", "hinglish"]


class CandidateExecutor(Protocol):
    prompt_bundle_sha256: str

    async def execute_turn(self, turn: BilingualCandidateTurn) -> CandidateTurnExecution: ...


@dataclass(frozen=True, slots=True)
class BilingualCandidateTurn:
    session_id: UUID
    turn_id: UUID
    request_id: UUID
    user_text: str
    stt_language: SttLanguage
    identity_evidence: IdentityEvidence
    prior_reply_mode: ReplyMode | None

    def __post_init__(self) -> None:
        if type(self.session_id) is not UUID:
            raise TypeError("session_id must be an exact UUID")
        if type(self.turn_id) is not UUID:
            raise TypeError("turn_id must be an exact UUID")
        if type(self.request_id) is not UUID:
            raise TypeError("request_id must be an exact UUID")
        if type(self.user_text) is not str or not self.user_text:
            raise ValueError("user_text is required")
        if self.stt_language not in {"en", "hi", "hinglish"}:
            raise ValueError("stt_language invalid")
        if self.identity_evidence not in {"synthetic_verified", "synthetic_ambiguous"}:
            raise ValueError("identity_evidence invalid")
        if self.prior_reply_mode is not None and self.prior_reply_mode not in {
            "en",
            "hi",
            "hi_romanized",
            "hinglish",
        }:
            raise ValueError("prior_reply_mode invalid")


@dataclass(frozen=True, slots=True)
class CandidateTurnExecution:
    prompt_bundle_sha256: str
    provider_messages_sha256: str
    boundary_evidence: ProviderBoundaryEvidence

    def __post_init__(self) -> None:
        _require_sha256(self.prompt_bundle_sha256, name="prompt_bundle_sha256")
        _require_sha256(self.provider_messages_sha256, name="provider_messages_sha256")
        if type(self.boundary_evidence) is not ProviderBoundaryEvidence:
            raise TypeError("boundary_evidence must be an exact ProviderBoundaryEvidence")


class TurnEvaluator(Protocol):
    async def evaluate(
        self,
        *,
        expected_reply_mode: str,
        protected_claims: tuple[ProtectedClaimV1, ...],
        answer: str,
        provider_capture: object,
    ) -> TurnEvaluation: ...


@dataclass(frozen=True, slots=True)
class CaseExecutionResult:
    case_id: str
    resolved_role: str
    expected_role: str
    executed_prompt_bundle_sha256: str
    rows: tuple[dict[str, object], ...]

    @property
    def observed_reply_modes(self) -> tuple[object, ...]:
        return tuple(row["observed_reply_mode"] for row in self.rows)


class BilingualPersonaRunner:
    def __init__(
        self,
        *,
        candidate_executor: CandidateExecutor,
        evaluator: TurnEvaluator,
        usage_receipt_verifier: ProviderUsageReceiptVerifier,
        response_receipt_verifier: ProviderResponseReceiptVerifier,
        expected_provider: Literal["openai", "qwen"],
        expected_model: str,
        uuid_factory: Callable[[], UUID] = uuid4,
        clock: Callable[[], datetime] = lambda: datetime.now(tz=UTC),
    ) -> None:
        _require_sha256(candidate_executor.prompt_bundle_sha256, name="prompt_bundle_sha256")
        if response_receipt_verifier is None:
            raise PermissionError("provider response receipt verifier is required")
        self._candidate = candidate_executor
        self._evaluator = evaluator
        self._usage_receipt_verifier = usage_receipt_verifier
        self._response_receipt_verifier = response_receipt_verifier
        self._expected_provider = _require_expected_provider(expected_provider)
        self._expected_model = _require_expected_model(expected_model)
        self._uuid_factory = uuid_factory
        self._clock = clock
        self._issued_session_ids: set[UUID] = set()
        self._issued_turn_ids: set[UUID] = set()
        self._issued_request_ids: set[UUID] = set()
        self.prompt_bundle_sha256 = candidate_executor.prompt_bundle_sha256
        self.provider_requests = 0

    async def run_case(self, case: BilingualPersonaCaseV1) -> CaseExecutionResult:
        if type(case) is not BilingualPersonaCaseV1:
            raise TypeError("case must be an exact BilingualPersonaCaseV1")
        prior: ReplyMode | None = None
        rows: list[dict[str, object]] = []
        resolved_role: ResolvedRole | None = None
        evaluated_at = _require_aware_utc_datetime(
            self._clock(),
            name="evaluation clock",
        )
        session_id = self._issue_uuid(self._issued_session_ids, "session_id")
        for turn in case.turns:
            issued_turn_id = self._issue_uuid(self._issued_turn_ids, "turn_id")
            issued_request_id = self._issue_uuid(self._issued_request_ids, "request_id")
            candidate_turn = BilingualCandidateTurn(
                session_id=session_id,
                turn_id=issued_turn_id,
                request_id=issued_request_id,
                user_text=turn.user_text,
                stt_language=turn.stt_language,
                identity_evidence=case.identity_evidence,
                prior_reply_mode=prior,
            )
            execution = await self._candidate.execute_turn(candidate_turn)
            if type(execution) is not CandidateTurnExecution:
                raise TypeError("candidate executor must return an exact CandidateTurnExecution")
            if execution.prompt_bundle_sha256 != self.prompt_bundle_sha256:
                raise ValueError("candidate prompt bundle changed within eval run")
            self.provider_requests += 1
            capture = await normalize_provider_capture(
                execution.boundary_evidence,
                evaluated_at=evaluated_at,
                usage_receipt_verifier=self._usage_receipt_verifier,
                response_receipt_verifier=self._response_receipt_verifier,
            )
            _require_expected_provider_model(
                capture,
                expected_provider=self._expected_provider,
                expected_model=self._expected_model,
            )
            self._require_issued_handles(
                capture,
                session_id=session_id,
                turn_id=issued_turn_id,
                request_id=issued_request_id,
            )
            if execution.provider_messages_sha256 != capture.turn_context.provider_messages_sha256:
                raise PermissionError("provider message hash does not match turn context")
            if capture.turn_context.prompt_bundle_sha256 != execution.prompt_bundle_sha256:
                raise PermissionError("provider message prompt bundle does not match execution")
            answer = capture.answer_text
            _require_word_cap(answer, turn.expected.maximum_words)
            turn_resolved_role = _require_authorized_identity(capture)
            if resolved_role is None:
                resolved_role = turn_resolved_role
            elif resolved_role != turn_resolved_role:
                raise ValueError("candidate resolved identity changed within eval case")
            evaluation = await self._evaluator.evaluate(
                expected_reply_mode=turn.expected.reply_mode,
                protected_claims=(),
                answer=answer,
                provider_capture=capture,
            )
            rows.append(
                {
                    "case_id": case.case_id,
                    "turn_id": turn.turn_id,
                    "expected_reply_mode": turn.expected.reply_mode,
                    "observed_reply_mode": evaluation.observed_reply_mode,
                    "language_ok": evaluation.language_ok,
                    "boundary_isolated": evaluation.boundary_isolated,
                    "relevance_ok": is_relevant(answer, turn.expected.topic_terms_any),
                    "synthetic_answer": answer,
                    "answer_sha256": sha256(answer.encode("utf-8")).hexdigest(),
                    "provider_attempt_sha256": capture.provider_attempt_sha256,
                    "provider_request_id": str(capture.request.request_id),
                    "provider_subject_id": (
                        None
                        if capture.request.route.subject_id is None
                        else str(capture.request.route.subject_id)
                    ),
                    "provider_session_id": str(capture.request.route.session_id),
                    "provider_turn_id": str(capture.request.route.turn_id),
                }
            )
            prior = cast(ReplyMode, evaluation.observed_reply_mode)
        return CaseExecutionResult(
            case_id=case.case_id,
            resolved_role=_require_final_resolved_role(resolved_role),
            expected_role=case.expected_resolved_role,
            executed_prompt_bundle_sha256=self.prompt_bundle_sha256,
            rows=tuple(rows),
        )

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


def _require_authorized_identity(capture: ProviderBoundaryEvidence) -> ResolvedRole:
    return capture.resolved_role


def _require_final_resolved_role(value: ResolvedRole | None) -> ResolvedRole:
    if value is None:
        raise PermissionError("authorized candidate identity evidence is required")
    return value


def _require_sha256(value: object, *, name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{name} must be a SHA-256 hex digest")
    return value


def _require_word_cap(answer: str, maximum_words: int) -> None:
    if type(maximum_words) is not int:
        raise TypeError("maximum_words must be an exact int")
    if len(answer.split()) > maximum_words:
        raise ValueError("answer exceeds word cap")


def _require_expected_provider(value: object) -> Literal["openai", "qwen"]:
    if type(value) is not str or value not in {"openai", "qwen"}:
        raise ValueError("expected_provider must be openai or qwen")
    return cast(Literal["openai", "qwen"], value)


def _require_expected_model(value: object) -> str:
    if type(value) is not str or not 1 <= len(value) <= 128:
        raise ValueError("expected_model must be a bounded provider model")
    return value


def _require_expected_provider_model(
    capture: ProviderBoundaryEvidence,
    *,
    expected_provider: Literal["openai", "qwen"],
    expected_model: str,
) -> None:
    providers = (
        capture.request.provider.value,
        capture.request.route.provider,
        capture.response_receipt.provider,
        capture.usage_receipt.provider,
    )
    if providers != (expected_provider,) * len(providers):
        raise PermissionError("provider evidence does not match expected provider")
    models = (
        capture.request.model,
        capture.request.route.model,
        capture.response_receipt.model,
        capture.usage_receipt.model,
    )
    if models != (expected_model,) * len(models):
        raise PermissionError("provider evidence does not match expected model")


def _require_aware_utc_datetime(value: object, *, name: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{name} must be an aware UTC datetime")
    return value
