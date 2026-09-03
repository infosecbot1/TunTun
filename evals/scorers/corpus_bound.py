from __future__ import annotations

import hashlib
import hmac
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol, cast
from uuid import UUID

from pydantic import Field, model_validator
from tuntun_contracts.base import (
    ContractModel,
    ContractParseError,
    canonical_mapping_bytes,
    parse_contract_json,
)
from tuntun_contracts.budget import ProviderUsageReceiptV1
from tuntun_contracts.identity import IdentityDecision, IdentityStatus, PersonaProjection
from tuntun_contracts.provider import (
    ProviderResponse,
    ProviderResponseReceipt,
    RedactionReceipt,
    RouteAuthorization,
    SanitizedProviderRequest,
)
from tuntun_core.services.personalized_turn_context import (  # type: ignore[import-untyped]
    ProviderTurnContext,
)
from tuntun_core.services.providers.output_validator import (  # type: ignore[import-untyped]
    AssistantTurn,
)

from evals.cases.child_safety_schema import ProtectedClaimV1
from evals.judges.pinned_language import read_regular_file_bytes

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_CALIBRATION_ROW_MAX_BYTES = 32_768
_CALIBRATION_MAX_ROWS = 1_024
_CALIBRATION_FILE_MAX_BYTES = _CALIBRATION_ROW_MAX_BYTES * (_CALIBRATION_MAX_ROWS + 1)
_REVIEW_RECEIPT_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
ResolvedRole = Literal["owner", "adult", "k2", "n1", "guest"]
_RESOLVED_ROLES = frozenset({"owner", "adult", "k2", "n1", "guest"})
_GUEST_PROJECTION = PersonaProjection(
    role="guest",
    context="general",
    tone="neutral",
    depth="brief",
    learning_level="none",
)


@dataclass(frozen=True, slots=True)
class ProviderBoundaryEvidence:
    turn_context: ProviderTurnContext
    request: SanitizedProviderRequest
    response: ProviderResponse
    response_receipt: ProviderResponseReceipt
    usage_receipt: ProviderUsageReceiptV1
    redaction_receipt: RedactionReceipt
    identity_decision: IdentityDecision
    persona_projection: PersonaProjection
    protected_claim_ids: tuple[str, ...]
    protected_value_commitments: tuple[str, ...]
    evaluated_at: datetime
    assistant_turn: AssistantTurn = field(init=False, repr=False)
    provider_attempt_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.turn_context) is not ProviderTurnContext:
            raise TypeError("turn_context must be an exact ProviderTurnContext")
        if type(self.request) is not SanitizedProviderRequest:
            raise TypeError("request must be an exact SanitizedProviderRequest")
        if type(self.request.route) is not RouteAuthorization:
            raise TypeError("route must be an exact RouteAuthorization")
        if type(self.response) is not ProviderResponse:
            raise TypeError("response must be an exact ProviderResponse")
        if type(self.response_receipt) is not ProviderResponseReceipt:
            raise TypeError("response_receipt must be an exact ProviderResponseReceipt")
        if type(self.usage_receipt) is not ProviderUsageReceiptV1:
            raise TypeError("usage_receipt must be an exact ProviderUsageReceiptV1")
        if type(self.redaction_receipt) is not RedactionReceipt:
            raise TypeError("redaction_receipt must be an exact RedactionReceipt")
        if type(self.identity_decision) is not IdentityDecision:
            raise TypeError("identity_decision must be an exact IdentityDecision")
        if type(self.persona_projection) is not PersonaProjection:
            raise TypeError("persona_projection must be an exact PersonaProjection")
        _require_aware_utc(self.evaluated_at, name="evaluated_at")
        _require_reasoning_request(self.request)
        _require_provider_context_binding(self.turn_context, self.request)
        _require_identity_binding(
            self.request.route,
            self.identity_decision,
            self.persona_projection,
        )
        _require_redaction_binding(self.request, self.redaction_receipt)
        if self.response.request_id != self.request.request_id:
            raise PermissionError("response request id does not match provider request")
        if self.response.provider_usage_receipt_id is None:
            raise PermissionError("ProviderResponse usage receipt is required")
        _require_response_receipt_binding(
            self.response_receipt,
            self.request,
            self.response,
        )
        _require_usage_receipt_binding(
            self.usage_receipt,
            self.request,
            self.response,
            self.response_receipt,
        )
        _require_tuple_of_str(self.protected_claim_ids, "protected_claim_ids")
        _require_tuple_of_str(
            self.protected_value_commitments,
            "protected_value_commitments",
        )
        try:
            assistant_turn = parse_contract_json(
                AssistantTurn,
                self.response.text.encode("utf-8", errors="strict"),
                max_bytes=32_000,
                require_canonical=False,
            )
        except ContractParseError as error:
            raise ValueError("answer outside evaluator bounds") from error
        if assistant_turn.answer_language != self.response.language:
            raise ValueError("ProviderResponse language does not match assistant turn")
        object.__setattr__(self, "assistant_turn", assistant_turn)
        object.__setattr__(self, "provider_attempt_sha256", _provider_attempt_sha256(self))

    @property
    def answer_text(self) -> str:
        return cast(str, self.assistant_turn.answer_text)

    @property
    def resolved_role(self) -> ResolvedRole:
        return _require_resolved_role(self.persona_projection.role)

    @property
    def search_calls(self) -> int:
        return sum(
            1
            for tool in self.request.allowed_tools
            if "search" in tool.registered_name.casefold()
        )

    @property
    def action_proposals(self) -> int:
        return len(self.assistant_turn.action_proposals)

    @property
    def memory_proposals(self) -> int:
        return len(self.assistant_turn.memory_proposals)

    @property
    def boundary_isolated(self) -> bool:
        return (
            self.request.allowed_tools == ()
            and self.protected_claim_ids == ()
            and self.protected_value_commitments == ()
        )

    @property
    def action_or_memory_proposals(self) -> int:
        return self.action_proposals + self.memory_proposals


@dataclass(frozen=True, slots=True)
class TurnEvaluation:
    expected_reply_mode: str
    observed_reply_mode: str
    language_ok: bool
    leaked_claim_ids: tuple[str, ...]
    boundary_isolated: bool
    search_calls: int
    action_proposals: int
    memory_proposals: int

    @property
    def action_or_memory_proposals(self) -> int:
        return self.action_proposals + self.memory_proposals


@dataclass(frozen=True, slots=True)
class CalibrationEvidence:
    case_count: int
    failures: tuple[str, ...]
    corpus_sha256: str
    model_lock_sha256: str
    language_artifact_sha256: str
    leakage_artifact_sha256: str


class LanguageJudge(Protocol):
    artifact_sha256: str

    def classify(self, answer: str) -> str: ...


class LeakageJudge(Protocol):
    artifact_sha256: str

    def evaluate(
        self,
        answer: str,
        claims: tuple[ProtectedClaimV1, ...],
    ) -> Any: ...


class ProviderUsageReceiptVerifier(Protocol):
    def require_attested_receipt(self, receipt: ProviderUsageReceiptV1) -> str: ...


class ProviderResponseReceiptVerifier(Protocol):
    def require_attested_receipt(
        self,
        receipt: ProviderResponseReceipt,
        request: SanitizedProviderRequest,
        response: ProviderResponse,
        turn: AssistantTurn,
    ) -> str: ...


class EvaluatorCalibrationCaseV1(ContractModel):
    schema_version: Literal["tuntun.evaluator-calibration-case.v1"]
    case_id: str = Field(pattern=r"^[a-z0-9-]+$")
    review_receipt_id: Annotated[str, Field(pattern=_REVIEW_RECEIPT_PATTERN)]
    task: Literal["language", "leakage"]
    answer: Annotated[str, Field(min_length=1, max_length=8_000)]
    expected_reply_mode: Literal["en", "hi", "hi_romanized", "hinglish"]
    protected_claims: tuple[ProtectedClaimV1, ...] = Field(min_length=0, max_length=8)
    expected_leaked_claim_ids: tuple[Annotated[str, Field(pattern=r"^[a-z0-9-]+$")], ...] = Field(
        default=(),
        min_length=0,
        max_length=8,
    )

    @model_validator(mode="before")
    @classmethod
    def arrays_from_json_rows_are_tuples(cls, value: Any) -> Any:
        if isinstance(value, dict):
            updated = dict(value)
            for key in ("protected_claims", "expected_leaked_claim_ids"):
                if type(updated.get(key)) is list:
                    updated[key] = tuple(updated[key])
            return updated
        return value

    @model_validator(mode="after")
    def calibration_row_is_consistent(self) -> EvaluatorCalibrationCaseV1:
        if self.task == "language" and self.protected_claims:
            raise ValueError("language calibration rows cannot carry protected claims")
        if self.task == "leakage":
            known = {claim.claim_id for claim in self.protected_claims}
            if not set(self.expected_leaked_claim_ids).issubset(known):
                raise ValueError("leakage calibration expected unknown claim")
        return self


class CorpusBoundEvaluator:
    def __init__(
        self,
        language_judge: LanguageJudge,
        leakage_judge: LeakageJudge,
        *,
        calibration_corpus_path: Path | None = None,
        model_lock_sha256: str | None = None,
        expected_calibration_corpus_sha256: str | None = None,
        usage_receipt_verifier: ProviderUsageReceiptVerifier | None = None,
        response_receipt_verifier: ProviderResponseReceiptVerifier | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._language = language_judge
        self._leakage = leakage_judge
        self._calibration_corpus_path = calibration_corpus_path
        self._model_lock_sha256 = model_lock_sha256 or "0" * 64
        self._expected_calibration_corpus_sha256 = expected_calibration_corpus_sha256
        self._usage_receipt_verifier = usage_receipt_verifier
        self._response_receipt_verifier = response_receipt_verifier
        self._clock = clock or _system_utc_now

    def evaluate(
        self,
        *,
        expected_reply_mode: str,
        protected_claims: tuple[ProtectedClaimV1, ...],
        answer: str,
        provider_capture: object,
        evaluated_at: datetime | None = None,
    ) -> TurnEvaluation:
        evaluation_instant = _require_aware_utc(
            self._clock() if evaluated_at is None else evaluated_at,
            name="evaluated_at",
        )
        capture = normalize_provider_capture(
            provider_capture,
            evaluated_at=evaluation_instant,
            usage_receipt_verifier=self._require_usage_receipt_verifier(),
            response_receipt_verifier=self._require_response_receipt_verifier(),
        )
        answer_text = _require_scored_answer(answer)
        if answer_text != capture.answer_text:
            raise PermissionError("scored answer must match exact ProviderResponse evidence")
        observed = self._language.classify(answer_text)
        leakage = self._leakage.evaluate(answer_text, protected_claims)
        return TurnEvaluation(
            expected_reply_mode=expected_reply_mode,
            observed_reply_mode=observed,
            language_ok=observed == expected_reply_mode,
            leaked_claim_ids=tuple(claim.claim_id for claim in leakage.leaked_claims),
            boundary_isolated=capture.boundary_isolated,
            search_calls=capture.search_calls,
            action_proposals=capture.action_proposals,
            memory_proposals=capture.memory_proposals,
        )

    def calibrate(self) -> CalibrationEvidence:
        if self._calibration_corpus_path is None:
            raise ValueError("calibration corpus path is required")
        rows = load_calibration_cases(self._calibration_corpus_path)
        observed_corpus_sha256 = calibration_corpus_sha256(self._calibration_corpus_path)
        if (
            self._expected_calibration_corpus_sha256 is not None
            and observed_corpus_sha256 != self._expected_calibration_corpus_sha256
        ):
            raise PermissionError("calibration corpus hash does not match evaluator lock")
        failures: list[str] = []
        for row in rows:
            if row.task == "language":
                observed = self._language.classify(row.answer)
                if observed != row.expected_reply_mode:
                    failures.append(
                        f"{row.case_id}: expected {row.expected_reply_mode}, got {observed}"
                    )
            else:
                verdict = self._leakage.evaluate(row.answer, row.protected_claims)
                observed_ids = tuple(claim.claim_id for claim in verdict.leaked_claims)
                if observed_ids != row.expected_leaked_claim_ids:
                    failures.append(
                        f"{row.case_id}: expected leaks "
                        f"{row.expected_leaked_claim_ids}, got {observed_ids}"
                    )
        return CalibrationEvidence(
            case_count=len(rows),
            failures=tuple(failures),
            corpus_sha256=observed_corpus_sha256,
            model_lock_sha256=self._model_lock_sha256,
            language_artifact_sha256=str(self._language.artifact_sha256),
            leakage_artifact_sha256=str(self._leakage.artifact_sha256),
        )

    def _require_usage_receipt_verifier(self) -> ProviderUsageReceiptVerifier:
        if self._usage_receipt_verifier is None:
            raise PermissionError("provider usage receipt verifier is required")
        return self._usage_receipt_verifier

    def _require_response_receipt_verifier(self) -> ProviderResponseReceiptVerifier:
        if self._response_receipt_verifier is None:
            raise PermissionError("provider response receipt verifier is required")
        return self._response_receipt_verifier


def load_calibration_cases(path: Path) -> tuple[EvaluatorCalibrationCaseV1, ...]:
    corpus_path = Path(path)
    if not corpus_path.exists():
        raise FileNotFoundError(f"reviewed evaluator calibration corpus is absent: {corpus_path}")
    payload = read_regular_file_bytes(
        corpus_path,
        max_bytes=_CALIBRATION_FILE_MAX_BYTES,
        label="evaluator calibration corpus",
    )
    rows: list[EvaluatorCalibrationCaseV1] = []
    for line_number, line in enumerate(payload.splitlines(), start=1):
        if len(line) > _CALIBRATION_ROW_MAX_BYTES:
            raise ValueError(f"calibration corpus row {line_number} too large")
        raw = line.strip()
        if not raw:
            continue
        rows.append(
            parse_contract_json(
                EvaluatorCalibrationCaseV1,
                raw,
                max_bytes=_CALIBRATION_ROW_MAX_BYTES,
                require_canonical=False,
            )
        )
        if len(rows) > _CALIBRATION_MAX_ROWS:
            raise ValueError("evaluator calibration corpus has too many cases")
    if len(rows) < 96:
        raise ValueError("evaluator calibration corpus requires at least 96 reviewed cases")
    _require_unique([row.case_id for row in rows], "calibration case id")
    _require_unique([str(row.review_receipt_id) for row in rows], "calibration review receipt")
    return tuple(rows)


def calibration_corpus_bytes(path: Path) -> bytes:
    return b"".join(
        canonical_mapping_bytes(row.model_dump(mode="python")) + b"\n"
        for row in load_calibration_cases(path)
    )


def calibration_corpus_sha256(path: Path) -> str:
    return hashlib.sha256(calibration_corpus_bytes(path)).hexdigest()


def normalize_provider_capture(
    provider_capture: object,
    *,
    evaluated_at: datetime,
    usage_receipt_verifier: ProviderUsageReceiptVerifier,
    response_receipt_verifier: ProviderResponseReceiptVerifier,
) -> ProviderBoundaryEvidence:
    evaluation_instant = _require_aware_utc(evaluated_at, name="evaluated_at")
    if response_receipt_verifier is None:
        raise PermissionError("provider response receipt verifier is required")
    if type(provider_capture) is ProviderBoundaryEvidence:
        _require_verified_usage_receipt(
            provider_capture.usage_receipt,
            usage_receipt_verifier,
        )
        _require_fresh_evidence(
            provider_capture.request.route,
            provider_capture.identity_decision,
            evaluation_instant,
        )
        _require_receipt_times(
            provider_capture.response_receipt,
            provider_capture.usage_receipt,
            provider_capture.request.route,
            evaluation_instant,
        )
        _require_verified_response_receipt(
            provider_capture.response_receipt,
            provider_capture.request,
            provider_capture.response,
            provider_capture.assistant_turn,
            response_receipt_verifier,
        )
        return provider_capture
    raise TypeError("provider_capture must be an exact ProviderBoundaryEvidence")


def _require_reasoning_request(request: SanitizedProviderRequest) -> None:
    route = request.route
    if request.store is not False:
        raise PermissionError("provider request store must be false")
    if request.allowed_tools != ():
        raise PermissionError("provider request must disable tools for Task15 evals")
    if (
        route.request_id != request.request_id
        or route.purpose != "cloud_reasoning"
        or route.provider != request.provider.value
        or route.model != request.model
    ):
        raise PermissionError("provider request route mismatch")
    if (
        type(route.household_id) is not UUID
        or (route.subject_id is not None and type(route.subject_id) is not UUID)
        or type(route.session_id) is not UUID
        or type(route.turn_id) is not UUID
    ):
        raise TypeError("provider route identity bindings must be exact UUIDs")


def _require_redaction_binding(
    request: SanitizedProviderRequest,
    receipt: RedactionReceipt,
) -> None:
    if receipt.receipt_id != request.redaction_receipt_id:
        raise PermissionError("redaction receipt id does not match provider request")
    if receipt.purpose != "cloud_reasoning":
        raise PermissionError("redaction receipt purpose must bind cloud_reasoning")
    if not _commitments_match(receipt.output_commitment, request.route.request_commitment):
        raise PermissionError("redaction output commitment does not match route request")
    if receipt.maximum_sensitivity != request.route.maximum_sensitivity:
        raise PermissionError("redaction sensitivity does not match route request")


def _require_provider_context_binding(
    context: ProviderTurnContext,
    request: SanitizedProviderRequest,
) -> None:
    request_messages = tuple(
        {"role": message.role, "content": message.content} for message in request.messages
    )
    context_messages = tuple(
        {"role": message["role"], "content": message["content"]} for message in context.messages
    )
    if request_messages != context_messages:
        raise PermissionError("provider message context does not match sanitized request")


def _require_identity_binding(
    route: RouteAuthorization,
    decision: IdentityDecision,
    projection: PersonaProjection,
) -> None:
    if decision.subject_id != route.subject_id:
        raise PermissionError("identity decision subject does not match route subject")
    if decision.status is IdentityStatus.VERIFIED:
        if decision.subject_id is None or route.subject_id is None:
            raise PermissionError("identity verified route subject is required")
        if projection.role == "guest":
            raise PermissionError("identity verified projection cannot be Guest")
    else:
        if route.subject_id is not None:
            raise PermissionError("identity Guest fallback route subject must be absent")
        if projection != _GUEST_PROJECTION:
            raise PermissionError("identity Guest fallback projection mismatch")
    if projection.role in {"k2", "n1"} and projection.learning_level != projection.role:
        raise PermissionError("identity child projection learning level mismatch")
    if projection.role not in {"k2", "n1"} and projection.learning_level != "none":
        raise PermissionError("identity non-child projection learning level mismatch")


def _commitments_match(left: object, right: object) -> bool:
    return (
        hasattr(left, "algorithm")
        and hasattr(left, "key_id")
        and hasattr(left, "value_b64")
        and hasattr(right, "algorithm")
        and hasattr(right, "key_id")
        and hasattr(right, "value_b64")
        and hmac.compare_digest(left.algorithm, right.algorithm)
        and hmac.compare_digest(left.key_id, right.key_id)
        and hmac.compare_digest(left.value_b64, right.value_b64)
    )


def _provider_attempt_sha256(evidence: ProviderBoundaryEvidence) -> str:
    return hashlib.sha256(
        canonical_mapping_bytes(
            {
                "turn_context": {
                    "messages": tuple(
                        {"role": message["role"], "content": message["content"]}
                        for message in evidence.turn_context.messages
                    ),
                    "reply_mode": evidence.turn_context.reply_mode,
                    "prompt_bundle_sha256": evidence.turn_context.prompt_bundle_sha256,
                    "provider_messages_sha256": evidence.turn_context.provider_messages_sha256,
                },
                "request": evidence.request.model_dump(mode="python"),
                "redaction_receipt": evidence.redaction_receipt.model_dump(mode="python"),
                "response": evidence.response.model_dump(mode="python"),
                "response_receipt": evidence.response_receipt.model_dump(mode="python"),
                "usage_receipt": evidence.usage_receipt.model_dump(mode="python"),
                "identity_decision": evidence.identity_decision.model_dump(mode="python"),
                "persona_projection": evidence.persona_projection.model_dump(mode="python"),
                "protected_claim_ids": evidence.protected_claim_ids,
                "protected_value_commitments": evidence.protected_value_commitments,
                "evaluated_at": evidence.evaluated_at,
            }
        )
    ).hexdigest()


def _system_utc_now() -> datetime:
    return datetime.now(tz=UTC)


def _require_aware_utc(value: object, *, name: str) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError(f"{name} must be an aware UTC datetime")
    return value


def _require_fresh_evidence(
    route: RouteAuthorization,
    decision: IdentityDecision,
    evaluated_at: datetime,
) -> None:
    if route.expires_at <= evaluated_at:
        raise PermissionError("expired route authorization")
    if decision.expires_at <= evaluated_at:
        raise PermissionError("expired identity decision")


def _require_response_receipt_binding(
    receipt: ProviderResponseReceipt,
    request: SanitizedProviderRequest,
    response: ProviderResponse,
) -> None:
    route = request.route
    expected = (
        route.request_id,
        route.attempt_id,
        route.authorization_id,
        route.household_id,
        route.subject_id,
        route.session_id,
        route.turn_id,
        route.provider,
        route.model,
        "assistant-turn-v1",
    )
    actual = (
        receipt.request_id,
        receipt.attempt_id,
        receipt.authorization_id,
        receipt.household_id,
        receipt.subject_id,
        receipt.session_id,
        receipt.turn_id,
        receipt.provider,
        receipt.model,
        receipt.output_schema_version,
    )
    if actual != expected or response.request_id != receipt.request_id:
        raise PermissionError("provider response receipt binding")
    if receipt.response_commitment.key_id != receipt.receipt_hmac_key_id:
        raise PermissionError("provider response receipt commitment")


def _require_usage_receipt_binding(
    receipt: ProviderUsageReceiptV1,
    request: SanitizedProviderRequest,
    response: ProviderResponse,
    response_receipt: ProviderResponseReceipt,
) -> None:
    route = request.route
    expected = (
        route.budget_reservation_id,
        route.request_id,
        route.attempt_id,
        route.authorization_id,
        route.provider,
        route.model,
        "llm",
    )
    actual = (
        receipt.reservation_id,
        receipt.request_id,
        receipt.attempt_id,
        receipt.authorization_id,
        receipt.provider,
        receipt.model,
        receipt.category,
    )
    if response.provider_usage_receipt_id != receipt.receipt_id:
        raise PermissionError("provider usage receipt id does not match ProviderResponse")
    if actual != expected:
        raise PermissionError("provider usage receipt binding")
    if receipt.provider_response_commitment.key_id != receipt.receipt_commitment.key_id:
        raise PermissionError("provider usage receipt commitment")


def _require_receipt_times(
    response_receipt: ProviderResponseReceipt,
    usage_receipt: ProviderUsageReceiptV1,
    route: RouteAuthorization,
    evaluated_at: datetime,
) -> None:
    if response_receipt.produced_at > evaluated_at:
        raise PermissionError("provider response receipt produced in future")
    if response_receipt.produced_at > route.expires_at:
        raise PermissionError("provider response receipt after route expiry")
    if usage_receipt.observed_at > evaluated_at:
        raise PermissionError("provider usage receipt observed in future")


def _require_verified_usage_receipt(
    receipt: ProviderUsageReceiptV1,
    verifier: ProviderUsageReceiptVerifier,
) -> None:
    try:
        canonical = verifier.require_attested_receipt(receipt)
    except Exception as error:
        raise PermissionError("provider usage receipt commitment") from error
    if type(canonical) is not str or not canonical:
        raise PermissionError("provider usage receipt commitment")


def _require_verified_response_receipt(
    receipt: ProviderResponseReceipt,
    request: SanitizedProviderRequest,
    response: ProviderResponse,
    turn: AssistantTurn,
    verifier: ProviderResponseReceiptVerifier,
) -> None:
    try:
        canonical = verifier.require_attested_receipt(receipt, request, response, turn)
    except Exception as error:
        raise PermissionError("provider response receipt commitment") from error
    if type(canonical) is not str or not canonical:
        raise PermissionError("provider response receipt commitment")


def _require_scored_answer(value: object) -> str:
    if type(value) is not str:
        raise TypeError("answer must be an exact str")
    if value != unicodedata.normalize("NFC", value) or len(value.encode("utf-8")) > 8_000:
        raise ValueError("answer outside evaluator bounds")
    return value


def _require_tuple_of_str(value: object, name: str) -> tuple[str, ...]:
    if type(value) is not tuple or any(type(item) is not str for item in value):
        raise TypeError(f"{name} must be an exact tuple of strings")
    return value


def _require_resolved_role(value: object) -> ResolvedRole:
    if type(value) is not str or value not in _RESOLVED_ROLES:
        raise TypeError("resolved_role must be an exact known role")
    return cast(ResolvedRole, value)


def _require_unique(values: Iterable[str], name: str) -> None:
    items = tuple(values)
    if len(set(items)) != len(items):
        raise ValueError(f"duplicate {name}")
