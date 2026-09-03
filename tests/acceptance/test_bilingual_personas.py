from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import fields
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal, cast
from uuid import UUID

import pytest
from pydantic import ValidationError
from tuntun_contracts.base import (
    Commitment,
    Sensitivity,
    canonical_bytes,
    canonical_mapping_bytes,
)
from tuntun_contracts.budget import LlmUsageUnits, ProviderUsageReceiptV1
from tuntun_contracts.commitments import commit_private
from tuntun_contracts.identity import IdentityDecision, IdentityStatus, PersonaProjection
from tuntun_contracts.provider import (
    ProviderName,
    ProviderResponse,
    ProviderResponseReceipt,
    RedactionReceipt,
    RouteAuthorization,
    SanitizedProviderMessage,
    SanitizedProviderRequest,
)
from tuntun_core.services.personalized_turn_context import (  # type: ignore[import-untyped]
    ProviderTurnContext,
    provider_messages_sha256,
)
from tuntun_core.services.providers.output_validator import (  # type: ignore[import-untyped]
    AssistantTurn,
)
from tuntun_core.services.providers.response_receipts import VerifiedProviderResponseReceipt

from evals.cases.bilingual_schema import BilingualPersonaCaseV1
from evals.cases.build_bilingual_family import CorpusProvisioningError, build_cases
from evals.judges.pinned_language import PinnedLanguageJudge
from evals.run_bilingual_personas import (
    BilingualCandidateTurn,
    BilingualPersonaRunner,
    CandidateTurnExecution,
)
from evals.scorers.corpus_bound import (
    CorpusBoundEvaluator,
    ProviderBoundaryEvidence,
    ResolvedRole,
    normalize_provider_capture,
)

_EVALUATED_AT = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
_EXPECTED_PROVIDER = "openai"
_EXPECTED_MODEL = "fixture-model"


def test_corpus_is_balanced_closed_and_covers_four_classes(tmp_path: Path) -> None:
    corpus_path = tmp_path / "bilingual-family.jsonl"
    _write_jsonl(corpus_path, _bilingual_rows())

    cases = build_cases(corpus_path)

    assert len(cases) == 280
    family = [case for case in cases if case.persona.role != "guest"]
    guest = [case for case in cases if case.persona.role == "guest"]
    assert len(family) == 240
    assert len(guest) == 40
    assert {turn.expected.input_class for case in family for turn in case.turns} == {
        "english",
        "hindi_devanagari",
        "hindi_romanized",
        "mixed",
    }
    assert all(len(case.turns) >= 2 for case in cases)


def test_default_bilingual_corpus_is_no_go_when_not_locally_provisioned() -> None:
    default_corpus = Path("evals/cases/bilingual-family.jsonl")
    if default_corpus.exists():
        pytest.skip("default reviewed corpus is provisioned in this checkout")

    with pytest.raises(CorpusProvisioningError, match="reviewed bilingual corpus"):
        build_cases()


def test_bilingual_corpus_loader_rejects_symlink_path(tmp_path: Path) -> None:
    corpus_path = tmp_path / "bilingual-family.jsonl"
    _write_jsonl(corpus_path, _bilingual_rows())
    symlink_path = tmp_path / "linked-bilingual-family.jsonl"
    symlink_path.symlink_to(corpus_path)

    with pytest.raises(PermissionError, match="unsafe|symlink"):
        build_cases(symlink_path)


def test_label_only_or_open_expected_rows_are_rejected() -> None:
    with pytest.raises(ValidationError):
        BilingualPersonaCaseV1.model_validate(
            {
                "schema_version": "tuntun.bilingual-persona-case.v1",
                "id": "label-only",
                "role": "n1",
                "language": "hi",
                "topic": "rain",
            }
        )


@pytest.mark.asyncio
async def test_runner_executes_candidate_prompts_and_switches_per_turn() -> None:
    switching_case = BilingualPersonaCaseV1.model_validate(_switching_case_row())
    evaluator = CorpusBoundEvaluator(
        PinnedLanguageJudge(
            _FixtureLanguageModel(),
            threshold_micros=900_000,
            artifact_sha256="a" * 64,
        ),
        _NoLeakageJudge(),
        usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
        response_receipt_verifier=_FixtureResponseReceiptVerifier(),
        clock=lambda: _EVALUATED_AT,
    )
    runner = BilingualPersonaRunner(
        candidate_executor=_ProductionPathExecutor(),
        evaluator=evaluator,
        usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
        response_receipt_verifier=_FixtureResponseReceiptVerifier(),
        expected_provider=_EXPECTED_PROVIDER,
        expected_model=_EXPECTED_MODEL,
        clock=lambda: _EVALUATED_AT,
    )

    result = await runner.run_case(switching_case)

    assert result.executed_prompt_bundle_sha256 == runner.prompt_bundle_sha256
    assert result.observed_reply_modes == tuple(
        turn.expected.reply_mode for turn in switching_case.turns
    )
    assert runner.provider_requests == len(switching_case.turns)


@pytest.mark.asyncio
async def test_runner_uses_authorized_candidate_identity_not_corpus_label() -> None:
    switching_case = BilingualPersonaCaseV1.model_validate(_switching_case_row())
    evaluator = CorpusBoundEvaluator(
        PinnedLanguageJudge(
            _FixtureLanguageModel(),
            threshold_micros=900_000,
            artifact_sha256="a" * 64,
        ),
        _NoLeakageJudge(),
        usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
        response_receipt_verifier=_FixtureResponseReceiptVerifier(),
        clock=lambda: _EVALUATED_AT,
    )
    runner = BilingualPersonaRunner(
        candidate_executor=_ProductionPathExecutor(resolved_role="guest"),
        evaluator=evaluator,
        usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
        response_receipt_verifier=_FixtureResponseReceiptVerifier(),
        expected_provider=_EXPECTED_PROVIDER,
        expected_model=_EXPECTED_MODEL,
        clock=lambda: _EVALUATED_AT,
    )

    result = await runner.run_case(switching_case)

    assert result.resolved_role == "guest"
    assert result.expected_role == "adult"


@pytest.mark.asyncio
async def test_runner_rejects_raw_provider_adapter_and_forged_boundary_booleans() -> None:
    switching_case = BilingualPersonaCaseV1.model_validate(_switching_case_row())
    runner = BilingualPersonaRunner(
        candidate_executor=cast(Any, _RawProviderAdapter()),
        evaluator=CorpusBoundEvaluator(
            PinnedLanguageJudge(
                _FixtureLanguageModel(),
                threshold_micros=900_000,
                artifact_sha256="a" * 64,
            ),
            _NoLeakageJudge(),
            usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
            response_receipt_verifier=_FixtureResponseReceiptVerifier(),
            clock=lambda: _EVALUATED_AT,
        ),
        usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
        response_receipt_verifier=_FixtureResponseReceiptVerifier(),
        expected_provider=_EXPECTED_PROVIDER,
        expected_model=_EXPECTED_MODEL,
        clock=lambda: _EVALUATED_AT,
    )

    with pytest.raises(TypeError, match="CandidateTurnExecution"):
        await runner.run_case(switching_case)


@pytest.mark.asyncio
async def test_runner_candidate_input_excludes_corpus_persona_and_expected_labels() -> None:
    switching_case = BilingualPersonaCaseV1.model_validate(_switching_case_row())
    executor = _ProductionPathExecutor()
    runner = BilingualPersonaRunner(
        candidate_executor=executor,
        evaluator=CorpusBoundEvaluator(
            PinnedLanguageJudge(
                _FixtureLanguageModel(),
                threshold_micros=900_000,
                artifact_sha256="a" * 64,
            ),
            _NoLeakageJudge(),
            usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
            response_receipt_verifier=_FixtureResponseReceiptVerifier(),
            clock=lambda: _EVALUATED_AT,
        ),
        usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
        response_receipt_verifier=_FixtureResponseReceiptVerifier(),
        expected_provider=_EXPECTED_PROVIDER,
        expected_model=_EXPECTED_MODEL,
        clock=lambda: _EVALUATED_AT,
    )

    await runner.run_case(switching_case)

    assert executor.seen_turns
    corpus_turn_ids = {turn.turn_id for turn in switching_case.turns}
    assert all(type(turn) is BilingualCandidateTurn for turn in executor.seen_turns)
    assert all(type(turn.session_id) is UUID for turn in executor.seen_turns)
    assert all(type(turn.turn_id) is UUID for turn in executor.seen_turns)
    assert all(type(turn.request_id) is UUID for turn in executor.seen_turns)
    assert all(not hasattr(turn, "persona") for turn in executor.seen_turns)
    assert all(not hasattr(turn, "expected_role") for turn in executor.seen_turns)
    assert all(not hasattr(turn, "expected_reply_mode") for turn in executor.seen_turns)
    assert all(not hasattr(turn, "case_id") for turn in executor.seen_turns)
    assert all(str(turn.turn_id) not in corpus_turn_ids for turn in executor.seen_turns)


@pytest.mark.asyncio
async def test_runner_binds_candidate_route_to_issued_opaque_handles() -> None:
    switching_case = BilingualPersonaCaseV1.model_validate(_switching_case_row())
    evaluator = CorpusBoundEvaluator(
        PinnedLanguageJudge(
            _FixtureLanguageModel(),
            threshold_micros=900_000,
            artifact_sha256="a" * 64,
        ),
        _NoLeakageJudge(),
        usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
        response_receipt_verifier=_FixtureResponseReceiptVerifier(),
        clock=lambda: _EVALUATED_AT,
    )

    for mutation in ("foreign_request_id", "route_session_id", "route_turn_id"):
        runner = BilingualPersonaRunner(
            candidate_executor=_ProductionPathExecutor(mutation=mutation),
            evaluator=evaluator,
            usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
            response_receipt_verifier=_FixtureResponseReceiptVerifier(),
            expected_provider=_EXPECTED_PROVIDER,
            expected_model=_EXPECTED_MODEL,
            clock=lambda: _EVALUATED_AT,
        )

        with pytest.raises(PermissionError, match="issued opaque"):
            await runner.run_case(switching_case)


@pytest.mark.asyncio
async def test_runner_rejects_provider_message_hash_or_request_message_substitution() -> None:
    switching_case = BilingualPersonaCaseV1.model_validate(_switching_case_row())
    evaluator = CorpusBoundEvaluator(
        PinnedLanguageJudge(
            _FixtureLanguageModel(),
            threshold_micros=900_000,
            artifact_sha256="a" * 64,
        ),
        _NoLeakageJudge(),
        usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
        response_receipt_verifier=_FixtureResponseReceiptVerifier(),
        clock=lambda: _EVALUATED_AT,
    )
    with pytest.raises(PermissionError, match="provider message"):
        await BilingualPersonaRunner(
            candidate_executor=_ProductionPathExecutor(mutation="provider_messages_hash"),
            evaluator=evaluator,
            usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
            response_receipt_verifier=_FixtureResponseReceiptVerifier(),
            expected_provider=_EXPECTED_PROVIDER,
            expected_model=_EXPECTED_MODEL,
            clock=lambda: _EVALUATED_AT,
        ).run_case(switching_case)
    with pytest.raises(PermissionError, match="provider message"):
        await BilingualPersonaRunner(
            candidate_executor=_ProductionPathExecutor(mutation="request_messages"),
            evaluator=evaluator,
            usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
            response_receipt_verifier=_FixtureResponseReceiptVerifier(),
            expected_provider=_EXPECTED_PROVIDER,
            expected_model=_EXPECTED_MODEL,
            clock=lambda: _EVALUATED_AT,
        ).run_case(switching_case)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("self_consistent_provider", "expected provider"),
        ("self_consistent_model", "expected model"),
    ),
)
async def test_runner_rejects_self_consistent_provider_or_model_substitution_before_scoring(
    mutation: str,
    message: str,
) -> None:
    switching_case = BilingualPersonaCaseV1.model_validate(_switching_case_row())
    language = _CountingLanguageJudge()
    evaluator = CorpusBoundEvaluator(
        language,
        _NoLeakageJudge(),
        usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
        response_receipt_verifier=_FixtureResponseReceiptVerifier(),
        clock=lambda: _EVALUATED_AT,
    )
    runner = BilingualPersonaRunner(
        candidate_executor=_ProductionPathExecutor(mutation=mutation),
        evaluator=evaluator,
        usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
        response_receipt_verifier=_FixtureResponseReceiptVerifier(),
        expected_provider=_EXPECTED_PROVIDER,
        expected_model=_EXPECTED_MODEL,
        clock=lambda: _EVALUATED_AT,
    )

    with pytest.raises(PermissionError, match=message):
        await runner.run_case(switching_case)

    assert language.called == 0


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("response_request_id", "response request"),
        ("redaction_receipt_id", "redaction"),
        ("store", "store"),
        ("purpose", "route"),
        ("provider", "route"),
        ("model", "route"),
        ("redaction_output_commitment", "redaction"),
        ("redaction_sensitivity", "redaction"),
        ("identity_subject", "identity"),
        ("persona_projection", "identity"),
        ("guest_projection", "identity"),
    ),
)
def test_provider_boundary_evidence_validates_exact_production_bindings(
    mutation: str,
    message: str,
) -> None:
    with pytest.raises((PermissionError, ValueError), match=message):
        _provider_evidence(
            "Rain forms from water in clouds.",
            "en",
            mutation=mutation,
        )


def test_redaction_receipt_commitment_binding_uses_constant_time_compare(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    compared: list[tuple[str, str]] = []

    def compare_digest(left: str, right: str) -> bool:
        compared.append((left, right))
        return left == right

    monkeypatch.setattr("evals.scorers.corpus_bound.hmac.compare_digest", compare_digest)

    _provider_evidence("Rain forms from water in clouds.", "en")

    assert (_commitment().value_b64, _commitment().value_b64) in compared


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("route_expired", "expired route authorization"),
        ("identity_expired", "expired identity decision"),
    ),
)
@pytest.mark.asyncio
async def test_provider_boundary_evidence_rejects_expired_authorization_or_identity(
    mutation: str,
    message: str,
) -> None:
    evidence = _provider_evidence(
        "Rain forms from water in clouds.",
        "en",
        mutation=mutation,
    )

    with pytest.raises(PermissionError, match=message):
        await normalize_provider_capture(
            evidence,
            evaluated_at=_EVALUATED_AT,
            usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
            response_receipt_verifier=_FixtureResponseReceiptVerifier(),
        )


def test_provider_boundary_evidence_exposes_exact_response_and_usage_receipts() -> None:
    evidence = _provider_evidence("Rain forms from water in clouds.", "en")

    assert type(getattr(evidence, "response_receipt", None)) is ProviderResponseReceipt
    assert type(getattr(evidence, "usage_receipt", None)) is ProviderUsageReceiptV1


def test_provider_boundary_evidence_no_longer_accepts_public_verified_wrapper_as_proof() -> None:
    field_names = {item.name for item in fields(ProviderBoundaryEvidence)}

    assert "verified_response_receipt" not in field_names
    assert "evaluated_at" not in field_names


def test_provider_boundary_evidence_digest_is_not_candidate_supplied() -> None:
    digest_field = next(
        item for item in fields(ProviderBoundaryEvidence) if item.name == "provider_attempt_sha256"
    )

    assert not digest_field.init
    assert "provider_attempt_sha256" not in ProviderBoundaryEvidence.__match_args__


def test_provider_boundary_evidence_parses_exact_production_assistant_turn() -> None:
    evidence = _provider_evidence("Rain forms from water in clouds.", "en")

    assert type(evidence.assistant_turn) is AssistantTurn


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("response_receipt_request_id", "provider response receipt"),
        ("response_receipt_attempt_id", "provider response receipt"),
        ("response_receipt_authorization_id", "provider response receipt"),
        ("response_receipt_household_id", "provider response receipt"),
        ("response_receipt_subject_id", "provider response receipt"),
        ("response_receipt_session_id", "provider response receipt"),
        ("response_receipt_turn_id", "provider response receipt"),
        ("response_receipt_provider", "provider response receipt"),
        ("response_receipt_model", "provider response receipt"),
        ("response_receipt_commitment", "provider response receipt commitment"),
        ("response_receipt_future", "provider response receipt produced in future"),
        ("usage_receipt_id", "provider usage receipt id"),
        ("usage_receipt_request_id", "provider usage receipt"),
        ("usage_receipt_attempt_id", "provider usage receipt"),
        ("usage_receipt_authorization_id", "provider usage receipt"),
        ("usage_receipt_reservation_id", "provider usage receipt"),
        ("usage_receipt_provider", "provider usage receipt"),
        ("usage_receipt_model", "provider usage receipt"),
        ("usage_receipt_category", "provider usage receipt"),
        ("usage_receipt_response_commitment", "provider usage receipt commitment"),
        ("usage_receipt_commitment", "provider usage receipt commitment"),
        ("usage_receipt_future", "provider usage receipt observed in future"),
    ),
)
@pytest.mark.asyncio
async def test_provider_boundary_evidence_rejects_unrelated_response_or_usage_receipts(
    mutation: str,
    message: str,
) -> None:
    with pytest.raises(PermissionError, match=message):
        evidence = _provider_evidence(
            "Rain forms from water in clouds.",
            "en",
            mutation=mutation,
        )
        await normalize_provider_capture(
            evidence,
            evaluated_at=_EVALUATED_AT,
            usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
            response_receipt_verifier=_FixtureResponseReceiptVerifier(),
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "response_receipt_hmac",
        "response_receipt_commitment_value",
        "response_text_after_receipt",
    ),
)
@pytest.mark.asyncio
async def test_response_receipt_attestation_rejects_forgery_before_judges(
    mutation: str,
) -> None:
    language = _CountingLanguageJudge()
    evaluator = CorpusBoundEvaluator(
        language,
        _NoLeakageJudge(),
        clock=lambda: _EVALUATED_AT,
        usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
        response_receipt_verifier=_FixtureResponseReceiptVerifier(),
    )
    evidence = _provider_evidence("Rain forms from water in clouds.", "en", mutation=mutation)

    with pytest.raises(PermissionError, match="provider response receipt"):
        await evaluator.evaluate(
            expected_reply_mode="en",
            protected_claims=(),
            answer=evidence.answer_text,
            provider_capture=evidence,
        )

    assert language.called == 0


@pytest.mark.asyncio
async def test_response_receipt_verifier_is_mandatory_before_judges() -> None:
    language = _CountingLanguageJudge()
    evaluator = CorpusBoundEvaluator(
        language,
        _NoLeakageJudge(),
        clock=lambda: _EVALUATED_AT,
        usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
    )
    evidence = _provider_evidence("Rain forms from water in clouds.", "en")

    with pytest.raises(PermissionError, match="provider response receipt verifier"):
        await evaluator.evaluate(
            expected_reply_mode="en",
            protected_claims=(),
            answer=evidence.answer_text,
            provider_capture=evidence,
        )

    assert language.called == 0


@pytest.mark.asyncio
async def test_failing_response_receipt_verifier_blocks_before_judges() -> None:
    language = _CountingLanguageJudge()
    evaluator = CorpusBoundEvaluator(
        language,
        _NoLeakageJudge(),
        clock=lambda: _EVALUATED_AT,
        usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
        response_receipt_verifier=_FailingResponseReceiptVerifier(),
    )
    evidence = _provider_evidence("Rain forms from water in clouds.", "en")

    with pytest.raises(PermissionError, match="provider response receipt"):
        await evaluator.evaluate(
            expected_reply_mode="en",
            protected_claims=(),
            answer=evidence.answer_text,
            provider_capture=evidence,
        )

    assert language.called == 0


@pytest.mark.asyncio
async def test_distinct_valid_response_and_usage_commitments_are_accepted() -> None:
    evidence = _provider_evidence(
        "Rain forms from water in clouds.",
        "en",
        mutation="valid_distinct_usage_response_commitment",
    )

    assert evidence.response_receipt.response_commitment != (
        evidence.usage_receipt.provider_response_commitment
    )
    assert (
        await normalize_provider_capture(
            evidence,
            evaluated_at=_EVALUATED_AT,
            usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
            response_receipt_verifier=_FixtureResponseReceiptVerifier(),
        )
        is evidence
    )
    assert len(evidence.provider_attempt_sha256) == 64


@pytest.mark.asyncio
async def test_evaluator_has_no_public_evaluated_at_escape_hatch() -> None:
    evaluator = CorpusBoundEvaluator(
        _CountingLanguageJudge(),
        _NoLeakageJudge(),
        clock=lambda: _EVALUATED_AT + timedelta(minutes=10),
        usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
        response_receipt_verifier=_FixtureResponseReceiptVerifier(),
    )
    evidence = _provider_evidence("Rain forms from water in clouds.", "en")

    with pytest.raises(TypeError, match="evaluated_at"):
        await evaluator.evaluate(
            expected_reply_mode="en",
            protected_claims=(),
            answer=evidence.answer_text,
            provider_capture=evidence,
            evaluated_at=_EVALUATED_AT,
        )


@pytest.mark.asyncio
async def test_genuine_response_receipt_and_independent_usage_commitment_are_accepted() -> None:
    language = _CountingLanguageJudge()
    evaluator = CorpusBoundEvaluator(
        language,
        _NoLeakageJudge(),
        clock=lambda: _EVALUATED_AT,
        usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
        response_receipt_verifier=_FixtureResponseReceiptVerifier(),
    )
    evidence = _provider_evidence(
        "Rain forms from water in clouds.",
        "en",
        mutation="valid_distinct_usage_response_commitment",
    )

    result = await evaluator.evaluate(
        expected_reply_mode="en",
        protected_claims=(),
        answer=evidence.answer_text,
        provider_capture=evidence,
    )

    assert result.language_ok
    assert language.called == 1
    assert evidence.response_receipt.response_commitment != (
        evidence.usage_receipt.provider_response_commitment
    )


@pytest.mark.asyncio
async def test_runner_uses_trusted_clock_not_candidate_supplied_evaluation_time() -> None:
    switching_case = BilingualPersonaCaseV1.model_validate(_switching_case_row())
    evaluator = CorpusBoundEvaluator(
        PinnedLanguageJudge(
            _FixtureLanguageModel(),
            threshold_micros=900_000,
            artifact_sha256="a" * 64,
        ),
        _NoLeakageJudge(),
        clock=lambda: _EVALUATED_AT,
        usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
        response_receipt_verifier=_FixtureResponseReceiptVerifier(),
    )
    runner = BilingualPersonaRunner(
        candidate_executor=_ProductionPathExecutor(),
        evaluator=evaluator,
        usage_receipt_verifier=_FixtureUsageReceiptVerifier(),
        response_receipt_verifier=_FixtureResponseReceiptVerifier(),
        expected_provider=_EXPECTED_PROVIDER,
        expected_model=_EXPECTED_MODEL,
        clock=lambda: _EVALUATED_AT + timedelta(minutes=10),
    )

    with pytest.raises(PermissionError, match="expired route authorization"):
        await runner.run_case(switching_case)


def _write_jsonl(path: Path, rows: Iterable[dict[str, object]]) -> None:
    path.write_bytes(b"".join(canonical_mapping_bytes(row) + b"\n" for row in rows))


def _bilingual_rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    roles = ("owner", "adult", "k2", "n1")
    classes = ("english", "hindi_devanagari", "hindi_romanized", "mixed")
    for index in range(240):
        role = roles[index % len(roles)]
        input_class = classes[index % len(classes)]
        second_class = classes[(index + 1) % len(classes)] if index < 40 else input_class
        rows.append(
            _case_row(
                case_id=f"family-{index:03d}",
                role=role,
                input_class=input_class,
                second_input_class=second_class,
                receipt_int=index + 1,
            )
        )
    for index in range(40):
        rows.append(
            _case_row(
                case_id=f"guest-{index:03d}",
                role="guest",
                input_class="english",
                second_input_class="english",
                identity_evidence="synthetic_ambiguous",
                expected_resolved_role="guest",
                receipt_int=1_000 + index,
            )
        )
    return rows


def _case_row(
    *,
    case_id: str,
    role: str,
    input_class: str,
    second_input_class: str,
    receipt_int: int,
    identity_evidence: str = "synthetic_verified",
    expected_resolved_role: str | None = None,
) -> dict[str, object]:
    return {
        "schema_version": "tuntun.bilingual-persona-case.v1",
        "case_id": case_id,
        "topic_id": "rain-cycle",
        "review_receipt_id": str(UUID(int=receipt_int)),
        "identity_evidence": identity_evidence,
        "expected_resolved_role": expected_resolved_role or role,
        "persona": _persona(role),
        "turns": (
            _turn_row(f"{case_id}-turn-1", input_class, receipt_int),
            _turn_row(f"{case_id}-turn-2", second_input_class, receipt_int + 10_000),
        ),
    }


def _persona(role: str) -> dict[str, str]:
    if role in {"k2", "n1"}:
        return {
            "role": role,
            "context": "early_learning",
            "tone": "warm",
            "depth": "brief",
            "learning_level": role,
        }
    return {
        "role": role,
        "context": "general",
        "tone": "neutral",
        "depth": "brief",
        "learning_level": "none",
    }


def _turn_row(turn_id: str, input_class: str, receipt_int: int) -> dict[str, object]:
    text_by_class = {
        "english": f"Please explain rain cycle example {receipt_int}",
        "hindi_devanagari": f"बारिश का कारण समझाओ {receipt_int}",
        "hindi_romanized": f"Baarish ka karan samjhao {receipt_int}",
        "mixed": f"Please baarish ka simple reason batao {receipt_int}",
    }
    stt_by_class = {
        "english": "en",
        "hindi_devanagari": "hi",
        "hindi_romanized": "hi",
        "mixed": "hinglish",
    }
    reply_by_class = {
        "english": "en",
        "hindi_devanagari": "hi",
        "hindi_romanized": "hi_romanized",
        "mixed": "hinglish",
    }
    return {
        "turn_id": turn_id,
        "user_text": text_by_class[input_class],
        "stt_language": stt_by_class[input_class],
        "expected": {
            "input_class": input_class,
            "reply_mode": reply_by_class[input_class],
            "topic_terms_any": ("rain", "cloud", "water"),
            "maximum_words": 80,
            "expected_policy": "adult_general",
        },
    }


def _switching_case_row() -> dict[str, object]:
    return {
        "schema_version": "tuntun.bilingual-persona-case.v1",
        "case_id": "switching-demo",
        "topic_id": "rain-cycle",
        "review_receipt_id": str(UUID(int=50_000)),
        "identity_evidence": "synthetic_verified",
        "expected_resolved_role": "adult",
        "persona": PersonaProjection(
            role="adult",
            context="general",
            tone="neutral",
            depth="brief",
            learning_level="none",
        ).model_dump(mode="json"),
        "turns": (
            _turn_row("switching-demo-turn-1", "english", 50_001),
            _turn_row("switching-demo-turn-2", "hindi_romanized", 50_002),
            _turn_row("switching-demo-turn-3", "mixed", 50_003),
        ),
    }


class _FixtureLanguageModel:
    def predict(self, spans: tuple[str, ...]) -> tuple[tuple[str, int], ...]:
        predictions: list[tuple[str, int]] = []
        for span in spans:
            lowered = span.casefold()
            if any("\u0900" <= character <= "\u097f" for character in span):
                predictions.append(("hin_Deva", 990_000))
            elif "clouds" in lowered and any(word in lowered for word in ("mein", "banti")):
                predictions.append(("eng_Latn", 990_000))
            elif any(word in lowered for word in ("mein", "banti", "badal", "paani", "aata")):
                predictions.append(("hin_Latn", 990_000))
            else:
                predictions.append(("eng_Latn", 990_000))
        return tuple(predictions)


class _NoLeakageJudge:
    artifact_sha256 = "b" * 64

    def evaluate(self, answer: str, claims: tuple[object, ...]) -> object:
        del answer, claims
        return type("Verdict", (), {"leaked_claims": ()})()


class _CountingLanguageJudge:
    artifact_sha256 = "d" * 64

    def __init__(self) -> None:
        self.called = 0

    def classify(self, answer: str) -> str:
        del answer
        self.called += 1
        return "en"


_RESPONSE_RECEIPT_ROOT = b"r" * 32
_RESPONSE_RECEIPT_KEY_ID = "fixture-v1"


class _FixtureUsageReceiptVerifier:
    def require_attested_receipt(self, receipt: ProviderUsageReceiptV1) -> str:
        if type(receipt) is not ProviderUsageReceiptV1:
            raise PermissionError("usage receipt must be exact")
        accepted_response_commitments = (_commitment(), _other_commitment())
        if (
            not any(
                receipt.provider_response_commitment == item
                for item in accepted_response_commitments
            )
            or receipt.receipt_commitment != _commitment()
        ):
            raise PermissionError("usage receipt commitment mismatch")
        return "{}"


class _FixtureResponseReceiptVerifier:
    async def require_exact(
        self,
        receipt_id: UUID,
        route: RouteAuthorization,
        turn: AssistantTurn,
        *,
        provider_usage_receipt_id: UUID | None,
    ) -> VerifiedProviderResponseReceipt:
        del provider_usage_receipt_id
        receipt = _response_receipt(route, turn)
        if receipt.receipt_id != receipt_id:
            raise PermissionError("provider response receipt binding")
        if type(receipt) is not ProviderResponseReceipt:
            raise PermissionError("response receipt must be exact")
        if type(route) is not RouteAuthorization:
            raise PermissionError("route must be exact")
        if type(turn) is not AssistantTurn:
            raise PermissionError("turn must be exact")
        unsigned = receipt.model_dump(mode="python", exclude={"receipt_hmac_b64"})
        expected_receipt_hmac = commit_private(
            _RESPONSE_RECEIPT_ROOT,
            receipt.receipt_hmac_key_id,
            "provider.response-receipt.v1",
            canonical_mapping_bytes(_jsonable(unsigned)),
        )
        response_commitment = _response_commitment(turn)
        if (
            receipt.request_id != route.request_id
            or receipt.attempt_id != route.attempt_id
            or receipt.authorization_id != route.authorization_id
            or receipt.household_id != route.household_id
            or receipt.subject_id != route.subject_id
            or receipt.session_id != route.session_id
            or receipt.turn_id != route.turn_id
            or receipt.provider != route.provider
            or receipt.model != route.model
            or receipt.response_commitment != response_commitment
            or receipt.receipt_hmac_key_id != _RESPONSE_RECEIPT_KEY_ID
            or receipt.receipt_hmac_b64 != expected_receipt_hmac.value_b64
        ):
            raise PermissionError("provider response receipt commitment")
        return VerifiedProviderResponseReceipt(receipt)


class _FailingResponseReceiptVerifier:
    async def require_exact(
        self,
        receipt_id: UUID,
        route: RouteAuthorization,
        turn: AssistantTurn,
        *,
        provider_usage_receipt_id: UUID | None,
    ) -> VerifiedProviderResponseReceipt:
        del receipt_id, route, turn, provider_usage_receipt_id
        raise PermissionError("provider response receipt rejected by fixture")


class _ProductionPathExecutor:
    prompt_bundle_sha256 = "9" * 64

    def __init__(
        self,
        *,
        resolved_role: ResolvedRole = "adult",
        mutation: str | None = None,
    ) -> None:
        self._resolved_role = resolved_role
        self._mutation = mutation
        self.seen_turns: list[BilingualCandidateTurn] = []

    async def execute_turn(self, turn: BilingualCandidateTurn) -> CandidateTurnExecution:
        self.seen_turns.append(turn)
        if "Baarish" in turn.user_text:
            answer = "Baarish mein badal se paani neeche aata hai."
            language = "hi"
        elif "baarish" in turn.user_text:
            answer = "Clouds mein water droplets banti hain."
            language = "hinglish"
        elif "बारिश" in turn.user_text:
            answer = "बारिश बादलों के पानी से होती है।"
            language = "hi"
        else:
            answer = "Rain forms from water in clouds."
            language = "en"
        evidence = _provider_evidence(
            answer,
            language,
            resolved_role=self._resolved_role,
            request_id=turn.request_id,
            session_id=turn.session_id,
            turn_id=turn.turn_id,
            mutation=self._mutation,
        )
        provider_hash = (
            "7" * 64
            if self._mutation == "provider_messages_hash"
            else evidence.turn_context.provider_messages_sha256
        )
        return CandidateTurnExecution(
            prompt_bundle_sha256=self.prompt_bundle_sha256,
            provider_messages_sha256=provider_hash,
            boundary_evidence=evidence,
        )


class _RawProviderAdapter:
    prompt_bundle_sha256 = "9" * 64

    async def execute_turn(self, turn: BilingualCandidateTurn) -> object:
        del turn
        return SimpleNamespace(
            answer="Rain forms from water in clouds.",
            authorized_provider_gateway=True,
            redaction_checked=True,
            resolved_role="adult",
        )


def _provider_evidence(
    answer: object,
    language: str,
    *,
    resolved_role: ResolvedRole = "adult",
    request_id: UUID | None = None,
    session_id: UUID | None = None,
    turn_id: UUID | None = None,
    action_proposals: int = 0,
    memory_proposals: int = 0,
    mutation: str | None = None,
) -> ProviderBoundaryEvidence:
    request_id = request_id or UUID("00000000-0000-0000-0000-000000000101")
    if mutation == "foreign_request_id":
        request_id = UUID("00000000-0000-0000-0000-000000000119")
    provider = "qwen" if mutation == "self_consistent_provider" else "openai"
    request_provider = ProviderName.QWEN if provider == "qwen" else ProviderName.OPENAI
    model = "other-model" if mutation == "self_consistent_model" else _EXPECTED_MODEL
    session_id = session_id or UUID("00000000-0000-0000-0000-000000000106")
    turn_id = turn_id or UUID("00000000-0000-0000-0000-000000000107")
    subject_id = None if resolved_role == "guest" else UUID("00000000-0000-0000-0000-000000000105")
    route_request_id = (
        UUID("00000000-0000-0000-0000-000000000113")
        if mutation == "route_request_id"
        else request_id
    )
    route_session_id = (
        UUID("00000000-0000-0000-0000-000000000114")
        if mutation == "route_session_id"
        else session_id
    )
    route_turn_id = (
        UUID("00000000-0000-0000-0000-000000000115") if mutation == "route_turn_id" else turn_id
    )
    route_expires_at = _EVALUATED_AT + timedelta(minutes=5)
    if mutation == "route_expired":
        route_expires_at = _EVALUATED_AT - timedelta(seconds=1)
    route = RouteAuthorization(
        authorization_id=UUID("00000000-0000-0000-0000-000000000102"),
        request_id=route_request_id,
        attempt_id=UUID("00000000-0000-0000-0000-000000000103"),
        purpose="cloud_reasoning",
        household_id=UUID("00000000-0000-0000-0000-000000000104"),
        subject_id=subject_id,
        session_id=route_session_id,
        turn_id=route_turn_id,
        provider=provider,
        model=model,
        request_commitment=_commitment(),
        max_input_bytes=4_096,
        max_input_units=4_096,
        privacy_receipt_id=UUID("00000000-0000-0000-0000-000000000108"),
        consent_receipt_ids=(UUID("00000000-0000-0000-0000-000000000109"),),
        budget_reservation_id=UUID("00000000-0000-0000-0000-000000000110"),
        maximum_sensitivity=Sensitivity.PUBLIC,
        expires_at=route_expires_at,
    )
    redaction_receipt_id = UUID("00000000-0000-0000-0000-000000000111")
    context = _provider_context(language)
    request = SanitizedProviderRequest(
        request_id=request_id,
        provider=request_provider,
        model=model,
        messages=_sanitized_messages(context),
        allowed_tools=(),
        max_output_tokens=512,
        store=False,
        redaction_receipt_id=redaction_receipt_id,
        route=route,
        timeout_ms=1_000,
    )
    provider_language = cast(
        Literal["en", "hi", "hinglish"],
        language if language != "hi_romanized" else "hi",
    )
    response = ProviderResponse(
        request_id=request_id,
        text=_assistant_turn_json(
            answer,
            language,
            action_proposals=action_proposals,
            memory_proposals=memory_proposals,
        ),
        language=provider_language,
        provider_usage_receipt_id=UUID("00000000-0000-0000-0000-000000000112"),
    )
    response_receipt = _response_receipt(route, _parse_assistant_turn(response.text))
    usage_receipt = _usage_receipt(
        route,
        cast(UUID, response.provider_usage_receipt_id),
    )
    redaction = RedactionReceipt(
        receipt_id=redaction_receipt_id,
        purpose="cloud_reasoning",
        input_commitment=_commitment(),
        output_commitment=_commitment(),
        removed_categories=(),
        removed_count=0,
        policy_version="fixture-v1",
        maximum_sensitivity=Sensitivity.PUBLIC,
    )
    identity_decision = _identity_decision(
        subject_id=subject_id,
        expires_at=(
            _EVALUATED_AT - timedelta(seconds=1) if mutation == "identity_expired" else None
        ),
    )
    persona_projection = PersonaProjection.model_validate(_persona(resolved_role))
    if mutation == "response_request_id":
        response = response.model_copy(
            update={"request_id": UUID("00000000-0000-0000-0000-000000000116")}
        )
    elif mutation == "redaction_receipt_id":
        redaction = redaction.model_copy(
            update={"receipt_id": UUID("00000000-0000-0000-0000-000000000117")}
        )
    elif mutation == "store":
        request = request.model_copy(update={"store": True})
    elif mutation == "purpose":
        bad_route = route.model_copy(update={"purpose": "cloud_tts"})
        request = request.model_copy(update={"route": bad_route})
    elif mutation == "provider":
        bad_route = route.model_copy(update={"provider": "qwen"})
        request = request.model_copy(update={"route": bad_route})
    elif mutation == "model":
        bad_route = route.model_copy(update={"model": "other-model"})
        request = request.model_copy(update={"route": bad_route})
    elif mutation == "request_messages":
        request = request.model_copy(
            update={
                "messages": (
                    SanitizedProviderMessage(role="system", content="Substituted prompt."),
                    SanitizedProviderMessage(role="user", content="Fixture user text."),
                )
            }
        )
    elif mutation == "redaction_output_commitment":
        redaction = redaction.model_copy(update={"output_commitment": _other_commitment()})
    elif mutation == "redaction_sensitivity":
        redaction = redaction.model_copy(update={"maximum_sensitivity": Sensitivity.SENSITIVE})
    elif mutation == "identity_subject":
        identity_decision = _identity_decision(
            subject_id=UUID("00000000-0000-0000-0000-000000000118")
        )
    elif mutation == "persona_projection":
        persona_projection = PersonaProjection.model_validate(_persona("guest"))
    elif mutation == "guest_projection":
        identity_decision = _identity_decision(subject_id=None, status=IdentityStatus.AMBIGUOUS)
        persona_projection = PersonaProjection.model_validate(_persona("adult"))
    elif mutation == "response_receipt_request_id":
        response_receipt = response_receipt.model_copy(update={"request_id": UUID(int=20_001)})
    elif mutation == "response_receipt_attempt_id":
        response_receipt = response_receipt.model_copy(update={"attempt_id": UUID(int=20_002)})
    elif mutation == "response_receipt_authorization_id":
        response_receipt = response_receipt.model_copy(
            update={"authorization_id": UUID(int=20_003)}
        )
    elif mutation == "response_receipt_household_id":
        response_receipt = response_receipt.model_copy(update={"household_id": UUID(int=20_004)})
    elif mutation == "response_receipt_subject_id":
        response_receipt = response_receipt.model_copy(update={"subject_id": UUID(int=20_005)})
    elif mutation == "response_receipt_session_id":
        response_receipt = response_receipt.model_copy(update={"session_id": UUID(int=20_006)})
    elif mutation == "response_receipt_turn_id":
        response_receipt = response_receipt.model_copy(update={"turn_id": UUID(int=20_007)})
    elif mutation == "response_receipt_provider":
        response_receipt = response_receipt.model_copy(update={"provider": "qwen"})
    elif mutation == "response_receipt_model":
        response_receipt = response_receipt.model_copy(update={"model": "other-model"})
    elif mutation == "response_receipt_commitment":
        response_receipt = response_receipt.model_copy(
            update={"response_commitment": _different_key_commitment()}
        )
    elif mutation == "response_receipt_commitment_value":
        response_receipt = response_receipt.model_copy(
            update={"response_commitment": _other_commitment()}
        )
    elif mutation == "response_receipt_hmac":
        response_receipt = response_receipt.model_copy(
            update={"receipt_hmac_b64": _other_commitment().value_b64}
        )
    elif mutation == "response_text_after_receipt":
        response = response.model_copy(
            update={
                "text": _assistant_turn_json(
                    "This answer was swapped after receipt creation.",
                    language,
                    action_proposals=action_proposals,
                    memory_proposals=memory_proposals,
                )
            }
        )
    elif mutation == "response_receipt_future":
        response_receipt = response_receipt.model_copy(
            update={"produced_at": _EVALUATED_AT + timedelta(seconds=1)}
        )
    elif mutation == "usage_receipt_id":
        usage_receipt = usage_receipt.model_copy(update={"receipt_id": UUID(int=30_001)})
    elif mutation == "usage_receipt_request_id":
        usage_receipt = usage_receipt.model_copy(update={"request_id": UUID(int=30_002)})
    elif mutation == "usage_receipt_attempt_id":
        usage_receipt = usage_receipt.model_copy(update={"attempt_id": UUID(int=30_003)})
    elif mutation == "usage_receipt_authorization_id":
        usage_receipt = usage_receipt.model_copy(update={"authorization_id": UUID(int=30_004)})
    elif mutation == "usage_receipt_reservation_id":
        usage_receipt = usage_receipt.model_copy(update={"reservation_id": UUID(int=30_005)})
    elif mutation == "usage_receipt_provider":
        usage_receipt = usage_receipt.model_copy(update={"provider": "qwen"})
    elif mutation == "usage_receipt_model":
        usage_receipt = usage_receipt.model_copy(update={"model": "other-model"})
    elif mutation == "usage_receipt_category":
        usage_receipt = usage_receipt.model_copy(update={"category": "stt"})
    elif mutation == "usage_receipt_response_commitment":
        usage_receipt = usage_receipt.model_copy(
            update={"provider_response_commitment": _different_key_commitment()}
        )
    elif mutation == "valid_distinct_usage_response_commitment":
        usage_receipt = usage_receipt.model_copy(
            update={"provider_response_commitment": _other_commitment()}
        )
    elif mutation == "usage_receipt_commitment":
        usage_receipt = usage_receipt.model_copy(
            update={"receipt_commitment": _different_key_commitment()}
        )
    elif mutation == "usage_receipt_future":
        usage_receipt = usage_receipt.model_copy(
            update={"observed_at": _EVALUATED_AT + timedelta(seconds=1)}
        )
    return ProviderBoundaryEvidence(
        turn_context=context,
        request=request,
        response=response,
        response_receipt=response_receipt,
        usage_receipt=usage_receipt,
        redaction_receipt=redaction,
        identity_decision=identity_decision,
        persona_projection=persona_projection,
        protected_claim_ids=(),
        protected_value_commitments=(),
    )


def _response_receipt(route: RouteAuthorization, turn: AssistantTurn) -> ProviderResponseReceipt:
    response_commitment = _response_commitment(turn)
    receipt = ProviderResponseReceipt(
        receipt_id=UUID("00000000-0000-0000-0000-000000000121"),
        request_id=route.request_id,
        attempt_id=route.attempt_id,
        authorization_id=route.authorization_id,
        household_id=route.household_id,
        subject_id=route.subject_id,
        session_id=route.session_id,
        turn_id=route.turn_id,
        provider=route.provider,
        model=route.model,
        output_schema_version="assistant-turn-v1",
        response_commitment=response_commitment,
        receipt_hmac_key_id=_RESPONSE_RECEIPT_KEY_ID,
        receipt_hmac_b64=_commitment().value_b64,
        produced_at=_EVALUATED_AT - timedelta(seconds=1),
    )
    unsigned = receipt.model_dump(mode="python", exclude={"receipt_hmac_b64"})
    signature = commit_private(
        _RESPONSE_RECEIPT_ROOT,
        _RESPONSE_RECEIPT_KEY_ID,
        "provider.response-receipt.v1",
        canonical_mapping_bytes(_jsonable(unsigned)),
    )
    return receipt.model_copy(update={"receipt_hmac_b64": signature.value_b64})


def _usage_receipt(
    route: RouteAuthorization,
    provider_usage_receipt_id: UUID,
) -> ProviderUsageReceiptV1:
    return ProviderUsageReceiptV1(
        schema_version="tuntun.provider-usage-receipt.v1",
        receipt_id=provider_usage_receipt_id,
        provider_call_id=UUID("00000000-0000-0000-0000-000000000122"),
        reservation_id=route.budget_reservation_id,
        request_id=route.request_id,
        attempt_id=route.attempt_id,
        authorization_id=route.authorization_id,
        provider=route.provider,
        model=route.model,
        category="llm",
        accounting_basis="provider_reported_exact",
        billable_usage=LlmUsageUnits(category="llm", input_tokens=1, output_tokens=1),
        provider_response_commitment=_commitment(),
        observed_at=_EVALUATED_AT - timedelta(seconds=2),
        receipt_commitment=_commitment(),
    )


def _provider_context(language: str) -> ProviderTurnContext:
    reply_mode = cast(Literal["en", "hi", "hi_romanized", "hinglish"], language)
    messages = (
        {"role": "system", "content": "Fixture prompt."},
        {"role": "user", "content": "Fixture user text."},
    )
    return ProviderTurnContext(
        messages=messages,
        reply_mode=reply_mode,
        prompt_bundle_sha256="9" * 64,
        provider_messages_sha256=provider_messages_sha256(messages),
    )


def _sanitized_messages(
    context: ProviderTurnContext,
) -> tuple[SanitizedProviderMessage, ...]:
    return tuple(
        SanitizedProviderMessage(
            role=cast(Literal["system", "user"], message["role"]),
            content=message["content"],
        )
        for message in context.messages
    )


def _identity_decision(
    *,
    subject_id: UUID | None,
    status: IdentityStatus | None = None,
    expires_at: datetime | None = None,
) -> IdentityDecision:
    decision_status = (
        status
        if status is not None
        else IdentityStatus.AMBIGUOUS
        if subject_id is None
        else IdentityStatus.VERIFIED
    )
    return IdentityDecision(
        status=decision_status,
        subject_id=subject_id,
        reason_code="fixture",
        expires_at=expires_at or _EVALUATED_AT + timedelta(minutes=5),
    )


def _assistant_turn_json(
    answer: object,
    language: str,
    *,
    action_proposals: int,
    memory_proposals: int,
) -> str:
    provider_language = language if language != "hi_romanized" else "hi"
    payload = {
        "answer_text": answer,
        "answer_language": provider_language,
        "memory_proposals": tuple(
            {
                "kind": "remember_preference",
                "subject_ref": "subject:fixture",
                "category": f"fixture-category-{index}",
                "key": "fixture-key",
                "value": "fixture-value",
                "confidence_micros": 900_000,
                "reason": "fixture",
            }
            for index in range(memory_proposals)
        ),
        "action_proposals": tuple(
            {
                "kind": "timer_create",
                "duration_seconds": 60,
                "label": f"fixture-{index}",
                "confidence_micros": 900_000,
                "reason": "fixture",
            }
            for index in range(action_proposals)
        ),
        "uncertainty_micros": 0,
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _parse_assistant_turn(raw: str) -> AssistantTurn:
    try:
        return AssistantTurn.model_validate_json(raw, strict=True)
    except ValidationError as error:
        raise ValueError("answer outside evaluator bounds") from error


def _response_commitment(turn: AssistantTurn) -> Commitment:
    return commit_private(
        _RESPONSE_RECEIPT_ROOT,
        _RESPONSE_RECEIPT_KEY_ID,
        "provider.response.assistant-turn.v1",
        canonical_bytes(turn),
    )


def _jsonable(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return _jsonable(value.model_dump(mode="python"))
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    return value


def _commitment() -> Commitment:
    return Commitment(
        algorithm="HMAC-SHA-256",
        key_id="fixture-v1",
        value_b64="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )


def _other_commitment() -> Commitment:
    return Commitment(
        algorithm="HMAC-SHA-256",
        key_id="fixture-v1",
        value_b64="AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
    )


def _different_key_commitment() -> Commitment:
    return Commitment(
        algorithm="HMAC-SHA-256",
        key_id="fixture-v2",
        value_b64="AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
    )
