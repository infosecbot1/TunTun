from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from tuntun_contracts.base import Commitment, Sensitivity
from tuntun_contracts.budget import TtsUsageUnits
from tuntun_contracts.provider import ProviderResponse, ProviderResponseReceipt, RouteAuthorization
from tuntun_contracts.speech import AuthorizedSynthesisRequest, SpeechChunk
from tuntun_core.services.providers.attempts import AttemptRunner, AttemptTemplate
from tuntun_core.services.providers.output_pipeline import OutputContext, OutputPipeline
from tuntun_core.services.providers.output_validator import AssistantTurn
from tuntun_core.services.providers.response_receipts import VerifiedProviderResponseReceipt
from tuntun_testing.fake_clock import FakeClock
from tuntun_testing.fake_providers import (
    RecordingBudget,
    RecordingRouteAuthorizer,
    RecordingTurnAttempts,
)


def _commitment() -> Commitment:
    return Commitment(
        algorithm="HMAC-SHA-256",
        key_id="route-hmac-v1",
        value_b64="A" * 43 + "=",
    )


def _route(request_id: UUID, turn_id: UUID) -> RouteAuthorization:
    return RouteAuthorization(
        authorization_id=uuid4(),
        request_id=request_id,
        attempt_id=uuid4(),
        purpose="cloud_reasoning",
        household_id=uuid4(),
        subject_id=uuid4(),
        session_id=uuid4(),
        turn_id=turn_id,
        provider="openai",
        model="gpt-5.6-sol",
        request_commitment=_commitment(),
        max_input_bytes=32_000,
        max_input_units=8_000,
        privacy_receipt_id=uuid4(),
        consent_receipt_ids=(uuid4(),),
        budget_reservation_id=uuid4(),
        maximum_sensitivity=Sensitivity.PERSONAL,
        expires_at=datetime(2026, 8, 27, tzinfo=UTC),
    )


@dataclass(slots=True)
class Captures:
    output_dlp_calls: int = 0
    tts_consent_checks: int = 0
    provider_response_receipts: int = 0
    pcm_chunk_sizes: list[int] | None = None
    pcm_segment_totals: list[int] | None = None

    def __post_init__(self) -> None:
        self.pcm_chunk_sizes = []
        self.pcm_segment_totals = []


class Dlp:
    def __init__(self, captures: Captures) -> None:
        self.captures = captures

    async def sanitize_output(self, text: str, turn_id: UUID):
        del turn_id
        self.captures.output_dlp_calls += 1
        return text, uuid4()


class Consent:
    def __init__(self, captures: Captures) -> None:
        self.captures = captures

    async def require(self, household_id, subject_id, session_id, purposes, now) -> None:
        del household_id, subject_id, session_id, now
        assert purposes == ("cloud_tts",)
        self.captures.tts_consent_checks += 1


class Segmenter:
    def sentences(self, text: str, *, max_chars: int, max_segments: int) -> tuple[str, ...]:
        del max_chars, max_segments
        return tuple(part.strip() for part in text.split(".") if part.strip())


class ResponseReceipts:
    def __init__(self, captures: Captures) -> None:
        self.captures = captures
        self.verified: VerifiedProviderResponseReceipt | None = None

    async def record(self, route, turn, *, provider_usage_receipt_id):
        del provider_usage_receipt_id
        self.captures.provider_response_receipts += 1
        receipt = ProviderResponseReceipt(
            receipt_id=uuid4(),
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
            response_commitment=_commitment(),
            receipt_hmac_key_id="provider-response-v1",
            receipt_hmac_b64="A" * 43 + "=",
            produced_at=datetime(2026, 8, 27, tzinfo=UTC),
        )
        self.verified = VerifiedProviderResponseReceipt(receipt)
        return receipt

    async def require_exact(self, receipt_id, route, turn, *, provider_usage_receipt_id):
        del receipt_id, route, turn, provider_usage_receipt_id
        assert self.verified is not None
        return self.verified


class TemplateFactory:
    def __init__(self, captures: Captures) -> None:
        self.captures = captures

    def tts_segment(
        self,
        context: OutputContext,
        text: str,
        index: int,
        count: int,
        dlp_receipt_id: UUID,
    ):
        commitment = _commitment()
        request_id = uuid4()
        route = RouteAuthorization(
            authorization_id=uuid4(),
            request_id=request_id,
            attempt_id=uuid4(),
            purpose="cloud_tts",
            household_id=context.household_id,
            subject_id=context.subject_id,
            session_id=context.session_id,
            turn_id=context.turn_id,
            provider="openai",
            model="tts-1",
            request_commitment=commitment,
            max_input_bytes=4_096,
            max_input_units=len(text),
            privacy_receipt_id=uuid4(),
            consent_receipt_ids=(uuid4(),),
            budget_reservation_id=uuid4(),
            maximum_sensitivity=Sensitivity.HOUSEHOLD,
            expires_at=datetime(2026, 8, 27, tzinfo=UTC),
        )
        template = AttemptTemplate(
            request_id=request_id,
            purpose="cloud_tts",
            household_id=context.household_id,
            subject_id=context.subject_id,
            session_id=context.session_id,
            turn_id=context.turn_id,
            provider="openai",
            model="tts-1",
            request_commitment=commitment,
            max_input_bytes=4_096,
            max_input_units=len(text),
            input_bytes=len(text.encode("utf-8")),
            input_units=len(text),
            privacy_receipt_id=uuid4(),
            consent_receipt_ids=(uuid4(),),
            maximum_sensitivity=Sensitivity.HOUSEHOLD,
            month_key="2026-08",
            category="tts",
            usage_ceiling=TtsUsageUnits(category="tts", characters=len(text)),
        )
        request = AuthorizedSynthesisRequest(
            request_id=request_id,
            turn_id=context.turn_id,
            text=text,
            text_commitment=commitment,
            segment_index=index,
            segment_count=count,
            language="hinglish",
            dlp_receipt_id=dlp_receipt_id,
            route=route,
        )
        return template, request


class StreamingTts:
    def __init__(self, captures: Captures, budget: RecordingBudget) -> None:
        self.captures = captures
        self.budget = budget
        self.second_chunk_requested = False
        self.allow_second = False

    def synthesize(self, request: AuthorizedSynthesisRequest):
        async def source():
            assert request.route.attempt_id != request.route.authorization_id
            await self.budget.mark_sent(
                request.route.budget_reservation_id,
                request.route.attempt_id,
            )
            first = b"a" * min(65_536, max(1, len(request.text.encode())))
            self.captures.pcm_chunk_sizes.append(len(first))
            self.captures.pcm_segment_totals.append(len(first))
            yield SpeechChunk(request_id=request.request_id, sequence=0, pcm=first, final=False)
            self.budget.record_exact_usage(request.route.attempt_id)
            yield SpeechChunk(request_id=request.request_id, sequence=1, pcm=b"", final=True)

        return source()


@pytest.fixture
def output_pipeline_case():
    captures = Captures()
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    budget = RecordingBudget(clock)
    attempts = RecordingTurnAttempts(budget)
    runner = AttemptRunner(RecordingRouteAuthorizer(clock), budget, attempts, clock)
    pipeline = OutputPipeline(
        Dlp(captures),
        Consent(captures),
        runner,
        Segmenter(),
        TemplateFactory(captures),
        StreamingTts(captures, budget),
        ResponseReceipts(captures),
        clock,
    )
    turn_id = uuid4()
    route = _route(uuid4(), turn_id)
    turn = AssistantTurn(
        answer_text="One. Two. Three.",
        answer_language="hinglish",
        memory_proposals=(),
        action_proposals=(),
        uncertainty_micros=0,
    )
    response = ProviderResponse(
        request_id=route.request_id,
        text=turn.model_dump_json(),
        language="hinglish",
        provider_usage_receipt_id=uuid4(),
    )
    context = OutputContext(
        household_id=route.household_id,
        subject_id=route.subject_id,
        session_id=route.session_id,
        turn_id=turn_id,
    )
    return pipeline, captures, response, route, context, budget, attempts


@pytest.mark.asyncio
async def test_each_tts_segment_rechecks_dlp_consent_and_gets_fresh_attempt(
    output_pipeline_case,
) -> None:
    pipeline, captures, response, route, context, budget, attempts = output_pipeline_case

    validated = await pipeline.validate(response, route)
    chunks = [chunk async for chunk in pipeline.synthesize(validated, context)]

    assert chunks
    assert captures.output_dlp_calls == 1
    assert captures.tts_consent_checks == 3
    assert len(set(budget.reservation_ids)) == 3
    assert len(set(attempt[2] for attempt in attempts.tracked)) == 3
    assert captures.provider_response_receipts == 1
    assert all(chunk_size <= 65_536 for chunk_size in captures.pcm_chunk_sizes)
    assert all(total <= 8_388_608 for total in captures.pcm_segment_totals)


@pytest.mark.asyncio
async def test_tts_terminal_marker_follows_receipt_ledger_and_turn_completion(
    output_pipeline_case,
) -> None:
    pipeline, _captures, response, route, context, budget, attempts = output_pipeline_case
    validated = await pipeline.validate(response, route)

    terminal = None
    async for chunk in pipeline.synthesize(validated, context):
        if chunk.final:
            terminal = chunk
            assert chunk.pcm == b""
            assert len(budget.terminal_pairs) == len(attempts.completed) == 1
            break

    assert terminal is not None


@pytest.mark.asyncio
async def test_cross_subject_context_fails_before_dlp_consent_or_tts_reservation(
    output_pipeline_case,
) -> None:
    pipeline, captures, response, route, context, budget, attempts = output_pipeline_case
    validated = await pipeline.validate(response, route)
    wrong_subject_context = OutputContext(
        household_id=context.household_id,
        subject_id=uuid4(),
        session_id=context.session_id,
        turn_id=context.turn_id,
    )

    with pytest.raises(PermissionError, match="provider_response_receipt_binding"):
        _ = [
            chunk
            async for chunk in pipeline.synthesize(validated, wrong_subject_context)
        ]

    assert captures.output_dlp_calls == 0
    assert captures.tts_consent_checks == 0
    assert budget.reservation_ids == []
    assert attempts.tracked == []
