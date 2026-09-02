from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any, cast
from uuid import UUID

from tuntun_contracts.base import parse_contract_json
from tuntun_contracts.provider import ProviderResponse, RouteAuthorization, RouteConsumption
from tuntun_contracts.speech import AuthorizedSynthesisRequest, SpeechChunk
from tuntun_core.services.providers.attempts import RetryPolicy
from tuntun_core.services.providers.output_validator import AssistantTurn
from tuntun_core.services.providers.response_receipts import VerifiedProviderResponseReceipt


@dataclass(frozen=True, slots=True)
class OutputContext:
    household_id: UUID
    subject_id: UUID | None
    session_id: UUID
    turn_id: UUID


@dataclass(frozen=True, slots=True)
class ValidatedAssistantOutput:
    turn: AssistantTurn
    route: RouteAuthorization
    response_receipt: VerifiedProviderResponseReceipt


class OutputPipeline:
    def __init__(
        self,
        dlp: Any,
        consent: Any,
        attempt_runner: Any,
        segmenter: Any,
        template_factory: Any,
        tts: Any,
        response_receipts: Any,
        clock: Any,
    ) -> None:
        self._dlp = dlp
        self._consent = consent
        self._attempt_runner = attempt_runner
        self._segmenter = segmenter
        self._template_factory = template_factory
        self._tts = tts
        self._response_receipts = response_receipts
        self._clock = clock

    async def validate(
        self,
        provider_response: ProviderResponse,
        route: RouteAuthorization,
    ) -> ValidatedAssistantOutput:
        if type(provider_response) is not ProviderResponse:
            raise TypeError("provider_response must be an exact ProviderResponse")
        if type(route) is not RouteAuthorization:
            raise TypeError("route must be an exact RouteAuthorization")
        if provider_response.request_id != route.request_id or route.purpose != "cloud_reasoning":
            raise PermissionError("provider_response_receipt_binding")
        if provider_response.provider_usage_receipt_id is None:
            raise PermissionError("provider_response_usage_unverified")
        turn = parse_contract_json(
            AssistantTurn,
            provider_response.text.encode("utf-8", errors="strict"),
            max_bytes=32_000,
            require_canonical=False,
        )
        if provider_response.language != turn.answer_language:
            raise ValueError("assistant output language mismatch")
        receipt = await self._response_receipts.record(
            route,
            turn,
            provider_usage_receipt_id=provider_response.provider_usage_receipt_id,
        )
        verified = await self._response_receipts.require_exact(
            receipt.receipt_id,
            route,
            turn,
            provider_usage_receipt_id=provider_response.provider_usage_receipt_id,
        )
        return ValidatedAssistantOutput(turn=turn, route=route, response_receipt=verified)

    async def synthesize(
        self,
        output: ValidatedAssistantOutput,
        context: OutputContext,
    ) -> AsyncIterator[SpeechChunk]:
        if type(output) is not ValidatedAssistantOutput:
            raise TypeError("output must be an exact ValidatedAssistantOutput")
        if type(context) is not OutputContext:
            raise TypeError("context must be an exact OutputContext")
        output.response_receipt.require_scope(
            context.household_id,
            context.subject_id,
            context.session_id,
            context.turn_id,
        )
        sanitized_text, dlp_receipt_id = await self._dlp.sanitize_output(
            output.turn.answer_text,
            context.turn_id,
        )
        segments = self._segmenter.sentences(
            sanitized_text,
            max_chars=4_096,
            max_segments=256,
        )
        if not segments:
            raise ValueError("assistant output segment empty")
        for index, segment in enumerate(segments):
            await self._consent.require(
                context.household_id,
                context.subject_id,
                context.session_id,
                ("cloud_tts",),
                self._clock.now(),
            )
            template, authorized_request = self._template_factory.tts_segment(
                context,
                segment,
                index,
                len(segments),
                dlp_receipt_id,
            )

            def invoke(
                route: RouteAuthorization,
                _consumption: RouteConsumption,
                request_template: AuthorizedSynthesisRequest = authorized_request,
            ) -> AsyncIterator[SpeechChunk]:
                request = AuthorizedSynthesisRequest(
                    request_id=request_template.request_id,
                    turn_id=request_template.turn_id,
                    text=request_template.text,
                    text_commitment=request_template.text_commitment,
                    segment_index=request_template.segment_index,
                    segment_count=request_template.segment_count,
                    language=request_template.language,
                    dlp_receipt_id=request_template.dlp_receipt_id,
                    route=route,
                )
                return cast(AsyncIterator[SpeechChunk], self._tts.synthesize(request))

            async for chunk in self._attempt_runner.stream(
                template,
                RetryPolicy(max_attempts=2, base_delay_ms=1),
                invoke,
            ):
                yield chunk
