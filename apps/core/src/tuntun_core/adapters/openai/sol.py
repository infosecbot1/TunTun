from __future__ import annotations

import hmac
from typing import Any

import httpx
from tuntun_contracts.base import ContractParseError, parse_contract_json
from tuntun_contracts.budget import LlmUsageUnits
from tuntun_contracts.commitments import commit_private
from tuntun_contracts.provider import (
    ProviderName,
    ProviderResponse,
    RouteConsumption,
    SanitizedProviderRequest,
)
from tuntun_core.adapters.openai.errors import translate_openai_error
from tuntun_core.services.providers.attempts import TransientProviderError
from tuntun_core.services.providers.gateway import ProviderUsageObservation
from tuntun_core.services.providers.output_validator import AssistantTurn
from tuntun_core.services.providers.reasoning_wire import build_openai_reasoning_wire_request

from openai import OpenAIError

_MAX_ASSISTANT_OUTPUT_BYTES = 32_000


class OpenAISol:
    def __init__(self, client: Any, gateway: Any, commitment_root: bytes, clock: Any) -> None:
        if type(commitment_root) is not bytes or len(commitment_root) != 32:
            raise ValueError("OpenAI route commitment root must be 32 bytes")
        self._client = client
        self._gateway = gateway
        self._root = commitment_root
        self._clock = clock

    async def complete(self, request: SanitizedProviderRequest) -> ProviderResponse:
        if type(request) is not SanitizedProviderRequest:
            raise TypeError("request must be an exact SanitizedProviderRequest")
        if request.provider is not ProviderName.OPENAI or request.route.provider != "openai":
            raise PermissionError("openai_reasoning_route_required")
        if request.route.purpose != "cloud_reasoning":
            raise PermissionError("openai_reasoning_route_required")
        payload, body = build_openai_reasoning_wire_request(
            model=request.model,
            messages=request.messages,
            allowed_tools=request.allowed_tools,
            max_output_tokens=request.max_output_tokens,
            store=request.store,
            output_schema=AssistantTurn.model_json_schema(),
        )
        expected = commit_private(
            self._root,
            request.route.request_commitment.key_id,
            "provider.request.cloud_reasoning",
            body,
        )
        if (
            expected.algorithm != request.route.request_commitment.algorithm
            or expected.key_id != request.route.request_commitment.key_id
            or not hmac.compare_digest(
                expected.value_b64,
                request.route.request_commitment.value_b64,
            )
        ):
            raise TransientProviderError(0, "never_sent", "reasoning_commitment_mismatch")

        consumption = RouteConsumption(
            request_id=request.route.request_id,
            attempt_id=request.route.attempt_id,
            purpose=request.route.purpose,
            household_id=request.route.household_id,
            subject_id=request.route.subject_id,
            session_id=request.route.session_id,
            turn_id=request.route.turn_id,
            provider=request.route.provider,
            model=request.route.model,
            request_commitment=request.route.request_commitment,
            input_bytes=len(body),
            input_units=min(request.route.max_input_units, len(body)),
            consumed_at=self._clock.now(),
        )
        output = bytearray()

        def open_response() -> Any:
            return self._client.responses.stream(
                **payload,
                timeout=request.timeout_ms / 1_000.0,
            )

        async def observe(response: Any) -> ProviderUsageObservation:
            final = await response.get_final_response()
            usage = getattr(final, "usage", None)
            provider_id = getattr(final, "id", None)
            input_tokens = getattr(usage, "input_tokens", None)
            output_tokens = getattr(usage, "output_tokens", None)
            if (
                type(provider_id) is not str
                or type(input_tokens) is not int
                or type(output_tokens) is not int
            ):
                raise ValueError("reasoning usage invalid")
            return ProviderUsageObservation(
                LlmUsageUnits(
                    category="llm",
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                ),
                provider_id,
            )

        try:
            async with self._gateway.open_stream(
                request.route,
                consumption,
                request.redaction_receipt_id,
                open_response,
                observe,
            ) as lease:
                async for event in lease.response:
                    event_type = getattr(event, "type", None)
                    if event_type == "response.output_text.delta":
                        delta = getattr(event, "delta", None)
                        if type(delta) is not str:
                            raise ValueError("assistant output invalid")
                        encoded = delta.encode("utf-8", errors="strict")
                        remaining = _MAX_ASSISTANT_OUTPUT_BYTES - len(output)
                        if len(encoded) > remaining:
                            raise ValueError("assistant output byte cap")
                        output.extend(encoded)
                    elif event_type in {"response.failed", "error"}:
                        raise RuntimeError("openai_reasoning_failed")
                provider_usage_receipt_id = await lease.finalize()
        except (httpx.TransportError, OpenAIError) as error:
            raise translate_openai_error(error, after_claim=True) from None

        try:
            turn = parse_contract_json(
                AssistantTurn,
                bytes(output),
                max_bytes=_MAX_ASSISTANT_OUTPUT_BYTES,
                require_canonical=False,
            )
        except ContractParseError as error:
            raise ValueError("assistant output invalid") from error
        return ProviderResponse(
            request_id=request.request_id,
            text=turn.model_dump_json(),
            language=turn.answer_language,
            provider_usage_receipt_id=provider_usage_receipt_id,
        )
