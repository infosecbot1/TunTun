from __future__ import annotations

import asyncio

import pytest
from tuntun_contracts.base import canonical_mapping_bytes
from tuntun_core.adapters.openai import sol as sol_module
from tuntun_core.services.providers.attempts import TransientProviderError
from tuntun_core.services.providers.output_validator import AssistantTurn


@pytest.mark.asyncio
async def test_sol_consumes_real_delta_stream_and_closes_on_cancellation(
    sol_adapter,
    authorized_reasoning_request,
    fake_responses_stream,
) -> None:
    fake_responses_stream.block_after_first_delta()
    task = asyncio.create_task(sol_adapter.complete(authorized_reasoning_request))
    await fake_responses_stream.first_delta_seen.wait()

    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task
    assert fake_responses_stream.closed is True
    assert fake_responses_stream.buffered_bytes <= 32_000
    assert fake_responses_stream.provider_call_outcome == "cancelled"


@pytest.mark.asyncio
async def test_sol_response_language_comes_from_validated_assistant_turn(
    sol_adapter,
    authorized_reasoning_request,
    fake_responses_stream,
) -> None:
    fake_responses_stream.complete_with(
        {
            "answer_text": "ठीक है",
            "answer_language": "hi",
            "memory_proposals": [],
            "action_proposals": [],
            "uncertainty_micros": 0,
        }
    )

    response = await sol_adapter.complete(authorized_reasoning_request)

    assert response.language == "hi"
    assert response.text.startswith('{"answer_text"')


@pytest.mark.asyncio
async def test_reasoning_timeout_is_transmitted_but_not_committed(
    sol_adapter,
    authorized_reasoning_request,
    fake_responses_stream,
) -> None:
    await sol_adapter.complete(authorized_reasoning_request)

    assert fake_responses_stream.sent_parameters["timeout"] == 45.0
    payload, body = sol_module.build_openai_reasoning_wire_request(
        model=authorized_reasoning_request.model,
        messages=authorized_reasoning_request.messages,
        allowed_tools=authorized_reasoning_request.allowed_tools,
        max_output_tokens=authorized_reasoning_request.max_output_tokens,
        store=authorized_reasoning_request.store,
        output_schema=AssistantTurn.model_json_schema(),
    )
    assert "timeout" not in payload
    assert b"timeout" not in body


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    ("max_output_tokens", "reasoning_effort", "output_schema", "store"),
)
async def test_every_actual_reasoning_wire_field_is_bound_before_network(
    sol_adapter,
    authorized_reasoning_request,
    fake_responses_stream,
    monkeypatch,
    mutation: str,
) -> None:
    real_builder = sol_module.build_openai_reasoning_wire_request

    def mutate_wire(**values):
        payload, _ = real_builder(**values)
        if mutation == "max_output_tokens":
            payload["max_output_tokens"] += 1
        elif mutation == "reasoning_effort":
            payload["reasoning"]["effort"] = "medium"
        elif mutation == "output_schema":
            payload["text"]["format"]["schema"] = {"type": "string"}
        elif mutation == "store":
            payload["store"] = True
        else:
            raise AssertionError(mutation)
        return payload, canonical_mapping_bytes(payload)

    monkeypatch.setattr(sol_module, "build_openai_reasoning_wire_request", mutate_wire)

    with pytest.raises(TransientProviderError, match="reasoning_commitment_mismatch"):
        await sol_adapter.complete(authorized_reasoning_request)

    assert fake_responses_stream.open_calls == 0
