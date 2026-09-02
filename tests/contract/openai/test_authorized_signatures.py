from __future__ import annotations

import inspect

import pytest
from tuntun_core.adapters.openai.sol import OpenAISol
from tuntun_core.adapters.openai.transcribe import OpenAITranscriber
from tuntun_core.adapters.openai.tts import OpenAITTS
from tuntun_core.services.providers.output_validator import AssistantTurn


def test_openai_adapters_expose_only_frozen_authorized_contracts() -> None:
    assert tuple(inspect.signature(OpenAITranscriber.transcribe).parameters) == (
        "self",
        "request",
        "audio",
    )
    assert tuple(inspect.signature(OpenAISol.complete).parameters) == ("self", "request")
    assert tuple(inspect.signature(OpenAITTS.synthesize).parameters) == ("self", "request")
    assert not hasattr(OpenAISol, "generate")
    assert not hasattr(OpenAITTS, "synthesize_segment")
    for adapter in (OpenAITranscriber, OpenAISol, OpenAITTS):
        assert "gateway" in inspect.signature(adapter.__init__).parameters


@pytest.mark.asyncio
async def test_sol_rejects_one_oversized_delta_before_extending_output_buffer(
    sol_stream_case,
) -> None:
    sol_stream_case.emit_delta("x" * 32_001)

    with pytest.raises(ValueError, match="assistant output byte cap"):
        await sol_stream_case.invoke()

    assert sol_stream_case.peak_adapter_output_bytes <= 32_000
    assert sol_stream_case.semantic_projection_calls == 0


@pytest.mark.asyncio
async def test_sol_requests_provider_strict_json_schema_and_still_validates_locally(
    sol_stream_case,
) -> None:
    await sol_stream_case.invoke()

    format_ = sol_stream_case.sent_parameters["text"]["format"]
    assert format_["type"] == "json_schema"
    assert format_["name"] == "assistant_turn"
    assert format_["schema"] == AssistantTurn.model_json_schema()
    assert format_["strict"] is True
    assert sol_stream_case.semantic_projection_calls == 1
