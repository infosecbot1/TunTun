from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

import pytest
from tuntun_contracts.provider import RouteAuthorization
from tuntun_contracts.speech import AuthorizedTranscriptionRequest
from tuntun_core.adapters.openai.transcribe import (
    _duration_millis,
    _normalize_transcription_languages,
    _parse_transcription_json,
)
from tuntun_core.services.providers.gateway import ProviderUsageUnknownError


@pytest.mark.parametrize(
    ("provider_value", "expected"),
    [
        ([{"code": "en"}], "en"),
        ([{"code": "hi"}], "hi"),
        ([{"code": "en"}, {"code": "hi"}], "hinglish"),
        ([SimpleNamespace(code="hi"), SimpleNamespace(code="en")], "hinglish"),
        (None, "unknown"),
        ([], "unknown"),
        ("en", "unknown"),
        (["en"], "unknown"),
        ([{"code": "und"}], "unknown"),
        ([{"code": "en"}] * 9, "unknown"),
        ([{"code": "en"}, {"code": "en"}], "unknown"),
        ([{"code": "en", "confidence": 1}], "unknown"),
    ],
)
def test_transcription_language_is_normalized_without_fabrication(
    provider_value,
    expected: str,
) -> None:
    assert _normalize_transcription_languages(provider_value) == expected


@pytest.mark.parametrize(
    ("seconds", "millis"),
    [("0", 0), ("0.0001", 1), ("1.0001", 1_001), (1, 1_000)],
)
def test_duration_uses_decimal_ceiling(seconds, millis: int) -> None:
    assert _duration_millis(seconds) == millis


@pytest.mark.parametrize("seconds", ("NaN", "Infinity", "-0.1", 0.1, float("nan"), float("inf")))
def test_invalid_duration_is_rejected(seconds) -> None:
    with pytest.raises(ValueError, match="transcription duration invalid"):
        _duration_millis(seconds)


def test_raw_transcription_json_preserves_fractional_decimal() -> None:
    payload = _parse_transcription_json(
        b'{"text":"ok","usage":{"type":"duration","seconds":0.0001},'
        b'"languages":[{"code":"en"}]}'
    )
    assert isinstance(payload["usage"]["seconds"], Decimal)
    assert _duration_millis(payload["usage"]["seconds"]) == 1


def test_empty_documented_languages_array_is_accepted_as_unknown() -> None:
    payload = _parse_transcription_json(
        b'{"text":"ok","usage":{"type":"duration","seconds":1},"languages":[]}'
    )
    assert _normalize_transcription_languages(payload["languages"]) == "unknown"


def test_absent_optional_languages_field_is_accepted_as_unknown() -> None:
    payload = _parse_transcription_json(
        b'{"text":"ok","usage":{"type":"duration","seconds":1}}'
    )
    assert _normalize_transcription_languages(payload.get("languages")) == "unknown"


@pytest.mark.parametrize("constant", ("NaN", "Infinity", "-Infinity"))
def test_raw_transcription_json_rejects_nonstandard_numbers(constant: str) -> None:
    with pytest.raises(ValueError, match="transcription response invalid"):
        _parse_transcription_json(
            ('{"text":"ok","usage":{"type":"duration","seconds":' + constant + "}}").encode()
        )


@pytest.mark.asyncio
async def test_transcriber_uses_raw_request_id_duration_usage_and_bilingual_control(
    stt_accounting_case,
) -> None:
    case = await stt_accounting_case(
        request_id="req_stt_1",
        usage={"type": "duration", "seconds": "1.0001"},
        languages=[{"code": "en"}, {"code": "hi"}],
    )

    result = await case.invoke()

    assert case.sent_parameters["languages"] == ["en", "hi"]
    assert "language" not in case.sent_parameters and "prompt" not in case.sent_parameters
    assert case.receipt.billable_usage.audio_millis == 1_001
    assert result.language == "hinglish"
    assert case.used_with_streaming_response


@pytest.mark.asyncio
async def test_transcriber_rejects_non_gpt_transcribe_model_before_gateway(
    stt_accounting_case,
) -> None:
    case = await stt_accounting_case()
    wrong_route = RouteAuthorization.model_validate(
        case.route.model_dump(mode="python") | {"model": "whisper-1"}
    )
    request = AuthorizedTranscriptionRequest.model_validate(
        case.request.model_dump(mode="python") | {"route": wrong_route}
    )

    async def audio_source():
        yield case.audio

    with pytest.raises(PermissionError, match="openai_transcription_route_required"):
        await case.adapter.transcribe(request, audio_source())

    assert case.gateway.calls == 0
    assert case.sent_parameters == {}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    (
        "missing_x_request_id",
        "usage_type_tokens",
        "usage_nan",
        "usage_negative",
        "extra_response_key",
    ),
)
async def test_invalid_transcription_accounting_never_mints_exact_receipt(
    stt_accounting_case,
    mutation: str,
) -> None:
    case = await stt_accounting_case(mutation=mutation)

    with pytest.raises(ProviderUsageUnknownError, match="unknown_overage"):
        await case.invoke()

    assert case.gateway.observation is None


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ("declared_oversize", "chunked_without_length"))
async def test_transcription_transport_is_bounded_before_json_projection(
    stt_accounting_case,
    transport: str,
) -> None:
    case = await stt_accounting_case(
        response_transport=transport,
        response_bytes=1_048_577,
        chunk_bytes=65_536,
    )

    with pytest.raises(ProviderUsageUnknownError, match="unknown_overage"):
        await case.invoke()

    assert case.stream_iter_bytes_calls <= 1
