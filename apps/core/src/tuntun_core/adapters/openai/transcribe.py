from __future__ import annotations

import hmac
from collections.abc import AsyncIterator
from dataclasses import dataclass
from decimal import ROUND_CEILING, Decimal
from io import BytesIO
from typing import Any, Literal

import httpx
from tuntun_contracts.base import ContractParseError, JSONValue, parse_bounded_json_value
from tuntun_contracts.budget import MAX_AUDIO_MILLIS, SttUsageUnits
from tuntun_contracts.commitments import commit_private
from tuntun_contracts.provider import RouteConsumption
from tuntun_contracts.speech import AuthorizedTranscriptionRequest, TranscriptResult
from tuntun_core.adapters.openai.errors import translate_openai_error
from tuntun_core.services.providers.attempts import TransientProviderError
from tuntun_core.services.providers.gateway import (
    ProviderUsageObservation,
    ProviderUsageUnknownError,
)

from openai import OpenAIError

_MAX_TRANSCRIPTION_RESPONSE_BYTES = 1_048_576
_MAX_AUDIO_BYTES = 8_388_608
_TranscriptLanguage = Literal["en", "hi", "hinglish", "unknown"]


@dataclass(frozen=True, slots=True)
class _TranscriptionEnvelope:
    body: bytes
    headers: dict[str, str]
    request_id: str | None


def _normalize_transcription_languages(value: object) -> _TranscriptLanguage:
    if value is None:
        return "unknown"
    if not isinstance(value, list) or len(value) == 0 or len(value) > 8:
        return "unknown"
    codes: list[str] = []
    for item in value:
        if type(item) is dict:
            if set(item) != {"code"}:
                return "unknown"
            code = item["code"]
        else:
            try:
                item_vars = vars(item)
            except TypeError:
                return "unknown"
            if set(item_vars) != {"code"}:
                return "unknown"
            code = getattr(item, "code", None)
        if type(code) is not str or code not in {"en", "hi"}:
            return "unknown"
        codes.append(code)
    if len(set(codes)) != len(codes):
        return "unknown"
    if codes == ["en"] or set(codes) == {"en"}:
        return "en"
    if codes == ["hi"] or set(codes) == {"hi"}:
        return "hi"
    if set(codes) == {"en", "hi"}:
        return "hinglish"
    return "unknown"


def _duration_millis(seconds: object) -> int:
    if type(seconds) is bool or type(seconds) is float:
        raise ValueError("transcription duration invalid")
    try:
        value = Decimal(seconds) if type(seconds) is str else seconds
    except Exception as error:
        raise ValueError("transcription duration invalid") from error
    if type(value) is int:
        decimal = Decimal(value)
    elif type(value) is Decimal:
        decimal = value
    else:
        raise ValueError("transcription duration invalid")
    if not decimal.is_finite() or decimal < 0:
        raise ValueError("transcription duration invalid")
    millis = int((decimal * Decimal(1_000)).to_integral_value(rounding=ROUND_CEILING))
    if not 0 <= millis <= MAX_AUDIO_MILLIS:
        raise ValueError("transcription duration invalid")
    return millis


def _parse_transcription_json(raw: bytes) -> dict[str, JSONValue]:
    try:
        value = parse_bounded_json_value(
            raw,
            max_bytes=_MAX_TRANSCRIPTION_RESPONSE_BYTES,
            max_depth=8,
            max_containers=64,
            max_structure_tokens=512,
        )
    except (ContractParseError, TypeError, ValueError) as error:
        raise ValueError("transcription response invalid") from error
    if type(value) is not dict:
        raise ValueError("transcription response invalid")
    if not set(value) <= {"text", "usage", "languages"}:
        raise ValueError("transcription response invalid")
    text = value.get("text")
    usage = value.get("usage")
    if type(text) is not str or not 1 <= len(text.encode("utf-8")) <= 131_072:
        raise ValueError("transcription response invalid")
    if type(usage) is not dict or set(usage) != {"type", "seconds"}:
        raise ValueError("transcription response invalid")
    if usage.get("type") != "duration":
        raise ValueError("transcription response invalid")
    languages = value.get("languages")
    if type(languages) is list and len(languages) > 8:
        raise ValueError("transcription response invalid")
    return value


async def _read_bounded_provider_body(response: Any) -> bytes:
    headers = getattr(response, "headers", {})
    declared = None
    if isinstance(headers, dict):
        declared = headers.get("content-length")
    else:
        declared = getattr(headers, "get", lambda _key, _default=None: None)("content-length")
    if declared is not None:
        try:
            if int(declared) > _MAX_TRANSCRIPTION_RESPONSE_BYTES:
                raise ValueError("transcription response invalid")
        except ValueError as error:
            raise ValueError("transcription response invalid") from error
    body = bytearray()
    async for chunk in response.iter_bytes():
        if type(chunk) is not bytes:
            raise TypeError("transcription response chunk invalid")
        remaining = _MAX_TRANSCRIPTION_RESPONSE_BYTES - len(body)
        if len(chunk) > remaining:
            raise ValueError("transcription response invalid")
        body.extend(chunk)
    return bytes(body)


class OpenAITranscriber:
    def __init__(self, client: Any, gateway: Any, commitment_root: bytes, clock: Any) -> None:
        if type(commitment_root) is not bytes or len(commitment_root) != 32:
            raise ValueError("OpenAI route commitment root must be 32 bytes")
        self._client = client
        self._gateway = gateway
        self._root = commitment_root
        self._clock = clock
        self.peak_audio_buffer_bytes = 0

    async def transcribe(
        self,
        request: AuthorizedTranscriptionRequest,
        audio: AsyncIterator[bytes],
    ) -> TranscriptResult:
        if type(request) is not AuthorizedTranscriptionRequest:
            raise TypeError("request must be an exact AuthorizedTranscriptionRequest")
        if (
            request.route.provider != "openai"
            or request.route.purpose != "cloud_stt"
            or request.route.model != "gpt-transcribe"
        ):
            raise PermissionError("openai_transcription_route_required")
        audio_bytes = await self._buffer_audio(request, audio)
        expected = commit_private(
            self._root,
            request.audio_commitment.key_id,
            "provider.request.cloud_stt",
            audio_bytes,
        )
        if (
            expected.algorithm != request.audio_commitment.algorithm
            or expected.key_id != request.audio_commitment.key_id
            or not hmac.compare_digest(expected.value_b64, request.audio_commitment.value_b64)
        ):
            raise TransientProviderError(0, "never_sent", "stt_commitment_mismatch")

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
            input_bytes=len(audio_bytes),
            input_units=request.duration_ms,
            consumed_at=self._clock.now(),
        )

        async def invoke() -> _TranscriptionEnvelope:
            file_body = BytesIO(audio_bytes)
            file_body.name = "turn.wav"
            async with self._client.audio.transcriptions.with_streaming_response.create(
                model=request.route.model,
                file=file_body,
                languages=list(request.language_hints),
                response_format="json",
            ) as response:
                try:
                    body = await _read_bounded_provider_body(response)
                except (TypeError, ValueError) as error:
                    raise ProviderUsageUnknownError(
                        "provider_usage_invalid_unknown_overage"
                    ) from error
                headers = dict(getattr(response, "headers", {}) or {})
                request_id = getattr(response, "request_id", None) or headers.get("x-request-id")
                return _TranscriptionEnvelope(body=body, headers=headers, request_id=request_id)

        async def observe(envelope: _TranscriptionEnvelope) -> ProviderUsageObservation:
            payload = _parse_transcription_json(envelope.body)
            usage = payload["usage"]
            if type(usage) is not dict:
                raise ValueError("transcription response invalid")
            millis = _duration_millis(usage["seconds"])
            provider_id = envelope.request_id or envelope.headers.get("x-request-id")
            if type(provider_id) is not str or not provider_id:
                raise ValueError("transcription response invalid")
            return ProviderUsageObservation(
                SttUsageUnits(category="stt", audio_millis=millis),
                provider_id,
            )

        try:
            result = await self._gateway.send(
                request.route,
                consumption,
                None,
                invoke,
                observe,
            )
        except (httpx.TransportError, OpenAIError) as error:
            raise translate_openai_error(error, after_claim=True) from None

        payload = _parse_transcription_json(result.value.body)
        return TranscriptResult(
            request_id=request.request_id,
            text=str(payload["text"]),
            language=_normalize_transcription_languages(payload.get("languages")),
            duration_ms=request.duration_ms,
        )

    async def _buffer_audio(
        self,
        request: AuthorizedTranscriptionRequest,
        audio: AsyncIterator[bytes],
    ) -> bytes:
        capacity = min(request.audio_bytes, request.route.max_input_bytes, _MAX_AUDIO_BYTES)
        body = bytearray()
        try:
            async for chunk in audio:
                if type(chunk) is not bytes:
                    raise TypeError("audio chunk type invalid")
                remaining = capacity - len(body)
                if len(chunk) > remaining:
                    raise ValueError("audio byte cap exceeded")
                body.extend(chunk)
                self.peak_audio_buffer_bytes = max(self.peak_audio_buffer_bytes, len(body))
            if len(body) != request.audio_bytes:
                raise ValueError("audio byte count mismatch")
            return bytes(body)
        finally:
            body[:] = b"\x00" * len(body)
            body.clear()
