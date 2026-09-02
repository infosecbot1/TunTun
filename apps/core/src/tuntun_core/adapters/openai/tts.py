from __future__ import annotations

import hmac
import unicodedata
from collections.abc import AsyncIterator
from typing import Any

import httpx
from tuntun_contracts.base import canonical_mapping_bytes
from tuntun_contracts.commitments import commit_private
from tuntun_contracts.provider import RouteConsumption
from tuntun_contracts.speech import AuthorizedSynthesisRequest, SpeechChunk
from tuntun_core.adapters.openai.errors import translate_openai_error
from tuntun_core.services.providers.attempts import TransientProviderError
from tuntun_core.services.providers.gateway import ProviderUsageObservation

from openai import OpenAIError

_MAX_PCM_BYTES = 8_388_608
_CHUNK_SIZE = 65_536
_VOICE = "alloy"


class OpenAITTS:
    def __init__(self, client: Any, gateway: Any, commitment_root: bytes, clock: Any) -> None:
        if type(commitment_root) is not bytes or len(commitment_root) != 32:
            raise ValueError("OpenAI route commitment root must be 32 bytes")
        self._client = client
        self._gateway = gateway
        self._root = commitment_root
        self._clock = clock

    async def synthesize(
        self,
        request: AuthorizedSynthesisRequest,
    ) -> AsyncIterator[SpeechChunk]:
        if type(request) is not AuthorizedSynthesisRequest:
            raise TypeError("request must be an exact AuthorizedSynthesisRequest")
        if (
            request.route.provider != "openai"
            or request.route.purpose != "cloud_tts"
            or request.route.model != "tts-1"
        ):
            raise PermissionError("openai_tts_route_required")
        if (
            request.text != unicodedata.normalize("NFC", request.text)
            or not 1 <= len(request.text) <= 4_096
        ):
            raise ValueError("tts_text_must_be_bounded_nfc")
        if len(request.text) != request.route.max_input_units:
            raise PermissionError("tts_request_character_binding_mismatch")

        body = canonical_mapping_bytes(
            {
                "input": request.text,
                "model": request.route.model,
                "response_format": "pcm",
                "voice": _VOICE,
            }
        )
        if len(body) > request.route.max_input_bytes:
            raise PermissionError("tts_request_byte_binding_mismatch")
        expected = commit_private(
            self._root,
            request.text_commitment.key_id,
            "provider.request.cloud_tts",
            body,
        )
        if (
            expected.algorithm != request.text_commitment.algorithm
            or expected.key_id != request.text_commitment.key_id
            or not hmac.compare_digest(expected.value_b64, request.text_commitment.value_b64)
        ):
            raise TransientProviderError(0, "never_sent", "tts_commitment_mismatch")

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
            input_units=len(request.text),
            consumed_at=self._clock.now(),
        )

        def open_response() -> Any:
            return self._client.audio.speech.with_streaming_response.create(
                model=request.route.model,
                voice=_VOICE,
                input=request.text,
                response_format="pcm",
            )

        async def observe(response: Any) -> ProviderUsageObservation:
            headers = getattr(response, "headers", {}) or {}
            provider_id = getattr(response, "request_id", None) or getattr(
                headers,
                "get",
                lambda _key, _default=None: None,
            )("x-request-id")
            if type(provider_id) is not str or not provider_id:
                raise ValueError("tts response id invalid")
            return ProviderUsageObservation(
                reported_usage=None,
                provider_response_identifier=provider_id,
            )

        try:
            async with self._gateway.open_stream(
                request.route,
                consumption,
                request.dlp_receipt_id,
                open_response,
                observe,
            ) as lease:
                sequence = 0
                total = 0
                received = False
                async for chunk in lease.response.iter_bytes(chunk_size=_CHUNK_SIZE):
                    if type(chunk) is not bytes:
                        raise TypeError("tts response chunk invalid")
                    if not chunk:
                        continue
                    remaining = _MAX_PCM_BYTES - total
                    if len(chunk) > remaining:
                        raise ValueError("tts_pcm_byte_cap")
                    total += len(chunk)
                    received = True
                    yield SpeechChunk(
                        request_id=request.request_id,
                        sequence=sequence,
                        pcm=chunk,
                        final=False,
                    )
                    sequence += 1
                if not received:
                    raise ValueError("tts response body empty")
                await lease.finalize()
                yield SpeechChunk(
                    request_id=request.request_id,
                    sequence=sequence,
                    pcm=b"",
                    final=True,
                )
        except (httpx.TransportError, OpenAIError) as error:
            raise translate_openai_error(error, after_claim=True) from None
