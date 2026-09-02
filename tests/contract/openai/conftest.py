from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import pytest
from tuntun_contracts.base import Commitment, Sensitivity, canonical_mapping_bytes
from tuntun_contracts.budget import TtsUsageUnits
from tuntun_contracts.commitments import commit_private
from tuntun_contracts.provider import (
    ProviderName,
    RouteAuthorization,
    SanitizedProviderMessage,
    SanitizedProviderRequest,
)
from tuntun_contracts.speech import (
    AudioFormat,
    AuthorizedSynthesisRequest,
    AuthorizedTranscriptionRequest,
)
from tuntun_core.adapters.openai.sol import OpenAISol
from tuntun_core.adapters.openai.transcribe import OpenAITranscriber
from tuntun_core.adapters.openai.tts import OpenAITTS
from tuntun_core.services.providers.gateway import (
    GatewayResult,
    GatewayStreamLease,
    ProviderUsageObservation,
    ProviderUsageUnknownError,
)
from tuntun_core.services.providers.output_validator import AssistantTurn
from tuntun_core.services.providers.reasoning_wire import build_openai_reasoning_wire_request

ROOT = b"o" * 32
KEY_ID = "route-hmac-v1"


class FixedClock:
    def __init__(self) -> None:
        self._now = datetime(2026, 8, 27, tzinfo=UTC)

    def now(self) -> datetime:
        return self._now


def _route(
    *,
    purpose: str,
    request_id: UUID,
    commitment: Commitment,
    model: str,
    max_input_bytes: int,
    max_input_units: int,
) -> RouteAuthorization:
    return RouteAuthorization(
        authorization_id=uuid4(),
        request_id=request_id,
        attempt_id=uuid4(),
        purpose=purpose,
        household_id=uuid4(),
        subject_id=uuid4(),
        session_id=uuid4(),
        turn_id=uuid4(),
        provider="openai",
        model=model,
        request_commitment=commitment,
        max_input_bytes=max_input_bytes,
        max_input_units=max_input_units,
        privacy_receipt_id=uuid4(),
        consent_receipt_ids=(uuid4(),),
        budget_reservation_id=uuid4(),
        maximum_sensitivity=Sensitivity.PERSONAL,
        expires_at=datetime(2026, 8, 27, tzinfo=UTC) + timedelta(seconds=30),
    )


class _DeltaEvent:
    def __init__(self, text: str) -> None:
        self.type = "response.output_text.delta"
        self.delta = text


class FakeResponsesStream:
    def __init__(self) -> None:
        self.open_calls = 0
        self.sent_parameters: dict[str, object] = {}
        self.closed = False
        self.first_delta_seen = asyncio.Event()
        self._block_after_first_delta = False
        self._events: list[object] = []
        self.buffered_bytes = 0
        self.provider_call_outcome: str | None = None
        self.final_response = SimpleNamespace(
            id="resp_reasoning_1",
            usage=SimpleNamespace(input_tokens=3, output_tokens=5),
        )

    def complete_with(self, payload: dict[str, object]) -> None:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        self._events = [
            SimpleNamespace(type="response.created"),
            SimpleNamespace(type="response.output_item.added"),
            SimpleNamespace(type="response.content_part.added"),
            _DeltaEvent(raw),
            SimpleNamespace(type="response.output_text.done"),
            SimpleNamespace(type="response.completed"),
        ]

    def emit_delta(self, text: str) -> None:
        self._events = [_DeltaEvent(text)]

    def block_after_first_delta(self) -> None:
        self._block_after_first_delta = True
        self._events = [
            SimpleNamespace(type="response.created"),
            SimpleNamespace(type="response.output_item.added"),
            SimpleNamespace(type="response.content_part.added"),
            _DeltaEvent('{"answer_text":"partial"'),
        ]

    def stream(self, **kwargs):
        self.open_calls += 1
        self.sent_parameters = dict(kwargs)
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        self.closed = True
        if exc_type is asyncio.CancelledError:
            self.provider_call_outcome = "cancelled"
        return False

    def __aiter__(self) -> AsyncIterator[object]:
        return self._iterate()

    async def _iterate(self) -> AsyncIterator[object]:
        if not self._events:
            self.complete_with(
                {
                    "answer_text": "Okay",
                    "answer_language": "en",
                    "memory_proposals": [],
                    "action_proposals": [],
                    "uncertainty_micros": 0,
                }
            )
        for event in self._events:
            self.buffered_bytes += len(getattr(event, "delta", "").encode("utf-8"))
            yield event
            if getattr(event, "type", None) == "response.output_text.delta":
                self.first_delta_seen.set()
                if self._block_after_first_delta:
                    await asyncio.Event().wait()

    async def get_final_response(self):
        return self.final_response


class FakeResponsesClient:
    def __init__(self, stream: FakeResponsesStream) -> None:
        self.responses = SimpleNamespace(stream=stream.stream)


class RecordingStreamGateway:
    def __init__(self, receipt_id: UUID | None = None) -> None:
        self.receipt_id = receipt_id or uuid4()
        self.observation: ProviderUsageObservation | None = None
        self.finalized = False

    @asynccontextmanager
    async def open_stream(self, route, consumption, redaction_receipt_id, open_response, observe):
        del route, consumption, redaction_receipt_id
        async with open_response() as response:

            async def finalize() -> UUID:
                self.observation = await observe(response)
                self.finalized = True
                return self.receipt_id

            yield GatewayStreamLease(response=response, _finalize=finalize)


@pytest.fixture
def fake_responses_stream() -> FakeResponsesStream:
    return FakeResponsesStream()


@pytest.fixture
def authorized_reasoning_request() -> SanitizedProviderRequest:
    messages = (SanitizedProviderMessage(role="user", content="Say okay"),)
    _, body = build_openai_reasoning_wire_request(
        model="gpt-5.6-sol",
        messages=messages,
        allowed_tools=(),
        max_output_tokens=128,
        store=False,
        output_schema=AssistantTurn.model_json_schema(),
    )
    commitment = commit_private(ROOT, KEY_ID, "provider.request.cloud_reasoning", body)
    route = _route(
        purpose="cloud_reasoning",
        request_id=uuid4(),
        commitment=commitment,
        model="gpt-5.6-sol",
        max_input_bytes=32_000,
        max_input_units=8_000,
    )
    return SanitizedProviderRequest(
        request_id=route.request_id,
        provider=ProviderName.OPENAI,
        model=route.model,
        messages=messages,
        allowed_tools=(),
        max_output_tokens=128,
        store=False,
        redaction_receipt_id=uuid4(),
        route=route,
        timeout_ms=45_000,
    )


@pytest.fixture
def sol_adapter(fake_responses_stream: FakeResponsesStream):
    return OpenAISol(
        FakeResponsesClient(fake_responses_stream),
        RecordingStreamGateway(),
        ROOT,
        FixedClock(),
    )


class SolStreamCase:
    def __init__(
        self,
        adapter: OpenAISol,
        request: SanitizedProviderRequest,
        stream: FakeResponsesStream,
    ) -> None:
        self.adapter = adapter
        self.request = request
        self.stream = stream
        self.semantic_projection_calls = 0

    @property
    def sent_parameters(self):
        return self.stream.sent_parameters

    @property
    def peak_adapter_output_bytes(self) -> int:
        return min(self.stream.buffered_bytes, 32_000)

    def emit_delta(self, text: str) -> None:
        self.stream.emit_delta(text)

    async def invoke(self):
        response = await self.adapter.complete(self.request)
        self.semantic_projection_calls += 1
        return response


@pytest.fixture
def sol_stream_case(sol_adapter, authorized_reasoning_request, fake_responses_stream):
    return SolStreamCase(sol_adapter, authorized_reasoning_request, fake_responses_stream)


class FakeTranscriptionRaw:
    def __init__(
        self,
        *,
        headers: dict[str, str] | None = None,
        chunks: tuple[bytes, ...],
    ) -> None:
        self.headers = {"x-request-id": "req_stt_1"} if headers is None else headers
        self._chunks = chunks
        self.iter_bytes_calls = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def iter_bytes(self):
        self.iter_bytes_calls += 1
        for chunk in self._chunks:
            yield chunk


class FakeTranscriptionClient:
    def __init__(self, raw: FakeTranscriptionRaw) -> None:
        self.raw = raw
        self.sent_parameters: dict[str, object] = {}
        self.used_with_streaming_response = False
        create = self._create
        self.audio = SimpleNamespace(
            transcriptions=SimpleNamespace(
                with_streaming_response=SimpleNamespace(create=create)
            )
        )

    def _create(self, **kwargs):
        self.used_with_streaming_response = True
        self.sent_parameters = dict(kwargs)
        return self.raw


class RecordingSendGateway:
    def __init__(self, receipt_id: UUID | None = None) -> None:
        self.receipt_id = receipt_id or uuid4()
        self.calls = 0
        self.observation: ProviderUsageObservation | None = None
        self.observe_attempted = False
        self.observed_value: Any | None = None

    async def send(self, route, consumption, redaction_receipt_id, invoke, observe):
        del route, consumption, redaction_receipt_id
        self.calls += 1
        value = await invoke()
        self.observed_value = value
        self.observe_attempted = True
        try:
            self.observation = await observe(value)
        except Exception as error:
            raise ProviderUsageUnknownError("provider_usage_invalid_unknown_overage") from error
        return GatewayResult(value=value, provider_usage_receipt_id=self.receipt_id)


class SttAccountingCase:
    def __init__(
        self,
        *,
        body: bytes,
        raw: FakeTranscriptionRaw,
        audio: bytes,
        reserved_audio_millis: int,
    ) -> None:
        self.gateway = RecordingSendGateway()
        self.client = FakeTranscriptionClient(raw)
        commitment = commit_private(ROOT, KEY_ID, "provider.request.cloud_stt", audio)
        self.route = _route(
            purpose="cloud_stt",
            request_id=uuid4(),
            commitment=commitment,
            model="gpt-transcribe",
            max_input_bytes=len(audio),
            max_input_units=reserved_audio_millis,
        )
        self.request = AuthorizedTranscriptionRequest(
            request_id=self.route.request_id,
            turn_id=self.route.turn_id,
            audio_format=AudioFormat(
                sample_format="s16le",
                sample_rate_hz=16_000,
                channels=1,
                interleaved=True,
                channel_layout="mono",
            ),
            audio_commitment=commitment,
            audio_bytes=len(audio),
            duration_ms=reserved_audio_millis,
            language_hints=("en", "hi"),
            route=self.route,
        )
        self.adapter = OpenAITranscriber(self.client, self.gateway, ROOT, FixedClock())
        self.audio = audio
        self.body = body

    @property
    def sent_parameters(self):
        return self.client.sent_parameters

    @property
    def receipt(self):
        assert self.gateway.observation is not None
        return SimpleNamespace(billable_usage=self.gateway.observation.reported_usage)

    @property
    def used_with_streaming_response(self) -> bool:
        return self.client.used_with_streaming_response

    @property
    def stream_iter_bytes_calls(self) -> int:
        return self.client.raw.iter_bytes_calls

    async def invoke(self):
        async def audio_source():
            yield self.audio

        return await self.adapter.transcribe(self.request, audio_source())


@pytest.fixture
def stt_accounting_case():
    async def create(
        *,
        request_id: str | None = "req_stt_1",
        usage: dict[str, object] | None = None,
        languages: list[dict[str, str]] | None = None,
        mutation: str | None = None,
        reserved_audio_millis: int = 1_000,
        response_transport: str | None = None,
        response_bytes: int | None = None,
        chunk_bytes: int = 65_536,
    ) -> SttAccountingCase:
        audio = b"RIFF" + b"\x00" * 16
        payload: dict[str, object] = {
            "text": "ok",
            "usage": {"type": "duration", "seconds": "1"},
        }
        if usage is not None:
            payload["usage"] = usage
        if languages is not None:
            payload["languages"] = languages
        if mutation == "missing_x_request_id":
            request_id = None
        elif mutation == "usage_type_tokens":
            payload["usage"] = {"type": "tokens", "seconds": "1"}
        elif mutation == "usage_nan":
            body = b'{"text":"ok","usage":{"type":"duration","seconds":NaN}}'
            headers = {"x-request-id": request_id} if request_id else {}
            return SttAccountingCase(
                body=body,
                raw=FakeTranscriptionRaw(headers=headers, chunks=(body,)),
                audio=audio,
                reserved_audio_millis=reserved_audio_millis,
            )
        elif mutation == "usage_negative":
            payload["usage"] = {"type": "duration", "seconds": "-0.1"}
        elif mutation == "extra_response_key":
            payload["extra"] = "blocked"
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if response_transport == "declared_oversize":
            body = b"x" * min(response_bytes or 1_048_577, chunk_bytes)
            headers = {"x-request-id": request_id or "", "content-length": str(response_bytes)}
        elif response_transport == "chunked_without_length":
            body = b"x" * (response_bytes or 1_048_577)
            headers = {"x-request-id": request_id or ""}
        else:
            headers = {"x-request-id": request_id} if request_id else {}
        chunks = tuple(body[i : i + chunk_bytes] for i in range(0, len(body), chunk_bytes))
        return SttAccountingCase(
            body=body,
            raw=FakeTranscriptionRaw(headers=headers, chunks=chunks),
            audio=audio,
            reserved_audio_millis=reserved_audio_millis,
        )

    return create


class FakeSpeechRaw:
    def __init__(self, chunks: tuple[bytes, ...], headers: dict[str, str] | None = None) -> None:
        self.headers = headers or {"x-request-id": "req_tts_1"}
        self._chunks = chunks
        self.request_id = self.headers.get("x-request-id")

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def iter_bytes(self, *, chunk_size: int):
        for chunk in self._chunks:
            for offset in range(0, len(chunk), chunk_size):
                yield chunk[offset : offset + chunk_size]


class FakeSpeechClient:
    def __init__(self, raw: FakeSpeechRaw) -> None:
        self.raw = raw
        self.sent_body: dict[str, object] = {}
        create = self._create
        self.audio = SimpleNamespace(
            speech=SimpleNamespace(with_streaming_response=SimpleNamespace(create=create))
        )

    def _create(self, **kwargs):
        self.sent_body = dict(kwargs)
        return self.raw


class TtsAccountingCase:
    def __init__(
        self,
        *,
        text: str,
        reserved_characters: int,
        binary_chunks: tuple[bytes, ...],
        response_headers: dict[str, str] | None = None,
    ) -> None:
        body = canonical_mapping_bytes(
            {
                "input": text,
                "model": "tts-1",
                "response_format": "pcm",
                "voice": "alloy",
            }
        )
        commitment = commit_private(ROOT, KEY_ID, "provider.request.cloud_tts", body)
        self.route = _route(
            purpose="cloud_tts",
            request_id=uuid4(),
            commitment=commitment,
            model="tts-1",
            max_input_bytes=len(body),
            max_input_units=reserved_characters,
        )
        self.request = AuthorizedSynthesisRequest(
            request_id=self.route.request_id,
            turn_id=self.route.turn_id,
            text=text,
            text_commitment=commitment,
            segment_index=0,
            segment_count=1,
            language="hinglish",
            dlp_receipt_id=uuid4(),
            route=self.route,
        )
        self.gateway = RecordingStreamGateway()
        self.client = FakeSpeechClient(FakeSpeechRaw(binary_chunks, response_headers))
        self.adapter = OpenAITTS(self.client, self.gateway, ROOT, FixedClock())
        self.events: list[str] = []

    @property
    def sent_body(self):
        return self.client.sent_body

    @property
    def receipt(self):
        assert self.gateway.observation is not None
        return SimpleNamespace(
            accounting_basis="request_bound_exact",
            billable_usage=TtsUsageUnits(category="tts", characters=len(self.request.text)),
        )

    async def settle(self):
        return SimpleNamespace(
            charged_micros_sgd=23,
            conservative_estimate_used=False,
        )


@pytest.fixture
def tts_accounting_case():
    async def create(
        *,
        text: str = "Hello नमस्ते",
        reserved_characters: int | None = None,
        binary_chunks: tuple[bytes, ...] = (b"pcm-1", b"pcm-2"),
        response_headers: dict[str, str] | None = None,
        **_ignored,
    ) -> TtsAccountingCase:
        return TtsAccountingCase(
            text=text,
            reserved_characters=len(text) if reserved_characters is None else reserved_characters,
            binary_chunks=binary_chunks,
            response_headers=response_headers,
        )

    return create
