from __future__ import annotations

import pytest
from tuntun_contracts.base import Sensitivity
from tuntun_contracts.commitments import commit_private
from tuntun_contracts.provider import RouteAuthorization
from tuntun_contracts.speech import AudioFormat, AuthorizedTranscriptionRequest
from tuntun_core.adapters.openai.transcribe import OpenAITranscriber

from tests.contract.openai.conftest import FakeTranscriptionRaw, RecordingSendGateway

ROOT = b"o" * 32
KEY_ID = "route-hmac-v1"


def _route(commitment, *, max_input_bytes: int) -> RouteAuthorization:
    from datetime import UTC, datetime
    from uuid import uuid4

    return RouteAuthorization(
        authorization_id=uuid4(),
        request_id=uuid4(),
        attempt_id=uuid4(),
        purpose="cloud_stt",
        household_id=uuid4(),
        subject_id=uuid4(),
        session_id=uuid4(),
        turn_id=uuid4(),
        provider="openai",
        model="gpt-transcribe",
        request_commitment=commitment,
        max_input_bytes=max_input_bytes,
        max_input_units=90_000,
        privacy_receipt_id=uuid4(),
        consent_receipt_ids=(uuid4(),),
        budget_reservation_id=uuid4(),
        maximum_sensitivity=Sensitivity.PERSONAL,
        expires_at=datetime(2026, 8, 27, tzinfo=UTC),
    )


class _Client:
    def __init__(self) -> None:
        from types import SimpleNamespace

        raw = FakeTranscriptionRaw(
            chunks=(b'{"text":"ok","usage":{"type":"duration","seconds":1}}',)
        )
        self.audio = SimpleNamespace(
            transcriptions=SimpleNamespace(
                with_streaming_response=SimpleNamespace(create=lambda **_kwargs: raw)
            )
        )


class _Clock:
    def now(self):
        from datetime import UTC, datetime

        return datetime(2026, 8, 27, tzinfo=UTC)


@pytest.mark.asyncio
async def test_stt_rejects_chunk_type_and_capacity_before_extending_buffer() -> None:
    audio = b"RIFF" + b"0" * 16
    commitment = commit_private(ROOT, KEY_ID, "provider.request.cloud_stt", audio)
    route = _route(commitment, max_input_bytes=len(audio))
    request = AuthorizedTranscriptionRequest(
        request_id=route.request_id,
        turn_id=route.turn_id,
        audio_format=AudioFormat(
            sample_format="s16le",
            sample_rate_hz=16_000,
            channels=1,
            interleaved=True,
            channel_layout="mono",
        ),
        audio_commitment=commitment,
        audio_bytes=len(audio),
        duration_ms=1_000,
        language_hints=("en", "hi"),
        route=route,
    )
    gateway = RecordingSendGateway()
    adapter = OpenAITranscriber(_Client(), gateway, ROOT, _Clock())

    async def hostile_audio():
        yield bytearray(audio)

    with pytest.raises(TypeError, match="audio chunk"):
        await adapter.transcribe(request, hostile_audio())

    assert gateway.calls == 0
    assert adapter.peak_audio_buffer_bytes == 0
