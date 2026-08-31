from __future__ import annotations

import asyncio
import copy
import json
import pickle
from collections.abc import AsyncIterator
from uuid import UUID

import pytest
from tuntun_contracts.poc.framing import TRANSPORT_AUDIO_FORMAT
from tuntun_contracts.provider import ProviderResponse, SanitizedProviderRequest
from tuntun_contracts.speech import (
    AudioFormat,
    AuthorizedSynthesisRequest,
    AuthorizedTranscriptionRequest,
    TranscriptResult,
)
from tuntun_core.services.poc.ports import (
    CapturedTurn,
    CapturedTurnError,
    CorePttEvent,
    CorePttInputPort,
    MonotonicClock,
    ProviderCancellationPort,
    PttBridgePort,
    VoiceAttemptAuthorizerPort,
)

TURN_ID = UUID("10000000-0000-4000-8000-000000000001")


class _Input:
    async def receive(self) -> CorePttEvent:
        return CorePttEvent.START

    async def close(self) -> None:
        return None


class _Bridge:
    async def receive(self, max_bytes: int) -> bytes:
        return b"" if max_bytes > 0 else b""

    async def send(self, frame: bytes) -> None:
        return None

    async def close(self) -> None:
        return None


class _Cancellation:
    async def close_active_transport(self, *, turn_id: UUID) -> None:
        return None


class _Clock:
    def now(self) -> float:
        return 0.0

    async def sleep_until(self, deadline: float) -> None:
        await asyncio.sleep(0)


class _Authorizer:
    async def authorize_transcription(
        self,
        *,
        turn_id: UUID,
        audio_format: AudioFormat,
        pcm: memoryview,
        duration_ms: int,
        language_hints: tuple[str, ...],
    ) -> AuthorizedTranscriptionRequest:
        raise NotImplementedError

    async def authorize_reasoning(
        self,
        *,
        turn_id: UUID,
        transcript: TranscriptResult,
    ) -> SanitizedProviderRequest:
        raise NotImplementedError

    async def authorize_synthesis(
        self,
        *,
        turn_id: UUID,
        response: ProviderResponse,
    ) -> AuthorizedSynthesisRequest:
        raise NotImplementedError


def test_core_local_ports_have_the_frozen_runtime_shape() -> None:
    assert {event.value for event in CorePttEvent} == {"start", "submit", "cancel"}
    assert isinstance(_Input(), CorePttInputPort)
    assert isinstance(_Bridge(), PttBridgePort)
    assert isinstance(_Cancellation(), ProviderCancellationPort)
    assert isinstance(_Clock(), MonotonicClock)
    assert isinstance(_Authorizer(), VoiceAttemptAuthorizerPort)


def test_captured_turn_transfers_the_exact_mutable_buffer_once() -> None:
    pcm = bytearray(b"\x01\x00\x02\x00")
    captured = CapturedTurn.take_ownership(
        turn_id=TURN_ID,
        audio_format=TRANSPORT_AUDIO_FORMAT,
        pcm=pcm,
    )

    assert captured.turn_id == TURN_ID
    assert captured.audio_format == TRANSPORT_AUDIO_FORMAT
    assert captured.audio_bytes == 4
    assert captured.duration_ms == 1
    assert captured.claim_pcm() is pcm
    captured.clear()
    assert pcm == bytearray(b"\x01\x00\x02\x00")

    with pytest.raises(CapturedTurnError, match="^captured-turn-unavailable$"):
        captured.claim_pcm()


def test_captured_turn_clear_zeroes_and_releases_owned_pcm() -> None:
    pcm = bytearray(b"private-pcm-even")
    captured = CapturedTurn.take_ownership(
        turn_id=TURN_ID,
        audio_format=TRANSPORT_AUDIO_FORMAT,
        pcm=pcm,
    )

    captured.clear()

    assert pcm == bytearray()
    captured.clear()
    with pytest.raises(CapturedTurnError, match="^captured-turn-unavailable$"):
        captured.claim_pcm()


@pytest.mark.parametrize("mutation", ["content", "resize"])
def test_captured_turn_rejects_alias_mutation_before_claim(mutation: str) -> None:
    pcm = bytearray(b"\x01\x00\x02\x00")
    captured = CapturedTurn.take_ownership(
        turn_id=TURN_ID,
        audio_format=TRANSPORT_AUDIO_FORMAT,
        pcm=pcm,
    )

    if mutation == "content":
        pcm[0] ^= 0xFF
    else:
        pcm.extend(b"\x03\x00")

    with pytest.raises(CapturedTurnError, match="^captured-turn-unavailable$"):
        captured.claim_pcm()

    assert pcm == bytearray()
    with pytest.raises(CapturedTurnError, match="^captured-turn-unavailable$"):
        captured.claim_pcm()


@pytest.mark.parametrize(
    "audio_format,pcm",
    [
        (TRANSPORT_AUDIO_FORMAT, b"\x00\x00"),
        (TRANSPORT_AUDIO_FORMAT, bytearray()),
        (TRANSPORT_AUDIO_FORMAT, bytearray(b"\x00")),
        (
            AudioFormat(
                sample_format="s16le",
                sample_rate_hz=24_000,
                channels=1,
                interleaved=False,
                channel_layout="mono",
            ),
            bytearray(b"\x00\x00"),
        ),
        (TRANSPORT_AUDIO_FORMAT, bytearray(2 * 16_000 * 90 + 2)),
    ],
)
def test_captured_turn_rejects_non_transport_or_unbounded_pcm(
    audio_format: AudioFormat,
    pcm: object,
) -> None:
    with pytest.raises((TypeError, ValueError)) as error:
        CapturedTurn.take_ownership(
            turn_id=TURN_ID,
            audio_format=audio_format,
            pcm=pcm,  # type: ignore[arg-type]
        )

    assert str(TURN_ID) not in str(error.value)
    assert "private" not in str(error.value)


def test_captured_turn_rejects_scalar_spoofed_transport_format() -> None:
    spoofed = AudioFormat.model_construct(
        sample_format="s16le",
        sample_rate_hz=16_000.0,
        channels=1.0,
        interleaved=False,
        channel_layout="mono",
    )
    pcm = bytearray(b"\x01\x00")

    with pytest.raises(ValueError, match="^invalid-captured-turn$"):
        CapturedTurn.take_ownership(
            turn_id=TURN_ID,
            audio_format=spoofed,
            pcm=pcm,
        )

    assert pcm == bytearray(b"\x01\x00")


def test_captured_turn_accepts_the_exact_ninety_second_sample_limit() -> None:
    pcm = bytearray(2 * 16_000 * 90)
    captured = CapturedTurn.take_ownership(
        turn_id=TURN_ID,
        audio_format=TRANSPORT_AUDIO_FORMAT,
        pcm=pcm,
    )

    assert captured.audio_bytes == 2_880_000
    assert captured.duration_ms == 90_000
    captured.clear()
    assert pcm == bytearray()


def test_captured_turn_rejects_copy_equality_and_serialization_without_content() -> None:
    secret = bytearray(b"\x19\x00\x20\x00")
    captured = CapturedTurn.take_ownership(
        turn_id=TURN_ID,
        audio_format=TRANSPORT_AUDIO_FORMAT,
        pcm=secret,
    )

    assert repr(captured) == "CapturedTurn(<redacted>)"
    operations = (
        lambda: copy.copy(captured),
        lambda: copy.deepcopy(captured),
        lambda: pickle.dumps(captured),
        lambda: json.dumps(captured),
        lambda: captured == captured,
    )
    for operation in operations:
        with pytest.raises((CapturedTurnError, TypeError)) as error:
            operation()
        assert str(TURN_ID) not in repr(error.value)
        assert "19" not in repr(error.value)
        assert "20" not in repr(error.value)

    captured.clear()


def test_captured_turn_cleanup_is_safe_after_rejected_partial_construction() -> None:
    partial = object.__new__(CapturedTurn)

    partial.clear()
    partial.clear()

    assert repr(partial) == "CapturedTurn(<redacted>)"


async def _empty_audio() -> AsyncIterator[bytes]:
    if False:
        yield b""
