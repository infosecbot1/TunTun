from __future__ import annotations

import asyncio
import base64
from collections.abc import AsyncIterator, Awaitable, Iterable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, cast
from unicodedata import normalize
from uuid import UUID

import pytest
from tuntun_contracts.base import Commitment, Sensitivity
from tuntun_contracts.poc.framing import (
    MAX_DIRECTION_BYTES,
    TRANSPORT_AUDIO_FORMAT,
)
from tuntun_contracts.provider import (
    ProviderName,
    ProviderResponse,
    RouteAuthorization,
    SanitizedProviderMessage,
    SanitizedProviderRequest,
    SanitizedToolReference,
)
from tuntun_contracts.speech import (
    AudioFormat,
    AuthorizedSynthesisRequest,
    AuthorizedTranscriptionRequest,
    SpeechChunk,
    TranscriptResult,
)
from tuntun_core.services.poc import deadlines as deadline_module
from tuntun_core.services.poc import voice_turn as voice_turn_module
from tuntun_core.services.poc.deadlines import DeadlineCleanupIncomplete
from tuntun_core.services.poc.ports import CapturedTurn
from tuntun_core.services.poc.voice_turn import VoiceTurnError, VoiceTurnPipeline

TURN_ID = UUID("20000000-0000-4000-8000-000000000001")
OTHER_TURN_ID = UUID("20000000-0000-4000-8000-000000000002")
STT_REQUEST_ID = UUID("21000000-0000-4000-8000-000000000001")
LLM_REQUEST_ID = UUID("22000000-0000-4000-8000-000000000001")
TTS_REQUEST_ID = UUID("23000000-0000-4000-8000-000000000001")
NOW = datetime(2026, 9, 1, tzinfo=UTC)
COMMITMENT = Commitment(
    algorithm="HMAC-SHA-256",
    key_id="task3-test-key",
    value_b64="A" * 43 + "=",
)
TTS_SOURCE_FORMAT = AudioFormat(
    sample_format="s16le",
    sample_rate_hz=24_000,
    channels=1,
    interleaved=False,
    channel_layout="mono",
)


class _FatalProbe(BaseException):
    pass


class _Clock:
    def __init__(self) -> None:
        self.current = 0.0
        self.sleepers: list[tuple[float, asyncio.Event]] = []
        self.sleep_entered = asyncio.Event()

    def now(self) -> float:
        return self.current

    async def sleep_until(self, deadline: float) -> None:
        release = asyncio.Event()
        self.sleepers.append((deadline, release))
        self.sleep_entered.set()
        await release.wait()

    def expire(self, deadline: float) -> None:
        self.current = deadline
        released = False
        for scheduled, event in self.sleepers:
            if scheduled == deadline:
                event.set()
                released = True
        assert released


def _uuid(prefix: int) -> UUID:
    return UUID(int=prefix)


def _route(
    purpose: Literal["cloud_stt", "cloud_reasoning", "cloud_tts"],
    request_id: UUID,
    *,
    turn_id: UUID = TURN_ID,
) -> RouteAuthorization:
    model = {
        "cloud_stt": "fake-stt",
        "cloud_reasoning": "fake-llm",
        "cloud_tts": "fake-tts",
    }[purpose]
    discriminator = {
        "cloud_stt": 1,
        "cloud_reasoning": 2,
        "cloud_tts": 3,
    }[purpose]
    return RouteAuthorization(
        authorization_id=_uuid(100 + discriminator),
        request_id=request_id,
        attempt_id=_uuid(200 + discriminator),
        purpose=purpose,
        household_id=_uuid(300),
        subject_id=None,
        session_id=_uuid(400),
        turn_id=turn_id,
        provider="openai",
        model=model,
        request_commitment=COMMITMENT,
        max_input_bytes=MAX_DIRECTION_BYTES,
        max_input_units=90_000,
        privacy_receipt_id=_uuid(500 + discriminator),
        consent_receipt_ids=(_uuid(600 + discriminator),),
        budget_reservation_id=_uuid(700 + discriminator),
        maximum_sensitivity=Sensitivity.PUBLIC,
        expires_at=NOW + timedelta(minutes=5),
    )


def _stt_request(*, turn_id: UUID = TURN_ID) -> AuthorizedTranscriptionRequest:
    return AuthorizedTranscriptionRequest(
        request_id=STT_REQUEST_ID,
        turn_id=turn_id,
        audio_format=TRANSPORT_AUDIO_FORMAT,
        audio_commitment=COMMITMENT,
        audio_bytes=8,
        duration_ms=1,
        language_hints=("en", "hi"),
        route=_route("cloud_stt", STT_REQUEST_ID, turn_id=turn_id),
    )


def _transcript(language: Literal["en", "hi", "hinglish"]) -> TranscriptResult:
    text = {
        "en": "What is our plan?",
        "hi": "हमारी योजना क्या है?",
        "hinglish": "Hamari plan kya hai?",
    }[language]
    return TranscriptResult(
        request_id=STT_REQUEST_ID,
        text=text,
        language=language,
        duration_ms=1,
    )


def _reasoning_request(transcript: TranscriptResult) -> SanitizedProviderRequest:
    return SanitizedProviderRequest(
        request_id=LLM_REQUEST_ID,
        provider=ProviderName.OPENAI,
        model="fake-llm",
        messages=(SanitizedProviderMessage(role="user", content=transcript.text),),
        allowed_tools=(),
        max_output_tokens=512,
        store=False,
        redaction_receipt_id=_uuid(800),
        route=_route("cloud_reasoning", LLM_REQUEST_ID),
        timeout_ms=45_000,
    )


def _response(language: Literal["en", "hi", "hinglish"]) -> ProviderResponse:
    text = {
        "en": "Here is the family plan.",
        "hi": "यह परिवार की योजना है।",
        "hinglish": "Yeh family ka plan hai.",
    }[language]
    return ProviderResponse(
        request_id=LLM_REQUEST_ID,
        text=text,
        language=language,
        provider_usage_receipt_id=None,
    )


def _synthesis_request(response: ProviderResponse) -> AuthorizedSynthesisRequest:
    return AuthorizedSynthesisRequest(
        request_id=TTS_REQUEST_ID,
        turn_id=TURN_ID,
        text=response.text,
        text_commitment=COMMITMENT,
        segment_index=0,
        segment_count=1,
        language=response.language,
        dlp_receipt_id=_uuid(900),
        route=_route("cloud_tts", TTS_REQUEST_ID),
    )


class _TrackedIterator:
    def __init__(self, items: Iterable[object]) -> None:
        self._items = iter(items)
        self.closed = 0

    def __aiter__(self) -> _TrackedIterator:
        return self

    async def __anext__(self) -> object:
        try:
            item = next(self._items)
        except StopIteration:
            raise StopAsyncIteration from None
        if isinstance(item, BaseException):
            raise item
        return item

    async def aclose(self) -> None:
        self.closed += 1


class _SplitAsyncIterable:
    def __init__(self, inner: AsyncIterator[object]) -> None:
        self.inner = inner
        self.closed = 0

    def __aiter__(self) -> AsyncIterator[object]:
        return self.inner

    async def aclose(self) -> None:
        self.closed += 1


class _BodyCloseIterator:
    def __init__(self, body: object, close_error: BaseException | None) -> None:
        self.body = body
        self.close_error = close_error
        self.started = False
        self.closed = 0

    def __aiter__(self) -> _BodyCloseIterator:
        return self

    async def __anext__(self) -> object:
        if self.started:
            raise StopAsyncIteration
        self.started = True
        if isinstance(self.body, BaseException):
            raise self.body
        return self.body

    async def aclose(self) -> None:
        self.closed += 1
        if self.close_error is not None:
            raise self.close_error


class _CancelRaisesFuture(asyncio.Future[None]):
    def __init__(self, error: BaseException) -> None:
        super().__init__()
        self.error = error
        self.cancel_calls = 0
        self.cancel_entered = asyncio.Event()

    def cancel(self, msg: object | None = None) -> bool:
        self.cancel_calls += 1
        self.cancel_entered.set()
        raise self.error


class _CancelRaisesAfterSettlingFuture(asyncio.Future[None]):
    def __init__(self, cancel_error: BaseException, terminal_error: BaseException) -> None:
        super().__init__()
        self.cancel_error = cancel_error
        self.terminal_error = terminal_error
        self.cancel_calls = 0

    def cancel(self, msg: object | None = None) -> bool:
        self.cancel_calls += 1
        self.set_exception(self.terminal_error)
        raise self.cancel_error


class _CancellationSuppressingIterator(_TrackedIterator):
    def __init__(self, late_items: Iterable[object] = ()) -> None:
        super().__init__(late_items)
        self.entered = asyncio.Event()
        self.cancelled = asyncio.Event()
        self.release = asyncio.Event()

    async def __anext__(self) -> object:
        self.entered.set()
        while not self.release.is_set():
            try:
                await self.release.wait()
            except asyncio.CancelledError:
                self.cancelled.set()
        return await super().__anext__()


class _CancellationSuppressingCloseIterator(_TrackedIterator):
    def __init__(self, items: Iterable[object]) -> None:
        super().__init__(items)
        self.close_entered = asyncio.Event()
        self.close_cancelled = asyncio.Event()
        self.release_close = asyncio.Event()

    async def aclose(self) -> None:
        self.closed += 1
        self.close_entered.set()
        while not self.release_close.is_set():
            try:
                await self.release_close.wait()
            except asyncio.CancelledError:
                self.close_cancelled.set()


class _Authorizer:
    def __init__(
        self,
        *,
        stt_request: object,
        reasoning_request: object,
        synthesis_request: object,
        events: list[str],
    ) -> None:
        self.stt_request = stt_request
        self.reasoning_request = reasoning_request
        self.synthesis_request = synthesis_request
        self.events = events
        self.transcription_calls = 0
        self.reasoning_calls = 0
        self.synthesis_calls = 0
        self.observed_audio: bytes | None = None
        self.observed_readonly: bool | None = None
        self.observed_hints: tuple[str, ...] | None = None
        self.retained_view: memoryview | None = None

    async def authorize_transcription(
        self,
        *,
        turn_id: UUID,
        audio_format: AudioFormat,
        pcm: memoryview,
        duration_ms: int,
        language_hints: tuple[Literal["en", "hi"], ...],
    ) -> AuthorizedTranscriptionRequest:
        self.events.append("authorize.stt")
        self.transcription_calls += 1
        assert turn_id == TURN_ID
        assert audio_format == TRANSPORT_AUDIO_FORMAT
        assert duration_ms == 1
        self.observed_audio = bytes(pcm)
        self.observed_readonly = pcm.readonly
        self.observed_hints = language_hints
        self.retained_view = pcm
        return cast(AuthorizedTranscriptionRequest, self.stt_request)

    async def authorize_reasoning(
        self,
        *,
        turn_id: UUID,
        transcript: TranscriptResult,
    ) -> SanitizedProviderRequest:
        self.events.append("authorize.reasoning")
        self.reasoning_calls += 1
        assert turn_id == TURN_ID
        return cast(SanitizedProviderRequest, self.reasoning_request)

    async def authorize_synthesis(
        self,
        *,
        turn_id: UUID,
        response: ProviderResponse,
    ) -> AuthorizedSynthesisRequest:
        self.events.append("authorize.synthesis")
        self.synthesis_calls += 1
        assert turn_id == TURN_ID
        return cast(AuthorizedSynthesisRequest, self.synthesis_request)


class _Stt:
    def __init__(self, result: object, events: list[str]) -> None:
        self.result = result
        self.events = events
        self.calls = 0
        self.observed_audio: bytes | None = None
        self.audio_iterator: AsyncIterator[bytes] | None = None

    async def transcribe(
        self,
        request: AuthorizedTranscriptionRequest,
        audio: AsyncIterator[bytes],
    ) -> TranscriptResult:
        self.events.append("stt")
        self.calls += 1
        self.audio_iterator = audio
        self.observed_audio = b"".join([chunk async for chunk in audio])
        if isinstance(self.result, BaseException):
            raise self.result
        return cast(TranscriptResult, self.result)


class _Llm:
    def __init__(self, result: object, events: list[str]) -> None:
        self.result = result
        self.events = events
        self.calls = 0

    async def complete(self, request: SanitizedProviderRequest) -> ProviderResponse:
        self.events.append("llm")
        self.calls += 1
        if isinstance(self.result, BaseException):
            raise self.result
        return cast(ProviderResponse, self.result)


class _Tts:
    def __init__(self, stream: _TrackedIterator, events: list[str]) -> None:
        self.stream = stream
        self.events = events
        self.calls = 0

    def synthesize(self, request: AuthorizedSynthesisRequest) -> AsyncIterator[SpeechChunk]:
        self.events.append("tts")
        self.calls += 1
        return cast(AsyncIterator[SpeechChunk], self.stream)


class _Converter:
    def __init__(self, stream: _TrackedIterator, events: list[str]) -> None:
        self.stream = stream
        self.events = events
        self.calls = 0
        self.source: AudioFormat | None = None
        self.target: AudioFormat | None = None
        self.observed_source = b""
        self.input_iterator: AsyncIterator[bytes] | None = None

    def convert(
        self,
        audio: AsyncIterator[bytes],
        source: AudioFormat,
        target: AudioFormat,
    ) -> AsyncIterator[bytes]:
        self.events.append("convert")
        self.calls += 1
        self.source = source
        self.target = target
        self.input_iterator = audio
        return self._convert(audio)

    async def _convert(self, audio: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
        self.observed_source = b"".join([chunk async for chunk in audio])
        try:
            async for item in self.stream:
                yield cast(bytes, item)
        finally:
            await self.stream.aclose()


@dataclass(slots=True)
class _Harness:
    pipeline: VoiceTurnPipeline
    authorizer: _Authorizer
    stt: _Stt
    llm: _Llm
    tts: _Tts
    converter: _Converter
    capture_pcm: bytearray
    source_pcm: bytes
    converted_pcm: bytes

    def captured(self) -> CapturedTurn:
        return CapturedTurn.take_ownership(
            turn_id=TURN_ID,
            audio_format=TRANSPORT_AUDIO_FORMAT,
            pcm=self.capture_pcm,
        )


def _harness(
    language: Literal["en", "hi", "hinglish"] = "en",
    *,
    stt_request: object | None = None,
    transcript: object | None = None,
    reasoning_request: object | None = None,
    response: object | None = None,
    synthesis_request: object | None = None,
    speech_items: Iterable[object] | None = None,
    converted_items: Iterable[object] | None = None,
    source_format: AudioFormat = TTS_SOURCE_FORMAT,
    clock: _Clock | None = None,
) -> _Harness:
    events: list[str] = []
    selected_transcript = transcript if transcript is not None else _transcript(language)
    typed_transcript = cast(TranscriptResult, selected_transcript)
    selected_response = response if response is not None else _response(language)
    typed_response = cast(ProviderResponse, selected_response)
    source_pcm = bytes(index % 251 for index in range(9_612))
    converted_pcm = bytes(255 - index % 251 for index in range(6_408))
    selected_speech = speech_items
    if selected_speech is None:
        selected_speech = (
            SpeechChunk(
                request_id=TTS_REQUEST_ID,
                sequence=0,
                pcm=source_pcm[:4_000],
                final=False,
            ),
            SpeechChunk(
                request_id=TTS_REQUEST_ID,
                sequence=1,
                pcm=source_pcm[4_000:],
                final=False,
            ),
            SpeechChunk(
                request_id=TTS_REQUEST_ID,
                sequence=2,
                pcm=b"",
                final=True,
            ),
        )
    selected_converted = converted_items if converted_items is not None else (converted_pcm,)
    authorizer = _Authorizer(
        stt_request=stt_request if stt_request is not None else _stt_request(),
        reasoning_request=(
            reasoning_request
            if reasoning_request is not None
            else _reasoning_request(typed_transcript)
        ),
        synthesis_request=(
            synthesis_request
            if synthesis_request is not None
            else _synthesis_request(typed_response)
        ),
        events=events,
    )
    stt = _Stt(selected_transcript, events)
    llm = _Llm(selected_response, events)
    tts = _Tts(_TrackedIterator(selected_speech), events)
    converter = _Converter(_TrackedIterator(selected_converted), events)
    return _Harness(
        pipeline=VoiceTurnPipeline(
            stt=stt,
            llm=llm,
            tts=tts,
            authorizer=authorizer,
            converter=converter,
            tts_source_format=source_format,
            clock=clock if clock is not None else _Clock(),
        ),
        authorizer=authorizer,
        stt=stt,
        llm=llm,
        tts=tts,
        converter=converter,
        capture_pcm=bytearray(b"\x01\x00\x02\x00\x03\x00\x04\x00"),
        source_pcm=source_pcm,
        converted_pcm=converted_pcm,
    )


async def _collect(stream: AsyncIterator[SpeechChunk]) -> tuple[SpeechChunk, ...]:
    return tuple([chunk async for chunk in stream])


@pytest.mark.asyncio
async def test_pipeline_stt_deadline_includes_authorization_and_clears_capture() -> None:
    clock = _Clock()
    harness = _harness(clock=clock)
    blocked = asyncio.Event()

    async def stalled_authorization(**_: object) -> AuthorizedTranscriptionRequest:
        await blocked.wait()
        return _stt_request()

    harness.authorizer.authorize_transcription = stalled_authorization  # type: ignore[method-assign]
    run = asyncio.create_task(_collect(harness.pipeline.run(harness.captured())))
    await clock.sleep_entered.wait()

    clock.expire(30.0)

    with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$"):
        await run
    assert harness.stt.calls == 0
    assert harness.llm.calls == 0
    assert harness.tts.calls == 0
    assert harness.capture_pcm == bytearray()


@pytest.mark.asyncio
async def test_pipeline_reasoning_deadline_includes_authorization() -> None:
    clock = _Clock()
    harness = _harness(clock=clock)
    blocked = asyncio.Event()

    async def stalled_authorization(**_: object) -> SanitizedProviderRequest:
        await blocked.wait()
        return _reasoning_request(_transcript("en"))

    harness.authorizer.authorize_reasoning = stalled_authorization  # type: ignore[method-assign]
    run = asyncio.create_task(_collect(harness.pipeline.run(harness.captured())))
    while harness.stt.calls == 0 or not clock.sleepers:
        await asyncio.sleep(0)
    clock.sleep_entered.clear()
    while len(clock.sleepers) < 3:
        await asyncio.sleep(0)

    clock.expire(45.0)

    with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$"):
        await run
    assert harness.llm.calls == 0
    assert harness.tts.calls == 0
    assert harness.capture_pcm == bytearray()


@pytest.mark.asyncio
async def test_pipeline_tts_deadline_contains_source_iteration_and_conversion() -> None:
    clock = _Clock()
    harness = _harness(clock=clock)
    blocked = asyncio.Event()
    entered = asyncio.Event()

    async def stalled_source() -> AsyncIterator[SpeechChunk]:
        entered.set()
        await blocked.wait()
        yield SpeechChunk(request_id=TTS_REQUEST_ID, sequence=0, pcm=b"\x00\x00", final=False)

    harness.tts.synthesize = lambda _request: stalled_source()  # type: ignore[method-assign]
    run = asyncio.create_task(_collect(harness.pipeline.run(harness.captured())))
    await entered.wait()
    while not any(deadline == 30.0 for deadline, _ in clock.sleepers):
        await asyncio.sleep(0)

    clock.expire(30.0)

    with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$"):
        await run
    assert harness.converter.calls == 0
    assert harness.capture_pcm == bytearray()


@pytest.mark.asyncio
async def test_pipeline_closes_tts_stream_acquired_at_the_inclusive_deadline() -> None:
    clock = _Clock()
    harness = _harness(clock=clock)
    source = harness.tts.stream

    def synthesize_at_deadline(
        request: AuthorizedSynthesisRequest,
    ) -> AsyncIterator[SpeechChunk]:
        harness.tts.calls += 1
        harness.tts.events.append("tts")
        clock.current = 30.0
        return cast(AsyncIterator[SpeechChunk], source)

    harness.tts.synthesize = synthesize_at_deadline  # type: ignore[method-assign]

    with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$"):
        await _collect(harness.pipeline.run(harness.captured()))

    assert source.closed == 1
    assert harness.converter.calls == 0
    assert harness.capture_pcm == bytearray()


@pytest.mark.parametrize("stage", ["source", "converter"])
@pytest.mark.asyncio
async def test_malformed_coroutine_stream_is_closed(stage: str) -> None:
    harness = _harness()

    async def private_malformed_stream() -> None:
        await asyncio.Event().wait()

    malformed = private_malformed_stream()
    if stage == "source":

        def malformed_source(
            request: AuthorizedSynthesisRequest,
        ) -> AsyncIterator[SpeechChunk]:
            harness.tts.calls += 1
            return cast(AsyncIterator[SpeechChunk], malformed)

        harness.tts.synthesize = malformed_source  # type: ignore[method-assign]
    else:

        def malformed_conversion(
            audio: AsyncIterator[bytes],
            source: AudioFormat,
            target: AudioFormat,
        ) -> AsyncIterator[bytes]:
            harness.converter.calls += 1
            harness.converter.input_iterator = audio
            return cast(AsyncIterator[bytes], malformed)

        harness.converter.convert = malformed_conversion  # type: ignore[method-assign]

    try:
        with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$"):
            await _collect(harness.pipeline.run(harness.captured()))

        assert malformed.cr_frame is None
        assert harness.capture_pcm == bytearray()
        if stage == "converter":
            assert getattr(harness.converter.input_iterator, "ag_frame", None) is None
    finally:
        if malformed.cr_frame is not None:
            malformed.close()


@pytest.mark.parametrize("stage", ["source", "converter"])
@pytest.mark.asyncio
async def test_malformed_task_stream_is_passively_observed(stage: str) -> None:
    harness = _harness()
    entered = asyncio.Event()
    finalized = asyncio.Event()
    release = asyncio.Event()

    async def private_malformed_stream() -> None:
        entered.set()
        try:
            await release.wait()
        finally:
            finalized.set()

    malformed = asyncio.create_task(private_malformed_stream())
    await entered.wait()
    if stage == "source":

        def malformed_source(
            request: AuthorizedSynthesisRequest,
        ) -> AsyncIterator[SpeechChunk]:
            harness.tts.calls += 1
            return cast(AsyncIterator[SpeechChunk], malformed)

        harness.tts.synthesize = malformed_source  # type: ignore[method-assign]
    else:

        def malformed_conversion(
            audio: AsyncIterator[bytes],
            source: AudioFormat,
            target: AudioFormat,
        ) -> AsyncIterator[bytes]:
            harness.converter.calls += 1
            harness.converter.input_iterator = audio
            return cast(AsyncIterator[bytes], malformed)

        harness.converter.convert = malformed_conversion  # type: ignore[method-assign]

    try:
        with pytest.raises(
            DeadlineCleanupIncomplete,
            match="^deadline-cleanup-incomplete$",
        ):
            await _collect(harness.pipeline.run(harness.captured()))

        assert not malformed.done()
        assert malformed.cancelling() == 0
        assert not finalized.is_set()
        assert not await harness.pipeline.observe_quarantine(
            deadline=asyncio.get_running_loop().time() + 0.01
        )
        assert harness.capture_pcm == bytearray()
        if stage == "converter":
            assert getattr(harness.converter.input_iterator, "ag_frame", None) is None
    finally:
        release.set()
        await malformed
        await asyncio.sleep(0)
        drained = await harness.pipeline.observe_quarantine(
            deadline=asyncio.get_running_loop().time() + 0.1
        )
        assert drained, (
            harness.pipeline._deadlines._quarantine_snapshot(),  # noqa: SLF001
            harness.pipeline._deadlines._settled_tombstones,  # noqa: SLF001
        )


@pytest.mark.parametrize("stage", ["source", "converter"])
@pytest.mark.asyncio
async def test_malformed_future_stream_is_passively_observed(stage: str) -> None:
    harness = _harness()
    malformed: asyncio.Future[None] = asyncio.get_running_loop().create_future()
    if stage == "source":

        def malformed_source(
            request: AuthorizedSynthesisRequest,
        ) -> AsyncIterator[SpeechChunk]:
            harness.tts.calls += 1
            return cast(AsyncIterator[SpeechChunk], malformed)

        harness.tts.synthesize = malformed_source  # type: ignore[method-assign]
    else:

        def malformed_conversion(
            audio: AsyncIterator[bytes],
            source: AudioFormat,
            target: AudioFormat,
        ) -> AsyncIterator[bytes]:
            harness.converter.calls += 1
            harness.converter.input_iterator = audio
            return cast(AsyncIterator[bytes], malformed)

        harness.converter.convert = malformed_conversion  # type: ignore[method-assign]

    with pytest.raises(
        DeadlineCleanupIncomplete,
        match="^deadline-cleanup-incomplete$",
    ):
        await _collect(harness.pipeline.run(harness.captured()))

    assert not malformed.done()
    assert not malformed.cancelled()
    assert not await harness.pipeline.observe_quarantine(
        deadline=asyncio.get_running_loop().time() + 0.01
    )
    malformed.set_result(None)
    await asyncio.sleep(0)
    assert await harness.pipeline.observe_quarantine(
        deadline=asyncio.get_running_loop().time() + 0.1
    )
    assert harness.capture_pcm == bytearray()
    if stage == "converter":
        assert getattr(harness.converter.input_iterator, "ag_frame", None) is None


@pytest.mark.parametrize("stage", ["source", "converter"])
@pytest.mark.asyncio
async def test_malformed_sync_closable_stream_is_closed(stage: str) -> None:
    harness = _harness()

    class MalformedClosable:
        def __init__(self) -> None:
            self.close_calls = 0

        def close(self) -> None:
            self.close_calls += 1

    malformed = MalformedClosable()
    if stage == "source":

        def malformed_source(
            request: AuthorizedSynthesisRequest,
        ) -> AsyncIterator[SpeechChunk]:
            harness.tts.calls += 1
            return cast(AsyncIterator[SpeechChunk], malformed)

        harness.tts.synthesize = malformed_source  # type: ignore[method-assign]
    else:

        def malformed_conversion(
            audio: AsyncIterator[bytes],
            source: AudioFormat,
            target: AudioFormat,
        ) -> AsyncIterator[bytes]:
            harness.converter.calls += 1
            harness.converter.input_iterator = audio
            return cast(AsyncIterator[bytes], malformed)

        harness.converter.convert = malformed_conversion  # type: ignore[method-assign]

    with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$"):
        await _collect(harness.pipeline.run(harness.captured()))

    assert malformed.close_calls == 1
    assert harness.capture_pcm == bytearray()
    if stage == "converter":
        assert getattr(harness.converter.input_iterator, "ag_frame", None) is None


@pytest.mark.parametrize("stage", ["source", "converter"])
@pytest.mark.asyncio
async def test_malformed_stream_never_cancels_public_voice_owner(stage: str) -> None:
    harness = _harness()
    holder: dict[str, asyncio.Task[list[SpeechChunk]]] = {}
    if stage == "source":

        def malformed_source(
            request: AuthorizedSynthesisRequest,
        ) -> AsyncIterator[SpeechChunk]:
            harness.tts.calls += 1
            return cast(AsyncIterator[SpeechChunk], holder["owner"])

        harness.tts.synthesize = malformed_source  # type: ignore[method-assign]
    else:

        def malformed_conversion(
            audio: AsyncIterator[bytes],
            source: AudioFormat,
            target: AudioFormat,
        ) -> AsyncIterator[bytes]:
            harness.converter.calls += 1
            harness.converter.input_iterator = audio
            return cast(AsyncIterator[bytes], holder["owner"])

        harness.converter.convert = malformed_conversion  # type: ignore[method-assign]

    owner = asyncio.create_task(_collect(harness.pipeline.run(harness.captured())))
    holder["owner"] = owner

    with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$"):
        await asyncio.wait_for(owner, timeout=0.2)

    assert owner.done()
    assert not owner.cancelled()
    assert owner.cancelling() == 0
    assert harness.capture_pcm == bytearray()
    if stage == "converter":
        assert getattr(harness.converter.input_iterator, "ag_frame", None) is None


@pytest.mark.parametrize("stage", ["source", "converter"])
@pytest.mark.parametrize("outcome", ["cancelled", "ordinary"])
@pytest.mark.asyncio
async def test_done_task_preserves_cleanup_incomplete_from_existing_context(
    stage: str,
    outcome: str,
) -> None:
    error: BaseException = (
        asyncio.CancelledError("private-task-cancellation")
        if outcome == "cancelled"
        else RuntimeError("private-task-error")
    )
    error.__context__ = DeadlineCleanupIncomplete()

    async def finish() -> None:
        raise error

    malformed = asyncio.create_task(finish())
    await asyncio.sleep(0)
    assert malformed.done()
    harness = _harness()
    if stage == "source":

        def malformed_source(
            request: AuthorizedSynthesisRequest,
        ) -> AsyncIterator[SpeechChunk]:
            harness.tts.calls += 1
            return cast(AsyncIterator[SpeechChunk], malformed)

        harness.tts.synthesize = malformed_source  # type: ignore[method-assign]
    else:

        def malformed_conversion(
            audio: AsyncIterator[bytes],
            source: AudioFormat,
            target: AudioFormat,
        ) -> AsyncIterator[bytes]:
            harness.converter.calls += 1
            harness.converter.input_iterator = audio
            return cast(AsyncIterator[bytes], malformed)

        harness.converter.convert = malformed_conversion  # type: ignore[method-assign]

    with pytest.raises(
        DeadlineCleanupIncomplete,
        match="^deadline-cleanup-incomplete$",
    ) as failure:
        await _collect(harness.pipeline.run(harness.captured()))

    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert harness.capture_pcm == bytearray()


@pytest.mark.parametrize("stage", ["source", "converter"])
@pytest.mark.asyncio
async def test_close_preserves_cleanup_incomplete_from_existing_context(stage: str) -> None:
    close_error = RuntimeError("private-close-error")
    close_error.__context__ = DeadlineCleanupIncomplete()
    malformed = _BodyCloseIterator(object(), close_error)
    harness = _harness()
    if stage == "source":

        def malformed_source(
            request: AuthorizedSynthesisRequest,
        ) -> AsyncIterator[SpeechChunk]:
            harness.tts.calls += 1
            return cast(AsyncIterator[SpeechChunk], malformed)

        harness.tts.synthesize = malformed_source  # type: ignore[method-assign]
    else:

        def malformed_conversion(
            audio: AsyncIterator[bytes],
            source: AudioFormat,
            target: AudioFormat,
        ) -> AsyncIterator[bytes]:
            harness.converter.calls += 1
            harness.converter.input_iterator = audio
            return cast(AsyncIterator[bytes], malformed)

        harness.converter.convert = malformed_conversion  # type: ignore[method-assign]

    with pytest.raises(
        DeadlineCleanupIncomplete,
        match="^deadline-cleanup-incomplete$",
    ) as failure:
        await _collect(harness.pipeline.run(harness.captured()))

    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert malformed.closed == 1
    assert harness.capture_pcm == bytearray()


@pytest.mark.parametrize("stage", ["source", "converter"])
@pytest.mark.parametrize(
    "close_kind",
    ["ordinary", "cancelled", "fatal-group", "cleanup-incomplete", "scalar-fatal"],
)
@pytest.mark.asyncio
async def test_primary_scalar_fatal_precedes_all_close_outcomes(
    stage: str,
    close_kind: str,
) -> None:
    primary = _FatalProbe("first-body-fatal")
    close_error: BaseException
    if close_kind == "ordinary":
        close_error = RuntimeError("private-close-error")
    elif close_kind == "cancelled":
        close_error = asyncio.CancelledError("private-close-cancellation")
    elif close_kind == "fatal-group":
        close_error = BaseExceptionGroup(
            "private-close-group",
            [_FatalProbe("private-grouped-fatal")],
        )
    elif close_kind == "cleanup-incomplete":
        close_error = DeadlineCleanupIncomplete()
    else:
        close_error = _FatalProbe("later-close-fatal")
    malformed = _BodyCloseIterator(primary, close_error)
    harness = _harness()
    if stage == "source":

        def malformed_source(
            request: AuthorizedSynthesisRequest,
        ) -> AsyncIterator[SpeechChunk]:
            harness.tts.calls += 1
            return cast(AsyncIterator[SpeechChunk], malformed)

        harness.tts.synthesize = malformed_source  # type: ignore[method-assign]
    else:

        def malformed_conversion(
            audio: AsyncIterator[bytes],
            source: AudioFormat,
            target: AudioFormat,
        ) -> AsyncIterator[bytes]:
            harness.converter.calls += 1
            harness.converter.input_iterator = audio
            return cast(AsyncIterator[bytes], malformed)

        harness.converter.convert = malformed_conversion  # type: ignore[method-assign]

    with pytest.raises(_FatalProbe) as failure:
        await _collect(harness.pipeline.run(harness.captured()))

    assert failure.value is primary
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    traceback = failure.value.__traceback__
    while traceback is not None:
        assert traceback.tb_frame.f_code.co_name not in {
            "buffer_owned_source",
            "buffer_owned_conversion",
            "_buffer_source",
            "_buffer_converted",
            "_close_all",
            "_close",
        }
        traceback = traceback.tb_next
    assert malformed.closed == 1
    assert harness.capture_pcm == bytearray()


@pytest.mark.parametrize("stage", ["source", "converter"])
@pytest.mark.parametrize("cancel_kind", ["ordinary", "cleanup-incomplete", "scalar-fatal"])
@pytest.mark.asyncio
async def test_hostile_future_stream_cancel_hook_is_never_invoked(
    stage: str,
    cancel_kind: str,
) -> None:
    if cancel_kind == "ordinary":
        cancel_error: BaseException = RuntimeError("private-hostile-cancel")
    elif cancel_kind == "cleanup-incomplete":
        cancel_error = RuntimeError("private-hostile-cancel")
        cancel_error.__context__ = DeadlineCleanupIncomplete()
    else:
        cancel_error = _FatalProbe("hostile-cancel-fatal")
    malformed = _CancelRaisesFuture(cancel_error)
    harness = _harness()
    if stage == "source":

        def malformed_source(
            request: AuthorizedSynthesisRequest,
        ) -> AsyncIterator[SpeechChunk]:
            harness.tts.calls += 1
            return cast(AsyncIterator[SpeechChunk], malformed)

        harness.tts.synthesize = malformed_source  # type: ignore[method-assign]
    else:

        def malformed_conversion(
            audio: AsyncIterator[bytes],
            source: AudioFormat,
            target: AudioFormat,
        ) -> AsyncIterator[bytes]:
            harness.converter.calls += 1
            harness.converter.input_iterator = audio
            return cast(AsyncIterator[bytes], malformed)

        harness.converter.convert = malformed_conversion  # type: ignore[method-assign]

    with pytest.raises(
        DeadlineCleanupIncomplete,
        match="^deadline-cleanup-incomplete$",
    ) as failure:
        await _collect(harness.pipeline.run(harness.captured()))
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None

    assert not malformed.done()
    assert malformed.cancel_calls == 0
    assert not await harness.pipeline.observe_quarantine(
        deadline=asyncio.get_running_loop().time() + 0.01
    )
    malformed.set_result(None)
    await asyncio.sleep(0)
    assert await harness.pipeline.observe_quarantine(
        deadline=asyncio.get_running_loop().time() + 0.1
    )
    assert harness.capture_pcm == bytearray()


@pytest.mark.parametrize("stage", ["source", "converter"])
@pytest.mark.parametrize("cancel_kind", ["ordinary", "cleanup-incomplete"])
@pytest.mark.asyncio
async def test_hostile_future_late_terminal_scalar_is_sanitized_without_cancel(
    stage: str,
    cancel_kind: str,
) -> None:
    terminal = _FatalProbe("terminal-fatal")
    cancel_error: BaseException = RuntimeError("private-hostile-cancel")
    if cancel_kind == "cleanup-incomplete":
        cancel_error.__context__ = DeadlineCleanupIncomplete()
    malformed = _CancelRaisesAfterSettlingFuture(cancel_error, terminal)
    harness = _harness()
    if stage == "source":

        def malformed_source(
            request: AuthorizedSynthesisRequest,
        ) -> AsyncIterator[SpeechChunk]:
            harness.tts.calls += 1
            return cast(AsyncIterator[SpeechChunk], malformed)

        harness.tts.synthesize = malformed_source  # type: ignore[method-assign]
    else:

        def malformed_conversion(
            audio: AsyncIterator[bytes],
            source: AudioFormat,
            target: AudioFormat,
        ) -> AsyncIterator[bytes]:
            harness.converter.calls += 1
            harness.converter.input_iterator = audio
            return cast(AsyncIterator[bytes], malformed)

        harness.converter.convert = malformed_conversion  # type: ignore[method-assign]

    with pytest.raises(
        DeadlineCleanupIncomplete,
        match="^deadline-cleanup-incomplete$",
    ):
        await _collect(harness.pipeline.run(harness.captured()))

    assert not malformed.done()
    assert malformed.cancel_calls == 0
    malformed.set_exception(terminal)
    await asyncio.sleep(0)
    with pytest.raises(
        DeadlineCleanupIncomplete,
        match="^deadline-cleanup-incomplete$",
    ) as failure:
        await harness.pipeline.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.1)
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert harness.capture_pcm == bytearray()


@pytest.mark.asyncio
async def test_malformed_task_stream_is_retained_without_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deadline_module, "_CANCEL_OBSERVE_SECONDS", 0.01, raising=False)
    clock = _Clock()
    harness = _harness(clock=clock)
    entered = asyncio.Event()
    cancelled = asyncio.Event()
    release = asyncio.Event()

    async def private_malformed_stream() -> None:
        entered.set()
        while not release.is_set():
            try:
                await release.wait()
            except asyncio.CancelledError:
                cancelled.set()

    malformed = asyncio.create_task(private_malformed_stream())
    await entered.wait()

    def malformed_source(
        request: AuthorizedSynthesisRequest,
    ) -> AsyncIterator[SpeechChunk]:
        harness.tts.calls += 1
        return cast(AsyncIterator[SpeechChunk], malformed)

    harness.tts.synthesize = malformed_source  # type: ignore[method-assign]
    run = asyncio.create_task(_collect(harness.pipeline.run(harness.captured())))

    try:
        with pytest.raises(DeadlineCleanupIncomplete, match="^deadline-cleanup-incomplete$"):
            await asyncio.wait_for(run, timeout=0.2)
        assert not cancelled.is_set()
        assert malformed.cancelling() == 0
        assert not await harness.pipeline.observe_quarantine(
            deadline=asyncio.get_running_loop().time() + 0.01
        )
    finally:
        release.set()
        if not run.done():
            run.cancel()
        await asyncio.gather(run, return_exceptions=True)
        await malformed
        assert await harness.pipeline.observe_quarantine(
            deadline=asyncio.get_running_loop().time() + 0.1
        )

    assert harness.capture_pcm == bytearray()


@pytest.mark.parametrize("stage", ["source", "converter"])
@pytest.mark.asyncio
async def test_exact_deadline_close_is_bounded_and_retained_by_voice_quarantine(
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    monkeypatch.setattr(deadline_module, "_CANCEL_OBSERVE_SECONDS", 0.01, raising=False)
    clock = _Clock()
    harness = _harness(clock=clock)
    items: Iterable[object] = (
        _speech_for_size(len(harness.source_pcm)) if stage == "source" else (harness.converted_pcm,)
    )
    owned = _CancellationSuppressingCloseIterator(items)

    if stage == "source":

        def acquire_at_deadline(
            request: AuthorizedSynthesisRequest,
        ) -> AsyncIterator[SpeechChunk]:
            harness.tts.calls += 1
            harness.tts.events.append("tts")
            clock.current = 30.0
            return cast(AsyncIterator[SpeechChunk], owned)

        harness.tts.synthesize = acquire_at_deadline  # type: ignore[method-assign]
    else:

        def acquire_at_deadline(
            audio: AsyncIterator[bytes],
            source: AudioFormat,
            target: AudioFormat,
        ) -> AsyncIterator[bytes]:
            harness.converter.calls += 1
            harness.converter.input_iterator = audio
            clock.current = 30.0
            return cast(AsyncIterator[bytes], owned)

        harness.converter.convert = acquire_at_deadline  # type: ignore[method-assign]

    run = asyncio.create_task(_collect(harness.pipeline.run(harness.captured())))
    await owned.close_entered.wait()
    clock.expire(30.0)

    try:
        done, _ = await asyncio.wait({run}, timeout=0.3)
        assert run in done
        with pytest.raises(DeadlineCleanupIncomplete, match="^deadline-cleanup-incomplete$"):
            await run
        assert not owned.close_cancelled.is_set()
        assert not await harness.pipeline.observe_quarantine(
            deadline=asyncio.get_running_loop().time() + 0.01
        )
    finally:
        owned.release_close.set()
        if not run.done():
            with suppress(BaseException):
                await asyncio.wait_for(run, timeout=0.3)
        drained = await harness.pipeline.observe_quarantine(
            deadline=asyncio.get_running_loop().time() + 0.1
        )
        assert drained, (
            harness.pipeline._deadlines._quarantine_snapshot(),  # noqa: SLF001
            harness.pipeline._deadlines._settled_tombstones,  # noqa: SLF001
        )

    assert owned.closed == 1
    assert harness.capture_pcm == bytearray()
    if stage == "source":
        assert harness.converter.calls == 0
    else:
        assert getattr(harness.converter.input_iterator, "ag_frame", None) is None


@pytest.mark.asyncio
async def test_pipeline_sanitizes_mixed_base_exception_group_and_clears_capture() -> None:
    harness = _harness()

    async def grouped_authorization(**_: object) -> AuthorizedTranscriptionRequest:
        raise BaseExceptionGroup(
            "private-provider-group",
            [
                asyncio.CancelledError("private-provider-cancellation"),
                RuntimeError("private-provider-error"),
            ],
        )

    harness.authorizer.authorize_transcription = grouped_authorization  # type: ignore[method-assign]

    with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$") as failure:
        await _collect(harness.pipeline.run(harness.captured()))

    assert "private" not in str(failure.value)
    assert harness.capture_pcm == bytearray()
    assert harness.stt.calls == 0


@pytest.mark.asyncio
async def test_pipeline_preserves_cleanup_incomplete_nested_in_mixed_group() -> None:
    harness = _harness()

    async def grouped_authorization(**_: object) -> AuthorizedTranscriptionRequest:
        raise BaseExceptionGroup(
            "private-provider-group",
            [
                RuntimeError("private-provider-error"),
                ExceptionGroup(
                    "private-cleanup-group",
                    [DeadlineCleanupIncomplete()],
                ),
            ],
        )

    harness.authorizer.authorize_transcription = grouped_authorization  # type: ignore[method-assign]

    with pytest.raises(DeadlineCleanupIncomplete, match="^deadline-cleanup-incomplete$"):
        await _collect(harness.pipeline.run(harness.captured()))

    assert harness.capture_pcm == bytearray()
    assert harness.stt.calls == 0


@pytest.mark.asyncio
async def test_pipeline_preserves_incomplete_cleanup_and_exposes_owned_quarantine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deadline_module, "_CANCEL_OBSERVE_SECONDS", 0.01, raising=False)
    clock = _Clock()
    harness = _harness(clock=clock)
    entered = asyncio.Event()
    cancelled = asyncio.Event()
    release = asyncio.Event()

    async def cancellation_suppressing_authorization(
        **_: object,
    ) -> AuthorizedTranscriptionRequest:
        entered.set()
        while not release.is_set():
            try:
                await release.wait()
            except asyncio.CancelledError:
                cancelled.set()
        return _stt_request()

    harness.authorizer.authorize_transcription = (  # type: ignore[method-assign]
        cancellation_suppressing_authorization
    )
    run = asyncio.create_task(_collect(harness.pipeline.run(harness.captured())))
    await entered.wait()
    while not any(deadline == 30.0 for deadline, _ in clock.sleepers):
        await asyncio.sleep(0)
    clock.expire(30.0)

    try:
        with pytest.raises(DeadlineCleanupIncomplete, match="^deadline-cleanup-incomplete$"):
            await run
        assert cancelled.is_set()
        assert not await harness.pipeline.observe_quarantine(
            deadline=asyncio.get_running_loop().time() + 0.01
        )
    finally:
        release.set()
        # Keep the RED test teardown bounded even before the public delegation
        # exists or the cleanup-incomplete exception is preserved.
        await harness.pipeline._deadlines.observe_quarantine(  # noqa: SLF001
            deadline=asyncio.get_running_loop().time() + 0.1
        )

    assert await harness.pipeline.observe_quarantine(
        deadline=asyncio.get_running_loop().time() + 0.1
    )
    assert harness.capture_pcm == bytearray()


@pytest.mark.asyncio
async def test_pipeline_cleanup_incompleteness_survives_concurrent_iterator_close_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deadline_module, "_CANCEL_OBSERVE_SECONDS", 0.01, raising=False)
    clock = _Clock()
    harness = _harness(clock=clock)
    converted = _CancellationSuppressingIterator()
    harness.converter.stream = converted
    run = asyncio.create_task(_collect(harness.pipeline.run(harness.captured())))
    await converted.entered.wait()
    while not any(deadline == 30.0 for deadline, _ in clock.sleepers):
        await asyncio.sleep(0)
    clock.expire(30.0)

    try:
        with pytest.raises(DeadlineCleanupIncomplete, match="^deadline-cleanup-incomplete$"):
            await run
        assert converted.cancelled.is_set()
    finally:
        converted.release.set()
        await harness.pipeline._deadlines.observe_quarantine(  # noqa: SLF001
            deadline=asyncio.get_running_loop().time() + 0.1
        )

    assert harness.capture_pcm == bytearray()


@pytest.mark.asyncio
async def test_late_quarantined_conversion_rewipes_its_owned_destination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deadline_module, "_CANCEL_OBSERVE_SECONDS", 0.01, raising=False)
    clock = _Clock()
    harness = _harness(clock=clock)
    entered = asyncio.Event()
    cancelled = asyncio.Event()
    release = asyncio.Event()
    destinations: list[bytearray] = []

    async def record_destination(
        stream: AsyncIterator[bytes],
        *,
        source_samples: int,
        destination: bytearray,
        protected_owner: asyncio.Task[object] | None,
    ) -> None:
        destinations.append(destination)
        entered.set()
        while not release.is_set():
            try:
                await release.wait()
            except asyncio.CancelledError:
                cancelled.set()
        destination.extend(harness.converted_pcm)

    harness.pipeline._buffer_converted = record_destination  # type: ignore[method-assign]  # noqa: SLF001
    run = asyncio.create_task(_collect(harness.pipeline.run(harness.captured())))
    await entered.wait()
    clock.expire(30.0)

    try:
        with pytest.raises(DeadlineCleanupIncomplete, match="^deadline-cleanup-incomplete$"):
            await run
        assert destinations == [bytearray()]
        assert cancelled.is_set()
    finally:
        release.set()
        assert await harness.pipeline.observe_quarantine(
            deadline=asyncio.get_running_loop().time() + 0.1
        )

    assert destinations == [bytearray()]


@pytest.mark.asyncio
async def test_late_quarantined_source_buffer_rewipes_its_owned_destination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deadline_module, "_CANCEL_OBSERVE_SECONDS", 0.01, raising=False)
    clock = _Clock()
    harness = _harness(clock=clock)
    entered = asyncio.Event()
    cancelled = asyncio.Event()
    release = asyncio.Event()
    destinations: list[bytearray] = []

    async def record_destination(
        stream: AsyncIterator[SpeechChunk],
        *,
        request_id: object,
        destination: bytearray,
        protected_owner: asyncio.Task[object] | None,
    ) -> int:
        destinations.append(destination)
        entered.set()
        while not release.is_set():
            try:
                await release.wait()
            except asyncio.CancelledError:
                cancelled.set()
        destination.extend(harness.source_pcm)
        return len(harness.source_pcm) // 2

    harness.pipeline._buffer_source = record_destination  # type: ignore[method-assign]  # noqa: SLF001
    run = asyncio.create_task(_collect(harness.pipeline.run(harness.captured())))
    await entered.wait()
    clock.expire(30.0)

    try:
        with pytest.raises(DeadlineCleanupIncomplete, match="^deadline-cleanup-incomplete$"):
            await run
        assert destinations == [bytearray()]
        assert cancelled.is_set()
    finally:
        release.set()
        assert await harness.pipeline.observe_quarantine(
            deadline=asyncio.get_running_loop().time() + 0.1
        )

    assert destinations == [bytearray()]


@pytest.mark.parametrize("language", ["en", "hi", "hinglish"])
@pytest.mark.asyncio
async def test_pipeline_runs_one_authorized_bilingual_turn_before_first_yield(
    language: Literal["en", "hi", "hinglish"],
) -> None:
    harness = _harness(language)
    captured = harness.captured()

    chunks = await _collect(harness.pipeline.run(captured))

    assert [event for event in harness.authorizer.events] == [
        "authorize.stt",
        "stt",
        "authorize.reasoning",
        "llm",
        "authorize.synthesis",
        "tts",
        "convert",
    ]
    assert harness.authorizer.transcription_calls == 1
    assert harness.authorizer.reasoning_calls == 1
    assert harness.authorizer.synthesis_calls == 1
    assert harness.stt.calls == harness.llm.calls == harness.tts.calls == 1
    assert harness.converter.calls == 1
    assert harness.authorizer.observed_audio == b"\x01\x00\x02\x00\x03\x00\x04\x00"
    assert harness.authorizer.observed_readonly is True
    assert harness.authorizer.observed_hints == ("en", "hi")
    assert harness.authorizer.retained_view is not None
    with pytest.raises(ValueError, match="released memoryview"):
        harness.authorizer.retained_view.tobytes()
    assert harness.stt.observed_audio == harness.authorizer.observed_audio
    assert harness.converter.source == TTS_SOURCE_FORMAT
    assert harness.converter.target == TRANSPORT_AUDIO_FORMAT
    assert harness.converter.observed_source == harness.source_pcm
    assert harness.source_pcm != harness.converted_pcm
    assert chunks == (
        SpeechChunk(
            request_id=TTS_REQUEST_ID,
            sequence=0,
            pcm=harness.converted_pcm[:6_400],
            final=False,
        ),
        SpeechChunk(
            request_id=TTS_REQUEST_ID,
            sequence=1,
            pcm=harness.converted_pcm[6_400:],
            final=False,
        ),
        SpeechChunk(
            request_id=TTS_REQUEST_ID,
            sequence=2,
            pcm=b"",
            final=True,
        ),
    )
    assert harness.capture_pcm == bytearray()
    assert harness.tts.stream.closed == 1
    assert harness.converter.stream.closed == 1
    assert getattr(harness.stt.audio_iterator, "ag_frame", None) is None
    assert getattr(harness.converter.input_iterator, "ag_frame", None) is None


@pytest.mark.asyncio
async def test_pipeline_closes_distinct_tts_iterable_and_iterator() -> None:
    harness = _harness()
    inner = harness.tts.stream
    outer = _SplitAsyncIterable(cast(AsyncIterator[object], inner))
    harness.tts.stream = cast(_TrackedIterator, outer)

    await _collect(harness.pipeline.run(harness.captured()))

    assert outer.closed == 1
    assert inner.closed == 1


@pytest.mark.asyncio
async def test_pipeline_closes_distinct_converter_iterable_and_iterator() -> None:
    harness = _harness()
    inner = _TrackedIterator((harness.converted_pcm,))
    outer = _SplitAsyncIterable(cast(AsyncIterator[object], inner))

    def split_convert(
        audio: AsyncIterator[bytes],
        source: AudioFormat,
        target: AudioFormat,
    ) -> AsyncIterator[bytes]:
        harness.converter.calls += 1
        harness.converter.source = source
        harness.converter.target = target
        harness.converter.input_iterator = audio
        return cast(AsyncIterator[bytes], outer)

    harness.converter.convert = split_convert  # type: ignore[method-assign]

    await _collect(harness.pipeline.run(harness.captured()))

    assert outer.closed == 1
    assert inner.closed == 1
    assert getattr(harness.converter.input_iterator, "ag_frame", None) is None


@pytest.mark.parametrize(
    "stage",
    ["stt_authorization", "transcript", "reasoning_authorization", "response", "synthesis"],
)
@pytest.mark.asyncio
async def test_pipeline_rejects_subclasses_spoofing_canonical_authorizer_or_provider_types(
    stage: str,
) -> None:
    transcript = _transcript("en")
    response = _response("en")

    class _SttRequestSpoof(AuthorizedTranscriptionRequest):
        pass

    class _TranscriptSpoof(TranscriptResult):
        pass

    class _ReasoningRequestSpoof(SanitizedProviderRequest):
        pass

    class _ResponseSpoof(ProviderResponse):
        pass

    class _SynthesisSpoof(AuthorizedSynthesisRequest):
        pass

    overrides: dict[str, object] = {}
    if stage == "stt_authorization":
        overrides["stt_request"] = _SttRequestSpoof.model_validate(
            _stt_request().model_dump(mode="python")
        )
    elif stage == "transcript":
        overrides["transcript"] = _TranscriptSpoof.model_validate(
            transcript.model_dump(mode="python")
        )
        overrides["reasoning_request"] = _reasoning_request(transcript)
        overrides["synthesis_request"] = _synthesis_request(response)
    elif stage == "reasoning_authorization":
        overrides["reasoning_request"] = _ReasoningRequestSpoof.model_validate(
            _reasoning_request(transcript).model_dump(mode="python")
        )
    elif stage == "response":
        overrides["response"] = _ResponseSpoof.model_validate(response.model_dump(mode="python"))
        overrides["synthesis_request"] = _synthesis_request(response)
    else:
        overrides["synthesis_request"] = _SynthesisSpoof.model_validate(
            _synthesis_request(response).model_dump(mode="python")
        )
    harness = _harness(**overrides)  # type: ignore[arg-type]
    observed: list[SpeechChunk] = []

    with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$"):
        async for chunk in harness.pipeline.run(harness.captured()):
            observed.append(chunk)

    assert observed == []
    if stage == "speech_final":
        assert harness.converter.calls == 0
    assert harness.capture_pcm == bytearray()


@pytest.mark.parametrize(
    "stage",
    ["stt_route", "reasoning_messages", "response_receipt", "synthesis_receipt", "speech_final"],
)
@pytest.mark.asyncio
async def test_pipeline_revalidates_canonical_dto_fields_spoofed_after_construction(
    stage: str,
) -> None:
    overrides: dict[str, object] = {}
    if stage == "stt_route":
        request = _stt_request()
        overrides["stt_request"] = request.model_copy(
            update={"route": request.route.model_copy(update={"provider": "evil"})}
        )
    elif stage == "reasoning_messages":
        request = _reasoning_request(_transcript("en"))
        overrides["reasoning_request"] = request.model_copy(update={"messages": (object(),)})
    elif stage == "response_receipt":
        overrides["response"] = _response("en").model_copy(
            update={"provider_usage_receipt_id": "not-a-uuid"}
        )
        overrides["synthesis_request"] = _synthesis_request(_response("en"))
    elif stage == "synthesis_receipt":
        overrides["synthesis_request"] = _synthesis_request(_response("en")).model_copy(
            update={"dlp_receipt_id": "not-a-uuid"}
        )
    else:
        valid = SpeechChunk(
            request_id=TTS_REQUEST_ID,
            sequence=0,
            pcm=b"\x00\x00",
            final=False,
        )
        final = SpeechChunk(
            request_id=TTS_REQUEST_ID,
            sequence=1,
            pcm=b"",
            final=True,
        ).model_copy(update={"final": "yes"})
        overrides["speech_items"] = (valid, final)
    harness = _harness(**overrides)  # type: ignore[arg-type]
    observed: list[SpeechChunk] = []

    with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$"):
        async for chunk in harness.pipeline.run(harness.captured()):
            observed.append(chunk)

    assert observed == []
    assert harness.capture_pcm == bytearray()


@pytest.mark.asyncio
async def test_pipeline_rejects_speech_and_converter_scalar_subclasses() -> None:
    class _SpeechSpoof(SpeechChunk):
        pass

    class _BytesSpoof(bytes):
        pass

    valid_speech = SpeechChunk(
        request_id=TTS_REQUEST_ID,
        sequence=0,
        pcm=b"\x00\x00",
        final=False,
    )
    speech_spoof = _SpeechSpoof.model_validate(valid_speech.model_dump(mode="python"))
    final = SpeechChunk(
        request_id=TTS_REQUEST_ID,
        sequence=1,
        pcm=b"",
        final=True,
    )
    first = _harness(speech_items=(speech_spoof, final))
    second = _harness(converted_items=(_BytesSpoof(bytes(6_408)),))

    with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$"):
        await _collect(first.pipeline.run(first.captured()))
    with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$"):
        await _collect(second.pipeline.run(second.captured()))

    assert first.converter.calls == 0
    assert first.capture_pcm == bytearray()
    assert second.capture_pcm == bytearray()


@pytest.mark.parametrize(
    "stt_request",
    [
        _stt_request().model_copy(update={"audio_bytes": 6}),
        _stt_request().model_copy(update={"duration_ms": 2}),
        _stt_request().model_copy(update={"language_hints": ("hi", "en")}),
        _stt_request().model_copy(
            update={"audio_format": TTS_SOURCE_FORMAT},
        ),
        _stt_request(turn_id=OTHER_TURN_ID),
        _stt_request().model_copy(
            update={
                "route": _route("cloud_reasoning", STT_REQUEST_ID).model_copy(
                    update={"request_id": STT_REQUEST_ID}
                )
            }
        ),
    ],
)
@pytest.mark.asyncio
async def test_pipeline_rejects_noncanonical_transcription_authorization_before_stt(
    stt_request: AuthorizedTranscriptionRequest,
) -> None:
    harness = _harness(stt_request=stt_request)

    with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$"):
        await _collect(harness.pipeline.run(harness.captured()))

    assert harness.stt.calls == 0
    assert harness.llm.calls == 0
    assert harness.capture_pcm == bytearray()


def _reasoning_variants() -> tuple[SanitizedProviderRequest, ...]:
    transcript = _transcript("en")
    request = _reasoning_request(transcript)
    tool = SanitizedToolReference(
        registered_name="demo.tool",
        schema_version="1.0",
        schema_commitment=COMMITMENT,
    )
    return (
        request.model_copy(update={"allowed_tools": (tool,)}),
        request.model_copy(update={"store": True}),
        request.model_copy(update={"timeout_ms": 44_999}),
        request.model_copy(update={"messages": ()}),
        request.model_copy(
            update={"route": request.route.model_copy(update={"turn_id": OTHER_TURN_ID})}
        ),
        request.model_copy(
            update={"route": request.route.model_copy(update={"purpose": "cloud_stt"})}
        ),
    )


@pytest.mark.parametrize("reasoning_request", _reasoning_variants())
@pytest.mark.asyncio
async def test_pipeline_rejects_reasoning_tools_store_timeout_or_route_drift_before_llm(
    reasoning_request: SanitizedProviderRequest,
) -> None:
    harness = _harness(reasoning_request=reasoning_request)

    with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$"):
        await _collect(harness.pipeline.run(harness.captured()))

    assert harness.stt.calls == 1
    assert harness.llm.calls == 0
    assert harness.capture_pcm == bytearray()


@pytest.mark.parametrize(
    "stt_request",
    [
        _stt_request().model_copy(
            update={
                "audio_commitment": Commitment(
                    algorithm="HMAC-SHA-256",
                    key_id="different-test-key",
                    value_b64=base64.b64encode(bytes([1]) * 32).decode("ascii"),
                )
            }
        ),
        _stt_request().model_copy(
            update={"route": _stt_request().route.model_copy(update={"max_input_bytes": 1})}
        ),
    ],
)
@pytest.mark.asyncio
async def test_pipeline_rejects_transcription_commitment_or_route_ceiling_drift(
    stt_request: AuthorizedTranscriptionRequest,
) -> None:
    harness = _harness(stt_request=stt_request)

    with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$"):
        await _collect(harness.pipeline.run(harness.captured()))

    assert harness.stt.calls == 0
    assert harness.capture_pcm == bytearray()


@pytest.mark.asyncio
async def test_pipeline_rejects_noncanonical_transcript_before_reasoning_authorization() -> None:
    transcript = _transcript("en").model_copy(update={"text": ""})
    harness = _harness(
        transcript=transcript,
        reasoning_request=_reasoning_request(_transcript("en")),
        synthesis_request=_synthesis_request(_response("en")),
    )

    with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$"):
        await _collect(harness.pipeline.run(harness.captured()))

    assert harness.authorizer.reasoning_calls == 0
    assert harness.llm.calls == 0
    assert harness.capture_pcm == bytearray()


@pytest.mark.parametrize(
    "response",
    [
        _response("en").model_copy(update={"request_id": OTHER_TURN_ID}),
        _response("en").model_copy(update={"language": "hi"}),
        _response("en").model_copy(update={"text": "e\u0301"}),
        _response("en").model_copy(update={"text": "x" * 4_097}),
    ],
)
@pytest.mark.asyncio
async def test_pipeline_rejects_response_id_language_or_text_drift_before_tts(
    response: ProviderResponse,
) -> None:
    harness = _harness(
        response=response,
        synthesis_request=_synthesis_request(_response("en")),
    )

    with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$"):
        await _collect(harness.pipeline.run(harness.captured()))

    assert harness.llm.calls == 1
    assert harness.tts.calls == 0
    assert harness.capture_pcm == bytearray()


@pytest.mark.parametrize(
    "update",
    [
        {"turn_id": OTHER_TURN_ID},
        {"text": "different"},
        {"language": "hi"},
        {"segment_index": 1, "segment_count": 2},
        {"route": _route("cloud_stt", TTS_REQUEST_ID)},
        {"route": _route("cloud_tts", TTS_REQUEST_ID).model_copy(update={"max_input_bytes": 1})},
    ],
)
@pytest.mark.asyncio
async def test_pipeline_rejects_synthesis_request_drift_before_provider_call(
    update: dict[str, object],
) -> None:
    response = _response("en")
    synthesis = _synthesis_request(response).model_copy(update=update)
    harness = _harness(response=response, synthesis_request=synthesis)

    with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$"):
        await _collect(harness.pipeline.run(harness.captured()))

    assert harness.tts.calls == 0
    assert harness.converter.calls == 0
    assert harness.capture_pcm == bytearray()


def _speech_grammar_failures() -> tuple[tuple[object, ...], ...]:
    nonfinal = SpeechChunk(
        request_id=TTS_REQUEST_ID,
        sequence=0,
        pcm=b"\x01\x00",
        final=False,
    )
    final = SpeechChunk(
        request_id=TTS_REQUEST_ID,
        sequence=1,
        pcm=b"",
        final=True,
    )
    return (
        (final.model_copy(update={"sequence": 0}),),
        (nonfinal,),
        (nonfinal, final.model_copy(update={"pcm": b"\x00\x00"})),
        (nonfinal, final, final.model_copy(update={"sequence": 2})),
        (nonfinal.model_copy(update={"sequence": 1}), final),
        (nonfinal.model_copy(update={"request_id": OTHER_TURN_ID}), final),
        (nonfinal.model_copy(update={"pcm": b""}), final),
        (nonfinal.model_copy(update={"pcm": b"\x00"}), final),
        (nonfinal, RuntimeError("private-source-body")),
    )


def _pcm_chunks(total_bytes: int) -> tuple[bytes, ...]:
    full, remainder = divmod(total_bytes, 65_536)
    chunks = (bytes(65_536),) * full
    return chunks + ((bytes(remainder),) if remainder else ())


def _speech_for_size(total_bytes: int) -> tuple[SpeechChunk, ...]:
    pcm_chunks = _pcm_chunks(total_bytes)
    speech = tuple(
        SpeechChunk(
            request_id=TTS_REQUEST_ID,
            sequence=index,
            pcm=pcm,
            final=False,
        )
        for index, pcm in enumerate(pcm_chunks)
    )
    return speech + (
        SpeechChunk(
            request_id=TTS_REQUEST_ID,
            sequence=len(speech),
            pcm=b"",
            final=True,
        ),
    )


@pytest.mark.parametrize("speech_items", _speech_grammar_failures())
@pytest.mark.asyncio
async def test_pipeline_buffers_and_rejects_complete_invalid_source_without_conversion(
    speech_items: tuple[object, ...],
) -> None:
    harness = _harness(speech_items=speech_items)
    observed: list[SpeechChunk] = []

    with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$") as error:
        async for chunk in harness.pipeline.run(harness.captured()):
            observed.append(chunk)

    assert observed == []
    assert harness.converter.calls == 0
    assert harness.tts.stream.closed == 1
    assert harness.capture_pcm == bytearray()
    assert "private-source-body" not in repr(error.value)
    assert error.value.__context__ is None
    assert error.value.__cause__ is None


@pytest.mark.parametrize(
    "converted_items",
    [
        (),
        (b"",),
        (b"\x00",),
        (b"\x00\x00", RuntimeError("private-converter-body")),
        (bytes(6_412),),
    ],
)
@pytest.mark.asyncio
async def test_pipeline_buffers_and_rejects_invalid_or_late_failed_conversion_without_yield(
    converted_items: tuple[object, ...],
) -> None:
    harness = _harness(converted_items=converted_items)
    observed: list[SpeechChunk] = []

    with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$") as error:
        async for chunk in harness.pipeline.run(harness.captured()):
            observed.append(chunk)

    assert observed == []
    assert harness.converter.calls == 1
    assert harness.converter.stream.closed == 1
    assert harness.capture_pcm == bytearray()
    assert "private-converter-body" not in repr(error.value)
    assert error.value.__context__ is None
    assert error.value.__cause__ is None


@pytest.mark.asyncio
async def test_pipeline_accepts_exact_source_and_converted_ninety_second_limits() -> None:
    source_bytes = 2 * 24_000 * 90
    converted_bytes = 2 * 16_000 * 90
    harness = _harness(
        speech_items=_speech_for_size(source_bytes),
        converted_items=_pcm_chunks(converted_bytes),
    )

    chunks = await _collect(harness.pipeline.run(harness.captured()))

    assert sum(len(chunk.pcm) for chunk in chunks) == converted_bytes
    assert len(chunks) == converted_bytes // 6_400 + 1
    assert chunks[-1].final is True
    assert chunks[-1].pcm == b""
    assert harness.converter.calls == 1
    assert harness.capture_pcm == bytearray()


@pytest.mark.parametrize(
    "source_bytes,source_format",
    [
        (2 * 24_000 * 90 + 2, TTS_SOURCE_FORMAT),
        (
            MAX_DIRECTION_BYTES + 2,
            AudioFormat(
                sample_format="s16le",
                sample_rate_hz=96_000,
                channels=1,
                interleaved=False,
                channel_layout="mono",
            ),
        ),
    ],
)
@pytest.mark.asyncio
async def test_pipeline_rejects_source_beyond_sample_or_byte_limit_before_conversion(
    source_bytes: int,
    source_format: AudioFormat,
) -> None:
    harness = _harness(
        speech_items=_speech_for_size(source_bytes),
        source_format=source_format,
    )
    observed: list[SpeechChunk] = []

    with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$"):
        async for chunk in harness.pipeline.run(harness.captured()):
            observed.append(chunk)

    assert observed == []
    assert harness.converter.calls == 0
    assert harness.capture_pcm == bytearray()


@pytest.mark.asyncio
async def test_pipeline_accepts_exact_eight_mib_source_at_high_sample_rate() -> None:
    source_format = AudioFormat(
        sample_format="s16le",
        sample_rate_hz=96_000,
        channels=1,
        interleaved=False,
        channel_layout="mono",
    )
    source_bytes = MAX_DIRECTION_BYTES
    source_samples = source_bytes // 2
    converted_samples = (
        source_samples * 16_000 + source_format.sample_rate_hz // 2
    ) // source_format.sample_rate_hz
    harness = _harness(
        speech_items=_speech_for_size(source_bytes),
        converted_items=_pcm_chunks(converted_samples * 2),
        source_format=source_format,
    )

    chunks = await _collect(harness.pipeline.run(harness.captured()))

    assert sum(len(chunk.pcm) for chunk in chunks) == converted_samples * 2
    assert chunks[-1].final is True
    assert harness.converter.calls == 1
    assert harness.capture_pcm == bytearray()


@pytest.mark.parametrize(
    "converted_bytes,accepted",
    [
        (6_410, True),
        (2 * 16_000 * 90 + 2, False),
        (MAX_DIRECTION_BYTES + 2, False),
    ],
)
@pytest.mark.asyncio
async def test_pipeline_enforces_one_sample_duration_tolerance_and_converted_limits(
    converted_bytes: int,
    accepted: bool,
) -> None:
    speech_items = None
    if converted_bytes > 1_000_000:
        speech_items = _speech_for_size(2 * 24_000 * 90)
    harness = _harness(
        speech_items=speech_items,
        converted_items=_pcm_chunks(converted_bytes),
    )

    if accepted:
        chunks = await _collect(harness.pipeline.run(harness.captured()))
        assert sum(len(chunk.pcm) for chunk in chunks) == converted_bytes
    else:
        observed: list[SpeechChunk] = []
        with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$"):
            async for chunk in harness.pipeline.run(harness.captured()):
                observed.append(chunk)
        assert observed == []
    assert harness.capture_pcm == bytearray()


@pytest.mark.asyncio
async def test_pipeline_cancellation_during_stt_closes_audio_and_clears_capture() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    transcript = _transcript("en")
    harness = _harness(transcript=transcript)

    async def blocked_transcribe(
        request: AuthorizedTranscriptionRequest,
        audio: AsyncIterator[bytes],
    ) -> TranscriptResult:
        harness.stt.calls += 1
        harness.stt.audio_iterator = audio
        await anext(audio)
        entered.set()
        await release.wait()
        return transcript

    harness.stt.transcribe = blocked_transcribe  # type: ignore[method-assign]
    stream = harness.pipeline.run(harness.captured())
    task = asyncio.create_task(anext(stream))
    await asyncio.wait_for(entered.wait(), timeout=1)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert harness.capture_pcm == bytearray()
    assert getattr(harness.stt.audio_iterator, "ag_frame", None) is None
    assert harness.llm.calls == 0
    with pytest.raises(StopAsyncIteration):
        await anext(stream)


@pytest.mark.asyncio
async def test_pipeline_cancellation_during_llm_clears_capture_and_stops_tts() -> None:
    entered = asyncio.Event()
    harness = _harness()

    async def blocked_complete(request: SanitizedProviderRequest) -> ProviderResponse:
        harness.llm.calls += 1
        entered.set()
        await asyncio.Future()
        raise AssertionError("unreachable")

    harness.llm.complete = blocked_complete  # type: ignore[method-assign]
    stream = harness.pipeline.run(harness.captured())
    task = asyncio.create_task(anext(stream))
    await asyncio.wait_for(entered.wait(), timeout=1)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert harness.capture_pcm == bytearray()
    assert harness.tts.calls == 0
    with pytest.raises(StopAsyncIteration):
        await anext(stream)


@pytest.mark.asyncio
async def test_pipeline_cancellation_swallowed_by_llm_still_stops_downstream() -> None:
    entered = asyncio.Event()
    harness = _harness()

    async def cancellation_swallowing_complete(
        request: SanitizedProviderRequest,
    ) -> ProviderResponse:
        harness.llm.calls += 1
        entered.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            return _response("en")

    harness.llm.complete = cancellation_swallowing_complete  # type: ignore[method-assign]
    stream = harness.pipeline.run(harness.captured())
    task = asyncio.create_task(anext(stream))
    await asyncio.wait_for(entered.wait(), timeout=1)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert harness.tts.calls == 0
    assert harness.capture_pcm == bytearray()
    with pytest.raises(StopAsyncIteration):
        await anext(stream)


@pytest.mark.asyncio
async def test_pipeline_rejects_capture_alias_resize_before_first_iteration() -> None:
    harness = _harness()
    captured = harness.captured()
    stream = harness.pipeline.run(captured)
    harness.capture_pcm.extend(b"\x05\x00")

    with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$"):
        await anext(stream)

    assert harness.authorizer.transcription_calls == 0
    assert harness.capture_pcm == bytearray()
    with pytest.raises(StopAsyncIteration):
        await anext(stream)


@pytest.mark.parametrize("stage", ["transcription", "reasoning", "synthesis"])
@pytest.mark.asyncio
async def test_pipeline_cancellation_during_authorization_clears_owned_state(
    stage: str,
) -> None:
    entered = asyncio.Event()
    harness = _harness()
    retained_view: list[memoryview] = []

    if stage == "transcription":

        async def blocked_transcription(**kwargs: object) -> AuthorizedTranscriptionRequest:
            retained_view.append(cast(memoryview, kwargs["pcm"]))
            entered.set()
            await asyncio.Future()
            raise AssertionError("unreachable")

        harness.authorizer.authorize_transcription = blocked_transcription  # type: ignore[method-assign]
    elif stage == "reasoning":

        async def blocked_reasoning(**kwargs: object) -> SanitizedProviderRequest:
            entered.set()
            await asyncio.Future()
            raise AssertionError("unreachable")

        harness.authorizer.authorize_reasoning = blocked_reasoning  # type: ignore[method-assign]
    else:

        async def blocked_synthesis(**kwargs: object) -> AuthorizedSynthesisRequest:
            entered.set()
            await asyncio.Future()
            raise AssertionError("unreachable")

        harness.authorizer.authorize_synthesis = blocked_synthesis  # type: ignore[method-assign]

    stream = harness.pipeline.run(harness.captured())
    task = asyncio.create_task(anext(stream))
    await asyncio.wait_for(entered.wait(), timeout=1)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert harness.capture_pcm == bytearray()
    if retained_view:
        with pytest.raises(ValueError, match="released memoryview"):
            retained_view[0].tobytes()
    with pytest.raises(StopAsyncIteration):
        await anext(stream)


@pytest.mark.parametrize("stage", ["stt", "llm", "tts"])
@pytest.mark.asyncio
async def test_pipeline_provider_failures_are_content_free_and_stop_downstream(
    stage: str,
) -> None:
    harness = _harness()
    if stage == "stt":
        harness.stt.result = RuntimeError("private-stt-body")
    elif stage == "llm":
        harness.llm.result = RuntimeError("private-llm-body")
    else:

        def failed_synthesis(
            request: AuthorizedSynthesisRequest,
        ) -> AsyncIterator[SpeechChunk]:
            harness.tts.calls += 1
            raise RuntimeError("private-tts-body")

        harness.tts.synthesize = failed_synthesis  # type: ignore[method-assign]

    with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$") as error:
        await _collect(harness.pipeline.run(harness.captured()))

    assert error.value.__context__ is None
    assert error.value.__cause__ is None
    assert "private" not in repr(error.value)
    assert harness.capture_pcm == bytearray()
    if stage == "stt":
        assert getattr(harness.stt.audio_iterator, "ag_frame", None) is None
        assert harness.llm.calls == 0
    elif stage == "llm":
        assert harness.tts.calls == 0
    else:
        assert harness.converter.calls == 0


_PRIVATE_PIPELINE_LOCAL_NAMES = {
    "transcription_candidate",
    "transcription_request",
    "transcript_candidate",
    "transcript",
    "reasoning_candidate",
    "reasoning_request",
    "response_candidate",
    "response",
    "synthesis_candidate",
    "synthesis_request",
    "source_stream",
}


@pytest.mark.asyncio
async def test_pipeline_drops_text_and_request_refs_before_first_playback_yield() -> None:
    harness = _harness()
    stream = harness.pipeline.run(harness.captured())

    first = await anext(stream)

    assert first.final is False
    assert stream.ag_frame is not None
    locals_at_yield = stream.ag_frame.f_locals
    for name in _PRIVATE_PIPELINE_LOCAL_NAMES:
        assert locals_at_yield.get(name) is None, name
    assert locals_at_yield["transcript_text"] == []
    assert locals_at_yield["response_text"] == []
    assert locals_at_yield["input_pcm"] == bytearray()
    assert locals_at_yield["source_pcm"] == bytearray()
    assert locals_at_yield["converted_pcm"] == bytearray()
    assert harness.capture_pcm == bytearray()

    await stream.aclose()
    assert stream.ag_frame is None


@pytest.mark.asyncio
async def test_pipeline_error_traceback_retains_no_private_turn_refs() -> None:
    harness = _harness()
    harness.llm.result = RuntimeError("private-llm-body")

    with pytest.raises(VoiceTurnError) as error:
        await _collect(harness.pipeline.run(harness.captured()))

    traceback = error.value.__traceback__
    pipeline_locals: dict[str, object] | None = None
    while traceback is not None:
        if traceback.tb_frame.f_code.co_name == "_run":
            pipeline_locals = dict(traceback.tb_frame.f_locals)
            break
        traceback = traceback.tb_next
    assert pipeline_locals is not None
    for name in _PRIVATE_PIPELINE_LOCAL_NAMES:
        assert pipeline_locals.get(name) is None, name
    assert pipeline_locals["transcript_text"] == []
    assert pipeline_locals["response_text"] == []
    assert pipeline_locals["input_pcm"] == bytearray()
    assert pipeline_locals["source_pcm"] == bytearray()
    assert pipeline_locals["converted_pcm"] == bytearray()
    assert harness.capture_pcm == bytearray()


@pytest.mark.asyncio
async def test_observe_quarantine_cancellation_drops_pipeline_and_deadline_frames(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = asyncio.Event()
    private_snapshot = bytearray(b"private-quarantine-snapshot")

    async def blocked_observation(
        guard: deadline_module.DeadlineGuard,
        *,
        deadline: float,
    ) -> bool:
        assert guard is not None
        assert deadline > 0
        assert private_snapshot
        entered.set()
        await asyncio.Event().wait()
        return True

    monkeypatch.setattr(
        deadline_module.DeadlineGuard,
        "observe_quarantine",
        blocked_observation,
    )
    pipeline = _harness().pipeline
    run = asyncio.create_task(
        pipeline.observe_quarantine(deadline=asyncio.get_running_loop().time() + 1.0)
    )
    await entered.wait()
    run.cancel("voice-quarantine-owner-cancel")

    with pytest.raises(asyncio.CancelledError) as failure:
        await run

    assert failure.value.args == ("voice-quarantine-owner-cancel",)
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    traceback = failure.value.__traceback__
    public_locals: dict[str, object] | None = None
    public_code = VoiceTurnPipeline.observe_quarantine.__code__
    while traceback is not None:
        assert traceback.tb_frame.f_code is not blocked_observation.__code__
        if traceback.tb_frame.f_code is public_code:
            public_locals = dict(traceback.tb_frame.f_locals)
        traceback = traceback.tb_next
    assert public_locals is not None
    assert public_locals["self"] is None
    assert public_locals["deadline"] is None
    assert "private-quarantine-snapshot" not in repr(public_locals)


class _BlockedSpeechStream:
    def __init__(self, *, close_error: BaseException | None = None) -> None:
        self.close_error = close_error
        self.closed = 0
        self.entered = asyncio.Event()
        self._sent = False

    def __aiter__(self) -> _BlockedSpeechStream:
        return self

    async def __anext__(self) -> SpeechChunk:
        if not self._sent:
            self._sent = True
            return SpeechChunk(
                request_id=TTS_REQUEST_ID,
                sequence=0,
                pcm=b"\x00\x00",
                final=False,
            )
        self.entered.set()
        await asyncio.Future()
        raise AssertionError("unreachable")

    async def aclose(self) -> None:
        self.closed += 1
        if self.close_error is not None:
            raise self.close_error


class _SpontaneousCancelledStream:
    def __init__(self, cancellation: asyncio.CancelledError) -> None:
        self._cancellation = cancellation
        self.closed = 0

    def __aiter__(self) -> _SpontaneousCancelledStream:
        return self

    async def __anext__(self) -> object:
        raise self._cancellation

    async def aclose(self) -> None:
        self.closed += 1
        raise RuntimeError("private-close-error")


class _CancellationReplacingCloseIterator(_TrackedIterator):
    def __init__(self, items: Iterable[object], close_error: BaseException) -> None:
        super().__init__(items)
        self.close_error = close_error
        self.close_entered = asyncio.Event()
        self.close_cancelled = asyncio.Event()
        self.release_close = asyncio.Event()

    async def aclose(self) -> None:
        self.closed += 1
        self.close_entered.set()
        try:
            await self.release_close.wait()
        except asyncio.CancelledError:
            self.close_cancelled.set()
            raise self.close_error from None


class _VoiceHostileFloat(float):
    def __new__(cls) -> _VoiceHostileFloat:
        return float.__new__(cls, 1_000_000.0)

    def __sub__(self, other: object) -> float:
        del other
        raise RuntimeError("private-voice-deadline-sub")


async def _suppress_voice_cancellation(
    entered: asyncio.Event,
    cancelled: asyncio.Event,
    release: asyncio.Event,
) -> None:
    entered.set()
    while not release.is_set():
        try:
            await release.wait()
        except asyncio.CancelledError:
            cancelled.set()


@pytest.mark.parametrize(
    "close_error",
    [None, RuntimeError("private-close-body"), KeyboardInterrupt()],
    ids=("clean", "runtime-error", "fatal-base-exception"),
)
@pytest.mark.asyncio
async def test_pipeline_cancellation_during_tts_preserves_cancel_and_closes_source(
    close_error: BaseException | None,
) -> None:
    harness = _harness()
    source = _BlockedSpeechStream(close_error=close_error)
    harness.tts.stream = cast(_TrackedIterator, source)
    stream = harness.pipeline.run(harness.captured())
    task = asyncio.create_task(anext(stream))
    await asyncio.wait_for(source.entered.wait(), timeout=1)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert source.closed == 1
    assert harness.converter.calls == 0
    assert harness.capture_pcm == bytearray()
    with pytest.raises(StopAsyncIteration):
        await anext(stream)


@pytest.mark.asyncio
async def test_tts_deadline_preserves_cleanup_incomplete_from_cancelled_source_close() -> None:
    clock = _Clock()
    harness = _harness(clock=clock)
    source = _BlockedSpeechStream(close_error=DeadlineCleanupIncomplete())
    harness.tts.stream = cast(_TrackedIterator, source)
    run = asyncio.create_task(_collect(harness.pipeline.run(harness.captured())))
    await asyncio.wait_for(source.entered.wait(), timeout=1)

    clock.expire(30.0)

    with pytest.raises(DeadlineCleanupIncomplete, match="^deadline-cleanup-incomplete$") as error:
        await run
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert source.closed == 1
    assert harness.converter.calls == 0
    assert harness.capture_pcm == bytearray()


@pytest.mark.parametrize("stage", ["source", "converter"])
@pytest.mark.parametrize("close_outcome", ["cleanup-incomplete", "fatal"])
@pytest.mark.asyncio
async def test_tts_deadline_never_injects_cancellation_into_close(
    stage: str,
    close_outcome: str,
) -> None:
    clock = _Clock()
    harness = _harness(clock=clock)
    close_error: BaseException = (
        DeadlineCleanupIncomplete()
        if close_outcome == "cleanup-incomplete"
        else KeyboardInterrupt("private-close-fatal")
    )
    items: Iterable[object] = (
        _speech_for_size(len(harness.source_pcm)) if stage == "source" else (harness.converted_pcm,)
    )
    provider = _CancellationReplacingCloseIterator(items, close_error)
    if stage == "source":
        harness.tts.stream = provider
    else:

        def blocking_close_convert(
            audio: AsyncIterator[bytes],
            source: AudioFormat,
            target: AudioFormat,
        ) -> AsyncIterator[bytes]:
            harness.converter.calls += 1
            harness.converter.input_iterator = audio
            return cast(AsyncIterator[bytes], provider)

        harness.converter.convert = blocking_close_convert  # type: ignore[method-assign]

    async def expire_during_close() -> None:
        await provider.close_entered.wait()
        clock.expire(30.0)

    expiry = asyncio.create_task(expire_during_close())
    caught: BaseException | None = None
    try:
        await _collect(harness.pipeline.run(harness.captured()))
    except BaseException as error:
        caught = error
    await expiry

    assert type(caught) is DeadlineCleanupIncomplete
    assert caught.__cause__ is None
    assert caught.__context__ is None
    assert provider.closed == 1
    assert not provider.close_cancelled.is_set()
    assert harness.capture_pcm == bytearray()
    provider.release_close.set()
    assert await harness.pipeline.observe_quarantine(
        deadline=asyncio.get_running_loop().time() + 0.1
    )
    if stage == "source":
        assert harness.converter.calls == 0
    else:
        assert getattr(harness.converter.input_iterator, "ag_frame", None) is None


@pytest.mark.parametrize("stage", ["source", "converter"])
@pytest.mark.parametrize("close_outcome", ["cleanup-incomplete", "fatal"])
@pytest.mark.asyncio
async def test_owner_cancellation_precedes_guarded_close_safety_outcome(
    stage: str,
    close_outcome: str,
) -> None:
    harness = _harness()
    close_error: BaseException = (
        DeadlineCleanupIncomplete()
        if close_outcome == "cleanup-incomplete"
        else KeyboardInterrupt("private-close-fatal")
    )
    items: Iterable[object] = (
        _speech_for_size(len(harness.source_pcm)) if stage == "source" else (harness.converted_pcm,)
    )
    provider = _CancellationReplacingCloseIterator(items, close_error)
    if stage == "source":
        harness.tts.stream = provider
    else:

        def blocking_close_convert(
            audio: AsyncIterator[bytes],
            source: AudioFormat,
            target: AudioFormat,
        ) -> AsyncIterator[bytes]:
            harness.converter.calls += 1
            harness.converter.input_iterator = audio
            return cast(AsyncIterator[bytes], provider)

        harness.converter.convert = blocking_close_convert  # type: ignore[method-assign]

    run = asyncio.create_task(_collect(harness.pipeline.run(harness.captured())))
    await provider.close_entered.wait()
    run.cancel("owner-during-close")

    with pytest.raises(asyncio.CancelledError) as cancellation:
        await run
    assert cancellation.value.args in ((), ("owner-during-close",))
    assert provider.closed == 1
    assert not provider.close_cancelled.is_set()
    assert harness.capture_pcm == bytearray()
    provider.release_close.set()
    assert await harness.pipeline.observe_quarantine(
        deadline=asyncio.get_running_loop().time() + 0.1
    )
    if stage == "source":
        assert harness.converter.calls == 0
    else:
        assert getattr(harness.converter.input_iterator, "ag_frame", None) is None


@pytest.mark.parametrize("stage", ["source", "converter"])
@pytest.mark.asyncio
async def test_spontaneous_provider_cancellation_fails_closed_after_close_failure(
    stage: str,
) -> None:
    harness = _harness()
    provider = _SpontaneousCancelledStream(asyncio.CancelledError("private-provider-cancellation"))
    if stage == "source":
        harness.tts.stream = cast(_TrackedIterator, provider)
    else:

        def cancelled_convert(
            audio: AsyncIterator[bytes],
            source: AudioFormat,
            target: AudioFormat,
        ) -> AsyncIterator[bytes]:
            harness.converter.calls += 1
            harness.converter.input_iterator = audio
            return cast(AsyncIterator[bytes], provider)

        harness.converter.convert = cancelled_convert  # type: ignore[method-assign]

    with pytest.raises(
        DeadlineCleanupIncomplete,
        match="^deadline-cleanup-incomplete$",
    ) as error:
        await _collect(harness.pipeline.run(harness.captured()))

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert "private-provider-cancellation" not in repr(error.value)
    assert provider.closed == 1
    assert harness.capture_pcm == bytearray()
    if stage == "source":
        assert harness.converter.calls == 0
    else:
        assert getattr(harness.converter.input_iterator, "ag_frame", None) is None


@pytest.mark.asyncio
async def test_spontaneous_provider_cancellation_cannot_mask_chained_cleanup_incomplete() -> None:
    harness = _harness()
    cancellation = asyncio.CancelledError("private-provider-cancellation")
    cancellation.__cause__ = DeadlineCleanupIncomplete()
    provider = _SpontaneousCancelledStream(cancellation)
    harness.tts.stream = cast(_TrackedIterator, provider)

    with pytest.raises(DeadlineCleanupIncomplete, match="^deadline-cleanup-incomplete$") as error:
        await _collect(harness.pipeline.run(harness.captured()))

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert provider.closed == 1
    assert harness.converter.calls == 0
    assert harness.capture_pcm == bytearray()


@pytest.mark.asyncio
async def test_pending_owner_cancellation_wins_over_spontaneous_source_cancellation_and_wipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _harness()
    public_owner: dict[str, asyncio.Task[SpeechChunk]] = {}
    private_pcm = b"\x10\x00\x11\x00"
    wiped: list[bytes] = []
    real_wipe = voice_turn_module._wipe  # noqa: SLF001

    def recording_wipe(buffer: bytearray) -> None:
        wiped.append(bytes(buffer))
        real_wipe(buffer)

    monkeypatch.setattr(voice_turn_module, "_wipe", recording_wipe)

    class _OwnerCancellingIterator:
        def __init__(self) -> None:
            self.sequence = 0
            self.closed = 0

        def __aiter__(self) -> _OwnerCancellingIterator:
            return self

        async def __anext__(self) -> SpeechChunk:
            if self.sequence == 0:
                self.sequence += 1
                return SpeechChunk(
                    request_id=TTS_REQUEST_ID,
                    sequence=0,
                    pcm=private_pcm,
                    final=False,
                )
            public_owner["task"].cancel("owner-cancel")
            raise asyncio.CancelledError("private-provider-cancel")

        async def aclose(self) -> None:
            self.closed += 1

    inner = _OwnerCancellingIterator()
    provider = _SplitAsyncIterable(inner)
    harness.tts.stream = cast(_TrackedIterator, provider)
    stream = harness.pipeline.run(harness.captured())
    run = asyncio.create_task(anext(stream))
    public_owner["task"] = run

    with pytest.raises(asyncio.CancelledError) as cancellation:
        await run

    assert cancellation.value.args in ((), ("owner-cancel",))
    assert "private-provider-cancel" not in repr(cancellation.value)
    assert provider.closed == 1
    assert inner.closed == 1
    assert harness.converter.calls == 0
    assert harness.capture_pcm == bytearray()
    assert b"\x01\x00\x02\x00\x03\x00\x04\x00" in wiped
    assert private_pcm in wiped


@pytest.mark.asyncio
async def test_pipeline_claims_owner_cancel_when_deadline_runner_raises_private_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def owner_cancelled_run(
        self: deadline_module.DeadlineGuard,
        operation: Awaitable[object],
        *,
        deadline: float,
    ) -> object:
        del self, deadline
        if hasattr(operation, "close"):
            operation.close()
        current = asyncio.current_task()
        assert current is not None
        current.cancel("voice-owner-cancel")
        raise asyncio.CancelledError("private-provider-cancel")

    monkeypatch.setattr(deadline_module.DeadlineGuard, "run", owner_cancelled_run)
    harness = _harness()

    run = asyncio.create_task(_collect(harness.pipeline.run(harness.captured())))
    with pytest.raises(asyncio.CancelledError) as cancellation:
        await run

    assert cancellation.value.args in ((), ("voice-owner-cancel",))
    assert "private-provider-cancel" not in repr(cancellation.value)
    assert harness.stt.calls == 0
    assert harness.llm.calls == 0
    assert harness.tts.calls == 0
    assert harness.capture_pcm == bytearray()


@pytest.mark.parametrize(
    "close_error",
    [None, RuntimeError("private-close-body"), KeyboardInterrupt()],
    ids=("swallowed", "runtime-error", "fatal-base-exception"),
)
@pytest.mark.asyncio
async def test_pipeline_pending_cancellation_wins_over_source_close_outcome(
    close_error: BaseException | None,
) -> None:
    harness = _harness()
    close_entered = asyncio.Event()

    class _CancellationSwallowingSource(_TrackedIterator):
        async def aclose(self) -> None:
            self.closed += 1
            close_entered.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                if close_error is not None:
                    raise close_error from None
                return

    source = _CancellationSwallowingSource(_speech_for_size(len(harness.source_pcm)))
    harness.tts.stream = source
    stream = harness.pipeline.run(harness.captured())
    task = asyncio.create_task(anext(stream))
    await asyncio.wait_for(close_entered.wait(), timeout=1)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert source.closed == 1
    assert harness.converter.calls == 0
    assert harness.capture_pcm == bytearray()
    with pytest.raises(StopAsyncIteration):
        await anext(stream)


class _BlockedBytesStream:
    def __init__(self, *, close_error: BaseException | None = None) -> None:
        self.close_error = close_error
        self.closed = 0
        self.entered = asyncio.Event()
        self._sent = False

    def __aiter__(self) -> _BlockedBytesStream:
        return self

    async def __anext__(self) -> bytes:
        if not self._sent:
            self._sent = True
            return bytes(6_408)
        self.entered.set()
        await asyncio.Future()
        raise AssertionError("unreachable")

    async def aclose(self) -> None:
        self.closed += 1
        if self.close_error is not None:
            raise self.close_error


@pytest.mark.parametrize(
    "close_error",
    [None, RuntimeError("private-close-body"), KeyboardInterrupt()],
    ids=("clean", "runtime-error", "fatal-base-exception"),
)
@pytest.mark.asyncio
async def test_pipeline_cancellation_during_conversion_preserves_cancel_and_closes_iterators(
    close_error: BaseException | None,
) -> None:
    harness = _harness()
    converted = _BlockedBytesStream(close_error=close_error)
    harness.converter.stream = cast(_TrackedIterator, converted)
    stream = harness.pipeline.run(harness.captured())
    task = asyncio.create_task(anext(stream))
    await asyncio.wait_for(converted.entered.wait(), timeout=1)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert converted.closed == 1
    assert getattr(harness.converter.input_iterator, "ag_frame", None) is None
    assert harness.capture_pcm == bytearray()
    with pytest.raises(StopAsyncIteration):
        await anext(stream)


@pytest.mark.asyncio
async def test_tts_deadline_preserves_cleanup_incomplete_from_cancelled_converter_close() -> None:
    clock = _Clock()
    harness = _harness(clock=clock)
    converted = _BlockedBytesStream(close_error=DeadlineCleanupIncomplete())

    def cleanup_incomplete_convert(
        audio: AsyncIterator[bytes],
        source: AudioFormat,
        target: AudioFormat,
    ) -> AsyncIterator[bytes]:
        harness.converter.calls += 1
        harness.converter.input_iterator = audio
        return converted

    harness.converter.convert = cleanup_incomplete_convert  # type: ignore[method-assign]
    run = asyncio.create_task(_collect(harness.pipeline.run(harness.captured())))
    await asyncio.wait_for(converted.entered.wait(), timeout=1)

    clock.expire(30.0)

    with pytest.raises(DeadlineCleanupIncomplete, match="^deadline-cleanup-incomplete$") as error:
        await run
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert converted.closed == 1
    assert getattr(harness.converter.input_iterator, "ag_frame", None) is None
    assert harness.capture_pcm == bytearray()


class _CloseFailOutput:
    def __init__(self, pcm: bytes, close_error: BaseException | None = None) -> None:
        self._pcm = pcm
        self._sent = False
        self.closed = 0
        self._close_error = close_error or RuntimeError("private-close-body")

    def __aiter__(self) -> _CloseFailOutput:
        return self

    async def __anext__(self) -> bytes:
        if self._sent:
            raise StopAsyncIteration
        self._sent = True
        return self._pcm

    async def aclose(self) -> None:
        self.closed += 1
        raise self._close_error


class _BlockingCloseOutput:
    def __init__(self) -> None:
        self.closed = 0
        self.close_entered = asyncio.Event()
        self.close_cancelled = asyncio.Event()
        self.release_close = asyncio.Event()

    async def aclose(self) -> None:
        self.closed += 1
        self.close_entered.set()
        try:
            await self.release_close.wait()
        except asyncio.CancelledError:
            self.close_cancelled.set()
            raise


class _DeadlineAdvancingOutput:
    def __init__(self, pcm: bytes, clock: _Clock, *, close_at: float) -> None:
        self._pcm = pcm
        self._clock = clock
        self._close_at = close_at
        self._sent = False
        self.closed = 0

    def __aiter__(self) -> _DeadlineAdvancingOutput:
        return self

    async def __anext__(self) -> bytes:
        if self._sent:
            raise StopAsyncIteration
        self._sent = True
        return self._pcm

    async def aclose(self) -> None:
        self.closed += 1
        self._clock.current = self._close_at


@pytest.mark.parametrize("cleanup_first", [True, False], ids=("cleanup-first", "cancel-first"))
@pytest.mark.asyncio
async def test_iterator_cleanup_incomplete_precedes_spontaneous_close_cancellation(
    cleanup_first: bool,
) -> None:
    cleanup = _CloseFailOutput(b"", DeadlineCleanupIncomplete())
    cancelled = _CloseFailOutput(
        b"",
        asyncio.CancelledError("private-close-cancellation"),
    )
    ordered = (cleanup, cancelled) if cleanup_first else (cancelled, cleanup)

    with pytest.raises(DeadlineCleanupIncomplete, match="^deadline-cleanup-incomplete$"):
        await voice_turn_module._close_all(  # noqa: SLF001
            *ordered,
            deadlines=deadline_module.DeadlineGuard(_Clock()),
        )

    assert cleanup.closed == 1
    assert cancelled.closed == 1


@pytest.mark.parametrize("chain", ["cause", "context"])
@pytest.mark.asyncio
async def test_iterator_close_cancellation_cannot_mask_chained_cleanup_incomplete(
    chain: str,
) -> None:
    close_error = asyncio.CancelledError("private-close-cancellation")
    if chain == "cause":
        close_error.__cause__ = DeadlineCleanupIncomplete()
    else:
        close_error.__context__ = DeadlineCleanupIncomplete()
    output = _CloseFailOutput(b"", close_error)

    with pytest.raises(DeadlineCleanupIncomplete, match="^deadline-cleanup-incomplete$") as error:
        await voice_turn_module._close_all(  # noqa: SLF001
            output,
            deadlines=deadline_module.DeadlineGuard(_Clock()),
        )

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert output.closed == 1


@pytest.mark.asyncio
async def test_iterator_close_preserves_exact_owner_cancellation() -> None:
    output = _BlockingCloseOutput()
    guard = deadline_module.DeadlineGuard(_Clock())
    close = asyncio.create_task(
        voice_turn_module._close_all(  # noqa: SLF001
            output,
            deadlines=guard,
        )
    )
    await output.close_entered.wait()

    close.cancel("exact-owner-cancel")

    with pytest.raises(asyncio.CancelledError) as cancellation:
        await close
    assert cancellation.value.args in ((), ("exact-owner-cancel",))
    assert output.closed == 1
    assert not output.close_cancelled.is_set()
    output.release_close.set()
    assert await guard.observe_quarantine(deadline=asyncio.get_running_loop().time() + 0.1)


@pytest.mark.parametrize(
    "deadline",
    [float("nan"), float("inf"), 10**1_000, 1.0e12, True, _VoiceHostileFloat()],
    ids=("nan", "infinity", "oversized-int", "far-future-float", "bool", "hostile-subclass"),
)
@pytest.mark.asyncio
async def test_pipeline_observe_quarantine_invalid_deadline_uses_immediate_bound(
    deadline: object,
) -> None:
    harness = _harness()
    entered = asyncio.Event()
    cancelled = asyncio.Event()
    release = asyncio.Event()
    task = asyncio.create_task(_suppress_voice_cancellation(entered, cancelled, release))
    await entered.wait()
    harness.pipeline._deadlines._retain(task)  # noqa: SLF001 - public wrapper boundary probe

    try:
        complete = await asyncio.wait_for(
            harness.pipeline.observe_quarantine(deadline=deadline),  # type: ignore[arg-type]
            timeout=0.2,
        )
        assert complete is False
        assert task in harness.pipeline._deadlines._quarantine  # noqa: SLF001
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
        await asyncio.sleep(0)

    assert cancelled.is_set()
    assert await harness.pipeline.observe_quarantine(
        deadline=asyncio.get_running_loop().time() + 0.1
    )


@pytest.mark.asyncio
async def test_converter_output_close_failure_still_closes_pipeline_owned_input() -> None:
    harness = _harness()
    output = _CloseFailOutput(harness.converted_pcm)

    def close_failing_convert(
        audio: AsyncIterator[bytes],
        source: AudioFormat,
        target: AudioFormat,
    ) -> AsyncIterator[bytes]:
        harness.converter.calls += 1
        harness.converter.input_iterator = audio
        return output

    harness.converter.convert = close_failing_convert  # type: ignore[method-assign]
    observed: list[SpeechChunk] = []

    with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$") as error:
        async for chunk in harness.pipeline.run(harness.captured()):
            observed.append(chunk)

    assert observed == []
    assert output.closed == 1
    assert getattr(harness.converter.input_iterator, "ag_frame", None) is None
    assert harness.capture_pcm == bytearray()
    assert "private-close-body" not in repr(error.value)


@pytest.mark.asyncio
async def test_converter_output_close_cleanup_incomplete_is_preserved() -> None:
    harness = _harness()
    output = _CloseFailOutput(harness.converted_pcm, DeadlineCleanupIncomplete())

    def cleanup_incomplete_convert(
        audio: AsyncIterator[bytes],
        source: AudioFormat,
        target: AudioFormat,
    ) -> AsyncIterator[bytes]:
        harness.converter.calls += 1
        harness.converter.input_iterator = audio
        return output

    harness.converter.convert = cleanup_incomplete_convert  # type: ignore[method-assign]

    with pytest.raises(DeadlineCleanupIncomplete, match="^deadline-cleanup-incomplete$"):
        await _collect(harness.pipeline.run(harness.captured()))

    assert output.closed == 1
    assert getattr(harness.converter.input_iterator, "ag_frame", None) is None
    assert harness.capture_pcm == bytearray()


@pytest.mark.asyncio
async def test_converter_output_close_grouped_cleanup_incomplete_is_preserved() -> None:
    harness = _harness()
    output = _CloseFailOutput(
        harness.converted_pcm,
        ExceptionGroup(
            "private-close-group",
            [RuntimeError("private-close-body"), DeadlineCleanupIncomplete()],
        ),
    )

    def grouped_cleanup_incomplete_convert(
        audio: AsyncIterator[bytes],
        source: AudioFormat,
        target: AudioFormat,
    ) -> AsyncIterator[bytes]:
        harness.converter.calls += 1
        harness.converter.input_iterator = audio
        return output

    harness.converter.convert = grouped_cleanup_incomplete_convert  # type: ignore[method-assign]

    with pytest.raises(DeadlineCleanupIncomplete, match="^deadline-cleanup-incomplete$"):
        await _collect(harness.pipeline.run(harness.captured()))

    assert output.closed == 1
    assert getattr(harness.converter.input_iterator, "ag_frame", None) is None
    assert harness.capture_pcm == bytearray()


@pytest.mark.asyncio
async def test_converter_close_at_inclusive_tts_deadline_cannot_admit_playback() -> None:
    clock = _Clock()
    harness = _harness(clock=clock)
    output = _DeadlineAdvancingOutput(harness.converted_pcm, clock, close_at=30.0)

    def deadline_advancing_convert(
        audio: AsyncIterator[bytes],
        source: AudioFormat,
        target: AudioFormat,
    ) -> AsyncIterator[bytes]:
        harness.converter.calls += 1
        harness.converter.input_iterator = audio
        return output

    harness.converter.convert = deadline_advancing_convert  # type: ignore[method-assign]
    observed: list[SpeechChunk] = []

    with pytest.raises(VoiceTurnError, match="^voice-turn-rejected$"):
        async for chunk in harness.pipeline.run(harness.captured()):
            observed.append(chunk)

    assert observed == []
    assert output.closed == 1
    assert clock.current == 30.0
    assert getattr(harness.converter.input_iterator, "ag_frame", None) is None
    assert harness.capture_pcm == bytearray()


@pytest.mark.asyncio
async def test_late_quarantined_conversion_closes_stable_owned_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deadline_module, "_CANCEL_OBSERVE_SECONDS", 0.01, raising=False)
    clock = _Clock()
    harness = _harness(clock=clock)
    output = _CancellationSuppressingIterator((harness.converted_pcm,))

    def cancellation_suppressing_convert(
        audio: AsyncIterator[bytes],
        source: AudioFormat,
        target: AudioFormat,
    ) -> AsyncIterator[bytes]:
        harness.converter.calls += 1
        harness.converter.input_iterator = audio
        return cast(AsyncIterator[bytes], output)

    harness.converter.convert = cancellation_suppressing_convert  # type: ignore[method-assign]
    run = asyncio.create_task(_collect(harness.pipeline.run(harness.captured())))
    await output.entered.wait()
    clock.expire(30.0)

    try:
        with pytest.raises(DeadlineCleanupIncomplete, match="^deadline-cleanup-incomplete$"):
            await run
        assert output.cancelled.is_set()
        assert getattr(harness.converter.input_iterator, "ag_frame", None) is not None
    finally:
        output.release.set()
        assert await harness.pipeline.observe_quarantine(
            deadline=asyncio.get_running_loop().time() + 0.1
        )

    assert output.closed == 1
    assert getattr(harness.converter.input_iterator, "ag_frame", None) is None
    assert harness.capture_pcm == bytearray()


@pytest.mark.asyncio
async def test_converter_fatal_output_close_still_closes_pipeline_owned_input() -> None:
    harness = _harness()
    output = _CloseFailOutput(harness.converted_pcm, KeyboardInterrupt())

    def fatal_close_convert(
        audio: AsyncIterator[bytes],
        source: AudioFormat,
        target: AudioFormat,
    ) -> AsyncIterator[bytes]:
        harness.converter.input_iterator = audio
        return output

    harness.converter.convert = fatal_close_convert  # type: ignore[method-assign]

    with pytest.raises(KeyboardInterrupt):
        await _collect(harness.pipeline.run(harness.captured()))

    assert output.closed == 1
    assert getattr(harness.converter.input_iterator, "ag_frame", None) is None
    assert harness.capture_pcm == bytearray()


def test_pipeline_constructor_rejects_noncanonical_source_format_objects() -> None:
    harness = _harness()
    invalid_formats = (
        cast(AudioFormat, object()),
        AudioFormat.model_construct(
            sample_format="bogus",
            sample_rate_hz=0,
            channels=0,
            interleaved="no",
            channel_layout="bogus",
        ),
    )

    for invalid in invalid_formats:
        with pytest.raises(ValueError, match="^invalid-voice-turn-pipeline$"):
            VoiceTurnPipeline(
                stt=harness.stt,
                llm=harness.llm,
                tts=harness.tts,
                authorizer=harness.authorizer,
                converter=harness.converter,
                tts_source_format=invalid,
                clock=_Clock(),
            )


def test_test_data_is_nfc_so_non_nfc_case_is_intentional() -> None:
    assert normalize("NFC", _response("hi").text) == _response("hi").text
