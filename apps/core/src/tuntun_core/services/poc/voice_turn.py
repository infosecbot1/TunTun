"""In-memory STT-to-LLM-to-TTS pipeline for one supervised Reachy turn."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable
from contextlib import suppress
from inspect import isawaitable, iscoroutine
from sys import exception as active_exception
from typing import Literal, cast
from unicodedata import is_normalized

from tuntun_contracts.base import ContractModel
from tuntun_contracts.poc.framing import (
    MAX_DIRECTION_BYTES,
    MAX_MEDIA_SAMPLES,
    MAX_PCM_BYTES,
    MAX_TRANSPORT_PCM_FRAME_BYTES,
    TRANSPORT_AUDIO_FORMAT,
)
from tuntun_contracts.ports import (
    AudioConverterPort,
    LanguageModelPort,
    SpeechToTextPort,
    TextToSpeechPort,
)
from tuntun_contracts.provider import ProviderResponse, SanitizedProviderRequest
from tuntun_contracts.speech import (
    AudioFormat,
    AuthorizedSynthesisRequest,
    AuthorizedTranscriptionRequest,
    SpeechChunk,
    TranscriptResult,
)

from .deadlines import (
    DeadlineCleanupIncomplete,
    DeadlineGuard,
    _capture_asyncio_future,
    _claim_entry_cancellation,
    _detach_exception,
    _is_scalar_fatal,
    _trusted_done,
    masks_cleanup_incomplete,
)
from .ports import CapturedTurn, MonotonicClock, VoiceAttemptAuthorizerPort

_LANGUAGE_HINTS: tuple[Literal["en", "hi"], ...] = ("en", "hi")
_STT_SECONDS = 30.0
_REASONING_SECONDS = 45.0
_TTS_SECONDS = 30.0
_PROVIDER_SECONDS = 120.0
_REASONING_TIMEOUT_MS = 45_000
_MAX_SOURCE_SECONDS = 90


class VoiceTurnError(RuntimeError):
    """Content-free failure of one ephemeral voice turn."""

    def __init__(self) -> None:
        super().__init__("voice-turn-rejected")

    def __repr__(self) -> str:
        return "VoiceTurnError()"


def _wipe(buffer: bytearray) -> None:
    buffer[:] = b"\x00" * len(buffer)
    with suppress(BufferError):
        buffer.clear()


def _is_protected_task(
    value: object,
    protected_tasks: tuple[asyncio.Task[object], ...],
) -> bool:
    return any(value is protected for protected in protected_tasks)


async def _await_untrusted(
    awaitable: Awaitable[object],
    *,
    deadlines: DeadlineGuard,
    protected_tasks: tuple[asyncio.Task[object], ...],
) -> None:
    if _is_protected_task(awaitable, protected_tasks):
        raise VoiceTurnError
    target = asyncio.ensure_future(awaitable)
    current = asyncio.current_task()
    if target is current or _is_protected_task(target, protected_tasks):
        raise VoiceTurnError
    observer = asyncio.create_task(
        _capture_asyncio_future(target),
        name="voice-turn-passive-awaitable-observer",
    )
    if _trusted_done(target) is not True:
        deadlines.retain_passive(observer)
        raise DeadlineCleanupIncomplete from None
    outcome = await observer
    if outcome.error is not None:
        raise outcome.error


async def _close_owned(
    iterator: object,
    *,
    deadlines: DeadlineGuard,
    protected_tasks: tuple[asyncio.Task[object], ...],
) -> None:
    if _is_protected_task(iterator, protected_tasks):
        raise VoiceTurnError
    async_close = getattr(iterator, "aclose", None)
    if async_close is not None:
        result = async_close()
        if not isawaitable(result):
            raise VoiceTurnError
        if isinstance(result, asyncio.Future):
            await _await_untrusted(
                result,
                deadlines=deadlines,
                protected_tasks=protected_tasks,
            )
        else:
            await result
        return
    if iscoroutine(iterator):
        iterator.close()
        return
    if isinstance(iterator, asyncio.Future):
        await _await_untrusted(
            iterator,
            deadlines=deadlines,
            protected_tasks=protected_tasks,
        )
        return
    close = getattr(iterator, "close", None)
    if close is not None:
        result = close()
        if isawaitable(result):
            if isinstance(result, asyncio.Future):
                await _await_untrusted(
                    result,
                    deadlines=deadlines,
                    protected_tasks=protected_tasks,
                )
            else:
                await result


async def _capture_close(
    iterator: object,
    *,
    deadlines: DeadlineGuard,
    protected_tasks: tuple[asyncio.Task[object], ...],
    started: asyncio.Event,
) -> BaseException | None:
    started.set()
    try:
        await _close_owned(
            iterator,
            deadlines=deadlines,
            protected_tasks=protected_tasks,
        )
    except BaseException as error:
        return error
    return None


async def _close(
    iterator: object,
    *,
    deadlines: DeadlineGuard,
    protected_tasks: tuple[asyncio.Task[object], ...],
) -> None:
    started = asyncio.Event()
    close_task = asyncio.create_task(
        _capture_close(
            iterator,
            deadlines=deadlines,
            protected_tasks=protected_tasks,
            started=started,
        ),
        name="voice-turn-close-capture",
    )
    first_cancellation: asyncio.CancelledError | None = None
    while not started.is_set() and not close_task.done():
        try:
            await asyncio.sleep(0)
        except asyncio.CancelledError as error:
            del error
            if first_cancellation is None and _cancellation_pending():
                first_cancellation = await _claim_owner_cancellation()
    if first_cancellation is None and not close_task.done():
        try:
            await asyncio.shield(close_task)
        except asyncio.CancelledError as error:
            del error
            if _cancellation_pending():
                first_cancellation = await _claim_owner_cancellation()
    cleanup_incomplete = False
    cleanup_fatal: BaseException | None = None
    if first_cancellation is not None and not close_task.done():
        deadlines.retain_passive(close_task)
        cleanup_incomplete = True
    close_error = close_task.result() if close_task.done() else None
    close_task = cast(asyncio.Task[BaseException | None], None)
    if first_cancellation is not None:
        _detach_exception(first_cancellation)
        raise first_cancellation from None
    if close_error is not None and _is_scalar_fatal(close_error):
        _detach_exception(close_error)
        raise close_error from None
    if close_error is not None and masks_cleanup_incomplete(close_error):
        raise DeadlineCleanupIncomplete from None
    if cleanup_fatal is not None:
        _detach_exception(cleanup_fatal)
        raise cleanup_fatal from None
    if cleanup_incomplete:
        raise DeadlineCleanupIncomplete from None
    if close_error is None:
        return
    if isinstance(close_error, asyncio.CancelledError):
        _detach_exception(close_error)
        raise close_error from None
    raise VoiceTurnError from None


def _cancellation_pending() -> bool:
    task = asyncio.current_task()
    return task is not None and task.cancelling() > 0


def _raise_if_cancelling(cancellation: asyncio.CancelledError | None = None) -> None:
    if _cancellation_pending():
        if cancellation is not None:
            _detach_exception(cancellation)
            raise cancellation from None
        raise asyncio.CancelledError


async def _claim_owner_cancellation() -> asyncio.CancelledError:
    claimed = await _claim_entry_cancellation()
    if claimed is not None:
        return claimed
    return asyncio.CancelledError()


async def _close_all(
    *iterators: object,
    deadlines: DeadlineGuard,
    protected_tasks: tuple[asyncio.Task[object], ...] = (),
    preserve_cancellation: bool = False,
    defer_pending_cancellation: bool = False,
) -> None:
    primary_failure = active_exception()
    primary_scalar = (
        primary_failure
        if primary_failure is not None and _is_scalar_fatal(primary_failure)
        else None
    )
    close_failed = False
    cleanup_incomplete = primary_failure is not None and masks_cleanup_incomplete(primary_failure)
    close_cancelled: asyncio.CancelledError | None = None
    owner_cancellation: asyncio.CancelledError | None = None
    fatal_close_error: BaseException | None = None
    current = asyncio.current_task()
    all_protected = tuple(task for task in (*protected_tasks, current) if task is not None)
    seen: set[int] = set()
    for iterator in iterators:
        identity = id(iterator)
        if identity in seen:
            continue
        seen.add(identity)
        try:
            await _close(
                iterator,
                deadlines=deadlines,
                protected_tasks=all_protected,
            )
        except asyncio.CancelledError as error:
            if _cancellation_pending() and owner_cancellation is None:
                owner_cancellation = error
            if defer_pending_cancellation or not preserve_cancellation:
                if masks_cleanup_incomplete(error):
                    cleanup_incomplete = True
                elif close_cancelled is None:
                    close_cancelled = error
        except Exception as error:
            if masks_cleanup_incomplete(error):
                cleanup_incomplete = True
            else:
                close_failed = True
        except BaseExceptionGroup as error:
            if masks_cleanup_incomplete(error):
                cleanup_incomplete = True
            else:
                close_failed = True
        except BaseException as error:
            if fatal_close_error is None:
                fatal_close_error = error
    if not defer_pending_cancellation:
        if preserve_cancellation:
            return
        _raise_if_cancelling(owner_cancellation)
    if primary_scalar is not None:
        _detach_exception(primary_scalar)
        raise primary_scalar from None
    if fatal_close_error is not None:
        _detach_exception(fatal_close_error)
        raise fatal_close_error from None
    if cleanup_incomplete:
        raise DeadlineCleanupIncomplete from None
    if defer_pending_cancellation:
        if preserve_cancellation:
            return
        _raise_if_cancelling(owner_cancellation)
    if close_cancelled is not None:
        _detach_exception(close_cancelled)
        raise close_cancelled from None
    if close_failed:
        raise VoiceTurnError from None


async def _one_chunk(buffer: bytearray) -> AsyncIterator[bytes]:
    if buffer:
        yield bytes(buffer)


def _source_frame_bytes(audio_format: AudioFormat) -> int:
    sample_bytes = 2 if audio_format.sample_format == "s16le" else 4
    return sample_bytes * audio_format.channels


def _is_canonical_audio_format(value: object) -> bool:
    if type(value) is not AudioFormat:
        return False
    try:
        dumped = value.model_dump(mode="python", warnings="error")
        validated = AudioFormat.model_validate(dumped, strict=True)
    except Exception:
        return False
    return dumped == validated.model_dump(mode="python")


def _strict_contract[ContractT: ContractModel](
    value: object,
    model_type: type[ContractT],
) -> ContractT | None:
    if type(value) is not model_type:
        return None
    try:
        dumped = value.model_dump(mode="python", warnings="error")
        validated = model_type.model_validate(dumped, strict=True)
        if dumped != validated.model_dump(mode="python"):
            return None
    except Exception:
        return None
    return validated


def _valid_route_binding(
    request: AuthorizedTranscriptionRequest | SanitizedProviderRequest | AuthorizedSynthesisRequest,
    *,
    turn_id: object,
    purpose: str,
) -> bool:
    route = request.route
    return (
        route.request_id == request.request_id
        and route.turn_id == turn_id
        and route.purpose == purpose
    )


class VoiceTurnPipeline:
    """Authorize and fully buffer one turn before exposing any playback bytes."""

    def __init__(
        self,
        *,
        stt: SpeechToTextPort,
        llm: LanguageModelPort,
        tts: TextToSpeechPort,
        authorizer: VoiceAttemptAuthorizerPort,
        converter: AudioConverterPort,
        tts_source_format: AudioFormat,
        clock: MonotonicClock,
    ) -> None:
        if (
            not isinstance(stt, SpeechToTextPort)
            or not isinstance(llm, LanguageModelPort)
            or not isinstance(tts, TextToSpeechPort)
            or not isinstance(authorizer, VoiceAttemptAuthorizerPort)
            or not isinstance(converter, AudioConverterPort)
            or not _is_canonical_audio_format(tts_source_format)
        ):
            raise ValueError("invalid-voice-turn-pipeline")
        self._stt = stt
        self._llm = llm
        self._tts = tts
        self._authorizer = authorizer
        self._converter = converter
        self._tts_source_format = tts_source_format
        self._deadlines = DeadlineGuard(clock)

    @property
    def clock(self) -> MonotonicClock:
        return self._deadlines.clock

    async def observe_quarantine(self, *, deadline: float) -> bool:
        """Retain and observe deadline-owned work without transferring ownership."""

        try:
            return await self._observe_quarantine_owned(deadline=deadline)
        except BaseException as error:
            self = cast(VoiceTurnPipeline, None)
            deadline = cast(float, None)
            _detach_exception(error)
            raise error from None

    async def _observe_quarantine_owned(self, *, deadline: float) -> bool:
        return await self._deadlines.observe_quarantine(deadline=deadline)

    def run(self, captured: CapturedTurn) -> AsyncIterator[SpeechChunk]:
        if type(captured) is not CapturedTurn:
            raise ValueError("invalid-captured-turn")
        return self._run(captured)

    async def _run(self, captured: CapturedTurn) -> AsyncIterator[SpeechChunk]:
        public_owner = asyncio.current_task()
        input_pcm = bytearray()
        source_pcm = bytearray()
        converted_pcm = bytearray()
        transcript_text: list[str] = []
        response_text: list[str] = []
        failed = False
        cleanup_incomplete = False
        owner_cancellation: asyncio.CancelledError | None = None
        fatal_failure: BaseException | None = None
        abandoned = False
        view: memoryview | None = None
        transcription_candidate: object | None = None
        transcription_request: AuthorizedTranscriptionRequest | None = None
        stt_audio: AsyncIterator[bytes] | None = None
        transcript_candidate: object | None = None
        transcript: TranscriptResult | None = None
        reasoning_candidate: object | None = None
        reasoning_request: SanitizedProviderRequest | None = None
        response_candidate: object | None = None
        response: ProviderResponse | None = None
        synthesis_candidate: object | None = None
        synthesis_request: AuthorizedSynthesisRequest | None = None
        playback_builder: list[SpeechChunk] = []
        playback_chunks: tuple[SpeechChunk, ...] = ()
        try:
            input_pcm = captured.claim_pcm()
            turn_id = captured.turn_id
            duration_ms = captured.duration_ms

            provider_deadline = self._deadlines.deadline_after(_PROVIDER_SECONDS)
            stt_deadline = min(
                self._deadlines.deadline_after(_STT_SECONDS),
                provider_deadline,
            )

            view = memoryview(input_pcm).toreadonly()
            try:
                transcription_candidate = await self._deadlines.run(
                    self._authorizer.authorize_transcription(
                        turn_id=turn_id,
                        audio_format=TRANSPORT_AUDIO_FORMAT,
                        pcm=view,
                        duration_ms=duration_ms,
                        language_hints=_LANGUAGE_HINTS,
                    ),
                    deadline=stt_deadline,
                )
                _raise_if_cancelling()
            finally:
                view.release()
                view = None
            transcription_request = _strict_contract(
                transcription_candidate,
                AuthorizedTranscriptionRequest,
            )
            if transcription_request is None:
                raise VoiceTurnError
            if not self._valid_transcription_request(
                transcription_request,
                turn_id=turn_id,
                audio_bytes=len(input_pcm),
                duration_ms=duration_ms,
            ):
                raise VoiceTurnError

            stt_audio = _one_chunk(input_pcm)
            stt_cancelled = False
            try:
                transcript_candidate = await self._deadlines.run(
                    self._stt.transcribe(
                        transcription_request,
                        stt_audio,
                    ),
                    deadline=stt_deadline,
                )
                _raise_if_cancelling()
            except asyncio.CancelledError:
                stt_cancelled = True
                raise
            finally:
                await _close_all(
                    stt_audio,
                    deadlines=self._deadlines,
                    protected_tasks=(public_owner,) if public_owner is not None else (),
                    preserve_cancellation=stt_cancelled,
                )
                stt_audio = None
            transcript = _strict_contract(transcript_candidate, TranscriptResult)
            if (
                transcript is None
                or transcript.request_id != transcription_request.request_id
                or transcript.language not in {"en", "hi", "hinglish"}
                or transcript.duration_ms != duration_ms
                or type(transcript.text) is not str
                or not 1 <= len(transcript.text) <= 32_000
                or not is_normalized("NFC", transcript.text)
            ):
                raise VoiceTurnError
            transcript_text.append(transcript.text)
            _wipe(input_pcm)

            reasoning_deadline = min(
                self._deadlines.deadline_after(_REASONING_SECONDS),
                provider_deadline,
            )
            reasoning_candidate = await self._deadlines.run(
                self._authorizer.authorize_reasoning(
                    turn_id=turn_id,
                    transcript=transcript,
                ),
                deadline=reasoning_deadline,
            )
            _raise_if_cancelling()
            reasoning_request = _strict_contract(
                reasoning_candidate,
                SanitizedProviderRequest,
            )
            if reasoning_request is None:
                raise VoiceTurnError
            if not self._valid_reasoning_request(reasoning_request, turn_id=turn_id):
                raise VoiceTurnError
            response_candidate = await self._deadlines.run(
                self._llm.complete(reasoning_request),
                deadline=reasoning_deadline,
            )
            _raise_if_cancelling()
            response = _strict_contract(response_candidate, ProviderResponse)
            if response is None:
                raise VoiceTurnError
            if not self._valid_response(
                response,
                request=reasoning_request,
                transcript=transcript,
            ):
                raise VoiceTurnError
            response_text.append(response.text)

            tts_deadline = min(
                self._deadlines.deadline_after(_TTS_SECONDS),
                provider_deadline,
            )
            synthesis_candidate = await self._deadlines.run(
                self._authorizer.authorize_synthesis(
                    turn_id=turn_id,
                    response=response,
                ),
                deadline=tts_deadline,
            )
            _raise_if_cancelling()
            synthesis_request = _strict_contract(
                synthesis_candidate,
                AuthorizedSynthesisRequest,
            )
            if synthesis_request is None:
                raise VoiceTurnError
            if not self._valid_synthesis_request(
                synthesis_request,
                turn_id=turn_id,
                response=response,
            ):
                raise VoiceTurnError

            async def buffer_owned_source() -> int:
                owned_request = synthesis_request
                if owned_request is None:
                    raise VoiceTurnError
                owned_stream = self._tts.synthesize(owned_request)
                try:
                    return await self._buffer_source(
                        owned_stream,
                        request_id=owned_request.request_id,
                        destination=source_pcm,
                        protected_owner=public_owner,
                    )
                finally:
                    if abandoned:
                        _wipe(source_pcm)

            source_samples = await self._deadlines.run(
                buffer_owned_source(),
                deadline=tts_deadline,
            )

            async def buffer_owned_conversion() -> None:
                owned_input = _one_chunk(source_pcm)
                owned_stream: AsyncIterator[bytes] | None = None
                conversion_cancelled = False
                try:
                    owned_stream = self._converter.convert(
                        owned_input,
                        self._tts_source_format,
                        TRANSPORT_AUDIO_FORMAT,
                    )
                    await self._buffer_converted(
                        owned_stream,
                        source_samples=source_samples,
                        destination=converted_pcm,
                        protected_owner=public_owner,
                    )
                except asyncio.CancelledError:
                    conversion_cancelled = True
                    raise
                finally:
                    try:
                        await _close_all(
                            owned_input,
                            deadlines=self._deadlines,
                            protected_tasks=((public_owner,) if public_owner is not None else ()),
                            preserve_cancellation=conversion_cancelled,
                            defer_pending_cancellation=True,
                        )
                    finally:
                        if abandoned:
                            _wipe(converted_pcm)

            await self._deadlines.run(
                buffer_owned_conversion(),
                deadline=tts_deadline,
            )
            _wipe(source_pcm)

            request_id = synthesis_request.request_id
            sequence = 0
            for offset in range(0, len(converted_pcm), MAX_TRANSPORT_PCM_FRAME_BYTES):
                playback_builder.append(
                    SpeechChunk(
                        request_id=request_id,
                        sequence=sequence,
                        pcm=bytes(converted_pcm[offset : offset + MAX_TRANSPORT_PCM_FRAME_BYTES]),
                        final=False,
                    )
                )
                sequence += 1
            playback_builder.append(
                SpeechChunk(
                    request_id=request_id,
                    sequence=sequence,
                    pcm=b"",
                    final=True,
                )
            )
            playback_chunks = tuple(playback_builder)
            playback_builder.clear()
            _wipe(converted_pcm)
            view = None
            transcription_candidate = None
            transcription_request = None
            stt_audio = None
            transcript_candidate = None
            transcript = None
            reasoning_candidate = None
            reasoning_request = None
            response_candidate = None
            response = None
            synthesis_candidate = None
            synthesis_request = None
            transcript_text.clear()
            response_text.clear()
            for playback_chunk in playback_chunks:
                yield playback_chunk
        except asyncio.CancelledError as error:
            if _cancellation_pending():
                owner_cancellation = await _claim_owner_cancellation()
            elif masks_cleanup_incomplete(error):
                cleanup_incomplete = True
            else:
                failed = True
        except DeadlineCleanupIncomplete:
            if _cancellation_pending():
                owner_cancellation = await _claim_owner_cancellation()
            else:
                cleanup_incomplete = True
        except BaseExceptionGroup as error:
            if _cancellation_pending():
                owner_cancellation = await _claim_owner_cancellation()
            elif masks_cleanup_incomplete(error):
                cleanup_incomplete = True
            else:
                failed = True
        except VoiceTurnError as error:
            if _cancellation_pending():
                owner_cancellation = await _claim_owner_cancellation()
            elif masks_cleanup_incomplete(error):
                cleanup_incomplete = True
            else:
                failed = True
        except Exception as error:
            if _cancellation_pending():
                owner_cancellation = await _claim_owner_cancellation()
            elif masks_cleanup_incomplete(error):
                cleanup_incomplete = True
            else:
                failed = True
        except BaseException as error:
            if _cancellation_pending():
                owner_cancellation = await _claim_owner_cancellation()
            else:
                fatal_failure = error
        finally:
            abandoned = True
            captured.clear()
            _wipe(input_pcm)
            _wipe(source_pcm)
            _wipe(converted_pcm)
            transcript_text.clear()
            response_text.clear()
            view = None
            transcription_candidate = None
            transcription_request = None
            stt_audio = None
            transcript_candidate = None
            transcript = None
            reasoning_candidate = None
            reasoning_request = None
            response_candidate = None
            response = None
            synthesis_candidate = None
            synthesis_request = None
            playback_builder.clear()
            playback_chunks = ()
        if owner_cancellation is not None:
            _detach_exception(owner_cancellation)
            raise owner_cancellation from None
        if fatal_failure is not None:
            fatal = fatal_failure
            fatal_failure = None
            _detach_exception(fatal)
            raise fatal from None
        if cleanup_incomplete:
            raise DeadlineCleanupIncomplete
        if failed:
            raise VoiceTurnError

    @staticmethod
    def _valid_transcription_request(
        request: object,
        *,
        turn_id: object,
        audio_bytes: int,
        duration_ms: int,
    ) -> bool:
        return (
            type(request) is AuthorizedTranscriptionRequest
            and request.turn_id == turn_id
            and request.audio_format == TRANSPORT_AUDIO_FORMAT
            and request.audio_bytes == audio_bytes
            and request.duration_ms == duration_ms
            and request.language_hints == _LANGUAGE_HINTS
            and request.audio_commitment == request.route.request_commitment
            and request.route.max_input_bytes >= audio_bytes
            and _valid_route_binding(
                request,
                turn_id=turn_id,
                purpose="cloud_stt",
            )
        )

    @staticmethod
    def _valid_reasoning_request(request: object, *, turn_id: object) -> bool:
        return (
            type(request) is SanitizedProviderRequest
            and bool(request.messages)
            and request.allowed_tools == ()
            and request.store is False
            and request.timeout_ms == _REASONING_TIMEOUT_MS
            and _valid_route_binding(
                request,
                turn_id=turn_id,
                purpose="cloud_reasoning",
            )
            and request.provider.value == request.route.provider
            and request.model == request.route.model
        )

    @staticmethod
    def _valid_response(
        response: object,
        *,
        request: SanitizedProviderRequest,
        transcript: TranscriptResult,
    ) -> bool:
        return (
            type(response) is ProviderResponse
            and response.request_id == request.request_id
            and response.language == transcript.language
            and 1 <= len(response.text) <= 4_096
            and is_normalized("NFC", response.text)
        )

    @staticmethod
    def _valid_synthesis_request(
        request: object,
        *,
        turn_id: object,
        response: ProviderResponse,
    ) -> bool:
        return (
            type(request) is AuthorizedSynthesisRequest
            and request.turn_id == turn_id
            and request.text == response.text
            and request.language == response.language
            and request.segment_index == 0
            and request.segment_count == 1
            and request.text_commitment == request.route.request_commitment
            and request.route.max_input_bytes >= len(request.text.encode("utf-8"))
            and _valid_route_binding(
                request,
                turn_id=turn_id,
                purpose="cloud_tts",
            )
        )

    async def _buffer_source(
        self,
        stream: AsyncIterator[SpeechChunk],
        *,
        request_id: object,
        destination: bytearray,
        protected_owner: asyncio.Task[object] | None,
    ) -> int:
        expected_sequence = 0
        final_seen = False
        frame_bytes = _source_frame_bytes(self._tts_source_format)
        source_cancelled = False
        iterator: AsyncIterator[SpeechChunk] | None = None
        candidate: object | None = None
        chunk: SpeechChunk | None = None
        try:
            iterator = aiter(stream)
            while True:
                try:
                    candidate = await anext(iterator)
                except StopAsyncIteration:
                    break
                _raise_if_cancelling()
                chunk = _strict_contract(candidate, SpeechChunk)
                if (
                    chunk is None
                    or final_seen
                    or chunk.request_id != request_id
                    or chunk.sequence != expected_sequence
                    or type(chunk.pcm) is not bytes
                ):
                    raise VoiceTurnError
                expected_sequence += 1
                if chunk.final:
                    if chunk.pcm:
                        raise VoiceTurnError
                    final_seen = True
                    continue
                if (
                    not chunk.pcm
                    or len(chunk.pcm) > MAX_PCM_BYTES
                    or len(chunk.pcm) % frame_bytes
                    or len(destination) + len(chunk.pcm) > MAX_DIRECTION_BYTES
                ):
                    raise VoiceTurnError
                destination.extend(chunk.pcm)
                if (
                    len(destination) // frame_bytes
                    > self._tts_source_format.sample_rate_hz * _MAX_SOURCE_SECONDS
                ):
                    raise VoiceTurnError
            _raise_if_cancelling()
            if not final_seen or not destination:
                raise VoiceTurnError
            return len(destination) // frame_bytes
        except asyncio.CancelledError:
            source_cancelled = True
            raise
        finally:
            try:
                await _close_all(
                    *((iterator, stream) if iterator is not None else (stream,)),
                    deadlines=self._deadlines,
                    protected_tasks=(protected_owner,) if protected_owner is not None else (),
                    preserve_cancellation=source_cancelled,
                    defer_pending_cancellation=True,
                )
            finally:
                iterator = None
                candidate = None
                chunk = None

    async def _buffer_converted(
        self,
        stream: AsyncIterator[bytes],
        *,
        source_samples: int,
        destination: bytearray,
        protected_owner: asyncio.Task[object] | None,
    ) -> None:
        iterator: AsyncIterator[bytes] | None = None
        candidate: object | None = None
        conversion_cancelled = False
        try:
            iterator = aiter(stream)
            while True:
                try:
                    candidate = await anext(iterator)
                except StopAsyncIteration:
                    break
                _raise_if_cancelling()
                if (
                    type(candidate) is not bytes
                    or not candidate
                    or len(candidate) > MAX_PCM_BYTES
                    or len(candidate) % 2
                    or len(destination) + len(candidate) > MAX_DIRECTION_BYTES
                ):
                    raise VoiceTurnError
                destination.extend(candidate)
                if len(destination) // 2 > MAX_MEDIA_SAMPLES:
                    raise VoiceTurnError
            _raise_if_cancelling()
            if not destination:
                raise VoiceTurnError
            converted_samples = len(destination) // 2
            if (
                abs(
                    converted_samples * self._tts_source_format.sample_rate_hz
                    - source_samples * TRANSPORT_AUDIO_FORMAT.sample_rate_hz
                )
                > self._tts_source_format.sample_rate_hz
            ):
                raise VoiceTurnError
        except asyncio.CancelledError:
            conversion_cancelled = True
            raise
        finally:
            try:
                await _close_all(
                    *((iterator, stream) if iterator is not None else (stream,)),
                    deadlines=self._deadlines,
                    protected_tasks=(protected_owner,) if protected_owner is not None else (),
                    preserve_cancellation=conversion_cancelled,
                    defer_pending_cancellation=True,
                )
            finally:
                iterator = None
                candidate = None
