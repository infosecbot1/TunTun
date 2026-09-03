from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID

from tuntun_core.domain.offline import OfflineMatch
from tuntun_core.offline.grammar import parse_offline

OFFLINE_ASR_MODEL_IDS = ("vosk-small-en-us-0.15", "vosk-small-hi-0.22")
OFFLINE_ASR_PURPOSE = "offline_command"
MAX_OFFLINE_ASR_AUDIO_BYTES = 8_388_608
MAX_OFFLINE_ASR_CHUNK_BYTES = 65_536
MIN_OFFLINE_ASR_CONFIDENCE_MICROS = 500_000


class ActivatedModelPort(Protocol):
    model_id: str

    def close(self) -> None: ...


class ModelRegistryPort(Protocol):
    def require_activated(self, model_id: str, purpose: str) -> ActivatedModelPort: ...


class LocalAsrDecoder(Protocol):
    def __call__(self, model: ActivatedModelPort, audio: memoryview) -> LocalAsrHypothesis: ...


@dataclass(frozen=True, slots=True)
class LocalAsrHypothesis:
    text: str = field(repr=False)
    confidence_micros: int = 1_000_000

    def __post_init__(self) -> None:
        if type(self.text) is not str:
            raise TypeError("offline_asr_hypothesis_text_invalid")
        if type(self.confidence_micros) is not int or not 0 <= self.confidence_micros <= 1_000_000:
            raise ValueError("offline_asr_hypothesis_confidence_invalid")


class LocalAsrRecognizer:
    __slots__ = ("_decode", "_max_audio_bytes", "_minimum_confidence_micros", "_registry")

    def __init__(
        self,
        registry: ModelRegistryPort,
        decode: LocalAsrDecoder,
        *,
        minimum_confidence_micros: int = MIN_OFFLINE_ASR_CONFIDENCE_MICROS,
        max_audio_bytes: int = MAX_OFFLINE_ASR_AUDIO_BYTES,
    ) -> None:
        if not callable(decode):
            raise TypeError("offline_asr_decoder_invalid")
        if (
            type(minimum_confidence_micros) is not int
            or not 0 <= minimum_confidence_micros <= 1_000_000
            or type(max_audio_bytes) is not int
            or not 2 <= max_audio_bytes <= MAX_OFFLINE_ASR_AUDIO_BYTES
            or max_audio_bytes % 2 != 0
        ):
            raise ValueError("offline_asr_bounds_invalid")
        self._registry = registry
        self._decode = decode
        self._minimum_confidence_micros = minimum_confidence_micros
        self._max_audio_bytes = max_audio_bytes

    async def recognize(self, turn_id: UUID, audio: AsyncIterator[bytes]) -> OfflineMatch:
        if type(turn_id) is not UUID:
            raise TypeError("turn_id must be an exact UUID")
        if not hasattr(audio, "__aiter__"):
            raise TypeError("offline_asr_audio_iterator_invalid")
        activated: list[ActivatedModelPort] = []
        payload = bytearray()
        view: memoryview | None = None
        primary_error: BaseException | None = None
        try:
            await self._read_pcm16(audio, payload)
            for model_id in OFFLINE_ASR_MODEL_IDS:
                activated.append(self._registry.require_activated(model_id, OFFLINE_ASR_PURPOSE))
            view = memoryview(payload).toreadonly()
            matches = tuple(self._match(model, view) for model in activated)
            return _select_match(matches)
        except BaseException as error:
            primary_error = error
            raise
        finally:
            cleanup_error = await _cleanup(audio, payload, view, tuple(activated))
            if cleanup_error is not None:
                if primary_error is not None:
                    primary_error.add_note("offline_asr_cleanup_failed")
                else:
                    raise cleanup_error

    async def _read_pcm16(self, audio: AsyncIterator[bytes], payload: bytearray) -> None:
        async for chunk in audio:
            if type(chunk) is not bytes or not chunk or len(chunk) > MAX_OFFLINE_ASR_CHUNK_BYTES:
                raise ValueError("offline_asr_audio_chunk_invalid")
            if len(chunk) > self._max_audio_bytes - len(payload):
                raise ValueError("offline_asr_audio_too_large")
            payload.extend(chunk)
        if not payload or len(payload) % 2 != 0:
            raise ValueError("offline_asr_audio_pcm16_invalid")

    def _match(self, model: ActivatedModelPort, audio: memoryview) -> OfflineMatch:
        hypothesis = self._decode(model, audio)
        if type(hypothesis) is not LocalAsrHypothesis:
            raise TypeError("offline_asr_decoder_invalid")
        if hypothesis.confidence_micros < self._minimum_confidence_micros:
            return _no_match()
        return parse_offline(hypothesis.text, None)


def _select_match(matches: tuple[OfflineMatch, ...]) -> OfflineMatch:
    accepted = tuple(match for match in matches if match.intent != "no_match")
    if not accepted:
        return _no_match()
    first = accepted[0]
    if any(item != first for item in accepted[1:]):
        return _no_match()
    return first


def _no_match() -> OfflineMatch:
    return OfflineMatch(intent="no_match", confidence_micros=0)


async def _cleanup(
    audio: AsyncIterator[bytes],
    payload: bytearray,
    view: memoryview | None,
    activated: tuple[ActivatedModelPort, ...],
) -> RuntimeError | None:
    first_error: BaseException | None = None
    try:
        if view is not None:
            view.release()
    except BaseException as error:
        if first_error is None:
            first_error = error
    try:
        if payload:
            for index in range(len(payload)):
                payload[index] = 0
            with contextlib.suppress(BufferError):
                payload.clear()
    except BaseException as error:
        first_error = error
    for model in reversed(activated):
        try:
            model.close()
        except BaseException as error:
            if first_error is None:
                first_error = error
    close_audio = getattr(audio, "aclose", None)
    if callable(close_audio):
        try:
            await close_audio()
        except BaseException as error:
            if first_error is None:
                first_error = error
    if first_error is None:
        return None
    failure = RuntimeError("offline_asr_cleanup_failed")
    failure.__cause__ = first_error
    return failure


__all__ = (
    "MAX_OFFLINE_ASR_AUDIO_BYTES",
    "MAX_OFFLINE_ASR_CHUNK_BYTES",
    "MIN_OFFLINE_ASR_CONFIDENCE_MICROS",
    "OFFLINE_ASR_MODEL_IDS",
    "OFFLINE_ASR_PURPOSE",
    "ActivatedModelPort",
    "LocalAsrDecoder",
    "LocalAsrHypothesis",
    "LocalAsrRecognizer",
    "ModelRegistryPort",
)
