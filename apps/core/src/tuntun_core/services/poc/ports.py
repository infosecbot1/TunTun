"""Core-owned ports and ephemeral capture ownership for the Reachy PTT slice."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable
from contextlib import suppress
from enum import StrEnum
from hashlib import sha256
from hmac import compare_digest
from typing import Literal, NoReturn, Protocol, Self, SupportsIndex, runtime_checkable
from uuid import UUID

from tuntun_contracts.poc.framing import (
    MAX_DIRECTION_BYTES,
    MAX_MEDIA_SAMPLES,
    TRANSPORT_AUDIO_FORMAT,
)
from tuntun_contracts.provider import ProviderResponse, SanitizedProviderRequest
from tuntun_contracts.speech import (
    AudioFormat,
    AuthorizedSynthesisRequest,
    AuthorizedTranscriptionRequest,
    SpeechChunk,
    TranscriptResult,
)


class CorePttEvent(StrEnum):
    START = "start"
    SUBMIT = "submit"
    CANCEL = "cancel"


class PttSendCommit(StrEnum):
    COMMITTED = "committed"
    UNCOMMITTED = "uncommitted"


@runtime_checkable
class CorePttInputPort(Protocol):
    """Terminal input whose receive/close cancellation must settle within the Core bound."""

    async def receive(self) -> CorePttEvent: ...

    async def close(self) -> None: ...


@runtime_checkable
class PttBridgePort(Protocol):
    """Bounded frame transport with bounded cancellation and priority admission.

    COMMITTED means the complete frame was admitted before return; UNCOMMITTED means no part can
    commit later. A cancelled, failed, or otherwise unsuccessful send cannot commit later. The
    synchronous call to close atomically fences every uncommitted and future send before returning
    its bounded awaitable. The first close call fixes one nonrenewable real-loop epoch S0; its
    awaitable must settle no later than S0+3 seconds, and repeated close calls cannot restart that
    budget. Priority admission is reserved from normal-media backpressure. Bytes already committed
    at a cancellation tie are unavoidable and require peer late-discard. A hardware adapter must
    separately qualify speaker sink/drain completion.
    """

    async def receive(self, max_bytes: int) -> bytes: ...

    def send(self, frame: bytes, *, priority: bool) -> Awaitable[PttSendCommit]: ...

    def close(self) -> Awaitable[None]: ...


@runtime_checkable
class ProviderCancellationPort(Protocol):
    async def close_active_transport(self, *, turn_id: UUID) -> None: ...


@runtime_checkable
class MonotonicClock(Protocol):
    """Clock whose sleeper must honor bounded task cancellation."""

    def now(self) -> float: ...

    async def sleep_until(self, deadline: float) -> None: ...


@runtime_checkable
class VoiceAttemptAuthorizerPort(Protocol):
    async def authorize_transcription(
        self,
        *,
        turn_id: UUID,
        audio_format: AudioFormat,
        pcm: memoryview,
        duration_ms: int,
        language_hints: tuple[Literal["en", "hi"], ...],
    ) -> AuthorizedTranscriptionRequest: ...

    async def authorize_reasoning(
        self,
        *,
        turn_id: UUID,
        transcript: TranscriptResult,
    ) -> SanitizedProviderRequest: ...

    async def authorize_synthesis(
        self,
        *,
        turn_id: UUID,
        response: ProviderResponse,
    ) -> AuthorizedSynthesisRequest: ...


@runtime_checkable
class VoiceTurnPort(Protocol):
    """Ephemeral voice pipeline whose retained deadline work remains observable."""

    @property
    def clock(self) -> MonotonicClock: ...

    def run(self, captured: CapturedTurn) -> AsyncIterator[SpeechChunk]: ...

    def observe_quarantine(self, *, deadline: float) -> Awaitable[bool]:
        """Settle retained work by a real-loop absolute deadline, or return false."""

        ...


class CapturedTurnError(RuntimeError):
    """Content-free ownership failure."""

    def __init__(self) -> None:
        super().__init__("captured-turn-unavailable")


_OWNERSHIP_TOKEN = object()


def _is_canonical_transport_format(value: object) -> bool:
    if type(value) is not AudioFormat:
        return False
    try:
        dumped = value.model_dump(mode="python", warnings="error")
        validated = AudioFormat.model_validate(dumped, strict=True)
    except Exception:
        return False
    return dumped == validated.model_dump(mode="python") and validated == TRANSPORT_AUDIO_FORMAT


class CapturedTurn:
    """A single-use owner for one bounded mutable transport-PCM capture."""

    __slots__ = (
        "_audio_bytes",
        "_audio_format",
        "_duration_ms",
        "_integrity_tag",
        "_pcm",
        "_turn_id",
    )
    __hash__ = None  # type: ignore[assignment]

    def __init__(
        self,
        *,
        turn_id: UUID,
        audio_format: AudioFormat,
        pcm: bytearray,
        _token: object,
    ) -> None:
        if _token is not _OWNERSHIP_TOKEN:
            raise CapturedTurnError
        self._turn_id = turn_id
        self._audio_format = audio_format
        self._pcm: bytearray | None = pcm
        self._audio_bytes = len(pcm)
        self._integrity_tag: bytes | None = sha256(pcm).digest()
        samples = self._audio_bytes // 2
        self._duration_ms = (samples * 1_000 + 15_999) // 16_000

    @classmethod
    def take_ownership(
        cls,
        *,
        turn_id: UUID,
        audio_format: AudioFormat,
        pcm: bytearray,
    ) -> Self:
        if not isinstance(turn_id, UUID):
            raise TypeError("invalid-captured-turn")
        if not _is_canonical_transport_format(audio_format):
            raise ValueError("invalid-captured-turn")
        if type(pcm) is not bytearray:
            raise TypeError("invalid-captured-turn")
        pcm_bytes = len(pcm)
        if (
            not 1 <= pcm_bytes <= MAX_DIRECTION_BYTES
            or pcm_bytes % 2
            or pcm_bytes // 2 > MAX_MEDIA_SAMPLES
        ):
            raise ValueError("invalid-captured-turn")
        return cls(
            turn_id=turn_id,
            audio_format=audio_format,
            pcm=pcm,
            _token=_OWNERSHIP_TOKEN,
        )

    @property
    def turn_id(self) -> UUID:
        return self._turn_id

    @property
    def audio_format(self) -> AudioFormat:
        return self._audio_format

    @property
    def audio_bytes(self) -> int:
        return self._audio_bytes

    @property
    def duration_ms(self) -> int:
        return self._duration_ms

    def claim_pcm(self) -> bytearray:
        pcm = self._pcm
        integrity_tag = self._integrity_tag
        if (
            pcm is None
            or integrity_tag is None
            or len(pcm) != self._audio_bytes
            or not compare_digest(sha256(pcm).digest(), integrity_tag)
        ):
            self.clear()
            raise CapturedTurnError
        self._pcm = None
        self._integrity_tag = None
        return pcm

    def clear(self) -> None:
        pcm = getattr(self, "_pcm", None)
        self._pcm = None
        self._integrity_tag = None
        if pcm is not None:
            pcm[:] = b"\x00" * len(pcm)
            with suppress(BufferError):
                pcm.clear()

    def __repr__(self) -> str:
        return "CapturedTurn(<redacted>)"

    def __copy__(self) -> Self:
        raise CapturedTurnError

    def __deepcopy__(self, memo: dict[int, object]) -> Self:
        raise CapturedTurnError

    def __reduce__(self) -> NoReturn:
        raise CapturedTurnError

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise CapturedTurnError

    def __getstate__(self) -> NoReturn:
        raise CapturedTurnError

    def __eq__(self, other: object) -> bool:
        raise CapturedTurnError

    def __del__(self) -> None:
        self.clear()
