"""Bounded disposable framing for the supervised Reachy PTT proof of concept."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from math import isfinite
from struct import Struct
from typing import ClassVar, NoReturn, Self, TypeAlias
from uuid import UUID

from pydantic import model_validator

from tuntun_contracts.base import (
    ContractModel,
    ContractParseError,
    canonical_bytes,
    parse_contract_json,
)
from tuntun_contracts.speech import AudioFormat

MAGIC = b"TTPT"
PROTOCOL_VERSION = 1
PREFIX = Struct(">4sBBHII16s")
PREFIX_BYTES = PREFIX.size
MAX_CONTROL_BYTES = 4_096
MAX_PCM_BYTES = 65_536
MAX_FEED_BYTES = 65_536
MAX_FRAMES_PER_FEED = 64
UINT32_MAX = 2**32 - 1
MAX_TRANSPORT_PCM_FRAME_BYTES = 6_400
MAX_DIRECTION_BYTES = 8_388_608
MAX_MEDIA_SAMPLES = 16_000 * 90
MAX_MEDIA_WALL_SECONDS = 90.0
MAX_PCM_FRAMES_PER_SECOND = 50

TRANSPORT_AUDIO_FORMAT = AudioFormat(
    sample_format="s16le",
    sample_rate_hz=16_000,
    channels=1,
    interleaved=False,
    channel_layout="mono",
)


class FrameKind(IntEnum):
    CONTROL = 1
    PCM = 2


class ControlKind(StrEnum):
    SESSION_OPEN = "session_open"
    SESSION_READY = "session_ready"
    PTT_START = "ptt_start"
    PTT_SUBMIT = "ptt_submit"
    HEARTBEAT = "heartbeat"
    CAPTURE_START = "capture_start"
    CAPTURE_END = "capture_end"
    PLAYBACK_START = "playback_start"
    PLAYBACK_END = "playback_end"
    STOP = "stop"
    CANCEL = "cancel"
    ABORT = "abort"
    SAFETY_RECEIPT = "safety_receipt"
    SAFETY_ACK = "safety_ack"
    ERROR = "error"


class PttInputMode(StrEnum):
    REACHY_LOCAL = "reachy_local"
    CORE_TERMINAL_TOGGLE = "core_terminal_toggle"


class StreamDirection(StrEnum):
    EDGE_TO_CORE = "edge_to_core"
    CORE_TO_EDGE = "core_to_edge"


class GuardDisposition(StrEnum):
    ACCEPTED = "accepted"
    LATE_DISCARDED = "late_discarded"


class PttStopSource(StrEnum):
    SUPERVISOR_INPUT = "supervisor_input"
    CORE_ABORT = "core_abort"
    PEER_EOF = "peer_eof"
    WATCHDOG = "watchdog"
    PROTOCOL_REJECTED = "protocol_rejected"


class PttErrorReason(StrEnum):
    PROTOCOL_REJECTED = "protocol_rejected"
    TURN_CANCELLED = "turn_cancelled"
    CAPTURE_FAILED = "capture_failed"
    PROVIDER_FAILED = "provider_failed"
    PLAYBACK_FAILED = "playback_failed"
    CLEANUP_INCOMPLETE = "cleanup_incomplete"
    PEER_CLOSED = "peer_closed"
    SESSION_TIMEOUT = "session_timeout"


class PttSessionOutcome(StrEnum):
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    PEER_CLOSED = "peer_closed"
    PROTOCOL_REJECTED = "protocol_rejected"
    CAPTURE_FAILED = "capture_failed"
    PROVIDER_FAILED = "provider_failed"
    PLAYBACK_FAILED = "playback_failed"
    CLEANUP_INCOMPLETE = "cleanup_incomplete"
    SESSION_TIMEOUT = "session_timeout"


class FrameErrorCode(StrEnum):
    CLOSED = "closed"
    FEED_TOO_LARGE = "feed_too_large"
    TOO_MANY_FRAMES = "too_many_frames"
    INVALID_PREFIX = "invalid_prefix"
    INVALID_LENGTH = "invalid_length"
    INVALID_CONTROL = "invalid_control"
    TURN_MISMATCH = "turn_mismatch"
    TRUNCATED = "truncated"
    INVALID_SEQUENCE = "invalid_sequence"
    INVALID_DIRECTION = "invalid_direction"
    INVALID_ORDER = "invalid_order"
    PCM_LIMIT = "pcm_limit"
    DURATION_LIMIT = "duration_limit"
    RATE_LIMIT = "rate_limit"
    INVALID_CLOCK = "invalid_clock"


class FrameProtocolError(Exception):
    """Closed, content-free protocol failure."""

    def __init__(self, code: FrameErrorCode) -> None:
        if not isinstance(code, FrameErrorCode):
            raise TypeError("code must be a FrameErrorCode")
        self.code = code
        super().__init__(code.value)

    def __repr__(self) -> str:
        return f"FrameProtocolError(code={self.code.value!r})"


class EmptyPayload(ContractModel):
    pass


class SessionPayload(ContractModel):
    input_mode: PttInputMode


class StartPayload(ContractModel):
    audio_format: AudioFormat


class PttSafetyReceipt(ContractModel):
    turn_id: UUID
    new_capture_rejected: bool
    recording_stopped: bool
    playback_stopped: bool
    motion_stopped: bool
    audio_reactive_disabled: bool
    owned_buffers_cleared: bool

    def is_complete(self) -> bool:
        return all(
            (
                self.new_capture_rejected,
                self.recording_stopped,
                self.playback_stopped,
                self.motion_stopped,
                self.audio_reactive_disabled,
                self.owned_buffers_cleared,
            )
        )


class SafetyPayload(ContractModel):
    receipt: PttSafetyReceipt


class AckPayload(ContractModel):
    accepted: bool


class ErrorPayload(ContractModel):
    reason_code: PttErrorReason


PttPayload: TypeAlias = (  # noqa: UP040 - package must remain importable on Python 3.11
    EmptyPayload | SessionPayload | StartPayload | SafetyPayload | AckPayload | ErrorPayload
)


class PttControl(ContractModel):
    kind: ControlKind
    turn_id: UUID
    payload: PttPayload

    _PAYLOAD_TYPES: ClassVar[dict[ControlKind, type[ContractModel]]] = {
        ControlKind.SESSION_OPEN: SessionPayload,
        ControlKind.SESSION_READY: SessionPayload,
        ControlKind.CAPTURE_START: StartPayload,
        ControlKind.PLAYBACK_START: StartPayload,
        ControlKind.SAFETY_RECEIPT: SafetyPayload,
        ControlKind.SAFETY_ACK: AckPayload,
        ControlKind.ABORT: ErrorPayload,
        ControlKind.ERROR: ErrorPayload,
        ControlKind.PTT_START: EmptyPayload,
        ControlKind.PTT_SUBMIT: EmptyPayload,
        ControlKind.HEARTBEAT: EmptyPayload,
        ControlKind.CAPTURE_END: EmptyPayload,
        ControlKind.PLAYBACK_END: EmptyPayload,
        ControlKind.STOP: EmptyPayload,
        ControlKind.CANCEL: EmptyPayload,
    }

    @model_validator(mode="after")
    def exact_payload_for_kind(self) -> Self:
        expected = self._PAYLOAD_TYPES[self.kind]
        if type(self.payload) is not expected:
            raise ValueError("control payload does not match kind")
        if isinstance(self.payload, SafetyPayload) and self.payload.receipt.turn_id != self.turn_id:
            raise ValueError("safety receipt turn mismatch")
        return self

    @classmethod
    def session_open(cls, turn_id: UUID, input_mode: PttInputMode) -> Self:
        return cls(
            kind=ControlKind.SESSION_OPEN,
            turn_id=turn_id,
            payload=SessionPayload(input_mode=input_mode),
        )

    @classmethod
    def session_ready(cls, turn_id: UUID, input_mode: PttInputMode) -> Self:
        return cls(
            kind=ControlKind.SESSION_READY,
            turn_id=turn_id,
            payload=SessionPayload(input_mode=input_mode),
        )

    @classmethod
    def ptt_start(cls, turn_id: UUID) -> Self:
        return cls(kind=ControlKind.PTT_START, turn_id=turn_id, payload=EmptyPayload())

    @classmethod
    def ptt_submit(cls, turn_id: UUID) -> Self:
        return cls(kind=ControlKind.PTT_SUBMIT, turn_id=turn_id, payload=EmptyPayload())

    @classmethod
    def heartbeat(cls, turn_id: UUID) -> Self:
        return cls(kind=ControlKind.HEARTBEAT, turn_id=turn_id, payload=EmptyPayload())

    @classmethod
    def capture_start(cls, turn_id: UUID, audio_format: AudioFormat) -> Self:
        return cls(
            kind=ControlKind.CAPTURE_START,
            turn_id=turn_id,
            payload=StartPayload(audio_format=audio_format),
        )

    @classmethod
    def capture_end(cls, turn_id: UUID) -> Self:
        return cls(kind=ControlKind.CAPTURE_END, turn_id=turn_id, payload=EmptyPayload())

    @classmethod
    def playback_start(cls, turn_id: UUID, audio_format: AudioFormat) -> Self:
        return cls(
            kind=ControlKind.PLAYBACK_START,
            turn_id=turn_id,
            payload=StartPayload(audio_format=audio_format),
        )

    @classmethod
    def playback_end(cls, turn_id: UUID) -> Self:
        return cls(kind=ControlKind.PLAYBACK_END, turn_id=turn_id, payload=EmptyPayload())

    @classmethod
    def stop(cls, turn_id: UUID) -> Self:
        return cls(kind=ControlKind.STOP, turn_id=turn_id, payload=EmptyPayload())

    @classmethod
    def cancel(cls, turn_id: UUID) -> Self:
        return cls(kind=ControlKind.CANCEL, turn_id=turn_id, payload=EmptyPayload())

    @classmethod
    def abort(cls, turn_id: UUID, reason_code: PttErrorReason) -> Self:
        return cls(
            kind=ControlKind.ABORT,
            turn_id=turn_id,
            payload=ErrorPayload(reason_code=reason_code),
        )

    @classmethod
    def safety_receipt(cls, turn_id: UUID, receipt: PttSafetyReceipt) -> Self:
        return cls(
            kind=ControlKind.SAFETY_RECEIPT,
            turn_id=turn_id,
            payload=SafetyPayload(receipt=receipt),
        )

    @classmethod
    def safety_ack(cls, turn_id: UUID, *, accepted: bool) -> Self:
        return cls(
            kind=ControlKind.SAFETY_ACK,
            turn_id=turn_id,
            payload=AckPayload(accepted=accepted),
        )

    @classmethod
    def error(cls, turn_id: UUID, reason_code: PttErrorReason) -> Self:
        return cls(
            kind=ControlKind.ERROR,
            turn_id=turn_id,
            payload=ErrorPayload(reason_code=reason_code),
        )


@dataclass(frozen=True, kw_only=True)
class FrameHeader:
    turn_id: UUID
    sequence: int
    kind: FrameKind
    payload_length: int

    def __post_init__(self) -> None:
        _require_turn_id(self.turn_id)
        _require_sequence(self.sequence)
        if type(self.kind) is not FrameKind:
            raise FrameProtocolError(FrameErrorCode.INVALID_PREFIX)
        if type(self.payload_length) is not int:
            raise FrameProtocolError(FrameErrorCode.INVALID_LENGTH)
        if self.kind is FrameKind.CONTROL:
            if not 1 <= self.payload_length <= MAX_CONTROL_BYTES:
                raise FrameProtocolError(FrameErrorCode.INVALID_LENGTH)
        elif not 1 <= self.payload_length <= MAX_PCM_BYTES or self.payload_length % 2:
            raise FrameProtocolError(FrameErrorCode.INVALID_LENGTH)


@dataclass(frozen=True, kw_only=True)
class ControlFrame:
    turn_id: UUID
    sequence: int
    control: PttControl

    def __post_init__(self) -> None:
        _require_turn_id(self.turn_id)
        _require_sequence(self.sequence)
        if type(self.control) is not PttControl:
            raise FrameProtocolError(FrameErrorCode.INVALID_CONTROL)
        if self.control.turn_id != self.turn_id:
            raise FrameProtocolError(FrameErrorCode.TURN_MISMATCH)


@dataclass(frozen=True, kw_only=True, repr=False)
class PcmFrame:
    turn_id: UUID
    sequence: int
    pcm: bytes

    def __post_init__(self) -> None:
        _require_turn_id(self.turn_id)
        _require_sequence(self.sequence)
        if type(self.pcm) is not bytes or not 1 <= len(self.pcm) <= MAX_PCM_BYTES:
            raise FrameProtocolError(FrameErrorCode.INVALID_LENGTH)
        if len(self.pcm) % 2:
            raise FrameProtocolError(FrameErrorCode.INVALID_LENGTH)

    def __repr__(self) -> str:
        return (
            f"PcmFrame(turn_id={self.turn_id!r}, sequence={self.sequence!r}, "
            f"pcm_bytes={len(self.pcm)})"
        )


WireFrame: TypeAlias = (  # noqa: UP040 - package must remain importable on Python 3.11
    ControlFrame | PcmFrame
)


@dataclass(frozen=True, kw_only=True)
class GuardedFrame:
    direction: StreamDirection
    frame: WireFrame
    disposition: GuardDisposition


class _DuplexState(StrEnum):
    WAIT_SESSION_OPEN = "wait_session_open"
    WAIT_SESSION_READY = "wait_session_ready"
    READY = "ready"
    ARMING = "arming"
    ARMING_SUBMIT_PENDING = "arming_submit_pending"
    CAPTURING = "capturing"
    CAPTURE_SUBMIT_PENDING = "capture_submit_pending"
    CAPTURE_CLOSED = "capture_closed"
    PLAYING = "playing"
    PLAYBACK_CLOSED = "playback_closed"
    CLEANUP_REQUIRED = "cleanup_required"
    RECEIPT_RECEIVED = "receipt_received"
    ACKNOWLEDGED = "acknowledged"
    ABORTED = "aborted"


@dataclass
class _MediaStats:
    byte_count: int = 0
    sample_count: int = 0
    wall_started_at: float | None = None
    frame_times: deque[float] = field(default_factory=deque)
    ended: bool = False


def _require_sequence(sequence: int) -> None:
    if type(sequence) is not int or not 0 <= sequence <= UINT32_MAX:
        raise FrameProtocolError(FrameErrorCode.INVALID_SEQUENCE)


def _require_turn_id(turn_id: UUID) -> None:
    if type(turn_id) is not UUID:
        raise FrameProtocolError(FrameErrorCode.TURN_MISMATCH)


def _pack_prefix(
    *,
    kind: FrameKind,
    sequence: int,
    payload_length: int,
    turn_id: UUID,
) -> bytes:
    _require_sequence(sequence)
    _require_turn_id(turn_id)
    return PREFIX.pack(
        MAGIC,
        PROTOCOL_VERSION,
        kind,
        0,
        sequence,
        payload_length,
        turn_id.bytes,
    )


def encode_control_frame(*, sequence: int, control: PttControl) -> bytes:
    if type(control) is not PttControl:
        raise FrameProtocolError(FrameErrorCode.INVALID_CONTROL)
    payload = canonical_bytes(control)
    if not 1 <= len(payload) <= MAX_CONTROL_BYTES:
        raise FrameProtocolError(FrameErrorCode.INVALID_LENGTH)
    return (
        _pack_prefix(
            kind=FrameKind.CONTROL,
            sequence=sequence,
            payload_length=len(payload),
            turn_id=control.turn_id,
        )
        + payload
    )


def encode_pcm_frame(*, turn_id: UUID, sequence: int, pcm: bytes) -> bytes:
    if type(pcm) is not bytes or not 1 <= len(pcm) <= MAX_PCM_BYTES or len(pcm) % 2:
        raise FrameProtocolError(FrameErrorCode.INVALID_LENGTH)
    return (
        _pack_prefix(
            kind=FrameKind.PCM,
            sequence=sequence,
            payload_length=len(pcm),
            turn_id=turn_id,
        )
        + pcm
    )


class FrameDecoder:
    """Incremental fail-closed decoder that buffers at most one bounded frame."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._header: FrameHeader | None = None
        self._closed = False

    def _require_open(self) -> None:
        if self._closed:
            raise FrameProtocolError(FrameErrorCode.CLOSED)

    def _poison(self) -> None:
        self._buffer.clear()
        self._header = None
        self._closed = True

    def _parse_prefix(self) -> FrameHeader:
        unpacked: tuple[bytes, int, int, int, int, int, bytes] | None
        try:
            unpacked = PREFIX.unpack(self._buffer)
        except Exception:
            unpacked = None
        if unpacked is None:
            raise FrameProtocolError(FrameErrorCode.INVALID_PREFIX) from None
        magic, version, raw_kind, flags, sequence, payload_length, raw_turn = unpacked
        if magic != MAGIC or version != PROTOCOL_VERSION or flags != 0:
            raise FrameProtocolError(FrameErrorCode.INVALID_PREFIX)
        kind: FrameKind | None
        try:
            kind = FrameKind(raw_kind)
        except ValueError:
            kind = None
        if kind is None:
            raise FrameProtocolError(FrameErrorCode.INVALID_PREFIX) from None
        if kind is FrameKind.CONTROL:
            if not 1 <= payload_length <= MAX_CONTROL_BYTES:
                raise FrameProtocolError(FrameErrorCode.INVALID_LENGTH)
        elif not 1 <= payload_length <= MAX_PCM_BYTES or payload_length % 2:
            raise FrameProtocolError(FrameErrorCode.INVALID_LENGTH)
        return FrameHeader(
            turn_id=UUID(bytes=raw_turn),
            sequence=sequence,
            kind=kind,
            payload_length=payload_length,
        )

    @staticmethod
    def _complete(header: FrameHeader, payload: bytes) -> WireFrame:
        if header.kind is FrameKind.PCM:
            return PcmFrame(turn_id=header.turn_id, sequence=header.sequence, pcm=payload)
        control: PttControl | None
        try:
            control = parse_contract_json(
                PttControl,
                payload,
                max_bytes=MAX_CONTROL_BYTES,
                require_canonical=True,
            )
        except (ContractParseError, ValueError, TypeError):
            control = None
        if control is None:
            raise FrameProtocolError(FrameErrorCode.INVALID_CONTROL) from None
        if control.turn_id != header.turn_id:
            raise FrameProtocolError(FrameErrorCode.TURN_MISMATCH)
        return ControlFrame(
            turn_id=header.turn_id,
            sequence=header.sequence,
            control=control,
        )

    def feed(self, data: bytes) -> tuple[WireFrame, ...]:
        self._require_open()
        if type(data) is not bytes:
            self._poison()
            raise FrameProtocolError(FrameErrorCode.INVALID_PREFIX)
        if len(data) > MAX_FEED_BYTES:
            self._poison()
            raise FrameProtocolError(FrameErrorCode.FEED_TOO_LARGE)
        if not data:
            return ()

        pending = memoryview(data)
        staged: list[WireFrame] = []
        try:
            while pending:
                if self._header is None:
                    needed = PREFIX_BYTES - len(self._buffer)
                    consumed = min(needed, len(pending))
                    self._buffer.extend(pending[:consumed])
                    pending = pending[consumed:]
                    if len(self._buffer) < PREFIX_BYTES:
                        continue
                    self._header = self._parse_prefix()
                    self._buffer.clear()

                needed = self._header.payload_length - len(self._buffer)
                consumed = min(needed, len(pending))
                self._buffer.extend(pending[:consumed])
                pending = pending[consumed:]
                if len(self._buffer) < self._header.payload_length:
                    continue
                completed = self._complete(self._header, bytes(self._buffer))
                staged.append(completed)
                self._buffer.clear()
                self._header = None
                if len(staged) > MAX_FRAMES_PER_FEED:
                    raise FrameProtocolError(FrameErrorCode.TOO_MANY_FRAMES)
        except FrameProtocolError:
            self._poison()
            raise
        return tuple(staged)

    def finish(self) -> None:
        self._require_open()
        if self._header is not None or self._buffer:
            self._poison()
            raise FrameProtocolError(FrameErrorCode.TRUNCATED)
        self._closed = True

    def abort(self) -> None:
        self._buffer.clear()
        self._header = None
        self._closed = True


_CORE_CONTROL_KINDS = frozenset(
    {
        ControlKind.SESSION_OPEN,
        ControlKind.PTT_START,
        ControlKind.PTT_SUBMIT,
        ControlKind.HEARTBEAT,
        ControlKind.PLAYBACK_START,
        ControlKind.PLAYBACK_END,
        ControlKind.ABORT,
        ControlKind.SAFETY_ACK,
        ControlKind.ERROR,
    }
)
_EDGE_CONTROL_KINDS = frozenset(
    {
        ControlKind.SESSION_READY,
        ControlKind.CAPTURE_START,
        ControlKind.CAPTURE_END,
        ControlKind.STOP,
        ControlKind.CANCEL,
        ControlKind.SAFETY_RECEIPT,
        ControlKind.ERROR,
    }
)
_CLEANUP_KINDS = frozenset(
    {ControlKind.STOP, ControlKind.CANCEL, ControlKind.ABORT, ControlKind.ERROR}
)
_LATE_CONTROL_KINDS = frozenset(
    {
        ControlKind.SESSION_READY,
        ControlKind.PTT_START,
        ControlKind.PTT_SUBMIT,
        ControlKind.HEARTBEAT,
        ControlKind.CAPTURE_START,
        ControlKind.CAPTURE_END,
        ControlKind.PLAYBACK_START,
        ControlKind.PLAYBACK_END,
    }
)
_REASON_OUTCOMES = {
    PttErrorReason.PROTOCOL_REJECTED: PttSessionOutcome.PROTOCOL_REJECTED,
    PttErrorReason.TURN_CANCELLED: PttSessionOutcome.CANCELLED,
    PttErrorReason.CAPTURE_FAILED: PttSessionOutcome.CAPTURE_FAILED,
    PttErrorReason.PROVIDER_FAILED: PttSessionOutcome.PROVIDER_FAILED,
    PttErrorReason.PLAYBACK_FAILED: PttSessionOutcome.PLAYBACK_FAILED,
    PttErrorReason.CLEANUP_INCOMPLETE: PttSessionOutcome.CLEANUP_INCOMPLETE,
    PttErrorReason.PEER_CLOSED: PttSessionOutcome.PEER_CLOSED,
    PttErrorReason.SESSION_TIMEOUT: PttSessionOutcome.SESSION_TIMEOUT,
}


class PttDuplexGuard:
    """Fail-closed supervisor for one bounded PTT duplex turn."""

    def __init__(self, *, turn_id: UUID, input_mode: PttInputMode) -> None:
        _require_turn_id(turn_id)
        if not isinstance(input_mode, PttInputMode):
            raise FrameProtocolError(FrameErrorCode.INVALID_CONTROL)
        self._turn_id = turn_id
        self._input_mode = input_mode
        self._state = _DuplexState.WAIT_SESSION_OPEN
        self._late_state = _DuplexState.WAIT_SESSION_OPEN
        self._next_sequence = {
            StreamDirection.CORE_TO_EDGE: 0,
            StreamDirection.EDGE_TO_CORE: 0,
        }
        self._media = {
            StreamDirection.CORE_TO_EDGE: _MediaStats(),
            StreamDirection.EDGE_TO_CORE: _MediaStats(),
        }
        self._last_now: float | None = None
        self._closed = False
        self._outcome = PttSessionOutcome.COMPLETED
        self._cleanup_latched = False
        self._receipt_complete: bool | None = None
        self._ptt_started = False
        self._ptt_submitted = False

    @property
    def state(self) -> str:
        return self._state.value

    def _fail(self, code: FrameErrorCode) -> NoReturn:
        self._state = _DuplexState.ABORTED
        self._closed = True
        raise FrameProtocolError(code)

    def _require_open(self) -> None:
        if self._closed:
            raise FrameProtocolError(FrameErrorCode.CLOSED)

    def _validate_clock(self, now: float) -> float:
        if type(now) not in (int, float):
            self._fail(FrameErrorCode.INVALID_CLOCK)
        try:
            normalized = float(now)
        except (OverflowError, ValueError):
            self._fail(FrameErrorCode.INVALID_CLOCK)
        if not isfinite(normalized) or (type(now) is int and normalized != now):
            self._fail(FrameErrorCode.INVALID_CLOCK)
        if self._last_now is not None and normalized < self._last_now:
            self._fail(FrameErrorCode.INVALID_CLOCK)
        self._last_now = normalized
        return normalized

    def _validate_frame(
        self,
        direction: StreamDirection,
        frame: WireFrame,
    ) -> None:
        if type(direction) is not StreamDirection:
            self._fail(FrameErrorCode.INVALID_DIRECTION)
        if type(frame) not in (ControlFrame, PcmFrame):
            self._fail(FrameErrorCode.INVALID_PREFIX)
        if frame.turn_id != self._turn_id:
            self._fail(FrameErrorCode.TURN_MISMATCH)
        expected = self._next_sequence[direction]
        if frame.sequence != expected or expected > UINT32_MAX:
            self._fail(FrameErrorCode.INVALID_SEQUENCE)
        if isinstance(frame, ControlFrame):
            allowed = (
                _CORE_CONTROL_KINDS
                if direction is StreamDirection.CORE_TO_EDGE
                else _EDGE_CONTROL_KINDS
            )
            if frame.control.kind not in allowed:
                self._fail(FrameErrorCode.INVALID_DIRECTION)

    def _advance_sequence(self, direction: StreamDirection) -> None:
        self._next_sequence[direction] += 1

    def _start_media(self, direction: StreamDirection, now: float) -> None:
        stats = self._media[direction]
        if stats.wall_started_at is not None or stats.ended:
            self._fail(FrameErrorCode.INVALID_ORDER)
        stats.wall_started_at = now

    def _require_wall(self, direction: StreamDirection, now: float) -> _MediaStats:
        stats = self._media[direction]
        if stats.wall_started_at is None or stats.ended:
            self._fail(FrameErrorCode.INVALID_ORDER)
        if now - stats.wall_started_at > MAX_MEDIA_WALL_SECONDS:
            self._fail(FrameErrorCode.DURATION_LIMIT)
        return stats

    def _admit_pcm(self, direction: StreamDirection, frame: PcmFrame, now: float) -> None:
        stats = self._require_wall(direction, now)
        pcm_bytes = len(frame.pcm)
        if pcm_bytes > MAX_TRANSPORT_PCM_FRAME_BYTES:
            self._fail(FrameErrorCode.PCM_LIMIT)
        if stats.byte_count + pcm_bytes > MAX_DIRECTION_BYTES:
            self._fail(FrameErrorCode.PCM_LIMIT)
        samples = pcm_bytes // 2
        if stats.sample_count + samples > MAX_MEDIA_SAMPLES:
            self._fail(FrameErrorCode.DURATION_LIMIT)
        cutoff = now - 1.0
        while stats.frame_times and stats.frame_times[0] < cutoff:
            stats.frame_times.popleft()
        if len(stats.frame_times) >= MAX_PCM_FRAMES_PER_SECOND:
            self._fail(FrameErrorCode.RATE_LIMIT)
        stats.byte_count += pcm_bytes
        stats.sample_count += samples
        stats.frame_times.append(now)

    def _end_media(self, direction: StreamDirection, now: float) -> None:
        stats = self._require_wall(direction, now)
        if stats.sample_count == 0:
            self._fail(FrameErrorCode.INVALID_ORDER)
        stats.ended = True

    @staticmethod
    def _require_transport_start(control: PttControl) -> None:
        if not isinstance(control.payload, StartPayload):
            raise FrameProtocolError(FrameErrorCode.INVALID_CONTROL)
        if control.payload.audio_format != TRANSPORT_AUDIO_FORMAT:
            raise FrameProtocolError(FrameErrorCode.INVALID_CONTROL)

    def _latch_cleanup(self, control: PttControl) -> None:
        if self._state not in {
            _DuplexState.CLEANUP_REQUIRED,
            _DuplexState.RECEIPT_RECEIVED,
        }:
            self._late_state = self._state
        if not self._cleanup_latched:
            if control.kind in {ControlKind.STOP, ControlKind.CANCEL}:
                self._outcome = PttSessionOutcome.CANCELLED
            elif isinstance(control.payload, ErrorPayload):
                self._outcome = _REASON_OUTCOMES[control.payload.reason_code]
            self._cleanup_latched = True
        if self._state is not _DuplexState.RECEIPT_RECEIVED:
            self._state = _DuplexState.CLEANUP_REQUIRED

    def _accept_late_progress(
        self,
        direction: StreamDirection,
        frame: WireFrame,
        now: float,
    ) -> GuardDisposition:
        if isinstance(frame, PcmFrame):
            expected_state = (
                _DuplexState.CAPTURING
                if direction is StreamDirection.EDGE_TO_CORE
                else _DuplexState.PLAYING
            )
            if self._late_state not in {expected_state, _DuplexState.CAPTURE_SUBMIT_PENDING}:
                self._fail(FrameErrorCode.INVALID_ORDER)
            if (
                direction is StreamDirection.CORE_TO_EDGE
                and self._late_state is _DuplexState.CAPTURE_SUBMIT_PENDING
            ):
                self._fail(FrameErrorCode.INVALID_ORDER)
            self._admit_pcm(direction, frame, now)
            return GuardDisposition.LATE_DISCARDED

        if frame.control.kind not in _LATE_CONTROL_KINDS:
            self._fail(FrameErrorCode.INVALID_ORDER)

        cleanup_state = self._state
        self._state = self._late_state
        self._accept_normal_control(direction, frame.control, now)
        if self._state in {
            _DuplexState.CLEANUP_REQUIRED,
            _DuplexState.RECEIPT_RECEIVED,
            _DuplexState.ACKNOWLEDGED,
            _DuplexState.ABORTED,
        }:
            self._fail(FrameErrorCode.INVALID_ORDER)
        self._late_state = self._state
        self._state = cleanup_state
        return GuardDisposition.LATE_DISCARDED

    def _accept_cleanup_phase(
        self,
        direction: StreamDirection,
        frame: WireFrame,
        now: float,
    ) -> GuardDisposition:
        if isinstance(frame, PcmFrame):
            return self._accept_late_progress(direction, frame, now)

        control = frame.control
        if control.kind in _CLEANUP_KINDS:
            self._latch_cleanup(control)
            return GuardDisposition.ACCEPTED
        if (
            control.kind is ControlKind.SAFETY_RECEIPT
            and self._state is _DuplexState.CLEANUP_REQUIRED
        ):
            if not isinstance(control.payload, SafetyPayload):
                self._fail(FrameErrorCode.INVALID_CONTROL)
            self._receipt_complete = control.payload.receipt.is_complete()
            self._state = _DuplexState.RECEIPT_RECEIVED
            return GuardDisposition.ACCEPTED
        if control.kind is ControlKind.SAFETY_ACK and self._state is _DuplexState.RECEIPT_RECEIVED:
            if not isinstance(control.payload, AckPayload) or self._receipt_complete is None:
                self._fail(FrameErrorCode.INVALID_CONTROL)
            if control.payload.accepted is not self._receipt_complete:
                self._fail(FrameErrorCode.INVALID_ORDER)
            if not control.payload.accepted:
                self._outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
            self._state = _DuplexState.ACKNOWLEDGED
            return GuardDisposition.ACCEPTED
        return self._accept_late_progress(direction, frame, now)

    def _accept_normal_control(
        self,
        direction: StreamDirection,
        control: PttControl,
        now: float,
    ) -> GuardDisposition:
        kind = control.kind
        if kind in _CLEANUP_KINDS:
            self._latch_cleanup(control)
            return GuardDisposition.ACCEPTED
        if kind is ControlKind.HEARTBEAT:
            if self._state not in {
                _DuplexState.WAIT_SESSION_READY,
                _DuplexState.READY,
                _DuplexState.ARMING,
                _DuplexState.ARMING_SUBMIT_PENDING,
                _DuplexState.CAPTURING,
                _DuplexState.CAPTURE_SUBMIT_PENDING,
                _DuplexState.CAPTURE_CLOSED,
                _DuplexState.PLAYING,
                _DuplexState.PLAYBACK_CLOSED,
            }:
                self._fail(FrameErrorCode.INVALID_ORDER)
            return GuardDisposition.ACCEPTED

        if self._state is _DuplexState.WAIT_SESSION_OPEN:
            if (
                kind is not ControlKind.SESSION_OPEN
                or direction is not StreamDirection.CORE_TO_EDGE
            ):
                self._fail(FrameErrorCode.INVALID_ORDER)
            if not isinstance(control.payload, SessionPayload):
                self._fail(FrameErrorCode.INVALID_CONTROL)
            if control.payload.input_mode is not self._input_mode:
                self._fail(FrameErrorCode.INVALID_ORDER)
            self._state = _DuplexState.WAIT_SESSION_READY
            return GuardDisposition.ACCEPTED

        if self._state is _DuplexState.WAIT_SESSION_READY:
            if (
                kind is not ControlKind.SESSION_READY
                or direction is not StreamDirection.EDGE_TO_CORE
            ):
                self._fail(FrameErrorCode.INVALID_ORDER)
            if not isinstance(control.payload, SessionPayload):
                self._fail(FrameErrorCode.INVALID_CONTROL)
            if control.payload.input_mode is not self._input_mode:
                self._fail(FrameErrorCode.INVALID_ORDER)
            self._state = _DuplexState.READY
            return GuardDisposition.ACCEPTED

        if self._state is _DuplexState.READY:
            if (
                self._input_mode is PttInputMode.CORE_TERMINAL_TOGGLE
                and kind is ControlKind.PTT_START
            ):
                self._ptt_started = True
                self._state = _DuplexState.ARMING
                return GuardDisposition.ACCEPTED
            if self._input_mode is PttInputMode.REACHY_LOCAL and kind is ControlKind.CAPTURE_START:
                try:
                    self._require_transport_start(control)
                except FrameProtocolError as error:
                    self._fail(error.code)
                self._start_media(StreamDirection.EDGE_TO_CORE, now)
                self._state = _DuplexState.CAPTURING
                return GuardDisposition.ACCEPTED
            self._fail(FrameErrorCode.INVALID_ORDER)

        if self._state is _DuplexState.ARMING:
            if kind is ControlKind.PTT_SUBMIT:
                self._ptt_submitted = True
                self._state = _DuplexState.ARMING_SUBMIT_PENDING
                return GuardDisposition.ACCEPTED
            if kind is ControlKind.CAPTURE_START:
                try:
                    self._require_transport_start(control)
                except FrameProtocolError as error:
                    self._fail(error.code)
                self._start_media(StreamDirection.EDGE_TO_CORE, now)
                self._state = _DuplexState.CAPTURING
                return GuardDisposition.ACCEPTED
            self._fail(FrameErrorCode.INVALID_ORDER)

        if self._state is _DuplexState.ARMING_SUBMIT_PENDING:
            if kind is not ControlKind.CAPTURE_START:
                self._fail(FrameErrorCode.INVALID_ORDER)
            try:
                self._require_transport_start(control)
            except FrameProtocolError as error:
                self._fail(error.code)
            self._start_media(StreamDirection.EDGE_TO_CORE, now)
            self._state = _DuplexState.CAPTURE_SUBMIT_PENDING
            return GuardDisposition.ACCEPTED

        if self._state is _DuplexState.CAPTURING:
            if (
                kind is ControlKind.PTT_SUBMIT
                and self._input_mode is PttInputMode.CORE_TERMINAL_TOGGLE
            ):
                self._ptt_submitted = True
                self._state = _DuplexState.CAPTURE_SUBMIT_PENDING
                return GuardDisposition.ACCEPTED
            if kind is ControlKind.CAPTURE_END and self._input_mode is PttInputMode.REACHY_LOCAL:
                self._end_media(StreamDirection.EDGE_TO_CORE, now)
                self._state = _DuplexState.CAPTURE_CLOSED
                return GuardDisposition.ACCEPTED
            self._fail(FrameErrorCode.INVALID_ORDER)

        if self._state is _DuplexState.CAPTURE_SUBMIT_PENDING:
            if kind is not ControlKind.CAPTURE_END:
                self._fail(FrameErrorCode.INVALID_ORDER)
            self._end_media(StreamDirection.EDGE_TO_CORE, now)
            self._state = _DuplexState.CAPTURE_CLOSED
            return GuardDisposition.ACCEPTED

        if self._state is _DuplexState.CAPTURE_CLOSED:
            if kind is not ControlKind.PLAYBACK_START:
                self._fail(FrameErrorCode.INVALID_ORDER)
            try:
                self._require_transport_start(control)
            except FrameProtocolError as error:
                self._fail(error.code)
            self._start_media(StreamDirection.CORE_TO_EDGE, now)
            self._state = _DuplexState.PLAYING
            return GuardDisposition.ACCEPTED

        if self._state is _DuplexState.PLAYING:
            if kind is not ControlKind.PLAYBACK_END:
                self._fail(FrameErrorCode.INVALID_ORDER)
            self._end_media(StreamDirection.CORE_TO_EDGE, now)
            self._state = _DuplexState.PLAYBACK_CLOSED
            return GuardDisposition.ACCEPTED

        if self._state is _DuplexState.PLAYBACK_CLOSED:
            if kind is not ControlKind.SAFETY_RECEIPT:
                self._fail(FrameErrorCode.INVALID_ORDER)
            if not isinstance(control.payload, SafetyPayload):
                self._fail(FrameErrorCode.INVALID_CONTROL)
            self._receipt_complete = control.payload.receipt.is_complete()
            self._state = _DuplexState.RECEIPT_RECEIVED
            return GuardDisposition.ACCEPTED

        self._fail(FrameErrorCode.INVALID_ORDER)

    def accept(
        self,
        direction: StreamDirection,
        frame: WireFrame,
        *,
        now: float,
    ) -> GuardedFrame:
        self._require_open()
        normalized_now = self._validate_clock(now)
        self._validate_frame(direction, frame)
        if self._state is _DuplexState.ACKNOWLEDGED:
            self._fail(FrameErrorCode.INVALID_ORDER)

        if self._state in {_DuplexState.CLEANUP_REQUIRED, _DuplexState.RECEIPT_RECEIVED}:
            disposition = self._accept_cleanup_phase(direction, frame, normalized_now)
        elif isinstance(frame, PcmFrame):
            expected_state = (
                _DuplexState.CAPTURING
                if direction is StreamDirection.EDGE_TO_CORE
                else _DuplexState.PLAYING
            )
            if self._state not in {expected_state, _DuplexState.CAPTURE_SUBMIT_PENDING}:
                self._fail(FrameErrorCode.INVALID_ORDER)
            if (
                direction is StreamDirection.CORE_TO_EDGE
                and self._state is _DuplexState.CAPTURE_SUBMIT_PENDING
            ):
                self._fail(FrameErrorCode.INVALID_ORDER)
            self._admit_pcm(direction, frame, normalized_now)
            disposition = GuardDisposition.ACCEPTED
        else:
            disposition = self._accept_normal_control(direction, frame.control, normalized_now)

        if self._state not in {
            _DuplexState.CLEANUP_REQUIRED,
            _DuplexState.RECEIPT_RECEIVED,
            _DuplexState.ACKNOWLEDGED,
            _DuplexState.ABORTED,
        }:
            self._late_state = self._state

        self._advance_sequence(direction)
        return GuardedFrame(direction=direction, frame=frame, disposition=disposition)

    def finish(self) -> PttSessionOutcome:
        self._require_open()
        if self._state is not _DuplexState.ACKNOWLEDGED:
            self._fail(FrameErrorCode.INVALID_ORDER)
        self._closed = True
        return self._outcome

    def abort(self) -> None:
        self._state = _DuplexState.ABORTED
        self._closed = True
