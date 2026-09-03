from __future__ import annotations

import asyncio
import audioop
import math
import struct
from collections.abc import AsyncGenerator, AsyncIterator, Sequence
from typing import Final, Protocol, TypeAlias, cast

from tuntun_contracts.speech import AudioFormat

MAX_AUDIO_CHUNK: Final = 65_536
MAX_SOURCE_CHUNK_BYTES: Final = 262_144
MAX_SOURCE_TURN_BYTES: Final = 8_388_608
MAX_TURN_BYTES: Final = 8_388_608
TARGET_SAMPLE_FORMAT: Final = "s16le"
TARGET_SAMPLE_RATE_HZ: Final = 16_000
TARGET_CHANNELS: Final = 1
TARGET_INTERLEAVED: Final = True
TARGET_CHANNEL_LAYOUT: Final = "mono"

_FLOAT32 = struct.Struct("<f")
_FLOAT32_STEREO = struct.Struct("<ff")
_S16 = struct.Struct("<h")
_S16_STEREO = struct.Struct("<hh")
_RateCvState: TypeAlias = tuple[  # noqa: UP040 -- keep Python 3.11 syntax compatibility.
    int,
    tuple[tuple[int, int], ...],
]
_CONTROL_FLOW_ERRORS: tuple[type[BaseException], ...] = (
    asyncio.CancelledError,
    KeyboardInterrupt,
    SystemExit,
    GeneratorExit,
)


class _Float32ChannelMatrix(Protocol):
    ndim: object
    shape: object
    dtype: object

    def tolist(self) -> object: ...


class AudioConversionError(ValueError):
    """Content-free rejection of malformed or unsupported audio."""

    def __init__(self) -> None:
        super().__init__("audio-conversion-rejected")


def _wipe(buffer: bytearray) -> None:
    buffer[:] = b"\x00" * len(buffer)
    buffer.clear()


async def _close(stream: object) -> None:
    close = getattr(stream, "aclose", None)
    if close is not None:
        await close()


def _cancellation_pending() -> bool:
    task = asyncio.current_task()
    return task is not None and task.cancelling() > 0


def _raise_if_cancelling() -> None:
    if _cancellation_pending():
        raise asyncio.CancelledError


def _strict_audio_format(value: object) -> AudioFormat | None:
    if type(value) is not AudioFormat:
        return None
    try:
        dumped = value.model_dump(mode="python", warnings="error")
        validated = AudioFormat.model_validate(dumped, strict=True)
    except _CONTROL_FLOW_ERRORS:
        raise
    except BaseException:
        return None
    if dumped != validated.model_dump(mode="python"):
        return None
    return validated


def _valid_source_format(audio_format: AudioFormat) -> bool:
    if (
        audio_format.sample_format not in {"float32_le", "s16le"}
        or audio_format.interleaved is not True
    ):
        return False
    if audio_format.channels == 1:
        return audio_format.channel_layout == "mono"
    if audio_format.channels == 2:
        return audio_format.channel_layout == "stereo"
    if audio_format.channels in {3, 4}:
        return audio_format.channel_layout == "reachy_native"
    return False


def _valid_target_format(audio_format: AudioFormat) -> bool:
    return (
        audio_format.sample_format == TARGET_SAMPLE_FORMAT
        and audio_format.sample_rate_hz == TARGET_SAMPLE_RATE_HZ
        and audio_format.channels == TARGET_CHANNELS
        and audio_format.interleaved is TARGET_INTERLEAVED
        and audio_format.channel_layout == TARGET_CHANNEL_LAYOUT
    )


def _source_frame_bytes(source: AudioFormat) -> int:
    width = 4 if source.sample_format == "float32_le" else 2
    return width * source.channels


def _scale_unit_float_to_s16(value: float) -> int:
    if type(value) is not float or not math.isfinite(value):
        raise AudioConversionError
    clipped = min(1.0, max(-1.0, value))
    if clipped >= 0:
        return int(clipped * 32767.0)
    return int(clipped * 32768.0)


def _s16_to_unit(value: int) -> float:
    if value >= 0:
        return value / 32767.0
    return value / 32768.0


def _is_float32_dtype(value: object) -> bool:
    name = getattr(value, "name", None)
    return name == "float32" or str(value) == "float32"


def _coerce_float32_channel_matrix(frame: _Float32ChannelMatrix) -> Sequence[Sequence[object]]:
    shape = frame.shape
    if (
        type(frame.ndim) is not int
        or frame.ndim != 2
        or not isinstance(shape, (list, tuple))
        or len(shape) != 2
        or not _is_float32_dtype(frame.dtype)
    ):
        raise AudioConversionError

    rows, channels = shape
    if type(rows) is not int or type(channels) is not int or rows < 1 or not 1 <= channels <= 4:
        raise AudioConversionError

    matrix = frame.tolist()
    if type(matrix) not in {list, tuple}:
        raise AudioConversionError
    return cast(Sequence[Sequence[object]], matrix)


def _coerce_audio_rows(frame: object) -> Sequence[Sequence[object]]:
    if type(frame) in {list, tuple}:
        if not frame:
            raise AudioConversionError
        return cast(Sequence[Sequence[object]], frame)

    if (
        hasattr(frame, "ndim")
        and hasattr(frame, "shape")
        and hasattr(frame, "dtype")
        and callable(getattr(frame, "tolist", None))
    ):
        return _coerce_float32_channel_matrix(cast(_Float32ChannelMatrix, frame))

    raise AudioConversionError


def to_s16le_mono(frame: object) -> bytes:
    channels: int | None = None
    output = bytearray()
    rejected = False
    converted: bytes | None = None
    try:
        rows = _coerce_audio_rows(frame)
        for row in rows:
            if type(row) not in {list, tuple} or not 1 <= len(row) <= 4:
                raise AudioConversionError
            if channels is None:
                channels = len(row)
            elif len(row) != channels:
                raise AudioConversionError
            total = 0.0
            for sample in row:
                if type(sample) is not float or not math.isfinite(sample):
                    raise AudioConversionError
                total += sample
            output.extend(_S16.pack(_scale_unit_float_to_s16(total / len(row))))
        converted = bytes(output)
    except _CONTROL_FLOW_ERRORS:
        raise
    except BaseException:
        rejected = True
    finally:
        _wipe(output)
    if rejected or converted is None:
        raise AudioConversionError
    return converted


def _float32_interleaved_to_s16le_mono(chunk: bytes, source: AudioFormat) -> bytes:
    output = bytearray()
    rejected = False
    converted: bytes | None = None
    try:
        if source.channels == 1:
            for offset in range(0, len(chunk), _FLOAT32.size):
                sample = _FLOAT32.unpack_from(chunk, offset)[0]
                output.extend(_S16.pack(_scale_unit_float_to_s16(sample)))
        else:
            frame_struct = struct.Struct("<" + ("f" * source.channels))
            for offset in range(0, len(chunk), frame_struct.size):
                samples = frame_struct.unpack_from(chunk, offset)
                output.extend(
                    _S16.pack(_scale_unit_float_to_s16(sum(samples) / source.channels)),
                )
        converted = bytes(output)
    except _CONTROL_FLOW_ERRORS:
        raise
    except BaseException:
        rejected = True
    finally:
        _wipe(output)
    if rejected or converted is None:
        raise AudioConversionError
    return converted


def _s16le_interleaved_to_s16le_mono(chunk: bytes, source: AudioFormat) -> bytes:
    if source.channels == 1:
        return chunk

    output = bytearray()
    rejected = False
    converted: bytes | None = None
    try:
        frame_struct = struct.Struct("<" + ("h" * source.channels))
        for offset in range(0, len(chunk), frame_struct.size):
            mono = sum(_s16_to_unit(sample) for sample in frame_struct.unpack_from(chunk, offset))
            mono /= source.channels
            output.extend(_S16.pack(_scale_unit_float_to_s16(mono)))
        converted = bytes(output)
    except _CONTROL_FLOW_ERRORS:
        raise
    except BaseException:
        rejected = True
    finally:
        _wipe(output)
    if rejected or converted is None:
        raise AudioConversionError
    return converted


def _decode_complete_frames(chunk: bytes, source: AudioFormat) -> bytes:
    if source.sample_format == "float32_le":
        return _float32_interleaved_to_s16le_mono(chunk, source)
    return _s16le_interleaved_to_s16le_mono(chunk, source)


def _append_bounded(
    output_carry: bytearray,
    chunk: bytes,
    converted_total: int,
) -> tuple[int, tuple[bytes, ...]]:
    if not chunk:
        return converted_total, ()
    if len(chunk) % _S16.size != 0 or len(chunk) > MAX_TURN_BYTES - converted_total:
        raise AudioConversionError

    ready: list[bytes] = []
    converted_total += len(chunk)
    offset = 0
    while offset < len(chunk):
        take = min(MAX_AUDIO_CHUNK - len(output_carry), len(chunk) - offset)
        output_carry.extend(chunk[offset : offset + take])
        offset += take
        if len(output_carry) == MAX_AUDIO_CHUNK:
            ready.append(bytes(output_carry))
            _wipe(output_carry)
    return converted_total, tuple(ready)


class StreamingAudioConverter:
    """Bounded converter to Reachy's exact 16 kHz mono s16le stream contract."""

    def convert(
        self,
        audio: AsyncIterator[bytes],
        source: AudioFormat,
        target: AudioFormat,
    ) -> AsyncGenerator[bytes, None]:
        return self._convert(audio, source, target)

    async def _convert(
        self,
        audio: AsyncIterator[bytes],
        source: AudioFormat,
        target: AudioFormat,
    ) -> AsyncGenerator[bytes, None]:
        output_carry = bytearray()
        residual = bytearray()
        close_attempted = False
        try:
            read_error: AudioConversionError | None = None
            canonical_source = _strict_audio_format(source)
            canonical_target = _strict_audio_format(target)
            if (
                not hasattr(audio, "__aiter__")
                or canonical_source is None
                or canonical_target is None
                or not _valid_source_format(canonical_source)
                or not _valid_target_format(canonical_target)
            ):
                read_error = AudioConversionError()
            else:
                source_bytes = 0
                converted_total = 0
                rate_state: _RateCvState | None = None
                frame_bytes = _source_frame_bytes(canonical_source)
                try:
                    async for chunk in audio:
                        _raise_if_cancelling()
                        if type(chunk) is not bytes or not chunk:
                            raise AudioConversionError
                        if len(chunk) > MAX_SOURCE_CHUNK_BYTES:
                            raise AudioConversionError
                        if len(chunk) > MAX_SOURCE_TURN_BYTES - source_bytes:
                            raise AudioConversionError
                        source_bytes += len(chunk)

                        combined = bytes(residual) + chunk
                        complete_len = len(combined) - (len(combined) % frame_bytes)
                        if complete_len:
                            mono_pcm = _decode_complete_frames(
                                combined[:complete_len],
                                canonical_source,
                            )
                            if canonical_source.sample_rate_hz != canonical_target.sample_rate_hz:
                                mono_pcm, rate_state = audioop.ratecv(
                                    mono_pcm,
                                    _S16.size,
                                    TARGET_CHANNELS,
                                    canonical_source.sample_rate_hz,
                                    canonical_target.sample_rate_hz,
                                    rate_state,
                                )
                            converted_total, ready_chunks = _append_bounded(
                                output_carry,
                                mono_pcm,
                                converted_total,
                            )
                            for ready_chunk in ready_chunks:
                                _raise_if_cancelling()
                                yield ready_chunk
                        residual[:] = combined[complete_len:]
                except asyncio.CancelledError:
                    raise
                except AudioConversionError:
                    read_error = AudioConversionError()
                except _CONTROL_FLOW_ERRORS:
                    raise
                except BaseException:
                    read_error = AudioConversionError()

                if read_error is None and (source_bytes == 0 or residual):
                    read_error = AudioConversionError()

            _raise_if_cancelling()
            close_attempted = True
            try:
                await _close(audio)
            except asyncio.CancelledError:
                raise
            except _CONTROL_FLOW_ERRORS:
                raise
            except BaseException:
                read_error = AudioConversionError()
            _raise_if_cancelling()
            if read_error is not None:
                raise read_error from None

            if output_carry:
                yield bytes(output_carry)
        except asyncio.CancelledError:
            raise
        except _CONTROL_FLOW_ERRORS:
            raise
        except AudioConversionError:
            if _cancellation_pending():
                raise asyncio.CancelledError from None
            raise
        except BaseException:
            if _cancellation_pending():
                raise asyncio.CancelledError from None
            read_error = AudioConversionError()
        finally:
            try:
                if not close_attempted:
                    try:
                        await _close(audio)
                    except asyncio.CancelledError:
                        raise
                    except _CONTROL_FLOW_ERRORS:
                        raise
                    except BaseException:
                        if _cancellation_pending():
                            raise asyncio.CancelledError from None
                        read_error = AudioConversionError()
            finally:
                _wipe(residual)
                _wipe(output_carry)
        if read_error is not None:
            raise read_error


__all__ = [
    "MAX_AUDIO_CHUNK",
    "MAX_SOURCE_CHUNK_BYTES",
    "MAX_SOURCE_TURN_BYTES",
    "MAX_TURN_BYTES",
    "TARGET_CHANNELS",
    "TARGET_CHANNEL_LAYOUT",
    "TARGET_INTERLEAVED",
    "TARGET_SAMPLE_FORMAT",
    "TARGET_SAMPLE_RATE_HZ",
    "AudioConversionError",
    "StreamingAudioConverter",
    "to_s16le_mono",
]
