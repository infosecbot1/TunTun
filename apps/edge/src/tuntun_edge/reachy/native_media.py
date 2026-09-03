"""Conversion-only media bridge below the Reachy SDK backend."""

from __future__ import annotations

import asyncio
import importlib
import math
import struct
from collections.abc import Awaitable, Callable
from typing import Any, Final, Protocol, cast

from tuntun_contracts.poc.framing import MAX_TRANSPORT_PCM_FRAME_BYTES, TRANSPORT_AUDIO_FORMAT
from tuntun_contracts.speech import AudioFormat

from tuntun_edge.audio.converter import AudioConversionError, to_s16le_mono

REACHY_SDK_DECLARED_NATIVE_AUDIO_FORMAT: Final = AudioFormat(
    sample_format="float32_le",
    sample_rate_hz=16_000,
    channels=2,
    interleaved=True,
    channel_layout="stereo",
)

_S16 = struct.Struct("<h")
_NATIVE_STEREO_FRAME_BYTES: Final = 8
_CONTROL_FLOW_ERRORS: tuple[type[BaseException], ...] = (
    asyncio.CancelledError,
    KeyboardInterrupt,
    SystemExit,
    GeneratorExit,
)

PlaybackFrameFactory = Callable[[tuple[tuple[float, float], ...]], object]


class ReachySdkNativeMediaBackend(Protocol):
    async def open_capture(
        self,
        *,
        native_format: AudioFormat,
        max_source_frame_bytes: int,
    ) -> None: ...

    async def read_capture(self) -> object | None: ...

    async def close_capture(self) -> bool: ...

    async def open_playback(self, *, native_format: AudioFormat) -> None: ...

    async def write_playback(self, frame: object) -> None: ...

    async def close_playback(self) -> bool: ...

    async def stop_recording(self) -> bool: ...

    async def stop_playback(self) -> bool: ...

    async def stop_motion(self) -> bool: ...

    async def disable_audio_reactive(self) -> bool: ...


class _Float32ChannelMatrix(Protocol):
    ndim: object
    shape: object
    dtype: object
    nbytes: object

    def tolist(self) -> object: ...


def _default_numpy_float32_stereo_frame(
    rows: tuple[tuple[float, float], ...],
) -> object:
    try:
        numpy: Any = importlib.import_module("numpy")
        return numpy.array(rows, dtype=numpy.float32)
    except _CONTROL_FLOW_ERRORS:
        raise
    except BaseException:
        raise AudioConversionError from None


def _is_float32_dtype(value: object) -> bool:
    byteorder = getattr(value, "byteorder", None)
    itemsize = getattr(value, "itemsize", None)
    if byteorder in {">", "!"}:
        return False
    if itemsize is not None and itemsize != 4:
        return False
    if byteorder in {"<", "=", "|"}:
        return getattr(value, "name", None) == "float32" or str(value) in {"float32", "<f4"}
    return type(value) is str and value == "float32"


def _require_transport_audio_format(value: object) -> None:
    if value != TRANSPORT_AUDIO_FORMAT:
        raise AudioConversionError


def _require_transport_frame_bytes(value: object) -> int:
    if (
        type(value) is not int
        or value <= 0
        or value > MAX_TRANSPORT_PCM_FRAME_BYTES
        or value % _S16.size != 0
    ):
        raise AudioConversionError
    return value


def _unit_float_from_s16(sample: int) -> float:
    if sample >= 0:
        return sample / 32767.0
    return sample / 32768.0


def _coerce_float32_stereo_rows(
    frame: object,
    *,
    max_rows: int,
) -> tuple[tuple[float, float], ...]:
    if (
        not hasattr(frame, "ndim")
        or not hasattr(frame, "shape")
        or not hasattr(frame, "dtype")
        or not callable(getattr(frame, "tolist", None))
    ):
        raise AudioConversionError
    matrix = cast(_Float32ChannelMatrix, frame)
    ndim = matrix.ndim
    shape = matrix.shape
    if (
        type(ndim) is not int
        or ndim != 2
        or not isinstance(shape, (list, tuple))
        or len(shape) != 2
        or not _is_float32_dtype(matrix.dtype)
    ):
        raise AudioConversionError
    row_count, channels = shape
    if (
        type(row_count) is not int
        or type(channels) is not int
        or not 1 <= row_count <= max_rows
        or channels != 2
    ):
        raise AudioConversionError
    nbytes = matrix.nbytes
    expected_nbytes = row_count * channels * 4
    if type(nbytes) is not int or nbytes != expected_nbytes:
        raise AudioConversionError

    raw_rows = matrix.tolist()
    if type(raw_rows) not in {list, tuple}:
        raise AudioConversionError
    row_values = cast(list[object] | tuple[object, ...], raw_rows)
    if len(row_values) != row_count:
        raise AudioConversionError
    rows: list[tuple[float, float]] = []
    for raw_row in row_values:
        if type(raw_row) not in {list, tuple}:
            raise AudioConversionError
        row = cast(list[object] | tuple[object, ...], raw_row)
        if len(row) != 2:
            raise AudioConversionError
        left, right = row
        if type(left) is not float or type(right) is not float:
            raise AudioConversionError
        if not math.isfinite(left) or not math.isfinite(right):
            raise AudioConversionError
        rows.append((left, right))
    return tuple(rows)


def _transport_pcm_to_float32_stereo(
    pcm: bytes,
) -> tuple[tuple[float, float], ...]:
    if (
        type(pcm) is not bytes
        or not pcm
        or len(pcm) > MAX_TRANSPORT_PCM_FRAME_BYTES
        or len(pcm) % _S16.size != 0
    ):
        raise AudioConversionError
    rows: list[tuple[float, float]] = []
    for offset in range(0, len(pcm), _S16.size):
        sample = _S16.unpack_from(pcm, offset)[0]
        value = _unit_float_from_s16(sample)
        rows.append((value, value))
    return tuple(rows)


async def _sanitize_native_bool_operation(operation: Callable[[], Awaitable[bool]]) -> bool:
    try:
        result = await operation()
    except _CONTROL_FLOW_ERRORS:
        raise
    except BaseException:
        raise AudioConversionError from None
    if type(result) is not bool:
        raise AudioConversionError
    return result


class ReachySdkNativeMediaAdapter:
    """Adapt an external Reachy SDK-native backend to the fixed Tuntun PTT transport."""

    def __init__(
        self,
        native: ReachySdkNativeMediaBackend,
        *,
        playback_frame_factory: PlaybackFrameFactory | None = None,
    ) -> None:
        self._native = native
        self._playback_frame_factory = playback_frame_factory or _default_numpy_float32_stereo_frame
        self._max_capture_rows = 0

    async def open_capture(
        self,
        *,
        output_format: AudioFormat,
        max_frame_bytes: int,
    ) -> None:
        try:
            _require_transport_audio_format(output_format)
            bounded_transport_bytes = _require_transport_frame_bytes(max_frame_bytes)
            self._max_capture_rows = bounded_transport_bytes // _S16.size
            await self._native.open_capture(
                native_format=REACHY_SDK_DECLARED_NATIVE_AUDIO_FORMAT,
                max_source_frame_bytes=self._max_capture_rows * _NATIVE_STEREO_FRAME_BYTES,
            )
        except AudioConversionError:
            raise
        except _CONTROL_FLOW_ERRORS:
            raise
        except BaseException:
            raise AudioConversionError from None

    async def read_capture(self) -> bytes | None:
        try:
            frame = await self._native.read_capture()
            if frame is None:
                return None
            rows = _coerce_float32_stereo_rows(frame, max_rows=self._max_capture_rows)
            return to_s16le_mono(rows)
        except AudioConversionError:
            raise
        except _CONTROL_FLOW_ERRORS:
            raise
        except BaseException:
            raise AudioConversionError from None

    async def close_capture(self) -> bool:
        return await _sanitize_native_bool_operation(self._native.close_capture)

    async def open_playback(self, *, input_format: AudioFormat) -> None:
        try:
            _require_transport_audio_format(input_format)
            await self._native.open_playback(native_format=REACHY_SDK_DECLARED_NATIVE_AUDIO_FORMAT)
        except AudioConversionError:
            raise
        except _CONTROL_FLOW_ERRORS:
            raise
        except BaseException:
            raise AudioConversionError from None

    async def write_playback(self, pcm: bytes) -> None:
        try:
            native_rows = _transport_pcm_to_float32_stereo(pcm)
            native_frame = self._playback_frame_factory(native_rows)
        except AudioConversionError:
            raise
        except _CONTROL_FLOW_ERRORS:
            raise
        except BaseException:
            raise AudioConversionError from None
        try:
            await self._native.write_playback(native_frame)
        except _CONTROL_FLOW_ERRORS:
            raise
        except BaseException:
            raise AudioConversionError from None

    async def close_playback(self) -> bool:
        return await _sanitize_native_bool_operation(self._native.close_playback)

    async def stop_recording(self) -> bool:
        return await _sanitize_native_bool_operation(self._native.stop_recording)

    async def stop_playback(self) -> bool:
        return await _sanitize_native_bool_operation(self._native.stop_playback)

    async def stop_motion(self) -> bool:
        return await _sanitize_native_bool_operation(self._native.stop_motion)

    async def disable_audio_reactive(self) -> bool:
        return await _sanitize_native_bool_operation(self._native.disable_audio_reactive)


__all__ = [
    "PlaybackFrameFactory",
    "REACHY_SDK_DECLARED_NATIVE_AUDIO_FORMAT",
    "ReachySdkNativeMediaAdapter",
    "ReachySdkNativeMediaBackend",
]
