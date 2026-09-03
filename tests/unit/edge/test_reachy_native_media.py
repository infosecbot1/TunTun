from __future__ import annotations

import struct
from collections import deque
from collections.abc import Callable

import pytest
from tuntun_contracts.poc.framing import MAX_TRANSPORT_PCM_FRAME_BYTES, TRANSPORT_AUDIO_FORMAT
from tuntun_contracts.speech import AudioFormat
from tuntun_edge.audio.converter import AudioConversionError
from tuntun_edge.poc.ports import ReachyLocalMediaPort
from tuntun_edge.reachy.native_media import (
    REACHY_SDK_DECLARED_NATIVE_AUDIO_FORMAT,
    ReachySdkNativeMediaAdapter,
)


def _pack_s16(samples: tuple[int, ...]) -> bytes:
    return struct.pack(f"<{len(samples)}h", *samples)


def _unpack_s16(pcm: bytes) -> list[int]:
    return list(struct.unpack(f"<{len(pcm) // 2}h", pcm))


class _Float32StereoMatrix:
    ndim = 2

    class DType:
        name = "float32"
        byteorder = "<"
        itemsize = 4

        def __str__(self) -> str:
            return "float32"

    dtype: object = DType()

    def __init__(self, rows: tuple[tuple[float, ...], ...]) -> None:
        self._rows = rows
        self.shape = (len(rows), len(rows[0]) if rows else 2)
        self.nbytes = len(rows) * (len(rows[0]) if rows else 2) * 4

    def tolist(self) -> list[list[float]]:
        return [list(row) for row in self._rows]

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, _Float32StereoMatrix)
            and self.shape == other.shape
            and self._rows == other._rows
        )


class _BigEndianFloat32StereoMatrix(_Float32StereoMatrix):
    class DType:
        name = "float32"
        byteorder = ">"
        itemsize = 4

        def __str__(self) -> str:
            return ">f4"

    dtype: object = DType()


class _OversizedLyingMatrix(_Float32StereoMatrix):
    def __init__(self) -> None:
        super().__init__(((0.0, 0.0),))
        self.nbytes = MAX_TRANSPORT_PCM_FRAME_BYTES * 4 + 8
        self.tolist_called = False

    def tolist(self) -> list[list[float]]:
        self.tolist_called = True
        raise AssertionError("private matrix payload should not be materialized")


class _NativeBackend:
    def __init__(self, capture_frames: tuple[object | None, ...] = ()) -> None:
        self.capture_frames = deque(capture_frames)
        self.capture_opened: list[tuple[AudioFormat, int]] = []
        self.playback_opened: list[AudioFormat] = []
        self.playback_frames: list[object] = []
        self.cleanup_calls: list[str] = []
        self.open_capture_error: BaseException | None = None
        self.read_capture_error: BaseException | None = None
        self.close_capture_error: BaseException | None = None
        self.open_playback_error: BaseException | None = None
        self.write_playback_error: BaseException | None = None
        self.close_playback_error: BaseException | None = None
        self.stop_recording_error: BaseException | None = None
        self.stop_playback_error: BaseException | None = None
        self.stop_motion_error: BaseException | None = None
        self.disable_audio_reactive_error: BaseException | None = None

    async def open_capture(
        self,
        *,
        native_format: AudioFormat,
        max_source_frame_bytes: int,
    ) -> None:
        if self.open_capture_error is not None:
            raise self.open_capture_error
        self.capture_opened.append((native_format, max_source_frame_bytes))

    async def read_capture(self) -> object | None:
        if self.read_capture_error is not None:
            raise self.read_capture_error
        return self.capture_frames.popleft() if self.capture_frames else None

    async def close_capture(self) -> bool:
        if self.close_capture_error is not None:
            raise self.close_capture_error
        self.cleanup_calls.append("close_capture")
        return True

    async def open_playback(self, *, native_format: AudioFormat) -> None:
        if self.open_playback_error is not None:
            raise self.open_playback_error
        self.playback_opened.append(native_format)

    async def write_playback(self, frame: object) -> None:
        if self.write_playback_error is not None:
            raise self.write_playback_error
        self.playback_frames.append(frame)

    async def close_playback(self) -> bool:
        if self.close_playback_error is not None:
            raise self.close_playback_error
        self.cleanup_calls.append("close_playback")
        return True

    async def stop_recording(self) -> bool:
        if self.stop_recording_error is not None:
            raise self.stop_recording_error
        self.cleanup_calls.append("stop_recording")
        return True

    async def stop_playback(self) -> bool:
        if self.stop_playback_error is not None:
            raise self.stop_playback_error
        self.cleanup_calls.append("stop_playback")
        return True

    async def stop_motion(self) -> bool:
        if self.stop_motion_error is not None:
            raise self.stop_motion_error
        self.cleanup_calls.append("stop_motion")
        return True

    async def disable_audio_reactive(self) -> bool:
        if self.disable_audio_reactive_error is not None:
            raise self.disable_audio_reactive_error
        self.cleanup_calls.append("disable_audio_reactive")
        return True


def _recording_factory(
    created: list[tuple[tuple[float, float], ...]],
) -> Callable[[tuple[tuple[float, float], ...]], object]:
    def factory(rows: tuple[tuple[float, float], ...]) -> object:
        created.append(rows)
        return _Float32StereoMatrix(rows)

    return factory


@pytest.mark.asyncio
async def test_sdk_native_media_adapter_downmixes_float32_stereo_capture_to_transport() -> None:
    native = _NativeBackend(
        (
            _Float32StereoMatrix(((1.0, 0.0), (-1.0, 1.0), (0.25, 0.25))),
            None,
        )
    )
    adapter = ReachySdkNativeMediaAdapter(native, playback_frame_factory=_recording_factory([]))

    assert isinstance(adapter, ReachyLocalMediaPort)

    await adapter.open_capture(
        output_format=TRANSPORT_AUDIO_FORMAT,
        max_frame_bytes=MAX_TRANSPORT_PCM_FRAME_BYTES,
    )
    pcm = await adapter.read_capture()

    assert native.capture_opened == [
        (REACHY_SDK_DECLARED_NATIVE_AUDIO_FORMAT, MAX_TRANSPORT_PCM_FRAME_BYTES * 4)
    ]
    assert pcm is not None
    assert _unpack_s16(pcm) == [16383, 0, 8191]
    assert await adapter.read_capture() is None


@pytest.mark.parametrize(
    "native_frame",
    (
        b"private raw sdk audio",
        _BigEndianFloat32StereoMatrix(((0.0, 0.0),)),
        _Float32StereoMatrix(((0.0,),)),
        _Float32StereoMatrix(((0.0, 0.0, 0.0),)),
        _Float32StereoMatrix(tuple((0.0, 0.0) for _ in range(3_201))),
    ),
)
@pytest.mark.asyncio
async def test_sdk_native_media_adapter_rejects_malformed_or_oversized_capture_without_leakage(
    native_frame: object,
) -> None:
    native = _NativeBackend((native_frame,))
    adapter = ReachySdkNativeMediaAdapter(native, playback_frame_factory=_recording_factory([]))
    await adapter.open_capture(
        output_format=TRANSPORT_AUDIO_FORMAT,
        max_frame_bytes=MAX_TRANSPORT_PCM_FRAME_BYTES,
    )

    with pytest.raises(AudioConversionError, match="^audio-conversion-rejected$") as raised:
        await adapter.read_capture()

    rendered = f"{raised.value!s} {raised.value!r}"
    assert "private" not in rendered
    assert "sdk audio" not in rendered


@pytest.mark.asyncio
async def test_sdk_native_media_adapter_rejects_oversized_matrix_before_tolist() -> None:
    native_frame = _OversizedLyingMatrix()
    native = _NativeBackend((native_frame,))
    adapter = ReachySdkNativeMediaAdapter(native, playback_frame_factory=_recording_factory([]))
    await adapter.open_capture(
        output_format=TRANSPORT_AUDIO_FORMAT,
        max_frame_bytes=MAX_TRANSPORT_PCM_FRAME_BYTES,
    )

    with pytest.raises(AudioConversionError, match="^audio-conversion-rejected$") as raised:
        await adapter.read_capture()

    rendered = f"{raised.value!s} {raised.value!r}"
    assert native_frame.tolist_called is False
    assert "private matrix payload" not in rendered


@pytest.mark.parametrize(
    "operation",
    ("open_capture", "read_capture", "open_playback", "write_playback"),
)
@pytest.mark.asyncio
async def test_sdk_native_media_adapter_sanitizes_private_native_backend_failures(
    operation: str,
) -> None:
    native = _NativeBackend((_Float32StereoMatrix(((0.0, 0.0),)),))
    setattr(native, f"{operation}_error", RuntimeError("private raw sdk audio"))
    adapter = ReachySdkNativeMediaAdapter(native, playback_frame_factory=_recording_factory([]))

    with pytest.raises(AudioConversionError, match="^audio-conversion-rejected$") as raised:
        if operation == "open_capture":
            await adapter.open_capture(
                output_format=TRANSPORT_AUDIO_FORMAT,
                max_frame_bytes=MAX_TRANSPORT_PCM_FRAME_BYTES,
            )
        elif operation == "read_capture":
            await adapter.open_capture(
                output_format=TRANSPORT_AUDIO_FORMAT,
                max_frame_bytes=MAX_TRANSPORT_PCM_FRAME_BYTES,
            )
            await adapter.read_capture()
        elif operation == "open_playback":
            await adapter.open_playback(input_format=TRANSPORT_AUDIO_FORMAT)
        else:
            await adapter.open_playback(input_format=TRANSPORT_AUDIO_FORMAT)
            await adapter.write_playback(_pack_s16((0,)))

    rendered = f"{raised.value!s} {raised.value!r}"
    assert "private" not in rendered
    assert "sdk audio" not in rendered


@pytest.mark.parametrize(
    "operation",
    (
        "close_capture",
        "close_playback",
        "stop_recording",
        "stop_playback",
        "stop_motion",
        "disable_audio_reactive",
    ),
)
@pytest.mark.asyncio
async def test_sdk_native_media_adapter_sanitizes_private_cleanup_failures(
    operation: str,
) -> None:
    native = _NativeBackend()
    setattr(native, f"{operation}_error", RuntimeError("private cleanup backend data"))
    adapter = ReachySdkNativeMediaAdapter(native, playback_frame_factory=_recording_factory([]))

    with pytest.raises(AudioConversionError, match="^audio-conversion-rejected$") as raised:
        await getattr(adapter, operation)()

    rendered = f"{raised.value!s} {raised.value!r}"
    assert "private" not in rendered
    assert "backend data" not in rendered


@pytest.mark.asyncio
async def test_sdk_native_media_adapter_converts_transport_playback_to_float32_stereo() -> None:
    created: list[tuple[tuple[float, float], ...]] = []
    native = _NativeBackend()
    adapter = ReachySdkNativeMediaAdapter(
        native,
        playback_frame_factory=_recording_factory(created),
    )

    await adapter.open_playback(input_format=TRANSPORT_AUDIO_FORMAT)
    await adapter.write_playback(_pack_s16((-32768, 0, 32767)))

    assert native.playback_opened == [REACHY_SDK_DECLARED_NATIVE_AUDIO_FORMAT]
    assert created == [((-1.0, -1.0), (0.0, 0.0), (1.0, 1.0))]
    assert native.playback_frames == [_Float32StereoMatrix(created[0])]


@pytest.mark.parametrize("payload", (b"", b"\x00", b"\x00" * (MAX_TRANSPORT_PCM_FRAME_BYTES + 2)))
@pytest.mark.asyncio
async def test_sdk_native_media_adapter_rejects_bad_transport_playback(payload: bytes) -> None:
    native = _NativeBackend()
    adapter = ReachySdkNativeMediaAdapter(native, playback_frame_factory=_recording_factory([]))
    await adapter.open_playback(input_format=TRANSPORT_AUDIO_FORMAT)

    with pytest.raises(AudioConversionError, match="^audio-conversion-rejected$"):
        await adapter.write_playback(payload)

    assert native.playback_frames == []


@pytest.mark.asyncio
async def test_sdk_native_media_adapter_delegates_cleanup_to_native_backend() -> None:
    native = _NativeBackend()
    adapter = ReachySdkNativeMediaAdapter(native, playback_frame_factory=_recording_factory([]))

    assert await adapter.close_capture() is True
    assert await adapter.close_playback() is True
    assert await adapter.stop_recording() is True
    assert await adapter.stop_playback() is True
    assert await adapter.stop_motion() is True
    assert await adapter.disable_audio_reactive() is True
    assert native.cleanup_calls == [
        "close_capture",
        "close_playback",
        "stop_recording",
        "stop_playback",
        "stop_motion",
        "disable_audio_reactive",
    ]
