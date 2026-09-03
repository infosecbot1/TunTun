from __future__ import annotations

import asyncio
import importlib
import importlib.util
import math
import struct
from collections.abc import AsyncIterator
from typing import Protocol, cast

import pytest
from tuntun_contracts.ports import AudioConverterPort
from tuntun_contracts.speech import AudioFormat
from tuntun_edge.audio.converter import (
    MAX_AUDIO_CHUNK,
    MAX_SOURCE_CHUNK_BYTES,
    MAX_TURN_BYTES,
    AudioConversionError,
    StreamingAudioConverter,
    to_s16le_mono,
)

TARGET_FORMAT = AudioFormat(
    sample_format="s16le",
    sample_rate_hz=16_000,
    channels=1,
    interleaved=True,
    channel_layout="mono",
)


def _format(
    *,
    sample_format: str = "s16le",
    sample_rate_hz: int = 16_000,
    channels: int = 1,
    interleaved: bool = True,
    channel_layout: str = "mono",
) -> AudioFormat:
    return AudioFormat(
        sample_format=sample_format,  # type: ignore[arg-type]
        sample_rate_hz=sample_rate_hz,
        channels=channels,
        interleaved=interleaved,
        channel_layout=channel_layout,  # type: ignore[arg-type]
    )


def _pack_s16(samples: tuple[int, ...]) -> bytes:
    return struct.pack(f"<{len(samples)}h", *samples)


def _unpack_s16(pcm: bytes) -> list[int]:
    return list(struct.unpack(f"<{len(pcm) // 2}h", pcm))


def _pack_float32(frames: tuple[tuple[float, ...], ...]) -> bytes:
    return b"".join(struct.pack(f"<{len(frame)}f", *frame) for frame in frames)


async def _chunks(items: tuple[bytes, ...]) -> AsyncIterator[bytes]:
    for item in items:
        yield item


async def _collect(
    items: tuple[bytes, ...],
    source: AudioFormat,
    target: AudioFormat = TARGET_FORMAT,
) -> bytes:
    chunks = [
        chunk
        async for chunk in StreamingAudioConverter().convert(
            _chunks(items),
            source,
            target,
        )
    ]
    assert all(0 < len(chunk) <= MAX_AUDIO_CHUNK and len(chunk) % 2 == 0 for chunk in chunks)
    return b"".join(chunks)


class _ClosingSource:
    def __init__(
        self,
        items: tuple[object, ...],
        *,
        error: BaseException | None = None,
    ) -> None:
        self.items = list(items)
        self.error = error
        self.closed = False
        self.close_count = 0
        self.stop_observed = False

    def __aiter__(self) -> _ClosingSource:
        return self

    async def __anext__(self) -> bytes:
        if self.items:
            return self.items.pop(0)  # type: ignore[return-value]
        if self.error is not None:
            raise self.error
        self.stop_observed = True
        raise StopAsyncIteration

    async def aclose(self) -> None:
        self.close_count += 1
        self.closed = True


class _CancellingCloseSource(_ClosingSource):
    async def aclose(self) -> None:
        self.close_count += 1
        self.closed = True
        raise asyncio.CancelledError


class _FatalCloseSource(_ClosingSource):
    async def aclose(self) -> None:
        self.close_count += 1
        self.closed = True
        raise BaseException("private converter close sentinel")


class _Float32ChannelMatrix:
    ndim = 2
    dtype = "float32"

    def __init__(self, rows: tuple[tuple[float, ...], ...]) -> None:
        self._rows = rows
        self.shape = (len(rows), len(rows[0]))

    def tolist(self) -> list[list[float]]:
        return [list(row) for row in self._rows]


class _NumpyArrayResult(Protocol):
    def tolist(self) -> list[int]: ...


class _NumpyModule(Protocol):
    float32: object

    def array(self, value: object, *, dtype: object) -> object: ...

    def frombuffer(self, buffer: bytes, *, dtype: str) -> _NumpyArrayResult: ...


class _BlockingAfterFirstSource:
    def __init__(self) -> None:
        self.closed = False
        self.close_count = 0
        self.first_sent = False
        self.waiting_for_second = asyncio.Event()

    def __aiter__(self) -> _BlockingAfterFirstSource:
        return self

    async def __anext__(self) -> bytes:
        if not self.first_sent:
            self.first_sent = True
            return b"\x00" * MAX_AUDIO_CHUNK
        self.waiting_for_second.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async def aclose(self) -> None:
        self.close_count += 1
        self.closed = True


def test_to_s16le_mono_clips_downmixes_and_scales_poles_exactly() -> None:
    pcm = to_s16le_mono(
        (
            (1.0, 1.0),
            (1.5, 1.5),
            (-1.0, -1.0),
            (-1.5, -1.5),
            (1.5, 0.5),
            (-1.5, -0.5),
            (0.25, -0.25),
        ),
    )

    assert _unpack_s16(pcm) == [32767, 32767, -32768, -32768, 32767, -32768, 0]
    assert pcm == struct.pack("<hhhhhhh", 32767, 32767, -32768, -32768, 32767, -32768, 0)


def test_to_s16le_mono_accepts_float32_channel_matrix_through_four_channels() -> None:
    pcm = to_s16le_mono(
        _Float32ChannelMatrix(
            (
                (1.0, 1.0, 1.0, 1.0),
                (-1.0, -1.0, -1.0, -1.0),
                (1.0, 0.0, 0.0, 0.0),
                (1.0, 1.0, -1.0, -1.0),
            ),
        ),
    )

    assert _unpack_s16(pcm) == [32767, -32768, 8191, 0]


def test_to_s16le_mono_accepts_numpy_float32_ndarray_when_available() -> None:
    if importlib.util.find_spec("numpy") is None:
        pytest.skip("numpy is not declared or installed in this workspace")

    numpy = cast(_NumpyModule, importlib.import_module("numpy"))
    frame = numpy.array(
        (
            (1.0, 1.0, 1.0, 1.0),
            (-1.0, -1.0, -1.0, -1.0),
            (1.0, 0.0, 0.0, 0.0),
            (1.0, 1.0, -1.0, -1.0),
        ),
        dtype=numpy.float32,
    )

    result = numpy.frombuffer(to_s16le_mono(frame), dtype="<i2")

    assert result.tolist() == [32767, -32768, 8191, 0]


@pytest.mark.parametrize("bad_value", (float("nan"), float("inf"), float("-inf"), True))
def test_to_s16le_mono_rejects_nonfinite_and_non_exact_float_values(bad_value: object) -> None:
    with pytest.raises(AudioConversionError, match="^audio-conversion-rejected$"):
        to_s16le_mono(((bad_value,),))


@pytest.mark.asyncio
async def test_public_converter_streams_bounded_target_chunks_and_matches_port() -> None:
    source = _format(sample_rate_hz=48_000)
    frame = _pack_s16(tuple((index % 257) - 128 for index in range(48_000)))

    converter = StreamingAudioConverter()
    chunks = [chunk async for chunk in converter.convert(_chunks((frame,)), source, TARGET_FORMAT)]

    assert isinstance(converter, AudioConverterPort)
    assert chunks
    assert all(0 < len(chunk) <= MAX_AUDIO_CHUNK and len(chunk) % 2 == 0 for chunk in chunks)
    assert sum(len(chunk) for chunk in chunks) <= MAX_TURN_BYTES


@pytest.mark.asyncio
async def test_s16le_mono_exact_endian_roundtrip_preserves_residual_frames() -> None:
    source = _format()
    expected = _pack_s16((-32768, -1, 0, 1, 32767))

    converted = await _collect((expected[:3], expected[3:7], expected[7:]), source)

    assert converted == expected


@pytest.mark.asyncio
async def test_float32_stereo_exact_endian_conversion_preserves_residual_frames() -> None:
    source = _format(
        sample_format="float32_le",
        sample_rate_hz=16_000,
        channels=2,
        channel_layout="stereo",
    )
    payload = _pack_float32(((1.0, 0.0), (-1.0, 0.0), (0.5, 0.5)))

    converted = await _collect((payload[:5], payload[5:17], payload[17:]), source)

    assert _unpack_s16(converted) == [16383, -16384, 16383]


@pytest.mark.asyncio
async def test_float32_reachy_native_three_and_four_channel_sources_downmix_exactly() -> None:
    three_channel = _format(
        sample_format="float32_le",
        sample_rate_hz=16_000,
        channels=3,
        channel_layout="reachy_native",
    )
    four_channel = _format(
        sample_format="float32_le",
        sample_rate_hz=16_000,
        channels=4,
        channel_layout="reachy_native",
    )

    converted_three = await _collect(
        (
            _pack_float32(
                ((1.0, 1.0, 1.0), (1.0, 0.0, 0.0), (-1.0, -1.0, -1.0)),
            ),
        ),
        three_channel,
    )
    converted_four = await _collect(
        (
            _pack_float32(
                ((1.0, 1.0, 1.0, 1.0), (1.0, 0.0, 0.0, 0.0), (1.0, 1.0, -1.0, -1.0)),
            ),
        ),
        four_channel,
    )

    assert _unpack_s16(converted_three) == [32767, 10922, -32768]
    assert _unpack_s16(converted_four) == [32767, 8191, 0]


@pytest.mark.asyncio
async def test_s16le_reachy_native_three_and_four_channel_sources_downmix_exactly() -> None:
    three_channel = _format(channels=3, channel_layout="reachy_native")
    four_channel = _format(channels=4, channel_layout="reachy_native")

    converted_three = await _collect(
        (_pack_s16((32767, 32767, 32767, 32767, 0, 0, -32768, -32768, -32768)),),
        three_channel,
    )
    converted_four = await _collect(
        (
            _pack_s16(
                (32767, 32767, 32767, 32767, 32767, 0, 0, 0, 32767, 32767, -32768, -32768),
            ),
        ),
        four_channel,
    )

    assert _unpack_s16(converted_three) == [32767, 10922, -32768]
    assert _unpack_s16(converted_four) == [32767, 8191, 0]


@pytest.mark.asyncio
async def test_resampling_is_stateful_across_awkward_async_boundaries() -> None:
    source = _format(sample_rate_hz=48_000, channels=2, channel_layout="stereo")
    frames: list[int] = []
    for index in range(4_800):
        value = int(math.sin(index / 17.0) * 12_000)
        frames.extend((value, -value // 2))
    payload = _pack_s16(tuple(frames))

    one_shot = await _collect((payload,), source)
    split = await _collect((payload[:3], payload[3:997], payload[997:4099], payload[4099:]), source)

    assert split == one_shot


@pytest.mark.asyncio
async def test_converter_emits_incrementally_with_only_chunk_sized_output_carry() -> None:
    source = _BlockingAfterFirstSource()
    converted = StreamingAudioConverter().convert(source, _format(), TARGET_FORMAT)

    first = await asyncio.wait_for(anext(converted), timeout=1)
    await converted.aclose()

    assert first == b"\x00" * MAX_AUDIO_CHUNK
    assert source.waiting_for_second.is_set() is False
    assert source.closed is True
    assert source.close_count == 1


@pytest.mark.asyncio
async def test_converter_reports_malformed_stream_end_after_emitting_prior_full_chunks() -> None:
    source = _ClosingSource((b"\x00" * MAX_AUDIO_CHUNK, b"\x01"))
    converted = StreamingAudioConverter().convert(source, _format(), TARGET_FORMAT)

    assert await anext(converted) == b"\x00" * MAX_AUDIO_CHUNK
    with pytest.raises(AudioConversionError, match="^audio-conversion-rejected$"):
        await anext(converted)

    assert source.closed is True
    assert source.close_count == 1


@pytest.mark.parametrize("source_rate", (8_000, 44_100, 96_000))
@pytest.mark.asyncio
async def test_converter_accepts_supported_source_rates_with_expected_duration(
    source_rate: int,
) -> None:
    source = _format(sample_rate_hz=source_rate)
    source_samples = min(source_rate // 10, MAX_AUDIO_CHUNK // 2)
    payload = _pack_s16(
        tuple(int(math.sin(index / 9.0) * 8_000) for index in range(source_samples)),
    )

    converted = await _collect((payload[:101], payload[101:]), source)
    expected_target_samples = round(source_samples * TARGET_FORMAT.sample_rate_hz / source_rate)

    assert abs((len(converted) // 2) - expected_target_samples) <= 1


@pytest.mark.parametrize(
    "source",
    (
        AudioFormat.model_construct(
            sample_format="s16le",
            sample_rate_hz="16000",
            channels=1,
            interleaved=True,
            channel_layout="mono",
        ),
        AudioFormat.model_construct(
            sample_format="s16le",
            sample_rate_hz=16_000,
            channels=2,
            interleaved=True,
            channel_layout="mono",
        ),
        AudioFormat.model_construct(
            sample_format="s16le",
            sample_rate_hz=16_000,
            channels=1,
            interleaved=False,
            channel_layout="mono",
        ),
        AudioFormat.model_construct(
            sample_format="s16le",
            sample_rate_hz=16_000,
            channels=1,
            interleaved=True,
            channel_layout="stereo",
        ),
        AudioFormat.model_construct(
            sample_format="s16le",
            sample_rate_hz=16_000,
            channels=2,
            interleaved=True,
            channel_layout="reachy_native",
        ),
        AudioFormat.model_construct(
            sample_format="s16le",
            sample_rate_hz=16_000,
            channels=3,
            interleaved=True,
            channel_layout="stereo",
        ),
        AudioFormat.model_construct(
            sample_format="s16le",
            sample_rate_hz=16_000,
            channels=4,
            interleaved=True,
            channel_layout="mono",
        ),
        AudioFormat.model_construct(
            sample_format="s16le",
            sample_rate_hz=16_000,
            channels=4,
            interleaved=True,
            channel_layout="quad",
        ),
    ),
)
@pytest.mark.asyncio
async def test_converter_revalidates_source_format_at_runtime(source: AudioFormat) -> None:
    with pytest.raises(AudioConversionError, match="^audio-conversion-rejected$"):
        await _collect((_pack_s16((0,)),), source)


@pytest.mark.asyncio
async def test_converter_rejects_reachy_native_frame_alignment_after_consuming_source() -> None:
    source = _ClosingSource((b"\x00" * 11,))

    with pytest.raises(AudioConversionError, match="^audio-conversion-rejected$") as raised:
        async for _ in StreamingAudioConverter().convert(
            source,
            _format(sample_format="float32_le", channels=3, channel_layout="reachy_native"),
            TARGET_FORMAT,
        ):
            raise AssertionError("converter yielded before rejecting misaligned native frame")

    assert source.items == []
    assert source.closed is True
    assert source.close_count == 1
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.asyncio
async def test_converter_rejects_reachy_native_chunk_bounds_after_consuming_source() -> None:
    source = _ClosingSource((b"\x00" * (MAX_SOURCE_CHUNK_BYTES + 1),))

    with pytest.raises(AudioConversionError, match="^audio-conversion-rejected$") as raised:
        async for _ in StreamingAudioConverter().convert(
            source,
            _format(channels=4, channel_layout="reachy_native"),
            TARGET_FORMAT,
        ):
            raise AssertionError("converter yielded after oversized native chunk")

    assert source.items == []
    assert source.closed is True
    assert source.close_count == 1
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.parametrize(
    "target",
    (
        AudioFormat.model_construct(
            sample_format="s16le",
            sample_rate_hz=16_000,
            channels="1",
            interleaved=True,
            channel_layout="mono",
        ),
        _format(sample_rate_hz=8_000),
        _format(channels=2, channel_layout="stereo"),
        _format(interleaved=False),
    ),
)
@pytest.mark.asyncio
async def test_converter_requires_exact_target_format(target: AudioFormat) -> None:
    with pytest.raises(AudioConversionError, match="^audio-conversion-rejected$"):
        await _collect((_pack_s16((0,)),), _format(), target)


@pytest.mark.asyncio
async def test_converter_rejects_non_bytes_chunks_and_stream_end_leftovers_content_free() -> None:
    bad_type = _ClosingSource((bytearray(b"\x00\x00"),))
    with pytest.raises(AudioConversionError, match="^audio-conversion-rejected$"):
        async for _ in StreamingAudioConverter().convert(bad_type, _format(), TARGET_FORMAT):
            raise AssertionError("converter yielded after rejected input")
    assert bad_type.closed is True
    assert bad_type.close_count == 1

    leftover = _ClosingSource((b"\x01",))
    with pytest.raises(AudioConversionError, match="^audio-conversion-rejected$"):
        async for _ in StreamingAudioConverter().convert(leftover, _format(), TARGET_FORMAT):
            raise AssertionError("converter yielded before stream-end leftover rejection")
    assert leftover.stop_observed is True
    assert leftover.closed is True
    assert leftover.close_count == 1


@pytest.mark.asyncio
async def test_converter_rejects_oversized_source_chunk_before_decoding() -> None:
    source = _ClosingSource((b"\x00" * (MAX_SOURCE_CHUNK_BYTES + 1),))

    with pytest.raises(AudioConversionError, match="^audio-conversion-rejected$"):
        async for _ in StreamingAudioConverter().convert(source, _format(), TARGET_FORMAT):
            raise AssertionError("converter yielded after oversized source input")

    assert source.closed is True


@pytest.mark.asyncio
async def test_converter_rejects_nonfinite_float_streams_without_private_content() -> None:
    source = _format(sample_format="float32_le")
    payload = struct.pack("<f", float("nan"))

    with pytest.raises(AudioConversionError, match="^audio-conversion-rejected$") as raised:
        await _collect((payload,), source)

    assert "nan" not in str(raised.value).lower()


@pytest.mark.asyncio
async def test_converter_closes_source_on_private_failure_without_partial_output() -> None:
    source = _ClosingSource((_pack_s16((1, 2, 3)),), error=RuntimeError("secret transcript RIFF"))
    produced: list[bytes] = []

    with pytest.raises(AudioConversionError, match="^audio-conversion-rejected$") as raised:
        async for chunk in StreamingAudioConverter().convert(source, _format(), TARGET_FORMAT):
            produced.append(chunk)

    assert produced == []
    assert source.closed is True
    assert source.close_count == 1
    assert "secret" not in str(raised.value)
    assert "RIFF" not in str(raised.value)


@pytest.mark.asyncio
async def test_converter_translates_non_control_base_exception_without_private_leakage() -> None:
    source = _ClosingSource((), error=BaseException("private fatal audio bytes"))

    with pytest.raises(AudioConversionError, match="^audio-conversion-rejected$") as raised:
        async for _ in StreamingAudioConverter().convert(source, _format(), TARGET_FORMAT):
            raise AssertionError("converter yielded after private base exception")

    rendered = f"{raised.value!s} {raised.value!r}"
    assert source.closed is True
    assert source.close_count == 1
    assert "private" not in rendered
    assert "fatal" not in rendered
    assert "audio bytes" not in rendered
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.asyncio
async def test_converter_translates_close_base_exception_without_private_leakage() -> None:
    source = _FatalCloseSource((_pack_s16((0,)),))

    with pytest.raises(AudioConversionError, match="^audio-conversion-rejected$") as raised:
        async for _ in StreamingAudioConverter().convert(source, _format(), TARGET_FORMAT):
            raise AssertionError("converter yielded before private close base exception")

    rendered = f"{raised.value!s} {raised.value!r}"
    assert source.closed is True
    assert source.close_count == 1
    assert "private" not in rendered
    assert "sentinel" not in rendered
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.asyncio
async def test_converter_preserves_cancellation_and_closes_source() -> None:
    source = _ClosingSource((), error=asyncio.CancelledError())

    with pytest.raises(asyncio.CancelledError):
        async for _ in StreamingAudioConverter().convert(source, _format(), TARGET_FORMAT):
            raise AssertionError("converter yielded during cancellation")

    assert source.closed is True
    assert source.close_count == 1


@pytest.mark.asyncio
async def test_converter_preserves_cancellation_from_source_aclose_exactly_once() -> None:
    source = _CancellingCloseSource((_pack_s16((0,)),))

    with pytest.raises(asyncio.CancelledError):
        async for _ in StreamingAudioConverter().convert(source, _format(), TARGET_FORMAT):
            raise AssertionError("converter yielded before close cancellation")

    assert source.closed is True
    assert source.close_count == 1


@pytest.mark.asyncio
async def test_converter_enforces_emitted_turn_cap_exactly() -> None:
    full_chunks = (b"\x00" * MAX_AUDIO_CHUNK,) * (MAX_TURN_BYTES // MAX_AUDIO_CHUNK)

    converted = await _collect(full_chunks, _format())
    assert len(converted) == MAX_TURN_BYTES

    with pytest.raises(AudioConversionError, match="^audio-conversion-rejected$"):
        await _collect((*full_chunks, b"\x00\x00"), _format())
