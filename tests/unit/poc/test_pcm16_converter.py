from __future__ import annotations

import asyncio
from array import array
from collections.abc import AsyncIterator, Iterable
from sys import byteorder

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from tuntun_contracts.poc.framing import (
    MAX_DIRECTION_BYTES,
    MAX_TRANSPORT_PCM_FRAME_BYTES,
    TRANSPORT_AUDIO_FORMAT,
)
from tuntun_contracts.speech import AudioFormat
from tuntun_core.adapters.poc.pcm16_converter import (
    AudioConversionError,
    Pcm16Converter,
)


def _format(sample_rate_hz: int) -> AudioFormat:
    return AudioFormat(
        sample_format="s16le",
        sample_rate_hz=sample_rate_hz,
        channels=1,
        interleaved=False,
        channel_layout="mono",
    )


def _pcm(samples: Iterable[int]) -> bytes:
    values = array("h", samples)
    if byteorder != "little":
        values.byteswap()
    return values.tobytes()


def _samples(pcm: bytes) -> tuple[int, ...]:
    values = array("h")
    values.frombytes(pcm)
    if byteorder != "little":
        values.byteswap()
    return tuple(values)


class _TrackedStream:
    def __init__(
        self,
        chunks: Iterable[bytes],
        *,
        late_error: BaseException | None = None,
    ) -> None:
        self._chunks = iter(chunks)
        self._late_error = late_error
        self.closed = False
        self._finished = False

    def __aiter__(self) -> _TrackedStream:
        return self

    async def __anext__(self) -> bytes:
        if self._finished:
            raise StopAsyncIteration
        try:
            return next(self._chunks)
        except StopIteration:
            self._finished = True
            if self._late_error is not None:
                raise self._late_error from None
            raise StopAsyncIteration from None

    async def aclose(self) -> None:
        self.closed = True


async def _collect(stream: AsyncIterator[bytes]) -> tuple[bytes, ...]:
    return tuple([chunk async for chunk in stream])


@pytest.mark.asyncio
async def test_identity_conversion_is_fully_buffered_and_deterministically_chunked() -> None:
    source_pcm = bytes(range(256)) * 51
    source = _TrackedStream((source_pcm[:6_401], source_pcm[6_401:]))

    chunks = await _collect(
        Pcm16Converter().convert(
            source,
            TRANSPORT_AUDIO_FORMAT,
            TRANSPORT_AUDIO_FORMAT,
        )
    )

    assert chunks == (source_pcm[:6_400], source_pcm[6_400:12_800], source_pcm[12_800:])
    assert all(0 < len(chunk) <= MAX_TRANSPORT_PCM_FRAME_BYTES for chunk in chunks)
    assert all(len(chunk) % 2 == 0 for chunk in chunks)
    assert b"".join(chunks) == source_pcm
    assert source.closed is True


@pytest.mark.asyncio
async def test_resampling_uses_deterministic_linear_interpolation() -> None:
    source = _TrackedStream((_pcm((100, 200, 300)),))

    chunks = await _collect(
        Pcm16Converter().convert(source, _format(24_000), TRANSPORT_AUDIO_FORMAT)
    )

    assert _samples(b"".join(chunks)) == (100, 250)
    assert source.closed is True


@given(
    source_rate=st.sampled_from((8_000, 12_000, 16_000, 24_000, 32_000, 44_100, 48_000)),
    sample_count=st.integers(min_value=1, max_value=2_000),
)
@settings(max_examples=40, deadline=None)
def test_resampled_duration_is_within_one_target_sample(
    source_rate: int,
    sample_count: int,
) -> None:
    async def exercise() -> int:
        converted = await _collect(
            Pcm16Converter().convert(
                _TrackedStream((_pcm([0] * sample_count),)),
                _format(source_rate),
                TRANSPORT_AUDIO_FORMAT,
            )
        )
        return len(b"".join(converted)) // 2

    target_samples = asyncio.run(exercise())
    assert abs(target_samples * source_rate - sample_count * 16_000) <= source_rate


@pytest.mark.asyncio
async def test_converter_accepts_exactly_ninety_seconds_in_identity_mode() -> None:
    source = _TrackedStream((bytes(2 * 16_000 * 90),))

    chunks = await _collect(
        Pcm16Converter().convert(source, TRANSPORT_AUDIO_FORMAT, TRANSPORT_AUDIO_FORMAT)
    )

    assert sum(map(len, chunks)) == 2_880_000
    assert source.closed is True


@pytest.mark.parametrize(
    "source_format,chunks",
    [
        (TRANSPORT_AUDIO_FORMAT, (b"",)),
        (TRANSPORT_AUDIO_FORMAT, (b"\x00",)),
        (TRANSPORT_AUDIO_FORMAT, (bytes(2 * 16_000 * 90 + 2),)),
        (_format(96_000), (bytes(MAX_DIRECTION_BYTES), b"\x00\x00")),
        (
            AudioFormat(
                sample_format="float32_le",
                sample_rate_hz=24_000,
                channels=1,
                interleaved=False,
                channel_layout="mono",
            ),
            (bytes(4),),
        ),
    ],
)
@pytest.mark.asyncio
async def test_converter_rejects_empty_misaligned_overlong_or_unsupported_input(
    source_format: AudioFormat,
    chunks: tuple[bytes, ...],
) -> None:
    source = _TrackedStream(chunks)

    with pytest.raises(AudioConversionError, match="^audio-conversion-rejected$"):
        await _collect(Pcm16Converter().convert(source, source_format, TRANSPORT_AUDIO_FORMAT))

    assert source.closed is True


@pytest.mark.parametrize("spoof_boundary", ["source", "target"])
@pytest.mark.asyncio
async def test_converter_rejects_scalar_spoofed_audio_formats(
    spoof_boundary: str,
) -> None:
    spoofed = AudioFormat.model_construct(
        sample_format="s16le",
        sample_rate_hz=16_000.0,
        channels=1.0,
        interleaved=False,
        channel_layout="mono",
    )
    source_format = spoofed if spoof_boundary == "source" else TRANSPORT_AUDIO_FORMAT
    target_format = spoofed if spoof_boundary == "target" else TRANSPORT_AUDIO_FORMAT
    source = _TrackedStream((_pcm((1, 2, 3)),))

    with pytest.raises(AudioConversionError, match="^audio-conversion-rejected$"):
        await _collect(Pcm16Converter().convert(source, source_format, target_format))

    assert source.closed is True


@pytest.mark.asyncio
async def test_converter_yields_nothing_when_source_fails_after_valid_pcm() -> None:
    source = _TrackedStream(
        (_pcm((1, 2, 3, 4)),),
        late_error=RuntimeError("private-provider-body"),
    )
    observed: list[bytes] = []

    with pytest.raises(AudioConversionError, match="^audio-conversion-rejected$") as error:
        async for chunk in Pcm16Converter().convert(
            source,
            _format(24_000),
            TRANSPORT_AUDIO_FORMAT,
        ):
            observed.append(chunk)

    assert observed == []
    assert "private-provider-body" not in repr(error.value)
    assert error.value.__context__ is None
    assert error.value.__cause__ is None
    assert source.closed is True


@pytest.mark.asyncio
async def test_converter_cancellation_closes_a_blocked_source_without_output() -> None:
    entered = asyncio.Event()

    class _BlockedSource:
        def __init__(self) -> None:
            self.closed = False
            self._sent = False

        def __aiter__(self) -> _BlockedSource:
            return self

        async def __anext__(self) -> bytes:
            if not self._sent:
                self._sent = True
                return _pcm((1, 2))
            entered.set()
            await asyncio.Future()
            raise AssertionError("unreachable")

        async def aclose(self) -> None:
            self.closed = True

    source = _BlockedSource()
    converted = Pcm16Converter().convert(source, _format(24_000), TRANSPORT_AUDIO_FORMAT)
    task = asyncio.create_task(anext(converted))
    await asyncio.wait_for(entered.wait(), timeout=1)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert source.closed is True
    with pytest.raises(StopAsyncIteration):
        await anext(converted)


@pytest.mark.asyncio
async def test_converter_cancellation_during_resampling_closes_without_output() -> None:
    source = _TrackedStream((_pcm([1] * (24_000 * 20)),))
    converted = Pcm16Converter().convert(
        source,
        _format(24_000),
        TRANSPORT_AUDIO_FORMAT,
    )
    task = asyncio.create_task(anext(converted))
    await asyncio.sleep(0)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert source.closed is True
    with pytest.raises(StopAsyncIteration):
        await anext(converted)


@pytest.mark.parametrize(
    "close_error",
    [RuntimeError("private-close-body"), KeyboardInterrupt()],
    ids=("runtime-error", "fatal-base-exception"),
)
@pytest.mark.asyncio
async def test_converter_preserves_cancellation_when_source_close_masks_it(
    close_error: BaseException,
) -> None:
    entered = asyncio.Event()

    class _MaskingCloseSource:
        def __init__(self) -> None:
            self._sent = False
            self.closed = 0

        def __aiter__(self) -> _MaskingCloseSource:
            return self

        async def __anext__(self) -> bytes:
            if self._sent:
                raise StopAsyncIteration
            self._sent = True
            return _pcm((1, 2, 3))

        async def aclose(self) -> None:
            self.closed += 1
            entered.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                raise close_error from None

    source = _MaskingCloseSource()
    converted = Pcm16Converter().convert(
        source,
        _format(24_000),
        TRANSPORT_AUDIO_FORMAT,
    )
    task = asyncio.create_task(anext(converted))
    await asyncio.wait_for(entered.wait(), timeout=1)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert source.closed == 1
    with pytest.raises(StopAsyncIteration):
        await anext(converted)


@pytest.mark.asyncio
async def test_converter_preserves_cancellation_when_source_close_swallows_it() -> None:
    entered = asyncio.Event()

    class _CancellationSwallowingSource:
        def __init__(self) -> None:
            self._sent = False
            self.closed = 0

        def __aiter__(self) -> _CancellationSwallowingSource:
            return self

        async def __anext__(self) -> bytes:
            if self._sent:
                raise StopAsyncIteration
            self._sent = True
            return _pcm((1, 2, 3))

        async def aclose(self) -> None:
            self.closed += 1
            entered.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                return

    source = _CancellationSwallowingSource()
    converted = Pcm16Converter().convert(
        source,
        _format(24_000),
        TRANSPORT_AUDIO_FORMAT,
    )
    task = asyncio.create_task(anext(converted))
    await asyncio.wait_for(entered.wait(), timeout=1)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert source.closed == 1
    with pytest.raises(StopAsyncIteration):
        await anext(converted)


@pytest.mark.asyncio
async def test_converter_wipes_buffers_when_iteration_and_close_raise_base_exceptions() -> None:
    class _FatalSource:
        def __init__(self) -> None:
            self._calls = 0

        def __aiter__(self) -> _FatalSource:
            return self

        async def __anext__(self) -> bytes:
            self._calls += 1
            if self._calls == 1:
                return _pcm((101, 202, 303))
            raise KeyboardInterrupt

        async def aclose(self) -> None:
            raise KeyboardInterrupt

    converted = Pcm16Converter().convert(
        _FatalSource(),
        _format(24_000),
        TRANSPORT_AUDIO_FORMAT,
    )

    with pytest.raises(KeyboardInterrupt) as error:
        await anext(converted)

    traceback = error.value.__traceback__
    converter_locals: dict[str, object] | None = None
    while traceback is not None:
        if traceback.tb_frame.f_code.co_name == "_convert":
            converter_locals = dict(traceback.tb_frame.f_locals)
            break
        traceback = traceback.tb_next
    assert converter_locals is not None
    assert converter_locals["source_pcm"] == bytearray()
    assert converter_locals["converted_pcm"] == bytearray()
