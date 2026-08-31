"""Deterministic bounded mono PCM16 conversion for the Reachy transport."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from struct import Struct

from tuntun_contracts.poc.framing import (
    MAX_DIRECTION_BYTES,
    MAX_TRANSPORT_PCM_FRAME_BYTES,
    TRANSPORT_AUDIO_FORMAT,
)
from tuntun_contracts.speech import AudioFormat

_PCM16 = Struct("<h")
_MAX_MEDIA_SECONDS = 90


class AudioConversionError(ValueError):
    """Content-free rejection of source audio or conversion output."""

    def __init__(self) -> None:
        super().__init__("audio-conversion-rejected")


def _wipe(buffer: bytearray) -> None:
    buffer[:] = b"\x00" * len(buffer)
    buffer.clear()


async def _close(stream: AsyncIterator[bytes]) -> None:
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
    except Exception:
        return None
    if dumped != validated.model_dump(mode="python"):
        return None
    return validated


def _valid_source_format(audio_format: AudioFormat) -> bool:
    return (
        type(audio_format) is AudioFormat
        and audio_format.sample_format == "s16le"
        and audio_format.channels == 1
        and audio_format.interleaved is False
        and audio_format.channel_layout == "mono"
    )


def _rounded_div(value: int, divisor: int) -> int:
    if value >= 0:
        return (value + divisor // 2) // divisor
    return -((-value + divisor // 2) // divisor)


class Pcm16Converter:
    """Fully buffer, validate, resample, then emit deterministic transport chunks."""

    def convert(
        self,
        audio: AsyncIterator[bytes],
        source: AudioFormat,
        target: AudioFormat,
    ) -> AsyncIterator[bytes]:
        return self._convert(audio, source, target)

    async def _convert(
        self,
        audio: AsyncIterator[bytes],
        source: AudioFormat,
        target: AudioFormat,
    ) -> AsyncIterator[bytes]:
        source_pcm = bytearray()
        converted_pcm = bytearray()
        read_error: AudioConversionError | None = None
        close_attempted = False
        try:
            canonical_source = _strict_audio_format(source)
            canonical_target = _strict_audio_format(target)
            if (
                not hasattr(audio, "__aiter__")
                or canonical_source is None
                or not _valid_source_format(canonical_source)
                or canonical_target != TRANSPORT_AUDIO_FORMAT
            ):
                read_error = AudioConversionError()
            else:
                source = canonical_source
                target = canonical_target
                try:
                    async for chunk in audio:
                        _raise_if_cancelling()
                        if type(chunk) is not bytes or not chunk:
                            raise AudioConversionError
                        if len(source_pcm) + len(chunk) > MAX_DIRECTION_BYTES:
                            raise AudioConversionError
                        source_pcm.extend(chunk)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    read_error = AudioConversionError()
            _raise_if_cancelling()
            close_attempted = True
            try:
                await _close(audio)
            except asyncio.CancelledError:
                raise
            except Exception:
                read_error = AudioConversionError()
            except BaseException:
                if _cancellation_pending():
                    raise asyncio.CancelledError from None
                raise
            _raise_if_cancelling()
            if read_error is not None:
                if _cancellation_pending():
                    raise asyncio.CancelledError from None
                raise read_error from None

            source_bytes = len(source_pcm)
            if (
                not source_bytes
                or source_bytes % _PCM16.size
                or source_bytes // _PCM16.size > source.sample_rate_hz * _MAX_MEDIA_SECONDS
            ):
                raise AudioConversionError from None

            source_samples = source_bytes // _PCM16.size
            target_samples = max(
                1,
                (source_samples * target.sample_rate_hz + source.sample_rate_hz // 2)
                // source.sample_rate_hz,
            )
            target_bytes = target_samples * _PCM16.size
            if (
                target_bytes > MAX_DIRECTION_BYTES
                or target_samples > target.sample_rate_hz * _MAX_MEDIA_SECONDS
            ):
                raise AudioConversionError from None

            if source.sample_rate_hz == target.sample_rate_hz:
                converted_pcm.extend(source_pcm)
            else:
                converted_pcm.extend(b"\x00" * target_bytes)
                for target_index in range(target_samples):
                    source_position = target_index * source.sample_rate_hz
                    left_index, fraction = divmod(
                        source_position,
                        target.sample_rate_hz,
                    )
                    if left_index >= source_samples - 1:
                        value = _PCM16.unpack_from(
                            source_pcm,
                            (source_samples - 1) * _PCM16.size,
                        )[0]
                    else:
                        left = _PCM16.unpack_from(
                            source_pcm,
                            left_index * _PCM16.size,
                        )[0]
                        right = _PCM16.unpack_from(
                            source_pcm,
                            (left_index + 1) * _PCM16.size,
                        )[0]
                        weighted = left * (target.sample_rate_hz - fraction) + right * fraction
                        value = _rounded_div(weighted, target.sample_rate_hz)
                    _PCM16.pack_into(converted_pcm, target_index * _PCM16.size, value)
                    if target_index and target_index % 8_192 == 0:
                        await asyncio.sleep(0)

            _wipe(source_pcm)
            for offset in range(0, len(converted_pcm), MAX_TRANSPORT_PCM_FRAME_BYTES):
                yield bytes(converted_pcm[offset : offset + MAX_TRANSPORT_PCM_FRAME_BYTES])
        except asyncio.CancelledError:
            raise
        except AudioConversionError:
            if _cancellation_pending():
                raise asyncio.CancelledError from None
            raise
        except Exception:
            if _cancellation_pending():
                raise asyncio.CancelledError from None
            raise AudioConversionError from None
        finally:
            try:
                if not close_attempted:
                    try:
                        await _close(audio)
                    except (asyncio.CancelledError, Exception):
                        pass
                    except BaseException:
                        if not _cancellation_pending():
                            raise
            finally:
                _wipe(source_pcm)
                _wipe(converted_pcm)
