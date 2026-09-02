from __future__ import annotations

import asyncio
import os
import signal
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path

from tuntun_contracts.speech import OfflineSynthesisRequest

_MAX_PCM_BYTES = 8_388_608
_PROCESS_TIMEOUT_SECONDS = 5.0


class MacOSSayOfflineTTS:
    SAY = Path("/usr/bin/say")
    AFCONVERT = Path("/usr/bin/afconvert")

    def __init__(self, voices: Mapping[str, str]) -> None:
        if set(voices) != {"en", "hi", "hinglish"}:
            raise ValueError("offline_tts_voice_allowlist_incomplete")
        self._voices = {language: _safe_voice_name(voice) for language, voice in voices.items()}

    async def synthesize(self, request: OfflineSynthesisRequest) -> bytes:
        if type(request) is not OfflineSynthesisRequest:
            raise TypeError("request must be an exact OfflineSynthesisRequest")
        voice = self._voices[request.language]
        with tempfile.TemporaryDirectory(prefix="tuntun-offline-tts-") as directory:
            root = Path(directory)
            aiff = root / "speech.aiff"
            wav = root / "speech.wav"
            await _run_bounded_process(
                str(self.SAY),
                "-v",
                voice,
                "-o",
                str(aiff),
                "-f",
                "-",
                stdin=request.text.encode("utf-8"),
                timeout=_PROCESS_TIMEOUT_SECONDS,
            )
            await _run_bounded_process(
                str(self.AFCONVERT),
                "-f",
                "WAVE",
                "-d",
                "LEI16@24000",
                "-c",
                "1",
                str(aiff),
                str(wav),
                stdin=b"",
                timeout=_PROCESS_TIMEOUT_SECONDS,
            )
            return _read_bounded_pcm(wav)


async def _run_bounded_process(*args: str, stdin: bytes, timeout: float) -> None:
    if not args or any(type(arg) is not str or "\x00" in arg for arg in args):
        raise ValueError("offline_tts_process_argv_invalid")
    process = await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    try:
        _stdout, stderr = await asyncio.wait_for(process.communicate(stdin), timeout=timeout)
    except (TimeoutError, asyncio.CancelledError):
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        await process.wait()
        raise
    if process.returncode != 0:
        del stderr
        raise RuntimeError("offline_tts_process_failed")


def _read_bounded_pcm(path: Path) -> bytes:
    raw = path.read_bytes()
    if len(raw) < 44 or len(raw) > _MAX_PCM_BYTES + 4_096:
        raise RuntimeError("offline_tts_pcm_invalid")
    if raw[:4] != b"RIFF" or raw[8:12] != b"WAVE":
        raise RuntimeError("offline_tts_pcm_invalid")
    offset = 12
    fmt: tuple[int, int, int, int, int, int] | None = None
    data: bytes | None = None
    while offset + 8 <= len(raw):
        chunk_id = raw[offset : offset + 4]
        chunk_size = int.from_bytes(raw[offset + 4 : offset + 8], "little")
        start = offset + 8
        end = start + chunk_size
        if end > len(raw):
            raise RuntimeError("offline_tts_pcm_invalid")
        chunk = raw[start:end]
        if chunk_id == b"fmt ":
            if len(chunk) < 16:
                raise RuntimeError("offline_tts_pcm_invalid")
            fmt = (
                int.from_bytes(chunk[0:2], "little"),
                int.from_bytes(chunk[2:4], "little"),
                int.from_bytes(chunk[4:8], "little"),
                int.from_bytes(chunk[8:12], "little"),
                int.from_bytes(chunk[12:14], "little"),
                int.from_bytes(chunk[14:16], "little"),
            )
        elif chunk_id == b"data":
            data = bytes(chunk)
        offset = end + (chunk_size % 2)
    if fmt != (1, 1, 24_000, 48_000, 2, 16):
        raise RuntimeError("offline_tts_pcm_invalid")
    if data is None or len(data) == 0 or len(data) > _MAX_PCM_BYTES or len(data) % 2:
        raise RuntimeError("offline_tts_pcm_invalid")
    return data


def _safe_voice_name(value: str) -> str:
    if type(value) is not str or not 1 <= len(value) <= 64 or "/" in value or "\x00" in value:
        raise ValueError("offline_tts_voice_invalid")
    return value
