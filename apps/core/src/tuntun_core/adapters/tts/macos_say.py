from __future__ import annotations

import asyncio
import os
import signal
import stat
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any

from tuntun_contracts.speech import OfflineSynthesisRequest

_MAX_PCM_BYTES = 8_388_608
_MAX_WAV_CONTAINER_OVERHEAD_BYTES = 4_096
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
    except TimeoutError:
        await _kill_process_group_and_wait(process)
        raise
    except asyncio.CancelledError:
        await _kill_process_group_and_wait(process)
        raise
    if process.returncode != 0:
        del stderr
        raise RuntimeError("offline_tts_process_failed")


async def _kill_process_group_and_wait(process: Any) -> None:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    wait_task = asyncio.create_task(process.wait(), name="offline-tts-process-wait")
    while not wait_task.done():
        try:
            await asyncio.shield(wait_task)
        except asyncio.CancelledError:
            continue
    wait_task.result()


def _read_bounded_pcm(path: Path) -> bytes:
    raw = _read_bounded_regular_file(path)
    if len(raw) < 44 or len(raw) > _MAX_PCM_BYTES + _MAX_WAV_CONTAINER_OVERHEAD_BYTES:
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
    if len(raw) - len(data) > _MAX_WAV_CONTAINER_OVERHEAD_BYTES:
        raise RuntimeError("offline_tts_pcm_invalid")
    return data


def _read_bounded_regular_file(path: Path) -> bytes:
    max_bytes = _MAX_PCM_BYTES + _MAX_WAV_CONTAINER_OVERHEAD_BYTES
    try:
        initial = path.stat(follow_symlinks=False)
    except OSError as error:
        raise RuntimeError("offline_tts_pcm_invalid") from error
    if (
        not stat.S_ISREG(initial.st_mode)
        or initial.st_size < 44
        or initial.st_size > max_bytes
    ):
        raise RuntimeError("offline_tts_pcm_invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise RuntimeError("offline_tts_pcm_invalid") from error
    try:
        current = os.fstat(fd)
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_size != initial.st_size
            or current.st_size > max_bytes
            or current.st_dev != initial.st_dev
            or current.st_ino != initial.st_ino
        ):
            raise RuntimeError("offline_tts_pcm_invalid")
        chunks: list[bytes] = []
        total = 0
        while total < current.st_size:
            chunk = os.read(fd, min(65_536, current.st_size - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        final = os.fstat(fd)
        if final.st_size != current.st_size or total != current.st_size:
            raise RuntimeError("offline_tts_pcm_invalid")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _safe_voice_name(value: str) -> str:
    if type(value) is not str or not 1 <= len(value) <= 64 or "/" in value or "\x00" in value:
        raise ValueError("offline_tts_voice_invalid")
    return value
