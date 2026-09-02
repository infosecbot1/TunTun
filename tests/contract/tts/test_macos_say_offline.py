from __future__ import annotations

import asyncio
import wave
from pathlib import Path
from uuid import uuid4

import pytest
from tuntun_contracts.speech import OfflineSynthesisRequest
from tuntun_core.adapters.tts.macos_say import (
    _MAX_PCM_BYTES,
    MacOSSayOfflineTTS,
    _read_bounded_pcm,
    _run_bounded_process,
)


def _write_wav(path, *, sample_rate: int = 24_000, channels: int = 1, width: int = 2) -> None:
    with wave.open(str(path), "wb") as handle:
        handle.setnchannels(channels)
        handle.setsampwidth(width)
        handle.setframerate(sample_rate)
        handle.writeframes(b"\x00\x00" * 32)


def test_offline_synthesis_request_is_frozen_bounded_nfc_contract() -> None:
    request = OfflineSynthesisRequest(
        request_id=uuid4(),
        turn_id=uuid4(),
        text="Hello नमस्ते",
        language="hinglish",
    )
    assert request.text == "Hello नमस्ते"
    with pytest.raises(ValueError, match="offline_tts_text_must_be_bounded_nfc"):
        OfflineSynthesisRequest(
            request_id=uuid4(),
            turn_id=uuid4(),
            text="e\u0301",
            language="en",
        )
    boundary = OfflineSynthesisRequest(
        request_id=uuid4(),
        turn_id=uuid4(),
        text="ठ" * 4_096,
        language="hi",
    )
    assert len(boundary.text) == 4_096


@pytest.mark.asyncio
async def test_macos_adapter_uses_fixed_binaries_no_shell_and_validates_pcm(
    tmp_path,
    monkeypatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    async def fake_run(*args, stdin, timeout):
        del stdin, timeout
        calls.append(tuple(args))
        if args[0] == str(MacOSSayOfflineTTS.AFCONVERT):
            _write_wav(args[-1])

    monkeypatch.setattr("tuntun_core.adapters.tts.macos_say._run_bounded_process", fake_run)
    adapter = MacOSSayOfflineTTS({"en": "Samantha", "hi": "Lekha", "hinglish": "Lekha"})
    request = OfflineSynthesisRequest(
        request_id=uuid4(),
        turn_id=uuid4(),
        text="Hello नमस्ते",
        language="hinglish",
    )

    payload = await adapter.synthesize(request)

    assert payload == b"\x00\x00" * 32
    assert calls[0][0] == "/usr/bin/say"
    assert calls[1][0] == "/usr/bin/afconvert"
    assert not any("/bin/sh" in call for call in calls for call in call)


def test_offline_tts_rejects_wrong_wav_format(tmp_path) -> None:
    path = tmp_path / "wrong.wav"
    _write_wav(path, sample_rate=16_000)

    with pytest.raises(RuntimeError, match="offline_tts_pcm_invalid"):
        _read_bounded_pcm(path)


def test_offline_tts_rejects_oversized_wav_before_unbounded_read(
    tmp_path,
    monkeypatch,
) -> None:
    path = tmp_path / "oversized.wav"
    path.write_bytes(b"x" * (_MAX_PCM_BYTES + 4_097))

    def fail_unbounded_read(_self: Path) -> bytes:
        raise AssertionError("unbounded read_bytes must not be used for oversized wav")

    monkeypatch.setattr(Path, "read_bytes", fail_unbounded_read)

    with pytest.raises(RuntimeError, match="offline_tts_pcm_invalid"):
        _read_bounded_pcm(path)


@pytest.mark.asyncio
async def test_process_cleanup_wait_is_shielded_from_repeated_cancellation(
    monkeypatch,
) -> None:
    wait_started = asyncio.Event()
    release_wait = asyncio.Event()
    wait_completed = False
    kills: list[tuple[int, int]] = []

    class FakeProcess:
        pid = 24_001
        returncode = None

        async def communicate(self, _stdin: bytes):
            raise asyncio.CancelledError

        async def wait(self) -> None:
            nonlocal wait_completed
            wait_started.set()
            await release_wait.wait()
            wait_completed = True

    async def fake_create_subprocess_exec(*_args, **_kwargs):
        return FakeProcess()

    monkeypatch.setattr(
        "tuntun_core.adapters.tts.macos_say.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )
    monkeypatch.setattr(
        "tuntun_core.adapters.tts.macos_say.os.killpg",
        lambda pid, sig: kills.append((pid, sig)),
    )

    task = asyncio.create_task(
        _run_bounded_process("/usr/bin/say", stdin=b"text", timeout=1.0)
    )
    await asyncio.wait_for(wait_started.wait(), timeout=1.0)
    task.cancel()
    await asyncio.sleep(0)
    assert task.done() is False

    release_wait.set()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert wait_completed is True
    assert kills == [(24_001, 9)]
