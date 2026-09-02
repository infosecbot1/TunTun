from __future__ import annotations

import wave
from uuid import uuid4

import pytest
from tuntun_contracts.speech import OfflineSynthesisRequest
from tuntun_core.adapters.tts.macos_say import MacOSSayOfflineTTS, _read_bounded_pcm


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
