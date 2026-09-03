from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

import pytest
import yaml
from tuntun_core.domain.offline import OfflineMatch, TimerArguments
from tuntun_core.offline.local_asr import (
    MAX_OFFLINE_ASR_AUDIO_BYTES,
    OFFLINE_ASR_MODEL_IDS,
    OFFLINE_ASR_PURPOSE,
    LocalAsrHypothesis,
    LocalAsrRecognizer,
)
from tuntun_core.services.models.registry import ModelRegistry

TURN_ID = UUID("00000000-0000-4000-8000-000000000201")
MODEL_HASHES = {
    "vosk-small-en-us-0.15": "30f26242c4eb449f948e42cb302dd7a686cb29a3423a8367f99ff41780942498",
    "vosk-small-hi-0.22": "7c50a10866889f0ac21d912c20537a055a597ed09fc1d3e5bcd798f9f0017e48",
}
MODEL_SIZES = {
    "vosk-small-en-us-0.15": 41_205_931,
    "vosk-small-hi-0.22": 44_458_845,
}


@dataclass(slots=True)
class _Activated:
    model_id: str
    hypothesis: LocalAsrHypothesis
    closed: bool = False

    def close(self) -> None:
        self.closed = True


class _Registry:
    def __init__(self, models: dict[str, _Activated]) -> None:
        self.models = models
        self.required: list[tuple[str, str]] = []

    def require_activated(self, model_id: str, purpose: str) -> _Activated:
        self.required.append((model_id, purpose))
        return self.models[model_id]


class _Decoder:
    def __init__(self) -> None:
        self.audio_buffers: list[bytearray] = []

    def __call__(self, model: _Activated, audio: memoryview) -> LocalAsrHypothesis:
        assert audio.readonly is True
        assert isinstance(audio.obj, bytearray)
        self.audio_buffers.append(audio.obj)
        return model.hypothesis


class _FailingDecoder(_Decoder):
    def __init__(self, error: BaseException) -> None:
        super().__init__()
        self.error = error

    def __call__(self, model: _Activated, audio: memoryview) -> LocalAsrHypothesis:
        super().__call__(model, audio)
        raise self.error


async def _chunks(*values: object):
    for value in values:
        yield value


def _registry(
    en: LocalAsrHypothesis | str,
    hi: LocalAsrHypothesis | str,
) -> _Registry:
    en_hypothesis = en if isinstance(en, LocalAsrHypothesis) else LocalAsrHypothesis(en)
    hi_hypothesis = hi if isinstance(hi, LocalAsrHypothesis) else LocalAsrHypothesis(hi)
    return _Registry(
        {
            "vosk-small-en-us-0.15": _Activated("vosk-small-en-us-0.15", en_hypothesis),
            "vosk-small-hi-0.22": _Activated("vosk-small-hi-0.22", hi_hypothesis),
        }
    )


def _assert_zeroized(buffers: list[bytearray]) -> None:
    assert buffers
    assert all(set(buffer) <= {0} for buffer in buffers)


@pytest.mark.asyncio
async def test_asr_requires_both_governed_local_models_and_accepts_one_clear_match() -> None:
    registry = _registry("stop", "synthetic unrecognized speech")
    decoder = _Decoder()
    recognizer = LocalAsrRecognizer(registry, decoder)

    match = await recognizer.recognize(TURN_ID, _chunks(b"\x00\x01" * 800))

    assert match == OfflineMatch(intent="stop", confidence_micros=1_000_000)
    assert registry.required == [
        ("vosk-small-en-us-0.15", "offline_command"),
        ("vosk-small-hi-0.22", "offline_command"),
    ]
    assert tuple(item.model_id for item in registry.models.values()) == OFFLINE_ASR_MODEL_IDS
    assert OFFLINE_ASR_PURPOSE == "offline_command"
    assert all(model.closed for model in registry.models.values())
    _assert_zeroized(decoder.audio_buffers)


@pytest.mark.asyncio
async def test_asr_rejects_conflicting_commands_and_timer_payloads() -> None:
    command_conflict = _registry("stop", "privacy on")
    command_match = await LocalAsrRecognizer(command_conflict, _Decoder()).recognize(
        TURN_ID,
        _chunks(b"\x00\x01" * 800),
    )
    assert command_match == OfflineMatch(intent="no_match", confidence_micros=0)

    timer_conflict = _registry("set a timer for 1 minute", "2 मिनट का टाइमर लगाओ")
    timer_match = await LocalAsrRecognizer(timer_conflict, _Decoder()).recognize(
        TURN_ID,
        _chunks(b"\x00\x01" * 800),
    )
    assert timer_match == OfflineMatch(intent="no_match", confidence_micros=0)


@pytest.mark.asyncio
async def test_asr_rejects_low_confidence_and_no_match_without_guessing() -> None:
    registry = _registry(
        LocalAsrHypothesis("stop", confidence_micros=499_999),
        LocalAsrHypothesis("synthetic unrecognized speech", confidence_micros=1_000_000),
    )

    match = await LocalAsrRecognizer(registry, _Decoder()).recognize(
        TURN_ID,
        _chunks(b"\x00\x01" * 800),
    )

    assert match == OfflineMatch(intent="no_match", confidence_micros=0)


@pytest.mark.asyncio
async def test_asr_accepts_identical_timer_payloads_from_both_models() -> None:
    registry = _registry("set a timer for 2 minutes", "2 minute ka timer lagao")

    match = await LocalAsrRecognizer(registry, _Decoder()).recognize(
        TURN_ID,
        _chunks(b"\x00\x01" * 800),
    )

    assert match == OfflineMatch(
        intent="timer_create",
        confidence_micros=1_000_000,
        timer=TimerArguments(duration_seconds=120),
    )


@pytest.mark.asyncio
async def test_asr_rejects_invalid_audio_before_model_activation() -> None:
    for bad_audio in (
        _chunks(b""),
        _chunks(bytearray(b"\x00\x01")),
        _chunks(b"\x00"),
        _chunks(b"\x00\x01" * 32_769),
        _chunks(b"\x00\x01" * (MAX_OFFLINE_ASR_AUDIO_BYTES // 2), b"\x00\x01"),
    ):
        registry = _registry("stop", "stop")
        with pytest.raises((TypeError, ValueError), match="offline_asr_audio"):
            await LocalAsrRecognizer(registry, _Decoder()).recognize(TURN_ID, bad_audio)

        assert registry.required == []
        assert not any(model.closed for model in registry.models.values())


@pytest.mark.asyncio
async def test_asr_bounds_pcm16_audio_and_chunk_types() -> None:
    for bad_audio in (
        _chunks(b""),
        _chunks(bytearray(b"\x00\x01")),
        _chunks(b"\x00"),
        _chunks(b"\x00\x01" * 32_769),
        _chunks(b"\x00\x01" * (MAX_OFFLINE_ASR_AUDIO_BYTES // 2), b"\x00\x01"),
    ):
        registry = _registry("stop", "stop")
        with pytest.raises((TypeError, ValueError), match="offline_asr_audio"):
            await LocalAsrRecognizer(registry, _Decoder()).recognize(TURN_ID, bad_audio)
        assert registry.required == []


@pytest.mark.asyncio
async def test_asr_zeroizes_and_closes_models_when_decode_fails_or_is_cancelled(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sentinel = b"private-audio-sentinel"
    for error in (RuntimeError("decode failed"), asyncio.CancelledError()):
        registry = _registry("stop", "stop")
        decoder = _FailingDecoder(error)
        recognizer = LocalAsrRecognizer(registry, decoder)
        with pytest.raises(type(error), match=str(error) if str(error) else None):
            await recognizer.recognize(TURN_ID, _chunks(sentinel, b"\x00\x00"))
        _assert_zeroized(decoder.audio_buffers)
        assert all(model.closed for model in registry.models.values())
        assert sentinel.decode("ascii") not in caplog.text


@pytest.mark.asyncio
async def test_asr_closes_partial_activation_when_second_model_fails() -> None:
    class FailingSecondRegistry(_Registry):
        def require_activated(self, model_id: str, purpose: str) -> _Activated:
            self.required.append((model_id, purpose))
            if model_id == "vosk-small-hi-0.22":
                raise RuntimeError("activation failed")
            return self.models[model_id]

    registry = FailingSecondRegistry(_registry("stop", "stop").models)

    with pytest.raises(RuntimeError, match="activation failed"):
        await LocalAsrRecognizer(registry, _Decoder()).recognize(
            TURN_ID,
            _chunks(b"\x00\x01" * 800),
        )

    assert registry.required == [
        ("vosk-small-en-us-0.15", "offline_command"),
        ("vosk-small-hi-0.22", "offline_command"),
    ]
    assert registry.models["vosk-small-en-us-0.15"].closed is True


def _offline_model_entry(model_id: str) -> dict[str, object]:
    file_name = f"vosk-model-{model_id.removeprefix('vosk-')}.zip"
    return {
        "id": model_id,
        "revision": MODEL_HASHES[model_id],
        "license": "Apache-2.0",
        "provenance": "Alphacep Vosk small model list, reviewed for local command use",
        "redistribution": "external governed model archive; not bundled in source or wheel",
        "approved_purpose": "offline_command",
        "runtime": "vosk==0.3.44",
        "runtime_max_bytes": 384_000_000 if model_id.endswith("hi-0.22") else 256_000_000,
        "architecture": "Vosk/Kaldi small-model ZIP archive",
        "input_contract": "PCM16 mono post-wake audio at 16000 Hz, bounded to 8388608 bytes",
        "output_contract": "bounded hypothesis text parsed only by tuntun_core.offline.grammar",
        "benchmark_gate": "tests/unit/offline/test_local_asr.py",
        "review_date": "2026-09-03",
        "files": [
            {
                "path": file_name,
                "size": MODEL_SIZES[model_id],
                "sha256": MODEL_HASHES[model_id],
                "url": f"https://alphacephei.com/vosk/models/{file_name}",
            }
        ],
    }


def test_model_registry_requires_exact_approved_purpose_before_activation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    activated = object()
    calls: list[str] = []
    registry = ModelRegistry.from_document(
        {
            "schema_version": "1.0",
            "models": [_offline_model_entry("vosk-small-en-us-0.15")],
        }
    )

    def fake_activate(self: ModelRegistry, model_id: str) -> object:
        calls.append(model_id)
        return activated

    monkeypatch.setattr(ModelRegistry, "activate", fake_activate)

    assert registry.require_activated("vosk-small-en-us-0.15", "offline_command") is activated
    with pytest.raises(PermissionError, match="model purpose mismatch"):
        registry.require_activated("vosk-small-en-us-0.15", "cloud_tts")
    assert calls == ["vosk-small-en-us-0.15"]


def test_offline_vosk_archive_manifest_rejects_zip_plus_extra_file() -> None:
    entry = _offline_model_entry("vosk-small-en-us-0.15")
    entry["files"].append(  # type: ignore[union-attr]
        {
            "path": "metadata.json",
            "size": 2,
            "sha256": "0" * 64,
            "url": "https://alphacephei.com/vosk/models/metadata.json",
        }
    )

    with pytest.raises(ValueError, match="invalid model manifest"):
        ModelRegistry.from_document({"schema_version": "1.0", "models": [entry]})


def test_offline_vosk_archive_manifest_requires_exact_runtime_bound() -> None:
    entry = _offline_model_entry("vosk-small-en-us-0.15")
    entry["runtime_max_bytes"] = 384_000_000

    with pytest.raises(ValueError, match="invalid model manifest"):
        ModelRegistry.from_document({"schema_version": "1.0", "models": [entry]})


def test_repository_manifest_registers_exact_offline_vosk_models() -> None:
    document = yaml.safe_load(Path("models/manifest.yaml").read_text(encoding="utf-8"))
    registry = ModelRegistry.from_document(document)
    models = {entry.model_id: entry for entry in registry.models}

    assert set(OFFLINE_ASR_MODEL_IDS) <= set(models)
    for model_id in OFFLINE_ASR_MODEL_IDS:
        entry = models[model_id]
        file = entry.files[0]
        assert entry.approved_purpose == "offline_command"
        assert entry.runtime == "vosk==0.3.44"
        assert entry.license == "Apache-2.0"
        assert entry.runtime_max_bytes == _offline_model_entry(model_id)["runtime_max_bytes"]
        assert entry.revision == MODEL_HASHES[model_id]
        assert file.path == f"vosk-model-{model_id.removeprefix('vosk-')}.zip"
        assert file.size == MODEL_SIZES[model_id]
        assert file.sha256 == MODEL_HASHES[model_id]
        assert file.url == f"https://alphacephei.com/vosk/models/{file.path}"

    assert (
        Path("apps/core/src/tuntun_core/resources/model-manifest.yaml").read_bytes()
        == Path("models/manifest.yaml").read_bytes()
    )
