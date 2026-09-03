from __future__ import annotations

import hashlib
import json
import wave
from pathlib import Path
from uuid import UUID

import pytest
from tuntun_core.adapters.local_audio.player import (
    FixedPromptManifest,
    FixedPromptPlayer,
    PlaybackReceipt,
)
from tuntun_core.offline.prompts import (
    PROMPT_CATALOG_VERSION,
    PromptCatalogError,
    prompt_catalog_sha256,
    prompt_text,
)

ASSET_ROOT = Path("assets/offline-prompts")
TURN_ID = UUID("00000000-0000-4000-8000-000000000301")


def _write_prompt_tree(root: Path) -> Path:
    from scripts.build_offline_tones import build_manifest_document, tone_bytes

    root.mkdir()
    (root / "confirm.wav").write_bytes(tone_bytes("confirm"))
    (root / "unavailable.wav").write_bytes(tone_bytes("unavailable"))
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(build_manifest_document()), encoding="utf-8")
    return manifest_path


def test_guest_disclosures_are_separate_versioned_and_fixed() -> None:
    assert PROMPT_CATALOG_VERSION == "guest-1"
    assert (
        prompt_text("guest_cloud_stt", "hi", "guest-1")
        == "आपकी आवाज़ क्लाउड स्पीच सेवा को भेजी जाएगी। हाँ या नहीं?"
    )
    assert (
        prompt_text("guest_cloud_tts", "en", "guest-1")
        == "Answer text will be sent to an AI voice generation service. Yes or no?"
    )
    assert prompt_text("guest_cloud_reasoning", "en", "guest-1") != prompt_text(
        "guest_cloud_tts",
        "en",
        "guest-1",
    )
    assert prompt_text("guest_cloud_stt", "hinglish", "guest-1").endswith("Haan ya nahin?")
    with pytest.raises(PromptCatalogError, match="offline_prompt_unknown"):
        prompt_text("guest_cloud_stt", "en", "guest-2")
    with pytest.raises(PromptCatalogError, match="offline_prompt_unknown"):
        prompt_text("guest_cloud_stt", "fr", "guest-1")


def test_prompt_catalog_digest_is_stable_and_content_addressed() -> None:
    assert (
        prompt_catalog_sha256()
        == hashlib.sha256(
            json.dumps(
                {
                    "version": PROMPT_CATALOG_VERSION,
                    "prompts": [
                        {
                            "id": "guest_cloud_reasoning",
                            "language": "en",
                            "text": "Sanitized text will be sent to cloud reasoning. Yes or no?",
                            "version": "guest-1",
                        },
                        {
                            "id": "guest_cloud_reasoning",
                            "language": "hi",
                            "text": "पहचान हटाया हुआ टेक्स्ट क्लाउड रीजनिंग सेवा को भेजा जाएगा। हाँ या नहीं?",
                            "version": "guest-1",
                        },
                        {
                            "id": "guest_cloud_reasoning",
                            "language": "hinglish",
                            "text": (
                                "Sanitized text cloud reasoning service ko bheja jayega. "
                                "Haan ya nahin?"
                            ),
                            "version": "guest-1",
                        },
                        {
                            "id": "guest_cloud_stt",
                            "language": "en",
                            "text": (
                                "Your voice will be sent to cloud speech recognition. Yes or no?"
                            ),
                            "version": "guest-1",
                        },
                        {
                            "id": "guest_cloud_stt",
                            "language": "hi",
                            "text": "आपकी आवाज़ क्लाउड स्पीच सेवा को भेजी जाएगी। हाँ या नहीं?",
                            "version": "guest-1",
                        },
                        {
                            "id": "guest_cloud_stt",
                            "language": "hinglish",
                            "text": (
                                "Aapki awaaz cloud speech service ko bheji jayegi. Haan ya nahin?"
                            ),
                            "version": "guest-1",
                        },
                        {
                            "id": "guest_cloud_tts",
                            "language": "en",
                            "text": (
                                "Answer text will be sent to an AI voice generation service. "
                                "Yes or no?"
                            ),
                            "version": "guest-1",
                        },
                        {
                            "id": "guest_cloud_tts",
                            "language": "hi",
                            "text": "जवाब का टेक्स्ट एआई आवाज़ बनाने की सेवा को भेजा जाएगा। हाँ या नहीं?",
                            "version": "guest-1",
                        },
                        {
                            "id": "guest_cloud_tts",
                            "language": "hinglish",
                            "text": (
                                "Answer text AI voice generation service ko bheja jayega. "
                                "Haan ya nahin?"
                            ),
                            "version": "guest-1",
                        },
                    ],
                },
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
    )


def test_committed_tone_manifest_verifies_hash_format_license_and_audio_bounds() -> None:
    from scripts.build_offline_tones import build_manifest_document, tone_bytes

    manifest = FixedPromptManifest.load(ASSET_ROOT / "manifest.json")

    assert manifest.ids == ("confirm", "unavailable")
    assert json.loads((ASSET_ROOT / "manifest.json").read_text(encoding="utf-8")) == (
        build_manifest_document()
    )
    for asset in manifest.assets:
        assert asset.license == "CC0-1.0"
        assert asset.path == (ASSET_ROOT / f"{asset.prompt_id}.wav").resolve()
        assert asset.sha256 == hashlib.sha256(asset.path.read_bytes()).hexdigest()
        assert asset.size_bytes == len(tone_bytes(asset.prompt_id))
        assert asset.path.read_bytes() == tone_bytes(asset.prompt_id)
        with wave.open(str(asset.path), "rb") as audio:
            assert audio.getnchannels() == 1
            assert audio.getsampwidth() == 2
            assert audio.getframerate() == 24_000
            assert audio.getnframes() <= 24_000


def test_prompt_manifest_rejects_path_traversal_hash_drift_and_unknown_assets(
    tmp_path: Path,
) -> None:
    from scripts.build_offline_tones import build_manifest_document, tone_bytes

    manifest_doc = build_manifest_document()
    root = tmp_path / "offline-prompts"
    root.mkdir()
    (root / "confirm.wav").write_bytes(tone_bytes("confirm"))
    (root / "unavailable.wav").write_bytes(tone_bytes("unavailable"))
    manifest_path = root / "manifest.json"

    escaped = json.loads(json.dumps(manifest_doc))
    escaped["assets"][0]["path"] = "../confirm.wav"
    manifest_path.write_text(json.dumps(escaped), encoding="utf-8")
    with pytest.raises(ValueError, match="offline prompt manifest invalid"):
        FixedPromptManifest.load(manifest_path)

    drifted = json.loads(json.dumps(manifest_doc))
    drifted["assets"][0]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(drifted), encoding="utf-8")
    with pytest.raises(ValueError, match="offline prompt manifest invalid"):
        FixedPromptManifest.load(manifest_path)

    manifest_path.write_text(json.dumps(manifest_doc), encoding="utf-8")
    manifest = FixedPromptManifest.load(manifest_path)
    with pytest.raises(ValueError, match="offline prompt asset unknown"):
        manifest.require("missing")


def test_prompt_manifest_rejects_symlink_assets_and_oversized_manifest(
    tmp_path: Path,
) -> None:
    from scripts.build_offline_tones import build_manifest_document, tone_bytes

    root = tmp_path / "offline-prompts"
    root.mkdir()
    actual_confirm = root / "actual-confirm.wav"
    actual_confirm.write_bytes(tone_bytes("confirm"))
    (root / "confirm.wav").symlink_to(actual_confirm)
    (root / "unavailable.wav").write_bytes(tone_bytes("unavailable"))
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(build_manifest_document()), encoding="utf-8")

    with pytest.raises(ValueError, match="offline prompt manifest invalid"):
        FixedPromptManifest.load(manifest_path)

    root = tmp_path / "large-offline-prompts"
    manifest_path = _write_prompt_tree(root)
    manifest_path.write_text(
        json.dumps(build_manifest_document()) + (" " * 65_536),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="offline prompt manifest invalid"):
        FixedPromptManifest.load(manifest_path)


@pytest.mark.asyncio
async def test_fixed_prompt_player_verifies_receipt_binding() -> None:
    class ReachySink:
        def __init__(self) -> None:
            self.calls: list[tuple[UUID, str, bytes, str]] = []

        async def play_fixed_asset(
            self,
            turn_id: UUID,
            prompt_id: str,
            audio: bytes,
            sha256: str,
        ) -> PlaybackReceipt:
            self.calls.append((turn_id, prompt_id, audio, sha256))
            assert hashlib.sha256(audio).hexdigest() == sha256
            return PlaybackReceipt(
                turn_id=turn_id,
                prompt_id=prompt_id,
                asset_sha256=sha256,
                accepted=True,
                reason_code="accepted",
            )

    sink = ReachySink()
    manifest = FixedPromptManifest.load(ASSET_ROOT / "manifest.json")
    receipt = await FixedPromptPlayer(sink, manifest).play("confirm", TURN_ID)

    assert receipt.accepted is True
    assert sink.calls == [
        (TURN_ID, "confirm", (ASSET_ROOT / "confirm.wav").read_bytes(), receipt.asset_sha256)
    ]

    class DriftedSink(ReachySink):
        async def play_fixed_asset(
            self,
            turn_id: UUID,
            prompt_id: str,
            audio: bytes,
            sha256: str,
        ) -> PlaybackReceipt:
            del audio, sha256
            return PlaybackReceipt(
                turn_id=turn_id,
                prompt_id=prompt_id,
                asset_sha256="0" * 64,
                accepted=True,
                reason_code="accepted",
            )

    with pytest.raises(RuntimeError, match="offline_prompt_receipt_mismatch"):
        await FixedPromptPlayer(DriftedSink(), manifest).play("confirm", TURN_ID)


@pytest.mark.asyncio
async def test_fixed_prompt_player_revalidates_asset_bytes_at_playback(
    tmp_path: Path,
) -> None:
    from scripts.build_offline_tones import tone_bytes

    class Sink:
        def __init__(self) -> None:
            self.calls = 0

        async def play_fixed_asset(
            self,
            turn_id: UUID,
            prompt_id: str,
            audio: bytes,
            sha256: str,
        ) -> PlaybackReceipt:
            self.calls += 1
            return PlaybackReceipt(
                turn_id=turn_id,
                prompt_id=prompt_id,
                asset_sha256=sha256,
                accepted=True,
                reason_code="accepted",
            )

    manifest_path = _write_prompt_tree(tmp_path / "offline-prompts")
    manifest = FixedPromptManifest.load(manifest_path)
    (manifest_path.parent / "confirm.wav").write_bytes(tone_bytes("unavailable"))
    sink = Sink()

    with pytest.raises(RuntimeError, match="offline_prompt_asset_changed"):
        await FixedPromptPlayer(sink, manifest).play("confirm", TURN_ID)
    assert sink.calls == 0
