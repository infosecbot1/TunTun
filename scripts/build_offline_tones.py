from __future__ import annotations

import hashlib
import io
import json
import struct
import wave
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

ASSET_ROOT = Path("assets/offline-prompts")
SAMPLE_RATE_HZ = 24_000
CHANNELS = 1
SAMPLE_WIDTH_BYTES = 2
DURATION_MS = 250
AMPLITUDE = 7_200
SCHEMA_VERSION = "tuntun.offline-prompts.v1"
LICENSE = "CC0-1.0"
FORMAT = "wav-pcm16-mono"


@dataclass(frozen=True, slots=True)
class ToneSpec:
    prompt_id: str
    frequency_hz: int


TONE_SPECS: Mapping[str, ToneSpec] = {
    "confirm": ToneSpec("confirm", 660),
    "unavailable": ToneSpec("unavailable", 220),
}


def tone_bytes(prompt_id: str) -> bytes:
    try:
        spec = TONE_SPECS[prompt_id]
    except KeyError as error:
        raise ValueError("unknown offline tone") from error
    frame_count = SAMPLE_RATE_HZ * DURATION_MS // 1000
    frames = bytearray()
    for index in range(frame_count):
        phase = index * spec.frequency_hz * 2 // SAMPLE_RATE_HZ
        sample = AMPLITUDE if phase % 2 == 0 else -AMPLITUDE
        frames.extend(struct.pack("<h", sample))
    output = io.BytesIO()
    with wave.open(output, "wb") as audio:
        audio.setnchannels(CHANNELS)
        audio.setsampwidth(SAMPLE_WIDTH_BYTES)
        audio.setframerate(SAMPLE_RATE_HZ)
        audio.writeframes(bytes(frames))
    return output.getvalue()


def build_manifest_document() -> dict[str, object]:
    assets = []
    for prompt_id in TONE_SPECS:
        payload = tone_bytes(prompt_id)
        assets.append(
            {
                "id": prompt_id,
                "path": f"{prompt_id}.wav",
                "sha256": hashlib.sha256(payload).hexdigest(),
                "license": LICENSE,
                "format": FORMAT,
                "sample_rate_hz": SAMPLE_RATE_HZ,
                "channels": CHANNELS,
                "duration_ms": DURATION_MS,
                "size_bytes": len(payload),
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "version": 1,
        "generated_by": "scripts/build_offline_tones.py",
        "assets": assets,
    }


def build_offline_tones(root: Path = Path(".")) -> None:
    asset_root = root / ASSET_ROOT
    asset_root.mkdir(parents=True, exist_ok=True)
    for prompt_id in TONE_SPECS:
        (asset_root / f"{prompt_id}.wav").write_bytes(tone_bytes(prompt_id))
    manifest = build_manifest_document()
    (asset_root / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    build_offline_tones()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
