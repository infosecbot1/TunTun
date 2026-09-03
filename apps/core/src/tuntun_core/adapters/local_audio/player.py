from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import wave
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

_ASSET_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SCHEMA_VERSION = "tuntun.offline-prompts.v1"
_LICENSE = "CC0-1.0"
_FORMAT = "wav-pcm16-mono"
_SAMPLE_RATE_HZ = 24_000
_CHANNELS = 1
_SAMPLE_WIDTH_BYTES = 2
_MAX_DURATION_MS = 1_000
_MAX_SIZE_BYTES = 65_536
_MAX_MANIFEST_BYTES = 8_192


@dataclass(frozen=True, slots=True)
class FixedPromptAsset:
    prompt_id: str
    path: Path
    sha256: str
    license: str
    format: str
    sample_rate_hz: int
    channels: int
    duration_ms: int
    size_bytes: int

    def __post_init__(self) -> None:
        if (
            type(self.prompt_id) is not str
            or _ASSET_ID.fullmatch(self.prompt_id) is None
            or not isinstance(self.path, Path)
            or type(self.sha256) is not str
            or _DIGEST.fullmatch(self.sha256) is None
            or self.license != _LICENSE
            or self.format != _FORMAT
            or self.sample_rate_hz != _SAMPLE_RATE_HZ
            or self.channels != _CHANNELS
            or type(self.duration_ms) is not int
            or not 1 <= self.duration_ms <= _MAX_DURATION_MS
            or type(self.size_bytes) is not int
            or not 1 <= self.size_bytes <= _MAX_SIZE_BYTES
        ):
            raise ValueError("offline prompt manifest invalid")


class FixedPromptManifest:
    __slots__ = ("_assets",)

    def __init__(self, assets: tuple[FixedPromptAsset, ...]) -> None:
        if not assets or len({item.prompt_id for item in assets}) != len(assets):
            raise ValueError("offline prompt manifest invalid")
        self._assets = assets

    @classmethod
    def load(cls, manifest_path: Path) -> FixedPromptManifest:
        if not isinstance(manifest_path, Path):
            raise TypeError("offline prompt manifest path invalid")
        try:
            root = manifest_path.parent.resolve(strict=True)
            manifest_payload = _read_regular_no_follow(
                manifest_path,
                expected_size=None,
                byte_limit=_MAX_MANIFEST_BYTES,
            )
            raw = json.loads(manifest_payload.decode("utf-8"))
            assets = tuple(_asset_from_document(root, item) for item in _raw_assets(raw))
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            raise ValueError("offline prompt manifest invalid") from error
        return cls(assets)

    @property
    def assets(self) -> tuple[FixedPromptAsset, ...]:
        return self._assets

    @property
    def ids(self) -> tuple[str, ...]:
        return tuple(item.prompt_id for item in self._assets)

    def require(self, prompt_id: str) -> FixedPromptAsset:
        if type(prompt_id) is not str or _ASSET_ID.fullmatch(prompt_id) is None:
            raise ValueError("offline prompt asset unknown")
        for asset in self._assets:
            if asset.prompt_id == prompt_id:
                return asset
        raise ValueError("offline prompt asset unknown")


@dataclass(frozen=True, slots=True)
class PlaybackReceipt:
    turn_id: UUID
    prompt_id: str
    asset_sha256: str
    accepted: bool
    reason_code: str

    def __post_init__(self) -> None:
        if (
            type(self.turn_id) is not UUID
            or type(self.prompt_id) is not str
            or _ASSET_ID.fullmatch(self.prompt_id) is None
            or type(self.asset_sha256) is not str
            or _DIGEST.fullmatch(self.asset_sha256) is None
            or type(self.accepted) is not bool
            or type(self.reason_code) is not str
            or not self.reason_code
            or len(self.reason_code) > 64
        ):
            raise ValueError("offline prompt playback receipt invalid")


class FixedPromptSink(Protocol):
    async def play_fixed_asset(
        self,
        turn_id: UUID,
        prompt_id: str,
        audio: bytes,
        sha256: str,
    ) -> PlaybackReceipt: ...


class FixedPromptPlayer:
    __slots__ = ("_manifest", "_sink")

    def __init__(self, sink: FixedPromptSink, manifest: FixedPromptManifest) -> None:
        if type(manifest) is not FixedPromptManifest:
            raise TypeError("offline prompt manifest invalid")
        self._sink = sink
        self._manifest = manifest

    async def play(self, prompt_id: str, turn_id: UUID) -> PlaybackReceipt:
        if type(turn_id) is not UUID:
            raise TypeError("turn_id must be an exact UUID")
        asset = self._manifest.require(prompt_id)
        try:
            audio = _verified_asset_payload(asset)
        except (OSError, ValueError) as error:
            raise RuntimeError("offline_prompt_asset_changed") from error
        receipt = await self._sink.play_fixed_asset(
            turn_id,
            asset.prompt_id,
            audio,
            asset.sha256,
        )
        if (
            type(receipt) is not PlaybackReceipt
            or receipt.turn_id != turn_id
            or receipt.prompt_id != asset.prompt_id
            or receipt.asset_sha256 != asset.sha256
        ):
            raise RuntimeError("offline_prompt_receipt_mismatch")
        if not receipt.accepted:
            raise RuntimeError("offline_prompt_playback_rejected")
        return receipt


def _raw_assets(raw: object) -> tuple[Mapping[str, object], ...]:
    if not isinstance(raw, dict) or set(raw) != {
        "schema_version",
        "version",
        "generated_by",
        "assets",
    }:
        raise ValueError("offline prompt manifest invalid")
    if (
        raw["schema_version"] != _SCHEMA_VERSION
        or raw["version"] != 1
        or raw["generated_by"] != "scripts/build_offline_tones.py"
        or not isinstance(raw["assets"], list)
        or not 1 <= len(raw["assets"]) <= 16
    ):
        raise ValueError("offline prompt manifest invalid")
    assets = tuple(raw["assets"])
    if any(not isinstance(item, dict) for item in assets):
        raise ValueError("offline prompt manifest invalid")
    return assets


def _asset_from_document(root: Path, raw: Mapping[str, object]) -> FixedPromptAsset:
    expected_keys = {
        "id",
        "path",
        "sha256",
        "license",
        "format",
        "sample_rate_hz",
        "channels",
        "duration_ms",
        "size_bytes",
    }
    if set(raw) != expected_keys:
        raise ValueError("offline prompt manifest invalid")
    prompt_id = _exact_string(raw["id"])
    relative_path = _exact_string(raw["path"])
    if (
        _ASSET_ID.fullmatch(prompt_id) is None
        or Path(relative_path).name != relative_path
        or Path(relative_path).suffix != ".wav"
        or relative_path != f"{prompt_id}.wav"
    ):
        raise ValueError("offline prompt manifest invalid")
    path = root / relative_path
    if path.parent != root:
        raise ValueError("offline prompt manifest invalid")
    actual = _read_regular_no_follow(
        path,
        expected_size=_exact_int(raw["size_bytes"]),
        byte_limit=_MAX_SIZE_BYTES,
    )
    if hashlib.sha256(actual).hexdigest() != _exact_string(raw["sha256"]):
        raise ValueError("offline prompt manifest invalid")
    _verify_wave_bytes(
        actual,
        duration_ms=_exact_int(raw["duration_ms"]),
        size_bytes=_exact_int(raw["size_bytes"]),
    )
    resolved = path.resolve(strict=True)
    if resolved.parent != root:
        raise ValueError("offline prompt manifest invalid")
    return FixedPromptAsset(
        prompt_id=prompt_id,
        path=resolved,
        sha256=_exact_string(raw["sha256"]),
        license=_exact_string(raw["license"]),
        format=_exact_string(raw["format"]),
        sample_rate_hz=_exact_int(raw["sample_rate_hz"]),
        channels=_exact_int(raw["channels"]),
        duration_ms=_exact_int(raw["duration_ms"]),
        size_bytes=_exact_int(raw["size_bytes"]),
    )


def _verified_asset_payload(asset: FixedPromptAsset) -> bytes:
    payload = _read_regular_no_follow(
        asset.path,
        expected_size=asset.size_bytes,
        byte_limit=_MAX_SIZE_BYTES,
    )
    if hashlib.sha256(payload).hexdigest() != asset.sha256:
        raise ValueError("offline prompt asset changed")
    _verify_wave_bytes(payload, duration_ms=asset.duration_ms, size_bytes=asset.size_bytes)
    return payload


def _read_regular_no_follow(
    path: Path,
    *,
    expected_size: int | None,
    byte_limit: int,
) -> bytes:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("offline prompt manifest invalid")
    if expected_size is not None and metadata.st_size != expected_size:
        raise ValueError("offline prompt manifest invalid")
    if metadata.st_size > byte_limit:
        raise ValueError("offline prompt manifest invalid")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (
            stat.S_ISLNK(opened.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
            or opened.st_size != metadata.st_size
        ):
            raise ValueError("offline prompt manifest invalid")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                raise ValueError("offline prompt manifest invalid")
            chunks.append(chunk)
            remaining -= len(chunk)
        final = os.fstat(descriptor)
        if (final.st_dev, final.st_ino) != (
            metadata.st_dev,
            metadata.st_ino,
        ) or final.st_size != metadata.st_size:
            raise ValueError("offline prompt manifest invalid")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _verify_wave_bytes(payload: bytes, *, duration_ms: int, size_bytes: int) -> None:
    try:
        if len(payload) != size_bytes:
            raise ValueError("offline prompt manifest invalid")
        with wave.open(io.BytesIO(payload), "rb") as audio:
            observed_duration_ms = round(audio.getnframes() * 1000 / audio.getframerate())
            if (
                audio.getnchannels() != _CHANNELS
                or audio.getsampwidth() != _SAMPLE_WIDTH_BYTES
                or audio.getframerate() != _SAMPLE_RATE_HZ
                or observed_duration_ms != duration_ms
                or audio.getcomptype() != "NONE"
                or size_bytes > _MAX_SIZE_BYTES
            ):
                raise ValueError("offline prompt manifest invalid")
    except (EOFError, wave.Error) as error:
        raise ValueError("offline prompt manifest invalid") from error


def _exact_string(value: Any) -> str:
    if type(value) is not str:
        raise ValueError("offline prompt manifest invalid")
    return value


def _exact_int(value: Any) -> int:
    if type(value) is not int:
        raise ValueError("offline prompt manifest invalid")
    return value


__all__ = (
    "FixedPromptAsset",
    "FixedPromptManifest",
    "FixedPromptPlayer",
    "FixedPromptSink",
    "PlaybackReceipt",
)
