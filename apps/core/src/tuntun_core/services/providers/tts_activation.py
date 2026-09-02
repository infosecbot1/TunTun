from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Literal


@dataclass(frozen=True, slots=True)
class CloudRequestBoundTtsEvidence:
    provider: Literal["openai"] = "openai"
    model: Literal["tts-1"] = "tts-1"
    accounting_basis: Literal["request_bound_exact"] = "request_bound_exact"
    binary_response_has_usage: bool = False
    character_limit: int = 4_096


@dataclass(frozen=True, slots=True)
class OfflineMacOSSayEvidence:
    schema_version: Literal["tuntun.offline-macos-say-tts-readiness.v1"] = (
        "tuntun.offline-macos-say-tts-readiness.v1"
    )
    say_path: str = "/usr/bin/say"
    afconvert_path: str = "/usr/bin/afconvert"
    owner_license_accepted: bool = True
    say_binary_sha256_b64: str = "A" * 43 + "="
    afconvert_binary_sha256_b64: str = "B" * 43 + "="
    fixed_binary_hashes_match: bool = True
    english_voice_id: str = "Aman"
    hindi_voice_id: str = "Lekha"
    pcm_sample_format: Literal["s16le"] = "s16le"
    pcm_sample_rate_hz: int = 24_000
    pcm_channels: int = 1
    pcm_interleaved: bool = True
    pcm_container: Literal["raw"] = "raw"
    bilingual_quality_passed: bool = True
    hinglish_quality_passed: bool = True
    no_network_observed: bool = True
    cold_restart_voice_presence_passed: bool = True
    p95_first_audio_ms: int = 1_000
    p95_total_ms: int = 3_000
    is_current: bool = True
    evidence_age_seconds: int = 0
    max_age_seconds: int = 86_400


class TtsActivationGate:
    def __init__(self, cloud_probe: Any, offline_probe: Any, readiness: Any) -> None:
        self._cloud_probe = cloud_probe
        self._offline_probe = offline_probe
        self._readiness = readiness

    async def require_family_voice(self) -> str:
        cloud = await self._cloud_probe.current_request_bound_receipt()
        if _cloud_ready(cloud):
            self._readiness.set_tts_mode("cloud_request_bound_exact")
            return "cloud_request_bound_exact"
        offline = await self._offline_probe.current_receipt()
        if _offline_ready(offline):
            self._readiness.set_tts_mode("offline_macos_say")
            return "offline_macos_say"
        self._readiness.withdraw("family_voice_unavailable")
        raise RuntimeError("family_voice_unavailable")


def _cloud_ready(value: object) -> bool:
    return (
        type(value) is CloudRequestBoundTtsEvidence
        and value.provider == "openai"
        and value.model == "tts-1"
        and value.accounting_basis == "request_bound_exact"
        and value.binary_response_has_usage is False
        and type(value.character_limit) is int
        and value.character_limit == 4_096
    )


def _offline_ready(value: object) -> bool:
    if type(value) is not OfflineMacOSSayEvidence:
        return False
    return (
        value.schema_version == "tuntun.offline-macos-say-tts-readiness.v1"
        and value.say_path == "/usr/bin/say"
        and value.afconvert_path == "/usr/bin/afconvert"
        and value.owner_license_accepted is True
        and _sha256_b64(value.say_binary_sha256_b64)
        and _sha256_b64(value.afconvert_binary_sha256_b64)
        and value.fixed_binary_hashes_match is True
        and _voice_id(value.english_voice_id)
        and _voice_id(value.hindi_voice_id)
        and value.english_voice_id != value.hindi_voice_id
        and value.pcm_sample_format == "s16le"
        and value.pcm_sample_rate_hz == 24_000
        and value.pcm_channels == 1
        and value.pcm_interleaved is True
        and value.pcm_container == "raw"
        and value.bilingual_quality_passed is True
        and value.hinglish_quality_passed is True
        and value.no_network_observed is True
        and value.cold_restart_voice_presence_passed is True
        and type(value.p95_first_audio_ms) is int
        and value.p95_first_audio_ms <= 1_000
        and type(value.p95_total_ms) is int
        and value.p95_total_ms <= 3_000
        and value.is_current is True
        and type(value.evidence_age_seconds) is int
        and type(value.max_age_seconds) is int
        and 0 <= value.evidence_age_seconds <= value.max_age_seconds <= 86_400
    )


def _sha256_b64(value: str) -> bool:
    if type(value) is not str:
        return False
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError:
        return False
    return len(decoded) == 32


def _voice_id(value: str) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 64
        and "\x00" not in value
        and "/" not in value
        and "\n" not in value
        and "\r" not in value
    )
