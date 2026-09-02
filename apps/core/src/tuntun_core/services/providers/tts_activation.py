from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal
from uuid import UUID


@dataclass(frozen=True, slots=True)
class CloudRequestBoundTtsEvidence:
    review_receipt_id: UUID
    provenance_receipt_id: UUID
    measured_at: datetime
    is_current: bool
    evidence_age_seconds: int
    max_age_seconds: int
    provider: Literal["openai"]
    model: Literal["tts-1"]
    accounting_basis: Literal["request_bound_exact"]
    binary_response_has_usage: bool
    character_limit: int


@dataclass(frozen=True, slots=True)
class OfflineMacOSSayEvidence:
    review_receipt_id: UUID
    provenance_receipt_id: UUID
    measured_at: datetime
    schema_version: Literal["tuntun.offline-macos-say-tts-readiness.v1"]
    say_path: str
    afconvert_path: str
    owner_license_accepted: bool
    say_binary_sha256_b64: str
    afconvert_binary_sha256_b64: str
    fixed_binary_hashes_match: bool
    english_voice_id: str
    hindi_voice_id: str
    pcm_sample_format: Literal["s16le"]
    pcm_sample_rate_hz: int
    pcm_channels: int
    pcm_interleaved: bool
    pcm_container: Literal["raw"]
    bilingual_quality_passed: bool
    hinglish_quality_passed: bool
    no_network_observed: bool
    cold_restart_voice_presence_passed: bool
    p95_first_audio_ms: int
    p95_total_ms: int
    is_current: bool
    evidence_age_seconds: int
    max_age_seconds: int


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
        and _reviewed_provenance(value)
        and _current_fresh(value)
    )


def _offline_ready(value: object) -> bool:
    if type(value) is not OfflineMacOSSayEvidence:
        return False
    return (
        value.schema_version == "tuntun.offline-macos-say-tts-readiness.v1"
        and _reviewed_provenance(value)
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
        and _current_fresh(value)
    )


def _reviewed_provenance(value: Any) -> bool:
    return (
        type(value.review_receipt_id) is UUID
        and value.review_receipt_id.int != 0
        and type(value.provenance_receipt_id) is UUID
        and value.provenance_receipt_id.int != 0
        and type(value.measured_at) is datetime
        and value.measured_at.tzinfo is not None
        and value.measured_at.utcoffset() is not None
    )


def _current_fresh(value: Any) -> bool:
    return (
        value.is_current is True
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
