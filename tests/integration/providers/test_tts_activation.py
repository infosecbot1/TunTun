from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from tuntun_core.services.providers.tts_activation import (
    CloudRequestBoundTtsEvidence,
    OfflineMacOSSayEvidence,
    TtsActivationGate,
)


class Probe:
    def __init__(self, value) -> None:
        self.value = value

    async def current_request_bound_receipt(self):
        return self.value

    async def current_receipt(self):
        return self.value


class Readiness:
    def __init__(self) -> None:
        self.tts_mode = None
        self.family_private_beta_ready = False
        self.withdrawn_reason = None

    def set_tts_mode(self, mode: str) -> None:
        self.tts_mode = mode
        self.family_private_beta_ready = True

    def withdraw(self, reason: str) -> None:
        self.withdrawn_reason = reason
        self.family_private_beta_ready = False


def _case(*, cloud=None, offline=None) -> tuple[TtsActivationGate, Readiness]:
    readiness = Readiness()
    gate = TtsActivationGate(Probe(cloud), Probe(offline), readiness)
    return gate, readiness


def _cloud_evidence(**overrides) -> CloudRequestBoundTtsEvidence:
    values = {
        "review_receipt_id": uuid4(),
        "provenance_receipt_id": uuid4(),
        "measured_at": datetime(2026, 8, 27, tzinfo=UTC),
        "is_current": True,
        "evidence_age_seconds": 0,
        "max_age_seconds": 86_400,
        "provider": "openai",
        "model": "tts-1",
        "accounting_basis": "request_bound_exact",
        "binary_response_has_usage": False,
        "character_limit": 4_096,
    }
    values.update(overrides)
    return CloudRequestBoundTtsEvidence(**values)


def _offline_evidence(**overrides) -> OfflineMacOSSayEvidence:
    values = {
        "review_receipt_id": uuid4(),
        "provenance_receipt_id": uuid4(),
        "measured_at": datetime(2026, 8, 27, tzinfo=UTC),
        "schema_version": "tuntun.offline-macos-say-tts-readiness.v1",
        "say_path": "/usr/bin/say",
        "afconvert_path": "/usr/bin/afconvert",
        "owner_license_accepted": True,
        "say_binary_sha256_b64": "A" * 43 + "=",
        "afconvert_binary_sha256_b64": "B" * 43 + "=",
        "fixed_binary_hashes_match": True,
        "english_voice_id": "Aman",
        "hindi_voice_id": "Lekha",
        "pcm_sample_format": "s16le",
        "pcm_sample_rate_hz": 24_000,
        "pcm_channels": 1,
        "pcm_interleaved": True,
        "pcm_container": "raw",
        "bilingual_quality_passed": True,
        "hinglish_quality_passed": True,
        "no_network_observed": True,
        "cold_restart_voice_presence_passed": True,
        "p95_first_audio_ms": 1_000,
        "p95_total_ms": 3_000,
        "is_current": True,
        "evidence_age_seconds": 0,
        "max_age_seconds": 86_400,
    }
    values.update(overrides)
    return OfflineMacOSSayEvidence(**values)


def test_tts_readiness_evidence_requires_explicit_reviewed_provenance() -> None:
    with pytest.raises(TypeError):
        CloudRequestBoundTtsEvidence()
    with pytest.raises(TypeError):
        OfflineMacOSSayEvidence()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("cloud", "offline", "expected"),
    (
        (_cloud_evidence(), None, "cloud_request_bound_exact"),
        (None, _offline_evidence(), "offline_macos_say"),
    ),
)
async def test_family_voice_requires_one_verified_branch(cloud, offline, expected: str) -> None:
    gate, readiness = _case(cloud=cloud, offline=offline)

    assert await gate.require_family_voice() == expected
    assert readiness.tts_mode == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("character_limit", (4_000, 4_097))
async def test_cloud_tts_evidence_requires_exact_contract_limit(
    character_limit: int,
) -> None:
    gate, readiness = _case(
        cloud=replace(
            _cloud_evidence(),
            character_limit=character_limit,
        )
    )

    with pytest.raises(RuntimeError, match="family_voice_unavailable"):
        await gate.require_family_voice()

    assert not readiness.family_private_beta_ready
    assert readiness.withdrawn_reason == "family_voice_unavailable"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("cloud_failure", "bad_value"),
    (
        ("review_receipt_id", UUID(int=0)),
        ("provenance_receipt_id", UUID(int=0)),
        ("measured_at", datetime(2026, 8, 27)),
        ("is_current", False),
        ("evidence_age_seconds", 86_401),
    ),
)
async def test_cloud_tts_evidence_requires_reviewed_current_provenance(
    cloud_failure: str,
    bad_value,
) -> None:
    gate, readiness = _case(cloud=replace(_cloud_evidence(), **{cloud_failure: bad_value}))

    with pytest.raises(RuntimeError, match="family_voice_unavailable"):
        await gate.require_family_voice()

    assert not readiness.family_private_beta_ready
    assert readiness.withdrawn_reason == "family_voice_unavailable"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("offline_failure", "bad_value"),
    (
        ("review_receipt_id", UUID(int=0)),
        ("provenance_receipt_id", UUID(int=0)),
        ("measured_at", datetime(2026, 8, 27)),
        ("say_path", "/tmp/fake-say"),
        ("afconvert_path", "/tmp/fake-afconvert"),
        ("owner_license_accepted", False),
        ("say_binary_sha256_b64", ""),
        ("say_binary_sha256_b64", "!"),
        ("afconvert_binary_sha256_b64", ""),
        ("afconvert_binary_sha256_b64", "!"),
        ("fixed_binary_hashes_match", False),
        ("english_voice_id", ""),
        ("hindi_voice_id", ""),
        ("pcm_sample_format", "float32_le"),
        ("pcm_sample_rate_hz", 16_000),
        ("pcm_channels", 2),
        ("pcm_interleaved", False),
        ("pcm_container", "wav"),
        ("bilingual_quality_passed", False),
        ("hinglish_quality_passed", False),
        ("no_network_observed", False),
        ("cold_restart_voice_presence_passed", False),
        ("p95_first_audio_ms", 1_001),
        ("p95_total_ms", 3_001),
        ("is_current", False),
        ("evidence_age_seconds", 86_401),
        ("max_age_seconds", 604_800),
    ),
)
async def test_unproved_cloud_and_bad_offline_voice_block_stage_one(
    offline_failure: str,
    bad_value,
) -> None:
    gate, readiness = _case(
        offline=replace(_offline_evidence(), **{offline_failure: bad_value})
    )

    with pytest.raises(RuntimeError, match="family_voice_unavailable"):
        await gate.require_family_voice()

    assert not readiness.family_private_beta_ready
    assert readiness.withdrawn_reason == "family_voice_unavailable"
