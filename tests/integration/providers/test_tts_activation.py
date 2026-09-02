from __future__ import annotations

from dataclasses import replace

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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("cloud", "offline", "expected"),
    (
        (CloudRequestBoundTtsEvidence(), None, "cloud_request_bound_exact"),
        (None, OfflineMacOSSayEvidence(), "offline_macos_say"),
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
            CloudRequestBoundTtsEvidence(),
            character_limit=character_limit,
        )
    )

    with pytest.raises(RuntimeError, match="family_voice_unavailable"):
        await gate.require_family_voice()

    assert not readiness.family_private_beta_ready
    assert readiness.withdrawn_reason == "family_voice_unavailable"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("offline_failure", "bad_value"),
    (
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
        offline=replace(OfflineMacOSSayEvidence(), **{offline_failure: bad_value})
    )

    with pytest.raises(RuntimeError, match="family_voice_unavailable"):
        await gate.require_family_voice()

    assert not readiness.family_private_beta_ready
    assert readiness.withdrawn_reason == "family_voice_unavailable"
