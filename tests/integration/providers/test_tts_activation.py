from __future__ import annotations

from dataclasses import dataclass, replace

import pytest
from tuntun_core.services.providers.tts_activation import TtsActivationGate


@dataclass(frozen=True, slots=True)
class CloudReceipt:
    provider: str = "openai"
    model: str = "tts-1"
    accounting_basis: str = "request_bound_exact"
    binary_response_has_usage: bool = False
    character_limit: int = 4_096


@dataclass(frozen=True, slots=True)
class OfflineReceipt:
    owner_license_accepted: bool = True
    fixed_binary_hashes_match: bool = True
    english_voice_present: bool = True
    hindi_voice_present: bool = True
    hinglish_corpus_passed: bool = True
    no_network_observed: bool = True
    cold_restart_voice_presence_passed: bool = True
    p95_first_audio_ms: int = 1_000
    p95_total_ms: int = 3_000


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
        (CloudReceipt(), None, "cloud_request_bound_exact"),
        (None, OfflineReceipt(), "offline_macos_say"),
    ),
)
async def test_family_voice_requires_one_verified_branch(cloud, offline, expected: str) -> None:
    gate, readiness = _case(cloud=cloud, offline=offline)

    assert await gate.require_family_voice() == expected
    assert readiness.tts_mode == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "offline_failure",
    (
        "owner_license_accepted",
        "fixed_binary_hashes_match",
        "english_voice_present",
        "hindi_voice_present",
        "hinglish_corpus_passed",
        "no_network_observed",
        "cold_restart_voice_presence_passed",
        "p95_first_audio_ms",
        "p95_total_ms",
    ),
)
async def test_unproved_cloud_and_bad_offline_voice_block_stage_one(
    offline_failure: str,
) -> None:
    boolean_probe = ("owner", "fixed", "english", "hindi", "hinglish", "no_", "cold")
    bad_value = False if offline_failure.startswith(boolean_probe) else 99_999
    gate, readiness = _case(
        offline=replace(OfflineReceipt(), **{offline_failure: bad_value})
    )

    with pytest.raises(RuntimeError, match="family_voice_unavailable"):
        await gate.require_family_voice()

    assert not readiness.family_private_beta_ready
    assert readiness.withdrawn_reason == "family_voice_unavailable"
