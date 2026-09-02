from __future__ import annotations

from typing import Any


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
        value is not None
        and getattr(value, "provider", None) == "openai"
        and getattr(value, "model", None) == "tts-1"
        and getattr(value, "accounting_basis", None) == "request_bound_exact"
        and getattr(value, "binary_response_has_usage", None) is False
        and getattr(value, "character_limit", 0) >= 4_096
    )


def _offline_ready(value: object) -> bool:
    return (
        value is not None
        and getattr(value, "owner_license_accepted", None) is True
        and getattr(value, "fixed_binary_hashes_match", None) is True
        and getattr(value, "english_voice_present", None) is True
        and getattr(value, "hindi_voice_present", None) is True
        and getattr(value, "hinglish_corpus_passed", None) is True
        and getattr(value, "no_network_observed", None) is True
        and getattr(value, "cold_restart_voice_presence_passed", None) is True
        and getattr(value, "p95_first_audio_ms", 99_999) <= 1_000
        and getattr(value, "p95_total_ms", 99_999) <= 3_000
    )
