from __future__ import annotations

import hashlib
import json
from types import MappingProxyType
from typing import Literal

PROMPT_CATALOG_VERSION = "guest-1"

PromptId = Literal["guest_cloud_stt", "guest_cloud_reasoning", "guest_cloud_tts"]
PromptLanguage = Literal["en", "hi", "hinglish"]
PromptVersion = Literal["guest-1"]

_PROMPTS: MappingProxyType[tuple[str, str, str], str] = MappingProxyType(
    {
        (
            "guest_cloud_reasoning",
            "en",
            "guest-1",
        ): "Sanitized text will be sent to cloud reasoning. Yes or no?",
        (
            "guest_cloud_reasoning",
            "hi",
            "guest-1",
        ): "पहचान हटाया हुआ टेक्स्ट क्लाउड रीजनिंग सेवा को भेजा जाएगा। हाँ या नहीं?",
        (
            "guest_cloud_reasoning",
            "hinglish",
            "guest-1",
        ): "Sanitized text cloud reasoning service ko bheja jayega. Haan ya nahin?",
        (
            "guest_cloud_stt",
            "en",
            "guest-1",
        ): "Your voice will be sent to cloud speech recognition. Yes or no?",
        (
            "guest_cloud_stt",
            "hi",
            "guest-1",
        ): "आपकी आवाज़ क्लाउड स्पीच सेवा को भेजी जाएगी। हाँ या नहीं?",
        (
            "guest_cloud_stt",
            "hinglish",
            "guest-1",
        ): "Aapki awaaz cloud speech service ko bheji jayegi. Haan ya nahin?",
        (
            "guest_cloud_tts",
            "en",
            "guest-1",
        ): "Answer text will be sent to an AI voice generation service. Yes or no?",
        (
            "guest_cloud_tts",
            "hi",
            "guest-1",
        ): "जवाब का टेक्स्ट एआई आवाज़ बनाने की सेवा को भेजा जाएगा। हाँ या नहीं?",
        (
            "guest_cloud_tts",
            "hinglish",
            "guest-1",
        ): "Answer text AI voice generation service ko bheja jayega. Haan ya nahin?",
    }
)


class PromptCatalogError(LookupError):
    def __init__(self) -> None:
        super().__init__("offline_prompt_unknown")


def prompt_text(prompt_id: str, language: str, version: str) -> str:
    if type(prompt_id) is not str or type(language) is not str or type(version) is not str:
        raise TypeError("offline_prompt_key_invalid")
    try:
        return _PROMPTS[(prompt_id, language, version)]
    except KeyError as error:
        raise PromptCatalogError() from error


def prompt_catalog_sha256() -> str:
    document = {
        "version": PROMPT_CATALOG_VERSION,
        "prompts": [
            {"id": key[0], "language": key[1], "text": value, "version": key[2]}
            for key, value in sorted(_PROMPTS.items())
        ],
    }
    return hashlib.sha256(
        json.dumps(
            document,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


__all__ = (
    "PROMPT_CATALOG_VERSION",
    "PromptCatalogError",
    "PromptId",
    "PromptLanguage",
    "PromptVersion",
    "prompt_catalog_sha256",
    "prompt_text",
)
