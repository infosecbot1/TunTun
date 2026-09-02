from __future__ import annotations

from tuntun_contracts.identity import PersonaProjection
from tuntun_core.services.language_tracker import (
    MAX_TRANSCRIPT_CHARS,
    MAX_TRANSCRIPT_UTF8_BYTES,
)
from tuntun_core.services.persona_builder import PersonaBuilder

MAX_PROVIDER_CONTEXT_UTF8_BYTES = 40_960


class ContextBuilder:
    def __init__(self, prompts: PersonaBuilder) -> None:
        if type(prompts) is not PersonaBuilder:
            raise TypeError("prompts must be an exact PersonaBuilder")
        self._prompts = prompts

    @property
    def prompt_bundle_sha256(self) -> str:
        return self._prompts.prompt_bundle_sha256

    def messages(
        self,
        persona: PersonaProjection,
        language: str,
        user_text: str,
    ) -> tuple[dict[str, str], ...]:
        if type(user_text) is not str:
            raise TypeError("user_text must be an exact str")
        if (
            len(user_text) > MAX_TRANSCRIPT_CHARS
            or len(user_text.encode("utf-8")) > MAX_TRANSCRIPT_UTF8_BYTES
        ):
            raise ValueError("provider context outside turn bounds")
        system = self._prompts.build(persona, language)
        if len(system.encode("utf-8")) + len(user_text.encode("utf-8")) > (
            MAX_PROVIDER_CONTEXT_UTF8_BYTES
        ):
            raise ValueError("provider context outside turn bounds")
        return (
            {"role": "system", "content": system},
            {"role": "user", "content": user_text},
        )
