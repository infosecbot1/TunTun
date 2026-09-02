from __future__ import annotations

from tuntun_contracts.identity import PersonaProjection
from tuntun_core.services.persona_builder import PersonaBuilder


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
        return (
            {"role": "system", "content": self._prompts.build(persona, language)},
            {"role": "user", "content": user_text},
        )
