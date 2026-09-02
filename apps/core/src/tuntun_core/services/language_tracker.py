from __future__ import annotations

from typing import Literal

ReplyMode = Literal["en", "hi", "hi_romanized", "hinglish"]
SttLanguage = Literal["en", "hi", "hinglish", "unknown"]

_REPLY_MODES = frozenset({"en", "hi", "hi_romanized", "hinglish"})
_STT_LANGUAGES = frozenset({"en", "hi", "hinglish", "unknown"})


class LanguageTracker:
    def detect(
        self,
        transcript: str,
        stt_language: SttLanguage,
        *,
        explicit_reply_language: ReplyMode | None = None,
        prior_language: ReplyMode | None = None,
        prior_age_turns: int | None = None,
    ) -> ReplyMode:
        if type(transcript) is not str:
            raise TypeError("transcript must be an exact str")
        if stt_language not in _STT_LANGUAGES:
            raise ValueError("unknown stt language")
        if explicit_reply_language is not None:
            if explicit_reply_language not in _REPLY_MODES:
                raise ValueError("unknown explicit reply language")
            return explicit_reply_language

        has_devanagari = any("\u0900" <= character <= "\u097f" for character in transcript)
        has_latin = any("a" <= character.casefold() <= "z" for character in transcript)
        if stt_language == "hinglish" or (has_devanagari and has_latin):
            return "hinglish"
        if stt_language == "hi":
            return "hi" if has_devanagari else "hi_romanized"
        if has_devanagari:
            return "hi"
        if stt_language == "en":
            return "en"
        if (
            _is_ambiguous_short_turn(transcript)
            and prior_language in _REPLY_MODES
            and prior_age_turns in {1, 2}
        ):
            return prior_language
        return "en"


def _is_ambiguous_short_turn(transcript: str) -> bool:
    stripped = transcript.strip()
    return bool(stripped) and len(stripped) <= 32 and len(stripped.split()) <= 4
