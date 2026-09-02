from __future__ import annotations

from typing import Literal, cast

ReplyMode = Literal["en", "hi", "hi_romanized", "hinglish"]
SttLanguage = Literal["en", "hi", "hinglish", "unknown"]

_REPLY_MODES = frozenset({"en", "hi", "hi_romanized", "hinglish"})
_STT_LANGUAGES = frozenset({"en", "hi", "hinglish", "unknown"})
MAX_TRANSCRIPT_CHARS = 4_096
MAX_TRANSCRIPT_UTF8_BYTES = 4_096


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
        require_transcript_text(transcript)
        require_stt_language(stt_language)
        if prior_language is not None:
            require_reply_mode(prior_language, name="prior_language")
        if prior_age_turns is not None:
            if type(prior_age_turns) is not int:
                raise TypeError("prior_age_turns must be an exact int")
            if prior_age_turns < 0:
                raise ValueError("prior_age_turns must be non-negative")
        if explicit_reply_language is not None:
            require_reply_mode(explicit_reply_language, name="explicit_reply_language")
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


def require_transcript_text(transcript: object) -> str:
    if type(transcript) is not str:
        raise TypeError("transcript must be an exact str")
    if (
        len(transcript) > MAX_TRANSCRIPT_CHARS
        or len(transcript.encode("utf-8")) > MAX_TRANSCRIPT_UTF8_BYTES
    ):
        raise ValueError("transcript outside turn bounds")
    return transcript


def require_stt_language(stt_language: object) -> SttLanguage:
    if type(stt_language) is not str:
        raise TypeError("stt_language must be an exact str")
    if stt_language not in _STT_LANGUAGES:
        raise ValueError("unknown stt language")
    return cast(SttLanguage, stt_language)


def require_reply_mode(value: object, *, name: str = "reply_mode") -> ReplyMode:
    if type(value) is not str:
        raise TypeError(f"{name} must be an exact str")
    if value not in _REPLY_MODES:
        raise ValueError(f"unknown {name}")
    return cast(ReplyMode, value)
