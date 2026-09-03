from __future__ import annotations

import re
import unicodedata
from types import MappingProxyType

from tuntun_core.domain.offline import ConsentChallenge, OfflineIntent, OfflineMatch, TimerArguments

MAX_OFFLINE_TEXT_CHARACTERS = 256
MAX_OFFLINE_TEXT_UTF8_BYTES = 512

EXACT_PHRASES: MappingProxyType[OfflineIntent, tuple[str, ...]] = MappingProxyType(
    {
        "stop": (
            "stop",
            "stop now",
            "please stop",
            "रुको",
            "अभी रुको",
            "बस करो",
            "ruko",
            "abhi ruko",
        ),
        "privacy_on": (
            "privacy on",
            "turn privacy on",
            "enable privacy",
            "privacy mode on",
            "privacy shield on",
            "प्राइवेसी चालू करो",
            "निजता चालू करो",
            "privacy chalu karo",
        ),
        "mute_on": (
            "mute",
            "mute on",
            "mute yourself",
            "go silent",
            "चुप हो जाओ",
            "आवाज़ बंद करो",
            "chup ho jao",
            "awaaz band karo",
        ),
        "timer_cancel": (
            "cancel timer",
            "cancel the timer",
            "stop timer",
            "timer cancel",
            "टाइमर रद्द करो",
            "टाइमर बंद करो",
            "timer radd karo",
            "timer band karo",
        ),
        "timer_status": (
            "timer status",
            "show timer status",
            "tell me the timer",
            "timer remaining",
            "टाइमर बताओ",
            "टाइमर कितना बाकी है",
            "timer batao",
            "timer kitna baki hai",
        ),
        "time_now": (
            "what time is it",
            "tell me the time",
            "current time",
            "time now",
            "समय बताओ",
            "अभी क्या समय है",
            "samay batao",
            "abhi kya samay hai",
        ),
        "system_status": (
            "system status",
            "show system status",
            "is the system okay",
            "system health",
            "सिस्टम स्थिति",
            "सिस्टम ठीक है",
            "system sthiti",
            "system theek hai",
        ),
        "reachy_status": (
            "reachy status",
            "show reachy status",
            "is reachy okay",
            "reachy health",
            "रीची स्थिति",
            "रीची ठीक है",
            "reachy sthiti",
            "reachy theek hai",
        ),
        "repeat_status": (
            "repeat status",
            "repeat the status",
            "say status again",
            "status again",
            "फिर बताओ",
            "स्थिति फिर बताओ",
            "phir batao",
            "sthiti phir batao",
        ),
    }
)

_EXACT: dict[str, OfflineIntent] = {}
for _intent, _phrases in EXACT_PHRASES.items():
    for _phrase in _phrases:
        if _phrase in _EXACT:
            raise RuntimeError("offline phrase is assigned to more than one intent")
        _EXACT[_phrase] = _intent

_TIMER_PATTERNS = (
    re.compile(
        r"^(?:set )?(?:a )?timer (?:for )?"
        r"(?P<n>[1-9]|1[0-9]|2[0-4]) (?P<u>minute|minutes|hour|hours)$"
    ),
    re.compile(
        r"^(?P<n>[1-9]|1[0-9]|2[0-4]) "
        r"(?P<u>मिनट|घंटा|घंटे) का टाइमर लगाओ$"
    ),
    re.compile(
        r"^(?P<n>[1-9]|1[0-9]|2[0-4]) "
        r"(?P<u>minute|minutes|ghanta|ghante) ka timer lagao$"
    ),
)
_HOUR_UNITS = frozenset({"hour", "hours", "घंटा", "घंटे", "ghanta", "ghante"})
_YES = frozenset({"yes", "हाँ", "haan"})
_NO = frozenset({"no", "नहीं", "nahi", "nahin"})


def _no_match() -> OfflineMatch:
    return OfflineMatch(intent="no_match", confidence_micros=0)


def _normalize_bounded(text: str) -> str | None:
    if type(text) is not str:
        raise TypeError("offline text must be a string")
    if not text or len(text) > MAX_OFFLINE_TEXT_CHARACTERS:
        return None
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if len(encoded) > MAX_OFFLINE_TEXT_UTF8_BYTES:
        return None
    if any(unicodedata.category(character).startswith("C") for character in text):
        return None
    normalized = " ".join(unicodedata.normalize("NFC", text).casefold().split())
    return normalized or None


def parse_offline(text: str, challenge: ConsentChallenge | None) -> OfflineMatch:
    if challenge is not None and type(challenge) is not ConsentChallenge:
        raise TypeError("challenge must be an exact ConsentChallenge")
    normalized = _normalize_bounded(text)
    if normalized is None:
        return _no_match()
    if challenge is not None and normalized in _YES:
        return OfflineMatch(
            intent=f"{challenge.purpose}_consent_yes",  # type: ignore[arg-type]
            confidence_micros=1_000_000,
            challenge_id=challenge.challenge_id,
        )
    if challenge is not None and normalized in _NO:
        return OfflineMatch(
            intent=f"{challenge.purpose}_consent_no",  # type: ignore[arg-type]
            confidence_micros=1_000_000,
            challenge_id=challenge.challenge_id,
        )
    for pattern in _TIMER_PATTERNS:
        match = pattern.fullmatch(normalized)
        if match is None:
            continue
        value = int(match.group("n"))
        seconds = value * (3600 if match.group("u") in _HOUR_UNITS else 60)
        return OfflineMatch(
            intent="timer_create",
            confidence_micros=1_000_000,
            timer=TimerArguments(duration_seconds=seconds),
        )
    intent = _EXACT.get(normalized)
    if intent is None:
        return _no_match()
    return OfflineMatch(intent=intent, confidence_micros=1_000_000)
