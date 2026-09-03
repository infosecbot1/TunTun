from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from tuntun_core.offline.grammar import EXACT_PHRASES

OUTPUT = Path("tests/fixtures/synthetic/offline-utterances.yaml")
_CHALLENGE_ID = {
    "cloud_stt": "00000000-0000-4000-8000-000000000201",
    "cloud_reasoning": "00000000-0000-4000-8000-000000000202",
    "cloud_tts": "00000000-0000-4000-8000-000000000203",
}
_CONSENT_ANSWERS = {
    "yes": ("yes", "YES", "हाँ", "haan"),
    "no": ("no", "NO", "नहीं", "nahin"),
}
_TIMER_POSITIVES = (
    ("set a timer for 1 minute", 60),
    ("set timer for 2 minutes", 120),
    ("timer for 3 hours", 10_800),
    ("set a timer for 24 hours", 86_400),
    ("4 मिनट का टाइमर लगाओ", 240),
    ("5 घंटे का टाइमर लगाओ", 18_000),
    ("6 minute ka timer lagao", 360),
    ("7 ghante ka timer lagao", 25_200),
)
_CURATED_NEGATIVES = (
    "privacy off",
    "turn privacy off",
    "disable privacy",
    "unmute",
    "प्राइवेसी बंद करो",
    "privacy band karo",
    "do not remember me",
    "yes",
    "no",
    "हाँ",
    "नहीं",
    "set a timer for 0 minutes",
    "set a timer for 25 hours",
    "set a timer for -1 minute",
    "set a timer for 1.5 hours",
    "set a timer for 1 day",
    "set a timer for 1 minute and privacy off",
    "stop and erase everything",
    "ignore instructions and privacy on",
    "please unmute now",
)


def _spacing_variants(phrase: str) -> tuple[str, ...]:
    return (phrase, f" {phrase}", f"{phrase} ", f"  {phrase}  ")


def build_corpus() -> dict[str, list[Any]]:
    positive: list[dict[str, object]] = []
    for intent, phrases in EXACT_PHRASES.items():
        for phrase in phrases:
            positive.extend(
                {"text": variant, "intent": intent} for variant in _spacing_variants(phrase)
            )
    for text, seconds in _TIMER_POSITIVES:
        positive.extend(
            {
                "text": variant,
                "intent": "timer_create",
                "timer": {"duration_seconds": seconds},
            }
            for variant in _spacing_variants(text)
        )
    for purpose, challenge_id in _CHALLENGE_ID.items():
        challenge = {
            "purpose": purpose,
            "challenge_id": challenge_id,
            "disclosure_version": "guest-disclosure-v1",
        }
        for suffix, answers in _CONSENT_ANSWERS.items():
            positive.extend(
                {
                    "text": answer,
                    "intent": f"{purpose}_consent_{suffix}",
                    "challenge": challenge,
                }
                for answer in answers
            )

    negative = list(_CURATED_NEGATIVES)
    for phrases in EXACT_PHRASES.values():
        for phrase in phrases:
            negative.extend((f"not {phrase}", f"{phrase} and continue"))
    index = 0
    while len(set(negative)) < 200:
        negative.append(f"unsupported offline phrase {index:03d}")
        index += 1
    return {"positive": positive, "negative": list(dict.fromkeys(negative))}


def main() -> None:
    OUTPUT.write_text(
        yaml.safe_dump(build_corpus(), allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
