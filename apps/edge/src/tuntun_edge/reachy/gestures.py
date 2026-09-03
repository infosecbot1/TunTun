from __future__ import annotations

from typing import Final

SAFE_GESTURES: Final = frozenset(
    {"neutral", "acknowledge", "listen", "think", "speak", "confirm", "deny", "error", "sleep"}
)


def validate_gesture(name: str) -> str:
    if type(name) is not str:
        raise TypeError("gesture_id must be an exact str")
    if name not in SAFE_GESTURES:
        raise ValueError("gesture_not_allowlisted")
    return name
