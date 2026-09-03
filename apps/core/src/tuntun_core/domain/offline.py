from __future__ import annotations

from typing import Annotated, Literal, Self
from unicodedata import category
from uuid import UUID

from pydantic import Field, field_validator, model_validator
from tuntun_contracts.base import ContractModel

ConsentPurpose = Literal["cloud_stt", "cloud_reasoning", "cloud_tts"]
OfflineIntent = Literal[
    "no_match",
    "stop",
    "privacy_on",
    "mute_on",
    "timer_create",
    "timer_cancel",
    "timer_status",
    "time_now",
    "system_status",
    "reachy_status",
    "repeat_status",
    "cloud_stt_consent_yes",
    "cloud_stt_consent_no",
    "cloud_reasoning_consent_yes",
    "cloud_reasoning_consent_no",
    "cloud_tts_consent_yes",
    "cloud_tts_consent_no",
]

ConsentIntent = Literal[
    "cloud_stt_consent_yes",
    "cloud_stt_consent_no",
    "cloud_reasoning_consent_yes",
    "cloud_reasoning_consent_no",
    "cloud_tts_consent_yes",
    "cloud_tts_consent_no",
]

_CONSENT_INTENTS = frozenset(
    {
        "cloud_stt_consent_yes",
        "cloud_stt_consent_no",
        "cloud_reasoning_consent_yes",
        "cloud_reasoning_consent_no",
        "cloud_tts_consent_yes",
        "cloud_tts_consent_no",
    }
)


class ConsentChallenge(ContractModel):
    purpose: ConsentPurpose
    challenge_id: UUID
    disclosure_version: Annotated[
        str,
        Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"),
    ]


class TimerArguments(ContractModel):
    duration_seconds: Annotated[int, Field(ge=60, le=86_400)]
    label: Annotated[str, Field(min_length=1, max_length=64)] | None = None

    @field_validator("label")
    @classmethod
    def label_is_canonical_display_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if value != value.strip() or any(
            category(character).startswith("C") or (character.isspace() and character != " ")
            for character in value
        ):
            raise ValueError("timer label must be trimmed display text without controls")
        return value


class OfflineMatch(ContractModel):
    intent: OfflineIntent
    confidence_micros: Literal[0, 1_000_000]
    challenge_id: UUID | None = None
    timer: TimerArguments | None = None

    @model_validator(mode="after")
    def exact_operation_shape(self) -> Self:
        is_no_match = self.intent == "no_match"
        is_consent = self.intent in _CONSENT_INTENTS
        is_timer_create = self.intent == "timer_create"
        if is_no_match != (self.confidence_micros == 0):
            raise ValueError("offline match confidence does not match intent")
        if is_consent != (self.challenge_id is not None):
            raise ValueError("offline consent match requires exactly one challenge")
        if is_timer_create != (self.timer is not None):
            raise ValueError("offline timer match requires exactly one timer payload")
        if self.challenge_id is not None and self.timer is not None:
            raise ValueError("offline match payloads are mutually exclusive")
        return self
