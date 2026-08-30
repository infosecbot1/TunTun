from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self, TypeAlias
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from .base import (
    JCS_MAX_SAFE_INTEGER,
    Commitment,
    ContractModel,
    Sensitivity,
    canonical_bytes,
    validate_canonical_base64,
)


class EventType(StrEnum):
    WAKE_DETECTED = "speech.wake_detected"
    STOP_REQUESTED = "safety.stop_requested"


class WakeDetectedPayload(ContractModel):
    kind: Literal["speech.wake_detected"]
    turn_id: UUID
    score_micros: Annotated[int, Field(ge=0, le=1_000_000)]


class StopRequestedPayload(ContractModel):
    kind: Literal["safety.stop_requested"]
    turn_id: UUID | None
    source: Literal[
        "edge_keyword",
        "physical_input",
        "owner_console",
        "watchdog",
    ]


EventPayload: TypeAlias = Annotated[  # noqa: UP040 -- Python 3.11 compatibility.
    WakeDetectedPayload | StopRequestedPayload,
    Field(discriminator="kind"),
]


class EventEnvelope(ContractModel):
    schema_version: Literal["1.0"]
    event_id: UUID
    event_type: EventType
    household_id: UUID
    device_id: UUID
    session_id: UUID | None
    correlation_id: UUID
    causation_id: UUID | None
    device_sequence: Annotated[int, Field(ge=0, le=JCS_MAX_SAFE_INTEGER)]
    occurred_at: AwareDatetime
    sensitivity: Sensitivity
    payload_commitment: Commitment
    payload: EventPayload

    @model_validator(mode="after")
    def matching_type(self) -> Self:
        if self.event_type.value != self.payload.kind:
            raise ValueError("event_type must equal payload.kind")
        return self


class SignedEventEnvelope(ContractModel):
    envelope: EventEnvelope
    signing_key_id: Annotated[
        str,
        Field(
            min_length=12,
            max_length=83,
            pattern=r"^ed25519:[a-z0-9][a-z0-9._-]{0,63}:v[1-9][0-9]{0,8}$",
        ),
    ]
    signature_b64: Annotated[
        str,
        Field(
            min_length=88,
            max_length=88,
            pattern=r"^[A-Za-z0-9+/]{86}==$",
        ),
    ]

    @field_validator("signature_b64")
    @classmethod
    def canonical_ed25519_signature(cls, value: str) -> str:
        return validate_canonical_base64(
            value,
            expected_bytes=64,
            label="signature",
        )

    def signing_bytes(self) -> bytes:
        """Return the sole Ed25519 signing input; wrapper fields are excluded."""
        return canonical_bytes(self.envelope)
