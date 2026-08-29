# packages/contracts/src/tuntun_contracts/identity.py
from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator

from .base import ContractModel


class IdentityStatus(StrEnum):
    VERIFIED = "verified"
    AMBIGUOUS = "ambiguous"
    UNKNOWN = "unknown"
    CONFLICT = "conflict"


class IdentityEvidence(ContractModel):
    modality: Literal["face", "voice"]
    subject_id: UUID | None
    confidence_micros: Annotated[int, Field(ge=0, le=1_000_000)]
    quality_micros: Annotated[int, Field(ge=0, le=1_000_000)]
    liveness_accepted: bool
    model_version: str
    observed_at: AwareDatetime
    expires_at: AwareDatetime


class IdentityRequest(ContractModel):
    household_id: UUID
    session_id: UUID
    evidence: Annotated[tuple[IdentityEvidence, ...], Field(min_length=0, max_length=2)]

    @field_validator("evidence")
    @classmethod
    def unique_modalities(
        cls,
        value: tuple[IdentityEvidence, ...],
    ) -> tuple[IdentityEvidence, ...]:
        if len({item.modality for item in value}) != len(value):
            raise ValueError("duplicate identity modality")
        return value


class IdentityDecision(ContractModel):
    status: IdentityStatus
    subject_id: UUID | None
    reason_code: str
    expires_at: AwareDatetime


class PersonaTraits(ContractModel):
    context: Literal["general", "technical_security", "household_practical", "early_learning"]
    tone: Literal["neutral", "precise", "practical", "warm"]
    depth: Literal["brief", "standard", "detailed"]
    learning_level: Literal["none", "n1", "k2"]


class PersonaProjection(ContractModel):
    role: Literal["owner", "adult", "k2", "n1", "guest"]
    context: Literal["general", "technical_security", "household_practical", "early_learning"]
    tone: Literal["neutral", "precise", "practical", "warm"]
    depth: Literal["brief", "standard", "detailed"]
    learning_level: Literal["none", "n1", "k2"]
