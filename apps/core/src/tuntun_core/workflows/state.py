from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

GraphPhase = Literal[
    "new",
    "ingress",
    "transcribe",
    "resolve_identity",
    "authorize_recall",
    "retrieve_context",
    "sanitize_and_reserve",
    "authorize_provider_egress",
    "generate",
    "validate",
    "synthesize",
    "propose_memories",
    "audit_and_finish",
]
ContentCommitment = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class GraphState(BaseModel):
    """The complete checkpointable graph state; conversation content is forbidden."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    turn_id: UUID
    phase: GraphPhase
    cancelled: bool
    content_commitments: Annotated[
        tuple[ContentCommitment, ...],
        Field(min_length=0, max_length=16),
    ]

    @field_validator("turn_id")
    @classmethod
    def exact_uuid(cls, value: UUID) -> UUID:
        if type(value) is not UUID:
            raise TypeError("turn_id must be an exact UUID")
        return value

    @field_validator("content_commitments")
    @classmethod
    def unique_content_commitments(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate content commitment")
        return value


__all__ = ["ContentCommitment", "GraphPhase", "GraphState"]
