# packages/contracts/src/tuntun_contracts/memory.py
from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self, TypeAlias
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from .base import Commitment, ContractModel, Sensitivity


class MemoryKind(StrEnum):
    WORKING = "working"
    EPISODIC = "episodic"
    SEMANTIC = "semantic"
    PREFERENCE = "preference"
    PROCEDURAL = "procedural"
    RELATIONAL = "relational"
    POLICY = "policy"


class MemoryAudience(StrEnum):
    SUBJECT_PRIVATE = "subject_private"
    GUARDIAN_CHILD = "guardian_child"
    HOUSEHOLD_ADULTS = "household_adults"
    HOUSEHOLD_ALL = "household_all"


class WorkingContent(ContractModel):
    kind: Literal["working"]
    state_summary: Annotated[str, Field(max_length=2_000)]
    unresolved_intents: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=256)], ...],
        Field(min_length=0, max_length=8),
    ]


class EpisodicContent(ContractModel):
    kind: Literal["episodic"]
    event_summary: Annotated[str, Field(max_length=2_000)]
    occurred_at: AwareDatetime
    participant_ids: Annotated[
        tuple[UUID, ...],
        Field(min_length=0, max_length=16),
    ]

    @field_validator("participant_ids")
    @classmethod
    def unique_participants(cls, value: tuple[UUID, ...]) -> tuple[UUID, ...]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate participant")
        return value


class SemanticContent(ContractModel):
    kind: Literal["semantic"]
    subject: Annotated[str, Field(max_length=256)]
    predicate: Annotated[str, Field(max_length=128)]
    object: Annotated[str, Field(max_length=2_000)]


class PreferenceContent(ContractModel):
    kind: Literal["preference"] = "preference"
    category: Annotated[str, Field(max_length=128)]
    key: Annotated[str, Field(max_length=128)]
    value: Annotated[str, Field(max_length=2_000)]
    strength_micros: Annotated[int, Field(ge=0, le=1_000_000)]


class ProceduralContent(ContractModel):
    kind: Literal["procedural"]
    name: Annotated[str, Field(max_length=256)]
    steps: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(min_length=1, max_length=32),
    ]
    tool_label: Annotated[str, Field(max_length=128)] | None = None


class RelationalContent(ContractModel):
    kind: Literal["relational"]
    subject_id: UUID
    relation: Annotated[str, Field(max_length=128)]
    object_subject_id: UUID
    note: Annotated[str, Field(max_length=1_000)] | None = None


class PolicyContent(ContractModel):
    kind: Literal["policy"]
    key: Annotated[str, Field(max_length=128)]
    value: str | int | bool


MemoryContent: TypeAlias = Annotated[  # noqa: UP040 -- Python 3.11 compatibility.
    WorkingContent
    | EpisodicContent
    | SemanticContent
    | PreferenceContent
    | ProceduralContent
    | RelationalContent
    | PolicyContent,
    Field(discriminator="kind"),
]


class MemoryProposalDraft(ContractModel):
    proposal_id: UUID
    schema_version: Literal["1.0"]
    operation: Literal["create", "replace", "delete"]
    household_id: UUID
    subject_id: UUID
    session_id: UUID
    turn_id: UUID
    idempotency_key: UUID
    content: MemoryContent | None
    audience: MemoryAudience | None
    target_memory_id: UUID | None
    expected_version: int | None
    sensitivity: Sensitivity
    confidence_micros: Annotated[int, Field(ge=0, le=1_000_000)]
    reason: Annotated[str, Field(min_length=1, max_length=256)]
    claim_commitment: Commitment
    source_receipt_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=8)]
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def operation_shape(self) -> Self:
        target_present = self.target_memory_id is not None
        version_present = self.expected_version is not None
        if self.operation == "create" and (
            self.content is None or self.audience is None or target_present or version_present
        ):
            raise ValueError("create memory proposal shape")
        if self.operation == "replace" and (
            self.content is None
            or self.audience is None
            or not target_present
            or not version_present
        ):
            raise ValueError("replace memory proposal shape")
        if self.operation == "delete" and (
            self.content is not None
            or self.audience is not None
            or not target_present
            or not version_present
        ):
            raise ValueError("delete memory proposal shape")
        return self


class MemoryProposal(ContractModel):
    draft: MemoryProposalDraft
    status: Literal["pending", "approved", "rejected", "expired"]


class MemoryRecord(ContractModel):
    memory_id: UUID
    household_id: UUID
    subject_id: UUID
    version: Annotated[int, Field(ge=1)]
    content: MemoryContent
    audience: MemoryAudience
    sensitivity: Sensitivity
    valid_until: AwareDatetime | None


class MemoryQuery(ContractModel):
    household_id: UUID
    subject_id: UUID
    kinds: Annotated[tuple[MemoryKind, ...], Field(min_length=1, max_length=7)]
    maximum_sensitivity: Sensitivity
    limit: Annotated[int, Field(ge=1, le=6)] = 6

    @field_validator("kinds")
    @classmethod
    def unique_kinds(cls, value: tuple[MemoryKind, ...]) -> tuple[MemoryKind, ...]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate memory kind")
        return value


class ApprovedMemory(ContractModel):
    memory_id: UUID
    household_id: UUID
    subject_id: UUID
    content: MemoryContent
    audience: MemoryAudience
    sensitivity: Sensitivity
    approved_proposal_id: UUID
    source_receipt_ids: Annotated[
        tuple[UUID, ...],
        Field(min_length=1, max_length=8),
    ]
    valid_until: AwareDatetime | None

    @field_validator("source_receipt_ids")
    @classmethod
    def unique_source_receipts(cls, value: tuple[UUID, ...]) -> tuple[UUID, ...]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate source receipt")
        return value


class ProposalContext(ContractModel):
    household_id: UUID
    subject_id: UUID | None
    session_id: UUID
    turn_id: UUID
    actor_subject_id: UUID | None


class DecideMemoryProposal(ContractModel):
    proposal_id: UUID
    decision: Literal["approve", "reject"]
    edited_content: MemoryContent | None
    expected_version: Annotated[int, Field(ge=1)]
