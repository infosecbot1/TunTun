# packages/contracts/src/tuntun_contracts/provider.py
from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator

from .base import Commitment, ContractModel, Sensitivity


class ProviderName(StrEnum):
    OPENAI = "openai"
    QWEN = "qwen"


class RouteAuthorization(ContractModel):
    authorization_id: UUID
    request_id: UUID
    attempt_id: UUID
    purpose: Literal["cloud_stt", "cloud_reasoning", "cloud_tts"]
    household_id: UUID
    subject_id: UUID | None
    session_id: UUID
    turn_id: UUID
    provider: Literal["openai", "qwen"]
    model: Annotated[str, Field(min_length=1, max_length=128)]
    request_commitment: Commitment
    max_input_bytes: Annotated[int, Field(ge=1, le=8_388_608)]
    max_input_units: Annotated[int, Field(ge=1)]
    privacy_receipt_id: UUID
    consent_receipt_ids: Annotated[
        tuple[UUID, ...],
        Field(min_length=1, max_length=8),
    ]
    budget_reservation_id: UUID
    maximum_sensitivity: Sensitivity
    expires_at: AwareDatetime


class RouteAuthorizationRequest(ContractModel):
    request_id: UUID
    attempt_id: UUID
    purpose: Literal["cloud_stt", "cloud_reasoning", "cloud_tts"]
    household_id: UUID
    subject_id: UUID | None
    session_id: UUID
    turn_id: UUID
    provider: Literal["openai", "qwen"]
    model: Annotated[str, Field(min_length=1, max_length=128)]
    request_commitment: Commitment
    max_input_bytes: Annotated[int, Field(ge=1, le=8_388_608)]
    max_input_units: Annotated[int, Field(ge=1)]
    privacy_receipt_id: UUID
    consent_receipt_ids: Annotated[
        tuple[UUID, ...],
        Field(min_length=1, max_length=8),
    ]
    budget_reservation_id: UUID
    maximum_sensitivity: Sensitivity


class RouteConsumption(ContractModel):
    request_id: UUID
    attempt_id: UUID
    purpose: Literal["cloud_stt", "cloud_reasoning", "cloud_tts"]
    household_id: UUID
    subject_id: UUID | None
    session_id: UUID
    turn_id: UUID
    provider: Literal["openai", "qwen"]
    model: Annotated[str, Field(min_length=1, max_length=128)]
    request_commitment: Commitment
    input_bytes: Annotated[int, Field(ge=0, le=8_388_608)]
    input_units: Annotated[int, Field(ge=0)]
    consumed_at: AwareDatetime


class ProviderResponseReceipt(ContractModel):
    receipt_id: UUID
    request_id: UUID
    attempt_id: UUID
    authorization_id: UUID
    household_id: UUID
    subject_id: UUID | None
    session_id: UUID
    turn_id: UUID
    provider: Literal["openai", "qwen"]
    model: Annotated[str, Field(min_length=1, max_length=128)]
    output_schema_version: Literal["assistant-turn-v1"]
    response_commitment: Commitment
    receipt_hmac_key_id: str
    receipt_hmac_b64: str
    produced_at: AwareDatetime


class SanitizedProviderMessage(ContractModel):
    role: Literal["system", "user", "assistant", "memory_data"]
    content: Annotated[str, Field(min_length=1, max_length=32_000)]


class SanitizedToolReference(ContractModel):
    registered_name: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{1,127}$")]
    schema_version: Literal["1.0"]
    schema_commitment: Commitment


class SanitizedProviderRequest(ContractModel):
    request_id: UUID
    provider: ProviderName
    model: Annotated[str, Field(min_length=1, max_length=128)]
    messages: Annotated[
        tuple[SanitizedProviderMessage, ...],
        Field(min_length=1, max_length=32),
    ]
    allowed_tools: Annotated[
        tuple[SanitizedToolReference, ...],
        Field(min_length=0, max_length=8),
    ]
    max_output_tokens: Annotated[int, Field(ge=1, le=16_384)]
    store: Literal[False] = False
    redaction_receipt_id: UUID
    route: RouteAuthorization
    timeout_ms: Annotated[int, Field(ge=1_000, le=120_000)]


class ProviderResponse(ContractModel):
    request_id: UUID
    text: Annotated[str, Field(min_length=1, max_length=8_000)]
    language: Literal["en", "hi", "hinglish"]
    provider_usage_receipt_id: UUID | None


class RedactionReceipt(ContractModel):
    receipt_id: UUID
    purpose: Literal["cloud_reasoning", "cloud_tts"]
    input_commitment: Commitment
    output_commitment: Commitment
    removed_categories: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=64)], ...],
        Field(min_length=0, max_length=16),
    ]
    removed_count: Annotated[int, Field(ge=0)]
    policy_version: str
    maximum_sensitivity: Sensitivity

    @field_validator("removed_categories")
    @classmethod
    def unique_removed_categories(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate redaction category")
        return value
