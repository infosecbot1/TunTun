# packages/contracts/src/tuntun_contracts/budget.py
from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Any, Literal, Self, TypeAlias
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from .base import Commitment, ContractModel

MAX_USAGE_UNITS = 10_000_000
MAX_AUDIO_MILLIS = 3_600_000
MAX_WEB_SEARCH_CALLS = 16
MAX_CHARGE_MICROS_SGD = 1_000_000_000_000


class LlmUsageUnits(ContractModel):
    category: Literal["llm"]
    input_tokens: Annotated[int, Field(ge=0, le=MAX_USAGE_UNITS)]
    output_tokens: Annotated[int, Field(ge=0, le=MAX_USAGE_UNITS)]


class SttUsageUnits(ContractModel):
    category: Literal["stt"]
    audio_millis: Annotated[int, Field(ge=0, le=MAX_AUDIO_MILLIS)]


class TtsUsageUnits(ContractModel):
    category: Literal["tts"]
    characters: Annotated[int, Field(ge=0, le=4_096)]


class WebSearchUsageUnits(ContractModel):
    category: Literal["web_search"]
    input_tokens: Annotated[int, Field(ge=0, le=MAX_USAGE_UNITS)]
    output_tokens: Annotated[int, Field(ge=0, le=MAX_USAGE_UNITS)]
    web_search_calls: Annotated[int, Field(ge=0, le=MAX_WEB_SEARCH_CALLS)]


UsageUnits: TypeAlias = Annotated[  # noqa: UP040 -- Python 3.11 compatibility.
    LlmUsageUnits | SttUsageUnits | TtsUsageUnits | WebSearchUsageUnits,
    Field(discriminator="category"),
]


def usage_total(value: UsageUnits) -> int:
    if isinstance(value, LlmUsageUnits):
        return value.input_tokens + value.output_tokens
    if isinstance(value, SttUsageUnits):
        return value.audio_millis
    if isinstance(value, TtsUsageUnits):
        return value.characters
    return value.input_tokens + value.output_tokens + value.web_search_calls


class BudgetReservationRequest(ContractModel):
    household_id: UUID
    turn_id: UUID
    request_id: UUID
    attempt_id: UUID
    provider: Literal["openai", "qwen"]
    model: Annotated[str, Field(min_length=1, max_length=128)]
    category: Literal["stt", "llm", "tts", "web_search"]
    usage_ceiling: UsageUnits
    month_key: Annotated[str, Field(pattern=r"^[0-9]{4}-(?:0[1-9]|1[0-2])$")]

    @model_validator(mode="before")
    @classmethod
    def forbid_caller_supplied_amounts(cls, value: Any) -> Any:
        if isinstance(value, Mapping):
            forbidden = {
                "worst_case_micros_sgd",
                "charged_micros_sgd",
                "amount_micros_sgd",
            }
            present = sorted(forbidden.intersection(value))
            if present:
                raise ValueError(f"{present[0]} is server-derived")
        return value

    @model_validator(mode="after")
    def exact_pricing_purpose(self) -> Self:
        if self.usage_ceiling.category != self.category or usage_total(self.usage_ceiling) <= 0:
            raise ValueError("budget_usage_ceiling_invalid")
        if (
            isinstance(self.usage_ceiling, WebSearchUsageUnits)
            and self.usage_ceiling.web_search_calls != 1
        ):
            raise ValueError("web_search_reservation_must_price_exactly_one_call")
        return self


class BudgetReservation(ContractModel):
    reservation_id: UUID
    request_id: UUID
    attempt_id: UUID
    outcome: Literal[
        "allow",
        "allow_soft_warning",
        "deny_hard_limit",
        "deny_unknown_price",
        "deny_cloud_egress_frozen",
    ]
    amount_micros_sgd: Annotated[int, Field(ge=0, le=MAX_CHARGE_MICROS_SGD)]
    pricing_commitment: Commitment | None
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def exact_quote_shape(self) -> Self:
        quote_absent = self.outcome in {
            "deny_unknown_price",
            "deny_cloud_egress_frozen",
        }
        if quote_absent != (self.pricing_commitment is None):
            raise ValueError("budget_reservation_quote_shape_invalid")
        allowed = self.outcome in {"allow", "allow_soft_warning"}
        if allowed != (self.amount_micros_sgd > 0):
            raise ValueError("budget_reservation_amount_shape_invalid")
        return self


class BudgetSettlementRequest(ContractModel):
    reservation_id: UUID
    attempt_id: UUID


class BudgetSettlement(ContractModel):
    reservation_id: UUID
    charged_micros_sgd: Annotated[int, Field(ge=0, le=MAX_CHARGE_MICROS_SGD)]
    conservative_estimate_used: bool
    estimate_overrun: bool
    cloud_egress_frozen: bool


class ProviderUsageReceiptV1(ContractModel):
    schema_version: Literal["tuntun.provider-usage-receipt.v1"]
    receipt_id: UUID
    provider_call_id: UUID
    reservation_id: UUID
    request_id: UUID
    attempt_id: UUID
    authorization_id: UUID
    provider: Literal["openai", "qwen"]
    model: Annotated[str, Field(min_length=1, max_length=128)]
    category: Literal["stt", "llm", "tts", "web_search"]
    accounting_basis: Literal[
        "provider_reported_exact",
        "request_bound_exact",
        "conservative_full_reservation",
    ]
    billable_usage: UsageUnits
    provider_response_commitment: Commitment
    observed_at: AwareDatetime
    receipt_commitment: Commitment

    @model_validator(mode="after")
    def exact_usage_category(self) -> Self:
        if self.category != self.billable_usage.category:
            raise ValueError("provider_usage_category_mismatch")
        if usage_total(self.billable_usage) <= 0:
            raise ValueError("provider_usage_must_be_positive")
        if (
            isinstance(self.billable_usage, WebSearchUsageUnits)
            and self.billable_usage.web_search_calls != 1
        ):
            raise ValueError("web_search_receipt_requires_exactly_one_call")
        return self


class TransportProof(ContractModel):
    reservation_id: UUID
    attempt_id: UUID
    disposition: Literal["never_sent", "sent", "unknown"]
    evidence_code: str
    observed_at: AwareDatetime


class BudgetReconciliationRequest(ContractModel):
    turn_id: UUID
    proofs: Annotated[tuple[TransportProof, ...], Field(min_length=0, max_length=8)]

    @field_validator("proofs")
    @classmethod
    def unique_attempt_proofs(
        cls,
        value: tuple[TransportProof, ...],
    ) -> tuple[TransportProof, ...]:
        keys = {(item.reservation_id, item.attempt_id) for item in value}
        if len(keys) != len(value):
            raise ValueError("duplicate transport proof")
        return value
