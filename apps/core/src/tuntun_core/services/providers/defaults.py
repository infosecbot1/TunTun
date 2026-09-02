from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator
from tuntun_contracts.base import ContractModel
from tuntun_core.config.loader import read_bounded_strict_yaml

MAX_PROVIDER_DEFAULTS_BYTES = 32_768
MAX_LOCAL_HARD_LIMIT_MICROS_SGD = 150_000_000
MAX_RESERVATION_EXPIRY_SECONDS = 900
PROVIDER_DEFAULTS_SCHEMA_VERSION = "tuntun.provider-defaults.v1"


class ProviderDefaultsBudgetV1(ContractModel):
    timezone: Literal["Asia/Singapore"]
    soft_limit_micros_sgd: Annotated[int, Field(ge=0, le=MAX_LOCAL_HARD_LIMIT_MICROS_SGD)]
    hard_limit_micros_sgd: Annotated[int, Field(ge=0, le=MAX_LOCAL_HARD_LIMIT_MICROS_SGD)]
    reservation_expiry_seconds: Annotated[int, Field(ge=1, le=MAX_RESERVATION_EXPIRY_SECONDS)]

    @model_validator(mode="after")
    def ordered_limits(self) -> ProviderDefaultsBudgetV1:
        if self.hard_limit_micros_sgd < self.soft_limit_micros_sgd:
            raise ValueError("hard limit must be at least soft limit")
        return self


class OpenAIProviderHardLimitPolicyV1(ContractModel):
    currency: Literal["USD"]
    interval: Literal["provider_month"]
    maximum_threshold_micros_usd: Literal[100_000_000]
    enforcement_status: Literal["enforcing"]
    runtime_admin_key_forbidden: Literal[True]


class OpenAIProviderDefaultsV1(ContractModel):
    sdk_retries: Annotated[int, Field(ge=0, le=0)]
    telemetry_enabled: Literal[False]
    dedicated_project_required: Literal[True]
    provider_hard_limit: OpenAIProviderHardLimitPolicyV1


class ProviderDefaultsProvidersV1(ContractModel):
    openai: OpenAIProviderDefaultsV1


class ProviderDefaultsDocumentV1(ContractModel):
    schema_version: Literal["tuntun.provider-defaults.v1"]
    budget: ProviderDefaultsBudgetV1
    providers: ProviderDefaultsProvidersV1


def load_provider_defaults(path: Path) -> ProviderDefaultsDocumentV1:
    return ProviderDefaultsDocumentV1.model_validate(
        read_bounded_strict_yaml(
            Path(path),
            max_bytes=MAX_PROVIDER_DEFAULTS_BYTES,
            require_private=False,
        ),
        strict=True,
    )
