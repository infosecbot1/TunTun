from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal, Protocol

from pydantic import AwareDatetime, Field, field_validator
from tuntun_contracts.base import (
    JCS_MAX_SAFE_INTEGER,
    ContractModel,
    ContractParseError,
    canonical_mapping_bytes,
    parse_contract_json,
)
from tuntun_core.services.transactions.protocols import UnitOfWorkProtocol

_HEX_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_OPENAI_REVIEW_KEY = "provider.review.openai"
_OPENAI_ROUTES = frozenset(
    {
        ("cloud_stt", "gpt-transcribe"),
        ("cloud_reasoning", "gpt-5.6-sol"),
        ("cloud_tts", "tts-1"),
    }
)
_OPENAI_MODELS = frozenset(model for _, model in _OPENAI_ROUTES)
_REVIEW_MAX_AGE = timedelta(days=90)
_STORAGE_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
_OPENAI_PROJECT_ID = re.compile(r"^proj_[A-Za-z0-9_-]{1,123}$")
_CENTS_TO_MICROS_USD = 10_000
_MAX_PROVIDER_LIMIT_MICROS_USD = 100_000_000


@dataclass(frozen=True, slots=True)
class RuntimeProviderIdentity:
    project_id_commitment_sha256: str
    credential_kind: str
    admin_key_present: bool


class RuntimeProviderIdentityReader(Protocol):
    def require_current(self, provider: str) -> RuntimeProviderIdentity: ...


class _OpenAIHardLimitEnforcementV1(ContractModel):
    status: Literal["enforcing"]


class _OpenAIProjectSpendLimitV1(ContractModel):
    object: Literal["project.spend_limit"]
    threshold_amount: Annotated[int, Field(ge=1, le=JCS_MAX_SAFE_INTEGER)]
    currency: Literal["USD"]
    interval: Literal["month"]
    enforcement: _OpenAIHardLimitEnforcementV1


class OpenAIProviderHardLimitV1(ContractModel):
    project_id_commitment_sha256: str = Field(pattern=_HEX_SHA256_PATTERN)
    threshold_micros_usd: Annotated[int, Field(ge=1, le=100_000_000)]
    currency: Literal["USD"]
    interval: Literal["provider_month"]
    enforcement_status: Literal["enforcing"]
    dashboard_evidence_sha256: str = Field(pattern=_HEX_SHA256_PATTERN)
    settings_commitment_sha256: str = Field(pattern=_HEX_SHA256_PATTERN)
    runtime_credential_kind: Literal["project_service_account"]
    runtime_admin_key_present: Literal[False]

    def committed_settings(self) -> dict[str, object]:
        return {
            "project_id_commitment_sha256": self.project_id_commitment_sha256,
            "threshold_micros_usd": self.threshold_micros_usd,
            "currency": self.currency,
            "interval": self.interval,
            "enforcement_status": self.enforcement_status,
            "dashboard_evidence_sha256": self.dashboard_evidence_sha256,
        }


def commission_openai_provider_hard_limit(
    raw: bytes,
    *,
    observed_project_id: str,
    runtime_identity: RuntimeProviderIdentity,
) -> OpenAIProviderHardLimitV1:
    """Fail-closed normalization of the raw admin API response."""
    try:
        payload = parse_contract_json(
            _OpenAIProjectSpendLimitV1,
            raw,
            max_bytes=2_048,
            require_canonical=False,
        )
    except (ContractParseError, TypeError, UnicodeError, ValueError):
        raise PermissionError("provider_hard_limit_commissioning_failed") from None
    if (
        type(observed_project_id) is not str
        or _OPENAI_PROJECT_ID.fullmatch(observed_project_id) is None
        or type(runtime_identity) is not RuntimeProviderIdentity
        or type(runtime_identity.project_id_commitment_sha256) is not str
        or re.fullmatch(_HEX_SHA256_PATTERN, runtime_identity.project_id_commitment_sha256) is None
        or runtime_identity.credential_kind != "project_service_account"
        or runtime_identity.admin_key_present is not False
    ):
        raise PermissionError("provider_hard_limit_commissioning_failed") from None
    project_commitment = hashlib.sha256(observed_project_id.encode("ascii")).hexdigest()
    if not hmac.compare_digest(
        project_commitment,
        runtime_identity.project_id_commitment_sha256,
    ):
        raise PermissionError("provider_hard_limit_commissioning_failed") from None
    cents = payload.threshold_amount
    if cents > JCS_MAX_SAFE_INTEGER // _CENTS_TO_MICROS_USD:
        raise PermissionError("provider_hard_limit_commissioning_failed") from None
    threshold_micros_usd = cents * _CENTS_TO_MICROS_USD
    if threshold_micros_usd > _MAX_PROVIDER_LIMIT_MICROS_USD:
        raise PermissionError("provider_hard_limit_commissioning_failed") from None
    committed: dict[str, object] = {
        "project_id_commitment_sha256": project_commitment,
        "threshold_micros_usd": threshold_micros_usd,
        "currency": "USD",
        "interval": "provider_month",
        "enforcement_status": "enforcing",
        "dashboard_evidence_sha256": hashlib.sha256(raw).hexdigest(),
    }
    return OpenAIProviderHardLimitV1.model_validate(
        committed
        | {
            "settings_commitment_sha256": hashlib.sha256(
                canonical_mapping_bytes(committed),
            ).hexdigest(),
            "runtime_credential_kind": "project_service_account",
            "runtime_admin_key_present": False,
        },
        strict=True,
    )


class ProviderReviewV1(ContractModel):
    schema_version: Literal["tuntun.provider-review.v1"]
    provider: Literal["openai"]
    accepted: Literal[True]
    expires_at: AwareDatetime
    source_changed: Literal[False]
    dashboard_changed: Literal[False]
    purposes: Annotated[
        tuple[Literal["cloud_stt", "cloud_reasoning", "cloud_tts"], ...],
        Field(min_length=1, max_length=3),
    ]
    models: Annotated[tuple[str, ...], Field(min_length=1, max_length=32)]
    endpoint: Literal["https://api.openai.com/v1"]
    workspace_id: None
    region: Literal["global"]
    review_version: Annotated[int, Field(ge=1)]
    source_sha256: str = Field(pattern=_HEX_SHA256_PATTERN)
    provider_hard_limit: OpenAIProviderHardLimitV1

    @field_validator("purposes", "models")
    @classmethod
    def unique_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("provider review values must be unique")
        return value

    @field_validator("models")
    @classmethod
    def bounded_ascii_models(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(
            not 1 <= len(item) <= 128
            or not item.isascii()
            or any(not 0x20 <= ord(character) <= 0x7E for character in item)
            or item not in _OPENAI_MODELS
            for item in value
        ):
            raise ValueError("provider review models must be bounded printable ASCII")
        return value


def _trusted_now(value: datetime) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise PermissionError("provider_review_not_current")
    return value.astimezone(UTC)


def _parse_storage_timestamp(raw: object) -> datetime:
    if type(raw) is not str:
        raise PermissionError("provider_review_not_current")
    try:
        parsed = datetime.strptime(raw, _STORAGE_TIMESTAMP_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        raise PermissionError("provider_review_not_current") from None
    if parsed.strftime(_STORAGE_TIMESTAMP_FORMAT) != raw:
        raise PermissionError("provider_review_not_current")
    return parsed


def _parse_review(raw: object) -> ProviderReviewV1:
    if type(raw) is not str:
        raise PermissionError("provider_review_not_current")
    try:
        return parse_contract_json(
            ProviderReviewV1,
            raw.encode("utf-8"),
            max_bytes=32_768,
            require_canonical=True,
        )
    except (ContractParseError, UnicodeError, ValueError):
        raise PermissionError("provider_review_not_current") from None


class ProviderReviewStore:
    """Read and validate the owner-accepted, encrypted OpenAI review record."""

    def __init__(
        self,
        transaction: UnitOfWorkProtocol,
        runtime_identities: RuntimeProviderIdentityReader,
    ) -> None:
        self._transaction = transaction
        self._runtime_identities = runtime_identities

    def require_current(
        self,
        provider: str,
        model: str,
        purpose: str,
        now: datetime,
    ) -> ProviderReviewV1:
        if (
            type(provider) is not str
            or provider != "openai"
            or type(model) is not str
            or type(purpose) is not str
        ):
            raise PermissionError("provider_review_not_current")
        normalized_now = _trusted_now(now)
        row = self._transaction.exec_driver_sql(
            "SELECT value_json,updated_at FROM runtime_settings WHERE key = ?",
            (_OPENAI_REVIEW_KEY,),
        ).fetchone()
        if row is None:
            raise PermissionError("provider_review_not_current")
        review = _parse_review(row[0])
        reviewed_at = _parse_storage_timestamp(row[1])
        expires_at = review.expires_at.astimezone(UTC)
        if (
            reviewed_at > normalized_now
            or expires_at > reviewed_at + _REVIEW_MAX_AGE
            or normalized_now >= expires_at
            or model not in review.models
            or purpose not in review.purposes
            or (purpose, model) not in _OPENAI_ROUTES
        ):
            raise PermissionError("provider_review_not_current")

        try:
            identity = self._runtime_identities.require_current(provider)
        except Exception:
            raise PermissionError("provider_review_not_current") from None
        if (
            type(identity) is not RuntimeProviderIdentity
            or type(identity.project_id_commitment_sha256) is not str
            or len(identity.project_id_commitment_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in identity.project_id_commitment_sha256
            )
            or type(identity.credential_kind) is not str
            or type(identity.admin_key_present) is not bool
        ):
            raise PermissionError("provider_review_not_current")
        hard_limit = review.provider_hard_limit
        calculated_commitment = hashlib.sha256(
            canonical_mapping_bytes(hard_limit.committed_settings())
        ).hexdigest()
        if (
            not hmac.compare_digest(
                hard_limit.settings_commitment_sha256,
                calculated_commitment,
            )
            or not hmac.compare_digest(
                hard_limit.project_id_commitment_sha256,
                identity.project_id_commitment_sha256,
            )
            or hard_limit.runtime_credential_kind != identity.credential_kind
            or hard_limit.runtime_admin_key_present is not identity.admin_key_present
            or identity.credential_kind != "project_service_account"
            or identity.admin_key_present is not False
        ):
            raise PermissionError("provider_review_not_current")
        return review


class SqlcipherCurrentProviderReviews:
    def __init__(self, runtime_identities: RuntimeProviderIdentityReader) -> None:
        self._runtime_identities = runtime_identities

    def require_current(
        self,
        uow: UnitOfWorkProtocol,
        provider: str,
        model: str,
        purpose: str,
        now: datetime,
    ) -> object:
        return ProviderReviewStore(uow, self._runtime_identities).require_current(
            provider,
            model,
            purpose,
            now,
        )
