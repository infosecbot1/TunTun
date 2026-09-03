from __future__ import annotations

from datetime import UTC, datetime

import pytest
from tuntun_core.services.budget.catalog import FxRecord, PriceCatalog, PriceRecord
from tuntun_core.services.budget.evidence import BudgetEvidenceService
from tuntun_core.services.providers.review import RuntimeProviderIdentity


@pytest.fixture
def catalog() -> PriceCatalog:
    start = datetime(2026, 8, 1, tzinfo=UTC)
    end = datetime(2026, 9, 26, tzinfo=UTC)
    sha = "d" * 64
    return PriceCatalog(
        prices=(
            PriceRecord(
                provider="openai",
                model="gpt-5.6-sol",
                category="llm",
                native_currency="USD",
                input_micro_usd_per_million=4_000_000,
                output_micro_usd_per_million=20_000_000,
                audio_micro_usd_per_minute=0,
                web_search_micro_usd_per_call=0,
                primary_accounting_basis="provider_reported_exact",
                missing_evidence_policy="freeze_unknown_overage",
                pricing_version="openai-2026-08-27",
                effective_at=start,
                expires_at=end,
                source_url="https://developers.openai.com/api/docs/models/gpt-5.6-sol",
                source_sha256=sha,
            ),
            PriceRecord(
                provider="openai",
                model="gpt-transcribe",
                category="stt",
                native_currency="USD",
                input_micro_usd_per_million=0,
                output_micro_usd_per_million=0,
                audio_micro_usd_per_minute=4_500,
                web_search_micro_usd_per_call=0,
                primary_accounting_basis="provider_reported_exact",
                missing_evidence_policy="freeze_unknown_overage",
                pricing_version="openai-2026-08-27",
                effective_at=start,
                expires_at=end,
                source_url="https://developers.openai.com/api/docs/models/gpt-transcribe",
                source_sha256=sha,
            ),
            PriceRecord(
                provider="openai",
                model="tts-1",
                category="tts",
                native_currency="USD",
                input_micro_usd_per_million=15_000_000,
                output_micro_usd_per_million=0,
                audio_micro_usd_per_minute=0,
                web_search_micro_usd_per_call=0,
                primary_accounting_basis="request_bound_exact",
                missing_evidence_policy="freeze_unknown_overage",
                pricing_version="openai-2026-08-27",
                effective_at=start,
                expires_at=end,
                source_url="https://developers.openai.com/api/docs/models/tts-1",
                source_sha256=sha,
            ),
            PriceRecord(
                provider="openai",
                model="gpt-5.6-sol",
                category="web_search",
                native_currency="USD",
                input_micro_usd_per_million=4_000_000,
                output_micro_usd_per_million=20_000_000,
                audio_micro_usd_per_minute=0,
                web_search_micro_usd_per_call=10_000,
                primary_accounting_basis="provider_reported_exact",
                missing_evidence_policy="conservative_full_reservation",
                pricing_version="openai-web-search-2026-08-27",
                effective_at=start,
                expires_at=end,
                source_url="https://developers.openai.com/api/docs/pricing",
                source_sha256=sha,
            ),
            PriceRecord(
                provider="qwen",
                model="qwen3.7-plus",
                category="llm",
                native_currency="USD",
                input_micro_usd_per_million=400_000,
                output_micro_usd_per_million=1_600_000,
                audio_micro_usd_per_minute=0,
                web_search_micro_usd_per_call=0,
                primary_accounting_basis="provider_reported_exact",
                missing_evidence_policy="freeze_unknown_overage",
                pricing_version="qwen3.7-plus-sg-2026-08-28",
                effective_at=start,
                expires_at=end,
                source_url="https://www.alibabacloud.com/help/en/model-studio/model-pricing",
                source_sha256=sha,
                tier_basis="llm_input_tokens",
                tier_min_input_tokens=0,
                tier_max_input_tokens=256_000,
            ),
            PriceRecord(
                provider="qwen",
                model="qwen3.7-plus",
                category="llm",
                native_currency="USD",
                input_micro_usd_per_million=1_200_000,
                output_micro_usd_per_million=4_800_000,
                audio_micro_usd_per_minute=0,
                web_search_micro_usd_per_call=0,
                primary_accounting_basis="provider_reported_exact",
                missing_evidence_policy="freeze_unknown_overage",
                pricing_version="qwen3.7-plus-sg-2026-08-28",
                effective_at=start,
                expires_at=end,
                source_url="https://www.alibabacloud.com/help/en/model-studio/model-pricing",
                source_sha256=sha,
                tier_basis="llm_input_tokens",
                tier_min_input_tokens=256_001,
                tier_max_input_tokens=1_000_000,
            ),
        ),
        fx=FxRecord(
            micros_sgd_per_usd=1_500_000,
            fx_version="bootstrap-2026-08-27",
            effective_at=start,
            expires_at=end,
            source="owner_policy",
            source_sha256="e" * 64,
        ),
    )


class CurrentReviews:
    def require_current(self, uow, provider, model, purpose, now) -> None:
        del uow, provider, model, purpose, now


@pytest.fixture
def provider_reviews() -> CurrentReviews:
    return CurrentReviews()


class CurrentRuntimeProviderIdentities:
    def require_current(self, provider: str) -> RuntimeProviderIdentity:
        assert provider == "openai"
        return RuntimeProviderIdentity(
            project_id_commitment_sha256="a" * 64,
            credential_kind="project_service_account",
            admin_key_present=False,
        )


@pytest.fixture
def runtime_provider_identities() -> CurrentRuntimeProviderIdentities:
    return CurrentRuntimeProviderIdentities()


@pytest.fixture
def budget_evidence(route_clock) -> BudgetEvidenceService:
    return BudgetEvidenceService(b"e" * 32, "budget-evidence-v1", route_clock)
