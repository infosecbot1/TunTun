from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import AwareDatetime, Field, field_validator
from tuntun_contracts.base import ContractModel
from tuntun_core.config.loader import read_bounded_strict_yaml
from tuntun_core.services.storage_time import parse_utc_storage

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
MAX_RATE_MICROS_USD = 1_000_000_000
MAX_FX_MICROS_SGD_PER_USD = 10_000_000


class PriceCatalogRowV1(ContractModel):
    provider: Literal["openai", "qwen"]
    model: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")]
    category: Literal["stt", "llm", "tts", "web_search"]
    native_currency: Literal["USD"]
    input_micro_usd_per_million: Annotated[int, Field(ge=0, le=MAX_RATE_MICROS_USD)]
    output_micro_usd_per_million: Annotated[int, Field(ge=0, le=MAX_RATE_MICROS_USD)]
    audio_micro_usd_per_minute: Annotated[int, Field(ge=0, le=MAX_RATE_MICROS_USD)]
    web_search_micro_usd_per_call: Annotated[int, Field(ge=0, le=MAX_RATE_MICROS_USD)]
    primary_accounting_basis: Literal["provider_reported_exact", "request_bound_exact"]
    missing_evidence_policy: Literal["freeze_unknown_overage", "conservative_full_reservation"]
    source_url: Annotated[str, Field(min_length=8, max_length=512)]
    source_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    tier_basis: Literal["flat", "llm_input_tokens"] = "flat"
    tier_min_input_tokens: Annotated[int, Field(ge=0, le=10_000_000)] = 0
    tier_max_input_tokens: Annotated[int, Field(ge=0, le=10_000_000)] = 0


class PriceCatalogDocumentV1(ContractModel):
    pricing_version: Annotated[str, Field(min_length=1, max_length=128)]
    retrieved_at: AwareDatetime
    expires_at: AwareDatetime
    records: Annotated[tuple[PriceCatalogRowV1, ...], Field(min_length=1, max_length=64)]

    @field_validator("records", mode="before")
    @classmethod
    def exact_records_tuple(cls, value: Any) -> Any:
        if isinstance(value, list):
            return tuple(value)
        return value

    @field_validator("retrieved_at", "expires_at", mode="before")
    @classmethod
    def exact_utc_strings(cls, value: object) -> datetime:
        if type(value) is not str:
            raise ValueError("stored timestamp must be canonical UTC")
        return parse_utc_storage(value)


class FxCatalogDocumentV1(ContractModel):
    micros_sgd_per_usd: Annotated[int, Field(ge=1, le=MAX_FX_MICROS_SGD_PER_USD)]
    fx_version: Annotated[str, Field(min_length=1, max_length=128)]
    effective_at: AwareDatetime
    expires_at: AwareDatetime
    source: Annotated[str, Field(min_length=1, max_length=512)]
    source_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    @field_validator("effective_at", "expires_at", mode="before")
    @classmethod
    def exact_utc_strings(cls, value: object) -> datetime:
        if type(value) is not str:
            raise ValueError("stored timestamp must be canonical UTC")
        return parse_utc_storage(value)


def _valid_interval(effective_at: datetime, expires_at: datetime) -> bool:
    return (
        effective_at.tzinfo is not None
        and expires_at.tzinfo is not None
        and effective_at < expires_at
    )


@dataclass(frozen=True, slots=True)
class PriceRecord:
    provider: str
    model: str
    category: str
    native_currency: str
    input_micro_usd_per_million: int
    output_micro_usd_per_million: int
    audio_micro_usd_per_minute: int
    web_search_micro_usd_per_call: int
    primary_accounting_basis: str
    missing_evidence_policy: str
    pricing_version: str
    effective_at: datetime
    expires_at: datetime
    source_url: str
    source_sha256: str
    tier_basis: str = "flat"
    tier_min_input_tokens: int = 0
    tier_max_input_tokens: int = 0

    def __post_init__(self) -> None:
        rates = (
            self.input_micro_usd_per_million,
            self.output_micro_usd_per_million,
            self.audio_micro_usd_per_minute,
            self.web_search_micro_usd_per_call,
        )
        flat_tier = (
            self.tier_basis == "flat"
            and self.tier_min_input_tokens == self.tier_max_input_tokens == 0
        )
        token_tier = (
            self.tier_basis == "llm_input_tokens"
            and self.category == "llm"
            and 0 <= self.tier_min_input_tokens <= self.tier_max_input_tokens <= 10_000_000
        )
        source = urlsplit(self.source_url)
        if (
            self.provider not in {"openai", "qwen"}
            or not self.model
            or self.category not in {"stt", "llm", "tts", "web_search"}
            or self.native_currency != "USD"
            or not self.pricing_version
            or self.primary_accounting_basis
            not in {"provider_reported_exact", "request_bound_exact"}
            or self.missing_evidence_policy
            not in {"freeze_unknown_overage", "conservative_full_reservation"}
            or any(not 0 <= rate <= MAX_RATE_MICROS_USD for rate in rates)
            or not any(rates)
            or not _valid_interval(self.effective_at, self.expires_at)
            or source.scheme != "https"
            or not source.hostname
            or source.username is not None
            or source.password is not None
            or source.port not in {None, 443}
            or source.query
            or source.fragment
            or _DIGEST.fullmatch(self.source_sha256) is None
            or not (flat_tier or token_tier)
            or (
                self.category == "tts"
                and (
                    self.primary_accounting_basis != "request_bound_exact"
                    or self.input_micro_usd_per_million <= 0
                    or self.output_micro_usd_per_million != 0
                    or self.audio_micro_usd_per_minute != 0
                    or self.web_search_micro_usd_per_call != 0
                )
            )
            or (
                self.category == "web_search"
                and (
                    self.primary_accounting_basis != "provider_reported_exact"
                    or self.missing_evidence_policy != "conservative_full_reservation"
                    or self.input_micro_usd_per_million <= 0
                    or self.output_micro_usd_per_million <= 0
                    or self.audio_micro_usd_per_minute != 0
                    or self.web_search_micro_usd_per_call <= 0
                )
            )
            or (
                self.category == "stt"
                and (
                    self.primary_accounting_basis != "provider_reported_exact"
                    or self.missing_evidence_policy != "freeze_unknown_overage"
                    or self.input_micro_usd_per_million != 0
                    or self.output_micro_usd_per_million != 0
                    or self.audio_micro_usd_per_minute <= 0
                    or self.web_search_micro_usd_per_call != 0
                )
            )
            or (
                self.category == "llm"
                and (
                    self.primary_accounting_basis != "provider_reported_exact"
                    or self.missing_evidence_policy != "freeze_unknown_overage"
                    or self.input_micro_usd_per_million <= 0
                    or self.output_micro_usd_per_million <= 0
                    or self.audio_micro_usd_per_minute != 0
                    or self.web_search_micro_usd_per_call != 0
                )
            )
        ):
            raise ValueError("invalid provider price/source digest")


@dataclass(frozen=True, slots=True)
class FxRecord:
    micros_sgd_per_usd: int
    fx_version: str
    effective_at: datetime
    expires_at: datetime
    source: str
    source_sha256: str

    def __post_init__(self) -> None:
        if (
            not 1 <= self.micros_sgd_per_usd <= MAX_FX_MICROS_SGD_PER_USD
            or not self.fx_version
            or not self.source
            or not _valid_interval(self.effective_at, self.expires_at)
            or _DIGEST.fullmatch(self.source_sha256) is None
        ):
            raise ValueError("invalid FX/source digest")


@dataclass(frozen=True, slots=True)
class PriceCatalog:
    prices: tuple[PriceRecord, ...]
    fx: FxRecord | None

    def __post_init__(self) -> None:
        identities = [
            (
                row.provider,
                row.model,
                row.category,
                row.pricing_version,
                row.tier_basis,
                row.tier_min_input_tokens,
                row.tier_max_input_tokens,
            )
            for row in self.prices
        ]
        if len(identities) != len(set(identities)):
            raise ValueError("duplicate provider price identity")
        groups: dict[tuple[str, str, str, str], list[PriceRecord]] = {}
        for row in self.prices:
            groups.setdefault(
                (row.provider, row.model, row.category, row.pricing_version),
                [],
            ).append(row)
        for rows in groups.values():
            bases = {row.tier_basis for row in rows}
            common = {
                (
                    row.native_currency,
                    row.primary_accounting_basis,
                    row.missing_evidence_policy,
                    row.effective_at,
                    row.expires_at,
                    row.source_url,
                    row.source_sha256,
                )
                for row in rows
            }
            ordered = sorted(rows, key=lambda row: row.tier_min_input_tokens)
            contiguous = ordered[0].tier_min_input_tokens == 0 and all(
                right.tier_min_input_tokens == left.tier_max_input_tokens + 1
                for left, right in zip(ordered, ordered[1:], strict=False)
            )
            if (
                len(common) != 1
                or (bases == {"flat"} and len(rows) != 1)
                or (bases == {"llm_input_tokens"} and not contiguous)
                or bases not in ({"flat"}, {"llm_input_tokens"})
            ):
                raise ValueError("invalid provider price tier schedule")

    @classmethod
    def load(cls, price_path: Path, fx_path: Path) -> PriceCatalog:
        return cls.load_many((price_path,), fx_path)

    @classmethod
    def load_many(cls, price_paths: tuple[Path, ...], fx_path: Path) -> PriceCatalog:
        if not 1 <= len(price_paths) <= 16 or len(set(price_paths)) != len(price_paths):
            raise ValueError("price catalog file set invalid")
        fx_doc = FxCatalogDocumentV1.model_validate(
            read_bounded_strict_yaml(fx_path, max_bytes=65_536),
            strict=True,
        )
        prices: list[PriceRecord] = []
        for price_path in price_paths:
            price_doc = PriceCatalogDocumentV1.model_validate(
                read_bounded_strict_yaml(price_path, max_bytes=262_144),
                strict=True,
            )
            effective = price_doc.retrieved_at
            expiry = price_doc.expires_at
            prices.extend(
                PriceRecord(
                    provider=row.provider,
                    model=row.model,
                    category=row.category,
                    native_currency=row.native_currency,
                    input_micro_usd_per_million=row.input_micro_usd_per_million,
                    output_micro_usd_per_million=row.output_micro_usd_per_million,
                    audio_micro_usd_per_minute=row.audio_micro_usd_per_minute,
                    web_search_micro_usd_per_call=row.web_search_micro_usd_per_call,
                    primary_accounting_basis=row.primary_accounting_basis,
                    missing_evidence_policy=row.missing_evidence_policy,
                    pricing_version=price_doc.pricing_version,
                    effective_at=effective,
                    expires_at=expiry,
                    source_url=row.source_url,
                    source_sha256=row.source_sha256,
                    tier_basis=row.tier_basis,
                    tier_min_input_tokens=row.tier_min_input_tokens,
                    tier_max_input_tokens=row.tier_max_input_tokens,
                )
                for row in price_doc.records
            )
        fx = FxRecord(
            micros_sgd_per_usd=fx_doc.micros_sgd_per_usd,
            fx_version=fx_doc.fx_version,
            effective_at=fx_doc.effective_at,
            expires_at=fx_doc.expires_at,
            source=fx_doc.source,
            source_sha256=fx_doc.source_sha256,
        )
        return cls(prices=tuple(prices), fx=fx)

    def current_prices(
        self, provider: str, model: str, category: str, now: datetime
    ) -> tuple[PriceRecord, ...]:
        rows = [
            row
            for row in self.prices
            if (
                row.provider == provider
                and row.model == model
                and row.category == category
                and row.effective_at <= now < row.expires_at
            )
        ]
        schedules = {
            (
                row.pricing_version,
                row.source_url,
                row.source_sha256,
                row.effective_at,
                row.expires_at,
                row.primary_accounting_basis,
                row.missing_evidence_policy,
                row.tier_basis,
            )
            for row in rows
        }
        if not rows or len(schedules) != 1:
            raise PermissionError("missing_or_stale_price")
        return tuple(sorted(rows, key=lambda row: row.tier_min_input_tokens))

    def current_fx(self, now: datetime) -> FxRecord:
        if self.fx is None or not self.fx.effective_at <= now < self.fx.expires_at:
            raise PermissionError("missing_or_stale_fx")
        return self.fx

    def without_price(self) -> PriceCatalog:
        return replace(self, prices=())

    def with_expired_price(self) -> PriceCatalog:
        return replace(
            self,
            prices=tuple(
                replace(row, expires_at=row.effective_at + timedelta(microseconds=1))
                for row in self.prices
            ),
        )

    def without_fx(self) -> PriceCatalog:
        return replace(self, fx=None)

    def with_expired_fx(self) -> PriceCatalog:
        return replace(
            self,
            fx=None
            if self.fx is None
            else replace(self.fx, expires_at=self.fx.effective_at + timedelta(microseconds=1)),
        )

    def with_expiry_equal(self, now: datetime) -> PriceCatalog:
        return replace(
            self,
            prices=tuple(replace(row, expires_at=now) for row in self.prices),
        )

    def with_cross_provider_collision(
        self,
        provider: str,
        model: str,
        input_micro_usd_per_million: int,
    ) -> PriceCatalog:
        source = next(row for row in self.prices if row.model == model)
        return replace(
            self,
            prices=(
                *self.prices,
                replace(
                    source,
                    provider=provider,
                    input_micro_usd_per_million=input_micro_usd_per_million,
                    pricing_version=f"{provider}-collision",
                ),
            ),
        )

    def with_price_source_digest(self, digest: str) -> PriceCatalog:
        return replace(
            self,
            prices=(replace(self.prices[0], source_sha256=digest), *self.prices[1:]),
        )

    def with_fx_source_digest(self, digest: str) -> PriceCatalog:
        return replace(
            self,
            fx=None if self.fx is None else replace(self.fx, source_sha256=digest),
        )
