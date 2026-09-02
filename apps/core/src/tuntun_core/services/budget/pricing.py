from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tuntun_contracts.budget import (
    MAX_CHARGE_MICROS_SGD,
    LlmUsageUnits,
    SttUsageUnits,
    TtsUsageUnits,
    UsageUnits,
    WebSearchUsageUnits,
)
from tuntun_core.services.budget.catalog import PriceCatalog

MAX_AGGREGATE_MICROS_SGD = 9_000_000_000_000_000
MAX_INTERMEDIATE = 1_000_000_000_000_000_000


def checked_add(left: int, right: int, limit: int = MAX_AGGREGATE_MICROS_SGD) -> int:
    if left < 0 or right < 0 or left > limit - right:
        raise OverflowError("budget_arithmetic_out_of_bounds")
    return left + right


def checked_mul(left: int, right: int, limit: int = MAX_AGGREGATE_MICROS_SGD) -> int:
    if left < 0 or right < 0 or (right != 0 and left > limit // right):
        raise OverflowError("budget_arithmetic_out_of_bounds")
    return left * right


def ceil_div(numerator: int, denominator: int) -> int:
    if numerator < 0 or denominator <= 0:
        raise OverflowError("budget_arithmetic_out_of_bounds")
    return (numerator + denominator - 1) // denominator


@dataclass(frozen=True, slots=True)
class PriceTier:
    tier_basis: str
    tier_min_input_tokens: int
    tier_max_input_tokens: int
    category: str
    native_currency: str
    input_micro_usd_per_million: int
    output_micro_usd_per_million: int
    audio_micro_usd_per_minute: int
    web_search_micro_usd_per_call: int

    @classmethod
    def from_record(cls, record: object) -> PriceTier:
        return cls(**{field: getattr(record, field) for field in cls.__dataclass_fields__})

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> PriceTier:
        return cls(**value)

    def __post_init__(self) -> None:
        flat = (
            self.tier_basis == "flat"
            and self.tier_min_input_tokens == self.tier_max_input_tokens == 0
        )
        tiered = (
            self.tier_basis == "llm_input_tokens"
            and self.category == "llm"
            and 0 <= self.tier_min_input_tokens <= self.tier_max_input_tokens <= 10_000_000
        )
        if not (flat or tiered):
            raise ValueError("invalid price tier")


@dataclass(frozen=True, slots=True)
class PriceQuote:
    provider: str
    model: str
    category: str
    amount_micros_sgd: int
    native_currency: str
    input_micro_usd_per_million: int
    output_micro_usd_per_million: int
    audio_micro_usd_per_minute: int
    web_search_micro_usd_per_call: int
    micros_sgd_per_usd: int
    primary_accounting_basis: str
    missing_evidence_policy: str
    pricing_version: str
    price_source_url: str
    price_source_sha256: str
    fx_version: str
    fx_source_sha256: str
    tier_basis: str
    selected_tier_min_input_tokens: int
    selected_tier_max_input_tokens: int
    tier_schedule: tuple[PriceTier, ...]

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> PriceQuote:
        parsed = dict(value)
        parsed["tier_schedule"] = tuple(
            PriceTier.from_mapping(item) for item in parsed["tier_schedule"]
        )
        return cls(**parsed)

    def __post_init__(self) -> None:
        selected = [
            tier
            for tier in self.tier_schedule
            if (
                tier.tier_basis == self.tier_basis
                and tier.tier_min_input_tokens == self.selected_tier_min_input_tokens
                and tier.tier_max_input_tokens == self.selected_tier_max_input_tokens
            )
        ]
        if len(selected) != 1 or (
            selected[0].category,
            selected[0].native_currency,
            selected[0].input_micro_usd_per_million,
            selected[0].output_micro_usd_per_million,
            selected[0].audio_micro_usd_per_minute,
            selected[0].web_search_micro_usd_per_call,
        ) != (
            self.category,
            self.native_currency,
            self.input_micro_usd_per_million,
            self.output_micro_usd_per_million,
            self.audio_micro_usd_per_minute,
            self.web_search_micro_usd_per_call,
        ):
            raise ValueError("price quote selected tier mismatch")


class Pricing:
    def __init__(self, catalog: PriceCatalog, clock: Any) -> None:
        self.catalog = catalog
        self.clock = clock

    @staticmethod
    def _tier_for(schedule: tuple[PriceTier, ...], usage: UsageUnits) -> PriceTier:
        bases = {tier.tier_basis for tier in schedule}
        if bases == {"flat"} and len(schedule) == 1:
            return schedule[0]
        if bases != {"llm_input_tokens"} or not isinstance(usage, LlmUsageUnits):
            raise PermissionError("price_usage_tier_mismatch")
        matches = [
            tier
            for tier in schedule
            if tier.tier_min_input_tokens <= usage.input_tokens <= tier.tier_max_input_tokens
        ]
        if len(matches) != 1:
            raise PermissionError("missing_or_stale_price_tier")
        return matches[0]

    @staticmethod
    def _native(price: PriceTier, usage: UsageUnits) -> int:
        if isinstance(usage, LlmUsageUnits):
            first = ceil_div(
                checked_mul(
                    usage.input_tokens, price.input_micro_usd_per_million, MAX_INTERMEDIATE
                ),
                1_000_000,
            )
            second = ceil_div(
                checked_mul(
                    usage.output_tokens, price.output_micro_usd_per_million, MAX_INTERMEDIATE
                ),
                1_000_000,
            )
        elif isinstance(usage, SttUsageUnits):
            first = ceil_div(
                checked_mul(usage.audio_millis, price.audio_micro_usd_per_minute, MAX_INTERMEDIATE),
                60_000,
            )
            second = 0
        elif isinstance(usage, TtsUsageUnits):
            first = ceil_div(
                checked_mul(usage.characters, price.input_micro_usd_per_million, MAX_INTERMEDIATE),
                1_000_000,
            )
            second = 0
        elif isinstance(usage, WebSearchUsageUnits):
            tokens = checked_add(
                ceil_div(
                    checked_mul(
                        usage.input_tokens, price.input_micro_usd_per_million, MAX_INTERMEDIATE
                    ),
                    1_000_000,
                ),
                ceil_div(
                    checked_mul(
                        usage.output_tokens, price.output_micro_usd_per_million, MAX_INTERMEDIATE
                    ),
                    1_000_000,
                ),
                MAX_INTERMEDIATE,
            )
            calls = checked_mul(
                usage.web_search_calls,
                price.web_search_micro_usd_per_call,
                MAX_INTERMEDIATE,
            )
            first, second = tokens, calls
        else:
            raise TypeError("unknown closed usage type")
        return checked_add(first, second, MAX_INTERMEDIATE)

    @classmethod
    def _amount(cls, price: PriceTier, fx: Any, usage: UsageUnits) -> int:
        if price.category != usage.category or price.native_currency != "USD":
            raise PermissionError("price_usage_purpose_mismatch")
        native = cls._native(price, usage)
        amount = ceil_div(
            checked_mul(native, fx.micros_sgd_per_usd, MAX_INTERMEDIATE),
            1_000_000,
        )
        if not 0 <= amount <= MAX_CHARGE_MICROS_SGD:
            raise OverflowError("budget_arithmetic_out_of_bounds")
        return amount

    def quote(self, provider: str, model: str, usage: UsageUnits) -> PriceQuote:
        now = self.clock.now()
        records = self.catalog.current_prices(provider, model, usage.category, now)
        schedule = tuple(PriceTier.from_record(row) for row in records)
        price = self._tier_for(schedule, usage)
        fx = self.catalog.current_fx(now)
        amount = self._amount(price, fx, usage)
        if amount == 0:
            raise PermissionError("zero_or_unpriced_usage_ceiling")
        return PriceQuote(
            provider=provider,
            model=model,
            category=usage.category,
            amount_micros_sgd=amount,
            native_currency=price.native_currency,
            input_micro_usd_per_million=price.input_micro_usd_per_million,
            output_micro_usd_per_million=price.output_micro_usd_per_million,
            audio_micro_usd_per_minute=price.audio_micro_usd_per_minute,
            web_search_micro_usd_per_call=price.web_search_micro_usd_per_call,
            micros_sgd_per_usd=fx.micros_sgd_per_usd,
            primary_accounting_basis=records[0].primary_accounting_basis,
            missing_evidence_policy=records[0].missing_evidence_policy,
            pricing_version=records[0].pricing_version,
            price_source_url=records[0].source_url,
            price_source_sha256=records[0].source_sha256,
            fx_version=fx.fx_version,
            fx_source_sha256=fx.source_sha256,
            tier_basis=price.tier_basis,
            selected_tier_min_input_tokens=price.tier_min_input_tokens,
            selected_tier_max_input_tokens=price.tier_max_input_tokens,
            tier_schedule=schedule,
        )

    def amount_from_snapshot(self, snapshot: PriceQuote, usage: UsageUnits) -> int:
        tier = self._tier_for(snapshot.tier_schedule, usage)
        return self._amount(tier, snapshot, usage)
