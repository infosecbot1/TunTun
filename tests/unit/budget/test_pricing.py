from __future__ import annotations

import shutil
from dataclasses import replace
from pathlib import Path

import pytest
from tuntun_contracts.budget import LlmUsageUnits, SttUsageUnits, TtsUsageUnits, WebSearchUsageUnits
from tuntun_core.services.budget.catalog import PriceCatalog
from tuntun_core.services.budget.pricing import Pricing

pytest_plugins = ("tests.fixtures.provider_egress",)


def test_exact_native_and_fx_integer_formulas(catalog, route_clock) -> None:
    pricing = Pricing(catalog, route_clock)
    assert (
        pricing.quote(
            "openai",
            "gpt-5.6-sol",
            LlmUsageUnits(category="llm", input_tokens=1_000_000, output_tokens=1_000_000),
        ).amount_micros_sgd
        == 36_000_000
    )
    assert (
        pricing.quote(
            "openai",
            "gpt-transcribe",
            SttUsageUnits(category="stt", audio_millis=60_000),
        ).amount_micros_sgd
        == 6_750
    )
    assert (
        pricing.quote(
            "openai", "tts-1", TtsUsageUnits(category="tts", characters=4_096)
        ).amount_micros_sgd
        == 92_160
    )
    search = pricing.quote(
        "openai",
        "gpt-5.6-sol",
        WebSearchUsageUnits(
            category="web_search",
            input_tokens=1_000_000,
            output_tokens=1_000_000,
            web_search_calls=1,
        ),
    )
    assert search.amount_micros_sgd == 36_015_000
    assert search.web_search_micro_usd_per_call == 10_000


def test_checked_in_catalog_loads_only_exact_quoted_utc_timestamps(tmp_path: Path) -> None:
    price_path = tmp_path / "openai-prices.yaml"
    fx_path = tmp_path / "fx.yaml"
    shutil.copyfile("config/providers/prices/openai-2026-08-27.yaml", price_path)
    shutil.copyfile(
        "config/providers/fx/bootstrap-safety-factor-2026-08-27.yaml",
        fx_path,
    )
    price_path.chmod(0o600)
    fx_path.chmod(0o600)
    loaded = PriceCatalog.load(
        price_path,
        fx_path,
    )
    assert len(loaded.prices) == 3
    assert all(row.category in {"llm", "stt", "tts"} for row in loaded.prices)


@pytest.mark.parametrize(
    "mutation", ("duplicate_key", "unknown_key", "bool_rate", "oversize", "symlink")
)
def test_price_and_fx_control_files_are_frozen_strict_and_bounded(tmp_path, mutation) -> None:
    source = Path("config/providers/prices/openai-2026-08-27.yaml")
    price = tmp_path / "price.yaml"
    fx = tmp_path / "fx.yaml"
    shutil.copyfile(source, price)
    shutil.copyfile("config/providers/fx/bootstrap-safety-factor-2026-08-27.yaml", fx)
    if mutation == "duplicate_key":
        price.write_text(price.read_text() + "\npricing_version: duplicate\n")
    elif mutation == "unknown_key":
        price.write_text(price.read_text() + "\ncaller_rate: 1\n")
    elif mutation == "bool_rate":
        price.write_text(
            price.read_text().replace(
                "input_micro_usd_per_million: 4000000",
                "input_micro_usd_per_million: true",
                1,
            )
        )
    elif mutation == "oversize":
        price.write_bytes(b"x" * 262_145)
    else:
        target = tmp_path / "actual.yaml"
        price.replace(target)
        price.symlink_to(target)
    with pytest.raises((PermissionError, ValueError)):
        PriceCatalog.load(price, fx)


def test_qwen_input_token_tiers_are_exact_and_snapshot_reselects_actual(
    catalog, route_clock
) -> None:
    pricing = Pricing(catalog, route_clock)
    low = pricing.quote(
        "qwen",
        "qwen3.7-plus",
        LlmUsageUnits(category="llm", input_tokens=256_000, output_tokens=1),
    )
    high = pricing.quote(
        "qwen",
        "qwen3.7-plus",
        LlmUsageUnits(category="llm", input_tokens=256_001, output_tokens=1),
    )
    top = pricing.quote(
        "qwen",
        "qwen3.7-plus",
        LlmUsageUnits(category="llm", input_tokens=1_000_000, output_tokens=0),
    )
    assert (low.input_micro_usd_per_million, low.output_micro_usd_per_million) == (
        400_000,
        1_600_000,
    )
    assert (high.input_micro_usd_per_million, high.output_micro_usd_per_million) == (
        1_200_000,
        4_800_000,
    )
    assert (low.amount_micros_sgd, high.amount_micros_sgd, top.amount_micros_sgd) == (
        153_603,
        460_811,
        1_800_000,
    )
    assert (
        pricing.amount_from_snapshot(
            high,
            LlmUsageUnits(category="llm", input_tokens=256_000, output_tokens=0),
        )
        == 153_600
    )
    with pytest.raises(PermissionError, match="missing_or_stale_price_tier"):
        pricing.quote(
            "qwen",
            "qwen3.7-plus",
            LlmUsageUnits(category="llm", input_tokens=1_000_001, output_tokens=0),
        )


@pytest.mark.parametrize("mutation", ("gap", "overlap", "mixed_source"))
def test_qwen_tier_schedule_gap_overlap_or_source_substitution_is_rejected(
    catalog, mutation
) -> None:
    qwen = [row for row in catalog.prices if row.provider == "qwen"]
    other = tuple(row for row in catalog.prices if row.provider != "qwen")
    changed = replace(
        qwen[1],
        tier_min_input_tokens=(256_002 if mutation == "gap" else 256_000),
        source_sha256=("f" * 64 if mutation == "mixed_source" else qwen[1].source_sha256),
    )
    if mutation == "mixed_source":
        changed = replace(changed, tier_min_input_tokens=256_001)
    with pytest.raises(ValueError, match="tier schedule"):
        PriceCatalog(prices=(*other, qwen[0], changed), fx=catalog.fx)


def test_missing_stale_price_or_fx_denies(catalog, route_clock) -> None:
    usage = LlmUsageUnits(category="llm", input_tokens=1, output_tokens=1)
    for mutation in (
        catalog.without_price(),
        catalog.with_expired_price(),
        catalog.without_fx(),
        catalog.with_expired_fx(),
        catalog.with_expiry_equal(route_clock.now()),
    ):
        with pytest.raises(PermissionError, match="missing_or_stale_(price|fx)"):
            Pricing(mutation, route_clock).quote("openai", "gpt-5.6-sol", usage)


def test_provider_is_part_of_price_identity_and_digests_are_canonical(catalog, route_clock) -> None:
    collision = catalog.with_cross_provider_collision(
        provider="qwen",
        model="gpt-5.6-sol",
        input_micro_usd_per_million=1,
    )
    openai = Pricing(collision, route_clock).quote(
        "openai",
        "gpt-5.6-sol",
        LlmUsageUnits(category="llm", input_tokens=1, output_tokens=0),
    )
    assert openai.amount_micros_sgd == 6
    assert openai.provider == "openai"
    assert len(openai.price_source_sha256) == len(openai.fx_source_sha256) == 64
    with pytest.raises(PermissionError, match="missing_or_stale_price"):
        Pricing(catalog, route_clock).quote(
            "qwen",
            "gpt-5.6-sol",
            LlmUsageUnits(category="llm", input_tokens=1, output_tokens=0),
        )


@pytest.mark.parametrize("digest", ("D" * 64, "g" * 64, "d" * 63, "d" * 65))
@pytest.mark.parametrize("target", ("price", "fx"))
def test_noncanonical_price_or_fx_digest_is_rejected(catalog, digest, target) -> None:
    with pytest.raises(ValueError, match="source digest"):
        getattr(catalog, f"with_{target}_source_digest")(digest)
