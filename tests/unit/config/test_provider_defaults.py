from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

PROJECT_ROOT = Path(__file__).parents[3]


def _valid_provider_defaults() -> dict[str, object]:
    return {
        "schema_version": "tuntun.provider-defaults.v1",
        "budget": {
            "timezone": "Asia/Singapore",
            "soft_limit_micros_sgd": 100_000_000,
            "hard_limit_micros_sgd": 150_000_000,
            "reservation_expiry_seconds": 900,
        },
        "providers": {
            "openai": {
                "sdk_retries": 0,
                "telemetry_enabled": False,
                "dedicated_project_required": True,
                "provider_hard_limit": {
                    "currency": "USD",
                    "interval": "provider_month",
                    "maximum_threshold_micros_usd": 100_000_000,
                    "enforcement_status": "enforcing",
                    "runtime_admin_key_forbidden": True,
                },
            },
        },
    }


def _mutated(path: tuple[str, ...], value: object) -> dict[str, object]:
    payload = deepcopy(_valid_provider_defaults())
    cursor: dict[str, Any] = payload
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    return payload


def test_checked_in_provider_defaults_manifest_loads() -> None:
    from tuntun_core.services.providers.defaults import load_provider_defaults

    document = load_provider_defaults(PROJECT_ROOT / "config/providers/default.yaml")

    assert document.schema_version == "tuntun.provider-defaults.v1"
    assert document.budget.timezone == "Asia/Singapore"
    assert (
        document.budget.soft_limit_micros_sgd,
        document.budget.hard_limit_micros_sgd,
        document.budget.reservation_expiry_seconds,
    ) == (100_000_000, 150_000_000, 900)
    assert document.providers.openai.sdk_retries == 0
    assert document.providers.openai.telemetry_enabled is False
    assert document.providers.openai.dedicated_project_required is True
    assert document.providers.openai.provider_hard_limit.maximum_threshold_micros_usd == 100_000_000


def test_provider_defaults_loader_reads_public_bounded_yaml(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from tuntun_core.services.providers import defaults

    manifest = tmp_path / "defaults.yaml"
    calls: list[tuple[Path, int, bool]] = []

    def fake_read_bounded_strict_yaml(
        path: Path,
        *,
        max_bytes: int,
        require_private: bool,
    ) -> object:
        calls.append((path, max_bytes, require_private))
        return _valid_provider_defaults()

    monkeypatch.setattr(defaults, "read_bounded_strict_yaml", fake_read_bounded_strict_yaml)

    document = defaults.load_provider_defaults(manifest)

    assert document.budget.reservation_expiry_seconds == 900
    assert calls == [(manifest, defaults.MAX_PROVIDER_DEFAULTS_BYTES, False)]


@pytest.mark.parametrize(
    "payload",
    (
        _mutated(("schema_version",), "tuntun.provider-defaults.v0"),
        _mutated(("budget", "timezone"), "UTC"),
        _mutated(("budget", "soft_limit_micros_sgd"), 150_000_001),
        _mutated(("budget", "hard_limit_micros_sgd"), 150_000_001),
        _mutated(("budget", "reservation_expiry_seconds"), 0),
        _mutated(("budget", "reservation_expiry_seconds"), 901),
        _mutated(("providers", "openai", "sdk_retries"), 1),
        _mutated(("providers", "openai", "telemetry_enabled"), True),
        _mutated(("providers", "openai", "dedicated_project_required"), False),
        _mutated(("providers", "openai", "provider_hard_limit", "currency"), "SGD"),
        _mutated(("providers", "openai", "provider_hard_limit", "interval"), "month"),
        _mutated(("providers", "openai", "provider_hard_limit", "enforcement_status"), "audit"),
        _mutated(
            ("providers", "openai", "provider_hard_limit", "maximum_threshold_micros_usd"),
            100_000_001,
        ),
        _mutated(
            ("providers", "openai", "provider_hard_limit", "maximum_threshold_micros_usd"),
            99_999_999,
        ),
        _mutated(
            ("providers", "openai", "provider_hard_limit", "runtime_admin_key_forbidden"),
            False,
        ),
        _valid_provider_defaults() | {"unexpected": True},
        _valid_provider_defaults() | {"budget": {"reservation_expires_seconds": 900}},
    ),
)
def test_provider_defaults_reject_unknown_misspelled_or_unsafe_fields(
    payload: dict[str, object],
) -> None:
    from tuntun_core.services.providers.defaults import ProviderDefaultsDocumentV1

    with pytest.raises(ValidationError):
        ProviderDefaultsDocumentV1.model_validate(payload, strict=True)


def test_provider_defaults_require_soft_limit_not_above_hard_limit() -> None:
    from tuntun_core.services.providers.defaults import ProviderDefaultsDocumentV1

    payload = _mutated(("budget", "soft_limit_micros_sgd"), 100)
    payload["budget"]["hard_limit_micros_sgd"] = 99

    with pytest.raises(ValidationError, match="hard limit must be at least soft limit"):
        ProviderDefaultsDocumentV1.model_validate(payload, strict=True)
