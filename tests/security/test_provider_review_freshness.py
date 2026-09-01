from __future__ import annotations

import asyncio
import hashlib
import json
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from tuntun_contracts.base import canonical_mapping_bytes
from tuntun_core.adapters.sqlcipher.unit_of_work import UnitOfWork
from tuntun_core.services.providers.review import (
    ProviderReviewStore,
    RuntimeProviderIdentity,
)

from tests.fixtures.provider_routes import RouteDatabase

NOW = datetime(2026, 8, 27, 1, 2, 3, 4, tzinfo=UTC)


class RuntimeIdentities:
    def __init__(self, identity: RuntimeProviderIdentity) -> None:
        self.identity = identity

    def require_current(self, provider: str) -> RuntimeProviderIdentity:
        if provider != "openai":
            raise PermissionError("provider_review_not_current")
        return self.identity


def _recommit_hard_limit(value: dict[str, object]) -> None:
    committed = {
        key: value[key]
        for key in (
            "project_id_commitment_sha256",
            "threshold_micros_usd",
            "currency",
            "interval",
            "enforcement_status",
            "dashboard_evidence_sha256",
        )
    }
    value["settings_commitment_sha256"] = hashlib.sha256(
        canonical_mapping_bytes(committed)
    ).hexdigest()


def _valid_review() -> dict[str, object]:
    hard_limit: dict[str, object] = {
        "project_id_commitment_sha256": "a" * 64,
        "threshold_micros_usd": 100_000_000,
        "currency": "USD",
        "interval": "provider_month",
        "enforcement_status": "enforcing",
        "dashboard_evidence_sha256": "b" * 64,
        "settings_commitment_sha256": "0" * 64,
        "runtime_credential_kind": "project_service_account",
        "runtime_admin_key_present": False,
    }
    _recommit_hard_limit(hard_limit)
    return {
        "schema_version": "tuntun.provider-review.v1",
        "provider": "openai",
        "accepted": True,
        "expires_at": (NOW + timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "source_changed": False,
        "dashboard_changed": False,
        "purposes": ["cloud_stt", "cloud_reasoning", "cloud_tts"],
        "models": ["gpt-5.6-sol"],
        "endpoint": "https://api.openai.com/v1",
        "workspace_id": None,
        "region": "global",
        "review_version": 1,
        "source_sha256": "c" * 64,
        "provider_hard_limit": hard_limit,
    }


def _identity() -> RuntimeProviderIdentity:
    return RuntimeProviderIdentity(
        project_id_commitment_sha256="a" * 64,
        credential_kind="project_service_account",
        admin_key_present=False,
    )


def _insert_review(
    database: RouteDatabase,
    raw: str,
    *,
    updated_at: datetime = NOW,
) -> None:
    with UnitOfWork(database.engine) as uow:
        uow.exec_driver_sql(
            "INSERT INTO runtime_settings(key,value_json,version,updated_at) VALUES(?,?,1,?)",
            (
                "provider.review.openai",
                raw,
                updated_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            ),
        )
        uow.commit()


def _require_current(
    database: RouteDatabase,
    identity: RuntimeProviderIdentity,
    *,
    now: datetime = NOW,
    model: str = "gpt-5.6-sol",
    purpose: str = "cloud_reasoning",
) -> None:
    with UnitOfWork(database.engine) as uow:
        ProviderReviewStore(uow, RuntimeIdentities(identity)).require_current(
            "openai",
            model,
            purpose,
            now,
        )
        uow.rollback()


def test_current_canonical_openai_review_is_accepted(route_database: RouteDatabase) -> None:
    value = _valid_review()
    _insert_review(route_database, canonical_mapping_bytes(value).decode("utf-8"))

    _require_current(route_database, _identity())


@pytest.mark.parametrize(
    ("model", "purpose"),
    [
        ("gpt-5.6-sol", "cloud_stt"),
        ("tts-1", "cloud_reasoning"),
        ("gpt-transcribe", "cloud_reasoning"),
        ("gpt-5.6-sol", "cloud_tts"),
        ("gpt-transcribe", "cloud_tts"),
        ("tts-1", "cloud_stt"),
    ],
)
def test_openai_review_rejects_invalid_purpose_model_cross_products(
    route_database: RouteDatabase,
    model: str,
    purpose: str,
) -> None:
    value = _valid_review()
    value["models"] = ["gpt-transcribe", "gpt-5.6-sol", "tts-1"]
    _insert_review(route_database, canonical_mapping_bytes(value).decode("utf-8"))

    with pytest.raises(PermissionError, match="provider_review_not_current"):
        _require_current(
            route_database,
            _identity(),
            model=model,
            purpose=purpose,
        )


@pytest.mark.parametrize(
    ("model", "purpose"),
    [
        ("gpt-transcribe", "cloud_stt"),
        ("gpt-5.6-sol", "cloud_reasoning"),
        ("tts-1", "cloud_tts"),
    ],
)
def test_openai_review_accepts_every_frozen_purpose_model_pair(
    route_database: RouteDatabase,
    model: str,
    purpose: str,
) -> None:
    value = _valid_review()
    value["models"] = ["gpt-transcribe", "gpt-5.6-sol", "tts-1"]
    _insert_review(route_database, canonical_mapping_bytes(value).decode("utf-8"))

    _require_current(
        route_database,
        _identity(),
        model=model,
        purpose=purpose,
    )


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("accepted",), False),
        (("source_changed",), True),
        (("dashboard_changed",), True),
        (("purposes",), ["cloud_stt", "cloud_tts"]),
        (("purposes",), ["cloud_reasoning", "cloud_reasoning"]),
        (("models",), ["other-model"]),
        (("models",), ["gpt-5.6-sol", "gpt-5.6-sol"]),
        (("endpoint",), "https://example.com/v1"),
        (("workspace_id",), "workspace"),
        (("region",), "ap-southeast-1"),
        (("provider_hard_limit", "threshold_micros_usd"), 100_000_001),
        (("provider_hard_limit", "currency"), "SGD"),
        (("provider_hard_limit", "interval"), "rolling_30d"),
        (("provider_hard_limit", "enforcement_status"), "warning_only"),
        (("provider_hard_limit", "runtime_admin_key_present"), True),
        (("provider_hard_limit", "runtime_credential_kind"), "project_admin"),
        (("provider_hard_limit", "dashboard_evidence_sha256"), "d" * 64),
        (("provider_hard_limit", "settings_commitment_sha256"), "e" * 64),
    ],
)
def test_review_policy_or_evidence_drift_fails_closed(
    route_database: RouteDatabase,
    path: tuple[str, ...],
    replacement: object,
) -> None:
    value = deepcopy(_valid_review())
    target = value
    for key in path[:-1]:
        nested = target[key]
        assert isinstance(nested, dict)
        target = nested
    target[path[-1]] = replacement
    _insert_review(route_database, canonical_mapping_bytes(value).decode("utf-8"))

    with pytest.raises(PermissionError, match="provider_review_not_current"):
        _require_current(route_database, _identity())


def test_self_consistent_wrong_project_still_fails_runtime_binding(
    route_database: RouteDatabase,
) -> None:
    value = _valid_review()
    hard_limit = value["provider_hard_limit"]
    assert isinstance(hard_limit, dict)
    hard_limit["project_id_commitment_sha256"] = "d" * 64
    _recommit_hard_limit(hard_limit)
    _insert_review(route_database, canonical_mapping_bytes(value).decode("utf-8"))

    with pytest.raises(PermissionError, match="provider_review_not_current"):
        _require_current(route_database, _identity())


def test_runtime_admin_or_wrong_credential_fails_closed(route_database: RouteDatabase) -> None:
    _insert_review(
        route_database,
        canonical_mapping_bytes(_valid_review()).decode("utf-8"),
    )

    for identity in (
        replace(_identity(), admin_key_present=True),
        replace(_identity(), credential_kind="project_admin"),
    ):
        with pytest.raises(PermissionError, match="provider_review_not_current"):
            _require_current(route_database, identity)


def test_malformed_runtime_identity_fails_closed(route_database: RouteDatabase) -> None:
    _insert_review(
        route_database,
        canonical_mapping_bytes(_valid_review()).decode("utf-8"),
    )
    malformed = (
        RuntimeProviderIdentity(  # type: ignore[arg-type]
            project_id_commitment_sha256=1,
            credential_kind="project_service_account",
            admin_key_present=False,
        ),
        RuntimeProviderIdentity(  # type: ignore[arg-type]
            project_id_commitment_sha256="a" * 64,
            credential_kind=1,
            admin_key_present=False,
        ),
        RuntimeProviderIdentity(  # type: ignore[arg-type]
            project_id_commitment_sha256="a" * 64,
            credential_kind="project_service_account",
            admin_key_present=0,
        ),
    )

    for identity in malformed:
        with pytest.raises(PermissionError, match="provider_review_not_current"):
            _require_current(route_database, identity)


def test_runtime_identity_cancellation_propagates(route_database: RouteDatabase) -> None:
    class CancelledIdentities:
        def require_current(self, provider: str) -> RuntimeProviderIdentity:
            del provider
            raise asyncio.CancelledError

    _insert_review(
        route_database,
        canonical_mapping_bytes(_valid_review()).decode("utf-8"),
    )
    with UnitOfWork(route_database.engine) as uow, pytest.raises(asyncio.CancelledError):
        ProviderReviewStore(uow, CancelledIdentities()).require_current(
            "openai",
            "gpt-5.6-sol",
            "cloud_reasoning",
            NOW,
        )


def test_runtime_identity_failure_is_sanitized(route_database: RouteDatabase) -> None:
    class FailingIdentities:
        def require_current(self, provider: str) -> RuntimeProviderIdentity:
            del provider
            raise RuntimeError("raw-project-id=secret-project")

    _insert_review(
        route_database,
        canonical_mapping_bytes(_valid_review()).decode("utf-8"),
    )
    with (
        UnitOfWork(route_database.engine) as uow,
        pytest.raises(
            PermissionError,
            match="provider_review_not_current",
        ) as captured,
    ):
        ProviderReviewStore(uow, FailingIdentities()).require_current(
            "openai",
            "gpt-5.6-sol",
            "cloud_reasoning",
            NOW,
        )

    assert captured.value.__cause__ is None
    assert "secret-project" not in str(captured.value)


def test_missing_malformed_noncanonical_or_extra_key_review_fails_closed(
    route_database: RouteDatabase,
) -> None:
    with pytest.raises(PermissionError, match="provider_review_not_current"):
        _require_current(route_database, _identity())

    cases = []
    value = _valid_review()
    cases.append(json.dumps(value, indent=2))
    cases.append("[]")
    extra = _valid_review()
    extra["unexpected"] = True
    cases.append(canonical_mapping_bytes(extra).decode("utf-8"))
    missing = _valid_review()
    del missing["source_sha256"]
    cases.append(canonical_mapping_bytes(missing).decode("utf-8"))

    for index, raw in enumerate(cases):
        database = route_database
        if index:
            with UnitOfWork(database.engine) as uow:
                uow.exec_driver_sql("DELETE FROM runtime_settings")
                uow.commit()
        _insert_review(database, raw)
        with pytest.raises(PermissionError, match="provider_review_not_current"):
            _require_current(database, _identity())


def test_malformed_review_parse_error_is_sanitized(
    route_database: RouteDatabase,
) -> None:
    _insert_review(route_database, json.dumps(_valid_review(), indent=2))

    with pytest.raises(
        PermissionError,
        match="provider_review_not_current",
    ) as captured:
        _require_current(route_database, _identity())

    assert captured.value.__cause__ is None
    assert captured.value.__suppress_context__ is True


def test_expiry_equality_and_qwen_fail_closed(route_database: RouteDatabase) -> None:
    value = _valid_review()
    value["expires_at"] = NOW.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    _insert_review(route_database, canonical_mapping_bytes(value).decode("utf-8"))

    with pytest.raises(PermissionError, match="provider_review_not_current"):
        _require_current(route_database, _identity(), now=NOW)

    with UnitOfWork(route_database.engine) as uow:
        with pytest.raises(PermissionError, match="provider_review_not_current"):
            ProviderReviewStore(uow, RuntimeIdentities(_identity())).require_current(
                "qwen",
                "qwen3.7-plus",
                "cloud_reasoning",
                NOW,
            )
        uow.rollback()


@pytest.mark.parametrize(
    ("updated_at", "expires_at"),
    [
        (NOW, NOW + timedelta(days=90, microseconds=1)),
        (NOW + timedelta(microseconds=1), NOW + timedelta(days=90)),
    ],
)
def test_review_timestamp_cannot_be_future_or_exceed_ninety_days(
    route_database: RouteDatabase,
    updated_at: datetime,
    expires_at: datetime,
) -> None:
    value = _valid_review()
    value["expires_at"] = expires_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    _insert_review(
        route_database,
        canonical_mapping_bytes(value).decode("utf-8"),
        updated_at=updated_at,
    )

    with pytest.raises(PermissionError, match="provider_review_not_current"):
        _require_current(route_database, _identity())
