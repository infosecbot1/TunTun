from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from tuntun_contracts.base import Commitment
from tuntun_contracts.provider import RouteAuthorizationRequest, RouteConsumption
from tuntun_core.services.providers.route_authorization import (
    QwenRouteActivationBindingV1,
    RouteAuthorizationEnvelopeV1,
)
from tuntun_core.services.providers.route_verifier import (
    authorization_from_request,
    verify_route_consumption,
)
from tuntun_testing.fake_clock import FakeClock

pytest_plugins = ("tests.fixtures.provider_routes",)


def _route(request: RouteAuthorizationRequest, clock: FakeClock):
    return authorization_from_request(
        request,
        authorization_id=uuid4(),
        expires_at=clock.now() + timedelta(seconds=30),
    )


def _qwen_binding_values(
    commitment: Commitment,
    clock: FakeClock,
) -> dict[str, object]:
    return {
        "schema_version": "tuntun.qwen-route-activation.v1",
        "owner_activation_commitment": commitment,
        "evaluation_report_commitment": commitment,
        "endpoint_authority_commitment": commitment,
        "pricing_schedule_commitment": commitment,
        "workspace_probe_receipt_id": uuid4(),
        "workspace_probe_generation": 1,
        "workspace_probe_commitment": commitment,
        "workspace_probe_expires_at": clock.now() + timedelta(minutes=10),
        "workspace_id": "tuntun-family",
        "region": "ap-southeast-1",
        "base_url": ("https://tuntun-family.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1"),
        "resolved_model_snapshot": "qwen3.7-plus-2026-05-26",
        "endpoint_review_version": 1,
        "endpoint_source_sha256": "a" * 64,
        "pricing_version": "qwen-2026-08-27",
        "price_source_url": ("https://www.alibabacloud.com/help/en/model-studio/model-pricing"),
        "price_source_sha256": "b" * 64,
        "fx_version": "owner-safety-factor-2026-08-27",
        "fx_micros_sgd_per_usd": 1_500_000,
        "fx_source": "owner_policy",
        "fx_source_sha256": "c" * 64,
        "fx_record_commitment": commitment,
        "terms_review_version": 1,
        "terms_source_sha256": "d" * 64,
        "expires_at": clock.now() + timedelta(minutes=5),
    }


def test_authorization_is_fully_derived_from_the_request(
    provider_route_request: RouteAuthorizationRequest,
    route_clock: FakeClock,
) -> None:
    authorization_id = uuid4()
    expires_at = route_clock.now() + timedelta(seconds=30)

    route = authorization_from_request(
        provider_route_request,
        authorization_id=authorization_id,
        expires_at=expires_at,
    )

    expected = provider_route_request.model_dump(mode="python") | {
        "authorization_id": authorization_id,
        "expires_at": expires_at,
    }
    assert route.model_dump(mode="python") == expected


def test_every_direct_binding_is_enforced(
    provider_route_request: RouteAuthorizationRequest,
    provider_route_consumption: RouteConsumption,
    route_clock: FakeClock,
) -> None:
    route = _route(provider_route_request, route_clock)
    verify_route_consumption(route, provider_route_consumption, now=route_clock.now())
    mutations = (
        {"request_id": uuid4()},
        {"attempt_id": uuid4()},
        {"purpose": "cloud_tts"},
        {"household_id": uuid4()},
        {"subject_id": uuid4()},
        {"subject_id": None},
        {"session_id": uuid4()},
        {"turn_id": uuid4()},
        {"provider": "qwen"},
        {"model": "other-model"},
        {
            "request_commitment": Commitment(
                algorithm="HMAC-SHA-256",
                key_id="other-key-v1",
                value_b64="AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
            )
        },
    )

    for values in mutations:
        with pytest.raises(PermissionError, match="route_consumption_mismatch"):
            verify_route_consumption(
                route,
                provider_route_consumption.model_copy(update=values),
                now=route_clock.now(),
            )


def test_both_limits_are_inclusive_and_one_over_is_rejected(
    provider_route_request: RouteAuthorizationRequest,
    provider_route_consumption: RouteConsumption,
    route_clock: FakeClock,
) -> None:
    route = _route(provider_route_request, route_clock)
    at_limit = provider_route_consumption.model_copy(
        update={
            "input_bytes": route.max_input_bytes,
            "input_units": route.max_input_units,
        }
    )
    verify_route_consumption(route, at_limit, now=route_clock.now())

    for values in (
        {"input_bytes": route.max_input_bytes + 1},
        {"input_units": route.max_input_units + 1},
    ):
        with pytest.raises(PermissionError, match="route_consumption_mismatch"):
            verify_route_consumption(
                route,
                provider_route_consumption.model_copy(update=values),
                now=route_clock.now(),
            )


def test_expiry_equality_and_future_consumption_fail_closed(
    provider_route_request: RouteAuthorizationRequest,
    provider_route_consumption: RouteConsumption,
    route_clock: FakeClock,
) -> None:
    route = _route(provider_route_request, route_clock)

    with pytest.raises(PermissionError, match="route_authorization_expired"):
        verify_route_consumption(route, provider_route_consumption, now=route.expires_at)
    with pytest.raises(PermissionError, match="route_authorization_expired"):
        verify_route_consumption(
            route,
            provider_route_consumption,
            now=route.expires_at + timedelta(microseconds=1),
        )
    future = provider_route_consumption.model_copy(
        update={"consumed_at": route_clock.now() + timedelta(seconds=1)}
    )
    with pytest.raises(PermissionError, match="route_consumption_from_future"):
        verify_route_consumption(route, future, now=route_clock.now())


def test_verifier_rejects_untrusted_runtime_types(
    provider_route_request: RouteAuthorizationRequest,
    provider_route_consumption: RouteConsumption,
    route_clock: FakeClock,
) -> None:
    route = _route(provider_route_request, route_clock)
    with pytest.raises(TypeError, match="now must be timezone-aware"):
        verify_route_consumption(
            route,
            provider_route_consumption,
            now=route_clock.now().replace(tzinfo=None),
        )
    with pytest.raises(TypeError, match="exact RouteAuthorizationRequest"):
        authorization_from_request(  # type: ignore[arg-type]
            object(),
            authorization_id=uuid4(),
            expires_at=route.expires_at,
        )
    with pytest.raises(TypeError, match="authorization_id must be an exact UUID"):
        authorization_from_request(  # type: ignore[arg-type]
            provider_route_request,
            authorization_id="not-a-uuid",
            expires_at=route.expires_at,
        )
    with pytest.raises(TypeError, match="route must be an exact RouteAuthorization"):
        verify_route_consumption(  # type: ignore[arg-type]
            object(),
            provider_route_consumption,
            now=route_clock.now(),
        )
    with pytest.raises(TypeError, match="consumption must be an exact RouteConsumption"):
        verify_route_consumption(  # type: ignore[arg-type]
            route,
            object(),
            now=route_clock.now(),
        )


def test_qwen_activation_binds_exact_regional_endpoint_and_earliest_expiry(
    provider_route_request: RouteAuthorizationRequest,
    route_clock: FakeClock,
) -> None:
    values = _qwen_binding_values(
        provider_route_request.request_commitment,
        route_clock,
    )

    binding = QwenRouteActivationBindingV1(**values)

    assert binding.workspace_id == "tuntun-family"
    for change in (
        {"workspace_id": "Tuntun-Family"},
        {"workspace_id": "-tuntun"},
        {"base_url": "https://example.com/compatible-mode/v1"},
        {"expires_at": route_clock.now() + timedelta(minutes=11)},
    ):
        with pytest.raises(ValueError):
            QwenRouteActivationBindingV1(**(values | change))


def test_private_envelope_rejects_subject_and_qwen_binding_mismatches(
    provider_route_request: RouteAuthorizationRequest,
    route_clock: FakeClock,
) -> None:
    route = _route(provider_route_request, route_clock)
    qwen_binding = QwenRouteActivationBindingV1(
        **_qwen_binding_values(
            provider_route_request.request_commitment,
            route_clock,
        )
    )

    with pytest.raises(ValueError, match="route_subject_authority_generation_mismatch"):
        RouteAuthorizationEnvelopeV1(
            route=route,
            subject_authority_generation=None,
        )
    with pytest.raises(ValueError, match="route_qwen_activation_binding_mismatch"):
        RouteAuthorizationEnvelopeV1(
            route=route,
            subject_authority_generation=1,
            qwen_activation=qwen_binding,
        )
    with pytest.raises(ValueError, match="route_qwen_activation_binding_mismatch"):
        RouteAuthorizationEnvelopeV1(
            route=route.model_copy(update={"provider": "qwen", "model": "other-model"}),
            subject_authority_generation=1,
            qwen_activation=qwen_binding,
        )
