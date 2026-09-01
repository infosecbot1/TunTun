from __future__ import annotations

import hmac
from datetime import UTC, datetime
from uuid import UUID

from tuntun_contracts.provider import (
    RouteAuthorization,
    RouteAuthorizationRequest,
    RouteConsumption,
)

_DIRECT_BINDINGS = (
    "request_id",
    "attempt_id",
    "purpose",
    "household_id",
    "subject_id",
    "session_id",
    "turn_id",
    "provider",
    "model",
)


def _aware_utc(value: datetime, *, name: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise TypeError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


def authorization_from_request(
    request: RouteAuthorizationRequest,
    *,
    authorization_id: UUID,
    expires_at: datetime,
) -> RouteAuthorization:
    """Derive the immutable public authorization without caller-selected fields."""

    if type(request) is not RouteAuthorizationRequest:
        raise TypeError("request must be an exact RouteAuthorizationRequest")
    if type(authorization_id) is not UUID:
        raise TypeError("authorization_id must be an exact UUID")
    normalized_expiry = _aware_utc(expires_at, name="expires_at")
    return RouteAuthorization(
        authorization_id=authorization_id,
        request_id=request.request_id,
        attempt_id=request.attempt_id,
        purpose=request.purpose,
        household_id=request.household_id,
        subject_id=request.subject_id,
        session_id=request.session_id,
        turn_id=request.turn_id,
        provider=request.provider,
        model=request.model,
        request_commitment=request.request_commitment,
        max_input_bytes=request.max_input_bytes,
        max_input_units=request.max_input_units,
        privacy_receipt_id=request.privacy_receipt_id,
        consent_receipt_ids=request.consent_receipt_ids,
        budget_reservation_id=request.budget_reservation_id,
        maximum_sensitivity=request.maximum_sensitivity,
        expires_at=normalized_expiry,
    )


def verify_route_consumption(
    route: RouteAuthorization,
    supplied: RouteConsumption,
    *,
    now: datetime,
) -> None:
    """Fail closed unless one unexpired authorization exactly binds one consumption."""

    if type(route) is not RouteAuthorization:
        raise TypeError("route must be an exact RouteAuthorization")
    if type(supplied) is not RouteConsumption:
        raise TypeError("consumption must be an exact RouteConsumption")
    normalized_now = _aware_utc(now, name="now")
    if normalized_now >= route.expires_at.astimezone(UTC):
        raise PermissionError("route_authorization_expired")
    if supplied.consumed_at.astimezone(UTC) > normalized_now:
        raise PermissionError("route_consumption_from_future")

    commitment_matches = (
        hmac.compare_digest(
            route.request_commitment.algorithm,
            supplied.request_commitment.algorithm,
        )
        and hmac.compare_digest(
            route.request_commitment.key_id,
            supplied.request_commitment.key_id,
        )
        and hmac.compare_digest(
            route.request_commitment.value_b64,
            supplied.request_commitment.value_b64,
        )
    )
    if (
        any(getattr(route, name) != getattr(supplied, name) for name in _DIRECT_BINDINGS)
        or not commitment_matches
        or supplied.input_bytes > route.max_input_bytes
        or supplied.input_units > route.max_input_units
    ):
        raise PermissionError("route_consumption_mismatch")
