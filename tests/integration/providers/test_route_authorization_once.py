from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import event
from tuntun_contracts.base import canonical_bytes, canonical_mapping_bytes, parse_contract_json
from tuntun_contracts.budget import LlmUsageUnits, SttUsageUnits, TtsUsageUnits
from tuntun_contracts.provider import RouteAuthorizationRequest, RouteConsumption
from tuntun_core.adapters.sqlcipher.async_unit_of_work import AsyncUnitOfWorkFactory
from tuntun_core.services.providers.review import (
    OpenAIProviderHardLimitV1,
    ProviderReviewV1,
    RuntimeProviderIdentity,
)
from tuntun_core.services.providers.route_authorization import (
    PrivacyReceiptBindingV1,
    QwenRouteActivationBindingV1,
    RouteAuthorizationEnvelopeV1,
    RouteAuthorizationService,
    SqlRoutePrerequisites,
)
from tuntun_core.services.providers.route_verifier import authorization_from_request
from tuntun_core.services.transactions.protocols import (
    AsyncUnitOfWorkProtocol,
    UnitOfWorkProtocol,
)
from tuntun_testing.fake_clock import FakeClock

from tests.fixtures.provider_routes import PrerequisitesFake, RouteDatabase

pytest_plugins = ("tests.fixtures.provider_routes",)


async def _stored_envelope(
    factory: AsyncUnitOfWorkFactory,
    authorization_id: object,
) -> tuple[str, RouteAuthorizationEnvelopeV1]:
    def select_raw(transaction: object) -> str | None:
        row = transaction.exec_driver_sql(  # type: ignore[attr-defined]
            "SELECT value_json FROM runtime_settings WHERE key = ?",
            (f"route.authorization.{authorization_id}",),
        ).fetchone()
        if row is None:
            return None
        value = row[0]
        assert type(value) is str
        return value

    async with factory() as uow:
        raw = await uow.run_sync(select_raw)
        await uow.rollback()
    assert raw is not None
    assert type(raw) is str
    envelope = parse_contract_json(
        RouteAuthorizationEnvelopeV1,
        raw.encode("utf-8"),
        max_bytes=131_072,
        require_canonical=True,
    )
    return raw, envelope


async def _authorization_artifact_counts(
    factory: AsyncUnitOfWorkFactory,
) -> tuple[int, int]:
    async with factory() as uow:
        route_count = await uow.run_sync(
            lambda transaction: transaction.exec_driver_sql(
                "SELECT count(*) FROM runtime_settings WHERE key GLOB 'route.authorization.*'"
            ).scalar_one()
        )
        receipt_count = await uow.run_sync(
            lambda transaction: transaction.exec_driver_sql(
                "SELECT count(*) FROM idempotency_receipts "
                "WHERE operation = 'provider.route.authorize'"
            ).scalar_one()
        )
        await uow.rollback()
    assert type(route_count) is int
    assert type(receipt_count) is int
    return route_count, receipt_count


class _SqlSubjectAuthority:
    def __init__(self, request: RouteAuthorizationRequest) -> None:
        self.scope = (request.household_id, request.subject_id)
        self.generation = 7
        self.error: BaseException | None = None

    async def require_current_in_uow(
        self,
        uow: AsyncUnitOfWorkProtocol,
        household_id: UUID,
        subject_id: UUID,
        expected_generation: int | None,
    ) -> int:
        del uow
        if self.error is not None:
            raise self.error
        if (household_id, subject_id) != self.scope or (
            expected_generation is not None and expected_generation != self.generation
        ):
            raise PermissionError("subject authority changed")
        return self.generation


class _SqlConsentEvidence:
    def __init__(self, request: RouteAuthorizationRequest) -> None:
        self.scope = (
            request.household_id,
            request.subject_id,
            request.session_id,
            request.purpose,
            request.consent_receipt_ids,
        )
        self.error: BaseException | None = None

    async def require_exact_in_uow(
        self,
        uow: AsyncUnitOfWorkProtocol,
        household_id: UUID,
        subject_id: UUID | None,
        session_id: UUID,
        purpose: str,
        receipt_ids: tuple[UUID, ...],
    ) -> None:
        del uow
        if self.error is not None:
            raise self.error
        if (household_id, subject_id, session_id, purpose, receipt_ids) != self.scope:
            raise PermissionError("consent evidence changed")


class _SqlRuntimeIdentities:
    def require_current(self, provider: str) -> RuntimeProviderIdentity:
        if provider != "openai":
            raise PermissionError("provider identity unavailable")
        return RuntimeProviderIdentity(
            project_id_commitment_sha256="a" * 64,
            credential_kind="project_service_account",
            admin_key_present=False,
        )


class _SqlQwenActivationStore:
    def __init__(self, binding: QwenRouteActivationBindingV1) -> None:
        self.current = binding

    def require_current_in_transaction(
        self,
        transaction: UnitOfWorkProtocol,
        *,
        model: str,
        purpose: str,
        expected: QwenRouteActivationBindingV1 | None,
        now: datetime,
    ) -> QwenRouteActivationBindingV1:
        assert transaction.exec_driver_sql("SELECT 1").scalar_one() == 1
        if (
            model != "qwen3.7-plus"
            or purpose != "cloud_reasoning"
            or now >= self.current.expires_at
            or now >= self.current.workspace_probe_expires_at
            or (expected is not None and expected != self.current)
        ):
            raise PermissionError("qwen activation changed")
        return self.current


def _openai_review(now: datetime) -> ProviderReviewV1:
    hard_limit_values: dict[str, object] = {
        "project_id_commitment_sha256": "a" * 64,
        "threshold_micros_usd": 100_000_000,
        "currency": "USD",
        "interval": "provider_month",
        "enforcement_status": "enforcing",
        "dashboard_evidence_sha256": "b" * 64,
    }
    settings_commitment = hashlib.sha256(canonical_mapping_bytes(hard_limit_values)).hexdigest()
    hard_limit = OpenAIProviderHardLimitV1(
        project_id_commitment_sha256="a" * 64,
        threshold_micros_usd=100_000_000,
        currency="USD",
        interval="provider_month",
        enforcement_status="enforcing",
        dashboard_evidence_sha256="b" * 64,
        settings_commitment_sha256=settings_commitment,
        runtime_credential_kind="project_service_account",
        runtime_admin_key_present=False,
    )
    return ProviderReviewV1(
        schema_version="tuntun.provider-review.v1",
        provider="openai",
        accepted=True,
        expires_at=now + timedelta(days=90),
        source_changed=False,
        dashboard_changed=False,
        purposes=("cloud_stt", "cloud_reasoning", "cloud_tts"),
        models=("gpt-transcribe", "gpt-5.6-sol", "tts-1"),
        endpoint="https://api.openai.com/v1",
        workspace_id=None,
        region="global",
        review_version=1,
        source_sha256="c" * 64,
        provider_hard_limit=hard_limit,
    )


def _qwen_activation(
    request: RouteAuthorizationRequest,
    route_clock: FakeClock,
) -> QwenRouteActivationBindingV1:
    commitment = request.request_commitment
    workspace_id = "tuntun-family"
    return QwenRouteActivationBindingV1(
        schema_version="tuntun.qwen-route-activation.v1",
        owner_activation_commitment=commitment,
        evaluation_report_commitment=commitment,
        endpoint_authority_commitment=commitment,
        pricing_schedule_commitment=commitment,
        workspace_probe_receipt_id=uuid4(),
        workspace_probe_generation=1,
        workspace_probe_commitment=commitment,
        workspace_probe_expires_at=route_clock.now() + timedelta(minutes=10),
        workspace_id=workspace_id,
        region="ap-southeast-1",
        base_url=(f"https://{workspace_id}.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1"),
        resolved_model_snapshot="qwen3.7-plus-2026-05-26",
        endpoint_review_version=1,
        endpoint_source_sha256="a" * 64,
        pricing_version="qwen-2026-08-27",
        price_source_url=("https://www.alibabacloud.com/help/en/model-studio/model-pricing"),
        price_source_sha256="b" * 64,
        fx_version="owner-safety-factor-2026-08-27",
        fx_micros_sgd_per_usd=1_500_000,
        fx_source="owner_policy",
        fx_source_sha256="c" * 64,
        fx_record_commitment=commitment,
        terms_review_version=1,
        terms_source_sha256="d" * 64,
        expires_at=route_clock.now() + timedelta(minutes=5),
    )


async def _seed_sql_route_prerequisites(
    factory: AsyncUnitOfWorkFactory,
    request: RouteAuthorizationRequest,
    route_clock: FakeClock,
) -> None:
    now = route_clock.now()
    timestamp = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    device_id = uuid4()
    privacy = PrivacyReceiptBindingV1(
        schema_version="tuntun.privacy-receipt-binding.v1",
        receipt_id=request.privacy_receipt_id,
        turn_id=request.turn_id,
        active=True,
        expires_at=now + timedelta(minutes=5),
    )
    review = _openai_review(now)
    if request.purpose == "cloud_stt":
        category = "stt"
        usage = SttUsageUnits(category="stt", audio_millis=request.max_input_units)
        accounting_basis = "provider_reported_exact"
    elif request.purpose == "cloud_tts":
        category = "tts"
        usage = TtsUsageUnits(category="tts", characters=request.max_input_units)
        accounting_basis = "request_bound_exact"
    else:
        category = "llm"
        usage = LlmUsageUnits(
            category="llm",
            input_tokens=request.max_input_units,
            output_tokens=4_000,
        )
        accounting_basis = "provider_reported_exact"

    def seed(transaction: UnitOfWorkProtocol) -> None:
        transaction.exec_driver_sql(
            "INSERT INTO households(id,display_label_ciphertext,created_at) VALUES(?,?,?)",
            (str(request.household_id), b"household", timestamp),
        )
        transaction.exec_driver_sql(
            "INSERT INTO devices("
            "id,household_id,kind,certificate_fingerprint,signing_public_key,"
            "signing_key_id,paired_at) VALUES(?,?,?,?,?,?,?)",
            (
                str(device_id),
                str(request.household_id),
                "reachy_mini",
                f"fingerprint-{device_id}",
                b"public-key",
                "reachy-signing-v1",
                timestamp,
            ),
        )
        transaction.exec_driver_sql(
            "INSERT INTO sessions("
            "id,household_id,device_id,state,speaker_subject_id,"
            "opened_at,last_activity_at) VALUES(?,?,?,?,?,?,?)",
            (
                str(request.session_id),
                str(request.household_id),
                str(device_id),
                "active",
                None if request.subject_id is None else str(request.subject_id),
                timestamp,
                timestamp,
            ),
        )
        transaction.exec_driver_sql(
            "INSERT INTO runtime_settings(key,value_json,version,updated_at) VALUES(?,?,1,?)",
            (
                f"privacy.receipt.{request.privacy_receipt_id}",
                canonical_bytes(privacy).decode("utf-8"),
                timestamp,
            ),
        )
        transaction.exec_driver_sql(
            "INSERT INTO runtime_settings(key,value_json,version,updated_at) "
            "VALUES('provider.review.openai',?,1,?)",
            (canonical_bytes(review).decode("utf-8"), timestamp),
        )
        transaction.exec_driver_sql(
            "INSERT INTO budget_reservations("
            "id,request_id,attempt_id,month_key,category,provider,model,outcome,"
            "reserved_micros_sgd,charged_micros_sgd,usage_ceiling_json,"
            "price_snapshot_json,primary_accounting_basis,missing_evidence_policy,"
            "pricing_version,price_source_sha256,fx_version,fx_source_sha256,"
            "pricing_commitment_key_id,pricing_commitment_hmac_b64,estimate_overrun,"
            "state,gateway_ordering_version,transport_phase,created_at,expires_at,"
            "settled_at,reconciled_at) VALUES("
            ":id,:request_id,:attempt_id,'2026-08',:category,:provider,:model,'allow',"
            "100,NULL,:usage,:snapshot,:accounting_basis,"
            "'freeze_unknown_overage','openai-2026-08-27',:price_sha,"
            "'bootstrap-safety-factor-2026-08-27',:fx_sha,'pricing-v1',:hmac,0,"
            "'reserved',1,'not_claimed',:created_at,:expires_at,NULL,NULL)",
            {
                "id": str(request.budget_reservation_id),
                "request_id": str(request.request_id),
                "attempt_id": str(request.attempt_id),
                "category": category,
                "provider": request.provider,
                "model": request.model,
                "accounting_basis": accounting_basis,
                "usage": canonical_bytes(usage).decode("utf-8"),
                "snapshot": '{"price":"bound"}',
                "price_sha": "d" * 64,
                "fx_sha": "e" * 64,
                "hmac": "A" * 43 + "=",
                "created_at": timestamp,
                "expires_at": (now + timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            },
        )

    async with factory() as uow:
        await uow.run_sync(seed)
        await uow.commit()


def _sql_route_service(
    factory: AsyncUnitOfWorkFactory,
    request: RouteAuthorizationRequest,
    route_clock: FakeClock,
    *,
    qwen_store: _SqlQwenActivationStore | None = None,
) -> RouteAuthorizationService:
    prerequisites = SqlRoutePrerequisites(
        route_clock,
        _SqlSubjectAuthority(request),
        _SqlConsentEvidence(request),
        _SqlRuntimeIdentities(),
        qwen_activation_store=qwen_store,
    )
    return RouteAuthorizationService(factory, prerequisites, route_clock)


@pytest.mark.asyncio
async def test_authorize_persists_a_canonical_private_envelope(
    route_uow_factory: AsyncUnitOfWorkFactory,
    provider_route_prerequisites: PrerequisitesFake,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
) -> None:
    service = RouteAuthorizationService(
        route_uow_factory,
        provider_route_prerequisites,
        route_clock,
    )

    route = await service.authorize(provider_route_request)
    raw, envelope = await _stored_envelope(route_uow_factory, route.authorization_id)

    assert raw.encode("utf-8") == canonical_bytes(envelope)
    assert envelope.route == route
    assert envelope.subject_authority_generation == 7
    assert envelope.qwen_activation is None
    assert provider_route_prerequisites.call_log == [
        "subject_authority",
        "consent",
        "privacy",
        "provider_review",
        "provider_activation",
        "budget_reservation",
        "authorization_barrier",
    ]


@pytest.mark.asyncio
async def test_route_service_rejects_untrusted_public_argument_types(
    route_uow_factory: AsyncUnitOfWorkFactory,
    provider_route_prerequisites: PrerequisitesFake,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    provider_route_consumption: RouteConsumption,
) -> None:
    service = RouteAuthorizationService(
        route_uow_factory,
        provider_route_prerequisites,
        route_clock,
    )

    with pytest.raises(TypeError, match="request must be an exact RouteAuthorizationRequest"):
        await service.authorize(object())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="authorization_id must be an exact UUID"):
        await service.consume("not-a-uuid", provider_route_consumption)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="consumption must be an exact RouteConsumption"):
        await service.consume(uuid4(), object())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="authorization_id must be an exact UUID"):
        await service.count_consumptions("not-a-uuid")  # type: ignore[arg-type]

    async with route_uow_factory() as uow:
        with pytest.raises(TypeError, match="subject_id must be an exact UUID"):
            await service.invalidate_subject_purpose_in_uow(  # type: ignore[arg-type]
                uow,
                object(),
                provider_route_request.purpose,
                route_clock.now(),
            )
        with pytest.raises(TypeError, match="purpose must be an exact cloud route purpose"):
            await service.invalidate_subject_purpose_in_uow(
                uow,
                provider_route_request.subject_id,
                "invalid-purpose",
                route_clock.now(),
            )
        with pytest.raises(TypeError, match="stored timestamp must be timezone-aware"):
            await service.invalidate_subject_purpose_in_uow(
                uow,
                provider_route_request.subject_id,
                provider_route_request.purpose,
                route_clock.now().replace(tzinfo=None),
            )
        await uow.rollback()


@pytest.mark.asyncio
async def test_authorization_id_factory_must_return_an_exact_uuid(
    route_uow_factory: AsyncUnitOfWorkFactory,
    provider_route_prerequisites: PrerequisitesFake,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
) -> None:
    service = RouteAuthorizationService(
        route_uow_factory,
        provider_route_prerequisites,
        route_clock,
        authorization_id_factory=lambda: "not-a-uuid",  # type: ignore[arg-type,return-value]
    )

    with pytest.raises(RuntimeError, match="authorization id factory must return an exact UUID"):
        await service.authorize(provider_route_request)

    assert await _authorization_artifact_counts(route_uow_factory) == (0, 0)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        {"request_id": uuid4()},
        {"max_input_bytes": 31_999},
        {"max_input_units": 7_999},
    ],
)
async def test_authorize_binds_the_complete_request_to_the_budget_reservation(
    route_uow_factory: AsyncUnitOfWorkFactory,
    provider_route_prerequisites: PrerequisitesFake,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    change: dict[str, object],
) -> None:
    service = RouteAuthorizationService(
        route_uow_factory,
        provider_route_prerequisites,
        route_clock,
    )

    with pytest.raises(PermissionError, match="route_invalidated:budget_reservation"):
        await service.authorize(provider_route_request.model_copy(update=change))


@pytest.mark.asyncio
async def test_sql_prerequisites_authorize_and_consume_without_network(
    route_uow_factory: AsyncUnitOfWorkFactory,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    provider_route_consumption: RouteConsumption,
) -> None:
    await _seed_sql_route_prerequisites(
        route_uow_factory,
        provider_route_request,
        route_clock,
    )
    service = _sql_route_service(
        route_uow_factory,
        provider_route_request,
        route_clock,
    )

    route = await service.authorize(provider_route_request)
    await service.consume(route.authorization_id, provider_route_consumption)

    assert await service.count_consumptions(route.authorization_id) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("purpose", "model", "maximum_units"),
    [
        ("cloud_stt", "gpt-transcribe", 90_000),
        ("cloud_tts", "tts-1", 4_000),
    ],
)
async def test_sql_prerequisites_accept_stt_and_tts_budget_ceiling_shapes(
    route_uow_factory: AsyncUnitOfWorkFactory,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    provider_route_consumption: RouteConsumption,
    purpose: str,
    model: str,
    maximum_units: int,
) -> None:
    request = provider_route_request.model_copy(
        update={
            "purpose": purpose,
            "model": model,
            "max_input_units": maximum_units,
        }
    )
    consumption = provider_route_consumption.model_copy(
        update={
            "purpose": purpose,
            "model": model,
            "input_units": min(500, maximum_units),
        }
    )
    await _seed_sql_route_prerequisites(route_uow_factory, request, route_clock)
    service = _sql_route_service(route_uow_factory, request, route_clock)

    route = await service.authorize(request)
    await service.consume(route.authorization_id, consumption)

    assert await service.count_consumptions(route.authorization_id) == 1


@pytest.mark.asyncio
async def test_sql_prerequisites_accept_guest_session_with_no_subject_generation(
    route_uow_factory: AsyncUnitOfWorkFactory,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    provider_route_consumption: RouteConsumption,
) -> None:
    request = provider_route_request.model_copy(update={"subject_id": None})
    consumption = provider_route_consumption.model_copy(update={"subject_id": None})
    await _seed_sql_route_prerequisites(route_uow_factory, request, route_clock)
    service = _sql_route_service(route_uow_factory, request, route_clock)

    route = await service.authorize(request)
    await service.consume(route.authorization_id, consumption)
    _, envelope = await _stored_envelope(route_uow_factory, route.authorization_id)

    assert envelope.subject_authority_generation is None


@pytest.mark.asyncio
async def test_sql_provider_review_drift_between_authorize_and_consume_denies(
    route_uow_factory: AsyncUnitOfWorkFactory,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    provider_route_consumption: RouteConsumption,
) -> None:
    await _seed_sql_route_prerequisites(
        route_uow_factory,
        provider_route_request,
        route_clock,
    )
    service = _sql_route_service(
        route_uow_factory,
        provider_route_request,
        route_clock,
    )
    route = await service.authorize(provider_route_request)
    expired_review = _openai_review(route_clock.now()).model_copy(
        update={"expires_at": route_clock.now()}
    )

    async with route_uow_factory() as uow:
        await uow.run_sync(
            lambda transaction: (
                transaction.exec_driver_sql(
                    "UPDATE runtime_settings SET value_json = ?,version = version + 1 "
                    "WHERE key = 'provider.review.openai'",
                    (canonical_bytes(expired_review).decode("utf-8"),),
                ).rowcount
            )
        )
        await uow.commit()

    with pytest.raises(PermissionError, match="route_invalidated:provider_review"):
        await service.consume(route.authorization_id, provider_route_consumption)
    assert await service.count_consumptions(route.authorization_id) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("drift", "expected_error"),
    [
        ("session_closed", "turn"),
        ("speaker_changed", "turn"),
        ("privacy_expired", "privacy"),
        ("privacy_wrong_turn", "privacy"),
        ("privacy_noncanonical", "privacy"),
    ],
)
async def test_sql_runtime_session_and_privacy_drift_fail_closed(
    route_uow_factory: AsyncUnitOfWorkFactory,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    provider_route_consumption: RouteConsumption,
    drift: str,
    expected_error: str,
) -> None:
    await _seed_sql_route_prerequisites(
        route_uow_factory,
        provider_route_request,
        route_clock,
    )
    service = _sql_route_service(
        route_uow_factory,
        provider_route_request,
        route_clock,
    )
    route = await service.authorize(provider_route_request)

    def apply_drift(transaction: UnitOfWorkProtocol) -> None:
        if drift == "session_closed":
            timestamp = route_clock.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            transaction.exec_driver_sql(
                "UPDATE sessions SET state = 'closed',closed_at = ? WHERE id = ?",
                (timestamp, str(provider_route_request.session_id)),
            )
        elif drift == "speaker_changed":
            transaction.exec_driver_sql(
                "UPDATE sessions SET speaker_subject_id = ? WHERE id = ?",
                (str(uuid4()), str(provider_route_request.session_id)),
            )
        elif drift == "privacy_noncanonical":
            transaction.exec_driver_sql(
                "UPDATE runtime_settings SET value_json = ' ' || value_json WHERE key = ?",
                (f"privacy.receipt.{provider_route_request.privacy_receipt_id}",),
            )
        else:
            privacy = PrivacyReceiptBindingV1(
                schema_version="tuntun.privacy-receipt-binding.v1",
                receipt_id=provider_route_request.privacy_receipt_id,
                turn_id=(
                    uuid4() if drift == "privacy_wrong_turn" else provider_route_request.turn_id
                ),
                active=True,
                expires_at=(
                    route_clock.now()
                    if drift == "privacy_expired"
                    else route_clock.now() + timedelta(minutes=5)
                ),
            )
            transaction.exec_driver_sql(
                "UPDATE runtime_settings SET value_json = ? WHERE key = ?",
                (
                    canonical_bytes(privacy).decode("utf-8"),
                    f"privacy.receipt.{provider_route_request.privacy_receipt_id}",
                ),
            )

    async with route_uow_factory() as uow:
        await uow.run_sync(apply_drift)
        await uow.commit()

    with pytest.raises(PermissionError, match=f"route_invalidated:{expected_error}"):
        await service.consume(route.authorization_id, provider_route_consumption)
    assert await service.count_consumptions(route.authorization_id) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "drift",
    ["request_id", "category", "usage_ceiling"],
)
async def test_sql_budget_binding_rejects_wrong_request_category_or_ceiling(
    route_uow_factory: AsyncUnitOfWorkFactory,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    drift: str,
) -> None:
    await _seed_sql_route_prerequisites(
        route_uow_factory,
        provider_route_request,
        route_clock,
    )
    wrong_llm_usage = LlmUsageUnits(
        category="llm",
        input_tokens=provider_route_request.max_input_units - 1,
        output_tokens=4_000,
    )
    wrong_tts_usage = TtsUsageUnits(
        category="tts",
        characters=min(provider_route_request.max_input_units, 4_096),
    )

    def apply_drift(transaction: UnitOfWorkProtocol) -> None:
        if drift == "request_id":
            transaction.exec_driver_sql(
                "UPDATE budget_reservations SET request_id = ? WHERE id = ?",
                (str(uuid4()), str(provider_route_request.budget_reservation_id)),
            )
        elif drift == "category":
            transaction.exec_driver_sql(
                "UPDATE budget_reservations SET category = 'tts',"
                "usage_ceiling_json = ?,primary_accounting_basis = 'request_bound_exact' "
                "WHERE id = ?",
                (
                    canonical_bytes(wrong_tts_usage).decode("utf-8"),
                    str(provider_route_request.budget_reservation_id),
                ),
            )
        else:
            transaction.exec_driver_sql(
                "UPDATE budget_reservations SET usage_ceiling_json = ? WHERE id = ?",
                (
                    canonical_bytes(wrong_llm_usage).decode("utf-8"),
                    str(provider_route_request.budget_reservation_id),
                ),
            )

    async with route_uow_factory() as uow:
        await uow.run_sync(apply_drift)
        await uow.commit()

    service = _sql_route_service(
        route_uow_factory,
        provider_route_request,
        route_clock,
    )
    with pytest.raises(PermissionError, match="route_invalidated:budget_reservation"):
        await service.authorize(provider_route_request)

    async with route_uow_factory() as uow:
        route_count = await uow.run_sync(
            lambda transaction: transaction.exec_driver_sql(
                "SELECT count(*) FROM runtime_settings WHERE key GLOB 'route.authorization.*'"
            ).scalar_one()
        )
        await uow.rollback()
    assert route_count == 0


@pytest.mark.asyncio
async def test_sql_budget_release_between_authorize_and_consume_denies(
    route_uow_factory: AsyncUnitOfWorkFactory,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    provider_route_consumption: RouteConsumption,
) -> None:
    await _seed_sql_route_prerequisites(
        route_uow_factory,
        provider_route_request,
        route_clock,
    )
    service = _sql_route_service(
        route_uow_factory,
        provider_route_request,
        route_clock,
    )
    route = await service.authorize(provider_route_request)

    async with route_uow_factory() as uow:
        await uow.run_sync(
            lambda transaction: (
                transaction.exec_driver_sql(
                    "UPDATE budget_reservations SET state = 'released' WHERE id = ?",
                    (str(provider_route_request.budget_reservation_id),),
                ).rowcount
            )
        )
        await uow.commit()

    with pytest.raises(PermissionError, match="route_invalidated:budget_reservation"):
        await service.consume(route.authorization_id, provider_route_consumption)
    assert await service.count_consumptions(route.authorization_id) == 0


@pytest.mark.asyncio
async def test_sql_phase1_adapter_keeps_qwen_disabled_even_with_activation_store(
    route_uow_factory: AsyncUnitOfWorkFactory,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
) -> None:
    qwen_request = provider_route_request.model_copy(
        update={"provider": "qwen", "model": "qwen3.7-plus"}
    )
    await _seed_sql_route_prerequisites(
        route_uow_factory,
        qwen_request,
        route_clock,
    )
    qwen_store = _SqlQwenActivationStore(_qwen_activation(qwen_request, route_clock))
    prerequisites = SqlRoutePrerequisites(
        route_clock,
        _SqlSubjectAuthority(qwen_request),
        _SqlConsentEvidence(qwen_request),
        _SqlRuntimeIdentities(),
        qwen_activation_store=qwen_store,
    )
    service = RouteAuthorizationService(route_uow_factory, prerequisites, route_clock)

    with pytest.raises(PermissionError, match="^route_invalidated:qwen_activation$"):
        await service.authorize(qwen_request)

    assert await _authorization_artifact_counts(route_uow_factory) == (0, 0)

    async with route_uow_factory() as uow:
        with pytest.raises(PermissionError, match="^route_invalidated:qwen_activation$"):
            await prerequisites.require_provider_activation(
                uow,
                qwen_request.provider,
                qwen_request.model,
                qwen_request.purpose,
            )
        qwen_route = authorization_from_request(
            qwen_request,
            authorization_id=uuid4(),
            expires_at=route_clock.now() + timedelta(seconds=30),
        )
        qwen_envelope = RouteAuthorizationEnvelopeV1(
            route=qwen_route,
            subject_authority_generation=7,
            qwen_activation=qwen_store.current,
        )
        qwen_consumption = RouteConsumption(
            **qwen_request.model_dump(
                mode="python",
                include={
                    "request_id",
                    "attempt_id",
                    "purpose",
                    "household_id",
                    "subject_id",
                    "session_id",
                    "turn_id",
                    "provider",
                    "model",
                    "request_commitment",
                },
            ),
            input_bytes=1,
            input_units=1,
            consumed_at=route_clock.now(),
        )
        with pytest.raises(PermissionError, match="^route_invalidated:qwen_activation$"):
            await uow.run_sync(
                lambda transaction: prerequisites.require_consumable_in_transaction(
                    transaction,
                    qwen_envelope,
                    qwen_consumption,
                    route_clock.now(),
                )
            )
        await uow.rollback()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("gate", "raw_error", "expected"),
    [
        (
            "subject",
            RuntimeError("raw-subject-id=private-family-member"),
            "route_invalidated:subject_authority",
        ),
        (
            "consent",
            ValueError("raw-consent-receipt=private-evidence"),
            "route_invalidated:consent",
        ),
    ],
)
async def test_sql_identity_ports_fail_closed_without_leaking_raw_errors(
    route_uow_factory: AsyncUnitOfWorkFactory,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    gate: str,
    raw_error: Exception,
    expected: str,
) -> None:
    await _seed_sql_route_prerequisites(
        route_uow_factory,
        provider_route_request,
        route_clock,
    )
    subjects = _SqlSubjectAuthority(provider_route_request)
    consent = _SqlConsentEvidence(provider_route_request)
    if gate == "subject":
        subjects.error = raw_error
    else:
        consent.error = raw_error
    service = RouteAuthorizationService(
        route_uow_factory,
        SqlRoutePrerequisites(
            route_clock,
            subjects,
            consent,
            _SqlRuntimeIdentities(),
        ),
        route_clock,
    )

    with pytest.raises(PermissionError, match=f"^{expected}$") as captured:
        await service.authorize(provider_route_request)

    assert captured.value.__cause__ is None
    assert captured.value.__suppress_context__ is True
    assert "raw-" not in str(captured.value)
    assert await _authorization_artifact_counts(route_uow_factory) == (0, 0)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("gate", "raw_error", "expected"),
    [
        (
            "subject",
            RuntimeError("raw-subject-id=private-family-member"),
            "route_invalidated:subject_authority",
        ),
        (
            "consent",
            ValueError("raw-consent-receipt=private-evidence"),
            "route_invalidated:consent",
        ),
    ],
)
async def test_sql_identity_port_failures_during_consume_are_sanitized(
    route_uow_factory: AsyncUnitOfWorkFactory,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    provider_route_consumption: RouteConsumption,
    gate: str,
    raw_error: Exception,
    expected: str,
) -> None:
    await _seed_sql_route_prerequisites(
        route_uow_factory,
        provider_route_request,
        route_clock,
    )
    subjects = _SqlSubjectAuthority(provider_route_request)
    consent = _SqlConsentEvidence(provider_route_request)
    service = RouteAuthorizationService(
        route_uow_factory,
        SqlRoutePrerequisites(
            route_clock,
            subjects,
            consent,
            _SqlRuntimeIdentities(),
        ),
        route_clock,
    )
    route = await service.authorize(provider_route_request)
    if gate == "subject":
        subjects.error = raw_error
    else:
        consent.error = raw_error

    with pytest.raises(PermissionError, match=f"^{expected}$") as captured:
        await service.consume(route.authorization_id, provider_route_consumption)

    assert captured.value.__cause__ is None
    assert captured.value.__suppress_context__ is True
    assert "raw-" not in str(captured.value)
    assert await service.count_consumptions(route.authorization_id) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("generation", [0, True, "7"])
async def test_sql_subject_authority_generation_must_be_an_exact_positive_integer(
    route_uow_factory: AsyncUnitOfWorkFactory,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    generation: object,
) -> None:
    subjects = _SqlSubjectAuthority(provider_route_request)
    subjects.generation = generation  # type: ignore[assignment]
    service = RouteAuthorizationService(
        route_uow_factory,
        SqlRoutePrerequisites(
            route_clock,
            subjects,
            _SqlConsentEvidence(provider_route_request),
            _SqlRuntimeIdentities(),
        ),
        route_clock,
    )

    with pytest.raises(PermissionError, match="^route_invalidated:subject_authority$"):
        await service.authorize(provider_route_request)

    assert await _authorization_artifact_counts(route_uow_factory) == (0, 0)


@pytest.mark.asyncio
@pytest.mark.parametrize("gate", ["subject", "consent"])
async def test_sql_identity_ports_preserve_cancellation(
    route_uow_factory: AsyncUnitOfWorkFactory,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    gate: str,
) -> None:
    subjects = _SqlSubjectAuthority(provider_route_request)
    consent = _SqlConsentEvidence(provider_route_request)
    if gate == "subject":
        subjects.error = asyncio.CancelledError()
    else:
        consent.error = asyncio.CancelledError()
    service = RouteAuthorizationService(
        route_uow_factory,
        SqlRoutePrerequisites(
            route_clock,
            subjects,
            consent,
            _SqlRuntimeIdentities(),
        ),
        route_clock,
    )

    with pytest.raises(asyncio.CancelledError):
        await service.authorize(provider_route_request)

    assert await _authorization_artifact_counts(route_uow_factory) == (0, 0)


@pytest.mark.asyncio
async def test_consume_is_single_use_after_service_restart(
    route_database: RouteDatabase,
    provider_route_prerequisites: PrerequisitesFake,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    provider_route_consumption: RouteConsumption,
) -> None:
    first_factory = AsyncUnitOfWorkFactory(route_database.engine)
    try:
        first = RouteAuthorizationService(
            first_factory,
            provider_route_prerequisites,
            route_clock,
        )
        route = await first.authorize(provider_route_request)
        await first.consume(route.authorization_id, provider_route_consumption)
    finally:
        await first_factory.aclose()

    restarted_factory = AsyncUnitOfWorkFactory(route_database.engine)
    try:
        restarted = RouteAuthorizationService(
            restarted_factory,
            provider_route_prerequisites,
            route_clock,
        )
        with pytest.raises(PermissionError, match="route_authorization_consumed"):
            await restarted.consume(route.authorization_id, provider_route_consumption)
        assert await restarted.count_consumptions(route.authorization_id) == 1
        assert provider_route_prerequisites.transaction_checks == 1
    finally:
        await restarted_factory.aclose()


@pytest.mark.asyncio
async def test_same_attempt_cannot_mint_two_routes_after_restart(
    route_database: RouteDatabase,
    provider_route_prerequisites: PrerequisitesFake,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
) -> None:
    first_factory = AsyncUnitOfWorkFactory(route_database.engine)
    try:
        first = RouteAuthorizationService(
            first_factory,
            provider_route_prerequisites,
            route_clock,
        )
        first_route = await first.authorize(provider_route_request)
    finally:
        await first_factory.aclose()

    restarted_factory = AsyncUnitOfWorkFactory(route_database.engine)
    try:
        restarted = RouteAuthorizationService(
            restarted_factory,
            provider_route_prerequisites,
            route_clock,
        )
        with pytest.raises(PermissionError, match="route_authorization_already_issued"):
            await restarted.authorize(provider_route_request)
        raw, envelope = await _stored_envelope(
            restarted_factory,
            first_route.authorization_id,
        )
        assert raw.encode("utf-8") == canonical_bytes(envelope)
        assert envelope.route == first_route
    finally:
        await restarted_factory.aclose()


@pytest.mark.asyncio
async def test_concurrent_double_consume_commits_exactly_once(
    route_uow_factory: AsyncUnitOfWorkFactory,
    provider_route_prerequisites: PrerequisitesFake,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    provider_route_consumption: RouteConsumption,
) -> None:
    service = RouteAuthorizationService(
        route_uow_factory,
        provider_route_prerequisites,
        route_clock,
    )
    route = await service.authorize(provider_route_request)

    outcomes = await asyncio.gather(
        service.consume(route.authorization_id, provider_route_consumption),
        service.consume(route.authorization_id, provider_route_consumption),
        return_exceptions=True,
    )

    assert sum(outcome is None for outcome in outcomes) == 1
    failures = [outcome for outcome in outcomes if isinstance(outcome, BaseException)]
    assert len(failures) == 1
    assert isinstance(failures[0], PermissionError)
    assert str(failures[0]) == "route_authorization_consumed"
    assert await service.count_consumptions(route.authorization_id) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid",
    [
        "subject_authority",
        "consent",
        "privacy",
        "turn",
        "provider_review",
        "budget_reservation",
        "transaction_barrier",
    ],
)
async def test_consume_atomically_rechecks_every_available_revocable_state(
    route_uow_factory: AsyncUnitOfWorkFactory,
    provider_route_prerequisites: PrerequisitesFake,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    provider_route_consumption: RouteConsumption,
    invalid: str,
) -> None:
    service = RouteAuthorizationService(
        route_uow_factory,
        provider_route_prerequisites,
        route_clock,
    )
    route = await service.authorize(provider_route_request)
    provider_route_prerequisites.invalid = invalid

    with pytest.raises(PermissionError, match=f"route_invalidated:{invalid}"):
        await service.consume(route.authorization_id, provider_route_consumption)

    assert await service.count_consumptions(route.authorization_id) == 0


@pytest.mark.asyncio
async def test_consumption_mismatch_and_unknown_route_create_no_receipt(
    route_uow_factory: AsyncUnitOfWorkFactory,
    provider_route_prerequisites: PrerequisitesFake,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    provider_route_consumption: RouteConsumption,
) -> None:
    service = RouteAuthorizationService(
        route_uow_factory,
        provider_route_prerequisites,
        route_clock,
    )
    route = await service.authorize(provider_route_request)
    mismatch = provider_route_consumption.model_copy(update={"attempt_id": uuid4()})

    with pytest.raises(PermissionError, match="route_consumption_mismatch"):
        await service.consume(route.authorization_id, mismatch)
    with pytest.raises(PermissionError, match="route_authorization_unknown"):
        await service.consume(uuid4(), provider_route_consumption)

    assert await service.count_consumptions(route.authorization_id) == 0


@pytest.mark.asyncio
async def test_expired_route_fails_before_prerequisite_rechecks(
    route_uow_factory: AsyncUnitOfWorkFactory,
    provider_route_prerequisites: PrerequisitesFake,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    provider_route_consumption: RouteConsumption,
) -> None:
    service = RouteAuthorizationService(
        route_uow_factory,
        provider_route_prerequisites,
        route_clock,
    )
    route = await service.authorize(provider_route_request)
    calls_after_authorize = tuple(provider_route_prerequisites.call_log)
    route_clock.advance(timedelta(seconds=30))

    with pytest.raises(PermissionError, match="route_authorization_expired"):
        await service.consume(route.authorization_id, provider_route_consumption)

    assert tuple(provider_route_prerequisites.call_log) == calls_after_authorize
    assert await service.count_consumptions(route.authorization_id) == 0


@pytest.mark.asyncio
async def test_expiry_crossed_during_rechecks_fails_at_the_final_writer_barrier(
    route_uow_factory: AsyncUnitOfWorkFactory,
    provider_route_prerequisites: PrerequisitesFake,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    provider_route_consumption: RouteConsumption,
) -> None:
    service = RouteAuthorizationService(
        route_uow_factory,
        provider_route_prerequisites,
        route_clock,
    )
    route = await service.authorize(provider_route_request)
    route_clock.advance(timedelta(seconds=29, microseconds=999_999))
    provider_route_prerequisites.on_consent = lambda: route_clock.advance(timedelta(microseconds=1))

    with pytest.raises(PermissionError, match="route_authorization_expired"):
        await service.consume(route.authorization_id, provider_route_consumption)

    assert route_clock.now() == route.expires_at
    assert await service.count_consumptions(route.authorization_id) == 0


@pytest.mark.asyncio
async def test_expiry_crossed_inside_writer_rechecks_creates_no_receipt(
    route_uow_factory: AsyncUnitOfWorkFactory,
    provider_route_prerequisites: PrerequisitesFake,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    provider_route_consumption: RouteConsumption,
) -> None:
    service = RouteAuthorizationService(
        route_uow_factory,
        provider_route_prerequisites,
        route_clock,
    )
    route = await service.authorize(provider_route_request)
    route_clock.advance(timedelta(seconds=29, microseconds=999_999))
    provider_route_prerequisites.on_consumption_barrier = lambda: route_clock.advance(
        timedelta(microseconds=1)
    )

    with pytest.raises(PermissionError, match="route_authorization_expired"):
        await service.consume(route.authorization_id, provider_route_consumption)

    assert route_clock.now() == route.expires_at
    assert await service.count_consumptions(route.authorization_id) == 0


@pytest.mark.asyncio
async def test_authorization_expiring_inside_writer_barrier_is_not_persisted(
    route_uow_factory: AsyncUnitOfWorkFactory,
    provider_route_prerequisites: PrerequisitesFake,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
) -> None:
    service = RouteAuthorizationService(
        route_uow_factory,
        provider_route_prerequisites,
        route_clock,
    )
    provider_route_prerequisites.on_authorization_barrier = lambda: route_clock.advance(
        timedelta(seconds=30)
    )

    with pytest.raises(PermissionError, match="route_authorization_expired"):
        await service.authorize(provider_route_request)

    async with route_uow_factory() as uow:
        persisted = await uow.run_sync(
            lambda transaction: transaction.exec_driver_sql(
                "SELECT count(*) FROM runtime_settings WHERE key GLOB 'route.authorization.*'"
            ).scalar_one()
        )
        issued = await uow.run_sync(
            lambda transaction: transaction.exec_driver_sql(
                "SELECT count(*) FROM idempotency_receipts "
                "WHERE operation = 'provider.route.authorize'"
            ).scalar_one()
        )
        await uow.rollback()

    assert (persisted, issued) == (0, 0)


@pytest.mark.asyncio
async def test_noncanonical_or_key_mismatched_envelope_fails_closed(
    route_uow_factory: AsyncUnitOfWorkFactory,
    provider_route_prerequisites: PrerequisitesFake,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    provider_route_consumption: RouteConsumption,
) -> None:
    service = RouteAuthorizationService(
        route_uow_factory,
        provider_route_prerequisites,
        route_clock,
    )
    route = await service.authorize(provider_route_request)
    raw, envelope = await _stored_envelope(route_uow_factory, route.authorization_id)

    async with route_uow_factory() as uow:
        await uow.run_sync(
            lambda transaction: (
                transaction.exec_driver_sql(
                    "UPDATE runtime_settings SET value_json = ? WHERE key = ?",
                    (f" {raw}", f"route.authorization.{route.authorization_id}"),
                ).rowcount
            )
        )
        await uow.commit()
    with pytest.raises(PermissionError, match="^route_authorization_corrupt$") as captured:
        await service.consume(route.authorization_id, provider_route_consumption)
    assert captured.value.__cause__ is None
    assert captured.value.__suppress_context__ is True

    mismatched = envelope.model_copy(
        update={"route": route.model_copy(update={"authorization_id": uuid4()})}
    )
    async with route_uow_factory() as uow:
        await uow.run_sync(
            lambda transaction: (
                transaction.exec_driver_sql(
                    "UPDATE runtime_settings SET value_json = ? WHERE key = ?",
                    (
                        canonical_bytes(mismatched).decode("utf-8"),
                        f"route.authorization.{route.authorization_id}",
                    ),
                ).rowcount
            )
        )
        await uow.commit()
    with pytest.raises(PermissionError, match="route_authorization_corrupt"):
        await service.consume(route.authorization_id, provider_route_consumption)

    assert await service.count_consumptions(route.authorization_id) == 0


@pytest.mark.asyncio
async def test_guest_envelope_has_no_subject_generation(
    route_uow_factory: AsyncUnitOfWorkFactory,
    provider_route_prerequisites: PrerequisitesFake,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
) -> None:
    guest_request = provider_route_request.model_copy(update={"subject_id": None})
    provider_route_prerequisites.bind_to_request(guest_request)
    service = RouteAuthorizationService(
        route_uow_factory,
        provider_route_prerequisites,
        route_clock,
    )

    route = await service.authorize(guest_request)
    _, envelope = await _stored_envelope(route_uow_factory, route.authorization_id)

    assert route.subject_id is None
    assert envelope.subject_authority_generation is None


@pytest.mark.asyncio
async def test_revocation_committed_first_deletes_only_the_matching_unused_route(
    route_uow_factory: AsyncUnitOfWorkFactory,
    provider_route_prerequisites: PrerequisitesFake,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    provider_route_consumption: RouteConsumption,
) -> None:
    service = RouteAuthorizationService(
        route_uow_factory,
        provider_route_prerequisites,
        route_clock,
    )
    route = await service.authorize(provider_route_request)

    async with route_uow_factory() as uow:
        revoked = await service.invalidate_subject_purpose_in_uow(
            uow,
            provider_route_request.subject_id,
            provider_route_request.purpose,
            route_clock.now(),
        )
        await uow.commit()

    assert revoked == (route.authorization_id,)
    with pytest.raises(PermissionError, match="route_authorization_unknown"):
        await service.consume(route.authorization_id, provider_route_consumption)
    assert await service.count_consumptions(route.authorization_id) == 0


@pytest.mark.asyncio
async def test_consumption_committed_first_is_not_rewritten_as_revoked(
    route_uow_factory: AsyncUnitOfWorkFactory,
    provider_route_prerequisites: PrerequisitesFake,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    provider_route_consumption: RouteConsumption,
) -> None:
    service = RouteAuthorizationService(
        route_uow_factory,
        provider_route_prerequisites,
        route_clock,
    )
    route = await service.authorize(provider_route_request)
    await service.consume(route.authorization_id, provider_route_consumption)

    async with route_uow_factory() as uow:
        revoked = await service.invalidate_subject_purpose_in_uow(
            uow,
            provider_route_request.subject_id,
            provider_route_request.purpose,
            route_clock.now(),
        )
        await uow.commit()

    assert revoked == ()
    assert await service.count_consumptions(route.authorization_id) == 1
    _, envelope = await _stored_envelope(route_uow_factory, route.authorization_id)
    assert envelope.route == route


@pytest.mark.asyncio
async def test_revocation_ignores_more_than_1024_unrelated_route_envelopes(
    route_uow_factory: AsyncUnitOfWorkFactory,
    provider_route_prerequisites: PrerequisitesFake,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
) -> None:
    service = RouteAuthorizationService(
        route_uow_factory,
        provider_route_prerequisites,
        route_clock,
    )
    route = await service.authorize(provider_route_request)
    _, envelope = await _stored_envelope(route_uow_factory, route.authorization_id)
    unrelated_subject = uuid4()
    updated_at = route_clock.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def seed_unrelated(transaction: UnitOfWorkProtocol) -> int:
        inserted = 0
        for _ in range(1_025):
            unrelated_id = uuid4()
            unrelated_route = envelope.route.model_copy(
                update={
                    "authorization_id": unrelated_id,
                    "subject_id": unrelated_subject,
                }
            )
            unrelated_envelope = envelope.model_copy(update={"route": unrelated_route})
            inserted += transaction.exec_driver_sql(
                "INSERT INTO runtime_settings(key,value_json,version,updated_at) VALUES(?,?,1,?)",
                (
                    f"route.authorization.{unrelated_id}",
                    canonical_bytes(unrelated_envelope).decode("utf-8"),
                    updated_at,
                ),
            ).rowcount
        return inserted

    async with route_uow_factory() as uow:
        assert await uow.run_sync(seed_unrelated) == 1_025
        await uow.commit()

    async with route_uow_factory() as uow:
        revoked = await service.invalidate_subject_purpose_in_uow(
            uow,
            provider_route_request.subject_id,
            provider_route_request.purpose,
            route_clock.now(),
        )
        await uow.commit()

    assert revoked == (route.authorization_id,)


@pytest.mark.asyncio
async def test_revocation_pages_past_more_than_1024_matching_consumed_routes(
    route_database: RouteDatabase,
    route_uow_factory: AsyncUnitOfWorkFactory,
    provider_route_prerequisites: PrerequisitesFake,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    provider_route_consumption: RouteConsumption,
) -> None:
    live_authorization_id = UUID(int=(1 << 128) - 1)
    service = RouteAuthorizationService(
        route_uow_factory,
        provider_route_prerequisites,
        route_clock,
        authorization_id_factory=lambda: live_authorization_id,
    )
    live_route = await service.authorize(provider_route_request)
    _, live_envelope = await _stored_envelope(
        route_uow_factory,
        live_route.authorization_id,
    )
    expired_at = route_clock.now() - timedelta(seconds=1)
    timestamp = route_clock.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    expired_timestamp = expired_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    route_rows: list[tuple[object, ...]] = []
    receipt_rows: list[tuple[object, ...]] = []
    consumed_ids: list[UUID] = []
    for index in range(1, 1_026):
        consumed_id = UUID(int=index)
        consumed_ids.append(consumed_id)
        consumed_route = live_envelope.route.model_copy(
            update={
                "authorization_id": consumed_id,
                "expires_at": expired_at,
            }
        )
        consumed_envelope = live_envelope.model_copy(update={"route": consumed_route})
        route_rows.append(
            (
                f"route.authorization.{consumed_id}",
                canonical_bytes(consumed_envelope).decode("utf-8"),
                timestamp,
            )
        )
        receipt_rows.append(
            (
                str(UUID(int=100_000 + index)),
                str(provider_route_request.household_id),
                str(consumed_id),
                timestamp,
                expired_timestamp,
            )
        )

    def seed_matching_consumed(transaction: UnitOfWorkProtocol) -> tuple[int, int]:
        routes = transaction.exec_driver_sql(
            "INSERT INTO runtime_settings(key,value_json,version,updated_at) VALUES(?,?,1,?)",
            route_rows,
        ).rowcount
        receipts = transaction.exec_driver_sql(
            "INSERT INTO idempotency_receipts("
            "id,operation,scope,idempotency_key,state,first_seen_at,last_seen_at,expires_at"
            ") VALUES(?,'provider.route.consume',?,?,'completed',?,?,?)",
            [(*row[:4], row[3], row[4]) for row in receipt_rows],
        ).rowcount
        return routes, receipts

    async with route_uow_factory() as uow:
        assert await uow.run_sync(seed_matching_consumed) == (1_025, 1_025)
        await uow.commit()

    scan_statements: list[str] = []

    def capture_scan(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        if "SELECT key,value_json FROM runtime_settings" in statement:
            scan_statements.append(statement)

    event.listen(route_database.engine, "before_cursor_execute", capture_scan)
    try:
        async with route_uow_factory() as uow:
            revoked = await service.invalidate_subject_purpose_in_uow(
                uow,
                provider_route_request.subject_id,
                provider_route_request.purpose,
                route_clock.now(),
            )
            await uow.commit()
    finally:
        event.remove(route_database.engine, "before_cursor_execute", capture_scan)

    assert revoked == (live_authorization_id,)
    assert len(scan_statements) > 1
    assert all(" LIMIT " in statement.upper() for statement in scan_statements)
    sampled_consumed_id = consumed_ids[512]
    assert await service.count_consumptions(sampled_consumed_id) == 1
    with pytest.raises(PermissionError, match="^route_authorization_consumed$"):
        await service.consume(sampled_consumed_id, provider_route_consumption)
    with pytest.raises(PermissionError, match="^route_authorization_unknown$"):
        await service.consume(live_authorization_id, provider_route_consumption)


@pytest.mark.asyncio
async def test_revocation_deletes_matching_corrupt_route_without_scanning_unrelated_corrupt(
    route_uow_factory: AsyncUnitOfWorkFactory,
    provider_route_prerequisites: PrerequisitesFake,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
) -> None:
    service = RouteAuthorizationService(
        route_uow_factory,
        provider_route_prerequisites,
        route_clock,
    )
    route = await service.authorize(provider_route_request)
    _, envelope = await _stored_envelope(route_uow_factory, route.authorization_id)
    corrupt_matching_id = uuid4()
    corrupt_unrelated_id = uuid4()
    corrupt_matching = envelope.model_copy(
        update={
            "route": envelope.route.model_copy(update={"authorization_id": corrupt_matching_id})
        }
    )
    corrupt_unrelated = envelope.model_copy(
        update={
            "route": envelope.route.model_copy(
                update={
                    "authorization_id": corrupt_unrelated_id,
                    "subject_id": uuid4(),
                }
            )
        }
    )
    timestamp = route_clock.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    async with route_uow_factory() as uow:
        await uow.run_sync(
            lambda transaction: (
                transaction.exec_driver_sql(
                    "INSERT INTO runtime_settings(key,value_json,version,updated_at) "
                    "VALUES(?,?,1,?),(?,?,1,?)",
                    (
                        f"route.authorization.{corrupt_matching_id}",
                        " " + canonical_bytes(corrupt_matching).decode("utf-8"),
                        timestamp,
                        f"route.authorization.{corrupt_unrelated_id}",
                        " " + canonical_bytes(corrupt_unrelated).decode("utf-8"),
                        timestamp,
                    ),
                ).rowcount
            )
        )
        await uow.commit()

    async with route_uow_factory() as uow:
        revoked = await service.invalidate_subject_purpose_in_uow(
            uow,
            provider_route_request.subject_id,
            provider_route_request.purpose,
            route_clock.now(),
        )
        await uow.commit()

    assert set(revoked) == {route.authorization_id, corrupt_matching_id}
    async with route_uow_factory() as uow:
        unrelated_exists = await uow.run_sync(
            lambda transaction: transaction.exec_driver_sql(
                "SELECT count(*) FROM runtime_settings WHERE key = ?",
                (f"route.authorization.{corrupt_unrelated_id}",),
            ).scalar_one()
        )
        await uow.rollback()
    assert unrelated_exists == 1
