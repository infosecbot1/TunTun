from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import partial
from types import TracebackType
from typing import Annotated, Literal, Protocol, Self
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field, model_validator
from tuntun_contracts.base import (
    Commitment,
    ContractModel,
    ContractParseError,
    canonical_bytes,
    parse_contract_json,
)
from tuntun_contracts.budget import LlmUsageUnits, SttUsageUnits, TtsUsageUnits
from tuntun_contracts.provider import (
    RouteAuthorization,
    RouteAuthorizationRequest,
    RouteConsumption,
)
from tuntun_core.services.transactions.protocols import (
    AsyncUnitOfWorkProtocol,
    UnitOfWorkProtocol,
)

from .review import ProviderReviewStore, RuntimeProviderIdentityReader
from .route_verifier import authorization_from_request, verify_route_consumption

_ROUTE_TTL = timedelta(seconds=30)
_ROUTE_ENVELOPE_MAX_BYTES = 131_072
_REVOCATION_SCAN_BATCH_SIZE = 128
_ISSUE_OPERATION = "provider.route.authorize"
_CONSUME_OPERATION = "provider.route.consume"


class QwenRouteActivationBindingV1(ContractModel):
    schema_version: Literal["tuntun.qwen-route-activation.v1"]
    owner_activation_commitment: Commitment
    evaluation_report_commitment: Commitment
    endpoint_authority_commitment: Commitment
    pricing_schedule_commitment: Commitment
    workspace_probe_receipt_id: UUID
    workspace_probe_generation: Annotated[int, Field(ge=1)]
    workspace_probe_commitment: Commitment
    workspace_probe_expires_at: AwareDatetime
    workspace_id: Annotated[
        str,
        Field(
            min_length=1,
            max_length=63,
            pattern=r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
        ),
    ]
    region: Literal["ap-southeast-1"]
    base_url: Annotated[str, Field(min_length=1, max_length=256)]
    resolved_model_snapshot: Literal["qwen3.7-plus-2026-05-26"]
    endpoint_review_version: Annotated[int, Field(ge=1)]
    endpoint_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    pricing_version: Annotated[str, Field(min_length=1, max_length=128)]
    price_source_url: Literal["https://www.alibabacloud.com/help/en/model-studio/model-pricing"]
    price_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    fx_version: Annotated[str, Field(min_length=1, max_length=128)]
    fx_micros_sgd_per_usd: Annotated[int, Field(ge=1, le=10_000_000)]
    fx_source: Annotated[str, Field(min_length=1, max_length=256)]
    fx_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    fx_record_commitment: Commitment
    terms_review_version: Annotated[int, Field(ge=1)]
    terms_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def exact_endpoint_and_expiry(self) -> Self:
        expected_base_url = (
            f"https://{self.workspace_id}.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1"
        )
        if self.base_url != expected_base_url:
            raise ValueError("qwen_route_activation_endpoint_mismatch")
        if self.expires_at > self.workspace_probe_expires_at:
            raise ValueError("qwen_route_activation_expiry_mismatch")
        return self


class PrivacyReceiptBindingV1(ContractModel):
    schema_version: Literal["tuntun.privacy-receipt-binding.v1"]
    receipt_id: UUID
    turn_id: UUID
    active: Literal[True]
    expires_at: AwareDatetime


class RouteAuthorizationEnvelopeV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    route: RouteAuthorization
    subject_authority_generation: Annotated[int | None, Field(default=None, ge=1)]
    qwen_activation: QwenRouteActivationBindingV1 | None = None

    @model_validator(mode="after")
    def bindings_match_route(self) -> Self:
        if (self.route.subject_id is None) != (self.subject_authority_generation is None):
            raise ValueError("route_subject_authority_generation_mismatch")
        if (self.route.provider == "qwen") != (self.qwen_activation is not None):
            raise ValueError("route_qwen_activation_binding_mismatch")
        if self.qwen_activation is not None and self.route.model != "qwen3.7-plus":
            raise ValueError("route_qwen_activation_binding_mismatch")
        return self


class AsyncUnitOfWorkContext(AsyncUnitOfWorkProtocol, Protocol):
    async def __aenter__(self) -> Self: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool: ...


class AsyncUnitOfWorkFactory(Protocol):
    def __call__(self) -> AsyncUnitOfWorkContext: ...


class Clock(Protocol):
    def now(self) -> datetime: ...


class RoutePrerequisites(Protocol):
    async def require_current_subject_authority(
        self,
        uow: AsyncUnitOfWorkProtocol,
        household_id: UUID,
        subject_id: UUID | None,
        expected_generation: int | None = None,
    ) -> int | None: ...

    async def require_current_consent(
        self,
        uow: AsyncUnitOfWorkProtocol,
        household_id: UUID,
        subject_id: UUID | None,
        session_id: UUID,
        purpose: str,
        receipt_ids: tuple[UUID, ...],
    ) -> None: ...

    async def require_privacy_receipt(
        self,
        uow: AsyncUnitOfWorkProtocol,
        receipt_id: UUID,
        turn_id: UUID,
    ) -> None: ...

    async def require_provider_review(
        self,
        uow: AsyncUnitOfWorkProtocol,
        provider: str,
        model: str,
        purpose: str,
    ) -> None: ...

    async def require_provider_activation(
        self,
        uow: AsyncUnitOfWorkProtocol,
        provider: str,
        model: str,
        purpose: str,
        expected: QwenRouteActivationBindingV1 | None = None,
    ) -> QwenRouteActivationBindingV1 | None: ...

    async def require_budget_reservation(
        self,
        uow: AsyncUnitOfWorkProtocol,
        request: RouteAuthorizationRequest,
    ) -> None: ...

    def require_authorizable_in_transaction(
        self,
        transaction: UnitOfWorkProtocol,
        envelope: RouteAuthorizationEnvelopeV1,
        now: datetime,
    ) -> None: ...

    def require_consumable_in_transaction(
        self,
        transaction: UnitOfWorkProtocol,
        envelope: RouteAuthorizationEnvelopeV1,
        consumption: RouteConsumption,
        now: datetime,
    ) -> None: ...


class SubjectAuthorityVerifier(Protocol):
    async def require_current_in_uow(
        self,
        uow: AsyncUnitOfWorkProtocol,
        household_id: UUID,
        subject_id: UUID,
        expected_generation: int | None,
    ) -> int: ...


class ConsentEvidenceVerifier(Protocol):
    async def require_exact_in_uow(
        self,
        uow: AsyncUnitOfWorkProtocol,
        household_id: UUID,
        subject_id: UUID | None,
        session_id: UUID,
        purpose: str,
        receipt_ids: tuple[UUID, ...],
    ) -> None: ...


class QwenActivationStore(Protocol):
    def require_current_in_transaction(
        self,
        transaction: UnitOfWorkProtocol,
        *,
        model: str,
        purpose: str,
        expected: QwenRouteActivationBindingV1 | None,
        now: datetime,
    ) -> QwenRouteActivationBindingV1: ...


def _trusted_now(clock: Clock) -> datetime:
    value = clock.now()
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise RuntimeError("route authorization clock must return an aware datetime")
    return value.astimezone(UTC)


def _utc_storage(value: datetime) -> str:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise TypeError("stored timestamp must be timezone-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _runtime_key(authorization_id: UUID) -> str:
    if type(authorization_id) is not UUID:
        raise TypeError("authorization_id must be an exact UUID")
    return f"route.authorization.{authorization_id}"


def _parse_persisted_route_envelope(raw: object) -> RouteAuthorizationEnvelopeV1:
    if type(raw) is not str:
        raise PermissionError("route_authorization_corrupt")
    try:
        return parse_contract_json(
            RouteAuthorizationEnvelopeV1,
            raw.encode("utf-8"),
            max_bytes=_ROUTE_ENVELOPE_MAX_BYTES,
            require_canonical=True,
        )
    except (ContractParseError, UnicodeError, ValueError):
        raise PermissionError("route_authorization_corrupt") from None


def _select_text_setting(
    transaction: UnitOfWorkProtocol,
    key: str,
) -> str | None:
    row = transaction.exec_driver_sql(
        "SELECT value_json FROM runtime_settings WHERE key = ?",
        (key,),
    ).fetchone()
    if row is None:
        return None
    value = row[0]
    if type(value) is not str:
        raise PermissionError("route_authorization_corrupt")
    return value


def _idempotency_exists(
    transaction: UnitOfWorkProtocol,
    operation: str,
    household_id: UUID,
    idempotency_key: UUID,
) -> bool:
    value = transaction.exec_driver_sql(
        "SELECT count(*) FROM idempotency_receipts "
        "WHERE operation = ? AND scope = ? AND idempotency_key = ?",
        (operation, str(household_id), str(idempotency_key)),
    ).scalar_one()
    if type(value) is not int or value not in (0, 1):
        raise RuntimeError("invalid route consumption state")
    return value == 1


def _consumption_exists(
    transaction: UnitOfWorkProtocol,
    household_id: UUID,
    authorization_id: UUID,
) -> bool:
    return _idempotency_exists(
        transaction,
        _CONSUME_OPERATION,
        household_id,
        authorization_id,
    )


def _consumption_exists_any_scope(
    transaction: UnitOfWorkProtocol,
    authorization_id: UUID,
) -> bool:
    value = transaction.exec_driver_sql(
        "SELECT count(*) FROM idempotency_receipts WHERE operation = ? AND idempotency_key = ?",
        (_CONSUME_OPERATION, str(authorization_id)),
    ).scalar_one()
    if type(value) is not int or value not in (0, 1):
        raise RuntimeError("invalid route consumption state")
    return value == 1


def _authorization_id_from_runtime_key(key: object) -> UUID | None:
    prefix = "route.authorization."
    if type(key) is not str or not key.startswith(prefix):
        return None
    suffix = key.removeprefix(prefix)
    try:
        authorization_id = UUID(suffix)
    except ValueError:
        return None
    if str(authorization_id) != suffix:
        return None
    return authorization_id


def _parse_privacy_receipt(raw: object) -> PrivacyReceiptBindingV1:
    if type(raw) is not str:
        raise PermissionError("route_invalidated:privacy")
    try:
        return parse_contract_json(
            PrivacyReceiptBindingV1,
            raw.encode("utf-8"),
            max_bytes=8_192,
            require_canonical=True,
        )
    except (ContractParseError, UnicodeError, ValueError):
        raise PermissionError("route_invalidated:privacy") from None


def _require_privacy_receipt_in_transaction(
    transaction: UnitOfWorkProtocol,
    receipt_id: UUID,
    turn_id: UUID,
    now: datetime,
) -> None:
    raw = _select_text_setting(transaction, f"privacy.receipt.{receipt_id}")
    if raw is None:
        raise PermissionError("route_invalidated:privacy")
    receipt = _parse_privacy_receipt(raw)
    if (
        receipt.receipt_id != receipt_id
        or receipt.turn_id != turn_id
        or now >= receipt.expires_at.astimezone(UTC)
    ):
        raise PermissionError("route_invalidated:privacy")


def _budget_category(purpose: str) -> Literal["stt", "llm", "tts"]:
    categories: dict[str, Literal["stt", "llm", "tts"]] = {
        "cloud_stt": "stt",
        "cloud_reasoning": "llm",
        "cloud_tts": "tts",
    }
    try:
        return categories[purpose]
    except (KeyError, TypeError):
        raise PermissionError("route_invalidated:budget_reservation") from None


def _parse_usage_ceiling(
    raw: object,
    category: Literal["stt", "llm", "tts"],
) -> LlmUsageUnits | SttUsageUnits | TtsUsageUnits:
    if type(raw) is not str:
        raise PermissionError("route_invalidated:budget_reservation")
    model_type: type[LlmUsageUnits] | type[SttUsageUnits] | type[TtsUsageUnits]
    if category == "llm":
        model_type = LlmUsageUnits
    elif category == "stt":
        model_type = SttUsageUnits
    else:
        model_type = TtsUsageUnits
    try:
        return parse_contract_json(
            model_type,
            raw.encode("utf-8"),
            max_bytes=8_192,
            require_canonical=True,
        )
    except (ContractParseError, UnicodeError, ValueError):
        raise PermissionError("route_invalidated:budget_reservation") from None


def _usage_input_units(
    usage: LlmUsageUnits | SttUsageUnits | TtsUsageUnits,
) -> int:
    if type(usage) is LlmUsageUnits:
        return usage.input_tokens
    if type(usage) is SttUsageUnits:
        return usage.audio_millis
    if type(usage) is TtsUsageUnits:
        return usage.characters
    raise PermissionError("route_invalidated:budget_reservation")


def _require_budget_reservation_in_transaction(
    transaction: UnitOfWorkProtocol,
    binding: RouteAuthorizationRequest | RouteAuthorization,
    now: datetime,
) -> None:
    category = _budget_category(binding.purpose)
    row = transaction.exec_driver_sql(
        "SELECT usage_ceiling_json FROM budget_reservations "
        "WHERE id = ? AND request_id = ? AND attempt_id = ? "
        "AND provider = ? AND model = ? AND category = ? "
        "AND outcome IN ('allow','allow_soft_warning') "
        "AND state = 'reserved' AND transport_phase = 'not_claimed' "
        "AND gateway_ordering_version = 1 AND reserved_micros_sgd > 0 "
        "AND price_snapshot_json IS NOT NULL AND charged_micros_sgd IS NULL "
        "AND settled_at IS NULL AND expires_at > ?",
        (
            str(binding.budget_reservation_id),
            str(binding.request_id),
            str(binding.attempt_id),
            binding.provider,
            binding.model,
            category,
            _utc_storage(now),
        ),
    ).fetchone()
    if row is None:
        raise PermissionError("route_invalidated:budget_reservation")
    usage = _parse_usage_ceiling(row[0], category)
    if _usage_input_units(usage) != binding.max_input_units:
        raise PermissionError("route_invalidated:budget_reservation")


def _require_active_session_in_transaction(
    transaction: UnitOfWorkProtocol,
    route: RouteAuthorization,
) -> None:
    if route.subject_id is None:
        subject_clause = "speaker_subject_id IS NULL"
        parameters: tuple[object, ...] = (
            str(route.session_id),
            str(route.household_id),
        )
    else:
        subject_clause = "speaker_subject_id = ?"
        parameters = (
            str(route.session_id),
            str(route.household_id),
            str(route.subject_id),
        )
    row = transaction.exec_driver_sql(
        "SELECT 1 FROM sessions WHERE id = ? AND household_id = ? "
        "AND state = 'active' AND closed_at IS NULL AND " + subject_clause,
        parameters,
    ).fetchone()
    if row is None:
        raise PermissionError("route_invalidated:turn")


class SqlRoutePrerequisites:
    """SQL-backed Phase-1 gates with Task-17 identity/consent ports injected."""

    def __init__(
        self,
        clock: Clock,
        subjects: SubjectAuthorityVerifier,
        consent: ConsentEvidenceVerifier,
        runtime_identities: RuntimeProviderIdentityReader,
        *,
        qwen_activation_store: QwenActivationStore | None = None,
    ) -> None:
        self._clock = clock
        self._subjects = subjects
        self._consent = consent
        self._runtime_identities = runtime_identities
        self._qwen_activation_store = qwen_activation_store

    async def require_current_subject_authority(
        self,
        uow: AsyncUnitOfWorkProtocol,
        household_id: UUID,
        subject_id: UUID | None,
        expected_generation: int | None = None,
    ) -> int | None:
        if subject_id is None:
            if expected_generation is not None:
                raise PermissionError("route_invalidated:subject_authority")
            return None
        try:
            generation = await self._subjects.require_current_in_uow(
                uow,
                household_id,
                subject_id,
                expected_generation,
            )
        except Exception:
            raise PermissionError("route_invalidated:subject_authority") from None
        if (
            type(generation) is not int
            or generation < 1
            or (expected_generation is not None and generation != expected_generation)
        ):
            raise PermissionError("route_invalidated:subject_authority")
        return generation

    async def require_current_consent(
        self,
        uow: AsyncUnitOfWorkProtocol,
        household_id: UUID,
        subject_id: UUID | None,
        session_id: UUID,
        purpose: str,
        receipt_ids: tuple[UUID, ...],
    ) -> None:
        try:
            await self._consent.require_exact_in_uow(
                uow,
                household_id,
                subject_id,
                session_id,
                purpose,
                receipt_ids,
            )
        except Exception:
            raise PermissionError("route_invalidated:consent") from None

    async def require_privacy_receipt(
        self,
        uow: AsyncUnitOfWorkProtocol,
        receipt_id: UUID,
        turn_id: UUID,
    ) -> None:
        now = _trusted_now(self._clock)
        await uow.run_sync(
            lambda transaction: _require_privacy_receipt_in_transaction(
                transaction,
                receipt_id,
                turn_id,
                now,
            )
        )

    async def require_provider_review(
        self,
        uow: AsyncUnitOfWorkProtocol,
        provider: str,
        model: str,
        purpose: str,
    ) -> None:
        if provider == "qwen":
            # Task 03 has no Qwen provider-review/runtime-account reader yet.
            # Keep the production SQL adapter disabled even if a future activation
            # store is accidentally injected.
            raise PermissionError("route_invalidated:qwen_activation")
        now = _trusted_now(self._clock)

        def require(transaction: UnitOfWorkProtocol) -> None:
            try:
                ProviderReviewStore(
                    transaction,
                    self._runtime_identities,
                ).require_current(provider, model, purpose, now)
            except PermissionError:
                raise PermissionError("route_invalidated:provider_review") from None

        await uow.run_sync(require)

    async def require_provider_activation(
        self,
        uow: AsyncUnitOfWorkProtocol,
        provider: str,
        model: str,
        purpose: str,
        expected: QwenRouteActivationBindingV1 | None = None,
    ) -> QwenRouteActivationBindingV1 | None:
        if provider == "qwen":
            raise PermissionError("route_invalidated:qwen_activation")
        if provider != "openai" or expected is not None:
            raise PermissionError("route_invalidated:qwen_activation")
        del uow, model, purpose
        return None

    async def require_budget_reservation(
        self,
        uow: AsyncUnitOfWorkProtocol,
        request: RouteAuthorizationRequest,
    ) -> None:
        now = _trusted_now(self._clock)
        await uow.run_sync(
            lambda transaction: _require_budget_reservation_in_transaction(
                transaction,
                request,
                now,
            )
        )

    def require_authorizable_in_transaction(
        self,
        transaction: UnitOfWorkProtocol,
        envelope: RouteAuthorizationEnvelopeV1,
        now: datetime,
    ) -> None:
        self._require_runtime_state(transaction, envelope, now)

    def require_consumable_in_transaction(
        self,
        transaction: UnitOfWorkProtocol,
        envelope: RouteAuthorizationEnvelopeV1,
        consumption: RouteConsumption,
        now: datetime,
    ) -> None:
        del consumption
        self._require_runtime_state(transaction, envelope, now)

    def _require_runtime_state(
        self,
        transaction: UnitOfWorkProtocol,
        envelope: RouteAuthorizationEnvelopeV1,
        now: datetime,
    ) -> None:
        route = envelope.route
        _require_active_session_in_transaction(transaction, route)
        _require_privacy_receipt_in_transaction(
            transaction,
            route.privacy_receipt_id,
            route.turn_id,
            now,
        )
        if route.provider == "qwen" or envelope.qwen_activation is not None:
            raise PermissionError("route_invalidated:qwen_activation")
        try:
            ProviderReviewStore(
                transaction,
                self._runtime_identities,
            ).require_current(route.provider, route.model, route.purpose, now)
        except PermissionError:
            raise PermissionError("route_invalidated:provider_review") from None
        _require_budget_reservation_in_transaction(transaction, route, now)


class RouteAuthorizationService:
    def __init__(
        self,
        uow_factory: AsyncUnitOfWorkFactory,
        prerequisites: RoutePrerequisites,
        clock: Clock,
        *,
        authorization_id_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._uow_factory = uow_factory
        self._prerequisites = prerequisites
        self._clock = clock
        self._authorization_id_factory = authorization_id_factory

    async def authorize(self, request: RouteAuthorizationRequest) -> RouteAuthorization:
        if type(request) is not RouteAuthorizationRequest:
            raise TypeError("request must be an exact RouteAuthorizationRequest")
        async with self._uow_factory() as uow:
            already_issued = await uow.run_sync(
                lambda transaction: _idempotency_exists(
                    transaction,
                    _ISSUE_OPERATION,
                    request.household_id,
                    request.attempt_id,
                )
            )
            if already_issued:
                raise PermissionError("route_authorization_already_issued")
            subject_generation = await self._prerequisites.require_current_subject_authority(
                uow,
                request.household_id,
                request.subject_id,
            )
            await self._prerequisites.require_current_consent(
                uow,
                request.household_id,
                request.subject_id,
                request.session_id,
                request.purpose,
                request.consent_receipt_ids,
            )
            await self._prerequisites.require_privacy_receipt(
                uow,
                request.privacy_receipt_id,
                request.turn_id,
            )
            await self._prerequisites.require_provider_review(
                uow,
                request.provider,
                request.model,
                request.purpose,
            )
            qwen_activation = await self._prerequisites.require_provider_activation(
                uow,
                request.provider,
                request.model,
                request.purpose,
            )
            await self._prerequisites.require_budget_reservation(
                uow,
                request,
            )
            now = _trusted_now(self._clock)
            authorization_id = self._authorization_id_factory()
            if type(authorization_id) is not UUID:
                raise RuntimeError("authorization id factory must return an exact UUID")
            route = authorization_from_request(
                request,
                authorization_id=authorization_id,
                expires_at=now + _ROUTE_TTL,
            )
            envelope = RouteAuthorizationEnvelopeV1(
                route=route,
                subject_authority_generation=subject_generation,
                qwen_activation=qwen_activation,
            )

            def persist_authorization(transaction: UnitOfWorkProtocol) -> tuple[int, int]:
                writer_now = _trusted_now(self._clock)
                if writer_now < now:
                    raise RuntimeError("route authorization clock moved backwards")
                if writer_now >= route.expires_at.astimezone(UTC):
                    raise PermissionError("route_authorization_expired")
                self._prerequisites.require_authorizable_in_transaction(
                    transaction,
                    envelope,
                    writer_now,
                )
                persisted_at = _trusted_now(self._clock)
                if persisted_at < writer_now:
                    raise RuntimeError("route authorization clock moved backwards")
                if persisted_at >= route.expires_at.astimezone(UTC):
                    raise PermissionError("route_authorization_expired")
                route_count = transaction.exec_driver_sql(
                    "INSERT INTO runtime_settings(key,value_json,version,updated_at) "
                    "VALUES(?,?,1,?)",
                    (
                        _runtime_key(route.authorization_id),
                        canonical_bytes(envelope).decode("utf-8"),
                        _utc_storage(persisted_at),
                    ),
                ).rowcount
                receipt_count = transaction.exec_driver_sql(
                    "INSERT INTO idempotency_receipts("
                    "id,operation,scope,idempotency_key,state,"
                    "first_seen_at,last_seen_at,expires_at"
                    ") VALUES(?,?,?,?,?,?,?,?)",
                    (
                        str(uuid4()),
                        _ISSUE_OPERATION,
                        str(route.household_id),
                        str(route.attempt_id),
                        "completed",
                        _utc_storage(persisted_at),
                        _utc_storage(persisted_at),
                        _utc_storage(route.expires_at),
                    ),
                ).rowcount
                return route_count, receipt_count

            persisted = await uow.run_sync(persist_authorization)
            if persisted != (1, 1):
                raise RuntimeError("route authorization persistence lost ownership")
            await uow.commit()
            return route
        raise RuntimeError("route authorization transaction suppressed an exception")

    async def consume(
        self,
        authorization_id: UUID,
        consumption: RouteConsumption,
    ) -> None:
        if type(authorization_id) is not UUID:
            raise TypeError("authorization_id must be an exact UUID")
        if type(consumption) is not RouteConsumption:
            raise TypeError("consumption must be an exact RouteConsumption")
        async with self._uow_factory() as uow:
            raw = await uow.run_sync(
                lambda transaction: _select_text_setting(
                    transaction,
                    _runtime_key(authorization_id),
                )
            )
            if raw is None:
                raise PermissionError("route_authorization_unknown")
            envelope = _parse_persisted_route_envelope(raw)
            route = envelope.route
            if route.authorization_id != authorization_id:
                raise PermissionError("route_authorization_corrupt")
            already_consumed = await uow.run_sync(
                lambda transaction: _consumption_exists(
                    transaction,
                    route.household_id,
                    route.authorization_id,
                )
            )
            if already_consumed:
                raise PermissionError("route_authorization_consumed")

            now = _trusted_now(self._clock)
            verify_route_consumption(route, consumption, now=now)
            await self._prerequisites.require_current_subject_authority(
                uow,
                route.household_id,
                route.subject_id,
                envelope.subject_authority_generation,
            )
            await self._prerequisites.require_current_consent(
                uow,
                route.household_id,
                route.subject_id,
                route.session_id,
                route.purpose,
                route.consent_receipt_ids,
            )
            final_now = _trusted_now(self._clock)
            verify_route_consumption(route, consumption, now=final_now)

            def persist_consumption(transaction: UnitOfWorkProtocol) -> int:
                writer_now = _trusted_now(self._clock)
                if writer_now < final_now:
                    raise RuntimeError("route authorization clock moved backwards")
                verify_route_consumption(route, consumption, now=writer_now)
                self._prerequisites.require_consumable_in_transaction(
                    transaction,
                    envelope,
                    consumption,
                    writer_now,
                )
                receipt_now = _trusted_now(self._clock)
                if receipt_now < writer_now:
                    raise RuntimeError("route authorization clock moved backwards")
                verify_route_consumption(route, consumption, now=receipt_now)
                receipt_id = uuid4()
                return transaction.exec_driver_sql(
                    "INSERT INTO idempotency_receipts("
                    "id,operation,scope,idempotency_key,state,"
                    "first_seen_at,last_seen_at,expires_at"
                    ") VALUES(?,?,?,?,?,?,?,?)",
                    (
                        str(receipt_id),
                        _CONSUME_OPERATION,
                        str(route.household_id),
                        str(route.authorization_id),
                        "completed",
                        _utc_storage(receipt_now),
                        _utc_storage(receipt_now),
                        _utc_storage(route.expires_at),
                    ),
                ).rowcount

            persisted = await uow.run_sync(persist_consumption)
            if persisted != 1:
                raise RuntimeError("route consumption persistence lost ownership")
            await uow.commit()

    async def count_consumptions(self, authorization_id: UUID) -> int:
        if type(authorization_id) is not UUID:
            raise TypeError("authorization_id must be an exact UUID")
        async with self._uow_factory() as uow:
            value = await uow.run_sync(
                lambda transaction: transaction.exec_driver_sql(
                    "SELECT count(*) FROM idempotency_receipts "
                    "WHERE operation = ? AND idempotency_key = ?",
                    (_CONSUME_OPERATION, str(authorization_id)),
                ).scalar_one()
            )
            await uow.rollback()
        if type(value) is not int or value < 0:
            raise RuntimeError("invalid route consumption count")
        return value

    async def invalidate_subject_purpose_in_uow(
        self,
        uow: AsyncUnitOfWorkProtocol,
        subject_id: UUID,
        purpose: str,
        now: datetime,
    ) -> tuple[UUID, ...]:
        """Delete matching unused routes inside the caller's revocation transaction."""

        if type(subject_id) is not UUID:
            raise TypeError("subject_id must be an exact UUID")
        if type(purpose) is not str or purpose not in {
            "cloud_stt",
            "cloud_reasoning",
            "cloud_tts",
        }:
            raise TypeError("purpose must be an exact cloud route purpose")
        _utc_storage(now)

        def invalidate_batch(
            transaction: UnitOfWorkProtocol,
            cursor: str,
        ) -> tuple[str, tuple[UUID, ...], int]:
            rows = transaction.exec_driver_sql(
                "SELECT key,value_json FROM runtime_settings "
                "WHERE key GLOB 'route.authorization.*' "
                "AND json_type(value_json,'$.route.subject_id') = 'text' "
                "AND json_extract(value_json,'$.route.subject_id') = ? "
                "AND json_type(value_json,'$.route.purpose') = 'text' "
                "AND json_extract(value_json,'$.route.purpose') = ? "
                "AND key > ? ORDER BY key LIMIT ?",
                (
                    str(subject_id),
                    purpose,
                    cursor,
                    _REVOCATION_SCAN_BATCH_SIZE,
                ),
            ).fetchall()
            next_cursor = cursor
            revoked_batch: list[UUID] = []
            for row in rows:
                key, raw = row
                if type(key) is not str or type(raw) is not str:
                    raise PermissionError("route_authorization_corrupt")
                next_cursor = key
                key_authorization_id = _authorization_id_from_runtime_key(key)
                try:
                    envelope = _parse_persisted_route_envelope(raw)
                except PermissionError:
                    if key_authorization_id is not None and _consumption_exists_any_scope(
                        transaction,
                        key_authorization_id,
                    ):
                        continue
                    deleted = transaction.exec_driver_sql(
                        "DELETE FROM runtime_settings WHERE key = ?",
                        (key,),
                    ).rowcount
                    if deleted != 1:
                        raise RuntimeError(
                            "route authorization revocation lost ownership"
                        ) from None
                    if key_authorization_id is not None:
                        revoked_batch.append(key_authorization_id)
                    continue
                route = envelope.route
                if key != _runtime_key(route.authorization_id):
                    if key_authorization_id is not None and _consumption_exists_any_scope(
                        transaction,
                        key_authorization_id,
                    ):
                        continue
                    deleted = transaction.exec_driver_sql(
                        "DELETE FROM runtime_settings WHERE key = ?",
                        (key,),
                    ).rowcount
                    if deleted != 1:
                        raise RuntimeError("route authorization revocation lost ownership")
                    if key_authorization_id is not None:
                        revoked_batch.append(key_authorization_id)
                    continue
                if route.subject_id != subject_id or route.purpose != purpose:
                    continue
                if _consumption_exists(
                    transaction,
                    route.household_id,
                    route.authorization_id,
                ):
                    continue
                deleted = transaction.exec_driver_sql(
                    "DELETE FROM runtime_settings WHERE key = ?",
                    (key,),
                ).rowcount
                if deleted != 1:
                    raise RuntimeError("route authorization revocation lost ownership")
                revoked_batch.append(route.authorization_id)
            return next_cursor, tuple(revoked_batch), len(rows)

        cursor = ""
        revoked: list[UUID] = []
        while True:
            cursor, revoked_batch, scanned = await uow.run_sync(
                partial(invalidate_batch, cursor=cursor)
            )
            revoked.extend(revoked_batch)
            if scanned < _REVOCATION_SCAN_BATCH_SIZE:
                return tuple(revoked)
