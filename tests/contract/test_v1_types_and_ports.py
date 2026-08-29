# tests/contract/test_v1_types_and_ports.py
from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from enum import Enum
from typing import Literal, Protocol, TypeVar, get_origin
from uuid import UUID

import pytest
import tuntun_contracts
from pydantic import TypeAdapter, ValidationError
from tuntun_contracts.actions import (
    ActionBinding,
    ActionProposalDraft,
    ActionReceipt,
    ConsentActionDraft,
    IdentityActionDraft,
    ProfileActionDraft,
    TimerCreateActionDraft,
    TimerTargetActionDraft,
)
from tuntun_contracts.audit import AuditDraft, AuditReceipt
from tuntun_contracts.base import (
    Commitment,
    ContractModel,
    Sensitivity,
    canonical_bytes,
    registered_contract_models,
)
from tuntun_contracts.budget import (
    BudgetReconciliationRequest,
    BudgetReservation,
    BudgetReservationRequest,
    BudgetSettlement,
    BudgetSettlementRequest,
    LlmUsageUnits,
    ProviderUsageReceiptV1,
    SttUsageUnits,
    TransportProof,
    TtsUsageUnits,
    WebSearchUsageUnits,
)
from tuntun_contracts.events import StopRequestedPayload
from tuntun_contracts.identity import (
    IdentityEvidence,
    IdentityRequest,
    PersonaProjection,
    PersonaTraits,
)
from tuntun_contracts.memory import (
    ApprovedMemory,
    EpisodicContent,
    MemoryAudience,
    MemoryKind,
    MemoryProposalDraft,
    MemoryQuery,
    PreferenceContent,
    ProceduralContent,
    WorkingContent,
)
from tuntun_contracts.policy import (
    AdminSessionPrincipal,
    AssuranceLevel,
    AuthGrant,
    CurrentOwnerAuthority,
)
from tuntun_contracts.ports import (
    ActionProviderPort,
    AsyncTransactionBoundary,
    AuditPort,
    AuthenticationPort,
    BudgetPort,
    LanguageModelPort,
    MemoryRepositoryPort,
    ReachyPort,
    RouteAuthorizerPort,
)
from tuntun_contracts.provider import (
    ProviderName,
    ProviderResponse,
    RedactionReceipt,
    RouteAuthorization,
    SanitizedProviderMessage,
    SanitizedProviderRequest,
    SanitizedToolReference,
)
from tuntun_contracts.reachy import StopSignal
from tuntun_contracts.speech import (
    AudioFormat,
    AuthorizedSynthesisRequest,
    AuthorizedTranscriptionRequest,
)

_T = TypeVar("_T")


class _PlannedExecutable(Protocol):
    pass


class _PlannedCursorResult(Protocol):
    pass


class _PlannedUnitOfWorkProtocol(Protocol):
    def execute(
        self,
        statement: _PlannedExecutable,
        parameters: Mapping[str, object] | None = None,
    ) -> _PlannedCursorResult: ...

    def exec_driver_sql(
        self,
        statement: str,
        parameters: tuple[object, ...] | Mapping[str, object] = (),
    ) -> _PlannedCursorResult: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...


class _PlannedAsyncUnitOfWorkProtocol(Protocol):
    async def run_sync(
        self,
        operation: Callable[[_PlannedUnitOfWorkProtocol], _T],
    ) -> _T: ...

    def signal_after_commit(self, name: str) -> None: ...

    async def commit(self) -> None: ...

    async def rollback(self) -> None: ...


class _PlannedAuditLedger:
    def append(
        self,
        uow: _PlannedUnitOfWorkProtocol,
        draft: AuditDraft,
    ) -> AuditReceipt:
        raise NotImplementedError


class _PlannedAsyncAuditLedger:
    def __init__(self, ledger: _PlannedAuditLedger) -> None:
        self._ledger = ledger

    async def append(
        self,
        uow: _PlannedAsyncUnitOfWorkProtocol,
        draft: AuditDraft,
    ) -> AuditReceipt:
        return await uow.run_sync(lambda transaction: self._ledger.append(transaction, draft))


def _bind_planned_audit_ledger(
    ledger: _PlannedAsyncAuditLedger,
) -> AuditPort[_PlannedAsyncUnitOfWorkProtocol]:
    return ledger


def test_every_registered_contract_model_is_strict_closed_and_frozen() -> None:
    # The explicit root imports complete the registry; fixture discovery is not
    # the authority for this test.
    registered = registered_contract_models()
    assert registered
    violations = {
        f"{model.__module__}.{model.__qualname__}": dict(model.model_config)
        for model in registered
        if model.model_config.get("strict") is not True
        or model.model_config.get("extra") != "forbid"
        or model.model_config.get("frozen") is not True
    }
    assert violations == {}


def test_root_exports_registry_and_public_type_families_are_exact() -> None:
    exports = tuntun_contracts.__all__
    assert type(exports) is tuple
    assert len(exports) == len(set(exports)) == 136
    assert len(registered_contract_models()) == 93

    enum_names = {
        name
        for name in exports
        if isinstance(exported := getattr(tuntun_contracts, name), type)
        and issubclass(exported, Enum)
    }
    assert enum_names == {
        "AssuranceLevel",
        "EventType",
        "IdentityStatus",
        "MemoryAudience",
        "MemoryKind",
        "PolicyEffect",
        "ProviderName",
        "ReachyState",
        "RiskTier",
        "Sensitivity",
    }
    protocol_names = {
        name for name in exports if getattr(getattr(tuntun_contracts, name), "_is_protocol", False)
    }
    assert protocol_names == {
        "ActionProviderPort",
        "AsyncTransactionBoundary",
        "AudioConverterPort",
        "AuthenticationPort",
        "AuditPort",
        "BudgetPort",
        "ClockPort",
        "ConversationWorkflow",
        "IdentityFusionPort",
        "LanguageModelPort",
        "MemoryProposalServicePort",
        "MemoryRepositoryPort",
        "PolicyEnginePort",
        "ReachyPort",
        "RouteAuthorizerPort",
        "SpeechToTextPort",
        "StopInputPort",
        "TextToSpeechPort",
    }
    alias_names = {
        name for name in exports if get_origin(getattr(tuntun_contracts, name)) is not None
    }
    assert alias_names == {
        "ActionProposalDraft",
        "EventPayload",
        "JSONValue",
        "MemoryContent",
        "UsageUnits",
    }
    assert {
        "MAX_AUDIO_MILLIS",
        "MAX_CHARGE_MICROS_SGD",
        "MAX_USAGE_UNITS",
        "MAX_WEB_SEARCH_CALLS",
        "usage_total",
    }.isdisjoint(exports)


def test_public_contract_collection_schemas_are_never_variadic() -> None:
    expected: dict[tuple[type[ContractModel], str], tuple[int, int]] = {
        (SanitizedProviderRequest, "messages"): (1, 32),
        (SanitizedProviderRequest, "allowed_tools"): (0, 8),
        (AuthorizedTranscriptionRequest, "language_hints"): (1, 2),
        (IdentityRequest, "evidence"): (0, 2),
        (BudgetReconciliationRequest, "proofs"): (0, 8),
        (RedactionReceipt, "removed_categories"): (0, 16),
        (WorkingContent, "unresolved_intents"): (0, 8),
        (EpisodicContent, "participant_ids"): (0, 16),
        (ProceduralContent, "steps"): (1, 32),
        (MemoryQuery, "kinds"): (1, 7),
        (ApprovedMemory, "source_receipt_ids"): (1, 8),
    }
    for (model, field), (minimum, maximum) in expected.items():
        schema = model.model_json_schema()["properties"][field]
        assert schema.get("minItems", 0) == minimum
        assert schema["maxItems"] == maximum


def test_required_memory_kinds_are_exact() -> None:
    assert {kind.value for kind in MemoryKind} == {
        "working",
        "episodic",
        "semantic",
        "preference",
        "procedural",
        "relational",
        "policy",
    }
    with pytest.raises(ValidationError):
        PreferenceContent.model_validate(
            {
                "category": "food",
                "key": "spice",
                "value": "high",
                "strength_micros": 1.5,
            }
        )


def test_memory_audiences_are_closed() -> None:
    assert {audience.value for audience in MemoryAudience} == {
        "subject_private",
        "guardian_child",
        "household_adults",
        "household_all",
    }


def test_memory_proposal_operation_target_shape_is_total_and_unambiguous() -> None:
    content = PreferenceContent(
        category="food",
        key="spice",
        value="medium",
        strength_micros=500_000,
    )
    common: dict[str, object] = {
        "proposal_id": UUID(int=501),
        "schema_version": "1.0",
        "household_id": UUID(int=502),
        "subject_id": UUID(int=503),
        "session_id": UUID(int=504),
        "turn_id": UUID(int=505),
        "idempotency_key": UUID(int=506),
        "sensitivity": Sensitivity.PERSONAL,
        "confidence_micros": 900_000,
        "reason": "synthetic proposal",
        "claim_commitment": Commitment(
            algorithm="HMAC-SHA-256",
            key_id="memory-claim-v1",
            value_b64="A" * 43 + "=",
        ),
        "source_receipt_ids": (UUID(int=507),),
        "expires_at": datetime(2026, 8, 27, tzinfo=UTC),
    }
    create = common | {
        "operation": "create",
        "content": content,
        "audience": MemoryAudience.SUBJECT_PRIVATE,
        "target_memory_id": None,
        "expected_version": None,
    }
    assert MemoryProposalDraft.model_validate(create).operation == "create"
    for target_memory_id, expected_version in (
        (UUID(int=508), None),
        (None, 1),
        (UUID(int=508), 1),
    ):
        with pytest.raises(ValidationError):
            MemoryProposalDraft.model_validate(
                create
                | {
                    "target_memory_id": target_memory_id,
                    "expected_version": expected_version,
                }
            )

    replace = create | {
        "operation": "replace",
        "target_memory_id": UUID(int=508),
        "expected_version": 1,
    }
    assert MemoryProposalDraft.model_validate(replace).operation == "replace"
    for target_memory_id, expected_version in (
        (None, None),
        (UUID(int=508), None),
        (None, 1),
    ):
        with pytest.raises(ValidationError):
            MemoryProposalDraft.model_validate(
                replace
                | {
                    "target_memory_id": target_memory_id,
                    "expected_version": expected_version,
                }
            )

    delete = replace | {"operation": "delete", "content": None, "audience": None}
    assert MemoryProposalDraft.model_validate(delete).operation == "delete"
    for target_memory_id, expected_version in (
        (None, None),
        (UUID(int=508), None),
        (None, 1),
    ):
        with pytest.raises(ValidationError):
            MemoryProposalDraft.model_validate(
                delete
                | {
                    "target_memory_id": target_memory_id,
                    "expected_version": expected_version,
                }
            )


def test_budget_request_carries_closed_usage_not_a_caller_cost() -> None:
    common = {
        "household_id": UUID(int=61),
        "turn_id": UUID(int=62),
        "request_id": UUID(int=63),
        "attempt_id": UUID(int=64),
        "provider": "openai",
        "model": "gpt-5.6-sol",
        "category": "llm",
        "month_key": "2026-08",
        "usage_ceiling": LlmUsageUnits(category="llm", input_tokens=8_000, output_tokens=2_000),
    }
    request = BudgetReservationRequest.model_validate(common)
    assert tuple(BudgetReservationRequest.model_fields) == (
        "household_id",
        "turn_id",
        "request_id",
        "attempt_id",
        "provider",
        "model",
        "category",
        "usage_ceiling",
        "month_key",
    )
    assert request.usage_ceiling.category == "llm"
    for caller_amount in (-1, 0, 1, 1_000_000_000_001):
        with pytest.raises(ValidationError):
            BudgetReservationRequest.model_validate(
                common | {"worst_case_micros_sgd": caller_amount}
            )
    with pytest.raises(ValidationError):
        BudgetReservationRequest.model_validate(
            common
            | {
                "category": "stt",
            }
        )
    with pytest.raises(ValidationError):
        BudgetReservationRequest.model_validate(
            common
            | {
                "usage_ceiling": LlmUsageUnits(category="llm", input_tokens=0, output_tokens=0),
            }
        )
    with pytest.raises(ValidationError):
        LlmUsageUnits(category="llm", input_tokens=10_000_001, output_tokens=0)
    with pytest.raises(ValidationError):
        SttUsageUnits(category="stt", audio_millis=3_600_001)
    with pytest.raises(ValidationError):
        TtsUsageUnits(category="tts", characters=4_097)
    assert (
        WebSearchUsageUnits(
            category="web_search",
            input_tokens=1,
            output_tokens=1,
            web_search_calls=1,
        ).web_search_calls
        == 1
    )
    for calls in (0, 2, -1, 17):
        with pytest.raises(ValidationError):
            BudgetReservationRequest.model_validate(
                common
                | {
                    "category": "web_search",
                    "usage_ceiling": {
                        "category": "web_search",
                        "input_tokens": 1,
                        "output_tokens": 1,
                        "web_search_calls": calls,
                    },
                }
            )


def test_budget_settlement_has_no_caller_actual_and_reports_overrun_freeze_truth() -> None:
    request = BudgetSettlementRequest(reservation_id=UUID(int=65), attempt_id=UUID(int=66))
    assert tuple(BudgetSettlementRequest.model_fields) == (
        "reservation_id",
        "attempt_id",
    )
    for injected in ({"actual_micros_sgd": 1}, {"provider_usage_present": True}):
        with pytest.raises(ValidationError):
            BudgetSettlementRequest.model_validate(request.model_dump() | injected)
    settlement = BudgetSettlement(
        reservation_id=request.reservation_id,
        charged_micros_sgd=501,
        conservative_estimate_used=False,
        estimate_overrun=True,
        cloud_egress_frozen=True,
    )
    assert settlement.estimate_overrun and settlement.cloud_egress_frozen
    with pytest.raises(ValidationError):
        BudgetSettlement.model_validate(
            settlement.model_dump() | {"charged_micros_sgd": 1_000_000_000_001}
        )


def test_provider_usage_receipt_is_closed_and_bound_to_the_exact_call() -> None:
    commitment = Commitment(
        algorithm="HMAC-SHA-256", key_id="provider-usage-v1", value_b64="A" * 43 + "="
    )
    receipt = ProviderUsageReceiptV1(
        schema_version="tuntun.provider-usage-receipt.v1",
        receipt_id=UUID(int=67),
        provider_call_id=UUID(int=68),
        reservation_id=UUID(int=69),
        request_id=UUID(int=70),
        attempt_id=UUID(int=71),
        authorization_id=UUID(int=72),
        provider="openai",
        model="gpt-5.6-sol",
        category="llm",
        accounting_basis="provider_reported_exact",
        billable_usage=LlmUsageUnits(category="llm", input_tokens=100, output_tokens=25),
        provider_response_commitment=commitment,
        observed_at=datetime(2026, 8, 27, tzinfo=UTC),
        receipt_commitment=commitment,
    )
    assert tuple(ProviderUsageReceiptV1.model_fields) == (
        "schema_version",
        "receipt_id",
        "provider_call_id",
        "reservation_id",
        "request_id",
        "attempt_id",
        "authorization_id",
        "provider",
        "model",
        "category",
        "accounting_basis",
        "billable_usage",
        "provider_response_commitment",
        "observed_at",
        "receipt_commitment",
    )
    with pytest.raises(ValidationError):
        ProviderUsageReceiptV1.model_validate(
            receipt.model_dump()
            | {
                "category": "stt",
                "billable_usage": {
                    "category": "llm",
                    "input_tokens": 100,
                    "output_tokens": 25,
                },
            }
        )
    with pytest.raises(ValidationError, match="web_search_receipt_requires_exactly_one_call"):
        ProviderUsageReceiptV1.model_validate(
            receipt.model_dump()
            | {
                "category": "web_search",
                "billable_usage": {
                    "category": "web_search",
                    "input_tokens": 100,
                    "output_tokens": 25,
                    "web_search_calls": 2,
                },
            }
        )


def test_provider_response_exposes_only_the_persisted_usage_receipt_identity() -> None:
    response = ProviderResponse(
        request_id=UUID(int=76),
        text="synthetic",
        language="en",
        provider_usage_receipt_id=UUID(int=77),
    )
    assert tuple(ProviderResponse.model_fields) == (
        "request_id",
        "text",
        "language",
        "provider_usage_receipt_id",
    )
    assert (
        ProviderResponse(
            request_id=UUID(int=78),
            text="synthetic-without-usage",
            language="en",
            provider_usage_receipt_id=None,
        ).provider_usage_receipt_id
        is None
    )
    with pytest.raises(ValidationError):
        ProviderResponse.model_validate(
            response.model_dump()
            | {
                "usage": {
                    "input_units": 1,
                    "output_units": 1,
                    "audio_millis": 0,
                    "provider_usage_present": True,
                },
            }
        )


@pytest.mark.parametrize(
    ("outcome", "amount", "commitment_present"),
    [
        ("allow", 1, True),
        ("allow_soft_warning", 1_000_000_000_000, True),
        ("deny_hard_limit", 0, True),
        ("deny_unknown_price", 0, False),
        ("deny_cloud_egress_frozen", 0, False),
    ],
)
def test_budget_reservation_outcome_amount_and_quote_commitment_are_exact(
    outcome: Literal[
        "allow",
        "allow_soft_warning",
        "deny_hard_limit",
        "deny_unknown_price",
        "deny_cloud_egress_frozen",
    ],
    amount: int,
    commitment_present: bool,
) -> None:
    commitment = Commitment(algorithm="HMAC-SHA-256", key_id="pricing-v1", value_b64="A" * 43 + "=")
    reservation = BudgetReservation(
        reservation_id=UUID(int=73),
        request_id=UUID(int=74),
        attempt_id=UUID(int=75),
        outcome=outcome,
        amount_micros_sgd=amount,
        pricing_commitment=commitment if commitment_present else None,
        expires_at=datetime(2026, 8, 27, tzinfo=UTC),
    )
    assert reservation.amount_micros_sgd == amount
    with pytest.raises(ValidationError):
        BudgetReservation.model_validate(
            reservation.model_dump()
            | {
                "pricing_commitment": None if commitment_present else commitment,
            }
        )


def test_assurance_values_are_exact_and_auth_grants_have_no_biometric_source() -> None:
    assert {value.value for value in AssuranceLevel} == {
        "guest",
        "identified",
        "confirmed",
        "pin_verified",
        "passkey_verified",
        "recovery_verified",
    }
    assert "biometric" not in str(AuthGrant.model_json_schema()).lower()


def test_stop_event_and_stop_signal_share_the_exact_closed_sources() -> None:
    expected = {"edge_keyword", "physical_input", "owner_console", "watchdog"}
    assert set(StopRequestedPayload.model_json_schema()["properties"]["source"]["enum"]) == expected
    assert set(StopSignal.model_json_schema()["properties"]["source"]["enum"]) == expected


def test_route_authorization_is_attempt_and_purpose_specific() -> None:
    route = RouteAuthorization(
        authorization_id=UUID(int=1),
        request_id=UUID(int=9),
        attempt_id=UUID(int=2),
        purpose="cloud_reasoning",
        household_id=UUID(int=3),
        subject_id=None,
        session_id=UUID(int=4),
        turn_id=UUID(int=5),
        provider="openai",
        model="gpt-5.6-sol",
        request_commitment=Commitment(
            algorithm="HMAC-SHA-256", key_id="route-v1", value_b64="A" * 43 + "="
        ),
        max_input_bytes=8_388_608,
        max_input_units=8_000,
        privacy_receipt_id=UUID(int=6),
        consent_receipt_ids=(UUID(int=7),),
        budget_reservation_id=UUID(int=8),
        maximum_sensitivity=Sensitivity.HOUSEHOLD,
        expires_at=datetime(2026, 8, 27, tzinfo=UTC),
    )
    assert route.purpose == "cloud_reasoning" and route.subject_id is None
    assert tuple(RouteAuthorization.model_fields) == (
        "authorization_id",
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
        "max_input_bytes",
        "max_input_units",
        "privacy_receipt_id",
        "consent_receipt_ids",
        "budget_reservation_id",
        "maximum_sensitivity",
        "expires_at",
    )
    with pytest.raises(ValidationError):
        RouteAuthorization.model_validate(route.model_dump() | {"consent_receipt_ids": []})
    assert {"audio_commitment", "audio_bytes", "duration_ms"} <= set(
        AuthorizedTranscriptionRequest.model_fields
    )
    assert {"text_commitment", "segment_index", "segment_count"} <= set(
        AuthorizedSynthesisRequest.model_fields
    )


def test_public_request_collections_have_exact_caps_and_uniqueness() -> None:
    commitment = Commitment(
        algorithm="HMAC-SHA-256",
        key_id="bounds-v1",
        value_b64="A" * 43 + "=",
    )
    route = RouteAuthorization(
        authorization_id=UUID(int=801),
        request_id=UUID(int=802),
        attempt_id=UUID(int=803),
        purpose="cloud_reasoning",
        household_id=UUID(int=804),
        subject_id=None,
        session_id=UUID(int=805),
        turn_id=UUID(int=806),
        provider="openai",
        model="gpt-5.6-sol",
        request_commitment=commitment,
        max_input_bytes=1024,
        max_input_units=1024,
        privacy_receipt_id=UUID(int=807),
        consent_receipt_ids=(UUID(int=808),),
        budget_reservation_id=UUID(int=809),
        maximum_sensitivity=Sensitivity.HOUSEHOLD,
        expires_at=datetime(2026, 8, 27, tzinfo=UTC),
    )
    message = SanitizedProviderMessage(role="user", content="synthetic")
    tool = SanitizedToolReference(
        registered_name="safe.tool",
        schema_version="1.0",
        schema_commitment=commitment,
    )
    request = dict(
        request_id=route.request_id,
        provider=ProviderName.OPENAI,
        model=route.model,
        messages=(message,),
        allowed_tools=(),
        max_output_tokens=10,
        store=False,
        redaction_receipt_id=UUID(int=810),
        route=route,
        timeout_ms=1_000,
    )
    SanitizedProviderRequest.model_validate(request)
    for mutation in (
        {"messages": ()},
        {"messages": (message,) * 33},
        {"allowed_tools": (tool,) * 9},
    ):
        with pytest.raises(ValidationError):
            SanitizedProviderRequest.model_validate(request | mutation)

    audio = dict(
        request_id=UUID(int=811),
        turn_id=route.turn_id,
        audio_format=AudioFormat(
            sample_format="s16le",
            sample_rate_hz=16_000,
            channels=1,
            interleaved=True,
            channel_layout="mono",
        ),
        audio_commitment=commitment,
        audio_bytes=2,
        duration_ms=1,
        language_hints=("en",),
        route=route,
    )
    AuthorizedTranscriptionRequest.model_validate(audio)
    for hints in ((), ("en", "en"), ("en", "hi", "en")):
        with pytest.raises(ValidationError):
            AuthorizedTranscriptionRequest.model_validate(audio | {"language_hints": hints})

    observed = datetime(2026, 8, 27, tzinfo=UTC)
    evidence = IdentityEvidence(
        modality="face",
        subject_id=None,
        confidence_micros=1,
        quality_micros=1,
        liveness_accepted=False,
        model_version="synthetic",
        observed_at=observed,
        expires_at=observed,
    )
    with pytest.raises(ValidationError):
        IdentityRequest(
            household_id=route.household_id,
            session_id=route.session_id,
            evidence=(evidence, evidence),
        )
    with pytest.raises(ValidationError):
        IdentityRequest(
            household_id=route.household_id,
            session_id=route.session_id,
            evidence=(evidence,) * 3,
        )

    proof = TransportProof(
        reservation_id=route.budget_reservation_id,
        attempt_id=route.attempt_id,
        disposition="never_sent",
        evidence_code="synthetic",
        observed_at=observed,
    )
    with pytest.raises(ValidationError):
        BudgetReconciliationRequest(turn_id=route.turn_id, proofs=(proof, proof))
    with pytest.raises(ValidationError):
        BudgetReconciliationRequest(turn_id=route.turn_id, proofs=(proof,) * 9)

    provider_schema = SanitizedProviderRequest.model_json_schema()["properties"]
    speech_schema = AuthorizedTranscriptionRequest.model_json_schema()["properties"]
    assert (
        provider_schema["messages"]["minItems"],
        provider_schema["messages"]["maxItems"],
    ) == (
        1,
        32,
    )
    assert provider_schema["allowed_tools"]["maxItems"] == 8
    assert (
        speech_schema["language_hints"]["minItems"],
        speech_schema["language_hints"]["maxItems"],
    ) == (1, 2)


def test_action_receipt_is_frozen_for_downstream_consumers() -> None:
    fields = ActionReceipt.model_fields
    assert tuple(fields) == (
        "receipt_id",
        "proposal_id",
        "household_id",
        "action_name",
        "resource_scope",
        "resource_id",
        "idempotency_key",
        "outcome",
        "reason_code",
        "occurred_at",
    )


def test_owner_authority_and_admin_session_bind_all_current_epochs() -> None:
    assert tuple(CurrentOwnerAuthority.model_fields) == (
        "household_id",
        "subject_id",
        "owner_generation",
        "profile_version",
        "observed_at",
    )
    assert tuple(AdminSessionPrincipal.model_fields) == (
        "admin_session_id",
        "household_id",
        "subject_id",
        "owner_generation",
        "profile_version",
        "session_version",
        "access_mode",
        "authenticated_at",
        "idle_expires_at",
        "absolute_expires_at",
    )


def test_action_drafts_are_a_closed_discriminated_union() -> None:
    schema = TypeAdapter(ActionProposalDraft).json_schema()
    assert schema["discriminator"]["propertyName"] == "action_name"
    encoded = str(schema)
    assert all(
        name in encoded
        for name in (
            "timer.create",
            "backup.restore",
            "backup.recovery_key.create",
            "profile.delete",
            "identity.enroll",
            "identity.enrollment.cancel",
            "security.finding.suppress",
            "search.profile_mode.change",
            "search.experimental.activate",
            "release.latency.accept",
            "release.family_stage.review",
            "release.p1r0",
        )
    )
    assert "identity.discovery" not in encoded
    assert "identity.candidate" not in encoded
    assert "additionalProperties': True" not in encoded
    with pytest.raises(ValidationError):
        TypeAdapter(ActionProposalDraft).validate_python(
            {"action_name": "smart_home.unlock", "parameters": {}}
        )


def test_timer_drafts_bind_the_exact_server_resource(
    valid_action_fields: Callable[[str], dict[str, object]],
) -> None:
    with pytest.raises(ValidationError):
        TimerCreateActionDraft.model_validate(
            valid_action_fields("timer.create")
            | {
                "resource_type": "timer",
                "resource_id": None,
                "duration_seconds": 30,
                "label": "tea",
            }
        )
    timer_id = UUID(int=81)
    with pytest.raises(ValidationError):
        TimerTargetActionDraft.model_validate(
            valid_action_fields("timer.cancel")
            | {
                "resource_type": "timer",
                "resource_id": UUID(int=82),
                "timer_id": timer_id,
            }
        )


def test_ordinary_profile_create_cannot_create_an_owner(
    valid_action_fields: Callable[[str], dict[str, object]],
) -> None:
    subject_id = UUID(int=83)
    with pytest.raises(ValidationError):
        ProfileActionDraft.model_validate(
            valid_action_fields("profile.create")
            | {
                "resource_type": "profile",
                "resource_id": subject_id,
                "subject_id": subject_id,
                "profile_class": "owner",
                "display_label": "second owner",
            }
        )


def test_enrollment_cancel_requires_exact_non_null_enrollment_resource(
    valid_action_fields: Callable[[str], dict[str, object]],
) -> None:
    subject_id, enrollment_id = UUID(int=84), UUID(int=85)
    common = valid_action_fields("identity.enrollment.cancel") | {
        "resource_type": "identity",
        "subject_id": subject_id,
        "enrollment_id": enrollment_id,
    }
    for resource_id in (None, UUID(int=86)):
        with pytest.raises(ValidationError):
            IdentityActionDraft.model_validate(common | {"resource_id": resource_id})


def test_prepared_consent_action_schema_has_exact_durable_purposes() -> None:
    purpose_schema = ConsentActionDraft.model_json_schema()["properties"]["purpose"]
    assert set(purpose_schema["enum"]) == {
        "face",
        "voice",
        "personalization",
        "cloud_stt",
        "cloud_reasoning",
        "cloud_tts",
        "web_search",
        "child_durable_memory_v1",
    }


def test_persona_contract_is_minimized_typed_and_identifier_free() -> None:
    assert tuple(PersonaProjection.model_fields) == (
        "role",
        "context",
        "tone",
        "depth",
        "learning_level",
    )
    assert set(PersonaTraits.model_json_schema()["properties"]["context"]["enum"]) == {
        "general",
        "technical_security",
        "household_practical",
        "early_learning",
    }
    encoded = str(PersonaProjection.model_json_schema()).lower()
    assert all(
        forbidden not in encoded
        for forbidden in (
            "subject_id",
            "name",
            "birth",
            "school",
            "secret",
            "free_form",
        )
    )
    with pytest.raises(ValidationError):
        PersonaTraits.model_validate(
            {
                "context": "my private biography",
                "tone": "warm",
                "depth": "standard",
                "learning_level": "none",
            }
        )
    assert {
        "persona_traits",
        "clear_persona_traits",
        "target_profile_class",
        "expected_version",
        "guardian_generation",
    } <= set(ProfileActionDraft.model_fields)
    assert "profile_persona" in str(TypeAdapter(ActionProposalDraft).json_schema())


@pytest.mark.parametrize(
    "change",
    [
        {},
        {
            "persona_traits": PersonaTraits(
                context="general",
                tone="neutral",
                depth="standard",
                learning_level="none",
            )
        },
        {
            "profile_class": "adult",
            "persona_traits": PersonaTraits(
                context="general",
                tone="neutral",
                depth="standard",
                learning_level="none",
            ),
            "expected_version": 1,
        },
        {
            "persona_traits": PersonaTraits(
                context="general",
                tone="neutral",
                depth="standard",
                learning_level="none",
            ),
            "expected_version": 1,
            "guardian_generation": 2,
        },
        {
            "persona_traits": PersonaTraits(
                context="general",
                tone="neutral",
                depth="standard",
                learning_level="none",
            ),
            "clear_persona_traits": True,
            "expected_version": 1,
        },
    ],
)
def test_profile_edit_is_exactly_versioned_replace_or_clear_without_role_change(
    change: dict[str, object],
) -> None:
    common = {
        "proposal_id": UUID(int=21),
        "schema_version": "1.0",
        "action_name": "profile.edit",
        "resource_type": "profile",
        "resource_id": UUID(int=22),
        "subject_id": UUID(int=22),
        "target_profile_class": "adult",
        "parameters_commitment": Commitment(
            algorithm="HMAC-SHA-256", key_id="action-hmac-v1", value_b64="A" * 43 + "="
        ),
        "uncertainty_micros": 0,
        "expires_at": datetime(2026, 8, 27, tzinfo=UTC),
        "idempotency_key": UUID(int=23),
    }
    with pytest.raises(ValidationError):
        ProfileActionDraft.model_validate(common | change)


@pytest.mark.parametrize(
    ("target_profile_class", "guardian_generation", "operation"),
    [
        ("owner", None, "replace"),
        ("adult", None, "clear"),
        ("k2", 3, "replace"),
        ("n1", 4, "clear"),
    ],
)
def test_profile_edit_allows_exact_server_derived_self_or_guardian_shape(
    target_profile_class: Literal["owner", "adult", "k2", "n1"],
    guardian_generation: int | None,
    operation: Literal["replace", "clear"],
) -> None:
    learning_level: Literal["none", "n1", "k2"]
    if target_profile_class == "k2":
        learning_level = "k2"
    elif target_profile_class == "n1":
        learning_level = "n1"
    else:
        learning_level = "none"
    traits = PersonaTraits(
        context="early_learning" if target_profile_class in {"k2", "n1"} else "general",
        tone="warm",
        depth="brief",
        learning_level=learning_level,
    )
    draft = ProfileActionDraft(
        proposal_id=UUID(int=24),
        schema_version="1.0",
        action_name="profile.edit",
        resource_type="profile",
        resource_id=UUID(int=25),
        subject_id=UUID(int=25),
        target_profile_class=target_profile_class,
        persona_traits=traits if operation == "replace" else None,
        clear_persona_traits=operation == "clear",
        expected_version=2,
        guardian_generation=guardian_generation,
        parameters_commitment=Commitment(
            algorithm="HMAC-SHA-256", key_id="action-hmac-v1", value_b64="A" * 43 + "="
        ),
        uncertainty_micros=0,
        expires_at=datetime(2026, 8, 27, tzinfo=UTC),
        idempotency_key=UUID(int=26),
    )
    assert draft.target_profile_class == target_profile_class
    if guardian_generation is not None:
        assert canonical_bytes(draft) != canonical_bytes(
            draft.model_copy(update={"guardian_generation": guardian_generation + 1})
        )


@pytest.mark.parametrize(
    ("target_profile_class", "guardian_generation"),
    [
        ("owner", 1),
        ("adult", 1),
        ("k2", None),
        ("n1", None),
    ],
)
def test_profile_edit_rejects_cross_role_or_null_guardian_generation(
    target_profile_class: Literal["owner", "adult", "k2", "n1"],
    guardian_generation: int | None,
) -> None:
    with pytest.raises(ValidationError):
        ProfileActionDraft(
            proposal_id=UUID(int=27),
            schema_version="1.0",
            action_name="profile.edit",
            resource_type="profile",
            resource_id=UUID(int=28),
            subject_id=UUID(int=28),
            target_profile_class=target_profile_class,
            persona_traits=PersonaTraits(
                context="general", tone="neutral", depth="brief", learning_level="none"
            ),
            expected_version=1,
            guardian_generation=guardian_generation,
            parameters_commitment=Commitment(
                algorithm="HMAC-SHA-256",
                key_id="action-hmac-v1",
                value_b64="A" * 43 + "=",
            ),
            uncertainty_micros=0,
            expires_at=datetime(2026, 8, 27, tzinfo=UTC),
            idempotency_key=UUID(int=29),
        )


@pytest.fixture
def valid_action_payloads() -> dict[str, dict[str, object]]:
    def base(action_name: str, resource_id: int) -> dict[str, object]:
        return {
            "proposal_id": UUID(int=100 + resource_id),
            "schema_version": "1.0",
            "action_name": action_name,
            "resource_type": action_name.split(".", 1)[0],
            "resource_id": UUID(int=resource_id),
            "parameters_commitment": Commitment(
                algorithm="HMAC-SHA-256",
                key_id="action-hmac-v1",
                value_b64="A" * 43 + "=",
            ),
            "uncertainty_micros": 0,
            "expires_at": datetime(2026, 8, 27, tzinfo=UTC),
            "idempotency_key": UUID(int=200 + resource_id),
        }

    edited = PreferenceContent(
        category="food", key="spice", value="medium", strength_micros=500_000
    )
    return {
        "privacy.off": base("privacy.off", 41) | {"typed_confirmation": "TURN OFF PRIVACY"},
        "provider.configure": base("provider.configure", 42)
        | {
            "provider": "openai",
            "enabled": True,
            "review_record_id": UUID(int=242),
            "expected_provider_version": 1,
        },
        "credential.passkey.revoke": base("credential.passkey.revoke", 43)
        | {"credential_id": UUID(int=243), "expected_version": 1},
        "backup.restore": base("backup.restore", 44)
        | {"backup_id": UUID(int=244), "manifest_sha256": "a" * 64},
        "memory.edit_approve": base("memory.edit_approve", 45)
        | {
            "subject_id": UUID(int=245),
            "proposal_id_ref": UUID(int=246),
            "expected_version": 1,
            "decision": "approve",
            "edited_content": edited,
        },
        "memory.export": base("memory.export", 49)
        | {
            "resource_id": UUID(int=253),
            "subject_id": UUID(int=254),
            "memory_id": UUID(int=253),
            "expected_version": 3,
            "export_format": "json",
        },
        "identity.enroll": base("identity.enroll", 46)
        | {
            "subject_id": UUID(int=247),
            "modality": "face",
            "expected_profile_version": 1,
            "expected_consent_receipt_id": UUID(int=248),
            "reenrollment_days": 180,
        },
        "search.profile_mode.change": base("search.profile_mode.change", 47)
        | {
            "subject_id": UUID(int=249),
            "expected_profile_version": 1,
            "mode": "controlled",
            "expected_web_consent_receipt_id": UUID(int=250),
        },
        "search.experimental.activate": base("search.experimental.activate", 48)
        | {
            "subject_id": UUID(int=251),
            "expected_profile_version": 1,
            "expected_web_consent_receipt_id": UUID(int=252),
            "provider_review_version": 1,
            "pricing_version": 1,
            "privacy_generation": 1,
            "feature_generation": 1,
            "activation_issued_at": datetime(2026, 8, 27, 0, 0, tzinfo=UTC),
            "activation_expires_at": datetime(2026, 8, 27, 0, 30, tzinfo=UTC),
            "max_passes": 4,
            "max_sources": 20,
            "max_duration_seconds": 1800,
            "no_memory": True,
            "no_authenticated_sites": True,
            "no_files": True,
            "no_tools": True,
        },
    }


@pytest.mark.parametrize(
    "action_name,invalid",
    [
        ("privacy.off", {"typed_confirmation": "UNMUTE"}),
        (
            "provider.configure",
            {
                "provider": "openai",
                "enabled": True,
                "expected_provider_version": 1,
                "hard_limit_micros_sgd": 1,
            },
        ),
        (
            "credential.passkey.revoke",
            {"credential_id": UUID(int=31), "expected_version": None},
        ),
        ("backup.restore", {"backup_id": None, "manifest_sha256": None}),
        (
            "memory.edit_approve",
            {
                "proposal_id_ref": UUID(int=32),
                "expected_version": 1,
                "decision": "approve",
                "edited_content": None,
            },
        ),
        ("memory.export", {"memory_id": None}),
        ("memory.export", {"expected_version": None}),
        ("memory.export", {"resource_id": UUID(int=35)}),
        ("memory.export", {"profile_id": UUID(int=36)}),
        (
            "identity.enroll",
            {
                "subject_id": UUID(int=33),
                "modality": "face",
                "expected_profile_version": None,
            },
        ),
        (
            "search.profile_mode.change",
            {"subject_id": UUID(int=34), "mode": None, "expected_profile_version": 1},
        ),
        ("search.profile_mode.change", {"expected_web_consent_receipt_id": None}),
        (
            "search.profile_mode.change",
            {"mode": "no_web", "expected_web_consent_receipt_id": UUID(int=35)},
        ),
        (
            "search.experimental.activate",
            {
                "subject_id": UUID(int=34),
                "mode": "controlled",
                "expected_profile_version": 1,
            },
        ),
    ],
)
def test_grouped_action_variants_reject_null_or_cross_operation_substitution(
    action_name: str,
    invalid: dict[str, object],
    valid_action_payloads: dict[str, dict[str, object]],
) -> None:
    payload = valid_action_payloads[action_name] | invalid
    with pytest.raises(ValidationError):
        TypeAdapter(ActionProposalDraft).validate_python(payload)


def test_action_binding_is_household_proposal_turn_and_idempotency_bound() -> None:
    assert tuple(ActionBinding.model_fields) == (
        "household_id",
        "proposal_id",
        "turn_id",
        "idempotency_key",
        "action_name",
        "resource_type",
        "resource_id",
        "parameter_commitment",
        "policy_version",
        "session_id",
        "subject_id",
    )


def test_external_ports_are_async() -> None:
    assert inspect.iscoroutinefunction(LanguageModelPort.complete)
    assert inspect.iscoroutinefunction(BudgetPort.reserve)
    assert inspect.iscoroutinefunction(BudgetPort.mark_sent)
    assert inspect.iscoroutinefunction(BudgetPort.release_unsent)
    assert inspect.iscoroutinefunction(BudgetPort.reconcile_turn)
    assert inspect.iscoroutinefunction(ReachyPort.stop_all)
    assert inspect.iscoroutinefunction(ActionProviderPort.execute)
    assert inspect.iscoroutinefunction(AuthenticationPort.consume)
    assert inspect.iscoroutinefunction(MemoryRepositoryPort.create)
    assert inspect.iscoroutinefunction(RouteAuthorizerPort.consume)
    assert inspect.iscoroutinefunction(AuditPort.append)
    assert inspect.iscoroutinefunction(AsyncTransactionBoundary.commit)
    assert inspect.iscoroutinefunction(AsyncTransactionBoundary.rollback)


def test_planned_task_14_15_audit_signatures_bind_to_the_generic_port() -> None:
    port = _bind_planned_audit_ledger(_PlannedAsyncAuditLedger(_PlannedAuditLedger()))
    assert isinstance(port, AuditPort)
