from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
import pytest_asyncio
from tuntun_contracts.provider import ProviderResponse
from tuntun_core.services.providers.gateway import ProviderUsageUnknownError
from tuntun_core.services.providers.output_validator import AssistantTurn
from tuntun_core.services.providers.response_receipts import (
    ProviderResponseReceiptRepository,
    ProviderResponseReceiptService,
)

pytest_plugins = ("tests.fixtures.provider_egress",)


@pytest_asyncio.fixture
async def response_receipt_case(production_provider_gateway_case, budget_evidence, clock):
    case = await production_provider_gateway_case(
        valid_usage=True,
        seed_response_scope=True,
    )
    result = await case.invoke()
    assert result.provider_usage_receipt_id is not None
    case.assistant_turn = AssistantTurn(
        answer_text="Okay",
        answer_language="en",
        memory_proposals=(),
        action_proposals=(),
        uncertainty_micros=10_000,
    )
    case.raw_invalid_output = (
        b'{"answer_text":"Okay","answer_language":"en",'
        b'"memory_proposals":[],"action_proposals":[],"uncertainty_micros":NaN}'
    )
    case.audit = case.transactional_audit()
    repository = ProviderResponseReceiptRepository(case.factory)
    case.receipt_service = ProviderResponseReceiptService(
        uow_factory=case.factory,
        repository=repository,
        commitment_root=b"r" * 32,
        key_id="provider-response-v1",
        clock=clock,
        audit=case.audit,
        usage_evidence=budget_evidence,
        assistant_turn_adapter=AssistantTurn,
    )
    case.provider_response = ProviderResponse(
        request_id=case.route.request_id,
        text=case.assistant_turn.model_dump_json(),
        language=case.assistant_turn.answer_language,
        provider_usage_receipt_id=result.provider_usage_receipt_id,
    )
    return case


@pytest.mark.asyncio
async def test_validated_response_receipt_is_exact_persistent_and_tamper_evident(
    response_receipt_case,
) -> None:
    case = response_receipt_case
    receipt = await case.receipt_service.record(
        case.route,
        case.assistant_turn,
        provider_usage_receipt_id=case.provider_response.provider_usage_receipt_id,
    )
    verified = await case.receipt_service.require_exact(
        receipt.receipt_id,
        case.route,
        case.assistant_turn,
        provider_usage_receipt_id=case.provider_response.provider_usage_receipt_id,
    )
    assert verified.receipt_id == receipt.receipt_id
    changes = (
        {"request_id": uuid4()},
        {"attempt_id": uuid4()},
        {"authorization_id": uuid4()},
        {"household_id": uuid4()},
        {"session_id": uuid4()},
        {"turn_id": uuid4()},
        {"provider": "qwen"},
        {"model": "other"},
    )
    for change in changes:
        changed = case.route.model_copy(update=change)
        with pytest.raises(PermissionError, match="provider_response_receipt_binding"):
            await case.receipt_service.require_exact(
                receipt.receipt_id,
                changed,
                case.assistant_turn,
                provider_usage_receipt_id=case.provider_response.provider_usage_receipt_id,
            )
    with pytest.raises(PermissionError, match="provider_response_receipt_commitment"):
        await case.receipt_service.require_exact(
            receipt.receipt_id,
            case.route,
            case.assistant_turn.model_copy(update={"answer_text": "changed"}),
            provider_usage_receipt_id=case.provider_response.provider_usage_receipt_id,
        )


@pytest.mark.asyncio
async def test_receipt_matches_provider_response_usage_receipt_identity(
    response_receipt_case,
) -> None:
    case = response_receipt_case
    with pytest.raises(PermissionError, match="provider_response_usage_receipt_mismatch"):
        await case.receipt_service.record(
            case.route,
            case.assistant_turn,
            provider_usage_receipt_id=uuid4(),
        )
    assert await case.receipt_service.count_for_authorization(case.route.authorization_id) == 0


@pytest.mark.asyncio
async def test_receipt_cannot_be_minted_before_validation(response_receipt_case) -> None:
    case = response_receipt_case
    with pytest.raises(ValueError):
        await case.receipt_service.validate_and_record(
            case.route,
            case.raw_invalid_output,
            provider_usage_receipt_id=case.provider_response.provider_usage_receipt_id,
        )
    assert await case.receipt_service.count_for_authorization(case.route.authorization_id) == 0


@pytest.mark.asyncio
async def test_valid_raw_json_arrays_validate_in_json_mode_and_mint_once(
    response_receipt_case,
) -> None:
    case = response_receipt_case
    raw = case.assistant_turn.model_dump_json()
    receipt = await case.receipt_service.validate_and_record(
        case.route,
        raw,
        provider_usage_receipt_id=case.provider_response.provider_usage_receipt_id,
    )
    verified = await case.receipt_service.require_exact(
        receipt.receipt_id,
        case.route,
        case.assistant_turn,
        provider_usage_receipt_id=case.provider_response.provider_usage_receipt_id,
    )
    assert verified.receipt_id == receipt.receipt_id
    assert await case.receipt_service.count_for_authorization(case.route.authorization_id) == 1


@pytest.mark.asyncio
async def test_concurrent_replay_is_one_receipt_and_one_audit(response_receipt_case) -> None:
    case = response_receipt_case
    first, second = await asyncio.gather(
        case.receipt_service.record(
            case.route,
            case.assistant_turn,
            provider_usage_receipt_id=case.provider_response.provider_usage_receipt_id,
        ),
        case.receipt_service.record(
            case.route,
            case.assistant_turn,
            provider_usage_receipt_id=case.provider_response.provider_usage_receipt_id,
        ),
    )
    assert first.receipt_id == second.receipt_id
    assert await case.receipt_service.count_for_authorization(case.route.authorization_id) == 1
    assert await case.audit.count("provider.response.receipt.created") == 1


@pytest.mark.asyncio
async def test_unknown_usage_success_cannot_mint_output_receipt(
    production_provider_gateway_case,
    budget_evidence,
    clock,
) -> None:
    case = await production_provider_gateway_case(
        valid_usage=False,
        seed_response_scope=True,
    )
    with pytest.raises(ProviderUsageUnknownError):
        await case.invoke()
    audit = case.transactional_audit()
    service = ProviderResponseReceiptService(
        uow_factory=case.factory,
        repository=ProviderResponseReceiptRepository(case.factory),
        commitment_root=b"r" * 32,
        key_id="provider-response-v1",
        clock=clock,
        audit=audit,
        usage_evidence=budget_evidence,
        assistant_turn_adapter=AssistantTurn,
    )
    assistant_turn = AssistantTurn(
        answer_text="Okay",
        answer_language="en",
        memory_proposals=(),
        action_proposals=(),
        uncertainty_micros=10_000,
    )
    with pytest.raises(PermissionError, match="provider_response_usage_unverified"):
        await service.record(case.route, assistant_turn, provider_usage_receipt_id=uuid4())
    assert await service.count_for_authorization(case.route.authorization_id) == 0


@pytest.mark.asyncio
async def test_object_and_raw_paths_share_exact_32000_byte_cap(response_receipt_case) -> None:
    case = response_receipt_case
    oversized = case.assistant_turn.model_copy(update={"answer_text": "😀" * 8_000})
    with pytest.raises(ValueError, match="assistant output byte cap"):
        await case.receipt_service.record(
            case.route,
            oversized,
            provider_usage_receipt_id=case.provider_response.provider_usage_receipt_id,
        )
    with pytest.raises(ValueError, match="assistant output byte cap"):
        await case.receipt_service.validate_and_record(
            case.route,
            b"{" + b" " * 32_000,
            provider_usage_receipt_id=case.provider_response.provider_usage_receipt_id,
        )
