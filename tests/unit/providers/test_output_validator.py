from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError
from tuntun_contracts.base import Commitment, parse_contract_json
from tuntun_contracts.provider import ProviderResponse, ProviderResponseReceipt
from tuntun_core.services.providers.output_validator import (
    AssistantTurn,
    ProposalMapper,
    RememberPreferenceIntent,
    action_execution_parameters,
)
from tuntun_core.services.providers.response_receipts import VerifiedProviderResponseReceipt
from tuntun_testing.fake_clock import FakeClock


def _commitment() -> Commitment:
    return Commitment(
        algorithm="HMAC-SHA-256",
        key_id="response-hmac-v1",
        value_b64="A" * 43 + "=",
    )


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(datetime(2026, 8, 27, tzinfo=UTC))


@pytest.fixture
def verified_response_receipt() -> VerifiedProviderResponseReceipt:
    receipt = ProviderResponseReceipt(
        receipt_id=uuid4(),
        request_id=uuid4(),
        attempt_id=uuid4(),
        authorization_id=uuid4(),
        household_id=uuid4(),
        subject_id=uuid4(),
        session_id=uuid4(),
        turn_id=uuid4(),
        provider="openai",
        model="gpt-5.6-sol",
        output_schema_version="assistant-turn-v1",
        response_commitment=_commitment(),
        receipt_hmac_key_id="response-hmac-v1",
        receipt_hmac_b64="A" * 43 + "=",
        produced_at=datetime(2026, 8, 27, tzinfo=UTC),
    )
    return VerifiedProviderResponseReceipt(receipt)


def test_assistant_turn_contract_is_strict_closed_frozen_and_bounded() -> None:
    assert AssistantTurn.model_config.get("strict") is True
    assert AssistantTurn.model_config.get("extra") == "forbid"
    assert AssistantTurn.model_config.get("frozen") is True
    schema = AssistantTurn.model_json_schema()["properties"]
    assert schema["memory_proposals"]["maxItems"] == 8
    assert schema["action_proposals"]["maxItems"] == 8
    base = {"answer_text": "Okay", "answer_language": "en", "uncertainty_micros": 10_000}
    memory = {
        "kind": "forget_memory",
        "subject_ref": "subject:synthetic",
        "memory_ref": "memory:synthetic",
        "confidence_micros": 900_000,
        "reason": "asked",
    }
    action = {
        "kind": "timer_create",
        "duration_seconds": 60,
        "label": "tea",
        "confidence_micros": 900_000,
        "reason": "asked",
    }
    for mutation in ({"memory_proposals": (memory,) * 9}, {"action_proposals": (action,) * 9}):
        with pytest.raises(ValidationError):
            AssistantTurn.model_validate(base | mutation)


def test_assistant_turn_provider_json_rejects_duplicates_nonfinite_and_oversize() -> None:
    valid = (
        b'{"answer_text":"Okay","answer_language":"en","memory_proposals":[],'
        b'"action_proposals":[],"uncertainty_micros":10000}'
    )
    assert parse_contract_json(
        AssistantTurn,
        valid,
        max_bytes=32_000,
        require_canonical=False,
    ).answer_text == "Okay"
    duplicate = valid.replace(b"{", b'{"answer_text":"substituted",', 1)
    for raw in (duplicate, valid.replace(b"10000", b"NaN"), b" " * 32_001):
        with pytest.raises((ValueError, ValidationError)):
            parse_contract_json(
                AssistantTurn,
                raw,
                max_bytes=32_000,
                require_canonical=False,
            )


def test_near_limit_validated_turn_fits_provider_response_transport() -> None:
    turn = AssistantTurn(
        answer_text="x" * 8_000,
        answer_language="en",
        memory_proposals=(),
        action_proposals=(),
        uncertainty_micros=0,
    )
    raw = turn.model_dump_json()
    assert 8_000 < len(raw.encode("utf-8")) <= 32_000
    response = ProviderResponse(
        request_id=uuid4(),
        text=raw,
        language="en",
        provider_usage_receipt_id=uuid4(),
    )
    assert response.text == raw
    with pytest.raises(ValidationError, match="UTF-8 byte cap"):
        ProviderResponse(
            request_id=uuid4(),
            text="ठ" * 11_000,
            language="hi",
            provider_usage_receipt_id=uuid4(),
        )


@pytest.mark.parametrize(
    "forbidden",
    [
        "proposal_id",
        "household_id",
        "subject_id",
        "session_id",
        "turn_id",
        "claim_commitment",
        "source_receipt_ids",
        "parameters_commitment",
        "idempotency_key",
        "expires_at",
    ],
)
def test_provider_cannot_mint_internal_proposal_fields(forbidden: str) -> None:
    intent = {
        "kind": "timer_create",
        "duration_seconds": 60,
        "label": "tea",
        "confidence_micros": 900_000,
        "reason": "asked",
        forbidden: str(uuid4()),
    }
    with pytest.raises(ValidationError):
        AssistantTurn(
            answer_text="Okay",
            answer_language="en",
            action_proposals=(intent,),
            uncertainty_micros=10_000,
        )


def test_unknown_pseudonymous_ref_denies_before_staging(
    clock: FakeClock,
    verified_response_receipt: VerifiedProviderResponseReceipt,
) -> None:
    class DenyRegistry:
        def subject(self, ref, **binding):
            return uuid4()

        def memory(self, ref, **binding):
            raise PermissionError("unknown_turn_reference")

        def memory_version(self, ref, **binding):
            raise PermissionError("unknown_turn_reference")

    class Provenance:
        def attach(self, *args):
            return None

    turn = AssistantTurn.model_validate(
        {
            "answer_text": "Okay",
            "answer_language": "en",
            "memory_proposals": [
                {
                    "kind": "forget_memory",
                    "subject_ref": "subject:guest",
                    "memory_ref": "memory:not_registered",
                    "confidence_micros": 900_000,
                    "reason": "asked",
                }
            ],
            "action_proposals": [],
            "uncertainty_micros": 10_000,
        }
    )
    scope = verified_response_receipt.receipt
    with pytest.raises(PermissionError, match="unknown_turn_reference"):
        ProposalMapper(
            DenyRegistry(),
            Provenance(),
            verified_response_receipt,
            b"k" * 32,
            "proposal-hmac-v1",
            clock,
        ).map_memory(turn.memory_proposals[0], scope.household_id, scope.session_id, scope.turn_id)


def test_mapper_requires_signed_response_receipt_and_turn_scoped_refs(
    clock: FakeClock,
    verified_response_receipt: VerifiedProviderResponseReceipt,
) -> None:
    class Provenance:
        pass

    with pytest.raises(PermissionError, match="provider_response_provenance_required"):
        ProposalMapper(object(), Provenance(), None, b"k" * 32, "proposal-hmac-v1", clock)
    with pytest.raises(PermissionError, match="provider_response_provenance_required"):
        ProposalMapper(
            object(),
            Provenance(),
            verified_response_receipt.receipt,
            b"k" * 32,
            "proposal-hmac-v1",
            clock,
        )


@pytest.mark.parametrize(
    ("profile_class", "expected_audience"),
    [
        ("owner", "subject_private"),
        ("adult", "subject_private"),
        ("k2", "guardian_child"),
        ("n1", "guardian_child"),
    ],
)
def test_memory_mapper_derives_audience_from_server_profile_not_provider(
    profile_class: str,
    expected_audience: str,
    clock: FakeClock,
    verified_response_receipt: VerifiedProviderResponseReceipt,
) -> None:
    scope = verified_response_receipt.receipt

    class Refs:
        def subject(self, ref, **binding):
            return scope.subject_id

        def profile_class(self, subject_id, **binding):
            return profile_class

    class Provenance:
        def attach(self, *args):
            return None

    intent = RememberPreferenceIntent.model_validate(
        {
            "kind": "remember_preference",
            "subject_ref": "subject:current",
            "category": "synthetic",
            "key": "format",
            "value": "brief",
            "confidence_micros": 900_000,
            "reason": "asked",
        }
    )
    mapper = ProposalMapper(
        Refs(),
        Provenance(),
        verified_response_receipt,
        b"k" * 32,
        "proposal-hmac-v1",
        clock,
    )
    draft = mapper.map_memory(intent, scope.household_id, scope.session_id, scope.turn_id)
    assert draft.audience == expected_audience


def test_action_mapper_and_executor_share_exact_closed_parameter_payload(
    clock: FakeClock,
    verified_response_receipt: VerifiedProviderResponseReceipt,
) -> None:
    scope = verified_response_receipt.receipt

    class Refs:
        def timer(self, ref, **binding):
            return uuid4()

    class Provenance:
        def attach(self, *args):
            return None

    mapper = ProposalMapper(
        Refs(),
        Provenance(),
        verified_response_receipt,
        b"k" * 32,
        "proposal-hmac-v1",
        clock,
    )
    intent = AssistantTurn(
        answer_text="Okay",
        answer_language="en",
        action_proposals=(
            {
                "kind": "timer_create",
                "duration_seconds": 60,
                "label": "tea",
                "confidence_micros": 731_000,
                "reason": "asked",
            },
        ),
        uncertainty_micros=10_000,
    ).action_proposals[0]
    draft = mapper.map_action(intent, scope.household_id, scope.session_id, scope.turn_id)
    binding = mapper.bind_action(
        draft,
        scope.household_id,
        scope.turn_id,
        "policy-v1",
        scope.session_id,
        scope.subject_id,
    )
    assert binding.parameter_commitment == draft.parameters_commitment
    assert action_execution_parameters(draft) == {
        "duration_seconds": 60,
        "label": "tea",
    }


@pytest.mark.parametrize("kind", ["timer_status", "privacy_on", "mute", "stop"])
def test_post_model_output_cannot_propose_queries_or_preemptive_safety_actions(kind: str) -> None:
    payload = {"kind": kind, "confidence_micros": 900_000, "reason": "synthetic"}
    if kind == "timer_status":
        payload["timer_ref"] = "timer:synthetic"
    with pytest.raises(ValidationError):
        AssistantTurn(
            answer_text="Okay",
            answer_language="en",
            action_proposals=(payload,),
            uncertainty_micros=10_000,
        )
