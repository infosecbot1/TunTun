# tests/unit/providers/test_redaction.py
from dataclasses import replace

import pytest
import rfc8785
from tuntun_contracts.base import Sensitivity
from tuntun_core.services.providers.reasoning_wire import (
    build_openai_reasoning_wire_request,
)
from tuntun_core.services.providers.redactor import Redactor


def test_redactor_rejects_secrets_before_receipt_creation() -> None:
    redactor = Redactor(root_key=b"k" * 32, key_id="route-hmac-v1")
    with pytest.raises(ValueError, match="PROHIBITED_SECRET"):
        redactor.sanitize(
            purpose="cloud_reasoning",
            session_label="session-1",
            system_text="Answer briefly",
            user_text="".join(("Use sk-", "proj-", "abcdefghijkl", "mnopqrstuv")),
            memory_texts=(),
        )


@pytest.mark.parametrize(
    "invisible_control",
    ("\x00", "\u200b", "\u2028", "\u2029", "\u202e", "\ud800"),
)
def test_redactor_rejects_unicode_controls_before_receipt_creation(
    invisible_control: str,
) -> None:
    redactor = Redactor(root_key=b"k" * 32, key_id="route-hmac-v1")
    with pytest.raises(ValueError, match="PROHIBITED_CONTROL"):
        redactor.sanitize(
            purpose="cloud_reasoning",
            session_label="session-1",
            system_text="Answer briefly",
            user_text=f"hello{invisible_control}secret",
            memory_texts=(),
        )


def test_finalize_binds_exact_sanitized_body_without_storing_it() -> None:
    redactor = Redactor(root_key=b"k" * 32, key_id="route-hmac-v1")
    draft = redactor.sanitize(
        purpose="cloud_reasoning",
        session_label="session-1",
        system_text="Answer briefly",
        user_text="Email me at person@example.test",
        memory_texts=("session-1 likes concise answers",),
    )
    _, body = build_openai_reasoning_wire_request(
        model="gpt-5.6-sol",
        messages=draft.provider_messages,
        allowed_tools=(),
        max_output_tokens=512,
        store=False,
        output_schema={
            "type": "object",
            "properties": {"answer": {"type": "string"}},
            "required": ["answer"],
            "additionalProperties": False,
        },
    )
    receipt = redactor.finalize(
        draft,
        purpose="cloud_reasoning",
        canonical_provider_body=body,
        policy_version="provider-redaction-v1",
        maximum_sensitivity=Sensitivity.PERSONAL,
    )
    assert receipt.input_commitment != receipt.output_commitment
    assert receipt.removed_categories == ("email", "session_label")
    assert receipt.removed_count == 2
    assert b"person@example.test" not in body
    assert b"session-1" not in body


@pytest.mark.parametrize(
    "injected",
    (
        "sk-proj-abcdefghijklmnopqrstuv",
        "person@example.test",
        "+65 8123 4567",
        "session-1",
    ),
)
def test_second_pass_rejection_emits_no_receipt(injected: str) -> None:
    redactor = Redactor(root_key=b"k" * 32, key_id="route-hmac-v1")
    draft = redactor.sanitize(
        purpose="cloud_reasoning",
        session_label="session-1",
        system_text="Answer briefly",
        user_text="safe",
        memory_texts=(),
    )
    with pytest.raises(ValueError, match="SECOND_PASS_REJECTED"):
        redactor.finalize(
            draft,
            purpose="cloud_reasoning",
            canonical_provider_body=rfc8785.dumps({"injected": injected}),
            policy_version="provider-redaction-v1",
            maximum_sensitivity=Sensitivity.PERSONAL,
        )


@pytest.mark.parametrize("invisible_control", ("\u200b", "\u2028", "\u2029", "\u202e"))
def test_second_pass_rejects_unicode_controls(invisible_control: str) -> None:
    redactor = Redactor(root_key=b"k" * 32, key_id="route-hmac-v1")
    draft = redactor.sanitize(
        purpose="cloud_reasoning",
        session_label="session-1",
        system_text="Answer briefly",
        user_text="safe",
        memory_texts=(),
    )
    with pytest.raises(ValueError, match="SECOND_PASS_REJECTED"):
        redactor.finalize(
            draft,
            purpose="cloud_reasoning",
            canonical_provider_body=rfc8785.dumps({"injected": f"hello{invisible_control}secret"}),
            policy_version="provider-redaction-v1",
            maximum_sensitivity=Sensitivity.PERSONAL,
        )


def test_finalize_rejects_tampered_ephemeral_draft() -> None:
    redactor = Redactor(root_key=b"k" * 32, key_id="route-hmac-v1")
    draft = redactor.sanitize(
        purpose="cloud_reasoning",
        session_label="session-1",
        system_text="Answer briefly",
        user_text="safe",
        memory_texts=(),
    )
    tampered = replace(draft, session_label="different-session")
    with pytest.raises(ValueError, match="redaction draft mismatch"):
        redactor.finalize(
            tampered,
            purpose="cloud_reasoning",
            canonical_provider_body=rfc8785.dumps({"input": "safe"}),
            policy_version="provider-redaction-v1",
            maximum_sensitivity=Sensitivity.PERSONAL,
        )


@pytest.mark.parametrize("body", (b'{ "input":"safe"}', b'["safe"]'))
def test_finalize_requires_one_canonical_json_object(body: bytes) -> None:
    redactor = Redactor(root_key=b"k" * 32, key_id="route-hmac-v1")
    draft = redactor.sanitize(
        purpose="cloud_reasoning",
        session_label="session-1",
        system_text="Answer briefly",
        user_text="safe",
        memory_texts=(),
    )
    with pytest.raises(ValueError, match="SECOND_PASS_REJECTED"):
        redactor.finalize(
            draft,
            purpose="cloud_reasoning",
            canonical_provider_body=body,
            policy_version="provider-redaction-v1",
            maximum_sensitivity=Sensitivity.PERSONAL,
        )
