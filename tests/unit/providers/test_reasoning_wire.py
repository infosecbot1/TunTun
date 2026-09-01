# tests/unit/providers/test_reasoning_wire.py
import json

import pytest
from tuntun_contracts.provider import SanitizedProviderMessage
from tuntun_core.services.providers.reasoning_wire import (
    build_openai_reasoning_wire_request,
)


def _messages() -> tuple[SanitizedProviderMessage, ...]:
    return (
        SanitizedProviderMessage(role="system", content="Answer briefly"),
        SanitizedProviderMessage(role="memory_data", content="Prefers concise answers"),
        SanitizedProviderMessage(role="user", content="What is gravity?"),
    )


def _schema() -> dict[str, object]:
    return {
        "type": "object",
        "properties": {"answer": {"type": "string"}},
        "required": ["answer"],
        "additionalProperties": False,
    }


def test_reasoning_wire_body_is_the_exact_detached_openai_payload() -> None:
    schema = _schema()
    payload, body = build_openai_reasoning_wire_request(
        model="gpt-5.6-sol",
        messages=_messages(),
        allowed_tools=(),
        max_output_tokens=512,
        store=False,
        output_schema=schema,
    )

    assert payload == json.loads(body)
    assert set(payload) == {"model", "input", "store", "max_output_tokens", "reasoning", "text"}
    assert payload["input"][1]["role"] == "developer"
    assert payload["reasoning"] == {"effort": "low"}
    assert payload["text"]["format"]["schema"] == schema
    assert not ({"request_id", "route", "timeout_ms", "redaction_receipt_id"} & set(payload))

    schema["properties"] = {}
    assert payload["text"]["format"]["schema"] != schema
    assert json.loads(body) == payload


@pytest.mark.parametrize(
    ("change", "error"),
    (
        ({"model": "other"}, "model"),
        ({"messages": ()}, "messages"),
        ({"allowed_tools": (object(),)}, "tools"),
        ({"max_output_tokens": 0}, "tokens"),
        ({"store": True}, "store"),
        ({"output_schema": []}, "schema"),
    ),
)
def test_reasoning_wire_rejects_unapproved_or_ambiguous_inputs(
    change: dict[str, object],
    error: str,
) -> None:
    values: dict[str, object] = {
        "model": "gpt-5.6-sol",
        "messages": _messages(),
        "allowed_tools": (),
        "max_output_tokens": 512,
        "store": False,
        "output_schema": _schema(),
    }
    values.update(change)
    with pytest.raises((TypeError, ValueError), match=error):
        build_openai_reasoning_wire_request(**values)  # type: ignore[arg-type]
