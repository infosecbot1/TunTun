from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from tuntun_contracts.base import canonical_mapping_bytes, parse_bounded_json_value
from tuntun_contracts.provider import (
    SanitizedProviderMessage,
    SanitizedToolReference,
)
from tuntun_core.services.providers.allowlist import ALLOWED_OPENAI_MODELS

_OPENAI_ROLES = {
    "system": "system",
    "user": "user",
    "assistant": "assistant",
    # Memory stays a separately-labelled trusted instruction at the provider
    # boundary; the private internal role is never sent as an unsupported role.
    "memory_data": "developer",
}


def build_openai_reasoning_wire_request(
    *,
    model: str,
    messages: tuple[SanitizedProviderMessage, ...],
    allowed_tools: tuple[SanitizedToolReference, ...],
    max_output_tokens: int,
    store: bool,
    output_schema: Mapping[str, Any],
) -> tuple[dict[str, Any], bytes]:
    """Return one detached payload plus its exact canonical semantic body."""

    if type(model) is not str or model not in ALLOWED_OPENAI_MODELS or model != "gpt-5.6-sol":
        raise ValueError("reasoning model not allowed")
    if (
        type(messages) is not tuple
        or not 1 <= len(messages) <= 32
        or any(type(message) is not SanitizedProviderMessage for message in messages)
    ):
        raise TypeError("reasoning messages must be an exact non-empty sanitized tuple")
    if type(allowed_tools) is not tuple or allowed_tools:
        raise ValueError("reasoning tools are disabled in Phase 1")
    if type(max_output_tokens) is not int or not 1 <= max_output_tokens <= 16_384:
        raise ValueError("reasoning max output tokens outside bounds")
    if store is not False:
        raise ValueError("reasoning store must be false")
    if not isinstance(output_schema, Mapping):
        raise TypeError("reasoning output schema must be a mapping")

    schema_body = canonical_mapping_bytes(output_schema)
    if len(schema_body) > 1_048_576:
        raise ValueError("reasoning output schema outside bounds")
    validated_schema = parse_bounded_json_value(schema_body, max_bytes=1_048_576)
    if type(validated_schema) is not dict:
        raise TypeError("reasoning output schema must be an object")
    # The SDK JSON encoder needs only standard JSON types, not Decimal values
    # returned by the hostile-input parser for numeric schema keywords.
    schema_snapshot = json.loads(schema_body)

    payload = {
        "model": model,
        "input": [
            {"role": _OPENAI_ROLES[message.role], "content": message.content}
            for message in messages
        ],
        "store": False,
        "max_output_tokens": max_output_tokens,
        "reasoning": {"effort": "low"},
        "text": {
            "format": {
                "type": "json_schema",
                "name": "assistant_turn",
                "schema": schema_snapshot,
                "strict": True,
            }
        },
    }
    canonical_body = canonical_mapping_bytes(payload)
    validated_payload = parse_bounded_json_value(canonical_body, max_bytes=8_388_608)
    if type(validated_payload) is not dict:  # Defensive: payload above is an object.
        raise AssertionError("reasoning wire payload must be an object")
    detached = json.loads(canonical_body)
    return detached, canonical_body
