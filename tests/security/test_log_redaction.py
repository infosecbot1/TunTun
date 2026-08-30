from __future__ import annotations

import base64
import io
import json
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import quote
from uuid import UUID

import pytest
import structlog
from tuntun_contracts.base import Sensitivity
from tuntun_contracts.memory import (
    EpisodicContent,
    MemoryAudience,
    MemoryRecord,
    PolicyContent,
    PreferenceContent,
    ProceduralContent,
    RelationalContent,
    SemanticContent,
    WorkingContent,
)
from tuntun_contracts.provider import ProviderResponse, SanitizedProviderMessage
from tuntun_contracts.speech import SpeechChunk, TranscriptResult
from tuntun_core.config import logging as logging_config
from tuntun_core.config.logging import (
    MAX_CONTAINER_ITEMS,
    MAX_LOG_DEPTH,
    MAX_LOG_NODES,
    MAX_PUBLIC_INTEGER,
    PRIVATE_KEY_REGISTRY,
    PUBLIC_LOG_KEYS,
    STRUCTURAL_LOG_KEYS,
    normalize_private_key,
    redact_private_fields,
)

TEXT_SENTINEL = "private-Δ-line\n-sentinel"
BINARY_SENTINEL = b"private-binary-sentinel"

EXPECTED_PRIVATE_KEYS = {
    "authorization": frozenset(
        {
            "authorization",
            "authorization_header",
            "authorization_headers",
            "access_token",
            "access_tokens",
            "refresh_token",
            "refresh_tokens",
            "bearer_token",
            "bearer_tokens",
            "token",
            "tokens",
        }
    ),
    "cookie": frozenset({"cookie", "cookies", "set_cookie"}),
    "api_key": frozenset(
        {
            "api_key",
            "api_keys",
            "provider_api_key",
            "credential",
            "credentials",
            "password",
            "passwords",
            "secret",
            "secrets",
            "client_secret",
            "private_key",
            "private_keys",
        }
    ),
    "pin": frozenset({"pin", "pins", "security_pin"}),
    "recovery_code": frozenset({"recovery_code", "recovery_codes"}),
    "audio": frozenset(
        {
            "audio",
            "audio_bytes",
            "audio_chunk",
            "audio_chunks",
            "pcm",
            "pcm_bytes",
            "speech_chunk",
            "speech_chunks",
        }
    ),
    "transcript": frozenset({"transcript", "transcripts", "transcript_text", "transcript_result"}),
    "search_query": frozenset(
        {"query", "queries", "search_query", "search_queries", "search_query_body"}
    ),
    "search_result": frozenset(
        {
            "result",
            "results",
            "search_result",
            "search_results",
            "search_result_body",
            "search_excerpts",
            "page_content",
            "snippet",
            "snippets",
        }
    ),
    "prompt_message": frozenset(
        {
            "prompt",
            "prompts",
            "system_prompt",
            "user_prompt",
            "message",
            "messages",
            "provider_messages",
        }
    ),
    "memory_content": frozenset(
        {"memory", "memories", "memory_content", "memory_body", "edited_content"}
    ),
    "free_text": frozenset(
        {
            "content",
            "text",
            "category",
            "state_summary",
            "unresolved_intents",
            "event_summary",
            "subject",
            "predicate",
            "object",
            "value",
            "steps",
            "note",
            "reason",
        }
    ),
    "biometric_vector": frozenset(
        {"biometric_vector", "biometric_vectors", "face_vector", "voice_vector"}
    ),
    "embedding": frozenset({"embedding", "embeddings", "face_embedding", "voice_embedding"}),
    "frame": frozenset(
        {
            "frame",
            "frames",
            "face_frame",
            "face_frames",
            "face_crop",
            "face_crops",
            "camera_frame",
            "camera_frames",
            "image",
            "images",
        }
    ),
    "provider_body": frozenset(
        {
            "provider_body",
            "provider_request_body",
            "provider_response_body",
            "request_body",
            "response_body",
        }
    ),
}

EXPECTED_PUBLIC_KEYS = frozenset(
    {
        "event",
        "level",
        "logger",
        "method",
        "status",
        "kind",
        "code",
        "operation",
        "provider",
        "model",
        "language",
        "role",
        "schema_version",
        "version",
        "ok",
        "count",
        "duration_ms",
        "elapsed_ms",
        "attempt",
        "sequence",
        "port",
        "enabled",
        "final",
        "redacted",
    }
)

EXPECTED_STRUCTURAL_KEYS = frozenset(
    {"mapping", "list", "tuple", "payload", "items", "data", "context", "metadata"}
)

EXPECTED_PUBLIC_TEXT_VALUES = {
    "event": frozenset({"test.probe"}),
    "level": frozenset({"debug", "info", "warning", "error", "critical"}),
    "logger": frozenset({"tuntun"}),
    "method": frozenset({"debug", "info", "warning", "error", "critical"}),
    "status": frozenset({"ready", "ok", "failed"}),
    "kind": frozenset(
        {"working", "episodic", "semantic", "preference", "procedural", "relational", "policy"}
    ),
    "code": frozenset({"ok"}),
    "operation": frozenset({"probe"}),
    "provider": frozenset({"openai", "qwen"}),
    "model": frozenset({"registered-model"}),
    "language": frozenset({"en"}),
    "role": frozenset({"system", "user", "assistant"}),
    "schema_version": frozenset(
        {
            "1.0",
            "assistant-turn-v1",
            "tuntun.provider-usage-receipt.v1",
            "tuntun.reachy-stop-all-receipts.v1",
        }
    ),
    "redacted": frozenset(
        set(EXPECTED_PRIVATE_KEYS)
        | {
            "binary",
            "cycle",
            "invalid_mapping",
            "invalid_root",
            "limit",
            "unclassified",
            "unsupported",
        }
    ),
}

EXPECTED_PUBLIC_BOOLEAN_KEYS = frozenset({"ok", "enabled", "final"})
EXPECTED_PUBLIC_INTEGER_KEYS = frozenset({"version", "count", "attempt", "sequence", "port"})
EXPECTED_PUBLIC_LATENCY_KEYS = frozenset({"duration_ms", "elapsed_ms"})


def _encoded_forms(value: str) -> frozenset[str]:
    raw = value.encode("utf-8")
    return frozenset(
        {
            value,
            json.dumps(value, ensure_ascii=True)[1:-1],
            base64.b64encode(raw).decode("ascii"),
            base64.urlsafe_b64encode(raw).decode("ascii"),
            raw.hex(),
            quote(value, safe=""),
        }
    )


def _render(event: str, **fields: object) -> str:
    output = io.StringIO()
    logger = structlog.wrap_logger(
        structlog.PrintLogger(file=output),
        processors=[
            redact_private_fields,
            structlog.processors.JSONRenderer(sort_keys=True),
        ],
        cache_logger_on_first_use=False,
    )
    logger.info(event, **fields)
    return output.getvalue()


def test_key_registries_are_exact_immutable_canonical_unique_and_disjoint() -> None:
    assert PRIVATE_KEY_REGISTRY == EXPECTED_PRIVATE_KEYS
    assert PUBLIC_LOG_KEYS == EXPECTED_PUBLIC_KEYS
    assert STRUCTURAL_LOG_KEYS == EXPECTED_STRUCTURAL_KEYS
    assert logging_config.PUBLIC_TEXT_VALUES == EXPECTED_PUBLIC_TEXT_VALUES
    assert logging_config.PUBLIC_BOOLEAN_KEYS == EXPECTED_PUBLIC_BOOLEAN_KEYS
    assert logging_config.PUBLIC_INTEGER_KEYS == EXPECTED_PUBLIC_INTEGER_KEYS
    assert logging_config.PUBLIC_LATENCY_KEYS == EXPECTED_PUBLIC_LATENCY_KEYS
    assert logging_config.MAX_PUBLIC_TEXT_CHARS == 128
    assert all(
        1 <= len(value) <= logging_config.MAX_PUBLIC_TEXT_CHARS
        for values in logging_config.PUBLIC_TEXT_VALUES.values()
        for value in values
    )
    public_policy_keys = (
        set(logging_config.PUBLIC_TEXT_VALUES)
        | logging_config.PUBLIC_BOOLEAN_KEYS
        | logging_config.PUBLIC_INTEGER_KEYS
        | logging_config.PUBLIC_LATENCY_KEYS
    )
    assert public_policy_keys == PUBLIC_LOG_KEYS
    aliases = [alias for values in PRIVATE_KEY_REGISTRY.values() for alias in values]
    assert len(aliases) == len(set(aliases))
    assert all(normalize_private_key(alias) == alias for alias in aliases)
    assert not set(aliases) & (PUBLIC_LOG_KEYS | STRUCTURAL_LOG_KEYS)
    with pytest.raises(TypeError):
        cast(Any, PRIVATE_KEY_REGISTRY)["authorization"] = frozenset()
    with pytest.raises(TypeError):
        cast(Any, logging_config.PUBLIC_TEXT_VALUES)["event"] = frozenset()


@pytest.mark.parametrize(
    "category,key",
    [
        (category, key)
        for category in sorted(EXPECTED_PRIVATE_KEYS)
        for key in sorted(EXPECTED_PRIVATE_KEYS[category])
    ],
)
def test_every_private_alias_removes_literal_and_common_encoded_forms(
    category: str,
    key: str,
) -> None:
    private_value = {form: form for form in _encoded_forms(TEXT_SENTINEL)}
    rendered = _render(
        "log.probe",
        mapping={"list": [{"tuple": ({key: private_value},)}]},
        ok=True,
    )
    for form in _encoded_forms(TEXT_SENTINEL):
        assert form not in rendered
    decoded = json.loads(rendered)
    assert decoded["mapping"]["list"][0]["tuple"][0][key] == {"redacted": category}
    assert decoded["ok"] is True


@pytest.mark.parametrize(
    "key,category",
    (
        ("Authorization Header", "authorization"),
        ("ＳＥＡＲＣＨ－ＲＥＳＵＬＴＳ", "search_result"),
        ("provider.response.body", "provider_body"),
        ("Biometric Vectors", "biometric_vector"),
        ("ACCESS-TOKEN", "authorization"),
    ),
)
def test_key_normalization_cannot_bypass_private_category(
    key: str,
    category: str,
) -> None:
    redacted = redact_private_fields(None, "info", {key: TEXT_SENTINEL})
    normalized = normalize_private_key(key)
    assert redacted[normalized] == {"redacted": category}
    if key != normalized:
        assert key not in redacted


def test_normalized_key_collisions_fail_closed() -> None:
    redacted = redact_private_fields(
        None,
        "info",
        {
            "payload": {
                "Authorization Header": TEXT_SENTINEL,
                "authorization_header": TEXT_SENTINEL,
            }
        },
    )
    assert redacted["payload"] == {"redacted": "invalid_mapping"}


@pytest.mark.parametrize("key", ("", "_", "x" * 257, 7))
def test_invalid_log_keys_fail_closed_without_emitting_the_key(key: object) -> None:
    redacted = redact_private_fields(
        None,
        "info",
        {"event": "invalid.mapping", "payload": {key: TEXT_SENTINEL}},
    )
    rendered = json.dumps(redacted, sort_keys=True)
    assert TEXT_SENTINEL not in rendered
    assert redacted["payload"] == {"redacted": "invalid_mapping"}


def test_unknown_key_names_and_values_are_not_an_output_channel() -> None:
    key = f"field-{TEXT_SENTINEL}"
    rendered = _render(
        "unknown.probe",
        payload={key: {"status": TEXT_SENTINEL.encode().hex()}},
    )
    for form in _encoded_forms(TEXT_SENTINEL):
        assert form not in rendered
    decoded = json.loads(rendered)
    assert decoded["payload"] == {"unclassified_0": {"redacted": "unclassified"}}


def test_public_scalar_allowlist_is_closed_and_rejects_free_text() -> None:
    rendered = _render(
        TEXT_SENTINEL,
        ok=True,
        status="ready",
        count=3,
        attempt=MAX_PUBLIC_INTEGER,
        sequence=MAX_PUBLIC_INTEGER + 1,
        duration_ms=float("inf"),
        elapsed_ms=1.25,
        model=BINARY_SENTINEL,
        metadata={"detail": TEXT_SENTINEL},
    )
    for form in _encoded_forms(TEXT_SENTINEL):
        assert form not in rendered
    decoded = json.loads(rendered)
    assert decoded["event"] == {"redacted": "unclassified"}
    assert decoded["ok"] is True
    assert decoded["status"] == "ready"
    assert decoded["count"] == 3
    assert decoded["attempt"] == MAX_PUBLIC_INTEGER
    assert decoded["sequence"] == {"redacted": "unsupported"}
    assert decoded["duration_ms"] == {"redacted": "unsupported"}
    assert decoded["elapsed_ms"] == 1.25
    assert decoded["model"] == {"redacted": "binary"}


def test_public_scalar_keys_reject_container_smuggling() -> None:
    rendered = _render(
        "container.probe",
        status=["private", "sentinel"],
        code={"payload": "private-sentinel"},
    )
    decoded = json.loads(rendered)
    assert decoded["status"] == {"redacted": "unsupported"}
    assert decoded["code"] == {"redacted": "unsupported"}
    assert "private-sentinel" not in rendered


@pytest.mark.parametrize("key", sorted(EXPECTED_PUBLIC_TEXT_VALUES))
@pytest.mark.parametrize(
    "value",
    (
        "sk-test-private-credential",
        "0123456789abcdef0123456789abcdef",
        "cHJpdmF0ZS1jcmVkZW50aWFs",
        "https://private.example/credential",
    ),
)
def test_every_textual_public_key_rejects_unregistered_token_shaped_values(
    key: str,
    value: str,
) -> None:
    redacted = redact_private_fields(None, "info", {key: value})
    assert redacted[key] == {"redacted": "unclassified"}


@pytest.mark.parametrize("key", sorted(EXPECTED_PUBLIC_TEXT_VALUES))
def test_every_textual_public_key_rejects_oversized_exact_strings(key: str) -> None:
    oversized = "x" * 129
    redacted = redact_private_fields(None, "info", {key: oversized})
    rendered = json.dumps(redacted, sort_keys=True)
    assert redacted[key] == {"redacted": "unclassified"}
    assert oversized not in rendered
    assert len(rendered) < 64


@pytest.mark.parametrize(
    "key,value",
    [
        (key, value)
        for key in sorted(EXPECTED_PUBLIC_TEXT_VALUES)
        for value in sorted(EXPECTED_PUBLIC_TEXT_VALUES[key])
    ],
)
def test_every_registered_public_text_value_is_preserved(key: str, value: str) -> None:
    assert redact_private_fields(None, "info", {key: value}) == {key: value}


@pytest.mark.parametrize("key", sorted(EXPECTED_PUBLIC_BOOLEAN_KEYS))
@pytest.mark.parametrize("value", (1, 1.0, "true", None))
def test_boolean_public_keys_reject_wrong_scalar_types(key: str, value: object) -> None:
    assert redact_private_fields(None, "info", {key: value})[key] == {"redacted": "unsupported"}


@pytest.mark.parametrize("key", sorted(EXPECTED_PUBLIC_INTEGER_KEYS))
@pytest.mark.parametrize("value", (True, 1.0, "1", None))
def test_integer_public_keys_reject_wrong_scalar_types(key: str, value: object) -> None:
    assert redact_private_fields(None, "info", {key: value})[key] == {"redacted": "unsupported"}


@pytest.mark.parametrize("key", sorted(EXPECTED_PUBLIC_LATENCY_KEYS))
@pytest.mark.parametrize("value", (True, "1", None))
def test_latency_public_keys_reject_wrong_scalar_types(key: str, value: object) -> None:
    assert redact_private_fields(None, "info", {key: value})[key] == {"redacted": "unsupported"}


def test_exact_public_scalar_types_and_bounds_are_preserved() -> None:
    event: dict[str, object] = {
        **{key: True for key in EXPECTED_PUBLIC_BOOLEAN_KEYS},
        **{key: 1 for key in EXPECTED_PUBLIC_INTEGER_KEYS},
        "duration_ms": 1,
        "elapsed_ms": 1.25,
    }
    assert redact_private_fields(None, "info", event) == event


def _actual_private_contract_payloads() -> tuple[dict[str, object], ...]:
    request_id = UUID("00000000-0000-4000-8000-000000000811")
    memory_id = UUID("00000000-0000-4000-8000-000000000812")
    household_id = UUID("00000000-0000-4000-8000-000000000813")
    subject_id = UUID("00000000-0000-4000-8000-000000000814")
    contents = (
        WorkingContent(
            kind="working", state_summary=TEXT_SENTINEL, unresolved_intents=(TEXT_SENTINEL,)
        ),
        EpisodicContent(
            kind="episodic",
            event_summary=TEXT_SENTINEL,
            occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
            participant_ids=(subject_id,),
        ),
        SemanticContent(
            kind="semantic",
            subject=TEXT_SENTINEL,
            predicate=TEXT_SENTINEL,
            object=TEXT_SENTINEL,
        ),
        PreferenceContent(
            category=TEXT_SENTINEL,
            key=TEXT_SENTINEL,
            value=TEXT_SENTINEL,
            strength_micros=500_000,
        ),
        ProceduralContent(
            kind="procedural",
            name=TEXT_SENTINEL,
            steps=(TEXT_SENTINEL,),
            tool_label=TEXT_SENTINEL,
        ),
        RelationalContent(
            kind="relational",
            subject_id=subject_id,
            relation=TEXT_SENTINEL,
            object_subject_id=subject_id,
            note=TEXT_SENTINEL,
        ),
        PolicyContent(kind="policy", key=TEXT_SENTINEL, value=TEXT_SENTINEL),
    )
    memories = tuple(
        MemoryRecord(
            memory_id=memory_id,
            household_id=household_id,
            subject_id=subject_id,
            version=1,
            content=content,
            audience=MemoryAudience.SUBJECT_PRIVATE,
            sensitivity=Sensitivity.PERSONAL,
            valid_until=None,
        ).model_dump(mode="python")
        for content in contents
    )
    return memories + (
        SanitizedProviderMessage(role="user", content=TEXT_SENTINEL).model_dump(mode="python"),
        ProviderResponse(
            request_id=request_id,
            text=TEXT_SENTINEL,
            language="en",
            provider_usage_receipt_id=None,
        ).model_dump(mode="python"),
        TranscriptResult(
            request_id=request_id,
            text=TEXT_SENTINEL,
            language="en",
            duration_ms=1,
        ).model_dump(mode="python"),
        SpeechChunk(
            request_id=request_id,
            sequence=0,
            pcm=BINARY_SENTINEL,
            final=True,
        ).model_dump(mode="python"),
        {
            "query": TEXT_SENTINEL,
            "results": [{"title": TEXT_SENTINEL, "page_content": TEXT_SENTINEL}],
        },
    )


@pytest.mark.parametrize(
    "payload",
    _actual_private_contract_payloads(),
    ids=(
        "memory-working",
        "memory-episodic",
        "memory-semantic",
        "memory-preference",
        "memory-procedural",
        "memory-relational",
        "memory-policy",
        "provider-message",
        "provider-response",
        "transcript",
        "speech",
        "search",
    ),
)
def test_actual_private_contract_shapes_are_json_safe_and_content_free(
    payload: dict[str, object],
) -> None:
    rendered = _render("contract.probe", payload=payload, ok=True)
    json.loads(rendered)
    for form in _encoded_forms(TEXT_SENTINEL):
        assert form not in rendered
    assert BINARY_SENTINEL.decode() not in rendered
    assert base64.b64encode(BINARY_SENTINEL).decode() not in rendered


def test_cycles_depth_node_limits_and_unsupported_values_fail_closed() -> None:
    cyclic: dict[str, object] = {"event": "cycle.probe"}
    cyclic["payload"] = cyclic
    cycle_result = redact_private_fields(None, "info", cyclic)
    assert cycle_result["payload"] == {"redacted": "cycle"}

    cyclic_list: list[object] = []
    cyclic_list.append(cyclic_list)
    list_cycle_result = redact_private_fields(
        None,
        "info",
        {"event": "cycle.list", "payload": cyclic_list},
    )
    assert list_cycle_result["payload"] == [{"redacted": "cycle"}]

    nested: object = {"text": TEXT_SENTINEL}
    for _ in range(MAX_LOG_DEPTH + 2):
        nested = {"payload": nested}
    depth_result = redact_private_fields(
        None,
        "info",
        {"event": "depth.probe", "payload": nested},
    )
    assert "limit" in json.dumps(depth_result, sort_keys=True)

    oversized = [{"text": TEXT_SENTINEL} for _ in range(MAX_CONTAINER_ITEMS + 1)]
    container_result = redact_private_fields(
        None,
        "info",
        {"event": "node.probe", "payload": oversized},
    )
    assert container_result["payload"] == {"redacted": "limit"}

    node_heavy = [
        [{"text": TEXT_SENTINEL} for _ in range(64)] for _ in range(MAX_LOG_NODES // 64 + 1)
    ]
    node_result = redact_private_fields(
        None,
        "info",
        {"event": "node.probe", "payload": node_heavy},
    )
    assert node_result["payload"] == {"redacted": "limit"}

    unsupported_result = redact_private_fields(
        None,
        "info",
        {
            "event": "unsupported.probe",
            "payload": {
                "blob": BINARY_SENTINEL,
                "object": object(),
                "number": float("inf"),
                "values": {TEXT_SENTINEL},
            },
        },
    )
    rendered = json.dumps(unsupported_result, sort_keys=True, allow_nan=False)
    assert TEXT_SENTINEL not in rendered
    assert BINARY_SENTINEL.decode() not in rendered


def test_hostile_mapping_and_sequence_iterators_fail_closed() -> None:
    effects: list[str] = []

    class HostileDict(dict[str, object]):
        def items(self) -> Any:
            effects.append("dict-items")
            return super().items()

        def __iter__(self) -> Iterator[str]:
            effects.append("dict-iter")
            return super().__iter__()

    class HostileMapping(Mapping[str, object]):
        def __getitem__(self, key: str) -> object:
            effects.append(f"getitem:{key}")
            raise KeyError(key)

        def __iter__(self) -> Iterator[str]:
            effects.append("mapping-iter")
            return iter(())

        def __len__(self) -> int:
            effects.append("mapping-len")
            return 0

    class HostileList(list[object]):
        def __iter__(self) -> Iterator[object]:
            effects.append("list-iter")
            return super().__iter__()

    class HostileTuple(tuple[object, ...]):
        def __iter__(self) -> Iterator[object]:
            effects.append("tuple-iter")
            return super().__iter__()

    dict_result = redact_private_fields(
        None,
        "info",
        {"event": "hostile.dict", "payload": HostileDict(status="ready")},
    )
    mapping_result = redact_private_fields(
        None,
        "info",
        {"event": "hostile.mapping", "payload": HostileMapping()},
    )
    sequence_result = redact_private_fields(
        None,
        "info",
        {"event": "hostile.sequence", "payload": HostileList([TEXT_SENTINEL])},
    )
    tuple_result = redact_private_fields(
        None,
        "info",
        {"event": "hostile.tuple", "payload": HostileTuple((TEXT_SENTINEL,))},
    )
    assert dict_result["payload"] == {"redacted": "unsupported"}
    assert mapping_result["payload"] == {"redacted": "unsupported"}
    assert sequence_result["payload"] == {"redacted": "unsupported"}
    assert tuple_result["payload"] == {"redacted": "unsupported"}
    assert effects == []


@pytest.mark.parametrize("position", ("root", "structural", "public"))
@pytest.mark.parametrize("raises", (False, True), ids=("recording", "raising"))
def test_class_spies_are_never_consulted(position: str, raises: bool) -> None:
    effects: list[str] = []

    class ClassSpy:
        @property
        def __class__(self) -> type[object]:
            effects.append("class-read")
            if raises:
                raise RuntimeError("private-class-sentinel")
            return bytes

    value = ClassSpy()
    if position == "root":
        result = redact_private_fields(None, "info", cast(Any, value))
        assert result == {"event": "redaction.invalid_root", "redacted": "invalid_root"}
    elif position == "structural":
        result = redact_private_fields(None, "info", {"payload": value})
        assert result["payload"] == {"redacted": "unsupported"}
    else:
        result = redact_private_fields(None, "info", {"status": value})
        assert result["status"] == {"redacted": "unsupported"}
    assert "private-class-sentinel" not in json.dumps(result, sort_keys=True)
    assert effects == []


@pytest.mark.parametrize("position", ("root", "structural", "public"))
def test_hostile_type_hash_is_never_invoked(position: str) -> None:
    effects: list[str] = []

    class HostileMeta(type):
        def __hash__(cls) -> int:
            effects.append("type-hash")
            raise RuntimeError("private-type-hash-sentinel")

    class HashSpy(metaclass=HostileMeta):
        pass

    value = HashSpy()
    if position == "root":
        result = redact_private_fields(None, "info", cast(Any, value))
        assert result == {"event": "redaction.invalid_root", "redacted": "invalid_root"}
    elif position == "structural":
        result = redact_private_fields(None, "info", {"payload": value})
        assert result["payload"] == {"redacted": "unsupported"}
    else:
        result = redact_private_fields(None, "info", {"status": value})
        assert result["status"] == {"redacted": "unsupported"}
    assert "private-type-hash-sentinel" not in json.dumps(result, sort_keys=True)
    assert effects == []


def test_redaction_does_not_mutate_input_and_invalid_root_is_safe() -> None:
    event: dict[str, object] = {
        "event": "immutable.probe",
        "mapping": {"list": [{"transcript": TEXT_SENTINEL}]},
    }
    original = {
        "event": event["event"],
        "mapping": {"list": [{"transcript": TEXT_SENTINEL}]},
    }
    redacted = redact_private_fields(None, "info", event)
    assert event == original
    assert redacted is not event
    invalid = redact_private_fields(None, "info", cast(Any, [TEXT_SENTINEL]))
    assert invalid == {"event": "redaction.invalid_root", "redacted": "invalid_root"}
