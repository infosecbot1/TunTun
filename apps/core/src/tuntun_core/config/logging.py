from __future__ import annotations

import math
import re
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any
from unicodedata import normalize

MAX_LOG_DEPTH = 32
MAX_LOG_NODES = 4_096
MAX_CONTAINER_ITEMS = 256
MAX_LOG_KEY_CHARS = 256
MIN_PUBLIC_INTEGER = -(2**53 - 1)
MAX_PUBLIC_INTEGER = 2**53 - 1

PRIVATE_KEY_REGISTRY: Mapping[str, frozenset[str]] = MappingProxyType(
    {
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
        "transcript": frozenset(
            {"transcript", "transcripts", "transcript_text", "transcript_result"}
        ),
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
            {
                "biometric_vector",
                "biometric_vectors",
                "face_vector",
                "voice_vector",
            }
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
)

PUBLIC_TEXT_VALUES: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "event": frozenset({"test.probe"}),
        "level": frozenset({"debug", "info", "warning", "error", "critical"}),
        "logger": frozenset({"tuntun"}),
        "method": frozenset({"debug", "info", "warning", "error", "critical"}),
        "status": frozenset({"ready", "ok", "failed"}),
        "kind": frozenset(
            {
                "working",
                "episodic",
                "semantic",
                "preference",
                "procedural",
                "relational",
                "policy",
            }
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
            {
                *PRIVATE_KEY_REGISTRY,
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
)

PUBLIC_BOOLEAN_KEYS = frozenset({"ok", "enabled", "final"})
PUBLIC_INTEGER_KEYS = frozenset({"version", "count", "attempt", "sequence", "port"})
PUBLIC_LATENCY_KEYS = frozenset({"duration_ms", "elapsed_ms"})
PUBLIC_LOG_KEYS = (
    frozenset(PUBLIC_TEXT_VALUES)
    | PUBLIC_BOOLEAN_KEYS
    | PUBLIC_INTEGER_KEYS
    | (PUBLIC_LATENCY_KEYS)
)

STRUCTURAL_LOG_KEYS = frozenset(
    {"mapping", "list", "tuple", "payload", "items", "data", "context", "metadata"}
)


def normalize_private_key(key: str) -> str:
    if type(key) is not str or not 1 <= len(key) <= MAX_LOG_KEY_CHARS:
        raise ValueError("structured log key must be a bounded string")
    normalized = re.sub(
        r"[^a-z0-9]+",
        "_",
        normalize("NFKC", key).casefold(),
    ).strip("_")
    if not normalized or len(normalized) > MAX_LOG_KEY_CHARS:
        raise ValueError("structured log key is not canonicalizable")
    return normalized


PRIVATE_KEY_TO_CATEGORY: Mapping[str, str] = MappingProxyType(
    {alias: category for category, aliases in PRIVATE_KEY_REGISTRY.items() for alias in aliases}
)

if len(PRIVATE_KEY_TO_CATEGORY) != sum(map(len, PRIVATE_KEY_REGISTRY.values())):
    raise RuntimeError("private log aliases must be unique")
if any(normalize_private_key(alias) != alias for alias in PRIVATE_KEY_TO_CATEGORY):
    raise RuntimeError("private log aliases must be canonical")
if PRIVATE_KEY_TO_CATEGORY.keys() & (PUBLIC_LOG_KEYS | STRUCTURAL_LOG_KEYS):
    raise RuntimeError("private and nonprivate log keys must be disjoint")
if len(PUBLIC_LOG_KEYS) != (
    len(PUBLIC_TEXT_VALUES)
    + len(PUBLIC_BOOLEAN_KEYS)
    + len(PUBLIC_INTEGER_KEYS)
    + len(PUBLIC_LATENCY_KEYS)
):
    raise RuntimeError("public log key policies must be disjoint")


def _marker(category: str) -> dict[str, str]:
    return {"redacted": category}


def _safe_public_scalar(key: str, value: object) -> object:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return _marker("binary")
    allowed_text = PUBLIC_TEXT_VALUES.get(key)
    if allowed_text is not None:
        if type(value) is str:
            return value if value in allowed_text else _marker("unclassified")
        return _marker("unsupported")
    if key in PUBLIC_BOOLEAN_KEYS:
        return value if type(value) is bool else _marker("unsupported")
    if key in PUBLIC_INTEGER_KEYS:
        if type(value) is not int:
            return _marker("unsupported")
        if MIN_PUBLIC_INTEGER <= value <= MAX_PUBLIC_INTEGER:
            return value
        return _marker("unsupported")
    if key in PUBLIC_LATENCY_KEYS:
        if type(value) is int and MIN_PUBLIC_INTEGER <= value <= MAX_PUBLIC_INTEGER:
            return value
        if (
            type(value) is float
            and math.isfinite(value)
            and MIN_PUBLIC_INTEGER <= value <= MAX_PUBLIC_INTEGER
        ):
            return value
        return _marker("unsupported")
    return _marker("unsupported")


@dataclass(slots=True)
class _RedactionTraversal:
    nodes: int = 0
    active: set[int] = field(default_factory=set)

    def redact(
        self,
        value: Any,
        *,
        public_key: str | None = None,
        depth: int = 0,
    ) -> object:
        self.nodes += 1
        if self.nodes > MAX_LOG_NODES or depth > MAX_LOG_DEPTH:
            return _marker("limit")
        if public_key is not None:
            return _safe_public_scalar(public_key, value)
        if type(value) is dict:
            return self._mapping(value, depth)
        if type(value) in {list, tuple}:
            return self._sequence(value, depth)
        if isinstance(value, (bytes, bytearray, memoryview)):
            return _marker("binary")
        if type(value) in {str, int, float, bool, type(None)}:
            return _marker("unclassified")
        return _marker("unsupported")

    def _mapping(self, value: dict[object, object], depth: int) -> object:
        identity = id(value)
        if identity in self.active:
            return _marker("cycle")
        self.active.add(identity)
        result: dict[str, object] = {}
        seen: set[str] = set()
        try:
            for index, pair in enumerate(value.items()):
                if self.nodes >= MAX_LOG_NODES:
                    return _marker("limit")
                if index >= MAX_CONTAINER_ITEMS:
                    return _marker("limit")
                key, item = pair
                if type(key) is not str:
                    return _marker("invalid_mapping")
                try:
                    normalized = normalize_private_key(key)
                except (TypeError, ValueError):
                    return _marker("invalid_mapping")
                if normalized in seen:
                    return _marker("invalid_mapping")
                seen.add(normalized)
                category = PRIVATE_KEY_TO_CATEGORY.get(normalized)
                if category is not None:
                    result[normalized] = _marker(category)
                elif normalized in PUBLIC_LOG_KEYS:
                    result[normalized] = self.redact(
                        item,
                        public_key=normalized,
                        depth=depth + 1,
                    )
                elif normalized in STRUCTURAL_LOG_KEYS:
                    result[normalized] = self.redact(item, depth=depth + 1)
                else:
                    result[f"unclassified_{index}"] = _marker("unclassified")
            return result
        except Exception:
            return _marker("unsupported")
        finally:
            self.active.remove(identity)

    def _sequence(
        self,
        value: list[object] | tuple[object, ...],
        depth: int,
    ) -> object:
        identity = id(value)
        if identity in self.active:
            return _marker("cycle")
        self.active.add(identity)
        result: list[object] = []
        try:
            for index, item in enumerate(value):
                if self.nodes >= MAX_LOG_NODES:
                    return _marker("limit")
                if index >= MAX_CONTAINER_ITEMS:
                    return _marker("limit")
                result.append(
                    self.redact(
                        item,
                        depth=depth + 1,
                    )
                )
            return result
        except Exception:
            return _marker("unsupported")
        finally:
            self.active.remove(identity)


def redact_private_fields(
    logger: object,
    method: str,
    event: MutableMapping[str, object],
) -> MutableMapping[str, object]:
    del logger, method
    redacted = _RedactionTraversal().redact(event)
    if type(redacted) is not dict:
        return {"event": "redaction.invalid_root", "redacted": "invalid_root"}
    return redacted
