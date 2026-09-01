import hmac
import json
import re
import unicodedata
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Literal
from uuid import UUID, uuid4

from tuntun_contracts.base import (
    Commitment,
    JSONValue,
    Sensitivity,
    canonical_mapping_bytes,
    parse_bounded_json_value,
)
from tuntun_contracts.commitments import commit_private
from tuntun_contracts.provider import RedactionReceipt, SanitizedProviderMessage

_SECRET = re.compile(r"(?:sk-(?:proj-)?[A-Za-z0-9_-]{20,}|-----BEGIN [A-Z ]+PRIVATE KEY-----)")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE = re.compile(r"(?<!\d)(?:\+?\d[ -]?){8,15}(?!\d)")
_PROHIBITED_TEXT_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})


def _has_prohibited_control(value: str) -> bool:
    return any(
        unicodedata.category(character) in _PROHIBITED_TEXT_CATEGORIES for character in value
    )


def _text_leaves(value: JSONValue) -> Iterator[str]:
    if type(value) is str:
        yield value
    elif type(value) is list:
        for item in value:
            yield from _text_leaves(item)
    elif type(value) is dict:
        for key, item in value.items():
            yield key
            yield from _text_leaves(item)


@dataclass(frozen=True, repr=False, slots=True)
class RedactionDraft:
    purpose: Literal["cloud_reasoning", "cloud_tts"]
    session_label: str
    system_text: str | None
    user_text: str
    memory_texts: tuple[str, ...]
    provider_messages: tuple[SanitizedProviderMessage, ...]
    input_commitment: Commitment
    draft_commitment: Commitment
    removed_categories: tuple[str, ...]
    removed_count: int


class Redactor:
    def __init__(
        self,
        root_key: bytes,
        key_id: str,
        receipt_id_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._root_key = root_key
        self._key_id = key_id
        self._receipt_id_factory = receipt_id_factory

    def sanitize(
        self,
        purpose: Literal["cloud_reasoning", "cloud_tts"],
        session_label: str,
        system_text: str | None,
        user_text: str,
        memory_texts: tuple[str, ...],
    ) -> RedactionDraft:
        if purpose == "cloud_reasoning" and system_text is None:
            raise ValueError("reasoning system text required")
        if purpose == "cloud_tts" and (system_text is not None or memory_texts):
            raise ValueError("TTS redaction accepts text only")
        label = unicodedata.normalize("NFC", session_label)
        if not 8 <= len(label.encode("utf-8")) <= 128:
            raise ValueError("session label outside bounds")
        raw_values = ((system_text,) if system_text is not None else ()) + (
            user_text,
            *memory_texts,
        )
        values = tuple(unicodedata.normalize("NFC", value) for value in raw_values)
        if any(_has_prohibited_control(value) for value in values):
            raise ValueError("PROHIBITED_CONTROL")
        if any(_SECRET.search(value) for value in values):
            raise ValueError("PROHIBITED_SECRET")
        removed: set[str] = set()
        removed_count = 0

        def redact(value: str) -> str:
            nonlocal removed_count
            value, email_count = _EMAIL.subn("[CONTACT]", value)
            if email_count:
                removed.add("email")
                removed_count += email_count
            value, phone_count = _PHONE.subn("[CONTACT]", value)
            if phone_count:
                removed.add("phone")
                removed_count += phone_count
            label_count = value.count(label)
            if label_count:
                removed.add("session_label")
                removed_count += label_count
                value = value.replace(label, "[SESSION]")
            return value

        sanitized = tuple(redact(value) for value in values)
        if any(_SECRET.search(value) or _has_prohibited_control(value) for value in sanitized):
            raise ValueError("SECOND_PASS_REJECTED")
        index = 0
        sanitized_system = None
        messages: list[SanitizedProviderMessage] = []
        if system_text is not None:
            sanitized_system = sanitized[0]
            messages.append(SanitizedProviderMessage(role="system", content=sanitized_system))
            index = 1
        sanitized_user = sanitized[index]
        sanitized_memory = sanitized[index + 1 :]
        messages.extend(
            SanitizedProviderMessage(role="memory_data", content=value)
            for value in sanitized_memory
        )
        messages.append(SanitizedProviderMessage(role="user", content=sanitized_user))
        raw_body = canonical_mapping_bytes(
            {"purpose": purpose, "session_label": label, "values": list(values)}
        )
        input_commitment = commit_private(
            self._root_key,
            self._key_id,
            f"redaction.input.{purpose}",
            raw_body,
        )
        draft_body = canonical_mapping_bytes(
            {
                "purpose": purpose,
                "session_label": label,
                "system_text": sanitized_system,
                "user_text": sanitized_user,
                "memory_texts": list(sanitized_memory),
                "provider_messages": [message.model_dump(mode="json") for message in messages],
                "input_commitment": input_commitment.model_dump(mode="json"),
                "removed_categories": sorted(removed),
                "removed_count": removed_count,
            }
        )
        return RedactionDraft(
            purpose=purpose,
            session_label=label,
            system_text=sanitized_system,
            user_text=sanitized_user,
            memory_texts=tuple(sanitized_memory),
            provider_messages=tuple(messages),
            input_commitment=input_commitment,
            draft_commitment=commit_private(
                self._root_key,
                self._key_id,
                f"redaction.draft.{purpose}",
                draft_body,
            ),
            removed_categories=tuple(sorted(removed)),
            removed_count=removed_count,
        )

    def finalize(
        self,
        draft: RedactionDraft,
        *,
        purpose: Literal["cloud_reasoning", "cloud_tts"],
        canonical_provider_body: bytes,
        policy_version: str,
        maximum_sensitivity: Sensitivity,
    ) -> RedactionReceipt:
        if type(draft) is not RedactionDraft or draft.purpose != purpose:
            raise ValueError("redaction purpose mismatch")
        draft_body = canonical_mapping_bytes(
            {
                "purpose": draft.purpose,
                "session_label": draft.session_label,
                "system_text": draft.system_text,
                "user_text": draft.user_text,
                "memory_texts": list(draft.memory_texts),
                "provider_messages": [
                    message.model_dump(mode="json") for message in draft.provider_messages
                ],
                "input_commitment": draft.input_commitment.model_dump(mode="json"),
                "removed_categories": list(draft.removed_categories),
                "removed_count": draft.removed_count,
            }
        )
        expected_draft_commitment = commit_private(
            self._root_key,
            self._key_id,
            f"redaction.draft.{purpose}",
            draft_body,
        )
        if not hmac.compare_digest(
            expected_draft_commitment.key_id,
            draft.draft_commitment.key_id,
        ) or not hmac.compare_digest(
            expected_draft_commitment.value_b64,
            draft.draft_commitment.value_b64,
        ):
            raise ValueError("redaction draft mismatch")
        if (
            type(canonical_provider_body) is not bytes
            or not 2 <= len(canonical_provider_body) <= 8_388_608
        ):
            raise ValueError("canonical provider body outside bounds")
        if (
            type(policy_version) is not str
            or unicodedata.normalize("NFC", policy_version) != policy_version
            or not 1 <= len(policy_version.encode("utf-8")) <= 128
        ):
            raise ValueError("redaction policy version invalid")
        try:
            body_value = parse_bounded_json_value(
                canonical_provider_body,
                max_bytes=8_388_608,
            )
        except ValueError as error:
            raise ValueError("SECOND_PASS_REJECTED") from error
        if type(body_value) is not dict:
            raise ValueError("SECOND_PASS_REJECTED")
        canonical_mapping = json.loads(canonical_provider_body)
        if (
            type(canonical_mapping) is not dict
            or canonical_mapping_bytes(canonical_mapping) != canonical_provider_body
        ):
            raise ValueError("SECOND_PASS_REJECTED")
        for text in _text_leaves(body_value):
            if (
                unicodedata.normalize("NFC", text) != text
                or _SECRET.search(text)
                or _EMAIL.search(text)
                or _PHONE.search(text)
                or _has_prohibited_control(text)
                or draft.session_label in text
            ):
                raise ValueError("SECOND_PASS_REJECTED")
        return RedactionReceipt(
            receipt_id=self._receipt_id_factory(),
            purpose=purpose,
            input_commitment=draft.input_commitment,
            output_commitment=commit_private(
                self._root_key,
                self._key_id,
                f"provider.request.{purpose}",
                canonical_provider_body,
            ),
            removed_categories=draft.removed_categories,
            removed_count=draft.removed_count,
            policy_version=policy_version,
            maximum_sensitivity=maximum_sensitivity,
        )
