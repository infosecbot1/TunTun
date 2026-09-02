from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Protocol
from uuid import UUID

from tuntun_contracts.identity import IdentityDecision, IdentityStatus, PersonaProjection
from tuntun_core.services.context_builder import (
    MAX_PROVIDER_CONTEXT_UTF8_BYTES,
    ContextBuilder,
)
from tuntun_core.services.language_tracker import (
    LanguageTracker,
    ReplyMode,
    SttLanguage,
    require_reply_mode,
    require_stt_language,
    require_transcript_text,
)

_REPLY_MODES = frozenset({"en", "hi", "hi_romanized", "hinglish"})
_STT_LANGUAGES = frozenset({"en", "hi", "hinglish", "unknown"})
_PROVIDER_ROLE_SEQUENCE = ("system", "user")
_GUEST_PROJECTION = PersonaProjection(
    role="guest",
    context="general",
    tone="neutral",
    depth="brief",
    learning_level="none",
)


@dataclass(frozen=True, slots=True)
class TranscribedTurn:
    text: str
    stt_language: SttLanguage
    explicit_reply_language: ReplyMode | None = None

    def __post_init__(self) -> None:
        require_transcript_text(self.text)
        require_stt_language(self.stt_language)
        if self.explicit_reply_language is not None:
            require_reply_mode(
                self.explicit_reply_language,
                name="explicit_reply_language",
            )


@dataclass(frozen=True, slots=True)
class ProviderTurnContext:
    messages: tuple[Mapping[str, str], ...]
    reply_mode: ReplyMode
    prompt_bundle_sha256: str

    def __post_init__(self) -> None:
        frozen = _freeze_provider_messages(self.messages)
        object.__setattr__(self, "messages", frozen)
        require_reply_mode(self.reply_mode)
        if (
            type(self.prompt_bundle_sha256) is not str
            or len(self.prompt_bundle_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.prompt_bundle_sha256)
        ):
            raise ValueError("invalid prompt hash")
        if self.prompt_bundle_sha256 != provider_messages_sha256(frozen):
            raise ValueError("prompt hash does not match provider messages")


@dataclass(frozen=True, slots=True)
class ActiveSessionContext:
    id: UUID
    household_id: UUID


class SessionContextLeasePort(Protocol):
    def active_context_lease(
        self,
        turn_id: UUID,
    ) -> AbstractAsyncContextManager[ActiveSessionContext]: ...


class IdentityContextPort(Protocol):
    async def require_current_for_turn(self, turn_id: UUID) -> object: ...


class ProfileProjectionPort(Protocol):
    async def get_persona_projection(
        self,
        household_id: UUID,
        subject_id: UUID | None,
        observed_at: datetime,
    ) -> PersonaProjection: ...


class ClockPort(Protocol):
    def now(self) -> datetime: ...


class SessionLanguageRegistry:
    """Ephemeral same-session language prior; never persisted or shared."""

    def __init__(self, tracker: LanguageTracker | None = None) -> None:
        self._tracker = tracker or LanguageTracker()
        self._items: dict[UUID, tuple[ReplyMode, int]] = {}
        self._turn_index: dict[UUID, int] = {}

    def detect(self, session_id: UUID, transcript: TranscribedTurn) -> ReplyMode:
        if type(session_id) is not UUID:
            raise TypeError("session_id must be an exact UUID")
        if type(transcript) is not TranscribedTurn:
            raise TypeError("transcript must be an exact TranscribedTurn")
        index = self._turn_index.get(session_id, 0) + 1
        prior = self._items.get(session_id)
        mode = self._tracker.detect(
            transcript.text,
            transcript.stt_language,
            explicit_reply_language=transcript.explicit_reply_language,
            prior_language=None if prior is None else prior[0],
            prior_age_turns=None if prior is None else index - prior[1],
        )
        self._turn_index[session_id] = index
        if _has_current_language_evidence(transcript):
            self._items[session_id] = (mode, index)
        return mode

    def clear(self, session_id: UUID) -> None:
        if type(session_id) is not UUID:
            raise TypeError("session_id must be an exact UUID")
        self._items.pop(session_id, None)
        self._turn_index.pop(session_id, None)

    def contains(self, session_id: UUID) -> bool:
        if type(session_id) is not UUID:
            raise TypeError("session_id must be an exact UUID")
        return session_id in self._items


class PersonalizedTurnContextProvider:
    def __init__(
        self,
        sessions: SessionContextLeasePort,
        identity: IdentityContextPort,
        profiles: ProfileProjectionPort,
        languages: SessionLanguageRegistry,
        contexts: ContextBuilder,
        clock: ClockPort,
    ) -> None:
        self._sessions = sessions
        self._identity = identity
        self._profiles = profiles
        self._languages = languages
        self._contexts = contexts
        self._clock = clock

    async def prepare(self, turn_id: UUID, transcript: TranscribedTurn) -> ProviderTurnContext:
        if type(turn_id) is not UUID:
            raise TypeError("turn_id must be an exact UUID")
        if type(transcript) is not TranscribedTurn:
            raise TypeError("transcript must be an exact TranscribedTurn")
        async with self._sessions.active_context_lease(turn_id) as session:
            decision = await self._identity.require_current_for_turn(turn_id)
            observed_at = self._clock.now()
            subject_id = _safe_current_subject_id(decision, observed_at)
            if subject_id is None:
                projection = _GUEST_PROJECTION
            else:
                projection = await self._profiles.get_persona_projection(
                    session.household_id,
                    subject_id,
                    observed_at,
                )
            if type(projection) is not PersonaProjection:
                raise TypeError("profile projection must be an exact PersonaProjection")
            mode = self._languages.detect(session.id, transcript)
            messages = self._contexts.messages(projection, mode, transcript.text)
            return ProviderTurnContext(
                messages=messages,
                reply_mode=mode,
                prompt_bundle_sha256=provider_messages_sha256(messages),
            )

    async def on_session_ended(self, session_id: UUID) -> None:
        self._languages.clear(session_id)


def _has_current_language_evidence(transcript: TranscribedTurn) -> bool:
    return (
        transcript.explicit_reply_language is not None
        or transcript.stt_language != "unknown"
        or any("\u0900" <= character <= "\u097f" for character in transcript.text)
    )


def _safe_current_subject_id(decision: object, observed_at: datetime) -> UUID | None:
    if type(decision) is not IdentityDecision:
        return None
    if decision.status is not IdentityStatus.VERIFIED:
        return None
    if decision.expires_at <= observed_at:
        return None
    if type(decision.subject_id) is not UUID:
        return None
    return decision.subject_id


def provider_messages_sha256(messages: tuple[Mapping[str, str], ...]) -> str:
    body = _provider_visible_body(_freeze_provider_messages(messages))
    return hashlib.sha256(body).hexdigest()


def _freeze_provider_messages(
    messages: tuple[Mapping[str, str], ...],
) -> tuple[Mapping[str, str], ...]:
    if type(messages) is not tuple:
        raise TypeError("messages must be an exact tuple")
    if len(messages) != len(_PROVIDER_ROLE_SEQUENCE):
        raise ValueError("provider message shape invalid")
    frozen: list[Mapping[str, str]] = []
    total = 0
    for expected_role, message in zip(_PROVIDER_ROLE_SEQUENCE, messages, strict=True):
        if not isinstance(message, Mapping):
            raise TypeError("provider message must be a mapping")
        if set(message.keys()) != {"role", "content"}:
            raise ValueError("provider message keys invalid")
        role = message["role"]
        content = message["content"]
        if type(role) is not str:
            raise TypeError("provider message role must be an exact str")
        if type(content) is not str:
            raise TypeError("provider message content must be an exact str")
        if role != expected_role:
            raise ValueError("provider message role invalid")
        total += len(role.encode("utf-8")) + len(content.encode("utf-8"))
        frozen.append(MappingProxyType({"role": role, "content": content}))
    if total > MAX_PROVIDER_CONTEXT_UTF8_BYTES:
        raise ValueError("provider context outside turn bounds")
    return tuple(frozen)


def _provider_visible_body(messages: tuple[Mapping[str, str], ...]) -> bytes:
    canonical = tuple({"role": item["role"], "content": item["content"]} for item in messages)
    return json.dumps(
        canonical,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
