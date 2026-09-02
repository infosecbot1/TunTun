from __future__ import annotations

from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from tuntun_contracts.identity import PersonaProjection
from tuntun_core.services.context_builder import ContextBuilder
from tuntun_core.services.language_tracker import LanguageTracker, ReplyMode, SttLanguage

_REPLY_MODES = frozenset({"en", "hi", "hi_romanized", "hinglish"})
_STT_LANGUAGES = frozenset({"en", "hi", "hinglish", "unknown"})


@dataclass(frozen=True, slots=True)
class TranscribedTurn:
    text: str
    stt_language: SttLanguage
    explicit_reply_language: ReplyMode | None = None

    def __post_init__(self) -> None:
        if type(self.text) is not str:
            raise TypeError("text must be an exact str")
        if self.stt_language not in _STT_LANGUAGES:
            raise ValueError("unknown stt language")
        if (
            self.explicit_reply_language is not None
            and self.explicit_reply_language not in _REPLY_MODES
        ):
            raise ValueError("unknown explicit reply language")


@dataclass(frozen=True, slots=True)
class ProviderTurnContext:
    messages: tuple[dict[str, str], ...]
    reply_mode: ReplyMode
    prompt_bundle_sha256: str

    def __post_init__(self) -> None:
        if type(self.messages) is not tuple:
            raise TypeError("messages must be an exact tuple")
        if self.reply_mode not in _REPLY_MODES:
            raise ValueError("unknown reply mode")
        if type(self.prompt_bundle_sha256) is not str or len(self.prompt_bundle_sha256) != 64:
            raise ValueError("invalid prompt bundle hash")


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
            subject_id = getattr(decision, "subject_id", None)
            if subject_id is not None and type(subject_id) is not UUID:
                raise TypeError("identity subject_id must be UUID or None")
            projection = await self._profiles.get_persona_projection(
                session.household_id,
                subject_id,
                self._clock.now(),
            )
            if type(projection) is not PersonaProjection:
                raise TypeError("profile projection must be an exact PersonaProjection")
            mode = self._languages.detect(session.id, transcript)
            return ProviderTurnContext(
                messages=self._contexts.messages(projection, mode, transcript.text),
                reply_mode=mode,
                prompt_bundle_sha256=self._contexts.prompt_bundle_sha256,
            )

    async def on_session_ended(self, session_id: UUID) -> None:
        self._languages.clear(session_id)


def _has_current_language_evidence(transcript: TranscribedTurn) -> bool:
    return (
        transcript.explicit_reply_language is not None
        or transcript.stt_language != "unknown"
        or any("\u0900" <= character <= "\u097f" for character in transcript.text)
    )
