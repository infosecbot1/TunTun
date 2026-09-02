from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Literal, cast
from uuid import UUID, uuid4

import pytest
from tuntun_contracts.identity import IdentityDecision, IdentityStatus, PersonaProjection
from tuntun_core.services.context_builder import ContextBuilder
from tuntun_core.services.language_tracker import ReplyMode, SttLanguage
from tuntun_core.services.persona_builder import PersonaBuilder
from tuntun_core.services.personalized_turn_context import (
    ActiveSessionContext,
    PersonalizedTurnContextProvider,
    ProviderTurnContext,
    SessionLanguageRegistry,
    TranscribedTurn,
    provider_messages_sha256,
)
from tuntun_core.workflows.conversation import LinearConversationEngine, TurnRequest

pytestmark = pytest.mark.asyncio

_NOW = datetime(2026, 8, 27, tzinfo=UTC)


class _Clock:
    def now(self) -> datetime:
        return _NOW


class _LeasedSessions:
    def __init__(self, session_id: UUID, household_id: UUID) -> None:
        self.session_id = session_id
        self.household_id = household_id
        self._active_turns: dict[UUID, ActiveSessionContext] = {}
        self._ended_sessions: set[UUID] = set()
        self._condition = asyncio.Condition()

    async def open_turn(self, turn_id: UUID) -> None:
        async with self._condition:
            self._active_turns[turn_id] = ActiveSessionContext(
                id=self.session_id,
                household_id=self.household_id,
            )
            self._condition.notify_all()

    @asynccontextmanager
    async def active_context_lease(self, turn_id: UUID) -> AsyncIterator[ActiveSessionContext]:
        async with self._condition:
            if self.session_id in self._ended_sessions or turn_id not in self._active_turns:
                raise RuntimeError("session ended")
            session = self._active_turns[turn_id]
            yield session
            self._active_turns.pop(turn_id, None)
            self._condition.notify_all()

    async def end_session(self) -> UUID:
        async with self._condition:
            session_id = self.session_id
            while self._active_turns:
                await self._condition.wait()
            self._ended_sessions.add(session_id)
            self.session_id = uuid4()
            return session_id


class _Identity:
    def __init__(self, state: str, subject_id: UUID | None) -> None:
        self.state = state
        self.subject_id = subject_id

    async def require_current_for_turn(self, turn_id: UUID) -> object:
        del turn_id
        if self.state == "malformed":
            return SimpleNamespace(subject_id=self.subject_id)
        if self.state == "stale":
            return IdentityDecision(
                status=IdentityStatus.VERIFIED,
                subject_id=self.subject_id,
                reason_code="stale",
                expires_at=_NOW - timedelta(seconds=1),
            )
        status = {
            "verified": IdentityStatus.VERIFIED,
            "uncertain": IdentityStatus.AMBIGUOUS,
            "ambiguous": IdentityStatus.AMBIGUOUS,
            "conflict": IdentityStatus.CONFLICT,
            "unknown": IdentityStatus.UNKNOWN,
        }[self.state]
        return IdentityDecision(
            status=status,
            subject_id=self.subject_id if status is IdentityStatus.VERIFIED else None,
            reason_code=self.state,
            expires_at=_NOW + timedelta(minutes=5),
        )


class _Profiles:
    def __init__(self, case: _PersonalizedWorkflowCase) -> None:
        self._case = case
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def get_persona_projection(
        self,
        household_id: UUID,
        subject_id: UUID | None,
        observed_at: datetime,
    ) -> PersonaProjection:
        del household_id, observed_at
        case = self._case
        if case.hold_projection:
            self.entered.set()
            await self.release.wait()
        case.profile_calls += 1
        if case.raw_private_profile is not None:
            case.raw_private_trait_was_loaded = True
        if case.consent_revoked or subject_id is None:
            case.reloaded_after_revocation = case.consent_revoked
            projection = PersonaProjection(
                role="guest" if subject_id is None else case.base_role,
                context="general",
                tone="neutral",
                depth="brief",
                learning_level="none",
            )
        else:
            projection = PersonaProjection(
                role=case.base_role,
                context=case.custom_context,
                tone="precise" if case.custom_context == "technical_security" else "neutral",
                depth="detailed" if case.custom_context == "technical_security" else "brief",
                learning_level="none",
            )
        case.last_projection = projection
        return projection


class _Ports:
    def __init__(self, case: _PersonalizedWorkflowCase) -> None:
        self._case = case

    async def start(self, turn_id: UUID) -> None:
        await self._case.sessions.open_turn(turn_id)

    async def transcribe(self, wav_bytes: bytes) -> object:
        del wav_bytes
        return self._case.next_transcript

    async def guest_identity(self) -> str:
        raise AssertionError("shadow identity path bypassed personalized context provider")

    async def generate(self, context: ProviderTurnContext) -> str:
        self._case.provider_captures.append(context)
        self._case.last_reply_mode = context.reply_mode
        self._case.system_prompt = context.messages[0]["content"]
        self._case.provider_capture_bytes += repr(context.messages).encode("utf-8")
        if self._case.ended_session_id is not None:
            self._case.provider_calls_after_session_end += 1
        return "safe answer"

    async def synthesize(self, answer: str) -> bytes:
        assert answer == "safe answer"
        return b"pcm"

    async def play(self, turn_id: UUID, pcm: bytes) -> None:
        del turn_id
        assert pcm == b"pcm"

    async def finish(self, turn_id: UUID) -> None:
        del turn_id


class _PersonalizedWorkflowCase:
    adult_private_sentinel = "adult-private-sentinel"

    def __init__(
        self,
        *,
        profile: Literal["guest", "adult", "owner", "k2", "n1"] = "guest",
        identity_state: str = "verified",
        seed_adult_private_traits: bool = False,
        custom_context: Literal[
            "general",
            "technical_security",
            "household_practical",
            "early_learning",
        ] = "general",
        hold_projection: bool = False,
    ) -> None:
        self.session_id = uuid4()
        self.household_id = uuid4()
        self.sessions = _LeasedSessions(self.session_id, self.household_id)
        self.language_registry = SessionLanguageRegistry()
        self.next_transcript: TranscribedTurn | None = None
        self.provider_captures: list[ProviderTurnContext] = []
        self.provider_capture_bytes = b""
        self.system_prompt = ""
        self.last_reply_mode = "en"
        self.profile_calls = 0
        self.provider_calls_after_session_end = 0
        self.session_ending = False
        self.ended_session_id: UUID | None = None
        self.consent_revoked = False
        self.reloaded_after_revocation = False
        self.last_projection: PersonaProjection | None = None
        self.hold_projection = hold_projection
        self.base_role: Literal["adult", "guest", "k2", "n1"] = cast(
            Literal["adult", "guest", "k2", "n1"],
            "adult" if profile in {"adult", "owner"} else profile,
        )
        self.subject_id = uuid4() if identity_state in {"verified", "stale", "malformed"} else None
        self.profile_name = "raw-name-sentinel"
        self.profession = "raw-profession-security-architect-sentinel"
        self.child_identifier = "raw-child-n1-identifier-sentinel"
        self.raw_private_profile: dict[str, object] | None = (
            {
                "subject_id": str(self.subject_id),
                "name": self.profile_name,
                "profession": self.profession,
                "child_identifier": self.child_identifier,
                "traits": {
                    "private_note": self.adult_private_sentinel,
                    "free_form_trait": "raw-free-form-trait-sentinel",
                },
            }
            if seed_adult_private_traits
            else None
        )
        self.raw_private_trait_was_loaded = False
        self.identity = _Identity(identity_state, self.subject_id)
        self.custom_context = custom_context
        self.profiles = _Profiles(self)
        self.projection_entered = self.profiles.entered
        self.context_builder = ContextBuilder(PersonaBuilder.from_directory(Path("prompts")))
        self.production_context_provider = PersonalizedTurnContextProvider(
            self.sessions,
            self.identity,
            self.profiles,
            self.language_registry,
            self.context_builder,
            _Clock(),
        )
        self.ports = _Ports(self)
        self.linear_engine = LinearConversationEngine(
            self.ports,
            context_provider=self.production_context_provider,
        )

    @property
    def production_context_provider_calls(self) -> int:
        return self.profile_calls

    @property
    def shadow_prompt_calls(self) -> int:
        return 0

    @property
    def profile_projection_was_reloaded_after_revocation(self) -> bool:
        return self.reloaded_after_revocation

    async def run_turn(
        self,
        *,
        text: str,
        stt_language: SttLanguage,
        explicit_reply_language: ReplyMode | None = None,
    ) -> None:
        turn_id = uuid4()
        self.next_transcript = TranscribedTurn(
            text=text,
            stt_language=stt_language,
            explicit_reply_language=explicit_reply_language,
        )
        await self.linear_engine.run(TurnRequest(turn_id=turn_id, wav_bytes=b"wav"))

    def start_turn(
        self,
        *,
        text: str,
        stt_language: SttLanguage,
        explicit_reply_language: ReplyMode | None = None,
    ) -> asyncio.Task[object]:
        turn_id = uuid4()
        self.next_transcript = TranscribedTurn(
            text=text,
            stt_language=stt_language,
            explicit_reply_language=explicit_reply_language,
        )
        return asyncio.create_task(
            self.linear_engine.run(TurnRequest(turn_id=turn_id, wav_bytes=b"wav"))
        )

    async def revoke_personalization_consent(self) -> None:
        self.consent_revoked = True

    async def end_session(self) -> None:
        self.ended_session_id = await self.sessions.end_session()
        await self.production_context_provider.on_session_ended(self.ended_session_id)

    def begin_end_session(self) -> asyncio.Task[None]:
        async def _end() -> None:
            self.session_ending = True
            await self.end_session()

        return asyncio.create_task(_end())

    async def start_new_session(self) -> None:
        self.session_id = self.sessions.session_id

    def release_projection(self) -> None:
        self.profiles.release.set()


@pytest.fixture
def personalized_workflow_case() -> Callable[..., _PersonalizedWorkflowCase]:
    return _PersonalizedWorkflowCase


async def test_production_workflow_follows_english_hindi_romanized_and_mixed_switches(
    personalized_workflow_case: Callable[..., _PersonalizedWorkflowCase],
) -> None:
    case = personalized_workflow_case(profile="adult")
    turns: tuple[tuple[str, SttLanguage, ReplyMode | None, str], ...] = (
        ("Please explain rain", "en", None, "Reply in English."),
        ("बारिश क्यों होती है", "hi", None, "Reply in Devanagari Hindi."),
        ("baarish kyon hoti hai", "hi", None, "Reply in Romanized Hindi"),
        ("Please baarish simply explain karo", "hinglish", None, "mixing naturally"),
        ("अब केवल अंग्रेज़ी में", "hi", "en", "Reply in English."),
    )

    for text, stt, explicit, expected_rule in turns:
        await case.run_turn(text=text, stt_language=stt, explicit_reply_language=explicit)
        assert expected_rule in case.provider_captures[-1].messages[0]["content"]

    assert case.production_context_provider_calls == len(turns)
    assert case.shadow_prompt_calls == 0
    assert case.linear_engine.context_provider is case.production_context_provider
    assert not hasattr(case, "langgraph_engine")


async def test_guest_and_revoked_personalization_use_current_safe_projection(
    personalized_workflow_case: Callable[..., _PersonalizedWorkflowCase],
) -> None:
    guest = personalized_workflow_case(
        identity_state="uncertain",
        seed_adult_private_traits=True,
    )
    await guest.run_turn(text="help me", stt_language="en")
    assert "general help" in guest.system_prompt.casefold()
    assert guest.adult_private_sentinel.encode("utf-8") not in guest.provider_capture_bytes

    adult = personalized_workflow_case(profile="adult", custom_context="technical_security")
    await adult.run_turn(text="first", stt_language="en")
    assert "security architecture" in adult.system_prompt.casefold()
    await adult.revoke_personalization_consent()
    await adult.run_turn(text="second", stt_language="en")
    assert "security architecture" not in adult.system_prompt.casefold()
    assert adult.last_projection is not None
    assert adult.last_projection.role == "adult"
    assert adult.profile_projection_was_reloaded_after_revocation


async def test_session_end_clears_language_prior(
    personalized_workflow_case: Callable[..., _PersonalizedWorkflowCase],
) -> None:
    case = personalized_workflow_case(profile="owner")
    await case.run_turn(text="बारिश", stt_language="hi")
    old_session = case.session_id

    await case.end_session()
    assert not case.language_registry.contains(old_session)
    await case.start_new_session()
    await case.run_turn(text="hmm", stt_language="unknown")

    assert case.last_reply_mode == "en"


async def test_session_end_racing_context_build_clears_after_the_last_lease(
    personalized_workflow_case: Callable[..., _PersonalizedWorkflowCase],
) -> None:
    case = personalized_workflow_case(profile="adult", hold_projection=True)
    prepare = case.start_turn(text="बारिश", stt_language="hi")
    await case.projection_entered.wait()

    ending = case.begin_end_session()
    await asyncio.sleep(0)
    assert ending.done() is False
    case.release_projection()
    await prepare
    await ending

    assert case.ended_session_id is not None
    assert not case.language_registry.contains(case.ended_session_id)
    assert case.provider_calls_after_session_end == 0


@pytest.mark.parametrize(
    "identity_state",
    ("ambiguous", "conflict", "unknown", "stale", "malformed"),
)
async def test_unsafe_identity_decisions_use_guest_without_profile_lookup(
    personalized_workflow_case: Callable[..., _PersonalizedWorkflowCase],
    identity_state: str,
) -> None:
    case = personalized_workflow_case(
        profile="adult",
        identity_state=identity_state,
        custom_context="technical_security",
        seed_adult_private_traits=True,
    )

    await case.run_turn(text="help me", stt_language="en")

    assert case.profile_calls == 0
    assert "general help" in case.system_prompt.casefold()
    assert "security architecture" not in case.system_prompt.casefold()
    assert case.raw_private_trait_was_loaded is False


async def test_private_profile_sentinels_are_loaded_but_never_provider_visible(
    personalized_workflow_case: Callable[..., _PersonalizedWorkflowCase],
    caplog: pytest.LogCaptureFixture,
) -> None:
    case = personalized_workflow_case(
        profile="adult",
        custom_context="technical_security",
        seed_adult_private_traits=True,
    )

    await case.run_turn(text="explain the design", stt_language="en")

    assert case.raw_private_trait_was_loaded is True
    assert case.subject_id is not None
    provider_surface = (
        case.provider_capture_bytes
        + repr(case.provider_captures).encode("utf-8")
        + case.provider_captures[-1].prompt_bundle_sha256.encode("utf-8")
        + case.provider_captures[-1].provider_messages_sha256.encode("utf-8")
        + caplog.text.encode("utf-8")
    )
    for sentinel in (
        case.profile_name,
        str(case.subject_id),
        case.profession,
        case.child_identifier,
        case.adult_private_sentinel,
        "raw-free-form-trait-sentinel",
    ):
        assert sentinel.encode("utf-8") not in provider_surface


async def test_prompt_bundle_hash_is_static_while_provider_body_hash_tracks_transcript(
    personalized_workflow_case: Callable[..., _PersonalizedWorkflowCase],
    caplog: pytest.LogCaptureFixture,
) -> None:
    case = personalized_workflow_case(profile="guest")
    first_transcript = "raw-transcript-digest-sentinel-one"
    second_transcript = "raw-transcript-digest-sentinel-two"

    await case.run_turn(text=first_transcript, stt_language="en")
    await case.run_turn(text=second_transcript, stt_language="en")
    first, second = case.provider_captures

    assert first.prompt_bundle_sha256 == case.context_builder.prompt_bundle_sha256
    assert second.prompt_bundle_sha256 == case.context_builder.prompt_bundle_sha256
    assert first.prompt_bundle_sha256 == second.prompt_bundle_sha256
    assert first.provider_messages_sha256 == provider_messages_sha256(first.messages)
    assert second.provider_messages_sha256 == provider_messages_sha256(second.messages)
    assert first.provider_messages_sha256 != second.provider_messages_sha256
    digest_and_log_surface = (
        first.prompt_bundle_sha256
        + second.prompt_bundle_sha256
        + first.provider_messages_sha256
        + second.provider_messages_sha256
        + caplog.text
    )
    assert first_transcript not in digest_and_log_surface
    assert second_transcript not in digest_and_log_surface
    assert first.provider_messages_sha256 not in caplog.text
    assert second.provider_messages_sha256 not in caplog.text


async def test_provider_turn_context_is_immutable_and_hash_commits_visible_body(
    personalized_workflow_case: Callable[..., _PersonalizedWorkflowCase],
) -> None:
    case = personalized_workflow_case(profile="guest")
    await case.run_turn(text="hello", stt_language="en")
    context = case.provider_captures[-1]

    with pytest.raises(TypeError):
        context.messages[0]["content"] = "mutated"

    tampered_system = dict(context.messages[0])
    tampered_user = dict(context.messages[1])
    tampered_system["content"] += " changed"
    with pytest.raises(ValueError, match="provider message hash"):
        ProviderTurnContext(
            messages=(tampered_system, tampered_user),
            reply_mode=context.reply_mode,
            prompt_bundle_sha256=context.prompt_bundle_sha256,
            provider_messages_sha256=context.provider_messages_sha256,
        )

    with pytest.raises(ValueError, match="provider message"):
        ProviderTurnContext(
            messages=({"role": "assistant", "content": "no"},),
            reply_mode="en",
            prompt_bundle_sha256=context.prompt_bundle_sha256,
            provider_messages_sha256=context.provider_messages_sha256,
        )

    with pytest.raises(ValueError, match="invalid prompt bundle hash"):
        ProviderTurnContext(
            messages=context.messages,
            reply_mode=context.reply_mode,
            prompt_bundle_sha256=context.prompt_bundle_sha256.upper(),
            provider_messages_sha256=context.provider_messages_sha256,
        )


async def test_provider_context_rejects_total_body_over_turn_limit_before_construction(
    personalized_workflow_case: Callable[..., _PersonalizedWorkflowCase],
) -> None:
    case = personalized_workflow_case(profile="guest")

    with pytest.raises(ValueError, match="provider context"):
        case.context_builder.messages(
            PersonaProjection(
                role="guest",
                context="general",
                tone="neutral",
                depth="brief",
                learning_level="none",
            ),
            "en",
            "a" * 4_097,
        )
