# tests/security/test_provider_boundary.py
from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from tuntun_contracts.identity import IdentityDecision, IdentityStatus, PersonaProjection
from tuntun_core.services.context_builder import ContextBuilder
from tuntun_core.services.persona_builder import PersonaBuilder
from tuntun_core.services.personalized_turn_context import (
    ActiveSessionContext,
    PersonalizedTurnContextProvider,
    SessionLanguageRegistry,
    TranscribedTurn,
)

pytest_plugins = ("tests.fixtures.provider_egress",)


@pytest.mark.asyncio
async def test_private_contact_never_reaches_capture_receipts_calls_logs_or_errors(
    provider_boundary_case, caplog
) -> None:
    sentinel = "family-secret-sentinel@example.test"
    case = provider_boundary_case(user_text=f"Please contact {sentinel}")
    await case.run_reasoning()
    assert sentinel not in case.captured_provider_body.decode("utf-8")
    assert "[CONTACT]" in case.captured_provider_body.decode("utf-8")
    assert sentinel not in await case.serialized_receipt_and_call_rows()
    assert sentinel not in caplog.text


@pytest.mark.asyncio
async def test_prohibited_secret_or_second_pass_failure_creates_zero_egress_proof(
    provider_boundary_case,
) -> None:
    for mutation in (
        "secret_in_input",
        "secret_in_canonical_body",
        "email_in_canonical_body",
        "phone_in_canonical_body",
        "session_label_in_canonical_body",
    ):
        case = provider_boundary_case(mutation=mutation)
        with pytest.raises(ValueError, match="PROHIBITED_SECRET|SECOND_PASS_REJECTED"):
            await case.run_reasoning()
        assert case.network_calls == 0
        assert await case.redaction_receipt_count() == 0
        assert await case.provider_call_count() == 0


def test_search_categories_are_not_registered_in_task05(production_core_container) -> None:
    assert production_core_container.provider_gateway.supported_purposes == frozenset(
        {"cloud_stt", "cloud_reasoning", "cloud_tts"}
    )


@pytest.mark.asyncio
async def test_task14_persona_projection_keeps_private_profile_out_of_provider_boundary(
    caplog: pytest.LogCaptureFixture,
) -> None:
    now = datetime(2026, 8, 27, tzinfo=UTC)
    session_id = uuid4()
    household_id = uuid4()
    subject_id = uuid4()
    sentinels = (
        "raw-person-name-sentinel",
        str(subject_id),
        "raw-profession-sentinel",
        "raw-child-identifier-sentinel",
        "raw-free-form-trait-sentinel",
    )

    class Sessions:
        @asynccontextmanager
        async def active_context_lease(
            self,
            turn_id: UUID,
        ) -> AsyncIterator[ActiveSessionContext]:
            assert turn_id == session_id
            yield ActiveSessionContext(id=session_id, household_id=household_id)

    class Identity:
        async def require_current_for_turn(self, turn_id: UUID) -> IdentityDecision:
            assert turn_id == session_id
            return IdentityDecision(
                status=IdentityStatus.VERIFIED,
                subject_id=subject_id,
                reason_code="test",
                expires_at=now + timedelta(minutes=5),
            )

    class Profiles:
        loaded_private_profile = False

        async def get_persona_projection(
            self,
            household_id_arg: UUID,
            subject_id_arg: UUID | None,
            observed_at: datetime,
        ) -> PersonaProjection:
            assert household_id_arg == household_id
            assert subject_id_arg == subject_id
            assert observed_at == now
            self.loaded_private_profile = True
            raw_profile = {
                "name": sentinels[0],
                "subject_id": sentinels[1],
                "profession": sentinels[2],
                "child_identifier": sentinels[3],
                "free_form_trait": sentinels[4],
            }
            assert raw_profile
            return PersonaProjection(
                role="adult",
                context="technical_security",
                tone="precise",
                depth="detailed",
                learning_level="none",
            )

    class Clock:
        def now(self) -> datetime:
            return now

    profiles = Profiles()
    context_builder = ContextBuilder(PersonaBuilder.from_directory(Path("prompts")))
    provider = PersonalizedTurnContextProvider(
        Sessions(),
        Identity(),
        profiles,
        SessionLanguageRegistry(),
        context_builder,
        Clock(),
    )

    context = await provider.prepare(session_id, TranscribedTurn(text="hello", stt_language="en"))

    assert profiles.loaded_private_profile is True
    assert context.prompt_bundle_sha256 != context_builder.prompt_bundle_sha256
    provider_surface = (repr(context.messages) + context.prompt_bundle_sha256 + caplog.text).encode(
        "utf-8"
    )
    for sentinel in sentinels:
        assert sentinel.encode("utf-8") not in provider_surface
