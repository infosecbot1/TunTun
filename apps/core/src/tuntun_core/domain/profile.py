from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator
from tuntun_contracts.actions import ActionBinding
from tuntun_contracts.identity import PersonaProjection, PersonaTraits


class ProfileClass(StrEnum):
    OWNER = "owner"
    ADULT = "adult"
    K2 = "k2"
    N1 = "n1"
    GUEST = "guest"


class ConsentPurpose(StrEnum):
    FACE = "face"
    VOICE = "voice"
    PERSONALIZATION = "personalization"
    CLOUD_STT = "cloud_stt"
    CLOUD_REASONING = "cloud_reasoning"
    CLOUD_TTS = "cloud_tts"
    WEB_SEARCH = "web_search"
    CHILD_DURABLE_MEMORY = "child_durable_memory_v1"


type GuestConsentPurpose = Literal["cloud_stt", "cloud_reasoning", "cloud_tts"]


class Modality(StrEnum):
    FACE = "face"
    VOICE = "voice"

    @property
    def consent_purpose(self) -> ConsentPurpose:
        return ConsentPurpose(self.value)


class DomainModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


class CreateProfile(DomainModel):
    household_id: UUID
    subject_id: UUID
    profile_class: ProfileClass
    guardian_id: UUID | None = None
    display_label: str = Field(min_length=1, max_length=128)
    action_binding: ActionBinding


class RevokeProfile(DomainModel):
    subject_id: UUID
    expected_version: int = Field(ge=1)
    action_binding: ActionBinding


class UpdatePersonaTraits(DomainModel):
    subject_id: UUID
    actor_id: UUID
    target_profile_class: ProfileClass
    traits: PersonaTraits | None
    expected_version: int = Field(ge=1)
    guardian_generation: int | None = Field(default=None, ge=1)
    action_binding: ActionBinding


class GrantConsent(DomainModel):
    subject_id: UUID
    actor_id: UUID
    purpose: ConsentPurpose
    expected_latest_receipt_id: UUID | None = None
    guardian_generation: int | None = Field(default=None, ge=1)
    action_binding: ActionBinding
    policy_version: str = Field(default="phase1-v1", min_length=1, max_length=64)
    disclosure_version: str = Field(default="phase1-disclosure-v1", min_length=1, max_length=64)


class RevokeConsent(DomainModel):
    subject_id: UUID
    actor_id: UUID
    purpose: ConsentPurpose
    expected_latest_receipt_id: UUID
    guardian_generation: int | None = Field(default=None, ge=1)
    policy_version: str = Field(min_length=1, max_length=64)
    disclosure_version: str = Field(min_length=1, max_length=64)
    action_binding: ActionBinding


class ConsentReceipt(DomainModel):
    id: UUID
    household_id: UUID
    subject_id: UUID
    actor_id: UUID
    guardian_id: UUID | None
    guardian_generation: int | None
    purpose: ConsentPurpose
    granted: bool
    policy_version: str = Field(min_length=1, max_length=64)
    disclosure_version: str = Field(min_length=1, max_length=64)
    commitment_key_id: str = Field(min_length=1, max_length=128)
    receipt_hmac: bytes = Field(min_length=32, max_length=64)
    created_at: AwareDatetime
    expires_at: AwareDatetime | None = None


class GuestSessionConsentReceipt(DomainModel):
    id: UUID
    household_id: UUID
    session_id: UUID
    challenge_id: UUID
    presentation_receipt_id: UUID
    purpose: GuestConsentPurpose
    disclosure_version: str = Field(min_length=1, max_length=64)
    granted: bool
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    revoked_at: AwareDatetime | None = None
    commitment_key_id: str = Field(min_length=1, max_length=128)
    receipt_hmac: bytes = Field(min_length=32, max_length=64)


class GuestDisclosureChallenge(DomainModel):
    id: UUID
    household_id: UUID
    session_id: UUID
    purpose: GuestConsentPurpose
    disclosure_version: str = Field(min_length=1, max_length=64)
    state: Literal["open", "accepted", "denied"]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    consumed_at: AwareDatetime | None = None
    presentation_receipt_id: UUID
    commitment_key_id: str = Field(min_length=1, max_length=128)
    challenge_hmac: bytes = Field(min_length=32, max_length=64)


class RequestEnrollment(DomainModel):
    subject_id: UUID
    modality: Modality
    expected_profile_version: int = Field(ge=1)
    expected_consent_receipt_id: UUID
    action_binding: ActionBinding
    reenrollment_days: int = Field(default=180, ge=30, le=365)


class CancelEnrollment(DomainModel):
    subject_id: UUID
    enrollment_id: UUID
    action_binding: ActionBinding


class EnrollmentSession(DomainModel):
    id: UUID
    household_id: UUID | None = None
    subject_id: UUID
    modality: Modality
    state: Literal["requested", "capturing", "calibrating", "approved", "cancelled", "expired"]
    consent_receipt_id: UUID | None = None
    reenrollment_days: int = Field(default=180, ge=30, le=365)
    subject_is_child: bool = False
    synthetic_template_id: UUID | None = None
    created_at: AwareDatetime | None = None
    expires_at: AwareDatetime | None = None
    closed_at: AwareDatetime | None = None
    next_reenrollment_reminder_at: AwareDatetime | None = None
    biometric_hard_expires_at: AwareDatetime | None = None


class BiometricTemplate(DomainModel):
    id: UUID
    enrollment_session_id: UUID | None = None
    household_id: UUID
    subject_id: UUID
    modality: Modality
    model_version: str = Field(min_length=1, max_length=128)
    consent_receipt_id: UUID
    created_at: AwareDatetime
    expires_at: AwareDatetime | None = None
    revoked_at: AwareDatetime | None = None


class Profile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    id: UUID
    household_id: UUID
    guardian_id: UUID | None
    guardian_generation: int = Field(ge=0)
    profile_class: ProfileClass
    encrypted_display_label: bytes = Field(min_length=28, max_length=1024)
    encrypted_persona_traits: bytes | None = Field(default=None, min_length=28, max_length=4096)
    current_consent_receipt_ids: Annotated[tuple[UUID, ...], Field(min_length=0, max_length=8)] = ()
    active: bool
    authority_generation: int = Field(ge=1)
    version: int = Field(ge=1)
    next_reenrollment_reminder_at: AwareDatetime | None
    created_at: AwareDatetime
    updated_at: AwareDatetime
    revoked_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def guest_is_projection_only(self) -> Profile:
        if self.profile_class is ProfileClass.GUEST:
            raise ValueError("guest_profile_must_not_be_persisted")
        is_child = self.profile_class in {ProfileClass.K2, ProfileClass.N1}
        if is_child != (self.guardian_id is not None):
            raise ValueError("guardian_required_exactly_for_child")
        if is_child != (self.guardian_generation >= 1):
            raise ValueError("guardian_generation_required_exactly_for_child")
        return self

    @field_validator("current_consent_receipt_ids")
    @classmethod
    def unique_current_consents(cls, value: tuple[UUID, ...]) -> tuple[UUID, ...]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate current consent receipt")
        return value


class ProfileProjection(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    subject_id: UUID | None
    profile_class: ProfileClass
    may_retrieve_private_memory: bool


GUEST_PROJECTION = ProfileProjection(
    subject_id=None,
    profile_class=ProfileClass.GUEST,
    may_retrieve_private_memory=False,
)

GUEST_PERSONA_PROJECTION = PersonaProjection(
    role="guest",
    context="general",
    tone="neutral",
    depth="brief",
    learning_level="none",
)
