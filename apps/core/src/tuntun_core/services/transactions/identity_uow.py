from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from types import TracebackType
from typing import Protocol, Self, TypeVar
from uuid import UUID

from tuntun_contracts.audit import AuditDraft
from tuntun_contracts.policy import AuthContext
from tuntun_core.domain.profile import (
    BiometricTemplate,
    ConsentPurpose,
    ConsentReceipt,
    EnrollmentSession,
    GuestConsentPurpose,
    GuestDisclosureChallenge,
    GuestSessionConsentReceipt,
    Profile,
    RequestEnrollment,
)
from tuntun_core.services.transactions.protocols import AsyncUnitOfWorkProtocol, UnitOfWorkProtocol

ResultT = TypeVar("ResultT")


class ProfileRepositoryPort(Protocol):
    async def insert(self, profile: Profile) -> None: ...

    async def get(self, subject_id: UUID) -> Profile: ...

    async def get_scoped(self, household_id: UUID, subject_id: UUID) -> Profile: ...

    async def get_optional_scoped(self, household_id: UUID, subject_id: UUID) -> Profile | None: ...

    async def list_children_due_for_reenrollment_reminder(
        self,
        household_id: UUID,
        now: datetime,
    ) -> tuple[Profile, ...]: ...

    async def disable_biometric_identity(
        self,
        subject_id: UUID,
        now: object,
    ) -> None: ...

    async def require_current_owner_guardian_generation(
        self,
        household_id: UUID,
        guardian_id: UUID,
        now: datetime,
    ) -> int: ...

    async def update_persona_expected_version(
        self,
        subject_id: UUID,
        expected_version: int,
        encrypted_persona_traits: bytes | None,
        now: object,
    ) -> Profile: ...

    async def revoke_and_advance_authority_generation_expected_version(
        self,
        subject_id: UUID,
        expected_version: int,
        current_authority_generation: int,
        now: object,
    ) -> Profile: ...

    def created_audit(self, profile: Profile, auth: AuthContext) -> AuditDraft: ...

    def persona_changed_audit(
        self,
        profile: Profile,
        auth: AuthContext,
        *,
        operation: str,
    ) -> AuditDraft: ...

    def revoked_audit(self, profile: Profile, auth: AuthContext) -> AuditDraft: ...


class ConsentReceiptRepositoryPort(Protocol):
    async def append(self, receipt: ConsentReceipt, auth: AuthContext) -> None: ...

    async def append_replacing_current(
        self,
        receipt: ConsentReceipt,
        *,
        expected_latest_receipt_id: UUID | None,
        auth: AuthContext,
    ) -> None: ...

    async def latest(self, subject_id: UUID, purpose: ConsentPurpose) -> ConsentReceipt | None: ...

    async def latest_for_update(
        self,
        subject_id: UUID,
        purpose: ConsentPurpose,
    ) -> ConsentReceipt | None: ...

    async def require_current_for_update(
        self,
        subject_id: UUID,
        purpose: ConsentPurpose,
        now: object,
    ) -> ConsentReceipt: ...

    def granted_from(
        self,
        command: object,
        *,
        household_id: UUID,
        guardian_id: UUID | None,
        guardian_generation: int | None,
        now: object,
        expires_at: object | None,
        commitment_key_id: str,
        receipt_hmac: bytes,
    ) -> ConsentReceipt: ...

    def revoked_from(
        self,
        current: ConsentReceipt,
        actor_id: UUID,
        *,
        guardian_id: UUID | None,
        guardian_generation: int | None,
        now: object,
        expires_at: object,
        commitment_key_id: str,
        receipt_hmac: bytes,
    ) -> ConsentReceipt: ...

    def audit_draft(self, receipt: ConsentReceipt, auth: AuthContext) -> AuditDraft: ...

    def identity_consent_revoked_event(self, receipt: ConsentReceipt, now: object) -> object: ...

    async def revoke_subject_authorities_in_uow(
        self,
        subject_id: UUID,
        through_generation: int,
        reason: str,
        now: object,
    ) -> None: ...


class EnrollmentRepositoryPort(Protocol):
    async def create(
        self,
        command: RequestEnrollment,
        auth: AuthContext,
        *,
        household_id: UUID,
        consent_receipt_id: UUID,
        subject_is_child: bool,
        now: object,
        expires_at: object,
        synthetic_template_id: UUID,
    ) -> EnrollmentSession: ...

    async def require_for_update(self, enrollment_id: UUID) -> EnrollmentSession: ...

    async def require_state(
        self,
        enrollment_id: UUID,
        states: str | tuple[str, ...],
    ) -> EnrollmentSession: ...

    async def begin_capture(self, enrollment_id: UUID, now: object) -> EnrollmentSession: ...

    async def mark_calibrating(self, enrollment_id: UUID, now: object) -> EnrollmentSession: ...

    async def cancel_pending(self, enrollment_id: UUID, now: object) -> EnrollmentSession: ...

    async def approve(
        self,
        enrollment_id: UUID,
        template_ids: tuple[UUID, ...],
        reminder_at: object | None,
        hard_expires_at: object | None,
        now: object,
    ) -> EnrollmentSession: ...

    async def cancel_subject_modality(
        self,
        subject_id: UUID,
        modality: str,
        now: object,
    ) -> int: ...

    def requested_audit(self, session: EnrollmentSession, auth: AuthContext) -> AuditDraft: ...

    def cancelled_audit(self, session: EnrollmentSession, auth: AuthContext) -> AuditDraft: ...

    def approved_audit(self, session: EnrollmentSession) -> AuditDraft: ...

    def expiry_batch_audit(
        self,
        templates: tuple[BiometricTemplate, ...],
        now: object,
    ) -> AuditDraft: ...


class BiometricTemplateRepositoryPort(Protocol):
    async def require_ready_for_approval(
        self,
        template_ids: tuple[UUID, ...],
        *,
        enrollment_session_id: UUID,
        expected_template_id: UUID,
        household_id: UUID,
        subject_id: UUID,
        modality: str,
        consent_receipt_id: UUID,
    ) -> tuple[BiometricTemplate, ...]: ...

    async def list_child_templates_past_hard_expiry(
        self,
        household_id: UUID,
        now: object,
    ) -> tuple[BiometricTemplate, ...]: ...

    async def expire_template(self, template_id: UUID, now: object) -> None: ...

    async def revoke_subject_modality(
        self,
        subject_id: UUID,
        modality: str,
        now: object,
    ) -> tuple[BiometricTemplate, ...]: ...

    async def revoke_subject_authorities_in_uow(
        self,
        subject_id: UUID,
        through_generation: int,
        reason: str,
        now: object,
    ) -> None: ...

    def managed_erasure_requested_audit(
        self,
        template: BiometricTemplate,
        *,
        stores: tuple[str, ...],
        requested_at: object,
    ) -> AuditDraft: ...


class GuestDisclosureChallengeRepositoryPort(Protocol):
    async def create(
        self,
        challenge_id: UUID,
        household_id: UUID,
        session_id: UUID,
        purpose: GuestConsentPurpose,
        disclosure_version: str,
        presentation_receipt_id: UUID,
        now: object,
        expires_at: object,
        commitment_key_id: str,
        challenge_hmac: bytes,
    ) -> GuestDisclosureChallenge: ...

    async def lock_open(self, challenge_id: UUID, now: object) -> GuestDisclosureChallenge: ...

    async def consume_denied(self, challenge_id: UUID, now: object) -> None: ...

    async def consume_accepted(self, challenge_id: UUID, now: object) -> None: ...


class GuestSessionConsentRepositoryPort(Protocol):
    async def append(
        self,
        household_id: UUID,
        session_id: UUID,
        challenge_id: UUID,
        presentation_receipt_id: UUID,
        purpose: GuestConsentPurpose,
        disclosure_version: str,
        granted: bool,
        issued_at: object,
        expires_at: object,
        revoked_at: object | None,
        commitment_key_id: str,
        receipt_hmac: bytes,
    ) -> GuestSessionConsentReceipt: ...

    async def latest(
        self,
        household_id: UUID,
        session_id: UUID,
        purpose: GuestConsentPurpose,
    ) -> GuestSessionConsentReceipt | None: ...

    async def lock_current(
        self,
        household_id: UUID,
        session_id: UUID,
        purpose: GuestConsentPurpose,
        now: object,
    ) -> GuestSessionConsentReceipt: ...

    def granted_audit(
        self, receipt: GuestSessionConsentReceipt, challenge_id: UUID
    ) -> AuditDraft: ...

    def revoked_audit(self, receipt: GuestSessionConsentReceipt) -> AuditDraft: ...


class IdentitySessionPort(Protocol):
    expires_at: datetime


class SessionIdentityRepositoryPort(Protocol):
    async def lock_active(
        self, household_id: UUID, session_id: UUID, now: object
    ) -> IdentitySessionPort: ...

    async def require_active(
        self, household_id: UUID, session_id: UUID, now: object
    ) -> IdentitySessionPort: ...

    async def invalidate_identity_subject(
        self, subject_id: UUID, reason: str, now: object
    ) -> None: ...


class EventReceiptRepositoryPort(Protocol):
    async def require_exact_guest_disclosure(
        self,
        presentation_receipt_id: UUID,
        *,
        household_id: UUID,
        session_id: UUID,
        purpose: GuestConsentPurpose,
        disclosure_version: str,
        now: object,
    ) -> None: ...


class SubjectRevocationOutboxPort(Protocol):
    async def enqueue_in_uow(
        self,
        uow: AsyncUnitOfWorkProtocol,
        *,
        event_key: str,
        subject_id: UUID,
        new_authority_generation: int,
        occurred_at: datetime,
    ) -> object: ...


class SubjectRevocationEffectRepositoryPort(Protocol):
    async def recover_stale(self, now: object) -> int: ...


class ProviderCallsRevocationPort(Protocol):
    async def reconcile_revoked_subject_once(
        self,
        *,
        event_id: UUID,
        family: str,
        subject_id: UUID,
        through_generation: int,
        idempotency_key: UUID,
    ) -> object: ...


class BudgetReservationsRevocationPort(Protocol):
    async def settle_conservative_once(
        self,
        reservation_ids: tuple[UUID, ...],
        *,
        idempotency_key: UUID,
    ) -> None: ...


class IdentityUnitOfWork(AsyncUnitOfWorkProtocol, Protocol):
    profiles: ProfileRepositoryPort
    consent_receipts: ConsentReceiptRepositoryPort
    enrollments: EnrollmentRepositoryPort
    biometric_templates: BiometricTemplateRepositoryPort
    guest_session_consents: GuestSessionConsentRepositoryPort
    guest_disclosure_challenges: GuestDisclosureChallengeRepositoryPort
    sessions: SessionIdentityRepositoryPort
    event_receipts: EventReceiptRepositoryPort
    subject_revocation_outbox: SubjectRevocationOutboxPort
    subject_revocation_effects: SubjectRevocationEffectRepositoryPort
    provider_calls: ProviderCallsRevocationPort
    budget_reservations: BudgetReservationsRevocationPort

    async def __aenter__(self) -> Self: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool: ...

    async def run_sync(self, operation: Callable[[UnitOfWorkProtocol], ResultT]) -> ResultT: ...


class IdentityUnitOfWorkFactory(Protocol):
    def __call__(self) -> IdentityUnitOfWork: ...
