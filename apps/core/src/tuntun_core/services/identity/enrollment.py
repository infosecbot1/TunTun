from __future__ import annotations

from collections.abc import Awaitable, Callable
from contextlib import AbstractAsyncContextManager
from datetime import datetime, timedelta
from typing import Protocol, TypeVar
from uuid import UUID, uuid4

from tuntun_contracts.actions import ActionBinding
from tuntun_contracts.audit import AuditDraft
from tuntun_contracts.policy import AssuranceLevel, AuthContext
from tuntun_core.domain.profile import (
    CancelEnrollment,
    ConsentPurpose,
    ConsentReceipt,
    EnrollmentSession,
    ProfileClass,
    RequestEnrollment,
)
from tuntun_core.services.actions.parameter_binding import (
    ActionBindingVerifier,
    ActionParameterBindingVerifier,
    enrollment_cancel_parameters,
    enrollment_request_parameters,
)
from tuntun_core.services.identity.consent import ConsentDenied
from tuntun_core.services.transactions.identity_uow import (
    IdentityUnitOfWork,
    IdentityUnitOfWorkFactory,
)

_FRESH_OWNER_PASSKEY_SECONDS = 120
_ENROLLMENT_SESSION_TTL = timedelta(minutes=30)
_CHILD_BIOMETRIC_HARD_EXPIRY = timedelta(days=365)
_CHILD_PROFILE_CLASSES = frozenset({ProfileClass.K2, ProfileClass.N1})
ResultT = TypeVar("ResultT", bound=EnrollmentSession)


class EnrollmentDenied(RuntimeError):
    pass


class ClockPort(Protocol):
    def now(self) -> datetime: ...


class MutationScopePort(Protocol):
    def require_active_uow(self) -> IdentityUnitOfWork: ...

    def open(self) -> AbstractAsyncContextManager[IdentityUnitOfWork]: ...


class AuditLedgerPort(Protocol):
    async def append(self, uow: IdentityUnitOfWork, draft: AuditDraft) -> None: ...


class ConsentReadPort(Protocol):
    async def require_current_in_uow(
        self,
        uow: IdentityUnitOfWork,
        subject_id: UUID,
        purpose: ConsentPurpose,
        now: datetime,
    ) -> ConsentReceipt: ...


class AuthenticationPort(Protocol):
    async def consume_in_uow(
        self,
        uow: IdentityUnitOfWork,
        grant_id: UUID,
        binding: ActionBinding,
    ) -> AuthContext: ...


class EnrollmentService:
    def __init__(
        self,
        uow_factory: IdentityUnitOfWorkFactory,
        mutation_scope: MutationScopePort,
        consents: ConsentReadPort,
        parameter_verifier: ActionParameterBindingVerifier,
        action_binding_verifier: ActionBindingVerifier,
        audit_ledger: AuditLedgerPort,
        clock: ClockPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._scope = mutation_scope
        self._consents = consents
        self._parameters = parameter_verifier
        self._bindings = action_binding_verifier
        self._audit = audit_ledger
        self._clock = clock

    async def request(self, command: RequestEnrollment, auth: AuthContext) -> EnrollmentSession:
        self._require_request_authorization(command, auth)
        uow = self._active_uow_or_none()
        if uow is not None:
            return await self._request_in_active_uow(uow, command, auth)
        async with self._scope.open() as opened_uow:
            session = await self._request_in_active_uow(opened_uow, command, auth)
            await opened_uow.commit()
            return session

    async def request_in_uow(
        self,
        uow: IdentityUnitOfWork,
        command: RequestEnrollment,
        auth: AuthContext,
    ) -> EnrollmentSession:
        if self._scope.require_active_uow() is not uow:
            raise RuntimeError("enrollment_uow_scope_mismatch")
        self._require_request_authorization(command, auth)
        return await self._request_in_active_uow(uow, command, auth)

    async def cancel_in_uow(
        self,
        uow: IdentityUnitOfWork,
        command: CancelEnrollment,
        auth: AuthContext,
    ) -> EnrollmentSession:
        if self._scope.require_active_uow() is not uow:
            raise RuntimeError("enrollment_uow_scope_mismatch")
        self._require_cancel_authorization(command, auth)
        assert auth.subject_id is not None
        try:
            await uow.profiles.require_current_owner_guardian_generation(
                command.action_binding.household_id,
                auth.subject_id,
                self._clock.now(),
            )
        except PermissionError as exc:
            raise EnrollmentDenied("fresh_owner_passkey_required") from exc
        session = await uow.enrollments.require_for_update(command.enrollment_id)
        if (
            session.subject_id != command.subject_id
            or session.household_id != command.action_binding.household_id
        ):
            raise EnrollmentDenied("enrollment_scope_mismatch")
        cancelled = await uow.enrollments.cancel_pending(command.enrollment_id, self._clock.now())
        await self._audit.append(uow, uow.enrollments.cancelled_audit(cancelled, auth))
        return cancelled

    async def begin_capture_in_uow(
        self,
        uow: IdentityUnitOfWork,
        enrollment_id: UUID,
    ) -> EnrollmentSession:
        if self._scope.require_active_uow() is not uow:
            raise RuntimeError("enrollment_uow_scope_mismatch")
        return await uow.enrollments.begin_capture(enrollment_id, self._clock.now())

    async def mark_calibrating_in_uow(
        self,
        uow: IdentityUnitOfWork,
        enrollment_id: UUID,
    ) -> EnrollmentSession:
        if self._scope.require_active_uow() is not uow:
            raise RuntimeError("enrollment_uow_scope_mismatch")
        return await uow.enrollments.mark_calibrating(enrollment_id, self._clock.now())

    async def complete_in_uow(
        self,
        uow: IdentityUnitOfWork,
        enrollment_id: UUID,
        template_ids: tuple[UUID, ...],
        consent_receipt: ConsentReceipt,
        now: datetime,
    ) -> EnrollmentSession:
        if self._scope.require_active_uow() is not uow:
            raise RuntimeError("enrollment_uow_scope_mismatch")
        if not template_ids or any(type(template_id) is not UUID for template_id in template_ids):
            raise EnrollmentDenied("enrollment_template_required")
        try:
            session = await uow.enrollments.require_state(enrollment_id, "calibrating")
        except RuntimeError as exc:
            raise EnrollmentDenied("enrollment_state_mismatch") from exc
        if session.expires_at is None or session.expires_at <= now:
            raise EnrollmentDenied("enrollment_session_expired")
        expected_template_id = session.synthetic_template_id
        if expected_template_id is None or template_ids != (expected_template_id,):
            raise EnrollmentDenied("enrollment_template_scope_mismatch")
        if (
            session.consent_receipt_id != consent_receipt.id
            or consent_receipt.subject_id != session.subject_id
            or consent_receipt.purpose is not session.modality.consent_purpose
        ):
            raise EnrollmentDenied("enrollment_consent_scope_mismatch")
        try:
            current_consent = await self._consents.require_current_in_uow(
                uow,
                session.subject_id,
                session.modality.consent_purpose,
                now,
            )
        except ConsentDenied as exc:
            raise EnrollmentDenied("enrollment_consent_state_changed") from exc
        if (
            current_consent.id != session.consent_receipt_id
            or current_consent.household_id != session.household_id
        ):
            raise EnrollmentDenied("enrollment_consent_state_changed")
        assert session.household_id is not None
        assert session.consent_receipt_id is not None
        try:
            await uow.biometric_templates.require_ready_for_approval(
                template_ids,
                enrollment_session_id=session.id,
                expected_template_id=expected_template_id,
                household_id=session.household_id,
                subject_id=session.subject_id,
                modality=session.modality.value,
                consent_receipt_id=session.consent_receipt_id,
            )
        except (KeyError, RuntimeError, PermissionError) as exc:
            raise EnrollmentDenied("enrollment_template_scope_mismatch") from exc
        reminder_at = None
        hard_expires_at = None
        if session.subject_is_child:
            reminder_at = now + timedelta(days=session.reenrollment_days)
            hard_expires_at = now + _CHILD_BIOMETRIC_HARD_EXPIRY
        approved = await uow.enrollments.approve(
            enrollment_id,
            template_ids,
            reminder_at,
            hard_expires_at,
            now,
        )
        await self._audit.append(uow, uow.enrollments.approved_audit(approved))
        return approved

    async def reminders_due(self, household_id: UUID, now: datetime) -> tuple[UUID, ...]:
        async with self._uow_factory() as uow:
            due = await uow.profiles.list_children_due_for_reenrollment_reminder(
                household_id,
                now,
            )
            await uow.rollback()
        return tuple(profile.id for profile in due)

    async def expire_due_child_templates(
        self, household_id: UUID, now: datetime
    ) -> tuple[UUID, ...]:
        async with self._uow_factory() as uow:
            due = await uow.biometric_templates.list_child_templates_past_hard_expiry(
                household_id,
                now,
            )
            for template in due:
                await uow.profiles.disable_biometric_identity(template.subject_id, now)
                await uow.biometric_templates.expire_template(template.id, now)
            if due:
                await self._audit.append(uow, uow.enrollments.expiry_batch_audit(due, now))
            await uow.commit()
        return tuple(dict.fromkeys(template.subject_id for template in due))

    def _active_uow_or_none(self) -> IdentityUnitOfWork | None:
        try:
            return self._scope.require_active_uow()
        except RuntimeError as exc:
            message = str(exc)
            if (
                "no active atomic mutation scope" in message
                or "mutation scope is not active" in message
            ):
                return None
            raise

    def _require_request_authorization(
        self,
        command: RequestEnrollment,
        auth: AuthContext,
    ) -> None:
        self._require_fresh_owner_passkey(auth, command.action_binding)
        try:
            self._parameters.require(
                command.action_binding,
                action_name="identity.enroll",
                resource_type="identity",
                resource_id=command.subject_id,
                actor_id=auth.subject_id,
                parameters=enrollment_request_parameters(command),
            )
        except PermissionError as exc:
            raise EnrollmentDenied("enrollment_parameter_binding_mismatch") from exc

    def _require_cancel_authorization(
        self,
        command: CancelEnrollment,
        auth: AuthContext,
    ) -> None:
        self._require_fresh_owner_passkey(auth, command.action_binding)
        try:
            self._parameters.require(
                command.action_binding,
                action_name="identity.enrollment.cancel",
                resource_type="identity",
                resource_id=command.enrollment_id,
                actor_id=auth.subject_id,
                parameters=enrollment_cancel_parameters(command),
            )
        except PermissionError as exc:
            raise EnrollmentDenied("enrollment_parameter_binding_mismatch") from exc

    def _require_fresh_owner_passkey(self, auth: AuthContext, binding: ActionBinding) -> None:
        if (
            auth.assurance is not AssuranceLevel.PASSKEY_VERIFIED
            or auth.assurance_source != "passkey"
            or auth.subject_id is None
        ):
            raise EnrollmentDenied("fresh_owner_passkey_required")
        try:
            self._bindings.require_exact(auth.binding, binding)
        except PermissionError as exc:
            raise EnrollmentDenied("fresh_owner_passkey_required") from exc
        age = self._clock.now() - auth.consumed_at
        if age < timedelta(0) or age > timedelta(seconds=_FRESH_OWNER_PASSKEY_SECONDS):
            raise EnrollmentDenied("fresh_owner_passkey_required")

    async def _request_in_active_uow(
        self,
        uow: IdentityUnitOfWork,
        command: RequestEnrollment,
        auth: AuthContext,
    ) -> EnrollmentSession:
        now = self._clock.now()
        assert auth.subject_id is not None
        try:
            await uow.profiles.require_current_owner_guardian_generation(
                command.action_binding.household_id,
                auth.subject_id,
                now,
            )
        except PermissionError as exc:
            raise EnrollmentDenied("fresh_owner_passkey_required") from exc
        try:
            profile = await uow.profiles.get_scoped(
                command.action_binding.household_id,
                command.subject_id,
            )
        except KeyError as exc:
            raise EnrollmentDenied("enrollment_profile_state_changed") from exc
        if (
            not profile.active
            or profile.revoked_at is not None
            or profile.version != command.expected_profile_version
        ):
            raise EnrollmentDenied("enrollment_profile_state_changed")
        try:
            consent = await self._consents.require_current_in_uow(
                uow,
                command.subject_id,
                command.modality.consent_purpose,
                now,
            )
        except ConsentDenied as exc:
            raise EnrollmentDenied("enrollment_consent_state_changed") from exc
        if (
            consent.household_id != profile.household_id
            or consent.id != command.expected_consent_receipt_id
        ):
            raise EnrollmentDenied("enrollment_consent_state_changed")
        session = await uow.enrollments.create(
            command,
            auth,
            household_id=profile.household_id,
            consent_receipt_id=consent.id,
            subject_is_child=profile.profile_class in _CHILD_PROFILE_CLASSES,
            now=now,
            expires_at=now + _ENROLLMENT_SESSION_TTL,
            synthetic_template_id=uuid4(),
        )
        await self._audit.append(uow, uow.enrollments.requested_audit(session, auth))
        return session


class EnrollmentMutationCoordinator:
    def __init__(
        self,
        mutation_scope: MutationScopePort,
        authentication: AuthenticationPort,
        enrollments: EnrollmentService,
    ) -> None:
        self._scope = mutation_scope
        self._auth = authentication
        self._enrollments = enrollments

    @property
    def mutation_scope(self) -> MutationScopePort:
        return self._scope

    async def request(self, command: RequestEnrollment, grant_id: UUID) -> EnrollmentSession:
        return await self._run(command.action_binding, grant_id, self._enrollments.request, command)

    async def cancel(self, command: CancelEnrollment, grant_id: UUID) -> EnrollmentSession:
        async with self._scope.open() as uow:
            auth = await self._auth.consume_in_uow(uow, grant_id, command.action_binding)
            result = await self._enrollments.cancel_in_uow(uow, command, auth)
            await uow.commit()
            return result

    async def _run(
        self,
        binding: ActionBinding,
        grant_id: UUID,
        operation: Callable[[RequestEnrollment, AuthContext], Awaitable[ResultT]],
        command: RequestEnrollment,
    ) -> ResultT:
        async with self._scope.open() as uow:
            auth = await self._auth.consume_in_uow(uow, grant_id, binding)
            result = await operation(command, auth)
            await uow.commit()
            return result
