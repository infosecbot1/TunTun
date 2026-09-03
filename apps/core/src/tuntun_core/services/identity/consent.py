from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from contextlib import AbstractAsyncContextManager
from datetime import datetime, timedelta
from typing import Literal, Protocol, TypeVar, cast
from uuid import UUID, uuid4

from tuntun_contracts.audit import AuditDraft
from tuntun_contracts.policy import AuthContext
from tuntun_core.domain.profile import (
    ConsentPurpose,
    ConsentReceipt,
    CreateProfile,
    GrantConsent,
    GuestConsentPurpose,
    GuestDisclosureChallenge,
    GuestSessionConsentReceipt,
    Profile,
    RevokeConsent,
    RevokeProfile,
    UpdatePersonaTraits,
)
from tuntun_core.services.actions.parameter_binding import (
    ActionBindingVerifier,
    ActionParameterBindingVerifier,
    consent_parameters,
)
from tuntun_core.services.storage_time import utc_storage
from tuntun_core.services.transactions.identity_uow import (
    IdentityUnitOfWork,
    IdentityUnitOfWorkFactory,
)

ADULT_CONSENT_CLASSES = frozenset({"owner", "adult"})
CHILD_CONSENT_CLASSES = frozenset({"k2", "n1"})
GUEST_SESSION_CONSENT_PURPOSES = frozenset(
    {
        ConsentPurpose.CLOUD_STT.value,
        ConsentPurpose.CLOUD_REASONING.value,
        ConsentPurpose.CLOUD_TTS.value,
    }
)

CommandT = TypeVar(
    "CommandT",
    CreateProfile,
    RevokeProfile,
    UpdatePersonaTraits,
    GrantConsent,
    RevokeConsent,
)
ResultT = TypeVar("ResultT", Profile, ConsentReceipt)


class ConsentDenied(RuntimeError):
    pass


class ClockPort(Protocol):
    def now(self) -> datetime: ...


class MutationScopePort(Protocol):
    def require_active_uow(self) -> IdentityUnitOfWork: ...

    def open(self) -> AbstractAsyncContextManager[IdentityUnitOfWork]: ...


class AuditLedgerPort(Protocol):
    async def append(self, uow: IdentityUnitOfWork, draft: AuditDraft) -> None: ...


class ReceiptSignerPort(Protocol):
    def sign_fields(self, purpose: str, fields: tuple[object, ...]) -> tuple[str, bytes]: ...

    def verify_fields(
        self,
        purpose: str,
        key_id: str,
        fields: tuple[object, ...],
        expected_hmac: bytes,
    ) -> bool: ...


class ConsentRevocationHandlerPort(Protocol):
    async def apply_in_uow(
        self,
        uow: IdentityUnitOfWork,
        receipt: ConsentReceipt,
        auth: AuthContext,
        now: datetime,
    ) -> None: ...


class ConsentRevocationAuditMapperPort(Protocol):
    def revoked(self, event: object, auth: AuthContext) -> AuditDraft: ...


class RouteAuthorizationRevocationPort(Protocol):
    async def invalidate_subject_purpose_in_uow(
        self,
        uow: IdentityUnitOfWork,
        subject_id: UUID,
        purpose: str,
        now: datetime,
    ) -> None: ...


class AuthenticationPort(Protocol):
    async def consume_in_uow(
        self,
        uow: IdentityUnitOfWork,
        grant_id: UUID,
        binding: object,
    ) -> AuthContext: ...


class ProfileMutationServicePort(Protocol):
    async def create(self, command: CreateProfile, auth: AuthContext) -> Profile: ...

    async def revoke(self, command: RevokeProfile, auth: AuthContext) -> Profile: ...

    async def update_persona_traits(
        self,
        command: UpdatePersonaTraits,
        auth: AuthContext,
    ) -> Profile: ...


class ConsentService:
    def __init__(
        self,
        uow_factory: IdentityUnitOfWorkFactory,
        mutation_scope: MutationScopePort,
        audit_ledger: AuditLedgerPort,
        receipt_signer: ReceiptSignerPort,
        parameter_verifier: ActionParameterBindingVerifier,
        action_binding_verifier: ActionBindingVerifier,
        revocation_cascade: ConsentRevocationCascade,
        clock: ClockPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._scope = mutation_scope
        self._audit = audit_ledger
        self._signer = receipt_signer
        self._parameters = parameter_verifier
        self._bindings = action_binding_verifier
        self._revocations = revocation_cascade
        self._clock = clock

    def _require_action_binding(
        self,
        command: GrantConsent | RevokeConsent,
        action_name: Literal["consent.grant", "consent.revoke"],
    ) -> None:
        try:
            self._parameters.require(
                command.action_binding,
                action_name=action_name,
                resource_type="consent",
                resource_id=command.subject_id,
                actor_id=command.actor_id,
                parameters=consent_parameters(command),
            )
        except PermissionError as exc:
            raise ConsentDenied("consent_action_binding_mismatch") from exc

    def _require_passkey(self, command: GrantConsent | RevokeConsent, auth: AuthContext) -> None:
        if auth.assurance_source != "passkey":
            raise ConsentDenied("subject_bound_passkey_required")
        try:
            self._bindings.require_exact(auth.binding, command.action_binding)
        except PermissionError as exc:
            raise ConsentDenied("subject_bound_passkey_required") from exc
        age = self._clock.now() - auth.consumed_at
        if age < timedelta(0) or age > timedelta(seconds=120):
            raise ConsentDenied("fresh_passkey_required")
        if auth.subject_id != command.actor_id:
            raise ConsentDenied("authenticated_actor_mismatch")

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

    async def grant(self, command: GrantConsent, auth: AuthContext) -> ConsentReceipt:
        self._require_action_binding(command, "consent.grant")
        self._require_passkey(command, auth)
        uow = self._active_uow_or_none()
        if uow is not None:
            return await self._grant_in_active_uow(uow, command, auth)
        async with self._scope.open() as opened_uow:
            receipt = await self._grant_in_active_uow(opened_uow, command, auth)
            await opened_uow.commit()
            return receipt

    async def _grant_in_active_uow(
        self,
        uow: IdentityUnitOfWork,
        command: GrantConsent,
        auth: AuthContext,
    ) -> ConsentReceipt:
        subject = await uow.profiles.get(command.subject_id)
        self._require_subject_authority(command, subject)
        latest = await uow.consent_receipts.latest_for_update(command.subject_id, command.purpose)
        latest_id = None if latest is None else latest.id
        if latest_id != command.expected_latest_receipt_id:
            raise ConsentDenied("consent_state_changed")
        now = _receipt_timestamp_after(latest, self._clock.now())
        guardian_id = (
            command.actor_id if subject.profile_class.value in CHILD_CONSENT_CLASSES else None
        )
        guardian_generation = command.guardian_generation if guardian_id is not None else None
        expires_at = (
            now + timedelta(days=365)
            if command.purpose is ConsentPurpose.CHILD_DURABLE_MEMORY
            else None
        )
        fields = _subject_consent_receipt_fields(
            household_id=subject.household_id,
            subject_id=subject.id,
            purpose=command.purpose,
            actor_id=command.actor_id,
            guardian_id=guardian_id,
            guardian_generation=guardian_generation,
            granted=True,
            policy_version=command.policy_version,
            disclosure_version=command.disclosure_version,
            created_at=now,
            expires_at=expires_at,
        )
        key_id, receipt_hmac = self._signer.sign_fields("subject_consent_receipt", fields)
        receipt = uow.consent_receipts.granted_from(
            command,
            household_id=subject.household_id,
            guardian_id=guardian_id,
            guardian_generation=guardian_generation,
            now=now,
            expires_at=expires_at,
            commitment_key_id=key_id,
            receipt_hmac=receipt_hmac,
        )
        await uow.consent_receipts.append_replacing_current(
            receipt,
            expected_latest_receipt_id=latest_id,
            auth=auth,
        )
        await self._audit.append(uow, uow.consent_receipts.audit_draft(receipt, auth))
        return receipt

    async def grant_in_uow(
        self,
        uow: IdentityUnitOfWork,
        command: GrantConsent,
        auth: AuthContext,
    ) -> ConsentReceipt:
        if self._scope.require_active_uow() is not uow:
            raise RuntimeError("consent_uow_scope_mismatch")
        self._require_action_binding(command, "consent.grant")
        self._require_passkey(command, auth)
        return await self._grant_in_active_uow(uow, command, auth)

    async def revoke(self, command: RevokeConsent, auth: AuthContext) -> ConsentReceipt:
        self._require_action_binding(command, "consent.revoke")
        self._require_passkey(command, auth)
        uow = self._active_uow_or_none()
        if uow is not None:
            return await self._revoke_in_active_uow(uow, command, auth)
        async with self._scope.open() as opened_uow:
            receipt = await self._revoke_in_active_uow(opened_uow, command, auth)
            await opened_uow.commit()
            return receipt

    async def _revoke_in_active_uow(
        self,
        uow: IdentityUnitOfWork,
        command: RevokeConsent,
        auth: AuthContext,
    ) -> ConsentReceipt:
        subject = await uow.profiles.get(command.subject_id)
        self._require_subject_authority(command, subject)
        current = await uow.consent_receipts.latest_for_update(
            command.subject_id,
            command.purpose,
        )
        now = _receipt_timestamp_after(current, self._clock.now())
        if (
            current is None
            or not current.granted
            or current.created_at > now
            or (current.expires_at is not None and current.expires_at <= now)
        ):
            raise ConsentDenied("current_consent_required")
        if (
            current.id != command.expected_latest_receipt_id
            or current.policy_version != command.policy_version
            or current.disclosure_version != command.disclosure_version
        ):
            raise ConsentDenied("consent_state_changed")
        if current.actor_id != command.actor_id and current.guardian_id != command.actor_id:
            raise ConsentDenied("consent_revoker_mismatch")
        guardian_id = (
            command.actor_id if subject.profile_class.value in CHILD_CONSENT_CLASSES else None
        )
        guardian_generation = command.guardian_generation if guardian_id is not None else None
        fields = _subject_consent_receipt_fields(
            household_id=current.household_id,
            subject_id=current.subject_id,
            purpose=current.purpose,
            actor_id=command.actor_id,
            guardian_id=guardian_id,
            guardian_generation=guardian_generation,
            granted=False,
            policy_version=current.policy_version,
            disclosure_version=current.disclosure_version,
            created_at=now,
            expires_at=now,
        )
        key_id, receipt_hmac = self._signer.sign_fields("subject_consent_receipt", fields)
        receipt = uow.consent_receipts.revoked_from(
            current,
            command.actor_id,
            guardian_id=guardian_id,
            guardian_generation=guardian_generation,
            now=now,
            expires_at=now,
            commitment_key_id=key_id,
            receipt_hmac=receipt_hmac,
        )
        await uow.consent_receipts.append_replacing_current(
            receipt,
            expected_latest_receipt_id=current.id,
            auth=auth,
        )
        await self._revocations.apply_in_uow(uow, receipt, auth, now)
        await self._audit.append(uow, uow.consent_receipts.audit_draft(receipt, auth))
        return receipt

    async def revoke_in_uow(
        self,
        uow: IdentityUnitOfWork,
        command: RevokeConsent,
        auth: AuthContext,
    ) -> ConsentReceipt:
        if self._scope.require_active_uow() is not uow:
            raise RuntimeError("consent_uow_scope_mismatch")
        self._require_action_binding(command, "consent.revoke")
        self._require_passkey(command, auth)
        return await self._revoke_in_active_uow(uow, command, auth)

    async def require_current(
        self,
        subject_id: UUID,
        purpose: ConsentPurpose,
        now: datetime,
    ) -> ConsentReceipt:
        async with self._uow_factory() as uow:
            receipt = await self.require_current_in_uow(uow, subject_id, purpose, now)
            await uow.rollback()
        return receipt

    async def require_current_in_uow(
        self,
        uow: IdentityUnitOfWork,
        subject_id: UUID,
        purpose: ConsentPurpose,
        now: datetime,
    ) -> ConsentReceipt:
        subject = await uow.profiles.get(subject_id)
        if not subject.active or subject.revoked_at is not None:
            raise ConsentDenied("current_active_subject_required")
        if (
            purpose is ConsentPurpose.WEB_SEARCH
            and subject.profile_class.value not in ADULT_CONSENT_CLASSES
        ):
            raise ConsentDenied("web_search_adult_self_consent_required")
        if (
            purpose is ConsentPurpose.CHILD_DURABLE_MEMORY
            and subject.profile_class.value not in CHILD_CONSENT_CLASSES
        ):
            raise ConsentDenied("child_durable_memory_guardian_consent_required")
        receipt = await uow.consent_receipts.latest(subject_id, purpose)
        if (
            receipt is None
            or not receipt.granted
            or receipt.created_at > now
            or (receipt.expires_at is not None and receipt.expires_at <= now)
        ):
            raise ConsentDenied("current_consent_required")
        fields = _subject_consent_receipt_fields(
            household_id=subject.household_id,
            subject_id=subject.id,
            purpose=purpose,
            actor_id=receipt.actor_id,
            guardian_id=receipt.guardian_id,
            guardian_generation=receipt.guardian_generation,
            granted=receipt.granted,
            policy_version=receipt.policy_version,
            disclosure_version=receipt.disclosure_version,
            created_at=receipt.created_at,
            expires_at=receipt.expires_at,
        )
        if receipt.household_id != subject.household_id or not self._signer.verify_fields(
            "subject_consent_receipt",
            receipt.commitment_key_id,
            fields,
            receipt.receipt_hmac,
        ):
            raise ConsentDenied("consent_receipt_hmac_invalid")
        if subject.profile_class.value in ADULT_CONSENT_CLASSES and (
            receipt.actor_id != subject.id
            or receipt.guardian_id is not None
            or receipt.guardian_generation is not None
        ):
            if purpose is ConsentPurpose.WEB_SEARCH:
                raise ConsentDenied("web_search_adult_self_receipt_required")
            raise ConsentDenied("adult_self_consent_receipt_required")
        if purpose is ConsentPurpose.WEB_SEARCH and (
            receipt.actor_id != subject.id
            or receipt.guardian_id is not None
            or receipt.guardian_generation is not None
        ):
            raise ConsentDenied("web_search_adult_self_receipt_required")
        if purpose is ConsentPurpose.CHILD_DURABLE_MEMORY and (
            receipt.actor_id != subject.guardian_id
            or receipt.guardian_id != subject.guardian_id
            or receipt.guardian_generation != subject.guardian_generation
        ):
            raise ConsentDenied("current_primary_guardian_consent_required")
        if subject.profile_class.value in CHILD_CONSENT_CLASSES and (
            receipt.guardian_id != subject.guardian_id
            or receipt.guardian_generation != subject.guardian_generation
        ):
            raise ConsentDenied("current_primary_guardian_consent_required")
        return receipt

    async def require_current_hmac_valid(
        self,
        household_id: UUID,
        subject_id: UUID,
        purpose: ConsentPurpose,
        now: datetime,
    ) -> ConsentReceipt:
        async with self._uow_factory() as uow:
            receipt = await self.require_current_in_uow(uow, subject_id, purpose, now)
            await uow.rollback()
        if receipt.household_id != household_id:
            raise ConsentDenied("consent_household_mismatch")
        return receipt

    async def is_current(
        self,
        subject_id: UUID,
        purpose: ConsentPurpose,
        now: datetime,
    ) -> bool:
        try:
            await self.require_current(subject_id, purpose, now)
        except ConsentDenied:
            return False
        return True

    async def verify_receipt(self, receipt: ConsentReceipt) -> ConsentReceipt:
        fields = _subject_consent_receipt_fields(
            household_id=receipt.household_id,
            subject_id=receipt.subject_id,
            purpose=receipt.purpose,
            actor_id=receipt.actor_id,
            guardian_id=receipt.guardian_id,
            guardian_generation=receipt.guardian_generation,
            granted=receipt.granted,
            policy_version=receipt.policy_version,
            disclosure_version=receipt.disclosure_version,
            created_at=receipt.created_at,
            expires_at=receipt.expires_at,
        )
        if not self._signer.verify_fields(
            "subject_consent_receipt",
            receipt.commitment_key_id,
            fields,
            receipt.receipt_hmac,
        ):
            raise ConsentDenied("consent_receipt_hmac_invalid")
        if receipt.purpose is ConsentPurpose.WEB_SEARCH and (
            receipt.actor_id != receipt.subject_id
            or receipt.guardian_id is not None
            or receipt.guardian_generation is not None
        ):
            raise ConsentDenied("web_search_adult_self_receipt_required")
        if (
            receipt.actor_id != receipt.subject_id
            and receipt.guardian_id is None
            and receipt.guardian_generation is None
        ):
            raise ConsentDenied("adult_self_consent_receipt_required")
        if receipt.guardian_id is not None or receipt.guardian_generation is not None:
            raise ConsentDenied("current_primary_guardian_receipt_state_required")
        return receipt

    def _require_subject_authority(
        self, command: GrantConsent | RevokeConsent, subject: Profile
    ) -> None:
        if not subject.active or subject.revoked_at is not None:
            raise ConsentDenied("current_active_subject_required")
        if subject.household_id != command.action_binding.household_id:
            raise ConsentDenied("consent_household_mismatch")
        profile_class = subject.profile_class.value
        if command.purpose is ConsentPurpose.WEB_SEARCH and (
            profile_class not in ADULT_CONSENT_CLASSES or command.actor_id != subject.id
        ):
            raise ConsentDenied("web_search_adult_self_consent_required")
        if (
            command.purpose is ConsentPurpose.CHILD_DURABLE_MEMORY
            and profile_class not in CHILD_CONSENT_CLASSES
        ):
            raise ConsentDenied("child_durable_memory_guardian_consent_required")
        if profile_class in ADULT_CONSENT_CLASSES:
            if command.actor_id != subject.id or command.guardian_generation is not None:
                raise ConsentDenied("adult_self_consent_required")
            return
        if profile_class in CHILD_CONSENT_CLASSES:
            if (
                subject.guardian_id != command.actor_id
                or subject.guardian_generation != command.guardian_generation
            ):
                raise ConsentDenied("current_primary_guardian_required")
            return
        raise ConsentDenied("current_active_subject_required")


class CloudRouteConsentRevocationHandler:
    def __init__(self, route_authorizations: RouteAuthorizationRevocationPort) -> None:
        self._routes = route_authorizations

    async def apply_in_uow(
        self,
        uow: IdentityUnitOfWork,
        receipt: ConsentReceipt,
        auth: AuthContext,
        now: datetime,
    ) -> None:
        del auth
        await self._routes.invalidate_subject_purpose_in_uow(
            uow,
            receipt.subject_id,
            receipt.purpose.value,
            now,
        )


class BiometricConsentRevocationHandler:
    """Close live biometric authority for FACE/VOICE consent revocation."""

    _MODALITIES = {
        ConsentPurpose.FACE: "face",
        ConsentPurpose.VOICE: "voice",
    }

    async def apply_in_uow(
        self,
        uow: IdentityUnitOfWork,
        receipt: ConsentReceipt,
        auth: AuthContext,
        now: datetime,
    ) -> None:
        del auth
        modality = self._MODALITIES.get(receipt.purpose)
        if modality is None:
            raise RuntimeError("biometric_consent_revocation_purpose_mismatch")
        await uow.sessions.invalidate_identity_subject(
            receipt.subject_id,
            f"{modality}_consent_revoked",
            now,
        )
        stored_now = utc_storage(now)
        await uow.run_sync(
            lambda transaction: (
                transaction.exec_driver_sql(
                    "UPDATE enrollment_sessions SET state='cancelled',closed_at=? "
                    "WHERE subject_id=? AND modality=? AND closed_at IS NULL "
                    "AND state IN ('requested','capturing','calibrating')",
                    (stored_now, str(receipt.subject_id), modality),
                ).rowcount,
                transaction.exec_driver_sql(
                    "UPDATE biometric_templates SET revoked_at=?,"
                    "expires_at=CASE WHEN expires_at IS NULL OR expires_at>? "
                    "THEN ? ELSE expires_at END "
                    "WHERE subject_id=? AND modality=? AND revoked_at IS NULL",
                    (
                        stored_now,
                        stored_now,
                        stored_now,
                        str(receipt.subject_id),
                        modality,
                    ),
                ).rowcount,
            )
        )


class ConsentRevocationCascade:
    def __init__(
        self,
        handlers: Mapping[ConsentPurpose, ConsentRevocationHandlerPort],
        audit_mapper: ConsentRevocationAuditMapperPort,
        audit_ledger: AuditLedgerPort,
    ) -> None:
        self._handlers = dict(handlers)
        self._audit_mapper = audit_mapper
        self._audit = audit_ledger

    async def apply_in_uow(
        self,
        uow: IdentityUnitOfWork,
        receipt: ConsentReceipt,
        auth: AuthContext,
        now: datetime,
    ) -> None:
        handler = self._handlers.get(receipt.purpose)
        if handler is not None:
            await handler.apply_in_uow(uow, receipt, auth, now)
        event = uow.consent_receipts.identity_consent_revoked_event(receipt, now)
        await self._audit.append(uow, self._audit_mapper.revoked(event, auth))


class GuestSessionConsentService:
    def __init__(
        self,
        uow_factory: IdentityUnitOfWorkFactory,
        audit_ledger: AuditLedgerPort,
        receipt_signer: ReceiptSignerPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._audit = audit_ledger
        self._signer = receipt_signer

    async def issue_challenge(
        self,
        household_id: UUID,
        session_id: UUID,
        purpose: ConsentPurpose | GuestConsentPurpose,
        disclosure_version: str,
        presentation_receipt_id: UUID,
        now: datetime,
    ) -> GuestDisclosureChallenge:
        guest_purpose = _require_guest_purpose(purpose)
        async with self._uow_factory() as uow:
            session = await uow.sessions.lock_active(household_id, session_id, now)
            await uow.event_receipts.require_exact_guest_disclosure(
                presentation_receipt_id,
                household_id=household_id,
                session_id=session_id,
                purpose=guest_purpose,
                disclosure_version=disclosure_version,
                now=now,
            )
            challenge_id = uuid4()
            expires_at = min(session.expires_at, now + timedelta(minutes=2))
            fields = (
                challenge_id,
                household_id,
                session_id,
                guest_purpose,
                disclosure_version,
                presentation_receipt_id,
                now,
                expires_at,
            )
            key_id, challenge_hmac = self._signer.sign_fields("guest_disclosure_challenge", fields)
            challenge = await uow.guest_disclosure_challenges.create(
                challenge_id,
                household_id,
                session_id,
                guest_purpose,
                disclosure_version,
                presentation_receipt_id,
                now,
                expires_at,
                key_id,
                challenge_hmac,
            )
            if hasattr(challenge, "started_audit"):
                await self._audit.append(uow, challenge.started_audit())
            await uow.commit()
        return challenge

    async def accept_challenge(
        self,
        challenge_id: UUID,
        response: str,
        now: datetime,
    ) -> GuestSessionConsentReceipt:
        async with self._uow_factory() as uow:
            challenge = await uow.guest_disclosure_challenges.lock_open(challenge_id, now)
            if challenge.issued_at > now or challenge.expires_at <= now:
                raise ConsentDenied("active_guest_disclosure_challenge_required")
            challenge_fields = (
                challenge.id,
                challenge.household_id,
                challenge.session_id,
                challenge.purpose,
                challenge.disclosure_version,
                challenge.presentation_receipt_id,
                challenge.issued_at,
                challenge.expires_at,
            )
            if not self._signer.verify_fields(
                "guest_disclosure_challenge",
                challenge.commitment_key_id,
                challenge_fields,
                challenge.challenge_hmac,
            ):
                raise ConsentDenied("active_guest_disclosure_challenge_required")
            if response not in {"yes", "haan", "हाँ"}:
                await uow.guest_disclosure_challenges.consume_denied(challenge.id, now)
                if hasattr(challenge, "denied_audit"):
                    await self._audit.append(uow, challenge.denied_audit(now))
                await uow.commit()
                raise ConsentDenied("guest_disclosure_declined")
            session = await uow.sessions.lock_active(
                challenge.household_id,
                challenge.session_id,
                now,
            )
            if (
                challenge.expires_at > session.expires_at
                or challenge.purpose not in GUEST_SESSION_CONSENT_PURPOSES
            ):
                raise ConsentDenied("active_guest_disclosure_challenge_required")
            expires_at = session.expires_at
            fields = (
                challenge.household_id,
                challenge.session_id,
                challenge.id,
                challenge.presentation_receipt_id,
                challenge.purpose,
                challenge.disclosure_version,
                True,
                now,
                expires_at,
                None,
            )
            key_id, receipt_hmac = self._signer.sign_fields(
                "guest_session_consent_receipt",
                fields,
            )
            await uow.guest_disclosure_challenges.consume_accepted(challenge.id, now)
            receipt = await uow.guest_session_consents.append(
                challenge.household_id,
                challenge.session_id,
                challenge.id,
                challenge.presentation_receipt_id,
                challenge.purpose,
                challenge.disclosure_version,
                True,
                now,
                expires_at,
                None,
                key_id,
                receipt_hmac,
            )
            await self._audit.append(
                uow,
                uow.guest_session_consents.granted_audit(receipt, challenge.id),
            )
            await uow.commit()
        return receipt

    async def revoke(
        self,
        household_id: UUID,
        session_id: UUID,
        purpose: ConsentPurpose | GuestConsentPurpose,
        now: datetime,
    ) -> GuestSessionConsentReceipt:
        guest_purpose = _require_guest_purpose(purpose)
        async with self._uow_factory() as uow:
            current = await uow.guest_session_consents.lock_current(
                household_id,
                session_id,
                guest_purpose,
                now,
            )
            fields = (
                household_id,
                session_id,
                current.challenge_id,
                current.presentation_receipt_id,
                guest_purpose,
                current.disclosure_version,
                False,
                now,
                current.expires_at,
                now,
            )
            key_id, receipt_hmac = self._signer.sign_fields(
                "guest_session_consent_receipt",
                fields,
            )
            revoked = await uow.guest_session_consents.append(
                household_id,
                session_id,
                current.challenge_id,
                current.presentation_receipt_id,
                guest_purpose,
                current.disclosure_version,
                False,
                now,
                current.expires_at,
                now,
                key_id,
                receipt_hmac,
            )
            await self._audit.append(uow, uow.guest_session_consents.revoked_audit(revoked))
            await uow.commit()
        return revoked

    async def require_current(
        self,
        household_id: UUID,
        session_id: UUID,
        purpose: ConsentPurpose | GuestConsentPurpose,
        now: datetime,
    ) -> GuestSessionConsentReceipt:
        guest_purpose = _require_guest_purpose(purpose)
        async with self._uow_factory() as uow:
            session = await uow.sessions.require_active(household_id, session_id, now)
            receipt = await uow.guest_session_consents.latest(
                household_id,
                session_id,
                guest_purpose,
            )
            await uow.rollback()
        if (
            receipt is None
            or not receipt.granted
            or receipt.revoked_at is not None
            or receipt.issued_at > now
            or receipt.expires_at <= now
            or receipt.expires_at > session.expires_at
        ):
            raise ConsentDenied("current_guest_session_consent_required")
        fields = (
            household_id,
            session_id,
            receipt.challenge_id,
            receipt.presentation_receipt_id,
            guest_purpose,
            receipt.disclosure_version,
            receipt.granted,
            receipt.issued_at,
            receipt.expires_at,
            receipt.revoked_at,
        )
        if not self._signer.verify_fields(
            "guest_session_consent_receipt",
            receipt.commitment_key_id,
            fields,
            receipt.receipt_hmac,
        ):
            raise ConsentDenied("guest_consent_receipt_hmac_invalid")
        return receipt

    async def require_current_hmac_valid(
        self,
        household_id: UUID,
        session_id: UUID,
        purpose: ConsentPurpose | GuestConsentPurpose,
        now: datetime,
    ) -> GuestSessionConsentReceipt:
        return await self.require_current(household_id, session_id, purpose, now)


class IdentityMutationCoordinator:
    def __init__(
        self,
        mutation_scope: MutationScopePort,
        authentication: AuthenticationPort,
        profiles: ProfileMutationServicePort,
        consents: ConsentService,
    ) -> None:
        self._scope = mutation_scope
        self._auth = authentication
        self._profiles = profiles
        self._consents = consents

    async def create_profile(self, command: CreateProfile, grant_id: UUID) -> Profile:
        return await self._run(command.action_binding, grant_id, self._profiles.create, command)

    async def revoke_profile(self, command: RevokeProfile, grant_id: UUID) -> Profile:
        return await self._run(command.action_binding, grant_id, self._profiles.revoke, command)

    async def update_persona_traits(
        self,
        command: UpdatePersonaTraits,
        grant_id: UUID,
    ) -> Profile:
        return await self._run(
            command.action_binding,
            grant_id,
            self._profiles.update_persona_traits,
            command,
        )

    async def grant_consent(self, command: GrantConsent, grant_id: UUID) -> ConsentReceipt:
        return await self._run(command.action_binding, grant_id, self._consents.grant, command)

    async def revoke_consent(self, command: RevokeConsent, grant_id: UUID) -> ConsentReceipt:
        return await self._run(command.action_binding, grant_id, self._consents.revoke, command)

    async def _run(
        self,
        binding: object,
        grant_id: UUID,
        operation: Callable[[CommandT, AuthContext], Awaitable[ResultT]],
        command: CommandT,
    ) -> ResultT:
        async with self._scope.open() as uow:
            auth = await self._auth.consume_in_uow(uow, grant_id, binding)
            result = await operation(command, auth)
            await uow.commit()
            return result


def _subject_consent_receipt_fields(
    *,
    household_id: UUID,
    subject_id: UUID,
    purpose: ConsentPurpose,
    actor_id: UUID,
    guardian_id: UUID | None,
    guardian_generation: int | None,
    granted: bool,
    policy_version: str,
    disclosure_version: str,
    created_at: datetime,
    expires_at: datetime | None,
) -> tuple[object, ...]:
    return (
        household_id,
        subject_id,
        purpose,
        actor_id,
        guardian_id,
        guardian_generation,
        granted,
        policy_version,
        disclosure_version,
        created_at,
        expires_at,
    )


def _receipt_timestamp_after(
    latest: ConsentReceipt | None,
    candidate: datetime,
) -> datetime:
    if latest is None or candidate > latest.created_at:
        return candidate
    return latest.created_at + timedelta(microseconds=1)


def _require_guest_purpose(purpose: ConsentPurpose | GuestConsentPurpose) -> GuestConsentPurpose:
    value = purpose.value if isinstance(purpose, ConsentPurpose) else purpose
    if value not in GUEST_SESSION_CONSENT_PURPOSES:
        raise ConsentDenied("guest_disclosure_purpose_denied")
    return cast(GuestConsentPurpose, value)
