from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol
from uuid import UUID

from tuntun_contracts.actions import ActionBinding
from tuntun_contracts.audit import AuditDraft
from tuntun_contracts.identity import PersonaProjection, PersonaTraits
from tuntun_contracts.policy import AuthContext
from tuntun_core.domain.profile import (
    GUEST_PERSONA_PROJECTION,
    GUEST_PROJECTION,
    ConsentPurpose,
    CreateProfile,
    Profile,
    ProfileClass,
    ProfileProjection,
    RevokeProfile,
    UpdatePersonaTraits,
)
from tuntun_core.services.actions.parameter_binding import (
    ActionBindingVerifier,
    ActionParameterBindingVerifier,
    profile_create_parameters,
    profile_persona_parameters,
    profile_revoke_parameters,
)
from tuntun_core.services.identity.consent import ConsentDenied
from tuntun_core.services.identity.subject_revocation import SubjectAuthorityRevocationCascade
from tuntun_core.services.transactions.identity_uow import (
    IdentityUnitOfWork,
    IdentityUnitOfWorkFactory,
)

ADULT_PROFILE_CLASSES = frozenset({ProfileClass.OWNER, ProfileClass.ADULT})
CHILD_PROFILE_CLASSES = frozenset({ProfileClass.K2, ProfileClass.N1})
type PersonaRole = Literal["owner", "adult", "k2", "n1", "guest"]

_DEFAULT_PERSONA: dict[ProfileClass, PersonaTraits] = {
    ProfileClass.OWNER: PersonaTraits(
        context="general",
        tone="neutral",
        depth="standard",
        learning_level="none",
    ),
    ProfileClass.ADULT: PersonaTraits(
        context="general",
        tone="neutral",
        depth="standard",
        learning_level="none",
    ),
    ProfileClass.K2: PersonaTraits(
        context="early_learning",
        tone="warm",
        depth="brief",
        learning_level="k2",
    ),
    ProfileClass.N1: PersonaTraits(
        context="early_learning",
        tone="warm",
        depth="brief",
        learning_level="n1",
    ),
}
_PERSONA_ROLES: dict[ProfileClass, PersonaRole] = {
    ProfileClass.OWNER: "owner",
    ProfileClass.ADULT: "adult",
    ProfileClass.K2: "k2",
    ProfileClass.N1: "n1",
    ProfileClass.GUEST: "guest",
}


class StaleProfileVersion(RuntimeError):
    pass


class ClockPort(Protocol):
    def now(self) -> datetime: ...


class MutationScopePort(Protocol):
    def require_active_uow(self) -> IdentityUnitOfWork: ...


class AuditLedgerPort(Protocol):
    async def append(self, uow: IdentityUnitOfWork, draft: AuditDraft) -> None: ...


class ConsentReadPort(Protocol):
    async def require_current_in_uow(
        self,
        uow: IdentityUnitOfWork,
        subject_id: UUID,
        purpose: ConsentPurpose,
        now: datetime,
    ) -> object: ...


class ProfileCryptoPort(Protocol):
    def seal_display_label(
        self,
        household_id: UUID,
        subject_id: UUID,
        profile_version: int,
        display_label: str,
    ) -> bytes: ...

    def seal_traits(
        self,
        household_id: UUID,
        subject_id: UUID,
        profile_version: int,
        traits: PersonaTraits,
    ) -> bytes: ...

    def open_traits(
        self,
        household_id: UUID,
        subject_id: UUID,
        profile_version: int,
        encrypted_persona_traits: bytes,
    ) -> PersonaTraits: ...


def require_fresh_passkey(
    auth: AuthContext,
    binding: ActionBinding,
    now: datetime,
    binding_verifier: ActionBindingVerifier,
    *,
    max_age_seconds: int = 120,
) -> None:
    if auth.assurance_source != "passkey":
        raise PermissionError("passkey_binding_required")
    binding_verifier.require_exact(auth.binding, binding)
    age = now - auth.consumed_at
    if age < timedelta(0) or age > timedelta(seconds=max_age_seconds):
        raise PermissionError("fresh_passkey_required")


class ProfileService:
    def __init__(
        self,
        uow_factory: IdentityUnitOfWorkFactory,
        mutation_scope: MutationScopePort,
        audit_ledger: AuditLedgerPort,
        consent_service: ConsentReadPort,
        subject_revocations: SubjectAuthorityRevocationCascade,
        profile_crypto: ProfileCryptoPort,
        parameter_verifier: ActionParameterBindingVerifier,
        action_binding_verifier: ActionBindingVerifier,
        clock: ClockPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._scope = mutation_scope
        self._audit = audit_ledger
        self._consents = consent_service
        self._subject_revocations = subject_revocations
        self._profile_crypto = profile_crypto
        self._parameters = parameter_verifier
        self._bindings = action_binding_verifier
        self._clock = clock

    async def create(self, command: CreateProfile, auth: AuthContext) -> Profile:
        if command.profile_class not in {ProfileClass.ADULT, ProfileClass.K2, ProfileClass.N1}:
            raise PermissionError("ordinary_profile_create_owner_forbidden")
        now = self._clock.now()
        require_fresh_passkey(auth, command.action_binding, now, self._bindings)
        self._parameters.require(
            command.action_binding,
            action_name="profile.create",
            resource_type="profile",
            resource_id=command.subject_id,
            actor_id=auth.subject_id,
            parameters=profile_create_parameters(command),
        )
        if command.action_binding.household_id != command.household_id:
            raise PermissionError("profile_create_household_mismatch")
        uow = self._scope.require_active_uow()
        if auth.subject_id is None:
            raise PermissionError("current_owner_authority_required")
        guardian_generation = await self._guardian_generation_for_create(
            uow,
            command,
            auth.subject_id,
            now,
        )
        encrypted_display_label = self._profile_crypto.seal_display_label(
            command.household_id,
            command.subject_id,
            1,
            command.display_label,
        )
        profile = Profile(
            id=command.subject_id,
            household_id=command.household_id,
            guardian_id=command.guardian_id,
            guardian_generation=guardian_generation,
            profile_class=command.profile_class,
            encrypted_display_label=encrypted_display_label,
            encrypted_persona_traits=None,
            current_consent_receipt_ids=(),
            active=True,
            authority_generation=1,
            version=1,
            next_reenrollment_reminder_at=None,
            created_at=now,
            updated_at=now,
        )
        await uow.profiles.insert(profile)
        await self._audit.append(uow, uow.profiles.created_audit(profile, auth))
        return profile

    async def create_in_uow(
        self,
        uow: IdentityUnitOfWork,
        command: CreateProfile,
        auth: AuthContext,
    ) -> Profile:
        if self._scope.require_active_uow() is not uow:
            raise RuntimeError("profile_uow_scope_mismatch")
        return await self.create(command, auth)

    async def get_projection(
        self,
        household_id: UUID,
        subject_id: UUID | None,
    ) -> ProfileProjection:
        if subject_id is None:
            return GUEST_PROJECTION
        async with self._uow_factory() as uow:
            profile = await uow.profiles.get_optional_scoped(household_id, subject_id)
            await uow.rollback()
        if profile is None or not profile.active or profile.revoked_at is not None:
            return GUEST_PROJECTION
        return ProfileProjection(
            subject_id=profile.id,
            profile_class=profile.profile_class,
            may_retrieve_private_memory=False,
        )

    async def current_policy_class(
        self,
        household_id: UUID,
        subject_id: UUID | None,
    ) -> ProfileClass:
        async with self._uow_factory() as uow:
            result = await self.current_policy_class_in_uow(uow, household_id, subject_id)
            await uow.rollback()
        return result

    async def current_policy_class_in_uow(
        self,
        uow: IdentityUnitOfWork,
        household_id: UUID,
        subject_id: UUID | None,
    ) -> ProfileClass:
        if subject_id is None:
            return ProfileClass.GUEST
        profile = await uow.profiles.get_optional_scoped(household_id, subject_id)
        if profile is None or not profile.active or profile.revoked_at is not None:
            return ProfileClass.GUEST
        return profile.profile_class

    async def require_current_active_in_uow(
        self,
        uow: IdentityUnitOfWork,
        household_id: UUID,
        subject_id: UUID,
    ) -> Profile:
        profile = await uow.profiles.get_scoped(household_id, subject_id)
        if not profile.active or profile.revoked_at is not None:
            raise PermissionError("current_active_subject_required")
        return profile

    async def get_persona_projection(
        self,
        household_id: UUID,
        subject_id: UUID | None,
        now: datetime,
    ) -> PersonaProjection:
        if subject_id is None:
            return GUEST_PERSONA_PROJECTION
        traits: PersonaTraits | None = None
        async with self._uow_factory() as uow:
            profile = await uow.profiles.get_optional_scoped(household_id, subject_id)
            if profile is not None and profile.active and profile.revoked_at is None:
                try:
                    await self._consents.require_current_in_uow(
                        uow,
                        profile.id,
                        ConsentPurpose.PERSONALIZATION,
                        now,
                    )
                except ConsentDenied:
                    traits = _DEFAULT_PERSONA[profile.profile_class]
                else:
                    traits = (
                        _DEFAULT_PERSONA[profile.profile_class]
                        if profile.encrypted_persona_traits is None
                        else self._profile_crypto.open_traits(
                            profile.household_id,
                            profile.id,
                            profile.version,
                            profile.encrypted_persona_traits,
                        )
                    )
            await uow.rollback()
        if profile is None or not profile.active or profile.revoked_at is not None:
            return GUEST_PERSONA_PROJECTION
        if traits is None:
            raise RuntimeError("persona_traits_projection_unreachable")
        self._require_valid_traits(profile.profile_class, traits)
        return PersonaProjection(role=_PERSONA_ROLES[profile.profile_class], **traits.model_dump())

    async def update_persona_traits(
        self,
        command: UpdatePersonaTraits,
        auth: AuthContext,
    ) -> Profile:
        self._parameters.require(
            command.action_binding,
            action_name="profile.edit",
            resource_type="profile",
            resource_id=command.subject_id,
            actor_id=command.actor_id,
            parameters=profile_persona_parameters(command),
        )
        now = self._clock.now()
        require_fresh_passkey(auth, command.action_binding, now, self._bindings)
        if auth.subject_id != command.actor_id:
            raise PermissionError("authenticated_actor_mismatch")
        uow = self._scope.require_active_uow()
        profile = await uow.profiles.get(command.subject_id)
        if profile.household_id != command.action_binding.household_id:
            raise PermissionError("profile_persona_household_mismatch")
        if profile.profile_class is not command.target_profile_class:
            raise PermissionError("profile_persona_target_class_changed")
        self._require_persona_authority(profile, command)
        if command.traits is not None:
            await self._consents.require_current_in_uow(
                uow,
                profile.id,
                ConsentPurpose.PERSONALIZATION,
                now,
            )
            self._require_valid_traits(profile.profile_class, command.traits)
            encrypted = self._profile_crypto.seal_traits(
                profile.household_id,
                profile.id,
                command.expected_version + 1,
                command.traits,
            )
            operation = "replace"
        else:
            encrypted = None
            operation = "clear"
        try:
            updated = await uow.profiles.update_persona_expected_version(
                profile.id,
                command.expected_version,
                encrypted,
                now,
            )
        except RuntimeError as error:
            if "stale" in str(error).casefold() or "version" in str(error).casefold():
                raise StaleProfileVersion("stale_profile_version") from error
            raise
        await self._audit.append(
            uow,
            uow.profiles.persona_changed_audit(updated, auth, operation=operation),
        )
        return updated

    async def update_persona_traits_in_uow(
        self,
        uow: IdentityUnitOfWork,
        command: UpdatePersonaTraits,
        auth: AuthContext,
    ) -> Profile:
        if self._scope.require_active_uow() is not uow:
            raise RuntimeError("profile_uow_scope_mismatch")
        return await self.update_persona_traits(command, auth)

    async def revoke(self, command: RevokeProfile, auth: AuthContext) -> Profile:
        now = self._clock.now()
        require_fresh_passkey(auth, command.action_binding, now, self._bindings)
        self._parameters.require(
            command.action_binding,
            action_name="profile.revoke",
            resource_type="profile",
            resource_id=command.subject_id,
            actor_id=auth.subject_id,
            parameters=profile_revoke_parameters(command),
        )
        uow = self._scope.require_active_uow()
        current = await uow.profiles.get(command.subject_id)
        if current.household_id != command.action_binding.household_id:
            raise PermissionError("profile_revoke_household_mismatch")
        if not current.active or current.revoked_at is not None:
            raise PermissionError("current_active_subject_required")
        if current.profile_class is ProfileClass.OWNER:
            raise PermissionError("current_owner_replacement_transaction_required")
        if auth.subject_id is None:
            raise PermissionError("profile_revoke_authority_required")
        await self._require_revoke_authority(uow, current, auth.subject_id, now)
        try:
            revoked = await uow.profiles.revoke_and_advance_authority_generation_expected_version(
                command.subject_id,
                command.expected_version,
                current.authority_generation,
                now.astimezone(UTC),
            )
        except RuntimeError as error:
            if "stale" in str(error).casefold() or "version" in str(error).casefold():
                raise StaleProfileVersion("stale_profile_version") from error
            raise
        await self._subject_revocations.apply_in_uow(uow, current, revoked, auth, now)
        await self._audit.append(uow, uow.profiles.revoked_audit(revoked, auth))
        return revoked

    async def revoke_in_uow(
        self,
        uow: IdentityUnitOfWork,
        command: RevokeProfile,
        auth: AuthContext,
    ) -> Profile:
        if self._scope.require_active_uow() is not uow:
            raise RuntimeError("profile_uow_scope_mismatch")
        return await self.revoke(command, auth)

    @staticmethod
    def _require_persona_authority(profile: Profile, command: UpdatePersonaTraits) -> None:
        if profile.profile_class in ADULT_PROFILE_CLASSES:
            if command.actor_id != profile.id or command.guardian_generation is not None:
                raise PermissionError("profile_persona_subject_authority_required")
            return
        if profile.profile_class in CHILD_PROFILE_CLASSES:
            if (
                profile.guardian_id != command.actor_id
                or profile.guardian_generation != command.guardian_generation
            ):
                raise PermissionError("profile_persona_guardian_authority_required")
            return
        raise PermissionError("profile_persona_subject_authority_required")

    @staticmethod
    def _require_valid_traits(profile_class: ProfileClass, traits: PersonaTraits) -> None:
        if profile_class in ADULT_PROFILE_CLASSES:
            if traits.learning_level != "none":
                raise PermissionError("adult_persona_learning_level_invalid")
            return
        expected = profile_class.value
        if not (
            traits.context == "early_learning"
            and traits.tone in {"neutral", "warm"}
            and traits.depth in {"brief", "standard"}
            and traits.learning_level == expected
        ):
            raise PermissionError("child_persona_traits_invalid")

    @staticmethod
    async def _require_revoke_authority(
        uow: IdentityUnitOfWork,
        profile: Profile,
        actor_id: UUID,
        now: datetime,
    ) -> None:
        if profile.profile_class in ADULT_PROFILE_CLASSES:
            if actor_id == profile.id:
                return
            try:
                await uow.profiles.require_current_owner_guardian_generation(
                    profile.household_id,
                    actor_id,
                    now,
                )
            except PermissionError as error:
                raise PermissionError("profile_revoke_authority_required") from error
            return
        if profile.profile_class in CHILD_PROFILE_CLASSES:
            if actor_id != profile.guardian_id:
                raise PermissionError("profile_revoke_authority_required")
            if profile.guardian_id is None:
                raise PermissionError("profile_revoke_authority_required")
            try:
                generation = await uow.profiles.require_current_owner_guardian_generation(
                    profile.household_id,
                    profile.guardian_id,
                    now,
                )
            except PermissionError as error:
                raise PermissionError("profile_revoke_authority_required") from error
            if generation != profile.guardian_generation:
                raise PermissionError("profile_revoke_authority_required")
            return
        raise PermissionError("profile_revoke_authority_required")

    @staticmethod
    async def _guardian_generation_for_create(
        uow: IdentityUnitOfWork,
        command: CreateProfile,
        actor_id: UUID,
        now: datetime,
    ) -> int:
        if command.profile_class in ADULT_PROFILE_CLASSES:
            if command.guardian_id is not None:
                raise PermissionError("adult_profile_guardian_forbidden")
            try:
                await uow.profiles.require_current_owner_guardian_generation(
                    command.household_id,
                    actor_id,
                    now,
                )
            except PermissionError as error:
                raise PermissionError("current_owner_authority_required") from error
            return 0
        if command.profile_class in CHILD_PROFILE_CLASSES:
            if command.guardian_id is None or command.guardian_id != actor_id:
                raise PermissionError("current_owner_guardian_required")
            return await uow.profiles.require_current_owner_guardian_generation(
                command.household_id,
                command.guardian_id,
                now,
            )
        raise PermissionError("ordinary_profile_create_owner_forbidden")
