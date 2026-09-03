from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol
from uuid import UUID

from tuntun_contracts.policy import AuthContext
from tuntun_core.domain.profile import ConsentPurpose, Profile
from tuntun_core.services.providers.route_authorization import (
    _authorization_id_from_runtime_key,
    _consumption_exists,
    _consumption_exists_any_scope,
    _parse_persisted_route_envelope,
)
from tuntun_core.services.storage_time import utc_storage
from tuntun_core.services.transactions.identity_uow import (
    IdentityUnitOfWork,
    SubjectRevocationOutboxPort,
)
from tuntun_core.services.transactions.protocols import UnitOfWorkProtocol

REQUIRED_SUBJECT_AUTHORITY_FAMILIES = (
    "sessions",
    "consents",
    "enrollments",
    "biometric_templates",
    "provider_routes",
    "search_capabilities",
    "action_authorities",
    "memory_authorities",
)


@dataclass(frozen=True, slots=True)
class SubjectRevocationEvent:
    id: UUID
    event_key: str
    subject_id: UUID
    new_authority_generation: int
    state: str
    occurred_at: datetime
    claimed_at: datetime | None = None
    lease_owner: UUID | None = None
    lease_expires_at: datetime | None = None
    fencing_token: int = 0
    completed_at: datetime | None = None
    attempt_count: int = 0
    last_error: str | None = None
    reconciliation_receipt_id: UUID | None = None


class SubjectAuthorityRevocationHandler(Protocol):
    family: str

    async def revoke_in_uow(
        self,
        uow: IdentityUnitOfWork,
        *,
        household_id: UUID,
        subject_id: UUID,
        through_generation: int,
        reason: str,
        now: datetime,
    ) -> None: ...


class CapabilityStagePort(Protocol):
    def require_schema_and_facade_absent(self, family: str, owning_revision: str) -> None: ...

    async def require_schema_and_facade_absent_in_uow(
        self,
        uow: IdentityUnitOfWork,
        family: str,
        owning_revision: str,
    ) -> None: ...


class ProviderRouteRevocationPort(Protocol):
    async def invalidate_subject_purpose_in_uow(
        self,
        uow: IdentityUnitOfWork,
        subject_id: UUID,
        purpose: str,
        now: datetime,
    ) -> tuple[UUID, ...]: ...


class SearchCapabilityRevocationPort(Protocol):
    async def revoke_subject_authorities_in_uow(
        self,
        uow: IdentityUnitOfWork,
        *,
        household_id: UUID,
        subject_id: UUID,
        through_generation: int,
        reason: str,
        now: datetime,
    ) -> None: ...


class NotInstalledSubjectAuthorityHandler:
    _ALLOWED = {"action_authorities": "0003_authentication", "memory_authorities": "0004_memory"}

    def __init__(
        self,
        capability_stage: CapabilityStagePort,
        *,
        family: str,
        owning_revision: str,
    ) -> None:
        if self._ALLOWED.get(family) != owning_revision:
            raise ValueError("closed not-installed authority family required")
        self._stage = capability_stage
        self.family = family
        self.owning_revision = owning_revision

    async def revoke_in_uow(
        self,
        uow: IdentityUnitOfWork,
        *,
        household_id: UUID,
        subject_id: UUID,
        through_generation: int,
        reason: str,
        now: datetime,
    ) -> None:
        del household_id, subject_id, through_generation, reason, now
        await self._stage.require_schema_and_facade_absent_in_uow(
            uow,
            self.family,
            self.owning_revision,
        )


class _SqlFamilyRevocationHandler:
    def __init__(self, family: str) -> None:
        self.family = family

    async def revoke_in_uow(
        self,
        uow: IdentityUnitOfWork,
        *,
        household_id: UUID,
        subject_id: UUID,
        through_generation: int,
        reason: str,
        now: datetime,
    ) -> None:
        del household_id, reason
        await uow.run_sync(
            lambda transaction: (
                transaction.exec_driver_sql(
                    "INSERT OR IGNORE INTO runtime_settings(key,value_json,version,updated_at) "
                    "VALUES(?,?,1,?)",
                    (
                        f"identity.revoked.{self.family}.{subject_id}.{through_generation}",
                        '{"state":"revoked"}',
                        now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    ),
                ).rowcount
            )
        )


class SqlProviderRouteAuthorityRevocation:
    """Invalidate persisted unused cloud route authorizations for a subject."""

    async def invalidate_subject_purpose_in_uow(
        self,
        uow: IdentityUnitOfWork,
        subject_id: UUID,
        purpose: str,
        now: datetime,
    ) -> tuple[UUID, ...]:
        if purpose not in {
            ConsentPurpose.CLOUD_STT.value,
            ConsentPurpose.CLOUD_REASONING.value,
            ConsentPurpose.CLOUD_TTS.value,
        }:
            raise TypeError("purpose must be an exact cloud route purpose")
        del now

        def invalidate(transaction: UnitOfWorkProtocol) -> tuple[UUID, ...]:
            rows = transaction.exec_driver_sql(
                "SELECT key,value_json FROM runtime_settings "
                "WHERE key GLOB 'route.authorization.*' "
                "AND json_type(value_json,'$.route.subject_id')='text' "
                "AND json_extract(value_json,'$.route.subject_id')=? "
                "AND json_type(value_json,'$.route.purpose')='text' "
                "AND json_extract(value_json,'$.route.purpose')=?",
                (str(subject_id), purpose),
            ).fetchall()
            revoked: list[UUID] = []
            for key, raw in rows:
                if type(key) is not str or type(raw) is not str:
                    raise PermissionError("route_authorization_corrupt")
                key_authorization_id = _authorization_id_from_runtime_key(key)
                try:
                    envelope = _parse_persisted_route_envelope(raw)
                except PermissionError:
                    if key_authorization_id is not None and _consumption_exists_any_scope(
                        transaction,
                        key_authorization_id,
                    ):
                        continue
                    deleted = transaction.exec_driver_sql(
                        "DELETE FROM runtime_settings WHERE key=?",
                        (key,),
                    ).rowcount
                    if deleted != 1:
                        raise RuntimeError(
                            "route authorization revocation lost ownership"
                        ) from None
                    if key_authorization_id is not None:
                        revoked.append(key_authorization_id)
                    continue
                route = envelope.route
                if route.subject_id != subject_id or route.purpose != purpose:
                    continue
                if _consumption_exists(
                    transaction,
                    route.household_id,
                    route.authorization_id,
                ):
                    continue
                deleted = transaction.exec_driver_sql(
                    "DELETE FROM runtime_settings WHERE key=?",
                    (key,),
                ).rowcount
                if deleted != 1:
                    raise RuntimeError("route authorization revocation lost ownership")
                revoked.append(route.authorization_id)
            return tuple(revoked)

        return await uow.run_sync(invalidate)


class SessionSubjectAuthorityRevocationHandler(_SqlFamilyRevocationHandler):
    def __init__(self) -> None:
        super().__init__("sessions")

    async def revoke_in_uow(
        self,
        uow: IdentityUnitOfWork,
        *,
        household_id: UUID,
        subject_id: UUID,
        through_generation: int,
        reason: str,
        now: datetime,
    ) -> None:
        del household_id, through_generation
        await uow.sessions.invalidate_identity_subject(subject_id, reason, now)


class ConsentSubjectAuthorityRevocationHandler(_SqlFamilyRevocationHandler):
    def __init__(self) -> None:
        super().__init__("consents")

    async def revoke_in_uow(
        self,
        uow: IdentityUnitOfWork,
        *,
        household_id: UUID,
        subject_id: UUID,
        through_generation: int,
        reason: str,
        now: datetime,
    ) -> None:
        del household_id
        await uow.consent_receipts.revoke_subject_authorities_in_uow(
            subject_id,
            through_generation,
            reason,
            now,
        )


class EnrollmentSubjectAuthorityRevocationHandler(_SqlFamilyRevocationHandler):
    def __init__(self) -> None:
        super().__init__("enrollments")

    async def revoke_in_uow(
        self,
        uow: IdentityUnitOfWork,
        *,
        household_id: UUID,
        subject_id: UUID,
        through_generation: int,
        reason: str,
        now: datetime,
    ) -> None:
        del household_id, through_generation, reason
        await uow.run_sync(
            lambda transaction: (
                transaction.exec_driver_sql(
                    "UPDATE enrollment_sessions SET state='cancelled',closed_at=? "
                    "WHERE subject_id=? AND closed_at IS NULL "
                    "AND state IN ('requested','capturing','calibrating')",
                    (utc_storage(now), str(subject_id)),
                ).rowcount
            )
        )


class BiometricTemplateSubjectAuthorityRevocationHandler(_SqlFamilyRevocationHandler):
    def __init__(self) -> None:
        super().__init__("biometric_templates")

    async def revoke_in_uow(
        self,
        uow: IdentityUnitOfWork,
        *,
        household_id: UUID,
        subject_id: UUID,
        through_generation: int,
        reason: str,
        now: datetime,
    ) -> None:
        del household_id, through_generation, reason
        stored_now = utc_storage(now)
        await uow.run_sync(
            lambda transaction: (
                transaction.exec_driver_sql(
                    "UPDATE biometric_templates SET revoked_at=?,"
                    "expires_at=CASE WHEN expires_at IS NULL OR expires_at>? "
                    "THEN ? ELSE expires_at END "
                    "WHERE subject_id=? AND revoked_at IS NULL",
                    (stored_now, stored_now, stored_now, str(subject_id)),
                ).rowcount
            )
        )


class ProviderRouteSubjectAuthorityRevocationHandler(_SqlFamilyRevocationHandler):
    def __init__(
        self,
        route_authorizations: ProviderRouteRevocationPort | None = None,
    ) -> None:
        super().__init__("provider_routes")
        self._routes = route_authorizations or SqlProviderRouteAuthorityRevocation()

    async def revoke_in_uow(
        self,
        uow: IdentityUnitOfWork,
        *,
        household_id: UUID,
        subject_id: UUID,
        through_generation: int,
        reason: str,
        now: datetime,
    ) -> None:
        del household_id, through_generation, reason
        for purpose in (
            ConsentPurpose.CLOUD_STT,
            ConsentPurpose.CLOUD_REASONING,
            ConsentPurpose.CLOUD_TTS,
        ):
            await self._routes.invalidate_subject_purpose_in_uow(
                uow,
                subject_id,
                purpose.value,
                now,
            )


class SearchCapabilitySubjectAuthorityRevocationHandler(_SqlFamilyRevocationHandler):
    def __init__(
        self,
        capability_stage: CapabilityStagePort | None = None,
        search_capabilities: SearchCapabilityRevocationPort | None = None,
        *,
        feature_state: Literal["absent", "present"] = "absent",
    ) -> None:
        super().__init__("search_capabilities")
        if feature_state == "present" and search_capabilities is None:
            raise RuntimeError("search_capability_revocation_repository_required")
        self._stage = capability_stage
        self._search_capabilities = search_capabilities
        self.feature_state = feature_state

    async def revoke_in_uow(
        self,
        uow: IdentityUnitOfWork,
        *,
        household_id: UUID,
        subject_id: UUID,
        through_generation: int,
        reason: str,
        now: datetime,
    ) -> None:
        if self.feature_state == "absent":
            if self._stage is None:
                raise RuntimeError("search_capability_absent_stage_required")
            await self._stage.require_schema_and_facade_absent_in_uow(
                uow,
                self.family,
                "search_0001_experimental_search",
            )
            return
        if self._search_capabilities is None:
            raise RuntimeError("search_capability_revocation_repository_required")
        await self._search_capabilities.revoke_subject_authorities_in_uow(
            uow,
            household_id=household_id,
            subject_id=subject_id,
            through_generation=through_generation,
            reason=reason,
            now=now,
        )


class SubjectAuthorityRevocationCascade:
    def __init__(
        self,
        handlers: Mapping[str, SubjectAuthorityRevocationHandler],
        outbox: SubjectRevocationOutboxPort,
    ) -> None:
        if set(handlers) != set(REQUIRED_SUBJECT_AUTHORITY_FAMILIES):
            raise RuntimeError("complete_subject_revocation_handlers_required")
        self._handlers = dict(handlers)
        self._outbox = outbox

    @property
    def handlers(self) -> Mapping[str, SubjectAuthorityRevocationHandler]:
        return self._handlers

    async def apply_in_uow(
        self,
        uow: IdentityUnitOfWork,
        current: Profile,
        revoked: Profile,
        auth: AuthContext,
        now: datetime,
    ) -> None:
        del auth
        if revoked.authority_generation != current.authority_generation + 1:
            raise RuntimeError("subject_authority_generation_not_advanced")
        for family in REQUIRED_SUBJECT_AUTHORITY_FAMILIES:
            await self._handlers[family].revoke_in_uow(
                uow,
                household_id=current.household_id,
                subject_id=current.id,
                through_generation=current.authority_generation,
                reason="profile_revoked",
                now=now,
            )
        await self._outbox.enqueue_in_uow(
            uow,
            event_key=f"subject-revoked:{current.id}:{revoked.authority_generation}",
            subject_id=current.id,
            new_authority_generation=revoked.authority_generation,
            occurred_at=now,
        )
        uow.signal_after_commit("subject_revocation")
