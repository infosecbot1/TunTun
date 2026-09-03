from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal, Protocol, cast
from uuid import UUID, uuid4, uuid5

from tuntun_contracts.actions import ActionBinding
from tuntun_contracts.audit import AuditDraft
from tuntun_contracts.base import Commitment
from tuntun_contracts.policy import AssuranceLevel, AuthContext
from tuntun_core.adapters.sqlcipher.subject_revocation_effect_repository import (
    DownstreamEffectReceipt,
    SubjectRevocationEffectUnitOfWorkFacade,
)
from tuntun_core.adapters.sqlcipher.subject_revocation_outbox_repository import (
    SubjectRevocationOutboxUnitOfWorkFacade,
)
from tuntun_core.domain.profile import (
    BiometricTemplate,
    ConsentPurpose,
    ConsentReceipt,
    EnrollmentSession,
    GrantConsent,
    GuestConsentPurpose,
    GuestDisclosureChallenge,
    GuestSessionConsentReceipt,
    Modality,
    Profile,
    ProfileClass,
    RequestEnrollment,
)
from tuntun_core.services.identity.consent import ConsentDenied
from tuntun_core.services.providers.route_authorization import (
    _parse_persisted_route_envelope,
)
from tuntun_core.services.storage_time import parse_utc_storage, utc_storage
from tuntun_core.services.transactions.identity_uow import IdentityUnitOfWorkFactory
from tuntun_core.services.transactions.protocols import AsyncUnitOfWorkProtocol, UnitOfWorkProtocol

_GUEST_SESSION_SECONDS = 30 * 60
_MAX_PROFILE_DISPLAY_LABEL_BYTES = 1024
_MAX_PROFILE_PERSONA_TRAITS_BYTES = 4096
_MAX_CURRENT_CONSENT_RECEIPT_IDS_BYTES = 512
_HMAC_DIGEST_BYTES = 32
_GUEST_DISCLOSURE_PRESENTATION_PREFIX = "guest_disclosure_presentation"
ClockCallable = Callable[[], datetime]
GuestChallengeState = Literal["open", "accepted", "denied"]


class _RowMappingSource(Protocol):
    @property
    def _mapping(self) -> Mapping[str, object]: ...


class _FacadeFactory:
    def __init__(self, factory: Callable[[AsyncUnitOfWorkProtocol], object]) -> None:
        self._factory = factory

    def bind(self, uow: object) -> object:
        return self._factory(cast(AsyncUnitOfWorkProtocol, uow))


class AuditCommitmentPort(Protocol):
    def commit_private(self, purpose: str, payload: bytes) -> Commitment: ...


def task1_identity_repository_facades(
    clock: ClockCallable,
    audit_commitments: AuditCommitmentPort,
) -> Mapping[str, _FacadeFactory]:
    return {
        "profiles": _FacadeFactory(lambda uow: SqlProfileRepository(uow, audit_commitments)),
        "consent_receipts": _FacadeFactory(
            lambda uow: SqlConsentReceiptRepository(uow, audit_commitments)
        ),
        "enrollments": _FacadeFactory(lambda uow: SqlEnrollmentRepository(uow, audit_commitments)),
        "biometric_templates": _FacadeFactory(
            lambda uow: SqlBiometricTemplateRepository(uow, audit_commitments)
        ),
        "guest_disclosure_challenges": _FacadeFactory(SqlGuestDisclosureChallengeRepository),
        "guest_session_consents": _FacadeFactory(
            lambda uow: SqlGuestSessionConsentRepository(uow, audit_commitments)
        ),
        "sessions": _FacadeFactory(SqlSessionIdentityRepository),
        "event_receipts": _FacadeFactory(SqlEventReceiptRepository),
        "subject_revocation_outbox": _FacadeFactory(SubjectRevocationOutboxUnitOfWorkFacade),
        "subject_revocation_effects": _FacadeFactory(SubjectRevocationEffectUnitOfWorkFacade),
        "provider_calls": _FacadeFactory(
            lambda uow: SqlProviderCallsRevocationRepository(uow, clock)
        ),
        "budget_reservations": _FacadeFactory(
            lambda uow: SqlBudgetReservationsRevocationRepository(uow, clock)
        ),
    }


def _row_to_dict(row: object | None) -> dict[str, object] | None:
    if row is None:
        return None
    return dict(cast(_RowMappingSource, row)._mapping)


def _bool_int(value: object) -> bool:
    return int(str(value)) == 1


def _receipt_ids_blob(values: tuple[UUID, ...]) -> bytes:
    return json.dumps([str(value) for value in values], separators=(",", ":")).encode("ascii")


def _blob(value: object, reason: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    raise ValueError(reason)


def _bounded_blob(value: object, reason: str, *, min_bytes: int, max_bytes: int) -> bytes:
    raw = _blob(value, reason)
    if not min_bytes <= len(raw) <= max_bytes:
        raise ValueError(reason)
    return raw


def _exact_blob(value: object, reason: str, *, expected_bytes: int) -> bytes:
    raw = _blob(value, reason)
    if len(raw) != expected_bytes:
        raise ValueError(reason)
    return raw


def _uuid_field(value: object, reason: str) -> UUID:
    if type(value) is not str or len(value) != 36:
        raise ValueError(reason)
    try:
        return UUID(value)
    except ValueError:
        raise ValueError(reason) from None


def _optional_uuid_field(value: object, reason: str) -> UUID | None:
    return None if value is None else _uuid_field(value, reason)


def _receipt_ids_from_blob(value: object) -> tuple[UUID, ...]:
    raw = _bounded_blob(
        value,
        "current consent receipt ids corrupt",
        min_bytes=2,
        max_bytes=_MAX_CURRENT_CONSENT_RECEIPT_IDS_BYTES,
    )
    try:
        parsed = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("current consent receipt ids corrupt") from None
    if not isinstance(parsed, list) or not all(type(item) is str for item in parsed):
        raise ValueError("current consent receipt ids corrupt")
    if len(parsed) > 8 or any(len(item) != 36 for item in parsed):
        raise ValueError("current consent receipt ids corrupt")
    try:
        return tuple(UUID(item) for item in parsed)
    except ValueError:
        raise ValueError("current consent receipt ids corrupt") from None


def _optional_time(value: object) -> datetime | None:
    return None if value is None else parse_utc_storage(str(value))


def _profile_from_row(row: Mapping[str, object]) -> Profile:
    return Profile(
        id=_uuid_field(row["id"], "profile id corrupt"),
        household_id=_uuid_field(row["household_id"], "profile household id corrupt"),
        guardian_id=_optional_uuid_field(row["guardian_id"], "profile guardian id corrupt"),
        guardian_generation=int(str(row["guardian_generation"])),
        profile_class=ProfileClass(str(row["profile_class"])),
        encrypted_display_label=_bounded_blob(
            row["encrypted_display_label"],
            "profile display label corrupt",
            min_bytes=1,
            max_bytes=_MAX_PROFILE_DISPLAY_LABEL_BYTES,
        ),
        encrypted_persona_traits=(
            None
            if row["encrypted_persona_traits"] is None
            else _bounded_blob(
                row["encrypted_persona_traits"],
                "profile persona traits corrupt",
                min_bytes=1,
                max_bytes=_MAX_PROFILE_PERSONA_TRAITS_BYTES,
            )
        ),
        current_consent_receipt_ids=_receipt_ids_from_blob(row["current_consent_receipt_ids"]),
        active=_bool_int(row["active"]),
        authority_generation=int(str(row["authority_generation"])),
        version=int(str(row["version"])),
        next_reenrollment_reminder_at=_optional_time(row["next_reenrollment_reminder_at"]),
        created_at=parse_utc_storage(str(row["created_at"])),
        updated_at=parse_utc_storage(str(row["updated_at"])),
        revoked_at=_optional_time(row["revoked_at"]),
    )


def _consent_from_row(row: Mapping[str, object]) -> ConsentReceipt:
    return ConsentReceipt(
        id=_uuid_field(row["id"], "consent receipt id corrupt"),
        household_id=_uuid_field(row["household_id"], "consent receipt household id corrupt"),
        subject_id=_uuid_field(row["subject_id"], "consent receipt subject id corrupt"),
        actor_id=_uuid_field(row["actor_id"], "consent receipt actor id corrupt"),
        guardian_id=_optional_uuid_field(row["guardian_id"], "consent receipt guardian id corrupt"),
        guardian_generation=(
            None if row["guardian_generation"] is None else int(str(row["guardian_generation"]))
        ),
        purpose=ConsentPurpose(str(row["purpose"])),
        granted=_bool_int(row["granted"]),
        policy_version=str(row["policy_version"]),
        disclosure_version=str(row["disclosure_version"]),
        commitment_key_id=str(row["commitment_key_id"]),
        receipt_hmac=_exact_blob(
            row["receipt_hmac"],
            "consent receipt hmac corrupt",
            expected_bytes=_HMAC_DIGEST_BYTES,
        ),
        created_at=parse_utc_storage(str(row["created_at"])),
        expires_at=_optional_time(row["expires_at"]),
    )


def _guest_challenge_from_row(row: Mapping[str, object]) -> GuestDisclosureChallenge:
    return GuestDisclosureChallenge(
        id=_uuid_field(row["id"], "guest challenge id corrupt"),
        household_id=_uuid_field(row["household_id"], "guest challenge household id corrupt"),
        session_id=_uuid_field(row["session_id"], "guest challenge session id corrupt"),
        purpose=cast(GuestConsentPurpose, str(row["purpose"])),
        disclosure_version=str(row["disclosure_version"]),
        state=cast(GuestChallengeState, str(row["state"])),
        issued_at=parse_utc_storage(str(row["issued_at"])),
        expires_at=parse_utc_storage(str(row["expires_at"])),
        consumed_at=_optional_time(row["consumed_at"]),
        presentation_receipt_id=_uuid_field(
            row["presentation_receipt_id"],
            "guest challenge presentation receipt id corrupt",
        ),
        commitment_key_id=str(row["commitment_key_id"]),
        challenge_hmac=_exact_blob(
            row["challenge_hmac"],
            "guest challenge hmac corrupt",
            expected_bytes=_HMAC_DIGEST_BYTES,
        ),
    )


def _guest_receipt_from_row(row: Mapping[str, object]) -> GuestSessionConsentReceipt:
    return GuestSessionConsentReceipt(
        id=_uuid_field(row["id"], "guest receipt id corrupt"),
        household_id=_uuid_field(row["household_id"], "guest receipt household id corrupt"),
        session_id=_uuid_field(row["session_id"], "guest receipt session id corrupt"),
        challenge_id=_uuid_field(row["challenge_id"], "guest receipt challenge id corrupt"),
        presentation_receipt_id=_uuid_field(
            row["presentation_receipt_id"],
            "guest receipt presentation receipt id corrupt",
        ),
        purpose=cast(GuestConsentPurpose, str(row["purpose"])),
        disclosure_version=str(row["disclosure_version"]),
        granted=_bool_int(row["granted"]),
        issued_at=parse_utc_storage(str(row["issued_at"])),
        expires_at=parse_utc_storage(str(row["expires_at"])),
        revoked_at=_optional_time(row["revoked_at"]),
        commitment_key_id=str(row["commitment_key_id"]),
        receipt_hmac=_exact_blob(
            row["receipt_hmac"],
            "guest receipt hmac corrupt",
            expected_bytes=_HMAC_DIGEST_BYTES,
        ),
    )


def _enrollment_from_row(row: Mapping[str, object]) -> EnrollmentSession:
    profile_class = ProfileClass(str(row["profile_class"]))
    modality = Modality(str(row["modality"]))
    return EnrollmentSession(
        id=_uuid_field(row["id"], "enrollment id corrupt"),
        household_id=_uuid_field(row["household_id"], "enrollment household id corrupt"),
        subject_id=_uuid_field(row["subject_id"], "enrollment subject id corrupt"),
        modality=modality,
        state=cast(
            Literal["requested", "capturing", "calibrating", "approved", "cancelled", "expired"],
            str(row["state"]),
        ),
        consent_receipt_id=_uuid_field(
            row["consent_receipt_id"],
            "enrollment consent receipt id corrupt",
        ),
        reenrollment_days=int(str(row["reenrollment_days"])),
        subject_is_child=profile_class in {ProfileClass.K2, ProfileClass.N1},
        synthetic_template_id=_optional_uuid_field(
            row.get("synthetic_template_id"),
            "enrollment synthetic template id corrupt",
        ),
        created_at=parse_utc_storage(str(row["created_at"])),
        expires_at=parse_utc_storage(str(row["expires_at"])),
        closed_at=_optional_time(row["closed_at"]),
        next_reenrollment_reminder_at=_optional_time(row["next_reenrollment_reminder_at"]),
        biometric_hard_expires_at=_optional_time(row["biometric_hard_expires_at"]),
    )


def _template_from_row(row: Mapping[str, object]) -> BiometricTemplate:
    return BiometricTemplate(
        id=_uuid_field(row["id"], "biometric template id corrupt"),
        enrollment_session_id=_optional_uuid_field(
            row.get("enrollment_session_id"),
            "biometric template enrollment session id corrupt",
        ),
        household_id=_uuid_field(row["household_id"], "biometric template household id corrupt"),
        subject_id=_uuid_field(row["subject_id"], "biometric template subject id corrupt"),
        modality=Modality(str(row["modality"])),
        model_version=str(row["model_version"]),
        consent_receipt_id=_uuid_field(
            row["consent_receipt_id"],
            "biometric template consent receipt id corrupt",
        ),
        created_at=parse_utc_storage(str(row["created_at"])),
        expires_at=_optional_time(row["expires_at"]),
        revoked_at=_optional_time(row["revoked_at"]),
    )


def _guest_disclosure_presentation_event_type(
    purpose: GuestConsentPurpose,
    disclosure_version: str,
) -> str:
    return f"{_GUEST_DISCLOSURE_PRESENTATION_PREFIX}:{purpose}:{disclosure_version}"


def _audit(
    action_code: str,
    auth: AuthContext,
    audit_commitments: AuditCommitmentPort,
    *,
    event_id: UUID | None = None,
    subject_id: UUID | None = None,
    private_fields: Mapping[str, object] | None = None,
) -> AuditDraft:
    resolved_event_id = event_id or uuid4()
    payload_body = {
        "action": action_code,
        "actor_subject_id": None if auth.subject_id is None else str(auth.subject_id),
        "event_id": str(resolved_event_id),
        "private": _audit_private_json(private_fields or {}),
        "subject_id": None if subject_id is None else str(subject_id),
    }
    payload = json.dumps(
        payload_body,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return AuditDraft(
        event_id=resolved_event_id,
        occurred_at=auth.consumed_at,
        actor_pseudonym=_audit_actor_pseudonym(auth, audit_commitments),
        action_code=action_code,
        outcome="recorded",
        reason_code="ok",
        correlation_id=uuid4(),
        payload_commitment=audit_commitments.commit_private("audit.payload", payload),
    )


def _system_audit(
    action_code: str,
    audit_commitments: AuditCommitmentPort,
    *,
    occurred_at: datetime,
    private_fields: Mapping[str, object],
) -> AuditDraft:
    payload = json.dumps(
        {
            "action": action_code,
            "actor": "system",
            "private": _audit_private_json(private_fields),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return AuditDraft(
        event_id=uuid4(),
        occurred_at=occurred_at,
        actor_pseudonym="actor:system:identity",
        action_code=action_code,
        outcome="recorded",
        reason_code="ok",
        correlation_id=uuid4(),
        payload_commitment=audit_commitments.commit_private("audit.payload", payload),
    )


def _audit_actor_pseudonym(
    auth: AuthContext,
    audit_commitments: AuditCommitmentPort,
) -> str:
    if auth.subject_id is None:
        return "actor:guest"
    payload = json.dumps(
        {"actor_subject_id": str(auth.subject_id)},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    commitment = audit_commitments.commit_private("audit.actor.subject", payload)
    return f"actor:pseudonym:v1:{commitment.value_b64}"


def _audit_private_json(value: object) -> object:
    if hasattr(value, "value"):
        return _audit_private_json(value.value)
    if isinstance(value, UUID):
        return str(value)
    if hasattr(value, "isoformat"):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, bytes):
        return "<bytes>"
    if isinstance(value, tuple):
        return [_audit_private_json(item) for item in value]
    if isinstance(value, list):
        return [_audit_private_json(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _audit_private_json(item) for key, item in value.items()}
    return value


def _guest_audit_binding(
    household_id: UUID,
    session_id: UUID,
    audit_commitments: AuditCommitmentPort,
) -> ActionBinding:
    payload = json.dumps(
        {
            "binding": "guest-audit",
            "household_id": str(household_id),
            "session_id": str(session_id),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return ActionBinding(
        household_id=household_id,
        proposal_id=uuid4(),
        turn_id=uuid4(),
        idempotency_key=uuid4(),
        action_name="system.status",
        resource_type="system",
        resource_id=None,
        parameter_commitment=audit_commitments.commit_private("guest.audit.binding", payload),
        policy_version="phase1-v1",
        session_id=session_id,
        subject_id=None,
    )


def _append_consent_receipt_replacing_current(
    tx: UnitOfWorkProtocol,
    receipt: ConsentReceipt,
    expected_latest_receipt_id: UUID | None,
) -> None:
    latest = _row_to_dict(
        tx.exec_driver_sql(
            "SELECT id,granted FROM consent_receipts "
            "WHERE subject_id=? AND purpose=? "
            "ORDER BY created_at DESC LIMIT 1",
            (str(receipt.subject_id), receipt.purpose.value),
        ).fetchone()
    )
    latest_id = None if latest is None else _uuid_field(latest["id"], "consent receipt id corrupt")
    if latest_id != expected_latest_receipt_id:
        raise ConsentDenied("consent_state_changed")
    profile = _row_to_dict(
        tx.exec_driver_sql(
            "SELECT current_consent_receipt_ids FROM subjects "
            "WHERE id=? AND household_id=? AND active=1 AND revoked_at IS NULL",
            (str(receipt.subject_id), str(receipt.household_id)),
        ).fetchone()
    )
    if profile is None:
        raise ConsentDenied("current_active_subject_required")
    current_ids = _receipt_ids_from_blob(profile["current_consent_receipt_ids"])
    if latest_id is not None:
        assert latest is not None
        latest_granted = _bool_int(latest["granted"])
        latest_is_pointed_to = latest_id in current_ids
        if latest_granted != latest_is_pointed_to:
            raise RuntimeError("current_consent_pointer_corrupt")
    next_ids = _receipt_ids_excluding_subject_purpose(
        tx,
        current_ids,
        receipt.subject_id,
        receipt.purpose,
    )
    if receipt.granted:
        if len(next_ids) >= 8:
            raise RuntimeError("current_consent_pointer_full")
        next_ids = next_ids + (receipt.id,)
    changed = _insert_consent_receipt(tx, receipt)
    if changed != 1:
        raise RuntimeError("consent_receipt_insert_lost_ownership")
    updated = tx.exec_driver_sql(
        "UPDATE subjects SET current_consent_receipt_ids=?,updated_at=? "
        "WHERE id=? AND household_id=? AND current_consent_receipt_ids=?",
        (
            _receipt_ids_blob(next_ids),
            utc_storage(receipt.created_at),
            str(receipt.subject_id),
            str(receipt.household_id),
            profile["current_consent_receipt_ids"],
        ),
    ).rowcount
    if updated != 1:
        raise RuntimeError("current_consent_pointer_changed")


def _receipt_ids_excluding_subject_purpose(
    tx: UnitOfWorkProtocol,
    current_ids: tuple[UUID, ...],
    subject_id: UUID,
    purpose: ConsentPurpose,
) -> tuple[UUID, ...]:
    kept: list[UUID] = []
    for receipt_id in current_ids:
        row = _row_to_dict(
            tx.exec_driver_sql(
                "SELECT subject_id,purpose FROM consent_receipts WHERE id=?",
                (str(receipt_id),),
            ).fetchone()
        )
        if row is None:
            raise RuntimeError("current_consent_pointer_corrupt")
        if row["subject_id"] == str(subject_id) and row["purpose"] == purpose.value:
            continue
        kept.append(receipt_id)
    return tuple(kept)


def _insert_consent_receipt(tx: UnitOfWorkProtocol, receipt: ConsentReceipt) -> int:
    return tx.exec_driver_sql(
        "INSERT INTO consent_receipts "
        "(id,household_id,subject_id,actor_id,guardian_id,guardian_generation,purpose,"
        "granted,policy_version,disclosure_version,commitment_key_id,receipt_hmac,"
        "created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            str(receipt.id),
            str(receipt.household_id),
            str(receipt.subject_id),
            str(receipt.actor_id),
            None if receipt.guardian_id is None else str(receipt.guardian_id),
            receipt.guardian_generation,
            receipt.purpose.value,
            int(receipt.granted),
            receipt.policy_version,
            receipt.disclosure_version,
            receipt.commitment_key_id,
            receipt.receipt_hmac,
            utc_storage(receipt.created_at),
            None if receipt.expires_at is None else utc_storage(receipt.expires_at),
        ),
    ).rowcount


class SqlProfileRepository:
    def __init__(
        self,
        uow: AsyncUnitOfWorkProtocol,
        audit_commitments: AuditCommitmentPort,
    ) -> None:
        self._uow = uow
        self._audit_commitments = audit_commitments

    async def insert(self, profile: Profile) -> None:
        changed = await self._uow.run_sync(
            lambda tx: (
                tx.exec_driver_sql(
                    "INSERT INTO subjects "
                    "(id,household_id,guardian_id,guardian_generation,profile_class,"
                    "encrypted_display_label,encrypted_persona_traits,current_consent_receipt_ids,"
                    "active,authority_generation,version,next_reenrollment_reminder_at,"
                    "created_at,updated_at,revoked_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        str(profile.id),
                        str(profile.household_id),
                        None if profile.guardian_id is None else str(profile.guardian_id),
                        profile.guardian_generation,
                        profile.profile_class.value,
                        profile.encrypted_display_label,
                        profile.encrypted_persona_traits,
                        _receipt_ids_blob(profile.current_consent_receipt_ids),
                        int(profile.active),
                        profile.authority_generation,
                        profile.version,
                        None
                        if profile.next_reenrollment_reminder_at is None
                        else utc_storage(profile.next_reenrollment_reminder_at),
                        utc_storage(profile.created_at),
                        utc_storage(profile.updated_at),
                        None if profile.revoked_at is None else utc_storage(profile.revoked_at),
                    ),
                ).rowcount
            )
        )
        if changed != 1:
            raise RuntimeError("profile_insert_lost_ownership")

    async def get(self, subject_id: UUID) -> Profile:
        row = await self._uow.run_sync(
            lambda tx: _row_to_dict(
                tx.exec_driver_sql(
                    "SELECT * FROM subjects WHERE id=?", (str(subject_id),)
                ).fetchone()
            )
        )
        if row is None:
            raise KeyError(subject_id)
        return _profile_from_row(row)

    async def get_scoped(self, household_id: UUID, subject_id: UUID) -> Profile:
        profile = await self.get(subject_id)
        if profile.household_id != household_id:
            raise KeyError(subject_id)
        return profile

    async def get_optional_scoped(self, household_id: UUID, subject_id: UUID) -> Profile | None:
        row = await self._uow.run_sync(
            lambda tx: _row_to_dict(
                tx.exec_driver_sql(
                    "SELECT * FROM subjects WHERE household_id=? AND id=?",
                    (str(household_id), str(subject_id)),
                ).fetchone()
            )
        )
        return None if row is None else _profile_from_row(row)

    async def list_children_due_for_reenrollment_reminder(
        self,
        household_id: UUID,
        now: datetime,
    ) -> tuple[Profile, ...]:
        timestamp = utc_storage(now)
        rows = await self._uow.run_sync(
            lambda tx: tuple(
                _row_to_dict(row)
                for row in tx.exec_driver_sql(
                    "SELECT * FROM subjects WHERE household_id=? AND active=1 "
                    "AND revoked_at IS NULL AND profile_class IN ('k2','n1') "
                    "AND next_reenrollment_reminder_at IS NOT NULL "
                    "AND next_reenrollment_reminder_at<=? "
                    "ORDER BY next_reenrollment_reminder_at,id",
                    (str(household_id), timestamp),
                ).fetchall()
            )
        )
        return tuple(_profile_from_row(row) for row in rows if row is not None)

    async def disable_biometric_identity(
        self,
        subject_id: UUID,
        now: object,
    ) -> None:
        timestamp = utc_storage(cast(datetime, now))
        await self._uow.run_sync(
            lambda tx: (
                tx.exec_driver_sql(
                    "UPDATE subjects SET next_reenrollment_reminder_at=NULL,updated_at=? "
                    "WHERE id=? AND profile_class IN ('k2','n1')",
                    (timestamp, str(subject_id)),
                ).rowcount
            )
        )

    async def require_current_owner_guardian_generation(
        self,
        household_id: UUID,
        guardian_id: UUID,
        now: datetime,
    ) -> int:
        del now
        row = await self._uow.run_sync(
            lambda tx: _row_to_dict(
                tx.exec_driver_sql(
                    "SELECT owner.owner_generation,subject.authority_generation,"
                    "subject.active,subject.revoked_at,subject.profile_class "
                    "FROM current_owner_authority AS owner "
                    "JOIN subjects AS subject ON subject.id=owner.subject_id "
                    "AND subject.household_id=owner.household_id "
                    "WHERE owner.household_id=? AND owner.subject_id=?",
                    (str(household_id), str(guardian_id)),
                ).fetchone()
            )
        )
        if (
            row is None
            or str(row["profile_class"]) != ProfileClass.OWNER.value
            or int(str(row["active"])) != 1
            or row["revoked_at"] is not None
            or int(str(row["owner_generation"])) != int(str(row["authority_generation"]))
        ):
            raise PermissionError("current_owner_guardian_required")
        return int(str(row["owner_generation"]))

    async def update_persona_expected_version(
        self,
        subject_id: UUID,
        expected_version: int,
        encrypted_persona_traits: bytes | None,
        now: object,
    ) -> Profile:
        timestamp = utc_storage(cast(datetime, now))
        row = await self._uow.run_sync(
            lambda tx: _row_to_dict(
                tx.exec_driver_sql(
                    "UPDATE subjects SET encrypted_persona_traits=?,version=version+1,"
                    "updated_at=? WHERE id=? AND version=? AND active=1 "
                    "RETURNING *",
                    (encrypted_persona_traits, timestamp, str(subject_id), expected_version),
                ).fetchone()
            )
        )
        if row is None:
            raise RuntimeError("stale_profile_version")
        return _profile_from_row(row)

    async def revoke_and_advance_authority_generation_expected_version(
        self,
        subject_id: UUID,
        expected_version: int,
        current_authority_generation: int,
        now: object,
    ) -> Profile:
        timestamp = utc_storage(cast(datetime, now))
        row = await self._uow.run_sync(
            lambda tx: _row_to_dict(
                tx.exec_driver_sql(
                    "UPDATE subjects SET active=0,authority_generation=authority_generation+1,"
                    "version=version+1,updated_at=?,revoked_at=? "
                    "WHERE id=? AND version=? AND authority_generation=? "
                    "AND active=1 AND revoked_at IS NULL RETURNING *",
                    (
                        timestamp,
                        timestamp,
                        str(subject_id),
                        expected_version,
                        current_authority_generation,
                    ),
                ).fetchone()
            )
        )
        if row is None:
            raise RuntimeError("stale_profile_version")
        return _profile_from_row(row)

    def created_audit(self, profile: Profile, auth: AuthContext) -> AuditDraft:
        return _audit(
            "profile.created",
            auth,
            self._audit_commitments,
            subject_id=profile.id,
        )

    def persona_changed_audit(
        self,
        profile: Profile,
        auth: AuthContext,
        *,
        operation: str,
    ) -> AuditDraft:
        return _audit(
            f"profile.persona.{operation}",
            auth,
            self._audit_commitments,
            subject_id=profile.id,
        )

    def revoked_audit(self, profile: Profile, auth: AuthContext) -> AuditDraft:
        return _audit(
            "profile.revoked",
            auth,
            self._audit_commitments,
            subject_id=profile.id,
        )


class SqlConsentReceiptRepository:
    def __init__(
        self,
        uow: AsyncUnitOfWorkProtocol,
        audit_commitments: AuditCommitmentPort,
    ) -> None:
        self._uow = uow
        self._audit_commitments = audit_commitments

    async def append(self, receipt: ConsentReceipt, auth: AuthContext) -> None:
        del auth
        changed = await self._uow.run_sync(
            lambda tx: (
                tx.exec_driver_sql(
                    "INSERT INTO consent_receipts "
                    "(id,household_id,subject_id,actor_id,guardian_id,guardian_generation,purpose,"
                    "granted,policy_version,disclosure_version,commitment_key_id,receipt_hmac,"
                    "created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        str(receipt.id),
                        str(receipt.household_id),
                        str(receipt.subject_id),
                        str(receipt.actor_id),
                        None if receipt.guardian_id is None else str(receipt.guardian_id),
                        receipt.guardian_generation,
                        receipt.purpose.value,
                        int(receipt.granted),
                        receipt.policy_version,
                        receipt.disclosure_version,
                        receipt.commitment_key_id,
                        receipt.receipt_hmac,
                        utc_storage(receipt.created_at),
                        None if receipt.expires_at is None else utc_storage(receipt.expires_at),
                    ),
                ).rowcount
            )
        )
        if changed != 1:
            raise RuntimeError("consent_receipt_insert_lost_ownership")

    async def append_replacing_current(
        self,
        receipt: ConsentReceipt,
        *,
        expected_latest_receipt_id: UUID | None,
        auth: AuthContext,
    ) -> None:
        del auth
        await self._uow.run_sync(
            lambda tx: _append_consent_receipt_replacing_current(
                tx,
                receipt,
                expected_latest_receipt_id,
            )
        )

    async def latest(self, subject_id: UUID, purpose: ConsentPurpose) -> ConsentReceipt | None:
        row = await self._uow.run_sync(
            lambda tx: _row_to_dict(
                tx.exec_driver_sql(
                    "SELECT * FROM consent_receipts WHERE subject_id=? AND purpose=? "
                    "ORDER BY created_at DESC LIMIT 1",
                    (str(subject_id), purpose.value),
                ).fetchone()
            )
        )
        return None if row is None else _consent_from_row(row)

    async def latest_for_update(
        self,
        subject_id: UUID,
        purpose: ConsentPurpose,
    ) -> ConsentReceipt | None:
        return await self.latest(subject_id, purpose)

    async def require_current_for_update(
        self,
        subject_id: UUID,
        purpose: ConsentPurpose,
        now: object,
    ) -> ConsentReceipt:
        receipt = await self.latest(subject_id, purpose)
        timestamp = cast(datetime, now)
        if (
            receipt is None
            or not receipt.granted
            or receipt.created_at > timestamp
            or (receipt.expires_at is not None and receipt.expires_at <= timestamp)
        ):
            raise ConsentDenied("current_consent_required")
        return receipt

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
    ) -> ConsentReceipt:
        if type(command) is not GrantConsent:
            raise TypeError("grant consent command required")
        grant = command
        return ConsentReceipt(
            id=uuid4(),
            household_id=household_id,
            subject_id=grant.subject_id,
            actor_id=grant.actor_id,
            guardian_id=guardian_id,
            guardian_generation=guardian_generation,
            purpose=grant.purpose,
            granted=True,
            policy_version=grant.policy_version,
            disclosure_version=grant.disclosure_version,
            commitment_key_id=commitment_key_id,
            receipt_hmac=receipt_hmac,
            created_at=cast(datetime, now),
            expires_at=cast(datetime | None, expires_at),
        )

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
    ) -> ConsentReceipt:
        return current.model_copy(
            update={
                "id": uuid4(),
                "actor_id": actor_id,
                "guardian_id": guardian_id,
                "guardian_generation": guardian_generation,
                "granted": False,
                "created_at": cast(datetime, now),
                "expires_at": cast(datetime, expires_at),
                "commitment_key_id": commitment_key_id,
                "receipt_hmac": receipt_hmac,
            }
        )

    def audit_draft(self, receipt: ConsentReceipt, auth: AuthContext) -> AuditDraft:
        return _audit(
            "consent.receipt",
            auth,
            self._audit_commitments,
            subject_id=receipt.subject_id,
            private_fields={"receipt_id": receipt.id, "purpose": receipt.purpose},
        )

    def identity_consent_revoked_event(self, receipt: ConsentReceipt, now: object) -> object:
        return {"receipt_id": receipt.id, "occurred_at": utc_storage(cast(datetime, now))}

    async def revoke_subject_authorities_in_uow(
        self,
        subject_id: UUID,
        through_generation: int,
        reason: str,
        now: object,
    ) -> None:
        del through_generation, reason
        timestamp = utc_storage(cast(datetime, now))
        await self._uow.run_sync(
            lambda tx: (
                tx.exec_driver_sql(
                    "UPDATE consent_receipts SET expires_at=? "
                    "WHERE subject_id=? AND granted=1 AND (expires_at IS NULL OR expires_at>?)",
                    (timestamp, str(subject_id), timestamp),
                ).rowcount
            )
        )


class SqlEnrollmentRepository:
    def __init__(
        self,
        uow: AsyncUnitOfWorkProtocol,
        audit_commitments: AuditCommitmentPort,
    ) -> None:
        self._uow = uow
        self._audit_commitments = audit_commitments

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
    ) -> EnrollmentSession:
        if auth.grant_id is None:
            raise RuntimeError("enrollment_auth_receipt_required")
        created_at = cast(datetime, now)
        expires = cast(datetime, expires_at)
        enrollment_id = uuid4()
        changed = await self._uow.run_sync(
            lambda tx: (
                tx.exec_driver_sql(
                    "INSERT INTO enrollment_sessions "
                    "(id,subject_id,modality,state,auth_receipt_id,consent_receipt_id,"
                    "reenrollment_days,created_at,expires_at,synthetic_template_id,closed_at) "
                    "VALUES (?,?,?,'requested',?,?,?,?,?,?,NULL)",
                    (
                        str(enrollment_id),
                        str(command.subject_id),
                        command.modality.value,
                        str(auth.grant_id),
                        str(consent_receipt_id),
                        command.reenrollment_days,
                        utc_storage(created_at),
                        utc_storage(expires),
                        str(synthetic_template_id),
                    ),
                ).rowcount
            )
        )
        if changed != 1:
            raise RuntimeError("enrollment_insert_lost_ownership")
        return EnrollmentSession(
            id=enrollment_id,
            household_id=household_id,
            subject_id=command.subject_id,
            modality=command.modality,
            state="requested",
            consent_receipt_id=consent_receipt_id,
            reenrollment_days=command.reenrollment_days,
            subject_is_child=subject_is_child,
            synthetic_template_id=synthetic_template_id,
            created_at=created_at,
            expires_at=expires,
        )

    async def require_for_update(self, enrollment_id: UUID) -> EnrollmentSession:
        row = await self._uow.run_sync(lambda tx: self._select_enrollment(tx, enrollment_id))
        if row is None:
            raise KeyError(enrollment_id)
        return _enrollment_from_row(row)

    async def require_state(
        self,
        enrollment_id: UUID,
        states: str | tuple[str, ...],
    ) -> EnrollmentSession:
        allowed = (states,) if type(states) is str else states
        session = await self.require_for_update(enrollment_id)
        if session.state not in allowed:
            raise RuntimeError("enrollment_state_mismatch")
        return session

    async def begin_capture(self, enrollment_id: UUID, now: object) -> EnrollmentSession:
        del now
        row = await self._uow.run_sync(
            lambda tx: self._transition_state(
                tx,
                enrollment_id,
                from_state="requested",
                to_state="capturing",
            )
        )
        if row is None:
            raise RuntimeError("enrollment_capture_transition_lost_ownership")
        return _enrollment_from_row(row)

    async def mark_calibrating(self, enrollment_id: UUID, now: object) -> EnrollmentSession:
        del now
        row = await self._uow.run_sync(
            lambda tx: self._transition_state(
                tx,
                enrollment_id,
                from_state="capturing",
                to_state="calibrating",
            )
        )
        if row is None:
            raise RuntimeError("enrollment_calibration_transition_lost_ownership")
        return _enrollment_from_row(row)

    async def cancel_pending(self, enrollment_id: UUID, now: object) -> EnrollmentSession:
        timestamp = utc_storage(cast(datetime, now))
        row = await self._uow.run_sync(
            lambda tx: self._cancel_pending(tx, enrollment_id, timestamp)
        )
        if row is None:
            raise RuntimeError("enrollment_cancel_lost_ownership")
        return _enrollment_from_row(row)

    async def approve(
        self,
        enrollment_id: UUID,
        template_ids: tuple[UUID, ...],
        reminder_at: object | None,
        hard_expires_at: object | None,
        now: object,
    ) -> EnrollmentSession:
        timestamp = utc_storage(cast(datetime, now))
        reminder = None if reminder_at is None else utc_storage(cast(datetime, reminder_at))
        hard_expiry = (
            None if hard_expires_at is None else utc_storage(cast(datetime, hard_expires_at))
        )
        row = await self._uow.run_sync(
            lambda tx: self._approve(
                tx,
                enrollment_id,
                template_ids,
                reminder,
                hard_expiry,
                timestamp,
            )
        )
        if row is None:
            raise RuntimeError("enrollment_approval_lost_ownership")
        return _enrollment_from_row(row)

    async def cancel_subject_modality(
        self,
        subject_id: UUID,
        modality: str,
        now: object,
    ) -> int:
        timestamp = utc_storage(cast(datetime, now))
        return await self._uow.run_sync(
            lambda tx: (
                tx.exec_driver_sql(
                    "UPDATE enrollment_sessions SET state='cancelled',closed_at=? "
                    "WHERE subject_id=? AND modality=? AND closed_at IS NULL "
                    "AND state IN ('requested','capturing','calibrating')",
                    (timestamp, str(subject_id), modality),
                ).rowcount
            )
        )

    def requested_audit(self, session: EnrollmentSession, auth: AuthContext) -> AuditDraft:
        return _audit(
            "identity.enrollment.requested",
            auth,
            self._audit_commitments,
            subject_id=session.subject_id,
            private_fields={
                "consent_receipt_id": session.consent_receipt_id,
                "enrollment_id": session.id,
                "modality": session.modality,
            },
        )

    def cancelled_audit(self, session: EnrollmentSession, auth: AuthContext) -> AuditDraft:
        return _audit(
            "identity.enrollment.cancelled",
            auth,
            self._audit_commitments,
            subject_id=session.subject_id,
            private_fields={"enrollment_id": session.id, "modality": session.modality},
        )

    def approved_audit(self, session: EnrollmentSession) -> AuditDraft:
        return _system_audit(
            "identity.enrollment.approved",
            self._audit_commitments,
            occurred_at=_session_event_time(session),
            private_fields={
                "enrollment_id": session.id,
                "modality": session.modality,
                "subject_id": session.subject_id,
            },
        )

    def expiry_batch_audit(
        self,
        templates: tuple[BiometricTemplate, ...],
        now: object,
    ) -> AuditDraft:
        return _system_audit(
            "identity.biometric_template.expired",
            self._audit_commitments,
            occurred_at=cast(datetime, now),
            private_fields={
                "subject_ids": tuple(dict.fromkeys(template.subject_id for template in templates)),
                "template_ids": tuple(template.id for template in templates),
            },
        )

    @staticmethod
    def _select_enrollment(
        tx: UnitOfWorkProtocol,
        enrollment_id: UUID,
    ) -> dict[str, object] | None:
        row = _row_to_dict(
            tx.exec_driver_sql(
                "SELECT enrollment.*,subject.household_id,subject.profile_class,"
                "subject.next_reenrollment_reminder_at,"
                "(SELECT MIN(template.expires_at) FROM biometric_templates AS template "
                "WHERE template.subject_id=enrollment.subject_id "
                "AND template.modality=enrollment.modality "
                "AND template.consent_receipt_id=enrollment.consent_receipt_id "
                "AND template.enrollment_session_id=enrollment.id "
                "AND template.id=enrollment.synthetic_template_id "
                "AND template.revoked_at IS NULL) AS biometric_hard_expires_at "
                "FROM enrollment_sessions AS enrollment "
                "JOIN subjects AS subject ON subject.id=enrollment.subject_id "
                "WHERE enrollment.id=?",
                (str(enrollment_id),),
            ).fetchone()
        )
        return row

    def _transition_state(
        self,
        tx: UnitOfWorkProtocol,
        enrollment_id: UUID,
        *,
        from_state: str,
        to_state: str,
    ) -> dict[str, object] | None:
        row = self._select_enrollment(tx, enrollment_id)
        if row is None:
            return None
        if row["closed_at"] is not None or str(row["state"]) != from_state:
            return None
        expected_template_id = _optional_uuid_field(
            row.get("synthetic_template_id"),
            "enrollment synthetic template id corrupt",
        )
        if expected_template_id is None:
            raise RuntimeError("enrollment_expected_template_required")
        changed = tx.exec_driver_sql(
            "UPDATE enrollment_sessions SET state=? "
            "WHERE id=? AND synthetic_template_id=? AND closed_at IS NULL AND state=?",
            (to_state, str(enrollment_id), str(expected_template_id), from_state),
        ).rowcount
        if changed != 1:
            return None
        return self._select_enrollment(tx, enrollment_id)

    def _cancel_pending(
        self,
        tx: UnitOfWorkProtocol,
        enrollment_id: UUID,
        timestamp: str,
    ) -> dict[str, object] | None:
        changed = tx.exec_driver_sql(
            "UPDATE enrollment_sessions SET state='cancelled',closed_at=? "
            "WHERE id=? AND closed_at IS NULL "
            "AND state IN ('requested','capturing','calibrating')",
            (timestamp, str(enrollment_id)),
        ).rowcount
        if changed != 1:
            return None
        return self._select_enrollment(tx, enrollment_id)

    def _approve(
        self,
        tx: UnitOfWorkProtocol,
        enrollment_id: UUID,
        template_ids: tuple[UUID, ...],
        reminder_at: str | None,
        hard_expires_at: str | None,
        timestamp: str,
    ) -> dict[str, object] | None:
        row = self._select_enrollment(tx, enrollment_id)
        if row is None:
            return None
        if str(row["state"]) != "calibrating":
            return None
        expected_template_id = _optional_uuid_field(
            row.get("synthetic_template_id"),
            "enrollment synthetic template id corrupt",
        )
        if expected_template_id is None or template_ids != (expected_template_id,):
            return None
        if not self._approved_template_is_linkable(tx, expected_template_id, row):
            return None
        changed = tx.exec_driver_sql(
            "UPDATE enrollment_sessions SET state='approved',closed_at=? "
            "WHERE id=? AND synthetic_template_id=? "
            "AND closed_at IS NULL AND state='calibrating'",
            (timestamp, str(enrollment_id), str(expected_template_id)),
        ).rowcount
        if changed != 1:
            return None
        if reminder_at is not None:
            profile_changed = tx.exec_driver_sql(
                "UPDATE subjects SET next_reenrollment_reminder_at=?,updated_at=? "
                "WHERE id=? AND profile_class IN ('k2','n1') AND active=1 "
                "AND revoked_at IS NULL",
                (reminder_at, timestamp, row["subject_id"]),
            ).rowcount
            if profile_changed != 1:
                raise RuntimeError("child_reenrollment_profile_update_lost_ownership")
        for template_id in template_ids:
            self._link_approved_template(
                tx,
                template_id,
                row,
                hard_expires_at,
                timestamp,
            )
        return self._select_enrollment(tx, enrollment_id)

    @staticmethod
    def _link_approved_template(
        tx: UnitOfWorkProtocol,
        template_id: UUID,
        row: Mapping[str, object],
        hard_expires_at: str | None,
        timestamp: str,
    ) -> None:
        del timestamp
        changed = tx.exec_driver_sql(
            "UPDATE biometric_templates SET expires_at=? "
            "WHERE id=? AND enrollment_session_id=? AND subject_id=? "
            "AND modality=? AND consent_receipt_id=? "
            "AND id=? "
            "AND expires_at IS NULL AND revoked_at IS NULL",
            (
                hard_expires_at,
                str(template_id),
                row["id"],
                row["subject_id"],
                row["modality"],
                row["consent_receipt_id"],
                row["synthetic_template_id"],
            ),
        ).rowcount
        if changed != 1:
            raise RuntimeError("biometric_template_link_lost_ownership")

    @staticmethod
    def _approved_template_is_linkable(
        tx: UnitOfWorkProtocol,
        template_id: UUID,
        row: Mapping[str, object],
    ) -> bool:
        return (
            tx.exec_driver_sql(
                "SELECT 1 FROM biometric_templates "
                "WHERE id=? AND enrollment_session_id=? AND subject_id=? "
                "AND modality=? AND consent_receipt_id=? "
                "AND expires_at IS NULL AND revoked_at IS NULL",
                (
                    str(template_id),
                    row["id"],
                    row["subject_id"],
                    row["modality"],
                    row["consent_receipt_id"],
                ),
            ).fetchone()
            is not None
        )


class SqlBiometricTemplateRepository:
    def __init__(
        self,
        uow: AsyncUnitOfWorkProtocol,
        audit_commitments: AuditCommitmentPort,
    ) -> None:
        self._uow = uow
        self._audit_commitments = audit_commitments

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
    ) -> tuple[BiometricTemplate, ...]:
        if template_ids != (expected_template_id,):
            raise RuntimeError("biometric_template_scope_mismatch")
        rows = await self._uow.run_sync(lambda tx: self._select_templates(tx, template_ids))
        templates = tuple(_template_from_row(row) for row in rows)
        if len(templates) != 1:
            raise KeyError("biometric_template_missing")
        for template in templates:
            if (
                template.id != expected_template_id
                or template.household_id != household_id
                or template.enrollment_session_id != enrollment_session_id
                or template.subject_id != subject_id
                or template.modality.value != modality
                or template.consent_receipt_id != consent_receipt_id
                or template.expires_at is not None
                or template.revoked_at is not None
            ):
                raise RuntimeError("biometric_template_scope_mismatch")
        return templates

    async def list_child_templates_past_hard_expiry(
        self,
        household_id: UUID,
        now: object,
    ) -> tuple[BiometricTemplate, ...]:
        timestamp = utc_storage(cast(datetime, now))
        rows = await self._uow.run_sync(
            lambda tx: tuple(
                _row_to_dict(row)
                for row in tx.exec_driver_sql(
                    "SELECT template.*,subject.household_id "
                    "FROM biometric_templates AS template "
                    "JOIN subjects AS subject ON subject.id=template.subject_id "
                    "WHERE subject.household_id=? AND subject.active=1 "
                    "AND subject.revoked_at IS NULL AND subject.profile_class IN ('k2','n1') "
                    "AND template.revoked_at IS NULL AND template.expires_at IS NOT NULL "
                    "AND template.expires_at<=? ORDER BY template.expires_at,template.id",
                    (str(household_id), timestamp),
                ).fetchall()
            )
        )
        return tuple(_template_from_row(row) for row in rows if row is not None)

    async def expire_template(self, template_id: UUID, now: object) -> None:
        timestamp = utc_storage(cast(datetime, now))
        await self._uow.run_sync(
            lambda tx: (
                tx.exec_driver_sql(
                    "UPDATE biometric_templates SET revoked_at=?,"
                    "expires_at=CASE WHEN expires_at IS NULL OR expires_at>? "
                    "THEN ? ELSE expires_at END "
                    "WHERE id=? AND revoked_at IS NULL",
                    (timestamp, timestamp, timestamp, str(template_id)),
                ).rowcount
            )
        )

    async def revoke_subject_modality(
        self,
        subject_id: UUID,
        modality: str,
        now: object,
    ) -> tuple[BiometricTemplate, ...]:
        timestamp = utc_storage(cast(datetime, now))
        rows = await self._uow.run_sync(
            lambda tx: self._revoke_subject_modality(tx, subject_id, modality, timestamp)
        )
        return tuple(_template_from_row(row) for row in rows)

    async def revoke_subject_authorities_in_uow(
        self,
        subject_id: UUID,
        through_generation: int,
        reason: str,
        now: object,
    ) -> None:
        del through_generation, reason
        timestamp = utc_storage(cast(datetime, now))
        await self._uow.run_sync(
            lambda tx: self._revoke_subject_modality(tx, subject_id, "%", timestamp)
        )

    def managed_erasure_requested_audit(
        self,
        template: BiometricTemplate,
        *,
        stores: tuple[str, ...],
        requested_at: object,
    ) -> AuditDraft:
        return _system_audit(
            "identity.biometric_template.erasure_requested",
            self._audit_commitments,
            occurred_at=cast(datetime, requested_at),
            private_fields={
                "modality": template.modality,
                "stores": stores,
                "subject_id": template.subject_id,
                "template_id": template.id,
            },
        )

    @staticmethod
    def _select_templates(
        tx: UnitOfWorkProtocol,
        template_ids: tuple[UUID, ...],
    ) -> tuple[dict[str, object], ...]:
        placeholders = ",".join("?" for _ in template_ids)
        rows = tx.exec_driver_sql(
            "SELECT template.*,subject.household_id "
            "FROM biometric_templates AS template "
            "JOIN subjects AS subject ON subject.id=template.subject_id "
            f"WHERE template.id IN ({placeholders})",
            tuple(str(template_id) for template_id in template_ids),
        ).fetchall()
        return tuple(row for row in (_row_to_dict(row) for row in rows) if row is not None)

    @staticmethod
    def _revoke_subject_modality(
        tx: UnitOfWorkProtocol,
        subject_id: UUID,
        modality: str,
        timestamp: str,
    ) -> tuple[dict[str, object], ...]:
        if modality == "%":
            modality_clause = ""
            parameters: tuple[object, ...] = (str(subject_id),)
        else:
            modality_clause = "AND template.modality=? "
            parameters = (str(subject_id), modality)
        rows = tuple(
            _row_to_dict(row)
            for row in tx.exec_driver_sql(
                "SELECT template.*,subject.household_id "
                "FROM biometric_templates AS template "
                "JOIN subjects AS subject ON subject.id=template.subject_id "
                "WHERE template.subject_id=? "
                + modality_clause
                + "AND template.revoked_at IS NULL ORDER BY template.id",
                parameters,
            ).fetchall()
        )
        tx.exec_driver_sql(
            "UPDATE biometric_templates SET revoked_at=?,"
            "expires_at=CASE WHEN expires_at IS NULL OR expires_at>? THEN ? ELSE expires_at END "
            "WHERE subject_id=? "
            + ("" if modality == "%" else "AND modality=? ")
            + "AND revoked_at IS NULL",
            (
                (timestamp, timestamp, timestamp, str(subject_id))
                if modality == "%"
                else (timestamp, timestamp, timestamp, str(subject_id), modality)
            ),
        )
        return tuple(row for row in rows if row is not None)


def _session_event_time(session: EnrollmentSession) -> datetime:
    occurred_at = session.closed_at or session.created_at
    if occurred_at is None:
        raise RuntimeError("enrollment_session_event_time_required")
    return occurred_at


@dataclass(frozen=True, slots=True)
class SqlSessionIdentity:
    expires_at: datetime


class SqlSessionIdentityRepository:
    def __init__(self, uow: AsyncUnitOfWorkProtocol) -> None:
        self._uow = uow

    async def lock_active(
        self,
        household_id: UUID,
        session_id: UUID,
        now: object,
    ) -> SqlSessionIdentity:
        return await self.require_active(household_id, session_id, now)

    async def require_active(
        self,
        household_id: UUID,
        session_id: UUID,
        now: object,
    ) -> SqlSessionIdentity:
        timestamp = cast(datetime, now)
        row = await self._uow.run_sync(
            lambda tx: _row_to_dict(
                tx.exec_driver_sql(
                    "SELECT last_activity_at,closed_at FROM sessions WHERE id=? AND household_id=?",
                    (str(session_id), str(household_id)),
                ).fetchone()
            )
        )
        if row is None or row["closed_at"] is not None:
            raise ConsentDenied("active_guest_session_required")
        expires_at = parse_utc_storage(str(row["last_activity_at"])) + timedelta(
            seconds=_GUEST_SESSION_SECONDS
        )
        if expires_at <= timestamp:
            raise ConsentDenied("active_guest_session_required")
        return SqlSessionIdentity(expires_at)

    async def invalidate_identity_subject(
        self,
        subject_id: UUID,
        reason: str,
        now: object,
    ) -> None:
        del reason
        await self._uow.run_sync(
            lambda tx: (
                tx.exec_driver_sql(
                    "UPDATE sessions SET speaker_subject_id=NULL,last_activity_at=? "
                    "WHERE speaker_subject_id=? AND closed_at IS NULL",
                    (utc_storage(cast(datetime, now)), str(subject_id)),
                ).rowcount
            )
        )


class SqlEventReceiptRepository:
    def __init__(self, uow: AsyncUnitOfWorkProtocol) -> None:
        self._uow = uow

    async def require_exact_guest_disclosure(
        self,
        presentation_receipt_id: UUID,
        *,
        household_id: UUID,
        session_id: UUID,
        purpose: GuestConsentPurpose,
        disclosure_version: str,
        now: object,
    ) -> None:
        row = await self._uow.run_sync(
            lambda tx: _row_to_dict(
                tx.exec_driver_sql(
                    "SELECT occurred_at FROM event_receipts "
                    "WHERE id=? AND household_id=? AND correlation_id=? "
                    "AND event_type=? AND decision='accepted'",
                    (
                        str(presentation_receipt_id),
                        str(household_id),
                        str(session_id),
                        _guest_disclosure_presentation_event_type(
                            purpose,
                            disclosure_version,
                        ),
                    ),
                ).fetchone()
            )
        )
        if row is None:
            raise ConsentDenied("guest_disclosure_presentation_mismatch")
        try:
            occurred_at = parse_utc_storage(str(row["occurred_at"]))
        except ValueError as error:
            raise ConsentDenied("guest_disclosure_presentation_mismatch") from error
        if occurred_at > cast(datetime, now):
            raise ConsentDenied("guest_disclosure_presentation_mismatch")


class SqlGuestDisclosureChallengeRepository:
    def __init__(self, uow: AsyncUnitOfWorkProtocol) -> None:
        self._uow = uow

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
    ) -> GuestDisclosureChallenge:
        await self._uow.run_sync(
            lambda tx: (
                tx.exec_driver_sql(
                    "INSERT INTO guest_disclosure_challenges "
                    "(id,household_id,session_id,purpose,disclosure_version,"
                    "presentation_receipt_id,state,issued_at,expires_at,consumed_at,"
                    "commitment_key_id,challenge_hmac) "
                    "VALUES (?,?,?,?,?,?,'open',?,?,NULL,?,?)",
                    (
                        str(challenge_id),
                        str(household_id),
                        str(session_id),
                        purpose,
                        disclosure_version,
                        str(presentation_receipt_id),
                        utc_storage(cast(datetime, now)),
                        utc_storage(cast(datetime, expires_at)),
                        commitment_key_id,
                        challenge_hmac,
                    ),
                ).rowcount
            )
        )
        return GuestDisclosureChallenge(
            id=challenge_id,
            household_id=household_id,
            session_id=session_id,
            purpose=purpose,
            disclosure_version=disclosure_version,
            state="open",
            issued_at=cast(datetime, now),
            expires_at=cast(datetime, expires_at),
            consumed_at=None,
            presentation_receipt_id=presentation_receipt_id,
            commitment_key_id=commitment_key_id,
            challenge_hmac=challenge_hmac,
        )

    async def lock_open(self, challenge_id: UUID, now: object) -> GuestDisclosureChallenge:
        row = await self._uow.run_sync(
            lambda tx: _row_to_dict(
                tx.exec_driver_sql(
                    "SELECT * FROM guest_disclosure_challenges WHERE id=? AND state='open'",
                    (str(challenge_id),),
                ).fetchone()
            )
        )
        timestamp = cast(datetime, now)
        if row is None:
            raise ConsentDenied("active_guest_disclosure_challenge_required")
        challenge = _guest_challenge_from_row(row)
        if challenge.issued_at > timestamp or challenge.expires_at <= timestamp:
            raise ConsentDenied("active_guest_disclosure_challenge_required")
        return challenge

    async def consume_denied(self, challenge_id: UUID, now: object) -> None:
        await self._consume(challenge_id, "denied", cast(datetime, now))

    async def consume_accepted(self, challenge_id: UUID, now: object) -> None:
        await self._consume(challenge_id, "accepted", cast(datetime, now))

    async def _consume(self, challenge_id: UUID, state: str, now: datetime) -> None:
        changed = await self._uow.run_sync(
            lambda tx: (
                tx.exec_driver_sql(
                    "UPDATE guest_disclosure_challenges SET state=?,consumed_at=? "
                    "WHERE id=? AND state='open'",
                    (state, utc_storage(now), str(challenge_id)),
                ).rowcount
            )
        )
        if changed != 1:
            raise ConsentDenied("active_guest_disclosure_challenge_required")


class SqlGuestSessionConsentRepository:
    def __init__(
        self,
        uow: AsyncUnitOfWorkProtocol,
        audit_commitments: AuditCommitmentPort,
    ) -> None:
        self._uow = uow
        self._audit_commitments = audit_commitments

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
    ) -> GuestSessionConsentReceipt:
        receipt = GuestSessionConsentReceipt(
            id=uuid4(),
            household_id=household_id,
            session_id=session_id,
            challenge_id=challenge_id,
            presentation_receipt_id=presentation_receipt_id,
            purpose=purpose,
            disclosure_version=disclosure_version,
            granted=granted,
            issued_at=cast(datetime, issued_at),
            expires_at=cast(datetime, expires_at),
            revoked_at=cast(datetime | None, revoked_at),
            commitment_key_id=commitment_key_id,
            receipt_hmac=receipt_hmac,
        )
        changed = await self._uow.run_sync(
            lambda tx: (
                tx.exec_driver_sql(
                    "INSERT INTO guest_session_consent_receipts "
                    "(id,household_id,session_id,challenge_id,presentation_receipt_id,purpose,"
                    "disclosure_version,granted,issued_at,expires_at,revoked_at,"
                    "commitment_key_id,receipt_hmac) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        str(receipt.id),
                        str(household_id),
                        str(session_id),
                        str(challenge_id),
                        str(presentation_receipt_id),
                        purpose,
                        disclosure_version,
                        int(granted),
                        utc_storage(receipt.issued_at),
                        utc_storage(receipt.expires_at),
                        None if receipt.revoked_at is None else utc_storage(receipt.revoked_at),
                        commitment_key_id,
                        receipt_hmac,
                    ),
                ).rowcount
            )
        )
        if changed != 1:
            raise RuntimeError("guest_session_consent_insert_lost_ownership")
        return receipt

    async def latest(
        self,
        household_id: UUID,
        session_id: UUID,
        purpose: GuestConsentPurpose,
    ) -> GuestSessionConsentReceipt | None:
        row = await self._uow.run_sync(
            lambda tx: _row_to_dict(
                tx.exec_driver_sql(
                    "SELECT * FROM guest_session_consent_receipts "
                    "WHERE household_id=? AND session_id=? AND purpose=? "
                    "ORDER BY issued_at DESC,id DESC LIMIT 1",
                    (str(household_id), str(session_id), purpose),
                ).fetchone()
            )
        )
        return None if row is None else _guest_receipt_from_row(row)

    async def lock_current(
        self,
        household_id: UUID,
        session_id: UUID,
        purpose: GuestConsentPurpose,
        now: object,
    ) -> GuestSessionConsentReceipt:
        receipt = await self.latest(household_id, session_id, purpose)
        timestamp = cast(datetime, now)
        if (
            receipt is None
            or not receipt.granted
            or receipt.revoked_at is not None
            or receipt.issued_at > timestamp
            or receipt.expires_at <= timestamp
        ):
            raise ConsentDenied("current_guest_session_consent_required")
        return receipt

    def granted_audit(self, receipt: GuestSessionConsentReceipt, challenge_id: UUID) -> AuditDraft:
        auth = AuthContext(
            grant_id=None,
            subject_id=None,
            binding=_guest_audit_binding(
                receipt.household_id,
                receipt.session_id,
                self._audit_commitments,
            ),
            assurance=AssuranceLevel.GUEST,
            assurance_source="guest",
            consumed_at=receipt.issued_at,
        )
        return _audit(
            "guest.consent.granted",
            auth,
            self._audit_commitments,
            event_id=challenge_id,
        )

    def revoked_audit(self, receipt: GuestSessionConsentReceipt) -> AuditDraft:
        auth = AuthContext(
            grant_id=None,
            subject_id=None,
            binding=_guest_audit_binding(
                receipt.household_id,
                receipt.session_id,
                self._audit_commitments,
            ),
            assurance=AssuranceLevel.GUEST,
            assurance_source="guest",
            consumed_at=receipt.issued_at,
        )
        return _audit(
            "guest.consent.revoked",
            auth,
            self._audit_commitments,
            event_id=receipt.id,
        )


@dataclass(frozen=True, slots=True)
class NetworkRevocationSummary:
    network_started_reservation_ids: tuple[UUID, ...]
    downstream_effect_receipt: DownstreamEffectReceipt
    reservations_settled_atomically: bool = False


class SqlProviderCallsRevocationRepository:
    def __init__(self, uow: AsyncUnitOfWorkProtocol, clock: ClockCallable) -> None:
        self._uow = uow
        self._clock = clock

    async def reconcile_revoked_subject_once(
        self,
        *,
        event_id: UUID,
        family: str,
        subject_id: UUID,
        through_generation: int,
        idempotency_key: UUID,
    ) -> NetworkRevocationSummary:
        now = self._clock()
        reservation_ids = await self._uow.run_sync(
            lambda tx: _close_and_settle_revoked_subject_provider_calls(tx, subject_id, now)
        )
        return NetworkRevocationSummary(
            reservation_ids,
            DownstreamEffectReceipt(
                uuid5(idempotency_key, "provider-routes"),
                idempotency_key,
                event_id,
                family,
                subject_id,
                through_generation,
                "conservatively_settled",
            ),
            reservations_settled_atomically=True,
        )


class SqlBudgetReservationsRevocationRepository:
    def __init__(self, uow: AsyncUnitOfWorkProtocol, clock: ClockCallable) -> None:
        self._uow = uow
        self._clock = clock

    async def settle_conservative_once(
        self,
        reservation_ids: tuple[UUID, ...],
        *,
        idempotency_key: UUID,
    ) -> None:
        del idempotency_key
        if not reservation_ids:
            return
        now = utc_storage(self._clock())
        for reservation_id in reservation_ids:

            def settle(tx: UnitOfWorkProtocol, item: UUID = reservation_id) -> int:
                return _settle_budget_reservation(tx, item, now)

            await self._uow.run_sync(settle)


class SqlProviderCallsRevocationPort:
    def __init__(self, uow_factory: IdentityUnitOfWorkFactory, clock: ClockCallable) -> None:
        self._uow_factory = uow_factory
        self._clock = clock

    async def reconcile_revoked_subject_once(
        self,
        *,
        event_id: UUID,
        family: str,
        subject_id: UUID,
        through_generation: int,
        idempotency_key: UUID,
    ) -> NetworkRevocationSummary:
        now = self._clock()
        async with self._uow_factory() as uow:
            reservation_ids = await uow.run_sync(
                lambda tx: _close_and_settle_revoked_subject_provider_calls(
                    tx,
                    subject_id,
                    now,
                )
            )
            await uow.commit()
        return NetworkRevocationSummary(
            reservation_ids,
            DownstreamEffectReceipt(
                uuid5(idempotency_key, "provider-routes"),
                idempotency_key,
                event_id,
                family,
                subject_id,
                through_generation,
                "conservatively_settled",
            ),
            reservations_settled_atomically=True,
        )


class SqlBudgetReservationsRevocationPort:
    def __init__(self, uow_factory: IdentityUnitOfWorkFactory, clock: ClockCallable) -> None:
        self._uow_factory = uow_factory
        self._clock = clock

    async def settle_conservative_once(
        self,
        reservation_ids: tuple[UUID, ...],
        *,
        idempotency_key: UUID,
    ) -> None:
        del idempotency_key
        if not reservation_ids:
            return
        now = utc_storage(self._clock())
        async with self._uow_factory() as uow:
            for reservation_id in reservation_ids:

                def settle(tx: UnitOfWorkProtocol, item: UUID = reservation_id) -> int:
                    return _settle_budget_reservation(tx, item, now)

                await uow.run_sync(settle)
            await uow.commit()


def _settle_budget_reservation(
    tx: UnitOfWorkProtocol,
    reservation_id: UUID,
    settled_at: str,
) -> int:
    return tx.exec_driver_sql(
        "UPDATE budget_reservations SET state='settled',"
        "transport_phase='finished',charged_micros_sgd=reserved_micros_sgd,"
        "settled_at=? WHERE id=? AND state IN ('reserved','sent')",
        (settled_at, str(reservation_id)),
    ).rowcount


def _close_and_settle_revoked_subject_provider_calls(
    tx: UnitOfWorkProtocol,
    subject_id: UUID,
    now: datetime,
) -> tuple[UUID, ...]:
    reservation_ids = _close_revoked_subject_provider_calls(tx, subject_id, now)
    settled_at = utc_storage(now)
    for reservation_id in reservation_ids:
        _require_conservative_reservation_settlement(tx, reservation_id, settled_at)
    return reservation_ids


def _require_conservative_reservation_settlement(
    tx: UnitOfWorkProtocol,
    reservation_id: UUID,
    settled_at: str,
) -> None:
    changed = _settle_budget_reservation(tx, reservation_id, settled_at)
    if changed == 1:
        return
    row = tx.exec_driver_sql(
        "SELECT state,transport_phase,reserved_micros_sgd,charged_micros_sgd,settled_at "
        "FROM budget_reservations WHERE id=?",
        (str(reservation_id),),
    ).fetchone()
    if row is None:
        raise RuntimeError("provider_budget_reservation_settlement_unproven")
    state, phase, reserved, charged, recorded_settled_at = row
    try:
        reserved_int = int(str(reserved)) if reserved is not None else None
        charged_int = int(str(charged)) if charged is not None else None
    except ValueError:
        raise RuntimeError("provider_budget_reservation_settlement_unproven") from None
    if (
        str(state) == "settled"
        and str(phase) == "finished"
        and recorded_settled_at is not None
        and charged_int is not None
        and reserved_int is not None
        and charged_int == reserved_int
    ):
        return
    raise RuntimeError("provider_budget_reservation_settlement_unproven")


def _close_revoked_subject_provider_calls(
    tx: UnitOfWorkProtocol,
    subject_id: UUID,
    now: datetime,
) -> tuple[UUID, ...]:
    rows = tx.exec_driver_sql(
        "SELECT call.id,call.authorization_id,call.budget_reservation_id,"
        "call.transport_phase,setting.key,setting.value_json "
        "FROM provider_calls AS call "
        "LEFT JOIN runtime_settings AS setting "
        "ON setting.key=('route.authorization.' || call.authorization_id) "
        "WHERE call.outcome='started'",
    ).fetchall()
    network_started: list[UUID] = []
    for call_id, authorization_id, reservation_id, phase, setting_key, raw in rows:
        if setting_key is None:
            raise RuntimeError("provider_route_authority_metadata_corrupt")
        if type(raw) is not str:
            raise RuntimeError("provider_route_authority_metadata_corrupt")
        try:
            envelope = _parse_persisted_route_envelope(raw)
        except PermissionError:
            raise RuntimeError("provider_route_authority_metadata_corrupt") from None
        if str(envelope.route.authorization_id) != str(authorization_id):
            raise RuntimeError("provider_route_authority_metadata_corrupt")
        if envelope.route.subject_id != subject_id:
            continue
        if phase == "claim_begun":
            outcome = "cancelled"
        elif phase in {"marked_sent", "network_invocation_starting"}:
            outcome = "ambiguous"
            if reservation_id is None:
                raise RuntimeError("provider_route_authority_metadata_corrupt")
            try:
                network_started.append(UUID(str(reservation_id)))
            except ValueError:
                raise RuntimeError("provider_route_authority_metadata_corrupt") from None
        else:
            raise RuntimeError("provider_call_transport_phase_unknown")
        tx.exec_driver_sql(
            "UPDATE provider_calls SET outcome=?,transport_phase='finished',finished_at=? "
            "WHERE id=? AND outcome='started' AND transport_phase=?",
            (outcome, utc_storage(now), str(call_id), str(phase)),
        )
    return tuple(network_started)
