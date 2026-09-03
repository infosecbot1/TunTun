from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, cast
from uuid import UUID

from tuntun_core.domain.profile import (
    ConsentPurpose,
    ConsentReceipt,
    GuestConsentPurpose,
    GuestSessionConsentReceipt,
)
from tuntun_core.services.identity.consent import ConsentDenied
from tuntun_core.services.transactions.identity_uow import IdentityUnitOfWork

_GUEST_ROUTE_PURPOSES = frozenset({"cloud_stt", "cloud_reasoning", "cloud_tts"})


@dataclass(frozen=True, slots=True)
class ConsentEvidence:
    receipt_id: UUID
    household_id: UUID
    subject_id: UUID | None
    session_id: UUID | None
    purpose: str
    expires_at: datetime | None


class SubjectConsentServicePort(Protocol):
    async def require_current_in_uow(
        self,
        uow: IdentityUnitOfWork,
        subject_id: UUID,
        purpose: ConsentPurpose,
        now: datetime,
    ) -> ConsentReceipt: ...

    async def require_current_hmac_valid(
        self,
        household_id: UUID,
        subject_id: UUID,
        purpose: ConsentPurpose,
        now: datetime,
    ) -> ConsentReceipt: ...


class GuestSessionConsentServicePort(Protocol):
    async def require_current_hmac_valid(
        self,
        household_id: UUID,
        session_id: UUID,
        purpose: ConsentPurpose | GuestConsentPurpose,
        now: datetime,
    ) -> GuestSessionConsentReceipt: ...


class ReceiptSignerPort(Protocol):
    def verify_fields(
        self,
        purpose: str,
        key_id: str,
        fields: tuple[object, ...],
        expected_hmac: bytes,
    ) -> bool: ...


class ClockPort(Protocol):
    def now(self) -> datetime: ...


class ConsentEvidenceService:
    def __init__(
        self,
        consents: SubjectConsentServicePort,
        guest_sessions: GuestSessionConsentServicePort,
    ) -> None:
        self._consents = consents
        self._guest_sessions = guest_sessions

    async def require(
        self,
        household_id: UUID,
        subject_id: UUID | None,
        session_id: UUID,
        purposes: tuple[str, ...],
        now: datetime,
    ) -> tuple[ConsentEvidence, ...]:
        evidence: list[ConsentEvidence] = []
        for purpose in purposes:
            if subject_id is None:
                guest_receipt = await self._guest_sessions.require_current_hmac_valid(
                    household_id,
                    session_id,
                    _guest_purpose(purpose),
                    now,
                )
                evidence.append(
                    ConsentEvidence(
                        guest_receipt.id,
                        household_id,
                        None,
                        session_id,
                        purpose,
                        guest_receipt.expires_at,
                    )
                )
            else:
                subject_receipt = await self._consents.require_current_hmac_valid(
                    household_id,
                    subject_id,
                    ConsentPurpose(purpose),
                    now,
                )
                evidence.append(
                    ConsentEvidence(
                        subject_receipt.id,
                        household_id,
                        subject_id,
                        None,
                        purpose,
                        subject_receipt.expires_at,
                    )
                )
        return tuple(evidence)


class ConsentHmacVerifier:
    def __init__(
        self,
        receipt_signer: ReceiptSignerPort,
        consent_service: SubjectConsentServicePort,
        clock: ClockPort,
    ) -> None:
        self._signer = receipt_signer
        self._consents = consent_service
        self._clock = clock

    async def require_exact_in_uow(
        self,
        uow: object,
        household_id: UUID,
        subject_id: UUID | None,
        session_id: UUID,
        purpose: str,
        receipt_ids: tuple[UUID, ...],
    ) -> None:
        if subject_id is None:
            await self._require_guest_exact_in_uow(
                cast(IdentityUnitOfWork, uow),
                household_id,
                session_id,
                purpose,
                receipt_ids,
            )
            return
        await self._require_subject_exact_in_uow(
            cast(IdentityUnitOfWork, uow),
            household_id,
            subject_id,
            purpose,
            receipt_ids,
        )

    async def _require_subject_exact_in_uow(
        self,
        uow: IdentityUnitOfWork,
        household_id: UUID,
        subject_id: UUID,
        purpose: str,
        receipt_ids: tuple[UUID, ...],
    ) -> None:
        if len(receipt_ids) != 1:
            raise PermissionError(f"consent_required:{purpose}")
        try:
            receipt = await self._consents.require_current_in_uow(
                uow,
                subject_id,
                ConsentPurpose(purpose),
                self._clock.now(),
            )
        except (ConsentDenied, ValueError) as exc:
            raise PermissionError(f"consent_required:{purpose}") from exc
        if receipt.household_id != household_id or receipt.id != receipt_ids[0]:
            raise PermissionError(f"consent_required:{purpose}")

    async def _require_guest_exact_in_uow(
        self,
        uow: IdentityUnitOfWork,
        household_id: UUID,
        session_id: UUID,
        purpose: str,
        receipt_ids: tuple[UUID, ...],
    ) -> None:
        if len(receipt_ids) != 1:
            raise PermissionError(f"guest_session_consent_required:{purpose}")
        now = self._clock.now()
        guest_purpose = _guest_purpose(purpose)
        try:
            session = await uow.sessions.require_active(household_id, session_id, now)
            receipt = await uow.guest_session_consents.latest(
                household_id,
                session_id,
                guest_purpose,
            )
        except Exception as exc:
            raise PermissionError(f"guest_session_consent_required:{purpose}") from exc
        if (
            receipt is None
            or receipt.id != receipt_ids[0]
            or receipt.household_id != household_id
            or receipt.session_id != session_id
            or receipt.purpose != guest_purpose
            or not receipt.granted
            or receipt.revoked_at is not None
            or receipt.issued_at > now
            or receipt.expires_at <= now
            or receipt.expires_at > session.expires_at
        ):
            raise PermissionError(f"guest_session_consent_required:{purpose}")
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
            raise PermissionError(f"guest_session_consent_required:{purpose}")


def _guest_purpose(purpose: str) -> GuestConsentPurpose:
    if purpose not in _GUEST_ROUTE_PURPOSES:
        raise PermissionError(f"guest_session_consent_required:{purpose}")
    return cast(GuestConsentPurpose, purpose)
