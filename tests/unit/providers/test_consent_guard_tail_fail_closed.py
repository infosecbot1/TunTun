from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

import pytest
from tuntun_core.domain.profile import (
    ConsentPurpose,
    ConsentReceipt,
    GuestSessionConsentReceipt,
)
from tuntun_core.services.identity.consent import ConsentDenied
from tuntun_core.services.providers.consent_guard import (
    ConsentEvidenceService,
    ConsentHmacVerifier,
)

NOW = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
HOUSEHOLD_ID = UUID("11111111-1111-4111-8111-111111111111")
OTHER_HOUSEHOLD_ID = UUID("22222222-2222-4222-8222-222222222222")
SUBJECT_ID = UUID("33333333-3333-4333-8333-333333333333")
ACTOR_ID = UUID("44444444-4444-4444-8444-444444444444")
SESSION_ID = UUID("55555555-5555-4555-8555-555555555555")
OTHER_SESSION_ID = UUID("66666666-6666-4666-8666-666666666666")
RECEIPT_ID = UUID("77777777-7777-4777-8777-777777777777")
OTHER_RECEIPT_ID = UUID("88888888-8888-4888-8888-888888888888")
CHALLENGE_ID = UUID("99999999-9999-4999-8999-999999999999")
PRESENTATION_RECEIPT_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
_DEFAULT_RECEIPT = object()


@dataclass(frozen=True, slots=True)
class _GuestSession:
    expires_at: datetime


class _Clock:
    def __init__(self, now: datetime = NOW) -> None:
        self._now = now
        self.calls = 0

    def now(self) -> datetime:
        self.calls += 1
        return self._now


class _SubjectConsentService:
    def __init__(
        self,
        *,
        hmac_receipt: ConsentReceipt | None = None,
        uow_receipt: ConsentReceipt | None = None,
        uow_error: BaseException | None = None,
    ) -> None:
        self.hmac_receipt = hmac_receipt or _subject_receipt()
        self.uow_receipt = uow_receipt or self.hmac_receipt
        self.uow_error = uow_error
        self.hmac_calls: list[tuple[UUID, UUID, ConsentPurpose, datetime]] = []
        self.uow_calls: list[tuple[UUID, ConsentPurpose, datetime]] = []

    async def require_current_hmac_valid(
        self,
        household_id: UUID,
        subject_id: UUID,
        purpose: ConsentPurpose,
        now: datetime,
    ) -> ConsentReceipt:
        self.hmac_calls.append((household_id, subject_id, purpose, now))
        return self.hmac_receipt

    async def require_current_in_uow(
        self,
        _uow: object,
        subject_id: UUID,
        purpose: ConsentPurpose,
        now: datetime,
    ) -> ConsentReceipt:
        self.uow_calls.append((subject_id, purpose, now))
        if self.uow_error is not None:
            raise self.uow_error
        return self.uow_receipt


class _GuestSessionConsentService:
    def __init__(self, receipt: GuestSessionConsentReceipt | None = None) -> None:
        self.receipt = receipt or _guest_receipt()
        self.calls: list[tuple[UUID, UUID, object, datetime]] = []

    async def require_current_hmac_valid(
        self,
        household_id: UUID,
        session_id: UUID,
        purpose: object,
        now: datetime,
    ) -> GuestSessionConsentReceipt:
        self.calls.append((household_id, session_id, purpose, now))
        return self.receipt


class _SessionsRepository:
    def __init__(self, *, expires_at: datetime | None = None, error: BaseException | None = None):
        self.session = _GuestSession(expires_at or NOW + timedelta(minutes=30))
        self.error = error
        self.calls: list[tuple[UUID, UUID, datetime]] = []

    async def require_active(
        self,
        household_id: UUID,
        session_id: UUID,
        now: datetime,
    ) -> _GuestSession:
        self.calls.append((household_id, session_id, now))
        if self.error is not None:
            raise self.error
        return self.session


class _GuestReceiptRepository:
    def __init__(self, receipt: GuestSessionConsentReceipt | None) -> None:
        self.receipt = receipt
        self.calls: list[tuple[UUID, UUID, object]] = []

    async def latest(
        self,
        household_id: UUID,
        session_id: UUID,
        purpose: object,
    ) -> GuestSessionConsentReceipt | None:
        self.calls.append((household_id, session_id, purpose))
        return self.receipt


class _UnitOfWork:
    def __init__(
        self,
        receipt: GuestSessionConsentReceipt | None | object = _DEFAULT_RECEIPT,
        *,
        session_expires_at: datetime | None = None,
        session_error: BaseException | None = None,
    ) -> None:
        self.sessions = _SessionsRepository(expires_at=session_expires_at, error=session_error)
        selected = (
            _guest_receipt()
            if receipt is _DEFAULT_RECEIPT
            else cast(GuestSessionConsentReceipt | None, receipt)
        )
        self.guest_session_consents = _GuestReceiptRepository(selected)


class _Signer:
    def __init__(self, valid: bool = True) -> None:
        self.valid = valid
        self.calls: list[tuple[str, str, tuple[object, ...], bytes]] = []

    def verify_fields(
        self,
        purpose: str,
        key_id: str,
        fields: tuple[object, ...],
        expected_hmac: bytes,
    ) -> bool:
        self.calls.append((purpose, key_id, fields, expected_hmac))
        return self.valid


def _subject_receipt(
    *,
    receipt_id: UUID = RECEIPT_ID,
    household_id: UUID = HOUSEHOLD_ID,
    subject_id: UUID = SUBJECT_ID,
    purpose: ConsentPurpose = ConsentPurpose.CLOUD_REASONING,
    expires_at: datetime | None = None,
) -> ConsentReceipt:
    return ConsentReceipt(
        id=receipt_id,
        household_id=household_id,
        subject_id=subject_id,
        actor_id=ACTOR_ID,
        guardian_id=None,
        guardian_generation=None,
        purpose=purpose,
        granted=True,
        policy_version="phase1-v1",
        disclosure_version="phase1-disclosure-v1",
        commitment_key_id="subject-consent-key",
        receipt_hmac=b"s" * 32,
        created_at=NOW,
        expires_at=expires_at,
    )


def _guest_receipt(
    *,
    receipt_id: UUID = RECEIPT_ID,
    household_id: UUID = HOUSEHOLD_ID,
    session_id: UUID = SESSION_ID,
    purpose: str = "cloud_tts",
    granted: bool = True,
    issued_at: datetime = NOW - timedelta(minutes=1),
    expires_at: datetime = NOW + timedelta(minutes=10),
    revoked_at: datetime | None = None,
) -> GuestSessionConsentReceipt:
    return GuestSessionConsentReceipt(
        id=receipt_id,
        household_id=household_id,
        session_id=session_id,
        challenge_id=CHALLENGE_ID,
        presentation_receipt_id=PRESENTATION_RECEIPT_ID,
        purpose=purpose,  # type: ignore[arg-type]
        disclosure_version="phase1-guest-disclosure-v1",
        granted=granted,
        issued_at=issued_at,
        expires_at=expires_at,
        revoked_at=revoked_at,
        commitment_key_id="guest-consent-key",
        receipt_hmac=b"g" * 32,
    )


@pytest.mark.asyncio
async def test_evidence_service_collects_subject_consent_receipts() -> None:
    receipt = _subject_receipt(expires_at=NOW + timedelta(days=1))
    consents = _SubjectConsentService(hmac_receipt=receipt)
    guests = _GuestSessionConsentService()
    service = ConsentEvidenceService(consents, guests)

    evidence = await service.require(
        HOUSEHOLD_ID,
        SUBJECT_ID,
        SESSION_ID,
        ("cloud_reasoning",),
        NOW,
    )

    assert [item.receipt_id for item in evidence] == [RECEIPT_ID]
    assert evidence[0].subject_id == SUBJECT_ID
    assert evidence[0].session_id is None
    assert evidence[0].purpose == "cloud_reasoning"
    assert evidence[0].expires_at == NOW + timedelta(days=1)
    assert consents.hmac_calls == [(HOUSEHOLD_ID, SUBJECT_ID, ConsentPurpose.CLOUD_REASONING, NOW)]
    assert guests.calls == []


@pytest.mark.asyncio
async def test_evidence_service_collects_guest_session_consent_receipts() -> None:
    receipt = _guest_receipt(expires_at=NOW + timedelta(minutes=5))
    consents = _SubjectConsentService()
    guests = _GuestSessionConsentService(receipt)
    service = ConsentEvidenceService(consents, guests)

    evidence = await service.require(
        HOUSEHOLD_ID,
        None,
        SESSION_ID,
        ("cloud_tts",),
        NOW,
    )

    assert [item.receipt_id for item in evidence] == [RECEIPT_ID]
    assert evidence[0].subject_id is None
    assert evidence[0].session_id == SESSION_ID
    assert evidence[0].purpose == "cloud_tts"
    assert evidence[0].expires_at == NOW + timedelta(minutes=5)
    assert guests.calls == [(HOUSEHOLD_ID, SESSION_ID, "cloud_tts", NOW)]
    assert consents.hmac_calls == []


@pytest.mark.asyncio
async def test_evidence_service_rejects_non_guest_route_purpose() -> None:
    service = ConsentEvidenceService(_SubjectConsentService(), _GuestSessionConsentService())

    with pytest.raises(PermissionError, match="guest_session_consent_required:web_search"):
        await service.require(HOUSEHOLD_ID, None, SESSION_ID, ("web_search",), NOW)


@pytest.mark.asyncio
async def test_subject_exact_consent_accepts_matching_current_receipt() -> None:
    consents = _SubjectConsentService(
        uow_receipt=_subject_receipt(purpose=ConsentPurpose.CLOUD_TTS)
    )
    verifier = ConsentHmacVerifier(_Signer(), consents, _Clock())

    await verifier.require_exact_in_uow(
        object(),
        HOUSEHOLD_ID,
        SUBJECT_ID,
        SESSION_ID,
        "cloud_tts",
        (RECEIPT_ID,),
    )

    assert consents.uow_calls == [(SUBJECT_ID, ConsentPurpose.CLOUD_TTS, NOW)]


@pytest.mark.parametrize("receipt_ids", ((), (RECEIPT_ID, OTHER_RECEIPT_ID)))
@pytest.mark.asyncio
async def test_subject_exact_consent_requires_one_receipt_id(
    receipt_ids: tuple[UUID, ...],
) -> None:
    consents = _SubjectConsentService()
    verifier = ConsentHmacVerifier(_Signer(), consents, _Clock())

    with pytest.raises(PermissionError, match="consent_required:cloud_tts"):
        await verifier.require_exact_in_uow(
            object(),
            HOUSEHOLD_ID,
            SUBJECT_ID,
            SESSION_ID,
            "cloud_tts",
            receipt_ids,
        )

    assert consents.uow_calls == []


@pytest.mark.parametrize(
    "uow_error",
    (
        ConsentDenied("revoked"),
        ValueError("bad current consent"),
    ),
)
@pytest.mark.asyncio
async def test_subject_exact_consent_collapses_current_consent_errors(
    uow_error: BaseException,
) -> None:
    verifier = ConsentHmacVerifier(
        _Signer(),
        _SubjectConsentService(uow_error=uow_error),
        _Clock(),
    )

    with pytest.raises(PermissionError, match="consent_required:cloud_tts"):
        await verifier.require_exact_in_uow(
            object(),
            HOUSEHOLD_ID,
            SUBJECT_ID,
            SESSION_ID,
            "cloud_tts",
            (RECEIPT_ID,),
        )


@pytest.mark.parametrize(
    "receipt",
    (
        _subject_receipt(receipt_id=OTHER_RECEIPT_ID),
        _subject_receipt(household_id=OTHER_HOUSEHOLD_ID),
    ),
)
@pytest.mark.asyncio
async def test_subject_exact_consent_rejects_mismatched_receipt_identity(
    receipt: ConsentReceipt,
) -> None:
    verifier = ConsentHmacVerifier(
        _Signer(),
        _SubjectConsentService(uow_receipt=receipt),
        _Clock(),
    )

    with pytest.raises(PermissionError, match="consent_required:cloud_reasoning"):
        await verifier.require_exact_in_uow(
            object(),
            HOUSEHOLD_ID,
            SUBJECT_ID,
            SESSION_ID,
            "cloud_reasoning",
            (RECEIPT_ID,),
        )


@pytest.mark.asyncio
async def test_guest_exact_consent_accepts_current_hmac_bound_receipt() -> None:
    receipt = _guest_receipt()
    signer = _Signer()
    verifier = ConsentHmacVerifier(signer, _SubjectConsentService(), _Clock())
    uow = _UnitOfWork(receipt, session_expires_at=NOW + timedelta(minutes=20))

    await verifier.require_exact_in_uow(
        uow,
        HOUSEHOLD_ID,
        None,
        SESSION_ID,
        "cloud_tts",
        (RECEIPT_ID,),
    )

    assert uow.sessions.calls == [(HOUSEHOLD_ID, SESSION_ID, NOW)]
    assert uow.guest_session_consents.calls == [(HOUSEHOLD_ID, SESSION_ID, "cloud_tts")]
    assert signer.calls == [
        (
            "guest_session_consent_receipt",
            "guest-consent-key",
            (
                HOUSEHOLD_ID,
                SESSION_ID,
                CHALLENGE_ID,
                PRESENTATION_RECEIPT_ID,
                "cloud_tts",
                "phase1-guest-disclosure-v1",
                True,
                NOW - timedelta(minutes=1),
                NOW + timedelta(minutes=10),
                None,
            ),
            b"g" * 32,
        )
    ]


@pytest.mark.parametrize("receipt_ids", ((), (RECEIPT_ID, OTHER_RECEIPT_ID)))
@pytest.mark.asyncio
async def test_guest_exact_consent_requires_one_receipt_id(
    receipt_ids: tuple[UUID, ...],
) -> None:
    signer = _Signer()
    verifier = ConsentHmacVerifier(signer, _SubjectConsentService(), _Clock())
    uow = _UnitOfWork()

    with pytest.raises(PermissionError, match="guest_session_consent_required:cloud_tts"):
        await verifier.require_exact_in_uow(
            uow,
            HOUSEHOLD_ID,
            None,
            SESSION_ID,
            "cloud_tts",
            receipt_ids,
        )

    assert uow.sessions.calls == []
    assert signer.calls == []


@pytest.mark.asyncio
async def test_guest_exact_consent_rejects_non_guest_route_purpose_before_lookup() -> None:
    signer = _Signer()
    verifier = ConsentHmacVerifier(signer, _SubjectConsentService(), _Clock())
    uow = _UnitOfWork()

    with pytest.raises(PermissionError, match="guest_session_consent_required:web_search"):
        await verifier.require_exact_in_uow(
            uow,
            HOUSEHOLD_ID,
            None,
            SESSION_ID,
            "web_search",
            (RECEIPT_ID,),
        )

    assert uow.sessions.calls == []
    assert signer.calls == []


@pytest.mark.asyncio
async def test_guest_exact_consent_collapses_session_lookup_errors() -> None:
    signer = _Signer()
    verifier = ConsentHmacVerifier(signer, _SubjectConsentService(), _Clock())
    uow = _UnitOfWork(session_error=RuntimeError("session store unavailable"))

    with pytest.raises(PermissionError, match="guest_session_consent_required:cloud_tts"):
        await verifier.require_exact_in_uow(
            uow,
            HOUSEHOLD_ID,
            None,
            SESSION_ID,
            "cloud_tts",
            (RECEIPT_ID,),
        )

    assert signer.calls == []


@pytest.mark.parametrize(
    "mutation",
    (
        "missing",
        "wrong_id",
        "wrong_household",
        "wrong_session",
        "wrong_purpose",
        "not_granted",
        "revoked",
        "issued_in_future",
        "expired",
        "longer_than_session",
    ),
)
@pytest.mark.asyncio
async def test_guest_exact_consent_rejects_stale_or_mismatched_receipts(
    mutation: str,
) -> None:
    receipt: GuestSessionConsentReceipt | None = _guest_receipt()
    session_expires_at = NOW + timedelta(minutes=20)
    if mutation == "missing":
        receipt = None
    elif mutation == "wrong_id":
        receipt = _guest_receipt(receipt_id=OTHER_RECEIPT_ID)
    elif mutation == "wrong_household":
        receipt = _guest_receipt(household_id=OTHER_HOUSEHOLD_ID)
    elif mutation == "wrong_session":
        receipt = _guest_receipt(session_id=OTHER_SESSION_ID)
    elif mutation == "wrong_purpose":
        receipt = _guest_receipt(purpose="cloud_stt")
    elif mutation == "not_granted":
        receipt = _guest_receipt(granted=False)
    elif mutation == "revoked":
        receipt = _guest_receipt(revoked_at=NOW)
    elif mutation == "issued_in_future":
        receipt = _guest_receipt(issued_at=NOW + timedelta(seconds=1))
    elif mutation == "expired":
        receipt = _guest_receipt(expires_at=NOW)
    elif mutation == "longer_than_session":
        session_expires_at = NOW + timedelta(minutes=1)

    signer = _Signer()
    verifier = ConsentHmacVerifier(signer, _SubjectConsentService(), _Clock())
    uow = _UnitOfWork(receipt, session_expires_at=session_expires_at)

    with pytest.raises(PermissionError, match="guest_session_consent_required:cloud_tts"):
        await verifier.require_exact_in_uow(
            uow,
            HOUSEHOLD_ID,
            None,
            SESSION_ID,
            "cloud_tts",
            (RECEIPT_ID,),
        )

    assert signer.calls == []


@pytest.mark.asyncio
async def test_guest_exact_consent_rejects_invalid_receipt_hmac() -> None:
    signer = _Signer(valid=False)
    verifier = ConsentHmacVerifier(signer, _SubjectConsentService(), _Clock())

    with pytest.raises(PermissionError, match="guest_session_consent_required:cloud_tts"):
        await verifier.require_exact_in_uow(
            _UnitOfWork(_guest_receipt()),
            HOUSEHOLD_ID,
            None,
            SESSION_ID,
            "cloud_tts",
            (RECEIPT_ID,),
        )

    assert signer.calls
