from __future__ import annotations

from datetime import datetime
from typing import Protocol

from tuntun_contracts.audit import AuditDraft
from tuntun_contracts.policy import AuthContext
from tuntun_core.domain.profile import ConsentPurpose, ConsentReceipt
from tuntun_core.services.transactions.identity_uow import IdentityUnitOfWork

_MANAGED_ERASURE_STORES = ("sqlcipher_wal", "managed_backup")


class AuditLedgerPort(Protocol):
    async def append(self, uow: IdentityUnitOfWork, draft: AuditDraft) -> None: ...


class BiometricConsentRevocationHandler:
    """Cancel active ceremonies and revoke face/voice templates for a consent revoke."""

    _MODALITIES = {
        ConsentPurpose.FACE: "face",
        ConsentPurpose.VOICE: "voice",
    }

    def __init__(self, audit_ledger: AuditLedgerPort) -> None:
        self._audit = audit_ledger

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
        await uow.enrollments.cancel_subject_modality(receipt.subject_id, modality, now)
        revoked = await uow.biometric_templates.revoke_subject_modality(
            receipt.subject_id,
            modality,
            now,
        )
        await uow.sessions.invalidate_identity_subject(
            receipt.subject_id,
            "biometric_consent_revoked",
            now,
        )
        for template in revoked:
            await self._audit.append(
                uow,
                uow.biometric_templates.managed_erasure_requested_audit(
                    template,
                    stores=_MANAGED_ERASURE_STORES,
                    requested_at=now,
                ),
            )
