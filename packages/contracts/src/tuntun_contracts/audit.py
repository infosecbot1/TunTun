# packages/contracts/src/tuntun_contracts/audit.py
from __future__ import annotations

from typing import Annotated
from uuid import UUID

from pydantic import AwareDatetime, Field

from .base import Commitment, ContractModel


class AuditDraft(ContractModel):
    event_id: UUID
    occurred_at: AwareDatetime
    actor_pseudonym: str
    action_code: str
    outcome: str
    reason_code: str
    correlation_id: UUID
    payload_commitment: Commitment


class AuditReceipt(ContractModel):
    receipt_id: UUID
    ordinal: Annotated[int, Field(ge=1)]
    public_hash_hex: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    hmac_key_id: str
    hmac_b64: str
    occurred_at: AwareDatetime
