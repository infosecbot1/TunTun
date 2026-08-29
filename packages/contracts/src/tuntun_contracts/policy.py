# packages/contracts/src/tuntun_contracts/policy.py
from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from .actions import ActionBinding, ActionProposalDraft
from .base import Commitment, ContractModel


class RiskTier(StrEnum):
    PERSONALIZATION = "personalization"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AssuranceLevel(StrEnum):
    GUEST = "guest"
    IDENTIFIED = "identified"
    CONFIRMED = "confirmed"
    PIN_VERIFIED = "pin_verified"
    PASSKEY_VERIFIED = "passkey_verified"
    RECOVERY_VERIFIED = "recovery_verified"


class PolicyEffect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    STEP_UP = "step_up"


class PolicyRequest(ContractModel):
    household_id: UUID
    subject_id: UUID | None
    action: ActionProposalDraft
    requested_risk: RiskTier
    assurance: AssuranceLevel


class PolicyDecision(ContractModel):
    effect: PolicyEffect
    reason_code: str
    policy_version: str
    required_assurance: AssuranceLevel | None
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def exact_step_up_shape(self) -> Self:
        if self.effect is PolicyEffect.STEP_UP:
            if self.required_assurance not in {
                AssuranceLevel.CONFIRMED,
                AssuranceLevel.PIN_VERIFIED,
                AssuranceLevel.PASSKEY_VERIFIED,
                AssuranceLevel.RECOVERY_VERIFIED,
            }:
                raise ValueError("step-up requires elevated assurance")
        elif self.required_assurance is not None:
            raise ValueError("non-step-up decision cannot require assurance")
        return self


class AuthenticationRequest(ContractModel):
    subject_id: UUID
    binding: ActionBinding
    requested_assurance: AssuranceLevel

    @model_validator(mode="after")
    def subject_matches_binding(self) -> Self:
        if self.subject_id != self.binding.subject_id:
            raise ValueError("authentication subject binding mismatch")
        return self


class AuthenticationChallenge(ContractModel):
    challenge_id: UUID
    subject_id: UUID
    binding: ActionBinding
    factor: Literal["confirmation", "pin", "passkey"]
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def subject_matches_binding(self) -> Self:
        if self.subject_id != self.binding.subject_id:
            raise ValueError("authentication subject binding mismatch")
        return self


class AuthenticationResponse(ContractModel):
    challenge_id: UUID
    response: Annotated[str, Field(min_length=1, max_length=16_384)]
    occurred_at: AwareDatetime


class AuthGrant(ContractModel):
    grant_id: UUID
    subject_id: UUID
    binding: ActionBinding
    assurance: AssuranceLevel
    assurance_source: Literal["explicit_confirmation", "pin", "passkey", "recovery"]
    issued_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def source_matches_assurance(self) -> Self:
        expected = {
            "explicit_confirmation": AssuranceLevel.CONFIRMED,
            "pin": AssuranceLevel.PIN_VERIFIED,
            "passkey": AssuranceLevel.PASSKEY_VERIFIED,
            "recovery": AssuranceLevel.RECOVERY_VERIFIED,
        }
        if self.assurance is not expected[self.assurance_source]:
            raise ValueError("assurance source mismatch")
        if self.subject_id != self.binding.subject_id:
            raise ValueError("authentication subject binding mismatch")
        if self.expires_at <= self.issued_at:
            raise ValueError("authentication grant expiry ordering")
        return self


class AuthContext(ContractModel):
    grant_id: UUID | None
    subject_id: UUID | None
    binding: ActionBinding
    assurance: AssuranceLevel
    assurance_source: Literal[
        "guest",
        "identity",
        "explicit_confirmation",
        "pin",
        "passkey",
        "recovery",
    ]
    consumed_at: AwareDatetime

    @model_validator(mode="after")
    def source_matches_assurance(self) -> Self:
        expected = {
            "guest": AssuranceLevel.GUEST,
            "identity": AssuranceLevel.IDENTIFIED,
            "explicit_confirmation": AssuranceLevel.CONFIRMED,
            "pin": AssuranceLevel.PIN_VERIFIED,
            "passkey": AssuranceLevel.PASSKEY_VERIFIED,
            "recovery": AssuranceLevel.RECOVERY_VERIFIED,
        }
        if self.assurance is not expected[self.assurance_source]:
            raise ValueError("assurance source mismatch")
        if self.subject_id != self.binding.subject_id:
            raise ValueError("authentication context subject binding mismatch")
        if self.assurance_source == "guest":
            if self.subject_id is not None or self.grant_id is not None:
                raise ValueError("guest authentication context shape")
        elif self.assurance_source == "identity":
            if self.subject_id is None or self.grant_id is not None:
                raise ValueError("identity authentication context shape")
        elif self.subject_id is None or self.grant_id is None:
            raise ValueError("grant-backed authentication context shape")
        return self


class CurrentOwnerAuthority(ContractModel):
    household_id: UUID
    subject_id: UUID
    owner_generation: Annotated[int, Field(ge=1)]
    profile_version: Annotated[int, Field(ge=1)]
    observed_at: AwareDatetime


class AdminSessionPrincipal(ContractModel):
    admin_session_id: UUID
    household_id: UUID
    subject_id: UUID
    owner_generation: Annotated[int, Field(ge=1)]
    profile_version: Annotated[int, Field(ge=1)]
    session_version: Annotated[int, Field(ge=1)]
    access_mode: Literal["loopback", "lan_https"]
    authenticated_at: AwareDatetime
    idle_expires_at: AwareDatetime
    absolute_expires_at: AwareDatetime

    @model_validator(mode="after")
    def expiry_ordering(self) -> Self:
        if not self.authenticated_at < self.idle_expires_at <= self.absolute_expires_at:
            raise ValueError("admin session expiry ordering")
        return self


class TimerIntent(ContractModel):
    timer_id: UUID
    operation: Literal["create", "cancel", "status"]
    duration_seconds: Annotated[int, Field(ge=1, le=86_400)] | None
    label_commitment: Commitment | None
    idempotency_key: UUID

    @model_validator(mode="after")
    def exact_operation_payload(self) -> Self:
        create_payload = self.duration_seconds is not None and self.label_commitment is not None
        if (self.operation == "create") != create_payload:
            raise ValueError("timer intent operation payload mismatch")
        if self.operation != "create" and (
            self.duration_seconds is not None or self.label_commitment is not None
        ):
            raise ValueError("timer intent operation payload mismatch")
        return self
