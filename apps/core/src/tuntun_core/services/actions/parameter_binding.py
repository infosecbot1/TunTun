from __future__ import annotations

import hmac
from collections.abc import Mapping
from typing import Protocol, cast
from uuid import UUID

import rfc8785
from rfc8785._impl import _Value as Rfc8785Value
from tuntun_contracts.actions import ActionBinding
from tuntun_contracts.base import Commitment
from tuntun_contracts.commitments import commit_private
from tuntun_contracts.identity import PersonaTraits
from tuntun_core.domain.profile import ConsentPurpose, GrantConsent, ProfileClass, RevokeConsent


class _ProfileCreateCommand(Protocol):
    household_id: UUID
    subject_id: UUID
    profile_class: ProfileClass
    guardian_id: UUID | None
    display_label: str


class _ProfilePersonaCommand(Protocol):
    subject_id: UUID
    target_profile_class: ProfileClass
    traits: PersonaTraits | None
    expected_version: int
    guardian_generation: int | None


class _ProfileRevokeCommand(Protocol):
    subject_id: UUID
    expected_version: int


class _ConsentCommand(Protocol):
    subject_id: UUID
    purpose: ConsentPurpose
    expected_latest_receipt_id: UUID | None
    guardian_generation: int | None
    policy_version: str
    disclosure_version: str


class _EnrollmentRequestCommand(Protocol):
    subject_id: UUID
    modality: object
    expected_profile_version: int
    expected_consent_receipt_id: UUID
    reenrollment_days: int


class _EnrollmentCancelCommand(Protocol):
    subject_id: UUID
    enrollment_id: UUID


class _TimerCreateRequest(Protocol):
    duration_seconds: int
    label: str | None


def profile_create_parameters(command: _ProfileCreateCommand) -> dict[str, object]:
    return {
        "display_label": command.display_label,
        "guardian_generation": 1 if command.guardian_id is not None else 0,
        "guardian_id": None if command.guardian_id is None else str(command.guardian_id),
        "household_id": str(command.household_id),
        "profile_class": command.profile_class.value,
        "subject_id": str(command.subject_id),
    }


def profile_persona_parameters(command: _ProfilePersonaCommand) -> dict[str, object]:
    return {
        "clear_persona_traits": command.traits is None,
        "expected_version": command.expected_version,
        "guardian_generation": command.guardian_generation,
        "persona_traits": None
        if command.traits is None
        else command.traits.model_dump(mode="json"),
        "subject_id": str(command.subject_id),
        "target_profile_class": command.target_profile_class.value,
    }


def profile_revoke_parameters(command: _ProfileRevokeCommand) -> dict[str, object]:
    return {"expected_version": command.expected_version, "subject_id": str(command.subject_id)}


def consent_parameters(command: GrantConsent | RevokeConsent) -> dict[str, object]:
    return {
        "disclosure_version": command.disclosure_version,
        "expected_latest_receipt_id": None
        if command.expected_latest_receipt_id is None
        else str(command.expected_latest_receipt_id),
        "guardian_generation": command.guardian_generation,
        "policy_version": command.policy_version,
        "purpose": command.purpose.value,
        "subject_id": str(command.subject_id),
    }


def enrollment_request_parameters(command: _EnrollmentRequestCommand) -> dict[str, object]:
    modality = getattr(command.modality, "value", command.modality)
    return {
        "expected_consent_receipt_id": str(command.expected_consent_receipt_id),
        "expected_profile_version": command.expected_profile_version,
        "modality": modality,
        "reenrollment_days": command.reenrollment_days,
        "subject_id": str(command.subject_id),
    }


def enrollment_cancel_parameters(command: _EnrollmentCancelCommand) -> dict[str, object]:
    return {"enrollment_id": str(command.enrollment_id), "subject_id": str(command.subject_id)}


def timer_create_parameters(request: _TimerCreateRequest) -> dict[str, object]:
    return {
        "duration_seconds": request.duration_seconds,
        "label": request.label,
    }


def timer_target_parameters(timer_id: UUID, idempotency_key: UUID) -> dict[str, object]:
    return {"idempotency_key": str(idempotency_key), "timer_id": str(timer_id)}


def safety_parameters(reason_code: str) -> dict[str, object]:
    return {"reason_code": reason_code}


class ActionParameterBindingVerifier:
    def __init__(self, commitment_root: bytes, *, key_id: str) -> None:
        self._root = commitment_root
        self.key_id = key_id

    def require(
        self,
        binding: ActionBinding,
        *,
        action_name: str,
        resource_type: str,
        resource_id: UUID | None,
        actor_id: UUID | None,
        parameters: Mapping[str, object],
    ) -> None:
        if (
            binding.action_name != action_name
            or binding.resource_type != resource_type
            or binding.resource_id != resource_id
            or binding.subject_id != actor_id
        ):
            raise PermissionError("action_binding_scope_mismatch")
        if binding.parameter_commitment.key_id != self.key_id:
            raise PermissionError("action_parameter_key_mismatch")
        expected = commit_private(
            self._root,
            self.key_id,
            "action.parameters",
            rfc8785.dumps(cast(Rfc8785Value, parameters)),
        )
        if not hmac.compare_digest(
            expected.value_b64.encode("ascii"),
            binding.parameter_commitment.value_b64.encode("ascii"),
        ):
            raise PermissionError("action_parameter_commitment_mismatch")


class ActionBindingVerifier:
    def require_exact(self, stored: ActionBinding, supplied: ActionBinding) -> None:
        ordinary = (
            stored.household_id == supplied.household_id
            and stored.proposal_id == supplied.proposal_id
            and stored.turn_id == supplied.turn_id
            and stored.idempotency_key == supplied.idempotency_key
            and stored.action_name == supplied.action_name
            and stored.resource_type == supplied.resource_type
            and stored.resource_id == supplied.resource_id
            and stored.policy_version == supplied.policy_version
            and stored.session_id == supplied.session_id
            and stored.subject_id == supplied.subject_id
            and stored.parameter_commitment.algorithm == supplied.parameter_commitment.algorithm
            and stored.parameter_commitment.key_id == supplied.parameter_commitment.key_id
        )
        commitment_equal = hmac.compare_digest(
            stored.parameter_commitment.value_b64.encode("ascii"),
            supplied.parameter_commitment.value_b64.encode("ascii"),
        )
        if not ordinary or not commitment_equal:
            raise PermissionError("action_binding_mismatch")

    def require_parts(
        self,
        stored: ActionBinding,
        *,
        household_id: UUID,
        proposal_id: UUID,
        turn_id: UUID,
        idempotency_key: UUID,
        action_name: str,
        resource_type: str,
        resource_id: UUID | None,
        parameter_commitment: Commitment,
        policy_version: str,
        session_id: UUID,
        subject_id: UUID | None,
    ) -> None:
        supplied = ActionBinding(
            household_id=household_id,
            proposal_id=proposal_id,
            turn_id=turn_id,
            idempotency_key=idempotency_key,
            action_name=action_name,
            resource_type=resource_type,
            resource_id=resource_id,
            parameter_commitment=parameter_commitment,
            policy_version=policy_version,
            session_id=session_id,
            subject_id=subject_id,
        )
        self.require_exact(stored, supplied)
