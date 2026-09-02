from __future__ import annotations

from collections.abc import Mapping
from datetime import timedelta
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from pydantic import Field, model_validator
from tuntun_contracts.actions import (
    ActionBinding,
    SafetyActionDraft,
    TimerCreateActionDraft,
    TimerTargetActionDraft,
)
from tuntun_contracts.base import Commitment, ContractModel, Sensitivity, canonical_mapping_bytes
from tuntun_contracts.commitments import commit_private
from tuntun_contracts.memory import (
    MemoryAudience,
    MemoryProposalDraft,
    PreferenceContent,
)


class _IntentBase(ContractModel):
    confidence_micros: Annotated[int, Field(ge=0, le=1_000_000)]
    reason: Annotated[str, Field(min_length=1, max_length=256)]


class RememberPreferenceIntent(_IntentBase):
    kind: Literal["remember_preference"]
    subject_ref: Annotated[str, Field(min_length=1, max_length=128)]
    category: Annotated[str, Field(min_length=1, max_length=128)]
    key: Annotated[str, Field(min_length=1, max_length=128)]
    value: Annotated[str, Field(min_length=1, max_length=2_000)]


class ForgetMemoryIntent(_IntentBase):
    kind: Literal["forget_memory"]
    subject_ref: Annotated[str, Field(min_length=1, max_length=128)]
    memory_ref: Annotated[str, Field(min_length=1, max_length=128)]


class TimerCreateIntent(_IntentBase):
    kind: Literal["timer_create"]
    duration_seconds: Annotated[int, Field(ge=1, le=86_400)]
    label: Annotated[str, Field(min_length=1, max_length=64)]


class TimerCancelIntent(_IntentBase):
    kind: Literal["timer_cancel"]
    timer_ref: Annotated[str, Field(min_length=1, max_length=128)]


ProviderMemoryIntent = Annotated[  # noqa: UP040 -- runtime Pydantic alias.
    RememberPreferenceIntent | ForgetMemoryIntent,
    Field(discriminator="kind"),
]
ProviderActionIntent = Annotated[  # noqa: UP040 -- runtime Pydantic alias.
    TimerCreateIntent | TimerCancelIntent,
    Field(discriminator="kind"),
]


class AssistantTurn(ContractModel):
    answer_text: Annotated[str, Field(min_length=1, max_length=8_000)]
    answer_language: Literal["en", "hi", "hinglish"]
    memory_proposals: Annotated[tuple[ProviderMemoryIntent, ...], Field(max_length=8)] = ()
    action_proposals: Annotated[tuple[ProviderActionIntent, ...], Field(max_length=8)] = ()
    uncertainty_micros: Annotated[int, Field(ge=0, le=1_000_000)]

    @model_validator(mode="before")
    @classmethod
    def provider_arrays_are_tuples_for_python_validation(cls, value: Any) -> Any:
        if isinstance(value, Mapping):
            updated = dict(value)
            for key in ("memory_proposals", "action_proposals"):
                if type(updated.get(key)) is list:
                    updated[key] = tuple(updated[key])
            return updated
        return value


class ProposalMapper:
    def __init__(
        self,
        refs: Any,
        provenance: Any,
        verified_response_receipt: Any,
        commitment_root: bytes,
        key_id: str,
        clock: Any,
    ) -> None:
        from tuntun_core.services.providers.response_receipts import VerifiedProviderResponseReceipt

        if type(verified_response_receipt) is not VerifiedProviderResponseReceipt:
            raise PermissionError("provider_response_provenance_required")
        if type(commitment_root) is not bytes or len(commitment_root) != 32:
            raise ValueError("proposal commitment root must be 32 bytes")
        self._refs = refs
        self._provenance = provenance
        self._verified = verified_response_receipt
        self._root = commitment_root
        self._key_id = key_id
        self._clock = clock

    def map_memory(
        self,
        intent: ProviderMemoryIntent,
        household_id: UUID,
        subject_id: UUID | None,
        session_id: UUID,
        turn_id: UUID,
    ) -> MemoryProposalDraft:
        self._verified.require_scope(household_id, subject_id, session_id, turn_id)
        if isinstance(intent, RememberPreferenceIntent):
            subject_id = self._refs.subject(
                intent.subject_ref,
                household_id=household_id,
                session_id=session_id,
                turn_id=turn_id,
            )
            profile_class = self._refs.profile_class(
                subject_id,
                household_id=household_id,
                session_id=session_id,
                turn_id=turn_id,
            )
            audience = _audience_for_profile_class(profile_class)
            content = PreferenceContent(
                kind="preference",
                category=intent.category,
                key=intent.key,
                value=intent.value,
                strength_micros=intent.confidence_micros,
            )
            draft = MemoryProposalDraft(
                proposal_id=uuid4(),
                schema_version="1.0",
                operation="create",
                household_id=household_id,
                subject_id=subject_id,
                session_id=session_id,
                turn_id=turn_id,
                idempotency_key=uuid4(),
                content=content,
                audience=audience,
                target_memory_id=None,
                expected_version=None,
                sensitivity=Sensitivity.PERSONAL,
                confidence_micros=intent.confidence_micros,
                reason=intent.reason,
                claim_commitment=self._commit("memory.proposal.claim.v1", _intent_payload(intent)),
                source_receipt_ids=(self._verified.receipt_id,),
                expires_at=self._clock.now() + timedelta(minutes=15),
            )
        elif isinstance(intent, ForgetMemoryIntent):
            subject_id = self._refs.subject(
                intent.subject_ref,
                household_id=household_id,
                session_id=session_id,
                turn_id=turn_id,
            )
            memory_id = self._refs.memory(
                intent.memory_ref,
                household_id=household_id,
                subject_id=subject_id,
                session_id=session_id,
                turn_id=turn_id,
            )
            version = self._refs.memory_version(
                intent.memory_ref,
                household_id=household_id,
                subject_id=subject_id,
                session_id=session_id,
                turn_id=turn_id,
            )
            draft = MemoryProposalDraft(
                proposal_id=uuid4(),
                schema_version="1.0",
                operation="delete",
                household_id=household_id,
                subject_id=subject_id,
                session_id=session_id,
                turn_id=turn_id,
                idempotency_key=uuid4(),
                content=None,
                audience=None,
                target_memory_id=memory_id,
                expected_version=version,
                sensitivity=Sensitivity.PERSONAL,
                confidence_micros=intent.confidence_micros,
                reason=intent.reason,
                claim_commitment=self._commit("memory.proposal.claim.v1", _intent_payload(intent)),
                source_receipt_ids=(self._verified.receipt_id,),
                expires_at=self._clock.now() + timedelta(minutes=15),
            )
        else:
            raise TypeError("unsupported memory intent")
        _attach_provenance(self._provenance, draft, self._verified)
        return draft

    def map_action(
        self,
        intent: ProviderActionIntent,
        household_id: UUID,
        subject_id: UUID | None,
        session_id: UUID,
        turn_id: UUID,
    ) -> TimerCreateActionDraft | TimerTargetActionDraft:
        self._verified.require_scope(household_id, subject_id, session_id, turn_id)
        if isinstance(intent, TimerCreateIntent):
            timer_id = uuid4()
            parameters = {"duration_seconds": intent.duration_seconds, "label": intent.label}
            create_draft = TimerCreateActionDraft(
                proposal_id=uuid4(),
                schema_version="1.0",
                resource_type="timer",
                resource_id=timer_id,
                parameters_commitment=self._commit("action.parameters.v1", parameters),
                uncertainty_micros=1_000_000 - intent.confidence_micros,
                expires_at=self._clock.now() + timedelta(minutes=5),
                idempotency_key=uuid4(),
                action_name="timer.create",
                duration_seconds=intent.duration_seconds,
                label=intent.label,
            )
            _attach_provenance(self._provenance, create_draft, self._verified)
            return create_draft
        if isinstance(intent, TimerCancelIntent):
            timer_id = self._refs.timer(
                intent.timer_ref,
                household_id=household_id,
                session_id=session_id,
                turn_id=turn_id,
            )
            parameters = {"timer_id": str(timer_id)}
            target_draft = TimerTargetActionDraft(
                proposal_id=uuid4(),
                schema_version="1.0",
                resource_type="timer",
                resource_id=timer_id,
                parameters_commitment=self._commit("action.parameters.v1", parameters),
                uncertainty_micros=1_000_000 - intent.confidence_micros,
                expires_at=self._clock.now() + timedelta(minutes=5),
                idempotency_key=uuid4(),
                action_name="timer.cancel",
                timer_id=timer_id,
            )
            _attach_provenance(self._provenance, target_draft, self._verified)
            return target_draft
        raise TypeError("unsupported action intent")

    def bind_action(
        self,
        draft: TimerCreateActionDraft | TimerTargetActionDraft,
        household_id: UUID,
        turn_id: UUID,
        policy_version: str,
        session_id: UUID,
        subject_id: UUID | None,
    ) -> ActionBinding:
        return ActionBinding(
            household_id=household_id,
            proposal_id=draft.proposal_id,
            turn_id=turn_id,
            idempotency_key=draft.idempotency_key,
            action_name=draft.action_name,
            resource_type=draft.resource_type,
            resource_id=draft.resource_id,
            parameter_commitment=draft.parameters_commitment,
            policy_version=policy_version,
            session_id=session_id,
            subject_id=subject_id,
        )

    def _commit(self, purpose: str, payload: Mapping[str, Any]) -> Commitment:
        return commit_private(
            self._root,
            self._key_id,
            purpose,
            canonical_mapping_bytes(payload),
        )


def action_execution_parameters(
    draft: TimerCreateActionDraft | TimerTargetActionDraft | SafetyActionDraft,
) -> dict[str, object]:
    if type(draft) is TimerCreateActionDraft:
        return {"duration_seconds": draft.duration_seconds, "label": draft.label}
    if type(draft) is TimerTargetActionDraft:
        return {
            "timer_id": str(draft.timer_id),
            "idempotency_key": str(draft.idempotency_key),
        }
    if type(draft) is SafetyActionDraft:
        return {"reason_code": draft.reason_code}
    raise TypeError("unsupported action draft")


def _intent_payload(intent: ContractModel) -> dict[str, Any]:
    return dict(intent.model_dump(mode="json"))


def _audience_for_profile_class(profile_class: object) -> MemoryAudience:
    if profile_class in {"owner", "adult"}:
        return MemoryAudience.SUBJECT_PRIVATE
    if profile_class in {"k2", "n1"}:
        return MemoryAudience.GUARDIAN_CHILD
    raise PermissionError("unknown_profile_class")


def _attach_provenance(provenance: Any, draft: object, verified: object) -> None:
    attach = getattr(provenance, "attach", None)
    if attach is not None:
        attach(draft, verified)
