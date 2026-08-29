# packages/contracts/src/tuntun_contracts/actions.py
from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Annotated, Literal, Self, TypeAlias
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from .base import Commitment, ContractModel
from .identity import PersonaTraits
from .memory import MemoryContent, MemoryProposalDraft

ACTION_RESOURCE_TYPE_BY_NAME: Mapping[str, str] = MappingProxyType(
    {
        "timer.create": "timer",
        "timer.cancel": "timer",
        "timer.status": "timer",
        "privacy.on": "privacy",
        "mute": "mute",
        "stop": "stop",
        "privacy.off": "privacy",
        "mute.off": "mute",
        "system.status": "system",
        "reachy.status": "reachy",
        "reachy.gesture_test": "reachy",
        "offline.prompt_test": "offline",
        "memory.propose": "memory",
        "memory.approve": "memory",
        "memory.edit_approve": "memory",
        "memory.reject": "memory",
        "memory.expire": "memory",
        "memory.delete": "memory",
        "memory.export": "memory",
        "profile.create": "profile",
        "profile.edit": "profile",
        "profile.revoke": "profile",
        "profile.delete": "profile",
        "profile.export": "profile",
        "consent.grant": "consent",
        "consent.revoke": "consent",
        "identity.enroll": "identity",
        "identity.enrollment.cancel": "identity",
        "provider.review": "provider",
        "provider.configure": "provider",
        "budget.change": "budget",
        "access.change": "access",
        "credential.passkey.add": "credential",
        "credential.passkey.revoke": "credential",
        "credential.pin.change": "credential",
        "credential.recovery.rotate": "credential",
        "audit.export": "audit",
        "audit.verify": "audit",
        "backup.recovery_key.create": "backup",
        "backup.create": "backup",
        "backup.verify": "backup",
        "backup.restore": "backup",
        "search.profile_mode.change": "search",
        "search.experimental.activate": "search",
        "security.finding.suppress": "security_finding",
        "release.latency.accept": "soak_run",
        "release.family_stage.review": "family_stage",
        "release.p1r0": "release_candidate",
    }
)


class ActionDraftBase(ContractModel):
    proposal_id: UUID
    schema_version: Literal["1.0"]
    resource_type: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
    resource_id: UUID | None
    parameters_commitment: Commitment
    uncertainty_micros: Annotated[int, Field(ge=0, le=1_000_000)]
    expires_at: AwareDatetime
    idempotency_key: UUID

    @model_validator(mode="after")
    def exact_resource_type(self) -> Self:
        action_name = getattr(self, "action_name", None)
        if (
            action_name is not None
            and (expected := ACTION_RESOURCE_TYPE_BY_NAME.get(action_name)) != self.resource_type
        ):
            raise ValueError(f"{action_name} resource type mismatch; expected {expected}")
        return self


class TimerCreateActionDraft(ActionDraftBase):
    action_name: Literal["timer.create"]
    duration_seconds: Annotated[int, Field(ge=1, le=86_400)]
    label: Annotated[str, Field(min_length=1, max_length=64)]

    @model_validator(mode="after")
    def exact_timer_create_shape(self) -> Self:
        if self.resource_type != "timer" or self.resource_id is None:
            raise ValueError("timer.create requires a server-generated exact timer resource")
        return self


class TimerTargetActionDraft(ActionDraftBase):
    action_name: Literal["timer.cancel", "timer.status"]
    timer_id: UUID

    @model_validator(mode="after")
    def exact_timer_target_shape(self) -> Self:
        if self.resource_type != "timer" or self.resource_id != self.timer_id:
            raise ValueError("timer target must equal the exact resource")
        return self


class SafetyActionDraft(ActionDraftBase):
    action_name: Literal["privacy.on", "mute", "stop"]
    reason_code: Annotated[str, Field(min_length=1, max_length=64)]


class PrivacyReductionActionDraft(ActionDraftBase):
    action_name: Literal["privacy.off", "mute.off"]
    typed_confirmation: Literal["TURN OFF PRIVACY", "UNMUTE"]

    @model_validator(mode="after")
    def exact_confirmation(self) -> PrivacyReductionActionDraft:
        expected = {"privacy.off": "TURN OFF PRIVACY", "mute.off": "UNMUTE"}[self.action_name]
        if self.typed_confirmation != expected:
            raise ValueError("privacy reduction confirmation mismatch")
        return self


class ComponentStatusActionDraft(ActionDraftBase):
    action_name: Literal["system.status", "reachy.status"]
    component: Literal["system", "reachy"]

    @model_validator(mode="after")
    def exact_component(self) -> ComponentStatusActionDraft:
        if self.component != self.action_name.removesuffix(".status"):
            raise ValueError("status component mismatch")
        return self


class DiagnosticActionDraft(ActionDraftBase):
    action_name: Literal["reachy.gesture_test", "offline.prompt_test"]
    registered_asset_id: Annotated[str, Field(min_length=1, max_length=128)]


class MemoryActionDraft(ActionDraftBase):
    action_name: Literal[
        "memory.propose",
        "memory.approve",
        "memory.edit_approve",
        "memory.reject",
        "memory.expire",
        "memory.delete",
        "memory.export",
    ]
    subject_id: UUID
    proposal_id_ref: UUID | None = None
    memory_id: UUID | None = None
    expected_version: Annotated[int, Field(ge=1)] | None = None
    decision: Literal["approve", "reject"] | None = None
    edited_content: MemoryContent | None = None
    memory_proposal: MemoryProposalDraft | None = None
    export_format: Literal["json"] | None = None

    @model_validator(mode="after")
    def exact_memory_operation_shape(self) -> MemoryActionDraft:
        if self.action_name == "memory.propose":
            if self.memory_proposal is None or self.memory_proposal.subject_id != self.subject_id:
                raise ValueError("memory.propose requires the exact server-mapped proposal")
            if any(
                (
                    self.proposal_id_ref,
                    self.memory_id,
                    self.expected_version,
                    self.decision,
                    self.edited_content,
                    self.export_format,
                )
            ):
                raise ValueError("memory.propose contains decision fields")
        elif self.action_name in {
            "memory.approve",
            "memory.edit_approve",
            "memory.reject",
        }:
            expected_decision = "reject" if self.action_name == "memory.reject" else "approve"
            if (
                self.proposal_id_ref is None
                or self.expected_version is None
                or self.decision != expected_decision
            ):
                raise ValueError("memory decision draft is incomplete")
            if (self.action_name == "memory.edit_approve") != (self.edited_content is not None):
                raise ValueError("edited content is exclusive to memory.edit_approve")
            if any((self.memory_id, self.memory_proposal, self.export_format)):
                raise ValueError("memory decision draft contains another operation's fields")
        elif self.action_name == "memory.expire":
            if (
                self.proposal_id_ref is None
                or self.expected_version is None
                or any(
                    (
                        self.memory_id,
                        self.decision,
                        self.edited_content,
                        self.memory_proposal,
                        self.export_format,
                    )
                )
            ):
                raise ValueError("memory.expire draft is incomplete")
        elif self.action_name == "memory.delete":
            if (
                self.memory_id is None
                or self.expected_version is None
                or any(
                    (
                        self.proposal_id_ref,
                        self.decision,
                        self.edited_content,
                        self.memory_proposal,
                        self.export_format,
                    )
                )
            ):
                raise ValueError("memory.delete requires only target and version")
        elif (
            self.memory_id is None
            or self.expected_version is None
            or self.export_format != "json"
            or self.resource_id != self.memory_id
            or any(
                (
                    self.proposal_id_ref,
                    self.decision,
                    self.edited_content,
                    self.memory_proposal,
                )
            )
        ):
            raise ValueError(
                "memory.export requires one exact resource, version, and closed export format"
            )
        if self.action_name == "memory.propose":
            target_resource_id = (
                None if self.memory_proposal is None else self.memory_proposal.proposal_id
            )
        elif self.action_name in {
            "memory.approve",
            "memory.edit_approve",
            "memory.reject",
            "memory.expire",
        }:
            target_resource_id = self.proposal_id_ref
        else:
            target_resource_id = self.memory_id
        if target_resource_id is None or self.resource_id != target_resource_id:
            raise ValueError("memory action resource must equal the typed target")
        return self


class ProfileActionDraft(ActionDraftBase):
    action_name: Literal[
        "profile.create",
        "profile.edit",
        "profile.revoke",
        "profile.delete",
        "profile.export",
    ]
    subject_id: UUID
    profile_class: Literal["owner", "adult", "k2", "n1"] | None = None
    target_profile_class: Literal["owner", "adult", "k2", "n1"] | None = None
    display_label: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    guardian_id: UUID | None = None
    persona_traits: PersonaTraits | None = None
    clear_persona_traits: bool = False
    expected_version: Annotated[int, Field(ge=1)] | None = None
    guardian_generation: Annotated[int, Field(ge=1)] | None = None

    @model_validator(mode="after")
    def exact_operation_shape(self) -> ProfileActionDraft:
        changes_persona = self.persona_traits is not None or self.clear_persona_traits
        if self.action_name == "profile.create":
            if (
                self.profile_class is None
                or self.target_profile_class is not None
                or self.display_label is None
                or changes_persona
                or self.expected_version is not None
                or self.guardian_generation is not None
            ):
                raise ValueError("profile.create requires class and display label only")
            if self.profile_class not in {"adult", "k2", "n1"}:
                raise ValueError("ordinary profile.create cannot create or replace the owner")
            if (self.profile_class in {"k2", "n1"}) != (self.guardian_id is not None):
                raise ValueError("profile.create guardian shape mismatch")
        elif self.action_name == "profile.edit":
            if not changes_persona:
                raise ValueError("profile.edit requires replace or clear")
            if self.persona_traits is not None and self.clear_persona_traits:
                raise ValueError("replace and clear are exclusive")
            if (
                self.expected_version is None
                or self.target_profile_class is None
                or self.profile_class is not None
                or self.display_label is not None
                or self.guardian_id is not None
            ):
                raise ValueError("persona edit requires version and cannot change role")
            child_target = self.target_profile_class in {"k2", "n1"}
            if child_target != (self.guardian_generation is not None):
                raise ValueError("guardian generation is required exactly for child persona edits")
        elif self.action_name == "profile.revoke":
            if (
                self.expected_version is None
                or any(
                    (
                        self.profile_class,
                        self.target_profile_class,
                        self.display_label,
                        self.guardian_id,
                        self.persona_traits,
                        self.guardian_generation,
                    )
                )
                or self.clear_persona_traits
            ):
                raise ValueError("profile.revoke requires only expected version")
        elif self.action_name in {"profile.delete", "profile.export"}:
            if (
                self.expected_version is None
                or any(
                    (
                        self.profile_class,
                        self.target_profile_class,
                        self.display_label,
                        self.guardian_id,
                        self.persona_traits,
                        self.guardian_generation,
                    )
                )
                or self.clear_persona_traits
            ):
                raise ValueError("profile lifecycle draft requires only expected version")
        if self.resource_id != self.subject_id:
            raise ValueError("profile action resource must equal subject")
        return self


class ConsentActionDraft(ActionDraftBase):
    action_name: Literal["consent.grant", "consent.revoke"]
    subject_id: UUID
    purpose: Literal[
        "face",
        "voice",
        "personalization",
        "cloud_stt",
        "cloud_reasoning",
        "cloud_tts",
        "web_search",
        "child_durable_memory_v1",
    ]
    expected_latest_receipt_id: UUID | None
    guardian_generation: Annotated[int, Field(ge=1)] | None = None
    policy_version: Annotated[str, Field(min_length=1, max_length=128)]
    disclosure_version: Annotated[str, Field(min_length=1, max_length=128)]

    @model_validator(mode="after")
    def expected_state_shape(self) -> ConsentActionDraft:
        if self.action_name == "consent.revoke" and self.expected_latest_receipt_id is None:
            raise ValueError("consent.revoke requires expected latest receipt")
        if self.resource_id != self.subject_id:
            raise ValueError("consent action resource must equal subject")
        return self


class IdentityActionDraft(ActionDraftBase):
    action_name: Literal["identity.enroll", "identity.enrollment.cancel"]
    subject_id: UUID | None
    modality: Literal["face", "voice"] | None
    enrollment_id: UUID | None = None
    expected_profile_version: Annotated[int, Field(ge=1)] | None = None
    expected_consent_receipt_id: UUID | None = None
    reenrollment_days: Annotated[int, Field(ge=30, le=365)] | None = None

    @model_validator(mode="after")
    def exact_enrollment_shape(self) -> IdentityActionDraft:
        if self.action_name == "identity.enroll":
            if (
                None
                in (
                    self.subject_id,
                    self.modality,
                    self.expected_profile_version,
                    self.expected_consent_receipt_id,
                    self.reenrollment_days,
                )
                or self.enrollment_id is not None
            ):
                raise ValueError("identity.enroll draft is incomplete")
            if self.resource_type != "identity" or self.resource_id != self.subject_id:
                raise ValueError("identity.enroll resource must equal subject")
        elif (
            self.subject_id is None
            or self.enrollment_id is None
            or any(
                (
                    self.modality,
                    self.expected_profile_version,
                    self.expected_consent_receipt_id,
                    self.reenrollment_days,
                )
            )
        ):
            raise ValueError(
                "identity.enrollment.cancel requires only enrollment and derived subject"
            )
        elif self.resource_type != "identity" or self.resource_id != self.enrollment_id:
            raise ValueError("identity.enrollment.cancel resource must equal enrollment")
        return self


class ProviderActionDraft(ActionDraftBase):
    action_name: Literal["provider.review", "provider.configure", "budget.change", "access.change"]
    provider: Literal["openai", "qwen"] | None = None
    enabled: bool | None = None
    review_record_id: UUID | None = None
    hard_limit_micros_sgd: Annotated[int, Field(ge=1)] | None = None
    access_mode: Literal["loopback", "lan_https"] | None = None
    expected_provider_version: Annotated[int, Field(ge=1)] | None = None
    expected_budget_version: Annotated[int, Field(ge=1)] | None = None
    expected_access_version: Annotated[int, Field(ge=1)] | None = None

    @model_validator(mode="after")
    def exact_provider_operation_shape(self) -> ProviderActionDraft:
        present = {
            "provider": self.provider is not None,
            "enabled": self.enabled is not None,
            "review": self.review_record_id is not None,
            "limit": self.hard_limit_micros_sgd is not None,
            "access": self.access_mode is not None,
            "provider_version": self.expected_provider_version is not None,
            "budget_version": self.expected_budget_version is not None,
            "access_version": self.expected_access_version is not None,
        }
        expected = {
            "provider.review": {"provider", "provider_version"},
            "provider.configure": {"provider", "enabled", "review", "provider_version"},
            "budget.change": {"limit", "budget_version"},
            "access.change": {"access", "access_version"},
        }[self.action_name]
        if {name for name, value in present.items() if value} != expected:
            raise ValueError("provider/admin operation shape mismatch")
        return self


class CredentialActionDraft(ActionDraftBase):
    action_name: Literal[
        "credential.passkey.add",
        "credential.passkey.revoke",
        "credential.pin.change",
        "credential.recovery.rotate",
    ]
    credential_id: UUID | None = None
    capability: Literal["owner_admin", "adult_self_consent", "profile_persona"] | None = None
    ceremony_id: UUID | None = None
    expected_version: Annotated[int, Field(ge=1)] | None = None

    @model_validator(mode="after")
    def exact_credential_operation_shape(self) -> CredentialActionDraft:
        present = {
            "credential": self.credential_id is not None,
            "capability": self.capability is not None,
            "ceremony": self.ceremony_id is not None,
            "version": self.expected_version is not None,
        }
        expected = {
            "credential.passkey.add": {"credential", "capability", "ceremony"},
            "credential.passkey.revoke": {"credential", "version"},
            "credential.pin.change": {"ceremony", "version"},
            "credential.recovery.rotate": {"version"},
        }[self.action_name]
        if {name for name, value in present.items() if value} != expected:
            raise ValueError("credential operation shape mismatch")
        if (
            self.action_name
            in {
                "credential.passkey.add",
                "credential.passkey.revoke",
            }
            and self.resource_id != self.credential_id
        ):
            raise ValueError("passkey action resource must equal credential")
        return self


class AuditActionDraft(ActionDraftBase):
    action_name: Literal["audit.export", "audit.verify"]
    from_ordinal: Annotated[int, Field(ge=1)] | None

    @model_validator(mode="after")
    def exact_audit_operation_shape(self) -> AuditActionDraft:
        if self.from_ordinal is None:
            raise ValueError("audit operation requires starting ordinal")
        return self


class BackupActionDraft(ActionDraftBase):
    action_name: Literal[
        "backup.recovery_key.create", "backup.create", "backup.verify", "backup.restore"
    ]
    backup_id: UUID | None = None
    recipient_key_id: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    manifest_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")] | None = None

    @model_validator(mode="after")
    def exact_backup_operation_shape(self) -> BackupActionDraft:
        present = {
            "backup": self.backup_id is not None,
            "recipient": self.recipient_key_id is not None,
            "manifest": self.manifest_sha256 is not None,
        }
        expected = {
            "backup.recovery_key.create": {"recipient"},
            "backup.create": {"backup", "recipient"},
            "backup.verify": {"backup", "manifest"},
            "backup.restore": {"backup", "manifest"},
        }[self.action_name]
        if {name for name, value in present.items() if value} != expected:
            raise ValueError("backup operation shape mismatch")
        if self.backup_id is not None and self.resource_id != self.backup_id:
            raise ValueError("backup action resource must equal backup")
        return self


class SearchActionDraft(ActionDraftBase):
    action_name: Literal["search.profile_mode.change", "search.experimental.activate"]
    subject_id: UUID
    expected_profile_version: Annotated[int, Field(ge=1)]
    mode: Literal["controlled", "no_web"] | None = None
    expected_web_consent_receipt_id: UUID | None = None
    provider_review_version: Annotated[int, Field(ge=1)] | None = None
    pricing_version: Annotated[int, Field(ge=1)] | None = None
    privacy_generation: Annotated[int, Field(ge=1)] | None = None
    feature_generation: Annotated[int, Field(ge=1)] | None = None
    activation_issued_at: AwareDatetime | None = None
    activation_expires_at: AwareDatetime | None = None
    max_passes: Literal[4] | None = None
    max_sources: Literal[20] | None = None
    max_duration_seconds: Literal[1800] | None = None
    no_memory: Literal[True] | None = None
    no_authenticated_sites: Literal[True] | None = None
    no_files: Literal[True] | None = None
    no_tools: Literal[True] | None = None

    @model_validator(mode="after")
    def exact_search_operation_shape(self) -> SearchActionDraft:
        experimental = (
            self.provider_review_version,
            self.pricing_version,
            self.privacy_generation,
            self.feature_generation,
            self.activation_issued_at,
            self.activation_expires_at,
            self.max_passes,
            self.max_sources,
            self.max_duration_seconds,
            self.no_memory,
            self.no_authenticated_sites,
            self.no_files,
            self.no_tools,
        )
        if self.action_name == "search.profile_mode.change":
            expected_consent = self.expected_web_consent_receipt_id is not None
            if (
                self.mode is None
                or expected_consent != (self.mode == "controlled")
                or any(value is not None for value in experimental)
            ):
                raise ValueError("search profile-mode draft shape mismatch")
        elif (
            self.mode is not None
            or self.expected_web_consent_receipt_id is None
            or self.activation_issued_at is None
            or self.activation_expires_at is None
            or any(value is None for value in experimental)
        ):
            raise ValueError("experimental search draft is incomplete")
        elif (
            self.activation_expires_at <= self.activation_issued_at
            or (self.activation_expires_at - self.activation_issued_at).total_seconds() > 1800
        ):
            raise ValueError(
                "experimental search activation must be positive and at most 30 minutes"
            )
        if self.resource_id != self.subject_id:
            raise ValueError("search action resource must equal subject")
        return self


class SecurityFindingActionDraft(ActionDraftBase):
    action_name: Literal["security.finding.suppress"]
    finding_id: Annotated[str, Field(min_length=1, max_length=128)]
    finding_fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    finding_code: Annotated[str, Field(min_length=1, max_length=128)]
    finding_severity: Literal["critical", "high"]
    candidate_version: Annotated[str, Field(min_length=1, max_length=128)]
    candidate_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40,64}$")]
    suppression_expires_at: AwareDatetime


class ReleaseP1R0ActionDraft(ActionDraftBase):
    action_name: Literal["release.p1r0"]
    candidate_version: Annotated[str, Field(min_length=1, max_length=128)]
    candidate_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40,64}$")]
    evidence_commitment: Commitment


class LatencyDeviationActionDraft(ActionDraftBase):
    action_name: Literal["release.latency.accept"]
    candidate_version: Annotated[str, Field(min_length=1, max_length=128)]
    candidate_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40,64}$")]
    run_id: UUID
    metric: Literal["first_audio_p95_ms"]
    observed_ms: Annotated[int, Field(ge=0, le=120_000)]
    limit_ms: Annotated[int, Field(ge=1, le=120_000)]
    release_notes_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    @model_validator(mode="after")
    def exact_run_resource(self) -> Self:
        if self.resource_id != self.run_id:
            raise ValueError("latency action resource must equal soak run")
        return self


class FamilyStageReviewActionDraft(ActionDraftBase):
    action_name: Literal["release.family_stage.review"]
    candidate_version: Annotated[str, Field(min_length=1, max_length=128)]
    candidate_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40,64}$")]
    reviewed_stage_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    decision: Literal["proceed", "stop"]


ActionProposalDraft: TypeAlias = Annotated[  # noqa: UP040 -- Python 3.11 compatibility.
    TimerCreateActionDraft
    | TimerTargetActionDraft
    | SafetyActionDraft
    | PrivacyReductionActionDraft
    | ComponentStatusActionDraft
    | DiagnosticActionDraft
    | MemoryActionDraft
    | ProfileActionDraft
    | ConsentActionDraft
    | IdentityActionDraft
    | ProviderActionDraft
    | CredentialActionDraft
    | AuditActionDraft
    | BackupActionDraft
    | SearchActionDraft
    | SecurityFindingActionDraft
    | LatencyDeviationActionDraft
    | FamilyStageReviewActionDraft
    | ReleaseP1R0ActionDraft,
    Field(discriminator="action_name"),
]


class ActionBinding(ContractModel):
    household_id: UUID
    proposal_id: UUID
    turn_id: UUID
    idempotency_key: UUID
    action_name: str
    resource_type: str
    resource_id: UUID | None
    parameter_commitment: Commitment
    policy_version: str
    session_id: UUID
    subject_id: UUID | None


class ValidatedActionProposal(ContractModel):
    draft: ActionProposalDraft
    binding: ActionBinding
    resource_scope: Annotated[str, Field(min_length=1, max_length=256)]
    required_assurance: Literal[
        "guest",
        "identified",
        "confirmed",
        "pin_verified",
        "passkey_verified",
        "recovery_verified",
    ]

    @model_validator(mode="after")
    def draft_matches_binding(self) -> Self:
        if (
            self.binding.proposal_id != self.draft.proposal_id
            or self.binding.idempotency_key != self.draft.idempotency_key
            or self.binding.action_name != self.draft.action_name
            or self.binding.resource_type != self.draft.resource_type
            or self.binding.resource_id != self.draft.resource_id
            or self.binding.parameter_commitment != self.draft.parameters_commitment
        ):
            raise ValueError("draft binding mismatch")
        return self


class ActionReceipt(ContractModel):
    receipt_id: UUID
    proposal_id: UUID
    household_id: UUID
    action_name: str
    resource_scope: Annotated[str, Field(min_length=1, max_length=256)]
    resource_id: UUID | None
    idempotency_key: UUID
    outcome: Literal["executed", "denied", "duplicate", "failed"]
    reason_code: str
    occurred_at: AwareDatetime
