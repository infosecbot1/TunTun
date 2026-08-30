# Tuntun Phase 1 Identity, Authorization, and Memory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement master-plan work packages 17–22 as a private, consent-bound identity, authorization, action-proposal, and seven-kind memory subsystem that always falls back to Guest on uncertainty and never treats biometrics as action authorization.

**Architecture:** Extend the encrypted modular monolith with narrow domain services behind the contracts established by master Tasks 01–16. Profile, consent, authentication, biometric, proposal, memory, and audit state changes share the SQLCipher unit of work; CPU-bound identity and embedding adapters receive only bounded in-memory media or typed claims. Workflow integration passes scoped, pseudonymous, locally minimized context to the existing sanitizer and provider boundary.

**Tech Stack:** Python 3.12, Pydantic v2, SQLAlchemy 2/Alembic over SQLCipher, `cryptography`, Argon2id, WebAuthn, OpenCV headless, ONNX Runtime, Hypothesis, pytest/pytest-asyncio, Ruff, and strict mypy.

**Source:** [Master implementation plan](./2026-08-27-tuntun-phase1-anchor.md) and [normative architecture specification](../specs/2026-08-27-tuntun-phase1-anchor-design.md).

## Global Constraints

- Exactly one household and one active household conversation are supported in Phase 1.
- Adults grant and revoke their own face, voice, personalization, cloud-STT, cloud-reasoning, cloud-TTS, and `web_search` consent. A guardian may grant and revoke the first six purposes for a child and separately manage that child's `child_durable_memory_v1` consent; `web_search` remains owner/adult self-only, while `child_durable_memory_v1` remains K2/N1 current-primary-guardian-only. Invalid profile classes are denied before any purpose-specific receipt lookup. The owner cannot silently consent for another adult or substitute for another child's current guardian.
- Face/voice identity runs only during an explicitly invoked Reachy interaction or enrollment ceremony. Passive/background discovery, unknown-candidate storage, and re-encounter review are absent; unknown or uncertain evidence becomes Guest without a durable biometric candidate.
- Explicit enrollment requires the subject consent described above plus a fresh, action-bound owner passkey. Source recordings, frames, and crops remain in RAM and are destroyed on every terminal path.
- Children receive an owner-visible re-enrollment reminder after 180 days by default. A reminder does not silently disable personalization; biometric templates hard-expire at 365 days unless renewed with guardian consent, at which point identity resolves to Guest until re-enrollment completes.
- Face or voice evidence may select a profile for personalization only after the governed liveness/presentation-attack gate passes. Agreement increases identity confidence but never satisfies action assurance. Every low-risk action requires a fresh, action-bound explicit confirmation; stronger actions require their typed PIN, passkey, recovery, or local-presence factor.
- Conflict, ambiguity, poor quality, failed/expired liveness, expired evidence, a child template past its 365-day hard expiry, revoked face/voice identity consent, a revoked profile, or an unaccepted biometric model resolves identity to Guest. Revoked personalization consent instead suppresses custom traits while preserving the already-resolved canonical role and its safe defaults.
- Pending, rejected, expired, deleted, superseded, or revoked memory never enters retrieval or provider context. Guest receives no private memory.
- Administrative authority never grants memory-body access. An owner-not-subject with legitimate lifecycle authority receives only an opaque, non-oracular administrative projection: opaque ID, kind, lifecycle state, sensitivity band, created/review/expiry times, storage/count impact, and consent health. It excludes audience detail, title, source wording, private provenance, keyed/content commitments, ciphertext size, and every body-derived field. An adult subject may see their own body, the current primary guardian may see governed child proposals/bodies, and `household_adults`/`household_all` access follows independent audience membership. Adult `subject_private` content remains hidden from every other adult, including the owner; Guest and unrelated principals receive no object or existence signal.
- Retrieval returns at most six memories and the complete serialized provider context is at most 8,000 tokens. Acceptance requires Recall@6 at least 0.90, MRR@6 at least 0.75, and zero cross-profile leakage.
- Working memory expires at session end plus 30 minutes; pending proposals expire after 30 days; episodic memory defaults to 180 days; semantic, preference, procedural, and relational records receive annual review; policy memory keeps complete revision history.
- Every task uses synthetic fixtures, observes the named red failure, passes its narrow and affected suites, runs `ruff format --check`, `ruff check`, and strict mypy, stages only its exact paths, inspects the cached diff, and creates one independently reviewable commit.

## Exact Interface Baseline

Tasks in this plan use these signatures; implementations may add private helpers but must not change these public contracts without a major contract revision and fixture update.

The finalized frozen `ActionBinding` consumed here contains `household_id`, `proposal_id`, `turn_id`, `idempotency_key`, `action_name`, `resource_type`, `resource_id`, `parameter_commitment`, `policy_version`, `session_id`, and `subject_id`. Every equality check compares the complete model, so a grant cannot cross proposals or turns even when parameters are otherwise identical.

```python
from collections.abc import Sequence
from datetime import datetime
from typing import Protocol
from uuid import UUID

from tuntun_contracts.actions import ActionBinding, ActionReceipt, ValidatedActionProposal
from tuntun_contracts.audit import AuditDraft
from tuntun_contracts.identity import IdentityDecision, IdentityEvidence, IdentityRequest, PersonaProjection, PersonaTraits
from tuntun_contracts.memory import ApprovedMemory, DecideMemoryProposal, MemoryProposal, MemoryProposalDraft, MemoryQuery, MemoryRecord, ProposalContext
from tuntun_contracts.policy import AdminSessionPrincipal, AuthContext, AuthGrant, AuthenticationChallenge, AuthenticationRequest, AuthenticationResponse, CurrentOwnerAuthority, PolicyDecision, PolicyRequest
from tuntun_contracts.ports import AuthenticationPort, PolicyEnginePort
from tuntun_contracts.speech import AudioFormat
from tuntun_core.domain.profile import CancelEnrollment, ConsentPurpose, ConsentReceipt, CreateProfile, EnrollmentSession, GrantConsent, GuestConsentPurpose, GuestDisclosureChallenge, GuestSessionConsentReceipt, Profile, ProfileClass, ProfileProjection, RequestEnrollment, RevokeConsent, RevokeProfile, UpdatePersonaTraits
from tuntun_core.models.registry import ActivatedModel
from tuntun_core.services.memory.retrieval import RetrievalResult, ScopedRecallQuery
from tuntun_core.services.transactions.identity_uow import IdentityUnitOfWork

class ProfileService(Protocol):
    async def create(self, command: CreateProfile, auth: AuthContext) -> Profile: raise NotImplementedError
    async def create_in_uow(self, uow: IdentityUnitOfWork, command: CreateProfile, auth: AuthContext) -> Profile: raise NotImplementedError
    async def get_projection(self, household_id: UUID, subject_id: UUID | None) -> ProfileProjection: raise NotImplementedError
    async def get_persona_projection(self, household_id: UUID, subject_id: UUID | None, now: datetime) -> PersonaProjection: raise NotImplementedError
    async def current_policy_class(self, household_id: UUID, subject_id: UUID | None) -> ProfileClass: raise NotImplementedError
    async def current_policy_class_in_uow(self, uow: IdentityUnitOfWork, household_id: UUID, subject_id: UUID | None) -> ProfileClass: raise NotImplementedError
    async def require_current_active_in_uow(self, uow: IdentityUnitOfWork, household_id: UUID, subject_id: UUID) -> Profile: raise NotImplementedError
    async def update_persona_traits(self, command: UpdatePersonaTraits, auth: AuthContext) -> Profile: raise NotImplementedError
    async def update_persona_traits_in_uow(self, uow: IdentityUnitOfWork, command: UpdatePersonaTraits, auth: AuthContext) -> Profile: raise NotImplementedError
    async def revoke(self, command: RevokeProfile, auth: AuthContext) -> Profile: raise NotImplementedError
    async def revoke_in_uow(self, uow: IdentityUnitOfWork, command: RevokeProfile, auth: AuthContext) -> Profile: raise NotImplementedError

class ConsentService(Protocol):
    async def grant(self, command: GrantConsent, auth: AuthContext) -> ConsentReceipt: raise NotImplementedError
    async def grant_in_uow(self, uow: IdentityUnitOfWork, command: GrantConsent, auth: AuthContext) -> ConsentReceipt: raise NotImplementedError
    async def revoke(self, command: RevokeConsent, auth: AuthContext) -> ConsentReceipt: raise NotImplementedError
    async def revoke_in_uow(self, uow: IdentityUnitOfWork, command: RevokeConsent, auth: AuthContext) -> ConsentReceipt: raise NotImplementedError
    async def require_current(self, subject_id: UUID, purpose: ConsentPurpose, now: datetime) -> ConsentReceipt: raise NotImplementedError
    async def require_current_in_uow(self, uow: IdentityUnitOfWork, subject_id: UUID, purpose: ConsentPurpose, now: datetime) -> ConsentReceipt: raise NotImplementedError
    async def require_current_hmac_valid(self, household_id: UUID, subject_id: UUID, purpose: ConsentPurpose, now: datetime) -> ConsentReceipt: raise NotImplementedError
    async def is_current(self, subject_id: UUID, purpose: ConsentPurpose, now: datetime) -> bool: raise NotImplementedError
    async def verify_receipt(self, receipt: ConsentReceipt) -> ConsentReceipt: raise NotImplementedError

class GuestSessionConsentServicePort(Protocol):
    async def issue_challenge(self, household_id: UUID, session_id: UUID, purpose: GuestConsentPurpose, disclosure_version: str, presentation_receipt_id: UUID, now: datetime) -> GuestDisclosureChallenge: raise NotImplementedError
    async def accept_challenge(self, challenge_id: UUID, response: str, now: datetime) -> GuestSessionConsentReceipt: raise NotImplementedError
    async def revoke(self, household_id: UUID, session_id: UUID, purpose: GuestConsentPurpose, now: datetime) -> GuestSessionConsentReceipt: raise NotImplementedError
    async def require_current(self, household_id: UUID, session_id: UUID, purpose: GuestConsentPurpose, now: datetime) -> GuestSessionConsentReceipt: raise NotImplementedError
    async def require_current_hmac_valid(self, household_id: UUID, session_id: UUID, purpose: GuestConsentPurpose, now: datetime) -> GuestSessionConsentReceipt: raise NotImplementedError

class EnrollmentService(Protocol):
    async def request(self, command: RequestEnrollment, auth: AuthContext) -> EnrollmentSession: raise NotImplementedError
    async def request_in_uow(self, uow: IdentityUnitOfWork, command: RequestEnrollment, auth: AuthContext) -> EnrollmentSession: raise NotImplementedError
    async def complete_in_uow(self, uow: IdentityUnitOfWork, enrollment_id: UUID, template_ids: tuple[UUID, ...], consent_receipt: ConsentReceipt, now: datetime) -> EnrollmentSession: raise NotImplementedError
    async def cancel_in_uow(self, uow: IdentityUnitOfWork, command: CancelEnrollment, auth: AuthContext) -> EnrollmentSession: raise NotImplementedError
    async def reminders_due(self, household_id: UUID, now: datetime) -> tuple[UUID, ...]: raise NotImplementedError
    async def expire_due_child_templates(self, household_id: UUID, now: datetime) -> tuple[UUID, ...]: raise NotImplementedError

class EphemeralFrame(Protocol):
    def view(self) -> memoryview: raise NotImplementedError
    def clear(self) -> None: raise NotImplementedError

class EphemeralAudio(Protocol):
    def view(self) -> memoryview: raise NotImplementedError
    def clear(self) -> None: raise NotImplementedError

class FaceMatcherPort(Protocol):
    async def observe(self, frames: Sequence[EphemeralFrame], model: ActivatedModel) -> IdentityEvidence: raise NotImplementedError

class VoiceMatcherPort(Protocol):
    async def observe(self, pcm: EphemeralAudio, audio_format: AudioFormat, model: ActivatedModel) -> IdentityEvidence: raise NotImplementedError

class IdentityFusionPort(Protocol):
    async def resolve(self, request: IdentityRequest) -> IdentityDecision: raise NotImplementedError

class TransactionalPolicyEnginePort(PolicyEnginePort, Protocol):
    async def decide_in_uow(self, uow: IdentityUnitOfWork, request: PolicyRequest) -> PolicyDecision: raise NotImplementedError

class TransactionalAuthenticationPort(AuthenticationPort, Protocol):
    async def consume_in_uow(self, uow: IdentityUnitOfWork, grant_id: UUID, binding: ActionBinding) -> AuthContext: raise NotImplementedError

class CurrentOwnerAuthorityPort(Protocol):
    async def require_current_in_uow(self, uow: IdentityUnitOfWork, household_id: UUID, subject_id: UUID, owner_generation: int, profile_version: int, now: datetime) -> CurrentOwnerAuthority: raise NotImplementedError
    async def require_admin_principal_in_uow(self, uow: IdentityUnitOfWork, principal: AdminSessionPrincipal, now: datetime) -> CurrentOwnerAuthority: raise NotImplementedError

class ActionBindingVerifierPort(Protocol):
    def require_exact(self, stored: ActionBinding, supplied: ActionBinding) -> None: raise NotImplementedError
    def require_parts(self, stored: ActionBinding, *, household_id: UUID, proposal_id: UUID, turn_id: UUID, idempotency_key: UUID, action_name: str, resource_type: str, resource_id: UUID | None, parameter_commitment: object, policy_version: str, session_id: UUID, subject_id: UUID | None) -> None: raise NotImplementedError

class ActionPolicyRequestFactoryPort(Protocol):
    def build(self, proposal: ValidatedActionProposal, auth: AuthContext) -> PolicyRequest: raise NotImplementedError

class ActionReceiptAuditMapperPort(Protocol):
    def to_audit_draft(self, receipt: ActionReceipt, auth: AuthContext) -> AuditDraft: raise NotImplementedError

class ActionProviderPort(Protocol):
    async def execute(self, proposal: ValidatedActionProposal, auth: AuthContext) -> ActionReceipt: raise NotImplementedError

class LocalActionProviderPort(Protocol):
    async def execute_in_uow(self, uow: IdentityUnitOfWork, proposal: ValidatedActionProposal, auth: AuthContext) -> ActionReceipt: raise NotImplementedError

class MemoryRepositoryPort(Protocol):
    async def create(self, memory: ApprovedMemory, expected_absent: bool = True) -> MemoryRecord: raise NotImplementedError
    async def replace(self, memory_id: UUID, expected_version: int, memory: ApprovedMemory) -> MemoryRecord: raise NotImplementedError
    async def delete(self, memory_id: UUID, expected_version: int, auth: AuthContext, approved_proposal_id: UUID) -> None: raise NotImplementedError
    async def query(self, query: MemoryQuery) -> tuple[MemoryRecord, ...]: raise NotImplementedError

class MemoryProposalServicePort(Protocol):
    async def stage(self, draft: MemoryProposalDraft, context: ProposalContext) -> MemoryProposal: raise NotImplementedError
    async def decide(self, command: DecideMemoryProposal, auth: AuthContext) -> MemoryProposal: raise NotImplementedError

class MemoryRetrievalPort(Protocol):
    async def retrieve(self, query: ScopedRecallQuery) -> RetrievalResult: raise NotImplementedError
```

The imported frozen `AuthenticationPort.consume(grant_id, binding)`, `PolicyEnginePort.decide(request)`, and `MemoryProposalServicePort.decide(command, auth)` signatures remain unchanged. Internal coordinators depend on the explicitly named structural extensions `TransactionalAuthenticationPort.consume_in_uow` and `TransactionalPolicyEnginePort.decide_in_uow`; neither silently redefines a public foundation port. The two-argument memory decision method is an explicit fail-closed compatibility boundary because those arguments cannot reconstruct a current proposal-specific binding; all real decisions enter through `MemoryMutationCoordinator.decide(command, decision_context, grant_id)` and then `decide_in_uow`. Frozen contracts are fields-only: `ActionBindingVerifierPort`, `ActionPolicyRequestFactoryPort`, and `ActionReceiptAuditMapperPort` perform exact comparisons, construct `PolicyRequest`, and map receipts to `AuditDraft`; no code calls undeclared `require_action`, `require_exact_resource`, `require_exact_binding`, `to_policy_request`, or `to_audit` methods on DTOs. Commitment bytes are compared with `hmac.compare_digest` before any protected domain read. All services consume the foundation `AsyncUnitOfWork`, the serialized async facade over the sync SQLCipher transaction running on its single database worker, and await `AsyncAuditLedger.append`. Task 1 declares a structural `IdentityUnitOfWork` protocol whose repository properties are the typed `AsyncRepositoryFacade` instances installed by the foundation factory; Tasks 2–10 extend that bounded-context protocol as they add repositories. No service uses dynamic attributes or a raw SQLCipher connection. For a mutation, `AuthenticationService.consume` requires the foundation `AtomicMutationScope`, locks and consumes the grant in that scope's `IdentityUnitOfWork`, and does not commit. `AuthenticationService.consume_in_uow`, internal `ActionExecutor.prepare_in_uow`, and the cross-plan `ActionMutationCoordinator.execute_in_uow(uow, proposal_id, grant_id)` likewise never commit. The authoritative action coordinator owns proposal lock, exact grant consumption, dynamic policy recheck, local receipt/audits or durable external claim; its caller owns the one commit. Calling `consume` for a mutation without an active scope fails with `atomic_mutation_scope_required`; no route or service may pre-consume a grant in a separate transaction.

Every typed repository facade method delegates through `await uow.run_sync(...)`. While `BEGIN IMMEDIATE` is held, code may await only those bounded repository methods and `AsyncAuditLedger`; CPU inference, WebAuthn, Reachy, filesystem, browser, provider, and other unbounded work happens before opening the mutation scope. The identity composition root exposes repository mutation methods only through the coordinators in this plan.

## Repository Map for This Subplan

```text
apps/core/migrations/versions/0002_profiles_consent_enrollment.py
apps/core/migrations/versions/0003_authentication.py
apps/core/migrations/versions/0004_memory.py
apps/core/migrations/versions/0005_memory_embeddings.py
apps/core/src/tuntun_core/domain/profile.py
apps/core/src/tuntun_core/services/transactions/identity_uow.py
apps/core/src/tuntun_core/services/identity/{profiles,consent,enrollment,face_enrollment,active_face_identity,face_liveness,voice_enrollment,voice_liveness,fusion,calibration}.py
apps/core/src/tuntun_core/adapters/identity/{face_yunet_sface,voice_onnx,worker}.py
apps/core/src/tuntun_core/services/policy/{action_registry,risk_classifier,engine}.py
apps/core/src/tuntun_core/services/auth/{confirmation,pin,passkey,recovery,sessions,local_presence}.py
apps/core/src/tuntun_core/services/identity/current_owner.py
apps/core/src/tuntun_core/services/actions/{parameter_binding,policy_requests,receipt_audit,provider_registry,proposals,validator,executor}.py
apps/core/src/tuntun_core/services/actions/providers/{identity,memory,search}.py
apps/core/src/tuntun_core/services/memory/{schemas,repository,mappers,revisions,scoping,projection,proposal_mapper,proposals,write_policy,approval,retrieval,embeddings,context}.py
apps/core/src/tuntun_core/adapters/embeddings/multilingual_e5.py
apps/core/src/tuntun_core/services/providers/token_counter.py
```

---

### Task 1: Persist profiles and enforce adult self-consent

**Master coverage:** Task 17
**Depends on:** master Tasks 06 and 15–16
**Estimated effort:** 1.5 person-days

**Files:**
- Create: `apps/core/src/tuntun_core/domain/profile.py`
- Create: `apps/core/src/tuntun_core/services/identity/profiles.py`
- Create: `apps/core/src/tuntun_core/services/identity/consent.py`
- Create: `apps/core/src/tuntun_core/services/identity/subject_revocation.py`
- Create: `apps/core/src/tuntun_core/services/identity/subject_revocation_processor.py`
- Create: `apps/core/src/tuntun_core/services/identity/subject_revocation_handlers.py`
- Create: `apps/core/src/tuntun_core/adapters/sqlcipher/subject_revocation_effect_repository.py`
- Create: `apps/core/src/tuntun_core/adapters/sqlcipher/subject_revocation_outbox_repository.py`
- Create: `apps/core/src/tuntun_core/workers/subject_revocation_worker.py`
- Modify: `apps/core/src/tuntun_core/adapters/sqlcipher/async_unit_of_work.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/lifecycle.py`
- Create: `apps/core/src/tuntun_core/services/actions/parameter_binding.py` (own the initial profile-parameter builders)
- Create: `apps/core/src/tuntun_core/services/transactions/identity_uow.py`
- Create: `apps/core/migrations/versions/0002_profiles_consent_enrollment.py`
- Create: `tests/unit/identity/test_profiles.py`
- Create: `tests/unit/identity/test_consent.py`
- Create: `tests/unit/identity/test_current_owner_repository.py`
- Create: `tests/integration/identity/test_profile_consent_migration.py`
- Create: `tests/integration/identity/test_profile_revocation.py`
- Create: `tests/unit/identity/test_subject_revocation_worker.py`
- Create: `tests/integration/identity/test_subject_revocation_handlers.py`

**Interfaces:**
- Consumes: foundation `AsyncUnitOfWork`, `await AsyncAuditLedger.append(uow: AsyncUnitOfWork, draft: AuditDraft) -> AuditReceipt`, `AuthContext(subject_id: UUID, assurance: AssuranceLevel)`, `ClockPort.now() -> datetime`, purpose-separated receipt HMAC signer/verifier, and active foundation `sessions`; callers never construct or append an `AuditReceipt`. The console/action preparation path and mutation services share the pure closed-payload builders in `services/actions/parameter_binding.py`; the server independently verifies action/resource/actor scope and the HMAC before domain-state access.
- Produces: typed `IdentityUnitOfWork`, whose profile facade explicitly implements `get_optional_scoped(household_id, subject_id) -> Profile | None` in addition to strict `get_scoped`; `ProfileService.create/get_projection/get_persona_projection/current_policy_class/current_policy_class_in_uow/require_current_active_in_uow/update_persona_traits/revoke`; monotonic `subjects.authority_generation`; the complete `SubjectAuthorityRevocationCascade`; production `SubjectRevocationOutboxRepository`, renewable and fenced `SubjectRevocationEffectRepository`, concrete Task-1 provider/search handlers, sealed `action_authorities|memory_authorities` not-yet-installed handlers, and a startup/periodic-drained `SubjectRevocationWorker`; a typed `current_owner_authority` repository storing exactly one `(household_id, subject_id, owner_generation)` pointer; `ConsentService.grant/revoke/require_current/require_current_hmac_valid/is_current`; `GuestSessionConsentService.issue_challenge/accept_challenge/revoke/require_current/require_current_hmac_valid`; and immutable migration `0002` for subjects, current-owner authority, consent, enrollment, modality-neutral biometric templates, the subject-revocation outbox, and per-family effect claims. The Task-1 sealed handlers may emit `not_installed_no_authority` only while their owning migration/facade is provably absent; Task 8 replaces action and Task 10 replaces memory after their migrations and repositories are registered. Only the optional profile method maps an absent row to `None`; SQLCipher/worker failures propagate.

Persona replace/clear is an optimistic-versioned `profile.edit`: owner/adult subjects act only for self, while a current-generation primary guardian acts only for K2/N1 and only with the closed child-safe shape. Replace requires current personalization consent; clear remains available after revocation. Missing/revoked personalization consent suppresses encrypted custom traits but preserves the resolved policy class: owner/adult use neutral defaults, K2/N1 retain guarded defaults, and only absent/inactive/revoked/unresolved identity projects as Guest. The encrypted envelope and five-field projection contain no subject ID or arbitrary text.

The durable subject-purpose set is exactly `face|voice|personalization|cloud_stt|cloud_reasoning|cloud_tts|web_search|child_durable_memory_v1`. Search is owner/adult self-only and is denied for K2/N1 before receipt lookup; its row invariant is exactly `actor_id=subject_id`, `guardian_id IS NULL`, and `guardian_generation IS NULL`, repeated after HMAC verification. `child_durable_memory_v1` is K2/N1-only and requires the current primary guardian ID and exact generation; owner/adult subjects are denied before a purpose-specific receipt lookup. Every child receipt row and HMAC binds the current primary guardian ID and generation. Every subject receipt HMAC also binds household, subject, purpose, actor, decision, policy/disclosure versions, and issue time. Guest models/checks remain exactly `cloud_stt|cloud_reasoning|cloud_tts`; their signed challenges and receipts bind household/session/purpose/disclosure/presentation/decision/times and cannot outlive the session. These additions change no Task 1 estimate.

Grant/revoke and later use compare the child guardian ID and generation to the current profile before receipt mutation, decryption, or egress; reassignment or generation drift invalidates the old receipt.

Current-owner authority is not inferred from a caller-supplied role or from any historical row with `profile_class='owner'`. `current_owner_authority` is the single canonical pointer for the household; bootstrap creates generation 1, and any recovery-driven owner replacement changes subject and increments generation in the same transaction that revokes the old owner and its sessions. A current-owner read must join that pointer to an active, non-revoked `subjects` row in the same household with class `owner`; the returned `profile_version` is the joined `subjects.version`. Historical owner subjects, stale generations, inactive rows, and version drift fail closed.

- [ ] **Step 1: Write the failing profile and consent tests**

```python
# tests/unit/identity/test_consent.py
import asyncio
import pytest
from tuntun_core.domain.profile import ConsentPurpose, GrantConsent, ProfileClass, RevokeConsent
from tuntun_core.services.identity.consent import ConsentDenied

@pytest.mark.asyncio
async def test_adult_must_consent_for_self(identity_mutations, adult_a, adult_b, adult_a_grant):
    command = GrantConsent(subject_id=adult_b.id, actor_id=adult_a.id, purpose=ConsentPurpose.CLOUD_STT, action_binding=adult_a_grant.binding)
    with pytest.raises(ConsentDenied, match="adult_self_consent_required"):
        await identity_mutations.grant_consent(command, adult_a_grant.id)

@pytest.mark.asyncio
async def test_guardian_may_consent_for_child(identity_mutations, guardian, child, guardian_grant):
    command = GrantConsent(subject_id=child.id, actor_id=guardian.id, purpose=ConsentPurpose.FACE, guardian_generation=child.guardian_generation, action_binding=guardian_grant.binding)
    receipt = await identity_mutations.grant_consent(command, guardian_grant.id)
    assert receipt.subject_id == child.id
    assert receipt.guardian_id == guardian.id
    assert receipt.granted is True


@pytest.mark.asyncio
@pytest.mark.parametrize("profile_class", [ProfileClass.K2, ProfileClass.N1])
async def test_current_guardian_controls_separate_child_durable_memory_consent(identity_mutations, child_profile_factory, guardian, child_memory_consent_grant_factory, profile_class):
    child = child_profile_factory(profile_class=profile_class, guardian_id=guardian.id)
    grant = child_memory_consent_grant_factory(child)
    receipt = await identity_mutations.grant_consent(
        GrantConsent(
            subject_id=child.id,
            actor_id=guardian.id,
            purpose=ConsentPurpose.CHILD_DURABLE_MEMORY,
            guardian_generation=child.guardian_generation,
            action_binding=grant.binding,
        ),
        grant.id,
    )
    assert receipt.purpose is ConsentPurpose.CHILD_DURABLE_MEMORY
    assert (receipt.guardian_id, receipt.guardian_generation) == (guardian.id, child.guardian_generation)


@pytest.mark.asyncio
@pytest.mark.parametrize("profile_class", [ProfileClass.OWNER, ProfileClass.ADULT])
async def test_adult_profile_cannot_create_child_memory_consent(consent_service, adult_child_memory_command_factory, actor_auth_factory, consent_repository_spy, profile_class):
    command = adult_child_memory_command_factory(profile_class=profile_class)
    with pytest.raises(ConsentDenied, match="child_durable_memory_guardian_consent_required"):
        await consent_service.grant(command, actor_auth_factory(command.actor_id, command.action_binding))
    assert consent_repository_spy.read_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["grant", "revoke"])
@pytest.mark.parametrize("stale_case", ["reassigned_guardian", "old_generation"])
async def test_stale_or_reassigned_guardian_cannot_manage_child_consent(consent_service, stale_child_consent_command_factory, guardian_auth_factory, consent_repository_spy, operation, stale_case):
    command = stale_child_consent_command_factory(operation=operation, stale_case=stale_case)
    auth = guardian_auth_factory(command.action_binding)
    with pytest.raises(ConsentDenied, match="current_primary_guardian_required"):
        await getattr(consent_service, operation)(command, auth)
    assert consent_repository_spy.read_count == 0


@pytest.mark.asyncio
async def test_adult_web_search_grant_and_revoke_are_subject_self_only(identity_mutations, adult_a, adult_web_search_grant, adult_web_search_revoke_grant_factory):
    granted = await identity_mutations.grant_consent(
        GrantConsent(subject_id=adult_a.id, actor_id=adult_a.id, purpose=ConsentPurpose.WEB_SEARCH, action_binding=adult_web_search_grant.binding),
        adult_web_search_grant.id,
    )
    assert granted.purpose is ConsentPurpose.WEB_SEARCH and granted.guardian_id is None
    revoke_grant = adult_web_search_revoke_grant_factory(granted)
    revoked = await identity_mutations.revoke_consent(
        RevokeConsent(subject_id=adult_a.id, actor_id=adult_a.id, purpose=ConsentPurpose.WEB_SEARCH, expected_latest_receipt_id=granted.id, policy_version=granted.policy_version, disclosure_version=granted.disclosure_version, action_binding=revoke_grant.binding),
        revoke_grant.id,
    )
    assert revoked.purpose is ConsentPurpose.WEB_SEARCH and revoked.granted is False


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["grant", "revoke"])
async def test_one_adult_cannot_manage_another_adults_web_search_consent(consent_service, cross_adult_search_command_factory, actor_auth_factory, consent_repository_spy, operation):
    command = cross_adult_search_command_factory(operation=operation)
    auth = actor_auth_factory(command.actor_id, command.action_binding)
    with pytest.raises(ConsentDenied, match="web_search_adult_self_consent_required"):
        await getattr(consent_service, operation)(command, auth)
    assert consent_repository_spy.read_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("profile_class", [ProfileClass.K2, ProfileClass.N1])
@pytest.mark.parametrize("operation", ["grant", "revoke"])
async def test_child_web_search_consent_is_denied_before_receipt_lookup(consent_service, child_search_command_factory, guardian_auth_factory, consent_repository_spy, profile_class, operation):
    command = child_search_command_factory(profile_class=profile_class, operation=operation)
    auth = guardian_auth_factory(command.action_binding)
    with pytest.raises(ConsentDenied, match="web_search_adult_self_consent_required"):
        await getattr(consent_service, operation)(command, auth)
    assert consent_repository_spy.read_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["grant", "revoke"])
@pytest.mark.parametrize("field", ["subject_id", "actor_id", "purpose", "expected_latest_receipt_id", "guardian_generation", "policy_version", "disclosure_version"])
async def test_consent_command_substitution_cannot_reuse_valid_grant(consent_service, bound_consent_command_factory, actor_auth_factory, repository_spies, operation, field):
    command = bound_consent_command_factory(operation=operation)
    auth = actor_auth_factory(command.actor_id, command.action_binding)
    substituted = bound_consent_command_factory(operation=operation, changed_field=field, keep_binding=command.action_binding)
    with pytest.raises(ConsentDenied, match="consent_action_binding_mismatch"):
        await getattr(consent_service, operation)(substituted, auth)
    assert repository_spies.profile_reads == 0 and repository_spies.consent_reads == 0


@pytest.mark.asyncio
async def test_grant_binding_cannot_execute_revoke(consent_service, bound_consent_command_factory, actor_auth_factory, repository_spies):
    grant_command = bound_consent_command_factory(operation="grant")
    auth = actor_auth_factory(grant_command.actor_id, grant_command.action_binding)
    with pytest.raises(ConsentDenied, match="consent_action_binding_mismatch"):
        await consent_service.revoke(grant_command, auth)
    assert repository_spies.profile_reads == 0 and repository_spies.consent_reads == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("forgery", ["cross_adult_actor", "guardian_actor", "legacy_restored_guardian"])
@pytest.mark.parametrize("profile_class", [ProfileClass.OWNER, ProfileClass.ADULT])
async def test_web_search_use_rejects_hmac_valid_non_self_receipt(consent_service, hmac_valid_search_receipt_factory, adult_subject_factory, consent_repository, now, forgery, profile_class):
    # Restoration/import code must not be able to bypass the current service rule
    # merely by producing a receipt with a valid historical HMAC.
    subject = adult_subject_factory(profile_class)
    await consent_repository.install_latest(hmac_valid_search_receipt_factory(subject=subject, forgery=forgery))
    with pytest.raises(ConsentDenied, match="web_search_adult_self_receipt_required"):
        await consent_service.require_current(subject.id, ConsentPurpose.WEB_SEARCH, now)

@pytest.mark.asyncio
async def test_subject_receipt_hmac_cannot_cross_household_subject_or_purpose(identity_mutations, consent_service, adult_a, adult_a_grant, receipt_tamper):
    receipt = await identity_mutations.grant_consent(GrantConsent(subject_id=adult_a.id, actor_id=adult_a.id, purpose=ConsentPurpose.CLOUD_REASONING, action_binding=adult_a_grant.binding), adult_a_grant.id)
    for changed in receipt_tamper.each(receipt, fields=("household_id", "subject_id", "purpose", "guardian_id", "guardian_generation")):
        with pytest.raises(ConsentDenied, match="consent_receipt_hmac_invalid"):
            await consent_service.verify_receipt(changed)

@pytest.mark.asyncio
async def test_guest_receipt_is_challenge_and_session_bound(guest_consent_service, active_guest_disclosure, active_session, other_session, now):
    receipt = await guest_consent_service.accept_challenge(active_guest_disclosure.id, "yes", now)
    assert receipt.expires_at == active_session.expires_at
    await guest_consent_service.require_current(active_session.household_id, active_session.id, ConsentPurpose.CLOUD_STT, now)
    with pytest.raises(ConsentDenied, match="current_guest_session_consent_required"):
        await guest_consent_service.require_current(active_session.household_id, other_session.id, ConsentPurpose.CLOUD_STT, now)

@pytest.mark.asyncio
async def test_guest_cannot_mint_consent_without_active_exact_disclosure(guest_consent_service, expired_guest_disclosure, now):
    with pytest.raises(ConsentDenied, match="active_guest_disclosure_challenge_required"):
        await guest_consent_service.accept_challenge(expired_guest_disclosure.id, "yes", now)

@pytest.mark.asyncio
async def test_guest_disclosure_challenge_is_signed_and_exactly_once(guest_consent_service, active_guest_disclosure, tampered_guest_disclosure, now):
    with pytest.raises(ConsentDenied, match="active_guest_disclosure_challenge_required"):
        await guest_consent_service.accept_challenge(tampered_guest_disclosure.id, "yes", now)
    results = await asyncio.gather(guest_consent_service.accept_challenge(active_guest_disclosure.id, "yes", now), guest_consent_service.accept_challenge(active_guest_disclosure.id, "yes", now), return_exceptions=True)
    assert sum(not isinstance(item, Exception) for item in results) == 1

@pytest.mark.asyncio
async def test_guest_challenge_requires_exact_local_presentation_receipt(guest_consent_service, active_session, other_session_disclosure_receipt, now):
    with pytest.raises(ConsentDenied, match="guest_disclosure_presentation_mismatch"):
        await guest_consent_service.issue_challenge(active_session.household_id, active_session.id, ConsentPurpose.CLOUD_REASONING, "phase1-disclosure-v1", other_session_disclosure_receipt.id, now)


@pytest.mark.asyncio
async def test_guest_web_search_is_denied_before_session_or_receipt_lookup(guest_consent_service, active_session, local_disclosure_receipt, guest_repository_spies, now):
    with pytest.raises(ConsentDenied, match="guest_disclosure_purpose_denied"):
        await guest_consent_service.issue_challenge(active_session.household_id, active_session.id, ConsentPurpose.WEB_SEARCH, "phase1-disclosure-v1", local_disclosure_receipt.id, now)
    with pytest.raises(ConsentDenied, match="guest_disclosure_purpose_denied"):
        await guest_consent_service.require_current(active_session.household_id, active_session.id, ConsentPurpose.WEB_SEARCH, now)
    assert guest_repository_spies.session_reads == 0
    assert guest_repository_spies.receipt_reads == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["grant", "revoke", "require_current"])
@pytest.mark.parametrize("state", ["inactive", "revoked"])
async def test_subject_consent_operations_require_current_active_profile_before_receipt_access(
    consent_service, subject_in_state_factory, consent_command_factory,
    actor_auth_factory, consent_repository_spy, now, operation, state,
):
    subject = subject_in_state_factory(state)
    with pytest.raises(ConsentDenied, match="current_active_subject_required"):
        if operation == "require_current":
            await consent_service.require_current(subject.id, ConsentPurpose.CLOUD_REASONING, now)
        else:
            command = consent_command_factory(subject, operation=operation)
            await getattr(consent_service, operation)(command, actor_auth_factory(command.action_binding))
    assert consent_repository_spy.read_count == 0
```

```python
# tests/integration/identity/test_profile_consent_migration.py
import pytest
import sqlalchemy as sa


def _checks(sync_connection, table: str) -> tuple[str, ...]:
    return tuple(item["sqltext"] for item in sa.inspect(sync_connection).get_check_constraints(table))


@pytest.mark.asyncio
async def test_migration_has_adult_search_but_exact_guest_cloud_purposes(migrated_sqlcipher_engine):
    async with migrated_sqlcipher_engine.connect() as connection:
        checks = await connection.run_sync(
            lambda sync: {
                table: _checks(sync, table)
                for table in ("consent_receipts", "guest_disclosure_challenges", "guest_session_consent_receipts")
            }
        )
    assert "purpose IN ('face','voice','personalization','cloud_stt','cloud_reasoning','cloud_tts','web_search','child_durable_memory_v1')" in checks["consent_receipts"]
    assert "purpose!='web_search' OR (actor_id=subject_id AND guardian_id IS NULL)" in checks["consent_receipts"]
    assert "purpose!='child_durable_memory_v1' OR (guardian_id IS NOT NULL AND guardian_generation >= 1 AND actor_id=guardian_id)" in checks["consent_receipts"]
    for table in ("guest_disclosure_challenges", "guest_session_consent_receipts"):
        assert "purpose IN ('cloud_stt','cloud_reasoning','cloud_tts')" in checks[table]
        assert all("web_search" not in constraint for constraint in checks[table])


@pytest.mark.asyncio
async def test_subject_schema_has_encrypted_optimistic_persona_storage(migrated_sqlcipher_engine):
    async with migrated_sqlcipher_engine.connect() as connection:
        columns = await connection.run_sync(
            lambda sync: {item["name"]: item for item in sa.inspect(sync).get_columns("subjects")}
        )
    assert columns["encrypted_persona_traits"]["type"].python_type is bytes
    assert columns["encrypted_persona_traits"]["nullable"] is True
    assert columns["version"]["nullable"] is False


@pytest.mark.asyncio
async def test_revocation_outbox_is_durable_leased_and_idempotent(migrated_sqlcipher_engine):
    async with migrated_sqlcipher_engine.connect() as connection:
        columns, uniques, checks = await connection.run_sync(
            lambda sync: (
                {item["name"]: item for item in sa.inspect(sync).get_columns("subject_revocation_outbox")},
                sa.inspect(sync).get_unique_constraints("subject_revocation_outbox"),
                _checks(sync, "subject_revocation_outbox"),
            )
        )
    assert set(columns) == {
        "id", "event_key", "subject_id", "new_authority_generation", "state",
        "occurred_at", "claimed_at", "lease_owner", "lease_expires_at",
        "fencing_token", "completed_at", "attempt_count", "last_error",
        "reconciliation_receipt_id",
    }
    assert any(item["column_names"] == ["event_key"] for item in uniques)
    assert "state IN ('pending','processing','completed')" in checks
    assert "attempt_count >= 0 AND fencing_token >= 0" in checks


@pytest.mark.asyncio
async def test_revocation_effect_claims_are_durable_leased_and_idempotent(migrated_sqlcipher_engine):
    async with migrated_sqlcipher_engine.connect() as connection:
        columns,uniques,checks=await connection.run_sync(
            lambda sync:(
                {item["name"]:item for item in sa.inspect(sync).get_columns("subject_revocation_effects")},
                sa.inspect(sync).get_unique_constraints("subject_revocation_effects"),
                _checks(sync,"subject_revocation_effects"),
            )
        )
    assert set(columns)=={
        "id","event_id","family","idempotency_key","state","lease_owner",
        "leased_until","fencing_token","attempt_count","downstream_receipt_id","disposition",
        "last_error","created_at","completed_at",
    }
    assert any(item["column_names"]==["idempotency_key"] for item in uniques)
    assert any(item["column_names"]==["event_id","family"] for item in uniques)
    assert "state IN ('pending','applying','completed')" in checks
    assert "attempt_count >= 0 AND fencing_token >= 0" in checks


@pytest.mark.asyncio
async def test_current_owner_authority_has_one_generation_bound_subject_per_household(migrated_sqlcipher_engine):
    async with migrated_sqlcipher_engine.connect() as connection:
        columns, uniques = await connection.run_sync(
            lambda sync: (
                {item["name"]: item for item in sa.inspect(sync).get_columns("current_owner_authority")},
                sa.inspect(sync).get_unique_constraints("current_owner_authority"),
            )
        )
    assert set(columns) == {"household_id", "subject_id", "owner_generation", "changed_at"}
    assert any(item["column_names"] == ["subject_id"] for item in uniques)


@pytest.mark.asyncio
async def test_web_search_subject_receipt_invariant_survives_downgrade_reupgrade(migration_runner):
    await migration_runner.downgrade("0001")
    await migration_runner.upgrade("0002")
    checks = await migration_runner.check_constraints("consent_receipts")
    assert "purpose!='web_search' OR (actor_id=subject_id AND guardian_id IS NULL AND guardian_generation IS NULL)" in checks


@pytest.mark.asyncio
async def test_subject_authority_generation_is_non_null_monotonic_state(migrated_sqlcipher_engine):
    async with migrated_sqlcipher_engine.connect() as connection:
        columns, checks = await connection.run_sync(
            lambda sync: (
                {item["name"]: item for item in sa.inspect(sync).get_columns("subjects")},
                _checks(sync, "subjects"),
            )
        )
    assert columns["authority_generation"]["nullable"] is False
    assert "authority_generation >= 1" in checks
```

```python
# tests/integration/identity/test_profile_revocation.py
import pytest

from tuntun_core.adapters.sqlcipher.subject_revocation_outbox_repository import (
    SubjectRevocationOutboxRepository,
)
from tuntun_core.services.identity.subject_revocation_processor import SubjectRevocationProcessor
from tuntun_core.workers.subject_revocation_worker import SubjectRevocationWorker

AUTHORITY_FAMILIES = frozenset({
    "sessions", "consents", "enrollments", "biometric_templates",
    "provider_routes", "search_capabilities", "action_authorities", "memory_authorities",
})


@pytest.mark.asyncio
async def test_profile_revocation_advances_generation_and_revokes_every_authority_in_one_commit(
    identity_mutations, active_subject_with_task1_authorities, revoke_profile_grant,
    subject_authority_snapshot,
):
    subject = active_subject_with_task1_authorities
    before = await subject_authority_snapshot(subject.id)
    revoked = await identity_mutations.revoke_profile(subject.revoke_command, revoke_profile_grant.id)
    after = await subject_authority_snapshot(subject.id)
    event = await subject_authority_snapshot.revocation_outbox_event(
        subject.id, revoked.authority_generation,
    )
    assert revoked.authority_generation == before.authority_generation + 1
    assert revoked.active is False and revoked.revoked_at is not None
    assert after.invalidated_families == AUTHORITY_FAMILIES
    assert event.event_key == f"subject-revoked:{subject.id}:{revoked.authority_generation}"
    assert event.subject_id == subject.id
    assert event.new_authority_generation == revoked.authority_generation
    assert event.state == "pending"


@pytest.mark.asyncio
@pytest.mark.parametrize("fault_after", [
    "sessions", "consents", "enrollments", "biometric_templates",
    "provider_routes", "search_capabilities", "action_authorities",
    "memory_authorities", "outbox", "audit",
])
async def test_revocation_fault_rolls_back_profile_authorities_and_outbox_together(
    identity_mutations, active_subject_with_task1_authorities, revoke_profile_grant,
    subject_authority_snapshot, revocation_faults, fault_after,
):
    subject=active_subject_with_task1_authorities
    before=await subject_authority_snapshot(subject.id)
    revocation_faults.raise_after(fault_after)
    with pytest.raises(RuntimeError, match="injected_revocation_fault"):
        await identity_mutations.revoke_profile(subject.revoke_command,revoke_profile_grant.id)
    after=await subject_authority_snapshot(subject.id)
    assert after.profile == before.profile
    assert after.active_authorities == before.active_authorities
    assert await subject_authority_snapshot.revocation_outbox_events(subject.id) == ()


@pytest.mark.asyncio
@pytest.mark.parametrize("winner", ["revoke", "consume"])
async def test_revoke_vs_consume_has_one_sqlcipher_linearization_point(
    revoke_consume_race, network_capture, effect_capture, winner,
):
    result = await revoke_consume_race.run(first=winner)
    if winner == "revoke":
        assert result.consume_error == "current_subject_authority_required"
        assert network_capture == [] and effect_capture == []
    else:
        assert result.claim_committed_before_revocation is True
        assert result.post_commit_disposition in {"cancelled", "conservatively_settled", "completed_once"}
        assert result.replay_attempts == 0


@pytest.mark.asyncio
async def test_restart_rejects_every_pre_revocation_authority_generation(
    restarted_identity_runtime, revoked_subject_fixture,
):
    stale = revoked_subject_fixture.pre_revocation_authorities
    outcomes = await restarted_identity_runtime.try_each(stale)
    assert set(outcomes) == AUTHORITY_FAMILIES
    assert all(item.error == "current_subject_authority_required" for item in outcomes.values())
    assert restarted_identity_runtime.network_capture == []


@pytest.mark.asyncio
async def test_revocation_outbox_reconciles_started_work_once_after_restart(
    crash_after_profile_revocation_commit, restarted_identity_runtime,
):
    assert isinstance(restarted_identity_runtime.revocation_outbox, SubjectRevocationOutboxRepository)
    assert isinstance(restarted_identity_runtime.revocation_worker, SubjectRevocationWorker)
    event_id = await crash_after_profile_revocation_commit()
    first = await restarted_identity_runtime.drain_subject_revocations()
    second = await restarted_identity_runtime.drain_subject_revocations()
    assert first.completed_event_ids == (event_id,)
    assert second.completed_event_ids == ()
    assert restarted_identity_runtime.audit_count(event_id) == 1
```

```python
# tests/unit/identity/test_subject_revocation_worker.py
import asyncio
import pytest

from tuntun_core.adapters.sqlcipher.subject_revocation_outbox_repository import (
    SubjectRevocationOutboxRepository,
)
from tuntun_core.services.identity.subject_revocation_processor import SubjectRevocationProcessor
from tuntun_core.workers.subject_revocation_worker import SubjectRevocationWorker


@pytest.mark.asyncio
async def test_immediate_restart_defers_live_claim_nonfatally_then_becomes_ready_at_expiry(
    file_backed_revocation_outbox_uow_factory, processing_event_factory,
    revocation_processor, clock,
):
    event=processing_event_factory("unexpired",seconds_remaining=30)
    repository = SubjectRevocationOutboxRepository(file_backed_revocation_outbox_uow_factory)
    worker = SubjectRevocationWorker(repository,revocation_processor,clock.heartbeats,clock)
    recovery=asyncio.create_task(worker.recover_and_drain_before_ready())
    await clock.advance_and_flush(seconds=29)
    assert not recovery.done()
    assert await repository.state(event.id)=="processing"
    assert repository.takeover_count(event.id)==0
    await clock.advance_and_flush(seconds=1)
    await recovery
    assert await repository.state(event.id) == "completed"
    assert revocation_processor.receipts_for(event.id) == 1


@pytest.mark.asyncio
async def test_two_workers_do_not_steal_seventy_five_second_call_with_heartbeats(
    two_revocation_workers,long_running_downstream,clock,
):
    first,second=two_revocation_workers
    event=await long_running_downstream.enqueue(duration_seconds=75)
    first_run=asyncio.create_task(first.run_one_periodic_drain())
    for seconds in (11,20,20,20):
        await clock.advance_and_flush(seconds=seconds)
        await second.run_one_periodic_drain()
    await clock.advance_and_flush(seconds=4); await first_run
    assert long_running_downstream.keys==(
        long_running_downstream.fixed_key(event.id,"provider_routes"),
    )
    assert long_running_downstream.side_effect_count==1
    assert two_revocation_workers.stale_fence_completions==0


@pytest.mark.asyncio
async def test_crashed_worker_expires_then_second_worker_reopens_exact_receipt_and_fences_late_completion(
    two_revocation_workers,crash_after_downstream_commit,clock,
):
    first,second=two_revocation_workers
    event,old_claim,receipt=await crash_after_downstream_commit(first)
    await second.run_one_periodic_drain()
    assert second.completed_event_ids==()
    await clock.advance_and_flush(seconds=30)
    await second.run_one_periodic_drain()
    assert second.completed_event_ids==(event.id,)
    assert crash_after_downstream_commit.effect_count(receipt.idempotency_key)==1
    with pytest.raises(RuntimeError,match="subject_revocation_claim_lost"):
        await first.complete_with_stale_fence(old_claim,receipt)


@pytest.mark.asyncio
async def test_startup_does_not_report_ready_when_revocation_drain_fails(
    task1_identity_bootstrap, revocation_processor, clock,
):
    revocation_processor.fail(RuntimeError("reconciliation unavailable"))
    with pytest.raises(RuntimeError, match="reconciliation unavailable"):
        await task1_identity_bootstrap.start()
    assert task1_identity_bootstrap.ready is False


@pytest.mark.asyncio
async def test_committed_revocation_live_kick_completes_without_process_restart(
    task1_identity_runtime,active_subject_with_task1_started_authorities,
    revoke_profile_grant,
):
    runtime=await task1_identity_runtime.start()
    assert isinstance(runtime.revocation_worker,SubjectRevocationWorker)
    assert isinstance(runtime.revocation_processor,SubjectRevocationProcessor)
    event=await runtime.revoke_profile(
        active_subject_with_task1_started_authorities,revoke_profile_grant,
    )
    await runtime.revocation_worker.wait_until_idle()
    assert await runtime.revocation_outbox.state(event.id)=="completed"
    assert runtime.process_restart_count==0
    assert runtime.revocation_processor.receipts_for(event.id)==1


@pytest.mark.asyncio
async def test_live_processor_error_requeues_event_and_fails_runtime_readiness(
    task1_identity_runtime,active_subject_with_task1_started_authorities,
    revoke_profile_grant,
):
    runtime=await task1_identity_runtime.start()
    runtime.revocation_processor.fail_family(
        "search_capabilities",RuntimeError("search cancellation unavailable"),
    )
    event=await runtime.revoke_profile(
        active_subject_with_task1_started_authorities,revoke_profile_grant,
    )
    with pytest.raises(RuntimeError,match="search cancellation unavailable"):
        await runtime.wait_for_revocation_worker_failure()
    assert runtime.ready is False
    assert await runtime.revocation_outbox.state(event.id)=="pending"
    assert await runtime.revocation_outbox.last_error(event.id)=="processor_error:RuntimeError"


@pytest.mark.asyncio
@pytest.mark.parametrize("unsafe_state",("worker_unavailable","backlog_over_limit"))
async def test_identity_readiness_fails_for_unavailable_worker_or_unsafe_backlog(
    task1_identity_bootstrap,unsafe_state,
):
    task1_identity_bootstrap.configure_revocation_state(unsafe_state)
    with pytest.raises(RuntimeError,match="subject revocation worker unavailable|subject revocation backlog unsafe"):
        await task1_identity_bootstrap.start()
    assert task1_identity_bootstrap.ready is False
```

```python
# tests/integration/identity/test_subject_revocation_handlers.py
import pytest
from uuid import uuid5

from tuntun_core.services.identity.subject_revocation_handlers import (
    NotInstalledAuthorityRevocationHandler,
    ProviderRouteRevocationHandler,SearchAuthorityRevocationHandler,
)
from tuntun_core.services.identity.subject_revocation import NotInstalledSubjectAuthorityHandler

EXPECTED_HANDLER_TYPES={
    "provider_routes":ProviderRouteRevocationHandler,
    "search_capabilities":SearchAuthorityRevocationHandler,
    "action_authorities":NotInstalledAuthorityRevocationHandler,
    "memory_authorities":NotInstalledAuthorityRevocationHandler,
}


def test_task1_container_composes_exact_schema_stage_handlers(
    task1_identity_container,
):
    handlers=task1_identity_container.post_commit_revocation_handlers
    assert set(handlers)==set(EXPECTED_HANDLER_TYPES)
    assert all(type(handlers[name]) is kind for name,kind in EXPECTED_HANDLER_TYPES.items())
    assert handlers["action_authorities"].owning_revision=="0003_authentication"
    assert handlers["memory_authorities"].owning_revision=="0004_memory"
    assert task1_identity_container.revocation_processor.handlers is handlers


@pytest.mark.asyncio
async def test_live_worker_runs_task1_handlers_once_without_later_schema_access(
    task1_identity_runtime,subject_with_task1_started_authorities,
    revoke_profile_grant,
):
    runtime=await task1_identity_runtime.start()
    event=await runtime.revoke_profile(
        subject_with_task1_started_authorities,revoke_profile_grant,
    )
    await runtime.revocation_worker.wait_until_idle()
    assert await runtime.revocation_outbox.state(event.id)=="completed"
    assert runtime.process_restart_count==0
    assert runtime.revocation_effects.counts(event.id)=={
        "provider_routes":1,"search_capabilities":1,
        "action_authorities":1,"memory_authorities":1,
    }
    assert runtime.revocation_effects.dispositions(event.id)=={
        "provider_routes":"conservatively_settled",
        "search_capabilities":"cancelled",
        "action_authorities":"not_installed_no_authority",
        "memory_authorities":"not_installed_no_authority",
    }
    await runtime.revocation_worker.recover_and_drain_before_ready()
    assert all(value==1 for value in runtime.revocation_effects.counts(event.id).values())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "crash_after",("effect_claim_commit","downstream_effect_commit","effect_complete_commit"),
)
async def test_effect_crash_boundaries_reuse_one_key_receipt_and_side_effect(
    task1_file_backed_identity_runtime,subject_with_task1_started_authorities,
    revoke_profile_grant,revocation_effect_faults,clock,crash_after,
):
    runtime=await task1_file_backed_identity_runtime.start()
    revocation_effect_faults.crash_after(crash_after,family="provider_routes")
    event=await runtime.revoke_profile(
        subject_with_task1_started_authorities,revoke_profile_grant,
    )
    with pytest.raises(BaseException,match="simulated_process_crash"):
        await runtime.revocation_worker.wait_for_crash()
    key=runtime.revocation_effects.fixed_key(event.id,"provider_routes")
    assert key==uuid5(event.id,"provider_routes")
    first_receipt=runtime.downstream_effects.receipt_for_key(key)
    clock.advance(seconds=31)
    restarted=await task1_file_backed_identity_runtime.restart()
    await restarted.revocation_worker.recover_and_drain_before_ready()
    completed=await restarted.revocation_effects.completed(key)
    assert completed is not None
    assert completed.idempotency_key==key
    assert restarted.downstream_effects.effect_count(key)==1
    if first_receipt is not None:
        assert completed.id==first_receipt.id
        assert restarted.downstream_effects.receipt_for_key(key).id==first_receipt.id


@pytest.mark.asyncio
async def test_periodic_drain_takes_expired_effect_but_not_live_effect(
    task1_identity_runtime,stale_and_live_effect_claims,clock,
):
    runtime=await task1_identity_runtime.start_without_initial_drain()
    stale,live=stale_and_live_effect_claims
    await runtime.revocation_worker.run_one_periodic_drain()
    assert await runtime.revocation_effects.state(stale.id)=="completed"
    assert await runtime.revocation_effects.lease_owner(stale.id)!=stale.lease_owner
    assert await runtime.revocation_effects.state(live.id)=="applying"


@pytest.mark.asyncio
@pytest.mark.parametrize("changed",(
    "idempotency_key","event_id","family","subject_id","through_generation",
))
async def test_fenced_effect_completion_rejects_exact_scope_substitution(
    claimed_revocation_effect,revocation_effects,downstream_receipt_variant,changed,
):
    claim,receipt=claimed_revocation_effect
    with pytest.raises(RuntimeError,match="revocation_downstream_receipt_scope_mismatch"):
        await revocation_effects.complete(
            claim.idempotency_key,claim.lease_owner,claim.fencing_token,
            downstream_receipt_variant(receipt,changed),claim.now,
        )
    assert await revocation_effects.state(claim.id)=="applying"


def test_absent_search_build_uses_closed_concrete_no_authority_handler(
    absent_search_identity_container,
):
    handler=absent_search_identity_container.post_commit_revocation_handlers[
        "search_capabilities"
    ]
    assert type(handler) is SearchAuthorityRevocationHandler
    assert handler.feature_state=="absent"
```

`subject_authority_snapshot` and its outbox methods query the migrated file-backed SQLCipher tables through a new connection; they do not project transaction metadata onto the frozen `Profile` DTO. The fault fixture raises after each concrete handler/outbox/audit boundary before commit, proving that profile generation, all eight authority families, and the persisted outbox row roll back together.

```python
# tests/unit/identity/test_current_owner_repository.py
import pytest


@pytest.mark.asyncio
async def test_current_owner_pointer_requires_active_exact_subject_generation_and_version(
    current_owner_repository, owner, now
):
    snapshot = await current_owner_repository.require_exact(
        owner.household_id, owner.id, owner_generation=1, profile_version=owner.version, now=now
    )
    assert (snapshot.subject_id, snapshot.owner_generation, snapshot.profile_version) == (
        owner.id, 1, owner.version,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change", ["owner_replaced", "owner_generation_changed", "profile_version_changed", "owner_revoked"]
)
async def test_stale_owner_snapshot_is_rejected(current_owner_scenario, change):
    stale = await current_owner_scenario.snapshot_then(change)
    with pytest.raises(PermissionError, match="current_owner_authority_required"):
        await current_owner_scenario.repository.require_exact(
            stale.household_id,
            stale.subject_id,
            owner_generation=stale.owner_generation,
            profile_version=stale.profile_version,
            now=current_owner_scenario.now,
        )
```

```python
# tests/unit/identity/test_profiles.py
import pytest
from tuntun_contracts.identity import PersonaTraits
from tuntun_core.domain.profile import ProfileClass, UpdatePersonaTraits
from tuntun_core.services.identity.consent import ConsentDenied
from tuntun_core.services.identity.profiles import StaleProfileVersion

def test_profile_consent_receipt_inventory_is_bounded_and_unique(profile_factory):
    schema=profile_factory.model_type.model_json_schema()["properties"]["current_consent_receipt_ids"]
    assert schema["maxItems"]==8
    with pytest.raises(ValueError): profile_factory(current_consent_receipt_ids=profile_factory.nine_receipt_ids())
    receipt=profile_factory.receipt_id()
    with pytest.raises(ValueError): profile_factory(current_consent_receipt_ids=(receipt,receipt))

@pytest.mark.asyncio
async def test_guest_is_projection_not_persisted(profile_service, profile_repository, household_id):
    projection = await profile_service.get_projection(household_id, None)
    assert projection.profile_class is ProfileClass.GUEST
    assert await profile_repository.count_subjects(household_id) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["missing", "inactive", "revoked"])
async def test_unresolved_or_stale_subject_is_guest_for_all_read_projections(
    profile_service, profile_repository, household_id, now, state
):
    subject_id = await profile_repository.subject_in_state(household_id, state)
    assert (await profile_service.get_projection(household_id, subject_id)).profile_class is ProfileClass.GUEST
    assert await profile_service.current_policy_class(household_id, subject_id) is ProfileClass.GUEST
    assert (await profile_service.get_persona_projection(household_id, subject_id, now)).role == "guest"


@pytest.mark.asyncio
async def test_projection_does_not_turn_database_failure_into_guest(profile_service, profile_repository, household_id, now):
    profile_repository.fail_optional_read(RuntimeError("sqlcipher_unavailable"))
    with pytest.raises(RuntimeError, match="sqlcipher_unavailable"):
        await profile_service.get_persona_projection(household_id, profile_repository.any_subject_id, now)


@pytest.mark.asyncio
@pytest.mark.parametrize(("profile_class", "learning_level"), [(ProfileClass.K2, "k2"), (ProfileClass.N1, "n1")])
async def test_missing_or_revoked_personalization_keeps_child_safety_class(profile_service, child_without_personalization_consent_factory, profile_class, learning_level, now):
    child = child_without_personalization_consent_factory(profile_class, encrypted_custom_traits=True)
    projection = await profile_service.get_persona_projection(child.household_id, child.id, now)
    assert projection.model_dump() == {
        "role": profile_class.value, "context": "early_learning", "tone": "warm",
        "depth": "brief", "learning_level": learning_level,
    }


@pytest.mark.asyncio
async def test_missing_personalization_uses_neutral_adult_defaults_not_guest(profile_service, adult_without_personalization_consent, now):
    projection = await profile_service.get_persona_projection(adult_without_personalization_consent.household_id, adult_without_personalization_consent.id, now)
    assert projection.model_dump() == {
        "role": "adult", "context": "general", "tone": "neutral", "depth": "standard", "learning_level": "none",
    }


@pytest.mark.asyncio
async def test_adult_replaces_and_clears_only_own_encrypted_persona(identity_mutations, profile_service, adult_a, adult_a_persona_grant, adult_a_clear_grant, sqlcipher_raw_scan, now):
    traits = PersonaTraits(context="technical_security", tone="precise", depth="detailed", learning_level="none")
    updated = await identity_mutations.update_persona_traits(
        UpdatePersonaTraits(subject_id=adult_a.id, actor_id=adult_a.id, target_profile_class=adult_a.profile_class, traits=traits, expected_version=adult_a.version, action_binding=adult_a_persona_grant.binding),
        adult_a_persona_grant.id,
    )
    assert updated.version == adult_a.version + 1 and updated.encrypted_persona_traits is not None
    assert sqlcipher_raw_scan.contains_any(("technical_security", "precise", "detailed")) is False
    projection = await profile_service.get_persona_projection(adult_a.household_id, adult_a.id, now)
    assert projection.model_dump() == {"role":"adult", "context":"technical_security", "tone":"precise", "depth":"detailed", "learning_level":"none"}
    cleared = await identity_mutations.update_persona_traits(
        UpdatePersonaTraits(subject_id=adult_a.id, actor_id=adult_a.id, target_profile_class=adult_a.profile_class, traits=None, expected_version=updated.version, action_binding=adult_a_clear_grant.binding),
        adult_a_clear_grant.id,
    )
    assert cleared.version == updated.version + 1 and cleared.encrypted_persona_traits is None


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["replace", "clear"])
async def test_owner_cannot_impersonate_another_adult_persona(identity_mutations, adult_b_persona_command_factory, owner_grant_factory, operation):
    command = adult_b_persona_command_factory(actor="owner", operation=operation)
    grant = owner_grant_factory(command.action_binding)
    with pytest.raises(PermissionError, match="profile_persona_subject_authority_required"):
        await identity_mutations.update_persona_traits(command, grant.id)


@pytest.mark.asyncio
@pytest.mark.parametrize(("profile_class", "learning_level"), [(ProfileClass.K2, "k2"), (ProfileClass.N1, "n1")])
async def test_current_guardian_can_set_only_child_safe_age_learning_persona(identity_mutations, child_profile_factory, guardian_persona_grant_factory, profile_class, learning_level):
    child = child_profile_factory(profile_class)
    valid = PersonaTraits(context="early_learning", tone="warm", depth="brief", learning_level=learning_level)
    grant = guardian_persona_grant_factory(child, valid)
    updated = await identity_mutations.update_persona_traits(
        UpdatePersonaTraits(subject_id=child.id, actor_id=child.guardian_id, target_profile_class=child.profile_class, traits=valid, expected_version=child.version, guardian_generation=child.guardian_generation, action_binding=grant.binding),
        grant.id,
    )
    assert updated.version == child.version + 1
    invalid = PersonaTraits(context="technical_security", tone="precise", depth="detailed", learning_level=learning_level)
    invalid_grant = guardian_persona_grant_factory(updated, invalid)
    with pytest.raises(PermissionError, match="child_persona_traits_invalid"):
        await identity_mutations.update_persona_traits(
            UpdatePersonaTraits(subject_id=child.id, actor_id=child.guardian_id, target_profile_class=updated.profile_class, traits=invalid, expected_version=updated.version, guardian_generation=updated.guardian_generation, action_binding=invalid_grant.binding),
            invalid_grant.id,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("profile_class", [ProfileClass.K2, ProfileClass.N1])
async def test_current_guardian_can_clear_child_persona_with_exact_generation(identity_mutations, child_profile_factory, guardian_persona_grant_factory, profile_class):
    child = child_profile_factory(profile_class, encrypted_custom_traits=True)
    grant = guardian_persona_grant_factory(child, None)
    cleared = await identity_mutations.update_persona_traits(
        UpdatePersonaTraits(
            subject_id=child.id, actor_id=child.guardian_id, target_profile_class=child.profile_class,
            traits=None, expected_version=child.version, guardian_generation=child.guardian_generation,
            action_binding=grant.binding,
        ),
        grant.id,
    )
    assert cleared.version == child.version + 1 and cleared.encrypted_persona_traits is None


@pytest.mark.asyncio
@pytest.mark.parametrize(("profile_class", "learning_level"), [(ProfileClass.K2, "k2"), (ProfileClass.N1, "n1")])
@pytest.mark.parametrize("operation", ["replace", "clear"])
async def test_child_persona_guardian_generation_substitution_fails_before_profile_read(
    identity_mutations, child_profile_factory, guardian_persona_grant_factory,
    profile_repository_spy, profile_class, learning_level, operation
):
    child = child_profile_factory(profile_class)
    traits = PersonaTraits(context="early_learning", tone="warm", depth="brief", learning_level=learning_level) if operation == "replace" else None
    grant = guardian_persona_grant_factory(child, traits)
    command = UpdatePersonaTraits(
        subject_id=child.id, actor_id=child.guardian_id, target_profile_class=child.profile_class,
        traits=traits, expected_version=child.version, guardian_generation=child.guardian_generation,
        action_binding=grant.binding,
    )
    substituted = command.model_copy(update={"guardian_generation": command.guardian_generation + 1})
    with pytest.raises(PermissionError, match="action_parameter_commitment_mismatch"):
        await identity_mutations.update_persona_traits(substituted, grant.id)
    assert profile_repository_spy.read_count == 0 and profile_repository_spy.write_count == 0


@pytest.mark.asyncio
async def test_stale_profile_version_or_stale_guardian_cannot_change_persona(identity_mutations, stale_persona_commands):
    for command, grant, reason in stale_persona_commands:
        with pytest.raises((PermissionError, StaleProfileVersion), match=reason):
            await identity_mutations.update_persona_traits(command, grant.id)


@pytest.mark.asyncio
@pytest.mark.parametrize(("operation", "field"), [
    ("create", "household_id"), ("create", "subject_id"), ("create", "profile_class"),
    ("create", "guardian_id"), ("create", "encrypted_display_label"),
    ("update_persona_traits", "traits"), ("update_persona_traits", "target_profile_class"), ("update_persona_traits", "expected_version"), ("update_persona_traits", "guardian_generation"),
    ("revoke", "subject_id"), ("revoke", "expected_version"),
])
async def test_profile_command_substitution_cannot_reuse_valid_grant(profile_service, bound_profile_command_factory, passkey_auth_factory, profile_repository_spy, operation, field):
    command = bound_profile_command_factory(operation=operation)
    auth = passkey_auth_factory(command.action_binding)
    substituted = bound_profile_command_factory(operation=operation, changed_field=field, keep_binding=command.action_binding)
    with pytest.raises(PermissionError, match="action_binding_scope_mismatch|action_parameter_commitment_mismatch"):
        await getattr(profile_service, operation)(substituted, auth)
    assert profile_repository_spy.read_count == 0 and profile_repository_spy.write_count == 0


@pytest.mark.asyncio
async def test_replace_requires_personalization_consent_but_authorized_clear_remains_available(identity_mutations, adult_without_personalization_consent, replace_persona_grant, clear_persona_grant):
    traits = PersonaTraits(context="household_practical", tone="practical", depth="standard", learning_level="none")
    with pytest.raises(ConsentDenied, match="current_consent_required"):
        await identity_mutations.update_persona_traits(
            UpdatePersonaTraits(subject_id=adult_without_personalization_consent.id, actor_id=adult_without_personalization_consent.id, target_profile_class=adult_without_personalization_consent.profile_class, traits=traits, expected_version=adult_without_personalization_consent.version, action_binding=replace_persona_grant.binding),
            replace_persona_grant.id,
        )
    cleared = await identity_mutations.update_persona_traits(
        UpdatePersonaTraits(subject_id=adult_without_personalization_consent.id, actor_id=adult_without_personalization_consent.id, target_profile_class=adult_without_personalization_consent.profile_class, traits=None, expected_version=adult_without_personalization_consent.version, action_binding=clear_persona_grant.binding),
        clear_persona_grant.id,
    )
    assert cleared.encrypted_persona_traits is None
```

- [ ] **Step 2: Run the tests and observe the intended failure**

Run: `uv run pytest tests/unit/identity/test_profiles.py tests/unit/identity/test_consent.py tests/unit/identity/test_current_owner_repository.py tests/unit/identity/test_subject_revocation_worker.py tests/integration/identity/test_subject_revocation_handlers.py tests/integration/identity/test_profile_consent_migration.py tests/integration/identity/test_profile_revocation.py -q`
Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core.domain.profile'`.

- [ ] **Step 3: Implement the domain rules and encrypted migration**

In `identity_uow.py`, declare `IdentityUnitOfWork` as a structural protocol over the foundation transaction methods plus exact repository protocols—never placeholder `Any` protocols. Task 1 owns typed `profiles`, `consent_receipts`, `guest_session_consents`, `guest_disclosure_challenges`, `sessions`, `subject_revocation_outbox`, and `subject_revocation_effects` properties; the sessions facade includes `invalidate_identity_subject(subject_id, reason, now)` for biometric-consent revocation. The production `AsyncUnitOfWorkFactory` registers the outbox/effect facades under those exact properties, and the cascade/container accepts no alternative in-memory implementation outside tests. Each later task adds its exact method-bearing repository protocol and property in the same commit that introduces that repository. Every facade implementation is registered with the foundation `AsyncUnitOfWorkFactory`, contains no connection, and implements each async method solely by calling its bound unit's `run_sync`; the strict-mypy gate therefore rejects missing or dynamically dispatched repository methods. Purpose-specific consent side effects are injected as typed `ConsentRevocationHandlerPort.apply_in_uow(uow, receipt, auth, now)` implementations. Task 1 registers biometric and cloud-route handlers; the controlled-web supplement registers its search-route handler when that typed repository exists; Task 10 registers the child-memory handler when `memory_proposals` exists. Personalization has no identity-session invalidation: every persona projection and recall path rechecks its current receipt, so revocation suppresses only encrypted custom traits and private recall while preserving the canonical role and safe defaults.

```python
# apps/core/src/tuntun_core/domain/profile.py
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator
from tuntun_contracts.actions import ActionBinding
from tuntun_contracts.identity import PersonaProjection, PersonaTraits

class ProfileClass(StrEnum):
    OWNER = "owner"
    ADULT = "adult"
    K2 = "k2"
    N1 = "n1"
    GUEST = "guest"

class ConsentPurpose(StrEnum):
    FACE="face"; VOICE="voice"; PERSONALIZATION="personalization"
    CLOUD_STT="cloud_stt"; CLOUD_REASONING="cloud_reasoning"; CLOUD_TTS="cloud_tts"
    WEB_SEARCH="web_search"; CHILD_DURABLE_MEMORY="child_durable_memory_v1"

GuestConsentPurpose = Literal["cloud_stt", "cloud_reasoning", "cloud_tts"]

class Modality(StrEnum):
    FACE="face"; VOICE="voice"
    @property
    def consent_purpose(self) -> ConsentPurpose: return ConsentPurpose(self.value)

class DomainModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

class CreateProfile(DomainModel):
    household_id: UUID; subject_id: UUID; profile_class: ProfileClass; guardian_id: UUID|None=None
    display_label: str = Field(min_length=1, max_length=128)
    action_binding: ActionBinding
class RevokeProfile(DomainModel):
    subject_id: UUID; expected_version: int; action_binding: ActionBinding
class UpdatePersonaTraits(DomainModel):
    subject_id: UUID; actor_id: UUID; target_profile_class: ProfileClass; traits: PersonaTraits | None
    expected_version: int = Field(ge=1); guardian_generation: int | None = Field(default=None, ge=1); action_binding: ActionBinding
class GrantConsent(DomainModel):
    subject_id: UUID; actor_id: UUID; purpose: ConsentPurpose; expected_latest_receipt_id: UUID | None = None
    guardian_generation: int | None = Field(default=None, ge=1)
    action_binding: ActionBinding; policy_version: str="phase1-v1"; disclosure_version: str="phase1-disclosure-v1"
class RevokeConsent(DomainModel):
    subject_id: UUID; actor_id: UUID; purpose: ConsentPurpose; expected_latest_receipt_id: UUID
    guardian_generation: int | None = Field(default=None, ge=1)
    policy_version: str; disclosure_version: str; action_binding: ActionBinding
class ConsentReceipt(DomainModel):
    id: UUID; household_id: UUID; subject_id: UUID; actor_id: UUID; guardian_id: UUID|None; guardian_generation: int|None; purpose: ConsentPurpose; granted: bool; policy_version: str; disclosure_version: str; commitment_key_id: str; receipt_hmac: bytes; created_at: AwareDatetime; expires_at: AwareDatetime|None=None
class GuestSessionConsentReceipt(DomainModel):
    id: UUID; household_id: UUID; session_id: UUID; purpose: GuestConsentPurpose; disclosure_version: str; granted: bool; issued_at: AwareDatetime; expires_at: AwareDatetime; revoked_at: AwareDatetime|None=None; commitment_key_id: str; receipt_hmac: bytes
class GuestDisclosureChallenge(DomainModel):
    id: UUID; household_id: UUID; session_id: UUID; purpose: GuestConsentPurpose; disclosure_version: str
    state: Literal["open","accepted","denied"]; issued_at: AwareDatetime; expires_at: AwareDatetime; consumed_at: AwareDatetime|None=None
    presentation_receipt_id: UUID; commitment_key_id: str; challenge_hmac: bytes
class RequestEnrollment(DomainModel):
    subject_id: UUID; modality: Modality; expected_profile_version: int = Field(ge=1)
    expected_consent_receipt_id: UUID; action_binding: ActionBinding; reenrollment_days: int=180
class CancelEnrollment(DomainModel):
    subject_id: UUID; enrollment_id: UUID; action_binding: ActionBinding
class EnrollmentSession(DomainModel):
    id: UUID; subject_id: UUID; modality: Modality; state: Literal["requested","capturing","calibrating","approved","cancelled","expired"]
    next_reenrollment_reminder_at: AwareDatetime|None=None; biometric_hard_expires_at: AwareDatetime|None=None

class Profile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    id: UUID
    household_id: UUID
    guardian_id: UUID | None
    guardian_generation: int = Field(ge=0)
    profile_class: ProfileClass
    encrypted_display_label: bytes = Field(min_length=28, max_length=1024)
    encrypted_persona_traits: bytes | None = Field(default=None, min_length=28, max_length=4096)
    current_consent_receipt_ids: Annotated[tuple[UUID,...],Field(min_length=0,max_length=8)] = ()
    active: bool
    authority_generation: int = Field(ge=1)
    version: int = Field(ge=1)
    next_reenrollment_reminder_at: AwareDatetime | None
    created_at: AwareDatetime
    updated_at: AwareDatetime
    revoked_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def guest_is_projection_only(self):
        if self.profile_class is ProfileClass.GUEST:
            raise ValueError("guest_profile_must_not_be_persisted")
        if (self.profile_class in {ProfileClass.K2, ProfileClass.N1}) != (self.guardian_id is not None):
            raise ValueError("guardian_required_exactly_for_child")
        if (self.profile_class in {ProfileClass.K2, ProfileClass.N1}) != (self.guardian_generation >= 1):
            raise ValueError("guardian_generation_required_exactly_for_child")
        return self

    @field_validator("current_consent_receipt_ids")
    @classmethod
    def unique_current_consents(cls,value):
        if len(set(value))!=len(value): raise ValueError("duplicate current consent receipt")
        return value

class ProfileProjection(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    subject_id: UUID | None
    profile_class: ProfileClass
    may_retrieve_private_memory: bool

GUEST_PROJECTION = ProfileProjection(
    subject_id=None,
    profile_class=ProfileClass.GUEST,
    may_retrieve_private_memory=False,
)

GUEST_PERSONA_PROJECTION = PersonaProjection(
    role="guest", context="general", tone="neutral", depth="brief", learning_level="none"
)
```

```python
# apps/core/src/tuntun_core/services/actions/parameter_binding.py
import hmac
import rfc8785

from tuntun_contracts.actions import ActionBinding
from tuntun_contracts.commitments import commit_private


def profile_create_parameters(command) -> dict:
    return {
        "household_id": str(command.household_id), "subject_id": str(command.subject_id),
        "profile_class": command.profile_class.value,
        "guardian_id": None if command.guardian_id is None else str(command.guardian_id),
        "guardian_generation": 1 if command.guardian_id is not None else 0,
        "display_label": command.display_label,
    }


def profile_persona_parameters(command) -> dict:
    return {
        "subject_id": str(command.subject_id),
        "target_profile_class": command.target_profile_class.value,
        "persona_traits": None if command.traits is None else command.traits.model_dump(mode="json"),
        "clear_persona_traits": command.traits is None,
        "expected_version": command.expected_version,
        "guardian_generation": command.guardian_generation,
    }


def profile_revoke_parameters(command) -> dict:
    return {"subject_id": str(command.subject_id), "expected_version": command.expected_version}


def consent_parameters(command) -> dict:
    return {
        "subject_id": str(command.subject_id), "purpose": command.purpose.value,
        "expected_latest_receipt_id": None if command.expected_latest_receipt_id is None else str(command.expected_latest_receipt_id),
        "guardian_generation": command.guardian_generation,
        "policy_version": command.policy_version, "disclosure_version": command.disclosure_version,
    }


def enrollment_request_parameters(command) -> dict:
    return {
        "subject_id": str(command.subject_id), "modality": command.modality.value,
        "expected_profile_version": command.expected_profile_version,
        "expected_consent_receipt_id": str(command.expected_consent_receipt_id),
        "reenrollment_days": command.reenrollment_days,
    }


def enrollment_cancel_parameters(command) -> dict:
    return {"subject_id": str(command.subject_id), "enrollment_id": str(command.enrollment_id)}


def timer_create_parameters(request) -> dict:
    return {"duration_seconds": request.duration_seconds, "label": request.label}


def timer_target_parameters(timer_id, idempotency_key) -> dict:
    return {"timer_id": str(timer_id), "idempotency_key": str(idempotency_key)}


def safety_parameters(reason_code) -> dict:
    return {"reason_code": reason_code}


class ActionParameterBindingVerifier:
    def __init__(self, commitment_root: bytes):
        self._root = commitment_root

    def require(self, binding, *, action_name, resource_type, resource_id, actor_id, parameters) -> None:
        if not (
            binding.action_name == action_name
            and binding.resource_type == resource_type
            and binding.resource_id == resource_id
            and binding.subject_id == actor_id
        ):
            raise PermissionError("action_binding_scope_mismatch")
        expected = commit_private(
            self._root,
            binding.parameter_commitment.key_id,
            "action.parameters",
            rfc8785.dumps(parameters),
        )
        if not hmac.compare_digest(expected.value_b64, binding.parameter_commitment.value_b64):
            raise PermissionError("action_parameter_commitment_mismatch")


class ActionBindingVerifier:
    def require_exact(self, stored, supplied):
        ordinary = (
            stored.household_id == supplied.household_id and stored.proposal_id == supplied.proposal_id
            and stored.turn_id == supplied.turn_id and stored.idempotency_key == supplied.idempotency_key
            and stored.action_name == supplied.action_name and stored.resource_type == supplied.resource_type
            and stored.resource_id == supplied.resource_id and stored.policy_version == supplied.policy_version
            and stored.session_id == supplied.session_id and stored.subject_id == supplied.subject_id
            and stored.parameter_commitment.algorithm == supplied.parameter_commitment.algorithm
            and stored.parameter_commitment.key_id == supplied.parameter_commitment.key_id
        )
        commitment_equal = hmac.compare_digest(
            stored.parameter_commitment.value_b64.encode("ascii"),
            supplied.parameter_commitment.value_b64.encode("ascii"),
        )
        if not ordinary or not commitment_equal:
            raise PermissionError("action_binding_mismatch")

    def require_parts(self, stored, **parts):
        self.require_exact(stored, ActionBinding(**parts))
```

`parameters` is the closed action-specific payload only; the verifier separately checks action, resource, actor, and the complete `ActionBinding` equality remains enforced by fresh authentication. UUIDs are lower-case canonical strings, enums use their values, and traits use `model_dump(mode="json")`. The server preparation path and mutation path must call these same pure payload builders; neither accepts extra keys.

```python
# apps/core/src/tuntun_core/services/identity/profiles.py
from datetime import UTC, timedelta
from tuntun_contracts.identity import PersonaProjection, PersonaTraits
from tuntun_core.domain.profile import ConsentPurpose, GUEST_PERSONA_PROJECTION, GUEST_PROJECTION, Profile, ProfileClass, ProfileProjection
from tuntun_core.services.identity.consent import ConsentDenied
from tuntun_core.services.actions.parameter_binding import ActionBindingVerifier, ActionParameterBindingVerifier, profile_create_parameters, profile_persona_parameters, profile_revoke_parameters

ADULT_PROFILE_CLASSES = frozenset({ProfileClass.OWNER, ProfileClass.ADULT})
CHILD_PROFILE_CLASSES = frozenset({ProfileClass.K2, ProfileClass.N1})

_DEFAULT_PERSONA = {
    ProfileClass.OWNER: PersonaTraits(context="general", tone="neutral", depth="standard", learning_level="none"),
    ProfileClass.ADULT: PersonaTraits(context="general", tone="neutral", depth="standard", learning_level="none"),
    ProfileClass.K2: PersonaTraits(context="early_learning", tone="warm", depth="brief", learning_level="k2"),
    ProfileClass.N1: PersonaTraits(context="early_learning", tone="warm", depth="brief", learning_level="n1"),
}

def require_fresh_passkey(auth, binding, now, binding_verifier, max_age_seconds=120):
    if auth.assurance_source != "passkey":
        raise PermissionError("passkey_binding_required")
    binding_verifier.require_exact(auth.binding, binding)
    if now - auth.consumed_at > timedelta(seconds=max_age_seconds):
        raise PermissionError("fresh_passkey_required")

class ProfileService:
    def __init__(self, uow_factory, mutation_scope, audit_ledger, consent_service, subject_revocations, profile_crypto, parameter_verifier: ActionParameterBindingVerifier, action_binding_verifier: ActionBindingVerifier, clock):
        self._uow_factory, self._scope, self._audit, self._clock = uow_factory, mutation_scope, audit_ledger, clock
        self._consents, self._profile_crypto, self._parameters = consent_service, profile_crypto, parameter_verifier
        self._bindings, self._subject_revocations = action_binding_verifier, subject_revocations

    async def create(self, command, auth):
        if command.profile_class not in {ProfileClass.ADULT, ProfileClass.K2, ProfileClass.N1}:
            raise PermissionError("ordinary_profile_create_owner_forbidden")
        require_fresh_passkey(auth, command.action_binding, self._clock.now(), self._bindings)
        self._parameters.require(
            command.action_binding,
            action_name="profile.create", resource_type="profile", resource_id=command.subject_id, actor_id=auth.subject_id,
            parameters=profile_create_parameters(command),
        )
        if command.action_binding.household_id != command.household_id:
            raise PermissionError("profile_create_household_mismatch")
        now = self._clock.now()
        encrypted_display_label = self._profile_crypto.seal_display_label(command.subject_id, 1, command.display_label)
        profile = Profile(id=command.subject_id, household_id=command.household_id, guardian_id=command.guardian_id, guardian_generation=1 if command.guardian_id is not None else 0, profile_class=command.profile_class, encrypted_display_label=encrypted_display_label, encrypted_persona_traits=None, current_consent_receipt_ids=(), active=True, authority_generation=1, version=1, next_reenrollment_reminder_at=None, created_at=now, updated_at=now)
        uow = self._scope.require_active_uow()
        await uow.profiles.insert(profile)
        await self._audit.append(uow, uow.profiles.created_audit(profile, auth))
        return profile

    async def create_in_uow(self, uow, command, auth):
        if self._scope.require_active_uow() is not uow:
            raise RuntimeError("profile_uow_scope_mismatch")
        return await self.create(command, auth)

    async def get_projection(self, household_id, subject_id):
        if subject_id is None:
            return GUEST_PROJECTION
        async with self._uow_factory() as uow:
            profile = await uow.profiles.get_optional_scoped(household_id, subject_id)
        if profile is None or not profile.active or profile.revoked_at is not None:
            return GUEST_PROJECTION
        # A projection is descriptive, never retrieval authority. Task 11 performs
        # fresh identity, consent, profile, policy, and template checks together.
        return ProfileProjection(subject_id=profile.id, profile_class=profile.profile_class, may_retrieve_private_memory=False)

    async def current_policy_class(self, household_id, subject_id) -> ProfileClass:
        async with self._uow_factory() as uow:
            return await self.current_policy_class_in_uow(uow, household_id, subject_id)

    async def current_policy_class_in_uow(self, uow, household_id, subject_id) -> ProfileClass:
        if subject_id is None:
            return ProfileClass.GUEST
        profile = await uow.profiles.get_optional_scoped(household_id, subject_id)
        if profile is None or not profile.active or profile.revoked_at is not None:
            return ProfileClass.GUEST
        return profile.profile_class

    async def require_current_active_in_uow(self, uow, household_id, subject_id) -> Profile:
        profile = await uow.profiles.get_scoped(household_id, subject_id)
        if not profile.active or profile.revoked_at is not None:
            raise PermissionError("current_active_subject_required")
        return profile

    async def get_persona_projection(self, household_id, subject_id, now) -> PersonaProjection:
        if subject_id is None:
            return GUEST_PERSONA_PROJECTION
        async with self._uow_factory() as uow:
            profile = await uow.profiles.get_optional_scoped(household_id, subject_id)
            if profile is None or not profile.active or profile.revoked_at is not None:
                return GUEST_PERSONA_PROJECTION
            try:
                await self._consents.require_current_in_uow(uow, profile.id, ConsentPurpose.PERSONALIZATION, now)
            except ConsentDenied:
                traits = _DEFAULT_PERSONA[profile.profile_class]
            else:
                traits = _DEFAULT_PERSONA[profile.profile_class] if profile.encrypted_persona_traits is None else self._profile_crypto.open_traits(profile.id, profile.version, profile.encrypted_persona_traits)
            self._require_valid_traits(profile.profile_class, traits)
            return PersonaProjection(role=profile.profile_class.value, **traits.model_dump())

    async def update_persona_traits(self, command, auth):
        self._parameters.require(
            command.action_binding,
            action_name="profile.edit", resource_type="profile", resource_id=command.subject_id, actor_id=command.actor_id,
            parameters=profile_persona_parameters(command),
        )
        require_fresh_passkey(auth, command.action_binding, self._clock.now(), self._bindings)
        if auth.subject_id != command.actor_id:
            raise PermissionError("authenticated_actor_mismatch")
        uow = self._scope.require_active_uow()
        profile = await uow.profiles.get(command.subject_id)
        if profile.household_id != command.action_binding.household_id:
            raise PermissionError("profile_persona_household_mismatch")
        if profile.profile_class is not command.target_profile_class:
            raise PermissionError("profile_persona_target_class_changed")
        if profile.profile_class in ADULT_PROFILE_CLASSES:
            if command.actor_id != profile.id or command.guardian_generation is not None:
                raise PermissionError("profile_persona_subject_authority_required")
        elif profile.profile_class in CHILD_PROFILE_CLASSES:
            if profile.guardian_id != command.actor_id or profile.guardian_generation != command.guardian_generation:
                raise PermissionError("profile_persona_guardian_authority_required")
        else:
            raise PermissionError("profile_persona_subject_authority_required")
        if command.traits is not None:
            await self._consents.require_current_in_uow(uow, profile.id, ConsentPurpose.PERSONALIZATION, self._clock.now())
            self._require_valid_traits(profile.profile_class, command.traits)
            encrypted = self._profile_crypto.seal_traits(profile.id, command.expected_version + 1, command.traits)
            operation = "replace"
        else:
            encrypted, operation = None, "clear"
        updated = await uow.profiles.update_persona_expected_version(profile.id, command.expected_version, encrypted, self._clock.now())
        await self._audit.append(uow, uow.profiles.persona_changed_audit(updated, auth, operation=operation))
        return updated

    async def update_persona_traits_in_uow(self, uow, command, auth):
        if self._scope.require_active_uow() is not uow:
            raise RuntimeError("profile_uow_scope_mismatch")
        return await self.update_persona_traits(command, auth)

    @staticmethod
    def _require_valid_traits(profile_class, traits):
        if profile_class in ADULT_PROFILE_CLASSES:
            if traits.learning_level != "none":
                raise PermissionError("adult_persona_learning_level_invalid")
            return
        expected = profile_class.value
        if not (
            traits.context == "early_learning"
            and traits.tone in {"neutral", "warm"}
            and traits.depth in {"brief", "standard"}
            and traits.learning_level == expected
        ):
            raise PermissionError("child_persona_traits_invalid")

    async def revoke(self, command, auth):
        require_fresh_passkey(auth, command.action_binding, self._clock.now(), self._bindings)
        self._parameters.require(
            command.action_binding,
            action_name="profile.revoke", resource_type="profile", resource_id=command.subject_id, actor_id=auth.subject_id,
            parameters=profile_revoke_parameters(command),
        )
        uow = self._scope.require_active_uow()
        current = await uow.profiles.get(command.subject_id)
        if current.household_id != command.action_binding.household_id:
            raise PermissionError("profile_revoke_household_mismatch")
        if not current.active or current.revoked_at is not None:
            raise PermissionError("current_active_subject_required")
        if current.profile_class is ProfileClass.OWNER:
            raise PermissionError("current_owner_replacement_transaction_required")
        now = self._clock.now()
        revoked = await uow.profiles.revoke_and_advance_authority_generation_expected_version(
            command.subject_id, command.expected_version, current.authority_generation, now
        )
        await self._subject_revocations.apply_in_uow(uow, current, revoked, auth, now)
        await self._audit.append(uow, uow.profiles.revoked_audit(revoked, auth))
        return revoked

    async def revoke_in_uow(self, uow, command, auth):
        if self._scope.require_active_uow() is not uow:
            raise RuntimeError("profile_uow_scope_mismatch")
        return await self.revoke(command, auth)
```

The ordinary `profile.revoke` path cannot revoke the current owner. Recovery-driven owner replacement uses its own transaction: it installs the next `current_owner_authority` pointer, advances the owner generation, and invokes the same subject-revocation cascade for the former owner before committing.

```python
# apps/core/src/tuntun_core/services/identity/subject_revocation.py
from typing import Protocol

REQUIRED_SUBJECT_AUTHORITY_FAMILIES = (
    "sessions", "consents", "enrollments", "biometric_templates",
    "provider_routes", "search_capabilities", "action_authorities", "memory_authorities",
)


class SubjectAuthorityRevocationHandler(Protocol):
    async def revoke_in_uow(
        self, uow, *, household_id, subject_id, through_generation, reason, now
    ) -> None: ...

class NotInstalledSubjectAuthorityHandler:
    _ALLOWED={"action_authorities":"0003_authentication","memory_authorities":"0004_memory"}
    def __init__(self,capability_stage,*,family,owning_revision):
        if self._ALLOWED.get(family)!=owning_revision:
            raise ValueError("closed not-installed authority family required")
        self._stage,self.family,self.owning_revision=capability_stage,family,owning_revision
    async def revoke_in_uow(self,uow,**scope):
        self._stage.require_schema_and_facade_absent_in_uow(
            uow,self.family,self.owning_revision,
        )


class SubjectAuthorityRevocationCascade:
    def __init__(self, handlers, outbox):
        if len(handlers) != len(REQUIRED_SUBJECT_AUTHORITY_FAMILIES) or set(handlers) != set(REQUIRED_SUBJECT_AUTHORITY_FAMILIES):
            raise RuntimeError("complete_subject_revocation_handlers_required")
        self._handlers, self._outbox = handlers, outbox

    async def apply_in_uow(self, uow, current, revoked, auth, now):
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
        # Fixed-name signal is discarded on rollback and offered only after
        # the SQLCipher commit containing profile, authorities, and outbox.
        uow.signal_after_commit("subject_revocation")
```

```python
# apps/core/src/tuntun_core/adapters/sqlcipher/subject_revocation_outbox_repository.py
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

@dataclass(frozen=True,slots=True)
class OutboxClaim:
    event: object
    lease_owner: UUID
    fencing_token: int
    leased_until: datetime


class SubjectRevocationOutboxRepository:
    """Async facade; every operation executes on the foundation SQLCipher worker."""

    def __init__(self, uow_factory):
        self._uow_factory = uow_factory

    @staticmethod
    def _utc(value):
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    async def enqueue_in_uow(
        self, uow, *, event_key: str, subject_id: UUID,
        new_authority_generation: int, occurred_at,
    ):
        return await uow.run_sync(
            lambda connection: connection.exec_driver_sql(
                """INSERT INTO subject_revocation_outbox
                   (id,event_key,subject_id,new_authority_generation,state,occurred_at,attempt_count,fencing_token)
                   VALUES (?,?,?,?, 'pending', ?,0,0)
                   ON CONFLICT(event_key) DO NOTHING""",
                (str(uuid4()), event_key, str(subject_id), new_authority_generation, self._utc(occurred_at)),
            )
        )

    async def recover_expired(self, now) -> int:
        async with self._uow_factory() as uow:
            changed=await uow.run_sync(
                lambda connection: connection.exec_driver_sql(
                    """UPDATE subject_revocation_outbox
                       SET state='pending',claimed_at=NULL,lease_owner=NULL,
                           lease_expires_at=NULL,last_error='expired_lease_recovered'
                       WHERE state='processing' AND lease_expires_at<=?""",
                    (self._utc(now),),
                ).rowcount
            )
            await uow.commit()
            return changed

    async def claim_next(self, now, lease_owner):
        lease_expires_at = now + timedelta(seconds=30)
        async with self._uow_factory() as uow:
            event = await uow.run_sync(
                lambda connection: connection.exec_driver_sql(
                    """UPDATE subject_revocation_outbox
                       SET state='processing',claimed_at=?,lease_owner=?,lease_expires_at=?,
                           attempt_count=attempt_count+1,fencing_token=fencing_token+1,last_error=NULL
                       WHERE id=(SELECT id FROM subject_revocation_outbox
                                 WHERE state='pending' ORDER BY occurred_at,id LIMIT 1)
                       RETURNING *""",
                    (self._utc(now),str(lease_owner),self._utc(lease_expires_at)),
                ).fetchone()
            )
            await uow.commit()
            if event is None: return None
            return OutboxClaim(event,lease_owner,int(event.fencing_token),lease_expires_at)

    async def renew(self,event_id,lease_owner,fencing_token,now) -> bool:
        leased_until=now+timedelta(seconds=30)
        async with self._uow_factory() as uow:
            changed=await uow.run_sync(lambda connection:connection.exec_driver_sql(
                """UPDATE subject_revocation_outbox SET lease_expires_at=?
                   WHERE id=? AND state='processing' AND lease_owner=?
                   AND fencing_token=? AND lease_expires_at>?""",
                (self._utc(leased_until),str(event_id),str(lease_owner),fencing_token,self._utc(now)),
            ).rowcount)
            await uow.commit(); return changed==1

    async def complete(self,event_id,receipt_id,lease_owner,fencing_token,now) -> None:
        async with self._uow_factory() as uow:
            changed = await uow.run_sync(
                lambda connection: connection.exec_driver_sql(
                    """UPDATE subject_revocation_outbox
                       SET state='completed',completed_at=?,lease_owner=NULL,lease_expires_at=NULL,
                           reconciliation_receipt_id=?,last_error=NULL
                       WHERE id=? AND state='processing' AND lease_owner=?
                       AND fencing_token=? AND lease_expires_at>?""",
                    (self._utc(now),str(receipt_id),str(event_id),str(lease_owner),
                     fencing_token,self._utc(now)),
                ).rowcount
            )
            if changed != 1:
                raise RuntimeError("subject_revocation_claim_lost")
            await uow.commit()

    async def retry_pending(self,event_id,lease_owner,fencing_token,reason_code,now) -> None:
        if len(reason_code)>128: raise ValueError("revocation reason code too long")
        async with self._uow_factory() as uow:
            changed=await uow.run_sync(
                lambda connection: connection.exec_driver_sql(
                    """UPDATE subject_revocation_outbox
                       SET state='pending',claimed_at=NULL,lease_owner=NULL,lease_expires_at=NULL,
                           last_error=? WHERE id=? AND state='processing'
                           AND lease_owner=? AND fencing_token=? AND lease_expires_at>?""",
                    (reason_code,str(event_id),str(lease_owner),fencing_token,self._utc(now)),
                ).rowcount
            )
            if changed!=1: raise RuntimeError("subject_revocation_claim_lost")
            await uow.commit()

    async def defer_until(self,event_id,lease_owner,fencing_token,leased_until,now) -> None:
        async with self._uow_factory() as uow:
            changed=await uow.run_sync(lambda connection:connection.exec_driver_sql(
                """UPDATE subject_revocation_outbox
                   SET lease_expires_at=?,last_error='deferred_live_effect_lease'
                   WHERE id=? AND state='processing' AND lease_owner=?
                   AND fencing_token=? AND lease_expires_at>?""",
                (self._utc(leased_until),str(event_id),str(lease_owner),fencing_token,
                 self._utc(now)),
            ).rowcount)
            if changed!=1: raise RuntimeError("subject_revocation_claim_lost")
            await uow.commit()

    async def earliest_live_expiry(self):
        async with self._uow_factory() as uow:
            value=await uow.run_sync(lambda connection:connection.exec_driver_sql(
                "SELECT min(lease_expires_at) FROM subject_revocation_outbox WHERE state='processing'"
            ).scalar_one_or_none())
            await uow.rollback()
        return None if value is None else datetime.fromisoformat(str(value).replace("Z","+00:00"))

    async def pending_count(self) -> int:
        async with self._uow_factory() as uow:
            value=await uow.run_sync(
                lambda connection: connection.exec_driver_sql(
                    "SELECT count(*) FROM subject_revocation_outbox WHERE state!='completed'"
                ).scalar_one()
            )
            await uow.rollback(); return int(value)

    async def state(self, event_id) -> str:
        async with self._uow_factory() as uow:
            row = await uow.run_sync(
                lambda connection: connection.exec_driver_sql(
                    "SELECT state FROM subject_revocation_outbox WHERE id=?", (str(event_id),)
                ).fetchone()
            )
            if row is None:
                raise KeyError(event_id)
            return str(row[0])

    async def last_error(self,event_id) -> str | None:
        async with self._uow_factory() as uow:
            row=await uow.run_sync(
                lambda connection: connection.exec_driver_sql(
                    "SELECT last_error FROM subject_revocation_outbox WHERE id=?",
                    (str(event_id),),
                ).fetchone()
            )
            await uow.rollback()
            if row is None: raise KeyError(event_id)
            return None if row[0] is None else str(row[0])
```

```python
# apps/core/src/tuntun_core/adapters/sqlcipher/subject_revocation_effect_repository.py
from dataclasses import dataclass
from datetime import UTC,datetime,timedelta
from typing import Literal
from uuid import UUID,uuid5

@dataclass(frozen=True,slots=True)
class DownstreamEffectReceipt:
    id:UUID; idempotency_key:UUID; event_id:UUID; family:str
    subject_id:UUID; through_generation:int; disposition:str

@dataclass(frozen=True,slots=True)
class EffectClaim:
    status:Literal["acquired","busy","completed"]
    id:UUID; idempotency_key:UUID
    fencing_token:int|None; leased_until:object|None
    downstream:DownstreamEffectReceipt|None=None

class SubjectRevocationEffectRepository:
    """Durable per-event/family lease and downstream receipt; no subject content."""
    def __init__(self,uow_factory): self._uow_factory=uow_factory

    @staticmethod
    def _utc(value): return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    async def claim(
        self,idempotency_key,*,event_id,family,subject_id,through_generation,
        lease_owner,now,
    ):
        row_id=uuid5(idempotency_key,"effect-row"); leased_until=now+timedelta(seconds=30)
        async with self._uow_factory() as uow:
            await uow.run_sync(lambda connection:connection.exec_driver_sql(
                """INSERT INTO subject_revocation_effects
                   (id,event_id,family,idempotency_key,state,attempt_count,fencing_token,created_at)
                   VALUES (?,?,?,?, 'pending',0,0,?) ON CONFLICT(idempotency_key) DO NOTHING""",
                (str(row_id),str(event_id),family,str(idempotency_key),self._utc(now)),
            ))
            acquired=await uow.run_sync(lambda connection:connection.exec_driver_sql(
                """UPDATE subject_revocation_effects
                   SET state='applying',lease_owner=?,leased_until=?,
                       attempt_count=attempt_count+1,fencing_token=fencing_token+1,last_error=NULL
                   WHERE idempotency_key=? AND
                     (state='pending' OR (state='applying' AND leased_until<=?))
                   RETURNING id,fencing_token""",
                (str(lease_owner),self._utc(leased_until),str(idempotency_key),self._utc(now)),
            ).fetchone())
            row=await uow.run_sync(lambda connection:connection.exec_driver_sql(
                """SELECT effect.id,effect.event_id,effect.family,effect.state,
                          effect.fencing_token,effect.leased_until,
                          effect.downstream_receipt_id,effect.disposition,
                          event.subject_id,event.new_authority_generation
                   FROM subject_revocation_effects AS effect
                   JOIN subject_revocation_outbox AS event ON event.id=effect.event_id
                   WHERE effect.idempotency_key=?""",
                (str(idempotency_key),),
            ).fetchone())
            if (
                row is None or str(row.event_id)!=str(event_id) or row.family!=family
                or str(row.subject_id)!=str(subject_id)
                or int(row.new_authority_generation)-1!=through_generation
            ):
                raise RuntimeError("revocation_effect_idempotency_scope_mismatch")
            await uow.commit()
        if acquired is not None:
            return EffectClaim(
                "acquired",UUID(row.id),idempotency_key,
                int(acquired.fencing_token),leased_until,
            )
        if row.state=="completed":
            receipt=DownstreamEffectReceipt(
                UUID(row.downstream_receipt_id),idempotency_key,UUID(row.event_id),
                row.family,UUID(row.subject_id),int(row.new_authority_generation)-1,
                row.disposition,
            )
            return EffectClaim("completed",UUID(row.id),idempotency_key,None,None,receipt)
        return EffectClaim(
            "busy",UUID(row.id),idempotency_key,None,
            datetime.fromisoformat(str(row.leased_until).replace("Z","+00:00")),
        )

    async def completed(self,idempotency_key):
        async with self._uow_factory() as uow:
            row=await uow.run_sync(lambda connection:connection.exec_driver_sql(
                """SELECT effect.downstream_receipt_id,effect.disposition,effect.event_id,
                          effect.family,event.subject_id,event.new_authority_generation
                   FROM subject_revocation_effects AS effect
                   JOIN subject_revocation_outbox AS event ON event.id=effect.event_id
                   WHERE effect.idempotency_key=? AND effect.state='completed'""",
                (str(idempotency_key),),
            ).fetchone())
            await uow.rollback()
        return None if row is None else DownstreamEffectReceipt(
            UUID(row.downstream_receipt_id),idempotency_key,UUID(row.event_id),
            row.family,UUID(row.subject_id),int(row.new_authority_generation)-1,
            row.disposition,
        )

    async def renew(self,idempotency_key,lease_owner,fencing_token,now) -> bool:
        leased_until=now+timedelta(seconds=30)
        async with self._uow_factory() as uow:
            changed=await uow.run_sync(lambda connection:connection.exec_driver_sql(
                """UPDATE subject_revocation_effects SET leased_until=?
                   WHERE idempotency_key=? AND state='applying' AND lease_owner=?
                   AND fencing_token=? AND leased_until>?""",
                (self._utc(leased_until),str(idempotency_key),str(lease_owner),
                 fencing_token,self._utc(now)),
            ).rowcount)
            await uow.commit(); return changed==1

    async def complete(self,idempotency_key,lease_owner,fencing_token,downstream,now):
        async with self._uow_factory() as uow:
            scope=await uow.run_sync(lambda connection:connection.exec_driver_sql(
                """SELECT effect.event_id,effect.family,event.subject_id,
                          event.new_authority_generation
                   FROM subject_revocation_effects AS effect
                   JOIN subject_revocation_outbox AS event ON event.id=effect.event_id
                   WHERE effect.idempotency_key=?""",
                (str(idempotency_key),),
            ).fetchone())
            expected=(
                str(idempotency_key),str(scope.event_id),scope.family,
                str(scope.subject_id),int(scope.new_authority_generation)-1,
            )
            actual=(
                str(downstream.idempotency_key),str(downstream.event_id),downstream.family,
                str(downstream.subject_id),downstream.through_generation,
            )
            if actual!=expected: raise RuntimeError("revocation_downstream_receipt_scope_mismatch")
            changed=await uow.run_sync(lambda connection:connection.exec_driver_sql(
                """UPDATE subject_revocation_effects SET state='completed',lease_owner=NULL,
                   leased_until=NULL,downstream_receipt_id=?,disposition=?,completed_at=?
                   WHERE idempotency_key=? AND state='applying' AND lease_owner=?
                   AND fencing_token=? AND leased_until>?""",
                (str(downstream.id),downstream.disposition,self._utc(now),
                 str(idempotency_key),str(lease_owner),fencing_token,self._utc(now)),
            ).rowcount)
            if changed!=1: raise RuntimeError("revocation_effect_claim_lost")
            await uow.commit()

    async def abandon(self,idempotency_key,lease_owner,fencing_token,reason_code,now):
        async with self._uow_factory() as uow:
            changed=await uow.run_sync(lambda connection:connection.exec_driver_sql(
                """UPDATE subject_revocation_effects SET state='pending',lease_owner=NULL,
                   leased_until=NULL,last_error=? WHERE idempotency_key=?
                   AND state='applying' AND lease_owner=? AND fencing_token=?
                   AND leased_until>?""",
                (reason_code,str(idempotency_key),str(lease_owner),fencing_token,
                 self._utc(now)),
            ).rowcount)
            if changed!=1: raise RuntimeError("revocation_effect_claim_lost")
            await uow.commit()

    async def recover_stale(self,now) -> int:
        async with self._uow_factory() as uow:
            changed=await uow.run_sync(lambda connection:connection.exec_driver_sql(
                """UPDATE subject_revocation_effects SET state='pending',lease_owner=NULL,
                   leased_until=NULL,last_error='stale_lease_recovered'
                   WHERE state='applying' AND leased_until<=?""",
                (self._utc(now),),
            ).rowcount)
            await uow.commit(); return changed
```

```python
# apps/core/src/tuntun_core/services/identity/subject_revocation_handlers.py
import asyncio
from dataclasses import dataclass
from datetime import timedelta
from uuid import uuid5
from tuntun_core.adapters.sqlcipher.subject_revocation_effect_repository import DownstreamEffectReceipt

@dataclass(frozen=True,slots=True)
class DeferredEffect:
    leased_until:object

class LeaseFenceLost(RuntimeError): pass

class LeaseHeartbeatRunner:
    def __init__(self,clock): self._clock=clock
    def now(self): return self._clock.now()
    async def run(self,operation,*,renew,interval_seconds):
        task=asyncio.create_task(operation())
        tick=None
        try:
            while True:
                tick=asyncio.create_task(self._clock.sleep_until(
                    self._clock.now()+timedelta(seconds=interval_seconds),
                ))
                done,_=await asyncio.wait(
                    {task,tick},return_when=asyncio.FIRST_COMPLETED,
                )
                if task in done:
                    tick.cancel(); await asyncio.gather(tick,return_exceptions=True)
                    return task.result()
                if not await renew(self._clock.now()):
                    task.cancel(); await asyncio.gather(task,return_exceptions=True)
                    raise LeaseFenceLost("revocation_lease_fence_lost")
        except BaseException:
            if tick is not None and not tick.done():
                tick.cancel(); await asyncio.gather(tick,return_exceptions=True)
            if not task.done():
                task.cancel(); await asyncio.gather(task,return_exceptions=True)
            raise

class _OnceHandler:
    family:str
    def __init__(self,effects,heartbeats):
        self._effects,self._heartbeats=effects,heartbeats
    def require_stage_match(self): return None
    async def reconcile_started_once(
        self,*,event_id,subject_id,through_generation,idempotency_key,
        lease_owner,now,
    ):
        claim=await self._effects.claim(
            idempotency_key,event_id=event_id,family=self.family,
            subject_id=subject_id,through_generation=through_generation,
            lease_owner=lease_owner,now=now,
        )
        if claim.status=="completed": return claim.downstream.disposition
        if claim.status=="busy": return DeferredEffect(claim.leased_until)
        try:
            downstream=await self._heartbeats.run(
                lambda:self._apply(event_id,subject_id,through_generation,idempotency_key),
                renew=lambda heartbeat_now:self._effects.renew(
                    idempotency_key,lease_owner,claim.fencing_token,heartbeat_now,
                ),
                interval_seconds=10,
            )
            expected=(event_id,self.family,subject_id,through_generation,idempotency_key)
            actual=(downstream.event_id,downstream.family,downstream.subject_id,
                    downstream.through_generation,downstream.idempotency_key)
            if actual!=expected: raise RuntimeError("revocation_downstream_receipt_scope_mismatch")
        except LeaseFenceLost:
            raise
        except Exception as error:
            await self._effects.abandon(
                idempotency_key,lease_owner,claim.fencing_token,
                f"handler_error:{type(error).__name__}",self._heartbeats.now(),
            )
            raise
        # BaseException models process death and deliberately leaves APPLYING;
        # startup/periodic stale-lease recovery reuses this exact key.
        await self._effects.complete(
            idempotency_key,lease_owner,claim.fencing_token,downstream,
            self._heartbeats.now(),
        )
        return downstream.disposition

class ProviderRouteRevocationHandler(_OnceHandler):
    family="provider_routes"
    def __init__(self,effects,heartbeats,uow_factory):
        super().__init__(effects,heartbeats); self._uow=uow_factory
    async def _apply(self,event_id,subject_id,through_generation,key):
        async with self._uow() as uow:
            summary=await uow.provider_calls.reconcile_revoked_subject_once(
                event_id=event_id,family=self.family,subject_id=subject_id,
                through_generation=through_generation,
                idempotency_key=key,
            )
            await uow.budget_reservations.settle_conservative_once(
                summary.network_started_reservation_ids,idempotency_key=key,
            )
            await uow.commit()
        return summary.downstream_effect_receipt

class SearchAuthorityRevocationHandler(_OnceHandler):
    family="search_capabilities"
    def __init__(self,effects,heartbeats,uow_factory,feature_state):
        super().__init__(effects,heartbeats); self._uow=uow_factory; self.feature_state=feature_state
    async def _apply(self,event_id,subject_id,through_generation,key):
        if self.feature_state=="absent":
            # No optional-search authority exists. The deterministic no-op
            # receipt is durably stored by the outer effect completion; a
            # crash before it simply regenerates this exact ID.
            return DownstreamEffectReceipt(
                uuid5(key,"absent-search-noop"),key,event_id,self.family,
                subject_id,through_generation,"none_open",
            )
        async with self._uow() as uow:
            receipt=await uow.experimental_search_attempts.reconcile_revocation_once(
                event_id=event_id,family=self.family,subject_id=subject_id,
                through_generation=through_generation,
                idempotency_key=key,
            )
            await uow.commit()
        return receipt

class ActionAuthorityRevocationHandler(_OnceHandler):
    family="action_authorities"
    def __init__(self,effects,heartbeats,claims,provider_registry):
        super().__init__(effects,heartbeats); self._claims=claims; self._providers=provider_registry
    async def _apply(self,event_id,subject_id,through_generation,key):
        return await self._claims.reconcile_subject_revocation_once(
            event_id=event_id,family=self.family,subject_id=subject_id,
            through_generation=through_generation,
            idempotency_key=key,provider_registry=self._providers,
        )

class MemoryAuthorityRevocationHandler(_OnceHandler):
    family="memory_authorities"
    def __init__(self,effects,heartbeats,uow_factory):
        super().__init__(effects,heartbeats); self._uow=uow_factory
    async def _apply(self,event_id,subject_id,through_generation,key):
        async with self._uow() as uow:
            receipt=await uow.memory_proposals.reconcile_subject_revocation_once(
                event_id=event_id,family=self.family,subject_id=subject_id,
                through_generation=through_generation,
                idempotency_key=key,
            )
            await uow.commit()
        return receipt

class NotInstalledAuthorityRevocationHandler(_OnceHandler):
    _ALLOWED={"action_authorities":"0003_authentication","memory_authorities":"0004_memory"}
    def __init__(self,effects,heartbeats,capability_stage,*,family,owning_revision):
        if self._ALLOWED.get(family)!=owning_revision:
            raise ValueError("closed not-installed revocation family required")
        super().__init__(effects,heartbeats)
        self.family,self._stage,self.owning_revision=family,capability_stage,owning_revision
    async def _apply(self,event_id,subject_id,through_generation,key):
        self._stage.require_schema_and_facade_absent(self.family,self.owning_revision)
        return DownstreamEffectReceipt(
            uuid5(key,"not-installed-no-authority"),key,event_id,self.family,
            subject_id,through_generation,"not_installed_no_authority",
        )
    def require_stage_match(self):
        self._stage.require_schema_and_facade_absent(self.family,self.owning_revision)
```

```python
# apps/core/src/tuntun_core/services/identity/subject_revocation_processor.py
from dataclasses import dataclass
from uuid import UUID,uuid5
from tuntun_core.services.identity.subject_revocation_handlers import DeferredEffect

POST_COMMIT_FAMILIES=(
    "provider_routes","search_capabilities","action_authorities","memory_authorities",
)
ALLOWED_DISPOSITIONS=frozenset({
    "none_open","cancelled","conservatively_settled","completed_once",
    "not_installed_no_authority",
})

@dataclass(frozen=True,slots=True)
class SubjectRevocationProcessingReceipt:
    id: UUID
    dispositions: tuple[tuple[str,str],...]

@dataclass(frozen=True,slots=True)
class DeferredRevocationProcessing:
    leased_until:object

class SubjectRevocationProcessor:
    def __init__(self,handlers):
        if set(handlers)!=set(POST_COMMIT_FAMILIES):
            raise RuntimeError("complete_post_commit_revocation_handlers_required")
        if len({id(handler._effects) for handler in handlers.values()})!=1:
            raise RuntimeError("one_revocation_effect_repository_required")
        self._handlers=handlers
        self._effects=next(iter(handlers.values()))._effects

    @property
    def available(self) -> bool:
        if set(self._handlers)!=set(POST_COMMIT_FAMILIES): return False
        for handler in self._handlers.values(): handler.require_stage_match()
        return True

    @property
    def handlers(self): return self._handlers

    async def recover_stale_effect_claims(self,now) -> int:
        return await self._effects.recover_stale(now)

    async def reconcile_once(self,event,*,idempotency_key,lease_owner,now):
        event_id=UUID(str(event.id))
        if UUID(str(idempotency_key))!=event_id:
            raise PermissionError("subject_revocation_idempotency_mismatch")
        dispositions=[]
        for family in POST_COMMIT_FAMILIES:
            disposition=await self._handlers[family].reconcile_started_once(
                event_id=event_id,
                subject_id=UUID(str(event.subject_id)),
                through_generation=int(event.new_authority_generation)-1,
                idempotency_key=uuid5(event_id,family),
                lease_owner=lease_owner,now=now,
            )
            if isinstance(disposition,DeferredEffect):
                return DeferredRevocationProcessing(disposition.leased_until)
            if disposition not in ALLOWED_DISPOSITIONS:
                raise RuntimeError("invalid_subject_revocation_disposition")
            dispositions.append((family,disposition))
        return SubjectRevocationProcessingReceipt(
            id=uuid5(event_id,"aggregate"),dispositions=tuple(dispositions),
        )
```

```python
# apps/core/src/tuntun_core/workers/subject_revocation_worker.py
import asyncio
from datetime import timedelta
from uuid import uuid4
from tuntun_core.services.identity.subject_revocation_processor import DeferredRevocationProcessing
from tuntun_core.services.identity.subject_revocation_handlers import LeaseFenceLost

MAX_SAFE_STARTUP_BACKLOG=10_000
PERIODIC_DRAIN_SECONDS=30
STARTUP_RECOVERY_WAIT_SECONDS=31

class SubjectRevocationWorker:
    def __init__(self,repository,processor,heartbeats,clock):
        self._repository,self._processor=repository,processor
        self._heartbeats,self._clock=heartbeats,clock
        self._kick=asyncio.Event(); self._running=asyncio.Event()

    @property
    def available(self): return bool(self._processor.available)

    def offer_nowait(self):
        self._kick.set()

    async def _drain_available(self) -> int:
        processed=0
        await self._repository.recover_expired(self._clock.now())
        await self._processor.recover_stale_effect_claims(self._clock.now())
        while claim := await self._repository.claim_next(self._clock.now(),uuid4()):
            event=claim.event
            try:
                result=await self._heartbeats.run(
                    lambda:self._processor.reconcile_once(
                        event,idempotency_key=event.id,
                        lease_owner=claim.lease_owner,now=self._clock.now(),
                    ),
                    renew=lambda heartbeat_now:self._repository.renew(
                        event.id,claim.lease_owner,claim.fencing_token,heartbeat_now,
                    ),
                    interval_seconds=10,
                )
                if isinstance(result,DeferredRevocationProcessing):
                    await self._repository.defer_until(
                        event.id,claim.lease_owner,claim.fencing_token,
                        result.leased_until,self._clock.now(),
                    )
                    continue
                await self._repository.complete(
                    event.id,result.id,claim.lease_owner,claim.fencing_token,
                    self._clock.now(),
                )
            except LeaseFenceLost:
                raise
            except Exception as error:
                await asyncio.shield(self._repository.retry_pending(
                    event.id,claim.lease_owner,claim.fencing_token,
                    f"processor_error:{type(error).__name__}",self._clock.now(),
                ))
                raise
            processed+=1
        return processed

    async def recover_and_drain_before_ready(self) -> None:
        if not self.available:
            raise RuntimeError("subject revocation worker unavailable")
        if await self._repository.pending_count()>MAX_SAFE_STARTUP_BACKLOG:
            raise RuntimeError("subject revocation backlog unsafe")
        deadline=self._clock.now()+timedelta(seconds=STARTUP_RECOVERY_WAIT_SECONDS)
        while await self._repository.pending_count()!=0:
            await self._drain_available()
            if await self._repository.pending_count()==0: break
            expiry=await self._repository.earliest_live_expiry()
            if expiry is None or expiry>deadline:
                raise RuntimeError("subject revocation backlog unsafe")
            # A previous process may have died after claim commit. Its live
            # lease is deferred, not treated as a fatal startup error or stolen.
            await self._clock.sleep_until(expiry)

    async def run_periodically(self,stop,on_fatal) -> None:
        if not self.available:
            raise RuntimeError("subject revocation worker unavailable")
        self._running.set()
        try:
            while not stop.is_set():
                try:
                    await asyncio.wait_for(
                        self._kick.wait(),timeout=PERIODIC_DRAIN_SECONDS,
                    )
                except TimeoutError:
                    pass
                self._kick.clear()
                await self._drain_available()
        except BaseException as error:
            on_fatal(error)
            raise

    async def wait_running(self) -> None: await self._running.wait()

    async def wait_until_idle(self) -> None:
        while self._kick.is_set() or await self._repository.pending_count():
            await asyncio.sleep(0)
```

```python
# apps/core/src/tuntun_core/bootstrap/container.py (revocation composition)
from tuntun_core.adapters.sqlcipher.subject_revocation_effect_repository import (
    SubjectRevocationEffectRepository,
)
from tuntun_core.services.identity.subject_revocation_handlers import (
    LeaseHeartbeatRunner,NotInstalledAuthorityRevocationHandler,
    ProviderRouteRevocationHandler,SearchAuthorityRevocationHandler,
)

revocation_outbox=SubjectRevocationOutboxRepository(async_uow_factory)
revocation_effects=SubjectRevocationEffectRepository(async_uow_factory)
revocation_heartbeats=LeaseHeartbeatRunner(clock)
transactional_subject_revocation_handlers.update({
    "action_authorities":NotInstalledSubjectAuthorityHandler(
        capability_stage,family="action_authorities",owning_revision="0003_authentication",
    ),
    "memory_authorities":NotInstalledSubjectAuthorityHandler(
        capability_stage,family="memory_authorities",owning_revision="0004_memory",
    ),
})
post_commit_revocation_handlers={
    "provider_routes":ProviderRouteRevocationHandler(
        revocation_effects,revocation_heartbeats,async_uow_factory,
    ),
    "search_capabilities":SearchAuthorityRevocationHandler(
        revocation_effects,revocation_heartbeats,async_uow_factory,
        feature_state=feature_registry.require_closed_state("experimental_search"),
    ),
    "action_authorities":NotInstalledAuthorityRevocationHandler(
        revocation_effects,revocation_heartbeats,capability_stage,
        family="action_authorities",owning_revision="0003_authentication",
    ),
    "memory_authorities":NotInstalledAuthorityRevocationHandler(
        revocation_effects,revocation_heartbeats,capability_stage,
        family="memory_authorities",owning_revision="0004_memory",
    ),
}
revocation_processor=SubjectRevocationProcessor(post_commit_revocation_handlers)
revocation_worker=SubjectRevocationWorker(
    revocation_outbox,revocation_processor,revocation_heartbeats,clock,
)
async_uow_factory.register_commit_signal("subject_revocation",revocation_worker)
```

```python
# apps/core/src/tuntun_core/bootstrap/lifecycle.py (identity startup projection)
async def start_identity_runtime(
    handler_registry,revocation_worker,readiness,task_group,stop,
) -> None:
    if set(handler_registry) != set(REQUIRED_SUBJECT_AUTHORITY_FAMILIES):
        raise RuntimeError("complete_subject_revocation_handlers_required")
    readiness.clear()
    if revocation_worker is None or not revocation_worker.available:
        raise RuntimeError("subject revocation worker unavailable")
    await revocation_worker.recover_and_drain_before_ready()
    task_group.create_task(
        revocation_worker.run_periodically(
            stop,lambda _error:readiness.clear(),
        )
    )
    await revocation_worker.wait_running()
    readiness.set()
```

Every independently consumable provider-route, search, action, authentication-grant, and pending-memory authority row stores the `subject_authority_generation` read from the locked active subject when it is minted. Sessions, consent, enrollment, and biometric-template handlers instead close their complete subject scope transactionally, and every later use still locks and requires the active subject before reading those authorities. Every claim/consume path requires `active=1`, `revoked_at IS NULL`, and, where stored, an exact generation match before it changes state. The single SQLCipher writer is the linearization point: if revocation commits first, consume fails before network or local effect; if a consume claim commits first, revocation records the already-started claim in the durable outbox.

Task-1 composition constructs exactly four closed post-commit handlers—concrete provider/search plus sealed action/memory not-installed handlers—and matching transactional placeholders; it never imports repositories introduced by `0003_authentication` or `0004_memory`. Each placeholder verifies that its owning schema and typed facade are absent before it can return deterministic `not_installed_no_authority`; startup fails if a placeholder remains after that capability is installed. Task 8 atomically installs and registers the real action handlers only after `0003`; Task 10 does the same for memory only after `0004`, and the final composition test requires all real handlers. Optional search follows the same rule in its owning supplement.

`SubjectRevocationEffectRepository` owns one durable `subject_revocation_effects` row per `(event_id,family)` with the exact UUIDv5 `(event_id,family)` idempotency key, `pending|applying|completed` state, lease owner/deadline, monotonically incremented fencing token, attempt count, downstream receipt ID/disposition, bounded error, and completion time. The outbox has the same renewable 30-second lease and fencing shape. Both heartbeats renew every 10 seconds while work is live, so a call longer than 30 seconds is not stolen; every renew, abandon, defer, and completion CAS-binds row, owner, and fencing token. Each authoritative downstream receipt/reopen operation binds event ID, family, subject ID, through-generation, exact idempotency key, receipt ID, and disposition, and substitution is rejected before outer completion. A crash after the durable downstream effect stops both heartbeats; only after expiry may another worker increment the fence and replay the same key, which reopens the same receipt. A late old-fence completion cannot complete the new attempt.

The revocation transaction marks the fixed UoW post-commit signal; only a successful commit offers the worker's nonblocking live kick. Kick loss is safe because the supervised worker also drains every 30 seconds and at startup. Startup and periodic recovery reset only expired claims. An immediate restart that finds a prior process's live outbox/effect lease records a nonfatal deferred state, waits only until the persisted expiry, retries, and reaches readiness within the 31-second startup bound; it never resets an unexpired row. A genuinely live worker continues to heartbeat, and another periodic worker cannot steal it. Ordinary processor/handler errors use the exact current fence to requeue/abandon and clear readiness; `BaseException` models hard death and deliberately leaves both claims to expire. Startup validates the exact eight transactional families, exact stage-matching post-commit class identities, fencing columns/repositories, downstream receipt facades, and closed search feature state. Missing/duplicate/fixture or schema-stage-mismatched handlers, unsafe backlog, renewal loss, startup processing error, or later worker death is a readiness failure.

```python
# apps/core/src/tuntun_core/services/identity/consent.py
from datetime import timedelta
from uuid import uuid4
from tuntun_core.domain.profile import ConsentPurpose, ConsentReceipt, GrantConsent, ProfileClass
from tuntun_core.services.actions.parameter_binding import consent_parameters

class ConsentDenied(RuntimeError):
    pass

ADULT_PROFILE_CLASSES = frozenset({ProfileClass.OWNER, ProfileClass.ADULT})
CHILD_PROFILE_CLASSES = frozenset({ProfileClass.K2, ProfileClass.N1})
GUEST_SESSION_CONSENT_PURPOSES = frozenset({ConsentPurpose.CLOUD_STT, ConsentPurpose.CLOUD_REASONING, ConsentPurpose.CLOUD_TTS})

class ConsentService:
    def __init__(self, uow_factory, mutation_scope, audit_ledger, receipt_signer, parameter_verifier, action_binding_verifier, revocation_cascade, clock):
        self._uow_factory, self._scope, self._audit, self._signer = uow_factory, mutation_scope, audit_ledger, receipt_signer
        self._parameters, self._bindings = parameter_verifier, action_binding_verifier
        self._revocations, self._clock = revocation_cascade, clock

    def _require_action_binding(self, command, action_name):
        try:
            self._parameters.require(
                command.action_binding,
                action_name=action_name, resource_type="consent", resource_id=command.subject_id, actor_id=command.actor_id,
                parameters=consent_parameters(command),
            )
        except PermissionError as exc:
            raise ConsentDenied("consent_action_binding_mismatch") from exc

    async def grant(self, command: GrantConsent, auth) -> ConsentReceipt:
        self._require_action_binding(command, "consent.grant")
        if auth.assurance_source != "passkey":
            raise ConsentDenied("subject_bound_passkey_required")
        try:
            self._bindings.require_exact(auth.binding, command.action_binding)
        except PermissionError as exc:
            raise ConsentDenied("subject_bound_passkey_required") from exc
        if self._clock.now() - auth.consumed_at > timedelta(seconds=120):
            raise ConsentDenied("fresh_passkey_required")
        if auth.subject_id != command.actor_id:
            raise ConsentDenied("authenticated_actor_mismatch")
        uow = self._scope.require_active_uow()
        subject = await uow.profiles.get(command.subject_id)
        if not subject.active or subject.revoked_at is not None:
            raise ConsentDenied("current_active_subject_required")
        if subject.household_id != command.action_binding.household_id:
            raise ConsentDenied("consent_household_mismatch")
        if command.purpose is ConsentPurpose.WEB_SEARCH and (subject.profile_class not in ADULT_PROFILE_CLASSES or command.actor_id != subject.id):
            raise ConsentDenied("web_search_adult_self_consent_required")
        if command.purpose is ConsentPurpose.CHILD_DURABLE_MEMORY and subject.profile_class not in CHILD_PROFILE_CLASSES:
            raise ConsentDenied("child_durable_memory_guardian_consent_required")
        if subject.profile_class in ADULT_PROFILE_CLASSES:
            if command.actor_id != subject.id or command.guardian_generation is not None:
                raise ConsentDenied("adult_self_consent_required")
        elif subject.profile_class in CHILD_PROFILE_CLASSES:
            if subject.guardian_id != command.actor_id or subject.guardian_generation != command.guardian_generation:
                raise ConsentDenied("current_primary_guardian_required")
        latest = await uow.consent_receipts.latest_for_update(command.subject_id, command.purpose)
        latest_id = None if latest is None else latest.id
        if latest_id != command.expected_latest_receipt_id:
            raise ConsentDenied("consent_state_changed")
        now = self._clock.now()
        guardian_id = command.actor_id if subject.profile_class in CHILD_PROFILE_CLASSES else None
        guardian_generation = command.guardian_generation if guardian_id is not None else None
        expires_at = now + timedelta(days=365) if command.purpose is ConsentPurpose.CHILD_DURABLE_MEMORY else None
        fields = (subject.household_id, subject.id, command.purpose, command.actor_id, guardian_id, guardian_generation, True, command.policy_version, command.disclosure_version, now, expires_at)
        key_id, receipt_hmac = self._signer.sign_fields("subject_consent_receipt", fields)
        receipt = uow.consent_receipts.granted_from(command, household_id=subject.household_id, guardian_id=guardian_id, guardian_generation=guardian_generation, now=now, expires_at=expires_at, commitment_key_id=key_id, receipt_hmac=receipt_hmac)
        await uow.consent_receipts.append(receipt, auth)
        await self._audit.append(uow, uow.consent_receipts.audit_draft(receipt, auth))
        return receipt

    async def grant_in_uow(self, uow, command, auth):
        if self._scope.require_active_uow() is not uow:
            raise RuntimeError("consent_uow_scope_mismatch")
        return await self.grant(command, auth)

    async def revoke(self, command, auth):
        self._require_action_binding(command, "consent.revoke")
        if auth.assurance_source != "passkey":
            raise ConsentDenied("subject_bound_passkey_required")
        try:
            self._bindings.require_exact(auth.binding, command.action_binding)
        except PermissionError as exc:
            raise ConsentDenied("subject_bound_passkey_required") from exc
        if self._clock.now() - auth.consumed_at > timedelta(seconds=120):
            raise ConsentDenied("fresh_passkey_required")
        if auth.subject_id != command.actor_id:
            raise ConsentDenied("authenticated_actor_mismatch")
        uow = self._scope.require_active_uow()
        subject = await uow.profiles.get(command.subject_id)
        if not subject.active or subject.revoked_at is not None:
            raise ConsentDenied("current_active_subject_required")
        if subject.household_id != command.action_binding.household_id:
            raise ConsentDenied("consent_household_mismatch")
        if command.purpose is ConsentPurpose.WEB_SEARCH and (subject.profile_class not in ADULT_PROFILE_CLASSES or command.actor_id != subject.id):
            raise ConsentDenied("web_search_adult_self_consent_required")
        if command.purpose is ConsentPurpose.CHILD_DURABLE_MEMORY and subject.profile_class not in CHILD_PROFILE_CLASSES:
            raise ConsentDenied("child_durable_memory_guardian_consent_required")
        if subject.profile_class in ADULT_PROFILE_CLASSES:
            if command.actor_id != subject.id or command.guardian_generation is not None:
                raise ConsentDenied("adult_self_consent_required")
        elif subject.profile_class in CHILD_PROFILE_CLASSES:
            if subject.guardian_id != command.actor_id or subject.guardian_generation != command.guardian_generation:
                raise ConsentDenied("current_primary_guardian_required")
        current = await uow.consent_receipts.require_current_for_update(command.subject_id, command.purpose, self._clock.now())
        if (
            current.id != command.expected_latest_receipt_id
            or current.policy_version != command.policy_version
            or current.disclosure_version != command.disclosure_version
        ):
            raise ConsentDenied("consent_state_changed")
        if current.actor_id != command.actor_id and current.guardian_id != command.actor_id:
            raise ConsentDenied("consent_revoker_mismatch")
        now = self._clock.now()
        guardian_id = command.actor_id if subject.profile_class in CHILD_PROFILE_CLASSES else None
        guardian_generation = command.guardian_generation if guardian_id is not None else None
        fields = (current.household_id, current.subject_id, current.purpose, command.actor_id, guardian_id, guardian_generation, False, current.policy_version, current.disclosure_version, now, now)
        key_id, receipt_hmac = self._signer.sign_fields("subject_consent_receipt", fields)
        receipt = uow.consent_receipts.revoked_from(current, command.actor_id, guardian_id=guardian_id, guardian_generation=guardian_generation, now=now, expires_at=now, commitment_key_id=key_id, receipt_hmac=receipt_hmac)
        await uow.consent_receipts.append(receipt, auth)
        await self._revocations.apply_in_uow(uow, receipt, auth, now)
        await self._audit.append(uow, uow.consent_receipts.audit_draft(receipt, auth))
        return receipt

    async def revoke_in_uow(self, uow, command, auth):
        if self._scope.require_active_uow() is not uow:
            raise RuntimeError("consent_uow_scope_mismatch")
        return await self.revoke(command, auth)

    async def require_current(self, subject_id, purpose, now):
        async with self._uow_factory() as uow:
            return await self.require_current_in_uow(uow, subject_id, purpose, now)

    async def require_current_in_uow(self, uow, subject_id, purpose, now):
        subject = await uow.profiles.get(subject_id)
        if not subject.active or subject.revoked_at is not None:
            raise ConsentDenied("current_active_subject_required")
        if purpose is ConsentPurpose.WEB_SEARCH and subject.profile_class not in ADULT_PROFILE_CLASSES:
            raise ConsentDenied("web_search_adult_self_consent_required")
        if purpose is ConsentPurpose.CHILD_DURABLE_MEMORY and subject.profile_class not in CHILD_PROFILE_CLASSES:
            raise ConsentDenied("child_durable_memory_guardian_consent_required")
        receipt = await uow.consent_receipts.latest(subject_id, purpose)
        if receipt is None or not receipt.granted or receipt.created_at > now or (receipt.expires_at is not None and receipt.expires_at <= now):
            raise ConsentDenied("current_consent_required")
        fields = (subject.household_id, subject.id, purpose, receipt.actor_id, receipt.guardian_id, receipt.guardian_generation, receipt.granted, receipt.policy_version, receipt.disclosure_version, receipt.created_at, receipt.expires_at)
        if receipt.household_id != subject.household_id or not self._signer.verify_fields("subject_consent_receipt", receipt.commitment_key_id, fields, receipt.receipt_hmac):
            raise ConsentDenied("consent_receipt_hmac_invalid")
        if purpose is ConsentPurpose.WEB_SEARCH and (
            receipt.actor_id != subject.id
            or receipt.guardian_id is not None
            or receipt.guardian_generation is not None
        ):
            raise ConsentDenied("web_search_adult_self_receipt_required")
        if purpose is ConsentPurpose.CHILD_DURABLE_MEMORY and (
            receipt.actor_id != subject.guardian_id
            or receipt.guardian_id != subject.guardian_id
            or receipt.guardian_generation != subject.guardian_generation
        ):
            raise ConsentDenied("current_primary_guardian_consent_required")
        if subject.profile_class in CHILD_PROFILE_CLASSES and (receipt.guardian_id != subject.guardian_id or receipt.guardian_generation != subject.guardian_generation):
            raise ConsentDenied("current_primary_guardian_consent_required")
        return receipt

    async def require_current_hmac_valid(self, household_id, subject_id, purpose, now):
        async with self._uow_factory() as uow:
            receipt = await self.require_current_in_uow(uow, subject_id, purpose, now)
            if receipt.household_id != household_id:
                raise ConsentDenied("consent_household_mismatch")
            return receipt

    async def is_current(self, subject_id, purpose, now):
        try:
            await self.require_current(subject_id, purpose, now)
            return True
        except ConsentDenied:
            return False

    async def verify_receipt(self, receipt):
        fields = (receipt.household_id, receipt.subject_id, receipt.purpose, receipt.actor_id, receipt.guardian_id, receipt.guardian_generation, receipt.granted, receipt.policy_version, receipt.disclosure_version, receipt.created_at, receipt.expires_at)
        if not self._signer.verify_fields("subject_consent_receipt", receipt.commitment_key_id, fields, receipt.receipt_hmac):
            raise ConsentDenied("consent_receipt_hmac_invalid")
        return receipt

class ConsentRevocationHandlerPort(Protocol):
    async def apply_in_uow(self, uow, receipt, auth, now) -> None: raise NotImplementedError

class CloudRouteConsentRevocationHandler:
    def __init__(self, route_authorizations): self._routes = route_authorizations
    async def apply_in_uow(self, uow, receipt, auth, now):
        await self._routes.invalidate_subject_purpose_in_uow(
            uow, receipt.subject_id, receipt.purpose.value, now
        )

class ConsentRevocationCascade:
    def __init__(self, handlers, audit_mapper, audit_ledger):
        self._handlers, self._audit_mapper, self._audit = handlers, audit_mapper, audit_ledger

    async def apply_in_uow(self, uow, receipt, auth, now):
        handler = self._handlers.get(receipt.purpose)
        if handler is not None:
            await handler.apply_in_uow(uow, receipt, auth, now)
        event = uow.consent_receipts.identity_consent_revoked_event(receipt, now)
        await self._audit.append(uow, self._audit_mapper.revoked(event, auth))

class GuestSessionConsentService:
    def __init__(self, uow_factory, audit_ledger, receipt_signer):
        self._uow_factory, self._audit, self._signer = uow_factory, audit_ledger, receipt_signer

    async def issue_challenge(self, household_id, session_id, purpose, disclosure_version, presentation_receipt_id, now):
        if purpose not in GUEST_SESSION_CONSENT_PURPOSES:
            raise ConsentDenied("guest_disclosure_purpose_denied")
        async with self._uow_factory() as uow:
            session = await uow.sessions.lock_active(household_id, session_id, now)
            await uow.event_receipts.require_exact_guest_disclosure(presentation_receipt_id, household_id=household_id, session_id=session_id, purpose=purpose, disclosure_version=disclosure_version, now=now)
            challenge_id, expires_at = uuid4(), min(session.expires_at, now + timedelta(minutes=2))
            fields = (challenge_id, household_id, session_id, purpose, disclosure_version, presentation_receipt_id, now, expires_at)
            key_id, challenge_hmac = self._signer.sign_fields("guest_disclosure_challenge", fields)
            challenge = await uow.guest_disclosure_challenges.create(challenge_id, household_id, session_id, purpose, disclosure_version, presentation_receipt_id, now, expires_at, key_id, challenge_hmac)
            await self._audit.append(uow, challenge.started_audit())
            await uow.commit()
            return challenge

    async def accept_challenge(self, challenge_id, response, now):
        async with self._uow_factory() as uow:
            challenge = await uow.guest_disclosure_challenges.lock_open(challenge_id, now)
            challenge_fields = (challenge.id, challenge.household_id, challenge.session_id, challenge.purpose, challenge.disclosure_version, challenge.presentation_receipt_id, challenge.issued_at, challenge.expires_at)
            if not self._signer.verify_fields("guest_disclosure_challenge", challenge.commitment_key_id, challenge_fields, challenge.challenge_hmac):
                raise ConsentDenied("active_guest_disclosure_challenge_required")
            if response not in {"yes", "haan", "हाँ"}:
                await uow.guest_disclosure_challenges.consume_denied(challenge.id, now)
                await self._audit.append(uow, challenge.denied_audit(now))
                await uow.commit()
                raise ConsentDenied("guest_disclosure_declined")
            session = await uow.sessions.lock_active(challenge.household_id, challenge.session_id, now)
            if challenge.expires_at > session.expires_at or challenge.purpose not in GUEST_SESSION_CONSENT_PURPOSES:
                raise ConsentDenied("active_guest_disclosure_challenge_required")
            expires_at = session.expires_at
            fields = (challenge.household_id, challenge.session_id, challenge.purpose, challenge.disclosure_version, True, now, expires_at, None)
            key_id, receipt_hmac = self._signer.sign_fields("guest_session_consent_receipt", fields)
            await uow.guest_disclosure_challenges.consume_accepted(challenge.id, now)
            receipt = await uow.guest_session_consents.append(challenge.household_id, challenge.session_id, challenge.purpose, challenge.disclosure_version, True, now, expires_at, None, key_id, receipt_hmac)
            await self._audit.append(uow, uow.guest_session_consents.granted_audit(receipt, challenge.id))
            await uow.commit()
            return receipt

    async def revoke(self, household_id, session_id, purpose, now):
        if purpose not in GUEST_SESSION_CONSENT_PURPOSES:
            raise ConsentDenied("guest_disclosure_purpose_denied")
        async with self._uow_factory() as uow:
            current = await uow.guest_session_consents.lock_current(household_id, session_id, purpose, now)
            fields = (household_id, session_id, purpose, current.disclosure_version, False, now, current.expires_at, now)
            key_id, receipt_hmac = self._signer.sign_fields("guest_session_consent_receipt", fields)
            revoked = await uow.guest_session_consents.append(household_id, session_id, purpose, current.disclosure_version, False, now, current.expires_at, now, key_id, receipt_hmac)
            await self._audit.append(uow, uow.guest_session_consents.revoked_audit(revoked))
            await uow.commit()
            return revoked

    async def require_current(self, household_id, session_id, purpose, now):
        if purpose not in GUEST_SESSION_CONSENT_PURPOSES:
            raise ConsentDenied("guest_disclosure_purpose_denied")
        async with self._uow_factory() as uow:
            session = await uow.sessions.require_active(household_id, session_id, now)
            receipt = await uow.guest_session_consents.latest(household_id, session_id, purpose)
        if receipt is None or not receipt.granted or receipt.revoked_at is not None or receipt.expires_at <= now or receipt.expires_at > session.expires_at:
            raise ConsentDenied("current_guest_session_consent_required")
        fields = (household_id, session_id, purpose, receipt.disclosure_version, receipt.granted, receipt.issued_at, receipt.expires_at, receipt.revoked_at)
        if not self._signer.verify_fields("guest_session_consent_receipt", receipt.commitment_key_id, fields, receipt.receipt_hmac):
            raise ConsentDenied("guest_consent_receipt_hmac_invalid")
        return receipt

    async def require_current_hmac_valid(self, household_id, session_id, purpose, now):
        return await self.require_current(household_id, session_id, purpose, now)

class IdentityMutationCoordinator:
    def __init__(self, mutation_scope, authentication, profiles, consents):
        self._scope, self._auth, self._profiles, self._consents = mutation_scope, authentication, profiles, consents

    async def create_profile(self, command, grant_id):
        return await self._run(command.action_binding, grant_id, self._profiles.create, command)

    async def revoke_profile(self, command, grant_id):
        return await self._run(command.action_binding, grant_id, self._profiles.revoke, command)

    async def update_persona_traits(self, command, grant_id):
        return await self._run(command.action_binding, grant_id, self._profiles.update_persona_traits, command)

    async def grant_consent(self, command, grant_id):
        return await self._run(command.action_binding, grant_id, self._consents.grant, command)

    async def revoke_consent(self, command, grant_id):
        return await self._run(command.action_binding, grant_id, self._consents.revoke, command)

    async def _run(self, binding, grant_id, operation, command):
        async with self._scope.open() as uow:
            auth = await self._auth.consume_in_uow(uow, grant_id, binding)
            result = await operation(command, auth)
            await uow.commit()
            return result
```

```python
# apps/core/migrations/versions/0002_profiles_consent_enrollment.py
from alembic import op
import sqlalchemy as sa

revision = "0002_profiles_consent_enrollment"
down_revision = "0001_foundation"

def upgrade() -> None:
    utc = "GLOB '????-??-??T??:??:??.??????Z'"
    op.create_table("subjects", sa.Column("id", sa.String(36), primary_key=True), sa.Column("household_id", sa.String(36), sa.ForeignKey("households.id"), nullable=False), sa.Column("guardian_id", sa.String(36), sa.ForeignKey("subjects.id")), sa.Column("guardian_generation", sa.Integer, nullable=False), sa.Column("profile_class", sa.String(16), nullable=False), sa.Column("encrypted_display_label", sa.LargeBinary, nullable=False), sa.Column("encrypted_persona_traits", sa.LargeBinary), sa.Column("current_consent_receipt_ids", sa.LargeBinary, nullable=False), sa.Column("active", sa.Integer, nullable=False), sa.Column("authority_generation", sa.Integer, nullable=False), sa.Column("version", sa.Integer, nullable=False), sa.Column("next_reenrollment_reminder_at", sa.String(27)), sa.Column("created_at", sa.String(27), nullable=False), sa.Column("updated_at", sa.String(27), nullable=False), sa.Column("revoked_at", sa.String(27)), sa.CheckConstraint("profile_class IN ('owner','adult','k2','n1')"), sa.CheckConstraint("active IN (0,1)"), sa.CheckConstraint("authority_generation >= 1"), sa.CheckConstraint("version >= 1"), sa.CheckConstraint(f"created_at {utc} AND updated_at {utc}"), sa.CheckConstraint("(profile_class IN ('k2','n1') AND guardian_id IS NOT NULL AND guardian_generation >= 1) OR (profile_class IN ('owner','adult') AND guardian_id IS NULL AND guardian_generation = 0)"), sa.CheckConstraint("(active=1 AND revoked_at IS NULL) OR active=0"))
    op.create_table("subject_revocation_outbox", sa.Column("id", sa.String(36), primary_key=True), sa.Column("event_key", sa.String(160), nullable=False, unique=True), sa.Column("subject_id", sa.String(36), sa.ForeignKey("subjects.id"), nullable=False), sa.Column("new_authority_generation", sa.Integer, nullable=False), sa.Column("state", sa.String(16), nullable=False), sa.Column("occurred_at", sa.String(27), nullable=False), sa.Column("claimed_at", sa.String(27)), sa.Column("lease_owner", sa.String(36)), sa.Column("lease_expires_at", sa.String(27)), sa.Column("fencing_token", sa.Integer, nullable=False), sa.Column("completed_at", sa.String(27)), sa.Column("attempt_count", sa.Integer, nullable=False), sa.Column("last_error", sa.String(512)), sa.Column("reconciliation_receipt_id", sa.String(36), unique=True), sa.CheckConstraint("new_authority_generation >= 2"), sa.CheckConstraint("state IN ('pending','processing','completed')"), sa.CheckConstraint("attempt_count >= 0 AND fencing_token >= 0"), sa.CheckConstraint(f"occurred_at {utc} AND (claimed_at IS NULL OR claimed_at {utc}) AND (lease_expires_at IS NULL OR lease_expires_at {utc}) AND (completed_at IS NULL OR completed_at {utc})"), sa.CheckConstraint("(state='pending' AND claimed_at IS NULL AND lease_owner IS NULL AND lease_expires_at IS NULL AND completed_at IS NULL) OR (state='processing' AND claimed_at IS NOT NULL AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL AND completed_at IS NULL) OR (state='completed' AND claimed_at IS NOT NULL AND lease_owner IS NULL AND lease_expires_at IS NULL AND completed_at IS NOT NULL AND reconciliation_receipt_id IS NOT NULL)"))
    op.create_table("subject_revocation_effects", sa.Column("id",sa.String(36),primary_key=True),sa.Column("event_id",sa.String(36),sa.ForeignKey("subject_revocation_outbox.id",ondelete="CASCADE"),nullable=False),sa.Column("family",sa.String(32),nullable=False),sa.Column("idempotency_key",sa.String(36),nullable=False,unique=True),sa.Column("state",sa.String(16),nullable=False),sa.Column("lease_owner",sa.String(36)),sa.Column("leased_until",sa.String(27)),sa.Column("fencing_token",sa.Integer,nullable=False),sa.Column("attempt_count",sa.Integer,nullable=False),sa.Column("downstream_receipt_id",sa.String(36)),sa.Column("disposition",sa.String(32)),sa.Column("last_error",sa.String(128)),sa.Column("created_at",sa.String(27),nullable=False),sa.Column("completed_at",sa.String(27)),sa.UniqueConstraint("event_id","family",name="uq_subject_revocation_effect_event_family"),sa.CheckConstraint("family IN ('provider_routes','search_capabilities','action_authorities','memory_authorities')"),sa.CheckConstraint("state IN ('pending','applying','completed')"),sa.CheckConstraint("attempt_count >= 0 AND fencing_token >= 0"),sa.CheckConstraint(f"created_at {utc} AND (leased_until IS NULL OR leased_until {utc}) AND (completed_at IS NULL OR completed_at {utc})"),sa.CheckConstraint("(state='pending' AND lease_owner IS NULL AND leased_until IS NULL AND completed_at IS NULL) OR (state='applying' AND lease_owner IS NOT NULL AND leased_until IS NOT NULL AND completed_at IS NULL) OR (state='completed' AND lease_owner IS NULL AND leased_until IS NULL AND completed_at IS NOT NULL AND downstream_receipt_id IS NOT NULL AND disposition IS NOT NULL)"))
    op.create_table("current_owner_authority", sa.Column("household_id", sa.String(36), sa.ForeignKey("households.id"), primary_key=True), sa.Column("subject_id", sa.String(36), sa.ForeignKey("subjects.id"), nullable=False, unique=True), sa.Column("owner_generation", sa.Integer, nullable=False), sa.Column("changed_at", sa.String(27), nullable=False), sa.CheckConstraint("owner_generation >= 1"), sa.CheckConstraint(f"changed_at {utc}"))
    op.create_table("consent_receipts", sa.Column("id", sa.String(36), primary_key=True), sa.Column("household_id", sa.String(36), sa.ForeignKey("households.id"), nullable=False), sa.Column("subject_id", sa.String(36), sa.ForeignKey("subjects.id"), nullable=False), sa.Column("actor_id", sa.String(36), sa.ForeignKey("subjects.id"), nullable=False), sa.Column("guardian_id", sa.String(36), sa.ForeignKey("subjects.id")), sa.Column("guardian_generation", sa.Integer), sa.Column("purpose", sa.String(32), nullable=False), sa.Column("granted", sa.Integer, nullable=False), sa.Column("policy_version", sa.String(64), nullable=False), sa.Column("disclosure_version", sa.String(64), nullable=False), sa.Column("commitment_key_id", sa.String(128), nullable=False), sa.Column("receipt_hmac", sa.LargeBinary, nullable=False), sa.Column("created_at", sa.String(27), nullable=False), sa.Column("expires_at", sa.String(27)), sa.CheckConstraint("purpose IN ('face','voice','personalization','cloud_stt','cloud_reasoning','cloud_tts','web_search','child_durable_memory_v1')"), sa.CheckConstraint("purpose!='web_search' OR (actor_id=subject_id AND guardian_id IS NULL AND guardian_generation IS NULL)"), sa.CheckConstraint("purpose!='child_durable_memory_v1' OR (guardian_id IS NOT NULL AND guardian_generation >= 1 AND actor_id=guardian_id AND expires_at IS NOT NULL)"), sa.CheckConstraint("(guardian_id IS NULL AND guardian_generation IS NULL) OR (guardian_id IS NOT NULL AND guardian_generation >= 1)"), sa.CheckConstraint("granted IN (0,1)"), sa.CheckConstraint(f"created_at {utc} AND (expires_at IS NULL OR expires_at {utc})"), sa.UniqueConstraint("household_id", "subject_id", "purpose", "created_at"))
    op.create_table("guest_disclosure_challenges", sa.Column("id", sa.String(36), primary_key=True), sa.Column("household_id", sa.String(36), sa.ForeignKey("households.id"), nullable=False), sa.Column("session_id", sa.String(36), sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False), sa.Column("purpose", sa.String(32), nullable=False), sa.Column("disclosure_version", sa.String(64), nullable=False), sa.Column("presentation_receipt_id", sa.String(36), sa.ForeignKey("event_receipts.id"), nullable=False), sa.Column("state", sa.String(16), nullable=False), sa.Column("issued_at", sa.String(27), nullable=False), sa.Column("expires_at", sa.String(27), nullable=False), sa.Column("consumed_at", sa.String(27)), sa.Column("commitment_key_id", sa.String(128), nullable=False), sa.Column("challenge_hmac", sa.LargeBinary, nullable=False), sa.CheckConstraint("purpose IN ('cloud_stt','cloud_reasoning','cloud_tts')"), sa.CheckConstraint("state IN ('open','accepted','denied')"), sa.CheckConstraint(f"issued_at {utc} AND expires_at {utc} AND (consumed_at IS NULL OR consumed_at {utc})"), sa.CheckConstraint("expires_at > issued_at"), sa.CheckConstraint("(state='open' AND consumed_at IS NULL) OR (state IN ('accepted','denied') AND consumed_at IS NOT NULL)"), sa.UniqueConstraint("presentation_receipt_id"), sa.UniqueConstraint("household_id", "session_id", "purpose", "disclosure_version", "issued_at"))
    op.create_table("guest_session_consent_receipts", sa.Column("id", sa.String(36), primary_key=True), sa.Column("household_id", sa.String(36), sa.ForeignKey("households.id"), nullable=False), sa.Column("session_id", sa.String(36), sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False), sa.Column("purpose", sa.String(32), nullable=False), sa.Column("disclosure_version", sa.String(64), nullable=False), sa.Column("granted", sa.Integer, nullable=False), sa.Column("issued_at", sa.String(27), nullable=False), sa.Column("expires_at", sa.String(27), nullable=False), sa.Column("revoked_at", sa.String(27)), sa.Column("commitment_key_id", sa.String(128), nullable=False), sa.Column("receipt_hmac", sa.LargeBinary, nullable=False), sa.CheckConstraint("purpose IN ('cloud_stt','cloud_reasoning','cloud_tts')"), sa.CheckConstraint("granted IN (0,1)"), sa.CheckConstraint(f"issued_at {utc} AND expires_at {utc} AND (revoked_at IS NULL OR revoked_at {utc})"), sa.CheckConstraint("expires_at > issued_at"), sa.CheckConstraint("revoked_at IS NULL OR revoked_at >= issued_at"), sa.UniqueConstraint("household_id", "session_id", "purpose", "issued_at"))
    op.create_table("enrollment_sessions", sa.Column("id", sa.String(36), primary_key=True), sa.Column("subject_id", sa.String(36), sa.ForeignKey("subjects.id"), nullable=False), sa.Column("modality", sa.String(16), nullable=False), sa.Column("state", sa.String(16), nullable=False), sa.Column("auth_receipt_id", sa.String(36), nullable=False), sa.Column("consent_receipt_id", sa.String(36), sa.ForeignKey("consent_receipts.id"), nullable=False), sa.Column("reenrollment_days", sa.Integer, nullable=False), sa.Column("created_at", sa.String(27), nullable=False), sa.Column("expires_at", sa.String(27), nullable=False), sa.Column("closed_at", sa.String(27)), sa.CheckConstraint("modality IN ('face','voice')"), sa.CheckConstraint("state IN ('requested','capturing','calibrating','approved','cancelled','expired')"), sa.CheckConstraint("reenrollment_days BETWEEN 30 AND 365"), sa.CheckConstraint(f"created_at {utc} AND expires_at {utc}"))
    op.create_table("biometric_templates", sa.Column("id", sa.String(36), primary_key=True), sa.Column("subject_id", sa.String(36), sa.ForeignKey("subjects.id"), nullable=False), sa.Column("modality", sa.String(16), nullable=False), sa.Column("model_version", sa.String(128), nullable=False), sa.Column("ciphertext", sa.LargeBinary, nullable=False), sa.Column("nonce", sa.LargeBinary, nullable=False), sa.Column("wrapped_dek", sa.LargeBinary, nullable=False), sa.Column("root_key_id", sa.String(128), nullable=False), sa.Column("consent_receipt_id", sa.String(36), sa.ForeignKey("consent_receipts.id"), nullable=False), sa.Column("created_at", sa.String(27), nullable=False), sa.Column("expires_at", sa.String(27)), sa.Column("revoked_at", sa.String(27)), sa.CheckConstraint("modality IN ('face','voice')"), sa.CheckConstraint(f"created_at {utc}"), sa.CheckConstraint("revoked_at IS NULL OR expires_at IS NOT NULL"))
    op.create_index("ux_subjects_one_owner", "subjects", ["household_id"], unique=True, sqlite_where=sa.text("profile_class='owner' AND active=1"))
    op.create_index("ix_subject_revocation_outbox_drain", "subject_revocation_outbox", ["state", "occurred_at", "id"])
    op.create_index("ix_subject_revocation_effect_lease", "subject_revocation_effects", ["state", "leased_until", "id"])
    op.create_index("ix_consent_subject_purpose_time", "consent_receipts", ["subject_id", "purpose", "created_at"])
    op.create_index("ix_guest_disclosure_session_purpose_state", "guest_disclosure_challenges", ["household_id", "session_id", "purpose", "state", "expires_at"])
    op.create_index("ix_guest_consent_session_purpose_time", "guest_session_consent_receipts", ["household_id", "session_id", "purpose", "issued_at"])
    op.create_index("ux_biometric_active_model", "biometric_templates", ["subject_id", "modality", "model_version"], unique=True, sqlite_where=sa.text("revoked_at IS NULL"))

def downgrade() -> None:
    op.drop_index("ux_biometric_active_model", table_name="biometric_templates")
    op.drop_table("biometric_templates")
    op.drop_table("enrollment_sessions")
    op.drop_index("ix_guest_consent_session_purpose_time", table_name="guest_session_consent_receipts")
    op.drop_table("guest_session_consent_receipts")
    op.drop_index("ix_guest_disclosure_session_purpose_state", table_name="guest_disclosure_challenges")
    op.drop_table("guest_disclosure_challenges")
    op.drop_index("ix_consent_subject_purpose_time", table_name="consent_receipts")
    op.drop_table("consent_receipts")
    op.drop_table("current_owner_authority")
    op.drop_index("ix_subject_revocation_effect_lease", table_name="subject_revocation_effects")
    op.drop_table("subject_revocation_effects")
    op.drop_index("ix_subject_revocation_outbox_drain", table_name="subject_revocation_outbox")
    op.drop_table("subject_revocation_outbox")
    op.drop_index("ux_subjects_one_owner", table_name="subjects")
    op.drop_table("subjects")
```

`subjects.encrypted_persona_traits` stores a versioned, self-contained record-AEAD envelope (nonce, wrapped random DEK, root-key ID, schema version, and ciphertext), never JSON or a free-form label. Its associated-data scope binds household, subject, profile version, and purpose `profile.persona_traits`; replace and clear both increment the existing optimistic `subjects.version`. Audit records contain only actor/subject pseudonyms, operation `replace|clear`, old/new version, result, and a purpose-separated payload commitment—never trait values. Current personalization consent is required to replace, while the same exact self/guardian authority may clear after consent revocation. Migration/raw-byte tests use synthetic sentinel trait values and prove no plaintext in DB/WAL/SHM.

- [ ] **Step 4: Run the narrow and migration tests**

Run: `uv run pytest tests/unit/identity/test_profiles.py tests/unit/identity/test_consent.py tests/unit/identity/test_current_owner_repository.py tests/unit/identity/test_subject_revocation_worker.py tests/integration/identity/test_subject_revocation_handlers.py tests/integration/identity/test_profile_consent_migration.py tests/integration/identity/test_profile_revocation.py -q`
Expected: PASS with exit code 0; schema inspection finds all seven owned tables, the one-row current-owner authority pointer, non-null monotonic subject authority generation, encrypted optimistic-version persona storage, and exactly eight durable subject purposes. Every consent operation rejects an inactive/revoked subject before receipt access. Revocation advances the generation and atomically invalidates all eight authority families; revoke-vs-consume, restart, and idempotent post-commit reconciliation tests prove no stale authority can create a new network call or effect. Adult-only `web_search`, child durable memory, and Guest purpose boundaries remain unchanged; downgrade/re-upgrade recreates the invariants; and no plaintext sentinel appears in the database scan.

- [ ] **Step 5: Run static checks and commit exact paths**

Run: `uv run ruff format --check apps/core/src/tuntun_core/domain/profile.py apps/core/src/tuntun_core/services/identity apps/core/src/tuntun_core/adapters/sqlcipher/subject_revocation_outbox_repository.py apps/core/src/tuntun_core/adapters/sqlcipher/subject_revocation_effect_repository.py apps/core/src/tuntun_core/adapters/sqlcipher/async_unit_of_work.py apps/core/src/tuntun_core/workers/subject_revocation_worker.py apps/core/src/tuntun_core/services/actions/parameter_binding.py apps/core/src/tuntun_core/services/transactions/identity_uow.py apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/bootstrap/lifecycle.py tests/unit/identity tests/integration/identity && uv run ruff check apps/core/src/tuntun_core/domain/profile.py apps/core/src/tuntun_core/services/identity apps/core/src/tuntun_core/adapters/sqlcipher/subject_revocation_outbox_repository.py apps/core/src/tuntun_core/adapters/sqlcipher/subject_revocation_effect_repository.py apps/core/src/tuntun_core/adapters/sqlcipher/async_unit_of_work.py apps/core/src/tuntun_core/workers/subject_revocation_worker.py apps/core/src/tuntun_core/services/actions/parameter_binding.py apps/core/src/tuntun_core/services/transactions/identity_uow.py apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/bootstrap/lifecycle.py tests/unit/identity tests/integration/identity && uv run mypy apps/core/src/tuntun_core/domain/profile.py apps/core/src/tuntun_core/services/identity apps/core/src/tuntun_core/adapters/sqlcipher/subject_revocation_outbox_repository.py apps/core/src/tuntun_core/adapters/sqlcipher/subject_revocation_effect_repository.py apps/core/src/tuntun_core/adapters/sqlcipher/async_unit_of_work.py apps/core/src/tuntun_core/workers/subject_revocation_worker.py apps/core/src/tuntun_core/services/actions/parameter_binding.py apps/core/src/tuntun_core/services/transactions/identity_uow.py apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/bootstrap/lifecycle.py`
Expected: PASS with exit code 0.

```bash
git add apps/core/src/tuntun_core/domain/profile.py apps/core/src/tuntun_core/services/identity/profiles.py apps/core/src/tuntun_core/services/identity/consent.py apps/core/src/tuntun_core/services/identity/subject_revocation.py apps/core/src/tuntun_core/services/identity/subject_revocation_processor.py apps/core/src/tuntun_core/services/identity/subject_revocation_handlers.py apps/core/src/tuntun_core/adapters/sqlcipher/subject_revocation_outbox_repository.py apps/core/src/tuntun_core/adapters/sqlcipher/subject_revocation_effect_repository.py apps/core/src/tuntun_core/adapters/sqlcipher/async_unit_of_work.py apps/core/src/tuntun_core/workers/subject_revocation_worker.py apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/bootstrap/lifecycle.py apps/core/src/tuntun_core/services/actions/parameter_binding.py apps/core/src/tuntun_core/services/transactions/identity_uow.py apps/core/migrations/versions/0002_profiles_consent_enrollment.py tests/unit/identity/test_profiles.py tests/unit/identity/test_consent.py tests/unit/identity/test_current_owner_repository.py tests/unit/identity/test_subject_revocation_worker.py tests/integration/identity/test_subject_revocation_handlers.py tests/integration/identity/test_profile_consent_migration.py tests/integration/identity/test_profile_revocation.py
git diff --cached --name-only
git diff --cached
git commit -m "feat(identity): add profiles and self-consent rules"
```

### Task 2: Implement enrollment, revocation, and child re-enrollment

**Master coverage:** Task 17
**Depends on:** Task 1
**Estimated effort:** 1.5 person-days

**Files:**
- Create: `apps/core/src/tuntun_core/services/identity/enrollment.py`
- Create: `apps/core/src/tuntun_core/services/identity/revocation_handlers.py`
- Create: `apps/core/src/tuntun_core/services/providers/consent_guard.py`
- Modify: `apps/core/src/tuntun_core/services/providers/route_authorization.py`
- Modify: `apps/core/src/tuntun_core/workflows/conversation.py`
- Modify: `apps/core/src/tuntun_core/workflows/nodes.py`
- Create: `tests/unit/identity/test_enrollment.py`
- Create: `tests/security/test_enrollment_authorization.py`
- Create: `tests/integration/identity/test_consent_revocation.py`

**Interfaces:**
- Consumes: `ConsentService.require_current`, `GuestSessionConsentService.require_current`, `AuthenticationPort.consume`, shared exact `enrollment_request_parameters|enrollment_cancel_parameters`, typed enrollment/biometric-template/session facades, and the audit outbox's managed-erasure request event.
- Produces: `EnrollmentService.request/request_in_uow/cancel_in_uow/complete_in_uow/reminders_due/expire_due_child_templates`; `BiometricConsentRevocationHandler`; non-transport `ConsentEvidenceService.require(household_id, subject_id, session_id, purposes, now) -> tuple[ConsentEvidence, ...]`; a `ConsentHmacVerifier` injected into the already-canonical `RouteAuthorizationService`; enrollment states `requested|capturing|calibrating|approved|cancelled|expired`; separate 180-day reminder and 365-day biometric hard expiry; immediate purpose-specific `IdentityConsentRevoked(subject_id, purpose, occurred_at)`. Request commands bind and CAS the current active profile version; cancel commands bind only the exact subject and enrollment resource. Task 2 extends `IdentityUnitOfWork` with exact `enrollments` and `biometric_templates` repository protocols before this handler is registered. The identity layer never exposes or changes a provider `send` path.

- [ ] **Step 1: Write failing enrollment and revocation tests**

```python
# tests/unit/identity/test_enrollment.py
from datetime import timedelta
import pytest
from tuntun_core.domain.profile import Modality, RequestEnrollment

@pytest.mark.asyncio
async def test_child_reenrollment_defaults_to_180_days(enrollment_mutations, enrollment_service, mutation_scope, child, guardian_consent, owner_passkey_grant, clock):
    session = await enrollment_mutations.request(RequestEnrollment(subject_id=child.id, modality=Modality.FACE, expected_profile_version=child.version, expected_consent_receipt_id=guardian_consent.id, action_binding=owner_passkey_grant.binding, reenrollment_days=180), owner_passkey_grant.id)
    assert session.consent_receipt_id == guardian_consent.id
    async with mutation_scope.open() as uow:
        completed = await enrollment_service.complete_in_uow(uow, session.id, (session.synthetic_template_id,), guardian_consent, clock.now())
        await uow.commit()
    assert completed.next_reenrollment_reminder_at == clock.now() + timedelta(days=180)
    assert completed.biometric_hard_expires_at == clock.now() + timedelta(days=365)

@pytest.mark.asyncio
async def test_reminder_does_not_expire_but_hard_deadline_does(enrollment_service, child, clock):
    clock.advance(days=181)
    assert await enrollment_service.reminders_due(child.household_id, clock.now()) == (child.id,)
    assert await enrollment_service.expire_due_child_templates(child.household_id, clock.now()) == ()
    clock.advance(days=185)
    expired = await enrollment_service.expire_due_child_templates(child.household_id, clock.now())
    assert expired == (child.id,)
```

```python
# tests/security/test_enrollment_authorization.py
import pytest
from tuntun_core.services.identity.enrollment import EnrollmentDenied

@pytest.mark.asyncio
async def test_biometric_or_pin_cannot_authorize_enrollment(enrollment_mutations, request, identified_grant):
    with pytest.raises(EnrollmentDenied, match="fresh_owner_passkey_required"):
        await enrollment_mutations.request(request, identified_grant.id)


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["subject_id", "modality", "expected_profile_version", "expected_consent_receipt_id", "reenrollment_days"])
async def test_enrollment_parameter_substitution_cannot_reuse_owner_grant(enrollment_service, bound_enrollment_request_factory, owner_auth_factory, enrollment_repository_spy, field):
    request = bound_enrollment_request_factory()
    auth = owner_auth_factory(request.action_binding)
    substituted = bound_enrollment_request_factory(changed_field=field, keep_binding=request.action_binding)
    with pytest.raises(EnrollmentDenied, match="enrollment_parameter_binding_mismatch"):
        await enrollment_service.request(substituted, auth)
    assert enrollment_repository_spy.read_count == 0 and enrollment_repository_spy.write_count == 0

@pytest.mark.asyncio
async def test_stale_enrollment_profile_version_denies_before_enrollment_write(
    enrollment_service, bound_enrollment_request_factory, owner_auth_factory, enrollment_repository_spy
):
    request = bound_enrollment_request_factory()
    auth = owner_auth_factory(request.action_binding)
    enrollment_repository_spy.bump_profile_version(request.subject_id)
    with pytest.raises(EnrollmentDenied, match="enrollment_profile_state_changed"):
        await enrollment_service.request(request, auth)
    assert enrollment_repository_spy.write_count == 0

@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["subject_id", "enrollment_id"])
async def test_enrollment_cancel_substitution_denies_before_enrollment_read(
    enrollment_service, bound_cancel_enrollment_factory, owner_auth_factory, enrollment_repository_spy, uow, field
):
    command = bound_cancel_enrollment_factory()
    auth = owner_auth_factory(command.action_binding)
    forged = bound_cancel_enrollment_factory(changed_field=field, keep_binding=command.action_binding)
    with pytest.raises(EnrollmentDenied, match="enrollment_parameter_binding_mismatch"):
        await enrollment_service.cancel_in_uow(uow, forged, auth)
    assert enrollment_repository_spy.read_count == 0 and enrollment_repository_spy.write_count == 0
```

```python
# tests/integration/identity/test_consent_revocation.py
import pytest

@pytest.mark.asyncio
async def test_revocation_blocks_the_next_route_authorization(route_authorizer, identity_mutations, adult, cloud_request, passkey_grant, network_capture):
    await identity_mutations.revoke_consent(adult.revoke_cloud_reasoning, passkey_grant.id)
    with pytest.raises(PermissionError, match="consent_required:cloud_reasoning"):
        await route_authorizer.authorize(cloud_request.for_subject(adult.id).to_route_authorization_request())
    assert network_capture == []

@pytest.mark.asyncio
async def test_guest_needs_session_specific_cloud_acceptance(route_authorizer, guest_cloud_request):
    with pytest.raises(PermissionError, match="guest_session_consent_required:cloud_reasoning"):
        await route_authorizer.authorize(guest_cloud_request.to_route_authorization_request())
```

- [ ] **Step 2: Run red tests**

Run: `uv run pytest tests/unit/identity/test_enrollment.py tests/security/test_enrollment_authorization.py tests/integration/identity/test_consent_revocation.py -q`
Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core.services.identity.enrollment'`.

- [ ] **Step 3: Implement the bounded lifecycle**

```python
# apps/core/src/tuntun_core/services/identity/enrollment.py
from datetime import timedelta
from tuntun_core.services.actions.parameter_binding import enrollment_cancel_parameters, enrollment_request_parameters

class EnrollmentDenied(RuntimeError):
    pass

class EnrollmentService:
    def __init__(self, uow_factory, mutation_scope, consents, parameter_verifier, action_binding_verifier, audit_ledger, clock):
        self._uow_factory, self._scope, self._consents, self._audit = uow_factory, mutation_scope, consents, audit_ledger
        self._parameters, self._bindings, self._clock = parameter_verifier, action_binding_verifier, clock

    async def request(self, command, auth_context):
        if auth_context.assurance.value != "passkey_verified" or auth_context.assurance_source != "passkey" or self._clock.now() - auth_context.consumed_at > timedelta(seconds=120):
            raise EnrollmentDenied("fresh_owner_passkey_required")
        try:
            self._bindings.require_exact(auth_context.binding, command.action_binding)
        except PermissionError as exc:
            raise EnrollmentDenied("enrollment_binding_mismatch") from exc
        if not 30 <= command.reenrollment_days <= 365:
            raise EnrollmentDenied("reenrollment_days_out_of_range")
        try:
            self._parameters.require(
                command.action_binding,
                action_name="identity.enroll", resource_type="identity", resource_id=command.subject_id, actor_id=auth_context.subject_id,
                parameters=enrollment_request_parameters(command),
            )
        except PermissionError as exc:
            raise EnrollmentDenied("enrollment_parameter_binding_mismatch") from exc
        uow = self._scope.require_active_uow()
        profile = await uow.profiles.get_scoped(command.action_binding.household_id, command.subject_id)
        if not profile.active or profile.revoked_at is not None or profile.version != command.expected_profile_version:
            raise EnrollmentDenied("enrollment_profile_state_changed")
        consent = await self._consents.require_current_in_uow(uow, command.subject_id, command.modality.consent_purpose, self._clock.now())
        if consent.household_id != command.action_binding.household_id:
            raise EnrollmentDenied("enrollment_household_mismatch")
        if consent.id != command.expected_consent_receipt_id:
            raise EnrollmentDenied("enrollment_consent_state_changed")
        session = await uow.enrollments.create(command, auth_context, consent_receipt_id=consent.id)
        await self._audit.append(uow, uow.enrollments.requested_audit(session, auth_context))
        return session

    async def request_in_uow(self, uow, command, auth_context):
        if self._scope.require_active_uow() is not uow:
            raise RuntimeError("enrollment_uow_scope_mismatch")
        return await self.request(command, auth_context)

    async def cancel_in_uow(self, uow, command, auth_context):
        if self._scope.require_active_uow() is not uow:
            raise RuntimeError("enrollment_uow_scope_mismatch")
        if auth_context.assurance.value != "passkey_verified" or auth_context.assurance_source != "passkey" or self._clock.now() - auth_context.consumed_at > timedelta(seconds=120):
            raise EnrollmentDenied("fresh_owner_passkey_required")
        try:
            self._bindings.require_exact(auth_context.binding, command.action_binding)
        except PermissionError as exc:
            raise EnrollmentDenied("enrollment_binding_mismatch") from exc
        try:
            self._parameters.require(
                command.action_binding,
                action_name="identity.enrollment.cancel", resource_type="identity",
                resource_id=command.enrollment_id, actor_id=auth_context.subject_id,
                parameters=enrollment_cancel_parameters(command),
            )
        except PermissionError as exc:
            raise EnrollmentDenied("enrollment_parameter_binding_mismatch") from exc
        session = await uow.enrollments.require_for_update(command.enrollment_id)
        if session.subject_id != command.subject_id or session.household_id != command.action_binding.household_id:
            raise EnrollmentDenied("enrollment_scope_mismatch")
        cancelled = await uow.enrollments.cancel_pending(command.enrollment_id, self._clock.now())
        await self._audit.append(uow, uow.enrollments.cancelled_audit(cancelled, auth_context))
        return cancelled

    async def complete_in_uow(self, uow, enrollment_id, template_ids, consent_receipt, now):
        session = await uow.enrollments.require_state(enrollment_id, "calibrating")
        if consent_receipt.id != session.consent_receipt_id or consent_receipt.subject_id != session.subject_id or consent_receipt.purpose.value != session.modality:
            raise EnrollmentDenied("enrollment_consent_scope_mismatch")
        reminder_at = now + timedelta(days=session.reenrollment_days) if session.subject_is_child else None
        hard_expires_at = now + timedelta(days=365) if session.subject_is_child else None
        approved = await uow.enrollments.approve(enrollment_id, template_ids, reminder_at, hard_expires_at)
        await self._audit.append(uow, uow.enrollments.approved_audit(approved))
        return approved

    async def reminders_due(self, household_id, now):
        async with self._uow_factory() as uow:
            due = await uow.profiles.list_children_due_for_reminder(household_id, now)
            return tuple(profile.id for profile in due)

    async def expire_due_child_templates(self, household_id, now):
        async with self._uow_factory() as uow:
            due = await uow.enrollments.list_child_templates_past_hard_expiry(household_id, now)
            for template in due:
                await uow.profiles.disable_biometric_identity(template.subject_id)
                await uow.enrollments.expire_template(template.id, now)
            if due:
                await self._audit.append(uow, uow.enrollments.expiry_batch_audit(due, now))
            await uow.commit()
            return tuple(dict.fromkeys(template.subject_id for template in due))

class EnrollmentMutationCoordinator:
    def __init__(self, mutation_scope, authentication, enrollments):
        self._scope, self._auth, self._enrollments = mutation_scope, authentication, enrollments

    async def request(self, command, grant_id):
        async with self._scope.open() as uow:
            auth = await self._auth.consume_in_uow(uow, grant_id, command.action_binding)
            session = await self._enrollments.request(command, auth)
            await uow.commit()
            return session

```

```python
# apps/core/src/tuntun_core/services/identity/revocation_handlers.py
class BiometricConsentRevocationHandler:
    def __init__(self, audit_ledger): self._audit = audit_ledger

    async def apply_in_uow(self, uow, receipt, auth, now):
        await uow.enrollments.cancel_subject_modality(receipt.subject_id, receipt.purpose.value, now)
        revoked = await uow.biometric_templates.revoke_subject_modality(
            receipt.subject_id, receipt.purpose.value, now
        )
        await uow.sessions.invalidate_identity_subject(
            receipt.subject_id, "biometric_consent_revoked", now
        )
        for template in revoked:
            await self._audit.append(
                uow,
                template.managed_erasure_requested_audit(
                    stores=("sqlcipher_wal", "managed_backup"), requested_at=now
                ),
            )
```

```python
# apps/core/src/tuntun_core/services/providers/consent_guard.py
from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class ConsentEvidence:
    receipt_id: UUID
    household_id: UUID
    subject_id: UUID | None
    session_id: UUID | None
    purpose: str
    expires_at: datetime | None

class ConsentEvidenceService:
    def __init__(self, consents, guest_sessions):
        self._consents, self._guest_sessions = consents, guest_sessions

    async def require(self, household_id, subject_id, session_id, purposes, now):
        evidence = []
        for purpose in purposes:
            if subject_id is None:
                receipt = await self._guest_sessions.require_current_hmac_valid(household_id, session_id, purpose, now)
                evidence.append(ConsentEvidence(receipt.id, household_id, None, session_id, purpose, receipt.expires_at))
            else:
                receipt = await self._consents.require_current_hmac_valid(household_id, subject_id, purpose, now)
                evidence.append(ConsentEvidence(receipt.id, household_id, subject_id, None, purpose, receipt.expires_at))
        return tuple(evidence)

class ConsentHmacVerifier:
    def __init__(self, receipt_signer, consent_service, clock):
        self._signer, self._consents, self._clock = receipt_signer, consent_service, clock
    async def require_exact_in_uow(self, uow, rows, *, household_id, subject_id, session_id, purpose, receipt_ids):
        if len(rows) != len(receipt_ids) or {row.id for row in rows} != set(receipt_ids): raise PermissionError(f"consent_required:{purpose}")
        if subject_id is None:
            current = await uow.guest_session_consents.latest(household_id, session_id, purpose)
        else:
            try:
                current = await self._consents.require_current_in_uow(
                    uow, subject_id, ConsentPurpose(purpose), self._clock.now()
                )
            except ConsentDenied as exc:
                raise PermissionError(f"consent_required:{purpose}") from exc
        if current is None or current.id not in receipt_ids or len(receipt_ids) != 1:
            raise PermissionError(f"consent_required:{purpose}")
        for row in rows:
            if row.household_id != household_id or row.purpose != purpose or not row.granted: raise PermissionError(f"consent_required:{purpose}")
            if subject_id is None:
                session = await uow.sessions.require_active(household_id, session_id, self._clock.now())
                if row.session_id != session_id or row.expires_at <= self._clock.now() or row.expires_at > session.expires_at or row.revoked_at is not None: raise PermissionError(f"guest_session_consent_required:{purpose}")
                fields = (household_id, session_id, purpose, row.disclosure_version, row.granted, row.issued_at, row.expires_at, row.revoked_at)
                receipt_purpose = "guest_session_consent_receipt"
            else:
                # The canonical consent service has already verified the complete
                # 11-field HMAC, expiry, adult-self/search invariant, and current
                # child guardian ID+generation in this same UoW.
                if row != current or row.subject_id != subject_id:
                    raise PermissionError(f"consent_required:{purpose}")
                continue
            if not self._signer.verify_fields(receipt_purpose, row.commitment_key_id, fields, row.receipt_hmac): raise PermissionError(f"consent_required:{purpose}")
```

```python
# apps/core/src/tuntun_core/services/providers/route_authorization.py
async def attach_current_consent_receipts(draft, consent_evidence, now):
    evidence = await consent_evidence.require(draft.household_id, draft.subject_id, draft.session_id, draft.required_consent_purposes, now)
    return draft.with_consent_receipt_ids(tuple(item.receipt_id for item in evidence))
```

This helper performs no transport, budgeting, authorization issuance, or `send`. It supplies receipt IDs to the frozen `RouteAuthorizationRequest`; the canonical `RouteAuthorizationService.authorize` independently reloads them and calls `ConsentHmacVerifier.require_exact_in_uow` inside its serialized UoW. That check requires the supplied ID to equal the latest event for the exact household/subject-or-active-Guest-session/purpose, so an older grant cannot survive a later revoke. The canonical `ProviderGateway.send(route, consumption, invoke)` remains unchanged and accepts only an already-issued route.

```python
# apps/core/src/tuntun_core/workflows/nodes.py
async def authorize_provider_egress(state, services):
    draft = await attach_current_consent_receipts(state.route_draft, services.consent_evidence, services.clock.now())
    route = await services.route_authorizer.authorize(draft.to_route_authorization_request())
    return state.with_route_authorization(route)

# apps/core/src/tuntun_core/workflows/conversation.py
PROVIDER_NODE_ORDER = ("resolve_current_identity_and_consent", "authorize_recall", "retrieve_context", "sanitize_provider_request", "reserve_budget", "authorize_provider_egress", "send_provider_request")
```

- [ ] **Step 4: Run green and affected tests**

Run: `uv run pytest tests/unit/identity/test_enrollment.py tests/security/test_enrollment_authorization.py tests/integration/identity/test_consent_revocation.py tests/unit/identity/test_consent.py -q`
Expected: PASS with no source-media field in the serialized enrollment row.

- [ ] **Step 5: Check and commit**

Run: `uv run ruff format --check apps/core/src/tuntun_core/services/identity/enrollment.py apps/core/src/tuntun_core/services/identity/revocation_handlers.py apps/core/src/tuntun_core/services/providers/consent_guard.py apps/core/src/tuntun_core/services/providers/route_authorization.py apps/core/src/tuntun_core/workflows/conversation.py apps/core/src/tuntun_core/workflows/nodes.py tests/unit/identity/test_enrollment.py tests/security/test_enrollment_authorization.py tests/integration/identity/test_consent_revocation.py && uv run ruff check apps/core/src/tuntun_core/services/identity/enrollment.py apps/core/src/tuntun_core/services/identity/revocation_handlers.py apps/core/src/tuntun_core/services/providers/consent_guard.py apps/core/src/tuntun_core/services/providers/route_authorization.py apps/core/src/tuntun_core/workflows/conversation.py apps/core/src/tuntun_core/workflows/nodes.py tests/unit/identity/test_enrollment.py tests/security/test_enrollment_authorization.py tests/integration/identity/test_consent_revocation.py && uv run mypy apps/core/src/tuntun_core/services/identity/enrollment.py apps/core/src/tuntun_core/services/identity/revocation_handlers.py apps/core/src/tuntun_core/services/providers/consent_guard.py apps/core/src/tuntun_core/services/providers/route_authorization.py apps/core/src/tuntun_core/workflows/conversation.py apps/core/src/tuntun_core/workflows/nodes.py`
Expected: PASS with exit code 0.

```bash
git add apps/core/src/tuntun_core/services/identity/enrollment.py apps/core/src/tuntun_core/services/identity/revocation_handlers.py apps/core/src/tuntun_core/services/providers/consent_guard.py apps/core/src/tuntun_core/services/providers/route_authorization.py apps/core/src/tuntun_core/workflows/conversation.py apps/core/src/tuntun_core/workflows/nodes.py tests/unit/identity/test_enrollment.py tests/security/test_enrollment_authorization.py tests/integration/identity/test_consent_revocation.py
git diff --cached --name-only
git diff --cached
git commit -m "feat(identity): govern enrollment and re-enrollment"
```

### Task 3: Govern face models, liveness, and enrollment evidence

**Master coverage:** Task 18
**Depends on:** Tasks 1–2 and master Tasks 04, 12–14
**Estimated effort:** 4 person-days

**Files:**
- Create: `apps/core/src/tuntun_core/services/identity/face_enrollment.py`
- Create: `apps/core/src/tuntun_core/services/identity/face_liveness.py`
- Create: `apps/core/src/tuntun_core/adapters/identity/face_yunet_sface.py`
- Create: `apps/core/src/tuntun_core/adapters/identity/worker.py`
- Modify: `apps/core/pyproject.toml` (headless OpenCV and ONNX Runtime dependencies)
- Modify: `uv.lock` (resolved artifacts and hashes)
- Modify: `models/manifest.yaml` (`face-yunet-sface` disabled-until-accepted entry)
- Create: `docs/privacy/biometric-model-governance.md`
- Create: `tests/unit/identity/test_face_consensus.py`
- Create: `tests/unit/identity/test_face_liveness.py`
- Create: `tests/security/test_face_retention.py`
- Create: `tests/security/test_face_presentation_attacks.py`
- Create: `tests/acceptance/test_face_calibration.py`

**Interfaces:**
- Consumes: `ActivatedModel(bundle_id="face-yunet-sface")`, an owner-authorized `EnrollmentSession` in `calibrating`, 5–10 bounded `EphemeralFrame` handles, current HMAC-valid face consent rechecked in the template-write UoW, `RecordAeadCodec.encrypt`, bounded worker executor.
- Produces: `FaceLivenessService.start(binding) -> FaceChallenge` and `verify(challenge_id, binding, observations, now) -> LivenessEvidence`; `FaceMatcherPort.observe(...) -> IdentityEvidence` using the exact foundation fields and encrypted normalized templates only. A challenge contains two distinct randomized steps from blink/left/right, is session/turn/subject-bound, single-use, and expires within 10 seconds.

`uow.identity_challenges` in the code below is the repository adapter over foundation `idempotency_receipts`: `operation` is `identity.face_liveness` or `identity.voice_liveness`, `scope` commits the complete frozen action binding, the UUID is the challenge key, `state` is `open|succeeded|failed`, `result_hmac_*` authenticates the deterministically derived step/digit sequence, and `expires_at` is at most ten seconds. Thus Task 3 adds no migration, challenge state survives a process restart, and `lock_open` plus `consume_*` is one SQLCipher transaction.

Production activation remains `blocked_owner_acceptance` through this task. Task 7's real passkey binding plus a passing calibration/presentation-attack report are both required before B1 can change the manifest activation state.

- [ ] **Step 1: Write red consensus, governance, liveness, and retention tests**

```python
# tests/unit/identity/test_face_consensus.py
import pytest
from tuntun_core.services.identity.face_enrollment import resolve_face_consensus

def test_three_of_five_consistent_frames_personalize(subject_a, now):
    observations = [subject_a.face(920000, True), subject_a.face(910000, True), subject_a.face(900000, True), subject_a.face(400000, False), subject_a.face(300000, False)]
    evidence = resolve_face_consensus(observations, now)
    assert evidence.subject_id == subject_a.id
    assert evidence.modality == "face"

def test_unaccepted_liveness_resolves_to_guest(subject_a, now):
    evidence = resolve_face_consensus([subject_a.face(950000, False)] * 5, now)
    assert evidence.liveness_accepted is False
    assert evidence.subject_id is None
    assert evidence.confidence_micros == 0
```

```python
# tests/unit/identity/test_face_liveness.py
from datetime import timedelta
import pytest
from tuntun_core.services.identity.face_liveness import FaceLivenessService

class SequenceStepGenerator:
    def __init__(self): self._values=iter((("blink","left"),("blink","right"),("left","right")))
    def two_distinct(self, allowed): return next(self._values)

@pytest.fixture
def face_liveness(uow_factory, landmark_model, audit_ledger, clock):
    return FaceLivenessService(uow_factory, landmark_model, audit_ledger, clock, SequenceStepGenerator())


@pytest.mark.asyncio
async def test_face_challenge_is_bound_ordered_and_single_use(face_liveness, binding, landmark_trace, now):
    challenge = await face_liveness.start(binding, now=now)
    evidence = await face_liveness.verify(challenge.id, binding, landmark_trace("blink", "left"), now + timedelta(seconds=4))
    assert evidence.accepted is True
    with pytest.raises(PermissionError, match="face_challenge_consumed"):
        await face_liveness.verify(challenge.id, binding, landmark_trace("blink", "left"), now + timedelta(seconds=5))


@pytest.mark.asyncio
async def test_stale_or_reordered_face_trace_fails(face_liveness, binding, landmark_trace, now):
    challenge = await face_liveness.start(binding, now=now)
    with pytest.raises(PermissionError, match="face_challenge_sequence"):
        await face_liveness.verify(challenge.id, binding, landmark_trace("right", "blink"), now + timedelta(seconds=2))
    expired = await face_liveness.start(binding, now=now)
    with pytest.raises(PermissionError, match="face_challenge_expired"):
        await face_liveness.verify(expired.id, binding, landmark_trace("left", "right"), now + timedelta(seconds=11))
```

```python
# tests/security/test_face_retention.py
import pytest

@pytest.mark.asyncio
async def test_frame_sentinel_is_absent_after_match(face_adapter, private_data_scanner, synthetic_frames):
    await face_adapter.observe(synthetic_frames.views, synthetic_frames.activated_model)
    assert private_data_scanner.find(synthetic_frames.sentinel) == ()
    assert all(frame.cleared for frame in synthetic_frames.handles)

@pytest.mark.asyncio
async def test_face_enrollment_rejects_cross_subject_consent(face_enrollment, adult_a_enrollment, adult_b_consent, consent_repository, synthetic_frames, activated_model, now):
    await consent_repository.force_latest_for_test(adult_a_enrollment.subject_id, "face", adult_b_consent)
    with pytest.raises(PermissionError, match="enrollment_consent_scope_mismatch"):
        await face_enrollment.enroll(adult_a_enrollment.id, synthetic_frames.handles, activated_model, now)
```

```python
# tests/acceptance/test_face_calibration.py
def test_face_calibration_gate(face_calibration_report):
    assert face_calibration_report.comparison_count >= 500
    assert face_calibration_report.false_personalizations == 0
    assert face_calibration_report.accepted_quality_genuine_rate >= 0.90
    assert face_calibration_report.contains_raw_media is False
```

- [ ] **Step 2: Run red tests**

Run: `uv run pytest tests/unit/identity/test_face_consensus.py tests/unit/identity/test_face_liveness.py tests/security/test_face_retention.py tests/security/test_face_presentation_attacks.py tests/acceptance/test_face_calibration.py -q`
Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core.services.identity.face_enrollment'`.

- [ ] **Step 3: Implement fail-closed face evidence and the acceptance gate**

```python
# apps/core/src/tuntun_core/services/identity/face_liveness.py
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID
from tuntun_contracts.actions import ActionBinding

FACE_STEPS = ("blink", "left", "right")
EAR_CLOSED_MAX = 180_000
EAR_OPEN_MIN = 250_000
LEFT_YAW_MAX_MILLIDEG = -15_000
RIGHT_YAW_MIN_MILLIDEG = 15_000
CHALLENGE_SECONDS = 10

@dataclass(frozen=True)
class LivenessAcceptance:
    model_manifest_accepted: bool
    calibration_passed: bool
    printed_face_passed: bool
    screen_face_passed: bool
    injected_frame_passed: bool

    @property
    def accepted(self) -> bool:
        return all((self.model_manifest_accepted, self.calibration_passed, self.printed_face_passed, self.screen_face_passed, self.injected_frame_passed))

@dataclass(frozen=True, slots=True)
class LivenessEvidence:
    accepted: bool
    challenge_id: UUID
    binding: ActionBinding
    observations: tuple[str, ...]
    observed_at: datetime
    expires_at: datetime


class FaceLivenessService:
    def __init__(self, uow_factory, landmark_model, audit_ledger, clock, step_generator):
        self._uow_factory = uow_factory
        self._landmark_model = landmark_model
        self._audit = audit_ledger
        self._clock = clock
        self._step_generator = step_generator

    async def start(self, binding, now=None):
        issued_at = now or self._clock.now()
        steps = self._step_generator.two_distinct(FACE_STEPS)
        async with self._uow_factory() as uow:
            challenge = await uow.identity_challenges.create(kind="face_liveness_v1", binding=binding, steps=steps, issued_at=issued_at, expires_at=issued_at + timedelta(seconds=CHALLENGE_SECONDS))
            await self._audit.append(uow, challenge.started_audit())
            await uow.commit()
            return challenge

    async def verify(self, challenge_id, binding, observations, now):
        # Snapshot bounded challenge state, then release SQLCipher before local CPU inference.
        async with self._uow_factory() as read_uow:
            snapshot = await read_uow.identity_challenges.get_open_snapshot(challenge_id, now)
            if snapshot.binding != binding:
                raise PermissionError("face_challenge_binding")
        observed = self._landmark_model.classify_ordered_steps(observations, ear_closed_max=EAR_CLOSED_MAX, ear_open_min=EAR_OPEN_MIN, left_yaw_max_millideg=LEFT_YAW_MAX_MILLIDEG, right_yaw_min_millideg=RIGHT_YAW_MIN_MILLIDEG, require_monotonic_frame_ids=True)

        # Re-lock and compare the complete immutable snapshot before the exactly-once consume.
        async with self._uow_factory() as uow:
            challenge = await uow.identity_challenges.lock_open(challenge_id, now)
            if challenge.binding != binding or challenge.snapshot_commitment != snapshot.snapshot_commitment:
                raise PermissionError("face_challenge_changed")
            if observed != challenge.steps:
                await uow.identity_challenges.consume_failed(challenge.id, "face_challenge_sequence", now)
                await self._audit.append(uow, challenge.failed_audit("face_challenge_sequence", now))
                await uow.commit()
                raise PermissionError("face_challenge_sequence")
            await uow.identity_challenges.consume_success(challenge.id, now)
            evidence = LivenessEvidence(True, challenge.id, binding, tuple(observed), now, min(challenge.expires_at, now + timedelta(seconds=10)))
            await self._audit.append(uow, challenge.succeeded_audit(evidence))
            await uow.commit()
            return evidence
```

```python
# apps/core/src/tuntun_core/services/identity/face_enrollment.py
from collections import Counter
from datetime import timedelta
from tuntun_contracts.identity import IdentityEvidence
from tuntun_core.domain.profile import ConsentPurpose

def guest_face(reason, now):
    return IdentityEvidence(modality="face", subject_id=None, confidence_micros=0, quality_micros=0, liveness_accepted=False, model_version=f"unaccepted:{reason}", observed_at=now, expires_at=now)

def resolve_face_consensus(observations, now):
    accepted = [item for item in observations if item.quality_micros >= 700_000]
    counts = Counter(item.subject_id for item in accepted)
    if not counts or counts.most_common(1)[0][1] < 3:
        return guest_face("insufficient_consensus", now)
    subject_id, count = counts.most_common(1)[0]
    if len(counts) > 1 and counts.most_common(2)[1][1] >= 2:
        return guest_face("ambiguous_candidates", now)
    matches = [item for item in accepted if item.subject_id == subject_id]
    liveness = all(item.liveness_accepted for item in matches)
    if not liveness:
        return guest_face("liveness_not_accepted", now)
    return IdentityEvidence(modality="face", subject_id=subject_id, confidence_micros=min(item.confidence_micros for item in matches), quality_micros=min(item.quality_micros for item in matches), liveness_accepted=True, model_version=matches[0].model_version, observed_at=now, expires_at=now + timedelta(seconds=10))

class FaceEnrollmentService:
    def __init__(self, matcher, uow_factory, consents, enrollments, crypto, audit_ledger):
        self._matcher, self._uow_factory, self._consents, self._enrollments = matcher, uow_factory, consents, enrollments
        self._crypto, self._audit = crypto, audit_ledger

    async def enroll(self, enrollment_id, frames, model, now):
        if not 5 <= len(frames) <= 10:
            raise ValueError("face_enrollment_requires_5_to_10_frames")
        try:
            async with self._uow_factory() as preflight:
                session = await preflight.enrollments.require_state(enrollment_id, "calibrating")
                if session.modality != "face": raise PermissionError("enrollment_modality_mismatch")
                await self._consents.require_current_in_uow(preflight, session.subject_id, ConsentPurpose.FACE, now)
            observations = await self._matcher.enrollment_observations(frames, model)
            centroid = self._matcher.require_quality_consensus(observations)
            encrypted = self._crypto.encrypt_record(centroid.to_bytes(), purpose="face_template")
            async with self._uow_factory() as uow:
                session = await uow.enrollments.lock_state(enrollment_id, "calibrating")
                consent = await self._consents.require_current_in_uow(uow, session.subject_id, ConsentPurpose.FACE, now)
                if consent.subject_id != session.subject_id or consent.purpose.value != "face": raise PermissionError("enrollment_consent_scope_mismatch")
                template = await uow.biometric_templates.insert(subject_id=session.subject_id, modality="face", model_version=model.version, encrypted=encrypted, consent_receipt_id=consent.id)
                await self._enrollments.complete_in_uow(uow, enrollment_id, (template.id,), consent, now)
                await self._audit.append(uow, uow.biometric_templates.enrolled_audit(template))
                await uow.commit()
                return template
        finally:
            for frame in frames:
                frame.clear()
```

```python
# apps/core/src/tuntun_core/adapters/identity/face_yunet_sface.py
class YuNetSFaceAdapter:
    def __init__(self, registry, executor, backend):
        self._registry, self._executor, self._backend = registry, executor, backend

    async def observe(self, frames, model):
        self._registry.require_activated(model, purpose="face_personalization")
        try:
            return await self._executor.run(self._backend.observe, tuple(frame.view() for frame in frames))
        finally:
            for frame in frames:
                frame.clear()
```

```python
# apps/core/src/tuntun_core/adapters/identity/worker.py
import asyncio
from concurrent.futures import ThreadPoolExecutor
class BoundedIdentityWorker:
    def __init__(self): self._executor=ThreadPoolExecutor(max_workers=1,thread_name_prefix="tuntun-identity"); self._slots=asyncio.Semaphore(2)
    async def run(self,fn,*args):
        async with self._slots: return await asyncio.get_running_loop().run_in_executor(self._executor,fn,*args)
```

```yaml
# models/manifest.yaml face entry
- id: face-yunet-sface
  purpose: face_personalization
  activation: blocked_owner_acceptance
  runtime: onnx
  raw_media_retention: false
```

```markdown
<!-- docs/privacy/biometric-model-governance.md -->
Face activation requires immutable artifact hashes, accepted licenses, 500 held-out comparisons with zero false personalization, at least 90% genuine acceptance on accepted-quality samples, and passing printed-face, screen-face, injected-frame, and two-step randomized ten-second liveness tests. Only aggregate results and commitments persist.
```

Register the reviewed local files without committing weights:

```bash
uv run tuntunctl models register-local --bundle face-yunet-sface --artifact var/model-review/face_detection_yunet_2023mar.onnx --artifact var/model-review/face_recognition_sface_2021dec.onnx --purpose face_personalization --activation blocked_owner_acceptance
```

Expected: `registered face-yunet-sface activation=blocked_owner_acceptance artifacts=2 hashes=verified`.

- [ ] **Step 4: Run green, governance, and privacy tests**

Run: `uv run pytest tests/unit/identity/test_face_consensus.py tests/unit/identity/test_face_liveness.py tests/security/test_face_retention.py tests/security/test_face_presentation_attacks.py tests/acceptance/test_face_calibration.py tests/security/test_model_governance.py -q`
Expected: PASS; all presentation attacks resolve to Guest or personalization-only and the sentinel scan reports zero matches.

- [ ] **Step 5: Check and commit**

Run: `uv run ruff format --check apps/core/src/tuntun_core/services/identity/face_enrollment.py apps/core/src/tuntun_core/services/identity/face_liveness.py apps/core/src/tuntun_core/adapters/identity/face_yunet_sface.py apps/core/src/tuntun_core/adapters/identity/worker.py tests/unit/identity/test_face_consensus.py tests/unit/identity/test_face_liveness.py tests/security/test_face_retention.py tests/security/test_face_presentation_attacks.py tests/acceptance/test_face_calibration.py && uv run ruff check apps/core/src/tuntun_core/services/identity/face_enrollment.py apps/core/src/tuntun_core/services/identity/face_liveness.py apps/core/src/tuntun_core/adapters/identity/face_yunet_sface.py apps/core/src/tuntun_core/adapters/identity/worker.py tests/unit/identity/test_face_consensus.py tests/unit/identity/test_face_liveness.py tests/security/test_face_retention.py tests/security/test_face_presentation_attacks.py tests/acceptance/test_face_calibration.py && uv run mypy apps/core/src/tuntun_core/services/identity apps/core/src/tuntun_core/adapters/identity`
Expected: PASS with exit code 0.

```bash
git add apps/core/src/tuntun_core/services/identity/face_enrollment.py apps/core/src/tuntun_core/services/identity/face_liveness.py apps/core/src/tuntun_core/adapters/identity/face_yunet_sface.py apps/core/src/tuntun_core/adapters/identity/worker.py apps/core/pyproject.toml uv.lock models/manifest.yaml docs/privacy/biometric-model-governance.md tests/unit/identity/test_face_consensus.py tests/unit/identity/test_face_liveness.py tests/security/test_face_retention.py tests/security/test_face_presentation_attacks.py tests/acceptance/test_face_calibration.py
git diff --cached --name-only
git diff --cached
git commit -m "feat(identity): add governed face evidence"
```

### Task 4: Prove identity is interaction-gated and unknown candidates are never stored

**Master coverage:** Task 18
**Depends on:** Tasks 1–3
**Estimated effort:** 1 person-day

**Files:**
- Create: `apps/core/src/tuntun_core/services/identity/active_face_identity.py`
- Create: `tests/security/test_identity_interaction_gate.py`
- Create: `tests/security/test_identity_negative_reachability.py`
- Modify: `tests/integration/storage/test_migrations.py`
- Modify: `tests/contracts/test_action_contracts.py`
- Modify: `tests/unit/config/test_settings.py`

**Interfaces:**
- Consumes: a current `CameraWindowGrant` whose purpose is exactly `explicit_enrollment` or `active_conversation_identity`, the matching live Reachy device/session/turn/privacy generations, consent state, bounded `EphemeralFrame` objects, and the Task 3 governed face matcher/liveness result.
- Produces: `ActiveFaceIdentityService.observe` returning enrolled-profile personalization evidence or Guest. It clears every frame on every terminal path and writes no raw frame, crop, unknown embedding, or unknown-person record.
- Does not expose a discovery setting/action/consent purpose, background frame consumer, candidate repository/table, re-encounter operation, unknown-person API/UI projection, or feature manifest entry.

- [ ] **Step 1: Write failing interaction-gate and negative-reachability tests**

```python
# tests/security/test_identity_interaction_gate.py
import pytest

@pytest.mark.asyncio
async def test_face_observation_requires_current_active_interaction(service, stale_grant, frames):
    result = await service.observe(stale_grant, frames)
    assert result.profile_id is None
    assert result.assurance == "guest"
    assert result.reason_code == "identity_window_not_current"
    assert all(frame.cleared for frame in frames)

@pytest.mark.asyncio
async def test_unknown_active_interaction_is_guest_and_not_persisted(service, active_grant, unknown_frames, database):
    result = await service.observe(active_grant, unknown_frames)
    assert result.assurance == "guest"
    assert result.reason_code == "identity_unknown"
    assert not database.has_table("unknown_identity_candidates")
    assert database.search_blob(unknown_frames.sentinel) == []
```

```python
# tests/security/test_identity_negative_reachability.py
def test_passive_identity_surface_is_absent(contract_registry, route_registry, settings_schema, feature_manifest, database):
    forbidden = {
        "passive_discovery",
        "identity.discovery.enable",
        "identity.discovery.opt_out",
        "identity.candidate.confirm",
        "identity.candidate.dismiss",
        "unknown_identity_candidates",
    }
    exported = "\n".join((
        contract_registry.canonical_json(),
        route_registry.canonical_json(),
        settings_schema.canonical_json(),
        feature_manifest.canonical_json(),
        database.schema_sql(),
    ))
    assert all(name not in exported for name in forbidden)
```

- [ ] **Step 2: Run red tests**

Run: `uv run pytest tests/security/test_identity_interaction_gate.py tests/security/test_identity_negative_reachability.py tests/integration/storage/test_migrations.py tests/contracts/test_action_contracts.py tests/unit/config/test_settings.py -q`
Expected: FAIL during collection because `active_face_identity.py` is absent, or fail the negative-reachability assertion if any earlier contract/config fixture still exposes a forbidden discovery/candidate name.

- [ ] **Step 3: Implement the active-interaction gate and remove every passive surface**

Implement `ActiveFaceIdentityService.observe(grant, frames)` as a bounded coordinator: validate the signed grant, paired device, live household/session/turn, action/purpose, issue/expiry time, privacy generation, consent, model acceptance, frame count/rate/byte caps, and one-time grant consumption before inference. Return Guest for any denial, ambiguity, liveness failure, unknown template, or matcher conflict. Clear each frame in `finally`. The service may read enrolled templates only; it has no repository method capable of storing an unknown observation.

Keep the migration chain at `0002_profiles_consent_enrollment.py → 0003_authentication.py`; no biometric-candidate migration exists. Remove forbidden action/consent/config discriminators rather than accepting and disabling them. Add startup/schema tests that fail if a future migration introduces an unknown-candidate table or if route/config/feature registration exposes passive identity.

- [ ] **Step 4: Run green, retention, and absence tests**

Run: `uv run pytest tests/security/test_identity_interaction_gate.py tests/security/test_identity_negative_reachability.py tests/security/test_face_retention.py tests/security/test_face_presentation_attacks.py tests/integration/storage/test_migrations.py tests/contracts/test_action_contracts.py tests/unit/config/test_settings.py -q`
Expected: PASS; all rejected/unknown observations resolve to Guest, every supplied frame is cleared, the sentinel is absent from durable stores/logs, and every forbidden passive/candidate surface is absent.

- [ ] **Step 5: Check and commit**

Run: `uv run ruff format --check apps/core/src/tuntun_core/services/identity/active_face_identity.py tests/security/test_identity_interaction_gate.py tests/security/test_identity_negative_reachability.py tests/integration/storage/test_migrations.py tests/contracts/test_action_contracts.py tests/unit/config/test_settings.py && uv run ruff check apps/core/src/tuntun_core/services/identity/active_face_identity.py tests/security/test_identity_interaction_gate.py tests/security/test_identity_negative_reachability.py tests/integration/storage/test_migrations.py tests/contracts/test_action_contracts.py tests/unit/config/test_settings.py && uv run mypy apps/core/src/tuntun_core/services/identity/active_face_identity.py`
Expected: PASS with exit code 0.

```bash
git add apps/core/src/tuntun_core/services/identity/active_face_identity.py tests/security/test_identity_interaction_gate.py tests/security/test_identity_negative_reachability.py tests/integration/storage/test_migrations.py tests/contracts/test_action_contracts.py tests/unit/config/test_settings.py
git diff --cached --name-only
git diff --cached
git commit -m "feat(identity): enforce interaction-gated identity"
```

### Task 5A: Add governed voice evidence and enrollment

**Master coverage:** Task 19
**Depends on:** Tasks 1–4 and master Tasks 04 and 14
**Estimated effort:** 3 person-days

**Files:**
- Create: `apps/core/src/tuntun_core/services/identity/voice_enrollment.py`
- Create: `apps/core/src/tuntun_core/adapters/identity/voice_onnx.py`
- Create: `scripts/models/convert_speechbrain_ecapa.py`
- Modify: `apps/core/pyproject.toml` (ONNX Runtime only after Intel probe)
- Modify: `uv.lock` (resolved runtime artifacts)
- Modify: `models/manifest.yaml` (`speechbrain-ecapa-onnx` entry at revision `0f99f2d0ebe89ac095bcc5903c4dd8f72b367286`)
- Create: `tests/unit/identity/test_voice_quality.py`
- Create: `tests/security/test_voice_retention.py`
- Create: `tests/hardware/test_intel_voice_runtime.py`

**Interfaces:**
- Consumes: 1.5–3.0 seconds of VAD-trimmed post-wake `EphemeralAudio`, an owner-authorized voice `EnrollmentSession` in `calibrating`, current HMAC-valid voice consent rechecked in the template-write UoW, and an activated reviewed ONNX model.
- Produces: `VoiceMatcherPort.observe(...) -> IdentityEvidence` using the exact foundation fields plus encrypted voice centroids; no audio recording or unsafe checkpoint enters the production runtime.

- [ ] **Step 1: Write failing quality, enrollment, and retention tests**

```python
# tests/unit/identity/test_voice_quality.py
import pytest
from tuntun_core.adapters.identity.voice_onnx import VoiceOnnxAdapter

@pytest.mark.asyncio
async def test_short_voice_is_guest_and_audio_is_cleared(adapter, short_audio, audio_format, activated_model):
    evidence = await adapter.observe(short_audio, audio_format, activated_model)
    assert evidence.subject_id is None and evidence.confidence_micros == 0
    assert short_audio.cleared is True
```

```python
# tests/security/test_voice_retention.py
import pytest

@pytest.mark.asyncio
async def test_voice_sentinel_is_absent_after_enrollment(voice_enrollment, voice_enrollment_session, synthetic_audio, private_data_scanner, now):
    await voice_enrollment.enroll(voice_enrollment_session.id, synthetic_audio.handles, now)
    assert private_data_scanner.find(synthetic_audio.sentinel) == ()
    assert all(handle.cleared for handle in synthetic_audio.handles)
```

- [ ] **Step 2: Run red tests**

Run: `uv run pytest tests/unit/identity/test_voice_quality.py tests/security/test_voice_retention.py -q`
Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core.adapters.identity.voice_onnx'`.

- [ ] **Step 3: Implement quality gating, safe ONNX loading, and encrypted enrollment**

```python
# apps/core/src/tuntun_core/adapters/identity/voice_onnx.py
from tuntun_contracts.identity import IdentityEvidence
class VoiceOnnxAdapter:
    MIN_SECONDS = 1.5
    MAX_SECONDS = 3.0

    def __init__(self, registry, executor, backend):
        self._registry, self._executor, self._backend = registry, executor, backend

    async def observe(self, pcm, audio_format, model):
        self._registry.require_activated(model, purpose="voice_personalization", safe_format="onnx")
        duration = pcm.view().nbytes / (audio_format.sample_rate_hz * audio_format.channels * 2)
        if not self.MIN_SECONDS <= duration <= self.MAX_SECONDS:
            pcm.clear()
            now=self._backend.clock.now()
            return IdentityEvidence(modality="voice",subject_id=None,confidence_micros=0,quality_micros=0,liveness_accepted=False,model_version=model.version,observed_at=now,expires_at=now)
        try:
            return await self._executor.run(self._backend.observe, pcm.view(), audio_format)
        finally:
            pcm.clear()
```

```python
# apps/core/src/tuntun_core/services/identity/voice_enrollment.py
from tuntun_core.domain.profile import ConsentPurpose

class VoiceEnrollmentService:
    def __init__(self, consents, enrollments, matcher, uow_factory, crypto, model, audit_ledger):
        self._consents, self._enrollments, self._matcher, self._uow_factory = consents, enrollments, matcher, uow_factory
        self._crypto, self._model, self._audit = crypto, model, audit_ledger

    async def enroll(self, enrollment_id, audio_handles, now):
        if not 3 <= len(audio_handles) <= 8:
            raise ValueError("voice_enrollment_requires_3_to_8_utterances")
        try:
            async with self._uow_factory() as preflight:
                session = await preflight.enrollments.require_state(enrollment_id, "calibrating")
                if session.modality != "voice": raise PermissionError("enrollment_modality_mismatch")
                await self._consents.require_current_in_uow(preflight, session.subject_id, ConsentPurpose.VOICE, now)
            embeddings = [await self._matcher.enrollment_embedding(handle, self._model) for handle in audio_handles]
            centroid = self._matcher.normalized_centroid(embeddings)
            encrypted = self._crypto.encrypt_record(centroid.to_bytes(), purpose="voice_template")
            async with self._uow_factory() as uow:
                session = await uow.enrollments.lock_state(enrollment_id, "calibrating")
                consent = await self._consents.require_current_in_uow(uow, session.subject_id, ConsentPurpose.VOICE, now)
                if consent.subject_id != session.subject_id or consent.purpose.value != "voice": raise PermissionError("enrollment_consent_scope_mismatch")
                template = await uow.biometric_templates.insert(session.subject_id, "voice", self._model.version, encrypted, consent_receipt_id=consent.id)
                await self._enrollments.complete_in_uow(uow, enrollment_id, (template.id,), consent, now)
                await self._audit.append(uow, uow.biometric_templates.enrolled_audit(template))
                await uow.commit()
                return template
        finally:
            for handle in audio_handles:
                handle.clear()
```

```python
# scripts/models/convert_speechbrain_ecapa.py
from pathlib import Path
import hashlib

SOURCE_REVISION = "0f99f2d0ebe89ac095bcc5903c4dd8f72b367286"

def record_safe_artifact(path: Path) -> dict[str, str | int]:
    data = path.read_bytes()
    if data[:2] == b"\x80\x04":
        raise ValueError("pickle_output_forbidden")
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "format": "onnx", "source_revision": SOURCE_REVISION}
```

```yaml
# models/manifest.yaml voice and liveness entries
- id: speechbrain-ecapa-onnx
  revision: 0f99f2d0ebe89ac095bcc5903c4dd8f72b367286
  purpose: voice_personalization
  activation: blocked_calibration
  runtime: onnx
- id: local-digits-v1
  purpose: voice_liveness
  activation: blocked_calibration
  runtime: onnx
  vocabulary: ["0","1","2","3","4","5","6","7","8","9"]
```

Run the isolated conversion and registration:

```bash
uv run --project scripts/models python scripts/models/convert_speechbrain_ecapa.py --source var/model-review/speechbrain-ecapa --output var/model-review/speechbrain-ecapa.onnx
uv run tuntunctl models register-local --bundle speechbrain-ecapa-onnx --artifact var/model-review/speechbrain-ecapa.onnx --purpose voice_personalization --activation blocked_calibration
```

Expected: `registered speechbrain-ecapa-onnx activation=blocked_calibration artifacts=1 hashes=verified`.

- [ ] **Step 4: Run green, retention, governance, and Intel tests**

Run: `uv run pytest tests/unit/identity/test_voice_quality.py tests/security/test_voice_retention.py tests/hardware/test_intel_voice_runtime.py tests/security/test_model_governance.py -q`
Expected: PASS; the sentinel scan is empty and the Intel test reports bounded latency without importing PyTorch in the core environment.

- [ ] **Step 5: Check and commit**

Run: `uv run ruff format --check apps/core/src/tuntun_core/services/identity/voice_enrollment.py apps/core/src/tuntun_core/adapters/identity/voice_onnx.py scripts/models/convert_speechbrain_ecapa.py tests/unit/identity/test_voice_quality.py tests/security/test_voice_retention.py tests/hardware/test_intel_voice_runtime.py && uv run ruff check apps/core/src/tuntun_core/services/identity/voice_enrollment.py apps/core/src/tuntun_core/adapters/identity/voice_onnx.py scripts/models/convert_speechbrain_ecapa.py tests/unit/identity/test_voice_quality.py tests/security/test_voice_retention.py tests/hardware/test_intel_voice_runtime.py && uv run mypy apps/core/src/tuntun_core/services/identity/voice_enrollment.py apps/core/src/tuntun_core/adapters/identity/voice_onnx.py`
Expected: PASS with exit code 0.

```bash
git add apps/core/src/tuntun_core/services/identity/voice_enrollment.py apps/core/src/tuntun_core/adapters/identity/voice_onnx.py scripts/models/convert_speechbrain_ecapa.py apps/core/pyproject.toml uv.lock models/manifest.yaml tests/unit/identity/test_voice_quality.py tests/security/test_voice_retention.py tests/hardware/test_intel_voice_runtime.py
git diff --cached --name-only
git diff --cached
git commit -m "feat(identity): add governed voice evidence"
```

### Task 5B: Verify randomized voice liveness and fuse identity safely

**Master coverage:** Task 19
**Depends on:** Tasks 3 and 5A
**Estimated effort:** 3 person-days

**Files:**
- Create: `apps/core/src/tuntun_core/services/identity/voice_liveness.py`
- Create: `apps/core/src/tuntun_core/adapters/identity/digit_onnx.py`
- Create: `apps/core/src/tuntun_core/services/identity/fusion.py`
- Create: `apps/core/src/tuntun_core/services/identity/calibration.py`
- Create: `tests/unit/identity/test_fusion.py`
- Create: `tests/security/test_biometric_authorization.py`
- Create: `tests/security/test_voice_replay_attacks.py`
- Create: `tests/unit/identity/test_voice_liveness.py`
- Create: `tests/acceptance/test_voice_calibration.py`

**Interfaces:**
- Consumes: `LocalDigitRecognizerPort.recognize(EphemeralAudio) -> str` implemented in this task, optional current face/voice `IdentityEvidence`, and a current acceptance record covering model governance, calibration, recorded/synthetic/converted voice, printed/screen face, injected frames, and combined attacks.
- Produces: a session/turn/subject-bound single-use `VoiceChallenge` containing a random 100–999 phrase and expiring in 10 seconds; `IdentityFusionPort.resolve(...) -> IdentityDecision`; `identified` personalization for one or two strong non-conflicting signals with accepted liveness, and Guest for every conflict, ambiguity, expiry, or liveness failure. It never produces `confirmed` action assurance. Production voice personalization remains disabled until the real local digit recognizer passes the control-plan gate.

- [ ] **Step 1: Write failing fusion, replay, and authorization tests**

```python
# tests/unit/identity/test_voice_liveness.py
from datetime import timedelta
import pytest
from tuntun_core.services.identity.voice_liveness import VoiceLivenessService

class SequenceDigitGenerator:
    def __init__(self): self._values=iter(("583","583","721","406"))
    def random_three_digits(self): return next(self._values)

@pytest.fixture
def voice_liveness(uow_factory, local_digits, replay_detector, audit_ledger, clock):
    return VoiceLivenessService(uow_factory, local_digits, replay_detector, audit_ledger, clock, SequenceDigitGenerator())


@pytest.mark.asyncio
async def test_voice_challenge_requires_current_random_digits(voice_liveness, binding, spoken_digits, now):
    challenge = await voice_liveness.start(binding, now=now)
    evidence = await voice_liveness.verify(challenge.id, binding, spoken_digits("583"), now + timedelta(seconds=3))
    assert evidence.accepted is True
    with pytest.raises(PermissionError, match="voice_challenge_consumed"):
        await voice_liveness.verify(challenge.id, binding, spoken_digits("583"), now + timedelta(seconds=4))


@pytest.mark.asyncio
async def test_wrong_replayed_or_expired_voice_is_guest(voice_liveness, binding, spoken_digits, now):
    wrong = await voice_liveness.start(binding, now=now)
    with pytest.raises(PermissionError, match="voice_phrase_mismatch"):
        await voice_liveness.verify(wrong.id, binding, spoken_digits("358"), now + timedelta(seconds=2))
    replay = await voice_liveness.start(binding, now=now)
    with pytest.raises(PermissionError, match="voice_replay_detected"):
        await voice_liveness.verify(replay.id, binding, spoken_digits("721", replay=True), now + timedelta(seconds=2))
    expired = await voice_liveness.start(binding, now=now)
    with pytest.raises(PermissionError, match="voice_challenge_expired"):
        await voice_liveness.verify(expired.id, binding, spoken_digits("406"), now + timedelta(seconds=11))
```

```python
# tests/unit/identity/test_fusion.py
import pytest

@pytest.mark.asyncio
async def test_conflicting_modalities_are_guest(fusion_service, face_a, voice_b, now, identity_request):
    decision = await fusion_service.resolve(identity_request(face_a, voice_b, now))
    assert decision.status == "conflict"
    assert decision.subject_id is None

@pytest.mark.asyncio
async def test_agreement_without_accepted_liveness_is_guest(fusion_service, face_a, voice_a_without_liveness, now, identity_request):
    decision = await fusion_service.resolve(identity_request(face_a, voice_a_without_liveness, now))
    assert decision.subject_id is None
    assert decision.status == "unknown"

@pytest.mark.asyncio
@pytest.mark.parametrize("invalid_state", ["face_consent_revoked", "voice_consent_revoked", "profile_revoked", "child_template_expired", "model_acceptance_revoked"])
async def test_current_identity_state_failure_is_guest(fusion_service, identity_state, face_a, voice_a, identity_request, invalid_state):
    await identity_state.force_invalid_for_test(invalid_state)
    decision = await fusion_service.resolve(identity_request(face_a, voice_a, identity_state.now()))
    assert decision.subject_id is None
    assert decision.status == "unknown"
```

```python
# tests/security/test_biometric_authorization.py
import pytest

@pytest.mark.parametrize("risk", ["low", "medium", "high"])
@pytest.mark.asyncio
async def test_biometrics_never_satisfy_any_action_risk(policy_engine, fused_identity, risk):
    decision = await policy_engine.decide(fused_identity.request(risk=risk))
    assert decision.effect.value == "step_up"
    assert decision.required_assurance.value in {"confirmed", "pin_verified", "passkey_verified"}
```

```python
# tests/acceptance/test_voice_calibration.py
def test_voice_calibration_gate(voice_calibration_report):
    assert voice_calibration_report.comparison_count >= 500
    assert voice_calibration_report.false_personalizations == 0
    assert voice_calibration_report.accepted_quality_genuine_rate >= 0.90
    assert voice_calibration_report.contains_raw_audio is False
```

- [ ] **Step 2: Run red tests**

Run: `uv run pytest tests/unit/identity/test_voice_liveness.py tests/unit/identity/test_fusion.py tests/security/test_biometric_authorization.py tests/security/test_voice_replay_attacks.py tests/acceptance/test_voice_calibration.py -q`
Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core.services.identity.voice_liveness'`.

- [ ] **Step 3: Implement acceptance and deterministic fusion**

```python
# apps/core/src/tuntun_core/services/identity/voice_liveness.py
from datetime import timedelta
from tuntun_core.services.identity.face_liveness import LivenessEvidence


class VoiceLivenessService:
    CHALLENGE_SECONDS = 10

    def __init__(self, uow_factory, local_digits, replay_detector, audit_ledger, clock, digit_generator):
        self._uow_factory = uow_factory
        self._local_digits = local_digits
        self._replay_detector = replay_detector
        self._audit = audit_ledger
        self._clock = clock
        self._digit_generator = digit_generator

    async def start(self, binding, now=None):
        issued_at = now or self._clock.now()
        digits = self._digit_generator.random_three_digits()
        async with self._uow_factory() as uow:
            challenge = await uow.identity_challenges.create(kind="voice_digits_v1", binding=binding, expected_digits=digits, issued_at=issued_at, expires_at=issued_at + timedelta(seconds=self.CHALLENGE_SECONDS))
            await self._audit.append(uow, challenge.started_audit())
            await uow.commit()
            return challenge

    async def verify(self, challenge_id, binding, audio, now):
        try:
            async with self._uow_factory() as read_uow:
                snapshot = await read_uow.identity_challenges.get_open_snapshot(challenge_id, now)
                if snapshot.binding != binding:
                    raise PermissionError("voice_challenge_binding")
            replayed = await self._replay_detector.is_replayed(audio)
            recognized = None if replayed else await self._local_digits.recognize(audio)
            reason = "voice_replay_detected" if replayed else None
            if not replayed and recognized != snapshot.expected_digits:
                reason = "voice_phrase_mismatch"

            async with self._uow_factory() as uow:
                challenge = await uow.identity_challenges.lock_open(challenge_id, now)
                if challenge.binding != binding or challenge.snapshot_commitment != snapshot.snapshot_commitment:
                    raise PermissionError("voice_challenge_changed")
                if reason is not None:
                    await uow.identity_challenges.consume_failed(challenge.id, reason, now)
                    await self._audit.append(uow, challenge.failed_audit(reason, now))
                    await uow.commit()
                    raise PermissionError(reason)
                assert recognized is not None
                await uow.identity_challenges.consume_success(challenge.id, now)
                evidence = LivenessEvidence(True, challenge.id, binding, (recognized,), now, min(challenge.expires_at, now + timedelta(seconds=10)))
                await self._audit.append(uow, challenge.succeeded_audit(evidence))
                await uow.commit()
                return evidence
        finally:
            audio.clear()
```

```python
# apps/core/src/tuntun_core/adapters/identity/digit_onnx.py
class LocalDigitRecognizer:
    def __init__(self, registry, backend):
        self._registry, self._backend = registry, backend

    async def recognize(self, audio):
        model = self._registry.require_activated("local-digits-v1", purpose="voice_liveness", safe_format="onnx")
        try:
            digits = await self._backend.recognize_three_digits(audio.view(), model.path)
            if len(digits) != 3 or not digits.isascii() or not digits.isdigit():
                raise PermissionError("voice_phrase_unrecognized")
            return digits
        finally:
            audio.clear()
```

```python
# apps/core/src/tuntun_core/services/identity/calibration.py
from dataclasses import dataclass

@dataclass(frozen=True)
class VoiceLivenessAcceptance:
    model_manifest_accepted: bool
    calibration_zero_false_personalization: bool
    recorded_voice_passed: bool
    synthetic_voice_passed: bool
    voice_conversion_passed: bool
    combined_attack_passed: bool

    @property
    def accepted(self) -> bool:
        return all((self.model_manifest_accepted, self.calibration_zero_false_personalization, self.recorded_voice_passed, self.synthetic_voice_passed, self.voice_conversion_passed, self.combined_attack_passed))
```

```python
# apps/core/src/tuntun_core/services/identity/fusion.py
from datetime import timedelta
from tuntun_contracts.identity import IdentityDecision, IdentityStatus
from tuntun_core.domain.profile import ConsentPurpose
class CurrentIdentityState:
    def __init__(self, uow_factory, consents, model_acceptance):
        self._uow_factory, self._consents, self._model_acceptance = uow_factory, consents, model_acceptance

    async def require_current(self, household_id, subject_id, evidence, now):
        async with self._uow_factory() as uow:
            profile = await uow.profiles.get_scoped(household_id, subject_id)
            if not profile.active or profile.revoked_at is not None: raise PermissionError("identity_profile_not_current")
            for item in evidence:
                consent = await self._consents.require_current_in_uow(uow, subject_id, ConsentPurpose(item.modality), now)
                template = await uow.biometric_templates.require_active(subject_id, item.modality, item.model_version, now)
                if template.consent_receipt_id != consent.id or template.revoked_at is not None or (template.expires_at is not None and template.expires_at <= now):
                    raise PermissionError("identity_template_not_current")
                await self._model_acceptance.require_current_in_uow(uow, item.modality, item.model_version, now)

class IdentityFusionService:
    def __init__(self, current_state, clock):
        self._current_state, self._clock = current_state, clock

    async def resolve(self, request):
        by_modality = {item.modality: item for item in request.evidence}
        face, voice, now = by_modality.get("face"), by_modality.get("voice"), self._clock.now()
        supplied = [item for item in (face, voice) if item is not None]
        if any(not item.liveness_accepted for item in supplied):
            return IdentityDecision(status=IdentityStatus.UNKNOWN,subject_id=None,reason_code="liveness_not_accepted",expires_at=now+timedelta(seconds=10))
        evidence = [item for item in supplied if item.expires_at > now and item.quality_micros >= 700_000]
        if not evidence:
            return IdentityDecision(status=IdentityStatus.UNKNOWN,subject_id=None,reason_code="no_current_quality_evidence",expires_at=now+timedelta(seconds=10))
        subjects = {item.subject_id for item in evidence if item.subject_id is not None}
        if len(subjects) != 1:
            status=IdentityStatus.CONFLICT if len(subjects)>1 else IdentityStatus.UNKNOWN
            return IdentityDecision(status=status,subject_id=None,reason_code=status.value,expires_at=now+timedelta(seconds=10))
        subject_id = subjects.pop()
        try:
            await self._current_state.require_current(request.household_id, subject_id, tuple(evidence), now)
        except PermissionError:
            return IdentityDecision(status=IdentityStatus.UNKNOWN,subject_id=None,reason_code="identity_state_not_current",expires_at=now+timedelta(seconds=10))
        both = face is not None and voice is not None
        return IdentityDecision(status=IdentityStatus.VERIFIED,subject_id=subject_id,expires_at=min(item.expires_at for item in evidence),reason_code="modalities_agree" if both else "single_modality")
```

- [ ] **Step 4: Run green, presentation/replay, and policy tests**

Run: `uv run pytest tests/unit/identity/test_voice_liveness.py tests/unit/identity/test_fusion.py tests/security/test_biometric_authorization.py tests/security/test_voice_replay_attacks.py tests/security/test_face_presentation_attacks.py tests/acceptance/test_voice_calibration.py -q`
Expected: PASS; every recorded, synthetic, converted, printed, screen, injected-frame, and combined attack is Guest, while accepted biometrics yield identified personalization only and never satisfy any action.

- [ ] **Step 5: Check and commit**

Run: `uv run ruff format --check apps/core/src/tuntun_core/services/identity/voice_liveness.py apps/core/src/tuntun_core/adapters/identity/digit_onnx.py apps/core/src/tuntun_core/services/identity/fusion.py apps/core/src/tuntun_core/services/identity/calibration.py tests/unit/identity/test_voice_liveness.py tests/unit/identity/test_fusion.py tests/security/test_biometric_authorization.py tests/security/test_voice_replay_attacks.py tests/acceptance/test_voice_calibration.py && uv run ruff check apps/core/src/tuntun_core/services/identity/voice_liveness.py apps/core/src/tuntun_core/adapters/identity/digit_onnx.py apps/core/src/tuntun_core/services/identity/fusion.py apps/core/src/tuntun_core/services/identity/calibration.py tests/unit/identity/test_voice_liveness.py tests/unit/identity/test_fusion.py tests/security/test_biometric_authorization.py tests/security/test_voice_replay_attacks.py tests/acceptance/test_voice_calibration.py && uv run mypy apps/core/src/tuntun_core/services/identity/voice_liveness.py apps/core/src/tuntun_core/adapters/identity/digit_onnx.py apps/core/src/tuntun_core/services/identity/fusion.py apps/core/src/tuntun_core/services/identity/calibration.py`
Expected: PASS with exit code 0.

```bash
git add apps/core/src/tuntun_core/services/identity/voice_liveness.py apps/core/src/tuntun_core/adapters/identity/digit_onnx.py apps/core/src/tuntun_core/services/identity/fusion.py apps/core/src/tuntun_core/services/identity/calibration.py tests/unit/identity/test_voice_liveness.py tests/unit/identity/test_fusion.py tests/security/test_biometric_authorization.py tests/security/test_voice_replay_attacks.py tests/acceptance/test_voice_calibration.py
git diff --cached --name-only
git diff --cached
git commit -m "feat(identity): fuse evidence with liveness gates"
```

### Task 6: Implement the default-deny policy engine and PIN challenges

**Master coverage:** first half of Task 20
**Depends on:** Tasks 1–5 and master Task 06
**Estimated effort:** 3 person-days

**Files:**
- Create: `apps/core/src/tuntun_core/services/policy/action_registry.py`
- Create: `apps/core/src/tuntun_core/services/policy/risk_classifier.py`
- Create: `apps/core/src/tuntun_core/services/policy/engine.py`
- Create: `apps/core/src/tuntun_core/services/auth/pin.py`
- Create: `apps/core/src/tuntun_core/services/auth/confirmation.py`
- Create: `apps/core/src/tuntun_core/services/auth/sessions.py`
- Create: `apps/core/src/tuntun_core/services/identity/current_owner.py`
- Create: `config/policies/default.yaml`
- Create: `apps/core/migrations/versions/0003_authentication.py`
- Create: `tests/unit/policy/test_risk_matrix.py`
- Create: `tests/security/test_auth_replay.py`
- Create: `tests/security/test_auth_rate_limit.py`
- Create: `tests/security/test_confirmation_binding.py`
- Create: `tests/security/test_child_permissions.py`
- Create: `tests/security/test_policy_default_deny.py`
- Create: `tests/security/test_current_owner_authority.py`

**Interfaces:**
- Consumes: a verified `IdentityDecision` only to set `PolicyRequest.assurance=AssuranceLevel.IDENTIFIED`, the server-loaded active profile class, immutable action registry rules with a non-empty closed `allowed_profile_classes`, `AsyncUnitOfWork`, and foundation `AsyncAuditLedger`. Identity never creates an `AuthGrant`, `AuthContext`, grant ID, or `confirmed` assurance.
- Produces: `PolicyEnginePort.decide`; `CurrentOwnerAuthorityPort` backed by the canonical `current_owner_authority` pointer plus active profile and exact admin-session row; a single-use explicit confirmation grant with age at most 60 seconds; Argon2id PIN credentials; action-bound challenge/grant with three-failure persistent lockout, PIN age at most 300 seconds, and atomic grant consumption; migration `0003` also owns the encrypted/authenticated action proposal/claim/receipt tables consumed by Task 8 so their restart-safe schema is created once. Owner-only action rules deny every non-owner class before assurance is considered.

- [ ] **Step 1: Write failing decision-table and replay tests**

```python
# tests/unit/policy/test_risk_matrix.py
import pytest

@pytest.mark.parametrize(("action", "assurance", "effect", "required_assurance"), [
    ("timer.create", "identified", "step_up", "confirmed"),
    ("timer.create", "confirmed", "allow", None),
    ("memory.approve", "identified", "step_up", "pin_verified"),
    ("identity.enroll", "pin_verified", "step_up", "passkey_verified"),
    ("profile.delete", "pin_verified", "step_up", "passkey_verified"),
    ("security.finding.suppress", "pin_verified", "step_up", "passkey_verified"),
    ("release.latency.accept", "pin_verified", "step_up", "passkey_verified"),
    ("release.family_stage.review", "pin_verified", "step_up", "passkey_verified"),
    ("unknown.action", "passkey_verified", "deny", None),
])
@pytest.mark.asyncio
async def test_registered_risk_matrix(policy_engine, request_factory, action, assurance, effect, required_assurance):
    decision = await policy_engine.decide(request_factory(action=action, assurance=assurance))
    assert decision.effect.value == effect
    assert (decision.required_assurance.value if decision.required_assurance else None) == required_assurance

@pytest.mark.parametrize("action", ["privacy.on", "mute", "stop"])
@pytest.mark.asyncio
async def test_preemptive_privacy_actions_allow_guest_without_grant(policy_engine, request_factory, action):
    decision = await policy_engine.decide(request_factory(action=action, assurance="guest"))
    assert decision.effect.value == "allow" and decision.required_assurance is None

@pytest.mark.parametrize("action", ["timer.status", "system.status", "reachy.status"])
@pytest.mark.asyncio
async def test_read_only_queries_never_request_action_grant(policy_engine, request_factory, action):
    decision = await policy_engine.decide(request_factory(action=action, assurance="guest"))
    assert decision.effect.value in {"allow", "deny"} and decision.required_assurance is None

@pytest.mark.asyncio
@pytest.mark.parametrize("forged_assurance", ["confirmed", "pin_verified", "passkey_verified", "recovery_verified"])
async def test_guest_cannot_mutate_even_with_forged_strong_assurance(policy_engine, guest_request_factory, forged_assurance):
    decision = await policy_engine.decide(guest_request_factory(action="timer.create", assurance=forged_assurance))
    assert decision.effect.value == "deny" and decision.reason_code == "guest_mutation_denied"


@pytest.mark.parametrize("profile_class", ["k2", "n1"])
@pytest.mark.asyncio
async def test_both_child_classes_are_resolved_authoritatively_before_policy(policy_engine, request_factory, policy_profile_factory, profile_class):
    child = await policy_profile_factory(profile_class)
    request = request_factory(action="profile.delete", assurance="passkey_verified", subject_id=child.id, household_id=child.household_id)
    decision = await policy_engine.decide(request)
    assert decision.effect.value == "deny" and decision.reason_code == "owner_profile_required"


@pytest.mark.asyncio
@pytest.mark.parametrize("profile_class", ["adult", "k2", "n1", "guest"])
async def test_owner_only_action_denies_non_owner_before_forged_assurance(
    policy_engine, action_registry, request_factory, policy_profile_factory, profile_class
):
    principal = await policy_profile_factory(profile_class)
    owner_actions = tuple(
        name for name in action_registry.names()
        if {item.value for item in action_registry.get(name).allowed_profile_classes} == {"owner"}
    )
    assert owner_actions
    for owner_action in owner_actions:
        request = request_factory(
            action=owner_action,
            assurance="passkey_verified",
            subject_id=principal.id,
            household_id=principal.household_id,
        )
        decision = await policy_engine.decide(request)
        assert decision.effect.value == "deny"
        assert decision.reason_code == "owner_profile_required"
        assert decision.required_assurance is None

EXPECTED_ACTIONS = frozenset({
    "privacy.on", "mute", "stop", "privacy.off", "mute.off",
    "timer.create", "timer.cancel", "timer.status", "system.status", "reachy.status",
    "reachy.gesture_test", "offline.prompt_test",
    "memory.propose", "memory.approve", "memory.edit_approve", "memory.reject", "memory.expire", "memory.delete", "memory.export",
    "identity.enroll", "identity.enrollment.cancel",
    "profile.create", "profile.edit", "profile.revoke", "profile.delete", "profile.export",
    "consent.grant", "consent.revoke", "provider.review", "provider.configure", "budget.change", "access.change",
    "search.profile_mode.change", "search.experimental.activate",
    "credential.passkey.add", "credential.passkey.revoke", "credential.pin.change", "credential.recovery.rotate",
    "audit.export", "audit.verify", "backup.create", "backup.verify", "backup.recovery_key.create", "backup.restore",
    "release.p1r0", "release.latency.accept", "release.family_stage.review", "security.finding.suppress",
})

def test_action_registry_is_exact_and_has_closed_draft_adapter(action_registry):
    assert action_registry.names() == EXPECTED_ACTIONS
    assert all(action_registry.draft_adapter(name) is not None for name in EXPECTED_ACTIONS)
    assert all(action_registry.get(name).allowed_profile_classes for name in EXPECTED_ACTIONS)
    assert {item.value for item in action_registry.get("provider.configure").allowed_profile_classes} == {"owner"}
```

```python
# tests/integration/storage/test_migrations.py
def test_action_receipt_idempotency_matches_proposal_scope(migrated_sqlcipher_engine):
    with migrated_sqlcipher_engine.connect() as connection:
        receipt_uniques, proposal_uniques = connection.run_sync(lambda sync: (
            sa.inspect(sync).get_unique_constraints("action_receipts"),
            sa.inspect(sync).get_unique_constraints("action_proposals"),
        ))
    scoped = ("household_id", "action_name", "resource_scope", "idempotency_key")
    assert {tuple(item["column_names"]) for item in receipt_uniques} == {
        ("proposal_id",),
        scoped,
    }
    assert {tuple(item["column_names"]) for item in proposal_uniques} == {scoped}
    assert all(item["column_names"] != ["idempotency_key"] for item in receipt_uniques)
```

```python
# tests/security/test_current_owner_authority.py
import pytest


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    ["session_revoked", "session_version_changed", "idle_expired", "absolute_expired",
     "owner_replaced", "owner_generation_changed", "profile_version_changed", "owner_revoked"],
)
async def test_admin_principal_requires_current_session_and_owner_snapshot(
    current_owner_authority, owner_principal_scenario, change
):
    principal = await owner_principal_scenario.issue_then(change)
    async with owner_principal_scenario.uow() as uow:
        with pytest.raises(PermissionError, match="current_owner_authority_required|admin_session_not_current"):
            await current_owner_authority.require_admin_principal_in_uow(
                uow, principal, owner_principal_scenario.now
            )


@pytest.mark.asyncio
async def test_historical_owner_role_row_is_not_current_authority(
    current_owner_authority, historical_owner, current_owner, uow, now
):
    with pytest.raises(PermissionError, match="current_owner_authority_required"):
        await current_owner_authority.require_current_in_uow(
            uow,
            historical_owner.household_id,
            historical_owner.id,
            historical_owner.owner_generation,
            historical_owner.version,
            now,
        )
```

```python
# tests/security/test_confirmation_binding.py
import asyncio
import pytest


@pytest.mark.asyncio
async def test_confirmation_is_action_bound_and_single_use(confirmation_service, auth_noop_coordinator, timer_binding, other_binding):
    challenge = await confirmation_service.start(timer_binding)
    grant = await confirmation_service.confirm(challenge.challenge_id, response="yes")
    with pytest.raises(PermissionError, match="grant_binding_mismatch"):
        await auth_noop_coordinator.consume(grant.grant_id, other_binding)
    await auth_noop_coordinator.consume(grant.grant_id, timer_binding)
    with pytest.raises(PermissionError, match="grant_already_consumed"):
        await auth_noop_coordinator.consume(grant.grant_id, timer_binding)

@pytest.mark.asyncio
async def test_confirmation_challenge_cannot_mint_two_grants(confirmation_service, timer_binding):
    challenge = await confirmation_service.start(timer_binding)
    results = await asyncio.gather(confirmation_service.confirm(challenge.challenge_id, "yes"), confirmation_service.confirm(challenge.challenge_id, "yes"), return_exceptions=True)
    assert sum(not isinstance(item, Exception) for item in results) == 1
```

```python
# tests/security/test_auth_replay.py
import asyncio
import pytest

@pytest.mark.asyncio
async def test_pin_grant_is_bound_and_single_use(auth_service, auth_noop_coordinator, pin_response, binding):
    grant = await auth_service.verify(pin_response)
    await auth_noop_coordinator.consume(grant.grant_id, binding)
    with pytest.raises(PermissionError, match="grant_already_consumed"):
        await auth_noop_coordinator.consume(grant.grant_id, binding)

@pytest.mark.asyncio
async def test_pin_challenge_cannot_mint_two_grants(auth_service, pin_response):
    results = await asyncio.gather(auth_service.verify(pin_response), auth_service.verify(pin_response), return_exceptions=True)
    assert sum(not isinstance(item, Exception) for item in results) == 1

@pytest.mark.parametrize("field", ["household_id", "proposal_id", "turn_id", "idempotency_key", "action_name", "resource_type", "resource_id", "parameter_commitment", "policy_version", "session_id", "subject_id"])
@pytest.mark.asyncio
async def test_grant_rejects_every_changed_binding_claim(auth_noop_coordinator, grant, binding_variant_factory, field):
    changed = binding_variant_factory(field)
    with pytest.raises(PermissionError, match="grant_binding_mismatch"):
        await auth_noop_coordinator.consume(grant.grant_id, changed)
```

- [ ] **Step 2: Run red tests**

Run: `uv run pytest tests/unit/policy/test_risk_matrix.py tests/security/test_confirmation_binding.py tests/security/test_auth_replay.py tests/security/test_auth_rate_limit.py tests/security/test_child_permissions.py tests/security/test_policy_default_deny.py tests/security/test_current_owner_authority.py tests/integration/storage/test_migrations.py -q`
Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core.services.policy.engine'`.

- [ ] **Step 3: Implement the registry, engine, and PIN binding**

```yaml
# config/policies/default.yaml
version: "phase1-v1"
actions:
  privacy.on: {risk: personalization, assurance: guest, mode: preemptive, allowed_profiles: [guest, owner, adult, k2, n1]}
  mute: {risk: personalization, assurance: guest, mode: preemptive, allowed_profiles: [guest, owner, adult, k2, n1]}
  stop: {risk: personalization, assurance: guest, mode: preemptive, allowed_profiles: [guest, owner, adult, k2, n1]}
  privacy.off: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  mute.off: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  timer.create: {risk: low, assurance: confirmed, allowed_profiles: [owner, adult, k2, n1]}
  timer.cancel: {risk: low, assurance: confirmed, allowed_profiles: [owner, adult, k2, n1]}
  timer.status: {risk: personalization, assurance: guest, mode: read_only, allowed_profiles: [guest, owner, adult, k2, n1]}
  system.status: {risk: personalization, assurance: guest, mode: read_only, allowed_profiles: [guest, owner, adult, k2, n1]}
  reachy.status: {risk: personalization, assurance: guest, mode: read_only, allowed_profiles: [guest, owner, adult, k2, n1]}
  reachy.gesture_test: {risk: low, assurance: confirmed, allowed_profiles: [owner]}
  offline.prompt_test: {risk: low, assurance: confirmed, allowed_profiles: [owner]}
  memory.propose: {risk: low, assurance: confirmed, allowed_profiles: [owner, adult]}
  memory.approve: {risk: medium, assurance: pin_verified, allowed_profiles: [owner, adult]}
  memory.edit_approve: {risk: medium, assurance: pin_verified, allowed_profiles: [owner, adult]}
  memory.reject: {risk: medium, assurance: pin_verified, allowed_profiles: [owner, adult]}
  memory.expire: {risk: medium, assurance: pin_verified, allowed_profiles: [owner, adult]}
  memory.delete: {risk: high, assurance: passkey_verified, allowed_profiles: [owner, adult]}
  memory.export: {risk: high, assurance: passkey_verified, allowed_profiles: [owner, adult]}
  identity.enroll: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  identity.enrollment.cancel: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  profile.create: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  profile.edit: {risk: high, assurance: passkey_verified, allowed_profiles: [owner, adult]}
  profile.revoke: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  profile.delete: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  profile.export: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  consent.grant: {risk: high, assurance: passkey_verified, allowed_profiles: [owner, adult]}
  consent.revoke: {risk: high, assurance: passkey_verified, allowed_profiles: [owner, adult]}
  provider.review: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  provider.configure: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  budget.change: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  access.change: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  search.profile_mode.change: {risk: high, assurance: passkey_verified, allowed_profiles: [owner, adult]}
  search.experimental.activate: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  credential.passkey.add: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  credential.passkey.revoke: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  credential.pin.change: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  credential.recovery.rotate: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  audit.export: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  audit.verify: {risk: low, assurance: confirmed, allowed_profiles: [owner]}
  backup.create: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  backup.verify: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  backup.recovery_key.create: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  backup.restore: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  release.p1r0: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  release.latency.accept: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  release.family_stage.review: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
  security.finding.suppress: {risk: high, assurance: passkey_verified, allowed_profiles: [owner]}
```

```python
# apps/core/src/tuntun_core/services/policy/action_registry.py
from dataclasses import dataclass
from tuntun_contracts.policy import AssuranceLevel, RiskTier
from tuntun_core.domain.profile import ProfileClass

@dataclass(frozen=True)
class ActionRule:
    action_name: str; risk: RiskTier; assurance: AssuranceLevel; version: str
    allowed_profile_classes: frozenset[ProfileClass]
    mode: str="mutation"; schema_version: str="1.0"; maximum_uncertainty_micros: int=200_000

class ActionRegistry:
    def __init__(self, document, draft_adapters):
        self.version=document["version"]
        self._rules={
            name: ActionRule(
                name, RiskTier(row["risk"]), AssuranceLevel(row["assurance"]), self.version,
                frozenset(ProfileClass(value) for value in row["allowed_profiles"]),
                row.get("mode", "mutation"),
            )
            for name, row in document["actions"].items()
        }
        if any(not rule.allowed_profile_classes for rule in self._rules.values()):
            raise ValueError("action rule requires allowed profiles")
        self._draft_adapters=draft_adapters
        if set(self._draft_adapters) != set(self._rules):
            raise ValueError("action rules and closed draft adapters must have exact coverage")
    def get(self,name): return self._rules.get(name)
    def draft_adapter(self,name): return self._draft_adapters.get(name)
    def names(self): return frozenset(self._rules)
```

```python
# apps/core/src/tuntun_core/services/policy/risk_classifier.py
from tuntun_contracts.policy import RiskTier
RANK={RiskTier.PERSONALIZATION:0,RiskTier.LOW:1,RiskTier.MEDIUM:2,RiskTier.HIGH:3}
def effective_risk(registered:RiskTier,requested:RiskTier)->RiskTier:
    return registered if RANK[registered]>=RANK[requested] else requested
```

```python
# apps/core/src/tuntun_core/services/policy/engine.py
from datetime import timedelta
from dataclasses import dataclass
from tuntun_contracts.policy import AssuranceLevel, PolicyDecision, PolicyEffect
from tuntun_core.domain.profile import ProfileClass
@dataclass(frozen=True)
class RequiredFactor:
    assurance: str
    factor: str | None
RANK = {"guest": 0, "identified": 1, "confirmed": 2, "pin_verified": 3, "passkey_verified": 4, "recovery_verified": 5}
RISK_RANK = {"personalization": 0, "low": 1, "medium": 2, "high": 3}
FACTOR_FOR_RISK = {
    "personalization": RequiredFactor("identified", None),
    "low": RequiredFactor("confirmed", "confirm"),
    "medium": RequiredFactor("pin_verified", "pin"),
    "high": RequiredFactor("passkey_verified", "passkey"),
}
class PolicyEngine:
    def __init__(self, registry, profiles, clock):
        self._registry, self._profiles, self._clock = registry, profiles, clock

    async def decide(self, request):
        profile_class = await self._profiles.current_policy_class(request.household_id, request.subject_id)
        return self._decide(request, profile_class)

    async def decide_in_uow(self, uow, request):
        profile_class = await self._profiles.current_policy_class_in_uow(uow, request.household_id, request.subject_id)
        return self._decide(request, profile_class)

    def _decide(self, request, profile_class):
        rule = self._registry.get(request.action.action_name)
        expires_at = self._clock.now() + timedelta(seconds=60)
        if rule is None:
            return PolicyDecision(effect=PolicyEffect.DENY,reason_code="unknown_action",policy_version=self._registry.version,required_assurance=None,expires_at=expires_at)
        if profile_class not in rule.allowed_profile_classes:
            reason = "owner_profile_required" if rule.allowed_profile_classes == frozenset({ProfileClass.OWNER}) else "profile_class_not_allowed"
            return PolicyDecision(effect=PolicyEffect.DENY,reason_code=reason,policy_version=rule.version,required_assurance=None,expires_at=expires_at)
        if rule.mode == "preemptive":
            return PolicyDecision(effect=PolicyEffect.ALLOW,reason_code="preemptive_privacy_allow",policy_version=rule.version,required_assurance=None,expires_at=expires_at)
        if rule.mode == "read_only":
            allowed = RANK[request.assurance.value] >= RANK[rule.assurance.value]
            return PolicyDecision(effect=PolicyEffect.ALLOW if allowed else PolicyEffect.DENY,reason_code="read_only_allow" if allowed else "read_only_limited",policy_version=rule.version,required_assurance=None,expires_at=expires_at)
        if profile_class is ProfileClass.GUEST:
            return PolicyDecision(effect=PolicyEffect.DENY,reason_code="guest_mutation_denied",policy_version=rule.version,required_assurance=None,expires_at=expires_at)
        effective_risk = max(rule.risk.value, request.requested_risk.value, key=lambda value: RISK_RANK[value])
        risk_required = FACTOR_FOR_RISK[effective_risk]
        required_assurance = max((risk_required.assurance, rule.assurance.value), key=lambda value: RANK[value])
        required = RequiredFactor(required_assurance, risk_required.factor if RANK[risk_required.assurance] >= RANK[rule.assurance.value] else {"confirmed":"confirm","pin_verified":"pin","passkey_verified":"passkey","recovery_verified":"recovery"}.get(required_assurance))
        if RANK[request.assurance.value] < RANK[required.assurance]:
            return PolicyDecision(effect=PolicyEffect.STEP_UP,reason_code="insufficient_assurance",policy_version=rule.version,required_assurance=AssuranceLevel(required.assurance),expires_at=expires_at)
        return PolicyDecision(effect=PolicyEffect.ALLOW,reason_code="policy_allow",policy_version=rule.version,required_assurance=None,expires_at=expires_at)
```

```python
# apps/core/src/tuntun_core/services/auth/confirmation.py
from datetime import timedelta

class ConfirmationService:
    MAX_AGE_SECONDS = 60

    def __init__(self, uow_factory, audit_ledger, clock):
        self._uow_factory, self._audit, self._clock = uow_factory, audit_ledger, clock

    async def start(self, binding):
        async with self._uow_factory() as uow:
            challenge = await uow.auth_challenges.create(factor="confirmation", exact_binding=binding, expires_at=self._clock.now() + timedelta(seconds=self.MAX_AGE_SECONDS))
            await self._audit.append(uow, uow.auth_challenges.started_audit(challenge))
            await uow.commit()
            return challenge

    async def confirm(self, challenge_id, response):
        async with self._uow_factory() as uow:
            challenge = await uow.auth_challenges.lock_open(challenge_id, self._clock.now())
            if response not in {"yes", "हाँ", "haan"}:
                await uow.auth_challenges.consume_failed(challenge_id, "confirmation_rejected", self._clock.now())
                await self._audit.append(uow, uow.auth_challenges.failure_audit(challenge, "confirmation_rejected", self._clock.now()))
                await uow.commit()
                raise PermissionError("confirmation_rejected")
            await uow.auth_challenges.consume_success(challenge_id, self._clock.now())
            grant = await uow.auth_grants.issue(challenge, assurance="confirmed", assurance_source="explicit_confirmation", expires_at=challenge.expires_at)
            await self._audit.append(uow, uow.auth_grants.issued_audit(grant))
            await uow.commit()
            return grant

```

```python
# apps/core/src/tuntun_core/services/auth/pin.py
from datetime import timedelta
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

class PinVerifier:
    MAX_FAILURES = 3
    MAX_GRANT_AGE_SECONDS = 300

    def __init__(self, uow_factory, audit_ledger, clock, hasher=None):
        self._uow_factory, self._audit, self._clock = uow_factory, audit_ledger, clock
        self._hasher = hasher or PasswordHasher(memory_cost=65536, time_cost=3, parallelism=1)

    def _verify_outside_transaction(self, credential_hash, plaintext):
        try:
            self._hasher.verify(credential_hash, plaintext)
        except (VerificationError, InvalidHashError):
            return False, None
        replacement = self._hasher.hash(plaintext) if self._hasher.check_needs_rehash(credential_hash) else None
        return True, replacement

    async def verify(self, response):
        async with self._uow_factory() as read_uow:
            snapshot = await read_uow.auth_challenges.get_open_snapshot(response.challenge_id, response.occurred_at)
            rate_snapshot = await read_uow.auth_rate_limits.get(snapshot.subject_id, snapshot.source_bucket)
            credential_snapshot = await read_uow.auth_credentials.get_pin(snapshot.subject_id)
            if rate_snapshot.locked_until is not None and rate_snapshot.locked_until > response.occurred_at:
                raise PermissionError("challenge_locked")
            if snapshot.failures >= self.MAX_FAILURES:
                raise PermissionError("challenge_locked")

        # Argon2 verify and optional rehash are deliberately outside SQLCipher.
        valid, replacement_hash = self._verify_outside_transaction(credential_snapshot.hash, response.response)
        async with self._uow_factory() as uow:
            challenge = await uow.auth_challenges.lock_open(response.challenge_id, response.occurred_at)
            rate = await uow.auth_rate_limits.lock(challenge.subject_id, challenge.source_bucket)
            if rate.locked_until is not None and rate.locked_until > response.occurred_at:
                raise PermissionError("challenge_locked")
            if challenge.failures >= self.MAX_FAILURES:
                raise PermissionError("challenge_locked")
            credential = await uow.auth_credentials.get_pin(challenge.subject_id)
            if credential.hash != credential_snapshot.hash or challenge.snapshot_commitment != snapshot.snapshot_commitment:
                raise PermissionError("pin_challenge_or_credential_changed")
            if not valid:
                await uow.auth_challenges.record_failure(challenge.challenge_id, response.occurred_at)
                await uow.auth_rate_limits.record_failure(challenge.subject_id, challenge.source_bucket, response.occurred_at, lock_after=3)
                await self._audit.append(uow, uow.auth_challenges.failure_audit(challenge, "invalid_pin", response.occurred_at))
                await uow.commit()
                raise PermissionError("invalid_pin")
            if replacement_hash is not None:
                await uow.auth_credentials.replace_pin_hash(credential.id, replacement_hash)
            await uow.auth_rate_limits.clear(challenge.subject_id, challenge.source_bucket, response.occurred_at)
            await uow.auth_challenges.consume_success(challenge.challenge_id, response.occurred_at)
            grant = await uow.auth_grants.issue(challenge, assurance="pin_verified", assurance_source="pin", expires_at=self._clock.now() + timedelta(seconds=self.MAX_GRANT_AGE_SECONDS))
            await self._audit.append(uow, uow.auth_grants.issued_audit(grant))
            await uow.commit()
            return grant
```

```python
# apps/core/src/tuntun_core/services/identity/current_owner.py
import hmac
from datetime import datetime
from typing import Protocol
from uuid import UUID
from tuntun_contracts.policy import AdminSessionPrincipal, CurrentOwnerAuthority
from tuntun_core.domain.profile import ProfileClass
from tuntun_core.services.transactions.identity_uow import IdentityUnitOfWork

class CurrentOwnerAuthorityPort(Protocol):
    async def require_current_in_uow(self, uow: IdentityUnitOfWork, household_id: UUID, subject_id: UUID, owner_generation: int, profile_version: int, now: datetime) -> CurrentOwnerAuthority: raise NotImplementedError
    async def require_admin_principal_in_uow(self, uow: IdentityUnitOfWork, principal: AdminSessionPrincipal, now: datetime) -> CurrentOwnerAuthority: raise NotImplementedError

class CurrentOwnerAuthorityService(CurrentOwnerAuthorityPort):
    def __init__(self, binding_commitments):
        self._commitments = binding_commitments

    async def require_current_in_uow(self, uow, household_id, subject_id, owner_generation, profile_version, now):
        pointer = await uow.current_owner_authority.get_by_household(household_id)
        profile = await uow.profiles.get_scoped(household_id, subject_id)
        exact = (
            pointer.subject_id == subject_id and pointer.owner_generation == owner_generation
            and profile.profile_class is ProfileClass.OWNER and profile.active and profile.revoked_at is None
            and profile.version == profile_version
        )
        if not exact:
            raise PermissionError("current_owner_authority_required")
        return CurrentOwnerAuthority(household_id=household_id, subject_id=subject_id, owner_generation=owner_generation, profile_version=profile_version, observed_at=now)

    async def require_admin_principal_in_uow(self, uow, principal, now):
        session = await uow.admin_sessions.lock_by_id(principal.admin_session_id)
        supplied = self._commitments.admin_principal(principal)
        stored = self._commitments.admin_session_row(session)
        if not hmac.compare_digest(stored, supplied):
            raise PermissionError("admin_session_not_current")
        if session.revoked_at is not None or session.idle_expires_at <= now or session.absolute_expires_at <= now:
            raise PermissionError("admin_session_not_current")
        if session.session_version != principal.session_version:
            raise PermissionError("admin_session_not_current")
        return await self.require_current_in_uow(
            uow, principal.household_id, principal.subject_id,
            principal.owner_generation, principal.profile_version, now,
        )
```

The principal commitment covers the complete frozen principal, including access mode and every timestamp; the row mapper independently reconstructs those fields. `hmac.compare_digest` runs before any protected admin-domain read. Owner replacement increments `owner_generation`, revokes the old subject's credentials/sessions, and advances affected profile/session versions in the same transaction, so a historical owner row cannot remain authoritative.

```python
# apps/core/src/tuntun_core/services/auth/sessions.py
from tuntun_contracts.policy import AdminSessionPrincipal

class AuthSessionRepository:
    async def revoke_subject(self, subject_id, occurred_at):
        async with self._uow_factory() as uow:
            await uow.admin_sessions.revoke_subject(subject_id, occurred_at, increment_session_version=True)
            await uow.auth_challenges.cancel_subject(subject_id, occurred_at)
            await self._audit.append(uow, uow.admin_sessions.subject_revoked_audit(subject_id, occurred_at))
            await uow.commit()
```

`AdminSessionPrincipal` authenticates the console session only and deliberately has no `binding`, `assurance`, or mutation-authorizing conversion. Its `session_version` is the revocation/validity epoch: issuance, renewal, access-mode change, and revocation update it consistently; revocation also stores `revoked_at`, and every use compares the complete principal snapshot then independently requires `revoked_at IS NULL` and both expiries in the future. Every mutation independently derives the exact `ActionBinding` from the server-observed method/path/body/resource plus proposal/turn/idempotency context, then consumes a separate action-bound `AuthGrant` into `AuthContext`.

```python
# apps/core/migrations/versions/0003_authentication.py
from alembic import op
import sqlalchemy as sa

revision = "0003_authentication"
down_revision = "0002_profiles_consent_enrollment"

def upgrade() -> None:
    utc = "GLOB '????-??-??T??:??:??.??????Z'"
    op.create_table("auth_credentials", sa.Column("id", sa.String(36), primary_key=True), sa.Column("household_id", sa.String(36), sa.ForeignKey("households.id"), nullable=False), sa.Column("subject_id", sa.String(36), sa.ForeignKey("subjects.id"), nullable=False), sa.Column("factor", sa.String(16), nullable=False), sa.Column("capability", sa.String(32), nullable=False), sa.Column("owner_generation", sa.Integer), sa.Column("profile_version", sa.Integer, nullable=False), sa.Column("credential_version", sa.Integer, nullable=False), sa.Column("credential_id", sa.LargeBinary), sa.Column("public_key", sa.LargeBinary), sa.Column("secret_hash", sa.LargeBinary), sa.Column("transports_json", sa.Text), sa.Column("sign_count", sa.Integer), sa.Column("created_at", sa.String(27), nullable=False), sa.Column("used_at", sa.String(27)), sa.Column("revoked_at", sa.String(27)), sa.CheckConstraint("factor IN ('pin','passkey','recovery')"), sa.CheckConstraint("capability IN ('owner_admin','adult_self_consent','profile_persona')"), sa.CheckConstraint("profile_version >= 1 AND credential_version >= 1 AND (owner_generation IS NULL OR owner_generation >= 1)"), sa.CheckConstraint("(capability='owner_admin') = (owner_generation IS NOT NULL)"), sa.CheckConstraint("sign_count IS NULL OR sign_count >= 0"), sa.CheckConstraint("(factor='passkey' AND credential_id IS NOT NULL AND public_key IS NOT NULL AND secret_hash IS NULL) OR (factor IN ('pin','recovery') AND credential_id IS NULL AND public_key IS NULL AND secret_hash IS NOT NULL)"), sa.CheckConstraint(f"created_at {utc}"))
    op.create_table("auth_challenges", sa.Column("id", sa.String(36), primary_key=True), sa.Column("household_id", sa.String(36), nullable=False), sa.Column("proposal_id", sa.String(36), nullable=False), sa.Column("turn_id", sa.String(36), nullable=False), sa.Column("idempotency_key", sa.String(36), nullable=False), sa.Column("subject_id", sa.String(36), nullable=False), sa.Column("session_id", sa.String(36), nullable=False), sa.Column("source_bucket", sa.String(128), nullable=False), sa.Column("factor", sa.String(16), nullable=False), sa.Column("state", sa.String(16), nullable=False), sa.Column("action_name", sa.String(128), nullable=False), sa.Column("resource_type", sa.String(64), nullable=False), sa.Column("resource_id", sa.String(36)), sa.Column("parameter_commitment_key_id", sa.String(128), nullable=False), sa.Column("parameter_commitment_hmac", sa.LargeBinary, nullable=False), sa.Column("policy_version", sa.String(128), nullable=False), sa.Column("nonce_commitment", sa.LargeBinary, nullable=False), sa.Column("webauthn_challenge", sa.LargeBinary), sa.Column("snapshot_commitment_key_id", sa.String(128), nullable=False), sa.Column("snapshot_commitment_hmac", sa.LargeBinary, nullable=False), sa.Column("failures", sa.Integer, nullable=False), sa.Column("issued_at", sa.String(27), nullable=False), sa.Column("expires_at", sa.String(27), nullable=False), sa.Column("consumed_at", sa.String(27)), sa.CheckConstraint("factor IN ('confirmation','pin','passkey')"), sa.CheckConstraint("state IN ('open','succeeded','failed','expired')"), sa.CheckConstraint("failures BETWEEN 0 AND 3"), sa.CheckConstraint("(factor='passkey') = (webauthn_challenge IS NOT NULL)"), sa.CheckConstraint("(state='open' AND consumed_at IS NULL) OR (state!='open' AND consumed_at IS NOT NULL)"), sa.UniqueConstraint("proposal_id", "factor"))
    op.create_table("auth_grants", sa.Column("id", sa.String(36), primary_key=True), sa.Column("subject_id", sa.String(36), sa.ForeignKey("subjects.id"), nullable=False), sa.Column("subject_authority_generation", sa.Integer, nullable=False), sa.Column("assurance", sa.String(32), nullable=False), sa.Column("assurance_source", sa.String(32), nullable=False), sa.Column("binding_ciphertext", sa.LargeBinary, nullable=False), sa.Column("issued_at", sa.String(32), nullable=False), sa.Column("expires_at", sa.String(32), nullable=False), sa.Column("consumed_at", sa.String(32)), sa.CheckConstraint("subject_authority_generation >= 1"))
    op.create_table("credential_invitations", sa.Column("id", sa.String(36), primary_key=True), sa.Column("subject_id", sa.String(36), nullable=False), sa.Column("capability", sa.String(32), nullable=False), sa.Column("nonce_commitment", sa.LargeBinary, nullable=False), sa.Column("expires_at", sa.String(32), nullable=False), sa.Column("consumed_at", sa.String(32)), sa.CheckConstraint("capability IN ('adult_self_consent','profile_persona')"))
    op.create_table("local_presence_receipts", sa.Column("id", sa.String(36), primary_key=True), sa.Column("binding_commitment", sa.LargeBinary, nullable=False), sa.Column("purpose_id", sa.String(64), nullable=False), sa.Column("key_id", sa.String(128), nullable=False), sa.Column("signature", sa.LargeBinary, nullable=False), sa.Column("issued_at", sa.String(32), nullable=False), sa.Column("expires_at", sa.String(32), nullable=False), sa.Column("consumed_at", sa.String(32)))
    op.create_table("action_proposals", sa.Column("id", sa.String(36), primary_key=True), sa.Column("household_id", sa.String(36), sa.ForeignKey("households.id"), nullable=False), sa.Column("subject_id", sa.String(36)), sa.Column("subject_authority_generation", sa.Integer), sa.Column("session_id", sa.String(36), nullable=False), sa.Column("turn_id", sa.String(36), nullable=False), sa.Column("origin", sa.String(16), nullable=False), sa.Column("schema_version", sa.String(16), nullable=False), sa.Column("action_name", sa.String(128), nullable=False), sa.Column("resource_type", sa.String(64), nullable=False), sa.Column("resource_id", sa.String(36)), sa.Column("resource_scope", sa.String(64), nullable=False), sa.Column("draft_ciphertext", sa.LargeBinary, nullable=False), sa.Column("draft_nonce", sa.LargeBinary, nullable=False), sa.Column("wrapped_dek", sa.LargeBinary, nullable=False), sa.Column("root_key_id", sa.String(128), nullable=False), sa.Column("parameter_commitment_key_id", sa.String(128), nullable=False), sa.Column("parameter_commitment_hmac", sa.LargeBinary, nullable=False), sa.Column("draft_commitment_key_id", sa.String(128), nullable=False), sa.Column("draft_commitment_hmac", sa.LargeBinary, nullable=False), sa.Column("provenance_receipt_id", sa.String(36), nullable=False), sa.Column("provenance_commitment_key_id", sa.String(128), nullable=False), sa.Column("provenance_commitment_hmac", sa.LargeBinary, nullable=False), sa.Column("uncertainty_micros", sa.Integer, nullable=False), sa.Column("idempotency_key", sa.String(36), nullable=False), sa.Column("policy_version", sa.String(128), nullable=False), sa.Column("required_assurance", sa.String(32), nullable=False), sa.Column("status", sa.String(16), nullable=False), sa.Column("execution_receipt_id", sa.String(36)), sa.Column("created_at", sa.String(27), nullable=False), sa.Column("expires_at", sa.String(27), nullable=False), sa.CheckConstraint("origin IN ('provider','admin','local')"), sa.CheckConstraint("schema_version='1.0'"), sa.CheckConstraint("uncertainty_micros BETWEEN 0 AND 1000000"), sa.CheckConstraint("required_assurance IN ('guest','identified','confirmed','pin_verified','passkey_verified','recovery_verified')"), sa.CheckConstraint("status IN ('pending','executed','expired')"), sa.CheckConstraint("(subject_id IS NULL AND subject_authority_generation IS NULL) OR (subject_id IS NOT NULL AND subject_authority_generation >= 1)"), sa.CheckConstraint("(status='executed') = (execution_receipt_id IS NOT NULL)"), sa.UniqueConstraint("household_id", "action_name", "resource_scope", "idempotency_key", name="uq_action_proposal_scope"))
    op.create_table("action_receipts", sa.Column("id", sa.String(36), primary_key=True), sa.Column("proposal_id", sa.String(36), sa.ForeignKey("action_proposals.id"), nullable=False, unique=True), sa.Column("household_id", sa.String(36), sa.ForeignKey("households.id"), nullable=False), sa.Column("action_name", sa.String(128), nullable=False), sa.Column("resource_scope", sa.String(64), nullable=False), sa.Column("resource_id", sa.String(36)), sa.Column("idempotency_key", sa.String(36), nullable=False), sa.Column("outcome", sa.String(16), nullable=False), sa.Column("reason_code", sa.String(128), nullable=False), sa.Column("receipt_hmac_key_id", sa.String(128), nullable=False), sa.Column("receipt_hmac", sa.LargeBinary, nullable=False), sa.Column("occurred_at", sa.String(27), nullable=False), sa.CheckConstraint("outcome IN ('executed','denied','duplicate','failed')"), sa.UniqueConstraint("household_id", "action_name", "resource_scope", "idempotency_key", name="uq_action_receipt_scope"))
    op.create_table("action_execution_claims", sa.Column("id", sa.String(36), primary_key=True), sa.Column("proposal_id", sa.String(36), sa.ForeignKey("action_proposals.id"), nullable=False, unique=True), sa.Column("grant_id", sa.String(36), sa.ForeignKey("auth_grants.id"), nullable=False), sa.Column("provider_name", sa.String(128), nullable=False), sa.Column("state", sa.String(32), nullable=False), sa.Column("receipt_id", sa.String(36), sa.ForeignKey("action_receipts.id")), sa.Column("created_at", sa.String(27), nullable=False), sa.Column("sent_at", sa.String(27)), sa.Column("finished_at", sa.String(27)), sa.CheckConstraint("state IN ('pending','sent','succeeded','ambiguous','cancelled_subject_revoked','settled_subject_revoked')"), sa.CheckConstraint("(state='succeeded' AND receipt_id IS NOT NULL AND finished_at IS NOT NULL) OR (state!='succeeded' AND receipt_id IS NULL)"))
    op.create_table("admin_sessions", sa.Column("id_commitment", sa.LargeBinary, primary_key=True), sa.Column("admin_session_id", sa.String(36), nullable=False, unique=True), sa.Column("household_id", sa.String(36), sa.ForeignKey("households.id"), nullable=False), sa.Column("subject_id", sa.String(36), sa.ForeignKey("subjects.id"), nullable=False), sa.Column("owner_generation", sa.Integer, nullable=False), sa.Column("profile_version", sa.Integer, nullable=False), sa.Column("session_version", sa.Integer, nullable=False), sa.Column("access_mode", sa.String(16), nullable=False), sa.Column("authenticated_at", sa.String(27), nullable=False), sa.Column("idle_expires_at", sa.String(27), nullable=False), sa.Column("absolute_expires_at", sa.String(27), nullable=False), sa.Column("revoked_at", sa.String(27)), sa.CheckConstraint("owner_generation >= 1 AND profile_version >= 1 AND session_version >= 1"), sa.CheckConstraint("access_mode IN ('loopback','lan_https')"), sa.CheckConstraint(f"authenticated_at {utc} AND idle_expires_at {utc} AND absolute_expires_at {utc}"))
    op.create_table("auth_rate_limits", sa.Column("subject_id", sa.String(36), nullable=False), sa.Column("source_bucket", sa.String(128), nullable=False), sa.Column("failure_count", sa.Integer, nullable=False), sa.Column("window_started_at", sa.String(32), nullable=False), sa.Column("locked_until", sa.String(32)), sa.PrimaryKeyConstraint("subject_id", "source_bucket"))

def downgrade() -> None:
    op.drop_table("action_execution_claims")
    op.drop_table("action_receipts")
    op.drop_table("action_proposals")
    op.drop_table("auth_rate_limits")
    op.drop_table("admin_sessions")
    op.drop_table("local_presence_receipts")
    op.drop_table("credential_invitations")
    op.drop_table("auth_grants")
    op.drop_table("auth_challenges")
    op.drop_table("auth_credentials")
```

- [ ] **Step 4: Run green and migration tests**

Run: `uv run pytest tests/unit/policy/test_risk_matrix.py tests/security/test_confirmation_binding.py tests/security/test_auth_replay.py tests/security/test_auth_rate_limit.py tests/security/test_child_permissions.py tests/security/test_policy_default_deny.py tests/security/test_current_owner_authority.py tests/integration/storage/test_migrations.py -q`
Expected: PASS; unknown actions deny, the fourth PIN attempt remains locked across repository restart, and `0003_authentication` upgrades/downgrades cleanly.

- [ ] **Step 5: Check and commit**

Run: `uv run ruff format --check apps/core/src/tuntun_core/services/policy apps/core/src/tuntun_core/services/identity/current_owner.py apps/core/src/tuntun_core/services/auth/confirmation.py apps/core/src/tuntun_core/services/auth/pin.py apps/core/src/tuntun_core/services/auth/sessions.py tests/unit/policy/test_risk_matrix.py tests/security/test_confirmation_binding.py tests/security/test_auth_replay.py tests/security/test_auth_rate_limit.py tests/security/test_child_permissions.py tests/security/test_policy_default_deny.py tests/security/test_current_owner_authority.py && uv run ruff check apps/core/src/tuntun_core/services/policy apps/core/src/tuntun_core/services/identity/current_owner.py apps/core/src/tuntun_core/services/auth/confirmation.py apps/core/src/tuntun_core/services/auth/pin.py apps/core/src/tuntun_core/services/auth/sessions.py tests/unit/policy/test_risk_matrix.py tests/security/test_confirmation_binding.py tests/security/test_auth_replay.py tests/security/test_auth_rate_limit.py tests/security/test_child_permissions.py tests/security/test_policy_default_deny.py tests/security/test_current_owner_authority.py && uv run mypy apps/core/src/tuntun_core/services/policy apps/core/src/tuntun_core/services/identity/current_owner.py apps/core/src/tuntun_core/services/auth/confirmation.py apps/core/src/tuntun_core/services/auth/pin.py apps/core/src/tuntun_core/services/auth/sessions.py`
Expected: PASS with exit code 0.

```bash
git add apps/core/src/tuntun_core/services/policy/action_registry.py apps/core/src/tuntun_core/services/policy/risk_classifier.py apps/core/src/tuntun_core/services/policy/engine.py apps/core/src/tuntun_core/services/identity/current_owner.py apps/core/src/tuntun_core/services/auth/confirmation.py apps/core/src/tuntun_core/services/auth/pin.py apps/core/src/tuntun_core/services/auth/sessions.py config/policies/default.yaml apps/core/migrations/versions/0003_authentication.py tests/unit/policy/test_risk_matrix.py tests/security/test_confirmation_binding.py tests/security/test_auth_replay.py tests/security/test_auth_rate_limit.py tests/security/test_child_permissions.py tests/security/test_policy_default_deny.py tests/security/test_current_owner_authority.py tests/integration/storage/test_migrations.py
git diff --cached --name-only
git diff --cached
git commit -m "feat(policy): add default-deny policy and PIN step-up"
```

### Task 7: Add passkeys, recovery, and signed local presence

**Master coverage:** authentication portion of Task 20
**Depends on:** Task 6
**Estimated effort:** 3 person-days

**Files:**
- Create: `apps/core/src/tuntun_core/services/auth/passkey.py`
- Create: `apps/core/src/tuntun_core/services/auth/recovery.py`
- Create: `apps/core/src/tuntun_core/services/auth/local_presence.py`
- Create: `apps/core/src/tuntun_core/services/auth/service.py`
- Modify: `apps/core/pyproject.toml` (Argon2 and WebAuthn dependencies)
- Modify: `uv.lock` (resolved artifacts and hashes)
- Create: `tests/security/test_passkey_binding.py`
- Create: `tests/security/test_recovery.py`
- Create: `tests/security/test_local_presence.py`

**Interfaces:**
- Consumes: exact frozen `ActionBinding(household_id, proposal_id, turn_id, idempotency_key, action_name, resource_type, resource_id, parameter_commitment, policy_version, session_id, subject_id)`, `ActionBindingVerifierPort`, `CurrentOwnerAuthorityPort`, canonical active profile/current-primary-guardian state, WebAuthn RP/origin settings, Keychain signing key, local console session inspector.
- Produces: passkey grants valid for one action and no more than 120 seconds; the closed credential capabilities `owner_admin|adult_self_consent|profile_persona`; single-use recovery requiring PIN, unused recovery code, and local presence; local-presence receipts valid for 60 seconds and rejected for SSH/remote sessions. Every credential binds its household, subject, current profile version, credential version, and revocation state. An `owner_admin` credential additionally binds the exact owner generation, and verification revalidates the current-owner pointer before capability or protected target reads; revoked, wrong-household, wrong-subject, replaced-owner, stale-profile, or forged adult-owner credentials fail closed. Every other capability first requires its credential subject to remain current and active. `adult_self_consent` remains limited to own consent grant/revoke. `profile_persona` is limited to an exact `profile.edit` for the credential subject's own owner/adult profile or a current-primary-guardian-bound K2/N1 profile; it cannot authorize consent, administration, another adult, or a stale guardian relationship. The action binding commits the target profile, optimistic version, replace-versus-clear, and the complete typed traits. Persona replacement still requires current personalization consent in `ProfileService`, while an authority-valid clear remains available after that consent is revoked.

`AuthenticationService.start` persists the complete binding fields, fresh WebAuthn server challenge bytes for passkey factors, and a purpose-separated snapshot HMAC in `auth_challenges`. Verification performs WebAuthn outside SQLCipher, then re-locks that exact snapshot and consumes the challenge once before issuing any grant.

- [ ] **Step 1: Write failing passkey, recovery, and local-presence tests**

```python
# tests/security/test_passkey_binding.py
import asyncio
import pytest

@pytest.mark.asyncio
async def test_passkey_grant_rejects_changed_parameters(passkey_service, auth_noop_coordinator, verified_assertion, binding, different_commitment):
    grant = await passkey_service.verify(verified_assertion, binding)
    changed = binding.model_copy(update={"parameter_commitment": different_commitment})
    with pytest.raises(PermissionError, match="binding_mismatch"):
        await auth_noop_coordinator.consume(grant.grant_id, changed)

@pytest.mark.asyncio
async def test_webauthn_assertion_cannot_cross_prepared_binding(passkey_service, verified_assertion, passkey_challenge, other_binding):
    with pytest.raises(PermissionError, match="passkey_challenge_binding_mismatch"):
        await passkey_service.verify(verified_assertion.for_challenge(passkey_challenge.id), other_binding)

@pytest.mark.asyncio
async def test_webauthn_challenge_cannot_mint_two_grants(passkey_service, verified_assertion, binding):
    results = await asyncio.gather(passkey_service.verify(verified_assertion, binding), passkey_service.verify(verified_assertion, binding), return_exceptions=True)
    assert sum(not isinstance(item, Exception) for item in results) == 1

@pytest.mark.asyncio
async def test_owner_invitation_cannot_complete_adult_self_consent_registration(passkey_service, adult_invitation, owner_presence, adult):
    with pytest.raises(PermissionError, match="adult_subject_presence_required"):
        await passkey_service.register_adult_credential(adult_invitation.id, adult.id, owner_presence, capability="adult_self_consent")

def test_auth_migration_closes_credential_capabilities(auth_schema_checks):
    assert "capability IN ('owner_admin','adult_self_consent','profile_persona')" in auth_schema_checks["auth_credentials"]
    assert "capability IN ('adult_self_consent','profile_persona')" in auth_schema_checks["credential_invitations"]
    assert {"household_id", "subject_id", "owner_generation", "profile_version", "credential_version", "revoked_at"} <= auth_schema_checks.columns("auth_credentials")

@pytest.mark.asyncio
async def test_rp_mode_change_invalidates_old_scope(passkey_service, lan_assertion, localhost_settings, binding):
    with pytest.raises(PermissionError, match="passkey_origin_or_rp_mismatch"):
        await passkey_service.verify(lan_assertion, binding, settings=localhost_settings)

@pytest.mark.asyncio
async def test_adult_self_consent_credential_cannot_admin_other_subject(passkey_service, adult_assertion, other_subject_admin_binding):
    with pytest.raises(PermissionError, match="credential_capability_denied"):
        await passkey_service.verify(adult_assertion, other_subject_admin_binding)

@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["credential_revoked", "wrong_household", "wrong_subject", "owner_replaced", "owner_generation_stale", "profile_version_stale", "owner_profile_revoked"])
async def test_owner_admin_credential_requires_exact_current_owner_before_domain_read(passkey_service, owner_admin_scenario, change, protected_profile_repository_spy):
    assertion, binding = await owner_admin_scenario.issue_then(change)
    with pytest.raises(PermissionError, match="credential_not_current|current_owner_authority_required"):
        await passkey_service.verify(assertion, binding)
    assert protected_profile_repository_spy.target_read_count == 0

@pytest.mark.asyncio
async def test_adult_cannot_forge_owner_admin_capability(passkey_service, forged_adult_owner_admin_assertion, owner_action_binding, protected_profile_repository_spy):
    with pytest.raises(PermissionError, match="current_owner_authority_required"):
        await passkey_service.verify(forged_adult_owner_admin_assertion, owner_action_binding)
    assert protected_profile_repository_spy.target_read_count == 0

@pytest.mark.asyncio
@pytest.mark.parametrize("capability", ["adult_self_consent", "profile_persona"])
@pytest.mark.parametrize("change", ["inactive", "revoked", "profile_version_changed"])
async def test_non_owner_capability_requires_current_active_subject(passkey_service, changed_adult_assertion_factory, self_binding_factory, capability, change):
    assertion = changed_adult_assertion_factory(capability, change)
    with pytest.raises(PermissionError, match="credential_subject_not_current"):
        await passkey_service.verify(assertion, self_binding_factory(capability))

@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["replace", "clear"])
async def test_profile_persona_credential_mints_only_exact_self_edit(passkey_service, adult_profile_assertion, self_persona_binding_factory, operation):
    binding = self_persona_binding_factory(operation=operation)
    grant = await passkey_service.verify(adult_profile_assertion.for_binding(binding), binding)
    assert grant.binding == binding

@pytest.mark.asyncio
@pytest.mark.parametrize("profile_class", ["k2", "n1"])
async def test_current_guardian_profile_persona_credential_can_bind_child_edit(passkey_service, guardian_profile_assertion, child_persona_binding_factory, profile_class):
    binding = child_persona_binding_factory(profile_class=profile_class, current_guardian=True)
    assert (await passkey_service.verify(guardian_profile_assertion.for_binding(binding), binding)).binding == binding

@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["other_adult", "stale_guardian", "changed_target", "changed_commitment", "consent_action"])
async def test_profile_persona_capability_fails_closed(passkey_service, profile_persona_denial_case, case):
    assertion, binding = profile_persona_denial_case(case)
    with pytest.raises(PermissionError, match="credential_capability_denied|passkey_challenge_binding_mismatch"):
        await passkey_service.verify(assertion, binding)

@pytest.mark.asyncio
async def test_adult_self_consent_capability_cannot_edit_persona(passkey_service, adult_consent_assertion, self_persona_binding):
    with pytest.raises(PermissionError, match="credential_capability_denied"):
        await passkey_service.verify(adult_consent_assertion.for_binding(self_persona_binding), self_persona_binding)

@pytest.mark.asyncio
async def test_profile_persona_clear_grant_survives_personalization_consent_revocation(passkey_service, revoked_personalization_subject, profile_clear_assertion, profile_clear_binding):
    grant = await passkey_service.verify(profile_clear_assertion, profile_clear_binding)
    assert grant.binding == profile_clear_binding and grant.subject_id == revoked_personalization_subject.id

@pytest.mark.asyncio
async def test_consume_requires_caller_owned_atomic_scope(authentication, passkey_grant):
    with pytest.raises(RuntimeError, match="atomic_mutation_scope_required"):
        await authentication.consume(passkey_grant.id, passkey_grant.binding)

@pytest.mark.asyncio
async def test_consume_in_uow_does_not_commit_and_rolls_back(authentication, mutation_scope, passkey_grant, auth_grants, audit_rows):
    with pytest.raises(RuntimeError, match="force_rollback"):
        async with mutation_scope.open() as uow:
            await authentication.consume_in_uow(uow, passkey_grant.id, passkey_grant.binding)
            raise RuntimeError("force_rollback")
    assert await auth_grants.is_consumed(passkey_grant.id) is False
    assert await audit_rows.authorization_for(passkey_grant.id) is None

@pytest.mark.asyncio
async def test_frozen_verify_response_dispatches_passkey_with_server_stored_binding(authentication, passkey_response, auth_challenge_repository_spy, passkey_service_spy):
    grant = await authentication.verify(passkey_response)
    assert passkey_service_spy.calls == ((passkey_response.response, auth_challenge_repository_spy.binding),)
    assert grant.binding == auth_challenge_repository_spy.binding

@pytest.mark.asyncio
async def test_confirmation_adapter_uses_challenge_id_and_text(authentication, confirmation_response, confirmation_service_spy):
    await authentication.verify(confirmation_response)
    assert confirmation_service_spy.calls == ((confirmation_response.challenge_id, confirmation_response.response),)

@pytest.mark.asyncio
async def test_recovery_is_not_a_generic_authentication_challenge(authentication, recovery_authentication_request):
    with pytest.raises(PermissionError, match="recovery_separate_ceremony_required"):
        await authentication.start(recovery_authentication_request)
```

```python
# tests/security/test_local_presence.py
import pytest

@pytest.mark.asyncio
async def test_ssh_session_cannot_create_local_presence(local_presence, ssh_console, binding):
    with pytest.raises(PermissionError, match="interactive_local_console_required"):
        await local_presence.issue(ssh_console, binding)
```

```python
# tests/security/test_recovery.py
import pytest

@pytest.mark.asyncio
async def test_recovery_code_is_single_use(recovery, pin_grant, code, local_presence_receipt, binding):
    await recovery.consume(pin_grant.id, code, local_presence_receipt, binding)
    with pytest.raises(PermissionError, match="recovery_code_consumed"):
        await recovery.consume(pin_grant.id, code, local_presence_receipt, binding)
```

- [ ] **Step 2: Run red tests**

Run: `uv run pytest tests/security/test_passkey_binding.py tests/security/test_recovery.py tests/security/test_local_presence.py -q`
Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core.services.auth.passkey'`.

- [ ] **Step 3: Implement exact binding and factor composition**

```python
# apps/core/src/tuntun_core/services/auth/passkey.py
import hmac
from datetime import timedelta
from tuntun_core.domain.profile import ProfileClass

ADULT_PROFILE_CLASSES = frozenset({ProfileClass.OWNER, ProfileClass.ADULT})
CHILD_PROFILE_CLASSES = frozenset({ProfileClass.K2, ProfileClass.N1})

class PasskeyService:
    MAX_AGE_SECONDS = 120

    def __init__(self, webauthn_backend, uow_factory, mutation_scope, binding_factory, binding_verifier, profiles, current_owner, audit_ledger, clock, settings):
        self._backend, self._uow_factory, self._audit = webauthn_backend, uow_factory, audit_ledger
        self._scope, self._bindings, self._binding_verifier = mutation_scope, binding_factory, binding_verifier
        self._profiles, self._current_owner, self._clock, self._settings = profiles, current_owner, clock, settings

    async def verify(self, assertion, binding, settings=None):
        expected = (settings or self._settings).webauthn_scope()
        async with self._uow_factory() as preflight:
            snapshot = await preflight.auth_challenges.require_open(assertion.challenge_id, self._clock.now())
            if snapshot.factor != "passkey": raise PermissionError("passkey_challenge_binding_mismatch")
            self._binding_verifier.require_exact(snapshot.binding, binding)
        try:
            result = self._backend.verify(assertion, expected_challenge=snapshot.webauthn_challenge, expected_origin=expected.origin, expected_rp_id=expected.rp_id)
        except ValueError as exc:
            raise PermissionError("passkey_origin_or_rp_mismatch") from exc
        async with self._uow_factory() as uow:
            challenge = await uow.auth_challenges.lock_open(assertion.challenge_id, self._clock.now())
            if challenge.factor != "passkey" or not hmac.compare_digest(challenge.webauthn_challenge, snapshot.webauthn_challenge) or not hmac.compare_digest(challenge.snapshot_commitment, snapshot.snapshot_commitment):
                raise PermissionError("passkey_challenge_binding_mismatch")
            self._binding_verifier.require_exact(challenge.binding, binding)
            credential = await uow.auth_credentials.lock(result.credential_id)
            if credential.revoked_at is not None or credential.household_id != binding.household_id or credential.subject_id != binding.subject_id:
                raise PermissionError("credential_not_current")
            try:
                actor = await self._profiles.require_current_active_in_uow(uow, binding.household_id, credential.subject_id)
            except PermissionError as exc:
                raise PermissionError("credential_subject_not_current") from exc
            if actor.version != credential.profile_version:
                reason = "credential_not_current" if credential.capability == "owner_admin" else "credential_subject_not_current"
                raise PermissionError(reason)
            if credential.capability == "owner_admin":
                await self._current_owner.require_current_in_uow(
                    uow, binding.household_id, credential.subject_id,
                    credential.owner_generation, credential.profile_version, self._clock.now(),
                )
            if result.sign_count < credential.sign_count or (credential.sign_count != 0 and result.sign_count == credential.sign_count):
                raise PermissionError("passkey_counter_regression")
            if credential.capability == "adult_self_consent" and (binding.action_name not in {"consent.grant", "consent.revoke"} or binding.subject_id != credential.subject_id):
                raise PermissionError("credential_capability_denied")
            if credential.capability == "profile_persona":
                if binding.action_name != "profile.edit" or binding.resource_type != "profile" or binding.resource_id is None or binding.subject_id != credential.subject_id:
                    raise PermissionError("credential_capability_denied")
                target = await uow.profiles.get_scoped(binding.household_id, binding.resource_id)
                self_edit = target.id == credential.subject_id and target.profile_class in ADULT_PROFILE_CLASSES
                guardian_edit = target.profile_class in CHILD_PROFILE_CLASSES and await uow.profiles.is_current_primary_guardian(credential.subject_id, target.id)
                if not (self_edit or guardian_edit):
                    raise PermissionError("credential_capability_denied")
            await uow.auth_credentials.update_counter(credential.id, result.sign_count)
            await uow.auth_challenges.consume_success(challenge.id, self._clock.now())
            grant = await uow.auth_grants.issue(assurance="passkey_verified", assurance_source="passkey", binding=binding, expires_at=self._clock.now() + timedelta(seconds=self.MAX_AGE_SECONDS), single_use=True)
            await self._audit.append(uow, uow.auth_grants.issued_audit(grant))
            await uow.commit()
            return grant

    async def create_adult_invitation(self, owner_auth, adult_subject_id, capability):
        if capability not in {"adult_self_consent", "profile_persona"}:
            raise PermissionError("credential_capability_denied")
        expected = self._bindings.adult_credential_invitation(owner_auth.subject_id, adult_subject_id, capability)
        if owner_auth.assurance_source != "passkey":
            raise PermissionError("owner_passkey_invitation_required")
        try:
            self._binding_verifier.require_exact(owner_auth.binding, expected)
        except PermissionError as exc:
            raise PermissionError("owner_passkey_invitation_required") from exc
        uow = self._scope.require_active_uow()
        invitation = await uow.credential_invitations.create(subject_id=adult_subject_id, capability=capability, expires_at=self._clock.now() + timedelta(minutes=10), single_use=True)
        await self._audit.append(uow, uow.credential_invitations.created_audit(invitation, owner_auth))
        return invitation

    async def register_adult_credential(self, invitation_id, subject_id, physical_presence, capability):
        if physical_presence.subject_id != subject_id or not physical_presence.verified_local_console:
            raise PermissionError("adult_subject_presence_required")
        registration = self._backend.verify_registration(physical_presence.registration_response, expected_origin=self._settings.webauthn_scope().origin, expected_rp_id=self._settings.webauthn_scope().rp_id)
        async with self._uow_factory() as uow:
            invitation = await uow.credential_invitations.lock(invitation_id)
            if invitation.consumed_at is not None or invitation.expires_at <= self._clock.now() or invitation.subject_id != subject_id or capability != invitation.capability:
                raise PermissionError("invitation_invalid_or_replayed")
            profile = await self._profiles.require_current_active_in_uow(uow, invitation.household_id, subject_id)
            credential = await uow.auth_credentials.add_passkey(household_id=invitation.household_id, subject_id=subject_id, capability=capability, owner_generation=None, profile_version=profile.version, credential_version=1, credential_id=registration.credential_id, public_key=registration.credential_public_key, sign_count=registration.sign_count, transports=registration.transports)
            await uow.credential_invitations.consume(invitation_id, self._clock.now())
            await self._audit.append(uow, uow.auth_credentials.registered_audit(credential))
            await uow.commit()
            return credential

```

Owner-passkey registration uses the same repository method but must first call `CurrentOwnerAuthorityPort.require_current_in_uow` and persist its exact `household_id`, `subject_id`, `owner_generation`, and `profile_version`; it never accepts any of those epochs from a registration response or browser body. Credential revocation increments `credential_version` and sets `revoked_at`. Owner replacement revokes all historical-owner credentials and sessions transactionally, but the generation/profile checks remain mandatory defense in depth.

```python
# apps/core/src/tuntun_core/services/auth/local_presence.py
from datetime import datetime, timedelta
from uuid import UUID
from typing import Annotated
from pydantic import BaseModel, ConfigDict, Field, field_validator
import rfc8785
from tuntun_contracts.actions import ActionBinding

class LocalPresencePayload(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    binding: ActionBinding
    issued_at: datetime
    expires_at: datetime
    nonce: bytes

class LocalPresenceReceipt(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    receipt_id: UUID
    payload: LocalPresencePayload
    purpose_id: str
    key_id: str
    signature: bytes
    single_use: bool

class LocalPresenceService:
    def __init__(self, keychain, nonce, uow_factory, audit_ledger, clock, key_id="tuntun-local-presence-v1"):
        self._keychain, self._nonce, self._uow_factory, self._audit, self._clock, self._key_id = keychain, nonce, uow_factory, audit_ledger, clock, key_id

    async def issue(self, console, binding):
        if not console.interactive or console.remote or console.ssh_connection:
            raise PermissionError("interactive_local_console_required")
        if not await console.verify_os_user():
            raise PermissionError("os_authentication_failed")
        issued_at = self._clock.now()
        body = LocalPresencePayload(binding=binding, issued_at=issued_at, expires_at=issued_at + timedelta(seconds=60), nonce=self._nonce.random())
        purpose_id = "tuntun.local-presence.v1"
        canonical = rfc8785.dumps(body.model_dump(mode="json"))
        signature = await self._keychain.sign(self._key_id, purpose_id.encode("ascii") + b"\x00" + canonical)
        receipt = LocalPresenceReceipt(receipt_id=self._nonce.uuid4(), payload=body, purpose_id=purpose_id, key_id=self._key_id, signature=signature, single_use=True)
        async with self._uow_factory() as uow:
            await uow.local_presence_receipts.insert(receipt)
            await self._audit.append(uow, receipt.issued_audit())
            await uow.commit()
        return receipt

    async def verify(self, receipt, binding, now):
        if receipt.payload.binding != binding or receipt.payload.expires_at <= now:
            raise PermissionError("current_presence_binding_required")
        canonical = rfc8785.dumps(receipt.payload.model_dump(mode="json"))
        signed = receipt.purpose_id.encode("ascii") + b"\x00" + canonical
        if receipt.purpose_id != "tuntun.local-presence.v1" or not await self._keychain.verify(receipt.key_id, signed, receipt.signature):
            raise PermissionError("local_presence_signature_invalid")
        return receipt

    async def consume_verified_in_uow(self, uow, receipt, now):
        await uow.local_presence_receipts.consume_exactly_once(receipt.receipt_id, now)
        await self._audit.append(uow, receipt.consumed_audit(now))
```

```python
# apps/core/src/tuntun_core/services/auth/recovery.py
from datetime import timedelta
from argon2.exceptions import InvalidHashError, VerificationError
from tuntun_contracts.policy import AssuranceLevel

class RecoveryService:
    def __init__(self, uow_factory, mutation_scope, authentication, presence, hasher, audit_ledger, clock):
        self._uow_factory = uow_factory
        self._scope, self._authentication, self._presence = mutation_scope, authentication, presence
        self._hasher, self._audit, self._clock = hasher, audit_ledger, clock

    def _verify_code_outside_transaction(self, credential_hash, plaintext_code):
        try:
            return bool(self._hasher.verify(credential_hash, plaintext_code))
        except (VerificationError, InvalidHashError):
            return False

    async def consume(self, pin_grant_id, plaintext_code, presence, binding):
        if binding.subject_id is None:
            raise PermissionError("recovery_subject_required")
        now = self._clock.now()
        async with self._uow_factory() as read_uow:
            pin_snapshot = await read_uow.auth_grants.get_open_snapshot(pin_grant_id, binding, now)
            if pin_snapshot.assurance is not AssuranceLevel.PIN_VERIFIED:
                raise PermissionError("pin_binding_required")
            code_snapshot = await read_uow.recovery_codes.get_current_snapshot(binding.subject_id)
            if code_snapshot.consumed_at is not None:
                raise PermissionError("recovery_code_consumed_or_invalid")
        if not self._verify_code_outside_transaction(code_snapshot.hash, plaintext_code):
            raise PermissionError("recovery_code_consumed_or_invalid")
        verified_presence = await self._presence.verify(presence, binding, self._clock.now())
        async with self._scope.open() as uow:
            pin_auth = await self._authentication.consume_in_uow(uow, pin_grant_id, binding)
            if pin_auth.assurance is not AssuranceLevel.PIN_VERIFIED: raise PermissionError("pin_binding_required")
            await self._presence.consume_verified_in_uow(uow, verified_presence, self._clock.now())
            record = await uow.recovery_codes.lock_by_subject(binding.subject_id)
            if record.consumed_at is not None or record.snapshot_commitment != code_snapshot.snapshot_commitment:
                raise PermissionError("recovery_code_consumed_or_invalid")
            await uow.recovery_codes.consume(record.id, self._clock.now())
            grant = await uow.auth_grants.issue(assurance="recovery_verified", assurance_source="recovery", binding=binding, expires_at=self._clock.now() + timedelta(seconds=120), single_use=True)
            await self._audit.append(uow, record.consumed_audit(pin_auth, verified_presence, self._clock.now()))
            await self._audit.append(uow, grant.issued_audit())
            await uow.commit()
            return grant
```

```python
# apps/core/src/tuntun_core/services/auth/service.py
from tuntun_contracts.base import parse_contract_json
from tuntun_contracts.policy import AuthContext

class AuthenticationResponseAdapter(Protocol):
    async def verify_response(self, response): raise NotImplementedError

class ConfirmationResponseAdapter:
    def __init__(self, confirmation): self._confirmation = confirmation
    async def verify_response(self, response):
        return await self._confirmation.confirm(response.challenge_id, response.response)

class PinResponseAdapter:
    def __init__(self, pin): self._pin = pin
    async def verify_response(self, response):
        return await self._pin.verify(response)

class PasskeyResponseAdapter:
    def __init__(self, uow_factory, passkeys, clock):
        self._uow_factory, self._passkeys, self._clock = uow_factory, passkeys, clock
    async def verify_response(self, response):
        raw=response.response
        if not isinstance(raw,(str,bytes)):
            raise PermissionError("passkey_response_encoding_invalid")
        assertion=parse_contract_json(
            PasskeyAssertion,raw.encode("utf-8") if isinstance(raw,str) else raw,
            max_bytes=65_536,require_canonical=False,
        )
        if assertion.challenge_id != response.challenge_id:
            raise PermissionError("passkey_response_challenge_mismatch")
        async with self._uow_factory() as uow:
            snapshot = await uow.auth_challenges.require_open(response.challenge_id, self._clock.now())
            if snapshot.factor != "passkey":
                raise PermissionError("authentication_factor_mismatch")
        return await self._passkeys.verify(assertion, snapshot.binding)

class AuthenticationService:
    def __init__(self, uow_factory, mutation_scope, response_adapters, binding_verifier, audit_ledger, clock):
        self._uow_factory, self._scope, self._response_adapters = uow_factory, mutation_scope, response_adapters
        self._binding_verifier, self._audit, self._clock = binding_verifier, audit_ledger, clock

    async def start(self, request):
        if request.requested_assurance is AssuranceLevel.RECOVERY_VERIFIED:
            raise PermissionError("recovery_separate_ceremony_required")
        async with self._uow_factory() as uow:
            challenge = await uow.auth_challenges.create_from_request(request)
            await self._audit.append(uow, uow.auth_challenges.started_audit(challenge))
            await uow.commit()
            return challenge

    async def verify(self, response):
        async with self._uow_factory() as uow:
            factor = await uow.auth_challenges.factor_for_open(response.challenge_id, response.occurred_at)
        adapter = self._response_adapters.get(factor)
        if adapter is None:
            raise PermissionError("authentication_factor_not_registered")
        return await adapter.verify_response(response)

    async def consume(self, grant_id, binding):
        uow = self._scope.require_active_uow()  # raises atomic_mutation_scope_required
        return await self.consume_in_uow(uow, grant_id, binding)

    async def consume_in_uow(self, uow, grant_id, binding):
        now = self._clock.now()
        grant = await uow.auth_grants.lock_open(grant_id, now)
        subject = await uow.profiles.lock(grant.subject_id)
        if (
            not subject.active
            or subject.revoked_at is not None
            or subject.authority_generation != grant.subject_authority_generation
        ):
            raise PermissionError("current_subject_authority_required")
        self._binding_verifier.require_exact(grant.binding, binding)
        await uow.auth_grants.mark_consumed(grant_id, now)
        context = AuthContext(grant_id=grant.grant_id, subject_id=grant.subject_id, binding=grant.binding, assurance=grant.assurance, assurance_source=grant.assurance_source, consumed_at=now)
        await self._audit.append(uow, uow.auth_grants.consumed_audit(grant))
        return context  # caller commits grant + authorized mutation + both audit drafts once
```

- [ ] **Step 4: Run green and affected auth tests**

Run: `uv run pytest tests/security/test_passkey_binding.py tests/security/test_recovery.py tests/security/test_local_presence.py tests/security/test_auth_replay.py tests/security/test_auth_rate_limit.py -q`
Expected: PASS; schema checks expose only `owner_admin|adult_self_consent|profile_persona` credentials and only the two adult invitation capabilities. Revoked credentials, wrong household/subject, historical or replaced owners, stale owner/profile generations, an adult-forged `owner_admin` capability, wrong origin/RP/action/resource/parameters/session/policy, other-adult/stale-guardian profile edits, cross-capability use, expiry, and replay all fail closed before protected target reads; both K2 and N1 current-guardian edits bind exactly, and privacy-reducing persona clear can still obtain its exact grant after personalization consent revocation.

- [ ] **Step 5: Check and commit**

Run: `uv run ruff format --check apps/core/src/tuntun_core/services/auth/passkey.py apps/core/src/tuntun_core/services/auth/recovery.py apps/core/src/tuntun_core/services/auth/local_presence.py apps/core/src/tuntun_core/services/auth/service.py tests/security/test_passkey_binding.py tests/security/test_recovery.py tests/security/test_local_presence.py && uv run ruff check apps/core/src/tuntun_core/services/auth/passkey.py apps/core/src/tuntun_core/services/auth/recovery.py apps/core/src/tuntun_core/services/auth/local_presence.py apps/core/src/tuntun_core/services/auth/service.py tests/security/test_passkey_binding.py tests/security/test_recovery.py tests/security/test_local_presence.py && uv run mypy apps/core/src/tuntun_core/services/auth`
Expected: PASS with exit code 0.

```bash
git add apps/core/src/tuntun_core/services/auth/passkey.py apps/core/src/tuntun_core/services/auth/recovery.py apps/core/src/tuntun_core/services/auth/local_presence.py apps/core/src/tuntun_core/services/auth/service.py apps/core/pyproject.toml uv.lock tests/security/test_passkey_binding.py tests/security/test_recovery.py tests/security/test_local_presence.py
git diff --cached --name-only
git diff --cached
git commit -m "feat(auth): add passkey recovery and local presence"
```

### Task 8: Enforce the typed action-proposal boundary

**Master coverage:** action portion of Task 20
**Depends on:** Tasks 6–7
**Estimated effort:** 2 person-days

**Files:**
- Create: `apps/core/src/tuntun_core/services/actions/proposals.py`
- Create: `apps/core/src/tuntun_core/services/actions/validator.py`
- Create: `apps/core/src/tuntun_core/services/actions/executor.py`
- Modify: `apps/core/src/tuntun_core/services/actions/parameter_binding.py` (extend Task 1's profile-parameter builders; do not replace them)
- Create: `apps/core/src/tuntun_core/services/actions/policy_requests.py`
- Create: `apps/core/src/tuntun_core/services/actions/receipt_audit.py`
- Create: `apps/core/src/tuntun_core/services/actions/provider_registry.py`
- Create: `apps/core/src/tuntun_core/services/actions/providers/identity.py`
- Create: `apps/core/src/tuntun_core/services/actions/providers/search.py`
- Modify: `apps/core/src/tuntun_core/services/identity/subject_revocation.py` (replace Task-1 action placeholder after `0003`)
- Modify: `apps/core/src/tuntun_core/services/identity/subject_revocation_handlers.py` (register real action reconciliation)
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/lifecycle.py`
- Create: `tests/security/test_action_proposal_boundary.py`
- Create: `tests/integration/test_action_idempotency.py`
- Create: `tests/unit/actions/test_action_validator.py`
- Create: `tests/unit/actions/test_parameter_binding.py`
- Create: `tests/unit/actions/test_provider_registry.py`
- Modify: `tests/integration/identity/test_subject_revocation_handlers.py`

**Interfaces:**
- Consumes: the closed discriminated `ProviderActionIntent` union already owned and validated by the Task 15 conversation output validator, or typed admin/local request DTOs; those upstream mappers—not this task—supply a locally constructed `ActionProposalDraft`. No `dict[str, object]`, arbitrary arguments, or provider-supplied internal UUID/HMAC field crosses this boundary. Also consumes policy registry, `PolicyEnginePort`, `AuthenticationPort`, `AsyncUnitOfWork`, foundation `AsyncAuditLedger`, the explicit binding/policy/audit mappers from this task, and registered external or database-local action providers.
- Produces: `ActionProposalService.stage(draft, context) -> ActionProposal`; durable encrypted `action_proposals`, `action_execution_claims`, and authenticated `action_receipts`; internal non-committing `ActionExecutor.prepare_in_uow(uow, proposal: ValidatedActionProposal, auth: AuthContext) -> ActionReceipt | PreparedExternalExecution`; and the one cross-plan signature `ActionMutationCoordinator.execute_in_uow(uow: IdentityUnitOfWork, proposal_id: UUID, grant_id: UUID) -> ActionReceipt | PreparedExternalExecution`. Subject-scoped proposals and grants carry the locked active subject's authority generation; `require_pending_current` and grant consumption re-lock the subject and require the same current generation before a local effect or external claim. `ActionMutationCoordinator.complete_post_commit(claim_id: UUID) -> ActionReceipt` is the only external completion entry point and may run only after the claim transaction commits. That authoritative coordinator owns proposal lock, exact grant consumption, dynamic policy recheck, local receipt/audits or durable external claim, but never commits in `execute_in_uow`. `ActionProviderPort.execute(proposal, auth)` is external/post-commit only; the separate internal `LocalActionProviderPort.execute_in_uow(uow, proposal, auth)` may perform only bounded repository mutations. The public `execute(proposal_id, grant_id) -> ActionReceipt` orchestrates commits and delegates external work to `complete_post_commit`. Unique proposal and receipt idempotency scope is `(household_id, action_name, resource_scope, idempotency_key)`; neither table has a global idempotency-key uniqueness rule, and no existing receipt is returned until a fresh exact grant has been consumed in the caller's transaction.

The closed database-local registry is assembled from concrete adapters, never action-name conditionals in the executor. `IdentityLocalActionProvider` wraps only the non-committing `ProfileService`, `ConsentService`, and `EnrollmentService` methods; Task 10 registers `MemoryLocalActionProvider`, C03 registers `TimerLocalActionProvider`, and the controlled-web supplement injects its service into the `SearchLocalActionProvider` declared here for `search.profile_mode.change|search.experimental.activate`. Until a required adapter is composed, the action is unregistered and execution fails `action_provider_not_registered`. Registration is exact and duplicate-safe. Each adapter first checks its closed draft type and exact `action_name`, then reconstructs the domain command from every typed draft field before the first domain read; operation substitution, missing fields, and unimplemented actions therefore fail closed.

After migration `0003_authentication` is at head and the action proposal/claim repositories plus provider registry are registered, Task 8 replaces both Task-1 `action_authorities` placeholders with `ActionSubjectAuthorityHandler` and `ActionAuthorityRevocationHandler`. The transactional handler closes pending proposals and unsent claims through the old subject generation in the profile-revocation UoW. The post-commit handler reconciles already-started claims through `reconcile_subject_revocation_once`, passing the exact revocation UUIDv5 key into each provider and reopening its exact scoped receipt. Bootstrap rejects a real handler before schema/facade registration and rejects a placeholder after `0003` is active.

- [ ] **Step 1: Write failing boundary and idempotency tests**

```python
# tests/security/test_action_proposal_boundary.py
import pytest

@pytest.mark.asyncio
async def test_model_output_is_mapped_before_stage_and_cannot_execute(proposal_service, proposal_mapper, fake_model_output, executor_capture):
    intent = fake_model_output.action_proposals[0]
    draft = proposal_mapper.map_action(intent, fake_model_output.context.household_id, fake_model_output.context.session_id, fake_model_output.context.turn_id)
    proposal = await proposal_service.stage(draft, fake_model_output.context)
    assert proposal.status == "pending"
    assert executor_capture.calls == ()

@pytest.mark.asyncio
async def test_unknown_action_denies_before_provider_lookup(proposal_service, unknown_action_draft, provider_registry):
    with pytest.raises(PermissionError, match="unknown_action"):
        await proposal_service.stage(unknown_action_draft, unknown_action_draft.context)
    assert provider_registry.lookups == ()

@pytest.mark.asyncio
async def test_forged_internal_draft_without_exact_mapper_attestation_is_rejected(proposal_service, forged_timer_draft, context):
    with pytest.raises(PermissionError, match="action_proposal_provenance_mismatch"):
        await proposal_service.stage(forged_timer_draft, context)

@pytest.mark.asyncio
async def test_low_risk_action_requires_exact_explicit_confirmation(action_coordinator, approved_timer_proposal, identified_grant):
    with pytest.raises(PermissionError, match="confirmed_assurance_required"):
        await action_coordinator.execute(approved_timer_proposal.id, identified_grant.id)
```

```python
# tests/integration/test_action_idempotency.py
import asyncio
import pytest

@pytest.mark.asyncio
async def test_duplicate_execute_returns_same_receipt(action_coordinator, approved_proposal, passkey_grants):
    first = await action_coordinator.execute(approved_proposal.id, passkey_grants[0].id)
    second = await action_coordinator.execute(approved_proposal.id, passkey_grants[1].id)
    assert second.receipt_id == first.receipt_id
    assert action_coordinator.provider_call_count == 1

@pytest.mark.asyncio
async def test_concurrent_duplicate_creates_one_execution_claim(action_coordinator, approved_proposal, passkey_grants):
    results = await asyncio.gather(*(action_coordinator.execute(approved_proposal.id, grant.id) for grant in passkey_grants[:8]))
    assert len({result.receipt_id for result in results}) == 1
    assert action_coordinator.provider_call_count == 1

@pytest.mark.asyncio
async def test_crash_after_send_is_ambiguous_and_never_blindly_replayed(action_coordinator, approved_proposal, passkey_grants, crash_after_send):
    with pytest.raises(RuntimeError, match="injected_crash_after_send"):
        await action_coordinator.execute(approved_proposal.id, passkey_grants[0].id)
    with pytest.raises(PermissionError, match="execution_ambiguous_requires_reconciliation"):
        await action_coordinator.execute(approved_proposal.id, passkey_grants[1].id)
    assert action_coordinator.provider_call_count == 1

@pytest.mark.asyncio
async def test_prepare_failure_rolls_back_grant_claim_and_audit(action_coordinator, approved_proposal, passkey_grants, fail_after_claim, auth_grants, action_claims, audit_rows):
    with pytest.raises(RuntimeError, match="injected_prepare_failure"):
        await action_coordinator.execute(approved_proposal.id, passkey_grants[0].id)
    assert await auth_grants.is_consumed(passkey_grants[0].id) is False
    assert await action_claims.for_proposal(approved_proposal.id) is None
    assert await audit_rows.authorization_for(passkey_grants[0].id) is None

@pytest.mark.asyncio
async def test_changed_provider_receipt_is_ambiguous_not_accepted(action_coordinator, approved_proposal, passkey_grants, tampered_provider_receipt):
    with pytest.raises(PermissionError, match="execution_ambiguous_requires_reconciliation"):
        await action_coordinator.execute(approved_proposal.id, passkey_grants[0].id)
    assert tampered_provider_receipt.was_persisted is False

@pytest.mark.asyncio
async def test_same_idempotency_key_is_independent_across_exact_receipt_scopes(action_coordinator, scoped_proposal_factory, grant_factory):
    first = scoped_proposal_factory(household="one", action="timer.cancel", resource_scope="timer:one", idempotency_key="same")
    second = scoped_proposal_factory(household="one", action="timer.cancel", resource_scope="timer:two", idempotency_key="same")
    receipts = [await action_coordinator.execute(item.id, grant_factory(item).id) for item in (first, second)]
    assert receipts[0].receipt_id != receipts[1].receipt_id

@pytest.mark.asyncio
async def test_receipt_repository_rejects_scope_substitution(action_receipts, receipt_factory):
    stored = await action_receipts.add(receipt_factory(resource_scope="profile:one", idempotency_key="same"))
    with pytest.raises(PermissionError, match="action_receipt_scope_conflict"):
        await action_receipts.add(receipt_factory(proposal_id=stored.proposal_id, resource_scope="profile:two", idempotency_key="same"))

@pytest.mark.asyncio
async def test_database_local_execution_returns_final_receipt_inside_caller_uow(action_coordinator, mutation_scope, local_proposal, local_grant):
    async with mutation_scope.open() as uow:
        result = await action_coordinator.execute_in_uow(uow, local_proposal.id, local_grant.id)
        assert result.outcome == "executed"
        assert await uow.action_receipts.get_by_proposal(local_proposal.id) == result

@pytest.mark.asyncio
async def test_external_prepare_returns_claim_and_never_a_placeholder_receipt(action_coordinator, mutation_scope, external_proposal, external_grant, provider_spy):
    async with mutation_scope.open() as uow:
        prepared = await action_coordinator.execute_in_uow(uow, external_proposal.id, external_grant.id)
        assert prepared.claim_id is not None
        assert await uow.action_receipts.get_optional_by_proposal(external_proposal.id) is None
        assert provider_spy.calls == ()
        await uow.commit()
    receipt = await action_coordinator.complete_post_commit(prepared.claim_id)
    assert receipt.proposal_id == external_proposal.id and provider_spy.call_count == 1
```

```python
# tests/unit/actions/test_provider_registry.py
import pytest
from tuntun_core.services.actions.provider_registry import (
    PHASE1_ACTION_PROVIDER_ACTIONS,
    PHASE1_DATABASE_LOCAL_ACTIONS,
    PHASE1_EXTERNAL_POST_COMMIT_ACTIONS,
    PHASE1_NON_PROPOSAL_ACTIONS,
)

def test_database_local_registry_has_exact_phase1_coverage(composed_action_providers):
    assert composed_action_providers.local_action_names() == PHASE1_DATABASE_LOCAL_ACTIONS

def test_phase1_provider_effect_partition_is_closed_and_disjoint():
    assert PHASE1_DATABASE_LOCAL_ACTIONS.isdisjoint(PHASE1_EXTERNAL_POST_COMMIT_ACTIONS)
    assert PHASE1_DATABASE_LOCAL_ACTIONS | PHASE1_EXTERNAL_POST_COMMIT_ACTIONS == PHASE1_ACTION_PROVIDER_ACTIONS
    assert {"memory.export", "profile.delete", "profile.export", "backup.restore", "access.change"} <= PHASE1_EXTERNAL_POST_COMMIT_ACTIONS
    assert {"memory.export", "profile.delete"}.isdisjoint(PHASE1_DATABASE_LOCAL_ACTIONS)
    assert PHASE1_NON_PROPOSAL_ACTIONS == {
        "privacy.on", "mute", "stop", "timer.status", "system.status", "reachy.status",
    }
    assert PHASE1_NON_PROPOSAL_ACTIONS.isdisjoint(PHASE1_ACTION_PROVIDER_ACTIONS)

@pytest.mark.asyncio
@pytest.mark.parametrize("provider_name", ["identity", "memory", "timer", "search"])
async def test_operation_substitution_denies_before_domain_read(local_provider_scenarios, provider_name):
    provider, wrong_operation_proposal, domain_spy = local_provider_scenarios[provider_name]
    with pytest.raises(PermissionError, match="action_provider_operation_mismatch"):
        await provider.execute_in_uow(domain_spy.uow, wrong_operation_proposal, domain_spy.auth)
    assert domain_spy.read_count == 0 and domain_spy.write_count == 0

@pytest.mark.asyncio
@pytest.mark.parametrize("action_name", [
    "profile.create", "profile.edit", "profile.revoke", "consent.grant", "consent.revoke",
    "identity.enroll", "identity.enrollment.cancel",
])
async def test_identity_local_adapter_uses_exact_caller_uow_without_commit(
    identity_provider, identity_proposal_factory, identity_uow_spy, auth, action_name
):
    await identity_provider.execute_in_uow(
        identity_uow_spy.uow, identity_proposal_factory(action_name), auth
    )
    assert identity_uow_spy.service_uows == (identity_uow_spy.uow,)
    assert identity_uow_spy.commit_count == 0

@pytest.mark.asyncio
async def test_identity_provider_rejects_ordinary_owner_create_before_profile_read(
    identity_provider, forged_owner_profile_create_proposal, identity_uow_spy, auth
):
    with pytest.raises(PermissionError, match="action_provider_operation_mismatch"):
        await identity_provider.execute_in_uow(
            identity_uow_spy.uow, forged_owner_profile_create_proposal, auth
        )
    assert identity_uow_spy.read_count == 0 and identity_uow_spy.write_count == 0

def test_unregistered_or_unimplemented_action_fails_closed(action_providers, validated_unknown_or_external_local_proposal):
    with pytest.raises(PermissionError, match="action_provider_not_registered"):
        action_providers.get(validated_unknown_or_external_local_proposal.draft.action_name)


def test_0003_bootstrap_replaces_action_revocation_placeholders_only_after_facades_exist(
    task8_identity_container,
):
    assert task8_identity_container.migration_head_at_least("0003_authentication")
    assert type(task8_identity_container.transactional_revocations["action_authorities"]).__name__=="ActionSubjectAuthorityHandler"
    assert type(task8_identity_container.post_commit_revocations["action_authorities"]).__name__=="ActionAuthorityRevocationHandler"
    assert task8_identity_container.external_action_claims.registered


@pytest.mark.parametrize("mismatch",("real_before_0003","placeholder_after_0003"))
def test_action_revocation_schema_stage_mismatch_blocks_startup(
    task8_container_factory,mismatch,
):
    with pytest.raises(RuntimeError,match="revocation handler schema stage mismatch"):
        task8_container_factory(mismatch=mismatch).start()
```

```python
# tests/unit/actions/test_parameter_binding.py
import pytest

@pytest.mark.parametrize("field", ["household_id", "proposal_id", "turn_id", "idempotency_key", "action_name", "resource_type", "resource_id", "parameter_commitment", "policy_version", "session_id", "subject_id"])
def test_explicit_binding_verifier_rejects_every_substitution_before_domain_read(binding_verifier, binding, binding_variant_factory, protected_repository_spy, field):
    with pytest.raises(PermissionError, match="action_binding_mismatch"):
        binding_verifier.require_exact(binding, binding_variant_factory(field))
    assert protected_repository_spy.read_count == 0

def test_binding_commitment_uses_constant_time_comparison(monkeypatch, binding_verifier, binding, different_commitment):
    calls = []
    monkeypatch.setattr("tuntun_core.services.actions.parameter_binding.hmac.compare_digest", lambda left, right: calls.append((left, right)) or False)
    with pytest.raises(PermissionError, match="action_binding_mismatch"):
        binding_verifier.require_exact(binding, binding.model_copy(update={"parameter_commitment": different_commitment}))
    assert len(calls) == 1
```

- [ ] **Step 2: Run red tests**

Run: `uv run pytest tests/security/test_action_proposal_boundary.py tests/integration/test_action_idempotency.py tests/unit/actions/test_action_validator.py tests/unit/actions/test_parameter_binding.py tests/unit/actions/test_provider_registry.py tests/integration/storage/test_migrations.py -q`
Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core.services.actions.proposals'`.

- [ ] **Step 3: Implement atomic validation plus durable external execution states**

```python
# apps/core/src/tuntun_core/services/actions/proposals.py
from tuntun_contracts.actions import ValidatedActionProposal
from tuntun_contracts.base import canonical_bytes,parse_contract_json

class ActionProposalService:
    def __init__(self, validator, provenance, crypto, binding_verifier, uow_factory, audit_ledger):
        self._validator, self._uow_factory, self._audit = validator, uow_factory, audit_ledger
        self._provenance, self._crypto, self._bindings = provenance, crypto, binding_verifier

    async def stage(self, draft, context):
        async with self._uow_factory() as uow:
            proposal = await self.stage_in_uow(uow, draft, context)
            await uow.commit()
            return proposal

    async def stage_in_uow(self, uow, draft, context):
        attestation = self._provenance.require_exact_draft(draft, context)
        validated = self._validator.validate(draft, context)
        subject_authority_generation = None
        if validated.binding.subject_id is not None:
            subject = await uow.profiles.lock(validated.binding.subject_id)
            if not subject.active or subject.revoked_at is not None:
                raise PermissionError("current_subject_authority_required")
            subject_authority_generation = subject.authority_generation
        frozen_draft=canonical_bytes(validated)
        draft_commitment = self._crypto.commit(frozen_draft, purpose="action_proposal_frozen_draft")
        encrypted = self._crypto.encrypt_record(frozen_draft, purpose="action_proposal", aad=draft_commitment)
        scope_key = (validated.binding.household_id, draft.action_name, validated.resource_scope, draft.idempotency_key)
        existing = await uow.action_proposals.find_scope_locked(scope_key)
        if existing is not None:
            if not self._crypto.constant_time_equal(existing.draft_commitment, draft_commitment):
                raise PermissionError("action_proposal_idempotency_conflict")
            return existing
        proposal = await uow.action_proposals.insert(validated, encrypted=encrypted, draft_commitment=draft_commitment, provenance=attestation, subject_authority_generation=subject_authority_generation, status="pending")
        await self._audit.append(uow, uow.action_proposals.staged_audit_draft(proposal))
        return proposal

    async def reload_validated_in_uow(self, uow, proposal_id):
        row = await uow.action_proposals.lock(proposal_id)
        plaintext = self._crypto.decrypt_record(row.encrypted_draft, purpose="action_proposal", aad=row.draft_commitment)
        if not self._crypto.constant_time_equal(self._crypto.commit(plaintext, purpose="action_proposal_frozen_draft"), row.draft_commitment):
            raise PermissionError("action_proposal_draft_commitment_mismatch")
        validated=parse_contract_json(
            ValidatedActionProposal,plaintext,max_bytes=131_072,
            require_canonical=True,
        )
        self._bindings.require_exact(row.binding_projection(), validated.binding)
        if validated.resource_scope != row.resource_scope:
            raise PermissionError("action_proposal_resource_scope_mismatch")
        self._provenance.require_persisted_attestation(row, validated.draft)
        return validated
```

```python
# apps/core/src/tuntun_core/services/actions/validator.py
from tuntun_contracts.actions import ValidatedActionProposal
from tuntun_contracts.actions import ActionBinding
class ActionValidator:
    def __init__(self, registry, scopes, clock):
        self._registry, self._scopes, self._clock = registry, scopes, clock

    def validate(self, draft, context):
        rule = self._registry.get(draft.action_name)
        if rule is None or rule.schema_version != draft.schema_version:
            raise PermissionError("unknown_action")
        if draft.expires_at <= self._clock.now():
            raise PermissionError("expired_action_proposal")
        if draft.uncertainty_micros > rule.maximum_uncertainty_micros:
            raise PermissionError("action_uncertainty_too_high")
        adapter = self._registry.draft_adapter(draft.action_name)
        if adapter is None: raise PermissionError("unknown_action")
        adapter.validate_python(draft.model_dump(mode="python"))
        binding = ActionBinding(household_id=context.household_id, proposal_id=draft.proposal_id, turn_id=context.turn_id, idempotency_key=draft.idempotency_key, action_name=draft.action_name, resource_type=draft.resource_type, resource_id=draft.resource_id, parameter_commitment=draft.parameters_commitment, policy_version=rule.version, session_id=context.session_id, subject_id=context.actor_subject_id)
        return ValidatedActionProposal(draft=draft, binding=binding, resource_scope=self._scopes.build(draft), required_assurance=rule.assurance)
```

```python
# apps/core/src/tuntun_core/services/actions/parameter_binding.py
# Extend the Task-1 module below its existing imports and profile parameter
# builders; those builders remain the canonical console/identity boundary.
from tuntun_contracts.actions import ActionBinding

class ActionBindingVerifier:
    def require_exact(self, stored, supplied):
        ordinary = (
            stored.household_id == supplied.household_id and stored.proposal_id == supplied.proposal_id
            and stored.turn_id == supplied.turn_id and stored.idempotency_key == supplied.idempotency_key
            and stored.action_name == supplied.action_name and stored.resource_type == supplied.resource_type
            and stored.resource_id == supplied.resource_id and stored.policy_version == supplied.policy_version
            and stored.session_id == supplied.session_id and stored.subject_id == supplied.subject_id
            and stored.parameter_commitment.algorithm == supplied.parameter_commitment.algorithm
            and stored.parameter_commitment.key_id == supplied.parameter_commitment.key_id
        )
        commitment_equal = hmac.compare_digest(
            stored.parameter_commitment.value_b64.encode("ascii"),
            supplied.parameter_commitment.value_b64.encode("ascii"),
        )
        if not ordinary or not commitment_equal:
            raise PermissionError("action_binding_mismatch")

    def require_parts(self, stored, **parts):
        self.require_exact(stored, ActionBinding(**parts))

class ActionResourceScopeBuilder:
    def build(self, draft):
        suffix = str(draft.resource_id) if draft.resource_id is not None else "singleton"
        return f"{draft.resource_type}:{suffix}"
```

```python
# apps/core/src/tuntun_core/services/actions/policy_requests.py
from tuntun_contracts.policy import PolicyRequest

class ActionPolicyRequestFactory:
    def __init__(self, registry, binding_verifier):
        self._registry, self._bindings = registry, binding_verifier

    def build(self, proposal, auth):
        self._bindings.require_exact(proposal.binding, auth.binding)
        rule = self._registry.get(proposal.draft.action_name)
        if rule is None: raise PermissionError("unknown_action")
        return PolicyRequest(
            household_id=proposal.binding.household_id,
            subject_id=auth.subject_id,
            action=proposal.draft,
            requested_risk=rule.risk,
            assurance=auth.assurance,
        )
```

```python
# apps/core/src/tuntun_core/services/actions/receipt_audit.py
from tuntun_contracts.audit import AuditDraft

class ActionReceiptAuditMapper:
    def __init__(self, ids, pseudonyms, commitments):
        self._ids, self._pseudonyms, self._commitments = ids, pseudonyms, commitments

    def to_audit_draft(self, receipt, auth):
        return AuditDraft(
            event_id=self._ids.uuid4(), occurred_at=receipt.occurred_at,
            actor_pseudonym=self._pseudonyms.for_subject(receipt.household_id, auth.subject_id),
            action_code=receipt.action_name, outcome=receipt.outcome, reason_code=receipt.reason_code,
            correlation_id=receipt.proposal_id,
            payload_commitment=self._commitments.action_receipt(receipt),
        )
```

```python
# apps/core/src/tuntun_core/services/actions/provider_registry.py
from dataclasses import dataclass
from typing import Literal

PHASE1_DATABASE_LOCAL_ACTIONS = frozenset({
    "timer.create", "timer.cancel",
    "profile.create", "profile.edit", "profile.revoke",
    "consent.grant", "consent.revoke", "identity.enroll", "identity.enrollment.cancel",
    "memory.propose", "memory.approve", "memory.edit_approve", "memory.reject", "memory.expire", "memory.delete",
    "search.profile_mode.change", "search.experimental.activate",
})

# Anything outside the exact DB-local set may touch a file, Keychain, hardware, a listener,
# a provider, or a result stream and therefore cannot run before its durable claim commits.
PHASE1_NON_PROPOSAL_ACTIONS = frozenset({
    "privacy.on", "mute", "stop", "timer.status", "system.status", "reachy.status",
})
PHASE1_EXTERNAL_POST_COMMIT_ACTIONS = frozenset({
    "privacy.off", "mute.off", "reachy.gesture_test", "offline.prompt_test",
    "memory.export", "profile.delete", "profile.export",
    "provider.review", "provider.configure", "budget.change", "access.change",
    "credential.passkey.add", "credential.passkey.revoke", "credential.pin.change", "credential.recovery.rotate",
    "audit.export", "audit.verify",
    "backup.create", "backup.verify", "backup.recovery_key.create", "backup.restore",
    "release.p1r0", "release.latency.accept", "release.family_stage.review", "security.finding.suppress",
})
PHASE1_ACTION_PROVIDER_ACTIONS = PHASE1_DATABASE_LOCAL_ACTIONS | PHASE1_EXTERNAL_POST_COMMIT_ACTIONS

@dataclass(frozen=True, slots=True)
class ActionProviderRegistration:
    action_name: str
    effect_kind: Literal["database_local", "external_post_commit"]
    replay_policy: Literal["not_applicable", "deny", "idempotent_resume"]
    provider_name: str
    provider: object

class ActionProviderRegistry:
    def __init__(self): self._registrations = {}

    def register_local(self, provider): self._register(provider, "database_local", "not_applicable")
    def register_external(self, provider, *, replay_policy: Literal["deny", "idempotent_resume"]):
        self._register(provider, "external_post_commit", replay_policy)

    def _register(self, provider, effect_kind, replay_policy):
        names = frozenset(provider.action_names)
        if not names: raise ValueError("action provider must declare actions")
        if names & self._registrations.keys(): raise ValueError("duplicate action provider registration")
        for name in names:
            self._registrations[name] = ActionProviderRegistration(name, effect_kind, replay_policy, provider.provider_name, provider)

    def get(self, action_name):
        registration = self._registrations.get(action_name)
        if registration is None: raise PermissionError("action_provider_not_registered")
        return registration

    def local_action_names(self):
        return frozenset(name for name, item in self._registrations.items() if item.effect_kind == "database_local")

    def external_action_names(self):
        return frozenset(name for name, item in self._registrations.items() if item.effect_kind == "external_post_commit")

    def action_names(self):
        return frozenset(self._registrations)

    def require_phase1_complete(self, policy_action_names):
        policy_names = frozenset(policy_action_names)
        if policy_names - PHASE1_NON_PROPOSAL_ACTIONS != PHASE1_ACTION_PROVIDER_ACTIONS:
            raise RuntimeError("policy_and_provider_action_sets_differ")
        if not PHASE1_NON_PROPOSAL_ACTIONS <= policy_names:
            raise RuntimeError("phase1_non_proposal_policy_actions_missing")
        if self.local_action_names() != PHASE1_DATABASE_LOCAL_ACTIONS:
            raise RuntimeError("phase1_database_local_provider_registry_incomplete")
        if self.external_action_names() != PHASE1_EXTERNAL_POST_COMMIT_ACTIONS:
            raise RuntimeError("phase1_external_provider_registry_incomplete")
```

```python
# apps/core/src/tuntun_core/services/actions/providers/identity.py
from pydantic import ValidationError
from tuntun_contracts.actions import ConsentActionDraft, IdentityActionDraft, ProfileActionDraft

class IdentityLocalActionProvider:
    provider_name = "identity"
    action_names = frozenset({
        "profile.create", "profile.edit", "profile.revoke",
        "consent.grant", "consent.revoke", "identity.enroll", "identity.enrollment.cancel",
    })

    def __init__(self, profiles, consents, enrollments, command_mapper, receipts):
        self._profiles, self._consents, self._enrollments = profiles, consents, enrollments
        self._commands, self._receipts = command_mapper, receipts

    async def execute_in_uow(self, uow, proposal, auth):
        draft = proposal.draft
        if draft.action_name not in self.action_names or type(draft) not in {ProfileActionDraft, ConsentActionDraft, IdentityActionDraft}:
            raise PermissionError("action_provider_operation_mismatch")
        try:
            draft = type(draft).model_validate(draft.model_dump(mode="python"))
        except ValidationError as exc:
            raise PermissionError("action_provider_operation_mismatch") from exc
        command = self._commands.identity(draft, proposal.binding)  # exhaustive, fields-only, no read
        handlers = {
            "profile.create": self._profiles.create_in_uow,
            "profile.edit": self._profiles.update_persona_traits_in_uow,
            "profile.revoke": self._profiles.revoke_in_uow,
            "consent.grant": self._consents.grant_in_uow,
            "consent.revoke": self._consents.revoke_in_uow,
            "identity.enroll": self._enrollments.request_in_uow,
            "identity.enrollment.cancel": self._enrollments.cancel_in_uow,
        }
        await handlers[draft.action_name](uow, command, auth)
        return self._receipts.executed(proposal, provider_name=self.provider_name)
```

```python
# apps/core/src/tuntun_core/services/actions/providers/search.py
from pydantic import ValidationError
from tuntun_contracts.actions import SearchActionDraft

class SearchLocalActionProvider:
    provider_name = "search"
    action_names = frozenset({"search.profile_mode.change", "search.experimental.activate"})

    def __init__(self, search_actions, command_mapper, receipts):
        self._search_actions, self._commands, self._receipts = search_actions, command_mapper, receipts

    async def execute_in_uow(self, uow, proposal, auth):
        draft = proposal.draft
        if type(draft) is not SearchActionDraft or draft.action_name not in self.action_names:
            raise PermissionError("action_provider_operation_mismatch")
        try:
            draft = SearchActionDraft.model_validate(draft.model_dump(mode="python"))
        except ValidationError as exc:
            raise PermissionError("action_provider_operation_mismatch") from exc
        command = self._commands.search(draft, proposal.binding)  # binds mode/consent and every experimental cap/version
        await self._search_actions.apply_in_uow(uow, command, auth)
        return self._receipts.executed(proposal, provider_name=self.provider_name)
```

```python
# apps/core/src/tuntun_core/bootstrap/container.py (Task-8 revocation replacement)
class ActionSubjectAuthorityHandler:
    def __init__(self,claims): self._claims=claims
    async def revoke_in_uow(
        self,uow,*,household_id,subject_id,through_generation,reason,now,
    ):
        await uow.action_proposals.cancel_pending_through_generation(
            household_id,subject_id,through_generation,reason=reason,now=now,
        )
        await self._claims.cancel_unsent_in_uow(
            uow,household_id=household_id,subject_id=subject_id,
            through_generation=through_generation,reason=reason,now=now,
        )

def install_action_revocation_handlers(
    transactional,post_commit,*,capability_stage,effects,heartbeats,
    action_claims,action_provider_registry,
):
    capability_stage.require_schema_and_facades_installed(
        "action_authorities","0003_authentication",
        (action_claims,action_provider_registry),
    )
    transactional["action_authorities"]=ActionSubjectAuthorityHandler(action_claims)
    post_commit["action_authorities"]=ActionAuthorityRevocationHandler(
        effects,heartbeats,action_claims,action_provider_registry,
    )
    if isinstance(post_commit["action_authorities"],NotInstalledAuthorityRevocationHandler):
        raise RuntimeError("revocation handler schema stage mismatch")
```

```python
# apps/core/src/tuntun_core/services/actions/executor.py
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID
from tuntun_contracts.actions import ActionReceipt, ValidatedActionProposal
from tuntun_contracts.policy import AuthContext, PolicyEffect
from tuntun_core.storage.uow import AsyncUnitOfWork

class ProviderOutcomeUnknown(RuntimeError):
    pass

@dataclass(frozen=True, slots=True)
class PreparedExternalExecution:
    claim_id: UUID
    proposal_id: UUID
    provider_name: str

class ActionMutationCoordinatorPort(Protocol):
    async def execute(self, proposal_id: UUID, grant_id: UUID) -> ActionReceipt: raise NotImplementedError
    async def execute_in_uow(self, uow: AsyncUnitOfWork, proposal_id: UUID, grant_id: UUID) -> ActionReceipt | PreparedExternalExecution: raise NotImplementedError
    async def complete_post_commit(self, claim_id: UUID) -> ActionReceipt: raise NotImplementedError

class ActionExecutor:
    def __init__(self, policy, policy_requests, providers, receipt_validator, receipt_audits, claim_audits, audit_ledger, clock, fault_injector):
        self._policy, self._policy_requests, self._providers = policy, policy_requests, providers
        self._receipt_validator, self._receipt_audits, self._claim_audits = receipt_validator, receipt_audits, claim_audits
        self._audit, self._clock, self._faults = audit_ledger, clock, fault_injector

    async def prepare_in_uow(self, uow, proposal, auth):
        decision = await self._policy.decide_in_uow(uow, self._policy_requests.build(proposal, auth))
        if decision.policy_version != proposal.binding.policy_version:
            raise PermissionError("policy_version_changed")
        if decision.effect is not PolicyEffect.ALLOW:
            reason = decision.required_assurance.value if decision.required_assurance is not None else decision.reason_code
            raise PermissionError(f"{reason}_assurance_required")
        proposal_id = proposal.draft.proposal_id
        prior_receipt = await uow.action_receipts.get_optional_by_proposal(proposal_id)
        if prior_receipt is not None:
            await uow.action_proposals.require_executed_exact(proposal_id, proposal.binding, prior_receipt.receipt_id)
            return prior_receipt
        existing = await uow.action_execution_claims.get_by_proposal(proposal_id)
        if existing is not None and existing.state == "succeeded":
            await uow.action_proposals.require_executed_exact(proposal_id, proposal.binding, existing.receipt_id)
            return await uow.action_receipts.get_by_proposal(proposal_id)
        if existing is not None and existing.state in {"sent", "ambiguous"}:
            raise PermissionError("execution_ambiguous_requires_reconciliation")
        await uow.action_proposals.require_pending_current(proposal_id, proposal.binding, self._clock.now())
        registration = self._providers.get(proposal.draft.action_name)
        if registration.effect_kind == "database_local":
            receipt = await registration.provider.execute_in_uow(uow, proposal, auth)
            self._require_exact_receipt(proposal, registration.provider_name, receipt)
            return receipt
        if auth.grant_id is None: raise PermissionError("external_action_grant_required")
        claim = existing or await uow.action_execution_claims.claim(proposal_id=proposal_id, grant_id=auth.grant_id, provider_name=registration.provider_name, state="pending", now=self._clock.now())
        await self._audit.append(uow, self._claim_audits.prepared(claim, proposal, auth))
        self._faults.after_claim()
        return PreparedExternalExecution(claim.id, proposal_id, registration.provider_name)

    def now(self):
        return self._clock.now()

    def require_exact_provider_receipt(self, proposal, provider_name, receipt):
        self._require_exact_receipt(proposal, provider_name, receipt)

    def _require_exact_receipt(self, proposal, provider_name, receipt):
        draft = proposal.draft
        self._receipt_validator.require_exact(receipt, proposal_id=draft.proposal_id, household_id=proposal.binding.household_id, action_name=draft.action_name, resource_scope=proposal.resource_scope, resource_id=draft.resource_id, idempotency_key=draft.idempotency_key, provider_name=provider_name)

    async def mark_sent_in_uow(self, uow, prepared):
        await uow.action_execution_claims.mark_sent(prepared.claim_id, self._clock.now())

    async def mark_ambiguous_in_uow(self, uow, prepared, reason):
        claim, changed = await uow.action_execution_claims.mark_ambiguous_once(prepared.claim_id, self._clock.now())
        if changed:
            await self._audit.append(uow, self._claim_audits.ambiguous(claim, reason))

    async def finalize_in_uow(self, uow, prepared, proposal, auth, receipt):
        stored, _ = await uow.action_receipts.add_or_get_exact(receipt)
        await uow.action_execution_claims.mark_succeeded(prepared.claim_id, receipt.receipt_id, self._clock.now())
        await uow.action_proposals.mark_executed(prepared.proposal_id, stored.receipt_id, self._clock.now())
        await self._audit.append(uow, self._receipt_audits.to_audit_draft(stored, auth))
        return stored

class ActionMutationCoordinator(ActionMutationCoordinatorPort):
    def __init__(self, mutation_scope, authentication, executor, providers, proposal_locks, receipt_audits, audit_ledger, fault_injector):
        self._scope, self._authentication, self._executor, self._providers = mutation_scope, authentication, executor, providers
        self._locks, self._receipt_audits, self._audit, self._faults = proposal_locks, receipt_audits, audit_ledger, fault_injector

    async def execute_in_uow(self, uow, proposal_id, grant_id):
        proposal = await uow.action_proposals.lock(proposal_id)
        auth = await self._authentication.consume_in_uow(uow, grant_id, proposal.validated.binding)
        result = await self._executor.prepare_in_uow(uow, proposal.validated, auth)
        if isinstance(result, PreparedExternalExecution):
            return result
        stored, created = await uow.action_receipts.add_or_get_exact(result)
        if created:
            await uow.action_proposals.mark_executed(proposal_id, stored.receipt_id, self._executor.now())
            await self._audit.append(uow, self._receipt_audits.to_audit_draft(stored, auth))
        return stored

    async def complete_post_commit(self, claim_id):
        async with self._locks.for_key(claim_id):
            async with self._scope.open() as uow:
                claim = await uow.action_execution_claims.lock(claim_id)
                if claim.state == "succeeded":
                    return await uow.action_receipts.get_by_proposal(claim.proposal_id)
                proposal = (await uow.action_proposals.lock(claim.proposal_id)).validated
                grant = await uow.auth_grants.require_consumed(claim.grant_id)
                auth = await uow.auth_grants.reconstruct_consumed_context(claim.grant_id)
                subject = await uow.profiles.lock(auth.subject_id)
                if (
                    not subject.active
                    or subject.revoked_at is not None
                    or subject.authority_generation != grant.subject_authority_generation
                ):
                    await uow.action_execution_claims.dispose_subject_revoked(
                        claim.id,
                        unsent_state="cancelled_subject_revoked",
                        sent_state="settled_subject_revoked",
                        now=self._executor.now(),
                    )
                    await uow.commit()
                    raise PermissionError("current_subject_authority_required")
                prepared = PreparedExternalExecution(claim.id, claim.proposal_id, claim.provider_name)
                registration = self._providers.get(proposal.draft.action_name)
                if registration.effect_kind != "external_post_commit" or registration.provider_name != prepared.provider_name:
                    raise PermissionError("action_provider_registration_changed")
                if claim.state in {"sent", "ambiguous"} and registration.replay_policy != "idempotent_resume":
                    raise PermissionError("execution_ambiguous_requires_reconciliation")
                if claim.state == "pending":
                    await self._executor.mark_sent_in_uow(uow, prepared)
                    await uow.commit()  # the durable sent marker always precedes external I/O
                elif claim.state not in {"sent", "ambiguous"}:
                    raise PermissionError("external_execution_claim_state_invalid")
            try:
                receipt = await registration.provider.execute(proposal, auth)
                self._faults.after_provider_send()
                self._executor.require_exact_provider_receipt(proposal, prepared.provider_name, receipt)
            except (ProviderOutcomeUnknown, ValueError) as exc:
                async with self._scope.open() as uow:
                    await self._executor.mark_ambiguous_in_uow(uow, prepared, "provider_outcome_unknown")
                    await uow.commit()
                raise PermissionError("execution_ambiguous_requires_reconciliation") from exc
            async with self._scope.open() as uow:
                finalized = await self._executor.finalize_in_uow(uow, prepared, proposal, auth, receipt)
                await uow.commit()
                return finalized

    async def execute(self, proposal_id, grant_id):
        async with self._locks.for_key(proposal_id):
            async with self._scope.open() as uow:
                result = await self.execute_in_uow(uow, proposal_id, grant_id)
                await uow.commit()
            if not isinstance(result, PreparedExternalExecution):
                return result
        return await self.complete_post_commit(result.claim_id)
```

- [ ] **Step 4: Run green and policy tests**

Run: `uv run pytest tests/security/test_action_proposal_boundary.py tests/integration/test_action_idempotency.py tests/unit/actions/test_action_validator.py tests/unit/actions/test_parameter_binding.py tests/unit/actions/test_provider_registry.py tests/integration/identity/test_subject_revocation_handlers.py tests/unit/policy/test_risk_matrix.py tests/integration/storage/test_migrations.py -q`
Expected: PASS; model output never calls a provider, stale/unknown/replayed proposals deny, duplicate execution produces one side effect, and `0003` startup replaces both action revocation placeholders only after the exact typed facades are registered.

- [ ] **Step 5: Check and commit**

Run: `uv run ruff format --check apps/core/src/tuntun_core/services/actions tests/security/test_action_proposal_boundary.py tests/integration/test_action_idempotency.py tests/unit/actions/test_action_validator.py tests/unit/actions/test_parameter_binding.py tests/unit/actions/test_provider_registry.py && uv run ruff check apps/core/src/tuntun_core/services/actions tests/security/test_action_proposal_boundary.py tests/integration/test_action_idempotency.py tests/unit/actions/test_action_validator.py tests/unit/actions/test_parameter_binding.py tests/unit/actions/test_provider_registry.py && uv run mypy apps/core/src/tuntun_core/services/actions`
Expected: PASS with exit code 0.

```bash
git add apps/core/src/tuntun_core/services/actions/proposals.py apps/core/src/tuntun_core/services/actions/validator.py apps/core/src/tuntun_core/services/actions/executor.py apps/core/src/tuntun_core/services/actions/parameter_binding.py apps/core/src/tuntun_core/services/actions/policy_requests.py apps/core/src/tuntun_core/services/actions/receipt_audit.py apps/core/src/tuntun_core/services/actions/provider_registry.py apps/core/src/tuntun_core/services/actions/providers/identity.py apps/core/src/tuntun_core/services/actions/providers/search.py apps/core/src/tuntun_core/services/identity/subject_revocation.py apps/core/src/tuntun_core/services/identity/subject_revocation_handlers.py apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/bootstrap/lifecycle.py tests/security/test_action_proposal_boundary.py tests/integration/test_action_idempotency.py tests/unit/actions/test_action_validator.py tests/unit/actions/test_parameter_binding.py tests/unit/actions/test_provider_registry.py tests/integration/identity/test_subject_revocation_handlers.py
git diff --cached --name-only
git diff --cached
git commit -m "feat(actions): enforce typed idempotent proposals"
```

### Task 9: Persist seven typed memory kinds with immutable revisions

**Master coverage:** Task 21
**Depends on:** Tasks 1–2 and 6
**Estimated effort:** 5 person-days

**Files:**
- Create: `apps/core/src/tuntun_core/services/memory/schemas.py`
- Create: `apps/core/src/tuntun_core/services/memory/repository.py`
- Create: `apps/core/src/tuntun_core/services/memory/mappers.py`
- Create: `apps/core/src/tuntun_core/services/memory/revisions.py`
- Create: `apps/core/src/tuntun_core/services/memory/scoping.py`
- Create: `apps/core/src/tuntun_core/services/memory/projection.py`
- Create: `apps/core/migrations/versions/0004_memory.py`
- Create: `tests/integration/memory/test_repository.py`
- Create: `tests/unit/memory/test_persistence_mappers.py`
- Create: `tests/integration/memory/test_revisions.py`
- Create: `tests/integration/memory/test_concurrency.py`
- Create: `tests/security/test_memory_isolation.py`
- Create: `tests/security/test_memory_admin_visibility.py`
- Create: `tests/security/test_procedural_memory.py`
- Create: `tests/benchmark/test_memory_repository_10k.py`

**Interfaces:**
- Consumes: typed seven-kind payloads, `AsyncUnitOfWork`, current consent/profile state, `PolicyEnginePort`, record AEAD/HMAC services, and the exact current `child_durable_memory_v1` receipt for every durable K2/N1 record.
- Produces: exact `MemoryRepositoryPort` baseline as an internal bounded-context port; explicit `MemoryPersistenceMapper` from encrypted persistence rows to the exact frozen `MemoryRecord` and explicit `MemoryAuditDraftMapper` to `AuditDraft`; immutable `memory_revisions`; mandatory non-null approved-proposal provenance on current and revision rows; mandatory household/subject scope; no conversational `list_all` operation; and `MemoryProjectionPolicy` that decides body visibility from subject identity, stored closed audience, current child-memory consent receipt, exact guardian generation, and explicit child-safe audience approval before decryption. No persistence row supplies a convenience `to_contract` or `to_audit` method. The composition root exposes its mutators only to `MemoryMutationCoordinator`; `create/replace/delete` require the caller's active `AtomicMutationScope`, validate the exact approved source proposal before writing, never consume an already-created `AuthContext` in a second transaction, and never commit.

- [ ] **Step 1: Write failing type, scope, lifecycle, and concurrency tests**

```python
# tests/integration/memory/test_repository.py
import pytest
from tuntun_contracts.memory import MemoryKind, MemoryQuery
from tuntun_contracts.policy import PolicyDecision, PolicyEffect
from tuntun_core.domain.profile import ConsentPurpose

@pytest.mark.asyncio
async def test_query_excludes_non_recallable_states(memory_repository, seeded_memories, owner_scope, now):
    result = await memory_repository.query(MemoryQuery(household_id=owner_scope.household_id, subject_id=owner_scope.subject_id, kinds=tuple(MemoryKind), maximum_sensitivity="personal", limit=6))
    assert all(item.subject_id == owner_scope.subject_id for item in result)
    assert all(item.valid_until is None or item.valid_until > now for item in result)

@pytest.mark.asyncio
async def test_subject_scope_never_returns_another_subject(memory_repository, subject_a_query, subject_b):
    result = await memory_repository.query(subject_a_query)
    assert all(item.subject_id != subject_b.id for item in result)

@pytest.mark.asyncio
async def test_create_and_replace_return_exact_frozen_contracts(memory_mutations, approved_memory):
    created = await memory_mutations.create_approved_for_test(approved_memory)
    replaced = await memory_mutations.replace_approved_for_test(created.memory_id, created.version, approved_memory.with_value("new"))
    assert set(created.model_fields) == {"memory_id", "household_id", "subject_id", "version", "content", "audience", "sensitivity", "valid_until"}
    assert replaced.memory_id == created.memory_id and replaced.version == created.version + 1
    assert replaced.content == approved_memory.with_value("new").content


@pytest.mark.asyncio
@pytest.mark.parametrize("case", [
    "missing", "pending", "rejected", "wrong_operation", "wrong_target",
    "wrong_expected_version", "wrong_subject", "wrong_source_receipts",
])
async def test_create_or_replace_requires_exact_approved_source_proposal_before_write(
    memory_mutations, approved_memory_case_factory, memory_write_spy, case,
):
    command = approved_memory_case_factory(case)
    with pytest.raises(PermissionError, match="exact_approved_memory_proposal_required"):
        await memory_mutations.apply_approved_for_test(command)
    assert memory_write_spy.current_writes == 0
    assert memory_write_spy.revision_writes == 0


@pytest.mark.asyncio
async def test_delete_rejects_outer_action_proposal_id_before_tombstone(
    memory_mutations, approved_delete, outer_action_proposal_id, memory_write_spy,
):
    with pytest.raises(PermissionError, match="exact_approved_memory_proposal_required"):
        await memory_mutations.delete_approved_for_test(
            approved_delete, approved_proposal_id=outer_action_proposal_id,
        )
    assert memory_write_spy.current_writes == 0
    assert memory_write_spy.revision_writes == 0
```

```python
# tests/integration/memory/test_revisions.py
import pytest


@pytest.mark.asyncio
async def test_real_migrated_sqlcipher_reopens_with_complete_create_replace_provenance(
    migrated_file_sqlcipher_path, sqlcipher_memory_runtime_factory, approved_create, approved_replace,
):
    first = await sqlcipher_memory_runtime_factory.open(migrated_file_sqlcipher_path)
    created = await first.apply(approved_create)
    replaced = await first.apply(approved_replace.for_target(created.memory_id, created.version))
    await first.checkpoint_and_close()

    restarted = await sqlcipher_memory_runtime_factory.open(migrated_file_sqlcipher_path)
    current = await restarted.memories.require(created.memory_id)
    revisions = await restarted.memory_revisions.for_memory(created.memory_id)
    assert current.approved_proposal_id == approved_replace.approved_proposal_id
    assert [(item.version, item.operation, item.proposal_id) for item in revisions] == [
        (1, "create", approved_create.approved_proposal_id),
        (2, "replace", approved_replace.approved_proposal_id),
    ]
    assert restarted.reconstruct(current).content == replaced.content


@pytest.mark.asyncio
async def test_migrated_schema_enforces_non_null_proposal_fks(migrated_file_sqlcipher):
    memories = await migrated_file_sqlcipher.columns("memories")
    revisions = await migrated_file_sqlcipher.columns("memory_revisions")
    foreign_keys = await migrated_file_sqlcipher.foreign_keys()
    assert memories["approved_proposal_id"].nullable is False
    assert revisions["proposal_id"].nullable is False
    assert ("memories", "approved_proposal_id", "memory_proposals", "id") in foreign_keys
    assert ("memory_revisions", "proposal_id", "memory_proposals", "id") in foreign_keys
```

```python
# tests/unit/memory/test_persistence_mappers.py
def test_memory_row_mapper_does_not_return_persistence_model(memory_row_mapper, persisted_memory_row, decrypted_content):
    record = memory_row_mapper.to_contract(persisted_memory_row, decrypted_content)
    assert record.__class__.__name__ == "MemoryRecord"
    assert record.memory_id == persisted_memory_row.id
    assert not hasattr(record, "ciphertext") and not hasattr(record, "wrapped_dek")

def test_memory_audit_mapper_returns_explicit_audit_draft(memory_audit_mapper, persisted_memory_row, auth):
    draft = memory_audit_mapper.created(persisted_memory_row, auth)
    assert draft.__class__.__name__ == "AuditDraft"
    assert not hasattr(persisted_memory_row, "to_audit")
```

```python
# tests/security/test_memory_admin_visibility.py
import pytest
from tuntun_core.domain.profile import ProfileClass

@pytest.mark.asyncio
@pytest.mark.parametrize(("principal_case", "body_visible"), [
    ("adult_subject", True), ("owner_not_subject", False),
    ("current_primary_guardian", True), ("stale_guardian", False),
    ("other_adult", False), ("other_k2", False), ("other_n1", False), ("guest", False),
])
async def test_admin_role_never_bypasses_subject_audience_or_guardian_policy(projection_policy, adult_private_or_child_fixture, principal_factory, principal_case, body_visible, uow):
    view = await projection_policy.project(adult_private_or_child_fixture.for_case(principal_case), principal_factory(principal_case), uow)
    assert hasattr(view, "content") is body_visible
    if principal_case == "owner_not_subject":
        assert view.projection_kind == "opaque_admin"
        assert set(view.model_dump()) == {"projection_kind", "opaque_id", "kind", "state", "sensitivity_band", "created_at", "review_at", "expires_at", "storage_impact", "count_impact", "consent_health"}
    elif not body_visible:
        assert view is None

@pytest.mark.asyncio
@pytest.mark.parametrize("principal_case", ["adult_subject", "current_primary_guardian", "other_adult", "k2", "n1", "guest"])
async def test_policy_memory_body_is_owner_only(projection_policy, policy_memory, principal_factory, principal_case, uow):
    assert await projection_policy.project(policy_memory, principal_factory(principal_case), uow) is None

@pytest.mark.asyncio
async def test_current_owner_may_view_policy_memory_body(projection_policy, policy_memory, current_owner, uow):
    view = await projection_policy.project(policy_memory, current_owner, uow)
    assert view.projection_kind == "body"
    assert view.content.kind == "policy"

@pytest.mark.asyncio
@pytest.mark.parametrize("invalid_audience", ["subject_private", "household_adults"])
async def test_child_durable_memory_rejects_non_guardian_audience(memory_service, child_subject, current_guardian, invalid_audience):
    with pytest.raises(ValueError, match="child_durable_audience_invalid"):
        await memory_service.create_approved_child_memory(
            child_subject, current_guardian, audience=invalid_audience
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("profile_class", [ProfileClass.K2, ProfileClass.N1])
@pytest.mark.parametrize("authority_case", ["missing_consent", "revoked_consent", "stale_guardian", "restored_missing_binding", "restored_bad_household_all_approval"])
async def test_child_body_authority_fails_before_decryption(projection_policy, child_memory_authority_case_factory, child_principal_factory, decrypt_spy, profile_class, authority_case, uow):
    record = child_memory_authority_case_factory(profile_class=profile_class, authority_case=authority_case, decrypt_spy=decrypt_spy)
    principal = child_principal_factory(profile_class, subject_id=record.subject_id)
    assert await projection_policy.project(record, principal, uow) is None
    assert decrypt_spy.calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("profile_class", [ProfileClass.K2, ProfileClass.N1])
async def test_both_child_classes_cannot_view_adult_private_or_household_adults(projection_policy, child_principal_factory, adult_private_memory, household_adults_memory, profile_class, uow):
    principal = child_principal_factory(profile_class)
    assert await projection_policy.may_view_body(adult_private_memory.metadata_only(), principal, uow) is False
    assert await projection_policy.may_view_body(household_adults_memory.metadata_only(), principal, uow) is False


@pytest.mark.asyncio
@pytest.mark.parametrize("profile_class", [ProfileClass.K2, ProfileClass.N1])
@pytest.mark.parametrize(("audience", "body_visible"), [
    ("subject_private", False),
    ("household_adults", False),
    ("guardian_child", True),
    ("household_all", True),
])
async def test_both_child_classes_see_only_own_guardian_or_child_safe_household_audience(projection_policy, approved_child_memory_factory, child_principal_factory, profile_class, audience, body_visible, uow):
    # The factory's household_all case carries the current guardian's explicit
    # child-safe approval; invalid/restored household_all rows are quarantined.
    record = approved_child_memory_factory(profile_class=profile_class, audience=audience)
    principal = child_principal_factory(profile_class, subject_id=record.subject_id)
    assert await projection_policy.may_view_body(record.metadata_only(), principal, uow) is body_visible
```

```python
# tests/integration/memory/test_concurrency.py
import asyncio
import pytest

@pytest.mark.asyncio
async def test_exactly_one_expected_version_writer_wins(memory_mutations, approved_memory):
    created = await memory_mutations.create_approved_for_test(approved_memory)
    results = await asyncio.gather(memory_mutations.replace_approved_for_test(created.memory_id, 1, approved_memory.with_value("a")), memory_mutations.replace_approved_for_test(created.memory_id, 1, approved_memory.with_value("b")), return_exceptions=True)
    assert sum(not isinstance(item, Exception) for item in results) == 1
    assert sum(isinstance(item, StaleMemoryVersion) for item in results) == 1
```

```python
# tests/security/test_procedural_memory.py
def test_procedure_is_inert(procedural_memory):
    assert procedural_memory.content.steps == ("open the timer screen", "choose five minutes")
    assert not hasattr(procedural_memory.content, "execute")
```

```python
# tests/benchmark/test_memory_repository_10k.py
def test_active_core_mac_scoped_query_over_10k(benchmark, seeded_repository_10k, owner_query):
    result = benchmark(lambda: seeded_repository_10k.query_sync(owner_query))
    assert len(result) <= 6
    assert benchmark.stats.stats.mean < 0.100
```

- [ ] **Step 2: Run red tests**

Run: `uv run pytest tests/integration/memory/test_repository.py tests/unit/memory/test_persistence_mappers.py tests/integration/memory/test_revisions.py tests/integration/memory/test_concurrency.py tests/security/test_memory_isolation.py tests/security/test_memory_admin_visibility.py tests/security/test_procedural_memory.py tests/benchmark/test_memory_repository_10k.py -q`
Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core.services.memory.repository'`.

- [ ] **Step 3: Implement typed schemas, scoped queries, and migration**

```python
# apps/core/src/tuntun_core/services/memory/schemas.py
from tuntun_contracts.memory import EpisodicContent, MemoryAudience, MemoryContent, MemoryKind, PolicyContent, PreferenceContent, ProceduralContent, RelationalContent, SemanticContent, WorkingContent
__all__ = ["EpisodicContent","MemoryAudience","MemoryContent","MemoryKind","PolicyContent","PreferenceContent","ProceduralContent","RelationalContent","SemanticContent","WorkingContent"]
```

```python
# apps/core/src/tuntun_core/services/memory/revisions.py
from datetime import timedelta

def default_expiry(kind, *, now, session_ends_at=None):
    if kind == "working":
        if session_ends_at is None:
            raise ValueError("working_memory_requires_session_end")
        return session_ends_at + timedelta(minutes=30)
    if kind == "episodic":
        return now + timedelta(days=180)
    if kind in {"semantic", "preference", "procedural", "relational"}:
        return None
    return None

def next_review_at(kind, *, now):
    if kind in {"semantic", "preference", "procedural", "relational"}:
        return now + timedelta(days=365)
    return None
```

```python
# apps/core/src/tuntun_core/services/memory/scoping.py
RECALLABLE_STATUSES = frozenset({"approved"})

def require_scoped_query(query):
    if query.household_id is None or query.subject_id is None:
        raise PermissionError("memory_scope_required")
    return query
```

```python
# apps/core/src/tuntun_core/services/memory/projection.py
from tuntun_core.domain.profile import ConsentPurpose, ProfileClass
from tuntun_core.services.identity.consent import ConsentDenied

CHILD_PROFILE_CLASSES = frozenset({ProfileClass.K2, ProfileClass.N1})

class MemoryProjectionPolicy:
    async def _current_child_authority(self, metadata, uow) -> bool:
        if not metadata.subject_is_child:
            return True
        try:
            profile = await uow.profiles.get_scoped(metadata.household_id, metadata.subject_id)
            receipt = await self._consents.require_current_in_uow(
                uow, metadata.subject_id, ConsentPurpose.CHILD_DURABLE_MEMORY, self._clock.now()
            )
        except (ConsentDenied, LookupError):
            return False
        if not profile.active or profile.profile_class not in CHILD_PROFILE_CLASSES:
            return False
        exact_authority = (
            receipt.id == metadata.child_consent_receipt_id
            and receipt.guardian_id == profile.guardian_id == metadata.guardian_id
            and receipt.guardian_generation == profile.guardian_generation == metadata.guardian_generation
        )
        if not exact_authority:
            return False
        if metadata.audience == "household_all" and metadata.child_safe_audience_approval_grant_id is None:
            return False
        return metadata.audience in {"guardian_child", "household_all"}

    async def may_view_body(self, metadata, principal, uow) -> bool:
        if principal.is_guest or principal.household_id != metadata.household_id:
            return False
        if metadata.kind == "policy":
            return principal.is_current_owner
        if metadata.subject_is_child and not await self._current_child_authority(metadata, uow):
            return False
        if principal.profile_class in CHILD_PROFILE_CLASSES:
            return principal.subject_id == metadata.subject_id and metadata.audience in {"guardian_child", "household_all"}
        if principal.subject_id == metadata.subject_id:
            return True
        if await uow.guardians.is_current_primary(
            principal.subject_id, metadata.subject_id, expected_generation=metadata.guardian_generation
        ):
            return metadata.subject_is_child and metadata.audience in {"guardian_child", "household_all"}
        if metadata.audience == "household_adults":
            return principal.profile_class in {ProfileClass.OWNER, ProfileClass.ADULT}
        if metadata.audience == "household_all":
            return principal.profile_class in {ProfileClass.OWNER, ProfileClass.ADULT}
        return False

    async def may_administer_opaque_lifecycle(self, metadata, principal, uow) -> bool:
        if principal.is_guest or principal.household_id != metadata.household_id:
            return False
        if principal.is_current_owner:
            return True
        if not metadata.subject_is_child:
            return False
        return await uow.guardians.is_current_primary(
            principal.subject_id,
            metadata.subject_id,
            expected_generation=metadata.guardian_generation,
        )

    async def project(self, encrypted_record, principal, uow):
        metadata = encrypted_record.metadata_only()
        if await self.may_view_body(metadata, principal, uow):
            return MemoryBodyView.from_record(metadata, content=await encrypted_record.decrypt_in_uow(uow))
        if await self.may_administer_opaque_lifecycle(metadata, principal, uow):
            return OpaqueAdminMemoryView.from_safe_lifecycle(metadata)
        return None
```

`MemoryProjection = Annotated[OpaqueAdminMemoryView | MemoryBodyView, Field(discriminator="projection_kind")]` is a closed response union; `None` is serialized as the same not-found response used for an unknown identifier. `OpaqueAdminMemoryView` contains exactly `projection_kind`, a request-scoped opaque ID, kind, lifecycle state, coarse sensitivity band, created/review/expiry times, bounded storage/count impact, and consent health. It has no stable canonical ID, subject/audience detail, title, source wording, reason, claim, provenance, keyed/content commitment, content length, ciphertext size, embedding, or other body-derived field. `MemoryBodyView` adds typed content only for an independently authorized audience member. The projector receives a server-authenticated principal and server-loaded current guardian/lifecycle authority; the browser cannot submit either as authority. Profile classes are exactly `owner|adult|k2|n1|guest`; there is no `child` alias. A `household_all` child read is reachable only for a record that has already passed the current guardian's explicit child-safe audience approval and restore quarantine checks; `guardian_child` remains subject/guardian-scoped. Owner status is intentionally absent from the `subject_private` body branch. Proposal, memory, approval, export, search, count, and audit read models must call this projector before body decryption and must use indistinguishable empty/not-found behavior for callers without body or lifecycle authority.

```python
# apps/core/src/tuntun_core/services/memory/mappers.py
from tuntun_contracts.audit import AuditDraft
from tuntun_contracts.base import Sensitivity
from tuntun_contracts.memory import MemoryAudience, MemoryRecord

class MemoryPersistenceMapper:
    def __init__(self, times): self._times = times
    def to_contract(self, row, content):
        return MemoryRecord(
            memory_id=row.id, household_id=row.household_id, subject_id=row.subject_id,
            version=row.version, content=content, audience=MemoryAudience(row.audience),
            sensitivity=Sensitivity(row.sensitivity), valid_until=self._times.optional_aware(row.valid_until),
        )

class MemoryAuditDraftMapper:
    def __init__(self, ids, clock, pseudonyms, commitments):
        self._ids, self._clock, self._pseudonyms, self._commitments = ids, clock, pseudonyms, commitments

    def created(self, row, auth): return self._draft("memory.create", row, auth, "created")
    def replaced(self, row, auth, previous_revision_id): return self._draft("memory.replace", row, auth, f"replaced:{previous_revision_id}")
    def erased(self, row, auth, stores): return self._draft("memory.delete", row, auth, "managed_erasure:" + ",".join(stores))
    def tombstoned(self, row, auth): return self._draft("memory.delete.tombstone", row, auth, "tombstoned")

    def _draft(self, action, row, auth, reason):
        return AuditDraft(event_id=self._ids.uuid4(), occurred_at=self._clock.now(), actor_pseudonym=self._pseudonyms.for_subject(row.household_id, auth.subject_id), action_code=action, outcome="executed", reason_code=reason, correlation_id=row.id, payload_commitment=self._commitments.memory_row(row))
```

```python
# apps/core/src/tuntun_core/services/memory/repository.py
from tuntun_core.domain.profile import ConsentPurpose, ProfileClass
from tuntun_core.services.identity.consent import ConsentDenied

class SqlCipherMemoryRepository:
    def __init__(self, mutation_scope, uow_factory, consents, proposal_validator, row_mapper, audit_mapper, binding_verifier, binding_builder, audit_ledger, clock):
        self._scope, self._uow_factory, self._consents = mutation_scope, uow_factory, consents
        self._proposal_validator, self._row_mapper, self._audit_mapper = proposal_validator, row_mapper, audit_mapper
        self._binding_verifier, self._binding_builder = binding_verifier, binding_builder
        self._audit, self._clock = audit_ledger, clock

    async def create(self, memory, expected_absent=True):
        uow = self._scope.require_active_uow()
        proposal = await uow.memory_proposals.lock(memory.approved_proposal_id)
        self._proposal_validator.require_exact_approved(
            proposal, operation="create", approved_memory=memory,
            target_memory_id=None, expected_version=None,
        )
        if expected_absent and await uow.memories.exists(memory.memory_id): raise MemoryAlreadyExists(memory.memory_id)
        created = await uow.memories.insert(
            self._encrypt_and_validate(memory), version=1,
            approved_proposal_id=proposal.id,
        )
        await uow.memory_revisions.append(created, proposal_id=proposal.id, operation="create")
        record = self._row_mapper.to_contract(created, memory.content)
        await self._audit.append(uow, self._audit_mapper.created(created, self._scope.require_auth()))
        return record

    async def query(self, query):
        if query.subject_id is None:
            return ()
        if query.limit > 6:
            raise ValueError("memory_limit_exceeds_six")
        async with self._uow_factory() as uow:
            profile = await uow.profiles.get_scoped(query.household_id, query.subject_id)
            if not profile.active or profile.revoked_at is not None:
                return ()
            try: await self._consents.require_current_in_uow(uow, query.subject_id, ConsentPurpose.PERSONALIZATION, self._clock.now())
            except ConsentDenied: return ()
            child_authority = None
            if profile.profile_class in {ProfileClass.K2, ProfileClass.N1}:
                try:
                    consent = await self._consents.require_current_in_uow(
                        uow, query.subject_id, ConsentPurpose.CHILD_DURABLE_MEMORY, self._clock.now()
                    )
                except ConsentDenied:
                    return ()
                child_authority = {
                    "child_consent_receipt_id": consent.id,
                    "guardian_id": profile.guardian_id,
                    "guardian_generation": profile.guardian_generation,
                }
            rows = await uow.memories.query_recallable_authorized(
                household_id=query.household_id,
                subject_id=query.subject_id,
                kinds=query.kinds,
                maximum_sensitivity=query.maximum_sensitivity,
                child_authority=child_authority,
                child_audiences=("guardian_child", "household_all"),
                require_household_all_approval=True,
                now=self._clock.now(),
                limit=query.limit,
            )
            # The SQL predicate above is repeated under the same transaction
            # immediately before AEAD opens any candidate.
            decrypted = []
            for row in rows:
                if child_authority is not None:
                    await uow.memories.require_exact_child_authority(row.id, **child_authority)
                decrypted.append(self._decrypt_and_validate(row))
            return tuple(decrypted)

    async def replace(self, memory_id, expected_version, memory):
        uow = self._scope.require_active_uow()
        current = await uow.memories.lock(memory_id)
        if current.version != expected_version: raise StaleMemoryVersion(memory_id)
        proposal = await uow.memory_proposals.lock(memory.approved_proposal_id)
        self._proposal_validator.require_exact_approved(
            proposal, operation="replace", approved_memory=memory,
            target_memory_id=memory_id, expected_version=expected_version,
        )
        previous_revision = await uow.memory_revisions.require_version(memory_id, expected_version)
        updated = await uow.memories.replace(
            current, memory, version=expected_version + 1,
            approved_proposal_id=proposal.id,
        )
        await uow.memory_revisions.append(updated, proposal_id=proposal.id, operation="replace")
        record = self._row_mapper.to_contract(updated, memory.content)
        await self._audit.append(uow, self._audit_mapper.replaced(updated, self._scope.require_auth(), previous_revision.id))
        return record

    async def delete(self, memory_id, expected_version, auth, approved_proposal_id):
        uow = self._scope.require_active_uow()
        current = await uow.memories.lock(memory_id)
        if current.version != expected_version: raise StaleMemoryVersion(memory_id)
        self._binding_verifier.require_exact(self._binding_builder.memory_delete(current), auth.binding)
        proposal = await uow.memory_proposals.lock(approved_proposal_id)
        self._proposal_validator.require_exact_approved(
            proposal, operation="delete", approved_memory=None,
            target_memory_id=memory_id, expected_version=expected_version,
        )
        await uow.memory_revisions.append_tombstone(
            current.metadata_only(), proposal_id=proposal.id, operation="delete"
        )
        await uow.memories.delete_row_with_wrapped_dek(memory_id)
        await uow.memory_revisions.authorized_crypto_shred_content(memory_id)
        await self._audit.append(
            uow,
            self._audit_mapper.erased(current, auth, stores=("sqlcipher_wal", "managed_backup")),
        )
        await self._audit.append(uow, self._audit_mapper.tombstoned(current, auth))
```

`MemoryProposalWriteValidator.require_exact_approved` accepts only `status='approved'` and compares the proposal ID, operation, household, subject, kind, audience, sensitivity, decrypted typed content commitment, exact source-receipt set, target ID, and expected version to the requested mutation. A mismatch is `exact_approved_memory_proposal_required` before either the current row or its revision is written. Create and replace revisions record the newly materialized version—not a second copy of the prior version—and both the current row and immutable revision carry the same approving proposal FK. Delete receives the finalized memory proposal ID separately from the outer action authorization, then validates that approved delete proposal before appending its tombstone. Confusing the outer action proposal ID with the approved memory proposal ID fails before any tombstone or current-row write. These checks run in the mutation's single SQLCipher transaction.

```python
# apps/core/migrations/versions/0004_memory.py
from alembic import op
import sqlalchemy as sa

revision = "0004_memory"
down_revision = "0003_authentication"

def upgrade() -> None:
    op.create_table(
        "memory_proposals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("schema_version", sa.String(16), nullable=False),
        sa.Column("household_id", sa.String(36), sa.ForeignKey("households.id"), nullable=False),
        sa.Column("subject_id", sa.String(36), sa.ForeignKey("subjects.id"), nullable=False),
        sa.Column("subject_authority_generation", sa.Integer, nullable=False),
        sa.Column("session_id", sa.String(36), sa.ForeignKey("sessions.id"), nullable=False),
        sa.Column("turn_id", sa.String(36), nullable=False),
        sa.Column("idempotency_key", sa.String(36), nullable=False),
        sa.Column("operation", sa.String(16), nullable=False),
        sa.Column("kind", sa.String(16)),
        sa.Column("audience", sa.String(32)),
        sa.Column("target_memory_id", sa.String(36)),
        sa.Column("expected_version", sa.Integer),
        sa.Column("sensitivity", sa.String(16), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary),
        sa.Column("nonce", sa.LargeBinary),
        sa.Column("reason_ciphertext", sa.LargeBinary, nullable=False),
        sa.Column("reason_nonce", sa.LargeBinary, nullable=False),
        sa.Column("wrapped_dek", sa.LargeBinary, nullable=False),
        sa.Column("root_key_id", sa.String(128), nullable=False),
        sa.Column("child_consent_receipt_id", sa.String(36), sa.ForeignKey("consent_receipts.id")),
        sa.Column("guardian_id", sa.String(36), sa.ForeignKey("subjects.id")),
        sa.Column("guardian_generation", sa.Integer),
        sa.Column("scope_commitment_hmac", sa.LargeBinary, nullable=False),
        sa.Column("required_factor", sa.String(32)),
        sa.Column("confidence_micros", sa.Integer, nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", sa.String(27), nullable=False),
        sa.Column("draft_expires_at", sa.String(27), nullable=False),
        sa.Column("expires_at", sa.String(27), nullable=False),
        sa.Column("decision_source", sa.String(32)),
        sa.Column("decision_receipt_id", sa.String(36)),
        sa.Column("decided_at", sa.String(27)),
        sa.Column("source_receipt_ids", sa.LargeBinary, nullable=False),
        sa.Column("commitment_key_id", sa.String(128), nullable=False),
        sa.Column("claim_commitment_hmac", sa.LargeBinary, nullable=False),
        sa.Column("draft_commitment_hmac", sa.LargeBinary, nullable=False),
        sa.CheckConstraint("schema_version='1.0'"),
        sa.CheckConstraint("operation IN ('create','replace','delete')"),
        sa.CheckConstraint("audience IS NULL OR audience IN ('subject_private','guardian_child','household_adults','household_all')"),
        sa.CheckConstraint("sensitivity IN ('public','household','personal','sensitive','restricted')"),
        sa.CheckConstraint("required_factor IS NULL OR required_factor IN ('pin','passkey')"),
        sa.CheckConstraint("status IN ('pending','approved','rejected','expired')"),
        sa.CheckConstraint("confidence_micros BETWEEN 0 AND 1000000"),
        sa.CheckConstraint("subject_authority_generation >= 1"),
        sa.CheckConstraint("(child_consent_receipt_id IS NULL AND guardian_id IS NULL AND guardian_generation IS NULL) OR (child_consent_receipt_id IS NOT NULL AND guardian_id IS NOT NULL AND guardian_generation >= 1 AND audience IN ('guardian_child','household_all'))"),
        sa.CheckConstraint("(operation='create' AND target_memory_id IS NULL AND expected_version IS NULL AND kind IS NOT NULL AND audience IS NOT NULL AND ciphertext IS NOT NULL AND nonce IS NOT NULL) OR (operation='replace' AND target_memory_id IS NOT NULL AND expected_version >= 1 AND kind IS NOT NULL AND audience IS NOT NULL AND ciphertext IS NOT NULL AND nonce IS NOT NULL) OR (operation='delete' AND target_memory_id IS NOT NULL AND expected_version >= 1 AND kind IS NULL AND audience IS NULL AND ciphertext IS NULL AND nonce IS NULL)"),
        sa.CheckConstraint("(status='pending' AND decision_source IS NULL AND decision_receipt_id IS NULL AND decided_at IS NULL) OR (status='approved' AND decision_source IN ('auth_grant','system_working_summary') AND decision_receipt_id IS NOT NULL AND decided_at IS NOT NULL) OR (status='rejected' AND decision_source='auth_grant' AND decision_receipt_id IS NOT NULL AND decided_at IS NOT NULL) OR (status='expired' AND decision_source='system_expiry' AND decision_receipt_id IS NOT NULL AND decided_at IS NOT NULL)"),
        sa.UniqueConstraint("household_id", "session_id", "idempotency_key", name="uq_memory_proposal_idempotency"),
        sa.UniqueConstraint("household_id", "turn_id", "commitment_key_id", "claim_commitment_hmac", name="uq_memory_proposal_turn_claim"),
    )
    op.create_table("memories", sa.Column("id", sa.String(36), primary_key=True), sa.Column("household_id", sa.String(36), sa.ForeignKey("households.id"), nullable=False), sa.Column("subject_id", sa.String(36), sa.ForeignKey("subjects.id"), nullable=False), sa.Column("approved_proposal_id", sa.String(36), sa.ForeignKey("memory_proposals.id"), nullable=False), sa.Column("kind", sa.String(16), nullable=False), sa.Column("audience", sa.String(32), nullable=False), sa.Column("sensitivity", sa.String(16), nullable=False), sa.Column("ciphertext", sa.LargeBinary, nullable=False), sa.Column("nonce", sa.LargeBinary, nullable=False), sa.Column("wrapped_dek", sa.LargeBinary, nullable=False), sa.Column("root_key_id", sa.String(128), nullable=False), sa.Column("status", sa.String(16), nullable=False), sa.Column("version", sa.Integer, nullable=False), sa.Column("confidence_micros", sa.Integer, nullable=False), sa.Column("source_kind", sa.String(32), nullable=False), sa.Column("valid_from", sa.String(27), nullable=False), sa.Column("valid_until", sa.String(27)), sa.Column("next_review_at", sa.String(27)), sa.Column("approved_at", sa.String(27), nullable=False), sa.Column("approval_source", sa.String(32), nullable=False), sa.Column("approved_by_grant_id", sa.String(36)), sa.Column("approved_by_system_receipt_id", sa.String(36)), sa.Column("consent_receipt_id", sa.String(36), sa.ForeignKey("consent_receipts.id")), sa.Column("child_consent_receipt_id", sa.String(36), sa.ForeignKey("consent_receipts.id")), sa.Column("guardian_id", sa.String(36), sa.ForeignKey("subjects.id")), sa.Column("guardian_generation", sa.Integer), sa.Column("child_safe_audience_approval_grant_id", sa.String(36), sa.ForeignKey("auth_grants.id")), sa.Column("source_receipt_ids", sa.LargeBinary, nullable=False), sa.Column("commitment_key_id", sa.String(128), nullable=False), sa.Column("content_commitment_hmac", sa.LargeBinary, nullable=False), sa.CheckConstraint("kind IN ('working','episodic','semantic','preference','procedural','relational','policy')"), sa.CheckConstraint("audience IN ('subject_private','guardian_child','household_adults','household_all')"), sa.CheckConstraint("sensitivity IN ('public','household','personal','sensitive','restricted')"), sa.CheckConstraint("status IN ('approved','superseded','revoked','quarantined')"), sa.CheckConstraint("approval_source IN ('auth_grant','system_working_summary')"), sa.CheckConstraint("(approval_source='auth_grant' AND approved_by_grant_id IS NOT NULL AND approved_by_system_receipt_id IS NULL) OR (approval_source='system_working_summary' AND kind='working' AND approved_by_grant_id IS NULL AND approved_by_system_receipt_id IS NOT NULL)"), sa.CheckConstraint("(child_consent_receipt_id IS NULL AND guardian_id IS NULL AND guardian_generation IS NULL AND child_safe_audience_approval_grant_id IS NULL) OR (child_consent_receipt_id IS NOT NULL AND guardian_id IS NOT NULL AND guardian_generation >= 1 AND audience IN ('guardian_child','household_all') AND approval_source='auth_grant' AND (audience!='household_all' OR child_safe_audience_approval_grant_id IS NOT NULL))"), sa.CheckConstraint("version >= 1"), sa.CheckConstraint("confidence_micros BETWEEN 0 AND 1000000"))
    op.create_index("ix_memories_scope_recall", "memories", ["household_id", "subject_id", "status", "kind", "valid_until"])
    op.create_table("memory_revisions", sa.Column("id", sa.String(36), primary_key=True), sa.Column("memory_id", sa.String(36), nullable=False), sa.Column("proposal_id", sa.String(36), sa.ForeignKey("memory_proposals.id"), nullable=False), sa.Column("version", sa.Integer, nullable=False), sa.Column("operation", sa.String(16), nullable=False), sa.Column("kind", sa.String(16), nullable=False), sa.Column("audience", sa.String(32), nullable=False), sa.Column("ciphertext", sa.LargeBinary), sa.Column("nonce", sa.LargeBinary), sa.Column("wrapped_dek", sa.LargeBinary), sa.Column("root_key_id", sa.String(128)), sa.Column("commitment_key_id", sa.String(128), nullable=False), sa.Column("content_commitment_hmac", sa.LargeBinary, nullable=False), sa.Column("source_receipt_ids", sa.LargeBinary, nullable=False), sa.Column("confidence_micros", sa.Integer, nullable=False), sa.Column("valid_from", sa.String(27), nullable=False), sa.Column("valid_until", sa.String(27)), sa.Column("next_review_at", sa.String(27)), sa.Column("approved_at", sa.String(27), nullable=False), sa.Column("approval_source", sa.String(32), nullable=False), sa.Column("approved_by_grant_id", sa.String(36)), sa.Column("approved_by_system_receipt_id", sa.String(36)), sa.Column("child_consent_receipt_id", sa.String(36)), sa.Column("guardian_id", sa.String(36)), sa.Column("guardian_generation", sa.Integer), sa.Column("child_safe_audience_approval_grant_id", sa.String(36)), sa.Column("created_at", sa.String(27), nullable=False), sa.CheckConstraint("operation IN ('create','replace','delete','crypto_shred')"), sa.CheckConstraint("kind IN ('working','episodic','semantic','preference','procedural','relational','policy')"), sa.CheckConstraint("audience IN ('subject_private','guardian_child','household_adults','household_all')"), sa.CheckConstraint("approval_source IN ('auth_grant','system_working_summary')"), sa.CheckConstraint("(approval_source='auth_grant' AND approved_by_grant_id IS NOT NULL AND approved_by_system_receipt_id IS NULL) OR (approval_source='system_working_summary' AND kind='working' AND approved_by_grant_id IS NULL AND approved_by_system_receipt_id IS NOT NULL)"), sa.CheckConstraint("(child_consent_receipt_id IS NULL AND guardian_id IS NULL AND guardian_generation IS NULL AND child_safe_audience_approval_grant_id IS NULL) OR (child_consent_receipt_id IS NOT NULL AND guardian_id IS NOT NULL AND guardian_generation >= 1 AND audience IN ('guardian_child','household_all'))"), sa.CheckConstraint("(operation IN ('delete','crypto_shred') AND ciphertext IS NULL AND wrapped_dek IS NULL) OR (operation IN ('create','replace') AND ciphertext IS NOT NULL AND wrapped_dek IS NOT NULL)"), sa.UniqueConstraint("memory_id", "version"))
    op.execute("CREATE TRIGGER memory_revisions_no_update BEFORE UPDATE ON memory_revisions WHEN tuntun_crypto_shred_authorized() != 1 BEGIN SELECT RAISE(ABORT,'memory_revisions_append_only'); END")
    op.execute("CREATE TRIGGER memory_revisions_no_delete BEFORE DELETE ON memory_revisions BEGIN SELECT RAISE(ABORT,'memory_revisions_append_only'); END")

def downgrade() -> None:
    op.execute("DROP TRIGGER memory_revisions_no_delete")
    op.execute("DROP TRIGGER memory_revisions_no_update")
    op.drop_table("memory_revisions")
    op.drop_index("ix_memories_scope_recall", table_name="memories")
    op.drop_table("memories")
    op.drop_table("memory_proposals")
```

`memory_proposals` is the lossless encrypted persistence projection of the foundation `MemoryProposalDraft`: it keeps the exact schema/proposal/household/subject/session/turn/idempotency/operation/target/version/audience/sensitivity/confidence/provenance/claim/expiry fields, encrypts both typed content and the bounded reason under the proposal DEK, and separates the mapper draft-validity expiry from the 30-day pending lifecycle expiry. The local mapper assigns ordinary adult creates `subject_private`; a provider cannot nominate a broader audience. A durable child proposal is valid only as `guardian_child` or as explicitly child-safe `household_all`, stores the exact current `child_durable_memory_v1` receipt, guardian ID, and guardian generation before persistence, and can never take the working-summary auto-apply route. Its separate exact guardian approval is rechecked against those values immediately before mutation; `household_all` additionally persists the approving grant ID as its child-safe-audience proof. Child `subject_private` and `household_adults` fail before persistence, and invalid legacy/restore rows are marked `quarantined` before any candidate lookup until guardian conversion or deletion. Reassignment never rewrites authority: it cancels pending proposals and existing rows remain hidden until an explicitly authorized reapproval creates a new revision. Any later audience expansion is a separately prepared exact approval bound to the target record/version and new audience. The full-draft HMAC detects an idempotency-key collision with changed input; the claim HMAC suppresses same-turn re-proposal without storing low-entropy plaintext.

`system_approval_receipts` is a typed facade over foundation `idempotency_receipts` with operation `memory.working_summary.auto_apply`, exact household/subject/session/turn/proposal scope, the content commitment, and the short expiry. It is not an `AuthGrant`; the mutually exclusive approval-source checks on both current records and immutable revisions restrict this source to `kind='working'` and prevent it from masquerading as one. The single internal `apply_system_approved_working_summary` operation revalidates that exact receipt and approved proposal, then writes the current row and version-1 revision with the same non-null proposal ID in the staging transaction; it cannot accept any other memory kind or approval source.

- [ ] **Step 4: Run green, isolation, and migration tests**

Run: `uv run pytest tests/integration/memory/test_repository.py tests/unit/memory/test_persistence_mappers.py tests/integration/memory/test_revisions.py tests/integration/memory/test_concurrency.py tests/security/test_memory_isolation.py tests/security/test_memory_admin_visibility.py tests/security/test_procedural_memory.py tests/benchmark/test_memory_repository_10k.py tests/integration/storage/test_migrations.py -q`
Expected: PASS; 1,000 randomized isolation examples produce zero unauthorized records; child `subject_private`/`household_adults` proposals and restored rows are rejected/quarantined; owner-not-subject, stale-guardian, other-profile, and Guest projections omit bodies and content-derived length hints. Forged, pending, wrong-operation/target/version/source proposals fail before writes, the non-null current/revision proposal FKs survive a real file-backed SQLCipher close/reopen, versions reconstruct as create then replace, and migration `0004_memory` upgrades/downgrades cleanly.

- [ ] **Step 5: Check and commit**

Run: `uv run ruff format --check apps/core/src/tuntun_core/services/memory/schemas.py apps/core/src/tuntun_core/services/memory/repository.py apps/core/src/tuntun_core/services/memory/mappers.py apps/core/src/tuntun_core/services/memory/revisions.py apps/core/src/tuntun_core/services/memory/scoping.py apps/core/src/tuntun_core/services/memory/projection.py tests/integration/memory/test_repository.py tests/unit/memory/test_persistence_mappers.py tests/integration/memory/test_revisions.py tests/integration/memory/test_concurrency.py tests/security/test_memory_isolation.py tests/security/test_memory_admin_visibility.py tests/security/test_procedural_memory.py tests/benchmark/test_memory_repository_10k.py && uv run ruff check apps/core/src/tuntun_core/services/memory/schemas.py apps/core/src/tuntun_core/services/memory/repository.py apps/core/src/tuntun_core/services/memory/mappers.py apps/core/src/tuntun_core/services/memory/revisions.py apps/core/src/tuntun_core/services/memory/scoping.py apps/core/src/tuntun_core/services/memory/projection.py tests/integration/memory/test_repository.py tests/unit/memory/test_persistence_mappers.py tests/integration/memory/test_revisions.py tests/integration/memory/test_concurrency.py tests/security/test_memory_isolation.py tests/security/test_memory_admin_visibility.py tests/security/test_procedural_memory.py tests/benchmark/test_memory_repository_10k.py && uv run mypy apps/core/src/tuntun_core/services/memory`
Expected: PASS with exit code 0.

```bash
git add apps/core/src/tuntun_core/services/memory/schemas.py apps/core/src/tuntun_core/services/memory/repository.py apps/core/src/tuntun_core/services/memory/mappers.py apps/core/src/tuntun_core/services/memory/revisions.py apps/core/src/tuntun_core/services/memory/scoping.py apps/core/src/tuntun_core/services/memory/projection.py apps/core/migrations/versions/0004_memory.py tests/integration/memory/test_repository.py tests/unit/memory/test_persistence_mappers.py tests/integration/memory/test_revisions.py tests/integration/memory/test_concurrency.py tests/security/test_memory_isolation.py tests/security/test_memory_admin_visibility.py tests/security/test_procedural_memory.py tests/benchmark/test_memory_repository_10k.py
git diff --cached --name-only
git diff --cached
git commit -m "feat(memory): add scoped seven-kind repository"
```

### Task 10: Stage and approve derived memory claims

**Master coverage:** write-policy portion of Task 22
**Depends on:** Tasks 6–9 and master Tasks 04, 08, and 15–16
**Estimated effort:** 3 person-days

**Files:**
- Create: `apps/core/src/tuntun_core/services/memory/proposal_mapper.py`
- Create: `apps/core/src/tuntun_core/services/memory/proposals.py`
- Create: `apps/core/src/tuntun_core/services/memory/write_policy.py`
- Create: `apps/core/src/tuntun_core/services/memory/approval.py`
- Create: `apps/core/src/tuntun_core/services/actions/providers/memory.py`
- Modify: `apps/core/src/tuntun_core/services/identity/subject_revocation.py` (replace Task-1 memory placeholder after `0004`)
- Modify: `apps/core/src/tuntun_core/services/identity/subject_revocation_handlers.py` (register real memory reconciliation)
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py` (complete consent and subject-revocation handler registries)
- Modify: `apps/core/src/tuntun_core/bootstrap/lifecycle.py`
- Create: `prompts/memory/proposal-schema.json`
- Create: `tests/unit/memory/test_write_policy.py`
- Create: `tests/security/test_memory_write_policy.py`
- Create: `tests/security/test_memory_deletion.py`
- Create: `tests/integration/memory/test_memory_approval.py`
- Create: `tests/unit/actions/test_memory_action_provider.py`
- Modify: `tests/integration/identity/test_subject_revocation_handlers.py`

**Interfaces:**
- Consumes: strict provider-facing `ProviderMemoryIntent` with pseudonymous references only, local `ProposalContext`, `PolicyEnginePort`, `AuthenticationPort`, `MemoryRepositoryPort`, `AsyncUnitOfWork`, and foundation `AsyncAuditLedger`.
- Produces: an identity-layer `ProposalMapper.map_memory` facade over the conversation-owned mapper. It resolves the pseudonymous subject to a current server-loaded profile and fixes `audience=guardian_child` for K2/N1 or `subject_private` for owner/adult; a provider has no audience field and cannot choose or broaden it. `MemoryProposalService` explicitly receives `ConsentService`, implements `stage`, non-committing `stage_in_uow`, and the exact fail-closed two-argument `MemoryProposalServicePort.decide`. `stage` independently verifies the complete frozen draft—proposal/schema/household/subject/session/turn/idempotency identifiers, operation and typed content or target/version, audience, sensitivity, bounded reason/confidence, expiry, source receipt set, and purpose-separated claim commitment—against the exact `ProposalContext` and signed mapper attestation before persistence. The persistence projection losslessly round-trips every draft field, encrypts content and reason, and stores separate scope/full-draft/claim HMAC commitments; no premature decision binding is stored. Also produces non-committing `MemoryApprovalService.decide_in_uow`, `MemoryLocalActionProvider`, and the sole standalone decision entry point `MemoryMutationCoordinator.decide(command, decision_context, grant_id)`; the coordinator deterministically rebuilds the complete decision-specific binding (`memory.approve|memory.edit_approve|memory.reject|memory.delete`) before consuming the grant. The action provider receives an already-consumed `AuthContext` from `ActionMutationCoordinator` and calls `decide_in_uow` directly—never a second grant consume. Status is `pending|approved|rejected|expired`; grant consumption, proposal disposition, revision, memory mutation, and authorization/mutation audit outbox share one transaction.

After `0004_memory` is applied and the typed memory proposal repository is registered, Task 10 replaces both Task-1 `memory_authorities` placeholders with the real transactional and post-commit memory handlers. Final Phase-1 bootstrap reads the actual core and feature-version rows and enumerates both packaged migration namespaces before it registers a facade or constructs a handler. Every artifact contains exactly the linear core revisions `0001_foundation` through `0008_prepared_mutations`, with every declared parent equal to the preceding frozen ID and with no branch label, dependency, extra base, fork, merge, or orphan; the sole core `alembic_version` head is always `0008_prepared_mutations`. The absent-search artifact omits the experimental-search migration namespace and its `alembic_version_experimental_search` table. The enabled artifact independently packages exactly one feature base/head, `search_0001_experimental_search` with `down_revision=None`, no graph metadata, and that exact sole feature-version-table row. Core and feature IDs can therefore never fork or collide. Wrong, forked, multiple, feature-mismatched, missing, or extra packaged revisions/tables/heads fail before recovery/readiness. Only after that gate does bootstrap register all typed facades/providers, construct exact stage-matching handlers, and run bounded revocation recovery. Startup proves action and memory handlers are real, search is either its concrete enabled handler or the closed absent handler, and no installed capability retains a placeholder.

- [ ] **Step 1: Write failing write-matrix and transcript-sentinel tests**

```python
# tests/unit/memory/test_write_policy.py
import pytest

@pytest.mark.parametrize(("kind", "sensitivity", "outcome", "factor"), [
    ("working", "personal", "auto_apply", None),
    ("semantic", "household", "stage", None),
    ("preference", "sensitive", "stage", "pin"),
    ("episodic", "personal", "stage", "pin"),
    ("procedural", "household", "stage", "passkey"),
    ("relational", "personal", "stage", "passkey"),
    ("policy", "household", "stage", "passkey"),
])
def test_write_matrix(write_policy, draft_factory, kind, sensitivity, outcome, factor):
    decision = write_policy.decide(draft_factory(kind=kind, sensitivity=sensitivity))
    assert decision.outcome == outcome
    assert decision.required_factor == factor
```

```python
# tests/security/test_memory_write_policy.py
import pytest
from pydantic import ValidationError
from tuntun_core.services.providers.output_validator import ProviderMemoryIntent

@pytest.mark.asyncio
async def test_proposal_contains_derived_claim_not_transcript(proposal_service, transcript_sentinel_draft, context):
    proposal = await proposal_service.stage(transcript_sentinel_draft.draft, context)
    assert proposal.status == "pending"
    assert transcript_sentinel_draft.sentinel not in await proposal_service.test_storage_bytes()

@pytest.mark.asyncio
@pytest.mark.parametrize("changed", ["household_id", "subject_id", "session_id", "turn_id", "idempotency_key", "reason", "confidence_micros", "claim_commitment", "source_receipt_ids", "expires_at"])
async def test_memory_proposal_rejects_every_cross_scope_or_provenance_change(proposal_service, mapped_draft, context, changed, proposal_tamper):
    with pytest.raises(PermissionError, match="memory_proposal_(scope|provenance)_mismatch"):
        await proposal_service.stage(proposal_tamper.change(mapped_draft, context, changed), context)

@pytest.mark.asyncio
async def test_stage_round_trips_complete_frozen_draft(proposal_service, mapped_draft, context):
    staged = await proposal_service.stage(mapped_draft, context)
    assert staged.draft == mapped_draft
    projection = await proposal_service.test_persistence_projection(staged.draft.proposal_id)
    assert projection.exact_draft_fields() == mapped_draft

@pytest.mark.asyncio
async def test_same_idempotency_key_with_different_draft_fails_closed(proposal_service, mapped_draft, mapped_draft_same_idempotency_different_claim, context):
    await proposal_service.stage(mapped_draft, context)
    with pytest.raises(PermissionError, match="memory_proposal_idempotency_conflict"):
        await proposal_service.stage(mapped_draft_same_idempotency_different_claim, context)


@pytest.mark.asyncio
@pytest.mark.parametrize("profile_class", ["k2", "n1"])
@pytest.mark.parametrize("authority_case", ["missing_consent", "revoked_consent", "stale_guardian"])
async def test_child_proposal_never_persists_without_exact_current_authority(proposal_service, child_draft_factory, child_context_factory, memory_proposal_repository_spy, profile_class, authority_case):
    draft, context = child_draft_factory(profile_class=profile_class, authority_case=authority_case), child_context_factory(profile_class)
    with pytest.raises(PermissionError, match="child_memory_current_guardian_consent_required"):
        await proposal_service.stage(draft, context)
    assert memory_proposal_repository_spy.write_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("profile_class", ["k2", "n1"])
async def test_child_working_summary_is_ephemeral_and_never_auto_applied(proposal_service, child_working_draft_factory, child_context_factory, profile_class):
    with pytest.raises(PermissionError, match="child_working_context_must_be_ephemeral"):
        await proposal_service.stage(child_working_draft_factory(profile_class), child_context_factory(profile_class))

@pytest.mark.asyncio
@pytest.mark.parametrize("profile_class", ["k2", "n1"])
async def test_provider_child_mapper_server_derives_guardian_audience_and_guarded_stage_succeeds(memory_proposal_mapper, provider_child_intent_factory, child_context_factory, proposal_service, profile_class):
    context = child_context_factory(profile_class, current_guardian_consent=True)
    intent = provider_child_intent_factory(profile_class)
    with pytest.raises(ValidationError):
        ProviderMemoryIntent.model_validate(intent.model_dump() | {"audience": "household_all"})
    draft = await memory_proposal_mapper.map_memory(intent, context.household_id, context.session_id, context.turn_id)
    assert draft.audience.value == "guardian_child"
    assert "audience" not in ProviderMemoryIntent.model_fields
    assert (await proposal_service.stage(draft, context)).status == "pending"


@pytest.mark.asyncio
async def test_direct_memory_decide_fails_closed_without_coordinator_binding(memory_approval_service, pending_decision_command, valid_auth_context, memory_repository_spy):
    with pytest.raises(PermissionError, match="memory_decision_requires_coordinator"):
        await memory_approval_service.decide(pending_decision_command, valid_auth_context)
    assert memory_repository_spy.read_count == 0 and memory_repository_spy.write_count == 0

@pytest.mark.asyncio
async def test_frozen_memory_proposal_port_exposes_stage_and_fail_closed_decide(memory_proposal_port, pending_decision_command, valid_auth_context, memory_repository_spy):
    assert callable(memory_proposal_port.stage) and callable(memory_proposal_port.decide)
    with pytest.raises(PermissionError, match="memory_decision_requires_coordinator"):
        await memory_proposal_port.decide(pending_decision_command, valid_auth_context)
    assert memory_repository_spy.read_count == 0 and memory_repository_spy.write_count == 0
```

```python
# tests/integration/memory/test_memory_approval.py
import pytest

@pytest.mark.asyncio
async def test_approval_failure_rolls_back_grant_memory_disposition_and_audits(memory_coordinator, pending_proposal, approval_grant, fail_after_memory_write, auth_grants, memories, memory_proposals, audit_rows):
    with pytest.raises(RuntimeError, match="injected_memory_approval_failure"):
        await memory_coordinator.decide(pending_proposal.approve_command(), pending_proposal.decision_context, approval_grant.id)
    assert await auth_grants.is_consumed(approval_grant.id) is False
    assert await memory_proposals.status(pending_proposal.id) == "pending"
    assert await memories.for_proposal(pending_proposal.id) is None
    assert await audit_rows.for_proposal(pending_proposal.id) == ()


@pytest.mark.asyncio
@pytest.mark.parametrize("profile_class", ["k2", "n1"])
@pytest.mark.parametrize("authority_change", ["consent_revoked", "consent_regranted_new_receipt", "guardian_reassigned", "guardian_generation_changed"])
async def test_child_approval_rechecks_exact_consent_and_guardian_in_same_uow(memory_coordinator, pending_child_proposal_factory, child_approval_grant_factory, profile_class, authority_change, memories, memory_proposals):
    proposal = await pending_child_proposal_factory(profile_class=profile_class, then=authority_change)
    grant = child_approval_grant_factory(proposal)
    with pytest.raises(PermissionError, match="child_memory_current_guardian_consent_required"):
        await memory_coordinator.decide(proposal.approve_command(), proposal.decision_context, grant.id)
    assert await memory_proposals.status(proposal.id) == "pending"
    assert await memories.for_proposal(proposal.id) is None
```

```python
# tests/unit/actions/test_memory_action_provider.py
import pytest

@pytest.mark.asyncio
async def test_memory_decision_provider_does_not_consume_a_second_grant(memory_action_provider, approved_memory_action, already_consumed_auth, authentication_spy, approval_spy, uow):
    await memory_action_provider.execute_in_uow(uow, approved_memory_action, already_consumed_auth)
    assert authentication_spy.consume_calls == ()
    assert approval_spy.decide_in_uow_calls == ((uow, approved_memory_action.decision_command(), already_consumed_auth, approved_memory_action.binding),)

@pytest.mark.asyncio
async def test_memory_operation_substitution_fails_before_proposal_read(memory_action_provider, forged_memory_operation, memory_repository_spy, uow, auth):
    with pytest.raises(PermissionError, match="action_provider_operation_mismatch"):
        await memory_action_provider.execute_in_uow(uow, forged_memory_operation, auth)
    assert memory_repository_spy.read_count == 0


@pytest.mark.parametrize("search_enabled",(False,True))
def test_final_composition_reads_one_exact_database_head_before_real_handlers(
    final_phase1_container_factory,search_enabled,
):
    container=final_phase1_container_factory(
        search_enabled=search_enabled,database_heads=("0008_prepared_mutations",),
        search_database_heads=(
            ("search_0001_experimental_search",) if search_enabled else ()
        ),
        search_version_table_present=search_enabled,
        optional_search_namespace_present=search_enabled,
        optional_search_revision_present=search_enabled,
        optional_search_down_revision=None,
    )
    container.start()
    assert container.observed_database_heads==("0008_prepared_mutations",)
    assert container.observed_search_database_heads==(
        ("search_0001_experimental_search",) if search_enabled else ()
    )
    assert type(container.transactional_revocations["action_authorities"]).__name__=="ActionSubjectAuthorityHandler"
    assert type(container.post_commit_revocations["action_authorities"]).__name__=="ActionAuthorityRevocationHandler"
    assert type(container.transactional_revocations["memory_authorities"]).__name__=="MemorySubjectAuthorityHandler"
    assert type(container.post_commit_revocations["memory_authorities"]).__name__=="MemoryAuthorityRevocationHandler"
    assert all(type(item).__name__!="NotInstalledAuthorityRevocationHandler" for item in container.post_commit_revocations.values())
    assert container.startup_order==(
        "migrate","register_typed_facades","compose_stage_handlers",
        "recover_revocations","ready",
    )


@pytest.mark.parametrize(("search_enabled","database_heads"),(
    (False,("0007_privacy_post_response_jobs",)),
    (False,("0007_privacy_post_response_jobs","0008_prepared_mutations")),
    (True,("0007_privacy_post_response_jobs",)),
    (True,("0007_privacy_post_response_jobs","0008_prepared_mutations")),
))
def test_wrong_or_multiple_core_heads_block_before_composition(
    final_phase1_container_factory,search_enabled,database_heads,
):
    container=final_phase1_container_factory(
        search_enabled=search_enabled,database_heads=database_heads,
        search_database_heads=(
            ("search_0001_experimental_search",) if search_enabled else ()
        ),
        search_version_table_present=search_enabled,
        optional_search_namespace_present=search_enabled,
        optional_search_revision_present=search_enabled,
        optional_search_down_revision=None,
    )
    with pytest.raises(RuntimeError,match="phase1 migration head mismatch"):
        container.start()
    assert container.typed_facade_registration_count==0
    assert container.revocation_handler_composition_count==0
    assert container.ready is False


@pytest.mark.parametrize((
    "search_enabled","namespace_present","revision_present","down_revision",
),(
    (False,True,True,None),
    (False,False,True,None),
    (True,False,False,None),
    (True,True,False,None),
    (True,True,True,"0008_prepared_mutations"),
))
def test_search_migration_namespace_must_match_closed_feature_state(
    final_phase1_container_factory,search_enabled,namespace_present,
    revision_present,down_revision,
):
    container=final_phase1_container_factory(
        search_enabled=search_enabled,
        database_heads=("0008_prepared_mutations",),
        search_database_heads=(
            ("search_0001_experimental_search",) if search_enabled else ()
        ),
        search_version_table_present=search_enabled,
        optional_search_namespace_present=namespace_present,
        optional_search_revision_present=revision_present,
        optional_search_down_revision=down_revision,
    )
    with pytest.raises(RuntimeError,match="phase1 migration graph mismatch"):
        container.start()
    assert container.revocation_handler_composition_count==0


@pytest.mark.parametrize(("search_enabled","table_present","search_heads"),(
    (False,True,()),
    (False,True,("search_0001_experimental_search",)),
    (True,False,()),
    (True,True,()),
    (True,True,("search_wrong",)),
    (True,True,("search_0001_experimental_search","search_extra")),
))
def test_search_feature_version_table_and_head_are_exact(
    final_phase1_container_factory,search_enabled,table_present,search_heads,
):
    container=final_phase1_container_factory(
        search_enabled=search_enabled,database_heads=("0008_prepared_mutations",),
        search_version_table_present=table_present,
        search_database_heads=search_heads,
        optional_search_namespace_present=search_enabled,
        optional_search_revision_present=search_enabled,
        optional_search_down_revision=None,
    )
    with pytest.raises(RuntimeError,match="phase1 migration head mismatch"):
        container.start()
    assert container.typed_facade_registration_count==0
    assert container.revocation_handler_composition_count==0


@pytest.mark.parametrize("mutation",(
    "extra_feature_revision","duplicate_feature_revision",
    "feature_branch_label","feature_depends_on",
))
def test_search_feature_graph_inventory_and_metadata_are_exact(
    final_phase1_container_factory,mutation,
):
    container=final_phase1_container_factory(
        search_enabled=True,database_heads=("0008_prepared_mutations",),
        search_version_table_present=True,
        search_database_heads=("search_0001_experimental_search",),
        optional_search_namespace_present=True,
        optional_search_revision_present=True,
        optional_search_down_revision=None,
        optional_search_graph_mutation=mutation,
    )
    with pytest.raises(RuntimeError,match="phase1 migration graph mismatch"):
        container.start()
    assert container.typed_facade_registration_count==0
    assert container.revocation_handler_composition_count==0


@pytest.mark.parametrize(("mandatory_down_revision","privacy_down_revision"),(
    ("0006_timers","0006_timers"),
    ("0007_privacy_post_response_jobs","0005_memory_embeddings"),
))
def test_mandatory_phase1_tail_must_keep_0008_to_0007_to_0006_edges(
    final_phase1_container_factory,mandatory_down_revision,privacy_down_revision,
):
    container=final_phase1_container_factory(
        search_enabled=False,database_heads=("0008_prepared_mutations",),
        optional_search_revision_present=False,
        mandatory_phase1_down_revision=mandatory_down_revision,
        privacy_jobs_down_revision=privacy_down_revision,
    )
    with pytest.raises(RuntimeError,match="phase1 migration graph mismatch"):
        container.start()
    assert container.typed_facade_registration_count==0
    assert container.revocation_handler_composition_count==0


@pytest.mark.parametrize("mutation",(
    "hidden_branch_and_merge","extra_orphan_revision","0003_wrong_parent",
    "branch_label","depends_on",
))
def test_packaged_phase1_revision_inventory_and_every_edge_are_exact(
    final_phase1_container_factory,mutation,
):
    container=final_phase1_container_factory(
        search_enabled=False,database_heads=("0008_prepared_mutations",),
        optional_search_revision_present=False,
        migration_graph_mutation=mutation,
    )
    with pytest.raises(RuntimeError,match="phase1 migration graph mismatch"):
        container.start()
    assert container.typed_facade_registration_count==0
    assert container.revocation_handler_composition_count==0


@pytest.mark.parametrize("mismatch",("real_without_0004","placeholder_after_0004"))
def test_memory_revocation_schema_stage_mismatch_blocks_startup(
    final_phase1_container_factory,mismatch,
):
    with pytest.raises(RuntimeError,match="revocation handler schema stage mismatch"):
        final_phase1_container_factory(mismatch=mismatch).start()
```

```python
# tests/integration/identity/test_subject_revocation_handlers.py (Task-10 additions)
import pytest
from uuid import uuid5

@pytest.mark.asyncio
@pytest.mark.parametrize("family",(
    "provider_routes","search_capabilities","action_authorities","memory_authorities",
))
async def test_final_handler_replay_uses_one_exact_scoped_downstream_key_and_receipt(
    final_phase1_identity_runtime,started_authority_factory,revoke_profile_grant,family,
):
    runtime=await final_phase1_identity_runtime.start()
    subject=started_authority_factory(family)
    event=await runtime.revoke_profile(subject,revoke_profile_grant)
    await runtime.revocation_worker.wait_until_idle()
    key=uuid5(event.id,family)
    first=runtime.downstream_effects.receipt_for_key(key)
    await runtime.revocation_worker.run_one_periodic_drain()
    reopened=runtime.downstream_effects.receipt_for_key(key)
    assert reopened==first
    assert (first.event_id,first.family,first.subject_id,first.through_generation)==(
        event.id,family,subject.id,event.new_authority_generation-1,
    )
    assert runtime.downstream_effects.effect_count(key)==1
```

- [ ] **Step 2: Run red tests**

Run: `uv run pytest tests/unit/memory/test_write_policy.py tests/security/test_memory_write_policy.py tests/security/test_memory_deletion.py tests/integration/memory/test_memory_approval.py tests/unit/actions/test_memory_action_provider.py -q`
Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core.services.memory.proposals'`.

- [ ] **Step 3: Implement the matrix, strict schema, and atomic approval**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://tuntun.local/schemas/memory-proposal-v1.json",
  "oneOf": [
    {"type":"object","additionalProperties":false,"required":["kind","subject_ref","category","key","value","confidence_micros","reason"],"properties":{"kind":{"const":"remember_preference"},"subject_ref":{"type":"string","pattern":"^subject:[a-z0-9_-]{1,64}$"},"category":{"type":"string","maxLength":128},"key":{"type":"string","maxLength":128},"value":{"type":"string","maxLength":2000},"confidence_micros":{"type":"integer","minimum":0,"maximum":1000000},"reason":{"type":"string","minLength":1,"maxLength":256}}},
    {"type":"object","additionalProperties":false,"required":["kind","subject_ref","memory_ref","confidence_micros","reason"],"properties":{"kind":{"const":"forget_memory"},"subject_ref":{"type":"string","pattern":"^subject:[a-z0-9_-]{1,64}$"},"memory_ref":{"type":"string","pattern":"^memory:[a-z0-9_-]{1,64}$"},"confidence_micros":{"type":"integer","minimum":0,"maximum":1000000},"reason":{"type":"string","minLength":1,"maxLength":256}}}
  ]
}
```

```python
# apps/core/src/tuntun_core/services/memory/proposal_mapper.py
from tuntun_contracts.memory import MemoryAudience
from tuntun_core.domain.profile import ProfileClass
from tuntun_core.services.providers.output_validator import ProposalMapper as ConversationProposalMapper, ProviderMemoryIntent

class ProposalMapper:
    def __init__(self, conversation_mapper: ConversationProposalMapper, subject_refs, profiles, uow_factory):
        self._delegate, self._subjects, self._profiles, self._uow_factory = conversation_mapper, subject_refs, profiles, uow_factory

    async def map_memory(self, intent, household_id, session_id, turn_id):
        subject_id = self._subjects.resolve(intent.subject_ref, household_id)
        async with self._uow_factory() as uow:
            profile = await self._profiles.require_current_active_in_uow(uow, household_id, subject_id)
        audience = MemoryAudience.GUARDIAN_CHILD if profile.profile_class in {ProfileClass.K2, ProfileClass.N1} else MemoryAudience.SUBJECT_PRIVATE
        return self._delegate.map_memory(
            intent, household_id, session_id, turn_id,
            server_subject_id=subject_id, server_audience=audience,
        )

__all__ = ["ProposalMapper", "ProviderMemoryIntent"]
```

```python
# apps/core/src/tuntun_core/services/memory/proposals.py
from datetime import timedelta
from tuntun_contracts.memory import MemoryProposalDraft
from tuntun_core.domain.profile import ConsentPurpose, ProfileClass
from tuntun_core.services.identity.consent import ConsentDenied

class MemoryProposalService:
    def __init__(self, validator, write_policy, provenance, consent_service, memory_repository, approved_mapper, uow_factory, crypto, clock, audit_ledger):
        self._validator, self._write_policy, self._uow_factory = validator, write_policy, uow_factory
        self._provenance, self._consents = provenance, consent_service
        self._memory, self._approved_mapper = memory_repository, approved_mapper
        self._crypto, self._clock, self._audit = crypto, clock, audit_ledger

    async def stage(self, draft, context):
        prepared = self._prepare(draft, context)
        async with self._uow_factory() as uow:
            proposal = await self._stage_prepared_in_uow(uow, draft, context, prepared)
            await uow.commit()
            return proposal

    async def stage_in_uow(self, uow, draft, context):
        return await self._stage_prepared_in_uow(uow, draft, context, self._prepare(draft, context))

    async def decide(self, command, auth):
        raise PermissionError("memory_decision_requires_coordinator")

    def _prepare(self, draft, context):
        self._validator.require_exact_scope(draft, context)
        self._provenance.require_exact_mapped_draft(draft, household_id=context.household_id, subject_id=draft.subject_id, session_id=context.session_id, turn_id=context.turn_id, source_receipt_ids=draft.source_receipt_ids, claim_commitment=draft.claim_commitment)
        now = self._clock.now()
        if draft.expires_at <= now: raise PermissionError("memory_proposal_expired")
        claim = self._validator.validate_memory_content(draft.content, draft.operation)
        decision = self._write_policy.decide(draft)
        if claim is None and draft.target_memory_id is None:
            raise PermissionError("memory_proposal_target_required")
        commitment_input = claim.canonical_bytes() if claim is not None else draft.target_memory_id.bytes
        content_commitment = self._crypto.commit(commitment_input, purpose="memory_proposal_content")
        draft_commitment = self._crypto.commit(draft.model_dump_json().encode(), purpose="memory_proposal_frozen_draft")
        scope_commitment = self._crypto.commit(context.model_dump_json().encode(), purpose="memory_proposal_scope")
        encrypted = self._crypto.encrypt_proposal(content=claim.canonical_bytes() if claim is not None else None, reason=draft.reason.encode(), purpose="memory_proposal", aad=draft_commitment)
        return now, decision, content_commitment, draft_commitment, scope_commitment, encrypted

    async def _stage_prepared_in_uow(self, uow, draft, context, prepared):
        now, decision, content_commitment, draft_commitment, scope_commitment, encrypted = prepared
        await self._validator.require_current_subject_permission_in_uow(uow, draft, context, now)
        profile = await uow.profiles.get_scoped(draft.household_id, draft.subject_id)
        child_authority = None
        if profile.profile_class in {ProfileClass.K2, ProfileClass.N1}:
            if draft.content is not None and draft.content.kind == "working": raise PermissionError("child_working_context_must_be_ephemeral")
            if draft.audience not in {"guardian_child", "household_all"}: raise PermissionError("child_durable_audience_invalid")
            try:
                receipt = await self._consents.require_current_in_uow(uow, draft.subject_id, ConsentPurpose.CHILD_DURABLE_MEMORY, now)
            except ConsentDenied as exc:
                raise PermissionError("child_memory_current_guardian_consent_required") from exc
            child_authority = {"child_consent_receipt_id": receipt.id, "guardian_id": profile.guardian_id, "guardian_generation": profile.guardian_generation}
            decision = self._write_policy.require_exact_guardian_passkey(decision)
        existing = await uow.memory_proposals.get_by_idempotency(draft.household_id, draft.session_id, draft.idempotency_key)
        if existing is not None:
            if not self._crypto.constant_time_equal(existing.draft_commitment, draft_commitment): raise PermissionError("memory_proposal_idempotency_conflict")
            return existing
        duplicate = await uow.memory_proposals.get_turn_claim(draft.household_id, draft.turn_id, draft.claim_commitment)
        if duplicate is not None: return duplicate
        proposal = await uow.memory_proposals.insert(draft=draft, encrypted=encrypted, scope_commitment=scope_commitment, draft_commitment=draft_commitment, claim_commitment=draft.claim_commitment, content_commitment=content_commitment, child_authority=child_authority, subject_authority_generation=profile.authority_generation, status="pending", draft_expires_at=draft.expires_at, expires_at=now + timedelta(days=30), required_factor=decision.required_factor)
        if decision.outcome == "auto_apply":
            working_expires_at = await uow.sessions.working_memory_deadline(context.session_id, grace=timedelta(minutes=30))
            system_receipt = await uow.system_approval_receipts.issue_working_summary(household_id=draft.household_id, subject_id=draft.subject_id, session_id=draft.session_id, turn_id=draft.turn_id, proposal_id=draft.proposal_id, content_commitment=content_commitment, expires_at=now + timedelta(minutes=5))
            approved = await uow.memory_proposals.apply_working_summary(proposal.id, expires_at=working_expires_at, system_approval_receipt_id=system_receipt.id, approval_source="system_working_summary", decided_at=now)
            await uow.memories.apply_system_approved_working_summary(
                approved,
                approved_proposal_id=approved.id,
                system_approval_receipt_id=system_receipt.id,
            )
            await self._audit.append(uow, uow.system_approval_receipts.audit_draft(system_receipt))
        await self._audit.append(uow, uow.memory_proposals.staged_audit_draft(proposal))
        return proposal
```

```python
# apps/core/src/tuntun_core/services/memory/write_policy.py
class MemoryWritePolicy:
    def decide(self, draft):
        kind = draft.content.kind if draft.content is not None else None
        if kind == "working":
            return WriteDecision("auto_apply", None)
        if kind == "policy":
            return WriteDecision("stage", "passkey")
        if kind in {"procedural", "relational"}:
            return WriteDecision("stage", "passkey")
        if kind == "episodic":
            return WriteDecision("stage", "pin")
        if kind in {"semantic", "preference"} and draft.sensitivity in {"personal", "sensitive", "restricted"}:
            return WriteDecision("stage", "pin")
        return WriteDecision("stage", None)

    def require_exact_guardian_passkey(self, decision):
        if decision.outcome == "auto_apply":
            raise PermissionError("child_working_context_must_be_ephemeral")
        return WriteDecision("stage", "passkey")
```

```python
# apps/core/src/tuntun_core/services/memory/approval.py
class MemoryApprovalService:
    def __init__(self, mutation_scope, consent_service, memory_repository, approved_mapper, binding_verifier, decision_audits, audit_ledger, clock):
        self._scope, self._consents, self._bindings = mutation_scope, consent_service, binding_verifier
        self._memory, self._approved_mapper = memory_repository, approved_mapper
        self._decision_audits, self._audit, self._clock = decision_audits, audit_ledger, clock

    async def decide(self, command, auth):
        raise PermissionError("memory_decision_requires_coordinator")

    async def decide_in_uow(self, uow, command, auth, expected_binding):
        proposal = await uow.memory_proposals.lock(command.proposal_id)
        if proposal.status != "pending" or proposal.expires_at <= self._clock.now():
            raise PermissionError("proposal_not_pending")
        self._bindings.require_exact(expected_binding, auth.binding)
        if command.expected_version != proposal.version: raise PermissionError("stale_memory_proposal_version")
        if command.decision == "reject":
            await uow.memory_proposals.reject_and_destroy_key(proposal.id)
        else:
            assurance_rank = {"guest": 0, "identified": 1, "confirmed": 2, "pin_verified": 3, "passkey_verified": 4, "recovery_verified": 5}
            required = {None: 0, "pin": 3, "passkey": 4}[proposal.required_factor]
            if assurance_rank[auth.assurance.value] < required:
                raise PermissionError("memory_approval_assurance_required")
            child_authority = proposal.child_authority()
            child_safe_audience_approval_grant_id = None
            if child_authority is not None:
                profile = await uow.profiles.get_scoped(proposal.household_id, proposal.subject_id)
                try:
                    consent = await self._consents.require_current_in_uow(
                        uow, proposal.subject_id, ConsentPurpose.CHILD_DURABLE_MEMORY, self._clock.now()
                    )
                except ConsentDenied as exc:
                    raise PermissionError("child_memory_current_guardian_consent_required") from exc
                if not (
                    profile.profile_class in {ProfileClass.K2, ProfileClass.N1}
                    and auth.assurance.value == "passkey_verified"
                    and auth.subject_id == profile.guardian_id == child_authority.guardian_id
                    and profile.guardian_generation == child_authority.guardian_generation
                    and consent.id == child_authority.child_consent_receipt_id
                    and consent.guardian_id == profile.guardian_id
                    and consent.guardian_generation == profile.guardian_generation
                ):
                    raise PermissionError("child_memory_current_guardian_consent_required")
                if proposal.audience == "household_all":
                    child_safe_audience_approval_grant_id = auth.grant_id
            approved = await uow.memory_proposals.approve_with_final_content(
                proposal.id,
                edited_content=command.edited_content,
                child_authority=child_authority,
                child_safe_audience_approval_grant_id=child_safe_audience_approval_grant_id,
                decision_receipt_id=auth.grant_id,
                decided_at=self._clock.now(),
            )
            if approved.operation == "create":
                await self._memory.create(self._approved_mapper.from_proposal(approved))
            elif approved.operation == "replace":
                await self._memory.replace(
                    approved.target_memory_id,
                    approved.expected_version,
                    self._approved_mapper.from_proposal(approved),
                )
            else:
                await self._memory.delete(
                    approved.target_memory_id, approved.expected_version, auth, approved.id
                )
        await self._audit.append(uow, self._decision_audits.disposition(proposal, command, auth))
        return await uow.memory_proposals.get(proposal.id)

class MemoryMutationCoordinator:
    def __init__(self, mutation_scope, authentication, binding_factory, approval):
        self._scope, self._auth, self._bindings, self._approval = mutation_scope, authentication, binding_factory, approval

    async def decide(self, command, decision_context, grant_id):
        async with self._scope.open() as uow:
            proposal = await uow.memory_proposals.lock(command.proposal_id)
            expected_binding = self._bindings.memory_decision(proposal, command, decision_context)
            auth = await self._auth.consume_in_uow(uow, grant_id, expected_binding)
            result = await self._approval.decide_in_uow(uow, command, auth, expected_binding)
            await uow.commit()
            return result

class ChildMemoryConsentRevocationHandler:
    async def apply_in_uow(self, uow, receipt, auth, now):
        await uow.memory_proposals.cancel_pending_for_subject(
            receipt.subject_id, reason="child_memory_consent_revoked", now=now
        )
        # Existing rows retain their encrypted bytes and immutable authority
        # metadata. Every candidate/decrypt/serialization check now fails because
        # the stored receipt is no longer the current granted receipt.

# apps/core/src/tuntun_core/services/actions/providers/memory.py
from pydantic import ValidationError
from tuntun_contracts.actions import MemoryActionDraft

class MemoryLocalActionProvider:
    provider_name = "memory"
    action_names = frozenset({"memory.propose", "memory.approve", "memory.edit_approve", "memory.reject", "memory.expire", "memory.delete"})

    def __init__(self, proposals, approval, repository, command_mapper, receipts, clock):
        self._proposals, self._approval, self._repository = proposals, approval, repository
        self._commands, self._receipts, self._clock = command_mapper, receipts, clock

    async def execute_in_uow(self, uow, proposal, auth):
        draft = proposal.draft
        if type(draft) is not MemoryActionDraft or draft.action_name not in self.action_names:
            raise PermissionError("action_provider_operation_mismatch")
        try:
            draft = MemoryActionDraft.model_validate(draft.model_dump(mode="python"))
        except ValidationError as exc:
            raise PermissionError("action_provider_operation_mismatch") from exc
        command = self._commands.memory(draft, proposal.binding)  # exhaustive and read-free
        if draft.action_name == "memory.propose":
            await self._proposals.stage_in_uow(uow, command.draft, command.context)
        elif draft.action_name in {"memory.approve", "memory.edit_approve", "memory.reject"}:
            await self._approval.decide_in_uow(uow, command.decision, auth, proposal.binding)
        elif draft.action_name == "memory.expire":
            await uow.memory_proposals.expire_exact(command.proposal_id, command.expected_version, self._clock.now())
        elif draft.action_name == "memory.delete":
            await self._approval.decide_in_uow(uow, command.decision, auth, proposal.binding)
        else:
            raise PermissionError("action_provider_operation_mismatch")
        return self._receipts.executed(proposal, provider_name=self.provider_name)

# apps/core/src/tuntun_core/bootstrap/container.py
from alembic.util.exc import CommandError
from dataclasses import dataclass

SEARCH_FEATURE_HEAD="search_0001_experimental_search"
SEARCH_VERSION_TABLE="alembic_version_experimental_search"
MANDATORY_PHASE1_REVISIONS=(
    "0001_foundation",
    "0002_profiles_consent_enrollment",
    "0003_authentication",
    "0004_memory",
    "0005_memory_embeddings",
    "0006_timers",
    "0007_privacy_post_response_jobs",
    "0008_prepared_mutations",
)


@dataclass(frozen=True,slots=True)
class Phase1MigrationState:
    actual_heads:tuple[str,...]
    search_heads:tuple[str,...]
    search_enabled:bool


def require_final_phase1_migration_state(
    connection,script_directory,search_script_directory,*,search_enabled:bool,
) -> Phase1MigrationState:
    try: revisions=tuple(script_directory.walk_revisions())
    except CommandError as error:
        raise RuntimeError("phase1 migration graph mismatch") from error
    by_id={revision.revision:revision for revision in revisions}
    if len(by_id)!=len(revisions) or set(by_id)!=set(MANDATORY_PHASE1_REVISIONS):
        raise RuntimeError("phase1 migration graph mismatch")
    for index,revision_id in enumerate(MANDATORY_PHASE1_REVISIONS):
        revision=by_id[revision_id]
        expected_parent=None if index==0 else MANDATORY_PHASE1_REVISIONS[index-1]
        dependencies=getattr(
            revision,"dependencies",getattr(revision,"depends_on",None),
        )
        if (revision.down_revision!=expected_parent
            or bool(getattr(revision,"branch_labels",None))
            or bool(dependencies)):
            raise RuntimeError("phase1 migration graph mismatch")
    actual=tuple(connection.exec_driver_sql(
        "SELECT version_num FROM alembic_version ORDER BY version_num"
    ).scalars())
    expected_heads=(MANDATORY_PHASE1_REVISIONS[-1],)
    if actual!=expected_heads:
        raise RuntimeError(
            f"phase1 migration head mismatch: expected={expected_heads!r} actual={actual!r}"
        )
    table_present=connection.exec_driver_sql(
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        f"AND name='{SEARCH_VERSION_TABLE}'"
    ).scalar_one_or_none() is not None
    if not search_enabled:
        if search_script_directory is not None:
            raise RuntimeError("phase1 migration graph mismatch")
        if table_present:
            raise RuntimeError("phase1 migration head mismatch: absent search version table")
        search_heads=()
    else:
        if search_script_directory is None:
            raise RuntimeError("phase1 migration graph mismatch")
        try: search_revisions=tuple(search_script_directory.walk_revisions())
        except CommandError as error:
            raise RuntimeError("phase1 migration graph mismatch") from error
        if len(search_revisions)!=1 or search_revisions[0].revision!=SEARCH_FEATURE_HEAD:
            raise RuntimeError("phase1 migration graph mismatch")
        search_revision=search_revisions[0]
        search_dependencies=getattr(
            search_revision,"dependencies",getattr(search_revision,"depends_on",None),
        )
        if (search_revision.down_revision is not None
            or bool(getattr(search_revision,"branch_labels",None))
            or bool(search_dependencies)):
            raise RuntimeError("phase1 migration graph mismatch")
        if not table_present:
            raise RuntimeError("phase1 migration head mismatch: search version table absent")
        search_heads=tuple(connection.exec_driver_sql(
            f"SELECT version_num FROM {SEARCH_VERSION_TABLE} ORDER BY version_num"
        ).scalars())
        if search_heads!=(SEARCH_FEATURE_HEAD,):
            raise RuntimeError("phase1 migration head mismatch: search feature head")
    return Phase1MigrationState(actual,search_heads,search_enabled)


class MemorySubjectAuthorityHandler:
    async def revoke_in_uow(
        self,uow,*,household_id,subject_id,through_generation,reason,now,
    ):
        await uow.memory_proposals.cancel_pending_through_generation(
            household_id,subject_id,through_generation,reason=reason,now=now,
        )

def install_memory_revocation_handlers(
    transactional,post_commit,*,capability_stage,effects,heartbeats,uow_factory,
):
    capability_stage.require_schema_and_facades_installed(
        "memory_authorities","0004_memory",(uow_factory.memory_proposals,),
    )
    transactional["memory_authorities"]=MemorySubjectAuthorityHandler()
    post_commit["memory_authorities"]=MemoryAuthorityRevocationHandler(
        effects,heartbeats,uow_factory,
    )
    if isinstance(post_commit["memory_authorities"],NotInstalledAuthorityRevocationHandler):
        raise RuntimeError("revocation handler schema stage mismatch")

def register_phase1_local_action_providers(registry, *, identity, memory, timer, search):
    for provider in (identity, memory, timer, search):
        registry.register_local(provider)
    if registry.local_action_names() != PHASE1_DATABASE_LOCAL_ACTIONS:
        raise RuntimeError("phase1_database_local_action_registry_incomplete")
    return registry

def build_consent_revocation_handlers(*, biometric, cloud_routes, search_routes, child_memory):
    return {
        ConsentPurpose.FACE: biometric,
        ConsentPurpose.VOICE: biometric,
        ConsentPurpose.CLOUD_STT: cloud_routes,
        ConsentPurpose.CLOUD_REASONING: cloud_routes,
        ConsentPurpose.CLOUD_TTS: cloud_routes,
        ConsentPurpose.WEB_SEARCH: search_routes,
        ConsentPurpose.CHILD_DURABLE_MEMORY: child_memory,
        # PERSONALIZATION reloads the latest receipt at projection/recall use;
        # it has no independently consumable route to invalidate.
    }
```

```python
# apps/core/src/tuntun_core/bootstrap/lifecycle.py (final Phase-1 bootstrap)
async def bootstrap_final_phase1_identity(
    *,migration_connection,script_directory,search_script_directory,
    feature_registry,facades,
    handler_composer,revocation_worker,readiness,task_group,stop,
):
    readiness.clear()
    search_enabled=feature_registry.require_closed_state("experimental_search")=="enabled"
    migration_state=require_final_phase1_migration_state(
        migration_connection,script_directory,search_script_directory,
        search_enabled=search_enabled,
    )
    # No typed facade, real handler, recovery task, or readiness side effect is
    # constructed until the exact core plus absent/enabled feature namespaces pass.
    registered=facades.register_all_for_phase1(migration_state)
    transactional,post_commit=handler_composer.compose_exact(
        migration_state=migration_state,facades=registered,
    )
    if any(type(item).__name__.startswith("NotInstalled") for item in (
        transactional["action_authorities"],transactional["memory_authorities"],
        post_commit["action_authorities"],post_commit["memory_authorities"],
    )):
        raise RuntimeError("revocation handler schema stage mismatch")
    await start_identity_runtime(
        transactional,revocation_worker,readiness,task_group,stop,
    )
    return migration_state
```

- [ ] **Step 4: Run green and repository tests**

Run: `uv run pytest tests/unit/memory/test_write_policy.py tests/security/test_memory_write_policy.py tests/security/test_memory_deletion.py tests/integration/memory/test_memory_approval.py tests/unit/actions/test_memory_action_provider.py tests/integration/memory/test_repository.py tests/integration/identity/test_subject_revocation_handlers.py tests/integration/storage/test_migrations.py -q`
Expected: PASS; pending/rejected claims are never recalled, rejection destroys the wrapped DEK, approval is idempotent, and final startup always requires the exact linear core `0001_foundation` through sole head `0008_prepared_mutations`, plus either no search namespace/version table or the independent exact `search_0001_experimental_search` namespace and sole feature-table head, with no hidden graph metadata or revision before registering facades or composing exact real action/memory revocation handlers.

- [ ] **Step 5: Check and commit**

Run: `uv run ruff format --check apps/core/src/tuntun_core/services/memory/proposal_mapper.py apps/core/src/tuntun_core/services/memory/proposals.py apps/core/src/tuntun_core/services/memory/write_policy.py apps/core/src/tuntun_core/services/memory/approval.py apps/core/src/tuntun_core/services/actions/providers/memory.py apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/bootstrap/lifecycle.py tests/unit/memory/test_write_policy.py tests/security/test_memory_write_policy.py tests/security/test_memory_deletion.py tests/integration/memory/test_memory_approval.py tests/unit/actions/test_memory_action_provider.py && uv run ruff check apps/core/src/tuntun_core/services/memory/proposal_mapper.py apps/core/src/tuntun_core/services/memory/proposals.py apps/core/src/tuntun_core/services/memory/write_policy.py apps/core/src/tuntun_core/services/memory/approval.py apps/core/src/tuntun_core/services/actions/providers/memory.py apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/bootstrap/lifecycle.py tests/unit/memory/test_write_policy.py tests/security/test_memory_write_policy.py tests/security/test_memory_deletion.py tests/integration/memory/test_memory_approval.py tests/unit/actions/test_memory_action_provider.py && uv run mypy apps/core/src/tuntun_core/services/memory apps/core/src/tuntun_core/services/actions/providers/memory.py apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/bootstrap/lifecycle.py`
Expected: PASS with exit code 0.

```bash
git add apps/core/src/tuntun_core/services/memory/proposal_mapper.py apps/core/src/tuntun_core/services/memory/proposals.py apps/core/src/tuntun_core/services/memory/write_policy.py apps/core/src/tuntun_core/services/memory/approval.py apps/core/src/tuntun_core/services/actions/providers/memory.py apps/core/src/tuntun_core/services/identity/subject_revocation.py apps/core/src/tuntun_core/services/identity/subject_revocation_handlers.py apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/bootstrap/lifecycle.py prompts/memory/proposal-schema.json tests/unit/memory/test_write_policy.py tests/security/test_memory_write_policy.py tests/security/test_memory_deletion.py tests/integration/memory/test_memory_approval.py tests/unit/actions/test_memory_action_provider.py tests/integration/identity/test_subject_revocation_handlers.py
git diff --cached --name-only
git diff --cached
git commit -m "feat(memory): govern proposal approval lifecycle"
```

### Task 11: Add local multilingual retrieval and workflow integration

**Master coverage:** retrieval/integration portion of Task 22
**Depends on:** Tasks 1–10 and master Tasks 04, 08, and 15–16
**Estimated effort:** 4 person-days

**Files:**
- Create: `apps/core/src/tuntun_core/services/memory/retrieval.py`
- Create: `apps/core/src/tuntun_core/services/memory/recall_authorization.py`
- Create: `apps/core/src/tuntun_core/services/memory/embeddings.py`
- Create: `apps/core/src/tuntun_core/services/memory/context.py`
- Create: `apps/core/src/tuntun_core/adapters/embeddings/multilingual_e5.py`
- Create: `apps/core/src/tuntun_core/services/providers/token_counter.py`
- Create: `apps/core/migrations/versions/0005_memory_embeddings.py`
- Modify: `models/manifest.yaml` (`intfloat/multilingual-e5-small` revision `0e60b8d9d2166d80387f86e3b48ec9ced55f4d15`)
- Modify: `apps/core/src/tuntun_core/workflows/nodes.py` (`authorize_recall`, `retrieve_context`, `propose_memories` nodes)
- Modify: `apps/core/src/tuntun_core/workflows/conversation.py` (same ordered path for the linear oracle)
- Create: `tests/unit/memory/test_retrieval.py`
- Create: `tests/security/test_context_minimization.py`
- Create: `tests/acceptance/test_multilingual_memory_retrieval.py`
- Create: `evals/cases/multilingual-memory.jsonl`
- Create: `scripts/build_memory_eval_corpus.py`
- Create: `tests/integration/test_personalized_memory_turn.py`
- Create: `tests/integration/test_guest_private_memory_denial.py`

**Interfaces:**
- Consumes: approved scoped memories, unexpired identity/current personalization consent/policy decision, and—for K2/N1—the exact current `child_durable_memory_v1` receipt plus guardian generation and stored child-safe audience approval; local activated E5 model; a local pre-route `ProviderDraft`; provider-specific `TokenCounter.count_serialized(final_sanitized_request) -> int`; existing sanitizer and budget/provider gateway.
- Produces: `MemoryRetrievalPort.retrieve -> RetrievalResult(memories: tuple[SelectedMemory, ...], serialized_context_tokens: int, degraded: bool)` plus a server-local short-lived recall authorization referenced by each selected item; local provenance reasons; no authorization ID or content outside the sanitizer boundary. Candidate SQL, pre-decrypt validation, and pre-provider serialization all repeat the exact child authority checks.

- [ ] **Step 1: Write failing scope, token, fallback, and acceptance tests**

```python
# tests/unit/memory/test_retrieval.py
from tuntun_core.services.memory.context import ProviderDraft
from tuntun_core.services.memory.retrieval import RetrievalResult,ScopedRecallQuery

def test_retrieval_and_provider_context_collections_have_schema_caps():
    expected={
        (ScopedRecallQuery,"tags"):16,(ScopedRecallQuery,"kinds"):7,
        (RetrievalResult,"memories"):6,(ProviderDraft,"messages_without_memory"):32,
        (ProviderDraft,"memory_claims"):6,
    }
    for (model,field),maximum in expected.items():
        assert model.model_json_schema()["properties"][field]["maxItems"]==maximum

import pytest

@pytest.mark.asyncio
async def test_retrieval_limits_six_and_uses_deterministic_ties(retrieval, owner_query, twelve_equal_memories):
    result = await retrieval.retrieve(owner_query)
    assert len(result.memories) == 6
    assert tuple(item.memory_id for item in result.memories) == tuple(sorted(item.memory_id for item in twelve_equal_memories)[:6])

@pytest.mark.asyncio
async def test_missing_model_uses_local_exact_fallback(retrieval_without_model, owner_query):
    result = await retrieval_without_model.retrieve(owner_query)
    assert result.degraded is True
    assert result.route == "exact_tag_type_recency"
    assert retrieval_without_model.cloud_embedding_calls == 0

@pytest.mark.asyncio
@pytest.mark.parametrize("profile_class", ["k2", "n1"])
@pytest.mark.parametrize("authority_case", ["missing_consent", "revoked_consent", "stale_guardian", "restored_missing_binding", "restored_bad_household_all_approval"])
async def test_child_retrieval_denies_before_candidate_fetch_or_decrypt(retrieval, child_query_factory, candidate_index_spy, memory_crypto_spy, profile_class, authority_case):
    result = await retrieval.retrieve(child_query_factory(profile_class=profile_class, authority_case=authority_case))
    assert result.memories == ()
    assert candidate_index_spy.calls == ()
    assert memory_crypto_spy.decrypt_calls == ()
```

```python
# tests/security/test_context_minimization.py
import pytest

@pytest.mark.asyncio
async def test_guest_denied_before_decryption(workflow, guest_turn, memory_crypto_spy, fake_provider):
    await workflow.run(guest_turn)
    assert memory_crypto_spy.decrypt_calls == ()
    assert fake_provider.last_request.memory_messages == ()

@pytest.mark.asyncio
async def test_full_serialized_request_is_within_8000_tokens(context_builder, owner_turn):
    request = await context_builder.build(owner_turn)
    assert context_builder.token_counter.count_serialized(request) <= 8000

@pytest.mark.asyncio
async def test_child_consent_revocation_between_retrieval_and_serialization_yields_no_provider_claims(context_builder, selected_child_memories, revoke_child_memory_consent, provider_draft):
    await revoke_child_memory_consent()
    selected, request, _ = await context_builder.build_once_sanitized(selected_child_memories, provider_draft, 8000)
    assert selected == ()
    assert request.memory_claims == ()
```

```python
# tests/acceptance/test_multilingual_memory_retrieval.py
def test_fixed_retrieval_gate(run_retrieval_corpus):
    report = run_retrieval_corpus("evals/cases/multilingual-memory.jsonl")
    assert report.case_count >= 120
    assert report.recall_at_6 >= 0.90
    assert report.mrr_at_6 >= 0.75
    assert report.cross_profile_leaks == 0
    assert report.maximum_items == 6
    assert report.maximum_context_tokens <= 8000
```

- [ ] **Step 2: Run red tests**

Run: `uv run pytest tests/unit/memory/test_retrieval.py tests/security/test_context_minimization.py tests/acceptance/test_multilingual_memory_retrieval.py tests/integration/test_personalized_memory_turn.py tests/integration/test_guest_private_memory_denial.py -q`
Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core.services.memory.retrieval'`.

- [ ] **Step 3: Implement local embeddings, bounded selection, context serialization, and workflow nodes**

```python
# apps/core/src/tuntun_core/services/memory/embeddings.py
class MemoryEmbeddingService:
    def __init__(self, adapter, rows, crypto, erasure_jobs, model):
        self._adapter, self._rows, self._crypto, self._model = adapter, rows, crypto, model
        self._erasure_jobs = erasure_jobs

    async def index(self, memory_id, minimal_claim):
        vector = self._adapter.embed_passage(minimal_claim, self._model)
        encoded = b"".join(float(value).hex().encode("ascii") + b"\n" for value in vector)
        encrypted = self._crypto.encrypt_record(encoded, purpose="memory_embedding")
        return await self._rows.upsert(memory_id=memory_id, model_id=self._model.version, dimensions=384, encrypted=encrypted)

    async def remove(self, memory_id):
        await self._rows.delete_rows_with_wrapped_deks(memory_id)
        await self._erasure_jobs.schedule_wal_and_managed_backup_purge("memory_embedding", memory_id)
```

```python
# apps/core/src/tuntun_core/adapters/embeddings/multilingual_e5.py
class MultilingualE5Adapter:
    DIMENSIONS = 384

    def __init__(self, registry, backend):
        self._registry, self._backend = registry, backend

    def embed_query(self, text, model):
        self._registry.require_activated(model, purpose="local_memory_retrieval", safe_format="onnx")
        return self._normalize(self._backend.encode("query: " + text))

    def embed_passage(self, text, model):
        self._registry.require_activated(model, purpose="local_memory_retrieval", safe_format="onnx")
        return self._normalize(self._backend.encode("passage: " + text))

    def _normalize(self, vector):
        if len(vector) != self.DIMENSIONS:
            raise ValueError("embedding_dimension_mismatch")
        norm = sum(value * value for value in vector) ** 0.5
        if norm == 0:
            raise ValueError("zero_embedding")
        return tuple(value / norm for value in vector)
```

```python
# apps/core/src/tuntun_core/services/memory/retrieval.py
from datetime import datetime, timedelta
from uuid import UUID
from pydantic import BaseModel, ConfigDict
from tuntun_contracts.base import Sensitivity
from tuntun_contracts.identity import IdentityDecision, IdentityStatus
from tuntun_contracts.memory import MemoryKind, MemoryQuery
from tuntun_core.domain.profile import ConsentPurpose, ProfileClass
from tuntun_core.services.identity.consent import ConsentDenied

class SelectedMemory(BaseModel):
    model_config=ConfigDict(frozen=True,extra="forbid",strict=True)
    memory_id: UUID; score_micros: int; recency_micros: int; minimal_claim: str; local_reason_code: str
    content_commitment: Commitment; recall_authorization_id: UUID
    def to_provider_claim(self): return {"claim": self.minimal_claim}

class ScopedRecallQuery(BaseModel):
    model_config=ConfigDict(frozen=True,extra="forbid",strict=True)
    household_id: UUID; subject_id: UUID|None; session_id: UUID; identity_decision: IdentityDecision; recall_policy: PolicyDecision; text: str
    tags: Annotated[tuple[Annotated[str,Field(min_length=1,max_length=64)],...],Field(min_length=0,max_length=16)]
    kinds: Annotated[tuple[MemoryKind,...],Field(min_length=1,max_length=7)]
    maximum_sensitivity: Sensitivity; provider_draft: ProviderDraft
    @field_validator("tags","kinds")
    @classmethod
    def unique_recall_filters(cls,value):
        if len(set(value))!=len(value): raise ValueError("duplicate recall filter")
        return value
    def to_memory_query(self,limit): return MemoryQuery(household_id=self.household_id,subject_id=self.subject_id,kinds=self.kinds,maximum_sensitivity=self.maximum_sensitivity,limit=min(limit,6))

class RetrievalResult(BaseModel):
    model_config=ConfigDict(frozen=True,extra="forbid",strict=True)
    memories: Annotated[tuple[SelectedMemory,...],Field(min_length=0,max_length=6)]
    serialized_context_tokens: int; degraded: bool; route: str
    @field_validator("memories")
    @classmethod
    def unique_memories(cls,value):
        if len({item.memory_id for item in value})!=len(value): raise ValueError("duplicate retrieved memory")
        return value
    @classmethod
    def empty(cls,route): return cls(memories=(),serialized_context_tokens=0,degraded=False,route=route)

class MemoryRetrievalService:
    MAX_ITEMS = 6
    MAX_CONTEXT_TOKENS = 8000

    async def retrieve(self, query):
        now = self._clock.now()
        if query.recall_policy.effect is not PolicyEffect.ALLOW or query.recall_policy.expires_at <= now:
            return RetrievalResult.empty("recall_policy_denied")
        if query.subject_id is None or query.identity_decision.status is not IdentityStatus.VERIFIED or query.identity_decision.subject_id != query.subject_id or query.identity_decision.expires_at <= now:
            return RetrievalResult.empty("guest_or_unverified")
        if not await self._current_identity_state.is_session_decision_current(query.household_id, query.session_id, query.identity_decision, now):
            return RetrievalResult.empty("identity_state_not_current")
        async with self._uow_factory() as uow:
            profile = await uow.profiles.get_scoped(query.household_id, query.subject_id)
            try:
                personalization = await self._consents.require_current_in_uow(
                    uow, query.subject_id, ConsentPurpose.PERSONALIZATION, now
                )
            except ConsentDenied:
                return RetrievalResult.empty("personalization_consent_missing")
            child_authority = None
            if profile.profile_class in {ProfileClass.K2, ProfileClass.N1}:
                try:
                    child_consent = await self._consents.require_current_in_uow(
                        uow, query.subject_id, ConsentPurpose.CHILD_DURABLE_MEMORY, now
                    )
                except ConsentDenied:
                    return RetrievalResult.empty("child_memory_consent_missing")
                child_authority = {
                    "child_consent_receipt_id": child_consent.id,
                    "guardian_id": profile.guardian_id,
                    "guardian_generation": profile.guardian_generation,
                }
            encrypted_rows = await self._candidate_index.sql_filter_scoped_approved_authorized(
                household_id=query.household_id,
                subject_id=query.subject_id,
                kinds=query.kinds,
                maximum_sensitivity=query.maximum_sensitivity,
                child_authority=child_authority,
                child_audiences=("guardian_child", "household_all"),
                require_household_all_approval=True,
                exclude_statuses=("pending", "rejected", "expired", "deleted", "superseded", "revoked", "quarantined"),
                now=now,
                limit=64,
            )
            eligible = []
            for row in encrypted_rows:
                if child_authority is not None:
                    await self._candidate_index.require_exact_child_authority_in_uow(
                        uow, row.id, **child_authority
                    )
                eligible.append(self._decrypt_rankable_in_uow(uow, row))
        if self._embedder.available:
            ranked = self._rank_semantic(query.text, eligible)
            route, degraded = "multilingual_e5", False
        else:
            ranked = self._rank_exact(query.tags, eligible)
            route, degraded = "exact_tag_type_recency", True
        selected = tuple(sorted(ranked, key=lambda item: (-item.score_micros, -item.recency_micros, str(item.memory_id)))[: self.MAX_ITEMS])
        recall_authorization = await self._recall_authorizations.issue(
            query=query,
            selected=selected,
            personalization_receipt_id=personalization.id,
            child_authority=child_authority,
            expires_at=min(query.identity_decision.expires_at, query.recall_policy.expires_at, now + timedelta(seconds=30)),
        )
        selected = tuple(item.model_copy(update={"recall_authorization_id": recall_authorization.id}) for item in selected)
        return RetrievalResult(memories=selected, serialized_context_tokens=0, degraded=degraded, route=route)
```

```python
# apps/core/src/tuntun_core/services/memory/recall_authorization.py
from uuid import uuid4

class RecallAuthorizationDenied(PermissionError): pass

class RecallAuthorizationService:
    """RAM-only, content-free recall leases; never a provider or browser DTO."""
    def __init__(self, uow_factory, consents, current_identity_state, clock):
        self._uow_factory, self._consents = uow_factory, consents
        self._identity, self._clock, self._leases = current_identity_state, clock, {}

    async def issue(self, *, query, selected, personalization_receipt_id, child_authority, expires_at):
        lease = RecallLease(
            id=uuid4(), household_id=query.household_id, subject_id=query.subject_id,
            session_id=query.session_id, identity_decision=query.identity_decision,
            recall_policy=query.recall_policy, personalization_receipt_id=personalization_receipt_id,
            child_authority=child_authority,
            selected=tuple((item.memory_id, item.content_commitment) for item in selected),
            expires_at=expires_at,
        )
        self._leases[lease.id] = lease
        return lease

    async def require_current_exact(self, selected, now):
        if not selected:
            return
        ids = {item.recall_authorization_id for item in selected}
        if len(ids) != 1:
            raise RecallAuthorizationDenied("recall_authorization_mixed")
        lease = self._leases.get(ids.pop())
        if lease is None or lease.expires_at <= now:
            raise RecallAuthorizationDenied("recall_authorization_expired")
        if not await self._identity.is_session_decision_current(
            lease.household_id, lease.session_id, lease.identity_decision, now
        ):
            raise RecallAuthorizationDenied("recall_identity_not_current")
        try:
            async with self._uow_factory() as uow:
                personalization = await self._consents.require_current_in_uow(
                    uow, lease.subject_id, ConsentPurpose.PERSONALIZATION, now
                )
                if personalization.id != lease.personalization_receipt_id:
                    raise RecallAuthorizationDenied("recall_personalization_changed")
                if lease.child_authority is not None:
                    child = await self._consents.require_current_in_uow(
                        uow, lease.subject_id, ConsentPurpose.CHILD_DURABLE_MEMORY, now
                    )
                    profile = await uow.profiles.get_scoped(lease.household_id, lease.subject_id)
                    if not (
                        child.id == lease.child_authority["child_consent_receipt_id"]
                        and child.guardian_id == profile.guardian_id == lease.child_authority["guardian_id"]
                        and child.guardian_generation == profile.guardian_generation == lease.child_authority["guardian_generation"]
                    ):
                        raise RecallAuthorizationDenied("recall_child_authority_changed")
                await uow.memories.require_selected_metadata_exact_without_decrypt(
                    lease.selected,
                    child_authority=lease.child_authority,
                    require_approved_current=True,
                    require_household_all_approval=True,
                )
        except (ConsentDenied, LookupError, StaleMemoryVersion) as exc:
            raise RecallAuthorizationDenied("recall_authority_not_current") from exc

    def consume(self, authorization_id):
        self._leases.pop(authorization_id, None)

```

```python
# apps/core/src/tuntun_core/services/memory/context.py
from typing import Annotated,Literal
from pydantic import BaseModel, ConfigDict, Field
from tuntun_contracts.provider import SanitizedProviderMessage
from tuntun_core.services.memory.recall_authorization import RecallAuthorizationDenied

class ProviderMemoryClaim(BaseModel):
    model_config=ConfigDict(frozen=True,extra="forbid",strict=True)
    claim:Annotated[str,Field(min_length=1,max_length=2_000)]

class ProviderDraft(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    provider:Literal["openai","qwen"]
    model:Annotated[str,Field(min_length=1,max_length=128)]
    messages_without_memory:Annotated[tuple[SanitizedProviderMessage,...],Field(min_length=1,max_length=32)]
    memory_claims:Annotated[tuple[ProviderMemoryClaim,...],Field(min_length=0,max_length=6)]=()

class MemoryContextBuilder:
    def __init__(self, sanitizer, token_counter, recall_authorizations, clock):
        self._sanitizer, self._token_counter = sanitizer, token_counter
        self._recall_authorizations, self._clock = recall_authorizations, clock

    async def build_once_sanitized(self, selected, provider_draft, maximum_tokens):
        bounded = list(selected)
        while True:
            try:
                await self._recall_authorizations.require_current_exact(tuple(bounded), now=self._clock.now())
            except RecallAuthorizationDenied:
                bounded.clear()
            unsanitized=ProviderDraft(
                provider=provider_draft.provider,model=provider_draft.model,
                messages_without_memory=provider_draft.messages_without_memory,
                memory_claims=tuple(
                    ProviderMemoryClaim.model_validate(item.to_provider_claim())
                    for item in bounded
                ),
            )
            request = self._sanitizer.sanitize_and_commit_route(unsanitized)
            if self._token_counter.count_serialized(request) <= maximum_tokens:
                return tuple(bounded), request, self._token_counter.count_serialized(request)
            if not bounded:
                raise ValueError("base_provider_context_exceeds_8000_tokens")
            bounded.pop()
```

```python
# apps/core/src/tuntun_core/services/providers/token_counter.py
class TokenCounter:
    def __init__(self, encoder):
        self._encoder = encoder

    def count_serialized(self, request):
        canonical = request.model_dump_json(exclude_none=True, by_alias=True)
        return len(self._encoder.encode(canonical))
```

```python
# scripts/build_memory_eval_corpus.py
from itertools import product
from pathlib import Path
import json
languages=("en","hi","hinglish"); kinds=("working","episodic","semantic","preference","procedural","relational","policy"); rows=[]
for index,(language,kind) in enumerate(product(languages,kinds)):
    for repeat in range(6): rows.append({"case_id":f"{language}-{kind}-{repeat}","language":language,"kind":kind,"query":f"synthetic {language} query {index}-{repeat}","expected_memory_ids":[f"synthetic-{kind}-{repeat}"],"distractor_subject":"other-subject"})
Path("evals/cases/multilingual-memory.jsonl").write_text("".join(json.dumps(row,sort_keys=True)+"\n" for row in rows))
assert len(rows)==126
```

Run: `uv run python scripts/build_memory_eval_corpus.py`
Expected: exit 0 and `evals/cases/multilingual-memory.jsonl` contains exactly 126 synthetic cases.

```yaml
# models/manifest.yaml retrieval entry
- id: intfloat-multilingual-e5-small
  revision: 0e60b8d9d2166d80387f86e3b48ec9ced55f4d15
  purpose: local_memory_retrieval
  activation: blocked_calibration
  dimensions: 384
  runtime: onnx
```

```python
# apps/core/src/tuntun_core/workflows/nodes.py
from dataclasses import dataclass
from tuntun_contracts.policy import PolicyEffect

@dataclass(frozen=True)
class RecallAuthorization:
    allowed: bool
    reason_code: str

    @property
    def empty(self):
        return not self.allowed

async def authorize_recall(state, services):
    policy = await services.policy.decide(state.to_recall_policy_request())
    allowed = policy.effect is PolicyEffect.ALLOW
    return state.with_recall_authorization(RecallAuthorization(allowed=allowed, reason_code=policy.reason_code))

async def retrieve_context(state, services):
    if state.recall_authorization.empty:
        return state.with_selected_memory((), 0)
    result = await services.memory_retrieval.retrieve(state.to_scoped_recall_query())
    bounded, sanitized, tokens = await services.memory_context.build_once_sanitized(result.memories, state.provider_draft, 8000)
    claims = tuple(item.to_provider_claim() for item in bounded)
    return state.with_selected_memory_and_sanitized_request(claims, tokens, sanitized)

async def propose_memories(state, services):
    for provider_intent in state.validated_assistant_turn.memory_proposals:
        draft = services.memory_proposal_mapper.map_memory(provider_intent, state.household_id, state.session_id, state.turn_id)
        await services.memory_proposals.stage(draft, state.to_proposal_context())
    return state
```

```python
# apps/core/migrations/versions/0005_memory_embeddings.py
from alembic import op
import sqlalchemy as sa

revision = "0005_memory_embeddings"
down_revision = "0004_memory"

def upgrade() -> None:
    op.create_table("memory_embeddings", sa.Column("id", sa.String(36), primary_key=True), sa.Column("memory_id", sa.String(36), nullable=False), sa.Column("model_id", sa.String(128), nullable=False), sa.Column("dimensions", sa.Integer, nullable=False), sa.Column("ciphertext", sa.LargeBinary, nullable=False), sa.Column("nonce", sa.LargeBinary, nullable=False), sa.Column("wrapped_dek", sa.LargeBinary, nullable=False), sa.Column("root_key_id", sa.String(128), nullable=False), sa.Column("created_at", sa.String(32), nullable=False), sa.CheckConstraint("dimensions = 384"), sa.UniqueConstraint("memory_id", "model_id"))

def downgrade() -> None:
    op.drop_table("memory_embeddings")
```

Register the exact reviewed revision through the governed installer:

```bash
uv run tuntunctl models install intfloat-multilingual-e5-small --revision 0e60b8d9d2166d80387f86e3b48ec9ced55f4d15 --purpose local_memory_retrieval
```

Expected: `installed intfloat-multilingual-e5-small revision=0e60b8d9d2166d80387f86e3b48ec9ced55f4d15 hashes=verified activation=blocked_calibration`.

- [ ] **Step 4: Run green, integration, privacy, and fixed acceptance gates**

Run: `uv run pytest tests/unit/memory/test_retrieval.py tests/security/test_context_minimization.py tests/acceptance/test_multilingual_memory_retrieval.py tests/integration/test_personalized_memory_turn.py tests/integration/test_guest_private_memory_denial.py tests/integration/storage/test_migrations.py -q`
Expected: PASS; the fixed 120+ case report satisfies Recall@6 ≥0.90, MRR@6 ≥0.75, zero cross-profile leakage, no more than six items, and no request above 8,000 tokens.

- [ ] **Step 5: Run the affected workflow suite and commit**

Run: `uv run pytest tests/unit/workflows tests/integration/test_langgraph_turn.py tests/security/test_langgraph_non_ownership.py tests/security/test_provider_boundary.py -q && uv run ruff format --check apps/core/src/tuntun_core/services/memory apps/core/src/tuntun_core/adapters/embeddings/multilingual_e5.py apps/core/src/tuntun_core/services/providers/token_counter.py apps/core/src/tuntun_core/workflows/nodes.py apps/core/src/tuntun_core/workflows/conversation.py tests/unit/memory/test_retrieval.py tests/security/test_context_minimization.py tests/acceptance/test_multilingual_memory_retrieval.py tests/integration/test_personalized_memory_turn.py tests/integration/test_guest_private_memory_denial.py && uv run ruff check apps/core/src/tuntun_core/services/memory apps/core/src/tuntun_core/adapters/embeddings/multilingual_e5.py apps/core/src/tuntun_core/services/providers/token_counter.py apps/core/src/tuntun_core/workflows/nodes.py apps/core/src/tuntun_core/workflows/conversation.py tests/unit/memory/test_retrieval.py tests/security/test_context_minimization.py tests/acceptance/test_multilingual_memory_retrieval.py tests/integration/test_personalized_memory_turn.py tests/integration/test_guest_private_memory_denial.py && uv run mypy apps/core/src/tuntun_core/services/memory apps/core/src/tuntun_core/adapters/embeddings apps/core/src/tuntun_core/services/providers/token_counter.py apps/core/src/tuntun_core/workflows`
Expected: PASS with exit code 0 and zero checkpoint/provider-capture sentinels.

```bash
git add apps/core/src/tuntun_core/services/memory/retrieval.py apps/core/src/tuntun_core/services/memory/embeddings.py apps/core/src/tuntun_core/services/memory/context.py apps/core/src/tuntun_core/adapters/embeddings/multilingual_e5.py apps/core/src/tuntun_core/services/providers/token_counter.py apps/core/migrations/versions/0005_memory_embeddings.py models/manifest.yaml apps/core/src/tuntun_core/workflows/nodes.py apps/core/src/tuntun_core/workflows/conversation.py tests/unit/memory/test_retrieval.py tests/security/test_context_minimization.py tests/acceptance/test_multilingual_memory_retrieval.py evals/cases/multilingual-memory.jsonl scripts/build_memory_eval_corpus.py tests/integration/test_personalized_memory_turn.py tests/integration/test_guest_private_memory_denial.py
git diff --cached --name-only
git diff --cached
git commit -m "feat(memory): add local scoped retrieval workflow"
```

## B1 Subplan Checkpoint

The twelve independently reviewable tasks total exactly 34 person-days: master Task 17 = 3, Task 18 = 5, Task 19 = 6, Task 20 = 8, Task 21 = 5, and Task 22 = 7. Calibration, policy-matrix, isolation/benchmark, and multilingual-retrieval evidence belongs to the task estimates and commits that define those gates; no unowned effort remains outside the TDD tasks.

Before enrolling a real family member or entering a real memory, run:

```bash
uv run pytest tests/unit/identity tests/unit/policy tests/unit/actions tests/unit/memory -q
uv run pytest tests/integration/identity tests/integration/memory tests/integration/test_personalized_memory_turn.py tests/integration/test_guest_private_memory_denial.py -q
uv run pytest tests/security/test_enrollment_authorization.py tests/security/test_face_retention.py tests/security/test_face_presentation_attacks.py tests/security/test_identity_interaction_gate.py tests/security/test_identity_negative_reachability.py tests/security/test_voice_retention.py tests/security/test_voice_replay_attacks.py tests/security/test_biometric_authorization.py tests/security/test_confirmation_binding.py tests/security/test_auth_replay.py tests/security/test_auth_rate_limit.py tests/security/test_passkey_binding.py tests/security/test_recovery.py tests/security/test_local_presence.py tests/security/test_action_proposal_boundary.py tests/security/test_memory_isolation.py tests/security/test_memory_write_policy.py tests/security/test_memory_deletion.py tests/security/test_context_minimization.py -q
uv run pytest tests/acceptance/test_multilingual_memory_retrieval.py -q
uv run pytest tests/acceptance/test_face_calibration.py tests/acceptance/test_voice_calibration.py -q
make verify-private-data
```

Expected: every command exits 0; identity calibration reports zero false personalization in 500 held-out comparisons and at least 90% accepted-quality genuine identification; the retrieval report satisfies its fixed gates; private-data scanning reports zero unauthorized raw media, transcript, biometric vector, secret, or private-memory sentinel.

The owner signs B1 only when:

- adult self-consent and guardian-child consent tests pass;
- passive/background discovery and unknown-candidate storage are absent across contracts, configuration, migrations, routes, feature manifests, UI projections, and runtime consumers;
- face and voice models have immutable hashes, accepted licenses/provenance, target-Mac calibration, and accepted presentation/replay results;
- unavailable or failed liveness produces Guest and cannot authorize an action; explicit non-biometric identity selection remains a separate personalization-only path;
- conflict, ambiguity, expiry, revocation, or a child template past its 365-day hard expiry produces Guest;
- every model action remains a pending typed proposal until local policy/auth/idempotency execution;
- seven memory kinds, approval rules, immutable revisions, 1,000-case isolation, six-item limit, and 8,000-token ceiling pass;
- the repository, logs, graph checkpoints, provider captures, exports, and test artifacts contain no prohibited sentinel.

## Implementation Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-27-tuntun-phase1-identity-memory-execution.md`. Two execution options:

1. **Subagent-Driven (recommended):** use `superpowers:subagent-driven-development`, dispatch one fresh implementation worker per task, and perform specification then code-quality review before continuing.
2. **Inline Execution:** use `superpowers:executing-plans`, execute tasks in order, and stop after Tasks 2, 5B, 8, and 11 for checkpoint review.
