# Tuntun Phase 6 Remote Access and Product Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the accepted local-first Phase 1–5 household system into a recoverable, supportable, signed Apache-2.0 beta with an optional owner-only Tailscale route to the existing console, while preserving LAN/local operation as the default and never creating a public service, delegated recovery authority, or general plugin surface.

**Architecture:** The Intel Mac remains the only canonical household authority. Phase 6 adds a provider-neutral `RemoteAccessPort` with one disabled-by-default Tailscale adapter, an exact-interface exposure guard, independent passkey-authenticated application sessions, a closed out-of-process two-capability plugin supervisor, and quarantined release/recovery/incident services. Every optional remote scope is separately registered after evidence; release proceeds on one immutable candidate through whole-program `C0` and then a distinct `C1`, never through Phase 1 `P1R0/P1R1` or a waiver.

**Tech Stack:** Python 3.12, `asyncio`, Pydantic v2, SQLAlchemy 2/Alembic over SQLCipher, macOS Keychain/FileVault/local CA, FastAPI/Uvicorn, WebAuthn/passkeys, authenticated Unix-domain sockets and Darwin peer credentials, macOS `launchd`/firewall/process-sandbox controls, the official Tailscale client behind a project-owned adapter, React 19/TypeScript/Vite/TanStack Query, pytest/pytest-asyncio/Hypothesis, Ruff, strict mypy, Vitest/Testing Library/Playwright/axe, SPDX SBOM, Sigstore-backed provenance, SLSA Build Level 2 initial target, Developer ID/hardened-runtime/notarization/stapling/Gatekeeper tooling, synthetic simulators, and content-safe signed evidence.

**Normative design:** [Phase 6 Remote Access & Product Hardening](../specs/2026-08-27-tuntun-phase6-remote-access-product-hardening-design.md), [Program A–H](../specs/2026-08-27-tuntun-program-architecture-a-h.md), [Program I–S](../specs/2026-08-27-tuntun-program-assurance-delivery-i-s.md), and [Six-Phase UI/UX](../specs/2026-08-27-tuntun-six-phase-ui-ux-design.md).

## Authority and Upstream Reconciliation

1. The current Phase 6 design owns all Phase 6 values, fields, limits, states, gates, and exclusions. Program A–H owns shared architecture/contracts, Program I–S owns assurance/operations/repository rules, and the UI design owns truthful projection, prepared-mutation, accessibility, and feature-registration behavior. The more restrictive current rule wins.
2. `P6-E0` requires the accepted Phase 1–5 release gates and current canonical contracts. A canonically optional upstream route may remain absent only with its owning feature-manifest declaration and negative reachability. A mandatory earlier-phase gate cannot be relabelled optional, waived, or replaced by documentation.
3. Phase 1 `P1R0` and `P1R1` remain standalone Phase 1 preview gates. They never satisfy, alias, rename, or contribute approval authority to whole-program `C0` or `C1`.
4. The exact initial plugin manifest is the Phase 6 Section 8.2 eleven-field contract. Program A–H's catalogue shorthand does not add `resource_profile` or any publisher-controlled policy field. Platform resource policy lives only in the signed `phase6.initial.1` registry.
5. Tailscale is the sole remote adapter implemented or packaged in the six-phase release. Provider neutrality is a core-port property, not authority to ship a direct WireGuard, relay, rendezvous, subnet-router, exit-node, public-Serve, Funnel, or public-tunnel implementation.
6. Recovery, restore, recovery-key display/import, deletion reconciliation, device retirement, household release installation, C0 approval/signing, and incident exit are one-owner local-presence ceremonies. Public multi-owner representations do not enable delegation, quorum, guardian, partner, maintainer, or plugin-publisher household/recovery authority. C1/publication is deliberately separate: an independently provisioned project-maintainer credential at a local release terminal may approve public artifacts, but it cannot authenticate to a household, satisfy C0, or exercise any owner operation—even when the same human holds both credentials.
7. C0 and C1 run in that order against one immutable commit/version/feature manifest and exact artifact set. Any source, lockfile, workflow, schema, dependency, package, feature manifest, evidence-policy, or artifact change after C0 invalidates C0 and C1.

## Global Constraints

1. Localhost and accepted private-LAN operation remain fully usable with Tailscale disabled or absent and with VPN, internet, repository, update service, or Tailscale control plane unavailable.
2. A clean install has remote state `DISABLED`, no remote route/listener/adapter registration, no VPN client requirement, and no household state exposed through a VPN interface.
3. The only eligible remote origin is `https://tuntun.home.arpa:8443` over the exact approved Tailscale interface and least-route ACL. Binding `0.0.0.0`, an unclassified interface, a public hostname, or a public address is forbidden.
4. Router port-forwarding, UPnP, NAT-PMP, PCP, public reverse proxy/tunnel, public REST/webhook/API, public Home Assistant, Tailscale Funnel, public Serve, subnet routing, exit-node routing, Tailscale SSH, arbitrary remote shell, and whole-LAN reach are absent and negatively tested.
5. Direct/self-managed WireGuard, a home UDP listener, self-managed relay/rendezvous, and any configuration switch or test bypass enabling them are absent from source registration, binaries, packages, configuration, UI, API, and live listeners.
6. Tailscale account, username, email, node name, IP address, and control-plane assertion never become the application actor or canonical household state. Core receives only a random local node pseudonym and approved posture generations.
7. VPN membership and Tuntun application authentication are independent. Every remote session requires an approved VPN node plus a valid owner passkey session with exact Host/Origin, CSRF, nonce, replay, rate, object-authorization, expiry, and revocation enforcement.
8. `remote_session.v1` idles after 15 minutes and expires absolutely after 8 hours. Approval bodies, private memory, mutations, and camera playback require a passkey no older than 5 minutes.
9. Revoking the VPN node, owner passkey/session, remote policy, route, device-approval generation, privacy generation, or application revocation generation invalidates associated remote sessions immediately.
10. Read-only health, availability, content-minimized alerts/cost, and approval-inbox metadata are the first remote production class. Approval bodies remain concealed without fresh step-up.
11. Private memory/approval detail, reversible light/media-stop actions, camera metadata, and camera playback are each disabled initially and separately enabled only after their exact P6-2 positive, negative, theft, freshness, and revocation gates.
12. A remote operation is always assurance-reducing through `remote_origin_v1`. It traverses the ordinary action registry, current topology/binding, risk, confirmation, idempotency, controller epoch, child/Guest/device/room/time/privacy policy, and downstream adapter; remote origin never upgrades a local denial.
13. Export/download, identity or biometric enrollment/calibration, profile/guardian/base-policy/provider/hard-cap/bind-mode/plugin-permission changes, recovery-key operations, restore, bulk/profile deletion, audit-key rotation, developer mode, release signing/approval, desktop execution, Raspbot driving/video, remote microphone/camera activation, and shell access remain locally unreachable from remote UI, API, configuration, replay, and direct request.
14. Remote camera playback is disabled by default. When separately approved, one owner-bound single-clip remote media session lasts at most 10 minutes; each byte/time range uses a fresh single-use Phase 3 grant lasting at most 60 seconds. Both layers are `no-store`, enumerate no other clip, reveal no RTSP/ONVIF credential or URL, and revoke together.
15. Remote route state is exactly `DISABLED → COMMISSIONING → READ_ONLY → SCOPED_ACTIONS`; any state may enter `SUSPENDED`, then only `DISABLED` or the prior locally re-approved state. Lost device, ACL/Tailnet Lock/client/certificate/firewall drift, impossible node state, repeated authentication failure, or owner action suspends.
16. The initial third-party capability registry revision is exactly `phase6.initial.1`, containing only `system.health.render.v1` and `notification.local_alert.render.v1`. Every other capability ID is unknown and denied.
17. Plugin manifests contain exactly `plugin_id`, `version`, `publisher`, `artifact_digest`, `signature_identity`, `protocol_major`, `capability_registry_revision`, `entrypoint`, `requested_capability_ids`, `licence`, and `sbom_digest`. `plugin.manifest.v1` is an out-of-band local dispatch/schema label, never a serialized manifest field; an input key named `schema_id` fails closed. No publisher-defined policy, purpose, DTO, actor, consent, sensitivity, retention, storage, egress, DNS, redirect, cleanup, or resource field is accepted.
18. Both plugin capabilities are display-only closed text DTOs. Markup, HTML, URLs, images, actions, hidden text, bidi controls, arbitrary labels, authorization/audit verdicts, observations, proposals, memories, policies, targets, credentials, model/tool ingestion, and downstream effects are rejected.
19. Every plugin call uses a fresh process under a dedicated unprivileged identity, authenticated Unix socket, no inherited secret, no writable mount, no persistence, no egress/network syscall, no DNS resolver, no URL/redirect path, a 5-second deadline, one concurrent request, 128 MiB memory, 50% of one CPU core, and 64 KiB total request/response limit.
20. `notification.local_alert.render.v1` is optional presentation beside the mandatory core local alert. A missing, denied, crashed, timed-out, malicious, revoked, or removed plugin cannot suppress, downgrade, acknowledge, close, forward, delay, or replace the authoritative alert.
21. Privacy Shield atomically revokes remote sessions/routes and plugin grants/jobs under `p6.remote_plugin` before fan-out, while preserving the independent local critical-alert surface and the truthful continued Reolink-recorder state.
22. Public contracts are strict semantic versions: duplicate keys, non-finite numbers, unknown fields/major versions/enums/discriminators/generations and oversize/replay/expiry fail closed. Current major support spans the stable release plus one documented migration release.
23. Remote/application/plugin audit is content-minimized. It stores pseudonyms, route/capability/outcome/version/latency/commitments only—never IPs, email, node names, request bodies, memory, plugin text, clip URLs, private diagnostics, or provider bodies. Remote detail retains 180 days; rate/security counters retain 30 days unless incident-bound.
24. Browser responses containing memory, approvals, clips, documents, backups, or audit exports use `Cache-Control: no-store`. Service workers, browser persistent private storage, analytics, background push, and reusable media URLs remain absent.
25. External application telemetry is off by default. Any crash report is generated from content-safe fields, scanned, shown exactly to the owner, and transmitted only after explicit opt-in.
26. Portable recovery holds seven daily and four weekly attached generations plus at least one current independently stored encrypted Tuntun/Green copy. Routine raw camera retention is excluded unless separately approved.
27. Portable recovery excludes provider, VPN, Mac leaf-TLS, device, and release-signing credentials. The owner recreates them after quarantined restore using offline recovery material and a fresh local action-bound passkey.
28. Restore begins with all action, routine, remote, plugin, desktop, camera-outcome, selected-frame, media-control, and robot routes closed. Integrity, migrations, deletion tombstones, topology, bindings, keys, credentials, policy and new generations reconcile before one phase is re-enabled at a time.
29. Deletion is reconciled across every managed backup/recovery generation; a clean restore must resurrect no deleted profile/data or prior authority. Owner exports and vendor/provider copies are separately disclosed and never claimed erased.
30. Incident states are exactly `NORMAL`, `CONTAINED_REMOTE`, `CONTAINED_EGRESS`, and `RECOVERY_QUARANTINE`. Containment remains locally enterable without internet/model; exit requires the owner, local presence, action-bound passkey, integrity/secret/credential checks, and new controller/session generations.
31. Updates are visible and owner-approved: strict staged download, signer/provenance/repository/workflow/version/SBOM/feature/compatibility checks, independently verified encrypted pre-update backup, transactional drain, quarantined migration, health/privacy/network/device probes, and atomic rollback. They are never silent or remotely installed.
32. Public builds use locked dependencies/actions, licence notices, SPDX SBOM, SLSA L2 provenance/attestation, immutable checksums/signatures/tags/assets, exact feature/compatibility/evidence manifests, and manual publication. Fork CI receives no production, signing, notarization, provider, VPN, or household secret.
33. The public macOS package requires Developer ID signing, hardened-runtime/entitlement review, Apple notarization, stapling, Gatekeeper, clean install, upgrade, rollback, and preserving uninstall on the supported 2020 Intel Mac plus at least one current declared Apple Silicon target. Unsigned builds are visibly developer-only.
34. Source, history, CI logs, fixtures, screenshots, docs, examples, issues, diagnostics, SBOM, evidence, and release artifacts contain no household secret, identity, biometric, transcript, raw media, private memory, stable household identifier, real network address, certificate, receipt, or configuration.
35. `T01`–`T25` each map to a named prevention/detection control, automated or owner-gated test, content-safe evidence, residual-risk owner, expiry/review, and disable/fallback. Any unresolved high/critical risk blocks the affected feature and release; no waiver path exists.
36. Whole-program C0 uses one immutable candidate and every mandatory Phase 1–6 gate plus negative reachability for canonically optional absent routes. C1 follows only after accepted C0 on the unchanged candidate and binds the exact public artifacts. Two fresh local passkey approvals are distinct; publication is a third, manual action.
37. Evidence logging may begin after 60 steady-state days. Evaluation for promotion requires at least 90 steady-state days and three complete monthly buckets; at that point, the full Phase 1–6 rolling three-month median of ordinary owner maintenance is at most 8 hours/month with subsystem attribution. Three consecutive months above 8 hours freeze optional expansion and trigger simplification or retirement review.
38. Ordinary maintenance includes health/backup/certificate/key/storage/device/plugin/update work. Commissioning, quarterly restore/security/physical-safety drills, incidents, hardware replacement, unplanned repair, and major migrations are recorded separately and cannot lower the ordinary metric.
39. Ordinary tests use fake clocks, temporary encrypted stores/keys, synthetic profiles/data/devices/providers/plugins/releases, and no paid API, household data, Keychain, WAN, Tailscale account, Apple signing credential, hardware, notarization, or publication. Owner-gated probes write content-safe evidence under ignored `var/evidence/phase6/`.
40. Project branch coverage remains at least 85%; authorization/session/route/exposure/plugin sandbox/release verifier/update/restore/deletion/incident/C0/C1 modules remain at least 95%. Every task follows red → green → affected suite → static/security checks → exact-path review → commit.

## Definition of Done for Every Task

- The named test is observed failing for the intended missing behavior before implementation.
- Narrow and affected Python suites pass with Ruff format/check and strict mypy; touched UI and packaging code passes lint, typecheck, unit, Playwright/axe, and deterministic build checks.
- Contract changes regenerate JSON Schema, OpenAPI, TypeScript, fixtures, migration compatibility, feature digests, and negative-reachability evidence in the same task.
- Persistence work includes encrypted pre-migration backup, forward migration, downgrade or isolated-restore strategy, interruption/corruption tests, strict table/index/trigger ownership, and forbidden-content column scans.
- Every route, session, plugin call, update, backup, restore, incident transition, and approval rechecks current policy/resource/privacy/revocation generations immediately before acceptance or I/O and after untrusted results return.
- A conditional feature proves either its positive gate or absence across package, source registration, configuration, API, prepared-action issuance, UI/direct URL/client bundle, IPC, listener, route, replay, and direct request.
- Logs, browser/cache/storage, sandboxes, process arguments/environments, packet captures, crash bundles, backups, diagnostics, evidence, source/history, CI, SBOM, and public artifacts pass secret/family/content/network sentinels.
- Owner-gated evidence binds clean commit/version, schemas/policies/features, exact pseudonymous hardware/OS/client/config, command, operator, start/end, metrics, result, artifact digests, invalidation triggers, and disabled exit without raw household identifiers/content.
- `git status --short` contains only task-owned paths; exact paths are staged; `git diff --cached --name-only`, `git diff --cached --check`, and `git diff --cached` are reviewed before the task commit.

## Phase Entry, Promotion, and Exit Gates

| Gate | Entry requirement | Positive exit | Disabled/failed exit |
|---|---|---|---|
| P6-E0 | Accepted Phase 1–5 gates and current canonical contracts; every conditional absent upstream route has signed negative evidence | Contract/schema/migration baseline, default feature absence, synthetic corpora and existing mandatory regressions pass | Every Phase 6 route/adapter/plugin/update/publication capability remains absent |
| P6-0 | P6-E0 | Consolidated service/asset/data/exposure inventory, A–S artifacts, T01–T25 control map, threat/privacy/risk/decision registers and clean-install LAN-only evidence pass | No remote/plugin/public-release promotion |
| P6-1 | P6-0 plus locally installed official Tailscale client and owner-approved account review | Local commissioning, exact least route, Tailnet Lock/device approval, app passkey, theft/revoke/drift/failure tests and seven-day read-only soak pass | Route enters `DISABLED`/`SUSPENDED`; local system remains unchanged |
| P6-2 | Accepted P6-1 | Each explicitly selected low-risk action, camera metadata, private detail, or playback class independently passes positive/negative/theft/revocation gates | Failed/unselected class is absent; read-only route may remain |
| P6-3 | P6-0 plus enforceable plugin sandbox and release credentials/runners | Exact two plugin paths and isolation pass; reproducible synthetic build, SBOM/provenance/signature/notarization, clean Intel/Apple-Silicon install/update/rollback/preserve-uninstall pass | Plugin/release gate blocks; prior household version remains |
| P6-4 | P6-0/P6-3 | Independent owner-only backup/clean restore/deletion reconciliation, incident/containment, retirement, weekly health, maintenance, UI truth and every failure injection pass | Affected route stays quarantined; no recovery/release claim |
| P6-5 | P6-1–P6-4 plus complete same-candidate Phase 1–6 evidence | Whole-program C0 accepted, then unchanged-candidate C1 accepted, then publication manually performed; signed immutable beta/support matrix verifies | Failure returns to a new candidate/C0; no waiver or automatic publication |

## Planned Repository Map

~~~text
packages/contracts/src/tuntun_contracts/hardening/
├── __init__.py
├── base.py                    # strict public model and canonical bytes
├── remote.py                  # remote node/session/route contracts
├── plugins.py                 # exact manifest and two render DTO pairs
├── release.py                 # release/update/compatibility evidence
├── recovery.py                # backup/restore/deletion receipts
├── incident.py                # containment state and local-alert facts
├── maintenance.py             # whole-system owner-work contracts
├── ui.py                      # owner-safe Phase 6 projections
└── ports.py                   # provider-neutral remote/plugin/release ports
packages/plugin-sdk/src/tuntun_plugin_sdk/
├── __init__.py
├── protocol.py
├── health_render.py
└── local_alert_render.py
schemas/hardening/v1/
schemas/plugins/phase6.initial.1/
schemas/releases/v1/
fixtures/synthetic/phase6/
├── contracts/
├── remote/
├── plugins/
├── releases/
├── recovery/
├── maintenance/
└── ui/
fixtures/adversarial/phase6/
├── remote-auth-v1.jsonl
├── exposure-v1.jsonl
├── plugin-manifest-v1.jsonl
├── plugin-result-v1.jsonl
├── update-manifest-v1.jsonl
├── archive-v1.jsonl
└── threat-cases-t01-t25.jsonl

apps/core/src/tuntun_core/domain/hardening/
├── remote.py
├── plugin.py
├── release.py
├── recovery.py
├── incident.py
└── maintenance.py
apps/core/src/tuntun_core/services/hardening/
├── remote_commissioning.py
├── remote_sessions.py
├── remote_policy.py
├── remote_revocation.py
├── exposure_guard.py
├── plugin_installation.py
├── plugin_invocation.py
├── release_verifier.py
├── updater.py
├── recovery.py
├── incident.py
├── maintenance.py
├── privacy_effects.py
└── health.py
apps/core/src/tuntun_core/api/routes/remote_access.py
apps/core/src/tuntun_core/api/routes/plugins.py
apps/core/src/tuntun_core/api/routes/releases.py
apps/core/src/tuntun_core/api/routes/recovery.py
apps/core/src/tuntun_core/api/routes/incidents.py
apps/core/src/tuntun_core/api/phase6_dtos.py
apps/core/migrations/versions/
├── 0023_remote_access.py
├── 0024_plugins_releases.py
└── 0025_recovery_incident_maintenance.py

integrations/remote-access/src/tuntun_remote_access/
├── __init__.py
├── tailscale.py
├── client_state.py
├── posture.py
└── sanitized_errors.py
apps/plugin-supervisor/src/tuntun_plugin_supervisor/
├── server.py
├── verifier.py
├── registry.py
├── sandbox.py
├── process.py
├── quotas.py
├── ipc.py
└── cleanup.py

apps/admin/src/features/system/
├── remote-access.tsx
├── remote-sessions.tsx
├── plugins.tsx
├── updates.tsx
├── backup-recovery.tsx
├── incidents.tsx
├── maintenance.tsx
└── release-diagnostics.tsx
apps/admin/src/routes/system-remote-access.tsx
apps/admin/src/routes/system-plugins.tsx
apps/admin/src/routes/system-updates.tsx
apps/admin/src/routes/system-recovery.tsx
apps/admin/src/routes/system-incidents.tsx
apps/admin/src/routes/system-maintenance.tsx

ops/network/
├── exposure-manifest.v1.yaml
├── verify_listeners.py
├── verify_routes.py
├── verify_router_mappings.py
├── verify_lateral_reachability.py
└── verify_external_exposure.py
ops/remote-access/
├── tailscale-acl.template.hujson
├── commission.py
├── disable.py
└── verify_posture.py
ops/plugins/
├── phase6.initial.1.registry.json
├── verify_registry.py
├── plugin.sb
└── qualify_sandbox.py
ops/release/
├── build.py
├── verify.py
├── sbom.py
├── attest.py
├── sign.py
├── notarize.py
├── publish.py
└── compatibility.py
ops/install/
├── install.py
├── uninstall.py
└── verify_clean_system.py
ops/backup/
├── create_independent.py
├── verify_independent.py
└── restore_isolated.py
ops/runbooks/phase6/

scripts/phase6/
├── generate_schemas.py
├── build_corpora.py
├── inventory_system.py
├── verify_default_absence.py
├── run_remote_pilot.py
├── run_plugin_qualification.py
├── run_restore_drill.py
├── run_retirement_drill.py
├── run_threat_matrix.py
├── run_stress.py
├── run_household_soak.py
├── evaluate_maintenance.py
├── build_c0.py
├── approve_c0.py
├── build_c1.py
├── approve_c1.py
└── verify_release.py
.github/workflows/ci.yml
.github/workflows/release-candidate.yml
.github/workflows/attest.yml
LICENSE
SECURITY.md
CODE_OF_CONDUCT.md
CONTRIBUTING.md
SUPPORT.md
docs/architecture/system-inventory.md
docs/security/threat-model.md
docs/security/risk-register.md
docs/privacy/data-flow-inventory.md
docs/privacy/phase6-remote-plugin-privacy.md
docs/operations/phase6-remote-access.md
docs/operations/phase6-plugins.md
docs/operations/phase6-update-rollback.md
docs/operations/phase6-backup-restore.md
docs/operations/phase6-incidents.md
docs/operations/phase6-retirement-uninstall.md
docs/operations/phase6-maintenance.md
docs/release/compatibility-matrix.md
docs/release/publication.md
docs/evidence/phase6-evidence-schema.json
docs/evidence/c0-evidence-schema.json
docs/evidence/c1-evidence-schema.json
~~~

## Frozen Contract and Policy Baseline

All fields are required unless marked optional. Implementations may add private helpers but may not rename, loosen, enrich, or join these public contracts.

~~~python
# packages/contracts/src/tuntun_contracts/hardening/base.py
def _validate_plain_safe_text(value: object) -> str:
    if not isinstance(value, str) or not value or contains_markup_url_hidden_or_bidi(value):
        raise ValueError("hardening_plain_text_invalid")
    return value

PlainSafeText = Annotated[str, BeforeValidator(_validate_plain_safe_text)]

def _validate_bounded_identity_token(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 3 <= len(value) <= 256
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@-]*", value)
        or ".." in value
        or "//" in value
    ):
        raise ValueError("hardening_identity_token_invalid")
    return value

def _validate_spdx_licence_expression(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 256:
        raise ValueError("spdx_licence_expression_invalid")
    parsed = parse_spdx_licence_expression(value)
    if not parsed.is_valid or parsed.canonical != value:
        raise ValueError("spdx_licence_expression_not_canonical")
    return value

BoundedPublisherIdentity = Annotated[str, BeforeValidator(_validate_bounded_identity_token)]
BoundedRepositoryIdentity = Annotated[str, BeforeValidator(_validate_bounded_identity_token)]
BoundedSignatureIdentity = Annotated[str, BeforeValidator(_validate_bounded_identity_token)]
BoundedWorkflowIdentity = Annotated[str, BeforeValidator(_validate_bounded_identity_token)]
SpdxLicenceExpression = Annotated[str, BeforeValidator(_validate_spdx_licence_expression)]

def _validate_relative_plugin_entrypoint(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", value):
        raise ValueError("plugin_entrypoint_syntax_invalid")
    path = PurePosixPath(value)
    if (
        value != path.as_posix()
        or path.is_absolute()
        or any(part in {".", ".."} for part in path.parts)
        or len(path.parts) > 8
        or path.suffix not in {".py", ".sh", ".bin"}
    ):
        raise ValueError("plugin_entrypoint_path_invalid")
    return value

BoundedRelativeEntrypoint = Annotated[str, BeforeValidator(_validate_relative_plugin_entrypoint)]

PluginComponentClass = Literal[
    "core", "voice", "identity", "memory", "automation", "video", "media",
    "desktop", "robot", "storage", "remote",
]

YearMonth = Annotated[str, Field(pattern=r"^[0-9]{4}-(?:0[1-9]|1[0-2])$")]
NonNegativeMinutes = Annotated[int, Field(ge=0, le=44_640)]

class MaintenanceSubsystem(str, Enum):
    PHASE1_FOUNDATION_CONTROL = "phase1_foundation_control"
    PHASE1_CONVERSATION_IDENTITY_MEMORY = "phase1_conversation_identity_memory"
    PHASE2_HOME_AUTOMATION = "phase2_home_automation"
    PHASE3_VISION_STORAGE = "phase3_vision_storage"
    PHASE4_VOICE_MEDIA_DISPLAYS = "phase4_voice_media_displays"
    PHASE5_PRIVATE_AI_DESKTOP_ROBOTICS = "phase5_private_ai_desktop_robotics"
    PHASE6_REMOTE_PLUGINS_RELEASE = "phase6_remote_plugins_release"
    CROSS_PHASE_BACKUP_RECOVERY_SECURITY = "cross_phase_backup_recovery_security"

class ExcludedMaintenanceClass(str, Enum):
    COMMISSIONING = "commissioning"
    QUARTERLY_RESTORE = "quarterly_restore"
    SECURITY_DRILL = "security_drill"
    PHYSICAL_SAFETY_DRILL = "physical_safety_drill"
    INCIDENT = "incident"
    HARDWARE_REPLACEMENT = "hardware_replacement"
    UNPLANNED_REPAIR = "unplanned_repair"
    MAJOR_MIGRATION = "major_migration"

# packages/contracts/src/tuntun_contracts/hardening/remote.py
class RemoteSessionV1(StrictHardeningContract):
    schema_id: Literal["remote_session.v1"] = "remote_session.v1"
    session_id: UUID
    actor_subject_id: StableSubjectId
    vpn_adapter_id: StableAdapterId
    vpn_node_pseudonym: RandomLocalPseudonym
    device_approval_generation: Annotated[int, Field(ge=1)]
    application_passkey_assurance: Literal["phishing_resistant"]
    established_at: AwareDatetime
    last_reauthenticated_at: AwareDatetime
    absolute_expires_at: AwareDatetime
    idle_expires_at: AwareDatetime
    allowed_operation_classes: Annotated[
        tuple[Literal["read_only_status", "private_detail", "light_power", "media_stop", "camera_metadata", "camera_playback"], ...],
        Field(max_length=6),
    ]
    operation_class_generation: Annotated[int, Field(ge=1)]
    policy_version: Annotated[int, Field(ge=1)]
    revocation_generation: Annotated[int, Field(ge=1)]

    @model_validator(mode="after")
    def valid_session_window(self) -> "RemoteSessionV1":
        if not self.established_at <= self.last_reauthenticated_at < self.absolute_expires_at:
            raise ValueError("remote_reauthentication_window_invalid")
        if self.absolute_expires_at > self.established_at + timedelta(hours=8):
            raise ValueError("remote_absolute_window_exceeded")
        if not self.last_reauthenticated_at < self.idle_expires_at <= self.last_reauthenticated_at + timedelta(minutes=15):
            raise ValueError("remote_idle_window_invalid")
        if self.idle_expires_at > self.absolute_expires_at:
            raise ValueError("remote_idle_after_absolute_expiry")
        if "read_only_status" not in self.allowed_operation_classes:
            raise ValueError("remote_session_missing_read_only_status")
        if len(set(self.allowed_operation_classes)) != len(self.allowed_operation_classes):
            raise ValueError("duplicate_remote_operation_class")
        return self

class RemoteRouteStateV1(StrictHardeningContract):
    schema_id: Literal["remote_route_state.v1"] = "remote_route_state.v1"
    state: Literal["disabled", "commissioning", "read_only", "scoped_actions", "suspended"]
    adapter_id: StableAdapterId | None
    interface_commitment: HmacCommitment | None
    origin: Literal["https://tuntun.home.arpa:8443"] | None
    device_approval_generation: Annotated[int, Field(ge=1)]
    route_generation: Annotated[int, Field(ge=1)]
    revocation_generation: Annotated[int, Field(ge=1)]
    posture: Literal["healthy", "drifted", "unavailable", "not_configured"]
    reason_codes: Annotated[tuple[SafeReasonCode, ...], Field(max_length=8)]
    observed_at: AwareDatetime
    valid_until: AwareDatetime

    @model_validator(mode="after")
    def coherent_route_state(self) -> "RemoteRouteStateV1":
        if not self.observed_at < self.valid_until <= self.observed_at + timedelta(seconds=30):
            raise ValueError("remote_route_validity_invalid")
        bound = self.adapter_id is not None and self.interface_commitment is not None
        any_route_binding = any(value is not None for value in (self.adapter_id, self.interface_commitment, self.origin))
        if self.state in {"read_only", "scoped_actions"}:
            if not bound or self.origin != "https://tuntun.home.arpa:8443" or self.posture != "healthy":
                raise ValueError("active_remote_route_shape_invalid")
        elif self.state == "disabled":
            if any_route_binding or self.posture != "not_configured":
                raise ValueError("disabled_remote_route_shape_invalid")
        elif self.state == "suspended":
            if not bound or self.origin is not None or self.posture not in {"drifted", "unavailable"}:
                raise ValueError("suspended_remote_route_shape_invalid")
        elif self.state == "commissioning" and (self.adapter_id is None or self.origin is not None):
            raise ValueError("commissioning_remote_route_shape_invalid")
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise ValueError("duplicate_remote_route_reason_code")
        if self.state == "suspended" and not self.reason_codes:
            raise ValueError("suspended_remote_route_missing_reason")
        return self

class RemoteAdapterPostureV1(StrictHardeningContract):
    schema_id: Literal["remote_adapter_posture.v1"] = "remote_adapter_posture.v1"
    adapter_id: StableAdapterId
    adapter_class: Literal["tailscale"]
    node_pseudonym: RandomLocalPseudonym
    device_approval_generation: Annotated[int, Field(ge=1)]
    tailnet_lock_state: Literal["enabled", "disabled", "unknown"]
    route_flags: Annotated[
        tuple[Literal["none", "subnet", "exit_node", "funnel", "ssh", "public_serve"], ...],
        Field(min_length=1, max_length=6),
    ]
    client_version_commitment: HmacCommitment
    observed_at: AwareDatetime
    valid_until: AwareDatetime

    @model_validator(mode="after")
    def bounded_unique_posture(self) -> "RemoteAdapterPostureV1":
        if not self.observed_at < self.valid_until <= self.observed_at + timedelta(seconds=30):
            raise ValueError("remote_adapter_posture_window_invalid")
        if len(set(self.route_flags)) != len(self.route_flags):
            raise ValueError("duplicate_remote_route_flag")
        if "none" in self.route_flags and self.route_flags != ("none",):
            raise ValueError("remote_route_none_flag_not_exclusive")
        return self

class TailscaleSelfNodeV1(StrictHardeningContract):
    public_key: Annotated[str, Field(min_length=16, max_length=256, pattern=r"^nodekey:[A-Za-z0-9+/=_-]+$")]
    online: bool
    device_approved: bool

class TailscaleClientStateV1(StrictHardeningContract):
    """Bounded adapter-local projection; vendor identity/address fields are never represented."""

    schema_id: Literal["tailscale_client_state.v1"] = "tailscale_client_state.v1"
    backend_state: Literal["running", "stopped", "needs_login", "unknown"]
    client_version: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[0-9A-Za-z.+_-]+$")]
    self_node: TailscaleSelfNodeV1
    tailnet_lock_state: Literal["enabled", "disabled", "unknown"]
    route_flags: Annotated[
        tuple[Literal["none", "subnet", "exit_node", "funnel", "ssh", "public_serve"], ...],
        Field(min_length=1, max_length=6),
    ]

    @model_validator(mode="after")
    def unique_route_flags(self) -> "TailscaleClientStateV1":
        if len(set(self.route_flags)) != len(self.route_flags):
            raise ValueError("duplicate_tailscale_route_flag")
        if "none" in self.route_flags and self.route_flags != ("none",):
            raise ValueError("tailscale_none_route_flag_not_exclusive")
        return self

class RemoteRouteReceiptV1(StrictHardeningContract):
    schema_id: Literal["remote_route_receipt.v1"] = "remote_route_receipt.v1"
    receipt_id: UUID
    adapter_id: StableAdapterId
    state: Literal["closed", "suspended", "already_closed", "error_safe"]
    reason_code: SafeReasonCode
    route_generation: Annotated[int, Field(ge=1)]
    revocation_generation: Annotated[int, Field(ge=1)]
    observed_at: AwareDatetime
    receipt_commitment: HmacCommitment

class NodeRevocationReceiptV1(StrictHardeningContract):
    schema_id: Literal["node_revocation_receipt.v1"] = "node_revocation_receipt.v1"
    receipt_id: UUID
    node_pseudonym: RandomLocalPseudonym
    state: Literal["revoked", "already_revoked", "unverified_error_safe"]
    device_approval_generation: Annotated[int, Field(ge=1)]
    revocation_generation: Annotated[int, Field(ge=1)]
    observed_at: AwareDatetime
    receipt_commitment: HmacCommitment

class RemoteCommissioningReceiptV1(StrictHardeningContract):
    schema_id: Literal["remote_commissioning_receipt.v1"] = "remote_commissioning_receipt.v1"
    receipt_id: UUID
    adapter_id: StableAdapterId
    adapter_class: Literal["tailscale"]
    state: Literal["read_only"]
    node_pseudonym: RandomLocalPseudonym
    client_version_commitment: HmacCommitment
    acl_evidence_digest: Sha256Digest
    tailnet_lock_evidence_digest: Sha256Digest
    device_approval_evidence_digest: Sha256Digest
    split_dns_evidence_digest: Sha256Digest
    local_ca_evidence_digest: Sha256Digest
    firewall_evidence_digest: Sha256Digest
    recovery_evidence_digest: Sha256Digest
    revocation_drill_evidence_digest: Sha256Digest
    local_independence_evidence_digest: Sha256Digest
    interface_commitment: HmacCommitment
    origin: Literal["https://tuntun.home.arpa:8443"]
    device_approval_generation: Annotated[int, Field(ge=1)]
    route_generation: Annotated[int, Field(ge=1)]
    revocation_generation: Annotated[int, Field(ge=1)]
    commissioned_at: AwareDatetime
    receipt_commitment: HmacCommitment

RemoteOperationName = Literal[
    "health_status", "phase_availability", "device_availability", "alert_metadata",
    "cost_summary", "approval_metadata", "approval_body", "owner_private_memory",
    "light_power", "media_stop", "camera_metadata", "camera_playback", "export",
    "download", "identity_enroll", "biometric_calibrate", "profile_delete",
    "guardian_change", "base_policy_change", "provider_change", "hard_cap_change",
    "bind_mode_change", "plugin_permission_change", "recovery_key_display",
    "recovery_key_import", "restore", "bulk_delete", "audit_key_rotate",
    "developer_mode", "release_approve", "release_sign", "desktop_execute",
    "robot_drive", "robot_video", "remote_shell", "microphone_activate", "camera_activate",
]

class RemoteOperationRequestV1(StrictHardeningContract):
    schema_id: Literal["remote_operation_request.v1"] = "remote_operation_request.v1"
    request_id: UUID
    remote_session_id: UUID
    actor_subject_id: StableSubjectId
    operation: RemoteOperationName
    source_object_id: UUID | None
    resource_binding_generation: Annotated[int, Field(ge=1)] | None
    expected_policy_version: Annotated[int, Field(ge=1)]
    expected_operation_class_generation: Annotated[int, Field(ge=1)]
    expected_privacy_generation: Annotated[int, Field(ge=1)]
    last_reauthenticated_at: AwareDatetime
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    request_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_bound_remote_request(self) -> "RemoteOperationRequestV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("remote_operation_request_window_invalid")
        if (self.source_object_id is None) != (self.resource_binding_generation is None):
            raise ValueError("remote_operation_resource_binding_incomplete")
        return self

class RemoteOperationDecisionV1(StrictHardeningContract):
    schema_id: Literal["remote_operation_decision.v1"] = "remote_operation_decision.v1"
    request_id: UUID
    operation: RemoteOperationName
    allowed: bool
    code: Literal[
        "REMOTE_OPERATION_ALLOWED", "REMOTE_OPERATION_DENIED", "POLICY_DENIED",
        "FEATURE_ABSENT", "ASSURANCE_INSUFFICIENT", "STALE_GENERATION",
        "PRIVACY_BLOCKED", "RESOURCE_NOT_FOUND",
    ]
    assurance_reduction: Literal["remote_origin_v1"]
    policy_version: Annotated[int, Field(ge=1)]
    operation_class_generation: Annotated[int, Field(ge=1)]
    decided_at: AwareDatetime
    decision_commitment: HmacCommitment

    @model_validator(mode="after")
    def coherent_remote_decision(self) -> "RemoteOperationDecisionV1":
        if self.allowed != (self.code == "REMOTE_OPERATION_ALLOWED"):
            raise ValueError("remote_operation_decision_state_mismatch")
        return self

class RemoteAccessRouteFact(StrictHardeningContract):
    plane: Literal["approved_vpn"]
    state: Literal["disabled", "commissioning", "read_only", "scoped_actions", "suspended"]
    evidence_commitment: HmacCommitment

class RemoteAccessRouteProjection(StrictHardeningContract):
    provider: Literal["tailscale"]
    origin: Literal["https://tuntun.home.arpa:8443"] | None
    posture: Literal["healthy", "drifted", "unavailable", "not_configured"]
    route_generation: Annotated[int, Field(ge=1)]
    allowed_operation_classes: Annotated[
        tuple[Literal["read_only_status", "private_detail", "light_power", "media_stop", "camera_metadata", "camera_playback"], ...],
        Field(max_length=6),
    ]

    @model_validator(mode="after")
    def truthful_route_projection(self) -> "RemoteAccessRouteProjection":
        if (self.origin is not None) != (self.posture == "healthy"):
            raise ValueError("remote_access_route_projection_mismatch")
        if len(set(self.allowed_operation_classes)) != len(self.allowed_operation_classes):
            raise ValueError("duplicate_remote_access_operation_class")
        if self.posture == "healthy" and "read_only_status" not in self.allowed_operation_classes:
            raise ValueError("healthy_remote_projection_missing_read_only_class")
        if self.posture != "healthy" and self.allowed_operation_classes:
            raise ValueError("unavailable_remote_projection_claims_operation_class")
        return self

class RemoteAccessSessionRow(StrictHardeningContract):
    session_pseudonym: RandomLocalPseudonym
    node_pseudonym: RandomLocalPseudonym
    last_access_at: AwareDatetime
    idle_expires_at: AwareDatetime
    absolute_expires_at: AwareDatetime
    assurance_age_seconds: Annotated[int, Field(ge=0, le=8 * 60 * 60)]

    @model_validator(mode="after")
    def coherent_session_row(self) -> "RemoteAccessSessionRow":
        if not self.last_access_at < self.idle_expires_at <= self.absolute_expires_at:
            raise ValueError("remote_access_session_row_window_invalid")
        if self.idle_expires_at > self.last_access_at + timedelta(minutes=15):
            raise ValueError("remote_access_session_row_idle_limit_exceeded")
        return self

class RemoteAccessHealthRow(StrictHardeningContract):
    component: Annotated[str, Field(min_length=1, max_length=48, pattern=r"^[a-z][a-z0-9_]*$")]
    state: Literal["available", "degraded", "unavailable"]

class RemoteAccessAlertRow(StrictHardeningContract):
    alert_code: SafeReasonCode
    severity: Literal["warning", "critical"]
    occurred_at: AwareDatetime

class RemoteAccessCostProjection(StrictHardeningContract):
    period: YearMonth
    amount_minor_units: Annotated[int, Field(ge=0)]
    currency: Annotated[str, Field(min_length=3, max_length=3, pattern=r"^[A-Z]{3}$")]

class RemoteAccessApprovalMetadata(StrictHardeningContract):
    pending_count: Annotated[int, Field(ge=0, le=10_000)]
    oldest_created_at: AwareDatetime | None

    @model_validator(mode="after")
    def coherent_pending_summary(self) -> "RemoteAccessApprovalMetadata":
        if (self.pending_count == 0) != (self.oldest_created_at is None):
            raise ValueError("remote_approval_metadata_count_time_mismatch")
        return self

class RemoteDisablePreparedAction(StrictHardeningContract):
    prepared_id: UUID
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    action_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_disable_action(self) -> "RemoteDisablePreparedAction":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(minutes=2):
            raise ValueError("remote_disable_action_window_invalid")
        return self

class RemoteAccessReadModelV1(StrictHardeningContract):
    schema_id: Literal["remote_access_read_model.v1"] = "remote_access_read_model.v1"
    generated_at: AwareDatetime
    valid_until: AwareDatetime
    route_fact: RemoteAccessRouteFact
    route: RemoteAccessRouteProjection
    sessions: Annotated[tuple[RemoteAccessSessionRow, ...], Field(max_length=32)]
    health: Annotated[tuple[RemoteAccessHealthRow, ...], Field(max_length=16)]
    alerts: Annotated[tuple[RemoteAccessAlertRow, ...], Field(max_length=100)]
    cost: RemoteAccessCostProjection
    approval_metadata: RemoteAccessApprovalMetadata
    local_only_operation_message_ids: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=96, pattern=r"^[a-z][a-z0-9_.-]*$")], ...],
        Field(min_length=1, max_length=32),
    ]
    disable_action: RemoteDisablePreparedAction | None

    @model_validator(mode="after")
    def bounded_current_read_model(self) -> "RemoteAccessReadModelV1":
        if not self.generated_at < self.valid_until <= self.generated_at + timedelta(seconds=30):
            raise ValueError("remote_access_read_model_window_invalid")
        if len(set(self.local_only_operation_message_ids)) != len(self.local_only_operation_message_ids):
            raise ValueError("duplicate_remote_local_only_message_id")
        active = self.route_fact.state in {"read_only", "scoped_actions"}
        if active != (self.route.origin is not None and self.route.posture == "healthy"):
            raise ValueError("remote_access_route_fact_projection_mismatch")
        if self.route_fact.state == "disabled" and (
            self.route.origin is not None or self.route.posture != "not_configured" or self.disable_action is not None
        ):
            raise ValueError("disabled_remote_access_read_model_invalid")
        if self.route_fact.state == "suspended" and (
            self.route.origin is not None or self.route.posture not in {"drifted", "unavailable"}
        ):
            raise ValueError("suspended_remote_access_read_model_invalid")
        if self.route_fact.state in {"read_only", "scoped_actions", "suspended"} and self.disable_action is None:
            raise ValueError("remote_access_read_model_missing_disable_action")
        if not active and self.sessions:
            raise ValueError("inactive_remote_route_exposes_session")
        if len({row.session_pseudonym for row in self.sessions}) != len(self.sessions):
            raise ValueError("duplicate_remote_session_projection")
        if any(
            not row.last_access_at <= self.generated_at < row.idle_expires_at <= row.absolute_expires_at
            for row in self.sessions
        ):
            raise ValueError("remote_session_projection_not_current_at_generation")
        return self

class RemoteCameraEventMetadataV1(StrictHardeningContract):
    schema_id: Literal["remote_camera_event_metadata.v1"] = "remote_camera_event_metadata.v1"
    event_pseudonym: RandomLocalPseudonym
    area_display_label: Annotated[PlainSafeText, Field(max_length=80)]
    zone_display_label: Annotated[PlainSafeText, Field(max_length=80)]
    native_event_class: Literal["person", "vehicle", "pet", "package", "motion", "unknown"]
    local_occurred_at: AwareDatetime
    verification_state: Literal["native_verified", "unverified", "unavailable"]
    clip_availability: Literal["available", "unavailable", "expired"]
    camera_binding_generation: Annotated[int, Field(ge=1)]
    zone_generation: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    catalog_generation: Annotated[int, Field(ge=1)]

class RemotePrivateDetailRequestV1(StrictHardeningContract):
    schema_id: Literal["remote_private_detail_request.v1"] = "remote_private_detail_request.v1"
    request_id: UUID
    owner_subject_id: StableSubjectId
    detail_class: Literal["approval_body", "owner_private_memory"]
    source_object_id: UUID
    expected_policy_generation: Annotated[int, Field(ge=1)]
    expected_subject_generation: Annotated[int, Field(ge=1)]
    expected_source_generation: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    request_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_private_detail_request(self) -> "RemotePrivateDetailRequestV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("remote_private_detail_request_window_invalid")
        return self

class RemotePrivateDetailProjectionV1(StrictHardeningContract):
    schema_id: Literal["remote_private_detail_projection.v1"] = "remote_private_detail_projection.v1"
    request_id: UUID
    detail_class: Literal["approval_body", "owner_private_memory"]
    audience: Literal["owner_private"]
    body: Annotated[PlainSafeText, Field(max_length=4096)]
    source_generation: Annotated[int, Field(ge=1)]
    policy_generation: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    projection_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_private_detail_projection(self) -> "RemotePrivateDetailProjectionV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=60):
            raise ValueError("remote_private_detail_projection_window_invalid")
        return self

class RemoteSingleClipMediaSessionV1(StrictHardeningContract):
    schema_id: Literal["remote_single_clip_media_session.v1"] = "remote_single_clip_media_session.v1"
    media_session_id: UUID
    owner_subject_id: StableSubjectId
    remote_session_id: UUID
    clip_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=1)]
    allowed_view: Literal["wide", "tracking"]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    route_generation: Annotated[int, Field(ge=1)]
    remote_session_revocation_generation: Annotated[int, Field(ge=1)]
    operation_class_generation: Annotated[int, Field(ge=1)]
    clip_generation: Annotated[int, Field(ge=1)]
    catalog_generation: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    session_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_single_clip_window(self) -> "RemoteSingleClipMediaSessionV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(minutes=10):
            raise ValueError("remote_media_session_window_invalid")
        return self
~~~

~~~python
# packages/contracts/src/tuntun_contracts/hardening/plugins.py
PLUGIN_MANIFEST_SCHEMA_LABEL = "plugin.manifest.v1"  # Local dispatch label; never serialized.

class PluginManifestV1(StrictHardeningContract):
    plugin_id: StablePluginId
    version: SemVer
    publisher: BoundedPublisherIdentity
    artifact_digest: Sha256Digest
    signature_identity: BoundedSignatureIdentity
    protocol_major: Literal[1]
    capability_registry_revision: Literal["phase6.initial.1"]
    entrypoint: BoundedRelativeEntrypoint
    requested_capability_ids: Annotated[
        tuple[Literal[
            "system.health.render.v1", "notification.local_alert.render.v1",
        ], ...],
        Field(min_length=1, max_length=2),
    ]
    licence: SpdxLicenceExpression
    sbom_digest: Sha256Digest

    @model_validator(mode="after")
    def unique_capabilities(self) -> "PluginManifestV1":
        if len(set(self.requested_capability_ids)) != len(self.requested_capability_ids):
            raise ValueError("duplicate_plugin_capability")
        return self

class PluginHealthComponentV1(StrictHardeningContract):
    component_class: PluginComponentClass
    state: Literal["available", "degraded", "unavailable", "disabled"]
    freshness: Literal["current", "stale", "unknown"]
    attention_codes: Annotated[
        tuple[Literal[
            "backup_stale", "storage_low", "credential_expiring", "unexpected_exposure",
            "privacy_control_failed", "safety_input_disabled", "update_pending",
        ], ...],
        Field(max_length=7),
    ]

class PluginHealthSnapshotV1(StrictHardeningContract):
    schema_id: Literal["plugin_health_snapshot.v1"] = "plugin_health_snapshot.v1"
    request_id: UUID
    purpose: Literal["owner_local_health_render"] = "owner_local_health_render"
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    components: Annotated[tuple[PluginHealthComponentV1, ...], Field(max_length=16)]

    @model_validator(mode="after")
    def bounded_request_window(self) -> "PluginHealthSnapshotV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("plugin_health_request_expiry_invalid")
        return self

class PluginHealthRenderItemV1(StrictHardeningContract):
    component_class: PluginComponentClass
    label: Annotated[PlainSafeText, Field(max_length=160)]

class PluginHealthRenderV1(StrictHardeningContract):
    schema_id: Literal["plugin_health_render.v1"] = "plugin_health_render.v1"
    request_id: UUID
    headline: Annotated[PlainSafeText, Field(max_length=160)]
    items: Annotated[tuple[PluginHealthRenderItemV1, ...], Field(max_length=16)]

class PluginLocalAlertV1(StrictHardeningContract):
    schema_id: Literal["plugin_local_alert.v1"] = "plugin_local_alert.v1"
    request_id: UUID
    purpose: Literal["owner_local_alert_render"] = "owner_local_alert_render"
    alert_code: Literal[
        "backup_failed", "storage_low", "unexpected_listener", "privacy_stop_failed",
        "audit_integrity_failed", "credential_expired", "unsigned_component",
        "robot_safety_input_disabled",
    ]
    severity: Literal["warning", "critical"]
    occurred_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def bounded_request_window(self) -> "PluginLocalAlertV1":
        if not self.occurred_at < self.expires_at <= self.occurred_at + timedelta(seconds=5):
            raise ValueError("plugin_alert_request_expiry_invalid")
        return self

class PluginLocalAlertRenderV1(StrictHardeningContract):
    schema_id: Literal["plugin_local_alert_render.v1"] = "plugin_local_alert_render.v1"
    request_id: UUID
    title: Annotated[PlainSafeText, Field(max_length=80)]
    body: Annotated[PlainSafeText, Field(max_length=240)]
    accent: Literal["amber", "red"]

class PluginCallEnvelopeV1(StrictHardeningContract):
    schema_id: Literal["plugin_call_envelope.v1"] = "plugin_call_envelope.v1"
    request_id: UUID
    plugin_id: StablePluginId
    plugin_version: SemVer
    capability_id: Literal["system.health.render.v1", "notification.local_alert.render.v1"]
    grant_generation: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    payload: PluginHealthSnapshotV1 | PluginLocalAlertV1
    payload_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_call_window(self) -> "PluginCallEnvelopeV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("plugin_call_window_invalid")
        expected_type = {
            "system.health.render.v1": PluginHealthSnapshotV1,
            "notification.local_alert.render.v1": PluginLocalAlertV1,
        }[self.capability_id]
        if not isinstance(self.payload, expected_type):
            raise ValueError("plugin_call_capability_payload_mismatch")
        inner_issued_at = (
            self.payload.issued_at
            if isinstance(self.payload, PluginHealthSnapshotV1)
            else self.payload.occurred_at
        )
        if (
            self.payload.request_id != self.request_id
            or inner_issued_at != self.issued_at
            or self.payload.expires_at != self.expires_at
        ):
            raise ValueError("plugin_call_outer_inner_binding_mismatch")
        return self

class PluginCallResultEnvelopeV1(StrictHardeningContract):
    schema_id: Literal["plugin_call_result_envelope.v1"] = "plugin_call_result_envelope.v1"
    request_id: UUID
    plugin_id: StablePluginId
    plugin_version: SemVer
    capability_id: Literal["system.health.render.v1", "notification.local_alert.render.v1"]
    grant_generation: Annotated[int, Field(ge=1)]
    state: Literal["rendered", "denied", "expired", "failed", "error_safe"]
    payload: PluginHealthRenderV1 | PluginLocalAlertRenderV1 | None
    observed_at: AwareDatetime
    result_commitment: HmacCommitment

    @model_validator(mode="after")
    def result_payload_matches_state(self) -> "PluginCallResultEnvelopeV1":
        if (self.state == "rendered") != (self.payload is not None):
            raise ValueError("plugin_result_payload_state_mismatch")
        expected_type = {
            "system.health.render.v1": PluginHealthRenderV1,
            "notification.local_alert.render.v1": PluginLocalAlertRenderV1,
        }[self.capability_id]
        if self.payload is not None and not isinstance(self.payload, expected_type):
            raise ValueError("plugin_result_capability_payload_mismatch")
        if self.payload is not None and self.payload.request_id != self.request_id:
            raise ValueError("plugin_result_outer_inner_request_mismatch")
        return self

class PluginRevocationReceiptV1(StrictHardeningContract):
    schema_id: Literal["plugin_revocation_receipt.v1"] = "plugin_revocation_receipt.v1"
    plugin_id: StablePluginId
    prior_grant_generation: Annotated[int, Field(ge=1)]
    revocation_generation: Annotated[int, Field(ge=1)]
    state: Literal["revoked", "already_revoked", "error_safe"]
    observed_at: AwareDatetime
    receipt_commitment: HmacCommitment
~~~

The signed registry—not the manifest—fixes both capabilities to local-owner eligibility, their distinct invocation/consent rules, exact DTO pairs, sensitivity ceilings, fresh-process/no-write/no-network policy, five-second deadline, 128 MiB/50%-CPU/64-KiB/one-concurrency quotas, generation-bound revocation, cleanup, and 180-day content-minimized invocation receipts. Health requires an explicit local owner click for every render. Local alerts may invoke automatically only after owner installation approval and always render beside an unchanged mandatory core alert.

~~~python
# packages/contracts/src/tuntun_contracts/hardening/release.py
class NamedArtifactDigestV1(StrictHardeningContract):
    artifact_name: Annotated[
        str,
        Field(min_length=1, max_length=96, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"),
    ]
    relative_path: Annotated[
        str,
        Field(
            min_length=1,
            max_length=256,
            pattern=r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))(?!.*//)[A-Za-z0-9][A-Za-z0-9._/-]*$",
        ),
    ]
    digest: Sha256Digest
    byte_length: Annotated[int, Field(ge=1, le=8 * 1024 * 1024 * 1024)]
    media_type: Literal[
        "application/zip", "application/gzip", "application/json", "application/spdx+json",
        "application/vnd.python.wheel", "text/plain",
    ]
    executable: bool

    @model_validator(mode="after")
    def artifact_name_matches_safe_relative_path(self) -> "NamedArtifactDigestV1":
        path = PurePosixPath(self.relative_path)
        if self.relative_path != path.as_posix() or path.name != self.artifact_name or len(path.parts) > 8:
            raise ValueError("release_artifact_path_name_invalid")
        return self

class ReleaseManifestV1(StrictHardeningContract):
    schema_id: Literal["release_manifest.v1"] = "release_manifest.v1"
    version: SemVer
    source_commit: GitObjectId
    source_repository_identity: BoundedRepositoryIdentity
    workflow_identity: BoundedWorkflowIdentity
    dependency_lock_digest: Sha256Digest
    sbom_spdx_digest: Sha256Digest
    provenance_digest: Sha256Digest
    feature_manifest_digest: Sha256Digest
    acceptance_evidence_digest: Sha256Digest
    compatibility_manifest_digest: Sha256Digest
    artifact_digests: Annotated[tuple[NamedArtifactDigestV1, ...], Field(min_length=1, max_length=64)]
    signer_identity: BoundedSignatureIdentity
    release_channel: Literal["stable", "migration"]
    issued_at: AwareDatetime
    expires_at: AwareDatetime | None

    @model_validator(mode="after")
    def positive_validity(self) -> "ReleaseManifestV1":
        if self.expires_at is not None and self.expires_at <= self.issued_at:
            raise ValueError("release_manifest_expiry_invalid")
        names = tuple(artifact.artifact_name for artifact in self.artifact_digests)
        paths = tuple(artifact.relative_path for artifact in self.artifact_digests)
        if len(set(names)) != len(names) or len(set(paths)) != len(paths):
            raise ValueError("duplicate_release_artifact")
        return self

class ReleaseCandidateV1(StrictHardeningContract):
    schema_id: Literal["release_candidate.v1"] = "release_candidate.v1"
    candidate_id: UUID
    manifest_json: Annotated[str, Field(min_length=2, max_length=1024 * 1024)]
    manifest_signature: Annotated[str, Field(min_length=16, max_length=16_384)]
    artifact_set_id: UUID
    artifact_set_commitment: HmacCommitment
    received_at: AwareDatetime

class InstalledReleaseV1(StrictHardeningContract):
    schema_id: Literal["installed_release.v1"] = "installed_release.v1"
    version: SemVer
    source_commit: GitObjectId
    feature_manifest_digest: Sha256Digest
    installed_at: AwareDatetime

class ReleaseDecisionV1(StrictHardeningContract):
    schema_id: Literal["release_decision.v1"] = "release_decision.v1"
    candidate_id: UUID
    install_allowed: bool
    preserve_version: SemVer
    accepted_manifest: ReleaseManifestV1 | None
    reason_code: SafeReasonCode
    decided_at: AwareDatetime
    decision_commitment: HmacCommitment

    @model_validator(mode="after")
    def coherent_release_decision(self) -> "ReleaseDecisionV1":
        if self.install_allowed != (self.accepted_manifest is not None):
            raise ValueError("release_decision_manifest_state_mismatch")
        return self

class C0CandidateV1(StrictHardeningContract):
    schema_id: Literal["c0_candidate.v1"] = "c0_candidate.v1"
    candidate_id: UUID
    version: SemVer
    source_commit: GitObjectId
    feature_manifest_digest: Sha256Digest
    tracked_inputs_digest: Sha256Digest
    mandatory_phase_gate_bundle_digest: Sha256Digest
    canonical_optional_absence_digest: Sha256Digest
    threat_t01_t25_closure_digest: Sha256Digest
    hardware_compatibility_digest: Sha256Digest
    seven_day_soak_digest: Sha256Digest
    eight_hour_stress_digests: Annotated[tuple[Sha256Digest, ...], Field(min_length=2, max_length=2)]
    clean_restore_digest: Sha256Digest
    deletion_no_resurrection_digest: Sha256Digest
    maintenance_evidence_digest: Sha256Digest
    listener_route_private_scan_digest: Sha256Digest
    built_at: AwareDatetime
    candidate_commitment: HmacCommitment

    @model_validator(mode="after")
    def distinct_stress_runs(self) -> "C0CandidateV1":
        if len(set(self.eight_hour_stress_digests)) != 2:
            raise ValueError("c0_stress_run_evidence_not_distinct")
        return self

class C1CandidateV1(StrictHardeningContract):
    schema_id: Literal["c1_candidate.v1"] = "c1_candidate.v1"
    candidate_id: UUID
    c0_candidate_id: UUID
    accepted_c0_commitment: HmacCommitment
    version: SemVer
    source_commit: GitObjectId
    feature_manifest_digest: Sha256Digest
    public_release_evidence_digest: Sha256Digest
    publication_manifest_digest: Sha256Digest
    artifact_digests: Annotated[tuple[NamedArtifactDigestV1, ...], Field(min_length=1, max_length=64)]
    built_at: AwareDatetime
    candidate_commitment: HmacCommitment

    @model_validator(mode="after")
    def unique_public_artifacts(self) -> "C1CandidateV1":
        names = tuple(artifact.artifact_name for artifact in self.artifact_digests)
        paths = tuple(artifact.relative_path for artifact in self.artifact_digests)
        if len(set(names)) != len(names) or len(set(paths)) != len(paths):
            raise ValueError("duplicate_c1_artifact")
        return self

# packages/contracts/src/tuntun_contracts/hardening/incident.py
class IncidentStateV1(StrictHardeningContract):
    schema_id: Literal["incident_state.v1"] = "incident_state.v1"
    incident_id: UUID
    state: Literal["normal", "contained_remote", "contained_egress", "recovery_quarantine"]
    reason_codes: Annotated[tuple[SafeReasonCode, ...], Field(max_length=16)]
    controller_generation: Annotated[int, Field(ge=1)]
    session_generation: Annotated[int, Field(ge=1)]
    entered_at: AwareDatetime
    exited_at: AwareDatetime | None
    owner_approval_commitment: HmacCommitment | None

    @model_validator(mode="after")
    def coherent_incident_window(self) -> "IncidentStateV1":
        if self.exited_at is not None and self.exited_at < self.entered_at:
            raise ValueError("incident_exit_precedes_entry")
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise ValueError("duplicate_incident_reason_code")
        if (self.state == "normal") != (not self.reason_codes):
            raise ValueError("incident_state_reason_mismatch")
        return self

# packages/contracts/src/tuntun_contracts/hardening/maintenance.py
class MaintenanceMonthV1(StrictHardeningContract):
    schema_id: Literal["maintenance_month.v1"] = "maintenance_month.v1"
    month: YearMonth
    steady_state_generation: Annotated[int, Field(ge=1)]
    steady_state_epoch_started_at: AwareDatetime
    logging_eligible_at: AwareDatetime
    period_start: AwareDatetime
    period_end_exclusive: AwareDatetime
    ordinary_minutes_by_subsystem: dict[MaintenanceSubsystem, NonNegativeMinutes]
    excluded_minutes_by_class: dict[ExcludedMaintenanceClass, NonNegativeMinutes]
    ordinary_total_minutes: NonNegativeMinutes
    recorded_at: AwareDatetime
    evidence_digest: Sha256Digest

    @model_validator(mode="after")
    def exact_complete_eligible_calendar_month(self) -> "MaintenanceMonthV1":
        if self.ordinary_total_minutes != sum(self.ordinary_minutes_by_subsystem.values()):
            raise ValueError("maintenance_ordinary_total_mismatch")
        if set(self.ordinary_minutes_by_subsystem) != set(MaintenanceSubsystem):
            raise ValueError("maintenance_subsystem_set_incomplete")
        if set(self.excluded_minutes_by_class) != set(ExcludedMaintenanceClass):
            raise ValueError("maintenance_excluded_class_set_incomplete")
        if self.logging_eligible_at != self.steady_state_epoch_started_at + timedelta(days=60):
            raise ValueError("maintenance_logging_eligibility_invalid")
        expected_start = first_utc_day_of_year_month(self.month)
        expected_end = next_calendar_month(expected_start)
        if self.period_start != expected_start or self.period_end_exclusive != expected_end:
            raise ValueError("maintenance_period_not_complete_calendar_month")
        if self.period_start < self.logging_eligible_at:
            raise ValueError("maintenance_month_begins_before_day_sixty")
        if self.recorded_at < self.period_end_exclusive:
            raise ValueError("maintenance_month_recorded_before_completion")
        return self

# packages/contracts/src/tuntun_contracts/hardening/recovery.py
class AttachedBackupTierV1(StrictHardeningContract):
    generation: Annotated[int, Field(ge=1)]
    volume_commitment: HmacCommitment
    failure_domain_commitment: HmacCommitment
    retained_daily_generations: Literal[7]
    retained_weekly_generations: Literal[4]
    latest_verified_at: AwareDatetime

class IndependentBackupCopyV1(StrictHardeningContract):
    copy_id: UUID
    generation: Annotated[int, Field(ge=1)]
    volume_or_adapter_commitment: HmacCommitment
    failure_domain_commitment: HmacCommitment
    owner_controlled_encryption: Literal[True]
    ciphertext_manifest_digest: Sha256Digest
    restore_probe_digest: Sha256Digest
    verified_at: AwareDatetime

PortableRecoveryExclusion = Literal[
    "provider_credentials", "vpn_credentials", "mac_leaf_tls", "device_credentials",
    "release_signing_credentials", "routine_camera_retention",
]

class BackupSetV1(StrictHardeningContract):
    schema_id: Literal["backup_set.v1"] = "backup_set.v1"
    backup_set_id: UUID
    source_generation: Annotated[int, Field(ge=1)]
    attached: AttachedBackupTierV1
    independent: IndependentBackupCopyV1
    excluded_classes: Annotated[tuple[PortableRecoveryExclusion, ...], Field(min_length=6, max_length=6)]
    created_at: AwareDatetime
    set_commitment: HmacCommitment

    @model_validator(mode="after")
    def independently_verified_exact_backup_set(self) -> "BackupSetV1":
        expected_exclusions = {
            "provider_credentials", "vpn_credentials", "mac_leaf_tls", "device_credentials",
            "release_signing_credentials", "routine_camera_retention",
        }
        if set(self.excluded_classes) != expected_exclusions or len(set(self.excluded_classes)) != 6:
            raise ValueError("portable_recovery_exclusions_incomplete")
        if self.attached.volume_commitment == self.independent.volume_or_adapter_commitment:
            raise ValueError("independent_copy_reuses_attached_volume")
        if self.attached.failure_domain_commitment == self.independent.failure_domain_commitment:
            raise ValueError("independent_copy_reuses_attached_failure_domain")
        if self.attached.generation != self.source_generation or self.independent.generation != self.source_generation:
            raise ValueError("backup_tier_generation_mismatch")
        if self.attached.latest_verified_at > self.created_at or self.independent.verified_at > self.created_at:
            raise ValueError("backup_set_created_before_tier_verification")
        return self

class RestoreRunV1(StrictHardeningContract):
    schema_id: Literal["restore_run.v1"] = "restore_run.v1"
    restore_run_id: UUID
    backup_set_id: UUID
    state: Literal["recovery_quarantine", "reconciling", "completed", "error_safe"]
    source_generation: Annotated[int, Field(ge=1)]
    new_controller_generation: Annotated[int, Field(ge=1)]
    new_session_generation: Annotated[int, Field(ge=1)]
    new_route_generation: Annotated[int, Field(ge=1)]
    archive_signature_evidence_digest: Sha256Digest
    offline_key_reconstruction_evidence_digest: Sha256Digest
    sqlcipher_audit_migration_evidence_digest: Sha256Digest
    deletion_reconciliation_evidence_digest: Sha256Digest
    credential_exclusion_evidence_digest: Sha256Digest
    topology_binding_evidence_digest: Sha256Digest
    device_pairing_evidence_digest: Sha256Digest
    enabled_phase_ids: Annotated[
        tuple[Literal["phase1", "phase2", "phase3", "phase4", "phase5", "phase6"], ...],
        Field(max_length=6),
    ]
    effect_route_state: Literal["closed", "scoped_current_generation"]
    started_at: AwareDatetime
    completed_at: AwareDatetime | None
    run_commitment: HmacCommitment

    @model_validator(mode="after")
    def quarantine_until_ordered_reconciliation(self) -> "RestoreRunV1":
        phase_order = ("phase1", "phase2", "phase3", "phase4", "phase5", "phase6")
        if self.enabled_phase_ids != phase_order[:len(self.enabled_phase_ids)]:
            raise ValueError("restore_phase_enablement_not_ordered")
        if self.state == "completed":
            if self.enabled_phase_ids != phase_order or self.effect_route_state != "scoped_current_generation":
                raise ValueError("completed_restore_without_full_reconciliation")
            if self.completed_at is None or self.completed_at < self.started_at:
                raise ValueError("completed_restore_time_invalid")
        elif self.effect_route_state != "closed" or self.completed_at is not None:
            raise ValueError("incomplete_restore_not_quarantined")
        return self

class DeviceRetirementStateV1(StrictHardeningContract):
    schema_id: Literal["device_retirement_state.v1"] = "device_retirement_state.v1"
    retirement_id: UUID
    device_id: StableDeviceId
    device_generation: Annotated[int, Field(ge=1)]
    lifecycle: Literal["active", "retirement_quarantined", "retired"]
    authority_revocation_generation: Annotated[int, Field(ge=1)]
    prepared_set_commitment: HmacCommitment
    authorities_revoked: bool
    vendor_reset_state: Literal["pending", "verified_reset", "verified_attempt_unverifiable_storage", "not_applicable"]
    managed_storage_state: Literal["pending", "verified_crypto_shredded", "not_managed"]
    reconnect_state: Literal["pending", "old_identity_denied"]
    quarantined_at: AwareDatetime | None
    retired_at: AwareDatetime | None
    state_commitment: HmacCommitment

    @model_validator(mode="after")
    def coherent_retirement_lifecycle(self) -> "DeviceRetirementStateV1":
        if self.lifecycle == "active":
            if self.authorities_revoked or self.quarantined_at is not None or self.retired_at is not None:
                raise ValueError("active_retirement_state_invalid")
        elif self.lifecycle == "retirement_quarantined":
            if not self.authorities_revoked or self.quarantined_at is None or self.retired_at is not None:
                raise ValueError("quarantined_retirement_state_invalid")
        else:
            effects_complete = (
                self.authorities_revoked
                and self.vendor_reset_state != "pending"
                and self.managed_storage_state != "pending"
                and self.reconnect_state == "old_identity_denied"
            )
            if not effects_complete or self.quarantined_at is None or self.retired_at is None or self.retired_at < self.quarantined_at:
                raise ValueError("retired_state_without_complete_evidence")
        return self

class RetirementReceiptV1(StrictHardeningContract):
    schema_id: Literal["retirement_receipt.v1"] = "retirement_receipt.v1"
    retirement_id: UUID
    device_id: StableDeviceId
    lifecycle: Literal["retirement_quarantined", "retired"]
    authority_revocation_generation: Annotated[int, Field(ge=1)]
    vendor_reset_state: Literal["pending", "verified_reset", "verified_attempt_unverifiable_storage", "not_applicable"]
    managed_storage_state: Literal["pending", "verified_crypto_shredded", "not_managed"]
    reconnect_state: Literal["pending", "old_identity_denied"]
    claims_physical_flash_erasure: Literal[False]
    observed_at: AwareDatetime
    state_commitment: HmacCommitment

    @model_validator(mode="after")
    def no_false_retired_receipt(self) -> "RetirementReceiptV1":
        if self.lifecycle == "retired" and (
            self.vendor_reset_state == "pending"
            or self.managed_storage_state == "pending"
            or self.reconnect_state != "old_identity_denied"
        ):
            raise ValueError("retired_receipt_without_complete_evidence")
        return self

# packages/contracts/src/tuntun_contracts/hardening/maintenance.py
class MaintenanceFreezeStateV1(StrictHardeningContract):
    schema_id: Literal["maintenance_freeze_state.v1"] = "maintenance_freeze_state.v1"
    generation: Annotated[int, Field(ge=1)]
    state: Literal["clear", "frozen"]
    trigger_window_digest: Sha256Digest | None
    trigger_window_end_exclusive: AwareDatetime | None
    triggered_at: AwareDatetime | None
    cleared_at: AwareDatetime | None
    cleared_through_period_end_exclusive: AwareDatetime | None
    clear_review_commitment: HmacCommitment | None

    @model_validator(mode="after")
    def coherent_freeze_state(self) -> "MaintenanceFreezeStateV1":
        trigger = (self.trigger_window_digest, self.trigger_window_end_exclusive, self.triggered_at)
        clear_history = (
            self.cleared_at,
            self.cleared_through_period_end_exclusive,
            self.clear_review_commitment,
        )
        if self.state == "frozen":
            if not all(value is not None for value in trigger):
                raise ValueError("maintenance_frozen_state_invalid")
        elif any(value is not None for value in trigger):
            raise ValueError("maintenance_clear_state_has_trigger")
        if any(value is not None for value in clear_history) and not all(value is not None for value in clear_history):
            raise ValueError("maintenance_clear_history_incomplete")
        for boundary in (self.trigger_window_end_exclusive, self.cleared_through_period_end_exclusive):
            if boundary is not None and not is_utc_calendar_month_boundary(boundary):
                raise ValueError("maintenance_freeze_period_end_not_utc_month_boundary")
        if (
            self.trigger_window_end_exclusive is not None
            and self.triggered_at is not None
            and self.trigger_window_end_exclusive > self.triggered_at
        ):
            raise ValueError("maintenance_trigger_precedes_window_completion")
        if (
            self.cleared_through_period_end_exclusive is not None
            and self.cleared_at is not None
            and self.cleared_through_period_end_exclusive > self.cleared_at
        ):
            raise ValueError("maintenance_clear_precedes_evaluated_window_completion")
        if self.triggered_at is not None and self.cleared_at is not None and self.triggered_at <= self.cleared_at:
            raise ValueError("maintenance_relatched_before_latest_clear")
        return self

class MaintenanceFreezeClearanceV1(StrictHardeningContract):
    schema_id: Literal["maintenance_freeze_clearance.v1"] = "maintenance_freeze_clearance.v1"
    review_id: UUID
    owner_subject_id: StableSubjectId
    expected_freeze_generation: Annotated[int, Field(ge=1)]
    steady_state_generation: Annotated[int, Field(ge=1)]
    steady_state_epoch_started_at: AwareDatetime
    evaluated_through_period_end_exclusive: AwareDatetime
    changed_optional_subsystem_ids: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=96, pattern=r"^[a-z0-9][a-z0-9_.-]*$")], ...],
        Field(min_length=1, max_length=16),
    ]
    simplification_or_retirement_evidence_digests: Annotated[tuple[Sha256Digest, ...], Field(min_length=1, max_length=16)]
    resulting_feature_manifest_digest: Sha256Digest
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    owner_action_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_clearance_window(self) -> "MaintenanceFreezeClearanceV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(minutes=2):
            raise ValueError("maintenance_freeze_clearance_window_invalid")
        if len(set(self.changed_optional_subsystem_ids)) != len(self.changed_optional_subsystem_ids):
            raise ValueError("duplicate_maintenance_clearance_subsystem")
        if len(self.changed_optional_subsystem_ids) != len(self.simplification_or_retirement_evidence_digests):
            raise ValueError("maintenance_clearance_evidence_cardinality_mismatch")
        if self.evaluated_through_period_end_exclusive > self.issued_at:
            raise ValueError("maintenance_clearance_claims_future_evidence")
        if not is_utc_calendar_month_boundary(self.evaluated_through_period_end_exclusive):
            raise ValueError("maintenance_clearance_period_end_not_utc_month_boundary")
        return self
~~~

~~~python
# packages/contracts/src/tuntun_contracts/hardening/ports.py
class RemoteAccessPort(Protocol):
    async def probe(self) -> RemoteAdapterPostureV1: ...
    async def close_route(self, reason: SafeReasonCode) -> RemoteRouteReceiptV1: ...
    async def revoke_node(self, local_pseudonym: RandomLocalPseudonym) -> NodeRevocationReceiptV1: ...

class PluginSupervisorPort(Protocol):
    async def invoke(self, call: PluginCallEnvelopeV1) -> PluginCallResultEnvelopeV1: ...
    async def revoke(self, plugin_id: StablePluginId, expected_grant_generation: int) -> PluginRevocationReceiptV1: ...

class ReleaseVerifierPort(Protocol):
    def verify(self, candidate: ReleaseCandidateV1, installed: InstalledReleaseV1) -> ReleaseDecisionV1: ...
~~~

## Durable State and Migration Map

| Migration | Tables/state | Forbidden content | Restore/rollback rule |
|---|---|---|---|
| `0023_remote_access` | `remote_nodes`, `remote_routes`, `remote_sessions`, `remote_operation_classes`, `remote_security_counters` | Vendor node name/user/email/IP, passkey secret, request body, clip URL, family content | Down migration revokes sessions and returns route to `DISABLED`; restore rotates route/session generations and requires re-commissioning |
| `0024_plugins_releases` | `plugin_installations`, `plugin_grants`, `plugin_invocation_receipts`, `release_candidates`, `release_artifacts`, `update_runs` | Plugin request/result text, filesystem/network data, signing/notarization secret, household evidence body | Plugin restore is quarantined and never restores running process/grant; release records are evidence only and cannot authorize publication |
| `0025_recovery_incident_maintenance` | `backup_sets`, `restore_runs`, `deletion_reconciliations`, `incidents`, `maintenance_months`, `maintenance_expansion_freeze` | Recovery key, archive plaintext, deleted record body, raw incident payload, arbitrary owner notes | Restore begins `RECOVERY_QUARANTINE`; deletion tombstones win over archive rows; freeze clears only through local owner simplification/retirement evidence |

Every migration uses the shared serialized SQLCipher unit of work and trigger-protected audit/outbox. An interrupted migration restores the verified pre-migration archive into isolated paths; it never partially opens a Phase 6 route. The portable archive omits live remote/plugin/provider/device/signing credentials by construction.

## Standard Commands and Owner-Gated Evidence Flags

~~~bash
make bootstrap
make check
uv run pytest -q
pnpm --dir apps/admin test
pnpm --dir apps/admin typecheck
pnpm --dir apps/admin build
pnpm --dir apps/admin exec playwright test
uv run python scripts/phase6/generate_schemas.py --check
uv run python scripts/phase6/verify_default_absence.py
uv run python scripts/phase6/run_threat_matrix.py --synthetic --output var/evidence/phase6/threat-matrix-synthetic.json
~~~

Ordinary CI must fail if any owner gate is inferred from an unavailable environment. The following explicit flags are accepted only by the named script, require a clean commit plus operator/evidence destination, and never enter committed workflow defaults:

~~~bash
TUNTUN_ALLOW_TAILSCALE_PROBE=1 uv run python ops/remote-access/verify_posture.py --output var/evidence/phase6/tailscale-posture.json
TUNTUN_ALLOW_NETWORK_SCAN=1 uv run python ops/network/verify_lateral_reachability.py --output var/evidence/phase6/network.json
TUNTUN_ALLOW_ELAPSED_PHASE6=1 uv run python scripts/phase6/run_remote_pilot.py --duration-seconds 604800 --output var/evidence/phase6/remote-pilot.json
TUNTUN_ALLOW_PLUGIN_SANDBOX_PROBE=1 uv run python scripts/phase6/run_plugin_qualification.py --output var/evidence/phase6/plugins.json
TUNTUN_ALLOW_CLEAN_MAC=1 uv run python ops/install/verify_clean_system.py --target-receipt var/evidence/phase6/clean-mac.json
TUNTUN_ALLOW_APPLE_RELEASE=1 uv run python ops/release/notarize.py --candidate var/release/candidate.json --output var/evidence/phase6/notarization.json
TUNTUN_ALLOW_ELAPSED_PHASE6=1 uv run python scripts/phase6/run_household_soak.py --duration-seconds 604800 --output var/evidence/phase6/household-soak.json
TUNTUN_ALLOW_PUBLICATION=1 uv run python ops/release/publish.py --c1-receipt var/evidence/phase6/c1.json --manual-confirm
~~~

The publication flag is intentionally absent from CI. It is valid only after the distinct accepted C1 receipt and a human-entered manual confirmation on the unchanged artifact set.

---

## Wave 0 — P6-E0/P6-0 Contracts, Persistence, Assurance Baseline, and Default Absence

### Task 01: Freeze strict Phase 6 contracts, exact plugin DTOs, and generated schemas

**Depends on:** accepted Phase 1–5 contract packages and shared strict bases.
**Gate contribution:** P6-E0.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `packages/contracts/src/tuntun_contracts/hardening/__init__.py`
- Create: `packages/contracts/src/tuntun_contracts/hardening/base.py`
- Create: `packages/contracts/src/tuntun_contracts/hardening/remote.py`
- Create: `packages/contracts/src/tuntun_contracts/hardening/plugins.py`
- Create: `packages/contracts/src/tuntun_contracts/hardening/release.py`
- Create: `packages/contracts/src/tuntun_contracts/hardening/recovery.py`
- Create: `packages/contracts/src/tuntun_contracts/hardening/incident.py`
- Create: `packages/contracts/src/tuntun_contracts/hardening/maintenance.py`
- Create: `packages/contracts/src/tuntun_contracts/hardening/ui.py`
- Create: `packages/contracts/src/tuntun_contracts/hardening/ports.py`
- Create: `scripts/phase6/generate_schemas.py`
- Create: `schemas/hardening/v1/*.schema.json`
- Create: `schemas/plugins/phase6.initial.1/*.schema.json`
- Create: `schemas/releases/v1/*.schema.json`
- Test: `tests/contract/hardening/test_phase6_contracts.py`
- Test: `tests/property/hardening/test_phase6_contract_rejection.py`

**Interfaces:** Consumes shared strict/JCS bases, random IDs, safe codes, feature commitments, `ui.plane_fact.v1`, prepared-action contracts, and the Phase 3 playback grant. Produces the frozen models above, `canonical_hardening_bytes(value) -> bytes`, `RemoteAccessPort`, `PluginSupervisorPort`, `ReleaseVerifierPort`, JSON Schemas, OpenAPI/TypeScript-ready artifacts, and schema bundle `tuntun.hardening.v1`.

**Rollback/disabled exit:** Contract failure leaves every Phase 6 feature unregistered; no compatibility shim drops a field, accepts an unknown plugin capability, or aliases C0/C1.

- [ ] **Step 1: Write red exact-schema, expiry, manifest, DTO, and C-gate tests**

~~~python
def test_plugin_manifest_has_only_normative_fields(plugin_manifest_fixture: dict[str, object]) -> None:
    assert set(PluginManifestV1.model_fields) == {
        "plugin_id", "version", "publisher", "artifact_digest", "signature_identity",
        "protocol_major", "capability_registry_revision", "entrypoint",
        "requested_capability_ids", "licence", "sbom_digest",
    }
    assert set(PluginManifestV1.model_validate(plugin_manifest_fixture).model_dump()) == set(
        PluginManifestV1.model_fields
    )

@pytest.mark.parametrize("unknown_field", ["schema_id", "resource_profile"])
def test_plugin_manifest_rejects_every_non_wire_field(
    plugin_manifest_fixture: dict[str, object], unknown_field: str,
) -> None:
    with pytest.raises(ValidationError):
        PluginManifestV1.model_validate({**plugin_manifest_fixture, unknown_field: "publisher-choice"})

@pytest.mark.parametrize("entrypoint", [
    "../run.py", "bin/../escape.py", "/tmp/run.py", "bin/./run.py", "bin/run.exe", "bin//run.py",
])
def test_plugin_entrypoint_is_canonical_relative_and_closed(plugin_manifest_fixture, entrypoint) -> None:
    with pytest.raises(ValidationError):
        PluginManifestV1.model_validate({**plugin_manifest_fixture, "entrypoint": entrypoint})

@pytest.mark.parametrize(("field", "value"), [
    ("publisher", "../publisher"),
    ("signature_identity", "https://keys.example/key"),
    ("licence", "MIT or Apache-2.0"),
])
def test_plugin_identity_and_spdx_fields_are_bounded_canonical(plugin_manifest_fixture, field, value) -> None:
    with pytest.raises(ValidationError):
        PluginManifestV1.model_validate({**plugin_manifest_fixture, field: value})

@pytest.mark.parametrize("capability", ["memory.read.v1", "network.fetch.v1", "speech.render.v1"])
def test_initial_registry_rejects_every_other_capability(plugin_manifest_fixture, capability) -> None:
    with pytest.raises(ValidationError):
        PluginManifestV1.model_validate({**plugin_manifest_fixture, "requested_capability_ids": [capability]})

def test_remote_session_limits_are_closed(remote_session_fixture) -> None:
    session = RemoteSessionV1.model_validate(remote_session_fixture)
    assert session.idle_expires_at - session.last_reauthenticated_at <= timedelta(minutes=15)
    assert session.absolute_expires_at - session.established_at <= timedelta(hours=8)
    assert session.operation_class_generation >= 1

@pytest.mark.parametrize("fault", [
    "reauth_before_established", "idle_not_positive", "idle_over_fifteen_minutes",
    "absolute_not_positive", "absolute_over_eight_hours", "idle_after_absolute",
])
def test_remote_session_rejects_every_invalid_window(remote_session_fixture, mutate_window, fault) -> None:
    with pytest.raises(ValidationError):
        RemoteSessionV1.model_validate(mutate_window(remote_session_fixture, fault))

def test_route_release_incident_and_maintenance_constraints_are_attached(
    remote_route_fixture, release_manifest_fixture, incident_fixture, maintenance_month_fixture,
) -> None:
    with pytest.raises(ValidationError):
        RemoteRouteStateV1.model_validate({**remote_route_fixture, "route_generation": 0})
    with pytest.raises(ValidationError):
        RemoteRouteStateV1.model_validate({**remote_route_fixture, "valid_until": remote_route_fixture["observed_at"]})
    with pytest.raises(ValidationError):
        RemoteRouteStateV1.model_validate({
            **remote_route_fixture,
            "valid_until": remote_route_fixture["observed_at"] + timedelta(seconds=31),
        })
    with pytest.raises(ValidationError):
        ReleaseManifestV1.model_validate({**release_manifest_fixture, "expires_at": release_manifest_fixture["issued_at"]})
    with pytest.raises(ValidationError):
        IncidentStateV1.model_validate({**incident_fixture, "controller_generation": 0})
    with pytest.raises(ValidationError):
        IncidentStateV1.model_validate({**incident_fixture, "exited_at": incident_fixture["entered_at"] - timedelta(seconds=1)})
    with pytest.raises(ValidationError):
        RemoteRouteStateV1.model_validate({**remote_route_fixture, "reason_codes": ("drift", "drift")})
    with pytest.raises(ValidationError):
        IncidentStateV1.model_validate({**incident_fixture, "reason_codes": ("containment",) * 17})
    with pytest.raises(ValidationError):
        MaintenanceMonthV1.model_validate({
            **maintenance_month_fixture,
            "ordinary_total_minutes": maintenance_month_fixture["ordinary_total_minutes"] + 1,
        })

def test_remote_adapter_posture_and_boundary_generations_are_closed(
    remote_adapter_posture_fixture, remote_route_receipt_fixture, node_revocation_receipt_fixture,
) -> None:
    with pytest.raises(ValidationError):
        RemoteAdapterPostureV1.model_validate({
            **remote_adapter_posture_fixture,
            "valid_until": remote_adapter_posture_fixture["observed_at"] + timedelta(seconds=31),
        })
    with pytest.raises(ValidationError):
        RemoteRouteReceiptV1.model_validate({**remote_route_receipt_fixture, "route_generation": 0})
    with pytest.raises(ValidationError):
        NodeRevocationReceiptV1.model_validate({**node_revocation_receipt_fixture, "revocation_generation": 0})

@pytest.mark.parametrize("mutation", [
    {"state": "read_only", "adapter_id": None},
    {"state": "scoped_actions", "posture": "drifted"},
    {"state": "disabled", "origin": "https://tuntun.home.arpa:8443", "posture": "not_configured"},
    {"state": "suspended", "origin": "https://tuntun.home.arpa:8443", "posture": "drifted"},
])
def test_remote_route_rejects_state_binding_lies(remote_route_fixture, mutation) -> None:
    with pytest.raises(ValidationError):
        RemoteRouteStateV1.model_validate({**remote_route_fixture, **mutation})

def test_remote_adapter_none_route_flag_is_exclusive(remote_adapter_posture_fixture) -> None:
    with pytest.raises(ValidationError):
        RemoteAdapterPostureV1.model_validate({
            **remote_adapter_posture_fixture,
            "route_flags": ("none", "funnel"),
        })

def test_adapter_local_state_has_no_vendor_identity_or_address(tailscale_state_fixture) -> None:
    for forbidden in ("node_name", "user_email", "ip_address"):
        with pytest.raises(ValidationError):
            TailscaleClientStateV1.model_validate({**tailscale_state_fixture, forbidden: "private"})

def test_remote_operation_request_and_decision_fail_closed(remote_operation_fixture, remote_decision_fixture) -> None:
    with pytest.raises(ValidationError):
        RemoteOperationRequestV1.model_validate({
            **remote_operation_fixture,
            "expires_at": remote_operation_fixture["issued_at"] + timedelta(seconds=6),
        })
    with pytest.raises(ValidationError):
        RemoteOperationDecisionV1.model_validate({
            **remote_decision_fixture,
            "allowed": True,
            "code": "REMOTE_OPERATION_DENIED",
        })

def test_remote_commissioning_and_read_model_cannot_overstate_route(
    commissioning_receipt_fixture, remote_access_read_model_fixture,
) -> None:
    with pytest.raises(ValidationError):
        RemoteCommissioningReceiptV1.model_validate({
            **commissioning_receipt_fixture,
            "origin": "https://public.example",
        })
    with pytest.raises(ValidationError):
        RemoteAccessReadModelV1.model_validate({
            **remote_access_read_model_fixture,
            "route_fact": {**remote_access_read_model_fixture["route_fact"], "state": "disabled"},
        })
    disabled = RemoteAccessReadModelV1.model_validate({
        **remote_access_read_model_fixture,
        "route_fact": {**remote_access_read_model_fixture["route_fact"], "state": "disabled"},
        "route": {
            **remote_access_read_model_fixture["route"],
            "origin": None,
            "posture": "not_configured",
            "allowed_operation_classes": (),
        },
        "sessions": (),
        "disable_action": None,
    })
    assert disabled.route.allowed_operation_classes == ()
    suspended = RemoteAccessReadModelV1.model_validate({
        **remote_access_read_model_fixture,
        "route_fact": {**remote_access_read_model_fixture["route_fact"], "state": "suspended"},
        "route": {
            **remote_access_read_model_fixture["route"],
            "origin": None,
            "posture": "drifted",
            "allowed_operation_classes": (),
        },
        "sessions": (),
    })
    assert suspended.route.allowed_operation_classes == ()
    session = remote_access_read_model_fixture["sessions"][0]
    with pytest.raises(ValidationError):
        RemoteAccessReadModelV1.model_validate({
            **remote_access_read_model_fixture,
            "sessions": ({
                **session,
                "idle_expires_at": remote_access_read_model_fixture["generated_at"],
            },),
        })
    with pytest.raises(ValidationError):
        RemoteAccessReadModelV1.model_validate({
            **remote_access_read_model_fixture,
            "sessions": (session, session),
        })

def test_plugin_call_and_result_state_are_enforced(plugin_call_fixture, plugin_result_fixture) -> None:
    with pytest.raises(ValidationError):
        PluginCallEnvelopeV1.model_validate({
            **plugin_call_fixture,
            "expires_at": plugin_call_fixture["issued_at"] + timedelta(seconds=6),
        })
    with pytest.raises(ValidationError):
        PluginCallResultEnvelopeV1.model_validate({**plugin_result_fixture, "state": "denied"})
    with pytest.raises(ValidationError):
        PluginCallEnvelopeV1.model_validate({
            **plugin_call_fixture,
            "payload": {**plugin_call_fixture["payload"], "request_id": WRONG_UUID},
        })
    with pytest.raises(ValidationError):
        PluginCallEnvelopeV1.model_validate({
            **plugin_call_fixture,
            "payload": {
                **plugin_call_fixture["payload"],
                "expires_at": plugin_call_fixture["expires_at"] - timedelta(microseconds=1),
            },
        })
    with pytest.raises(ValidationError):
        PluginCallResultEnvelopeV1.model_validate({
            **plugin_result_fixture,
            "payload": {**plugin_result_fixture["payload"], "request_id": WRONG_UUID},
        })

def test_release_decision_cannot_allow_without_verified_manifest(release_decision_fixture) -> None:
    with pytest.raises(ValidationError):
        ReleaseDecisionV1.model_validate({**release_decision_fixture, "install_allowed": True, "accepted_manifest": None})

@pytest.mark.parametrize("mutation", [
    {"relative_path": "../core.whl"},
    {"relative_path": "/absolute/core.whl"},
    {"artifact_name": "core.whl", "relative_path": "wheels/./core.whl"},
    {"artifact_name": "core.whl", "relative_path": "wheels/core.whl/"},
    {"artifact_name": "core.whl", "relative_path": "wheels/other.whl"},
])
def test_release_artifact_name_and_path_are_closed(named_artifact_fixture, mutation) -> None:
    with pytest.raises(ValidationError):
        NamedArtifactDigestV1.model_validate({**named_artifact_fixture, **mutation})

def test_release_manifest_rejects_duplicate_artifact_name_or_path(release_manifest_fixture) -> None:
    artifact = release_manifest_fixture["artifact_digests"][0]
    with pytest.raises(ValidationError):
        ReleaseManifestV1.model_validate({
            **release_manifest_fixture,
            "artifact_digests": (artifact, artifact),
        })

def test_backup_restore_and_c_gate_contracts_reject_false_evidence(
    backup_set_fixture, restore_run_fixture, c0_fixture, c1_fixture,
) -> None:
    with pytest.raises(ValidationError):
        BackupSetV1.model_validate({
            **backup_set_fixture,
            "independent": {
                **backup_set_fixture["independent"],
                "volume_or_adapter_commitment": backup_set_fixture["attached"]["volume_commitment"],
            },
        })
    with pytest.raises(ValidationError):
        BackupSetV1.model_validate({
            **backup_set_fixture,
            "independent": {
                **backup_set_fixture["independent"],
                "failure_domain_commitment": backup_set_fixture["attached"]["failure_domain_commitment"],
            },
        })
    with pytest.raises(ValidationError):
        BackupSetV1.model_validate({
            **backup_set_fixture,
            "attached": {**backup_set_fixture["attached"], "generation": backup_set_fixture["source_generation"] + 1},
        })
    with pytest.raises(ValidationError):
        BackupSetV1.model_validate({
            **backup_set_fixture,
            "attached": {
                **backup_set_fixture["attached"],
                "latest_verified_at": backup_set_fixture["created_at"] + timedelta(seconds=1),
            },
        })
    with pytest.raises(ValidationError):
        RestoreRunV1.model_validate({**restore_run_fixture, "state": "completed", "enabled_phase_ids": ("phase1",)})
    with pytest.raises(ValidationError):
        C0CandidateV1.model_validate({**c0_fixture, "eight_hour_stress_digests": (SAME_DIGEST, SAME_DIGEST)})
    artifact = c1_fixture["artifact_digests"][0]
    with pytest.raises(ValidationError):
        C1CandidateV1.model_validate({**c1_fixture, "artifact_digests": (artifact, artifact)})

def test_retirement_contracts_cannot_claim_retired_with_pending_effects(
    retirement_state_fixture, retirement_receipt_fixture,
) -> None:
    with pytest.raises(ValidationError):
        DeviceRetirementStateV1.model_validate({
            **retirement_state_fixture,
            "lifecycle": "retired",
            "managed_storage_state": "pending",
        })
    with pytest.raises(ValidationError):
        RetirementReceiptV1.model_validate({
            **retirement_receipt_fixture,
            "lifecycle": "retired",
            "reconnect_state": "pending",
        })

def test_maintenance_freeze_and_clearance_are_closed(
    freeze_state_fixture, cleared_freeze_state_fixture, relatched_freeze_state_fixture, freeze_clearance_fixture,
) -> None:
    with pytest.raises(ValidationError):
        MaintenanceFreezeStateV1.model_validate({
            **freeze_state_fixture,
            "state": "frozen",
            "trigger_window_digest": None,
        })
    with pytest.raises(ValidationError):
        MaintenanceFreezeStateV1.model_validate({
            **freeze_state_fixture,
            "trigger_window_end_exclusive": freeze_state_fixture["triggered_at"] + timedelta(seconds=1),
        })
    with pytest.raises(ValidationError):
        MaintenanceFreezeStateV1.model_validate({
            **cleared_freeze_state_fixture,
            "cleared_through_period_end_exclusive": cleared_freeze_state_fixture["cleared_at"] + timedelta(seconds=1),
        })
    with pytest.raises(ValidationError):
        MaintenanceFreezeStateV1.model_validate({
            **relatched_freeze_state_fixture,
            "triggered_at": relatched_freeze_state_fixture["cleared_at"],
        })
    with pytest.raises(ValidationError):
        MaintenanceFreezeClearanceV1.model_validate({
            **freeze_clearance_fixture,
            "expires_at": freeze_clearance_fixture["issued_at"] + timedelta(minutes=2, microseconds=1),
        })
    with pytest.raises(ValidationError):
        MaintenanceFreezeClearanceV1.model_validate({
            **freeze_clearance_fixture,
            "evaluated_through_period_end_exclusive": freeze_clearance_fixture["issued_at"] + timedelta(seconds=1),
        })

@pytest.mark.parametrize("unsafe", ["<b>urgent</b>", "https://evil.example", "safe\u202ehidden", "[click](x)"])
def test_plugin_render_text_rejects_markup_urls_hidden_and_bidi(plugin_health_render_fixture, unsafe) -> None:
    with pytest.raises(ValidationError):
        PluginHealthRenderV1.model_validate({**plugin_health_render_fixture, "headline": unsafe})

def test_plugin_request_expiry_validators_are_attached(plugin_health_snapshot_fixture, plugin_alert_fixture) -> None:
    with pytest.raises(ValidationError):
        PluginHealthSnapshotV1.model_validate({
            **plugin_health_snapshot_fixture,
            "expires_at": plugin_health_snapshot_fixture["issued_at"] + timedelta(seconds=6),
        })
    with pytest.raises(ValidationError):
        PluginLocalAlertV1.model_validate({
            **plugin_alert_fixture,
            "expires_at": plugin_alert_fixture["occurred_at"],
        })

def test_p1_preview_gate_cannot_parse_as_whole_program_gate() -> None:
    for value in ("P1R0", "P1R1"):
        with pytest.raises(ValidationError):
            WholeProgramGateId.model_validate(value)
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/hardening/test_phase6_contracts.py tests/property/hardening/test_phase6_contract_rejection.py -q`
Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_contracts.hardening'`.

- [ ] **Step 3: Implement the complete strict models and generators**

~~~python
INITIAL_PLUGIN_CAPABILITY_IDS: Final[frozenset[str]] = frozenset({
    "system.health.render.v1",
    "notification.local_alert.render.v1",
})

class StrictHardeningContract(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
~~~

The validators are methods on the frozen models (and `PlainSafeText` is a validated annotated type), never detached helpers that Pydantic cannot register. Generate recursively closed schemas and positive/adversarial fixtures. Property mutations cover duplicate JSON keys, non-finite values, unknown field/version/enum/discriminator, unsafe IDs/text/entrypoints, expiry inversions, wrong route origin, zero generations, capability-list widening, policy-like manifest fields, markup/URL/bidi/plugin action injection, oversized lists/text, malformed SPDX/digest/signature identity, C-gate aliasing, and unsupported migration majors.

- [ ] **Step 4: Run green and regeneration drift checks**

Run: `uv run python scripts/phase6/generate_schemas.py --check && uv run pytest tests/contract/hardening tests/property/hardening/test_phase6_contract_rejection.py -q && uv run ruff check packages/contracts/src/tuntun_contracts/hardening scripts/phase6/generate_schemas.py tests/contract/hardening tests/property/hardening && uv run mypy packages/contracts/src`
Expected: PASS; generator prints `hardening schema drift: none`; every forbidden field/capability/value fails closed.

- [ ] **Step 5: Commit exact contract paths**

~~~bash
git add packages/contracts/src/tuntun_contracts/hardening scripts/phase6/generate_schemas.py schemas/hardening/v1 schemas/plugins/phase6.initial.1 schemas/releases/v1 tests/contract/hardening tests/property/hardening/test_phase6_contract_rejection.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(hardening): freeze Phase 6 contracts"
~~~

### Task 02: Build deterministic Phase 6 fakes, hostile corpora, and T01–T25 scenario registry

**Depends on:** Task 01.
**Gate contribution:** P6-E0 and every non-hardware Phase 6 task.
**Estimated effort:** 1 person-day.

**Files:**
- Create: `packages/testing/src/tuntun_testing/phase6/clock.py`
- Create: `packages/testing/src/tuntun_testing/phase6/remote.py`
- Create: `packages/testing/src/tuntun_testing/phase6/plugin.py`
- Create: `packages/testing/src/tuntun_testing/phase6/release.py`
- Create: `packages/testing/src/tuntun_testing/phase6/recovery.py`
- Create: `packages/testing/src/tuntun_testing/phase6/scenario.py`
- Create: `scripts/phase6/build_corpora.py`
- Create: `fixtures/synthetic/phase6/contracts/*.json`
- Create: `fixtures/adversarial/phase6/*.jsonl`
- Test: `tests/unit/testing/phase6/test_phase6_fakes.py`
- Test: `tests/privacy/phase6/test_synthetic_only.py`
- Test: `tests/contract/hardening/test_threat_scenario_registry.py`

**Interfaces:** Produces fake clock, route, Tailscale posture, firewall scan, passkey assurance, plugin child, sandbox, release signer, archive, restore target, fault points, and a closed `ThreatScenarioRegistry` with exactly `T01` through `T25`. Fakes never require a real VPN, Keychain, Apple credential, network, or household bytes.

**Rollback/disabled exit:** Missing threat scenario or nondeterministic fixture blocks all later acceptance builders; it cannot be marked documentation-only.

- [ ] **Step 1: Write red determinism, completeness, and sentinel tests**

~~~python
def test_threat_registry_is_exactly_t01_through_t25() -> None:
    registry = load_threat_scenarios()
    assert tuple(registry.ids()) == tuple(f"T{i:02d}" for i in range(1, 26))
    assert all(case.control_ids and case.test_ids and case.fallback for case in registry)

def test_phase6_scenario_replays_same_faults() -> None:
    a = Phase6Scenario(seed=601, faults={"after_route_commit": 1, "during_plugin_cleanup": 1})
    b = Phase6Scenario(seed=601, faults={"after_route_commit": 1, "during_plugin_cleanup": 1})
    assert a.run_digest() == b.run_digest()

def test_public_fixture_tree_has_no_private_sentinel(public_fixture_tree) -> None:
    assert scan_private_sentinels(public_fixture_tree).findings == ()
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/testing/phase6/test_phase6_fakes.py tests/privacy/phase6/test_synthetic_only.py tests/contract/hardening/test_threat_scenario_registry.py -q`
Expected: FAIL because `tuntun_testing.phase6` and the threat corpus do not exist.

- [ ] **Step 3: Implement bounded fakes and exact hostile cases**

~~~python
THREAT_IDS: Final[tuple[str, ...]] = tuple(f"T{i:02d}" for i in range(1, 26))

@dataclass(frozen=True)
class Phase6FaultPoint:
    name: Literal[
        "before_route_commit", "after_route_commit", "before_session_revoke",
        "after_session_revoke", "during_plugin_spawn", "during_plugin_cleanup",
        "after_backup_verify", "during_migration", "after_install_before_health",
        "during_restore_reconcile", "before_c0_approval", "before_c1_approval",
    ]

def assert_complete_threat_registry(cases: Sequence[ThreatScenario]) -> None:
    if tuple(case.threat_id for case in cases) != THREAT_IDS:
        raise ValueError("threat_registry_not_t01_through_t25")
~~~

Corpora include wrong node/passkey/origin/CSRF/nonce/session generation, route drift, public/lateral listeners, forbidden remote operations, capability/manifest/result injection, plugin exfiltration/resource/crash/late output, malicious signer/workflow/SBOM/tag/update/migration/archive, deletion resurrection, incident-state bypass, maintainer/fork-secret, and content-sentinel cases. Every fixture uses synthetic pseudonyms, private documentation IP ranges, fake certificates, and non-secret signatures.

- [ ] **Step 4: Run green and reproduce the corpus twice**

Run: `uv run python scripts/phase6/build_corpora.py --check-determinism && uv run pytest tests/unit/testing/phase6 tests/privacy/phase6/test_synthetic_only.py tests/contract/hardening/test_threat_scenario_registry.py -q && uv run ruff check packages/testing/src/tuntun_testing/phase6 scripts/phase6/build_corpora.py tests/unit/testing/phase6 tests/privacy/phase6 && uv run mypy packages/testing/src`
Expected: PASS; both builds have the same manifest digest and registry reports exactly 25 threats.

- [ ] **Step 5: Commit fakes and corpora**

~~~bash
git add packages/testing/src/tuntun_testing/phase6 scripts/phase6/build_corpora.py fixtures/synthetic/phase6 fixtures/adversarial/phase6 tests/unit/testing/phase6 tests/privacy/phase6/test_synthetic_only.py tests/contract/hardening/test_threat_scenario_registry.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(hardening): add Phase 6 adversarial harness"
~~~

### Task 03: Persist remote, plugin, release, recovery, incident, and maintenance state

**Depends on:** Tasks 01–02 and current Phase 5 migration head `0022`.
**Gate contribution:** P6-E0.
**Estimated effort:** 2 person-days.

**Files:**
- Create: `apps/core/migrations/versions/0023_remote_access.py`
- Create: `apps/core/migrations/versions/0024_plugins_releases.py`
- Create: `apps/core/migrations/versions/0025_recovery_incident_maintenance.py`
- Create: `apps/core/src/tuntun_core/domain/hardening/*.py`
- Create: `apps/core/src/tuntun_core/services/hardening/repositories.py`
- Test: `apps/core/tests/migrations/test_phase6_migrations.py`
- Test: `apps/core/tests/integration/hardening/test_phase6_repositories.py`
- Test: `tests/privacy/phase6/test_phase6_database_columns.py`
- Test: `tests/fault/phase6/test_phase6_migration_interruption.py`

**Interfaces:** Produces transactional repositories for node/route/session, plugin installation/grant/receipt, release/update, backup/restore/deletion reconciliation, incident, maintenance month, and expansion freeze. All writes consume the shared serialized unit of work and audit/outbox.

**Rollback/disabled exit:** Migration ambiguity restores the verified pre-migration database in isolation and leaves Phase 6 routes absent. Downgrade revokes sessions/grants and never reconstitutes credentials.

- [ ] **Step 1: Write red migration, forbidden-column, CAS, interruption, and retention tests**

~~~python
def test_remote_schema_has_no_vendor_identity_or_address(inspector) -> None:
    columns = all_column_names(inspector, "remote_nodes", "remote_sessions")
    assert columns.isdisjoint({"node_name", "user_email", "ip_address", "provider_username"})

async def test_route_cas_and_revocation_are_one_transaction(repositories, route) -> None:
    updated = await repositories.routes.transition(route.id, expected_generation=4, state="suspended")
    assert updated.route_generation == 5
    assert await repositories.sessions.active_for_route(route.id) == ()

def test_interrupted_phase6_migration_opens_no_route(interrupted_upgrade) -> None:
    assert interrupted_upgrade.recovered_from_verified_backup
    assert interrupted_upgrade.feature_manifest.remote_access == "absent"
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/core/tests/migrations/test_phase6_migrations.py apps/core/tests/integration/hardening/test_phase6_repositories.py tests/privacy/phase6/test_phase6_database_columns.py tests/fault/phase6/test_phase6_migration_interruption.py -q`
Expected: FAIL because revisions `0023`–`0025` and hardening repositories are absent.

- [ ] **Step 3: Implement migrations, constraints, triggers, and repositories**

~~~python
async def suspend_route_and_revoke_sessions(
    uow: SerializedUnitOfWork,
    route_id: UUID,
    expected_generation: int,
    reason: SafeReasonCode,
) -> RemoteRouteStateV1:
    async with uow.authoritative() as tx:
        route = await tx.remote_routes.require_generation(route_id, expected_generation)
        suspended = route.suspend(reason=reason, next_generation=expected_generation + 1)
        await tx.remote_routes.save(suspended)
        await tx.remote_sessions.revoke_for_route(route_id, suspended.revocation_generation)
        await tx.audit.append_safe("remote.route_suspended", suspended.commitment())
        await tx.outbox.add("remote.route_closed.v1", suspended.safe_event())
        return suspended
~~~

Add database constraints for exact states/generations/expiry, partial unique active route, one current registry revision, immutable release candidate digests, incident transitions, deletion-generation monotonicity, and monthly arithmetic. Add retention jobs for 180-day remote/plugin receipts and 30-day counters, preserving incident-bound counters only by explicit incident reference.

- [ ] **Step 4: Run migration round-trip, fault, privacy, and static checks**

Run: `uv run alembic -c apps/core/alembic.ini upgrade head && uv run pytest apps/core/tests/migrations/test_phase6_migrations.py apps/core/tests/integration/hardening/test_phase6_repositories.py tests/privacy/phase6/test_phase6_database_columns.py tests/fault/phase6/test_phase6_migration_interruption.py -q && uv run ruff check apps/core/migrations/versions/0023_remote_access.py apps/core/migrations/versions/0024_plugins_releases.py apps/core/migrations/versions/0025_recovery_incident_maintenance.py apps/core/src/tuntun_core/domain/hardening apps/core/src/tuntun_core/services/hardening/repositories.py && uv run mypy apps/core/src`
Expected: PASS; upgrade reaches `0025`, interruption restores isolation, and forbidden columns are absent.

- [ ] **Step 5: Commit migrations and repositories**

~~~bash
git add apps/core/migrations/versions/0023_remote_access.py apps/core/migrations/versions/0024_plugins_releases.py apps/core/migrations/versions/0025_recovery_incident_maintenance.py apps/core/src/tuntun_core/domain/hardening apps/core/src/tuntun_core/services/hardening/repositories.py apps/core/tests/migrations/test_phase6_migrations.py apps/core/tests/integration/hardening/test_phase6_repositories.py tests/privacy/phase6/test_phase6_database_columns.py tests/fault/phase6/test_phase6_migration_interruption.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(hardening): persist Phase 6 control state"
~~~

### Task 04: Register cross-phase amendments, Privacy Shield effect, and default feature absence

**Depends on:** Tasks 01–03 and accepted shared policy/feature registries.
**Gate contribution:** P6-E0.
**Estimated effort:** 1.5 person-days.

**Files:**
- Modify: `packages/policy/src/tuntun_policy/registry.py`
- Modify: `packages/contracts/src/tuntun_contracts/ui.py`
- Modify: `apps/core/src/tuntun_core/services/features/registry.py`
- Modify: `apps/core/src/tuntun_core/services/privacy/effects.py`
- Modify: `apps/admin/src/app/feature-registry.ts`
- Create: `apps/core/src/tuntun_core/services/hardening/privacy_effects.py`
- Create: `fixtures/synthetic/features/phase6-default-absent-v1.json`
- Test: `tests/policy/test_phase6_amendments.py`
- Test: `tests/security/phase6/test_phase6_feature_absence.py`
- Test: `tests/privacy/phase6/test_p6_privacy_effect.py`
- Test: `apps/admin/src/app/feature-registry.phase6.test.ts`

**Interfaces:** Registers `owner_vpn_console_v1`, `remote_origin_v1`, `p6.remote_plugin`, and feature IDs `remote_access`, `remote_scoped_actions`, `remote_camera_metadata`, `remote_camera_playback`, `third_party_plugins`, `signed_updates`, and `public_release`. The default manifest marks every Phase 6 ID `absent`.

**Rollback/disabled exit:** Revocation/policy/feature drift removes API/UI/client registrations, closes routes/sessions/plugins, and leaves earlier local features operating under their accepted contracts.

- [ ] **Step 1: Write red amendment direction, privacy, and clean-absence tests**

~~~python
def test_remote_origin_can_only_reduce_local_decision(policy, local_request) -> None:
    local = policy.decide(local_request)
    remote = policy.decide(local_request.model_copy(update={"origin": "remote_origin_v1"}))
    assert not (local.denied and remote.allowed)

async def test_privacy_shield_revokes_remote_and_plugins_before_fanout(harness) -> None:
    receipt = await harness.activate_privacy()
    assert receipt.effect("p6.remote_plugin").authority_revoked
    assert harness.remote.active_sessions == ()
    assert harness.plugins.active_calls == ()
    assert harness.core_alerts.mandatory_surface_available

def test_default_manifest_has_no_phase6_route(feature_app) -> None:
    assert feature_app.manifest.state("remote_access") == "absent"
    assert feature_app.routes.match("/api/v1/remote-access") is None
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/policy/test_phase6_amendments.py tests/security/phase6/test_phase6_feature_absence.py tests/privacy/phase6/test_p6_privacy_effect.py -q && pnpm --dir apps/admin test -- feature-registry.phase6.test.ts`
Expected: FAIL because the amendments/effect and Phase 6 IDs are unknown.

- [ ] **Step 3: Implement exact amendments, revocation ordering, and absent registration**

~~~python
PHASE6_AMENDMENTS = {
    "owner_vpn_console_v1": AmendmentEffect.PRIVATE_INTERFACE_ONLY,
    "remote_origin_v1": AmendmentEffect.ASSURANCE_REDUCING_ONLY,
}

async def revoke_p6_remote_plugin(ctx: PrivacyEffectContext) -> PrivacyEffectReceipt:
    committed = await ctx.uow.revoke_authority(
        effect_id="p6.remote_plugin",
        privacy_generation=ctx.privacy_generation,
        authorities=("remote_sessions", "remote_routes", "plugin_grants", "plugin_calls"),
    )
    await ctx.outbox.request_after_commit("p6.remote_plugin.stop.v1", committed.commitment)
    return committed
~~~

The UI fact union gains `vpn_remote` and `plugin` only through the shared schema. Default browser chunks, direct URLs, API routes, prepared actions, IPC endpoints, config keys, and launchd jobs remain absent. Regenerate shared schemas/OpenAPI/TypeScript and feature digests.

- [ ] **Step 4: Run green, generation, absence, and browser checks**

Run: `uv run pytest tests/policy/test_phase6_amendments.py tests/security/phase6/test_phase6_feature_absence.py tests/privacy/phase6/test_p6_privacy_effect.py -q && uv run python scripts/check_feature_absence.py --manifest fixtures/synthetic/features/phase6-default-absent-v1.json --features remote_access,remote_scoped_actions,remote_camera_metadata,remote_camera_playback,third_party_plugins,signed_updates,public_release && pnpm --dir apps/admin test -- feature-registry.phase6.test.ts && uv run ruff check packages/policy apps/core/src/tuntun_core/services/hardening/privacy_effects.py tests/policy tests/security/phase6 tests/privacy/phase6 && uv run mypy packages/policy/src apps/core/src`
Expected: PASS; absence checker reports no Phase 6 route/bundle/registration, and privacy authority revokes before stop requests.

- [ ] **Step 5: Commit shared amendments and absence evidence**

~~~bash
git add packages/policy/src/tuntun_policy/registry.py packages/contracts/src/tuntun_contracts/ui.py apps/core/src/tuntun_core/services/features/registry.py apps/core/src/tuntun_core/services/privacy/effects.py apps/core/src/tuntun_core/services/hardening/privacy_effects.py apps/admin/src/app/feature-registry.ts fixtures/synthetic/features/phase6-default-absent-v1.json tests/policy/test_phase6_amendments.py tests/security/phase6/test_phase6_feature_absence.py tests/privacy/phase6/test_p6_privacy_effect.py apps/admin/src/app/feature-registry.phase6.test.ts schemas packages/ui-contracts
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(policy): register Phase 6 amendments fail closed"
~~~

### Task 05: Consolidate the system inventory, A–S assurance artifacts, and exact T01–T25 control map

**Depends on:** Tasks 01–04 and accepted Phase 1–5 evidence manifests.
**Gate contribution:** P6-0.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `scripts/phase6/inventory_system.py`
- Create: `docs/architecture/system-inventory.md`
- Create: `docs/security/threat-model.md`
- Create: `docs/security/risk-register.md`
- Create: `docs/privacy/data-flow-inventory.md`
- Create: `docs/privacy/phase6-remote-plugin-privacy.md`
- Create: `docs/evidence/phase6-evidence-schema.json`
- Create: `fixtures/synthetic/phase6/threat-control-map-v1.json`
- Test: `tests/contract/hardening/test_phase6_evidence_schema.py`
- Test: `tests/acceptance/phase6/test_system_inventory.py`
- Test: `tests/acceptance/phase6/test_t01_t25_control_map.py`
- Test: `tests/privacy/phase6/test_assurance_artifacts_safe.py`

**Interfaces:** Produces the P6-0 asset/service/process/account/key/store/listener/route/data-flow inventory, A–H completion links, I–S assurance map, ranked risks, decisions, exact T01–T25 control/test/evidence ownership, and a signed content-safe P6-0 receipt. It consumes digests and safe facts, never raw prior evidence.

**Rollback/disabled exit:** Missing owner/test/fallback or any unmitigated high/critical item blocks P6-0; an unsupported component is declared disabled/absent, not silently omitted.

- [ ] **Step 1: Write red completeness, risk, and content-safety tests**

~~~python
def test_every_threat_has_prevention_detection_test_and_fallback(control_map) -> None:
    assert set(control_map) == {f"T{i:02d}" for i in range(1, 26)}
    for row in control_map.values():
        assert row.controls and row.test_commands and row.evidence_schema
        assert row.residual_owner and row.review_at and row.disable_or_fallback

def test_no_high_or_critical_risk_is_unowned_or_open(risk_register) -> None:
    assert not [r for r in risk_register if r.residual in {"high", "critical"} and r.status != "mitigated"]

def test_inventory_has_no_real_endpoint_or_identity(inventory_packet) -> None:
    assert scan_public_private_data(inventory_packet).findings == ()
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/hardening/test_phase6_evidence_schema.py tests/acceptance/phase6/test_system_inventory.py tests/acceptance/phase6/test_t01_t25_control_map.py tests/privacy/phase6/test_assurance_artifacts_safe.py -q`
Expected: FAIL because the inventory, control map, evidence schema, and assurance artifacts do not exist.

- [ ] **Step 3: Implement inventory collection and deterministic assurance rendering**

~~~python
def build_p6_baseline(inputs: BaselineInputs) -> P6BaselineReceipt:
    require(inputs.threat_ids == tuple(f"T{i:02d}" for i in range(1, 26)))
    require(all(item.owner and item.test_ids for item in inputs.assets_and_risks))
    require(not inputs.unmitigated_high_or_critical)
    return P6BaselineReceipt.from_safe_commitments(
        build=inputs.clean_build,
        feature_manifest=inputs.feature_manifest_digest,
        architecture_sections=tuple("ABCDEFGHIJKLMNOPQRS"),
        threat_map_digest=inputs.threat_map_digest,
        inventory_digest=inputs.inventory_digest,
    )
~~~

Inventory local processes, launchd jobs, Unix/TCP/UDP listeners, outbound destinations by class, stores/keys/certificates, feature routes, actors, backups, update/signing boundaries, manual controls, provider dependencies, and failure consequences. Docs use synthetic examples and link to canonical specs rather than copying household identifiers or raw evidence.

- [ ] **Step 4: Run green, generate synthetic receipt, and scan all artifacts**

Run: `uv run python scripts/phase6/inventory_system.py --synthetic --output var/evidence/phase6/p6-0-synthetic.json && uv run pytest tests/contract/hardening/test_phase6_evidence_schema.py tests/acceptance/phase6/test_system_inventory.py tests/acceptance/phase6/test_t01_t25_control_map.py tests/privacy/phase6/test_assurance_artifacts_safe.py -q && uv run python scripts/scan_private_data.py --paths docs/architecture docs/security docs/privacy fixtures/synthetic/phase6 var/evidence/phase6/p6-0-synthetic.json && uv run ruff check scripts/phase6/inventory_system.py tests/acceptance/phase6 tests/privacy/phase6`
Expected: PASS; receipt reports 25 mapped threats, A–S coverage, zero unsafe findings, and zero open high/critical risk.

- [ ] **Step 5: Commit the baseline artifacts**

~~~bash
git add scripts/phase6/inventory_system.py docs/architecture/system-inventory.md docs/security/threat-model.md docs/security/risk-register.md docs/privacy/data-flow-inventory.md docs/privacy/phase6-remote-plugin-privacy.md docs/evidence/phase6-evidence-schema.json fixtures/synthetic/phase6/threat-control-map-v1.json tests/contract/hardening/test_phase6_evidence_schema.py tests/acceptance/phase6/test_system_inventory.py tests/acceptance/phase6/test_t01_t25_control_map.py tests/privacy/phase6/test_assurance_artifacts_safe.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "docs(assurance): bind the six-phase security baseline"
~~~

### Task 06: Build the LAN-only clean installer and prove Phase 6 default absence

**Depends on:** Tasks 01–05 and accepted Phase 1–5 install layout.
**Gate contribution:** P6-0.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `ops/install/install.py`
- Create: `ops/install/verify_clean_system.py`
- Create: `ops/network/exposure-manifest.v1.yaml`
- Create: `ops/network/verify_listeners.py`
- Create: `ops/network/verify_routes.py`
- Create: `ops/network/verify_router_mappings.py`
- Create: `scripts/phase6/verify_default_absence.py`
- Test: `tests/integration/install/test_phase6_clean_install.py`
- Test: `tests/security/phase6/test_default_network_absence.py`
- Test: `tests/security/phase6/test_forbidden_remote_implementations_absent.py`
- Test: `tests/acceptance/phase6/test_p6_0_gate.py`

**Interfaces:** Produces a least-privilege install with loopback/private-LAN accepted services only, empty Phase 6 feature state, and deterministic source/package/config/listener/route scans. It does not install or start Tailscale, a remote route, plugin child, updater, or publication job.

**Rollback/disabled exit:** Any unexpected listener, route, mapping, adapter, remote switch, or public dependency stops services and leaves recovery guidance; it never broadens a bind to complete installation.

- [ ] **Step 1: Write red clean-install and forbidden-surface tests**

~~~python
def test_clean_install_registers_no_remote_adapter(clean_install) -> None:
    assert clean_install.feature_state("remote_access") == "absent"
    assert clean_install.listeners.for_phase(6) == ()
    assert clean_install.launchd_jobs.matching("remote|plugin|publish") == ()

@pytest.mark.parametrize("needle", [
    "WireGuardRemoteAccessAdapter", "advertise-routes", "exit-node", "tailscale funnel",
    "tailscale ssh", "upnp", "nat-pmp", "rendezvous_server", "public_reverse_proxy",
])
def test_runtime_release_surface_has_no_forbidden_remote_implementation(
    release_surface_registry, needle,
) -> None:
    assert release_surface_registry.find_runtime_reference(needle) == ()

def test_no_wildcard_or_public_bind(exposure_receipt) -> None:
    assert not exposure_receipt.binds_any("0.0.0.0", "::", scope="tuntun")
    assert exposure_receipt.publicly_routed == ()
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/install/test_phase6_clean_install.py tests/security/phase6/test_default_network_absence.py tests/security/phase6/test_forbidden_remote_implementations_absent.py tests/acceptance/phase6/test_p6_0_gate.py -q`
Expected: FAIL because the clean installer and exposure/absence scanners are absent.

- [ ] **Step 3: Implement fail-closed prerequisite, install, and absence verification**

~~~python
def assert_default_exposure(receipt: ExposureReceipt) -> None:
    allowed = {Listener("127.0.0.1", 8787, "owner_api")}
    if not receipt.tuntun_listeners.issubset(allowed):
        raise InstallBlocked("unexpected_listener")
    if receipt.router_mappings or receipt.public_routes or receipt.phase6_adapters:
        raise InstallBlocked("remote_default_not_absent")

def initial_phase6_manifest() -> dict[str, str]:
    return {feature: "absent" for feature in PHASE6_FEATURE_IDS}
~~~

Prerequisites verify supported Intel macOS, FileVault, disk reserve, time, owner account, no public mapping, and exact two-router topology evidence. Install purpose-separated Keychain/data paths and existing accepted services only. Scanners inspect Python/TypeScript registrations, package metadata, launchd, socket tables, route tables, firewall, UPnP/NAT-PMP/PCP receipts, binaries/strings, config schemas, API/OpenAPI, browser chunks, and simulator manifests.

- [ ] **Step 4: Run green and P6-0 synthetic gate**

Run: `uv run python scripts/phase6/verify_default_absence.py && uv run pytest tests/integration/install/test_phase6_clean_install.py tests/security/phase6/test_default_network_absence.py tests/security/phase6/test_forbidden_remote_implementations_absent.py tests/acceptance/phase6/test_p6_0_gate.py -q && uv run python ops/install/verify_clean_system.py --synthetic --target-receipt var/evidence/phase6/clean-install-synthetic.json && uv run ruff check ops/install ops/network scripts/phase6/verify_default_absence.py tests/integration/install tests/security/phase6 tests/acceptance/phase6 && uv run mypy ops/install ops/network`
Expected: PASS; P6-0 synthetic receipt says `remote=absent`, no public/Phase 6 listener, and no forbidden implementation or route.

- [ ] **Step 5: Commit clean install and absence gates**

~~~bash
git add ops/install/install.py ops/install/verify_clean_system.py ops/network/exposure-manifest.v1.yaml ops/network/verify_listeners.py ops/network/verify_routes.py ops/network/verify_router_mappings.py scripts/phase6/verify_default_absence.py tests/integration/install/test_phase6_clean_install.py tests/security/phase6/test_default_network_absence.py tests/security/phase6/test_forbidden_remote_implementations_absent.py tests/acceptance/phase6/test_p6_0_gate.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(install): keep Phase 6 remote routes absent by default"
~~~

## Wave 1 — P6-1 Tailscale-Only Read-Only Remote Pilot

### Task 07: Implement the provider-neutral port and sole Tailscale adapter

**Depends on:** P6-0 and Tasks 01–06.
**Gate contribution:** P6-1 adapter boundary.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `integrations/remote-access/src/tuntun_remote_access/__init__.py`
- Create: `integrations/remote-access/src/tuntun_remote_access/tailscale.py`
- Create: `integrations/remote-access/src/tuntun_remote_access/client_state.py`
- Create: `integrations/remote-access/src/tuntun_remote_access/posture.py`
- Create: `integrations/remote-access/src/tuntun_remote_access/sanitized_errors.py`
- Test: `integrations/remote-access/tests/unit/test_tailscale_state.py`
- Test: `integrations/remote-access/tests/contract/test_remote_access_port.py`
- Test: `tests/security/phase6/test_tailscale_is_sole_adapter.py`
- Test: `tests/privacy/phase6/test_remote_adapter_minimization.py`

**Interfaces:** Implements provider-neutral `RemoteAccessPort.probe() -> RemoteAdapterPostureV1`, `close_route(reason) -> RemoteRouteReceiptV1`, and `revoke_node(local_pseudonym) -> NodeRevocationReceiptV1` with the official local Tailscale client. Core sees random HMAC-derived local pseudonyms, posture/generations and commitments only.

**Rollback/disabled exit:** Missing/unknown/stale/malformed client state yields `not_configured` or `unavailable`; adapter remains unregistered and no second provider is attempted.

- [ ] **Step 1: Write red conformance, sole-adapter, and minimization tests**

~~~python
async def test_tailscale_adapter_conforms_without_exporting_vendor_identity(fake_tailscale) -> None:
    posture = await TailscaleRemoteAccessAdapter(fake_tailscale).probe()
    assert posture.adapter_class == "tailscale"
    assert posture.node_pseudonym.startswith("rnode_")
    assert not hasattr(posture, "node_name")
    assert not hasattr(posture, "user_email")
    assert not hasattr(posture, "ip_address")

def test_release_has_exactly_one_remote_adapter(adapter_registry) -> None:
    assert adapter_registry.implementation_ids("RemoteAccessPort") == ("tailscale.v1",)
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest integrations/remote-access/tests tests/security/phase6/test_tailscale_is_sole_adapter.py tests/privacy/phase6/test_remote_adapter_minimization.py -q`
Expected: FAIL because the integration package and adapter registration are absent.

- [ ] **Step 3: Implement strict local-client parsing and safe posture projection**

~~~python
class TailscaleRemoteAccessAdapter(RemoteAccessPort):
    async def probe(self) -> RemoteAdapterPostureV1:
        raw = await self._client.status_json(timeout=timedelta(seconds=2), max_bytes=256 * 1024)
        parsed = project_bounded_tailscale_state(reject_duplicate_json_keys(raw), TailscaleClientStateV1)
        now = self._clock.now()
        return RemoteAdapterPostureV1(
            adapter_id=self._adapter_id,
            adapter_class="tailscale",
            node_pseudonym=self._pseudonyms.for_node_key(parsed.self_node.public_key),
            device_approval_generation=self._approval_generation(parsed),
            tailnet_lock_state=self._closed_lock_state(parsed),
            route_flags=self._closed_route_flags(parsed),
            client_version_commitment=hmac_commit(parsed.client_version),
            observed_at=now,
            valid_until=now + timedelta(seconds=30),
        )
~~~

Invoke the official client without a shell, fixed absolute executable digest, bounded output, empty nonessential environment, timeout, and sanitized errors. Reject unexpected JSON, advertised routes, exit-node use, Funnel/public Serve, SSH, unapproved peer/path state, or version below the locally approved minimum. The adapter has no SQLCipher/Keychain/provider/camera/HA credential.

- [ ] **Step 4: Run green, import-boundary, and forbidden-adapter scans**

Run: `uv run pytest integrations/remote-access/tests tests/security/phase6/test_tailscale_is_sole_adapter.py tests/privacy/phase6/test_remote_adapter_minimization.py -q && uv run python scripts/check_import_boundaries.py --domain remote-access && uv run python scripts/phase6/verify_default_absence.py --allow-source-adapter tailscale.v1 && uv run ruff check integrations/remote-access tests/security/phase6 tests/privacy/phase6 && uv run mypy integrations/remote-access/src`
Expected: PASS; registry reports only `tailscale.v1`, and no provider identity/address reaches core DTOs/logs.

- [ ] **Step 5: Commit the adapter**

~~~bash
git add integrations/remote-access tests/security/phase6/test_tailscale_is_sole_adapter.py tests/privacy/phase6/test_remote_adapter_minimization.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(remote): add the sole Tailscale adapter"
~~~

### Task 08: Enforce exact-interface exposure and fail-closed drift suspension

**Depends on:** Task 07 and accepted host firewall/local CA services.
**Gate contribution:** P6-1 network boundary; T15.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/services/hardening/exposure_guard.py`
- Create: `ops/network/verify_lateral_reachability.py`
- Create: `ops/network/verify_external_exposure.py`
- Create: `ops/launchd/com.tuntun.exposure-guard.plist`
- Modify: `ops/network/exposure-manifest.v1.yaml`
- Test: `apps/core/tests/unit/hardening/test_exposure_guard.py`
- Test: `tests/security/phase6/test_interface_bind_policy.py`
- Test: `tests/fault/phase6/test_exposure_drift_suspends.py`
- Test: `tests/integration/phase6/test_local_independence_on_remote_close.py`

**Interfaces:** Produces `ExposureGuard.evaluate(posture, listeners, routes, firewall) -> ExposureDecision` and atomic `suspend_route_and_revoke_sessions`. Only an explicitly commissioned Tailscale interface/address may serve port 8443; the owner API remains loopback behind the same application policy.

**Rollback/disabled exit:** Any missing/stale/unclassified interface, firewall difference, unexpected listener/route/mapping, or scan uncertainty closes the 8443 listener and sessions before alerting locally; local/LAN services remain intact.

- [ ] **Step 1: Write red wildcard, lateral, drift, and local-independence tests**

~~~python
@pytest.mark.parametrize("bind", ["0.0.0.0", "::", "192.0.2.44", "unclassified0"])
def test_exposure_guard_rejects_noncommissioned_bind(guard, healthy_posture, bind) -> None:
    assert guard.evaluate(healthy_posture, listeners=[listener(bind, 8443)]).decision == "suspend"

async def test_firewall_drift_revokes_remote_before_alert(harness) -> None:
    await harness.inject_firewall_drift()
    assert harness.timeline.index("remote_sessions_revoked") < harness.timeline.index("local_alert_rendered")
    assert harness.local_voice.healthy and harness.local_home.healthy

def test_remote_node_cannot_reach_inner_targets(network_rig) -> None:
    assert network_rig.remote_reachable == {"https://tuntun.home.arpa:8443"}
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/core/tests/unit/hardening/test_exposure_guard.py tests/security/phase6/test_interface_bind_policy.py tests/fault/phase6/test_exposure_drift_suspends.py tests/integration/phase6/test_local_independence_on_remote_close.py -q`
Expected: FAIL because exposure evaluation and drift suspension are missing.

- [ ] **Step 3: Implement exact allowlist evaluation and atomic close path**

~~~python
def evaluate(self, snapshot: ExposureSnapshot) -> ExposureDecision:
    expected = Listener(snapshot.commissioned_tailscale_address, 8443, "owner_vpn_console_v1")
    forbidden = snapshot.listeners - snapshot.accepted_local_listeners - {expected}
    if forbidden or snapshot.router_mappings or snapshot.public_routes:
        return ExposureDecision.suspend("unexpected_exposure")
    if not snapshot.firewall.permits_only(expected, snapshot.approved_node_class):
        return ExposureDecision.suspend("firewall_drift")
    if snapshot.tailscale_flags.any_of("funnel", "public_serve", "subnet", "exit_node", "ssh"):
        return ExposureDecision.suspend("forbidden_tailscale_route")
    return ExposureDecision.healthy(valid_for=timedelta(seconds=30))
~~~

Run the guard at commissioning, every 30 seconds, and on listener/route/firewall/client events. Circuit-break repeated scan crashes, mark posture unknown, suspend, and show a mandatory local alert. The guard never edits router mappings or enables a replacement transport.

- [ ] **Step 4: Run green, synthetic drift campaign, and launchd lint**

Run: `uv run pytest apps/core/tests/unit/hardening/test_exposure_guard.py tests/security/phase6/test_interface_bind_policy.py tests/fault/phase6/test_exposure_drift_suspends.py tests/integration/phase6/test_local_independence_on_remote_close.py -q && uv run python ops/network/verify_lateral_reachability.py --synthetic --output var/evidence/phase6/lateral-synthetic.json && plutil -lint ops/launchd/com.tuntun.exposure-guard.plist && uv run ruff check apps/core/src/tuntun_core/services/hardening/exposure_guard.py ops/network tests/security/phase6 tests/fault/phase6 && uv run mypy apps/core/src`
Expected: PASS; every drift closes remote state and the synthetic remote node reaches only the console origin.

- [ ] **Step 5: Commit exposure enforcement**

~~~bash
git add apps/core/src/tuntun_core/services/hardening/exposure_guard.py ops/network ops/launchd/com.tuntun.exposure-guard.plist apps/core/tests/unit/hardening/test_exposure_guard.py tests/security/phase6/test_interface_bind_policy.py tests/fault/phase6/test_exposure_drift_suspends.py tests/integration/phase6/test_local_independence_on_remote_close.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(remote): suspend on exposure drift"
~~~

### Task 09: Build the local owner Tailscale commissioning ceremony

**Depends on:** Tasks 07–08 and a real-owner gate only for physical acceptance.
**Gate contribution:** P6-1 commissioning.
**Estimated effort:** 1.5 person-days plus owner ceremony.

**Files:**
- Create: `apps/core/src/tuntun_core/services/hardening/remote_commissioning.py`
- Create: `ops/remote-access/tailscale-acl.template.hujson`
- Create: `ops/remote-access/commission.py`
- Create: `ops/remote-access/disable.py`
- Create: `ops/remote-access/verify_posture.py`
- Create: `docs/operations/phase6-remote-access.md`
- Test: `apps/core/tests/unit/hardening/test_remote_commissioning.py`
- Test: `tests/security/phase6/test_commissioning_local_owner_only.py`
- Test: `tests/contract/hardening/test_tailscale_acl_template.py`
- Test: `tests/acceptance/phase6/test_remote_commissioning_receipt.py`

**Interfaces:** Produces a prepared local-owner ceremony and `RemoteCommissioningReceiptV1` binding exact adapter/client/ACL/Tailnet Lock/device-approval/split-DNS/local-CA/firewall/origin/recovery/revocation evidence. It transitions only `DISABLED → COMMISSIONING → READ_ONLY`.

**Rollback/disabled exit:** Failure calls `disable.py`, closes the 8443 route, revokes application sessions/generations, leaves Tailscale account cleanup instructions, and returns canonical state to `DISABLED`.

- [ ] **Step 1: Write red local-presence, ACL, lock, recovery, and state tests**

~~~python
def test_remote_commissioning_requires_local_owner_action_bound_passkey(service, remote_request) -> None:
    with pytest.raises(AssuranceInsufficient):
        service.prepare(remote_request)

def test_acl_template_has_one_destination_and_no_wildcards(acl_template) -> None:
    assert acl_template.destinations == ("tag:tuntun-core:8443",)
    assert not acl_template.has_wildcard_destination
    assert acl_template.advertised_routes == ()

def test_household_state_is_hidden_during_commissioning(harness) -> None:
    harness.route_state = "commissioning"
    assert harness.remote_get("/api/v1/ui/posture").status_code == 503
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/core/tests/unit/hardening/test_remote_commissioning.py tests/security/phase6/test_commissioning_local_owner_only.py tests/contract/hardening/test_tailscale_acl_template.py tests/acceptance/phase6/test_remote_commissioning_receipt.py -q`
Expected: FAIL because the commissioning state machine, template, and receipt are absent.

- [ ] **Step 3: Implement the complete evidence-bound local ceremony**

~~~python
async def complete(self, prepared_id: UUID, passkey: PasskeyResult, evidence: CommissionEvidence) -> Receipt:
    prepared = await self._prepared.consume_local_owner(prepared_id, passkey, local_presence=True)
    require(evidence.device_approval_enabled)
    require(evidence.tailnet_lock_enabled and evidence.recovery_signers_independent)
    require(evidence.acl_destinations == ("tuntun.home.arpa:8443",))
    require(not evidence.forbidden_route_flags)
    require(evidence.local_ca_origin == "https://tuntun.home.arpa:8443")
    require(evidence.revoke_drill_passed and evidence.local_independence_passed)
    return await self._routes.promote_read_only(prepared, evidence.safe_commitments())
~~~

The tool never creates a router mapping, public DNS, subnet/exit route, Funnel, SSH, or public Serve. It records current Tailscale terms/pricing review, independent recovery/signing-node procedure, lost-device revoke, exact owner devices by pseudonym, cert lifecycle, and disabled exit. During commissioning only a synthetic test endpoint is allowed; no household projection is returned.

- [ ] **Step 4: Run green and synthetic commissioning/disable round-trip**

Run: `uv run pytest apps/core/tests/unit/hardening/test_remote_commissioning.py tests/security/phase6/test_commissioning_local_owner_only.py tests/contract/hardening/test_tailscale_acl_template.py tests/acceptance/phase6/test_remote_commissioning_receipt.py -q && uv run python ops/remote-access/commission.py --synthetic --output var/evidence/phase6/commission-synthetic.json && uv run python ops/remote-access/disable.py --synthetic --assert-no-route && uv run ruff check apps/core/src/tuntun_core/services/hardening/remote_commissioning.py ops/remote-access tests/security/phase6 tests/acceptance/phase6 && uv run mypy apps/core/src ops/remote-access`
Expected: PASS; synthetic state reaches read-only only after every proof, then disables with no route/session.

- [ ] **Step 5: Commit commissioning**

~~~bash
git add apps/core/src/tuntun_core/services/hardening/remote_commissioning.py ops/remote-access docs/operations/phase6-remote-access.md apps/core/tests/unit/hardening/test_remote_commissioning.py tests/security/phase6/test_commissioning_local_owner_only.py tests/contract/hardening/test_tailscale_acl_template.py tests/acceptance/phase6/test_remote_commissioning_receipt.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(remote): commission read-only Tailscale access"
~~~

### Task 10: Enforce independent passkey-authenticated remote application sessions

**Depends on:** Task 09 and existing Phase 1 passkey/session service.
**Gate contribution:** P6-1 authentication; T13–T15.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/services/hardening/remote_sessions.py`
- Create: `apps/core/src/tuntun_core/api/routes/remote_access.py`
- Modify: `apps/core/src/tuntun_core/services/auth/sessions.py`
- Modify: `apps/core/src/tuntun_core/api/middleware/origin.py`
- Create: `apps/core/tests/unit/hardening/test_remote_sessions.py`
- Create: `apps/core/tests/integration/hardening/test_remote_session_api.py`
- Create: `tests/security/phase6/test_remote_auth_matrix.py`
- Create: `tests/property/phase6/test_remote_nonce_replay.py`

**Interfaces:** Produces `RemoteSessionService.establish(vpn_posture, passkey, request_context) -> RemoteSessionV1`, `require(operation_class, fresh_within)`, revoke, idle/absolute expiry, and the same-origin remote authentication endpoints. VPN username never enters application identity.

**Rollback/disabled exit:** Any VPN/app/origin/nonce/rate/generation uncertainty returns no private state, revokes the attempted session where appropriate, and cannot fall back to password, biometric-only, LAN cookie, or VPN identity.

- [ ] **Step 1: Write red two-factor-boundary, origin, expiry, and replay tests**

~~~python
@pytest.mark.parametrize("vpn_ok,passkey_ok", [(True, False), (False, True), (False, False)])
async def test_both_vpn_and_app_passkey_are_required(client, vpn_ok, passkey_ok) -> None:
    response = await client.establish_remote(vpn_ok=vpn_ok, passkey_ok=passkey_ok)
    assert response.status_code in {401, 403, 503}
    assert response.private_body is None

def test_remote_session_expires_at_first_idle_or_absolute(fake_clock, session_service) -> None:
    session = session_service.establish_synthetic()
    fake_clock.advance(minutes=15, microseconds=1)
    assert session_service.lookup(session.session_id) is None

def test_node_name_email_and_ip_never_reach_audit(remote_audit_row) -> None:
    assert set(remote_audit_row).isdisjoint({"node_name", "email", "ip", "request_body"})

async def test_operation_class_change_revokes_old_session_and_requires_reissue(harness) -> None:
    old = await harness.establish_remote()
    assert old.allowed_operation_classes == ("read_only_status",)
    await harness.local_owner_enable_exact_class("remote_media_stop_v1")
    assert await harness.require(old, "media_stop") == "session_revoked"
    new = await harness.establish_remote()
    assert new.operation_class_generation > old.operation_class_generation
    assert set(new.allowed_operation_classes) == {"read_only_status", "media_stop"}
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/core/tests/unit/hardening/test_remote_sessions.py apps/core/tests/integration/hardening/test_remote_session_api.py tests/security/phase6/test_remote_auth_matrix.py tests/property/phase6/test_remote_nonce_replay.py -q`
Expected: FAIL because remote session establishment and middleware rules are absent.

- [ ] **Step 3: Implement exact layered establishment and current-generation checks**

~~~python
async def establish(self, posture, passkey, request) -> RemoteSessionV1:
    self._routes.require_state("read_only", "scoped_actions")
    self._posture.require_current_approved_node(posture)
    self._origin.require_exact(request, host="tuntun.home.arpa:8443", scheme="https")
    self._csrf.consume_bound_nonce(request.csrf, request.nonce)
    owner = await self._passkeys.require_owner_phishing_resistant(passkey)
    now = self._clock.now()
    enabled = await self._operation_classes.current_exact_for_owner(
        owner.subject_id,
        route_state=self._routes.current_state(),
    )
    return await self._repository.create(RemoteSessionV1(
        session_id=uuid4(), actor_subject_id=owner.subject_id,
        vpn_adapter_id=posture.adapter_id, vpn_node_pseudonym=posture.node_pseudonym,
        device_approval_generation=posture.device_approval_generation,
        application_passkey_assurance="phishing_resistant", established_at=now,
        last_reauthenticated_at=now, idle_expires_at=now + timedelta(minutes=15),
        absolute_expires_at=now + timedelta(hours=8),
        allowed_operation_classes=tuple(sorted({"read_only_status", *enabled.operation_class_ids})),
        operation_class_generation=enabled.generation,
        policy_version=self._policy.version, revocation_generation=self._revocations.current,
    ))
~~~

Apply per-node/session/IP-free pseudonymous rate limits, exact content type/size, Host/Origin/CORS/CSRF, cookie `Secure`/`HttpOnly`/`SameSite=Strict`, no bearer in URL/storage, concurrent revoke locking, and five-minute fresh-passkey checks. `require(...)` compares the session's exact operation-class generation and membership to the current locally enabled registry on every use. Enabling, disabling, or changing any class increments that generation and transactionally revokes every earlier remote session; only a fresh passkey-authenticated reissue can receive the new closed class set. Return stable safe errors and `no-store` on protected responses.

- [ ] **Step 4: Run green plus complete auth/fuzz suite**

Run: `uv run pytest apps/core/tests/unit/hardening/test_remote_sessions.py apps/core/tests/integration/hardening/test_remote_session_api.py tests/security/phase6/test_remote_auth_matrix.py tests/property/phase6/test_remote_nonce_replay.py -q && uv run pytest tests/security/auth tests/property/auth -q && uv run ruff check apps/core/src/tuntun_core/services/hardening/remote_sessions.py apps/core/src/tuntun_core/api/routes/remote_access.py apps/core/src/tuntun_core/services/auth/sessions.py tests/security/phase6 tests/property/phase6 && uv run mypy apps/core/src`
Expected: PASS; VPN-only and app-only cases reveal zero state, and replay/expiry/revocation deny deterministically.

- [ ] **Step 5: Commit remote sessions**

~~~bash
git add apps/core/src/tuntun_core/services/hardening/remote_sessions.py apps/core/src/tuntun_core/api/routes/remote_access.py apps/core/src/tuntun_core/services/auth/sessions.py apps/core/src/tuntun_core/api/middleware/origin.py apps/core/tests/unit/hardening/test_remote_sessions.py apps/core/tests/integration/hardening/test_remote_session_api.py tests/security/phase6/test_remote_auth_matrix.py tests/property/phase6/test_remote_nonce_replay.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(auth): require app passkeys after VPN admission"
~~~

### Task 11: Implement the closed remote operation matrix and local-only denial wall

**Depends on:** Task 10 and accepted Phase 1–5 risk/action registries.
**Gate contribution:** P6-1/P6-2 policy boundary.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/services/hardening/remote_policy.py`
- Modify: `packages/policy/src/tuntun_policy/evaluator.py`
- Create: `fixtures/adversarial/phase6/remote-operation-matrix-v1.jsonl`
- Test: `apps/core/tests/unit/hardening/test_remote_policy.py`
- Test: `tests/policy/test_remote_operation_matrix.py`
- Test: `tests/security/phase6/test_remote_local_only_denials.py`
- Test: `tests/property/phase6/test_remote_never_upgrades_authority.py`

**Interfaces:** Produces `RemotePolicy.decide(RemoteOperationRequestV1) -> RemoteOperationDecisionV1`. The matrix has closed classes for allowed read-only projections, separately disabled optional scopes, and permanent Phase 6 remote denials.

**Rollback/disabled exit:** Unknown operation/class, stale assurance, locally denied operation, or missing explicit local enablement returns `REMOTE_OPERATION_DENIED`; no generic action, route substitution, or ordinary-local default exists.

- [ ] **Step 1: Write red exhaustive matrix and monotonic-authority tests**

~~~python
PERMANENT_REMOTE_DENIALS = {
    "export", "download", "identity_enroll", "biometric_calibrate", "profile_delete",
    "guardian_change", "base_policy_change", "provider_change", "hard_cap_change",
    "bind_mode_change", "plugin_permission_change", "recovery_key_display",
    "recovery_key_import", "restore", "bulk_delete", "audit_key_rotate",
    "developer_mode", "release_approve", "release_sign", "desktop_execute",
    "robot_drive", "robot_video", "remote_shell", "microphone_activate", "camera_activate",
}

@pytest.mark.parametrize("operation", sorted(PERMANENT_REMOTE_DENIALS))
def test_permanent_denial_has_no_prepare_or_execute_route(remote_policy, operation) -> None:
    assert remote_policy.decide(request(operation)).code == "REMOTE_OPERATION_DENIED"
    assert not remote_policy.can_prepare(operation)

def test_remote_allowed_set_is_subset_of_local_allowed_set(property_requests, policy) -> None:
    for request in property_requests:
        if policy.remote(request).allowed:
            assert policy.local(request).allowed
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/core/tests/unit/hardening/test_remote_policy.py tests/policy/test_remote_operation_matrix.py tests/security/phase6/test_remote_local_only_denials.py tests/property/phase6/test_remote_never_upgrades_authority.py -q`
Expected: FAIL because the closed remote policy is absent.

- [ ] **Step 3: Implement explicit decisions and deny every unknown/local-only request**

~~~python
def decide(self, request: RemoteOperationRequestV1) -> RemoteOperationDecisionV1:
    if request.operation in PERMANENT_REMOTE_DENIALS:
        return deny("REMOTE_OPERATION_DENIED")
    rule = self._registry.lookup_exact(request.operation)
    if rule is None or not rule.remote_capability_id:
        return deny("REMOTE_OPERATION_DENIED")
    if not self._local_policy.decide(request.as_local()).allowed:
        return deny("POLICY_DENIED")
    if not self._features.is_current_enabled(rule.remote_capability_id):
        return deny("FEATURE_ABSENT")
    return rule.evaluate_remote(request, assurance_reduction="remote_origin_v1")
~~~

Read-only initially allows health/phase/device availability/content-minimized alerts/cost and approval metadata. Exact bodies require five-minute passkey plus local class enablement. Optional actions/media classes stay absent until Tasks 16–18. Test direct API, prepared issuance, config, replay, alternate content type, batch, client bundle, and underlying service calls.

- [ ] **Step 4: Run green and the full actor/resource policy matrix**

Run: `uv run pytest apps/core/tests/unit/hardening/test_remote_policy.py tests/policy/test_remote_operation_matrix.py tests/security/phase6/test_remote_local_only_denials.py tests/property/phase6/test_remote_never_upgrades_authority.py -q && uv run pytest tests/policy/test_actor_resource_matrix.py -q && uv run ruff check apps/core/src/tuntun_core/services/hardening/remote_policy.py packages/policy/src/tuntun_policy/evaluator.py tests/policy tests/security/phase6 tests/property/phase6 && uv run mypy apps/core/src packages/policy/src`
Expected: PASS; every permanent/unknown operation is denied and remote allow is a strict subset of local allow.

- [ ] **Step 5: Commit remote policy**

~~~bash
git add apps/core/src/tuntun_core/services/hardening/remote_policy.py packages/policy/src/tuntun_policy/evaluator.py fixtures/adversarial/phase6/remote-operation-matrix-v1.jsonl apps/core/tests/unit/hardening/test_remote_policy.py tests/policy/test_remote_operation_matrix.py tests/security/phase6/test_remote_local_only_denials.py tests/property/phase6/test_remote_never_upgrades_authority.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(policy): close the remote operation matrix"
~~~

### Task 12: Deliver the constrained read-only remote API and responsive owner UI

**Depends on:** Tasks 09–11 and accepted owner-safe UI projections.
**Gate contribution:** P6-1 user path.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/api/phase6_dtos.py`
- Modify: `apps/core/src/tuntun_core/api/routes/remote_access.py`
- Create: `apps/admin/src/features/system/remote-access.tsx`
- Create: `apps/admin/src/features/system/remote-sessions.tsx`
- Create: `apps/admin/src/routes/system-remote-access.tsx`
- Test: `apps/core/tests/integration/hardening/test_remote_read_only_api.py`
- Test: `apps/admin/src/features/system/remote-access.test.tsx`
- Test: `tests/ui/phase6/remote-read-only.spec.ts`
- Test: `tests/ui/phase6/remote-accessibility.spec.ts`

**Interfaces:** Produces owner-safe route/session/posture/health/alert/cost/approval-metadata read models, signed feature registration, and route-origin label `approved VPN`. It uses the same console, never a public/mobile-native/PWA application.

**Rollback/disabled exit:** Missing/stale API/route/posture evidence clears protected UI and shows suspended/unavailable locally; no cached green state, service worker, persistent private storage, or background notification remains.

- [ ] **Step 1: Write red feature, body-concealment, no-store, and accessibility tests**

~~~typescript
test("remote read-only shows safe metadata and hides approval bodies", async ({page}) => {
  await openApprovedVpnConsole(page);
  await expect(page.getByText("Approved VPN")).toBeVisible();
  await expect(page.getByTestId("approval-metadata-count")).toHaveText("2");
  await expect(page.getByTestId("approval-body")).toHaveCount(0);
  expect(await browserPersistentPrivateKeys(page)).toEqual([]);
});

test("direct local-only route is denied without leaking existence", async ({request}) => {
  const response = await request.get("/api/v1/recovery/key");
  expect(response.status()).toBe(403);
  expect(await response.json()).toMatchObject({code: "REMOTE_OPERATION_DENIED"});
});
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/core/tests/integration/hardening/test_remote_read_only_api.py -q && pnpm --dir apps/admin test -- remote-access.test.tsx && pnpm --dir apps/admin exec playwright test tests/ui/phase6/remote-read-only.spec.ts tests/ui/phase6/remote-accessibility.spec.ts`
Expected: FAIL because the read-only route models/UI are absent.

- [ ] **Step 3: Implement bounded projections and truthful route/session UI**

~~~typescript
import type {RemoteAccessReadModelV1} from "@tuntun/ui-contracts/hardening/v1";

export function RemoteAccessPage({model}: {model: RemoteAccessReadModelV1}) {
  return <SystemPage title={msg("remote.title")}>
    <PlaneFactCard fact={model.routeFact} />
    <DefinitionList rows={safeRouteRows(model)} />
    <RemoteSessionTable sessions={model.sessions} />
    <LocalOnlyBoundary operations={model.localOnlyOperationMessageIds} />
    {model.disableAction && <DisableRemotePreparedAction action={model.disableAction} />}
  </SystemPage>;
}
~~~

Render provider, exposed origin, pseudonymous approved nodes, allowed operation classes, last access, idle/absolute expiry, assurance age, route/posture evidence and local disable path. Safe alert/health/cost projections reuse server-filtered DTOs. Sensitive bodies are reveal-on-demand only where policy allows. Add English/Hindi strings, keyboard flow, VoiceOver labels/live states, light/dark/high-contrast/reduced-motion, 320 px and 200% zoom. No analytics/service worker/localStorage/sessionStorage/IndexedDB/private Cache API.

- [ ] **Step 4: Run green, OpenAPI/client drift, UI, axe, and build checks**

Run: `uv run pytest apps/core/tests/integration/hardening/test_remote_read_only_api.py -q && uv run python scripts/generate_openapi.py --check && pnpm --dir apps/admin test -- remote-access.test.tsx && pnpm --dir apps/admin exec playwright test tests/ui/phase6/remote-read-only.spec.ts tests/ui/phase6/remote-accessibility.spec.ts && pnpm --dir apps/admin typecheck && pnpm --dir apps/admin build`
Expected: PASS; read-only safe data renders in English/Hindi at all fixtures, all local-only requests deny, and storage/cache scan is empty.

- [ ] **Step 5: Commit read-only API/UI**

~~~bash
git add apps/core/src/tuntun_core/api/phase6_dtos.py apps/core/src/tuntun_core/api/routes/remote_access.py apps/admin/src/features/system/remote-access.tsx apps/admin/src/features/system/remote-sessions.tsx apps/admin/src/routes/system-remote-access.tsx apps/core/tests/integration/hardening/test_remote_read_only_api.py apps/admin/src/features/system/remote-access.test.tsx tests/ui/phase6/remote-read-only.spec.ts tests/ui/phase6/remote-accessibility.spec.ts packages/ui-contracts schemas/openapi
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(ui): add constrained remote read-only console"
~~~

### Task 13: Prove theft, revocation, posture drift, IdP outage, and concurrent session closure

**Depends on:** Tasks 08–12.
**Gate contribution:** P6-1 T13–T15 resilience.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/services/hardening/remote_revocation.py`
- Create: `fixtures/synthetic/phase6/remote/theft-drill-v1.json`
- Test: `tests/security/phase6/test_lost_device_revocation.py`
- Test: `tests/security/phase6/test_remote_session_theft.py`
- Test: `tests/fault/phase6/test_remote_posture_failures.py`
- Test: `tests/property/phase6/test_concurrent_remote_revocation.py`
- Test: `tests/integration/phase6/test_privacy_remote_revocation.py`

**Interfaces:** Produces `RemoteRevocationService.suspend(reason, affected_node=None)`, generation rotation, session/media revocation fan-out, and content-safe theft/drift receipts. It consumes adapter/exposure/auth/privacy events.

**Rollback/disabled exit:** Any ambiguous node/session/route state suspends the whole remote route; re-enable never resumes an old session and requires local owner re-approval plus rotated affected credentials.

- [ ] **Step 1: Write red lost-device, replay, race, and outage tests**

~~~python
async def test_lost_device_revocation_closes_sessions_and_media(harness) -> None:
    session, media = await harness.open_remote_session_and_media()
    await harness.report_lost_device(session.vpn_node_pseudonym)
    assert await harness.use(session) == "revoked"
    assert await harness.use(media) == "revoked"
    assert harness.route.state == "suspended"

@pytest.mark.parametrize("fault", [
    "acl_drift", "tailnet_lock_failure", "stale_client", "certificate_failure",
    "firewall_drift", "idp_outage", "impossible_node_state", "credential_stuffing",
])
async def test_every_posture_fault_suspends(fault_harness, fault) -> None:
    await fault_harness.inject(fault)
    assert fault_harness.route.state == "suspended"

async def test_concurrent_authorize_and_revoke_never_executes(race_harness) -> None:
    result = await race_harness.race_authorize_with_revoke()
    assert result.external_effects == 0
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/security/phase6/test_lost_device_revocation.py tests/security/phase6/test_remote_session_theft.py tests/fault/phase6/test_remote_posture_failures.py tests/property/phase6/test_concurrent_remote_revocation.py tests/integration/phase6/test_privacy_remote_revocation.py -q`
Expected: FAIL because revocation orchestration and generation races are unimplemented.

- [ ] **Step 3: Implement transactional suspension and re-enable rotation rules**

~~~python
async def suspend(self, reason: SafeReasonCode, node: str | None = None) -> SuspensionReceipt:
    async with self._uow.authoritative() as tx:
        route = await tx.routes.require_active()
        receipt = await tx.routes.suspend_and_increment(route, reason)
        await tx.sessions.revoke_all(route.id, receipt.revocation_generation)
        await tx.media_sessions.revoke_by_origin("remote_origin_v1")
        await tx.prepared_actions.invalidate_by_origin("remote_origin_v1")
        await tx.audit.append_safe("remote.suspended", receipt.commitment())
    await self._adapter.close_route(reason)
    return receipt
~~~

Lost-device response also revokes the local node mapping, documents provider-side revoke, rotates application revocation generation and affected passkey/session material, then scans before a fresh local commissioning decision. IdP/control-plane outage closes new application admission and preserves local operation; it never falls back to LAN/public/direct WireGuard.

- [ ] **Step 4: Run green with 1,000 concurrent schedules and privacy fault tests**

Run: `uv run pytest tests/security/phase6/test_lost_device_revocation.py tests/security/phase6/test_remote_session_theft.py tests/fault/phase6/test_remote_posture_failures.py tests/property/phase6/test_concurrent_remote_revocation.py tests/integration/phase6/test_privacy_remote_revocation.py -q --hypothesis-seed=613 && uv run ruff check apps/core/src/tuntun_core/services/hardening/remote_revocation.py tests/security/phase6 tests/fault/phase6 tests/property/phase6 tests/integration/phase6 && uv run mypy apps/core/src`
Expected: PASS; zero schedule executes after the winning revoke/Privacy Shield commit and every posture fault suspends.

- [ ] **Step 5: Commit revocation hardening**

~~~bash
git add apps/core/src/tuntun_core/services/hardening/remote_revocation.py fixtures/synthetic/phase6/remote/theft-drill-v1.json tests/security/phase6/test_lost_device_revocation.py tests/security/phase6/test_remote_session_theft.py tests/fault/phase6/test_remote_posture_failures.py tests/property/phase6/test_concurrent_remote_revocation.py tests/integration/phase6/test_privacy_remote_revocation.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(remote): revoke stolen and drifted sessions"
~~~

### Task 14: Run the real least-route and no-public/no-lateral network qualification

**Depends on:** Tasks 07–13 and explicit owner network/Tailscale flags.
**Gate contribution:** P6-1 physical network gate; T14–T15.
**Estimated effort:** 1 person-day plus controlled scans.

**Files:**
- Modify: `ops/network/verify_lateral_reachability.py`
- Modify: `ops/network/verify_external_exposure.py`
- Create: `docs/evidence/phase6-network-schema.json`
- Create: `tests/acceptance/phase6/test_network_receipt.py`
- Create: `tests/hardware/phase6/test_tailscale_least_route.py`
- Create: `tests/hardware/phase6/test_external_exposure.py`

**Interfaces:** Produces a content-safe `P6NetworkQualificationReceipt` from the approved remote node, BE800 outer side, ASUS inner side, and an independent internet vantage. Exact addresses/hostnames are HMAC-committed outside Git.

**Rollback/disabled exit:** Any reachable non-console target, uncertain external scan, route flag, public listener/mapping, or identifier leak disables the remote adapter and blocks P6-1.

- [ ] **Step 1: Write red receipt-oracle and target-closure tests**

~~~python
def test_network_receipt_proves_only_console_origin(receipt) -> None:
    assert receipt.remote_success_classes == ("tuntun_console_8443",)
    assert set(receipt.remote_denied_classes) >= {
        "home_assistant", "camera", "reachy", "mzhub", "television", "router_admin",
        "smb", "ssh", "plugin", "inner_client",
    }
    assert receipt.internet_success_classes == ()
    assert receipt.forbidden_tailscale_flags == ()

def test_network_receipt_contains_no_real_address(receipt_json) -> None:
    assert scan_network_identifiers(receipt_json).findings == ()
~~~

- [ ] **Step 2: Run red/collection-only**

Run: `uv run pytest tests/acceptance/phase6/test_network_receipt.py -q && uv run pytest tests/hardware/phase6/test_tailscale_least_route.py tests/hardware/phase6/test_external_exposure.py --collect-only -q`
Expected: acceptance test FAIL because no receipt schema/oracle exists; hardware tests collect and skip without explicit flags.

- [ ] **Step 3: Implement bounded scan plan and signed result verifier**

~~~python
REQUIRED_DENIAL_CLASSES = frozenset({
    "home_assistant", "camera", "reachy", "mzhub", "television", "router_admin",
    "smb", "ssh", "plugin", "inner_client",
})

def verify_network_receipt(receipt: P6NetworkQualificationReceipt) -> None:
    require(receipt.remote_success_classes == ("tuntun_console_8443",))
    require(REQUIRED_DENIAL_CLASSES <= set(receipt.remote_denied_classes))
    require(not receipt.internet_success_classes)
    require(not receipt.outer_or_inner_unexpected_success)
    require(not receipt.router_mappings and not receipt.forbidden_tailscale_flags)
~~~

The operator runs explicit bounded TCP/UDP/HTTP probes from all four vantage classes, captures only target-class outcomes and commitments, reviews router mappings/UPnP/NAT-PMP/PCP, firewall/listeners/routes, Tailscale ACL/device approval/Tailnet Lock/Serve/Funnel/subnet/exit/SSH state, DNS/certificate origin and disable behavior. PCAPs remain owner-local and are scanned before deletion.

- [ ] **Step 4: Run synthetic green and document the gated real commands**

Run: `uv run pytest tests/acceptance/phase6/test_network_receipt.py -q && uv run python ops/network/verify_lateral_reachability.py --synthetic --output var/evidence/phase6/network-synthetic.json && uv run python ops/network/verify_external_exposure.py --synthetic --output var/evidence/phase6/external-synthetic.json && uv run python scripts/scan_private_data.py --paths var/evidence/phase6/network-synthetic.json var/evidence/phase6/external-synthetic.json && uv run ruff check ops/network tests/acceptance/phase6 tests/hardware/phase6`
Expected: PASS; synthetic receipt contains one remote success class and all required denials. Real promotion additionally requires the two owner-gated commands from Standard Commands and independent-vantage receipt.

- [ ] **Step 5: Commit network qualification tooling**

~~~bash
git add ops/network/verify_lateral_reachability.py ops/network/verify_external_exposure.py docs/evidence/phase6-network-schema.json tests/acceptance/phase6/test_network_receipt.py tests/hardware/phase6/test_tailscale_least_route.py tests/hardware/phase6/test_external_exposure.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(remote): qualify the exact least route"
~~~

### Task 15: Complete the seven-day read-only remote soak and P6-1 go/no-go

**Depends on:** Tasks 07–14 and accepted real commissioning/network receipts.
**Gate contribution:** completes P6-1.
**Estimated effort:** 1 person-day plus seven elapsed representative days.

**Files:**
- Create: `scripts/phase6/run_remote_pilot.py`
- Create: `docs/evidence/phase6-remote-pilot-schema.json`
- Create: `tests/acceptance/phase6/test_remote_pilot_oracle.py`
- Create: `tests/acceptance/phase6/test_p6_1_gate.py`
- Create: `tests/fault/phase6/test_remote_pilot_faults.py`

**Interfaces:** Produces `P6RemotePilotReceipt` bound to clean build/config/route/auth/network evidence, seven actual elapsed days, read-only requests, local availability, revoke/drift/failure injections, latency/resource/maintenance and privacy truth.

**Rollback/disabled exit:** A failed pilot disables or suspends remote access; it never shortens the soak, enables actions, or weakens route/auth controls. Earlier local phases continue.

- [ ] **Step 1: Write red elapsed-time, zero-mutation, failure, and local-independence tests**

~~~python
def test_remote_pilot_requires_actual_seven_days(receipt) -> None:
    assert receipt.monotonic_elapsed_seconds >= 604_800
    assert receipt.wall_elapsed_seconds >= 604_800
    assert receipt.clock_acceleration_used is False

def test_remote_pilot_has_zero_mutation_and_lateral_effect(pilot) -> None:
    assert pilot.remote_mutation_count == 0
    assert pilot.non_console_reachability_count == 0
    assert pilot.public_reachability_count == 0
    assert pilot.local_unavailability_caused_by_remote == 0

def test_fault_matrix_closes_remote_and_keeps_local(pilot) -> None:
    assert all(row.remote_closed for row in pilot.fault_rows)
    assert all(row.local_essentials_available for row in pilot.fault_rows)
~~~

- [ ] **Step 2: Run red and synthetic mode**

Run: `uv run pytest tests/acceptance/phase6/test_remote_pilot_oracle.py tests/acceptance/phase6/test_p6_1_gate.py tests/fault/phase6/test_remote_pilot_faults.py -q`
Expected: FAIL because the pilot runner/schema/oracle are absent.

- [ ] **Step 3: Implement resumable elapsed runner and immutable promotion oracle**

~~~python
def decide_p6_1(receipt: P6RemotePilotReceipt) -> GateDecision:
    require(receipt.monotonic_elapsed_seconds >= 604_800)
    require(receipt.wall_elapsed_seconds >= 604_800 and not receipt.clock_acceleration_used)
    require(receipt.remote_mutation_count == 0)
    require(receipt.non_console_reachability_count == 0 and receipt.public_reachability_count == 0)
    require(receipt.auth_bypass_count == 0 and receipt.replay_success_count == 0)
    require(receipt.every_required_fault_suspended and receipt.local_independence_passed)
    require(receipt.private_data_scan_findings == 0)
    return GateDecision.accept("P6-1", receipt.digest())
~~~

Sample route/posture/session/listener/firewall/certificate/Tailnet/client/resource health, safe read requests, logout/expiry/revocation, Mac/router/client restart, WAN/DNS/IdP outage, drift, Privacy Shield, audit/backup state, and owner work. Persist only content-safe checkpoints; restart cannot reset elapsed evidence or revive sessions.

- [ ] **Step 4: Run synthetic fault acceptance and stage the real command**

Run: `uv run python scripts/phase6/run_remote_pilot.py --synthetic --duration-seconds 604800 --output var/evidence/phase6/remote-pilot-synthetic.json && uv run pytest tests/acceptance/phase6/test_remote_pilot_oracle.py tests/acceptance/phase6/test_p6_1_gate.py tests/fault/phase6/test_remote_pilot_faults.py -q && uv run ruff check scripts/phase6/run_remote_pilot.py tests/acceptance/phase6 tests/fault/phase6`
Expected: PASS for the deterministic synthetic time/fault oracle. Household P6-1 remains blocked until `TUNTUN_ALLOW_ELAPSED_PHASE6=1 ... --duration-seconds 604800` records real monotonic and wall time.

- [ ] **Step 5: Commit pilot runner and gate**

~~~bash
git add scripts/phase6/run_remote_pilot.py docs/evidence/phase6-remote-pilot-schema.json tests/acceptance/phase6/test_remote_pilot_oracle.py tests/acceptance/phase6/test_p6_1_gate.py tests/fault/phase6/test_remote_pilot_faults.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(remote): gate the seven-day read-only pilot"
~~~

## Wave 2 — P6-2 Separately Gated Optional Remote Scopes

### Task 16: Gate exact private-detail read and reversible light or media-stop classes

**Depends on:** accepted P6-1, the Phase 1 owner-private memory/approval projections, and Phase 2/4 action registries for the selected class.
**Gate contribution:** optional P6-2 private-detail and scoped-action classes.
**Estimated effort:** 1.5 person-days.

**Files:**
- Modify: `apps/core/src/tuntun_core/services/hardening/remote_policy.py`
- Modify: `apps/core/src/tuntun_core/services/hardening/remote_sessions.py`
- Modify: `apps/core/src/tuntun_core/services/actions/coordinator.py`
- Create: `apps/core/src/tuntun_core/services/hardening/remote_private_detail.py`
- Create: `fixtures/synthetic/phase6/remote/scoped-actions-v1.json`
- Test: `tests/policy/test_remote_scoped_actions.py`
- Test: `tests/integration/phase6/test_remote_private_detail.py`
- Test: `tests/privacy/phase6/test_remote_private_detail_isolation.py`
- Test: `tests/integration/phase6/test_remote_reversible_action.py`
- Test: `tests/security/phase6/test_remote_action_substitution.py`
- Test: `tests/fault/phase6/test_remote_action_revocation_race.py`

**Interfaces:** Adds independently feature-bound `remote_private_detail_v1`, `remote_light_power_v1` and `remote_media_stop_v1` candidates. Private detail consumes the exact five-second `RemotePrivateDetailRequestV1`, a fresh five-minute passkey, current owner/subject/source/policy generations, and returns one no-store owner-private projection for at most 60 seconds; listing, search, export, child/other-adult content and cross-object substitution remain absent. The light path reuses the canonical Phase 2 `light.set_power.v1` contract with one exact `on: bool` desired state; it does not invent another light registry ID. Each action uses the existing server-prepared action, fresh five-minute passkey, exact confirmation, current binding/capability/policy/controller epoch, idempotency and truthful downstream result. Local class enable/disable increments the operation-class generation, revokes existing remote sessions, and affects only newly passkey-authenticated sessions.

**Rollback/disabled exit:** Each class stays absent until locally enabled after its own evidence. Failure removes only that class and invalidates prepared actions; read-only remains. No generic home/media operation is introduced.

- [ ] **Step 1: Write red exact-class, local-enable, substitution, and race tests**

~~~python
@pytest.mark.parametrize("operation", ["light.toggle", "scene.run", "media.play", "media.seek", "volume.set"])
async def test_remote_reversible_registry_rejects_nonexact_operation(harness, operation) -> None:
    assert (await harness.remote_prepare(operation)).code in {"FEATURE_ABSENT", "REMOTE_OPERATION_DENIED"}

async def test_remote_stop_uses_fresh_passkey_and_exact_confirmation(harness) -> None:
    prepared = await harness.prepare_remote("media.stop.v1", target="player_synth_01")
    assert (await harness.execute(prepared, assurance_age_seconds=301)).code == "ASSURANCE_INSUFFICIENT"
    result = await harness.confirm_and_execute(prepared, assurance_age_seconds=10)
    assert result.target_results[0].target_id == "player_synth_01"

async def test_remote_light_reuses_canonical_phase2_power_shape(harness) -> None:
    prepared = await harness.prepare_remote("light.set_power.v1", target="light_synth_01", desired_state={"on": False})
    assert prepared.local_action.action_type == "light.set_power.v1"
    assert (await harness.prepare_remote(
        "light.set_power.v1", target="light_synth_01", desired_state={"on": False, "brightness": 10},
    )).code == "PARAMETER_SHAPE_DENIED"

async def test_private_detail_requires_exact_class_fresh_passkey_and_owner_audience(harness) -> None:
    request = await harness.prepare_private_detail("owner_memory_synth_01")
    assert (await harness.read_private_detail(request, assurance_age_seconds=301)).code == "ASSURANCE_INSUFFICIENT"
    projection = await harness.read_private_detail(request, assurance_age_seconds=10)
    assert projection.audience == "owner_private"
    assert projection.expires_at - projection.issued_at <= timedelta(seconds=60)
    assert (await harness.substitute_private_detail_source(request, "child_memory_synth_01")).code == "RESOURCE_UNAVAILABLE"

async def test_revoke_wins_before_dispatch(race_harness) -> None:
    assert (await race_harness.revoke_during_remote_authorize()).external_dispatches == 0
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/policy/test_remote_scoped_actions.py tests/integration/phase6/test_remote_private_detail.py tests/privacy/phase6/test_remote_private_detail_isolation.py tests/integration/phase6/test_remote_reversible_action.py tests/security/phase6/test_remote_action_substitution.py tests/fault/phase6/test_remote_action_revocation_race.py -q`
Expected: FAIL because optional remote private-detail and action classes are absent.

- [ ] **Step 3: Implement explicit per-class registration through existing action authority**

~~~python
REMOTE_REVERSIBLE_RULES = {
    "light.set_power.v1": RemoteRule(
        feature="remote_light_power_v1", local_action="light.set_power.v1",
        require_fresh_passkey=timedelta(minutes=5), require_exact_confirmation=True,
    ),
    "media.stop.v1": RemoteRule(
        feature="remote_media_stop_v1", local_action="media.stop.v1",
        require_fresh_passkey=timedelta(minutes=5), require_exact_confirmation=True,
    ),
}

async def execute_remote(prepared, confirmation, context):
    await remote_policy.require_current_exact(prepared, confirmation, context)
    return await ordinary_action_coordinator.execute(prepared, confirmation, origin="remote_origin_v1")

async def read_private_detail(request: RemotePrivateDetailRequestV1, context) -> RemotePrivateDetailProjectionV1:
    await remote_policy.require_current_exact_class(context, "private_detail", fresh_passkey=timedelta(minutes=5))
    source = await private_detail_store.require_exact_owner_object(
        owner_subject_id=request.owner_subject_id,
        source_object_id=request.source_object_id,
        detail_class=request.detail_class,
        source_generation=request.expected_source_generation,
        policy_generation=request.expected_policy_generation,
        subject_generation=request.expected_subject_generation,
    )
    return RemotePrivateDetailProjectionV1.from_ephemeral_source(request, source, max_lifetime=timedelta(seconds=60))
~~~

Local enablement binds one operation class, exact eligible endpoint set, current policy/binding/capability generations, evidence digest and expiry with a local owner action-bound passkey. Remote cannot change that set. Test stale topology, child/Guest/time/room/privacy denial, replay, duplicate mismatch, unknown physical result, downstream outage and manual fallback.

- [ ] **Step 4: Run green and affected Phase 2/4 action suites**

Run: `uv run pytest tests/policy/test_remote_scoped_actions.py tests/integration/phase6/test_remote_private_detail.py tests/privacy/phase6/test_remote_private_detail_isolation.py tests/integration/phase6/test_remote_reversible_action.py tests/security/phase6/test_remote_action_substitution.py tests/fault/phase6/test_remote_action_revocation_race.py tests/integration/home_actions tests/integration/media_actions -q && uv run ruff check apps/core/src/tuntun_core/services/hardening/remote_policy.py apps/core/src/tuntun_core/services/hardening/remote_private_detail.py apps/core/src/tuntun_core/services/actions/coordinator.py tests/policy tests/integration/phase6 tests/privacy/phase6 tests/security/phase6 tests/fault/phase6 && uv run mypy apps/core/src`
Expected: PASS; private detail is one exact owner-only projection, only locally enabled exact action classes dispatch, and no remote request upgrades ordinary policy.

- [ ] **Step 5: Commit optional scoped actions**

~~~bash
git add apps/core/src/tuntun_core/services/hardening/remote_policy.py apps/core/src/tuntun_core/services/hardening/remote_sessions.py apps/core/src/tuntun_core/services/hardening/remote_private_detail.py apps/core/src/tuntun_core/services/actions/coordinator.py fixtures/synthetic/phase6/remote/scoped-actions-v1.json tests/policy/test_remote_scoped_actions.py tests/integration/phase6/test_remote_private_detail.py tests/privacy/phase6/test_remote_private_detail_isolation.py tests/integration/phase6/test_remote_reversible_action.py tests/security/phase6/test_remote_action_substitution.py tests/fault/phase6/test_remote_action_revocation_race.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(remote): gate exact private detail and action scopes"
~~~

### Task 17: Gate camera metadata and two-layer single-clip remote playback

**Depends on:** accepted P6-1, accepted Phase 3 event/playback services, and separately selected camera scopes.
**Gate contribution:** optional P6-2 camera classes.
**Estimated effort:** 1.5 person-days.

**Files:**
- Modify: `apps/core/src/tuntun_core/services/vision/playback_broker.py`
- Modify: `apps/core/src/tuntun_core/services/hardening/remote_policy.py`
- Modify: `apps/core/src/tuntun_core/services/hardening/remote_sessions.py`
- Create: `apps/core/src/tuntun_core/services/hardening/remote_media.py`
- Modify: `apps/core/src/tuntun_core/api/routes/cameras.py`
- Test: `apps/core/tests/unit/hardening/test_remote_media_session.py`
- Test: `tests/integration/phase6/test_remote_camera_metadata.py`
- Test: `tests/integration/phase6/test_remote_camera_playback.py`
- Test: `tests/security/phase6/test_remote_media_isolation.py`
- Test: `tests/fault/phase6/test_remote_media_revocation.py`

**Interfaces:** Adds separately registered `remote_camera_metadata_v1` and `remote_camera_playback_v1`; produces `RemoteSingleClipMediaSessionV1` for one owner/session/clip up to 10 minutes and delegates every exact byte/time range to a new single-use Phase 3 playback grant up to 60 seconds.

**Rollback/disabled exit:** Metadata/playback are absent independently. Any route/privacy/passkey/policy/clip/generation/retention/catalog/recorder uncertainty revokes both layers; export/download remains denied.

- [ ] **Step 1: Write red duration, range, enumeration, credential, cache, and revoke tests**

~~~python
def test_remote_media_session_is_one_clip_and_at_most_ten_minutes(session) -> None:
    assert len(session.clip_ids) == 1
    assert session.expires_at - session.issued_at <= timedelta(minutes=10)

async def test_every_range_consumes_fresh_phase3_grant(harness) -> None:
    media_session = await harness.open_remote_media("clip_synth_01")
    first = await harness.read_range(media_session, 0, 4095)
    assert first.phase3_grant.grant.single_use
    assert first.phase3_grant.grant.expires_at - first.phase3_grant.grant.issued_at <= timedelta(seconds=60)
    assert first.phase3_grant.algorithm == "Ed25519"
    assert (await harness.reuse(first.phase3_grant)).status_code == 403

async def test_remote_media_cannot_enumerate_or_export(harness) -> None:
    assert (await harness.read_other_clip()).status_code == 403
    assert (await harness.export_clip()).json()["code"] == "REMOTE_OPERATION_DENIED"
    assert not harness.responses.contain_any("rtsp://", "onvif", "camera_password", "storage_path")
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/core/tests/unit/hardening/test_remote_media_session.py tests/integration/phase6/test_remote_camera_metadata.py tests/integration/phase6/test_remote_camera_playback.py tests/security/phase6/test_remote_media_isolation.py tests/fault/phase6/test_remote_media_revocation.py -q`
Expected: FAIL because remote camera/media classes and session broker are absent.

- [ ] **Step 3: Implement the exact two-layer broker and metadata projection**

~~~python
async def open_single_clip(self, request, context) -> RemoteSingleClipMediaSessionV1:
    await self._policy.require_remote_camera_playback(context, fresh_passkey=timedelta(minutes=5))
    clip = await self._vision.require_owner_playable_clip(request.clip_id, context.owner_subject_id)
    now = self._clock.now()
    return await self._sessions.create(
        media_session_id=uuid4(),
        owner_subject_id=context.owner_subject_id,
        remote_session_id=context.remote_session_id,
        clip_ids=(clip.clip_id,), allowed_view=request.view,
        issued_at=now, expires_at=min(now + timedelta(minutes=10), clip.immutable_expires_at),
        route_generation=context.route_generation,
        remote_session_revocation_generation=context.revocation_generation,
        operation_class_generation=context.operation_class_generation,
        clip_generation=clip.clip_generation,
        catalog_generation=clip.catalog_generation,
        privacy_generation=context.privacy_generation,
        session_commitment=self._commitments.for_remote_media_session(context, clip, request.view),
    )

async def read_range(self, media_session, byte_range, context):
    current = await self._sessions.consume_range_authority(media_session, context)
    now = self._clock.now()
    request = PlaybackRangeRequestV1(
        request_id=uuid4(), clip_id=current.clip_ids[0], view=current.allowed_view,
        byte_range=byte_range,
        expected_clip_generation=current.clip_generation,
        expected_catalog_generation=current.catalog_generation,
        expected_privacy_generation=current.privacy_generation,
        issued_at=now, expires_at=now + timedelta(seconds=5),
        request_commitment=self._commitments.for_remote_range(current, byte_range, context),
    )
    signed_grant = await self._phase3.prepare_range(request, context.phase3_actor_context())
    return await self._phase3.proxy_once(signed_grant, cache_control="no-store")
~~~

Metadata contains safe area/zone display label, native class, local time, verification and clip availability only—no thumbnail, identity, address, credential or URL. The seam uses the canonical Phase 3 `prepare_range(PlaybackRangeRequestV1, ActorContext)` method and passes the complete `SignedMediaPlaybackGrantV1`; the Phase 3 proxy verifies the envelope before consulting the inner grant. Recheck retention and all route/session/operation-class/passkey/camera/zone/privacy/catalog generations per range. Enabling or disabling either camera class increments the session operation-class generation and revokes old sessions; newly authenticated sessions receive only the exact locally enabled classes. Revoke media on logout, expiry, disable, route suspension, Privacy Shield, clip deletion/expiry, recorder/catalog uncertainty, and policy change.

- [ ] **Step 4: Run green with Phase 3 playback regressions and browser scans**

Run: `uv run pytest apps/core/tests/unit/hardening/test_remote_media_session.py tests/integration/phase6/test_remote_camera_metadata.py tests/integration/phase6/test_remote_camera_playback.py tests/security/phase6/test_remote_media_isolation.py tests/fault/phase6/test_remote_media_revocation.py tests/integration/vision/test_media_proxy.py tests/security/vision/test_playback_grants.py -q && uv run python scripts/scan_browser_artifacts.py --forbid camera_credentials,media_urls,storage_paths,persistent_grants && uv run ruff check apps/core/src/tuntun_core/services/hardening/remote_media.py apps/core/src/tuntun_core/services/vision/playback_broker.py tests/integration/phase6 tests/security/phase6 tests/fault/phase6 && uv run mypy apps/core/src`
Expected: PASS; every range has a distinct ≤60-second grant, media session is ≤10 minutes/one clip, and no credential/path/export route exists.

- [ ] **Step 5: Commit optional remote camera scopes**

~~~bash
git add apps/core/src/tuntun_core/services/vision/playback_broker.py apps/core/src/tuntun_core/services/hardening/remote_policy.py apps/core/src/tuntun_core/services/hardening/remote_sessions.py apps/core/src/tuntun_core/services/hardening/remote_media.py apps/core/src/tuntun_core/api/routes/cameras.py apps/core/tests/unit/hardening/test_remote_media_session.py tests/integration/phase6/test_remote_camera_metadata.py tests/integration/phase6/test_remote_camera_playback.py tests/security/phase6/test_remote_media_isolation.py tests/fault/phase6/test_remote_media_revocation.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(remote): gate single-clip camera playback"
~~~

### Task 18: Add optional-scope UI and issue the P6-2 per-class go/no-go manifest

**Depends on:** Tasks 16–17; unselected scopes remain absent.
**Gate contribution:** completes P6-2.
**Estimated effort:** 1 person-day.

**Files:**
- Modify: `apps/admin/src/features/system/remote-access.tsx`
- Create: `apps/admin/src/features/system/remote-scopes.tsx`
- Create: `scripts/phase6/verify_p6_2.py`
- Create: `docs/evidence/phase6-optional-scopes-schema.json`
- Test: `apps/admin/src/features/system/remote-scopes.test.tsx`
- Test: `tests/ui/phase6/remote-scopes.spec.ts`
- Test: `tests/security/phase6/test_remote_scope_absence.py`
- Test: `tests/acceptance/phase6/test_p6_2_gate.py`

**Interfaces:** Produces locally managed per-class enablement/evidence UI, remote safe scope status, and a signed `P6OptionalScopesReceipt` declaring each exact class `enabled` or `absent`. Remote UI cannot change scope policy.

**Rollback/disabled exit:** A class without complete evidence has no route, bundle, config, prepared action, or capability registration. Disabling a class immediately revokes its sessions/grants and removes it from remote navigation.

- [ ] **Step 1: Write red local-management, remote-denial, feature-absence, and truth tests**

~~~typescript
test("remote page can use but cannot enable an approved scope", async ({page}) => {
  await openApprovedVpnConsole(page, {features: ["remote_media_stop_v1"]});
  await expect(page.getByRole("button", {name: "Stop media"})).toBeVisible();
  await expect(page.getByRole("button", {name: /enable remote/i})).toHaveCount(0);
});

test("absent camera playback has no route or code chunk", async ({page}) => {
  await installFeatureManifest(page, {remote_camera_playback_v1: "absent"});
  await expect(page.goto("/cameras/remote-playback")).toHaveURL(/feature-absent/);
  expect(await loadedChunkNames(page)).not.toContain("remote-camera-playback");
});
~~~

- [ ] **Step 2: Run red**

Run: `pnpm --dir apps/admin test -- remote-scopes.test.tsx && pnpm --dir apps/admin exec playwright test tests/ui/phase6/remote-scopes.spec.ts && uv run pytest tests/security/phase6/test_remote_scope_absence.py tests/acceptance/phase6/test_p6_2_gate.py -q`
Expected: FAIL because scope UI and P6-2 verifier are absent.

- [ ] **Step 3: Implement per-class state, prepared local enablement, and manifest verifier**

~~~python
OPTIONAL_REMOTE_CLASSES = (
    "remote_private_detail_v1", "remote_light_power_v1", "remote_media_stop_v1",
    "remote_camera_metadata_v1", "remote_camera_playback_v1",
)

def verify_p6_2(evidence: Mapping[str, ScopeEvidence]) -> P6OptionalScopesReceipt:
    rows = []
    for capability in OPTIONAL_REMOTE_CLASSES:
        row = evidence[capability]
        if row.state == "enabled":
            require(row.positive and row.negative and row.theft and row.revocation)
        else:
            require(row.state == "absent" and row.negative_reachability_complete)
        rows.append(row.to_safe_receipt())
    return P6OptionalScopesReceipt(rows=tuple(rows))
~~~

Local UI shows exact operation/data, route, actors, fresh-passkey requirement, evidence, residual risks and disable effect in a server-prepared summary. Remote UI shows only currently allowed use controls. Add localized truth for browser capture outside deletion control and local-only export/recovery/admin boundaries.

- [ ] **Step 4: Run green, absence scan, accessibility, and gate verification**

Run: `pnpm --dir apps/admin test -- remote-scopes.test.tsx && pnpm --dir apps/admin exec playwright test tests/ui/phase6/remote-scopes.spec.ts && uv run pytest tests/security/phase6/test_remote_scope_absence.py tests/acceptance/phase6/test_p6_2_gate.py -q && uv run python scripts/phase6/verify_p6_2.py --synthetic fixtures/synthetic/phase6/remote/scoped-actions-v1.json --output var/evidence/phase6/p6-2-synthetic.json && pnpm --dir apps/admin typecheck && pnpm --dir apps/admin build`
Expected: PASS; receipt declares every class enabled-with-four-gates or negatively absent, and remote has no enablement route.

- [ ] **Step 5: Commit optional-scope UI and gate**

~~~bash
git add apps/admin/src/features/system/remote-access.tsx apps/admin/src/features/system/remote-scopes.tsx scripts/phase6/verify_p6_2.py docs/evidence/phase6-optional-scopes-schema.json apps/admin/src/features/system/remote-scopes.test.tsx tests/ui/phase6/remote-scopes.spec.ts tests/security/phase6/test_remote_scope_absence.py tests/acceptance/phase6/test_p6_2_gate.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(ui): bind optional remote scopes to evidence"
~~~

## Wave 3 — P6-3 Exact Third-Party Plugin Registry and Isolation

### Task 19: Publish the exact `phase6.initial.1` registry and capability-limited SDK

**Depends on:** Tasks 01–06.
**Gate contribution:** P6-3 plugin contract.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `packages/plugin-sdk/src/tuntun_plugin_sdk/__init__.py`
- Create: `packages/plugin-sdk/src/tuntun_plugin_sdk/protocol.py`
- Create: `packages/plugin-sdk/src/tuntun_plugin_sdk/health_render.py`
- Create: `packages/plugin-sdk/src/tuntun_plugin_sdk/local_alert_render.py`
- Create: `ops/plugins/phase6.initial.1.registry.json`
- Create: `ops/plugins/verify_registry.py`
- Test: `packages/plugin-sdk/tests/test_public_sdk.py`
- Test: `tests/contract/plugins/test_initial_registry.py`
- Test: `tests/security/plugins/test_unknown_capability_denial.py`
- Test: `tests/privacy/plugins/test_sdk_surface.py`

**Interfaces:** Produces the signed platform registry and public request/result codecs for exactly `system.health.render.v1` and `notification.local_alert.render.v1`. SDK contains no core import, canonical entity, transport/network helper, persistence API, policy field, action, tool, or generic payload.

**Rollback/disabled exit:** Registry/schema/signature drift blocks all third-party plugin installation and P6-3; no household override or developer-mode exception exists.

- [ ] **Step 1: Write red exact-ID, policy-ownership, and SDK-reachability tests**

~~~python
def test_initial_registry_has_exactly_two_ids(registry) -> None:
    assert tuple(registry.capabilities) == (
        "system.health.render.v1",
        "notification.local_alert.render.v1",
    )

def test_registry_not_manifest_owns_every_policy_dimension(registry) -> None:
    for capability in registry.capabilities.values():
        assert capability.policy.keys() == {
            "actor_invocation", "consent_guardian", "sensitivity", "retention_storage",
            "egress_dns_redirects", "revocation_cleanup", "resources",
        }

def test_sdk_exports_no_generic_or_authoritative_type() -> None:
    assert set(tuntun_plugin_sdk.__all__) == {
        "PluginHealthSnapshotV1", "PluginHealthRenderV1",
        "PluginLocalAlertV1", "PluginLocalAlertRenderV1", "serve_one_request",
    }
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest packages/plugin-sdk/tests tests/contract/plugins/test_initial_registry.py tests/security/plugins/test_unknown_capability_denial.py tests/privacy/plugins/test_sdk_surface.py -q`
Expected: FAIL because the SDK and signed registry are absent.

- [ ] **Step 3: Implement fixed codecs and a platform-owned immutable registry**

~~~python
CAPABILITY_CODECS: Final = MappingProxyType({
    "system.health.render.v1": CodecPair(PluginHealthSnapshotV1, PluginHealthRenderV1),
    "notification.local_alert.render.v1": CodecPair(PluginLocalAlertV1, PluginLocalAlertRenderV1),
})

def serve_one_request(stdin: BinaryIO, stdout: BinaryIO, renderer: Renderer) -> None:
    envelope = PluginCallEnvelopeV1.model_validate_json(read_bounded(stdin, 64 * 1024))
    codecs = CAPABILITY_CODECS.get(envelope.capability_id)
    if codecs is None:
        raise ProtocolDenied("unknown_capability")
    request = codecs.request.model_validate(envelope.payload)
    response = codecs.response.model_validate(renderer.render(request))
    write_bounded(stdout, response.model_dump_json(), 64 * 1024)
~~~

Registry fixes the distinct owner invocation/consent rules, exact attention/alert enums, no subjects/devices/networks/cost/content/history/stable IDs, no plugin queue or retained text, content-minimized 180-day receipt, five-second/fresh-process/no-write policy, zero network/DNS/redirect, one concurrency, 128 MiB/50%-CPU/64-KiB bounds, generation cleanup and mandatory-core-alert independence. Sign it as a release input.

- [ ] **Step 4: Run green, build wheel, inspect exports/dependencies, and verify registry signature**

Run: `uv run pytest packages/plugin-sdk/tests tests/contract/plugins/test_initial_registry.py tests/security/plugins/test_unknown_capability_denial.py tests/privacy/plugins/test_sdk_surface.py -q && uv build packages/plugin-sdk && uv run python scripts/check_public_api.py packages/plugin-sdk --expected fixtures/synthetic/phase6/plugins/sdk-api-v1.json && uv run python ops/plugins/verify_registry.py ops/plugins/phase6.initial.1.registry.json && uv run ruff check packages/plugin-sdk ops/plugins/verify_registry.py tests/contract/plugins tests/security/plugins tests/privacy/plugins && uv run mypy packages/plugin-sdk/src`
Expected: PASS; wheel exports only four DTOs/one bounded runner, and registry verifier reports the exact two IDs.

- [ ] **Step 5: Commit registry and SDK**

~~~bash
git add packages/plugin-sdk ops/plugins/phase6.initial.1.registry.json ops/plugins/verify_registry.py tests/contract/plugins/test_initial_registry.py tests/security/plugins/test_unknown_capability_denial.py tests/privacy/plugins/test_sdk_surface.py fixtures/synthetic/phase6/plugins/sdk-api-v1.json
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(plugins): freeze the two-capability public SDK"
~~~

### Task 20: Verify signed plugin installation and authenticated single-call IPC

**Depends on:** Task 19 and shared signature/SBOM verifiers.
**Gate contribution:** P6-3 plugin admission.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `apps/plugin-supervisor/src/tuntun_plugin_supervisor/server.py`
- Create: `apps/plugin-supervisor/src/tuntun_plugin_supervisor/verifier.py`
- Create: `apps/plugin-supervisor/src/tuntun_plugin_supervisor/registry.py`
- Create: `apps/plugin-supervisor/src/tuntun_plugin_supervisor/ipc.py`
- Create: `apps/core/src/tuntun_core/services/hardening/plugin_installation.py`
- Create: `apps/core/src/tuntun_core/services/hardening/plugin_invocation.py`
- Test: `apps/plugin-supervisor/tests/test_plugin_verifier.py`
- Test: `apps/plugin-supervisor/tests/test_authenticated_ipc.py`
- Test: `tests/integration/plugins/test_install_and_call.py`
- Test: `tests/security/plugins/test_plugin_admission_denials.py`
- Test: `tests/property/plugins/test_manifest_result_fuzz.py`

**Interfaces:** Produces local owner-only prepared install/remove, artifact/signature/publisher/protocol/registry/licence/SBOM verification, one authenticated Unix-socket request, generation/correlation/expiry validation before and after child execution, and minimized receipts.

**Rollback/disabled exit:** Any unsigned/mismatched/unknown/expired plugin or registry disables that installation and launches no child. Admission never trusts manifest-declared policy.

- [ ] **Step 1: Write red signer, digest, manifest-field, IPC-peer, and late-result tests**

~~~python
@pytest.mark.parametrize("fault", [
    "unsigned", "wrong_digest", "wrong_publisher", "resigned_wrong_publisher",
    "unknown_protocol", "unknown_registry", "policy_field", "sbom_mismatch",
    "licence_mismatch", "unsafe_entrypoint", "unlicensed_dependency",
])
def test_plugin_admission_fails_closed(verifier, candidate, fault) -> None:
    assert verifier.verify(candidate.with_fault(fault)).decision == "deny"

async def test_ipc_rejects_wrong_peer_and_late_generation(supervisor) -> None:
    assert (await supervisor.call_from_wrong_peer()).code == "plugin_peer_denied"
    call = await supervisor.begin_call()
    await supervisor.revoke(call.plugin_id)
    assert (await supervisor.deliver_late_result(call)).code == "plugin_result_stale"

@pytest.mark.parametrize("fault", [
    "capability_payload_mismatch", "expired_call", "bad_payload_commitment",
    "unknown_render_field", "wrong_render_request_id", "wrong_render_schema",
    "late_result", "oversize_combined_wire_bytes",
])
async def test_plugin_ipc_rejects_every_unbound_call_or_result(supervisor, valid_call, fault) -> None:
    result = await supervisor.invoke_with_fault(valid_call, fault)
    assert result.state == "error_safe"
    assert result.payload is None

async def test_sdk_render_round_trip_is_supervisor_wrapped_and_bound(sdk_child, supervisor, valid_call) -> None:
    raw_render = await sdk_child.render_one(valid_call)
    result = await supervisor.decode_and_wrap_render(valid_call, raw_render)
    assert type(result) is PluginCallResultEnvelopeV1
    assert result.request_id == result.payload.request_id == valid_call.request_id
    assert result.plugin_id == valid_call.plugin_id
    assert result.capability_id == valid_call.capability_id
    supervisor.require_valid_result_commitment(result)
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/plugin-supervisor/tests/test_plugin_verifier.py apps/plugin-supervisor/tests/test_authenticated_ipc.py tests/integration/plugins/test_install_and_call.py tests/security/plugins/test_plugin_admission_denials.py -q`
Expected: FAIL because the supervisor/admission/IPC services are absent.

- [ ] **Step 3: Implement immutable admission and generation-bound one-call protocol**

~~~python
def verify_candidate(self, package: PluginPackage) -> VerifiedPlugin:
    manifest = PluginManifestV1.model_validate_json(reject_duplicate_json_keys(package.manifest))
    self._signatures.require_authorized_publisher_identity_and_digest(
        signature=package.signature,
        signature_identity=manifest.signature_identity,
        claimed_publisher=manifest.publisher,
        artifact=package.bytes,
        expected_digest=manifest.artifact_digest,
        canonical_manifest=canonical_hardening_bytes(manifest),
        domain="tuntun.plugin-package.v1",
    )
    self._registry.require_revision_and_exact_ids(manifest.capability_registry_revision, manifest.requested_capability_ids)
    self._sbom.require_manifest_identity_licence_and_policy(
        sbom=package.sbom,
        expected_digest=manifest.sbom_digest,
        plugin_id=manifest.plugin_id,
        version=manifest.version,
        declared_licence=manifest.licence,
    )
    self._entrypoints.require_relative_inside_package(manifest.entrypoint)
    return VerifiedPlugin(manifest=manifest, package_handle=package.read_only_handle())

async def invoke(self, call: PluginCallEnvelopeV1) -> PluginCallResultEnvelopeV1:
    validated_call = PluginCallEnvelopeV1.model_validate(call, strict=True)
    self._clock.require_current(validated_call.issued_at, validated_call.expires_at)
    self._commitments.require_payload(
        validated_call.payload,
        validated_call.payload_commitment,
        domain="tuntun.plugin-call-payload.v1",
    )
    current = await self._grants.require_current(
        validated_call.plugin_id,
        validated_call.capability_id,
        validated_call.grant_generation,
    )
    result = await self._supervisor.call_once(current, validated_call)
    validated_result = PluginCallResultEnvelopeV1.model_validate(result, strict=True)
    require_exact_plugin_result_binding(validated_call, validated_result)
    self._commitments.require_result(
        validated_result,
        validated_result.result_commitment,
        domain="tuntun.plugin-call-result.v1",
    )
    if validated_result.observed_at > validated_call.expires_at:
        raise PluginResultExpired
    await self._grants.require_current(
        validated_call.plugin_id,
        validated_call.capability_id,
        validated_call.grant_generation,
    )
    return validated_result
~~~

The signature policy verifies the exact package bytes and domain, maps the signing identity to the claimed publisher, and rejects even a correctly re-signed manifest whose publisher claim is not authorized for that signer. The SBOM policy binds plugin ID/version and the manifest's declared SPDX licence to the signed SBOM before dependency-policy evaluation. Install requires local owner/passkey prepared summary showing publisher/signature/digest/licence/SBOM/exact capabilities/platform policies. Adult partner, guardian, child, Guest, remote session, plugin or maintainer cannot install/grant. IPC authenticates OS peer/nonce/correlation, enforces one request, rejects ancillary handles, clears socket/result, and audits only ID/version/digest/capability/random request ID/outcome/latency.

- [ ] **Step 4: Run green plus manifest/result fuzz and audit-content scan**

Run: `uv run pytest apps/plugin-supervisor/tests/test_plugin_verifier.py apps/plugin-supervisor/tests/test_authenticated_ipc.py tests/integration/plugins/test_install_and_call.py tests/security/plugins/test_plugin_admission_denials.py -q && uv run pytest tests/property/plugins -q && uv run python scripts/scan_private_data.py --paths var/test-artifacts/plugin-audit --allow-safe-ids && uv run ruff check apps/plugin-supervisor apps/core/src/tuntun_core/services/hardening/plugin_installation.py apps/core/src/tuntun_core/services/hardening/plugin_invocation.py tests/integration/plugins tests/security/plugins && uv run mypy apps/plugin-supervisor/src apps/core/src`
Expected: PASS; every admission fault spawns zero processes and late/wrong-peer results are discarded.

- [ ] **Step 5: Commit plugin admission and IPC**

~~~bash
git add apps/plugin-supervisor/src/tuntun_plugin_supervisor/server.py apps/plugin-supervisor/src/tuntun_plugin_supervisor/verifier.py apps/plugin-supervisor/src/tuntun_plugin_supervisor/registry.py apps/plugin-supervisor/src/tuntun_plugin_supervisor/ipc.py apps/core/src/tuntun_core/services/hardening/plugin_installation.py apps/core/src/tuntun_core/services/hardening/plugin_invocation.py apps/plugin-supervisor/tests/test_plugin_verifier.py apps/plugin-supervisor/tests/test_authenticated_ipc.py tests/integration/plugins/test_install_and_call.py tests/security/plugins/test_plugin_admission_denials.py tests/property/plugins/test_manifest_result_fuzz.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(plugins): verify and isolate plugin IPC"
~~~

### Task 21: Prove fresh-process sandbox, resource ceilings, zero persistence, and zero network

**Depends on:** Task 20 and actual target macOS sandbox capability for production promotion.
**Gate contribution:** mandatory P6-3 isolation; T16.
**Estimated effort:** 1.5 person-days plus target-Mac qualification.

**Files:**
- Create: `apps/plugin-supervisor/src/tuntun_plugin_supervisor/sandbox.py`
- Create: `apps/plugin-supervisor/src/tuntun_plugin_supervisor/process.py`
- Create: `apps/plugin-supervisor/src/tuntun_plugin_supervisor/quotas.py`
- Create: `apps/plugin-supervisor/src/tuntun_plugin_supervisor/cleanup.py`
- Create: `ops/plugins/plugin.sb`
- Create: `ops/plugins/qualify_sandbox.py`
- Test: `apps/plugin-supervisor/tests/test_sandbox_policy.py`
- Test: `tests/security/plugins/test_plugin_exfiltration.py`
- Test: `tests/fault/plugins/test_plugin_resource_and_cleanup.py`
- Test: `tests/hardware/phase6/test_plugin_sandbox_enforcement.py`

**Interfaces:** Produces `SandboxBackend.run_fresh(VerifiedPlugin, PluginCallEnvelopeV1) -> PluginCallResultEnvelopeV1` using a dedicated unprivileged identity, read-only executable/package, empty per-call sandbox, no inherited environment secret, authenticated socket only, and fixed quotas. The child IPC serializes only the frozen call envelope and accepts only the exact duplicate-key-rejected capability render DTO selected by the trusted registry. The supervisor—not the untrusted child—is the sole wrapper: it binds request/plugin/version/capability/grant/time, computes the Keychain-backed result commitment, and returns the frozen result envelope to core. There is no parallel generic call/result, dictionary, or attribute-map protocol.

**Rollback/disabled exit:** If filesystem/process/network/DNS/redirect/resource/cleanup enforcement cannot be proved on supported macOS, third-party plugin support and P6-3/C0/C1 are blocked. No developer switch bypasses it.

- [ ] **Step 1: Write red exfiltration, persistence, quota, crash, and cleanup tests**

~~~python
@pytest.mark.parametrize("attempt", [
    "open_tuntun_db", "open_keychain", "open_home", "open_camera_store", "open_backup",
    "open_source_repo", "write_file", "connect_tcp", "connect_udp", "resolve_dns",
    "follow_redirect", "inherit_secret_env", "spawn_child", "open_removable_volume",
])
async def test_plugin_sandbox_denies_every_forbidden_attempt(sandbox, attempt) -> None:
    result = await sandbox.run_adversary(attempt)
    assert result.denied and result.exfiltrated_bytes == 0

async def test_every_terminal_path_destroys_process_socket_and_sandbox(sandbox) -> None:
    for terminal in ("return", "timeout", "cancel", "crash", "quota", "revoke"):
        receipt = await sandbox.run_terminal_path(terminal)
        assert receipt.process_dead and receipt.socket_closed and receipt.sandbox_erased

def test_limits_are_exact(policy) -> None:
    assert policy.wall_seconds == 5 and policy.memory_mib == 128
    assert policy.cpu_fraction == Decimal("0.50") and policy.concurrent_calls == 1
    assert policy.request_response_bytes == 64 * 1024
~~~

- [ ] **Step 2: Run red and hardware collection-only**

Run: `uv run pytest apps/plugin-supervisor/tests/test_sandbox_policy.py tests/security/plugins/test_plugin_exfiltration.py tests/fault/plugins/test_plugin_resource_and_cleanup.py -q && uv run pytest tests/hardware/phase6/test_plugin_sandbox_enforcement.py --collect-only -q`
Expected: unit/security tests FAIL because sandbox enforcement is absent; hardware test collects and skips without its explicit flag.

- [ ] **Step 3: Implement enforceable macOS profile, child limits, and postcondition cleanup**

~~~python
async def run_fresh(
    self,
    plugin: VerifiedPlugin,
    call: PluginCallEnvelopeV1,
) -> PluginCallResultEnvelopeV1:
    validated_call = PluginCallEnvelopeV1.model_validate(call, strict=True)
    wire_call = canonical_hardening_bytes(validated_call)
    remaining_wire_bytes = 64 * 1024 - len(wire_call)
    if remaining_wire_bytes <= 0:
        raise PluginWireLimitExceeded
    sandbox = await self._sandboxes.create_empty_readonly_exec(plugin)
    process = await self._processes.spawn(
        identity=self._dedicated_identity,
        executable=sandbox.entrypoint,
        argv=("--one-call",), env={}, cwd=sandbox.empty_workdir,
        inherited_fds=(sandbox.authenticated_ipc_fd,),
        limits=ProcessLimits(wall_seconds=5, memory_mib=128, cpu_fraction=Decimal("0.50"), processes=1),
        network=NetworkPolicy.DENY_ALL, filesystem=sandbox.profile,
    )
    try:
        raw_result = await asyncio.wait_for(
            self._ipc.exchange(
                process,
                wire_call,
                max_response_bytes=remaining_wire_bytes,
            ),
            timeout=5,
        )
        result_model = self._registry.exact_render_model(validated_call.capability_id)
        render = result_model.model_validate_json(reject_duplicate_json_keys(raw_result))
        observed_at = self._clock.now()
        if observed_at > validated_call.expires_at:
            raise PluginResultExpired
        return self._result_factory.rendered(
            call=validated_call,
            render=render,
            observed_at=observed_at,
            commitment_domain="tuntun.plugin-call-result.v1",
        )
    finally:
        await self._cleanup.kill_close_erase(process, sandbox)
        await self._cleanup.assert_no_process_socket_or_writable_residue(process, sandbox)
~~~

`_result_factory.rendered` first requires `render.request_id == call.request_id` and the exact capability-to-render class, copies every outer binding from the already validated call, and computes `result_commitment` with a supervisor-only purpose key over canonical envelope bytes excluding that field. The key, outer fields, and wrapper are absent from the plugin SDK/process. Error paths are wrapped the same way with `state="error_safe"` and no payload. The 64 KiB ceiling applies to request plus response bytes together, not to each direction independently.

The profile allows only loader/system libraries proven necessary, read-only plugin bytes, one inherited authenticated socket and empty ephemeral metadata. Deny all other file, network, DNS, Mach/service, device, mount, clipboard, user-home, Keychain and process actions. Enforce quotas both at OS launch and supervisor measurement. A cleanup postcondition failure revokes the installation and opens a critical local alert.

- [ ] **Step 4: Run green synthetic enforcement and stage mandatory physical qualification**

Run: `uv run pytest apps/plugin-supervisor/tests/test_sandbox_policy.py tests/security/plugins/test_plugin_exfiltration.py tests/fault/plugins/test_plugin_resource_and_cleanup.py -q && uv run python ops/plugins/qualify_sandbox.py --synthetic --output var/evidence/phase6/plugin-sandbox-synthetic.json && uv run ruff check apps/plugin-supervisor ops/plugins tests/security/plugins tests/fault/plugins tests/hardware/phase6 && uv run mypy apps/plugin-supervisor/src`
Expected: PASS for synthetic enforcement with zero leaked/persisted bytes. P6-3 remains blocked until `TUNTUN_ALLOW_PLUGIN_SANDBOX_PROBE=1 ...` passes on the supported Intel Mac and declared Apple Silicon target.

- [ ] **Step 5: Commit sandbox and qualification gate**

~~~bash
git add apps/plugin-supervisor/src/tuntun_plugin_supervisor/sandbox.py apps/plugin-supervisor/src/tuntun_plugin_supervisor/process.py apps/plugin-supervisor/src/tuntun_plugin_supervisor/quotas.py apps/plugin-supervisor/src/tuntun_plugin_supervisor/cleanup.py ops/plugins/plugin.sb ops/plugins/qualify_sandbox.py apps/plugin-supervisor/tests/test_sandbox_policy.py tests/security/plugins/test_plugin_exfiltration.py tests/fault/plugins/test_plugin_resource_and_cleanup.py tests/hardware/phase6/test_plugin_sandbox_enforcement.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(plugins): enforce ephemeral zero-egress sandboxes"
~~~

### Task 22: Implement local-click health rendering in an isolated third-party panel

**Depends on:** Tasks 19–21.
**Gate contribution:** first mandatory P6-3 plugin path.
**Estimated effort:** 1 person-day.

**Files:**
- Modify: `apps/core/src/tuntun_core/services/hardening/plugin_invocation.py`
- Create: `apps/core/src/tuntun_core/api/routes/plugins.py`
- Create: `apps/admin/src/features/system/plugins.tsx`
- Create: `apps/admin/src/routes/system-plugins.tsx`
- Test: `tests/integration/plugins/test_health_render.py`
- Test: `tests/security/plugins/test_health_actor_and_sensitivity.py`
- Test: `apps/admin/src/features/system/plugins.test.tsx`
- Test: `tests/ui/phase6/plugin-health.spec.ts`

**Interfaces:** Implements `system.health.render.v1` from exact current core safe component facts to optional plain-text result. Every invocation requires a locally present owner, active passkey session and explicit click; output renders in a labelled isolated “Third-party plugin” panel while core health remains authoritative.

**Rollback/disabled exit:** Missing/crashed/timed-out/revoked output removes only the third-party panel and shows core health unchanged. Remote/adult/guardian/child/Guest cannot invoke.

- [ ] **Step 1: Write red actor, field, click, expiry, and render isolation tests**

~~~python
@pytest.mark.parametrize("actor", ["remote_owner", "adult_partner", "guardian", "child", "guest", "plugin", "maintainer"])
async def test_only_local_owner_click_invokes_health_plugin(harness, actor) -> None:
    assert (await harness.invoke_health(actor=actor, explicit_click=True)).code == "POLICY_DENIED"

async def test_health_request_contains_only_closed_operational_facts(harness) -> None:
    request = await harness.capture_health_request()
    assert request.expires_at - request.issued_at <= timedelta(seconds=5)
    assert not contains_subject_device_network_cost_content_or_history(request)

def test_plugin_result_is_labelled_and_not_authoritative(rendered_page) -> None:
    assert rendered_page.panel_label == "Third-party plugin"
    assert rendered_page.core_health_present and rendered_page.core_health_authoritative
    assert not rendered_page.has_markup_url_action_or_hidden_text
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/plugins/test_health_render.py tests/security/plugins/test_health_actor_and_sensitivity.py -q && pnpm --dir apps/admin test -- plugins.test.tsx && pnpm --dir apps/admin exec playwright test tests/ui/phase6/plugin-health.spec.ts`
Expected: FAIL because health invocation/API/UI are absent.

- [ ] **Step 3: Implement minimized request, explicit invocation, and isolated rendering**

~~~python
async def invoke_health_render(self, owner, explicit_click: bool) -> PluginHealthRenderV1:
    self._auth.require_local_owner_active_passkey(owner)
    if not explicit_click:
        raise PolicyDenied("health_plugin_requires_explicit_click")
    request = self._projections.build_plugin_health_snapshot(max_components=16, ttl=timedelta(seconds=5))
    result = await self._plugins.invoke_exact("system.health.render.v1", request)
    return PluginHealthRenderV1.model_validate(result)
~~~

Map only the closed component/state/freshness/attention enums, never free-form core text or identifiers. Escape plain text, reject bidi/markup/URLs/images/actions, and prevent plugin result from search/model/memory/tool/audit-body ingestion. UI uses an isolated component tree with no unsafe HTML and provides core fallback, keyboard focus, VoiceOver label, English/Hindi platform copy and narrow/high-contrast fixtures.

- [ ] **Step 4: Run green, UI security/accessibility, and core-authority assertions**

Run: `uv run pytest tests/integration/plugins/test_health_render.py tests/security/plugins/test_health_actor_and_sensitivity.py -q && pnpm --dir apps/admin test -- plugins.test.tsx && pnpm --dir apps/admin exec playwright test tests/ui/phase6/plugin-health.spec.ts && pnpm --dir apps/admin typecheck && pnpm --dir apps/admin build`
Expected: PASS; exactly one local click produces a labelled safe panel, and every failure leaves authoritative core health visible.

- [ ] **Step 5: Commit health render path**

~~~bash
git add apps/core/src/tuntun_core/services/hardening/plugin_invocation.py apps/core/src/tuntun_core/api/routes/plugins.py apps/admin/src/features/system/plugins.tsx apps/admin/src/routes/system-plugins.tsx tests/integration/plugins/test_health_render.py tests/security/plugins/test_health_actor_and_sensitivity.py apps/admin/src/features/system/plugins.test.tsx tests/ui/phase6/plugin-health.spec.ts
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(plugins): render optional local health panels"
~~~

### Task 23: Implement local-alert rendering, core non-suppression, revocation, removal, and containment

**Depends on:** Tasks 19–22 and mandatory local core-alert service.
**Gate contribution:** second mandatory P6-3 plugin path; T16/T22/T24.
**Estimated effort:** 1.5 person-days.

**Files:**
- Modify: `apps/core/src/tuntun_core/services/hardening/plugin_invocation.py`
- Create: `apps/core/src/tuntun_core/services/hardening/incident.py`
- Modify: `apps/admin/src/features/system/plugins.tsx`
- Create: `scripts/phase6/run_plugin_qualification.py`
- Create: `docs/operations/phase6-plugins.md`
- Test: `tests/integration/plugins/test_local_alert_render.py`
- Test: `tests/security/plugins/test_core_alert_non_suppression.py`
- Test: `tests/fault/plugins/test_revoke_remove_crash.py`
- Test: `tests/privacy/plugins/test_contained_egress_and_shield.py`
- Test: `tests/acceptance/phase6/test_plugin_gate.py`

**Interfaces:** Implements `notification.local_alert.render.v1` only after an authoritative listed alert and active owner-approved installation. Produces optional adjacent presentation while core alert lifecycle/acknowledgement remains wholly independent. Adds immediate grant/process/socket/request/sandbox cleanup on revoke/remove/privacy/incident.

**Rollback/disabled exit:** Any plugin failure drops its presentation only. The mandatory core alert remains visible/actionable on the local console and physical/status surfaces. Failure of non-suppression or cleanup blocks P6-3/release.

- [ ] **Step 1: Write red exact-alert, non-suppression, containment, and lifecycle tests**

~~~python
@pytest.mark.parametrize("terminal", ["missing", "malicious", "crash", "timeout", "revoked", "removed"])
async def test_plugin_never_suppresses_core_alert(harness, terminal) -> None:
    alert = await harness.raise_core_alert("privacy_stop_failed", severity="critical")
    await harness.plugin_terminal(terminal, alert)
    assert harness.core_alert(alert.id).visible and harness.core_alert(alert.id).actionable
    assert not harness.core_alert(alert.id).acknowledged

async def test_contained_egress_stops_outbound_but_preserves_local_alert(harness) -> None:
    await harness.enter_contained_egress()
    assert harness.external_notifications.active == ()
    assert harness.external_adapters.active == ()
    assert harness.local_core_critical_surface.available

async def test_remove_erases_plugin_and_empty_sandbox_not_core_alert(harness) -> None:
    receipt = await harness.remove_plugin()
    assert receipt.binary_erased and receipt.sandbox_erased and receipt.outstanding_requests == 0
    assert harness.core_alerts.current
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/plugins/test_local_alert_render.py tests/security/plugins/test_core_alert_non_suppression.py tests/fault/plugins/test_revoke_remove_crash.py tests/privacy/plugins/test_contained_egress_and_shield.py tests/acceptance/phase6/test_plugin_gate.py -q`
Expected: FAIL because local-alert invocation and lifecycle orchestration are absent.

- [ ] **Step 3: Implement authoritative-core-first invocation and irreversible cleanup**

~~~python
async def present_local_alert(self, alert: CoreLocalAlert) -> PluginPresentation | None:
    await self._core_alerts.require_committed_and_visible(alert.alert_id)
    if alert.code not in PLUGIN_LOCAL_ALERT_CODES or not self._grants.is_active("notification.local_alert.render.v1"):
        return None
    request = PluginLocalAlertV1.from_core_safe_alert(alert, ttl=timedelta(seconds=5))
    try:
        result = await self._plugins.invoke_exact("notification.local_alert.render.v1", request)
        return PluginLocalAlertRenderV1.model_validate(result)
    except PluginTerminalFailure:
        return None
    finally:
        await self._core_alerts.assert_unchanged(alert.alert_id)

async def revoke_and_remove(self, plugin_id: str) -> RemovalReceipt:
    await self._grants.increment_generation(plugin_id)
    await self._supervisor.cancel_close_kill(plugin_id)
    await self._supervisor.erase_binary_and_empty_sandboxes(plugin_id)
    return await self._audit.safe_plugin_removal_receipt(plugin_id)
~~~

Reject unlisted alert codes, diagnostic detail and plugin attempts to acknowledge/close/forward/delay. Privacy Shield cancels plugin calls but not core alerts. `CONTAINED_EGRESS` stops external notifications/adapters/updates while local core alert and eligible no-network plugin presentation remain truthful; plugin failure never affects the core surface.

- [ ] **Step 4: Run green, synthetic qualification, and cleanup/content scans**

Run: `uv run pytest tests/integration/plugins/test_local_alert_render.py tests/security/plugins/test_core_alert_non_suppression.py tests/fault/plugins/test_revoke_remove_crash.py tests/privacy/plugins/test_contained_egress_and_shield.py tests/acceptance/phase6/test_plugin_gate.py -q && uv run python scripts/phase6/run_plugin_qualification.py --synthetic --output var/evidence/phase6/plugins-synthetic.json && uv run python scripts/scan_sandbox_residue.py --root var/test-artifacts/plugin-sandboxes --require-empty && uv run python scripts/scan_private_data.py --paths var/evidence/phase6/plugins-synthetic.json && uv run ruff check apps/core/src/tuntun_core/services/hardening/plugin_invocation.py scripts/phase6/run_plugin_qualification.py tests/integration/plugins tests/security/plugins tests/fault/plugins tests/privacy/plugins`
Expected: PASS; both exact capabilities pass, all unknown IDs deny, every terminal path cleans, and core alert survives unchanged.

- [ ] **Step 5: Commit alert path and plugin gate**

~~~bash
git add apps/core/src/tuntun_core/services/hardening/plugin_invocation.py apps/core/src/tuntun_core/services/hardening/incident.py apps/admin/src/features/system/plugins.tsx scripts/phase6/run_plugin_qualification.py docs/operations/phase6-plugins.md tests/integration/plugins/test_local_alert_render.py tests/security/plugins/test_core_alert_non_suppression.py tests/fault/plugins/test_revoke_remove_crash.py tests/privacy/plugins/test_contained_egress_and_shield.py tests/acceptance/phase6/test_plugin_gate.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(plugins): preserve mandatory core alerts"
~~~

## Wave 4 — P6-3 Public Simulator, Supply Chain, macOS Package, and Update/Rollback

### Task 24: Ship a synthetic zero-device simulator and public governance/support boundary

**Depends on:** P6-0 and synthetic fixtures from all accepted phases.
**Gate contribution:** P6-3/P6-5 public-source boundary; T18/T25.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/simulator/phase6.py`
- Create: `scripts/run_public_simulator.py`
- Modify: `README.md`
- Create: `LICENSE`
- Create: `SECURITY.md`
- Create: `CODE_OF_CONDUCT.md`
- Create: `CONTRIBUTING.md`
- Create: `SUPPORT.md`
- Create: `docs/operations/public-simulator.md`
- Test: `tests/acceptance/public/test_zero_device_poc.py`
- Test: `tests/privacy/public/test_public_tree_and_history.py`
- Test: `tests/contract/public/test_support_claims.py`

**Interfaces:** Produces an Apache-2.0 simulator with synthetic owner, devices, remote posture, plugins, update, incident and recovery receipts requiring zero cloud/device/Tailscale/Apple credential. Public docs define stable/migration release support, exact tested profiles, security disclosure and no household diagnostic upload.

**Rollback/disabled exit:** Any private-data or unsupported-capability claim blocks public artifacts. The simulator never auto-enables real adapters or masquerades as household acceptance.

- [ ] **Step 1: Write red zero-dependency, licence, support, and private-history tests**

~~~python
def test_public_simulator_needs_no_external_dependency(simulator_env) -> None:
    result = run_public_simulator(simulator_env.with_no_network_hardware_keychain())
    assert result.exit_code == 0
    assert result.feature_manifest.all_hardware_and_cloud_are_synthetic

def test_public_docs_claim_only_tested_profiles(public_docs, compatibility_manifest) -> None:
    assert claimed_profiles(public_docs) <= tested_supported_profiles(compatibility_manifest)

def test_source_history_docs_and_output_have_no_private_data(repo_and_output) -> None:
    assert scan_private_data(repo_and_output, include_git_history=True).findings == ()
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/acceptance/public/test_zero_device_poc.py tests/privacy/public/test_public_tree_and_history.py tests/contract/public/test_support_claims.py -q`
Expected: FAIL because the simulator and public governance files are absent.

- [ ] **Step 3: Implement deterministic simulator and exact public boundaries**

~~~python
def run_phase6_public_poc(seed: int = 6001) -> PublicPocReceipt:
    scenario = SyntheticSixPhaseHousehold(seed=seed, network=FakeNetwork.denied())
    scenario.assert_no_real_adapters_credentials_or_household_ids()
    scenario.exercise_local_health_remote_absence_plugins_update_restore_incident()
    return scenario.content_safe_receipt()
~~~

Docs explain LAN-only default, Tailscale opt-in, exact plugin registry, local authority, conditional hardware, privacy limits, supported stable/current migration releases, issue-vs-private-disclosure path and redacted diagnostic preview. Include no real screenshots/fixtures/logs/addresses. Maintainer succession/recovery material is project-signing only and conveys no household recovery authority.

- [ ] **Step 4: Run simulator twice, scan source/history/docs/output, and validate licences/links**

Run: `uv run python scripts/run_public_simulator.py --seed 6001 --output var/evidence/phase6/public-poc-a.json && uv run python scripts/run_public_simulator.py --seed 6001 --output var/evidence/phase6/public-poc-b.json && cmp var/evidence/phase6/public-poc-a.json var/evidence/phase6/public-poc-b.json && uv run pytest tests/acceptance/public/test_zero_device_poc.py tests/privacy/public/test_public_tree_and_history.py tests/contract/public/test_support_claims.py -q && uv run python scripts/scan_private_data.py --include-git-history --paths . var/evidence/phase6/public-poc-a.json && uv run python scripts/check_licenses.py --project && uv run python scripts/check_docs_links.py README.md SECURITY.md CONTRIBUTING.md SUPPORT.md docs/operations/public-simulator.md`
Expected: PASS; simulator receipts are byte-identical, zero unsafe findings, Apache-2.0 present, and claims are within tested profiles.

- [ ] **Step 5: Commit simulator and public governance**

~~~bash
git add apps/core/src/tuntun_core/simulator/phase6.py scripts/run_public_simulator.py README.md LICENSE SECURITY.md CODE_OF_CONDUCT.md CONTRIBUTING.md SUPPORT.md docs/operations/public-simulator.md tests/acceptance/public/test_zero_device_poc.py tests/privacy/public/test_public_tree_and_history.py tests/contract/public/test_support_claims.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "docs(public): add the synthetic open-source baseline"
~~~

### Task 25: Harden CI, dependency locks, fork isolation, licences, and private-data scanning

**Depends on:** Task 24 and existing test/build workflows.
**Gate contribution:** P6-3 supply chain; T18/T25.
**Estimated effort:** 1.5 person-days.

**Files:**
- Modify: `.github/workflows/ci.yml`
- Create: `.github/workflows/release-candidate.yml`
- Create: `.github/workflows/attest.yml`
- Modify: `.github/dependabot.yml`
- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Modify: `package.json`
- Modify: `pnpm-lock.yaml`
- Create: `ops/release/licences.py`
- Create: `tests/security/release/test_workflow_permissions.py`
- Create: `tests/security/release/test_fork_secret_isolation.py`
- Create: `tests/acceptance/release/test_locked_dependencies.py`
- Create: `tests/privacy/release/test_ci_artifact_scan.py`

**Interfaces:** Produces least-privilege pinned workflows, deterministic locks, dependency review/licence notices, branch-protection requirements and artifact/private-data scan results. Fork PR workflows receive no privileged environment or credential.

**Rollback/disabled exit:** Floating action/dependency, licence violation, secret-capable fork path, scan gap, or unreviewed generated drift blocks release-candidate workflow. It never disables a scanner to make CI green.

- [ ] **Step 1: Write red workflow pin, permission, fork-secret, lock, and licence tests**

~~~python
def test_all_actions_are_pinned_to_full_commit(workflows) -> None:
    assert all(action.ref_is_full_commit_sha for action in workflows.actions)

def test_fork_jobs_have_no_sensitive_permissions_or_secrets(workflows) -> None:
    for job in workflows.jobs_reachable_from_fork:
        assert job.permissions <= {"contents": "read"}
        assert not job.environment and not job.uses_secret_context

def test_lock_and_licence_policy_is_closed(dependencies) -> None:
    assert all(d.locked_digest_or_hash for d in dependencies)
    assert not dependencies.unapproved_or_unknown_licences
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/security/release/test_workflow_permissions.py tests/security/release/test_fork_secret_isolation.py tests/acceptance/release/test_locked_dependencies.py tests/privacy/release/test_ci_artifact_scan.py -q`
Expected: FAIL because hardened workflows/policy tests and licence tooling are absent.

- [ ] **Step 3: Implement least privilege, immutable references, deterministic locks, and scan gates**

~~~yaml
permissions:
  contents: read

jobs:
  test:
    runs-on: macos-14
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          persist-credentials: false
      - run: make check
      - run: uv run python scripts/scan_private_data.py --paths . var/test-artifacts
~~~

Record the review of each full action commit in the workflow-policy fixture. Separate unprivileged PR CI from protected candidate/attestation workflows; signing/notarization remains outside fork jobs and requires protected environment/manual approval. Add dependency review, secret scan, generated drift, test/coverage, licences/notices, source/history/artifact scan and workflow-policy self-test. No household evidence is uploaded.

- [ ] **Step 4: Run workflow policy, locks, licences, scanners, and full deterministic checks**

Run: `uv run pytest tests/security/release/test_workflow_permissions.py tests/security/release/test_fork_secret_isolation.py tests/acceptance/release/test_locked_dependencies.py tests/privacy/release/test_ci_artifact_scan.py -q && uv lock --check && pnpm install --frozen-lockfile --ignore-scripts && uv run python ops/release/licences.py --check --output var/release/THIRD_PARTY_NOTICES.txt && uv run python scripts/check_workflow_pins.py .github/workflows && uv run python scripts/scan_private_data.py --include-git-history --paths . var/test-artifacts && make check`
Expected: PASS; every action is immutable, fork exposure is zero, locks clean, licences approved, and private scan has zero findings.

- [ ] **Step 5: Commit supply-chain controls**

~~~bash
git add .github/workflows/ci.yml .github/workflows/release-candidate.yml .github/workflows/attest.yml .github/dependabot.yml pyproject.toml uv.lock package.json pnpm-lock.yaml ops/release/licences.py tests/security/release/test_workflow_permissions.py tests/security/release/test_fork_secret_isolation.py tests/acceptance/release/test_locked_dependencies.py tests/privacy/release/test_ci_artifact_scan.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "ci(security): lock the public build boundary"
~~~

### Task 26: Generate and verify SPDX SBOM, provenance, signatures, and immutable release manifests

**Depends on:** Tasks 24–25 and exact feature/evidence manifests.
**Gate contribution:** P6-3 release integrity; T17/T25.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `ops/release/build.py`
- Create: `ops/release/verify.py`
- Create: `ops/release/sbom.py`
- Create: `ops/release/attest.py`
- Create: `ops/release/sign.py`
- Create: `apps/core/src/tuntun_core/services/hardening/release_verifier.py`
- Create: `docs/release/publication.md`
- Test: `tests/contract/release/test_release_manifest.py`
- Test: `tests/security/release/test_release_verifier_denials.py`
- Test: `tests/reproducibility/test_release_build.py`
- Test: `tests/privacy/release/test_release_artifact_contents.py`

**Interfaces:** Produces deterministic artifacts, SPDX SBOM, licences/notices, SLSA L2 Sigstore-backed provenance/attestation, checksum/signature, immutable `ReleaseManifestV1`, and `ReleaseVerifierPort.verify(ReleaseCandidateV1, InstalledReleaseV1) -> ReleaseDecisionV1`; the verifier reads its injected trusted clock and verifies the domain-separated signature over the exact canonical manifest bytes. Denial is a returned closed decision, never an exception that an updater could mistake for approval.

**Rollback/disabled exit:** Wrong/unknown/revoked signer, repository/workflow/builder, SBOM, dependency, tag/artifact, version/downgrade/replay, corruption, expiry, feature/evidence/compatibility mismatch preserves the prior version and blocks publication.

- [ ] **Step 1: Write red reproducibility and every negative-verifier test**

~~~python
@pytest.mark.parametrize("fault", [
    "wrong_signer", "wrong_repository", "wrong_workflow", "unknown_builder", "modified_sbom",
    "dependency_policy", "tag_artifact_mismatch", "downgrade", "replayed_manifest",
    "corrupt_download", "future_issued", "expired_release", "revoked_release",
    "mutated_manifest_reused_signature", "feature_digest", "acceptance_digest",
    "compatibility_digest",
])
def test_release_verifier_preserves_prior_on_any_fault(verifier, candidate, installed, fault) -> None:
    decision = verifier.verify(candidate.with_fault(fault), installed)
    assert decision.install_allowed is False
    assert decision.preserve_version == installed.version

def test_two_clean_builds_are_identical(clean_checkout_a, clean_checkout_b) -> None:
    assert build_release(clean_checkout_a).artifact_digests == build_release(clean_checkout_b).artifact_digests

def test_release_build_emits_unique_safe_named_artifacts(clean_checkout_a) -> None:
    manifest = build_release(clean_checkout_a)
    assert manifest.artifact_digests
    assert len({artifact.artifact_name for artifact in manifest.artifact_digests}) == len(manifest.artifact_digests)
    assert len({artifact.relative_path for artifact in manifest.artifact_digests}) == len(manifest.artifact_digests)
    for artifact in manifest.artifact_digests:
        assert PurePosixPath(artifact.relative_path).name == artifact.artifact_name

def test_valid_signature_cannot_be_replayed_over_changed_manifest(verifier, candidate, installed) -> None:
    changed = candidate.change_manifest_without_resigning(release_channel="migration")
    decision = verifier.verify(changed, installed)
    assert decision.install_allowed is False
    assert decision.reason_code == "release_manifest_signature_invalid"
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/release/test_release_manifest.py tests/security/release/test_release_verifier_denials.py tests/reproducibility/test_release_build.py tests/privacy/release/test_release_artifact_contents.py -q`
Expected: FAIL because release tooling/verifier/manifests are absent.

- [ ] **Step 3: Implement deterministic build graph and strict independent verifier**

~~~python
def verify(self, candidate: ReleaseCandidateV1, installed: InstalledReleaseV1) -> ReleaseDecisionV1:
    now = self._clock.now()
    try:
        manifest = ReleaseManifestV1.model_validate_json(reject_duplicate_json_keys(candidate.manifest_json))
        if manifest.issued_at > now or (manifest.expires_at is not None and now >= manifest.expires_at):
            raise ReleaseDenied("release_manifest_time_invalid")
        canonical_manifest = canonical_hardening_bytes(manifest)
        self._signers.require_current_manifest_signature(
            signer_identity=manifest.signer_identity,
            signature=candidate.manifest_signature,
            domain="tuntun.release-manifest.v1",
            payload=canonical_manifest,
        )
        self._provenance.require_slsa_l2(manifest.provenance_digest, manifest.source_commit,
                                         manifest.source_repository_identity, manifest.workflow_identity)
        self._sbom.require_spdx_and_policy(manifest.sbom_spdx_digest, manifest.dependency_lock_digest)
        assets = self._artifacts.resolve_exact_set(candidate.artifact_set_id, candidate.artifact_set_commitment)
        self._artifacts.require_exact_digests(manifest.artifact_digests, assets)
        self._versions.require_monotonic_nonreplayed(manifest.version, installed.version, manifest.source_commit)
        self._bindings.require_exact_feature_evidence_compatibility(manifest)
    except (ValidationError, DuplicateKeyError, ReleaseVerificationError, ReleaseDenied) as error:
        reason = safe_release_reason(error)
        return ReleaseDecisionV1(
            candidate_id=candidate.candidate_id,
            install_allowed=False,
            preserve_version=installed.version,
            accepted_manifest=None,
            reason_code=reason,
            decided_at=now,
            decision_commitment=self._commitments.for_release_decision(
                candidate.candidate_id, False, installed.version, None, reason, now,
            ),
        )
    return ReleaseDecisionV1(
        candidate_id=candidate.candidate_id,
        install_allowed=True,
        preserve_version=installed.version,
        accepted_manifest=manifest,
        reason_code="release_verified",
        decided_at=now,
        decision_commitment=self._commitments.for_release_decision(
            candidate.candidate_id, True, installed.version, manifest, "release_verified", now,
        ),
    )
~~~

Use clean source-date/build environment, normalized archive metadata/order/permissions, immutable dependency inputs and no household environment. Bind each component package separately to its manifest/compatibility matrix. Attestation uses protected workflow identity; signing/account recovery is project-only and conveys no household recovery. `publish.py` is not called here.

- [ ] **Step 4: Run two clean builds, verify all faults, SBOM/licences/provenance, and scan artifacts**

Run: `uv run pytest tests/contract/release/test_release_manifest.py tests/security/release/test_release_verifier_denials.py tests/reproducibility/test_release_build.py tests/privacy/release/test_release_artifact_contents.py -q && uv run python ops/release/build.py --synthetic --clean-a var/release/a --clean-b var/release/b --assert-reproducible && uv run python ops/release/sbom.py --input var/release/a --format spdx-json --output var/release/a/sbom.spdx.json && uv run python ops/release/attest.py --synthetic --verify var/release/a && uv run python ops/release/verify.py bundle var/release/a && uv run python scripts/scan_private_data.py --paths var/release/a var/release/b && uv run ruff check ops/release apps/core/src/tuntun_core/services/hardening/release_verifier.py tests/contract/release tests/security/release tests/reproducibility tests/privacy/release && uv run mypy ops/release apps/core/src`
Expected: PASS; both clean artifact digests match, every mutated bundle preserves the prior release, and scans find zero private bytes.

- [ ] **Step 5: Commit release integrity tooling**

~~~bash
git add ops/release/build.py ops/release/verify.py ops/release/sbom.py ops/release/attest.py ops/release/sign.py apps/core/src/tuntun_core/services/hardening/release_verifier.py docs/release/publication.md tests/contract/release/test_release_manifest.py tests/security/release/test_release_verifier_denials.py tests/reproducibility/test_release_build.py tests/privacy/release/test_release_artifact_contents.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(release): bind SBOM provenance and signatures"
~~~

### Task 27: Package, sign, notarize, and qualify Intel plus declared Apple Silicon support

**Depends on:** Task 26, Apple Developer Program credentials held outside the repository, and clean supported test Macs.
**Gate contribution:** mandatory P6-3/C1 macOS distribution.
**Estimated effort:** 1.5 person-days plus Apple/clean-machine elapsed time.

**Files:**
- Create: `ops/release/notarize.py`
- Create: `ops/release/compatibility.py`
- Create: `ops/release/entitlements/*.plist`
- Create: `ops/release/package/*.plist`
- Create: `docs/release/compatibility-matrix.md`
- Test: `tests/security/release/test_entitlements.py`
- Test: `tests/acceptance/release/test_macos_package.py`
- Test: `tests/hardware/release/test_intel_clean_install.py`
- Test: `tests/hardware/release/test_apple_silicon_clean_install.py`

**Interfaces:** Produces Developer-ID-signed, hardened-runtime packages; notarization/stapling/Gatekeeper receipts; and an exact compatibility manifest for the supported 2020 Intel target and at least one current Apple Silicon target. Developer builds are separately named/visibly non-production.

**Rollback/disabled exit:** Missing signing/notarization/stapling/Gatekeeper or either architecture's declared compatibility blocks public production/C1. It cannot be replaced by an unsigned archive or “expected compatible” statement.

- [ ] **Step 1: Write red entitlement, developer-label, architecture, and Gatekeeper tests**

~~~python
def test_production_package_has_minimum_reviewed_entitlements(package) -> None:
    assert package.hardened_runtime
    assert package.entitlements == approved_minimum_entitlements()
    assert package.developer_id_identity and package.notarization_ticket_stapled

def test_developer_build_is_visibly_nonproduction(developer_package) -> None:
    assert developer_package.channel == "developer-unsigned"
    assert "NOT FOR PRODUCTION" in developer_package.installer_and_ui_labels

def test_compatibility_has_real_intel_and_apple_silicon_receipts(matrix) -> None:
    assert matrix.supported("x86_64", model_class="2020_intel_macbook_pro")
    assert matrix.current_supported_targets("arm64")
    assert all(row.clean_install_update_rollback_uninstall for row in matrix.supported_rows)
~~~

- [ ] **Step 2: Run red and collect hardware tests**

Run: `uv run pytest tests/security/release/test_entitlements.py tests/acceptance/release/test_macos_package.py -q && uv run pytest tests/hardware/release/test_intel_clean_install.py tests/hardware/release/test_apple_silicon_clean_install.py --collect-only -q`
Expected: software tests FAIL because package/notarization/compatibility tooling is absent; hardware tests collect and skip without explicit clean-Mac flags.

- [ ] **Step 3: Implement architecture-explicit packaging and verification pipeline**

~~~python
def verify_macos_distribution(bundle: MacPackageBundle, receipts: Sequence[MacTargetReceipt]) -> None:
    require(bundle.developer_id_verified and bundle.hardened_runtime_verified)
    require(bundle.entitlements == approved_minimum_entitlements())
    require(bundle.notarized and bundle.ticket_stapled and bundle.gatekeeper_accepted)
    require(any(r.arch == "x86_64" and r.target_class == "2020_intel_macbook_pro" and r.passed for r in receipts))
    require(any(r.arch == "arm64" and r.current_supported_macos and r.passed for r in receipts))
~~~

Package least-privilege services, plugin supervisor/sandbox profile, schemas, licences/notices and simulator without credentials/data. Verify signatures for nested code, entitlements, hardened runtime, installer scripts and uninstall manifest. Run install, launch, simulator, upgrade from supported stable, failed-update rollback, preserve-uninstall and destructive-uninstall rehearsal on each declared architecture.

- [ ] **Step 4: Run synthetic package checks and stage mandatory signed/clean-Mac gates**

Run: `uv run pytest tests/security/release/test_entitlements.py tests/acceptance/release/test_macos_package.py -q && uv run python ops/release/compatibility.py --synthetic --output var/evidence/phase6/compatibility-synthetic.json && uv run python scripts/scan_private_data.py --paths var/evidence/phase6/compatibility-synthetic.json && plutil -lint ops/release/entitlements/*.plist ops/release/package/*.plist && uv run ruff check ops/release/notarize.py ops/release/compatibility.py tests/security/release tests/acceptance/release tests/hardware/release`
Expected: PASS for schema/package simulation. P6-3/C1 remains blocked until Developer ID/notarization plus real Intel and Apple Silicon receipts pass under explicit flags.

- [ ] **Step 5: Commit macOS distribution tooling**

~~~bash
git add ops/release/notarize.py ops/release/compatibility.py ops/release/entitlements ops/release/package docs/release/compatibility-matrix.md tests/security/release/test_entitlements.py tests/acceptance/release/test_macos_package.py tests/hardware/release/test_intel_clean_install.py tests/hardware/release/test_apple_silicon_clean_install.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(release): qualify notarized macOS packages"
~~~

### Task 28: Implement owner-visible atomic updates, quarantined migrations, and rollback

**Depends on:** Tasks 03, 26–27 and accepted backup verifier.
**Gate contribution:** P6-3/P6-4 update resilience; T17/T19.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/services/hardening/updater.py`
- Create: `apps/core/src/tuntun_core/api/routes/releases.py`
- Create: `apps/admin/src/features/system/updates.tsx`
- Create: `apps/admin/src/routes/system-updates.tsx`
- Create: `docs/operations/phase6-update-rollback.md`
- Test: `apps/core/tests/unit/hardening/test_updater.py`
- Test: `tests/integration/release/test_atomic_update.py`
- Test: `tests/fault/release/test_update_failure_matrix.py`
- Test: `tests/ui/phase6/update-review.spec.ts`

**Interfaces:** Produces local-only prepared update review, strict staging/verifier, independently verified encrypted pre-update backup, drain/restore point, quarantined migrations, readiness/policy/privacy/storage/device/network probes, atomic commit or exact rollback, and safe receipt.

**Rollback/disabled exit:** Any ambiguity restores prior signed code/schema/data and leaves changed features quarantined. Remote install and silent update endpoints do not exist.

- [ ] **Step 1: Write red ordering, local-only, fault, prior-version, and UI-summary tests**

~~~python
async def test_update_orders_backup_before_drain_and_install(harness) -> None:
    await harness.run_update()
    assert harness.timeline.index("backup_verified") < harness.timeline.index("drain_started")
    assert harness.timeline.index("drain_started") < harness.timeline.index("install_started")

@pytest.mark.parametrize("fault", [
    "download_oversize", "wrong_type", "verify_failure", "backup_failure", "drain_timeout",
    "migration_interrupt", "readiness_failure", "privacy_failure", "listener_failure",
    "device_failure", "post_install_health_failure",
])
async def test_every_update_fault_preserves_prior(harness, fault) -> None:
    before = harness.installed_snapshot()
    result = await harness.update_with_fault(fault)
    assert result.committed is False
    assert harness.installed_snapshot() == before

async def test_verifier_denial_stops_before_backup_or_install(harness) -> None:
    result = await harness.run_update(verifier_decision="deny")
    assert result.committed is False
    assert result.reason_code == "release_verification_denied"
    assert "backup_started" not in harness.timeline
    assert "install_started" not in harness.timeline

def test_remote_cannot_prepare_or_install_update(remote_client) -> None:
    assert remote_client.post("/api/v1/releases/prepare").json()["code"] == "REMOTE_OPERATION_DENIED"
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/core/tests/unit/hardening/test_updater.py tests/integration/release/test_atomic_update.py tests/fault/release/test_update_failure_matrix.py -q && pnpm --dir apps/admin exec playwright test tests/ui/phase6/update-review.spec.ts`
Expected: FAIL because updater/API/UI and failure state machine are absent.

- [ ] **Step 3: Implement exact ten-stage update state machine and truthful UI**

~~~python
async def install(self, prepared: PreparedUpdate, local_owner: LocalOwnerApproval) -> UpdateReceipt:
    self._auth.consume_local_owner_action_bound(prepared, local_owner)
    staged = await self._downloads.fetch_bounded_unprivileged(prepared.source)
    decision = self._verifier.verify(staged, self._installed.current())
    if not decision.install_allowed:
        return UpdateReceipt.preserved_prior(
            version=decision.preserve_version,
            reason_code="release_verification_denied",
            verifier_reason_code=decision.reason_code,
        )
    manifest = require_not_none(decision.accepted_manifest)
    backup = await self._backups.create_and_independently_verify_preupdate(manifest)
    await self._turns_and_actions.drain_without_replay()
    restore_point = await self._installer.create_restore_point(backup)
    try:
        candidate = await self._installer.install_atomic_staged(staged)
        await self._migrations.run_in_quarantine(candidate)
        await self._probes.require_all(candidate, groups=("readiness", "policy", "privacy", "storage", "device", "network"))
        return await self._installer.commit(candidate, keep_prior=True)
    except Exception as error:
        return await self._installer.restore_exact(restore_point, safe_reason(error))
~~~

The updater consumes only `ReleaseDecisionV1`: a deny decision returns before backup, drain, migration or installer I/O, and an allow decision must carry the exact accepted manifest by contract. UI shows signer/digest/version/security notes/features/migrations/data-egress changes/compatibility/pre-backup/restart/rollback limits, then requires local owner passkey. It never auto-installs. Prior package stays until configured soak; rollback UI shows restored code/schema/health and quarantined features.

- [ ] **Step 4: Run green, exhaustive failure matrix, UI/accessibility, and remote absence**

Run: `uv run pytest apps/core/tests/unit/hardening/test_updater.py tests/integration/release/test_atomic_update.py tests/fault/release/test_update_failure_matrix.py -q && pnpm --dir apps/admin exec playwright test tests/ui/phase6/update-review.spec.ts && uv run python scripts/check_feature_absence.py --feature remote_update_install --phase 6 && pnpm --dir apps/admin typecheck && pnpm --dir apps/admin build && uv run ruff check apps/core/src/tuntun_core/services/hardening/updater.py tests/integration/release tests/fault/release && uv run mypy apps/core/src`
Expected: PASS; every injected failure restores exact prior state, remote route absent, and UI exposes rollback truth.

- [ ] **Step 5: Commit updater and rollback**

~~~bash
git add apps/core/src/tuntun_core/services/hardening/updater.py apps/core/src/tuntun_core/api/routes/releases.py apps/admin/src/features/system/updates.tsx apps/admin/src/routes/system-updates.tsx docs/operations/phase6-update-rollback.md apps/core/tests/unit/hardening/test_updater.py tests/integration/release/test_atomic_update.py tests/fault/release/test_update_failure_matrix.py tests/ui/phase6/update-review.spec.ts
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(update): install atomically or restore prior release"
~~~

### Task 29: Verify clean install, upgrade, rollback, both uninstall modes, and P6-3 go/no-go

**Depends on:** Tasks 19–28 and mandatory real plugin sandbox/signing/platform receipts.
**Gate contribution:** completes P6-3.
**Estimated effort:** 1.5 person-days plus clean-machine runs.

**Files:**
- Create: `ops/install/uninstall.py`
- Modify: `ops/install/verify_clean_system.py`
- Create: `docs/operations/phase6-retirement-uninstall.md`
- Create: `tests/acceptance/release/test_install_upgrade_rollback_uninstall.py`
- Create: `tests/security/release/test_uninstall_residue.py`
- Create: `tests/acceptance/phase6/test_p6_3_gate.py`
- Create: `docs/evidence/phase6-p6-3-schema.json`

**Interfaces:** Produces clean install/upgrade/rollback plus `preserve_encrypted_data` and `destroy_managed_data` uninstall receipts, and a P6-3 decision binding exact two plugin paths, sandbox, build/SBOM/provenance/signature/notarization, Intel/Apple-Silicon compatibility and private scans.

**Rollback/disabled exit:** Failed install/update preserves prior version; failed uninstall stops before ambiguous deletion; failed P6-3 blocks public candidate. Unrelated vendor data and preserved archives are never deleted.

- [ ] **Step 1: Write red preserve/destroy, residue, platform, and complete-gate tests**

~~~python
def test_preserve_uninstall_removes_runtime_but_keeps_encrypted_archives(harness) -> None:
    receipt = harness.uninstall(mode="preserve_encrypted_data")
    assert receipt.services_listeners_firewall_cert_routes_plugins_caches_removed
    assert receipt.encrypted_household_archives_preserved

def test_destroy_uninstall_requires_exact_local_owner_and_discloses_external_copies(harness) -> None:
    assert harness.remote_destroy_attempt().code == "REMOTE_OPERATION_DENIED"
    receipt = harness.local_owner_destroy_with_two_exact_confirmations()
    assert receipt.managed_keys_crypto_shredded
    assert set(receipt.uncontrolled_copy_classes) == {"owner_exports", "vendor_state", "provider_history"}

def test_p6_3_requires_both_plugin_paths_and_both_architectures(evidence) -> None:
    assert decide_p6_3(evidence.without("notification.local_alert.render.v1")).denied
    assert decide_p6_3(evidence.without("arm64_compatibility")).denied
    assert decide_p6_3(evidence.without("preserve_encrypted_data_uninstall")).denied
    assert decide_p6_3(evidence.without("destroy_managed_data_uninstall")).denied
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/acceptance/release/test_install_upgrade_rollback_uninstall.py tests/security/release/test_uninstall_residue.py tests/acceptance/phase6/test_p6_3_gate.py -q`
Expected: FAIL because uninstall orchestration and P6-3 oracle are absent.

- [ ] **Step 3: Implement exact uninstall manifests and immutable P6-3 verifier**

~~~python
def uninstall(self, prepared: PreparedUninstall, approval: LocalOwnerApproval) -> UninstallReceipt:
    self._auth.consume_local_owner(prepared, approval, require_local_presence=True)
    self._services.stop_and_remove_all_tuntun_jobs()
    self._network.remove_exact_tuntun_listeners_firewall_certs_and_vpn_route()
    self._plugins.revoke_remove_all()
    self._temporary.remove_verified_owned_paths_only()
    if prepared.mode == "destroy_managed_data":
        self._destruction.crypto_shred_exact_committed_managed_set(prepared.data_set_commitment)
    return self._verification.assert_no_runtime_residue_and_disclose_external_copies(prepared.mode)

def decide_p6_3(evidence: P6ThreeEvidence) -> GateDecision:
    require(evidence.plugin_capabilities == INITIAL_PLUGIN_CAPABILITY_IDS)
    require(evidence.plugin_isolation_and_cleanup_passed)
    require(evidence.reproducible_build_sbom_provenance_signature_passed)
    require(evidence.developer_id_notarization_stapling_gatekeeper_passed)
    require(evidence.intel_passed and evidence.apple_silicon_passed)
    require(evidence.clean_install_update_rollback_passed)
    require(evidence.preserve_encrypted_data_uninstall_passed)
    require(evidence.destroy_managed_data_uninstall_passed)
    require(evidence.private_findings == 0)
    return GateDecision.accept("P6-3", evidence.digest())
~~~

Uninstall resolves explicit owned paths/identities before removal, never broad globs. Preserve keeps encrypted household data and offline recovery material. Destroy requires set/count commitment and second local confirmation, removes managed Keychain/data/plugin/cache/temp material, records unverifiable SSD residual bytes, and never claims owner/vendor/cloud erasure.

- [ ] **Step 4: Run green synthetic lifecycle and verify real-evidence requirements**

Run: `uv run pytest tests/acceptance/release/test_install_upgrade_rollback_uninstall.py tests/security/release/test_uninstall_residue.py tests/acceptance/phase6/test_p6_3_gate.py -q && uv run python ops/install/verify_clean_system.py --synthetic-lifecycle --target-receipt var/evidence/phase6/install-lifecycle-synthetic.json && uv run python scripts/scan_private_data.py --paths var/evidence/phase6/install-lifecycle-synthetic.json && uv run ruff check ops/install/uninstall.py ops/install/verify_clean_system.py tests/acceptance/release tests/security/release tests/acceptance/phase6`
Expected: PASS for synthetic lifecycle. P6-3 remains denied unless referenced real sandbox, signing/notarization, Intel, Apple Silicon and clean-machine receipt digests all verify.

- [ ] **Step 5: Commit uninstall and P6-3 gate**

~~~bash
git add ops/install/uninstall.py ops/install/verify_clean_system.py docs/operations/phase6-retirement-uninstall.md tests/acceptance/release/test_install_upgrade_rollback_uninstall.py tests/security/release/test_uninstall_residue.py tests/acceptance/phase6/test_p6_3_gate.py docs/evidence/phase6-p6-3-schema.json
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(release): gate the complete Phase 6 package lifecycle"
~~~

## Wave 5 — P6-4 Independent Recovery, Incident Containment, Retirement, and Operations

### Task 30: Create independently stored encrypted recovery copies with owner-only key authority

**Depends on:** accepted existing attached-backup service, Tasks 03–06, and an owner-selected independent encrypted medium or approved object adapter.
**Gate contribution:** P6-4 recovery tier; T19–T20/T22.
**Estimated effort:** 1.5 person-days plus storage qualification.

**Files:**
- Create: `apps/core/src/tuntun_core/services/hardening/recovery.py`
- Create: `ops/backup/create_independent.py`
- Create: `ops/backup/verify_independent.py`
- Create: `docs/operations/phase6-backup-restore.md`
- Test: `apps/core/tests/unit/hardening/test_independent_backup.py`
- Test: `tests/security/recovery/test_owner_only_recovery_authority.py`
- Test: `tests/privacy/recovery/test_portable_secret_exclusions.py`
- Test: `tests/fault/recovery/test_independent_copy_failures.py`

**Interfaces:** Produces at least one current independently stored, owner-controlled encrypted Tuntun/Green configuration generation and a `BackupSetV1`/verification receipt. Attached tier retains seven daily/four weekly. Raw camera retention and live provider/VPN/Mac-leaf-TLS/device/release-signing credentials are excluded.

**Rollback/disabled exit:** Missing/unverified independent copy blocks P6-4/new imports/updates where backup policy requires but never writes plaintext or substitutes the attached SSD as an independent site.

- [ ] **Step 1: Write red authority, tier, exclusion, theft, and failure tests**

~~~python
@pytest.mark.parametrize("actor", ["adult_partner", "guardian", "maintainer", "plugin_publisher", "remote_owner"])
def test_nonowner_cannot_create_import_or_decrypt_recovery(harness, actor) -> None:
    assert harness.recovery_attempt(actor).code in {"POLICY_DENIED", "REMOTE_OPERATION_DENIED"}

def test_portable_recovery_excludes_live_credentials_and_video(archive_manifest) -> None:
    assert set(archive_manifest.excluded_classes) >= {
        "provider_credentials", "vpn_credentials", "mac_leaf_tls", "device_credentials",
        "release_signing_credentials", "routine_camera_retention",
    }

def test_stolen_archive_is_confidential_without_offline_key(stolen_archive) -> None:
    assert stolen_archive.decrypt_without_owner_material().plaintext_bytes == 0

def test_independent_copy_is_not_attached_failure_domain(backup_set) -> None:
    assert backup_set.independent.volume_or_adapter_commitment != backup_set.attached.volume_commitment
    assert backup_set.independent.failure_domain_commitment != backup_set.attached.failure_domain_commitment
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/core/tests/unit/hardening/test_independent_backup.py tests/security/recovery/test_owner_only_recovery_authority.py tests/privacy/recovery/test_portable_secret_exclusions.py tests/fault/recovery/test_independent_copy_failures.py -q`
Expected: FAIL because independent copy orchestration and exclusion verifier are absent.

- [ ] **Step 3: Implement owner-local backup creation, encryption, verification, and rotation**

~~~python
async def create_independent(self, prepared, approval, destination) -> BackupSetV1:
    self._auth.consume_local_owner(prepared, approval, require_local_presence=True)
    binding = self._destinations.require_independent_encrypted_owner_controlled(destination)
    snapshot = await self._sources.freeze_authorized_portable_state(exclude=PORTABLE_SECRET_AND_VIDEO_EXCLUSIONS)
    archive = await self._archives.encrypt_for_offline_recovery(snapshot, binding)
    verification = await self._archives.verify_ciphertext_manifest_and_restore_probe(archive, binding)
    return await self._repository.record_verified_independent(archive.safe_manifest(), verification)
~~~

Use purpose-separated offline recovery recipient/key ceremony, strict volume/adapter binding, quota/reserve, authenticated encryption/manifests, temporary plaintext prohibition, atomic write/fsync/rename and safe pruning. Object storage is optional only after an explicit encrypted adapter policy; provider cannot decrypt. Review recovery material annually and after owner-device/router/OS/provider/signing events.

- [ ] **Step 4: Run green, 7/4 retention simulation, theft/failure matrix, and artifact scan**

Run: `uv run pytest apps/core/tests/unit/hardening/test_independent_backup.py tests/security/recovery/test_owner_only_recovery_authority.py tests/privacy/recovery/test_portable_secret_exclusions.py tests/fault/recovery/test_independent_copy_failures.py -q && uv run python ops/backup/create_independent.py --synthetic --output var/evidence/phase6/independent-backup-synthetic.json && uv run python ops/backup/verify_independent.py --synthetic var/evidence/phase6/independent-backup-synthetic.json && uv run python scripts/scan_backup_artifacts.py --root var/test-artifacts/recovery --require-encrypted --forbid-live-credentials,video,plaintext && uv run ruff check apps/core/src/tuntun_core/services/hardening/recovery.py ops/backup tests/security/recovery tests/privacy/recovery tests/fault/recovery && uv run mypy apps/core/src ops/backup`
Expected: PASS; attached 7/4 plus distinct current independent copy verify, stolen archive yields no plaintext, and excluded classes are absent.

- [ ] **Step 5: Commit independent recovery copy**

~~~bash
git add apps/core/src/tuntun_core/services/hardening/recovery.py ops/backup/create_independent.py ops/backup/verify_independent.py docs/operations/phase6-backup-restore.md apps/core/tests/unit/hardening/test_independent_backup.py tests/security/recovery/test_owner_only_recovery_authority.py tests/privacy/recovery/test_portable_secret_exclusions.py tests/fault/recovery/test_independent_copy_failures.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(recovery): add independent encrypted copies"
~~~

### Task 31: Restore on an isolated clean Mac with deletion-no-resurrection and phased reconciliation

**Depends on:** Task 30, all accepted phase restore hooks, and an isolated target.
**Gate contribution:** P6-4 restore; T19–T20.
**Estimated effort:** 2 person-days plus quarterly-style drill.

**Files:**
- Create: `ops/backup/restore_isolated.py`
- Modify: `apps/core/src/tuntun_core/services/hardening/recovery.py`
- Create: `scripts/phase6/run_restore_drill.py`
- Create: `docs/evidence/phase6-restore-schema.json`
- Test: `tests/integration/recovery/test_phase6_clean_restore.py`
- Test: `tests/security/recovery/test_restore_authority_quarantine.py`
- Test: `tests/privacy/recovery/test_deletion_no_resurrection.py`
- Test: `tests/fault/recovery/test_restore_failure_matrix.py`

**Interfaces:** Produces an owner-only `RestoreRunV1` and signed drill receipt verifying archive/signature, offline-key reconstruction, SQLCipher/audit/migrations, deletion reconciliation, credential exclusions, route quarantine, device re-pairing and one-phase-at-a-time enablement under new generations.

**Rollback/disabled exit:** Any key/integrity/migration/deletion/topology/credential uncertainty preserves source/archives read-only and leaves `RECOVERY_QUARANTINE`; it never guesses, skips a tombstone, or opens an action route.

- [ ] **Step 1: Write red owner-only, quarantine, deletion, credential, and interruption tests**

~~~python
@pytest.mark.parametrize("actor", ["adult_partner", "guardian", "public_maintainer", "plugin_publisher", "remote_owner"])
def test_restore_has_no_delegated_authority(harness, actor) -> None:
    assert harness.prepare_restore(actor).code in {"POLICY_DENIED", "REMOTE_OPERATION_DENIED"}

def test_restored_deleted_profile_and_authority_do_not_exist(restored) -> None:
    assert restored.profile("subject_deleted_synth") is None
    assert restored.memories_for("subject_deleted_synth") == ()
    assert restored.sessions_grants_credentials_for("subject_deleted_synth") == ()
    assert restored.backup_generations_containing("subject_deleted_synth") == ()

def test_restore_opens_no_effect_route_before_reconcile(restored) -> None:
    assert restored.incident_state == "recovery_quarantine"
    assert restored.open_effect_routes == ()
    assert restored.live_provider_vpn_device_signing_credentials == ()
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/recovery/test_phase6_clean_restore.py tests/security/recovery/test_restore_authority_quarantine.py tests/privacy/recovery/test_deletion_no_resurrection.py tests/fault/recovery/test_restore_failure_matrix.py -q`
Expected: FAIL because clean restore/reconciliation and deletion oracle are absent.

- [ ] **Step 3: Implement exact quarantined restore sequence and deletion precedence**

~~~python
async def restore(self, archive, offline_key, prepared, approval) -> RestoreRunV1:
    self._auth.consume_local_owner(prepared, approval, require_local_presence=True)
    verified = self._archives.verify_before_decrypt(archive)
    target = self._targets.create_isolated_empty()
    state = await self._archives.restore_with_offline_key(verified, offline_key, target)
    await self._incident.enter_recovery_quarantine(target)
    await self._migrations.run_quarantined(state)
    await self._integrity.require_sqlcipher_audit_and_manifests(state)
    await self._deletions.apply_tombstones_and_purge_managed_generations(state)
    await self._credentials.assert_excluded_live_classes_absent(state)
    await self._routes.assert_all_effect_routes_closed(state)
    return await self._reconcile.issue_new_generations_and_enable_one_phase_at_a_time(state)
~~~

Recreate Keychain purpose roots and excluded credentials, re-pair devices, verify canonical subject/guardian/audience state, topology/camera/media/knowledge/plugin bindings and feature absence. A deletion reconciliation produces a clean generation within 24 hours and makes affected old generations immediately ineligible. Record physical byte-erasure limits and owner-export/vendor/provider exclusions.

- [ ] **Step 4: Run green synthetic drill, all interruption points, and clean-target scan**

Run: `uv run pytest tests/integration/recovery/test_phase6_clean_restore.py tests/security/recovery/test_restore_authority_quarantine.py tests/privacy/recovery/test_deletion_no_resurrection.py tests/fault/recovery/test_restore_failure_matrix.py -q && uv run python scripts/phase6/run_restore_drill.py --synthetic --deleted-subject subject_deleted_synth --output var/evidence/phase6/restore-synthetic.json && uv run python scripts/scan_private_data.py --paths var/evidence/phase6/restore-synthetic.json && uv run ruff check ops/backup/restore_isolated.py scripts/phase6/run_restore_drill.py tests/integration/recovery tests/security/recovery tests/privacy/recovery tests/fault/recovery && uv run mypy ops/backup apps/core/src`
Expected: PASS; deleted subject never returns, excluded credentials are absent, and every failure remains quarantined with zero effect route.

- [ ] **Step 5: Commit clean restore and deletion reconciliation**

~~~bash
git add ops/backup/restore_isolated.py apps/core/src/tuntun_core/services/hardening/recovery.py scripts/phase6/run_restore_drill.py docs/evidence/phase6-restore-schema.json tests/integration/recovery/test_phase6_clean_restore.py tests/security/recovery/test_restore_authority_quarantine.py tests/privacy/recovery/test_deletion_no_resurrection.py tests/fault/recovery/test_restore_failure_matrix.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(recovery): restore without resurrecting deleted authority"
~~~

### Task 32: Implement incident containment and mandatory local critical-alert continuity

**Depends on:** Tasks 04, 08, 13, 23, 28, 30–31 and accepted local privacy/safety surfaces.
**Gate contribution:** P6-4 incident response; T13–T24.
**Estimated effort:** 2 person-days.

**Files:**
- Modify: `apps/core/src/tuntun_core/services/hardening/incident.py`
- Create: `apps/core/src/tuntun_core/api/routes/incidents.py`
- Create: `apps/admin/src/features/system/incidents.tsx`
- Create: `apps/admin/src/routes/system-incidents.tsx`
- Create: `docs/operations/phase6-incidents.md`
- Create: `ops/runbooks/phase6/*.md`
- Test: `apps/core/tests/unit/hardening/test_incident_state_machine.py`
- Test: `tests/integration/phase6/test_containment_effects.py`
- Test: `tests/security/phase6/test_incident_exit_authority.py`
- Test: `tests/fault/phase6/test_local_alert_survival.py`
- Test: `tests/ui/phase6/incidents.spec.ts`

**Interfaces:** Produces exact incident transitions, local offline entry, transactional containment effects, local alert/status truth, owner-only local exit with new generations, safe incident receipts and runbooks for every named Phase 6 scenario.

**Rollback/disabled exit:** Entry is privacy/safety enhancing and available locally without model/internet. Failed exit remains contained/quarantined; it never partially resumes old sessions/credentials/actions.

- [ ] **Step 1: Write red state, effect, local-alert, no-model, and exit-authority tests**

~~~python
def test_incident_transitions_are_closed(machine) -> None:
    assert machine.allowed == {
        "normal": {"contained_remote"},
        "contained_remote": {"normal", "contained_egress"},
        "contained_egress": {"normal", "recovery_quarantine"},
        "recovery_quarantine": {"normal"},
    }

async def test_contained_egress_preserves_mandatory_local_alerts(harness) -> None:
    await harness.enter("contained_egress", internet=False, model=False)
    assert harness.outbound_cloud_search_notifications_updates == ()
    assert harness.nonlocal_adapter_egress == ()
    assert harness.local_console_critical_alerts.available
    assert harness.physical_status_surfaces.available

@pytest.mark.parametrize("actor", ["remote_owner", "adult_partner", "guardian", "maintainer", "plugin"])
def test_only_local_owner_can_exit_with_new_generations(harness, actor) -> None:
    assert harness.exit_incident(actor).code in {"POLICY_DENIED", "REMOTE_OPERATION_DENIED"}
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/core/tests/unit/hardening/test_incident_state_machine.py tests/integration/phase6/test_containment_effects.py tests/security/phase6/test_incident_exit_authority.py tests/fault/phase6/test_local_alert_survival.py -q && pnpm --dir apps/admin exec playwright test tests/ui/phase6/incidents.spec.ts`
Expected: FAIL because incident orchestration/routes/UI/runbooks are absent.

- [ ] **Step 3: Implement transactional containment and verified owner-only exit**

~~~python
async def enter(self, target: IncidentState, reason: SafeReasonCode) -> IncidentStateV1:
    async with self._uow.authoritative() as tx:
        incident = await tx.incidents.transition_closed(target, reason)
        effects = INCIDENT_EFFECTS[target]
        await tx.authorities.revoke(effects.authorities)
        await tx.sessions.increment_generations(effects.session_classes)
        await tx.audit.append_safe("incident.entered", incident.commitment())
        await tx.outbox.add_many(effects.after_commit_stop_requests(incident))
    await self._local_alerts.require_mandatory_surface(incident)
    return incident

async def exit(self, prepared, local_owner, checks) -> IncidentStateV1:
    self._auth.consume_local_owner(prepared, local_owner, require_local_presence=True)
    require(checks.integrity and checks.secret_rotation and checks.credential_recreation)
    require(checks.network_exposure and checks.deletion_reconciliation and checks.safety)
    return await self._incidents.exit_with_new_controller_and_session_generations()
~~~

Runbooks cover lost owner device/lockout, stolen Mac/Reachy/room node, camera/HA/plugin/provider/VPN compromise, leaked key, malicious release, DB/audit corruption, deleted data, storage/full disk, public-data exposure, power/network/router reset and unsafe robot state. They state irrecoverable limits and forbid public private-diagnostic uploads.

- [ ] **Step 4: Run green, complete containment fault matrix, UI/accessibility, and runbook lint**

Run: `uv run pytest apps/core/tests/unit/hardening/test_incident_state_machine.py tests/integration/phase6/test_containment_effects.py tests/security/phase6/test_incident_exit_authority.py tests/fault/phase6/test_local_alert_survival.py -q && pnpm --dir apps/admin exec playwright test tests/ui/phase6/incidents.spec.ts && uv run python scripts/check_runbooks.py ops/runbooks/phase6 --required-scenarios lost-device,owner-lockout,stolen-host,camera,home-assistant,plugin,provider,vpn,key,release,database,audit,deleted-data,storage,power,network,router,robot,public-data && uv run ruff check apps/core/src/tuntun_core/services/hardening/incident.py tests/integration/phase6 tests/security/phase6 tests/fault/phase6 && uv run mypy apps/core/src`
Expected: PASS; all containment effects stop, mandatory local alerts remain, and exit always rotates generations after owner verification.

- [ ] **Step 5: Commit incident coordination and runbooks**

~~~bash
git add apps/core/src/tuntun_core/services/hardening/incident.py apps/core/src/tuntun_core/api/routes/incidents.py apps/admin/src/features/system/incidents.tsx apps/admin/src/routes/system-incidents.tsx docs/operations/phase6-incidents.md ops/runbooks/phase6 apps/core/tests/unit/hardening/test_incident_state_machine.py tests/integration/phase6/test_containment_effects.py tests/security/phase6/test_incident_exit_authority.py tests/fault/phase6/test_local_alert_survival.py tests/ui/phase6/incidents.spec.ts
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(incident): preserve local safety during containment"
~~~

### Task 33: Retire devices and recover owner lockout without delegating household authority

**Depends on:** Tasks 30–32 and existing topology/key/session/device services.
**Gate contribution:** P6-4 retirement/recovery; T06/T13/T18/T22/T25.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/services/hardening/retirement.py`
- Create: `apps/core/src/tuntun_core/services/hardening/owner_lockout.py`
- Create: `scripts/phase6/run_retirement_drill.py`
- Modify: `docs/operations/phase6-retirement-uninstall.md`
- Create: `tests/integration/phase6/test_device_retirement.py`
- Create: `tests/security/phase6/test_owner_lockout_authority.py`
- Create: `tests/fault/phase6/test_retired_device_reconnect.py`
- Create: `tests/acceptance/phase6/test_retirement_drill.py`

**Interfaces:** Produces local owner action-bound retirement and offline owner-lockout ceremonies, revoking exact certificates/keys/sessions/grants/topology/media/vendor tokens, managed storage keys and reconnect authority. It records unverifiable residual/vendor storage truth.

**Rollback/disabled exit:** An incomplete revoke/wipe/reconnect proof leaves the device `retirement_quarantined`; no replacement actor gains recovery authority and no device is declared wiped without evidence.

- [ ] **Step 1: Write red delegation, exact-device, reconnect, vendor, and residual-storage tests**

~~~python
@pytest.mark.parametrize("actor", ["adult_partner", "guardian", "maintainer", "plugin_publisher", "remote_owner"])
def test_retirement_and_lockout_recovery_have_no_delegation(harness, actor) -> None:
    assert harness.retire(actor).code in {"POLICY_DENIED", "REMOTE_OPERATION_DENIED"}
    assert harness.recover_owner(actor).code in {"POLICY_DENIED", "REMOTE_OPERATION_DENIED"}

async def test_retired_device_cannot_reconnect_replay_or_repair(harness) -> None:
    receipt = await harness.retire_local_owner("device_synth_01")
    assert receipt.lifecycle == "retired"
    assert receipt.reconnect_state == "old_identity_denied"
    assert await harness.connect_old_device() == "denied"
    assert await harness.replay_old_message() == "denied"

def test_retirement_truthfully_records_unverifiable_storage(receipt) -> None:
    assert receipt.vendor_reset_state in {
        "verified_reset", "verified_attempt_unverifiable_storage", "not_applicable",
    }
    assert not receipt.claims_physical_flash_erasure

@pytest.mark.parametrize("crash_after", [
    "authority_revocation", "vendor_reset_checkpoint", "managed_storage_checkpoint", "reconnect_checkpoint",
])
async def test_interrupted_retirement_never_claims_retired(harness, crash_after) -> None:
    await harness.retire_with_crash("device_synth_01", crash_after=crash_after)
    state = await harness.retirement_state("device_synth_01")
    assert state.lifecycle == "retirement_quarantined"
    assert state.authorities_revoked
    assert not await harness.has_event("device.retired", state.retirement_id)
    assert await harness.connect_old_device() == "denied"

async def test_retry_resumes_same_quarantine_and_retires_only_after_all_evidence(harness) -> None:
    first = await harness.retire_with_crash("device_synth_01", crash_after="managed_storage_checkpoint")
    receipt = await harness.resume_retirement(first.retirement_id)
    assert receipt.retirement_id == first.retirement_id
    assert receipt.lifecycle == "retired"
    assert receipt.vendor_reset_state != "pending"
    assert receipt.managed_storage_state != "pending"
    assert receipt.reconnect_state == "old_identity_denied"
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/phase6/test_device_retirement.py tests/security/phase6/test_owner_lockout_authority.py tests/fault/phase6/test_retired_device_reconnect.py tests/acceptance/phase6/test_retirement_drill.py -q`
Expected: FAIL because retirement/lockout state machines and receipts are absent.

- [ ] **Step 3: Implement exact committed-set retirement and sealed-material owner recovery**

~~~python
async def retire(self, prepared, local_owner) -> RetirementReceiptV1:
    self._auth.consume_local_owner(prepared, local_owner, require_local_presence=True)
    device = await self._topology.require_exact_generation(prepared.device_id, prepared.device_generation)
    await self._features.stop_dependents(device)
    await self._exports.perform_only_prepared_owner_exports(prepared.export_set_commitment)
    async with self._uow.authoritative() as tx:
        retirement = await tx.retirements.enter_quarantine_exact(
            device=device,
            prepared_set_commitment=prepared.complete_set_commitment,
        )
        await tx.authorities.revoke_device_everywhere(device)
        retirement = await tx.retirements.mark_authorities_revoked_and_increment_generations(retirement)
        await tx.audit.append_safe("device.retirement_quarantined", retirement.state_commitment)

    vendor = await self._vendor.perform_and_verify_reset_truth(device, retirement.retirement_id)
    await self._retirements.checkpoint_vendor_result(retirement.retirement_id, vendor)
    managed = await self._storage.crypto_shred_and_verify_exact_managed_set(
        prepared.managed_set_commitment,
        retirement.retirement_id,
    )
    await self._retirements.checkpoint_managed_storage_result(retirement.retirement_id, managed)
    reconnect = await self._pairing.prove_old_identity_denied(device)
    await self._retirements.checkpoint_reconnect_result(retirement.retirement_id, reconnect)

    async with self._uow.authoritative() as tx:
        current = await tx.retirements.require_quarantined_with_all_effect_evidence(retirement.retirement_id)
        await tx.topology.mark_retired_exact(device, current.authority_revocation_generation)
        retired = await tx.retirements.finalize_retired(current, retired_at=self._clock.now())
        await tx.audit.append_safe("device.retired", retired.state_commitment)
        return RetirementReceiptV1.from_verified_state(retired)
~~~

The durable lifecycle is `active -> retirement_quarantined -> retired`. The first transaction atomically quarantines the exact device, revokes all authority and increments its generations before any reset/wipe proof is attempted. Every external effect has an idempotent persisted checkpoint; a crash or unverifiable required effect leaves the device quarantined and reconnect-denied. Finalization uses compare-and-swap and can emit `device.retired` only after the vendor-attempt truth, managed-storage result and old-identity denial are all verified. A vendor that cannot prove physical flash erasure is recorded as `verified_attempt_unverifiable_storage`, never as wiped. Owner lockout uses independently sealed offline recovery material on a clean local ceremony, validates archive/system integrity, revokes prior owner sessions/passkeys/remote nodes, creates new owner passkey and generations, then requires backup/revoke test. Maintainer/project signing recovery remains cryptographically and procedurally separate.

- [ ] **Step 4: Run green, 100 reconnect/replay attempts, and owner-lockout drill**

Run: `uv run pytest tests/integration/phase6/test_device_retirement.py tests/security/phase6/test_owner_lockout_authority.py tests/fault/phase6/test_retired_device_reconnect.py tests/acceptance/phase6/test_retirement_drill.py -q && uv run python scripts/phase6/run_retirement_drill.py --synthetic --reconnect-attempts 100 --output var/evidence/phase6/retirement-synthetic.json && uv run python scripts/scan_private_data.py --paths var/evidence/phase6/retirement-synthetic.json && uv run ruff check apps/core/src/tuntun_core/services/hardening/retirement.py apps/core/src/tuntun_core/services/hardening/owner_lockout.py scripts/phase6/run_retirement_drill.py tests/integration/phase6 tests/security/phase6 tests/fault/phase6 tests/acceptance/phase6 && uv run mypy apps/core/src`
Expected: PASS; all old identity attempts deny, no actor other than local owner succeeds, and residual storage is explicit.

- [ ] **Step 5: Commit retirement and owner lockout recovery**

~~~bash
git add apps/core/src/tuntun_core/services/hardening/retirement.py apps/core/src/tuntun_core/services/hardening/owner_lockout.py scripts/phase6/run_retirement_drill.py docs/operations/phase6-retirement-uninstall.md tests/integration/phase6/test_device_retirement.py tests/security/phase6/test_owner_lockout_authority.py tests/fault/phase6/test_retired_device_reconnect.py tests/acceptance/phase6/test_retirement_drill.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(recovery): retire devices under sole-owner authority"
~~~

### Task 34: Measure full Phase 1–6 maintenance and freeze expansion after sustained excess

**Depends on:** Task 03 and all enabled subsystem health summaries.
**Gate contribution:** P6-4 and non-compressible C0 operations evidence.
**Estimated effort:** 1.5 person-days plus a non-compressible evidence window: logging may begin after 60 steady-state days, while promotion evaluation requires at least 90 steady-state days and three complete monthly buckets.

**Files:**
- Create: `apps/core/src/tuntun_core/services/hardening/maintenance.py`
- Create: `scripts/phase6/evaluate_maintenance.py`
- Create: `docs/operations/phase6-maintenance.md`
- Create: `docs/evidence/phase6-maintenance-schema.json`
- Test: `apps/core/tests/unit/hardening/test_maintenance_evaluator.py`
- Test: `tests/property/phase6/test_maintenance_accounting.py`
- Test: `tests/security/phase6/test_expansion_freeze.py`
- Test: `tests/acceptance/phase6/test_maintenance_gate.py`

**Interfaces:** Produces subsystem-attributed `MaintenanceMonthV1` records for complete UTC calendar months only, each bound to one uninterrupted server-owned steady-state generation/epoch and a derived day-60 logging boundary, plus rolling three-month median, target status, three-consecutive-overage expansion freeze, and simplification/retirement review state. It consumes owner-entered durations and signed health/update receipts, never a caller-supplied elapsed-day count and never surveillance/behavior inference. The evaluator reads its trusted clock/current steady-state record, rejects duplicate/gapped/mixed-generation/stale months, requires the complete uninterrupted eligible series through the latest closed month, uses the latest three for promotion/median, and scans every eligible consecutive three-month window for a durable overage trigger. A clearance records the exact evaluated-through month so pre-clear history cannot immediately re-latch the freeze.

**Rollback/disabled exit:** Insufficient elapsed evidence is `not_yet_eligible`, not a synthetic pass. Three consecutive months over 8 hours freezes optional expansion; only a local owner evidence-bound simplification/retirement review can clear it.

- [ ] **Step 1: Write red exact-window, median, categories, and freeze tests**

~~~python
async def test_elapsed_time_comes_only_from_trusted_epoch_and_clock(evaluator) -> None:
    evaluator.clock.set(evaluator.steady_epoch.started_at + timedelta(days=89))
    assert (await evaluator.evaluate(())).state == "not_yet_eligible"

async def test_first_gate_needs_latest_three_complete_eligible_months(evaluator) -> None:
    assert (await evaluator.evaluate(months(minutes=[300, 300]))).state == "not_yet_eligible"

@pytest.mark.parametrize("mutator", [mix_generation, duplicate_month, gap_middle, drop_latest])
async def test_mixed_duplicate_gapped_or_stale_months_fail_closed(evaluator, mutator) -> None:
    decision = await evaluator.evaluate(mutator(months(minutes=[300, 300, 300])))
    assert decision.state == "not_yet_eligible"

def test_partial_month_cannot_be_constructed(valid_month_payload) -> None:
    partial = valid_month_payload | {"period_end_exclusive": valid_month_payload["period_end_exclusive"] - timedelta(days=1)}
    with pytest.raises(ValidationError, match="maintenance_period_not_complete_calendar_month"):
        MaintenanceMonthV1.model_validate(partial)

async def test_rolling_three_month_median_target_is_eight_hours(evaluator) -> None:
    decision = await evaluator.evaluate(months(minutes=[420, 480, 540]))
    assert decision.rolling_three_month_median_minutes == 480
    assert decision.target_met

async def test_three_consecutive_months_above_eight_hours_freeze_expansion(evaluator) -> None:
    decision = await evaluator.evaluate(months(minutes=[481, 700, 482]))
    assert decision.expansion_frozen

async def test_delayed_evaluation_still_latches_historical_consecutive_overage(evaluator) -> None:
    decision = await evaluator.evaluate(months(minutes=[481, 700, 482, 120]))
    assert decision.expansion_frozen

async def test_freeze_is_latched_after_a_later_good_window(evaluator) -> None:
    first = await evaluator.evaluate(months(minutes=[481, 700, 482]))
    evaluator.advance_to_next_three_complete_months()
    later = await evaluator.evaluate(months(minutes=[481, 700, 482, 120, 180, 240]))
    assert first.expansion_frozen and later.expansion_frozen
    assert later.freeze_generation == first.freeze_generation

async def test_only_local_owner_evidence_bound_review_clears_freeze(evaluator, clearance, local_owner) -> None:
    frozen = await evaluator.evaluate(months(minutes=[481, 700, 482]))
    with pytest.raises(PolicyDenied):
        await evaluator.clear_freeze(clearance, actor="maintainer")
    with pytest.raises(EvidenceMismatch):
        await evaluator.clear_freeze(clearance.model_copy(update={"resulting_feature_manifest_digest": WRONG_DIGEST}), local_owner)
    cleared = await evaluator.clear_freeze(clearance, local_owner)
    assert cleared.state == "clear"
    assert cleared.generation == frozen.freeze_generation + 1
    assert cleared.clear_review_commitment is not None
    evaluator.advance_to_next_three_complete_months()
    after_clear = await evaluator.evaluate(months(minutes=[481, 700, 482, 120, 180, 240]))
    assert not after_clear.expansion_frozen

def test_drills_incidents_and_repairs_do_not_reduce_ordinary_total(month) -> None:
    assert month.ordinary_total_minutes == sum(month.ordinary_minutes_by_subsystem.values())
    assert set(month.excluded_minutes_by_class) == {
        "commissioning", "quarterly_restore", "security_drill", "physical_safety_drill",
        "incident", "hardware_replacement", "unplanned_repair", "major_migration",
    }
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/core/tests/unit/hardening/test_maintenance_evaluator.py tests/property/phase6/test_maintenance_accounting.py tests/security/phase6/test_expansion_freeze.py tests/acceptance/phase6/test_maintenance_gate.py -q`
Expected: FAIL because maintenance records/evaluator/freeze are absent.

- [ ] **Step 3: Implement exact arithmetic, attribution, and transactional freeze**

~~~python
async def evaluate(self, records: Sequence[MaintenanceMonthV1]) -> MaintenanceDecision:
    prior_freeze = await self._freeze_store.current()
    steady = await self._steady_state_store.current()
    now = self._clock.now()

    def not_yet_eligible() -> MaintenanceDecision:
        return MaintenanceDecision.not_yet_eligible(
            expansion_frozen=prior_freeze.state == "frozen",
            freeze_generation=prior_freeze.generation,
        )

    if now < steady.started_at + timedelta(days=90):
        return not_yet_eligible()

    ordered = sorted(records, key=lambda record: record.period_start)
    if len(ordered) < 3 or len({record.month for record in ordered}) != len(ordered):
        return not_yet_eligible()
    if any(
        record.steady_state_generation != steady.generation
        or record.steady_state_epoch_started_at != steady.started_at
        or record.logging_eligible_at != steady.started_at + timedelta(days=60)
        or record.period_end_exclusive > now
        or record.recorded_at > now
        for record in ordered
    ):
        return not_yet_eligible()
    if any(left.period_end_exclusive != right.period_start for left, right in pairwise(ordered)):
        return not_yet_eligible()

    expected_starts = tuple(eligible_complete_utc_month_starts(
        logging_eligible_at=steady.started_at + timedelta(days=60),
        observed_at=now,
    ))
    if len(expected_starts) < 3 or tuple(record.period_start for record in ordered) != expected_starts:
        return not_yet_eligible()

    window = ordered[-3:]
    median_minutes = int(statistics.median(r.ordinary_total_minutes for r in window))
    consecutive_windows = tuple(tuple(ordered[index:index + 3]) for index in range(len(ordered) - 2))
    clear_cutoff = prior_freeze.cleared_through_period_end_exclusive
    trigger_window = next((
        candidate for candidate in consecutive_windows
        if (clear_cutoff is None or candidate[0].period_start >= clear_cutoff)
        and all(record.ordinary_total_minutes > 8 * 60 for record in candidate)
    ), None)
    current_freeze = prior_freeze
    if trigger_window is not None and prior_freeze.state == "clear":
        current_freeze = await self._freeze_store.latch_compare_and_swap(
            expected_generation=prior_freeze.generation,
            trigger_window_digest=canonical_window_digest(trigger_window),
            trigger_window_end_exclusive=trigger_window[-1].period_end_exclusive,
            triggered_at=self._clock.now(),
        )
    return MaintenanceDecision(
        rolling_three_month_median_minutes=median_minutes,
        target_met=median_minutes <= 8 * 60,
        expansion_frozen=current_freeze.state == "frozen",
        freeze_generation=current_freeze.generation,
        subsystem_totals=sum_by_subsystem(window),
    )

async def clear_freeze(
    self,
    clearance: MaintenanceFreezeClearanceV1,
    local_owner: LocalOwnerApproval,
) -> MaintenanceFreezeStateV1:
    self._auth.consume_local_owner_action_bound(clearance, local_owner, require_local_presence=True)
    async with self._uow.authoritative() as tx:
        frozen = await tx.maintenance_freeze.require_frozen_generation(clearance.expected_freeze_generation)
        await tx.steady_state.require_exact(
            generation=clearance.steady_state_generation,
            started_at=clearance.steady_state_epoch_started_at,
        )
        await tx.maintenance_months.require_latest_complete_period_end(
            steady_state_generation=clearance.steady_state_generation,
            expected_period_end_exclusive=clearance.evaluated_through_period_end_exclusive,
        )
        await tx.features.require_exact_simplification_or_retirement_applied(
            subsystem_ids=clearance.changed_optional_subsystem_ids,
            evidence_digests=clearance.simplification_or_retirement_evidence_digests,
            resulting_manifest_digest=clearance.resulting_feature_manifest_digest,
        )
        cleared = await tx.maintenance_freeze.clear_with_review(
            frozen,
            clearance,
            cleared_at=self._clock.now(),
            cleared_through_period_end_exclusive=clearance.evaluated_through_period_end_exclusive,
        )
        await tx.audit.append_safe("maintenance.expansion_freeze_cleared", cleared.clear_review_commitment)
        return cleared
~~~

Ordinary categories include health review, backup review, certificate/key attention, storage cleanup, device/plugin checks and routine update approval across all phases. Record exclusions separately by actual duration. Freeze prevents new optional feature registration/procurement but does not disable privacy, safety, backup, recovery or already accepted essentials. Once triggered, `maintenance_expansion_freeze` is durable and latched; a later low-burden window cannot clear it. Only a fresh local-owner action bound to the exact freeze generation, already-applied optional-subsystem simplification/retirement evidence and resulting feature-manifest digest clears it transactionally. UI identifies highest-burden optional subsystems for owner simplification/retirement review.

- [ ] **Step 4: Run green, property arithmetic, boundary cases, and synthetic report**

Run: `uv run pytest apps/core/tests/unit/hardening/test_maintenance_evaluator.py tests/property/phase6/test_maintenance_accounting.py tests/security/phase6/test_expansion_freeze.py tests/acceptance/phase6/test_maintenance_gate.py -q && uv run python scripts/phase6/evaluate_maintenance.py --synthetic fixtures/synthetic/phase6/maintenance/three-months.json --output var/evidence/phase6/maintenance-synthetic.json && uv run ruff check apps/core/src/tuntun_core/services/hardening/maintenance.py scripts/phase6/evaluate_maintenance.py tests/property/phase6 tests/security/phase6 tests/acceptance/phase6 && uv run mypy apps/core/src`
Expected: PASS; exact 480-minute median passes, 481/700/482 freezes, and insufficient real time never passes.

- [ ] **Step 5: Commit maintenance accounting and freeze**

~~~bash
git add apps/core/src/tuntun_core/services/hardening/maintenance.py scripts/phase6/evaluate_maintenance.py docs/operations/phase6-maintenance.md docs/evidence/phase6-maintenance-schema.json apps/core/tests/unit/hardening/test_maintenance_evaluator.py tests/property/phase6/test_maintenance_accounting.py tests/security/phase6/test_expansion_freeze.py tests/acceptance/phase6/test_maintenance_gate.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(operations): enforce whole-system maintenance limits"
~~~

### Task 35: Complete System UI truth, diagnostics preview, accessibility/localization, and P6-4 gate

**Depends on:** Tasks 28–34 and all P6-4 real evidence.
**Gate contribution:** completes P6-4.
**Estimated effort:** 2 person-days.

**Files:**
- Create: `apps/admin/src/features/system/backup-recovery.tsx`
- Create: `apps/admin/src/features/system/maintenance.tsx`
- Create: `apps/admin/src/features/system/release-diagnostics.tsx`
- Create: `apps/admin/src/routes/system-recovery.tsx`
- Create: `apps/admin/src/routes/system-maintenance.tsx`
- Create: `apps/core/src/tuntun_core/api/routes/recovery.py`
- Modify: `apps/core/src/tuntun_core/api/phase6_dtos.py`
- Create: `tests/ui/phase6/system-hardening.spec.ts`
- Create: `tests/ui/phase6/system-hardening-accessibility.spec.ts`
- Create: `tests/privacy/phase6/test_diagnostic_preview.py`
- Create: `tests/acceptance/phase6/test_p6_4_gate.py`

**Interfaces:** Produces truthful owner-safe backup/independent-copy/verification/restore-drill/key-availability, update/rollback, plugin, remote, incident, retirement, maintenance/freeze and public-diagnostic projections. Local-only ceremonies use prepared immutable summaries; remote sees status only where allowed.

**Rollback/disabled exit:** Unknown/stale/degraded/quarantined/error-safe states never render healthy. Diagnostic export transmits nothing automatically. Any accessibility/localization/recovery-truth failure blocks P6-4.

- [ ] **Step 1: Write red state-truth, diagnostic, local-only, language, and accessibility tests**

~~~typescript
test("restore card distinguishes backup creation verification drill and key availability", async ({page}) => {
  await openLocalSystemRecovery(page);
  await expect(page.getByTestId("backup-created-state")).toHaveText("Available");
  await expect(page.getByTestId("backup-verified-state")).toHaveText("Stale");
  await expect(page.getByTestId("restore-drill-state")).toHaveText("Due");
  await expect(page.getByTestId("recovery-key-state")).toHaveText("Owner verification required");
});

test("remote recovery route shows no ceremony controls", async ({page}) => {
  await openApprovedVpnConsole(page);
  await page.goto("/system/recovery");
  await expect(page.getByRole("button", {name: /restore|import key|destroy/i})).toHaveCount(0);
});

test("diagnostic preview enumerates exact safe fields before opt-in", async ({page}) => {
  await openDiagnosticPreview(page);
  expect(await previewFieldNames(page)).toEqual(expectedContentSafeDiagnosticFields());
  await expect(page.getByText(/nothing has been sent/i)).toBeVisible();
});
~~~

- [ ] **Step 2: Run red**

Run: `pnpm --dir apps/admin exec playwright test tests/ui/phase6/system-hardening.spec.ts tests/ui/phase6/system-hardening-accessibility.spec.ts && uv run pytest tests/privacy/phase6/test_diagnostic_preview.py tests/acceptance/phase6/test_p6_4_gate.py -q`
Expected: FAIL because consolidated System pages/DTOs and P6-4 oracle are absent.

- [ ] **Step 3: Implement safe projections, exact ceremonies, diagnostic preview, and gate oracle**

~~~python
def decide_p6_4(evidence: P6FourEvidence) -> GateDecision:
    require(evidence.independent_backup_current_and_verified)
    require(evidence.clean_owner_only_restore_and_no_resurrection)
    require(evidence.incident_containment_and_local_alert_continuity)
    require(evidence.retirement_and_old_identity_denial)
    require(evidence.update_rollback_and_uninstall)
    require(evidence.maintenance_window_complete_and_target_met)
    require(evidence.ui_truth_accessibility_localization_and_diagnostics_safe)
    require(evidence.failure_matrix_passed and evidence.high_critical_open == 0)
    return GateDecision.accept("P6-4", evidence.digest())
~~~

Every fact has controller/evidence time/generation/validity/verification/reason. Preview includes only safe versions, states, reason codes, digests and bounded metrics; no bodies/IDs/addresses. Crash reporting defaults off and requires exact preview plus opt-in. Implement English/Hindi, mixed-script robustness, keyboard, VoiceOver, 320 px/200%, light/dark/high-contrast/reduced-motion and all loading/empty/error/stale/degraded/privacy/quarantine states.

- [ ] **Step 4: Run green UI matrix, API/privacy tests, build, and P6-4 verifier**

Run: `pnpm --dir apps/admin exec playwright test tests/ui/phase6/system-hardening.spec.ts tests/ui/phase6/system-hardening-accessibility.spec.ts && uv run pytest tests/privacy/phase6/test_diagnostic_preview.py tests/acceptance/phase6/test_p6_4_gate.py -q && pnpm --dir apps/admin test && pnpm --dir apps/admin typecheck && pnpm --dir apps/admin build && uv run python scripts/run_ui_matrix.py --phase 6 --languages en,hi --themes light,dark,high-contrast --widths 320,768,1440 --zoom 200 --reduced-motion && uv run python scripts/scan_browser_artifacts.py --forbid private_payloads,secrets,reusable_urls,service_workers,persistent_storage`
Expected: PASS; all UI states are truthful/accessible/localized, diagnostic findings zero, and P6-4 accepts only complete real evidence.

- [ ] **Step 5: Commit System hardening UI and P6-4 gate**

~~~bash
git add apps/admin/src/features/system/backup-recovery.tsx apps/admin/src/features/system/maintenance.tsx apps/admin/src/features/system/release-diagnostics.tsx apps/admin/src/routes/system-recovery.tsx apps/admin/src/routes/system-maintenance.tsx apps/core/src/tuntun_core/api/routes/recovery.py apps/core/src/tuntun_core/api/phase6_dtos.py tests/ui/phase6/system-hardening.spec.ts tests/ui/phase6/system-hardening-accessibility.spec.ts tests/privacy/phase6/test_diagnostic_preview.py tests/acceptance/phase6/test_p6_4_gate.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(ui): complete Phase 6 recovery and operations truth"
~~~

## Wave 6 — Whole-Program Threat Closure, C0 Freeze, C1 Approval, and Manual Beta Publication

### Task 36: Close T01–T25 on one candidate and complete full-system soak/stress evidence

**Depends on:** accepted P6-1 through P6-4 plus current mandatory Phase 1–5 evidence runners.
**Gate contribution:** pre-C0 whole-program acceptance.
**Estimated effort:** 2 person-days plus seven elapsed household days and two elapsed eight-hour stress runs.

**Files:**
- Create: `scripts/phase6/run_threat_matrix.py`
- Create: `scripts/phase6/run_stress.py`
- Create: `scripts/phase6/run_household_soak.py`
- Create: `docs/evidence/phase6-soak-schema.json`
- Create: `docs/evidence/phase6-threat-closure-schema.json`
- Create: `tests/acceptance/phase6/test_t01_t25_closure.py`
- Create: `tests/acceptance/phase6/test_household_soak.py`
- Create: `tests/performance/phase6/test_eight_hour_stress.py`
- Create: `tests/privacy/phase6/test_whole_program_sentinels.py`

**Interfaces:** Produces same-candidate content-safe closure rows for `T01`–`T25`, two actual eight-hour stress receipts, one seven-day household soak, program invariant/private-data/listener/route scans, and exact enabled/absent feature evidence for C0.

**Rollback/disabled exit:** One missing/failed threat, mandatory gate, soak/stress bound, scan, or open high/critical item blocks C0. An optional affected route may be disabled only if its canonical spec classifies it optional and full negative reachability passes.

- [ ] **Step 1: Write red exact-threat, non-compressible duration, bounds, and invariants tests**

~~~python
def test_threat_closure_is_exact_and_has_no_waiver(packet) -> None:
    assert tuple(row.threat_id for row in packet.rows) == tuple(f"T{i:02d}" for i in range(1, 26))
    assert all(row.status == "closed" and row.control_digest and row.test_digest for row in packet.rows)
    assert not hasattr(packet, "waivers") and not hasattr(packet, "accepted_failure")

def test_elapsed_campaigns_are_not_accelerated(evidence) -> None:
    assert evidence.household_soak.monotonic_seconds >= 604_800
    assert evidence.household_soak.wall_seconds >= 604_800
    assert len(evidence.stress_runs) == 2
    assert all(run.monotonic_seconds >= 28_800 and run.wall_seconds >= 28_800 for run in evidence.stress_runs)
    assert not evidence.any_clock_acceleration

def test_resource_and_growth_are_bounded(evidence) -> None:
    assert evidence.oom_count == 0 and evidence.unsafe_replay_count == 0
    assert evidence.unbounded_queue_retry_cost_audit_growth_count == 0
    assert evidence.public_or_unapproved_listener_count == 0
    assert evidence.private_data_findings == 0

def test_local_system_survives_every_external_loss(evidence) -> None:
    for dependency in ("vpn", "internet", "repository", "update_service", "tailscale_control_plane"):
        assert evidence.local_essentials_available_during(dependency)
~~~

- [ ] **Step 2: Run red and synthetic closure**

Run: `uv run pytest tests/acceptance/phase6/test_t01_t25_closure.py tests/acceptance/phase6/test_household_soak.py tests/performance/phase6/test_eight_hour_stress.py tests/privacy/phase6/test_whole_program_sentinels.py -q`
Expected: FAIL because closure/stress/soak runners and schemas are absent.

- [ ] **Step 3: Implement immutable campaign runners and threat/control verifier**

~~~python
def verify_threat_closure(rows: Sequence[ThreatClosureRow]) -> ThreatClosureReceipt:
    require(tuple(row.threat_id for row in rows) == tuple(f"T{i:02d}" for i in range(1, 26)))
    for row in rows:
        require(row.status == "closed")
        require(row.prevention_detection_controls and row.test_receipts and row.fallback)
        require(row.residual_risk not in {"high", "critical"})
        require(row.owner and row.review_at)
    return ThreatClosureReceipt.from_rows(rows)

def decide_campaign(e: WholeProgramCampaign) -> GateDecision:
    require(e.soak.monotonic_seconds >= 604_800 and e.soak.wall_seconds >= 604_800)
    require(len(e.stress) == 2 and all(r.monotonic_seconds >= 28_800 and r.wall_seconds >= 28_800 for r in e.stress))
    require(not e.clock_acceleration_used and e.resources_bounded and e.local_independence)
    require(e.private_findings == 0 and e.public_exposure_findings == 0)
    return GateDecision.accept("whole_program_campaign", e.digest())
~~~

Run all current mandatory phase corpora/faults on the same build. Stress one run under worst simultaneous voice/video/home/media/AI/plugin/remote/update-check load and one under periodic failure/restart/storage/backup activity. Soak covers ordinary family use, Privacy Shield, remote revoke/drift, plugin crash, backup/restore probe, update rollback, incidents, device failures and maintenance logging. Measure CPU/RAM/swap/disk/thermal/queues/retries/cost/audit and all owning phase latency/safety thresholds.

- [ ] **Step 4: Run synthetic oracle and stage exact real elapsed commands**

Run: `uv run python scripts/phase6/run_threat_matrix.py --synthetic --output var/evidence/phase6/threat-closure-synthetic.json && uv run python scripts/phase6/run_stress.py --synthetic --duration-seconds 28800 --runs 2 --output var/evidence/phase6/stress-synthetic.json && uv run python scripts/phase6/run_household_soak.py --synthetic --duration-seconds 604800 --output var/evidence/phase6/household-soak-synthetic.json && uv run pytest tests/acceptance/phase6/test_t01_t25_closure.py tests/acceptance/phase6/test_household_soak.py tests/performance/phase6/test_eight_hour_stress.py tests/privacy/phase6/test_whole_program_sentinels.py -q && uv run python scripts/scan_private_data.py --paths var/evidence/phase6/threat-closure-synthetic.json var/evidence/phase6/stress-synthetic.json var/evidence/phase6/household-soak-synthetic.json && uv run ruff check scripts/phase6 tests/acceptance/phase6 tests/performance/phase6 tests/privacy/phase6`
Expected: PASS for synthetic clocks/fault oracle. C0 remains blocked until both actual eight-hour runs and actual seven-day soak record monotonic plus wall evidence under `TUNTUN_ALLOW_ELAPSED_PHASE6=1`.

- [ ] **Step 5: Commit whole-program campaign tooling**

~~~bash
git add scripts/phase6/run_threat_matrix.py scripts/phase6/run_stress.py scripts/phase6/run_household_soak.py docs/evidence/phase6-soak-schema.json docs/evidence/phase6-threat-closure-schema.json tests/acceptance/phase6/test_t01_t25_closure.py tests/acceptance/phase6/test_household_soak.py tests/performance/phase6/test_eight_hour_stress.py tests/privacy/phase6/test_whole_program_sentinels.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(assurance): close T01 through T25 on one candidate"
~~~

### Task 37: Build and approve whole-program C0 with no waiver or Phase 1 gate alias

**Depends on:** Task 36, accepted P6-1–P6-4, every mandatory Phase 1–6 gate on the same clean commit, and applicable non-compressible maintenance evidence.
**Gate contribution:** whole-program C0.
**Estimated effort:** 1.5 person-days plus owner review.

**Files:**
- Create: `scripts/phase6/build_c0.py`
- Create: `scripts/phase6/approve_c0.py`
- Create: `docs/evidence/c0-evidence-schema.json`
- Create: `tests/contract/release/test_c0_packet.py`
- Create: `tests/security/release/test_c0_no_waiver.py`
- Create: `tests/acceptance/release/test_c0_gate.py`
- Create: `tests/fault/release/test_c0_invalidation.py`

**Interfaces:** Produces `C0CandidateV1` and a distinct local owner passkey approve/reject receipt over immutable version/commit/feature manifest, every mandatory gate/evidence digest, optional-absence proof, T01–T25 closure, hardware compatibility, soak/stress, risks/scans, clean restore/deletion and maintenance evidence.

**Rollback/disabled exit:** Failure or any tracked change invalidates the packet and returns to a new candidate. C0 approval freezes but does not publish, sign missing artifacts, enable absent features, waive gates, or authorize C1.

- [ ] **Step 1: Write red P1R alias, same-candidate, mandatory/optional, waiver, change, and authority tests**

~~~python
@pytest.mark.parametrize("alias", ["P1R0", "P1R1", "p1_release", "phase1_preview"])
def test_phase1_gate_cannot_satisfy_c0(builder, alias) -> None:
    with pytest.raises(C0Denied, match="whole_program_gate_required"):
        builder.substitute_gate("C0", alias)

def test_mandatory_gate_cannot_be_absent_or_waived(c0_fixture) -> None:
    assert decide_c0(c0_fixture.with_mandatory_gate("P3-retention", state="absent")).denied
    assert decide_c0(c0_fixture.with_field("waiver", "owner accepted")).denied

def test_optional_absence_needs_canonical_optional_class_and_negative_reachability(c0_fixture) -> None:
    assert decide_c0(c0_fixture.with_optional_absence(negative_complete=False)).denied

def test_any_tracked_change_invalidates_c0(frozen_candidate) -> None:
    for category in C0_INVALIDATING_CATEGORIES:
        assert mutate(frozen_candidate, category).c0_state == "invalid"

def test_c0_requires_fresh_local_owner_passkey(c0_service, remote_or_stale_approval) -> None:
    assert c0_service.approve(remote_or_stale_approval).code in {"REMOTE_OPERATION_DENIED", "ASSURANCE_INSUFFICIENT"}
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/release/test_c0_packet.py tests/security/release/test_c0_no_waiver.py tests/acceptance/release/test_c0_gate.py tests/fault/release/test_c0_invalidation.py -q`
Expected: FAIL because C0 builder/approval/invalidation are absent.

- [ ] **Step 3: Implement strict C0 builder and local passkey freeze ceremony**

~~~python
C0_INVALIDATING_CATEGORIES = frozenset({
    "source", "lockfile", "workflow", "schema", "feature_manifest", "dependency",
    "package", "evidence_policy", "release_artifact",
})

def build_c0(inputs: WholeProgramEvidence) -> C0CandidateV1:
    require(inputs.one_clean_immutable_commit_and_version)
    require(inputs.every_mandatory_phase1_to_phase6_gate_same_candidate)
    require(inputs.optional_absences_are_canonical_and_negative_complete)
    require(inputs.threat_ids == tuple(f"T{i:02d}" for i in range(1, 26)) and inputs.all_threats_closed)
    require(inputs.exact_hardware_firmware_compatibility and inputs.seven_day_soak)
    require(inputs.two_eight_hour_stress_runs and inputs.high_critical_open == 0)
    require(inputs.clean_owner_restore and inputs.deletion_no_resurrection)
    require(inputs.listener_route_private_scans_clean)
    require(inputs.maintenance_noncompressible_window_satisfied)
    require(not inputs.has_waiver_or_gate_reclassification)
    return C0CandidateV1(
        candidate_id=uuid4(), version=inputs.version, source_commit=inputs.source_commit,
        feature_manifest_digest=inputs.feature_manifest_digest,
        tracked_inputs_digest=inputs.tracked_inputs_digest(),
        mandatory_phase_gate_bundle_digest=inputs.mandatory_gate_bundle_digest(),
        canonical_optional_absence_digest=inputs.optional_absence_digest(),
        threat_t01_t25_closure_digest=inputs.threat_closure_digest(),
        hardware_compatibility_digest=inputs.hardware_compatibility_digest(),
        seven_day_soak_digest=inputs.soak_digest,
        eight_hour_stress_digests=inputs.stress_digests,
        clean_restore_digest=inputs.clean_restore_digest,
        deletion_no_resurrection_digest=inputs.deletion_no_resurrection_digest,
        maintenance_evidence_digest=inputs.maintenance_digest,
        listener_route_private_scan_digest=inputs.scan_digest(),
        built_at=inputs.observed_at,
        candidate_commitment=inputs.candidate_commitment(),
    )

async def approve_c0(candidate, local_owner_passkey) -> C0ApprovalReceipt:
    approval = await require_fresh_local_owner_passkey(local_owner_passkey, purpose="c0_freeze")
    return await freeze_exact_candidate(candidate, approval.commitment)
~~~

Hardware-conditioned not-applicable is allowed only when the owning canonical phase spec defines the condition and the named hardware/route is genuinely absent. The feature manifest cannot reclassify. C0 official evidence contains digests/safe metrics only and is created in order on the frozen clean commit.

- [ ] **Step 4: Run green, mutation matrix, synthetic builder, and approval denial tests**

Run: `uv run pytest tests/contract/release/test_c0_packet.py tests/security/release/test_c0_no_waiver.py tests/acceptance/release/test_c0_gate.py tests/fault/release/test_c0_invalidation.py -q && uv run python scripts/phase6/build_c0.py --synthetic fixtures/synthetic/phase6/releases/c0-input.json --output var/evidence/phase6/c0-synthetic-unsigned.json && uv run python scripts/phase6/approve_c0.py --synthetic-reject-remote-and-stale var/evidence/phase6/c0-synthetic-unsigned.json && uv run python scripts/scan_private_data.py --paths var/evidence/phase6/c0-synthetic-unsigned.json && uv run ruff check scripts/phase6/build_c0.py scripts/phase6/approve_c0.py tests/contract/release tests/security/release tests/acceptance/release tests/fault/release`
Expected: PASS; every mutation/alias/waiver denies, synthetic packet verifies but has no production approval, and private scan is clean.

- [ ] **Step 5: Commit C0 builder and freeze gate**

~~~bash
git add scripts/phase6/build_c0.py scripts/phase6/approve_c0.py docs/evidence/c0-evidence-schema.json tests/contract/release/test_c0_packet.py tests/security/release/test_c0_no_waiver.py tests/acceptance/release/test_c0_gate.py tests/fault/release/test_c0_invalidation.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(release): freeze the whole-program C0 candidate"
~~~

### Task 38: Build distinct C1, approve exact artifacts, and manually publish the immutable beta

**Depends on:** accepted C0, unchanged candidate, complete reproducible/public/macOS evidence and protected publication access.
**Gate contribution:** C1 and P6-5 completion.
**Estimated effort:** 2 person-days plus clean-build/notarization/publication elapsed time.

**Files:**
- Create: `scripts/phase6/build_c1.py`
- Create: `scripts/phase6/approve_c1.py`
- Create: `scripts/phase6/verify_release.py`
- Create: `ops/release/publish.py`
- Create: `docs/evidence/c1-evidence-schema.json`
- Create: `tests/contract/release/test_c1_packet.py`
- Create: `tests/security/release/test_c1_separation_and_manual_publish.py`
- Create: `tests/acceptance/release/test_c1_gate.py`
- Create: `tests/acceptance/phase6/test_p6_5_gate.py`
- Create: `tests/fault/release/test_c1_failure_returns_to_c0.py`

**Interfaces:** Produces C1 packet on unchanged accepted C0, a second distinct fresh project-maintainer passkey receipt at the local release terminal binding every public artifact/evidence digest, publication manifest, manual immutable publish receipt, and independently verified P6-5 release/support result. This project identity is independently provisioned and has no household authentication or recovery authority.

**Rollback/disabled exit:** A failed C1 check or post-C0 tracked change invalidates C0/C1 and requires a new C0 candidate. CI cannot approve or publish. Published defects create a new version/advisory; assets are never overwritten.

- [ ] **Step 1: Write red separation, unchanged candidate, exact evidence, second approval, and manual-publish tests**

~~~python
def test_c1_requires_accepted_unchanged_c0(c1_builder, c0) -> None:
    assert c1_builder.build(c0.with_source_change()).decision == "new_c0_required"

def test_c1_requires_complete_public_artifact_evidence(c1_fixture) -> None:
    for field in (
        "reproducible_build", "dependency_licence", "spdx_sbom", "provenance",
        "checksums_signatures", "developer_id_hardened_runtime", "notarization_stapling_gatekeeper",
        "intel_lifecycle", "apple_silicon_lifecycle", "simulator_docs_support",
        "source_history_artifact_scan", "immutable_tag", "publication_manifest",
    ):
        assert decide_c1(c1_fixture.without(field)).denied

def test_c1_approval_is_distinct_and_fresh(c0_receipt, c1_service) -> None:
    assert c1_service.approve(using=c0_receipt.passkey_assertion).code == "ASSURANCE_INSUFFICIENT"

def test_green_ci_cannot_publish(publish_workflow) -> None:
    assert publish_workflow.automatic_triggers == ()
    assert publish_workflow.requires_c1_receipt and publish_workflow.requires_manual_confirmation

def test_failed_c1_returns_to_new_c0(candidate) -> None:
    assert fail_one_c1_check(candidate).next_gate == "C0"
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/release/test_c1_packet.py tests/security/release/test_c1_separation_and_manual_publish.py tests/acceptance/release/test_c1_gate.py tests/acceptance/phase6/test_p6_5_gate.py tests/fault/release/test_c1_failure_returns_to_c0.py -q`
Expected: FAIL because C1 builder/approval/publication verifier are absent.

- [ ] **Step 3: Implement unchanged-candidate C1 and manual immutable publication**

~~~python
def build_c1(c0: AcceptedC0, evidence: PublicReleaseEvidence) -> C1CandidateV1:
    require(c0.current_and_unchanged())
    require(evidence.source_commit == c0.source_commit)
    require(evidence.feature_manifest_digest == c0.feature_manifest_digest)
    require(evidence.reproducible_clean_build and evidence.dependency_and_licence_policy)
    require(evidence.spdx_sbom and evidence.provenance_attestation)
    require(evidence.checksums_signatures and evidence.developer_id_hardened_runtime)
    require(evidence.notarization_stapling_gatekeeper)
    require(evidence.intel_lifecycle and evidence.apple_silicon_lifecycle)
    require(evidence.synthetic_simulator_docs_support_matrix)
    require(evidence.source_history_artifact_private_findings == 0)
    require(evidence.immutable_tag_and_publication_manifest)
    return C1CandidateV1(
        candidate_id=uuid4(), c0_candidate_id=c0.candidate_id,
        accepted_c0_commitment=c0.approval_commitment,
        version=c0.version, source_commit=c0.source_commit,
        feature_manifest_digest=c0.feature_manifest_digest,
        public_release_evidence_digest=evidence.digest(),
        publication_manifest_digest=evidence.publication_manifest_digest,
        artifact_digests=evidence.artifact_digests,
        built_at=evidence.observed_at,
        candidate_commitment=evidence.bind_to_c0(c0.candidate_commitment),
    )

async def approve_c1(candidate, fresh_local_passkey) -> C1ApprovalReceipt:
    require(candidate.c0.current_and_unchanged())
    assertion = await require_fresh_project_maintainer_passkey_at_local_release_terminal(
        fresh_local_passkey, purpose="c1_public_beta", distinct_from=candidate.c0.approval_id,
    )
    return sign_exact_c1(candidate, assertion)

def publish(c1: AcceptedC1, manual_confirmation: str) -> PublicationReceipt:
    require(c1.current_and_artifacts_exact())
    require_manual_confirmation(manual_confirmation)
    return upload_new_immutable_version_only(c1.publication_manifest)
~~~

Verification downloads public assets independently, checks tag/source/workflow/provenance/SBOM/licences/feature/evidence/signatures/notarization/compatibility and reruns simulator. Publication remains a separate project-maintainer terminal action after C1. Record release advisory/rollback/support boundaries and enforce that project-maintainer accounts are structurally absent from household authentication and recovery stores.

- [ ] **Step 4: Run green, synthetic C1/manual-publish denials, and final independent verification**

Run: `uv run pytest tests/contract/release/test_c1_packet.py tests/security/release/test_c1_separation_and_manual_publish.py tests/acceptance/release/test_c1_gate.py tests/acceptance/phase6/test_p6_5_gate.py tests/fault/release/test_c1_failure_returns_to_c0.py -q && uv run python scripts/phase6/build_c1.py --synthetic fixtures/synthetic/phase6/releases/c1-input.json --output var/evidence/phase6/c1-synthetic-unsigned.json && uv run python scripts/phase6/approve_c1.py --synthetic-reject-reused-c0-approval var/evidence/phase6/c1-synthetic-unsigned.json && uv run python ops/release/publish.py --dry-run --assert-requires-c1-and-manual-confirmation && uv run python scripts/phase6/verify_release.py --synthetic var/evidence/phase6/c1-synthetic-unsigned.json && uv run python scripts/scan_private_data.py --include-git-history --paths . var/evidence/phase6/c1-synthetic-unsigned.json && uv run ruff check scripts/phase6 ops/release/publish.py tests/contract/release tests/security/release tests/acceptance/release tests/acceptance/phase6 tests/fault/release`
Expected: PASS; synthetic approval cannot reuse C0 assertion, dry-run cannot publish, failed checks return to C0, and independent verification/private scan pass. Production publication still requires the explicit `TUNTUN_ALLOW_PUBLICATION=1` manual command with accepted C1.

- [ ] **Step 5: Commit C1 and manual publication tooling**

~~~bash
git add scripts/phase6/build_c1.py scripts/phase6/approve_c1.py scripts/phase6/verify_release.py ops/release/publish.py docs/evidence/c1-evidence-schema.json tests/contract/release/test_c1_packet.py tests/security/release/test_c1_separation_and_manual_publish.py tests/acceptance/release/test_c1_gate.py tests/acceptance/phase6/test_p6_5_gate.py tests/fault/release/test_c1_failure_returns_to_c0.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(release): separate C1 approval from manual publication"
~~~

## Effort and Calendar Envelope

The task estimates total **57.5 focused one-developer days**, or **11.5 five-day engineering weeks**, inside the normative **8–12 focused weeks**. This is implementation/review effort, not permission to compress physical, provider, recovery, platform, soak, or maintenance evidence.

| Wave | Tasks | Focused person-days | Principal output |
|---|---:|---:|---|
| P6-E0/P6-0 baseline | 01–06 | 9.0 | Contracts, persistence, A–S/T01–T25 baseline, LAN-only clean install |
| P6-1 read-only remote | 07–15 | 12.5 | Sole Tailscale adapter, exact route, independent app auth, theft/drift gates, pilot |
| P6-2 optional scopes | 16–18 | 4.0 | Independently enabled reversible/private/camera classes or proved absence |
| P6-3 plugins | 19–23 | 7.0 | Exact two-capability registry, fresh sandboxed processes, core-alert independence |
| P6-3 release pipeline | 24–29 | 9.0 | Public simulator, CI/locks, SBOM/provenance/signatures, notarized package, update/uninstall |
| P6-4 resilience/operations | 30–35 | 10.5 | Independent backup, clean restore, incidents, retirement, maintenance, System UI |
| Whole-program P6-5 | 36–38 | 5.5 | T01–T25 closure, whole-system campaign, C0 then C1, manual publication |
| **Total** | **01–38** | **57.5** | **One immutable evidence-bound public beta** |

Non-compressible calendar evidence is separate:

- P6-1 requires seven representative wall-clock and monotonic days after real Tailscale commissioning.
- Task 36 requires a later same-candidate seven-day full-system household soak and two distinct eight-hour wall/monotonic stress runs. Do not double-count the P6-1 pilot unless the signed campaign definitions, exact unchanged candidate, start state, injections and every metric independently satisfy both schemas; default planning treats them as separate.
- Maintenance evidence logging may begin after at least 60 steady-state days. Evaluation for promotion requires at least 90 steady-state days and three complete monthly buckets for the rolling three-month median. Fake-clock/synthetic reports test arithmetic only and never satisfy C0.
- One clean owner-only quarterly-style restore/lockout/retirement exercise is mandatory for acceptance; continuing quarterly operation remains scheduled after release.
- Official Tailscale client/account terms, device approval, Tailnet Lock/recovery signers, remote-device enrollment, IdP/control-plane availability and independent internet/outer/inner scan vantage are owner/provider elapsed gates, not coding estimates.
- Apple Developer enrollment, protected signing access, notarization service latency, Gatekeeper verification and clean Intel plus current Apple Silicon machine availability are external elapsed gates. C1 waits rather than substituting an unsigned or single-architecture claim.
- A hardware/OS/router/client/plugin-sandbox version change invalidates its receipt and can extend the calendar. Security findings and Apple/provider review override the nominal 8–12 focused weeks.
- C0 and C1 are sequential local approvals on one frozen candidate. C1 cannot start before accepted C0, and publication remains a separate manual action after C1.

## Dependency and Execution Order

~~~text
Accepted Phase 1–5 + canonical contracts
  └─ 01 contracts ─┬─ 02 fakes/T01–T25 corpus
                   └─ 03 migrations
  01–03 ─────────────> 04 amendments/privacy/default absence
  01–04 ─────────────> 05 inventory/A–S/threat/privacy/risk
  01–05 ─────────────> 06 LAN-only clean install ── P6-0

  06 ─> 07 sole Tailscale adapter ─> 08 exposure guard ─> 09 commissioning
  09 ─> 10 app sessions ─> 11 operation matrix ─> 12 read-only UI
  08–12 ─> 13 theft/revoke/drift ─> 14 physical network qualification
  07–14 ─> 15 seven-day read-only pilot ── P6-1

  15 ─┬─> 16 reversible action scopes ─┐
      └─> 17 camera metadata/playback ├─> 18 per-class manifest ── P6-2
                                      ┘
  06 ─> 19 exact plugin SDK/registry ─> 20 admission/IPC ─> 21 sandbox
  19–21 ─> 22 health render ─> 23 alert render/non-suppression ─┐
  06 ─> 24 simulator/docs ─> 25 CI/locks ─> 26 release verifier ┤
  26 ─> 27 macOS package ─> 28 update/rollback ─> 29 lifecycle ─┴─ P6-3

  03/06 ─> 30 independent backup ─> 31 clean restore/no resurrection
  04/08/13/23/28/30/31 ─> 32 incidents ─> 33 retirement/lockout
  03 + enabled subsystem health ─> 34 maintenance window
  28–34 ─> 35 System UI/P6-4

  P6-1 + P6-2 + P6-3 + P6-4 + Phase 1–5 gates
    └─> 36 T01–T25/full-system campaigns
         └─> 37 fresh local owner C0 freeze
              └─> unchanged candidate public evidence
                   └─> 38 distinct C1 approval ─> separate manual publication ── P6-5
~~~

Tasks may run in parallel only when this graph shows no shared authority/file/evidence dependency. Real campaign evidence must bind one clean immutable candidate; parallel code changes invalidate the campaign candidate.

## T01–T25 Threat Closure Traceability

| Threat | Primary implementation tasks | Mandatory evidence at Task 36/C0 |
|---|---|---|
| T01 voice imitation/replay | Accepted P1 gates; 05, 36–37 | P1 replay/Guest fallback and zero biometric authorization on C0 candidate |
| T02 face presentation/replay | Accepted P1/P3 gates; 05, 36–37 | Interaction-gated liveness; Reolink identity route absent |
| T03 cross-profile/child disclosure | Accepted P1/UI gates; 05, 11–12, 36–37 | 1,000-case isolation plus remote object/audience/guardian denial |
| T04 prompt injection | Accepted P1–P5 gates; 02, 19–23, 36–37 | Web/document/media/output/plugin corpora yield no authority/tool/memory/action |
| T05 camera compromise | Accepted P3/P5 gates; 11, 17, 36–37 | Parser/credential/lateral/no-cloud/no-identity and selected-frame separation |
| T06 Reachy/room compromise | Accepted P1/P4 gates; 13, 33, 36–37 | Clone/replay/stolen-device revoke, no secret/remote route |
| T07 HA/IoT compromise | Accepted P2/P4 gates; 11, 14, 36–37 | Signed closed bridge, forged/stale denial, no remote direct HA reach |
| T08 hallucinated/escalated tool | Accepted P1–P5 gates; 11, 16, 36–37 | Unknown target/action/payload/replay/late result deny |
| T09 child policy bypass | Accepted P1/P2/P4 gates; 11, 36–37 | Child/guardian policy, restart/clock/manual truth, no remote upgrade |
| T10 Guest private access | Accepted P1 gates; 10–12, 16–18, 30–33, 36–37 | Complete actor-resource/direct-API matrix; Guest has no admin/private route |
| T11 destructive desktop execution | Accepted P5 gates; 11, 36–37 | D3/D4 sandbox and model-egress separation; remote desktop absent |
| T12 unsafe robot motion | Accepted P5 gates; 11, 32–33, 36–37 | E-stop/lease/geofence gates; remote driving/video absent |
| T13 stolen remote device | 10, 13–15, 17–18, 32, 36–37 | Lost-device/concurrent revoke/session/media replay and rotated generations |
| T14 VPN/IdP compromise | 07–15, 32, 36–37 | Independent app auth, least route, Tailnet Lock, outage/disable, no second adapter |
| T15 public exposure | 06, 08–09, 13–15, 36–37 | Independent internet plus both home-side scans; unexpected drift suspends |
| T16 malicious plugin | 19–23, 29, 36–37 | Exact registry, signer/schema/IPC/resource/exfiltration/cleanup/non-suppression |
| T17 malicious update | 25–29, 32, 36–38 | Signer/builder/SBOM/tag/downgrade/replay/corruption/health preserve prior |
| T18 secret exposure | 01–06, 10, 19–30, 36–38 | Source/history/browser/process/log/crash/archive/SBOM/artifact sentinel scans |
| T19 corruption/ransomware | 03, 28, 30–32, 36–37 | SQLCipher/integrity/interruption, independent copy, quarantined clean restore |
| T20 backup theft/resurrection | 30–31, 35–37 | Archive confidentiality, tombstone precedence, managed-copy purge, no resurrection |
| T21 exhaustion/DoS | 02, 08, 10, 13, 20–23, 28, 36–37 | Quotas/circuit breakers/full-disk/repeated-wake and two bounded eight-hour runs |
| T22 outage/containment | 08, 13–15, 23, 28, 30–36 | WAN/VPN/repository/update/power/provider loss; local essentials/alerts survive |
| T23 false event/presence/emergency | Accepted P3 gates; 11, 17, 36–37 | Native calibration/expiry/dedupe/no false vacancy/no automatic action |
| T24 overstated privacy | 04, 08, 12–13, 17, 23, 32, 35–37 | Separate planes/unverified stops/independent recorder/local alert truth |
| T25 malicious maintainer/contribution | 05, 19–29, 33, 36–38 | Fork isolation, review/locks/scans/provenance/manual C0/C1/publish separation |

## Requirement-to-Task Traceability

| Locked Phase 6 requirement | Tasks |
|---|---|
| LAN/local default; clean install has no remote dependency/listener | 04, 06, 08, 15, 29, 36–38 |
| Tailscale sole adapter, disabled until configured; no direct WireGuard/forward/Funnel/subnet/exit/SSH/public route | 06–09, 14–15, 24–29, 36–38 |
| Exact origin `tuntun.home.arpa:8443`, least route, no inner lateral reach | 08–09, 12–15, 36–37 |
| VPN plus independent Tuntun passkey, 15m/8h/5m freshness | 01, 09–13, 15–18, 36–37 |
| Remote operation matrix and local-only high-impact operations | 11–18, 30–33, 36–37 |
| Read-only seven-day pilot before optional scopes | 12–15 |
| Optional action/camera scopes independently enabled or absent | 16–18, 36–38 |
| Two-layer remote playback ≤10m plus fresh P3 grants ≤60s | 17–18, 36–37 |
| Exact `phase6.initial.1` two-capability display-only registry | 01, 19–23, 29, 36–38 |
| Fresh out-of-process plugin, no persistence/egress/DNS/redirect/write, exact quotas | 19–23, 29, 36–38 |
| Plugin cannot suppress authoritative local core alert | 23, 29, 32, 35–38 |
| SBOM/provenance/signatures/immutable release and pinned CI | 24–29, 36–38 |
| Developer ID/notarization/Gatekeeper plus Intel and current Apple Silicon | 27, 29, 36–38 |
| Visible local update, pre-backup, quarantine, atomic rollback | 28–29, 32, 35–38 |
| Owner-only recovery with no delegation; independent copy; deletion no resurrection | 30–35, 36–38 |
| Incident containment preserves local critical alerts | 23, 32, 35–37 |
| Retirement/lockout/uninstall and old-device denial | 29, 33, 35–38 |
| Full Phase 1–6 maintenance ≤8h median; three-month overage freezes expansion | 34–38 |
| T01–T25 exact closure; seven-day soak; two eight-hour stress runs | 05, 36–37 |
| Whole-program C0 then unchanged-candidate C1, no waiver; P1R0/R1 not aliases | 01, 26–29, 36–38 |
| Publication manual after distinct C1 | 25–26, 37–38 |

## Physical and External Evidence Campaign Order

1. Freeze a clean P6-0 candidate and verify LAN-only/default absence before installing or configuring Tailscale.
2. Review current Tailscale terms/pricing and official client; commission one synthetic-only test client, device approval, Tailnet Lock/recovery signers, exact ACL, split DNS/local CA, firewall and revoke path locally.
3. From the approved remote node, BE800 outer side, ASUS inner side and an independent internet host, prove only the console origin is remotely reachable and no public/inner target succeeds.
4. Complete the seven-day P6-1 read-only pilot. Revoke the test node and prove all old sessions/media fail before optional scopes.
5. Select zero or more P6-2 classes locally; calibrate each exact class and record `enabled` or complete negative absence. Do not enable a bundle.
6. Qualify the plugin sandbox on the supported Intel Mac and declared Apple Silicon target with every exfiltration/resource/cleanup case before enabling either mandatory capability path.
7. Enroll protected Apple signing/notarization credentials outside the repository; build twice clean, produce SBOM/provenance/signatures, and run clean install/update/rollback/preserve-uninstall on both architectures.
8. Create and verify the independent encrypted recovery copy; conduct the clean isolated owner-only restore, deletion-no-resurrection, owner lockout, incident and retirement drills.
9. Begin maintenance logging no earlier than 60 steady-state days, and accumulate at least 90 steady-state days and three complete monthly maintenance records before promotion evaluation. Expansion stays frozen if the last three complete months each exceed eight hours.
10. Freeze the final same candidate, run two eight-hour stress campaigns and seven-day full-system soak, then close T01–T25 and every Phase 1–6 mandatory/optional-absence gate.
11. Build C0, review all digests, and collect a fresh local owner passkey approve/reject. Make no tracked change after approval.
12. Build/reproduce/notarize/verify exact public artifacts from unchanged C0, collect a second distinct fresh local C1 approval, then perform the separate manual immutable publication and independent download verification.

## Milestone Go/No-Go Checklists

### P6-0 — Consolidated LAN-Only Baseline

- [ ] Accepted Phase 1–5 mandatory gates and canonical contracts are current; optional upstream absences have complete negative evidence.
- [ ] Strict Phase 6 contracts/schemas/migrations/fakes pass and every Phase 6 feature defaults absent.
- [ ] A–S inventory, data flows, ranked risks, decisions and T01–T25 control map have owners/tests/fallbacks and no open high/critical item.
- [ ] Clean install registers no remote adapter/listener/client requirement, public route, plugin child, updater or publisher.
- [ ] Source/package/config/API/UI/IPC/listener scans find no direct WireGuard, relay, forward, Funnel, subnet, exit, SSH or public service.
- [ ] Private-data/source/history/docs/evidence scan has zero findings.

**No-go:** Leave Phase 6 absent; repair the baseline. Do not configure Tailscale or plugins.

### P6-1 — Read-Only Remote Pilot

- [ ] Tailscale is the sole registered adapter and core sees only a random local node pseudonym/current posture.
- [ ] Device approval, Tailnet Lock/recovery signers, least ACL, split DNS/local CA, exact interface/8443, firewall and revoke drill pass.
- [ ] VPN-only and application-only authentication reveal no private state; passkey/origin/CSRF/nonce/rate/expiry/revocation tests pass.
- [ ] Independent internet/outer/inner/remote scans prove the console is the only reachable target and no public route exists.
- [ ] Theft, ACL/lock/client/cert/firewall/IdP/replay/session-race injections suspend and revoke while local essentials remain.
- [ ] Seven actual read-only days have zero mutation/lateral/public reach/auth bypass and content-safe evidence.

**No-go:** Disable/suspend route, revoke sessions/generations and continue locally. Do not enable P6-2.

### P6-2 — Optional Remote Scopes

- [ ] Each selected class has local-owner enablement bound to exact class/targets/generations/evidence and fresh passkey policy.
- [ ] Every enabled class passes positive, direct-negative, substitution, theft, revocation, replay and underlying phase-policy tests.
- [ ] Playback, if enabled, is one clip/≤10 minutes and every range is a new single-use ≤60-second P3 grant with `no-store`.
- [ ] Every unselected/failed class is absent across package/config/API/prepared/UI/bundle/replay/direct request.
- [ ] Export, recovery, administration, desktop and robot operations remain remote-denied.

**No-go:** Remove only failed scopes and revoke them. Read-only may remain if P6-1 posture is current.

### P6-3 — Plugins and Release Pipeline

- [ ] Registry revision is exactly `phase6.initial.1` with only the two normative capability IDs and exact DTOs/policies.
- [ ] Signed/digest/SBOM/manifest/IPC admission and unknown/policy-field denials pass.
- [ ] Fresh-process sandbox proves no secret/mount/write/persistence/network/DNS/redirect/process escape and exact resource/deadline/cleanup limits on both targets.
- [ ] Health requires local owner click; alert path cannot suppress/change core alert under missing/malicious/crash/revoke/remove/containment.
- [ ] Clean builds reproduce; locks/licences/SPDX SBOM/SLSA L2 provenance/checksums/signatures/feature/evidence/compatibility/private scans pass.
- [ ] Developer ID/hardened-runtime/notarization/stapling/Gatekeeper and clean Intel/Apple-Silicon install/update/rollback/preserve-uninstall pass.

**No-go:** Block plugin/public release, preserve prior signed household version and fix evidence; no sandbox/signing waiver.

### P6-4 — Resilience and Operations

- [ ] Attached 7-daily/4-weekly plus distinct current independent encrypted Tuntun/Green recovery copy verify; excluded credentials/video are absent.
- [ ] Owner alone completes isolated clean restore; all routes begin quarantined, credentials are recreated and deleted data/authority never resurrects.
- [ ] `CONTAINED_REMOTE`, `CONTAINED_EGRESS`, and `RECOVERY_QUARANTINE` stop exact authorities while mandatory local critical alerts/privacy/manual safety remain.
- [ ] Retirement/owner-lockout/uninstall revoke exact authority and old identities cannot reconnect/replay; residual copies are truthful.
- [ ] System UI/diagnostic preview is truthful, no-store, accessible and English/Hindi complete across failure states.
- [ ] After at least 90 steady-state days and three complete monthly buckets, rolling three-month median is ≤8 hours/month; three overage months set expansion freeze.

**No-go:** Keep affected routes quarantined and optional expansion frozen. Do not approach C0.

### C0 — Whole-Program Candidate Freeze

- [ ] One immutable version/commit/feature manifest binds every mandatory Phase 1–6 gate; no candidate feature manifest reclassification exists.
- [ ] Every canonically optional absence has complete UI/API/config/replay/direct/package/network negative evidence.
- [ ] T01–T25 are exactly closed with owner/test/fallback/review and no unresolved blocker/high/critical finding.
- [ ] Exact hardware/firmware compatibility, two eight-hour runs, seven-day full-system soak, restore/no-resurrection and listener/route/private scans pass.
- [ ] Applicable maintenance logging begins no earlier than 60 steady-state days, and promotion evidence includes at least 90 steady-state days plus three complete monthly buckets; the window is not accelerated or waived.
- [ ] Packet has no waiver field; P1R0/P1R1 cannot parse or substitute; fresh local owner passkey approve/reject binds all digests.
- [ ] Approval freezes only; it does not publish or enable a missing feature.

**No-go:** Any failure/change creates a new candidate and reruns C0.

### C1/P6-5 — Public Beta Approval and Manual Publication

- [ ] Accepted C0 is current and unchanged byte-for-byte in every invalidating category.
- [ ] Reproducible clean build, locks/licences, SPDX SBOM, provenance, signatures, Developer ID/notarization/Gatekeeper and both architecture lifecycle receipts bind exact artifacts.
- [ ] Simulator/docs/support/compatibility/publication manifest and source/history/artifact private scans pass.
- [ ] Immutable tag/assets exist only as staged publication inputs and match source/artifact/evidence digests.
- [ ] A second distinct fresh project-maintainer passkey at the local release terminal approves exact C1; it has no household authority and CI has not inferred approval or published.
- [ ] A separate manual publication uploads a new immutable version, then an independent verifier downloads and verifies every asset.
- [ ] Incident/advisory/rollback/support paths are current; maintainers gain no household recovery authority.

**No-go:** Failed C1 returns to a new C0. Never overwrite a published asset or auto-publish on green CI.

## Final Verification Commands

Run from a clean checkout of the frozen candidate before C0:

~~~bash
make check
uv run pytest -q
uv run pytest --cov=apps --cov=packages --cov=integrations --cov-fail-under=85
uv run python scripts/check_critical_coverage.py --minimum 95 --modules auth,remote,exposure,plugin,release,update,recovery,deletion,incident,c0,c1
uv run python scripts/phase6/generate_schemas.py --check
uv run python scripts/check_generated_artifacts.py --check
uv run python scripts/phase6/verify_default_absence.py
uv run python scripts/check_feature_absence.py --all-canonically-absent --direct-and-replay
uv run python scripts/check_import_boundaries.py --all
uv run python scripts/scan_private_data.py --include-git-history --paths . var/test-artifacts var/release
uv run python scripts/scan_browser_artifacts.py --forbid private_payloads,secrets,reusable_urls,service_workers,persistent_storage
uv run python scripts/check_workflow_pins.py .github/workflows
uv run python ops/release/licences.py --check --output var/release/THIRD_PARTY_NOTICES.txt
pnpm --dir apps/admin test
pnpm --dir apps/admin typecheck
pnpm --dir apps/admin build
pnpm --dir apps/admin exec playwright test
~~~

Then verify, without regenerating or modifying the frozen candidate, the signed real receipts for P6-1 network/pilot, P6-2 per-class state, P6-3 sandbox/Intel/Apple/notarization, P6-4 restore/incident/retirement/maintenance, Task 36 stress/soak/threat closure, C0 and C1. A missing real receipt cannot be replaced by its synthetic counterpart.

## Final Handoff Checklist

- [ ] Exactly one provider-neutral remote port and one six-phase implementation (`tailscale.v1`) exist; Tailscale remains disabled by default.
- [ ] No public bind/forward/domain/tunnel/Funnel/Serve/subnet/exit/SSH/direct-WireGuard/relay route exists.
- [ ] Local/LAN voice, home, recording, media, AI, privacy, backup and recovery remain usable when remote/internet/repository/update service is absent.
- [ ] Remote device membership never creates an app actor; owner passkey/origin/CSRF/expiry/revocation and ordinary policy are independent/current.
- [ ] Read-only precedes optional scopes; every optional scope is evidence-enabled or completely absent.
- [ ] Recovery/high-impact administration remains owner-only, local-presence and non-delegable.
- [ ] Plugin manifest is the exact eleven-field contract; registry is exactly the two display-only IDs and has no publisher policy field.
- [ ] Plugin processes are fresh/no-write/no-persistence/no-network/no-DNS/no-redirect/limited/cleaned, and plugin failure cannot suppress core alerts.
- [ ] Backups/restores exclude live secrets, reconcile every deletion and resurrect no profile/data/authority.
- [ ] Incident containment preserves mandatory local privacy/safety/integrity alerts and truthful independent-plane state.
- [ ] Clean install/update/rollback/preserve-uninstall/destructive-uninstall/retirement/owner-lockout paths pass on supported targets.
- [ ] Release artifacts have locks/licences/SPDX SBOM/SLSA L2 provenance/checksums/signatures/feature/evidence/compatibility and private scans.
- [ ] Developer ID, hardened runtime, notarization, stapling, Gatekeeper, Intel and current Apple Silicon lifecycle evidence pass.
- [ ] T01–T25 close on the same candidate; two eight-hour runs and seven-day whole-system soak are real and bounded.
- [ ] Full-system maintenance evidence has at least 90 steady-state days and three complete monthly buckets; median ≤8h/month and expansion-freeze semantics pass.
- [ ] C0 is whole-program, not P1R0/P1R1, has no waiver and freezes one immutable candidate.
- [ ] C1 is a second distinct approval on unchanged C0; publication is a third separate manual action.
- [ ] Public simulator/docs/evidence contain only synthetic/content-safe data and make no unsupported hardware/privacy claim.
- [ ] No source, lock, workflow, schema, feature, dependency, package, evidence policy or artifact changed after C0.

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-27-tuntun-phase6-remote-access-product-hardening-execution.md`.

Implementation should use `superpowers:subagent-driven-development` task-by-task with a fresh reviewer at every commit, or `superpowers:executing-plans` in dependency-ordered batches. Never begin a real Tailscale, network-scan, plugin-sandbox, clean-Mac, Apple-signing, elapsed campaign, C0/C1, or publication gate from a dirty checkout or with an unreviewed evidence destination.
