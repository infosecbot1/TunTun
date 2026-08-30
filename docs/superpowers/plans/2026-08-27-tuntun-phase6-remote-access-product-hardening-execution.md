# Tuntun Phase 6 Remote Access and Product Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the accepted local-first Phase 1–5 household system into a recoverable, supportable, signed Apache-2.0 beta with an optional owner-only Tailscale route to the existing console, while preserving LAN/local operation as the default and never creating a public service, delegated recovery authority, or general plugin surface.

**Architecture:** The owner-approved Darwin `arm64` Core Mac from ADR 0001 is both the office-use machine and the only canonical household authority; no second office laptop/helper exists. The family-ready baseline single-homes it on inner ASUS/AiMesh with the direct BE800 link disconnected, while an optional dual-home mode is separately qualified and grants no forwarding, bridging, outer ingress, or ambient helper authority. Intel macOS remains a mandatory supported-distribution target and future household-transition candidate only after fresh real-host probes. Phase 6 adds a provider-neutral `RemoteAccessPort` with one disabled-by-default Tailscale adapter, an `owner_vpn_https` class on the existing Phase 3 owner-ingress server, a two-view authoritative-only resolver for the stable `tuntun.home.arpa` RP ID, an exact-interface exposure guard, independent passkey-authenticated application sessions, a closed out-of-process two-capability plugin supervisor, and quarantined release/recovery/incident services. Every optional remote scope is separately registered after evidence; release proceeds on one immutable candidate through whole-program `C0` and then a distinct `C1`, never through Phase 1 `P1R0/P1R1` or a waiver.

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
3. The only eligible remote origin is `https://tuntun.home.arpa:8443` over the exact approved Tailscale interface and canonical least-route `grants` policy. Phase 6 extends the Phase 3 owner-ingress server with `owner_vpn_https` on the exact commissioned Tailnet address:8443; it does not create a parallel HTTP server. Binding `0.0.0.0`, an unclassified interface, a public hostname/address, or any core/media-proxy listener is forbidden.
4. Router port-forwarding, UPnP, NAT-PMP, PCP, public reverse proxy/tunnel, public REST/webhook/API, public Home Assistant, Tailscale Funnel, public Serve, subnet routing, exit-node routing, Tailscale SSH, arbitrary remote shell, and whole-LAN reach are absent and negatively tested.
5. Direct/self-managed WireGuard, a home UDP listener, self-managed relay/rendezvous, and any configuration switch or test bypass enabling them are absent from source registration, binaries, packages, configuration, UI, API, and live listeners.
6. Tailscale account, username, email, node name, IP address, and control-plane assertion never become the application actor or canonical household state. Core receives only a random local node pseudonym and approved posture generations.
7. VPN membership and Tuntun application authentication are independent. Every remote session requires an approved VPN node plus a valid owner passkey session with exact Host/Origin, CSRF, nonce, replay, rate, object-authorization, expiry, and revocation enforcement.
8. `remote_session.v1` idles after 15 minutes and expires absolutely after 8 hours. Approval bodies, private memory, mutations, and camera playback require a passkey no older than 5 minutes.
9. Revoking the VPN node, owner passkey/session, remote policy, route, Tailnet-Lock signed-node/set generation, privacy generation, or application revocation generation invalidates associated remote sessions immediately. Device Approval is disabled and mutual enablement with Tailnet Lock is a commissioning failure because the provider features are mutually exclusive.
10. Read-only health, availability, content-minimized alerts/cost, and approval-inbox metadata are the first remote production class. Approval bodies remain concealed without fresh step-up.
11. Private memory/approval detail, reversible light/media-stop actions, camera metadata, and camera playback are each disabled initially and separately enabled only after their exact P6-2 positive, negative, theft, freshness, and revocation gates.
12. A remote operation is always assurance-reducing through `remote_origin_v1`. It traverses the ordinary action registry, current topology/binding, risk, confirmation, idempotency, controller epoch, child/Guest/device/room/time/privacy policy, and downstream adapter; remote origin never upgrades a local denial.
13. Export/download, identity or biometric enrollment/calibration, profile/guardian/base-policy/provider/hard-cap/bind-mode/plugin-permission changes, recovery-key operations, restore, bulk/profile deletion, audit-key rotation, developer mode, release signing/approval, desktop execution, Raspbot driving/video, remote microphone/camera activation, and shell access remain locally unreachable from remote UI, API, configuration, replay, and direct request.
14. Remote camera playback is disabled by default. When separately approved, one owner-bound single-clip remote media session lasts at most 10 minutes; each byte/time range uses a fresh single-use Phase 3 grant lasting at most 60 seconds. Both layers are `no-store`, enumerate no other clip, reveal no RTSP/ONVIF credential or URL, and revoke together.
15. Remote route state is exactly `DISABLED → COMMISSIONING → READ_ONLY → SCOPED_ACTIONS`; any state may enter `SUSPENDED`, then only `DISABLED` or the prior locally re-approved state. Lost device, canonical grants-policy/Tailnet-Lock/client/DNS/certificate/firewall drift, impossible signed-node state, repeated authentication failure, or owner action suspends.
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
33. The public macOS package requires Developer ID signing, hardened-runtime/entitlement review, Apple notarization, stapling, Gatekeeper, clean install, upgrade, rollback, and preserving uninstall on the supported Intel macOS distribution target plus at least one current declared Apple Silicon target. Unsigned builds are visibly developer-only.
34. Source, history, CI logs, fixtures, screenshots, docs, examples, issues, diagnostics, SBOM, evidence, and release artifacts contain no household secret, identity, biometric, transcript, raw media, private memory, stable household identifier, real network address, certificate, receipt, or configuration.
35. `T01`–`T25` each map to a named prevention/detection control, automated or owner-gated test, content-safe evidence, residual-risk owner, expiry/review, and disable/fallback. Any unresolved high/critical risk blocks the affected feature and release; no waiver path exists.
36. Whole-program C0 uses one immutable final candidate, preserves the accepted historical phase-gate sequence, and requires Task 36C to rerun every current mandatory Phase 1–6 control plus negative reachability for canonically optional absent routes on that final candidate. A historical pilot/gate receipt cannot substitute for the final rerun. C1 follows only after accepted C0 on the unchanged candidate and binds the exact public artifacts. Two fresh local passkey approvals are distinct; publication is a third, manual action.
37. Evidence logging may begin after 60 steady-state days. Evaluation for promotion requires at least 90 steady-state days and three complete monthly buckets; at that point, the full Phase 1–6 rolling three-month median of ordinary owner maintenance is at most 8 hours/month with subsystem attribution. Three consecutive months above 8 hours freeze optional expansion and trigger simplification or retirement review.
38. Ordinary maintenance includes health/backup/certificate/key/storage/device/plugin/update work. Commissioning, quarterly restore/security/physical-safety drills, incidents, hardware replacement, unplanned repair, and major migrations are recorded separately and cannot lower the ordinary metric.
39. Ordinary tests use fake clocks, temporary encrypted stores/keys, synthetic profiles/data/devices/providers/plugins/releases, and no paid API, household data, Keychain, WAN, Tailscale account, Apple signing credential, hardware, notarization, or publication. Owner-gated probes write content-safe evidence under ignored `var/evidence/phase6/`.
40. Project branch coverage remains at least 85%; authorization/session/route/exposure/plugin sandbox/release verifier/update/restore/deletion/incident/C0/C1 modules remain at least 95%. Every task follows red → green → affected suite → static/security checks → exact-path review → commit.
41. Every multi-day Phase 6 pilot, maintenance-eligibility window, soak, stress run and final-evidence campaign consumes Phase 2's canonical externally signed, pre-issued `SignedFeatureManifestRolloverChainV1` through the inherited `FeatureManifestLeaseSupervisor` and per-admission `FeatureAuthorityLease`; Phase 6 creates no signer, renewal service, fallback chain or grace extension. The complete ordered chain must bind one frozen candidate and exact registrations, cover the planned interval, and install each valid successor before its predecessor expires. The historical P6-1 pilot may use its earlier gated candidate, but Task 36B freezes the one final candidate **before** Task 34B opens the counted maintenance epoch; that same candidate plus chain/campaign commitments then bind Task 34B, Task 35R, U8B, Task 35B/P6-4 and Task 36C. Every admission and background-work iteration checks both wall expiry and the process-local monotonic lease. Missing, late, reordered, widened, rollback, signature-invalid, candidate-drifted or expired current/next authority closes work before preparation or I/O, invalidates the campaign and enters the existing controlled whole-composition recovery path. Maintenance observations during a closed-authority interval remain truthful records but cannot count toward the 60-/90-day promotion window; eligibility restarts only under a newly frozen candidate and controlled-recovery steady-state generation. Gate evidence binds the chain ID, ordered manifest digests and transition receipts and requires zero expired-authority interval. After Task 36B, every remaining step is evidence collection, acceptance or publication only; any source/route/service-row/lock/workflow/schema/package/release-artifact mutation invalidates the candidate and restarts at Task 36B.

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
| P6-E0 | Accepted Phase 1–5 gates and current canonical contracts, including the Phase 2 feature-manifest rollover/lease verifier; every conditional absent upstream route has signed negative evidence | Contract/schema/migration baseline, canonical rollover fault corpus, default feature absence, synthetic corpora and existing mandatory regressions pass | Every Phase 6 route/adapter/plugin/update/publication capability remains absent |
| P6-0 | P6-E0 | Consolidated service/asset/data/exposure inventory, A–S artifacts, T01–T25 control map, threat/privacy/risk/decision registers and clean-install LAN-only evidence pass | No remote/plugin/public-release promotion |
| P6-1 | P6-0 plus locally installed official Tailscale client, owner-approved account review, and a complete canonical rollover chain covering the pilot | Local commissioning, exact least route, Tailnet Lock/current signed-node set with Device Approval disabled, app passkey, DNS, theft/revoke/drift/failure tests and seven-day read-only soak pass with zero expired-authority interval | Route enters `DISABLED`/`SUSPENDED`; missing/stale/invalid manifest authority invalidates the pilot; local system remains unchanged |
| P6-2 | Accepted P6-1 | Each explicitly selected low-risk action, camera metadata, private detail, or playback class independently passes positive/negative/theft/revocation gates | Failed/unselected class is absent; read-only route may remain |
| P6-3 | P6-0 plus enforceable plugin sandbox and release credentials/runners | Exact two plugin paths and isolation pass; reproducible synthetic build, SBOM/provenance/signature/notarization, clean Intel/Apple-Silicon install/update/rollback/preserve-uninstall pass | Plugin/release gate blocks; prior household version remains |
| P6-4 | P6-0/P6-3 plus Task 36B frozen final candidate | Independent owner-only backup/clean restore/deletion reconciliation, incident/containment, retirement, weekly health, UI truth and every failure injection pass; the real Task 34B maintenance window is completed on those exact immutable bytes before the evidence-only Task 35B acceptance | Affected route stays quarantined; no recovery/release claim, and any candidate drift restarts the full maintenance window |
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
├── tailscale-policy.template.hujson
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

config/assurance/
└── license-policy.v1.json
scripts/
├── assurance_common.py
├── check_feature_absence.py
├── check_import_boundaries.py
├── check_migration_ownership.py
├── scan_browser_artifacts.py
├── scan_network_surface.py
├── check_public_api.py
├── check_licenses.py
├── check_docs_links.py
├── check_workflow_pins.py
├── check_runbooks.py
├── run_ui_matrix.py
├── check_critical_coverage.py
└── check_generated_artifacts.py
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
from tuntun_contracts.base import canonical_bytes

# This is an alias, not an independently maintained encoder. Every Phase 6 digest,
# signature and commitment therefore uses the one shared RFC 8785/JCS implementation.
canonical_hardening_bytes = canonical_bytes

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

def _validate_exact_tailnet_node_source(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("tailscale_grant_source_not_text")
    try:
        address = IPv4Address(value)
    except ValueError as error:
        raise ValueError("tailscale_grant_source_not_ipv4") from error
    if str(address) != value or address not in IPv4Network("100.64.0.0/10"):
        raise ValueError("tailscale_grant_source_not_canonical_tailnet_ipv4")
    return value

def _validate_tailscale_tag_owner_selector(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= 128 or not re.fullmatch(
        r"(?:[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+|(?:tag|group|autogroup):[A-Za-z0-9._@+-]+)", value,
    ):
        raise ValueError("tailscale_tag_owner_selector_invalid")
    return value

ExactTailnetNodeSource = Annotated[str, BeforeValidator(_validate_exact_tailnet_node_source)]
BoundedTailscaleTagOwnerSelector = Annotated[str, BeforeValidator(_validate_tailscale_tag_owner_selector)]

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
    PHASE4_QUARTERLY_DRILL = "phase4_quarterly_drill"
    INCIDENT = "incident"
    HARDWARE_REPLACEMENT = "hardware_replacement"
    UNPLANNED_REPAIR = "unplanned_repair"
    MAJOR_MIGRATION = "major_migration"

# packages/contracts/src/tuntun_contracts/hardening/maintenance.py
Phase4MaintenanceSubsystem = Literal["room_voice", "media", "display", "television", "screen_time"]
Phase4ExcludedEventClass = Literal[
    "initial_commissioning", "incident", "repair", "hardware_replacement",
    "major_migration", "quarterly_drill",
]

PHASE4_SUBSYSTEM_TO_AGGREGATE: Final = MappingProxyType({
    "room_voice": MaintenanceSubsystem.PHASE4_VOICE_MEDIA_DISPLAYS,
    "media": MaintenanceSubsystem.PHASE4_VOICE_MEDIA_DISPLAYS,
    "display": MaintenanceSubsystem.PHASE4_VOICE_MEDIA_DISPLAYS,
    "television": MaintenanceSubsystem.PHASE4_VOICE_MEDIA_DISPLAYS,
    "screen_time": MaintenanceSubsystem.PHASE4_VOICE_MEDIA_DISPLAYS,
})
PHASE4_EXCLUSION_TO_AGGREGATE: Final = MappingProxyType({
    "initial_commissioning": ExcludedMaintenanceClass.COMMISSIONING,
    "incident": ExcludedMaintenanceClass.INCIDENT,
    "repair": ExcludedMaintenanceClass.UNPLANNED_REPAIR,
    "hardware_replacement": ExcludedMaintenanceClass.HARDWARE_REPLACEMENT,
    "major_migration": ExcludedMaintenanceClass.MAJOR_MIGRATION,
    # Phase 4 does not distinguish restore/security/physical-safety quarterly drills.
    # Preserve that truth instead of guessing one of the three narrower Phase 6 classes.
    "quarterly_drill": ExcludedMaintenanceClass.PHASE4_QUARTERLY_DRILL,
})

class Phase4MaintenanceContributionV1(StrictHardeningContract):
    schema_id: Literal["phase4_maintenance_contribution.v1"] = "phase4_maintenance_contribution.v1"
    source_schema_version: Literal["1.0"]
    source_record_id: UUID
    month: YearMonth
    source_subsystem: Phase4MaintenanceSubsystem
    source_record_class: Literal["ordinary", "excluded_event"]
    source_excluded_event_class: Phase4ExcludedEventClass | None
    minutes: Annotated[int, Field(ge=1, le=1_440)]
    occurred_at_utc: AwareDatetime
    aggregate_subsystem: MaintenanceSubsystem | None
    aggregate_excluded_class: ExcludedMaintenanceClass | None
    source_evidence_commitment: HmacCommitment
    contribution_commitment: HmacCommitment

    @model_validator(mode="after")
    def exact_source_to_aggregate_mapping(self) -> "Phase4MaintenanceContributionV1":
        if self.occurred_at_utc.utcoffset() != timedelta(0):
            raise ValueError("phase4_maintenance_occurrence_not_utc")
        if self.month != self.occurred_at_utc.strftime("%Y-%m"):
            raise ValueError("phase4_maintenance_month_occurrence_mismatch")
        expected_subsystem = PHASE4_SUBSYSTEM_TO_AGGREGATE[self.source_subsystem]
        if self.source_record_class == "ordinary":
            if (
                self.source_excluded_event_class is not None
                or self.aggregate_subsystem != expected_subsystem
                or self.aggregate_excluded_class is not None
            ):
                raise ValueError("phase4_ordinary_maintenance_mapping_invalid")
        else:
            if (
                self.source_excluded_event_class is None
                or self.aggregate_subsystem is not None
                or self.aggregate_excluded_class
                != PHASE4_EXCLUSION_TO_AGGREGATE[self.source_excluded_event_class]
            ):
                raise ValueError("phase4_excluded_maintenance_mapping_invalid")
        return self

# packages/contracts/src/tuntun_contracts/hardening/remote.py
class RemoteSessionV1(StrictHardeningContract):
    schema_id: Literal["remote_session.v1"] = "remote_session.v1"
    session_id: UUID
    actor_subject_id: StableSubjectId
    vpn_adapter_id: StableAdapterId
    vpn_node_pseudonym: RandomLocalPseudonym
    tailnet_lock_generation: Annotated[int, Field(ge=1)]
    signed_node_set_generation: Annotated[int, Field(ge=1)]
    route_generation: Annotated[int, Field(ge=1)]
    application_passkey_assurance: Literal["phishing_resistant"]
    established_at: AwareDatetime
    last_reauthenticated_at: AwareDatetime
    last_access_at: AwareDatetime
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
        if not self.established_at <= self.last_reauthenticated_at <= self.last_access_at < self.absolute_expires_at:
            raise ValueError("remote_reauthentication_window_invalid")
        if self.absolute_expires_at > self.established_at + timedelta(hours=8):
            raise ValueError("remote_absolute_window_exceeded")
        if not self.last_access_at < self.idle_expires_at <= self.last_access_at + timedelta(minutes=15):
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
    tailnet_lock_generation: Annotated[int, Field(ge=1)]
    signed_node_set_generation: Annotated[int, Field(ge=1)]
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
    state: Literal["available"] = "available"
    probe_generation: Annotated[int, Field(ge=1)]
    adapter_id: StableAdapterId
    adapter_class: Literal["tailscale"]
    node_pseudonym: RandomLocalPseudonym
    tailnet_lock_state: Literal["enabled", "disabled", "unknown"]
    admission_authority_mode: Literal["tailnet_lock_only"]
    current_signed_node_state: Literal["signed", "unsigned", "invalid", "unknown"]
    tailnet_lock_generation: Annotated[int, Field(ge=1)]
    signed_node_set_generation: Annotated[int, Field(ge=1)]
    approved_node_set_commitment: HmacCommitment
    independent_signing_node_commitments: Annotated[
        tuple[HmacCommitment, ...], Field(min_length=2, max_length=8),
    ]
    recovery_configuration_commitment: HmacCommitment
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
        if len(set(self.independent_signing_node_commitments)) != len(self.independent_signing_node_commitments):
            raise ValueError("duplicate_tailnet_lock_signing_node")
        return self

class RemoteAdapterUnavailableV1(StrictHardeningContract):
    """Closed, content-minimized result for an adapter that cannot supply current posture."""

    schema_id: Literal["remote_adapter_unavailable.v1"] = "remote_adapter_unavailable.v1"
    state: Literal["not_configured", "unavailable"]
    probe_generation: Annotated[int, Field(ge=1)]
    adapter_id: StableAdapterId
    adapter_class: Literal["tailscale"]
    reason_code: Literal[
        "remote_client_not_installed",
        "remote_client_state_unavailable",
        "remote_client_state_invalid",
    ]
    observed_at: AwareDatetime
    valid_until: AwareDatetime

    @model_validator(mode="after")
    def bounded_failure_window(self) -> "RemoteAdapterUnavailableV1":
        if not self.observed_at < self.valid_until <= self.observed_at + timedelta(seconds=5):
            raise ValueError("remote_adapter_failure_window_invalid")
        if self.state == "not_configured" and self.reason_code != "remote_client_not_installed":
            raise ValueError("remote_adapter_not_configured_reason_invalid")
        if self.state == "unavailable" and self.reason_code == "remote_client_not_installed":
            raise ValueError("remote_adapter_unavailable_reason_invalid")
        return self

RemoteAdapterProbeResultV1 = Annotated[
    RemoteAdapterPostureV1 | RemoteAdapterUnavailableV1,
    Field(discriminator="state"),
]

class TailscaleSelfNodeV1(StrictHardeningContract):
    public_key: Annotated[str, Field(min_length=16, max_length=256, pattern=r"^nodekey:[A-Za-z0-9+/=_-]+$")]
    online: bool

class TailscaleClientStateV1(StrictHardeningContract):
    """Allow-list projection of stable `tailscale status --json` facts."""

    schema_id: Literal["tailscale_client_state.v1"] = "tailscale_client_state.v1"
    backend_state: Literal["running", "stopped", "needs_login", "unknown"]
    client_version: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[0-9A-Za-z.+_-]+$")]
    self_node: TailscaleSelfNodeV1

TailnetLockPublicKey = Annotated[
    str, Field(min_length=16, max_length=256, pattern=r"^tlpub:[A-Za-z0-9+/=_-]+$"),
]
TailnetLockAUMHead = Annotated[
    # Official tka.AUMHash.String(): unpadded RFC 4648 base32 of 32 BLAKE2s bytes.
    str, Field(min_length=52, max_length=52, pattern=r"^[A-Z2-7]{52}$"),
]

class TailscaleTrustedLockKeyV1(StrictHardeningContract):
    kind: Literal["25519"]
    public_key: TailnetLockPublicKey
    votes: Annotated[int, Field(ge=1, le=16)]

class TailscaleLockSnapshotV1(StrictHardeningContract):
    """Allow-list projection of stable `tailscale lock status --json` v1."""

    schema_version: Literal["1"]
    enabled: Literal[True]
    head: TailnetLockAUMHead
    state_id: Annotated[int, Field(ge=1)]
    local_tailnet_lock_public_key: TailnetLockPublicKey
    current_node_public_key: Annotated[
        str, Field(min_length=16, max_length=256, pattern=r"^nodekey:[A-Za-z0-9+/=_-]+$"),
    ]
    current_node_signed: Literal[True]
    current_node_signature_present: Literal[True]
    trusted_signing_keys: Annotated[
        tuple[TailscaleTrustedLockKeyV1, ...], Field(min_length=2, max_length=8),
    ]
    visible_signed_peer_node_keys: Annotated[
        tuple[Annotated[str, Field(min_length=16, max_length=256, pattern=r"^nodekey:[A-Za-z0-9+/=_-]+$")], ...],
        Field(max_length=16),
    ]
    filtered_peer_node_keys: Annotated[
        tuple[Annotated[str, Field(min_length=16, max_length=256, pattern=r"^nodekey:[A-Za-z0-9+/=_-]+$")], ...],
        Field(max_length=16),
    ]

    @model_validator(mode="after")
    def unique_closed_lock_snapshot(self) -> "TailscaleLockSnapshotV1":
        signer_keys = tuple(key.public_key for key in self.trusted_signing_keys)
        if len(set(signer_keys)) != len(signer_keys):
            raise ValueError("duplicate_tailnet_signing_node")
        if len(set(self.visible_signed_peer_node_keys)) != len(self.visible_signed_peer_node_keys):
            raise ValueError("duplicate_visible_signed_tailnet_node")
        if len(set(self.filtered_peer_node_keys)) != len(self.filtered_peer_node_keys):
            raise ValueError("duplicate_filtered_tailnet_node")
        if set(self.visible_signed_peer_node_keys) & set(self.filtered_peer_node_keys):
            raise ValueError("tailnet_peer_visible_and_filtered")
        return self

class TailscalePreferencesV1(StrictHardeningContract):
    """Allow-list projection of `tailscale get --json all`; identity fields are discarded."""

    accept_routes: Literal[False]
    advertise_routes: tuple[()]
    exit_node_configured: Literal[False]
    run_ssh: Literal[False]
    run_web_client: Literal[False]
    advertise_services: tuple[()]
    app_connector_advertised: Literal[False]
    relay_server_configured: Literal[False]

class TailscaleProviderSnapshotV1(StrictHardeningContract):
    client: TailscaleClientStateV1
    lock: TailscaleLockSnapshotV1
    preferences: TailscalePreferencesV1
    serve_configuration_present: Literal[False]
    funnel_configuration_present: Literal[False]

class TailscaleGrantV1(StrictHardeningContract):
    """Exact current grants shape; destination identity and protocol/port are separate fields."""

    src: Annotated[tuple[ExactTailnetNodeSource, ...], Field(min_length=1, max_length=8)]
    dst: Annotated[tuple[Literal["tag:tuntun-core"], ...], Field(min_length=1, max_length=1)]
    ip: tuple[Literal["tcp:8443"], Literal["tcp:53"], Literal["udp:53"]]

    @model_validator(mode="after")
    def exact_closed_grant(self) -> "TailscaleGrantV1":
        if len(set(self.src)) != len(self.src):
            raise ValueError("duplicate_grants_source")
        if any(selector.endswith((':8443', ':53', ':53/tcp', ':53/udp')) for selector in self.dst):
            raise ValueError("port_suffixed_grants_destination")
        return self

class TailscaleGrantsPolicyV1(StrictHardeningContract):
    tagOwners: dict[
        Literal["tag:tuntun-core"],
        Annotated[tuple[BoundedTailscaleTagOwnerSelector, ...], Field(min_length=1, max_length=8)],
    ]
    grants: Annotated[tuple[TailscaleGrantV1, ...], Field(min_length=1, max_length=1)]

    @model_validator(mode="after")
    def exact_tag_owner_key(self) -> "TailscaleGrantsPolicyV1":
        if set(self.tagOwners) != {"tag:tuntun-core"}:
            raise ValueError("grants_tag_owners_not_exact")
        owners = self.tagOwners["tag:tuntun-core"]
        if len(set(owners)) != len(owners):
            raise ValueError("duplicate_grants_tag_owner")
        return self

class AuthoritativeResolverViewV1(StrictHardeningContract):
    view: Literal["commissioned_lan", "approved_tailnet"]
    listener_address: IPv4Address
    answer_address: IPv4Address
    allowed_source_set_commitment: HmacCommitment

class AuthoritativeResolverBindingV1(StrictHardeningContract):
    schema_id: Literal["authoritative_resolver_binding.v1"] = "authoritative_resolver_binding.v1"
    rp_id_and_record: Literal["tuntun.home.arpa"]
    ttl_seconds: Annotated[int, Field(ge=30, le=300)]
    views: Annotated[tuple[AuthoritativeResolverViewV1, ...], Field(min_length=2, max_length=2)]
    transport_ports: tuple[Literal["tcp/53"], Literal["udp/53"]]
    recursion: Literal[False]
    dynamic_update: Literal[False]
    axfr: Literal[False]
    wildcard_answers: Literal[False]
    ipv6_answers: Literal[False]
    parser_privilege: Literal["launchd_socket_activation_unprivileged_parser"]
    certificate_san: Literal["tuntun.home.arpa"]
    local_ca_commitment: HmacCommitment
    grants_policy_digest: Sha256Digest
    binding_generation: Annotated[int, Field(ge=1)]
    observed_at: AwareDatetime
    valid_until: AwareDatetime
    binding_commitment: HmacCommitment

    @model_validator(mode="after")
    def exact_two_view_authority(self) -> "AuthoritativeResolverBindingV1":
        if tuple(view.view for view in self.views) != ("commissioned_lan", "approved_tailnet"):
            raise ValueError("resolver_views_missing_or_reordered")
        if len({view.listener_address for view in self.views}) != 2:
            raise ValueError("resolver_listener_views_not_distinct")
        if len({view.answer_address for view in self.views}) != 2:
            raise ValueError("resolver_answer_views_not_distinct")
        if not self.observed_at < self.valid_until <= self.observed_at + timedelta(seconds=30):
            raise ValueError("resolver_binding_window_invalid")
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
    tailnet_lock_generation: Annotated[int, Field(ge=1)]
    signed_node_set_generation: Annotated[int, Field(ge=1)]
    revocation_generation: Annotated[int, Field(ge=1)]
    observed_at: AwareDatetime
    receipt_commitment: HmacCommitment

class RemoteCommissioningReceiptV1(StrictHardeningContract):
    schema_id: Literal["remote_commissioning_receipt.v1"] = "remote_commissioning_receipt.v1"
    receipt_id: UUID
    adapter_id: StableAdapterId
    adapter_class: Literal["tailscale"]
    admission_authority_mode: Literal["tailnet_lock_only"]
    state: Literal["read_only"]
    node_pseudonym: RandomLocalPseudonym
    client_version_commitment: HmacCommitment
    grants_policy_digest: Sha256Digest
    provider_policy_validation_evidence_digest: Sha256Digest
    tailnet_lock_evidence_digest: Sha256Digest
    tailnet_lock_aum_head: TailnetLockAUMHead
    tailnet_lock_state_id: Annotated[int, Field(ge=1)]
    signed_node_set_evidence_digest: Sha256Digest
    approved_node_set_commitment: HmacCommitment
    independent_signing_node_commitments: Annotated[tuple[HmacCommitment, ...], Field(min_length=2, max_length=8)]
    recovery_configuration_commitment: HmacCommitment
    authoritative_dns_binding_commitment: HmacCommitment
    lan_resolver_address: IPv4Address
    tailnet_resolver_address: IPv4Address
    record_name: Literal["tuntun.home.arpa"]
    record_ttl_seconds: Annotated[int, Field(ge=30, le=300)]
    client_dns_acceptance_evidence_digest: Sha256Digest
    certificate_san: Literal["tuntun.home.arpa"]
    local_ca_commitment: HmacCommitment
    local_ca_evidence_digest: Sha256Digest
    firewall_evidence_digest: Sha256Digest
    recovery_evidence_digest: Sha256Digest
    revocation_drill_evidence_digest: Sha256Digest
    local_independence_evidence_digest: Sha256Digest
    pinned_client_projection_fixture_digest: Sha256Digest
    interface_commitment: HmacCommitment
    origin: Literal["https://tuntun.home.arpa:8443"]
    tailnet_lock_generation: Annotated[int, Field(ge=1)]
    signed_node_set_generation: Annotated[int, Field(ge=1)]
    route_generation: Annotated[int, Field(ge=1)]
    revocation_generation: Annotated[int, Field(ge=1)]
    commissioned_at: AwareDatetime
    receipt_commitment: HmacCommitment

    @model_validator(mode="after")
    def exact_tailnet_lock_commissioning(self) -> "RemoteCommissioningReceiptV1":
        if len(set(self.independent_signing_node_commitments)) != len(self.independent_signing_node_commitments):
            raise ValueError("duplicate_tailnet_lock_commissioning_signer")
        return self

RemoteOperationName = Literal[
    "health_status", "phase_availability", "device_availability", "alert_metadata",
    "cost_summary", "approval_metadata", "approval_body", "subject_private_memory",
    "light_power_on", "light_power_off", "media_stop", "camera_metadata", "camera_playback", "export",
    "download", "identity_enroll", "biometric_calibrate", "profile_delete",
    "guardian_change", "base_policy_change", "provider_change", "hard_cap_change",
    "bind_mode_change", "plugin_permission_change", "recovery_key_display",
    "recovery_key_import", "restore", "bulk_delete", "audit_key_rotate",
    "developer_mode", "release_approve", "release_sign", "desktop_execute",
    "robot_drive", "robot_video", "remote_shell", "microphone_activate", "camera_activate",
]

RemoteResourceType = Literal[
    "approval", "subject_private_memory", "light", "media_player", "camera_event", "camera_clip",
]

class OpaqueRemoteResourceRefV1(StrictHardeningContract):
    """Client-visible opaque selector; never a canonical target or authority claim."""

    resource_type: RemoteResourceType
    opaque_id: RandomLocalPseudonym

class ResolvedRemoteResourceV1(StrictHardeningContract):
    """Server-only current mapping resolved after session/posture authorization."""

    resource_type: RemoteResourceType
    canonical_resource_id: UUID
    resource_generation: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    resolution_commitment: HmacCommitment

class RemoteOperationRequestV1(StrictHardeningContract):
    """Exact HTTP JSON body; version is the out-of-band media type, never a serialized field."""

    operation: RemoteOperationName
    resource: OpaqueRemoteResourceRefV1 | None
    idempotency_key: UUID

    @model_validator(mode="after")
    def exact_resource_shape_for_operation(self) -> "RemoteOperationRequestV1":
        expected = {
            "approval_body": "approval", "subject_private_memory": "subject_private_memory",
            "light_power_on": "light", "light_power_off": "light", "media_stop": "media_player",
            "camera_metadata": "camera_event", "camera_playback": "camera_clip",
        }.get(self.operation)
        if (expected is None) != (self.resource is None):
            raise ValueError("remote_operation_resource_presence_invalid")
        if self.resource is not None and self.resource.resource_type != expected:
            raise ValueError("remote_operation_resource_type_invalid")
        return self

class AuthorizedRemoteContextV1(StrictHardeningContract):
    """Server-only; construction is impossible from HTTP JSON or generated clients."""

    schema_id: Literal["authorized_remote_context.v1"] = "authorized_remote_context.v1"
    request_id: UUID
    idempotency_key: UUID
    operation: RemoteOperationName
    resource: ResolvedRemoteResourceV1 | None
    authenticated_owner_subject_id: StableSubjectId
    application_session_id: UUID
    vpn_node_pseudonym: RandomLocalPseudonym
    route_generation: Annotated[int, Field(ge=1)]
    tailnet_lock_generation: Annotated[int, Field(ge=1)]
    signed_node_set_generation: Annotated[int, Field(ge=1)]
    operation_class_generation: Annotated[int, Field(ge=1)]
    policy_version: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    application_revocation_generation: Annotated[int, Field(ge=1)]
    last_reauthenticated_at: AwareDatetime
    authorized_at: AwareDatetime
    valid_until: AwareDatetime
    context_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_server_context(self) -> "AuthorizedRemoteContextV1":
        if self.last_reauthenticated_at > self.authorized_at:
            raise ValueError("authorized_remote_context_reauthentication_in_future")
        if not self.authorized_at < self.valid_until <= self.authorized_at + timedelta(seconds=5):
            raise ValueError("authorized_remote_context_window_invalid")
        return self

class RemoteOperationDecisionV1(StrictHardeningContract):
    schema_id: Literal["remote_operation_decision.v1"] = "remote_operation_decision.v1"
    request_id: UUID
    authorized_context_commitment: HmacCommitment
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
    source_generation: Annotated[int, Field(ge=1)]
    observed_at: AwareDatetime
    valid_until: AwareDatetime
    fact_commitment: HmacCommitment

    @model_validator(mode="after")
    def current_source_fact(self) -> "RemoteAccessHealthRow":
        if not self.observed_at < self.valid_until:
            raise ValueError("remote_health_fact_window_invalid")
        return self

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
    context: AuthorizedRemoteContextV1
    detail_class: Literal["approval_body", "subject_private_memory"]

class RemotePrivateDetailProjectionV1(StrictHardeningContract):
    schema_id: Literal["remote_private_detail_projection.v1"] = "remote_private_detail_projection.v1"
    request_id: UUID
    detail_class: Literal["approval_body", "subject_private_memory"]
    subject_id: StableSubjectId
    audience: Literal["subject_private"]
    audience_generation: Annotated[int, Field(ge=1)]
    guardian_generation: Annotated[int | None, Field(ge=1)]
    consent_generation: Annotated[int, Field(ge=1)]
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
    subject: ClipPlaybackSubjectV1
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    route_generation: Annotated[int, Field(ge=1)]
    remote_session_revocation_generation: Annotated[int, Field(ge=1)]
    operation_class_generation: Annotated[int, Field(ge=1)]
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

PluginCapabilityId = Literal[
    "system.health.render.v1",
    "notification.local_alert.render.v1",
]

class PluginResourcePolicyV1(StrictHardeningContract):
    wall_seconds: Literal[5]
    memory_mib: Literal[128]
    cpu_fraction_decimal: Literal["0.50"]
    concurrent_calls: Literal[1]
    combined_request_response_bytes: Literal[65536]
    fresh_process: Literal[True]
    filesystem_write: Literal[False]
    network_dns_redirects: Literal[False]

class PluginCapabilityPolicyV1(StrictHardeningContract):
    actor_invocation: Literal["local_owner_explicit_click", "core_automatic_local_alert"]
    consent_guardian: Literal["owner_install_and_each_call", "owner_install"]
    sensitivity: Literal["closed_operational_no_household_content"]
    retention_storage: Literal["content_minimized_receipt_180_days"]
    egress_dns_redirects: Literal["none"]
    revocation_cleanup: Literal["generation_bound_kill_close_erase"]
    resources: PluginResourcePolicyV1

class PluginCapabilityRegistryEntryV1(StrictHardeningContract):
    capability_id: PluginCapabilityId
    request_schema_id: Literal[
        "plugin_health_child_input.v1", "plugin_alert_child_input.v1",
    ]
    response_schema_id: Literal[
        "plugin_health_child_output.v1", "plugin_alert_child_output.v1",
    ]
    policy: PluginCapabilityPolicyV1

    @model_validator(mode="after")
    def exact_schema_and_policy_for_capability(self) -> "PluginCapabilityRegistryEntryV1":
        expected = {
            "system.health.render.v1": (
                "plugin_health_child_input.v1", "plugin_health_child_output.v1",
                "local_owner_explicit_click", "owner_install_and_each_call",
            ),
            "notification.local_alert.render.v1": (
                "plugin_alert_child_input.v1", "plugin_alert_child_output.v1",
                "core_automatic_local_alert", "owner_install",
            ),
        }[self.capability_id]
        actual = (
            self.request_schema_id, self.response_schema_id,
            self.policy.actor_invocation, self.policy.consent_guardian,
        )
        if actual != expected:
            raise ValueError("plugin_registry_capability_policy_mismatch")
        return self

class PluginCapabilityRegistryV1(StrictHardeningContract):
    schema_id: Literal["plugin_capability_registry.v1"] = "plugin_capability_registry.v1"
    registry_revision: Literal["phase6.initial.1"]
    signer_identity: BoundedSignatureIdentity
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    capabilities: tuple[PluginCapabilityRegistryEntryV1, PluginCapabilityRegistryEntryV1]

    @model_validator(mode="after")
    def exact_current_registry(self) -> "PluginCapabilityRegistryV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(days=90):
            raise ValueError("plugin_registry_validity_invalid")
        if tuple(entry.capability_id for entry in self.capabilities) != (
            "system.health.render.v1", "notification.local_alert.render.v1",
        ):
            raise ValueError("plugin_registry_capability_set_or_order_invalid")
        return self

class PluginManifestV1(StrictHardeningContract):
    plugin_id: StablePluginId
    version: SemVer
    publisher: BoundedPublisherIdentity
    artifact_digest: Sha256Digest
    signature_identity: BoundedSignatureIdentity
    protocol_major: Literal[1]
    capability_registry_revision: Literal["phase6.initial.1"]
    entrypoint: BoundedRelativeEntrypoint
    requested_capability_ids: tuple[PluginCapabilityId]
    licence: SpdxLicenceExpression
    sbom_digest: Sha256Digest

    @model_validator(mode="after")
    def unique_capabilities(self) -> "PluginManifestV1":
        if len(self.requested_capability_ids) != 1:
            raise ValueError("plugin_package_must_bind_exactly_one_capability")
        return self

class PluginHealthComponentV1(StrictHardeningContract):
    component_class: PluginComponentClass
    state: Literal["available", "degraded", "unavailable", "disabled"]
    freshness: Literal["current", "stale", "unknown"]
    source_generation: Annotated[int, Field(ge=1)]
    observed_at: AwareDatetime
    valid_until: AwareDatetime
    fact_commitment: HmacCommitment
    attention_codes: Annotated[
        tuple[Literal[
            "backup_stale", "storage_low", "credential_expiring", "unexpected_exposure",
            "privacy_control_failed", "safety_input_disabled", "update_pending",
        ], ...],
        Field(max_length=7),
    ]

    @model_validator(mode="after")
    def bounded_unique_source_fact(self) -> "PluginHealthComponentV1":
        if not self.observed_at < self.valid_until <= self.observed_at + timedelta(seconds=30):
            raise ValueError("plugin_health_component_window_invalid")
        if len(set(self.attention_codes)) != len(self.attention_codes):
            raise ValueError("duplicate_plugin_health_attention_code")
        return self

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
        if len({component.component_class for component in self.components}) != len(self.components):
            raise ValueError("duplicate_plugin_health_component")
        if any(
            component.observed_at > self.issued_at or component.valid_until < self.expires_at
            for component in self.components
        ):
            raise ValueError("plugin_health_component_does_not_cover_snapshot_window")
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

class PluginHealthChildFactV1(StrictHardeningContract):
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

class PluginHealthChildInputV1(StrictHardeningContract):
    components: Annotated[tuple[PluginHealthChildFactV1, ...], Field(max_length=16)]

class PluginAlertChildInputV1(StrictHardeningContract):
    alert_code: Literal[
        "backup_failed", "storage_low", "unexpected_listener", "privacy_stop_failed",
        "audit_integrity_failed", "credential_expired", "unsigned_component",
        "robot_safety_input_disabled",
    ]
    severity: Literal["warning", "critical"]

class PluginHealthChildOutputV1(StrictHardeningContract):
    headline: Annotated[PlainSafeText, Field(max_length=160)]
    items: Annotated[tuple[PluginHealthRenderItemV1, ...], Field(max_length=16)]

class PluginAlertChildOutputV1(StrictHardeningContract):
    title: Annotated[PlainSafeText, Field(max_length=80)]
    body: Annotated[PlainSafeText, Field(max_length=240)]
    accent: Literal["amber", "red"]

PluginChildWireInput = Annotated[bytes, Field(min_length=1, max_length=64 * 1024)]

class SupervisorCodecSelectionV1(StrictHardeningContract):
    """Supervisor-local configuration; never serialized to or read from the child."""

    plugin_id: StablePluginId
    plugin_version: SemVer
    capability_id: Literal["system.health.render.v1", "notification.local_alert.render.v1"]
    codec: Literal["canonical_json_v1"]
    registry_digest: Sha256Digest

class PluginCallResultEnvelopeV1(StrictHardeningContract):
    schema_id: Literal["plugin_call_result_envelope.v1"] = "plugin_call_result_envelope.v1"
    request_id: UUID
    plugin_id: StablePluginId
    plugin_version: SemVer
    capability_id: Literal["system.health.render.v1", "notification.local_alert.render.v1"]
    grant_generation: Annotated[int, Field(ge=1)]
    state: Literal["rendered", "error_safe"]
    payload: PluginHealthRenderV1 | PluginLocalAlertRenderV1 | None
    observed_at: AwareDatetime
    supervisor_signer_identity: BoundedSignatureIdentity
    supervisor_key_generation: Annotated[int, Field(ge=1)]
    result_signature: P256Signature

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

The signed registry—not the manifest—fixes both capabilities to local-owner eligibility, their distinct invocation/consent rules, exact DTO pairs, sensitivity ceilings, fresh-process/no-write/no-network policy, five-second deadline, 128 MiB/50%-CPU/64-KiB/one-concurrency quotas, generation-bound revocation, cleanup, and 180-day content-minimized invocation receipts. The supervisor first validates the trusted envelope and each health fact's own generation/time/validity/commitment, selects `canonical_json_v1` out of band, projects only `PluginHealthChildInputV1` or `PluginAlertChildInputV1`, and passes the child those exact encoded bytes. The child wire contains no schema label, request ID, purpose, generation, timestamp, expiry, grant, commitment, plugin/version/capability/codec/registry metadata in either direction; recursive decoded-key tests enforce the prohibition. Child output is untrusted bytes until the supervisor decodes the matching child-output DTO, reconstructs request ID and all trusted bindings from the admitted call, and signs the canonical closed result fields (everything except `result_signature`) with domain `tuntun.plugin-call-result.v1`. The supervisor account alone can use the non-exportable P-256 signing key; Core pins only its public key, signer identity and generation and has no signing operation. Health requires an explicit local owner click for every render. Local alerts may invoke automatically only after owner installation approval and always render beside an unchanged mandatory core alert.

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

class PublicationManifestV1(StrictHardeningContract):
    """Detached-signature payload for one immutable public version."""

    schema_id: Literal["publication_manifest.v1"] = "publication_manifest.v1"
    candidate_id: UUID
    version: SemVer
    immutable_tag: Annotated[
        str,
        Field(min_length=2, max_length=65, pattern=r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$"),
    ]
    source_commit: GitObjectId
    source_repository_identity: BoundedRepositoryIdentity
    release_manifest_digest: Sha256Digest
    artifact_set_digest: Sha256Digest
    artifact_inventory_digest: Sha256Digest
    artifact_digests: Annotated[
        tuple[NamedArtifactDigestV1, ...],
        Field(min_length=1, max_length=64),
    ]
    signer_identity: BoundedSignatureIdentity
    issued_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def exact_bounded_publication(self) -> "PublicationManifestV1":
        if self.immutable_tag != f"v{self.version}":
            raise ValueError("publication_manifest_tag_version_mismatch")
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(hours=24):
            raise ValueError("publication_manifest_validity_invalid")
        names = tuple(artifact.artifact_name for artifact in self.artifact_digests)
        paths = tuple(artifact.relative_path for artifact in self.artifact_digests)
        if len(set(names)) != len(names) or len(set(paths)) != len(paths):
            raise ValueError("duplicate_publication_artifact")
        if digest_named_artifact_inventory(self.artifact_digests) != self.artifact_inventory_digest:
            raise ValueError("publication_artifact_inventory_digest_mismatch")
        release_manifests = tuple(
            artifact for artifact in self.artifact_digests
            if artifact.artifact_name == "release-manifest.json"
        )
        if len(release_manifests) != 1 or release_manifests[0].digest != self.release_manifest_digest:
            raise ValueError("publication_release_manifest_artifact_mismatch")
        return self

class PublicationActionBindingV1(StrictHardeningContract):
    """One short-lived, exact, terminal-local publication challenge."""

    schema_id: Literal["publication_action_binding.v1"] = "publication_action_binding.v1"
    publication_action_id: UUID
    candidate_id: UUID
    accepted_c1_commitment: HmacCommitment
    publication_manifest_digest: Sha256Digest
    release_manifest_digest: Sha256Digest
    artifact_set_digest: Sha256Digest
    artifact_inventory_digest: Sha256Digest
    immutable_tag: Annotated[
        str,
        Field(min_length=2, max_length=65, pattern=r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$"),
    ]
    credential_namespace: Literal["project_maintainer_publication"]
    signature_domain: Literal["tuntun.publication.project-maintainer.v1"]
    purpose: Literal["publish_exact_immutable_public_beta"]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    action_commitment: HmacCommitment

    @model_validator(mode="after")
    def short_publication_action_window(self) -> "PublicationActionBindingV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(minutes=2):
            raise ValueError("publication_action_window_invalid")
        return self

class ReleaseCandidateV1(StrictHardeningContract):
    schema_id: Literal["release_candidate.v1"] = "release_candidate.v1"
    candidate_id: UUID
    # Exact staged bytes; never framework-decoded or normalized before verification.
    manifest_bytes: Annotated[bytes, Field(min_length=2, max_length=1024 * 1024)]
    manifest_digest: Sha256Digest
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
    update_run_id: UUID
    candidate_id: UUID
    candidate_manifest_digest: Sha256Digest
    artifact_set_id: UUID
    artifact_set_commitment: HmacCommitment
    install_allowed: bool
    preserve_version: SemVer
    accepted_manifest: ReleaseManifestV1 | None
    reason_code: SafeReasonCode
    decided_at: AwareDatetime
    valid_until: AwareDatetime
    decision_commitment: HmacCommitment

    @model_validator(mode="after")
    def coherent_release_decision(self) -> "ReleaseDecisionV1":
        if self.install_allowed != (self.accepted_manifest is not None):
            raise ValueError("release_decision_manifest_state_mismatch")
        if self.accepted_manifest is not None and (
            sha256(canonical_hardening_bytes(self.accepted_manifest)).hexdigest()
            != self.candidate_manifest_digest
        ):
            raise ValueError("release_decision_accepted_manifest_digest_mismatch")
        if not self.decided_at < self.valid_until <= self.decided_at + timedelta(minutes=5):
            raise ValueError("release_decision_validity_window_invalid")
        if (
            self.accepted_manifest is not None
            and self.accepted_manifest.expires_at is not None
            and self.valid_until > self.accepted_manifest.expires_at
        ):
            raise ValueError("release_decision_outlives_manifest")
        return self

class C0CandidateV1(StrictHardeningContract):
    schema_id: Literal["c0_candidate.v1"] = "c0_candidate.v1"
    candidate_id: UUID
    version: SemVer
    source_commit: GitObjectId
    feature_manifest_digest: Sha256Digest
    feature_authority_evidence_digest: Sha256Digest
    artifact_set_digest: Sha256Digest
    artifact_inventory_digest: Sha256Digest
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
    source_repository_identity: BoundedRepositoryIdentity
    feature_manifest_digest: Sha256Digest
    public_release_evidence_digest: Sha256Digest
    publication_manifest_digest: Sha256Digest
    release_manifest_digest: Sha256Digest
    artifact_set_digest: Sha256Digest
    artifact_inventory_digest: Sha256Digest
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

class BuildSmokeReceiptV1(StrictHardeningContract):
    schema_id: Literal["build_smoke_receipt.v1"] = "build_smoke_receipt.v1"
    architecture: Literal["x86_64", "arm64"]
    runner_image_digest: Sha256Digest
    source_commit: GitObjectId
    artifact_digest: Sha256Digest
    state: Literal["built_and_launched", "failed"]
    evidence_class: Literal["public_collect_only"]
    qualifies_real_hardware_lifecycle: Literal[False]
    observed_at: AwareDatetime
    receipt_commitment: HmacCommitment

class MacTargetReceiptV1(StrictHardeningContract):
    schema_id: Literal["mac_target_receipt.v1"] = "mac_target_receipt.v1"
    target_id: UUID
    architecture: Literal["x86_64", "arm64"]
    os_version: BoundedSafeCode
    os_build: BoundedSafeCode
    hardware_model_commitment: HmacCommitment
    artifact_digest: Sha256Digest
    install_verified: Literal[True]
    update_verified: Literal[True]
    rollback_verified: Literal[True]
    preserve_uninstall_verified: Literal[True]
    destroy_uninstall_verified: Literal[True]
    real_hardware: Literal[True]
    started_at: AwareDatetime
    completed_at: AwareDatetime
    evidence_digest: Sha256Digest
    receipt_commitment: HmacCommitment

    @model_validator(mode="after")
    def positive_real_target_window(self) -> "MacTargetReceiptV1":
        if self.completed_at <= self.started_at:
            raise ValueError("mac_target_receipt_window_invalid")
        return self

class LinuxServiceTargetReceiptV1(StrictHardeningContract):
    schema_id: Literal["linux_service_target_receipt.v1"] = "linux_service_target_receipt.v1"
    target_id: UUID
    service_manifest_id: BoundedSafeCode
    service_target_id: BoundedSafeCode
    distribution_name: BoundedSafeCode
    target_kind: Literal["systemd", "compose", "reachy_managed_app"]
    architecture: Literal["x86_64", "arm64"]
    os_distribution: BoundedSafeCode
    os_version: BoundedSafeCode
    service_manager_version: BoundedSafeCode
    artifact_digest: Sha256Digest
    service_manifest_digest: Sha256Digest
    job_or_unit_digest: Sha256Digest
    config_template_digest: Sha256Digest
    install_verified: Literal[True]
    start_health_verified: Literal[True]
    crash_restart_new_generation_verified: Literal[True]
    wrong_account_config_denial_verified: Literal[True]
    update_verified: Literal[True]
    rollback_verified: Literal[True]
    preserve_uninstall_verified: Literal[True]
    destroy_uninstall_verified: Literal[True]
    residue_absent_verified: Literal[True]
    real_clean_target: Literal[True]
    started_at: AwareDatetime
    completed_at: AwareDatetime
    evidence_digest: Sha256Digest
    receipt_commitment: HmacCommitment

    @model_validator(mode="after")
    def positive_real_linux_target_window(self) -> "LinuxServiceTargetReceiptV1":
        if self.completed_at <= self.started_at:
            raise ValueError("linux_service_target_receipt_window_invalid")
        return self

class LinuxServiceTargetKeyV1(StrictHardeningContract):
    service_manifest_id: BoundedSafeCode
    service_target_id: BoundedSafeCode

class CompatibilityTargetV1(StrictHardeningContract):
    architecture: Literal["x86_64", "arm64"]
    os_version: BoundedSafeCode
    os_build: BoundedSafeCode
    artifact_digest: Sha256Digest
    real_hardware_receipt_commitment: HmacCommitment

class CompatibilityManifestV1(StrictHardeningContract):
    schema_id: Literal["compatibility_manifest.v1"] = "compatibility_manifest.v1"
    targets: Annotated[tuple[CompatibilityTargetV1, ...], Field(min_length=1, max_length=8)]
    feature_manifest_digest: Sha256Digest
    service_inventory_digest: Sha256Digest
    enabled_linux_service_targets: Annotated[tuple[LinuxServiceTargetKeyV1, ...], Field(max_length=16)]
    linux_service_targets: Annotated[tuple[LinuxServiceTargetReceiptV1, ...], Field(max_length=16)]
    public_smoke_receipts: Annotated[tuple[BuildSmokeReceiptV1, ...], Field(min_length=2, max_length=16)]
    manifest_digest: Sha256Digest
    issued_at: AwareDatetime
    signer_identity: BoundedSignatureIdentity
    manifest_commitment: HmacCommitment

    @model_validator(mode="after")
    def unique_real_hardware_targets(self) -> "CompatibilityManifestV1":
        keys = tuple((target.architecture, target.os_version, target.os_build, target.artifact_digest) for target in self.targets)
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate_compatibility_target")
        linux_keys = tuple(
            (target.service_manifest_id, target.service_target_id, target.artifact_digest)
            for target in self.linux_service_targets
        )
        if len(set(linux_keys)) != len(linux_keys):
            raise ValueError("duplicate_linux_service_compatibility_target")
        expected_linux_keys = {
            (target.service_manifest_id, target.service_target_id)
            for target in self.enabled_linux_service_targets
        }
        actual_linux_keys = {
            (target.service_manifest_id, target.service_target_id)
            for target in self.linux_service_targets
        }
        if actual_linux_keys != expected_linux_keys:
            raise ValueError("linux_service_target_matrix_mismatch")
        if {target.architecture for target in self.targets} != {"x86_64", "arm64"}:
            raise ValueError("compatibility_real_target_architectures_incomplete")
        if {receipt.architecture for receipt in self.public_smoke_receipts} != {"x86_64", "arm64"}:
            raise ValueError("compatibility_public_smoke_architectures_incomplete")
        target_artifacts = {(target.architecture, target.artifact_digest) for target in self.targets}
        if any(
            receipt.state != "built_and_launched"
            or (receipt.architecture, receipt.artifact_digest) not in target_artifacts
            for receipt in self.public_smoke_receipts
        ):
            raise ValueError("compatibility_smoke_not_bound_to_final_target_artifact")
        commitments = tuple(receipt.receipt_commitment for receipt in self.public_smoke_receipts)
        if len(set(commitments)) != len(commitments):
            raise ValueError("duplicate_public_smoke_receipt")
        return self

class GateAssertionBaseV1(StrictHardeningContract):
    candidate_id: UUID
    candidate_commitment: HmacCommitment
    artifact_set_digest: Sha256Digest
    artifact_inventory_digest: Sha256Digest
    assertion_id: UUID
    signer_identity: BoundedSignatureIdentity
    local_presence: Literal[True]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    credential_revocation_generation: Annotated[int, Field(ge=1)]
    assertion_commitment: HmacCommitment
    signature: P256Signature

    @model_validator(mode="after")
    def fresh_local_assertion(self) -> "GateAssertionBaseV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(minutes=2):
            raise ValueError("release_gate_assertion_window_invalid")
        return self

class C0ApprovalReceiptV1(GateAssertionBaseV1):
    schema_id: Literal["c0_approval_receipt.v1"] = "c0_approval_receipt.v1"
    decision: Literal["approve"]
    credential_namespace: Literal["household_owner_c0"]
    signature_domain: Literal["tuntun.c0.household-owner.v1"]

class C0RejectionReceiptV1(GateAssertionBaseV1):
    schema_id: Literal["c0_rejection_receipt.v1"] = "c0_rejection_receipt.v1"
    decision: Literal["reject"]
    credential_namespace: Literal["household_owner_c0"]
    signature_domain: Literal["tuntun.c0.household-owner.v1"]
    reason_codes: Annotated[tuple[SafeReasonCode, ...], Field(min_length=1, max_length=16)]

class C0AcceptedReceiptV1(StrictHardeningContract):
    schema_id: Literal["c0_accepted_receipt.v1"] = "c0_accepted_receipt.v1"
    candidate_id: UUID
    candidate_commitment: HmacCommitment
    artifact_set_digest: Sha256Digest
    artifact_inventory_digest: Sha256Digest
    accepted_assertion_id: UUID
    approval_receipt_commitment: HmacCommitment
    credential_namespace: Literal["household_owner_c0"]
    signer_identity: BoundedSignatureIdentity
    signature_domain: Literal["tuntun.c0.household-owner.v1"]
    local_presence: Literal[True]
    assertion_issued_at: AwareDatetime
    assertion_expires_at: AwareDatetime
    approval_signature: P256Signature
    credential_revocation_generation: Annotated[int, Field(ge=1)]
    accepted_at: AwareDatetime
    accepted_commitment: HmacCommitment

    @model_validator(mode="after")
    def accepted_current_c0_assertion_window(self) -> "C0AcceptedReceiptV1":
        if not self.assertion_issued_at <= self.accepted_at < self.assertion_expires_at:
            raise ValueError("c0_acceptance_outside_assertion_window")
        return self

class C0ReleaseHandoffV1(StrictHardeningContract):
    schema_id: Literal["c0_release_handoff.v1"] = "c0_release_handoff.v1"
    handoff_id: UUID
    handoff_generation: Annotated[int, Field(ge=1)]
    candidate: C0CandidateV1
    candidate_canonical_digest: Sha256Digest
    accepted_c0: C0AcceptedReceiptV1
    accepted_c0_commitment: HmacCommitment
    release_manifest_digest: Sha256Digest
    artifact_set_digest: Sha256Digest
    artifact_inventory_digest: Sha256Digest
    artifact_digests: Annotated[tuple[NamedArtifactDigestV1, ...], Field(min_length=1, max_length=256)]
    credential_status: Literal["current"]
    handoff_assertion_id: UUID
    handoff_signer_identity: BoundedSignatureIdentity
    handoff_key_generation: Annotated[int, Field(ge=1)]
    signature_domain: Literal["tuntun.c0.release-handoff.v1"]
    issued_at: AwareDatetime
    valid_until: AwareDatetime
    handoff_signature: P256Signature

    @model_validator(mode="after")
    def exact_short_lived_c0_binding(self) -> "C0ReleaseHandoffV1":
        if not self.issued_at < self.valid_until <= self.issued_at + timedelta(minutes=15):
            raise ValueError("c0_release_handoff_window_invalid")
        if sha256(canonical_hardening_bytes(self.candidate)).hexdigest() != self.candidate_canonical_digest:
            raise ValueError("c0_release_handoff_candidate_digest_mismatch")
        if (
            self.candidate.candidate_id != self.accepted_c0.candidate_id
            or self.candidate.candidate_commitment != self.accepted_c0.candidate_commitment
            or self.accepted_c0.accepted_commitment != self.accepted_c0_commitment
            or self.candidate.artifact_set_digest != self.artifact_set_digest
            or self.accepted_c0.artifact_set_digest != self.artifact_set_digest
            or self.candidate.artifact_inventory_digest != self.artifact_inventory_digest
            or self.accepted_c0.artifact_inventory_digest != self.artifact_inventory_digest
            or digest_named_artifact_inventory(self.artifact_digests) != self.artifact_inventory_digest
            or self.handoff_assertion_id == self.accepted_c0.accepted_assertion_id
            or self.handoff_signer_identity != self.accepted_c0.signer_identity
            or self.handoff_key_generation != self.accepted_c0.credential_revocation_generation
        ):
            raise ValueError("c0_release_handoff_binding_mismatch")
        release_manifests = tuple(
            item for item in self.artifact_digests if item.artifact_name == "release-manifest.json"
        )
        if len(release_manifests) != 1 or release_manifests[0].digest != self.release_manifest_digest:
            raise ValueError("c0_release_handoff_release_manifest_mismatch")
        return self

class C1ApprovalReceiptV1(GateAssertionBaseV1):
    schema_id: Literal["c1_approval_receipt.v1"] = "c1_approval_receipt.v1"
    decision: Literal["approve"]
    credential_namespace: Literal["project_maintainer_c1"]
    signature_domain: Literal["tuntun.c1.project-maintainer.v1"]
    accepted_c0_commitment: HmacCommitment

class C1RejectionReceiptV1(GateAssertionBaseV1):
    schema_id: Literal["c1_rejection_receipt.v1"] = "c1_rejection_receipt.v1"
    decision: Literal["reject"]
    credential_namespace: Literal["project_maintainer_c1"]
    signature_domain: Literal["tuntun.c1.project-maintainer.v1"]
    accepted_c0_commitment: HmacCommitment
    reason_codes: Annotated[tuple[SafeReasonCode, ...], Field(min_length=1, max_length=16)]

class C1AcceptedReceiptV1(StrictHardeningContract):
    schema_id: Literal["c1_accepted_receipt.v1"] = "c1_accepted_receipt.v1"
    candidate_id: UUID
    candidate_commitment: HmacCommitment
    artifact_set_digest: Sha256Digest
    artifact_inventory_digest: Sha256Digest
    publication_manifest_digest: Sha256Digest
    release_manifest_digest: Sha256Digest
    accepted_c0_commitment: HmacCommitment
    accepted_assertion_id: UUID
    approval_receipt_commitment: HmacCommitment
    credential_namespace: Literal["project_maintainer_c1"]
    signer_identity: BoundedSignatureIdentity
    signature_domain: Literal["tuntun.c1.project-maintainer.v1"]
    local_presence: Literal[True]
    assertion_issued_at: AwareDatetime
    assertion_expires_at: AwareDatetime
    approval_signature: P256Signature
    credential_revocation_generation: Annotated[int, Field(ge=1)]
    accepted_at: AwareDatetime
    accepted_commitment: HmacCommitment

    @model_validator(mode="after")
    def accepted_current_c1_assertion_window(self) -> "C1AcceptedReceiptV1":
        if not self.assertion_issued_at <= self.accepted_at < self.assertion_expires_at:
            raise ValueError("c1_acceptance_outside_assertion_window")
        return self

class PublicationReceiptV1(StrictHardeningContract):
    schema_id: Literal["publication_receipt.v1"] = "publication_receipt.v1"
    candidate_id: UUID
    accepted_c1_commitment: HmacCommitment
    publication_manifest_digest: Sha256Digest
    final_release_manifest_digest: Sha256Digest
    exact_published_artifact_set_digest: Sha256Digest
    exact_published_artifact_inventory_digest: Sha256Digest
    immutable_tag: Annotated[
        str,
        Field(min_length=2, max_length=65, pattern=r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$"),
    ]
    published_source_commit: GitObjectId
    tag_created_without_overwrite: Literal[True]
    tag_target_verified: Literal[True]
    publication_action_id: UUID
    publication_action_commitment: HmacCommitment
    assertion_id: UUID
    credential_namespace: Literal["project_maintainer_publication"]
    publisher_identity: BoundedSignatureIdentity
    signature_domain: Literal["tuntun.publication.project-maintainer.v1"]
    local_presence: Literal[True]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    authority_claimed_at: AwareDatetime
    operation_deadline: AwareDatetime
    published_at: AwareDatetime
    credential_revocation_generation: Annotated[int, Field(ge=1)]
    publication_commitment: HmacCommitment
    signature: P256Signature

    @model_validator(mode="after")
    def fresh_publication_assertion(self) -> "PublicationReceiptV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(minutes=2):
            raise ValueError("publication_assertion_window_invalid")
        if not self.issued_at <= self.authority_claimed_at < self.expires_at:
            raise ValueError("publication_authority_claim_outside_assertion_window")
        if not (
            self.authority_claimed_at <= self.published_at < self.operation_deadline
            <= self.authority_claimed_at + timedelta(minutes=30)
        ):
            raise ValueError("publication_outside_bounded_effect_window")
        return self

# packages/contracts/src/tuntun_contracts/hardening/incident.py
class IncidentStateV1(StrictHardeningContract):
    schema_id: Literal["incident_state.v1"] = "incident_state.v1"
    incident_id: UUID
    incident_generation: Annotated[int, Field(ge=1)]
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
        if self.state != "normal" and (self.exited_at is not None or self.owner_approval_commitment is not None):
            raise ValueError("contained_incident_cannot_claim_exit")
        if self.state == "normal" and (
            (self.exited_at is None) != (self.owner_approval_commitment is None)
        ):
            raise ValueError("normal_incident_exit_shape_incomplete")
        return self

IncidentExitCheckClass = Literal[
    "integrity", "secret_rotation", "credential_recreation",
    "network_exposure", "deletion_reconciliation", "safety",
]

class IncidentExitCheckV1(StrictHardeningContract):
    check_class: IncidentExitCheckClass
    generation: Annotated[int, Field(ge=1)]
    evidence_digest: Sha256Digest
    observed_at: AwareDatetime
    valid_until: AwareDatetime

    @model_validator(mode="after")
    def bounded_incident_exit_check(self) -> "IncidentExitCheckV1":
        if not self.observed_at < self.valid_until <= self.observed_at + timedelta(seconds=30):
            raise ValueError("incident_exit_check_window_invalid")
        return self

class PreparedIncidentExitV1(StrictHardeningContract):
    schema_id: Literal["prepared_incident_exit.v1"] = "prepared_incident_exit.v1"
    preparation_id: UUID
    incident_id: UUID
    expected_incident_state: Literal["contained_remote", "contained_egress", "recovery_quarantine"]
    expected_incident_generation: Annotated[int, Field(ge=1)]
    expected_controller_generation: Annotated[int, Field(ge=1)]
    expected_session_generation: Annotated[int, Field(ge=1)]
    checks: Annotated[tuple[IncidentExitCheckV1, ...], Field(min_length=6, max_length=6)]
    prepared_at: AwareDatetime
    expires_at: AwareDatetime
    preparation_commitment: HmacCommitment

    @model_validator(mode="after")
    def exact_current_incident_exit_preparation(self) -> "PreparedIncidentExitV1":
        expected = {
            "integrity", "secret_rotation", "credential_recreation",
            "network_exposure", "deletion_reconciliation", "safety",
        }
        classes = tuple(check.check_class for check in self.checks)
        if set(classes) != expected or len(set(classes)) != len(classes):
            raise ValueError("incident_exit_check_set_invalid")
        if not self.prepared_at < self.expires_at <= self.prepared_at + timedelta(minutes=2):
            raise ValueError("incident_exit_preparation_window_invalid")
        if any(not check.observed_at <= self.prepared_at < self.expires_at <= check.valid_until for check in self.checks):
            raise ValueError("incident_exit_preparation_not_covered_by_checks")
        return self

# packages/contracts/src/tuntun_contracts/hardening/maintenance.py
class MaintenanceMonthV1(StrictHardeningContract):
    schema_id: Literal["maintenance_month.v1"] = "maintenance_month.v1"
    month: YearMonth
    steady_state_generation: Annotated[int, Field(ge=1)]
    steady_state_epoch_started_at: AwareDatetime
    logging_eligible_at: AwareDatetime
    feature_rollover_chain_id: UUID
    feature_candidate_digest: Sha256Digest
    feature_authority_interval_digest: Sha256Digest
    feature_authority_expired_interval_count: Literal[0]
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
    source_snapshot_digest: Sha256Digest
    archive_manifest_digest: Sha256Digest
    deletion_generation: Annotated[int, Field(ge=1)]
    deletion_watermark: HmacCommitment
    key_bundle_commitment: HmacCommitment
    rpo_deadline: AwareDatetime
    restore_eligibility: Literal["eligible", "ineligible_deleted"]
    volume_commitment: HmacCommitment
    failure_domain_commitment: HmacCommitment
    retained_daily_generations: Literal[7]
    retained_weekly_generations: Literal[4]
    latest_verified_at: AwareDatetime

class IndependentBackupCopyV1(StrictHardeningContract):
    copy_id: UUID
    generation: Annotated[int, Field(ge=1)]
    source_snapshot_digest: Sha256Digest
    archive_manifest_digest: Sha256Digest
    deletion_generation: Annotated[int, Field(ge=1)]
    deletion_watermark: HmacCommitment
    key_bundle_commitment: HmacCommitment
    rpo_deadline: AwareDatetime
    restore_eligibility: Literal["eligible", "ineligible_deleted"]
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
        identical_snapshot_fields = (
            "source_snapshot_digest", "archive_manifest_digest", "deletion_generation",
            "deletion_watermark", "key_bundle_commitment", "rpo_deadline", "restore_eligibility",
        )
        if any(getattr(self.attached, field) != getattr(self.independent, field) for field in identical_snapshot_fields):
            raise ValueError("backup_tiers_do_not_bind_identical_source_snapshot")
        if self.attached.latest_verified_at > self.created_at or self.independent.verified_at > self.created_at:
            raise ValueError("backup_set_created_before_tier_verification")
        if self.created_at > self.attached.rpo_deadline:
            raise ValueError("backup_set_missed_rpo_deadline")
        return self

class RestoreRunV1(StrictHardeningContract):
    schema_id: Literal["restore_run.v1"] = "restore_run.v1"
    restore_run_id: UUID
    backup_set_id: UUID
    state: Literal["recovery_quarantine", "reconciling", "completed", "error_safe"]
    source_generation: Annotated[int, Field(ge=1)]
    prior_controller_generation: Annotated[int, Field(ge=1)]
    new_controller_generation: Annotated[int, Field(ge=1)]
    prior_session_generation: Annotated[int, Field(ge=1)]
    new_session_generation: Annotated[int, Field(ge=1)]
    prior_route_generation: Annotated[int, Field(ge=1)]
    new_route_generation: Annotated[int, Field(ge=1)]
    archive_signature_evidence_digest: Sha256Digest
    offline_key_reconstruction_evidence_digest: Sha256Digest
    sqlcipher_audit_migration_evidence_digest: Sha256Digest
    deletion_reconciliation_evidence_digest: Sha256Digest
    credential_exclusion_evidence_digest: Sha256Digest
    topology_binding_evidence_digest: Sha256Digest
    device_pairing_evidence_digest: Sha256Digest
    source_feature_manifest_digest: Sha256Digest
    restored_feature_manifest_digest: Sha256Digest
    feature_absence_evidence_digest: Sha256Digest
    reconciled_phase_ids: Annotated[
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
        if (
            self.new_controller_generation <= self.prior_controller_generation
            or self.new_session_generation <= self.prior_session_generation
            or self.new_route_generation <= self.prior_route_generation
        ):
            raise ValueError("restore_authority_generation_not_advanced")
        if self.reconciled_phase_ids != phase_order[:len(self.reconciled_phase_ids)]:
            raise ValueError("restore_phase_reconciliation_not_ordered")
        if self.restored_feature_manifest_digest != self.source_feature_manifest_digest:
            raise ValueError("restore_feature_manifest_or_absence_drift")
        if self.state == "completed":
            if self.reconciled_phase_ids != phase_order:
                raise ValueError("completed_restore_without_full_reconciliation")
            if self.completed_at is None or self.completed_at < self.started_at:
                raise ValueError("completed_restore_time_invalid")
        elif self.effect_route_state != "closed" or self.completed_at is not None:
            raise ValueError("incomplete_restore_not_quarantined")
        return self

class OfflineRecoveryBootstrapV1(StrictHardeningContract):
    schema_id: Literal["offline_recovery_bootstrap.v1"] = "offline_recovery_bootstrap.v1"
    bootstrap_id: UUID
    owner_recovery_identity_commitment: HmacCommitment
    archive_half_commitment: HmacCommitment
    offline_key_half_commitment: HmacCommitment
    archive_manifest_digest: Sha256Digest
    allowed_operations: tuple[
        Literal["verify"], Literal["decrypt_to_quarantine"], Literal["quarantine"],
    ]
    live_identity_state: Literal["mac_keychain_and_identity_db_unavailable"]
    state: Literal["prepared", "verifying", "quarantined", "consumed", "failed_closed"]
    one_shot_generation: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    consumed_at: AwareDatetime | None
    bootstrap_commitment: HmacCommitment

    @model_validator(mode="after")
    def one_shot_offline_only(self) -> "OfflineRecoveryBootstrapV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(hours=1):
            raise ValueError("offline_recovery_bootstrap_window_invalid")
        if (self.state == "consumed") != (self.consumed_at is not None):
            raise ValueError("offline_recovery_bootstrap_consumption_mismatch")
        if self.consumed_at is not None and not self.issued_at <= self.consumed_at < self.expires_at:
            raise ValueError("offline_recovery_bootstrap_consumed_outside_window")
        return self

class RecoveryIdentityReenrollmentReceiptV1(StrictHardeningContract):
    schema_id: Literal["recovery_identity_reenrollment_receipt.v1"] = "recovery_identity_reenrollment_receipt.v1"
    bootstrap_id: UUID
    restored_owner_subject_id: StableSubjectId
    new_passkey_generation: Annotated[int, Field(ge=1)]
    revoked_prior_credential_generation: Annotated[int, Field(ge=1)]
    restored_identity_generation: Annotated[int, Field(ge=1)]
    reenrolled_at: AwareDatetime
    receipt_commitment: HmacCommitment

    @model_validator(mode="after")
    def advances_beyond_every_revoked_prior_credential(self) -> "RecoveryIdentityReenrollmentReceiptV1":
        if self.new_passkey_generation <= self.revoked_prior_credential_generation:
            raise ValueError("recovery_passkey_generation_not_advanced")
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
    dependent_stop_state: Literal["pending", "completed"]
    owner_export_state: Literal["pending", "completed", "not_requested"]
    vendor_reset_state: Literal["pending", "verified_reset", "verified_attempt_unverifiable_storage", "not_applicable"]
    managed_storage_state: Literal["pending", "verified_crypto_shredded", "not_managed"]
    reconnect_state: Literal["pending", "old_identity_denied"]
    quarantined_at: AwareDatetime | None
    retired_at: AwareDatetime | None
    state_commitment: HmacCommitment

    @model_validator(mode="after")
    def coherent_retirement_lifecycle(self) -> "DeviceRetirementStateV1":
        if self.lifecycle == "active":
            effects_pending = (
                self.dependent_stop_state == "pending"
                and self.owner_export_state == "pending"
                and self.vendor_reset_state == "pending"
                and self.managed_storage_state == "pending"
                and self.reconnect_state == "pending"
            )
            if (
                self.authorities_revoked
                or not effects_pending
                or self.quarantined_at is not None
                or self.retired_at is not None
            ):
                raise ValueError("active_retirement_state_invalid")
        elif self.lifecycle == "retirement_quarantined":
            if not self.authorities_revoked or self.quarantined_at is None or self.retired_at is not None:
                raise ValueError("quarantined_retirement_state_invalid")
        else:
            effects_complete = (
                self.authorities_revoked
                and self.dependent_stop_state == "completed"
                and self.owner_export_state != "pending"
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
    dependent_stop_state: Literal["pending", "completed"]
    owner_export_state: Literal["pending", "completed", "not_requested"]
    vendor_reset_state: Literal["pending", "verified_reset", "verified_attempt_unverifiable_storage", "not_applicable"]
    managed_storage_state: Literal["pending", "verified_crypto_shredded", "not_managed"]
    reconnect_state: Literal["pending", "old_identity_denied"]
    claims_physical_flash_erasure: Literal[False]
    observed_at: AwareDatetime
    state_commitment: HmacCommitment

    @model_validator(mode="after")
    def no_false_retired_receipt(self) -> "RetirementReceiptV1":
        if self.lifecycle == "retired" and (
            self.dependent_stop_state != "completed"
            or self.owner_export_state == "pending"
            or self.vendor_reset_state == "pending"
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
    async def probe(self) -> RemoteAdapterProbeResultV1: ...
    async def close_route(self, reason: SafeReasonCode) -> RemoteRouteReceiptV1: ...
    async def revoke_node(self, local_pseudonym: RandomLocalPseudonym) -> NodeRevocationReceiptV1: ...

class PluginSupervisorPort(Protocol):
    async def invoke(self, call: PluginCallEnvelopeV1) -> PluginCallResultEnvelopeV1: ...
    async def revoke(self, plugin_id: StablePluginId, expected_grant_generation: int) -> PluginRevocationReceiptV1: ...

class ReleaseVerifierPort(Protocol):
    def verify(
        self, candidate: ReleaseCandidateV1, installed: InstalledReleaseV1, *, update_run_id: UUID,
    ) -> ReleaseDecisionV1: ...
~~~

### Durable update/rollback journal

~~~python
UpdateRunState = Literal[
    "prepared", "download_verified", "services_drained", "restore_points_durable",
    "code_switched", "schema_migrating", "schema_migrated", "health_verifying",
    "accepted", "rejected", "rollback_code", "rollback_schema", "rollback_verifying",
    "rolled_back", "quarantined",
]

UPDATE_RUN_TRANSITIONS: Final[dict[UpdateRunState, frozenset[UpdateRunState]]] = {
    "prepared": frozenset({"download_verified", "rejected", "quarantined"}),
    "download_verified": frozenset({"services_drained", "rejected", "quarantined"}),
    "services_drained": frozenset({"restore_points_durable", "rejected", "quarantined"}),
    "restore_points_durable": frozenset({"code_switched", "rollback_verifying", "quarantined"}),
    "code_switched": frozenset({"schema_migrating", "rollback_code", "quarantined"}),
    "schema_migrating": frozenset({"schema_migrated", "rollback_code", "quarantined"}),
    "schema_migrated": frozenset({"health_verifying", "rollback_code", "quarantined"}),
    "health_verifying": frozenset({"accepted", "rollback_code", "quarantined"}),
    "rollback_code": frozenset({"rollback_schema", "quarantined"}),
    "rollback_schema": frozenset({"rollback_verifying", "quarantined"}),
    "rollback_verifying": frozenset({"rolled_back", "quarantined"}),
    "accepted": frozenset({"accepted"}),
    "rejected": frozenset({"rejected"}),
    "rolled_back": frozenset({"rolled_back"}),
    "quarantined": frozenset({"quarantined"}),
}

class UpdateRestoreSetV1(StrictHardeningContract):
    restore_set_id: UUID
    update_run_id: UUID
    candidate_id: UUID
    candidate_manifest_digest: Sha256Digest
    candidate_artifact_set_id: UUID
    candidate_artifact_set_commitment: HmacCommitment
    backup_set_id: UUID
    admission_barrier_generation: Annotated[int, Field(ge=1)]
    source_generation: Annotated[int, Field(ge=1)]
    prior_release_manifest_digest: Sha256Digest
    prior_code_tree_digest: Sha256Digest
    prior_schema_head: BoundedSafeCode
    encrypted_database_snapshot_digest: Sha256Digest
    deletion_watermark: HmacCommitment
    feature_manifest_digest: Sha256Digest
    restore_set_commitment: HmacCommitment

class UpdateRunV1(StrictHardeningContract):
    schema_id: Literal["update_run.v1"] = "update_run.v1"
    update_run_id: UUID
    candidate_id: UUID
    candidate_manifest_digest: Sha256Digest
    candidate_artifact_set_id: UUID
    candidate_artifact_set_commitment: HmacCommitment
    state: UpdateRunState
    transition_sequence: Annotated[int, Field(ge=1)]
    verified_decision: ReleaseDecisionV1 | None
    restore_set: UpdateRestoreSetV1 | None
    state_file_fsynced: Literal[True]
    parent_directory_fsynced: Literal[True]
    services_exposed: bool
    started_at: AwareDatetime
    transitioned_at: AwareDatetime

    @model_validator(mode="after")
    def exposure_only_after_terminal_acceptance(self) -> "UpdateRunV1":
        if self.services_exposed != (self.state in {"accepted", "rejected", "rolled_back"}):
            raise ValueError("update_service_exposure_before_reconciliation")
        if self.transitioned_at < self.started_at:
            raise ValueError("update_transition_precedes_start")
        if self.verified_decision is not None and (
            not self.verified_decision.install_allowed
            or self.verified_decision.update_run_id != self.update_run_id
            or self.verified_decision.candidate_id != self.candidate_id
            or self.verified_decision.candidate_manifest_digest != self.candidate_manifest_digest
            or self.verified_decision.artifact_set_id != self.candidate_artifact_set_id
            or self.verified_decision.artifact_set_commitment != self.candidate_artifact_set_commitment
        ):
            raise ValueError("update_verified_decision_binding_mismatch")
        if self.state == "prepared" and self.verified_decision is not None:
            raise ValueError("prepared_update_cannot_claim_verified_decision")
        if self.state not in {"prepared", "rejected", "quarantined"} and self.verified_decision is None:
            raise ValueError("update_verified_decision_state_mismatch")
        if self.restore_set is not None and (
            self.restore_set.update_run_id != self.update_run_id
            or self.restore_set.candidate_id != self.candidate_id
            or self.restore_set.candidate_manifest_digest != self.candidate_manifest_digest
            or self.restore_set.candidate_artifact_set_id != self.candidate_artifact_set_id
            or self.restore_set.candidate_artifact_set_commitment != self.candidate_artifact_set_commitment
        ):
            raise ValueError("update_restore_set_run_or_candidate_binding_mismatch")
        if self.state == "quarantined":
            return self
        restore_set_required = self.state not in {"prepared", "download_verified", "services_drained", "rejected"}
        restore_set_present = self.restore_set is not None
        if restore_set_required != restore_set_present:
            raise ValueError("update_restore_set_state_mismatch")
        return self

class UpdateRunJournalEnvelopeV1(StrictHardeningContract):
    schema_id: Literal["update_run_journal_envelope.v1"] = "update_run_journal_envelope.v1"
    payload: UpdateRunV1
    payload_digest: Sha256Digest
    signer_key_id: KeyId
    signer_key_generation: Annotated[int, Field(ge=1)]
    signature_domain: Literal["tuntun.update-run-journal.v1"]
    journal_commitment: HmacCommitment
    signature: P256Signature

    @model_validator(mode="after")
    def exact_nonrecursive_payload_digest(self) -> "UpdateRunJournalEnvelopeV1":
        expected = sha256(canonical_hardening_bytes(self.payload)).hexdigest()
        if not hmac.compare_digest(self.payload_digest, expected):
            raise ValueError("update_journal_payload_digest_invalid")
        return self
~~~

`payload_digest` is SHA-256 over the exact canonical `UpdateRunV1` payload bytes; the payload contains neither its own digest nor the envelope commitment/signature, so the construction is nonrecursive. Repository reads use an owner-only nofollow regular-file bounded read, reject duplicate JSON keys/noncanonical bytes, validate the envelope, recompute the payload digest, verify the fixed-domain signature/current key generation, and only then expose the parsed payload. Every transition must be a legal edge in `UPDATE_RUN_TRANSITIONS` and uses compare-and-swap on `(update_run_id, expected_state, transition_sequence, prior_payload_digest)`; the new sequence is exactly prior+1. Terminal same-state retries are idempotent and no other terminal exit exists.

Every transition writes a new owner-only journal file with create/write/fsync/atomic-rename/fsync-parent semantics and fsyncs the code and database parent directories after namespace changes. Startup acquires the global update lock, enumerates journals, and either reconciles the sole current run or quarantines multiple competing/nonterminal/corrupt runs before any listener, worker, scheduler, plugin, action, media, desktop, robot, or remote route starts. Rollback restores code and schema from the independently verified restore points, re-runs migration and privacy/network/health checks in quarantine, and only then records `rolled_back`; exception handling alone is never rollback evidence. SIGKILL and power-loss tests stop after every durable and namespace transition, including each inverse transition, and corrupt/missing/mismatched restore points keep the system quarantined.

## Durable State and Migration Map

The canonical core Alembic graph remains one exact linear head. Phase 6 consumes the accepted Phase 5 head and appends `0023_remote_access.down_revision = 0022_robotics`, `0024_plugins_releases.down_revision = 0023_remote_access`, and `0025_recovery_incident_maintenance.down_revision = 0024_plugins_releases`. The verifier enumerates every revision/edge from the canonical base through `0025`; an edited applied revision, branch label, `depends_on`, multi-parent merge, hidden fork, orphan, missing parent, extra head, or conditional authority reopened by downgrade/restore blocks startup.

| Migration | Exact parent | Tables/state | Forbidden content | Restore/rollback rule |
|---|---|---|---|---|
| `0023_remote_access` | `0022_robotics` | `remote_nodes`, `remote_routes`, `remote_sessions`, `remote_operation_classes`, `remote_security_counters` | Vendor node name/user/email/IP, passkey secret, request body, clip URL, family content | Down migration revokes sessions and returns route to `DISABLED`; restore rotates route/session generations and requires re-commissioning |
| `0024_plugins_releases` | `0023_remote_access` | `plugin_installations`, `plugin_grants`, `plugin_invocation_receipts`, `release_candidates`, `release_artifacts`, `update_runs` | Plugin request/result text, filesystem/network data, signing/notarization secret, household evidence body | Plugin restore is quarantined and never restores running process/grant; release records are evidence only and cannot authorize publication |
| `0025_recovery_incident_maintenance` | `0024_plugins_releases` | `backup_sets`, `independent_copy_operations`, `restore_runs`, `restore_journals`, `deletion_reconciliations`, `incidents`, `containment_effect_runs`, `containment_admission_barriers`, `retirement_effect_runs`, `phase4_maintenance_source_claims`, `maintenance_months`, `maintenance_expansion_freeze` | Recovery key, archive plaintext, raw restore path, deleted record body, raw incident payload, raw retirement export, arbitrary owner notes | Nonterminal copy/restore/containment/retirement state blocks readiness; restore begins `RECOVERY_QUARANTINE`; deletion tombstones win over archive rows; each committed Phase 4 source record is unique/idempotent; freeze clears only through local owner simplification/retirement evidence |

Every migration uses the shared serialized SQLCipher unit of work and trigger-protected audit/outbox. An interrupted migration restores the verified pre-migration archive into isolated paths; it never partially opens a Phase 6 route. The portable archive omits live remote/plugin/provider/device/signing credentials by construction.

### Mandatory audited negative, provider-backed, crash, and release gates

These tests are part of the existing Tasks 01–38 and do not add or renumber tasks:

- **Tasks 01, 07–10 — sole Tailnet Lock admission:** provider-backed fixtures prove Device Approval is disabled, Tailnet Lock enabled, the current core node signed, the exact approved owner-node set current, generations current, and at least two distinct independent signing nodes plus tested recovery. Reject both features enabled, Device Approval enabled alone, unsigned/removed/revoked/extra node, one/duplicate signer, generation drift, recovery mismatch, and provider state changing between context creation and I/O. Rename all positive DTO/schema/table/evidence fields to Tailnet-Lock/signed-node terminology; legacy device-approval keys are accepted nowhere.
- **Tasks 01, 08–10, 14 — resolver and grants policy:** generate one canonical current Tailscale `grants` policy from exact approved owner-node `src` selectors, a closed `tagOwners`, separate exact `dst: ["tag:tuntun-core"]`, and `ip: ["tcp:8443", "tcp:53", "udp:53"]`. Validate it with the pinned official provider parser/check command and built-in tests, hash the canonical provider output, then probe approved, unapproved, and revoked nodes. Reject legacy positive `acls` sections/files, port-suffixed `dst` selectors, hostname destinations, wildcard source/destination/port, subnet/exit/Funnel/Serve/SSH, untagged core, open tag owner, and provider digest drift.
- **Tasks 08–10, 14 — exact authoritative DNS:** with the stable WebAuthn RP ID `tuntun.home.arpa`, a LAN-view commissioned client receives only the current commissioned LAN IPv4 address and an approved Tailnet node receives only the current Tailnet IPv4 address. The unprivileged parser receives port 53 sockets from `launchd`; no long-running root parser exists. Tests deny recursion, dynamic update, AXFR, other zones/names, wildcard, AAAA/IPv6, wrong/uncommissioned source/listener, wrong-view answer, rebinding, cache leakage across views, nonzero household payload fields, TCP truncation bypass, and DNS/certificate/grants digest drift. Commissioning binds both resolver/listener addresses, record/TTL, client DNS acceptance, certificate SAN/local CA, and canonical grants-policy digest.
- **Tasks 08, 10–18, 22, 28, 32, 35–36 — one owner-ingress and server authority:** listener inventory proves Phase 6 adds `owner_vpn_https` to the Phase 3 owner-ingress server on the exact Tailnet address:8443 and preserves loopback/LAN classes. Core and media proxy own no TCP listener or alternate media route throughout enable, suspend, revoke, restart, update, and rollback. Every Phase 6 owner-facing route is composed through the canonical Core app/container, owner-ingress router and one signed route manifest; the service row is re-signed and lifecycle-qualified at the P6-1, P6-2, P6-3 and final post-P6-4 checkpoints. HTTP JSON contains only operation/resource/idempotency; injected former session/actor/node/policy/generation/assurance/time/commitment fields fail `extra=forbid`. The server resolves the HttpOnly cookie, authoritative current owner/session, node posture, resources, and all generations into `AuthorizedRemoteContextV1`; policy, storage, action, and media ports accept only that context. Spoofing each former field, cross-owner/cross-subject access, revocation or commitment mutation yields zero database decrypt, adapter, media, or other I/O.
- **Tasks 11, 16–18 and UI U23 — shared remote denial registry:** generate all denial tests from `RemoteOperationName` and `PERMANENT_REMOTE_DENIALS`; real IDs include `plugin_permission_change` and `recovery_key_import`. `plugin_permission`, `recovery_import`, and every alias/unknown spelling are `SCHEMA_UNSUPPORTED`, never mapped. Remote private detail may reveal only the authenticated owner's own current `subject_private` body; owner-not-subject and all legacy audience aliases are opaque/absent.
- **Tasks 20–23 — plugin child-wire separation:** capture child stdin/stdout for both capabilities and prove byte-for-byte equality with the dedicated child DTO bytes. Recursively inspect decoded objects and reject every schema/request/purpose/generation/time/expiry/grant/commitment/plugin/version/capability/codec/registry key at any depth. Codec selection is supervisor-local and cannot be influenced by manifest, payload, child output, environment, argv, or filename. Wrong codec, cross-capability payload, metadata smuggling, replay, output-envelope forgery, crash, timeout, OOM, network syscall, and cleanup faults deny while the mandatory core alert remains.
- **Tasks 26–29 — exact release bytes and real targets:** build, lock dependencies, generate SPDX SBOM and provenance, then sign/notarize/staple the package; only after stapling hash the exact final distributable bytes and sign `ReleaseManifestV1` plus the C1 candidate commitment. Re-download verification hashes the frozen bytes. Public pinned x86_64/arm64 smoke receipts remain collect-only. Each architecture/OS/artifact claimed by `CompatibilityManifestV1` requires a separate current `MacTargetReceiptV1` from real hardware covering install, update, rollback, preserve uninstall, and destroy uninstall. Every Linux service target enabled by the same signed feature/service manifest requires a separate `LinuxServiceTargetReceiptV1` over its exact final distribution/job-or-unit/config/inventory digests and target kind (`systemd|compose|reachy_managed_app`), including clean install, start/health, crash/new-generation, wrong-account/config denial, update, rollback, both uninstall modes and residue absence on its declared target. An absent Linux target must have no artifact or receipt. Synthetic/collect-only/cross-artifact/old-OS receipt substitution, undeclared virtualization, download mutation, and one-byte final-artifact mutation block C1.
- **Tasks 28–29 — crash-safe update/rollback:** inject SIGKILL and simulated power loss before and after every state-file fsync, atomic rename, parent-directory fsync, code switch, schema transition, health check, and inverse transition. Restart must reconcile under the global update lock before service exposure. Missing/corrupt/mismatched code or schema restore point, interrupted rollback, failed inverse fsync, multiple journals, and a migration that reopens conditional authority remain quarantined with the prior accepted release preserved.
- **Tasks 30–31 — durable copy/restore ownership and offline bootstrap:** both tiers must match source snapshot/archive manifest digests, deletion generation/watermark, key-bundle commitment, generation, restore eligibility, and RPO deadline while remaining independent failure domains. Preallocate and fsync a copy operation before destination I/O; inject cancellation, SIGKILL, commit-response loss and restart at every boundary and require exactly one recorded copy, proved erase or owned non-eligible quarantine before readiness. Before the first restore plaintext byte, fsync the network-none proof, hash-linked restore journal and target quarantine marker; inject crash/corruption/competition at every decrypt/migration/integrity/tombstone/credential/reconciliation/publication boundary and require startup reconciliation before exposure. Deleting data immediately marks every affected older generation restore-ineligible and clean restore never resurrects it. When and only when live Mac/Keychain/identity DB is unavailable, a one-shot bootstrap can verify/decrypt-to-quarantine/quarantine; it cannot authenticate, list bodies, enable routes, mutate policy, or perform an action. Test each archive/key half missing/wrong, wrong owner, replay, expiry, concurrent/restarted/interrupted bootstrap, and live-system misuse. Successful canonical identity restore requires a new passkey generation and revokes all prior credential generations before phase re-enable.
- **Tasks 32–33 — durable containment and retirement ordering:** incident entry first commits a pending effect run plus closed admission barrier, revoked generations and exact stop operations; no final public state or exit/competing transition is allowed until current stop acknowledgements and zero-residue proof pass. Device retirement locks/rechecks topology and commits quarantine/revocation before dependent stop, owner export, vendor reset, managed-storage shred or reconnect proof. Inject delay, failure, SIGKILL and restart before/after every commit/effect/checkpoint; startup resumes the same run with admissions/old identity denied, and final state requires the exact complete checkpoint set.
- **Task 34 — Phase 4 maintenance composition:** consume `Phase4MaintenanceRecordV1` only through the closed `Phase4MaintenanceContributionV1` mapper. All five Phase 4 source subsystems map to `phase4_voice_media_displays`; every source exclusion maps exactly, while ambiguous `quarterly_drill` remains the explicit `phase4_quarterly_drill` aggregate class and is never guessed to mean restore, security, or physical-safety drill. Verify the source commitment, normalize `occurred_at` to UTC, and require its UTC calendar month to equal `month_key` before aggregation. Unknown source values, altered commitments, month-boundary/offset substitution, ordinary/excluded shape mismatch, duplicate source record, or double counting fails closed.
- **Tasks 03, 28–31 — migration graph:** fresh install, exact sequential upgrade, interruption/restart at every Phase 5/6 revision, downgrade-or-clean-restore, and restored prior-head fixtures enumerate the actual canonical `0019_screen_time_real_adapter -> 0020_private_ai_registry -> 0021_desktop_authority -> 0022_robotics -> 0023_remote_access -> 0024_plugins_releases -> 0025_recovery_incident_maintenance` graph. Wrong parent, edited applied hash, branch/merge/multiple head, hidden fork, orphan, and downgrade authority resurrection fail closed.
- **Tasks 36–38 — C0/C1 authority and publication:** strict approval, rejection, accepted, and publication receipts verify exact candidate/artifact set, credential namespace, assertion ID, signer identity/signature domain, local-presence freshness/expiry, and revocation generation. CI can collect evidence only; household owner credentials can sign only C0, maintainer credentials only C1/publication, and each cross-use (including remote requests, household UI, diagnostics, backup, or support bundle) is denied. Household UI projects read-only C1 state; the separate maintainer terminal/app imports no household package, database, cookie, key, evidence body, or API client. Publication is a third fresh action over the accepted unchanged C1 bytes.

All negative tests assert the rejection occurs before external I/O and that the route/listener/feature manifest returns to its exact prior disabled or quarantined state.

## Standard Commands and Owner-Gated Evidence Flags

~~~bash
make bootstrap
make check
uv run pytest -q
pnpm --filter @tuntun/admin test
pnpm --filter @tuntun/admin typecheck
pnpm --filter @tuntun/admin build
pnpm --filter @tuntun/admin e2e
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

def test_one_plugin_artifact_binds_exactly_one_capability(plugin_manifest_fixture) -> None:
    with pytest.raises(ValidationError):
        PluginManifestV1.model_validate({
            **plugin_manifest_fixture,
            "requested_capability_ids": (
                "system.health.render.v1",
                "notification.local_alert.render.v1",
            ),
        })

def test_remote_session_limits_are_closed(remote_session_fixture) -> None:
    session = RemoteSessionV1.model_validate(remote_session_fixture)
    assert session.idle_expires_at - session.last_access_at <= timedelta(minutes=15)
    assert session.absolute_expires_at - session.established_at <= timedelta(hours=8)
    assert session.operation_class_generation >= 1

@pytest.mark.parametrize("fault", [
    "reauth_before_established", "access_before_reauthentication", "idle_not_positive", "idle_over_fifteen_minutes",
    "absolute_not_positive", "absolute_over_eight_hours", "idle_after_absolute",
])
def test_remote_session_rejects_every_invalid_window(remote_session_fixture, mutate_window, fault) -> None:
    with pytest.raises(ValidationError):
        RemoteSessionV1.model_validate(mutate_window(remote_session_fixture, fault))

def test_authorized_context_rejects_future_reauthentication(authorized_context_fixture) -> None:
    with pytest.raises(ValidationError, match="reauthentication_in_future"):
        AuthorizedRemoteContextV1.model_validate({
            **authorized_context_fixture,
            "last_reauthenticated_at": authorized_context_fixture["authorized_at"] + timedelta(microseconds=1),
        })

@pytest.mark.parametrize("source", [
    "owner@example.test", "group:owners", "autogroup:member", "tag:owner-device",
    "100.63.255.255", "100.128.0.1", "100.064.0.1", "*",
])
def test_grant_source_is_one_canonical_tailnet_ipv4_not_a_broad_principal(grants_payload, source) -> None:
    with pytest.raises(ValidationError):
        TailscaleGrantsPolicyV1.model_validate(grants_payload.with_src((source,)))

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
    with pytest.raises(ValidationError, match="contained_incident_cannot_claim_exit"):
        IncidentStateV1.model_validate({
            **incident_fixture,
            "exited_at": incident_fixture["entered_at"] + timedelta(seconds=1),
            "owner_approval_commitment": SYNTHETIC_COMMITMENT,
        })
    with pytest.raises(ValidationError, match="normal_incident_exit_shape_incomplete"):
        IncidentStateV1.model_validate({
            **incident_fixture,
            "state": "normal", "reason_codes": (),
            "exited_at": incident_fixture["entered_at"] + timedelta(seconds=1),
            "owner_approval_commitment": None,
        })
    with pytest.raises(ValidationError):
        RemoteRouteStateV1.model_validate({**remote_route_fixture, "reason_codes": ("drift", "drift")})
    with pytest.raises(ValidationError):
        IncidentStateV1.model_validate({**incident_fixture, "reason_codes": ("containment",) * 17})
    with pytest.raises(ValidationError):
        MaintenanceMonthV1.model_validate({
            **maintenance_month_fixture,
            "ordinary_total_minutes": maintenance_month_fixture["ordinary_total_minutes"] + 1,
        })

@pytest.mark.parametrize("mutation", [
    "duplicate_check_class", "missing_check_class", "check_generation_zero",
    "check_window_inverted", "check_window_over_thirty_seconds",
    "prepared_before_check_observation", "preparation_expiry_after_check_expiry",
])
def test_prepared_incident_exit_requires_exact_fresh_check_set(
    prepared_incident_exit_fixture, mutate_incident_exit_preparation, mutation,
) -> None:
    with pytest.raises(ValidationError):
        PreparedIncidentExitV1.model_validate(
            mutate_incident_exit_preparation(prepared_incident_exit_fixture, mutation),
        )

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

def test_remote_adapter_failure_is_short_lived_and_content_minimized(remote_adapter_id, now) -> None:
    failure = RemoteAdapterUnavailableV1(
        state="unavailable",
        adapter_id=remote_adapter_id,
        adapter_class="tailscale",
        reason_code="remote_client_state_invalid",
        observed_at=now,
        valid_until=now + timedelta(seconds=5),
    )
    assert set(failure.model_dump()) == {
        "schema_id", "state", "adapter_id", "adapter_class", "reason_code",
        "observed_at", "valid_until",
    }
    assert not hasattr(failure, "node_pseudonym")
    with pytest.raises(ValidationError):
        RemoteAdapterUnavailableV1.model_validate({
            **failure.model_dump(),
            "valid_until": now + timedelta(seconds=6),
        })

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
    for former_caller_field in (
        "remote_session_id", "actor_subject_id", "vpn_node_pseudonym", "expected_policy_version",
        "expected_operation_class_generation", "expected_privacy_generation",
        "last_reauthenticated_at", "issued_at", "expires_at", "request_commitment",
    ):
        with pytest.raises(ValidationError):
            RemoteOperationRequestV1.model_validate({**remote_operation_fixture, former_caller_field: "spoof"})
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
    for former_error_state in ("expired", "failed"):
        with pytest.raises(ValidationError):
            PluginCallResultEnvelopeV1.model_validate({
                **plugin_result_fixture,
                "state": former_error_state,
                "payload": None,
            })
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

@pytest.mark.parametrize("mutation", [
    "inverted_window", "window_over_thirty_seconds", "duplicate_attention_code",
    "duplicate_component", "component_observed_after_snapshot", "component_expires_before_snapshot",
])
def test_plugin_health_component_facts_cannot_be_freshened_by_wrapper(
    plugin_health_snapshot_fixture, mutate_plugin_health_snapshot, mutation,
) -> None:
    with pytest.raises(ValidationError):
        PluginHealthSnapshotV1.model_validate(
            mutate_plugin_health_snapshot(plugin_health_snapshot_fixture, mutation),
        )

def test_release_decision_cannot_allow_without_verified_manifest(release_decision_fixture) -> None:
    with pytest.raises(ValidationError):
        ReleaseDecisionV1.model_validate({**release_decision_fixture, "install_allowed": True, "accepted_manifest": None})
    with pytest.raises(ValidationError, match="accepted_manifest_digest_mismatch"):
        ReleaseDecisionV1.model_validate({
            **release_decision_fixture,
            "candidate_manifest_digest": different_sha256(release_decision_fixture["candidate_manifest_digest"]),
        })

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

@pytest.mark.parametrize("mutation", [
    {"immutable_tag": "v9.9.9"},
    {"artifact_inventory_digest": "0" * 64},
    {"expires_at_delta": timedelta(hours=24, microseconds=1)},
])
def test_publication_manifest_rejects_tag_inventory_or_time_lies(
    publication_manifest_fixture, mutation,
) -> None:
    value = dict(publication_manifest_fixture)
    delta = mutation.pop("expires_at_delta", None)
    value.update(mutation)
    if delta is not None:
        value["expires_at"] = value["issued_at"] + delta
    with pytest.raises(ValidationError):
        PublicationManifestV1.model_validate(value)

@pytest.mark.parametrize("field", [
    "tag_created_without_overwrite", "tag_target_verified",
])
def test_publication_receipt_cannot_claim_unverified_or_overwritten_tag(
    publication_receipt_fixture, field,
) -> None:
    with pytest.raises(ValidationError):
        PublicationReceiptV1.model_validate({**publication_receipt_fixture, field: False})

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
        RestoreRunV1.model_validate({**restore_run_fixture, "state": "completed", "reconciled_phase_ids": ("phase1",)})
    with pytest.raises(ValidationError, match="feature_manifest_or_absence_drift"):
        RestoreRunV1.model_validate({
            **restore_run_fixture,
            "restored_feature_manifest_digest": DIFFERENT_DIGEST,
        })
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
            "lifecycle": "active",
            "authorities_revoked": False,
            "dependent_stop_state": "completed",
            "owner_export_state": "pending",
            "vendor_reset_state": "pending",
            "managed_storage_state": "pending",
            "reconnect_state": "pending",
            "quarantined_at": None,
            "retired_at": None,
        })
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
    for field in ("dependent_stop_state", "owner_export_state"):
        with pytest.raises(ValidationError):
            DeviceRetirementStateV1.model_validate({
                **retirement_state_fixture,
                "lifecycle": "retired",
                field: "pending",
            })
        with pytest.raises(ValidationError):
            RetirementReceiptV1.model_validate({
                **retirement_receipt_fixture,
                "lifecycle": "retired",
                field: "pending",
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

def test_hardening_canonicalizer_is_the_shared_encoder(canonical_edge_case_contract) -> None:
    assert canonical_hardening_bytes is canonical_bytes
    assert canonical_hardening_bytes(canonical_edge_case_contract) == canonical_bytes(
        canonical_edge_case_contract,
    )

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

### Task 02: Build deterministic Phase 6 fakes, hostile corpora, and the assurance-tool suite

**Depends on:** Task 01, the accepted Phase 1 shared structural-assurance scanners, and the accepted Phase 1–5/shared-UI generator set enumerated below.
**Gate contribution:** P6-E0 and every non-hardware Phase 6 task.
**Estimated effort:** 2.5 person-days.

**Files:**
- Create: `packages/testing/src/tuntun_testing/phase6/clock.py`
- Create: `packages/testing/src/tuntun_testing/phase6/remote.py`
- Create: `packages/testing/src/tuntun_testing/phase6/plugin.py`
- Create: `packages/testing/src/tuntun_testing/phase6/release.py`
- Create: `packages/testing/src/tuntun_testing/phase6/recovery.py`
- Create: `packages/testing/src/tuntun_testing/phase6/scenario.py`
- Create: `scripts/phase6/build_corpora.py`
- Modify: `scripts/assurance_common.py`
- Modify: `scripts/check_feature_absence.py`
- Modify: `scripts/check_import_boundaries.py`
- Modify: `scripts/check_migration_ownership.py`
- Modify: `scripts/scan_browser_artifacts.py`
- Modify: `scripts/scan_network_surface.py`
- Create: `scripts/check_public_api.py`
- Create: `scripts/check_licenses.py`
- Create: `scripts/check_docs_links.py`
- Create: `scripts/check_workflow_pins.py`
- Create: `scripts/check_runbooks.py`
- Create: `scripts/run_ui_matrix.py`
- Create: `scripts/check_critical_coverage.py`
- Create: `scripts/check_generated_artifacts.py`
- Create: `config/assurance/license-policy.v1.json`
- Create: `fixtures/synthetic/phase6/contracts/*.json`
- Create: `fixtures/adversarial/phase6/*.jsonl`
- Test: `tests/unit/testing/phase6/test_phase6_fakes.py`
- Test: `tests/unit/scripts/test_phase6_assurance_tools.py`
- Test: `tests/security/phase6/test_assurance_tools_fail_closed.py`
- Test: `tests/privacy/phase6/test_synthetic_only.py`
- Test: `tests/contract/hardening/test_threat_scenario_registry.py`

**Interfaces:** Produces fake clock, route, Tailscale posture, firewall scan, passkey assurance, plugin child, sandbox, release signer, archive, restore target, fault points, and a closed `ThreatScenarioRegistry` with exactly `T01` through `T25`. Fakes never require a real VPN, Keychain, Apple credential, network, or household bytes.

This task is the sole owner of the eight Phase 6 assurance commands and extends—without renaming or weakening—the five foundation-owned shared commands. Every command exposes `main(argv: Sequence[str] | None = None) -> int`, accepts the common optional lexical `--root PATH` (default: current repository), uses `scripts/assurance_common.py`, returns `0` only after a complete passing inventory, `1` for a finding, and `2` for invalid/incomplete/raced/unparseable input. Ordinary mode is read-only, deterministic, network-free, bounded by file/count/depth/token/subprocess-output/time limits, and rejects symlinks/special files/duplicate keys/non-canonical CSV/unknown arguments.

- `check_public_api.py PACKAGE --expected PATH` builds or inspects the named local package without importing it, enumerates wheel modules/`__all__`/public symbols/signatures/dependencies from bounded metadata and AST, and requires canonical equality with the duplicate-safe expected JSON manifest.
- `check_licenses.py --project [--check] [--output PATH]` reads exact Python and pnpm lock entries, requires one SPDX expression and source/version/digest for every transitive dependency, evaluates only the closed policy in `config/assurance/license-policy.v1.json`, and deterministically renders `THIRD_PARTY_NOTICES.txt`. `--check` compares the frozen bytes; without it, writing is allowed only to the explicit lexical output below `var/` or a task-owned release staging root via atomic create/fsync/rename.
- `check_docs_links.py PATH [PATH ...]` validates local relative links, case-exact targets, fragments and duplicate headings. HTTP(S) links are syntax/allowlist checked but never fetched in ordinary CI; an explicit future network link-health probe must be a separately owner-gated tool and cannot affect this command's deterministic result.
- `check_workflow_pins.py PATH` inventories both `*.yml` and `*.yaml`, expands bounded literal matrices/reusable-workflow references, permits repository-local actions, and otherwise requires an exact 40-lowercase-hex reviewed action commit plus least-privilege permissions. Tags, branches, abbreviated SHAs, unbounded expressions, unresolved local workflows, secret-capable fork paths and truncated YAML block.
- `check_runbooks.py ROOT --required-scenarios CSV` requires one canonical runbook manifest entry per requested scenario, unique IDs, prerequisites, owner/local-presence authority, detection, containment, recovery, verification, disabled exit, evidence schema and last-review date; missing/broken links or a scenario implemented only as prose blocks.
- `run_ui_matrix.py --phase N --languages CSV --themes CSV --widths CSV --zoom PERCENT [--reduced-motion]` accepts only registered languages/themes and bounded numeric values, computes a sorted unique Cartesian matrix capped at 64 cases, and invokes the fixed Playwright project/grep/env argument vector once per case with `shell=False`; any missing case, timeout, axe violation, screenshot overflow or inconsistent feature manifest fails the whole run.
- `check_critical_coverage.py --coverage-json PATH --minimum PERCENT --modules CSV` duplicate-safely parses coverage.py JSON, resolves each requested logical module to its closed path prefixes, requires every module present with measured branches, and fails if any module's branch percentage is below the threshold; absent/line-only/stale-source coverage never rounds up or passes.
- `check_generated_artifacts.py --check` runs the exact fixed `--check` argv for shared OpenAPI/contracts and Phase 1–6 schema generators, then requires a clean diff across their declared generated roots. It uses no shell and fails for a missing generator, duplicate output ownership, generated-root escape, nonzero/timeout/truncated output, output mutation during a check, or any residual diff.

The shared commands retain every Phase 3–5 invocation grammar. Their Phase 6 extensions add the Phase 6 feature IDs, `remote-access` import domain, canonical-absence direct/replay aggregation, Phase 6 browser denial names and remote/interface process classes; legacy invocations and exit semantics are regression-tested byte-for-byte.

**Rollback/disabled exit:** Missing threat scenario, nondeterministic fixture, missing tool inventory, or an assurance-tool error blocks all later acceptance builders; it cannot be marked documentation-only or converted to a warning.

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

@pytest.mark.parametrize(("command", "argv"), [
    (check_public_api.main, ["synthetic-package", "--expected", "api.json"]),
    (check_licenses.main, ["--project", "--check", "--output", "var/notices.txt"]),
    (check_docs_links.main, ["README.md", "docs/guide.md"]),
    (check_workflow_pins.main, [".github/workflows"]),
    (check_runbooks.main, ["ops/runbooks", "--required-scenarios", "lost-device,owner-lockout"]),
    (run_ui_matrix.main, [
        "--phase", "6", "--languages", "en,hi", "--themes", "light,dark",
        "--widths", "320,1440", "--zoom", "200", "--reduced-motion",
    ]),
    (check_critical_coverage.main, [
        "--coverage-json", "coverage.json", "--minimum", "95", "--modules", "auth,remote",
    ]),
    (check_generated_artifacts.main, ["--check"]),
])
def test_every_phase6_assurance_command_has_one_callable_owner(
    assurance_workspace, command, argv,
) -> None:
    assurance_workspace.install_complete_positive_case(command)
    assert command(["--root", str(assurance_workspace.root), *argv]) == 0

@pytest.mark.parametrize("fault", [
    "missing", "symlink", "special", "changed_after_open", "duplicate_key",
    "invalid_utf8", "oversize", "overdepth", "too_many_items", "timeout",
    "truncated_subprocess_output", "unknown_argument",
])
def test_every_assurance_tool_fails_closed_for_incomplete_input(
    phase6_assurance_harness, fault,
) -> None:
    results = phase6_assurance_harness.run_every_command(fault=fault)
    assert results
    assert all(result.exit_code in {1, 2} for result in results)
    assert all(not result.claimed_pass for result in results)

def test_shared_cli_grammar_remains_compatible_with_phase3_through_phase5(
    phase6_assurance_harness,
) -> None:
    for invocation in phase6_assurance_harness.phase3_to_phase5_invocations:
        assert invocation.run().parsed_without_alias_or_semantic_change

def test_license_notice_is_deterministic_and_unknown_spdx_blocks(license_project) -> None:
    first = check_licenses.render_project(license_project.root)
    second = check_licenses.render_project(license_project.root)
    assert first == second
    license_project.add_transitive_dependency(spdx="LicenseRef-Unknown")
    assert check_licenses.main(["--root", str(license_project.root), "--project"]) == 1

def test_generated_checker_runs_exact_closed_generator_set(generated_workspace) -> None:
    assert check_generated_artifacts.GENERATOR_ARGV == (
        ("scripts/generate_schemas.py", "--check"),
        ("scripts/generate_openapi.py", "--check"),
        ("scripts/ui/generate_contracts.py", "--check"),
        ("scripts/phase2/generate_home_schemas.py", "--check"),
        ("scripts/phase3/generate_vision_schemas.py", "--check"),
        ("scripts/phase4/generate_schemas.py", "--check"),
        ("scripts/phase5/generate_schemas.py", "--check"),
        ("scripts/phase6/generate_schemas.py", "--check"),
    )
    generated_workspace.hide_generator("scripts/phase4/generate_schemas.py")
    assert check_generated_artifacts.main([
        "--root", str(generated_workspace.root), "--check",
    ]) == 2

def test_critical_coverage_requires_measured_branches_for_each_named_module(
    coverage_fixture,
) -> None:
    coverage_fixture.remove_branch_measurement("remote")
    assert check_critical_coverage.main([
        "--coverage-json", str(coverage_fixture.path),
        "--minimum", "95", "--modules", "auth,remote",
    ]) == 2

def test_ui_matrix_is_unique_bounded_and_shell_free(ui_matrix_harness) -> None:
    receipt = ui_matrix_harness.run(languages=9, themes=3, widths=3, zooms=1)
    assert receipt.exit_code == 2
    assert receipt.started_processes == ()
    assert ui_matrix_harness.command_uses_shell is False
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/testing/phase6/test_phase6_fakes.py tests/unit/scripts/test_phase6_assurance_tools.py tests/security/phase6/test_assurance_tools_fail_closed.py tests/privacy/phase6/test_synthetic_only.py tests/contract/hardening/test_threat_scenario_registry.py -q`
Expected: FAIL because `tuntun_testing.phase6`, the threat corpus, and the Phase 6 assurance tools do not exist.

- [ ] **Step 3: Implement bounded fakes, exact hostile cases, and fail-closed assurance commands**

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

Implement every assurance command as a thin parser over typed, side-effect-free inspection functions. No command may catch `BaseException`, `KeyboardInterrupt`, `SystemExit`, cancellation, or programmer errors; expected bounded I/O/parse/process failures become an explicit incomplete result and exit `2`. Use this fixed generator inventory—never filesystem auto-discovery or shell text—as the generated-artifact authority:

~~~python
# scripts/check_generated_artifacts.py
GENERATOR_ARGV: Final[tuple[tuple[str, ...], ...]] = (
    ("scripts/generate_schemas.py", "--check"),
    ("scripts/generate_openapi.py", "--check"),
    ("scripts/ui/generate_contracts.py", "--check"),
    ("scripts/phase2/generate_home_schemas.py", "--check"),
    ("scripts/phase3/generate_vision_schemas.py", "--check"),
    ("scripts/phase4/generate_schemas.py", "--check"),
    ("scripts/phase5/generate_schemas.py", "--check"),
    ("scripts/phase6/generate_schemas.py", "--check"),
)

GENERATED_ROOTS: Final[tuple[str, ...]] = (
    "schemas", "packages/ui-contracts", "apps/admin/src/generated",
)


def check_all(root: Path, runner: BoundedRunner) -> AssuranceResult:
    before = freeze_tracked_tree(root, GENERATED_ROOTS)
    findings: list[AssuranceFinding] = []
    for relative_argv in GENERATOR_ARGV:
        script = require_owned_regular_child(root, relative_argv[0], max_bytes=4 * 1024 * 1024)
        completed = runner.run(
            (sys.executable, str(script.path), *relative_argv[1:]),
            cwd=root, timeout_seconds=120, max_output_bytes=4 * 1024 * 1024,
        )
        if completed.returncode != 0:
            findings.append(AssuranceFinding(script.path, "generator-check-failed"))
    after = freeze_tracked_tree(root, GENERATED_ROOTS)
    if before != after:
        findings.append(AssuranceFinding(root, "generated-tree-mutated-by-check"))
    return AssuranceResult("generated-artifacts", complete=True, findings=tuple(findings))
~~~

`config/assurance/license-policy.v1.json` is canonical duplicate-safe JSON with `schema_id: "tuntun.license-policy.v1"`, an exact sorted allowlist of SPDX identifiers/expressions accepted for source and binary redistribution, an exact denylist, `unknown: "deny"`, and no wildcard/regex/category inference. The checker canonicalizes equivalent SPDX syntax but never guesses a missing licence, follows a package homepage, or accepts a package-name exception. A policy change is a reviewed source change that invalidates C0/C1.

`check_public_api` compares sorted canonical records `{module, symbol, kind, signature, reexported_from}` and the wheel's `Requires-Dist`; dunder names, private names and undeclared re-exports are rejected. `check_docs_links` derives GitHub-compatible fragments with an explicit duplicate-heading ordinal and rejects root escapes. `check_workflow_pins` uses a YAML loader with aliases/tags/merge keys disabled before validating the normalized object. `check_runbooks` parses front matter with the same restrictions. `run_ui_matrix` passes only fixed environment keys and a synthetic output directory unique to the case digest. `check_critical_coverage` compares integer covered/total branch counts (`covered * 100 >= minimum * total`) and never floating-point rounded percentages.

Corpora include wrong node/passkey/origin/CSRF/nonce/session generation, route drift, public/lateral listeners, forbidden remote operations, capability/manifest/result injection, plugin exfiltration/resource/crash/late output, malicious signer/workflow/SBOM/tag/update/migration/archive, deletion resurrection, incident-state bypass, maintainer/fork-secret, and content-sentinel cases. Every fixture uses synthetic pseudonyms, private documentation IP ranges, fake certificates, and non-secret signatures.

- [ ] **Step 4: Run green, reproduce the corpus twice, and exercise the owned tool paths**

Run: `uv run python scripts/phase6/build_corpora.py --check-determinism && uv run pytest tests/unit/testing/phase6 tests/unit/scripts/test_phase6_assurance_tools.py tests/security/phase6/test_assurance_tools_fail_closed.py tests/privacy/phase6/test_synthetic_only.py tests/contract/hardening/test_threat_scenario_registry.py -q && uv run python scripts/check_licenses.py --project && uv run python scripts/check_docs_links.py README.md docs/superpowers/specs/2026-08-27-tuntun-phase6-remote-access-product-hardening-design.md && uv run python scripts/check_workflow_pins.py .github/workflows && uv run python scripts/check_generated_artifacts.py --check && uv run ruff check packages/testing/src/tuntun_testing/phase6 scripts/assurance_common.py scripts/check_feature_absence.py scripts/check_import_boundaries.py scripts/check_migration_ownership.py scripts/scan_browser_artifacts.py scripts/scan_network_surface.py scripts/check_public_api.py scripts/check_licenses.py scripts/check_docs_links.py scripts/check_workflow_pins.py scripts/check_runbooks.py scripts/run_ui_matrix.py scripts/check_critical_coverage.py scripts/check_generated_artifacts.py scripts/phase6/build_corpora.py tests/unit/testing/phase6 tests/unit/scripts/test_phase6_assurance_tools.py tests/security/phase6/test_assurance_tools_fail_closed.py tests/privacy/phase6 && uv run mypy packages/testing/src scripts`
Expected: PASS; both corpus builds have the same manifest digest, the registry reports exactly 25 threats, all legacy shared-tool invocations retain their semantics, and each new assurance command passes a complete positive fixture and blocks every incomplete or adversarial fixture.

- [ ] **Step 5: Commit fakes, corpora, and assurance tooling**

~~~bash
git add packages/testing/src/tuntun_testing/phase6 scripts/phase6/build_corpora.py scripts/assurance_common.py scripts/check_feature_absence.py scripts/check_import_boundaries.py scripts/check_migration_ownership.py scripts/scan_browser_artifacts.py scripts/scan_network_surface.py scripts/check_public_api.py scripts/check_licenses.py scripts/check_docs_links.py scripts/check_workflow_pins.py scripts/check_runbooks.py scripts/run_ui_matrix.py scripts/check_critical_coverage.py scripts/check_generated_artifacts.py config/assurance/license-policy.v1.json fixtures/synthetic/phase6 fixtures/adversarial/phase6 tests/unit/testing/phase6 tests/unit/scripts/test_phase6_assurance_tools.py tests/security/phase6/test_assurance_tools_fail_closed.py tests/privacy/phase6/test_synthetic_only.py tests/contract/hardening/test_threat_scenario_registry.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(hardening): add Phase 6 adversarial and assurance harness"
~~~

### Task 03: Persist remote, plugin, release, recovery, incident, retirement, and maintenance state

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

**Interfaces:** Produces transactional repositories for node/route/session, plugin installation/grant/receipt, release/update, backup/restore/deletion reconciliation, incident, retirement, exact Phase 4 maintenance-source claim, maintenance month, and expansion freeze. Recovery/containment persistence includes durable independent-copy operations, pre-decrypt restore journals, containment effect runs/admission barriers, and retirement effect checkpoints. A unique source-record claim and its aggregate contribution share the serialized transaction, so concurrent retries can return the exact existing contribution but cannot count it twice. All writes consume the shared serialized unit of work and audit/outbox.

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

async def test_phase4_maintenance_source_claim_is_unique_and_atomic(repositories, phase4_contribution) -> None:
    first, retry = await asyncio.gather(
        repositories.maintenance.ingest_phase4(phase4_contribution),
        repositories.maintenance.ingest_phase4(phase4_contribution),
    )
    assert first.contribution_commitment == retry.contribution_commitment
    assert await repositories.maintenance.source_claim_count(phase4_contribution.source_record_id) == 1
    assert await repositories.maintenance.aggregate_contribution_count(phase4_contribution.source_record_id) == 1

def test_recovery_and_containment_operation_tables_are_migrated(inspector) -> None:
    assert {
        "independent_copy_operations", "restore_journals", "containment_effect_runs",
        "containment_admission_barriers", "retirement_effect_runs",
    } <= set(inspector.get_table_names())

def test_operation_journals_store_only_safe_commitments(inspector) -> None:
    columns = all_column_names(
        inspector,
        "independent_copy_operations", "restore_journals",
        "containment_effect_runs", "retirement_effect_runs",
    )
    assert columns.isdisjoint({
        "archive_plaintext", "recovery_key", "raw_target_path", "raw_destination_path",
        "incident_payload", "owner_export_body", "device_secret", "provider_credential",
    })

async def test_backup_record_and_copy_operation_completion_are_atomic(repositories, pending_copy) -> None:
    with pytest.raises(InjectedFault):
        await repositories.faults.raise_after_backup_record_before_operation_completion(pending_copy)
    assert await repositories.backup_sets.for_operation(pending_copy.operation_id) is None
    assert (await repositories.independent_copy_operations.get(pending_copy.operation_id)).state == "pending"
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

Add database constraints for exact states/generations/expiry, partial unique active route, one current registry revision, immutable release candidate digests, incident transitions, deletion-generation monotonicity, a unique Phase 4 maintenance `source_record_id` bound to its source/contribution commitments, and monthly arithmetic. Migration `0025` also owns unique active independent-copy operations, hash-linked restore journals, unique active containment effect runs with fail-closed admission barriers, and retirement runs with one idempotent checkpoint per exact external effect. Backup-record/copy-operation completion and containment-final-state/effect-run completion are each one serialized transaction. The unique maintenance claim and aggregate contribution are one transaction; exact retry returns the prior contribution, while same-ID/different-commitment substitution rolls back. Add retention jobs for 180-day remote/plugin receipts and 30-day counters, preserving incident-bound counters only by explicit incident reference; nonterminal recovery, containment and retirement records are never age-pruned.

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
- Modify: `apps/core/src/tuntun_core/services/privacy/supervisor.py`
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

Run: `uv run pytest tests/policy/test_phase6_amendments.py tests/security/phase6/test_phase6_feature_absence.py tests/privacy/phase6/test_p6_privacy_effect.py -q && pnpm --filter @tuntun/admin test -- feature-registry.phase6.test.ts`
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

Run: `uv run pytest tests/policy/test_phase6_amendments.py tests/security/phase6/test_phase6_feature_absence.py tests/privacy/phase6/test_p6_privacy_effect.py -q && uv run python scripts/check_feature_absence.py --manifest fixtures/synthetic/features/phase6-default-absent-v1.json --features remote_access,remote_scoped_actions,remote_camera_metadata,remote_camera_playback,third_party_plugins,signed_updates,public_release && pnpm --filter @tuntun/admin test -- feature-registry.phase6.test.ts && uv run ruff check packages/policy apps/core/src/tuntun_core/services/privacy/supervisor.py apps/core/src/tuntun_core/services/hardening/privacy_effects.py tests/policy tests/security/phase6 tests/privacy/phase6 && uv run mypy packages/policy/src apps/core/src`
Expected: PASS; absence checker reports no Phase 6 route/bundle/registration, and privacy authority revokes before stop requests.

- [ ] **Step 5: Commit shared amendments and absence evidence**

~~~bash
git add packages/policy/src/tuntun_policy/registry.py packages/contracts/src/tuntun_contracts/ui.py apps/core/src/tuntun_core/services/features/registry.py apps/core/src/tuntun_core/services/privacy/supervisor.py apps/core/src/tuntun_core/services/hardening/privacy_effects.py apps/admin/src/app/feature-registry.ts fixtures/synthetic/features/phase6-default-absent-v1.json tests/policy/test_phase6_amendments.py tests/security/phase6/test_phase6_feature_absence.py tests/privacy/phase6/test_p6_privacy_effect.py apps/admin/src/app/feature-registry.phase6.test.ts schemas packages/ui-contracts
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
- Create: `docs/procurement/phase6-clean-mac-access.md`
- Modify: `docs/privacy/data-flow-inventory.md` (extend the Phase 1 foundation inventory; never replace its earlier rows)
- Create: `docs/privacy/phase6-remote-plugin-privacy.md`
- Create: `docs/evidence/phase6-evidence-schema.json`
- Create: `fixtures/synthetic/phase6/threat-control-map-v1.json`
- Test: `tests/contract/hardening/test_phase6_evidence_schema.py`
- Test: `tests/acceptance/phase6/test_system_inventory.py`
- Test: `tests/acceptance/phase6/test_t01_t25_control_map.py`
- Test: `tests/privacy/phase6/test_assurance_artifacts_safe.py`

**Interfaces:** Produces the P6-0 asset/service/process/account/key/store/listener/route/data-flow inventory, A–H completion links, I–S assurance map, ranked risks, decisions, exact T01–T25 control/test/evidence ownership, and a signed content-safe P6-0 receipt. It also produces the unapproved clean-Mac access template: exact supported Intel/current-Apple-Silicon targets and OS versions, borrow/rent/physical-lab/purchase route, owner/control/isolation/wipe/restore terms, access window, quote source/date/landed cost, explicit spend cap, and owner decision. The template states that this plan authorizes neither a purchase nor a booking, the always-home production Core Mac cannot serve as a destructive clean-install/restore target, hosted Macs are synthetic-package-only, and real private restore data may run only on an isolated owner-controlled Mac. It consumes digests and safe facts, never raw prior evidence.

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

def test_clean_mac_access_template_cannot_authorize_spend_or_real_hosted_restore(
    clean_mac_access_template,
) -> None:
    assert clean_mac_access_template.status == "unapproved"
    assert clean_mac_access_template.automatic_spend_authority is False
    assert clean_mac_access_template.live_home_mac_destructive_use_allowed is False
    assert clean_mac_access_template.hosted_real_private_restore_allowed is False
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

Run: `uv run python scripts/phase6/inventory_system.py --synthetic --output var/evidence/phase6/p6-0-synthetic.json && uv run pytest tests/contract/hardening/test_phase6_evidence_schema.py tests/acceptance/phase6/test_system_inventory.py tests/acceptance/phase6/test_t01_t25_control_map.py tests/privacy/phase6/test_assurance_artifacts_safe.py -q && uv run python scripts/scan_private_data.py --paths docs/architecture docs/security docs/privacy docs/procurement/phase6-clean-mac-access.md fixtures/synthetic/phase6 var/evidence/phase6/p6-0-synthetic.json && uv run ruff check scripts/phase6/inventory_system.py tests/acceptance/phase6 tests/privacy/phase6`
Expected: PASS; receipt reports 25 mapped threats, A–S coverage, zero unsafe findings, zero open high/critical risk, and an explicitly unapproved clean-Mac access template with no implicit spend or hosted-private-restore authority.

- [ ] **Step 5: Commit the baseline artifacts**

~~~bash
git add scripts/phase6/inventory_system.py docs/architecture/system-inventory.md docs/security/threat-model.md docs/security/risk-register.md docs/procurement/phase6-clean-mac-access.md docs/privacy/data-flow-inventory.md docs/privacy/phase6-remote-plugin-privacy.md docs/evidence/phase6-evidence-schema.json fixtures/synthetic/phase6/threat-control-map-v1.json tests/contract/hardening/test_phase6_evidence_schema.py tests/acceptance/phase6/test_system_inventory.py tests/acceptance/phase6/test_t01_t25_control_map.py tests/privacy/phase6/test_assurance_artifacts_safe.py
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

Prerequisites verify the active Darwin `arm64` Core Mac, mandatory Intel macOS distribution support, FileVault, disk reserve, time, owner account, no public mapping, and exact two-router topology evidence. Install purpose-separated Keychain/data paths and existing accepted services only. Scanners inspect Python/TypeScript registrations, package metadata, launchd, socket tables, route tables, firewall, UPnP/NAT-PMP/PCP receipts, binaries/strings, config schemas, API/OpenAPI, browser chunks, and simulator manifests.

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
- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Create: `integrations/remote-access/pyproject.toml`
- Create: `integrations/remote-access/src/tuntun_remote_access/__init__.py`
- Create: `integrations/remote-access/src/tuntun_remote_access/tailscale.py`
- Create: `integrations/remote-access/src/tuntun_remote_access/client_state.py`
- Create: `integrations/remote-access/src/tuntun_remote_access/posture.py`
- Create: `integrations/remote-access/src/tuntun_remote_access/sanitized_errors.py`
- Create: `fixtures/provider/tailscale/pinned-macos-cli-v1/README.md`
- Create: `fixtures/provider/tailscale/pinned-macos-cli-v1/*.json`
- Test: `integrations/remote-access/tests/unit/test_tailscale_state.py`
- Test: `integrations/remote-access/tests/contract/test_remote_access_port.py`
- Test: `tests/security/phase6/test_tailscale_is_sole_adapter.py`
- Test: `tests/privacy/phase6/test_remote_adapter_minimization.py`
- Modify: `tests/unit/test_package_smoke.py`

**Interfaces:** Implements provider-neutral `RemoteAccessPort.probe() -> RemoteAdapterProbeResultV1`, `close_route(reason) -> RemoteRouteReceiptV1`, and `revoke_node(local_pseudonym) -> NodeRevocationReceiptV1` with the official local Tailscale client. A successful probe returns `RemoteAdapterPostureV1`; a missing, unreadable, timed-out, malformed, structurally excessive or schema-invalid client response returns the short-lived content-minimized `RemoteAdapterUnavailableV1`. Core sees random HMAC-derived local pseudonyms only on a successful posture result.

**Rollback/disabled exit:** Missing/unknown/stale/malformed client state yields `not_configured` or `unavailable`; adapter remains unregistered and no second provider is attempted.

- [ ] **Step 1: Write red conformance, sole-adapter, and minimization tests**

~~~python
async def test_tailscale_adapter_conforms_without_exporting_vendor_identity(fake_tailscale) -> None:
    posture = await TailscaleRemoteAccessAdapter(fake_tailscale).probe()
    assert posture.state == "available"
    assert posture.adapter_class == "tailscale"
    assert posture.node_pseudonym.startswith("rnode_")
    assert not hasattr(posture, "node_name")
    assert not hasattr(posture, "user_email")
    assert not hasattr(posture, "ip_address")

def test_release_has_exactly_one_remote_adapter(adapter_registry) -> None:
    assert adapter_registry.implementation_ids("RemoteAccessPort") == ("tailscale.v1",)

@pytest.mark.parametrize("fault", [
    "not_installed", "timeout", "invalid_utf8", "duplicate_key", "nonfinite_number",
    "decimal_over_64_digits", "depth_33", "container_4097", "structure_token_16385",
    "oversize_status_output", "oversize_lock_output", "oversize_preferences_output",
    "oversize_serve_output", "oversize_funnel_output", "wrong_root",
    "missing_required_projection_field", "lock_snapshot_changes_during_probe",
    "commissioning_receipt_changes_during_probe", "current_node_key_mismatch",
    "unsigned_current_node", "approved_node_set_mismatch", "signer_set_mismatch",
    "recovery_configuration_mismatch", "lock_head_mismatch", "lock_state_id_mismatch",
    "filtered_peer_present", "preferences_enable_route", "serve_present", "funnel_present",
    "generation_mismatch", "client_version_mismatch",
])
async def test_tailscale_probe_fails_closed_without_identity_or_fallback(
    fake_tailscale, adapter_registry, fault,
) -> None:
    result = await TailscaleRemoteAccessAdapter(fake_tailscale.with_fault(fault)).probe()
    assert result.state in {"not_configured", "unavailable"}
    assert result.valid_until - result.observed_at <= timedelta(seconds=5)
    assert not hasattr(result, "node_pseudonym")
    assert adapter_registry.provider_attempts == ("tailscale.v1",)

async def test_each_probe_gets_a_durable_monotonic_generation(harness) -> None:
    first = await harness.adapter.probe()
    restarted = await harness.restart_adapter()
    second = await restarted.probe()
    assert second.probe_generation > first.probe_generation

async def test_late_healthy_probe_cannot_overwrite_newer_failure(harness) -> None:
    old_healthy = await harness.adapter.probe()
    restarted = await harness.restart_adapter()
    newer_failure = await restarted.probe_with_forced_failure()
    assert newer_failure.state == "unavailable"
    await harness.route_controller.apply_probe(newer_failure)
    assert not await harness.route_controller.apply_probe(old_healthy)
    assert harness.route_controller.current.state == "suspended"
    assert harness.route_controller.current_probe_generation == newer_failure.probe_generation

async def test_same_generation_replay_is_ignored(harness) -> None:
    result = await harness.adapter.probe()
    assert await harness.route_controller.apply_probe(result)
    assert not await harness.route_controller.apply_probe(result)

async def test_generation_store_failure_suspends_without_fabricating_result(harness) -> None:
    harness.probe_generation_store.fail_next_write()
    with pytest.raises(ProbeGenerationUnavailable):
        await harness.adapter.probe()
    assert harness.route_controller.current.state == "suspended"
    assert harness.route_controller.accepting_requests is False

async def test_one_snapshot_command_failure_reaps_all_sibling_processes(harness) -> None:
    harness.client.fail_one_command_and_hang_the_other_four()
    result = await harness.adapter.probe()
    assert result.state == "unavailable"
    assert harness.client.live_subprocesses == ()
    assert harness.client.open_stdout_readers == ()
    assert harness.route_controller.late_mutations == ()

async def test_simultaneous_expected_command_failures_collapse_without_exception_group(harness) -> None:
    harness.client.fail_commands_simultaneously(
        TailscaleClientNotInstalled(), TailscaleSnapshotReadError(),
    )
    result = await harness.adapter.probe()
    assert result.state == "unavailable"
    assert result.reason_code == "remote_client_state_unavailable"
    assert harness.client.live_subprocesses == ()

async def test_unexpected_projector_programmer_fault_is_visible(harness) -> None:
    harness.projector.raise_unexpected(RuntimeError("programmer fault"))
    with pytest.raises(RuntimeError, match="programmer fault"):
        await harness.adapter.probe()

def test_projector_matches_sanitized_real_macos_golden_outputs(provider_fixture) -> None:
    assert provider_fixture.client_version == PINNED_TAILSCALE_CLIENT_VERSION
    snapshot = project_official_tailscale_snapshot(*provider_fixture.raw_command_outputs)
    assert snapshot.lock.schema_version == "1"
    assert snapshot.lock.current_node_signed is True
    assert snapshot.lock.current_node_signature_present is True
    assert snapshot.lock.filtered_peer_node_keys == ()
    assert snapshot.preferences == expected_closed_preferences()
    assert snapshot.serve_configuration_present is False
    assert snapshot.funnel_configuration_present is False

def test_tailnet_lock_head_uses_the_real_aum_base32_wire_format(provider_fixture) -> None:
    snapshot = project_official_tailscale_snapshot(*provider_fixture.raw_command_outputs)
    assert re.fullmatch(r"[A-Z2-7]{52}", snapshot.lock.head)
    with pytest.raises((ContractParseError, TailscaleStateProjectionError)):
        project_official_tailscale_snapshot(
            *provider_fixture.with_lock_head("a" * 64).raw_command_outputs,
        )

@pytest.mark.real_provider
async def test_pinned_client_live_outputs_match_golden_schema(real_macos_tailscale) -> None:
    captured = await real_macos_tailscale.capture_all_bounded_machine_outputs()
    assert captured.client_binary_digest == PINNED_TAILSCALE_BINARY_DIGEST
    assert project_official_tailscale_snapshot(*captured.outputs)
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest integrations/remote-access/tests tests/security/phase6/test_tailscale_is_sole_adapter.py tests/privacy/phase6/test_remote_adapter_minimization.py -q`
Expected: FAIL because the integration package and adapter registration are absent.

- [ ] **Step 3: Implement strict local-client parsing and safe posture projection**

Register `integrations/remote-access` in the root `[tool.uv.workspace].members` list, update `uv.lock`, add `tuntun_remote_access` to the shared package-smoke parametrization, and create this independently importable adapter package before its first root-level test:

~~~toml
# integrations/remote-access/pyproject.toml
[project]
name = "tuntun-remote-access"
version = "0.1.0.dev0"
requires-python = "==3.12.*"
dependencies = ["tuntun-contracts"]

[tool.uv.sources]
tuntun-contracts = { workspace = true }

[build-system]
requires = ["hatchling>=1.27,<2"]
build-backend = "hatchling.build"
~~~

The package `__init__.py` defines `__version__ = "0.1.0.dev0"`. Workspace smoke and import-boundary tests prove the adapter resolves from the lock and imports contracts only, never `tuntun_core`, household stores, or another provider package.

~~~python
import asyncio
import hmac

from tuntun_contracts.base import ContractParseError, parse_bounded_json_value

class TailscaleExpectedBoundaryError(Exception): ...
class TailscaleClientNotInstalled(TailscaleExpectedBoundaryError): ...
class TailscaleSnapshotReadError(TailscaleExpectedBoundaryError): ...
class TailscaleStateProjectionError(TailscaleExpectedBoundaryError): ...
class CommissioningReceiptInvalid(TailscaleExpectedBoundaryError): ...
class ProbeGenerationUnavailable(TailscaleExpectedBoundaryError): ...

def iter_exception_leaves(group: BaseExceptionGroup):
    for error in group.exceptions:
        if isinstance(error, BaseExceptionGroup):
            yield from iter_exception_leaves(error)
        else:
            yield error

class TailscaleRemoteAccessAdapter(RemoteAccessPort):
    async def probe(self) -> RemoteAdapterProbeResultV1:
        # The process-shared lock makes allocation and all authoritative reads a
        # single flight. The durable allocator commits before any provider I/O.
        probe_generation: int | None = None
        try:
            async with asyncio.timeout(5):
                async with self._probe_lock:
                    probe_generation = await self._probe_generations.allocate_and_commit_next()
                    commissioned_before = await self._commissioning.require_current()
                    provider_before = await self._read_provider_snapshot()
                    provider_after = await self._read_provider_snapshot()
                    commissioned_after = await self._commissioning.require_current()
                    self._require_stable_exact_authority(
                        commissioned_before, commissioned_after, provider_before, provider_after,
                    )
        except TailscaleClientNotInstalled as error:
            if probe_generation is None:
                await self._suspend_without_generation(error)
            return self._unavailable(
                probe_generation, "not_configured", "remote_client_not_installed",
            )
        except (TailscaleSnapshotReadError, TimeoutError, OSError) as error:
            if probe_generation is None:
                await self._suspend_without_generation(error)
            return self._unavailable(
                probe_generation, "unavailable", "remote_client_state_unavailable",
            )
        except (ContractParseError, TailscaleStateProjectionError, CommissioningReceiptInvalid) as error:
            if probe_generation is None:
                await self._suspend_without_generation(error)
            return self._unavailable(
                probe_generation, "unavailable", "remote_client_state_invalid",
            )

        assert probe_generation is not None  # proven by the success path; not an input check
        observed_at = self._clock.now()  # sample after every authoritative read
        return RemoteAdapterPostureV1(
                state="available",
                probe_generation=probe_generation,
                adapter_id=self._adapter_id,
                adapter_class="tailscale",
                node_pseudonym=commissioned_after.node_pseudonym,
                tailnet_lock_state="enabled",
                admission_authority_mode="tailnet_lock_only",
                current_signed_node_state="signed",
                tailnet_lock_generation=commissioned_after.tailnet_lock_generation,
                signed_node_set_generation=commissioned_after.signed_node_set_generation,
                approved_node_set_commitment=commissioned_after.approved_node_set_commitment,
                independent_signing_node_commitments=commissioned_after.independent_signing_node_commitments,
                recovery_configuration_commitment=commissioned_after.recovery_configuration_commitment,
                route_flags=("none",),
                client_version_commitment=commissioned_after.client_version_commitment,
                observed_at=observed_at,
                valid_until=observed_at + timedelta(seconds=30),
        )

    async def _read_provider_snapshot(self) -> TailscaleProviderSnapshotV1:
        # These are the official stable/ documented machine-readable surfaces.
        # Commands run without a shell and each reader stores at most max+1 bytes.
        try:
            async with asyncio.TaskGroup() as commands:
                status_task = commands.create_task(self._run_provider_command(
                    self._client.status_json(timeout=timedelta(seconds=2), max_bytes=256 * 1024),
                ))
                lock_task = commands.create_task(self._run_provider_command(
                    self._client.lock_status_json(timeout=timedelta(seconds=2), max_bytes=256 * 1024),
                ))
                preferences_task = commands.create_task(self._run_provider_command(
                    self._client.get_all_json(timeout=timedelta(seconds=2), max_bytes=256 * 1024),
                ))
                serve_task = commands.create_task(self._run_provider_command(
                    self._client.serve_status_json(timeout=timedelta(seconds=2), max_bytes=64 * 1024),
                ))
                funnel_task = commands.create_task(self._run_provider_command(
                    self._client.funnel_status_json(timeout=timedelta(seconds=2), max_bytes=64 * 1024),
                ))
        except BaseExceptionGroup as errors:
            leaves = tuple(iter_exception_leaves(errors))
            if any(
                not isinstance(error, (TailscaleClientNotInstalled, TailscaleSnapshotReadError))
                for error in leaves
            ):
                raise  # cancellation and programmer faults remain visible
            if all(isinstance(error, TailscaleClientNotInstalled) for error in leaves):
                raise TailscaleClientNotInstalled from errors
            raise TailscaleSnapshotReadError from errors
        status_raw, lock_raw, preferences_raw, serve_raw, funnel_raw = (
            status_task.result(), lock_task.result(), preferences_task.result(),
            serve_task.result(), funnel_task.result(),
        )
        values = tuple(
            parse_bounded_json_value(
                raw, max_bytes=ceiling, max_depth=32,
                max_containers=4096, max_structure_tokens=16384,
            )
            for raw, ceiling in (
                (status_raw, 256 * 1024), (lock_raw, 256 * 1024),
                (preferences_raw, 256 * 1024), (serve_raw, 64 * 1024),
                (funnel_raw, 64 * 1024),
            )
        )
        # The projector accepts only pinned real-client v1 golden shapes and maps
        # the external CamelCase fields to the minimized contracts above. It
        # deliberately drops DNS names, addresses, users and metadata.
        return project_official_tailscale_snapshot(*values)

    async def _run_provider_command(self, command: Awaitable[bytes]) -> bytes:
        try:
            return await command
        except TailscaleClientNotInstalled:
            raise
        except (TimeoutError, OSError) as error:
            raise TailscaleSnapshotReadError from error

    def _require_stable_exact_authority(self, before, after, provider_before, provider_after) -> None:
        if before.receipt_commitment != after.receipt_commitment:
            raise TailscaleStateProjectionError("commissioning_changed_during_probe")
        if canonical_hardening_bytes(provider_before) != canonical_hardening_bytes(provider_after):
            raise TailscaleStateProjectionError("provider_snapshot_changed_during_probe")
        status = provider_after.client
        lock = provider_after.lock
        current_signed_node_keys = tuple(sorted({
            lock.current_node_public_key, *lock.visible_signed_peer_node_keys,
        }))
        trusted_signer_commitments = tuple(
            hmac_commit(key.public_key)
            for key in sorted(lock.trusted_signing_keys, key=lambda item: item.public_key)
        )
        if (
            status.backend_state != "running"
            or not status.self_node.online
            or status.self_node.public_key != lock.current_node_public_key
            or lock.filtered_peer_node_keys
            or lock.head != after.tailnet_lock_aum_head
            or lock.state_id != after.tailnet_lock_state_id
            or not hmac.compare_digest(hmac_commit(status.client_version), after.client_version_commitment)
            or not hmac.compare_digest(
                commit_node_key_set(current_signed_node_keys),
                after.approved_node_set_commitment,
            )
            or trusted_signer_commitments != after.independent_signing_node_commitments
            or self._pseudonyms.for_node_key(status.self_node.public_key) != after.node_pseudonym
        ):
            raise TailscaleStateProjectionError("current_authority_mismatch")

    def _unavailable(self, generation, state, reason) -> RemoteAdapterUnavailableV1:
        observed_at = self._clock.now()
        return RemoteAdapterUnavailableV1(
            state=state,
            probe_generation=generation,
            adapter_id=self._adapter_id,
            adapter_class="tailscale",
            reason_code=reason,
            observed_at=observed_at,
            valid_until=observed_at + timedelta(seconds=5),
        )

    async def _suspend_without_generation(self, error: BaseException) -> NoReturn:
        # A result generation must never be guessed if its durable allocation did
        # not commit. This independent fail-closed lane accepts no traffic.
        await complete_owned_suspension_despite_caller_cancellation(
            self._emergency_suspension.close_route_and_revoke_sessions(
                "remote_probe_authority_unavailable",
            ),
        )
        raise ProbeGenerationUnavailable from error
~~~

Invoke the official client without a shell, fixed absolute executable digest, bounded max-plus-one stdout readers, empty nonessential environment, timeout, and sanitized errors. Each probe compares two complete projected bundles of `status --json`, stable `lock status --json` v1, `get --json all`, `serve status --json`, and `funnel status --json`; each command has a two-second ceiling and both bundles plus commissioning reads share one five-second deadline. An officially documented no-configuration response projects to false; a missing/unsupported command never does. The adapter models the real 52-character unpadded RFC 4648 base32 BLAKE2s AUM `Head`, integer `State`, `nodekey:` and `tlpub:` values and does not invent provider generations or mislabel the AUM head as SHA-256. Tuntun's two generations are allocated locally at commissioning and remain usable only while the current Head/State, signed-node set, trusted signing-key set and closed preference/exposure bundle exactly reproduce that receipt. Recovery-secret KDF evidence is collected locally at commissioning and may be reused only while that exact Head/State authority epoch is unchanged. The allow-list projector normalizes only hostile/provider-shape failures to `TailscaleStateProjectionError`; malformed identity-bearing fields are discarded, not logged. The commissioning store re-verifies the current signed receipt, its revocation generation, and all evidence commitments on both reads. Never catch cancellation or programmer errors. The route controller applies a probe only with an atomic compare-and-swap requiring `probe_generation` greater than its durable last-applied generation; every failure immediately suspends/closes before another request, and a delayed older success or same-generation replay is ignored. It never retains prior healthy posture or tries a second provider. Task 07 cannot turn green, register the adapter, or enable a listener until sanitized golden outputs captured from the pinned official client on the active approved Core Mac and a fresh live capture both pass the same projector. A later move to Intel requires a new Intel live capture before household remote access can run there. The adapter has no SQLCipher/Keychain/provider/camera/HA credential.

- [ ] **Step 4: Run green, import-boundary, and forbidden-adapter scans**

Run: `uv lock && uv sync --all-packages && uv run pytest tests/unit/test_package_smoke.py integrations/remote-access/tests tests/security/phase6/test_tailscale_is_sole_adapter.py tests/privacy/phase6/test_remote_adapter_minimization.py -q && TUNTUN_ALLOW_REAL_TAILSCALE_PROBE=1 uv run pytest integrations/remote-access/tests/acceptance/test_pinned_macos_client.py -m real_provider -q && uv run python scripts/check_import_boundaries.py --domain remote-access && uv run python scripts/phase6/verify_default_absence.py --allow-source-adapter tailscale.v1 && uv run ruff check integrations/remote-access tests/unit/test_package_smoke.py tests/security/phase6 tests/privacy/phase6 && uv run mypy integrations/remote-access/src`
Expected: PASS on the target Mac and pinned official client; recorded and fresh live shapes match, registry reports only `tailscale.v1`, and no provider identity/address reaches core DTOs/logs. Synthetic success alone cannot satisfy this gate.

- [ ] **Step 5: Commit the adapter**

~~~bash
git add pyproject.toml uv.lock integrations/remote-access tests/unit/test_package_smoke.py tests/security/phase6/test_tailscale_is_sole_adapter.py tests/privacy/phase6/test_remote_adapter_minimization.py
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
- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Create: `apps/network-boundary/pyproject.toml`
- Create: `apps/network-boundary/src/tuntun_network_boundary/__init__.py`
- Create: `apps/network-boundary/src/tuntun_network_boundary/main.py`
- Create: `apps/network-boundary/src/tuntun_network_boundary/exposure_probe.py`
- Create: `apps/network-boundary/src/tuntun_network_boundary/authoritative_resolver.py`
- Create: `packages/contracts/src/tuntun_contracts/hardening/exposure.py`
- Create: `apps/core/src/tuntun_core/services/hardening/exposure_guard.py`
- Create: `apps/core/src/tuntun_core/services/hardening/exposure_probe_ingress.py`
- Create: `ops/network/verify_lateral_reachability.py`
- Create: `ops/network/verify_external_exposure.py`
- Create: `ops/launchd/com.tuntun.exposure-guard.plist`
- Create: `ops/launchd/com.tuntun.authoritative-resolver.plist`
- Create: `ops/services/phase6-network-boundary.v1.json`
- Modify: `ops/network/exposure-manifest.v1.yaml`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/listeners.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Test: `apps/core/tests/unit/hardening/test_exposure_guard.py`
- Test: `tests/security/phase6/test_interface_bind_policy.py`
- Test: `tests/fault/phase6/test_exposure_drift_suspends.py`
- Test: `tests/integration/phase6/test_local_independence_on_remote_close.py`
- Test: `tests/integration/phase6/test_owner_ingress_listener_extension.py`
- Modify: `tests/integration/deploy/test_owner_ingress_route_manifest.py`
- Test: `tests/security/phase6/test_core_media_have_no_listener.py`
- Test: `tests/unit/phase6/test_network_boundary_package_smoke.py`
- Test: `tests/contract/phase6/test_exposure_probe_ipc.py`
- Test: `tests/security/phase6/test_exposure_probe_ipc.py`
- Test: `tests/security/phase6/test_authoritative_resolver_wire.py`
- Test: `tests/integration/phase6/test_network_boundary_service_lifecycle.py`
- Create: `fixtures/adversarial/phase6/dns-wire-corpus/README.md`
- Create: `fixtures/adversarial/phase6/dns-wire-corpus/*.bin`

**Interfaces:** Produces `ExposureGuard.evaluate(posture, listeners, routes, firewall) -> ExposureDecision` and atomic `suspend_route_and_revoke_sessions`. The independently packaged `tuntun-network-boundary` exposes frozen commands `tuntun-exposure-guard = tuntun_network_boundary.main:exposure_guard_app` and `tuntun-authoritative-resolver = tuntun_network_boundary.main:resolver_app`; it depends only on `tuntun-contracts` and talks to Core only through `/private/var/run/tuntun/exposure-guard.sock`. Core owns that Unix socket and the closed `ExposureProbeChallengeV1` → `ExposureSnapshotV1` → `ExposureProbeReceiptV1` protocol; both peers verify Darwin credentials and the owner/mode/no-follow identity of every socket ancestor, and each direction uses one 64-KiB max-plus-one, one-second length-prefixed frame with no ancillary descriptors. Core allocates a durable one-use generation/nonce challenge valid for at most five seconds, binds it to the current route and commissioning generations, and rejects stale, duplicate, cross-route, wrong-peer or late snapshots before evaluation. It extends the accepted Phase 3 owner-ingress listener/context registry with class `owner_vpn_https` on only the commissioned Tailnet IPv4 address:8443 while preserving its loopback and commissioned-LAN classes; it creates no second FastAPI/Uvicorn/server composition. The authoritative resolver is a separate least-privilege `launchd` socket-activated parser on only the commissioned LAN/Tailnet IPv4 addresses TCP/UDP 53. Core and media proxy own no TCP listener and media remains reachable only through the existing owner-ingress capability path.

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
    assert network_rig.remote_reachable == {
        "https://tuntun.home.arpa:8443", "dns://tuntun.home.arpa:53/tcp", "dns://tuntun.home.arpa:53/udp",
    }

def test_phase6_extends_one_owner_ingress_and_core_media_own_no_listener(process_inventory) -> None:
    assert process_inventory.owner_ingress.listener_classes == {
        "loopback_http", "commissioned_lan_https", "owner_vpn_https",
    }
    assert process_inventory.core.tcp_listeners == ()
    assert process_inventory.media_proxy.tcp_listeners == ()

def test_signed_route_manifest_extends_canonical_listener_classes_without_parallel_manifest(
    route_manifest,
) -> None:
    assert route_manifest.manifest_id == "owner_ingress_routes.v1"
    assert route_manifest.listener_classes == {
        "loopback_http", "commissioned_lan_https", "owner_vpn_https",
    }
    assert route_manifest.parallel_phase6_route_manifests == ()

def test_phase4_route_manifest_cannot_enable_phase6_listener(old_phase4_route_manifest) -> None:
    with pytest.raises(RouteManifestMismatch, match="listener_class_set_mismatch"):
        boot_owner_ingress_candidate(
            route_manifest=old_phase4_route_manifest,
            enabled_listener_classes={
                "loopback_http", "commissioned_lan_https", "owner_vpn_https",
            },
        )

@pytest.mark.parametrize("fault", [
    "missing_owner_vpn_8443", "missing_lan_dns_tcp", "missing_lan_dns_udp",
    "missing_tailnet_dns_tcp", "missing_tailnet_dns_udp", "wrong_listener_process",
    "duplicate_required_listener",
])
def test_exposure_guard_requires_each_exact_listener_once_from_its_owner(
    guard, healthy_posture, fault,
) -> None:
    snapshot = healthy_posture.with_listener_fault(fault)
    assert guard.evaluate(snapshot).decision == "suspend"

async def test_newer_failure_wins_over_delayed_healthy_result(
    route_controller, result_factory, snapshot_factory,
) -> None:
    healthy = result_factory.available(probe_generation=41)
    failed = result_factory.unavailable(probe_generation=42)
    assert await route_controller.apply_probe(failed, None)
    assert not await route_controller.apply_probe(healthy, snapshot_factory.verified_for(healthy))
    assert route_controller.current.state == "suspended"

async def test_probe_generation_cas_is_durable_across_restart(
    route_controller, result_factory, snapshot_factory,
) -> None:
    healthy = result_factory.available(probe_generation=51)
    assert await route_controller.apply_probe(healthy, snapshot_factory.verified_for(healthy))
    restarted = await route_controller.restart()
    assert not await restarted.apply_probe(result_factory.unavailable(probe_generation=51), None)
    assert await restarted.apply_probe(result_factory.unavailable(probe_generation=52), None)

@pytest.mark.parametrize(("view", "transport"), [
    ("lan", "udp"), ("lan", "tcp"), ("tailnet", "udp"), ("tailnet", "tcp"),
])
def test_resolver_answers_exact_address_for_listener_view_on_both_transports(
    resolver, view, transport,
) -> None:
    answer = resolver.exchange(
        valid_dns_query("tuntun.home.arpa", qtype="A"),
        listener=resolver.listener_for_view(view, transport),
        source=resolver.approved_source_for_view(view),
    )
    assert answer.address == resolver.commissioned_address_for_view(view)
    assert answer.authoritative and not answer.recursion_available

@pytest.mark.parametrize("fault", [
    "uncommissioned_listener", "wrong_listener_view", "unapproved_source",
    "cross_view_source", "prior_view_cache_leak",
])
def test_resolver_denies_listener_source_or_view_confusion_without_cache(
    resolver, fault,
) -> None:
    result = resolver.exchange_with_view_fault(
        valid_dns_query("tuntun.home.arpa", qtype="A"), fault,
    )
    assert result.state == "refused_or_dropped"
    assert resolver.cache_entries == ()

@pytest.mark.parametrize("fault", [
    "oversize", "truncated", "two_questions", "compression_loop", "pointer_out_of_bounds",
    "unknown_name", "unknown_type", "recursion_desired", "edns_oversize", "trailing_bytes",
])
def test_resolver_rejects_hostile_wire_without_forwarding_or_logging(resolver, fault) -> None:
    assert resolver.exchange(dns_wire_fault(fault)).state == "refused_or_format_error"
    assert resolver.upstream_calls == 0
    assert resolver.query_name_logs == ()

def test_network_boundary_installed_commands_and_launchd_arguments_are_exact(service_inventory) -> None:
    service_inventory.require_entrypoint("tuntun-exposure-guard")
    service_inventory.require_entrypoint("tuntun-authoritative-resolver")
    assert service_inventory.jobs_run_as == {"_tuntun_netprobe", "_tuntun_dns"}
    assert service_inventory.resolver_socket_activated_tcp_udp_53

@pytest.mark.parametrize("fault", [
    "wrong_client_uid", "wrong_server_uid", "socket_symlink", "socket_parent_replaced",
    "oversize_declaration", "short_frame", "ancillary_fd", "stale_challenge",
    "replayed_challenge", "generation_substitution", "route_substitution",
    "commissioning_substitution", "late_snapshot",
])
async def test_exposure_probe_ipc_fails_closed_before_evaluation(
    exposure_ipc, fault,
) -> None:
    result = await exposure_ipc.exchange_with_fault(fault)
    assert result.code == "exposure_probe_denied"
    assert exposure_ipc.exposure_evaluations == 0
    assert exposure_ipc.route_state == "suspended"

async def test_missed_exposure_probe_deadline_suspends_without_client(core_watchdog) -> None:
    await core_watchdog.advance_past_next_scan_deadline_without_connection()
    assert core_watchdog.route_state == "suspended"
    assert core_watchdog.remote_sessions == ()
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/phase6/test_network_boundary_package_smoke.py tests/contract/phase6/test_exposure_probe_ipc.py tests/security/phase6/test_exposure_probe_ipc.py tests/security/phase6/test_authoritative_resolver_wire.py tests/integration/phase6/test_network_boundary_service_lifecycle.py apps/core/tests/unit/hardening/test_exposure_guard.py tests/security/phase6/test_interface_bind_policy.py tests/fault/phase6/test_exposure_drift_suspends.py tests/integration/phase6/test_local_independence_on_remote_close.py tests/integration/phase6/test_owner_ingress_listener_extension.py tests/security/phase6/test_core_media_have_no_listener.py -q`
Expected: FAIL because exposure evaluation and drift suspension are missing.

- [ ] **Step 3: Implement exact allowlist evaluation and atomic close path**

Append `apps/network-boundary` to the existing root uv workspace and update `uv.lock`. Create a Hatchling project with Python `==3.12.*`, version `0.1.0.dev0`, workspace dependency `tuntun-contracts`, `typer>=0.16,<1`, the two script entries above, and matching package `__version__`. Import-boundary tests reject `tuntun_core`, household stores and provider adapters. Both commands support side-effect-free `--help`; `tuntun-exposure-guard doctor --synthetic --no-network --json` and `tuntun-authoritative-resolver doctor --synthetic --no-bind --json` validate installed configuration without opening a socket. The contracts package owns frozen, `extra="forbid"` challenge/snapshot/receipt DTOs with closed enums and bounded collections. The Core ingress authenticates `_tuntun_netprobe` before reading application bytes, issues the one-use challenge from its durable serialized writer, and validates the returned snapshot against the same route, commissioning, challenge and monotonic deadline before calling `ExposureGuard`. A persisted watchdog deadline is advanced only by a committed healthy evaluation; no connection, peer/frame failure, scanner crash or incomplete exchange reaches the deadline without atomically suspending the route and revoking sessions.

~~~python
async def apply_probe(
    self,
    result: RemoteAdapterProbeResultV1,
    snapshot: VerifiedExposureSnapshot | None,
) -> bool:
    async with self._repository.serialized_writer() as tx:
        last_applied_generation = await tx.last_applied_probe_generation()
        if result.probe_generation <= last_applied_generation:
            return False
        if self._clock.now() >= result.valid_until:
            await tx.suspend_route_revoke_sessions_and_commit_generation(
                result.probe_generation, "remote_posture_stale",
            )
            return True
        if result.state != "available":
            await tx.suspend_route_revoke_sessions_and_commit_generation(
                result.probe_generation, result.reason_code,
            )
            return True
        if snapshot is None or not snapshot.matches_current_result_and_generations(result):
            await tx.suspend_route_revoke_sessions_and_commit_generation(
                result.probe_generation, "exposure_snapshot_unavailable",
            )
            return True
        decision = self.evaluate(snapshot.value)
        if decision.decision != "healthy":
            await tx.suspend_route_revoke_sessions_and_commit_generation(
                result.probe_generation, decision.reason_code,
            )
            return True
        await tx.activate_exact_posture_and_commit_generation(result, decision)
        return True

def evaluate(self, snapshot: ExposureSnapshot) -> ExposureDecision:
    expected = {
        Listener(snapshot.commissioned_tailscale_address, 8443, "owner_vpn_https"),
        Listener(snapshot.commissioned_tailscale_address, 53, "authoritative_dns_tcp"),
        DatagramListener(snapshot.commissioned_tailscale_address, 53, "authoritative_dns_udp"),
        Listener(snapshot.commissioned_lan_address, 53, "authoritative_dns_tcp"),
        DatagramListener(snapshot.commissioned_lan_address, 53, "authoritative_dns_udp"),
    }
    required_owners = {
        "owner_vpn_https": "tuntun-owner-ingress",
        "authoritative_dns_tcp": "tuntun-authoritative-resolver",
        "authoritative_dns_udp": "tuntun-authoritative-resolver",
    }
    if not snapshot.listener_inventory.contains_each_exactly_once_from_owner(
        expected, required_owners,
    ):
        return ExposureDecision.suspend("required_listener_missing_or_misowned")
    forbidden = snapshot.listeners - snapshot.accepted_phase3_owner_ingress_listeners - expected
    if forbidden or snapshot.router_mappings or snapshot.public_routes:
        return ExposureDecision.suspend("unexpected_exposure")
    if not snapshot.firewall.permits_only(expected, snapshot.approved_node_set):
        return ExposureDecision.suspend("firewall_drift")
    if snapshot.tailscale_flags.any_of("funnel", "public_serve", "subnet", "exit_node", "ssh"):
        return ExposureDecision.suspend("forbidden_tailscale_route")
    return ExposureDecision.healthy(valid_for=timedelta(seconds=30))
~~~

Run the guard at commissioning, every 30 seconds, and on listener/route/firewall/client events. Probe application, route state, last-applied probe generation, and session revocation share one durable serialized transaction; commit the generation even for a failure or stale result, and accept only a strictly larger generation. Circuit-break repeated scan crashes, mark posture unknown, suspend, and show a mandatory local alert. The guard never edits router mappings or enables a replacement transport.

The resolver accepts launchd-provided socket descriptors only—never self-privileged bind—and verifies their exact commissioned address/port/transport and listener view before reading. Its bounded DNS wire parser permits one standard class-IN `A` question for the single lower-cased wire name `tuntun.home.arpa.` and returns the commissioned LAN address on both LAN transports and the commissioned Tailnet address on both Tailnet transports, each with a 30-second TTL. The listener view, not UDP versus TCP, selects the answer; source policy is independently checked for that view. It has no recursion, forwarder, cache, search-domain expansion, dynamic update, zone transfer, EDNS enlargement or query-name logging. UDP/TCP frames, compression pointers, labels, question count and total bytes have explicit ceilings; malformed/unknown/cross-view input receives a fixed bounded authoritative refusal/format response or is dropped according to the corpus oracle. Launchd runs the guard as `_tuntun_netprobe` and resolver as `_tuntun_dns`, with absolute installed ProgramArguments, empty nonessential environment, working directory `/`, socket activation, no shell and no broad filesystem read. Start/health/restart/wrong-account tests verify both jobs, the Core UDS peer policy, missed-deadline suspension and old-generation denial. `ops/services/phase6-network-boundary.v1.json` binds package/wheel/plist/config/entrypoint/accounts, the Core-owned UDS, resolver sockets and owned cleanup paths; Tasks 27 and 29 must package and remove that exact inventory. This task extends the sole signed `ops/routes/owner-ingress-routes.v1.json` listener-class envelope with `owner_vpn_https`; it creates no Phase 6 route manifest. That change deliberately makes the inherited `phase3-owner-ingress.v1.json` wheel/route digest stale. Tasks 10–12 finish the P6-1 route/composition graph, and Task 15 refreshes/re-signs the canonical owner-ingress row and reruns its installed lifecycle before the real pilot. Tasks 18, 29 and 36 repeat that checkpoint after their later route graphs.

- [ ] **Step 4: Run green, synthetic drift campaign, and launchd lint**

Run: `uv lock && uv sync --all-packages && uv run pytest tests/unit/phase6/test_network_boundary_package_smoke.py tests/contract/phase6/test_exposure_probe_ipc.py tests/security/phase6/test_exposure_probe_ipc.py tests/security/phase6/test_authoritative_resolver_wire.py tests/integration/phase6/test_network_boundary_service_lifecycle.py apps/core/tests/unit/hardening/test_exposure_guard.py tests/security/phase6/test_interface_bind_policy.py tests/fault/phase6/test_exposure_drift_suspends.py tests/integration/phase6/test_local_independence_on_remote_close.py tests/integration/phase6/test_owner_ingress_listener_extension.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/security/phase6/test_core_media_have_no_listener.py -q && uv build apps/network-boundary && uv run tuntun-exposure-guard --help && uv run tuntun-authoritative-resolver --help && uv run tuntun-exposure-guard doctor --synthetic --no-network --json && uv run tuntun-authoritative-resolver doctor --synthetic --no-bind --json && uv run python ops/network/verify_lateral_reachability.py --synthetic --output var/evidence/phase6/lateral-synthetic.json && plutil -lint ops/launchd/com.tuntun.exposure-guard.plist ops/launchd/com.tuntun.authoritative-resolver.plist && uv run python scripts/check_import_boundaries.py --domain network-boundary && uv run ruff check apps/network-boundary packages/contracts/src/tuntun_contracts/hardening/exposure.py apps/core/src/tuntun_core/services/hardening/exposure_guard.py apps/core/src/tuntun_core/services/hardening/exposure_probe_ingress.py ops/network tests/unit/phase6 tests/contract/phase6 tests/security/phase6 tests/integration/phase6 tests/fault/phase6 && uv run mypy apps/network-boundary/src packages/contracts/src apps/core/src`
Expected: PASS; every drift closes remote state and the synthetic remote node reaches only the console origin.

- [ ] **Step 5: Commit exposure enforcement**

~~~bash
git add pyproject.toml uv.lock apps/network-boundary packages/contracts/src/tuntun_contracts/hardening/exposure.py apps/core/src/tuntun_core/services/hardening/exposure_guard.py apps/core/src/tuntun_core/services/hardening/exposure_probe_ingress.py apps/owner-ingress/src/tuntun_owner_ingress/listeners.py ops/network ops/network/exposure-manifest.v1.yaml ops/launchd/com.tuntun.exposure-guard.plist ops/launchd/com.tuntun.authoritative-resolver.plist ops/services/phase6-network-boundary.v1.json ops/routes/owner-ingress-routes.v1.json fixtures/adversarial/phase6/dns-wire-corpus tests/unit/phase6/test_network_boundary_package_smoke.py tests/contract/phase6/test_exposure_probe_ipc.py tests/security/phase6/test_exposure_probe_ipc.py tests/security/phase6/test_authoritative_resolver_wire.py tests/integration/phase6/test_network_boundary_service_lifecycle.py apps/core/tests/unit/hardening/test_exposure_guard.py tests/security/phase6/test_interface_bind_policy.py tests/fault/phase6/test_exposure_drift_suspends.py tests/integration/phase6/test_local_independence_on_remote_close.py tests/integration/phase6/test_owner_ingress_listener_extension.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/security/phase6/test_core_media_have_no_listener.py
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
- Create: `ops/remote-access/tailscale-policy.template.hujson`
- Create: `ops/remote-access/commission.py`
- Create: `ops/remote-access/disable.py`
- Create: `ops/remote-access/verify_posture.py`
- Create: `docs/operations/phase6-remote-access.md`
- Test: `apps/core/tests/unit/hardening/test_remote_commissioning.py`
- Test: `tests/security/phase6/test_commissioning_local_owner_only.py`
- Test: `tests/contract/hardening/test_tailscale_grants_policy.py`
- Test: `tests/acceptance/phase6/test_remote_commissioning_receipt.py`

**Interfaces:** Produces a prepared local-owner ceremony and `RemoteCommissioningReceiptV1` binding exact adapter/client/current signed-node state/Tailnet Lock and signed-node-set generations/exact approved-node set/at least two independent signing nodes/recovery, canonical Tailscale `grants` policy digest, two-view authoritative DNS addresses/record/TTL/client acceptance, local CA/certificate SAN, firewall/origin and revocation evidence. Every positive grant `src` is the canonical Tailnet IPv4 address of one commissioned node; email, group, autogroup, or tag principals are valid only in the separately typed `tagOwners` map and can never grant console reachability. Device Approval is proved disabled. It transitions only `DISABLED → COMMISSIONING → READ_ONLY`.

**Rollback/disabled exit:** Failure calls `disable.py`, closes the 8443 route, revokes application sessions/generations, leaves Tailscale account cleanup instructions, and returns canonical state to `DISABLED`.

- [ ] **Step 1: Write red local-presence, grants-policy, lock, resolver, recovery, and state tests**

~~~python
def test_remote_commissioning_requires_local_owner_action_bound_passkey(service, remote_request) -> None:
    with pytest.raises(AssuranceInsufficient):
        service.prepare(remote_request)

def test_grants_policy_has_exact_sources_tag_and_ports(grants_policy) -> None:
    assert len(grants_policy.grants) == 1
    grant = grants_policy.grants[0]
    assert grant.src == APPROVED_OWNER_NODE_SOURCES
    assert grant.dst == ("tag:tuntun-core",)
    assert grant.ip == ("tcp:8443", "tcp:53", "udp:53")
    assert grants_policy.tagOwners == {"tag:tuntun-core": CLOSED_TUNTUN_CORE_TAG_OWNERS}
    assert not grants_policy.has_wildcard_source_or_destination
    assert grants_policy.advertised_routes == ()

def test_second_device_under_same_owner_principal_is_not_selected(grants_policy, policy_checker) -> None:
    assert policy_checker.can_reach(grants_policy, APPROVED_OWNER_NODE_TAILNET_IPV4, "tag:tuntun-core", "tcp:8443")
    assert not policy_checker.can_reach(
        grants_policy, UNAPPROVED_SAME_OWNER_NODE_TAILNET_IPV4, "tag:tuntun-core", "tcp:8443",
    )

@pytest.mark.parametrize("broad_source", [
    "owner@example.test", "group:owners", "autogroup:member", "tag:owner-device",
])
def test_grants_reject_every_broad_principal_as_source(grants_payload, broad_source) -> None:
    with pytest.raises(ValidationError):
        TailscaleGrantsPolicyV1.model_validate(grants_payload.with_src(broad_source))

def test_tag_owner_selector_is_byte_bounded_and_unique(grants_payload) -> None:
    with pytest.raises(ValidationError, match="tailscale_tag_owner_selector_invalid"):
        TailscaleGrantsPolicyV1.model_validate(grants_payload.with_tag_owners(("group:" + "a" * 129,)))
    owner = CLOSED_TUNTUN_CORE_TAG_OWNERS[0]
    with pytest.raises(ValidationError, match="duplicate_grants_tag_owner"):
        TailscaleGrantsPolicyV1.model_validate(grants_payload.with_tag_owners((owner, owner)))

@pytest.mark.parametrize("bad_dst", [
    "tag:tuntun-core:8443", "tag:tuntun-core:53", "tag:tuntun-core:53/tcp", "tag:tuntun-core:53/udp",
])
def test_grants_rejects_acl_style_port_suffixed_destination(grants_payload, bad_dst) -> None:
    with pytest.raises(ValidationError):
        TailscaleGrantsPolicyV1.model_validate(grants_payload.with_dst(bad_dst))

def test_tailnet_lock_and_device_approval_are_mutually_exclusive(posture) -> None:
    assert posture.tailnet_lock_state == "enabled"

def test_legacy_device_approval_contract_key_is_rejected(tailscale_client_payload) -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        TailscaleClientStateV1.model_validate({
            **tailscale_client_payload, "device_approval_state": "disabled",
        })

@pytest.mark.parametrize("provider_admission_state", ["device_approval_only", "both_enabled"])
def test_control_plane_evidence_rejects_device_approval_or_mutual_enablement(
    provider_policy_evidence, provider_admission_state,
) -> None:
    with pytest.raises(AdapterPostureDenied, match="tailnet_lock_must_be_sole_admission_authority"):
        verify_signed_provider_policy_evidence(
            provider_policy_evidence.with_admission_state(provider_admission_state),
        )

def test_commissioning_allocates_local_generations_from_real_authority_facts(harness) -> None:
    first = harness.commission()
    same = harness.recommission_without_fact_change()
    changed_lock = harness.recommission_with_changed_lock_head()
    changed_nodes = harness.recommission_with_changed_signed_node_set()
    assert same.tailnet_lock_generation == first.tailnet_lock_generation
    assert same.signed_node_set_generation == first.signed_node_set_generation
    assert changed_lock.tailnet_lock_generation > same.tailnet_lock_generation
    assert changed_nodes.signed_node_set_generation > changed_lock.signed_node_set_generation

def test_authoritative_resolver_has_exact_two_views(resolver) -> None:
    assert resolver.lookup(LAN_CLIENT, "tuntun.home.arpa", "A") == COMMISSIONED_LAN_ADDRESS
    assert resolver.lookup(APPROVED_TAILNET_NODE, "tuntun.home.arpa", "A") == COMMISSIONED_TAILNET_ADDRESS
    for query in RECURSION_UPDATE_AXFR_OTHER_ZONE_WILDCARD_AAAA_CASES:
        assert resolver.query(query).denied

def test_household_state_is_hidden_during_commissioning(harness) -> None:
    harness.route_state = "commissioning"
    assert harness.remote_get("/api/v1/ui/posture").status_code == 503
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/core/tests/unit/hardening/test_remote_commissioning.py tests/security/phase6/test_commissioning_local_owner_only.py tests/contract/hardening/test_tailscale_grants_policy.py tests/contract/hardening/test_authoritative_resolver.py tests/acceptance/phase6/test_remote_commissioning_receipt.py -q`
Expected: FAIL because the commissioning state machine, template, and receipt are absent.

- [ ] **Step 3: Implement the complete evidence-bound local ceremony**

~~~python
async def complete(self, prepared_id: UUID, passkey: PasskeyResult, evidence: CommissionEvidence) -> Receipt:
    prepared = await self._prepared.consume_local_owner(prepared_id, passkey, local_presence=True)
    require(evidence.tailnet_lock_is_sole_admission_authority)
    require(evidence.tailnet_lock_enabled and evidence.current_core_node_signed)
    require(evidence.lock_status_schema_version == "1")
    require(evidence.tailnet_lock_aum_head and evidence.tailnet_lock_state_id >= 1)
    require(evidence.signed_node_set_current and evidence.recovery_signers_independent)
    require(len(set(evidence.signing_node_commitments)) >= 2)
    require(evidence.grants_sources == APPROVED_OWNER_NODE_SOURCES)
    require(evidence.grants_destinations == ("tag:tuntun-core",))
    require(evidence.grants_ip == ("tcp:8443", "tcp:53", "udp:53"))
    require(evidence.authoritative_resolver_exact_two_views)
    require(evidence.resolver_record == "tuntun.home.arpa")
    require(evidence.certificate_san == "tuntun.home.arpa")
    require(not evidence.forbidden_route_flags)
    require(evidence.local_ca_origin == "https://tuntun.home.arpa:8443")
    require(evidence.revoke_drill_passed and evidence.local_independence_passed)
    require(evidence.real_macos_projection_fixture_matches_live_pinned_client)
    tailnet_lock_generation = await self._generations.advance_if_changed(
        "tailnet_lock",
        evidence.commitment_for_lock_head_state_trusted_keys_and_recovery(),
    )
    signed_node_set_generation = await self._generations.advance_if_changed(
        "signed_node_set", evidence.commitment_for_exact_signed_node_keys(),
    )
    return await self._routes.promote_read_only(
        prepared,
        evidence.safe_commitments(
            tailnet_lock_generation=tailnet_lock_generation,
            signed_node_set_generation=signed_node_set_generation,
        ),
    )
~~~

The tool never creates a router mapping, public DNS, subnet/exit route, Funnel, SSH, or public Serve. It records current Tailscale terms/pricing review, stable lock-status schema version, exact Head/State, locally committed recovery KDF configuration, independent `tlpub:` signing-key procedure, lost-device revoke, exact signed `nodekey:` set by pseudonym, cert lifecycle, pinned-client fixture digest, and disabled exit. Device Approval state comes from a separately signed/exported provider-policy evidence artifact during the local ceremony; it is not fabricated from `status --json`. No provider credential enters the runtime adapter. During commissioning only a synthetic test endpoint is allowed; no household projection is returned.

- [ ] **Step 4: Run green and synthetic commissioning/disable round-trip**

Run: `uv run pytest apps/core/tests/unit/hardening/test_remote_commissioning.py tests/security/phase6/test_commissioning_local_owner_only.py tests/contract/hardening/test_tailscale_grants_policy.py tests/contract/hardening/test_authoritative_resolver.py tests/acceptance/phase6/test_remote_commissioning_receipt.py -q && uv run python ops/remote-access/commission.py --synthetic --output var/evidence/phase6/commission-synthetic.json && uv run python ops/remote-access/disable.py --synthetic --assert-no-route && uv run ruff check apps/core/src/tuntun_core/services/hardening/remote_commissioning.py ops/remote-access tests/security/phase6 tests/acceptance/phase6 && uv run mypy apps/core/src ops/remote-access`
Expected: PASS; synthetic state reaches read-only only after every proof, then disables with no route/session.

- [ ] **Step 5: Commit commissioning**

~~~bash
git add apps/core/src/tuntun_core/services/hardening/remote_commissioning.py ops/remote-access docs/operations/phase6-remote-access.md apps/core/tests/unit/hardening/test_remote_commissioning.py tests/security/phase6/test_commissioning_local_owner_only.py tests/contract/hardening/test_tailscale_grants_policy.py tests/contract/hardening/test_authoritative_resolver.py tests/acceptance/phase6/test_remote_commissioning_receipt.py
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
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/core/src/tuntun_core/services/auth/sessions.py`
- Modify: `apps/core/src/tuntun_core/api/middleware.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Create: `apps/core/tests/unit/hardening/test_remote_sessions.py`
- Create: `apps/core/tests/integration/hardening/test_remote_session_api.py`
- Create: `tests/security/phase6/test_remote_auth_matrix.py`
- Create: `tests/property/phase6/test_remote_nonce_replay.py`
- Create: `tests/integration/phase6/test_owner_ingress_phase6_composition.py`
- Modify: `tests/integration/deploy/test_owner_ingress_route_manifest.py`

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

async def test_authorized_access_slides_idle_without_refreshing_passkey_assurance(harness, fake_clock) -> None:
    session = await harness.establish_remote()
    original_reauthentication = session.last_reauthenticated_at
    fake_clock.advance(minutes=14)
    touched = await harness.require(session, "read_only_status")
    assert touched.last_access_at == fake_clock.now()
    assert touched.idle_expires_at == min(fake_clock.now() + timedelta(minutes=15), session.absolute_expires_at)
    assert touched.last_reauthenticated_at == original_reauthentication
    fake_clock.advance(minutes=5, microseconds=1)
    assert await harness.require(touched, "camera_playback", fresh_within=timedelta(minutes=5)) == "fresh_passkey_required"

async def test_idle_touch_samples_time_inside_serialized_current_authority_check(harness) -> None:
    session = await harness.establish_remote()
    waiting = harness.begin_require_while_session_writer_locked(session, "read_only_status")
    harness.clock.advance(minutes=15, microseconds=1)
    harness.release_session_writer()
    assert await waiting == "session_idle_expired"
    assert harness.repository.last_access_at(session.session_id) == session.last_access_at

async def test_idle_slide_is_capped_by_absolute_expiry(harness, fake_clock) -> None:
    session = await harness.establish_remote(absolute_ttl=timedelta(minutes=20))
    await harness.keep_active_until(session, session.absolute_expires_at - timedelta(minutes=1))
    touched = await harness.require(session, "read_only_status")
    assert touched.idle_expires_at == session.absolute_expires_at
    fake_clock.advance(minutes=1, microseconds=1)
    assert await harness.require(touched, "read_only_status") == "session_absolute_expired"

async def test_restart_preserves_last_access_and_never_extends_idle(harness, fake_clock) -> None:
    session = await harness.establish_remote()
    fake_clock.advance(minutes=14)
    touched = await harness.require(session, "read_only_status")
    restarted = await harness.restart()
    persisted = restarted.repository.require(session.session_id)
    assert (persisted.last_access_at, persisted.idle_expires_at) == (
        touched.last_access_at, touched.idle_expires_at,
    )
    fake_clock.advance(minutes=15, microseconds=1)
    assert await restarted.require(persisted, "read_only_status") == "session_idle_expired"

async def test_concurrent_idle_touch_and_revoke_cannot_resurrect_session(harness) -> None:
    session = await harness.establish_remote()
    touch_result, revoke_result = await harness.race_touch_against_revoke(session.session_id)
    assert touch_result in {"admitted_before_revoke", "session_revoked"}
    assert revoke_result == "revoked"
    assert harness.repository.lookup(session.session_id) is None
    assert await harness.require(session, "read_only_status") == "session_revoked"

@pytest.mark.parametrize("winner", ["establish", "revoke"])
async def test_establish_and_revoke_share_one_authoritative_serialization_boundary(
    harness, winner,
) -> None:
    result = await harness.race_establish_against_revoke(winner=winner)
    assert result.revoke_state == "revoked"
    assert harness.repository.active_sessions == ()
    assert result.establishment_token is None or not harness.token_is_active(result.establishment_token)
    if winner == "revoke":
        assert result.establish_state == "session_revoked"

async def test_restart_cannot_recover_session_from_pre_revocation_generation(harness) -> None:
    result = await harness.race_establish_against_revoke(winner="establish")
    restarted = await harness.restart()
    assert restarted.repository.lookup(result.session_id) is None
    assert not restarted.token_is_active(result.establishment_token)

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

@pytest.mark.parametrize(("method", "path"), [
    ("POST", "/api/v1/remote/session/challenge"),
    ("POST", "/api/v1/remote/session/establish"),
    ("POST", "/api/v1/remote/session/reauthenticate"),
    ("DELETE", "/api/v1/remote/session/current"),
])
async def test_installed_candidate_composes_each_signed_remote_session_route_once(
    installed_owner_ingress, method, path,
) -> None:
    response = await installed_owner_ingress.request_exact(method, path)
    assert response.route_manifest_matches == 1
    assert response.core_uds_dispatches == 1
    assert response.direct_core_tcp_dispatches == 0

@pytest.mark.parametrize("path", [
    "/api/v1/remote/session/unknown", "/api/v1/remote/session/debug",
])
async def test_unknown_or_disabled_remote_session_route_is_404_without_uds_call(
    installed_owner_ingress, path,
) -> None:
    response = await installed_owner_ingress.request_exact("POST", path)
    assert response.status_code == 404
    assert response.core_uds_dispatches == 0
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/core/tests/unit/hardening/test_remote_sessions.py apps/core/tests/integration/hardening/test_remote_session_api.py tests/security/phase6/test_remote_auth_matrix.py tests/property/phase6/test_remote_nonce_replay.py -q`
Expected: FAIL because remote session establishment and middleware rules are absent.

- [ ] **Step 3: Implement exact layered establishment and current-generation checks**

~~~python
async def establish(self, posture, passkey, request) -> RemoteSessionV1:
    self._origin.require_exact(request, host="tuntun.home.arpa:8443", scheme="https")
    self._csrf.consume_bound_nonce(request.csrf, request.nonce)
    verified_assertion = await self._passkeys.verify_owner_phishing_resistant(passkey)
    async with self._uow.authoritative() as tx:
        route = await tx.routes.require_state("read_only", "scoped_actions")
        await tx.posture.require_current_approved_node_exact_route(posture, route)
        owner = await tx.credentials.require_current_verified_assertion(verified_assertion)
        enabled = await tx.operation_classes.current_exact_for_owner(
            owner.subject_id, route_state=route.state,
        )
        revocation_generation = await tx.revocations.current_generation()
        now = self._clock.now()
        session = RemoteSessionV1(
            session_id=uuid4(), actor_subject_id=owner.subject_id,
            vpn_adapter_id=posture.adapter_id, vpn_node_pseudonym=posture.node_pseudonym,
            tailnet_lock_generation=posture.tailnet_lock_generation,
            signed_node_set_generation=posture.signed_node_set_generation,
            route_generation=route.route_generation,
            application_passkey_assurance="phishing_resistant", established_at=now,
            last_reauthenticated_at=now, last_access_at=now,
            idle_expires_at=now + timedelta(minutes=15),
            absolute_expires_at=now + timedelta(hours=8),
            allowed_operation_classes=tuple(sorted({"read_only_status", *enabled.operation_class_ids})),
            operation_class_generation=enabled.generation,
            policy_version=await tx.policy.current_version(),
            revocation_generation=revocation_generation,
        )
        await tx.sessions.create_if_all_generations_still_exact(
            session, route=route, posture=posture, operation_classes=enabled,
            verified_assertion=verified_assertion,
        )
        return session
~~~

Apply per-node/session/IP-free pseudonymous rate limits, exact content type/size, Host/Origin/CORS/CSRF, cookie `Secure`/`HttpOnly`/`SameSite=Strict`, no bearer in URL/storage, concurrent revoke locking, and five-minute fresh-passkey checks. Establishment and Task 13 suspension use the same authoritative serialized UoW: route, posture, credential, operation-class, policy and revocation generations are loaded and the new session inserted under one transaction/CAS. The session persists `route_generation`; no response token/cookie is emitted until commit, and a later winning revoke makes any already emitted token inactive by deleting all sessions at that route/revocation generation. `require(...)` acquires the same serialized session writer, then samples trusted time, compares idle/absolute expiry plus the session's exact route, revocation, operation-class and policy generations and membership to current state, and only on successful admission atomically advances `last_access_at` and `idle_expires_at=min(last_access_at+15 minutes, absolute_expires_at)`. It never changes `last_reauthenticated_at`; only a successful fresh passkey ceremony may do that. Enabling, disabling, or changing any class increments that generation and transactionally revokes every earlier remote session; only a fresh passkey-authenticated reissue can receive the new closed class set. Restart performs the same generation join before admitting a token. Return stable safe errors and `no-store` on protected responses.

`api/app.py` registers the exact four session endpoints above, `bootstrap/container.py` supplies their one service instance, and the existing owner-ingress router adds exactly those four rows to the sole signed `ops/routes/owner-ingress-routes.v1.json`. The installed composition loads Core and ingress from that same manifest; an unknown, disabled, duplicate or unsigned path is 404 before UDS dispatch, and Core still owns no TCP listener. No decorator-only or test-only route counts as reachable. These mutations intentionally stale the inherited owner-ingress service row; after Tasks 11–12 complete the P6-1 graph, Task 15 rebuilds the wheel and re-signs its route-manifest binding before the real pilot.

- [ ] **Step 4: Run green plus complete auth/fuzz suite**

Run: `uv run pytest apps/core/tests/unit/hardening/test_remote_sessions.py apps/core/tests/integration/hardening/test_remote_session_api.py tests/security/phase6/test_remote_auth_matrix.py tests/property/phase6/test_remote_nonce_replay.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py -q && uv run pytest tests/security/auth tests/property/auth -q && uv run ruff check apps/core/src/tuntun_core/services/hardening/remote_sessions.py apps/core/src/tuntun_core/api/routes/remote_access.py apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/services/auth/sessions.py apps/owner-ingress/src/tuntun_owner_ingress/router.py tests/security/phase6 tests/property/phase6 tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py && uv run mypy apps/core/src apps/owner-ingress/src`
Expected: PASS; VPN-only and app-only cases reveal zero state, and replay/expiry/revocation deny deterministically.

- [ ] **Step 5: Commit remote sessions**

~~~bash
git add apps/core/src/tuntun_core/services/hardening/remote_sessions.py apps/core/src/tuntun_core/api/routes/remote_access.py apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/services/auth/sessions.py apps/core/src/tuntun_core/api/middleware.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json apps/core/tests/unit/hardening/test_remote_sessions.py apps/core/tests/integration/hardening/test_remote_session_api.py tests/security/phase6/test_remote_auth_matrix.py tests/property/phase6/test_remote_nonce_replay.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py
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
- Create: `apps/owner-ingress/src/tuntun_owner_ingress/remote_operation.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/service.py`
- Create: `apps/core/src/tuntun_core/services/hardening/remote_policy.py`
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Create: `packages/policy/src/tuntun_policy/evaluator.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Create: `fixtures/adversarial/phase6/remote-operation-matrix-v1.jsonl`
- Test: `apps/core/tests/unit/hardening/test_remote_policy.py`
- Test: `tests/policy/test_remote_operation_matrix.py`
- Test: `tests/security/phase6/test_remote_local_only_denials.py`
- Test: `tests/property/phase6/test_remote_never_upgrades_authority.py`
- Test: `apps/owner-ingress/tests/security/test_remote_operation_ingress.py`
- Test: `tests/integration/phase6/test_owner_ingress_remote_operation.py`
- Modify: `tests/integration/phase6/test_owner_ingress_phase6_composition.py`
- Modify: `tests/integration/deploy/test_owner_ingress_route_manifest.py`

**Interfaces:** Owner-ingress produces `RemoteOperationIngress.handle_raw(OwnerIngressRequest) -> HttpResponse` at the TLS socket boundary and sends only a validated three-field `RemoteOperationRequestV1` plus a fixed bounded transport/session frame over the already authenticated owner-ingress→Core UDS. Core produces `RemoteRequestAuthorizer.authorize(RemoteOperationRequestV1, HttpOnlySession) -> AuthorizedRemoteContextV1` and `RemotePolicy.decide(AuthorizedRemoteContextV1) -> RemoteOperationDecisionV1`. This task is the first owner of `tuntun_policy.evaluator`, whose closed `PolicyEvaluator.evaluate(LocalPolicyContextV1) -> LocalPolicyDecisionV1` applies the already frozen registry/corpus without I/O or remote defaults; remote policy may only invoke it through `context.as_assurance_reduced_local()`. The external body has only operation/resource/idempotency. The matrix has closed classes for allowed read-only projections, separately disabled optional scopes, and permanent Phase 6 remote denials; policy/storage/action/media consumers accept only the server-built context. Core never receives a raw HTTP body and never creates a parallel TCP/framework route.

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
    assert remote_policy.decide(server_context(operation)).code == "REMOTE_OPERATION_DENIED"
    assert not remote_policy.can_prepare(operation)

@pytest.mark.parametrize("alias", ["plugin_permission", "recovery_import"])
def test_remote_denial_aliases_are_unknown(alias) -> None:
    with pytest.raises(ValidationError):
        RemoteOperationRequestV1.model_validate({"operation": alias, "resource": None, "idempotency_key": uuid4()})

def test_remote_allowed_set_is_subset_of_local_allowed_set(property_requests, policy) -> None:
    for request in property_requests:
        if policy.remote(request).allowed:
            assert policy.local(request).allowed

@pytest.mark.parametrize("caller_authority_field", [
    "schema_id", "target", "desired_state", "actor_subject_id", "application_session_id", "vpn_node_pseudonym",
    "route_generation", "tailnet_lock_generation", "signed_node_set_generation",
    "operation_class_generation", "policy_version", "privacy_generation",
    "application_revocation_generation", "last_reauthenticated_at", "authorized_at",
    "valid_until", "context_commitment",
])
def test_http_request_rejects_every_field_outside_operation_resource_idempotency(caller_authority_field) -> None:
    body = valid_remote_request_json()
    body[caller_authority_field] = plausible_spoof(caller_authority_field)
    with pytest.raises(ValidationError, match="extra_forbidden"):
        RemoteOperationRequestV1.model_validate(body)

@pytest.mark.parametrize("fault", [
    "invalid_utf8", "duplicate_key", "noncanonical_json", "nonfinite_number",
    "decimal_over_64_digits", "depth_33", "container_4097", "structure_token_16385",
    "declared_oversize_body", "chunked_oversize_body", "truncated_declared_body",
    "client_disconnect", "slow_body_timeout",
    "wrong_root", "unknown_field",
])
async def test_raw_remote_operation_body_fails_before_authority_or_io(remote_http, fault) -> None:
    response = await remote_http.post_raw_operation_body(remote_body_with_fault(fault))
    assert response.status_code == 400
    assert response.json() == {"code": "SCHEMA_UNSUPPORTED"}
    assert remote_http.session_store_calls == 0
    assert remote_http.authorizer_calls == 0
    assert remote_http.database_calls == 0
    assert remote_http.adapter_calls == 0
    assert remote_http.peak_body_buffer_bytes <= REMOTE_OPERATION_BODY_MAX_BYTES + 1

async def test_wrong_media_type_reads_no_body_or_session(remote_http) -> None:
    response = await remote_http.post_operation(content_type="application/json", endless_body=True)
    assert response.status_code == 400
    assert remote_http.body_bytes_read == 0
    assert remote_http.session_store_calls == 0

async def test_valid_canonical_body_dispatches_exactly_once_over_authenticated_core_uds(
    remote_http,
) -> None:
    response = await remote_http.post_canonical_operation(
        valid_remote_request_json(),
        content_type="application/vnd.tuntun.remote-operation.v1+json",
    )
    assert response.status_code == 200
    assert remote_http.core_uds_dispatch_calls == 1
    assert remote_http.dispatched_request == RemoteOperationRequestV1.model_validate(
        valid_remote_request_json(),
    )

def test_signed_manifest_has_one_exact_raw_remote_operation_route(route_manifest) -> None:
    row = route_manifest.require_exact("POST", "/api/v1/remote/operation")
    assert row.request_media_type == "application/vnd.tuntun.remote-operation.v1+json"
    assert row.handler == "owner_ingress.raw_remote_operation_v1"
    assert row.target == "peer_authenticated_core_uds"
    assert route_manifest.match_count("POST", "/api/v1/remote/operation") == 1

@pytest.mark.parametrize("path", [
    "/api/v1/remote/operations", "/api/v1/remote/operation/debug",
])
async def test_unknown_or_disabled_remote_operation_path_is_404_before_body_or_uds(
    installed_owner_ingress, path,
) -> None:
    response = await installed_owner_ingress.post_raw(path, endless_body=True)
    assert response.status_code == 404
    assert installed_owner_ingress.body_bytes_read == 0
    assert installed_owner_ingress.core_uds_dispatch_calls == 0

@pytest.mark.parametrize("fault", [
    "missing_cookie", "duplicate_cookie", "oversize_cookie", "invalid_cookie_octet",
    "duplicate_host", "invalid_host", "wrong_origin", "missing_csrf", "duplicate_csrf",
    "oversize_route_metadata", "route_peer_binding_mismatch",
])
async def test_hostile_cookie_or_route_metadata_denies_before_body_authority_or_io(remote_http, fault) -> None:
    response = await remote_http.post_with_metadata_fault(
        valid_remote_request_json(),
        fault=fault,
    )
    assert response.status_code == 400
    assert response.json() == {"code": "SCHEMA_UNSUPPORTED"}
    assert remote_http.body_bytes_read == 0
    assert remote_http.session_store_calls == 0
    assert remote_http.authorizer_calls == 0
    assert remote_http.core_uds_dispatch_calls == 0
    assert remote_http.database_calls == 0
    assert remote_http.peak_metadata_buffer_bytes <= REMOTE_OPERATION_METADATA_MAX_BYTES + 1

@pytest.mark.parametrize("unexpected", [
    ValueError("programmer fault"), TypeError("programmer fault"),
    AssertionError("programmer fault"), RuntimeError("programmer fault"),
    asyncio.CancelledError(),
])
async def test_metadata_adapter_programmer_fault_or_cancellation_is_not_normalized(
    remote_http, unexpected,
) -> None:
    remote_http.inject_metadata_programmer_fault(unexpected)
    with pytest.raises(type(unexpected)):
        await remote_http.post_canonical_operation(valid_remote_request_json())

def test_external_request_serializes_exact_three_field_body(valid_remote_request) -> None:
    assert set(valid_remote_request.model_dump()) == {"operation", "resource", "idempotency_key"}

@pytest.mark.parametrize("offset", [timedelta(microseconds=1), timedelta(minutes=5)])
def test_server_context_rejects_future_reauthentication(authorized_context_fixture, offset) -> None:
    with pytest.raises(ValidationError, match="reauthentication_in_future"):
        AuthorizedRemoteContextV1.model_validate({
            **authorized_context_fixture,
            "last_reauthenticated_at": authorized_context_fixture["authorized_at"] + offset,
        })

async def test_clock_rollback_cannot_turn_stale_passkey_fresh(harness) -> None:
    context = await harness.authorized_context(passkey_age=timedelta(minutes=5, microseconds=1))
    harness.clock.roll_back(seconds=30)
    assert await harness.decide(context) == "ASSURANCE_INSUFFICIENT"
    assert harness.downstream_calls == ()

@pytest.mark.parametrize(("operation", "resource_type"), [
    ("light_power_on", "media_player"), ("light_power_off", "camera_event"),
    ("media_stop", "light"), ("subject_private_memory", "approval"),
])
def test_external_operation_resource_type_substitution_is_rejected(operation, resource_type) -> None:
    with pytest.raises(ValidationError, match="remote_operation_resource_type_invalid"):
        RemoteOperationRequestV1(
            operation=operation,
            resource=OpaqueRemoteResourceRefV1(resource_type=resource_type, opaque_id=random_pseudonym()),
            idempotency_key=uuid4(),
        )
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/owner-ingress/tests/security/test_remote_operation_ingress.py tests/integration/phase6/test_owner_ingress_remote_operation.py apps/core/tests/unit/hardening/test_remote_policy.py tests/policy/test_remote_operation_matrix.py tests/security/phase6/test_remote_local_only_denials.py tests/property/phase6/test_remote_never_upgrades_authority.py -q`
Expected: FAIL because the closed remote policy is absent.

- [ ] **Step 3: Implement explicit decisions and deny every unknown/local-only request**

~~~python
# apps/owner-ingress/src/tuntun_owner_ingress/remote_operation.py
from tuntun_contracts.base import ContractParseError, parse_contract_json

class BodyReadError(Exception): ...
class BodyReadTimeout(BodyReadError): ...
class BodyTooLarge(BodyReadError): ...
class BodyTruncated(BodyReadError): ...
class BodyClientDisconnected(BodyReadError): ...
class UnsupportedMediaType(Exception): ...
class RequestMetadataRejected(Exception): ...
class SessionCookieRejected(RequestMetadataRejected): ...
class AuthenticatedRouteContextRejected(RequestMetadataRejected): ...

REMOTE_OPERATION_BODY_MAX_BYTES = 4096
REMOTE_OPERATION_BODY_TIMEOUT = timedelta(seconds=2)
REMOTE_OPERATION_METADATA_MAX_BYTES = 8192

class RemoteOperationIngress:
    def __init__(self, core_remote_operations: CoreRemoteOperationDispatcher) -> None:
        self._core_remote_operations = core_remote_operations

    async def handle_raw(self, http_request: OwnerIngressRequest) -> HttpResponse:
        try:
            require_exact_content_type(http_request, "application/vnd.tuntun.remote-operation.v1+json")
            session_cookie = http_request.require_bounded_http_only_cookie(
                max_bytes=4096,
                max_total_metadata_bytes=REMOTE_OPERATION_METADATA_MAX_BYTES,
            )
            route_context = http_request.require_fixed_authenticated_route_context(
                max_total_metadata_bytes=REMOTE_OPERATION_METADATA_MAX_BYTES,
            )
            raw_body = await read_stream_bounded(
                http_request.body_stream,
                max_bytes=REMOTE_OPERATION_BODY_MAX_BYTES,
                max_buffer_bytes=REMOTE_OPERATION_BODY_MAX_BYTES + 1,
                timeout=REMOTE_OPERATION_BODY_TIMEOUT,
                declared_content_length=http_request.content_length,
            )
            request = parse_contract_json(
                RemoteOperationRequestV1,
                raw_body,
                max_bytes=REMOTE_OPERATION_BODY_MAX_BYTES,
                require_canonical=True,
            )
        except (BodyReadError, UnsupportedMediaType, RequestMetadataRejected, ContractParseError):
            # No session lookup, authorizer, database, adapter, policy or audit-body access
            # occurs for an unparseable control frame.
            return json_error(400, "SCHEMA_UNSUPPORTED", cache_control="no-store")
        # Only after bounded canonical parsing, forward exactly one fixed frame
        # through the pre-existing authenticated owner-ingress UDS. Core resolves
        # the opaque HttpOnly session and constructs authority; ingress owns no policy/store.
        return await self._core_remote_operations.dispatch_validated(
            request=request,
            session_cookie=session_cookie,
            route_context=route_context,
        )

def decide(self, context: AuthorizedRemoteContextV1) -> RemoteOperationDecisionV1:
    self._contexts.require_current_commitment(context)
    if context.operation in PERMANENT_REMOTE_DENIALS:
        return deny("REMOTE_OPERATION_DENIED")
    rule = self._registry.lookup_exact(context.operation)
    if rule is None or not rule.remote_capability_id:
        return deny("REMOTE_OPERATION_DENIED")
    if not self._local_policy.decide(context.as_assurance_reduced_local()).allowed:
        return deny("POLICY_DENIED")
    if not self._features.is_current_enabled(rule.remote_capability_id):
        return deny("FEATURE_ABSENT")
    return rule.evaluate_remote(context, assurance_reduction="remote_origin_v1")
~~~

The owner-ingress server preserves the exact HTTP bytes through an incremental max-plus-one reader; it rejects a declared oversize length before reading and stops a chunked/slow stream at the byte/deadline ceiling, so the whole body is never buffered ahead of the bound. Before reading that body, the request adapter bounds and validates the exact single cookie plus Host/Origin/CSRF/authenticated-route metadata. Missing, duplicate, malformed, oversized or peer-mismatched hostile metadata becomes only `SessionCookieRejected` or `AuthenticatedRouteContextRejected`; those named types return the same fixed no-store pre-I/O denial. The adapter does not translate cancellation, allocation failure, `TypeError`, `ValueError`, `AssertionError` or other programmer faults. The body reader similarly maps only its declared under-run, peer disconnect/I/O, timeout and size failures to `BodyReadError` subclasses. Router/service registration binds the exact media type directly to this raw stream handler before FastAPI, Starlette, Pydantic request-body injection or any generic JSON middleware. Direct raw-socket tests prove those decoders, Core UDS, session store, authorizer, database and adapters have zero calls for every malformed/oversize/slow/wrong-media/body/cookie/route-metadata request. After parsing, the fixed authenticated UDS frame carries only the already bounded cookie/route context, forbids arbitrary header maps, and Core revalidates the DTO before resolving the session and building authority. Core exposes no TCP listener or alternate framework endpoint. Read-only initially allows health/phase/device availability/content-minimized alerts/cost and approval metadata. Exact bodies require five-minute passkey plus local class enablement. A server-built context rejects `last_reauthenticated_at > authorized_at`; freshness is computed with the trusted monotonic/UTC clock pair and clock rollback cannot make old assurance fresh. Optional actions/media classes stay absent until Tasks 16–18. Test direct API, prepared issuance, config, replay, alternate content type, batch, client bundle, and underlying service calls.

The sole signed route manifest gains exactly `POST /api/v1/remote/operation`, bound to the raw handler, exact media type and peer-authenticated Core UDS. `api/app.py` exposes the corresponding UDS-only Core dispatch and `bootstrap/container.py` injects the same policy/session services; the owner-ingress router has no generic `/remote` prefix. Installed-candidate composition proves the signed row reaches exactly one handler, while unknown, disabled, duplicate or unsigned paths return 404 before body read or UDS I/O. This is the last raw remote-operation ingress mutation; Task 12 completes the P6-1 read-route graph, and Task 15 must rebuild/re-sign that checkpoint before the real pilot. Later owner-facing tasks extend the same manifest and trigger the later Task 18, 29 and 36 checkpoint refreshes.

- [ ] **Step 4: Run green and the full actor/resource policy matrix**

Run: `uv run pytest apps/owner-ingress/tests/security/test_remote_operation_ingress.py tests/integration/phase6/test_owner_ingress_remote_operation.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py apps/core/tests/unit/hardening/test_remote_policy.py tests/policy/test_remote_operation_matrix.py tests/security/phase6/test_remote_local_only_denials.py tests/property/phase6/test_remote_never_upgrades_authority.py -q && uv run pytest tests/policy/test_actor_resource_matrix.py -q && uv run python scripts/check_import_boundaries.py --domain owner-ingress && uv run ruff check apps/owner-ingress/src/tuntun_owner_ingress/remote_operation.py apps/owner-ingress/src/tuntun_owner_ingress/router.py apps/owner-ingress/src/tuntun_owner_ingress/service.py apps/owner-ingress/tests/security/test_remote_operation_ingress.py tests/integration/phase6/test_owner_ingress_remote_operation.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/services/hardening/remote_policy.py packages/policy/src/tuntun_policy/evaluator.py tests/policy tests/security/phase6 tests/property/phase6 && uv run mypy apps/owner-ingress/src apps/core/src packages/policy/src`
Expected: PASS; every permanent/unknown operation is denied and remote allow is a strict subset of local allow.

- [ ] **Step 5: Commit remote policy**

~~~bash
git add apps/owner-ingress/src/tuntun_owner_ingress/remote_operation.py apps/owner-ingress/src/tuntun_owner_ingress/router.py apps/owner-ingress/src/tuntun_owner_ingress/service.py apps/owner-ingress/tests/security/test_remote_operation_ingress.py tests/integration/phase6/test_owner_ingress_remote_operation.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/services/hardening/remote_policy.py packages/policy/src/tuntun_policy/evaluator.py ops/routes/owner-ingress-routes.v1.json fixtures/adversarial/phase6/remote-operation-matrix-v1.jsonl apps/core/tests/unit/hardening/test_remote_policy.py tests/policy/test_remote_operation_matrix.py tests/security/phase6/test_remote_local_only_denials.py tests/property/phase6/test_remote_never_upgrades_authority.py
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
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Create: `apps/admin/src/features/system/remote-access.tsx`
- Create: `apps/admin/src/features/system/remote-sessions.tsx`
- Create: `apps/admin/src/routes/system-remote-access.tsx`
- Test: `apps/core/tests/integration/hardening/test_remote_read_only_api.py`
- Modify: `tests/integration/phase6/test_owner_ingress_phase6_composition.py`
- Modify: `tests/integration/deploy/test_owner_ingress_route_manifest.py`
- Test: `apps/admin/src/features/system/remote-access.test.tsx`
- Test: `tests/ui/phase6/remote-read-only.spec.ts`
- Test: `tests/ui/phase6/remote-accessibility.spec.ts`

**Interfaces:** Produces owner-safe route/session/posture/health/alert/cost/approval-metadata read models, signed feature registration, route-origin label `approved VPN`, and a generated remote-operation client that emits the exact shared RFC 8785/JCS bytes from an immutable typed request. Python and TypeScript canonicalizers must pass the same edge-case golden corpus before this route can register. It uses the same console, never a public/mobile-native/PWA application.

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

test("remote operation client emits the shared RFC 8785 golden bytes", async ({page}) => {
  const captured = await captureNextRemoteOperationBody(page);
  await requestRemoteHealthStatus(page, "018f28d8-2dcb-7b33-a323-93f164164abc");
  expect(await captured).toEqual(
    canonicalGoldenBytes("remote-operation-health-status-v1"),
  );
});
~~~

~~~python
@pytest.mark.parametrize("method,path", [
    ("GET", "/api/v1/remote/status"),
    ("GET", "/api/v1/remote/sessions"),
])
def test_installed_remote_read_routes_dispatch_once_from_signed_manifest(
    installed_owner_ingress, method, path,
) -> None:
    result = installed_owner_ingress.request(method, path, feature_enabled=True)
    assert result.status_code == 200
    assert result.core_uds_dispatch_count == 1


@pytest.mark.parametrize("state", ["unknown", "disabled"])
def test_unknown_or_disabled_remote_read_route_is_404_before_dispatch(
    installed_owner_ingress, state,
) -> None:
    result = installed_owner_ingress.request("GET", "/api/v1/remote/status", route_state=state)
    assert result.status_code == 404
    assert result.body_read_count == 0
    assert result.core_uds_dispatch_count == 0
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/core/tests/integration/hardening/test_remote_read_only_api.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py -q && pnpm --filter @tuntun/admin test -- remote-access.test.tsx && pnpm --filter @tuntun/admin e2e -- tests/ui/phase6/remote-read-only.spec.ts tests/ui/phase6/remote-accessibility.spec.ts`
Expected: FAIL because the read-only route models/UI are absent.

- [ ] **Step 3: Implement bounded projections and truthful route/session UI**

~~~tsx
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

Render provider, exposed origin, pseudonymous approved nodes, allowed operation classes, last access, idle/absolute expiry, assurance age, route/posture evidence and local disable path. The generated client owns canonical request encoding; callers cannot pass pre-serialized JSON, and the cross-language golden corpus includes Unicode normalization, key order, UUIDs and all numeric edge cases accepted by the closed request schema. Safe alert/health/cost projections reuse server-filtered DTOs. Sensitive bodies are reveal-on-demand only where policy allows. Add English/Hindi strings, keyboard flow, VoiceOver labels/live states, light/dark/high-contrast/reduced-motion, 320 px and 200% zoom. No analytics/service worker/localStorage/sessionStorage/IndexedDB/private Cache API.

Register exactly `GET /api/v1/remote/status` and `GET /api/v1/remote/sessions` in Core `api/app.py`, supply their one service graph from `bootstrap/container.py`, and add the matching rows to the existing owner-ingress router and sole signed `ops/routes/owner-ingress-routes.v1.json`. Installed-candidate composition must derive reachability from that manifest: enabled rows dispatch once over the peer-authenticated Core UDS, while unknown, disabled, duplicate or unsigned rows are 404 before body read or UDS I/O. No decorator-only or test-only route counts as reachable.

- [ ] **Step 4: Run green, OpenAPI/client drift, UI, axe, and build checks**

Run: `uv run pytest apps/core/tests/integration/hardening/test_remote_read_only_api.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py -q && uv run python scripts/generate_openapi.py --check && pnpm --filter @tuntun/admin test -- remote-access.test.tsx && pnpm --filter @tuntun/admin e2e -- tests/ui/phase6/remote-read-only.spec.ts tests/ui/phase6/remote-accessibility.spec.ts && pnpm --filter @tuntun/admin typecheck && pnpm --filter @tuntun/admin build`
Expected: PASS; read-only safe data renders in English/Hindi at all fixtures, all local-only requests deny, and storage/cache scan is empty.

- [ ] **Step 5: Commit read-only API/UI**

~~~bash
git add apps/core/src/tuntun_core/api/phase6_dtos.py apps/core/src/tuntun_core/api/routes/remote_access.py apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json apps/admin/src/features/system/remote-access.tsx apps/admin/src/features/system/remote-sessions.tsx apps/admin/src/routes/system-remote-access.tsx apps/core/tests/integration/hardening/test_remote_read_only_api.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py apps/admin/src/features/system/remote-access.test.tsx tests/ui/phase6/remote-read-only.spec.ts tests/ui/phase6/remote-accessibility.spec.ts packages/ui-contracts schemas/openapi
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
    "grants_policy_drift", "tailnet_lock_failure", "stale_client", "certificate_failure",
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

def test_same_account_unapproved_node_and_revoked_node_fail_before_application_auth(real_tailnet_harness) -> None:
    assert real_tailnet_harness.probe_console_from("approved_node").network_reachable
    assert not real_tailnet_harness.probe_console_from("unapproved_same_account_node").network_reachable
    real_tailnet_harness.revoke("approved_node")
    assert not real_tailnet_harness.probe_console_from("approved_node").network_reachable
    assert real_tailnet_harness.application_auth_attempts_after_revocation == 0
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

The operator runs explicit bounded TCP/UDP/HTTP probes from all four vantage classes plus a second unapproved device under the same owner account, captures only target-class outcomes and commitments, reviews router mappings/UPnP/NAT-PMP/PCP, firewall/listeners/routes, canonical Tailscale `grants`/closed-tag-owner policy, Device Approval disabled state, Tailnet Lock/signed-node set/Serve/Funnel/subnet/exit/SSH state, authoritative DNS views/certificate origin and disable behavior. The test revokes an approved node and proves its exact network path disappears before application authentication. PCAPs remain owner-local and are scanned before deletion.

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
- Modify: `ops/services/phase3-owner-ingress.v1.json`
- Modify: `tests/integration/deploy/test_phase3_side_process_lifecycle.py`
- Modify: `tests/integration/deploy/test_owner_ingress_route_manifest.py`
- Modify: `tests/integration/phase6/test_owner_ingress_phase6_composition.py`

**Interfaces:** Produces `P6RemotePilotReceipt` bound to clean build/config/route/auth/network evidence, seven actual elapsed days, read-only requests, local availability, revoke/drift/failure injections, latency/resource/maintenance and privacy truth. The runner consumes Phase 2's canonical pre-issued `SignedFeatureManifestRolloverChainV1` through the existing rollover verifier and `FeatureAuthorityLease`; it neither signs nor renews authority. The receipt binds the chain ID, frozen candidate digest, complete ordered manifest-digest tuple, transition-receipt digests, pilot interval and zero expired-authority intervals. Every read admission and background sample checks the current wall expiry and monotonic lease; missing, stale, reordered, widened, rollback, signature-invalid, candidate-drifted or expired current/next authority closes work before preparation or I/O and permanently invalidates that pilot run.

**Rollback/disabled exit:** A failed pilot disables or suspends remote access; it never shortens the soak, enables actions, or weakens route/auth controls. Earlier local phases continue.

- [ ] **Step 1: Write red elapsed-time, zero-mutation, failure, and local-independence tests**

~~~python
def test_remote_pilot_requires_actual_seven_days(receipt) -> None:
    assert receipt.monotonic_elapsed_seconds >= 604_800
    assert receipt.wall_elapsed_seconds >= 604_800
    assert receipt.clock_acceleration_used is False

def test_remote_pilot_has_continuous_canonical_feature_authority(receipt) -> None:
    authority = receipt.feature_manifest_authority
    assert authority.rollover_chain_id
    assert authority.candidate_digest == receipt.candidate_digest
    assert authority.coverage_started_at <= receipt.started_at
    assert authority.coverage_ended_at >= receipt.ended_at
    assert authority.expired_authority_interval_count == 0
    assert len(authority.transition_receipt_digests) == len(authority.ordered_manifest_digests) - 1

def test_remote_pilot_manifest_rollover_faults_close_before_work(pilot) -> None:
    for fault in (
        "missing_next", "late_next", "reordered", "widened", "rollback",
        "signature_invalid", "candidate_drifted", "wall_expired", "monotonic_expired",
    ):
        outcome = pilot.inject_feature_manifest_authority_fault(fault)
        assert outcome.admission_closed_before_preparation_or_io
        assert outcome.background_work_closed_before_io
        assert outcome.campaign_invalid

def test_remote_pilot_has_zero_mutation_and_lateral_effect(pilot) -> None:
    assert pilot.remote_mutation_count == 0
    assert pilot.non_console_reachability_count == 0
    assert pilot.public_reachability_count == 0
    assert pilot.local_unavailability_caused_by_remote == 0

def test_fault_matrix_closes_remote_and_keeps_local(pilot) -> None:
    assert all(row.remote_closed for row in pilot.fault_rows)
    assert all(row.local_essentials_available for row in pilot.fault_rows)


def test_p6_1_owner_ingress_checkpoint_binds_current_wheel_and_routes(
    p6_1_owner_ingress_wheel, p6_1_route_manifest, inherited_owner_ingress_row,
    p6_1_owner_ingress_row, service_verifier,
) -> None:
    assert service_verifier.verify(
        inherited_owner_ingress_row, p6_1_owner_ingress_wheel, p6_1_route_manifest,
    ).denied
    assert service_verifier.verify(
        p6_1_owner_ingress_row, p6_1_owner_ingress_wheel, p6_1_route_manifest,
    ).accepted
    assert p6_1_owner_ingress_row.package_digest == p6_1_owner_ingress_wheel.digest
    assert p6_1_owner_ingress_row.route_manifest_digest == p6_1_route_manifest.digest


def test_p6_1_installed_owner_ingress_lifecycle_precedes_real_pilot(installed_candidate) -> None:
    assert installed_candidate.owner_ingress.all_signed_p6_1_routes_dispatch_once
    assert installed_candidate.owner_ingress.unknown_and_disabled_routes_are_404
    assert installed_candidate.owner_ingress.takeover_start_health_restart_update_rollback_pass
~~~

- [ ] **Step 2: Run red and synthetic mode**

Run: `uv run pytest tests/acceptance/phase6/test_remote_pilot_oracle.py tests/acceptance/phase6/test_p6_1_gate.py tests/fault/phase6/test_remote_pilot_faults.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/phase6/test_owner_ingress_phase6_composition.py -q`
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
    require(receipt.feature_manifest_authority.same_frozen_candidate)
    require(receipt.feature_manifest_authority.complete_ordered_chain)
    require(receipt.feature_manifest_authority.expired_authority_interval_count == 0)
    require(receipt.feature_manifest_authority.every_transition_receipt_current)
    require(receipt.private_data_scan_findings == 0)
    return GateDecision.accept("P6-1", receipt.digest())
~~~

Sample route/posture/session/listener/firewall/certificate/Tailnet/client/resource health, safe read requests, logout/expiry/revocation, Mac/router/client restart, WAN/DNS/IdP outage, drift, Privacy Shield, audit/backup state, and owner work. At runner startup, before each manifest transition, on every admission/background iteration, and at completion, invoke the canonical Phase 2 rollover/lease verifier against the same frozen-candidate commitment. Persist only content-safe checkpoints, ordered manifest/transition commitments and zero-gap timing evidence; restart cannot reset elapsed evidence, revive sessions, extend an expired lease or skip a required successor.

Before any real seven-day pilot, rebuild `tuntun-owner-ingress` from the completed Tasks 08/10–12 graph and refresh/re-sign the one canonical `phase3-owner-ingress.v1.json` row against that exact wheel and `ops/routes/owner-ingress-routes.v1.json` digest. The inherited pre-Phase-6 row/receipt must reject against this graph. Install that candidate and rerun listener→ingress→peer-authenticated Core/media UDS dispatch, unknown/disabled 404, takeover, start/health/restart and update/rollback. Only the resulting current lifecycle receipt may enter P6-1 evidence; the predecessor may be retained solely as a complete matching rollback set and is never current authority.

- [ ] **Step 4: Run synthetic fault acceptance and stage the real command**

Run: `uv build --offline --wheel --package tuntun-owner-ingress --out-dir var/build-smoke/phase6/owner-ingress-p6-1 && uv run pytest tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/phase6/test_owner_ingress_phase6_composition.py -q && uv run python scripts/phase6/run_remote_pilot.py --synthetic --duration-seconds 604800 --output var/evidence/phase6/remote-pilot-synthetic.json && uv run pytest tests/acceptance/phase6/test_remote_pilot_oracle.py tests/acceptance/phase6/test_p6_1_gate.py tests/fault/phase6/test_remote_pilot_faults.py -q && uv run ruff check scripts/phase6/run_remote_pilot.py tests/acceptance/phase6 tests/fault/phase6 tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy`
Expected: PASS for the deterministic synthetic time/fault oracle. Household P6-1 remains blocked until `TUNTUN_ALLOW_ELAPSED_PHASE6=1 uv run python scripts/phase6/run_remote_pilot.py --feature-manifest-chain var/evidence/phase6/p6-1-feature-authority/signed-rollover-chain.json --duration-seconds 604800 --output var/evidence/phase6/remote-pilot.json` consumes the externally pre-issued canonical chain and records real monotonic/wall time, all transition receipts and zero expired-authority interval.

- [ ] **Step 5: Commit pilot runner and gate**

~~~bash
git add scripts/phase6/run_remote_pilot.py docs/evidence/phase6-remote-pilot-schema.json tests/acceptance/phase6/test_remote_pilot_oracle.py tests/acceptance/phase6/test_p6_1_gate.py tests/fault/phase6/test_remote_pilot_faults.py ops/services/phase3-owner-ingress.v1.json tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/phase6/test_owner_ingress_phase6_composition.py
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
- Modify: `apps/core/src/tuntun_core/services/actions/executor.py`
- Create: `apps/core/src/tuntun_core/services/hardening/remote_private_detail.py`
- Create: `fixtures/synthetic/phase6/remote/scoped-actions-v1.json`
- Test: `tests/policy/test_remote_scoped_actions.py`
- Test: `tests/integration/phase6/test_remote_private_detail.py`
- Test: `tests/privacy/phase6/test_remote_private_detail_isolation.py`
- Test: `tests/integration/phase6/test_remote_reversible_action.py`
- Test: `tests/security/phase6/test_remote_action_substitution.py`
- Test: `tests/fault/phase6/test_remote_action_revocation_race.py`

**Interfaces:** Adds independently feature-bound `remote_private_detail_v1`, `remote_light_power_v1` and `remote_media_stop_v1` candidates. Private detail consumes only the current server-built `AuthorizedRemoteContextV1`, requires a fresh five-minute passkey, and returns for at most 60 seconds either the authenticated owner's own current `subject_private` record or an approval body already authorized to that owner. Owner-not-subject remains opaque/absent; listing, search, export, child/other-adult content and cross-object substitution remain absent. The external light operations are exactly `light_power_on` and `light_power_off`; the operation discriminator supplies the only desired-state intent, while the bounded opaque resource contains only `resource_type="light"` and a random local opaque ID. The server resolves that mapping under the authorized context and translates it to canonical Phase 2 `light.set_power.v1` with exact `on: bool`; no caller target, desired-state object, registry ID, binding, generation, or authority field exists. `media_stop` similarly carries only an opaque `media_player` reference. Each action uses the existing server-prepared action, fresh five-minute passkey, exact confirmation, current binding/capability/policy/controller epoch, idempotency and truthful downstream result. Local class enable/disable increments the operation-class generation, revokes existing remote sessions, and affects only newly passkey-authenticated sessions.

**Rollback/disabled exit:** Each class stays absent until locally enabled after its own evidence. Failure removes only that class and invalidates prepared actions; read-only remains. No generic home/media operation is introduced.

- [ ] **Step 1: Write red exact-class, local-enable, substitution, and race tests**

~~~python
@pytest.mark.parametrize("operation", ["light.toggle", "scene.run", "media.play", "media.seek", "volume.set"])
async def test_remote_reversible_registry_rejects_nonexact_operation(harness, operation) -> None:
    assert (await harness.remote_prepare(operation)).code in {"FEATURE_ABSENT", "REMOTE_OPERATION_DENIED"}

async def test_remote_stop_uses_fresh_passkey_and_exact_confirmation(harness) -> None:
    opaque_id = random_pseudonym()
    canonical_player_id = uuid4()
    await harness.bind_opaque_resource(
        resource_type="media_player", opaque_id=opaque_id,
        canonical_resource_id=canonical_player_id, ttl=timedelta(minutes=5),
    )
    request = RemoteOperationRequestV1(
        operation="media_stop", resource=opaque_resource("media_player", opaque_id),
        idempotency_key=uuid4(),
    )
    prepared = await harness.authorize_and_prepare_remote(request)
    assert (await harness.execute(prepared, assurance_age_seconds=301)).code == "ASSURANCE_INSUFFICIENT"
    result = await harness.confirm_and_execute(prepared, assurance_age_seconds=10)
    assert result.target_results[0].target_id == canonical_player_id
    assert opaque_id != str(canonical_player_id)

async def test_remote_light_reuses_canonical_phase2_power_shape(harness) -> None:
    request = RemoteOperationRequestV1(
        operation="light_power_off", resource=opaque_resource("light", random_pseudonym()),
        idempotency_key=uuid4(),
    )
    prepared = await harness.authorize_and_prepare_remote(request)
    assert prepared.local_action.action_type == "light.set_power.v1"
    assert prepared.local_action.desired_state == {"on": False}
    assert (await harness.post_remote_json({**request.model_dump(mode="json"), "desired_state": {"on": False}})).code == "SCHEMA_UNSUPPORTED"

@pytest.mark.parametrize(("operation", "expected_on"), [("light_power_on", True), ("light_power_off", False)])
async def test_light_intent_is_closed_operation_not_caller_parameter(harness, operation, expected_on) -> None:
    context = await harness.authorize_remote(RemoteOperationRequestV1(
        operation=operation, resource=opaque_resource("light", random_pseudonym()), idempotency_key=uuid4(),
    ))
    prepared = await harness.prepare_from_authorized_context(context)
    assert prepared.local_action.desired_state == {"on": expected_on}

@pytest.mark.parametrize("mutation", [
    "canonical_resource_id", "resource_generation", "binding_generation", "resolution_commitment",
    "expired_mapping", "replayed_prior_mapping",
])
async def test_opaque_mapping_substitution_expiry_or_replay_denies_before_action_lookup(harness, mutation) -> None:
    context = await harness.authorize_remote(valid_light_off_request())
    result = await harness.invoke_after_opaque_mapping_mutation(context, mutation)
    assert result.code in {"RESOURCE_NOT_FOUND", "STALE_GENERATION"}
    assert harness.action_registry_lookups == 0
    assert harness.downstream_dispatches == 0

async def test_private_detail_requires_exact_class_fresh_passkey_and_owner_audience(harness) -> None:
    request = await harness.prepare_private_detail("owner_memory_synth_01")
    assert (await harness.read_private_detail(request, assurance_age_seconds=301)).code == "ASSURANCE_INSUFFICIENT"
    projection = await harness.read_private_detail(request, assurance_age_seconds=10)
    assert projection.audience == "subject_private"
    assert projection.subject_id == harness.authenticated_owner_subject_id
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
    "light_power_on": RemoteRule(
        feature="remote_light_power_v1", local_action="light.set_power.v1",
        fixed_parameters={"on": True},
        expected_resource_type="light",
        require_fresh_passkey=timedelta(minutes=5), require_exact_confirmation=True,
    ),
    "light_power_off": RemoteRule(
        feature="remote_light_power_v1", local_action="light.set_power.v1",
        fixed_parameters={"on": False},
        expected_resource_type="light",
        require_fresh_passkey=timedelta(minutes=5), require_exact_confirmation=True,
    ),
    "media_stop": RemoteRule(
        feature="remote_media_stop_v1", local_action="media.stop.v1",
        fixed_parameters={}, expected_resource_type="media_player",
        require_fresh_passkey=timedelta(minutes=5), require_exact_confirmation=True,
    ),
}

async def execute_remote(prepared, confirmation, context: AuthorizedRemoteContextV1):
    await remote_policy.require_current_exact(prepared, confirmation, context)
    return await ordinary_action_coordinator.execute(prepared, confirmation, origin="remote_origin_v1")

async def read_private_detail(context: AuthorizedRemoteContextV1) -> RemotePrivateDetailProjectionV1:
    await remote_policy.require_current_exact_class(context, "private_detail", fresh_passkey=timedelta(minutes=5))
    source = await private_detail_store.require_exact_authenticated_subject_private_object(
        owner_subject_id=context.authenticated_owner_subject_id,
        resource=context.resource,
        policy_version=context.policy_version,
    )
    return RemotePrivateDetailProjectionV1.from_ephemeral_source(context, source, max_lifetime=timedelta(seconds=60))
~~~

Local enablement binds one operation class, exact eligible endpoint set, current policy/binding/capability generations, evidence digest and expiry with a local owner action-bound passkey. Remote cannot change that set. Test stale topology, child/Guest/time/room/privacy denial, replay, duplicate mismatch, unknown physical result, downstream outage and manual fallback.

- [ ] **Step 4: Run green and affected Phase 2/4 action suites**

Run: `uv run pytest tests/policy/test_remote_scoped_actions.py tests/integration/phase6/test_remote_private_detail.py tests/privacy/phase6/test_remote_private_detail_isolation.py tests/integration/phase6/test_remote_reversible_action.py tests/security/phase6/test_remote_action_substitution.py tests/fault/phase6/test_remote_action_revocation_race.py tests/integration/home_actions tests/integration/media_actions -q && uv run ruff check apps/core/src/tuntun_core/services/hardening/remote_policy.py apps/core/src/tuntun_core/services/hardening/remote_private_detail.py apps/core/src/tuntun_core/services/actions/executor.py tests/policy tests/integration/phase6 tests/privacy/phase6 tests/security/phase6 tests/fault/phase6 && uv run mypy apps/core/src`
Expected: PASS; private detail is one exact owner-only projection, only locally enabled exact action classes dispatch, and no remote request upgrades ordinary policy.

- [ ] **Step 5: Commit optional scoped actions**

~~~bash
git add apps/core/src/tuntun_core/services/hardening/remote_policy.py apps/core/src/tuntun_core/services/hardening/remote_sessions.py apps/core/src/tuntun_core/services/hardening/remote_private_detail.py apps/core/src/tuntun_core/services/actions/executor.py fixtures/synthetic/phase6/remote/scoped-actions-v1.json tests/policy/test_remote_scoped_actions.py tests/integration/phase6/test_remote_private_detail.py tests/privacy/phase6/test_remote_private_detail_isolation.py tests/integration/phase6/test_remote_reversible_action.py tests/security/phase6/test_remote_action_substitution.py tests/fault/phase6/test_remote_action_revocation_race.py
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
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Test: `apps/core/tests/unit/hardening/test_remote_media_session.py`
- Test: `tests/integration/phase6/test_remote_camera_metadata.py`
- Test: `tests/integration/phase6/test_remote_camera_playback.py`
- Test: `tests/contract/hardening/test_remote_phase3_playback_seam.py`
- Test: `tests/security/phase6/test_remote_media_isolation.py`
- Test: `tests/fault/phase6/test_remote_media_revocation.py`
- Modify: `tests/integration/phase6/test_owner_ingress_phase6_composition.py`
- Modify: `tests/integration/deploy/test_owner_ingress_route_manifest.py`

**Interfaces:** Adds separately registered `remote_camera_metadata_v1` and `remote_camera_playback_v1`; produces `RemoteSingleClipMediaSessionV1` for one owner/session and one canonical Phase 3 event-clip subject up to 10 minutes, and delegates every exact inclusive byte range to a new single-use Phase 3 playback grant up to 60 seconds.

**Rollback/disabled exit:** Metadata/playback are absent independently. Any route/privacy/passkey/policy/clip/generation/retention/catalog/recorder uncertainty revokes both layers; export/download remains denied.

- [ ] **Step 1: Write red duration, range, enumeration, credential, cache, and revoke tests**

~~~python
def test_remote_media_session_is_one_clip_and_at_most_ten_minutes(session) -> None:
    assert session.subject.kind == "event_clip"
    assert session.expires_at - session.issued_at <= timedelta(minutes=10)

async def test_every_range_consumes_fresh_phase3_grant(harness) -> None:
    media_session = await harness.open_remote_media("clip_synth_01")
    first = await harness.read_range(media_session, 0, 4095)
    assert harness.phase3_request_verifier.exact_hmac_valid(
        domain="tuntun.playback-range-request.v1",
        canonical_bytes=canonical_playback_range_request_unsigned_bytes(first.request),
        supplied_commitment=first.request.request_commitment,
        actor=first.phase3_actor,
    )
    assert first.phase3_grant.grant.single_use
    assert first.phase3_grant.grant.expires_at - first.phase3_grant.grant.issued_at <= timedelta(seconds=60)
    assert first.phase3_grant.algorithm == "Ed25519"
    assert (await harness.reuse(first.phase3_grant)).status_code == 403

@pytest.mark.parametrize("earliest_expiry", ["remote_media_session", "authorized_context", "five_second_request_cap"])
async def test_range_request_and_grant_never_outlive_outer_authority(harness, earliest_expiry) -> None:
    media_session, context = await harness.open_remote_media_near_expiry(earliest_expiry)
    result = await harness.read_range(media_session, 0, 4095, context=context)
    expected = min(media_session.expires_at, context.valid_until, result.request.issued_at + timedelta(seconds=5))
    assert result.request.expires_at == expected
    assert result.phase3_grant.grant.expires_at <= expected

async def test_exhausted_outer_playback_window_denies_before_phase3_io(harness) -> None:
    media_session, context = await harness.open_remote_media_near_expiry("authorized_context")
    harness.clock.advance_to(context.valid_until)
    result = await harness.read_range(media_session, 0, 4095, context=context)
    assert result.code in {"STALE_GENERATION", "ASSURANCE_INSUFFICIENT"}
    assert harness.phase3_prepare_calls == ()
    assert harness.phase3_proxy_calls == ()

async def test_remote_media_cannot_enumerate_or_export(harness) -> None:
    assert (await harness.read_other_clip()).status_code == 403
    assert (await harness.export_clip()).json()["code"] == "REMOTE_OPERATION_DENIED"
    assert not harness.responses.contain_any("rtsp://", "onvif", "camera_password", "storage_path")

def test_remote_range_builder_compiles_against_canonical_phase3_contract(harness) -> None:
    request = harness.build_remote_range_request(start=0, end_inclusive=4095)
    assert set(PlaybackRangeRequestV1.model_fields) == {
        "schema_id", "request_id", "subject", "byte_range", "expected_catalog_generation",
        "expected_privacy_generation", "issued_at", "expires_at", "request_commitment",
    }
    assert isinstance(request.subject, ClipPlaybackSubjectV1)
    assert isinstance(request.byte_range, InclusiveByteRangeV1)
    assert PlaybackRangeRequestV1.model_validate(request.model_dump()) == request

@pytest.mark.parametrize("field", [
    "kind", "clip_id", "clip_generation", "catalog_generation", "view",
])
async def test_one_field_clip_subject_substitution_denies_before_phase3_io(harness, field) -> None:
    media_session = await harness.open_remote_media("clip_synth_01")
    substituted = mutate_one_subject_field(media_session.subject, field)
    result = await harness.read_range_with_substituted_subject(media_session, substituted, 0, 4095)
    assert result.code in {"SCHEMA_UNSUPPORTED", "STALE_GENERATION", "RESOURCE_NOT_FOUND", "PRIVACY_BLOCKED"}
    assert harness.phase3_prepare_calls == ()
    assert harness.phase3_proxy_calls == ()

@pytest.mark.parametrize("method,path", [
    ("GET", "/api/v1/cameras/remote/metadata"),
    ("POST", "/api/v1/cameras/remote/playback/session"),
    ("GET", "/api/v1/cameras/remote/playback/session_synth_01"),
])
def test_installed_remote_camera_routes_dispatch_once_from_signed_manifest(
    installed_owner_ingress, method, path,
) -> None:
    result = installed_owner_ingress.request(method, path, feature_enabled=True)
    assert result.status_code in {200, 201, 206}
    assert result.peer_authenticated_uds_dispatch_count == 1


@pytest.mark.parametrize("state", ["unknown", "disabled"])
def test_unknown_or_disabled_remote_camera_route_is_404_before_dispatch(
    installed_owner_ingress, state,
) -> None:
    result = installed_owner_ingress.request(
        "GET", "/api/v1/cameras/remote/metadata", route_state=state,
    )
    assert result.status_code == 404
    assert result.body_read_count == 0
    assert result.peer_authenticated_uds_dispatch_count == 0
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/core/tests/unit/hardening/test_remote_media_session.py tests/integration/phase6/test_remote_camera_metadata.py tests/integration/phase6/test_remote_camera_playback.py tests/contract/hardening/test_remote_phase3_playback_seam.py tests/security/phase6/test_remote_media_isolation.py tests/fault/phase6/test_remote_media_revocation.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py -q`
Expected: FAIL because remote camera/media classes and session broker are absent.

- [ ] **Step 3: Implement the exact two-layer broker and metadata projection**

~~~python
async def open_single_clip(self, request, context) -> RemoteSingleClipMediaSessionV1:
    await self._policy.require_remote_camera_playback(context, fresh_passkey=timedelta(minutes=5))
    resource = require_resolved_resource(context.resource, expected_type="camera_clip")
    clip = await self._vision.require_owner_playable_clip(
        clip_id=resource.canonical_resource_id,
        owner_subject_id=context.authenticated_owner_subject_id,
        expected_clip_generation=resource.resource_generation,
        expected_binding_generation=resource.binding_generation,
    )
    subject = clip.require_event_clip_playback_subject_from_current_opaque_mapping()
    now = self._clock.now()
    return await self._sessions.create(
        media_session_id=uuid4(),
        owner_subject_id=context.authenticated_owner_subject_id,
        remote_session_id=context.application_session_id,
        subject=subject,
        issued_at=now, expires_at=min(now + timedelta(minutes=10), clip.immutable_expires_at),
        route_generation=context.route_generation,
        remote_session_revocation_generation=context.application_revocation_generation,
        operation_class_generation=context.operation_class_generation,
        privacy_generation=context.privacy_generation,
        session_commitment=self._commitments.for_remote_media_session(context, subject),
    )

async def read_range(
    self, media_session: RemoteSingleClipMediaSessionV1,
    byte_range: InclusiveByteRangeV1, context: AuthorizedRemoteContextV1,
):
    current = await self._sessions.consume_range_authority(media_session, context)
    now = self._clock.now()
    expires_at = min(now + timedelta(seconds=5), current.expires_at, context.valid_until)
    if now >= expires_at:
        raise RemoteMediaDenied("remote_media_outer_authority_expired")
    # Phase 3 verifies the canonical request excluding only request_commitment. Build one
    # immutable field map so the generated ID and exact timestamps cannot drift from the HMAC.
    request_fields = {
        "schema_id": "playback_range_request.v1",
        "request_id": uuid4(),
        "subject": current.subject,
        "byte_range": byte_range,
        "expected_catalog_generation": current.subject.catalog_generation,
        "expected_privacy_generation": current.privacy_generation,
        "issued_at": now,
        "expires_at": expires_at,
    }
    request = PlaybackRangeRequestV1(
        **request_fields,
        request_commitment=self._commitments.hmac_canonical_fields(
            domain="tuntun.playback-range-request.v1", fields=request_fields,
        ),
    )
    signed_grant = await self._phase3.prepare_range(request, context.phase3_actor_context())
    if signed_grant.grant.expires_at > expires_at:
        raise RemoteMediaDenied("phase3_grant_outlives_remote_authority")
    return await self._phase3.proxy_once(signed_grant, cache_control="no-store")
~~~

Metadata contains safe area/zone display label, native class, local time, verification and clip availability only—no thumbnail, identity, address, credential or URL. The seam uses the canonical Phase 3 `prepare_range(PlaybackRangeRequestV1, ActorContext)` method and passes the complete `SignedMediaPlaybackGrantV1`; the Phase 3 proxy verifies the envelope before consulting the inner grant. The Phase 6 builder creates one immutable field map containing the generated request ID, exact subject/range/generations and timestamps, then computes the domain-separated HMAC over the same canonical representation that Phase 3 verifies after excluding only `request_commitment`; an exact recomputation contract test prevents builder/verifier drift. Each range request expires at the earliest of five seconds, the outer remote-media-session expiry and the current authorized-context expiry, and the returned Phase 3 grant may not outlive that intersection. An exhausted window or overlong inner grant is rejected before proxy I/O. Recheck retention and all route/session/operation-class/passkey/camera/zone/privacy/catalog generations per range. Enabling or disabling either camera class increments the session operation-class generation and revokes old sessions; newly authenticated sessions receive only the exact locally enabled classes. Revoke media on logout, expiry, disable, route suspension, Privacy Shield, clip deletion/expiry, recorder/catalog uncertainty, and policy change.

Register only `GET /api/v1/cameras/remote/metadata`, `POST /api/v1/cameras/remote/playback/session`, and `GET /api/v1/cameras/remote/playback/{session_id}` through the canonical Core app/container, owner-ingress router and signed route manifest. Each row names its exact Core or media UDS target and feature flag; no generic camera prefix, export or download row exists. Installed composition proves each enabled template dispatches exactly once, and unknown, disabled, duplicate or unsigned rows are 404 before body read or UDS I/O.

- [ ] **Step 4: Run green with Phase 3 playback regressions and browser scans**

Run: `uv run pytest apps/core/tests/unit/hardening/test_remote_media_session.py tests/integration/phase6/test_remote_camera_metadata.py tests/integration/phase6/test_remote_camera_playback.py tests/contract/hardening/test_remote_phase3_playback_seam.py tests/security/phase6/test_remote_media_isolation.py tests/fault/phase6/test_remote_media_revocation.py tests/integration/vision/test_media_proxy.py tests/security/vision/test_playback_grants.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py -q && uv run python scripts/scan_browser_artifacts.py --forbid camera_credentials,media_urls,storage_paths,persistent_grants && uv run ruff check apps/core/src/tuntun_core/services/hardening/remote_media.py apps/core/src/tuntun_core/services/vision/playback_broker.py tests/contract/hardening/test_remote_phase3_playback_seam.py tests/integration/phase6 tests/integration/deploy/test_owner_ingress_route_manifest.py tests/security/phase6 tests/fault/phase6 && uv run mypy apps/core/src`
Expected: PASS; every range has a distinct ≤60-second grant, media session is ≤10 minutes/one clip, and no credential/path/export route exists.

- [ ] **Step 5: Commit optional remote camera scopes**

~~~bash
git add apps/core/src/tuntun_core/services/vision/playback_broker.py apps/core/src/tuntun_core/services/hardening/remote_policy.py apps/core/src/tuntun_core/services/hardening/remote_sessions.py apps/core/src/tuntun_core/services/hardening/remote_media.py apps/core/src/tuntun_core/api/routes/cameras.py apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json apps/core/tests/unit/hardening/test_remote_media_session.py tests/integration/phase6/test_remote_camera_metadata.py tests/integration/phase6/test_remote_camera_playback.py tests/contract/hardening/test_remote_phase3_playback_seam.py tests/security/phase6/test_remote_media_isolation.py tests/fault/phase6/test_remote_media_revocation.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py
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
- Modify: `ops/services/phase3-owner-ingress.v1.json`
- Modify: `tests/integration/deploy/test_phase3_side_process_lifecycle.py`
- Modify: `tests/integration/deploy/test_owner_ingress_route_manifest.py`
- Modify: `tests/integration/phase6/test_owner_ingress_phase6_composition.py`

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

~~~python
def test_p6_2_owner_ingress_checkpoint_rejects_p6_1_row_and_binds_optional_graph(
    p6_2_owner_ingress_wheel, p6_2_route_manifest, p6_1_owner_ingress_row,
    p6_2_owner_ingress_row, service_verifier,
) -> None:
    assert service_verifier.verify(
        p6_1_owner_ingress_row, p6_2_owner_ingress_wheel, p6_2_route_manifest,
    ).denied
    assert service_verifier.verify(
        p6_2_owner_ingress_row, p6_2_owner_ingress_wheel, p6_2_route_manifest,
    ).accepted
    assert p6_2_owner_ingress_row.package_digest == p6_2_owner_ingress_wheel.digest
    assert p6_2_owner_ingress_row.route_manifest_digest == p6_2_route_manifest.digest


def test_p6_2_installed_graph_matches_enabled_and_absent_scope_receipt(installed_candidate) -> None:
    assert installed_candidate.owner_ingress.routes_match_optional_scope_receipt_exactly
    assert installed_candidate.owner_ingress.all_enabled_routes_dispatch_once
    assert installed_candidate.owner_ingress.absent_unknown_and_disabled_routes_are_404
    assert installed_candidate.owner_ingress.takeover_start_health_restart_update_rollback_pass
~~~

- [ ] **Step 2: Run red**

Run: `pnpm --filter @tuntun/admin test -- remote-scopes.test.tsx && pnpm --filter @tuntun/admin e2e -- tests/ui/phase6/remote-scopes.spec.ts && uv run pytest tests/security/phase6/test_remote_scope_absence.py tests/acceptance/phase6/test_p6_2_gate.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/phase6/test_owner_ingress_phase6_composition.py -q`
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

After Task 17 fixes the exact optional camera route templates and the enabled/absent scope receipt is known, rebuild `tuntun-owner-ingress` and refresh/re-sign the same canonical `phase3-owner-ingress.v1.json` row against that wheel and route-manifest digest. The P6-1 checkpoint row/receipt must reject against the P6-2 graph even when a scope is absent; absence is represented by the signed feature/route state, never by silently reusing stale package authority. Install the new row and rerun the complete enabled dispatch, negative absent/unknown/disabled reachability, takeover, start/health/restart and update/rollback lifecycle. Preserve the P6-1 checkpoint only as a complete matching rollback set.

- [ ] **Step 4: Run green, absence scan, accessibility, and gate verification**

Run: `uv build --offline --wheel --package tuntun-owner-ingress --out-dir var/build-smoke/phase6/owner-ingress-p6-2 && pnpm --filter @tuntun/admin test -- remote-scopes.test.tsx && pnpm --filter @tuntun/admin e2e -- tests/ui/phase6/remote-scopes.spec.ts && uv run pytest tests/security/phase6/test_remote_scope_absence.py tests/acceptance/phase6/test_p6_2_gate.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/phase6/test_owner_ingress_phase6_composition.py -q && uv run python scripts/phase6/verify_p6_2.py --synthetic fixtures/synthetic/phase6/remote/scoped-actions-v1.json --output var/evidence/phase6/p6-2-synthetic.json && pnpm --filter @tuntun/admin typecheck && pnpm --filter @tuntun/admin build`
Expected: PASS; receipt declares every class enabled-with-four-gates or negatively absent, and remote has no enablement route.

- [ ] **Step 5: Commit optional-scope UI and gate**

~~~bash
git add apps/admin/src/features/system/remote-access.tsx apps/admin/src/features/system/remote-scopes.tsx scripts/phase6/verify_p6_2.py docs/evidence/phase6-optional-scopes-schema.json apps/admin/src/features/system/remote-scopes.test.tsx tests/ui/phase6/remote-scopes.spec.ts tests/security/phase6/test_remote_scope_absence.py tests/acceptance/phase6/test_p6_2_gate.py ops/services/phase3-owner-ingress.v1.json tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/phase6/test_owner_ingress_phase6_composition.py
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
- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Create: `packages/plugin-sdk/pyproject.toml`
- Create: `packages/plugin-sdk/src/tuntun_plugin_sdk/__init__.py`
- Create: `packages/plugin-sdk/src/tuntun_plugin_sdk/protocol.py`
- Create: `packages/plugin-sdk/src/tuntun_plugin_sdk/health_render.py`
- Create: `packages/plugin-sdk/src/tuntun_plugin_sdk/local_alert_render.py`
- Create: `ops/plugins/phase6.initial.1.registry.json`
- Create: `ops/plugins/phase6.initial.1.registry.sig`
- Create: `ops/plugins/trusted-registry-signers.json`
- Create: `ops/plugins/sign_registry.py`
- Create: `ops/plugins/verify_registry.py`
- Test: `packages/plugin-sdk/tests/test_public_sdk.py`
- Test: `tests/contract/plugins/test_initial_registry.py`
- Test: `tests/security/plugins/test_unknown_capability_denial.py`
- Test: `tests/privacy/plugins/test_sdk_surface.py`
- Modify: `tests/unit/test_package_smoke.py`

**Interfaces:** Produces the signed platform registry, detached signature, public signer allowlist, explicit offline signing command, and the four dedicated metadata-free child input/output DTOs for exactly `system.health.render.v1` and `notification.local_alert.render.v1`. `sign_registry.py --registry PATH --output PATH --signer-id ID` requires the explicit `TUNTUN_ALLOW_PLUGIN_REGISTRY_SIGNING=1` local-maintainer ceremony, reads the private signing handle only from the OS credential provider, signs exact already-canonical bytes under the single frozen domain `tuntun.plugin-capability-registry.v1`, creates the signature with nofollow/exclusive owner-only semantics, and never exports a private key. `verify_registry.py --registry PATH --signature PATH --trusted-signers PATH` verifies independent bounds, pinned registry digest, that exact domain, signer allowlist, current key generation, signature, and expiry before returning either the complete two-capability registry or blocked. The production loader receives only registry and signature paths; its trusted-signer allowlist and pinned registry digest are immutable application configuration, never caller-selected paths. Trusted snapshot/alert envelopes and supervisor result envelopes are not SDK exports and never cross child stdin/stdout. SDK contains no core import, canonical entity, transport/network helper, persistence API, policy field, action, tool, or generic payload.

**Rollback/disabled exit:** Registry/schema/signature drift blocks all third-party plugin installation and P6-3; no household override or developer-mode exception exists.

- [ ] **Step 1: Write red exact-ID, policy-ownership, and SDK-reachability tests**

~~~python
from pathlib import Path

import pytest
import tuntun_plugin_sdk

def test_initial_registry_has_exactly_two_ids(registry) -> None:
    assert tuple(entry.capability_id for entry in registry.capabilities) == (
        "system.health.render.v1",
        "notification.local_alert.render.v1",
    )

def test_checked_in_registry_and_detached_signature_verify_as_one_input(
    production_registry_loader,
) -> None:
    loaded=production_registry_loader.load(
        Path("ops/plugins/phase6.initial.1.registry.json"),
        Path("ops/plugins/phase6.initial.1.registry.sig"),
    )
    assert loaded.state=="available"
    assert tuple(item.capability_id for item in loaded.capabilities)==(
        "system.health.render.v1","notification.local_alert.render.v1",
    )

def test_registry_not_manifest_owns_every_policy_dimension(registry) -> None:
    for capability in registry.capabilities:
        assert set(capability.policy.model_fields) == {
            "actor_invocation", "consent_guardian", "sensitivity", "retention_storage",
            "egress_dns_redirects", "revocation_cleanup", "resources",
        }

@pytest.mark.parametrize("fault", [
    "invalid_utf8", "duplicate_key", "noncanonical_json", "nonfinite_number",
    "decimal_over_64_digits", "depth_33", "container_4097", "structure_token_16385",
    "oversize_registry", "oversize_signature", "wrong_signature", "expired", "capability_reordered",
    "attacker_selected_signer_identity", "policy_widened", "unknown_field",
    "missing_file", "permission_denied", "symlink", "non_regular", "wrong_owner",
    "group_or_other_writable", "link_count_two", "short_read", "growth_during_read",
    "replacement_during_read",
])
def test_registry_raw_fault_blocks_every_capability_without_child_launch(
    registry_loader, signed_registry, fault,
) -> None:
    registry_path, signature_path = signed_registry.materialize_fault(fault)
    result = registry_loader.load(registry_path, signature_path)
    assert result.state == "blocked"
    assert result.capabilities == ()
    assert registry_loader.child_launches == 0

def test_registry_programmer_fault_is_not_hidden_as_blocked(registry_loader, signed_registry) -> None:
    registry_loader.signatures.raise_unexpected(RuntimeError("programmer fault"))
    with pytest.raises(RuntimeError, match="programmer fault"):
        registry_loader.load(signed_registry.registry_path, signed_registry.signature_path)

def test_sdk_exports_no_generic_or_authoritative_type() -> None:
    assert set(tuntun_plugin_sdk.__all__) == {
        "PluginHealthChildInputV1", "PluginHealthChildOutputV1",
        "PluginAlertChildInputV1", "PluginAlertChildOutputV1", "serve_one_request",
    }

@pytest.mark.parametrize("fault", [
    "duplicate_key", "noncanonical_json", "depth_33", "container_4097", "oversize_wire",
])
def test_sdk_child_ingress_is_bounded_duplicate_safe_and_canonical(sdk_runner, fault) -> None:
    with pytest.raises((ValueError, ValidationError)):
        sdk_runner.serve_fault(fault)
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest packages/plugin-sdk/tests tests/contract/plugins/test_initial_registry.py tests/security/plugins/test_unknown_capability_denial.py tests/privacy/plugins/test_sdk_surface.py -q`
Expected: FAIL because the SDK and signed registry are absent.

- [ ] **Step 3: Implement fixed codecs and a platform-owned immutable registry**

Register `packages/plugin-sdk` in the root `[tool.uv.workspace].members` list in the same change, update `uv.lock`, add `tuntun_plugin_sdk` to the shared package-smoke parametrization, and give the SDK an independently buildable package definition:

~~~toml
# packages/plugin-sdk/pyproject.toml
[project]
name = "tuntun-plugin-sdk"
version = "0.1.0.dev0"
requires-python = "==3.12.*"
dependencies = ["tuntun-contracts"]

[tool.uv.sources]
tuntun-contracts = { workspace = true }

[build-system]
requires = ["hatchling>=1.27,<2"]
build-backend = "hatchling.build"
~~~

The public `__init__.py` exposes `__version__ = "0.1.0.dev0"` in addition to the exact capability DTO/runner `__all__`; the version symbol is package metadata, not an additional plugin capability. The smoke test must prove the SDK resolves from the locked workspace rather than an ambient installation.

~~~python
from tuntun_contracts.base import ContractParseError, parse_contract_json

class PluginRegistryUnavailable(Exception): ...
class PluginRegistrySignatureInvalid(PluginRegistryUnavailable): ...
class PluginRegistryReadDenied(PluginRegistryUnavailable): ...
class DetachedSignatureVerificationFailed(Exception): ...

CAPABILITY_CODECS: Final = MappingProxyType({
    "system.health.render.v1": CodecPair(PluginHealthChildInputV1, PluginHealthChildOutputV1),
    "notification.local_alert.render.v1": CodecPair(PluginAlertChildInputV1, PluginAlertChildOutputV1),
})

def require_verified_registry(
    raw_registry: bytes,
    detached_signature: bytes,
    *,
    expected_digest: Sha256Digest,
    signatures: PluginRegistrySignatureVerifier,
    now: datetime,
) -> VerifiedPluginRegistry:
    if not hmac.compare_digest(sha256(raw_registry).hexdigest(), expected_digest):
        raise PluginRegistryUnavailable("plugin_registry_digest_mismatch")
    try:
        verified_signer_identity = signatures.verify_current_detached_signature_from_allowlist(
            signature=detached_signature,
            domain="tuntun.plugin-capability-registry.v1",
            payload=raw_registry,
        )
    except DetachedSignatureVerificationFailed as error:
        raise PluginRegistrySignatureInvalid from error
    registry = parse_contract_json(
        PluginCapabilityRegistryV1,
        raw_registry,
        max_bytes=64 * 1024,
        require_canonical=True,
    )
    if not registry.issued_at <= now < registry.expires_at:
        raise PluginRegistryUnavailable("plugin_registry_not_current")
    if registry.signer_identity != verified_signer_identity:
        raise PluginRegistryUnavailable("plugin_registry_signer_identity_mismatch")
    if canonical_hardening_bytes(registry) != raw_registry:
        raise PluginRegistryUnavailable("plugin_registry_encoder_drift")
    return VerifiedPluginRegistry.from_frozen_contract(registry, expected_digest)

def load(self, registry_path: Path, signature_path: Path) -> PluginRegistryLoadResult:
    try:
        raw_registry = read_regular_nofollow_bounded(
            registry_path, max_bytes=64 * 1024, max_buffer_bytes=64 * 1024 + 1,
            expected_owner_uid=os.geteuid(), required_mode=0o600, require_nlink=1,
            expected_error=PluginRegistryReadDenied,
        )
        detached_signature = read_regular_nofollow_bounded(
            signature_path, max_bytes=16 * 1024, max_buffer_bytes=16 * 1024 + 1,
            expected_owner_uid=os.geteuid(), required_mode=0o600, require_nlink=1,
            expected_error=PluginRegistryReadDenied,
        )
        verified = require_verified_registry(
            raw_registry,
            detached_signature,
            expected_digest=self._pinned_registry_digest,
            signatures=self._signatures,
            now=self._clock.now(),
        )
    except (ContractParseError, PluginRegistryUnavailable):
        return PluginRegistryLoadResult.blocked(capabilities=())
    return PluginRegistryLoadResult.available(verified)

class _PluginSdkWireLimitExceeded(Exception): ...

def serve_one_request(
    stdin: BinaryIO, stdout: BinaryIO, renderer: Renderer, *, selected_codec: CodecPair,
) -> None:
    # selected_codec is prebound by the supervisor-owned registry/entrypoint; it is never read from stdin.
    raw_request = read_bounded(
        stdin, max_bytes=64 * 1024, max_buffer_bytes=64 * 1024 + 1,
        timeout=timedelta(seconds=1),
    )
    request = parse_contract_json(
        selected_codec.request,
        raw_request,
        max_bytes=64 * 1024,
        require_canonical=True,
    )
    response = selected_codec.response.model_validate(renderer.render(request))
    raw_response = canonical_hardening_bytes(response)
    if len(raw_request) + len(raw_response) > 64 * 1024:
        raise _PluginSdkWireLimitExceeded("plugin_child_combined_wire_limit")
    write_bounded(stdout, raw_response, 64 * 1024)
~~~

Each signed plugin artifact requests exactly one of the two registry capabilities; a two-capability artifact or one entrypoint with ambiguous codecs is schema-invalid. `selected_codec` is therefore the supervisor-selected, capability-specific SDK codec object prebound in the platform-owned fresh-process bootstrap for that one verified artifact/capability pair; no capability ID, codec name, registry value, request ID, purpose, time, generation, grant, or commitment is serialized in stdin/stdout, environment, argv or a child-selected filename. Registry fixes the distinct owner invocation/consent rules, exact attention/alert enums, no subjects/devices/networks/cost/content/history/stable IDs, no plugin queue or retained text, content-minimized 180-day receipt, five-second/fresh-process/no-write policy, zero network/DNS/redirect, one concurrency, 128 MiB/50%-CPU/64-KiB bounds, generation cleanup and mandatory-core-alert independence. The task cannot turn green until the exact checked-in registry has a separately generated detached signature from one current allowlisted public signer; a synthetic fixture signature cannot satisfy the production positive test.

`registry_loader.load(...)` is a total startup/admission wrapper around `require_verified_registry`: it normalizes only expected read, bounded-parse, validation, digest, expiry and signature failures to a closed `blocked` result with an empty capability tuple. Registry and detached signature are separate owner-only nofollow regular files with independent max-plus-one ceilings of 64 KiB and 16 KiB. It never returns a partially parsed registry, never falls back to manifest policy, and starts no plugin child. Cancellation and programmer errors remain visible. The detached signature covers the exact already-canonical bounded bytes; the pinned digest and shared canonicalizer equality are checked before any registry field authorizes installation or invocation.

The shared `read_regular_nofollow_bounded(..., expected_error=PluginRegistryReadDenied)` protocol opens each ancestor and leaf by descriptor with no-follow semantics, requires a regular owner-only `nlink=1` file, snapshots device/inode/size/mode/owner before reading, performs a max-plus-one offset-independent read, rejects short read/growth/replacement and rechecks the same identity afterward. It translates only its documented open/stat/read/close `OSError` and those file-integrity violations into `PluginRegistryReadDenied`; allocation/programmer/cancellation failures remain visible. Direct tests above exercise every translation, including oversize, rather than relying on an undefined generic size exception.

- [ ] **Step 4: Run green, build wheel, inspect exports/dependencies, and verify registry signature**

Run: `uv lock && uv sync --all-packages && uv run pytest tests/unit/test_package_smoke.py packages/plugin-sdk/tests tests/contract/plugins/test_initial_registry.py tests/security/plugins/test_unknown_capability_denial.py tests/privacy/plugins/test_sdk_surface.py -q && uv build packages/plugin-sdk && uv run python scripts/check_public_api.py packages/plugin-sdk --expected fixtures/synthetic/phase6/plugins/sdk-api-v1.json && uv run python ops/plugins/verify_registry.py --registry ops/plugins/phase6.initial.1.registry.json --signature ops/plugins/phase6.initial.1.registry.sig --trusted-signers ops/plugins/trusted-registry-signers.json && uv run ruff check packages/plugin-sdk ops/plugins/sign_registry.py ops/plugins/verify_registry.py tests/unit/test_package_smoke.py tests/contract/plugins tests/security/plugins tests/privacy/plugins && uv run mypy packages/plugin-sdk/src`
Expected: PASS; the locked workspace imports the SDK, its wheel exports only four DTOs/one bounded runner, and the registry verifier reports the exact two IDs.

- [ ] **Step 5: Commit registry and SDK**

~~~bash
git add pyproject.toml uv.lock packages/plugin-sdk ops/plugins/phase6.initial.1.registry.json ops/plugins/phase6.initial.1.registry.sig ops/plugins/trusted-registry-signers.json ops/plugins/sign_registry.py ops/plugins/verify_registry.py tests/unit/test_package_smoke.py tests/contract/plugins/test_initial_registry.py tests/security/plugins/test_unknown_capability_denial.py tests/privacy/plugins/test_sdk_surface.py fixtures/synthetic/phase6/plugins/sdk-api-v1.json
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
- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Create: `apps/plugin-supervisor/pyproject.toml`
- Create: `apps/plugin-supervisor/src/tuntun_plugin_supervisor/__init__.py`
- Create: `apps/plugin-supervisor/src/tuntun_plugin_supervisor/main.py`
- Create: `apps/plugin-supervisor/src/tuntun_plugin_supervisor/server.py`
- Create: `apps/plugin-supervisor/src/tuntun_plugin_supervisor/verifier.py`
- Create: `apps/plugin-supervisor/src/tuntun_plugin_supervisor/registry.py`
- Create: `apps/plugin-supervisor/src/tuntun_plugin_supervisor/ipc.py`
- Create: `apps/core/src/tuntun_core/services/hardening/plugin_installation.py`
- Create: `apps/core/src/tuntun_core/services/hardening/plugin_invocation.py`
- Create: `ops/launchd/com.tuntun.plugin-supervisor.plist`
- Create: `ops/services/phase6-plugin-supervisor.v1.json`
- Create: `ops/plugins/supervisor-result-verifier.v1.json`
- Test: `apps/plugin-supervisor/tests/test_plugin_verifier.py`
- Test: `apps/plugin-supervisor/tests/test_authenticated_ipc.py`
- Test: `tests/integration/plugins/test_install_and_call.py`
- Test: `tests/security/plugins/test_plugin_admission_denials.py`
- Test: `tests/security/plugins/test_plugin_result_signature_boundary.py`
- Test: `tests/property/plugins/test_manifest_result_fuzz.py`
- Test: `apps/plugin-supervisor/tests/test_service_bootstrap.py`
- Test: `tests/integration/plugins/test_supervisor_service_lifecycle.py`
- Modify: `tests/unit/test_package_smoke.py`

**Interfaces:** Produces local owner-only prepared install/remove, artifact/signature/publisher/protocol/registry/licence/SBOM verification, one authenticated Unix-socket request, generation/correlation/expiry validation before and after child execution, and minimized receipts. It also produces the frozen service entry point `tuntun-plugin-supervisor = tuntun_plugin_supervisor.main:app`, a least-privilege launchd job, and an exact signed-install-inventory fragment consumed by package/update/uninstall gates. `serve` owns only `/private/var/run/tuntun/plugin-supervisor.sock`; `doctor --no-network --json` validates configuration, registry, runtime-dir ownership, socket peer policy and the current supervisor signing-key/public-verifier binding without starting children or reading household data. Installer provisioning creates a non-exportable P-256 signing key whose ACL admits only `_tuntun_plugin`; the signed service inventory binds its public key, signer identity and monotonic generation, while Core receives a verify-only handle and no sign operation.

**Rollback/disabled exit:** Any unsigned/mismatched/unknown/expired plugin or registry disables that installation and launches no child. Admission never trusts manifest-declared policy.

- [ ] **Step 1: Write red signer, digest, manifest-field, IPC-peer, and late-result tests**

~~~python
@pytest.mark.parametrize("fault", [
    "unsigned", "wrong_digest", "wrong_publisher", "resigned_wrong_publisher",
    "unknown_protocol", "unknown_registry", "policy_field", "sbom_mismatch",
    "licence_mismatch", "unsafe_entrypoint", "unlicensed_dependency",
    "duplicate_manifest_key", "noncanonical_manifest", "oversize_manifest",
    "oversize_artifact", "oversize_signature", "oversize_sbom", "archive_entry_2049",
    "archive_uncompressed_over_128_mib", "archive_ratio_over_100", "nested_archive",
    "absolute_archive_path", "dotdot_archive_path", "duplicate_casefold_path",
    "symlink_entry", "hardlink_entry", "device_fifo_or_socket_entry",
    "artifact_swap_after_open", "artifact_swap_after_verify", "parent_rename",
    "sealed_inode_substitution", "attacker_selected_signer_identity",
])
def test_plugin_admission_fails_closed(verifier, candidate, fault) -> None:
    assert verifier.verify(candidate.with_fault(fault)).decision == "deny"
    assert verifier.child_launches == 0

@pytest.mark.parametrize("fault", [
    "partial_open_manifest", "partial_open_signature", "partial_open_sbom", "partial_open_artifact",
    "close_manifest_fd", "close_signature_fd", "close_sbom_fd", "close_artifact_fd",
    "post_seal_source_close_before_transfer", "sealed_handle_close", "sealed_tree_erase",
    "residue_quarantine",
])
def test_admission_cleanup_attempts_every_step_and_leaves_nothing_launchable(
    verifier, candidate, fault,
) -> None:
    result = verifier.verify(candidate.with_cleanup_fault(fault))
    assert result.decision == "deny"
    assert verifier.cleanup_attempted_all_later_steps
    assert verifier.child_launches == 0
    assert verifier.launchable_residue == ()
    if verifier.cleanup_not_proved:
        assert verifier.plugin_readiness is False
        assert verifier.release_gate is False
        assert verifier.local_critical_alerts == ("plugin_cleanup_unproved",)

def test_plugin_admission_programmer_fault_remains_visible(verifier, candidate) -> None:
    verifier.sbom.raise_unexpected(ValueError("programmer fault"))
    with pytest.raises(ValueError, match="programmer fault"):
        verifier.verify(candidate)

@pytest.mark.parametrize("fault", [
    "invalid_utf8", "duplicate_key", "noncanonical_json", "nonfinite_number",
    "depth_33", "container_4097", "structure_token_16385", "oversize_length_prefix",
    "truncated_frame", "slow_frame", "ancillary_fd_scm_rights",
])
async def test_supervisor_raw_call_frame_rejects_before_child(supervisor, valid_call, fault) -> None:
    response = await supervisor.send_raw_call_frame(call_frame_with_fault(valid_call, fault))
    assert response.code == "plugin_call_schema_invalid"
    assert supervisor.child_launches == 0
    assert supervisor.peak_frame_buffer_bytes <= 64 * 1024 + 1
    assert supervisor.received_ancillary_fds_are_closed

async def test_ipc_rejects_wrong_peer_and_late_generation(supervisor) -> None:
    assert (await supervisor.call_from_wrong_peer()).code == "plugin_peer_denied"
    assert supervisor.child_launches == 0
    call = await supervisor.begin_call()
    await supervisor.revoke(call.plugin_id)
    assert (await supervisor.deliver_late_result(call)).code == "plugin_result_stale"

@pytest.mark.parametrize("fault", [
    "cross_capability_child_output",
    "unknown_render_field", "wrong_render_request_id", "wrong_render_schema",
    "invalid_child_utf8", "duplicate_child_output_key", "noncanonical_child_output",
    "nonfinite_child_number", "child_depth_33", "child_container_4097",
    "child_structure_token_16385", "result_observed_before_call",
    "result_observed_in_future", "child_returns_at_exact_expiry", "late_result",
    "timeout", "crash",
])
async def test_admitted_child_fault_returns_supervisor_signed_error_safe(
    supervisor, valid_call, fault,
) -> None:
    result = await supervisor.invoke_with_fault(valid_call, fault)
    assert result.state == "error_safe"
    assert result.payload is None
    supervisor.require_valid_result_signature(result)

@pytest.mark.parametrize("fault", [
    "expired_call", "bad_payload_commitment", "clock_boundary_exception",
    "commitment_boundary_exception", "grant_boundary_exception",
    "supervisor_transport_timeout", "supervisor_transport_oserror",
    "oversize_combined_wire_bytes", "supervisor_result_ancillary_fd",
    "malformed_supervisor_result", "wrong_supervisor_signer", "stale_supervisor_key_generation",
    "signed_denied_state", "signed_expired_state", "signed_failed_state",
])
async def test_core_local_or_transport_fault_creates_no_supervisor_envelope(
    core_plugin_invoker, valid_call, fault,
) -> None:
    outcome = await core_plugin_invoker.invoke_with_fault(valid_call, fault)
    assert outcome == PluginInvocationUnavailable(code="plugin_unavailable")
    assert outcome.supervisor_envelope is None
    assert core_plugin_invoker.supervisor_result_sign_calls == 0

def test_core_has_verify_only_supervisor_key_and_cannot_sign_result(
    core_plugin_invoker,
) -> None:
    assert core_plugin_invoker.supervisor_result_verifier.has_pinned_public_key
    assert core_plugin_invoker.supervisor_result_verifier.sign_operation is None
    assert core_plugin_invoker.supervisor_result_private_keys == ()

async def test_sdk_render_round_trip_is_supervisor_wrapped_and_bound(sdk_child, supervisor, valid_call) -> None:
    payload_bytes = supervisor.encode_metadata_free_child_input(valid_call)
    assert recursively_decoded_keys(payload_bytes).isdisjoint(FORBIDDEN_CHILD_METADATA_KEYS)
    raw_render = await sdk_child.render_one(payload_bytes)
    assert recursively_decoded_keys(raw_render).isdisjoint(FORBIDDEN_CHILD_METADATA_KEYS)
    result = await supervisor.decode_and_wrap_render(valid_call, raw_render)
    assert type(result) is PluginCallResultEnvelopeV1
    assert result.request_id == result.payload.request_id == valid_call.request_id
    assert result.plugin_id == valid_call.plugin_id
    assert result.capability_id == valid_call.capability_id
    supervisor.require_valid_result_signature(result)

def test_installed_supervisor_entrypoint_and_launchd_are_exact(service_install) -> None:
    assert service_install.console_script == "tuntun-plugin-supervisor"
    assert service_install.program_arguments == (
        "/Applications/Tuntun.app/Contents/Resources/venv/bin/tuntun-plugin-supervisor",
        "serve", "--config", "/Library/Application Support/Tuntun/plugin-supervisor.v1.json",
    )
    assert service_install.socket_path == "/private/var/run/tuntun/plugin-supervisor.sock"
    assert service_install.run_as_account == "_tuntun_plugin"

async def test_wrong_account_restart_and_health_never_accept_core_frame(service_harness) -> None:
    assert (await service_harness.start_as_wrong_account()).state == "refused"
    await service_harness.start_installed_job()
    assert (await service_harness.doctor()).state == "ready_no_children"
    generation = service_harness.generation
    await service_harness.restart()
    assert service_harness.generation > generation
    assert (await service_harness.replay_old_core_frame()).code == "plugin_peer_denied"
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/plugin-supervisor/tests/test_plugin_verifier.py apps/plugin-supervisor/tests/test_authenticated_ipc.py tests/integration/plugins/test_install_and_call.py tests/security/plugins/test_plugin_admission_denials.py tests/security/plugins/test_plugin_result_signature_boundary.py -q`
Expected: FAIL because the supervisor/admission/IPC services are absent.

- [ ] **Step 3: Implement immutable admission and generation-bound one-call protocol**

Register `apps/plugin-supervisor` in the root `[tool.uv.workspace].members` list in the same change, update `uv.lock`, add `tuntun_plugin_supervisor` to the shared package-smoke parametrization, and bootstrap the service before importing it in any gate:

~~~toml
# apps/plugin-supervisor/pyproject.toml
[project]
name = "tuntun-plugin-supervisor"
version = "0.1.0.dev0"
requires-python = "==3.12.*"
dependencies = ["tuntun-contracts", "tuntun-plugin-sdk"]

[project.scripts]
tuntun-plugin-supervisor = "tuntun_plugin_supervisor.main:app"

[tool.uv.sources]
tuntun-contracts = { workspace = true }
tuntun-plugin-sdk = { workspace = true }

[build-system]
requires = ["hatchling>=1.27,<2"]
build-backend = "hatchling.build"
~~~

`tuntun_plugin_supervisor/__init__.py` contains only `__version__ = "0.1.0.dev0"`; it re-exports no admission internals. `main.py` owns `serve`, `doctor`, `version` and `--help`, performs bounded configuration validation before binding, refuses root/wrong UID, creates no network socket, and starts no child until a verified Core peer submits an admitted request. The launchd job runs as `_tuntun_plugin` with an empty nonessential environment, absolute ProgramArguments, working directory `/`, no shell, no KeepAlive crash loop, and a root-created runtime directory/socket ACL that admits only `_tuntun_plugin` and the pinned Core service identity. Startup verifies runtime ancestors/owner/mode/no-follow, removes only its own stale socket after proving no live peer, rotates the supervisor generation, then binds; restart rejects all old nonces/generations. A package-boundary test rejects imports from `tuntun_core` in both the SDK and supervisor, so the standalone supervisor can never acquire core authority through workspace registration. `ops/services/phase6-plugin-supervisor.v1.json` initially binds this package/wheel digest, entry point, account, plist digest, runtime directory, socket and owned cleanup paths. Task 21 adds sandbox/process/quota/cleanup package files, so it must rebuild the wheel, refresh/re-sign this same canonical row and invalidate this task's row/receipt before Task 27 packages it or Task 29 accepts lifecycle evidence.

~~~python
from dataclasses import dataclass
from tuntun_contracts.base import ContractParseError, parse_contract_json

PLUGIN_MANIFEST_MAX_BYTES = 64 * 1024
PLUGIN_SIGNATURE_MAX_BYTES = 16 * 1024
PLUGIN_SBOM_MAX_BYTES = 2 * 1024 * 1024
PLUGIN_ARTIFACT_MAX_BYTES = 64 * 1024 * 1024
PLUGIN_ARCHIVE_MAX_ENTRIES = 2048
PLUGIN_ARCHIVE_MAX_UNCOMPRESSED_BYTES = 128 * 1024 * 1024
PLUGIN_ARCHIVE_MAX_ENTRY_BYTES = 32 * 1024 * 1024
PLUGIN_ARCHIVE_MAX_COMPRESSION_RATIO = 100

class PluginExpectedBoundaryError(Exception):
    """Base for normalized hostile/environmental failures; never programmer errors."""

class PluginAdmissionDenied(PluginExpectedBoundaryError): pass
class PluginTransportRejected(PluginExpectedBoundaryError): pass
class PeerAuthenticationError(PluginTransportRejected): pass
class FrameTooLarge(PluginTransportRejected): pass
class FrameTruncated(PluginTransportRejected): pass
class AncillaryHandleRejected(PluginTransportRejected): pass
class PluginPublisherVerificationFailed(PluginExpectedBoundaryError): pass
class PluginInvocationRejected(PluginExpectedBoundaryError): pass
class PluginClockWindowError(PluginInvocationRejected): pass
class PluginCommitmentMismatch(PluginInvocationRejected): pass
class PluginGrantDenied(PluginInvocationRejected): pass
class StaleGrantGeneration(PluginInvocationRejected): pass
class PluginSupervisorExpectedFailure(PluginInvocationRejected): pass
class PluginWireLimitExceeded(PluginInvocationRejected): pass
class PluginCleanupFailure(PluginInvocationRejected): pass

@dataclass(frozen=True, slots=True)
class PluginAdmissionResult:
    decision: Literal["allow", "deny"]
    verified_plugin: VerifiedPlugin | None
    reason_code: Literal["plugin_verified", "plugin_verification_failed"]

    def __post_init__(self) -> None:
        if (self.decision == "allow") != (self.verified_plugin is not None):
            raise ValueError("plugin_admission_result_shape_invalid")
        expected_reason = "plugin_verified" if self.decision == "allow" else "plugin_verification_failed"
        if self.reason_code != expected_reason:
            raise ValueError("plugin_admission_result_reason_invalid")

def _require_verified_candidate(self, package: PluginPackage) -> VerifiedPlugin:
    cleanup = PluginAdmissionCleanup()
    primary_error: BaseException | None = None
    sources = None
    sealed_handle = None
    try:
        # This opener is itself transactional: on a partial open it attempts
        # every already-owned FD close and raises PluginCleanupFailure if any
        # close cannot be proved. No descriptor escapes on ordinary failure.
        sources = self._packages.open_regular_nofollow_bounded(
            package,
            manifest_max_bytes=PLUGIN_MANIFEST_MAX_BYTES,
            signature_max_bytes=PLUGIN_SIGNATURE_MAX_BYTES,
            sbom_max_bytes=PLUGIN_SBOM_MAX_BYTES,
            artifact_max_bytes=PLUGIN_ARTIFACT_MAX_BYTES,
            require_owner_only=True,
            require_nlink_one=True,
        )
        cleanup.add("source_descriptors", sources.close_all_best_effort)
        raw_manifest = sources.manifest.pread_exact()
        raw_signature = sources.signature.pread_exact()
        raw_sbom = sources.sbom.pread_exact()
        artifact_digest = sha256_fd_with_pread(sources.artifact)
        try:
            verified_signer = self._signatures.verify_authorized_publisher_from_allowlist(
                signature=raw_signature,
                artifact_fd=sources.artifact,
                artifact_digest=artifact_digest,
                canonical_manifest=raw_manifest,
                domain="tuntun.plugin-package.v1",
            )
        except PluginPublisherVerificationFailed as error:
            raise PluginAdmissionDenied("plugin_publisher_signature_invalid") from error
        manifest = parse_contract_json(
            PluginManifestV1,
            raw_manifest,
            max_bytes=PLUGIN_MANIFEST_MAX_BYTES,
            require_canonical=True,
        )
        if (
            manifest.signature_identity != verified_signer.identity
            or manifest.publisher != verified_signer.publisher
            or not hmac.compare_digest(manifest.artifact_digest, artifact_digest)
        ):
            raise PluginAdmissionDenied("plugin_signer_publisher_or_digest_mismatch")
        self._registry.require_revision_and_exact_ids(
            manifest.capability_registry_revision,
            manifest.requested_capability_ids,
        )
        self._sbom.require_manifest_identity_licence_and_policy_bytes(
            sbom_bytes=raw_sbom,
            max_bytes=PLUGIN_SBOM_MAX_BYTES,
            expected_digest=manifest.sbom_digest,
            plugin_id=manifest.plugin_id,
            version=manifest.version,
            declared_licence=manifest.licence,
        )
        inventory = self._archives.inspect_exact_fd(
            sources.artifact,
            max_entries=PLUGIN_ARCHIVE_MAX_ENTRIES,
            max_uncompressed_bytes=PLUGIN_ARCHIVE_MAX_UNCOMPRESSED_BYTES,
            max_entry_bytes=PLUGIN_ARCHIVE_MAX_ENTRY_BYTES,
            max_compression_ratio=PLUGIN_ARCHIVE_MAX_COMPRESSION_RATIO,
            reject_nested_archives=True,
            reject_absolute_dotdot_duplicate_casefold_link_special_and_sparse=True,
        )
        self._entrypoints.require_exact_regular_executable(inventory, manifest.entrypoint)
        sealed_handle = self._packages.seal_content_addressed_from_verified_fd(
            sources.artifact,
            inventory=inventory,
            expected_digest=artifact_digest,
            owner_only_root=True,
            retain_read_only_descriptors=True,
        )
        cleanup.add(
            "untransferred_sealed_tree",
            lambda: sealed_handle.close_erase_or_quarantine_nofollow_best_effort()
            if not sealed_handle.transferred_to_verified_plugin else (),
        )
        sealed_handle.require_same_tree_digest_inodes_nlink_and_no_writer(artifact_digest, inventory)
        # Source descriptors must be conclusively closed before the sealed handle
        # can become owned by a VerifiedPlugin. A failed step stays registered so
        # finally retries it while the still-untransferred sealed tree is erased
        # or quarantined.
        source_cleanup_failures = cleanup.run_step_best_effort("source_descriptors")
        if source_cleanup_failures:
            raise PluginCleanupFailure(source_cleanup_failures)
        cleanup.discard_completed("source_descriptors")
        verified = VerifiedPlugin(
            manifest=manifest,
            capability_id=manifest.requested_capability_ids[0],
            codec=self._registry.codec_for(manifest.requested_capability_ids[0]),
            package_handle=sealed_handle,
        )
        sealed_handle.transfer_ownership_to(verified)
        return verified
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_failures = cleanup.run_all_steps_best_effort()
        if cleanup_failures:
            self._plugin_readiness.withdraw_and_block_release_sync("plugin_cleanup_unproved")
            self._alerts.emit_owned_critical_best_effort("plugin_cleanup_unproved")
            # Launch authorization always requires an active verified-handle row;
            # quarantined bytes are chmod/noexec and never path-launchable.
            self._packages.deny_all_unowned_or_quarantined_handles_sync()
            if primary_error is None or isinstance(primary_error, PluginExpectedBoundaryError):
                raise PluginCleanupFailure(cleanup_failures)

def verify(self, package: PluginPackage) -> PluginAdmissionResult:
    try:
        verified = self._require_verified_candidate(package)
    except (OSError, ContractParseError, PluginAdmissionDenied, PluginCleanupFailure):
        return PluginAdmissionResult(
            decision="deny",
            verified_plugin=None,
            reason_code="plugin_verification_failed",
        )
    return PluginAdmissionResult(
        decision="allow",
        verified_plugin=verified,
        reason_code="plugin_verified",
    )

# apps/plugin-supervisor/.../server.py
def decode_supervisor_call_frame(raw_frame: bytes) -> PluginCallEnvelopeV1:
    return parse_contract_json(
        PluginCallEnvelopeV1,
        raw_frame,
        max_bytes=64 * 1024,
        require_canonical=True,
    )

PLUGIN_CALL_SCHEMA_INVALID_FRAME = b'{"code":"plugin_call_schema_invalid"}'
PLUGIN_PEER_DENIED_FRAME = b'{"code":"plugin_peer_denied"}'

async def accept_supervisor_call_frame(
    self,
    peer: AuthenticatedUnixPeer,
    frame_reader: LengthPrefixedFrameReader,
) -> bytes:
    try:
        self._peers.require_core_identity_nonce_and_correlation(peer)
    except PeerAuthenticationError:
        return PLUGIN_PEER_DENIED_FRAME
    try:
        raw_frame = await frame_reader.read_bounded(
            max_bytes=64 * 1024,
            max_buffer_bytes=64 * 1024 + 1,
            timeout=timedelta(seconds=1),
            reject_ancillary_handles=True,
        )
        call = decode_supervisor_call_frame(raw_frame)
    except (FrameTooLarge, FrameTruncated, AncillaryHandleRejected, TimeoutError, ContractParseError):
        return PLUGIN_CALL_SCHEMA_INVALID_FRAME
    encoded = canonical_hardening_bytes(await self.invoke(call))
    if len(raw_frame) + len(encoded) > 64 * 1024:
        raise PluginInvocationRejected("plugin_result_frame_oversize")
    return encoded

# apps/core/.../plugin_invocation.py
@dataclass(frozen=True, slots=True)
class PluginInvocationUnavailable:
    code: Literal["plugin_unavailable"] = "plugin_unavailable"
    supervisor_envelope: None = None

class PluginSupervisorResultSignatureInvalid(PluginInvocationRejected): ...

def decode_supervisor_result_frame(raw_frame: bytes) -> PluginCallResultEnvelopeV1:
    try:
        return parse_contract_json(
            PluginCallResultEnvelopeV1,
            raw_frame,
            max_bytes=64 * 1024,
            require_canonical=True,
        )
    except ContractParseError as error:
        raise PluginInvocationRejected("plugin_result_frame_invalid") from error

async def call_once_raw(self, current, call: PluginCallEnvelopeV1) -> bytes:
    encoded_call = canonical_hardening_bytes(call)
    remaining = 64 * 1024 - len(encoded_call)
    if remaining < MIN_PLUGIN_RESULT_FRAME_BYTES:
        raise PluginWireLimitExceeded("plugin_combined_wire_limit")
    try:
        return await self._transport.exchange_one_length_prefixed_frame(
            peer=self._supervisor_peer,
            request=encoded_call,
            max_request_bytes=64 * 1024,
            max_response_bytes=remaining,
            max_response_buffer_bytes=remaining + 1,
            timeout=timedelta(seconds=1),
            reject_and_close_ancillary_handles=True,
        )
    except (PluginTransportRejected, TimeoutError, OSError) as error:
        raise PluginSupervisorExpectedFailure("plugin_supervisor_transport_failed") from error

def require_exact_plugin_result_binding(
    call: PluginCallEnvelopeV1,
    result: PluginCallResultEnvelopeV1,
) -> None:
    if (
        result.request_id != call.request_id
        or result.plugin_id != call.plugin_id
        or result.plugin_version != call.plugin_version
        or result.capability_id != call.capability_id
        or result.grant_generation != call.grant_generation
    ):
        raise PluginCommitmentMismatch("plugin_result_outer_binding_mismatch")

async def invoke(
    self, call: PluginCallEnvelopeV1,
) -> PluginCallResultEnvelopeV1 | PluginInvocationUnavailable:
    validated_call = PluginCallEnvelopeV1.model_validate(call, strict=True)
    try:
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
        raw_result = await self._supervisor.call_once_raw(current, validated_call)
        validated_result = decode_supervisor_result_frame(raw_result)
        received_at = self._clock.now()
        self._supervisor_result_verifier.require_current_signature(
            validated_result,
            domain="tuntun.plugin-call-result.v1",
            expected_signer_identity=current.supervisor_signer_identity,
            expected_key_generation=current.supervisor_key_generation,
        )
        require_exact_plugin_result_binding(validated_call, validated_result)
        if not (
            validated_call.issued_at
            <= validated_result.observed_at
            <= received_at
            < validated_call.expires_at
        ):
            raise PluginInvocationRejected("plugin_result_time_invalid_or_expired")
        await self._grants.require_current(
            validated_call.plugin_id,
            validated_call.capability_id,
            validated_call.grant_generation,
        )
        return validated_result
    except PluginInvocationRejected:
        # This is a Core-local availability outcome, never a supervisor result.
        # Core has only the pinned public verification key and cannot create or
        # sign PluginCallResultEnvelopeV1.
        return PluginInvocationUnavailable()
~~~

The public admission verifier is total for expected hostile package failures; signer, registry, SBOM, licence, archive and entrypoint adapters normalize expected denials to `PluginAdmissionDenied`. It returns `deny` and launches no process, while cancellation and programmer errors remain visible. Every source is opened once as an owner-only nofollow regular `nlink=1` descriptor before inspection. The multi-open and final cleanup are transactional best-effort sequences: every already-owned FD/handle/erase/quarantine step is attempted even after an earlier cleanup error. Unproved cleanup synchronously withdraws plugin readiness, blocks the release gate, emits a local critical alert, and denies every unowned/quarantined handle; residue may remain for recovery, but no path-based or inactive-handle launch is possible. Manifest/signature/SBOM/artifact, entry count, per-entry and aggregate uncompressed bytes, compression ratio and path depth have fixed ceilings. Verification uses offset-independent reads from those descriptors, rejects links/special/sparse/duplicate-casefold/traversal/nested-archive entries, verifies the raw manifest plus exact artifact descriptor against a closed publisher-key allowlist, then compares the parsed signer/publisher/digest. It securely materializes the already verified inventory into an owner-only content-addressed root, closes all writers, retains exact read-only descriptors, and rechecks tree digest/inodes/link counts/no-writer immediately before every launch. Rename, symlink, hardlink, parent or post-verification substitution can never change the executed bytes. The SBOM policy binds plugin ID/version and the manifest's declared SPDX licence to the exact bounded SBOM bytes before dependency-policy evaluation. Install requires local owner/passkey prepared summary showing publisher/signature/digest/licence/SBOM/exact single capability/platform policies. Adult partner, guardian, child, Guest, remote session, plugin or maintainer cannot install/grant. IPC authenticates OS peer/nonce/correlation before reading application bytes, accepts one length-prefixed frame through a max-plus-one 64-KiB/one-second reader, rejects an oversize declaration before allocation, rejects and closes ancillary handles, and bounds the symmetric result exchange with the same rule before buffering. Wrong peers receive the fixed metadata-free transport denial and launch no child. Raw call-frame rejection returns a fixed transport-level safe code because no attacker-supplied binding may be copied into a signed result. The shared exception taxonomy defines `PluginAdmissionDenied`, the peer/frame transport subclasses, and `PluginInvocationRejected` subclasses for clock, commitment, grant, stale generation, supervisor transport/wire/signature and cleanup failures. Every adapter translates only its documented hostile/environmental failures into that taxonomy; cancellation and programmer errors remain visible. Before an admitted call reaches the supervisor, and for transport/malformed-frame/wrong-signer/stale-key failures where no authentic supervisor envelope exists, Core returns only in-process `PluginInvocationUnavailable` and creates no `PluginCallResultEnvelopeV1`. Core owns no supervisor signing key or signing broker. After the supervisor has admitted a valid call, child timeout, crash, malformed output or late output becomes a supervisor-signed `error_safe` envelope with no payload. Core verifies the pinned signer identity, public key, key generation, P-256 signature domain, exact outer binding and time window before accepting either `rendered` or `error_safe`.

- [ ] **Step 4: Run green plus manifest/result fuzz and audit-content scan**

Run: `uv lock && uv sync --all-packages && uv run pytest tests/unit/test_package_smoke.py apps/plugin-supervisor/tests/test_service_bootstrap.py apps/plugin-supervisor/tests/test_plugin_verifier.py apps/plugin-supervisor/tests/test_authenticated_ipc.py tests/integration/plugins/test_supervisor_service_lifecycle.py tests/integration/plugins/test_install_and_call.py tests/security/plugins/test_plugin_admission_denials.py tests/security/plugins/test_plugin_result_signature_boundary.py -q && uv run pytest tests/property/plugins -q && uv build apps/plugin-supervisor && uv run tuntun-plugin-supervisor --help && uv run tuntun-plugin-supervisor doctor --no-network --synthetic-config fixtures/synthetic/phase6/plugins/supervisor-config-v1.json --json && plutil -lint ops/launchd/com.tuntun.plugin-supervisor.plist && uv run python scripts/scan_private_data.py --paths var/test-artifacts/plugin-audit --allow-safe-ids && uv run ruff check apps/plugin-supervisor apps/core/src/tuntun_core/services/hardening/plugin_installation.py apps/core/src/tuntun_core/services/hardening/plugin_invocation.py tests/unit/test_package_smoke.py tests/integration/plugins tests/security/plugins && uv run mypy apps/plugin-supervisor/src apps/core/src`
Expected: PASS; the locked workspace imports the standalone supervisor, every admission fault spawns zero processes, and late/wrong-peer results are discarded.

- [ ] **Step 5: Commit plugin admission and IPC**

~~~bash
git add pyproject.toml uv.lock apps/plugin-supervisor/pyproject.toml apps/plugin-supervisor/src/tuntun_plugin_supervisor/__init__.py apps/plugin-supervisor/src/tuntun_plugin_supervisor/main.py apps/plugin-supervisor/src/tuntun_plugin_supervisor/server.py apps/plugin-supervisor/src/tuntun_plugin_supervisor/verifier.py apps/plugin-supervisor/src/tuntun_plugin_supervisor/registry.py apps/plugin-supervisor/src/tuntun_plugin_supervisor/ipc.py apps/core/src/tuntun_core/services/hardening/plugin_installation.py apps/core/src/tuntun_core/services/hardening/plugin_invocation.py ops/launchd/com.tuntun.plugin-supervisor.plist ops/services/phase6-plugin-supervisor.v1.json ops/plugins/supervisor-result-verifier.v1.json apps/plugin-supervisor/tests/test_service_bootstrap.py apps/plugin-supervisor/tests/test_plugin_verifier.py apps/plugin-supervisor/tests/test_authenticated_ipc.py tests/unit/test_package_smoke.py tests/integration/plugins/test_supervisor_service_lifecycle.py tests/integration/plugins/test_install_and_call.py tests/security/plugins/test_plugin_admission_denials.py tests/security/plugins/test_plugin_result_signature_boundary.py tests/property/plugins/test_manifest_result_fuzz.py
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
- Modify: `ops/services/phase6-plugin-supervisor.v1.json`
- Test: `apps/plugin-supervisor/tests/test_sandbox_policy.py`
- Test: `tests/security/plugins/test_plugin_exfiltration.py`
- Test: `tests/fault/plugins/test_plugin_resource_and_cleanup.py`
- Test: `tests/hardware/phase6/test_plugin_sandbox_enforcement.py`
- Modify: `apps/plugin-supervisor/tests/test_service_bootstrap.py`
- Modify: `tests/integration/plugins/test_supervisor_service_lifecycle.py`

**Interfaces:** Produces `SandboxBackend.run_fresh(VerifiedPlugin, payload_bytes: PluginChildWireInput, deadline: MonotonicDeadline) -> bytes` using a dedicated unprivileged identity, the exact retained read-only sealed package handles, empty per-call sandbox, no inherited environment secret, authenticated socket only, and fixed quotas. The one call deadline covers sandbox setup, spawn and exchange. Before this call, the supervisor verifies the frozen trusted envelope/source facts, chooses the registry codec out of band, and serializes only the dedicated metadata-free child-input DTO. Afterward it passes the untrusted stdout bytes through the shared bounded, duplicate-safe, canonical parser for exactly the selected child-output DTO and only then constructs/signs `PluginCallResultEnvelopeV1` itself. There is no parallel generic call/result, dictionary, attribute-map, or child-visible trusted envelope protocol.

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

@pytest.mark.parametrize("fault", [
    "create_after_directory", "create_after_ipc_fd", "spawn", "kill", "socket_close",
    "sandbox_erase", "postcondition_probe",
])
async def test_partial_setup_and_each_cleanup_fault_attempt_every_cleanup_and_revoke(
    sandbox, fault,
) -> None:
    receipt = await sandbox.run_lifecycle_fault(fault)
    assert receipt.attempted_steps == {"kill", "close_socket", "erase", "residue_probe"}
    assert receipt.plugin_revoked and receipt.critical_local_alert_open
    assert not receipt.plugin_readiness

async def test_setup_spawn_and_exchange_share_one_call_deadline(sandbox) -> None:
    result = await sandbox.run_with_delayed_setup(total_delay_seconds=5.01)
    assert result.state == "error_safe"
    assert sandbox.live_processes == ()

def test_limits_are_exact(policy) -> None:
    assert policy.wall_seconds == 5 and policy.memory_mib == 128
    assert policy.cpu_fraction == Decimal("0.50") and policy.concurrent_calls == 1
    assert policy.request_response_bytes == 64 * 1024

@pytest.mark.parametrize("capability", ["system.health.render.v1", "notification.local_alert.render.v1"])
async def test_child_wire_contains_only_dedicated_inner_dto(sandbox, capability) -> None:
    capture = await sandbox.capture_call(capability)
    assert capture.stdin_bytes == capture.expected_child_input_bytes
    assert capture.stdout_bytes == capture.expected_child_output_bytes
    forbidden = {
        "schema_id", "schema_version", "request_id", "purpose", "source_generation",
        "observed_at", "issued_at", "occurred_at", "expires_at", "valid_until",
        "fact_commitment", "payload_commitment", "result_commitment", "result_signature",
        "supervisor_signer_identity", "supervisor_key_generation", "grant_generation",
        "plugin_id", "plugin_version", "capability_id", "codec", "registry_digest",
    }
    assert recursively_collect_json_keys(capture.stdin_bytes).isdisjoint(forbidden)
    assert recursively_collect_json_keys(capture.stdout_bytes).isdisjoint(forbidden)

def test_malformed_child_contract_becomes_error_safe_without_payload(sandbox) -> None:
    result = sandbox.decode_malformed_child_output(b'{"state":')
    assert result.state == "error_safe"
    assert result.payload is None

@pytest.mark.parametrize("error", [ValueError("programmer fault"), TypeError("programmer fault")])
def test_child_decoder_does_not_normalize_programmer_errors(sandbox, error) -> None:
    sandbox.inject_parser_programmer_error(error)
    with pytest.raises(type(error), match="programmer fault"):
        sandbox.decode_valid_child_output()

def test_sandbox_package_change_requires_refreshed_signed_supervisor_row(
    final_supervisor_wheel, task20_service_row, current_service_row, service_verifier,
) -> None:
    assert service_verifier.verify(task20_service_row, final_supervisor_wheel).denied
    assert service_verifier.verify(current_service_row, final_supervisor_wheel).accepted
    assert current_service_row.package_digest == final_supervisor_wheel.digest

async def test_refreshed_supervisor_row_repeats_installed_lifecycle(service_harness) -> None:
    await service_harness.install_from_current_signed_row()
    assert (await service_harness.doctor()).state == "ready_no_children"
    await service_harness.restart()
    assert service_harness.new_generation_enforced
    await service_harness.update_and_rollback_exact_current_row()
    assert service_harness.old_task20_row_and_receipt_rejected
    assert service_harness.both_uninstall_modes_leave_no_owned_residue
~~~

- [ ] **Step 2: Run red and hardware collection-only**

Run: `uv run pytest apps/plugin-supervisor/tests/test_sandbox_policy.py tests/security/plugins/test_plugin_exfiltration.py tests/fault/plugins/test_plugin_resource_and_cleanup.py -q && uv run pytest tests/hardware/phase6/test_plugin_sandbox_enforcement.py --collect-only -q`
Expected: unit/security tests FAIL because sandbox enforcement is absent; hardware test collects and skips without its explicit flag.

- [ ] **Step 3: Implement enforceable macOS profile, child limits, and postcondition cleanup**

~~~python
from tuntun_contracts.base import ContractParseError, parse_contract_json

async def run_fresh(
    self,
    plugin: VerifiedPlugin,
    payload_bytes: PluginChildWireInput,
    *,
    deadline: MonotonicDeadline,
) -> bytes:
    remaining_wire_bytes = 64 * 1024 - len(payload_bytes)
    if remaining_wire_bytes <= 0:
        raise PluginWireLimitExceeded
    lifecycle = SandboxLifecycle()
    primary_error: BaseException | None = None
    try:
        plugin.package_handle.require_same_tree_digest_inodes_nlink_and_no_writer(
            plugin.manifest.artifact_digest,
            plugin.package_handle.verified_inventory,
        )
        async with asyncio.timeout_at(deadline.loop_time):
            sandbox = await self._sandboxes.create_empty_readonly_exec(
                plugin,
                lifecycle=lifecycle,
            )
            process = await self._processes.spawn(
                identity=self._dedicated_identity,
                executable_handle=plugin.package_handle.entrypoint_handle,
                argv=("--one-call",), env={}, cwd=sandbox.empty_workdir,
                inherited_fds=(sandbox.authenticated_ipc_fd,),
                limits=ProcessLimits(
                    wall_seconds=deadline.remaining_seconds_capped(5),
                    memory_mib=128, cpu_fraction=Decimal("0.50"), processes=1,
                ),
                network=NetworkPolicy.DENY_ALL, filesystem=sandbox.profile,
                lifecycle=lifecycle,
            )
            return await self._ipc.exchange(
                process,
                payload_bytes,
                max_response_bytes=remaining_wire_bytes,
                max_response_buffer_bytes=remaining_wire_bytes + 1,
                lifecycle=lifecycle,
            )
    except BaseException as error:
        primary_error = error
        raise
    finally:
        receipt = await complete_owned_cleanup_despite_caller_cancellation(
            self._cleanup.run_all_steps_best_effort(lifecycle),
        )
        if not receipt.complete_and_residue_free:
            self._readiness.withdraw_plugin_support_synchronously()
            await complete_owned_cleanup_despite_caller_cancellation(
                self._cleanup.revoke_and_alert_best_effort(
                    plugin.manifest.plugin_id,
                    alert_code="plugin_cleanup_failed",
                ),
            )
            if primary_error is None:
                raise PluginCleanupFailure(receipt.safe_reason_codes)

def decode_child_output(
    selected_codec: CodecPair,
    raw_result: bytes,
    *,
    request_bytes: int,
) -> PluginHealthChildOutputV1 | PluginAlertChildOutputV1:
    remaining_wire_bytes = 64 * 1024 - request_bytes
    if remaining_wire_bytes <= 0:
        raise PluginInvocationRejected("plugin_wire_limit_exceeded")
    try:
        return parse_contract_json(
            selected_codec.response,
            raw_result,
            max_bytes=remaining_wire_bytes,
            require_canonical=True,
        )
    except ContractParseError as error:
        raise PluginInvocationRejected("plugin_child_output_invalid") from error
~~~

The supervisor orchestration surrounding `run_fresh` validates `PluginCallEnvelopeV1`, verifies each source fact, derives the exact child-input DTO, selects/encodes with its local registry codec, calls `decode_child_output` on the untrusted bytes, checks the admitted call has not expired, then copies `request_id` and all outer bindings from that call into the public render/result envelope. It signs the canonical envelope fields excluding `result_signature` with the supervisor account's non-exportable P-256 key under domain `tuntun.plugin-call-result.v1`, including the pinned signer identity and key generation. Core has only the corresponding pinned public verifier. The private key, outer fields, and wrapper are absent from the plugin SDK/process. Invalid UTF-8, duplicate/noncanonical keys, non-finite or structurally excessive values, wrong schema/capability, timeout, crash and late child output after admission all normalize to the same supervisor-signed `state="error_safe"` result with no payload, while the mandatory core alert remains. The 64 KiB ceiling applies to request plus response bytes together, not to each direction independently.

The profile allows only loader/system libraries proven necessary, read-only plugin bytes, one inherited authenticated socket and empty ephemeral metadata. Deny all other file, network, DNS, Mach/service, device, mount, clipboard, user-home, Keychain and process actions. Enforce quotas both at OS launch and supervisor measurement. `SandboxLifecycle` exists before the first directory/FD allocation, so create and spawn failures are cleanable. Its cleanup routine attempts kill, socket close, erase and residue probe independently even when an earlier step fails, and an owned cleanup task completes before caller cancellation is re-raised. Any incomplete postcondition synchronously withdraws plugin readiness, best-effort revokes the installation, opens a critical local alert and blocks P6-3/C0/C1; a cleanup exception never skips later cleanup or masquerades as success. After these four package modules are final, rebuild `tuntun-plugin-supervisor`, refresh/re-sign only `ops/services/phase6-plugin-supervisor.v1.json`, and repeat start/health/restart/update/rollback/preserve-uninstall/destroy-uninstall against that exact installed wheel. The Task 20 row and its lifecycle receipt must fail the same verifier; no digest exemption exists.

- [ ] **Step 4: Run green synthetic enforcement and stage mandatory physical qualification**

Run: `uv run pytest apps/plugin-supervisor/tests/test_sandbox_policy.py apps/plugin-supervisor/tests/test_service_bootstrap.py tests/integration/plugins/test_supervisor_service_lifecycle.py tests/security/plugins/test_plugin_exfiltration.py tests/fault/plugins/test_plugin_resource_and_cleanup.py -q && uv build --offline --wheel --package tuntun-plugin-supervisor --out-dir var/build-smoke/phase6/plugin-supervisor-final && uv run python ops/plugins/qualify_sandbox.py --synthetic --output var/evidence/phase6/plugin-sandbox-synthetic.json && uv run ruff check apps/plugin-supervisor ops/plugins tests/integration/plugins/test_supervisor_service_lifecycle.py tests/security/plugins tests/fault/plugins tests/hardware/phase6 && uv run mypy apps/plugin-supervisor/src`
Expected: PASS for synthetic enforcement with zero leaked/persisted bytes. P6-3 remains blocked until `TUNTUN_ALLOW_PLUGIN_SANDBOX_PROBE=1 ...` passes on the supported Intel Mac and declared Apple Silicon target.

- [ ] **Step 5: Commit sandbox and qualification gate**

~~~bash
git add apps/plugin-supervisor/src/tuntun_plugin_supervisor/sandbox.py apps/plugin-supervisor/src/tuntun_plugin_supervisor/process.py apps/plugin-supervisor/src/tuntun_plugin_supervisor/quotas.py apps/plugin-supervisor/src/tuntun_plugin_supervisor/cleanup.py ops/plugins/plugin.sb ops/plugins/qualify_sandbox.py ops/services/phase6-plugin-supervisor.v1.json apps/plugin-supervisor/tests/test_sandbox_policy.py apps/plugin-supervisor/tests/test_service_bootstrap.py tests/integration/plugins/test_supervisor_service_lifecycle.py tests/security/plugins/test_plugin_exfiltration.py tests/fault/plugins/test_plugin_resource_and_cleanup.py tests/hardware/phase6/test_plugin_sandbox_enforcement.py
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
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Create: `apps/admin/src/features/system/plugins.tsx`
- Create: `apps/admin/src/routes/system-plugins.tsx`
- Test: `tests/integration/plugins/test_health_render.py`
- Test: `tests/security/plugins/test_health_actor_and_sensitivity.py`
- Modify: `tests/integration/phase6/test_owner_ingress_phase6_composition.py`
- Modify: `tests/integration/deploy/test_owner_ingress_route_manifest.py`
- Test: `apps/admin/src/features/system/plugins.test.tsx`
- Test: `tests/ui/phase6/plugin-health.spec.ts`

**Interfaces:** Implements `system.health.render.v1` from exact current core safe component facts to optional plain-text result. Each unique component fact has a bounded observation/validity window covering the whole five-second snapshot, a current source generation and unique attention codes. The supervisor rechecks source generations before child invocation and after child return. Every invocation requires a locally present owner, active passkey session and explicit click; output renders in a labelled isolated “Third-party plugin” panel while core health remains authoritative.

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

@pytest.mark.parametrize("mutation", [
    "stale_source_generation", "component_observed_after_issue", "component_expires_during_snapshot",
    "duplicate_component", "duplicate_attention_code",
])
async def test_health_fact_drift_or_time_lie_denies_before_plugin_call(harness, mutation) -> None:
    result = await harness.invoke_health_with_fact_mutation(mutation)
    assert result.code in {"STALE_GENERATION", "SCHEMA_UNSUPPORTED"}
    assert harness.plugin_child_calls == 0

async def test_source_generation_change_during_child_call_discards_render(harness) -> None:
    waiting = harness.begin_health_render_while_child_paused()
    await harness.advance_component_source_generation("storage")
    harness.release_plugin_child()
    result = await waiting
    assert result.code == "STALE_GENERATION"
    assert result.render is None

def test_plugin_result_is_labelled_and_not_authoritative(rendered_page) -> None:
    assert rendered_page.panel_label == "Third-party plugin"
    assert rendered_page.core_health_present and rendered_page.core_health_authoritative
    assert not rendered_page.has_markup_url_action_or_hidden_text

async def test_valid_signed_rendered_health_envelope_uses_only_payload(harness) -> None:
    result = await harness.invoke_health_with_supervisor_outcome("signed_rendered")
    assert isinstance(result, PluginHealthRenderV1)
    assert result == harness.signed_supervisor_envelope.payload

@pytest.mark.parametrize("outcome", ["signed_error_safe", "core_local_unavailable"])
async def test_health_error_or_unavailable_removes_optional_panel(harness, outcome) -> None:
    assert await harness.invoke_health_with_supervisor_outcome(outcome) is None
    assert harness.core_health_authoritative


def test_installed_health_render_route_dispatches_once_from_signed_manifest(
    installed_owner_ingress,
) -> None:
    result = installed_owner_ingress.request(
        "POST", "/api/v1/plugins/health-render", feature_enabled=True,
    )
    assert result.status_code == 200
    assert result.core_uds_dispatch_count == 1


@pytest.mark.parametrize("state", ["unknown", "disabled"])
def test_unknown_or_disabled_health_render_route_is_404_before_dispatch(
    installed_owner_ingress, state,
) -> None:
    result = installed_owner_ingress.request(
        "POST", "/api/v1/plugins/health-render", route_state=state,
    )
    assert result.status_code == 404
    assert result.body_read_count == 0
    assert result.core_uds_dispatch_count == 0
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/plugins/test_health_render.py tests/security/plugins/test_health_actor_and_sensitivity.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py -q && pnpm --filter @tuntun/admin test -- plugins.test.tsx && pnpm --filter @tuntun/admin e2e -- tests/ui/phase6/plugin-health.spec.ts`
Expected: FAIL because health invocation/API/UI are absent.

- [ ] **Step 3: Implement minimized request, explicit invocation, and isolated rendering**

~~~python
async def invoke_health_render(
    self, owner, explicit_click: bool,
) -> PluginHealthRenderV1 | None:
    self._auth.require_local_owner_active_passkey(owner)
    if not explicit_click:
        raise PolicyDenied("health_plugin_requires_explicit_click")
    request = self._projections.build_plugin_health_snapshot(max_components=16, ttl=timedelta(seconds=5))
    await self._projections.require_current_source_generations_and_snapshot_overlap(request)
    result = await self._plugins.invoke_exact("system.health.render.v1", request)
    await self._projections.require_current_source_generations_and_snapshot_overlap(request)
    if isinstance(result, PluginInvocationUnavailable) or result.state != "rendered":
        return None
    return PluginHealthRenderV1.model_validate(result.payload)
~~~

Map only the closed component/state/freshness/attention enums, never free-form core text or identifiers. Build the snapshot and verify each fact under the same serialized generation read; require unique component classes and attention codes, `observed_at <= issued_at < expires_at <= valid_until`, and the exact current source generation both before serialization and after the child returns. A wrapper timestamp can never freshen a stale, expired, duplicate, or superseded fact. Escape plain text, reject bidi/markup/URLs/images/actions, and prevent plugin result from search/model/memory/tool/audit-body ingestion. UI uses an isolated component tree with no unsafe HTML and provides core fallback, keyboard focus, VoiceOver label, English/Hindi platform copy and narrow/high-contrast fixtures.

Register only `POST /api/v1/plugins/health-render` in the canonical Core app/container, owner-ingress router and signed route manifest. Its handler still enforces local-owner presence and therefore denies remote-origin calls; route registration does not widen policy. Installed-candidate composition proves one enabled row dispatches once over the peer-authenticated Core UDS and every unknown, disabled, duplicate or unsigned row is 404 before request-body read or UDS I/O.

- [ ] **Step 4: Run green, UI security/accessibility, and core-authority assertions**

Run: `uv run pytest tests/integration/plugins/test_health_render.py tests/security/plugins/test_health_actor_and_sensitivity.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py -q && pnpm --filter @tuntun/admin test -- plugins.test.tsx && pnpm --filter @tuntun/admin e2e -- tests/ui/phase6/plugin-health.spec.ts && pnpm --filter @tuntun/admin typecheck && pnpm --filter @tuntun/admin build`
Expected: PASS; exactly one local click produces a labelled safe panel, and every failure leaves authoritative core health visible.

- [ ] **Step 5: Commit health render path**

~~~bash
git add apps/core/src/tuntun_core/services/hardening/plugin_invocation.py apps/core/src/tuntun_core/api/routes/plugins.py apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json apps/admin/src/features/system/plugins.tsx apps/admin/src/routes/system-plugins.tsx tests/integration/plugins/test_health_render.py tests/security/plugins/test_health_actor_and_sensitivity.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py apps/admin/src/features/system/plugins.test.tsx tests/ui/phase6/plugin-health.spec.ts
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

async def test_valid_signed_rendered_alert_creates_only_adjacent_presentation(harness) -> None:
    alert = await harness.raise_core_alert("privacy_stop_failed", severity="critical")
    presentation = await harness.present_with_supervisor_outcome(alert, "signed_rendered")
    assert isinstance(presentation, PluginLocalAlertRenderV1)
    assert presentation == harness.signed_supervisor_envelope.payload
    assert harness.core_alert(alert.id).visible and harness.core_alert(alert.id).actionable

@pytest.mark.parametrize("outcome", ["signed_error_safe", "core_local_unavailable"])
async def test_alert_error_or_unavailable_creates_no_plugin_presentation(
    harness, outcome,
) -> None:
    alert = await harness.raise_core_alert("privacy_stop_failed", severity="critical")
    assert await harness.present_with_supervisor_outcome(alert, outcome) is None
    assert harness.core_alert(alert.id).visible and harness.core_alert(alert.id).actionable
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
    result = await self._plugins.invoke_exact("notification.local_alert.render.v1", request)
    try:
        if isinstance(result, PluginInvocationUnavailable) or result.state != "rendered":
            return None
        return PluginLocalAlertRenderV1.model_validate(result.payload)
    finally:
        await self._core_alerts.assert_unchanged(alert.alert_id)

async def revoke_and_remove(self, plugin_id: str) -> RemovalReceipt:
    await self._grants.increment_generation(plugin_id)
    await self._supervisor.cancel_close_kill(plugin_id)
    await self._supervisor.erase_binary_and_empty_sandboxes(plugin_id)
    return await self._audit.safe_plugin_removal_receipt(plugin_id)
~~~

Task 20's supervisor is the sole creator of authenticated result envelopes: timeout, crash, stale generation and malformed child output after an admitted call arrive here as a validated supervisor-signed `error_safe` result with no payload. A Core-local preadmission, transport, frame or signature failure is the distinct non-envelope `PluginInvocationUnavailable`; this task renders no plugin panel for it and still preserves the mandatory core alert. This task does not invent or catch a second terminal exception. Cancellation and programmer failures from the supervisor remain visible while the mandatory core alert is still protected by the `finally` assertion. Reject unlisted alert codes, diagnostic detail and plugin attempts to acknowledge/close/forward/delay. Privacy Shield cancels plugin calls but not core alerts. `CONTAINED_EGRESS` stops external notifications/adapters/updates while local core alert and eligible no-network plugin presentation remain truthful; plugin failure never affects the core surface.

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
- Create if absent, otherwise Modify: `LICENSE` (Phase 1 P1R1 is optional; converge to one canonical file)
- Create if absent, otherwise Modify: `SECURITY.md` (preserve any Phase 1 disclosure history)
- Create if absent, otherwise Modify: `CODE_OF_CONDUCT.md` (converge to one canonical file)
- Create if absent, otherwise Modify: `CONTRIBUTING.md` (converge to one canonical file)
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
Expected: FAIL because the hardened workflows, lock/policy changes, reviewed dependency inventory, and notice bytes are absent; the Task 02 licence checker itself remains present and passing its synthetic contract tests.

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

Record the review of each full action commit in the workflow-policy fixture. Separate unprivileged PR CI from protected candidate/attestation workflows; signing/notarization remains outside fork jobs and requires protected environment/manual approval. Add dependency review, secret scan, generated drift, test/coverage, licences/notices through the sole `scripts/check_licenses.py` owner from Task 02, source/history/artifact scan and workflow-policy self-test. No household evidence is uploaded.

- [ ] **Step 4: Run workflow policy, locks, licences, scanners, and full deterministic checks**

Run: `uv run pytest tests/security/release/test_workflow_permissions.py tests/security/release/test_fork_secret_isolation.py tests/acceptance/release/test_locked_dependencies.py tests/privacy/release/test_ci_artifact_scan.py -q && uv lock --check && pnpm install --frozen-lockfile --ignore-scripts && uv run python scripts/check_licenses.py --project --output var/release/THIRD_PARTY_NOTICES.txt && uv run python scripts/check_licenses.py --project --check --output var/release/THIRD_PARTY_NOTICES.txt && uv run python scripts/check_workflow_pins.py .github/workflows && uv run python scripts/scan_private_data.py --include-git-history --paths . var/test-artifacts && make check`
Expected: PASS; every action is immutable, fork exposure is zero, locks clean, licences approved, and private scan has zero findings.

- [ ] **Step 5: Commit supply-chain controls**

~~~bash
git add .github/workflows/ci.yml .github/workflows/release-candidate.yml .github/workflows/attest.yml .github/dependabot.yml pyproject.toml uv.lock package.json pnpm-lock.yaml tests/security/release/test_workflow_permissions.py tests/security/release/test_fork_secret_isolation.py tests/acceptance/release/test_locked_dependencies.py tests/privacy/release/test_ci_artifact_scan.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "ci(security): lock the public build boundary"
~~~

### Task 26: Generate and verify build outputs, SPDX SBOM, provenance, and the pre-signing inventory

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

**Interfaces:** Produces deterministic unsigned build outputs, SPDX SBOM, licences/notices, SLSA L2 Sigstore-backed provenance/attestation, and a content-addressed pre-signing inventory. It does **not** create the final artifact hashes, `ReleaseManifestV1`, or C1 commitment because signing/notarization/stapling changes the bytes. Task 27 consumes this frozen inventory, signs/notarizes/staples, hashes the exact final bytes, and only then signs the final manifest. During Tasks 26–35 these commands qualify tooling with synthetic/developer inputs only; no output is a C0/C1 candidate, and any later tracked change invalidates it. The mandatory production rerun occurs only in Task 36's final frozen-candidate ceremony after all implementation, UI, C0 and C1/publication tooling is committed. `ReleaseVerifierPort.verify(ReleaseCandidateV1, InstalledReleaseV1, update_run_id=...) -> ReleaseDecisionV1` verifies that final output and binds its authenticated, at-most-five-minute decision to the exact run, candidate ID, canonical manifest digest, artifact-set ID and artifact-set commitment; denial is a returned closed decision, never an exception an updater could mistake for approval.

**Rollback/disabled exit:** Wrong/unknown/revoked signer, repository/workflow/builder, SBOM, dependency, tag/artifact, version/downgrade/replay, corruption, expiry, feature/evidence/compatibility mismatch preserves the prior version and blocks publication.

- [ ] **Step 1: Write red reproducibility and every negative-verifier test**

~~~python
@pytest.mark.parametrize("fault", [
    "wrong_signer", "wrong_repository", "wrong_workflow", "unknown_builder", "modified_sbom",
    "dependency_policy", "tag_artifact_mismatch", "downgrade", "replayed_manifest",
    "corrupt_download", "future_issued", "expired_release", "revoked_release",
    "mutated_manifest_reused_signature", "feature_digest", "acceptance_digest",
    "compatibility_digest", "invalid_manifest_utf8", "duplicate_manifest_key",
    "noncanonical_manifest", "nonfinite_manifest_number", "manifest_depth_33",
    "manifest_container_4097", "manifest_structure_token_16385", "oversize_manifest",
    "attacker_selected_signer_identity", "signer_backend_unavailable",
    "provenance_backend_unavailable", "artifact_store_unavailable",
])
def test_release_verifier_preserves_prior_on_any_fault(verifier, candidate, installed, fault) -> None:
    decision = verifier.verify(candidate.with_fault(fault), installed, update_run_id=UPDATE_RUN_ID)
    assert decision.install_allowed is False
    assert decision.preserve_version == installed.version

def test_release_verifier_does_not_hide_programmer_value_error(verifier, candidate, installed) -> None:
    verifier.sbom.raise_unexpected(ValueError("programmer fault"))
    with pytest.raises(ValueError, match="programmer fault"):
        verifier.verify(candidate, installed, update_run_id=UPDATE_RUN_ID)

def test_release_candidate_signature_has_independent_16kib_ceiling(candidate_payload) -> None:
    with pytest.raises(ValidationError):
        ReleaseCandidateV1.model_validate({
            **candidate_payload, "manifest_signature": "a" * (16 * 1024 + 1),
        })

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
    decision = verifier.verify(changed, installed, update_run_id=UPDATE_RUN_ID)
    assert decision.install_allowed is False
    assert decision.reason_code == "release_manifest_signature_invalid"

@pytest.mark.parametrize("fault", [
    "valid_until_equals_decided_at", "valid_until_over_five_minutes",
    "valid_until_after_manifest_expiry",
])
def test_release_decision_rejects_invalid_or_overlong_time_binding(valid_release_decision, fault) -> None:
    with pytest.raises(ValidationError):
        ReleaseDecisionV1.model_validate(valid_release_decision.with_fault(fault))
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/release/test_release_manifest.py tests/security/release/test_release_verifier_denials.py tests/reproducibility/test_release_build.py tests/privacy/release/test_release_artifact_contents.py -q`
Expected: FAIL because release tooling/verifier/manifests are absent.

- [ ] **Step 3: Implement deterministic build graph and strict independent verifier**

~~~python
from tuntun_contracts.base import ContractParseError, parse_contract_json

class ReleaseVerificationError(Exception): ...
class ReleaseDenied(ReleaseVerificationError): ...
class ReleaseSignatureVerificationError(ReleaseVerificationError): ...
class ProvenanceVerificationError(ReleaseVerificationError): ...
class SbomVerificationError(ReleaseVerificationError): ...
class ArtifactStoreError(ReleaseVerificationError): ...
class VersionRegistryError(ReleaseVerificationError): ...
class ReleaseBindingError(ReleaseVerificationError): ...

def verify(
    self, candidate: ReleaseCandidateV1, installed: InstalledReleaseV1, *, update_run_id: UUID,
) -> ReleaseDecisionV1:
    now = self._clock.now()
    try:
        if not hmac.compare_digest(
            sha256(candidate.manifest_bytes).hexdigest(),
            candidate.manifest_digest,
        ):
            raise ReleaseDenied("release_candidate_manifest_digest_mismatch")
        try:
            verified_signer_identity = self._signers.verify_current_manifest_signature_from_allowlist(
                signature=candidate.manifest_signature,
                domain="tuntun.release-manifest.v1",
                payload=candidate.manifest_bytes,
            )
        except ReleaseSignatureVerificationError as error:
            raise ReleaseDenied("release_manifest_signature_invalid") from error
        manifest = parse_contract_json(
            ReleaseManifestV1,
            candidate.manifest_bytes,
            max_bytes=1024 * 1024,
            require_canonical=True,
        )
        if manifest.issued_at > now or (manifest.expires_at is not None and now >= manifest.expires_at):
            raise ReleaseDenied("release_manifest_time_invalid")
        if manifest.signer_identity != verified_signer_identity:
            raise ReleaseDenied("release_manifest_signer_identity_mismatch")
        self._provenance.require_slsa_l2(manifest.provenance_digest, manifest.source_commit,
                                         manifest.source_repository_identity, manifest.workflow_identity)
        self._sbom.require_spdx_and_policy(manifest.sbom_spdx_digest, manifest.dependency_lock_digest)
        assets = self._artifacts.resolve_exact_set(candidate.artifact_set_id, candidate.artifact_set_commitment)
        self._artifacts.require_exact_digests(manifest.artifact_digests, assets)
        self._versions.require_monotonic_nonreplayed(manifest.version, installed.version, manifest.source_commit)
        self._bindings.require_exact_feature_evidence_compatibility(manifest)
    except (
        ContractParseError,
        ReleaseVerificationError,
        TimeoutError,
        OSError,
    ) as error:
        reason = safe_release_reason(error)
        return ReleaseDecisionV1(
            update_run_id=update_run_id,
            candidate_id=candidate.candidate_id,
            candidate_manifest_digest=candidate.manifest_digest,
            artifact_set_id=candidate.artifact_set_id,
            artifact_set_commitment=candidate.artifact_set_commitment,
            install_allowed=False,
            preserve_version=installed.version,
            accepted_manifest=None,
            reason_code=reason,
            decided_at=now,
            valid_until=now + timedelta(minutes=5),
            decision_commitment=self._commitments.for_release_decision(
                update_run_id, candidate.candidate_id, candidate.manifest_digest,
                candidate.artifact_set_id, candidate.artifact_set_commitment, False,
                installed.version, None, reason, now, now + timedelta(minutes=5),
            ),
        )
    valid_until = min(
        now + timedelta(minutes=5),
        manifest.expires_at if manifest.expires_at is not None else now + timedelta(minutes=5),
    )
    return ReleaseDecisionV1(
        update_run_id=update_run_id,
        candidate_id=candidate.candidate_id,
        candidate_manifest_digest=candidate.manifest_digest,
        artifact_set_id=candidate.artifact_set_id,
        artifact_set_commitment=candidate.artifact_set_commitment,
        install_allowed=True,
        preserve_version=installed.version,
        accepted_manifest=manifest,
        reason_code="release_verified",
        decided_at=now,
        valid_until=valid_until,
        decision_commitment=self._commitments.for_release_decision(
            update_run_id, candidate.candidate_id, candidate.manifest_digest,
            candidate.artifact_set_id, candidate.artifact_set_commitment, True,
            installed.version, manifest, "release_verified", now, valid_until,
        ),
    )
~~~

Use clean source-date/build environment, normalized archive metadata/order/permissions, immutable dependency inputs and no household environment. Bind each component package separately to the pre-signing inventory. The initial verifier is a synchronous in-process port and its decision commitment is authenticated with a Core-only HMAC key; no serialized verifier-result trust boundary exists before the authenticated decision enters the signed update journal. A positive decision is valid for at most five minutes and never beyond manifest expiry. A future out-of-process verifier requires a new fixed-domain signed envelope and key-generation contract. Attestation uses protected workflow identity; signing/account recovery is project-only and conveys no household recovery. This task must fail if a final release manifest/signature is emitted before Task 27's stapled-byte hashing. `publish.py` is not called here.

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

### Task 27: Package, sign, notarize, and qualify every declared macOS and Linux target

**Machine-access prerequisite:** Before this task begins, the owner must sign a fresh record derived from `docs/procurement/phase6-clean-mac-access.md` selecting a time-bounded borrow, rent, owner-controlled physical lab, or purchase route for both a clean supported Intel macOS target, the declared current Apple-Silicon target, and every Linux service target enabled in the signed feature manifest. The record binds exact model/OS/architecture, service-target IDs, control/isolation and wipe/restore terms, availability window, dated landed quote, and an explicit spend cap. This plan does not authorize spending or booking. The always-home production Core Mac cannot be wiped or treated as clean; hosted Macs may run synthetic package tests only. A Linux VM qualifies only when the public support declaration explicitly names virtualization and all hardware-dependent audio/HDMI/indicator gates are separately bound to the exact physical endpoint; otherwise the lifecycle must run on the selected clean physical target. Missing access leaves those receipt cells and C1 intentionally blocked rather than weakening the matrix.

**Depends on:** Task 26, Apple Developer Program credentials held outside the repository, and the approved clean-Mac access record above.
**Gate contribution:** mandatory P6-3/C1 macOS distribution.
**Estimated effort:** 1.5 person-days plus Apple/clean-machine elapsed time.

**Files:**
- Create: `ops/release/finalize.py`
- Create: `ops/release/notarize.py`
- Create: `ops/release/compatibility.py`
- Create: `ops/release/entitlements/*.plist`
- Create: `ops/release/package/*.plist`
- Create: `docs/release/compatibility-matrix.md`
- Test: `tests/security/release/test_entitlements.py`
- Test: `tests/acceptance/release/test_macos_package.py`
- Test: `tests/acceptance/release/test_final_candidate_ceremony.py`
- Test: `tests/hardware/release/test_intel_clean_install.py`
- Test: `tests/hardware/release/test_apple_silicon_clean_install.py`
- Test: `tests/hardware/release/test_linux_service_targets.py`

**Interfaces:** Consumes Task 26 build/SBOM/provenance, then in order produces Developer-ID-signed hardened-runtime Mac packages plus exact immutable Linux service artifacts, completes Apple notarization/stapling/Gatekeeper, hashes all exact final distributable bytes from frozen descriptors, and signs the final `ReleaseManifestV1`/C1 artifact inventory. `ops/release/finalize.py --source-ref HEAD --require-clean --clean-a DIR --clean-b DIR --output DIR` is the single production orchestrator: it resolves and freezes `HEAD` once, rejects a dirty/submodule-dirty/untracked source tree, builds twice from independent clean checkouts of that exact object, compares unsigned inventories, creates SBOM/provenance, signs/notarizes/staples where applicable, hashes only final bytes, writes an owner-only immutable candidate manifest, and rechecks source/ref cleanliness before returning. It produces `BuildSmokeReceiptV1`, `MacTargetReceiptV1`, `LinuxServiceTargetReceiptV1`, and one `CompatibilityManifestV1` for the supported Intel macOS target, every current Apple Silicon architecture/OS/artifact combination claimed, and exactly every enabled signed Linux service target. Developer builds are separately named/visibly non-production. Task 27 initially commits and tests this tooling; only Task 36's post-implementation invocation may produce the candidate later consumed by C0/C1.

**Rollback/disabled exit:** Missing signing/notarization/stapling/Gatekeeper, either Mac architecture's declared compatibility, or any enabled Linux service-target lifecycle blocks public production/C1. It cannot be replaced by an unsigned archive, synthetic receipt, unlisted VM, or “expected compatible” statement. A disabled Linux target is acceptable only when its production package/unit/config/account/listener/runtime and target row are all absent.

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

def test_compatibility_has_exact_enabled_linux_service_target_receipts(
    compatibility_builder, signed_feature_manifest, signed_service_inventory, linux_receipts,
) -> None:
    expected = signed_feature_manifest.enabled_linux_service_target_ids
    assert {(r.service_manifest_id, r.service_target_id) for r in linux_receipts} == expected
    matrix = compatibility_builder.build_with_linux_targets(
        signed_feature_manifest, signed_service_inventory, linux_receipts,
    )
    assert {(r.service_manifest_id, r.service_target_id) for r in matrix.linux_service_targets} == expected

def test_missing_extra_or_cross_artifact_linux_receipt_blocks_candidate(
    compatibility_builder, signed_feature_manifest, signed_service_inventory, linux_receipts,
) -> None:
    for changed in (
        linux_receipts[:-1],
        linux_receipts + (extra_undeclared_linux_receipt(),),
        replace_one_linux_receipt_artifact(linux_receipts),
    ):
        with pytest.raises(CompatibilityDenied, match="linux_service_target_matrix_mismatch"):
            compatibility_builder.build_with_linux_targets(
                signed_feature_manifest, signed_service_inventory, changed,
            )

def test_final_manifest_hashes_only_stapled_bytes(release_pipeline) -> None:
    timeline = release_pipeline.timeline
    assert timeline.index("build_sbom_provenance") < timeline.index("sign_notarize_staple")
    assert timeline.index("sign_notarize_staple") < timeline.index("hash_final_bytes_and_sign_manifest")

def test_public_smoke_receipt_cannot_qualify_real_target(compatibility_builder, smoke_receipt) -> None:
    with pytest.raises(CompatibilityDenied, match="real_hardware_lifecycle_required"):
        compatibility_builder.claim_target(smoke_receipt)

def test_compatibility_requires_both_public_smoke_architectures_on_exact_final_bytes(
    compatibility_builder, x86_smoke, arm_smoke, final_targets,
) -> None:
    manifest = compatibility_builder.build(final_targets, (x86_smoke, arm_smoke))
    assert {receipt.architecture for receipt in manifest.public_smoke_receipts} == {"x86_64", "arm64"}
    with pytest.raises(CompatibilityDenied):
        compatibility_builder.build(final_targets, (x86_smoke, x86_smoke))
    with pytest.raises(CompatibilityDenied):
        compatibility_builder.build(final_targets, (x86_smoke.with_other_artifact(), arm_smoke))

def test_final_candidate_orchestrator_rejects_dirty_or_moving_source(finalizer) -> None:
    assert finalizer.with_dirty_tracked_file().run().code == "source_not_clean"
    assert finalizer.with_untracked_file().run().code == "source_not_clean"
    assert finalizer.with_submodule_drift().run().code == "source_not_clean"
    assert finalizer.with_head_change_after_first_build().run().code == "source_changed"
    assert finalizer.production_manifests_created == 0
~~~

- [ ] **Step 2: Run red and collect hardware tests**

Run: `uv run pytest tests/security/release/test_entitlements.py tests/acceptance/release/test_macos_package.py -q && uv run pytest tests/hardware/release/test_intel_clean_install.py tests/hardware/release/test_apple_silicon_clean_install.py tests/hardware/release/test_linux_service_targets.py --collect-only -q`
Expected: software tests FAIL because package/notarization/compatibility tooling is absent; hardware tests collect and skip without explicit clean-Mac flags.

- [ ] **Step 3: Implement architecture-explicit packaging and verification pipeline**

~~~python
def verify_macos_distribution(bundle: MacPackageBundle, receipts: Sequence[MacTargetReceiptV1]) -> None:
    require(bundle.developer_id_verified and bundle.hardened_runtime_verified)
    require(bundle.entitlements == approved_minimum_entitlements())
    require(bundle.notarized and bundle.ticket_stapled and bundle.gatekeeper_accepted)
    require(any(r.architecture == "x86_64" and r.real_hardware for r in receipts))
    require(any(r.architecture == "arm64" and r.real_hardware for r in receipts))
    final_bytes = freeze_stapled_distributables(bundle)
    final_inventory = stream_hash_exact_final_bytes(final_bytes)
    require(final_inventory == bundle.expected_final_inventory)
    sign_release_manifest_and_c1_inventory(final_inventory, bundle.sbom, bundle.provenance)

def verify_linux_service_targets(
    final_inventory: FinalArtifactInventoryV1,
    feature_manifest: SignedFeatureManifestV1,
    service_inventory: SignedServiceInventoryV1,
    receipts: Sequence[LinuxServiceTargetReceiptV1],
) -> None:
    expected = feature_manifest.enabled_linux_service_target_ids
    require(service_inventory.linux_target_ids == expected)
    require({(r.service_manifest_id, r.service_target_id) for r in receipts} == expected)
    for receipt in receipts:
        target = service_inventory.require_exact_target(
            receipt.service_manifest_id, receipt.service_target_id,
        )
        require(receipt.artifact_digest == final_inventory.require_digest(target.distribution_name))
        require(receipt.service_manifest_digest == target.manifest_digest)
        require(receipt.target_kind == target.target_kind)
        require(receipt.job_or_unit_digest == target.job_or_unit_digest)
        require(receipt.config_template_digest == target.config_template_digest)
        require(receipt.real_clean_target)
    require_no_disabled_linux_target_artifacts(feature_manifest, service_inventory, final_inventory)
~~~

Package least-privilege services, plugin supervisor/sandbox profile, schemas, licences/notices and simulator without credentials/data. Verify signatures for nested code, entitlements, hardened runtime, installer scripts, Linux distribution/job-or-unit/config/service rows and uninstall manifest. Pinned public x86_64/arm64 runners perform build-and-launch smoke and emit collect-only receipts. Separately, run install, launch, simulator, upgrade from supported stable, failed-update rollback, preserve-uninstall and destructive-uninstall on current real Mac hardware for every declared architecture/OS/final-artifact digest. For every enabled Linux service target, install the exact final artifact into the declared clean target through its declared systemd, compose or Reachy-managed-app orchestrator and verify start/health, SIGTERM, crash/restart with a new generation and no replay, wrong-account/config pre-effect denial, update/rollback, both uninstall modes and zero job/account/socket/listener/runtime residue. Target receipts bind the signed service row and artifact/job-or-unit/config digests; offline target work is journaled by target ID and cannot be claimed by the Mac orchestrator without a signed return receipt. Re-downloading and changing one final byte must fail the final inventory/manifest signature.

- [ ] **Step 4: Run synthetic package checks and stage mandatory signed/clean-Mac gates**

Run: `uv run pytest tests/security/release/test_entitlements.py tests/acceptance/release/test_macos_package.py tests/acceptance/release/test_final_candidate_ceremony.py -q && uv run pytest tests/hardware/release/test_linux_service_targets.py --collect-only -q && uv run python ops/release/finalize.py --synthetic-tooling-self-test --output var/evidence/phase6/finalizer-synthetic && uv run python ops/release/compatibility.py --synthetic --output var/evidence/phase6/compatibility-synthetic.json && uv run python scripts/scan_private_data.py --paths var/evidence/phase6/finalizer-synthetic var/evidence/phase6/compatibility-synthetic.json && plutil -lint ops/release/entitlements/*.plist ops/release/package/*.plist && uv run ruff check ops/release/finalize.py ops/release/notarize.py ops/release/compatibility.py tests/security/release tests/acceptance/release tests/hardware/release`
Expected: PASS for schema/package simulation. P6-3/C1 remains blocked until Developer ID/notarization, real Intel and Apple Silicon receipts, and every signed enabled Linux service-target receipt pass under explicit flags.

- [ ] **Step 5: Commit macOS distribution tooling**

~~~bash
git add ops/release/finalize.py ops/release/notarize.py ops/release/compatibility.py ops/release/entitlements ops/release/package docs/release/compatibility-matrix.md tests/security/release/test_entitlements.py tests/acceptance/release/test_macos_package.py tests/acceptance/release/test_final_candidate_ceremony.py tests/hardware/release/test_intel_clean_install.py tests/hardware/release/test_apple_silicon_clean_install.py tests/hardware/release/test_linux_service_targets.py
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
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Create: `apps/admin/src/features/system/updates.tsx`
- Create: `apps/admin/src/routes/system-updates.tsx`
- Create: `docs/operations/phase6-update-rollback.md`
- Test: `apps/core/tests/unit/hardening/test_updater.py`
- Test: `tests/integration/release/test_atomic_update.py`
- Test: `tests/fault/release/test_update_failure_matrix.py`
- Test: `tests/ui/phase6/update-review.spec.ts`
- Modify: `tests/integration/phase6/test_owner_ingress_phase6_composition.py`
- Modify: `tests/integration/deploy/test_owner_ingress_route_manifest.py`

**Interfaces:** Produces local-only prepared update review, strict staging/verifier, an eligibility-only readiness backup, then one independently verified quiescent atomic update/run/candidate/backup/admission-barrier/source-generation-bound restore set for code plus schema/data, quarantined migrations, readiness/policy/privacy/storage/device/network probes, and a durable `UpdateRunV1` journal whose fsync-backed startup reconciliation is the only authority to expose either the accepted candidate or the exactly restored prior release.

**Rollback/disabled exit:** Any ambiguity restores prior signed code/schema/data and leaves changed features quarantined. Remote install and silent update endpoints do not exist.

- [ ] **Step 1: Write red ordering, local-only, fault, prior-version, and UI-summary tests**

~~~python
async def test_update_uses_readiness_backup_then_quiescent_restore_snapshot(harness) -> None:
    await harness.run_update()
    assert harness.timeline.index("readiness_backup_verified") < harness.timeline.index("admission_closed")
    assert harness.timeline.index("admission_closed") < harness.timeline.index("authoritative_writers_drained")
    assert harness.timeline.index("authoritative_writers_drained") < harness.timeline.index("quiescent_backup_started")
    assert harness.timeline.index("quiescent_backup_verified") < harness.timeline.index("restore_set_durable")
    assert harness.timeline.index("restore_set_durable") < harness.timeline.index("install_started")

@pytest.mark.parametrize("fault", [
    "download_oversize", "wrong_type", "verify_failure", "backup_failure", "drain_timeout",
    "migration_interrupt", "readiness_failure", "privacy_failure", "listener_failure",
    "device_failure", "post_install_health_failure", "journal_corrupt", "restore_set_missing",
    "restore_set_commitment_mismatch", "restore_set_cross_run_replay", "second_nonterminal_journal",
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
    assert "readiness_backup_started" not in harness.timeline
    assert "quiescent_backup_started" not in harness.timeline
    assert "admission_closed" not in harness.timeline
    assert "install_started" not in harness.timeline

@pytest.mark.parametrize("field", [
    "update_run_id", "candidate_id", "candidate_manifest_digest", "artifact_set_id",
    "artifact_set_commitment",
    "install_allowed", "preserve_version", "accepted_manifest", "reason_code", "decided_at",
    "valid_until", "decision_commitment",
])
async def test_release_decision_one_field_substitution_stops_before_backup_or_drain(harness, field) -> None:
    run, staged, decision = await harness.prepared_verified_candidate()
    result = await harness.resume_with_decision(run, staged, mutate_one_field(decision, field))
    assert result.state in {"rejected", "quarantined"}
    assert "readiness_backup_started" not in harness.timeline
    assert "admission_closed" not in harness.timeline
    assert "install_started" not in harness.timeline

async def test_expired_release_decision_stops_before_backup_or_drain(harness) -> None:
    run, staged, decision = await harness.prepared_verified_candidate()
    harness.clock.advance_to(decision.valid_until)
    result = await harness.resume_with_decision(run, staged, decision)
    assert result.state in {"rejected", "quarantined"}
    assert "readiness_backup_started" not in harness.timeline
    assert "admission_closed" not in harness.timeline

async def test_authenticated_future_dated_release_decision_stops_before_backup_or_drain(harness) -> None:
    run, staged, decision = await harness.prepared_candidate_with_authenticated_future_decision()
    result = await harness.resume_with_decision(run, staged, decision)
    assert result.state in {"rejected", "quarantined"}
    assert "readiness_backup_started" not in harness.timeline
    assert "admission_closed" not in harness.timeline

async def test_decision_expiry_during_readiness_backup_rejects_before_drain(harness) -> None:
    before = harness.installed_snapshot()
    result = await harness.expire_verified_decision_at("during_readiness_backup")
    assert result.state == "rejected"
    assert harness.installed_snapshot() == before
    assert "admission_closed" not in harness.timeline
    assert harness.authoritative_admission_open

@pytest.mark.parametrize("boundary", [
    "during_authoritative_writer_drain", "during_quiescent_backup",
    "after_restore_set_cas_before_code_switch",
])
async def test_decision_expiry_during_drain_or_snapshot_never_reaches_code_switch(harness, boundary) -> None:
    before = harness.installed_snapshot()
    result = await harness.expire_verified_decision_at(boundary)
    assert result.state in {"rolled_back", "quarantined"}
    assert harness.installed_snapshot() == before
    assert "code_switch_started" not in harness.timeline
    assert harness.authoritative_admission_open == (result.state == "rolled_back")

async def test_cross_candidate_or_replayed_verified_decision_cannot_authorize_update(harness) -> None:
    old_run, _, old_decision = await harness.prepared_verified_candidate(candidate="old")
    new_run, new_staged, _ = await harness.prepared_verified_candidate(candidate="new")
    result = await harness.resume_with_decision(new_run, new_staged, old_decision)
    assert result.state in {"rejected", "quarantined"}
    assert old_decision.update_run_id == old_run.update_run_id
    assert "readiness_backup_started" not in harness.timeline_for(new_run.update_run_id)
    assert "admission_closed" not in harness.timeline_for(new_run.update_run_id)

@pytest.mark.parametrize("field", [
    "candidate_id", "manifest_digest", "artifact_set_id", "artifact_set_commitment",
])
async def test_prepared_staged_candidate_drift_denies_before_verifier_or_backup(harness, field) -> None:
    prepared = harness.prepared_update()
    staged = mutate_one_field(await harness.stage(prepared), field)
    result = await harness.install_prepared_with_staged(prepared, staged)
    assert result.state == "rejected"
    assert harness.release_verifier_calls == ()
    assert "readiness_backup_started" not in harness.timeline
    assert "admission_closed" not in harness.timeline

@pytest.mark.parametrize("path", [
    "/api/v1/releases/prepare", "/api/v1/releases/install", "/api/v1/releases/rollback",
])
def test_remote_cannot_prepare_install_or_rollback_update(remote_client, path) -> None:
    response = remote_client.post(path)
    assert response.status_code in {403, 404}
    if response.status_code == 403:
        assert response.json()["code"] == "REMOTE_OPERATION_DENIED"

@pytest.mark.parametrize("trigger", [
    "scheduler", "startup", "config_import", "remote_replay", "plugin", "ci_callback",
])
async def test_no_silent_or_automatic_update_trigger_exists(harness, trigger) -> None:
    before = harness.installed_snapshot()
    result = await harness.attempt_nonlocal_or_automatic_update(trigger)
    assert result.code in {"FEATURE_ABSENT", "REMOTE_OPERATION_DENIED", "POLICY_DENIED"}
    assert harness.installed_snapshot() == before
    assert harness.update_journals == ()
    assert "download_started" not in harness.timeline

@pytest.mark.parametrize("boundary", ALL_UPDATE_DURABILITY_BOUNDARIES)
async def test_sigkill_or_power_loss_reconciles_before_any_service(harness, boundary) -> None:
    await harness.crash_update(boundary=boundary)
    restarted = await harness.restart()
    assert restarted.timeline.index("update_journal_reconciled") < restarted.timeline.index("first_service_exposed")
    assert restarted.update_state in {"accepted", "rejected", "rolled_back", "quarantined"}
    assert restarted.nonterminal_update_journals == ()

async def test_restart_reverifies_durable_positive_decision_before_continuing(harness) -> None:
    run = await harness.crash_update(boundary="after_verified_decision_journal_fsync")
    restarted = await harness.restart()
    persisted = restarted.update_journal.require(run.update_run_id)
    assert persisted.verified_decision is not None
    assert persisted.verified_decision.update_run_id == persisted.update_run_id
    assert persisted.verified_decision.candidate_id == persisted.candidate_id
    assert persisted.verified_decision.candidate_manifest_digest == persisted.candidate_manifest_digest
    assert persisted.verified_decision.artifact_set_id == persisted.candidate_artifact_set_id
    assert persisted.verified_decision.artifact_set_commitment == persisted.candidate_artifact_set_commitment
    assert restarted.release_decision_authenticator.verified(persisted.verified_decision)
    assert persisted.verified_decision.decided_at <= restarted.clock.now() < persisted.verified_decision.valid_until
    assert restarted.staged_candidate_matches_run(persisted)

@pytest.mark.parametrize("fault", [
    "expired_decision", "one_field_decision_substitution", "cross_candidate_decision",
    "staged_candidate_id_drift", "staged_manifest_digest_drift",
    "staged_artifact_set_id_drift", "staged_artifact_set_commitment_drift",
])
async def test_restart_rejects_stale_or_unbound_durable_decision_before_backup_or_drain(harness, fault) -> None:
    run = await harness.crash_update(boundary="after_verified_decision_journal_fsync")
    restarted = await harness.restart_with_durable_update_fault(run.update_run_id, fault)
    assert restarted.update_state in {"rejected", "quarantined"}
    assert "readiness_backup_started" not in restarted.timeline
    assert "admission_closed" not in restarted.timeline
    assert restarted.open_effect_routes == ()

@pytest.mark.parametrize("fault", [
    "drain_timeout", "quiescent_backup_error", "decision_expired_after_admission_closed",
])
async def test_typed_live_failure_is_fsynced_and_reconciled_before_install_returns(harness, fault) -> None:
    before = harness.installed_snapshot()
    result = await harness.update_with_fault(fault, keep_process_alive=True)
    assert harness.timeline.index("recoverable_failure_fsynced") < harness.timeline.index("same_process_reconciliation_started")
    assert harness.timeline.index("same_process_reconciliation_finished") < harness.timeline.index("install_returned")
    assert result.state in {"rejected", "rolled_back", "quarantined"}
    assert harness.installed_snapshot() == before
    assert harness.authoritative_admission_open == (result.state in {"rejected", "rolled_back"})

async def test_crash_in_live_failure_handler_keeps_admission_closed_until_startup_reconciliation(harness) -> None:
    before = harness.installed_snapshot()
    await harness.crash_update(boundary="after_recoverable_failure_fsync_before_live_reconcile")
    assert not harness.authoritative_admission_open
    restarted = await harness.restart()
    assert restarted.timeline.index("update_journal_reconciled") < restarted.timeline.index("authoritative_admission_reopened")
    assert restarted.update_state in {"rejected", "rolled_back", "quarantined"}
    assert restarted.installed_snapshot() == before
    assert restarted.authoritative_admission_open == (restarted.update_state in {"rejected", "rolled_back"})

async def test_interrupted_inverse_transition_stays_quarantined(harness) -> None:
    await harness.crash_rollback(after="rollback_schema_parent_fsync")
    restarted = await harness.restart()
    assert restarted.update_state == "quarantined"
    assert restarted.open_listeners_workers_schedulers_effect_routes == ()

def test_update_state_graph_rejects_skip_reorder_and_sequence_race(journal) -> None:
    run = journal.create_prepared()
    with pytest.raises(UpdateTransitionDenied):
        journal.transition_cas(run, expected_state="prepared", expected_sequence=1, next_state="code_switched")
    downloaded = journal.transition_cas(
        run, expected_state="prepared", expected_sequence=1, next_state="download_verified",
    )
    with pytest.raises(UpdateTransitionDenied):
        journal.transition_cas(
            downloaded, expected_state="download_verified", expected_sequence=2,
            next_state="restore_points_durable",
        )
    with pytest.raises(UpdateTransitionDenied):
        journal.transition_cas(
            downloaded, expected_state="download_verified", expected_sequence=1,
            next_state="services_drained",
        )

@pytest.mark.parametrize("mutation", [
    "payload_byte", "payload_digest", "journal_commitment", "signature", "signer_key_id",
    "signer_key_generation", "signature_domain", "noncanonical_json",
])
def test_update_journal_mutation_rejects_before_state_use(journal_bytes, mutation) -> None:
    with pytest.raises(UpdateJournalDenied):
        read_and_verify_update_journal(mutate_journal(journal_bytes, mutation))

def test_terminal_retry_is_idempotent_and_multiple_current_runs_quarantine(harness) -> None:
    accepted = harness.accepted_run()
    assert harness.transition(accepted, "accepted") == accepted
    assert harness.restart_with_two_current_runs().update_state == "quarantined"

def test_update_transition_cannot_precede_run_start(update_run_payload) -> None:
    with pytest.raises(ValidationError, match="update_transition_precedes_start"):
        UpdateRunV1.model_validate(update_run_payload.with_transitioned_at(update_run_payload.started_at - timedelta(microseconds=1)))

@pytest.mark.parametrize("field", [
    "update_run_id", "candidate_id", "candidate_manifest_digest",
    "candidate_artifact_set_id", "candidate_artifact_set_commitment", "backup_set_id",
    "admission_barrier_generation",
    "source_generation",
    "prior_release_manifest_digest", "prior_code_tree_digest", "prior_schema_head",
    "encrypted_database_snapshot_digest", "deletion_watermark", "feature_manifest_digest",
    "restore_set_commitment",
])
async def test_restore_set_one_field_substitution_or_cross_run_replay_quarantines(harness, field) -> None:
    run, restore_set = await harness.prepared_update_with_atomic_restore_set()
    substituted = harness.substitute_restore_set_field(restore_set, field)
    result = await harness.try_attach_restore_set(run, substituted)
    assert result.state == "quarantined"
    assert harness.open_listeners_workers_schedulers_effect_routes == ()

async def test_concurrent_backup_cannot_change_source_generation_inside_restore_set(harness) -> None:
    run = await harness.create_prepared_update()
    waiting = harness.begin_restore_set_creation(run)
    await harness.complete_newer_backup_generation()
    result = await waiting
    assert result.state == "quarantined"
    assert harness.restore_set_for(run.update_run_id) is None

@pytest.mark.parametrize("writer", [
    "conversation", "memory", "action", "audit", "deletion", "feature_registry",
])
async def test_write_racing_drain_is_committed_before_snapshot_or_rejected_without_loss(harness, writer) -> None:
    racing_write = harness.begin_authoritative_write(writer)
    update = harness.begin_update()
    write_result, update_result = await harness.release_race_and_wait(racing_write, update)
    if write_result.committed:
        assert write_result.generation <= update_result.restore_set.source_generation
        assert harness.quiescent_backup_contains(write_result.commitment)
    else:
        assert write_result.code == "UPDATE_ADMISSION_CLOSED"
        assert not harness.authoritative_store_contains(write_result.commitment)

@pytest.mark.parametrize("boundary", [
    "after_admission_closed", "after_authoritative_writers_drained",
    "during_quiescent_backup", "after_quiescent_backup_before_restore_set_cas",
    "after_restore_set_cas_before_code_switch",
])
async def test_restart_at_quiescent_snapshot_boundaries_never_loses_committed_write(harness, boundary) -> None:
    before = harness.commit_authoritative_sentinel()
    await harness.crash_update(boundary=boundary)
    restarted = await harness.restart()
    assert restarted.authoritative_store_contains(before.commitment)
    assert restarted.update_state in {"rejected", "rolled_back", "quarantined"}
    assert restarted.first_service_exposed_after_update_reconciliation

async def test_recoverable_install_exception_reconciles_before_same_process_return(harness) -> None:
    result = await harness.update_with_fault("post_code_switch_recoverable_exception", keep_process_alive=True)
    assert harness.timeline.index("recoverable_failure_fsynced") < harness.timeline.index("same_process_reconciliation_started")
    assert harness.timeline.index("same_process_reconciliation_finished") < harness.timeline.index("install_returned")
    assert result.state in {"rolled_back", "quarantined"}
    assert harness.open_effect_routes == ()

@pytest.mark.parametrize("operation", [
    "fetch_staged_candidate", "readiness_backup", "close_and_drain",
    "quiescent_backup", "restore_set_fsync_and_cas", "switch_code_namespace",
    "journal_code_switched_fsync", "journal_schema_migrating_fsync",
    "run_quarantined_migrations", "journal_schema_migrated_fsync",
    "journal_health_verifying_fsync", "run_post_migration_probes",
    "journal_accepted_parent_fsync",
])
async def test_each_expected_operational_failure_is_typed_and_reconciled(harness, operation) -> None:
    result = await harness.fail_named_adapter_operation(operation, OSError("synthetic I/O"))
    assert harness.adapter_error_seen_by_updater.__class__.__name__ in EXPECTED_UPDATE_ERROR_TYPES
    assert harness.timeline.index("recoverable_failure_fsynced") < harness.timeline.index("same_process_reconciliation_started")
    assert result.state in {"rejected", "rolled_back", "quarantined"}

async def test_programmer_and_cancellation_failures_are_never_normalized(harness) -> None:
    with pytest.raises(ValueError, match="programmer fault"):
        await harness.fail_named_adapter_operation("run_quarantined_migrations", ValueError("programmer fault"))
    assert harness.authoritative_admission_open is False
    with pytest.raises(asyncio.CancelledError):
        await harness.fail_named_adapter_operation("run_post_migration_probes", asyncio.CancelledError())


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/v1/releases/update-review"),
    ("POST", "/api/v1/releases/update-prepare"),
])
def test_installed_local_update_routes_dispatch_once_from_signed_manifest(
    installed_owner_ingress, method, path,
) -> None:
    result = installed_owner_ingress.local_request(method, path, feature_enabled=True)
    assert result.status_code in {200, 201}
    assert result.core_uds_dispatch_count == 1


@pytest.mark.parametrize("state", ["unknown", "disabled"])
def test_unknown_or_disabled_update_route_is_404_before_dispatch(
    installed_owner_ingress, state,
) -> None:
    result = installed_owner_ingress.local_request(
        "GET", "/api/v1/releases/update-review", route_state=state,
    )
    assert result.status_code == 404
    assert result.body_read_count == 0
    assert result.core_uds_dispatch_count == 0
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/core/tests/unit/hardening/test_updater.py tests/integration/release/test_atomic_update.py tests/fault/release/test_update_failure_matrix.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py -q && pnpm --filter @tuntun/admin e2e -- tests/ui/phase6/update-review.spec.ts`
Expected: FAIL because updater/API/UI and failure state machine are absent.

- [ ] **Step 3: Implement the complete durable update/rollback graph and truthful UI**

~~~python
class UpdateExpectedBoundaryError(Exception):
    """Documented hostile/environmental update boundary; never programmer failure."""

class StagedCandidateBindingError(UpdateExpectedBoundaryError): ...
class ReleaseDecisionBindingError(UpdateExpectedBoundaryError): ...
class RecoverableUpdateError(UpdateExpectedBoundaryError): ...
class UpdateDownloadError(RecoverableUpdateError): ...
class ReadinessBackupError(RecoverableUpdateError): ...
class AdmissionDrainError(RecoverableUpdateError): ...
class QuiescentSnapshotError(RecoverableUpdateError): ...
class RestoreSetDurabilityError(RecoverableUpdateError): ...
class CodeNamespaceSwitchError(RecoverableUpdateError): ...
class UpdateJournalDurabilityError(RecoverableUpdateError): ...
class QuarantinedMigrationError(RecoverableUpdateError): ...
class UpdateHealthProbeError(RecoverableUpdateError): ...

async def install(self, prepared: PreparedUpdate, local_owner: LocalOwnerApproval) -> UpdateReceipt:
    async with self._global_update_lock.acquire_fail_closed():
        await self._journal.reconcile_all_before_service_exposure()
        self._auth.consume_local_owner_action_bound(prepared, local_owner)
        run = await self._journal.create_prepared_durable(
            candidate_id=prepared.candidate_id,
            candidate_manifest_digest=prepared.manifest_digest,
            candidate_artifact_set_id=prepared.artifact_set_id,
            candidate_artifact_set_commitment=prepared.artifact_set_commitment,
        )
        try:
            return await self._install_prepared_run_under_held_global_lock(run, prepared)
        except RecoverableUpdateError as error:
            # Persist the failure before invoking the one shared live/startup reconciler. The
            # catch is deliberately typed; programmer errors are not misreported as rollback.
            failed = await self._journal.record_recoverable_failure_fsync(
                update_run_id=run.update_run_id,
                reason_code=safe_release_reason(error),
            )
            return await self._journal.reconcile_run_under_held_global_lock(failed)
        finally:
            # This reloads the journal. It reopens authoritative admissions only for a fully
            # reconciled accepted/rejected/rolled_back terminal; otherwise it leaves the
            # durable fail-closed gate owned by startup reconciliation.
            await self._authoritative_writers.reconcile_admission_gate_from_journal(
                run.update_run_id,
            )

async def _install_prepared_run_under_held_global_lock(
    self, run: UpdateRunV1, prepared: PreparedUpdate,
) -> UpdateReceipt:
        staged = await self._downloads.fetch_bounded_unprivileged(prepared.source)
        try:
            self._staging.require_exact_prepared_identity(
                staged,
                candidate_id=run.candidate_id,
                manifest_digest=run.candidate_manifest_digest,
                artifact_set_id=run.candidate_artifact_set_id,
                artifact_set_commitment=run.candidate_artifact_set_commitment,
            )
        except StagedCandidateBindingError as error:
            return await self._journal.reject_before_install_and_preserve_prior(
                run, safe_release_reason(error),
            )
        decision = self._verifier.verify(
            staged, self._installed.current(), update_run_id=run.update_run_id,
        )
        try:
            decision_now = self._clock.now()
            self._release_decisions.require_exact_authenticated(
                decision,
                update_run_id=run.update_run_id,
                candidate_id=run.candidate_id,
                candidate_manifest_digest=run.candidate_manifest_digest,
                artifact_set_id=run.candidate_artifact_set_id,
                artifact_set_commitment=run.candidate_artifact_set_commitment,
                observed_at=decision_now,
            )
        except ReleaseDecisionBindingError as error:
            return await self._journal.reject_before_install_and_preserve_prior(
                run, safe_release_reason(error),
            )
        if not decision.install_allowed:
            return await self._journal.reject_before_install_and_preserve_prior(run, decision.reason_code)
        manifest = require_not_none(decision.accepted_manifest)
        run = await self._journal.transition_cas(
            run, expected_state="prepared", expected_sequence=1, next_state="download_verified",
            verified_decision=decision,
        )
        await self._backups.create_and_verify_readiness_backup(manifest)  # Eligibility only; never rollback authority.
        try:
            self._release_decisions.require_exact_authenticated(
                decision,
                update_run_id=run.update_run_id,
                candidate_id=run.candidate_id,
                candidate_manifest_digest=run.candidate_manifest_digest,
                artifact_set_id=run.candidate_artifact_set_id,
                artifact_set_commitment=run.candidate_artifact_set_commitment,
                observed_at=self._clock.now(),
            )
        except ReleaseDecisionBindingError as error:
            return await self._journal.reject_before_install_and_preserve_prior(
                run, safe_release_reason(error),
            )
        barrier = await self._authoritative_writers.close_admission_and_drain_without_replay()
        run = await self._journal.transition_cas(
            run, expected_state="download_verified", expected_sequence=2,
            next_state="services_drained",
            expected_admission_barrier_generation=barrier.generation,
        )
        async with self._authoritative_writers.hold_quiescent_snapshot_gate(barrier) as frozen:
            # The durable gate blocks new authoritative writers, but no SQLCipher writer transaction
            # is held across filesystem backup I/O.
            backup = await self._backups.create_and_independently_verify_quiescent(frozen)
            restore_set = await self._installer.create_atomic_restore_set_durable(
                update_run_id=run.update_run_id,
                candidate_id=run.candidate_id,
                candidate_manifest_digest=run.candidate_manifest_digest,
                candidate_artifact_set_id=run.candidate_artifact_set_id,
                candidate_artifact_set_commitment=run.candidate_artifact_set_commitment,
                backup=backup,
                admission_barrier_generation=barrier.generation,
                source_generation=frozen.source_generation,
            )
            run = await self._journal.transition_cas(
                run, expected_state="services_drained", expected_sequence=3,
                next_state="restore_points_durable", restore_set=restore_set,
                expected_admission_barrier_generation=barrier.generation,
                expected_source_generation=frozen.source_generation,
                expected_deletion_watermark=frozen.deletion_watermark,
                expected_feature_manifest_digest=frozen.feature_manifest_digest,
            )
        try:
            # The drain/snapshot may consume the remaining decision lifetime. Recheck both the
            # immutable staged bytes and authenticated decision at the last pre-switch boundary.
            self._staging.require_exact_prepared_identity(
                staged,
                candidate_id=run.candidate_id,
                manifest_digest=run.candidate_manifest_digest,
                artifact_set_id=run.candidate_artifact_set_id,
                artifact_set_commitment=run.candidate_artifact_set_commitment,
            )
            self._release_decisions.require_exact_authenticated(
                decision,
                update_run_id=run.update_run_id,
                candidate_id=run.candidate_id,
                candidate_manifest_digest=run.candidate_manifest_digest,
                artifact_set_id=run.candidate_artifact_set_id,
                artifact_set_commitment=run.candidate_artifact_set_commitment,
                observed_at=self._clock.now(),
            )
        except (StagedCandidateBindingError, ReleaseDecisionBindingError) as error:
            # At restore_points_durable the shared reconciler follows rollback_verifying; it
            # verifies the unchanged prior release before reopening admission and never switches.
            raise RecoverableUpdateError(safe_release_reason(error)) from error
        candidate = await self._installer.switch_code_namespace_durable(staged, run)
        run = await self._journal.transition_cas(
            run, expected_state="restore_points_durable", expected_sequence=4, next_state="code_switched",
        )
        run = await self._journal.transition_cas(
            run, expected_state="code_switched", expected_sequence=5, next_state="schema_migrating",
        )
        await self._migrations.run_in_quarantine(candidate, run=run)
        run = await self._journal.transition_cas(
            run, expected_state="schema_migrating", expected_sequence=6, next_state="schema_migrated",
        )
        run = await self._journal.transition_cas(
            run, expected_state="schema_migrated", expected_sequence=7, next_state="health_verifying",
        )
        await self._probes.require_all(candidate, groups=("readiness", "policy", "privacy", "storage", "device", "network"))
        return await self._journal.transition_cas(
            run, expected_state="health_verifying", expected_sequence=8, next_state="accepted",
            require_all_parent_fsyncs=True, keep_prior=True,
        )
~~~

The updater consumes only `ReleaseDecisionV1`. Before even calling the verifier it exact-compares staged candidate ID, canonical manifest digest, artifact-set ID and artifact-set commitment with the prepared update and durable run. It then authenticates the Core-HMAC decision and exact-compares its update-run/candidate/manifest/artifact-set bindings plus `decided_at <= observed_at < valid_until`; stale, future, replayed, cross-candidate or one-field-substituted decisions reject before readiness backup. A positive decision is journaled inside `UpdateRunV1` at `download_verified`; restart re-authenticates its bounded time and every binding, then rechecks the unchanged staged candidate before continuing. The same current-time/authentication check repeats after the readiness backup and before admission closure, so expiry during backup rejects before drain. A deny decision returns before backup, drain, migration or installer I/O. The early readiness backup proves storage/crypto eligibility only and is never rollback authority. After update admission closes and every authoritative writer drains, a durable global snapshot gate blocks new writers without holding a SQLCipher writer transaction across filesystem I/O. Only the backup captured and independently verified inside that quiescent interval may enter the restore set. The attach CAS repeats the admission-barrier, source, deletion-watermark and feature-manifest generations; immediately after that CAS and before code switch, the updater again exact-checks the immutable staged identity and current authenticated decision. Expiry or substitution during drain/snapshot enters rollback verification without switching code. The restore set is one committed object bound to this update-run ID, candidate ID/manifest/artifact-set ID and commitment, verified backup-set ID, admission-barrier generation and source generation; code and schema/data cannot be paired from different releases, backups, runs, barriers or feature/deletion states. Its commitment is verified before every forward or inverse transition.

Every download, backup, admission/drain, snapshot, restore-set, installer, journal, migration and probe adapter has an explicit protocol contract: it translates only its documented `OSError`, timeout, corruption, durability, migration or health failure into the matching hierarchy member above at the adapter boundary. `switch_code_namespace_durable`, every journal fsync/CAS, quarantined migration and every post-migration probe therefore reaches the same outer `RecoverableUpdateError` handler. Adapter conformance tests inject each named raw operational failure directly and assert the exact translation; `CancelledError`, `TypeError`, `KeyError`, `ValueError`, assertion failures and other programmer defects are never translated or caught. The outer handler fsyncs the typed failure and immediately invokes the same live/startup reconciler under the held global lock before returning. Its `finally` reloads durable state and reopens authoritative admission only for a fully reconciled `accepted`, `rejected`, or `rolled_back` terminal; handler failure, cancellation or process death leaves admission closed for startup reconciliation. A broad exception is never rollback evidence. The reconciler restores code and schema/data from that one independently verified restore set, fsyncs each inverse namespace, reruns migration/privacy/network/health probes in quarantine, and records `rolled_back` before exposing services. A crash before the restore-set CAS reopens the unchanged prior release only after journal reconciliation; it never treats the readiness backup as a restore point. UI shows signer/digest/version/security notes/features/migrations/data-egress changes/compatibility/pre-backup/restart/rollback limits, then requires local owner passkey. It never auto-installs. Prior package stays until configured soak; rollback UI shows restored code/schema/health and quarantined features.

Register only the local-console rows `GET /api/v1/releases/update-review` and `POST /api/v1/releases/update-prepare` through the canonical Core app/container, owner-ingress router and signed route manifest. The signed listener/origin policy makes both absent to remote origin, and no install or rollback HTTP row exists. Installed-candidate composition proves enabled local rows dispatch once over the peer-authenticated Core UDS; unknown, disabled, duplicate or unsigned rows are 404 before body read or UDS I/O.

- [ ] **Step 4: Run green, exhaustive failure matrix, UI/accessibility, and remote absence**

Run: `uv run pytest apps/core/tests/unit/hardening/test_updater.py tests/integration/release/test_atomic_update.py tests/fault/release/test_update_failure_matrix.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py -q && pnpm --filter @tuntun/admin e2e -- tests/ui/phase6/update-review.spec.ts && uv run python scripts/check_feature_absence.py --feature remote_update_install --phase 6 && pnpm --filter @tuntun/admin typecheck && pnpm --filter @tuntun/admin build && uv run ruff check apps/core/src/tuntun_core/services/hardening/updater.py tests/integration/release tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/fault/release && uv run mypy apps/core/src`
Expected: PASS; every injected failure either restores the exact prior state or remains quarantined, every restart reconciles before any service exposure, the remote route is absent, and UI exposes rollback truth.

- [ ] **Step 5: Commit updater and rollback**

~~~bash
git add apps/core/src/tuntun_core/services/hardening/updater.py apps/core/src/tuntun_core/api/routes/releases.py apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json apps/admin/src/features/system/updates.tsx apps/admin/src/routes/system-updates.tsx docs/operations/phase6-update-rollback.md apps/core/tests/unit/hardening/test_updater.py tests/integration/release/test_atomic_update.py tests/fault/release/test_update_failure_matrix.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/ui/phase6/update-review.spec.ts
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(update): install atomically or restore prior release"
~~~

### Task 29: Verify clean install, upgrade, rollback, both uninstall modes, and P6-3 go/no-go

**Depends on:** Tasks 08–28 and mandatory real plugin sandbox/signing/platform receipts.
**Gate contribution:** completes P6-3.
**Estimated effort:** 1.5 person-days plus clean-machine runs.

**Files:**
- Create: `ops/install/uninstall.py`
- Create: `ops/install/uninstall_journal.py`
- Modify: `ops/install/verify_clean_system.py`
- Create: `docs/operations/phase6-retirement-uninstall.md`
- Create: `tests/acceptance/release/test_install_upgrade_rollback_uninstall.py`
- Create: `tests/security/release/test_uninstall_residue.py`
- Create: `tests/fault/release/test_uninstall_failure_matrix.py`
- Create: `tests/acceptance/phase6/test_p6_3_gate.py`
- Create: `docs/evidence/phase6-p6-3-schema.json`
- Create: `docs/evidence/uninstall-run-v1.schema.json`
- Modify: `ops/services/phase3-owner-ingress.v1.json`
- Modify: `tests/integration/vision/test_deployed_process_entrypoints.py`
- Modify: `tests/integration/deploy/test_phase3_side_process_lifecycle.py`
- Modify: `tests/integration/deploy/test_owner_ingress_route_manifest.py`
- Modify: `tests/integration/vision/test_owner_ingress_takeover.py`
- Modify: `tests/fault/vision/test_owner_ingress_takeover_rollback.py`
- Modify: `tests/integration/plugins/test_supervisor_service_lifecycle.py`
- Modify: `tests/integration/phase6/test_owner_ingress_phase6_composition.py`

**Interfaces:** Produces clean install/upgrade/rollback plus `preserve_encrypted_data` and `destroy_managed_data` uninstall receipts, and a P6-3 decision binding exact two plugin paths, sandbox, build/SBOM/provenance/signature/notarization, Intel/Apple-Silicon compatibility, every enabled Linux service-target receipt and private scans. Install/update/uninstall derive their service set from the signed exact `ops/services/*.v1.json` inventory included in the release manifest; the expected target tuple set comes only from the signed feature manifest, never host discovery. The closed known family set is `phase1-reachy-edge.v1`; `phase3-camera-source.v1`, `phase3-recorder.v1`, `phase3-media-proxy.v1`, `phase3-owner-ingress.v1`; `phase4-room-node.v1`, `phase4-display-agent.v1`; `phase5-inference-proxy.v1`, `phase5-desktop-helper.v1`, `phase5-perception-proxy.v1`, `phase5-robot-edge.v1`; and `phase6-network-boundary.v1`, `phase6-plugin-supervisor.v1`. Conditional targets are required exactly when enabled and a zero-target family has no row. Before authority consumption, `PreparedUninstallV1` freezes the release-manifest digest, complete signed service-inventory digest, exact pre-resolved owned path/identity set, mode, and—only for destroy—the exact managed-key/data-set commitment. A signed, fsync-backed `UninstallRunV1` journal and one global uninstall lock make every removal, crypto-shred and receipt boundary idempotently restartable. A packaged service absent from that inventory, an inventory entry absent from the package, or post-uninstall job/account/socket/runtime residue fails the lifecycle. The Mac orchestrator removes only Mac-owned targets; Reachy/Linux/Pi/appliance targets return signed idempotent target-orchestrator/retirement receipts, remain pending while offline, and can never cause cross-target path deletion.

**Rollback/disabled exit:** Failed install/update preserves prior version. Uninstall never guesses after a crash: before the durable irreversible boundary it remains pending with runtime admission closed; after `crypto_shred_committed`, destroy mode cannot revert to preserve and every restart must finish the exact committed shred/remove set before a receipt. Failed P6-3 blocks public candidate. Unrelated vendor data and preserved archives are never deleted.

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
    assert decide_p6_3(evidence.without_one_enabled_linux_service_target_receipt()).denied

def test_install_and_uninstall_cover_every_signed_service_inventory(harness) -> None:
    expected = harness.release_manifest.signed_service_inventory_ids
    known = {
        "phase1-reachy-edge.v1",
        "phase3-camera-source.v1", "phase3-recorder.v1",
        "phase3-media-proxy.v1", "phase3-owner-ingress.v1",
        "phase4-room-node.v1", "phase4-display-agent.v1",
        "phase5-inference-proxy.v1", "phase5-desktop-helper.v1",
        "phase5-perception-proxy.v1", "phase5-robot-edge.v1",
        "phase6-network-boundary.v1", "phase6-plugin-supervisor.v1",
    }
    assert expected == harness.feature_manifest.enabled_service_family_ids
    assert expected <= known
    assert {"phase6-network-boundary.v1", "phase6-plugin-supervisor.v1"} <= expected
    installed = harness.install().service_inventory_ids
    assert installed == expected
    receipt = harness.uninstall(mode="preserve_encrypted_data")
    assert receipt.removed_service_inventory_ids == expected
    assert harness.jobs_accounts_sockets_runtime_residue_for(expected) == ()

def test_signed_target_tuples_match_every_lifecycle_and_never_cross_cleanup(harness) -> None:
    expected = harness.feature_manifest.enabled_service_target_tuples
    assert harness.install().installed_target_tuples == expected
    assert harness.update().updated_target_tuples == expected
    assert harness.rollback().restored_target_tuples == expected
    receipt = harness.uninstall(mode="preserve_encrypted_data")
    assert receipt.removed_target_tuples == expected
    assert harness.target_orchestrator_receipts_cover(expected)
    assert harness.cross_target_cleanup_attempts == ()

def test_offline_remote_target_keeps_uninstall_pending_without_false_receipt(harness) -> None:
    target = harness.one_enabled_remote_target()
    result = harness.uninstall_with_target_offline(target)
    assert result.state == "pending_or_quarantined"
    assert harness.uninstall_receipts == ()
    assert harness.restart_and_retry_target(target).removed_target_tuples == (
        harness.feature_manifest.enabled_service_target_tuples
    )

def test_p6_3_owner_ingress_checkpoint_binds_current_wheel_and_route_manifest(
    p6_3_owner_ingress_wheel, p6_3_route_manifest, p6_2_owner_ingress_row,
    p6_3_owner_ingress_row, service_verifier,
) -> None:
    assert service_verifier.verify(
        p6_2_owner_ingress_row, p6_3_owner_ingress_wheel, p6_3_route_manifest,
    ).denied
    assert service_verifier.verify(
        p6_3_owner_ingress_row, p6_3_owner_ingress_wheel, p6_3_route_manifest,
    ).accepted
    assert p6_3_owner_ingress_row.package_digest == p6_3_owner_ingress_wheel.digest
    assert p6_3_owner_ingress_row.route_manifest_digest == p6_3_route_manifest.digest

def test_p6_3_installed_owner_ingress_and_supervisor_rows_have_current_lifecycle_receipts(
    installed_candidate,
) -> None:
    assert installed_candidate.owner_ingress.all_signed_phase6_routes_dispatch_once
    assert installed_candidate.owner_ingress.unknown_and_disabled_routes_are_404
    assert installed_candidate.owner_ingress.takeover_restart_update_rollback_both_uninstalls_pass
    assert installed_candidate.plugin_supervisor.row_matches_task21_final_wheel
    assert installed_candidate.plugin_supervisor.old_task20_row_and_receipt_rejected

@pytest.mark.parametrize("edge", ["before", "after"])
@pytest.mark.parametrize("step", [
    "authority_consumed", "each_service_removed", "network_removed", "plugins_removed",
    "temporary_removed", "crypto_shred_committed", "each_key_shredded",
    "managed_data_removed", "residue_verified", "receipt_fsynced",
])
def test_uninstall_crash_restart_resumes_exactly_once_without_ambiguous_receipt(
    harness, step, edge,
) -> None:
    run_id = harness.crash_uninstall_at(step, edge, mode="destroy_managed_data")
    assert harness.receipt_for(run_id) is None
    receipt = harness.restart_and_resume_uninstall(run_id)
    assert receipt.run_id == run_id
    assert harness.removal_attempts_are_idempotent_for_exact_owned_set(run_id)
    assert harness.jobs_accounts_sockets_runtime_residue_for(
        harness.release_manifest.signed_service_inventory_ids,
    ) == ()

def test_destroy_mode_is_irreversible_only_after_durable_shred_commit(harness) -> None:
    before = harness.crash_before("crypto_shred_committed")
    assert harness.resume_or_cancel_without_key_loss(before).managed_keys_intact
    after = harness.crash_after("crypto_shred_committed")
    assert harness.try_change_mode(after, "preserve_encrypted_data").code == "UNINSTALL_MODE_LOCKED"
    assert harness.restart_and_resume_uninstall(after).managed_keys_crypto_shredded

@pytest.mark.parametrize("fault", [
    "owned_path_replaced", "owned_parent_replaced", "symlink_substitution",
    "device_inode_changed", "unexpected_hardlink", "journal_corrupt",
    "journal_fsync_failed", "journal_parent_fsync_failed",
])
def test_uninstall_identity_or_journal_fault_deletes_nothing_unproved(harness, fault) -> None:
    result = harness.uninstall_with_fault(fault)
    assert result.state == "pending_or_quarantined"
    assert harness.unrelated_paths_deleted == ()
    assert harness.uninstall_receipts == ()
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/acceptance/release/test_install_upgrade_rollback_uninstall.py tests/security/release/test_uninstall_residue.py tests/fault/release/test_uninstall_failure_matrix.py tests/acceptance/phase6/test_p6_3_gate.py -q`
Expected: FAIL because uninstall orchestration and P6-3 oracle are absent.

- [ ] **Step 3: Implement exact uninstall manifests and immutable P6-3 verifier**

~~~python
def uninstall(self, prepared: PreparedUninstallV1, approval: LocalOwnerApproval) -> UninstallReceipt:
    with self._journal.global_uninstall_lock():
        run = self._journal.start_or_load_exact(prepared)
        if run.state == "prepared":
            self._auth.consume_local_owner(prepared, approval, require_local_presence=True)
            run = self._journal.transition_fsync(run, "authority_consumed")
        run = self._reconciler.resume_to_terminal(run)
        return self._journal.require_terminal_receipt(run)

def resume_to_terminal(self, run: UninstallRunV1) -> UninstallRunV1:
    for owned in run.runtime_owned_set.in_canonical_order():
        if not run.completed(owned.item_id):
            self._owned_items.require_same_pre_resolved_identity_or_already_absent(owned)
            self._owned_items.remove_idempotent_exact(owned, run_id=run.run_id)
            run = self._journal.mark_item_complete_fsync(run, owned.item_id)
    run = self._journal.transition_if_needed_fsync(run, "runtime_removed")
    if run.mode == "destroy_managed_data":
        # This fsynced transition is the one irreversible semantic boundary.
        run = self._journal.transition_if_needed_fsync(run, "crypto_shred_committed")
        self._destruction.finish_exact_committed_shred_idempotently(
            run.run_id, run.managed_key_set_commitment,
        )
        run = self._journal.transition_if_needed_fsync(run, "managed_keys_shredded")
        self._destruction.remove_exact_committed_managed_data_idempotently(
            run.run_id, run.managed_data_set_commitment,
        )
        run = self._journal.transition_if_needed_fsync(run, "managed_data_removed")
    residue = self._verification.require_no_runtime_residue_and_disclose_external_copies(run.mode)
    return self._journal.accept_and_fsync_receipt_once(run, residue)

def decide_p6_3(evidence: P6ThreeEvidence) -> GateDecision:
    require(evidence.plugin_capabilities == INITIAL_PLUGIN_CAPABILITY_IDS)
    require(evidence.plugin_isolation_and_cleanup_passed)
    require(evidence.reproducible_build_sbom_provenance_signature_passed)
    require(evidence.developer_id_notarization_stapling_gatekeeper_passed)
    require(evidence.intel_passed and evidence.apple_silicon_passed)
    require(evidence.enabled_linux_service_target_receipts_exact_and_passed)
    require(evidence.clean_install_update_rollback_passed)
    require(evidence.preserve_encrypted_data_uninstall_passed)
    require(evidence.destroy_managed_data_uninstall_passed)
    require(evidence.private_findings == 0)
    return GateDecision.accept("P6-3", evidence.digest())
~~~

Uninstall resolves explicit owned paths/identities before approval, never broad globs, and records their device/inode/type/owner/mode/link-count plus signed service-inventory commitment in the immutable run. Immediately before each removal it reopens ancestors/leaves nofollow and requires the same identity or a journal-proved already-complete absence; replacement, hardlink or unowned residue quarantines the run without deleting the substitute. Every transition signs non-self-referential canonical fields, writes a new owner-only journal with write/fsync/atomic-rename/fsync-parent, and advances by state/sequence CAS. Startup finds and reconciles the sole nonterminal run before exposing any service. Each service/job/account/socket/firewall/certificate/route/plugin/temp removal and each key/data deletion is keyed by `(run_id, item_id)` and safe to repeat. Preserve keeps encrypted household data and offline recovery material. Destroy requires set/count commitment and second local confirmation; the journal fsyncs `crypto_shred_committed` before deleting the first key, and thereafter missing keys count as progress only for that exact committed run/set. It removes managed Keychain/data/plugin/cache/temp material, records unverifiable SSD residual bytes, and never claims owner/vendor/cloud erasure. No success receipt exists until final residue verification and receipt fsync both complete; corrupt/competing journals keep admission closed for operator recovery.

Before this gate, build `tuntun-owner-ingress` from the completed Task 28 source/route graph and refresh/re-sign only the canonical `phase3-owner-ingress.v1.json` row so it binds that exact wheel plus the current `ops/routes/owner-ingress-routes.v1.json` digest. The Task 18 P6-2 row and every receipt derived from it must fail against this graph. Re-run installed listener→owner-ingress→peer-authenticated Core/media UDS routing for every signed route, unknown/disabled 404, takeover, start/health/restart, update/rollback and both uninstall modes. Independently require the Task 21-refreshed plugin-supervisor row to match its final wheel and rerun the same installed lifecycle; the Task 20 row/receipt must fail. No P6-3 evidence may use an earlier service digest. This is an interim P6-3 checkpoint: later Task 32 and Task 35 owner-ingress changes deliberately invalidate it, and Task 36 must refresh the canonical row again before the final build/finalizer/C0 evidence. The checkpoint may remain only as a complete matching rollback set.

- [ ] **Step 4: Run green synthetic lifecycle and verify real-evidence requirements**

Run: `uv build --offline --wheel --package tuntun-owner-ingress --out-dir var/build-smoke/phase6/owner-ingress-p6-3 && uv run pytest tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/plugins/test_supervisor_service_lifecycle.py tests/acceptance/release/test_install_upgrade_rollback_uninstall.py tests/security/release/test_uninstall_residue.py tests/fault/release/test_uninstall_failure_matrix.py tests/acceptance/phase6/test_p6_3_gate.py -q && uv run python ops/install/verify_clean_system.py --synthetic-lifecycle --target-receipt var/evidence/phase6/install-lifecycle-synthetic.json && uv run python scripts/scan_private_data.py --paths var/evidence/phase6/install-lifecycle-synthetic.json && uv run ruff check ops/install/uninstall.py ops/install/uninstall_journal.py ops/install/verify_clean_system.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/plugins/test_supervisor_service_lifecycle.py tests/acceptance/release tests/security/release tests/fault/release tests/acceptance/phase6`
Expected: PASS for synthetic lifecycle. P6-3 remains denied unless referenced real sandbox, signing/notarization, Intel, Apple Silicon, every enabled Linux service target and clean-target receipt digest all verify.

- [ ] **Step 5: Commit uninstall and P6-3 gate**

~~~bash
git add ops/install/uninstall.py ops/install/uninstall_journal.py ops/install/verify_clean_system.py ops/services/phase3-owner-ingress.v1.json docs/operations/phase6-retirement-uninstall.md tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py tests/integration/plugins/test_supervisor_service_lifecycle.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/acceptance/release/test_install_upgrade_rollback_uninstall.py tests/security/release/test_uninstall_residue.py tests/fault/release/test_uninstall_failure_matrix.py tests/acceptance/phase6/test_p6_3_gate.py docs/evidence/phase6-p6-3-schema.json docs/evidence/uninstall-run-v1.schema.json
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

def test_both_tiers_bind_the_identical_authoritative_generation(backup_set) -> None:
    fields = (
        "generation", "source_snapshot_digest", "archive_manifest_digest", "deletion_generation",
        "deletion_watermark", "key_bundle_commitment", "rpo_deadline", "restore_eligibility",
    )
    assert all(getattr(backup_set.attached, field) == getattr(backup_set.independent, field) for field in fields)

@pytest.mark.parametrize("field", [
    "generation", "source_snapshot_digest", "archive_manifest_digest", "deletion_generation",
    "deletion_watermark", "key_bundle_commitment", "rpo_deadline", "restore_eligibility",
])
def test_tier_binding_mismatch_is_rejected(backup_set_payload, field) -> None:
    backup_set_payload["independent"][field] = different_valid_value(field)
    with pytest.raises(ValidationError, match="backup_tiers_do_not_bind_identical_source_snapshot"):
        BackupSetV1.model_validate(backup_set_payload)

async def test_concurrent_source_or_deletion_change_cannot_pair_mixed_tiers(harness) -> None:
    pending = harness.pause_independent_copy_after_attached_generation_selected()
    await harness.commit_source_write_and_deletion_generation_change()
    result = await harness.release_and_finish_independent_copy(pending)
    assert result.code == "ATTACHED_GENERATION_CHANGED"
    assert harness.recorded_backup_sets == ()
    assert harness.unowned_independent_archive_bytes == 0

async def test_newer_attached_backup_wins_before_independent_record_cas(harness) -> None:
    pending = harness.pause_independent_copy_before_record_cas()
    newer = await harness.create_new_verified_attached_generation()
    result = await harness.release_and_finish_independent_copy(pending)
    assert result.code == "ATTACHED_GENERATION_CHANGED"
    assert harness.current_attached.generation == newer.generation
    assert all(item.generation == newer.generation for item in harness.current_complete_sets)

@pytest.mark.parametrize("fault", [
    "copy_verification_failed", "uow_open_failed", "record_cas_failed",
    "after_copy_before_verify", "after_verify_before_record", "record_validation_failed",
])
async def test_every_post_copy_failure_leaves_no_unowned_archive(harness, fault) -> None:
    result = await harness.fail_independent_copy_after_durable_handle(fault)
    assert result.failed
    assert harness.recorded_backup_sets == ()
    assert harness.unowned_independent_archive_bytes == 0
    assert harness.independent_residue_states <= {"erased", "owned_quarantine"}

async def test_cancellation_waits_for_owned_cleanup_then_propagates(harness) -> None:
    pending = harness.pause_independent_copy_after_durable_handle()
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
    assert harness.recorded_backup_sets == ()
    assert harness.unowned_independent_archive_bytes == 0

async def test_copy_primitive_owns_partial_output_until_it_returns_a_handle(harness) -> None:
    await harness.crash_during_independent_copy_before_handle_return()
    restarted = await harness.restart()
    assert restarted.unowned_independent_archive_bytes == 0
    assert restarted.independent_residue_states <= {"erased", "owned_quarantine"}

@pytest.mark.parametrize("boundary", [
    "after_handle_before_verify", "during_verify", "after_verify_before_record",
    "during_record_commit", "after_record_commit_before_response",
])
async def test_process_death_reconciles_durable_copy_operation_before_backup_readiness(harness, boundary) -> None:
    await harness.hard_crash_independent_copy(boundary)
    restarted = await harness.restart()
    assert restarted.copy_operation_reconciled_before_backup_readiness
    assert restarted.unowned_independent_archive_bytes == 0
    assert restarted.independent_residue_states <= {"recorded", "erased", "owned_quarantine"}

async def test_unprovable_cleanup_withdraws_backup_readiness_and_alerts(harness) -> None:
    await harness.fail_copy_and_cleanup_proof()
    assert not harness.backup_readiness.current
    assert harness.p6_4_blocked
    assert harness.local_critical_alerts.contains("independent_backup_cleanup_unproven")
    assert harness.quarantined_copy_restore_eligible is False

async def test_lost_commit_response_resolves_by_preallocated_copy_id_without_erasing_record(harness) -> None:
    result = await harness.lose_record_commit_response()
    assert result.original_call_failed
    assert result.exact_recorded_copy_count == 1
    assert result.recorded_copy_bytes_erased == 0
    assert result.unowned_independent_archive_bytes == 0
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/core/tests/unit/hardening/test_independent_backup.py tests/security/recovery/test_owner_only_recovery_authority.py tests/privacy/recovery/test_portable_secret_exclusions.py tests/fault/recovery/test_independent_copy_failures.py -q`
Expected: FAIL because independent copy orchestration and exclusion verifier are absent.

- [ ] **Step 3: Implement owner-local backup creation, encryption, verification, and rotation**

~~~python
async def create_independent(self, prepared, approval, destination) -> BackupSetV1:
    self._auth.consume_local_owner(prepared, approval, require_local_presence=True)
    binding = self._destinations.require_independent_encrypted_owner_controlled(destination)
    attached = await self._repository.require_current_verified_attached_portable_generation(
        prepared.attached_generation,
        prepared.source_snapshot_digest,
        prepared.archive_manifest_digest,
    )
    copy_id = self._ids.new_independent_copy_id()
    operation = await self._repository.begin_independent_copy_operation_fsynced(
        operation_id=copy_id,
        attached=attached,
        destination_commitment=binding.safe_commitment(),
    )
    independent = None
    recorded = False
    primary_error: BaseException | None = None
    try:
        async with self._repository.pin_immutable_attached_generation(attached) as pinned:
            independent = await self._archives.copy_exact_ciphertext_archive(
                pinned.open_archive_nofollow(),
                binding,
                operation_id=copy_id,
                operation_commitment=operation.commitment,
            )
            verification = await self._archives.verify_exact_ciphertext_manifest_and_restore_probe(
                independent, binding, expected_attached=attached,
            )
            async with self._uow.authoritative() as tx:
                current = await tx.attached_backups.require_current_exact(
                    generation=attached.generation,
                    source_snapshot_digest=attached.source_snapshot_digest,
                    archive_manifest_digest=attached.archive_manifest_digest,
                    deletion_generation=attached.deletion_generation,
                    deletion_watermark=attached.deletion_watermark,
                    key_bundle_commitment=attached.key_bundle_commitment,
                    rpo_deadline=attached.rpo_deadline,
                    restore_eligibility=attached.restore_eligibility,
                )
                backup_set = BackupSetV1.model_validate(
                    await tx.backup_sets.record_independent_for_exact_attached_cas(
                        current,
                        independent.safe_manifest(),
                        verification,
                        operation_id=copy_id,
                    )
                )
                await tx.independent_copy_operations.complete_exact(
                    operation,
                    backup_set_commitment=backup_set.commitment(),
                )
        recorded = True  # Set only after the authoritative UoW has durably committed.
    except BaseException as error:
        primary_error = error
        raise
    finally:
        if independent is not None and not recorded:
            resolution = await complete_owned_cleanup_despite_caller_cancellation(
                self._repository.resolve_record_or_quarantine_unrecorded_copy(
                    operation_id=copy_id,
                    independent=independent,
                    archives=self._archives,
                ),
            )
            if (
                resolution.requires_readiness_withdrawal
                or not resolution.proves_recorded_exact_or_erased_or_owned_quarantine
            ):
                self._backup_readiness.withdraw_synchronously(block_gate="P6-4")
                await complete_owned_cleanup_despite_caller_cancellation(
                    self._local_alerts.persist_critical_best_effort(
                        "independent_backup_cleanup_unproven",
                        resolution.safe_commitment(),
                    ),
                )
                if primary_error is None:
                    raise IndependentBackupCleanupFailure(resolution.safe_reason_codes)
    return backup_set
~~~

The independent tier never takes a second source snapshot or re-encrypts a logically similar archive. It copies the exact already verified attached ciphertext/archive-manifest/key-bundle generation through a pinned immutable descriptor, so both tiers necessarily bind identical source, archive, deletion, key, RPO and restore-eligibility fields. Before destination I/O, one durable pending operation preallocates `copy_id` and binds the source and destination commitments. The copy primitive owns every temporary object until it returns one durable handle; the pending operation owns it thereafter, including across process death. Startup reconciles every pending operation before declaring backup readiness. The same `copy_id` binds the destination object and authoritative record, and record creation plus operation completion share one authoritative transaction, making an uncertain commit outcome resolvable without erasing an already recorded copy. The final authoritative CAS requires that generation still be the current eligible attached backup with every field unchanged. Every exceptional path after handle return—including verification, validation, storage/UoW/CAS failure, lost commit response, cancellation and programmer error—runs one independently awaited, cancellation-safe resolver before the original outcome propagates. It proves the exact record exists, proves no record and erases the copy, or retains it in explicit owned quarantine while withdrawing readiness; uncertainty is never treated as permission to erase. Cleanup never makes the quarantine restore-eligible. If ownership cannot be proved, backup readiness is synchronously withdrawn, P6-4 remains blocked and a mandatory local critical alert is persisted. Use purpose-separated offline recovery recipient/key ceremony, strict volume/adapter binding, quota/reserve, authenticated encryption/manifests, temporary plaintext prohibition, atomic write/fsync/rename and safe pruning. Object storage is optional only after an explicit encrypted adapter policy; provider cannot decrypt. Review recovery material annually and after owner-device/router/OS/provider/signing events.

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

**Machine-access prerequisite:** Reopen the current owner-approved clean-Mac access record before scheduling the drill. A real restore containing private household state is permitted only on an offline-capable, isolated, owner-controlled Mac whose wipe/reimage/return handling is recorded; a hosted/rented service without exclusive owner control may exercise synthetic archives only. The live always-home Core Mac is not a clean restore target. If no qualifying target is available within the approved window/cap, retain the archives read-only and leave P6-4/C1 blocked.

**Depends on:** Task 30, all accepted phase restore hooks, and the qualifying isolated target above.
**Gate contribution:** P6-4 restore; T19–T20.
**Estimated effort:** 2 person-days plus quarterly-style drill.

**Files:**
- Create: `ops/backup/restore_isolated.py`
- Create: `ops/backup/bootstrap_offline.py`
- Modify: `apps/core/src/tuntun_core/services/hardening/recovery.py`
- Create: `scripts/phase6/run_restore_drill.py`
- Create: `docs/evidence/phase6-restore-schema.json`
- Create: `docs/evidence/restore-journal-v1.schema.json`
- Test: `tests/integration/recovery/test_phase6_clean_restore.py`
- Test: `tests/security/recovery/test_restore_authority_quarantine.py`
- Test: `tests/privacy/recovery/test_deletion_no_resurrection.py`
- Test: `tests/fault/recovery/test_restore_failure_matrix.py`
- Test: `tests/security/recovery/test_offline_bootstrap.py`

**Interfaces:** Produces an owner-only `RestoreRunV1` and signed drill receipt verifying archive/signature, offline-key reconstruction, SQLCipher/audit/migrations, deletion reconciliation, credential exclusions, route quarantine, device re-pairing and one-phase-at-a-time reconciliation under new generations. Phase reconciliation is not feature enablement: the exact source feature manifest, including every optional absence, remains bound to the completed run.

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

def test_d4_restore_target_has_no_network_interface_or_route(d4_restore_target) -> None:
    assert d4_restore_target.network_mode == "none"
    assert d4_restore_target.network_interfaces == ()
    assert d4_restore_target.routes == ()

@pytest.mark.parametrize("network_mode", ["loopback", "nat", "host", "bridge", "outbound_only"])
def test_d4_rejects_every_non_none_network_mode(d4_factory, network_mode) -> None:
    with pytest.raises(IsolationDenied, match="d4_requires_network_none"):
        d4_factory.create(network_mode=network_mode)

@pytest.mark.parametrize("fault", [
    "archive_half_missing", "archive_half_wrong", "key_half_missing", "key_half_wrong",
    "wrong_owner", "replayed_generation", "expired", "live_system_available",
    "concurrent_second_bootstrap", "restart_after_consume", "interrupt_verify",
    "interrupt_decrypt", "interrupt_quarantine",
])
async def test_offline_bootstrap_fails_closed_without_authority(harness, fault) -> None:
    result = await harness.offline_bootstrap_with_fault(fault)
    assert result.state in {"failed_closed", "quarantined"}
    assert result.authentication_succeeded is False
    assert result.listed_body_count == 0
    assert result.open_effect_routes == ()
    assert result.policy_mutations == ()

@pytest.mark.parametrize("consumed_offset", [timedelta(microseconds=-1), timedelta(hours=1)])
def test_consumed_bootstrap_time_must_be_inside_issued_expiry_window(bootstrap_payload, consumed_offset) -> None:
    consumed_at = bootstrap_payload["issued_at"] + consumed_offset
    with pytest.raises(ValidationError, match="consumed_outside_window"):
        OfflineRecoveryBootstrapV1.model_validate({
            **bootstrap_payload, "state": "consumed", "consumed_at": consumed_at,
        })

async def test_consumed_bootstrap_generation_cannot_be_replayed(harness) -> None:
    first = await harness.consume_offline_bootstrap(one_shot_generation=7)
    assert first.state == "consumed"
    assert (await harness.consume_offline_bootstrap(one_shot_generation=7)).state == "failed_closed"

def test_completed_restore_may_keep_all_effect_routes_closed(restore_run_fixture) -> None:
    restored = RestoreRunV1.model_validate({
        **restore_run_fixture,
        "state": "completed",
        "reconciled_phase_ids": ("phase1", "phase2", "phase3", "phase4", "phase5", "phase6"),
        "effect_route_state": "closed",
    })
    assert restored.effect_route_state == "closed"

async def test_restore_preserves_all_optional_absence_without_authority_resurrection(harness) -> None:
    source = harness.synthetic_backup(feature_states="all_optional_absent")
    restored = await harness.restore_and_reconcile(source)
    assert restored.feature_manifest_digest == source.feature_manifest_digest
    assert restored.enabled_optional_features == ()
    assert restored.open_effect_routes == ()

async def test_mixed_feature_manifest_reopens_only_independently_reconciled_prior_enabled_features(harness) -> None:
    source = harness.synthetic_backup(feature_states="mixed_enabled_absent")
    restored = await harness.restore_and_reconcile(source, fail_feature="remote_camera_playback")
    assert restored.absent_features == source.absent_features
    assert "remote_camera_playback" in restored.quarantined_features
    assert set(restored.open_effect_routes) <= set(source.enabled_features) - {"remote_camera_playback"}

@pytest.mark.parametrize("generation_class", ["controller", "session", "route"])
@pytest.mark.parametrize("delta", [-1, 0])
def test_restore_contract_rejects_every_nonadvancing_authority_generation(
    restore_run_payload, generation_class, delta,
) -> None:
    prior_field = f"prior_{generation_class}_generation"
    new_field = f"new_{generation_class}_generation"
    with pytest.raises(ValidationError, match="restore_authority_generation_not_advanced"):
        RestoreRunV1.model_validate({
            **restore_run_payload,
            prior_field: 7,
            new_field: 7 + delta,
        })

@pytest.mark.parametrize("field", [
    "prior_controller_generation", "new_controller_generation",
    "prior_session_generation", "new_session_generation",
    "prior_route_generation", "new_route_generation",
])
async def test_restore_generation_one_field_substitution_never_reopens_authority(harness, field) -> None:
    run = await harness.completed_restore_run()
    replay = await harness.restart_with_substituted_restore_run(run, field)
    assert replay.state in {"recovery_quarantine", "error_safe"}
    assert replay.open_effect_routes == ()
    assert replay.accepted_old_sessions_controllers_routes == ()

async def test_restore_journal_and_quarantine_are_durable_before_first_plaintext_byte(harness) -> None:
    run = await harness.restore_with_write_timeline()
    first_plaintext = run.timeline.index("first_plaintext_write")
    for prerequisite in (
        "network_none_verified", "restore_journal_fsynced", "quarantine_marker_fsynced",
    ):
        assert run.timeline.index(prerequisite) < first_plaintext
    assert run.journal.target_root_identity_commitment == run.plaintext_target_root_identity_commitment
    assert run.open_effect_routes == ()

@pytest.mark.parametrize("boundary", [
    "after_target_create_before_journal", "after_journal_fsync", "after_quarantine_marker_fsync",
    "during_decrypt", "after_decrypt", "during_migration", "during_integrity_check",
    "during_tombstone_reconciliation", "during_credential_check", "during_phase_reconciliation",
    "after_publication_intent", "after_public_run_before_journal_completion",
])
async def test_restore_restart_reconciles_durable_journal_before_service_exposure(harness, boundary) -> None:
    restarted = await harness.crash_restore_and_restart(boundary)
    assert restarted.startup_barrier_closed_until_restore_journal_reconciled
    assert restarted.open_effect_routes == ()
    assert restarted.orphan_plaintext_roots == ()
    assert restarted.restore_target_states <= {"erased", "recovery_quarantine", "completed"}

@pytest.mark.parametrize("fault", [
    "corrupt_journal", "truncated_journal", "replayed_prior_valid_head",
    "one_field_substitution", "competing_journals", "orphan_plaintext_root",
])
async def test_ambiguous_restore_ownership_fails_closed(harness, fault) -> None:
    restarted = await harness.restart_with_restore_ownership_fault(fault)
    assert restarted.startup_barrier_closed
    assert restarted.open_effect_routes == ()
    assert restarted.unowned_plaintext_bytes == 0
    assert restarted.restore_target_states <= {"erased", "recovery_quarantine"}
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/recovery/test_phase6_clean_restore.py tests/security/recovery/test_restore_authority_quarantine.py tests/security/recovery/test_offline_bootstrap.py tests/privacy/recovery/test_deletion_no_resurrection.py tests/fault/recovery/test_restore_failure_matrix.py -q`
Expected: FAIL because clean restore/reconciliation and deletion oracle are absent.

- [ ] **Step 3: Implement exact quarantined restore sequence and deletion precedence**

~~~python
async def restore(self, archive, offline_key, prepared, approval) -> RestoreRunV1:
    self._auth.consume_local_owner(prepared, approval, require_local_presence=True)
    verified = self._archives.verify_before_decrypt(archive)
    target = self._targets.create_isolated_empty(network_mode="none")
    isolation = await self._targets.verify_no_interfaces_or_routes(target)
    journal = await self._restore_journals.create_unique_fsynced(
        target_root_identity_commitment=target.root_identity_commitment_nofollow(),
        source_archive_commitment=verified.archive_commitment,
        source_feature_manifest_digest=verified.feature_manifest_digest,
        isolation_commitment=isolation.commitment,
        state="prepared",
    )
    await self._targets.install_quarantine_marker_and_fsync_parent(
        target,
        journal_id=journal.journal_id,
        journal_commitment=journal.commitment,
    )
    journal = await self._restore_journals.advance_fsynced(journal, state="decrypting")
    state = await self._archives.restore_with_offline_key(verified, offline_key, target)
    journal = await self._restore_journals.advance_fsynced(journal, state="decrypted")
    await self._migrations.run_quarantined(state)
    journal = await self._restore_journals.advance_fsynced(journal, state="migrated")
    await self._integrity.require_sqlcipher_audit_and_manifests(state)
    journal = await self._restore_journals.advance_fsynced(journal, state="integrity_verified")
    await self._deletions.apply_tombstones_and_purge_managed_generations(state)
    journal = await self._restore_journals.advance_fsynced(journal, state="deletions_reconciled")
    await self._credentials.assert_excluded_live_classes_absent(state)
    await self._routes.assert_all_effect_routes_closed(state)
    journal = await self._restore_journals.advance_fsynced(journal, state="route_safe")
    source_features = verified.require_exact_feature_manifest_and_absence_commitment()
    prior_authority_generations = verified.require_exact_authority_generation_watermarks()
    candidate = await self._reconcile.prepare_new_generations_and_reconcile_one_phase_at_a_time(
        state,
        source_feature_manifest=source_features,
        prior_authority_generations=prior_authority_generations,
        require_strict_generation_advance=True,
        preserve_every_optional_absence=True,
        default_effect_routes="closed",
        permit_effect_route_open=False,
    )
    return await self._restore_journals.complete_and_publish_public_run_fsynced(journal, candidate)
~~~

The D4 target is created with `network_mode="none"`; loopback, NAT, host, bridge, outbound-only, inherited interfaces, and routes are all noncompliant. A private `RestoreJournalV1` is distinct from the public result-oriented `RestoreRunV1`. Its canonical schema binds one source/archive commitment, an HMAC target-root identity commitment (never the raw path), isolation commitment, strictly increasing transition sequence, previous-record commitment and fixed-domain record HMAC. The authoritative control store pins the current sequence/head, so truncation, rollback to an older valid head and one-field substitution all fail closed. The unique journal, network-none proof and target-local quarantine marker are each fsynced before the first decrypted byte; every later migration, integrity, tombstone, credential and reconciliation boundary advances the journal durably. The copy/decrypt primitives may write plaintext only beneath that no-follow-bound journal root and cannot overwrite the reserved marker/control namespace. On startup, a fail-closed barrier enumerates and reconciles the sole journal and every restore target before any service or effect route is exposed. A corrupt/competing journal or unknown plaintext root is never guessed: the target remains network-none and is securely erased or retained in owner-visible `RECOVERY_QUARANTINE`. Expected failures may durably advance to `error_safe`; cancellation, process death and programmer faults may leave a nonterminal progress state, which is itself a startup-blocking recovery record. `complete_and_publish_public_run_fsynced` first fsyncs a publication intent keyed by journal ID, then idempotently publishes the exact `RestoreRunV1` and completes the journal. A crash between those durability domains is reconciled by that ID before startup exposure; pending-journal truth takes precedence over a prematurely visible public row. All effect routes remain closed throughout, so no cross-store atomicity is assumed.

When and only when both the live Mac Keychain and identity database are unavailable, `bootstrap_offline.py` consumes an `OfflineRecoveryBootstrapV1` under a single process-wide lock and may perform exactly `verify`, `decrypt_to_quarantine`, and `quarantine`. It cannot authenticate, enumerate bodies, enable a route, mutate policy, or invoke an action. Consumption is one-shot and durable across interruption/restart. After canonical identity restore, issue `RecoveryIdentityReenrollmentReceiptV1`: create a new passkey generation and revoke every prior credential generation before any phase is re-enabled.

Recreate Keychain purpose roots and excluded credentials, re-pair devices, verify canonical subject/guardian/audience state, topology/camera/media/knowledge/plugin bindings and feature absence. The verified archive supplies the exact prior controller, session and route generation watermarks; each replacement generation must be strictly greater, and the signed run commitment binds all six values. Equal/lower/substituted generations keep every route closed, including after restart. `RestoreRunV1.reconciled_phase_ids` records validation progress only. Completion requires all six phases reconciled but does not imply that any optional feature or effect route is enabled: an absent source feature remains absent, a previously enabled feature remains quarantined until its own current binding/generation/evidence passes, and a failed optional reconciliation cannot block safe completion with that feature closed. The source and restored feature-manifest digests must match exactly; any intentional later feature change is a new local owner ceremony, never part of restore. A deletion reconciliation produces a clean generation within 24 hours and makes affected old generations immediately ineligible. Record physical byte-erasure limits and owner-export/vendor/provider exclusions.

- [ ] **Step 4: Run green synthetic drill, all interruption points, and clean-target scan**

Run: `uv run pytest tests/integration/recovery/test_phase6_clean_restore.py tests/security/recovery/test_restore_authority_quarantine.py tests/security/recovery/test_offline_bootstrap.py tests/privacy/recovery/test_deletion_no_resurrection.py tests/fault/recovery/test_restore_failure_matrix.py -q && uv run python ops/backup/bootstrap_offline.py --synthetic --network none --assert-no-authority --output var/evidence/phase6/bootstrap-synthetic.json && uv run python scripts/phase6/run_restore_drill.py --synthetic --network none --deleted-subject subject_deleted_synth --output var/evidence/phase6/restore-synthetic.json && uv run python scripts/scan_private_data.py --paths var/evidence/phase6/bootstrap-synthetic.json var/evidence/phase6/restore-synthetic.json && uv run ruff check ops/backup/restore_isolated.py ops/backup/bootstrap_offline.py scripts/phase6/run_restore_drill.py tests/integration/recovery tests/security/recovery tests/privacy/recovery tests/fault/recovery && uv run mypy ops/backup apps/core/src`
Expected: PASS; D4 has no network, deleted subject never returns, excluded credentials are absent, one-shot bootstrap grants no authority, and every failure remains quarantined with zero effect route.

- [ ] **Step 5: Commit clean restore and deletion reconciliation**

~~~bash
git add ops/backup/restore_isolated.py ops/backup/bootstrap_offline.py apps/core/src/tuntun_core/services/hardening/recovery.py scripts/phase6/run_restore_drill.py docs/evidence/phase6-restore-schema.json docs/evidence/restore-journal-v1.schema.json tests/integration/recovery/test_phase6_clean_restore.py tests/security/recovery/test_restore_authority_quarantine.py tests/security/recovery/test_offline_bootstrap.py tests/privacy/recovery/test_deletion_no_resurrection.py tests/fault/recovery/test_restore_failure_matrix.py
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
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Create: `apps/admin/src/features/system/incidents.tsx`
- Create: `apps/admin/src/routes/system-incidents.tsx`
- Create: `docs/operations/phase6-incidents.md`
- Create: `ops/runbooks/phase6/*.md`
- Test: `apps/core/tests/unit/hardening/test_incident_state_machine.py`
- Test: `tests/integration/phase6/test_containment_effects.py`
- Test: `tests/security/phase6/test_incident_exit_authority.py`
- Test: `tests/fault/phase6/test_local_alert_survival.py`
- Test: `tests/ui/phase6/incidents.spec.ts`
- Modify: `tests/integration/phase6/test_owner_ingress_phase6_composition.py`
- Modify: `tests/integration/deploy/test_owner_ingress_route_manifest.py`

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

@pytest.mark.parametrize("field", [
    "incident_id", "expected_incident_state", "expected_incident_generation",
    "expected_controller_generation", "expected_session_generation",
    "preparation_commitment",
])
async def test_stale_or_substituted_prepared_exit_remains_contained(harness, field) -> None:
    prepared = await harness.prepare_incident_exit()
    result = await harness.exit_with_preparation(mutate_one_field(prepared, field))
    assert result.code in {"STALE_GENERATION", "POLICY_DENIED", "INTEGRITY_DENIED"}
    assert harness.incident_state != "normal"
    assert harness.open_effect_routes == ()

@pytest.mark.parametrize("check_class", [
    "integrity", "secret_rotation", "credential_recreation",
    "network_exposure", "deletion_reconciliation", "safety",
])
@pytest.mark.parametrize("field", ["generation", "evidence_digest", "observed_at", "valid_until"])
async def test_each_exit_check_drift_is_rechecked_inside_exit_cas(harness, check_class, field) -> None:
    prepared = await harness.prepare_incident_exit()
    await harness.mutate_current_exit_check(check_class, field)
    result = await harness.exit_with_preparation(prepared)
    assert result.code in {"STALE_GENERATION", "INTEGRITY_DENIED"}
    assert harness.incident_state != "normal"
    assert harness.controller_generation == prepared.expected_controller_generation
    assert harness.session_generation == prepared.expected_session_generation

@pytest.mark.parametrize("boundary", [
    "before_passkey_consume", "after_passkey_consume_before_generation_rotation",
    "after_generation_rotation_before_incident_cas", "after_incident_cas_before_commit",
    "after_commit_before_response",
])
async def test_incident_exit_restart_is_atomic_and_never_reuses_old_generations(harness, boundary) -> None:
    prepared = await harness.prepare_incident_exit()
    await harness.crash_exit(prepared, boundary=boundary)
    restarted = await harness.restart()
    if restarted.incident_state == "normal":
        assert restarted.incident_generation == prepared.expected_incident_generation + 1
        assert restarted.controller_generation > prepared.expected_controller_generation
        assert restarted.session_generation > prepared.expected_session_generation
        assert restarted.preparation_consumed_exactly_once(prepared.preparation_id)
    else:
        assert restarted.open_effect_routes == ()
    assert restarted.has_no_partial_exit_transaction

@pytest.mark.parametrize("boundary", [
    "after_pending_commit_before_first_stop_ack", "between_stop_acks",
    "after_all_stop_acks_before_residue_probe", "after_residue_probe_before_final_cas",
])
async def test_containment_never_claims_target_before_external_effects_are_proved(harness, boundary) -> None:
    pending = await harness.pause_containment(boundary)
    assert pending.effective_security_state == "containment_pending"
    assert pending.public_incident_state != pending.requested_target
    assert pending.admission_barrier_closed
    assert await pending.attempt_new_effect() == "denied"
    assert not pending.enter_call_returned

    restarted = await harness.crash_and_restart()
    assert restarted.startup_barrier_closed_until_containment_reconciled
    assert await restarted.attempt_new_effect() == "denied"

@pytest.mark.parametrize("effect", [
    "cloud", "search", "notification", "update", "nonlocal_adapter", "supervised_child",
])
async def test_failed_or_delayed_stop_keeps_pending_barrier_closed(harness, effect) -> None:
    pending = await harness.enter_with_stop_fault(effect)
    assert pending.effective_security_state == "containment_pending"
    assert pending.admission_barrier_closed
    assert pending.open_new_effect_routes == ()
    assert not pending.claims_target_contained

async def test_containment_completes_only_for_exact_acks_and_zero_residue(harness) -> None:
    pending = await harness.begin_containment("contained_egress")
    await harness.ack_all_exact_stop_operations(pending.run_id)
    probe = await harness.prove_no_effect_residue(pending.run_id)
    incident = await harness.finalize_containment(pending.run_id, probe)
    assert incident.state == "contained_egress"
    assert incident.exact_stop_ack_set_verified
    assert incident.effect_residue_count == 0

async def test_pending_containment_blocks_exit_and_competing_transition(harness) -> None:
    pending = await harness.pause_containment("between_stop_acks")
    assert (await harness.exit_incident("local_owner")).code == "CONTAINMENT_PENDING"
    assert (await harness.enter_competing_incident_state()).code == "CONTAINMENT_PENDING"
    assert pending.admission_barrier_closed


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/v1/incidents/current"),
    ("POST", "/api/v1/incidents/enter"),
    ("POST", "/api/v1/incidents/exit/prepare"),
    ("POST", "/api/v1/incidents/exit"),
])
def test_installed_incident_routes_dispatch_once_from_signed_manifest(
    installed_owner_ingress, method, path,
) -> None:
    result = installed_owner_ingress.local_request(method, path, feature_enabled=True)
    assert result.status_code in {200, 201, 202}
    assert result.core_uds_dispatch_count == 1


@pytest.mark.parametrize("state", ["unknown", "disabled"])
def test_unknown_or_disabled_incident_route_is_404_before_dispatch(
    installed_owner_ingress, state,
) -> None:
    result = installed_owner_ingress.local_request(
        "GET", "/api/v1/incidents/current", route_state=state,
    )
    assert result.status_code == 404
    assert result.body_read_count == 0
    assert result.core_uds_dispatch_count == 0
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/core/tests/unit/hardening/test_incident_state_machine.py tests/integration/phase6/test_containment_effects.py tests/security/phase6/test_incident_exit_authority.py tests/fault/phase6/test_local_alert_survival.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py -q && pnpm --filter @tuntun/admin e2e -- tests/ui/phase6/incidents.spec.ts`
Expected: FAIL because incident orchestration/routes/UI/runbooks are absent.

- [ ] **Step 3: Implement transactional containment and verified owner-only exit**

~~~python
async def enter(self, target: IncidentState, reason: SafeReasonCode) -> IncidentStateV1:
    async with self._uow.authoritative() as tx:
        current = await tx.incidents.require_current_for_update()
        effects = INCIDENT_EFFECTS[target]
        pending = await tx.containment_runs.begin_pending_exact(
            current=current,
            requested_target=target,
            reason=reason,
            exact_effect_set=effects.commitment(),
        )
        await tx.admission_barriers.close_for_containment(
            pending.run_id,
            target=target,
            deny_new_effects=True,
        )
        await tx.authorities.revoke(effects.authorities)
        await tx.sessions.increment_generations(effects.session_classes)
        await tx.outbox.add_many(effects.idempotent_stop_requests(pending.run_id))
        await tx.audit.append_safe("incident.containment_pending", pending.safe_commitment())

    await self._local_alerts.open_mandatory_surface_without_blocking_containment(
        pending.safe_projection(),
    )
    acknowledgements = await self._containment_effects.reconcile_exact_stop_requests(
        pending.run_id,
    )
    residue = await self._containment_effects.probe_no_live_effect_residue(
        pending.run_id,
        acknowledgements=acknowledgements,
    )

    async with self._uow.authoritative() as tx:
        current_pending = await tx.containment_runs.require_pending_for_update(pending.run_id)
        await tx.admission_barriers.require_closed_for(current_pending.run_id)
        await tx.outbox.require_exact_current_ack_set(current_pending, acknowledgements)
        await tx.effect_supervisors.require_stop_generation_enforced(current_pending)
        await tx.containment_probes.require_exact_current_zero_residue(current_pending, residue)
        incident = await tx.incidents.transition_closed_from_pending(current_pending)
        await tx.containment_runs.complete_exact(current_pending, incident)
        await tx.audit.append_safe("incident.entered", incident.commitment())
    return incident

async def exit(
    self, prepared: PreparedIncidentExitV1, local_owner: LocalOwnerApproval,
) -> IncidentStateV1:
    async with self._uow.authoritative() as tx:
        now = tx.clock.sample_after_writer_acquired()
        current = await tx.incidents.require_for_update(prepared.incident_id)
        await tx.containment_runs.require_none_active_for_update(current.incident_id)
        await tx.incident_exit_preparations.require_exact_unconsumed(prepared, now=now)
        await tx.incidents.require_exact_state_and_generation(
            current,
            expected_state=prepared.expected_incident_state,
            expected_generation=prepared.expected_incident_generation,
        )
        await tx.incident_exit_checks.require_exact_current_set(prepared.checks, now=now)
        await tx.generations.require_exact(
            controller=prepared.expected_controller_generation,
            session=prepared.expected_session_generation,
        )
        await tx.auth.consume_local_owner_action_bound(
            prepared, local_owner, require_local_presence=True, now=now,
        )
        new_controller = await tx.generations.rotate_controller_cas(
            expected=prepared.expected_controller_generation,
        )
        new_session = await tx.generations.rotate_session_cas(
            expected=prepared.expected_session_generation,
        )
        exited = await tx.incidents.exit_cas(
            current=current,
            expected_generation=prepared.expected_incident_generation,
            new_generation=prepared.expected_incident_generation + 1,
            new_controller_generation=new_controller,
            new_session_generation=new_session,
            exited_at=now,
            owner_approval_commitment=local_owner.commitment,
        )
        await tx.incident_exit_preparations.consume(prepared.preparation_id, at=now)
        await tx.audit.append_safe("incident.exited", exited.commitment())
        await tx.outbox.add_many(INCIDENT_EXIT_EFFECTS.after_commit(exited))
        await tx.commit()
        return exited
~~~

Containment entry is a durable two-commit protocol. The first commit creates a private `containment_pending` effect run, atomically closes the fail-closed admission barrier, revokes Core authority/generations and enqueues idempotent stop operations. While pending, authorization and UI projections must report `containment_pending`/unavailable rather than the older public incident state, and `enter` cannot return or claim the requested final state. Each supervisor persists and enforces the stop generation so a stopped child/adapter cannot restart while the barrier is closed. Only an exact current acknowledgement set plus an independent zero-residue probe permits the second CAS to transition the public incident and complete the effect run. Delay, failure, cancellation or crash leaves the barrier closed; startup resumes the sole pending run before service exposure. Mandatory local alerts use the safe pending projection and remain independent of internet/model/outbox delivery.

`PreparedIncidentExitV1` binds the exact contained incident ID/state/generation, controller/session generations, and one unique current generation/digest/time window for each of integrity, secret rotation, credential recreation, network exposure, deletion reconciliation, and safety. Preparation grants no exit authority. The authoritative transaction resamples trusted time only after it owns the writer, rechecks every binding, consumes the local action-bound passkey, rotates controller/session generations, transitions the incident, consumes the preparation, and writes audit/outbox in one CAS commit. Any miss or interruption leaves containment in force; after restart the transaction is either wholly absent or wholly committed and never reuses an old generation. Runbooks cover lost owner device/lockout, stolen Mac/Reachy/room node, camera/HA/plugin/provider/VPN compromise, leaked key, malicious release, DB/audit corruption, deleted data, storage/full disk, public-data exposure, power/network/router reset and unsafe robot state. They state irrecoverable limits and forbid public private-diagnostic uploads.

Register exactly `GET /api/v1/incidents/current`, `POST /api/v1/incidents/enter`, `POST /api/v1/incidents/exit/prepare`, and `POST /api/v1/incidents/exit` through the canonical Core app/container, owner-ingress router and signed route manifest. The entry/exit authority remains local-only and offline-capable; registration does not grant remote origin. Installed composition proves every enabled row dispatches once over the peer-authenticated Core UDS, while unknown, disabled, duplicate or unsigned rows are 404 before body read or UDS I/O.

- [ ] **Step 4: Run green, complete containment fault matrix, UI/accessibility, and runbook lint**

Run: `uv run pytest apps/core/tests/unit/hardening/test_incident_state_machine.py tests/integration/phase6/test_containment_effects.py tests/security/phase6/test_incident_exit_authority.py tests/fault/phase6/test_local_alert_survival.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py -q && pnpm --filter @tuntun/admin e2e -- tests/ui/phase6/incidents.spec.ts && uv run python scripts/check_runbooks.py ops/runbooks/phase6 --required-scenarios lost-device,owner-lockout,stolen-host,camera,home-assistant,plugin,provider,vpn,key,release,database,audit,deleted-data,storage,power,network,router,robot,public-data && uv run ruff check apps/core/src/tuntun_core/services/hardening/incident.py tests/integration/phase6 tests/integration/deploy/test_owner_ingress_route_manifest.py tests/security/phase6 tests/fault/phase6 && uv run mypy apps/core/src`
Expected: PASS; all containment effects stop, mandatory local alerts remain, and exit always rotates generations after owner verification.

- [ ] **Step 5: Commit incident coordination and runbooks**

~~~bash
git add apps/core/src/tuntun_core/services/hardening/incident.py apps/core/src/tuntun_core/api/routes/incidents.py apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json apps/admin/src/features/system/incidents.tsx apps/admin/src/routes/system-incidents.tsx docs/operations/phase6-incidents.md ops/runbooks/phase6 apps/core/tests/unit/hardening/test_incident_state_machine.py tests/integration/phase6/test_containment_effects.py tests/security/phase6/test_incident_exit_authority.py tests/fault/phase6/test_local_alert_survival.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/ui/phase6/incidents.spec.ts
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

**Interfaces:** Produces local owner action-bound retirement and offline owner-lockout ceremonies, revoking exact certificates/keys/sessions/grants/topology/media/vendor tokens, managed storage keys and reconnect authority. Lockout recovery consumes the one-shot `OfflineRecoveryBootstrapV1` from Task 31 and ends only with `RecoveryIdentityReenrollmentReceiptV1`; it records unverifiable residual/vendor storage truth.

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
    "quarantine_authority_commit", "vendor_reset_checkpoint", "managed_storage_checkpoint",
    "reconnect_checkpoint",
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
    assert receipt.dependent_stop_state == "completed"
    assert receipt.owner_export_state in {"completed", "not_requested"}
    assert receipt.vendor_reset_state != "pending"
    assert receipt.managed_storage_state != "pending"
    assert receipt.reconnect_state == "old_identity_denied"

async def test_lockout_reenrolls_new_passkey_then_revokes_all_prior_generations(harness) -> None:
    receipt = await harness.recover_owner_from_consumed_offline_bootstrap()
    assert isinstance(receipt, RecoveryIdentityReenrollmentReceiptV1)
    assert receipt.new_passkey_generation > receipt.revoked_prior_credential_generation
    assert await harness.prior_owner_credentials_accepted() == ()
    assert harness.timeline.index("all_prior_credentials_revoked") < harness.timeline.index("first_phase_reenabled")

@pytest.mark.parametrize("new_generation_delta", [-1, 0])
def test_reenrollment_receipt_requires_strict_generation_advance(reenrollment_payload, new_generation_delta) -> None:
    prior = 7
    with pytest.raises(ValidationError, match="generation_not_advanced"):
        RecoveryIdentityReenrollmentReceiptV1.model_validate({
            **reenrollment_payload,
            "revoked_prior_credential_generation": prior,
            "new_passkey_generation": prior + new_generation_delta,
        })

async def test_topology_generation_is_locked_and_rechecked_with_first_quarantine_commit(harness) -> None:
    prepared = await harness.prepare_retirement("device_synth_01")
    await harness.advance_device_generation(prepared.device_id)
    result = await harness.retire_with_preparation(prepared)
    assert result.code == "STALE_GENERATION"
    assert not await harness.has_retirement_for_prepared_generation(prepared)

@pytest.mark.parametrize("boundary", [
    "after_quarantine_before_dependent_stop", "during_dependent_stop", "during_owner_export",
])
async def test_quarantine_and_revocation_precede_every_external_retirement_effect(harness, boundary) -> None:
    pending = await harness.pause_retirement(boundary)
    state = await harness.retirement_state(pending.device_id)
    assert state.lifecycle == "retirement_quarantined"
    assert state.authorities_revoked
    assert harness.timeline.index("quarantine_commit") < harness.timeline.index(boundary)
    assert await harness.connect_old_device() == "denied"
    assert await harness.attempt_topology_mutation(pending.device_id) == "denied"

async def test_restart_after_quarantine_before_external_effects_resumes_same_retirement(harness) -> None:
    first = await harness.crash_after_quarantine_commit("device_synth_01")
    restarted = await harness.restart()
    state = await restarted.retirement_state("device_synth_01")
    assert state.retirement_id == first.retirement_id
    assert state.lifecycle == "retirement_quarantined"
    assert state.authorities_revoked
    assert await restarted.connect_old_device() == "denied"
    receipt = await restarted.resume_retirement(first.retirement_id)
    assert receipt.retirement_id == first.retirement_id
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/phase6/test_device_retirement.py tests/security/phase6/test_owner_lockout_authority.py tests/fault/phase6/test_retired_device_reconnect.py tests/acceptance/phase6/test_retirement_drill.py -q`
Expected: FAIL because retirement/lockout state machines and receipts are absent.

- [ ] **Step 3: Implement exact committed-set retirement and sealed-material owner recovery**

~~~python
async def retire(self, prepared, local_owner) -> RetirementReceiptV1:
    async with self._uow.authoritative() as tx:
        now = tx.clock.sample_after_writer_acquired()
        await tx.retirement_preparations.require_exact_unconsumed_for_update(prepared, now=now)
        device = await tx.topology.require_exact_generation_for_update(
            prepared.device_id,
            prepared.device_generation,
        )
        await tx.auth.consume_local_owner_action_bound(
            prepared,
            local_owner,
            require_local_presence=True,
            now=now,
        )
        retirement = await tx.retirements.enter_quarantine_exact(
            device=device,
            prepared=prepared,
        )
        await tx.authorities.revoke_device_everywhere(device)
        retirement = await tx.retirements.mark_authorities_revoked_and_increment_generations(retirement)
        await tx.retirement_preparations.consume(prepared.preparation_id, at=now)
        await tx.audit.append_safe("device.retirement_quarantined", retirement.state_commitment)

    stopped = await self._features.stop_dependents_exact(
        retirement.device_binding,
        retirement.retirement_id,
    )
    await self._retirements.checkpoint_dependents_stopped(retirement.retirement_id, stopped)
    exported = await self._exports.perform_only_prepared_owner_exports(
        retirement.export_set_commitment,
        retirement_id=retirement.retirement_id,
        quarantined_device_binding=retirement.device_binding,
    )
    await self._retirements.checkpoint_owner_exports(retirement.retirement_id, exported)
    vendor = await self._vendor.perform_and_verify_reset_truth(
        retirement.device_binding,
        retirement.retirement_id,
    )
    await self._retirements.checkpoint_vendor_result(retirement.retirement_id, vendor)
    managed = await self._storage.crypto_shred_and_verify_exact_managed_set(
        retirement.managed_set_commitment,
        retirement.retirement_id,
    )
    await self._retirements.checkpoint_managed_storage_result(retirement.retirement_id, managed)
    reconnect = await self._pairing.prove_old_identity_denied(retirement.device_binding)
    await self._retirements.checkpoint_reconnect_result(retirement.retirement_id, reconnect)

    async with self._uow.authoritative() as tx:
        current = await tx.retirements.require_quarantined_with_all_effect_evidence(retirement.retirement_id)
        await tx.topology.mark_retired_exact(
            device_id=current.device_id,
            expected_quarantined_device_generation=current.device_generation,
            expected_authority_revocation_generation=current.authority_revocation_generation,
        )
        retired = await tx.retirements.finalize_retired(
            current,
            retired_at=tx.clock.sample_after_writer_acquired(),
        )
        await tx.audit.append_safe("device.retired", retired.state_commitment)
        return RetirementReceiptV1.from_verified_state(retired)
~~~

The durable lifecycle is `active -> retirement_quarantined -> retired`. The first authoritative transaction locks and re-reads the exact topology generation, rechecks/consumes the preparation and action-bound local-owner approval, then atomically quarantines the device, revokes all authority and increments its generations. No dependent stop, owner export, reset or wipe starts before that commit. Dependent-stop and exact prepared owner-export operations are retirement-ID-bound, idempotent and durably checkpointed just like vendor reset, managed-storage removal and reconnect denial. A crash or unverifiable required effect leaves the same retirement ID quarantined and reconnect-denied; startup resumes it without accepting a new preparation. Finalization re-reads the quarantined generation and all five effect checkpoints under compare-and-swap, and can emit `device.retired` only after each is exact and current. A vendor that cannot prove physical flash erasure is recorded as `verified_attempt_unverifiable_storage`, never as wiped. Owner lockout uses independently sealed offline recovery material on a clean local ceremony, validates archive/system integrity, revokes prior owner sessions/passkeys/remote nodes, creates new owner passkey and generations, then requires backup/revoke test. Maintainer/project signing recovery remains cryptographically and procedurally separate.

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

**Tooling-preparation dependency/order:** Task 03 and all stable enabled-subsystem health/evidence contracts. Steps 1–5 implement, test and commit the evaluator before Task 35A/Task 36A; synthetic evidence grants no maintenance or P6-4 authority.
**Production-evidence dependency/order:** Task 36 Step 6 (Task 36B), which freezes final release bytes, signed service rows and real-target receipts. Step 6 below opens and evaluates the one real steady-state epoch on that exact frozen candidate and writes evidence only; it must complete before Task 35B accepts P6-4.
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

**Interfaces:** Produces subsystem-attributed `MaintenanceMonthV1` records for complete UTC calendar months only, each bound to one uninterrupted server-owned steady-state generation/epoch, a derived day-60 logging boundary, and the same canonical Phase 2 feature-rollover chain ID/candidate/interval-evidence digest with literal zero expired-authority intervals, plus rolling three-month median, target status, three-consecutive-overage expansion freeze, and simplification/retirement review state. A steady-state epoch is opened only with that exact `feature_rollover_chain_id` and `feature_candidate_digest`; they are immutable for its generation. It consumes owner-entered durations and signed health/update receipts, never a caller-supplied elapsed-day count and never surveillance/behavior inference. Phase 4 records enter only through the exact `Phase4MaintenanceRecordV1 -> Phase4MaintenanceContributionV1` mapper: all five source subsystems map to `phase4_voice_media_displays`; the six source exclusion classes map one-for-one, with ambiguous `quarterly_drill` preserved as `phase4_quarterly_drill`; and `month_key` must equal the source occurrence's UTC calendar month. The evaluator consumes the externally pre-issued chain through the existing Phase 2 rollover verifier and `FeatureAuthorityLease`, reads its trusted clock/current steady-state record, rejects duplicate/gapped/mixed-generation/stale months, and requires uninterrupted same-candidate authority from the steady-state epoch through the latest closed month before the interval can contribute to day 60, day 90 or a complete bucket. The canonical verifier maps only its declared hostile/signature/binding/expiry faults to `FeatureAbsent`; cancellation and programmer faults remain visible. Missing, late, reordered, widened, rollback, signature-invalid, candidate-drifted or expired current/next authority closes admissions/background work and invalidates the eligible steady-state generation. Maintenance observations made while authority is closed remain separately truthful but do not count; a new 60-/90-day window begins only under the controlled-recovery generation. The evaluator requires the complete uninterrupted eligible series through the latest closed month, uses the latest three for promotion/median, and scans every eligible consecutive three-month window for a durable overage trigger. A clearance records the exact evaluated-through month so pre-clear history cannot immediately re-latch the freeze. Task 34 never signs, renews or extends manifest authority.

**Rollback/disabled exit:** Insufficient elapsed evidence is `not_yet_eligible`, not a synthetic pass. Three consecutive months over 8 hours freezes optional expansion; only a local owner evidence-bound simplification/retirement review can clear it.

- [ ] **Step 1: Write red exact-window, median, categories, and freeze tests**

~~~python
async def test_elapsed_time_comes_only_from_trusted_epoch_and_clock(evaluator) -> None:
    evaluator.clock.set(evaluator.steady_epoch.started_at + timedelta(days=89))
    assert (await evaluator.evaluate(())).state == "not_yet_eligible"

async def test_first_gate_needs_latest_three_complete_eligible_months(evaluator) -> None:
    assert (await evaluator.evaluate(months(minutes=[300, 300]))).state == "not_yet_eligible"

async def test_promotion_window_requires_continuous_canonical_feature_authority(evaluator) -> None:
    decision = await evaluator.evaluate(months(minutes=[300, 300, 300]))
    assert decision.feature_authority_expired_interval_count == 0
    assert decision.feature_authority_covers_full_steady_state_interval

async def test_real_window_is_bound_to_final_frozen_candidate_and_cannot_survive_drift(
    maintenance_harness,
) -> None:
    epoch = await maintenance_harness.open_epoch_from_frozen_candidate()
    assert (
        epoch.feature_candidate_digest
        == maintenance_harness.frozen_signed_feature_manifest.candidate_digest
    )
    assert (
        maintenance_harness.digest(maintenance_harness.frozen_signed_feature_manifest)
        == maintenance_harness.frozen_release_manifest.feature_manifest_digest
    )
    drift = await maintenance_harness.replace_candidate_after_epoch_start()
    assert drift.admission_and_background_work_closed_before_io
    assert drift.previous_epoch_invalid_for_promotion
    assert drift.new_steady_state_generation > epoch.generation
    assert (await drift.evaluator.evaluate(drift.pre_drift_months)).state == "not_yet_eligible"

@pytest.mark.parametrize("fault", [
    "missing_next", "late_next", "reordered", "widened", "rollback",
    "signature_invalid", "candidate_drifted", "wall_expired", "monotonic_expired",
])
async def test_feature_authority_gap_does_not_count_and_restarts_eligibility(
    maintenance_harness, fault,
) -> None:
    result = await maintenance_harness.inject_feature_authority_fault(fault)
    assert result.admission_and_background_work_closed_before_io
    assert result.maintenance_observation_retained_but_not_promotion_eligible
    assert result.new_steady_state_generation > result.previous_steady_state_generation
    assert (await result.evaluator.evaluate(result.pre_gap_months)).state == "not_yet_eligible"

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
        "phase4_quarterly_drill", "incident", "hardware_replacement", "unplanned_repair",
        "major_migration",
    }

def test_phase4_maintenance_source_vocabularies_have_total_closed_maps() -> None:
    assert set(PHASE4_SUBSYSTEM_TO_AGGREGATE) == {
        "room_voice", "media", "display", "television", "screen_time",
    }
    assert set(PHASE4_SUBSYSTEM_TO_AGGREGATE.values()) == {
        MaintenanceSubsystem.PHASE4_VOICE_MEDIA_DISPLAYS,
    }
    assert set(PHASE4_EXCLUSION_TO_AGGREGATE) == {
        "initial_commissioning", "incident", "repair", "hardware_replacement",
        "major_migration", "quarterly_drill",
    }
    assert PHASE4_EXCLUSION_TO_AGGREGATE["quarterly_drill"] is ExcludedMaintenanceClass.PHASE4_QUARTERLY_DRILL

@pytest.mark.parametrize(("source", "expected"), tuple(PHASE4_EXCLUSION_TO_AGGREGATE.items()))
def test_phase4_exclusions_map_without_guessing_or_dropping_minutes(
    phase4_maintenance_mapper, phase4_excluded_record, source, expected,
) -> None:
    contribution = phase4_maintenance_mapper.map(
        phase4_maintenance_mapper.resign_source_record(
            phase4_excluded_record, update={"excluded_event_class": source},
        ),
    )
    assert contribution.aggregate_subsystem is None
    assert contribution.aggregate_excluded_class is expected
    assert contribution.minutes == phase4_excluded_record.minutes

def test_phase4_month_key_is_checked_against_utc_occurrence_before_aggregation(
    phase4_maintenance_mapper, phase4_ordinary_record,
) -> None:
    # 2026-09-01 00:15 +08:00 is still 2026-08-31 in the authoritative UTC bucket.
    edge = phase4_maintenance_mapper.resign_source_record(phase4_ordinary_record, update={
        "month_key": "2026-09", "occurred_at": datetime.fromisoformat("2026-09-01T00:15:00+08:00"),
    })
    with pytest.raises(MaintenanceSourceMismatch, match="phase4_maintenance_month_occurrence_mismatch"):
        phase4_maintenance_mapper.map(edge)
    accepted_source = phase4_maintenance_mapper.resign_source_record(edge, update={"month_key": "2026-08"})
    accepted = phase4_maintenance_mapper.map(accepted_source)
    assert accepted.occurred_at_utc == datetime.fromisoformat("2026-08-31T16:15:00+00:00")

@pytest.mark.parametrize("fault", [
    "changed_evidence_commitment", "unknown_source_value", "ordinary_with_exclusion",
    "excluded_without_exclusion", "duplicate_source_record", "double_count_as_ordinary_and_excluded",
])
def test_phase4_mapping_faults_fail_before_month_totals(
    phase4_maintenance_mapper, phase4_maintenance_record, fault,
) -> None:
    with pytest.raises((ValidationError, MaintenanceSourceMismatch)):
        phase4_maintenance_mapper.map_with_fault(phase4_maintenance_record, fault)
    assert phase4_maintenance_mapper.aggregate_write_count == 0

async def test_phase4_source_retry_and_concurrent_ingest_are_exactly_once(
    phase4_maintenance_mapper, phase4_ordinary_record,
) -> None:
    first, second = await asyncio.gather(
        phase4_maintenance_mapper.ingest(phase4_ordinary_record),
        phase4_maintenance_mapper.ingest(phase4_ordinary_record),
    )
    assert first.contribution_commitment == second.contribution_commitment
    assert await phase4_maintenance_mapper.committed_source_count(phase4_ordinary_record.record_id) == 1
    assert await phase4_maintenance_mapper.month_contribution_count(phase4_ordinary_record.record_id) == 1

async def test_phase4_source_id_with_changed_commitment_is_not_an_idempotent_retry(
    phase4_maintenance_mapper, phase4_ordinary_record,
) -> None:
    await phase4_maintenance_mapper.ingest(phase4_ordinary_record)
    substituted = phase4_maintenance_mapper.resign_changed_minutes_with_same_source_id(
        phase4_ordinary_record,
    )
    with pytest.raises(MaintenanceSourceMismatch, match="phase4_maintenance_source_commitment_collision"):
        await phase4_maintenance_mapper.ingest(substituted)
    assert await phase4_maintenance_mapper.month_contribution_count(phase4_ordinary_record.record_id) == 1
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/core/tests/unit/hardening/test_maintenance_evaluator.py tests/property/phase6/test_maintenance_accounting.py tests/security/phase6/test_expansion_freeze.py tests/acceptance/phase6/test_maintenance_gate.py -q`
Expected: FAIL because maintenance records/evaluator/freeze are absent.

- [ ] **Step 3: Implement exact arithmetic, attribution, and transactional freeze**

~~~python
def map_phase4_record(self, source: Phase4MaintenanceRecordV1) -> Phase4MaintenanceContributionV1:
    record = Phase4MaintenanceRecordV1.model_validate(source, strict=True)
    self._source_commitments.require_exact(
        record,
        record.evidence_commitment,
        domain="tuntun.phase4-maintenance-record.v1",
    )
    occurred_at_utc = record.occurred_at.astimezone(timezone.utc)
    if record.month_key != occurred_at_utc.strftime("%Y-%m"):
        raise MaintenanceSourceMismatch("phase4_maintenance_month_occurrence_mismatch")
    ordinary = record.record_class == "ordinary"
    payload = {
        "source_schema_version": record.schema_version,
        "source_record_id": record.record_id,
        "month": record.month_key,
        "source_subsystem": record.subsystem,
        "source_record_class": record.record_class,
        "source_excluded_event_class": record.excluded_event_class,
        "minutes": record.minutes,
        "occurred_at_utc": occurred_at_utc,
        "aggregate_subsystem": PHASE4_SUBSYSTEM_TO_AGGREGATE[record.subsystem] if ordinary else None,
        "aggregate_excluded_class": (
            None if ordinary else PHASE4_EXCLUSION_TO_AGGREGATE[record.excluded_event_class]
        ),
        "source_evidence_commitment": record.evidence_commitment,
    }
    return Phase4MaintenanceContributionV1.model_validate({
        **payload,
        "contribution_commitment": self._commitments.issue(
            payload, domain="tuntun.phase4-maintenance-contribution.v1",
        ),
    })

async def ingest_phase4_record(self, source: Phase4MaintenanceRecordV1) -> Phase4MaintenanceContributionV1:
    contribution = self.map_phase4_record(source)
    async with self._uow.authoritative() as tx:
        claim = await tx.phase4_maintenance_source_claims.claim_once(
            source_record_id=contribution.source_record_id,
            source_evidence_commitment=contribution.source_evidence_commitment,
            contribution_commitment=contribution.contribution_commitment,
        )
        if not claim.created:
            if (
                claim.source_evidence_commitment != contribution.source_evidence_commitment
                or claim.contribution_commitment != contribution.contribution_commitment
            ):
                raise MaintenanceSourceMismatch("phase4_maintenance_source_commitment_collision")
            return await tx.maintenance_contributions.require_exact(claim.contribution_commitment)
        await tx.maintenance_contributions.add_exact(contribution)
        await tx.audit.append_safe(
            "maintenance.phase4_source_ingested", contribution.contribution_commitment,
        )
        return contribution

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

    try:
        authority = await self._canonical_feature_authority.require_continuous_interval(
            expected_chain_id=steady.feature_rollover_chain_id,
            expected_candidate_digest=steady.feature_candidate_digest,
            interval_start=steady.started_at,
            interval_end=now,
            require_zero_expired_interval=True,
        )
    except FeatureAbsent:
        await self._steady_state_store.invalidate_for_controlled_recovery(
            expected_generation=steady.generation,
            reason="feature_manifest_authority_not_continuous",
        )
        return not_yet_eligible()

    ordered = sorted(records, key=lambda record: record.period_start)
    if len(ordered) < 3 or len({record.month for record in ordered}) != len(ordered):
        return not_yet_eligible()
    if any(
        record.steady_state_generation != steady.generation
        or record.steady_state_epoch_started_at != steady.started_at
        or record.logging_eligible_at != steady.started_at + timedelta(days=60)
        or record.feature_rollover_chain_id != authority.rollover_chain_id
        or record.feature_candidate_digest != authority.candidate_digest
        or record.feature_authority_interval_digest
        != authority.interval_digest_for(record.period_start, record.period_end_exclusive)
        or record.feature_authority_expired_interval_count != 0
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
        feature_rollover_chain_id=authority.rollover_chain_id,
        feature_authority_interval_digest=authority.interval_digest,
        feature_authority_expired_interval_count=0,
        feature_authority_covers_full_steady_state_interval=True,
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

Ordinary categories include health review, backup review, certificate/key attention, storage cleanup, device/plugin checks and routine update approval across all phases. Record exclusions separately by actual duration. The canonical Phase 2 feature-authority service verifies the complete externally pre-issued chain and both wall/monotonic leases throughout the counted interval; Task 34 stores only its content-safe interval/transition commitments and cannot sign or renew it. Any authority fault closes admissions/background work through the existing whole-composition recovery path, rotates the steady-state generation, and prevents pre-gap days/months from satisfying the new generation's 60-/90-day window. Owner-entered maintenance during the closed interval remains recorded outside eligible promotion buckets. Freeze prevents new optional feature registration/procurement but does not disable privacy, safety, backup, recovery or already accepted essentials. Once triggered, `maintenance_expansion_freeze` is durable and latched; a later low-burden window cannot clear it. Only a fresh local-owner action bound to the exact freeze generation, already-applied optional-subsystem simplification/retirement evidence and resulting feature-manifest digest clears it transactionally. UI identifies highest-burden optional subsystems for owner simplification/retirement review.

- [ ] **Step 4: Run green, property arithmetic, boundary cases, and synthetic report**

Run: `uv run pytest apps/core/tests/unit/hardening/test_maintenance_evaluator.py tests/property/phase6/test_maintenance_accounting.py tests/security/phase6/test_expansion_freeze.py tests/acceptance/phase6/test_maintenance_gate.py -q && uv run python scripts/phase6/evaluate_maintenance.py --synthetic fixtures/synthetic/phase6/maintenance/three-months.json --output var/evidence/phase6/maintenance-synthetic.json && uv run ruff check apps/core/src/tuntun_core/services/hardening/maintenance.py scripts/phase6/evaluate_maintenance.py tests/property/phase6 tests/security/phase6 tests/acceptance/phase6 && uv run mypy apps/core/src`
Expected: PASS; exact 480-minute median passes, 481/700/482 freezes, and insufficient real time, candidate drift or any feature-authority gap never passes. This step is tooling-only; the production command and authority-bearing window are reserved for Step 6 after the final candidate is frozen.

- [ ] **Step 5: Commit maintenance accounting and freeze**

~~~bash
git add apps/core/src/tuntun_core/services/hardening/maintenance.py scripts/phase6/evaluate_maintenance.py docs/operations/phase6-maintenance.md docs/evidence/phase6-maintenance-schema.json apps/core/tests/unit/hardening/test_maintenance_evaluator.py tests/property/phase6/test_maintenance_accounting.py tests/security/phase6/test_expansion_freeze.py tests/acceptance/phase6/test_maintenance_gate.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(operations): enforce whole-system maintenance limits"
~~~

Stop Task 34 here during implementation. Complete Task 35A, Task 36A, Task 37A and Task 38A, then freeze the candidate in Task 36B before returning to Task 34B below. Running the real window before Task 36B produces permanently ineligible evidence.

- [ ] **Step 6 (Task 34B): Collect the non-compressible maintenance evidence on the immutable final candidate**

Require empty `git status --porcelain=v1`, the exact Task 36B frozen release manifest and service inventory, its real target-lifecycle receipts, and a complete externally pre-issued canonical Phase 2 `SignedFeatureManifestRolloverChainV1` covering the planned steady-state interval plus the later Task 36C campaigns. Use only Phase 2's canonical prepare/external-sign/assemble/verify ceremony against the exact installed candidate/package/registration/evidence metadata; Phase 6 adds no signing path. With Core stopped, stage those already signed bytes through the inherited nofollow-bounded command, then perform a controlled restart: `uv run tuntunctl service stop && uv run --frozen --offline --no-sync tuntunctl features stage-rollover --file var/evidence/phase6/final-feature-authority/signed-rollover-chain.json && uv run tuntunctl service start`. Open the steady-state epoch only after the restart re-verifies a currently valid envelope and the exact Task 36B installation. Logging may become promotion-eligible only after 60 uninterrupted days; do not evaluate a production pass until at least 90 uninterrupted days and three complete UTC monthly buckets exist. Then run: `TUNTUN_ALLOW_ELAPSED_PHASE6=1 uv run python scripts/phase6/evaluate_maintenance.py --candidate-manifest var/release/frozen/release-manifest.json --feature-manifest-chain var/evidence/phase6/final-feature-authority/signed-rollover-chain.json --real --output var/evidence/phase6/maintenance.json && uv run python ops/release/finalize.py --verify-unchanged var/release/frozen && uv run python scripts/scan_private_data.py --paths var/evidence/phase6/maintenance.json && test -z "$(git status --porcelain=v1)"`.

Expected: the production receipt binds the exact Task 36B release-manifest/artifact/service-row digests, one uninterrupted steady-state generation, at least 90 actual wall/monotonic days, three complete monthly buckets, the canonical rollover chain and zero expired-authority intervals. A tracked, artifact, service-row, feature-candidate or chain drift invalidates the entire counted window and starts a new generation only after a newly frozen candidate; observations remain truthful but cannot be carried into the replacement window. This step writes evidence only and performs no source, route, service-row, lockfile, workflow, schema, package or release-artifact mutation.

### Task 35: Complete System UI truth, diagnostics preview, accessibility/localization, and P6-4 gate

**Tooling-preparation dependency/order:** Tasks 28–33 and Task 34 Steps 1–5. Steps 1–5 implement, test and commit the final System UI/recovery route and a synthetic P6-4 oracle before Task 36A; they make the last owner-ingress source/route mutation but grant no production P6-4 authority.
**Production-acceptance dependency/order:** Task 36B's immutable final candidate plus accepted real Task 34B evidence. Step 6a reruns the real resilience drills on those exact bytes; U8B then accepts the post-drill UI state, and Step 6b accepts P6-4 from that complete current evidence. Both steps write evidence only.
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
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Create: `tests/ui/phase6/system-hardening.spec.ts`
- Create: `tests/ui/phase6/system-hardening-accessibility.spec.ts`
- Create: `tests/privacy/phase6/test_diagnostic_preview.py`
- Create: `tests/acceptance/phase6/test_p6_4_gate.py`
- Create: `scripts/phase6/run_p6_4_resilience_campaign.py`
- Create: `scripts/phase6/verify_p6_4.py`
- Modify: `tests/integration/phase6/test_owner_ingress_phase6_composition.py`
- Modify: `tests/integration/deploy/test_owner_ingress_route_manifest.py`

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

test("pending safety journals never render healthy or expose a conflicting ceremony", async ({page}) => {
  await openLocalSystemRecovery(page, {operationState: "restore_journal_pending"});
  await expect(page.getByTestId("system-effective-state")).toHaveText(/quarantined|reconciliation required/i);
  await expect(page.getByTestId("backup-verified-state")).not.toHaveText("Available");
  await expect(page.getByRole("button", {name: /enable|resume|exit containment/i})).toHaveCount(0);
});
~~~

~~~python
def test_installed_recovery_status_route_dispatches_once_from_signed_manifest(
    installed_owner_ingress,
) -> None:
    result = installed_owner_ingress.request(
        "GET", "/api/v1/recovery/status", feature_enabled=True,
    )
    assert result.status_code == 200
    assert result.core_uds_dispatch_count == 1


@pytest.mark.parametrize("state", ["unknown", "disabled"])
def test_unknown_or_disabled_recovery_status_route_is_404_before_dispatch(
    installed_owner_ingress, state,
) -> None:
    result = installed_owner_ingress.request(
        "GET", "/api/v1/recovery/status", route_state=state,
    )
    assert result.status_code == 404
    assert result.body_read_count == 0
    assert result.core_uds_dispatch_count == 0


def test_p6_4_rejects_maintenance_from_a_different_candidate(p6_4_harness) -> None:
    result = p6_4_harness.verify_with_maintenance_candidate_substituted()
    assert result.denied
    assert result.reason_code == "p6_4_candidate_mismatch"
    assert result.accepted_receipt_write_count == 0


def test_real_resilience_campaign_binds_every_drill_to_frozen_candidate(p6_4_harness) -> None:
    campaign = p6_4_harness.run_real_resilience_campaign()
    assert campaign.started_after_frozen_candidate_verification
    assert campaign.every_drill_candidate_digest == campaign.frozen_candidate_digest
    assert campaign.final_candidate_bytes_unchanged

def test_real_resilience_campaign_rejects_pre_freeze_or_cross_candidate_receipt(
    p6_4_harness,
) -> None:
    result = p6_4_harness.try_import_pre_freeze_or_cross_candidate_receipt()
    assert result.denied
    assert result.effect_count == 0
    assert result.campaign_receipt_write_count == 0
~~~

- [ ] **Step 2: Run red**

Run: `pnpm --filter @tuntun/admin e2e -- tests/ui/phase6/system-hardening.spec.ts tests/ui/phase6/system-hardening-accessibility.spec.ts && uv run pytest tests/privacy/phase6/test_diagnostic_preview.py tests/acceptance/phase6/test_p6_4_gate.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py -q`
Expected: FAIL because consolidated System pages/DTOs and P6-4 oracle are absent.

- [ ] **Step 3: Implement safe projections, exact ceremonies, diagnostic preview, and gate oracle**

~~~python
def decide_p6_4(evidence: P6FourEvidence) -> GateDecision:
    require(
        evidence.signed_feature_manifest_digest
        == evidence.frozen_release_manifest.feature_manifest_digest
    )
    require(
        evidence.feature_candidate_digest
        == evidence.signed_feature_manifest.candidate_digest
        == evidence.maintenance_feature_candidate_digest
        == evidence.ui_acceptance_feature_candidate_digest
    )
    require(evidence.independent_backup_current_and_verified)
    require(evidence.clean_owner_only_restore_and_no_resurrection)
    require(evidence.incident_containment_and_local_alert_continuity)
    require(evidence.retirement_and_old_identity_denial)
    require(evidence.update_rollback_and_uninstall)
    require(evidence.maintenance_window_complete_and_target_met)
    require(evidence.no_unreconciled_copy_restore_containment_or_retirement_operations)
    require(evidence.ui_truth_accessibility_localization_and_diagnostics_safe)
    require(evidence.failure_matrix_passed and evidence.high_critical_open == 0)
    return GateDecision.accept("P6-4", evidence.digest())
~~~

Every fact has controller/evidence time/generation/validity/verification/reason. A pending independent-copy operation, restore journal, containment effect run or retirement effect run supersedes older healthy/public state in the projection and blocks P6-4 until reconciled. Preview includes only safe versions, states, reason codes, digests and bounded metrics; no bodies/IDs/addresses. Crash reporting defaults off and requires exact preview plus opt-in. Implement English/Hindi, mixed-script robustness, keyboard, VoiceOver, 320 px/200%, light/dark/high-contrast/reduced-motion and all loading/empty/error/stale/degraded/privacy/quarantine states.

`run_p6_4_resilience_campaign.py` is the one production envelope for the existing independent-copy, clean-restore/no-resurrection, incident/containment, retirement/lockout, update/rollback and UI-truth drills. Before the first effect and after every drill, it reloads and verifies the exact Task 36B release manifest, signed feature manifest, service inventory and post-Task-35A owner-ingress row; it passes that immutable candidate commitment into each runner and accepts only receipts that repeat it. Pre-freeze, synthetic, cross-candidate, stale or missing receipts cannot be imported. It writes only ignored content-safe evidence and stops on candidate drift or an unreconciled journal; it never edits source, routes, rows or release artifacts.

Register exactly `GET /api/v1/recovery/status` through the canonical Core app/container, owner-ingress router and signed route manifest; maintenance and release-diagnostic UI reuse already registered safe projection routes and do not create hidden aliases. Installed composition proves the enabled recovery row dispatches once over the peer-authenticated Core UDS, while unknown, disabled, duplicate or unsigned rows are 404 before body read or UDS I/O. This is the final Phase 6 owner-ingress source/route mutation; Task 36A must rebuild/re-sign the canonical service row before Task 37A/38A and the Task 36B artifact freeze.

- [ ] **Step 4: Run green UI matrix, API/privacy tests, build, and the synthetic P6-4 oracle**

Run: `pnpm --filter @tuntun/admin e2e -- tests/ui/phase6/system-hardening.spec.ts tests/ui/phase6/system-hardening-accessibility.spec.ts && uv run pytest tests/privacy/phase6/test_diagnostic_preview.py tests/acceptance/phase6/test_p6_4_gate.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py -q && uv run python scripts/phase6/run_p6_4_resilience_campaign.py --synthetic --output var/evidence/phase6/p6-4-resilience-synthetic.json && uv run ruff check scripts/phase6/run_p6_4_resilience_campaign.py scripts/phase6/verify_p6_4.py tests/acceptance/phase6/test_p6_4_gate.py && pnpm --filter @tuntun/admin test && pnpm --filter @tuntun/admin typecheck && pnpm --filter @tuntun/admin build && uv run python scripts/run_ui_matrix.py --phase 6 --languages en,hi --themes light,dark,high-contrast --widths 320,768,1440 --zoom 200 --reduced-motion && uv run python scripts/scan_browser_artifacts.py --forbid private_payloads,secrets,reusable_urls,service_workers,persistent_storage`
Expected: PASS; all UI states are truthful/accessible/localized, diagnostic findings zero, and synthetic fixtures prove the oracle rejects incomplete, cross-candidate or accelerated evidence. No production P6-4 receipt exists yet.

- [ ] **Step 5: Commit System hardening UI and P6-4 gate**

~~~bash
git add apps/admin/src/features/system/backup-recovery.tsx apps/admin/src/features/system/maintenance.tsx apps/admin/src/features/system/release-diagnostics.tsx apps/admin/src/routes/system-recovery.tsx apps/admin/src/routes/system-maintenance.tsx apps/core/src/tuntun_core/api/routes/recovery.py apps/core/src/tuntun_core/api/phase6_dtos.py apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json scripts/phase6/run_p6_4_resilience_campaign.py scripts/phase6/verify_p6_4.py tests/ui/phase6/system-hardening.spec.ts tests/ui/phase6/system-hardening-accessibility.spec.ts tests/privacy/phase6/test_diagnostic_preview.py tests/acceptance/phase6/test_p6_4_gate.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(ui): complete Phase 6 recovery and operations truth"
~~~

Stop Task 35 here during implementation. Complete Task 36A/37A/38A and Task 36B, then Task 34B before returning to Step 6a below. Run U8B after Step 6a, then return to Step 6b. No production resilience or P6-4 receipt may be created from the pre-freeze tooling candidate.

- [ ] **Step 6a (Task 35R): Rerun current resilience drills on the frozen candidate**

After Task 34B completes, require empty `git status --porcelain=v1` and run every real P6-4 drill through the candidate-bound envelope so every receipt is current: `TUNTUN_ALLOW_REAL_P6_4_RESILIENCE=1 uv run python scripts/phase6/run_p6_4_resilience_campaign.py --candidate-manifest var/release/frozen/release-manifest.json --service-inventory var/release/frozen/service-inventory.json --real --output var/evidence/phase6/p6-4-resilience.json && uv run python ops/release/finalize.py --verify-unchanged var/release/frozen && uv run python scripts/scan_private_data.py --paths var/evidence/phase6/p6-4-resilience.json && test -z "$(git status --porcelain=v1)"`.

Expected: every independent-copy/clean-restore/no-resurrection/incident/retirement/update/UI drill receipt binds the exact Task 36B candidate, all journals are terminal and the final installed state is that candidate. This step writes evidence only. Run U8B against this post-drill state before continuing.

- [ ] **Step 6b (Task 35B): Accept P6-4 from the frozen-candidate evidence without changing the candidate**

After U8B completes, run: `TUNTUN_ALLOW_REAL_PHASE6_GATE=1 uv run python scripts/phase6/verify_p6_4.py --candidate-manifest var/release/frozen/release-manifest.json --service-inventory var/release/frozen/service-inventory.json --evidence-root var/evidence/phase6 --require-resilience-receipt var/evidence/phase6/p6-4-resilience.json --require-maintenance-receipt var/evidence/phase6/maintenance.json --require-ui-receipt var/evidence/ui/u8-accepted.json --output var/evidence/phase6/p6-4-accepted.json && uv run python ops/release/finalize.py --verify-unchanged var/release/frozen && uv run python scripts/scan_private_data.py --paths var/evidence/phase6/p6-4-accepted.json && test -z "$(git status --porcelain=v1)"`.

Expected: the signed P6-4 receipt binds the exact Task 36B frozen release/artifact/service inventory, Task 34B maintenance receipt, current Task 35R resilience receipt, U8B and all recovery/incident/retirement/UI evidence; stale interim rows, synthetic reports, candidate substitution or incomplete journals deny without a receipt. This step writes evidence only. P6-4 acceptance authorizes Task 36C evidence collection, never a source, route, service-row or artifact mutation.

## Wave 6 — Whole-Program Threat Closure, C0 Freeze, C1 Approval, and Manual Beta Publication

### Task 36: Close T01–T25 on one candidate and complete full-system soak/stress evidence

**Tooling-preparation dependency/order (Task 36A):** accepted P6-1–P6-3, Tasks 01–33, Task 34 Steps 1–5, Task 35 Steps 1–5, current mandatory Phase 1–5 evidence runners and UI checkpoint U8A tooling qualification. Steps 1–5 refresh the final owner-ingress row and commit all campaign tooling before Tasks 37A–38A; they grant no real-campaign authority and do not wait for U8B.
**Frozen-build dependency/order (Task 36B):** Task 36A plus the committed tooling-preparation stages of Tasks 37–38. Step 6 freezes/signs/notarizes/staples the final candidate and runs real target lifecycles before Task 34B starts its steady-state epoch.
**Production-campaign dependency/order (Task 36C):** unchanged Task 36B bytes, accepted Task 34B maintenance evidence and Task 35B/P6-4. Step 7 runs T01–T25, stress and soak evidence only; it makes no tracked or release-artifact change.
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
- Modify: `ops/services/phase3-owner-ingress.v1.json`
- Modify: `tests/integration/deploy/test_phase3_side_process_lifecycle.py`
- Modify: `tests/integration/deploy/test_owner_ingress_route_manifest.py`
- Modify: `tests/integration/phase6/test_owner_ingress_phase6_composition.py`
- Modify: `tests/integration/vision/test_owner_ingress_takeover.py`
- Modify: `tests/fault/vision/test_owner_ingress_takeover_rollback.py`
- Modify: `tests/acceptance/release/test_install_upgrade_rollback_uninstall.py`

**Interfaces:** Produces same-candidate content-safe closure rows for `T01`–`T25`, two actual eight-hour stress receipts, one seven-day household soak, program invariant/private-data/listener/route scans, and exact enabled/absent feature evidence for C0. Each real runner requires `--candidate-manifest PATH` plus Phase 2's exact canonical `--feature-manifest-chain PATH` carrying `SignedFeatureManifestRolloverChainV1`, invokes the existing rollover verifier and `FeatureAuthorityLease` at startup, every admission/background iteration, each transition and completion, and writes evidence outside the tracked tree. The aggregate binds one rollover-chain ID, the complete ordered manifest and transition-receipt digests, the frozen candidate and the union of all campaign intervals, with zero expired-authority interval. Missing, stale, reordered, widened, rollback, signature-invalid, candidate-drifted or expired current/next authority closes work before preparation/I/O and invalidates the candidate's campaign evidence. A source/ref/manifest/artifact change likewise revokes the run rather than restarting under the same ID; no runner signs, renews or extends manifest authority.

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

def test_all_final_campaigns_share_continuous_canonical_feature_authority(evidence) -> None:
    authority = evidence.feature_manifest_authority
    assert authority.same_frozen_candidate
    assert authority.complete_ordered_chain
    assert authority.covers_exact_union(evidence.household_soak, *evidence.stress_runs)
    assert authority.expired_authority_interval_count == 0
    assert len(authority.transition_receipt_digests) == len(authority.ordered_manifest_digests) - 1

def test_maintenance_and_final_campaigns_bind_the_same_frozen_candidate(
    frozen_release, maintenance_receipt, evidence,
) -> None:
    candidate_digest = frozen_release.signed_feature_manifest.candidate_digest
    assert frozen_release.signed_feature_manifest_digest == frozen_release.release_manifest.feature_manifest_digest
    assert maintenance_receipt.feature_candidate_digest == candidate_digest
    assert evidence.feature_manifest_authority.candidate_digest == candidate_digest
    assert evidence.p6_4_acceptance.feature_candidate_digest == candidate_digest

@pytest.mark.parametrize(
    "runner_name",
    (
        "run_remote_pilot",
        "evaluate_maintenance",
        "run_threat_matrix",
        "run_stress",
        "run_household_soak",
    ),
)
def test_every_phase6_elapsed_runner_uses_the_exact_phase2_chain_interface(
    phase6_runner_cli, runner_name,
) -> None:
    parser = phase6_runner_cli.for_runner(runner_name)
    assert parser.feature_authority_option_names == ("--feature-manifest-chain",)
    parsed = parser.parse_required_feature_authority("signed-rollover-chain.json")
    assert isinstance(parsed.feature_manifest_chain, SignedFeatureManifestRolloverChainV1)

def test_final_campaign_rollover_faults_close_before_work(campaign_runner) -> None:
    for fault in (
        "missing_next", "late_next", "reordered", "widened", "rollback",
        "signature_invalid", "candidate_drifted", "wall_expired", "monotonic_expired",
    ):
        outcome = campaign_runner.inject_feature_manifest_authority_fault(fault)
        assert outcome.admission_closed_before_preparation_or_io
        assert outcome.background_work_closed_before_io
        assert outcome.campaign_invalid

def test_resource_and_growth_are_bounded(evidence) -> None:
    assert evidence.oom_count == 0 and evidence.unsafe_replay_count == 0
    assert evidence.unbounded_queue_retry_cost_audit_growth_count == 0
    assert evidence.public_or_unapproved_listener_count == 0
    assert evidence.private_data_findings == 0

def test_local_system_survives_every_external_loss(evidence) -> None:
    for dependency in ("vpn", "internet", "repository", "update_service", "tailscale_control_plane"):
        assert evidence.local_essentials_available_during(dependency)


def test_final_owner_ingress_row_rejects_interim_and_inherited_rows(
    final_owner_ingress_wheel, final_route_manifest, p6_3_owner_ingress_row,
    inherited_owner_ingress_row, final_owner_ingress_row, service_verifier,
) -> None:
    for stale in (p6_3_owner_ingress_row, inherited_owner_ingress_row):
        assert service_verifier.verify(
            stale, final_owner_ingress_wheel, final_route_manifest,
        ).denied
    assert service_verifier.verify(
        final_owner_ingress_row, final_owner_ingress_wheel, final_route_manifest,
    ).accepted
    assert final_owner_ingress_row.package_digest == final_owner_ingress_wheel.digest
    assert final_owner_ingress_row.route_manifest_digest == final_route_manifest.digest


def test_final_installed_owner_ingress_lifecycle_covers_every_signed_route(
    installed_candidate,
) -> None:
    ingress = installed_candidate.owner_ingress
    assert ingress.all_signed_phase6_routes_dispatch_once_to_peer_authenticated_core_or_media_uds
    assert ingress.unknown_and_disabled_routes_are_404_before_dispatch
    assert ingress.takeover_start_health_restart_update_rollback_both_uninstalls_pass
~~~

- [ ] **Step 2: Run red and synthetic closure**

Run: `uv run pytest tests/acceptance/phase6/test_t01_t25_closure.py tests/acceptance/phase6/test_household_soak.py tests/performance/phase6/test_eight_hour_stress.py tests/privacy/phase6/test_whole_program_sentinels.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py tests/acceptance/release/test_install_upgrade_rollback_uninstall.py -q`
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
    require(e.feature_manifest_authority.same_frozen_candidate)
    require(e.feature_manifest_authority.complete_ordered_chain)
    require(e.feature_manifest_authority.covers_all_campaign_intervals)
    require(e.feature_manifest_authority.expired_authority_interval_count == 0)
    require(e.feature_manifest_authority.every_transition_receipt_current)
    require(e.private_findings == 0 and e.public_exposure_findings == 0)
    return GateDecision.accept("whole_program_campaign", e.digest())
~~~

Run all current mandatory phase corpora/faults on the same build. Stress one run under worst simultaneous voice/video/home/media/AI/plugin/remote/update-check load and one under periodic failure/restart/storage/backup activity. Soak covers ordinary family use, Privacy Shield, remote revoke/drift, plugin crash, backup/restore probe, update rollback, incidents, device failures and maintenance logging. The complete Phase 2 pre-issued rollover chain must cover every actual interval before the first campaign begins; the existing canonical verifier performs every transition and any unavailable or invalid successor stops authoritative admissions/background work and invalidates the campaign rather than opening a grace window. Measure CPU/RAM/swap/disk/thermal/queues/retries/cost/audit and all owning phase latency/safety thresholds.

After Task 35A's final owner-facing route mutation and before any Step 6 build, rebuild `tuntun-owner-ingress` and refresh/re-sign the one canonical `phase3-owner-ingress.v1.json` row against the final wheel and final `ops/routes/owner-ingress-routes.v1.json` digest. Reject both the interim Task 29 P6-3 row and the inherited pre-Phase-6 row against this graph; either may exist only inside its complete matching rollback set. Install the final candidate and rerun every signed listener→owner-ingress→peer-authenticated Core/media UDS route, unknown/disabled 404, takeover, start/health/restart, update/rollback and both uninstall modes. Task 36B, Task 34B, Task 35R, U8B, Task 35B, Task 36C, the finalizer, C0 and C1 may consume only this post-Task-35A row and its current lifecycle receipt.

- [ ] **Step 4: Run synthetic oracle and stage exact real elapsed commands**

Run: `uv build --offline --wheel --package tuntun-owner-ingress --out-dir var/build-smoke/phase6/owner-ingress-final && uv run pytest tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py tests/acceptance/release/test_install_upgrade_rollback_uninstall.py -q && uv run python scripts/phase6/run_threat_matrix.py --synthetic --output var/evidence/phase6/threat-closure-synthetic.json && uv run python scripts/phase6/run_stress.py --synthetic --duration-seconds 28800 --runs 2 --output var/evidence/phase6/stress-synthetic.json && uv run python scripts/phase6/run_household_soak.py --synthetic --duration-seconds 604800 --output var/evidence/phase6/household-soak-synthetic.json && uv run pytest tests/acceptance/phase6/test_t01_t25_closure.py tests/acceptance/phase6/test_household_soak.py tests/performance/phase6/test_eight_hour_stress.py tests/privacy/phase6/test_whole_program_sentinels.py -q && uv run python scripts/scan_private_data.py --paths var/evidence/phase6/threat-closure-synthetic.json var/evidence/phase6/stress-synthetic.json var/evidence/phase6/household-soak-synthetic.json && uv run ruff check scripts/phase6 tests/acceptance/phase6 tests/performance/phase6 tests/privacy/phase6 tests/integration/deploy tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py tests/acceptance/release/test_install_upgrade_rollback_uninstall.py`
Expected: PASS for synthetic clocks/fault oracle. C0 remains blocked until Task 36B freezes the candidate, Task 34B and Task 35B accept P6-4 on those bytes, and Step 7 records both actual eight-hour runs plus the actual seven-day soak under `TUNTUN_ALLOW_ELAPSED_PHASE6=1`.

- [ ] **Step 5: Commit whole-program campaign tooling**

~~~bash
git add scripts/phase6/run_threat_matrix.py scripts/phase6/run_stress.py scripts/phase6/run_household_soak.py docs/evidence/phase6-soak-schema.json docs/evidence/phase6-threat-closure-schema.json tests/acceptance/phase6/test_t01_t25_closure.py tests/acceptance/phase6/test_household_soak.py tests/performance/phase6/test_eight_hour_stress.py tests/privacy/phase6/test_whole_program_sentinels.py ops/services/phase3-owner-ingress.v1.json tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/phase6/test_owner_ingress_phase6_composition.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py tests/acceptance/release/test_install_upgrade_rollback_uninstall.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(assurance): prepare final-candidate campaign tooling"
~~~

Stop Task 36 here after Task 36A. Execute Task 37 Steps 1–5 and Task 38 Steps 1–5, require those tooling commits plus an empty tree, and only then return to Task 36B below. Task 36B is not permitted to precede either later-numbered tooling stage.

- [ ] **Step 6 (Task 36B): Freeze the final bytes and qualify real targets before the maintenance clock starts**

First require an empty `git status --porcelain=v1` after the Task 36A, Task 37A and Task 38A tooling commits. Then run: `TUNTUN_ALLOW_PRODUCTION_RELEASE=1 uv run python ops/release/finalize.py --source-ref HEAD --require-clean --clean-a var/release/final-a --clean-b var/release/final-b --output var/release/frozen && TUNTUN_ALLOW_REAL_RELEASE_TARGETS=1 TUNTUN_ALLOW_REAL_LINUX_TARGETS=1 uv run pytest tests/hardware/release/test_intel_clean_install.py tests/hardware/release/test_apple_silicon_clean_install.py tests/hardware/release/test_linux_service_targets.py -m real_release --release-root var/release/frozen --signed-feature-manifest var/release/frozen/feature-manifest.json --signed-service-inventory var/release/frozen/service-inventory.json -q && uv run python ops/release/finalize.py --verify-unchanged var/release/frozen && uv run python scripts/scan_private_data.py --paths var/release/frozen && test -z "$(git status --porcelain=v1)"`.

Expected: the two clean builds, final signed/notarized/stapled inventory, both real Mac-architecture lifecycle receipts and exact lifecycle receipts for every enabled Linux service target (or cryptographically complete absence) bind one resolved commit and artifact inventory. This is the only candidate on which Task 34B may open its real steady-state epoch. From this point through publication, no tracked source, route, service row, lockfile, workflow, schema, feature registration, package or release-artifact byte may change. Any such drift, ref movement, artifact replacement, receipt mismatch or target omission invalidates the candidate and restarts at this step after all tooling changes are committed.

- [ ] **Step 7 (Task 36C): Run final threat, stress and soak campaigns on the unchanged P6-4 candidate**

Require the accepted Task 35B P6-4 receipt, the Task 34B maintenance receipt, the complete canonical rollover chain begun for this Task 36B candidate, `ops/release/finalize.py --verify-unchanged var/release/frozen`, and empty tracked status. Then run: `TUNTUN_ALLOW_ELAPSED_PHASE6=1 uv run python scripts/phase6/run_threat_matrix.py --candidate-manifest var/release/frozen/release-manifest.json --p6-4-receipt var/evidence/phase6/p6-4-accepted.json --feature-manifest-chain var/evidence/phase6/final-feature-authority/signed-rollover-chain.json --real --output var/evidence/phase6/threat-closure.json && TUNTUN_ALLOW_ELAPSED_PHASE6=1 uv run python scripts/phase6/run_stress.py --candidate-manifest var/release/frozen/release-manifest.json --feature-manifest-chain var/evidence/phase6/final-feature-authority/signed-rollover-chain.json --real --duration-seconds 28800 --runs 2 --output var/evidence/phase6/stress.json && TUNTUN_ALLOW_ELAPSED_PHASE6=1 uv run python scripts/phase6/run_household_soak.py --candidate-manifest var/release/frozen/release-manifest.json --feature-manifest-chain var/evidence/phase6/final-feature-authority/signed-rollover-chain.json --real --duration-seconds 604800 --output var/evidence/phase6/household-soak.json && uv run python ops/release/finalize.py --verify-unchanged var/release/frozen && uv run python scripts/scan_private_data.py --paths var/evidence/phase6/threat-closure.json var/evidence/phase6/stress.json var/evidence/phase6/household-soak.json && test -z "$(git status --porcelain=v1)"`.

Expected: T01–T25 closure, two actual eight-hour runs, seven actual soak days, scans, P6-4 and canonical feature-authority chain/transition receipts all bind the exact Task 36B release manifest and have zero expired-authority interval. The current Phase 1–6 mandatory control corpora and every optional-absence check are rerun against this final candidate; earlier P6-1/P6-2 receipts remain chronological sequencing evidence, not substitutes for the final-candidate rerun. This step writes evidence only. A campaign interruption or authority fault invalidates the affected campaign; candidate drift invalidates Task 34B/P6-4/Task 36C together and restarts at Step 6.

### Task 37: Prepare C0 tooling, then build and approve whole-program C0 with no waiver or Phase 1 gate alias

**Tooling-preparation dependency/order:** Tasks 01–33, Task 34 Steps 1–5, Task 35 Steps 1–5, Task 36 Steps 1–5, and UI checkpoint U8A tooling qualification. Steps 1–5 below are implemented, tested and committed **before** Task 36 Step 6 freezes final bytes; their synthetic evidence grants no C0 authority and they do not wait for Task 34B, U8B or Task 35B.
**Production-ceremony dependency/order:** Task 36 Step 7 (Task 36C), accepted P6-1–P6-4, every mandatory Phase 1–6 control rerun on that same clean commit/final artifact inventory, U8B against the same pre-C0 feature manifest/candidate, and the Task 34B non-compressible maintenance evidence. Step 6 below makes no tracked change.
**Gate contribution:** whole-program C0.
**Estimated effort:** 1.5 person-days plus owner review.

**Files:**
- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Create: `packages/release-public-contracts/pyproject.toml`
- Create: `packages/release-public-contracts/src/tuntun_release_public_contracts/__init__.py`
- Create: `packages/release-public-contracts/src/tuntun_release_public_contracts/canonical.py`
- Create: `packages/release-public-contracts/src/tuntun_release_public_contracts/c0.py`
- Create: `scripts/phase6/build_c0.py`
- Create: `scripts/phase6/approve_c0.py`
- Create: `docs/evidence/c0-evidence-schema.json`
- Create: `docs/evidence/c0-release-handoff-v1.schema.json`
- Create: `tests/unit/release/test_release_public_c0_package_smoke.py`
- Create: `tests/contract/release/test_c0_packet.py`
- Create: `tests/contract/release/test_c0_public_contract_parity.py`
- Create: `tests/security/release/test_c0_no_waiver.py`
- Create: `tests/acceptance/release/test_c0_gate.py`
- Create: `tests/fault/release/test_c0_invalidation.py`
- Create: `tests/security/release/test_c0_credential_namespace.py`

**Interfaces:** Produces `C0CandidateV1` and a distinct local owner passkey approve/reject receipt over immutable version/commit/feature manifest, the canonical exact final post-sign/notarize/staple/hash artifact-set digest, every mandatory gate/evidence digest, optional-absence proof, T01–T25 closure, hardware compatibility, soak/stress, risks/scans, clean restore/deletion and maintenance evidence. `feature_authority_evidence_digest` separately preserves the historical P6-1 sequencing-chain receipt, then binds the one final Task 36B candidate to the complete canonical Phase 2 ordered signed-manifest/transition-receipt chain across Task 34B's counted maintenance interval and every Task 36C campaign with zero expired-authority interval. Task 36C reruns the current P6-1/P6-2 and all other mandatory/optional-absence controls on that final candidate; an earlier pilot receipt cannot substitute. C0 rejects a missing, synthetic-only, discontinuous, cross-candidate or faulted chain receipt. It first-owns the minimal `tuntun-release-public-contracts` distribution containing only bounded canonical parsing plus frozen C0 candidate/accepted/handoff/named-artifact DTOs; Task 38 extends that same package with C1/publication DTOs rather than duplicating C0 types. Approval and acceptance require exact equality between the candidate and assertion artifact-set digest. A separate fresh household-owner assertion, distinct from the approval assertion and domain-bound to `tuntun.c0.release-handoff.v1`, signs the at-most-15-minute public handoff. Tooling is committed before candidate freeze; the later production invocation reads only the frozen Task 36 evidence and writes owner-only receipts under `var/evidence`, never source files.

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

def test_c0_rejects_missing_discontinuous_or_faulted_feature_authority(c0_fixture) -> None:
    for changed in (
        c0_fixture.without_feature_authority_evidence(),
        c0_fixture.with_expired_authority_interval(),
        c0_fixture.with_missing_transition_receipt(),
        c0_fixture.with_feature_authority_candidate_drift(),
    ):
        assert decide_c0(changed).denied

def test_c0_rejects_maintenance_or_final_campaign_from_another_candidate(c0_fixture) -> None:
    assert decide_c0(c0_fixture.with_cross_candidate_maintenance_receipt()).denied
    assert decide_c0(c0_fixture.with_cross_candidate_final_campaign()).denied

def test_any_tracked_change_invalidates_c0(frozen_candidate) -> None:
    for category in C0_INVALIDATING_CATEGORIES:
        assert mutate(frozen_candidate, category).c0_state == "invalid"

@pytest.mark.parametrize(
    "field",
    sorted(set(C0CandidateV1.model_fields) - {"candidate_commitment"}),
)
def test_c0_commitment_covers_every_final_candidate_field(c0_candidate, field) -> None:
    changed = c0_candidate.model_copy(update={field: valid_alternate_value(c0_candidate, field)})
    with pytest.raises(C0Denied, match="candidate_commitment_invalid"):
        require_valid_c0_candidate_commitment(changed)

async def test_c0_requires_fresh_local_owner_passkey(
    c0_service, c0_candidate, remote_or_stale_approval,
) -> None:
    result = await c0_service.approve(c0_candidate, remote_or_stale_approval)
    assert result.code in {"REMOTE_OPERATION_DENIED", "ASSURANCE_INSUFFICIENT"}

@pytest.mark.parametrize("receipt_type", [C0ApprovalReceiptV1, C0RejectionReceiptV1])
def test_c0_assertion_binds_exact_candidate_artifacts_and_fresh_owner_credential(receipt_type, c0_payload) -> None:
    receipt = receipt_type.model_validate(c0_payload.for_type(receipt_type))
    assert receipt.credential_namespace == "household_owner_c0"
    assert receipt.signature_domain == "tuntun.c0.household-owner.v1"
    assert receipt.local_presence is True
    assert receipt.candidate_id and receipt.candidate_commitment and receipt.artifact_set_digest
    assert receipt.artifact_inventory_digest
    assert receipt.assertion_id and receipt.signer_identity and receipt.credential_revocation_generation >= 1

async def test_c0_accepted_receipt_requires_current_unrevoked_approval(
    c0_service, c0_candidate, approval,
) -> None:
    accepted = await c0_service.accept(c0_candidate, approval)
    assert isinstance(accepted, C0AcceptedReceiptV1)
    assert accepted.accepted_assertion_id == approval.assertion_id
    assert accepted.artifact_set_digest == c0_candidate.artifact_set_digest == approval.artifact_set_digest
    assert accepted.artifact_inventory_digest == c0_candidate.artifact_inventory_digest
    assert accepted.artifact_inventory_digest == approval.artifact_inventory_digest == c0_service.frozen_inventory.digest
    stale = approval.with_revocation_generation(approval.credential_revocation_generation - 1)
    assert (await c0_service.accept(c0_candidate, stale)).denied

async def test_c0_acceptance_cannot_lose_or_substitute_immutable_approval_receipt(
    c0_service, c0_candidate, approval_store, approval,
) -> None:
    approval_store.delete(approval.assertion_id)
    assert (await c0_service.accept(c0_candidate, approval)).reason_code == "approval_receipt_missing"
    approval_store.put(approval.with_signer_identity("different-signer"))
    assert (await c0_service.accept(c0_candidate, approval)).reason_code == "approval_receipt_binding_invalid"

async def test_c0_release_handoff_requires_distinct_fresh_owner_assertion(
    c0_service, c0_candidate, accepted_c0, owner_credential,
) -> None:
    reused = await c0_service.build_release_handoff(
        c0_candidate, accepted_c0, owner_credential.reuse(accepted_c0.accepted_assertion_id),
    )
    assert reused.code == "ASSURANCE_INSUFFICIENT"
    handoff = await c0_service.build_release_handoff(
        c0_candidate, accepted_c0, owner_credential.fresh_assertion(),
    )
    assert isinstance(handoff, C0ReleaseHandoffV1)
    assert handoff.handoff_assertion_id != accepted_c0.accepted_assertion_id
    assert handoff.valid_until <= handoff.issued_at + timedelta(minutes=15)

def test_release_public_c0_package_is_minimal_and_locked(installed_workspace) -> None:
    assert installed_workspace.version("tuntun-release-public-contracts") == "0.1.0.dev0"
    assert installed_workspace.exports("tuntun_release_public_contracts") == EXPECTED_C0_PUBLIC_EXPORTS
    assert installed_workspace.import_closure("tuntun_release_public_contracts").isdisjoint(HOUSEHOLD_MODULES)

@pytest.mark.parametrize("fixture_name", C0_PUBLIC_CONTRACT_POSITIVE_AND_BOUNDARY_FIXTURES)
def test_installed_c0_public_and_core_contracts_have_exact_shape_and_bytes(
    installed_contract_pair, fixture_name,
) -> None:
    core_type, public_type = installed_contract_pair.for_fixture(fixture_name)
    raw = canonical_hardening_bytes(load_fixture(fixture_name))
    assert contract_shape_digest(core_type) == contract_shape_digest(public_type)
    core_value = core_type.model_validate_json(raw)
    public_value = public_type.model_validate_json(raw)
    assert canonical_hardening_bytes(core_value) == raw
    assert canonical_public_bytes(public_value) == raw
    assert core_type.model_validate(public_value.model_dump(mode="python"))
    assert public_type.model_validate(core_value.model_dump(mode="python"))

@pytest.mark.parametrize("wrong_namespace", ["project_maintainer_c1", "project_maintainer_publication"])
def test_project_maintainer_credentials_cannot_decide_c0(c0_service, wrong_namespace) -> None:
    assert c0_service.decide(credential_namespace=wrong_namespace).code == "ASSURANCE_INSUFFICIENT"
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/release/test_c0_packet.py tests/contract/release/test_c0_public_contract_parity.py tests/security/release/test_c0_no_waiver.py tests/acceptance/release/test_c0_gate.py tests/fault/release/test_c0_invalidation.py -q`
Expected: FAIL because C0 builder/approval/invalidation are absent.

- [ ] **Step 3: Implement strict C0 builder and local passkey freeze ceremony**

Append `packages/release-public-contracts` to the root uv workspace, update `uv.lock`, and bootstrap it before either C0 script imports it. Its Hatchling project is Python `==3.12.*`, version `0.1.0.dev0`, depends only on `pydantic>=2.11,<3` and `rfc8785>=0.1.4,<0.2`, and exports only the explicit canonical/C0 public symbols. `__init__.py` defines the matching version. Static wheel inspection rejects `tuntun_contracts`, `tuntun_core`, household apps, dynamic path injection and undeclared imports. Because the isolated wheel deliberately duplicates wire DTOs from `tuntun-contracts`, the installed-wheel parity gate compares fully dereferenced JSON-schema shapes after stripping only non-semantic module/title metadata; field names, requiredness, unions, literals, bounds, patterns and nested definitions remain in the digest. Positive plus min/max/time-window fixtures must parse reciprocally and RFC 8785-encode to identical bytes in both packages. Any shared DTO change therefore requires the same commit to update both surfaces and their golden fixtures.

~~~python
C0_INVALIDATING_CATEGORIES = frozenset({
    "source", "lockfile", "workflow", "schema", "feature_manifest", "dependency",
    "package", "evidence_policy", "release_artifact",
})

def build_c0(inputs: WholeProgramEvidence) -> C0CandidateV1:
    require(inputs.one_clean_immutable_commit_and_version)
    require(inputs.historical_phase_gate_sequence_complete_and_current)
    require(inputs.every_current_mandatory_control_same_final_candidate)
    require(inputs.optional_absences_are_canonical_and_negative_complete)
    require(inputs.threat_ids == tuple(f"T{i:02d}" for i in range(1, 26)) and inputs.all_threats_closed)
    require(inputs.exact_hardware_firmware_compatibility and inputs.seven_day_soak)
    require(inputs.two_eight_hour_stress_runs and inputs.high_critical_open == 0)
    require(inputs.feature_manifest_authority_evidence.final_candidate_same_across_maintenance_and_campaigns)
    require(inputs.feature_manifest_authority_evidence.complete_ordered_chain)
    require(inputs.feature_manifest_authority_evidence.preserves_historical_p6_1_sequencing_receipt)
    require(inputs.feature_manifest_authority_evidence.covers_final_candidate_maintenance_and_all_final_campaign_intervals)
    require(inputs.feature_manifest_authority_evidence.expired_authority_interval_count == 0)
    require(inputs.feature_manifest_authority_evidence.every_transition_receipt_current)
    require(inputs.clean_owner_restore and inputs.deletion_no_resurrection)
    require(inputs.listener_route_private_scans_clean)
    require(inputs.maintenance_noncompressible_window_satisfied)
    require(not inputs.has_waiver_or_gate_reclassification)
    fields = {
        "schema_id": "c0_candidate.v1",
        "candidate_id": uuid4(), "version": inputs.version,
        "source_commit": inputs.source_commit,
        "feature_manifest_digest": inputs.feature_manifest_digest,
        "feature_authority_evidence_digest": inputs.feature_manifest_authority_evidence.digest(),
        "artifact_set_digest": inputs.final_post_staple_artifact_set_digest,
        "artifact_inventory_digest": inputs.final_post_staple_artifact_inventory_digest,
        "tracked_inputs_digest": inputs.tracked_inputs_digest(),
        "mandatory_phase_gate_bundle_digest": inputs.mandatory_gate_bundle_digest(),
        "canonical_optional_absence_digest": inputs.optional_absence_digest(),
        "threat_t01_t25_closure_digest": inputs.threat_closure_digest(),
        "hardware_compatibility_digest": inputs.hardware_compatibility_digest(),
        "seven_day_soak_digest": inputs.soak_digest,
        "eight_hour_stress_digests": inputs.stress_digests,
        "clean_restore_digest": inputs.clean_restore_digest,
        "deletion_no_resurrection_digest": inputs.deletion_no_resurrection_digest,
        "maintenance_evidence_digest": inputs.maintenance_digest,
        "listener_route_private_scan_digest": inputs.scan_digest(),
        "built_at": inputs.observed_at,
    }
    candidate = C0CandidateV1(
        **fields,
        candidate_commitment=candidate_commitments.hmac_canonical_mapping(
            domain="tuntun.c0-candidate.v1", value=fields,
        ),
    )
    require_valid_c0_candidate_commitment(candidate)
    c0_candidates.put_new_immutable(candidate)
    return candidate

def require_valid_c0_candidate_commitment(candidate: C0CandidateV1) -> None:
    fields = candidate.model_dump(mode="python", exclude={"candidate_commitment"})
    expected = candidate_commitments.hmac_canonical_mapping(
        domain="tuntun.c0-candidate.v1", value=fields,
    )
    if not hmac.compare_digest(expected, candidate.candidate_commitment):
        raise C0Denied("candidate_commitment_invalid")

async def approve_c0(candidate, local_owner_passkey) -> C0ApprovalReceiptV1:
    candidate = c0_candidates.require_current_exact(
        candidate.candidate_id, candidate.candidate_commitment,
    )
    require_valid_c0_candidate_commitment(candidate)
    approval = await require_fresh_local_owner_passkey(local_owner_passkey, purpose="c0_freeze")
    approval_receipt = await sign_exact_c0_assertion(candidate, approval, decision="approve")
    return C0ApprovalReceiptV1.model_validate(approval_receipt)

async def reject_c0(candidate, local_owner_passkey, reasons) -> C0RejectionReceiptV1:
    candidate = c0_candidates.require_current_exact(
        candidate.candidate_id, candidate.candidate_commitment,
    )
    require_valid_c0_candidate_commitment(candidate)
    assertion = await require_fresh_local_owner_passkey(local_owner_passkey, purpose="c0_freeze")
    return await sign_exact_c0_assertion(candidate, assertion, decision="reject", reason_codes=reasons)

async def accept_c0(candidate, approval: C0ApprovalReceiptV1) -> C0AcceptedReceiptV1:
    candidate = c0_candidates.require_current_exact(
        candidate.candidate_id, candidate.candidate_commitment,
    )
    require_valid_c0_candidate_commitment(candidate)
    require(approval.artifact_set_digest == candidate.artifact_set_digest)
    require(approval.artifact_inventory_digest == candidate.artifact_inventory_digest)
    require_current_unrevoked_exact_assertion(candidate, approval)
    return await freeze_exact_candidate(candidate, approval.assertion_commitment)

async def build_c0_release_handoff(
    candidate: C0CandidateV1,
    accepted: C0AcceptedReceiptV1,
    fresh_handoff_passkey,
    final_inventory: FinalArtifactInventoryV1,
) -> C0ReleaseHandoffV1:
    candidate = c0_candidates.require_current_exact(
        candidate.candidate_id, candidate.candidate_commitment,
    )
    require_valid_c0_candidate_commitment(candidate)
    accepted = accepted_c0_store.require_current_exact(
        candidate.candidate_id, accepted.accepted_commitment,
    )
    final_inventory.require_exact_candidate(candidate)
    assertion = await require_fresh_local_owner_passkey(
        fresh_handoff_passkey,
        purpose="c0_release_handoff",
        distinct_from=accepted.accepted_assertion_id,
    )
    now = release_clock.now()
    fields = {
        "schema_id": "c0_release_handoff.v1",
        "handoff_id": uuid4(),
        "handoff_generation": handoff_generations.allocate_next_durable(),
        "candidate": candidate,
        "candidate_canonical_digest": sha256(canonical_hardening_bytes(candidate)).hexdigest(),
        "accepted_c0": accepted,
        "accepted_c0_commitment": accepted.accepted_commitment,
        "release_manifest_digest": final_inventory.release_manifest_digest,
        "artifact_set_digest": candidate.artifact_set_digest,
        "artifact_inventory_digest": candidate.artifact_inventory_digest,
        "artifact_digests": final_inventory.artifact_digests,
        "credential_status": "current",
        "handoff_assertion_id": assertion.assertion_id,
        "handoff_signer_identity": assertion.signer_identity,
        "handoff_key_generation": assertion.credential_revocation_generation,
        "signature_domain": "tuntun.c0.release-handoff.v1",
        "issued_at": now,
        "valid_until": now + timedelta(minutes=15),
    }
    signature = await sign_canonical_local_assertion(
        assertion,
        domain="tuntun.c0.release-handoff.v1",
        payload=canonical_hardening_bytes(fields),
    )
    return C0ReleaseHandoffV1.model_validate({**fields, "handoff_signature": signature})
~~~

Hardware-conditioned not-applicable is allowed only when the owning canonical phase spec defines the condition and the named hardware/route is genuinely absent. The feature manifest cannot reclassify. C0 official evidence contains digests/safe metrics only and is created in order on the frozen clean commit. The domain-separated commitment is computed only after the UUID and complete unsigned field map exist; verification derives its input from every model field except the commitment itself, so a newly added field is automatically covered. Build, approve, reject, accept, restart and later C1/publication boundaries all reload the immutable candidate and reverify that commitment before trusting any field.

- [ ] **Step 4: Run green, mutation matrix, synthetic builder, and approval denial tests**

Run: `uv lock && uv sync --all-packages && uv run pytest tests/unit/release/test_release_public_c0_package_smoke.py tests/contract/release/test_c0_packet.py tests/contract/release/test_c0_public_contract_parity.py tests/security/release/test_c0_no_waiver.py tests/security/release/test_c0_credential_namespace.py tests/acceptance/release/test_c0_gate.py tests/fault/release/test_c0_invalidation.py -q && uv build packages/release-public-contracts && uv run python scripts/phase6/build_c0.py --synthetic fixtures/synthetic/phase6/releases/c0-input.json --output var/evidence/phase6/c0-synthetic-unsigned.json && uv run python scripts/phase6/approve_c0.py --synthetic-reject-remote-stale-revoked-cross-namespace var/evidence/phase6/c0-synthetic-unsigned.json && uv run python scripts/scan_private_data.py --paths var/evidence/phase6/c0-synthetic-unsigned.json && uv run ruff check packages/release-public-contracts scripts/phase6/build_c0.py scripts/phase6/approve_c0.py tests/unit/release/test_release_public_c0_package_smoke.py tests/contract/release tests/security/release tests/acceptance/release tests/fault/release`
Expected: PASS; every mutation/alias/waiver denies, synthetic packet verifies but has no production approval, and private scan is clean.

- [ ] **Step 5: Commit C0 builder/freeze tooling before final candidate creation**

~~~bash
git add pyproject.toml uv.lock packages/release-public-contracts scripts/phase6/build_c0.py scripts/phase6/approve_c0.py docs/evidence/c0-evidence-schema.json docs/evidence/c0-release-handoff-v1.schema.json tests/unit/release/test_release_public_c0_package_smoke.py tests/contract/release/test_c0_packet.py tests/contract/release/test_c0_public_contract_parity.py tests/security/release/test_c0_no_waiver.py tests/security/release/test_c0_credential_namespace.py tests/acceptance/release/test_c0_gate.py tests/fault/release/test_c0_invalidation.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(release): freeze the whole-program C0 candidate"
~~~

This commit is a prerequisite to Task 36 Step 6, not a C0 approval. After it and the Task 38A commit, do not change tracked files while completing Task 36B, Task 34B, Task 35R, U8B, Task 35B, Task 36C or the production ceremony below.

- [ ] **Step 6: Execute the production C0 ceremony against the unchanged frozen candidate**

Require empty `git status --porcelain=v1`, then run: `TUNTUN_ALLOW_PRODUCTION_C0=1 uv run python scripts/phase6/build_c0.py --release-root var/release/frozen --evidence-root var/evidence/phase6 --require-current-head --output var/evidence/phase6/c0-unsigned.json && TUNTUN_ALLOW_PRODUCTION_C0=1 uv run python scripts/phase6/approve_c0.py --candidate var/evidence/phase6/c0-unsigned.json --local-owner-passkey-ceremony --output var/evidence/phase6/c0-accepted.json --fresh-handoff-passkey-ceremony --release-handoff-output var/evidence/phase6/c0-release-handoff.json && uv run python scripts/phase6/build_c0.py --verify-accepted var/evidence/phase6/c0-accepted.json --release-root var/release/frozen --evidence-root var/evidence/phase6 && uv run python scripts/scan_private_data.py --paths var/evidence/phase6/c0-unsigned.json var/evidence/phase6/c0-accepted.json var/evidence/phase6/c0-release-handoff.json`.

Expected: builder, approval and verification independently reload the immutable C0 candidate, exact final inventory and every evidence digest; the approval and handoff flags each run a fresh local household-owner ceremony, the two assertion IDs must differ, and each assertion is consumed once for only its domain. `git status --porcelain=v1` stays empty. Reject or any missing/stale/revoked/substituted input leaves no accepted C0 and returns to Task 36 Step 6 after a new clean candidate and a new Task 34B/Task 35R/U8B/P6-4/Task 36C evidence sequence.

### Task 38: Prepare isolated C1/publication tooling, then approve and manually publish the immutable beta

**Tooling-preparation dependency/order:** Tasks 01–33, Task 34 Steps 1–5, Task 35 Steps 1–5, Task 36 Steps 1–5, the Task 37 tooling-preparation commit, and UI checkpoint U8A tooling qualification. Steps 1–5 below create/test/commit the isolated contracts and terminal **before** Task 36 Step 6 freezes final bytes; they do not wait for Task 34B/U8B/Task 35B and no synthetic receipt is C1 authority.
**Production-ceremony dependency/order:** accepted C0 from Task 37 Step 6, unchanged Task 36B candidate plus Task 34B/Task 35R/U8B/Task 35B/Task 36C evidence, complete reproducible/public/macOS evidence and protected publication access. Step 6 below creates no tracked file. U25's C1/publication UI and U8A verifier were qualified before C0 from frozen projections; production must verify actual signed C1/publication state through the unchanged read-only projection and preserve current U8B before claiming P6-5.
**Gate contribution:** C1 and P6-5 completion.
**Estimated effort:** 2 person-days plus clean-build/notarization/publication elapsed time.

**Files:**
- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Modify: `packages/release-public-contracts/src/tuntun_release_public_contracts/__init__.py`
- Create: `packages/release-public-contracts/src/tuntun_release_public_contracts/c1.py`
- Create: `packages/release-public-contracts/src/tuntun_release_public_contracts/publication.py`
- Create: `scripts/phase6/build_c1.py`
- Create: `scripts/phase6/approve_c1.py`
- Create: `scripts/phase6/verify_release.py`
- Create: `ops/release/publish.py`
- Create: `apps/release-maintainer/README.md`
- Create: `apps/release-maintainer/pyproject.toml`
- Create: `apps/release-maintainer/src/tuntun_release_maintainer/__init__.py`
- Create: `apps/release-maintainer/src/tuntun_release_maintainer/main.py`
- Create: `apps/release-maintainer/src/tuntun_release_maintainer/c1.py`
- Create: `apps/release-maintainer/src/tuntun_release_maintainer/publication.py`
- Create: `apps/release-maintainer/src/tuntun_release_maintainer/credentials.py`
- Create: `apps/release-maintainer/src/tuntun_release_maintainer/uploader.py`
- Create: `docs/evidence/c1-evidence-schema.json`
- Create: `tests/contract/release/test_c1_packet.py`
- Create: `tests/contract/release/test_c1_public_contract_parity.py`
- Create: `tests/security/release/test_c1_separation_and_manual_publish.py`
- Create: `tests/acceptance/release/test_c1_gate.py`
- Create: `tests/acceptance/phase6/test_p6_5_gate.py`
- Create: `tests/fault/release/test_c1_failure_returns_to_c0.py`
- Create: `tests/security/release/test_maintainer_terminal_boundary.py`
- Create: `tests/unit/release/test_release_public_package_smoke.py`

**Interfaces:** Produces C1 packet on unchanged accepted C0, a second distinct fresh project-maintainer passkey receipt at the local release terminal binding every public artifact/evidence digest, publication manifest, manual immutable publish receipt, and independently verified P6-5 release/support result. One canonical `PreparedPublicationStore` durably owns each prepared descriptor plus its manifest/signature and is the only reader used by C1 build, publication preparation, publication execution, uploader revalidation and restart reconciliation; there is no second publication-store alias or copied authority. This project identity is independently provisioned and has no household authentication or recovery authority. `tuntun-release-public-contracts` is a separate minimal distribution containing only frozen C0-accepted/C0-release-handoff/C1/publication DTOs plus bounded canonical parsing; it contains no household identity, memory, backup, diagnostics, device, media, policy or authentication module. `C0ReleaseHandoffV1` binds canonical C0 candidate bytes/digest, accepted receipt/commitment, final release/artifact inventory, a content-free current credential-generation status, issued/expiry times of at most 15 minutes and a one-use handoff ID under domain `tuntun.c0.release-handoff.v1`. The household C0 tool writes it owner-only; the maintainer imports it by explicit local file selection into its own immutable one-use store and verifies the public signatures/bytes without a household API, package, database or credential. `tuntun-release-maintainer` depends only on that distribution plus its CLI/cryptographic transport dependencies and exposes the frozen entry point `tuntun-release-maintainer = tuntun_release_maintainer.main:app`. Production C1 approval and publication are available only through this installed terminal; `scripts/phase6/*.py` and `ops/release/publish.py` are synthetic/verifier wrappers and cannot load a production credential handle or upload.

**Rollback/disabled exit:** A failed C1 check or post-C0 tracked change invalidates C0/C1 and requires a new C0 candidate. CI cannot approve or publish. Published defects create a new version/advisory; assets are never overwritten.

- [ ] **Step 1: Write red separation, unchanged candidate, exact evidence, second approval, and manual-publish tests**

~~~python
def test_c1_requires_accepted_unchanged_c0(c1_builder, c0) -> None:
    assert c1_builder.build(c0.with_source_change()).decision == "new_c0_required"

def test_c1_cannot_rebuild_or_substitute_one_artifact_after_c0(c1_builder, accepted_c0, public_evidence) -> None:
    assert c1_builder.build(accepted_c0, public_evidence.mutate_one_artifact_byte()).decision == "new_c0_required"
    assert c1_builder.build(accepted_c0, public_evidence.rebuild_same_source()).decision == "new_c0_required"

@pytest.mark.parametrize(
    "field",
    sorted(set(C1CandidateV1.model_fields) - {"candidate_commitment"}),
)
def test_c1_commitment_covers_every_final_candidate_field(c1_candidate, field) -> None:
    changed = c1_candidate.model_copy(update={field: valid_alternate_value(c1_candidate, field)})
    with pytest.raises(C1Denied, match="candidate_commitment_invalid"):
        require_valid_c1_candidate_commitment(changed)

@pytest.mark.parametrize("fault", [
    "accepted_c0_missing", "accepted_c0_revoked", "accepted_c0_stale",
    "accepted_c0_commitment_substituted", "accepted_c0_candidate_substituted",
    "accepted_c0_artifact_inventory_drift",
])
async def test_c1_approval_reloads_authoritative_c0_before_credential_use(
    c1_service, candidate, maintainer, fault,
) -> None:
    c1_service.inject_authoritative_c0_fault(fault)
    result = await c1_service.approve(candidate, maintainer.fresh_distinct_assertion())
    assert result.code == "new_c0_required"
    assert c1_service.credential_consume_calls == 0

def test_c1_uses_fresh_signed_public_handoff_not_household_api(c1_service, c0_handoff) -> None:
    assert c0_handoff.signature_domain == "tuntun.c0.release-handoff.v1"
    assert c0_handoff.valid_until <= c0_handoff.issued_at + timedelta(minutes=15)
    c1_service.load_handoff(c0_handoff)
    assert c1_service.household_api_calls == 0
    assert c1_service.household_store_imports == ()
    assert c1_service.build().c0_candidate_id == c0_handoff.candidate.candidate_id

@pytest.mark.parametrize(
    "field",
    sorted(set(C0ReleaseHandoffV1.model_fields) - {"handoff_signature"}),
)
def test_c0_handoff_signature_or_binding_covers_every_unsigned_field(
    handoff_importer, c0_handoff, field,
) -> None:
    changed = mutate_one_field(c0_handoff, field)
    assert handoff_importer.import_handoff(changed).code == "c0_handoff_invalid"
    assert handoff_importer.maintainer_credential_calls == 0

@pytest.mark.parametrize("fault", [
    "invalid_utf8", "duplicate_key", "noncanonical_json", "nonfinite_number",
    "depth_33", "container_4097", "structure_token_16385", "oversize",
    "missing_file", "permission_denied", "symlink", "non_regular", "wrong_owner",
    "mode_too_open", "nlink_not_one", "short_read", "growth_during_read",
    "replacement_during_read", "wrong_signature", "self_selected_signer",
    "stale_key_generation", "revoked_credential_status", "candidate_bytes_substituted",
    "accepted_receipt_substituted", "artifact_inventory_substituted",
])
def test_c0_handoff_raw_file_signature_and_binding_faults_fail_before_credential(
    handoff_importer, fault,
) -> None:
    result = handoff_importer.import_file_with_fault(fault)
    assert result.code == "c0_handoff_invalid"
    assert handoff_importer.maintainer_credential_calls == 0
    assert handoff_importer.current_handoffs == ()

def test_c0_handoff_import_is_one_use_and_restart_safe(handoff_importer, c0_handoff) -> None:
    imported = handoff_importer.import_handoff(c0_handoff)
    restarted = handoff_importer.restart()
    assert restarted.require_current(imported.handoff_id).handoff_id == c0_handoff.handoff_id
    restarted.consume_once(imported.handoff_id)
    assert restarted.import_handoff(c0_handoff).code == "c0_handoff_replayed"
    assert restarted.maintainer_credential_calls == 0

@pytest.mark.parametrize("edge", ["before_store_fsync", "after_store_fsync"])
def test_c0_handoff_import_interruption_recovers_zero_or_one_exact_record(
    handoff_importer, c0_handoff, edge,
) -> None:
    handoff_importer.crash_import_at(c0_handoff, edge)
    restarted = handoff_importer.restart_and_reconcile()
    assert restarted.current_handoff_count in {0, 1}
    if restarted.current_handoff_count == 1:
        assert restarted.current_handoff.canonical_bytes == canonical_hardening_bytes(c0_handoff)
    assert restarted.duplicate_handoff_records == ()

def test_c1_requires_complete_public_artifact_evidence(c1_fixture) -> None:
    for field in (
        "reproducible_build", "dependency_licence", "spdx_sbom", "provenance",
        "checksums_signatures", "developer_id_hardened_runtime", "notarization_stapling_gatekeeper",
        "intel_lifecycle", "apple_silicon_lifecycle", "linux_service_lifecycle",
        "simulator_docs_support",
        "source_history_artifact_scan", "intended_immutable_tag",
        "immutable_tag_target_available",
    ):
        assert decide_c1(c1_fixture.without(field)).denied

async def test_c1_approval_is_distinct_and_fresh(c0_receipt, c1_service, candidate) -> None:
    result = await c1_service.approve(candidate, c0_receipt.passkey_assertion)
    assert result.code == "ASSURANCE_INSUFFICIENT"

def test_green_ci_cannot_publish(publish_workflow) -> None:
    assert publish_workflow.automatic_triggers == ()
    assert publish_workflow.requires_c1_receipt and publish_workflow.requires_manual_confirmation

def test_failed_c1_returns_to_new_c0(candidate) -> None:
    assert fail_one_c1_check(candidate).next_gate == "C0"

async def test_c1_rejection_and_acceptance_are_closed_current_receipts(
    c1_service, candidate, maintainer,
) -> None:
    rejected = await c1_service.reject(candidate, maintainer, reasons=("artifact_mismatch",))
    assert isinstance(rejected, C1RejectionReceiptV1)
    assert rejected.credential_namespace == "project_maintainer_c1"
    approved = await c1_service.approve(candidate, maintainer.fresh_distinct_assertion())
    accepted = await c1_service.accept(candidate, approved)
    assert isinstance(approved, C1ApprovalReceiptV1)
    assert isinstance(accepted, C1AcceptedReceiptV1)
    assert accepted.accepted_assertion_id == approved.assertion_id
    assert accepted.artifact_set_digest == candidate.artifact_set_digest == approved.artifact_set_digest
    assert accepted.artifact_inventory_digest == candidate.artifact_inventory_digest == approved.artifact_inventory_digest
    assert accepted.publication_manifest_digest == candidate.publication_manifest_digest
    assert accepted.release_manifest_digest == candidate.release_manifest_digest

async def test_c1_acceptance_cannot_lose_or_substitute_immutable_approval_receipt(
    c1_service, candidate, approval_store, approval,
) -> None:
    approval_store.delete(approval.assertion_id)
    assert (await c1_service.accept(candidate, approval)).reason_code == "approval_receipt_missing"
    approval_store.put(approval.with_signature_from_other_signer())
    assert (await c1_service.accept(candidate, approval)).reason_code == "approval_receipt_binding_invalid"

def test_publication_is_third_fresh_exact_action(c1_service, accepted_c1, publication_assertion) -> None:
    action = c1_service.prepare_publication(accepted_c1)
    publication_assertion.sign_challenge(sha256(canonical_hardening_bytes(action)).digest())
    receipt = c1_service.publish(action, publication_assertion)
    assert isinstance(receipt, PublicationReceiptV1)
    assert receipt.credential_namespace == "project_maintainer_publication"
    assert receipt.signature_domain == "tuntun.publication.project-maintainer.v1"
    assert receipt.accepted_c1_commitment == accepted_c1.accepted_commitment
    assert receipt.exact_published_artifact_set_digest == accepted_c1.artifact_set_digest
    assert receipt.exact_published_artifact_inventory_digest == accepted_c1.artifact_inventory_digest
    assert receipt.immutable_tag == action.immutable_tag
    assert receipt.published_source_commit == c1_service.current_candidate.source_commit
    assert receipt.tag_created_without_overwrite is True
    assert receipt.tag_target_verified is True
    assert receipt.issued_at <= receipt.authority_claimed_at < receipt.expires_at
    assert receipt.authority_claimed_at <= receipt.published_at < receipt.operation_deadline
    assert receipt.publication_manifest_digest == accepted_c1.publication_manifest_digest
    assert receipt.final_release_manifest_digest == accepted_c1.release_manifest_digest
    assert receipt.publication_action_id == action.publication_action_id
    assert receipt.publication_action_commitment == action.action_commitment
    assert receipt.assertion_id == publication_assertion.assertion_id
    assert receipt.assertion_id != accepted_c1.accepted_assertion_id

@pytest.mark.parametrize("expiry_position", ["exact", "past"])
def test_publication_action_expired_before_claim_creates_no_effect_run_or_write(
    c1_service, accepted_c1, publication_assertion, expiry_position,
) -> None:
    action = c1_service.prepare_publication(accepted_c1)
    if expiry_position == "exact":
        c1_service.clock.advance_to(action.expires_at)
    else:
        c1_service.clock.advance_past(action.expires_at)
    result = c1_service.publish(action, publication_assertion)
    assert result.code == "publication_action_invalid"
    assert c1_service.publication_effect_runs == ()
    assert c1_service.first_remote_write_calls == 0


@pytest.mark.parametrize("boundary", ["put_pending", "load_pending", "claim_effect_run"])
def test_action_store_io_failure_is_bounded_before_remote_write(
    c1_service, accepted_c1, publication_assertion, boundary,
) -> None:
    result = c1_service.publish_with_action_store_fault(
        accepted_c1, publication_assertion, boundary, OSError("synthetic store I/O"),
    )
    assert result.code == "publication_action_invalid"
    assert c1_service.first_remote_write_calls == 0
    assert c1_service.publication_receipts == ()


def test_action_store_programmer_fault_remains_visible(
    c1_service, accepted_c1, publication_assertion,
) -> None:
    with pytest.raises(ValueError, match="programmer fault"):
        c1_service.publish_with_action_store_fault(
            accepted_c1, publication_assertion, "claim_effect_run",
            ValueError("programmer fault"),
        )
    assert c1_service.first_remote_write_calls == 0

def test_assertion_expiry_after_durable_claim_does_not_cancel_exact_bounded_run(
    c1_service, accepted_c1, publication_assertion,
) -> None:
    action = c1_service.prepare_publication(accepted_c1)
    pending = c1_service.pause_publish_after_durable_claim(action, publication_assertion)
    c1_service.clock.advance_past(action.expires_at)
    receipt = c1_service.resume_exact_publication_run(pending.run_id)
    assert isinstance(receipt, PublicationReceiptV1)
    assert receipt.authority_claimed_at < action.expires_at < receipt.published_at
    assert receipt.published_at < receipt.operation_deadline
    assert receipt.publication_action_commitment == action.action_commitment

@pytest.mark.parametrize("deadline_position", ["exact", "past"])
def test_publication_effect_deadline_or_binding_substitution_never_widens_authority(
    c1_service, accepted_c1, publication_assertion, deadline_position,
) -> None:
    action = c1_service.prepare_publication(accepted_c1)
    pending = c1_service.pause_publish_after_durable_claim(action, publication_assertion)
    if deadline_position == "exact":
        c1_service.clock.advance_to(pending.operation_deadline)
    else:
        c1_service.clock.advance_past(pending.operation_deadline)
    assert c1_service.resume_exact_publication_run(pending.run_id).code == "publication_upload_unverified"
    with pytest.raises(PublicationActionDenied):
        c1_service.resume_exact_publication_run(
            pending.run_id, override_candidate_id=uuid4(),
        )
    assert c1_service.remote_overwrite_calls == 0


def test_pre_c1_acceptance_failure_retains_only_accepted_c0(c1_service, accepted_c0) -> None:
    result = c1_service.fail_before_c1_acceptance(accepted_c0)
    assert not isinstance(result, C1AcceptedReceiptV1)
    assert c1_service.current_accepted_c0 == accepted_c0
    assert c1_service.accepted_c1_history == ()
    assert c1_service.publication_receipts == ()


def test_post_c1_pre_receipt_failure_preserves_c1_and_records_unverified_publication(
    c1_service, accepted_c1, publication_assertion,
) -> None:
    result = c1_service.publish_with_upload_fault(
        accepted_c1, publication_assertion, "ambiguous_timeout",
    )
    assert result.code == "publication_upload_unverified"
    assert c1_service.current_accepted_c1 == accepted_c1
    assert c1_service.accepted_c1_history == (accepted_c1,)
    assert c1_service.publication_receipts == ()
    assert c1_service.one_exact_incomplete_publication_run_for(accepted_c1)


def test_drift_after_c1_invalidates_publication_eligibility_without_erasing_history(
    c1_service, accepted_c1,
) -> None:
    c1_service.mutate_frozen_source_after_c1()
    result = c1_service.prepare_publication(accepted_c1)
    assert result.code == "publication_not_authorized"
    assert c1_service.accepted_c1_history == (accepted_c1,)
    assert c1_service.publication_receipts == ()
    assert c1_service.requires_new_c0_candidate
    assert not c1_service.can_reuse_accepted_c1_for_changed_bytes

@pytest.mark.parametrize("field", [
    "candidate_id", "accepted_c1_commitment", "publication_manifest_digest",
    "release_manifest_digest", "artifact_set_digest", "artifact_inventory_digest",
    "immutable_tag", "purpose", "issued_at", "expires_at", "action_commitment",
])
def test_publication_action_one_field_substitution_never_uploads(
    c1_service, accepted_c1, publication_assertion, field,
) -> None:
    action = c1_service.prepare_publication(accepted_c1)
    result = c1_service.publish(mutate_one_field(action, field), publication_assertion)
    assert result.code == "publication_action_invalid"
    assert c1_service.upload_calls == 0

def test_publication_assertion_cannot_cross_candidate_or_replay(
    c1_service, accepted_c1, second_accepted_c1, publication_assertion,
) -> None:
    first = c1_service.prepare_publication(accepted_c1)
    second = c1_service.prepare_publication(second_accepted_c1)
    publication_assertion.sign_challenge(sha256(canonical_hardening_bytes(first)).digest())
    assert c1_service.publish(second, publication_assertion).code == "publication_action_invalid"
    assert isinstance(c1_service.publish(first, publication_assertion), PublicationReceiptV1)
    assert c1_service.publish(first, publication_assertion).code == "publication_action_invalid"
    assert c1_service.upload_calls == 1

@pytest.mark.parametrize("fault", [
    "stale_c1", "revoked_c1", "missing_candidate", "artifact_set_drift",
    "artifact_inventory_drift", "accepted_commitment_mismatch",
])
def test_publication_pre_authority_fault_consumes_no_assertion_or_upload(
    c1_service, accepted_c1, publication_assertion, fault,
) -> None:
    result = c1_service.prepare_with_authority_fault(accepted_c1, fault)
    assert result.code == "publication_not_authorized"
    assert c1_service.assertion_calls == 0
    assert c1_service.upload_calls == 0

@pytest.mark.parametrize("post_prepare_fault", [
    "revoke_c1", "replace_candidate_artifact_set", "replace_candidate_inventory",
    "replace_publication_manifest", "expire_action",
])
def test_publication_rechecks_every_authority_after_prepare(
    c1_service, accepted_c1, publication_assertion, post_prepare_fault,
) -> None:
    action = c1_service.prepare_publication(accepted_c1)
    c1_service.inject_after_prepare(post_prepare_fault)
    result = c1_service.publish(action, publication_assertion)
    assert result.code in {
        "publication_not_authorized", "publication_manifest_invalid", "publication_action_invalid",
    }
    assert c1_service.assertion_calls == 0
    assert c1_service.upload_calls == 0

def test_persisted_publication_action_reloads_authoritative_c1_after_restart(
    c1_service, accepted_c1, publication_assertion,
) -> None:
    action = c1_service.prepare_publication(accepted_c1)
    restarted = c1_service.restart()
    receipt = restarted.publish(action, publication_assertion)
    assert isinstance(receipt, PublicationReceiptV1)
    assert restarted.accepted_c1_reload_calls == 1

@pytest.mark.parametrize("fault", [
    "accepted_c1_missing", "accepted_c1_substituted", "accepted_c1_store_io",
])
def test_restart_with_lost_or_substituted_c1_denies_before_credential_or_upload(
    c1_service, accepted_c1, publication_assertion, fault,
) -> None:
    action = c1_service.prepare_publication(accepted_c1)
    restarted = c1_service.restart_with_accepted_c1_fault(fault)
    result = restarted.publish(action, publication_assertion)
    assert result.code == "publication_not_authorized"
    assert restarted.assertion_calls == 0
    assert restarted.upload_calls == 0

@pytest.mark.parametrize("post_claim_fault", [
    "action_reload_unavailable", "action_no_longer_claimed_exact",
    "revoke_c1", "missing_candidate", "replace_candidate_artifact_set",
    "replace_candidate_inventory", "replace_publication_manifest",
])
def test_publication_rechecks_after_claim_and_before_first_write(
    c1_service, accepted_c1, publication_assertion, post_claim_fault,
) -> None:
    action = c1_service.prepare_publication(accepted_c1)
    c1_service.inject_after_claim_before_first_write(post_claim_fault)
    result = c1_service.publish(action, publication_assertion)
    assert result.code == "publication_not_authorized"
    assert c1_service.assertion_calls == 1
    assert c1_service.claim_calls == 1
    assert c1_service.first_remote_write_calls == 0

@pytest.mark.parametrize("error", [
    PublicationActionDenied("lost action"), CurrentC1Unavailable("lost C1"),
    CurrentC1Revoked("revoked C1"), CandidateUnavailable("lost candidate"),
    ArtifactSetDrift("candidate drift"), OSError("authority store unavailable"),
])
def test_uploader_normalizes_only_expected_prewrite_authority_losses(
    publication_uploader, verified_publication, action, assertion, error,
) -> None:
    publication_uploader.fail_authority_reload_with(error)
    with pytest.raises(PublicationAuthorityLost):
        publication_uploader.upload(verified_publication,action,assertion)
    assert publication_uploader.first_remote_write_calls==0
    publication_uploader.fail_authority_reload_with(ValueError("programmer fault"))
    with pytest.raises(ValueError,match="programmer fault"):
        publication_uploader.upload(verified_publication,action,assertion)

def test_publication_does_not_hide_programmer_value_error(c1_service, accepted_c1) -> None:
    c1_service.signatures.raise_unexpected(ValueError("programmer fault"))
    with pytest.raises(ValueError, match="programmer fault"):
        c1_service.prepare_publication(accepted_c1)

@pytest.mark.parametrize("fault", [
    "invalid_utf8", "duplicate_key", "noncanonical_json", "nonfinite_number",
    "depth_33", "container_4097", "structure_token_16385", "oversize_manifest",
    "oversize_signature", "digest_mismatch", "signature_mismatch", "attacker_selected_signer_identity",
    "expired_manifest", "artifact_binding_mismatch", "missing_file", "permission_denied",
    "symlink", "non_regular", "wrong_owner", "mode_too_open", "nlink_not_one",
    "short_read", "growth_during_read", "replacement_during_read",
])
def test_publication_manifest_fault_never_reaches_upload(c1_service, accepted_c1, fault) -> None:
    result = c1_service.publish_with_manifest_fault(accepted_c1, fault)
    assert result.code == "publication_manifest_invalid"
    assert c1_service.upload_calls == 0

@pytest.mark.parametrize("fault", [
    "missing_file", "permission_denied", "symlink", "non_regular", "wrong_owner",
    "mode_too_open", "nlink_not_one", "short_read", "growth_during_read",
    "replacement_during_read", "oversize",
])
def test_publication_manifest_reader_translates_only_declared_file_faults(
    prepared_publication_store, fault,
) -> None:
    prepared_publication_store.inject_reader_fault(fault)
    with pytest.raises(PublicationManifestReadDenied):
        prepared_publication_store.read_manifest_regular_nofollow_bounded(
            uuid4(), max_bytes=1024 * 1024, max_buffer_bytes=1024 * 1024 + 1,
            expected_owner_uid=os.geteuid(), required_mode=0o600, require_nlink=1,
            expected_error=PublicationManifestReadDenied,
        )
    prepared_publication_store.inject_reader_fault(ValueError("programmer fault"))
    with pytest.raises(ValueError, match="programmer fault"):
        prepared_publication_store.read_manifest_regular_nofollow_bounded(
            uuid4(), max_bytes=1024 * 1024, max_buffer_bytes=1024 * 1024 + 1,
            expected_owner_uid=os.geteuid(), required_mode=0o600, require_nlink=1,
            expected_error=PublicationManifestReadDenied,
        )

@pytest.mark.parametrize("fault", [
    "partial_upload", "ambiguous_timeout", "redownload_byte_substitution",
    "missing_remote_artifact", "extra_remote_artifact", "renamed_remote_artifact",
])
def test_publication_receipt_requires_exact_independent_redownload(
    c1_service, accepted_c1, publication_assertion, fault,
) -> None:
    result = c1_service.publish_with_upload_fault(accepted_c1, publication_assertion, fault)
    assert result.code == "publication_upload_unverified"
    assert not isinstance(result, PublicationReceiptV1)
    assert c1_service.remote_overwrite_calls == 0
    assert c1_service.retry_scope == (accepted_c1.candidate_id, accepted_c1.publication_manifest_digest)

def test_household_and_maintainer_credential_cross_use_is_denied(boundary) -> None:
    assert boundary.c1_with_household_owner().code == "ASSURANCE_INSUFFICIENT"
    assert boundary.publish_with_household_owner().code == "ASSURANCE_INSUFFICIENT"
    assert boundary.c0_with_maintainer().code == "ASSURANCE_INSUFFICIENT"

def test_maintainer_terminal_has_no_household_dependency_or_data_import(graph) -> None:
    assert graph.imports_from("apps/release-maintainer") & {
        "apps/admin", "apps/core", "tuntun_contracts.identity", "tuntun_contracts.household",
    } == set()
    assert graph.maintainer_terminal_household_api_clients == ()

def test_release_public_packages_resolve_from_lock_and_have_closed_surface(installed_workspace) -> None:
    assert installed_workspace.version("tuntun-release-public-contracts") == "0.1.0.dev0"
    assert installed_workspace.version("tuntun-release-maintainer") == "0.1.0.dev0"
    assert installed_workspace.entry_point("tuntun-release-maintainer") == "tuntun_release_maintainer.main:app"
    assert installed_workspace.import_closure("tuntun_release_maintainer").isdisjoint(HOUSEHOLD_MODULES)
    assert installed_workspace.exports("tuntun_release_public_contracts") == EXPECTED_RELEASE_PUBLIC_EXPORTS
    assert {
        "C0CandidateV1", "C0AcceptedReceiptV1", "C0ReleaseHandoffV1",
        "C1CandidateV1", "C1AcceptedReceiptV1", "PublicationManifestV1",
        "PublicationActionBindingV1", "PublicationReceiptV1",
    } <= EXPECTED_RELEASE_PUBLIC_EXPORTS

@pytest.mark.parametrize("fixture_name", C1_PUBLIC_CONTRACT_POSITIVE_AND_BOUNDARY_FIXTURES)
def test_installed_c1_public_and_core_contracts_have_exact_shape_and_bytes(
    installed_contract_pair, fixture_name,
) -> None:
    core_type, public_type = installed_contract_pair.for_fixture(fixture_name)
    raw = canonical_hardening_bytes(load_fixture(fixture_name))
    assert contract_shape_digest(core_type) == contract_shape_digest(public_type)
    core_value = core_type.model_validate_json(raw)
    public_value = public_type.model_validate_json(raw)
    assert canonical_hardening_bytes(core_value) == raw
    assert canonical_public_bytes(public_value) == raw
    assert core_type.model_validate(public_value.model_dump(mode="python"))
    assert public_type.model_validate(core_value.model_dump(mode="python"))

async def test_one_preallocated_candidate_id_survives_build_approval_and_publication(
    c1_service, accepted_c0, public_evidence, maintainer, publication_assertion,
) -> None:
    prepared = c1_service.prepare_publication_manifest(accepted_c0, public_evidence)
    candidate = c1_service.build(accepted_c0, public_evidence, prepared)
    assert candidate.candidate_id == prepared.candidate_id
    manifest = c1_service.reload_publication_manifest(prepared)
    assert manifest.candidate_id == candidate.candidate_id
    assert manifest.issued_at < manifest.expires_at <= manifest.issued_at + timedelta(hours=24)
    assert candidate.publication_manifest_digest == prepared.manifest_digest
    assert candidate.artifact_set_digest == manifest.artifact_set_digest
    assert candidate.artifact_inventory_digest == manifest.artifact_inventory_digest
    approval = await c1_service.approve(candidate, maintainer.fresh_distinct_assertion())
    accepted = await c1_service.accept(candidate, approval)
    action = c1_service.prepare_publication(accepted)
    publication_assertion.sign_challenge(sha256(canonical_hardening_bytes(action)).digest())
    assert isinstance(c1_service.publish(action, publication_assertion), PublicationReceiptV1)

def test_prepared_manifest_candidate_id_substitution_raises_named_denial_before_credential_or_upload(
    c1_service, accepted_c0, public_evidence, prepared_publication_manifest,
) -> None:
    changed = replace(prepared_publication_manifest, candidate_id=uuid4())
    with pytest.raises(
        PreparedPublicationManifestDenied,
        match="prepared_publication_manifest_invalid",
    ):
        c1_service.build(accepted_c0, public_evidence, changed)
    assert c1_service.credential_consume_calls == 0
    assert c1_service.upload_calls == 0

@pytest.mark.parametrize("fault", [
    "intended_tag_not_v_version", "publication_manifest_tag_differs_from_intent",
    "tag_preexisting_before_manifest_prepare",
])
def test_pre_c1_tag_target_fault_creates_no_prepared_authority(
    c1_service, accepted_c0, public_evidence, fault,
) -> None:
    with pytest.raises(PreparedPublicationManifestDenied):
        c1_service.prepare_publication_manifest_with_tag_fault(
            accepted_c0, public_evidence, fault,
        )
    assert c1_service.complete_prepared_manifest_sets == 0
    assert c1_service.credential_consume_calls == 0
    assert c1_service.upload_calls == 0

@pytest.mark.parametrize("fault", [
    "tag_created_after_action_before_first_write",
    "tag_retargeted_before_independent_redownload",
])
def test_preexisting_or_retargeted_publication_tag_never_produces_receipt(
    c1_service, accepted_c1, publication_assertion, fault,
) -> None:
    action = c1_service.prepare_publication(accepted_c1)
    c1_service.inject_tag_race(fault)
    result = c1_service.publish(action, publication_assertion)
    assert result.code == "publication_upload_unverified"
    assert not isinstance(result, PublicationReceiptV1)
    assert c1_service.remote_overwrite_calls == 0

def test_tag_target_programmer_fault_is_not_normalized(
    c1_service, accepted_c1,
) -> None:
    c1_service.publication_target.raise_unexpected(ValueError("programmer fault"))
    with pytest.raises(ValueError, match="programmer fault"):
        c1_service.prepare_publication(accepted_c1)

def test_exact_tag_from_same_ambiguous_run_is_reconciled_without_overwrite(
    c1_service, accepted_c1, publication_assertion,
) -> None:
    first_action = c1_service.prepare_publication(accepted_c1)
    ambiguous = c1_service.publish_with_lost_response_after_exact_tag_create(
        first_action, publication_assertion,
    )
    assert ambiguous.code == "publication_upload_unverified"
    assert c1_service.exact_owned_incomplete_tag_count == 1
    fresh_action = c1_service.prepare_publication(accepted_c1)
    receipt = c1_service.publish(
        fresh_action, publication_assertion.fresh_for(fresh_action),
    )
    assert isinstance(receipt, PublicationReceiptV1)
    assert c1_service.remote_tag_create_calls == 1
    assert c1_service.remote_overwrite_calls == 0

def test_build_c1_cli_maps_only_named_prepared_manifest_denial(
    c1_cli, accepted_c0, public_evidence, prepared_publication_manifest,
) -> None:
    changed = replace(prepared_publication_manifest, candidate_id=uuid4())
    result = c1_cli.build(accepted_c0, public_evidence, changed)
    assert result.code == "publication_manifest_invalid"
    c1_cli.inject_build_fault(ValueError("programmer fault"))
    with pytest.raises(ValueError, match="programmer fault"):
        c1_cli.build(accepted_c0, public_evidence, prepared_publication_manifest)

async def test_one_prepared_publication_store_survives_restart_through_publication(
    c1_service, accepted_c0, public_evidence, maintainer, publication_assertion,
) -> None:
    prepared = c1_service.prepare_publication_manifest(accepted_c0, public_evidence)
    first_bytes = c1_service.reload_publication_manifest_bytes(prepared)
    restarted = c1_service.restart_and_reconcile_prepared_manifests()
    assert restarted.reload_publication_manifest_bytes(prepared) == first_bytes
    candidate = restarted.build(accepted_c0, public_evidence, prepared)
    approval = await restarted.approve(candidate, maintainer.fresh_distinct_assertion())
    accepted = await restarted.accept(candidate, approval)
    action = restarted.prepare_publication(accepted)
    publication_assertion.sign_challenge(sha256(canonical_hardening_bytes(action)).digest())
    assert isinstance(restarted.publish(action, publication_assertion), PublicationReceiptV1)
    assert restarted.prepared_publication_store_read_phases == (
        "reload", "build_c1", "prepare_publication", "publish",
    )
    assert restarted.distinct_publication_store_calls == 0

@pytest.mark.parametrize("boundary", [
    "manifest_fsync", "signature_fsync", "descriptor_fsync", "parent_fsync",
])
def test_prepared_manifest_crash_recovers_zero_or_one_complete_set(
    c1_service, accepted_c0, public_evidence, boundary,
) -> None:
    c1_service.crash_prepare_publication_manifest_at(boundary, accepted_c0, public_evidence)
    restarted = c1_service.restart_and_reconcile_prepared_manifests()
    assert restarted.complete_prepared_manifest_sets in {0, 1}
    assert restarted.unowned_manifest_or_signature_files == ()
    assert restarted.publication_authority_without_complete_descriptor == ()
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/release/test_release_public_package_smoke.py tests/contract/release/test_c1_packet.py tests/contract/release/test_c1_public_contract_parity.py tests/security/release/test_c1_separation_and_manual_publish.py tests/acceptance/release/test_c1_gate.py tests/acceptance/phase6/test_p6_5_gate.py tests/fault/release/test_c1_failure_returns_to_c0.py -q`
Expected: FAIL because C1 builder/approval/publication verifier are absent.

- [ ] **Step 3: Implement unchanged-candidate C1 and manual immutable publication**

`packages/release-public-contracts` is already installed and locked by Task 37. Extend only its explicit `__init__.py` export surface with the C1/publication symbols; do not recreate its project file, canonical parser, version, dependencies, or C0 DTOs. The same installed-wheel shape-digest, reciprocal-parse and byte-identical RFC 8785 parity gate now covers every shared C1/publication DTO and boundary fixture as well. Append only the new `apps/release-maintainer` root to the existing root `[tool.uv.workspace].members` list without replacing prior members, then update `uv.lock` and package the app independently:

~~~toml
# apps/release-maintainer/pyproject.toml
[project]
name = "tuntun-release-maintainer"
version = "0.1.0.dev0"
requires-python = "==3.12.*"
dependencies = ["tuntun-release-public-contracts", "typer>=0.16,<1"]

[project.scripts]
tuntun-release-maintainer = "tuntun_release_maintainer.main:app"

[tool.uv.sources]
tuntun-release-public-contracts = { workspace = true }

[build-system]
requires = ["hatchling>=1.27,<2"]
build-backend = "hatchling.build"
~~~

Both `__init__.py` files define version `0.1.0.dev0`; only the explicit public DTO/canonical symbols are exported. The terminal uses OS project-credential handles and its own owner-only stores. Static wheel inspection and an installed-artifact import graph reject `tuntun_contracts`, `tuntun_core`, all household apps, undeclared dynamic imports and path injection. Its `--help` path performs no credential/store/network read.

~~~python
from dataclasses import dataclass, replace
from typing import Protocol
from tuntun_release_public_contracts.canonical import ContractParseError, parse_contract_json

class C0HandoffImportDenied(Exception): ...
class C0HandoffSignatureVerificationFailed(C0HandoffImportDenied): ...
class C0ApprovalSignatureVerificationFailed(C0HandoffImportDenied): ...
class C0HandoffStoreDenied(C0HandoffImportDenied): ...
class PreparedPublicationManifestDenied(Exception): ...

@dataclass(frozen=True, slots=True)
class PreparedPublicationManifest:
    descriptor_id: UUID
    candidate_id: UUID
    c0_candidate_id: UUID
    accepted_c0_commitment: HmacCommitment
    handoff_id: UUID
    handoff_generation: int
    manifest_digest: Sha256Digest
    descriptor_commitment: HmacCommitment

class PreparedPublicationStore(Protocol):
    """One durable journal owning each manifest/signature/descriptor triplet."""

    def put_manifest_signature_and_descriptor_fsync_once(
        self, prepared: PreparedPublicationManifest, *, manifest_bytes: bytes,
        detached_signature: bytes, required_mode: int,
        expected_error: type[PreparedPublicationManifestDenied],
    ) -> None: ...

    def require_current_exact(
        self, prepared: PreparedPublicationManifest, *,
        expected_error: type[PreparedPublicationManifestDenied],
    ) -> PreparedPublicationManifest: ...

    def require_complete_descriptor_for_candidate(
        self, candidate_id: UUID, *, expected_manifest_digest: Sha256Digest,
        expected_error: "type[PublicationManifestReadDenied]",
    ) -> PreparedPublicationManifest: ...

    def read_manifest_regular_nofollow_bounded(
        self, candidate_id: UUID, **requirements: object,
    ) -> bytes: ...

    def read_signature_regular_nofollow_bounded(
        self, candidate_id: UUID, **requirements: object,
    ) -> bytes: ...

def import_c0_handoff(
    path: Path,
    store: ImmutableOneUseC0HandoffStore,
    signatures: PinnedC0HandoffPublicVerifier,
    now: datetime,
) -> ImportedC0Handoff:
    raw = read_regular_nofollow_bounded(
        path,
        max_bytes=2 * 1024 * 1024,
        max_buffer_bytes=2 * 1024 * 1024 + 1,
        expected_owner_uid=os.geteuid(),
        required_mode=0o600,
        require_nlink=1,
        expected_error=C0HandoffImportDenied,
    )
    try:
        handoff = parse_contract_json(
            C0ReleaseHandoffV1, raw, max_bytes=2 * 1024 * 1024, require_canonical=True,
        )
    except ContractParseError as error:
        raise C0HandoffImportDenied("c0_handoff_contract_invalid") from error
    if canonical_hardening_bytes(handoff) != raw:
        raise C0HandoffImportDenied("c0_handoff_encoder_drift")
    unsigned = handoff.model_dump(mode="python", exclude={"handoff_signature"})
    try:
        signatures.require_current_allowlisted_signature(
            signature=handoff.handoff_signature,
            domain="tuntun.c0.release-handoff.v1",
            payload=canonical_hardening_bytes(unsigned),
            signer_identity=handoff.handoff_signer_identity,
            key_generation=handoff.handoff_key_generation,
        )
        signatures.require_valid_c0_approval_and_accepted_receipt(
            candidate=handoff.candidate,
            accepted=handoff.accepted_c0,
            expected_current_status=handoff.credential_status,
        )
    except (
        C0HandoffSignatureVerificationFailed,
        C0ApprovalSignatureVerificationFailed,
    ) as error:
        raise C0HandoffImportDenied("c0_handoff_signature_invalid") from error
    if handoff.issued_at > now or now >= handoff.valid_until:
        raise C0HandoffImportDenied("c0_handoff_time_invalid")
    try:
        return store.put_new_exact_canonical_fsync_once(handoff, raw)
    except (C0HandoffStoreDenied, OSError) as error:
        raise C0HandoffImportDenied("c0_handoff_store_unavailable") from error

def prepare_publication_manifest(
    c0: C0AcceptedReceiptV1,
    evidence: PublicReleaseEvidenceWithoutPublicationManifest,
) -> PreparedPublicationManifest:
    current = accepted_c0_store.require_current_exact(c0.candidate_id, c0.accepted_commitment)
    current.require_fresh_verified_handoff_and_unchanged_candidate_artifacts()
    c0_candidate = current.candidate
    require(evidence.exactly_matches(c0_candidate))
    intended_tag = evidence.intended_immutable_tag
    if (
        intended_tag != f"v{c0_candidate.version}"
        or not evidence.immutable_tag_target_available
    ):
        raise PreparedPublicationManifestDenied("prepared_publication_manifest_invalid")
    try:
        publication_target.require_tag_absent_and_create_only_policy(
            repository_identity=evidence.source_repository_identity,
            immutable_tag=intended_tag,
            expected_source_commit=c0_candidate.source_commit,
            expected_error=PublicationTagTargetUnavailable,
        )
    except PublicationTagTargetUnavailable as error:
        raise PreparedPublicationManifestDenied(
            "prepared_publication_manifest_invalid",
        ) from error
    candidate_id = uuid4()
    now = publication_clock.now()
    manifest = PublicationManifestV1(
        candidate_id=candidate_id,
        version=c0_candidate.version,
        immutable_tag=intended_tag,
        source_commit=c0_candidate.source_commit,
        source_repository_identity=evidence.source_repository_identity,
        release_manifest_digest=evidence.release_manifest_digest,
        artifact_set_digest=c0_candidate.artifact_set_digest,
        artifact_inventory_digest=c0_candidate.artifact_inventory_digest,
        artifact_digests=evidence.artifact_digests,
        signer_identity=project_release_signatures.current_allowlisted_identity,
        issued_at=now,
        expires_at=now + timedelta(hours=24),
    )
    raw = canonical_hardening_bytes(manifest)
    signature = project_release_signatures.sign_detached(
        domain="tuntun.publication-manifest.v1", payload=raw,
    )
    descriptor_fields = {
        "descriptor_id": uuid4(),
        "candidate_id": candidate_id,
        "c0_candidate_id": c0_candidate.candidate_id,
        "accepted_c0_commitment": current.receipt.accepted_commitment,
        "handoff_id": current.handoff_id,
        "handoff_generation": current.handoff_generation,
        "manifest_digest": sha256(raw).hexdigest(),
    }
    prepared = PreparedPublicationManifest(
        **descriptor_fields,
        descriptor_commitment=maintainer_commitments.hmac_canonical_mapping(
            domain="tuntun.prepared-publication-manifest.v1", value=descriptor_fields,
        ),
    )
    prepared_publication_store.put_manifest_signature_and_descriptor_fsync_once(
        prepared,
        manifest_bytes=raw,
        detached_signature=signature,
        required_mode=0o600,
        expected_error=PreparedPublicationManifestDenied,
    )
    return prepared

def build_c1(
    c0: C0AcceptedReceiptV1,
    evidence: PublicReleaseEvidenceWithoutPublicationManifest,
    prepared: PreparedPublicationManifest,
) -> C1CandidateV1:
    current = accepted_c0_store.require_current_exact(c0.candidate_id, c0.accepted_commitment)
    current.require_fresh_verified_handoff_and_unchanged_candidate_artifacts()
    prepared = prepared_publication_store.require_current_exact(
        prepared, expected_error=PreparedPublicationManifestDenied,
    )
    if (
        prepared.c0_candidate_id != current.candidate.candidate_id
        or prepared.accepted_c0_commitment != current.receipt.accepted_commitment
        or prepared.handoff_id != current.handoff_id
        or prepared.handoff_generation != current.handoff_generation
    ):
        raise PreparedPublicationManifestDenied("prepared_publication_manifest_invalid")
    c0_candidate = current.candidate
    c0_receipt = current.receipt
    try:
        publication_manifest = load_immutable_publication_manifest(
            prepared_publication_store,
            project_release_signatures,
            prepared.candidate_id,
            prepared.manifest_digest,
            publication_clock.now(),
        )
    except (ContractParseError, PublicationManifestDenied) as error:
        raise PreparedPublicationManifestDenied(
            "prepared_publication_manifest_invalid",
        ) from error
    require(evidence.source_commit == c0_candidate.source_commit)
    require(evidence.feature_manifest_digest == c0_candidate.feature_manifest_digest)
    require(evidence.final_post_staple_artifact_set_digest == c0_candidate.artifact_set_digest)
    require(evidence.final_post_staple_artifact_inventory_digest == c0_candidate.artifact_inventory_digest)
    require(digest_named_artifact_inventory(evidence.artifact_digests) == c0_candidate.artifact_inventory_digest)
    if (
        publication_manifest.candidate_id != prepared.candidate_id
        or publication_manifest.version != c0_candidate.version
        or publication_manifest.source_commit != c0_candidate.source_commit
        or publication_manifest.source_repository_identity != evidence.source_repository_identity
        or publication_manifest.release_manifest_digest != evidence.release_manifest_digest
        or publication_manifest.artifact_set_digest != c0_candidate.artifact_set_digest
        or publication_manifest.artifact_inventory_digest != c0_candidate.artifact_inventory_digest
        or publication_manifest.artifact_digests != evidence.artifact_digests
    ):
        raise PreparedPublicationManifestDenied("prepared_publication_manifest_invalid")
    require(evidence.reproducible_clean_build and evidence.dependency_and_licence_policy)
    require(evidence.spdx_sbom and evidence.provenance_attestation)
    require(evidence.checksums_signatures and evidence.developer_id_hardened_runtime)
    require(evidence.notarization_stapling_gatekeeper)
    require(evidence.intel_lifecycle and evidence.apple_silicon_lifecycle)
    require(evidence.enabled_linux_service_target_receipts_exact_and_passed)
    require(evidence.synthetic_simulator_docs_support_matrix)
    require(evidence.source_history_artifact_private_findings == 0)
    if (
        evidence.intended_immutable_tag != f"v{c0_candidate.version}"
        or not evidence.immutable_tag_target_available
        or publication_manifest.immutable_tag != evidence.intended_immutable_tag
    ):
        raise PreparedPublicationManifestDenied("prepared_publication_manifest_invalid")
    fields = {
        "schema_id": "c1_candidate.v1",
        "candidate_id": prepared.candidate_id, "c0_candidate_id": c0_candidate.candidate_id,
        "accepted_c0_commitment": c0_receipt.accepted_commitment,
        "version": c0_candidate.version, "source_commit": c0_candidate.source_commit,
        "source_repository_identity": evidence.source_repository_identity,
        "feature_manifest_digest": c0_candidate.feature_manifest_digest,
        "public_release_evidence_digest": evidence.digest(),
        "publication_manifest_digest": prepared.manifest_digest,
        "release_manifest_digest": publication_manifest.release_manifest_digest,
        "artifact_set_digest": evidence.final_post_staple_artifact_set_digest,
        "artifact_inventory_digest": evidence.final_post_staple_artifact_inventory_digest,
        "artifact_digests": evidence.artifact_digests,
        "built_at": evidence.observed_at,
    }
    candidate = C1CandidateV1(
        **fields,
        candidate_commitment=candidate_commitments.hmac_canonical_mapping(
            domain="tuntun.c1-candidate.v1", value=fields,
        ),
    )
    require_valid_c1_candidate_commitment(candidate)
    accepted_c0_store.require_same_generation_and_exact(current)
    c1_candidates.put_new_immutable(candidate)
    return candidate

def require_valid_c1_candidate_commitment(candidate: C1CandidateV1) -> None:
    fields = candidate.model_dump(mode="python", exclude={"candidate_commitment"})
    expected = candidate_commitments.hmac_canonical_mapping(
        domain="tuntun.c1-candidate.v1", value=fields,
    )
    if not hmac.compare_digest(expected, candidate.candidate_commitment):
        raise C1Denied("candidate_commitment_invalid")

async def approve_c1(candidate, fresh_local_passkey) -> C1ApprovalReceiptV1:
    candidate = c1_candidates.require_current_exact(
        candidate.candidate_id, candidate.candidate_commitment,
    )
    require_valid_c1_candidate_commitment(candidate)
    current_c0 = accepted_c0_store.require_current_exact(
        candidate.c0_candidate_id, candidate.accepted_c0_commitment,
    )
    current_c0.require_fresh_verified_handoff_and_unchanged_candidate_artifacts()
    assertion = await require_fresh_project_maintainer_passkey_at_local_release_terminal(
        fresh_local_passkey, purpose="c1_public_beta",
        distinct_from=current_c0.receipt.accepted_assertion_id,
    )
    return C1ApprovalReceiptV1.model_validate(sign_exact_c1(candidate, assertion))

async def reject_c1(candidate, fresh_local_passkey, reasons) -> C1RejectionReceiptV1:
    candidate = c1_candidates.require_current_exact(
        candidate.candidate_id, candidate.candidate_commitment,
    )
    require_valid_c1_candidate_commitment(candidate)
    current_c0 = accepted_c0_store.require_current_exact(
        candidate.c0_candidate_id, candidate.accepted_c0_commitment,
    )
    current_c0.require_fresh_verified_handoff_and_unchanged_candidate_artifacts()
    assertion = await require_fresh_project_maintainer_passkey_at_local_release_terminal(
        fresh_local_passkey, purpose="c1_public_beta_reject",
        distinct_from=current_c0.receipt.accepted_assertion_id,
    )
    return sign_exact_c1_rejection(candidate, assertion, reasons)

async def accept_c1(candidate, approval: C1ApprovalReceiptV1) -> C1AcceptedReceiptV1:
    candidate = c1_candidates.require_current_exact(
        candidate.candidate_id, candidate.candidate_commitment,
    )
    require_valid_c1_candidate_commitment(candidate)
    accepted_c0_store.require_current_exact(
        candidate.c0_candidate_id, candidate.accepted_c0_commitment,
    ).require_fresh_verified_handoff_and_unchanged_candidate_artifacts()
    require(approval.artifact_set_digest == candidate.artifact_set_digest)
    require(approval.artifact_inventory_digest == candidate.artifact_inventory_digest)
    require_current_unrevoked_exact_assertion(candidate, approval)
    return await freeze_exact_c1(candidate, approval)

@dataclass(frozen=True, slots=True)
class PublicationDeniedResult:
    code: Literal[
        "publication_not_authorized", "publication_manifest_invalid",
        "publication_action_invalid", "publication_upload_unverified",
    ] = "publication_manifest_invalid"

def build_c1_at_cli_boundary(
    c0: C0AcceptedReceiptV1,
    evidence: PublicReleaseEvidenceWithoutPublicationManifest,
    prepared: PreparedPublicationManifest,
) -> C1CandidateV1 | PublicationDeniedResult:
    try:
        return build_c1(c0, evidence, prepared)
    except PreparedPublicationManifestDenied:
        # This is the only build failure normalized by the CLI. Cancellation and
        # programmer/contract errors remain visible and fail the command loudly.
        return PublicationDeniedResult(code="publication_manifest_invalid")

class PublicationExpectedBoundaryError(Exception):
    """Base for normalized environmental/adversarial publication failures."""

class PublicationAuthorizationDenied(PublicationExpectedBoundaryError): ...
class CurrentC1Unavailable(PublicationAuthorizationDenied): ...
class CurrentC1Revoked(PublicationAuthorizationDenied): ...
class CandidateUnavailable(PublicationAuthorizationDenied): ...
class ArtifactSetDrift(PublicationAuthorizationDenied): ...
class PublicationManifestDenied(PublicationExpectedBoundaryError): ...
class PublicationManifestReadDenied(PublicationManifestDenied): ...
class ProjectSignatureVerificationFailed(PublicationManifestDenied): ...
class PublicationTagTargetUnavailable(PublicationManifestDenied): ...
class PublicationActionDenied(PublicationExpectedBoundaryError): ...
class PublicationAuthorityLost(PublicationExpectedBoundaryError): ...
class PublicationUploadUnverified(PublicationExpectedBoundaryError): ...
class PublicationTagRaceAfterAction(PublicationUploadUnverified): ...

@dataclass(frozen=True, slots=True)
class PublicationEffectRun:
    run_id: UUID
    publication_action_id: UUID
    publication_action_commitment: HmacCommitment
    candidate_id: UUID
    accepted_c1_commitment: HmacCommitment
    publication_manifest_digest: Sha256Digest
    assertion_id: UUID
    authority_claimed_at: AwareDatetime
    operation_deadline: AwareDatetime
    state: Literal["claimed", "uploading", "verifying", "completed", "error_safe"]
    run_commitment: HmacCommitment

@dataclass(frozen=True, slots=True)
class VerifiedPublicationCandidate:
    manifest: PublicationManifestV1
    publication_manifest_digest: Sha256Digest
    accepted_c1: C1AcceptedReceiptV1
    candidate: C1CandidateV1

def load_immutable_publication_manifest(
    store: PreparedPublicationStore,
    signatures: ProjectReleaseSignatureVerifier,
    candidate_id: UUID,
    expected_digest: Sha256Digest,
    now: datetime,
) -> PublicationManifestV1:
    store.require_complete_descriptor_for_candidate(
        candidate_id,
        expected_manifest_digest=expected_digest,
        expected_error=PublicationManifestReadDenied,
    )
    raw_manifest = store.read_manifest_regular_nofollow_bounded(
        candidate_id, max_bytes=1024 * 1024, max_buffer_bytes=1024 * 1024 + 1,
        expected_owner_uid=os.geteuid(), required_mode=0o600, require_nlink=1,
        expected_error=PublicationManifestReadDenied,
    )
    detached_signature = store.read_signature_regular_nofollow_bounded(
        candidate_id, max_bytes=16 * 1024, max_buffer_bytes=16 * 1024 + 1,
        expected_owner_uid=os.geteuid(), required_mode=0o600, require_nlink=1,
        expected_error=PublicationManifestReadDenied,
    )
    if not hmac.compare_digest(sha256(raw_manifest).hexdigest(), expected_digest):
        raise PublicationManifestDenied("publication_manifest_digest_mismatch")
    try:
        verified_signer_identity = signatures.verify_current_project_manifest_from_allowlist(
            signature=detached_signature,
            domain="tuntun.publication-manifest.v1",
            payload=raw_manifest,
        )
    except ProjectSignatureVerificationFailed as error:
        raise PublicationManifestDenied("publication_manifest_signature_invalid") from error
    manifest = parse_contract_json(
        PublicationManifestV1,
        raw_manifest,
        max_bytes=1024 * 1024,
        require_canonical=True,
    )
    if manifest.signer_identity != verified_signer_identity:
        raise PublicationManifestDenied("publication_manifest_signer_identity_mismatch")
    if manifest.issued_at > now or now >= manifest.expires_at:
        raise PublicationManifestDenied("publication_manifest_time_invalid")
    if canonical_hardening_bytes(manifest) != raw_manifest:
        raise PublicationManifestDenied("publication_manifest_encoder_drift")
    return manifest

def require_publication_manifest_exact_bindings(
    manifest: PublicationManifestV1,
    accepted: C1AcceptedReceiptV1,
    candidate: C1CandidateV1,
) -> None:
    if (
        manifest.candidate_id != accepted.candidate_id
        or candidate.candidate_id != accepted.candidate_id
        or manifest.version != candidate.version
        or manifest.source_commit != candidate.source_commit
        or manifest.source_repository_identity != candidate.source_repository_identity
        or manifest.release_manifest_digest != accepted.release_manifest_digest
        or manifest.release_manifest_digest != candidate.release_manifest_digest
        or manifest.artifact_set_digest != accepted.artifact_set_digest
        or manifest.artifact_set_digest != candidate.artifact_set_digest
        or manifest.artifact_inventory_digest != accepted.artifact_inventory_digest
        or manifest.artifact_inventory_digest != candidate.artifact_inventory_digest
        or manifest.artifact_digests != candidate.artifact_digests
    ):
        raise PublicationManifestDenied("publication_manifest_binding_mismatch")

def prepare_publication(
    c1: C1AcceptedReceiptV1,
) -> PublicationActionBindingV1 | PublicationDeniedResult:
    try:
        candidate = require_current_accepted_c1_and_exact_artifacts(c1)
    except (CurrentC1Unavailable, CurrentC1Revoked, CandidateUnavailable, ArtifactSetDrift, OSError):
        return PublicationDeniedResult(code="publication_not_authorized")
    try:
        manifest = load_immutable_publication_manifest(
            prepared_publication_store,
            project_release_signatures,
            c1.candidate_id,
            c1.publication_manifest_digest,
            publication_clock.now(),
        )
        require_publication_manifest_exact_bindings(manifest, c1, candidate)
        publication_target.require_tag_absent_or_exact_owned_incomplete(
            repository_identity=manifest.source_repository_identity,
            immutable_tag=manifest.immutable_tag,
            expected_source_commit=manifest.source_commit,
            accepted_c1_commitment=c1.accepted_commitment,
            expected_error=PublicationTagTargetUnavailable,
        )
    except (ContractParseError, PublicationManifestDenied):
        return PublicationDeniedResult(code="publication_manifest_invalid")

    now = publication_clock.now()
    fields = {
        "schema_id": "publication_action_binding.v1",
        "publication_action_id": uuid4(),
        "candidate_id": candidate.candidate_id,
        "accepted_c1_commitment": c1.accepted_commitment,
        "publication_manifest_digest": c1.publication_manifest_digest,
        "release_manifest_digest": c1.release_manifest_digest,
        "artifact_set_digest": c1.artifact_set_digest,
        "artifact_inventory_digest": c1.artifact_inventory_digest,
        "immutable_tag": manifest.immutable_tag,
        "credential_namespace": "project_maintainer_publication",
        "signature_domain": "tuntun.publication.project-maintainer.v1",
        "purpose": "publish_exact_immutable_public_beta",
        "issued_at": now,
        "expires_at": now + timedelta(minutes=2),
    }
    action = PublicationActionBindingV1(
        **fields,
        action_commitment=publication_commitments.hmac_canonical_fields(
            domain="tuntun.publication-action.v1", fields=fields,
        ),
    )
    try:
        publication_actions.put_new_pending_exact(action)
    except (PublicationActionDenied, OSError):
        return PublicationDeniedResult(code="publication_action_invalid")
    return action

def publish(
    action: PublicationActionBindingV1,
    fresh_publication_assertion,
) -> PublicationReceiptV1 | PublicationDeniedResult:
    try:
        pending_action = publication_actions.require_current_pending_exact(action)
    except (PublicationActionDenied, OSError):
        return PublicationDeniedResult(code="publication_action_invalid")
    try:
        accepted_c1 = accepted_c1_store.require_current_exact(
            pending_action.candidate_id,
            pending_action.accepted_c1_commitment,
        )
        candidate = require_current_accepted_c1_and_exact_artifacts(accepted_c1)
    except (CurrentC1Unavailable, CurrentC1Revoked, CandidateUnavailable, ArtifactSetDrift, OSError):
        return PublicationDeniedResult(code="publication_not_authorized")
    try:
        manifest = load_immutable_publication_manifest(
            prepared_publication_store, project_release_signatures, action.candidate_id,
            action.publication_manifest_digest, publication_clock.now(),
        )
        require_publication_manifest_exact_bindings(manifest, accepted_c1, candidate)
        publication_target.require_tag_absent_or_exact_owned_incomplete(
            repository_identity=manifest.source_repository_identity,
            immutable_tag=manifest.immutable_tag,
            expected_source_commit=manifest.source_commit,
            accepted_c1_commitment=accepted_c1.accepted_commitment,
            expected_error=PublicationTagRaceAfterAction,
        )
    except (ContractParseError, PublicationManifestDenied):
        return PublicationDeniedResult(code="publication_manifest_invalid")
    except PublicationTagRaceAfterAction:
        return PublicationDeniedResult(code="publication_upload_unverified")
    try:
        require_action_recomputes_exactly_from_current_candidate(
            action, accepted_c1, candidate, manifest,
        )
    except PublicationActionDenied:
        return PublicationDeniedResult(code="publication_action_invalid")

    verified = VerifiedPublicationCandidate(
        manifest=manifest,
        publication_manifest_digest=action.publication_manifest_digest,
        accepted_c1=accepted_c1,
        candidate=candidate,
    )
    try:
        assertion = require_fresh_project_maintainer_publication_assertion(
            fresh_publication_assertion,
            expected_challenge=sha256(canonical_hardening_bytes(action)).digest(),
            purpose=action.purpose,
            credential_namespace=action.credential_namespace,
            signature_domain=action.signature_domain,
            distinct_from=accepted_c1.accepted_assertion_id,
        )
    except PublicationActionDenied:
        return PublicationDeniedResult(code="publication_action_invalid")
    try:
        run = publication_actions.claim_once_and_begin_effect_run_fsynced(
            action,
            assertion.assertion_id,
            trusted_clock=publication_clock,
            max_operation_duration=timedelta(minutes=30),
        )
    except (PublicationActionDenied, OSError):
        return PublicationDeniedResult(code="publication_action_invalid")
    try:
        # The uploader independently reloads the action, authoritative accepted
        # C1 and current candidate, then checks this same assertion/challenge
        # immediately before its first write and on every reconciliation attempt.
        return upload_new_immutable_version_only(
            verified,
            run,
            action,
            assertion,
            tag_create_mode="create_only_expected_absent",
            expected_immutable_tag=manifest.immutable_tag,
            expected_tag_target=candidate.source_commit,
            require_independent_redownload_and_rehash=True,
            require_independent_tag_target_and_no_overwrite_verification=True,
        )
    except PublicationAuthorityLost:
        return PublicationDeniedResult(code="publication_not_authorized")
    except PublicationUploadUnverified:
        return PublicationDeniedResult(code="publication_upload_unverified")
~~~

The C1 builder, approver, rejector and acceptor reload the immutable C1 candidate and the maintainer terminal's verified one-use C0 handoff store by the candidate's `c0_candidate_id` plus `accepted_c0_commitment`; caller-supplied nested C0 state is structurally absent. Import reads one owner-only `0600`, nofollow regular `nlink=1` file with a 2 MiB max-plus-one bound and pre/post device/inode/size/owner/mode/link checks, applies the shared duplicate-safe canonical parser, requires byte-for-byte canonical re-encoding, and verifies the embedded handoff signature with a previously pinned public key/signer identity/generation—not a key selected by the file. It independently verifies the C0 approval/accepted-receipt public signatures, exact canonical candidate digest and bytes, candidate/receipt/outer commitments, release-manifest and named-artifact inventory, current credential status and 15-minute window before one fsync/rename/fsync-parent import CAS. The immutable store journals `(handoff_id, handoff_generation, canonical_digest, state)` and reconciles an interrupted import to zero or one exact record; duplicate IDs with different bytes quarantine, while exact retry returns the same record. Acceptance consumes the handoff generation exactly once with another fsync/CAS, so restart/replay cannot reuse it. The maintainer cannot recompute the household Core HMAC and does not need that key: the already verified C0 approval and handoff signatures bind the candidate commitment and exact canonical candidate bytes, while C0 verified the HMAC before export. Missing, unreadable, malformed, expired, consumed, revoked-status, self-signed, substituted or artifact-drifted handoff fails before any project credential is consumed. File/parser/signature/store adapters translate only their documented hostile and `OSError` failures to `C0HandoffImportDenied`; cancellation and programmer faults remain visible. Only after the seven-day soak and accepted C0, the maintainer allocates one C1 candidate UUID and commits the at-most-24-hour manifest, detached signature and private prepared descriptor through one fsync/rename/fsync-parent journal. The descriptor binds its own ID/commitment, candidate UUID, C0 candidate/accepted commitment and handoff ID/generation; the CLI file is only an owner-only `0600`, nofollow, bounded selector for the exact immutable store record. Startup removes or quarantines any interrupted unowned manifest/signature and exposes either zero or one complete prepared set. `build_c1` reloads the committed descriptor and exact signed manifest and uses its UUID rather than generating another one; every later C1, action, publication and receipt binding reuses it. Expiry or any descriptor/candidate-ID substitution requires a newly prepared manifest and a new C1 candidate, before any approval assertion. The domain-separated C1 commitment is computed only after that preallocated UUID and complete unsigned field map exists and is rederived from every non-commitment model field at build, approve, reject, accept, restart and publication.

`PreparedPublicationStore` is that journal's sole interface and namespace: preparation writes the descriptor/manifest/signature triplet there, and build, action preparation, publish, uploader pre-write revalidation and restart all reload that same committed triplet. No `publication_store` alias, copied manifest authority or independently mutable descriptor view exists. Store integrity and expected descriptor/manifest/signature/binding failures at `build_c1` become only `PreparedPublicationManifestDenied`; the strict builder still returns only `C1CandidateV1`. Only the outer CLI boundary maps that named exception to `publication_manifest_invalid`. It does not catch cancellation, `TypeError`, `ValueError`, `AssertionError`, allocation failure or other programmer/contract errors.

Pre-C1 evidence says only that the intended exact `v{version}` tag is absent at the named repository and that the target enforces create-only/no-overwrite publication; it never claims that an immutable public tag already exists. Manifest preparation performs a fresh absence/policy check, binds that intended tag, and `build_c1` compares the evidence intent to the signed manifest. Action preparation and execution accept only absence or an exact tag already owned by the same accepted-C1 immutable incomplete publication journal. The uploader must atomically create rather than replace an absent tag, then independently re-read both the artifacts and tag target. An unowned pre-existing tag, create race, mismatched prior run or retargeted tag produces no `PublicationReceiptV1`; a lost response after this exact run created the exact tag is reconciled by identity without a second create or any overwrite. Only the receipt records `immutable_tag`, exact source target, create-without-overwrite, and successful target verification for P6-5.

The publication service is a two-call ceremony: `prepare_publication` authenticates current C1/artifacts and returns a two-minute immutable action whose canonical bytes become the WebAuthn challenge; `publish` accepts only that exact pending action and a fresh project-maintainer assertion over it. The action store persists only `PublicationActionBindingV1`; it never embeds or snapshots an accepted-C1 object. On every publish or restart, the service reloads authoritative accepted C1 by the action's exact `(candidate_id, accepted_c1_commitment)`, then reloads the candidate, manifest and artifacts and matches every action field before assertion consumption. Lost, revoked or substituted accepted C1 returns `publication_not_authorized` with no credential or upload call. The uploader repeats those reloads immediately before its first write and on every reconciliation attempt. Its pre-write adapter catches only the expected action/current-authority taxonomy (`PublicationActionDenied`, action-store `OSError`, `CurrentC1Unavailable`, `CurrentC1Revoked`, `CandidateUnavailable`, and `ArtifactSetDrift`) and normalizes it to `PublicationAuthorityLost`; no remote write has occurred at that point. The outer service maps that typed result to `publication_not_authorized`. Contract/programmer errors such as `TypeError`, `ValueError`, and `AssertionError` are never normalized. Cross-candidate assertions, one-field substitutions, replays and actions expired before claim consume no upload authority. Expected current-authority failures return `publication_not_authorized`; immutable-store/parse/digest/signature/binding failures return `publication_manifest_invalid`; an unowned tag appearing after action preparation returns `publication_upload_unverified`; unexpected programmer exceptions remain visible. Manifest and detached signature are separate owner-only nofollow regular `nlink=1` files with independent max-plus-one limits of 1 MiB and 16 KiB. Their shared descriptor reader verifies every ancestor and leaf without following links, requires the expected owner and exact `0600` mode, snapshots device/inode/size/mode/owner/link count before reading, performs one offset-independent bounded read, then rejects short read, growth or replacement on the final identity check. Only its documented open/stat/read/close `OSError` and file-integrity failures become `PublicationManifestReadDenied`; allocation, cancellation and programmer faults remain visible. The uploader accepts only `VerifiedPublicationCandidate`, the exact durable effect run, action and assertion, uploads with the immutable version/idempotency key, independently re-downloads every named artifact and both manifests, rehashes the complete ordered inventory, and creates `PublicationReceiptV1` only after those bytes exactly reproduce the action, accepted C1, publication-manifest and release-manifest digests. A partial/ambiguous/mismatched upload returns `publication_upload_unverified`, preserves the immutable reconciliation record and never claims a receipt; reconciliation requires a new action/fresh assertion after the bounded run deadline but can only target the same immutable bytes, never overwrite them. Verification checks tag/source/workflow/provenance/SBOM/licences/feature/evidence/signatures/notarization/compatibility and reruns simulator. A one-byte substitution, same-source rebuild, missing/extra/renamed artifact, or manifest/inventory divergence invalidates C0 and cannot publish. Publication remains a third fresh project-maintainer terminal action after C1. `apps/release-maintainer` imports only release-public contracts and operating-system credential APIs; it has no household packages, database, cookies, keys, evidence bodies, backup reader, diagnostics reader, support-bundle reader, or household API client. The household System UI may project only signed read-only C1 state and cannot approve, reject, accept, or publish. Record release advisory/rollback/support boundaries and enforce that project-maintainer accounts are structurally absent from household authentication and recovery stores.

The fresh assertion must be verified and atomically claimed before the two-minute action expires. Under the action-store writer, the claim reloads the exact pending action/assertion, samples the trusted clock, rejects `now >= expires_at`, and fsyncs one fixed-domain-HMAC `PublicationEffectRun` binding the exact action/candidate/C1/manifest/assertion and a server-chosen deadline no more than 30 minutes later. Every run transition revalidates and recomputes that commitment by state/sequence CAS. No remote write occurs before this durable claim. Assertion expiry after claim does not cancel or broaden that exact-byte run; restart may resume only the same run while `now < operation_deadline`. The authority window is half-open: every remote write and the terminal receipt CAS rejects at or after the deadline, so `authority_claimed_at <= published_at < operation_deadline <= authority_claimed_at + 30 minutes`. At or after the deadline, all writes stop and a new action/assertion may only reconcile the same immutable candidate. `PublicationReceiptV1` records the in-window `authority_claimed_at`, the bounded `operation_deadline` and the later verified `published_at`; it no longer pretends the complete upload/redownload must fit inside the assertion window.

- [ ] **Step 4: Run green, synthetic C1/manual-publish denials, and final independent verification**

Run: `uv lock && uv sync --all-packages && uv run pytest tests/unit/release/test_release_public_package_smoke.py tests/contract/release/test_c1_packet.py tests/contract/release/test_c1_public_contract_parity.py tests/security/release/test_c1_separation_and_manual_publish.py tests/security/release/test_maintainer_terminal_boundary.py tests/acceptance/release/test_c1_gate.py tests/acceptance/phase6/test_p6_5_gate.py tests/fault/release/test_c1_failure_returns_to_c0.py -q && uv build packages/release-public-contracts && uv build apps/release-maintainer && uv run tuntun-release-maintainer --help && uv run python scripts/phase6/build_c1.py --synthetic fixtures/synthetic/phase6/releases/c1-input.json --output var/evidence/phase6/c1-synthetic-unsigned.json && uv run python scripts/phase6/approve_c1.py --synthetic-reject-reused-c0-approval-and-cross-namespace var/evidence/phase6/c1-synthetic-unsigned.json && uv run tuntun-release-maintainer publish dry-run --assert-third-fresh-action --assert-requires-c1-and-manual-confirmation && uv run python scripts/phase6/verify_release.py --synthetic var/evidence/phase6/c1-synthetic-unsigned.json && uv run python scripts/scan_private_data.py --include-git-history --paths . var/evidence/phase6/c1-synthetic-unsigned.json && uv run ruff check scripts/phase6 ops/release/publish.py packages/release-public-contracts apps/release-maintainer tests/unit/release tests/contract/release tests/security/release tests/acceptance/release tests/acceptance/phase6 tests/fault/release && uv run mypy packages/release-public-contracts/src apps/release-maintainer/src`
Expected: PASS; synthetic approval cannot reuse C0 assertion, dry-run cannot publish, failed checks return to C0, and independent verification/private scan pass. Production publication still requires the explicit `TUNTUN_ALLOW_PUBLICATION=1` manual command with accepted C1.

- [ ] **Step 5: Commit isolated C1/manual-publication tooling before final candidate creation**

~~~bash
git add pyproject.toml uv.lock packages/release-public-contracts apps/release-maintainer scripts/phase6/build_c1.py scripts/phase6/approve_c1.py scripts/phase6/verify_release.py ops/release/publish.py docs/evidence/c1-evidence-schema.json tests/unit/release/test_release_public_package_smoke.py tests/contract/release/test_c1_packet.py tests/contract/release/test_c1_public_contract_parity.py tests/security/release/test_c1_separation_and_manual_publish.py tests/security/release/test_maintainer_terminal_boundary.py tests/acceptance/release/test_c1_gate.py tests/acceptance/phase6/test_p6_5_gate.py tests/fault/release/test_c1_failure_returns_to_c0.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(release): separate C1 approval from manual publication"
~~~

This tooling commit is also a prerequisite to Task 36 Step 6. No production C1 or publication occurs while source can still change.

- [ ] **Step 6: Execute distinct C1 approval and a third manual publication action with no source change**

After accepted C0, require empty `git status --porcelain=v1`. Explicitly import the fresh handoff and run C1 only through the installed isolated terminal. Prepare the short-lived signed publication manifest now—not before the seven-day soak—so it and the C1 candidate share one preallocated UUID: `TUNTUN_ALLOW_PRODUCTION_C1=1 uv run tuntun-release-maintainer c1 import-c0-handoff --handoff var/evidence/phase6/c0-release-handoff.json && TUNTUN_ALLOW_PRODUCTION_C1=1 uv run tuntun-release-maintainer c1 prepare-publication-manifest --c0-candidate-id-from-handoff --release-root var/release/frozen --evidence-root var/evidence/phase6 --valid-for-seconds 86400 --output var/evidence/phase6/prepared-publication-manifest.json && TUNTUN_ALLOW_PRODUCTION_C1=1 uv run tuntun-release-maintainer c1 build --c0-candidate-id-from-handoff --prepared-publication-manifest var/evidence/phase6/prepared-publication-manifest.json --release-root var/release/frozen --evidence-root var/evidence/phase6 --output var/evidence/phase6/c1-unsigned.json && TUNTUN_ALLOW_PRODUCTION_C1=1 uv run tuntun-release-maintainer c1 approve --candidate var/evidence/phase6/c1-unsigned.json --fresh-project-passkey-ceremony --output var/evidence/phase6/c1-accepted.json && uv run tuntun-release-maintainer c1 verify --accepted var/evidence/phase6/c1-accepted.json --c0-handoff-store current --release-root var/release/frozen`.

Only after that succeeds, and while the same signed manifest remains current, may the project maintainer run the distinct two-call publication ceremony: `TUNTUN_ALLOW_PUBLICATION=1 uv run tuntun-release-maintainer publish prepare --accepted-c1 var/evidence/phase6/c1-accepted.json --release-root var/release/frozen --output var/evidence/phase6/publication-action.json`, inspect the immutable action, then `TUNTUN_ALLOW_PUBLICATION=1 uv run tuntun-release-maintainer publish execute --action var/evidence/phase6/publication-action.json --fresh-project-passkey-ceremony --output var/evidence/phase6/publication-receipt.json`. Finally run `uv run tuntun-release-maintainer publish verify-receipt --receipt var/evidence/phase6/publication-receipt.json --independent-redownload && uv run python scripts/phase6/verify_release.py --accepted-c1 var/evidence/phase6/c1-accepted.json --publication-receipt var/evidence/phase6/publication-receipt.json --release-root var/release/frozen && uv run python scripts/scan_private_data.py --paths var/evidence/phase6/prepared-publication-manifest.json var/evidence/phase6/c1-unsigned.json var/evidence/phase6/c1-accepted.json var/evidence/phase6/publication-action.json var/evidence/phase6/publication-receipt.json`.

Expected: C1 uses a fresh project-maintainer assertion distinct from C0, publication uses a third fresh assertion bound to the prepared action, independent redownload reproduces every immutable byte, P6-5 passes, and `git status --porcelain=v1` remains empty. A failure before C1 acceptance leaves only accepted C0. A failure after `C1AcceptedReceiptV1` but before a verified `PublicationReceiptV1` preserves the immutable accepted-C1 history and records no publication claim; it may reconcile only the exact owned incomplete run/tag, or after the half-open run deadline use a fresh action/assertion for the same immutable bytes. Source, artifact or C0 drift invalidates publication eligibility and returns to Task 36 Step 6 for a new candidate without erasing the prior C1 history or permitting that C1 to authorize changed bytes.

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
- Task 36C requires a later same-candidate seven-day full-system household soak and two distinct eight-hour wall/monotonic stress runs after Task 35B accepts P6-4. Do not double-count the historical P6-1 pilot; Task 36C reruns the current controls against the final candidate.
- Task 34B opens the maintenance epoch only after Task 36B has frozen and real-target-qualified every final byte/row. Evidence logging may begin after at least 60 steady-state days; evaluation for promotion requires at least 90 steady-state days and three complete monthly buckets for the rolling three-month median. Fake-clock/synthetic reports test arithmetic only and never satisfy P6-4 or C0.
- One clean owner-only quarterly-style restore/lockout/retirement exercise is mandatory for acceptance; continuing quarterly operation remains scheduled after release.
- Official Tailscale client/account terms, Tailnet Lock/current signed-node set with Device Approval disabled, independent recovery signers, remote-device enrollment, authoritative DNS acceptance, IdP/control-plane availability and independent internet/outer/inner scan vantage are owner/provider elapsed gates, not coding estimates.
- Apple Developer enrollment, protected signing access, notarization service latency, Gatekeeper verification, and owner-approved clean Intel plus current Apple Silicon access are external elapsed gates. Borrow/rent/lab/purchase needs a dated quote and explicit owner cap; this plan grants no automatic spend. Hosted targets are synthetic-only, and a real private restore requires an isolated owner-controlled Mac. C1 waits rather than substituting an unsigned, single-architecture, or synthetic-only claim.
- A hardware/OS/router/client/plugin-sandbox version change invalidates its receipt and can extend the calendar. Security findings and Apple/provider review override the nominal 8–12 focused weeks.
- C0 and C1 are sequential local approvals on one frozen candidate. C1 cannot start before accepted C0, and publication remains a separate manual action after C1.
- **Final-candidate critical path:** `36A → 37A → 38A → 36B → 34B → 35R → U8B → 35B/P6-4 → 36C → 37B/C0 → 38B/C1 → publication`. The minimum calendar is dominated by Task 34B's at-least-90-day/three-complete-month window after the immutable build, followed by the current resilience/UI acceptances and Task 36C's seven-day soak (the two eight-hour runs may overlap only if both schemas and resource/load definitions remain independently satisfied). No earlier elapsed receipt shortens this path.

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
  08 + 10–12 final P6-1 ingress graph ─> 15 row refresh/lifecycle + seven-day pilot ── P6-1

  15 ─┬─> 16 reversible action scopes ─┐
      └─> 17 camera metadata/playback ├─> 18 row refresh/lifecycle + per-class manifest ── P6-2
                                      ┘
  06 ─> 19 exact plugin SDK/registry ─> 20 admission/IPC ─> 21 sandbox
  19–21 ─> 22 health render ─> 23 alert render/non-suppression ─┐
  06 ─> 24 simulator/docs ─> 25 CI/locks ─> 26 build/verifier tooling ┤
  26 ─> 27 finalizer/package tooling ─> 28 update/rollback ─> 29 interim row refresh/lifecycle ─┴─ P6-3
  18 P6-2 row + 19–28 plugin/release graph ────────────────────> 29

  03/06 ─> 30 independent backup ─> 31 clean restore/no resurrection
  04/08/13/23/28/30/31 ─> 32 incidents ─> 33 retirement/lockout
  03 + enabled subsystem health ─> 34A maintenance tooling commit
  28–33 + 34A ─> 35A final route/System UI/P6-4-oracle tooling commit

  P6-1 + P6-2 + P6-3 + Phase 1–5 gates + U8A + 35A
    └─> 36A final row refresh/lifecycle + campaign tooling commit
         └─> 37A C0 tooling commit ─> 38A isolated C1/publication tooling commit
              └─> 36B clean final build/sign/notarize/staple + real targets
                   └─> 34B exact-candidate 60/90-day maintenance evidence
                        └─> 35R current exact-candidate resilience evidence
                             └─> U8B post-drill UI evidence acceptance
                                  └─> 35B evidence-only P6-4 acceptance
                                       └─> 36C same-candidate T01–T25/soak/stress evidence
                                            └─> 37B fresh local owner C0 freeze
                                                 └─> 38B distinct C1 approval
                                                      └─> separate manual publication ── P6-5
~~~

The `A` nodes are tooling-only implementation/test commits. Task 36B is the one immutable candidate creation/target-qualification boundary; Task 34B, Task 35R, U8B, Task 35B, Task 36C, Task 37B and Task 38B are authority-bearing evidence/acceptance ceremonies outside the tracked source tree. Tasks may run in parallel only when this graph shows no shared authority/file/evidence dependency. No tracked or release-artifact mutation occurs after Task 36B and before publication. Maintenance, resilience, UI, P6-4, hardware and campaign evidence must bind that one clean immutable candidate; any parallel or later mutation invalidates Task 34B, Task 35R, U8B, Task 35B, Task 36C and C0/C1 together.

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
| Canonical pre-issued feature-manifest rollover chain, per-admission lease and zero expired-authority interval across multi-day gates | 01, 15, 34, 36–38 |
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
2. Review current Tailscale terms/pricing and official client; commission one synthetic-only test client, Tailnet Lock/current signed-node set/at least two independent recovery signers with Device Approval disabled, exact canonical `grants` policy, two-view authoritative DNS/local CA, firewall and revoke path locally.
3. From the approved remote node, BE800 outer side, ASUS inner side and an independent internet host, prove only the console origin is remotely reachable and no public/inner target succeeds.
4. Rebuild/re-sign and install-lifecycle-qualify the Task 15 P6-1 owner-ingress checkpoint, load one complete externally signed canonical feature-manifest rollover chain for the same candidate, then complete the seven-day read-only pilot with zero expired-authority interval. Revoke the test node and prove all old sessions/media fail before optional scopes.
5. Select zero or more P6-2 classes locally; calibrate each exact class, refresh/install-lifecycle-qualify the Task 18 row for the exact enabled/absent graph, and record `enabled` or complete negative absence. Do not enable a bundle.
6. Qualify the plugin sandbox on the supported Intel Mac and declared Apple Silicon target with every exfiltration/resource/cleanup case before enabling either mandatory capability path.
7. Enroll protected Apple signing/notarization credentials outside the repository; refresh/install-lifecycle-qualify the interim Task 29 P6-3 row after the plugin/release route graph, build twice clean, produce SBOM/provenance/signatures, and run clean install/update/rollback/preserve-uninstall on both architectures.
8. Implement/test/commit Tasks 30–33, Task 34A maintenance tooling and Task 35A System UI/final route/P6-4 oracle. Synthetic drills at this stage qualify tooling only; they are not final-candidate evidence.
9. Complete Task 36A's post-Task-35A owner-ingress rebuild/re-sign and installed lifecycle, then commit Task 37A C0 and Task 38A isolated C1/publication tooling. Require an empty tree; these are the last source/route/service-row/lock/workflow/schema/package mutations.
10. Run Task 36B: build twice, sign/notarize/staple, hash/freeze the exact final artifact/service inventory, and qualify every real Mac and enabled Linux target (or prove cryptographic absence). From this boundary through publication, permit only evidence/acceptance/publication writes; any candidate-byte drift restarts here after all source changes are committed.
11. On that exact Task 36B installation, pre-issue/verify/stage the one canonical same-candidate `SignedFeatureManifestRolloverChainV1` covering Task 34B plus Task 36C. This is an evidence/authority-staging operation and changes no candidate byte.
12. Run Task 34B: open the final-candidate steady-state epoch, begin promotion-eligible logging no earlier than 60 uninterrupted days, and accumulate at least 90 uninterrupted days plus three complete UTC monthly records with zero expired-authority interval. A closed-authority interval or candidate drift retains observations but restarts the entire eligible generation; three overage months freeze expansion.
13. Run Task 35R's candidate-bound real resilience envelope so independent-copy/clean-restore/no-resurrection/incident/retirement/update receipts are current and the exact Task 36B installation is restored after every drill.
14. Run U8B on that post-drill frozen candidate and the Task 34B/Task 35R receipts. It writes only the signed UI acceptance receipt outside the tracked tree.
15. Run Task 35B to accept P6-4 from only the exact frozen-candidate receipts, including Task 35R and U8B. It writes evidence outside the tracked tree and makes no source, route, service-row or artifact change.
16. Run Task 36C on those unchanged bytes: two eight-hour stress campaigns, a seven-day full-system soak, T01–T25, every current Phase 1–6 control and optional-absence check, with zero expired-authority interval. Earlier P6-1/P6-2 receipts remain sequencing evidence only.
17. Build C0 from Task 34B/Task 35R/U8B/P6-4/Task 36C, review all digests, and collect a fresh local owner passkey approve/reject. Make no tracked or artifact change.
18. Reload and verify the already frozen post-sign/notarize/staple public artifacts without rebuilding them, confirm the intended `v{version}` tag is still absent under create-only/no-overwrite policy, prepare the tag-bound manifest and build C1 from unchanged C0, collect a second distinct fresh local C1 approval, then perform the separate manual publication and independent download/tag-target verification.

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
- [ ] Tailnet Lock/current signed-node set/approved nodes/two independent recovery signers with Device Approval disabled, canonical least-route `grants` policy, two-view authoritative DNS/local CA, exact interfaces/8443/53, firewall and revoke drill pass.
- [ ] VPN-only and application-only authentication reveal no private state; passkey/origin/CSRF/nonce/rate/expiry/revocation tests pass.
- [ ] Independent internet/outer/inner/remote scans prove the console is the only reachable target and no public route exists.
- [ ] Theft, grants-policy/lock/signed-node/DNS/client/cert/firewall/IdP/replay/session-race injections suspend and revoke while local essentials remain.
- [ ] The canonical externally signed rollover chain binds the pilot candidate and complete interval; every wall/monotonic lease check and transition passes with zero expired-authority interval, while missing/stale/invalid next-authority injections close before work and invalidate the run.
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
- [ ] No independent-copy operation, restore journal, containment effect run or retirement effect run is pending, ambiguous or unreconciled at gate time.
- [ ] System UI/diagnostic preview is truthful, no-store, accessible and English/Hindi complete across failure states.
- [ ] Task 36B froze and real-target-qualified every final byte and signed service row before the real maintenance epoch or any counted P6-4 acceptance evidence; no later source/route/service-row/artifact mutation occurred.
- [ ] After at least 90 steady-state days and three complete monthly buckets, rolling three-month median is ≤8 hours/month; three overage months set expansion freeze.
- [ ] The counted maintenance interval binds the canonical Task 36B same-candidate rollover chain and every transition, has zero expired-authority interval, and excludes rather than credits observations across any closed-authority gap; the Task 35B receipt binds that exact candidate and maintenance receipt.

**No-go:** Keep affected routes quarantined and optional expansion frozen. Do not approach C0.

### C0 — Whole-Program Candidate Freeze

- [ ] One immutable version/commit/feature manifest binds every current Phase 1–6 mandatory-control and optional-absence rerun; accepted historical phase-gate receipts prove ordering but cannot substitute for the final-candidate rerun, and no candidate feature-manifest reclassification exists.
- [ ] Every canonically optional absence has complete UI/API/config/replay/direct/package/network negative evidence.
- [ ] T01–T25 are exactly closed with owner/test/fallback/review and no unresolved blocker/high/critical finding.
- [ ] Exact hardware/firmware compatibility, two eight-hour runs, seven-day full-system soak, restore/no-resurrection and listener/route/private scans pass.
- [ ] The historical P6-1 chain receipt proves sequencing; the one Task 36B final candidate binds the counted maintenance window, P6-4 acceptance and final campaigns to the complete ordered Phase 2 manifest/transition-receipt chain with zero expired-authority interval. Missing, stale, cross-candidate or invalid authority cannot be replaced by synthetic evidence.
- [ ] Applicable maintenance logging begins no earlier than 60 steady-state days, and promotion evidence includes at least 90 steady-state days plus three complete monthly buckets; the window is not accelerated or waived.
- [ ] Packet has no waiver field; P1R0/P1R1 cannot parse or substitute; fresh local owner passkey approve/reject binds all digests.
- [ ] Approval freezes only; it does not publish or enable a missing feature.

**No-go:** Any failure/change creates a new candidate and reruns C0.

### C1/P6-5 — Public Beta Approval and Manual Publication

- [ ] Accepted C0 is current and unchanged byte-for-byte in every invalidating category.
- [ ] Reproducible clean build, locks/licences, SPDX SBOM, provenance, signatures, Developer ID/notarization/Gatekeeper and both architecture lifecycle receipts bind exact artifacts.
- [ ] Simulator/docs/support/compatibility/publication manifest and source/history/artifact private scans pass.
- [ ] Before C1, the intended tag is exactly `v{version}`, is absent at the exact repository target, and the create-only/no-overwrite policy is verified; this is availability evidence, not a claim that publication already occurred.
- [ ] A second distinct fresh project-maintainer passkey at the local release terminal approves exact C1; it has no household authority and CI has not inferred approval or published.
- [ ] A separate manual publication atomically creates (never overwrites) the tag/new version, then an independent verifier downloads every asset and verifies the tag still targets the exact source commit; the signed `PublicationReceiptV1` records those facts.
- [ ] Incident/advisory/rollback/support paths are current; maintainers gain no household recovery authority.

**No-go:** Failed C1 returns to a new C0. Never overwrite a published asset or auto-publish on green CI.

## Final Verification Commands

Run from a clean checkout of the frozen candidate before C0:

~~~bash
mkdir -p var/test-artifacts var/release
make check
uv run pytest -q
uv run pytest --cov=apps --cov=packages --cov=integrations --cov=scripts/phase6 --cov-fail-under=85 --cov-report=term-missing --cov-report=json:var/test-artifacts/coverage.json
uv run python scripts/check_critical_coverage.py --coverage-json var/test-artifacts/coverage.json --minimum 95 --modules auth,remote,exposure,plugin,release,update,recovery,deletion,incident,c0,c1
uv run python scripts/phase6/generate_schemas.py --check
uv run python scripts/check_generated_artifacts.py --check
uv run python scripts/phase6/verify_default_absence.py
uv run python scripts/check_feature_absence.py --all-canonically-absent --direct-and-replay
uv run python scripts/check_import_boundaries.py --all
uv run python scripts/scan_private_data.py --include-git-history --paths . var/test-artifacts var/release
uv run python scripts/scan_browser_artifacts.py --forbid private_payloads,secrets,reusable_urls,service_workers,persistent_storage
uv run python scripts/check_workflow_pins.py .github/workflows
uv run python scripts/check_licenses.py --project --check --output var/release/THIRD_PARTY_NOTICES.txt
pnpm --filter @tuntun/admin test
pnpm --filter @tuntun/admin typecheck
pnpm --filter @tuntun/admin build
pnpm --filter @tuntun/admin e2e
~~~

Then verify, without regenerating or modifying the frozen candidate, the historical signed P6-1 network/pilot and P6-2 sequencing receipts plus the final-candidate P6-3 sandbox/Intel/Apple/notarization, Task 34B maintenance, Task 35R resilience, U8B, Task 35B P6-4, Task 36C stress/soak/threat/control-rerun, canonical feature-manifest rollover/zero-gap lease, C0 and C1 receipts. A missing final-candidate receipt cannot be replaced by its historical or synthetic counterpart.

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
- [ ] Historical P6-1 and the final-candidate evidence use only Phase 2's canonical pre-issued rollover chain and per-admission lease; Task 34B, Task 35R, U8B, Task 35B and Task 36C bind every ordered transition to the exact Task 36B candidate, have zero expired-authority interval where the chain governs elapsed work, and fail closed on a missing/stale/invalid successor; no Phase 6 renewal path exists.
- [ ] Full-system maintenance evidence has at least 90 steady-state days and three complete monthly buckets; median ≤8h/month and expansion-freeze semantics pass.
- [ ] C0 is whole-program, not P1R0/P1R1, has no waiver and freezes one immutable candidate.
- [ ] C1 is a second distinct approval on unchanged C0; publication is a third separate manual action.
- [ ] Public simulator/docs/evidence contain only synthetic/content-safe data and make no unsupported hardware/privacy claim.
- [ ] No source, route, service row, lock, workflow, schema, feature, dependency, package, evidence policy or release artifact changed after Task 36B; the post-freeze maintenance/P6-4/campaign/C0/C1/publication sequence is evidence-only.

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-27-tuntun-phase6-remote-access-product-hardening-execution.md`.

Implementation should use `superpowers:subagent-driven-development` task-by-task with a fresh reviewer at every commit, or `superpowers:executing-plans` in dependency-ordered batches. Never begin a real Tailscale, network-scan, plugin-sandbox, clean-Mac, Apple-signing, elapsed campaign, C0/C1, or publication gate from a dirty checkout or with an unreviewed evidence destination.
