# Tuntun Phase 2 Home Automation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver deterministic, local, policy-governed control of twelve MOES Zigbee ceiling lights through a capability-proved Home Assistant Green/MZHUB path, governed light scenes and routines, and a simulator-only screen-time policy foundation without expanding Home Assistant, a model, a Guest session, or an unproved television into household authority.

**Architecture:** Extend the Phase 1 Mac modular monolith with versioned topology, policy, action, automation, screen-time, owner-API, and UI modules. A narrow Home Assistant Core custom integration on Green exposes only a channel-authenticated state route plus signed desired-state action and bounded-routine routes; it owns a separate durable receipt database and translates compiled light capabilities using Home Assistant system context, while the Mac retains identity, family policy, passkeys, action commitment, audit, and reconciliation authority. Commission the existing MZHUB through a no-reset capability probe and one-light pilot before twelve-light rollout; direct Zigbee through ZBT-2 is a conditional, separately approved fallback.

**Tech Stack:** Python 3.12, `asyncio`, Pydantic v2, SQLAlchemy 2/Alembic over SQLCipher, `cryptography`, macOS Secure Enclave/Keychain through a project-owned P-256 signing port, FastAPI, Home Assistant Core custom-integration APIs, SQLite WAL with `synchronous=FULL`, JSON Schema 2020-12, RFC 8785/JCS; React 19, TypeScript, Vite, React Router, TanStack Query; pytest, pytest-asyncio, Hypothesis, Ruff, strict mypy, Vitest, Testing Library, Playwright, and owner-gated hardware/fault campaigns.

**Normative design:** [Phase 2 Home Automation](../specs/2026-08-27-tuntun-phase2-home-automation-design.md), [Program A–H](../specs/2026-08-27-tuntun-program-architecture-a-h.md), [Program I–S](../specs/2026-08-27-tuntun-program-assurance-delivery-i-s.md), and [Six-Phase UI/UX](../specs/2026-08-27-tuntun-six-phase-ui-ux-design.md).

## Authority and Upstream Reconciliation

1. The Phase 2 design is normative for Phase 2 limits and gates. Program A–H is normative for shared contracts and composition; Program I–S is normative for repository, assurance, operations, and synthetic-fixture rules; the UI/UX design is normative for UI truth and feature registration.
2. Existing Phase 1 execution plans define consumed interfaces and repository conventions, but they do not override newer approved program amendments. When an inherited Phase 1 literal conflicts, implementation updates the shared contract, migration, corpus, feature manifest, and generated client in the same commit before Phase 2 code consumes it.
3. Register exactly these Phase 2 amendments before action execution: `home_reversible_low_v1`, `child_guarded_light_v1`, `designated_guest_request_v1`, and `offline_home_action_lifecycle_v1`. They are closed exceptions, not broad role changes.
4. The current program baseline stores no unknown biometric candidate. Phase 2 actor resolution consumes only current bounded identity evidence and a separately owner-created designated-Guest bearer session; it never reads or recreates a passive unknown-candidate queue.
5. The MZHUB product name proves no Matter bridge, Thread radio, Zigbee coordinator behavior, local runtime, endpoint fidelity, or attestation. The capability record stores independent `matter_bridge`, `thread_radio`, `zigbee_coordinator`, and `local_runtime` findings. Phase 2 uses only a positively proved local Matter-bridge path; it never assumes or requires Thread.
6. The Phase 1 owner API's server-prepared `428 step_up_required` transaction remains authoritative. Phase 2 browser code submits typed resource fields only and never constructs `ActionBinding`, policy versions, Home Assistant entity IDs, signatures, or assurance claims.
7. `ActionProviderPort` remains the cross-phase seam, but home actions use the expanded post-commit lifecycle defined below. No Phase 1 external-effect path may skip `AUTHORIZED_COMMITTED`, signing, HA pre-dispatch persistence, or reconciliation.
8. A conditional feature passes by positive evidence or by proving its package registration, route, API, UI, configuration, and action endpoint are absent. A disabled front-end control is not sufficient.
9. `area_id` is the sole canonical household location key across Phase 2 and all later-phase seams. Optional `zone_id` records are versioned children of exactly one `area_id` and one owning adapter/binding generation; they never replace an area, move across areas, or broaden target resolution. No contract, database, API, fixture, generated client, or compatibility mapping may introduce `room_id`.
10. `AreaV1` and `CanonicalLocationRefV1` are the imported cross-phase authority. Every location-sensitive Phase 3/4 row and wire DTO binds exact `(area_id, area_generation)` and reopens the current `AreaV1` before effect. Guest is an orthogonal narrowing actor/session policy, never an area class; reclassification increments generation and revokes stale authority through restart/restore.
11. The canonical core Alembic graph is linear: `0009_home_topology_policy.down_revision == "0008_prepared_mutations"`, then `0010 -> 0009`, `0011 -> 0010`, and `0012 -> 0011`. Experimental search is `search_0001_experimental_search` in the separate `alembic_version_experimental_search` feature version table and is never a core parent, merge revision, or core head.

## Global Constraints

1. Phase 1 family-ready gate `FB0` must pass before Phase 2 household mutation is enabled. Phase 2 consumes the accepted `IdentityFusionPort` Guest-on-uncertainty decision, `PolicyEnginePort`, `AuthenticationPort`, `ActionBinding`/single-use `AuthGrant`, serialized SQLCipher `AsyncUnitOfWork`, `ActionMutationCoordinator`, `ActionProviderPort`, `AuditPort` plus transactional audit outbox, loopback owner-console prepared-mutation/428 protocol, backup/restore smoke evidence, and Reachy isolation decision. Each consumed interface must retain its FB0 contract and tests; the later Phase-1-only `P1R0` preview may proceed in parallel and is not a Phase 2 entry gate.
2. All committed fixtures, screenshots, examples, evidence schemas, and tests are synthetic. No household name, real area/display alias, IP/MAC, serial, certificate, Matter setup code, vendor account, entity ID, light model signature, TV identifier, biometric, transcript, memory, credential, or provider/device body enters Git or CI.
3. Real capability evidence is written only to ignored owner storage under `var/evidence/phase2/` using pseudonymous device IDs and content-safe hashes. Tests use `fixtures/synthetic/home/` and temporary keys/databases.
4. Home Assistant receives no Tuntun user identity, biometric evidence, transcript, canonical memory, PIN, passkey credential, provider context, family policy rationale, or actor ID.
5. The Mac receives no Home Assistant user, refresh token, long-lived token, general REST/WebSocket credential, Supervisor token, or arbitrary service permission.
6. The custom integration is the explicit privileged TCB. Its three routes are the only Tuntun-to-HA routes: channel-authenticated state/heartbeat, signed desired-state action, and signed bounded-routine manifest. It holds no HA/Supervisor credential or response-signing key and accepts no caller-selected entity, service, template, script, scene, automation, YAML, event name, or argument bag.
7. Every trust-boundary DTO is frozen, rejects unknown fields/enum values and duplicate keys, uses Unicode NFC and RFC 8785/JCS canonical bytes where signed, uses aware UTC with six fractional digits, bounds every collection/string/body, and has an explicit version.
8. All Home Assistant mutations are exact desired states. `toggle`, relative brightness, wildcard areas, dynamic groups, nested scenes, non-light targets, and non-idempotent operations are invalid.
9. Security, lock, alarm, cooking/heating, mains relay, purchase, and other hazardous classes are absent from the Phase 2 action registry even for the owner.
10. One identified adult may immediately execute only one unambiguous, reversible, registered single-light action with fresh identity, policy, topology, binding, capability, and observation evidence. Any missing condition returns to confirmation or denial.
11. A child light rule is disabled until an owner and a distinct current primary guardian approve the same child/rule digest and generation. It covers one ordinary light in enumerated `area_id` values/hours only and never scenes, routines, persistence, private areas outside scope, security, or hazards.
12. A designated-Guest session is a scoped request channel, not identity or authorization. Every exact common-area action remains pending until independent owner console/passkey co-approval. Identity conflict, mixed-speaker evidence, failed liveness, or possible-child evidence cancels it.
13. `anonymous_restricted` has no Phase 2 side-effect authority. Uncertainty never increases a person's permissions; explicit deny wins.
14. Adult scene execution requires one exact aggregate confirmation. Scene create/edit/delete, policy mutation, routine install/rollback/re-enable, mode expansion, credential/epoch rotation, restore recovery, and topology/binding mutation require an exact owner passkey.
15. Manual is the commissioning default for every automation domain. Assisted installs only a signed closed routine manifest. Learning creates local drafts only and cannot install, edit, enable, disable, merge, or delete a routine.
16. Screen-time Phase 2 execution is simulator-only. A real TV endpoint remains `ADVISORY_ONLY` and has no enforcement route until its exact control and observation gates pass in the owning phase. Strict additionally requires independent failure domains or a directly proved equivalent campaign.
17. A command is never called successful from an acknowledgement alone. Human-facing terminal classes are `VERIFIED`, `ACCEPTED_UNVERIFIED`, `FAILED`, `UNKNOWN`, and `EXPIRED`; the UI and speech preserve that distinction.
18. Mac action timing is exact: `issued_at >= authorized_at`, signing occurs no more than five seconds after authorization, `expires_at <= authorized_at + 30 seconds`, and measured Mac/Green offset must be at most two seconds. HA must durably commit `PRE_DISPATCH` before expiry and start service I/O within two seconds of that commit and before expiry. An otherwise valid envelope first received at or after expiry is unadmitted: it creates no `PRE_DISPATCH` row or `HAReceiptV1`. Only recovery of an exact row durably admitted before expiry may terminalize as `EXPIRED`, retaining its actual `pre_dispatch_at`; admission evidence is never backdated.
19. HA receipt storage uses WAL, `synchronous=FULL`, a 100 MiB hard quota, maintenance at 75%, mutation rejection at 90%, no purge of nonterminal rows, immutable `terminal_at`, full live detail through `terminal_at + 10 days`, and keyed tombstone through `terminal_at + 30 days`.
20. Encrypted HA backup retention discloses archive bounds separately: full receipt detail may remain through `terminal_at + 38 days`, and tombstones through `terminal_at + 58 days`. Archive deletion, not restore-time compaction, ends that retention.
21. The strict opaque UUIDv4 `controller_epoch`, owned only by `tuntun_contracts.home.channel`, must match on Mac and Green. Restore or rollback isolates device paths, rotates to a fresh cryptographically random UUIDv4 epoch using owner passkey plus local HA owner/admin confirmation, marks old nonterminal Mac actions `UNKNOWN`, and quarantines every restored routine. It is never coerced from an integer/string in Python-mode construction or aliased by later phases.
22. Home Assistant Recorder has an explicit allowlist, `purge_keep_days: 10`, and no unnecessary long-term statistics. Learning projections and unapproved drafts expire in at most 30 days; screen-time session detail expires in 30 days.
23. Green, the inner router/switch, and MZHUB are the UPS load. A proved NUT signalling path shuts down Green before exhaustion; router/switch/MZHUB are described only as ride-through loads unless their own shutdown interfaces are independently proved. Household lights are not promised during mains loss.
24. The BE800 is the outer router and the GT-AX6000 plus three AX5400 nodes are the inner household network. The office laptop and Tuntun Mac are the same Phase 1 owner-approved opaque active-Core inventory target, currently verified as Darwin arm64. The family-ready baseline disconnects its BE800 link and single-homes it on one inner-ASUS interface; dual-homing that same host is a separately disabled gate, never an assumed second machine. Double NAT is topology, not mutual isolation. Architecture, model, product, and model-year strings never grant host authority, and no VLAN/SSID isolation claim is allowed without exact firmware and negative-reachability evidence.
25. Green and MZHUB remain on the same inner LAN for the bridge pilot. IPv6, mDNS, Matter discovery, and every actual AiMesh wired/wireless path are proved; speculative segmentation must not break commissioning.
26. No public inbound route, port forwarding, DMZ, UPnP, NAT-PMP/PCP mapping, WAN administration, or Home Assistant Cloud remote access is enabled. Phase 6 owns any remote owner route.
27. Reachy production voice ingress is enabled only if its Phase 1 isolation gate passed. Otherwise automatic voice/face processing and action ingress are absent, and only the owner-authenticated loopback commissioning harness exercises the post-intent path.
28. The existing MZHUB/light network is never reset before P2-1 passes or the owner explicitly approves conditional P2-F. One failed Matter observation does not authorize a twelve-light migration.
29. Ordinary tests perform no paid, WAN, hardware, Keychain, Secure Enclave, Home Assistant, router, SMB, or UPS I/O. Marker-gated campaigns require explicit environment flags and bounded, pseudonymized evidence destinations.
30. Project-wide branch coverage remains at least 85%; policy/auth/action/signature/receipt/routine/restore modules remain at least 95%. Every implementation task follows red → green → refactor → affected suite → static/security checks → exact-path commit.
31. A fixed-local-time routine is installable only with one signed `RoutineScheduleAuthorityV1` whose exact tzdata version and SHA-256 resolve every declared IANA zone through a pinned `ZoneInfo` artifact at activation. Scheduled occurrence identity is the canonical local date/time/zone, `fold=0`, resolved UTC instant, artifact authority, routine generation, and manifest digest. Policy is exactly `fold_first_gap_skip_no_replay.v1`: the first fall-back occurrence may run once, a spring-forward gap is durably skipped without shift/catch-up, and a backward wall-clock jump closes scheduled admission until trusted UTC strictly exceeds the durable high-water mark; no committed or skipped slot may fire later.
32. A feature manifest is valid for at most 24 hours. The Core runtime never holds or invokes the acceptance signer. Any multi-day campaign uses a complete, externally signed, pre-issued, hash-chained rollover set for one frozen candidate; every admission also requires the active manifest's wall expiry and a process-local monotonic expiry lease. Missing, late, reordered, widened, rollback, signature-invalid, candidate-drifted, or expired rollover authority closes admission before preparation or background work and triggers controlled whole-composition recovery.
33. Home Assistant has no response-signing key. Restore readiness arrives only as strict `HAReadinessObservationV1` data on the existing pinned-TLS, request-bound state channel; the Mac validates its echoed nonce, monotonic stream sequence, freshness, epoch/generation and exact build/configuration digests, then writes a separately keyed, locally authenticated durable mirror. Neither a transport observation nor the mirror alone can reopen mutation.
34. If a delayed restore contains only expired feature authority, no HTTP recovery route is reachable. With Core stopped, the sole escape hatch is `tuntunctl features stage-rollover --file PATH`: a nofollow, bounded, owner-only, verify-only atomic import of a separately delivered externally signed chain for the exact installed candidate. It has no signer, renewal, network-fetch or activation capability; controlled restart re-verifies and opens at most the current read/recovery-safe composition, while ordinary mutation remains quarantined.

## Definition of Done for Every Task

- The named failing test is observed before implementation and fails for the intended missing contract or behavior.
- Narrow and affected Python suites pass with Ruff format/check and strict mypy; touched UI passes lint, TypeScript, Vitest, Playwright, axe, and production build.
- Contract changes regenerate and diff-clean Python/JSON/OpenAPI/TypeScript artifacts, include positive and adversarial fixtures, and reject unsupported versions and unknown fields.
- Database changes have an encrypted pre-migration backup, forward upgrade, downgrade-or-isolated-restore strategy, restart/corruption tests, and exact table/index/trigger ownership assertions.
- External-effect code has crash injection immediately before and after every durable transition and never performs I/O while the canonical SQLCipher writer lock is held.
- Logs, browser state, artifacts, evidence, and backups are scanned for synthetic forbidden sentinels appropriate to the boundary.
- `git status --short` contains only task-owned paths; only exact paths are staged; `git diff --cached --name-only`, `git diff --cached --check`, and `git diff --cached` are reviewed before the task commit.

## Phase Entry, Promotion, and Exit Gates

| Gate | Entry requirement | Positive exit | Disabled/failed exit |
|---|---|---|---|
| P2-E0 | Phase 1 `FB0` accepted and every explicitly consumed Phase 1 interface in Global Constraint 1 is present at its accepted contract version | Four amendments, contracts, migrations, simulator, feature absence, and synthetic corpora pass; no `P1R0` preview decision is required | Phase 2 remains absent from feature manifest/API/UI |
| P2-0 | P2-E0 software baseline | Inventory/recovery/network/TLS/Secure Enclave/Green/UPS/backup prerequisites pass without resetting a light | No hardware mutation route; native lights continue |
| P2-1 | P2-0, exact MZHUB evidence, and complete externally signed pilot rollover chain | One-light Matter bridge path proves fidelity, truthful state, WAN-off use, reboot/AiMesh recovery for seven elapsed days with every wall/monotonic admission and rollover receipt bound | Keep MZHUB/native estate; open P2-F decision only |
| P2-2 | Either P2-1 `PASS_BRIDGE` or P2-F passed one exact fallback controller path | Twelve stable endpoints have zero ambiguity/wrong-device/false-success cases | Only passed endpoints are registered; household rollout stops |
| P2-3 | P2-2 plus Secure Enclave client signing | Channel-authenticated state route exposes only compiled projection and strict readiness observation; mutation routes absent | Tuntun home control remains read-only/absent |
| P2-4 | P2-3 | Single actions, scenes, adult/child/Guest/anonymous matrix, durable reconciliation, and owner UI pass | Physical/HA-native control remains; Tuntun mutation absent |
| P2-5 | P2-4 | Manual/Assisted/Learning manifests, deterministic runtime, budgets, drift, rollback, and quarantine pass | Domain stays Manual; routine endpoint absent |
| P2-6 | P2-E0 | Screen-time simulator passes 720-case corpus and 10,000 property sequences | Real televisions remain Advisory/manual and unregistered for enforcement |
| P2-7 | All enabled gates and complete externally signed soak rollover chain | Failure matrix, restore, network, power, retention, seven-day household soak, every wall/monotonic admission/rollover receipt, and signed promotion evidence pass | Affected capability is quarantined/absent; unaffected manual paths continue |
| P2-F | P2-1 failed materially and owner approved fallback | One ZBT-2/ZHA light proves capability, offline mesh, restart, and destructive re-pair rollback before area-by-area device migration | No ZBT-2 purchase/migration; all lights stay on MZHUB |

## Planned Repository Map

```text
packages/contracts/src/tuntun_contracts/home/
├── __init__.py
├── base.py                 # strict home schema helpers and canonical bytes
├── topology.py             # canonical areas, subordinate zones, devices/endpoints/capabilities/bindings
├── events.py               # CrossDomainEventV1 and light state projection
├── channel.py              # challenge/proof/key lifecycle DTOs
├── actions.py              # desired state, scene, receipt/result DTOs
├── routines.py             # closed routine manifests and runtime receipts
├── screen_time.py          # allowance/session/eligibility and canonical enforcement-intent DTOs
├── ui.py                   # Phase 2 read models only
└── ports.py                # exact cross-module protocols
packages/contracts/src/tuntun_contracts/features.py
packages/contracts/src/tuntun_contracts/ui.py  # owned by cross-phase UI Task U01; imported unchanged
schemas/home/v1/
├── topology-v1.schema.json
├── events-v1.schema.json
├── channel-v1.schema.json
├── actions-v1.schema.json
├── routines-v1.schema.json
├── screen-time-v1.schema.json
└── ui-v1.schema.json
schemas/features/v1/
├── feature-manifest-v1.schema.json
├── feature-manifest-rollover-chain-v1.schema.json
└── feature-authority-campaign-evidence-v1.schema.json
schemas/ui/v1/operation-result-v1.schema.json
fixtures/synthetic/home/contracts/
├── topology-v1.json
├── state-event-v1.json
├── state-snapshot-v1.json
├── state-delta-v1.json
├── channel-proof-v1.json
├── ha-readiness-observation-v1.json
├── light-action-v1.json
├── light-action-result-v1.json
├── ha-receipt-v1.json
├── scene-envelope-v1.json
├── routine-manifest-v1.json
├── target-resolution-v1.json
├── screen-time-v1.json
├── enforcement-intent-v1.json
├── tv-port-v1.json
└── ui-read-model-v1.json
fixtures/synthetic/home/authorization-corpus-v1.jsonl
fixtures/synthetic/home/screen-time-corpus-v1.jsonl
fixtures/synthetic/home/light-utterances-v1.jsonl
fixtures/synthetic/home/mzhub-capability-samples.json
fixtures/synthetic/home/twelve-light-registry.json
fixtures/synthetic/home/zigbee-radio-survey.json
fixtures/synthetic/home/fault-matrix-v1.json
fixtures/synthetic/features/phase2-home-manifest-v1.json
fixtures/synthetic/ui/operation-result-light-v1.json

apps/core/src/tuntun_core/domain/home/
├── topology.py
├── actions.py
├── policy.py
├── routines.py
├── screen_time.py
└── commissioning.py
apps/core/src/tuntun_core/services/home/
├── topology_registry.py
├── actor_resolution.py
├── permissions.py
├── child_rules.py
├── guest_sessions.py
├── target_resolver.py
├── action_coordinator.py
├── reconciliation.py
├── scenes.py
├── automation.py
├── routine_simulator.py
├── learning.py
├── screen_time.py
├── screen_time_clock.py
├── screen_time_enforcement.py
├── tv_eligibility.py
├── backup_health.py
├── restore.py
└── health.py
apps/core/src/tuntun_core/adapters/home_assistant/
├── client.py
├── state_sync.py
├── secure_enclave.py
└── signer.py
apps/core/src/tuntun_core/api/routes/home.py
apps/core/src/tuntun_core/api/home_dtos.py
apps/core/src/tuntun_core/api/routes/features.py
apps/core/src/tuntun_core/services/features/
├── __init__.py
├── lease.py
├── rollover.py
├── staging.py
└── registry.py
apps/core/src/tuntun_core/cli/main.py
apps/core/src/tuntun_core/cli/commands/features.py
apps/core/migrations/versions/
├── 0009_home_topology_policy.py
├── 0010_home_actions.py
├── 0011_home_automation.py
└── 0012_screen_time.py

integrations/home-assistant/custom_components/tuntun_bridge/
├── manifest.json
├── __init__.py
├── const.py
├── canonical.py
├── models.py
├── schema.py
├── store.py
├── verifier.py
├── http.py
├── projection.py
├── actions.py
├── routines.py
├── backup.py
├── sensor.py
├── switch.py
├── config_flow.py
├── strings.json
└── translations/en.json

apps/admin/src/features/home/
├── index.ts
├── inventory.tsx
├── permissions.tsx
├── lights-scenes.tsx
├── automations.tsx
├── screen-time.tsx
└── health.tsx
apps/admin/src/routes/home-inventory.tsx
apps/admin/src/routes/home-permissions.tsx
apps/admin/src/routes/home-lights.tsx
apps/admin/src/routes/home-automations.tsx
apps/admin/src/routes/home-screen-time.tsx
apps/admin/src/routes/home-health.tsx
apps/admin/src/app/feature-registry.ts

packages/testing/src/tuntun_testing/home/
├── fake_clock.py
├── fake_ha.py
├── fake_light.py
├── fake_tv.py
├── fault_points.py
└── scenario.py
scripts/phase2/
├── generate_home_schemas.py
├── build_authorization_corpus.py
├── build_screen_time_corpus.py
├── build_light_grammar_corpus.py
├── inventory.py
├── probe_network.py
├── probe_mzhub.py
├── commission_lights.py
├── evaluate_zigbee_fallback.py
├── qualify_ups.py
├── verify_green_backup.py
├── rotate_green_backups.py
├── audit_green_logging.py
├── run_fault_matrix.py
├── verify_network_exposure.py
├── verify_home_update.py
├── prepare_feature_manifest_rollover.py
├── assemble_feature_manifest_rollover.py
├── verify_feature_manifest_rollover.py
├── run_acceptance.py
└── verify_acceptance.py
ops/home-assistant/
├── recorder-allowlist.example.yaml
├── green-backup-catchup.example.yaml
├── network-flow-policy.yaml
├── light-registry.synthetic.yaml
└── logging.example.yaml
docs/operations/phase2-commissioning.md
docs/operations/phase2-network.md
docs/operations/phase2-green-backup-restore.md
docs/operations/phase2-ups.md
docs/operations/phase2-key-pairing.md
docs/operations/phase2-mzhub-pilot.md
docs/operations/phase2-light-rollout.md
docs/operations/phase2-direct-zigbee-fallback.md
docs/operations/phase2-observability.md
docs/operations/phase2-update-rollback.md
docs/operations/phase2-failure-recovery.md
docs/operations/phase2-acceptance-runbook.md
docs/privacy/phase2-home-data.md
docs/evidence/phase2-mzhub-gate-schema.json
docs/evidence/phase2-light-baseline-schema.json
docs/evidence/phase2-zigbee-fallback-schema.json
docs/evidence/phase2-fault-gate-schema.json
docs/evidence/phase2-acceptance-schema.json
docs/evidence/phase2-soak-schema.json
```

## Frozen Contract Baseline

All fields below are required unless typed optional. Implementations may add private helpers, not rename or loosen these public contracts.

```python
# packages/contracts/src/tuntun_contracts/home/channel.py
# One canonical opaque epoch type is owned here and imported everywhere else.
# Python-mode construction is strict (UUID object only); canonical JSON wire
# encoding remains the standard lowercase UUID string.
ControllerEpoch = Annotated[UUID, Strict()]

# packages/contracts/src/tuntun_contracts/home/topology.py
class AreaV1(HomeContract):
    area_id: StableHomeId
    display_label: BoundedLabel
    room_class: Literal["common", "adult_private", "child_private", "prohibited"]
    privacy_class: Literal["household", "personal", "restricted"]
    generation: Annotated[int, Field(ge=1)]

class ZoneV1(HomeContract):
    zone_id: StableHomeId
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    owning_binding_id: UUID
    owning_binding_generation: Annotated[int, Field(ge=1)]
    display_label: BoundedLabel
    zone_class: Literal["camera_mask", "robot_boundary", "commissioned_boundary"]
    generation: Annotated[int, Field(ge=1)]
    zone_digest: Sha256Digest
    lifecycle_state: Literal["active", "quarantined", "retired"]

class CanonicalLocationRefV1(HomeContract):
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    zone_id: StableHomeId | None = None
    zone_generation: Annotated[int | None, Field(ge=1)] = None

    @model_validator(mode="after")
    def zone_pair_is_atomic(self) -> "CanonicalLocationRefV1":
        if (self.zone_id is None) != (self.zone_generation is None):
            raise ValueError("zone_id_and_generation_required_together")
        return self

class EndpointBindingV1(HomeContract):
    binding_id: UUID
    endpoint_id: StableHomeId
    capability_id: StableHomeId
    topology_version: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    binding_digest: Sha256Digest
    resolved_ha_entity_commitment: HmacCommitment
    capability_digest: Sha256Digest
    source_integration: Literal["matter", "zha", "zigbee2mqtt", "simulator"]
    observed_at: AwareDatetime
    availability: Literal["available", "unavailable", "stale", "quarantined"]
    commissioning_generation: Annotated[int, Field(ge=1)]

class TopologyBindingLocationV1(HomeContract):
    binding_id: UUID
    binding_generation: Annotated[int, Field(ge=1)]
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]

class TopologyBundleV1(HomeContract):
    topology_schema_version: Literal["1.0"]
    topology_version: Annotated[int, Field(ge=1)]
    areas: Annotated[tuple[AreaV1, ...], Field(min_length=1, max_length=64)]
    zones: Annotated[tuple[ZoneV1, ...], Field(max_length=128)]
    endpoint_bindings: Annotated[tuple[EndpointBindingV1, ...], Field(max_length=128)]
    binding_locations: Annotated[tuple[TopologyBindingLocationV1, ...], Field(max_length=128)]
    bundle_digest: Sha256Digest

    @model_validator(mode="after")
    def exact_topology_relationships(self) -> "TopologyBundleV1":
        area_by_id = {area.area_id: area for area in self.areas}
        binding_by_id = {binding.binding_id: binding for binding in self.endpoint_bindings}
        location_by_id = {location.binding_id: location for location in self.binding_locations}
        if len(area_by_id) != len(self.areas) or len(binding_by_id) != len(self.endpoint_bindings):
            raise ValueError("duplicate_topology_area_or_binding")
        endpoint_capability_keys = tuple(
            (binding.endpoint_id, binding.capability_id) for binding in self.endpoint_bindings
        )
        if len(set(endpoint_capability_keys)) != len(endpoint_capability_keys):
            raise ValueError("duplicate_current_endpoint_capability_binding")
        if any(binding.topology_version != self.topology_version for binding in self.endpoint_bindings):
            raise ValueError("endpoint_binding_topology_version_mismatch")
        if len(location_by_id) != len(self.binding_locations) or set(location_by_id) != set(binding_by_id):
            raise ValueError("topology_binding_location_set_mismatch")
        zone_ids = tuple(zone.zone_id for zone in self.zones)
        if len(set(zone_ids)) != len(zone_ids):
            raise ValueError("duplicate_topology_zone")
        if tuple((area.area_id, area.generation) for area in self.areas) != tuple(sorted(
            (area.area_id, area.generation) for area in self.areas
        )):
            raise ValueError("topology_areas_not_canonical")
        if tuple((zone.area_id, zone.zone_id, zone.generation) for zone in self.zones) != tuple(sorted(
            (zone.area_id, zone.zone_id, zone.generation) for zone in self.zones
        )):
            raise ValueError("topology_zones_not_canonical")
        if tuple(
            (binding.endpoint_id, binding.capability_id, str(binding.binding_id), binding.binding_generation)
            for binding in self.endpoint_bindings
        ) != tuple(sorted(
            (binding.endpoint_id, binding.capability_id, str(binding.binding_id), binding.binding_generation)
            for binding in self.endpoint_bindings
        )):
            raise ValueError("topology_endpoint_bindings_not_canonical")
        if tuple(
            (str(location.binding_id), location.binding_generation) for location in self.binding_locations
        ) != tuple(sorted(
            (str(location.binding_id), location.binding_generation) for location in self.binding_locations
        )):
            raise ValueError("topology_binding_locations_not_canonical")
        for location in self.binding_locations:
            area = area_by_id.get(location.area_id)
            binding = binding_by_id.get(location.binding_id)
            if area is None or binding is None:
                raise ValueError("topology_binding_location_unknown_member")
            if location.area_generation != area.generation or location.binding_generation != binding.binding_generation:
                raise ValueError("topology_binding_location_generation_mismatch")
        for zone in self.zones:
            area = area_by_id.get(zone.area_id)
            location = location_by_id.get(zone.owning_binding_id)
            if area is None or location is None:
                raise ValueError("topology_zone_unknown_parent")
            if (
                zone.area_id != location.area_id
                or zone.area_generation != area.generation
                or zone.owning_binding_generation != location.binding_generation
            ):
                raise ValueError("topology_zone_parent_or_owner_mismatch")
        if self.bundle_digest != topology_bundle_digest(self):
            raise ValueError("topology_bundle_digest_mismatch")
        return self

def topology_bundle_digest_from_parts(
    topology_schema_version: str,
    topology_version: int,
    areas: tuple[AreaV1, ...],
    zones: tuple[ZoneV1, ...],
    endpoint_bindings: tuple[EndpointBindingV1, ...],
    binding_locations: tuple[TopologyBindingLocationV1, ...],
) -> str:
    authority_payload = {
        "topology_schema_version": topology_schema_version,
        "topology_version": topology_version,
        "areas": tuple(area.model_dump(mode="python") for area in areas),
        "zones": tuple(zone.model_dump(mode="python") for zone in zones),
        "endpoint_bindings": tuple(
            binding.model_dump(mode="python") for binding in endpoint_bindings
        ),
        "binding_locations": tuple(
            location.model_dump(mode="python") for location in binding_locations
        ),
    }
    canonical = canonical_mapping_bytes(authority_payload)
    return hashlib.sha256(b"tuntun.home.topology-bundle.v1\x00" + canonical).hexdigest()

def topology_bundle_digest(value: TopologyBundleV1) -> str:
    return topology_bundle_digest_from_parts(
        value.topology_schema_version,
        value.topology_version,
        value.areas,
        value.zones,
        value.endpoint_bindings,
        value.binding_locations,
    )

class EndpointRegistrationV1(HomeContract):
    registration_schema_version: Literal["1.0"]
    endpoint_id: StableHomeId
    capability_ids: Annotated[
        tuple[Literal["light.power.v1", "light.brightness.v1"], ...],
        Field(min_length=1, max_length=2),
    ]
    location: CanonicalLocationRefV1
    safe_display_label: BoundedLabel
    normalized_aliases: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[^\x00-\x1f\x7f]+$")], ...],
        Field(min_length=1, max_length=8),
    ]
    hardware_identity_commitment: HmacCommitment
    firmware_commitment: HmacCommitment
    source_integration: Literal["matter", "zha", "zigbee2mqtt", "simulator"]
    topology_version: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    commissioning_generation: Annotated[int, Field(ge=1)]
    lifecycle_state: Literal["candidate", "commissioned", "quarantined", "retired"]
    evidence_digest: Sha256Digest

    @model_validator(mode="after")
    def unique_endpoint_capabilities(self) -> "EndpointRegistrationV1":
        if len(set(self.capability_ids)) != len(self.capability_ids):
            raise ValueError("duplicate_endpoint_capability")
        if len(set(self.normalized_aliases)) != len(self.normalized_aliases):
            raise ValueError("duplicate_endpoint_alias")
        return self

class LearningProjectionV1(HomeContract):
    endpoint_id: StableHomeId
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    transition: Literal["off_to_on", "on_to_off", "brightness_changed"]
    coarse_time_bucket: Literal["overnight", "morning", "afternoon", "evening"]
    observed_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def bounded_learning_projection(self) -> "LearningProjectionV1":
        if not self.observed_at < self.expires_at <= self.observed_at + timedelta(days=30):
            raise ValueError("learning_projection_window_invalid")
        return self

class FeatureRegistrationV1(HomeContract):
    feature_id: Annotated[str, Field(min_length=1, max_length=96, pattern=r"^[a-z0-9][a-z0-9._-]*$")]
    backend_provider_ids: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9._-]*$")], ...],
        Field(min_length=1, max_length=32),
    ]
    backend_route_ids: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9._:/{}-]*$")], ...],
        Field(min_length=1, max_length=32),
    ]
    ui_module_id: Annotated[str, Field(min_length=1, max_length=96, pattern=r"^[a-z0-9][a-z0-9._-]*$")]
    ui_chunk_digest: Sha256Digest
    contract_digest: Sha256Digest
    schema_digest: Sha256Digest
    policy_digest: Sha256Digest
    corpus_digest: Sha256Digest
    migration_digest: Sha256Digest
    package_digest: Sha256Digest
    positive_gate_evidence_digest: Sha256Digest
    negative_reachability_evidence_digest: Sha256Digest

    @model_validator(mode="after")
    def unique_feature_providers_and_routes(self) -> "FeatureRegistrationV1":
        if len(set(self.backend_provider_ids)) != len(self.backend_provider_ids):
            raise ValueError("duplicate_feature_backend_provider")
        if len(set(self.backend_route_ids)) != len(self.backend_route_ids):
            raise ValueError("duplicate_feature_backend_route")
        return self

class SignedFeatureManifestV1(HomeContract):
    manifest_schema_version: Literal["tuntun.feature-manifest.v1"]
    manifest_version: Annotated[int, Field(ge=1)]
    rollover_chain_id: UUID
    rollover_index: Annotated[int, Field(ge=0)]
    previous_manifest_digest: Sha256Digest | None
    candidate_digest: Sha256Digest
    package_digest: Sha256Digest
    registrations: Annotated[tuple[FeatureRegistrationV1, ...], Field(min_length=1, max_length=64)]
    issued_at: AwareDatetime
    valid_from: AwareDatetime
    expires_at: AwareDatetime
    signer_key_id: KeyId
    signature: P256Signature

    @model_validator(mode="after")
    def exact_feature_manifest(self) -> "SignedFeatureManifestV1":
        feature_ids = tuple(row.feature_id for row in self.registrations)
        module_ids = tuple(row.ui_module_id for row in self.registrations)
        provider_ids = tuple(
            provider_id for row in self.registrations for provider_id in row.backend_provider_ids
        )
        route_ids = tuple(route_id for row in self.registrations for route_id in row.backend_route_ids)
        if len(set(feature_ids)) != len(feature_ids) or len(set(module_ids)) != len(module_ids):
            raise ValueError("duplicate_feature_or_ui_module")
        if len(set(provider_ids)) != len(provider_ids) or len(set(route_ids)) != len(route_ids):
            raise ValueError("cross_feature_provider_or_route_alias")
        if self.rollover_index == 0 and self.previous_manifest_digest is not None:
            raise ValueError("first_rollover_manifest_forbids_previous_digest")
        if self.rollover_index > 0 and self.previous_manifest_digest is None:
            raise ValueError("rollover_manifest_requires_previous_digest")
        if not self.issued_at <= self.valid_from < self.expires_at <= self.valid_from + timedelta(hours=24):
            raise ValueError("feature_manifest_window_invalid")
        return self

def signed_feature_manifest_digest(value: SignedFeatureManifestV1) -> str:
    return hashlib.sha256(
        b"tuntun.feature-manifest.signed-envelope.v1\x00" + canonical_home_bytes(value)
    ).hexdigest()

class SignedFeatureManifestRolloverChainV1(HomeContract):
    rollover_schema_version: Literal["tuntun.feature-manifest-rollover-chain.v1"]
    rollover_chain_id: UUID
    coverage_starts_at: AwareDatetime
    coverage_ends_at: AwareDatetime
    manifests: Annotated[tuple[SignedFeatureManifestV1, ...], Field(min_length=2, max_length=256)]

    @model_validator(mode="after")
    def exact_preissued_chain(self) -> "SignedFeatureManifestRolloverChainV1":
        if not self.coverage_starts_at < self.coverage_ends_at:
            raise ValueError("rollover_coverage_window_invalid")
        first = self.manifests[0]
        frozen_authority = (
            first.candidate_digest,
            first.package_digest,
            first.registrations,
        )
        if first.valid_from > self.coverage_starts_at or self.manifests[-1].expires_at <= self.coverage_ends_at:
            raise ValueError("rollover_chain_does_not_cover_campaign")
        for index, manifest in enumerate(self.manifests):
            if manifest.rollover_chain_id != self.rollover_chain_id or manifest.rollover_index != index:
                raise ValueError("rollover_chain_identity_or_index_mismatch")
            if (manifest.candidate_digest, manifest.package_digest, manifest.registrations) != frozen_authority:
                raise ValueError("rollover_chain_widens_or_drifts_authority")
            if index == 0:
                continue
            previous = self.manifests[index - 1]
            if manifest.manifest_version != previous.manifest_version + 1:
                raise ValueError("rollover_manifest_version_not_contiguous")
            if manifest.previous_manifest_digest != signed_feature_manifest_digest(previous):
                raise ValueError("rollover_previous_manifest_digest_mismatch")
            if manifest.valid_from <= previous.valid_from:
                raise ValueError("rollover_valid_from_not_strictly_advancing")
            if not manifest.valid_from < previous.expires_at:
                raise ValueError("rollover_chain_has_validity_gap")
            if manifest.expires_at <= previous.expires_at:
                raise ValueError("rollover_chain_does_not_extend_expiry")
        return self

class FeatureAuthorityCampaignEvidenceV1(HomeContract):
    evidence_schema_version: Literal["tuntun.feature-authority-campaign-evidence.v1"]
    rollover_chain_id: UUID
    rollover_chain_digest: Sha256Digest
    coverage_starts_at: AwareDatetime
    coverage_ends_at: AwareDatetime
    ordered_manifest_digests: Annotated[tuple[Sha256Digest, ...], Field(min_length=2, max_length=256)]
    ordered_transition_receipt_digests: Annotated[
        tuple[Sha256Digest, ...], Field(min_length=1, max_length=255)
    ]
    restart_activation_receipt_digests: Annotated[
        tuple[Sha256Digest, ...], Field(min_length=1, max_length=256)
    ]
    admission_sample_log_digest: Sha256Digest
    early_admission_count: Literal[0]
    expired_admission_count: Literal[0]
    uncovered_wall_or_monotonic_seconds: Literal[0]
    stale_composition_generation_count: Literal[0]
    runtime_signer_call_count: Literal[0]
    runtime_renewal_call_count: Literal[0]

    @model_validator(mode="after")
    def exact_campaign_authority_evidence(self) -> "FeatureAuthorityCampaignEvidenceV1":
        if not self.coverage_starts_at < self.coverage_ends_at:
            raise ValueError("feature_authority_campaign_coverage_invalid")
        if len(self.ordered_transition_receipt_digests) != len(self.ordered_manifest_digests) - 1:
            raise ValueError("feature_authority_transition_set_incomplete")
        if len(set(self.ordered_manifest_digests)) != len(self.ordered_manifest_digests):
            raise ValueError("feature_authority_manifest_digest_reused")
        if len(set(self.ordered_transition_receipt_digests)) != len(
            self.ordered_transition_receipt_digests
        ):
            raise ValueError("feature_authority_transition_receipt_reused")
        if len(set(self.restart_activation_receipt_digests)) != len(
            self.restart_activation_receipt_digests
        ):
            raise ValueError("feature_authority_restart_receipt_reused")
        return self

@dataclass(frozen=True, slots=True)
class FeatureAuthorityLease:
    manifest_version: int
    manifest_digest: Sha256Digest
    wall_valid_from: AwareDatetime
    wall_expires_at: AwareDatetime
    monotonic_deadline_ns: int

    def require_admission(self, *, now: AwareDatetime, monotonic_ns: int) -> None:
        if (
            now < self.wall_valid_from
            or now >= self.wall_expires_at
            or monotonic_ns >= self.monotonic_deadline_ns
        ):
            raise FeatureAbsent("feature_manifest_lease_expired")

class FeatureManifestLeaseSupervisor:
    """Shared Phase 2–6 fail-closed manifest rollover and admission authority."""

    def require_admission(self, *, authority_digest, now, monotonic_ns) -> None: ...
    async def stage_preissued(self, manifest: SignedFeatureManifestV1) -> None: ...
    async def activate_by_atomic_recomposition(self) -> None: ...

class MzhubCapabilityFindingV1(HomeContract):
    capability: Literal[
        "matter_bridge", "thread_radio", "zigbee_coordinator", "local_runtime",
        "bidirectional_state", "wan_off_runtime", "reboot_recovery",
    ]
    finding: Literal["passed", "failed", "unknown", "not_present"]
    evidence_digest: Sha256Digest

class MzhubCapabilityReportV1(HomeContract):
    report_schema_version: Literal["1.0"]
    report_id: UUID
    operational_vendor_id: Annotated[int, Field(ge=0, le=65_535)]
    operational_product_id: Annotated[int, Field(ge=0, le=65_535)]
    hardware_version: Annotated[str, Field(min_length=1, max_length=64)]
    firmware_version: Annotated[str, Field(min_length=1, max_length=64)]
    attestation_chain_digest: Sha256Digest
    certification_declaration_digest: Sha256Digest
    commissioning_path_evidence_digest: Sha256Digest
    findings: Annotated[tuple[MzhubCapabilityFindingV1, ...], Field(min_length=7, max_length=7)]
    observed_at: AwareDatetime
    report_digest: Sha256Digest

    @model_validator(mode="after")
    def complete_mzhub_findings(self) -> "MzhubCapabilityReportV1":
        expected = (
            "matter_bridge", "thread_radio", "zigbee_coordinator", "local_runtime",
            "bidirectional_state", "wan_off_runtime", "reboot_recovery",
        )
        if tuple(row.capability for row in self.findings) != expected:
            raise ValueError("mzhub_findings_must_be_complete_canonical_order")
        if self.report_digest != mzhub_report_digest(self):
            raise ValueError("mzhub_report_digest_mismatch")
        return self

def mzhub_report_digest(
    value: MzhubCapabilityReportV1 | Mapping[str, object],
) -> str:
    unsigned = (
        value.model_dump(mode="python", exclude={"report_digest"})
        if isinstance(value, MzhubCapabilityReportV1)
        else {key: item for key, item in value.items() if key != "report_digest"}
    )
    canonical = canonical_mapping_bytes(unsigned)
    return hashlib.sha256(
        b"tuntun.home.mzhub-capability-report.v1\x00" + canonical
    ).hexdigest()

class MzhubPilotCaseV1(HomeContract):
    case_id: Literal[
        "bidirectional_state", "wan_off_cold_boot", "green_restart",
        "matter_server_restart", "mzhub_restart", "router_restart",
        "aimesh_discovery", "ethernet_up_zigbee_down", "native_physical_control",
    ]
    outcome: Literal["passed", "failed"]
    evidence_digest: Sha256Digest

class MzhubOneLightPilotReceiptV1(HomeContract):
    receipt_schema_version: Literal["1.0"]
    signature_domain: Literal["tuntun.mzhub-one-light-pilot.v1"]
    pilot_id: UUID
    report_id: UUID
    report_digest: Sha256Digest
    one_light_identity_commitment: HmacCommitment
    build_digest: Sha256Digest
    configuration_digest: Sha256Digest
    cases: Annotated[tuple[MzhubPilotCaseV1, ...], Field(min_length=9, max_length=9)]
    false_success_count: Literal[0]
    wrong_target_count: Literal[0]
    started_at: AwareDatetime
    completed_at: AwareDatetime
    monotonic_clock_id: UUID
    started_monotonic_ns: Annotated[int, Field(ge=0)]
    completed_monotonic_ns: Annotated[int, Field(ge=0)]
    feature_authority: FeatureAuthorityCampaignEvidenceV1
    acceptance_signer_key_id: KeyId
    acceptance_signature: P256Signature

    @model_validator(mode="after")
    def exact_elapsed_pilot(self) -> "MzhubOneLightPilotReceiptV1":
        expected_cases = (
            "bidirectional_state", "wan_off_cold_boot", "green_restart",
            "matter_server_restart", "mzhub_restart", "router_restart",
            "aimesh_discovery", "ethernet_up_zigbee_down", "native_physical_control",
        )
        if tuple(case.case_id for case in self.cases) != expected_cases:
            raise ValueError("mzhub_pilot_cases_not_complete_canonical")
        if any(case.outcome != "passed" for case in self.cases):
            raise ValueError("mzhub_pilot_case_failed")
        if self.completed_at - self.started_at < timedelta(seconds=604_800):
            raise ValueError("mzhub_pilot_wall_elapsed_too_short")
        if self.completed_monotonic_ns - self.started_monotonic_ns < 604_800_000_000_000:
            raise ValueError("mzhub_pilot_monotonic_elapsed_too_short")
        if (
            self.feature_authority.coverage_starts_at > self.started_at
            or self.feature_authority.coverage_ends_at <= self.completed_at
        ):
            raise ValueError("mzhub_pilot_feature_authority_does_not_cover_elapsed_window")
        return self

@dataclass(frozen=True, slots=True)
class CurrentMzhubPilotAuthority:
    one_light_identity_commitment: HmacCommitment
    build_digest: Sha256Digest
    configuration_digest: Sha256Digest
    rollover_chain_id: UUID
    rollover_chain_digest: Sha256Digest

class FaultEvidenceV1(HomeContract):
    evidence_schema_version: Literal["1.0"]
    evidence_id: UUID
    fault_case_id: Annotated[str, Field(min_length=1, max_length=96, pattern=r"^[a-z0-9][a-z0-9._-]*$")]
    injected_fault_class: Literal[
        "network", "process", "device", "storage", "power", "credential",
        "generation", "ordering", "restore", "update",
    ]
    expected_terminal_state: Literal["safe", "degraded", "unavailable", "quarantined", "manual"]
    actual_terminal_state: Literal["safe", "degraded", "unavailable", "quarantined", "manual", "unsafe"]
    build_digest: Sha256Digest
    schema_digest: Sha256Digest
    policy_digest: Sha256Digest
    feature_manifest_digest: Sha256Digest
    duplicate_effect_count: Annotated[int, Field(ge=0)]
    false_success_count: Annotated[int, Field(ge=0)]
    unsafe_retry_count: Annotated[int, Field(ge=0)]
    private_finding_count: Annotated[int, Field(ge=0)]
    manual_recovery_disclosed: bool
    started_at: AwareDatetime
    completed_at: AwareDatetime
    evidence_digest: Sha256Digest

    @model_validator(mode="after")
    def coherent_fault_evidence(self) -> "FaultEvidenceV1":
        if self.completed_at < self.started_at:
            raise ValueError("fault_evidence_time_invalid")
        return self
```

`CanonicalLocationRefV1` requires `zone_id` and `zone_generation` together or neither. Registry validation resolves an active zone version whose parent matches the supplied area ID/generation and whose owning binding generation matches the operation's exact binding. A bare area reference remains valid; a bare zone, cross-area zone, stale generation, or zone used to widen an ambiguous target is invalid.

```python
# packages/contracts/src/tuntun_contracts/home/events.py
VerifierGeneration = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
EventPayloadT = TypeVar("EventPayloadT", bound=ContractModel)

class CrossDomainEventV1(ContractModel, Generic[EventPayloadT]):
    event_id: UUID
    schema_version: Literal[1]
    event_type: BoundedSafeCode
    source_endpoint_id: StableHomeId
    source_generation: Annotated[int, Field(ge=1)]
    source_sequence: Annotated[int, Field(ge=1, le=9_223_372_036_854_775_807)]
    observed_at: AwareDatetime
    ingested_at: AwareDatetime
    expires_at: AwareDatetime
    correlation_id: UUID
    causation_id: UUID | None
    deduplication_key: HmacCommitment
    sensitivity_class: Literal["household_private_metadata"]
    payload: EventPayloadT

    @model_validator(mode="after")
    def coherent_envelope(self) -> "CrossDomainEventV1[EventPayloadT]":
        if (
            self.event_type != getattr(self.payload, "schema_id", None)
            or self.event_id != getattr(self.payload, "event_id", None)
        ):
            raise ValueError("cross_domain_event_payload_binding_invalid")
        if not (
            self.observed_at <= self.ingested_at
            <= self.observed_at + timedelta(seconds=30)
        ):
            raise ValueError("cross_domain_event_ingress_window_invalid")
        if not (
            self.ingested_at < self.expires_at
            <= self.observed_at + timedelta(seconds=60)
        ):
            raise ValueError("cross_domain_event_window_invalid")
        return self

def validate_cross_domain_event_at_ingress(
    event: CrossDomainEventV1[EventPayloadT],
    *,
    now: AwareDatetime,
    maximum_receiver_clock_skew: timedelta = timedelta(seconds=2),
) -> None:
    if maximum_receiver_clock_skew != timedelta(seconds=2):
        raise ValueError("cross_domain_receiver_skew_policy_not_canonical")
    if event.ingested_at > now + maximum_receiver_clock_skew:
        raise ValueError("cross_domain_event_from_future")
    if now >= event.expires_at:
        raise ValueError("cross_domain_event_expired_at_receiver")

class StateCursorV1(HomeContract):
    cursor_schema_version: Literal["1.0"]
    controller_epoch: ControllerEpoch
    verifier_generation: VerifierGeneration
    sequence: Annotated[int, Field(ge=0, le=9_223_372_036_854_775_807)]

class HomeEndpointStateV1(HomeContract):
    event_schema_version: Literal["1.0"]
    endpoint_id: StableHomeId
    resolved_ha_entity_commitment: HmacCommitment
    topology_version: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    binding_digest: Sha256Digest
    capability_generation: Annotated[int, Field(ge=1)]
    capability_digest: Sha256Digest
    desired_state: LightDesiredStateV1 | None
    observed_state: LightDesiredStateV1 | None
    availability: Literal["available", "unavailable", "stale", "quarantined"]
    observation_source: Literal["matter_device", "zha_device", "zigbee2mqtt_device", "ha_optimistic", "none"]
    observed_at: AwareDatetime | None
    sequence: Annotated[int, Field(ge=1, le=9_223_372_036_854_775_807)]

    @model_validator(mode="after")
    def observation_is_atomic(self) -> "HomeEndpointStateV1":
        has_observation = self.observed_state is not None
        if has_observation != (self.observed_at is not None):
            raise ValueError("observed_state_and_time_required_together")
        if has_observation != (self.observation_source != "none"):
            raise ValueError("observation_source_must_match_observation")
        return self

class HomeBoundaryHealthV1(HomeContract):
    health_schema_version: Literal["1.0"]
    component: Literal["home_assistant_core", "zigbee_path"]
    state: Literal["healthy", "degraded", "unavailable", "quarantined"]
    generation: Annotated[int, Field(ge=1)]
    observed_at: AwareDatetime

class HAReadinessObservationV1(HomeContract):
    readiness_schema_version: Literal["tuntun.ha-readiness-observation.v1"]
    controller_epoch: ControllerEpoch
    verifier_generation: VerifierGeneration
    integration_package_digest: Sha256Digest
    ha_core_build_digest: Sha256Digest
    integration_configuration_digest: Sha256Digest
    restore_quarantine_required: bool
    mutation_gate_state: Literal["ready", "quarantined"]
    request_nonce: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    readiness_sequence: Annotated[int, Field(ge=1, le=9_223_372_036_854_775_807)]
    observed_at: AwareDatetime
    expires_at: AwareDatetime
    ha_admin_confirmation_generation: Annotated[int, Field(ge=1)] | None = None
    ha_admin_confirmation_challenge_digest: Sha256Digest | None = None
    ha_admin_confirmation_expires_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def exact_channel_readiness(self) -> "HAReadinessObservationV1":
        if not self.observed_at < self.expires_at <= self.observed_at + timedelta(seconds=60):
            raise ValueError("ha_readiness_window_invalid")
        if self.restore_quarantine_required != (self.mutation_gate_state == "quarantined"):
            raise ValueError("ha_readiness_marker_state_mismatch")
        confirmation = (
            self.ha_admin_confirmation_generation,
            self.ha_admin_confirmation_challenge_digest,
            self.ha_admin_confirmation_expires_at,
        )
        if any(value is not None for value in confirmation) != all(
            value is not None for value in confirmation
        ):
            raise ValueError("ha_admin_confirmation_fields_must_be_atomic")
        if (
            self.ha_admin_confirmation_expires_at is not None
            and not self.observed_at < self.ha_admin_confirmation_expires_at
            <= self.observed_at + timedelta(minutes=15)
        ):
            raise ValueError("ha_admin_confirmation_window_invalid")
        return self

class HomeStateSnapshotV1(HomeContract):
    state_schema_version: Literal["1.0"]
    cursor: StateCursorV1
    endpoints: Annotated[tuple[HomeEndpointStateV1, ...], Field(max_length=12)]
    health: Annotated[tuple[HomeBoundaryHealthV1, ...], Field(min_length=2, max_length=2)]
    readiness: HAReadinessObservationV1
    heartbeat_at: AwareDatetime

    @model_validator(mode="after")
    def snapshot_is_canonical_and_coherent(self) -> "HomeStateSnapshotV1":
        endpoint_ids = tuple(row.endpoint_id for row in self.endpoints)
        if endpoint_ids != tuple(sorted(endpoint_ids)) or len(set(endpoint_ids)) != len(endpoint_ids):
            raise ValueError("snapshot_endpoints_must_be_unique_canonical_order")
        if any(row.sequence > self.cursor.sequence for row in self.endpoints):
            raise ValueError("endpoint_sequence_after_cursor")
        if tuple(row.component for row in self.health) != ("home_assistant_core", "zigbee_path"):
            raise ValueError("health_components_must_be_complete_canonical_order")
        if (
            self.readiness.controller_epoch != self.cursor.controller_epoch
            or self.readiness.verifier_generation != self.cursor.verifier_generation
            or self.readiness.readiness_sequence > self.cursor.sequence
            or not self.readiness.observed_at <= self.heartbeat_at < self.readiness.expires_at
        ):
            raise ValueError("snapshot_readiness_stream_or_window_mismatch")
        timestamps = [row.observed_at for row in self.endpoints if row.observed_at is not None]
        timestamps.extend(row.observed_at for row in self.health)
        if any(value > self.heartbeat_at for value in timestamps):
            raise ValueError("projection_timestamp_after_heartbeat")
        return self

class HomeStateDeltaV1(HomeContract):
    state_schema_version: Literal["1.0"]
    from_cursor: StateCursorV1
    cursor: StateCursorV1
    changes: Annotated[tuple[HomeEndpointStateV1, ...], Field(max_length=12)]
    health: Annotated[tuple[HomeBoundaryHealthV1, ...], Field(min_length=2, max_length=2)]
    readiness: HAReadinessObservationV1
    heartbeat_at: AwareDatetime

    @model_validator(mode="after")
    def delta_advances_one_stream(self) -> "HomeStateDeltaV1":
        if (
            self.from_cursor.controller_epoch != self.cursor.controller_epoch
            or self.from_cursor.verifier_generation != self.cursor.verifier_generation
        ):
            raise ValueError("delta_cursor_stream_mismatch")
        if self.cursor.sequence <= self.from_cursor.sequence:
            raise ValueError("delta_cursor_must_advance")
        sequences = tuple(row.sequence for row in self.changes)
        endpoint_ids = tuple(row.endpoint_id for row in self.changes)
        if sequences != tuple(sorted(sequences)) or len(set(sequences)) != len(sequences):
            raise ValueError("delta_changes_must_follow_event_order")
        if len(set(endpoint_ids)) != len(endpoint_ids):
            raise ValueError("delta_contains_duplicate_endpoint")
        if any(not self.from_cursor.sequence < value <= self.cursor.sequence for value in sequences):
            raise ValueError("delta_change_outside_cursor_interval")
        if tuple(row.component for row in self.health) != ("home_assistant_core", "zigbee_path"):
            raise ValueError("health_components_must_be_complete_canonical_order")
        if (
            self.readiness.controller_epoch != self.cursor.controller_epoch
            or self.readiness.verifier_generation != self.cursor.verifier_generation
            or not self.from_cursor.sequence < self.readiness.readiness_sequence <= self.cursor.sequence
            or not self.readiness.observed_at <= self.heartbeat_at < self.readiness.expires_at
        ):
            raise ValueError("delta_readiness_stream_or_window_mismatch")
        timestamps = [row.observed_at for row in self.changes if row.observed_at is not None]
        timestamps.extend(row.observed_at for row in self.health)
        if any(value > self.heartbeat_at for value in timestamps):
            raise ValueError("projection_timestamp_after_heartbeat")
        return self
```

`StateCursorV1.sequence` is monotonic only inside the exact `(controller_epoch, verifier_generation)` stream. A missing or foreign stream cursor never produces a reset-flavoured delta: the route returns a fresh `HomeStateSnapshotV1`. Snapshot rows are unique and ordered by `endpoint_id`; delta rows contain only the latest change for each endpoint and are ordered by their global sequence. `HAReadinessObservationV1` is not HA-signed: pinned TLS authenticates the server, the authenticated request body commits the single-use `request_nonce`, and the response must echo that nonce inside the same bounded exchange. The Mac accepts only the outstanding nonce and a strictly advancing readiness sequence, rejects substitutions or replay before persistence, and writes a keyed local mirror containing the canonical observation digest and exact authority tuple. A mirror is evidence of the last accepted observation, never permission to reopen without a new current observation. For restore recovery, the Mac creates a random single-use challenge and displays it only in the local owner ceremony; the owner enters it in the HA integration's local admin UI. HA stores and returns only its ordinary SHA-256 digest, generation, and expiry in the channel-authenticated observation. The Mac exact-matches and consumes that digest; no HMAC or HA signing key is implied.

```python
# packages/contracts/src/tuntun_contracts/home/topology.py
class ExactTargetRequestV1(HomeContract):
    request_schema_version: Literal["1.0"]
    request_id: UUID
    intent_type: Literal["light.set_power.v1", "light.set_brightness.v1"]
    normalized_alias: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[^\x00-\x1f\x7f]+$")]
    desired_state: LightDesiredStateV1
    location: CanonicalLocationRefV1 | None
    visible_endpoint_ids: Annotated[tuple[StableHomeId, ...], Field(max_length=12)]
    topology_version: Annotated[int, Field(ge=1)]
    policy_version: PolicyVersion
    requested_at: AwareDatetime

    @model_validator(mode="after")
    def exact_request_is_closed_and_canonical(self) -> "ExactTargetRequestV1":
        if self.intent_type == "light.set_power.v1" and self.desired_state.brightness_percent is not None:
            raise ValueError("power_request_cannot_carry_brightness")
        if self.intent_type == "light.set_brightness.v1" and (
            self.desired_state.on is not True or self.desired_state.brightness_percent is None
        ):
            raise ValueError("brightness_request_requires_on_and_brightness")
        if self.visible_endpoint_ids != tuple(sorted(set(self.visible_endpoint_ids))):
            raise ValueError("visible_endpoints_must_be_unique_canonical_order")
        return self

class ResolvedEndpointV1(HomeContract):
    result_schema_version: Literal["1.0"]
    result_kind: Literal["exact"]
    request_id: UUID
    endpoint_id: StableHomeId
    capability_id: StableHomeId
    location: CanonicalLocationRefV1
    topology_version: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    observation_generation: Annotated[int, Field(ge=1)]
    observed_state: LightDesiredStateV1
    observed_at: AwareDatetime
    binding: EndpointBindingV1

    @model_validator(mode="after")
    def resolved_binding_matches_endpoint(self) -> "ResolvedEndpointV1":
        if self.binding.endpoint_id != self.endpoint_id or self.binding.capability_id != self.capability_id:
            raise ValueError("resolved_binding_target_mismatch")
        if self.binding.topology_version != self.topology_version:
            raise ValueError("resolved_binding_topology_mismatch")
        return self

class AmbiguousTargetV1(HomeContract):
    result_schema_version: Literal["1.0"]
    result_kind: Literal["ambiguous"]
    request_id: UUID
    topology_version: Annotated[int, Field(ge=1)]
    candidate_count: Annotated[int, Field(ge=2, le=12)]
    reason_code: Literal["ambiguous_target"]

class NoTargetV1(HomeContract):
    result_schema_version: Literal["1.0"]
    result_kind: Literal["not_found"]
    request_id: UUID
    topology_version: Annotated[int, Field(ge=1)]
    reason_code: Literal["no_target"]

TargetResolutionV1 = Annotated[
    ResolvedEndpointV1 | AmbiguousTargetV1 | NoTargetV1,
    Field(discriminator="result_kind"),
]
```

Ambiguous and missing results disclose no candidate identifiers. Resolution accepts only the policy-filtered, canonical `visible_endpoint_ids`; an alias or optional location can narrow that set but can never widen it, and only `result_kind="exact"` may proceed to preparation.

```python
# packages/contracts/src/tuntun_contracts/home/actions.py
class LightDesiredStateV1(HomeContract):
    on: bool
    brightness_percent: Annotated[int | None, Field(ge=1, le=100)] = None

    @model_validator(mode="after")
    def off_has_no_brightness(self) -> "LightDesiredStateV1":
        if self.on is False and self.brightness_percent is not None:
            raise ValueError("off_state_cannot_carry_brightness")
        return self

class CommittedHomeActionV1(HomeContract):
    committed_schema_version: Literal["1.0"]
    action_id: UUID
    action_type: Literal["light.set_power.v1", "light.set_brightness.v1"]
    target_endpoint_id: StableHomeId
    desired_state: LightDesiredStateV1
    controller_epoch: ControllerEpoch
    topology_version: Annotated[int, Field(ge=1)]
    binding_id: UUID
    binding_generation: Annotated[int, Field(ge=1)]
    binding_digest: Sha256Digest
    resolved_ha_entity_commitment: HmacCommitment
    expected_capability_generation: Annotated[int, Field(ge=1)]
    expected_capability_digest: Sha256Digest
    policy_version: PolicyVersion
    authorization_commitment: HmacCommitment
    authorized_at: AwareDatetime
    idempotency_key: UUID
    correlation_id: UUID

    @model_validator(mode="after")
    def exact_committed_state_shape(self) -> "CommittedHomeActionV1":
        if self.action_type == "light.set_power.v1":
            if self.desired_state.brightness_percent is not None:
                raise ValueError("power_action_cannot_carry_brightness")
        elif self.desired_state.brightness_percent is None or self.desired_state.on is not True:
            raise ValueError("brightness_action_requires_on_and_brightness")
        return self

class ClosedLightActionV1(HomeContract):
    action_id: UUID
    action_schema_version: Literal["1.0"]
    signature_domain: Literal["tuntun-action-v1"]
    action_type: Literal["light.set_power.v1", "light.set_brightness.v1"]
    target_endpoint_id: StableHomeId
    desired_state: LightDesiredStateV1
    controller_epoch: ControllerEpoch
    topology_version: Annotated[int, Field(ge=1)]
    binding_id: UUID
    binding_generation: Annotated[int, Field(ge=1)]
    binding_digest: Sha256Digest
    resolved_ha_entity_commitment: HmacCommitment
    expected_capability_generation: Annotated[int, Field(ge=1)]
    expected_capability_digest: Sha256Digest
    policy_version: PolicyVersion
    authorization_commitment: HmacCommitment
    signing_key_id: KeyId
    authorized_at: AwareDatetime
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    idempotency_key: UUID
    correlation_id: UUID
    envelope_signature: P256Signature

    @model_validator(mode="after")
    def exact_action_state_shape(self) -> "ClosedLightActionV1":
        if self.action_type == "light.set_power.v1":
            if self.desired_state.brightness_percent is not None:
                raise ValueError("power_action_cannot_carry_brightness")
        elif self.desired_state.brightness_percent is None or self.desired_state.on is not True:
            raise ValueError("brightness_action_requires_on_and_brightness")
        if not self.authorized_at <= self.issued_at <= self.authorized_at + timedelta(seconds=5):
            raise ValueError("issued_at_outside_authorization_window")
        if not self.issued_at < self.expires_at <= self.authorized_at + timedelta(seconds=30):
            raise ValueError("expires_at_outside_action_window")
        return self

def closed_light_action_request_digest(action: ClosedLightActionV1) -> Sha256Digest:
    return hashlib.sha256(
        b"tuntun.home.closed-light-action-request.v1\x00" + canonical_home_bytes(action)
    ).hexdigest()

class HomeActionResultV1(HomeContract):
    result_schema_version: Literal["1.0"]
    action_id: UUID
    desired_state: LightDesiredStateV1
    terminal_state: Literal["VERIFIED", "ACCEPTED_UNVERIFIED", "FAILED", "UNKNOWN", "EXPIRED"]
    dispatch_status: Literal["not_dispatched", "dispatching", "accepted", "rejected", "possibly_in_flight"]
    dispatch_started_at: AwareDatetime | None
    ha_context_id: UUID | None
    dispatch_context_commitment: HmacCommitment | None
    observed_state: LightDesiredStateV1 | None
    observed_at: AwareDatetime | None
    observation_source: Literal["matter_device", "zha_device", "zigbee2mqtt_device", "ha_optimistic", "none"]
    verification_strength: Literal["commissioned_truthful", "integration_only", "unverified", "none"]
    terminal_reason: SafeReasonCode
    controller_epoch: ControllerEpoch
    topology_version: Annotated[int, Field(ge=1)]
    binding_id: UUID
    binding_generation: Annotated[int, Field(ge=1)]
    binding_digest: Sha256Digest
    resolved_ha_entity_commitment: HmacCommitment
    policy_version: PolicyVersion
    terminal_at: AwareDatetime

    @model_validator(mode="after")
    def terminal_dispatch_and_evidence_agree(self) -> "HomeActionResultV1":
        dispatch_fields = (
            self.dispatch_started_at,
            self.ha_context_id,
            self.dispatch_context_commitment,
        )
        has_dispatch = all(value is not None for value in dispatch_fields)
        if any(value is not None for value in dispatch_fields) != has_dispatch:
            raise ValueError("dispatch_start_context_and_commitment_required_together")
        requires_dispatch = self.dispatch_status in {"dispatching", "accepted", "possibly_in_flight"}
        if requires_dispatch != has_dispatch:
            raise ValueError("dispatch_status_and_bound_context_evidence_mismatch")
        if self.dispatch_started_at is not None and self.terminal_at < self.dispatch_started_at:
            raise ValueError("terminal_before_dispatch_start")
        has_observation = self.observed_state is not None
        if has_observation != (self.observed_at is not None):
            raise ValueError("observed_state_and_time_required_together")
        if has_observation != (self.observation_source != "none"):
            raise ValueError("observation_source_must_match_observation")
        if has_observation != (self.verification_strength != "none"):
            raise ValueError("verification_strength_must_match_observation")
        if self.observed_at is not None:
            if self.observed_at > self.terminal_at:
                raise ValueError("observation_after_terminal")
            if self.dispatch_started_at is None or self.observed_at < self.dispatch_started_at:
                raise ValueError("observation_cannot_prove_undispatched_or_prior_state")
        if self.dispatch_status == "not_dispatched" and (
            has_dispatch or has_observation
        ):
            raise ValueError("not_dispatched_cannot_have_ha_evidence")
        if self.dispatch_status == "rejected" and (has_dispatch or has_observation):
            raise ValueError("rejected_dispatch_cannot_have_ha_evidence")
        if self.terminal_state == "VERIFIED":
            if (
                self.dispatch_status != "accepted"
                or not has_observation
                or self.observed_state != self.desired_state
                or self.observation_source == "ha_optimistic"
                or self.verification_strength != "commissioned_truthful"
            ):
                raise ValueError("verified_requires_truthful_device_observation")
        elif self.terminal_state == "ACCEPTED_UNVERIFIED":
            if self.dispatch_status != "accepted" or self.verification_strength == "commissioned_truthful":
                raise ValueError("accepted_unverified_has_wrong_evidence")
        elif self.terminal_state == "UNKNOWN":
            if self.dispatch_status not in {"dispatching", "accepted", "possibly_in_flight"}:
                raise ValueError("unknown_requires_possible_dispatch")
        elif self.terminal_state == "FAILED":
            if self.dispatch_status not in {"not_dispatched", "rejected", "accepted"}:
                raise ValueError("failed_has_impossible_dispatch_status")
            if self.dispatch_status == "accepted" and not (
                has_observation
                and self.observed_state != self.desired_state
                and self.observation_source != "ha_optimistic"
                and self.verification_strength == "commissioned_truthful"
                and self.dispatch_started_at is not None
                and self.observed_at is not None
                and self.observed_at >= self.dispatch_started_at
            ):
                raise ValueError(
                    "accepted_failure_requires_fresh_truthful_post_dispatch_contradiction"
                )
        elif self.terminal_state == "EXPIRED" and self.dispatch_status != "not_dispatched":
            raise ValueError("expired_must_be_not_dispatched")
        return self

class HAReceiptV1(HomeContract):
    receipt_schema_version: Literal["1.0"]
    receipt_kind: Literal["light_action"]
    receipt_id: UUID
    action_id: UUID
    idempotency_key: UUID
    correlation_id: UUID
    request_digest: Sha256Digest
    action_type: Literal["light.set_power.v1", "light.set_brightness.v1"]
    target_endpoint_id: StableHomeId
    desired_state: LightDesiredStateV1
    receipt_state: Literal[
        "PRE_DISPATCH", "DISPATCHING", "RECONCILING",
        "VERIFIED", "ACCEPTED_UNVERIFIED", "FAILED", "UNKNOWN", "EXPIRED",
    ]
    dispatch_status: Literal["not_dispatched", "dispatching", "accepted", "rejected", "possibly_in_flight"]
    safe_code: SafeReasonCode
    controller_epoch: ControllerEpoch
    topology_version: Annotated[int, Field(ge=1)]
    binding_id: UUID
    binding_generation: Annotated[int, Field(ge=1)]
    binding_digest: Sha256Digest
    resolved_ha_entity_commitment: HmacCommitment
    expected_capability_generation: Annotated[int, Field(ge=1)]
    expected_capability_digest: Sha256Digest
    policy_version: PolicyVersion
    authorized_at: AwareDatetime
    issued_at: AwareDatetime
    pre_dispatch_at: AwareDatetime
    dispatch_started_at: AwareDatetime | None
    expires_at: AwareDatetime
    ha_context_id: UUID | None
    dispatch_context_commitment: HmacCommitment | None
    observed_state: LightDesiredStateV1 | None
    observed_at: AwareDatetime | None
    observation_source: Literal["matter_device", "zha_device", "zigbee2mqtt_device", "ha_optimistic", "none"]
    verification_strength: Literal["commissioned_truthful", "integration_only", "unverified", "none"]
    terminal_at: AwareDatetime | None

    @model_validator(mode="after")
    def receipt_lifecycle_is_coherent(self) -> "HAReceiptV1":
        terminal_states = {"VERIFIED", "ACCEPTED_UNVERIFIED", "FAILED", "UNKNOWN", "EXPIRED"}
        is_terminal = self.receipt_state in terminal_states
        if self.action_type == "light.set_power.v1" and self.desired_state.brightness_percent is not None:
            raise ValueError("power_action_cannot_carry_brightness")
        if self.action_type == "light.set_brightness.v1" and (
            self.desired_state.on is not True or self.desired_state.brightness_percent is None
        ):
            raise ValueError("brightness_action_requires_on_and_brightness")
        if is_terminal != (self.terminal_at is not None):
            raise ValueError("terminal_state_and_time_required_together")
        if not self.authorized_at <= self.issued_at <= self.authorized_at + timedelta(seconds=5):
            raise ValueError("issued_at_outside_authorization_window")
        if not self.issued_at <= self.pre_dispatch_at < self.expires_at <= self.authorized_at + timedelta(seconds=30):
            raise ValueError("pre_dispatch_or_expiry_outside_action_window")
        if self.dispatch_started_at is not None and not (
            self.pre_dispatch_at <= self.dispatch_started_at < self.expires_at
            and self.dispatch_started_at <= self.pre_dispatch_at + timedelta(seconds=2)
        ):
            raise ValueError("dispatch_started_outside_durable_admission_window")
        if self.terminal_at is not None and self.terminal_at < self.pre_dispatch_at:
            raise ValueError("terminal_before_pre_dispatch")
        if (
            self.terminal_at is not None
            and self.dispatch_started_at is not None
            and self.terminal_at < self.dispatch_started_at
        ):
            raise ValueError("terminal_before_dispatch_start")
        dispatch_fields = (
            self.dispatch_started_at,
            self.ha_context_id,
            self.dispatch_context_commitment,
        )
        has_dispatch = all(value is not None for value in dispatch_fields)
        if any(value is not None for value in dispatch_fields) != has_dispatch:
            raise ValueError("dispatch_start_context_and_commitment_required_together")
        requires_dispatch = self.dispatch_status in {"dispatching", "accepted", "possibly_in_flight"}
        if requires_dispatch != has_dispatch:
            raise ValueError("dispatch_status_and_bound_context_evidence_mismatch")
        has_observation = self.observed_state is not None
        if has_observation != (self.observed_at is not None):
            raise ValueError("observed_state_and_time_required_together")
        if has_observation != (self.observation_source != "none"):
            raise ValueError("observation_source_must_match_observation")
        if has_observation != (self.verification_strength != "none"):
            raise ValueError("verification_strength_must_match_observation")
        if self.observed_at is not None:
            if self.terminal_at is not None and self.observed_at > self.terminal_at:
                raise ValueError("observation_after_terminal")
            if self.dispatch_started_at is None or self.observed_at < self.dispatch_started_at:
                raise ValueError("observation_cannot_prove_undispatched_or_prior_state")
        if self.dispatch_status in {"not_dispatched", "rejected"} and (
            has_dispatch or has_observation
        ):
            raise ValueError("undispatched_or_rejected_receipt_cannot_have_ha_evidence")
        if self.receipt_state == "PRE_DISPATCH" and (
            self.dispatch_status != "not_dispatched"
            or self.dispatch_started_at is not None
            or self.ha_context_id is not None
        ):
            raise ValueError("pre_dispatch_cannot_claim_dispatch")
        if self.receipt_state == "DISPATCHING" and (
            self.dispatch_status != "dispatching" or self.dispatch_started_at is None
        ):
            raise ValueError("dispatching_requires_start")
        if self.receipt_state == "RECONCILING" and (
            self.dispatch_status not in {"accepted", "possibly_in_flight"}
            or self.dispatch_started_at is None
        ):
            raise ValueError("reconciling_requires_dispatch")
        if self.receipt_state == "VERIFIED" and (
            self.dispatch_status != "accepted"
            or not has_observation
            or self.observed_state != self.desired_state
            or self.observation_source == "ha_optimistic"
            or self.verification_strength != "commissioned_truthful"
        ):
            raise ValueError("verified_receipt_requires_truthful_device_observation")
        if self.receipt_state == "ACCEPTED_UNVERIFIED" and (
            self.dispatch_status != "accepted" or self.verification_strength == "commissioned_truthful"
        ):
            raise ValueError("accepted_unverified_receipt_is_contradictory")
        if self.receipt_state == "UNKNOWN" and self.dispatch_status not in {
            "dispatching", "accepted", "possibly_in_flight"
        }:
            raise ValueError("unknown_receipt_requires_possible_dispatch")
        if self.receipt_state == "FAILED" and self.dispatch_status not in {
            "not_dispatched", "rejected", "accepted"
        }:
            raise ValueError("failed_receipt_has_impossible_dispatch_status")
        if self.receipt_state == "FAILED" and self.dispatch_status == "accepted" and not (
            has_observation
            and self.observed_state != self.desired_state
            and self.observation_source != "ha_optimistic"
            and self.verification_strength == "commissioned_truthful"
            and self.dispatch_started_at is not None
            and self.observed_at is not None
            and self.observed_at >= self.dispatch_started_at
        ):
            raise ValueError(
                "accepted_failure_requires_fresh_truthful_post_dispatch_contradiction"
            )
        if self.receipt_state == "EXPIRED" and (
            self.dispatch_status != "not_dispatched"
            or has_dispatch
            or has_observation
        ):
            raise ValueError("expired_receipt_must_be_undispatched")
        if (
            self.receipt_state == "EXPIRED"
            and self.terminal_at is not None
            and self.terminal_at < self.expires_at
        ):
            raise ValueError("receipt_expired_before_deadline")
        return self

class SceneActionEntryV1(HomeContract):
    entry_schema_version: Literal["1.0"]
    ordinal: Annotated[int, Field(ge=0, le=11)]
    child_action_id: UUID
    child_idempotency_key: UUID
    request_digest: Sha256Digest
    action_type: Literal["light.set_power.v1", "light.set_brightness.v1"]
    target_endpoint_id: StableHomeId
    desired_state: LightDesiredStateV1
    binding_id: UUID
    binding_generation: Annotated[int, Field(ge=1)]
    binding_digest: Sha256Digest
    resolved_ha_entity_commitment: HmacCommitment
    expected_capability_generation: Annotated[int, Field(ge=1)]
    expected_capability_digest: Sha256Digest

    @model_validator(mode="after")
    def exact_scene_child_state(self) -> "SceneActionEntryV1":
        if self.action_type == "light.set_power.v1" and self.desired_state.brightness_percent is not None:
            raise ValueError("power_action_cannot_carry_brightness")
        if self.action_type == "light.set_brightness.v1" and (
            self.desired_state.on is not True or self.desired_state.brightness_percent is None
        ):
            raise ValueError("brightness_action_requires_on_and_brightness")
        return self

class SceneExecutionBodyV1(HomeContract):
    scene_execution_id: UUID
    scene_id: UUID
    scene_generation: Annotated[int, Field(ge=1)]
    scene_manifest_digest: Sha256Digest
    entries: Annotated[tuple[SceneActionEntryV1, ...], Field(min_length=1, max_length=12)]
    controller_epoch: ControllerEpoch
    topology_version: Annotated[int, Field(ge=1)]
    policy_version: PolicyVersion
    authorization_commitment: HmacCommitment
    authorized_at: AwareDatetime
    idempotency_key: UUID
    correlation_id: UUID

    @model_validator(mode="after")
    def scene_entries_are_bounded_and_canonical(self) -> "SceneExecutionBodyV1":
        if tuple(row.ordinal for row in self.entries) != tuple(range(len(self.entries))):
            raise ValueError("scene_ordinals_must_be_contiguous")
        endpoint_ids = tuple(row.target_endpoint_id for row in self.entries)
        if endpoint_ids != tuple(sorted(endpoint_ids)) or len(set(endpoint_ids)) != len(endpoint_ids):
            raise ValueError("scene_endpoints_must_be_unique_canonical_order")
        if len({row.child_action_id for row in self.entries}) != len(self.entries):
            raise ValueError("duplicate_scene_child_action_id")
        if len({row.child_idempotency_key for row in self.entries}) != len(self.entries):
            raise ValueError("duplicate_scene_child_idempotency_key")
        for row in self.entries:
            if row.request_digest != scene_child_request_digest(self, row):
                raise ValueError("scene_child_request_digest_mismatch")
        if self.scene_manifest_digest != scene_manifest_digest(self):
            raise ValueError("scene_manifest_digest_mismatch")
        return self

def scene_manifest_digest_from_parts(
    scene_id: UUID,
    scene_generation: int,
    entries: tuple[SceneActionEntryV1, ...],
) -> str:
    # This is the stable approved scene-definition digest. Per-execution child
    # IDs, idempotency keys, and request digests are intentionally excluded and
    # are instead bound by the signed execution envelope/request digest below.
    entry_payloads = tuple({
        "ordinal": row.ordinal,
        "action_type": row.action_type,
        "target_endpoint_id": row.target_endpoint_id,
        "desired_state": row.desired_state.model_dump(mode="python"),
    } for row in entries)
    payload = {
        "scene_id": str(scene_id),
        "scene_generation": scene_generation,
        "entries": entry_payloads,
    }
    canonical = canonical_mapping_bytes(payload)
    return hashlib.sha256(canonical).hexdigest()

def scene_manifest_digest(value: SceneExecutionBodyV1) -> str:
    return scene_manifest_digest_from_parts(value.scene_id, value.scene_generation, value.entries)

def scene_child_request_digest(
    scene: SceneExecutionBodyV1, entry: SceneActionEntryV1,
) -> Sha256Digest:
    payload = {
        "domain": "tuntun.home.scene-child-request.v1",
        "scene_execution_id": str(scene.scene_execution_id),
        "scene_id": str(scene.scene_id),
        "scene_generation": scene.scene_generation,
        "parent_idempotency_key": str(scene.idempotency_key),
        "correlation_id": str(scene.correlation_id),
        "controller_epoch": str(scene.controller_epoch),
        "topology_version": scene.topology_version,
        "policy_version": scene.policy_version,
        "authorization_commitment": scene.authorization_commitment,
        "authorized_at": scene.authorized_at,
        "entry": entry.model_dump(mode="python", exclude={"request_digest"}),
    }
    return hashlib.sha256(canonical_mapping_bytes(payload)).hexdigest()

class CommittedSceneExecutionV1(SceneExecutionBodyV1):
    committed_schema_version: Literal["1.0"]

class BoundedSceneEnvelopeV1(SceneExecutionBodyV1):
    envelope_schema_version: Literal["1.0"]
    signature_domain: Literal["tuntun-action-v1"]
    signing_key_id: KeyId
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    envelope_signature: P256Signature

    @model_validator(mode="after")
    def scene_signature_window_is_bounded(self) -> "BoundedSceneEnvelopeV1":
        if not self.authorized_at <= self.issued_at <= self.authorized_at + timedelta(seconds=5):
            raise ValueError("issued_at_outside_authorization_window")
        if not self.issued_at < self.expires_at <= self.authorized_at + timedelta(seconds=30):
            raise ValueError("expires_at_outside_scene_window")
        return self

def bounded_scene_request_digest(envelope: BoundedSceneEnvelopeV1) -> Sha256Digest:
    return hashlib.sha256(
        b"tuntun.home.bounded-scene-execution-request.v1\x00"
        + canonical_home_bytes(envelope)
    ).hexdigest()

class HASceneChildReceiptV1(HomeContract):
    child_receipt_schema_version: Literal["1.0"]
    ordinal: Annotated[int, Field(ge=0, le=11)]
    target_endpoint_id: StableHomeId
    receipt: HAReceiptV1

def derive_scene_terminal_aggregate(
    child_states: tuple[
        Literal["VERIFIED", "ACCEPTED_UNVERIFIED", "FAILED", "UNKNOWN", "EXPIRED"],
        ...,
    ],
) -> Literal["VERIFIED", "ACCEPTED_UNVERIFIED", "PARTIAL", "FAILED", "UNKNOWN", "EXPIRED"]:
    states = set(child_states)
    if states == {"VERIFIED"}:
        return "VERIFIED"
    if "VERIFIED" in states:
        # ACCEPTED_UNVERIFIED is not effect-bearing: PARTIAL needs at least one
        # genuinely VERIFIED effect plus at least one non-VERIFIED child.
        return "PARTIAL"
    if len(states) == 1:
        return child_states[0]
    if "UNKNOWN" in states or "ACCEPTED_UNVERIFIED" in states:
        return "UNKNOWN"
    # The only remaining heterogeneous terminal set is FAILED + EXPIRED: no
    # child effect was proved, and the aggregate is a truthful failure.
    return "FAILED"

class HASceneReceiptV1(HomeContract):
    receipt_schema_version: Literal["1.0"]
    receipt_kind: Literal["light_scene"]
    receipt_id: UUID
    scene_execution_id: UUID
    scene_id: UUID
    scene_generation: Annotated[int, Field(ge=1)]
    scene_manifest_digest: Sha256Digest
    scene_execution_request_digest: Sha256Digest
    idempotency_key: UUID
    correlation_id: UUID
    controller_epoch: ControllerEpoch
    topology_version: Annotated[int, Field(ge=1)]
    policy_version: PolicyVersion
    aggregate_state: Literal[
        "PRE_DISPATCH", "DISPATCHING", "RECONCILING", "VERIFIED",
        "ACCEPTED_UNVERIFIED", "PARTIAL", "FAILED", "UNKNOWN", "EXPIRED",
    ]
    safe_code: SafeReasonCode
    manifest_entries: Annotated[tuple[SceneActionEntryV1, ...], Field(min_length=1, max_length=12)]
    children: Annotated[tuple[HASceneChildReceiptV1, ...], Field(min_length=1, max_length=12)]
    authorized_at: AwareDatetime
    issued_at: AwareDatetime
    pre_dispatch_at: AwareDatetime
    expires_at: AwareDatetime
    terminal_at: AwareDatetime | None

    @model_validator(mode="after")
    def aggregate_matches_complete_children(self) -> "HASceneReceiptV1":
        terminal_states = {"VERIFIED", "ACCEPTED_UNVERIFIED", "PARTIAL", "FAILED", "UNKNOWN", "EXPIRED"}
        if (self.aggregate_state in terminal_states) != (self.terminal_at is not None):
            raise ValueError("scene_terminal_state_and_time_required_together")
        if not self.authorized_at <= self.issued_at <= self.authorized_at + timedelta(seconds=5):
            raise ValueError("scene_issued_at_outside_authorization_window")
        if not self.issued_at <= self.pre_dispatch_at < self.expires_at <= self.authorized_at + timedelta(seconds=30):
            raise ValueError("scene_pre_dispatch_or_expiry_outside_action_window")
        if self.terminal_at is not None and self.terminal_at < self.pre_dispatch_at:
            raise ValueError("scene_terminal_before_pre_dispatch")
        if tuple(row.ordinal for row in self.manifest_entries) != tuple(range(len(self.manifest_entries))):
            raise ValueError("scene_receipt_manifest_ordinals_must_be_contiguous")
        manifest_endpoint_ids = tuple(row.target_endpoint_id for row in self.manifest_entries)
        if (
            manifest_endpoint_ids != tuple(sorted(manifest_endpoint_ids))
            or len(set(manifest_endpoint_ids)) != len(manifest_endpoint_ids)
        ):
            raise ValueError("scene_receipt_manifest_must_be_unique_canonical_order")
        if self.scene_manifest_digest != scene_manifest_digest_from_parts(
            self.scene_id, self.scene_generation, self.manifest_entries
        ):
            raise ValueError("scene_receipt_manifest_digest_mismatch")
        if tuple(row.ordinal for row in self.children) != tuple(range(len(self.children))):
            raise ValueError("scene_receipt_ordinals_must_be_contiguous")
        endpoint_ids = tuple(row.target_endpoint_id for row in self.children)
        if endpoint_ids != tuple(sorted(endpoint_ids)) or len(set(endpoint_ids)) != len(endpoint_ids):
            raise ValueError("scene_receipt_targets_incomplete_or_out_of_order")
        if len({row.receipt.action_id for row in self.children}) != len(self.children):
            raise ValueError("duplicate_scene_receipt_action")
        if len(self.manifest_entries) != len(self.children):
            raise ValueError("scene_receipt_children_incomplete")
        for entry, child in zip(self.manifest_entries, self.children, strict=True):
            receipt = child.receipt
            if (
                child.ordinal != entry.ordinal
                or child.target_endpoint_id != entry.target_endpoint_id
                or receipt.action_id != entry.child_action_id
                or receipt.idempotency_key != entry.child_idempotency_key
                or receipt.request_digest != entry.request_digest
                or receipt.correlation_id != self.correlation_id
                or receipt.action_type != entry.action_type
                or receipt.target_endpoint_id != entry.target_endpoint_id
                or receipt.desired_state != entry.desired_state
                or receipt.binding_id != entry.binding_id
                or receipt.binding_generation != entry.binding_generation
                or receipt.binding_digest != entry.binding_digest
                or receipt.resolved_ha_entity_commitment != entry.resolved_ha_entity_commitment
                or receipt.expected_capability_generation != entry.expected_capability_generation
                or receipt.expected_capability_digest != entry.expected_capability_digest
                or receipt.controller_epoch != self.controller_epoch
                or receipt.topology_version != self.topology_version
                or receipt.policy_version != self.policy_version
                or receipt.authorized_at != self.authorized_at
                or receipt.issued_at != self.issued_at
                or receipt.pre_dispatch_at != self.pre_dispatch_at
                or receipt.expires_at != self.expires_at
            ):
                raise ValueError("scene_child_receipt_does_not_match_manifest")
        if self.terminal_at is None:
            child_states = tuple(row.receipt.receipt_state for row in self.children)
            if self.aggregate_state == "PRE_DISPATCH":
                if set(child_states) != {"PRE_DISPATCH"}:
                    raise ValueError("pre_dispatch_scene_has_advanced_child")
            elif self.aggregate_state == "DISPATCHING":
                if (
                    not set(child_states).issubset({"PRE_DISPATCH", "DISPATCHING"})
                    or "DISPATCHING" not in child_states
                ):
                    raise ValueError("dispatching_scene_child_lifecycle_invalid")
            elif self.aggregate_state == "RECONCILING":
                allowed = {"DISPATCHING", "RECONCILING", *terminal_states}
                if (
                    not set(child_states).issubset(allowed)
                    or not any(
                        state == "RECONCILING" or state in terminal_states
                        for state in child_states
                    )
                ):
                    raise ValueError("reconciling_scene_child_lifecycle_invalid")
            return self
        if self.aggregate_state == "EXPIRED" and self.terminal_at < self.expires_at:
            raise ValueError("scene_expired_before_deadline")
        child_terminal_times = tuple(row.receipt.terminal_at for row in self.children)
        if any(value is None for value in child_terminal_times):
            raise ValueError("terminal_scene_requires_terminal_children")
        if any(
            value is not None and value > self.terminal_at
            for value in child_terminal_times
        ):
            raise ValueError("child_terminal_after_scene")
        child_states = tuple(row.receipt.receipt_state for row in self.children)
        expected_aggregate = derive_scene_terminal_aggregate(child_states)
        if self.aggregate_state != expected_aggregate:
            raise ValueError("scene_aggregate_truth_table_mismatch")
        return self
```

```python
# packages/contracts/src/tuntun_contracts/home/routines.py
WeekdayV1 = Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
LocalTimeV1 = Annotated[str, Field(pattern=r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$")]
IanaTimezoneV1 = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^(?:UTC|[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)+)$")]
TzdataVersionV1 = Annotated[
    str,
    Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]*$"),
]
RoutineScheduleResolutionPolicyV1 = Literal["fold_first_gap_skip_no_replay.v1"]

class RoutineScheduleAuthorityV1(HomeContract):
    authority_schema_version: Literal["1.0"]
    tzdata_version: TzdataVersionV1
    tzdata_sha256: Sha256Digest
    resolution_policy: RoutineScheduleResolutionPolicyV1

class FixedTimeDayTriggerV1(HomeContract):
    variant_schema_version: Literal["1.0"]
    trigger_type: Literal["fixed_time_day.v1"]
    weekdays: Annotated[tuple[WeekdayV1, ...], Field(min_length=1, max_length=7)]
    local_time: LocalTimeV1
    timezone: IanaTimezoneV1

    @model_validator(mode="after")
    def weekdays_are_unique_canonical_order(self) -> "FixedTimeDayTriggerV1":
        order = {day: index for index, day in enumerate(("mon", "tue", "wed", "thu", "fri", "sat", "sun"))}
        if self.weekdays != tuple(sorted(set(self.weekdays), key=order.__getitem__)):
            raise ValueError("weekdays_must_be_unique_canonical_order")
        return self

class LightStateTriggerV1(HomeContract):
    variant_schema_version: Literal["1.0"]
    trigger_type: Literal["light_state.v1"]
    endpoint_id: StableHomeId
    binding_generation: Annotated[int, Field(ge=1)]
    binding_digest: Sha256Digest
    state: LightDesiredStateV1

class LightAvailabilityTriggerV1(HomeContract):
    variant_schema_version: Literal["1.0"]
    trigger_type: Literal["light_availability.v1"]
    endpoint_id: StableHomeId
    binding_generation: Annotated[int, Field(ge=1)]
    binding_digest: Sha256Digest
    availability: Literal["available", "unavailable"]

RoutineTriggerV1 = Annotated[
    FixedTimeDayTriggerV1 | LightStateTriggerV1 | LightAvailabilityTriggerV1,
    Field(discriminator="trigger_type"),
]

class ScheduledRoutineSlotV1(HomeContract):
    slot_schema_version: Literal["1.0"]
    routine_id: UUID
    activation_generation: Annotated[int, Field(ge=1)]
    manifest_digest: Sha256Digest
    timezone: IanaTimezoneV1
    local_date: date
    local_weekday: WeekdayV1
    local_time: LocalTimeV1
    fold: Literal[0]
    resolved_utc: AwareDatetime
    tzdata_version: TzdataVersionV1
    tzdata_sha256: Sha256Digest
    resolution_policy: RoutineScheduleResolutionPolicyV1
    slot_commitment: HmacCommitment

    @model_validator(mode="after")
    def canonical_scheduled_wall_slot(self) -> "ScheduledRoutineSlotV1":
        expected_weekday = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")[
            self.local_date.weekday()
        ]
        if self.local_weekday != expected_weekday:
            raise ValueError("scheduled_slot_local_weekday_mismatch")
        if self.resolved_utc.utcoffset() != timedelta(0):
            raise ValueError("scheduled_slot_resolved_time_not_utc")
        return self

def canonical_scheduled_routine_slot_unsigned_bytes(
    slot: ScheduledRoutineSlotV1,
) -> bytes:
    return canonical_mapping_bytes(
        slot.model_dump(mode="python", exclude={"slot_commitment"}),
    )

class FixedTimeDayConditionV1(HomeContract):
    variant_schema_version: Literal["1.0"]
    condition_type: Literal["fixed_time_day.v1"]
    weekdays: Annotated[tuple[WeekdayV1, ...], Field(min_length=1, max_length=7)]
    not_before_local: LocalTimeV1
    before_local: LocalTimeV1
    timezone: IanaTimezoneV1

    @model_validator(mode="after")
    def fixed_window_is_nonempty_and_canonical(self) -> "FixedTimeDayConditionV1":
        order = {day: index for index, day in enumerate(("mon", "tue", "wed", "thu", "fri", "sat", "sun"))}
        if self.weekdays != tuple(sorted(set(self.weekdays), key=order.__getitem__)):
            raise ValueError("weekdays_must_be_unique_canonical_order")
        if self.not_before_local >= self.before_local:
            raise ValueError("condition_window_must_not_wrap_midnight")
        return self

class LightStateConditionV1(HomeContract):
    variant_schema_version: Literal["1.0"]
    condition_type: Literal["light_state.v1"]
    endpoint_id: StableHomeId
    binding_generation: Annotated[int, Field(ge=1)]
    binding_digest: Sha256Digest
    state: LightDesiredStateV1

RoutineConditionV1 = Annotated[
    FixedTimeDayConditionV1 | LightStateConditionV1,
    Field(discriminator="condition_type"),
]

class RoutineLightActionV1(HomeContract):
    variant_schema_version: Literal["1.0"]
    step_type: Literal["light_action.v1"]
    action_type: Literal["light.set_power.v1", "light.set_brightness.v1"]
    target_endpoint_id: StableHomeId
    desired_state: LightDesiredStateV1
    binding_id: UUID
    binding_generation: Annotated[int, Field(ge=1)]
    binding_digest: Sha256Digest
    resolved_ha_entity_commitment: HmacCommitment
    expected_capability_generation: Annotated[int, Field(ge=1)]
    expected_capability_digest: Sha256Digest

    @model_validator(mode="after")
    def exact_routine_action_state(self) -> "RoutineLightActionV1":
        if self.action_type == "light.set_power.v1" and self.desired_state.brightness_percent is not None:
            raise ValueError("power_action_cannot_carry_brightness")
        if self.action_type == "light.set_brightness.v1" and (
            self.desired_state.on is not True or self.desired_state.brightness_percent is None
        ):
            raise ValueError("brightness_action_requires_on_and_brightness")
        return self

class RoutineDelayActionV1(HomeContract):
    variant_schema_version: Literal["1.0"]
    step_type: Literal["delay.v1"]
    delay_seconds: Annotated[int, Field(ge=1, le=300)]

RoutineActionV1 = Annotated[
    RoutineLightActionV1 | RoutineDelayActionV1,
    Field(discriminator="step_type"),
]

class RoutineManifestBodyV1(HomeContract):
    routine_id: UUID
    routine_version: Annotated[int, Field(ge=1)]
    manifest_digest: Sha256Digest
    previous_approved_digest: Sha256Digest | None
    origin: Literal["assisted", "learning_approved"]
    controller_epoch: ControllerEpoch
    topology_version: Annotated[int, Field(ge=1)]
    policy_version: PolicyVersion
    expected_activation_generation: Annotated[int, Field(ge=0)]
    next_activation_generation: Annotated[int, Field(ge=1)]
    trigger: RoutineTriggerV1
    conditions: Annotated[tuple[RoutineConditionV1, ...], Field(max_length=8)]
    schedule_authority: RoutineScheduleAuthorityV1 | None
    actions: Annotated[tuple[RoutineActionV1, ...], Field(min_length=1, max_length=24)]
    install_authorization_commitment: HmacCommitment
    authorized_at: AwareDatetime
    install_idempotency_key: UUID

    @model_validator(mode="after")
    def manifest_is_closed_bounded_and_exact_cas(self) -> "RoutineManifestBodyV1":
        if self.next_activation_generation != self.expected_activation_generation + 1:
            raise ValueError("activation_generation_must_increment_once")
        if (self.expected_activation_generation == 0) != (self.previous_approved_digest is None):
            raise ValueError("previous_digest_must_match_install_generation")
        light_actions = tuple(row for row in self.actions if isinstance(row, RoutineLightActionV1))
        if not 1 <= len(light_actions) <= 12:
            raise ValueError("routine_requires_one_to_twelve_light_actions")
        if isinstance(self.actions[0], RoutineDelayActionV1) or isinstance(self.actions[-1], RoutineDelayActionV1):
            raise ValueError("routine_cannot_start_or_end_with_delay")
        if any(
            isinstance(left, RoutineDelayActionV1) and isinstance(right, RoutineDelayActionV1)
            for left, right in zip(self.actions, self.actions[1:], strict=False)
        ):
            raise ValueError("routine_cannot_have_consecutive_delays")
        uses_wall_time = isinstance(self.trigger, FixedTimeDayTriggerV1) or any(
            isinstance(row, FixedTimeDayConditionV1) for row in self.conditions
        )
        if uses_wall_time != (self.schedule_authority is not None):
            raise ValueError("routine_schedule_authority_shape_invalid")
        condition_keys = tuple(canonical_home_bytes(row) for row in self.conditions)
        if len(set(condition_keys)) != len(condition_keys):
            raise ValueError("duplicate_routine_condition")
        trigger_endpoint = getattr(self.trigger, "endpoint_id", None)
        if trigger_endpoint is not None and any(
            row.target_endpoint_id == trigger_endpoint for row in light_actions
        ):
            raise ValueError("routine_self_trigger_edge_forbidden")
        if self.manifest_digest != routine_manifest_digest(self):
            raise ValueError("routine_manifest_digest_mismatch")
        return self

def routine_manifest_digest(value: RoutineManifestBodyV1) -> str:
    digest_fields = (
        "routine_id", "routine_version", "previous_approved_digest", "origin",
        "controller_epoch", "topology_version", "policy_version",
        "expected_activation_generation", "next_activation_generation",
        "trigger", "conditions", "schedule_authority", "actions",
    )
    payload = value.model_dump(mode="python", include=set(digest_fields))
    canonical = canonical_mapping_bytes(payload)
    return hashlib.sha256(canonical).hexdigest()

class CommittedRoutineInstallV1(RoutineManifestBodyV1):
    committed_schema_version: Literal["1.0"]

class BoundedRoutineManifestV1(RoutineManifestBodyV1):
    manifest_schema_version: Literal["1.0"]
    signature_domain: Literal["tuntun-routine-v1"]
    signing_key_id: KeyId
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    manifest_signature: P256Signature

    @model_validator(mode="after")
    def install_signature_window_is_bounded(self) -> "BoundedRoutineManifestV1":
        if not self.authorized_at <= self.issued_at <= self.authorized_at + timedelta(seconds=5):
            raise ValueError("issued_at_outside_authorization_window")
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=60):
            raise ValueError("expires_at_outside_routine_install_window")
        return self

class HARoutineInstallReceiptV1(HomeContract):
    receipt_schema_version: Literal["1.0"]
    receipt_kind: Literal["routine_install"]
    receipt_id: UUID
    routine_id: UUID
    routine_version: Annotated[int, Field(ge=1)]
    manifest_digest: Sha256Digest
    install_idempotency_key: UUID
    controller_epoch: ControllerEpoch
    expected_activation_generation: Annotated[int, Field(ge=0)]
    expected_active_manifest_digest: Sha256Digest | None
    requested_activation_generation: Annotated[int, Field(ge=1)]
    observed_preinstall_activation_generation: Annotated[int, Field(ge=0)]
    observed_preinstall_manifest_digest: Sha256Digest | None
    active_activation_generation: Annotated[int, Field(ge=0)]
    active_manifest_digest: Sha256Digest | None
    receipt_state: Literal["INSTALLED", "REJECTED"]
    safe_code: SafeReasonCode
    received_at: AwareDatetime
    terminal_at: AwareDatetime

    @model_validator(mode="after")
    def install_receipt_matches_cas_outcome(self) -> "HARoutineInstallReceiptV1":
        if self.requested_activation_generation != self.expected_activation_generation + 1:
            raise ValueError("requested_activation_generation_must_increment_once")
        if self.terminal_at < self.received_at:
            raise ValueError("routine_receipt_terminal_before_received")
        if (self.expected_activation_generation == 0) != (
            self.expected_active_manifest_digest is None
        ):
            raise ValueError("expected_routine_generation_and_digest_required_together")
        if (self.observed_preinstall_activation_generation == 0) != (
            self.observed_preinstall_manifest_digest is None
        ):
            raise ValueError("observed_routine_generation_and_digest_required_together")
        if (self.active_activation_generation == 0) != (self.active_manifest_digest is None):
            raise ValueError("active_routine_generation_and_digest_required_together")
        expected_preinstall = (
            self.expected_activation_generation,
            self.expected_active_manifest_digest,
        )
        observed_preinstall = (
            self.observed_preinstall_activation_generation,
            self.observed_preinstall_manifest_digest,
        )
        active = (self.active_activation_generation, self.active_manifest_digest)
        if self.receipt_state == "INSTALLED":
            if observed_preinstall != expected_preinstall:
                raise ValueError("installed_routine_cas_precondition_not_observed")
            if active != (self.requested_activation_generation, self.manifest_digest):
                raise ValueError("installed_routine_active_manifest_mismatch")
        else:
            if observed_preinstall == expected_preinstall:
                raise ValueError("rejected_routine_cas_precondition_matched")
            if active != observed_preinstall:
                raise ValueError("rejected_routine_changed_active_manifest")
        return self
```

The discriminators above are the complete Phase 2 routine language. Every nested variant is strict and versioned; unknown trigger/condition/step variants, caller-selected event/service/template/YAML fields, midnight-wrapping time windows, delays over 300 seconds, more than twelve light actions, and self-trigger edges fail model validation before signature verification or persistence. `routine_manifest_digest()` is recomputed over exactly the immutable authority fields listed above; authorization, transport timing, and signature fields cannot change its meaning.

```python
# packages/contracts/src/tuntun_contracts/home/screen_time.py
FailureDomainId = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")]

class TVObservationV1(HomeContract):
    observation_schema_version: Literal["1.0"]
    observation_id: UUID
    endpoint_id: StableHomeId
    endpoint_generation: Annotated[int, Field(ge=1)]
    observer_generation: Annotated[int, Field(ge=1)]
    power_state: Literal["on", "off", "unknown"]
    playback_state: Literal["playing", "paused", "stopped", "unknown"]
    application_class: Literal["educational", "other", "unknown"]
    source: Literal["fake_tv", "direct_device", "independent_sensor", "adapter_cached"]
    failure_domain_id: FailureDomainId
    truthfulness: Literal["proved", "unproved", "unavailable"]
    control_correlation_id: UUID | None
    observed_at: AwareDatetime
    valid_until: AwareDatetime

    @model_validator(mode="after")
    def observation_state_and_freshness_agree(self) -> "TVObservationV1":
        if not self.observed_at < self.valid_until <= self.observed_at + timedelta(seconds=30):
            raise ValueError("tv_observation_freshness_out_of_bounds")
        if self.power_state == "off" and self.playback_state != "stopped":
            raise ValueError("powered_off_tv_must_report_stopped")
        if self.power_state == "unknown" and self.playback_state != "unknown":
            raise ValueError("unknown_power_cannot_claim_playback")
        if self.playback_state != "playing" and self.application_class != "unknown":
            raise ValueError("application_class_requires_active_playback")
        if self.truthfulness == "unavailable" and (
            self.power_state != "unknown"
            or self.playback_state != "unknown"
            or self.application_class != "unknown"
        ):
            raise ValueError("unavailable_observer_cannot_claim_state")
        return self

class TVPowerEligibilityV1(HomeContract):
    eligibility_schema_version: Literal["1.0"]
    evidence_id: UUID
    endpoint_id: StableHomeId
    endpoint_generation: Annotated[int, Field(ge=1)]
    state: Literal[
        "UNCOMMISSIONED", "DISPLAY_ONLY_MANUAL", "OBSERVE_ONLY",
        "COOPERATIVE_ELIGIBLE", "STRICT_ELIGIBLE", "DEGRADED",
        "QUARANTINED", "RETIRED",
    ]
    standby_control_operation: Literal["tv.set_power.v1"] | None
    standby_control_generation: Annotated[int | None, Field(ge=1)]
    standby_control_failure_domain_id: FailureDomainId | None
    power_observation_dimension: Literal["power"] | None
    power_observation_generation: Annotated[int | None, Field(ge=1)]
    power_observation_failure_domain_id: FailureDomainId | None
    independence_evidence_digest: Sha256Digest | None
    capability_generation: Annotated[int, Field(ge=1)]
    qualified_at: AwareDatetime
    valid_until: AwareDatetime
    evidence_digest: Sha256Digest

    @model_validator(mode="after")
    def exact_standby_power_eligibility(self) -> "TVPowerEligibilityV1":
        control = (
            self.standby_control_operation,
            self.standby_control_generation,
            self.standby_control_failure_domain_id,
        )
        observation = (
            self.power_observation_dimension,
            self.power_observation_generation,
            self.power_observation_failure_domain_id,
        )
        has_control = all(value is not None for value in control)
        has_observation = all(value is not None for value in observation)
        if any(value is not None for value in control) != has_control:
            raise ValueError("standby_control_evidence_shape_invalid")
        if any(value is not None for value in observation) != has_observation:
            raise ValueError("power_observation_evidence_shape_invalid")
        if not self.qualified_at < self.valid_until <= self.qualified_at + timedelta(days=30):
            raise ValueError("tv_power_eligibility_window_invalid")
        if self.state == "OBSERVE_ONLY" and (has_control or not has_observation):
            raise ValueError("observe_only_power_eligibility_shape_invalid")
        eligible = self.state in {"COOPERATIVE_ELIGIBLE", "STRICT_ELIGIBLE"}
        if eligible != (has_control and has_observation):
            raise ValueError("screen_time_power_eligibility_shape_invalid")
        independent = (
            has_control
            and has_observation
            and self.standby_control_failure_domain_id != self.power_observation_failure_domain_id
            and self.independence_evidence_digest is not None
        )
        if (self.state == "STRICT_ELIGIBLE") != independent:
            raise ValueError("strict_power_eligibility_independence_invalid")
        if self.state != "STRICT_ELIGIBLE" and self.independence_evidence_digest is not None:
            raise ValueError("non_strict_power_eligibility_carries_independence")
        if self.state in {
            "UNCOMMISSIONED", "DISPLAY_ONLY_MANUAL", "DEGRADED", "QUARANTINED", "RETIRED",
        } and (has_control or has_observation):
            raise ValueError("inactive_power_eligibility_has_active_route")
        return self

class EnforcementIntentV1(HomeContract):
    intent_schema_version: Literal["1.0"]
    intent_id: UUID
    screen_time_session_id: UUID
    session_commitment: HmacCommitment
    session_state: Literal["EXPIRED"]
    child_subject_id: UUID
    child_profile_generation: Annotated[int, Field(ge=1)]
    viewer_state: Literal["authorized_child"]
    viewer_evidence_generation: Annotated[int, Field(ge=1)]
    viewer_evidence_commitment: HmacCommitment
    viewer_observed_at: AwareDatetime
    viewer_valid_until: AwareDatetime
    clock_state: Literal["reconciled"]
    monotonic_clock_id: UUID
    clock_reconciliation_generation: Annotated[int, Field(ge=1)]
    clock_checkpoint_commitment: HmacCommitment
    clock_reconciled_at: AwareDatetime
    endpoint_id: StableHomeId
    endpoint_generation: Annotated[int, Field(ge=1)]
    control_adapter_id: StableHomeId
    observation_adapter_id: StableHomeId
    controller_epoch: ControllerEpoch
    topology_generation: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    control_generation: Annotated[int, Field(ge=1)]
    observation_generation: Annotated[int, Field(ge=1)]
    authorization_generation: Annotated[int, Field(ge=1)]
    enforcement_generation: Annotated[int, Field(ge=1)]
    manual_override_generation: Annotated[int, Field(ge=0)]
    manual_override_state: Literal["clear"]
    policy_version: PolicyVersion
    mode: Literal["COOPERATIVE", "STRICT"]
    eligibility_state: Literal["COOPERATIVE_ELIGIBLE", "STRICT_ELIGIBLE"]
    power_eligibility_evidence_id: UUID
    power_eligibility_evidence_digest: Sha256Digest
    observation_strength: Literal[
        "same_adapter_observed", "out_of_band_observed", "independence_proven",
    ]
    operation: Literal["tv.set_power.v1"]
    desired_power: Literal["STANDBY"]
    attempt_kind: Literal["primary", "bounded_reenforcement"]
    attempt_number: Literal[1, 2]
    first_attempt_at: AwareDatetime | None
    previous_attempt_id: UUID | None
    reenforcement_evidence_commitment: HmacCommitment | None
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    idempotency_key: UUID
    intent_commitment: HmacCommitment

    @model_validator(mode="after")
    def exact_current_enforcement_authority(self) -> "EnforcementIntentV1":
        if not (
            self.viewer_observed_at
            < self.issued_at
            < self.viewer_valid_until
            <= self.viewer_observed_at + timedelta(seconds=30)
        ):
            raise ValueError("enforcement_viewer_evidence_not_current")
        if self.clock_reconciled_at > self.issued_at:
            raise ValueError("enforcement_clock_reconciliation_from_future")
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("enforcement_intent_window_out_of_bounds")
        strict = self.mode == "STRICT"
        if strict and self.eligibility_state != "STRICT_ELIGIBLE":
            raise ValueError("strict_enforcement_requires_strict_eligibility")
        if strict and self.observation_strength != "independence_proven":
            raise ValueError("strict_enforcement_requires_independent_observation")
        reenforcement = self.attempt_kind == "bounded_reenforcement"
        if reenforcement != (self.attempt_number == 2):
            raise ValueError("enforcement_attempt_kind_number_mismatch")
        prior_field_presence = (
            self.first_attempt_at is not None,
            self.previous_attempt_id is not None,
            self.reenforcement_evidence_commitment is not None,
        )
        if (reenforcement and not all(prior_field_presence)) or (
            not reenforcement and any(prior_field_presence)
        ):
            raise ValueError("enforcement_prior_attempt_shape_invalid")
        if reenforcement and not (
            self.first_attempt_at < self.issued_at
            <= self.first_attempt_at + timedelta(minutes=2)
        ):
            raise ValueError("enforcement_reenforcement_window_invalid")
        return self

class TVOffRequestV1(HomeContract):
    request_schema_version: Literal["1.0"]
    request_id: UUID
    session_commitment: HmacCommitment
    endpoint_id: StableHomeId
    endpoint_generation: Annotated[int, Field(ge=1)]
    control_adapter_id: StableHomeId
    controller_epoch: ControllerEpoch
    topology_generation: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    control_generation: Annotated[int, Field(ge=1)]
    policy_version: PolicyVersion
    mode: Literal["COOPERATIVE", "STRICT"]
    operation: Literal["tv.set_power.v1"]
    desired_power: Literal["STANDBY"]
    attempt_kind: Literal["primary", "bounded_reenforcement"]
    attempt_number: Annotated[int, Field(ge=1, le=2)]
    requested_at: AwareDatetime
    expires_at: AwareDatetime
    idempotency_key: UUID
    correlation_id: UUID
    request_commitment: HmacCommitment

    @model_validator(mode="after")
    def request_is_one_of_two_bounded_attempts(self) -> "TVOffRequestV1":
        expected_number = 1 if self.attempt_kind == "primary" else 2
        if self.attempt_number != expected_number:
            raise ValueError("tv_attempt_kind_number_mismatch")
        if not self.requested_at < self.expires_at <= self.requested_at + timedelta(seconds=10):
            raise ValueError("tv_control_window_out_of_bounds")
        return self

class TVDispatchProofV1(HomeContract):
    proof_schema_version: Literal["1.0"]
    request_id: UUID
    idempotency_key: UUID
    request_commitment: HmacCommitment
    session_commitment: HmacCommitment
    endpoint_id: StableHomeId
    endpoint_generation: Annotated[int, Field(ge=1)]
    control_adapter_id: StableHomeId
    controller_epoch: ControllerEpoch
    topology_generation: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    control_generation: Annotated[int, Field(ge=1)]
    operation: Literal["tv.set_power.v1"]
    desired_power: Literal["STANDBY"]
    policy_version: PolicyVersion
    mode: Literal["COOPERATIVE", "STRICT"]
    attempt_kind: Literal["primary", "bounded_reenforcement"]
    attempt_number: Literal[1, 2]
    requested_at: AwareDatetime
    expires_at: AwareDatetime
    correlation_id: UUID
    dispatch_started_at: AwareDatetime
    adapter_context_commitment: HmacCommitment
    effect_commitment: HmacCommitment

    @model_validator(mode="after")
    def dispatch_start_is_inside_signed_window(self) -> "TVDispatchProofV1":
        if not self.requested_at <= self.dispatch_started_at < self.expires_at:
            raise ValueError("tv_dispatch_started_outside_signed_window")
        return self

class TVControlReceiptV1(HomeContract):
    receipt_schema_version: Literal["1.0"]
    receipt_kind: Literal["tv_off_control"]
    receipt_id: UUID
    request_id: UUID
    idempotency_key: UUID
    request_commitment: HmacCommitment
    session_commitment: HmacCommitment
    endpoint_id: StableHomeId
    endpoint_generation: Annotated[int, Field(ge=1)]
    control_adapter_id: StableHomeId
    controller_epoch: ControllerEpoch
    topology_generation: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    control_generation: Annotated[int, Field(ge=1)]
    operation: Literal["tv.set_power.v1"]
    desired_power: Literal["STANDBY"]
    policy_version: PolicyVersion
    mode: Literal["COOPERATIVE", "STRICT"]
    attempt_kind: Literal["primary", "bounded_reenforcement"]
    attempt_number: Annotated[int, Field(ge=1, le=2)]
    correlation_id: UUID
    outcome: Literal["ACCEPTED_UNVERIFIED", "FAILED", "UNKNOWN", "EXPIRED"]
    dispatch_status: Literal["not_dispatched", "accepted", "rejected", "possibly_in_flight"]
    safe_code: SafeReasonCode
    dispatch_proof: TVDispatchProofV1 | None
    dispatch_context_commitment: HmacCommitment | None
    effect_commitment: HmacCommitment | None
    adapter_receipt_commitment: HmacCommitment | None
    requested_at: AwareDatetime
    expires_at: AwareDatetime
    received_at: AwareDatetime
    terminal_at: AwareDatetime

    @model_validator(mode="after")
    def control_receipt_never_claims_observed_success(self) -> "TVControlReceiptV1":
        expected_attempt = 1 if self.attempt_kind == "primary" else 2
        if self.attempt_number != expected_attempt:
            raise ValueError("tv_receipt_attempt_kind_number_mismatch")
        if not self.requested_at < self.expires_at <= self.requested_at + timedelta(seconds=10):
            raise ValueError("tv_control_window_out_of_bounds")
        if self.received_at < self.requested_at or self.terminal_at < self.received_at:
            raise ValueError("tv_control_receipt_time_order_invalid")
        dispatch_started = self.dispatch_status in {"accepted", "possibly_in_flight"}
        dispatch_evidence = (
            self.dispatch_proof,
            self.dispatch_context_commitment,
            self.effect_commitment,
        )
        if dispatch_started != all(value is not None for value in dispatch_evidence):
            raise ValueError("tv_dispatch_status_and_proof_mismatch")
        if any(value is not None for value in dispatch_evidence) != all(
            value is not None for value in dispatch_evidence
        ):
            raise ValueError("tv_dispatch_proof_evidence_pair_incomplete")
        if self.dispatch_proof is not None:
            proof = self.dispatch_proof
            if (
                proof.request_id != self.request_id
                or proof.idempotency_key != self.idempotency_key
                or proof.request_commitment != self.request_commitment
                or proof.session_commitment != self.session_commitment
                or proof.endpoint_id != self.endpoint_id
                or proof.endpoint_generation != self.endpoint_generation
                or proof.control_adapter_id != self.control_adapter_id
                or proof.controller_epoch != self.controller_epoch
                or proof.topology_generation != self.topology_generation
                or proof.binding_generation != self.binding_generation
                or proof.capability_generation != self.capability_generation
                or proof.control_generation != self.control_generation
                or proof.operation != self.operation
                or proof.desired_power != self.desired_power
                or proof.policy_version != self.policy_version
                or proof.mode != self.mode
                or proof.attempt_kind != self.attempt_kind
                or proof.attempt_number != self.attempt_number
                or proof.requested_at != self.requested_at
                or proof.expires_at != self.expires_at
                or proof.correlation_id != self.correlation_id
                or proof.adapter_context_commitment != self.dispatch_context_commitment
                or proof.effect_commitment != self.effect_commitment
                or not self.requested_at <= proof.dispatch_started_at < self.expires_at
                or self.received_at < proof.dispatch_started_at
                or proof.dispatch_started_at > self.terminal_at
            ):
                raise ValueError("tv_dispatch_proof_receipt_binding_invalid")
        if self.dispatch_status == "accepted" and self.adapter_receipt_commitment is None:
            raise ValueError("accepted_tv_control_requires_adapter_commitment")
        if self.dispatch_status == "possibly_in_flight" and self.adapter_receipt_commitment is not None:
            raise ValueError("possibly_in_flight_cannot_claim_adapter_receipt")
        if self.outcome == "ACCEPTED_UNVERIFIED" and self.dispatch_status != "accepted":
            raise ValueError("accepted_tv_control_requires_adapter_commitment")
        if self.outcome == "UNKNOWN" and self.dispatch_status not in {"accepted", "possibly_in_flight"}:
            raise ValueError("unknown_tv_control_requires_possible_dispatch")
        if self.outcome == "FAILED" and self.dispatch_status not in {
            "not_dispatched", "rejected", "accepted",
        }:
            raise ValueError("failed_tv_control_has_impossible_dispatch_status")
        if self.dispatch_status == "possibly_in_flight" and self.outcome != "UNKNOWN":
            raise ValueError("possibly_in_flight_tv_control_must_be_unknown")
        if self.outcome == "EXPIRED" and (
            self.dispatch_status != "not_dispatched"
            or self.dispatch_proof is not None
            or self.dispatch_context_commitment is not None
            or self.effect_commitment is not None
            or self.adapter_receipt_commitment is not None
        ):
            raise ValueError("expired_tv_control_must_be_undispatched")
        if self.outcome == "EXPIRED" and self.terminal_at < self.expires_at:
            raise ValueError("tv_control_expired_before_deadline")
        reconciliation_deadline = self.expires_at + timedelta(seconds=5)
        if self.received_at > reconciliation_deadline or self.terminal_at > reconciliation_deadline:
            raise ValueError("tv_control_receipt_after_reconciliation_deadline")
        if (
            self.dispatch_status in {"not_dispatched", "rejected"}
            and self.outcome != "EXPIRED"
            and self.terminal_at >= self.expires_at
        ):
            raise ValueError("undispatched_tv_control_at_deadline_must_be_expired")
        if self.dispatch_status in {"not_dispatched", "rejected"} and (
            self.dispatch_proof is not None
            or self.dispatch_context_commitment is not None
            or self.effect_commitment is not None
            or self.adapter_receipt_commitment is not None
        ):
            raise ValueError("undispatched_tv_control_cannot_have_dispatch_evidence")
        return self
```

The screen-time control receipt deliberately has no `VERIFIED` variant. The adapter must atomically persist `TVDispatchProofV1`—the exact request/session/idempotency commitment; request/correlation identity; attempt kind/number; request window; policy/mode; dispatch start; exact endpoint/adapter/controller/topology/binding/capability/control context; and exact `tv.set_power.v1=STANDBY` effect commitment—before device I/O. The public receipt repeats and exact-compares every proof authority/effect field, so a valid proof from another request, session, attempt, window, adapter, epoch, topology, binding, capability, control generation, policy/mode, correlation, or effect cannot be wrapped as this receipt. Dispatch admission is proved by `requested_at <= dispatch_started_at < expires_at`, not by receipt arrival time. A proof-bearing receipt may arrive at or just after expiry but no later than the fixed `expires_at + 5 seconds` reconciliation deadline; a later response is ignored and recovery remains `UNKNOWN`. `accepted` and `possibly_in_flight` require the complete proof/context/effect triple; `rejected`, `not_dispatched`, and `EXPIRED` forbid it. Any no-dispatch terminal at or after expiry must be `EXPIRED`; `possibly_in_flight` is always `UNKNOWN` and can never be collapsed into `FAILED`. An adapter acknowledgement is accepted only when its commitment is bound to the same stored proof, so a matching receipt that predates the dispatch CAS cannot be attached. Only a fresh, generation-matched `TVObservationV1` from an eligibility-approved observation path, correlated to this request and observed at or after `dispatch_started_at`, can prove off. Phase 2 registers these ports only for `FakeTV`; a household endpoint still has no `ScreenTimeControlPort` binding.

The remaining Phase 2 execution receipts do not leave an equivalent gap: each `HASceneChildReceiptV1` embeds the fully dispatch-bound `HAReceiptV1`, and `HASceneReceiptV1` exact-compares the complete child set; `HARoutineInstallReceiptV1` records the expected and atomically observed pre-install generation/digest pairs. `INSTALLED` is valid only when that compare-and-swap precondition matched and the requested generation/digest became active; `REJECTED` is valid only when the atomically observed prior pair remained active. UI operation results are projections of those authoritative receipts and cannot add dispatch evidence.

```python
# Canonical cross-phase UI Task U01 definition, reproduced here only to make the
# Phase 2 receipt projection checks explicit. Phase 2 imports these names from
# tuntun_contracts.ui and MUST NOT create, modify, or generate this module.
# packages/contracts/src/tuntun_contracts/ui.py
class OperationTargetResultV1(ContractModel):
    result_schema_version: Literal["1.0"]
    result_kind: Literal["light_v1", "player_v1", "television_v1", "display_v1", "clip_v1", "document_v1", "desktop_step_v1", "robot_v1"]
    target_id: OpaquePurposeScopedId
    outcome: Literal["verified", "accepted_unverified", "denied", "duplicate", "failed", "unknown", "expired", "cancelled"]
    dispatch_status: SafeDispatchStatus
    dispatch_started_at: AwareDatetime | None
    reason_code: SafeReasonCode
    safe_message_id: RegisteredMessageId
    observation_source: Literal["device", "home_assistant", "player_adapter", "tv_sensor", "display_agent", "media_proxy", "knowledge_store", "desktop_helper", "robot_safety", "none"]
    verification_strength: Literal["authoritative", "corroborated", "acknowledged_unverified", "none"]
    observed_state_schema_id: SchemaId | None
    observed_state_code: SafeObservedStateCode | None
    observation_relation_to_requested_effect: Literal[
        "matches", "contradicts", "not_comparable", "none",
    ]
    evidence_generation: Annotated[int, Field(ge=0)]
    observed_at: AwareDatetime | None
    terminal_at: AwareDatetime

    @model_validator(mode="after")
    def outcome_matches_evidence(self) -> "OperationTargetResultV1":
        has_observation = self.observation_source != "none"
        state_fields = (self.observed_state_schema_id, self.observed_state_code)
        if any(value is not None for value in state_fields) != all(
            value is not None for value in state_fields
        ):
            raise ValueError("observed_state_schema_and_code_required_together")
        if has_observation != all(value is not None for value in state_fields):
            raise ValueError("observed_state_requires_observation_evidence")
        if has_observation != (self.observed_at is not None):
            raise ValueError("observation_source_and_time_required_together")
        if has_observation != (self.evidence_generation >= 1):
            raise ValueError("observation_source_and_generation_required_together")
        if has_observation != (self.verification_strength != "none"):
            raise ValueError("observation_source_and_strength_required_together")
        if has_observation != (self.observation_relation_to_requested_effect != "none"):
            raise ValueError("observation_relation_must_match_observation")
        requires_dispatch_start = self.dispatch_status in {
            "dispatching", "accepted", "possibly_in_flight",
        }
        if requires_dispatch_start != (self.dispatch_started_at is not None):
            raise ValueError("dispatch_status_and_start_time_mismatch")
        if self.dispatch_started_at is not None and self.dispatch_started_at > self.terminal_at:
            raise ValueError("dispatch_start_after_terminal")
        if self.observed_at is not None and self.observed_at > self.terminal_at:
            raise ValueError("observation_after_terminal")
        if self.observed_at is not None and (
            self.dispatch_started_at is None
            or self.observed_at < self.dispatch_started_at
        ):
            raise ValueError("observation_cannot_prove_undispatched_or_prior_state")
        if self.outcome == "verified" and (
            self.dispatch_status != "accepted"
            or self.observation_source == "none"
            or self.verification_strength not in {"authoritative", "corroborated"}
            or self.observation_relation_to_requested_effect != "matches"
            or self.evidence_generation < 1
            or self.observed_at is None
        ):
            raise ValueError("verified_target_requires_adequate_evidence")
        if self.outcome == "accepted_unverified" and (
            self.dispatch_status != "accepted"
            or (
                has_observation
                and self.verification_strength != "acknowledged_unverified"
            )
        ):
            raise ValueError("accepted_unverified_target_is_contradictory")
        if self.outcome in {"denied", "cancelled", "expired"} and (
            self.dispatch_status != "not_dispatched"
            or self.observation_source != "none"
            or self.verification_strength != "none"
            or self.observed_at is not None
        ):
            raise ValueError("non_dispatched_target_cannot_have_observation")
        if self.outcome == "unknown" and self.dispatch_status not in {
            "dispatching", "accepted", "possibly_in_flight"
        }:
            raise ValueError("unknown_target_requires_possible_dispatch")
        if self.outcome == "failed" and self.dispatch_status not in {
            "not_dispatched", "rejected", "accepted"
        }:
            raise ValueError("failed_target_has_impossible_dispatch_status")
        if self.outcome == "failed" and self.dispatch_status == "accepted" and not (
            has_observation
            and self.verification_strength in {"authoritative", "corroborated"}
            and self.observation_relation_to_requested_effect == "contradicts"
            and self.dispatch_started_at is not None
            and self.observed_at is not None
            and self.observed_at >= self.dispatch_started_at
        ):
            raise ValueError(
                "accepted_failed_target_requires_post_dispatch_contradiction"
            )
        if self.outcome == "failed" and self.dispatch_status in {"not_dispatched", "rejected"} and has_observation:
            raise ValueError("undispatched_or_rejected_failure_cannot_have_observation")
        if self.outcome == "duplicate" and self.dispatch_status not in {
            "not_dispatched", "accepted", "possibly_in_flight"
        }:
            raise ValueError("duplicate_target_has_impossible_dispatch_status")
        if self.outcome == "duplicate" and self.dispatch_status == "not_dispatched" and has_observation:
            raise ValueError("undispatched_duplicate_cannot_have_observation")
        return self

class OperationResultV1(ContractModel):
    result_schema_version: Literal["1.0"]
    operation_id: UUID
    action_name: RegisteredActionName
    outcome: Literal["verified", "accepted_unverified", "partial", "denied", "duplicate", "failed", "unknown", "expired", "cancelled"]
    reason_code: SafeReasonCode
    safe_message_id: RegisteredMessageId
    target_manifest: Annotated[tuple[OpaquePurposeScopedId, ...], Field(max_length=64)]
    target_results: Annotated[tuple[OperationTargetResultV1, ...], Field(max_length=64)]
    terminal_at: AwareDatetime
    operation_generation: Annotated[int, Field(ge=1)]
    audit_receipt_id: UUID

    @model_validator(mode="after")
    def aggregate_matches_complete_ordered_targets(self) -> "OperationResultV1":
        if len(set(self.target_manifest)) != len(self.target_manifest):
            raise ValueError("duplicate_manifest_target")
        if tuple(row.target_id for row in self.target_results) != self.target_manifest:
            raise ValueError("target_rows_incomplete_or_out_of_order")
        if any(row.terminal_at > self.terminal_at for row in self.target_results):
            raise ValueError("child_terminal_after_aggregate")
        if not self.target_results:
            if self.outcome not in {"denied", "failed", "expired", "cancelled"}:
                raise ValueError("empty_result_cannot_claim_target_effect")
            return self
        child_outcomes = tuple(row.outcome for row in self.target_results)
        unique_outcomes = set(child_outcomes)
        if unique_outcomes == {"verified"}:
            expected_outcome = "verified"
        elif "verified" in unique_outcomes:
            expected_outcome = "partial"
        elif len(unique_outcomes) == 1:
            expected_outcome = child_outcomes[0]
        elif unique_outcomes & {"unknown", "accepted_unverified", "duplicate"}:
            expected_outcome = "unknown"
        else:
            expected_outcome = "failed"
        if self.outcome != expected_outcome:
            raise ValueError("operation_aggregate_truth_table_mismatch")
        if self.outcome == "verified" and any(
            row.outcome != "verified"
            or row.observation_source == "none"
            or row.verification_strength not in {"authoritative", "corroborated"}
            or row.evidence_generation < 1
            or row.observed_at is None
            for row in self.target_results
        ):
            raise ValueError("verified_aggregate_requires_verified_children")
        return self
```

`OperationResultV1.target_manifest` is the immutable ordered tuple of the same opaque target IDs committed by the prepared mutation; it is empty only for a genuinely untargeted operation that terminated as `denied`, `failed`, `expired`, or `cancelled` before any effect target existed. Empty results can never claim `verified`, `accepted_unverified`, `partial`, `duplicate`, or `unknown`. Each targeted result binds its dispatch start and a closed relation between the observed state and requested effect. An accepted dispatch can project `failed` only from an authoritative/corroborated post-dispatch observation explicitly classified `contradicts`; absent or non-authoritative contradiction maps to `accepted_unverified` or `unknown`. The aggregate validator proves complete order and the exact effect-bearing truth table: homogeneous children retain their class, `partial` requires at least one `verified` and one non-verified child, a heterogeneous set without `verified` is `unknown` when uncertainty/acceptance/duplicate remains and otherwise `failed`, and aggregate `verified` has only adequately evidenced `verified` children. Phase 2 home routes additionally require 1–12 unique `light_v1` targets and never serialize raw HA entity IDs.

```python
# packages/contracts/src/tuntun_contracts/home/ports.py
class HomeStatePort(Protocol):
    async def snapshot(self) -> HomeStateSnapshotV1: ...
    async def delta(self, cursor: StateCursorV1) -> HomeStateDeltaV1 | HomeStateSnapshotV1: ...
    async def receipt(self, action_id: UUID, idempotency_key: UUID) -> HAReceiptV1: ...

class HomeActionSignerPort(Protocol):
    async def sign_action(self, committed: CommittedHomeActionV1) -> ClosedLightActionV1: ...
    async def sign_scene(self, committed: CommittedSceneExecutionV1) -> BoundedSceneEnvelopeV1: ...
    async def sign_routine(self, committed: CommittedRoutineInstallV1) -> BoundedRoutineManifestV1: ...

class HomeActionTransportPort(Protocol):
    async def dispatch_action(self, envelope: ClosedLightActionV1) -> HAReceiptV1: ...
    async def dispatch_scene(self, envelope: BoundedSceneEnvelopeV1) -> HASceneReceiptV1: ...
    async def install_routine(self, manifest: BoundedRoutineManifestV1) -> HARoutineInstallReceiptV1: ...

class TopologyRegistryPort(Protocol):
    async def resolve_exact(self, request: ExactTargetRequestV1) -> TargetResolutionV1: ...
    async def freeze_binding(self, endpoint_id: StableHomeId, now: AwareDatetime) -> EndpointBindingV1: ...

class ScreenTimeObservationPort(Protocol):
    async def observe(self, endpoint_id: StableHomeId) -> TVObservationV1: ...

class ScreenTimeControlPort(Protocol):
    async def request_off(self, request: TVOffRequestV1) -> TVControlReceiptV1: ...
```

Every named public port parameter and return above is a frozen model or bounded scalar defined in this baseline. Protocol implementations may raise typed transport/unavailable exceptions, but ambiguity, not-found, terminal lifecycle, and install rejection are data variants shown above rather than undocumented `dict` bodies or ad hoc sentinels.

## Durable State and Migration Map

### Mac SQLCipher migrations

This is one frozen core graph, not a set of mergeable feature branches: `0009_home_topology_policy.down_revision = "0008_prepared_mutations"`, `0010_home_actions.down_revision = "0009_home_topology_policy"`, `0011_home_automation.down_revision = "0010_home_actions"`, and `0012_screen_time.down_revision = "0011_home_automation"`. The optional search feature owns `search_0001_experimental_search` in its exact independent `alembic_version_experimental_search` version table. Core upgrade/head discovery never reads that feature row as a core revision, and neither namespace parents or merges the other.

| Revision | Tables and critical invariants |
|---|---|
| `0009_home_topology_policy` | `home_areas`, `home_zones`, `home_devices`, `home_endpoints`, `home_capabilities`, `home_bindings`, `home_aliases`, `child_light_rules`, `child_light_rule_approvals`, `delegated_guardian_grants`, `designated_guest_sessions`, `scene_manifests`, `scene_manifest_entries`; sole canonical location key `area_id`; optional zone versions bind one immutable parent `area_id`, exact area generation, and exact owning binding ID/generation; no `room_id` column/table/alias/mapping; stable random IDs, one current binding per endpoint/capability, unique normalized alias per area scope, generation/digest CAS, two distinct principals for enabled child rule, no person/IP/MAC/vendor-account field |
| `0010_home_actions` | `home_actions`, `home_action_transitions`, `home_action_envelopes`, `home_action_results`, `scene_executions`, `scene_execution_children`; one immutable `AUTHORIZED_COMMITTED` payload, legal transition trigger, unique idempotency scope, one signature digest/key, one immutable terminal result/time, child rows 1–12 and exact manifest digest |
| `0011_home_automation` | `automation_domain_modes`, `routine_drafts`, `routine_manifests`, `routine_installs`, `learning_projections`, `learning_suggestions`; Manual default, passkey receipt/digest on exposure expansion, immutable approved manifest including optional exact schedule authority, projection schema excludes actor/session/profile/join key, 30-day expiry |
| `0012_screen_time` | `screen_time_policies`, `allowance_ledgers`, `screen_time_sessions`, `screen_time_checkpoints`, `screen_time_extensions`, `screen_time_overrides`, `screen_time_enforcement_intents`, `tv_capability_evidence`; daily/weekly ledgers separate, legal state transitions, immutable canonical intent bytes/commitment, unique `(screen_time_session_id, enforcement_generation, attempt_number)` with attempt constrained to 1 or 2, observer/control generations, nullable atomic dispatch-start/adapter-context/effect proof columns with an exact all-or-none state constraint, exact adapter-receipt binding, 30-day session expiry, content-minimized audit references |

`0010_home_actions` uses this Mac state machine and rejects every other transition in a database trigger:

```text
PREPARED -> AUTHORIZED_COMMITTED -> SIGNED -> DISPATCHING -> RECONCILING
RECONCILING -> VERIFIED | ACCEPTED_UNVERIFIED | FAILED | UNKNOWN | EXPIRED
AUTHORIZED_COMMITTED -> FAILED          # signing failure, no HA I/O
SIGNED -> EXPIRED                       # deadline crossed before dispatch admission
DISPATCHING -> UNKNOWN                  # potentially in flight and unreconcilable
```

`AUTHORIZED_COMMITTED` is one SQLCipher transaction that consumes the exact grant, checks current policy/topology/binding generations, inserts the home action/scene children, and appends the audit outbox. Signing and network I/O occur only after that commit and outside the writer lock.

### Green receipt-store migrations

The HA integration owns `/config/tuntun_bridge/receipts.sqlite3` and `PRAGMA user_version` migrations:

| Store version | Tables |
|---|---|
| `1` | `global_state`, `verification_keys`, `compiled_bindings`, `action_receipts`, `receipt_transitions`, `nonce_cache`, `challenge_cache` |
| `2` | `scene_receipts`, `scene_child_receipts`, endpoint/session rate buckets |
| `3` | `routine_manifests`, `routine_installs`, `routine_trigger_cursors`, `routine_schedule_skips`, `routine_occurrences`, `routine_child_receipts`, `circuit_breakers`, `backup_state`; the schedule cursor uniquely binds routine/activation/manifest plus pinned tzdata authority, durable UTC high-water, rollback-hold state, and last admitted/skipped wall-slot commitment; occurrence and skip uniqueness prevents fold/restart replay |

HA action rows use `PRE_DISPATCH -> DISPATCHING -> RECONCILING -> VERIFIED | ACCEPTED_UNVERIFIED | FAILED | UNKNOWN | EXPIRED`. The integration commits and flushes `PRE_DISPATCH` before service I/O, advances to `DISPATCHING` immediately before the compiled call, records the generated HA context, and never redispatches an uncertain `DISPATCHING` row.

## Standard Commands

```bash
make bootstrap
make format
make lint
make typecheck
make test
make test-contract
make test-security
make web-test
make web-build
make verify-private-data
uv run pytest -m "not home_hardware and not elapsed" -q
uv run pytest integrations/home-assistant/tests -q
pnpm --filter @tuntun/admin e2e -- tests/e2e/home-*.spec.ts
```

Owner-gated commands are explicit and write only to ignored `var/evidence/phase2/`:

```bash
TUNTUN_ALLOW_HOME_HARDWARE=1 uv run pytest -m "home_hardware and not elapsed" tests/hardware/home -q
TUNTUN_ALLOW_NETWORK_PROBE=1 uv run python scripts/phase2/probe_network.py --output var/evidence/phase2/network.json
TUNTUN_ALLOW_MZHUB_PROBE=1 uv run python scripts/phase2/probe_mzhub.py --output var/evidence/phase2/mzhub.json
TUNTUN_ALLOW_UPS_TEST=1 uv run python scripts/phase2/qualify_ups.py --output var/evidence/phase2/ups.json
# Elapsed campaigns have no standalone shortcut; use the full Task 15 or Task 34 ceremony.
```

The two explicitly elapsed multi-day Phase 2 campaigns are Task 15's seven-day one-light pilot and Task 34's seven-day household soak; their task-local commands are the only supported entry points because each performs the full chain ceremony, Core-stopped staging, controlled restart, live-composition check and campaign-authority evidence binding. Ten-/30-/38-/58-day retention and expiry checks use deterministic fake clocks or inspect already-aged artifacts, and the 72-hour backup posture is observed inside the Task 34 chain-bound soak rather than started as an ungoverned runner. If any nominally short hardware/restore/fault drill is intentionally extended past 24 hours, it becomes a multi-day campaign and must use the same pre-issued chain, lease checks and transition evidence before its elapsed results can count.

---

## Wave 0 — Contracts, Simulation, Persistence, and Phase 1 Amendments

### Task 01: Freeze strict Phase 2 contracts and generated schemas

**Depends on:** Phase 1 contract package accepted and cross-phase UI Task U01 accepted.
**Gate contribution:** P2-E0.
**Estimated effort:** 1 engineering person-day.

**Files:**
- Create: `packages/contracts/src/tuntun_contracts/home/__init__.py`
- Create: `packages/contracts/src/tuntun_contracts/home/base.py`
- Create: `packages/contracts/src/tuntun_contracts/home/topology.py`
- Create: `packages/contracts/src/tuntun_contracts/home/events.py`
- Create: `packages/contracts/src/tuntun_contracts/home/channel.py`
- Create: `packages/contracts/src/tuntun_contracts/home/actions.py`
- Create: `packages/contracts/src/tuntun_contracts/home/routines.py`
- Create: `packages/contracts/src/tuntun_contracts/home/screen_time.py`
- Create: `packages/contracts/src/tuntun_contracts/home/ui.py`
- Create: `packages/contracts/src/tuntun_contracts/home/ports.py`
- Create: `scripts/phase2/generate_home_schemas.py`
- Create: `schemas/home/v1/topology-v1.schema.json`
- Create: `schemas/home/v1/events-v1.schema.json`
- Create: `schemas/home/v1/channel-v1.schema.json`
- Create: `schemas/home/v1/actions-v1.schema.json`
- Create: `schemas/home/v1/routines-v1.schema.json`
- Create: `schemas/home/v1/screen-time-v1.schema.json`
- Create: `schemas/home/v1/ui-v1.schema.json`
- Create: `fixtures/synthetic/home/contracts/topology-v1.json`
- Create: `fixtures/synthetic/home/contracts/state-event-v1.json`
- Create: `fixtures/synthetic/home/contracts/state-snapshot-v1.json`
- Create: `fixtures/synthetic/home/contracts/state-delta-v1.json`
- Create: `fixtures/synthetic/home/contracts/channel-proof-v1.json`
- Create: `fixtures/synthetic/home/contracts/ha-readiness-observation-v1.json`
- Create: `fixtures/synthetic/home/contracts/light-action-v1.json`
- Create: `fixtures/synthetic/home/contracts/light-action-result-v1.json`
- Create: `fixtures/synthetic/home/contracts/ha-receipt-v1.json`
- Create: `fixtures/synthetic/home/contracts/scene-envelope-v1.json`
- Create: `fixtures/synthetic/home/contracts/routine-manifest-v1.json`
- Create: `fixtures/synthetic/home/contracts/target-resolution-v1.json`
- Create: `fixtures/synthetic/home/contracts/screen-time-v1.json`
- Create: `fixtures/synthetic/home/contracts/enforcement-intent-v1.json`
- Create: `fixtures/synthetic/home/contracts/tv-port-v1.json`
- Create: `fixtures/synthetic/home/contracts/ui-read-model-v1.json`
- Create: `fixtures/synthetic/ui/operation-result-light-v1.json`
- Test: `tests/contract/home/test_home_contracts.py`
- Test: `tests/property/home/test_contract_rejection.py`

**Interfaces:** Produces every Phase 2-owned frozen DTO and port in the contract baseline, including canonical strict opaque `ControllerEpoch = Annotated[UUID, Strict()]` owned only by `home.channel`, canonical `AreaV1`, `CanonicalLocationRefV1`, `TopologyBundleV1`, `MzhubCapabilityReportV1`, `MzhubOneLightPilotReceiptV1`, generic `CrossDomainEventV1`, `StateCursorV1`, `HAReadinessObservationV1`, `HomeStateSnapshotV1`, `HomeStateDeltaV1`, `CommittedHomeActionV1`, `HomeActionResultV1`, `HAReceiptV1`, `CommittedSceneExecutionV1`, `BoundedSceneEnvelopeV1`, `HASceneReceiptV1`, `RoutineScheduleAuthorityV1`, `ScheduledRoutineSlotV1`, `CommittedRoutineInstallV1`, `BoundedRoutineManifestV1`, `HARoutineInstallReceiptV1`, `ExactTargetRequestV1`, the closed `TargetResolutionV1` variants, `TVObservationV1`, `TVPowerEligibilityV1`, canonical `EnforcementIntentV1`, `TVOffRequestV1`, `TVDispatchProofV1`, and `TVControlReceiptV1`; `topology_bundle_digest_from_parts(...) -> str`; `topology_bundle_digest(bundle: TopologyBundleV1) -> str`; stable definition `scene_manifest_digest(...)`; exact terminal derivation `derive_scene_terminal_aggregate(...)`; per-execution `closed_light_action_request_digest(...)`, `scene_child_request_digest(...)`, and `bounded_scene_request_digest(...)`; scheduled-slot canonicalizer `canonical_scheduled_routine_slot_unsigned_bytes(...)`; receiver-clock boundary `validate_cross_domain_event_at_ingress(event, now, maximum_receiver_clock_skew=2s) -> None`; `canonical_home_bytes(model: HomeContract) -> bytes`; `parse_home_json(model: type[HomeModelT], raw: bytes, *, max_bytes: int = 65_536) -> HomeModelT`; and exact schema bundles/IDs `tuntun.home.topology.v1`, `tuntun.home.events.v1`, `tuntun.home.channel.v1`, `tuntun.home.actions.v1`, `tuntun.home.routines.v1`, `tuntun.home.screen-time.v1`, and `tuntun.home.ui.v1`. `HAReadinessObservationV1` is a channel-authenticated response DTO, not a signed artifact: it binds the request nonce, exact controller epoch/verifier generation, integration package/Core build/configuration digests, quarantine marker/state, strictly monotonic readiness sequence, and a maximum 60-second observation window. It consumes the U01-owned shared `OperationTargetResultV1`, `OperationResultV1`, and `tuntun.ui.operation-result.v1` generated schema unchanged from `tuntun_contracts.ui`; Phase 2 has no write ownership over that module or shared schema. Every other Phase 2/3/4 module imports `ControllerEpoch` from `home.channel` and defines no alias. Every consumer invokes the receiver-clock boundary immediately after canonical parse/signature verification and before deduplication, persistence, projection, or dispatch; deterministic Pydantic models never consult ambient wall clock or ambient tzdata. Consumes `tuntun_contracts.base.ContractModel`, `Commitment`, the single shared `canonical_mapping_bytes` encoder, and shared safe error primitives. Every whole-model or exclusion helper uses `model_dump(mode="python")` and no Phase 2-local JCS or timestamp normalizer exists.

`AreaV1.area_id` is the only canonical household location identifier. `ZoneV1` is optional; each immutable version binds its stable `zone_id` to one `area_id`, the current area generation, and one exact owning binding ID/generation. Zone CAS may change its shape/label/binding generation only by creating the next zone generation; changing `area_id`, treating `zone_id` as an area, or accepting a `room_id` compatibility field is invalid.

`TopologyBundleV1` is a complete ordered authority snapshot, not an unordered transport wrapper. Every endpoint binding repeats the bundle's exact `topology_version`; at most one current binding may exist for each `(endpoint_id, capability_id)` pair. Areas sort by `(area_id, generation)`, zones by `(area_id, zone_id, generation)`, endpoint bindings by `(endpoint_id, capability_id, binding_id, binding_generation)`, and binding locations by `(binding_id, binding_generation)`. `bundle_digest` is recomputed as SHA-256 over the domain prefix `tuntun.home.topology-bundle.v1\0` followed by JCS-canonical bytes of the schema/version and all four complete ordered collections. Producers must compute the digest only after canonical sorting; consumers reject stale versions, duplicate authority, reordered members, and digest substitution before resolving an endpoint.

- [ ] **Step 1: Write red positive/negative contract tests**

```python
from tuntun_contracts.base import ContractParseError

def test_closed_action_canonical_round_trip(action_fixture: dict[str, object]) -> None:
    action = ClosedLightActionV1.model_validate(action_fixture)
    canonical = canonical_home_bytes(action)
    assert parse_home_json(ClosedLightActionV1, canonical) == action
    assert canonical == canonical_home_bytes(action)

def test_duplicate_json_key_is_rejected_before_model_validation() -> None:
    raw = b'{"action_schema_version":"1.0","action_schema_version":"1.0"}'
    with pytest.raises(ContractParseError, match="contract JSON ingress rejected") as raised:
        parse_home_json(ClosedLightActionV1, raw)
    assert "duplicate JSON key" in str(raised.value.__cause__)

@pytest.mark.parametrize(("raw", "reason"), [
    (b'"\xff"', "utf-8"),
    (b"[" * 33 + b"0" + b"]" * 33, "contract JSON shape limit exceeded"),
    (b"[" + b",".join((b"[]",) * 4_096) + b"]", "contract JSON shape limit exceeded"),
    (b"[" + b"0," * 16_384 + b"0]", "contract JSON shape limit exceeded"),
    (b'{"value":123456789012345678901}', "JSON integer too large"),
    (b'{"value":1e309}', "JSON decimal range exceeded"),
])
def test_home_json_rejects_shared_hostile_parser_shapes_before_model_validation(
    raw: bytes, reason: str,
) -> None:
    with pytest.raises(ContractParseError, match="contract JSON ingress rejected") as raised:
        parse_home_json(ClosedLightActionV1, raw)
    assert reason in str(raised.value.__cause__)

@pytest.mark.parametrize("raw", [b"", b" " * 65_537])
def test_home_json_rejects_invalid_size_before_model_validation(raw: bytes) -> None:
    with pytest.raises(ContractParseError, match="contract JSON size invalid"):
        parse_home_json(ClosedLightActionV1, raw)

def test_controller_epoch_has_one_strict_owner_and_canonical_json_round_trip() -> None:
    epoch = uuid4()
    adapter = TypeAdapter(ControllerEpoch)
    assert adapter.validate_python(epoch) == epoch
    assert adapter.validate_json(json.dumps(str(epoch))) == epoch
    for coerced in (str(epoch), 1, b"not-an-epoch"):
        with pytest.raises(ValidationError):
            adapter.validate_python(coerced)
    from tuntun_contracts.home import actions, events, screen_time
    assert not hasattr(actions, "ControllerEpochAlias")
    assert not hasattr(events, "ControllerEpochAlias")
    assert not hasattr(screen_time, "ControllerEpochAlias")

def test_scene_definition_digest_is_stable_but_execution_digests_are_unique(
    approved_scene_definition,
) -> None:
    first = build_signed_scene_execution(approved_scene_definition, execution_seed=1)
    second = build_signed_scene_execution(approved_scene_definition, execution_seed=2)
    assert first.scene_manifest_digest == second.scene_manifest_digest
    assert tuple(row.request_digest for row in first.entries) != tuple(
        row.request_digest for row in second.entries
    )
    assert bounded_scene_request_digest(first) != bounded_scene_request_digest(second)

@pytest.mark.parametrize(("action_type", "desired_state"), [
    ("light.set_power.v1", {"on": True, "brightness_percent": 50}),
    ("light.set_power.v1", {"on": False, "brightness_percent": 1}),
    ("light.set_brightness.v1", {"on": True, "brightness_percent": None}),
    ("light.set_brightness.v1", {"on": False, "brightness_percent": 50}),
])
def test_light_action_type_has_exactly_one_state_shape(action_fixture, action_type, desired_state) -> None:
    with pytest.raises(ValidationError):
        ClosedLightActionV1.model_validate({
            **action_fixture, "action_type": action_type, "desired_state": desired_state,
        })

@pytest.mark.parametrize("field", ["topology_version", "binding_generation"])
def test_action_and_result_generations_reject_zero(action_fixture, result_fixture, field) -> None:
    with pytest.raises(ValidationError):
        ClosedLightActionV1.model_validate({**action_fixture, field: 0})
    with pytest.raises(ValidationError):
        HomeActionResultV1.model_validate({**result_fixture, field: 0})

@pytest.mark.parametrize("mutation", [add_unknown_field, replace_with_toggle, add_wildcard])
def test_forbidden_action_shapes_fail(action_fixture, mutation) -> None:
    with pytest.raises(ValidationError):
        ClosedLightActionV1.model_validate(mutation(action_fixture))

@pytest.mark.parametrize("mutation", [inject_room_id, move_zone_to_another_area, mismatch_zone_owner_generation])
def test_zone_is_a_generation_bound_child_of_one_area(zone_fixture, mutation) -> None:
    with pytest.raises(ValidationError):
        TopologyBundleV1.model_validate(mutation(zone_fixture))

def test_topology_bundle_rejects_stale_endpoint_topology_version(topology_fixture) -> None:
    bindings = list(topology_fixture["endpoint_bindings"])
    bindings[0] = {
        **bindings[0],
        "topology_version": topology_fixture["topology_version"] + 1,
    }
    with pytest.raises(ValidationError, match="endpoint_binding_topology_version_mismatch"):
        TopologyBundleV1.model_validate({**topology_fixture, "endpoint_bindings": bindings})

def test_topology_bundle_rejects_second_current_binding_for_endpoint_capability(
    topology_fixture,
) -> None:
    first = topology_fixture["endpoint_bindings"][0]
    duplicate_authority = {**first, "binding_id": uuid4()}
    with pytest.raises(ValidationError, match="duplicate_current_endpoint_capability_binding"):
        TopologyBundleV1.model_validate({
            **topology_fixture,
            "endpoint_bindings": [*topology_fixture["endpoint_bindings"], duplicate_authority],
        })

@pytest.mark.parametrize("collection", [
    "areas", "zones", "endpoint_bindings", "binding_locations",
])
def test_topology_bundle_rejects_reordered_authority_collection(
    two_member_topology_fixture,
    collection,
) -> None:
    assert len(two_member_topology_fixture[collection]) >= 2
    with pytest.raises(ValidationError, match="not_canonical"):
        TopologyBundleV1.model_validate({
            **two_member_topology_fixture,
            collection: list(reversed(two_member_topology_fixture[collection])),
        })

def test_topology_bundle_recomputes_and_rejects_substituted_digest(topology_fixture) -> None:
    bundle = TopologyBundleV1.model_validate(topology_fixture)
    assert bundle.bundle_digest == topology_bundle_digest(bundle)
    substituted = "0" * 64 if bundle.bundle_digest != "0" * 64 else "1" * 64
    with pytest.raises(ValidationError, match="topology_bundle_digest_mismatch"):
        TopologyBundleV1.model_validate({**topology_fixture, "bundle_digest": substituted})

@pytest.mark.parametrize("partial", [
    {"zone_id": "zone_boundary_synth_01", "zone_generation": None},
    {"zone_id": None, "zone_generation": 7},
])
def test_location_ref_rejects_each_half_present_zone_pair(location_ref_fixture, partial) -> None:
    with pytest.raises(ValidationError):
        CanonicalLocationRefV1.model_validate({**location_ref_fixture, **partial})

@pytest.mark.parametrize(("model", "fixture_name", "version_field"), [
    (StateCursorV1, "cursor_fixture", "cursor_schema_version"),
    (HomeStateSnapshotV1, "snapshot_fixture", "state_schema_version"),
    (HomeStateDeltaV1, "delta_fixture", "state_schema_version"),
    (CommittedHomeActionV1, "committed_action_fixture", "committed_schema_version"),
    (HomeActionResultV1, "result_fixture", "result_schema_version"),
    (HAReceiptV1, "ha_receipt_fixture", "receipt_schema_version"),
    (CommittedSceneExecutionV1, "committed_scene_fixture", "committed_schema_version"),
    (BoundedSceneEnvelopeV1, "scene_envelope_fixture", "envelope_schema_version"),
    (HASceneReceiptV1, "scene_receipt_fixture", "receipt_schema_version"),
    (CommittedRoutineInstallV1, "committed_routine_fixture", "committed_schema_version"),
    (BoundedRoutineManifestV1, "routine_manifest_fixture", "manifest_schema_version"),
    (HARoutineInstallReceiptV1, "routine_receipt_fixture", "receipt_schema_version"),
    (ExactTargetRequestV1, "target_request_fixture", "request_schema_version"),
    (ResolvedEndpointV1, "resolved_endpoint_fixture", "result_schema_version"),
    (TVObservationV1, "tv_observation_fixture", "observation_schema_version"),
    (TVPowerEligibilityV1, "tv_power_eligibility_fixture", "eligibility_schema_version"),
    (EnforcementIntentV1, "enforcement_intent_fixture", "intent_schema_version"),
    (TVOffRequestV1, "tv_off_request_fixture", "request_schema_version"),
    (TVDispatchProofV1, "tv_dispatch_proof_fixture", "proof_schema_version"),
    (TVControlReceiptV1, "tv_control_receipt_fixture", "receipt_schema_version"),
    (OperationTargetResultV1, "operation_target_result_fixture", "result_schema_version"),
    (OperationResultV1, "operation_result_fixture", "result_schema_version"),
])
def test_public_boundary_rejects_unsupported_version(request, model, fixture_name, version_field) -> None:
    fixture = request.getfixturevalue(fixture_name)
    with pytest.raises(ValidationError):
        model.model_validate({**fixture, version_field: "2.0"})

@pytest.mark.parametrize(("model", "fixture_name", "field"), [
    (ClosedLightActionV1, "action_fixture", "expected_capability_generation"),
    (HomeEndpointStateV1, "endpoint_state_fixture", "capability_generation"),
    (HAReceiptV1, "ha_receipt_fixture", "binding_generation"),
    (SceneActionEntryV1, "scene_entry_fixture", "binding_generation"),
    (BoundedRoutineManifestV1, "routine_manifest_fixture", "next_activation_generation"),
    (ExactTargetRequestV1, "target_request_fixture", "topology_version"),
    (ResolvedEndpointV1, "resolved_endpoint_fixture", "observation_generation"),
    (TVObservationV1, "tv_observation_fixture", "observer_generation"),
    (TVPowerEligibilityV1, "tv_power_eligibility_fixture", "capability_generation"),
    (EnforcementIntentV1, "enforcement_intent_fixture", "enforcement_generation"),
    (TVOffRequestV1, "tv_off_request_fixture", "control_generation"),
    (TVDispatchProofV1, "tv_dispatch_proof_fixture", "binding_generation"),
    (TVControlReceiptV1, "tv_control_receipt_fixture", "endpoint_generation"),
    (OperationResultV1, "operation_result_fixture", "operation_generation"),
])
def test_public_generations_reject_zero(request, model, fixture_name, field) -> None:
    fixture = request.getfixturevalue(fixture_name)
    with pytest.raises(ValidationError):
        model.model_validate({**fixture, field: 0})

def test_rejected_routine_receipt_requires_a_failed_cas_precondition(
    routine_receipt_fixture,
) -> None:
    with pytest.raises(
        ValidationError, match="rejected_routine_cas_precondition_matched",
    ):
        HARoutineInstallReceiptV1.model_validate({
            **routine_receipt_fixture,
            "receipt_state": "REJECTED",
            "observed_preinstall_activation_generation": (
                routine_receipt_fixture["expected_activation_generation"]
            ),
            "observed_preinstall_manifest_digest": (
                routine_receipt_fixture["expected_active_manifest_digest"]
            ),
            "active_activation_generation": (
                routine_receipt_fixture["expected_activation_generation"]
            ),
            "active_manifest_digest": (
                routine_receipt_fixture["expected_active_manifest_digest"]
            ),
        })

@pytest.mark.parametrize("mutation", [
    {"mode": "ADVISORY"},
    {"operation": "tv.mute.v1"},
    {"desired_power": "ON"},
    {"mode": "STRICT", "eligibility_state": "COOPERATIVE_ELIGIBLE"},
    {"mode": "STRICT", "eligibility_state": "STRICT_ELIGIBLE", "observation_strength": "same_adapter_observed"},
    {"attempt_kind": "primary", "attempt_number": 1, "previous_attempt_id": uuid4()},
    {"attempt_kind": "bounded_reenforcement", "attempt_number": 2,
     "first_attempt_at": None, "previous_attempt_id": None,
     "reenforcement_evidence_commitment": None},
    {"manual_override_state": "present"},
    {"viewer_subject_id": uuid4()},
])
def test_enforcement_intent_rejects_authority_or_operation_substitution(
    enforcement_intent_fixture, mutation,
) -> None:
    with pytest.raises(ValidationError):
        EnforcementIntentV1.model_validate({**enforcement_intent_fixture, **mutation})

def test_reenforcement_intent_must_be_within_two_minutes(enforcement_intent_fixture) -> None:
    issued_at = enforcement_intent_fixture["issued_at"]
    with pytest.raises(ValidationError):
        EnforcementIntentV1.model_validate({
            **enforcement_intent_fixture,
            "attempt_kind": "bounded_reenforcement",
            "attempt_number": 2,
            "first_attempt_at": issued_at - timedelta(minutes=2, microseconds=1),
            "previous_attempt_id": uuid4(),
            "reenforcement_evidence_commitment": SYNTHETIC_COMMITMENT,
        })

@pytest.mark.parametrize("mutation", [
    {"dispatch_proof": None},
    {"dispatch_proof": {"request_id": uuid4()}},
    {"dispatch_proof": {"idempotency_key": uuid4()}},
    {"dispatch_proof": {"request_commitment": DIFFERENT_SYNTHETIC_COMMITMENT}},
    {"dispatch_proof": {"session_commitment": DIFFERENT_SYNTHETIC_COMMITMENT}},
    {"dispatch_proof": {"endpoint_id": "tv_substituted_synth_01"}},
    {"dispatch_proof": {"control_adapter_id": "tv_adapter_substituted_synth_01"}},
    {"dispatch_proof": {"controller_epoch": uuid4()}},
    {"dispatch_proof": {"topology_generation": 99}},
    {"dispatch_proof": {"binding_generation": 99}},
    {"dispatch_proof": {"capability_generation": 99}},
    {"dispatch_proof": {"control_generation": 99}},
    {"dispatch_proof": {"policy_version": 99}},
    {"dispatch_proof": {"mode": "STRICT"}},
    {"dispatch_proof": {"attempt_kind": "bounded_reenforcement"}},
    {"dispatch_proof": {"attempt_number": 2}},
    {"dispatch_proof": {"requested_at": SYNTHETIC_NOW - timedelta(seconds=1)}},
    {"dispatch_proof": {"expires_at": SYNTHETIC_NOW + timedelta(seconds=1)}},
    {"dispatch_proof": {"correlation_id": uuid4()}},
    {"dispatch_proof": {"adapter_context_commitment": DIFFERENT_SYNTHETIC_COMMITMENT}},
    {"dispatch_proof": {"effect_commitment": DIFFERENT_SYNTHETIC_COMMITMENT}},
    {"dispatch_context_commitment": DIFFERENT_SYNTHETIC_COMMITMENT},
    {"effect_commitment": DIFFERENT_SYNTHETIC_COMMITMENT},
])
def test_started_tv_receipt_requires_exact_atomic_dispatch_proof(
    tv_control_receipt_fixture, mutation,
) -> None:
    candidate = deep_merge(tv_control_receipt_fixture, mutation)
    with pytest.raises(ValidationError):
        TVControlReceiptV1.model_validate(candidate)

@pytest.mark.parametrize("mutation", [
    {"request_id": uuid4()},
    {"idempotency_key": uuid4()},
    {"request_commitment": DIFFERENT_SYNTHETIC_COMMITMENT},
    {"session_commitment": DIFFERENT_SYNTHETIC_COMMITMENT},
    {"endpoint_id": "tv_substituted_synth_01"},
    {"endpoint_generation": 99},
    {"control_adapter_id": "tv_adapter_substituted_synth_01"},
    {"controller_epoch": uuid4()},
    {"topology_generation": 99},
    {"binding_generation": 99},
    {"capability_generation": 99},
    {"control_generation": 99},
    {"policy_version": 99},
    {"mode": "STRICT"},
    {"attempt_kind": "bounded_reenforcement"},
    {"attempt_number": 2},
    {"requested_at": SYNTHETIC_NOW - timedelta(seconds=1)},
    {"expires_at": SYNTHETIC_NOW + timedelta(seconds=1)},
    {"correlation_id": uuid4()},
    {"dispatch_started_at": SYNTHETIC_NOW + timedelta(microseconds=1)},
    {"adapter_context_commitment": DIFFERENT_SYNTHETIC_COMMITMENT},
    {"effect_commitment": DIFFERENT_SYNTHETIC_COMMITMENT},
])
def test_tv_dispatch_verifier_rejects_context_or_effect_substitution_before_io(
    tv_dispatch_binding_verifier, tv_off_request, tv_dispatch_proof_fixture,
    adapter_registry, fake_tv, mutation,
) -> None:
    candidate = TVDispatchProofV1.model_validate({
        **tv_dispatch_proof_fixture, **mutation,
    })
    with pytest.raises(TVDispatchBindingError):
        tv_dispatch_binding_verifier.require_exact(tv_off_request, candidate)
    assert adapter_registry.read_count == 0
    assert fake_tv.effect_calls == ()

def test_tv_dispatch_verifier_accepts_the_exact_bound_proof_without_io(
    tv_dispatch_binding_verifier, tv_off_request, tv_dispatch_proof_fixture,
    adapter_registry, fake_tv,
) -> None:
    proof = TVDispatchProofV1.model_validate(tv_dispatch_proof_fixture)
    assert tv_dispatch_binding_verifier.require_exact(
        tv_off_request, proof,
    ) is proof
    assert adapter_registry.read_count == 0
    assert fake_tv.effect_calls == ()

@pytest.mark.parametrize("dispatch_status", ["not_dispatched", "rejected"])
def test_undispatched_or_rejected_tv_receipt_forbids_dispatch_evidence(
    tv_control_receipt_fixture, dispatch_status,
) -> None:
    with pytest.raises(ValidationError, match="undispatched|status_and_proof"):
        TVControlReceiptV1.model_validate({
            **tv_control_receipt_fixture,
            "outcome": "FAILED",
            "dispatch_status": dispatch_status,
        })

def test_preexisting_adapter_receipt_cannot_be_attached_to_new_tv_dispatch(
    tv_control_receipt_fixture,
) -> None:
    candidate = deep_merge(tv_control_receipt_fixture, {
        "dispatch_proof": {
            "dispatch_started_at": tv_control_receipt_fixture["received_at"]
            + timedelta(microseconds=1),
        },
    })
    with pytest.raises(ValidationError, match="dispatch_proof_receipt_binding_invalid"):
        TVControlReceiptV1.model_validate(candidate)

@pytest.mark.parametrize("received_delta", [timedelta(0), timedelta(microseconds=1)])
def test_tv_dispatch_admitted_before_expiry_may_arrive_at_or_just_after_expiry(
    tv_control_receipt_fixture, received_delta,
) -> None:
    expiry = tv_control_receipt_fixture["expires_at"]
    candidate = deep_merge(tv_control_receipt_fixture, {
        "dispatch_proof": {"dispatch_started_at": expiry - timedelta(microseconds=1)},
        "received_at": expiry + received_delta,
        "terminal_at": expiry + received_delta,
    })
    assert TVControlReceiptV1.model_validate(candidate).dispatch_status == "accepted"

@pytest.mark.parametrize("delta", [timedelta(0), timedelta(microseconds=1)])
def test_tv_dispatch_proof_start_must_be_strictly_before_expiry(
    tv_dispatch_proof_fixture, delta,
) -> None:
    with pytest.raises(ValidationError, match="outside_signed_window"):
        TVDispatchProofV1.model_validate({
            **tv_dispatch_proof_fixture,
            "dispatch_started_at": tv_dispatch_proof_fixture["expires_at"] + delta,
        })

def test_tv_receipt_reconciliation_deadline_and_no_dispatch_expiry_are_exact(
    tv_control_receipt_fixture,
) -> None:
    expiry = tv_control_receipt_fixture["expires_at"]
    at_deadline = deep_merge(tv_control_receipt_fixture, {
        "dispatch_proof": {"dispatch_started_at": expiry - timedelta(microseconds=1)},
        "received_at": expiry + timedelta(seconds=5),
        "terminal_at": expiry + timedelta(seconds=5),
    })
    TVControlReceiptV1.model_validate(at_deadline)
    with pytest.raises(ValidationError, match="reconciliation_deadline"):
        TVControlReceiptV1.model_validate({
            **at_deadline,
            "received_at": expiry + timedelta(seconds=5, microseconds=1),
            "terminal_at": expiry + timedelta(seconds=5, microseconds=1),
        })
    with pytest.raises(ValidationError, match="must_be_expired"):
        TVControlReceiptV1.model_validate(no_dispatch_tv_receipt(
            tv_control_receipt_fixture,
            outcome="FAILED",
            terminal_at=expiry,
            received_at=expiry,
        ))
    expired = no_dispatch_tv_receipt(
        tv_control_receipt_fixture,
        outcome="EXPIRED",
        terminal_at=expiry,
        received_at=expiry,
    )
    assert TVControlReceiptV1.model_validate(expired).outcome == "EXPIRED"

async def test_late_tv_receipt_restart_never_redispatches(
    tv_control_receipt_fixture, screen_time_runtime,
) -> None:
    expiry = tv_control_receipt_fixture["expires_at"]
    receipt = deep_merge(tv_control_receipt_fixture, {
        "dispatch_proof": {"dispatch_started_at": expiry - timedelta(microseconds=1)},
        "received_at": expiry + timedelta(microseconds=1),
        "terminal_at": expiry + timedelta(microseconds=1),
    })
    await screen_time_runtime.accept_control_receipt(receipt)
    restarted = await screen_time_runtime.restart()
    assert await restarted.control_receipt(receipt["request_id"]) == receipt
    assert restarted.new_effect_calls == ()

def test_delta_rejects_foreign_or_nonadvancing_cursor(delta_fixture) -> None:
    foreign = deep_merge(delta_fixture, {"cursor": {"verifier_generation": "b" * 64}})
    nonadvancing = deep_merge(delta_fixture, {"cursor": delta_fixture["from_cursor"]})
    outside_interval = deep_merge(delta_fixture, {
        "changes": [{**delta_fixture["changes"][0], "sequence": delta_fixture["from_cursor"]["sequence"]}],
    })
    for candidate in (foreign, nonadvancing, outside_interval):
        with pytest.raises(ValidationError):
            HomeStateDeltaV1.model_validate(candidate)

@pytest.mark.parametrize("mutation", [
    {"mutation_gate_state": "ready", "restore_quarantine_required": True},
    {"expires_at": SYNTHETIC_NOW + timedelta(seconds=60, microseconds=1)},
    {"request_nonce": "not-a-256-bit-nonce"},
    {"ha_admin_confirmation_generation": 2},
])
def test_ha_readiness_observation_is_closed_and_coherent(
    ha_readiness_observation_fixture, mutation,
) -> None:
    with pytest.raises(ValidationError):
        HAReadinessObservationV1.model_validate({
            **ha_readiness_observation_fixture,
            **mutation,
        })

@pytest.mark.parametrize(("issued_seconds", "expires_seconds"), [
    (-0.000001, 10), (5.000001, 10), (0, 0), (0, 30.000001),
])
def test_action_and_scene_reject_time_outside_frozen_window(
    action_fixture, scene_envelope_fixture, issued_seconds, expires_seconds,
) -> None:
    authorized_at = datetime.fromisoformat(action_fixture["authorized_at"])
    timing = {
        "issued_at": authorized_at + timedelta(seconds=issued_seconds),
        "expires_at": authorized_at + timedelta(seconds=expires_seconds),
    }
    with pytest.raises(ValidationError):
        ClosedLightActionV1.model_validate({**action_fixture, **timing})
    with pytest.raises(ValidationError):
        BoundedSceneEnvelopeV1.model_validate({**scene_envelope_fixture, **timing})

@pytest.mark.parametrize("mutation", [
    {"terminal_state": "VERIFIED", "dispatch_status": "accepted", "observed_state": None,
     "observed_at": None, "observation_source": "none", "verification_strength": "none"},
    {"terminal_state": "VERIFIED", "dispatch_status": "accepted",
     "observation_source": "ha_optimistic", "verification_strength": "commissioned_truthful"},
    {"terminal_state": "VERIFIED", "dispatch_status": "accepted",
     "desired_state": {"on": True, "brightness_percent": None},
     "observed_state": {"on": False, "brightness_percent": None}},
    {"terminal_state": "ACCEPTED_UNVERIFIED", "dispatch_status": "not_dispatched"},
    {"terminal_state": "UNKNOWN", "dispatch_status": "not_dispatched"},
    {"terminal_state": "EXPIRED", "dispatch_status": "accepted"},
])
def test_home_result_rejects_contradictory_terminal_claim(result_fixture, mutation) -> None:
    with pytest.raises(ValidationError):
        HomeActionResultV1.model_validate({**result_fixture, **mutation})

@pytest.mark.parametrize("mutation", [
    {"dispatch_started_at": None},
    {"ha_context_id": None},
    {"dispatch_context_commitment": None},
])
def test_dispatched_result_requires_atomic_start_context_and_effect_commitment(
    result_fixture, mutation,
) -> None:
    with pytest.raises(ValidationError):
        HomeActionResultV1.model_validate({**result_fixture, **mutation})

def test_preexisting_matching_observation_cannot_prove_this_dispatch(result_fixture) -> None:
    with pytest.raises(ValidationError, match="observation_cannot_prove"):
        HomeActionResultV1.model_validate({
            **result_fixture,
            "observed_at": result_fixture["dispatch_started_at"] - timedelta(microseconds=1),
        })

def test_home_result_and_receipt_terminal_time_cannot_precede_dispatch_start(
    result_fixture, ha_receipt_fixture,
) -> None:
    for model, payload in (
        (HomeActionResultV1, result_fixture),
        (HAReceiptV1, ha_receipt_fixture),
    ):
        with pytest.raises(ValidationError, match="terminal_before_dispatch_start"):
            model.model_validate({
                **payload,
                "terminal_at": payload["dispatch_started_at"] - timedelta(microseconds=1),
            })

@pytest.mark.parametrize(("model", "fixture_name", "state_field"), [
    (HAReceiptV1, "ha_receipt_fixture", "receipt_state"),
    (HomeActionResultV1, "result_fixture", "terminal_state"),
])
@pytest.mark.parametrize("evidence_mutation", [
    remove_observation_tuple,
    make_observation_match_desired_state,
    make_observation_optimistic,
    make_observation_integration_only,
    move_observation_before_dispatch,
])
def test_accepted_failure_requires_fresh_truthful_post_dispatch_contradiction(
    request, model, fixture_name, state_field, evidence_mutation,
) -> None:
    payload = accepted_failed_payload(
        request.getfixturevalue(fixture_name), state_field=state_field,
    )
    with pytest.raises(ValidationError, match="failure.*contradict|observation.*dispatch"):
        model.model_validate(evidence_mutation(payload))

@pytest.mark.parametrize(("model", "fixture_name", "state_field"), [
    (HAReceiptV1, "ha_receipt_fixture", "receipt_state"),
    (HomeActionResultV1, "result_fixture", "terminal_state"),
])
def test_accepted_failure_accepts_exact_fresh_commissioned_mismatch(
    request, model, fixture_name, state_field,
) -> None:
    payload = accepted_failed_payload(
        request.getfixturevalue(fixture_name),
        state_field=state_field,
        observed_state=DIFFERENT_VALID_LIGHT_STATE,
        observed_at_field="dispatch_started_at",
        observation_source="matter_device",
        verification_strength="commissioned_truthful",
    )
    assert getattr(model.model_validate(payload), state_field) == "FAILED"

@pytest.mark.parametrize("terminal_state", ["ACCEPTED_UNVERIFIED", "UNKNOWN"])
def test_accepted_without_truthful_contradiction_uses_nonfailure_class(
    result_fixture, terminal_state,
) -> None:
    candidate = accepted_result_without_commissioned_observation(
        result_fixture, terminal_state=terminal_state,
    )
    assert HomeActionResultV1.model_validate(candidate).terminal_state == terminal_state

@pytest.mark.parametrize("mutation", [
    pre_dispatch_with_dispatch_time,
    terminal_without_terminal_at,
    verified_without_truthful_observation,
    verified_with_wrong_observed_state,
    expired_with_ha_context,
    dispatch_more_than_two_seconds_after_pre_dispatch,
])
def test_ha_receipt_rejects_impossible_lifecycle(ha_receipt_fixture, mutation) -> None:
    with pytest.raises(ValidationError):
        HAReceiptV1.model_validate(mutation(ha_receipt_fixture))

def test_cross_domain_event_rejects_type_id_and_expiry(home_event_fixture) -> None:
    class SyntheticHomeEventPayloadV1(ContractModel):
        schema_id: Literal["home.synthetic.v1"]
        event_id: UUID

    event_model = CrossDomainEventV1[SyntheticHomeEventPayloadV1]
    event = event_model.model_validate(home_event_fixture)
    for mutation in (
        {"event_type": "camera.security_event.v1"},
        {"event_id": uuid4()},
        {"expires_at": event.observed_at + timedelta(seconds=60, microseconds=1)},
    ):
        with pytest.raises(ValidationError):
            event_model.model_validate({**home_event_fixture, **mutation})

def test_cross_domain_event_ingest_delay_is_bounded_once_in_canonical_contract(
    home_event_fixture,
) -> None:
    class SyntheticHomeEventPayloadV1(ContractModel):
        schema_id: Literal["home.synthetic.v1"]
        event_id: UUID

    event_model = CrossDomainEventV1[SyntheticHomeEventPayloadV1]
    observed_at = home_event_fixture["observed_at"]
    event_model.model_validate({
        **home_event_fixture,
        "ingested_at": observed_at + timedelta(seconds=30),
        "expires_at": observed_at + timedelta(seconds=31),
    })
    with pytest.raises(ValidationError, match="cross_domain_event_ingress_window_invalid"):
        event_model.model_validate({
            **home_event_fixture,
            "ingested_at": observed_at + timedelta(seconds=30, microseconds=1),
            "expires_at": observed_at + timedelta(seconds=31),
        })
    with pytest.raises(ValidationError, match="cross_domain_event_ingress_window_invalid"):
        event_model.model_validate({
            **home_event_fixture,
            "ingested_at": observed_at - timedelta(microseconds=1),
        })

def test_cross_domain_receiver_clock_rejects_expired_or_future_event(
    home_event_fixture,
) -> None:
    class SyntheticHomeEventPayloadV1(ContractModel):
        schema_id: Literal["home.synthetic.v1"]
        event_id: UUID

    event = CrossDomainEventV1[SyntheticHomeEventPayloadV1].model_validate(home_event_fixture)
    validate_cross_domain_event_at_ingress(
        event, now=event.ingested_at - timedelta(seconds=2),
    )
    validate_cross_domain_event_at_ingress(
        event, now=event.expires_at - timedelta(microseconds=1),
    )
    for now, reason in (
        (event.ingested_at - timedelta(seconds=2, microseconds=1), "from_future"),
        (event.expires_at, "expired_at_receiver"),
        (event.expires_at + timedelta(seconds=1), "expired_at_receiver"),
    ):
        with pytest.raises(ValueError, match=reason):
            validate_cross_domain_event_at_ingress(event, now=now)

@pytest.mark.parametrize("mutation", [
    exceed_scene_12,
    duplicate_scene_endpoint,
    reorder_scene_endpoint_without_ordinals,
    duplicate_scene_child_idempotency_key,
    corrupt_scene_manifest_digest,
])
def test_scene_envelope_rejects_noncanonical_or_unbounded_children(scene_envelope_fixture, mutation) -> None:
    with pytest.raises(ValidationError):
        BoundedSceneEnvelopeV1.model_validate(mutation(scene_envelope_fixture))

def test_scene_receipt_rejects_false_aggregate(scene_receipt_fixture) -> None:
    same_outcome_partial = deep_merge(scene_receipt_fixture, {"aggregate_state": "PARTIAL"})
    false_verified = deep_merge(scene_receipt_fixture, {
        "aggregate_state": "VERIFIED",
        "children": [{**row, "receipt": {**row["receipt"], "receipt_state": "FAILED"}}
                     for row in scene_receipt_fixture["children"]],
    })
    for candidate in (
        same_outcome_partial,
        false_verified,
        omit_scene_receipt_child(scene_receipt_fixture),
        mismatch_scene_child_action_id(scene_receipt_fixture),
        mismatch_scene_child_pre_dispatch_time(scene_receipt_fixture),
    ):
        with pytest.raises(ValidationError):
            HASceneReceiptV1.model_validate(candidate)

@pytest.mark.parametrize(("child_states", "expected_aggregate"), [
    (("VERIFIED", "VERIFIED"), "VERIFIED"),
    (("VERIFIED", "ACCEPTED_UNVERIFIED"), "PARTIAL"),
    (("VERIFIED", "FAILED"), "PARTIAL"),
    (("VERIFIED", "UNKNOWN"), "PARTIAL"),
    (("VERIFIED", "EXPIRED"), "PARTIAL"),
    (("ACCEPTED_UNVERIFIED", "ACCEPTED_UNVERIFIED"), "ACCEPTED_UNVERIFIED"),
    (("FAILED", "FAILED"), "FAILED"),
    (("EXPIRED", "EXPIRED"), "EXPIRED"),
    (("UNKNOWN", "UNKNOWN"), "UNKNOWN"),
    (("FAILED", "EXPIRED"), "FAILED"),
    (("FAILED", "UNKNOWN"), "UNKNOWN"),
    (("EXPIRED", "UNKNOWN"), "UNKNOWN"),
    (("ACCEPTED_UNVERIFIED", "FAILED"), "UNKNOWN"),
    (("ACCEPTED_UNVERIFIED", "EXPIRED"), "UNKNOWN"),
    (("ACCEPTED_UNVERIFIED", "UNKNOWN"), "UNKNOWN"),
    (("FAILED", "EXPIRED", "UNKNOWN"), "UNKNOWN"),
])
def test_scene_terminal_aggregate_exact_vectors(
    terminal_scene_receipt_payload, child_states, expected_aggregate,
) -> None:
    payload = terminal_scene_receipt_payload(
        child_states=child_states, aggregate_state=expected_aggregate,
    )
    assert HASceneReceiptV1.model_validate(payload).aggregate_state == expected_aggregate
    for wrong in {
        "VERIFIED", "ACCEPTED_UNVERIFIED", "PARTIAL", "FAILED", "UNKNOWN", "EXPIRED",
    } - {expected_aggregate}:
        with pytest.raises(ValidationError, match="scene_aggregate_truth_table"):
            HASceneReceiptV1.model_validate({**payload, "aggregate_state": wrong})

def test_scene_partial_requires_verified_effect_not_only_acceptance(
    terminal_scene_receipt_payload,
) -> None:
    payload = terminal_scene_receipt_payload(
        child_states=("ACCEPTED_UNVERIFIED", "FAILED"),
        aggregate_state="PARTIAL",
    )
    with pytest.raises(ValidationError, match="scene_aggregate_truth_table"):
        HASceneReceiptV1.model_validate(payload)

@pytest.mark.parametrize(("aggregate_state", "child_states"), [
    ("PRE_DISPATCH", ("PRE_DISPATCH", "VERIFIED")),
    ("DISPATCHING", ("PRE_DISPATCH", "PRE_DISPATCH")),
    ("DISPATCHING", ("DISPATCHING", "VERIFIED")),
    ("RECONCILING", ("PRE_DISPATCH", "RECONCILING")),
])
def test_nonterminal_scene_aggregate_requires_exact_child_lifecycle(
    nonterminal_scene_receipt_payload, aggregate_state, child_states,
) -> None:
    payload = nonterminal_scene_receipt_payload(
        aggregate_state=aggregate_state,
        child_states=child_states,
    )
    with pytest.raises(ValidationError, match="scene.*child|child.*scene"):
        HASceneReceiptV1.model_validate(payload)

@pytest.mark.parametrize("mutation", [
    replace_routine_trigger("arbitrary_event.v1"),
    replace_routine_step("service_call.v1"),
    add_routine_field("template", "{{ states('light.any') }}"),
    set_routine_delay_seconds(301),
    set_routine_generations(expected=4, next_value=6),
    make_routine_self_triggering,
    corrupt_routine_manifest_digest,
    expire_routine_more_than_60_seconds_after_issue,
])
def test_closed_routine_manifest_rejects_escape_generation_and_time(routine_manifest_fixture, mutation) -> None:
    with pytest.raises(ValidationError):
        BoundedRoutineManifestV1.model_validate(mutation(routine_manifest_fixture))

@pytest.mark.parametrize("mutation", [
    remove_schedule_authority_from_fixed_time_manifest,
    add_schedule_authority_to_state_only_manifest,
    replace_tzdata_digest_with_non_sha256,
    replace_schedule_policy_with_unknown_value,
])
def test_routine_schedule_authority_shape_is_closed(
    routine_manifest_fixture, mutation,
) -> None:
    with pytest.raises(ValidationError):
        BoundedRoutineManifestV1.model_validate(mutation(routine_manifest_fixture))

@pytest.mark.parametrize("field", [
    "routine_id", "activation_generation", "manifest_digest", "timezone",
    "local_date", "local_weekday", "local_time", "fold", "resolved_utc",
    "tzdata_version", "tzdata_sha256", "resolution_policy",
])
def test_scheduled_slot_commitment_covers_every_identity_field(
    scheduled_slot_fixture, slot_commitment_verifier, field,
) -> None:
    candidate = substitute_valid_value(scheduled_slot_fixture, field)
    with pytest.raises(ScheduledSlotBindingError):
        slot_commitment_verifier.require_exact(candidate)

@pytest.mark.parametrize("mutation", [
    duplicate_visible_endpoint,
    mismatch_resolved_binding_endpoint,
    set_ambiguous_candidate_count(1),
    add_candidate_ids_to_ambiguous_result,
])
def test_target_resolution_rejects_guessing_or_leak(target_contract_fixture, mutation) -> None:
    model, candidate = mutation(target_contract_fixture)
    with pytest.raises(ValidationError):
        model.model_validate(candidate)

@pytest.mark.parametrize("mutation", [
    mismatch_tv_attempt_kind_and_number,
    extend_tv_request_past_10_seconds,
    extend_tv_observation_past_30_seconds,
    report_playing_while_tv_off,
    claim_verified_tv_control_outcome,
    accept_tv_control_without_adapter_commitment,
    receive_tv_receipt_before_bound_dispatch,
    fail_possibly_in_flight_tv_control,
])
def test_tv_ports_reject_unbounded_or_false_success(tv_port_fixture, mutation) -> None:
    model, candidate = mutation(tv_port_fixture)
    with pytest.raises(ValidationError):
        model.model_validate(candidate)

@pytest.mark.parametrize("mutation", [
    {"state": "COOPERATIVE_ELIGIBLE", "standby_control_operation": None},
    {"state": "COOPERATIVE_ELIGIBLE", "power_observation_dimension": None},
    {"state": "STRICT_ELIGIBLE", "independence_evidence_digest": None},
    {"state": "DEGRADED", "standby_control_operation": "tv.set_power.v1"},
    {"standby_control_operation": "tv.set_volume.v1"},
    {"power_observation_dimension": "input"},
])
def test_screen_time_eligibility_requires_exact_standby_and_power_pair(
    tv_power_eligibility_fixture, mutation,
) -> None:
    with pytest.raises(ValidationError):
        TVPowerEligibilityV1.model_validate({**tv_power_eligibility_fixture, **mutation})

@pytest.mark.parametrize("mutation", [
    accepted_unverified_with_source_generation_time_but_no_strength,
    denied_with_positive_evidence_generation,
    observation_time_without_source,
    observation_source_without_time,
    observation_source_without_generation,
    observation_strength_without_source,
    failed_with_possibly_in_flight_dispatch,
    rejected_failure_with_observation,
    duplicate_with_dispatching_status,
])
def test_operation_target_evidence_tuple_and_outcome_are_atomic(
    operation_target_result_fixture, mutation,
) -> None:
    with pytest.raises(ValidationError):
        OperationTargetResultV1.model_validate(mutation(operation_target_result_fixture))

@pytest.mark.parametrize("mutation", [
    remove_observation_tuple,
    remove_dispatch_started_at,
    make_target_observation_acknowledged_only,
    make_target_observation_match_requested_effect,
    move_target_observation_before_dispatch,
])
def test_accepted_target_failure_requires_post_dispatch_contradiction_projection(
    operation_target_result_fixture, mutation,
) -> None:
    candidate = accepted_failed_target_from_truthful_home_result(
        operation_target_result_fixture,
    )
    with pytest.raises(ValidationError, match="failed.*contradict|observation.*dispatch"):
        OperationTargetResultV1.model_validate(mutation(candidate))

def test_accepted_target_failure_accepts_fresh_authoritative_contradiction_projection(
    operation_target_result_fixture,
) -> None:
    candidate = accepted_failed_target_from_truthful_home_result(
        operation_target_result_fixture,
        dispatch_started_at=SYNTHETIC_NOW,
        observed_at=SYNTHETIC_NOW + timedelta(microseconds=1),
        verification_strength="authoritative",
        observation_relation_to_requested_effect="contradicts",
    )
    assert OperationTargetResultV1.model_validate(candidate).outcome == "failed"

@pytest.mark.parametrize("source_fault", [
    "observed_matches_desired", "observation_before_dispatch",
    "optimistic_source", "integration_only", "stale_generation",
])
def test_home_result_projection_cannot_forge_contradiction_relation(
    home_result_projector, accepted_home_result, source_fault,
) -> None:
    source = accepted_home_result.with_fault(source_fault)
    with pytest.raises(HomeResultProjectionError, match="contradiction_not_proved"):
        home_result_projector.project(source, requested_outcome="failed")

@pytest.mark.parametrize("outcome", ["accepted_unverified", "unknown"])
def test_accepted_target_without_contradiction_uses_nonfailure_outcome(
    operation_target_result_fixture, outcome,
) -> None:
    candidate = accepted_target_without_truthful_contradiction(
        operation_target_result_fixture, outcome=outcome,
    )
    assert OperationTargetResultV1.model_validate(candidate).outcome == outcome

@pytest.mark.parametrize("outcome", ["denied", "expired", "cancelled", "failed", "unknown"])
def test_target_without_observation_cannot_carry_fabricated_state(
    operation_target_result_fixture, outcome,
) -> None:
    candidate = result_without_observation(
        operation_target_result_fixture,
        outcome=outcome,
        dispatch_status=("possibly_in_flight" if outcome == "unknown" else "not_dispatched"),
    )
    assert candidate["observed_state_schema_id"] is None
    assert candidate["observed_state_code"] is None
    assert candidate["observation_relation_to_requested_effect"] == "none"
    OperationTargetResultV1.model_validate(candidate)
    for mutation in (
        {"observed_state_schema_id": "tuntun.home.light-state.v1"},
        {"observed_state_code": "on"},
        {
            "observed_state_schema_id": "tuntun.home.light-state.v1",
            "observed_state_code": "on",
        },
        {"observation_relation_to_requested_effect": "contradicts"},
    ):
        with pytest.raises(ValidationError, match="observed_state"):
            OperationTargetResultV1.model_validate({**candidate, **mutation})

@pytest.mark.parametrize("mutation", [
    omit_manifest_target_row,
    swap_manifest_target_rows,
    make_partial_children_homogeneous,
    make_verified_child_unobserved,
    put_child_terminal_after_aggregate,
    claim_verified_with_empty_manifest,
    claim_accepted_with_empty_manifest,
    claim_unknown_with_empty_manifest,
])
def test_operation_result_rejects_incomplete_or_false_aggregate(operation_result_fixture, mutation) -> None:
    with pytest.raises(ValidationError):
        OperationResultV1.model_validate(mutation(operation_result_fixture))

@pytest.mark.parametrize(("child_outcomes", "expected_aggregate"), [
    (("verified", "verified"), "verified"),
    (("verified", "failed"), "partial"),
    (("verified", "accepted_unverified"), "partial"),
    (("verified", "unknown"), "partial"),
    (("verified", "expired"), "partial"),
    (("accepted_unverified", "accepted_unverified"), "accepted_unverified"),
    (("failed", "failed"), "failed"),
    (("expired", "expired"), "expired"),
    (("unknown", "unknown"), "unknown"),
    (("failed", "expired"), "failed"),
    (("failed", "unknown"), "unknown"),
    (("expired", "unknown"), "unknown"),
    (("accepted_unverified", "failed"), "unknown"),
    (("accepted_unverified", "expired"), "unknown"),
    (("accepted_unverified", "unknown"), "unknown"),
    (("failed", "expired", "unknown"), "unknown"),
])
def test_operation_result_uses_same_effect_bearing_aggregate_truth(
    operation_result_payload, child_outcomes, expected_aggregate,
) -> None:
    payload = operation_result_payload(
        child_outcomes=child_outcomes, outcome=expected_aggregate,
    )
    assert OperationResultV1.model_validate(payload).outcome == expected_aggregate
    for wrong in {
        "verified", "accepted_unverified", "partial", "denied", "duplicate",
        "failed", "unknown", "expired", "cancelled",
    } - {expected_aggregate}:
        with pytest.raises(ValidationError, match="operation_aggregate_truth_table"):
            OperationResultV1.model_validate({**payload, "outcome": wrong})
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/home/test_home_contracts.py tests/property/home/test_contract_rejection.py -q`
Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_contracts.home'`.

- [ ] **Step 3: Implement the complete closed models, canonicalization, schemas, and synthetic fixtures**

```python
from tuntun_contracts.base import canonical_mapping_bytes,parse_contract_json

class HomeContract(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True, validate_assignment=True, str_strip_whitespace=True)

def canonical_home_bytes(value: HomeContract) -> bytes:
    return canonical_mapping_bytes(value.model_dump(mode="python"))

HomeModelT = TypeVar("HomeModelT", bound=HomeContract)

def parse_home_json(model: type[HomeModelT], raw: bytes, *, max_bytes: int = 65_536) -> HomeModelT:
    return parse_contract_json(
        model,
        raw,
        max_bytes=max_bytes,
        require_canonical=False,
    )
```

Generate every Phase 2-owned schema from the exact home model registry, including each discriminated target/routine variant, `HAReadinessObservationV1`, `EnforcementIntentV1`, and `TVDispatchProofV1`, write with sorted keys, and fail if a generated file differs from the committed schema. Import the U01-owned shared operation-result models and validate the Phase 2 fixture against their already-generated schema; `generate_home_schemas.py` must not write `tuntun_contracts/ui.py` or `schemas/ui/v1/operation-result-v1.schema.json`. Every route/fixture loader uses `parse_home_json()`, which delegates its first pass to the Phase 1 shared bounded parser and therefore inherits the 32-depth, 4,096-container, 16,384-structure-token, bounded-number, duplicate-key, strict UTF-8, and caller-supplied byte ceilings. Direct `json.loads`, `model_validate_json`, or a Phase 2-local decoder is forbidden at runtime ingress. Signed bodies additionally require `raw == canonical_home_bytes(parsed)` before signature verification. The primary topology fixture contains `area_common_synth_01` and optional `zone_boundary_synth_01` with matching area/binding generations; a second fixture has at least two canonically ordered members in every topology collection. Both contain no location compatibility alias, repeat the exact bundle topology version in every endpoint binding, have one binding per endpoint/capability pair, and carry a recomputable domain-separated bundle digest. Snapshot/delta fixtures bind one exact epoch/verifier stream and carry one coherent channel-authenticated readiness observation whose nonce is synthetic and whose sequence is inside the cursor interval; receipt fixtures cover every intermediate and terminal class; scene/routine fixtures contain canonical 1–12 light children and recomputable digests; target fixtures cover exact/ambiguous/not-found without candidate leakage; TV fixtures never claim control acknowledgement proves off. The enforcement-intent fixture is an exact Cooperative primary standby intent; separate cases cover Strict and the sole bounded re-enforcement shape. The TV dispatch fixture binds its exact request, adapter/controller/topology/binding/capability/control context, committed start, and standby effect. Other fixtures use `ep_light_synth_01`, fixed UUIDs, test digests, and the literal signature `TEST_SIGNATURE_NOT_VALID_IN_PRODUCTION`.

- [ ] **Step 4: Run green and generation drift checks**

Run: `uv run python scripts/ui/generate_contracts.py --check && uv run python scripts/phase2/generate_home_schemas.py --check && uv run pytest tests/contract/home tests/property/home/test_contract_rejection.py -q && uv run ruff check packages/contracts scripts/phase2/generate_home_schemas.py tests/contract/home tests/property/home/test_contract_rejection.py && uv run mypy packages/contracts/src`
Expected: PASS; schema generation prints `home schema drift: none`; empty or oversized bodies, invalid UTF-8, duplicate keys, depth 33, container 4,097, structure token 16,385, 21-digit integers, out-of-range decimals, and every unknown field/version/action/result kind/enum, noncanonical timestamp, zero/stale/mismatched generation, stale endpoint topology version, duplicate current endpoint/capability binding, reordered topology collection, substituted topology bundle digest, foreign/nonadvancing cursor, readiness nonce/sequence/epoch/generation/digest/marker-state/time-window mismatch, action/scene/routine time-window violation, impossible receipt transition, accepted `FAILED` without a fresh truthful post-dispatch contradiction, non-atomic UI observation/dispatch/relation tuple, wildcard, `toggle`, relative state, scene entry 13, duplicate/unordered scene child, routine trigger/condition/action escape, stale routine CAS, delay over 300 seconds, routine digest mismatch, incomplete/unordered target result, false aggregate `verified`, `partial` without a `verified` child, no-effect mixtures misreported as partial, target ambiguity leak/guess, false TV verified-off claim, substituted enforcement viewer/session/TV/adapter/generation/operation, invalid Strict evidence, partial prior-attempt fields, third/late re-enforcement, injected `room_id`, cross-area zone move, and stale/mismatched area or owning-binding generation is rejected.

- [ ] **Step 5: Commit exact contract paths**

```bash
git add packages/contracts/src/tuntun_contracts/home scripts/phase2/generate_home_schemas.py schemas/home/v1 fixtures/synthetic/home/contracts fixtures/synthetic/ui/operation-result-light-v1.json tests/contract/home tests/property/home/test_contract_rejection.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(home): freeze Phase 2 contracts"
```

### Task 02: Build deterministic home fakes, fault points, and corpus generators

**Depends on:** Task 01.
**Gate contribution:** P2-E0, P2-4, P2-6, P2-7.
**Estimated effort:** 1 engineering person-day.

**Files:**
- Create: `packages/testing/src/tuntun_testing/home/__init__.py`
- Create: `packages/testing/src/tuntun_testing/home/fake_clock.py`
- Create: `packages/testing/src/tuntun_testing/home/fake_ha.py`
- Create: `packages/testing/src/tuntun_testing/home/fake_light.py`
- Create: `packages/testing/src/tuntun_testing/home/fake_tv.py`
- Create: `packages/testing/src/tuntun_testing/home/fault_points.py`
- Create: `packages/testing/src/tuntun_testing/home/scenario.py`
- Create: `scripts/phase2/build_authorization_corpus.py`
- Create: `scripts/phase2/build_screen_time_corpus.py`
- Create: `fixtures/synthetic/home/authorization-corpus-v1.jsonl`
- Create: `fixtures/synthetic/home/screen-time-corpus-v1.jsonl`
- Test: `tests/unit/testing/home/test_home_scenario.py`
- Test: `tests/contract/home/test_corpus_shape.py`

**Interfaces:** `HomeScenario.run(events: tuple[ScenarioEvent,...]) -> ScenarioResult`; `FakeHAService.call_count`; `FaultPlan.hit(point: HomeFaultPoint) -> None`; authorization corpus exactly 1,350 rows; screen-time corpus exactly 720 rows; all rows bind generator, schema, policy versions, and seed.

- [ ] **Step 1: Write red deterministic-count and no-hardware tests**

```python
def test_corpora_have_exact_cross_products() -> None:
    auth = load_jsonl("fixtures/synthetic/home/authorization-corpus-v1.jsonl")
    screen = load_jsonl("fixtures/synthetic/home/screen-time-corpus-v1.jsonl")
    assert len(auth) == 9 * 3 * 10 * 5 == 1_350
    assert len(screen) == 3 * 5 * 3 * 8 * 2 == 720
    assert {row["seed"] for row in auth} == {220827}
    assert {row["seed"] for row in screen} == {220828}

def test_scenario_never_opens_network(monkeypatch) -> None:
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: pytest.fail("network forbidden"))
    assert HomeScenario.synthetic().run((ScenarioEvent.wan_down(),)).network_calls == 0
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/testing/home/test_home_scenario.py tests/contract/home/test_corpus_shape.py -q`
Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_testing.home'`.

- [ ] **Step 3: Implement fakes and exact cross-product builders**

```python
class HomeFaultPoint(StrEnum):
    MAC_BEFORE_AUTH_COMMIT = "mac.before_auth_commit"
    MAC_AFTER_AUTH_COMMIT = "mac.after_auth_commit"
    MAC_AFTER_SIGN = "mac.after_sign"
    HA_BEFORE_PRE_DISPATCH = "ha.before_pre_dispatch"
    HA_AFTER_PRE_DISPATCH = "ha.after_pre_dispatch"
    HA_AFTER_DISPATCHING = "ha.after_dispatching"
    HA_AFTER_SERVICE_CALL = "ha.after_service_call"
    HA_BEFORE_TERMINAL = "ha.before_terminal"

@dataclass
class FakeLight:
    endpoint_id: str
    actual: LightDesiredStateV1
    observable: bool = True
    service_calls: list[LightDesiredStateV1] = field(default_factory=list)
```

The authorization builder enumerates the nine actor/evidence, three language, ten action/target, and five phrasing indices from the Phase 2 acceptance gate and writes a deterministic expected decision/target/result oracle. The screen builder enumerates all named modes, roles, language modes, scenarios, and variants with exact transition/message/ledger/authority/control-attempt oracles.

- [ ] **Step 4: Run green and regenerate twice**

Run: `uv run python scripts/phase2/build_authorization_corpus.py --check && uv run python scripts/phase2/build_screen_time_corpus.py --check && uv run pytest tests/unit/testing/home tests/contract/home/test_corpus_shape.py -q`
Expected: PASS; both generators report exact counts and byte-identical second output; no network, Keychain, HA, hardware, or paid provider call occurs.

- [ ] **Step 5: Commit exact fake/corpus paths**

```bash
git add packages/testing/src/tuntun_testing/home scripts/phase2/build_authorization_corpus.py scripts/phase2/build_screen_time_corpus.py fixtures/synthetic/home/authorization-corpus-v1.jsonl fixtures/synthetic/home/screen-time-corpus-v1.jsonl tests/unit/testing/home tests/contract/home/test_corpus_shape.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(home): add deterministic Phase 2 harness"
```

### Task 03: Persist topology, child/Guest policy, and immutable scenes

**Depends on:** Tasks 01–02 and Phase 1 `0008_prepared_mutations`.
**Gate contribution:** P2-E0.
**Estimated effort:** 1.5 engineering person-days.

**Files:**
- Create: `apps/core/migrations/versions/0009_home_topology_policy.py`
- Modify: `apps/core/src/tuntun_core/adapters/sqlcipher/models.py`
- Create: `apps/core/src/tuntun_core/domain/home/topology.py`
- Create: `apps/core/src/tuntun_core/domain/home/policy.py`
- Create: `apps/core/src/tuntun_core/services/home/topology_registry.py`
- Create: `apps/core/src/tuntun_core/services/home/guest_sessions.py`
- Create: `apps/core/src/tuntun_core/services/home/scenes.py`
- Test: `tests/integration/storage/test_home_topology_migration.py`
- Test: `tests/integration/home/test_topology_generation.py`
- Test: `tests/security/home/test_child_rule_dual_approval.py`
- Test: `tests/security/home/test_canonical_location_keys.py`
- Test: `tests/integration/storage/test_core_and_feature_migration_graphs.py`

**Interfaces:** `TopologyRegistry.mutate(command, auth, uow) -> TopologyMutationReceipt`; `resolve_exact`; `freeze_binding`; `create_zone(area_id, owning_binding_id, owning_binding_generation, command, auth, uow)`; `compare_and_swap_zone(zone_id, expected_generation, command, auth, uow)`; `GuestSessionService.create/cancel/resolve`; `SceneRegistry.create/edit/delete/get`. `area_id` is the only canonical location key. A zone version has one immutable parent `area_id`, exact area generation, and exact owning binding ID/generation; every area/zone/binding mutation increments its generation and invalidates outstanding target/scene/cross-phase operation commitments in the same transaction.

- [ ] **Step 1: Write red migration and dual-principal tests**

```python
def test_0009_upgrade_downgrade_upgrade_owns_exact_tables(migration_db) -> None:
    migration_db.upgrade("0009_home_topology_policy")
    assert migration_db.new_tables_since("0008_prepared_mutations") == EXPECTED_0009_TABLES
    migration_db.downgrade("0008_prepared_mutations")
    assert not EXPECTED_0009_TABLES & migration_db.tables()
    migration_db.upgrade("head")

@pytest.mark.parametrize("search_enabled", [False, True])
def test_core_graph_is_linear_and_search_namespace_is_independent(
    migration_harness, search_enabled,
) -> None:
    installation = migration_harness.install(search_enabled=search_enabled)
    assert installation.core.edges_from("0008_prepared_mutations") == (
        ("0008_prepared_mutations", "0009_home_topology_policy"),
    )
    assert installation.core.heads() == {"0009_home_topology_policy"}
    assert installation.core.merge_revisions() == set()
    assert installation.feature("search").heads() == (
        {"search_0001_experimental_search"} if search_enabled else set()
    )
    assert installation.core.version_table == "alembic_version"
    assert installation.feature("search").version_table == "alembic_version_experimental_search"
    assert "search_0001_experimental_search" not in installation.core.revisions()

@pytest.mark.asyncio
async def test_same_subject_cannot_activate_child_rule(rule_service, owner_subject) -> None:
    with pytest.raises(PermissionError, match="distinct_guardian_required"):
        await rule_service.activate(owner_subject, owner_subject, same_digest_rule())

def test_0009_has_no_parallel_room_identifier(migration_db) -> None:
    migration_db.upgrade("0009_home_topology_policy")
    assert "home_zones" in migration_db.tables()
    assert not any("room_id" in column.name for table in migration_db.metadata.tables.values() for column in table.columns)

@pytest.mark.asyncio
async def test_zone_cannot_move_between_areas(registry, active_zone, owner_passkey, uow) -> None:
    with pytest.raises(ConflictError, match="zone_area_immutable"):
        await registry.compare_and_swap_zone(active_zone.zone_id, active_zone.generation, move_to_another_area(), owner_passkey, uow)
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/storage/test_home_topology_migration.py tests/integration/storage/test_core_and_feature_migration_graphs.py tests/integration/home/test_topology_generation.py tests/security/home/test_child_rule_dual_approval.py tests/security/home/test_canonical_location_keys.py -q`
Expected: FAIL because Alembic revision `0009_home_topology_policy` and `TopologyRegistry` do not exist.

- [ ] **Step 3: Implement exact tables, triggers, repositories, and services**

The migration has exact `down_revision = "0008_prepared_mutations"` and creates exactly the thirteen `0009` tables in the migration map, in dependency order: areas; devices/endpoints/capabilities; bindings; zones; aliases/policies/scenes, with downgrade in exact reverse order. `home_areas` versions key on `(area_id, generation)`, and every located device stores an exact `(area_id, area_generation)` foreign key. `home_zones` versions key on `(zone_id, generation)` and carry non-null `area_id`, `area_generation`, `owning_binding_id`, `owning_binding_generation`, `zone_digest`, and lifecycle state; foreign keys resolve the exact area and binding generations. A trigger rejects a new version when its `area_id` differs from generation 1, while binding/shape/label changes require expected-generation CAS and invalidate prior prepared operations. Do not create a room table, `room_id` column, alias, compatibility view, mapping table, DTO property, or JSON key. Add unique/current indexes, `CHECK` constraints for area/device/capability classes, scene size `1..12`, endpoint uniqueness, and triggers that reject enabling a child rule unless both current approvals match its digest/generation and principal IDs differ. Search migrations use their own version table and runner; a core migration must reject a feature revision as parent/head and vice versa.

```python
async def mutate(self, command: TopologyMutation, auth: AuthContext, uow: HomeUnitOfWork) -> TopologyMutationReceipt:
    require_owner_passkey(auth, command.binding())
    current = await uow.home_topology.lock(command.resource_id)
    updated = current.apply_exact(command, next_generation=current.generation + 1)
    await uow.home_topology.save(updated)
    invalidated = await uow.home_actions.invalidate_uncommitted_target(current.resource_id)
    await self._audit.append(uow, updated.audit(invalidated))
    return updated.receipt(invalidated)
```

- [ ] **Step 4: Run green, encrypted backup, and migration checks**

Run: `uv run pytest tests/integration/storage/test_home_topology_migration.py tests/integration/home/test_topology_generation.py tests/security/home/test_child_rule_dual_approval.py tests/security/home/test_canonical_location_keys.py -q && uv run mypy apps/core/src/tuntun_core/domain/home apps/core/src/tuntun_core/services/home`
Expected: PASS; downgrade removes only the thirteen `0009` tables; schema introspection finds no parallel room identifier; cross-area zone moves and stale area/binding/zone generations fail; same-principal dual approval fails; area/zone/alias/rebind increments generation; and every pre-commit stale target is invalidated.

- [ ] **Step 5: Commit exact topology paths**

```bash
git add apps/core/migrations/versions/0009_home_topology_policy.py apps/core/src/tuntun_core/adapters/sqlcipher/models.py apps/core/src/tuntun_core/domain/home/topology.py apps/core/src/tuntun_core/domain/home/policy.py apps/core/src/tuntun_core/services/home/topology_registry.py apps/core/src/tuntun_core/services/home/guest_sessions.py apps/core/src/tuntun_core/services/home/scenes.py tests/integration/storage/test_home_topology_migration.py tests/integration/storage/test_core_and_feature_migration_graphs.py tests/integration/home/test_topology_generation.py tests/security/home/test_child_rule_dual_approval.py tests/security/home/test_canonical_location_keys.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(home): persist topology and guarded policy"
```

### Task 04: Persist the Mac home-action lifecycle and scene children

**Depends on:** Task 03 and Phase 1 `ActionMutationCoordinator`.
**Gate contribution:** P2-E0, P2-4.
**Estimated effort:** 1.5 engineering person-days.

**Files:**
- Create: `apps/core/migrations/versions/0010_home_actions.py`
- Modify: `apps/core/src/tuntun_core/adapters/sqlcipher/models.py`
- Create: `apps/core/src/tuntun_core/domain/home/actions.py`
- Create: `apps/core/src/tuntun_core/services/transactions/home_uow.py`
- Test: `tests/integration/storage/test_home_action_migration.py`
- Test: `tests/integration/home/test_action_transition_store.py`
- Test: `tests/property/home/test_action_state_machine.py`

**Interfaces:** `HomeActionRepository.prepare`, `authorize_committed`, `record_signature`, `mark_dispatching`, `mark_reconciling`, `finish`; `HomeUnitOfWork` extends the Phase 1 structural async UoW without raw database access. Produces legal transition enforcement and immutable terminal time/result.

- [ ] **Step 1: Write red transition and terminal-immutability tests**

```python
@pytest.mark.parametrize("illegal", ILLEGAL_HOME_ACTION_TRANSITIONS)
def test_illegal_transition_is_rejected(action_store, illegal) -> None:
    action = action_store.seed(illegal.before)
    with pytest.raises(IntegrityError):
        action_store.transition(action.id, illegal.after)

def test_terminal_at_and_result_cannot_be_rewritten(action_store) -> None:
    action = action_store.seed("RECONCILING")
    action_store.finish(action.id, "UNKNOWN", at=instant(10), result_hash="a" * 64)
    with pytest.raises(IntegrityError):
        action_store.finish(action.id, "VERIFIED", at=instant(11), result_hash="b" * 64)
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/storage/test_home_action_migration.py tests/integration/home/test_action_transition_store.py tests/property/home/test_action_state_machine.py -q`
Expected: FAIL because migration `0010_home_actions` is unavailable.

- [ ] **Step 3: Implement exact tables and database-enforced lifecycle**

Create the six `0010` tables with exact `down_revision = "0009_home_topology_policy"`, legal-transition trigger, terminal immutability triggers, unique `(household_id, action_type, target_endpoint_id, idempotency_key)`, and one scene child per canonical endpoint index. Persist dispatch start, exact HA context ID, and a commitment over action/idempotency ID, compiled domain/service/data, entity commitment, desired state, and frozen generations in the same CAS that advances `PRE_DISPATCH -> DISPATCHING`; store desired state encrypted plus purpose-separated commitments and no spoken text or identity evidence.

```python
TERMINAL = frozenset({"VERIFIED", "ACCEPTED_UNVERIFIED", "FAILED", "UNKNOWN", "EXPIRED"})

async def finish(self, uow, action_id, result, now):
    if result.terminal_state not in TERMINAL:
        raise ValueError("home_action_terminal_required")
    return await uow.home_actions.compare_and_set_terminal(action_id, expected="RECONCILING", result=result, terminal_at=now)
```

- [ ] **Step 4: Run green and crash-safe migration tests**

Run: `uv run pytest tests/integration/storage/test_home_action_migration.py tests/integration/home/test_action_transition_store.py tests/property/home/test_action_state_machine.py -q`
Expected: PASS across every legal transition and restoration from a database copy taken at each state; terminal fields cannot be rewritten.

- [ ] **Step 5: Commit exact lifecycle paths**

```bash
git add apps/core/migrations/versions/0010_home_actions.py apps/core/src/tuntun_core/adapters/sqlcipher/models.py apps/core/src/tuntun_core/domain/home/actions.py apps/core/src/tuntun_core/services/transactions/home_uow.py tests/integration/storage/test_home_action_migration.py tests/integration/home/test_action_transition_store.py tests/property/home/test_action_state_machine.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(home): persist durable action lifecycle"
```

### Task 05: Persist automation governance and screen-time foundations

**Depends on:** Tasks 03–04.
**Gate contribution:** P2-E0, P2-5, P2-6.
**Estimated effort:** 1.5 engineering person-days.

**Files:**
- Create: `apps/core/migrations/versions/0011_home_automation.py`
- Create: `apps/core/migrations/versions/0012_screen_time.py`
- Modify: `apps/core/src/tuntun_core/adapters/sqlcipher/models.py`
- Create: `apps/core/src/tuntun_core/domain/home/routines.py`
- Create: `apps/core/src/tuntun_core/domain/home/screen_time.py`
- Test: `tests/integration/storage/test_home_automation_migrations.py`
- Test: `tests/integration/storage/test_screen_time_migration.py`
- Test: `tests/security/home/test_learning_projection_schema.py`
- Modify: `tests/integration/storage/test_core_and_feature_migration_graphs.py`

**Interfaces:** Persisted models in the migration map; `AutomationMode` defaults to `MANUAL`; `LearningProjectionV1` has only endpoint, exact area ID/generation, state transition, coarse time bucket, observed time, and expiry. Projection reads and draft generation reopen that exact area generation; reclassification quarantines/deletes the stale projection before it can influence a suggestion. `ScreenTimeSessionState` is the exact declared state machine; the `0012` enforcement-intent row owns the atomic `TVDispatchProofV1` transition and exact downstream adapter-receipt binding.

- [ ] **Step 1: Write red schema/default/retention tests**

```python
def test_every_domain_starts_manual(automation_store) -> None:
    assert automation_store.create_domain("lights").mode == "MANUAL"

def test_learning_projection_has_no_identity_join_field() -> None:
    assert set(LearningProjectionV1.model_fields) == {
        "endpoint_id", "area_id", "area_generation", "transition",
        "coarse_time_bucket", "observed_at", "expires_at",
    }

def test_area_reclassification_invalidates_learning_projection_before_draft(
    learning_service, learning_projection_fixture,
) -> None:
    projection = LearningProjectionV1.model_validate(learning_projection_fixture)
    learning_service.reclassify_area(
        projection.area_id, next_generation=projection.area_generation + 1,
    )
    assert learning_service.drafts_from((projection,)) == ()
    assert learning_service.quarantined_projection_ids == (projection.endpoint_id,)

def test_learning_projection_cannot_outlive_thirty_days(learning_projection_fixture) -> None:
    with pytest.raises(ValidationError):
        LearningProjectionV1.model_validate({
            **learning_projection_fixture,
            "expires_at": learning_projection_fixture["observed_at"] + timedelta(days=30, microseconds=1),
        })

def test_screen_time_transition_trigger_rejects_active_to_ended(screen_store) -> None:
    session = screen_store.seed("ACTIVE")
    with pytest.raises(IntegrityError):
        screen_store.transition(session.id, "ENDED")

@pytest.mark.parametrize("mutation", [
    "dispatch_start_only", "context_only", "effect_only",
    "started_without_proof", "undispatched_with_proof",
    "adapter_receipt_without_proof", "adapter_receipt_before_dispatch",
])
def test_0012_requires_atomic_tv_dispatch_proof_and_exact_receipt_binding(
    screen_store, committed_enforcement_intent, mutation,
) -> None:
    with pytest.raises(IntegrityError):
        screen_store.inject_dispatch_state(committed_enforcement_intent, mutation)

async def test_0012_closed_dispatch_cas_commits_complete_proof_before_effect(
    screen_store_factory, committed_enforcement_intent, tv_off_request_fixture,
    tv_dispatch_proof_fixture, fake_tv_compiler,
) -> None:
    screen_store = screen_store_factory.open(
        trusted_clock=fake_tv_compiler.clock,
        sealed_fake_tv_begin_port=fake_tv_compiler.begin_probe_no_yield,
    )
    request = TVOffRequestV1.model_validate(tv_off_request_fixture)
    await screen_store.seed_pre_dispatch_and_current_authority(
        committed_enforcement_intent, request, fake_tv_compiler.current_authority(),
    )
    screen_store.clock.set(tv_dispatch_proof_fixture["dispatch_started_at"])
    result = await screen_store.advance_to_dispatching_if_fresh(
        request.request_id,
        expected_canonical_request=canonical_home_bytes(request),
        expected_request_commitment=request.request_commitment,
    )
    assert result.kind == "dispatch_begun"
    row = screen_store.require(request.request_id)
    assert row.dispatch_proof() == result.proof
    assert result.proof == TVDispatchProofV1.model_validate(tv_dispatch_proof_fixture)
    assert fake_tv_compiler.begin_probes == (
        (
            "tv.set_power.v1", "STANDBY",
            result.proof.effect_commitment, result.actual_call_started_at,
        ),
    )
    assert fake_tv_compiler.effect_calls == ()

@pytest.mark.parametrize("search_enabled", [False, True])
def test_complete_phase2_core_graph_has_one_exact_head_and_no_feature_parent(
    migration_harness, search_enabled,
) -> None:
    installation = migration_harness.install(search_enabled=search_enabled)
    assert installation.core.edges_from("0008_prepared_mutations") == (
        ("0008_prepared_mutations", "0009_home_topology_policy"),
        ("0009_home_topology_policy", "0010_home_actions"),
        ("0010_home_actions", "0011_home_automation"),
        ("0011_home_automation", "0012_screen_time"),
    )
    assert installation.core.heads() == {"0012_screen_time"}
    assert installation.core.merge_revisions() == set()
    assert "search_0001_experimental_search" not in installation.core.revisions()
    assert installation.feature("search").heads() == (
        {"search_0001_experimental_search"} if search_enabled else set()
    )
    assert installation.core.version_table == "alembic_version"
    assert installation.feature("search").version_table == "alembic_version_experimental_search"
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/storage/test_home_automation_migrations.py tests/integration/storage/test_screen_time_migration.py tests/integration/storage/test_core_and_feature_migration_graphs.py tests/security/home/test_learning_projection_schema.py -q`
Expected: FAIL because revisions `0011_home_automation` and `0012_screen_time` do not exist.

- [ ] **Step 3: Implement exact migrations and domain records**

Create every table named in the migration map with exact `0011.down_revision = "0010_home_actions"` and `0012.down_revision = "0011_home_automation"`, indexes for expiry and current generation, routine content/digest immutability, Manual default, projection field allowlist, legal screen-session transition trigger, and immutable canonical enforcement-intent bytes plus commitment. The intent row rejects duplicate/third attempts and any rewritten `(session, enforcement generation, attempt number)` binding; its dispatch transition atomically stores start, exact adapter/controller/topology/binding/capability/control context commitment, and exact standby-effect commitment before I/O. Database checks require that proof for `accepted|possibly_in_flight` and every started terminal, forbid it for `not_dispatched|rejected|EXPIRED`, and accept an adapter-receipt commitment only when it postdates and exact-binds that proof. A session and committed intent store child subject ID locally because policy requires it; TV observations and HA payloads never contain it. Core and feature Alembic runners use distinct version tables and independently verify their heads; no fork, merge, orphan, or extra core head is accepted.

- [ ] **Step 4: Run green and upgrade/downgrade chain**

Run: `uv run pytest tests/integration/storage/test_home_automation_migrations.py tests/integration/storage/test_screen_time_migration.py tests/integration/storage/test_core_and_feature_migration_graphs.py tests/security/home/test_learning_projection_schema.py tests/integration/storage/test_migrations.py -q`
Expected: PASS for the sole core path `0008 -> 0009 -> 0010 -> 0011 -> 0012`, reverse downgrade, both absent-search and enabled-search installs, independent `search_0001_experimental_search` feature head, encrypted backup, exact table ownership, Manual default, immutable one-or-two-attempt intent rows, atomic all-or-none dispatch proofs with exact post-start adapter receipts, and identity-free projection schema; no fork, merge, orphan, or multiple-head ambiguity exists.

- [ ] **Step 5: Commit exact automation/screen schema paths**

```bash
git add apps/core/migrations/versions/0011_home_automation.py apps/core/migrations/versions/0012_screen_time.py apps/core/src/tuntun_core/adapters/sqlcipher/models.py apps/core/src/tuntun_core/domain/home/routines.py apps/core/src/tuntun_core/domain/home/screen_time.py tests/integration/storage/test_home_automation_migrations.py tests/integration/storage/test_screen_time_migration.py tests/integration/storage/test_core_and_feature_migration_graphs.py tests/security/home/test_learning_projection_schema.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(home): add automation and screen-time schema"
```

### Task 06: Register Phase 2 policy amendments and restrictive actor resolution

**Depends on:** Tasks 03–05 and Phase 1 policy/auth/identity contracts.
**Gate contribution:** P2-E0, P2-4.
**Estimated effort:** 1.5 engineering person-days.

**Files:**
- Modify: `config/policies/default.yaml`
- Modify: `apps/core/src/tuntun_core/services/policy/action_registry.py`
- Modify: `apps/core/src/tuntun_core/services/policy/engine.py`
- Create: `apps/core/src/tuntun_core/services/home/actor_resolution.py`
- Create: `apps/core/src/tuntun_core/services/home/permissions.py`
- Create: `tests/unit/home/test_actor_resolution.py`
- Create: `tests/security/home/test_phase2_policy_amendments.py`
- Create: `tests/security/home/test_guest_session_policy.py`
- Create: `tests/acceptance/home/test_authorization_corpus.py`
- Modify: `tests/unit/policy/test_risk_matrix.py`

**Interfaces:** `resolve_home_actor(identity: IdentityDecision, evidence: IdentityConflictFlags, guest: DesignatedGuestSession | None, now: datetime) -> HomeActorDecision`; `HomePermissionEngine.decide(HomePolicyRequest) -> HomePolicyDecision`. Produces the four named policy versions and exact assurance results `execute`, `hold_owner_coapproval`, `require_adult_confirmation`, `require_owner_passkey`, `deny`, `unavailable`.

- [ ] **Step 1: Write red restrictive-precedence tests**

```python
@pytest.mark.parametrize("flag", ["conflicting_enrolled", "mixed_speaker", "failed_liveness", "possible_child"])
def test_restrictive_evidence_cancels_designated_guest(valid_guest_session, flag) -> None:
    result = resolve_home_actor(unknown_identity(), flags(**{flag: True}), valid_guest_session, NOW)
    assert result.actor_class == "anonymous_restricted"
    assert result.cancel_pending_guest_requests

def test_identified_adult_single_reversible_light_uses_named_exception(policy) -> None:
    result = policy.decide(adult_single_light_request())
    assert (result.effect, result.policy_amendment) == ("execute", "home_reversible_low_v1")
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/home/test_actor_resolution.py tests/security/home/test_phase2_policy_amendments.py tests/security/home/test_guest_session_policy.py tests/unit/policy/test_risk_matrix.py -q`
Expected: FAIL with missing `tuntun_core.services.home.actor_resolution` and absent policy registry keys.

- [ ] **Step 3: Implement the exact precedence and policy table**

```python
def resolve_home_actor(identity, conflict, guest, now):
    if conflict.conflicting_enrolled or conflict.mixed_speaker or conflict.failed_liveness or conflict.possible_child:
        return HomeActorDecision("anonymous_restricted", True, "restrictive_evidence")
    if identity.is_verified:
        return HomeActorDecision.from_verified(identity)
    if guest is not None and guest.active_at(now):
        return HomeActorDecision("designated_guest_request", False, "scoped_bearer_session")
    return HomeActorDecision("anonymous_restricted", True, "no_eligible_identity_or_session")
```

The action registry contains single-light power/brightness, registered-scene execute, scene definition mutations, child-rule/Guest-session/topology/routine/screen policy operations, and emergency reduction operations. It contains no generic home action and no hazardous class.

- [ ] **Step 4: Run green and full 1,350-case corpus**

Run: `uv run pytest tests/unit/home/test_actor_resolution.py tests/security/home/test_phase2_policy_amendments.py tests/security/home/test_guest_session_policy.py tests/unit/policy/test_risk_matrix.py tests/acceptance/home/test_authorization_corpus.py -q`
Expected: PASS; 1,350/1,350 cases equal their exact oracle with zero unauthorized execution, wrong target, false authorization claim, or false denial.

- [ ] **Step 5: Commit exact policy paths**

```bash
git add config/policies/default.yaml apps/core/src/tuntun_core/services/policy/action_registry.py apps/core/src/tuntun_core/services/policy/engine.py apps/core/src/tuntun_core/services/home/actor_resolution.py apps/core/src/tuntun_core/services/home/permissions.py tests/unit/home/test_actor_resolution.py tests/security/home/test_phase2_policy_amendments.py tests/security/home/test_guest_session_policy.py tests/unit/policy/test_risk_matrix.py tests/acceptance/home/test_authorization_corpus.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(policy): register guarded home amendments"
```

### Task 07: Extend the offline grammar and exact light target resolver

**Depends on:** Tasks 01–03, 06 and Phase 1 offline grammar.
**Gate contribution:** P2-E0, P2-4, P2-7.
**Estimated effort:** 1 engineering person-day.

**Files:**
- Modify: `apps/core/src/tuntun_core/domain/offline.py`
- Modify: `apps/core/src/tuntun_core/offline/grammar.py`
- Modify: `apps/core/src/tuntun_core/offline/router.py`
- Create: `apps/core/src/tuntun_core/services/home/target_resolver.py`
- Create: `scripts/phase2/build_light_grammar_corpus.py`
- Create: `fixtures/synthetic/home/light-utterances-v1.jsonl`
- Create: `tests/unit/offline/test_home_light_grammar.py`
- Create: `tests/property/home/test_target_resolution.py`
- Create: `tests/security/home/test_offline_home_action_lifecycle.py`

**Interfaces:** Extends `OfflineIntent` with only `light_set_power` and `light_set_brightness`; `resolve_light_target(intent, visible_aliases, context) -> ExactTarget | AmbiguousTarget | NoTarget`; local grammar produces a typed proposal, never an action/signature; production ingress requires the Reachy isolation flag.

- [ ] **Step 1: Write red closed-grammar and ambiguity tests**

```python
@pytest.mark.parametrize("text", ["kitchen light on", "रसोई की लाइट चालू करो", "kitchen ki light 40 percent karo"])
def test_registered_light_phrases_return_typed_intent(text, registry) -> None:
    match = parse_offline(text, None, registry.synthetic_aliases())
    assert match.intent in {"light_set_power", "light_set_brightness"}

def test_homonym_never_guesses(resolver) -> None:
    result = resolver.resolve(intent(alias="lamp"), aliases=[living_lamp(), study_lamp()])
    assert result.kind == "ambiguous" and result.targets == ()
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/offline/test_home_light_grammar.py tests/property/home/test_target_resolution.py tests/security/home/test_offline_home_action_lifecycle.py -q`
Expected: FAIL because `light_set_power` is not a registered `OfflineIntent` and `target_resolver.py` is absent.

- [ ] **Step 3: Implement bounded multilingual patterns and exact resolution**

```python
LIGHT_POWER = re.compile(r"^(?P<alias>[\w\- ]{1,64}) (?:light )?(?P<state>on|off)$", re.IGNORECASE)
LIGHT_BRIGHTNESS = re.compile(r"^(?P<alias>[\w\- ]{1,64}) (?:light )?(?P<value>[1-9]|[1-9][0-9]|100)(?: percent|%)$", re.IGNORECASE)

def resolve_light_target(intent, visible_aliases, context):
    matches = tuple(binding for binding in visible_aliases if binding.normalized_alias == intent.normalized_alias and binding.scope_allows(context))
    return ExactTarget(matches[0]) if len(matches) == 1 else AmbiguousTarget() if matches else NoTarget()
```

Hindi/Hinglish patterns are separately enumerated in the generated corpus; transliteration is closed and no fuzzy location inference or guessed current `area_id` is allowed.

- [ ] **Step 4: Run green, 100 randomized resolver cases, and WAN-off branch tests**

Run: `uv run python scripts/phase2/build_light_grammar_corpus.py --check && uv run pytest tests/unit/offline/test_home_light_grammar.py tests/property/home/test_target_resolution.py tests/security/home/test_offline_home_action_lifecycle.py -q`
Expected: PASS; 100 randomized cases have zero wrong target; failed Reachy isolation makes production ingress absent while the authenticated loopback harness reaches only the post-intent path.

- [ ] **Step 5: Commit exact grammar/resolver paths**

```bash
git add apps/core/src/tuntun_core/domain/offline.py apps/core/src/tuntun_core/offline/grammar.py apps/core/src/tuntun_core/offline/router.py apps/core/src/tuntun_core/services/home/target_resolver.py scripts/phase2/build_light_grammar_corpus.py fixtures/synthetic/home/light-utterances-v1.jsonl tests/unit/offline/test_home_light_grammar.py tests/property/home/test_target_resolution.py tests/security/home/test_offline_home_action_lifecycle.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(offline): add exact local light intents"
```

---

## Wave 1 — P2-0 Green Boundary, Secure Channel, Read-Only State, and Recovery Baseline

### Task 08: Scaffold the Home Assistant custom integration and compiled light registry

**Depends on:** Tasks 01–02.
**Gate contribution:** P2-0, P2-3.
**Estimated effort:** 1 engineering person-day.

**Files:**
- Create: `integrations/home-assistant/pyproject.toml`
- Create: `integrations/home-assistant/custom_components/tuntun_bridge/manifest.json`
- Create: `integrations/home-assistant/custom_components/tuntun_bridge/__init__.py`
- Create: `integrations/home-assistant/custom_components/tuntun_bridge/const.py`
- Create: `integrations/home-assistant/custom_components/tuntun_bridge/models.py`
- Create: `integrations/home-assistant/custom_components/tuntun_bridge/canonical.py`
- Create: `integrations/home-assistant/custom_components/tuntun_bridge/config_flow.py`
- Create: `integrations/home-assistant/custom_components/tuntun_bridge/strings.json`
- Create: `integrations/home-assistant/custom_components/tuntun_bridge/translations/en.json`
- Create: `integrations/home-assistant/tests/conftest.py`
- Create: `integrations/home-assistant/tests/test_manifest.py`
- Create: `integrations/home-assistant/tests/test_compiled_registry.py`
- Create: `integrations/home-assistant/tests/test_no_credentials.py`

**Interfaces:** `CompiledLightRegistry.from_config(entry_data) -> CompiledLightRegistry`; `require_binding(endpoint_id, binding_generation, digest, entity_commitment) -> CompiledBinding`; integration domain `tuntun_bridge`; no config option accepts a token, service name, template, YAML, or wildcard. The package starts with all request routes and mutation handlers unregistered until later tasks install verified handlers.

- [ ] **Step 1: Write red manifest, registry, and no-credential tests**

```python
def test_manifest_is_core_integration_without_iot_class_escape(manifest) -> None:
    assert manifest["domain"] == "tuntun_bridge"
    assert manifest["integration_type"] == "service"
    assert "requirements" not in manifest

def test_registry_rejects_non_light_and_wildcard(registry_factory) -> None:
    with pytest.raises(ValueError, match="compiled_light_only"):
        registry_factory(entity_id="lock.synthetic_front")
    with pytest.raises(ValueError, match="exact_entity_required"):
        registry_factory(entity_id="light.*")

def test_config_and_runtime_hold_no_ha_or_supervisor_token(hass, config_entry) -> None:
    assert not recursive_key_match(config_entry.data, r"token|password|secret")
    assert "SUPERVISOR_TOKEN" not in os.environ
```

- [ ] **Step 2: Run red**

Run: `uv run pytest integrations/home-assistant/tests/test_manifest.py integrations/home-assistant/tests/test_compiled_registry.py integrations/home-assistant/tests/test_no_credentials.py -q`
Expected: FAIL because the `tuntun_bridge` package and manifest do not exist.

- [ ] **Step 3: Implement minimal package and exact compiled registry**

```python
DOMAIN = "tuntun_bridge"
MAX_LIGHT_ENDPOINTS = 12
ALLOWED_ACTIONS = frozenset({"light.set_power.v1", "light.set_brightness.v1"})

@dataclass(frozen=True, slots=True)
class CompiledBinding:
    endpoint_id: str
    entity_id: str
    entity_commitment: str
    binding_generation: int
    binding_digest: str
    capability_digest: str

    def __post_init__(self) -> None:
        if not self.entity_id.startswith("light.") or "*" in self.entity_id:
            raise ValueError("compiled_light_only")
```

`async_setup_entry` loads only validated public verification/config data, installs no standard HA credential, performs no device I/O, and exposes integration health as unavailable until store, verifier, and state-route tasks finish.

- [ ] **Step 4: Run green and Home Assistant quality checks**

Run: `uv run pytest integrations/home-assistant/tests/test_manifest.py integrations/home-assistant/tests/test_compiled_registry.py integrations/home-assistant/tests/test_no_credentials.py -q && uv run ruff check integrations/home-assistant && uv run mypy integrations/home-assistant/custom_components/tuntun_bridge`
Expected: PASS; config rejects a thirteenth endpoint, duplicate endpoint/entity, non-light domain, wildcard, token-like field, or malformed digest; no route or mutation handler is registered.

- [ ] **Step 5: Commit exact integration scaffold paths**

```bash
git add integrations/home-assistant/pyproject.toml integrations/home-assistant/custom_components/tuntun_bridge integrations/home-assistant/tests/conftest.py integrations/home-assistant/tests/test_manifest.py integrations/home-assistant/tests/test_compiled_registry.py integrations/home-assistant/tests/test_no_credentials.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(ha): scaffold closed Tuntun integration"
```

### Task 09: Implement the HA receipt store, migrations, retention, and quota gates

**Depends on:** Task 08.
**Gate contribution:** P2-0, P2-4, P2-5, P2-7.
**Estimated effort:** 1.5 engineering person-days.

**Files:**
- Create: `integrations/home-assistant/custom_components/tuntun_bridge/schema.py`
- Create: `integrations/home-assistant/custom_components/tuntun_bridge/store.py`
- Create: `integrations/home-assistant/tests/test_store_migrations.py`
- Create: `integrations/home-assistant/tests/test_store_durability.py`
- Create: `integrations/home-assistant/tests/test_store_retention.py`
- Create: `integrations/home-assistant/tests/test_store_quota.py`
- Create: `integrations/home-assistant/tests/test_store_corruption.py`

**Interfaces:** `ReceiptStore.open(path, *, trusted_clock, sealed_service_begin_port) -> ReceiptStore`; the clock and begin port are fixed for that store lifetime and retained explicitly across reopen; async methods `reserve_action`, `advance`, `terminalize`, `get_exact`, `compact`, `integrity_check`, `checkpoint`; database versions 1–3 from the migration map; one serialized writer and bounded read transactions.

- [ ] **Step 1: Write red durability, mismatch, retention, and pressure tests**

```python
async def test_pre_dispatch_is_durable_before_callback(store, action, fault) -> None:
    fault.raise_after("store.pre_dispatch_commit")
    with pytest.raises(InjectedCrash):
        await store.reserve_action(action)
    reopened = await ReceiptStore.open(
        store.path,
        trusted_clock=store.trusted_clock,
        sealed_service_begin_port=store.sealed_service_begin_port,
    )
    assert (await reopened.get_exact(action.action_id, action.idempotency_key)).state == "PRE_DISPATCH"

async def test_same_key_changed_payload_is_security_error(store, action) -> None:
    await store.reserve_action(action)
    with pytest.raises(SecurityError, match="duplicate_mismatch"):
        await store.reserve_action(action.model_copy(update={"desired_state": different_state()}))

async def test_pressure_never_purges_nonterminal(store) -> None:
    await fill_to_percent(store, 91, preserve_nonterminal=True)
    assert await store.mutations_allowed() is False
    assert await store.count_nonterminal() == SEEDED_NONTERMINAL
```

- [ ] **Step 2: Run red**

Run: `uv run pytest integrations/home-assistant/tests/test_store_migrations.py integrations/home-assistant/tests/test_store_durability.py integrations/home-assistant/tests/test_store_retention.py integrations/home-assistant/tests/test_store_quota.py integrations/home-assistant/tests/test_store_corruption.py -q`
Expected: FAIL because `tuntun_bridge.store.ReceiptStore` does not exist.

- [ ] **Step 3: Implement schema versions and synchronous-FULL writer semantics**

```python
async def open_store(
    path: Path, *, trusted_clock: TrustedClock,
    sealed_service_begin_port: SealedServiceBeginPort,
) -> ReceiptStore:
    db = await aiosqlite.connect(path)
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA synchronous=FULL")
    await db.execute("PRAGMA foreign_keys=ON")
    await migrate_user_version(db, target=3)
    return ReceiptStore(
        db, path, asyncio.Lock(), trusted_clock, sealed_service_begin_port,
    )

async def reserve_action(self, action):
    async with self._writer:
        await self._begin_immediate()
        prior = await self._find_idempotency(action.idempotency_key)
        if prior and prior.payload_hash != canonical_payload_hash(action):
            raise SecurityError("duplicate_mismatch")
        if prior:
            await self._rollback()
            return prior
        await self._insert_pre_dispatch(action)
        await self._commit()
```

Compaction computes deadlines from immutable `terminal_at`, replaces detail with keyed tombstone after 10 days, deletes live tombstone after 30 days, checkpoints and securely replaces the compacted file weekly, and never treats backup copies as erased. At 75% run integrity/eligible compaction and alert; at 90% reject new direct/scene/routine mutations.

- [ ] **Step 4: Run green including crash/reopen and corruption recovery**

Run: `uv run pytest integrations/home-assistant/tests/test_store_migrations.py integrations/home-assistant/tests/test_store_durability.py integrations/home-assistant/tests/test_store_retention.py integrations/home-assistant/tests/test_store_quota.py integrations/home-assistant/tests/test_store_corruption.py -q`
Expected: PASS; all three schema migrations round-trip, crash after commit retains `PRE_DISPATCH`, duplicate mismatch is rejected, immutable `terminal_at` controls both deletions, thresholds act at 75/90%, and corruption quarantines mutations without discarding nonterminal evidence.

- [ ] **Step 5: Commit exact receipt-store paths**

```bash
git add integrations/home-assistant/custom_components/tuntun_bridge/schema.py integrations/home-assistant/custom_components/tuntun_bridge/store.py integrations/home-assistant/tests/test_store_migrations.py integrations/home-assistant/tests/test_store_durability.py integrations/home-assistant/tests/test_store_retention.py integrations/home-assistant/tests/test_store_quota.py integrations/home-assistant/tests/test_store_corruption.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(ha): add durable bounded receipt store"
```

### Task 10: Implement pinned TLS channel proofs and Secure Enclave signing

**Depends on:** Tasks 01, 08–09 and Phase 1 passkey/local-presence services.
**Gate contribution:** P2-0, P2-3, P2-4.
**Estimated effort:** 2 engineering person-days plus the target-Mac probe.

**Files:**
- Create: `apps/core/src/tuntun_core/adapters/home_assistant/secure_enclave.py`
- Create: `apps/core/src/tuntun_core/adapters/home_assistant/signer.py`
- Create: `apps/core/src/tuntun_core/adapters/home_assistant/client.py`
- Create: `integrations/home-assistant/custom_components/tuntun_bridge/verifier.py`
- Create: `integrations/home-assistant/custom_components/tuntun_bridge/http.py`
- Create: `tests/unit/home/test_home_signer.py`
- Create: `tests/security/home/test_secure_enclave_required.py`
- Create: `tests/security/home/test_channel_proof.py`
- Create: `tests/security/home/test_tls_pinning.py`
- Create: `integrations/home-assistant/tests/test_verifier_lifecycle.py`
- Create: `integrations/home-assistant/tests/test_pre_auth_limits.py`
- Create: `tests/hardware/home/test_secure_enclave_probe.py`
- Create: `docs/operations/phase2-key-pairing.md`

**Interfaces:** `SecureEnclaveP256Provider.probe() -> HardwareKeyProbe`; `create_non_exportable(label) -> KeyDescriptor`; domain-separated `sign_channel`, `sign_action`, `sign_routine`; one process-global HA `VerifierService` with random 256-bit `verifier_generation`, nonce/challenge caches, key overlap at most 24 hours, and exact source-address defense-in-depth.

- [ ] **Step 1: Write red domain-separation, replay, reload, and pinning tests**

```python
def test_channel_signature_cannot_verify_as_action(signer, verifier, challenge) -> None:
    proof = signer.sign_channel(challenge)
    assert verifier.verify_channel(proof)
    with pytest.raises(SignatureError):
        verifier.verify_action(proof)

async def test_config_entry_reload_preserves_replay_cache(hass, verifier, valid_proof) -> None:
    await verifier.verify_request(valid_proof)
    await reload_config_entry(hass)
    with pytest.raises(ReplayError):
        await verifier.verify_request(valid_proof)

def test_tls_hostname_or_ca_replacement_fails(client_factory) -> None:
    with pytest.raises(TLSPinningError):
        client_factory(certificate=untrusted_replacement()).connect()
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/home/test_home_signer.py tests/security/home/test_secure_enclave_required.py tests/security/home/test_channel_proof.py tests/security/home/test_tls_pinning.py integrations/home-assistant/tests/test_verifier_lifecycle.py integrations/home-assistant/tests/test_pre_auth_limits.py -q`
Expected: FAIL because the signer, client, verifier, and route classes are absent.

- [ ] **Step 3: Implement exact proof transcript and lifecycle gates**

```python
CHANNEL_DOMAIN = b"tuntun-channel-v1\0"
ACTION_DOMAIN = b"tuntun-action-v1\0"
ROUTINE_DOMAIN = b"tuntun-routine-v1\0"

def channel_transcript(challenge, client_nonce):
    return canonical_join(CHANNEL_DOMAIN, challenge.challenge_id, challenge.server_nonce, client_nonce,
                          challenge.controller_epoch, challenge.verifier_generation, challenge.route,
                          challenge.issued_at, challenge.expires_at)
```

The pre-auth parser limits bodies to 64 KiB, sources to five requests/second, failed proofs to twenty/minute, and streams to one. Channel proof expiry is at most 60 seconds; stream challenge expiry is at most 30 seconds and reauthentication occurs at least every 15 minutes. A Core restart/cache reset rotates generation and closes streams. Pairing/rotation requires a Phase 1 owner-passkey receipt plus separate local HA owner/admin confirmation; only public key metadata is stored on Green.

- [ ] **Step 4: Run green, then run the explicit target-Mac probe**

Run: `uv run pytest tests/unit/home/test_home_signer.py tests/security/home/test_secure_enclave_required.py tests/security/home/test_channel_proof.py tests/security/home/test_tls_pinning.py integrations/home-assistant/tests/test_verifier_lifecycle.py integrations/home-assistant/tests/test_pre_auth_limits.py -q`
Expected: PASS; noncanonical bodies, >30-second skew, >60-second expiry, replay, old generation/epoch/key, source mismatch, cross-domain signature, pin/hostname/downgrade failure, and request excess fail before state or mutation.

Owner run: `TUNTUN_ALLOW_HOME_HARDWARE=1 uv run pytest -m home_hardware tests/hardware/home/test_secure_enclave_probe.py -q --evidence-dir var/evidence/phase2/secure-enclave`
Expected positive result: `1 passed`; evidence reports `available=true`, `non_exportable=true`, and an actual sign/verify round trip. Expected negative result: test records `blocked_reason=secure_enclave_unavailable` and P2-3/P2-4 remain disabled; no file-key fallback is created.

- [ ] **Step 5: Commit exact channel/key paths without real evidence**

```bash
git add apps/core/src/tuntun_core/adapters/home_assistant/secure_enclave.py apps/core/src/tuntun_core/adapters/home_assistant/signer.py apps/core/src/tuntun_core/adapters/home_assistant/client.py integrations/home-assistant/custom_components/tuntun_bridge/verifier.py integrations/home-assistant/custom_components/tuntun_bridge/http.py tests/unit/home/test_home_signer.py tests/security/home/test_secure_enclave_required.py tests/security/home/test_channel_proof.py tests/security/home/test_tls_pinning.py integrations/home-assistant/tests/test_verifier_lifecycle.py integrations/home-assistant/tests/test_pre_auth_limits.py tests/hardware/home/test_secure_enclave_probe.py docs/operations/phase2-key-pairing.md
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(home): authenticate pinned HA channel"
```

### Task 11: Expose the channel-authenticated, read-only compiled state projection

**Depends on:** Tasks 08–10.
**Gate contribution:** P2-3.
**Estimated effort:** 1.5 engineering person-days.

**Files:**
- Create: `integrations/home-assistant/custom_components/tuntun_bridge/projection.py`
- Modify: `integrations/home-assistant/custom_components/tuntun_bridge/http.py`
- Create: `integrations/home-assistant/tests/test_state_route.py`
- Create: `integrations/home-assistant/tests/test_projection_privacy.py`
- Create: `integrations/home-assistant/tests/test_projection_cursor.py`
- Create: `integrations/home-assistant/tests/test_readiness_observation.py`
- Create: `tests/security/home/test_off_registry_read.py`
- Create: `tests/security/home/test_standard_ha_api_absence.py`

**Interfaces:** `ProjectionService.snapshot(request_nonce) -> HomeStateSnapshotV1`; `delta(cursor: StateCursorV1, request_nonce) -> HomeStateDeltaV1 | HomeStateSnapshotV1`; no caller-selected entity/filter/query body; 30-second heartbeat; sequence monotonic within one exact epoch/verifier stream; an unknown or foreign cursor returns a fresh full allowlisted snapshot; mutation routes remain absent. Every response includes strict `HAReadinessObservationV1`, bound to the exact outstanding channel request nonce, controller epoch, verifier generation, integration package/Core build/configuration digests, durable quarantine marker/state, a strictly increasing readiness sequence, and a maximum 60-second window. Pinned TLS authenticates HA and the channel proof authenticates/binds the request; HA does not sign the response and gains no second signing key.

- [ ] **Step 1: Write red positive projection and indistinguishable off-registry tests**

```python
async def test_snapshot_contains_exact_registered_light_projection(client, compiled_registry) -> None:
    response = await client.signed_get("/api/tuntun/v1/state")
    assert {row.endpoint_id for row in response.endpoints} == compiled_registry.endpoint_ids
    assert all(row.ha_entity_id is None for row in response.endpoints)

async def test_validly_signed_off_registry_attempt_has_no_lookup_or_state(client, spy_registry) -> None:
    first = await client.signed_post("/api/tuntun/v1/state", {"entity_id": "lock.synthetic"})
    second = await client.signed_post("/api/tuntun/v1/state", {"entity_id": "light.synthetic_unknown"})
    assert (first.status, first.body) == (second.status, second.body)
    assert spy_registry.lookups == ()

async def test_readiness_echoes_exact_nonce_and_advances(client, current_builds) -> None:
    first = await client.signed_snapshot(request_nonce="a" * 64)
    second = await client.signed_snapshot(request_nonce="b" * 64)
    assert first.readiness.request_nonce == "a" * 64
    assert second.readiness.request_nonce == "b" * 64
    assert second.readiness.readiness_sequence > first.readiness.readiness_sequence
    assert second.readiness.integration_package_digest == current_builds.integration
```

- [ ] **Step 2: Run red**

Run: `uv run pytest integrations/home-assistant/tests/test_state_route.py integrations/home-assistant/tests/test_projection_privacy.py integrations/home-assistant/tests/test_projection_cursor.py integrations/home-assistant/tests/test_readiness_observation.py tests/security/home/test_off_registry_read.py -q`
Expected: FAIL because `ProjectionService` and state handler are absent.

- [ ] **Step 3: Implement full/delta projection and heartbeat**

```python
async def snapshot(self, request_nonce: str):
    heartbeat_at = self._clock.now()
    cursor = self._next_cursor()
    readiness = await self._readiness.observe_atomic(
        request_nonce=request_nonce,
        readiness_sequence=cursor.sequence,
        observed_at=heartbeat_at,
    )
    rows = tuple(self._normalize(self._hass.states.get(binding.entity_id), binding)
                 for binding in self._registry.bindings_canonical_order())
    return HomeStateSnapshotV1(
        state_schema_version="1.0",
        cursor=cursor,
        endpoints=rows,
        health=self._health.canonical_snapshot(heartbeat_at),
        readiness=readiness,
        heartbeat_at=heartbeat_at,
    )
```

Only stable endpoint ID, entity commitment, topology/binding/capability generations/digests, normalized light state, availability, source/time, sequence, separate Core/Zigbee-side health, and the closed readiness observation leave HA. The observation is constructed only after the channel proof consumes the single-use request nonce; it echoes that nonce, samples the durable marker/gate state and exact local digests in one read transaction, and allocates its sequence from the same process-global verifier stream. No raw HA attributes, entity IDs, credential, reusable proof, or response signature leave the route.

- [ ] **Step 4: Run green and standard-API escape attempts**

Run: `uv run pytest integrations/home-assistant/tests/test_state_route.py integrations/home-assistant/tests/test_projection_privacy.py integrations/home-assistant/tests/test_projection_cursor.py integrations/home-assistant/tests/test_readiness_observation.py tests/security/home/test_off_registry_read.py tests/security/home/test_standard_ha_api_absence.py -q`
Expected: PASS; positive projection and readiness observation are exact; an unsolicited/substituted nonce, duplicate/nonadvancing sequence, mismatched epoch/generation/digest, marker/state contradiction, or stale observation is rejected; unknown cursor returns a snapshot; excluded entities produce no distinguishing result; direct REST/WebSocket/template/script/scene/automation calls have no credential; action/routine custom routes return `404`.

- [ ] **Step 5: Commit exact read-only projection paths**

```bash
git add integrations/home-assistant/custom_components/tuntun_bridge/projection.py integrations/home-assistant/custom_components/tuntun_bridge/http.py integrations/home-assistant/tests/test_state_route.py integrations/home-assistant/tests/test_projection_privacy.py integrations/home-assistant/tests/test_projection_cursor.py integrations/home-assistant/tests/test_readiness_observation.py tests/security/home/test_off_registry_read.py tests/security/home/test_standard_ha_api_absence.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(ha): expose minimized channel-authenticated light state"
```

### Task 12: Synchronize topology, freshness, capability drift, and home health on the Mac

**Depends on:** Tasks 03, 10–11.
**Gate contribution:** P2-3, P2-4.
**Estimated effort:** 1.5 engineering person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/adapters/home_assistant/state_sync.py`
- Create: `apps/core/src/tuntun_core/services/home/health.py`
- Modify: `apps/core/src/tuntun_core/services/home/topology_registry.py`
- Create: `tests/integration/home/test_state_sync.py`
- Create: `tests/integration/home/test_home_freshness.py`
- Create: `tests/security/home/test_capability_drift.py`
- Create: `tests/fault/home/test_state_stream_reconnect.py`

**Interfaces:** `HomeStateSynchronizer.apply(snapshot|delta) -> SyncReceipt`; `HomeHealthService.preflight(endpoint_id, now) -> HomeExecutionEligibility`; active query completes within two seconds, observation age at most five seconds, heartbeat every 30 seconds, two missed heartbeats disables all Tuntun light mutations; Core health and Zigbee-side health remain distinct.

- [ ] **Step 1: Write red stale/drift/reconnect tests**

```python
@pytest.mark.parametrize("condition", ["query_over_2s", "observation_over_5s", "two_heartbeats_missed", "zigbee_unhealthy"])
async def test_preflight_fails_closed(health, condition) -> None:
    health.inject(condition)
    assert (await health.preflight(EP, NOW)).eligible is False

async def test_capability_digest_drift_quarantines_binding(sync, current_binding) -> None:
    receipt = await sync.apply(delta_for(current_binding, capability_digest="sha256:" + "9" * 64))
    assert receipt.binding_state == "quarantined"
    assert receipt.invalidated_actions > 0
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/home/test_state_sync.py tests/integration/home/test_home_freshness.py tests/security/home/test_capability_drift.py tests/fault/home/test_state_stream_reconnect.py -q`
Expected: FAIL because `HomeStateSynchronizer` and `HomeHealthService` do not exist.

- [ ] **Step 3: Implement cursor/idempotency/freshness processing**

```python
async def apply(self, message):
    self._schemas.require_supported(message)
    async with self._uow_factory() as uow:
        prior = await uow.home_state.cursor_for_update()
        if message.cursor <= prior.cursor:
            return SyncReceipt.duplicate(message.cursor)
        receipt = await self._apply_exact_projection(uow, message)
        await uow.home_state.advance_cursor(message.cursor, message.heartbeat_at)
        await self._audit.append(uow, receipt.audit())
        await uow.commit()
        return receipt
```

Unknown schemas are quarantined before payload use. Reordered/duplicate deltas cannot roll state back. Reconnect begins with a signed challenge and uses snapshot if cursor continuity cannot be proved.

- [ ] **Step 4: Run green and affected topology/action eligibility tests**

Run: `uv run pytest tests/integration/home/test_state_sync.py tests/integration/home/test_home_freshness.py tests/security/home/test_capability_drift.py tests/fault/home/test_state_stream_reconnect.py tests/integration/home/test_topology_generation.py -q`
Expected: PASS; stale, unavailable, duplicate, reordered, unknown-schema, capability-drift, Core-down, and Zigbee-down cases are independently represented and ineligible for mutation.

- [ ] **Step 5: Commit exact state-sync paths**

```bash
git add apps/core/src/tuntun_core/adapters/home_assistant/state_sync.py apps/core/src/tuntun_core/services/home/health.py apps/core/src/tuntun_core/services/home/topology_registry.py tests/integration/home/test_state_sync.py tests/integration/home/test_home_freshness.py tests/security/home/test_capability_drift.py tests/fault/home/test_state_stream_reconnect.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(home): synchronize truthful HA state"
```

### Task 13: Add Phase 2 owner API read models and inventory/permission/health UI

**Depends on:** Tasks 03, 06, 12 and Phase 1 prepared-mutation/UI shell.
**Gate contribution:** P2-0, P2-3.
**Estimated effort:** 1.5 engineering person-days.

**Files:**
- Create: `packages/contracts/src/tuntun_contracts/features.py`
- Create: `schemas/features/v1/feature-manifest-v1.schema.json`
- Create: `schemas/features/v1/feature-manifest-rollover-chain-v1.schema.json`
- Create: `schemas/features/v1/feature-authority-campaign-evidence-v1.schema.json`
- Create: `fixtures/synthetic/features/phase2-home-manifest-v1.json`
- Create: `fixtures/synthetic/features/phase2-home-rollover-chain-v1.json`
- Create: `fixtures/synthetic/features/phase2-feature-authority-campaign-v1.json`
- Modify: `scripts/phase2/generate_home_schemas.py`
- Create: `apps/core/src/tuntun_core/services/features/__init__.py`
- Create: `apps/core/src/tuntun_core/services/features/lease.py`
- Create: `apps/core/src/tuntun_core/services/features/rollover.py`
- Create: `apps/core/src/tuntun_core/services/features/staging.py`
- Create: `apps/core/src/tuntun_core/services/features/registry.py`
- Modify: `apps/core/src/tuntun_core/cli/main.py`
- Create: `apps/core/src/tuntun_core/cli/commands/features.py`
- Create: `scripts/phase2/prepare_feature_manifest_rollover.py`
- Create: `scripts/phase2/assemble_feature_manifest_rollover.py`
- Create: `scripts/phase2/verify_feature_manifest_rollover.py`
- Create: `apps/core/src/tuntun_core/api/routes/features.py`
- Create: `apps/core/src/tuntun_core/api/home_dtos.py`
- Create: `apps/core/src/tuntun_core/api/routes/home.py`
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `packages/contracts/openapi/admin-v1.yaml`
- Modify: `apps/admin/src/api/generated/admin-v1.ts`
- Create: `apps/admin/src/app/feature-registry.ts`
- Modify: `apps/admin/src/app/router.tsx`
- Create: `apps/admin/src/features/home/index.ts`
- Create: `apps/admin/src/features/home/inventory.tsx`
- Create: `apps/admin/src/features/home/permissions.tsx`
- Create: `apps/admin/src/features/home/health.tsx`
- Create: `apps/admin/src/routes/home-inventory.tsx`
- Create: `apps/admin/src/routes/home-permissions.tsx`
- Create: `apps/admin/src/routes/home-health.tsx`
- Create: `tests/contract/api/test_home_openapi.py`
- Create: `tests/contract/api/test_feature_manifest.py`
- Create: `tests/security/test_home_admin_api.py`
- Create: `tests/security/test_home_feature_registration.py`
- Create: `tests/integration/home/test_phase2_boot_composition.py`
- Create: `tests/integration/home/test_feature_manifest_rollover.py`
- Create: `tests/integration/cli/test_feature_manifest_rollover_ceremony.py`
- Create: `tests/integration/cli/test_feature_manifest_stage_rollover.py`
- Create: `tests/security/test_feature_manifest_stage_rollover.py`
- Create: `tests/fault/home/test_feature_manifest_rollover_races.py`
- Create: `tests/support/feature_authority_campaign.py`
- Create: `tests/support/test_feature_authority_campaign.py`
- Create: `docs/operations/feature-manifest-rollover.md`
- Create: `tests/e2e/home-inventory.spec.ts`
- Create: `tests/e2e/home-permissions.spec.ts`
- Create: `tests/e2e/home-health.spec.ts`
- Create: `tests/e2e/home-feature-absence.spec.ts`
- Create: `tests/e2e/home-performance.spec.ts`

**Interfaces:** `SignedFeatureManifestV1` contains manifest version, rollover chain/index/previous-envelope digest, candidate/package digest, actual external `issued_at`, future-capable `valid_from`, expiry, signer key ID/signature, and exact `FeatureRegistrationV1` rows binding feature ID to non-overlapping backend provider IDs and route IDs, UI module ID/chunk digest, contract/schema/policy/corpus/migration/package digests, positive gate evidence hash, and negative-reachability evidence hash. It requires `issued_at <= valid_from < expires_at <= valid_from + 24h`; pre-issuance never falsifies signing time or opens future authority early. Duplicate IDs inside one row or provider/route aliasing across rows are invalid, so ownership and disable semantics are unambiguous. Its canonical envelope uses the Phase 1 `EvidenceSigner`/`SignerRegistry` with expected purpose `acceptance` and discriminator `tuntun.feature-manifest.v1`; runtime code has no reference to that signer and cannot self-sign or accept another acceptance payload type. `SignedFeatureManifestRolloverChainV1` is the shared Phase 2–6 multi-day authority: an external ceremony pre-issues up to 256 at-most-24-hour envelopes, enough for the later 90-day/three-month campaign with margin; index zero forbids a previous digest, each later version exact-hash-chains the prior signed envelope, strictly advances both `valid_from` and expiry while overlapping its predecessor, and preserves byte-identical candidate/package/registration authority for the frozen campaign. `FeatureAuthorityCampaignEvidenceV1` is the shared signed-evidence projection: it binds chain ID/digest, exact planned coverage, ordered unique manifest digests, exactly one ordered transition-receipt digest per successor, any restart-activation receipts, the per-admission sample-log digest, and literal-zero early/expired/gap/stale-generation/runtime-signer/runtime-renewal counts. `FeatureRegistry.verify_and_load` rejects unknown, not-yet-valid, expired, unsigned, untrusted-signer, rollback, skipped-version, chain-mismatched, nonextending, widened, or drifted authority before registering either side.

The reusable `FeatureManifestLeaseSupervisor` owns one immutable composition generation and a `FeatureAuthorityLease`. At boot or rollover it verifies the whole envelope and current durable safety gates, refuses activation before `valid_from`, samples trusted wall and monotonic clocks together, and derives `monotonic_deadline_ns = sampled_monotonic_ns + (expires_at - sampled_wall_time)`. Every request admission, prepared-mutation commit/retry, background trigger, and provider call exact-compares the active manifest/version/composition generation and requires `valid_from <= now < expires_at` plus `monotonic_now < monotonic_deadline_ns`; wall rollback therefore cannot open future authority or extend expired authority. Before a scheduled rollover it verifies and stages the next externally signed envelope and constructs the complete container/router generation without exposing it. One serialized CAS closes the old admission barrier, invalidates old prepared work, swaps the entire immutable provider/route/lease generation, and opens the new barrier; it never incrementally adds one route or permits two generations. A restart during staging reopens only the last durably active unexpired version; a restart after the CAS opens only the new version. Failure, equality with either deadline, or absence of a valid next envelope leaves admission closed and initiates controlled process recomposition. Rollover-chain tests prove contiguous versions/digests, overlapping validity, no early, expired, or unsigned admission, no authority gap at the atomic handoff, and zero stale preparation/trigger/provider use across pause points. Later Phases 3–6 import this same supervisor and rollover contract rather than inventing another lease.

`prepare_feature_manifest_rollover.py` freezes chain identity, contiguous indices/versions, exact candidate/package/registration/evidence authority, and overlapping at-most-24-hour validity slots with strictly advancing starts and expiries, without importing a signer. The existing isolated Phase 1 acceptance ceremony then processes slots sequentially: it records each actual `issued_at`, sets index zero's predecessor to `None` or derives the next predecessor from the complete prior signed envelope, canonicalizes the full envelope, and returns its external key ID/signature. `assemble_feature_manifest_rollover.py` independently reconstructs and verifies every signed byte against the trusted acceptance registry, then creates its output with exclusive create, mode `0600`, file fsync and parent-directory fsync so the result is directly eligible for the offline importer; it refuses to overwrite or follow an existing path. `verify_feature_manifest_rollover.py` proves full planned-interval coverage and exact installed-candidate equality. All three tools reject signer/private-key arguments and network access. Tests inspect their import/call graph, prove they cannot create or renew a signature, and reject dishonest signing time, wrong signer, missing/reordered record, an equal or backward successor start, chain gap, nonextending expiry, authority drift, insufficient coverage, unsafe output path/mode and more than 256 slots. These tools exist before P2-1 so every Phase 2 multi-day hardware or soak campaign can use the same ceremony.

Task 13 is also the sole owner of the phase-neutral test oracle `tests/support/feature_authority_campaign.py` and its conformance suite. `require_feature_authority_campaign(...)` bounded-nofollow reopens the content-addressed chain, signed envelopes, transition/restart receipts and per-admission log; exact-compares them with `FeatureAuthorityCampaignEvidenceV1`; and returns only after proving continuous half-open wall and monotonic authority for the frozen candidate/composition. A counted campaign must begin under an initial controlled-restart receipt for chain index zero, at or after its `valid_from` and before its expiry; it cannot silently skip ceremony-expired slots and later claim all successor transitions. The closed fault catalog covers a missing or stale initial activation receipt or a nonzero initial index; a missing, extra, reordered, late, signature-invalid, or equal/backward-`valid_from` successor; candidate or registration drift; future activation; wall-expiry equality or rollback; monotonic-expiry equality; stale composition; and the Cartesian set of restart immediately before/after the rollover CAS × missing/duplicate/substituted × transition/restart receipt. Every injected fault must produce zero delta in admission, prepared-work commit, provider call, trigger and physical-effect counters after the fault boundary. Phases 3–6 import this helper and run the same conformance suite against their campaign adapters; they neither copy it nor depend on a later phase to define it.

The existing local operator executable gains `tuntunctl features stage-rollover --file PATH` solely to recover or extend authority while Core is stopped. It contains no signer, key-generation, renewal, network-fetch, activation, or in-process route-mounting capability. A descriptor-relative nofollow walk opens at most 16 MiB of canonical input under the effective local owner's control, requires a regular single-link `0600` file beneath owner-controlled non-group/world-writable directories, rejects symlinks, devices, hard-link substitution, oversize/extra-field/noncanonical input, and freezes descriptor/inode identity through verification. The command uses only the installed acceptance-signer registry and exact immutable installed-candidate metadata; it verifies every external signature plus chain identity/order/hash/coverage, and exact candidate, package, feature-registration and evidence digests before writing. It copies the already-signed canonical bytes to a `0600` same-filesystem private sibling beneath fixed `0700` `/private/var/lib/tuntun/features`, fsyncs the file and parent directory, atomically renames it to `staged-rollover-chain-v1.json`, fsyncs again, and emits only a content-safe digest receipt. Core must already be stopped; a live PID/listener or state-generation change aborts without replacing the prior staged chain. A subsequent controlled restart re-verifies the staged bytes and activates only an envelope for which `valid_from <= now < expires_at`; an expired or future-only set leaves all feature admission closed. This phase-neutral import path and staging format are inherited unchanged by Phases 3–6.

The accepted manifest remains the maximum composition authority for canonical `bootstrap/container.py` and `api/app.py`: providers and routes appear as one exact generation, route imports construct no authority, and an absent/drifted row leaves both absent. A durable safety gate may only subtract from that set. `test_phase2_boot_composition.py` exact-compares installed providers/routes with the accepted manifest intersected with current gates, including unknown/disabled direct-path absence. Phase 2 still uses the accepted Phase 1 local API process and does not pre-create Phase 3 owner ingress. `GET /api/v1/ui/features` exposes only the verified safe projection. Read routes are `GET /api/v1/ui/home/inventory`, `/permissions`, and `/health`. Typed mutations include area/zone, alias/binding, child-rule, delegated-grant, and Guest-session routes through Phase 1 428/step-up/retry. Area and zone writes require expected-generation CAS; UI models expose canonical `area_id` and optional generation-bound subordinate zone data, never raw HA entity IDs, credentials, or a parallel room key.

- [ ] **Step 1: Write red feature-gating and no-optimism tests**

```python
def test_home_routes_absent_without_signed_feature(client, feature_manifest) -> None:
    feature_manifest.remove("phase2.home.read")
    assert client.get("/api/v1/ui/home/inventory").json()["code"] == "FEATURE_ABSENT"

def test_manifest_digest_drift_registers_neither_backend_nor_ui(registry, signed_manifest) -> None:
    first = signed_manifest.registrations[0].model_copy(
        update={"package_digest": "sha256:" + "0" * 64}
    )
    tampered = signed_manifest.model_copy(
        update={"registrations": (first, *signed_manifest.registrations[1:])}
    )
    with pytest.raises(IntegrityError, match="feature_manifest_drift"):
        registry.verify_and_load(tampered)
    assert registry.registered_provider_ids == ()
    assert registry.registered_route_ids == ()

def test_feature_manifest_rejects_duplicate_rows_and_overlong_window(signed_manifest_fixture) -> None:
    row = signed_manifest_fixture["registrations"][0]
    with pytest.raises(ValidationError):
        SignedFeatureManifestV1.model_validate({
            **signed_manifest_fixture,
            "registrations": (row, row),
        })
    with pytest.raises(ValidationError):
        SignedFeatureManifestV1.model_validate({
            **signed_manifest_fixture,
            "expires_at": signed_manifest_fixture["valid_from"] + timedelta(hours=24, microseconds=1),
        })

def test_feature_manifest_rejects_cross_feature_provider_or_route_alias(signed_manifest_fixture) -> None:
    first, second, *rest = signed_manifest_fixture["registrations"]
    aliased = {
        **second,
        "backend_provider_ids": first["backend_provider_ids"],
        "backend_route_ids": first["backend_route_ids"],
    }
    with pytest.raises(ValidationError, match="cross_feature_provider_or_route_alias"):
        SignedFeatureManifestV1.model_validate({
            **signed_manifest_fixture,
            "registrations": (first, aliased, *rest),
        })

@pytest.mark.parametrize("mutation", [
    set_index_zero_previous_digest,
    break_previous_envelope_digest,
    skip_manifest_version,
    move_successor_valid_from_backward_or_equal,
    create_validity_gap,
    fail_to_extend_later_expiry,
    change_candidate_digest_mid_chain,
    widen_one_registration_mid_chain,
])
def test_preissued_rollover_chain_rejects_gap_rollback_or_drift(
    signed_rollover_chain_fixture, mutation,
) -> None:
    with pytest.raises(ValidationError):
        SignedFeatureManifestRolloverChainV1.model_validate(
            mutation(signed_rollover_chain_fixture)
        )

@pytest.mark.parametrize("boundary", ["wall_expiry", "monotonic_expiry"])
def test_feature_admission_is_half_open_at_both_expiries(active_lease, boundary) -> None:
    now, monotonic_ns = active_lease.sample_immediately_before(boundary)
    active_lease.require_admission(now=now, monotonic_ns=monotonic_ns)
    now, monotonic_ns = active_lease.sample_at(boundary)
    with pytest.raises(FeatureAbsent, match="lease_expired"):
        active_lease.require_admission(now=now, monotonic_ns=monotonic_ns)

def test_preissued_manifest_cannot_open_before_valid_from(future_lease) -> None:
    with pytest.raises(FeatureAbsent, match="lease_expired"):
        future_lease.require_admission(
            now=future_lease.wall_valid_from - timedelta(microseconds=1),
            monotonic_ns=future_lease.monotonic_deadline_ns - 1,
        )

async def test_rollover_cas_has_one_generation_and_no_admission_gap(rollover_harness) -> None:
    result = await rollover_harness.pause_at_every_atomic_handoff_boundary()
    assert result.active_generation_counts == (1,)
    assert result.expired_or_unsigned_admissions == 0
    assert result.uncovered_admission_samples == 0
    assert result.old_prepared_commits_after_swap == 0

def test_offline_stage_rollover_has_no_sign_or_activate_capability(staging_cli) -> None:
    result = staging_cli.stage_valid_externally_signed_chain(core_stopped=True)
    assert result.staged_digest
    assert staging_cli.signer_calls == ()
    assert staging_cli.network_calls == ()
    assert staging_cli.runtime_activation_calls == ()

@pytest.mark.parametrize("fault", [
    "core_running", "symlink", "hardlink_swap", "group_readable", "oversize",
    "noncanonical", "untrusted_signer", "candidate_drift", "registration_drift",
    "chain_gap", "expired_only", "core_state_generation_race",
    "interrupted_before_rename", "interrupted_after_file_fsync",
])
def test_offline_stage_rollover_rejects_unsafe_input_without_replacement(
    staging_cli, fault,
) -> None:
    before = staging_cli.current_staged_digest
    with pytest.raises(SafeOperatorError):
        staging_cli.stage_fault(fault)
    assert staging_cli.current_staged_digest == before

def test_future_external_chain_can_stage_but_cannot_activate_early(staging_cli) -> None:
    result = staging_cli.stage_valid_future_chain(core_stopped=True)
    assert result.staged_digest
    restart = staging_cli.controlled_restart(before_first_valid_from=True)
    assert restart.registered_provider_ids == ()
    assert restart.registered_route_ids == ()

def test_atomic_stage_restart_observes_old_or_complete_new_chain(staging_cli) -> None:
    observations = staging_cli.crash_at_every_fsync_and_rename_boundary()
    assert all(row.digest in {row.old_complete_digest, row.new_complete_digest} for row in observations)
    assert all(not row.partial_bytes_visible for row in observations)

def test_rollover_ceremony_tools_cannot_sign_or_fetch(ceremony_tools) -> None:
    bundle = ceremony_tools.prepare(valid_frozen_candidate, seven_day_coverage)
    assert ceremony_tools.signer_calls == ()
    assert ceremony_tools.network_calls == ()
    with pytest.raises(ExternalSignatureRequired):
        ceremony_tools.assemble(bundle, external_signing_records=())

FEATURE_AUTHORITY_CLOSED_FAULTS = (
    "missing_initial_activation_receipt", "stale_initial_activation_composition",
    "initial_activation_not_chain_index_zero",
    "missing_successor", "extra_successor", "reordered_successor",
    "late_successor", "signature_invalid_successor", "candidate_drift",
    "registration_drift", "future_activation", "wall_expiry_equality",
    "wall_rollback", "monotonic_expiry_equality", "stale_composition",
    *(
        f"restart_{side}_{cardinality}_{receipt}_receipt"
        for side in ("pre_cas", "post_cas")
        for cardinality in ("missing", "duplicate", "substituted")
        for receipt in ("transition", "restart")
    ),
)

@pytest.mark.parametrize("fault", FEATURE_AUTHORITY_CLOSED_FAULTS)
def test_shared_campaign_oracle_fails_closed_with_zero_post_fault_work(
    feature_authority_campaign_harness, fault,
) -> None:
    before = feature_authority_campaign_harness.effect_counters()
    with pytest.raises(FeatureAuthorityEvidenceError):
        feature_authority_campaign_harness.inject_and_verify(fault)
    after = feature_authority_campaign_harness.effect_counters()
    assert after.admissions - before.admissions == 0
    assert after.prepared_commits - before.prepared_commits == 0
    assert after.provider_calls - before.provider_calls == 0
    assert after.trigger_dispatches - before.trigger_dispatches == 0
    assert after.physical_effects - before.physical_effects == 0

def test_binding_mutation_ignores_client_authority_fields(client, owner_session) -> None:
    response = client.patch("/api/v1/home/bindings/synth", json={"ha_entity_id": "lock.bad", "policy_version": 999})
    assert response.status_code == 422

def test_area_is_the_only_location_key(client, owner_session) -> None:
    response = client.patch("/api/v1/home/areas/area_common_synth_01", json={"room_id": "legacy_synth", "expected_generation": 1})
    assert response.status_code == 422

def test_zone_parent_cannot_be_edited(client, owner_session) -> None:
    response = client.patch("/api/v1/home/zones/zone_boundary_synth_01", json={"area_id": "area_other_synth_01", "expected_generation": 1})
    assert response.status_code in {409, 422}
```

```typescript
test("unknown light remains unavailable rather than optimistic", async ({page}) => {
  await mockHomeInventory(page, {availability:"unknown", observed_state:null});
  await page.goto("/home/inventory");
  await expect(page.getByText("Unknown — control unavailable")).toBeVisible();
  await expect(page.getByRole("button", {name:"Turn on"})).toHaveCount(0);
});

test("absent home feature has no direct route or imported chunk", async ({page}) => {
  await mockSignedFeatures(page, []);
  await page.goto("/home/inventory");
  await expect(page).toHaveURL(/not-found/);
  expect(await loadedAssetNames(page)).not.toContain("home-inventory");
});
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/api/test_home_openapi.py tests/contract/api/test_feature_manifest.py tests/security/test_home_admin_api.py tests/security/test_home_feature_registration.py tests/security/test_feature_manifest_stage_rollover.py tests/integration/home/test_phase2_boot_composition.py tests/integration/home/test_feature_manifest_rollover.py tests/integration/cli/test_feature_manifest_rollover_ceremony.py tests/integration/cli/test_feature_manifest_stage_rollover.py tests/fault/home/test_feature_manifest_rollover_races.py tests/support/test_feature_authority_campaign.py -q && pnpm --filter @tuntun/admin e2e -- tests/e2e/home-inventory.spec.ts tests/e2e/home-permissions.spec.ts tests/e2e/home-health.spec.ts tests/e2e/home-feature-absence.spec.ts tests/e2e/home-performance.spec.ts`
Expected: FAIL with missing feature/rollover contracts, monotonic lease supervisor, canonical composition, home routes, signed registry, and UI route/chunk gating.

- [ ] **Step 3: Implement generated read models and feature-gated routes**

The registry recognizes only `phase2.home.read`, `phase2.home.actions`, `phase2.home.automations`, and `phase2.home.screen_time`, and registers each backend provider/route set and lazy UI module only after its P2-3/P2-4/P2-5/P2-6 evidence is present in an externally signed exact-candidate envelope. The implementation package exposes verification and staging ports but no signer port. `FeatureManifestLeaseSupervisor` durably records chain ID, active version/envelope digest and composition generation with compare-and-swap, derives the non-extendable monotonic lease, and is the mandatory first check at every route, prepared mutation, provider and trigger boundary. It preconstructs the next immutable full composition, then atomically swaps the entire generation; any failure closes the barrier before wall or monotonic equality and leaves a bounded feature-absent response. Crash tests at every staging/CAS/restart boundary prove one generation, no authority gap, no two-active interval, no rollback, and no stale work. The shared contract/supervisor module is phase-neutral so Phases 3–6 reuse it unchanged.

Build the canonical container first from the verified manifest, then compose `api/app.py` only from successfully constructed typed providers; any construction failure aborts boot rather than exposing a partial route. Unknown, absent, future, expired, schema/policy/migration/package-drifted, signature-invalid, untrusted-signer, chain-invalid, or monotonic-lease-expired rows register neither provider, backend route nor UI; the built candidate omits their client chunks. Mutations call the existing `MutationCoordinator` and bind the exact active manifest digest/composition generation so a rollover invalidates stale prepared work. Implement the shared campaign oracle as pure phase-neutral verification/test support: it has no signer, renewal, provider, router, trigger or physical-device capability and accepts adapters only for read-only evidence reopening and post-fault counters. The inventory groups display labels under canonical `area_id`; an optional zone is rendered only beneath its parent area with its exact owning binding/generation, never as another area or an ambiguity resolver. Area/zone edits invalidate every prepared device/media/camera operation bound to the replaced generation. The permissions view includes bounded Designated Guest session creation/cancellation and owner-passkey pending co-approval without exposing anonymous/child access. UI renders `healthy`, `active`, `disabled`, `absent`, `degraded`, `stale`, `unknown`, `quarantined`, and `error-safe` with text, timestamp, and manual fallback.

- [ ] **Step 4: Regenerate clients and run API/UI/accessibility gates**

Run: `uv run python scripts/phase2/generate_home_schemas.py --check && uv run pytest tests/contract/api/test_home_openapi.py tests/contract/api/test_feature_manifest.py tests/security/test_home_admin_api.py tests/security/test_home_feature_registration.py tests/security/test_feature_manifest_stage_rollover.py tests/integration/home/test_phase2_boot_composition.py tests/integration/home/test_feature_manifest_rollover.py tests/integration/cli/test_feature_manifest_rollover_ceremony.py tests/integration/cli/test_feature_manifest_stage_rollover.py tests/fault/home/test_feature_manifest_rollover_races.py tests/support/test_feature_authority_campaign.py -q && sh scripts/generate_openapi_client.sh && git diff --exit-code -- packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts && pnpm --filter @tuntun/admin test && pnpm --filter @tuntun/admin lint && pnpm --filter @tuntun/admin typecheck && pnpm --filter @tuntun/admin build && pnpm --filter @tuntun/admin e2e -- tests/e2e/home-inventory.spec.ts tests/e2e/home-permissions.spec.ts tests/e2e/home-health.spec.ts tests/e2e/home-feature-absence.spec.ts tests/e2e/home-performance.spec.ts`
Expected: PASS for at-most-24-hour envelopes, external acceptance-signer enforcement, complete pre-issued chain coverage, exact previous-envelope/version/candidate/registration binding, wall rollback, wall/monotonic expiry equality, rollover/restart races, one atomic active generation and no uncovered admission sample; runtime and offline staging import no acceptance signer. The shared campaign oracle rejects every closed successor/time/composition/restart-receipt fault and proves zero post-fault admission, prepared commit, provider/trigger call or physical effect. Nofollow/owner-only/bounded offline staging preserves the prior chain on every fault and a controlled restart activates only a currently valid externally signed envelope. UI passes English/Hindi, accessibility/responsive and performance gates; schemas/generated clients/browser storage/network capture contain no parallel room key, HA credential/entity ID, or policy binding; stale CAS and cross-area zone edits fail; missing/drifted/expired authority leaves direct URL/API/prepared-action/client registration and chunk absent.

- [ ] **Step 5: Commit exact API/UI paths**

```bash
git add packages/contracts/src/tuntun_contracts/features.py schemas/features/v1/feature-manifest-v1.schema.json schemas/features/v1/feature-manifest-rollover-chain-v1.schema.json schemas/features/v1/feature-authority-campaign-evidence-v1.schema.json fixtures/synthetic/features/phase2-home-manifest-v1.json fixtures/synthetic/features/phase2-home-rollover-chain-v1.json fixtures/synthetic/features/phase2-feature-authority-campaign-v1.json scripts/phase2/generate_home_schemas.py scripts/phase2/prepare_feature_manifest_rollover.py scripts/phase2/assemble_feature_manifest_rollover.py scripts/phase2/verify_feature_manifest_rollover.py apps/core/src/tuntun_core/services/features/__init__.py apps/core/src/tuntun_core/services/features/lease.py apps/core/src/tuntun_core/services/features/rollover.py apps/core/src/tuntun_core/services/features/staging.py apps/core/src/tuntun_core/services/features/registry.py apps/core/src/tuntun_core/cli/main.py apps/core/src/tuntun_core/cli/commands/features.py apps/core/src/tuntun_core/api/routes/features.py apps/core/src/tuntun_core/api/home_dtos.py apps/core/src/tuntun_core/api/routes/home.py apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts apps/admin/src/app/feature-registry.ts apps/admin/src/app/router.tsx apps/admin/src/features/home/index.ts apps/admin/src/features/home/inventory.tsx apps/admin/src/features/home/permissions.tsx apps/admin/src/features/home/health.tsx apps/admin/src/routes/home-inventory.tsx apps/admin/src/routes/home-permissions.tsx apps/admin/src/routes/home-health.tsx tests/contract/api/test_home_openapi.py tests/contract/api/test_feature_manifest.py tests/security/test_home_admin_api.py tests/security/test_home_feature_registration.py tests/security/test_feature_manifest_stage_rollover.py tests/integration/home/test_phase2_boot_composition.py tests/integration/home/test_feature_manifest_rollover.py tests/integration/cli/test_feature_manifest_rollover_ceremony.py tests/integration/cli/test_feature_manifest_stage_rollover.py tests/fault/home/test_feature_manifest_rollover_races.py tests/support/feature_authority_campaign.py tests/support/test_feature_authority_campaign.py tests/e2e/home-inventory.spec.ts tests/e2e/home-permissions.spec.ts tests/e2e/home-health.spec.ts tests/e2e/home-feature-absence.spec.ts tests/e2e/home-performance.spec.ts docs/operations/feature-manifest-rollover.md
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(admin): add truthful home inventory views"
```

### Task 14: Commission P2-0 inventory, network, Green recovery, and UPS topology

**Depends on:** Tasks 08–13. Home Assistant Green and a signalling-capable UPS/power-protection path are mandatory for the Phase 2 family-ready gate; before ordering the selected UPS model, verify its exact hardware revision has current NUT USB/network-driver support, capture a same-day landed quotation, and confirm the complete-load runtime target. If it fails that evidence gate, select another compatible model rather than weakening P2-0.
**Gate contribution:** P2-0.
**Estimated effort:** 1.5 engineering person-days plus physical power/restore time.

**Files:**
- Create: `scripts/phase2/inventory.py`
- Create: `scripts/phase2/probe_network.py`
- Create: `scripts/phase2/qualify_ups.py`
- Create: `scripts/phase2/verify_green_backup.py`
- Create: `ops/home-assistant/recorder-allowlist.example.yaml`
- Create: `ops/home-assistant/green-backup-catchup.example.yaml`
- Create: `ops/home-assistant/network-flow-policy.yaml`
- Create: `docs/operations/phase2-commissioning.md`
- Create: `docs/operations/phase2-network.md`
- Create: `docs/operations/phase2-green-backup-restore.md`
- Create: `docs/operations/phase2-ups.md`
- Create: `docs/privacy/phase2-home-data.md`
- Create: `tests/unit/phase2/test_inventory_redaction.py`
- Create: `tests/security/home/test_network_policy.py`
- Create: `tests/hardware/home/test_green_baseline.py`
- Create: `tests/hardware/home/test_ups_nut.py`
- Create: `tests/hardware/home/test_green_backup_restore.py`

**Interfaces:** Content-safe evidence records `phase2.inventory.v1`, `phase2.network-gate.v1`, `phase2.ups-gate.v1`, and `phase2.green-recovery.v1`; scripts hash real identifiers with an evidence-only key and never write raw setup codes, IP/MAC/serials, certificates, account names, or paths.

- [ ] **Step 1: Write red evidence redaction and topology tests**

```python
def test_inventory_output_is_content_safe(raw_synthetic_inventory) -> None:
    report = build_inventory(raw_synthetic_inventory, evidence_key=TEST_KEY)
    assert_forbidden_absent(report, ["192.168.", "aa:bb:", "setup-code", "/Users/"])
    assert report["mzhub"]["thread_radio"] in {"present", "absent", "unknown"}

def test_network_policy_has_only_required_inner_flows(policy) -> None:
    assert policy.public_inbound == ()
    assert policy.outer_interface_tuntun_admission == ()
    assert policy.green_to_mzhub == {"matter_ipv6", "mdns"}

def test_family_baseline_has_one_single_homed_mac(inventory, network_probe) -> None:
    assert inventory.physical_hosts.named({"office_laptop", "tuntun_mac"}) == {
        inventory.active_core_host_id,
    }
    assert inventory.active_core_host_id == inventory.owner_approved_core_target_id
    assert network_probe.enabled_interfaces(inventory.active_core_host_id) == {"inner_asus"}
    assert network_probe.outer_be800_link_state == "disconnected"

@pytest.mark.parametrize("drift", [
    "internet_sharing", "bridge", "ip_forwarding", "outer_listener",
    "cross_interface_transit", "dhcp_renewal", "interface_order", "default_route",
])
def test_optional_dual_home_drift_closes_family_ingress(dual_home_gate, drift) -> None:
    result = dual_home_gate.evaluate(drift=drift, probes_from=("outer_be800", "inner_asus"))
    assert result.family_automation_ingress == "disabled"
    assert result.reachy_admission == "disabled"
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/phase2/test_inventory_redaction.py tests/security/home/test_network_policy.py -q`
Expected: FAIL because inventory/network tools and flow policy are absent.

- [ ] **Step 3: Implement bounded probes, configuration templates, and recovery runbooks**

The commissioning runbook records one physical Phase 1 owner-approved active-Core inventory target for both office and Tuntun roles, its opaque target binding, selected inner-ASUS interface, and disconnected BE800 direct link, plus exact but local-only descriptive host observations and MZHUB/light/router/AiMesh/TV/phone/HAOS/Core/Matter Server/custom-integration/UPS versions, non-overlapping subnets and reservations, every AiMesh backhaul path, current native light recovery, wall-switch/mains behavior, certificate/key expiry, storage, and external-backup state. Descriptive architecture/model/product/year values cannot select or authorize the target. It disables UPnP/NAT-PMP/PCP, DMZ, WAN admin, public mappings, and HA Cloud remote access before claiming P2-0. If the owner later elects dual-homing, a distinct disabled-by-default profile proves no Internet Sharing/bridge/IP forwarding/transit; exact per-interface binds/routes/firewall/DNS; no outer-interface Tuntun, HA, or Reachy admission; restart/DHCP/interface-order/default-route safety; and negative probes from both networks. Any failed or unknown check closes family ingress.

The power diagram is exact: UPS outlets supply Green, GT-AX6000, required inner switch, and MZHUB; UPS USB/network signalling terminates at an audited NUT server app on Green; Green has host shutdown enabled; routers/switch/MZHUB receive measured ride-through only. The Green restore drill runs with production MZHUB/device paths powered down or on an electrically/network-isolated test LAN.

- [ ] **Step 4: Run synthetic gates, then owner-gated physical campaigns**

Run: `uv run pytest tests/unit/phase2/test_inventory_redaction.py tests/security/home/test_network_policy.py -q`
Expected: PASS; sample evidence is strict, content-safe, and distinguishes `unknown` from `absent`.

Owner runs:

```bash
TUNTUN_ALLOW_HOME_HARDWARE=1 uv run pytest -m home_hardware tests/hardware/home/test_green_baseline.py -q --evidence-dir var/evidence/phase2/p2-0-green
TUNTUN_ALLOW_NETWORK_PROBE=1 uv run python scripts/phase2/probe_network.py --policy ops/home-assistant/network-flow-policy.yaml --output var/evidence/phase2/p2-0-network.json
TUNTUN_ALLOW_UPS_TEST=1 uv run pytest -m home_hardware tests/hardware/home/test_ups_nut.py -q --evidence-dir var/evidence/phase2/p2-0-ups
TUNTUN_ALLOW_HOME_HARDWARE=1 uv run pytest -m home_hardware tests/hardware/home/test_green_backup_restore.py -q --evidence-dir var/evidence/phase2/p2-0-restore
```

Expected positive outcome: Green is locally healthy; inventory proves one single-homed Mac and the disabled BE800 link; no forwarding/public listener exists; outer/inner and Reachy negative probes pass; local encrypted backup restores in isolation; NUT telemetry survives reboot and shuts Green down before measured battery exhaustion; native lights were not reset. An optionally enabled dual-home profile additionally passes every per-interface and drift case above. Any failed check writes `eligible=false`, closes inbound family automation/Reachy admission, and blocks P2-1 without changing the existing light estate.

- [ ] **Step 5: Commit tools/templates/runbooks, never real evidence**

```bash
git add scripts/phase2/inventory.py scripts/phase2/probe_network.py scripts/phase2/qualify_ups.py scripts/phase2/verify_green_backup.py ops/home-assistant/recorder-allowlist.example.yaml ops/home-assistant/green-backup-catchup.example.yaml ops/home-assistant/network-flow-policy.yaml docs/operations/phase2-commissioning.md docs/operations/phase2-network.md docs/operations/phase2-green-backup-restore.md docs/operations/phase2-ups.md docs/privacy/phase2-home-data.md tests/unit/phase2/test_inventory_redaction.py tests/security/home/test_network_policy.py tests/hardware/home/test_green_baseline.py tests/hardware/home/test_ups_nut.py tests/hardware/home/test_green_backup_restore.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "ops(home): define P2-0 recovery baseline"
```

**P2-0 checkpoint:** Review the four content-safe evidence envelopes from ignored owner storage. Proceed only if no light was reset, existing native/physical control still works, Secure Enclave actual signing passed, Green/TLS/backup/recovery/storage and exact UPS/NUT topology passed, external/public mappings are absent, and every proposed P2-1 change has a tested manual recovery path.

---

## Wave 2 — P2-1/P2-2 Capability-Gated MZHUB and Light Commissioning

### Task 15: Probe the MZHUB without assuming Matter, Thread, or local control

**Depends on:** Task 13 feature-authority tooling and the P2-0 checkpoint.
**Gate contribution:** P2-1.
**Estimated effort:** 1 engineering person-day plus a non-compressible seven-day one-light pilot.

**Files:**
- Create: `scripts/phase2/probe_mzhub.py`
- Create: `apps/core/src/tuntun_core/domain/home/commissioning.py`
- Create: `fixtures/synthetic/home/mzhub-capability-samples.json`
- Create: `tests/unit/phase2/test_mzhub_capability_report.py`
- Create: `tests/unit/phase2/test_mzhub_pilot_feature_authority.py`
- Create: `tests/security/home/test_mzhub_no_assumptions.py`
- Create: `tests/hardware/home/test_mzhub_capability.py`
- Create: `tests/hardware/home/test_one_light_matter_pilot.py`
- Create: `docs/operations/phase2-mzhub-pilot.md`
- Create: `docs/evidence/phase2-mzhub-gate-schema.json`

**Interfaces:** `MzhubCapabilityReportV1` records operational VID, PID, hardware/firmware, attestation-chain and certification-declaration digests, commissioning-path evidence, and exactly seven canonically ordered `MzhubCapabilityFindingV1` rows for `matter_bridge`, `thread_radio`, `zigbee_coordinator`, `local_runtime`, `bidirectional_state`, `wan_off_runtime`, and `reboot_recovery`. `MzhubOneLightPilotReceiptV1` is a separately signed acceptance artifact over the exact report, one-light commitment, build/configuration, complete case set, zero false-success/wrong-target counts, and both wall-clock and monotonic elapsed time of at least 604,800 seconds. It also embeds `FeatureAuthorityCampaignEvidenceV1`: the complete externally pre-issued same-candidate chain ID/digest, ordered signed-envelope digests, exactly one ordered atomic transition-receipt digest for every successor, the mandatory initial controlled-restart activation receipt plus any later restart receipts, the per-admission sample-log digest, and literal-zero early/expired/gap/stale-generation/runtime-signer/runtime-renewal counts. Its authority coverage must begin no later than the pilot and end strictly after completion.

The hardware harness accepts one required `--feature-manifest-chain` produced by Task 13's prepare → isolated external signing → assemble/verify ceremony. The chain is staged with Core stopped and activated only by the commanded controlled restart; before the elapsed clock, the harness bounded-reopens that initial activation receipt, requires chain index zero inside its half-open window, and exact-compares its envelope/candidate/provider/route/composition generation with the supplied chain and live composition. `FeatureManifestLeaseSupervisor` then verifies full planned coverage and checks the active envelope's half-open wall window, process-local monotonic lease, envelope digest and composition generation at every sample and pilot action. Each rollover is the canonical whole-composition CAS and is durably receipted; a later restart is reactivated only under a current verified envelope. Missing/stale/nonzero initial activation, missing, late, reordered, wrong-signer, signature-invalid, widened, candidate-drifted, early, expired or unreceipted authority closes pilot work before I/O and invalidates the uninterrupted seven-day clock. Neither the harness nor runtime can sign, renew or silently extend the chain. `decide_mzhub_gate(report, pilot_receipt, accepted_product_registry, acceptance_verifier, current_pilot_authority) -> GateDecision` receives an `acceptance_verifier` built from Task 13's sole-owned `tests/support/feature_authority_campaign.py` oracle over the fixed owner-only content-addressed campaign evidence root; it uses the embedded digests to bounded-nofollow reopen the exact chain and transition/restart/sample artifacts with no network lookup. It then reloads and exact-compares the current light/build/configuration/chain after signature verification and can never return `PASS_BRIDGE` for another candidate or any authority gap.

- [ ] **Step 1: Write red no-inference and certified-baseline tests**

```python
def test_product_name_does_not_imply_any_radio(sample_named_mzhub) -> None:
    report = build_mzhub_report(sample_named_mzhub)
    findings = {row.capability: row.finding for row in report.findings}
    assert findings["matter_bridge"] == "unknown"
    assert findings["thread_radio"] == "unknown"
    assert findings["local_runtime"] == "unknown"

@pytest.mark.parametrize("field,replacement", [
    ("operational_vendor_id", 0xFFFF),
    ("operational_product_id", 0x9999),
    ("attestation_chain_digest", OTHER_SHA256),
    ("certification_declaration_digest", OTHER_SHA256),
])
def test_operational_identity_or_attestation_mismatch_is_different_variant(
    certified_report_payload, accepted_product_registry, acceptance_verifier,
    current_pilot_authority, field, replacement,
) -> None:
    changed = {**certified_report_payload, field: replacement}
    changed["report_digest"] = mzhub_report_digest(changed)
    report = MzhubCapabilityReportV1.model_validate(changed)
    decision = decide_mzhub_gate(
        report, None, accepted_product_registry, acceptance_verifier,
        current_pilot_authority,
    )
    assert decision.decision == "BLOCK_UNKNOWN"
    assert decision.reason == "oem_variant_not_proven"

def test_mzhub_report_digest_rejects_one_field_substitution(certified_report_payload) -> None:
    with pytest.raises(ValidationError, match="mzhub_report_digest_mismatch"):
        MzhubCapabilityReportV1.model_validate({
            **certified_report_payload,
            "firmware_version": "substituted",
        })

def test_forged_passed_report_without_verified_elapsed_pilot_cannot_pass(
    certified_report_payload, accepted_product_registry, acceptance_verifier,
    current_pilot_authority,
) -> None:
    forged = with_all_required_findings_passed(certified_report_payload)
    forged["report_digest"] = mzhub_report_digest(forged)
    report = MzhubCapabilityReportV1.model_validate(forged)
    decision = decide_mzhub_gate(
        report, None, accepted_product_registry, acceptance_verifier,
        current_pilot_authority,
    )
    assert decision == GateDecision("BLOCK_UNKNOWN", "one_light_pilot_not_proven")

def test_known_material_failure_precedes_other_unknown_findings(
    certified_report_payload, accepted_product_registry, acceptance_verifier,
    current_pilot_authority,
) -> None:
    mixed = set_mzhub_findings(
        certified_report_payload,
        matter_bridge="failed",
        reboot_recovery="unknown",
    )
    mixed["report_digest"] = mzhub_report_digest(mixed)
    decision = decide_mzhub_gate(
        MzhubCapabilityReportV1.model_validate(mixed),
        None,
        accepted_product_registry,
        acceptance_verifier,
        current_pilot_authority,
    )
    assert decision == GateDecision("FAIL_OPEN_FALLBACK", "bridge_gate_failed")

@pytest.mark.parametrize("mutation", [
    shorten_wall_elapsed_below_604800,
    shorten_monotonic_elapsed_below_604800,
    omit_required_case,
    fail_required_case,
    add_false_success,
    add_wrong_target,
    substitute_report_digest,
    substitute_light_commitment,
    invalidate_acceptance_signature,
])
def test_one_light_pilot_receipt_is_exact_and_noncompressible(
    pilot_receipt_fixture, report, accepted_product_registry,
    acceptance_verifier, current_pilot_authority, mutation,
) -> None:
    with pytest.raises((ValidationError, AcceptanceSignatureError)):
        decide_mzhub_gate(
            report,
            mutation(pilot_receipt_fixture),
            accepted_product_registry,
            acceptance_verifier,
            current_pilot_authority,
        )

@pytest.mark.parametrize("other_receipt", [
    valid_signed_pilot_for_other_light,
    valid_signed_pilot_for_other_build,
    valid_signed_pilot_for_other_configuration,
])
def test_valid_pilot_from_another_candidate_cannot_authorize_current_deployment(
    report, accepted_product_registry, acceptance_verifier,
    current_pilot_authority, other_receipt,
) -> None:
    decision = decide_mzhub_gate(
        report,
        other_receipt,
        accepted_product_registry,
        acceptance_verifier,
        current_pilot_authority,
    )
    assert decision == GateDecision("BLOCK_UNKNOWN", "one_light_pilot_candidate_mismatch")

@pytest.mark.parametrize("mutation", [
    remove_initial_activation_receipt,
    substitute_stale_initial_composition,
    remove_required_manifest,
    remove_transition_receipt,
    reorder_manifest_digests,
    substitute_wrong_signer_chain,
    create_authority_gap,
    record_early_or_expired_admission,
    drift_chain_candidate,
    record_stale_composition_generation,
    record_runtime_signer_or_renewal_call,
])
def test_one_light_pilot_rejects_incomplete_feature_authority(
    pilot_receipt_fixture, report, accepted_product_registry,
    acceptance_verifier, current_pilot_authority, mutation,
) -> None:
    # Mutation helpers use only the test acceptance signer so the semantic
    # verifier, not an earlier outer-signature failure, proves each rejection.
    decision = decide_mzhub_gate(
        report,
        mutation(pilot_receipt_fixture),
        accepted_product_registry,
        acceptance_verifier,
        current_pilot_authority,
    )
    assert decision == GateDecision("BLOCK_UNKNOWN", "pilot_feature_authority_invalid")
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/phase2/test_mzhub_capability_report.py tests/unit/phase2/test_mzhub_pilot_feature_authority.py tests/security/home/test_mzhub_no_assumptions.py -q`
Expected: FAIL because `MzhubCapabilityReportV1`, the pilot's strict feature-authority evidence verifier, and `probe_mzhub.py` do not exist.

- [ ] **Step 3: Implement independent findings and bridge decision**

```python
CERTIFIED_BASELINE = CertifiedProduct(
    operational_vendor_id=0x147D,
    operational_product_id=0x0638,
    hardware_version="1.0.4",
    firmware_version="2.0.0",
)

def decide_mzhub_gate(
    report, pilot_receipt, accepted_product_registry,
    acceptance_verifier, current_pilot_authority,
):
    accepted_identity = accepted_product_registry.resolve_exact(
        operational_vendor_id=report.operational_vendor_id,
        operational_product_id=report.operational_product_id,
        hardware_version=report.hardware_version,
        firmware_version=report.firmware_version,
        attestation_chain_digest=report.attestation_chain_digest,
        certification_declaration_digest=report.certification_declaration_digest,
    )
    if accepted_identity is None:
        return GateDecision("BLOCK_UNKNOWN", "oem_variant_not_proven")
    findings = {row.capability: row.finding for row in report.findings}
    required = tuple(findings[name] for name in (
        "matter_bridge", "local_runtime", "bidirectional_state",
        "wan_off_runtime", "reboot_recovery",
    ))
    if any(finding in {"failed", "not_present"} for finding in required):
        return GateDecision("FAIL_OPEN_FALLBACK", "bridge_gate_failed")
    if any(finding == "unknown" for finding in required):
        return GateDecision("BLOCK_UNKNOWN", "required_capability_unknown")
    if any(finding != "passed" for finding in required):
        return GateDecision("BLOCK_UNKNOWN", "required_capability_unrecognized")
    if pilot_receipt is None:
        return GateDecision("BLOCK_UNKNOWN", "one_light_pilot_not_proven")
    pilot = MzhubOneLightPilotReceiptV1.model_validate(pilot_receipt)
    acceptance_verifier.require_valid(
        pilot,
        expected_domain="tuntun.mzhub-one-light-pilot.v1",
        expected_purpose="acceptance",
    )
    if pilot.report_id != report.report_id or pilot.report_digest != report.report_digest:
        return GateDecision("BLOCK_UNKNOWN", "one_light_pilot_report_mismatch")
    current_tuple = (
        current_pilot_authority.one_light_identity_commitment,
        current_pilot_authority.build_digest,
        current_pilot_authority.configuration_digest,
        str(current_pilot_authority.rollover_chain_id),
        current_pilot_authority.rollover_chain_digest,
    )
    pilot_tuple = (
        pilot.one_light_identity_commitment,
        pilot.build_digest,
        pilot.configuration_digest,
        str(pilot.feature_authority.rollover_chain_id),
        pilot.feature_authority.rollover_chain_digest,
    )
    if not all(
        hmac.compare_digest(current, accepted)
        for current, accepted in zip(current_tuple, pilot_tuple, strict=True)
    ):
        return GateDecision("BLOCK_UNKNOWN", "one_light_pilot_candidate_mismatch")
    try:
        acceptance_verifier.require_feature_authority_campaign(
            pilot.feature_authority,
            expected_candidate=current_pilot_authority,
            actual_started_at=pilot.started_at,
            actual_completed_at=pilot.completed_at,
        )
    except FeatureAuthorityEvidenceError:
        return GateDecision("BLOCK_UNKNOWN", "pilot_feature_authority_invalid")
    return GateDecision("PASS_BRIDGE", "one_light_pilot_passed")
```

`thread_radio` is recorded and displayed but excluded from the bridge decision. The script never resets/unpairs a light and never claims the MZHUB can be used as a Thread border router.

`phase2-mzhub-gate-schema.json` is recursively closed and references the exact generated `FeatureAuthorityCampaignEvidenceV1` schema. It requires the chain and receipt-digest arrays plus every literal-zero authority counter; a caller-authored `passed` Boolean, omitted transition, free-form signer claim, or unbounded evidence object cannot validate.

- [ ] **Step 4: Run synthetic tests; after Step 5, freeze and run the one-light elapsed campaign**

Run: `uv run pytest tests/unit/phase2/test_mzhub_capability_report.py tests/unit/phase2/test_mzhub_pilot_feature_authority.py tests/security/home/test_mzhub_no_assumptions.py -q`
Expected: PASS for certified, documented-update, mismatched-OEM, no-Matter, unknown-Thread, no-WAN-off, stale-state, and reboot-failure synthetic records.

Owner run below is deferred until Step 5 has committed the tooling and `git status --porcelain` is empty. Choose and export recorded `P2_1_START_RFC3339`/`P2_1_END_RFC3339` bounds spanning the full run plus bounded margin, with index zero starting far enough in the future to complete signing, transfer, verification and staging; the block captures the exact current `HEAD` itself and fails if either bound is absent. If that first window is missed, or source/configuration/manifest/hardware identity changes, discard the attempt and restart this subsection from the beginning rather than activating a successor:

```bash
test -z "$(git status --porcelain)"
P2_1_CANDIDATE_COMMIT="$(git rev-parse HEAD)"
: "${P2_1_START_RFC3339:?export P2_1_START_RFC3339}"
: "${P2_1_END_RFC3339:?export P2_1_END_RFC3339}"
uv run python scripts/phase2/prepare_feature_manifest_rollover.py --candidate-commit "$P2_1_CANDIDATE_COMMIT" --manifest-template fixtures/synthetic/features/phase2-home-manifest-v1.json --coverage-start "$P2_1_START_RFC3339" --coverage-end "$P2_1_END_RFC3339" --max-window-seconds 86400 --overlap-seconds 300 --output var/evidence/phase2/p2-1-feature-authority/unsigned-rollover-bundle.json
# Complete the isolated external acceptance-signing ceremony from docs/operations/feature-manifest-rollover.md.
uv run python scripts/phase2/assemble_feature_manifest_rollover.py --unsigned-bundle var/evidence/phase2/p2-1-feature-authority/unsigned-rollover-bundle.json --external-signing-records /absolute/owner-only/p2-1-external-signing-records.json --signer-registry security/evidence-signers-v1.json --output var/evidence/phase2/p2-1-feature-authority/signed-rollover-chain.json
uv run python scripts/phase2/verify_feature_manifest_rollover.py --chain var/evidence/phase2/p2-1-feature-authority/signed-rollover-chain.json --commit "$P2_1_CANDIDATE_COMMIT" --coverage-start "$P2_1_START_RFC3339" --coverage-end "$P2_1_END_RFC3339"
uv run tuntunctl service stop
uv run --frozen --offline --no-sync tuntunctl features stage-rollover --file var/evidence/phase2/p2-1-feature-authority/signed-rollover-chain.json
# At/after index zero valid_from and strictly before its expiry, perform the controlled start.
uv run tuntunctl service start
TUNTUN_ALLOW_MZHUB_PROBE=1 uv run pytest -m home_hardware tests/hardware/home/test_mzhub_capability.py -q --evidence-dir var/evidence/phase2/p2-1-capability
TUNTUN_ALLOW_ELAPSED_PHASE2=1 uv run pytest -m "home_hardware and elapsed" tests/hardware/home/test_one_light_matter_pilot.py -q --duration-seconds 604800 --feature-manifest-chain var/evidence/phase2/p2-1-feature-authority/signed-rollover-chain.json --feature-authority-evidence-root var/evidence/phase2/p2-1-feature-authority --evidence-dir var/evidence/phase2/p2-1-one-light
```

Expected `PASS_BRIDGE`: exact attestation/certification provenance is valid; one easy-to-recover light exposes every required feature; physical/vendor/HA changes reconcile bidirectionally; WAN is already absent during cold boot; Green/Matter Server/MZHUB/router restarts recover; every AiMesh path discovers; Ethernet-up/Zigbee-down becomes stale/unavailable; and zero false success or wrong target occurs for seven elapsed days. The receipt binds the exact initial live-composition activation, complete same-candidate chain, every ordered envelope and rollover/restart receipt, per-admission wall/monotonic lease evidence, zero expired-authority interval, and zero runtime signer/renewal call. Any authority fault closes work and restarts the seven-day clock. Expected `FAIL_OPEN_FALLBACK`: native light estate remains unchanged and P2-F becomes eligible for owner decision. Expected `BLOCK_UNKNOWN`: gather manufacturer/certification/feature-authority evidence or keep Phase 2 light mutation disabled.

- [ ] **Step 5: Commit probe code, schemas, and runbook only**

```bash
git add scripts/phase2/probe_mzhub.py apps/core/src/tuntun_core/domain/home/commissioning.py fixtures/synthetic/home/mzhub-capability-samples.json tests/unit/phase2/test_mzhub_capability_report.py tests/unit/phase2/test_mzhub_pilot_feature_authority.py tests/security/home/test_mzhub_no_assumptions.py tests/hardware/home/test_mzhub_capability.py tests/hardware/home/test_one_light_matter_pilot.py docs/operations/phase2-mzhub-pilot.md docs/evidence/phase2-mzhub-gate-schema.json
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(home): gate the MZHUB bridge path"
```

After this commit, rerun the Step 4 owner subsection from the new clean candidate. Generated chain, signatures, transition receipts and pilot evidence remain under ignored owner-only storage and are never added to Git.

### Task 16: Commission twelve stable light endpoints area by area

**Depends on:** P2-1 decision `PASS_BRIDGE`; if it did not pass, skip this task until P2-F produces a passed one-light path.
**Gate contribution:** P2-2.
**Estimated effort:** 1 engineering person-day plus area-by-area observation.

**Files:**
- Create: `scripts/phase2/commission_lights.py`
- Create: `ops/home-assistant/light-registry.synthetic.yaml`
- Create: `fixtures/synthetic/home/twelve-light-registry.json`
- Create: `tests/unit/phase2/test_light_registry.py`
- Create: `tests/property/home/test_wrong_target_protection.py`
- Create: `tests/hardware/home/test_twelve_light_baseline.py`
- Create: `docs/operations/phase2-light-rollout.md`
- Create: `docs/evidence/phase2-light-baseline-schema.json`

**Interfaces:** `build_light_registry(observations, alias_plan) -> tuple[EndpointRegistrationV1,...]`; exactly twelve stable endpoint IDs only after hardware inventory confirms twelve; capabilities are the intersection of observed/proved operations, never copied from marketing; `commission_lights.py` supports `plan`, `observe`, `verify`, and never factory resets a device.

- [ ] **Step 1: Write red uniqueness and wrong-target property tests**

```python
def test_twelve_light_registry_is_exact_and_unambiguous(synthetic_registry) -> None:
    rows = build_light_registry(synthetic_registry.observations, synthetic_registry.aliases)
    assert len(rows) == 12
    assert len({row.endpoint_id for row in rows}) == 12
    assert len({(row.location.area_id, alias) for row in rows for alias in row.normalized_aliases}) == sum(len(row.normalized_aliases) for row in rows)

def test_light_registration_rejects_duplicate_capability_or_alias(endpoint_registration_fixture) -> None:
    for mutation in (
        {"capability_ids": ("light.power.v1", "light.power.v1")},
        {"normalized_aliases": ("hall light", "hall light")},
    ):
        with pytest.raises(ValidationError):
            EndpointRegistrationV1.model_validate({**endpoint_registration_fixture, **mutation})

@given(target_resolution_cases())
def test_no_resolution_can_select_nonmatching_endpoint(case) -> None:
    result = resolve_light_target(case.intent, case.aliases, case.context)
    assert result.endpoint_id in case.allowed_exact_endpoints or result.kind in {"ambiguous", "none"}
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/phase2/test_light_registry.py tests/property/home/test_wrong_target_protection.py -q`
Expected: FAIL because the commissioning builder and synthetic twelve-light registry do not exist.

- [ ] **Step 3: Implement stable registration and area-by-area verification**

```python
def build_light_registry(observations, alias_plan):
    registrations = tuple(register_exact_light(row, alias_plan[row.pseudonym]) for row in observations)
    require_exact_count(registrations, 12)
    require_unique_endpoint_binding_aliases(registrations)
    require_observed_capabilities_only(registrations)
    return tuple(sorted(registrations, key=lambda row: row.endpoint_id))
```

The runbook adds one canonical `area_id` at a time, observes manual wall/native/HA changes, records power-restoration behavior, checks native groups without importing them as Tuntun scenes, runs 100 randomized target cases, and stops on the first wrong target, missing required capability, stale false availability, or false completion. Mutable display labels never become target identity, and no zone is required or inferred for a light.

- [ ] **Step 4: Run synthetic tests, then the owner-gated baseline**

Run: `uv run pytest tests/unit/phase2/test_light_registry.py tests/property/home/test_wrong_target_protection.py -q`
Expected: PASS with 100+ randomized exact/ambiguous/missing alias cases and zero wrong-target selection.

Owner run: `TUNTUN_ALLOW_HOME_HARDWARE=1 uv run pytest -m home_hardware tests/hardware/home/test_twelve_light_baseline.py -q --registry-output var/evidence/phase2/p2-2-lights.json`
Expected positive outcome: twelve pseudonymous endpoint records, zero ambiguous alias, zero wrong-device action, zero false success, required power/brightness capabilities proved, physical/manual state reflected, and native control remains. On failure, only passed endpoints remain read-only inventory; no partial household action feature is advertised as twelve-light control.

- [ ] **Step 5: Commit synthetic registry tooling, never household bindings**

```bash
git add scripts/phase2/commission_lights.py ops/home-assistant/light-registry.synthetic.yaml fixtures/synthetic/home/twelve-light-registry.json tests/unit/phase2/test_light_registry.py tests/property/home/test_wrong_target_protection.py tests/hardware/home/test_twelve_light_baseline.py docs/operations/phase2-light-rollout.md docs/evidence/phase2-light-baseline-schema.json
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "ops(home): define twelve-light commissioning"
```

### Task 17: Implement the conditional one-light direct-Zigbee fallback gate

**Depends on:** P2-1 decision `FAIL_OPEN_FALLBACK` and an owner-approved ZBT-2 procurement record. Do not execute the physical branch after `PASS_BRIDGE` or `BLOCK_UNKNOWN`.
**Gate contribution:** P2-F, then P2-2.
**Estimated effort:** 1 engineering person-day plus destructive one-light re-pair evidence.

**Files:**
- Create: `scripts/phase2/evaluate_zigbee_fallback.py`
- Create: `fixtures/synthetic/home/zigbee-radio-survey.json`
- Create: `tests/unit/phase2/test_zigbee_fallback_decision.py`
- Create: `tests/hardware/home/test_one_light_zha_fallback.py`
- Create: `docs/operations/phase2-direct-zigbee-fallback.md`
- Create: `docs/evidence/phase2-zigbee-fallback-schema.json`

**Interfaces:** `decide_zigbee_stack(exact_signature, zha_evidence, z2m_evidence) -> ZHA | ZIGBEE2MQTT | REJECT`; ZHA is default; Zigbee2MQTT is selected only when exact-model converter evidence proves a required capability/stability gap. ZBT-2 is dedicated to Zigbee and never dual-used as Thread.

- [ ] **Step 1: Write red default/rejection tests**

```python
def test_zha_is_default_when_exact_capabilities_are_equal(evidence) -> None:
    assert decide_zigbee_stack(evidence.signature, zha=pass_all(), z2m=pass_all()) == "ZHA"

def test_zigbee2mqtt_requires_exact_model_material_advantage(evidence) -> None:
    assert decide_zigbee_stack(evidence.signature, zha=missing_required(), z2m=generic_converter_claim()) == "REJECT"
    assert decide_zigbee_stack(evidence.signature, zha=missing_required(), z2m=exact_model_proof()) == "ZIGBEE2MQTT"
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/phase2/test_zigbee_fallback_decision.py -q`
Expected: FAIL because `evaluate_zigbee_fallback.py` does not exist.

- [ ] **Step 3: Implement evidence decision and destructive rollback runbook**

The runbook surveys 2.4 GHz/AiMesh interference, selects/document Zigbee channel, uses a USB extension away from Wi-Fi/USB interference, captures exact light signature/diagnostics, resets only one easy-to-recover light, pairs it to ZHA, and proves capability/offline/mesh/reboot behavior. Rollback means a second factory reset and re-pair to MZHUB; the light never belongs to both coordinators simultaneously.

- [ ] **Step 4: Run synthetic gate, then physical fallback only with all prerequisites**

Run: `uv run pytest tests/unit/phase2/test_zigbee_fallback_decision.py -q`
Expected: PASS for ZHA default, exact Z2M exception, no exact converter, interference failure, rollback failure, and dual-radio-role rejection.

Owner run: `TUNTUN_ALLOW_DESTRUCTIVE_ZIGBEE_PILOT=1 uv run pytest -m home_hardware tests/hardware/home/test_one_light_zha_fallback.py -q --evidence-dir var/evidence/phase2/p2-f-zha`
Expected positive outcome: exact one-light ZHA capability, WAN-off behavior, mesh health, reboot recovery, and reset/re-pair rollback pass before any second light moves. Expected failure: light is restored to MZHUB/native control and no direct-Zigbee binding is enabled.

- [ ] **Step 5: Commit fallback evaluator/runbook only**

```bash
git add scripts/phase2/evaluate_zigbee_fallback.py fixtures/synthetic/home/zigbee-radio-survey.json tests/unit/phase2/test_zigbee_fallback_decision.py tests/hardware/home/test_one_light_zha_fallback.py docs/operations/phase2-direct-zigbee-fallback.md docs/evidence/phase2-zigbee-fallback-schema.json
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "ops(home): gate direct Zigbee fallback"
```

**P2-1/P2-2 checkpoint:** Record exactly one active controller path per light. For the bridge branch, retain MZHUB Zigbee ownership and the proved Matter bridge binding. For the fallback branch, do not begin area-by-area migration until one-light reset/re-pair rollback has passed. In both branches, P2-2 requires twelve exact registrations, no ambiguous aliases, zero wrong-device actions, and no false-success observation.

---

## Wave 3 — P2-4 Governed Single-Light Actions, Scenes, and Truthful UI

### Task 18: Commit and sign Mac home actions after exact authorization

**Depends on:** Tasks 04, 06–07, 10, 12 and P2-2.
**Gate contribution:** P2-4.
**Estimated effort:** 2 engineering person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/services/home/action_coordinator.py`
- Modify: `apps/core/src/tuntun_core/services/actions/executor.py`
- Modify: `apps/core/src/tuntun_core/services/transactions/home_uow.py`
- Create: `tests/integration/home/test_action_authorization_commit.py`
- Create: `tests/integration/home/test_action_signing_lifecycle.py`
- Create: `tests/fault/home/test_mac_action_crash_points.py`
- Create: `tests/security/home/test_action_time_binding.py`
- Create: `tests/security/home/test_action_signature_boundary.py`

**Interfaces:** `HomeActionCoordinator.prepare(intent, actor_context) -> PreparedHomeAction`; `authorize_and_commit(prepared_id, grant_id) -> CommittedHomeActionV1`; `sign(committed: CommittedHomeActionV1) -> ClosedLightActionV1`; `dispatch(signed: ClosedLightActionV1) -> HomeActionResultV1`; `recover_nonterminal() -> tuple[RecoveryReceipt,...]`. The Phase 1 UoW owns exact grant consumption, dynamic policy/binding recheck, action/audit insertion, and one commit.

- [ ] **Step 1: Write red atomicity, signing failure, and timing tests**

```python
async def test_grant_action_and_audit_commit_atomically(coordinator, prepared, grant, fault) -> None:
    fault.raise_after("mac.before_authorized_commit")
    with pytest.raises(InjectedCrash):
        await coordinator.authorize_and_commit(prepared.id, grant.id)
    assert not await grant_store.is_consumed(grant.id)
    assert await home_actions.for_prepared(prepared.id) is None
    assert await audit.for_resource(prepared.id) == ()

async def test_signing_failure_terminalizes_without_transport(coordinator, committed, signer, transport) -> None:
    signer.fail("secure_enclave_sign_failed")
    result = await coordinator.sign_and_dispatch(committed.id)
    assert result.terminal_state == "FAILED"
    assert transport.calls == ()

@pytest.mark.parametrize("offset_seconds", [-2.01, 2.01])
async def test_clock_offset_disables_mutation(coordinator, offset_seconds) -> None:
    with pytest.raises(PermissionError, match="clock_offset_gate"):
        await coordinator.prepare(valid_intent(), context(clock_offset=offset_seconds))
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/home/test_action_authorization_commit.py tests/integration/home/test_action_signing_lifecycle.py tests/fault/home/test_mac_action_crash_points.py tests/security/home/test_action_time_binding.py tests/security/home/test_action_signature_boundary.py -q`
Expected: FAIL because `HomeActionCoordinator` is absent.

- [ ] **Step 3: Implement the serialized commit/sign/dispatch boundary**

```python
async def authorize_and_commit(self, prepared_id, grant_id):
    async with self._scope.open() as uow:
        prepared = await uow.home_actions.lock_prepared(prepared_id)
        await self._health.require_execution_eligible(prepared.endpoint_id)
        binding = await self._topology.freeze_binding_in_uow(uow, prepared.endpoint_id, self._clock.now())
        decision = await self._policy.decide_in_uow(uow, prepared.policy_request(binding))
        auth = await self._auth.consume_in_uow(uow, grant_id, prepared.action_binding(decision, binding))
        committed = await uow.home_actions.authorize_committed(prepared, binding, decision, auth, self._clock.now())
        await self._audit.append(uow, committed.audit())
        await uow.commit()
        return committed

async def sign_and_dispatch(self, action_id):
    committed = await self._repo.require_state(action_id, "AUTHORIZED_COMMITTED")
    try:
        envelope = await self._signer.sign_action(committed)
    except Exception:
        return await self._repo.fail_without_dispatch(action_id, "signing_failed")
    await self._repo.record_signature(action_id, envelope.digest(), envelope.signing_key_id)
    return await self._dispatch_signed(envelope)
```

Signing uses only canonical committed fields, sets `issued_at` within five seconds of `authorized_at`, and caps expiry at 30 seconds. Model/tool code receives neither signer nor key-provider reference.

- [ ] **Step 4: Run green across every Mac crash boundary**

Run: `uv run pytest tests/integration/home/test_action_authorization_commit.py tests/integration/home/test_action_signing_lifecycle.py tests/fault/home/test_mac_action_crash_points.py tests/security/home/test_action_time_binding.py tests/security/home/test_action_signature_boundary.py -q`
Expected: PASS before/after authorization commit, sign, envelope-record, dispatch-state, and result commit; no external I/O occurs under the SQLCipher writer lock; signing failure has zero HA calls; old policy/binding/grant/signature cannot cross a commit.

- [ ] **Step 5: Commit exact Mac coordinator paths**

```bash
git add apps/core/src/tuntun_core/services/home/action_coordinator.py apps/core/src/tuntun_core/services/actions/executor.py apps/core/src/tuntun_core/services/transactions/home_uow.py tests/integration/home/test_action_authorization_commit.py tests/integration/home/test_action_signing_lifecycle.py tests/fault/home/test_mac_action_crash_points.py tests/security/home/test_action_time_binding.py tests/security/home/test_action_signature_boundary.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(home): commit and sign governed actions"
```

### Task 19: Validate, persist, and dispatch exact light desired state on Green

**Depends on:** Tasks 08–10, 18.
**Gate contribution:** P2-4.
**Estimated effort:** 2 engineering person-days.

**Files:**
- Create: `integrations/home-assistant/custom_components/tuntun_bridge/actions.py`
- Modify: `integrations/home-assistant/custom_components/tuntun_bridge/http.py`
- Create: `integrations/home-assistant/tests/test_action_endpoint.py`
- Create: `integrations/home-assistant/tests/test_action_allowlist.py`
- Create: `integrations/home-assistant/tests/test_action_dispatch_deadline.py`
- Create: `integrations/home-assistant/tests/test_action_system_context.py`
- Create: `integrations/home-assistant/tests/test_action_idempotency.py`
- Create: `integrations/home-assistant/tests/test_action_crash_points.py`
- Create: `integrations/home-assistant/tests/test_action_receipt_binding.py`

**Interfaces:** `ActionEndpoint.handle(request) -> HAReceiptV1` for an already or newly admitted action and raises typed `ActionAdmissionRejected` for a safe no-row pre-admission rejection; `AdmissionAuthorityPreflight.require_current(envelope) -> AdmissionAuthoritySnapshot`; `ActionDispatcher.dispatch(receipt_id) -> HAReceiptV1`; `ReceiptStore.open(..., trusted_clock, sealed_service_begin_port) -> ReceiptStore`; `ReceiptStore.reserve_or_recover_action(..., expected_authority) -> ReservedOrExisting | UnadmittedExpired | SafePreAdmissionReject`; `ReceiptStore.advance_to_dispatching_if_fresh(..., context_id) -> DispatchBegun | DispatchCommitNotBegun | TerminalNoDispatch`. The store owns the trusted clock; neither method accepts a caller timestamp. Its fixed construction-time `sealed_service_begin_port` is not replaceable per request. Only `DispatchBegun` carries an awaitable completion handle, and the internally compiled call is passed solely to that synchronous capability after the successful commit and writer release. `HAReceiptBindingVerifier.require_exact(stored_canonical_request, receipt) -> HAReceiptV1`; `HASceneReceiptBindingVerifier.require_exact(stored_canonical_envelope, receipt) -> HASceneReceiptV1`. Green stores the exact canonical `ClosedLightActionV1` bytes and `closed_light_action_request_digest` atomically with `PRE_DISPATCH`; every lifecycle receipt repeats that digest. Both Green before returning and Core before any reconciliation/projection reload the immutable stored canonical envelope, recompute the domain-separated digest, and constant-time compare the digest plus the authoritative repeated-field inventory. For scenes, the verifier parses canonical bytes as `BoundedSceneEnvelopeV1`, verifies `tuntun-action-v1`, recomputes `bounded_scene_request_digest`, and exact-compares receipt execution/scene IDs, generation, stable manifest digest, parent idempotency/correlation, controller/topology/policy/authorization authority, action window, the complete ordered entry tuple, and every entry's per-execution child request digest before any child state is accepted. `HASceneReceiptV1` then validates complete ordered child receipts against those already verified entries. The separate `scene_manifest_digest` stays stable across executions because it covers only the approved scene definition. Compiled translations are exactly `light.turn_on` with exact brightness or `light.turn_off`, internally chosen, with `Context()` mapped to Tuntun correlation and no household identity.

- [ ] **Step 1: Write red validation-order and dispatch-bound tests**

```python
async def test_no_store_or_service_before_all_validation(
    endpoint, stale_validly_signed_action, hass_services, store, quota,
) -> None:
    with pytest.raises(ActionAdmissionRejected, match="STALE_GENERATION"):
        await endpoint.handle(stale_validly_signed_action)
    assert await store.count_actions() == 0
    assert quota.reservation_writes == ()
    assert hass_services.calls == ()

def test_store_time_and_begin_authority_are_not_per_request_arguments(store) -> None:
    assert "received_at" not in inspect.signature(
        store.reserve_or_recover_action,
    ).parameters
    dispatch_parameters = inspect.signature(
        store.advance_to_dispatching_if_fresh,
    ).parameters
    assert "dispatch_started_at" not in dispatch_parameters
    assert "begin_after_commit_no_yield" not in dispatch_parameters

@pytest.mark.parametrize("fault", [
    "off_registry", "binding_replaced", "endpoint_retired",
    "capability_generation_changed", "capability_digest_changed",
    "controller_epoch_rotated", "mutation_gate_closed", "quota_gate_closed",
])
async def test_stale_signed_flood_cannot_consume_rows_or_quota(
    endpoint, signed_action_factory, fault, store, quota, hass_services,
) -> None:
    await endpoint.inject_durable_authority_fault(fault)
    for sequence in range(100):
        with pytest.raises(ActionAdmissionRejected):
            await endpoint.handle(signed_action_factory(
                valid_signature=True, distinct_sequence=sequence,
            ))
    assert await store.count_actions() == 0
    assert quota.reservation_writes == ()
    assert hass_services.calls == ()

async def test_stale_signed_flood_does_not_exhaust_next_valid_admission(
    endpoint, stale_signed_action_factory, fresh_valid_action, store, quota,
) -> None:
    for sequence in range(100):
        with pytest.raises(ActionAdmissionRejected):
            await endpoint.handle(stale_signed_action_factory(distinct_sequence=sequence))
    await endpoint.restore_current_authority()
    result = await endpoint.handle(fresh_valid_action)
    assert result.safe_code != "QUOTA_EXCEEDED"
    assert await store.count_actions() == 1
    assert quota.reservation_writes == (fresh_valid_action.action_id,)

async def test_service_starts_only_after_durable_pre_dispatch(endpoint, valid_action, trace) -> None:
    await endpoint.handle(valid_action)
    assert trace.index("sqlite.commit.PRE_DISPATCH") < trace.index("sqlite.commit.DISPATCHING_WITH_CONTEXT") < trace.index("hass.services.async_call")

async def test_dispatch_cas_binds_context_and_exact_effect_before_call(
    endpoint, valid_action, store, hass_services,
) -> None:
    await endpoint.handle(valid_action)
    row = await store.require(valid_action.action_id)
    assert row.dispatch_started_at is not None
    assert row.ha_context_id == hass_services.calls[0].context.id
    assert row.dispatch_context_commitment == commit_dispatch_effect(
        action=valid_action,
        context_id=row.ha_context_id,
        compiled_call=hass_services.calls[0].without_context(),
    )

async def test_request_digest_is_recomputed_and_exact_after_restart(
    endpoint, valid_action, receipt_verifier,
) -> None:
    receipt = await endpoint.handle(valid_action)
    stored = await endpoint.store.canonical_request(valid_action.action_id)
    assert receipt.request_digest == closed_light_action_request_digest(valid_action)
    assert receipt_verifier.require_exact(stored, receipt) == receipt
    restarted = await endpoint.restart()
    prior = await restarted.get_receipt(valid_action.action_id)
    with pytest.raises(HAReceiptBindingError):
        receipt_verifier.require_exact(
            await restarted.store.canonical_request(valid_action.action_id),
            prior.model_copy(update={"request_digest": different_sha256()}),
        )

async def test_same_action_id_replaced_request_or_scene_child_digest_fails_closed(
    receipt_verifier, scene_receipt_verifier,
    stored_action, action_receipt, stored_scene, scene_receipt,
) -> None:
    with pytest.raises(HAReceiptBindingError):
        receipt_verifier.require_exact(
            replace_same_id_canonical_action(stored_action), action_receipt,
        )
    with pytest.raises(HASceneReceiptBindingError):
        scene_receipt_verifier.require_exact(
            replace_one_scene_child_request_digest(stored_scene), scene_receipt,
        )
    assert receipt_verifier.projection_writes == []
    assert receipt_verifier.device_calls == []

@pytest.mark.parametrize("field", [
    "scene_execution_request_digest", "scene_execution_id", "scene_id",
    "scene_generation", "scene_manifest_digest", "idempotency_key",
    "correlation_id", "controller_epoch", "topology_version", "policy_version",
    "authorized_at", "issued_at", "expires_at", "manifest_entries",
])
async def test_scene_receipt_exactly_binds_stored_execution_before_projection(
    scene_receipt_verifier, stored_scene_envelope, scene_receipt, field,
) -> None:
    with pytest.raises(HASceneReceiptBindingError):
        scene_receipt_verifier.require_exact(
            stored_scene_envelope,
            substitute_valid_value(scene_receipt, field),
        )
    assert scene_receipt_verifier.projection_writes == []
    assert scene_receipt_verifier.device_calls == []

async def test_replaced_same_id_scene_execution_stays_rejected_after_restart(
    scene_receipt_service, stored_scene_envelope, scene_receipt,
) -> None:
    runtime = await scene_receipt_service.replace_same_id_canonical_envelope(
        stored_scene_envelope,
    ).restart()
    with pytest.raises(HASceneReceiptBindingError):
        await runtime.accept(scene_receipt)
    assert runtime.public_scene_results == []

@pytest.mark.parametrize("delta", [timedelta(0), timedelta(microseconds=1)])
async def test_first_seen_at_or_after_expiry_is_unadmitted_without_receipt(
    endpoint, valid_action, store, hass_services, delta,
) -> None:
    endpoint.clock.set(valid_action.expires_at + delta)
    with pytest.raises(ActionAdmissionRejected, match="expired_before_admission"):
        await endpoint.handle(valid_action)
    assert await store.get_optional(valid_action.action_id) is None
    assert hass_services.calls == ()

async def test_admission_time_is_sampled_only_after_waiting_for_writer(
    endpoint, valid_action, store, quota, hass_services,
) -> None:
    endpoint.clock.set(valid_action.expires_at - timedelta(microseconds=1))
    held_writer = await store.hold_serialized_writer()
    task = asyncio.create_task(endpoint.handle(valid_action))
    await store.wait_until_writer_queued(task)
    endpoint.clock.set(valid_action.expires_at)
    held_writer.release()
    with pytest.raises(ActionAdmissionRejected, match="expired_before_admission"):
        await task
    assert await store.get_optional(valid_action.action_id) is None
    assert quota.reservation_writes == ()
    assert hass_services.calls == ()

async def test_recovered_real_pre_expiry_row_expires_without_backdated_evidence(
    endpoint, valid_action, store, hass_services,
) -> None:
    real_pre_dispatch_at = valid_action.expires_at - timedelta(microseconds=1)
    await store.seed_durable_pre_dispatch(
        valid_action, pre_dispatch_at=real_pre_dispatch_at,
    )
    restarted = await endpoint.restart(now=valid_action.expires_at)
    result = await restarted.handle(valid_action)
    assert result.receipt_state == "EXPIRED"
    assert result.pre_dispatch_at == real_pre_dispatch_at
    assert result.terminal_at >= valid_action.expires_at
    assert result.dispatch_started_at is None
    assert hass_services.calls == ()

@pytest.mark.parametrize(("cas_fault", "terminal_state"), [
    ("expiry", "EXPIRED"),
    ("endpoint_retired", "FAILED"),
    ("controller_epoch_rotated", "FAILED"),
    ("mutation_gate_closed", "FAILED"),
    ("quota_gate_closed", "FAILED"),
])
async def test_dispatch_cas_miss_terminalizes_without_service_call(
    endpoint, valid_action, pause, hass_services, cas_fault, terminal_state,
) -> None:
    task = asyncio.create_task(endpoint.handle(valid_action, pause_before="dispatch_cas"))
    await pause.reached()
    await endpoint.inject_durable_cas_fault(cas_fault)
    pause.resume()
    result = await task
    assert result.receipt_state == terminal_state
    assert result.dispatch_started_at is None
    assert result.ha_context_id is None
    assert result.dispatch_context_commitment is None
    assert hass_services.calls == ()

async def test_rebind_between_preflight_and_dispatch_cas_terminalizes_without_io(
    endpoint, valid_action, pause, store, registry, hass_services,
) -> None:
    task = asyncio.create_task(endpoint.handle(valid_action, pause_before="dispatch_cas"))
    await pause.reached()
    admitted = await store.require(valid_action.action_id)
    assert admitted.receipt_state == "PRE_DISPATCH"
    await registry.rebind_with_new_generation(valid_action.target_endpoint_id)
    pause.resume()
    result = await task
    assert result.receipt_state == "FAILED"
    assert result.safe_code == "STALE_GENERATION"
    assert result.dispatch_started_at is None
    assert result.ha_context_id is None
    assert result.dispatch_context_commitment is None
    assert hass_services.calls == ()

@pytest.mark.parametrize("crossed_bound", ["expiry", "pre_dispatch_plus_two_seconds"])
async def test_dispatch_time_is_sampled_only_after_waiting_for_writer(
    endpoint, valid_action, store, hass_services, crossed_bound,
) -> None:
    admitted = await store.seed_durable_pre_dispatch(
        valid_action,
        pre_dispatch_at=valid_action.issued_at,
    )
    held_writer = await store.hold_serialized_writer()
    task = asyncio.create_task(endpoint.dispatcher.dispatch(admitted.receipt_id))
    await store.wait_until_writer_queued(task)
    endpoint.clock.set(
        valid_action.expires_at
        if crossed_bound == "expiry"
        else admitted.pre_dispatch_at + timedelta(seconds=2, microseconds=1)
    )
    held_writer.release()
    result = await task
    assert result.receipt_state == (
        "EXPIRED" if crossed_bound == "expiry" else "FAILED"
    )
    assert result.dispatch_started_at is None
    assert result.ha_context_id is None
    assert result.dispatch_context_commitment is None
    assert hass_services.calls == ()

async def test_commit_return_time_is_resampled_before_no_yield_service_begin(
    endpoint, valid_action, store, hass_services, trace,
) -> None:
    await store.inject_clock_at_dispatch_commit_return(valid_action.expires_at)
    result = await endpoint.handle(valid_action)
    assert result.receipt_state == "UNKNOWN"
    assert result.dispatch_status == "possibly_in_flight"
    assert trace.index("sqlite.commit.DISPATCHING_WITH_CONTEXT") < trace.index(
        "dispatch.actual_call_start.rejected"
    )
    assert "hass.services.begin_call_no_yield" not in trace
    assert hass_services.calls == ()

async def test_crash_before_or_after_dispatch_cas_never_blindly_calls_or_replays(
    endpoint, valid_action, hass_services,
) -> None:
    await endpoint.inject_crash(valid_action, at="before_dispatch_cas_commit")
    assert hass_services.calls == ()
    before = await endpoint.restart(now=valid_action.expires_at)
    assert (await before.handle(valid_action)).receipt_state == "EXPIRED"
    await endpoint.inject_crash(fresh_action(), at="after_dispatch_cas_commit_before_service")
    assert hass_services.calls == ()
    after = await endpoint.restart()
    assert (await after.recover_nonterminal()).service_calls == 0
    assert (await after.latest_receipt()).receipt_state in {"DISPATCHING", "UNKNOWN"}

@pytest.mark.parametrize("body", [
    duplicate_key_signed_action_body(),
    noncanonical_but_semantically_equivalent_signed_action_body(),
])
async def test_action_endpoint_rejects_duplicate_or_noncanonical_body_before_state(
    endpoint, body, store, hass_services,
) -> None:
    with pytest.raises(HomeWireRejected):
        await endpoint.handle(authenticated_raw_request(body))
    assert await store.count_actions() == 0
    assert hass_services.calls == ()
```

- [ ] **Step 2: Run red**

Run: `uv run pytest integrations/home-assistant/tests/test_action_endpoint.py integrations/home-assistant/tests/test_action_allowlist.py integrations/home-assistant/tests/test_action_dispatch_deadline.py integrations/home-assistant/tests/test_action_system_context.py integrations/home-assistant/tests/test_action_idempotency.py integrations/home-assistant/tests/test_action_crash_points.py integrations/home-assistant/tests/test_action_receipt_binding.py -q`
Expected: FAIL because the action endpoint/dispatcher is absent.

- [ ] **Step 3: Implement ordered checks and compiled system-context translation**

```python
async def handle(self, raw_request):
    request = await self._verifier.require_channel_and_body(raw_request, max_bytes=65_536)
    envelope = parse_home_json(ClosedLightActionV1, request.body)
    if not hmac.compare_digest(request.body, canonical_home_bytes(envelope)):
        raise HomeWireRejected("home_action_body_not_canonical")
    self._verifier.require_action_signature(envelope)
    request_digest = closed_light_action_request_digest(envelope)
    existing = await self._store.find_exact_existing(
        envelope.action_id, envelope.idempotency_key, request.body, request_digest,
    )
    if existing is not None:
        receipt = existing.receipt
        if receipt.receipt_state != "PRE_DISPATCH":
            return receipt
        return await self._dispatcher.dispatch(receipt.receipt_id)
    try:
        authority = await self._preflight.require_current(envelope)
    except PreAdmissionAuthorityRejected as rejected:
        # Read-only rejection: no receipt row, quota debit, rate debit, or device I/O.
        raise ActionAdmissionRejected(rejected.safe_code) from rejected
    admission = await self._store.reserve_or_recover_action(
        envelope,
        canonical_request_bytes=request.body,
        request_digest=request_digest,
        session_key=request.session_key,
        expected_authority=authority,
    )
    if admission.kind in {"unadmitted_expired", "safe_pre_admission_reject"}:
        # No PRE_DISPATCH row or HAReceiptV1 exists on either closed rejection.
        raise ActionAdmissionRejected(admission.safe_code)
    receipt = admission.receipt
    if receipt.receipt_state != "PRE_DISPATCH":
        return receipt
    return await self._dispatcher.dispatch(receipt.receipt_id)

async def dispatch(self, receipt_id):
    context = Context()
    advance = await self._store.advance_to_dispatching_if_fresh(
        receipt_id,
        context_id=context.id,
    )
    if advance.kind in {"terminal_no_dispatch", "dispatch_commit_not_begun"}:
        return advance.receipt
    receipt = advance.receipt
    require(
        receipt.receipt_state == "DISPATCHING"
        and receipt.dispatch_started_at is not None
        and receipt.ha_context_id == context.id
        and advance.actual_call_started_at >= receipt.dispatch_started_at
        and advance.actual_call_started_at < receipt.expires_at
        and advance.actual_call_started_at <= receipt.pre_dispatch_at + timedelta(seconds=2)
    )
    await advance.completion
    return await self._store.mark_reconciling(
        receipt_id, context.id, receipt.dispatch_context_commitment,
    )
```

After channel/body/canonical-schema/signature validation, `find_exact_existing` is a read-only idempotency probe: only an exact content/digest match may resume an already admitted row, and a same-key mismatch is a security rejection. Every genuinely new action then passes a read-only `AdmissionAuthorityPreflight` that exact-checks the closed action shape, current controller epoch/topology, active endpoint, registry-owned entity commitment, binding and capability generations/digests, and mutation/quota/rate gates before any row or quota mutation. A stale, rebound, retired, off-registry, malformed, or closed-gate signed envelope is therefore a typed safe rejection with zero row, quota/rate debit, receipt, or I/O; flooding distinct validly signed stale IDs cannot consume admission capacity.

`reserve_or_recover_action` runs under the serialized writer and owns an injected trusted clock rather than accepting a claimed time. It first returns an exact matching durable row (so recovery can truthfully expire a real pre-expiry `PRE_DISPATCH` row), rejects a same-key/content mismatch, and for a new row exact-compares the `AdmissionAuthoritySnapshot` against the still-current authority before touching quota/rate state. A mismatch returns `SafePreAdmissionReject` with no write. Only after acquiring the writer and completing that current-authority comparison does the store sample `received_at`, require `received_at < envelope.expires_at`, reserve rate/quota capacity, and write that exact value as `pre_dispatch_at`. It never fabricates or backdates `pre_dispatch_at`; a caller that arrived before expiry but waited on the writer until equality or later returns `UnadmittedExpired`, writes no action/transition/receipt row, and cannot produce `HAReceiptV1`. The final dispatch CAS independently repeats the complete authority/gate truth table, closing both preflight-to-admission and admission-to-dispatch races.

`advance_to_dispatching_if_fresh` is one closed decision under the same serialized writer used by rebind/retire/epoch/gate/quota changes; no earlier read or caller clock sample is an authority decision. After acquiring that writer it reloads and exact-verifies the canonical stored envelope and digest, repeats every current-authority predicate, and only then samples the store clock as `dispatch_started_at`. A commit is possible only when the row is still exact `PRE_DISPATCH`, `dispatch_started_at < expires_at`, `dispatch_started_at <= pre_dispatch_at + 2 seconds`, and the current controller epoch, endpoint lifecycle, topology, binding/capability generations and digests, mutation gate, and quota gate all equal the frozen action authority. Inside that success branch, deterministic code resolves the registry-owned entity, compiles the closed service/data tuple, and commits its exact context/effect commitment with `DISPATCHING`. Every predicate miss atomically returns `TerminalNoDispatch`: only an elapsed envelope becomes `EXPIRED`; a rebind, retirement, epoch/topology change, mutation-gate failure, quota failure, row-state race, or exact-envelope/digest failure becomes a safe-code-specific `FAILED`, all with no dispatch evidence.

After `COMMIT` returns and the writer is released, the same store call permits no coroutine yield or scheduler handoff: it resamples `actual_call_started_at`, repeats both strict time bounds against that actual sample, and only then invokes its fixed construction-time synchronous `sealed_service_begin_port` with the internally compiled call. That capability must begin the HA invocation before returning an awaitable completion handle; callable service data is never returned to ordinary caller code and the port cannot be substituted per request. If commit latency or an injected handoff crosses either bound, the capability is not invoked, the committed proof is conservatively closed as `UNKNOWN/possibly_in_flight` (`DispatchCommitNotBegun`), and recovery never replays it. Thus a timestamp captured before writer contention or commit delay cannot authorize later I/O. A crash before the CAS leaves a recoverable real `PRE_DISPATCH`; a crash after successful `DISPATCHING` remains potentially in flight and is reconciled without replay even when instrumentation saw zero service calls.

`ClosedLightActionV1` rejects ambiguous state before persistence: power carries `brightness_percent=None`; brightness carries `on=True` and one bounded value. `compiled_light_translation` has no string argument from the request except that already cross-field-validated action enum and exact registry-owned entity. Signed off-registry entities, mismatched action/state variants, service names, actions, key/content mismatch, old epoch/generation, clock offset, or store pressure produce zero service call.

- [ ] **Step 4: Run green with crash at every HA transition**

Run: `uv run pytest integrations/home-assistant/tests/test_action_endpoint.py integrations/home-assistant/tests/test_action_allowlist.py integrations/home-assistant/tests/test_action_dispatch_deadline.py integrations/home-assistant/tests/test_action_system_context.py integrations/home-assistant/tests/test_action_idempotency.py integrations/home-assistant/tests/test_action_crash_points.py integrations/home-assistant/tests/test_action_receipt_binding.py -q`
Expected: PASS; a first-seen late envelope is unadmitted with no row/receipt/I/O, while only a genuinely durable pre-expiry `PRE_DISPATCH` may recover as truthful `EXPIRED` with its unchanged timestamp; stale/rebound/retired/off-registry/malformed/closed-gate valid-signature floods consume neither rows nor quota/rate capacity; admission and dispatch times are sampled by the store only after serialized-writer/current-authority acquisition, so lock waits crossing expiry or `pre_dispatch_at + 2 seconds` cannot preserve an early caller time; context/effect/start are committed atomically before service I/O; the immediate post-commit no-yield resample prevents delayed I/O and conservatively returns `UNKNOWN` if commit return crosses a bound; every expiry/rebind/retire/epoch/gate/quota CAS miss returns before I/O, including rebind between successful preflight and CAS; crashes before the CAS have zero I/O, crashes after it are potentially in flight with exact evidence and never replayed; duplicate same content returns the prior receipt; mismatch is a security error; instrumentation observes only the two compiled light services.

- [ ] **Step 5: Commit exact HA action paths**

```bash
git add integrations/home-assistant/custom_components/tuntun_bridge/actions.py integrations/home-assistant/custom_components/tuntun_bridge/http.py integrations/home-assistant/tests/test_action_endpoint.py integrations/home-assistant/tests/test_action_allowlist.py integrations/home-assistant/tests/test_action_dispatch_deadline.py integrations/home-assistant/tests/test_action_system_context.py integrations/home-assistant/tests/test_action_idempotency.py integrations/home-assistant/tests/test_action_crash_points.py integrations/home-assistant/tests/test_action_receipt_binding.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(ha): dispatch exact durable light state"
```

### Task 20: Reconcile physical observations, limits, timeouts, and restart recovery

**Depends on:** Tasks 12, 18–19.
**Gate contribution:** P2-4, P2-7.
**Estimated effort:** 1.5 engineering person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/services/home/reconciliation.py`
- Modify: `apps/core/src/tuntun_core/services/home/action_coordinator.py`
- Modify: `integrations/home-assistant/custom_components/tuntun_bridge/actions.py`
- Create: `tests/integration/home/test_action_reconciliation.py`
- Create: `tests/integration/home/test_action_rate_limits.py`
- Create: `tests/fault/home/test_action_restart_recovery.py`
- Create: `tests/security/home/test_no_false_success.py`
- Create: `tests/unit/home/test_result_language.py`

**Interfaces:** `HomeActionReconciler.reconcile(action_id) -> HomeActionResultV1`; `recover_nonterminal`; `HAReceiptBindingVerifier.require_exact` is mandatory before any receipt-derived state, observation lookup, or projection. It reloads the immutable canonical signed request, recomputes `request_digest`, and exact-compares action/idempotency/correlation, operation/target/desired state, controller/topology/binding/entity/capability/policy authority, and action window. Per-endpoint maximum five commands/10 seconds and per-session maximum twenty/minute; excess is rejected/coalesced immediately and never queued for delayed dispatch.

- [ ] **Step 1: Write red truthful-result and no-replay tests**

```python
@pytest.mark.parametrize(("source", "fresh", "matches", "terminal"), [
    ("matter_device", True, True, "VERIFIED"),
    ("ha_optimistic", True, True, "ACCEPTED_UNVERIFIED"),
    ("matter_device", False, True, "UNKNOWN"),
    ("matter_device", True, False, "FAILED"),
    ("matter_device", False, False, "UNKNOWN"),
    ("ha_optimistic", True, False, "ACCEPTED_UNVERIFIED"),
])
async def test_result_class_requires_proved_observation(reconciler, source, fresh, matches, terminal) -> None:
    assert (await reconciler.reconcile(seed_action(source, fresh, matches))).terminal_state == terminal

async def test_restart_queries_same_ha_receipt_before_any_send(recovery, transport, in_flight_action) -> None:
    await recovery.run()
    assert transport.calls[0].operation == "get_receipt"
    assert not any(call.operation == "new_action" for call in transport.calls)

async def test_matching_observation_before_dispatch_start_cannot_verify(reconciler) -> None:
    action = seed_action(
        source="matter_device", fresh=True, matches=True,
        observed_at=instant(9), dispatch_started_at=instant(10),
    )
    result = await reconciler.reconcile(action)
    assert result.terminal_state == "UNKNOWN"
    assert result.terminal_reason == "observation_precedes_bound_dispatch"

@pytest.mark.parametrize(("dispatch_status", "expected"), [
    ("accepted", "ACCEPTED_UNVERIFIED"),
    ("possibly_in_flight", "UNKNOWN"),
])
async def test_no_fresh_contradiction_never_maps_possible_dispatch_to_failed(
    reconciler, dispatch_status, expected,
) -> None:
    result = await reconciler.reconcile(seed_action(
        source="none", fresh=False, matches=False, dispatch_status=dispatch_status,
    ))
    assert result.terminal_state == expected

async def test_substituted_request_digest_or_stored_envelope_blocks_reconciliation(
    reconciler, action_store, valid_receipt,
) -> None:
    for fault in ("receipt_request_digest", "stored_same_id_envelope"):
        action_store.inject_fault(fault)
        with pytest.raises(HAReceiptBindingError):
            await reconciler.reconcile(valid_receipt.action_id)
        assert reconciler.state_reads == []
        assert reconciler.projection_writes == []
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/home/test_action_reconciliation.py tests/integration/home/test_action_rate_limits.py tests/fault/home/test_action_restart_recovery.py tests/security/home/test_no_false_success.py tests/unit/home/test_result_language.py -q`
Expected: FAIL because `HomeActionReconciler` is absent.

- [ ] **Step 3: Implement result truth table and recovery**

```python
async def reconcile(self, action_id):
    action = await self._actions.get(action_id)
    receipt = await self._ha.receipt(action.action_id, action.idempotency_key)
    receipt = self._receipt_verifier.require_exact(
        action.canonical_signed_request_bytes, receipt,
    )
    observation = await self._state.fresh_correlated_observation(action)
    result = classify_result(receipt, observation, self._commissioning.verification_basis(action.endpoint_id))
    async with self._uow_factory() as uow:
        await uow.home_actions.mark_reconciling_if_needed(action_id)
        terminal = await uow.home_actions.finish_exact(action_id, result, self._clock.now())
        await self._audit.append(uow, terminal.audit())
        await uow.commit()
        return terminal.result
```

`classify_result` has one closed evidence order. A fresh, generation-matched, commissioned-truthful observation correlated at or after the bound dispatch start maps an accepted request to `VERIFIED` when it matches the desired state and to `FAILED` only when it contradicts that state. An accepted acknowledgement, HA-optimistic/integration-only state, stale/missing observation, or other non-authoritative mismatch cannot produce `FAILED`; it maps to `ACCEPTED_UNVERIFIED` when acceptance itself is known and otherwise `UNKNOWN`. A potentially-in-flight dispatch without a fresh contradiction is `UNKNOWN`. Pre-dispatch policy/transport rejection may still be `FAILED/not_dispatched|rejected`, and expiry before dispatch remains `EXPIRED`. The UI mapper copies the validated dispatch start and emits `observation_relation_to_requested_effect="matches"|"contradicts"` only after this exact source-receipt comparison; it cannot infer that relation from a display string.

Actions nonterminal 24 hours after expiry become `UNKNOWN` with immutable `terminal_at`. Human messages map to “completed and verified,” “command accepted but not verified,” “not completed,” “outcome unknown,” and “expired before execution” in English/Hindi; timeout never maps to success.

- [ ] **Step 4: Run green and flood/restart tests**

Run: `uv run pytest tests/integration/home/test_action_reconciliation.py tests/integration/home/test_action_rate_limits.py tests/fault/home/test_action_restart_recovery.py tests/security/home/test_no_false_success.py tests/unit/home/test_result_language.py -q`
Expected: PASS; a fresh commissioned match yields `VERIFIED`, only a fresh commissioned post-dispatch contradiction may yield accepted `FAILED`, and acknowledgement/optimistic/stale/missing evidence maps to `ACCEPTED_UNVERIFIED` or `UNKNOWN`; command 6/10s and 21/minute are rejected without delayed execution; restart performs receipt query and zero blind replay.

- [ ] **Step 5: Commit exact reconciliation paths**

```bash
git add apps/core/src/tuntun_core/services/home/reconciliation.py apps/core/src/tuntun_core/services/home/action_coordinator.py integrations/home-assistant/custom_components/tuntun_bridge/actions.py tests/integration/home/test_action_reconciliation.py tests/integration/home/test_action_rate_limits.py tests/fault/home/test_action_restart_recovery.py tests/security/home/test_no_false_success.py tests/unit/home/test_result_language.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(home): reconcile truthful light outcomes"
```

### Task 21: Complete adult, child, guardian, Guest, and anonymous action policy

**Depends on:** Tasks 03, 06, 18–20.
**Gate contribution:** P2-4.
**Estimated effort:** 1.5 engineering person-days.

**Files:**
- Modify: `apps/core/src/tuntun_core/services/home/permissions.py`
- Modify: `apps/core/src/tuntun_core/services/home/guest_sessions.py`
- Create: `apps/core/src/tuntun_core/services/home/child_rules.py`
- Modify: `tests/acceptance/home/test_authorization_corpus.py`
- Create: `tests/security/home/test_child_light_policy.py`
- Create: `tests/security/home/test_guest_coapproval.py`
- Create: `tests/integration/home/test_policy_linearization.py`
- Create: `tests/property/home/test_restrictive_identity_precedence.py`

**Interfaces:** `ChildLightRuleService.configure/approve/revoke/reassign`; `GuestSessionService.create/cancel/hold_request/owner_coapprove`; exact rule/Guest/action digests and generations; the authorization-commit transaction is the revocation/policy linearization point. Child rules carry an exact non-empty `allowed_area_ids` set and a single endpoint; Designated Guest sessions carry exact common `allowed_area_ids`. Neither policy accepts a zone as a substitute for an area or infers location from a display label.

- [ ] **Step 1: Write red before/after linearization and co-approval tests**

```python
async def test_guardian_revocation_before_commit_forces_reevaluation(race) -> None:
    result = await race.run(revocation="immediately_before_AUTHORIZED_COMMITTED")
    assert result.dispatch_count == 0 and result.reason == "guardian_generation_stale"

async def test_revocation_after_commit_does_not_claim_cancellation(race) -> None:
    result = await race.run(revocation="immediately_after_AUTHORIZED_COMMITTED")
    assert result.audit.crossed_in_flight is True
    assert result.spoken_claim != "cancelled"

async def test_guest_voice_or_session_never_executes_without_owner_passkey(guest_request) -> None:
    assert (await guest_request.submit()).state == "HOLD_OWNER_COAPPROVAL"
    assert guest_request.transport.calls == ()
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/acceptance/home/test_authorization_corpus.py tests/security/home/test_child_light_policy.py tests/security/home/test_guest_coapproval.py tests/integration/home/test_policy_linearization.py tests/property/home/test_restrictive_identity_precedence.py -q`
Expected: FAIL because child rule lifecycle/co-approval behavior is incomplete.

- [ ] **Step 3: Implement exact rule and pending-request transactions**

Child activation requires two receipts over the same child/rule digest/generation with `owner_subject_id != guardian_subject_id`. The rule digest commits the exact endpoint, canonical `allowed_area_ids`, time bounds, action bounds, child/guardian/policy generations, and expiry. Reassignment/revocation or an applicable area/binding generation change increments generation and cancels pre-commit confirmations/extensions/pending Guest work as applicable. Guest co-approval verifies exact action, target, desired state, session, common `area_id`, owner console origin, policy/area/binding generations, expiry, and passkey before passing its grant to Task 18. `zone_id` can only further restrict an already-exact area-bound operation; it cannot grant child or Guest eligibility.

- [ ] **Step 4: Run green corpus and all race placements**

Run: `uv run pytest tests/acceptance/home/test_authorization_corpus.py tests/security/home/test_child_light_policy.py tests/security/home/test_guest_coapproval.py tests/integration/home/test_policy_linearization.py tests/property/home/test_restrictive_identity_precedence.py -q`
Expected: PASS for all 1,350 deterministic cells and revocation/edit immediately before/after commit, during confirmation/co-approval, after signing, same-subject dual role, Guest substitution/expiry/cancel, possible-child evidence, private area, broad scene, routine, persistent, stale, hazardous, and unavailable targets.

- [ ] **Step 5: Commit exact household-policy paths**

```bash
git add apps/core/src/tuntun_core/services/home/permissions.py apps/core/src/tuntun_core/services/home/guest_sessions.py apps/core/src/tuntun_core/services/home/child_rules.py tests/acceptance/home/test_authorization_corpus.py tests/security/home/test_child_light_policy.py tests/security/home/test_guest_coapproval.py tests/integration/home/test_policy_linearization.py tests/property/home/test_restrictive_identity_precedence.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(home): enforce family light policy"
```

### Task 22: Execute immutable bounded scenes with truthful partial results

**Depends on:** Tasks 03–04, 18–21.
**Gate contribution:** P2-4.
**Estimated effort:** 2 engineering person-days.

**Files:**
- Modify: `apps/core/src/tuntun_core/services/home/scenes.py`
- Modify: `apps/core/src/tuntun_core/services/home/action_coordinator.py`
- Modify: `integrations/home-assistant/custom_components/tuntun_bridge/actions.py`
- Create: `integrations/home-assistant/tests/test_scene_endpoint.py`
- Create: `tests/integration/home/test_scene_execution.py`
- Create: `tests/fault/home/test_scene_partial_failure.py`
- Create: `tests/security/home/test_scene_definition_auth.py`
- Create: `tests/property/home/test_scene_manifest.py`

**Interfaces:** `SceneService.create/edit/delete` with owner passkey; `prepare_execution(scene_id, adult_context) -> PreparedScene`; `execute(prepared_id, confirmation_grant) -> OperationResultV1`; HA reserves the aggregate and every child `PRE_DISPATCH` row in one SQLite transaction, then returns the frozen complete manifest-ordered operation result rather than a parallel scene result type.

- [ ] **Step 1: Write red manifest, atomic-admission, and partial-result tests**

```python
@pytest.mark.parametrize("bad", [duplicate_endpoint_scene(), dynamic_area_scene(), nested_scene(), non_light_scene(), thirteen_light_scene(), toggle_scene()])
def test_invalid_scene_definition_never_persists(scene_service, owner_passkey, bad) -> None:
    with pytest.raises(ValidationError):
        scene_service.create(bad, owner_passkey)

async def test_aggregate_reservation_failure_has_zero_device_io(scene_endpoint, scene, store, hass_services) -> None:
    store.fail_commit("scene_pre_dispatch")
    result = await scene_endpoint.handle(scene)
    assert result.aggregate_state == "FAILED" and hass_services.calls == ()

async def test_partial_failure_is_not_rolled_back_or_called_atomic(scene_runner) -> None:
    result = await scene_runner.run(fail_child=2)
    assert result.children[0].terminal_state == "VERIFIED"
    assert result.children[1].terminal_state == "FAILED"
    assert result.aggregate_state == "PARTIAL"
    assert scene_runner.rollback_calls == ()

@pytest.mark.parametrize(("child_states", "expected"), [
    (("VERIFIED", "VERIFIED"), "VERIFIED"),
    (("VERIFIED", "ACCEPTED_UNVERIFIED"), "PARTIAL"),
    (("VERIFIED", "FAILED"), "PARTIAL"),
    (("VERIFIED", "UNKNOWN"), "PARTIAL"),
    (("VERIFIED", "EXPIRED"), "PARTIAL"),
    (("ACCEPTED_UNVERIFIED", "ACCEPTED_UNVERIFIED"), "ACCEPTED_UNVERIFIED"),
    (("FAILED", "FAILED"), "FAILED"),
    (("EXPIRED", "EXPIRED"), "EXPIRED"),
    (("UNKNOWN", "UNKNOWN"), "UNKNOWN"),
    (("FAILED", "EXPIRED"), "FAILED"),
    (("FAILED", "UNKNOWN"), "UNKNOWN"),
    (("EXPIRED", "UNKNOWN"), "UNKNOWN"),
    (("ACCEPTED_UNVERIFIED", "FAILED"), "UNKNOWN"),
    (("ACCEPTED_UNVERIFIED", "EXPIRED"), "UNKNOWN"),
    (("ACCEPTED_UNVERIFIED", "UNKNOWN"), "UNKNOWN"),
    (("FAILED", "EXPIRED", "UNKNOWN"), "UNKNOWN"),
])
async def test_scene_runtime_uses_exact_effect_bearing_truth_table(
    scene_runner, child_states, expected,
) -> None:
    result = await scene_runner.run_with_terminal_child_states(child_states)
    assert result.aggregate_state == expected

async def test_accepted_unverified_child_alone_never_makes_partial(scene_runner) -> None:
    result = await scene_runner.run_with_terminal_child_states(
        ("ACCEPTED_UNVERIFIED", "FAILED"),
    )
    assert result.aggregate_state == "UNKNOWN"
    assert result.aggregate_state != "PARTIAL"
```

- [ ] **Step 2: Run red**

Run: `uv run pytest integrations/home-assistant/tests/test_scene_endpoint.py tests/integration/home/test_scene_execution.py tests/fault/home/test_scene_partial_failure.py tests/security/home/test_scene_definition_auth.py tests/property/home/test_scene_manifest.py -q`
Expected: FAIL because scene transport/aggregate reservation is absent.

- [ ] **Step 3: Implement exact scene commit order**

Mac atomically commits aggregate plus every child and consumes one confirmation; signs one canonical aggregate. HA validates all entries/rates/bindings/deadline and inserts aggregate plus all child `PRE_DISPATCH` rows in one local transaction before first device call. Children dispatch in canonical endpoint order; every invocation begins before aggregate expiry and within two seconds of reservation. Successful children are never rolled back to stale prior state. Terminal aggregation uses `derive_scene_terminal_aggregate` from the contract: `PARTIAL` means at least one genuinely `VERIFIED` child plus at least one non-verified child; `ACCEPTED_UNVERIFIED` alone is not effect-bearing. Heterogeneous children with no `VERIFIED` outcome become `UNKNOWN` when acceptance/uncertainty remains, while the closed `FAILED+EXPIRED` mixture is `FAILED`.

- [ ] **Step 4: Run green with final-child deadline and crash placement**

Run: `uv run pytest integrations/home-assistant/tests/test_scene_endpoint.py tests/integration/home/test_scene_execution.py tests/fault/home/test_scene_partial_failure.py tests/security/home/test_scene_definition_auth.py tests/property/home/test_scene_manifest.py -q`
Expected: PASS for 1–12 entries, definition create/edit/delete, stale/replayed passkey, concurrent edit, digest/key mismatch, final child immediately inside/outside both deadlines, crash between every child, uncertain `DISPATCHING` reconciliation, expired `PRE_DISPATCH` no-I/O, no stale rollback, all exact homogeneous/verified-mixed/non-verified-mixed aggregate vectors, and no `PARTIAL` without a `VERIFIED` effect.

- [ ] **Step 5: Commit exact scene paths**

```bash
git add apps/core/src/tuntun_core/services/home/scenes.py apps/core/src/tuntun_core/services/home/action_coordinator.py integrations/home-assistant/custom_components/tuntun_bridge/actions.py integrations/home-assistant/tests/test_scene_endpoint.py tests/integration/home/test_scene_execution.py tests/fault/home/test_scene_partial_failure.py tests/security/home/test_scene_definition_auth.py tests/property/home/test_scene_manifest.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(home): execute immutable bounded scenes"
```

### Task 23: Add light/scene control UI with exact approvals and correlated outcomes

**Depends on:** Tasks 13, 18–22.
**Gate contribution:** P2-4.
**Estimated effort:** 1.5 engineering person-days.

**Files:**
- Modify: `fixtures/synthetic/features/phase2-home-manifest-v1.json`
- Modify: `apps/core/src/tuntun_core/api/home_dtos.py`
- Modify: `apps/core/src/tuntun_core/api/routes/home.py`
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `packages/contracts/openapi/admin-v1.yaml`
- Modify: `apps/admin/src/api/generated/admin-v1.ts`
- Create: `apps/admin/src/features/home/lights-scenes.tsx`
- Create: `apps/admin/src/routes/home-lights.tsx`
- Create: `tests/contract/api/test_home_action_openapi.py`
- Create: `tests/security/test_home_action_api.py`
- Modify: `tests/integration/home/test_phase2_boot_composition.py`
- Create: `tests/e2e/home-lights.spec.ts`
- Create: `tests/e2e/home-scenes.spec.ts`

**Interfaces:** `GET /api/v1/ui/home/lights`, `GET /api/v1/ui/home/scenes`; typed single-light request and scene definition/execution routes through the Phase 1 prepared mutation mechanism; `ui.operation_result.v1` maps exact home result classes without optimism. A targeted result carries the immutable ordered opaque `target_manifest` plus exactly one row per manifest entry in that order; Phase 2 accepts only `light_v1`, one row for single action and 1–12 for scene, and rejects an aggregate `verified` unless every child is adequately evidenced `verified` or `partial` unless at least one child is `verified` and at least one is non-verified. A no-`verified` heterogeneous scene maps by the same closed `failed|unknown` truth table as `HASceneReceiptV1`. This task replaces the exact `phase2.home.actions` registration, including its package digest and exact provider/route IDs, then changes both canonical composition roots: `bootstrap/container.py` constructs the action provider only from that accepted registration, and `api/app.py` mounts exactly its declared routes only after successful provider construction. After every registration and top-level digest is frozen, the external acceptance ceremony increments the manifest version and re-signs the entire `SignedFeatureManifestV1` envelope; no row has an independent signature and runtime code has no signing authority. `test_phase2_boot_composition.py` boots the installed candidate, exact-compares the provider and route set to the accepted manifest, and proves an absent, disabled, unknown, stale, or drifted action registration leaves the provider absent and every direct action path at the same bounded not-found/feature-absent result with zero preparation or dispatch.

- [ ] **Step 1: Write red request-sent/unknown and scene-preview tests**

```typescript
test("request sent is not shown as physical success", async ({page}) => {
  await mockLightAction(page, {outcome:"unknown", safe_message_id:"home.action.outcome_unknown"});
  await page.goto("/home/lights");
  await page.getByRole("button", {name:"Turn synthetic lamp on"}).click();
  await expect(page.getByText("Outcome unknown — check the light or Home Assistant")).toBeVisible();
  await expect(page.getByText("On and verified")).toHaveCount(0);
});

test("scene confirmation lists every frozen endpoint", async ({page}) => {
  await page.goto("/home/lights");
  await page.getByRole("button", {name:"Run Synthetic Evening"}).click();
  await expect(page.getByRole("dialog")).toContainText("12 lights");
  await expect(page.getByRole("dialog")).toContainText("Manifest sha256:");
});

test("partial scene renders every manifest-ordered child outcome", async ({page}) => {
  await mockSceneResult(page, syntheticVerifiedAndFailedSceneResultInManifestOrder());
  await page.goto("/home/lights");
  await expect(page.getByTestId("scene-target-result")).toHaveCount(12);
  await expect(page.getByText("Partially completed — review each light")).toBeVisible();
});

test("accepted and failed without verification is unknown, not partial", async ({page}) => {
  await mockSceneResult(page, syntheticAcceptedAndFailedSceneResultInManifestOrder());
  await page.goto("/home/lights");
  await expect(page.getByText("Outcome unknown — review each light")).toBeVisible();
  await expect(page.getByText("Partially completed — review each light")).toHaveCount(0);
});
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/api/test_home_action_openapi.py tests/security/test_home_action_api.py tests/integration/home/test_phase2_boot_composition.py -q && pnpm --filter @tuntun/admin e2e -- tests/e2e/home-lights.spec.ts tests/e2e/home-scenes.spec.ts`
Expected: FAIL because the action provider, its manifest-bound canonical composition, and light/scene routes are absent.

- [ ] **Step 3: Implement server-built previews and correlated result presentation**

Single controls show requested target, fresh observed state/source/time/strength, effective actor class, risk/required assurance, known bypass, and manual fallback. Scene preview enumerates exact manifest digest/version, canonical `area_id` groupings with safe display labels, endpoints, and desired effects. Browser code reuses one idempotency key across preparation, step-up, and unchanged retry and never changes local state to the desired state until a correlated server result arrives. After the final route/provider/package bytes are frozen, replace the action registration, recompute every row and top-level digest, increment the manifest version, and externally re-sign the entire synthetic candidate envelope; wire those providers in `container.py` and only then mount their declared routes in `app.py`. Add installed-candidate positive composition plus absent/disabled/unknown/stale/drifted negative boot cases; importing `home.py` directly must not construct action authority or make an undeclared path reachable.

- [ ] **Step 4: Regenerate and run full UI matrix**

Run: `sh scripts/generate_openapi_client.sh && git diff --exit-code -- packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts && uv run pytest tests/contract/api/test_home_action_openapi.py tests/security/test_home_action_api.py tests/integration/home/test_phase2_boot_composition.py -q && pnpm --filter @tuntun/admin test && pnpm --filter @tuntun/admin lint && pnpm --filter @tuntun/admin typecheck && pnpm --filter @tuntun/admin build && pnpm --filter @tuntun/admin e2e -- tests/e2e/home-lights.spec.ts tests/e2e/home-scenes.spec.ts`
Expected: PASS for exact installed-candidate provider/route composition and disabled/unknown direct-path absence; request, confirmation, passkey, Guest pending/deny, child allow/deny, complete manifest-ordered per-target results, false aggregate rejection, partial scene, timeout/unknown, stale binding, manual bypass disclosure, English/Hindi, keyboard, VoiceOver semantics, 320 px, 200% zoom, dark/light/high-contrast, reduced motion, and no browser persistence.

- [ ] **Step 5: Commit exact action UI paths**

```bash
git add fixtures/synthetic/features/phase2-home-manifest-v1.json apps/core/src/tuntun_core/api/home_dtos.py apps/core/src/tuntun_core/api/routes/home.py apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts apps/admin/src/features/home/lights-scenes.tsx apps/admin/src/routes/home-lights.tsx tests/contract/api/test_home_action_openapi.py tests/security/test_home_action_api.py tests/integration/home/test_phase2_boot_composition.py tests/e2e/home-lights.spec.ts tests/e2e/home-scenes.spec.ts
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(admin): show truthful light and scene results"
```

**P2-4 checkpoint:** Enable `phase2.home.actions` only after the single-action and scene suites pass, all 1,350 policy cases agree with their oracles, standard HA APIs have no credential, signed off-registry/service attempts produce zero I/O, all timing/crash/idempotency/rate gates pass, and adult/child/Guest/anonymous behavior is truthful in voice and UI. Physical switches, MZHUB native control, and owner HA UI remain disclosed recovery/bypass paths.

---

## Wave 4 — P2-5 Manual, Assisted, and Learning Automation Governance

### Task 24: Implement Manual mode, closed drafts, simulation, and owner-passkey review

**Depends on:** Tasks 05–06, 13, 21.
**Gate contribution:** P2-5.
**Estimated effort:** 1.5 engineering person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/services/home/automation.py`
- Create: `apps/core/src/tuntun_core/services/home/routine_simulator.py`
- Create: `tests/unit/home/test_automation_modes.py`
- Create: `tests/unit/home/test_routine_schema.py`
- Create: `tests/integration/home/test_routine_draft_review.py`
- Create: `tests/security/home/test_routine_authoring_policy.py`
- Create: `tests/property/home/test_routine_cycle_analysis.py`

**Interfaces:** `AutomationGovernance.set_mode(domain, mode, scope, auth) -> ModeReceipt`; `draft(request) -> RoutineDraft`; `simulate(draft_id, representative_states) -> RoutineSimulation`; `approve_for_install(draft_id, owner_passkey) -> CommittedRoutineInstallV1`. Manual-origin HA routines are mirrored as `origin=home_assistant` and never rewritten.

- [ ] **Step 1: Write red default/mode/schema/author tests**

```python
def test_lights_domain_defaults_manual(governance) -> None:
    assert governance.get_mode("lights").mode == "MANUAL"

@pytest.mark.parametrize("actor", ["child", "designated_guest_request", "anonymous_restricted"])
async def test_non_owner_authoring_is_unreachable(governance, actor) -> None:
    with pytest.raises(PermissionError, match="authoring_denied"):
        await governance.draft(routine_request(actor=actor))

@pytest.mark.parametrize("bad", [template_trigger(), arbitrary_event_trigger(), dynamic_membership(), nested_routine(), non_light_action(), overlong_delay()])
def test_closed_routine_schema_rejects_escape(simulator, bad) -> None:
    with pytest.raises(ValidationError):
        simulator.validate(bad)
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/home/test_automation_modes.py tests/unit/home/test_routine_schema.py tests/integration/home/test_routine_draft_review.py tests/security/home/test_routine_authoring_policy.py tests/property/home/test_routine_cycle_analysis.py -q`
Expected: FAIL because automation governance/simulator modules are absent.

- [ ] **Step 3: Implement closed mode and draft pipeline**

```python
async def set_mode(self, domain, mode, scope, auth):
    current = await self._repo.get_domain(domain)
    if exposure_rank(mode) > exposure_rank(current.mode):
        require_owner_passkey(auth, mode_binding(domain, mode, scope, current.generation))
    elif mode != "MANUAL":
        require_owner_passkey(auth, mode_binding(domain, mode, scope, current.generation))
    return await self._repo.compare_and_set_mode(current, mode, scope)

def validate_manifest(manifest):
    require_trigger(manifest.trigger, {"fixed_time_day", "light_state", "light_availability"})
    require_conditions(manifest.conditions, {"fixed_time_day", "light_state"})
    require_schedule_authority_iff_wall_time_used(manifest)
    require_exact_light_actions(manifest.actions, maximum=12)
    dependency_graph(manifest).require_acyclic_without_self_edge()
```

Returning to Manual closes exposure immediately without network. Assisted/Learning expansion or scope change requires owner passkey bound to domain/mode/scope/policy/expiry. Drafts contain safety/privacy/child/Guest/failure implications, frequency, rollback digest, exact endpoints, and representative simulation output; drafts have no execution authority. A fixed-time trigger or condition also displays and signs the exact tzdata version/digest and immutable `fold_first_gap_skip_no_replay.v1` behavior. Draft validation is structural; Task 25 must still open the pinned content-addressed artifact and resolve every zone with `ZoneInfo` before activation.

- [ ] **Step 4: Run green and mode-race tests**

Run: `uv run pytest tests/unit/home/test_automation_modes.py tests/unit/home/test_routine_schema.py tests/integration/home/test_routine_draft_review.py tests/security/home/test_routine_authoring_policy.py tests/property/home/test_routine_cycle_analysis.py -q`
Expected: PASS; Manual is default, Manual reduction works offline, expansion needs exact owner passkey, every escape schema/cycle fails, and failed simulation/approval leaves no install authority.

- [ ] **Step 5: Commit exact governance/draft paths**

```bash
git add apps/core/src/tuntun_core/services/home/automation.py apps/core/src/tuntun_core/services/home/routine_simulator.py tests/unit/home/test_automation_modes.py tests/unit/home/test_routine_schema.py tests/integration/home/test_routine_draft_review.py tests/security/home/test_routine_authoring_policy.py tests/property/home/test_routine_cycle_analysis.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(home): govern closed automation drafts"
```

### Task 25: Install, disable, rollback, and quarantine signed routines on Green

**Depends on:** Tasks 09–10, 19, 24.
**Gate contribution:** P2-5.
**Estimated effort:** 2 engineering person-days.

**Files:**
- Create: `integrations/home-assistant/custom_components/tuntun_bridge/routines.py`
- Create: `integrations/home-assistant/custom_components/tuntun_bridge/tzdata.py`
- Create: `integrations/home-assistant/custom_components/tuntun_bridge/switch.py`
- Modify: `integrations/home-assistant/custom_components/tuntun_bridge/http.py`
- Modify: `apps/core/src/tuntun_core/services/home/automation.py`
- Create: `integrations/home-assistant/tests/test_routine_install.py`
- Create: `integrations/home-assistant/tests/test_routine_disable.py`
- Create: `integrations/home-assistant/tests/test_routine_rollback.py`
- Create: `integrations/home-assistant/tests/test_routine_restore_quarantine.py`
- Create: `integrations/home-assistant/tests/test_routine_timezone_activation.py`
- Create: `tests/integration/home/test_routine_install_coordinator.py`
- Create: `tests/security/home/test_routine_escape_paths.py`

**Interfaces:** HA route accepts only `tuntun-routine-v1`; compare-and-swap exact expected activation generation to `expected+1`; `RoutineInstaller.install/disable/rollback`; `PinnedTzdataResolver.resolve_for_activation(manifest) -> FrozenScheduleResolution | None` verifies one approved content-addressed artifact by exact version/SHA-256 and opens every trigger/condition zone through `ZoneInfo.from_file(..., key=zone)` before any manifest/current-row mutation; HA exposes an integration-owned read/disable switch entity without editable YAML/template surface.

- [ ] **Step 1: Write red CAS/atomicity/quarantine tests**

```python
async def test_stale_activation_generation_cannot_install(
    endpoint, current_manifest, next_manifest, store,
) -> None:
    await store.seed_routine(current_manifest, active=True)
    stale = resign_routine(next_manifest.model_copy(update={
        "expected_activation_generation": current_manifest.expected_activation_generation,
        "next_activation_generation": current_manifest.next_activation_generation,
        "previous_approved_digest": current_manifest.previous_approved_digest,
    }))
    receipt = await endpoint.handle(stale)
    assert receipt.receipt_state == "REJECTED"
    assert receipt.safe_code == "STALE_GENERATION"
    active = await store.get_routine(current_manifest.routine_id)
    assert (active.activation_generation, active.manifest_digest) == (
        current_manifest.next_activation_generation,
        current_manifest.manifest_digest,
    )

async def test_failed_install_leaves_prior_active(store, installer, prior, invalid_next) -> None:
    await store.seed_routine(prior, active=True)
    with pytest.raises(ValidationError):
        await installer.install(invalid_next)
    assert (await store.get_routine(prior.routine_id)).manifest_digest == prior.manifest_digest

async def test_same_generation_wrong_prior_digest_cannot_install(
    endpoint, store, current_manifest, next_manifest,
) -> None:
    await store.seed_routine(current_manifest, active=True)
    wrong_prior = resign_routine(next_manifest.model_copy(update={
        "previous_approved_digest": OTHER_SHA256,
    }))
    receipt = await endpoint.handle(wrong_prior)
    assert receipt.receipt_state == "REJECTED"
    assert (
        receipt.observed_preinstall_activation_generation,
        receipt.observed_preinstall_manifest_digest,
    ) == (current_manifest.next_activation_generation, current_manifest.manifest_digest)
    assert (receipt.active_activation_generation, receipt.active_manifest_digest) == (
        current_manifest.next_activation_generation,
        current_manifest.manifest_digest,
    )

async def test_restored_active_flag_is_quarantined(store_from_backup) -> None:
    runtime = await load_runtime(store_from_backup)
    assert runtime.registered_trigger_count == 0
    assert (await runtime.routines())[0].state == "QUARANTINED"

@pytest.mark.parametrize("zone", ["Mars/Olympus", "Asia/No_Such_City"])
async def test_regex_valid_but_unknown_zone_rejects_before_activation(
    installer, prior_manifest, fixed_time_manifest, zone,
) -> None:
    prior_triggers = installer.registered_trigger_snapshot()
    candidate = resign_routine(with_schedule_zone(fixed_time_manifest, zone))
    with pytest.raises(RoutineScheduleActivationError, match="zoneinfo_not_found"):
        await installer.install(candidate)
    assert await installer.active_manifest() == prior_manifest
    assert installer.registered_trigger_snapshot() == prior_triggers

@pytest.mark.parametrize("fault", [
    "missing_artifact", "wrong_version", "wrong_sha256", "replace_after_open",
    "condition_zone_missing",
])
async def test_schedule_artifact_or_zone_fault_leaves_prior_manifest_active(
    installer, prior_manifest, fixed_time_manifest, fault,
) -> None:
    installer.tzdata.inject(fault)
    with pytest.raises(RoutineScheduleActivationError):
        await installer.install(fixed_time_manifest)
    assert await installer.active_manifest() == prior_manifest
    assert installer.schedule_mutation_count == 0

async def test_restart_reopens_exact_pinned_tzdata_before_trigger_registration(
    active_scheduled_runtime,
) -> None:
    active_scheduled_runtime.tzdata.remove_or_replace_pinned_artifact()
    restarted = await active_scheduled_runtime.restart()
    assert restarted.registered_trigger_count == 0
    assert (await restarted.routines())[0].state == "QUARANTINED"
```

- [ ] **Step 2: Run red**

Run: `uv run pytest integrations/home-assistant/tests/test_routine_install.py integrations/home-assistant/tests/test_routine_disable.py integrations/home-assistant/tests/test_routine_rollback.py integrations/home-assistant/tests/test_routine_restore_quarantine.py integrations/home-assistant/tests/test_routine_timezone_activation.py tests/integration/home/test_routine_install_coordinator.py -q`
Expected: FAIL because routine endpoint/installer is absent.

- [ ] **Step 3: Implement signed CAS and atomic activation**

```python
async def install(self, manifest):
    self._verifier.require_routine_signature(manifest)
    self._validator.require_closed_manifest(manifest)
    # The resolver freezes one no-follow/content-addressed artifact, verifies
    # its complete SHA-256/version, and calls ZoneInfo.from_file for every
    # declared trigger/condition zone before any current/manifest mutation.
    schedule = await self._schedule_resolver.resolve_for_activation(manifest)
    async with self._store.writer_transaction() as tx:
        current = await tx.lock_routine(manifest.routine_id)
        observed_pair = (current.activation_generation, current.manifest_digest)
        expected_pair = (
            manifest.expected_activation_generation,
            manifest.previous_approved_digest,
        )
        requested_pair = (
            manifest.next_activation_generation,
            manifest.manifest_digest,
        )
        if observed_pair != expected_pair:
            await tx.insert_routine_install_receipt(
                manifest=manifest,
                expected_pair=expected_pair,
                observed_preinstall_pair=observed_pair,
                active_pair=observed_pair,
                receipt_state="REJECTED",
                safe_code="STALE_GENERATION",
            )
        else:
            require_exact_cas(observed_pair, expected_pair, requested_pair)
            await tx.require_frozen_schedule_resolution(schedule)
            await tx.replace_active_manifest_atomically(current, manifest, schedule)
            await tx.insert_routine_install_receipt(
                manifest=manifest,
                expected_pair=expected_pair,
                observed_preinstall_pair=observed_pair,
                active_pair=requested_pair,
                receipt_state="INSTALLED",
            )
    return await self._store.routine_install_receipt(manifest.routine_id, manifest.install_idempotency_key)
```

`resolve_for_activation` returns `None` only when no fixed-time trigger or condition exists and `schedule_authority` is absent. Otherwise it resolves every distinct zone from the exact signed authority using a frozen descriptor/snapshot, never ambient `/usr/share/zoneinfo`; a missing zone, archive/path anomaly, version/hash mismatch, or artifact replacement fails before mutation and leaves the prior routine active. The resolved schedule authority is persisted with the active generation. Normal restart, rollback, restore recovery, and re-enable reopen and rehash that same pinned artifact before registering any trigger; failure quarantines the routine. Updating host or bundled tzdata never silently reinterprets an active manifest: adopting a different artifact requires a new owner-approved manifest digest and activation generation.

Disable uses the same writer, increments generation, closes trigger gate, and expires undispatched `PRE_DISPATCH` occurrence/children; `DISPATCHING` work is reconciled. Rollback/re-enable requires a newly owner-authenticated signed manifest with current generation. Restore/epoch rotation closes all gates and marks every routine quarantined before handlers/triggers register.

- [ ] **Step 4: Run green and YAML/template/API escape tests**

Run: `uv run pytest integrations/home-assistant/tests/test_routine_install.py integrations/home-assistant/tests/test_routine_disable.py integrations/home-assistant/tests/test_routine_rollback.py integrations/home-assistant/tests/test_routine_restore_quarantine.py integrations/home-assistant/tests/test_routine_timezone_activation.py tests/integration/home/test_routine_install_coordinator.py tests/security/home/test_routine_escape_paths.py -q`
Expected: PASS; stale CAS, invalid schema/signature/epoch/deadline/digest, failed install, manual disable, rollback, and restore behave atomically; YAML/template/general automation/service paths install nothing and perform no action.

- [ ] **Step 5: Commit exact install/disable paths**

```bash
git add integrations/home-assistant/custom_components/tuntun_bridge/routines.py integrations/home-assistant/custom_components/tuntun_bridge/tzdata.py integrations/home-assistant/custom_components/tuntun_bridge/switch.py integrations/home-assistant/custom_components/tuntun_bridge/http.py apps/core/src/tuntun_core/services/home/automation.py integrations/home-assistant/tests/test_routine_install.py integrations/home-assistant/tests/test_routine_disable.py integrations/home-assistant/tests/test_routine_rollback.py integrations/home-assistant/tests/test_routine_restore_quarantine.py integrations/home-assistant/tests/test_routine_timezone_activation.py tests/integration/home/test_routine_install_coordinator.py tests/security/home/test_routine_escape_paths.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(ha): install bounded signed routines"
```

### Task 26: Execute deterministic routine occurrences with budgets and circuit breakers

**Depends on:** Tasks 09, 19‐20, 25.
**Gate contribution:** P2-5, P2-7.
**Estimated effort:** 2.5 engineering person-days.

**Files:**
- Modify: `integrations/home-assistant/custom_components/tuntun_bridge/routines.py`
- Create: `integrations/home-assistant/tests/test_routine_runtime.py`
- Create: `integrations/home-assistant/tests/test_routine_trigger_cas.py`
- Create: `integrations/home-assistant/tests/test_routine_idempotency.py`
- Create: `integrations/home-assistant/tests/test_routine_budgets.py`
- Create: `integrations/home-assistant/tests/test_routine_circuit_breaker.py`
- Create: `integrations/home-assistant/tests/test_routine_restart.py`
- Create: `integrations/home-assistant/tests/test_routine_schedule_time.py`
- Create: `integrations/home-assistant/tests/test_routine_feedback.py`
- Create: `tests/fault/home/test_routine_disable_races.py`

**Interfaces:** `RoutineEvaluator.admit(trigger, now) -> RoutineOccurrenceReceipt`; a scheduled trigger is accepted only as a verified `ScheduledRoutineSlotV1`, while a state/availability trigger retains its exact source-event commitment. `PinnedTzdataResolver.materialize_slot(active_manifest, local_date) -> ScheduledRoutineSlotV1 | GapSkip` round-trips both PEP 495 folds through the activation-pinned `ZoneInfo`, discards non-round-tripping candidates, and deduplicates candidates that resolve to the same UTC instant: one unique instant is canonicalized as `fold=0`, two distinct instants select only the earlier `fold=0` instant, and no instant durably records a spring-gap skip. Occurrence/child IDs and idempotency keys derive from domain-separated hashes of controller epoch, activation generation, manifest digest, and the verified slot/source-event commitment plus child index/state; trigger and dispatch CAS use exact active/epoch/generation predicates.

- [ ] **Step 1: Write red CAS, budget, restart, and feedback tests**

```python
async def test_disable_wins_before_pre_dispatch_to_dispatching(runtime, pause, routine) -> None:
    occurrence = await runtime.trigger(routine, pause_before="child_dispatch_cas")
    await runtime.disable(routine.id)
    pause.resume()
    assert occurrence.child_service_calls == 0
    assert occurrence.children[0].state == "EXPIRED"

@pytest.mark.parametrize((history, opens), [
    (three_executions_within_10m(), True),
    (two_consecutive_failed_unknown(), True),
    (receipt_pressure(), True),
    (origin_cursor_inconsistency(), True),
])
async def test_circuit_breaker_oracles(runtime, history, opens) -> None:
    assert (await runtime.evaluate_breaker(history)).opened is opens

async def test_restart_skips_missed_slots_without_burst(runtime) -> None:
    await runtime.stop_for(hours=4)
    result = await runtime.restart()
    assert result.missed_slots_recorded > 0 and result.service_calls == 0

async def test_fall_back_uses_first_fold_once_across_restart(
    scheduled_runtime, new_york_2026a_routine,
) -> None:
    first = await scheduled_runtime.tick("2026-11-01T05:30:00Z")
    assert first.slot.local_time == "01:30:00" and first.slot.fold == 0
    assert first.service_calls == 1
    restarted = await scheduled_runtime.restart()
    second_fold = await restarted.tick("2026-11-01T06:30:00Z")
    assert second_fold.service_calls == 0
    assert restarted.occurrence_count(first.slot.slot_commitment) == 1

async def test_restart_during_second_fold_skips_missed_first_fold_without_firing(
    stopped_scheduled_runtime, new_york_2026a_routine,
) -> None:
    restarted = await stopped_scheduled_runtime.restart_at("2026-11-01T06:30:00Z")
    result = await restarted.poll()
    assert result.service_calls == 0
    assert result.missed_slots_recorded == 1
    assert result.skipped[0].local_time == "01:30:00"
    assert result.skipped[0].fold == 0

async def test_ordinary_wall_time_deduplicates_equal_fold_probe_instants(
    scheduled_runtime, ordinary_day_routine,
) -> None:
    slot = await scheduled_runtime.materialize(date(2026, 2, 2), "10:15:00")
    assert slot.fold == 0
    assert slot.resolved_utc == datetime(2026, 2, 2, 15, 15, tzinfo=UTC)

async def test_spring_gap_is_durably_skipped_without_shift_or_catchup(
    scheduled_runtime, new_york_2026a_gap_routine,
) -> None:
    result = await scheduled_runtime.run_local_day(date(2026, 3, 8))
    assert result.requested_local_time == "02:30:00"
    assert result.gap_skips == 1 and result.service_calls == 0
    restarted = await scheduled_runtime.restart()
    assert (await restarted.tick("2026-03-08T07:30:00Z")).service_calls == 0
    assert restarted.gap_skip_count(result.wall_slot_commitment) == 1

async def test_wall_clock_rollback_holds_and_never_refires_committed_slot(
    scheduled_runtime, weekly_scheduled_routine,
) -> None:
    first = await scheduled_runtime.fire_current_slot()
    high_water = scheduled_runtime.utc_high_water
    scheduled_runtime.clock.set(high_water - timedelta(minutes=20))
    assert (await scheduled_runtime.poll()).state == "ROLLBACK_HOLD"
    assert scheduled_runtime.service_calls_for(first.slot.slot_commitment) == 1
    scheduled_runtime.clock.set(high_water)
    assert (await scheduled_runtime.poll()).state == "ROLLBACK_HOLD"
    scheduled_runtime.clock.set(high_water + timedelta(microseconds=1))
    assert (await scheduled_runtime.poll()).service_calls == 0
    assert scheduled_runtime.service_calls_for(first.slot.slot_commitment) == 1

async def test_active_schedule_uses_pinned_tzdata_and_drift_quarantines_before_trigger(
    active_scheduled_runtime,
) -> None:
    active_scheduled_runtime.replace_ambient_tzdata_with_different_rules()
    assert (await active_scheduled_runtime.materialize_next_slot()).tzdata_sha256 == PINNED_TZDATA_SHA256
    active_scheduled_runtime.mutate_pinned_artifact_after_shutdown()
    restarted = await active_scheduled_runtime.restart()
    assert restarted.registered_trigger_count == 0
    assert (await restarted.routines())[0].state == "QUARANTINED"
```

- [ ] **Step 2: Run red**

Run: `uv run pytest integrations/home-assistant/tests/test_routine_runtime.py integrations/home-assistant/tests/test_routine_trigger_cas.py integrations/home-assistant/tests/test_routine_idempotency.py integrations/home-assistant/tests/test_routine_budgets.py integrations/home-assistant/tests/test_routine_circuit_breaker.py integrations/home-assistant/tests/test_routine_restart.py integrations/home-assistant/tests/test_routine_schedule_time.py integrations/home-assistant/tests/test_routine_feedback.py tests/fault/home/test_routine_disable_races.py -q`
Expected: FAIL because deterministic runtime methods are absent.

- [ ] **Step 3: Implement occurrence admission, second dispatch CAS, and hard constants**

```python
PER_ROUTINE_MIN_INTERVAL_SECONDS = 60
PER_ROUTINE_ROLLING_DAY_MAX = 24
GLOBAL_ROLLING_HOUR_MAX = 60

async def admit(self, trigger, now):
    captured = await self._store.capture_routine_generation(trigger.routine_id)
    if isinstance(trigger, ScheduledRoutineSlotV1):
        self._schedule_verifier.require_exact_current_slot(captured, trigger)
        trigger_commitment = trigger.slot_commitment
        budget_time = trigger.resolved_utc
    else:
        self._source_event_verifier.require_exact_current_event(captured, trigger, now)
        trigger_commitment = trigger.commitment
        budget_time = trigger.observed_at
    occurrence_id = derive_occurrence_id(
        captured.epoch, captured.generation, captured.digest, trigger_commitment,
    )
    async with self._store.writer_transaction() as tx:
        await tx.require_active_epoch_generation(captured)
        await tx.require_schedule_clock_open_or_hold(captured, now)
        await tx.reserve_budget_or_open_breaker(captured, budget_time)
        return await tx.insert_occurrence_and_children_once(
            occurrence_id, captured, trigger, trigger_commitment,
        )

async def dispatch_child(self, occurrence, child):
    receipt = await self._store.cas_child_to_dispatching(
        child.id, active=True, epoch=occurrence.epoch, generation=occurrence.activation_generation)
    if receipt is None:
        return await self._store.expire_child(child.id, "routine_gate_closed")
    return await self._compiled_actions.dispatch_existing_receipt(receipt)
```

For fixed-time routines the scheduler uses only the persisted activation-pinned resolver, never ambient host tzdata. It constructs a `ScheduledRoutineSlotV1`, recomputes the purpose-HMAC over `canonical_scheduled_routine_slot_unsigned_bytes`, and exact-compares routine/generation/manifest, zone/local date/weekday/time, canonical `fold=0`, resolved UTC, tzdata version/digest, and policy before budget or occurrence mutation. The same transaction uniquely claims `(routine_id, activation_generation, manifest_digest, slot_commitment)`, advances the durable UTC high-water, and inserts all child `PRE_DISPATCH` rows. A spring gap instead inserts one unique `routine_schedule_skips` row over the same wall tuple/artifact authority with reason `DST_GAP`; it creates no `ScheduledRoutineSlotV1`, occurrence, budget debit, or device I/O. The second fall-back fold resolves to the already claimed canonical first-fold slot and performs no I/O.

Every trusted clock sample monotonically advances the persisted UTC high-water. If a later sample is lower, the same serialized store enters `ROLLBACK_HOLD`; scheduled admission remains closed at equality and reopens only when trusted UTC is strictly greater than the stored high-water. Reopening never catches up: enumerated DST-gap, downtime, restart, or rollback-crossed wall slots are inserted once as skipped and never dispatched. Restart restores the high-water/hold/slot/skip uniqueness before trigger registration. Routine-originated contexts are excluded from all triggers; state events are not replayed; dependencies reject self/cross cycles. Breaker opening disables the routine and alerts; only owner-authenticated review can re-enable.

- [ ] **Step 4: Run green with every before/after CAS race**

Run: `uv run pytest integrations/home-assistant/tests/test_routine_runtime.py integrations/home-assistant/tests/test_routine_trigger_cas.py integrations/home-assistant/tests/test_routine_idempotency.py integrations/home-assistant/tests/test_routine_budgets.py integrations/home-assistant/tests/test_routine_circuit_breaker.py integrations/home-assistant/tests/test_routine_restart.py integrations/home-assistant/tests/test_routine_schedule_time.py integrations/home-assistant/tests/test_routine_feedback.py tests/fault/home/test_routine_disable_races.py -q`
Expected: PASS; no recursive/duplicate/backlog-burst/post-disable undispatched/blind-replay execution; disabled predicate misses expire with zero I/O; already dispatching reconciles; ordinary fold probes deduplicate, fall-back executes only the first fold, second-fold restart never fires late, spring gaps skip durably, rollback holds through UTC high-water equality, and ambient/pinned tzdata drift cannot reinterpret or register a trigger; restore/reset sequence and same-manifest re-enable cannot collide due to epoch/generation-derived keys.

- [ ] **Step 5: Commit exact runtime paths**

```bash
git add integrations/home-assistant/custom_components/tuntun_bridge/routines.py integrations/home-assistant/custom_components/tuntun_bridge/tzdata.py integrations/home-assistant/tests/test_routine_runtime.py integrations/home-assistant/tests/test_routine_trigger_cas.py integrations/home-assistant/tests/test_routine_idempotency.py integrations/home-assistant/tests/test_routine_budgets.py integrations/home-assistant/tests/test_routine_circuit_breaker.py integrations/home-assistant/tests/test_routine_restart.py integrations/home-assistant/tests/test_routine_schedule_time.py integrations/home-assistant/tests/test_routine_feedback.py tests/fault/home/test_routine_disable_races.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(ha): execute bounded routine occurrences"
```

### Task 27: Add local Learning suggestions and the automation owner UI

**Depends on:** Tasks 05, 13, 24‐26.
**Gate contribution:** P2-5.
**Estimated effort:** 1.5 engineering person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/services/home/learning.py`
- Modify: `fixtures/synthetic/features/phase2-home-manifest-v1.json`
- Modify: `apps/core/src/tuntun_core/api/home_dtos.py`
- Modify: `apps/core/src/tuntun_core/api/routes/home.py`
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `packages/contracts/openapi/admin-v1.yaml`
- Modify: `apps/admin/src/api/generated/admin-v1.ts`
- Create: `apps/admin/src/features/home/automations.tsx`
- Create: `apps/admin/src/routes/home-automations.tsx`
- Create: `tests/unit/home/test_learning_detector.py`
- Create: `tests/security/home/test_learning_privacy.py`
- Create: `tests/integration/home/test_learning_lifecycle.py`
- Modify: `tests/integration/home/test_phase2_boot_composition.py`
- Create: `tests/e2e/home-automations.spec.ts`

**Interfaces:** `LearningProjector.project(event, child_conversation_correlated) -> LearningProjectionV1 | None`; `LearningDetector.suggest(projections) -> tuple[RoutineDraft,...]`; `disable_learning(domain) -> DeletionReceipt`; UI shows mode/origin/draft/diff/simulation/install/rollback/drift/projection expiry/delete/disable. This task replaces the exact `phase2.home.automations` registration, including its final package digest and provider/route IDs. After all rows and top-level digests freeze, the external acceptance ceremony increments the manifest version and re-signs the entire `SignedFeatureManifestV1` envelope; no row has an independent signature. The canonical container constructs the automation and Learning providers only from the accepted registration; the canonical app mounts only that registration's declared automation routes after construction succeeds. Installed-candidate composition tests exact-compare providers and routes and prove absent, disabled, unknown, stale, or drifted registrations expose neither Learning provider nor automation API/direct URL and cannot create, simulate, review, or install a draft.

- [ ] **Step 1: Write red no-identity/draft-only and UI drift tests**

```python
def test_child_correlated_event_is_excluded_before_projection(projector) -> None:
    assert projector.project(light_event(), child_conversation_correlated=True) is None

def test_detector_output_has_no_install_authority(detector, repeated_projection) -> None:
    suggestion = detector.suggest((repeated_projection,) * 4)[0]
    assert suggestion.status == "inactive_draft"
    assert not hasattr(suggestion, "activation_generation")
```

```typescript
test("manual drift is preserved for owner reconciliation", async ({page}) => {
  await mockAutomation(page, {state:"drift_conflict", origin:"home_assistant"});
  await page.goto("/home/automations");
  await expect(page.getByText("Manual Home Assistant change preserved")).toBeVisible();
  await expect(page.getByRole("button", {name:"Overwrite automatically"})).toHaveCount(0);
});
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/home/test_learning_detector.py tests/security/home/test_learning_privacy.py tests/integration/home/test_learning_lifecycle.py tests/integration/home/test_phase2_boot_composition.py -q && pnpm --filter @tuntun/admin e2e -- tests/e2e/home-automations.spec.ts`
Expected: FAIL because the Learning/automation providers, their manifest-bound canonical composition, and automation route are absent.

- [ ] **Step 3: Implement identity-free projection, deterministic suggestions, and UI**

Learning consumes only endpoint, area, transition, coarse time bucket, observed time/expiry. It has no actor/session/profile field, output API, or join key; it never sends data to a model. Disabling Learning deletes projections and unapproved drafts immediately while preserving approved routines with provenance. Suggestions always enter Task 24 simulation/review/passkey/install. After final code generation, replace the automation registration, recompute every row and top-level digest, increment the manifest version, and externally re-sign the entire candidate envelope; construct its exact providers in `container.py`, then mount only its declared routes in `app.py`. A route-module import never constructs authority. Extend installed-candidate positive composition and absent/disabled/unknown/stale/drifted negative boot cases.

- [ ] **Step 4: Regenerate and run privacy/lifecycle/UI gates**

Run: `sh scripts/generate_openapi_client.sh && git diff --exit-code -- packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts && uv run pytest tests/unit/home/test_learning_detector.py tests/security/home/test_learning_privacy.py tests/integration/home/test_learning_lifecycle.py tests/integration/home/test_phase2_boot_composition.py -q && pnpm --filter @tuntun/admin test && pnpm --filter @tuntun/admin lint && pnpm --filter @tuntun/admin typecheck && pnpm --filter @tuntun/admin build && pnpm --filter @tuntun/admin e2e -- tests/e2e/home-automations.spec.ts`
Expected: PASS; installed-candidate provider/route composition is exact and disabled/unknown direct paths remain absent; Learning works with identity/conversation inputs physically absent, child-correlated events are dropped before projection, 30-day expiry/disable deletion pass, silent install paths are absent, drift remains owner-visible, and English/Hindi accessible states render correctly.

- [ ] **Step 5: Commit exact Learning/UI paths**

```bash
git add apps/core/src/tuntun_core/services/home/learning.py fixtures/synthetic/features/phase2-home-manifest-v1.json apps/core/src/tuntun_core/api/home_dtos.py apps/core/src/tuntun_core/api/routes/home.py apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts apps/admin/src/features/home/automations.tsx apps/admin/src/routes/home-automations.tsx tests/unit/home/test_learning_detector.py tests/security/home/test_learning_privacy.py tests/integration/home/test_learning_lifecycle.py tests/integration/home/test_phase2_boot_composition.py tests/e2e/home-automations.spec.ts
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(home): add private Learning suggestions"
```

**P2-5 checkpoint:** Manual is the default; non-owner authoring is unreachable; Assisted/Learning expansion is passkey-bound; every installed manifest is closed, simulated, signed, CAS-installed, deterministic, budgeted, disableable, rollbackable, drift-aware, and restore-quarantined; every wall-time manifest carries a pinned, activation-resolved schedule authority and passes invalid-zone, DST fold/gap, clock-rollback, restart, and tzdata-drift gates under `fold_first_gap_skip_no_replay.v1`; every draft is inert; no YAML/template/general automation route exists; Learning has no actor or model path and deletes unapproved data on disable/expiry.

---

## Wave 5 — P2-6 Screen-Time Policy Simulator and TV Eligibility Truth

### Task 28: Implement persisted screen-time sessions and allowance ledgers

**Depends on:** Tasks 02, 05‐06.
**Gate contribution:** P2-6.
**Estimated effort:** 2 engineering person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/services/home/screen_time.py`
- Create: `apps/core/src/tuntun_core/services/home/screen_time_clock.py`
- Create: `tests/unit/home/test_screen_time_state_machine.py`
- Create: `tests/unit/home/test_allowance_ledgers.py`
- Create: `tests/integration/home/test_screen_time_restart.py`
- Create: `tests/security/home/test_screen_time_authority.py`
- Create: `tests/property/home/test_screen_time_clock.py`

**Interfaces:** `ScreenTimeService.request/start/observe/warn/begin_grace/request_extension/decide_extension/expire/enforce/end/reconcile`; `AllowanceLedger.remaining(child, at) -> RemainingAllowance`; daily and weekly ledgers are independent and minimum remaining wins; UTC checkpoints plus monotonic reference support restart reconciliation.

- [ ] **Step 1: Write red transition, ledger, clock, and authority tests**

```python
def test_more_restrictive_daily_or_weekly_allowance_wins(ledger) -> None:
    ledger.seed(daily_remaining=45, weekly_remaining=20)
    assert ledger.remaining(CHILD, NOW).minutes == 20

@pytest.mark.parametrize("uncertainty", ["wall_clock_jump", "timezone_change", "dst_anomaly", "missing_observation"])
async def test_uncertain_time_enters_reconciliation_without_blind_debit(service, uncertainty) -> None:
    result = await service.inject_uncertainty(active_session(), uncertainty)
    assert result.state == "UNKNOWN"
    assert result.unobserved_ledger_delta_seconds == 0

def test_reboot_epoch_mismatch_denies_even_when_numeric_deltas_coincidentally_match(clock_reconciler) -> None:
    checkpoint = clock_checkpoint(utc=NOW, monotonic=100.0, monotonic_clock_id="boot-a")
    current = clock_sample(utc=NOW + timedelta(seconds=10), monotonic=110.0, monotonic_clock_id="boot-b")
    result = clock_reconciler.reconstruct(checkpoint, current, trustworthy_observation(covered_seconds=10))
    assert result == ReconciliationRequired("monotonic_clock_epoch_changed")
    assert result.supported_debit_seconds == 0

@pytest.mark.parametrize(
    ("profile_class", "guardian_relation", "identity_state"),
    [
        ("adult", "none", "identified"),
        ("k2", "self", "identified"),
        ("n1", "self", "identified"),
        ("guest", "none", "identified"),
        ("guest", "none", "anonymous_restricted"),
    ],
)
async def test_only_owner_or_current_guardian_changes_extension_ledger(
    service, profile_class, guardian_relation, identity_state,
) -> None:
    with pytest.raises(PermissionError):
        await service.decide_extension(
            extension_request(), actor(profile_class, guardian_relation, identity_state),
        )
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/home/test_screen_time_state_machine.py tests/unit/home/test_allowance_ledgers.py tests/integration/home/test_screen_time_restart.py tests/security/home/test_screen_time_authority.py tests/property/home/test_screen_time_clock.py -q`
Expected: FAIL because screen-time service/clock modules are absent.

- [ ] **Step 3: Implement exact transition and checkpoint logic**

```python
LEGAL = {
    "IDLE": {"REQUESTED"}, "REQUESTED": {"AUTHORIZED", "UNKNOWN"},
    "AUTHORIZED": {"ACTIVE", "UNKNOWN"}, "ACTIVE": {"WARNING", "UNKNOWN"},
    "WARNING": {"GRACE", "UNKNOWN"}, "GRACE": {"EXTENSION_PENDING", "EXPIRED", "UNKNOWN"},
    "EXTENSION_PENDING": {"ACTIVE", "EXPIRED", "UNKNOWN"},
    "EXPIRED": {"ENFORCING", "ENDED", "UNKNOWN"},
    "ENFORCING": {"ENDED", "UNKNOWN"}, "ENDED": set(), "UNKNOWN": {"IDLE"},
}

def reconstruct_elapsed(last_utc, last_monotonic, last_monotonic_clock_id,
                        now_utc, now_monotonic, now_monotonic_clock_id, observation):
    if last_monotonic_clock_id != now_monotonic_clock_id:
        return ReconciliationRequired("monotonic_clock_epoch_changed")
    if not observation.trustworthy or now_utc < last_utc or now_monotonic < last_monotonic or abs((now_utc-last_utc).total_seconds() - (now_monotonic-last_monotonic)) > CLOCK_TOLERANCE:
        return ReconciliationRequired("clock_or_observation_unreliable")
    return SupportedElapsed(min((now_utc-last_utc).total_seconds(), observation.covered_seconds))
```

Every persisted checkpoint and live sample binds a random OS-boot/monotonic-clock generation (`monotonic_clock_id`) in addition to UTC and the numeric monotonic value. Epoch equality is checked before any subtraction, so a reboot whose reset counter happens to produce a plausible delta cannot debit a ledger. Sessions bind child, TV endpoint, policy/mode/version, daily/weekly ledgers, wall/monotonic references and clock generation, viewer evidence, and last trustworthy device observation. TV-on alone never identifies a viewer. Missing observer time does not debit the child.

- [ ] **Step 4: Run green and 10,000 seeded clock/restart sequences**

Run: `uv run pytest tests/unit/home/test_screen_time_state_machine.py tests/unit/home/test_allowance_ledgers.py tests/integration/home/test_screen_time_restart.py tests/security/home/test_screen_time_authority.py tests/property/home/test_screen_time_clock.py -q --hypothesis-seed=220829`
Expected: PASS; legal transitions persist, illegal transitions fail, daily/weekly minimum wins, extension/override authority is exact, and 10,000 generated clock/restart/viewer/consent changes produce zero unauthorized debit or policy mutation.

- [ ] **Step 5: Commit exact screen-time core paths**

```bash
git add apps/core/src/tuntun_core/services/home/screen_time.py apps/core/src/tuntun_core/services/home/screen_time_clock.py tests/unit/home/test_screen_time_state_machine.py tests/unit/home/test_allowance_ledgers.py tests/integration/home/test_screen_time_restart.py tests/security/home/test_screen_time_authority.py tests/property/home/test_screen_time_clock.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(home): persist screen-time policy state"
```

### Task 29: Simulate Advisory, Cooperative, and Strict eligibility and bounded enforcement

**Depends on:** Tasks 02, 28.
**Gate contribution:** P2-6.
**Estimated effort:** 2 engineering person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/services/home/tv_eligibility.py`
- Create: `apps/core/src/tuntun_core/services/home/screen_time_enforcement.py`
- Create: `tests/unit/home/test_tv_eligibility.py`
- Create: `tests/integration/home/test_screen_time_enforcement.py`
- Create: `tests/acceptance/home/test_screen_time_corpus.py`
- Create: `tests/property/home/test_screen_time_sequences.py`
- Create: `tests/fault/home/test_tv_common_mode_failures.py`
- Create: `tests/security/home/test_no_real_tv_enforcement.py`

**Interfaces:** `TVEligibilityEvaluator.evaluate(control_evidence, observation_evidence) -> TVPowerEligibilityV1`; `ScreenTimeEnforcer.prepare_enforcement(session, attempt_kind) -> EnforcementIntentV1` owns the writer transaction and delegates only to `prepare_enforcement_in_uow(session, attempt_kind, uow) -> EnforcementIntentV1`; `TVDispatchStore.open(..., trusted_clock, sealed_fake_tv_begin_port) -> TVDispatchStore`; `TVDispatchStore.advance_to_dispatching_if_fresh(request_id, *, expected_canonical_request, expected_request_commitment) -> TVDispatchBegun | TVDispatchCommitNotBegun | TVTerminalNoDispatch`. The store owns its trusted clock and accepts no caller dispatch timestamp. Its fixed construction-time begin port cannot be replaced per request. Only `TVDispatchBegun` carries the proof and awaitable completion handle; adapter/effect values are delivered solely to the synchronous post-commit begin capability and never exposed on a miss. `TVDispatchBindingVerifier.require_exact(TVOffRequestV1, TVDispatchProofV1) -> TVDispatchProofV1`; `ScreenTimeEnforcer.enforce(session) -> EnforcementResult`; one primary attempt plus at most one configured re-enforcement attempt. Generic TV capability discovery is separate from persisted power eligibility. Preparing an attempt reloads the exact current child/session/viewer/clock/TV/policy/authorization/adapter and `TVPowerEligibilityV1` facts, persists canonical intent bytes and audit outbox in one writer transaction, and returns that committed `EnforcementIntentV1`. The FakeTV adapter commits the exact dispatch proof before I/O; recovery never converts an older acknowledgement or observation into evidence for a newer attempt. Phase 2 production adapters consume it only through `FakeTV`; no household TV adapter is registered.

- [ ] **Step 1: Write red independence and attempt-ceiling tests**

```python
def test_same_adapter_ack_and_state_cannot_enable_strict(evaluator) -> None:
    result = evaluator.evaluate(control=same_adapter_control(), observation=same_adapter_cached_state())
    assert result.strict is False
    assert result.maximum_mode in {"ADVISORY", "COOPERATIVE"}

def test_fake_tv_dispatch_time_and_begin_authority_are_store_owned(
    dispatch_store,
) -> None:
    parameters = inspect.signature(
        dispatch_store.advance_to_dispatching_if_fresh,
    ).parameters
    assert "dispatch_started_at" not in parameters
    assert "begin_after_commit_no_yield" not in parameters

@pytest.mark.parametrize("failure", ["ack_false_state", "stale_mirror", "control_restart", "observer_restart", "common_mode_outage"])
async def test_unverified_enforcement_degrades_and_stops(enforcer, failure) -> None:
    result = await enforcer.run_synthetic(failure=failure)
    assert result.final_state == "UNKNOWN"
    assert result.control_attempt_count <= 2
    assert result.degraded_mode == "ADVISORY"

def test_real_tv_control_adapter_is_not_registered(feature_manifest) -> None:
    assert "phase2.tv.enforcement" not in feature_manifest.capabilities

@pytest.mark.parametrize(("control_operation", "observation_dimension"), [
    ("tv.set_volume.v1", "power"),
    ("tv.set_power.v1", "input"),
    ("tv.mute.v1", "playback"),
])
def test_irrelevant_tv_capability_never_enables_screen_time_power(
    evaluator, control_operation, observation_dimension,
) -> None:
    result = evaluator.evaluate(
        control=evidence_for(control_operation),
        observation=evidence_for(observation_dimension),
    )
    assert result.state in {"UNCOMMISSIONED", "DISPLAY_ONLY_MANUAL", "OBSERVE_ONLY", "DEGRADED"}

async def test_drift_restart_and_restore_persist_degraded_advisory_fallback(
    eligibility_store, evaluator,
) -> None:
    await eligibility_store.save(evaluator.evaluate(standby_control(), power_observation()))
    await eligibility_store.inject_generation_drift()
    for reopened in (await eligibility_store.restart(), await eligibility_store.restore_copy()):
        assert (await reopened.current()).state == "DEGRADED"
        assert (await reopened.maximum_mode()) == "ADVISORY"

async def test_intent_commits_before_fake_tv_and_substitution_reads_nothing(
    enforcer, intent_repository, current_fact_repository, fake_tv,
) -> None:
    intent = await enforcer.prepare_enforcement(expired_session(), attempt_kind="primary")
    assert intent_repository.committed(intent.intent_id)
    assert fake_tv.call_count == 0
    tampered = EnforcementIntentV1.model_validate({
            **intent.model_dump(),
            "endpoint_id": "tv_substituted_synth_01",
            "intent_commitment": intent.intent_commitment,
        })
    with pytest.raises(EnforcementIntentBindingError):
        await enforcer.enforce_committed(tampered)
    assert current_fact_repository.read_count == 0
    assert fake_tv.call_count == 0

async def test_fake_tv_dispatch_cas_binds_start_context_and_exact_standby_effect(
    enforcer, fake_tv, dispatch_store, trace,
) -> None:
    intent = await enforcer.prepare_enforcement(expired_session(), "primary")
    receipt = await enforcer.enforce_committed(intent)
    proof = receipt.dispatch_proof
    assert proof is not None
    assert trace.index("sqlite.dispatch_proof.commit") < trace.index("fake_tv.set_standby")
    assert (
        proof.request_id,
        proof.control_adapter_id,
        proof.controller_epoch,
        proof.topology_generation,
        proof.binding_generation,
        proof.capability_generation,
        proof.control_generation,
        proof.operation,
        proof.desired_power,
    ) == (
        receipt.request_id,
        intent.control_adapter_id,
        intent.controller_epoch,
        intent.topology_generation,
        intent.binding_generation,
        intent.capability_generation,
        intent.control_generation,
        "tv.set_power.v1",
        "STANDBY",
    )
    assert await dispatch_store.effect_commitment_matches_exact_request(receipt.request_id)
    assert proof.idempotency_key == intent.idempotency_key
    assert proof.request_commitment == intent.intent_commitment
    assert proof.session_commitment == intent.session_commitment
    assert proof.policy_version == intent.policy_version
    assert proof.mode == intent.mode
    assert proof.attempt_kind == intent.attempt_kind
    assert proof.attempt_number == intent.attempt_number
    assert proof.requested_at == intent.issued_at
    assert proof.expires_at == intent.expires_at
    assert proof.correlation_id == intent.intent_id

@pytest.mark.parametrize("delta", [timedelta(0), timedelta(microseconds=1)])
async def test_fake_tv_dispatch_cas_at_or_after_expiry_terminalizes_without_io(
    enforcer, expired_session, pause, dispatch_store, fake_tv, delta,
) -> None:
    intent = await enforcer.prepare_enforcement(expired_session(), "primary")
    task = asyncio.create_task(enforcer.enforce_committed(
        intent, pause_before="tv_dispatch_cas",
    ))
    await pause.reached()
    assert (await dispatch_store.latest()).dispatch_state == "PRE_DISPATCH"
    enforcer.clock.set(intent.expires_at + delta)
    pause.resume()
    receipt = await task
    assert receipt.outcome == "EXPIRED"
    assert receipt.dispatch_status == "not_dispatched"
    assert receipt.dispatch_proof is None
    assert receipt.dispatch_context_commitment is None
    assert receipt.effect_commitment is None
    assert not hasattr(enforcer.last_dispatch_decision, "compiled_adapter")
    assert not hasattr(enforcer.last_dispatch_decision, "compiled_effect")
    assert fake_tv.effect_calls == ()

async def test_fake_tv_dispatch_time_is_sampled_after_waiting_for_writer(
    enforcer, expired_session, dispatch_store, fake_tv,
) -> None:
    intent = await enforcer.prepare_enforcement(expired_session(), "primary")
    held_writer = await dispatch_store.hold_serialized_writer()
    task = asyncio.create_task(enforcer.enforce_committed(intent))
    await dispatch_store.wait_until_writer_queued(task)
    enforcer.clock.set(intent.expires_at)
    held_writer.release()
    receipt = await task
    assert receipt.outcome == "EXPIRED"
    assert receipt.dispatch_status == "not_dispatched"
    assert receipt.dispatch_proof is None
    assert fake_tv.effect_calls == ()

async def test_fake_tv_commit_return_time_is_resampled_before_no_yield_begin(
    enforcer, expired_session, dispatch_store, fake_tv, trace,
) -> None:
    intent = await enforcer.prepare_enforcement(expired_session(), "primary")
    await dispatch_store.inject_clock_at_dispatch_commit_return(intent.expires_at)
    receipt = await enforcer.enforce_committed(intent)
    assert receipt.outcome == "UNKNOWN"
    assert receipt.dispatch_status == "possibly_in_flight"
    assert trace.index("sqlite.dispatch_proof.commit") < trace.index(
        "fake_tv.actual_call_start.rejected"
    )
    assert "fake_tv.begin_set_standby_no_yield" not in trace
    assert fake_tv.effect_calls == ()

@pytest.mark.parametrize(("fault", "safe_code"), [
    ("binding_replaced", "STALE_GENERATION"),
    ("capability_generation_changed", "STALE_GENERATION"),
    ("control_generation_changed", "STALE_GENERATION"),
    ("controller_epoch_rotated", "STALE_EPOCH"),
    ("topology_generation_changed", "STALE_GENERATION"),
    ("enforcement_gate_closed", "POLICY_DENIED"),
])
async def test_fake_tv_authority_change_at_dispatch_cas_returns_closed_no_io(
    enforcer, expired_session, pause, dispatch_store, fake_tv, fault, safe_code,
) -> None:
    intent = await enforcer.prepare_enforcement(expired_session(), "primary")
    task = asyncio.create_task(enforcer.enforce_committed(
        intent, pause_before="tv_dispatch_cas",
    ))
    await pause.reached()
    assert (await dispatch_store.latest()).dispatch_state == "PRE_DISPATCH"
    await enforcer.inject_durable_tv_dispatch_fault(fault)
    pause.resume()
    receipt = await task
    assert receipt.outcome == "FAILED"
    assert receipt.safe_code == safe_code
    assert receipt.dispatch_status == "not_dispatched"
    assert receipt.dispatch_proof is None
    assert receipt.dispatch_context_commitment is None
    assert receipt.effect_commitment is None
    assert not hasattr(enforcer.last_dispatch_decision, "compiled_adapter")
    assert not hasattr(enforcer.last_dispatch_decision, "compiled_effect")
    assert fake_tv.effect_calls == ()

@pytest.mark.parametrize(
    "crash_at",
    ("before_dispatch_cas", "after_dispatch_cas_before_io", "after_io_before_receipt"),
)
async def test_tv_dispatch_crash_boundaries_never_reuse_unproved_ack(
    enforcer, fake_tv, dispatch_store, crash_at,
) -> None:
    fake_tv.crash_at(crash_at)
    await enforcer.run_one_attempt(expired_session())
    row = await dispatch_store.latest()
    if crash_at == "before_dispatch_cas":
        assert row.dispatch_proof is None and fake_tv.effect_calls == ()
    else:
        assert row.dispatch_proof is not None
        assert row.dispatch_status == "possibly_in_flight"
    restarted = await enforcer.restart()
    await restarted.reconcile_without_redispatch()
    assert fake_tv.new_effect_calls_after_restart == ()

async def test_preexisting_adapter_ack_and_observation_cannot_prove_new_tv_dispatch(
    enforcer, fake_tv, observer,
) -> None:
    fake_tv.seed_ack_before_next_dispatch()
    observer.seed_matching_off_before_next_dispatch()
    result = await enforcer.run_one_attempt(expired_session())
    assert result.final_state == "UNKNOWN"
    assert result.reason_codes >= {
        "adapter_receipt_precedes_dispatch", "observation_precedes_bound_dispatch",
    }
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/home/test_tv_eligibility.py tests/integration/home/test_screen_time_enforcement.py tests/acceptance/home/test_screen_time_corpus.py tests/property/home/test_screen_time_sequences.py tests/fault/home/test_tv_common_mode_failures.py tests/security/home/test_no_real_tv_enforcement.py -q`
Expected: FAIL because eligibility/enforcement services are absent.

- [ ] **Step 3: Implement evidence classes and bounded simulator control**

```python
def evaluate(control, observation):
    if control.operation != "tv.set_power.v1" or not control.proves_standby:
        return TVPowerEligibilityV1.degraded("standby_control_unproved")
    if observation.dimension != "power" or not observation.truthful:
        return TVPowerEligibilityV1.degraded("power_observation_unproved")
    independent = (
        control.failure_domain_id != observation.failure_domain_id
        and observation.independence_evidence_digest is not None
    )
    return TVPowerEligibilityV1.current(
        state="STRICT_ELIGIBLE" if independent else "COOPERATIVE_ELIGIBLE",
        control=control,
        observation=observation,
        independence_evidence_digest=(
            observation.independence_evidence_digest if independent else None
        ),
    )

class TVDispatchBindingVerifier:
    """Fields-only verification; no adapter/domain read precedes this check."""
    def require_exact(self, request, proof):
        expected_fields = (
            request.request_id, request.idempotency_key,
            request.request_commitment, request.session_commitment,
            request.endpoint_id, request.endpoint_generation,
            request.control_adapter_id, request.controller_epoch,
            request.topology_generation, request.binding_generation,
            request.capability_generation, request.control_generation,
            request.operation, request.desired_power,
            request.policy_version, request.mode,
            request.attempt_kind, request.attempt_number,
            request.requested_at, request.expires_at,
            request.correlation_id,
        )
        actual_fields = (
            proof.request_id, proof.idempotency_key,
            proof.request_commitment, proof.session_commitment,
            proof.endpoint_id, proof.endpoint_generation,
            proof.control_adapter_id, proof.controller_epoch,
            proof.topology_generation, proof.binding_generation,
            proof.capability_generation, proof.control_generation,
            proof.operation, proof.desired_power,
            proof.policy_version, proof.mode,
            proof.attempt_kind, proof.attempt_number,
            proof.requested_at, proof.expires_at,
            proof.correlation_id,
        )
        expected_context = commit_tv_adapter_context_fields(
            request, proof.dispatch_started_at,
        )
        expected_effect = commit_tv_effect_fields(
            request, proof.dispatch_started_at, expected_context,
        )
        if (
            actual_fields != expected_fields
            or not compare_digest(proof.adapter_context_commitment, expected_context)
            or not compare_digest(proof.effect_commitment, expected_effect)
        ):
            raise TVDispatchBindingError("tv_dispatch_proof_substituted")
        return proof

async def enforce(self, session):
    attempts = 0
    for permitted in ("primary", "bounded_reenforcement"):
        if attempts >= self._policy.maximum_attempts(session):
            break
        attempts += 1
        intent = await self.prepare_enforcement(session, permitted)
        receipt = await self._adapter.enforce(intent)
        proof = receipt.dispatch_proof
        observation = await self._observe.fresh(session.endpoint_id)
        proves_this_dispatch = (
            proof is not None
            and observation.proves_off
            and observation.control_correlation_id == receipt.request_id
            and observation.observed_at >= proof.dispatch_started_at
        )
        if proves_this_dispatch:
            return EnforcementResult("ENDED", attempts, "verified_off")
        if not self._policy.may_reenforce(session, observation):
            break
    return EnforcementResult("UNKNOWN", attempts, "unverified_manual_bypass", degraded_mode="ADVISORY")

async def dispatch_fake_tv(self, request):
    advance = await self._store.advance_to_dispatching_if_fresh(
        request.request_id,
        expected_canonical_request=canonical_home_bytes(request),
        expected_request_commitment=request.request_commitment,
    )
    if advance.kind in {"terminal_no_dispatch", "dispatch_commit_not_begun"}:
        return advance.receipt
    proof = advance.proof
    require(
        advance.receipt.dispatch_proof == proof
        and proof.dispatch_started_at < proof.expires_at
        and advance.actual_call_started_at >= proof.dispatch_started_at
        and advance.actual_call_started_at < proof.expires_at
    )
    # The effect began through the no-yield capability after proof commit.
    # Recovery queries the same request/proof and never emits a second effect.
    adapter_receipt = await advance.completion
    return await self._store.finish_with_exact_adapter_receipt(proof, adapter_receipt)
```

`prepare_enforcement` constructs the intent only from current server-side rows and the closed `EnforcementIntentV1` builder, including the exact current power-eligibility evidence ID/digest, writes its canonical bytes/commitment plus audit outbox through `prepare_enforcement_in_uow`, commits, and only then invokes the injected adapter. `EnforcementIntentValidator.require_committed_exact` first recomputes the HMAC over canonical bytes excluding `intent_commitment`, compares both the HMAC and stored canonical bytes in constant time, and performs no session/topology/domain read on failure; it then reloads and exactly compares every current fact before dispatch. The Phase 2 adapter maps the exact intent to `TVOffRequestV1` with a fields-only `FakeTVOffRequestMapper`; it cannot choose an endpoint, adapter, controller/topology/binding/capability/control generation, operation, desired state, or attempt.

`advance_to_dispatching_if_fresh` is the sole FakeTV `PRE_DISPATCH -> DISPATCHING` authority and runs under the same serialized writer as controller-epoch/topology, endpoint/binding/capability/control, eligibility/policy, and enforcement-gate changes. It reloads the exact canonical request and commitment, rechecks every current authority predicate, and only then samples its injected trusted clock as `dispatch_started_at`; no caller time can predate writer contention. A commit is possible only when the row is still exact `PRE_DISPATCH`, trusted `requested_at <= dispatch_started_at < expires_at`, and every current epoch, topology, active endpoint, binding, capability, control route, power-eligibility evidence, policy/mode, and gate value equals the committed request/intent authority. Only that branch resolves the registered FakeTV adapter, constructs the closed `tv.set_power.v1=STANDBY` effect, and commits the complete `TVDispatchProofV1`. A PRE_DISPATCH predicate miss atomically returns `TVTerminalNoDispatch` with no proof or adapter/effect: expiry alone is `EXPIRED/not_dispatched`; rebind, retirement, epoch/topology, capability/control, eligibility/policy, gate, content, or row-authority failure is safe-code-specific `FAILED/not_dispatched`.

After commit and writer release, the same call performs no await or scheduler handoff before resampling `actual_call_started_at`, requiring it still be `< expires_at`, and invoking its fixed construction-time synchronous `sealed_fake_tv_begin_port`. The capability begins only the already-compiled registered FakeTV standby effect before returning its completion handle; ordinary caller code never receives adapter/effect authority and cannot substitute the port per request. A commit-return delay that reaches expiry invokes no adapter and returns `TVDispatchCommitNotBegun`, conservatively terminalized `UNKNOWN/possibly_in_flight`; it is never redispatched. A crash before the CAS is `not_dispatched`; a crash after its success is `possibly_in_flight` and recovery queries the same proof/idempotency key without resending. An adapter receipt must postdate and exact-bind that proof and the actual begin path. An off observation must carry the same request correlation and satisfy `observed_at >= dispatch_started_at`; an older matching acknowledgement or observation is never evidence for this attempt. Startup and restore revalidate the exact standby-control/power-observation pair; they never reconstruct eligibility from unrelated generic capabilities. Educational/content exceptions require trustworthy typed adapter evidence or exact current-guardian session approval; Phase 2 stores no programme title, audiovisual content, or inferred interest. A physical remote is explicitly an unauthenticated manual bypass, never adult identity.

- [ ] **Step 4: Run green 720-case corpus and 10,000 sequences**

Run: `uv run pytest tests/unit/home/test_tv_eligibility.py tests/integration/home/test_screen_time_enforcement.py tests/acceptance/home/test_screen_time_corpus.py tests/property/home/test_screen_time_sequences.py tests/fault/home/test_tv_common_mode_failures.py tests/security/home/test_no_real_tv_enforcement.py -q --hypothesis-seed=220830`
Expected: PASS for 720/720 exact oracles and at least 10,000 property sequences; zero unauthorized ledger/policy mutation, enforcement outside mode/endpoint/viewer eligibility, substituted/stale intent or dispatch proof, external call before intent/audit and atomic dispatch-proof commits, caller-sampled dispatch time, I/O after writer contention or commit return crosses expiry, I/O after any paused-CAS rebind/epoch/topology/capability/control/gate miss, reuse of a pre-existing adapter acknowledgement/observation, blind redispatch after any crash boundary, false verified-off claim, false denial of eligible extension/session, or control attempt above two; real TV enforcement registration remains absent.

- [ ] **Step 5: Commit exact eligibility/simulator paths**

```bash
git add apps/core/src/tuntun_core/services/home/tv_eligibility.py apps/core/src/tuntun_core/services/home/screen_time_enforcement.py tests/unit/home/test_tv_eligibility.py tests/integration/home/test_screen_time_enforcement.py tests/acceptance/home/test_screen_time_corpus.py tests/property/home/test_screen_time_sequences.py tests/fault/home/test_tv_common_mode_failures.py tests/security/home/test_no_real_tv_enforcement.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(home): prove screen-time simulator"
```

### Task 30: Add transparent screen-time policy and simulator UI

**Depends on:** Tasks 13, 28‐29.
**Gate contribution:** P2-6.
**Estimated effort:** 1.5 engineering person-days.

**Files:**
- Modify: `fixtures/synthetic/features/phase2-home-manifest-v1.json`
- Modify: `apps/core/src/tuntun_core/api/home_dtos.py`
- Modify: `apps/core/src/tuntun_core/api/routes/home.py`
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `packages/contracts/openapi/admin-v1.yaml`
- Modify: `apps/admin/src/api/generated/admin-v1.ts`
- Create: `apps/admin/src/features/home/screen-time.tsx`
- Create: `apps/admin/src/routes/home-screen-time.tsx`
- Create: `tests/contract/api/test_screen_time_openapi.py`
- Create: `tests/security/test_screen_time_api.py`
- Modify: `tests/integration/home/test_phase2_boot_composition.py`
- Create: `tests/e2e/home-screen-time.spec.ts`

**Interfaces:** `GET /api/v1/ui/home/screen-time`; typed policy/allowance/extension/override operations through server-prepared mutation; read model exposes eligibility, known bypasses, state, daily/weekly remaining, warnings/grace, pending extensions, evidence strength/time, attempt count, and `simulator_only=true`. This task replaces the exact `phase2.home.screen_time` registration, including its final package digest and provider/route IDs. After all rows and top-level digests freeze, the external acceptance ceremony increments the manifest version and re-signs the entire `SignedFeatureManifestV1` envelope; no row has an independent signature. The canonical container constructs the screen-time provider only from the accepted registration; the canonical app mounts only that registration's declared routes after construction succeeds. Installed-candidate composition tests exact-compare providers and routes and prove absent, disabled, unknown, stale, or drifted registrations expose neither provider nor screen-time API/direct URL and cannot read another subject or prepare a policy mutation.

- [ ] **Step 1: Write red simulator-only and private-subject tests**

```typescript
test("Phase 2 never claims either real TV is enforced", async ({page}) => {
  await mockScreenTime(page, {simulator_only:true, maximum_real_mode:"ADVISORY", bypasses:["physical_remote"]});
  await page.goto("/home/screen-time");
  await expect(page.getByText("Policy simulator — real TV enforcement is not enabled")).toBeVisible();
  await expect(page.getByRole("button", {name:/enforce now/i})).toHaveCount(0);
});

test("one child projection does not expose another ledger", async ({page}) => {
  await page.goto("/home/screen-time?child=child_synth_01");
  await expect(page.getByText("child_synth_02")).toHaveCount(0);
});
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/api/test_screen_time_openapi.py tests/security/test_screen_time_api.py tests/integration/home/test_phase2_boot_composition.py -q && pnpm --filter @tuntun/admin e2e -- tests/e2e/home-screen-time.spec.ts`
Expected: FAIL because the screen-time provider, its manifest-bound canonical composition, and API/UI routes are absent.

- [ ] **Step 3: Implement subject-filtered read model and exact mutations**

The server authorizes child/guardian/owner views before returning labels or ledger entries. Owner base-policy mutations require passkey; current primary guardian may approve exact session extension and view that child's transparent ledger; non-guardian adult may stop manually but cannot alter ledger/rule; child may request an extension but not approve it. Warning copy has reviewed English/Hindi message IDs and age-band variants, with remaining time and extension route. After final code generation, replace the screen-time registration, recompute every row and top-level digest, increment the manifest version, and externally re-sign the entire candidate envelope; construct the exact provider in `container.py`, then mount only its declared routes in `app.py`. A route-module import never constructs authority. Extend installed-candidate positive composition and absent/disabled/unknown/stale/drifted negative boot cases.

- [ ] **Step 4: Regenerate and run full UI/security/accessibility gates**

Run: `sh scripts/generate_openapi_client.sh && git diff --exit-code -- packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts && uv run pytest tests/contract/api/test_screen_time_openapi.py tests/security/test_screen_time_api.py tests/integration/home/test_phase2_boot_composition.py -q && pnpm --filter @tuntun/admin test && pnpm --filter @tuntun/admin lint && pnpm --filter @tuntun/admin typecheck && pnpm --filter @tuntun/admin build && pnpm --filter @tuntun/admin e2e -- tests/e2e/home-screen-time.spec.ts`
Expected: PASS for exact installed-candidate provider/route composition and disabled/unknown direct-path absence; owner/current-guardian/non-guardian/child/Guest matrices, no cross-subject data, exact step-up, simulator-only truth, physical-remote bypass disclosure, unknown observation/clock behavior, English/Hindi, keyboard, screen reader, 320 px, 200% zoom, dark/light, and reduced motion.

- [ ] **Step 5: Commit exact screen-time UI paths**

```bash
git add fixtures/synthetic/features/phase2-home-manifest-v1.json apps/core/src/tuntun_core/api/home_dtos.py apps/core/src/tuntun_core/api/routes/home.py apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts apps/admin/src/features/home/screen-time.tsx apps/admin/src/routes/home-screen-time.tsx tests/contract/api/test_screen_time_openapi.py tests/security/test_screen_time_api.py tests/integration/home/test_phase2_boot_composition.py tests/e2e/home-screen-time.spec.ts
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(admin): expose screen-time simulator truth"
```

**P2-6 checkpoint:** The 720 deterministic cases and at least 10,000 seeded sequences pass with exact transition/message/ledger/authority/control-attempt oracles. The UI truthfully labels Phase 2 as simulator-only; both household televisions remain manual/Advisory inventory unless a separately owning phase proves exact control and independent observation. No physical remote is described as adult-only.

---

## Wave 6 — P2-7 Backup, Restore Quarantine, Observability, Rollback, and Acceptance

### Task 31: Implement HA backup hooks and fresh-epoch restore quarantine

**Depends on:** Tasks 09, 13, 20, 23, 25‐27, 30.
**Gate contribution:** P2-7.
**Estimated effort:** 2 engineering person-days.

**Files:**
- Create: `integrations/home-assistant/custom_components/tuntun_bridge/backup.py`
- Modify: `integrations/home-assistant/custom_components/tuntun_bridge/__init__.py`
- Modify: `integrations/home-assistant/custom_components/tuntun_bridge/projection.py`
- Create: `apps/core/src/tuntun_core/services/home/restore.py`
- Create: `apps/core/src/tuntun_core/services/home/readiness.py`
- Modify: `apps/core/src/tuntun_core/adapters/home_assistant/state_sync.py`
- Modify: `fixtures/synthetic/features/phase2-home-manifest-v1.json`
- Modify: `apps/core/src/tuntun_core/api/home_dtos.py`
- Modify: `apps/core/src/tuntun_core/api/routes/home.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `packages/contracts/openapi/admin-v1.yaml`
- Modify: `apps/admin/src/api/generated/admin-v1.ts`
- Modify: `apps/admin/src/features/home/health.tsx`
- Create: `integrations/home-assistant/tests/test_backup_hooks.py`
- Create: `integrations/home-assistant/tests/test_backup_crash.py`
- Create: `integrations/home-assistant/tests/test_restore_quarantine.py`
- Create: `tests/integration/home/test_controller_epoch_rotation.py`
- Create: `tests/integration/home/test_readiness_observation_mirror.py`
- Create: `tests/integration/home/test_recovery_safe_surface.py`
- Create: `tests/contract/api/test_home_recovery_openapi.py`
- Create: `tests/security/home/test_home_recovery_authority.py`
- Modify: `tests/integration/home/test_phase2_boot_composition.py`
- Create: `tests/fault/home/test_restore_between_dispatch_reconcile.py`
- Create: `tests/fault/home/test_recovery_interruption.py`
- Create: `tests/fault/home/test_delayed_restore_feature_authority.py`
- Create: `tests/e2e/home-recovery.spec.ts`
- Modify: `docs/operations/phase2-green-backup-restore.md`

**Interfaces:** HA `async_pre_backup`/`async_post_backup`; `HAReadinessObservationV1` on the existing pinned-TLS state route; `HAReadinessValidator.accept(observation, outstanding_nonce, now) -> LocalReadinessMirror`; `HomeRestoreCoordinator.begin/reconcile/rotate_epoch/enable`; and the manifest-owned recovery-safe Core routes `GET /api/v1/ui/home/recovery` plus `POST /api/v1/home/recovery/{begin|reconcile|rotate|enable}`. `restore_quarantine_required` is durable and is read before HA registers mutation handlers/routine triggers and before Core composes mutation providers. HA does not sign readiness and has no HMAC/signing key: the Mac authenticates the server with the pinned TLS channel, exact-matches the single-use echoed request nonce, requires a strictly advancing sequence inside the current epoch/verifier stream, verifies the maximum-60-second window and exact integration package/Core build/configuration digests, and rejects replay or field substitution. Only then does it write a SQLCipher row whose canonical observation digest and authority tuple carry a Keychain-backed local authentication tag. Boot requires a fresh current channel observation that exact-matches the locally authenticated mirror; the mirror alone, an unavailable HA path, or an old observation can never reopen mutation.

The `phase2.home.read` registration owns a non-overlapping `home.recovery_safe` provider and exact recovery route IDs. Restore quarantine deliberately retains only feature-manifest-authorized read views and this recovery-safe provider; topology, permission, action, automation, screen-time and every routine-trigger provider/route remain absent. `begin` uses the normal server-prepared mutation protocol and an exact local owner-passkey receipt to freeze one recovery-ceremony digest/generation and a random single-use challenge. The owner enters that challenge only in the custom integration's local HA-admin UI; HA stores SHA-256 of the challenge, never an HMAC, and the next channel-authenticated readiness observation returns only that digest, confirmation generation and at-most-15-minute expiry. `reconcile` exact-matches and atomically consumes that one HA confirmation while committing reconciled bindings/receipts and marking old Mac work `UNKNOWN`; `rotate` can consume only that durable reconciled-stage evidence, not the already-consumed confirmation, and installs one fresh UUIDv4 epoch while incrementing routine generations. `enable` requires the complete staged evidence and a still-current or freshly repeated owner step-up, writes the new locally authenticated mirror/readiness state, and requests controlled whole-process restart/recomposition. No stage can resolve an ordinary mutation provider, call a device, dynamically add a route, skip a prior stage, reuse a confirmation, or continue after expiry/interruption; restart resumes only the durable stage with all ordinary mutation authority still absent.

A backup restored after every embedded manifest has expired is not allowed to bypass expiry and cannot expose the recovery-safe API. The operator instead stops Core and uses Task 13's verify-only `tuntunctl features stage-rollover --file PATH` with a separately delivered current/future `SignedFeatureManifestRolloverChainV1` from the external acceptance ceremony. The nofollow, owner-only, bounded importer verifies the current trusted signer plus exact installed candidate/package/registration/evidence digests, has no signing or network capability, and atomically fsync/renames the already-signed canonical chain. A controlled restart re-verifies it and composes only the read/recovery-safe generation when one envelope is currently valid; ordinary mutation remains quarantined until the complete `begin -> reconcile -> rotate -> enable` ceremony and its second controlled restart. Invalid, expired-only, interrupted, substituted, or candidate-drifted input is rejected and preserves the last staged bytes. A valid future-only chain may be staged, but a restart before its first `valid_from` remains fully closed and requires another controlled restart once authority is current. This is an offline authority-recovery mechanism, not an alternative authentication or activation route.

The signed feature manifest remains maximum authority and restore/readiness can only subtract. A live marker, readiness expiry, sequence rollback, epoch/generation/build/config substitution, lost channel, or local-mirror authentication failure immediately closes the `FeatureManifestLeaseSupervisor` admission barrier before another preparation/provider/trigger admission and initiates controlled recomposition into read/recovery-only mode. `test_phase2_boot_composition.py` exact-compares normal, unavailable-readiness, backed-up, interrupted-backup, restored, every recovery stage, and post-enable restart compositions. Direct ordinary mutation paths return the same bounded absence response and produce zero preparation while quarantined; the narrow recovery route remains reachable only when its signed read registration and lease are current.

- [ ] **Step 1: Write red archive-marker, interruption, and replay tests**

```python
async def test_every_valid_backup_contains_quarantine_marker(integration, backup_reader) -> None:
    artifact = await integration.create_backup()
    restored = backup_reader.open_receipt_db(artifact)
    assert restored.global_state.restore_quarantine_required is True

async def test_live_post_hook_clears_marker_but_interruption_does_not(integration) -> None:
    await integration.async_pre_backup()
    assert await integration.store.quarantined()
    await integration.async_post_backup()
    assert not await integration.store.quarantined()
    await integration.async_pre_backup()
    await integration.simulate_core_crash()
    assert await integration.reopen().store.quarantined()

async def test_restore_after_physical_dispatch_cannot_replay(restore_case) -> None:
    result = await restore_case.restore_snapshot_taken_between_dispatch_and_reconciliation()
    assert result.old_action_state == "UNKNOWN"
    assert result.device_calls_after_restore == 0

@pytest.mark.parametrize("fault", [
    "unsolicited_nonce", "duplicate_sequence", "older_sequence", "expired",
    "wrong_epoch", "wrong_verifier_generation", "wrong_integration_digest",
    "wrong_core_build", "wrong_configuration", "marker_state_mismatch",
    "bad_local_mirror_auth_tag",
])
async def test_readiness_fault_cannot_open_mutation(readiness_harness, fault) -> None:
    result = await readiness_harness.accept_with_fault(fault)
    assert result.mutation_admission == "closed"
    assert result.prepared_mutations == 0
    assert result.background_triggers == 0

async def test_recovery_route_is_narrow_and_stage_ordered(recovery_client) -> None:
    begun = await recovery_client.begin_with_owner_passkey()
    assert begun.stage == "BEGUN"
    assert begun.ordinary_mutation_provider_ids == ()
    with pytest.raises(RecoveryStageError):
        await recovery_client.enable(expected_generation=begun.generation)
    await recovery_client.enter_challenge_in_local_ha_admin(begun.challenge)
    reconciled = await recovery_client.reconcile(expected_generation=begun.generation)
    rotated = await recovery_client.rotate(expected_generation=reconciled.generation)
    enabled = await recovery_client.enable(expected_generation=rotated.generation)
    assert enabled.requires_controlled_restart is True

@pytest.mark.parametrize("fault", [
    "missing_owner_passkey", "replayed_owner_passkey", "wrong_ha_challenge_digest",
    "expired_ha_confirmation", "replayed_ha_confirmation", "stage_generation_race",
    "crash_after_each_stage_commit",
])
async def test_recovery_fault_stays_quarantined(recovery_harness, fault) -> None:
    result = await recovery_harness.run_with_fault(fault)
    assert result.ordinary_mutation_provider_ids == ()
    assert result.device_calls == 0
    assert result.automatic_enable_count == 0

async def test_delayed_restore_with_expired_chain_requires_offline_external_rollover(
    delayed_restore_harness,
) -> None:
    restored = await delayed_restore_harness.restore_after_all_manifests_expire()
    assert restored.http_route_ids == ()
    assert restored.ordinary_mutation_provider_ids == ()
    await restored.stop_core()
    staged = restored.tuntunctl_stage_rollover(restored.current_external_chain)
    assert staged.signer_calls == ()
    restarted = await restored.controlled_restart()
    assert restarted.route_ids == restored.manifest_read_and_recovery_route_ids
    assert restarted.ordinary_mutation_provider_ids == ()
    assert restarted.recovery_stage == "QUARANTINED"
```

- [ ] **Step 2: Run red**

Run: `uv run pytest integrations/home-assistant/tests/test_backup_hooks.py integrations/home-assistant/tests/test_backup_crash.py integrations/home-assistant/tests/test_restore_quarantine.py tests/integration/home/test_controller_epoch_rotation.py tests/integration/home/test_readiness_observation_mirror.py tests/integration/home/test_recovery_safe_surface.py tests/contract/api/test_home_recovery_openapi.py tests/security/home/test_home_recovery_authority.py tests/integration/home/test_phase2_boot_composition.py tests/fault/home/test_restore_between_dispatch_reconcile.py tests/fault/home/test_recovery_interruption.py tests/fault/home/test_delayed_restore_feature_authority.py -q && pnpm --filter @tuntun/admin e2e -- tests/e2e/home-recovery.spec.ts`
Expected: FAIL because backup hooks, channel-readiness validation/local mirror, recovery-safe owner surface, restore coordinator, and boot/live route-provider narrowing are absent.

- [ ] **Step 3: Implement backup pause/checkpoint/marker and restore sequence**

```python
async def async_pre_backup(self):
    await self._gates.close_all("backup")
    await asyncio.wait_for(self._store.wait_for_receipt_transactions(), timeout=30)
    await self._store.mark_inflight_dispatching()
    await self._store.set_restore_quarantine_required(True)
    await self._store.checkpoint(truncate=True)
    await self._store.require_integrity_ok()

async def async_post_backup(self):
    await self._store.set_restore_quarantine_required(False)
    await self._gates.reopen_if_live_epoch_healthy()
```

Any timeout, marker/checkpoint/integrity failure fails the backup and keeps gates closed. Extend the existing state projection, not the route count, with `HAReadinessObservationV1`. Its request nonce is the exact nonce already consumed by the authenticated channel exchange; its sequence comes from the process-global verifier stream; its marker/state and exact integration package/Core build/configuration digests are read atomically. `HAReadinessValidator` rejects non-outstanding/replayed nonce, nonadvancing sequence, stale window, epoch/generation/digest substitution or marker contradiction before updating the SQLCipher mirror. The mirror's authentication key is Mac-local Keychain material and never leaves the Mac. A live invalidation closes admission first and only then updates status/restarts; no cached mirror authorizes through HA unavailability.

Implement the recovery-safe provider as an explicit constructor dependency with no service locator or access to action/routine/screen-time providers. Its typed DTO exposes safe stage/generation/challenge status only. Every POST uses the Phase 1 prepared-mutation/428 protocol, exact ceremony, expected-generation CAS and a stage-scoped owner passkey. The random challenge is displayed locally, hashed with ordinary SHA-256 by HA after local-admin entry, returned only over the current pinned channel, and atomically consumed exactly once by `reconcile`; `rotate` and `enable` require the resulting durable stage receipts and cannot ask HA to replay it. Interruption before a stage commit changes nothing; interruption after commit resumes that exact durable stage with gates closed. After all Task 31 route/provider/OpenAPI/UI bytes freeze, the release ceremony replaces the `phase2.home.read` registration with the final recovery route/provider IDs, increments the manifest version, recomputes top-level and row digests, and externally re-signs the entire `SignedFeatureManifestV1` envelope; the runtime never has that signer. During an actual restore, `enable` cannot change or sign authority or open in-process routes: it persists final readiness and requests controlled Core restart/recomposition under the already-current envelope.

Document the expired-authority branch before the API ceremony: obtain an externally signed chain for the exact installed candidate on a separate trusted system, transfer it as an owner-only local file, stop Core, run `uv run --frozen --offline --no-sync tuntunctl features stage-rollover --file /absolute/owner-only/phase2-rollover-chain-v1.json`, inspect the content-safe digest receipt, and request the normal controlled service restart. The importer never accepts a signing-key argument or environment secret and performs no network I/O. If staging or the restart verifier fails, keep Core stopped or feature-closed, retain physical/HA-native recovery, and do not weaken file, signer, candidate, chain, validity, or quarantine checks.

The canonical container verifies the current observation and locally authenticated mirror before constructing mutation providers; `api/app.py` mounts only the manifest-authorized, gate-passed generation and starts no excluded trigger. Restore isolates device paths, marks pre-restore nonterminal Mac actions `UNKNOWN`, follows `begin -> reconcile -> rotate -> enable`, rotates epoch while incrementing routine generations/expiring undispatched work, pairs the new epoch on both sides, and opens each capability only after owner review and controlled restart. Old epoch signatures never dispatch.

- [ ] **Step 4: Run green with every hook/crash placement**

Run: `sh scripts/generate_openapi_client.sh && git diff --exit-code -- packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts && uv run pytest integrations/home-assistant/tests/test_backup_hooks.py integrations/home-assistant/tests/test_backup_crash.py integrations/home-assistant/tests/test_restore_quarantine.py tests/integration/home/test_controller_epoch_rotation.py tests/integration/home/test_readiness_observation_mirror.py tests/integration/home/test_recovery_safe_surface.py tests/contract/api/test_home_recovery_openapi.py tests/security/home/test_home_recovery_authority.py tests/integration/home/test_phase2_boot_composition.py tests/fault/home/test_restore_between_dispatch_reconcile.py tests/fault/home/test_recovery_interruption.py tests/fault/home/test_delayed_restore_feature_authority.py -q && pnpm --filter @tuntun/admin test && pnpm --filter @tuntun/admin lint && pnpm --filter @tuntun/admin typecheck && pnpm --filter @tuntun/admin build && pnpm --filter @tuntun/admin e2e -- tests/e2e/home-recovery.spec.ts`
Expected: PASS; valid artifact always has marker; uninterrupted live instance clears it only after archive end; interruption stays quarantined; pre-hook waits at most 30 seconds; every nonce/sequence/freshness/epoch/generation/build/config/marker/mirror-auth fault closes live and boot admission; only the manifest-owned recovery-safe provider/routes remain. A delayed restore with wholly expired authority exposes no HTTP route until a current exact-candidate external chain is safely staged while Core is stopped; that restart exposes only read/recovery-safe routes. Missing/replayed/stale passkey or HA confirmation, skipped stage and every interruption stay quarantined with zero ordinary provider/trigger/device call; post-enable requires controlled restart; restored routines stay inactive and pre-restore in-flight work never replays.

- [ ] **Step 5: Commit exact backup/restore paths**

```bash
git add integrations/home-assistant/custom_components/tuntun_bridge/backup.py integrations/home-assistant/custom_components/tuntun_bridge/__init__.py integrations/home-assistant/custom_components/tuntun_bridge/projection.py apps/core/src/tuntun_core/services/home/restore.py apps/core/src/tuntun_core/services/home/readiness.py apps/core/src/tuntun_core/adapters/home_assistant/state_sync.py fixtures/synthetic/features/phase2-home-manifest-v1.json apps/core/src/tuntun_core/api/home_dtos.py apps/core/src/tuntun_core/api/routes/home.py apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/api/app.py packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts apps/admin/src/features/home/health.tsx integrations/home-assistant/tests/test_backup_hooks.py integrations/home-assistant/tests/test_backup_crash.py integrations/home-assistant/tests/test_restore_quarantine.py tests/integration/home/test_controller_epoch_rotation.py tests/integration/home/test_readiness_observation_mirror.py tests/integration/home/test_recovery_safe_surface.py tests/contract/api/test_home_recovery_openapi.py tests/security/home/test_home_recovery_authority.py tests/integration/home/test_phase2_boot_composition.py tests/fault/home/test_restore_between_dispatch_reconcile.py tests/fault/home/test_recovery_interruption.py tests/fault/home/test_delayed_restore_feature_authority.py tests/e2e/home-recovery.spec.ts docs/operations/phase2-green-backup-restore.md
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(home): quarantine HA backup restore"
```

### Task 32: Add content-safe observability and encrypted external-backup health

**Depends on:** Tasks 09, 13‐14, 27, 30‐31.
**Gate contribution:** P2-7.
**Estimated effort:** 1.5 engineering person-days plus cold-Mac/share/restore checks.

**Files:**
- Create: `integrations/home-assistant/custom_components/tuntun_bridge/sensor.py`
- Create: `apps/core/src/tuntun_core/services/home/backup_health.py`
- Modify: `fixtures/synthetic/features/phase2-home-manifest-v1.json`
- Modify: `scripts/phase2/verify_green_backup.py`
- Create: `scripts/phase2/rotate_green_backups.py`
- Create: `scripts/phase2/audit_green_logging.py`
- Modify: `ops/home-assistant/green-backup-catchup.example.yaml`
- Create: `ops/home-assistant/logging.example.yaml`
- Create: `docs/operations/phase2-observability.md`
- Modify: `apps/core/src/tuntun_core/services/home/health.py`
- Modify: `apps/core/src/tuntun_core/api/home_dtos.py`
- Modify: `apps/core/src/tuntun_core/api/routes/home.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `packages/contracts/openapi/admin-v1.yaml`
- Modify: `apps/admin/src/api/generated/admin-v1.ts`
- Modify: `apps/admin/src/features/home/health.tsx`
- Create: `tests/unit/home/test_backup_health.py`
- Create: `tests/integration/home/test_backup_rotation.py`
- Modify: `tests/integration/home/test_phase2_boot_composition.py`
- Create: `tests/contract/api/test_backup_health_openapi.py`
- Create: `tests/security/home/test_cifs_boundary.py`
- Create: `tests/security/home/test_home_observability_content.py`
- Create: `tests/hardware/home/test_green_external_backup.py`
- Create: `tests/hardware/home/test_green_logging_retention.py`
- Create: `tests/e2e/home-backup-health.spec.ts`

**Interfaces:** HA sensors expose receipt/store pressure, mutation quarantine, routine breaker, binding freshness, and Green-side exact CIFS readiness without identities/content. `BackupHealthService.evaluate(now) -> BackupPosture`; external alert at >36h, risky update/new routine block at >72h, conditional RPO target only when one verified 60-minute Mac/SSD availability window exists in each 72h. This task changes the existing `phase2.home.read` provider graph and health representation without adding a route. After service, handler, DTO, OpenAPI, generated-client and UI bytes freeze, the release ceremony replaces that registration, recomputes its row digest plus every top-level candidate/package/evidence digest, increments `manifest_version`, and externally re-signs the entire `SignedFeatureManifestV1` envelope. A feature row has no independent signature, and runtime code cannot sign either the row or envelope. `BackupHealthService` is wired through the canonical container into the existing health handler; the canonical app's route set remains unchanged. Installed-candidate composition verifies the final provider graph and route set; absent, disabled, unknown, stale, or drifted read registrations expose neither health provider nor direct health route, while restore quarantine cannot accidentally re-enable a manifest-denied surface.

- [ ] **Step 1: Write red RPO, rotation, CIFS, and content tests**

```python
@pytest.mark.parametrize((age_hours, window_met, state, blocks), [
    (35, True, "healthy", False),
    (37, True, "degraded", False),
    (73, True, "blocked_risky_change", True),
    (10, False, "best_effort_unbounded", False),
])
def test_backup_posture_truth(age_hours, window_met, state, blocks, service) -> None:
    result = service.evaluate(sample_backup(age_hours, window_met))
    assert (result.state, result.blocks_risky_changes) == (state, blocks)

def test_rotation_keeps_seven_daily_four_weekly_and_only_successful_external(catalog) -> None:
    kept = rotate(catalog.synthetic_success_and_failures())
    assert len(kept.daily) == 7 and len(kept.weekly) == 4
    assert all(row.destination_success for row in kept.all)

def test_green_account_cannot_reach_tuntun_or_video(cifs_probe) -> None:
    assert cifs_probe.allowed_paths == ("HA_BACKUPS",)
    assert cifs_probe.denied_paths == ("TUNTUN_DATA", "TUNTUN_VIDEO", "macOS_home")

def test_backup_health_openapi_and_generated_client_are_exact(contract) -> None:
    response = contract.operation("getHomeHealth").response(200)
    assert response.schema_ref == "#/components/schemas/HomeHealthV1"
    assert contract.generated_types_match_openapi()
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/home/test_backup_health.py tests/integration/home/test_backup_rotation.py tests/integration/home/test_phase2_boot_composition.py tests/contract/api/test_backup_health_openapi.py tests/security/home/test_cifs_boundary.py tests/security/home/test_home_observability_content.py -q && sh scripts/generate_openapi_client.sh && git diff --exit-code -- packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts && pnpm --filter @tuntun/admin test && pnpm --filter @tuntun/admin typecheck && pnpm --filter @tuntun/admin build && pnpm --filter @tuntun/admin e2e -- tests/e2e/home-backup-health.spec.ts`
Expected: FAIL because backup health/rotation, the final read-provider composition, OpenAPI/generated client, contract coverage, and updated UI are absent or drifted.

- [ ] **Step 3: Implement exact readiness, catch-up, retention, and health truth**

The Green-side readiness sensor is true only after mount, write/delete, SMB 3 encryption, and free-space probes of the exact configured CIFS target. An owner-created `origin=home_assistant` fixed automation invokes only `backup.create_automatic`, allows one in-flight job and one attempt/30 minutes, and stops after destination-success receipt. Tuntun never invokes/edits it. If HAOS/Core cannot expose required readiness/success evidence, automatic catch-up and SLA are disabled/manual.

Green creates encrypted local configuration backup daily and pre-update, retains newest three locally, and succeeds locally even while Mac target sleeps. External full backup artifacts are deleted by age so receipt-detail/tombstone bounds stay at +38/+58 days. Routine backups exclude Recorder; diagnostic full backups expire within 10 days. Mac rotation keeps seven daily/four weekly only after Green destination success. Recorder remains an explicit allowlist with `purge_keep_days: 10`; the separate raw operational-log policy rotates at seven days, disables unneeded long-term statistics, redacts request bodies/identifiers/content, and fails commissioning if the delivered HAOS/Core build leaves raw-log retention unbounded or longer than Recorder. Generate the client from the committed OpenAPI document, require a clean generation diff plus contract test/typecheck/build, then replace the final read registration and externally re-sign the complete manifest envelope only after the health provider, route handler, DTO, OpenAPI, generated client, and UI bytes are frozen. Re-run installed-candidate positive and manifest-denied composition cases against that exact envelope.

- [ ] **Step 4: Run green, then cold-Mac/external backup campaign**

Run: `uv run pytest tests/unit/home/test_backup_health.py tests/integration/home/test_backup_rotation.py tests/integration/home/test_phase2_boot_composition.py tests/contract/api/test_backup_health_openapi.py tests/security/home/test_cifs_boundary.py tests/security/home/test_home_observability_content.py -q && sh scripts/generate_openapi_client.sh && git diff --exit-code -- packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts && pnpm --filter @tuntun/admin test && pnpm --filter @tuntun/admin lint && pnpm --filter @tuntun/admin typecheck && pnpm --filter @tuntun/admin build && pnpm --filter @tuntun/admin e2e -- tests/e2e/home-backup-health.spec.ts`
Expected: PASS; OpenAPI and generated client are drift-free, contract/UI tests plus lint/typecheck/build pass, and no transcript/biometric/PIN/passkey/family memory/provider secret enters sensors/logs/UI; infrastructure public key/CIFS account/TLS material is correctly classified rather than falsely absent. The installed candidate accepts only the newly externally signed whole manifest envelope.

Owner run: `TUNTUN_ALLOW_HOME_HARDWARE=1 uv run pytest -m home_hardware tests/hardware/home/test_green_external_backup.py tests/hardware/home/test_green_logging_retention.py -q --evidence-dir var/evidence/phase2/p2-7-external-backup`
Expected positive outcome: cold Mac reboot unlocks dedicated encrypted volume/share without exposing key to Green; SMB 3 encrypted packet capture contains no plaintext backup or reusable credential; unavailable Mac still permits local Green backup; recovered target starts catch-up within 30 minutes and verifies within 60 minutes; an external encrypted backup no older than 72 hours restores in isolation; emergency key copy works; Recorder is allowlisted/10-day, raw operational logs rotate at seven days, and unneeded long-term statistics are absent. If the required availability window is missed, UI shows best-effort/unbounded instead of a 72-hour claim; if raw-log retention is unsupported or unbounded, P2-7 remains blocked.

- [ ] **Step 5: Commit observability/backup code, never real evidence**

```bash
git add integrations/home-assistant/custom_components/tuntun_bridge/sensor.py apps/core/src/tuntun_core/services/home/backup_health.py fixtures/synthetic/features/phase2-home-manifest-v1.json scripts/phase2/verify_green_backup.py scripts/phase2/rotate_green_backups.py scripts/phase2/audit_green_logging.py ops/home-assistant/green-backup-catchup.example.yaml ops/home-assistant/logging.example.yaml docs/operations/phase2-observability.md apps/core/src/tuntun_core/services/home/health.py apps/core/src/tuntun_core/api/home_dtos.py apps/core/src/tuntun_core/api/routes/home.py apps/core/src/tuntun_core/bootstrap/container.py packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts apps/admin/src/features/home/health.tsx tests/unit/home/test_backup_health.py tests/integration/home/test_backup_rotation.py tests/integration/home/test_phase2_boot_composition.py tests/contract/api/test_backup_health_openapi.py tests/security/home/test_cifs_boundary.py tests/security/home/test_home_observability_content.py tests/hardware/home/test_green_external_backup.py tests/hardware/home/test_green_logging_retention.py tests/e2e/home-backup-health.spec.ts
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(home): report backup and bridge health"
```

### Task 33: Prove update rollback and the complete network/power/failure matrix

**Depends on:** All prior tasks and every enabled physical gate.
**Gate contribution:** P2-7.
**Estimated effort:** 2.5 engineering person-days plus controlled outage/update drills.

**Files:**
- Create: `scripts/phase2/run_fault_matrix.py`
- Create: `scripts/phase2/verify_network_exposure.py`
- Create: `scripts/phase2/verify_home_update.py`
- Create: `fixtures/synthetic/home/fault-matrix-v1.json`
- Create: `tests/fault/home/test_complete_phase2_matrix.py`
- Create: `tests/security/home/test_phase2_lateral_reachability.py`
- Create: `tests/security/home/test_phase2_private_data_scan.py`
- Create: `tests/integration/home/test_green_update_rollback.py`
- Create: `tests/hardware/home/test_phase2_outages.py`
- Create: `tests/hardware/home/test_phase2_network_exposure.py`
- Create: `tests/hardware/home/test_phase2_power_recovery.py`
- Create: `docs/operations/phase2-failure-recovery.md`
- Create: `docs/operations/phase2-update-rollback.md`
- Create: `docs/evidence/phase2-fault-gate-schema.json`

**Interfaces:** `Phase2FaultRunner.run(case) -> FaultEvidenceV1`; cases enumerate WAN, cloud, Reachy, Mac, Green, custom integration, Matter Server, MZHUB Ethernet, MZHUB Zigbee, inner router, BE800, disk, Recorder, key/cert/channel, topology/policy cache, command duplication/reorder/loss, restore, backup, power, brownout, and update migration. Update verifier binds HAOS/Core/Matter Server/custom-integration versions and package hashes to backup/rollback evidence.

- [ ] **Step 1: Write red complete-case and invariant tests**

```python
def test_fault_catalog_covers_every_normative_failure(catalog) -> None:
    assert set(catalog.case_ids) == REQUIRED_PHASE2_FAULT_IDS

@pytest.mark.parametrize("case_id", REQUIRED_PHASE2_FAULT_IDS)
async def test_fault_preserves_global_invariants(runner, case_id) -> None:
    evidence = await runner.run_synthetic(case_id)
    assert evidence.duplicate_effect_count == 0
    assert evidence.false_success_count == 0
    assert evidence.unsafe_retry_count == 0
    assert evidence.manual_recovery_disclosed

def test_update_failure_rolls_to_exact_compatible_artifact(update_harness) -> None:
    result = update_harness.fail_after("schema_migration")
    assert result.active_package_hash == result.prior_verified_package_hash
    assert result.mutations_enabled is False
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/fault/home/test_complete_phase2_matrix.py tests/security/home/test_phase2_lateral_reachability.py tests/security/home/test_phase2_private_data_scan.py tests/integration/home/test_green_update_rollback.py -q`
Expected: FAIL because complete fault catalog/runner and update verifier are absent.

- [ ] **Step 3: Implement deterministic faults, exposure verifier, and rollback runbook**

Update sequence is: verify encrypted local/external backup and emergency key; close mutation/routine gates; bind current/target HAOS/Core/Matter Server/custom-integration versions and hashes; apply one layer at a time; migrate receipt store in quarantine; run schema/store/state/off-registry/physical one-light probes; reconcile; enable. Any package hash, migration, Matter, state truth, backup, or rollback ambiguity restores the last compatible artifact and leaves automation/device mutation disabled until review.

Network verification inspects both NAT mapping tables, external scan, outer-to-inner direction, the disabled direct BE800 link on the one Mac, reserved source address, listener inventory, and compromised inner client/TV reachability to Reachy daemon/media/API/WebRTC/SSH. If optional dual-home is enabled it additionally probes both interfaces, exact binds/routes/firewall/DNS, cross-interface transit, restart, DHCP renewal, interface order, and default-route drift. Stronger segmentation remains `unproved` unless exact firmware and flows pass.

- [ ] **Step 4: Run synthetic matrix, then controlled physical drills**

Run: `uv run pytest tests/fault/home/test_complete_phase2_matrix.py tests/security/home/test_phase2_lateral_reachability.py tests/security/home/test_phase2_private_data_scan.py tests/integration/home/test_green_update_rollback.py -q && uv run python scripts/verify_private_data.py .`
Expected: PASS; every synthetic fault produces zero duplicate effect, false success, unsafe retry, or secret/private-content finding; update rollback restores exact prior hashes and remains quarantined until reconciliation.

Owner runs:

```bash
TUNTUN_ALLOW_HOME_HARDWARE=1 uv run pytest -m home_hardware tests/hardware/home/test_phase2_outages.py -q --evidence-dir var/evidence/phase2/p2-7-outages
TUNTUN_ALLOW_NETWORK_PROBE=1 uv run pytest -m home_hardware tests/hardware/home/test_phase2_network_exposure.py -q --evidence-dir var/evidence/phase2/p2-7-network
TUNTUN_ALLOW_UPS_TEST=1 uv run pytest -m home_hardware tests/hardware/home/test_phase2_power_recovery.py -q --evidence-dir var/evidence/phase2/p2-7-power
```

Expected: WAN/cloud loss preserves local HA/native/manual and eligible local grammar; Mac/Reachy loss preserves HA/native/manual; Green/Matter/MZHUB/router failure becomes unavailable without repeated command; external scan finds no service; the direct BE800 attachment stays disabled, optional dual-home outer/inner and Reachy forbidden flows fail, and any interface drift closes inbound family automation; brownout/low battery shuts Green gracefully before exhaustion, router/MZHUB ride-through is measured without graceful-shutdown claim, recovery reboots in documented order and replays nothing. If Reachy isolation failed, production action ingress remains absent throughout.

- [ ] **Step 5: Commit fault/update tooling and runbooks only**

```bash
git add scripts/phase2/run_fault_matrix.py scripts/phase2/verify_network_exposure.py scripts/phase2/verify_home_update.py fixtures/synthetic/home/fault-matrix-v1.json tests/fault/home/test_complete_phase2_matrix.py tests/security/home/test_phase2_lateral_reachability.py tests/security/home/test_phase2_private_data_scan.py tests/integration/home/test_green_update_rollback.py tests/hardware/home/test_phase2_outages.py tests/hardware/home/test_phase2_network_exposure.py tests/hardware/home/test_phase2_power_recovery.py docs/operations/phase2-failure-recovery.md docs/operations/phase2-update-rollback.md docs/evidence/phase2-fault-gate-schema.json
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(home): prove Phase 2 failure recovery"
```

### Task 34: Freeze Phase 2 acceptance evidence and run the seven-day household soak

**Depends on:** Tasks 01–33, every enabled hardware gate, accepted UI checkpoint U3 (UI Tasks U13–U14), and a clean candidate commit.
**Gate contribution:** final P2-7 exit.
**Estimated effort:** 1.5 engineering person-days plus one non-compressible seven-day soak.

**Files:**
- Create: `scripts/phase2/run_acceptance.py`
- Create: `scripts/phase2/verify_acceptance.py`
- Create: `docs/evidence/phase2-acceptance-schema.json`
- Create: `docs/evidence/phase2-soak-schema.json`
- Create: `docs/operations/phase2-acceptance-runbook.md`
- Create: `tests/acceptance/home/test_phase2_acceptance_gate.py`
- Create: `tests/acceptance/home/test_phase2_evidence_schema.py`
- Create: `tests/acceptance/home/test_phase2_feature_absence.py`
- Create: `tests/acceptance/home/test_phase2_feature_manifest_rollover.py`
- Create: `tests/acceptance/home/test_phase2_soak_oracles.py`

**Interfaces:** `prepare_rollover_chain(candidate, registrations, coverage, max_window=24h, overlap) -> UnsignedFeatureManifestRolloverBundleV1`; `assemble_rollover_chain(unsigned_bundle, external_signing_records, trusted_acceptance_registry) -> SignedFeatureManifestRolloverChainV1`; `verify_rollover_chain(chain, installed_candidate, planned_interval) -> VerifiedRolloverPlan`; `run_acceptance(candidate, evidence_inputs, signer) -> SignedEvidence`; `verify_acceptance(envelope, candidate, schemas, feature_manifest_chain) -> Phase2Decision`; `run_soak(duration_seconds=604800, feature_manifest_chain=verified_chain) -> SignedSoakEvidence`. The `run_acceptance` signer is the post-run evidence attestor over a completed report, never a feature-authority signer and never available to the running campaign. The prepare/assemble/verify programs contain no private key, signer port, renewal call, or network fetch and are not imported into the Core runtime. Preparation freezes chain identity, contiguous indices/versions, candidate/package/registration/evidence authority and distinct future-capable `valid_from`/expiry slots; only actual `issued_at`, signer key ID/signature, and each successor's deterministically derived previous-signed-envelope digest remain for the isolated ceremony. That ceremony processes envelopes in order: it records the real signing time, sets index zero's predecessor to `None` or hashes the complete prior signed envelope for a successor, canonicalizes the completed envelope, and signs every field including those values. Assembly independently reconstructs and verifies those exact bytes. The result requires `issued_at <= valid_from < expires_at <= valid_from + 24h`; index zero has no previous digest, every later envelope exact-hash-links its predecessor, overlaps it, and strictly extends expiry. The frozen candidate/package/registration/evidence authority is byte-identical across the complete chain. Core, the soak runner, and these assembly tools cannot self-sign, extend, or substitute authority.

At startup, every loop iteration and every rollover/restart boundary, the soak runner calls the shared `FeatureManifestLeaseSupervisor`. It refuses a chain that does not cover the full planned interval, activates nothing before `valid_from`, and requires both the active envelope's half-open wall window and its process-local monotonic lease at every admission/background iteration. Before the elapsed clock starts, the chain must have been staged with Core stopped and activated by controlled restart; the runner bounded-reopens that initial restart receipt and exact-compares its envelope/candidate/provider/route/composition generation with the supplied chain and live composition. Each later controlled whole-composition rollover emits one locally authenticated transition receipt binding chain ID, predecessor/successor envelope digests and versions, old/new composition generations, barrier-close/CAS/barrier-open timestamps, sampled wall/monotonic clocks and successor lease deadline. `SignedSoakEvidence.feature_authority` is the same `FeatureAuthorityCampaignEvidenceV1` used by the P2-1 pilot: it binds the chain and ordered envelope/transition/restart/sample-log digests. Task 34 imports Task 13's sole-owned `tests/support/feature_authority_campaign.py` oracle to reopen those referenced artifacts and exact-check every envelope version, `issued_at`, `valid_from`, expiry, signer key ID, active lease and composition generation. Verification rejects a missing initial activation receipt, stale production composition, missing, extra, late, early, reordered, wrong-signer, signature-invalid, nonextending, gap-bearing, candidate-drifted, stale-generation or unreceipted rollover; any expired-authority interval invalidates the entire uninterrupted soak and requires a fresh seven-day run. This Phase 2 evidence shape and verifier are the canonical ones inherited by Phases 3–6 for their longer campaigns.

Acceptance and soak evidence is content-safe, signed, and binds exact candidate commit, Phase 1 `FB0` evidence hash plus the exact consumed-interface contract/test digests named in Global Constraint 1, schemas/policies/corpora/migrations/UI/HA package hashes, pseudonymous hardware/firmware/config digests, commands, start/end, operator, and deviations. It neither requires nor makes a claim about the parallel Phase-1-only `P1R0` preview.

- [ ] **Step 1: Write red semantic gate and feature-absence tests**

```python
def test_true_label_cannot_override_failed_counts(valid_report) -> None:
    valid_report["suites"]["authorization_1350"].update(executed=1350, passed=1349, failed=1)
    valid_report["claimed_pass"] = True
    decision = verify_acceptance_payload(valid_report)
    assert not decision.allowed and "authorization_1350:failed" in decision.failures

@pytest.mark.parametrize("feature", ["tv_enforcement", "hazardous_actions", "public_remote", "general_ha_api"])
def test_excluded_feature_is_absent_across_all_surfaces(installed_candidate, feature) -> None:
    evidence = probe_feature_absence(installed_candidate, feature)
    assert evidence.source_registration == "absent"
    assert evidence.package_registration == "absent"
    assert evidence.configuration == "absent"
    assert evidence.api == "absent"
    assert evidence.direct_url == "absent"
    assert evidence.prepared_action_issuance == "absent"
    assert evidence.client_registration == "absent"
    assert evidence.client_bundle_chunk == "absent"
    assert evidence.network == "absent"

def test_soak_label_cannot_replace_elapsed_time(valid_soak) -> None:
    valid_soak["monotonic_elapsed_seconds"] = 604799
    assert "elapsed" in verify_soak(valid_soak).failures

@pytest.mark.parametrize("mutation", [
    remove_required_rollover,
    remove_activation_receipt,
    activate_initial_successor_instead_of_index_zero,
    reorder_two_envelopes,
    replace_with_wrong_signer,
    create_validity_gap,
    activate_before_valid_from,
    admit_at_or_after_expiry,
    drift_candidate_or_registration,
    reuse_old_composition_generation,
])
def test_soak_rejects_incomplete_or_stale_feature_authority(valid_soak, mutation) -> None:
    decision = verify_soak(mutation(valid_soak))
    assert not decision.allowed
    assert decision.failures

def test_every_scheduled_rollover_is_bound_once(valid_soak) -> None:
    authority = valid_soak["feature_authority"]
    assert authority["early_admission_count"] == 0
    assert authority["expired_admission_count"] == 0
    assert authority["uncovered_wall_or_monotonic_seconds"] == 0
    assert len(authority["ordered_transition_receipt_digests"]) == (
        len(authority["ordered_manifest_digests"]) - 1
    )
    assert reopen_transition_receipts(authority).successor_digests == tuple(
        authority["ordered_manifest_digests"][1:]
    )

def test_candidate_has_one_canonical_location_key(installed_candidate) -> None:
    evidence = probe_location_contracts(installed_candidate)
    assert evidence.canonical_household_location_keys == ("area_id",)
    assert evidence.subordinate_location_keys == ("zone_id",)
    assert evidence.parallel_or_compatibility_keys == ()
    assert evidence.zone_parent_and_generation_checks == "enforced"
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/acceptance/home/test_phase2_acceptance_gate.py tests/acceptance/home/test_phase2_evidence_schema.py tests/acceptance/home/test_phase2_feature_absence.py tests/acceptance/home/test_phase2_feature_manifest_rollover.py tests/acceptance/home/test_phase2_soak_oracles.py -q`
Expected: FAIL because Phase 2 evidence builders/verifiers and externally signed rollover-chain/transition evidence are absent.

- [ ] **Step 3: Implement strict evidence schemas and semantic verifier**

The acceptance schema is recursively `additionalProperties:false` and has no caller-authored pass Boolean. The verifier recomputes exact suite sets/counts, zero fields, thresholds, elapsed durations, hash bindings, enabled-feature positive gates, disabled-feature source/package/configuration/API/direct-URL/prepared-action/client-registration/client-bundle/network absence gates, archive/retention bounds, and hardware-decision consistency. Required suite minima include:

- authorization corpus: exactly 1,350 and zero oracle mismatch;
- target resolution: at least 100 randomized and zero wrong endpoint;
- screen-time corpus: exactly 720 and zero oracle mismatch;
- screen-time property: at least 10,000 sequences and zero invariant failure;
- duplicate/delay/reorder/loss/crash timing: every Mac/HA/scene/routine transition, including both sides of pre-dispatch commit, admission/dispatch writer contention across expiry and the two-second bound, and post-commit no-yield actual-start resampling;
- truthful results: every accepted-failure match/mismatch/source/freshness/timing vector and every scene homogeneous/verified-mixed/no-verified-mixed aggregate vector, with zero accepted `FAILED` lacking a fresh contradiction and zero `PARTIAL` lacking a `VERIFIED` child;
- signed-route adversarial matrix: standard API, off-registry, wrong domain/key/epoch/generation/noncanonical/replay/oversize/rate paths, zero state leak/action;
- topology surface matrix: generated JSON Schema, Pydantic serialization, migration metadata, OpenAPI, generated TypeScript, synthetic fixtures, prepared-action bindings, and installed API accept only canonical `area_id`; optional `zone_id` is generation-bound beneath one area/owning binding, while cross-area moves and every parallel/compatibility location key are absent or rejected;
- receipt retention/quota/corruption/backup archive bounds;
- routine CAS/feedback/budget/circuit/restore quarantine;
- network/private-data/backup/restore/update/power evidence;
- seven elapsed one-light days and seven elapsed household-soak days where the bridge path is enabled;
- one externally signed `SignedFeatureManifestRolloverChainV1` covering the entire planned and actual campaign interval, with every at-most-24-hour envelope and transition/restart receipt bound exactly once, zero early/expired admission, zero wall or monotonic lease gap, one immutable candidate/registration set, and no runtime signer capability.

- [ ] **Step 4: Freeze one clean candidate and execute the evidence ceremony**

Run before physical evidence:

```bash
test -z "$(git status --porcelain)"
make bootstrap
make check
make test-security
make test-contract
make web-test
make web-build
make verify-private-data
uv run pytest -m "not home_hardware and not elapsed" -q
uv run pytest integrations/home-assistant/tests -q
uv run python scripts/phase2/run_acceptance.py synthetic --commit "$(git rev-parse HEAD)" --output var/evidence/phase2/synthetic-acceptance.json
uv run python scripts/phase2/verify_acceptance.py var/evidence/phase2/synthetic-acceptance.json --commit "$(git rev-parse HEAD)"
```

Expected: clean candidate; all software suites/static/UI/content scans pass; synthetic acceptance verifies exact counts/hashes and every disabled route.

Before starting any elapsed clock, prepare the unsigned chain from that exact clean commit and final manifest registrations. Export actual `START_RFC3339`/`END_RFC3339` coverage bounds with enough margin for commissioning and the full run; the block captures the clean `HEAD`, fails if either bound is absent, and the tool derives as many overlapping envelopes as required (within the 256-envelope cap) without setting `issued_at` itself:

```bash
test -z "$(git status --porcelain)"
CANDIDATE_COMMIT="$(git rev-parse HEAD)"
: "${START_RFC3339:?export START_RFC3339}"
: "${END_RFC3339:?export END_RFC3339}"
uv run python scripts/phase2/prepare_feature_manifest_rollover.py --candidate-commit "$CANDIDATE_COMMIT" --manifest-template fixtures/synthetic/features/phase2-home-manifest-v1.json --coverage-start "$START_RFC3339" --coverage-end "$END_RFC3339" --max-window-seconds 86400 --overlap-seconds 300 --output var/evidence/phase2/feature-authority/unsigned-rollover-bundle.json
```

Transfer only that canonical unsigned bundle to the existing isolated Phase 1 acceptance-signing ceremony. In index order, the ceremony inserts its real signing time as `issued_at`, sets the first predecessor to `None` or derives the successor predecessor from the complete prior signed envelope, canonicalizes the resulting envelope, signs it for purpose `acceptance` and discriminator `tuntun.feature-manifest.v1`, and returns one record containing that `issued_at`, derived predecessor, signer key ID and detached signature. It may alter no chain identity/index/version, candidate, registration or validity-slot field. No runtime command or soak script receives signer access. Assemble and verify the returned chain before installing it:

```bash
test -z "$(git status --porcelain)"
CANDIDATE_COMMIT="$(git rev-parse HEAD)"
: "${START_RFC3339:?export START_RFC3339}"
: "${END_RFC3339:?export END_RFC3339}"
uv run python scripts/phase2/assemble_feature_manifest_rollover.py --unsigned-bundle var/evidence/phase2/feature-authority/unsigned-rollover-bundle.json --external-signing-records /absolute/owner-only/external-signing-records.json --signer-registry security/evidence-signers-v1.json --output var/evidence/phase2/feature-authority/signed-rollover-chain.json
uv run python scripts/phase2/verify_feature_manifest_rollover.py --chain var/evidence/phase2/feature-authority/signed-rollover-chain.json --commit "$CANDIDATE_COMMIT" --coverage-start "$START_RFC3339" --coverage-end "$END_RFC3339"
uv run tuntunctl service stop
uv run --frozen --offline --no-sync tuntunctl features stage-rollover --file var/evidence/phase2/feature-authority/signed-rollover-chain.json
# At/after index zero valid_from and strictly before its expiry, perform the controlled start.
uv run tuntunctl service start
```

The ceremony fails before the campaign if signatures are missing/untrusted, `issued_at` is later than `valid_from`, a window exceeds 24 hours, index zero has a predecessor, any later digest/version/expiry is noncontiguous or nonextending, windows do not overlap, coverage is short, or candidate/package/registration/evidence bytes differ. Choose index zero's `valid_from` far enough in the future to finish external signing, transfer, verification and staging, but start Core only inside that first half-open window; if it is missed, discard the attempt and generate a fresh chain rather than starting the campaign on a successor. The assembler also refuses unsafe output ownership/mode or replacement; keep detached signatures and all generated authority/evidence under owner-only ignored storage and commit none of them. The Core-stopped staging and controlled restart above are mandatory even when the previous composition appears healthy: the soak cannot start until its startup check exact-matches chain index zero plus the active candidate/provider/route generation and reopens the initial restart-activation receipt that will be bound into campaign evidence. If the restored/current Core has no valid authority, use this same staging path, although non-campaign delayed-restore recovery may activate whichever envelope is current; do not use an expired manifest to expose an HTTP recovery route.

Then run the elapsed/physical gate:

```bash
TUNTUN_ALLOW_ELAPSED_PHASE2=1 uv run python scripts/phase2/run_acceptance.py household-soak --duration-seconds 604800 --sample-seconds 60 --commit "$(git rev-parse HEAD)" --feature-manifest-chain var/evidence/phase2/feature-authority/signed-rollover-chain.json --evidence-root var/evidence/phase2 --output var/evidence/phase2/household-soak.json
uv run python scripts/phase2/verify_acceptance.py var/evidence/phase2/household-soak.json --commit "$(git rev-parse HEAD)" --require-physical-gates
uv run python scripts/verify_private_data.py var/evidence/phase2
```

Expected: the staged-chain restart produces one exact initial activation receipt for the live final candidate/provider/route composition before time begins; monotonic and wall elapsed are each at least 604,800 seconds; every scheduled at-most-24-hour envelope is externally signed and appears once in ordered evidence, every successor activation/restart has one exact transition receipt, and every admission/background sample has a current wall-valid and monotonic-valid lease under one composition generation. There are zero authority gaps, early/expired admissions, stale-generation calls, wrong-device commands, false completions, duplicate effects, unbounded retries, silent automation changes, post-disable undispatched routines, cross-profile/Guest/child violations, or losses of physical/manual recovery. Backup/network/power/update and conditional feature decisions remain current; evidence scan finds no raw identifier/content/secret. A missing/stale initial activation, missing/late/invalid rollover, or source, policy, schema, UI, integration, firmware, router, area/zone, or hardware revision change invalidates its dependent evidence, closes authority, and returns that capability to quarantine; the interrupted soak does not count.

- [ ] **Step 5: Commit evidence tooling before the frozen run; never commit generated owner evidence**

```bash
git add scripts/phase2/run_acceptance.py scripts/phase2/verify_acceptance.py docs/evidence/phase2-acceptance-schema.json docs/evidence/phase2-soak-schema.json docs/operations/phase2-acceptance-runbook.md tests/acceptance/home/test_phase2_acceptance_gate.py tests/acceptance/home/test_phase2_evidence_schema.py tests/acceptance/home/test_phase2_feature_absence.py tests/acceptance/home/test_phase2_feature_manifest_rollover.py tests/acceptance/home/test_phase2_soak_oracles.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(home): freeze Phase 2 acceptance gate"
```

After this commit, restart Step 4 from the new clean commit. Generated evidence remains under ignored `var/evidence/phase2/` and is never added to Git.

## Effort and Calendar Envelope

The mechanically normalized task estimates total **53.5 engineering person-days**, approximately **10.7 focused one-developer weeks** at five engineering days per week, inside the locked Phase 2 planning envelope of 8–12 focused weeks. These values size implementation/review work only; the named physical, operator, recovery and elapsed gates remain additional calendar time and cannot be compressed to fit an estimate.

| Work package | Tasks | Engineering person-days |
|---|---:|---:|
| Contracts, fakes, persistence, policy and offline target resolution | 01–07 | 9.0 |
| Green integration, receipt/signing/state boundary, owner UI and P2-0 | 08–14 | 10.5 |
| MZHUB one-light/twelve-light commissioning and conditional fallback | 15–17 | 3.0 |
| Durable actions, reconciliation, family policy, scenes and action UI | 18–23 | 10.5 |
| Automation governance, signed routines, runtime and Learning UI | 24–27 | 7.5 |
| Screen-time persistence, simulator and policy UI | 28–30 | 5.5 |
| Backup/restore, observability, fault/update/rollback and acceptance | 31–34 | 7.5 |
| **Total** | **01–34** | **53.5 (~10.7 focused weeks)** |

Non-compressible calendar evidence includes the target-Mac Secure Enclave probe; same-day UPS quote and supported-signalling/NUT verification before ordering; protected-power installation and outage/recovery trials; actual MZHUB capability probing with a seven-day one-light pilot; area-by-area twelve-light observation; any destructive one-light re-pair fallback trial; cold-Mac, encrypted-share, backup, isolated-restore and fresh-epoch reconciliation; controlled outage/update rollback drills; and the separate seven-day household soak. Hardware availability, return windows, installation/repair lead time and owner-supervised ceremonies extend calendar duration without changing the 53.5 engineering person-day total or weakening a gate.

---

## Dependency and Parallelization Map

```text
01 contracts → 02 fakes/corpora
01/02 → 03 topology/policy → 04 actions → 05 automation/screen persistence
03/04/05 → 06 policy amendments; 01/02/03/06 → 07 offline target path
01/02 → 08 HA scaffold → 09 receipt store; 01/08/09 → 10 verifier/key → 11 state route; 03/10/11 → 12 sync/health
03/06/12 → 13 owner read UI → 14 P2-0 evidence
13/14 → 15 MZHUB one-light gate with continuous feature authority → 16 twelve-light baseline
15 failure + owner decision → 17 conditional direct-Zigbee pilot → 16
04/06/07/10/12/16 → 18 Mac action; 08/09/10/18 → 19 HA dispatch; 12/18/19 → 20 reconcile
03/06/18/19/20 → 21 family policy; 03/04/18/19/20/21 → 22 scenes; 13/18/19/20/21/22 → 23 action UI/composition
05/06/13/21 → 24 draft governance; 09/10/19/24 → 25 routine install; 09/19/20/25 → 26 routine runtime; 05/13/24/25/26 → 27 Learning/UI composition
02/05/06 → 28 screen state; 02/28 → 29 eligibility simulator; 13/28/29 → 30 screen UI composition
09/13/20/23/25/26/27/30 → 31 backup/restore composition; 09/13/14/27/30/31 → 32 observability/external backup/final read composition
all enabled paths → 33 fault/update/rollback → 34 acceptance/soak
```

Tasks 03–07 and 08‐11 may proceed in separate clean worktrees after shared Task 02 is accepted; each branch still honors the exact prerequisites above. Tasks 24 and 28 may proceed in parallel after their declared dependencies. Physical campaigns are serialized against the single household controller estate; a cloned Matter fabric, Zigbee coordinator identity, or routine controller never runs beside production.

## Requirements Traceability

| Requirement | Primary tasks |
|---|---|
| Canonical topology/event/action contracts and future seams | 01, 03, 12 |
| Sole canonical `area_id`; optional versioned binding-owned `zone_id`; no parallel location key | 01, 03, 13, 16, 21, 34 |
| Signed feature registry, shared rollover/lease authority, multi-day campaign evidence, and backend/API/direct-URL/client-chunk absence | 13, 15, 34 |
| Four Phase 1 amendments and no unknown-candidate regression | 06‐07, 21 |
| No HA token/general API; signed narrow TCB | 08, 10‐11, 19, 25, 33 |
| MZHUB capability probe with independent Matter/Thread findings | 14‐15 |
| One-light then twelve-light staged rollout, including continuous P2-1 feature authority | 13, 15‐16 |
| Conditional ZBT-2/ZHA fallback | 17 |
| Durable Mac/HA action state, timing, idempotency, reconciliation | 04, 09, 18‐20 |
| Adult/child/guardian/Guest/anonymous and restrictive precedence | 06, 21 |
| Immutable scenes and truthful partial failure | 03, 22‐23 |
| Manual/Assisted/Learning governance | 05, 24‐27 |
| Screen-time simulator, TV eligibility, bounded enforcement | 05, 28‐30 |
| Owner UI feature gates, no optimism, accessibility/localization | 13, 23, 27, 30, 32 |
| HA Green/UPS/two-router topology and negative reachability | 14, 33 |
| Receipt retention/quota/corruption and backup archive bounds | 09, 31‐32 |
| Green local/external backup, catch-up, restore quarantine/epoch | 14, 31‐32 |
| Update rollback, full failure injection, privacy/security scan | 33 |
| Synthetic evidence, seven-day P2-1 pilot, and seven-day household soak | 02, 13, 15, 34 |

## Final Phase 2 Go/No-Go Checklist

- [ ] Phase 1 `FB0` evidence and every named consumed Phase 1 contract/service digest are current; Phase-1-only `P1R0` is not treated as a prerequisite; all four named amendments are current.
- [ ] Exact MZHUB identity/attestation and independent capability findings are recorded; no Matter or Thread behavior is inferred. Its seven-day pilot binds the complete same-candidate pre-issued chain and every transition/restart receipt with zero early/expired/gap/stale-generation/runtime-signer/runtime-renewal count.
- [ ] Exactly one accepted controller branch is active; no device belongs to two Zigbee coordinators.
- [ ] Twelve endpoints/aliases/bindings are exact, generation-bound, and have zero wrong-target results.
- [ ] `area_id` is the only canonical household location key across schemas, migration metadata, APIs, generated clients, fixtures, prepared operations, and installed behavior; optional `zone_id` records remain immutable-area, generation-bound children of one owning binding, and no compatibility mapping exists.
- [ ] Secure Enclave actual signing, pinned TLS, challenge/replay lifecycle, source filtering, and clock-offset gate pass.
- [ ] No HA/Supervisor/user token exists; standard HA APIs and every off-registry/custom escape path produce zero Tuntun mutation/state leak.
- [ ] Mac and HA state machines, store-owned post-lock admission/dispatch clocks, no-yield post-commit call-start checks, accepted-failure evidence truth tables, deadlines, receipts, rate limits, crash recovery, retention, quota, and corruption gates pass.
- [ ] Adult convenience is limited to one exact reversible light; child dual approval and Guest owner co-approval match every oracle; anonymous side effects are zero.
- [ ] Scene definitions/execution have exact passkey/confirmation, 1–12 canonical children, `PARTIAL` only with a verified effect plus a non-verified child, exact no-effect `FAILED|UNKNOWN` aggregation, and no rollback fiction.
- [ ] Manual is default; Assisted/Learning have no silent install; routine CAS/budgets/circuit/disable/restart/restore gates pass; wall-time routines prove exact pinned `ZoneInfo` activation and the complete fold/gap/rollback/no-replay policy.
- [ ] Screen-time 720-case and 10,000-sequence gates pass; real TV enforcement remains absent/Advisory unless separately qualified.
- [ ] UI routes are signed-feature-gated, no optimistic state appears, bypasses/manual recovery are disclosed, and English/Hindi/accessibility/responsive gates pass.
- [ ] Green local/external backup, SMB encryption, availability-conditioned RPO truth, archive retention, isolated restore, and new-epoch quarantine pass.
- [ ] Exact UPS/NUT, power recovery, router/AiMesh, external scan, single-homed one-Mac baseline (plus optional dual-home interface gate when enabled), and Reachy isolation branch pass.
- [ ] Update/rollback preserves the prior compatible release and never reopens mutation before reconciliation.
- [ ] Private-data/content scan passes; only synthetic fixtures and content-safe evidence tooling are tracked.
- [ ] Seven elapsed household-soak days pass under the complete same-candidate pre-issued chain, with every rollover/restart receipt and zero early/expired/gap/stale-generation/runtime-signer/runtime-renewal count, wrong-device action, false completion, unsafe retry, silent automation change, or lost manual recovery.

## Implementation Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-27-tuntun-phase2-home-automation-execution.md`.

Execute Tasks 01–34 with `superpowers:subagent-driven-development` (recommended) for fresh task workers and two-stage review, or `superpowers:executing-plans` for checkpointed inline batches. Start no physical Phase 2 mutation until P2-0 and the relevant hardware gate are accepted; conditional P2-F requires its explicit owner decision.
