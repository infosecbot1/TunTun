# Tuntun Phase 2 Home Automation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver deterministic, local, policy-governed control of twelve MOES Zigbee ceiling lights through a capability-proved Home Assistant Green/MZHUB path, governed light scenes and routines, and a simulator-only screen-time policy foundation without expanding Home Assistant, a model, a Guest session, or an unproved television into household authority.

**Architecture:** Extend the Phase 1 Mac modular monolith with versioned topology, policy, action, automation, screen-time, owner-API, and UI modules. A narrow Home Assistant Core custom integration on Green exposes only signed state, desired-state action, and bounded-routine routes; it owns a separate durable receipt database and translates compiled light capabilities using Home Assistant system context, while the Mac retains identity, family policy, passkeys, action commitment, audit, and reconciliation authority. Commission the existing MZHUB through a no-reset capability probe and one-light pilot before twelve-light rollout; direct Zigbee through ZBT-2 is a conditional, separately approved fallback.

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

## Global Constraints

1. Phase 1 family-ready gate `FB0` must pass before Phase 2 household mutation is enabled. Phase 2 consumes the accepted `IdentityFusionPort` Guest-on-uncertainty decision, `PolicyEnginePort`, `AuthenticationPort`, `ActionBinding`/single-use `AuthGrant`, serialized SQLCipher `AsyncUnitOfWork`, `ActionMutationCoordinator`, `ActionProviderPort`, `AuditPort` plus transactional audit outbox, loopback owner-console prepared-mutation/428 protocol, backup/restore smoke evidence, and Reachy isolation decision. Each consumed interface must retain its FB0 contract and tests; the later Phase-1-only `P1R0` preview may proceed in parallel and is not a Phase 2 entry gate.
2. All committed fixtures, screenshots, examples, evidence schemas, and tests are synthetic. No household name, real area/display alias, IP/MAC, serial, certificate, Matter setup code, vendor account, entity ID, light model signature, TV identifier, biometric, transcript, memory, credential, or provider/device body enters Git or CI.
3. Real capability evidence is written only to ignored owner storage under `var/evidence/phase2/` using pseudonymous device IDs and content-safe hashes. Tests use `fixtures/synthetic/home/` and temporary keys/databases.
4. Home Assistant receives no Tuntun user identity, biometric evidence, transcript, canonical memory, PIN, passkey credential, provider context, family policy rationale, or actor ID.
5. The Mac receives no Home Assistant user, refresh token, long-lived token, general REST/WebSocket credential, Supervisor token, or arbitrary service permission.
6. The custom integration is the explicit privileged TCB. Its three routes are the only Tuntun-to-HA routes: signed state/heartbeat, signed desired-state action, and signed bounded-routine manifest. It holds no HA/Supervisor credential and accepts no caller-selected entity, service, template, script, scene, automation, YAML, event name, or argument bag.
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
18. Mac action timing is exact: `issued_at >= authorized_at`, signing occurs no more than five seconds after authorization, `expires_at <= authorized_at + 30 seconds`, and measured Mac/Green offset must be at most two seconds. HA must durably commit `PRE_DISPATCH` before expiry and start service I/O within two seconds of that commit and before expiry.
19. HA receipt storage uses WAL, `synchronous=FULL`, a 100 MiB hard quota, maintenance at 75%, mutation rejection at 90%, no purge of nonterminal rows, immutable `terminal_at`, full live detail through `terminal_at + 10 days`, and keyed tombstone through `terminal_at + 30 days`.
20. Encrypted HA backup retention discloses archive bounds separately: full receipt detail may remain through `terminal_at + 38 days`, and tombstones through `terminal_at + 58 days`. Archive deletion, not restore-time compaction, ends that retention.
21. The random 256-bit `controller_epoch` must match on Mac and Green. Restore or rollback isolates device paths, rotates to a fresh epoch using owner passkey plus local HA owner/admin confirmation, marks old nonterminal Mac actions `UNKNOWN`, and quarantines every restored routine.
22. Home Assistant Recorder has an explicit allowlist, `purge_keep_days: 10`, and no unnecessary long-term statistics. Learning projections and unapproved drafts expire in at most 30 days; screen-time session detail expires in 30 days.
23. Green, the inner router/switch, and MZHUB are the UPS load. A proved NUT signalling path shuts down Green before exhaustion; router/switch/MZHUB are described only as ride-through loads unless their own shutdown interfaces are independently proved. Household lights are not promised during mains loss.
24. The BE800 is the outer router and office-laptop network. The GT-AX6000 and three AX5400 nodes are the inner household network. Double NAT is topology, not mutual isolation. No VLAN/SSID isolation claim is allowed without exact firmware and negative reachability evidence.
25. Green and MZHUB remain on the same inner LAN for the bridge pilot. IPv6, mDNS, Matter discovery, and every actual AiMesh wired/wireless path are proved; speculative segmentation must not break commissioning.
26. No public inbound route, port forwarding, DMZ, UPnP, NAT-PMP/PCP mapping, WAN administration, or Home Assistant Cloud remote access is enabled. Phase 6 owns any remote owner route.
27. Reachy production voice ingress is enabled only if its Phase 1 isolation gate passed. Otherwise automatic voice/face processing and action ingress are absent, and only the owner-authenticated loopback commissioning harness exercises the post-intent path.
28. The existing MZHUB/light network is never reset before P2-1 passes or the owner explicitly approves conditional P2-F. One failed Matter observation does not authorize a twelve-light migration.
29. Ordinary tests perform no paid, WAN, hardware, Keychain, Secure Enclave, Home Assistant, router, SMB, or UPS I/O. Marker-gated campaigns require explicit environment flags and bounded, pseudonymized evidence destinations.
30. Project-wide branch coverage remains at least 85%; policy/auth/action/signature/receipt/routine/restore modules remain at least 95%. Every implementation task follows red → green → refactor → affected suite → static/security checks → exact-path commit.

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
| P2-1 | P2-0 and exact MZHUB evidence | One-light Matter bridge path proves fidelity, truthful state, WAN-off use, reboot/AiMesh recovery for seven elapsed days | Keep MZHUB/native estate; open P2-F decision only |
| P2-2 | Either P2-1 `PASS_BRIDGE` or P2-F passed one exact fallback controller path | Twelve stable endpoints have zero ambiguity/wrong-device/false-success cases | Only passed endpoints are registered; household rollout stops |
| P2-3 | P2-2 plus Secure Enclave signing | Signed state route exposes only compiled projection; mutation routes absent | Tuntun home control remains read-only/absent |
| P2-4 | P2-3 | Single actions, scenes, adult/child/Guest/anonymous matrix, durable reconciliation, and owner UI pass | Physical/HA-native control remains; Tuntun mutation absent |
| P2-5 | P2-4 | Manual/Assisted/Learning manifests, deterministic runtime, budgets, drift, rollback, and quarantine pass | Domain stays Manual; routine endpoint absent |
| P2-6 | P2-E0 | Screen-time simulator passes 720-case corpus and 10,000 property sequences | Real televisions remain Advisory/manual and unregistered for enforcement |
| P2-7 | All enabled gates | Failure matrix, restore, network, power, retention, seven-day household soak, and signed promotion evidence pass | Affected capability is quarantined/absent; unaffected manual paths continue |
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
packages/contracts/src/tuntun_contracts/ui.py
schemas/home/v1/
├── topology-v1.schema.json
├── events-v1.schema.json
├── channel-v1.schema.json
├── actions-v1.schema.json
├── routines-v1.schema.json
├── screen-time-v1.schema.json
└── ui-v1.schema.json
schemas/features/v1/feature-manifest-v1.schema.json
schemas/ui/v1/operation-result-v1.schema.json
fixtures/synthetic/home/contracts/
├── topology-v1.json
├── state-event-v1.json
├── state-snapshot-v1.json
├── state-delta-v1.json
├── channel-proof-v1.json
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
└── registry.py
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
        if len(location_by_id) != len(self.binding_locations) or set(location_by_id) != set(binding_by_id):
            raise ValueError("topology_binding_location_set_mismatch")
        zone_ids = tuple(zone.zone_id for zone in self.zones)
        if len(set(zone_ids)) != len(zone_ids):
            raise ValueError("duplicate_topology_zone")
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
        return self

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
    backend_route_ids: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9._:/{}-]*$")], ...],
        Field(max_length=32),
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
    def unique_feature_routes(self) -> "FeatureRegistrationV1":
        if len(set(self.backend_route_ids)) != len(self.backend_route_ids):
            raise ValueError("duplicate_feature_backend_route")
        return self

class SignedFeatureManifestV1(HomeContract):
    manifest_schema_version: Literal["tuntun.feature-manifest.v1"]
    manifest_version: Annotated[int, Field(ge=1)]
    candidate_digest: Sha256Digest
    package_digest: Sha256Digest
    registrations: Annotated[tuple[FeatureRegistrationV1, ...], Field(min_length=1, max_length=64)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    signer_key_id: KeyId
    signature: P256Signature

    @model_validator(mode="after")
    def exact_feature_manifest(self) -> "SignedFeatureManifestV1":
        feature_ids = tuple(row.feature_id for row in self.registrations)
        module_ids = tuple(row.ui_module_id for row in self.registrations)
        if len(set(feature_ids)) != len(feature_ids) or len(set(module_ids)) != len(module_ids):
            raise ValueError("duplicate_feature_or_ui_module")
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(hours=24):
            raise ValueError("feature_manifest_window_invalid")
        return self

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
        return self

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

class HomeStateSnapshotV1(HomeContract):
    state_schema_version: Literal["1.0"]
    cursor: StateCursorV1
    endpoints: Annotated[tuple[HomeEndpointStateV1, ...], Field(max_length=12)]
    health: Annotated[tuple[HomeBoundaryHealthV1, ...], Field(min_length=2, max_length=2)]
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
        timestamps = [row.observed_at for row in self.changes if row.observed_at is not None]
        timestamps.extend(row.observed_at for row in self.health)
        if any(value > self.heartbeat_at for value in timestamps):
            raise ValueError("projection_timestamp_after_heartbeat")
        return self
```

`StateCursorV1.sequence` is monotonic only inside the exact `(controller_epoch, verifier_generation)` stream. A missing or foreign stream cursor never produces a reset-flavoured delta: the route returns a fresh `HomeStateSnapshotV1`. Snapshot rows are unique and ordered by `endpoint_id`; delta rows contain only the latest change for each endpoint and are ordered by their global sequence.

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

class HomeActionResultV1(HomeContract):
    result_schema_version: Literal["1.0"]
    action_id: UUID
    desired_state: LightDesiredStateV1
    terminal_state: Literal["VERIFIED", "ACCEPTED_UNVERIFIED", "FAILED", "UNKNOWN", "EXPIRED"]
    dispatch_status: Literal["not_dispatched", "dispatching", "accepted", "rejected", "possibly_in_flight"]
    ha_context_id: UUID | None
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
        has_observation = self.observed_state is not None
        if has_observation != (self.observed_at is not None):
            raise ValueError("observed_state_and_time_required_together")
        if has_observation != (self.observation_source != "none"):
            raise ValueError("observation_source_must_match_observation")
        if has_observation != (self.verification_strength != "none"):
            raise ValueError("verification_strength_must_match_observation")
        if self.observed_at is not None and self.observed_at > self.terminal_at:
            raise ValueError("observation_after_terminal")
        if self.dispatch_status == "not_dispatched" and (
            self.ha_context_id is not None or has_observation
        ):
            raise ValueError("not_dispatched_cannot_have_ha_evidence")
        if self.dispatch_status == "rejected" and (self.ha_context_id is not None or has_observation):
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
        elif self.terminal_state == "FAILED" and self.dispatch_status not in {
            "not_dispatched", "rejected", "accepted"
        }:
            raise ValueError("failed_has_impossible_dispatch_status")
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
        has_observation = self.observed_state is not None
        if has_observation != (self.observed_at is not None):
            raise ValueError("observed_state_and_time_required_together")
        if has_observation != (self.observation_source != "none"):
            raise ValueError("observation_source_must_match_observation")
        if has_observation != (self.verification_strength != "none"):
            raise ValueError("verification_strength_must_match_observation")
        if self.observed_at is not None and self.terminal_at is not None and self.observed_at > self.terminal_at:
            raise ValueError("observation_after_terminal")
        if self.dispatch_status in {"not_dispatched", "rejected"} and (
            self.dispatch_started_at is not None or self.ha_context_id is not None or has_observation
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
        if self.receipt_state == "EXPIRED" and (
            self.dispatch_status != "not_dispatched"
            or self.dispatch_started_at is not None
            or self.ha_context_id is not None
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
        if self.scene_manifest_digest != scene_manifest_digest(self):
            raise ValueError("scene_manifest_digest_mismatch")
        return self

def scene_manifest_digest_from_parts(
    scene_id: UUID,
    scene_generation: int,
    entries: tuple[SceneActionEntryV1, ...],
) -> str:
    entry_payloads = tuple({
        "ordinal": row.ordinal,
        "action_type": row.action_type,
        "target_endpoint_id": row.target_endpoint_id,
        "desired_state": row.desired_state.model_dump(mode="json"),
    } for row in entries)
    payload = {
        "scene_id": str(scene_id),
        "scene_generation": scene_generation,
        "entries": entry_payloads,
    }
    canonical = jcs.canonicalize(normalize_nfc_and_utc(payload))
    return hashlib.sha256(canonical).hexdigest()

def scene_manifest_digest(value: SceneExecutionBodyV1) -> str:
    return scene_manifest_digest_from_parts(value.scene_id, value.scene_generation, value.entries)

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

class HASceneChildReceiptV1(HomeContract):
    child_receipt_schema_version: Literal["1.0"]
    ordinal: Annotated[int, Field(ge=0, le=11)]
    target_endpoint_id: StableHomeId
    receipt: HAReceiptV1

class HASceneReceiptV1(HomeContract):
    receipt_schema_version: Literal["1.0"]
    receipt_kind: Literal["light_scene"]
    receipt_id: UUID
    scene_execution_id: UUID
    scene_id: UUID
    scene_generation: Annotated[int, Field(ge=1)]
    scene_manifest_digest: Sha256Digest
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
        child_states = {row.receipt.receipt_state for row in self.children}
        if self.aggregate_state == "PARTIAL":
            if len(self.children) < 2 or len(child_states) < 2:
                raise ValueError("partial_scene_requires_differing_child_states")
        elif len(child_states) != 1 or self.aggregate_state not in child_states:
            raise ValueError("scene_aggregate_must_match_homogeneous_children")
        return self
```

```python
# packages/contracts/src/tuntun_contracts/home/routines.py
WeekdayV1 = Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
LocalTimeV1 = Annotated[str, Field(pattern=r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$")]
IanaTimezoneV1 = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^(?:UTC|[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)+)$")]

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
        "trigger", "conditions", "actions",
    )
    payload = value.model_dump(mode="json", include=set(digest_fields))
    canonical = jcs.canonicalize(normalize_nfc_and_utc(payload))
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
    requested_activation_generation: Annotated[int, Field(ge=1)]
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
        if (self.active_activation_generation == 0) != (self.active_manifest_digest is None):
            raise ValueError("active_routine_generation_and_digest_required_together")
        installed = (
            self.active_activation_generation == self.requested_activation_generation
            and self.active_manifest_digest == self.manifest_digest
        )
        if (self.receipt_state == "INSTALLED") != installed:
            raise ValueError("routine_receipt_state_does_not_match_active_manifest")
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
    control_generation: Annotated[int, Field(ge=1)]
    policy_version: PolicyVersion
    mode: Literal["COOPERATIVE", "STRICT"]
    attempt_kind: Literal["primary", "bounded_reenforcement"]
    attempt_number: Annotated[int, Field(ge=1, le=2)]
    requested_at: AwareDatetime
    expires_at: AwareDatetime
    idempotency_key: UUID
    correlation_id: UUID

    @model_validator(mode="after")
    def request_is_one_of_two_bounded_attempts(self) -> "TVOffRequestV1":
        expected_number = 1 if self.attempt_kind == "primary" else 2
        if self.attempt_number != expected_number:
            raise ValueError("tv_attempt_kind_number_mismatch")
        if not self.requested_at < self.expires_at <= self.requested_at + timedelta(seconds=10):
            raise ValueError("tv_control_window_out_of_bounds")
        return self

class TVControlReceiptV1(HomeContract):
    receipt_schema_version: Literal["1.0"]
    receipt_kind: Literal["tv_off_control"]
    receipt_id: UUID
    request_id: UUID
    idempotency_key: UUID
    endpoint_id: StableHomeId
    endpoint_generation: Annotated[int, Field(ge=1)]
    control_generation: Annotated[int, Field(ge=1)]
    attempt_number: Annotated[int, Field(ge=1, le=2)]
    outcome: Literal["ACCEPTED_UNVERIFIED", "FAILED", "UNKNOWN", "EXPIRED"]
    dispatch_status: Literal["not_dispatched", "accepted", "rejected", "possibly_in_flight"]
    safe_code: SafeReasonCode
    adapter_receipt_commitment: HmacCommitment | None
    requested_at: AwareDatetime
    expires_at: AwareDatetime
    received_at: AwareDatetime
    terminal_at: AwareDatetime

    @model_validator(mode="after")
    def control_receipt_never_claims_observed_success(self) -> "TVControlReceiptV1":
        if not self.requested_at < self.expires_at <= self.requested_at + timedelta(seconds=10):
            raise ValueError("tv_control_window_out_of_bounds")
        if self.received_at < self.requested_at or self.terminal_at < self.received_at:
            raise ValueError("tv_control_receipt_time_order_invalid")
        if self.outcome == "ACCEPTED_UNVERIFIED" and (
            self.dispatch_status != "accepted" or self.adapter_receipt_commitment is None
        ):
            raise ValueError("accepted_tv_control_requires_adapter_commitment")
        if self.outcome == "UNKNOWN" and self.dispatch_status not in {"accepted", "possibly_in_flight"}:
            raise ValueError("unknown_tv_control_requires_possible_dispatch")
        if self.outcome == "EXPIRED" and (
            self.dispatch_status != "not_dispatched" or self.adapter_receipt_commitment is not None
        ):
            raise ValueError("expired_tv_control_must_be_undispatched")
        if self.outcome == "EXPIRED" and self.terminal_at < self.expires_at:
            raise ValueError("tv_control_expired_before_deadline")
        if self.dispatch_status != "not_dispatched" and self.received_at >= self.expires_at:
            raise ValueError("tv_control_dispatched_after_expiry")
        if self.dispatch_status in {"not_dispatched", "rejected"} and self.adapter_receipt_commitment is not None:
            raise ValueError("undispatched_tv_control_cannot_have_adapter_commitment")
        return self
```

The screen-time control receipt deliberately has no `VERIFIED` variant: only a fresh, generation-matched `TVObservationV1` from an eligibility-approved observation path can prove off. Phase 2 registers these ports only for `FakeTV`; a household endpoint still has no `ScreenTimeControlPort` binding.

```python
# packages/contracts/src/tuntun_contracts/ui.py
class OperationTargetResultV1(ContractModel):
    result_schema_version: Literal["1.0"]
    result_kind: Literal["light_v1", "player_v1", "television_v1", "display_v1", "clip_v1", "document_v1", "desktop_step_v1", "robot_v1"]
    target_id: OpaquePurposeScopedId
    outcome: Literal["verified", "accepted_unverified", "denied", "duplicate", "failed", "unknown", "expired", "cancelled"]
    dispatch_status: SafeDispatchStatus
    reason_code: SafeReasonCode
    safe_message_id: RegisteredMessageId
    observation_source: Literal["device", "home_assistant", "player_adapter", "tv_sensor", "display_agent", "media_proxy", "knowledge_store", "desktop_helper", "robot_safety", "none"]
    verification_strength: Literal["authoritative", "corroborated", "acknowledged_unverified", "none"]
    observed_state_schema_id: SchemaId
    observed_state_code: SafeObservedStateCode
    evidence_generation: Annotated[int, Field(ge=0)]
    observed_at: AwareDatetime | None
    terminal_at: AwareDatetime

    @model_validator(mode="after")
    def outcome_matches_evidence(self) -> "OperationTargetResultV1":
        has_observation = self.observation_source != "none"
        if has_observation != (self.observed_at is not None):
            raise ValueError("observation_source_and_time_required_together")
        if has_observation != (self.evidence_generation >= 1):
            raise ValueError("observation_source_and_generation_required_together")
        if has_observation != (self.verification_strength != "none"):
            raise ValueError("observation_source_and_strength_required_together")
        if self.observed_at is not None and self.observed_at > self.terminal_at:
            raise ValueError("observation_after_terminal")
        if self.outcome == "verified" and (
            self.dispatch_status != "accepted"
            or self.observation_source == "none"
            or self.verification_strength not in {"authoritative", "corroborated"}
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
            if self.outcome == "partial":
                raise ValueError("partial_requires_multiple_targets")
            return self
        child_outcomes = {row.outcome for row in self.target_results}
        if self.outcome == "partial":
            if len(self.target_results) < 2 or len(child_outcomes) < 2:
                raise ValueError("partial_requires_differing_target_outcomes")
        elif len(child_outcomes) != 1 or self.outcome not in child_outcomes:
            raise ValueError("aggregate_outcome_must_match_homogeneous_targets")
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

`OperationResultV1.target_manifest` is the immutable ordered tuple of the same opaque target IDs committed by the prepared mutation; it is empty only for a genuinely untargeted operation. The validator proves that result rows are complete and in that exact order, `partial` has at least two rows with differing terminal outcomes, homogeneous aggregate outcomes match every child, and aggregate `verified` has only adequately evidenced `verified` children. Phase 2 home routes additionally require 1–12 unique `light_v1` targets and never serialize raw HA entity IDs.

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

| Revision | Tables and critical invariants |
|---|---|
| `0009_home_topology_policy` | `home_areas`, `home_zones`, `home_devices`, `home_endpoints`, `home_capabilities`, `home_bindings`, `home_aliases`, `child_light_rules`, `child_light_rule_approvals`, `delegated_guardian_grants`, `designated_guest_sessions`, `scene_manifests`, `scene_manifest_entries`; sole canonical location key `area_id`; optional zone versions bind one immutable parent `area_id`, exact area generation, and exact owning binding ID/generation; no `room_id` column/table/alias/mapping; stable random IDs, one current binding per endpoint/capability, unique normalized alias per area scope, generation/digest CAS, two distinct principals for enabled child rule, no person/IP/MAC/vendor-account field |
| `0010_home_actions` | `home_actions`, `home_action_transitions`, `home_action_envelopes`, `home_action_results`, `scene_executions`, `scene_execution_children`; one immutable `AUTHORIZED_COMMITTED` payload, legal transition trigger, unique idempotency scope, one signature digest/key, one immutable terminal result/time, child rows 1–12 and exact manifest digest |
| `0011_home_automation` | `automation_domain_modes`, `routine_drafts`, `routine_manifests`, `routine_installs`, `learning_projections`, `learning_suggestions`; Manual default, passkey receipt/digest on exposure expansion, immutable approved manifest, projection schema excludes actor/session/profile/join key, 30-day expiry |
| `0012_screen_time` | `screen_time_policies`, `allowance_ledgers`, `screen_time_sessions`, `screen_time_checkpoints`, `screen_time_extensions`, `screen_time_overrides`, `screen_time_enforcement_intents`, `tv_capability_evidence`; daily/weekly ledgers separate, legal state transitions, immutable canonical intent bytes/commitment, unique `(screen_time_session_id, enforcement_generation, attempt_number)` with attempt constrained to 1 or 2, observer/control generations, 30-day session expiry, content-minimized audit references |

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
| `3` | `routine_manifests`, `routine_installs`, `routine_trigger_cursors`, `routine_occurrences`, `routine_child_receipts`, `circuit_breakers`, `backup_state` |

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
pnpm --filter @tuntun/admin exec playwright test tests/e2e/home-*.spec.ts
```

Owner-gated commands are explicit and write only to ignored `var/evidence/phase2/`:

```bash
TUNTUN_ALLOW_HOME_HARDWARE=1 uv run pytest -m home_hardware tests/hardware/home -q
TUNTUN_ALLOW_NETWORK_PROBE=1 uv run python scripts/phase2/probe_network.py --output var/evidence/phase2/network.json
TUNTUN_ALLOW_MZHUB_PROBE=1 uv run python scripts/phase2/probe_mzhub.py --output var/evidence/phase2/mzhub.json
TUNTUN_ALLOW_UPS_TEST=1 uv run python scripts/phase2/qualify_ups.py --output var/evidence/phase2/ups.json
TUNTUN_ALLOW_ELAPSED_PHASE2=1 uv run python scripts/phase2/run_acceptance.py --output var/evidence/phase2/acceptance.json
```

---

## Wave 0 — Contracts, Simulation, Persistence, and Phase 1 Amendments

### Task 01: Freeze strict Phase 2 contracts and generated schemas

**Depends on:** Phase 1 contract package accepted.
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
- Create: `packages/contracts/src/tuntun_contracts/ui.py`
- Create: `scripts/phase2/generate_home_schemas.py`
- Create: `schemas/home/v1/topology-v1.schema.json`
- Create: `schemas/home/v1/events-v1.schema.json`
- Create: `schemas/home/v1/channel-v1.schema.json`
- Create: `schemas/home/v1/actions-v1.schema.json`
- Create: `schemas/home/v1/routines-v1.schema.json`
- Create: `schemas/home/v1/screen-time-v1.schema.json`
- Create: `schemas/home/v1/ui-v1.schema.json`
- Create: `schemas/ui/v1/operation-result-v1.schema.json`
- Create: `fixtures/synthetic/home/contracts/topology-v1.json`
- Create: `fixtures/synthetic/home/contracts/state-event-v1.json`
- Create: `fixtures/synthetic/home/contracts/state-snapshot-v1.json`
- Create: `fixtures/synthetic/home/contracts/state-delta-v1.json`
- Create: `fixtures/synthetic/home/contracts/channel-proof-v1.json`
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

**Interfaces:** Produces every frozen DTO and port in the contract baseline, including `StateCursorV1`, `HomeStateSnapshotV1`, `HomeStateDeltaV1`, `CommittedHomeActionV1`, `HAReceiptV1`, `CommittedSceneExecutionV1`, `BoundedSceneEnvelopeV1`, `HASceneReceiptV1`, `CommittedRoutineInstallV1`, `BoundedRoutineManifestV1`, `HARoutineInstallReceiptV1`, `ExactTargetRequestV1`, the closed `TargetResolutionV1` variants, `TVObservationV1`, canonical `EnforcementIntentV1`, `TVOffRequestV1`, and `TVControlReceiptV1`; `canonical_home_bytes(model: HomeContract) -> bytes`; `parse_home_json(model: type[HomeModelT], raw: bytes, *, max_bytes: int = 65_536) -> HomeModelT`; and exact schema bundles/IDs `tuntun.home.topology.v1`, `tuntun.home.events.v1`, `tuntun.home.channel.v1`, `tuntun.home.actions.v1`, `tuntun.home.routines.v1`, `tuntun.home.screen-time.v1`, `tuntun.home.ui.v1`, and shared `tuntun.ui.operation-result.v1`. Consumes only `tuntun_contracts.base.ContractModel`, `Commitment`, and shared safe error primitives.

`AreaV1.area_id` is the only canonical household location identifier. `ZoneV1` is optional; each immutable version binds its stable `zone_id` to one `area_id`, the current area generation, and one exact owning binding ID/generation. Zone CAS may change its shape/label/binding generation only by creating the next zone generation; changing `area_id`, treating `zone_id` as an area, or accepting a `room_id` compatibility field is invalid.

- [ ] **Step 1: Write red positive/negative contract tests**

```python
def test_closed_action_canonical_round_trip(action_fixture: dict[str, object]) -> None:
    action = ClosedLightActionV1.model_validate(action_fixture)
    canonical = canonical_home_bytes(action)
    assert parse_home_json(ClosedLightActionV1, canonical) == action
    assert canonical == canonical_home_bytes(action)

def test_duplicate_json_key_is_rejected_before_model_validation() -> None:
    raw = b'{"action_schema_version":"1.0","action_schema_version":"1.0"}'
    with pytest.raises(ValueError, match="duplicate_json_key"):
        parse_home_json(ClosedLightActionV1, raw)

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
    (EnforcementIntentV1, "enforcement_intent_fixture", "intent_schema_version"),
    (TVOffRequestV1, "tv_off_request_fixture", "request_schema_version"),
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
    (EnforcementIntentV1, "enforcement_intent_fixture", "enforcement_generation"),
    (TVOffRequestV1, "tv_off_request_fixture", "control_generation"),
    (TVControlReceiptV1, "tv_control_receipt_fixture", "endpoint_generation"),
    (OperationResultV1, "operation_result_fixture", "operation_generation"),
])
def test_public_generations_reject_zero(request, model, fixture_name, field) -> None:
    fixture = request.getfixturevalue(fixture_name)
    with pytest.raises(ValidationError):
        model.model_validate({**fixture, field: 0})

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

def test_delta_rejects_foreign_or_nonadvancing_cursor(delta_fixture) -> None:
    foreign = deep_merge(delta_fixture, {"cursor": {"verifier_generation": "b" * 64}})
    nonadvancing = deep_merge(delta_fixture, {"cursor": delta_fixture["from_cursor"]})
    outside_interval = deep_merge(delta_fixture, {
        "changes": [{**delta_fixture["changes"][0], "sequence": delta_fixture["from_cursor"]["sequence"]}],
    })
    for candidate in (foreign, nonadvancing, outside_interval):
        with pytest.raises(ValidationError):
            HomeStateDeltaV1.model_validate(candidate)

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
])
def test_tv_ports_reject_unbounded_or_false_success(tv_port_fixture, mutation) -> None:
    model, candidate = mutation(tv_port_fixture)
    with pytest.raises(ValidationError):
        model.model_validate(candidate)

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
    omit_manifest_target_row,
    swap_manifest_target_rows,
    make_partial_children_homogeneous,
    make_verified_child_unobserved,
    put_child_terminal_after_aggregate,
])
def test_operation_result_rejects_incomplete_or_false_aggregate(operation_result_fixture, mutation) -> None:
    with pytest.raises(ValidationError):
        OperationResultV1.model_validate(mutation(operation_result_fixture))
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/home/test_home_contracts.py tests/property/home/test_contract_rejection.py -q`
Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_contracts.home'`.

- [ ] **Step 3: Implement the complete closed models, canonicalization, schemas, and synthetic fixtures**

```python
class HomeContract(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True, validate_assignment=True, str_strip_whitespace=True)

def canonical_home_bytes(value: HomeContract) -> bytes:
    normalized = normalize_nfc_and_utc(value.model_dump(mode="json"))
    return jcs.canonicalize(normalized)

HomeModelT = TypeVar("HomeModelT", bound=HomeContract)

def parse_home_json(model: type[HomeModelT], raw: bytes, *, max_bytes: int = 65_536) -> HomeModelT:
    if not 0 < len(raw) <= max_bytes:
        raise ValueError("home_json_size_out_of_bounds")

    def reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result

    def reject_non_json_number(value: str) -> Never:
        raise ValueError(f"non_json_number:{value}")

    decoded = json.loads(
        raw.decode("utf-8", errors="strict"),
        object_pairs_hook=reject_duplicate_pairs,
        parse_constant=reject_non_json_number,
    )
    return model.model_validate(decoded)
```

Generate every schema from the exact model registry, including each discriminated target/routine variant and `EnforcementIntentV1`, write with sorted keys, and fail if a generated file differs from the committed schema. Every route/fixture loader uses `parse_home_json()` rather than Pydantic's duplicate-oblivious convenience decoder; signed bodies additionally require `raw == canonical_home_bytes(parsed)` before signature verification. The topology fixture contains `area_common_synth_01` and optional `zone_boundary_synth_01` with matching area/binding generations; it contains no location compatibility alias. Snapshot/delta fixtures bind one exact epoch/verifier stream; receipt fixtures cover every intermediate and terminal class; scene/routine fixtures contain canonical 1–12 light children and recomputable digests; target fixtures cover exact/ambiguous/not-found without candidate leakage; TV fixtures never claim control acknowledgement proves off. The enforcement-intent fixture is an exact Cooperative primary standby intent; separate cases cover Strict and the sole bounded re-enforcement shape. Other fixtures use `ep_light_synth_01`, fixed UUIDs, test digests, and the literal signature `TEST_SIGNATURE_NOT_VALID_IN_PRODUCTION`.

- [ ] **Step 4: Run green and generation drift checks**

Run: `uv run python scripts/phase2/generate_home_schemas.py --check && uv run pytest tests/contract/home tests/property/home/test_contract_rejection.py -q && uv run ruff check packages/contracts scripts/phase2/generate_home_schemas.py tests/contract/home tests/property/home/test_contract_rejection.py && uv run mypy packages/contracts/src`
Expected: PASS; schema generation prints `home schema drift: none`; every unknown field/version/action/result kind/enum, duplicate key, noncanonical timestamp, zero/stale/mismatched generation, foreign/nonadvancing cursor, action/scene/routine time-window violation, impossible receipt transition, contradictory dispatch/evidence claim, non-atomic UI observation source/strength/generation/time tuple, wildcard, `toggle`, relative state, oversized body, scene entry 13, duplicate/unordered scene child, routine trigger/condition/action escape, stale routine CAS, delay over 300 seconds, routine digest mismatch, incomplete/unordered target result, false aggregate `verified`, same-outcome `partial`, target ambiguity leak/guess, false TV verified-off claim, substituted enforcement viewer/session/TV/adapter/generation/operation, invalid Strict evidence, partial prior-attempt fields, third/late re-enforcement, injected `room_id`, cross-area zone move, and stale/mismatched area or owning-binding generation is rejected.

- [ ] **Step 5: Commit exact contract paths**

```bash
git add packages/contracts/src/tuntun_contracts/home packages/contracts/src/tuntun_contracts/ui.py scripts/phase2/generate_home_schemas.py schemas/home/v1 schemas/ui/v1/operation-result-v1.schema.json fixtures/synthetic/home/contracts fixtures/synthetic/ui/operation-result-light-v1.json tests/contract/home tests/property/home/test_contract_rejection.py
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

**Interfaces:** `TopologyRegistry.mutate(command, auth, uow) -> TopologyMutationReceipt`; `resolve_exact`; `freeze_binding`; `create_zone(area_id, owning_binding_id, owning_binding_generation, command, auth, uow)`; `compare_and_swap_zone(zone_id, expected_generation, command, auth, uow)`; `GuestSessionService.create/cancel/resolve`; `SceneRegistry.create/edit/delete/get`. `area_id` is the only canonical location key. A zone version has one immutable parent `area_id`, exact area generation, and exact owning binding ID/generation; every area/zone/binding mutation increments its generation and invalidates outstanding target/scene/cross-phase operation commitments in the same transaction.

- [ ] **Step 1: Write red migration and dual-principal tests**

```python
def test_0009_upgrade_downgrade_upgrade_owns_exact_tables(migration_db) -> None:
    migration_db.upgrade("0009_home_topology_policy")
    assert migration_db.new_tables_since("0008_prepared_mutations") == EXPECTED_0009_TABLES
    migration_db.downgrade("0008_prepared_mutations")
    assert not EXPECTED_0009_TABLES & migration_db.tables()
    migration_db.upgrade("head")

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

Run: `uv run pytest tests/integration/storage/test_home_topology_migration.py tests/integration/home/test_topology_generation.py tests/security/home/test_child_rule_dual_approval.py tests/security/home/test_canonical_location_keys.py -q`
Expected: FAIL because Alembic revision `0009_home_topology_policy` and `TopologyRegistry` do not exist.

- [ ] **Step 3: Implement exact tables, triggers, repositories, and services**

The migration creates exactly the thirteen `0009` tables in the migration map, in dependency order: areas; devices/endpoints/capabilities; bindings; zones; aliases/policies/scenes, with downgrade in exact reverse order. `home_areas` versions key on `(area_id, generation)`, and every located device stores an exact `(area_id, area_generation)` foreign key. `home_zones` versions key on `(zone_id, generation)` and carry non-null `area_id`, `area_generation`, `owning_binding_id`, `owning_binding_generation`, `zone_digest`, and lifecycle state; foreign keys resolve the exact area and binding generations. A trigger rejects a new version when its `area_id` differs from generation 1, while binding/shape/label changes require expected-generation CAS and invalidate prior prepared operations. Do not create a room table, `room_id` column, alias, compatibility view, mapping table, DTO property, or JSON key. Add unique/current indexes, `CHECK` constraints for area/device/capability classes, scene size `1..12`, endpoint uniqueness, and triggers that reject enabling a child rule unless both current approvals match its digest/generation and principal IDs differ.

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
git add apps/core/migrations/versions/0009_home_topology_policy.py apps/core/src/tuntun_core/adapters/sqlcipher/models.py apps/core/src/tuntun_core/domain/home/topology.py apps/core/src/tuntun_core/domain/home/policy.py apps/core/src/tuntun_core/services/home/topology_registry.py apps/core/src/tuntun_core/services/home/guest_sessions.py apps/core/src/tuntun_core/services/home/scenes.py tests/integration/storage/test_home_topology_migration.py tests/integration/home/test_topology_generation.py tests/security/home/test_child_rule_dual_approval.py tests/security/home/test_canonical_location_keys.py
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

Create the six `0010` tables, legal-transition trigger, terminal immutability triggers, unique `(household_id, action_type, target_endpoint_id, idempotency_key)`, and one scene child per canonical endpoint index. Store desired state encrypted plus purpose-separated commitments; store no spoken text or identity evidence.

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

**Interfaces:** Persisted models in the migration map; `AutomationMode` defaults to `MANUAL`; `LearningProjectionV1` has only endpoint, area, state transition, coarse time bucket, observed time, expiry; `ScreenTimeSessionState` is the exact declared state machine.

- [ ] **Step 1: Write red schema/default/retention tests**

```python
def test_every_domain_starts_manual(automation_store) -> None:
    assert automation_store.create_domain("lights").mode == "MANUAL"

def test_learning_projection_has_no_identity_join_field() -> None:
    assert set(LearningProjectionV1.model_fields) == {"endpoint_id", "area_id", "transition", "coarse_time_bucket", "observed_at", "expires_at"}

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
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/storage/test_home_automation_migrations.py tests/integration/storage/test_screen_time_migration.py tests/security/home/test_learning_projection_schema.py -q`
Expected: FAIL because revisions `0011_home_automation` and `0012_screen_time` do not exist.

- [ ] **Step 3: Implement exact migrations and domain records**

Create every table named in the migration map, indexes for expiry and current generation, routine content/digest immutability, Manual default, projection field allowlist, legal screen-session transition trigger, and immutable canonical enforcement-intent bytes plus commitment. The intent table rejects duplicate/third attempts and any rewritten `(session, enforcement generation, attempt number)` binding. A session and committed intent store child subject ID locally because policy requires it; TV observations and HA payloads never contain it.

- [ ] **Step 4: Run green and upgrade/downgrade chain**

Run: `uv run pytest tests/integration/storage/test_home_automation_migrations.py tests/integration/storage/test_screen_time_migration.py tests/security/home/test_learning_projection_schema.py tests/integration/storage/test_migrations.py -q`
Expected: PASS for `0008 -> 0009 -> 0010 -> 0011 -> 0012`, reverse downgrade, encrypted backup, exact table ownership, Manual default, immutable one-or-two-attempt intent rows, and identity-free projection schema.

- [ ] **Step 5: Commit exact automation/screen schema paths**

```bash
git add apps/core/migrations/versions/0011_home_automation.py apps/core/migrations/versions/0012_screen_time.py apps/core/src/tuntun_core/adapters/sqlcipher/models.py apps/core/src/tuntun_core/domain/home/routines.py apps/core/src/tuntun_core/domain/home/screen_time.py tests/integration/storage/test_home_automation_migrations.py tests/integration/storage/test_screen_time_migration.py tests/security/home/test_learning_projection_schema.py
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

**Interfaces:** `ReceiptStore.open(path) -> ReceiptStore`; async methods `reserve_action`, `advance`, `terminalize`, `get_exact`, `compact`, `integrity_check`, `checkpoint`; database versions 1–3 from the migration map; one serialized writer and bounded read transactions.

- [ ] **Step 1: Write red durability, mismatch, retention, and pressure tests**

```python
async def test_pre_dispatch_is_durable_before_callback(store, action, fault) -> None:
    fault.raise_after("store.pre_dispatch_commit")
    with pytest.raises(InjectedCrash):
        await store.reserve_action(action)
    reopened = await ReceiptStore.open(store.path)
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
async def open_store(path: Path) -> ReceiptStore:
    db = await aiosqlite.connect(path)
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA synchronous=FULL")
    await db.execute("PRAGMA foreign_keys=ON")
    await migrate_user_version(db, target=3)
    return ReceiptStore(db, path, asyncio.Lock())

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

### Task 11: Expose the signed, read-only compiled state projection

**Depends on:** Tasks 08–10.
**Gate contribution:** P2-3.
**Estimated effort:** 1.5 engineering person-days.

**Files:**
- Create: `integrations/home-assistant/custom_components/tuntun_bridge/projection.py`
- Modify: `integrations/home-assistant/custom_components/tuntun_bridge/http.py`
- Create: `integrations/home-assistant/tests/test_state_route.py`
- Create: `integrations/home-assistant/tests/test_projection_privacy.py`
- Create: `integrations/home-assistant/tests/test_projection_cursor.py`
- Create: `tests/security/home/test_off_registry_read.py`
- Create: `tests/security/home/test_standard_ha_api_absence.py`

**Interfaces:** `ProjectionService.snapshot() -> HomeStateSnapshotV1`; `delta(cursor: StateCursorV1) -> HomeStateDeltaV1 | HomeStateSnapshotV1`; no caller-selected entity/filter/query body; 30-second heartbeat; sequence monotonic within one exact epoch/verifier stream; an unknown or foreign cursor returns a fresh full allowlisted snapshot; mutation routes remain absent.

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
```

- [ ] **Step 2: Run red**

Run: `uv run pytest integrations/home-assistant/tests/test_state_route.py integrations/home-assistant/tests/test_projection_privacy.py integrations/home-assistant/tests/test_projection_cursor.py tests/security/home/test_off_registry_read.py -q`
Expected: FAIL because `ProjectionService` and state handler are absent.

- [ ] **Step 3: Implement full/delta projection and heartbeat**

```python
async def snapshot(self):
    heartbeat_at = self._clock.now()
    rows = tuple(self._normalize(self._hass.states.get(binding.entity_id), binding)
                 for binding in self._registry.bindings_canonical_order())
    return HomeStateSnapshotV1(
        state_schema_version="1.0",
        cursor=self._next_cursor(),
        endpoints=rows,
        health=self._health.canonical_snapshot(heartbeat_at),
        heartbeat_at=heartbeat_at,
    )
```

Only stable endpoint ID, entity commitment, topology/binding/capability generations/digests, normalized light state, availability, source/time, sequence, and separate Core/Zigbee-side health leave HA. No raw HA attributes or entity IDs leave the route.

- [ ] **Step 4: Run green and standard-API escape attempts**

Run: `uv run pytest integrations/home-assistant/tests/test_state_route.py integrations/home-assistant/tests/test_projection_privacy.py integrations/home-assistant/tests/test_projection_cursor.py tests/security/home/test_off_registry_read.py tests/security/home/test_standard_ha_api_absence.py -q`
Expected: PASS; positive projection is exact; unknown cursor returns a snapshot; excluded entities produce no distinguishing result; direct REST/WebSocket/template/script/scene/automation calls have no credential; action/routine custom routes return `404`.

- [ ] **Step 5: Commit exact read-only projection paths**

```bash
git add integrations/home-assistant/custom_components/tuntun_bridge/projection.py integrations/home-assistant/custom_components/tuntun_bridge/http.py integrations/home-assistant/tests/test_state_route.py integrations/home-assistant/tests/test_projection_privacy.py integrations/home-assistant/tests/test_projection_cursor.py tests/security/home/test_off_registry_read.py tests/security/home/test_standard_ha_api_absence.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(ha): expose minimized signed light state"
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
- Create: `fixtures/synthetic/features/phase2-home-manifest-v1.json`
- Modify: `scripts/phase2/generate_home_schemas.py`
- Create: `apps/core/src/tuntun_core/services/features/__init__.py`
- Create: `apps/core/src/tuntun_core/services/features/registry.py`
- Create: `apps/core/src/tuntun_core/api/routes/features.py`
- Create: `apps/core/src/tuntun_core/api/home_dtos.py`
- Create: `apps/core/src/tuntun_core/api/routes/home.py`
- Modify: `apps/core/src/tuntun_core/api/app.py`
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
- Create: `tests/e2e/home-inventory.spec.ts`
- Create: `tests/e2e/home-permissions.spec.ts`
- Create: `tests/e2e/home-health.spec.ts`
- Create: `tests/e2e/home-feature-absence.spec.ts`
- Create: `tests/e2e/home-performance.spec.ts`

**Interfaces:** `SignedFeatureManifestV1` contains manifest version, candidate/package digest, issued/expiry times, signer key ID/signature, and exact `FeatureRegistrationV1` rows binding feature ID to backend route IDs, UI module ID/chunk digest, contract/schema/policy/corpus/migration/package digests, positive gate evidence hash, and negative-reachability evidence hash. Its canonical envelope uses the Phase 1 `EvidenceSigner`/`SignerRegistry` with expected purpose `acceptance` and protocol/schema discriminator `tuntun.feature-manifest.v1`; runtime code cannot self-sign or accept another acceptance payload type. `FeatureRegistry.verify_and_load` rejects unknown/stale/unsigned/drifted rows before registering either side. `GET /api/v1/ui/features` exposes only the server-verified safe projection. Read routes are `GET /api/v1/ui/home/inventory`, `/permissions`, and `/health`. Typed mutations include `PATCH /api/v1/home/areas/{area_id}`, `POST /api/v1/home/zones`, `PATCH /api/v1/home/zones/{zone_id}`, plus alias/binding, child-rule, delegated-grant, and Guest-session routes using Phase 1 428/step-up/retry. Area and zone writes require expected-generation CAS; the server supplies current area/binding generations in the prepared commitment and rejects zone-parent changes. UI read models expose canonical `area_id` and an optional subordinate zone header (`zone_id`, zone/area/owning-binding generations), commitments, and freshness—not raw HA entity IDs, credentials, or a parallel room key.

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
            "expires_at": signed_manifest_fixture["issued_at"] + timedelta(hours=24, microseconds=1),
        })

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

Run: `uv run pytest tests/contract/api/test_home_openapi.py tests/contract/api/test_feature_manifest.py tests/security/test_home_admin_api.py tests/security/test_home_feature_registration.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/home-inventory.spec.ts tests/e2e/home-permissions.spec.ts tests/e2e/home-health.spec.ts tests/e2e/home-feature-absence.spec.ts tests/e2e/home-performance.spec.ts`
Expected: FAIL with missing feature/manifest contracts, home routes, signed registry, and UI route/chunk gating.

- [ ] **Step 3: Implement generated read models and feature-gated routes**

The registry recognizes only `phase2.home.read`, `phase2.home.actions`, `phase2.home.automations`, and `phase2.home.screen_time`, and registers each backend route set and lazy UI module only after its P2-3/P2-4/P2-5/P2-6 evidence is signed into the exact candidate manifest. Unknown, absent, stale, expired, schema/policy/migration/package-drifted, or signature-invalid rows register neither backend nor UI; the built candidate omits their client chunks. Mutations call the existing `MutationCoordinator`; the server resolves current area/zone/binding generations, policy, risk, assurance, and safe summary. The inventory groups display labels under canonical `area_id`; an optional zone is rendered only beneath its parent area with its exact owning binding/generation, never as another area or an ambiguity resolver. Area/zone edits invalidate every prepared device/media/camera operation bound to the replaced generation. The permissions view includes bounded Designated Guest session creation/cancellation and owner-passkey pending co-approval without exposing anonymous/child access. UI renders `healthy`, `active`, `disabled`, `absent`, `degraded`, `stale`, `unknown`, `quarantined`, and `error-safe` with text, timestamp, and manual fallback.

- [ ] **Step 4: Regenerate clients and run API/UI/accessibility gates**

Run: `uv run python scripts/phase2/generate_home_schemas.py --check && uv run pytest tests/contract/api/test_home_openapi.py tests/contract/api/test_feature_manifest.py tests/security/test_home_admin_api.py tests/security/test_home_feature_registration.py -q && sh scripts/generate_openapi_client.sh && git diff --exit-code -- packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts && pnpm --filter @tuntun/admin exec vitest run && pnpm --filter @tuntun/admin exec lint && pnpm --filter @tuntun/admin exec tsc --noEmit && pnpm --filter @tuntun/admin exec vite build && pnpm --filter @tuntun/admin exec playwright test tests/e2e/home-inventory.spec.ts tests/e2e/home-permissions.spec.ts tests/e2e/home-health.spec.ts tests/e2e/home-feature-absence.spec.ts tests/e2e/home-performance.spec.ts`
Expected: PASS in English/Hindi, light/dark/high-contrast, reduced motion, 320 px, 200% zoom, keyboard, VoiceOver semantics, and axe runs; localhost authenticated shell interactive time is at most two seconds, cached navigation p95 at most 250 ms, fresh local view p95 at most one second; schemas/generated clients/browser storage/network capture contain no parallel room key, HA credential/entity ID, or policy binding; stale CAS and cross-area zone edits fail and invalidate no current state; missing/drifted manifest leaves direct URL/API/prepared-action/client registration and chunk absent.

- [ ] **Step 5: Commit exact API/UI paths**

```bash
git add packages/contracts/src/tuntun_contracts/features.py schemas/features/v1/feature-manifest-v1.schema.json fixtures/synthetic/features/phase2-home-manifest-v1.json scripts/phase2/generate_home_schemas.py apps/core/src/tuntun_core/services/features/__init__.py apps/core/src/tuntun_core/services/features/registry.py apps/core/src/tuntun_core/api/routes/features.py apps/core/src/tuntun_core/api/home_dtos.py apps/core/src/tuntun_core/api/routes/home.py apps/core/src/tuntun_core/api/app.py packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts apps/admin/src/app/feature-registry.ts apps/admin/src/app/router.tsx apps/admin/src/features/home/index.ts apps/admin/src/features/home/inventory.tsx apps/admin/src/features/home/permissions.tsx apps/admin/src/features/home/health.tsx apps/admin/src/routes/home-inventory.tsx apps/admin/src/routes/home-permissions.tsx apps/admin/src/routes/home-health.tsx tests/contract/api/test_home_openapi.py tests/contract/api/test_feature_manifest.py tests/security/test_home_admin_api.py tests/security/test_home_feature_registration.py tests/e2e/home-inventory.spec.ts tests/e2e/home-permissions.spec.ts tests/e2e/home-health.spec.ts tests/e2e/home-feature-absence.spec.ts tests/e2e/home-performance.spec.ts
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
    assert policy.inner_to_office == ()
    assert policy.green_to_mzhub == {"matter_ipv6", "mdns"}
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/phase2/test_inventory_redaction.py tests/security/home/test_network_policy.py -q`
Expected: FAIL because inventory/network tools and flow policy are absent.

- [ ] **Step 3: Implement bounded probes, configuration templates, and recovery runbooks**

The commissioning runbook records exact but local-only MZHUB/light/router/AiMesh/TV/phone/HAOS/Core/Matter Server/custom-integration/UPS versions, non-overlapping subnets and reservations, every AiMesh backhaul path, current native light recovery, wall-switch/mains behavior, certificate/key expiry, storage, and external-backup state. It disables UPnP/NAT-PMP/PCP, DMZ, WAN admin, public mappings, and HA Cloud remote access before claiming P2-0.

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

Expected positive outcome: Green is locally healthy; no forwarding/public listener exists; office/inner and Reachy negative probes pass; local encrypted backup restores in isolation; NUT telemetry survives reboot and shuts Green down before measured battery exhaustion; native lights were not reset. Any failed check writes `eligible=false` with a safe reason and blocks P2-1 without changing the existing light estate.

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

**Depends on:** P2-0 checkpoint.
**Gate contribution:** P2-1.
**Estimated effort:** 1 engineering person-day plus a non-compressible seven-day one-light pilot.

**Files:**
- Create: `scripts/phase2/probe_mzhub.py`
- Create: `apps/core/src/tuntun_core/domain/home/commissioning.py`
- Create: `fixtures/synthetic/home/mzhub-capability-samples.json`
- Create: `tests/unit/phase2/test_mzhub_capability_report.py`
- Create: `tests/security/home/test_mzhub_no_assumptions.py`
- Create: `tests/hardware/home/test_mzhub_capability.py`
- Create: `tests/hardware/home/test_one_light_matter_pilot.py`
- Create: `docs/operations/phase2-mzhub-pilot.md`
- Create: `docs/evidence/phase2-mzhub-gate-schema.json`

**Interfaces:** `MzhubCapabilityReportV1` records operational VID, PID, hardware/firmware, attestation-chain and certification-declaration digests, commissioning-path evidence, and exactly seven canonically ordered `MzhubCapabilityFindingV1` rows for `matter_bridge`, `thread_radio`, `zigbee_coordinator`, `local_runtime`, `bidirectional_state`, `wan_off_runtime`, and `reboot_recovery`. `decide_mzhub_gate(report) -> PASS_BRIDGE | FAIL_OPEN_FALLBACK | BLOCK_UNKNOWN`.

- [ ] **Step 1: Write red no-inference and certified-baseline tests**

```python
def test_product_name_does_not_imply_any_radio(sample_named_mzhub) -> None:
    report = build_mzhub_report(sample_named_mzhub)
    assert report.matter_bridge.status == "unknown"
    assert report.thread_radio.status == "unknown"
    assert report.local_runtime.status == "unknown"

def test_vid_pid_or_attestation_mismatch_is_different_variant(certified_baseline) -> None:
    report = certified_baseline.model_copy(update={"pid": "0x9999"})
    assert decide_mzhub_gate(report).decision == "BLOCK_UNKNOWN"
    assert decide_mzhub_gate(report).reason == "oem_variant_not_proven"
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/phase2/test_mzhub_capability_report.py tests/security/home/test_mzhub_no_assumptions.py -q`
Expected: FAIL because `MzhubCapabilityReportV1` and `probe_mzhub.py` do not exist.

- [ ] **Step 3: Implement independent findings and bridge decision**

```python
CERTIFIED_BASELINE = CertifiedProduct(vid="0x147D", pid="0x0638", hardware="1.0.4", firmware="2.0.0")

def decide_mzhub_gate(report):
    if not report.identity_matches_certified_or_documented_update:
        return GateDecision("BLOCK_UNKNOWN", "oem_variant_not_proven")
    required = (report.matter_bridge, report.local_runtime, report.bidirectional_state,
                report.wan_off_runtime, report.reboot_recovery)
    if any(item.status == "unknown" for item in required):
        return GateDecision("BLOCK_UNKNOWN", "required_capability_unknown")
    if any(item.status == "absent" or not item.passed for item in required):
        return GateDecision("FAIL_OPEN_FALLBACK", "bridge_gate_failed")
    return GateDecision("PASS_BRIDGE", "one_light_pilot_passed")
```

`thread_radio` is recorded and displayed but excluded from the bridge decision. The script never resets/unpairs a light and never claims the MZHUB can be used as a Thread border router.

- [ ] **Step 4: Run synthetic tests, then the one-light elapsed campaign**

Run: `uv run pytest tests/unit/phase2/test_mzhub_capability_report.py tests/security/home/test_mzhub_no_assumptions.py -q`
Expected: PASS for certified, documented-update, mismatched-OEM, no-Matter, unknown-Thread, no-WAN-off, stale-state, and reboot-failure synthetic records.

Owner run:

```bash
TUNTUN_ALLOW_MZHUB_PROBE=1 uv run pytest -m home_hardware tests/hardware/home/test_mzhub_capability.py -q --evidence-dir var/evidence/phase2/p2-1-capability
TUNTUN_ALLOW_ELAPSED_PHASE2=1 uv run pytest -m "home_hardware and elapsed" tests/hardware/home/test_one_light_matter_pilot.py -q --duration-seconds 604800 --evidence-dir var/evidence/phase2/p2-1-one-light
```

Expected `PASS_BRIDGE`: exact attestation/certification provenance is valid; one easy-to-recover light exposes every required feature; physical/vendor/HA changes reconcile bidirectionally; WAN is already absent during cold boot; Green/Matter Server/MZHUB/router restarts recover; every AiMesh path discovers; Ethernet-up/Zigbee-down becomes stale/unavailable; zero false success or wrong target occurs for seven elapsed days. Expected `FAIL_OPEN_FALLBACK`: native light estate remains unchanged and P2-F becomes eligible for owner decision. Expected `BLOCK_UNKNOWN`: gather manufacturer/certification evidence or keep Phase 2 light mutation disabled.

- [ ] **Step 5: Commit probe code, schemas, and runbook only**

```bash
git add scripts/phase2/probe_mzhub.py apps/core/src/tuntun_core/domain/home/commissioning.py fixtures/synthetic/home/mzhub-capability-samples.json tests/unit/phase2/test_mzhub_capability_report.py tests/security/home/test_mzhub_no_assumptions.py tests/hardware/home/test_mzhub_capability.py tests/hardware/home/test_one_light_matter_pilot.py docs/operations/phase2-mzhub-pilot.md docs/evidence/phase2-mzhub-gate-schema.json
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(home): gate the MZHUB bridge path"
```

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

**Interfaces:** `ActionEndpoint.handle(request) -> HAReceiptV1`; `ActionDispatcher.dispatch(receipt_id) -> HAReceiptV1`; compiled translations are exactly `light.turn_on` with exact brightness or `light.turn_off`, internally chosen, with `Context()` mapped to Tuntun correlation and no household identity.

- [ ] **Step 1: Write red validation-order and dispatch-bound tests**

```python
async def test_no_store_or_service_before_all_validation(endpoint, invalid_signed_action, hass_services, store) -> None:
    response = await endpoint.handle(invalid_signed_action)
    assert response.safe_code == "STALE_GENERATION"
    assert await store.count_actions() == 0
    assert hass_services.calls == ()

async def test_service_starts_only_after_durable_pre_dispatch(endpoint, valid_action, trace) -> None:
    await endpoint.handle(valid_action)
    assert trace.index("sqlite.commit.PRE_DISPATCH") < trace.index("sqlite.commit.DISPATCHING") < trace.index("hass.services.async_call")

async def test_late_pre_dispatch_never_calls_device(endpoint, action_after_expiry, hass_services) -> None:
    result = await endpoint.handle(action_after_expiry)
    assert result.receipt_state == "EXPIRED" and hass_services.calls == ()
```

- [ ] **Step 2: Run red**

Run: `uv run pytest integrations/home-assistant/tests/test_action_endpoint.py integrations/home-assistant/tests/test_action_allowlist.py integrations/home-assistant/tests/test_action_dispatch_deadline.py integrations/home-assistant/tests/test_action_system_context.py integrations/home-assistant/tests/test_action_idempotency.py integrations/home-assistant/tests/test_action_crash_points.py -q`
Expected: FAIL because the action endpoint/dispatcher is absent.

- [ ] **Step 3: Implement ordered checks and compiled system-context translation**

```python
async def handle(self, raw_request):
    request = await self._verifier.require_channel_and_body(raw_request, max_bytes=65_536)
    envelope = ClosedLightActionV1.model_validate_json(request.body)
    self._verifier.require_action_signature(envelope)
    binding = self._registry.require_exact_envelope(envelope)
    self._time.require_action_window(envelope)
    self._rates.reserve_exact(envelope.target_endpoint_id, request.session_key)
    receipt = await self._store.reserve_action(envelope)
    if receipt.receipt_state != "PRE_DISPATCH":
        return receipt
    return await self._dispatcher.dispatch(receipt.receipt_id, binding)

async def dispatch(self, receipt_id, binding):
    receipt = await self._store.advance_to_dispatching_if_fresh(receipt_id, within_seconds=2)
    domain, service, data = compiled_light_translation(receipt.action_type, binding.entity_id, receipt.desired_state)
    context = Context()
    await self._hass.services.async_call(domain, service, data, blocking=True, context=context)
    return await self._store.mark_reconciling(receipt_id, context.id)
```

`ClosedLightActionV1` rejects ambiguous state before persistence: power carries `brightness_percent=None`; brightness carries `on=True` and one bounded value. `compiled_light_translation` has no string argument from the request except that already cross-field-validated action enum and exact registry-owned entity. Signed off-registry entities, mismatched action/state variants, service names, actions, key/content mismatch, old epoch/generation, clock offset, or store pressure produce zero service call.

- [ ] **Step 4: Run green with crash at every HA transition**

Run: `uv run pytest integrations/home-assistant/tests/test_action_endpoint.py integrations/home-assistant/tests/test_action_allowlist.py integrations/home-assistant/tests/test_action_dispatch_deadline.py integrations/home-assistant/tests/test_action_system_context.py integrations/home-assistant/tests/test_action_idempotency.py integrations/home-assistant/tests/test_action_crash_points.py -q`
Expected: PASS; calls begin before expiry and within two seconds of pre-dispatch commit; expired recovered `PRE_DISPATCH` has zero I/O; recovered `DISPATCHING` is not replayed; duplicate same content returns prior receipt; mismatch is a security error; instrumentation observes only the two compiled light services.

- [ ] **Step 5: Commit exact HA action paths**

```bash
git add integrations/home-assistant/custom_components/tuntun_bridge/actions.py integrations/home-assistant/custom_components/tuntun_bridge/http.py integrations/home-assistant/tests/test_action_endpoint.py integrations/home-assistant/tests/test_action_allowlist.py integrations/home-assistant/tests/test_action_dispatch_deadline.py integrations/home-assistant/tests/test_action_system_context.py integrations/home-assistant/tests/test_action_idempotency.py integrations/home-assistant/tests/test_action_crash_points.py
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

**Interfaces:** `HomeActionReconciler.reconcile(action_id) -> HomeActionResultV1`; `recover_nonterminal`; per-endpoint maximum five commands/10 seconds and per-session maximum twenty/minute; excess is rejected/coalesced immediately and never queued for delayed dispatch.

- [ ] **Step 1: Write red truthful-result and no-replay tests**

```python
@pytest.mark.parametrize((source, fresh, matches, terminal), [
    ("matter_device", True, True, "VERIFIED"),
    ("ha_optimistic", True, True, "ACCEPTED_UNVERIFIED"),
    ("matter_device", False, True, "UNKNOWN"),
    ("matter_device", True, False, "FAILED"),
])
async def test_result_class_requires_proved_observation(reconciler, source, fresh, matches, terminal) -> None:
    assert (await reconciler.reconcile(seed_action(source, fresh, matches))).terminal_state == terminal

async def test_restart_queries_same_ha_receipt_before_any_send(recovery, transport, in_flight_action) -> None:
    await recovery.run()
    assert transport.calls[0].operation == "get_receipt"
    assert not any(call.operation == "new_action" for call in transport.calls)
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/home/test_action_reconciliation.py tests/integration/home/test_action_rate_limits.py tests/fault/home/test_action_restart_recovery.py tests/security/home/test_no_false_success.py tests/unit/home/test_result_language.py -q`
Expected: FAIL because `HomeActionReconciler` is absent.

- [ ] **Step 3: Implement result truth table and recovery**

```python
async def reconcile(self, action_id):
    action = await self._actions.get(action_id)
    receipt = await self._ha.receipt(action.action_id, action.idempotency_key)
    observation = await self._state.fresh_correlated_observation(action)
    result = classify_result(receipt, observation, self._commissioning.verification_basis(action.endpoint_id))
    async with self._uow_factory() as uow:
        await uow.home_actions.mark_reconciling_if_needed(action_id)
        terminal = await uow.home_actions.finish_exact(action_id, result, self._clock.now())
        await self._audit.append(uow, terminal.audit())
        await uow.commit()
        return terminal.result
```

Actions nonterminal 24 hours after expiry become `UNKNOWN` with immutable `terminal_at`. Human messages map to “completed and verified,” “command accepted but not verified,” “not completed,” “outcome unknown,” and “expired before execution” in English/Hindi; timeout never maps to success.

- [ ] **Step 4: Run green and flood/restart tests**

Run: `uv run pytest tests/integration/home/test_action_reconciliation.py tests/integration/home/test_action_rate_limits.py tests/fault/home/test_action_restart_recovery.py tests/security/home/test_no_false_success.py tests/unit/home/test_result_language.py -q`
Expected: PASS; fresh commissioned observations alone yield `VERIFIED`; acknowledgement/optimistic/stale/contradictory states do not; command 6/10s and 21/minute are rejected without delayed execution; restart performs receipt query and zero blind replay.

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
```

- [ ] **Step 2: Run red**

Run: `uv run pytest integrations/home-assistant/tests/test_scene_endpoint.py tests/integration/home/test_scene_execution.py tests/fault/home/test_scene_partial_failure.py tests/security/home/test_scene_definition_auth.py tests/property/home/test_scene_manifest.py -q`
Expected: FAIL because scene transport/aggregate reservation is absent.

- [ ] **Step 3: Implement exact scene commit order**

Mac atomically commits aggregate plus every child and consumes one confirmation; signs one canonical aggregate. HA validates all entries/rates/bindings/deadline and inserts aggregate plus all child `PRE_DISPATCH` rows in one local transaction before first device call. Children dispatch in canonical endpoint order; every invocation begins before aggregate expiry and within two seconds of reservation. Successful children are never rolled back to stale prior state.

- [ ] **Step 4: Run green with final-child deadline and crash placement**

Run: `uv run pytest integrations/home-assistant/tests/test_scene_endpoint.py tests/integration/home/test_scene_execution.py tests/fault/home/test_scene_partial_failure.py tests/security/home/test_scene_definition_auth.py tests/property/home/test_scene_manifest.py -q`
Expected: PASS for 1–12 entries, definition create/edit/delete, stale/replayed passkey, concurrent edit, digest/key mismatch, final child immediately inside/outside both deadlines, crash between every child, uncertain `DISPATCHING` reconciliation, expired `PRE_DISPATCH` no-I/O, no stale rollback, and truthful aggregate result.

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
- Modify: `apps/core/src/tuntun_core/api/home_dtos.py`
- Modify: `apps/core/src/tuntun_core/api/routes/home.py`
- Modify: `packages/contracts/openapi/admin-v1.yaml`
- Modify: `apps/admin/src/api/generated/admin-v1.ts`
- Create: `apps/admin/src/features/home/lights-scenes.tsx`
- Create: `apps/admin/src/routes/home-lights.tsx`
- Create: `tests/contract/api/test_home_action_openapi.py`
- Create: `tests/security/test_home_action_api.py`
- Create: `tests/e2e/home-lights.spec.ts`
- Create: `tests/e2e/home-scenes.spec.ts`

**Interfaces:** `GET /api/v1/ui/home/lights`, `GET /api/v1/ui/home/scenes`; typed single-light request and scene definition/execution routes through the Phase 1 prepared mutation mechanism; `ui.operation_result.v1` maps exact home result classes without optimism. A targeted result carries the immutable ordered opaque `target_manifest` plus exactly one row per manifest entry in that order; Phase 2 accepts only `light_v1`, one row for single action and 1–12 for scene, and rejects an aggregate `verified` unless every child is adequately evidenced `verified` or `partial` unless at least two child terminal outcomes differ.

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
  await mockSceneResult(page, syntheticMixedSceneResultInManifestOrder());
  await page.goto("/home/lights");
  await expect(page.getByTestId("scene-target-result")).toHaveCount(12);
  await expect(page.getByText("Partially completed — review each light")).toBeVisible();
});
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/api/test_home_action_openapi.py tests/security/test_home_action_api.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/home-lights.spec.ts tests/e2e/home-scenes.spec.ts`
Expected: FAIL because light/scene read models and routes are absent.

- [ ] **Step 3: Implement server-built previews and correlated result presentation**

Single controls show requested target, fresh observed state/source/time/strength, effective actor class, risk/required assurance, known bypass, and manual fallback. Scene preview enumerates exact manifest digest/version, canonical `area_id` groupings with safe display labels, endpoints, and desired effects. Browser code reuses one idempotency key across preparation, step-up, and unchanged retry and never changes local state to the desired state until a correlated server result arrives.

- [ ] **Step 4: Regenerate and run full UI matrix**

Run: `sh scripts/generate_openapi_client.sh && git diff --exit-code -- packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts && uv run pytest tests/contract/api/test_home_action_openapi.py tests/security/test_home_action_api.py -q && pnpm --filter @tuntun/admin exec vitest run && pnpm --filter @tuntun/admin exec lint && pnpm --filter @tuntun/admin exec tsc --noEmit && pnpm --filter @tuntun/admin exec vite build && pnpm --filter @tuntun/admin exec playwright test tests/e2e/home-lights.spec.ts tests/e2e/home-scenes.spec.ts`
Expected: PASS for request, confirmation, passkey, Guest pending/deny, child allow/deny, complete manifest-ordered per-target results, false aggregate rejection, partial scene, timeout/unknown, stale binding, manual bypass disclosure, English/Hindi, keyboard, VoiceOver semantics, 320 px, 200% zoom, dark/light/high-contrast, reduced motion, and no browser persistence.

- [ ] **Step 5: Commit exact action UI paths**

```bash
git add apps/core/src/tuntun_core/api/home_dtos.py apps/core/src/tuntun_core/api/routes/home.py packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts apps/admin/src/features/home/lights-scenes.tsx apps/admin/src/routes/home-lights.tsx tests/contract/api/test_home_action_openapi.py tests/security/test_home_action_api.py tests/e2e/home-lights.spec.ts tests/e2e/home-scenes.spec.ts
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
    require_exact_light_actions(manifest.actions, maximum=12)
    dependency_graph(manifest).require_acyclic_without_self_edge()
```

Returning to Manual closes exposure immediately without network. Assisted/Learning expansion or scope change requires owner passkey bound to domain/mode/scope/policy/expiry. Drafts contain safety/privacy/child/Guest/failure implications, frequency, rollback digest, exact endpoints, and representative simulation output; drafts have no execution authority.

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
- Create: `integrations/home-assistant/custom_components/tuntun_bridge/switch.py`
- Modify: `integrations/home-assistant/custom_components/tuntun_bridge/http.py`
- Modify: `apps/core/src/tuntun_core/services/home/automation.py`
- Create: `integrations/home-assistant/tests/test_routine_install.py`
- Create: `integrations/home-assistant/tests/test_routine_disable.py`
- Create: `integrations/home-assistant/tests/test_routine_rollback.py`
- Create: `integrations/home-assistant/tests/test_routine_restore_quarantine.py`
- Create: `tests/integration/home/test_routine_install_coordinator.py`
- Create: `tests/security/home/test_routine_escape_paths.py`

**Interfaces:** HA route accepts only `tuntun-routine-v1`; compare-and-swap exact expected activation generation to `expected+1`; `RoutineInstaller.install/disable/rollback`; HA exposes an integration-owned read/disable switch entity without editable YAML/template surface.

- [ ] **Step 1: Write red CAS/atomicity/quarantine tests**

```python
async def test_stale_activation_generation_cannot_install(endpoint, manifest, store) -> None:
    await store.seed_routine(manifest.routine_id, generation=4)
    stale = manifest.model_copy(update={"expected_activation_generation": 3, "next_activation_generation": 4})
    result = await endpoint.handle(stale)
    assert result.safe_code == "STALE_GENERATION"
    assert (await store.get_routine(manifest.routine_id)).generation == 4

async def test_failed_install_leaves_prior_active(store, installer, prior, invalid_next) -> None:
    await store.seed_routine(prior, active=True)
    with pytest.raises(ValidationError):
        await installer.install(invalid_next)
    assert (await store.get_routine(prior.id)).manifest_digest == prior.digest

async def test_restored_active_flag_is_quarantined(store_from_backup) -> None:
    runtime = await load_runtime(store_from_backup)
    assert runtime.registered_trigger_count == 0
    assert (await runtime.routines())[0].state == "QUARANTINED"
```

- [ ] **Step 2: Run red**

Run: `uv run pytest integrations/home-assistant/tests/test_routine_install.py integrations/home-assistant/tests/test_routine_disable.py integrations/home-assistant/tests/test_routine_rollback.py integrations/home-assistant/tests/test_routine_restore_quarantine.py tests/integration/home/test_routine_install_coordinator.py -q`
Expected: FAIL because routine endpoint/installer is absent.

- [ ] **Step 3: Implement signed CAS and atomic activation**

```python
async def install(self, manifest):
    self._verifier.require_routine_signature(manifest)
    self._validator.require_closed_manifest(manifest)
    async with self._store.writer_transaction() as tx:
        current = await tx.lock_routine(manifest.routine_id)
        require_exact_cas(current.activation_generation, manifest.expected_activation_generation,
                          manifest.next_activation_generation)
        await tx.insert_install_receipt(manifest)
        await tx.replace_active_manifest_atomically(current, manifest)
    return await self._store.routine_install_receipt(manifest.routine_id, manifest.next_activation_generation)
```

Disable uses the same writer, increments generation, closes trigger gate, and expires undispatched `PRE_DISPATCH` occurrence/children; `DISPATCHING` work is reconciled. Rollback/re-enable requires a newly owner-authenticated signed manifest with current generation. Restore/epoch rotation closes all gates and marks every routine quarantined before handlers/triggers register.

- [ ] **Step 4: Run green and YAML/template/API escape tests**

Run: `uv run pytest integrations/home-assistant/tests/test_routine_install.py integrations/home-assistant/tests/test_routine_disable.py integrations/home-assistant/tests/test_routine_rollback.py integrations/home-assistant/tests/test_routine_restore_quarantine.py tests/integration/home/test_routine_install_coordinator.py tests/security/home/test_routine_escape_paths.py -q`
Expected: PASS; stale CAS, invalid schema/signature/epoch/deadline/digest, failed install, manual disable, rollback, and restore behave atomically; YAML/template/general automation/service paths install nothing and perform no action.

- [ ] **Step 5: Commit exact install/disable paths**

```bash
git add integrations/home-assistant/custom_components/tuntun_bridge/routines.py integrations/home-assistant/custom_components/tuntun_bridge/switch.py integrations/home-assistant/custom_components/tuntun_bridge/http.py apps/core/src/tuntun_core/services/home/automation.py integrations/home-assistant/tests/test_routine_install.py integrations/home-assistant/tests/test_routine_disable.py integrations/home-assistant/tests/test_routine_rollback.py integrations/home-assistant/tests/test_routine_restore_quarantine.py tests/integration/home/test_routine_install_coordinator.py tests/security/home/test_routine_escape_paths.py
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
- Create: `integrations/home-assistant/tests/test_routine_feedback.py`
- Create: `tests/fault/home/test_routine_disable_races.py`

**Interfaces:** `RoutineEvaluator.admit(trigger) -> RoutineOccurrenceReceipt`; occurrence/child IDs derive from domain-separated hashes of controller epoch, activation generation, manifest digest, and trigger commitment/index/state; trigger and dispatch CAS use exact active/epoch/generation predicates.

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
```

- [ ] **Step 2: Run red**

Run: `uv run pytest integrations/home-assistant/tests/test_routine_runtime.py integrations/home-assistant/tests/test_routine_trigger_cas.py integrations/home-assistant/tests/test_routine_idempotency.py integrations/home-assistant/tests/test_routine_budgets.py integrations/home-assistant/tests/test_routine_circuit_breaker.py integrations/home-assistant/tests/test_routine_restart.py integrations/home-assistant/tests/test_routine_feedback.py tests/fault/home/test_routine_disable_races.py -q`
Expected: FAIL because deterministic runtime methods are absent.

- [ ] **Step 3: Implement occurrence admission, second dispatch CAS, and hard constants**

```python
PER_ROUTINE_MIN_INTERVAL_SECONDS = 60
PER_ROUTINE_ROLLING_DAY_MAX = 24
GLOBAL_ROLLING_HOUR_MAX = 60

async def admit(self, trigger):
    captured = await self._store.capture_routine_generation(trigger.routine_id)
    occurrence_id = derive_occurrence_id(captured.epoch, captured.generation, captured.digest, trigger.commitment)
    async with self._store.writer_transaction() as tx:
        await tx.require_active_epoch_generation(captured)
        await tx.reserve_budget_or_open_breaker(captured, trigger.observed_at)
        return await tx.insert_occurrence_and_children(occurrence_id, captured, trigger)

async def dispatch_child(self, occurrence, child):
    receipt = await self._store.cas_child_to_dispatching(
        child.id, active=True, epoch=occurrence.epoch, generation=occurrence.activation_generation)
    if receipt is None:
        return await self._store.expire_child(child.id, "routine_gate_closed")
    return await self._compiled_actions.dispatch_existing_receipt(receipt)
```

Routine-originated contexts are excluded from all triggers; state events are not replayed; scheduled downtime slots are marked skipped; dependencies reject self/cross cycles. Breaker opening disables the routine and alerts; only owner-authenticated review can re-enable.

- [ ] **Step 4: Run green with every before/after CAS race**

Run: `uv run pytest integrations/home-assistant/tests/test_routine_runtime.py integrations/home-assistant/tests/test_routine_trigger_cas.py integrations/home-assistant/tests/test_routine_idempotency.py integrations/home-assistant/tests/test_routine_budgets.py integrations/home-assistant/tests/test_routine_circuit_breaker.py integrations/home-assistant/tests/test_routine_restart.py integrations/home-assistant/tests/test_routine_feedback.py tests/fault/home/test_routine_disable_races.py -q`
Expected: PASS; no recursive/duplicate/backlog-burst/post-disable undispatched/blind-replay execution; disabled predicate misses expire with zero I/O; already dispatching reconciles; restore/reset sequence and same-manifest re-enable cannot collide due to epoch/generation-derived keys.

- [ ] **Step 5: Commit exact runtime paths**

```bash
git add integrations/home-assistant/custom_components/tuntun_bridge/routines.py integrations/home-assistant/tests/test_routine_runtime.py integrations/home-assistant/tests/test_routine_trigger_cas.py integrations/home-assistant/tests/test_routine_idempotency.py integrations/home-assistant/tests/test_routine_budgets.py integrations/home-assistant/tests/test_routine_circuit_breaker.py integrations/home-assistant/tests/test_routine_restart.py integrations/home-assistant/tests/test_routine_feedback.py tests/fault/home/test_routine_disable_races.py
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
- Modify: `apps/core/src/tuntun_core/api/home_dtos.py`
- Modify: `apps/core/src/tuntun_core/api/routes/home.py`
- Modify: `packages/contracts/openapi/admin-v1.yaml`
- Modify: `apps/admin/src/api/generated/admin-v1.ts`
- Create: `apps/admin/src/features/home/automations.tsx`
- Create: `apps/admin/src/routes/home-automations.tsx`
- Create: `tests/unit/home/test_learning_detector.py`
- Create: `tests/security/home/test_learning_privacy.py`
- Create: `tests/integration/home/test_learning_lifecycle.py`
- Create: `tests/e2e/home-automations.spec.ts`

**Interfaces:** `LearningProjector.project(event, child_conversation_correlated) -> LearningProjectionV1 | None`; `LearningDetector.suggest(projections) -> tuple[RoutineDraft,...]`; `disable_learning(domain) -> DeletionReceipt`; UI shows mode/origin/draft/diff/simulation/install/rollback/drift/projection expiry/delete/disable.

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

Run: `uv run pytest tests/unit/home/test_learning_detector.py tests/security/home/test_learning_privacy.py tests/integration/home/test_learning_lifecycle.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/home-automations.spec.ts`
Expected: FAIL because Learning service and automation route are absent.

- [ ] **Step 3: Implement identity-free projection, deterministic suggestions, and UI**

Learning consumes only endpoint, area, transition, coarse time bucket, observed time/expiry. It has no actor/session/profile field, output API, or join key; it never sends data to a model. Disabling Learning deletes projections and unapproved drafts immediately while preserving approved routines with provenance. Suggestions always enter Task 24 simulation/review/passkey/install.

- [ ] **Step 4: Regenerate and run privacy/lifecycle/UI gates**

Run: `sh scripts/generate_openapi_client.sh && git diff --exit-code -- packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts && uv run pytest tests/unit/home/test_learning_detector.py tests/security/home/test_learning_privacy.py tests/integration/home/test_learning_lifecycle.py -q && pnpm --filter @tuntun/admin exec vitest run && pnpm --filter @tuntun/admin exec lint && pnpm --filter @tuntun/admin exec tsc --noEmit && pnpm --filter @tuntun/admin exec vite build && pnpm --filter @tuntun/admin exec playwright test tests/e2e/home-automations.spec.ts`
Expected: PASS; Learning works with identity/conversation inputs physically absent, child-correlated events are dropped before projection, 30-day expiry/disable deletion pass, silent install paths are absent, drift remains owner-visible, and English/Hindi accessible states render correctly.

- [ ] **Step 5: Commit exact Learning/UI paths**

```bash
git add apps/core/src/tuntun_core/services/home/learning.py apps/core/src/tuntun_core/api/home_dtos.py apps/core/src/tuntun_core/api/routes/home.py packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts apps/admin/src/features/home/automations.tsx apps/admin/src/routes/home-automations.tsx tests/unit/home/test_learning_detector.py tests/security/home/test_learning_privacy.py tests/integration/home/test_learning_lifecycle.py tests/e2e/home-automations.spec.ts
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(home): add private Learning suggestions"
```

**P2-5 checkpoint:** Manual is the default; non-owner authoring is unreachable; Assisted/Learning expansion is passkey-bound; every installed manifest is closed, simulated, signed, CAS-installed, deterministic, budgeted, disableable, rollbackable, drift-aware, and restore-quarantined; every draft is inert; no YAML/template/general automation route exists; Learning has no actor or model path and deletes unapproved data on disable/expiry.

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

**Interfaces:** `TVEligibilityEvaluator.evaluate(control_evidence, observation_evidence) -> TVEligibility`; `ScreenTimeEnforcer.prepare_enforcement(session, attempt_kind) -> EnforcementIntentV1` owns the writer transaction and delegates only to `prepare_enforcement_in_uow(session, attempt_kind, uow) -> EnforcementIntentV1`; `ScreenTimeEnforcer.enforce(session) -> EnforcementResult`; one primary attempt plus at most one configured re-enforcement attempt. Preparing an attempt reloads the exact current child/session/viewer/clock/TV/policy/authorization/adapter facts, persists canonical intent bytes and audit outbox in one writer transaction, and returns that committed `EnforcementIntentV1`. Phase 2 production adapters consume it only through `FakeTV`; no household TV adapter is registered.

- [ ] **Step 1: Write red independence and attempt-ceiling tests**

```python
def test_same_adapter_ack_and_state_cannot_enable_strict(evaluator) -> None:
    result = evaluator.evaluate(control=same_adapter_control(), observation=same_adapter_cached_state())
    assert result.strict is False
    assert result.maximum_mode in {"ADVISORY", "COOPERATIVE"}

@pytest.mark.parametrize("failure", ["ack_false_state", "stale_mirror", "control_restart", "observer_restart", "common_mode_outage"])
async def test_unverified_enforcement_degrades_and_stops(enforcer, failure) -> None:
    result = await enforcer.run_synthetic(failure=failure)
    assert result.final_state == "UNKNOWN"
    assert result.control_attempt_count <= 2
    assert result.degraded_mode == "ADVISORY"

def test_real_tv_control_adapter_is_not_registered(feature_manifest) -> None:
    assert "phase2.tv.enforcement" not in feature_manifest.capabilities

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
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/home/test_tv_eligibility.py tests/integration/home/test_screen_time_enforcement.py tests/acceptance/home/test_screen_time_corpus.py tests/property/home/test_screen_time_sequences.py tests/fault/home/test_tv_common_mode_failures.py tests/security/home/test_no_real_tv_enforcement.py -q`
Expected: FAIL because eligibility/enforcement services are absent.

- [ ] **Step 3: Implement evidence classes and bounded simulator control**

```python
def evaluate(control, observation):
    if not control.repeatable or not observation.truthful:
        return TVEligibility("ADVISORY", False, "control_or_observation_unproved")
    independent = not control.shares_failure_domain_with(observation) or observation.direct_independence_campaign_passed
    return TVEligibility("STRICT" if independent else "COOPERATIVE", independent,
                         "independent_paths" if independent else "shared_failure_domain")

async def enforce(self, session):
    attempts = 0
    for permitted in ("primary", "bounded_reenforcement"):
        if attempts >= self._policy.maximum_attempts(session):
            break
        attempts += 1
        intent = await self.prepare_enforcement(session, permitted)
        await self._adapter.enforce(intent)
        observation = await self._observe.fresh(session.endpoint_id)
        if observation.proves_off:
            return EnforcementResult("ENDED", attempts, "verified_off")
        if not self._policy.may_reenforce(session, observation):
            break
    return EnforcementResult("UNKNOWN", attempts, "unverified_manual_bypass", degraded_mode="ADVISORY")
```

`prepare_enforcement` constructs the intent only from current server-side rows and the closed `EnforcementIntentV1` builder, writes its canonical bytes/commitment plus audit outbox through `prepare_enforcement_in_uow`, commits, and only then invokes the injected adapter. `EnforcementIntentValidator.require_committed_exact` first recomputes the HMAC over canonical bytes excluding `intent_commitment`, compares both the HMAC and stored canonical bytes in constant time, and performs no session/topology/domain read on failure; it then reloads and exactly compares every current fact before dispatch. The Phase 2 adapter maps the exact intent to `TVOffRequestV1` with a fields-only `FakeTVOffRequestMapper`; it cannot choose an endpoint, operation, desired state, generation, or attempt. A mismatch between reloaded facts and any intent field closes the generation before adapter/domain I/O. Educational/content exceptions require trustworthy typed adapter evidence or exact current-guardian session approval; Phase 2 stores no programme title, audiovisual content, or inferred interest. A physical remote is explicitly an unauthenticated manual bypass, never adult identity.

- [ ] **Step 4: Run green 720-case corpus and 10,000 sequences**

Run: `uv run pytest tests/unit/home/test_tv_eligibility.py tests/integration/home/test_screen_time_enforcement.py tests/acceptance/home/test_screen_time_corpus.py tests/property/home/test_screen_time_sequences.py tests/fault/home/test_tv_common_mode_failures.py tests/security/home/test_no_real_tv_enforcement.py -q --hypothesis-seed=220830`
Expected: PASS for 720/720 exact oracles and at least 10,000 property sequences; zero unauthorized ledger/policy mutation, enforcement outside mode/endpoint/viewer eligibility, substituted/stale intent dispatch, external call before intent/audit commit, false verified-off claim, false denial of eligible extension/session, or control attempt above two; real TV enforcement registration remains absent.

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
- Modify: `apps/core/src/tuntun_core/api/home_dtos.py`
- Modify: `apps/core/src/tuntun_core/api/routes/home.py`
- Modify: `packages/contracts/openapi/admin-v1.yaml`
- Modify: `apps/admin/src/api/generated/admin-v1.ts`
- Create: `apps/admin/src/features/home/screen-time.tsx`
- Create: `apps/admin/src/routes/home-screen-time.tsx`
- Create: `tests/contract/api/test_screen_time_openapi.py`
- Create: `tests/security/test_screen_time_api.py`
- Create: `tests/e2e/home-screen-time.spec.ts`

**Interfaces:** `GET /api/v1/ui/home/screen-time`; typed policy/allowance/extension/override operations through server-prepared mutation; read model exposes eligibility, known bypasses, state, daily/weekly remaining, warnings/grace, pending extensions, evidence strength/time, attempt count, and `simulator_only=true`.

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

Run: `uv run pytest tests/contract/api/test_screen_time_openapi.py tests/security/test_screen_time_api.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/home-screen-time.spec.ts`
Expected: FAIL because screen-time API/UI routes are absent.

- [ ] **Step 3: Implement subject-filtered read model and exact mutations**

The server authorizes child/guardian/owner views before returning labels or ledger entries. Owner base-policy mutations require passkey; current primary guardian may approve exact session extension and view that child's transparent ledger; non-guardian adult may stop manually but cannot alter ledger/rule; child may request an extension but not approve it. Warning copy has reviewed English/Hindi message IDs and age-band variants, with remaining time and extension route.

- [ ] **Step 4: Regenerate and run full UI/security/accessibility gates**

Run: `sh scripts/generate_openapi_client.sh && git diff --exit-code -- packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts && uv run pytest tests/contract/api/test_screen_time_openapi.py tests/security/test_screen_time_api.py -q && pnpm --filter @tuntun/admin exec vitest run && pnpm --filter @tuntun/admin exec lint && pnpm --filter @tuntun/admin exec tsc --noEmit && pnpm --filter @tuntun/admin exec vite build && pnpm --filter @tuntun/admin exec playwright test tests/e2e/home-screen-time.spec.ts`
Expected: PASS for owner/current-guardian/non-guardian/child/Guest matrices, no cross-subject data, exact step-up, simulator-only truth, physical-remote bypass disclosure, unknown observation/clock behavior, English/Hindi, keyboard, screen reader, 320 px, 200% zoom, dark/light, and reduced motion.

- [ ] **Step 5: Commit exact screen-time UI paths**

```bash
git add apps/core/src/tuntun_core/api/home_dtos.py apps/core/src/tuntun_core/api/routes/home.py packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts apps/admin/src/features/home/screen-time.tsx apps/admin/src/routes/home-screen-time.tsx tests/contract/api/test_screen_time_openapi.py tests/security/test_screen_time_api.py tests/e2e/home-screen-time.spec.ts
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(admin): expose screen-time simulator truth"
```

**P2-6 checkpoint:** The 720 deterministic cases and at least 10,000 seeded sequences pass with exact transition/message/ledger/authority/control-attempt oracles. The UI truthfully labels Phase 2 as simulator-only; both household televisions remain manual/Advisory inventory unless a separately owning phase proves exact control and independent observation. No physical remote is described as adult-only.

---

## Wave 6 — P2-7 Backup, Restore Quarantine, Observability, Rollback, and Acceptance

### Task 31: Implement HA backup hooks and fresh-epoch restore quarantine

**Depends on:** Tasks 09, 20, 25‐26.
**Gate contribution:** P2-7.
**Estimated effort:** 2 engineering person-days.

**Files:**
- Create: `integrations/home-assistant/custom_components/tuntun_bridge/backup.py`
- Modify: `integrations/home-assistant/custom_components/tuntun_bridge/__init__.py`
- Create: `apps/core/src/tuntun_core/services/home/restore.py`
- Create: `integrations/home-assistant/tests/test_backup_hooks.py`
- Create: `integrations/home-assistant/tests/test_backup_crash.py`
- Create: `integrations/home-assistant/tests/test_restore_quarantine.py`
- Create: `tests/integration/home/test_controller_epoch_rotation.py`
- Create: `tests/fault/home/test_restore_between_dispatch_reconcile.py`
- Modify: `docs/operations/phase2-green-backup-restore.md`

**Interfaces:** HA `async_pre_backup`/`async_post_backup`; `HomeRestoreCoordinator.begin/reconcile/rotate_epoch/enable`; `restore_quarantine_required` is durable and checked before mutation/routine handlers register. Fresh epoch requires exact owner passkey plus separately recorded local HA owner/admin confirmation.

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
```

- [ ] **Step 2: Run red**

Run: `uv run pytest integrations/home-assistant/tests/test_backup_hooks.py integrations/home-assistant/tests/test_backup_crash.py integrations/home-assistant/tests/test_restore_quarantine.py tests/integration/home/test_controller_epoch_rotation.py tests/fault/home/test_restore_between_dispatch_reconcile.py -q`
Expected: FAIL because backup hooks and restore coordinator are absent.

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

Any timeout, marker/checkpoint/integrity failure fails the backup and keeps gates closed. Restore reads the marker before registering routes/triggers, isolates device paths, marks pre-restore nonterminal Mac actions `UNKNOWN`, rotates controller epoch while incrementing all routine generations/expiring undispatched work, pairs new epoch on both sides, reconciles bindings/receipts, and opens each capability only after owner review. Old epoch signatures never dispatch.

- [ ] **Step 4: Run green with every hook/crash placement**

Run: `uv run pytest integrations/home-assistant/tests/test_backup_hooks.py integrations/home-assistant/tests/test_backup_crash.py integrations/home-assistant/tests/test_restore_quarantine.py tests/integration/home/test_controller_epoch_rotation.py tests/fault/home/test_restore_between_dispatch_reconcile.py -q`
Expected: PASS; valid artifact always has marker; uninterrupted live instance clears it only after archive end; interruption stays quarantined; pre-hook waits at most 30 seconds; restore registers zero mutation/trigger before new epoch; restored routines stay inactive; pre-restore in-flight work never replays.

- [ ] **Step 5: Commit exact backup/restore paths**

```bash
git add integrations/home-assistant/custom_components/tuntun_bridge/backup.py integrations/home-assistant/custom_components/tuntun_bridge/__init__.py apps/core/src/tuntun_core/services/home/restore.py integrations/home-assistant/tests/test_backup_hooks.py integrations/home-assistant/tests/test_backup_crash.py integrations/home-assistant/tests/test_restore_quarantine.py tests/integration/home/test_controller_epoch_rotation.py tests/fault/home/test_restore_between_dispatch_reconcile.py docs/operations/phase2-green-backup-restore.md
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
- Modify: `scripts/phase2/verify_green_backup.py`
- Create: `scripts/phase2/rotate_green_backups.py`
- Create: `scripts/phase2/audit_green_logging.py`
- Modify: `ops/home-assistant/green-backup-catchup.example.yaml`
- Create: `ops/home-assistant/logging.example.yaml`
- Create: `docs/operations/phase2-observability.md`
- Modify: `apps/core/src/tuntun_core/services/home/health.py`
- Modify: `apps/core/src/tuntun_core/api/home_dtos.py`
- Modify: `apps/admin/src/features/home/health.tsx`
- Create: `tests/unit/home/test_backup_health.py`
- Create: `tests/integration/home/test_backup_rotation.py`
- Create: `tests/security/home/test_cifs_boundary.py`
- Create: `tests/security/home/test_home_observability_content.py`
- Create: `tests/hardware/home/test_green_external_backup.py`
- Create: `tests/hardware/home/test_green_logging_retention.py`
- Create: `tests/e2e/home-backup-health.spec.ts`

**Interfaces:** HA sensors expose receipt/store pressure, mutation quarantine, routine breaker, binding freshness, and Green-side exact CIFS readiness without identities/content. `BackupHealthService.evaluate(now) -> BackupPosture`; external alert at >36h, risky update/new routine block at >72h, conditional RPO target only when one verified 60-minute Mac/SSD availability window exists in each 72h.

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
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/home/test_backup_health.py tests/integration/home/test_backup_rotation.py tests/security/home/test_cifs_boundary.py tests/security/home/test_home_observability_content.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/home-backup-health.spec.ts`
Expected: FAIL because backup health/rotation and updated UI are absent.

- [ ] **Step 3: Implement exact readiness, catch-up, retention, and health truth**

The Green-side readiness sensor is true only after mount, write/delete, SMB 3 encryption, and free-space probes of the exact configured CIFS target. An owner-created `origin=home_assistant` fixed automation invokes only `backup.create_automatic`, allows one in-flight job and one attempt/30 minutes, and stops after destination-success receipt. Tuntun never invokes/edits it. If HAOS/Core cannot expose required readiness/success evidence, automatic catch-up and SLA are disabled/manual.

Green creates encrypted local configuration backup daily and pre-update, retains newest three locally, and succeeds locally even while Mac target sleeps. External full backup artifacts are deleted by age so receipt-detail/tombstone bounds stay at +38/+58 days. Routine backups exclude Recorder; diagnostic full backups expire within 10 days. Mac rotation keeps seven daily/four weekly only after Green destination success. Recorder remains an explicit allowlist with `purge_keep_days: 10`; the separate raw operational-log policy rotates at seven days, disables unneeded long-term statistics, redacts request bodies/identifiers/content, and fails commissioning if the delivered HAOS/Core build leaves raw-log retention unbounded or longer than Recorder.

- [ ] **Step 4: Run green, then cold-Mac/external backup campaign**

Run: `uv run pytest tests/unit/home/test_backup_health.py tests/integration/home/test_backup_rotation.py tests/security/home/test_cifs_boundary.py tests/security/home/test_home_observability_content.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/home-backup-health.spec.ts`
Expected: PASS; no transcript/biometric/PIN/passkey/family memory/provider secret enters sensors/logs/UI; infrastructure public key/CIFS account/TLS material is correctly classified rather than falsely absent.

Owner run: `TUNTUN_ALLOW_HOME_HARDWARE=1 uv run pytest -m home_hardware tests/hardware/home/test_green_external_backup.py tests/hardware/home/test_green_logging_retention.py -q --evidence-dir var/evidence/phase2/p2-7-external-backup`
Expected positive outcome: cold Mac reboot unlocks dedicated encrypted volume/share without exposing key to Green; SMB 3 encrypted packet capture contains no plaintext backup or reusable credential; unavailable Mac still permits local Green backup; recovered target starts catch-up within 30 minutes and verifies within 60 minutes; an external encrypted backup no older than 72 hours restores in isolation; emergency key copy works; Recorder is allowlisted/10-day, raw operational logs rotate at seven days, and unneeded long-term statistics are absent. If the required availability window is missed, UI shows best-effort/unbounded instead of a 72-hour claim; if raw-log retention is unsupported or unbounded, P2-7 remains blocked.

- [ ] **Step 5: Commit observability/backup code, never real evidence**

```bash
git add integrations/home-assistant/custom_components/tuntun_bridge/sensor.py apps/core/src/tuntun_core/services/home/backup_health.py scripts/phase2/verify_green_backup.py scripts/phase2/rotate_green_backups.py scripts/phase2/audit_green_logging.py ops/home-assistant/green-backup-catchup.example.yaml ops/home-assistant/logging.example.yaml docs/operations/phase2-observability.md apps/core/src/tuntun_core/services/home/health.py apps/core/src/tuntun_core/api/home_dtos.py apps/admin/src/features/home/health.tsx tests/unit/home/test_backup_health.py tests/integration/home/test_backup_rotation.py tests/security/home/test_cifs_boundary.py tests/security/home/test_home_observability_content.py tests/hardware/home/test_green_external_backup.py tests/hardware/home/test_green_logging_retention.py tests/e2e/home-backup-health.spec.ts
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

Network verification inspects both NAT mapping tables, external scan, outer-to-inner and inner-to-office directions, reserved source address, listener inventory, and compromised inner client/TV reachability to Reachy daemon/media/API/WebRTC/SSH. Stronger segmentation remains `unproved` unless exact firmware and flows pass.

- [ ] **Step 4: Run synthetic matrix, then controlled physical drills**

Run: `uv run pytest tests/fault/home/test_complete_phase2_matrix.py tests/security/home/test_phase2_lateral_reachability.py tests/security/home/test_phase2_private_data_scan.py tests/integration/home/test_green_update_rollback.py -q && uv run python scripts/verify_private_data.py .`
Expected: PASS; every synthetic fault produces zero duplicate effect, false success, unsafe retry, or secret/private-content finding; update rollback restores exact prior hashes and remains quarantined until reconciliation.

Owner runs:

```bash
TUNTUN_ALLOW_HOME_HARDWARE=1 uv run pytest -m home_hardware tests/hardware/home/test_phase2_outages.py -q --evidence-dir var/evidence/phase2/p2-7-outages
TUNTUN_ALLOW_NETWORK_PROBE=1 uv run pytest -m home_hardware tests/hardware/home/test_phase2_network_exposure.py -q --evidence-dir var/evidence/phase2/p2-7-network
TUNTUN_ALLOW_UPS_TEST=1 uv run pytest -m home_hardware tests/hardware/home/test_phase2_power_recovery.py -q --evidence-dir var/evidence/phase2/p2-7-power
```

Expected: WAN/cloud loss preserves local HA/native/manual and eligible local grammar; Mac/Reachy loss preserves HA/native/manual; Green/Matter/MZHUB/router failure becomes unavailable without repeated command; external scan finds no service; office/inner and Reachy forbidden flows fail; brownout/low battery shuts Green gracefully before exhaustion, router/MZHUB ride-through is measured without graceful-shutdown claim, recovery reboots in documented order and replays nothing. If Reachy isolation failed, production action ingress remains absent throughout.

- [ ] **Step 5: Commit fault/update tooling and runbooks only**

```bash
git add scripts/phase2/run_fault_matrix.py scripts/phase2/verify_network_exposure.py scripts/phase2/verify_home_update.py fixtures/synthetic/home/fault-matrix-v1.json tests/fault/home/test_complete_phase2_matrix.py tests/security/home/test_phase2_lateral_reachability.py tests/security/home/test_phase2_private_data_scan.py tests/integration/home/test_green_update_rollback.py tests/hardware/home/test_phase2_outages.py tests/hardware/home/test_phase2_network_exposure.py tests/hardware/home/test_phase2_power_recovery.py docs/operations/phase2-failure-recovery.md docs/operations/phase2-update-rollback.md docs/evidence/phase2-fault-gate-schema.json
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(home): prove Phase 2 failure recovery"
```

### Task 34: Freeze Phase 2 acceptance evidence and run the seven-day household soak

**Depends on:** Tasks 01–33, every enabled hardware gate, and a clean candidate commit.
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
- Create: `tests/acceptance/home/test_phase2_soak_oracles.py`

**Interfaces:** `run_acceptance(candidate, evidence_inputs, signer) -> SignedEvidence`; `verify_acceptance(envelope, candidate, schemas, feature_manifest) -> Phase2Decision`; `run_soak(duration_seconds=604800) -> SignedSoakEvidence`. Evidence is content-safe, signed, and binds exact candidate commit, Phase 1 `FB0` evidence hash plus the exact consumed-interface contract/test digests named in Global Constraint 1, schemas/policies/corpora/migrations/UI/HA package hashes, pseudonymous hardware/firmware/config digests, commands, start/end, operator, and deviations. It neither requires nor makes a claim about the parallel Phase-1-only `P1R0` preview.

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

def test_candidate_has_one_canonical_location_key(installed_candidate) -> None:
    evidence = probe_location_contracts(installed_candidate)
    assert evidence.canonical_household_location_keys == ("area_id",)
    assert evidence.subordinate_location_keys == ("zone_id",)
    assert evidence.parallel_or_compatibility_keys == ()
    assert evidence.zone_parent_and_generation_checks == "enforced"
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/acceptance/home/test_phase2_acceptance_gate.py tests/acceptance/home/test_phase2_evidence_schema.py tests/acceptance/home/test_phase2_feature_absence.py tests/acceptance/home/test_phase2_soak_oracles.py -q`
Expected: FAIL because Phase 2 evidence builders/verifiers are absent.

- [ ] **Step 3: Implement strict evidence schemas and semantic verifier**

The acceptance schema is recursively `additionalProperties:false` and has no caller-authored pass Boolean. The verifier recomputes exact suite sets/counts, zero fields, thresholds, elapsed durations, hash bindings, enabled-feature positive gates, disabled-feature source/package/configuration/API/direct-URL/prepared-action/client-registration/client-bundle/network absence gates, archive/retention bounds, and hardware-decision consistency. Required suite minima include:

- authorization corpus: exactly 1,350 and zero oracle mismatch;
- target resolution: at least 100 randomized and zero wrong endpoint;
- screen-time corpus: exactly 720 and zero oracle mismatch;
- screen-time property: at least 10,000 sequences and zero invariant failure;
- duplicate/delay/reorder/loss/crash timing: every Mac/HA/scene/routine transition, including both sides of pre-dispatch commit;
- signed-route adversarial matrix: standard API, off-registry, wrong domain/key/epoch/generation/noncanonical/replay/oversize/rate paths, zero state leak/action;
- topology surface matrix: generated JSON Schema, Pydantic serialization, migration metadata, OpenAPI, generated TypeScript, synthetic fixtures, prepared-action bindings, and installed API accept only canonical `area_id`; optional `zone_id` is generation-bound beneath one area/owning binding, while cross-area moves and every parallel/compatibility location key are absent or rejected;
- receipt retention/quota/corruption/backup archive bounds;
- routine CAS/feedback/budget/circuit/restore quarantine;
- network/private-data/backup/restore/update/power evidence;
- seven elapsed one-light days and seven elapsed household-soak days where the bridge path is enabled.

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

Then run the elapsed/physical gate:

```bash
TUNTUN_ALLOW_ELAPSED_PHASE2=1 uv run python scripts/phase2/run_acceptance.py household-soak --duration-seconds 604800 --sample-seconds 60 --commit "$(git rev-parse HEAD)" --evidence-root var/evidence/phase2 --output var/evidence/phase2/household-soak.json
uv run python scripts/phase2/verify_acceptance.py var/evidence/phase2/household-soak.json --commit "$(git rev-parse HEAD)" --require-physical-gates
uv run python scripts/verify_private_data.py var/evidence/phase2
```

Expected: monotonic and wall elapsed are each at least 604,800 seconds; zero wrong-device command, false completion, duplicate effect, unbounded retry, silent automation change, post-disable undispatched routine, cross-profile/Guest/child violation, or loss of physical/manual recovery; backup/network/power/update and conditional feature decisions remain current; evidence scan finds no raw identifier/content/secret. A source, policy, schema, UI, integration, firmware, router, area/zone, or hardware revision change invalidates its dependent evidence and returns that capability to quarantine.

- [ ] **Step 5: Commit evidence tooling before the frozen run; never commit generated owner evidence**

```bash
git add scripts/phase2/run_acceptance.py scripts/phase2/verify_acceptance.py docs/evidence/phase2-acceptance-schema.json docs/evidence/phase2-soak-schema.json docs/operations/phase2-acceptance-runbook.md tests/acceptance/home/test_phase2_acceptance_gate.py tests/acceptance/home/test_phase2_evidence_schema.py tests/acceptance/home/test_phase2_feature_absence.py tests/acceptance/home/test_phase2_soak_oracles.py
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
03/05 → 06 policy amendments → 07 offline target path
01/02 → 08 HA scaffold → 09 receipt store → 10 verifier/key → 11 state route → 12 sync/health
03/06/12 → 13 owner read UI → 14 P2-0 evidence
14 → 15 MZHUB one-light gate → 16 twelve-light baseline
15 failure + owner decision → 17 conditional direct-Zigbee pilot → 16
04/06/10/12/16 → 18 Mac action → 19 HA dispatch → 20 reconcile → 21 family policy → 22 scenes → 23 action UI
05/21 → 24 draft governance → 25 routine install → 26 routine runtime → 27 Learning/UI
02/05/06 → 28 screen state → 29 eligibility simulator → 30 screen UI
09/20/25/26 → 31 backup/restore → 32 observability/external backup
all enabled paths → 33 fault/update/rollback → 34 acceptance/soak
```

Tasks 03–07 and 08‐11 may proceed in separate clean worktrees after Task 01 contracts freeze. Tasks 24 and 28 may proceed in parallel after their declared dependencies. Physical campaigns are serialized against the single household controller estate; a cloned Matter fabric, Zigbee coordinator identity, or routine controller never runs beside production.

## Requirements Traceability

| Requirement | Primary tasks |
|---|---|
| Canonical topology/event/action contracts and future seams | 01, 03, 12 |
| Sole canonical `area_id`; optional versioned binding-owned `zone_id`; no parallel location key | 01, 03, 13, 16, 21, 34 |
| Signed feature registry and backend/API/direct-URL/client-chunk absence | 13, 34 |
| Four Phase 1 amendments and no unknown-candidate regression | 06‐07, 21 |
| No HA token/general API; signed narrow TCB | 08, 10‐11, 19, 25, 33 |
| MZHUB capability probe with independent Matter/Thread findings | 14‐15 |
| One-light then twelve-light staged rollout | 15‐16 |
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
| Synthetic evidence and seven-day household soak | 02, 34 |

## Final Phase 2 Go/No-Go Checklist

- [ ] Phase 1 `FB0` evidence and every named consumed Phase 1 contract/service digest are current; Phase-1-only `P1R0` is not treated as a prerequisite; all four named amendments are current.
- [ ] Exact MZHUB identity/attestation and independent capability findings are recorded; no Matter or Thread behavior is inferred.
- [ ] Exactly one accepted controller branch is active; no device belongs to two Zigbee coordinators.
- [ ] Twelve endpoints/aliases/bindings are exact, generation-bound, and have zero wrong-target results.
- [ ] `area_id` is the only canonical household location key across schemas, migration metadata, APIs, generated clients, fixtures, prepared operations, and installed behavior; optional `zone_id` records remain immutable-area, generation-bound children of one owning binding, and no compatibility mapping exists.
- [ ] Secure Enclave actual signing, pinned TLS, challenge/replay lifecycle, source filtering, and clock-offset gate pass.
- [ ] No HA/Supervisor/user token exists; standard HA APIs and every off-registry/custom escape path produce zero Tuntun mutation/state leak.
- [ ] Mac and HA state machines, deadlines, receipts, rate limits, crash recovery, retention, quota, and corruption gates pass.
- [ ] Adult convenience is limited to one exact reversible light; child dual approval and Guest owner co-approval match every oracle; anonymous side effects are zero.
- [ ] Scene definitions/execution have exact passkey/confirmation, 1–12 canonical children, truthful partial outcomes, and no rollback fiction.
- [ ] Manual is default; Assisted/Learning have no silent install; routine CAS/budgets/circuit/disable/restart/restore gates pass.
- [ ] Screen-time 720-case and 10,000-sequence gates pass; real TV enforcement remains absent/Advisory unless separately qualified.
- [ ] UI routes are signed-feature-gated, no optimistic state appears, bypasses/manual recovery are disclosed, and English/Hindi/accessibility/responsive gates pass.
- [ ] Green local/external backup, SMB encryption, availability-conditioned RPO truth, archive retention, isolated restore, and new-epoch quarantine pass.
- [ ] Exact UPS/NUT, power recovery, router/AiMesh, external scan, office/inner isolation, and Reachy isolation branch pass.
- [ ] Update/rollback preserves the prior compatible release and never reopens mutation before reconciliation.
- [ ] Private-data/content scan passes; only synthetic fixtures and content-safe evidence tooling are tracked.
- [ ] Seven elapsed household-soak days pass with zero wrong-device action, false completion, unsafe retry, silent automation change, or lost manual recovery.

## Implementation Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-27-tuntun-phase2-home-automation-execution.md`.

Execute Tasks 01–34 with `superpowers:subagent-driven-development` (recommended) for fresh task workers and two-stage review, or `superpowers:executing-plans` for checkpointed inline batches. Start no physical Phase 2 mutation until P2-0 and the relevant hardware gate are accepted; conditional P2-F requires its explicit owner decision.
