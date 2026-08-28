# Tuntun Six-Phase Master Implementation Roadmap

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development for bounded work packages in the current session, or superpowers:executing-plans for a checkpointed implementation session. This roadmap controls sequencing; the linked phase plans control exact files, tests, and commits.

**Goal:** Build Tuntun from a disposable Mac-and-Reachy bilingual voice proof into a family-ready, locally governed, open-source home-assistant platform without allowing later home, camera, media, AI, desktop, robot, plugin, or remote capabilities to bypass the identity, child-safety, privacy, authorization, audit, and recovery boundaries established earlier.

**Architecture:** Keep canonical household authority in a local modular monolith on the 2020 Intel Mac. Reachy and later room/display/robot endpoints are bounded edge devices. Home Assistant Green is the deterministic device plane. Reolink recording is a process/key/storage-separated video plane. Local and cloud models remain untrusted computation behind typed gateways. Every external effect uses an exact prepared authorization and truthful result. Optional capabilities are absent from package, configuration, API, UI, and runtime until their positive gate passes.

**Primary stack:** Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2/Alembic, SQLCipher, macOS Keychain/Secure Enclave ports, React 19/TypeScript/Vite, strict JSON Schema/JCS contracts, pytest/Hypothesis, Vitest/Testing Library/Playwright, Ruff/mypy, Home Assistant custom integration APIs, signed local mTLS/Unix-socket adapters, and synthetic evidence tooling. Hardware/provider/runtime selections remain behind ports and exact acceptance records.

**Normative specifications:**

- [Program architecture A–H](../specs/2026-08-27-tuntun-program-architecture-a-h.md)
- [Program assurance and delivery I–S](../specs/2026-08-27-tuntun-program-assurance-delivery-i-s.md)
- [Six-phase UI/UX](../specs/2026-08-27-tuntun-six-phase-ui-ux-design.md)
- [Phase 1](../specs/2026-08-27-tuntun-phase1-anchor-design.md), [Phase 2](../specs/2026-08-27-tuntun-phase2-home-automation-design.md), [Phase 3](../specs/2026-08-27-tuntun-phase3-vision-presence-storage-design.md), [Phase 4](../specs/2026-08-27-tuntun-phase4-voice-media-displays-design.md), [Phase 5](../specs/2026-08-27-tuntun-phase5-private-ai-desktop-robotics-design.md), and [Phase 6](../specs/2026-08-27-tuntun-phase6-remote-access-product-hardening-design.md)

---

## 1. Locked household baseline

| Boundary | Locked baseline |
|---|---|
| Core host | One 2020 Intel MacBook Pro, 16 GB RAM, normally at home; this is the same physical machine previously described as the office laptop, not a second host. FileVault and owner-only local administration are required |
| Embodied endpoint | Reachy Mini Wireless; wake phrase “Hello Tuntun” |
| Language | English, Hindi, and natural Hinglish; follow the active speaker's switches within a conversation |
| Family | One owner/operator; adult partner; K2 child; N1 child; guarded child policy and distinct current-primary-guardian decisions |
| Initial inference | Quality-first approved cloud route, S$100 monthly soft warning and S$150 hard cap; offline essentials remain local |
| Memory | Local encrypted seven-kind memory with subject/audience/guardian visibility; no hosted canonical memory |
| Home devices | Twelve MOES Zigbee ceiling lights through existing MZHUB, tested first as a local Matter bridge; Home Assistant Green selected |
| Power | Signalling-capable UPS required for the Phase 2 family-ready gate; exact unit waits for current NUT compatibility and landed quote |
| Cameras | TrackMix in hall/pathway toward bedrooms; two E1-family units in kitchen from different views; exact SKU/firmware capability gates |
| Camera privacy | Audio off/stripped; Reolink never identifies or greets; raw media never reaches LLM/VLM, memory, Home Assistant, or cloud |
| Initial camera storage | Existing encrypted external SSD; exactly seven days low-resolution continuous plus 90 days full-resolution native-event clips |
| NAS | Decision pending until measured seven-day camera/storage campaign and one-/three-/five-year VMS/licence/power/recovery comparison |
| TVs | Samsung Neo LED 49-inch and TCL 42-inch; manual HDMI display first, exact-unit control/observation gates later |
| Network | Archer BE800 is the outer/primary router and ASUS GT-AX6000 plus three AX5400 AiMesh nodes is the inner household network. For the Phase 1 family-ready baseline, the single Mac and Reachy are single-homed on the same trusted ASUS/AiMesh L2 and the Mac's direct BE800 Ethernet link is disconnected. Any later dual-homing is a separate fail-closed qualification, not an assumed route |
| Remote boundary | LAN-only through Phase 5. Phase 6 implements Tailscale only, no forwarding/public bind/Funnel/subnet route/direct WireGuard |
| Robotics | Existing Raspbot and LILYGO hardware may be evaluated; no autonomous child supervision or model-generated motion |
| Distribution | Apache-2.0 framework, synthetic public fixtures, signed/notarized evidence-bound macOS beta |

These are design inputs, not permission to purchase conditional hardware, enable a vendor cloud, publish a release, or expose a network route.

## 2. Execution documents

| Scope | Controlling execution document |
|---|---|
| Phase 1 master work packages | [Phase 1 anchor plan](./2026-08-27-tuntun-phase1-anchor.md) |
| Phase 1 foundation | [Foundation execution](./2026-08-27-tuntun-phase1-foundation-execution.md) |
| Phase 1 conversation and Reachy | [Conversation/Reachy execution](./2026-08-27-tuntun-phase1-conversation-reachy-execution.md) |
| Phase 1 controlled web/search | [Controlled-web execution supplement](./2026-08-27-tuntun-phase1-controlled-web-execution.md) |
| Phase 1 identity and memory | [Identity/memory execution](./2026-08-27-tuntun-phase1-identity-memory-execution.md) |
| Phase 1 owner console | [Control-console execution](./2026-08-27-tuntun-phase1-control-console-execution.md) |
| Phase 1 packaging/release | [Phase 1 release execution](./2026-08-27-tuntun-phase1-release-execution.md) |
| Phase 2 | [Home-automation execution](./2026-08-27-tuntun-phase2-home-automation-execution.md) |
| Phase 3 | [Vision/presence/storage execution](./2026-08-27-tuntun-phase3-vision-presence-storage-execution.md) |
| Phase 4 | [Voice/media/displays execution](./2026-08-27-tuntun-phase4-voice-media-displays-execution.md) |
| Phase 5 | [Private-AI/desktop/robotics execution](./2026-08-27-tuntun-phase5-private-ai-desktop-robotics-execution.md) |
| Phase 6 | [Remote-access/product-hardening execution](./2026-08-27-tuntun-phase6-remote-access-product-hardening-execution.md) |
| Cross-phase UI | [Six-phase UI execution](./2026-08-27-tuntun-six-phase-ui-execution.md) |

If a linked phase plan and its normative phase specification differ, stop implementation and reconcile the contract, policy corpus, migration, generated client, feature manifest, tests, and documentation in one reviewed change. Do not silently choose the less restrictive wording.

## 3. Dependency and promotion graph

```mermaid
flowchart TD
  POC[Disposable POC\nMac + Reachy\n1–2 week target] --> FB0[Phase 1 FB0\nfamily-private-beta gate]
  FB0 --> P1R0[Phase 1 P1R0\nphase-only candidate]
  P1R0 --> P1R1[Phase 1 P1R1\noptional phase-only preview]
  FB0 --> P2[Phase 2\nHome automation]
  P2 --> P3[Phase 3\nVision + storage]
  P2 --> P4E[Phase 4 Tasks 01–03 + simulator\nno owner-ingress mutation]
  P3 -->|Task 17 ingress infrastructure\nand Task 32 final inventory| P4[Phase 4 integrated\nvoice + media + displays]
  P4E --> P4
  P3 --> P5[Phase 5\nSelected-frame seam]
  P4 --> P5
  P3 --> P6[Phase 6\nProgram hardening]
  P4 --> P6
  P5 --> P6
  P6 --> C0[Whole-program C0\nfrozen release candidate]
  C0 --> C1[Whole-program C1\nmanual public beta approval]

  UI[Cross-phase UI contracts] -. delivered inside each phase .-> FB0
  UI -.-> P2
  UI -.-> P3
  UI -.-> P4
  UI -.-> P5
  UI -.-> P6
```

Rules:

1. Simulator, schema, UI-fixture, and adapter work for a later phase may begin after the consumed contract is frozen.
2. Household mutation, capture, media, execution, motion, or remote routes cannot open before every prerequisite positive gate passes on the real target.
3. Optional absence is an engineering result: package registration, configuration, routes, direct APIs, prepared-action issuance, UI, client bundle, and runtime entry points are all negatively tested.
4. A failure quarantines only the affected capability when separation is proved. It never grants a fallback with broader data or authority.
5. P1R0/P1R1 are Phase 1-only. Only Phase 6 can produce whole-program C0/C1.
6. Phase acceptance consumes its allocated UI checkpoint on the same candidate: Phase 2 requires U3/U13–U14, Phase 3 U4/U15–U16, Phase 4 U5/U17–U19, Phase 5 U6/U20–U22, and whole-program C0 U8/U23–U28. U8 is split to avoid a dependency cycle: U8A commits the verifier/UI tooling before Task 36B freezes the release, while U8B consumes Task 34B maintenance plus Task 35R post-drill resilience evidence and accepts the exact frozen candidate before Task 35B/P6-4. U25/U8A do not require or create C1. Phase 6 Task 38 later verifies the actual signed C1/publication state through that unchanged read-only UI while preserving U8B before P6-5 completion.

### Cross-phase authority and release invariants

- The inventoried 2020 Intel Mac is both the office-use machine and the sole canonical Core host. Phase 6 extends the Phase 3 owner-ingress server and cannot invent a second helper or parallel server.
- Phase 3 Task 17 creates the sole signed owner-ingress route manifest and canonical `phase3.owner_ingress.v1` service row; Task 26 refreshes/re-signs and lifecycle-qualifies it before the seven-day alert calibration, and Task 32 repeats that protocol for the final Phase 3 graph. Phase 4 serializes the same row at Tasks 05, 22, 27, 32, 35, and 36 before each corresponding physical/promotion checkpoint. Phase 6 then extends only that canonical manifest. Every owner-facing endpoint is wired through the installed Core app/container and owner-ingress router. The canonical Phase 3 owner-ingress service row is rebuilt/re-signed against the current wheel/route digest before the Task 15 P6-1 pilot, again at Task 18 for P6-2, again at Task 29 for P6-3, and finally in Task 36A after Task 35A and before frozen release bytes. Each changed graph rejects its predecessor row/receipt and preserves it only as a complete matching rollback set; installed dispatch/negative-reachability/takeover/start/health/restart/update/rollback/uninstall evidence is rerun. No physical or promotion campaign begins after a route change until its owning checkpoint is committed, the worktree is clean, and that exact installed row passes. Task 37A/38A commit the remaining release tooling, then Task 36B freezes the final candidate before Task 34B's maintenance clock. Finalizer, Task 34B, Task 35R, U8B, Task 35B/P6-4, Task 36C, C0 and C1 consume only the post-Task-35A row. The plugin-supervisor row is likewise refreshed after its sandbox modules are added, with the earlier row/receipt rejected.
- Program-wide from Phase 2 through Phase 6, the sole authority for a multi-day pilot, soak, stress run, maintenance-eligibility window or other elapsed gate is Phase 2's externally signed, pre-issued `SignedFeatureManifestRolloverChainV1`, consumed by the canonical `FeatureManifestLeaseSupervisor` and checked through a per-admission `FeatureAuthorityLease`; every runner exposes only `--feature-manifest-chain PATH`. No runtime process receives a feature-manifest signer or implements renewal, an alternate chain/file alias, a fallback chain, a grace extension or an implicit successor. Each ordered chain binds the exact candidate/composition and feature registrations it authorizes. Any package, route, service-row, registration or other composition change invalidates the chain and requires a newly externally signed candidate-specific chain, controlled restart and fresh eligible epoch. Missing, late, stale, reordered, widened, rollback, signature-invalid, cross-candidate or expired current/next authority closes admission and background work before I/O and produces zero credited expired-authority interval.
- Within Phase 6, every multi-day pilot, counted maintenance-eligibility window, soak, stress run and final-evidence campaign consumes that one canonical chain/lease boundary; Phase 6 creates no signer, renewal path or alternate interface. The ordered chain must bind one frozen candidate, cover the complete campaign, transition before each predecessor expiry, and produce zero expired-authority interval. The earlier P6-1 pilot remains historical sequencing evidence. For final release, Task 36B freezes one candidate before Task 34B opens its real steady-state epoch; that exact candidate and one pre-issued chain bind the complete Task 34B interval, Task 35R, U8B, Task 35B/P6-4 and Task 36C final campaigns. Missing, stale, reordered, widened, rollback, signature-invalid, candidate-drifted or expired current/next authority closes admission/background work before I/O, invalidates the campaign, and enters controlled whole-composition recovery. Maintenance observations during a closed-authority interval remain recorded but cannot count toward the 60-/90-day promotion window, which restarts only under a newly frozen candidate/generation. P6-1, Task 34B, Task 35R, U8B, Task 35B, Task 36C, C0 and final handoff evidence bind the chain ID, ordered manifest digests and transition receipts.
- Phase 5 core migrations are exactly `0019_screen_time_real_adapter -> 0020_private_ai_registry -> 0021_desktop_authority -> 0022_robotics`; the private knowledge catalog has a separate migration configuration/version table. Phase 6 extends only the core graph through `0023_remote_access -> 0024_plugins_releases -> 0025_recovery_incident_maintenance`.
- Memory audiences remain exactly `subject_private|guardian_child|household_adults|household_all`. D3 and D4 execution network policy is exactly `none`; robot authority binds canonical Phase 2 area/zone and robot-binding generations plus non-overlapping signed state domains.
- Phase 6 VPN admission uses Tailnet Lock with Device Approval disabled, current signed nodes, at least two independent recovery signers, current Tailscale `grants` syntax with separate `dst` and `ip`, and exact two-view authoritative DNS/certificate bindings. External remote action JSON is only `operation`, opaque `resource`, and `idempotency_key`; all authority is server-resolved.
- Plugin children see only bounded inner payload bytes; backup tiers bind identical source truth; offline bootstrap is one-shot quarantine-only; update state is signed, fsync-durable, CAS-sequenced, and reconciled before service exposure.
- Every non-Core executable service family is release-owned by one signed `ops/services/*.v1.json` row whose target records bind the exact package, job/unit or managed-app registration, executable argv, dedicated account, configuration, socket/listener/runtime boundary, restart/health policy and cleanup set. Feature manifest, package and target records are one-to-one: enabled targets pass start/health/crash-restart/wrong-account and both uninstall modes on their declared platform; absent targets ship none of their production service artifacts, and a family with no target has no row. Phase 6 install/update/uninstall consumes the signed Phase 1 Reachy managed-app row, four Phase 3 camera/recording/ingress rows, both Phase 4 Linux rows and the four conditional Phase 5 proxy/helper/robot rows rather than scanning a live host; remote-target cleanup requires signed target-orchestrator receipts and never applies a Mac path operation to Reachy/Linux/Pi/appliance storage.
- Phase 4 maintenance records enter the Phase 6 whole-program gate through one closed mapper: all Phase 4 subsystems map to its Phase 4 aggregate, each exclusion has one exact destination, ambiguous `quarterly_drill` stays separately classified, and `month_key` must match `occurred_at` in UTC before aggregation.
- Maintenance/P6-4, U8A, release build/finalizer, campaign, C0 and isolated C1/publication tooling are all committed first, including the final owner-ingress row. Only then does Task 36B build and attest release bytes, sign/notarize/staple where applicable, hash/bind the final manifest, and qualify real Intel/Apple-Silicon plus every signed enabled Linux service target. Task 34B then collects the non-compressible 60-/90-day maintenance evidence on those exact bytes, Task 35R refreshes the candidate-bound resilience drills, U8B accepts the post-drill candidate/UI evidence, Task 35B accepts P6-4 without changing them, and Task 36C runs soak/stress/threat/current-control evidence. From Task 36B through publication, every operation is evidence, acceptance or publication only; any source/route/service-row/lock/workflow/schema/package/artifact mutation invalidates the whole final-candidate sequence. Disabled Linux targets have no package/unit/config/account/listener/runtime/receipt. After accepted C0 and the soak, one preallocated C1 UUID is used to sign the short-lived publication manifest and build C1; C1 and publication reuse the exact accepted C0 artifact-set and named-inventory digests. C0 approval and its distinct handoff assertion are household-owner ceremonies; C1 and publication are distinct project-maintainer ceremonies at a separate local terminal, while household UI remains read-only. Publication authority is durably claimed before the two-minute assertion expires and is usable only in a half-open, at-most-30-minute exact-byte run; reaching the deadline stops writes. A post-C1/pre-receipt failure preserves accepted-C1 history but claims no publication, and later source/artifact/C0 drift cannot reuse that C1 for changed bytes.

## 4. Phase-by-phase delivery contract

| Phase | Family outcome | Entry | Mandatory exit | Conditional/absent result | Solo engineering estimate |
|---:|---|---|---|---|---:|
| 1 | Reachy bilingual personal family assistant, guarded profiles, seven memories, owner console, offline essentials | Supported Mac baseline and delivered Reachy probes | FB0 physical loop, child safety, Guest fallback, memory isolation, auth, privacy/stop, budget, backup/restore; later phase-only P1R0/R1 evidence | Automatic identity, Qwen, Realtime, LAN console, or advanced preview routes may be absent only where Phase 1 marks them optional; passive identity is always absent | 177.5 person-days for complete preview scope; aggressive FB0 feedback target 6–8 weeks, about 9–10 months solo for the full scope |
| 2 | Deterministic local lights, governed scenes/routines, screen-time simulator | Phase 1 FB0 stable; shared contracts reconciled | Green/UPS/recovery, one-light then twelve-light proof, signed HA bridge, policy corpus, durable results, Manual/Assisted/Learning, screen-time simulator, failures/restore/soak | Failed Matter bridge leaves estate native and opens a separately owner-approved ZBT-2 pilot; no silent reset or purchase | 8–12 focused weeks |
| 3 | Private local recording, owner alerts, optional anonymous occupancy | Phase 2 topology/event/auth contracts stable | Exact camera/zone/vendor-egress gates, TrackMix privacy arc, audio-off, seven-day capacity run, exact 7/90 deletion, gaps/full-disk/recovery, owner playback, local inbox/SSE alerts, false-vacancy prevention, NAS decision receipt | Ineligible E1/camera stays inventory/vendor-native only; unsupported TrackMix second view stays absent; NAS remains pending | 7–11 weeks plus any 30-day optional migration comparison |
| 4 | Whole-home voice endpoint, media, teaching display, exact-TV screen-time capability | Phase 2 signed bridge/simulator stable and Phase 1 room policies current for Tasks 01–03/simulator; Phase 3 Task 17 owner-ingress infrastructure before integrated Task 04; accepted Phase 3 Task 32 final service inventory before Phase 4 Task 36/final acceptance | One selected common-room hardware endpoint passes the bakeoff, physical mute/indicator, duplicate arbitration and one-slot routing with Reachy; legal media adapter, closed display renderer, exact TV probes, bounded screen-time enforcement, consent/accessibility/soak also pass | A failed common-room bakeoff may continue only as non-promotable simulator/manual-display learning; TV stays manual/display-only or Advisory, and second-conversation/private-room rollout remains absent until its gates pass | 88–130 person-days, 18–26 focused weeks |
| 5 | Staged local inference, private corpus, bounded desktop help, supervised Raspbot | Phase 3 frame and Phase 4 endpoint contracts stable | Task-specific inference evidence, one identity-bound corpus root/recovery, owner-only desktop grant/egress, D3/D4 separation, anonymous CV, robot safety, optional-board decision, signed per-target service inventory/lifecycle, soak/rollback | No appliance purchase if benchmark fails; D4 absent without proved sandbox; robot stays simulation/bench if safety fails; LILYGO route removed if no unique value; every absent service target omits its production package/job/config/account/socket/unit/target record | 130–210 person-days, 26–42 focused weeks |
| 6 | VPN-constrained owner access, closed plugins, complete recovery/release hardening | Accepted Phase 1–5 mandatory gates and stable contracts, including canonical feature-manifest rollover authority | Tailscale least-route/app auth, exact two-capability no-egress plugin registry, `T01`–`T25`, continuous zero-gap feature authority, supply chain, clean restore/update/rollback/uninstall, incidents/retirement, operations burden, C0 then C1 | Optional remote low-risk action/playback classes may remain absent; mandatory plugin and release gates cannot be waived; direct WireGuard absent | 8–12 focused weeks plus non-compressible soak/rolling evidence |

Estimates describe engineering effort, not permission to compress physical, seven-day, 30-day, 60-day maintenance-logging start, minimum-90-day/three-complete-month promotion evaluation, recovery, or family-soak evidence.

## 5. First eight weeks: feedback track

This track is deliberately narrower than complete Phase 1 implementation.

### Days 0–2 — delivered-hardware truth

- [ ] Inventory the exact Mac OS/build, disk reserve, FileVault, sleep/power settings, interfaces, listeners, and external SSD identity.
- [ ] Inventory the delivered Reachy Mini Wireless SKU, serial commitment, firmware, SDK/daemon version, network services, audio formats, camera APIs, buttons/LEDs, reboot behavior, and physical safety path.
- [ ] Keep Reachy on an isolated/test path until the daemon/media/API/WebRTC/SSH negative-reachability gate passes.
- [ ] Record content-free evidence outside Git; commit only synthetic fixtures and schema examples.

### Weeks 1–2 — disposable voice POC

- [ ] Implement local “Hello Tuntun” candidate wake, bounded post-wake capture, explicit push-to-talk diagnostic, stop/privacy, cloud STT/reasoning/TTS, bilingual reply, basic role-aware persona, and per-attempt cost reservation.
- [ ] Exclude biometrics, children in production, durable/personal memory, web, home control, cameras, document/desktop/robot, remote, and public packaging.
- [ ] Run the scripted English/Hindi/Hinglish quality, latency, stop, outage, cost, buffer-clearing, and content-scan corpus.
- [ ] Produce a keep/change/stop POC receipt. Do not harden disposable code into the family architecture without the Phase 1 contracts.

### Weeks 3–5 — canonical core

- [ ] Establish strict contracts, SQLCipher serialized unit of work, Keychain roots, audit/outbox, configuration, provider/cost gateway, one-turn state machine, offline timers/status, and owner authentication.
- [ ] Build the owner console shell, signed feature registry, Privacy Shield, health, approvals, audit, cost, backup, and subject/guardian exact-decision surfaces.
- [ ] Add owner and adult partner profiles with explicit consent and non-biometric selection/Guest fallback.
- [ ] Keep every device/camera/media/desktop/robot/remote domain absent from production registration.

### Weeks 5–8 — family-private-beta attempt

- [ ] Complete interaction-gated Reachy face/voice enrollment and liveness attempt; retain explicit profile choice and Guest if automatic personalization does not pass.
- [ ] Implement the seven memory kinds, subject visibility, child proposal plus separate current-guardian consent/approval, retrieval triple checks, deletion, and backup no-resurrection.
- [ ] Complete guarded child answer policy, no-web child baseline, English/Hindi/Hinglish corpora, controlled adult search, and exact provider disclosures.
- [ ] Run FB0 acceptance, two-hour/50-turn bounded-resource soak, seven-day maintenance rehearsal, and owner then second-adult staged family trial.
- [ ] Enable family use only for the exact FB0 feature manifest. Continue complete P1R0/R1 work on the longer evidence schedule.

## 6. Long-horizon release train

The safest solo sequence is:

1. complete the Phase 1 FB0 foundation and stabilize real household use;
2. finish the Phase 1 mandatory foundation used by hardware phases while continuing phase-only preview hardening;
3. commission Phase 2 Green/UPS and lights without resetting the estate until one-light proof;
4. build Phase 3 recorder/storage before alerts, and alerts before anonymous presence;
5. begin only Phase 4 Tasks 01–03 and simulator work in parallel with Phase 3 where they share no mutable implementation state; wait for Phase 3 Task 17 before Phase 4 owner-ingress integration, then build one common room before private/additional rooms;
6. wait for accepted Phase 3 Task 32 final service inventory before Phase 4 Task 36 refreshes the owner-ingress row and performs final Phase 4 acceptance;
7. enter Phase 5 only after the frame, endpoint, display, policy, and sandbox inputs are stable;
8. in Phase 6, commit all maintenance/P6-4/U8A/release/campaign/C0/C1 tooling, freeze and real-target-qualify one final candidate, run the real 60-/90-day maintenance window, refresh Task 35R resilience, accept U8B then P6-4, run final campaigns, then freeze C0 and separately approve/publish C1 without another candidate mutation.

A single owner-engineer should plan roughly **24–34 months** for the complete six-phase scope when the Phase 1 full-preview estimate, Phase 2–6 focused ranges, hardware lead time, and non-compressible evidence are treated honestly. A useful family assistant arrives much earlier at FB0; later phases are independently valuable increments, not one all-or-nothing launch.

Safe calendar overlap:

| Can overlap | Must remain sequential |
|---|---|
| Synthetic contracts, fake adapters, UI fixtures, documentation, threat cases, procurement research | Real household enablement and owning-phase gates |
| Phase 3 recorder simulator and Phase 4 endpoint simulator after Phase 2 schemas freeze | Camera alerts after recording/storage truth; presence after alert/source calibration |
| Phase 5 model benchmark harness and corpus parser threat fixtures | Appliance purchase after benchmark; D4 after sandbox proof; robot floor run after bench/e-stop proof |
| Phase 6 release tooling and synthetic plugin sandbox research | Remote route after P1–5 auth/operations; C0 after every mandatory gate; C1 after unchanged C0 artifacts |

## 7. Cross-phase workstreams

### 7.1 Contracts and feature registration

- [ ] Keep one strict schema registry with generated Python/JSON/OpenAPI/TypeScript artifacts.
- [ ] Use `area_id` as the sole canonical household location; `zone_id` is a versioned child of one area and binding generation.
- [ ] Register a capability only with schema, policy, retention, auth, UI, audit, backup/restore, failure behavior, and negative tests.
- [ ] Reject unknown major versions, fields, enum values, payload variants, signature domains, capabilities, and action types.

### 7.2 Identity, subjects, and memory

- [ ] Keep Reachy identity interaction-gated; store no unknown/passive candidate or re-encounter history.
- [ ] Treat biometrics as personalization evidence only; use confirmations/passkeys for authority.
- [ ] Enforce subject/audience/guardian/consent checks before search, decryption, and serialization.
- [ ] Ensure system administration never reveals a `subject_private` or `guardian_child` body to an otherwise unauthorized owner.

### 7.3 Privacy and truthful state

- [ ] Implement one canonical Privacy Shield generation transaction and the complete cross-phase effect registry.
- [ ] Report authority revocation, stop requested, acknowledged, physically verified, and unverified as different states.
- [ ] Keep independent Reolink recording, manual/HA device control, media, and already completed egress/write facts visible.
- [ ] Make every stop, delete, export, retention, remote, and physical-state statement testable and source-attributed.

### 7.4 Authorization and external effects

- [ ] Server-prepare every mutation from current resource/policy/principal/generation facts.
- [ ] Bind exact principal slots and enforce owner/guardian distinctness where required.
- [ ] Atomically commit authorization/audit/outbox before external I/O.
- [ ] Reconcile unknown effects; never invent success or retry under a new key automatically.
- [ ] Return complete, ordered per-target results for multi-target operations.

### 7.5 UI and accessibility

- [ ] Deliver owner console, Reachy interaction, subject/guardian one-use ceremony, and shared-display surfaces as separate trust zones.
- [ ] Ship the UI work assigned to each phase before that phase's family gate; do not postpone it as dashboard polish.
- [ ] Maintain English/Hindi/mixed-script, keyboard, VoiceOver, 200% zoom, 320-pixel width, high contrast, reduced motion, and safe degraded-state fixtures.
- [ ] Keep absent routes out of navigation, direct URL, API, prepared-action issuance, feature registration, and client bundles.

### 7.6 Security, evidence, and operations

- [ ] Map every control to `T01`–`T25`, a test/evidence command, owner, expiry, and revalidation trigger.
- [ ] Use synthetic fixtures in Git/CI; keep household evidence encrypted and ignored outside source.
- [ ] Pin dependencies/models/actions, generate SBOM/licence records, scan secrets/private data, and quarantine drift.
- [ ] Prove backup, restore, update, rollback, uninstall, device retirement, owner lockout, and incident containment before relying on them.
- [ ] Freeze/sign/real-target-qualify the exact final Phase 6 candidate before opening the maintenance epoch. Evidence logging may begin after 60 steady-state days; evaluate the rolling three-month median for promotion only after at least 90 steady-state days and three complete monthly buckets, then hold ordinary full-system owner maintenance to at most eight hours/month; three consecutive months above eight freeze expansion. Candidate/authority drift resets the whole window, and only evidence/acceptance/publication writes are allowed after the freeze.

## 8. Procurement gates

| Purchase | Earliest decision point | Required evidence before order |
|---|---|---|
| Home Assistant Green | Phase 2 P2-0 | Exact SKU/current landed quote, warranty/return, network placement, backup plan |
| UPS | Phase 2 P2-0 | Exact hardware revision, current NUT driver/signalling, complete connected load, estimated runtime, shutdown/recovery plan, landed quote |
| ZBT-2 | Only after MZHUB one-light bridge failure and owner approval | Failure record, exact MOES identifiers, one-light migration/rollback plan, stock/landed quote |
| Reolink Home Hub/NVR | Phase 3 source-path decision only | Exact E1 compatibility, local/WAN-off behavior, channel/view/licence count, retention/export/recovery limits |
| NAS/VMS | After Phase 3 seven-day campaign | Measured 3/4/6/8 stream capacity, drives/RAID/backup/UPS/licences, one-/three-/five-year TCO, owner maintenance, recovery and exit plan |
| Room endpoint fleet | After Phase 4 one-room bakeoff | Exact winner's acoustic/privacy/mute/indicator/update/recovery/maintenance evidence; buy one room at a time |
| TV/CEC/IR adapter | After exact-TV probe | One capability gap, desired-state operation, separate observation evidence, manual override and no-hostile-loop proof |
| Local inference host | After Phase 5 named-task benchmark | Quality, bilingual safety, latency, throughput, privacy, watts/noise/thermal, maintenance, three-year TCO, rollback; entry 1.5–3.5k, preferred 24 GB 3.5–7.5k, 48 GB+ 8–18k SGD are separate planning tiers |
| Raspbot modifications | Phase 5 safety gate | Physical e-stop, barriers/sensors/power, exact owned-kit inventory, stopping-distance/geofence plan |
| Apple Developer membership | Phase 6 release path | Decision to produce a notarized public macOS beta and current local price/tax/account eligibility |
| Clean Mac qualification access | Before Phase 6 Tasks 27/31 | Owner-approved borrow/rent/lab/purchase route, exact Intel and current Apple-Silicon model/OS targets, isolation/wipe/restore terms, availability window, landed quote and explicit spend cap; hosted Macs may run synthetic package tests only, and no spend is authorized by this plan |

No marketplace listing, foreign list price, brand label, protocol logo, or model-loading demonstration is procurement approval.

## 9. Gate ledger

| Gate | Meaning | May be waived? |
|---|---|---|
| POC receipt | Disposable physical voice-loop learning decision | No; a failed POC changes the approach rather than being relabelled family-ready |
| `FB0` | First Phase 1 family-private-beta eligibility | No mandatory safety/privacy/auth/child/recovery requirement may be waived |
| `P1R0` | Phase 1-only release-candidate preview | No; optional feature absence follows Phase 1's explicit list and negative tests |
| `P1R1` | Optional Phase 1-only Apache preview publication | No; never represents whole-program readiness |
| P2-0…P2-7/P2-F | Home commissioning and conditional direct-Zigbee gates | Only P2-F is conditional; it needs a separate owner decision |
| P3-0…P3-6 / conditional P3-F | Camera/storage/alerts/presence gates | Conditional cameras/views/sensors and the migration pilot may remain absent; privacy, audio, storage truth and access gates cannot |
| P4-0…P4-7 | Endpoint/media/display/TV/room rollout gates | The selected common-room endpoint is mandatory; exact TV, additional/private-room, and second-slot capabilities may remain at their weaker declared state; no false enforcement |
| P5-0…P5-9 | Inference/corpus/desktop/perception/robot gates | Appliance, D4, robot floor, or LILYGO routes may be absent as explicitly defined; no weaker execution/motion path |
| P6-0…P6-5 | Remote/plugin/recovery/release hardening | Optional remote scopes may be absent; mandatory plugin, recovery, security and release gates cannot |
| `C0` | Frozen whole-program release candidate on one commit/version/feature manifest | Never; any tracked or evidence-policy change invalidates it |
| `C1` | Separate manual public beta approval over unchanged C0 artifacts/evidence | Never; CI cannot infer it and publication remains manual |

## 10. Evidence packet and repository discipline

Every task-level commit must include or update:

- failing test observed first and passing narrow/affected suites afterward;
- strict schema and generated artifact diff when a contract changes;
- threat/control/test reference for a trust-boundary change;
- synthetic fixtures only;
- rollback/quarantine behavior for migration or external effect;
- exact file staging and reviewed `git diff --cached --check`;
- no secrets, household names, media, memories, local identifiers, absolute private paths, device credentials, or production evidence in Git.

Every phase promotion packet binds:

```text
phase_and_gate
candidate_version_and_commit
feature_manifest_digest
schema_policy_migration_versions
hardware_firmware_configuration_commitments
dataset_corpus_and_seed_versions
test_commands_and_start_end_times
metrics_and_thresholds
fault_recovery_and_negative_reachability_results
privacy_security_content_scan_results
known_limitations_and_absent_features
artifact_hashes
operator_reviewer_and_expiry
owner_approval_or_rejection_commitment
```

The packet contains commitments and aggregate evidence, not raw family content. Real local evidence is stored under an ignored owner-only evidence root with encryption, retention, and deletion policy.

## 11. Program completion definition

The six-phase design-and-plan package is implementation-ready when:

- [x] all nine normative specifications are internally consistent and pass link, fence, Mermaid, terminology, and whitespace checks;
- [x] each phase has a detailed file/test/interface/task execution plan and the UI has a cross-phase execution plan;
- [x] the master plan maps every locked household decision, purchase gate, dependency, release gate, and deferment;
- [x] no passive identity; no Reolink identity/audio or raw-media edge to an LLM, VLM, memory, Home Assistant, or cloud; and no unrestricted HA/model/desktop/plugin/robot authority, public inbound route, or silent optional fallback remains;
- [x] the canonical area/zone, memory visibility, Privacy Shield, alert delivery, selected-frame, desktop egress/D3/D4, remote/plugin, recovery, maintenance, and C0/C1 contracts agree across documents;
- [x] a clean repository audit identifies the exact document set and no unintended user file is changed;
- [x] the final handoff clearly distinguishes completed design work from code/hardware implementation still to execute.

The product itself is complete only after C1 is explicitly approved and the immutable artifact is manually published. Writing or accepting this roadmap is not C0, C1, a hardware purchase, a family-use authorization, or a release.
