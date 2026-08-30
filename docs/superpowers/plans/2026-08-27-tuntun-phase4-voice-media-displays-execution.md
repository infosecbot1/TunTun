# Tuntun Phase 4 Whole-Home Voice, Media, and Displays Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver one safe household conversation across Reachy and evidence-winning room speech endpoints, deterministic entitled media, a signed closed teaching renderer, exact-unit television qualification for the household's Samsung Neo LED 49-inch and TCL 42-inch televisions, and real screen-time enforcement only at the strength each exact television proves.

**Architecture:** Extend the Phase 1 Mac modular monolith and the Phase 2 topology/signed Home Assistant boundary. Every room endpoint performs wake/VAD locally, obtains a single-use capture lease before post-wake audio leaves, and has locally authoritative physical mute, capture indication, and stop. The Mac remains the sole identity, policy, consent, memory, budget, conversation, media, teaching, and screen-time authority. Home Assistant and optionally Music Assistant receive only signed closed media/TV operations. A paired local HDMI/browser agent accepts only signed, audience-bound components and volatile hashed assets. Both televisions begin as `UNCOMMISSIONED`; exact-unit identity plus successful manual-HDMI evidence may promote one unit to `DISPLAY_ONLY_MANUAL`, while every control or enforcement route still requires its own exact control and observation evidence.

**Tech Stack:** Python 3.12, `asyncio`, Pydantic v2, SQLAlchemy 2/Alembic over SQLCipher, FastAPI, paired mTLS WebSockets, Ed25519 endpoint events, the existing Secure Enclave-backed P-256 Home Assistant signer, RFC 8785/JCS, JSON Schema 2020-12; local wake/VAD and audio backends behind ports; Home Assistant Core custom-integration APIs; optional official Music Assistant integration; a Linux kiosk agent with Chromium, React 19/TypeScript/Vite, strict CSP and hash-checked assets; optional libCEC and bounded IR adapters behind exact TV ports; pytest, pytest-asyncio, Hypothesis, Ruff, strict mypy, Vitest, Testing Library, Playwright, axe, packet/content scanners, and owner-gated hardware/fault/elapsed campaigns.

**Normative design:** [Phase 4 Whole-Home Voice, Media, and Displays](../specs/2026-08-27-tuntun-phase4-voice-media-displays-design.md), [Program A–H](../specs/2026-08-27-tuntun-program-architecture-a-h.md), [Program I–S](../specs/2026-08-27-tuntun-program-assurance-delivery-i-s.md), [Six-Phase UI/UX](../specs/2026-08-27-tuntun-six-phase-ui-ux-design.md), and [Six-Phase Master Roadmap](./2026-08-27-tuntun-six-phase-master-roadmap.md).

## Authority and Upstream Reconciliation

1. The Phase 4 design controls Phase 4 behavior, gates, thresholds, and conditional absence. Program A–H controls shared composition/contracts; Program I–S controls repository, assurance, evidence, operations, procurement, and maintenance; UI/UX controls truthful read models, ceremonies, accessibility, and feature registration.
2. Phase 4 household activation requires the accepted Phase 1 `FB0` services it consumes and a stable accepted Phase 2 signed bridge, topology registry, transaction/outbox lifecycle, subject/guardian ceremonies, and screen-time simulator. Phase-1-only `P1R0/P1R1` and Phase 3 camera features are not Phase 4 entry gates.
3. The canonical core migration graph is frozen and linear: Phase 2 owns `0009_home_topology_policy` (whose exact parent is `0008_prepared_mutations`) through `0012`; Phase 3 owns `0013` through `0015`; and this plan owns `0016` through `0019`. Every revision has the one exact predecessor frozen in Task 03. There is no fork, merge revision, orphan, alternative parent, or extra core head. Independent feature schemas, including experimental search and the recorder catalog, use their own version table/graph and are never a parent of or merged into the core graph.
4. Register `whole_home_single_session_v1`, `home_reversible_media_v1`, `child_guarded_media_v1`, `guarded_teaching_display_v1`, and `screen_time_real_adapter_v1` before the matching production feature is registered. These are exact amendments, not broad role grants.
5. `area_id` is the sole room/location identifier in every contract, migration, API, fixture, generated client, renderer manifest, audit commitment, and adapter binding, and every authoritative use pairs it with exact current `area_generation`. A `zone_id` is an optional stable versioned child of exactly one `(area_id, area_generation)`. There is no `room_id` field, table, alias, mapping, compatibility adapter, or migration.
6. Extend the existing Phase 1 edge/session and Phase 2 Home Assistant/screen-time interfaces. Do not create a second identity engine, policy engine, subject ceremony, topology registry, action lifecycle, or screen-time state machine.
7. The browser, room endpoint, display agent, television, Home Assistant, and Music Assistant are untrusted presenters/adapters. None can construct actor authority, guardian consent, memory audience, an action binding, or an enforcement decision.
8. If any plan instruction appears less restrictive than a normative design, stop and reconcile the design, contract, policy corpus, migration, generated client, feature manifest, tests, and documentation together before implementing.

## Global Constraints

1. `household_conversation_slots` is compiled to exactly `1` for this release. There is no setting, environment variable, owner API, UI control, or adapter command that raises it. Attempts to configure or admit `2` fail before capture/provider work. A future two-slot feature needs the separate Phase 4 Section 22.8 design gate and a new reviewed contract.
2. Every Phase 4 wire and persistence model uses exact `(area_id, area_generation)` authority and no other room identifier. Property tests scan source, schemas, migrations, generated clients, fixtures, OpenAPI, SQL, UI bundles, and configuration for forbidden `room_id`, missing generations, and naked single-column area foreign keys.
3. Local wake and VAD run on each commissioned speech endpoint. Only bounded three-to-five-second pre-roll exists, in endpoint RAM. No always-on room audio, pre-wake sample, losing candidate buffer, voice embedding, fine-grained acoustic feature, or ambient transcript reaches the Mac, Home Assistant, Music Assistant, a television, a provider, or durable storage.
4. A metadata-only wake claim precedes arbitration. Post-wake audio cannot leave until a current signed `CaptureLeaseV1` binds the winning claim, endpoint, `area_id`, turn, session epoch, privacy/capability generations, duration/byte quota, and the one household slot.
5. Endpoint capture retains the Phase 1 maximum of 90 seconds or 8 MiB per turn, whichever closes first. Bounded queues cancel on congestion rather than accumulating late audio or replies.
6. A real physical microphone cutoff is locally authoritative. Software and voice cannot unmute it. A visible capture indicator is active before the first leased frame may leave and remains truthful through the complete egress interval. Mute/indicator/supervisor uncertainty closes the network audio path and sets `ERROR_SAFE`.
7. Local stop/privacy remains available without Mac, Home Assistant, or WAN. Recognized stop/privacy blocks new media egress and stops local Tuntun playback at P95 no more than 250 ms. Privacy Shield revokes all room capture leases and signed display fetch handles through the shared canonical privacy generation.
8. Phase 4 reuses the exact Phase 2 `AreaV1`/`CanonicalLocationRefV1` authority and its closed area classes: `common`, `adult_private`, `child_private`, and `prohibited`. Guest/Designated Guest is an orthogonal actor/session restriction and never a location class. No speech endpoint can be commissioned in `prohibited`. Adult-private enablement requires every recorded adult occupant's current subject consent. Child-private enablement requires owner configuration and a distinct current-primary-guardian exact approval for the same child/area/endpoint/policy generations. Every area-bearing authority binds both `area_id` and current `area_generation`; reclassification revokes in-flight authority and restart/restore may not resurrect an old generation.
9. Physical mute/revoke/stop reductions are immediate and need no authentication. Enabling, recommissioning, provider enrollment, group definition, TV adapter promotion, Strict mode, or any privacy expansion uses the exact Phase 1 prepared-action/passkey and, where applicable, subject/guardian ceremony.
10. A room, endpoint, television, media player, camera/presence fact, device alias, voice match, or biometric match never authorizes an action or proves identity. Identity conflict or downgrade applies Guest/restrictive policy and cancels or revalidates private speech, media, and display work.
11. Duplicate-wake arbitration uses the Phase 4 stable order and exact 350 ms decision/1.5-second correlation windows. Losers get cancellation, clear all candidate RAM, and expose only a neutral busy light/tone with no person, question, room, answer, or memory information.
12. Reply defaults to the endpoint holding the current capture lease. Private speech, authentication prompts, child disclosures, security facts, or memory-derived answers never route to a media group, television speaker, guessed nearby endpoint, or whole-home broadcast.
13. Handoff is explicit, exact-target, single-use, and expires within 30 seconds. The target requires a new wake and re-evaluates identity/room/guardian policy. It transfers no authentication, action approval, prior private content, or child authority. Passive acoustic “follow me” is absent.
14. The existing per-turn language tracker follows English, Hindi, or natural Hinglish and may change after a clear within-conversation switch. Endpoint/area does not select identity or language. Fixed local prompts are human-reviewed in English/Hindi and common Hinglish.
15. Speech capture/reply and music playback are separate capabilities. One enclosure may implement both only when each independent gate passes. Speech never falls back to a player group and music never becomes the response route for a private turn.
16. Media sources are limited to owner-entitled local files, reviewed licensed services/radio, and approved local player protocols. No DRM bypass, ripping, scraping, torrenting, account sharing, ad removal, arbitrary URL/URI/path, redirect, Home Assistant service, Music Assistant admin call, shell, or queue language reaches an LLM-facing or browser-facing interface.
17. Provider enrollment and reusable credentials stay in the owner-controlled Home Assistant/Music Assistant surface. Tuntun stores only an opaque provider binding/capability digest and a 90-day entitlement-review generation. No HA/MA general token or provider secret reaches Tuntun, a room node, display, prompt, log, browser, backup, evidence packet, or repository.
18. Initial media commands are the exact Phase 4 closed set. `toggle`, relative volume, account switching, dynamic “all speakers,” free-form queue mutation, and caller-supplied target/provider IDs are rejected.
19. A new catalog item/provider, material volume change, transfer, immutable group, persistent queue/routine, account, or policy change requires the specified stronger confirmation/passkey. Child playback requires exact owner-configured and distinct-guardian-approved area/player/provider/content/volume/hour generations. Unknown/explicit content denies unless the fresh single-use handle resolves to a durable keyed item/playlist identity commitment in the active signed rule.
20. A player must expose fresh trustworthy state and safe absolute starting volume before Tuntun may start it. Results remain `VERIFIED_PLAYING`, `ACCEPTED_UNVERIFIED`, `PARTIAL`, `FAILED`, or `UNKNOWN`. No automatic provider/protocol fallback or blind retry is permitted.
21. Music Assistant is optional. Until its exact Home Assistant application/integration, Green resource/backup, one provider/player, ports/discovery, history/scrobbling, upgrade/rollback, credential revocation, and failure gates pass, every Tuntun MA package registration, configuration route, API route, UI control, and runtime call is absent.
22. A teaching display is a paired local browser/HDMI agent using pinned TLS, a locked kiosk origin, and a signed closed manifest. It receives no general HTML, CSS, JavaScript, SVG script, iframe, URL, path, form, download, WebRTC, browser permission, prompt, memory store, credential, shell, camera, or microphone.
23. Display text/assets pass identity audience, child safety, DLP, provenance, type, size, decompression, hash, session, policy, binding, generation, and expiry validation. A child lesson performs zero live web request. A TV receives pixels and bounded desired-state control only; it never receives family memory or supplies identity.
24. Teaching session assets and the end-card learning summary are RAM-only. The broad topic/duration/completion summary expires at the earliest of five minutes, dismissal, Privacy Shield, or session end policy and is absent from SQL, audit, history, backups, corpus, logs, screenshots, and browser persistence. A durable note can be created only as a separately minimized Phase 1 child-memory proposal awaiting exact current-guardian approval.
25. Both `tv_samsung_neoled_49` (“Samsung Neo LED 49-inch”) and `tv_tcl_42` (“TCL 42-inch”) begin with generic lifecycle `candidate` and imported screen-time power state `UNCOMMISSIONED`; the UI offers only manual display and makes no Tuntun capability claim. `DISPLAY_ONLY_MANUAL` is a later explicit evidence result, not the inventory default. Their household descriptions prove no model, OS, firmware, API, CEC, IR, Wake-on-LAN, app, source, power, volume, or observation capability.
26. Native local API, HDMI-CEC, and bounded IR are probed and qualified independently per exact TV. Runtime uses one owner-selected primary control binding per capability; a failure returns `FAILED` or `UNKNOWN` and never sprays another protocol. Manual remote/buttons/input selection always remain available.
27. TV operations are desired-state only: power, exact commissioned input, safe absolute volume, desired mute, and individually registered key/app operations only where evidence passes. Mains-cut smart-plug enforcement, toggles, arbitrary keys/macros/codes/apps/URIs/services/entities, and relay control through an observation sensor are absent.
28. Observation strength is explicit. Command acknowledgement, optimistic mirror, same-adapter observation, out-of-band observation, and proved independence are not interchangeable. A firmware/OS/integration/pairing/network/HDMI/CEC/IR/observation change increments capability generation, invalidates pending work, and degrades the TV.
29. The Phase 2 screen-time ledger, warning, grace, extension, authority, viewer uncertainty, clock reconciliation, and retention remain unchanged. Phase 4 adds only a real adapter. Cooperative requires proven control plus trustworthy observation; Strict additionally requires independently evidenced observation/common-mode failure proof.
30. One enforcement generation permits one initial control attempt and at most one qualifying re-enforcement within two minutes. Failure, uncertainty, restart, network loss, observation loss, or manual remote/button/source/renderer-stop intervention ends automatic contention as `MANUAL_OVERRIDE` or `UNKNOWN`. No third or delayed surprise command is reachable.
31. A child is debited/enforced only inside a currently authorized child session with current identity/session evidence. TV power, HDMI input, area, programme, application, renderer, or camera/presence state never identifies a viewer or establishes educational content.
32. LAN-only and outbound-cloud-only boundaries remain. No port forwarding, public bind/domain, DMZ, UPnP/NAT-PMP/PCP, WAN admin, remote renderer, cloud smart-speaker endpoint, or direct HA/MA/TV/debug service is enabled.
33. Every endpoint/adapter has per-device keys, pinned version/hash/licence/SBOM, bounded heartbeat/replay/rate/queue state, update/rollback, quarantine on drift, and retirement/revocation. Room nodes and display agents initiate outbound paired connections and have no unauthenticated production listener.
34. Ordinary tests perform no hardware, paid provider, Keychain/Secure Enclave, HA/MA, TV, CEC/IR, LAN, or WAN I/O. Owner-gated commands require explicit environment flags and write pseudonymized content-safe results only under ignored `var/evidence/phase4/`.
35. Project branch coverage remains at least 85%; policy, consent, admission, lease, signature, media/TV action, renderer validation, screen-time, privacy, and audit-critical modules remain at least 95%.
36. Every task follows red → green → refactor → affected suite → static/security checks → exact-path review → commit. This document supplies future commit commands; writing this plan does not execute them.
37. Conditional absence is tested across source registration, install/package manifest, configuration, environment parsing, feature manifest, API/OpenAPI, prepared-action issuance, navigation/direct URL, client bundle, IPC/network routes, and runtime dispatch. A disabled UI control is insufficient.
38. Phase 4 records ordinary owner time by subsystem against its one-to-two-hour monthly planning allocation, but that allocation is not a Phase 4 promotion trigger. All ordinary time contributes to the single Phase 6 full-system gate: logging may begin after 60 steady-state days, but promotion evaluation requires at least 90 steady-state days and three complete monthly buckets. At that point, the rolling three-month median is at most eight hours/month; three consecutive months above eight hours freeze optional expansion and trigger simplification or retirement. Initial commissioning, incidents, repairs, hardware replacement, major migrations, and scheduled quarterly drills are measured separately.
39. Phase 4 imports Phase 2's canonical externally signed, pre-issued `SignedFeatureManifestRolloverChainV1`, `FeatureManifestLeaseSupervisor`, per-admission `FeatureAuthorityLease`, and `FeatureAuthorityCampaignEvidenceV1`/generated schema unchanged; it creates no signer, renewal service, fallback manifest, local evidence alias, or grace extension. Before either Task 16 seven-day endpoint bakeoff, a Task 35 per-area seven-day rollout, the Task 36 seven-day family soak, or any Phase 4 maintenance interval later counted by Phase 6, the complete ordered chain must bind one frozen candidate and exact registrations, cover the planned wall-time interval, and install each valid successor before its predecessor expires. The counted clock starts only after a current index-zero controlled-restart activation receipt exact-matches the live candidate/composition. Purchased and DIY endpoint candidates always use separate externally signed chains when their hardware/configuration candidate commitments differ; every later area/endpoint/binding generation and steady-state maintenance generation likewise gets a candidate-specific owner-only chain. No chain or evidence is copied, merged, widened, or reused after a code, package, registration, route, policy/configuration, hardware, firmware, placement, consent, or generation change. Every admission and background-work iteration checks both `valid_from <= trusted_now < expires_at` and `monotonic_now < monotonic_deadline_ns`. A missing/stale initial activation receipt, nonzero initial index, missing, extra, late, reordered, widened, rollback, signature-invalid, candidate-drifted, or expired current/next authority, either exact deadline equality, wall rollback, stale composition, or a missing/duplicated/substituted rollover/restart receipt closes capture, media, display, television, screen-time, and owner-route work before preparation or I/O, invalidates the affected campaign, and enters controlled whole-composition recovery. Closed-authority maintenance observations remain truthful but cannot count toward day 60, day 90, or a promotion bucket; eligibility restarts under the recovered steady-state generation with a newly signed chain. Gate evidence binds the chain ID/digest, ordered signed-envelope and transition/restart-receipt digests, admission-sample-log digest, exact interval, and every canonical literal-zero counter; the shared downstream harness proves zero post-fault admission/preparation/provider-call/trigger/effect delta and semantic rejection.
40. Tasks 05, 22, 27, 32, 35, and 36 are the serialized Phase 4 owner-ingress composition checkpoints. After all route/container/UI bytes owned by that checkpoint are final, each checkpoint rebuilds the locked `tuntun-owner-ingress` wheel, refreshes and externally re-signs the same canonical `ops/services/phase3-owner-ingress.v1.json` against the exact wheel and `ops/routes/owner-ingress-routes.v1.json` digests, and reruns installed dispatch, negative reachability, takeover, start/health, deliberate crash/restart, wrong-account/config denial, update, rollback, preserve/destroy uninstall, cleanup, and reinstall. The predecessor row/receipt must fail the current verifier and remains usable only with its complete matching rollback set. Intermediate route-owning Tasks 04, 17, and 23 cannot start physical or promotion evidence until the next listed checkpoint has completed this protocol. Every checkpoint commits its route sources, route manifest, refreshed service row, and lifecycle-test updates together; any real campaign begins only after that commit, a clean-worktree check, installed-candidate verification, and a newly externally signed exact-candidate chain.

## Definition of Done for Every Task

- The named failing test is run before implementation and fails for the intended missing behavior.
- Narrow and affected Python suites pass with Ruff format/check and strict mypy. Touched web/renderer code passes lint, TypeScript, Vitest, Playwright/axe, and production build.
- Contract changes regenerate Python/JSON/OpenAPI/TypeScript artifacts and diff clean; positive/adversarial fixtures reject unknown major versions, fields, variants, enums, duplicate keys, over-bounds values, and forbidden location aliases.
- Persistence changes include an encrypted pre-migration backup, forward upgrade, downgrade-or-isolated-restore plan, restart/corruption tests, table/index/trigger ownership assertions, and a scan proving no audio/transcript/display/summary/provider secret body column.
- External effects inject failure before and after every durable transition, perform no network/device I/O while the canonical writer lock is held, and reconcile uncertainty without blind retry.
- Hardware changes bind exact pseudonymous SKU/revision/firmware/configuration/placement and evidence digest, prove physical fallback, and document quarantine/rollback before promotion.
- Logs, browser/cache/storage, renderer filesystem, crash reports, backups, packet captures, evidence, and source artifacts pass the appropriate synthetic forbidden-sentinel scan.
- A conditional path either passes its positive gate or proves negative reachability at package/config/API/UI/network/runtime levels.
- `git status --short` contains only task-owned paths; only exact paths are staged; `git diff --cached --name-only`, `git diff --cached --check`, and `git diff --cached` are reviewed before the task commit.

## Phase Entry, Promotion, and Exit Gates

| Gate | Entry requirement | Positive exit | Disabled/failed exit |
|---|---|---|---|
| P4-E0 | Accepted Phase 1 `FB0` and stable accepted Phase 2 contracts/bridge/screen-time simulator | Five amendments, strict contracts, migrations, fakes/corpora, schema generation, feature absence, and no-`room_id` checks pass | All Phase 4 packages/routes/features remain absent |
| P4-0 | P4-E0 software baseline | Exact room/TV/player/display inventory, privacy/consent model, simulators, signed domains, and negative routes pass; no purchase is called compatible | Production mutations/capture/rendering remain absent |
| P4-1 | P4-0 plus approved exact landed quotes/return terms | Purchased and DIY candidates each complete identical common-area acoustic/privacy/safety/update/maintenance campaigns; winner is recorded | No fleet purchase or private-room deployment; both may be rejected |
| P4-2 | P4-1 winner plus current common-room approval | Reachy plus one winner prove one-slot arbitration, leased capture, same-room reply, language, handoff, physical controls, privacy, and seven-day use | Reachy remains the sole endpoint; room-node route unregistered |
| P4-3 | P4-0 and Phase 2 signed bridge | One entitled provider plus one exact player pass catalog/actions/volume/state/reboot/WAN/revocation; optional MA passes separately | Media disabled or narrow HA single-player path retained; MA route absent |
| P4-4 | P4-0 and accepted teaching/guardian policy | One paired renderer passes closed manifest, child safety, no-network, volatile cache, clear, manual HDMI, and accessibility gates | Voice-only teaching remains; renderer/display routes absent |
| P4-5 | P4-4 and exact physical TV inventory | Each Samsung/TCL unit is promoted only to its proved `DISPLAY_ONLY_MANUAL`, `OBSERVE_ONLY`, `COOPERATIVE_ELIGIBLE`, or `STRICT_ELIGIBLE` state | That unit remains manual/degraded; unsupported action/adapter routes absent |
| P4-6 | P4-5 per eligible TV plus unchanged Phase 2 corpus | Real adapter passes 720 oracle cases, 10,000 sequences, observation, manual override, restart, and two-attempt ceiling | Advisory only; no enforcement mutation route |
| P4-7 | P4-2 plus per-room owner/occupant/guardian approval | One room at a time passes placement, mute access, quiet hours, privacy/routing, seven-day soak, and maintenance review | Private/additional room remains uncommissioned; prohibited rooms always absent |

## Planned Repository Map

```text
packages/contracts/src/tuntun_contracts/whole_home/
├── __init__.py
├── base.py                    # strict Phase 4 canonical bytes and bounds
├── speech.py                  # endpoint registration, wake, lease, frame, handoff
├── media.py                   # provider/player/group/catalog/action/observation
├── display.py                 # closed teaching components, manifest, receipts
├── television.py              # exact desired-state TV action and observation
├── ui.py                      # Phase 4 owner/display read models
└── ports.py                   # speech/media/display/TV protocols
packages/contracts/src/tuntun_contracts/home/
├── topology.py                # extend endpoint capability kinds; still area_id only
└── screen_time.py             # consume canonical EnforcementIntentV1/TV screen-time DTOs unchanged
packages/contracts/src/tuntun_contracts/ui.py
schemas/whole-home/v1/
├── speech-endpoint-v1.schema.json
├── wake-lease-v1.schema.json
├── media-v1.schema.json
├── teaching-manifest-v1.schema.json
├── television-v1.schema.json
└── ui-v1.schema.json
fixtures/synthetic/whole-home/
├── contracts/
├── policy-corpus-v1.jsonl
├── duplicate-wake-corpus-v1.jsonl
├── routing-corpus-v1.jsonl
├── media-adversarial-corpus-v1.jsonl
├── display-manifest-corpus-v1.jsonl
├── television-fault-corpus-v1.jsonl
├── language-room-corpus-v1.jsonl
├── endpoint-candidates-v1.json
├── players-providers-v1.json
├── televisions-v1.json
└── fault-matrix-v1.json
fixtures/synthetic/features/phase4-whole-home-manifest-v1.json
fixtures/synthetic/ui/phase4/

packages/policy/pyproject.toml
packages/policy/src/tuntun_policy/
├── __init__.py
├── registry.py
└── corpora.py

apps/core/src/tuntun_core/domain/whole_home/
├── rooms.py
├── speech.py
├── media.py
├── display.py
└── television.py
apps/core/src/tuntun_core/services/whole_home/
├── endpoint_registry.py
├── room_policy.py
├── endpoint_gateway.py
├── wake_arbiter.py
├── conversation_admission.py
├── reply_router.py
├── handoff.py
├── media_catalog.py
├── media_policy.py
├── media_coordinator.py
├── media_reconciliation.py
├── display_sessions.py
├── teaching_policy.py
├── teaching_content.py
├── ephemeral_learning_summary.py
├── tv_registry.py
├── tv_coordinator.py
├── tv_eligibility.py
├── screen_time_adapter.py
├── privacy_effects.py
├── restore.py
└── health.py
apps/core/src/tuntun_core/adapters/room_endpoints/
├── reachy.py
└── websocket.py
apps/core/src/tuntun_core/adapters/media/
├── home_assistant.py
└── music_assistant.py
apps/core/src/tuntun_core/adapters/television/
├── home_assistant.py
├── cec.py
└── ir.py
apps/core/src/tuntun_core/api/routes/
├── whole_home.py
├── media.py
├── teaching.py
└── televisions.py
apps/core/src/tuntun_core/api/phase4_dtos.py
apps/core/migrations/versions/
├── 0016_whole_home_endpoints.py
├── 0017_media_and_display.py
├── 0018_television_capabilities.py
└── 0019_screen_time_real_adapter.py

apps/room-node/
├── pyproject.toml
├── src/tuntun_room_node/
│   ├── __init__.py
│   ├── main.py
│   ├── agent.py
│   ├── config.py
│   ├── pairing.py
│   ├── protocol.py
│   ├── audio.py
│   ├── wake.py
│   ├── vad.py
│   ├── ram_buffer.py
│   ├── safety_supervisor.py
│   ├── physical_mute.py
│   ├── indicator.py
│   ├── stop.py
│   ├── playback.py
│   ├── health.py
│   └── update.py
└── tests/
apps/display-agent/
├── pyproject.toml
├── src/tuntun_display_agent/
│   ├── __init__.py
│   ├── agent.py
│   ├── config.py
│   ├── pairing.py
│   ├── manifest.py
│   ├── assets.py
│   ├── clear.py
│   ├── hdmi.py
│   ├── health.py
│   └── kiosk.py
├── package.json
├── src-ui/
│   ├── main.tsx
│   ├── manifest-validator.tsx
│   ├── expiry-supervisor.tsx
│   ├── components/
│   └── neutral-screen.tsx
└── tests/

integrations/home-assistant/custom_components/tuntun_bridge/
├── media.py
├── media_schema.py
├── television.py
├── television_schema.py
├── observations.py
└── store.py                    # additive receipt migrations
integrations/music-assistant/
├── README.md
├── pyproject.toml
├── src/tuntun_ma_adapter/
│   ├── __init__.py
│   ├── capabilities.py
│   ├── catalog.py
│   └── playback.py
└── tests/

apps/admin/src/features/media-learning/
├── index.ts
├── room-nodes.tsx
├── media.tsx
├── teaching.tsx
├── televisions.tsx
└── phase4-health.tsx
apps/admin/src/routes/
├── media-learning-rooms.tsx
├── media-learning-media.tsx
├── media-learning-teaching.tsx
└── media-learning-televisions.tsx
apps/admin/src/features/home/screen-time.tsx
apps/admin/src/features/privacy/plane-cards.tsx
apps/admin/src/app/feature-registry.ts

packages/testing/src/tuntun_testing/whole_home/
├── fake_clock.py
├── fake_endpoint.py
├── fake_player.py
├── fake_renderer.py
├── fake_tv.py
├── fault_points.py
└── scenario.py
scripts/phase4/
├── generate_schemas.py
├── build_corpora.py
├── check_ephemeral_summary_imports.py
├── inventory.py
├── pair_endpoint.py
├── probe_purchased_endpoint.py
├── probe_diy_endpoint.py
├── run_endpoint_bakeoff.py
├── qualify_media.py
├── qualify_music_assistant.py
├── pair_display.py
├── probe_television.py
├── qualify_tv_adapter.py
├── run_screen_time_adapter.py
├── run_fault_matrix.py
├── verify_network_exposure.py
├── verify_update_rollback.py
├── measure_maintenance.py
├── run_acceptance.py
└── verify_acceptance.py
ops/room-node/
├── tuntun-room-node.service
├── room-node.toml.example
├── firewall.example.nft
└── tmpfiles.conf
ops/display-agent/
├── tuntun-display-agent.service
├── display-agent.toml.example
├── kiosk-policy.json
└── firewall.example.nft
ops/services/
├── phase4-room-node.v1.json
└── phase4-display-agent.v1.json
ops/whole-home/
docs/operations/phase4-*.md
docs/privacy/phase4-*.md
docs/procurement/phase4-*.md
docs/evidence/phase4-*.schema.json
tests/{unit,contract,property,integration,security,privacy,ui,fault,performance,hardware,acceptance}/whole_home/
```

## Frozen Contract and Port Baseline

The strict public models are frozen Pydantic models with `extra="forbid"`, immutable nested collections, NFC text, aware six-fraction UTC timestamps, bounded sizes, and explicit `schema_version`. Signed objects use their own signature domain; a signature is never valid across domains. Media actions, immutable group manifests, finalized child rules, and Core-created media deadline terminals use `tuntun-media-v1`/`media_action`, `tuntun-media-group-v1`/`media_group_manifest`, `tuntun-child-media-rule-v1`/`child_media_rule`, and `tuntun-media-dispatch-unknown-terminal-v1`/`core_media_dispatch_unknown_terminal`, respectively. Teaching manifests, renderer receipts, and display-clear requests use three distinct domains—`tuntun-display-manifest-v1`, `tuntun-display-receipt-v1`, and `tuntun-display-clear-request-v1`—and verifier key purpose is also exact. Television actions, adapter dispatch receipts, adapter observations, and Core-created television deadline terminals likewise use four distinct domains and key purposes: `tuntun-tv-action-v1`/`tv_action`, `tuntun-tv-dispatch-receipt-v1`/`tv_dispatch_receipt`, `tuntun-tv-observation-v1`/`tv_observation`, and `tuntun-tv-dispatch-unknown-terminal-v1`/`core_tv_dispatch_unknown_terminal`. Even if one physical key is paired for multiple roles, purpose-constrained verification prevents cross-type replay.

The shared `whole_home.base` timing helper preserves each independently auditable media/television predicate, including the deliberately redundant 30-second post-authorization cap:

```python
# packages/contracts/src/tuntun_contracts/whole_home/base.py
from collections.abc import Mapping
from typing import Any

from tuntun_contracts.base import ContractModel,canonical_mapping_bytes

class WholeHomeContract(ContractModel):
    model_config=ConfigDict(
        extra="forbid",frozen=True,strict=True,validate_assignment=True,
        str_strip_whitespace=True,
    )

def canonical_json_bytes(value:Mapping[str,Any]) -> bytes:
    """Compatibility name; the Phase 1 encoder is the sole implementation."""
    return canonical_mapping_bytes(value)

def canonical_whole_home_bytes(value:WholeHomeContract) -> bytes:
    return canonical_mapping_bytes(value.model_dump(mode="python"))

def media_tv_authority_window_failures(
    authorized_at: AwareDatetime,
    issued_at: AwareDatetime,
    expires_at: AwareDatetime,
) -> frozenset[str]:
    failures: set[str] = set()
    if not authorized_at <= issued_at <= authorized_at + timedelta(seconds=5):
        failures.add("signing_after_authorization_bound")
    if not issued_at < expires_at <= issued_at + timedelta(seconds=5):
        failures.add("post_issue_expiry_bound")
    if expires_at > authorized_at + timedelta(seconds=30):
        failures.add("post_authorization_expiry_bound")
    return frozenset(failures)
```

### Speech contracts

- `SpeechEndpointRegistrationV1`: `endpoint_id`, exact `(area_id, area_generation)`, room class, exact pseudonymous hardware/firmware/wake/VAD/audio/mute/indicator/stop evidence digests, protocol version, privacy/capability generations, and lifecycle state.
- `WakeClaimV1`: metadata-only Phase 4 claim fields; no audio, embedding, fine acoustic vector, subject, identity, or memory field.
- `CaptureLeaseV1`: claim/endpoint/area/turn/slot/session-epoch/privacy/capability/format/quota/time binding and Mac signature.
- `SpeechFrameV1`: lease/stream/turn, monotonic sequence/time, exact format/duration/length, and bytes under remaining lease quota.
- `WakeArbitrationV1`: canonical complete claim-to-endpoint members with signed-claim digests and session/privacy/capability generations, one exact eligible winner when present, the exactly derived loser endpoint tuple, decision reason/windows, and one cancellation generation.
- `EndpointHealthV1` and `PhysicalSafetyReceiptV1`: separate hardware mute, local wake, leased egress, indicator, stop, queues, clock, model hashes, thermal, and error-safe facts.
- `HandoffTokenV1`: current endpoint/area, exact target endpoint/area, source turn, privacy/policy generations, 30-second maximum expiry, single-use commitment, and no auth grant.

```python
from tuntun_contracts.home.topology import AreaV1, CanonicalLocationRefV1
from tuntun_contracts.memory import MemoryAudience

class SpeechAudioFormatV1(WholeHomeContract):
    sample_rate_hz: Literal[16_000, 24_000, 48_000]
    channels: Literal[1]
    sample_format: Literal["pcm_s16le"]
    frame_duration_ms: Literal[10, 20, 30, 40, 50, 100, 200]

class SpeechEndpointRegistrationV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    endpoint_id: StableEndpointId
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    room_class: Literal["common", "adult_private", "child_private", "prohibited"]
    hardware_sku_and_revision: Annotated[str, Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_.: /()-]+$")]
    firmware_version: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.+-]+$")]
    firmware_digest: Sha256Digest
    endpoint_protocol_version: Literal["1.0"]
    wake_model_id: Annotated[str, Field(min_length=1, max_length=96, pattern=r"^[A-Za-z0-9_.:-]+$")]
    wake_model_version: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.+-]+$")]
    wake_model_digest: Sha256Digest
    vad_model_id: Annotated[str, Field(min_length=1, max_length=96, pattern=r"^[A-Za-z0-9_.:-]+$")]
    vad_model_version: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.+-]+$")]
    vad_model_digest: Sha256Digest
    native_capture_format: SpeechAudioFormatV1
    native_playback_format: SpeechAudioFormatV1
    pre_roll_ms: Annotated[int, Field(ge=3_000, le=5_000)]
    mute_probe_digest: Sha256Digest
    indicator_probe_digest: Sha256Digest
    stop_input_probe_digest: Sha256Digest
    acoustic_bakeoff_evidence_digest: Sha256Digest
    privacy_policy_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    lifecycle_state: Literal["candidate", "commissioned", "quarantined", "retired"]
    registered_at: AwareDatetime
    owner_authorization_commitment: HmacCommitment

    @model_validator(mode="after")
    def no_sensitive_area_commissioning(self) -> "SpeechEndpointRegistrationV1":
        if self.room_class == "prohibited" and self.lifecycle_state == "commissioned":
            raise ValueError("sensitive_area_endpoint_cannot_be_commissioned")
        return self

class CaptureLeaseV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    lease_id: UUID
    claim_id: UUID
    endpoint_id: StableEndpointId
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    conversation_id: UUID
    turn_id: UUID
    household_slot: Literal[0]
    endpoint_session_epoch: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    audio_format: SpeechAudioFormatV1
    max_duration_ms: Annotated[int, Field(ge=1, le=90_000)]
    max_bytes: Annotated[int, Field(ge=1, le=8 * 1024 * 1024)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    single_use: Literal[True]
    authorization_commitment: HmacCommitment
    core_key_id: KeyId
    core_signature: P256Signature

    @model_validator(mode="after")
    def bounded_capture_lease(self) -> "CaptureLeaseV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=90):
            raise ValueError("capture_lease_window_invalid")
        lease_ms = int((self.expires_at - self.issued_at).total_seconds() * 1_000)
        if self.max_duration_ms > lease_ms:
            raise ValueError("capture_duration_exceeds_lease_window")
        return self

class SpeechFrameV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    lease_id: UUID
    stream_id: UUID
    turn_id: UUID
    sequence: Annotated[int, Field(ge=0)]
    captured_monotonic_ns: Annotated[int, Field(ge=0)]
    audio_format: SpeechAudioFormatV1
    duration_ms: Annotated[int, Field(ge=10, le=200)]
    payload_length: Annotated[int, Field(ge=1, le=64 * 1024)]
    remaining_duration_ms_after_frame: Annotated[int, Field(ge=0, le=90_000)]
    remaining_bytes_after_frame: Annotated[int, Field(ge=0, le=8 * 1024 * 1024)]
    privacy_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    payload: SkipJsonSchema[bytes] = Field(exclude=True)

    @model_validator(mode="after")
    def exact_binary_frame(self) -> "SpeechFrameV1":
        expected_bytes = (
            self.audio_format.sample_rate_hz
            * self.audio_format.channels
            * 2
            * self.duration_ms
            // 1_000
        )
        if self.duration_ms != self.audio_format.frame_duration_ms:
            raise ValueError("speech_frame_duration_format_mismatch")
        if len(self.payload) != self.payload_length or self.payload_length != expected_bytes:
            raise ValueError("speech_frame_payload_length_mismatch")
        return self

class HandoffTokenV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    token_id: UUID
    conversation_id: UUID
    source_turn_id: UUID
    source_endpoint_id: StableEndpointId
    source_area_id: StableHomeId
    source_area_generation: Annotated[int, Field(ge=1)]
    target_endpoint_id: StableEndpointId
    target_area_id: StableHomeId
    target_area_generation: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    policy_generation: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    single_use: Literal[True]
    token_commitment: HmacCommitment
    core_key_id: KeyId
    core_signature: P256Signature

    @model_validator(mode="after")
    def bounded_exact_handoff(self) -> "HandoffTokenV1":
        if self.source_endpoint_id == self.target_endpoint_id:
            raise ValueError("handoff_target_must_change_endpoint")
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=30):
            raise ValueError("handoff_token_window_invalid")
        return self

class PhysicalSafetyReceiptV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    receipt_id: UUID
    control_id: UUID
    endpoint_id: StableEndpointId
    control: Literal["block_capture", "privacy_indicator", "stop_playback", "enter_error_safe"]
    outcome: Literal["acknowledged", "physically_verified", "unverified"]
    requested_at: AwareDatetime
    acknowledged_at: AwareDatetime | None
    physically_verified_at: AwareDatetime | None
    capability_generation: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    hardware_evidence_commitment: HmacCommitment
    signing_key_id: KeyId
    signature: P256Signature

    @model_validator(mode="after")
    def exact_outcome_evidence(self) -> "PhysicalSafetyReceiptV1":
        if self.outcome == "physically_verified":
            if self.acknowledged_at is None or self.physically_verified_at is None:
                raise ValueError("physical verification timestamps required")
        elif self.outcome == "acknowledged":
            if self.acknowledged_at is None or self.physically_verified_at is not None:
                raise ValueError("acknowledged receipt evidence mismatch")
        elif self.acknowledged_at is not None or self.physically_verified_at is not None:
            raise ValueError("unverified receipt cannot claim endpoint evidence")
        if self.acknowledged_at is not None and self.acknowledged_at < self.requested_at:
            raise ValueError("acknowledgement precedes request")
        if self.physically_verified_at is not None:
            if self.acknowledged_at is None or self.physically_verified_at < self.acknowledged_at:
                raise ValueError("physical verification precedes acknowledgement")
        return self

class SafetyTransportFailureV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    receipt_id: UUID
    control_id: UUID
    endpoint_id: StableEndpointId
    control: Literal["block_capture", "privacy_indicator", "stop_playback", "enter_error_safe"]
    outcome: Literal["unverified"]
    reason_code: Literal["timeout", "disconnected", "transport_error", "invalid_endpoint_receipt"]
    observed_at: AwareDatetime
    capability_generation: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    core_signing_key_id: KeyId
    core_signature: P256Signature
```

The endpoint signs only an actual domain-separated receipt as `tuntun-physical-safety-receipt-v1`. When no valid endpoint receipt can exist—timeout, disconnect, transport error, or invalid response—the core instead signs a `SafetyTransportFailureV1` under the distinct domain `tuntun-safety-transport-failure-v1`. That transport receipt can assert only `unverified`; it can never be parsed as endpoint acknowledgement or physical verification.

```python
class EndpointHealthV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    endpoint_id: StableEndpointId
    hardware_mute: Literal["muted", "unmuted", "unverified"]
    local_wake: Literal["listening", "disabled", "failed"]
    leased_audio_egress: Literal["idle", "active", "blocked", "unverified"]
    privacy_indicator: Literal["off", "capture_visible", "mute_visible", "failed"]
    physical_stop_input: Literal["ready", "triggered", "unverified"]
    playback: Literal["idle", "playing", "stopped", "failed", "unverified"]
    capture_queue_frames: Annotated[int, Field(ge=0, le=500)]
    playback_queue_frames: Annotated[int, Field(ge=0, le=500)]
    clock_skew_ms: Annotated[int, Field(ge=-2_000, le=2_000)]
    wake_model_digest: Sha256Digest
    vad_model_digest: Sha256Digest
    thermal_state: Literal["nominal", "warm", "hot", "shutdown", "unknown"]
    privacy_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    observed_at: AwareDatetime
    valid_until: AwareDatetime
    endpoint_key_id: KeyId
    endpoint_signature: P256Signature

    @model_validator(mode="after")
    def bounded_endpoint_health(self) -> "EndpointHealthV1":
        if not self.observed_at < self.valid_until <= self.observed_at + timedelta(seconds=5):
            raise ValueError("endpoint_health_window_invalid")
        if self.hardware_mute == "muted" and self.leased_audio_egress == "active":
            raise ValueError("muted_endpoint_claims_audio_egress")
        return self

class WakeClaimV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    claim_id: UUID
    endpoint_id: StableEndpointId
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    endpoint_session_epoch: Annotated[int, Field(ge=1)]
    wake_model_id: Annotated[str, Field(min_length=1, max_length=96)]
    wake_model_digest: Sha256Digest
    wake_confidence_bucket: Annotated[int, Field(ge=0, le=4)]
    snr_bucket: Annotated[int, Field(ge=0, le=4)]
    first_vad_monotonic_ns: Annotated[int, Field(ge=0)]
    mute_state: Literal["unmuted", "muted", "unverified"]
    indicator_ready: bool
    local_sequence: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    endpoint_key_id: KeyId
    endpoint_signature: P256Signature

    @model_validator(mode="after")
    def bounded_wake_claim(self) -> "WakeClaimV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=2):
            raise ValueError("wake_claim_window_invalid")
        return self

class WakeArbitrationMemberV1(WholeHomeContract):
    claim_id: UUID
    endpoint_id: StableEndpointId
    endpoint_session_epoch: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    claim_digest: Sha256Digest
    eligible: bool
    ineligibility_reason: Literal[
        "muted", "indicator_not_ready", "unhealthy", "expired", "late",
        "replayed", "invalid_signature", "stale_generation", "wrong_model",
    ] | None

    @model_validator(mode="after")
    def exact_eligibility_shape(self) -> "WakeArbitrationMemberV1":
        if self.eligible == (self.ineligibility_reason is not None):
            raise ValueError("wake_member_eligibility_shape_invalid")
        return self

class WakeArbitrationV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    arbitration_id: UUID
    state: Literal["winner", "busy", "no_eligible_claim"]
    considered_members: Annotated[tuple[WakeArbitrationMemberV1, ...], Field(min_length=1, max_length=16)]
    winner_claim_id: UUID | None
    winner_endpoint_id: StableEndpointId | None
    loser_endpoint_ids: Annotated[tuple[StableEndpointId, ...], Field(max_length=16)]
    decision_reason: Literal["continuation", "confidence_hysteresis", "gateway_order", "stable_id_tiebreak", "slot_busy", "all_ineligible"]
    decision_window_opened_at: AwareDatetime
    decided_at: AwareDatetime
    acoustic_correlation_valid_until: AwareDatetime
    cancellation_generation: Annotated[int, Field(ge=1)]
    decision_commitment: HmacCommitment

    @model_validator(mode="after")
    def coherent_arbitration(self) -> "WakeArbitrationV1":
        if (self.winner_claim_id is None) != (self.winner_endpoint_id is None):
            raise ValueError("wake_arbitration_partial_winner")
        has_winner = self.winner_claim_id is not None and self.winner_endpoint_id is not None
        if (self.state == "winner") != has_winner:
            raise ValueError("wake_arbitration_winner_shape_invalid")
        expected_reason_class = {
            "winner": {"continuation", "confidence_hysteresis", "gateway_order", "stable_id_tiebreak"},
            "busy": {"slot_busy"},
            "no_eligible_claim": {"all_ineligible"},
        }
        if self.decision_reason not in expected_reason_class[self.state]:
            raise ValueError("wake_arbitration_reason_invalid")
        ordered_members = tuple(sorted(
            self.considered_members,
            key=lambda member: (str(member.endpoint_id), str(member.claim_id)),
        ))
        if self.considered_members != ordered_members:
            raise ValueError("wake_members_not_canonical_order")
        claim_ids = tuple(member.claim_id for member in self.considered_members)
        endpoint_ids = tuple(member.endpoint_id for member in self.considered_members)
        if len(set(claim_ids)) != len(claim_ids) or len(set(endpoint_ids)) != len(endpoint_ids):
            raise ValueError("duplicate_wake_arbitration_member")
        winner_members = tuple(
            member for member in self.considered_members
            if member.claim_id == self.winner_claim_id
            and member.endpoint_id == self.winner_endpoint_id
        )
        if has_winner and (len(winner_members) != 1 or not winner_members[0].eligible):
            raise ValueError("wake_winner_not_exact_eligible_member")
        if self.state == "no_eligible_claim" and any(
            member.eligible for member in self.considered_members
        ):
            raise ValueError("no_eligible_wake_contains_eligible_member")
        expected_losers = tuple(
            member.endpoint_id for member in self.considered_members
            if member.endpoint_id != self.winner_endpoint_id
        )
        if self.loser_endpoint_ids != expected_losers:
            raise ValueError("wake_loser_set_not_exact")
        if not self.decision_window_opened_at <= self.decided_at <= self.decision_window_opened_at + timedelta(milliseconds=350):
            raise ValueError("wake_decision_window_invalid")
        if not self.decided_at < self.acoustic_correlation_valid_until <= self.decision_window_opened_at + timedelta(seconds=1.5):
            raise ValueError("wake_correlation_window_invalid")
        return self

CancellationReason = Literal[
    "privacy_shield", "owner_stop", "barge_in", "hardware_mute", "disconnect",
    "timeout", "newer_turn", "policy_change", "error_safe",
]

class EndpointControlV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    control_id: UUID
    endpoint_id: StableEndpointId
    control: Literal["block_capture", "privacy_indicator", "stop_playback", "enter_error_safe"]
    desired_state: Literal["blocked", "enabled", "stopped", "error_safe"]
    privacy_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    authorization_commitment: HmacCommitment
    core_key_id: KeyId
    core_signature: P256Signature

    @model_validator(mode="after")
    def exact_control_shape(self) -> "EndpointControlV1":
        expected = {
            "block_capture": {"blocked"},
            "privacy_indicator": {"enabled"},
            "stop_playback": {"stopped"},
            "enter_error_safe": {"error_safe"},
        }
        if self.desired_state not in expected[self.control]:
            raise ValueError("endpoint_control_state_invalid")
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=2):
            raise ValueError("endpoint_control_window_invalid")
        return self

class SpeechPlaybackFrameV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    playback_id: UUID
    request_id: UUID
    conversation_id: UUID
    turn_id: UUID
    capture_lease_id: UUID
    capture_lease_commitment: HmacCommitment
    request_commitment: HmacCommitment
    reply_decision_commitment: HmacCommitment
    cancellation_generation: Annotated[int, Field(ge=1)]
    endpoint_id: StableEndpointId
    sequence: Annotated[int, Field(ge=0)]
    byte_offset: Annotated[int, Field(ge=0, le=16 * 1024 * 1024)]
    sample_rate_hz: Literal[16_000, 24_000, 48_000]
    channels: Literal[1]
    sample_format: Literal["pcm_s16le"]
    duration_ms: Annotated[int, Field(ge=10, le=200)]
    byte_count: Annotated[int, Field(ge=1, le=64 * 1024)]
    frame_bytes: bytes
    final_frame: bool
    final_stream_byte_count: Annotated[int | None, Field(ge=1, le=16 * 1024 * 1024)]
    frame_commitment: HmacCommitment
    privacy_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def exact_playback_frame_length(self) -> "SpeechPlaybackFrameV1":
        expected_bytes = (
            self.sample_rate_hz
            * self.channels
            * 2  # signed 16-bit PCM
            * self.duration_ms
            // 1_000
        )
        if len(self.frame_bytes) != self.byte_count or self.byte_count != expected_bytes:
            raise ValueError("speech_playback_frame_length_mismatch")
        if self.sequence == 0 and self.byte_offset != 0:
            raise ValueError("first_playback_frame_offset_not_zero")
        if self.final_frame != (self.final_stream_byte_count is not None):
            raise ValueError("playback_final_frame_total_shape_invalid")
        if (
            self.final_frame
            and self.final_stream_byte_count != self.byte_offset + self.byte_count
        ):
            raise ValueError("playback_final_frame_total_invalid")
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=2):
            raise ValueError("speech_playback_frame_window_invalid")
        return self

class PlaybackReceiptV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    playback_id: UUID
    request_id: UUID
    conversation_id: UUID
    turn_id: UUID
    capture_lease_id: UUID
    capture_lease_commitment: HmacCommitment
    request_commitment: HmacCommitment
    reply_decision_commitment: HmacCommitment
    cancellation_generation: Annotated[int, Field(ge=1)]
    endpoint_id: StableEndpointId
    outcome: Literal["completed", "stopped", "partial", "unverified", "error_safe"]
    last_sequence: Annotated[int, Field(ge=0)] | None
    bytes_accepted: Annotated[int, Field(ge=0)]
    terminal_frame_commitment: HmacCommitment | None
    expected_final_sequence: Annotated[int | None, Field(ge=0)]
    expected_total_bytes: Annotated[int | None, Field(ge=1, le=16 * 1024 * 1024)]
    started_at: AwareDatetime | None
    completed_at: AwareDatetime
    privacy_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    evidence_commitment: HmacCommitment
    endpoint_key_id: KeyId
    endpoint_signature: P256Signature

    @model_validator(mode="after")
    def coherent_playback_outcome(self) -> "PlaybackReceiptV1":
        if self.started_at is not None and self.completed_at < self.started_at:
            raise ValueError("playback_receipt_time_invalid")
        has_progress = self.started_at is not None
        if has_progress != (self.last_sequence is not None) or has_progress != (self.bytes_accepted > 0):
            raise ValueError("playback_receipt_progress_evidence_incomplete")
        if self.outcome in {"completed", "stopped", "partial"} and not has_progress:
            raise ValueError("playback_outcome_without_start")
        terminal_evidence = (
            self.terminal_frame_commitment,
            self.expected_final_sequence,
            self.expected_total_bytes,
        )
        if any(value is not None for value in terminal_evidence) != all(
            value is not None for value in terminal_evidence
        ):
            raise ValueError("playback_terminal_evidence_incomplete")
        has_terminal_evidence = all(value is not None for value in terminal_evidence)
        if has_terminal_evidence and not has_progress:
            raise ValueError("playback_terminal_evidence_without_progress")
        if has_terminal_evidence and (
            self.last_sequence > self.expected_final_sequence
            or self.bytes_accepted > self.expected_total_bytes
        ):
            raise ValueError("playback_progress_exceeds_committed_terminal")
        if self.outcome == "completed" and not (
            has_terminal_evidence
            and self.last_sequence == self.expected_final_sequence
            and self.bytes_accepted == self.expected_total_bytes
        ):
            raise ValueError("playback_completed_without_full_terminal_frame")
        return self

class ConversationAdmissionV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    conversation_id: UUID
    turn_id: UUID
    winning_claim_id: UUID
    endpoint_id: StableEndpointId
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    household_slot: Literal[0]
    identity_mode: Literal["identified", "guest", "uncertain"]
    privacy_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    provider_reservation_commitment: HmacCommitment
    admitted_at: AwareDatetime
    expires_at: AwareDatetime
    admission_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_admission_window(self) -> "ConversationAdmissionV1":
        if not self.admitted_at < self.expires_at <= self.admitted_at + timedelta(seconds=90):
            raise ValueError("conversation_admission_window_invalid")
        return self

class ConversationCancellationReceiptV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    conversation_id: UUID
    reason: CancellationReason
    state: Literal["cancelled", "already_cancelled", "error_safe"]
    cancellation_generation: Annotated[int, Field(ge=1)]
    observed_at: AwareDatetime
    receipt_commitment: HmacCommitment

class ReplyRoutingRequestV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    request_id: UUID
    conversation_id: UUID
    turn_id: UUID
    capture_lease_id: UUID
    capture_lease_commitment: HmacCommitment
    cancellation_generation: Annotated[int, Field(ge=1)]
    source_endpoint_id: StableEndpointId
    source_area_id: StableHomeId
    source_area_generation: Annotated[int, Field(ge=1)]
    identity_mode: Literal["identified", "guest", "uncertain"]
    profile_class: Literal["owner", "adult", "k2", "n1", "guest"]
    subject_id: UUID | None
    profile_version: Annotated[int | None, Field(ge=1)]
    memory_audience: MemoryAudience | None
    audience_policy_generation: Annotated[int | None, Field(ge=1)]
    presentation_policy: Literal["personalized", "generic_guest_public"]
    guardian_generation: Annotated[int | None, Field(ge=1)]
    child_safe_household_approval_grant_id: UUID | None
    sensitivity: Literal["public", "household", "private", "restricted"]
    policy_generation: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    request_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_reply_request(self) -> "ReplyRoutingRequestV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=2):
            raise ValueError("reply_route_request_window_invalid")
        restrictive = self.identity_mode in {"guest", "uncertain"} or self.profile_class == "guest"
        if restrictive:
            if (
                self.profile_class != "guest"
                or self.identity_mode not in {"guest", "uncertain"}
                or self.subject_id is not None
                or self.profile_version is not None
                or self.memory_audience is not None
                or self.audience_policy_generation is not None
                or self.presentation_policy != "generic_guest_public"
                or self.guardian_generation is not None
                or self.child_safe_household_approval_grant_id is not None
            ):
                raise ValueError("guest_reply_memory_forbidden")
            return self
        if (
            self.identity_mode != "identified"
            or self.subject_id is None
            or self.profile_version is None
            or self.memory_audience is None
            or self.audience_policy_generation is None
            or self.presentation_policy != "personalized"
        ):
            raise ValueError("identified_reply_audience_required")
        child = self.profile_class in {"k2", "n1"}
        if child:
            if self.memory_audience not in {MemoryAudience.GUARDIAN_CHILD, MemoryAudience.HOUSEHOLD_ALL}:
                raise ValueError("child_reply_memory_audience_invalid")
            if self.guardian_generation is None:
                raise ValueError("child_reply_guardian_generation_required")
            if (
                self.memory_audience == MemoryAudience.HOUSEHOLD_ALL
            ) != (self.child_safe_household_approval_grant_id is not None):
                raise ValueError("child_household_reply_approval_invalid")
        else:
            if self.memory_audience not in {
                MemoryAudience.SUBJECT_PRIVATE,
                MemoryAudience.HOUSEHOLD_ADULTS,
                MemoryAudience.HOUSEHOLD_ALL,
            }:
                raise ValueError("adult_reply_memory_audience_invalid")
            if self.guardian_generation is not None or self.child_safe_household_approval_grant_id is not None:
                raise ValueError("non_child_reply_guardian_fields_forbidden")
        return self

class ReplyRouteDecisionV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    request_id: UUID
    conversation_id: UUID
    turn_id: UUID
    capture_lease_id: UUID
    capture_lease_commitment: HmacCommitment
    request_commitment: HmacCommitment
    cancellation_generation: Annotated[int, Field(ge=1)]
    request_expires_at: AwareDatetime
    decision: Literal["speak_at_source", "no_speech"]
    endpoint_id: StableEndpointId | None
    area_id: StableHomeId | None
    area_generation: Annotated[int | None, Field(ge=1)]
    maximum_volume_percent: Annotated[int, Field(ge=0, le=100)] | None
    reason_code: SafeReasonCode
    privacy_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    decided_at: AwareDatetime
    valid_until: AwareDatetime
    decision_commitment: HmacCommitment

    @model_validator(mode="after")
    def coherent_reply_decision(self) -> "ReplyRouteDecisionV1":
        speaking = self.decision == "speak_at_source"
        routed_fields = (
            self.endpoint_id, self.area_id, self.area_generation, self.maximum_volume_percent,
        )
        if (speaking and not all(value is not None for value in routed_fields)) or (
            not speaking and any(value is not None for value in routed_fields)
        ):
            raise ValueError("reply_route_decision_shape_invalid")
        if not self.decided_at < self.valid_until <= self.decided_at + timedelta(seconds=2):
            raise ValueError("reply_route_decision_window_invalid")
        if self.valid_until > self.request_expires_at:
            raise ValueError("reply_route_decision_outlives_request")
        return self
```

### Media contracts

- `MediaProviderBindingV1` and `ProviderEntitlementReviewV1` contain opaque binding, adapter/version/source, account class, region, entitlement/expiry, egress/history disclosures, content classification capability, and no credential.
- `MediaPlayerBindingV1` binds one player to exact `(area_id, area_generation)`, exact provider/protocol, capabilities, state freshness, absolute-volume semantics, manual fallback, and generation.
- `MediaGroupManifestV1` is owner-passkey-approved, immutable, and canonically enumerates each player's exact `(area_id, area_generation)`, player binding/capability generation, and per-member maximum volume; it never contains a selector/wildcard.
- `AuthorizedCatalogQueryV1` is an internal ephemeral bounded query whose canonical provider-authority tuple contains binding ID plus provider/adapter/entitlement generations. `OpaqueCatalogHandleV1` repeats that exact tuple and binds account/item/classification/result generation plus short expiry without a playable URL.
- `AuthorizedMediaRequestV1` and `MediaAuthorizationDecisionV1` remain inside Tuntun and bind exact actor/target/action/policy/generation/assurance facts. `SignedMediaEnvelopeV1` is the minimized outbound closed action described by the Phase 4 design and uses signature domain `tuntun-media-v1`.
- Adapter `MediaDispatchReceiptV1` has no `unknown` variant. `MediaDispatchControlRecordV1` is the closed internal adapter-receipt/Core-terminal union; Core `MediaDispatchUnknownTerminalV1` alone represents unresolved attempt-one work at the fixed reconciliation deadline and uses its own domain/purpose. No network, adapter, API, DTO, or caller-facing constructor accepts that Core branch or either Core timestamp; the mapper reloads it only from the immutable terminal repository. Its `terminal_id` is verifier-recomputed UUIDv5 over the fixed media-terminal namespace plus operation, envelope digest, and target-transition-set commitment. The finalizer sets `materialized_at` from its writer-owned trusted post-lock sample; verification requires `terminal_at <= materialized_at <= trusted_verification_time`.
- `PlayerObservationV1`, `MediaTargetOperationResultV1`, and `MediaOperationResultV1` preserve source/freshness/generation, manifest order, per-target evidence, action-specific verified states, and an exactly derived verified/unverified/partial/failure/unknown aggregate.

```python
from tuntun_contracts.home.channel import ControllerEpoch
from tuntun_contracts.whole_home.base import media_tv_authority_window_failures

class MediaProviderBindingV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    provider_binding_id: StableEndpointId
    adapter_id: StableEndpointId
    adapter_version: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.+-]+$")]
    adapter_digest: Sha256Digest
    source_class: Literal["owner_local_files", "reviewed_licensed_service", "reviewed_radio"]
    account_class: Literal["owner_entitled", "household_entitled", "child_rule_entitled"]
    region_code: Annotated[str, Field(min_length=2, max_length=2, pattern=r"^[A-Z]{2}$")]
    entitlement_state: Literal["current", "expired", "revoked", "unknown"]
    provider_egress: Literal["none", "provider_only", "unknown"]
    provider_history: Literal["disabled", "provider_managed", "unknown"]
    content_classification_capability: Literal["verified", "limited", "none", "unknown"]
    provider_generation: Annotated[int, Field(ge=1)]
    adapter_generation: Annotated[int, Field(ge=1)]
    entitlement_generation: Annotated[int, Field(ge=1)]
    current_review_id: UUID
    current_review_evidence_digest: Sha256Digest
    lifecycle_state: Literal["candidate", "enabled", "quarantined", "disabled", "retired"]
    binding_commitment: HmacCommitment

    @model_validator(mode="after")
    def enabled_requires_current_entitlement(self) -> "MediaProviderBindingV1":
        if self.lifecycle_state == "enabled" and self.entitlement_state != "current":
            raise ValueError("enabled_media_provider_not_currently_entitled")
        return self

class ProviderEntitlementReviewV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    review_id: UUID
    provider_binding_id: StableEndpointId
    provider_generation: Annotated[int, Field(ge=1)]
    adapter_generation: Annotated[int, Field(ge=1)]
    entitlement_generation: Annotated[int, Field(ge=1)]
    decision: Literal["eligible", "ineligible", "unknown"]
    source_class: Literal["owner_local_files", "reviewed_licensed_service", "reviewed_radio"]
    account_class: Literal["owner_entitled", "household_entitled", "child_rule_entitled"]
    provider_egress: Literal["none", "provider_only", "unknown"]
    provider_history: Literal["disabled", "provider_managed", "unknown"]
    content_classification_capability: Literal["verified", "limited", "none", "unknown"]
    reviewed_at: AwareDatetime
    expires_at: AwareDatetime
    evidence_digest: Sha256Digest
    owner_authorization_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_entitlement_review(self) -> "ProviderEntitlementReviewV1":
        if not self.reviewed_at < self.expires_at <= self.reviewed_at + timedelta(days=90):
            raise ValueError("provider_entitlement_review_window_invalid")
        return self

class ProviderAuthorityRefV1(WholeHomeContract):
    provider_binding_id: StableEndpointId
    provider_generation: Annotated[int, Field(ge=1)]
    adapter_generation: Annotated[int, Field(ge=1)]
    entitlement_generation: Annotated[int, Field(ge=1)]

MediaActionType = Literal[
    "media.play_catalog_item.v1", "media.pause.v1", "media.resume.v1", "media.stop.v1",
    "media.set_volume_absolute.v1", "media.seek_absolute.v1", "media.play_group_manifest.v1",
]

class MediaPlayerBindingV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    player_id: StableEndpointId
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    provider_binding_ids: Annotated[tuple[StableEndpointId, ...], Field(min_length=1, max_length=8)]
    protocol: Literal["home_assistant_native", "music_assistant_via_home_assistant", "reviewed_local_player"]
    available_actions: Annotated[tuple[MediaActionType, ...], Field(min_length=1, max_length=7)]
    state_freshness_seconds: Annotated[int, Field(ge=1, le=5)]
    absolute_volume_semantics: Literal["reliable", "bounded", "unavailable"]
    safe_start_volume_percent: Annotated[int, Field(ge=0, le=100)] | None
    manual_fallback_available: bool
    topology_generation: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    lifecycle_state: Literal["candidate", "enabled", "quarantined", "disabled", "retired"]
    capability_digest: Sha256Digest

    @model_validator(mode="after")
    def coherent_player_binding(self) -> "MediaPlayerBindingV1":
        if len(set(self.provider_binding_ids)) != len(self.provider_binding_ids):
            raise ValueError("duplicate_player_provider_binding")
        if len(set(self.available_actions)) != len(self.available_actions):
            raise ValueError("duplicate_player_action")
        has_safe_volume = self.safe_start_volume_percent is not None
        if (self.absolute_volume_semantics != "unavailable") != has_safe_volume:
            raise ValueError("player_absolute_volume_shape_invalid")
        return self

class MediaGroupMemberV1(WholeHomeContract):
    member_index: Annotated[int, Field(ge=0, le=7)]
    player_id: StableEndpointId
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    player_binding_generation: Annotated[int, Field(ge=1)]
    player_capability_generation: Annotated[int, Field(ge=1)]
    maximum_volume_percent: Annotated[int, Field(ge=0, le=100)]

class MediaGroupManifestV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    group_manifest_id: StableEndpointId
    manifest_version: Annotated[int, Field(ge=1)]
    members: Annotated[tuple[MediaGroupMemberV1, ...], Field(min_length=1, max_length=8)]
    topology_generation: Annotated[int, Field(ge=1)]
    created_at: AwareDatetime
    owner_passkey_authorization_commitment: HmacCommitment
    manifest_digest: Sha256Digest
    key_id: KeyId
    signature: P256Signature

    @model_validator(mode="after")
    def exact_immutable_group(self) -> "MediaGroupManifestV1":
        ids = tuple(member.player_id for member in self.members)
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate_media_group_player")
        if tuple(member.member_index for member in self.members) != tuple(range(len(self.members))):
            raise ValueError("media_group_members_not_canonically_ordered")
        if self.manifest_digest != media_group_authority_digest(self):
            raise ValueError("media_group_manifest_digest_mismatch")
        return self

def media_group_authority_digest(manifest: MediaGroupManifestV1) -> Sha256Digest:
    unsigned = manifest.model_dump(
        mode="python",
        exclude={"manifest_digest", "key_id", "signature"},
    )
    return sha256(
        b"tuntun-media-group-v1\x00" + canonical_json_bytes(unsigned)
    ).hexdigest()

def canonical_media_group_signature_bytes(manifest: MediaGroupManifestV1) -> bytes:
    return canonical_json_bytes({
        "signature_domain": "tuntun-media-group-v1",
        "manifest_digest": manifest.manifest_digest,
    })

class ChildMediaRulePlayerV1(WholeHomeContract):
    player_id: StableEndpointId
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    player_binding_generation: Annotated[int, Field(ge=1)]
    player_capability_generation: Annotated[int, Field(ge=1)]
    maximum_volume_percent: Annotated[int, Field(ge=0, le=100)]

class ChildMediaTimeWindowV1(WholeHomeContract):
    weekday: Annotated[int, Field(ge=0, le=6)]
    # Canonical half-open minute-of-day interval [start, end). 1440 is the
    # exclusive end-of-day sentinel, so [1439, 1440) includes 23:59.
    start_local_minute: Annotated[int, Field(ge=0, le=1_439)]
    end_local_minute: Annotated[int, Field(ge=1, le=1_440)]

    @model_validator(mode="after")
    def no_implicit_overnight_window(self) -> "ChildMediaTimeWindowV1":
        if self.start_local_minute >= self.end_local_minute:
            raise ValueError("child_media_window_must_not_wrap_midnight")
        return self

class ChildMediaRuleProposalV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    rule_id: UUID
    rule_version: Annotated[int, Field(ge=1)]
    child_subject_id: UUID
    child_profile_id: UUID
    child_profile_generation: Annotated[int, Field(ge=1)]
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    players: Annotated[tuple[ChildMediaRulePlayerV1, ...], Field(min_length=1, max_length=8)]
    provider_authorities: Annotated[tuple[ProviderAuthorityRefV1, ...], Field(min_length=1, max_length=8)]
    permitted_content_classes: Annotated[
        tuple[Literal["child_safe", "non_explicit"], ...], Field(max_length=2),
    ]
    approved_item_identity_commitments: Annotated[tuple[HmacCommitment, ...], Field(max_length=32)]
    maximum_volume_percent: Annotated[int, Field(ge=0, le=100)]
    timezone_id: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_+./-]+$")]
    timezone_data_version: Annotated[str, Field(min_length=1, max_length=64)]
    timezone_data_digest: Sha256Digest
    timezone_policy: Literal["instant_to_local_window.v1"]
    allowed_windows: Annotated[tuple[ChildMediaTimeWindowV1, ...], Field(min_length=1, max_length=14)]
    policy_version: Annotated[int, Field(ge=1)]
    expected_lifecycle_generation: Annotated[int, Field(ge=1)]
    owner_prepared_mutation_id: UUID
    owner_subject_id: UUID
    owner_authorization_commitment: HmacCommitment
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    proposal_digest: Sha256Digest

    @model_validator(mode="after")
    def exact_child_media_rule_proposal(self) -> "ChildMediaRuleProposalV1":
        validate_child_media_rule_scope(self)
        if self.proposal_digest != child_media_rule_proposal_digest(self):
            raise ValueError("child_media_rule_proposal_digest_mismatch")
        return self

class ChildMediaRuleApprovalV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    approval_id: UUID
    rule_id: UUID
    proposed_rule_version: Annotated[int, Field(ge=1)]
    proposal_digest: Sha256Digest
    owner_subject_id: UUID
    owner_prepared_mutation_id: UUID
    owner_authorization_commitment: HmacCommitment
    guardian_subject_id: UUID
    guardian_generation: Annotated[int, Field(ge=1)]
    guardian_approval_commitment: HmacCommitment
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    single_use: Literal[True]

    @model_validator(mode="after")
    def exact_distinct_guardian_approval(self) -> "ChildMediaRuleApprovalV1":
        if self.owner_subject_id == self.guardian_subject_id:
            raise ValueError("child_media_owner_and_guardian_must_be_distinct")
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(minutes=5):
            raise ValueError("child_media_guardian_approval_window_invalid")
        return self

class ChildMediaRuleV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    rule_id: UUID
    rule_version: Annotated[int, Field(ge=1)]
    child_subject_id: UUID
    child_profile_id: UUID
    child_profile_generation: Annotated[int, Field(ge=1)]
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    players: Annotated[tuple[ChildMediaRulePlayerV1, ...], Field(min_length=1, max_length=8)]
    provider_authorities: Annotated[tuple[ProviderAuthorityRefV1, ...], Field(min_length=1, max_length=8)]
    permitted_content_classes: Annotated[
        tuple[Literal["child_safe", "non_explicit"], ...], Field(max_length=2),
    ]
    approved_item_identity_commitments: Annotated[tuple[HmacCommitment, ...], Field(max_length=32)]
    maximum_volume_percent: Annotated[int, Field(ge=0, le=100)]
    timezone_id: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_+./-]+$")]
    timezone_data_version: Annotated[str, Field(min_length=1, max_length=64)]
    timezone_data_digest: Sha256Digest
    timezone_policy: Literal["instant_to_local_window.v1"]
    allowed_windows: Annotated[tuple[ChildMediaTimeWindowV1, ...], Field(min_length=1, max_length=14)]
    policy_version: Annotated[int, Field(ge=1)]
    expected_lifecycle_generation: Annotated[int, Field(ge=1)]
    owner_prepared_mutation_id: UUID
    owner_subject_id: UUID
    owner_authorization_commitment: HmacCommitment
    guardian_approval_id: UUID
    guardian_subject_id: UUID
    guardian_generation: Annotated[int, Field(ge=1)]
    guardian_approval_commitment: HmacCommitment
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    proposal_digest: Sha256Digest
    rule_digest: Sha256Digest
    key_id: KeyId
    signature: P256Signature

    @model_validator(mode="after")
    def exact_signed_child_media_rule(self) -> "ChildMediaRuleV1":
        if self.owner_subject_id == self.guardian_subject_id:
            raise ValueError("child_media_owner_and_guardian_must_be_distinct")
        validate_child_media_rule_scope(self)
        if self.proposal_digest != child_media_rule_proposal_digest(self):
            raise ValueError("child_media_rule_proposal_digest_mismatch")
        if self.rule_digest != child_media_rule_digest(self):
            raise ValueError("child_media_rule_digest_mismatch")
        return self

def validate_child_media_rule_scope(
    rule: ChildMediaRuleProposalV1 | ChildMediaRuleV1,
) -> None:
    player_ids = tuple(player.player_id for player in rule.players)
    if player_ids != tuple(sorted(player_ids)) or len(set(player_ids)) != len(player_ids):
        raise ValueError("child_media_rule_players_not_canonical")
    if any(
        (player.area_id, player.area_generation) != (rule.area_id, rule.area_generation)
        for player in rule.players
    ):
        raise ValueError("child_media_rule_player_outside_exact_area")
    provider_ids = tuple(ref.provider_binding_id for ref in rule.provider_authorities)
    if provider_ids != tuple(sorted(provider_ids)) or len(set(provider_ids)) != len(provider_ids):
        raise ValueError("child_media_rule_providers_not_canonical")
    if rule.permitted_content_classes != tuple(sorted(rule.permitted_content_classes)) or len(
        set(rule.permitted_content_classes)
    ) != len(rule.permitted_content_classes):
        raise ValueError("child_media_rule_content_classes_not_canonical")
    windows = tuple(
        (window.weekday, window.start_local_minute, window.end_local_minute)
        for window in rule.allowed_windows
    )
    if windows != tuple(sorted(windows)) or len(set(windows)) != len(windows):
        raise ValueError("child_media_rule_windows_not_canonical")
    if any(
        previous[0] == current[0] and current[1] < previous[2]
        for previous, current in zip(windows[:-1], windows[1:], strict=True)
    ):
        raise ValueError("child_media_rule_windows_overlap")
    if rule.approved_item_identity_commitments != tuple(
        sorted(rule.approved_item_identity_commitments)
    ) or len(set(rule.approved_item_identity_commitments)) != len(
        rule.approved_item_identity_commitments
    ):
        raise ValueError("child_media_rule_item_commitments_not_canonical")
    if not rule.permitted_content_classes and not rule.approved_item_identity_commitments:
        raise ValueError("child_media_rule_has_no_permitted_content")
    if any(player.maximum_volume_percent > rule.maximum_volume_percent for player in rule.players):
        raise ValueError("child_media_player_cap_exceeds_rule_cap")
    if not rule.issued_at < rule.expires_at <= rule.issued_at + timedelta(days=90):
        raise ValueError("child_media_rule_window_invalid")

_CHILD_MEDIA_RULE_PROPOSAL_FIELDS = (
    "schema_version", "rule_id", "rule_version", "child_subject_id",
    "child_profile_id", "child_profile_generation", "area_id", "area_generation",
    "players", "provider_authorities", "permitted_content_classes",
    "approved_item_identity_commitments", "maximum_volume_percent", "timezone_id",
    "timezone_data_version", "timezone_data_digest", "timezone_policy",
    "allowed_windows", "policy_version", "expected_lifecycle_generation",
    "owner_prepared_mutation_id", "owner_subject_id", "owner_authorization_commitment",
    "issued_at", "expires_at",
)

def child_media_rule_proposal_digest(
    rule: ChildMediaRuleProposalV1 | ChildMediaRuleV1,
) -> Sha256Digest:
    payload = rule.model_dump(mode="python")
    unsigned = {field: payload[field] for field in _CHILD_MEDIA_RULE_PROPOSAL_FIELDS}
    return sha256(
        b"tuntun-child-media-rule-proposal-v1\x00" + canonical_json_bytes(unsigned)
    ).hexdigest()

def child_media_rule_digest(rule: ChildMediaRuleV1) -> Sha256Digest:
    unsigned = rule.model_dump(mode="python", exclude={"rule_digest", "key_id", "signature"})
    return sha256(
        b"tuntun-child-media-rule-v1\x00" + canonical_json_bytes(unsigned)
    ).hexdigest()

def canonical_child_media_rule_signature_bytes(rule: ChildMediaRuleV1) -> bytes:
    return canonical_json_bytes({
        "signature_domain": "tuntun-child-media-rule-v1",
        "rule_digest": rule.rule_digest,
    })

class ChildMediaRuleLifecycleReceiptV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    receipt_id: UUID
    operation: Literal["activate", "replace", "revoke"]
    rule_id: UUID
    rule_version: Annotated[int, Field(ge=1)]
    rule_digest: Sha256Digest
    rule_ceremony_prepared_mutation_id: UUID
    rule_ceremony_owner_authorization_commitment: HmacCommitment
    rule_ceremony_guardian_approval_id: UUID
    rule_ceremony_guardian_approval_commitment: HmacCommitment
    revocation_request_id: UUID | None
    revocation_source: Literal[
        "owner_local_stop", "adult_local_stop", "current_guardian_local_stop",
        "privacy_shield", "policy_emergency_stop",
    ] | None
    revocation_requested_at: AwareDatetime | None
    expected_lifecycle_generation: Annotated[int, Field(ge=1)]
    observed_lifecycle_generation: Annotated[int, Field(ge=1)]
    observed_state: Literal["draft", "active", "revoked"]
    resulting_lifecycle_generation: Annotated[int, Field(ge=1)]
    outcome: Literal["APPLIED", "REJECTED"]
    resulting_state: Literal["draft", "active", "revoked"]
    processed_at: AwareDatetime
    receipt_commitment: HmacCommitment

    @model_validator(mode="after")
    def exact_child_rule_lifecycle_cas(self) -> "ChildMediaRuleLifecycleReceiptV1":
        revocation_authority = (
            self.revocation_request_id,
            self.revocation_source,
            self.revocation_requested_at,
        )
        if self.operation in {"activate", "replace"} and any(
            value is not None for value in revocation_authority
        ):
            raise ValueError("child_media_activation_carries_revocation_authority")
        if self.operation == "revoke" and not all(
            value is not None for value in revocation_authority
        ):
            raise ValueError("child_media_revocation_authority_incomplete")
        if (
            self.revocation_requested_at is not None
            and not self.revocation_requested_at
            <= self.processed_at
            <= self.revocation_requested_at + timedelta(seconds=2)
        ):
            raise ValueError("child_media_revocation_not_immediate")
        if self.outcome == "APPLIED":
            expected_transition = {
                "activate": ("draft", "active"),
                "replace": ("active", "active"),
                "revoke": ("active", "revoked"),
            }[self.operation]
            if (
                self.observed_lifecycle_generation != self.expected_lifecycle_generation
                or self.resulting_lifecycle_generation != self.expected_lifecycle_generation + 1
                or (self.observed_state, self.resulting_state) != expected_transition
            ):
                raise ValueError("child_media_rule_applied_cas_invalid")
        elif (
            self.resulting_lifecycle_generation != self.observed_lifecycle_generation
            or self.resulting_state != self.observed_state
        ):
            raise ValueError("child_media_rule_rejected_cas_mutated_state")
        return self

class ChildMediaAuthorizationAuthorityV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    rule_id: UUID
    rule_version: Annotated[int, Field(ge=1)]
    proposal_digest: Sha256Digest
    rule_digest: Sha256Digest
    lifecycle_generation: Annotated[int, Field(ge=1)]
    lifecycle_receipt_commitment: HmacCommitment
    child_subject_id: UUID
    child_profile_id: UUID
    child_profile_generation: Annotated[int, Field(ge=1)]
    content_basis: Literal["classification", "item_identity_commitment"]
    matched_content_class: Literal["child_safe", "non_explicit"] | None
    matched_item_identity_commitment: HmacCommitment | None

    @model_validator(mode="after")
    def atomic_child_media_content_authority(self) -> "ChildMediaAuthorizationAuthorityV1":
        classification = self.matched_content_class is not None
        item = self.matched_item_identity_commitment is not None
        if self.content_basis == "classification" and not (classification and not item):
            raise ValueError("child_media_classification_authority_shape_invalid")
        if self.content_basis == "item_identity_commitment" and not (item and not classification):
            raise ValueError("child_media_item_authority_shape_invalid")
        return self

MediaAuthorizationClass = Literal[
    "adult_reversible_immediate", "exact_confirmation", "owner_passkey",
    "designated_guest_owner_coapproval", "child_rule_guardian_approved",
]

class AuthorizedMediaRequestV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    request_id: UUID
    action_type: MediaActionType
    target_kind: Literal["player", "group_manifest"]
    target_player_or_group_id: StableEndpointId
    actor_class: Literal["owner", "adult", "child", "designated_guest", "guest", "uncertain"]
    actor_subject_id: UUID | None
    designated_guest_session_id: UUID | None
    designated_guest_session_generation: Annotated[int | None, Field(ge=1)]
    designated_guest_owner_coapproval_commitment: HmacCommitment | None
    catalog_handle_id: UUID | None
    content_classification: Literal["child_safe", "non_explicit", "explicit", "unknown"] | None
    requested_absolute_volume_percent: Annotated[int, Field(ge=0, le=100)] | None
    requested_seek_position_seconds: Annotated[int, Field(ge=0, le=86_400)] | None
    group_manifest_version: Annotated[int, Field(ge=1)] | None
    group_manifest_digest: Sha256Digest | None
    group_members: Annotated[tuple[MediaGroupMemberV1, ...], Field(max_length=8)]
    topology_generation: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    provider_binding_id: StableEndpointId
    provider_generation: Annotated[int, Field(ge=1)]
    adapter_generation: Annotated[int, Field(ge=1)]
    entitlement_generation: Annotated[int, Field(ge=1)]
    policy_version: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    idempotency_key: UUID
    request_binding_commitment: HmacCommitment

    @model_validator(mode="after")
    def exact_authorized_media_request(self) -> "AuthorizedMediaRequestV1":
        play = self.action_type in {"media.play_catalog_item.v1", "media.play_group_manifest.v1"}
        volume = self.action_type == "media.set_volume_absolute.v1"
        seek = self.action_type == "media.seek_absolute.v1"
        if play != (self.catalog_handle_id is not None and self.content_classification is not None):
            raise ValueError("media_request_catalog_shape_invalid")
        if volume != (self.requested_absolute_volume_percent is not None):
            raise ValueError("media_request_volume_shape_invalid")
        if seek != (self.requested_seek_position_seconds is not None):
            raise ValueError("media_request_seek_shape_invalid")
        group_fields = (
            self.group_manifest_version is not None,
            self.group_manifest_digest is not None,
            bool(self.group_members),
        )
        if self.target_kind == "group_manifest" and not all(group_fields):
            raise ValueError("media_request_group_shape_invalid")
        if self.target_kind == "player" and any(group_fields):
            raise ValueError("media_request_player_carries_group_authority")
        if self.group_members and tuple(member.member_index for member in self.group_members) != tuple(range(len(self.group_members))):
            raise ValueError("media_request_group_members_not_canonical")
        if len({member.player_id for member in self.group_members}) != len(self.group_members):
            raise ValueError("media_request_duplicate_group_player")
        if self.action_type == "media.play_group_manifest.v1" and self.target_kind != "group_manifest":
            raise ValueError("group_play_requires_group_manifest_target")
        if self.action_type == "media.play_catalog_item.v1" and self.target_kind != "player":
            raise ValueError("single_player_play_requires_player_target")
        identified = self.actor_class in {"owner", "adult", "child"}
        if identified != (self.actor_subject_id is not None):
            raise ValueError("media_request_actor_shape_invalid")
        designated_guest = self.actor_class == "designated_guest"
        guest_authority = (
            self.designated_guest_session_id,
            self.designated_guest_session_generation,
            self.designated_guest_owner_coapproval_commitment,
        )
        if designated_guest != all(value is not None for value in guest_authority):
            raise ValueError("media_request_designated_guest_authority_missing")
        if any(value is not None for value in guest_authority) != all(
            value is not None for value in guest_authority
        ):
            raise ValueError("media_request_designated_guest_authority_incomplete")
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("media_request_window_invalid")
        return self

class MediaAuthorizationDecisionV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    request_id: UUID
    request_binding_commitment: HmacCommitment
    effect: Literal["allow", "deny", "step_up"]
    authorization_class: MediaAuthorizationClass | None
    child_rule_authority: ChildMediaAuthorizationAuthorityV1 | None
    required_assurance: Literal["confirmed", "passkey_verified"] | None
    reason_code: SafeReasonCode
    policy_version: Annotated[int, Field(ge=1)]
    topology_generation: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    provider_binding_id: StableEndpointId
    provider_generation: Annotated[int, Field(ge=1)]
    adapter_generation: Annotated[int, Field(ge=1)]
    entitlement_generation: Annotated[int, Field(ge=1)]
    decided_at: AwareDatetime
    valid_until: AwareDatetime
    decision_commitment: HmacCommitment

    @model_validator(mode="after")
    def exact_media_decision(self) -> "MediaAuthorizationDecisionV1":
        if self.effect == "allow":
            if self.authorization_class is None or self.required_assurance is not None:
                raise ValueError("allowed_media_decision_shape_invalid")
        elif self.effect == "step_up":
            if self.authorization_class is not None or self.required_assurance is None:
                raise ValueError("step_up_media_decision_shape_invalid")
        elif self.authorization_class is not None or self.required_assurance is not None:
            raise ValueError("denied_media_decision_carries_authority")
        child_rule_allow = (
            self.effect == "allow"
            and self.authorization_class == "child_rule_guardian_approved"
        )
        if child_rule_allow != (self.child_rule_authority is not None):
            raise ValueError("media_decision_child_rule_authority_shape_invalid")
        if not self.decided_at < self.valid_until <= self.decided_at + timedelta(seconds=5):
            raise ValueError("media_decision_window_invalid")
        return self

class MediaTargetOperationResultV1(WholeHomeContract):
    operation_id: UUID
    request_id: UUID
    action_id: UUID
    idempotency_key: UUID
    signed_envelope_digest: Sha256Digest
    target_id: StableEndpointId
    target_transition_kind: Literal["not_dispatched", "dispatch_started"]
    target_transition_record_commitment: HmacCommitment
    state: Literal[
        "VERIFIED_PLAYING", "VERIFIED_PAUSED", "VERIFIED_STOPPED", "VERIFIED_VOLUME",
        "VERIFIED_POSITION", "ACCEPTED_UNVERIFIED", "FAILED", "UNKNOWN",
    ]
    dispatch_attempt: Literal[0, 1]
    dispatch_started_at: AwareDatetime | None
    dispatch_context_commitment: HmacCommitment | None
    effect_commitment: HmacCommitment | None
    observation_strength: Literal[
        "none", "command_ack_only", "mirrored_optimistic", "same_adapter_observed",
        "out_of_band_observed", "independence_proven",
    ]
    observed_playback_state: Literal[
        "idle", "playing", "paused", "stopped", "buffering", "unavailable", "unknown",
    ] | None
    observed_item_identity_commitment: HmacCommitment | None
    observed_volume_percent: Annotated[int | None, Field(ge=0, le=100)]
    observed_position_seconds: Annotated[int | None, Field(ge=0, le=86_400)]
    control_correlation_id: UUID | None
    source_receipt_commitment: HmacCommitment | None
    core_unknown_terminal_commitment: HmacCommitment | None
    observed_at: AwareDatetime
    evidence_commitment: HmacCommitment

    @model_validator(mode="after")
    def exact_target_result_evidence(self) -> "MediaTargetOperationResultV1":
        if self.state != "FAILED" and self.dispatch_attempt != 1:
            raise ValueError("media_target_result_without_dispatch")
        if (self.dispatch_attempt == 1) != (
            self.target_transition_kind == "dispatch_started"
        ):
            raise ValueError("media_target_transition_kind_mismatch")
        dispatch_evidence = (
            self.dispatch_started_at,
            self.dispatch_context_commitment,
            self.effect_commitment,
        )
        if (self.dispatch_attempt == 1) != all(value is not None for value in dispatch_evidence):
            raise ValueError("media_target_dispatch_evidence_shape_invalid")
        if self.dispatch_attempt == 0 and any(value is not None for value in dispatch_evidence):
            raise ValueError("undispatched_media_target_carries_effect_evidence")
        if self.dispatch_attempt == 0 and self.observation_strength != "none":
            raise ValueError("undispatched_media_target_carries_observation_strength")
        observation_fields = (
            self.observed_playback_state,
            self.observed_item_identity_commitment,
            self.observed_volume_percent,
            self.observed_position_seconds,
            self.control_correlation_id,
        )
        if self.observation_strength == "none" and any(
            value is not None for value in observation_fields
        ):
            raise ValueError("media_target_without_observation_carries_state")
        if (self.observation_strength != "none") != (
            self.source_receipt_commitment is not None
        ):
            raise ValueError("media_target_observation_receipt_binding_invalid")
        if (self.state == "UNKNOWN") != (
            self.core_unknown_terminal_commitment is not None
        ):
            raise ValueError("media_target_unknown_terminal_binding_invalid")
        if self.dispatch_started_at is not None and self.observed_at < self.dispatch_started_at:
            raise ValueError("media_result_observed_before_dispatch")
        if self.state.startswith("VERIFIED_") and self.observation_strength in {"none", "command_ack_only", "mirrored_optimistic"}:
            raise ValueError("verified_media_result_without_observation")
        if self.state.startswith("VERIFIED_") and self.control_correlation_id != self.action_id:
            raise ValueError("verified_media_result_without_exact_action_correlation")
        if self.state == "ACCEPTED_UNVERIFIED" and self.observation_strength not in {
            "command_ack_only", "same_adapter_observed", "out_of_band_observed",
            "independence_proven",
        }:
            raise ValueError("accepted_unverified_media_without_bound_ack_or_observation")
        return self

class MediaOperationResultV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    operation_id: UUID
    request_id: UUID
    action_id: UUID
    idempotency_key: UUID
    action_type: MediaActionType
    target_kind: Literal["player", "group_manifest"]
    target_player_or_group_id: StableEndpointId
    catalog_item_identity_commitment: HmacCommitment | None
    absolute_volume_percent: Annotated[int | None, Field(ge=0, le=100)]
    seek_position_seconds: Annotated[int | None, Field(ge=0, le=86_400)]
    seek_verification_tolerance_seconds: Annotated[int | None, Field(ge=0, le=5)]
    signed_envelope_digest: Sha256Digest
    manifest_order_target_ids: Annotated[tuple[StableEndpointId, ...], Field(min_length=1, max_length=8)]
    target_results: Annotated[tuple[MediaTargetOperationResultV1, ...], Field(min_length=1, max_length=8)]
    aggregate_state: Literal["VERIFIED", "ACCEPTED_UNVERIFIED", "PARTIAL", "FAILED", "UNKNOWN"]
    controller_epoch: ControllerEpoch
    topology_generation: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    capability_digest: Sha256Digest
    provider_binding_id: StableEndpointId
    provider_generation: Annotated[int, Field(ge=1)]
    adapter_generation: Annotated[int, Field(ge=1)]
    entitlement_generation: Annotated[int, Field(ge=1)]
    policy_version: Annotated[int, Field(ge=1)]
    request_binding_commitment: HmacCommitment
    authorization_class: MediaAuthorizationClass
    child_rule_authority: ChildMediaAuthorizationAuthorityV1 | None
    authorization_commitment: HmacCommitment
    authorized_at: AwareDatetime
    request_expires_at: AwareDatetime
    decision_valid_until: AwareDatetime
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    reconciliation_deadline: AwareDatetime
    completed_at: AwareDatetime
    result_commitment: HmacCommitment

    @model_validator(mode="after")
    def exact_manifest_order_and_aggregate(self) -> "MediaOperationResultV1":
        if (
            self.authorization_class == "child_rule_guardian_approved"
        ) != (self.child_rule_authority is not None):
            raise ValueError("media_result_child_rule_authority_shape_invalid")
        play = self.action_type in {"media.play_catalog_item.v1", "media.play_group_manifest.v1"}
        volume = self.action_type == "media.set_volume_absolute.v1"
        seek = self.action_type == "media.seek_absolute.v1"
        if play != (self.catalog_item_identity_commitment is not None):
            raise ValueError("media_result_catalog_item_shape_invalid")
        if volume != (self.absolute_volume_percent is not None):
            raise ValueError("media_result_volume_shape_invalid")
        if seek != (
            self.seek_position_seconds is not None
            and self.seek_verification_tolerance_seconds is not None
        ):
            raise ValueError("media_result_seek_shape_invalid")
        if media_tv_authority_window_failures(
            self.authorized_at, self.issued_at, self.expires_at,
        ):
            raise ValueError("media_result_authority_window_invalid")
        authority_deadline = min(self.request_expires_at, self.decision_valid_until)
        if self.issued_at >= authority_deadline or self.expires_at > authority_deadline:
            raise ValueError("media_result_outlives_request_or_decision")
        if not (
            self.expires_at
            <= self.reconciliation_deadline
            <= self.expires_at + timedelta(seconds=5)
        ):
            raise ValueError("media_result_reconciliation_window_invalid")
        if not self.issued_at <= self.completed_at <= self.reconciliation_deadline:
            raise ValueError("media_result_completion_outside_reconciliation_window")
        result_ids = tuple(result.target_id for result in self.target_results)
        if result_ids != self.manifest_order_target_ids or len(set(result_ids)) != len(result_ids):
            raise ValueError("media_result_manifest_order_invalid")
        expected_verified = {
            "media.play_catalog_item.v1": "VERIFIED_PLAYING",
            "media.play_group_manifest.v1": "VERIFIED_PLAYING",
            "media.pause.v1": "VERIFIED_PAUSED",
            "media.resume.v1": "VERIFIED_PLAYING",
            "media.stop.v1": "VERIFIED_STOPPED",
            "media.set_volume_absolute.v1": "VERIFIED_VOLUME",
            "media.seek_absolute.v1": "VERIFIED_POSITION",
        }[self.action_type]
        if any(result.state.startswith("VERIFIED_") and result.state != expected_verified for result in self.target_results):
            raise ValueError("media_result_verified_state_action_mismatch")
        for result in self.target_results:
            if not result.state.startswith("VERIFIED_"):
                continue
            if self.action_type in {"media.play_catalog_item.v1", "media.play_group_manifest.v1"} and (
                result.observed_playback_state != "playing"
                or result.observed_item_identity_commitment is None
                or not compare_digest(
                    result.observed_item_identity_commitment,
                    self.catalog_item_identity_commitment,
                )
            ):
                raise ValueError("verified_media_play_item_mismatch")
            if self.action_type == "media.pause.v1" and result.observed_playback_state != "paused":
                raise ValueError("verified_media_pause_state_mismatch")
            if self.action_type == "media.resume.v1" and result.observed_playback_state != "playing":
                raise ValueError("verified_media_resume_state_mismatch")
            if self.action_type == "media.stop.v1" and result.observed_playback_state != "stopped":
                raise ValueError("verified_media_stop_state_mismatch")
            if self.action_type == "media.set_volume_absolute.v1" and (
                result.observed_volume_percent != self.absolute_volume_percent
            ):
                raise ValueError("verified_media_volume_mismatch")
            if self.action_type == "media.seek_absolute.v1" and (
                result.observed_position_seconds is None
                or abs(result.observed_position_seconds - self.seek_position_seconds)
                > self.seek_verification_tolerance_seconds
            ):
                raise ValueError("verified_media_position_mismatch")
        states = tuple(result.state for result in self.target_results)
        if any(state == "UNKNOWN" for state in states) and (
            self.completed_at != self.reconciliation_deadline
        ):
            raise ValueError("media_unknown_result_before_reconciliation_deadline")
        verified = tuple(state.startswith("VERIFIED_") for state in states)
        if all(verified):
            expected_aggregate = "VERIFIED"
        elif any(verified):
            expected_aggregate = "PARTIAL"
        elif all(state == "ACCEPTED_UNVERIFIED" for state in states):
            expected_aggregate = "ACCEPTED_UNVERIFIED"
        elif all(state == "FAILED" for state in states):
            expected_aggregate = "FAILED"
        else:
            expected_aggregate = "UNKNOWN"
        if self.aggregate_state != expected_aggregate:
            raise ValueError("media_result_aggregate_invalid")
        if any(
            result.operation_id != self.operation_id
            or result.request_id != self.request_id
            or result.action_id != self.action_id
            or result.idempotency_key != self.idempotency_key
            or not compare_digest(
                result.signed_envelope_digest,
                self.signed_envelope_digest,
            )
            or result.observed_at < self.issued_at
            or result.observed_at > self.completed_at
            or (
                result.dispatch_started_at is not None
                and not (
                    self.issued_at
                    <= result.dispatch_started_at
                    <= result.observed_at
                )
            )
            for result in self.target_results
        ):
            raise ValueError("media_result_child_lineage_or_time_invalid")
        return self

class OpaqueCatalogHandleV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    handle_id: UUID
    provider_binding_id: StableEndpointId
    account_class: Literal["owner_entitled", "household_entitled", "child_rule_entitled"]
    item_identity_commitment: HmacCommitment
    content_classification: Literal["child_safe", "non_explicit", "explicit", "unknown"]
    provider_generation: Annotated[int, Field(ge=1)]
    adapter_generation: Annotated[int, Field(ge=1)]
    entitlement_generation: Annotated[int, Field(ge=1)]
    result_generation: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    single_use: Literal[True]
    handle_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_catalog_handle(self) -> "OpaqueCatalogHandleV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=30):
            raise ValueError("catalog_handle_window_invalid")
        return self

class AuthorizedCatalogQueryV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    query_id: UUID
    normalized_query: Annotated[str, Field(min_length=1, max_length=256)]
    actor_class: Literal["owner", "adult", "guardian_child", "designated_guest"]
    provider_authorities: Annotated[tuple[ProviderAuthorityRefV1, ...], Field(min_length=1, max_length=8)]
    content_ceiling: Literal["child_safe", "non_explicit", "adult"]
    result_cap: Annotated[int, Field(ge=1, le=12)]
    policy_generation: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    authorization_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_catalog_query(self) -> "AuthorizedCatalogQueryV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("catalog_query_window_invalid")
        ids = tuple(authority.provider_binding_id for authority in self.provider_authorities)
        if len(set(ids)) != len(ids) or ids != tuple(sorted(ids)):
            raise ValueError("duplicate_catalog_provider_binding")
        return self

class MediaCatalogResultV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    query_id: UUID
    state: Literal["exact", "ambiguous", "no_match", "denied", "error_safe"]
    handles: Annotated[tuple[OpaqueCatalogHandleV1, ...], Field(max_length=12)]
    authorized_provider_authorities: Annotated[
        tuple[ProviderAuthorityRefV1, ...],
        Field(min_length=1, max_length=8),
    ]
    query_authorization_commitment: HmacCommitment
    result_generation: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    result_commitment: HmacCommitment

    @model_validator(mode="after")
    def coherent_catalog_result(self) -> "MediaCatalogResultV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=30):
            raise ValueError("catalog_result_window_invalid")
        if self.state == "exact" and len(self.handles) != 1:
            raise ValueError("exact_catalog_result_requires_one_handle")
        if self.state == "ambiguous" and len(self.handles) < 2:
            raise ValueError("ambiguous_catalog_result_requires_choices")
        if self.state in {"no_match", "denied", "error_safe"} and self.handles:
            raise ValueError("nonresult_catalog_state_cannot_carry_handles")
        authority_by_id = {
            authority.provider_binding_id: authority
            for authority in self.authorized_provider_authorities
        }
        authority_ids = tuple(authority.provider_binding_id for authority in self.authorized_provider_authorities)
        if len(authority_by_id) != len(self.authorized_provider_authorities) or authority_ids != tuple(sorted(authority_ids)):
            raise ValueError("duplicate_catalog_result_provider_binding")
        handle_ids = tuple(handle.handle_id for handle in self.handles)
        handle_commitments = tuple(handle.handle_commitment for handle in self.handles)
        if len(set(handle_ids)) != len(handle_ids) or len(set(handle_commitments)) != len(
            handle_commitments
        ):
            raise ValueError("duplicate_catalog_result_handle")
        if any(
            handle.result_generation != self.result_generation
            or handle.provider_binding_id not in authority_by_id
            or handle.provider_generation != authority_by_id[handle.provider_binding_id].provider_generation
            or handle.adapter_generation != authority_by_id[handle.provider_binding_id].adapter_generation
            or handle.entitlement_generation != authority_by_id[handle.provider_binding_id].entitlement_generation
            or not self.issued_at <= handle.issued_at < handle.expires_at <= self.expires_at
            for handle in self.handles
        ):
            raise ValueError("catalog_result_handle_binding_invalid")
        return self

class MediaDispatchReceiptV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    record_kind: Literal["adapter_receipt"]
    operation_id: UUID
    request_id: UUID
    action_id: UUID
    idempotency_key: UUID
    action_type: MediaActionType
    target_kind: Literal["player", "group_manifest"]
    target_player_or_group_id: StableEndpointId
    target_ids: Annotated[tuple[StableEndpointId, ...], Field(min_length=1, max_length=8)]
    state: Literal["authorized_committed", "dispatching", "reconciling", "accepted_unverified", "failed", "expired"]
    dispatch_attempt: Literal[0, 1]
    dispatch_started_at: AwareDatetime | None
    dispatch_context_commitment: HmacCommitment | None
    effect_commitment: HmacCommitment | None
    signed_envelope_digest: Sha256Digest
    controller_epoch: ControllerEpoch
    topology_generation: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    provider_binding_id: StableEndpointId
    provider_generation: Annotated[int, Field(ge=1)]
    adapter_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    capability_digest: Sha256Digest
    entitlement_generation: Annotated[int, Field(ge=1)]
    policy_version: Annotated[int, Field(ge=1)]
    request_binding_commitment: HmacCommitment
    authorization_class: MediaAuthorizationClass
    child_rule_authority: ChildMediaAuthorizationAuthorityV1 | None
    authorization_commitment: HmacCommitment
    authorized_at: AwareDatetime
    request_expires_at: AwareDatetime
    decision_valid_until: AwareDatetime
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    reconciliation_deadline: AwareDatetime
    terminal_at: AwareDatetime | None
    observed_at: AwareDatetime
    receipt_commitment: HmacCommitment

    @model_validator(mode="after")
    def coherent_media_dispatch(self) -> "MediaDispatchReceiptV1":
        if (
            self.authorization_class == "child_rule_guardian_approved"
        ) != (self.child_rule_authority is not None):
            raise ValueError("media_receipt_child_rule_authority_shape_invalid")
        attempted_states = {
            "dispatching", "reconciling", "accepted_unverified",
        }
        if self.state in attempted_states and self.dispatch_attempt != 1:
            raise ValueError("media_dispatch_state_without_attempt")
        if self.state in {"authorized_committed", "expired"} and self.dispatch_attempt != 0:
            raise ValueError("undispatched_media_state_claims_attempt")
        evidence = (
            self.dispatch_started_at,
            self.dispatch_context_commitment,
            self.effect_commitment,
        )
        if (self.dispatch_attempt == 1) != all(value is not None for value in evidence):
            raise ValueError("media_dispatch_context_evidence_shape_invalid")
        if self.dispatch_attempt == 0 and any(value is not None for value in evidence):
            raise ValueError("undispatched_media_receipt_carries_effect_evidence")
        if self.observed_at < self.issued_at:
            raise ValueError("media_receipt_observation_predates_issue")
        if self.dispatch_started_at is not None and self.observed_at < self.dispatch_started_at:
            raise ValueError("media_receipt_observation_predates_dispatch")
        if media_tv_authority_window_failures(
            self.authorized_at, self.issued_at, self.expires_at,
        ):
            raise ValueError("media_receipt_authority_window_invalid")
        authority_deadline = min(self.request_expires_at, self.decision_valid_until)
        if self.issued_at >= authority_deadline or self.expires_at > authority_deadline:
            raise ValueError("media_receipt_outlives_request_or_decision")
        if not (
            self.expires_at
            <= self.reconciliation_deadline
            <= self.expires_at + timedelta(seconds=5)
        ):
            raise ValueError("media_receipt_reconciliation_window_invalid")
        if self.observed_at > self.reconciliation_deadline:
            raise ValueError("media_receipt_observation_after_reconciliation_deadline")
        if self.dispatch_started_at is not None and not (
            self.issued_at <= self.dispatch_started_at < self.expires_at
        ):
            raise ValueError("media_receipt_dispatch_outside_envelope_window")
        terminal_state = self.state in {
            "accepted_unverified", "failed", "expired",
        }
        if terminal_state != (self.terminal_at is not None):
            raise ValueError("media_receipt_terminal_time_shape_invalid")
        if self.terminal_at is not None and not (
            self.issued_at <= self.terminal_at <= self.observed_at
            and self.terminal_at <= self.reconciliation_deadline
        ):
            raise ValueError("media_receipt_terminal_time_invalid")
        if (
            self.terminal_at is not None
            and self.dispatch_started_at is not None
            and self.terminal_at < self.dispatch_started_at
        ):
            raise ValueError("media_receipt_terminal_predates_dispatch")
        if self.state == "expired" and self.terminal_at < self.expires_at:
            raise ValueError("media_receipt_expired_before_deadline")
        if self.state == "authorized_committed" and self.observed_at >= self.expires_at:
            raise ValueError("undispatched_media_nonterminal_at_deadline")
        if (
            self.state == "failed"
            and self.dispatch_attempt == 0
            and self.terminal_at >= self.expires_at
        ):
            raise ValueError("undispatched_media_failure_at_deadline_must_expire")
        if (
            self.state in {"dispatching", "reconciling"}
            and self.observed_at >= self.reconciliation_deadline
        ):
            raise ValueError("attempted_media_nonterminal_at_reconciliation_deadline")
        if len(set(self.target_ids)) != len(self.target_ids):
            raise ValueError("duplicate_media_dispatch_target")
        return self

class MediaDispatchUnknownTerminalV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    record_kind: Literal["core_unknown_terminal"]
    terminal_id: UUID
    operation_id: UUID
    request_id: UUID
    action_id: UUID
    idempotency_key: UUID
    action_type: MediaActionType
    target_kind: Literal["player", "group_manifest"]
    target_player_or_group_id: StableEndpointId
    target_ids: Annotated[tuple[StableEndpointId, ...], Field(min_length=1, max_length=8)]
    signed_envelope_digest: Sha256Digest
    dispatch_attempt: Literal[1]
    dispatch_started_at: AwareDatetime
    dispatch_context_commitment: HmacCommitment
    effect_commitment: HmacCommitment
    target_transition_set_commitment: HmacCommitment
    controller_epoch: ControllerEpoch
    topology_generation: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    provider_binding_id: StableEndpointId
    provider_generation: Annotated[int, Field(ge=1)]
    adapter_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    capability_digest: Sha256Digest
    entitlement_generation: Annotated[int, Field(ge=1)]
    policy_version: Annotated[int, Field(ge=1)]
    request_binding_commitment: HmacCommitment
    authorization_class: MediaAuthorizationClass
    child_rule_authority: ChildMediaAuthorizationAuthorityV1 | None
    authorization_commitment: HmacCommitment
    authorized_at: AwareDatetime
    request_expires_at: AwareDatetime
    decision_valid_until: AwareDatetime
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    reconciliation_deadline: AwareDatetime
    terminal_at: AwareDatetime
    materialized_at: AwareDatetime
    terminal_reason: Literal["reconciliation_deadline_elapsed"]
    terminal_commitment: HmacCommitment
    core_key_id: KeyId
    core_signature: P256Signature

    @model_validator(mode="after")
    def coherent_media_unknown_terminal(self) -> "MediaDispatchUnknownTerminalV1":
        if (
            self.authorization_class == "child_rule_guardian_approved"
        ) != (self.child_rule_authority is not None):
            raise ValueError("media_terminal_child_rule_authority_shape_invalid")
        if media_tv_authority_window_failures(
            self.authorized_at, self.issued_at, self.expires_at,
        ):
            raise ValueError("media_terminal_authority_window_invalid")
        authority_deadline = min(self.request_expires_at, self.decision_valid_until)
        if self.issued_at >= authority_deadline or self.expires_at > authority_deadline:
            raise ValueError("media_terminal_outlives_request_or_decision")
        if not (
            self.expires_at
            <= self.reconciliation_deadline
            <= self.expires_at + timedelta(seconds=5)
        ):
            raise ValueError("media_terminal_reconciliation_window_invalid")
        if not self.issued_at <= self.dispatch_started_at < self.expires_at:
            raise ValueError("media_terminal_dispatch_outside_envelope_window")
        if self.terminal_at != self.reconciliation_deadline:
            raise ValueError("media_terminal_not_at_reconciliation_deadline")
        if self.materialized_at < self.terminal_at:
            raise ValueError("media_terminal_materialized_before_deadline")
        if len(set(self.target_ids)) != len(self.target_ids):
            raise ValueError("duplicate_media_terminal_target")
        return self

MediaDispatchControlRecordV1 = Annotated[
    MediaDispatchReceiptV1 | MediaDispatchUnknownTerminalV1,
    Field(discriminator="record_kind"),
]

class SignedMediaEnvelopeV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    operation_id: UUID
    request_id: UUID
    action_id: UUID
    action_type: MediaActionType
    target_kind: Literal["player", "group_manifest"]
    target_player_or_group_id: StableEndpointId
    group_manifest_version: Annotated[int, Field(ge=1)] | None
    group_manifest_digest: Sha256Digest | None
    group_members: Annotated[tuple[MediaGroupMemberV1, ...], Field(max_length=8)]
    catalog_handle_id: UUID | None
    catalog_item_identity_commitment: HmacCommitment | None
    absolute_volume_percent: Annotated[int, Field(ge=0, le=100)] | None
    seek_position_seconds: Annotated[int, Field(ge=0, le=86_400)] | None
    seek_verification_tolerance_seconds: Annotated[int | None, Field(ge=0, le=5)]
    controller_epoch: ControllerEpoch
    topology_generation: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    capability_digest: Sha256Digest
    provider_binding_id: StableEndpointId
    provider_generation: Annotated[int, Field(ge=1)]
    adapter_generation: Annotated[int, Field(ge=1)]
    entitlement_generation: Annotated[int, Field(ge=1)]
    policy_version: Annotated[int, Field(ge=1)]
    request_binding_commitment: HmacCommitment
    authorization_class: MediaAuthorizationClass
    child_rule_authority: ChildMediaAuthorizationAuthorityV1 | None
    authorization_commitment: HmacCommitment
    idempotency_key: UUID
    authorized_at: AwareDatetime
    request_expires_at: AwareDatetime
    decision_valid_until: AwareDatetime
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    reconciliation_deadline: AwareDatetime
    key_id: KeyId
    signature: P256Signature

    @model_validator(mode="after")
    def exact_media_action_shape(self) -> "SignedMediaEnvelopeV1":
        if (
            self.authorization_class == "child_rule_guardian_approved"
        ) != (self.child_rule_authority is not None):
            raise ValueError("media_envelope_child_rule_authority_shape_invalid")
        play = self.action_type in {"media.play_catalog_item.v1", "media.play_group_manifest.v1"}
        volume = self.action_type == "media.set_volume_absolute.v1"
        seek = self.action_type == "media.seek_absolute.v1"
        if play != (
            self.catalog_handle_id is not None
            and self.catalog_item_identity_commitment is not None
        ):
            raise ValueError("media_catalog_handle_shape_invalid")
        if volume != (self.absolute_volume_percent is not None):
            raise ValueError("media_volume_shape_invalid")
        if seek != (
            self.seek_position_seconds is not None
            and self.seek_verification_tolerance_seconds is not None
        ):
            raise ValueError("media_seek_shape_invalid")
        group_fields = (
            self.group_manifest_version is not None,
            self.group_manifest_digest is not None,
            bool(self.group_members),
        )
        if self.target_kind == "group_manifest" and not all(group_fields):
            raise ValueError("media_envelope_group_authority_incomplete")
        if self.target_kind == "player" and any(group_fields):
            raise ValueError("media_envelope_player_carries_group_authority")
        if self.action_type == "media.play_group_manifest.v1" and self.target_kind != "group_manifest":
            raise ValueError("media_group_action_target_invalid")
        if self.action_type == "media.play_catalog_item.v1" and self.target_kind != "player":
            raise ValueError("media_player_action_target_invalid")
        if self.group_members and tuple(member.member_index for member in self.group_members) != tuple(range(len(self.group_members))):
            raise ValueError("media_envelope_group_members_not_canonical")
        if len({member.player_id for member in self.group_members}) != len(self.group_members):
            raise ValueError("media_envelope_duplicate_group_player")
        if media_tv_authority_window_failures(
            self.authorized_at, self.issued_at, self.expires_at,
        ):
            raise ValueError("media_envelope_window_invalid")
        authority_deadline = min(self.request_expires_at, self.decision_valid_until)
        if self.issued_at >= authority_deadline or self.expires_at > authority_deadline:
            raise ValueError("media_envelope_outlives_request_or_decision")
        if not (
            self.expires_at
            <= self.reconciliation_deadline
            <= self.expires_at + timedelta(seconds=5)
        ):
            raise ValueError("media_envelope_reconciliation_window_invalid")
        return self

def canonical_signed_media_envelope_unsigned_bytes(
    envelope: SignedMediaEnvelopeV1,
) -> bytes:
    unsigned = envelope.model_dump(
        mode="python", exclude={"key_id", "signature"},
    )
    return canonical_json_bytes(unsigned)

class PlayerObservationV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    player_id: StableEndpointId
    source: Literal["native_player", "home_assistant", "music_assistant", "out_of_band"]
    playback_state: Literal["idle", "playing", "paused", "stopped", "buffering", "unavailable", "unknown"]
    observed_item_identity_commitment: HmacCommitment | None
    volume_percent: Annotated[int, Field(ge=0, le=100)] | None
    position_seconds: Annotated[int, Field(ge=0, le=86_400)] | None
    control_correlation_id: UUID | None
    observation_strength: Literal["command_ack_only", "mirrored_optimistic", "same_adapter_observed", "out_of_band_observed", "independence_proven"]
    binding_generation: Annotated[int, Field(ge=1)]
    provider_binding_id: StableEndpointId
    provider_generation: Annotated[int, Field(ge=1)]
    adapter_generation: Annotated[int, Field(ge=1)]
    entitlement_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    sampled_at: AwareDatetime
    ingested_at: AwareDatetime
    valid_until: AwareDatetime
    source_receipt_commitment: HmacCommitment

    @model_validator(mode="after")
    def coherent_player_observation(self) -> "PlayerObservationV1":
        if not (
            self.sampled_at <= self.ingested_at <= self.sampled_at + timedelta(seconds=5)
            and self.ingested_at < self.valid_until <= self.ingested_at + timedelta(seconds=5)
        ):
            raise ValueError("player_observation_window_invalid")
        if self.playback_state in {"unavailable", "unknown"} and any(value is not None for value in (
            self.observed_item_identity_commitment,
            self.volume_percent,
            self.position_seconds,
            self.control_correlation_id,
        )):
            raise ValueError("unknown_player_state_has_precise_values")
        return self
```

### Display and television contracts

- Phase 4 consumes the Phase 2 screen-time boundary with this exact import and does not redeclare any imported name:

```python
# apps/core/src/tuntun_core/services/whole_home/screen_time_adapter.py
from tuntun_contracts.home.screen_time import (
    EnforcementIntentV1,
    TVControlReceiptV1,
    TVDispatchProofV1,
    TVObservationV1,
    TVPowerEligibilityV1,
)
from tuntun_contracts.whole_home.television import (
    TVActionDispatchReceiptV1,
    WholeHomeTVObservationV1,
)
```

- `TeachingSessionManifestV1` uses signature domain `tuntun-display-manifest-v1` and the exact closed component union: title, paragraph, image asset, vocabulary card, multiple choice, number line, timer, progress, and citation.
- `TeachingAssetV1` contains only content hash, media type, byte length, and single-use local fetch handle. No URL/path/raw markup field exists.
- `DisplayReceiptV1` reports validated/ready/rendered/cleared/expired/error-safe with HDMI evidence and never contains pixels, screenshot, lesson body, or child response.
- `EphemeralLearningSummary` is an internal RAM-only value with broad topic code, bounded duration/completion class, and expiry no later than five minutes. It has no repository port or JSON/API persistence contract.
- `TelevisionBindingV1` and `TVCapabilityEvidenceV1` bind one exact deployment TV, its distinct endpoint/binding/capability generations, generic lifecycle and operation routes, per-route control or observation generation, primary control/optional distinct observation adapters, strength, and test digest. The imported Phase 2 `TVPowerEligibilityV1` separately persists the complete `UNCOMMISSIONED`, `DISPLAY_ONLY_MANUAL`, `OBSERVE_ONLY`, `COOPERATIVE_ELIGIBLE`, `STRICT_ELIGIBLE`, `DEGRADED`, `QUARANTINED`, and `RETIRED` screen-time power states. Endpoint, binding, capability, control, and observation generations are never aliased; positive fixtures intentionally give them unequal values. A generic input/volume/app capability can never imply power-enforcement eligibility.
- `SignedTVActionV1` uses `tuntun-tv-action-v1` with key purpose `tv_action` and one closed desired state. Adapter-side `TVActionDispatchReceiptV1` uses `tuntun-tv-dispatch-receipt-v1`/`tv_dispatch_receipt`; `WholeHomeTVObservationV1` uses `tuntun-tv-observation-v1`/`tv_observation` and carries source/sample/ingest/freshness/generation/strength plus registered closed observed dimensions only. The adapter receipt has no `unknown` variant. Core alone may derive `TVDispatchUnknownTerminalV1` under `tuntun-tv-dispatch-unknown-terminal-v1`/`core_tv_dispatch_unknown_terminal` from a stored signed action and immutable attempt-one proof at its deadline. No network, adapter, API, DTO, or caller-facing constructor accepts that Core branch or either Core timestamp; the mapper reloads it only from the immutable terminal repository. Its `terminal_id` is verifier-recomputed UUIDv5 over the fixed TV-terminal namespace plus action digest and dispatch-proof commitment. The finalizer sets `materialized_at` from its writer-owned trusted post-lock sample; verification requires `terminal_at <= materialized_at <= trusted_verification_time`. Verifiers reject all cross-type domain or key-purpose replay even when an adapter reuses one paired physical key. The canonical names `TVObservationV1` and `TVControlReceiptV1` remain owned exclusively by the Phase 2 screen-time contract.
- `ManualOverrideEventV1` identifies a local physical/renderer/contrary-observation source and enforcement generation, but never identifies the person using the remote/button.

```python
from tuntun_contracts.home.channel import ControllerEpoch
from tuntun_contracts.whole_home.base import media_tv_authority_window_failures

TeachingTopicCode = Literal[
    "literacy", "numeracy", "general_knowledge", "creative",
    "language_practice", "other",
]

class TeachingAudienceBindingV1(WholeHomeContract):
    audience_class: Literal["adult", "k2_child", "n1_child", "guest"]
    subject_id: UUID | None
    profile_version: Annotated[int, Field(ge=1)] | None
    identity_mode: Literal["identified", "guest", "uncertain"]
    memory_audience: MemoryAudience | None
    presentation_policy: Literal["personalized", "generic_guest_public"]
    guardian_approval_generation: Annotated[int, Field(ge=1)] | None
    child_safe_household_approval_grant_id: UUID | None
    consent_generation: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    screen_time_policy_generation: Annotated[int, Field(ge=1)]
    binding_commitment: HmacCommitment

    @model_validator(mode="after")
    def exact_teaching_audience(self) -> "TeachingAudienceBindingV1":
        identified = self.audience_class != "guest"
        if identified != (self.subject_id is not None and self.profile_version is not None):
            raise ValueError("teaching_audience_subject_shape_invalid")
        if identified != (self.identity_mode == "identified"):
            raise ValueError("teaching_audience_identity_mode_invalid")
        child = self.audience_class in {"k2_child", "n1_child"}
        if child != (self.guardian_approval_generation is not None):
            raise ValueError("teaching_audience_guardian_shape_invalid")
        if self.audience_class == "guest":
            if (
                self.identity_mode != "guest"
                or self.memory_audience is not None
                or self.presentation_policy != "generic_guest_public"
                or self.child_safe_household_approval_grant_id is not None
            ):
                raise ValueError("guest_teaching_audience_widened")
        elif self.memory_audience is None or self.presentation_policy != "personalized":
            raise ValueError("identified_teaching_audience_missing")
        if child:
            if self.memory_audience not in {MemoryAudience.GUARDIAN_CHILD, MemoryAudience.HOUSEHOLD_ALL}:
                raise ValueError("child_teaching_audience_invalid")
            if (
                self.memory_audience == MemoryAudience.HOUSEHOLD_ALL
            ) != (self.child_safe_household_approval_grant_id is not None):
                raise ValueError("child_teaching_household_approval_invalid")
        elif self.child_safe_household_approval_grant_id is not None:
            raise ValueError("nonchild_teaching_household_approval_forbidden")
        elif identified and self.memory_audience not in {
            MemoryAudience.SUBJECT_PRIVATE,
            MemoryAudience.HOUSEHOLD_ADULTS,
            MemoryAudience.HOUSEHOLD_ALL,
        }:
            raise ValueError("adult_teaching_audience_invalid")
        return self

class TeachingRequestV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    request_id: UUID
    display_endpoint_id: StableEndpointId
    renderer_endpoint_id: StableEndpointId
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    requested_audience_class: Literal["adult", "k2_child", "n1_child", "guest"]
    actor_subject_id: UUID | None
    language_mode: Literal["en", "hi", "hinglish"]
    topic_code: TeachingTopicCode
    requested_duration_minutes: Annotated[int, Field(ge=1, le=120)]
    web_mode: Literal["no_web", "controlled"]
    controlled_web_authorization_commitment: HmacCommitment | None
    screen_time_session_ref: UUID | None
    identity_generation: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    policy_version: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    request_content_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_teaching_request(self) -> "TeachingRequestV1":
        if (self.requested_audience_class != "guest") != (self.actor_subject_id is not None):
            raise ValueError("teaching_request_actor_shape_invalid")
        controlled = self.web_mode == "controlled"
        if controlled != (self.controlled_web_authorization_commitment is not None):
            raise ValueError("teaching_request_web_authority_shape_invalid")
        if self.requested_audience_class != "adult" and controlled:
            raise ValueError("nonadult_teaching_web_mode_invalid")
        child = self.requested_audience_class in {"k2_child", "n1_child"}
        if child != (self.screen_time_session_ref is not None):
            raise ValueError("teaching_request_child_screen_time_shape_invalid")
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("teaching_request_window_invalid")
        return self

class AuthorizedTeachingRequestV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    request_id: UUID
    request_content_commitment: HmacCommitment
    request_issued_at: AwareDatetime
    request_expires_at: AwareDatetime
    display_endpoint_id: StableEndpointId
    display_endpoint_generation: Annotated[int, Field(ge=1)]
    display_binding_generation: Annotated[int, Field(ge=1)]
    display_capability_generation: Annotated[int, Field(ge=1)]
    display_capability_evidence_digest: Sha256Digest
    renderer_endpoint_id: StableEndpointId
    renderer_endpoint_generation: Annotated[int, Field(ge=1)]
    renderer_binding_generation: Annotated[int, Field(ge=1)]
    renderer_capability_generation: Annotated[int, Field(ge=1)]
    renderer_capability_evidence_digest: Sha256Digest
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    audience_binding: TeachingAudienceBindingV1
    privacy_generation: Annotated[int, Field(ge=1)]
    language_mode: Literal["en", "hi", "hinglish"]
    topic_code: TeachingTopicCode
    requested_duration_minutes: Annotated[int, Field(ge=1, le=120)]
    maximum_duration_minutes: Annotated[int, Field(ge=1, le=120)]
    web_mode: Literal["no_web", "controlled"]
    controlled_web_authorization_commitment: HmacCommitment | None
    approved_source_pack_commitments: Annotated[tuple[HmacCommitment, ...], Field(max_length=16)]
    screen_time_session_ref: UUID | None
    screen_time_session_commitment: HmacCommitment | None
    screen_time_session_expires_at: AwareDatetime | None
    screen_time_policy_version: Annotated[int | None, Field(ge=1)]
    child_safe_household_approval_commitment: HmacCommitment | None
    child_extended_duration_commitment: HmacCommitment | None
    teaching_policy_version: Annotated[int, Field(ge=1)]
    authorized_at: AwareDatetime
    expires_at: AwareDatetime
    authorization_commitment: HmacCommitment

    @model_validator(mode="after")
    def exact_authorized_teaching_request(self) -> "AuthorizedTeachingRequestV1":
        if self.privacy_generation != self.audience_binding.privacy_generation:
            raise ValueError("authorized_teaching_privacy_generation_mismatch")
        if self.audience_binding.audience_class in {"k2_child", "n1_child", "guest"} and self.web_mode != "no_web":
            raise ValueError("nonadult_teaching_web_mode_invalid")
        controlled = self.web_mode == "controlled"
        if controlled != (self.controlled_web_authorization_commitment is not None):
            raise ValueError("authorized_teaching_web_authority_shape_invalid")
        if len(set(self.approved_source_pack_commitments)) != len(self.approved_source_pack_commitments):
            raise ValueError("duplicate_teaching_source_pack")
        if self.maximum_duration_minutes > self.requested_duration_minutes:
            raise ValueError("authorized_teaching_duration_exceeds_request")
        child = self.audience_binding.audience_class in {"k2_child", "n1_child"}
        screen_time_authority = (
            self.screen_time_session_ref,
            self.screen_time_session_commitment,
            self.screen_time_session_expires_at,
            self.screen_time_policy_version,
        )
        if child != all(value is not None for value in screen_time_authority):
            raise ValueError("authorized_teaching_child_screen_time_shape_invalid")
        if any(value is not None for value in screen_time_authority) != all(
            value is not None for value in screen_time_authority
        ):
            raise ValueError("authorized_teaching_screen_time_authority_incomplete")
        if child and self.expires_at > self.screen_time_session_expires_at:
            raise ValueError("authorized_teaching_outlives_screen_time_session")
        household_child = child and self.audience_binding.memory_audience == MemoryAudience.HOUSEHOLD_ALL
        if household_child != (self.child_safe_household_approval_commitment is not None):
            raise ValueError("authorized_teaching_child_household_commitment_invalid")
        extended_child = child and self.maximum_duration_minutes > 30
        if extended_child != (self.child_extended_duration_commitment is not None):
            raise ValueError("authorized_teaching_child_duration_commitment_invalid")
        if not (
            self.request_issued_at <= self.authorized_at < self.request_expires_at
            and self.authorized_at < self.expires_at
            <= min(self.authorized_at + timedelta(seconds=5), self.request_expires_at)
        ):
            raise ValueError("authorized_teaching_request_window_invalid")
        return self

class TeachingAuthorizationDecisionV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    request_id: UUID
    request_content_commitment: HmacCommitment
    request_expires_at: AwareDatetime
    effect: Literal["allow", "deny"]
    authorized_request: AuthorizedTeachingRequestV1 | None
    reason_code: SafeReasonCode
    decided_at: AwareDatetime
    valid_until: AwareDatetime
    decision_commitment: HmacCommitment

    @model_validator(mode="after")
    def exact_teaching_decision(self) -> "TeachingAuthorizationDecisionV1":
        if (self.effect == "allow") != (self.authorized_request is not None):
            raise ValueError("teaching_decision_authority_shape_invalid")
        if self.authorized_request is not None and (
            self.authorized_request.request_id != self.request_id
            or self.authorized_request.request_content_commitment != self.request_content_commitment
            or self.authorized_request.request_expires_at != self.request_expires_at
            or not self.authorized_request.authorized_at <= self.decided_at < self.authorized_request.expires_at
            or self.valid_until > self.authorized_request.expires_at
        ):
            raise ValueError("teaching_decision_request_binding_invalid")
        if not (
            self.decided_at < self.valid_until
            <= min(self.decided_at + timedelta(seconds=5), self.request_expires_at)
        ):
            raise ValueError("teaching_decision_window_invalid")
        return self

def _validate_teaching_text(value: object) -> str:
    if not isinstance(value, str) or not value or contains_markup_url_hidden_or_bidi(value):
        raise ValueError("teaching_text_invalid")
    return value

TeachingText = Annotated[str, BeforeValidator(_validate_teaching_text)]

class TitleComponentV1(WholeHomeContract):
    component_type: Literal["title"]
    component_id: UUID
    text: Annotated[TeachingText, Field(max_length=160)]

class ParagraphComponentV1(WholeHomeContract):
    component_type: Literal["paragraph"]
    component_id: UUID
    text: Annotated[TeachingText, Field(max_length=2_000)]

class ImageAssetComponentV1(WholeHomeContract):
    component_type: Literal["image_asset"]
    component_id: UUID
    asset_id: UUID
    alt_text: Annotated[TeachingText, Field(max_length=240)]

class VocabularyCardComponentV1(WholeHomeContract):
    component_type: Literal["vocabulary_card"]
    component_id: UUID
    term: Annotated[TeachingText, Field(max_length=80)]
    definition: Annotated[TeachingText, Field(max_length=480)]

class MultipleChoiceComponentV1(WholeHomeContract):
    component_type: Literal["multiple_choice"]
    component_id: UUID
    prompt: Annotated[TeachingText, Field(max_length=480)]
    choices: Annotated[tuple[Annotated[TeachingText, Field(max_length=240)], ...], Field(min_length=2, max_length=6)]
    correct_choice_index: Annotated[int, Field(ge=0, le=5)]

    @model_validator(mode="after")
    def valid_choice_index(self) -> "MultipleChoiceComponentV1":
        if self.correct_choice_index >= len(self.choices):
            raise ValueError("teaching_choice_index_invalid")
        return self

class NumberLineComponentV1(WholeHomeContract):
    component_type: Literal["number_line"]
    component_id: UUID
    minimum: Annotated[int, Field(ge=-10_000, le=10_000)]
    maximum: Annotated[int, Field(ge=-10_000, le=10_000)]
    marker: Annotated[int, Field(ge=-10_000, le=10_000)]

    @model_validator(mode="after")
    def ordered_number_line(self) -> "NumberLineComponentV1":
        if not self.minimum < self.maximum or not self.minimum <= self.marker <= self.maximum:
            raise ValueError("teaching_number_line_invalid")
        return self

class TimerComponentV1(WholeHomeContract):
    component_type: Literal["timer"]
    component_id: UUID
    duration_seconds: Annotated[int, Field(ge=1, le=3_600)]

class ProgressComponentV1(WholeHomeContract):
    component_type: Literal["progress"]
    component_id: UUID
    completed: Annotated[int, Field(ge=0, le=1_000)]
    total: Annotated[int, Field(ge=1, le=1_000)]

    @model_validator(mode="after")
    def bounded_progress(self) -> "ProgressComponentV1":
        if self.completed > self.total:
            raise ValueError("teaching_progress_invalid")
        return self

class CitationComponentV1(WholeHomeContract):
    component_type: Literal["citation"]
    component_id: UUID
    label: Annotated[TeachingText, Field(max_length=240)]
    provenance_commitment: HmacCommitment

TeachingComponentV1 = Annotated[
    TitleComponentV1 | ParagraphComponentV1 | ImageAssetComponentV1 | VocabularyCardComponentV1 |
    MultipleChoiceComponentV1 | NumberLineComponentV1 | TimerComponentV1 | ProgressComponentV1 |
    CitationComponentV1,
    Field(discriminator="component_type"),
]

class TeachingAssetV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    asset_id: UUID
    content_hash: Sha256Digest
    media_type: Literal["image/jpeg", "image/png", "image/webp"]
    byte_length: Annotated[int, Field(ge=1, le=5 * 1024 * 1024)]
    local_fetch_handle: Annotated[str, Field(min_length=22, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")]
    issued_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def bounded_asset_handle(self) -> "TeachingAssetV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(minutes=5):
            raise ValueError("teaching_asset_handle_window_invalid")
        return self

class TeachingSessionManifestV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    session_id: UUID
    manifest_version: Annotated[int, Field(ge=1)]
    renderer_endpoint_id: StableEndpointId
    renderer_endpoint_generation: Annotated[int, Field(ge=1)]
    renderer_binding_generation: Annotated[int, Field(ge=1)]
    renderer_capability_generation: Annotated[int, Field(ge=1)]
    renderer_capability_evidence_digest: Sha256Digest
    display_endpoint_id: StableEndpointId
    display_endpoint_generation: Annotated[int, Field(ge=1)]
    display_binding_generation: Annotated[int, Field(ge=1)]
    display_capability_generation: Annotated[int, Field(ge=1)]
    display_capability_evidence_digest: Sha256Digest
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    audience_class: Literal["adult", "k2_child", "n1_child", "guest"]
    memory_audience: MemoryAudience | None
    presentation_policy: Literal["personalized", "generic_guest_public"]
    audience_binding_commitment: HmacCommitment
    privacy_generation: Annotated[int, Field(ge=1)]
    child_safe_household_approval_commitment: HmacCommitment | None
    language_mode: Literal["en", "hi", "hinglish"]
    web_mode: Literal["no_web", "controlled"]
    maximum_duration_minutes: Annotated[int, Field(ge=1, le=120)]
    teaching_policy_version: Annotated[int, Field(ge=1)]
    teaching_authorization_commitment: HmacCommitment
    screen_time_session_ref: UUID | None
    screen_time_session_commitment: HmacCommitment | None
    screen_time_session_expires_at: AwareDatetime | None
    screen_time_policy_version: Annotated[int | None, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    child_extended_duration_commitment: HmacCommitment | None
    components: Annotated[tuple[TeachingComponentV1, ...], Field(min_length=1, max_length=64)]
    assets: Annotated[tuple[TeachingAssetV1, ...], Field(max_length=16)]
    manifest_digest: Sha256Digest
    signing_key_id: KeyId
    signature: P256Signature

    @model_validator(mode="after")
    def coherent_teaching_manifest(self) -> "TeachingSessionManifestV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(
            minutes=self.maximum_duration_minutes,
        ):
            raise ValueError("teaching_manifest_window_invalid")
        if self.audience_class == "guest":
            if (
                self.memory_audience is not None
                or self.presentation_policy != "generic_guest_public"
                or self.child_safe_household_approval_commitment is not None
            ):
                raise ValueError("guest_teaching_manifest_audience_widened")
        elif self.memory_audience is None or self.presentation_policy != "personalized":
            raise ValueError("identified_teaching_manifest_audience_missing")
        child = self.audience_class in {"k2_child", "n1_child"}
        screen_time_authority = (
            self.screen_time_session_ref,
            self.screen_time_session_commitment,
            self.screen_time_session_expires_at,
            self.screen_time_policy_version,
        )
        if child != all(value is not None for value in screen_time_authority):
            raise ValueError("teaching_manifest_child_screen_time_shape_invalid")
        if any(value is not None for value in screen_time_authority) != all(
            value is not None for value in screen_time_authority
        ):
            raise ValueError("teaching_manifest_screen_time_authority_incomplete")
        if child and self.expires_at > self.screen_time_session_expires_at:
            raise ValueError("teaching_manifest_outlives_screen_time_session")
        if child:
            if self.memory_audience not in {MemoryAudience.GUARDIAN_CHILD, MemoryAudience.HOUSEHOLD_ALL}:
                raise ValueError("child_teaching_manifest_memory_audience_invalid")
            if (
                self.memory_audience == MemoryAudience.HOUSEHOLD_ALL
            ) != (self.child_safe_household_approval_commitment is not None):
                raise ValueError("child_teaching_manifest_household_approval_invalid")
            if self.web_mode != "no_web":
                raise ValueError("child_teaching_manifest_web_mode_invalid")
            if self.expires_at > self.issued_at + timedelta(minutes=30) and self.child_extended_duration_commitment is None:
                raise ValueError("child_teaching_extension_unbound")
        elif self.audience_class == "guest":
            if self.web_mode != "no_web":
                raise ValueError("guest_teaching_manifest_web_mode_invalid")
            if (
                self.child_extended_duration_commitment is not None
                or self.child_safe_household_approval_commitment is not None
            ):
                raise ValueError("guest_teaching_manifest_child_authority_forbidden")
        else:
            if self.child_extended_duration_commitment is not None:
                raise ValueError("nonchild_teaching_extension_invalid")
            if self.child_safe_household_approval_commitment is not None:
                raise ValueError("nonchild_teaching_household_approval_forbidden")
            if self.memory_audience not in {
                MemoryAudience.SUBJECT_PRIVATE,
                MemoryAudience.HOUSEHOLD_ADULTS,
                MemoryAudience.HOUSEHOLD_ALL,
            }:
                raise ValueError("adult_teaching_manifest_memory_audience_invalid")
        component_ids = tuple(component.component_id for component in self.components)
        asset_ids = tuple(asset.asset_id for asset in self.assets)
        if len(set(component_ids)) != len(component_ids) or len(set(asset_ids)) != len(asset_ids):
            raise ValueError("duplicate_teaching_component_or_asset")
        referenced_assets = {component.asset_id for component in self.components if isinstance(component, ImageAssetComponentV1)}
        if referenced_assets != set(asset_ids):
            raise ValueError("teaching_manifest_asset_set_not_exact")
        if any(
            not self.issued_at <= asset.issued_at < asset.expires_at <= self.expires_at
            for asset in self.assets
        ):
            raise ValueError("teaching_asset_window_outside_manifest")
        if self.manifest_digest != teaching_manifest_authority_digest(self):
            raise ValueError("teaching_manifest_digest_mismatch")
        return self

def teaching_manifest_authority_digest(manifest: TeachingSessionManifestV1) -> Sha256Digest:
    unsigned = manifest.model_dump(
        mode="python",
        exclude={"manifest_digest", "signing_key_id", "signature"},
    )
    return sha256(canonical_json_bytes(unsigned)).hexdigest()

TEACHING_MANIFEST_SIGNATURE_AUTHORITY_FIELDS = (
    "session_id", "manifest_version",
    "renderer_endpoint_id", "renderer_endpoint_generation",
    "renderer_binding_generation", "renderer_capability_generation",
    "renderer_capability_evidence_digest",
    "display_endpoint_id", "display_endpoint_generation",
    "display_binding_generation", "display_capability_generation",
    "display_capability_evidence_digest", "area_id", "area_generation",
    "audience_class", "memory_audience", "presentation_policy",
    "audience_binding_commitment", "privacy_generation",
    "child_safe_household_approval_commitment", "language_mode", "web_mode",
    "maximum_duration_minutes", "teaching_policy_version",
    "teaching_authorization_commitment", "screen_time_session_ref",
    "screen_time_session_commitment", "screen_time_session_expires_at",
    "screen_time_policy_version", "issued_at", "expires_at",
    "child_extended_duration_commitment",
)

def canonical_teaching_manifest_signature_bytes(
    manifest: TeachingSessionManifestV1,
) -> bytes:
    authority = manifest.model_dump(
        mode="python",
        include=set(TEACHING_MANIFEST_SIGNATURE_AUTHORITY_FIELDS),
    )
    return canonical_json_bytes({
        "signature_domain": "tuntun-display-manifest-v1",
        "manifest_digest": manifest.manifest_digest,
        "authority": authority,
    })

@dataclass(frozen=True, slots=True)
class EphemeralLearningSummary:
    summary_id: UUID
    teaching_session_id: UUID
    topic_code: Literal[
        "literacy", "numeracy", "general_knowledge", "creative",
        "language_practice", "other",
    ]
    duration_class: Literal[
        "under_5_minutes", "5_to_15_minutes", "16_to_30_minutes", "over_30_minutes",
    ]
    completion_class: Literal["started", "partial", "completed", "stopped"]
    created_at: AwareDatetime
    expires_at: AwareDatetime

    def __post_init__(self) -> None:
        if not self.created_at < self.expires_at <= self.created_at + timedelta(minutes=5):
            raise ValueError("ephemeral_learning_summary_window_invalid")

TVOperation = Literal[
    "tv.set_power.v1", "tv.select_input.v1", "tv.set_volume.v1",
    "tv.mute.v1", "tv.send_key.v1", "tv.launch_app.v1",
]
TVObservationDimension = Literal["power", "input", "volume", "mute", "playback"]

class TVControlBindingV1(WholeHomeContract):
    operation: TVOperation
    primary_control_adapter_id: StableEndpointId
    capability_generation: Annotated[int, Field(ge=1)]
    control_generation: Annotated[int, Field(ge=1)]
    capability_evidence_id: UUID

class TVObservationBindingV1(WholeHomeContract):
    dimension: TVObservationDimension
    observation_adapter_id: StableEndpointId
    observation_strength: Literal[
        "command_ack_only", "mirrored_optimistic", "same_adapter_observed",
        "out_of_band_observed", "independence_proven",
    ]
    capability_generation: Annotated[int, Field(ge=1)]
    observation_generation: Annotated[int, Field(ge=1)]
    capability_evidence_id: UUID

class TelevisionBindingV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    tv_endpoint_id: StableEndpointId
    endpoint_generation: Annotated[int, Field(ge=1)]
    inventory_id: StableEndpointId
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    safe_household_label: Annotated[TeachingText, Field(max_length=80)]
    exact_model_commitment: HmacCommitment
    platform_version_commitment: HmacCommitment
    firmware_commitment: HmacCommitment
    control_bindings: Annotated[tuple[TVControlBindingV1, ...], Field(max_length=6)]
    observation_bindings: Annotated[tuple[TVObservationBindingV1, ...], Field(max_length=5)]
    lifecycle_state: Literal["candidate", "commissioned", "degraded", "quarantined", "retired"]
    screen_time_power_eligibility: TVPowerEligibilityV1
    topology_generation: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    binding_digest: Sha256Digest

    @model_validator(mode="after")
    def exact_tv_binding_routes(self) -> "TelevisionBindingV1":
        controls = tuple(binding.operation for binding in self.control_bindings)
        observations = tuple(binding.dimension for binding in self.observation_bindings)
        if len(set(controls)) != len(controls) or len(set(observations)) != len(observations):
            raise ValueError("duplicate_tv_binding_capability")
        if self.lifecycle_state != "commissioned" and (controls or observations):
            raise ValueError("inactive_tv_cannot_have_active_adapter_route")
        if any(
            binding.capability_generation != self.capability_generation
            for binding in (*self.control_bindings, *self.observation_bindings)
        ):
            raise ValueError("tv_nested_capability_generation_mismatch")
        power = self.screen_time_power_eligibility
        if (
            power.endpoint_id != self.tv_endpoint_id
            or power.endpoint_generation != self.endpoint_generation
            or power.capability_generation != self.capability_generation
        ):
            raise ValueError("tv_power_eligibility_binding_mismatch")
        live_power_states = {
            "DISPLAY_ONLY_MANUAL", "OBSERVE_ONLY",
            "COOPERATIVE_ELIGIBLE", "STRICT_ELIGIBLE",
        }
        if self.lifecycle_state == "candidate" and power.state != "UNCOMMISSIONED":
            raise ValueError("candidate_tv_must_be_power_uncommissioned")
        if power.state == "UNCOMMISSIONED" and self.lifecycle_state != "candidate":
            raise ValueError("power_uncommissioned_tv_must_be_candidate")
        if self.lifecycle_state == "degraded" and power.state != "DEGRADED":
            raise ValueError("degraded_tv_power_eligibility_mismatch")
        if power.state == "DEGRADED" and self.lifecycle_state != "degraded":
            raise ValueError("power_degraded_tv_must_have_degraded_lifecycle")
        if power.state in live_power_states and self.lifecycle_state != "commissioned":
            raise ValueError("live_tv_power_eligibility_requires_commissioned_binding")
        if self.lifecycle_state == "quarantined" and power.state != "QUARANTINED":
            raise ValueError("quarantined_tv_power_eligibility_mismatch")
        if power.state == "QUARANTINED" and self.lifecycle_state != "quarantined":
            raise ValueError("power_quarantined_tv_must_have_quarantined_lifecycle")
        if self.lifecycle_state == "retired" and power.state != "RETIRED":
            raise ValueError("retired_tv_power_eligibility_mismatch")
        if power.state == "RETIRED" and self.lifecycle_state != "retired":
            raise ValueError("power_retired_tv_must_have_retired_lifecycle")
        if power.standby_control_operation is not None:
            matching_controls = tuple(
                binding for binding in self.control_bindings
                if binding.operation == power.standby_control_operation
            )
            if len(matching_controls) != 1 or matching_controls[0].control_generation != power.standby_control_generation:
                raise ValueError("tv_power_control_not_in_generic_capabilities")
        if power.power_observation_dimension is not None:
            matching_observations = tuple(
                binding for binding in self.observation_bindings
                if binding.dimension == power.power_observation_dimension
            )
            if len(matching_observations) != 1 or matching_observations[0].observation_generation != power.power_observation_generation:
                raise ValueError("tv_power_observation_not_in_generic_capabilities")
        return self

class TVCapabilityEvidenceV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    evidence_id: UUID
    tv_endpoint_id: StableEndpointId
    adapter_id: StableEndpointId
    evidence_kind: Literal["control", "observation"]
    operation: TVOperation | None
    dimension: TVObservationDimension | None
    observation_strength: Literal[
        "command_ack_only", "mirrored_optimistic", "same_adapter_observed",
        "out_of_band_observed", "independence_proven",
    ] | None
    result: Literal["passed", "failed", "unknown"]
    exact_model_commitment: HmacCommitment
    platform_version_commitment: HmacCommitment
    firmware_commitment: HmacCommitment
    configuration_digest: Sha256Digest
    test_evidence_digest: Sha256Digest
    capability_generation: Annotated[int, Field(ge=1)]
    tested_at: AwareDatetime

    @model_validator(mode="after")
    def exact_tv_evidence_shape(self) -> "TVCapabilityEvidenceV1":
        if self.evidence_kind == "control":
            if self.operation is None or self.dimension is not None or self.observation_strength is not None:
                raise ValueError("tv_control_evidence_shape_invalid")
        elif self.operation is not None or self.dimension is None or self.observation_strength is None:
            raise ValueError("tv_observation_evidence_shape_invalid")
        return self

class ManualOverrideEventV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    event_id: UUID
    tv_endpoint_id: StableEndpointId
    screen_time_session_id: UUID
    enforcement_generation: Annotated[int, Field(ge=1)]
    source: Literal[
        "physical_remote", "physical_button", "renderer_stop", "contrary_observation",
        "input_change", "power_change",
    ]
    observation_adapter_id: StableEndpointId | None
    observed_at: AwareDatetime
    source_receipt_commitment: HmacCommitment

    @model_validator(mode="after")
    def exact_manual_override_source(self) -> "ManualOverrideEventV1":
        observation_derived = self.source in {
            "contrary_observation", "input_change", "power_change",
        }
        if observation_derived != (self.observation_adapter_id is not None):
            raise ValueError("manual_override_observation_adapter_shape_invalid")
        return self

DisplayClearReason = Literal[
    "owner_stop", "privacy_shield", "identity_downgrade", "expiry",
    "screen_time_end", "renderer_error",
]

class DisplayReceiptV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    session_id: UUID
    manifest_version: Annotated[int, Field(ge=1)]
    renderer_endpoint_id: StableEndpointId
    renderer_endpoint_generation: Annotated[int, Field(ge=1)]
    renderer_binding_generation: Annotated[int, Field(ge=1)]
    renderer_capability_generation: Annotated[int, Field(ge=1)]
    renderer_capability_evidence_digest: Sha256Digest
    display_endpoint_id: StableEndpointId
    display_endpoint_generation: Annotated[int, Field(ge=1)]
    display_binding_generation: Annotated[int, Field(ge=1)]
    display_capability_generation: Annotated[int, Field(ge=1)]
    display_capability_evidence_digest: Sha256Digest
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    state: Literal["validated", "ready", "rendered", "cleared", "expired", "error_safe", "unverified"]
    manifest_digest: Sha256Digest
    manifest_issued_at: AwareDatetime
    manifest_expires_at: AwareDatetime
    receipt_sequence: Annotated[int, Field(ge=1)]
    rendered_at: AwareDatetime | None
    cleared_at: AwareDatetime | None
    clear_request_id: UUID | None
    clear_request_issuer: Literal["core", "renderer_local_safety"] | None
    clear_reason: DisplayClearReason | None
    clear_request_issued_at: AwareDatetime | None
    clear_request_expires_at: AwareDatetime | None
    clear_request_commitment: HmacCommitment | None
    hdmi_evidence: Literal["connected", "disconnected", "unknown"]
    privacy_generation: Annotated[int, Field(ge=1)]
    observed_at: AwareDatetime
    evidence_commitment: HmacCommitment
    renderer_key_id: KeyId
    renderer_signature: P256Signature

    @model_validator(mode="after")
    def coherent_display_receipt(self) -> "DisplayReceiptV1":
        if not self.manifest_issued_at < self.manifest_expires_at:
            raise ValueError("display_receipt_manifest_window_invalid")
        if self.observed_at < self.manifest_issued_at:
            raise ValueError("display_receipt_observation_predates_manifest")
        if self.state in {"validated", "ready", "rendered"} and not (
            self.observed_at < self.manifest_expires_at
        ):
            raise ValueError("active_display_receipt_at_or_after_manifest_expiry")
        clear_binding = (
            self.clear_request_id,
            self.clear_request_issuer,
            self.clear_reason,
            self.clear_request_issued_at,
            self.clear_request_expires_at,
            self.clear_request_commitment,
        )
        if (self.state == "cleared") != all(value is not None for value in clear_binding):
            raise ValueError("display_clear_receipt_binding_shape_invalid")
        if any(value is not None for value in clear_binding) != all(
            value is not None for value in clear_binding
        ):
            raise ValueError("display_clear_receipt_binding_incomplete")
        if (
            self.clear_request_issuer == "renderer_local_safety"
            and self.clear_reason not in {"owner_stop", "renderer_error"}
        ):
            raise ValueError("local_display_clear_reason_not_safety_bounded")
        if self.state == "rendered" and (self.rendered_at is None or self.cleared_at is not None):
            raise ValueError("rendered_display_evidence_invalid")
        if self.state in {"validated", "ready", "error_safe", "unverified"} and self.rendered_at is not None:
            raise ValueError("nonrendered_display_claims_render_time")
        if self.state in {"cleared", "expired"} and self.cleared_at is None:
            raise ValueError("terminal_display_missing_clear_time")
        if self.state not in {"cleared", "expired"} and self.cleared_at is not None:
            raise ValueError("nonterminal_display_claims_clear_time")
        if self.cleared_at is not None and self.rendered_at is not None and self.cleared_at < self.rendered_at:
            raise ValueError("display_clear_time_invalid")
        if self.rendered_at is not None and self.rendered_at > self.observed_at:
            raise ValueError("display_render_time_after_observation")
        if self.rendered_at is not None and not (
            self.manifest_issued_at <= self.rendered_at < self.manifest_expires_at
        ):
            raise ValueError("display_render_time_outside_manifest_window")
        if self.cleared_at is not None and self.cleared_at > self.observed_at:
            raise ValueError("display_clear_time_after_observation")
        if self.state == "cleared" and not (
            self.clear_request_issued_at
            <= self.cleared_at
            <= self.clear_request_expires_at
        ):
            raise ValueError("display_clear_outside_request_window")
        if self.state == "expired" and self.cleared_at < self.manifest_expires_at:
            raise ValueError("display_expiry_clear_predates_manifest_expiry")
        return self

class DisplayClearRequestV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    request_id: UUID
    teaching_session_id: UUID
    manifest_digest: Sha256Digest
    manifest_version: Annotated[int, Field(ge=1)]
    renderer_endpoint_id: StableEndpointId
    renderer_endpoint_generation: Annotated[int, Field(ge=1)]
    renderer_binding_generation: Annotated[int, Field(ge=1)]
    renderer_capability_generation: Annotated[int, Field(ge=1)]
    renderer_capability_evidence_digest: Sha256Digest
    display_endpoint_id: StableEndpointId
    display_endpoint_generation: Annotated[int, Field(ge=1)]
    display_binding_generation: Annotated[int, Field(ge=1)]
    display_capability_generation: Annotated[int, Field(ge=1)]
    display_capability_evidence_digest: Sha256Digest
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    issuer: Literal["core", "renderer_local_safety"]
    reason: DisplayClearReason
    privacy_generation: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    request_commitment: HmacCommitment
    key_id: KeyId
    signature: P256Signature

    @model_validator(mode="after")
    def bounded_clear_request(self) -> "DisplayClearRequestV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("display_clear_window_invalid")
        if self.issuer == "renderer_local_safety" and self.reason not in {
            "owner_stop", "renderer_error",
        }:
            raise ValueError("local_display_clear_reason_not_safety_bounded")
        return self

class AuthorizedTVRequestV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    request_id: UUID
    tv_endpoint_id: StableEndpointId
    endpoint_generation: Annotated[int, Field(ge=1)]
    control_adapter_id: StableEndpointId
    operation: TVOperation
    desired_power: Literal["ON", "STANDBY"] | None
    desired_input_id: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")] | None
    desired_volume_percent: Annotated[int, Field(ge=0, le=100)] | None
    desired_muted: bool | None
    desired_key: Literal["home", "back", "up", "down", "left", "right", "select"] | None
    desired_app_id: Annotated[str, Field(min_length=1, max_length=96, pattern=r"^[A-Za-z0-9_.:-]+$")] | None
    actor_class: Literal["owner", "adult", "system_screen_time"]
    actor_subject_id: UUID | None
    authorization_class: Literal[
        "adult_reversible_immediate", "exact_confirmation", "owner_passkey",
        "system_enforcement",
    ]
    controller_epoch: ControllerEpoch
    topology_generation: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    control_generation: Annotated[int, Field(ge=1)]
    authorization_generation: Annotated[int, Field(ge=1)]
    enforcement_generation: Annotated[int, Field(ge=1)] | None
    policy_version: Annotated[int, Field(ge=1)]
    authorized_at: AwareDatetime
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    idempotency_key: UUID
    request_binding_commitment: HmacCommitment

    @model_validator(mode="after")
    def exact_authorized_tv_request(self) -> "AuthorizedTVRequestV1":
        desired = {
            "tv.set_power.v1": self.desired_power,
            "tv.select_input.v1": self.desired_input_id,
            "tv.set_volume.v1": self.desired_volume_percent,
            "tv.mute.v1": self.desired_muted,
            "tv.send_key.v1": self.desired_key,
            "tv.launch_app.v1": self.desired_app_id,
        }
        if desired[self.operation] is None or sum(value is not None for value in desired.values()) != 1:
            raise ValueError("authorized_tv_request_desired_state_invalid")
        system = self.actor_class == "system_screen_time"
        if system:
            if self.actor_subject_id is not None or self.authorization_class != "system_enforcement" or self.enforcement_generation is None:
                raise ValueError("system_tv_request_authority_shape_invalid")
            if self.operation != "tv.set_power.v1" or self.desired_power != "STANDBY":
                raise ValueError("system_screen_time_may_only_request_standby")
        elif (
            self.actor_subject_id is None
            or self.authorization_class == "system_enforcement"
            or self.enforcement_generation is not None
        ):
            raise ValueError("human_tv_request_authority_shape_invalid")
        human_authorization_matrix = {
            "owner": {"adult_reversible_immediate", "exact_confirmation", "owner_passkey"},
            "adult": {"adult_reversible_immediate", "exact_confirmation"},
        }
        if not system and self.authorization_class not in human_authorization_matrix[self.actor_class]:
            raise ValueError("human_tv_request_actor_authorization_mismatch")
        immediate_reversible = (
            self.operation == "tv.mute.v1"
            or (
                self.operation == "tv.send_key.v1"
                and self.desired_key in {"home", "back", "up", "down", "left", "right"}
            )
        )
        if (
            not system
            and self.authorization_class == "adult_reversible_immediate"
            and not immediate_reversible
        ):
            raise ValueError("human_tv_request_under_assured_for_operation")
        if media_tv_authority_window_failures(
            self.authorized_at, self.issued_at, self.expires_at,
        ):
            raise ValueError("authorized_tv_request_window_invalid")
        return self

class SignedTVActionV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    action_id: UUID
    request_id: UUID
    tv_endpoint_id: StableEndpointId
    endpoint_generation: Annotated[int, Field(ge=1)]
    control_adapter_id: StableEndpointId
    operation: TVOperation
    desired_power: Literal["ON", "STANDBY"] | None
    desired_input_id: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")] | None
    desired_volume_percent: Annotated[int, Field(ge=0, le=100)] | None
    desired_muted: bool | None
    desired_key: Literal["home", "back", "up", "down", "left", "right", "select"] | None
    desired_app_id: Annotated[str, Field(min_length=1, max_length=96, pattern=r"^[A-Za-z0-9_.:-]+$")] | None
    controller_epoch: ControllerEpoch
    topology_generation: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    control_generation: Annotated[int, Field(ge=1)]
    authorization_generation: Annotated[int, Field(ge=1)]
    enforcement_generation: Annotated[int, Field(ge=1)] | None
    policy_version: Annotated[int, Field(ge=1)]
    idempotency_key: UUID
    request_binding_commitment: HmacCommitment
    authorized_at: AwareDatetime
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    reconciliation_deadline: AwareDatetime
    authorization_commitment: HmacCommitment
    signing_key_id: KeyId
    signature: P256Signature

    @model_validator(mode="after")
    def exact_tv_action_shape(self) -> "SignedTVActionV1":
        desired = {
            "tv.set_power.v1": self.desired_power,
            "tv.select_input.v1": self.desired_input_id,
            "tv.set_volume.v1": self.desired_volume_percent,
            "tv.mute.v1": self.desired_muted,
            "tv.send_key.v1": self.desired_key,
            "tv.launch_app.v1": self.desired_app_id,
        }
        if desired[self.operation] is None or sum(value is not None for value in desired.values()) != 1:
            raise ValueError("tv_action_desired_state_invalid")
        if media_tv_authority_window_failures(
            self.authorized_at, self.issued_at, self.expires_at,
        ):
            raise ValueError("tv_action_window_invalid")
        if not (
            self.expires_at
            <= self.reconciliation_deadline
            <= self.expires_at + timedelta(seconds=5)
        ):
            raise ValueError("tv_action_reconciliation_window_invalid")
        return self

class TVActionDispatchReceiptV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    record_kind: Literal["adapter_receipt"]
    action_id: UUID
    request_id: UUID
    idempotency_key: UUID
    signed_action_digest: Sha256Digest
    request_binding_commitment: HmacCommitment
    tv_endpoint_id: StableEndpointId
    endpoint_generation: Annotated[int, Field(ge=1)]
    control_adapter_id: StableEndpointId
    operation: TVOperation
    desired_power: Literal["ON", "STANDBY"] | None
    desired_input_id: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")] | None
    desired_volume_percent: Annotated[int, Field(ge=0, le=100)] | None
    desired_muted: bool | None
    desired_key: Literal["home", "back", "up", "down", "left", "right", "select"] | None
    desired_app_id: Annotated[str, Field(min_length=1, max_length=96, pattern=r"^[A-Za-z0-9_.:-]+$")] | None
    state: Literal[
        "accepted", "rejected", "unverified", "error_safe", "expired",
    ]
    dispatch_attempt: Literal[0, 1]
    dispatch_started_at: AwareDatetime | None
    adapter_context_commitment: HmacCommitment | None
    effect_commitment: HmacCommitment | None
    controller_epoch: ControllerEpoch
    topology_generation: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    control_generation: Annotated[int, Field(ge=1)]
    authorization_generation: Annotated[int, Field(ge=1)]
    enforcement_generation: Annotated[int, Field(ge=1)] | None
    policy_version: Annotated[int, Field(ge=1)]
    authorization_commitment: HmacCommitment
    authorized_at: AwareDatetime
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    reconciliation_deadline: AwareDatetime
    observed_at: AwareDatetime
    evidence_commitment: HmacCommitment
    adapter_key_id: KeyId
    adapter_signature: P256Signature

    @model_validator(mode="after")
    def coherent_tv_control_receipt(self) -> "TVActionDispatchReceiptV1":
        desired = {
            "tv.set_power.v1": self.desired_power,
            "tv.select_input.v1": self.desired_input_id,
            "tv.set_volume.v1": self.desired_volume_percent,
            "tv.mute.v1": self.desired_muted,
            "tv.send_key.v1": self.desired_key,
            "tv.launch_app.v1": self.desired_app_id,
        }
        if desired[self.operation] is None or sum(value is not None for value in desired.values()) != 1:
            raise ValueError("tv_receipt_desired_state_invalid")
        if media_tv_authority_window_failures(
            self.authorized_at, self.issued_at, self.expires_at,
        ):
            raise ValueError("tv_receipt_action_window_invalid")
        if self.observed_at < self.issued_at:
            raise ValueError("tv_receipt_observation_predates_issue")
        if not (
            self.expires_at
            <= self.reconciliation_deadline
            <= self.expires_at + timedelta(seconds=5)
        ):
            raise ValueError("tv_receipt_reconciliation_window_invalid")
        if self.observed_at > self.reconciliation_deadline:
            raise ValueError("tv_receipt_after_reconciliation_deadline")
        if self.state in {"accepted", "unverified"} and self.dispatch_attempt != 1:
            raise ValueError("tv_control_receipt_without_attempt")
        if self.state in {"rejected", "expired"} and self.dispatch_attempt != 0:
            raise ValueError("undispatched_tv_control_state_claims_attempt")
        evidence = (
            self.dispatch_started_at,
            self.adapter_context_commitment,
            self.effect_commitment,
        )
        if (self.dispatch_attempt == 1) != all(value is not None for value in evidence):
            raise ValueError("tv_dispatch_context_evidence_shape_invalid")
        if self.dispatch_attempt == 0 and any(value is not None for value in evidence):
            raise ValueError("undispatched_tv_receipt_carries_effect_evidence")
        if self.dispatch_started_at is not None and self.observed_at < self.dispatch_started_at:
            raise ValueError("tv_receipt_observation_predates_dispatch")
        if self.dispatch_started_at is not None and not (
            self.issued_at <= self.dispatch_started_at < self.expires_at
        ):
            raise ValueError("tv_receipt_dispatch_outside_action_window")
        if self.state == "expired":
            if self.observed_at < self.expires_at:
                raise ValueError("tv_receipt_expired_before_deadline")
        elif self.dispatch_attempt == 0 and self.observed_at >= self.expires_at:
            raise ValueError("undispatched_tv_receipt_at_deadline_must_be_expired")
        return self

class TVDispatchUnknownTerminalV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    record_kind: Literal["core_unknown_terminal"]
    terminal_id: UUID
    action_id: UUID
    request_id: UUID
    idempotency_key: UUID
    signed_action_digest: Sha256Digest
    request_binding_commitment: HmacCommitment
    tv_endpoint_id: StableEndpointId
    endpoint_generation: Annotated[int, Field(ge=1)]
    control_adapter_id: StableEndpointId
    operation: TVOperation
    desired_power: Literal["ON", "STANDBY"] | None
    desired_input_id: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")] | None
    desired_volume_percent: Annotated[int, Field(ge=0, le=100)] | None
    desired_muted: bool | None
    desired_key: Literal["home", "back", "up", "down", "left", "right", "select"] | None
    desired_app_id: Annotated[str, Field(min_length=1, max_length=96, pattern=r"^[A-Za-z0-9_.:-]+$")] | None
    dispatch_attempt: Literal[1]
    dispatch_started_at: AwareDatetime
    adapter_context_commitment: HmacCommitment
    effect_commitment: HmacCommitment
    dispatch_proof_commitment: HmacCommitment
    controller_epoch: ControllerEpoch
    topology_generation: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    control_generation: Annotated[int, Field(ge=1)]
    authorization_generation: Annotated[int, Field(ge=1)]
    enforcement_generation: Annotated[int, Field(ge=1)] | None
    policy_version: Annotated[int, Field(ge=1)]
    authorization_commitment: HmacCommitment
    authorized_at: AwareDatetime
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    reconciliation_deadline: AwareDatetime
    terminal_at: AwareDatetime
    materialized_at: AwareDatetime
    terminal_reason: Literal["reconciliation_deadline_elapsed"]
    terminal_commitment: HmacCommitment
    core_key_id: KeyId
    core_signature: P256Signature

    @model_validator(mode="after")
    def coherent_tv_unknown_terminal(self) -> "TVDispatchUnknownTerminalV1":
        desired = {
            "tv.set_power.v1": self.desired_power,
            "tv.select_input.v1": self.desired_input_id,
            "tv.set_volume.v1": self.desired_volume_percent,
            "tv.mute.v1": self.desired_muted,
            "tv.send_key.v1": self.desired_key,
            "tv.launch_app.v1": self.desired_app_id,
        }
        if desired[self.operation] is None or sum(value is not None for value in desired.values()) != 1:
            raise ValueError("tv_terminal_desired_state_invalid")
        if media_tv_authority_window_failures(
            self.authorized_at, self.issued_at, self.expires_at,
        ):
            raise ValueError("tv_terminal_action_window_invalid")
        if not (
            self.expires_at
            <= self.reconciliation_deadline
            <= self.expires_at + timedelta(seconds=5)
        ):
            raise ValueError("tv_terminal_reconciliation_window_invalid")
        if not self.issued_at <= self.dispatch_started_at < self.expires_at:
            raise ValueError("tv_terminal_dispatch_outside_action_window")
        if self.terminal_at != self.reconciliation_deadline:
            raise ValueError("tv_terminal_not_at_reconciliation_deadline")
        if self.materialized_at < self.terminal_at:
            raise ValueError("tv_terminal_materialized_before_deadline")
        return self

TVDispatchControlRecordV1 = Annotated[
    TVActionDispatchReceiptV1 | TVDispatchUnknownTerminalV1,
    Field(discriminator="record_kind"),
]

class TVObservedDimensionV1(WholeHomeContract):
    dimension: Literal["power", "input", "volume", "mute", "playback"]
    state: Literal["observed", "unknown"]
    power: Literal["ON", "STANDBY", "OFF"] | None
    input_id: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")] | None
    volume_percent: Annotated[int, Field(ge=0, le=100)] | None
    muted: bool | None
    playback: Literal["idle", "playing", "paused", "stopped", "buffering"] | None

    @model_validator(mode="after")
    def exact_observed_dimension(self) -> "TVObservedDimensionV1":
        values = {
            "power": self.power,
            "input": self.input_id,
            "volume": self.volume_percent,
            "mute": self.muted,
            "playback": self.playback,
        }
        populated = tuple(name for name, value in values.items() if value is not None)
        if self.state == "observed" and populated != (self.dimension,):
            raise ValueError("tv_observed_dimension_shape_invalid")
        if self.state == "unknown" and populated:
            raise ValueError("unknown_tv_dimension_has_value")
        return self

class WholeHomeTVObservationV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    request_id: UUID
    tv_endpoint_id: StableEndpointId
    endpoint_generation: Annotated[int, Field(ge=1)]
    observation_adapter_id: StableEndpointId
    dimensions: Annotated[tuple[TVObservedDimensionV1, ...], Field(min_length=1, max_length=5)]
    observation_strength: Literal[
        "command_ack_only", "mirrored_optimistic", "same_adapter_observed",
        "out_of_band_observed", "independence_proven",
    ]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    observation_generation: Annotated[int, Field(ge=1)]
    sampled_at: AwareDatetime
    ingested_at: AwareDatetime
    valid_until: AwareDatetime
    source_receipt_commitment: HmacCommitment
    adapter_key_id: KeyId
    adapter_signature: P256Signature

    @model_validator(mode="after")
    def coherent_tv_observation(self) -> "WholeHomeTVObservationV1":
        if not (
            self.sampled_at <= self.ingested_at <= self.sampled_at + timedelta(seconds=5)
            and self.ingested_at < self.valid_until <= self.ingested_at + timedelta(seconds=5)
        ):
            raise ValueError("tv_observation_window_invalid")
        names = tuple(dimension.dimension for dimension in self.dimensions)
        if len(set(names)) != len(names):
            raise ValueError("duplicate_tv_observed_dimension")
        return self

class TVObservationRequestV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    request_id: UUID
    tv_endpoint_id: StableEndpointId
    endpoint_generation: Annotated[int, Field(ge=1)]
    observation_adapter_id: StableEndpointId
    dimensions: Annotated[
        tuple[Literal["power", "input", "volume", "mute", "playback"], ...],
        Field(min_length=1, max_length=5),
    ]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    observation_generation: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    request_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_unique_observation_request(self) -> "TVObservationRequestV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("tv_observation_request_window_invalid")
        if len(set(self.dimensions)) != len(self.dimensions):
            raise ValueError("duplicate_tv_observation_dimension")
        return self

class Phase4MaintenanceRecordV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    record_id: UUID
    month_key: Annotated[str, Field(pattern=r"^[0-9]{4}-(0[1-9]|1[0-2])$")]
    subsystem: Literal["room_voice", "media", "display", "television", "screen_time"]
    record_class: Literal["ordinary", "excluded_event"]
    minutes: Annotated[int, Field(ge=1, le=1_440)]
    excluded_event_class: Literal[
        "initial_commissioning", "incident", "repair", "hardware_replacement",
        "major_migration", "quarterly_drill",
    ] | None
    occurred_at: AwareDatetime
    evidence_commitment: HmacCommitment

    @model_validator(mode="after")
    def exact_maintenance_class(self) -> "Phase4MaintenanceRecordV1":
        if (self.record_class == "excluded_event") != (self.excluded_event_class is not None):
            raise ValueError("phase4_maintenance_record_class_invalid")
        expected_month = self.occurred_at.astimezone(timezone.utc).strftime("%Y-%m")
        if self.month_key != expected_month:
            raise ValueError("phase4_maintenance_month_key_not_utc_event_month")
        return self
```

### Ports

```python
class SpeechEndpointPort(Protocol):
    async def send_control(self, endpoint_id: StableEndpointId, control: EndpointControlV1) -> PhysicalSafetyReceiptV1 | SafetyTransportFailureV1: ...
    async def play(self, endpoint_id: StableEndpointId, stream: AsyncIterator[SpeechPlaybackFrameV1]) -> PlaybackReceiptV1: ...
    async def health(self, endpoint_id: StableEndpointId) -> EndpointHealthV1: ...

class WakeArbiterPort(Protocol):
    async def arbitrate(self, claims: tuple[WakeClaimV1, ...], now: datetime) -> WakeArbitrationV1: ...

class ConversationAdmissionPort(Protocol):
    async def admit(self, winner: WakeArbitrationV1) -> ConversationAdmissionV1: ...
    async def cancel(self, conversation_id: UUID, reason: CancellationReason) -> ConversationCancellationReceiptV1: ...

class RoomReplyRouterPort(Protocol):
    async def resolve(self, request: ReplyRoutingRequestV1) -> ReplyRouteDecisionV1: ...

class MediaCatalogPort(Protocol):
    async def search(self, query: AuthorizedCatalogQueryV1) -> MediaCatalogResultV1: ...

class MediaPlaybackPort(Protocol):
    async def dispatch(self, envelope: SignedMediaEnvelopeV1) -> MediaDispatchReceiptV1: ...
    async def observe(self, player_id: StableEndpointId) -> PlayerObservationV1: ...

class DisplaySessionPort(Protocol):
    async def present(self, manifest: TeachingSessionManifestV1) -> DisplayReceiptV1: ...
    async def clear(self, request: DisplayClearRequestV1) -> DisplayReceiptV1: ...

class DisplayLifecycleIngressPort(Protocol):
    async def accept_receipt(self, receipt: DisplayReceiptV1) -> None: ...
    async def accept_renderer_local_clear(
        self, request: DisplayClearRequestV1, receipt: DisplayReceiptV1,
    ) -> None: ...

class TVControlPort(Protocol):
    async def dispatch(self, action: SignedTVActionV1) -> TVActionDispatchReceiptV1: ...

class TVObservationPort(Protocol):
    async def observe(self, request: TVObservationRequestV1) -> WholeHomeTVObservationV1: ...
```

No port accepts `dict[str, Any]`, a provider credential, a Home Assistant service/entity name, a playable URL, browser markup, arbitrary television key/code, subject identity, memory object, or general adapter token.

## Durable State and Migration Map

| Revision | Exact `down_revision` | Tables and invariants |
|---|---|---|
| `0016_whole_home_endpoints` | `0015_presence_checkpoint` | `speech_endpoint_registrations`, `area_voice_policies`, `area_occupant_consents`, `child_room_voice_approvals`, `endpoint_commissioning_evidence`, `conversation_admissions`, `conversation_transitions`, `handoff_tokens`, `speech_playback_terminal_frames`; every located row has the composite foreign key `(area_id, area_generation) -> home_areas(area_id, generation)`, never a naked `area_id` foreign key and never `room_id`; one nonterminal household slot row; terminal-frame rows contain only playback/lease lineage, final sequence/byte total, keyed frame commitment and time—never frame/audio bytes; no claim/audio/transcript/embedding; current exact privacy/capability generations; distinct owner/current-guardian approval constraint |
| `0017_media_and_display` | `0016_whole_home_endpoints` | `media_provider_bindings`, `provider_entitlement_reviews`, `media_player_bindings`, `media_player_commissioning_evidence`, `media_group_manifests`, `media_group_members`, `child_media_rules`, `child_media_rule_approvals`, `media_actions`, `media_action_transitions`, `media_target_transition_records`, `media_dispatch_unknown_terminals`, `media_late_dispatch_evidence`, `media_results`, `display_endpoint_bindings`, `teaching_sessions`, `teaching_manifest_authority_records`, `teaching_session_transitions`, `display_clear_requests`, `display_receipts`; every located player/member/display/session/rule row has the same composite current-generation area reference; player/group/rule activation uses owner-prepared exact CAS and groups/rules have one current immutable version; child rule approval is a distinct-current-guardian, one-use, exact-rule commitment; `media_actions` owns the immutable `(operation_id, request_id, action_id, signed_envelope_digest)` tuple, each canonical target has one immutable `not_dispatched\|dispatch_started` transition record, `media_dispatch_unknown_terminals` has one immutable Core-signed row per exact operation/envelope/attempt-proof set with fixed logical deadline plus actual materialization time, and `media_late_dispatch_evidence` has one immutable encrypted non-authoritative row per operation/adapter-receipt digest; display clear request/receipt sequence is immutable and replay-unique; the teaching authority record stores the signed manifest digest plus its complete non-content authority header/HMAC but no component text, asset descriptor/handle, or signed manifest body; no secret/query text/URL/path/lesson body/asset bytes/screenshot/learning-summary column; semantic updates are forbidden, and deletion is allowed only through FK-safe retention purge at or after each row's signed/committed retention deadline |
| `0018_television_capabilities` | `0017_media_and_display` | `television_inventory`, `tv_adapter_bindings`, `whole_home_tv_capability_evidence`, `tv_actions`, `tv_action_transitions`, `tv_dispatch_unknown_terminals`, `tv_late_dispatch_evidence`, `tv_observations`; every located TV inventory/binding authority has the same composite current-generation area reference; exact stable TV endpoint, one primary control binding per operation, optional distinct observation binding, generation invalidation, closed dimensions, one immutable Core-signed unknown terminal per exact action/attempt proof, and one immutable encrypted non-authoritative late-evidence row per action/adapter-receipt digest; no MAC/serial/token/account/arbitrary key map; the Phase 2-owned `tv_capability_evidence` table is not recreated or adopted |
| `0019_screen_time_real_adapter` | `0018_television_capabilities` | additive `screen_time_adapter_bindings`, `screen_time_enforcement_generations`, `screen_time_control_attempts`, `screen_time_manual_overrides`; every located adapter/enforcement authority retains the composite area reference; imported TV power state persists exactly `UNCOMMISSIONED\|DISPLAY_ONLY_MANUAL\|OBSERVE_ONLY\|COOPERATIVE_ELIGIBLE\|STRICT_ELIGIBLE\|DEGRADED\|QUARANTINED\|RETIRED` and remains lifecycle-coherent across restart/restore; existing Phase 2 policy/ledger/session authority is unchanged; attempt number constrained to 1 or 2 and unique per generation; manual/unknown terminal states block further insertion; no programme/viewer inference |

Claims, audio frames, pre-roll, catalog query text, catalog results, display assets, rendered pixels, and learning summaries are intentionally absent from the database. Short-lived catalog-handle commitments may be held in a bounded in-memory store; if crash recovery needs replay denial, persist only keyed handle digest, generation, expiry, and consumed state—not query/item text or provider URI.

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
uv run pytest -m "not phase4_hardware and not elapsed and not live_cloud" -q
uv run pytest integrations/home-assistant/tests integrations/music-assistant/tests -q
pnpm --filter @tuntun/admin e2e -- tests/ui/e2e/media-learning-*.spec.ts
pnpm --filter @tuntun/display-agent test
pnpm --filter @tuntun/display-agent build
```

Owner-gated commands write only to ignored `var/evidence/phase4/`:

```bash
TUNTUN_ALLOW_PHASE4_HARDWARE=1 uv run pytest -m phase4_hardware tests/hardware/whole_home -q
TUNTUN_ALLOW_ENDPOINT_PROBE=1 uv run python scripts/phase4/run_endpoint_bakeoff.py --candidate purchased --feature-manifest-chain var/evidence/phase4/feature-authority/task16/purchased/PURCHASED_CANDIDATE_DIGEST/signed-rollover-chain.json --duration-seconds 604800 --stress-seconds 28800 --evidence-root var/evidence/phase4/endpoints/purchased/PURCHASED_CANDIDATE_DIGEST
TUNTUN_ALLOW_ENDPOINT_PROBE=1 uv run python scripts/phase4/run_endpoint_bakeoff.py --candidate diy --feature-manifest-chain var/evidence/phase4/feature-authority/task16/diy/DIY_CANDIDATE_DIGEST/signed-rollover-chain.json --duration-seconds 604800 --stress-seconds 28800 --evidence-root var/evidence/phase4/endpoints/diy/DIY_CANDIDATE_DIGEST
TUNTUN_ALLOW_MEDIA_PROBE=1 uv run python scripts/phase4/qualify_media.py --evidence-root var/evidence/phase4/media
TUNTUN_ALLOW_DISPLAY_PROBE=1 uv run python scripts/phase4/pair_display.py --evidence-root var/evidence/phase4/display
TUNTUN_ALLOW_TV_PROBE=1 uv run python scripts/phase4/probe_television.py --inventory-id tv_samsung_neoled_49 --evidence-root var/evidence/phase4/televisions
TUNTUN_ALLOW_TV_PROBE=1 uv run python scripts/phase4/probe_television.py --inventory-id tv_tcl_42 --evidence-root var/evidence/phase4/televisions
TUNTUN_ALLOW_PHASE4_HARDWARE=1 uv run python scripts/phase4/run_area_rollout.py --area-id AREA_ID --area-generation AREA_GENERATION --endpoint-id ENDPOINT_ID --endpoint-generation ENDPOINT_GENERATION --placement-generation PLACEMENT_GENERATION --configuration-generation CONFIGURATION_GENERATION --consent-generation CONSENT_GENERATION --feature-manifest-chain var/evidence/phase4/feature-authority/task35/AREA_ID/AREA_GENERATION/ENDPOINT_ID/ENDPOINT_GENERATION/PLACEMENT_GENERATION/CONFIGURATION_GENERATION/CONSENT_GENERATION/signed-rollover-chain.json --duration-seconds 604800 --output var/evidence/phase4/areas/AREA_ID/AREA_GENERATION/ENDPOINT_ID/ENDPOINT_GENERATION/PLACEMENT_GENERATION/CONFIGURATION_GENERATION/CONSENT_GENERATION.json
TUNTUN_ALLOW_ELAPSED_PHASE4=1 uv run python scripts/phase4/run_acceptance.py household-soak --feature-manifest-chain var/evidence/phase4/feature-authority/task36/signed-rollover-chain.json --duration-seconds 604800 --sample-seconds 60 --commit "$(git rev-parse HEAD)" --evidence-root var/evidence/phase4/acceptance --output var/evidence/phase4/acceptance/household-soak.json
```

---

## Wave 0 — P4-E0/P4-0 Contracts, Simulation, Persistence, and Policy Amendments

### Task 01: Freeze strict Phase 4 contracts, ports, schemas, and synthetic fixtures

**Depends on:** accepted Phase 1/2 contract packages and the current Program A–H contract catalogue.
**Gate contribution:** P4-E0, P4-0.
**Estimated effort:** 2.5 person-days.

**Files:**

- Create every file under `packages/contracts/src/tuntun_contracts/whole_home/` named in the repository map.
- Modify `packages/contracts/src/tuntun_contracts/home/topology.py` and `packages/contracts/src/tuntun_contracts/ui.py` only additively; consume `packages/contracts/src/tuntun_contracts/home/screen_time.py` unchanged.
- Create `scripts/phase4/generate_schemas.py` and all six `schemas/whole-home/v1/*.schema.json` files.
- Create `fixtures/synthetic/whole-home/contracts/*.json` and `fixtures/synthetic/ui/phase4/*.json`.
- Test `tests/contract/whole_home/test_phase4_contracts.py`.
- Test `tests/property/whole_home/test_contract_rejection.py`.
- Test `tests/contract/whole_home/test_area_id_only.py`.

**Interfaces:** Produces the complete Frozen Contract and Port Baseline above; schema IDs `tuntun.whole-home.speech-endpoint.v1`, `tuntun.whole-home.wake-lease.v1`, `tuntun.whole-home.media.v1`, `tuntun.whole-home.teaching-manifest.v1`, `tuntun.whole-home.television.v1`, and `tuntun.whole-home.ui.v1`; signature domains `tuntun-endpoint-event-v1`, `tuntun-capture-lease-v1`, `tuntun-physical-safety-receipt-v1`, `tuntun-safety-transport-failure-v1`, `tuntun-media-v1`, `tuntun-media-group-v1`, `tuntun-child-media-rule-v1`, `tuntun-media-dispatch-unknown-terminal-v1`, `tuntun-display-manifest-v1`, `tuntun-display-receipt-v1`, `tuntun-display-clear-request-v1`, `tuntun-tv-action-v1`, `tuntun-tv-dispatch-receipt-v1`, `tuntun-tv-observation-v1`, and `tuntun-tv-dispatch-unknown-terminal-v1`, each with its exact registered key purpose. The media registry fixes `media_action`, `media_group_manifest`, `child_media_rule`, and `core_media_dispatch_unknown_terminal`; the TV registry fixes `tv_action`, `tv_dispatch_receipt`, `tv_observation`, and `core_tv_dispatch_unknown_terminal`. A key registered for one purpose cannot verify another type. Endpoint physical-safety receipts use `endpoint_safety_receipt`; core-created transport failures use `core_safety_transport_failure`, so neither can verify as the other or as a generic endpoint event. Phase 4 imports `EnforcementIntentV1`, `TVDispatchProofV1`, `TVObservationV1`, `TVPowerEligibilityV1`, and `TVControlReceiptV1` from `tuntun_contracts.home.screen_time`; it defines no local alias or model under any of those five names. It also imports the shared opaque Phase 2 `ControllerEpoch` from its canonical owner `tuntun_contracts.home.channel`, the Phase 1 `MemoryAudience` enum, and Phase 2 `AreaV1`/`CanonicalLocationRefV1` unchanged.

Canonical byte ownership is singular: every Phase 4 whole-model, mapping, exclusion, digest, and signature helper delegates to Phase 1 `canonical_mapping_bytes` over `model_dump(mode="python")`. `whole_home.base` has no second JCS dependency, key coercion, or timestamp normalizer.

- [ ] **Step 1: Write red strictness, signature-domain, and location tests**

```python
def test_wake_claim_is_metadata_only(valid_claim: dict[str, object]) -> None:
    claim = WakeClaimV1.model_validate(valid_claim)
    assert claim.area_id == "area_synth_common_01"
    forbidden = {"audio", "samples", "embedding", "speaker_id", "profile_id", "room_id"}
    assert forbidden.isdisjoint(claim.model_dump())

@pytest.mark.parametrize("model_name", [
    "speech_endpoint_registration", "wake_claim", "capture_lease", "conversation_admission",
    "reply_routing_request", "media_player_binding", "teaching_request",
    "authorized_teaching_request", "teaching_session_manifest", "television_binding",
])
def test_every_area_authority_rejects_missing_or_substituted_generation(model_name, phase4_contract_fixtures) -> None:
    model, payload = phase4_contract_fixtures[model_name]
    for mutation in ({"area_generation": None}, {"area_generation": payload["area_generation"] + 1}):
        with pytest.raises((ValidationError, StaleAreaAuthority)):
            validate_against_current_area(model, {**payload, **mutation})

@pytest.mark.parametrize(
    "mutation",
    [
        inject_room_id,
        inject_playable_url,
        inject_ha_service,
        inject_arbitrary_tv_key,
        inject_display_html,
        inject_learning_summary_body,
        add_unknown_field,
    ],
)
def test_boundary_contracts_reject_forbidden_shapes(
    phase4_contract_case: tuple[type[WholeHomeContract], dict[str, object]], mutation: Mutation
) -> None:
    model, payload = phase4_contract_case
    with pytest.raises(ValidationError):
        model.model_validate(mutation(payload))

def test_signature_domains_are_not_interchangeable(
    signer: TestSigner, media: SignedMediaEnvelopeV1
) -> None:
    unsigned = canonical_signed_media_envelope_unsigned_bytes(media)
    signature = signer.sign("tuntun-media-v1", unsigned, key_purpose="media_action")
    assert signer.verify(
        "tuntun-media-v1", unsigned, signature, key_purpose="media_action",
    )
    assert not signer.verify(
        "tuntun-tv-action-v1", unsigned, signature, key_purpose="media_action",
    )

MEDIA_SIGNED_DOMAINS = (
    ("tuntun-media-v1", "media_action"),
    ("tuntun-media-group-v1", "media_group_manifest"),
    ("tuntun-child-media-rule-v1", "child_media_rule"),
    (
        "tuntun-media-dispatch-unknown-terminal-v1",
        "core_media_dispatch_unknown_terminal",
    ),
)

@pytest.mark.parametrize(
    ("signed_domain", "signed_purpose", "replay_domain", "replay_purpose"),
    [
        (*signed, *replay)
        for signed in MEDIA_SIGNED_DOMAINS
        for replay in MEDIA_SIGNED_DOMAINS
        if signed != replay
    ],
)
def test_media_signed_types_reject_every_cross_domain_or_key_purpose_replay(
    signer, media_unsigned_bytes_by_domain, signed_domain, signed_purpose,
    replay_domain, replay_purpose,
) -> None:
    unsigned = media_unsigned_bytes_by_domain[signed_domain]
    signature = signer.sign(signed_domain, unsigned, key_purpose=signed_purpose)
    assert signer.verify(signed_domain, unsigned, signature, key_purpose=signed_purpose)
    assert not signer.verify(replay_domain, unsigned, signature, key_purpose=signed_purpose)
    assert not signer.verify(signed_domain, unsigned, signature, key_purpose=replay_purpose)

def test_group_manifest_digest_and_signature_cover_every_member_field(
    media_group_manifest, signer,
) -> None:
    signature_bytes = canonical_media_group_signature_bytes(media_group_manifest)
    signature = signer.sign(
        "tuntun-media-group-v1", signature_bytes,
        key_purpose="media_group_manifest",
    )
    assert signer.verify(
        "tuntun-media-group-v1", signature_bytes, signature,
        key_purpose="media_group_manifest",
    )
    for field in (
        "player_id", "area_id", "area_generation", "player_binding_generation",
        "player_capability_generation", "maximum_volume_percent",
    ):
        changed = substitute_group_member_field(media_group_manifest, field)
        with pytest.raises((ValidationError, SignatureRejected)):
            verify_media_group_manifest(changed)

TV_SIGNED_DOMAINS = (
    ("tuntun-tv-action-v1", "tv_action"),
    ("tuntun-tv-dispatch-receipt-v1", "tv_dispatch_receipt"),
    ("tuntun-tv-observation-v1", "tv_observation"),
    (
        "tuntun-tv-dispatch-unknown-terminal-v1",
        "core_tv_dispatch_unknown_terminal",
    ),
)

@pytest.mark.parametrize(
    ("signed_domain", "signed_purpose", "replay_domain", "replay_purpose"),
    [
        (*signed, *replay)
        for signed in TV_SIGNED_DOMAINS
        for replay in TV_SIGNED_DOMAINS
        if signed != replay
    ],
)
def test_tv_signed_types_reject_every_cross_domain_or_key_purpose_replay(
    signer, tv_unsigned_bytes_by_domain, signed_domain, signed_purpose,
    replay_domain, replay_purpose,
) -> None:
    unsigned = tv_unsigned_bytes_by_domain[signed_domain]
    signature = signer.sign(signed_domain, unsigned, key_purpose=signed_purpose)
    assert signer.verify(signed_domain, unsigned, signature, key_purpose=signed_purpose)
    assert not signer.verify(replay_domain, unsigned, signature, key_purpose=signed_purpose)
    assert not signer.verify(signed_domain, unsigned, signature, key_purpose=replay_purpose)

@pytest.mark.parametrize(("signed_domain", "signed_purpose", "replay_domain", "replay_purpose"), [
    ("tuntun-physical-safety-receipt-v1", "endpoint_safety_receipt",
     "tuntun-safety-transport-failure-v1", "core_safety_transport_failure"),
    ("tuntun-safety-transport-failure-v1", "core_safety_transport_failure",
     "tuntun-physical-safety-receipt-v1", "endpoint_safety_receipt"),
    ("tuntun-physical-safety-receipt-v1", "endpoint_safety_receipt",
     "tuntun-endpoint-event-v1", "endpoint_event"),
    ("tuntun-safety-transport-failure-v1", "core_safety_transport_failure",
     "tuntun-endpoint-event-v1", "endpoint_event"),
])
def test_physical_receipt_and_core_transport_failure_are_not_interchangeable(
    signer, safety_unsigned_bytes_by_domain, signed_domain, signed_purpose,
    replay_domain, replay_purpose,
) -> None:
    unsigned = safety_unsigned_bytes_by_domain[signed_domain]
    signature = signer.sign(signed_domain, unsigned, key_purpose=signed_purpose)
    assert signer.verify(signed_domain, unsigned, signature, key_purpose=signed_purpose)
    assert not signer.verify(replay_domain, unsigned, signature, key_purpose=signed_purpose)
    assert not signer.verify(signed_domain, unsigned, signature, key_purpose=replay_purpose)

@pytest.mark.parametrize(("signed_domain", "replay_domain", "key_purpose", "wrong_key_purpose"), [
    ("tuntun-display-manifest-v1", "tuntun-display-receipt-v1", "display_manifest", "renderer_receipt"),
    ("tuntun-display-receipt-v1", "tuntun-display-clear-request-v1", "renderer_receipt", "display_clear"),
    ("tuntun-display-clear-request-v1", "tuntun-display-manifest-v1", "display_clear", "display_manifest"),
])
def test_display_signature_domains_and_key_purposes_are_not_interchangeable(
    signer: TestSigner, display_unsigned_bytes_by_domain,
    signed_domain: str, replay_domain: str, key_purpose: str, wrong_key_purpose: str,
) -> None:
    unsigned = display_unsigned_bytes_by_domain[signed_domain]
    signature = signer.sign(signed_domain, unsigned, key_purpose=key_purpose)
    assert signer.verify(signed_domain, unsigned, signature, key_purpose=key_purpose)
    assert not signer.verify(replay_domain, unsigned, signature, key_purpose=key_purpose)
    assert not signer.verify(signed_domain, unsigned, signature, key_purpose=wrong_key_purpose)

def test_speech_playback_frame_declares_exact_bytes(speech_playback_frame_fixture) -> None:
    with pytest.raises(ValidationError):
        SpeechPlaybackFrameV1.model_validate({
            **speech_playback_frame_fixture,
            "byte_count": len(speech_playback_frame_fixture["frame_bytes"]) + 1,
        })

@pytest.mark.parametrize("mutation", [
    {"outcome": "partial", "bytes_accepted": 0, "last_sequence": None},
    {"outcome": "stopped", "bytes_accepted": 0, "last_sequence": None},
    {"outcome": "unverified", "started_at": None, "bytes_accepted": 3200},
    {"outcome": "error_safe", "started_at": None, "last_sequence": 0},
    {"outcome": "completed", "terminal_frame_commitment": None},
])
def test_playback_receipt_progress_evidence_is_atomic(playback_receipt_fixture, mutation) -> None:
    with pytest.raises(ValidationError):
        PlaybackReceiptV1.model_validate({**playback_receipt_fixture, **mutation})

def test_playback_completion_requires_the_committed_final_frame_and_exact_total(
    playback_receipt_fixture, stored_final_playback_frame, playback_receipt_verifier,
) -> None:
    receipt = PlaybackReceiptV1.model_validate(playback_receipt_fixture)
    playback_receipt_verifier.verify_terminal_frame(stored_final_playback_frame, receipt)
    assert receipt.last_sequence == receipt.expected_final_sequence
    assert receipt.bytes_accepted == receipt.expected_total_bytes
    with pytest.raises(ValidationError, match="full_terminal_frame"):
        PlaybackReceiptV1.model_validate({
            **playback_receipt_fixture,
            "bytes_accepted": playback_receipt_fixture["expected_total_bytes"] - 1,
        })
    for mutation in (
        {"expected_final_sequence": receipt.expected_final_sequence + 1},
        {"expected_total_bytes": receipt.expected_total_bytes + 1},
        {"terminal_frame_commitment": DIFFERENT_SYNTHETIC_COMMITMENT},
    ):
        with pytest.raises((ValidationError, PlaybackReceiptBindingError)):
            playback_receipt_verifier.verify_terminal_frame(
                stored_final_playback_frame,
                {**playback_receipt_fixture, **mutation},
            )

def test_playback_frames_form_one_contiguous_committed_stream(
    playback_stream_sender, playback_frames,
) -> None:
    sent = playback_stream_sender.send(playback_frames)
    assert sent[0].sequence == 0 and sent[0].byte_offset == 0
    for previous, current in zip(sent[:-1], sent[1:], strict=True):
        assert current.sequence == previous.sequence + 1
        assert current.byte_offset == previous.byte_offset + previous.byte_count
    assert sent[-1].final_frame is True
    assert sent[-1].final_stream_byte_count == sum(frame.byte_count for frame in sent)

@pytest.mark.parametrize(("model", "fixture_name", "start_field", "end_field", "limit"), [
    (WakeClaimV1, "wake_claim", "issued_at", "expires_at", timedelta(seconds=2)),
    (CaptureLeaseV1, "capture_lease", "issued_at", "expires_at", timedelta(seconds=90)),
    (HandoffTokenV1, "handoff_token", "issued_at", "expires_at", timedelta(seconds=30)),
    (EndpointHealthV1, "endpoint_health", "observed_at", "valid_until", timedelta(seconds=5)),
    (EndpointControlV1, "endpoint_control", "issued_at", "expires_at", timedelta(seconds=2)),
    (ConversationAdmissionV1, "conversation_admission", "admitted_at", "expires_at", timedelta(seconds=90)),
    (ReplyRoutingRequestV1, "reply_routing_request", "issued_at", "expires_at", timedelta(seconds=2)),
    (ReplyRouteDecisionV1, "reply_route_decision", "decided_at", "valid_until", timedelta(seconds=2)),
    (OpaqueCatalogHandleV1, "opaque_catalog_handle", "issued_at", "expires_at", timedelta(seconds=30)),
    (ProviderEntitlementReviewV1, "provider_entitlement_review", "reviewed_at", "expires_at", timedelta(days=90)),
    (AuthorizedCatalogQueryV1, "authorized_catalog_query", "issued_at", "expires_at", timedelta(seconds=5)),
    (AuthorizedMediaRequestV1, "authorized_media_request", "issued_at", "expires_at", timedelta(seconds=5)),
    (MediaAuthorizationDecisionV1, "media_authorization_decision", "decided_at", "valid_until", timedelta(seconds=5)),
    (MediaCatalogResultV1, "media_catalog_result", "issued_at", "expires_at", timedelta(seconds=30)),
    (SignedMediaEnvelopeV1, "signed_media_envelope", "issued_at", "expires_at", timedelta(seconds=5)),
    (PlayerObservationV1, "player_observation", "ingested_at", "valid_until", timedelta(seconds=5)),
    (TeachingRequestV1, "teaching_request", "issued_at", "expires_at", timedelta(seconds=5)),
    (AuthorizedTeachingRequestV1, "authorized_teaching_request", "authorized_at", "expires_at", timedelta(seconds=5)),
    (TeachingAuthorizationDecisionV1, "teaching_authorization_decision", "decided_at", "valid_until", timedelta(seconds=5)),
    (TeachingAssetV1, "teaching_asset", "issued_at", "expires_at", timedelta(minutes=5)),
    (TeachingSessionManifestV1, "teaching_session_manifest", "issued_at", "expires_at", timedelta(hours=2)),
    (DisplayClearRequestV1, "display_clear_request", "issued_at", "expires_at", timedelta(seconds=5)),
    (AuthorizedTVRequestV1, "authorized_tv_request", "issued_at", "expires_at", timedelta(seconds=5)),
    (SignedTVActionV1, "signed_tv_action", "issued_at", "expires_at", timedelta(seconds=5)),
    (TVObservationRequestV1, "tv_observation_request", "issued_at", "expires_at", timedelta(seconds=5)),
    (WholeHomeTVObservationV1, "tv_observation", "ingested_at", "valid_until", timedelta(seconds=5)),
])
def test_port_authorities_reject_nonpositive_and_overlong_windows(
    model, fixture_name, start_field, end_field, limit, request
) -> None:
    payload = request.getfixturevalue(f"{fixture_name}_fixture")
    start = payload[start_field]
    for expiry in (start, start + limit + timedelta(microseconds=1)):
        with pytest.raises(ValidationError):
            model.model_validate({**payload, end_field: expiry})

def test_child_rule_proposal_approval_and_final_digest_have_no_construction_cycle(
    child_rule_proposal_fixture, child_rule_approval_fixture, finalized_child_rule_fixture,
) -> None:
    proposal = ChildMediaRuleProposalV1.model_validate(child_rule_proposal_fixture)
    approval = ChildMediaRuleApprovalV1.model_validate(child_rule_approval_fixture)
    rule = ChildMediaRuleV1.model_validate(finalized_child_rule_fixture)
    assert approval.proposal_digest == proposal.proposal_digest == rule.proposal_digest
    assert rule.rule_digest == child_media_rule_digest(rule)
    assert rule.rule_digest != rule.proposal_digest

def test_child_media_windows_are_half_open_cover_last_minute_and_reject_overlap(
    child_rule_proposal_fixture,
) -> None:
    proposal = ChildMediaRuleProposalV1.model_validate(child_rule_proposal_fixture)
    last_minute = ChildMediaTimeWindowV1(
        weekday=0, start_local_minute=1439, end_local_minute=1440,
    )
    validate_child_media_rule_scope(
        proposal.model_copy(update={"allowed_windows": (last_minute,)}),
    )
    adjacent = (
        ChildMediaTimeWindowV1(weekday=1, start_local_minute=60, end_local_minute=120),
        ChildMediaTimeWindowV1(weekday=1, start_local_minute=120, end_local_minute=180),
    )
    validate_child_media_rule_scope(
        proposal.model_copy(update={"allowed_windows": adjacent}),
    )
    overlapping = (
        ChildMediaTimeWindowV1(weekday=1, start_local_minute=60, end_local_minute=121),
        ChildMediaTimeWindowV1(weekday=1, start_local_minute=120, end_local_minute=180),
    )
    with pytest.raises(ValueError, match="windows_overlap"):
        validate_child_media_rule_scope(
            proposal.model_copy(update={"allowed_windows": overlapping}),
        )

@pytest.mark.parametrize("field", [
    "child_subject_id", "child_profile_id", "child_profile_generation", "area_id",
    "area_generation", "players", "provider_authorities", "permitted_content_classes",
    "approved_item_identity_commitments", "maximum_volume_percent", "timezone_id",
    "timezone_data_version", "timezone_data_digest", "timezone_policy",
    "allowed_windows", "policy_version", "expected_lifecycle_generation",
    "owner_prepared_mutation_id", "owner_subject_id", "owner_authorization_commitment",
    "issued_at", "expires_at",
])
def test_child_rule_proposal_digest_rejects_every_field_substitution(
    child_rule_proposal_fixture, field,
) -> None:
    with pytest.raises(ValidationError, match="proposal_digest"):
        ChildMediaRuleProposalV1.model_validate(
            substitute_valid_value(child_rule_proposal_fixture, field),
        )

def test_child_rule_rejects_cross_area_player_and_approval_substitution(
    finalized_child_rule_fixture, child_rule_verifier,
) -> None:
    cross_area = substitute_child_player_area(finalized_child_rule_fixture)
    with pytest.raises(ValidationError, match="outside_exact_area"):
        ChildMediaRuleV1.model_validate(cross_area)
    for field in (
        "guardian_approval_id", "guardian_subject_id", "guardian_generation",
        "guardian_approval_commitment", "proposal_digest",
    ):
        with pytest.raises((ValidationError, SignatureRejected, ChildRuleBindingRejected)):
            child_rule_verifier.verify(
                substitute_and_recompute_rule_digest(finalized_child_rule_fixture, field),
            )

@pytest.mark.parametrize(("operation", "observed", "resulting"), [
    ("activate", "draft", "active"),
    ("replace", "active", "active"),
    ("revoke", "active", "revoked"),
])
def test_child_rule_applied_receipt_is_one_legal_exact_cas_transition(
    child_rule_activation_receipt_fixture, operation, observed, resulting,
) -> None:
    revocation = ({
        "revocation_request_id": uuid4(),
        "revocation_source": "current_guardian_local_stop",
        "revocation_requested_at": child_rule_activation_receipt_fixture["processed_at"],
    } if operation == "revoke" else {
        "revocation_request_id": None,
        "revocation_source": None,
        "revocation_requested_at": None,
    })
    receipt = ChildMediaRuleLifecycleReceiptV1.model_validate({
        **child_rule_activation_receipt_fixture,
        **revocation,
        "operation": operation,
        "outcome": "APPLIED",
        "observed_state": observed,
        "resulting_state": resulting,
    })
    assert receipt.resulting_lifecycle_generation == receipt.expected_lifecycle_generation + 1

def test_child_rule_rejected_receipt_cannot_claim_a_state_or_generation_change(
    child_rule_activation_receipt_fixture,
) -> None:
    rejected = {
        **child_rule_activation_receipt_fixture,
        "outcome": "REJECTED",
        "observed_state": "active",
        "resulting_state": "active",
        "resulting_lifecycle_generation": child_rule_activation_receipt_fixture[
            "observed_lifecycle_generation"
        ],
    }
    ChildMediaRuleLifecycleReceiptV1.model_validate(rejected)
    for mutation in (
        {"resulting_state": "revoked"},
        {"resulting_lifecycle_generation": rejected["resulting_lifecycle_generation"] + 1},
        {"rule_ceremony_owner_authorization_commitment": DIFFERENT_SYNTHETIC_COMMITMENT},
        {"rule_ceremony_guardian_approval_commitment": DIFFERENT_SYNTHETIC_COMMITMENT},
    ):
        with pytest.raises((ValidationError, ChildRuleBindingRejected)):
            verify_child_rule_activation_receipt({**rejected, **mutation})

async def test_child_rule_revoke_is_offline_immediate_and_needs_no_new_ceremony(
    child_rule_registry, active_child_rule, unavailable_auth_and_cloud,
) -> None:
    receipt = await child_rule_registry.revoke_immediately(
        rule_id=active_child_rule.rule_id,
        source="current_guardian_local_stop",
        expected_generation=active_child_rule.lifecycle_generation,
    )
    assert receipt.outcome == "APPLIED"
    assert (receipt.observed_state, receipt.resulting_state) == ("active", "revoked")
    assert unavailable_auth_and_cloud.calls == []
    restarted = await child_rule_registry.crash_and_restart()
    assert await restarted.state(active_child_rule.rule_id) == "revoked"
    assert await restarted.authorize_child_play(active_child_rule.rule_id) == "deny"

def test_reply_route_has_atomic_speech_or_no_speech_location_shape(reply_route_fixture) -> None:
    for mutation in (
        {"decision": "speak_at_source", "endpoint_id": None},
        {"decision": "speak_at_source", "area_id": None},
        {"decision": "speak_at_source", "area_generation": None},
        {"decision": "speak_at_source", "maximum_volume_percent": None},
        {"decision": "no_speech", "endpoint_id": "endpoint_synth_01"},
        {"decision": "no_speech", "area_id": "area_synth_common_01"},
        {"decision": "no_speech", "area_generation": 7},
        {"decision": "no_speech", "maximum_volume_percent": 20},
    ):
        with pytest.raises(ValidationError):
            ReplyRouteDecisionV1.model_validate({**reply_route_fixture, **mutation})

@pytest.mark.parametrize("field", [
    "conversation_id", "turn_id", "capture_lease_id", "capture_lease_commitment",
    "request_commitment", "cancellation_generation", "request_expires_at",
])
async def test_reply_decision_or_frame_substitution_stops_before_playback(
    reply_delivery, reply_route_fixture, field,
) -> None:
    with pytest.raises(ReplyBindingRejected):
        await reply_delivery.deliver(substitute_valid_value(reply_route_fixture, field))
    assert reply_delivery.endpoint.frames == []

@pytest.mark.parametrize(
    "forbidden_audience",
    ["owner_private", "adult_private", "household", "public_only", "household_shared"],
)
def test_reply_memory_audience_rejects_non_phase1_vocabulary(
    reply_routing_request_fixture, forbidden_audience,
) -> None:
    with pytest.raises(ValidationError):
        ReplyRoutingRequestV1.model_validate({
            **reply_routing_request_fixture,
            "memory_audience": forbidden_audience,
        })

@pytest.mark.parametrize(
    ("identity_mode", "profile_class", "memory_audience", "accepted"),
    (
        *(('identified', profile, audience, True)
          for profile in ('owner', 'adult')
          for audience in (
              MemoryAudience.SUBJECT_PRIVATE,
              MemoryAudience.HOUSEHOLD_ADULTS,
              MemoryAudience.HOUSEHOLD_ALL,
          )),
        ("identified", "owner", MemoryAudience.GUARDIAN_CHILD, False),
        ("identified", "adult", MemoryAudience.GUARDIAN_CHILD, False),
        ("guest", "guest", None, True),
        ("uncertain", "guest", None, True),
        ("uncertain", "adult", None, False),
        ("identified", "guest", None, False),
        ("guest", "guest", MemoryAudience.SUBJECT_PRIVATE, False),
    ),
)
def test_reply_identity_profile_memory_combinations_are_closed(
    identity_mode, profile_class, memory_audience, accepted,
) -> None:
    payload = reply_request_for_identity_profile_and_audience(
        identity_mode=identity_mode,
        profile_class=profile_class,
        memory_audience=memory_audience,
    )
    if accepted:
        ReplyRoutingRequestV1.model_validate(payload)
    else:
        with pytest.raises(ValidationError):
            ReplyRoutingRequestV1.model_validate(payload)

@pytest.mark.asyncio
@pytest.mark.parametrize("identity_mode", ("guest", "uncertain"))
async def test_guest_or_uncertain_reply_serializes_zero_memory_and_performs_no_lookup(
    guest_reply_fixture, memory_reader, reply_router, identity_mode,
) -> None:
    request = ReplyRoutingRequestV1.model_validate({
        **guest_reply_fixture,
        "identity_mode": identity_mode,
    })
    await reply_router.resolve(request)
    serialized = request.model_dump(mode="json")
    assert serialized["subject_id"] is None
    assert serialized["profile_version"] is None
    assert request.model_dump(mode="json")["memory_audience"] is None
    assert serialized["audience_policy_generation"] is None
    assert request.presentation_policy == "generic_guest_public"
    assert memory_reader.calls == []

@pytest.mark.parametrize("field", ("subject_id", "profile_version", "audience_policy_generation"))
def test_reply_rejects_missing_or_stale_subject_audience_authority(
    reply_routing_request_fixture, field,
) -> None:
    with pytest.raises((ValidationError, StaleAudienceAuthority)):
        validate_reply_against_current_subject_and_audience_policy(
            ReplyRoutingRequestV1,
            {**reply_routing_request_fixture, field: stale_or_absent(field)},
        )

@pytest.mark.parametrize(("state", "handle_count"), [
    ("exact", 0), ("exact", 2), ("ambiguous", 1), ("no_match", 1), ("denied", 1),
])
def test_catalog_result_state_matches_opaque_handles(media_catalog_result_payload, state, handle_count) -> None:
    with pytest.raises(ValidationError):
        MediaCatalogResultV1.model_validate(media_catalog_result_payload(state=state, handle_count=handle_count))

def test_physical_safety_unverified_cannot_carry_acknowledgement(physical_safety_receipt_fixture) -> None:
    with pytest.raises(ValidationError):
        PhysicalSafetyReceiptV1.model_validate({
            **physical_safety_receipt_fixture,
            "outcome": "unverified",
            "acknowledged_at": physical_safety_receipt_fixture["requested_at"],
            "physically_verified_at": None,
        })

def test_muted_endpoint_cannot_claim_active_audio_egress(endpoint_health_fixture) -> None:
    with pytest.raises(ValidationError):
        EndpointHealthV1.model_validate({
            **endpoint_health_fixture,
            "hardware_mute": "muted",
            "leased_audio_egress": "active",
        })

@pytest.mark.parametrize("mutation", [
    {"state": "winner", "winner_claim_id": None, "winner_endpoint_id": None},
    {"state": "busy", "winner_claim_id": uuid4(), "winner_endpoint_id": None},
    {"state": "busy", "decision_reason": "confidence_hysteresis"},
    {"state": "no_eligible_claim", "decision_reason": "slot_busy"},
])
def test_wake_arbitration_requires_exact_winner_and_reason_shape(wake_arbitration_fixture, mutation) -> None:
    with pytest.raises(ValidationError):
        WakeArbitrationV1.model_validate({**wake_arbitration_fixture, **mutation})

def test_wake_arbitration_rejects_late_decision_and_correlation(wake_arbitration_fixture) -> None:
    opened = wake_arbitration_fixture["decision_window_opened_at"]
    for mutation in (
        {"decided_at": opened + timedelta(milliseconds=351)},
        {"acoustic_correlation_valid_until": opened + timedelta(milliseconds=1_501)},
    ):
        with pytest.raises(ValidationError):
            WakeArbitrationV1.model_validate({**wake_arbitration_fixture, **mutation})

@pytest.mark.parametrize("mutation", [
    omit_one_considered_member,
    duplicate_claim_id,
    duplicate_endpoint_id,
    permute_considered_members,
    pair_winner_claim_with_wrong_endpoint,
    omit_one_loser,
    include_winner_as_loser,
    mark_winner_ineligible,
    declare_no_eligible_with_eligible_member,
])
def test_wake_arbitration_binds_complete_claim_membership(
    wake_arbitration_fixture, admitted_wake_claims, mutation,
) -> None:
    with pytest.raises((ValidationError, IncompleteWakeClaimSet)):
        candidate = mutation(wake_arbitration_fixture)
        require_exact_wake_claim_set(candidate, admitted_wake_claims)
        WakeArbitrationV1.model_validate(candidate)

@pytest.mark.parametrize("mutation", [
    {"action_type": "media.pause.v1", "catalog_handle_id": uuid4()},
    {"action_type": "media.play_catalog_item.v1", "catalog_handle_id": None},
    {"action_type": "media.set_volume_absolute.v1", "absolute_volume_percent": None},
    {"action_type": "media.seek_absolute.v1", "seek_position_seconds": None},
])
def test_media_envelope_requires_one_action_specific_value(signed_media_envelope_fixture, mutation) -> None:
    with pytest.raises(ValidationError):
        SignedMediaEnvelopeV1.model_validate({**signed_media_envelope_fixture, **mutation})

def test_media_group_envelope_serializes_the_full_immutable_manifest(
    signed_group_media_envelope_fixture,
) -> None:
    envelope = SignedMediaEnvelopeV1.model_validate(signed_group_media_envelope_fixture)
    assert envelope.target_kind == "group_manifest"
    assert envelope.group_manifest_version is not None
    assert envelope.group_manifest_digest is not None
    assert tuple(member.member_index for member in envelope.group_members) == tuple(range(len(envelope.group_members)))
    assert all(member.area_generation >= 1 for member in envelope.group_members)
    assert all(member.player_binding_generation >= 1 for member in envelope.group_members)
    assert all(member.player_capability_generation >= 1 for member in envelope.group_members)
    for mutation in (
        {"group_manifest_version": None},
        {"group_manifest_digest": None},
        {"group_members": ()},
        {"target_kind": "player"},
    ):
        with pytest.raises(ValidationError, match="group|player"):
            SignedMediaEnvelopeV1.model_validate({**signed_group_media_envelope_fixture, **mutation})

def test_media_and_tv_authority_windows_are_conjunctive(
    signed_media_envelope_fixture, authorized_tv_request_fixture, signed_tv_action_fixture,
) -> None:
    media_deadline = min(
        signed_media_envelope_fixture["request_expires_at"],
        signed_media_envelope_fixture["decision_valid_until"],
    )
    exact_media = {
        **signed_media_envelope_fixture,
        "issued_at": media_deadline - timedelta(microseconds=1),
        "expires_at": media_deadline,
        "reconciliation_deadline": media_deadline + timedelta(seconds=5),
    }
    assert SignedMediaEnvelopeV1.model_validate(exact_media).expires_at == media_deadline
    with pytest.raises(ValidationError, match="outlives_request_or_decision"):
        SignedMediaEnvelopeV1.model_validate({
            **exact_media,
            "issued_at": media_deadline,
        })

    for model, payload in (
        (AuthorizedTVRequestV1, authorized_tv_request_fixture),
        (SignedTVActionV1, signed_tv_action_fixture),
    ):
        # The 5-second signing and post-issue bounds are inclusive at their
        # upper edges; expiry remains strictly after issue.
        exact={
            **payload,
            "issued_at":payload["authorized_at"]+timedelta(seconds=5),
            "expires_at":payload["authorized_at"]+timedelta(seconds=10),
        }
        if model is SignedTVActionV1:
            exact["reconciliation_deadline"] = exact["expires_at"] + timedelta(seconds=5)
        assert model.model_validate(exact).expires_at==exact["expires_at"]
        with pytest.raises(ValidationError):
            model.model_validate({
                **payload,
                "issued_at": payload["authorized_at"] + timedelta(seconds=5, microseconds=1),
            })
        with pytest.raises(ValidationError):
            model.model_validate({
                **payload,
                "expires_at": payload["issued_at"] + timedelta(seconds=5, microseconds=1),
            })

def test_thirty_second_authorization_expiry_predicate_is_independently_visible() -> None:
    authorized_at = aware_datetime_fixture()
    # The conjunction's two 5-second bounds imply a tighter 10-second cap.
    # Deliberately violate signing here so this helper-level test can isolate
    # the otherwise redundant 30-second defense-in-depth predicate.
    inside = media_tv_authority_window_failures(
        authorized_at,
        authorized_at + timedelta(seconds=29),
        authorized_at + timedelta(seconds=30),
    )
    outside = media_tv_authority_window_failures(
        authorized_at,
        authorized_at + timedelta(seconds=29),
        authorized_at + timedelta(seconds=30, microseconds=1),
    )
    assert "post_authorization_expiry_bound" not in inside
    assert outside - inside == {"post_authorization_expiry_bound"}

def test_phase4_maintenance_month_is_derived_from_utc_event_time(maintenance_record_fixture) -> None:
    occurred_at = datetime(2027, 1, 1, 0, 30, tzinfo=timezone(timedelta(hours=8)))
    assert occurred_at.astimezone(timezone.utc).strftime("%Y-%m") == "2026-12"
    with pytest.raises(ValidationError, match="month_key_not_utc_event_month"):
        Phase4MaintenanceRecordV1.model_validate({
            **maintenance_record_fixture,
            "occurred_at": occurred_at,
            "month_key": "2027-01",
        })

@pytest.mark.asyncio
@pytest.mark.parametrize("kind",("media","tv"))
async def test_generation_drift_between_authorization_signing_and_dispatch_is_no_io(
    phase4_authority_compiler,phase4_adapter_spy,kind,
) -> None:
    authorized=await phase4_authority_compiler.authorize_current(kind)
    await phase4_authority_compiler.bump_bound_generation(kind)
    with pytest.raises(StaleAuthority):
        await phase4_authority_compiler.sign_and_dispatch(authorized)
    assert phase4_adapter_spy.domain_reads==[]
    assert phase4_adapter_spy.io_calls==[]

def test_unknown_player_observation_cannot_claim_precise_state(player_observation_fixture) -> None:
    with pytest.raises(ValidationError):
        PlayerObservationV1.model_validate({
            **player_observation_fixture,
            "playback_state": "unknown",
            "volume_percent": 20,
        })

def test_child_teaching_extension_requires_bound_guardian_commitment(teaching_manifest_fixture) -> None:
    with pytest.raises(ValidationError):
        TeachingSessionManifestV1.model_validate({
            **teaching_manifest_fixture,
            "audience_class": "k2_child",
            "expires_at": teaching_manifest_fixture["issued_at"] + timedelta(minutes=31),
            "child_extended_duration_commitment": None,
        })

def test_child_teaching_request_requires_one_exact_screen_time_session(
    child_teaching_request_fixture, adult_teaching_request_fixture,
) -> None:
    with pytest.raises(ValidationError, match="child_screen_time_shape_invalid"):
        TeachingRequestV1.model_validate({
            **child_teaching_request_fixture,
            "screen_time_session_ref": None,
        })
    with pytest.raises(ValidationError, match="child_screen_time_shape_invalid"):
        TeachingRequestV1.model_validate({
            **adult_teaching_request_fixture,
            "screen_time_session_ref": child_teaching_request_fixture["screen_time_session_ref"],
        })

@pytest.mark.parametrize("field", [
    "screen_time_session_ref", "screen_time_session_commitment",
    "screen_time_session_expires_at", "screen_time_policy_version",
])
def test_child_authorization_and_manifest_require_complete_screen_time_authority(
    authorized_child_teaching_fixture, child_teaching_manifest_fixture, field,
) -> None:
    for model, payload in (
        (AuthorizedTeachingRequestV1, authorized_child_teaching_fixture),
        (TeachingSessionManifestV1, child_teaching_manifest_fixture),
    ):
        with pytest.raises(ValidationError, match="screen_time"):
            model.model_validate({**payload, field: None})

def test_child_manifest_is_capped_by_exact_screen_time_session_deadline(
    child_teaching_manifest_fixture,
) -> None:
    at_deadline = resign_teaching_manifest({
        **child_teaching_manifest_fixture,
        "expires_at": child_teaching_manifest_fixture["screen_time_session_expires_at"],
    })
    TeachingSessionManifestV1.model_validate(at_deadline)
    with pytest.raises(ValidationError, match="outlives_screen_time_session"):
        TeachingSessionManifestV1.model_validate(resign_teaching_manifest({
            **at_deadline,
            "expires_at": at_deadline["screen_time_session_expires_at"] + timedelta(microseconds=1),
        }))

@pytest.mark.asyncio
@pytest.mark.parametrize("fault", [
    "missing_screen_time_session", "stale_screen_time_session",
    "cross_child_screen_time_session", "stale_screen_time_policy",
    "stale_guardian_generation", "screen_time_session_already_ended",
])
async def test_child_teaching_screen_time_faults_deny_before_content_or_display_reads(
    teaching_policy_service, child_teaching_request_fixture, fault,
) -> None:
    service = teaching_policy_service.with_screen_time_fault(fault)
    decision = await service.authorize(child_teaching_request_fixture)
    assert decision.effect == "deny"
    assert service.content_reads == []
    assert service.display_reads == []

def test_teaching_manifest_rejects_unknown_asset_and_markup(teaching_manifest_fixture) -> None:
    with pytest.raises(ValidationError):
        TeachingSessionManifestV1.model_validate(
            manifest_with_unknown_image_asset(teaching_manifest_fixture)
        )
    with pytest.raises(ValidationError):
        TeachingSessionManifestV1.model_validate(
            manifest_with_paragraph(teaching_manifest_fixture, '<script src="https://evil.invalid/x.js">')
        )

def test_teaching_manifest_signature_binds_full_body_digest_and_persistable_authority(
    teaching_manifest_fixture, display_manifest_signer,
) -> None:
    manifest = TeachingSessionManifestV1.model_validate(teaching_manifest_fixture)
    assert manifest.manifest_digest == teaching_manifest_authority_digest(manifest)
    signature_bytes = canonical_teaching_manifest_signature_bytes(manifest)
    assert display_manifest_signer.verify(
        "tuntun-display-manifest-v1",
        signature_bytes,
        manifest.signature,
        key_purpose="display_manifest",
    )
    record = teaching_manifest_authority_record_from(manifest)
    assert record.manifest_digest == manifest.manifest_digest
    assert record.canonical_signature_bytes() == signature_bytes
    assert not hasattr(record, "components") and not hasattr(record, "assets")

async def test_display_receipt_verifies_after_restart_without_persisting_lesson_body(
    display_receipt_service, teaching_manifest_fixture, display_receipt_fixture,
) -> None:
    await display_receipt_service.register_manifest_authority(teaching_manifest_fixture)
    restarted = await display_receipt_service.restart()
    assert await restarted.accept(display_receipt_fixture)
    assert restarted.database_contains_manifest_body() is False
    await restarted.expire_manifest_authority_record()
    with pytest.raises(DisplayReceiptBindingError):
        await (await restarted.restart()).accept(display_receipt_fixture)

@pytest.mark.parametrize("mutation", [
    {"state": "rendered", "rendered_at": None},
    {"state": "rendered", "cleared_at": SYNTHETIC_NOW},
    {"state": "cleared", "cleared_at": None},
    {"state": "ready", "cleared_at": SYNTHETIC_NOW},
])
def test_display_receipt_state_requires_exact_render_clear_evidence(display_receipt_fixture, mutation) -> None:
    with pytest.raises(ValidationError):
        DisplayReceiptV1.model_validate({**display_receipt_fixture, **mutation})

@pytest.mark.parametrize("field", [
    "session_id", "manifest_version", "manifest_digest", "renderer_endpoint_id",
    "manifest_issued_at", "manifest_expires_at",
    "renderer_endpoint_generation", "renderer_binding_generation",
    "renderer_capability_generation", "renderer_capability_evidence_digest",
    "display_endpoint_id", "display_endpoint_generation", "display_binding_generation",
    "display_capability_generation", "display_capability_evidence_digest",
    "area_id", "area_generation", "privacy_generation",
])
def test_display_receipt_exactly_binds_the_stored_signed_manifest(
    display_receipt_verifier, stored_teaching_manifest_authority,
    display_receipt_fixture, field,
) -> None:
    with pytest.raises(DisplayReceiptBindingError):
        display_receipt_verifier.verify(
            stored_teaching_manifest_authority,
            substitute_valid_value(display_receipt_fixture, field),
        )
    assert display_receipt_verifier.ui_writes == []

def test_display_render_and_expiry_receipts_obey_the_stored_manifest_window(
    display_receipt_fixture,
) -> None:
    with pytest.raises(ValidationError, match="manifest_expiry|manifest_window"):
        DisplayReceiptV1.model_validate({
            **display_receipt_fixture,
            "state": "rendered",
            "rendered_at": display_receipt_fixture["manifest_expires_at"],
            "observed_at": display_receipt_fixture["manifest_expires_at"],
        })
    exact_expiry = {
        **display_receipt_fixture,
        "state": "expired",
        "cleared_at": display_receipt_fixture["manifest_expires_at"],
        "observed_at": display_receipt_fixture["manifest_expires_at"],
        "clear_request_id": None,
        "clear_request_issuer": None,
        "clear_reason": None,
        "clear_request_issued_at": None,
        "clear_request_expires_at": None,
        "clear_request_commitment": None,
    }
    assert DisplayReceiptV1.model_validate(exact_expiry).state == "expired"
    with pytest.raises(ValidationError, match="predates_manifest_expiry"):
        DisplayReceiptV1.model_validate({
            **exact_expiry,
            "cleared_at": exact_expiry["manifest_expires_at"] - timedelta(microseconds=1),
        })

def test_display_receipt_from_the_future_is_rejected_before_state_write(
    display_receipt_verifier, stored_teaching_manifest_authority,
    display_receipt_fixture, trusted_now,
) -> None:
    with pytest.raises(DisplayReceiptBindingError, match="future"):
        display_receipt_verifier.verify(
            stored_teaching_manifest_authority,
            {
                **display_receipt_fixture,
                "observed_at": trusted_now + timedelta(microseconds=1),
            },
            now=trusted_now,
        )
    assert display_receipt_verifier.ui_writes == []

@pytest.mark.parametrize("fault", [
    "same_session_version_different_digest", "deleted_manifest", "replaced_manifest",
    "stale_endpoint_generation_after_restart", "stale_privacy_generation_after_restart",
])
async def test_display_receipt_rejects_missing_replaced_or_stale_manifest_lineage(
    display_receipt_service, display_receipt_fixture, fault,
) -> None:
    runtime = await display_receipt_service.with_fault(fault).restart()
    with pytest.raises(DisplayReceiptBindingError):
        await runtime.accept(display_receipt_fixture)
    assert runtime.public_display_state == []

@pytest.mark.parametrize("field", [
    "clear_request_id", "clear_request_issuer", "clear_reason",
    "clear_request_issued_at", "clear_request_expires_at", "clear_request_commitment",
])
def test_cleared_receipt_exactly_acknowledges_the_signed_clear_request(
    display_receipt_verifier, stored_teaching_manifest_authority,
    stored_display_clear_request,
    cleared_display_receipt_fixture, field,
) -> None:
    with pytest.raises(DisplayReceiptBindingError):
        display_receipt_verifier.verify_clear(
            stored_teaching_manifest_authority,
            stored_display_clear_request,
            substitute_valid_value(cleared_display_receipt_fixture, field),
        )

@pytest.mark.parametrize("fault", [
    "old_clear_receipt_after_new_render", "deleted_clear_request",
    "replaced_clear_request", "stale_clear_privacy_generation_after_restart",
])
async def test_old_or_unbound_clear_receipt_never_acknowledges_current_pixels(
    display_receipt_service, cleared_display_receipt_fixture, fault,
) -> None:
    runtime = await display_receipt_service.with_fault(fault).restart()
    with pytest.raises(DisplayReceiptBindingError):
        await runtime.accept(cleared_display_receipt_fixture)
    assert runtime.clear_truth == "unverified"

@pytest.mark.parametrize("mutation", [
    {"operation": "tv.set_power.v1", "desired_power": None},
    {"operation": "tv.set_power.v1", "desired_power": "ON", "desired_muted": False},
    {"operation": "tv.send_key.v1", "desired_key": None},
])
def test_tv_action_has_exactly_one_operation_specific_desired_state(signed_tv_action_fixture, mutation) -> None:
    with pytest.raises(ValidationError):
        SignedTVActionV1.model_validate({**signed_tv_action_fixture, **mutation})

def test_tv_action_reconciliation_deadline_is_signed_and_bounded(
    signed_tv_action_fixture,
) -> None:
    expiry = signed_tv_action_fixture["expires_at"]
    for deadline in (
        expiry - timedelta(microseconds=1),
        expiry + timedelta(seconds=5, microseconds=1),
    ):
        with pytest.raises(ValidationError, match="reconciliation_window"):
            SignedTVActionV1.model_validate({
                **signed_tv_action_fixture, "reconciliation_deadline": deadline,
            })

def test_tv_receipt_cannot_claim_acceptance_without_dispatch(tv_control_receipt_fixture) -> None:
    with pytest.raises(ValidationError):
        TVActionDispatchReceiptV1.model_validate({
            **tv_control_receipt_fixture,
            "state": "accepted",
            "dispatch_attempt": 0,
        })
    for field in ("dispatch_started_at", "adapter_context_commitment", "effect_commitment"):
        with pytest.raises(ValidationError):
            TVActionDispatchReceiptV1.model_validate({
                **tv_control_receipt_fixture,
                field: None,
            })
    with pytest.raises(ValidationError, match="predates_dispatch"):
        TVActionDispatchReceiptV1.model_validate({
            **tv_control_receipt_fixture,
            "observed_at": tv_control_receipt_fixture["dispatch_started_at"] - timedelta(microseconds=1),
        })

@pytest.mark.parametrize(("state", "attempt", "accepted"), [
    ("accepted", 1, True), ("accepted", 0, False),
    ("unverified", 1, True), ("unverified", 0, False),
    ("rejected", 0, True), ("rejected", 1, False),
    ("error_safe", 0, True), ("error_safe", 1, True),
    ("expired", 0, True), ("expired", 1, False),
])
def test_tv_receipt_state_attempt_matrix_is_exact(
    tv_control_receipt_payload, state, attempt, accepted,
) -> None:
    candidate = tv_control_receipt_payload(state=state, dispatch_attempt=attempt)
    if accepted:
        TVActionDispatchReceiptV1.model_validate(candidate)
    else:
        with pytest.raises(ValidationError):
            TVActionDispatchReceiptV1.model_validate(candidate)

def test_tv_expiry_boundary_distinguishes_no_dispatch_from_late_receipt(
    tv_control_receipt_payload,
) -> None:
    deadline = tv_control_receipt_payload()["expires_at"]
    TVActionDispatchReceiptV1.model_validate(tv_control_receipt_payload(
        state="expired", dispatch_attempt=0, observed_at=deadline,
    ))
    with pytest.raises(ValidationError, match="expired_before_deadline"):
        TVActionDispatchReceiptV1.model_validate(tv_control_receipt_payload(
            state="expired", dispatch_attempt=0,
            observed_at=deadline - timedelta(microseconds=1),
        ))
    # The effect was admitted before expiry; a receipt may safely arrive after it.
    TVActionDispatchReceiptV1.model_validate(tv_control_receipt_payload(
        state="unverified", dispatch_attempt=1,
        dispatch_started_at=deadline - timedelta(microseconds=1),
        observed_at=deadline + timedelta(microseconds=1),
    ))

def test_tv_adapter_receipt_cannot_claim_core_unknown(
    tv_control_receipt_payload,
) -> None:
    payload = tv_control_receipt_payload()
    deadline = payload["reconciliation_deadline"]
    with pytest.raises(ValidationError):
        TVActionDispatchReceiptV1.model_validate(tv_control_receipt_payload(
            state="unknown", dispatch_attempt=1, observed_at=deadline,
        ))

def test_tv_core_unknown_terminal_has_exact_logical_deadline(
    tv_unknown_terminal_fixture,
) -> None:
    terminal = TVDispatchUnknownTerminalV1.model_validate(tv_unknown_terminal_fixture)
    deadline = terminal.reconciliation_deadline
    assert terminal.record_kind == "core_unknown_terminal"
    assert terminal.terminal_at == deadline
    assert terminal.materialized_at >= deadline
    assert terminal.terminal_id == deterministic_tv_terminal_id(
        terminal.signed_action_digest,
        terminal.dispatch_proof_commitment,
    )
    for terminal_at in (
        deadline - timedelta(microseconds=1),
        deadline + timedelta(microseconds=1),
    ):
        with pytest.raises(ValidationError, match="not_at_reconciliation_deadline"):
            TVDispatchUnknownTerminalV1.model_validate({
                **tv_unknown_terminal_fixture, "terminal_at": terminal_at,
            })

async def test_tv_core_terminal_and_timestamps_are_not_network_constructible(
    tv_adapter_ingress, tv_unknown_terminal_fixture, tv_terminal_repository,
) -> None:
    with pytest.raises(TVReceiptBindingError, match="adapter_receipt_only"):
        await tv_adapter_ingress.accept(tv_unknown_terminal_fixture)
    assert tv_terminal_repository.writes == []

def test_tv_terminal_cross_domain_and_wrong_purpose_replay_rejects(
    tv_unknown_terminal_fixture, tv_signature_verifier,
) -> None:
    for domain, purpose in (
        ("tuntun-tv-action-v1", "tv_action"),
        ("tuntun-tv-dispatch-receipt-v1", "tv_dispatch_receipt"),
        ("tuntun-tv-observation-v1", "tv_observation"),
        ("tuntun-tv-dispatch-unknown-terminal-v1", "tv_dispatch_receipt"),
    ):
        with pytest.raises(SignatureVerificationError):
            tv_signature_verifier.verify(tv_unknown_terminal_fixture, domain, purpose)

def test_adapter_key_cannot_mint_core_tv_unknown_terminal(
    tv_unknown_terminal_fixture, adapter_test_signer, tv_terminal_verifier,
) -> None:
    forged = resign_with_key(
        tv_unknown_terminal_fixture,
        adapter_test_signer,
        domain="tuntun-tv-dispatch-unknown-terminal-v1",
        purpose="core_tv_dispatch_unknown_terminal",
    )
    with pytest.raises(SignatureVerificationError, match="key_role_or_purpose"):
        tv_terminal_verifier.verify(forged)

def test_tv_terminal_rejects_future_materialization(
    tv_unknown_terminal_fixture, tv_terminal_verifier,
) -> None:
    terminal = TVDispatchUnknownTerminalV1.model_validate(tv_unknown_terminal_fixture)
    with pytest.raises(TVReceiptBindingError, match="future_materialization"):
        tv_terminal_verifier.verify(
            terminal,
            trusted_verification_time=terminal.materialized_at - timedelta(microseconds=1),
        )

@pytest.mark.parametrize("offset", [
    -timedelta(microseconds=1), timedelta(0), timedelta(microseconds=1),
])
async def test_tv_core_unknown_finalizer_boundary_is_idempotent(
    tv_deadline_finalizer, dispatching_tv_action, offset,
) -> None:
    deadline = dispatching_tv_action.reconciliation_deadline
    tv_deadline_finalizer.clock.set(deadline + offset)
    terminal = await tv_deadline_finalizer.finalize(dispatching_tv_action.action_id)
    if offset < timedelta(0):
        assert terminal is None
        return
    assert terminal.terminal_at == deadline
    restarted = await tv_deadline_finalizer.restart()
    assert await restarted.finalize(dispatching_tv_action.action_id) == terminal
    assert restarted.new_adapter_effect_calls == ()

async def test_late_tv_adapter_evidence_cannot_replace_core_terminal(
    tv_deadline_finalizer, dispatching_tv_action, delayed_adapter_receipt,
) -> None:
    terminal = await tv_deadline_finalizer.finalize_at_deadline(dispatching_tv_action.action_id)
    with pytest.raises(TVReceiptBindingError, match="late_receiver_ingress"):
        await tv_deadline_finalizer.accept_adapter_receipt(delayed_adapter_receipt)
    assert await tv_deadline_finalizer.current_terminal(
        dispatching_tv_action.action_id,
    ) == terminal
    retained = await tv_deadline_finalizer.late_evidence_for(
        dispatching_tv_action.action_id,
    )
    assert retained.signed_adapter_receipt_digest == canonical_digest(
        delayed_adapter_receipt,
    )
    assert retained.disposition == "retained_not_authoritative"
    assert tv_deadline_finalizer.new_adapter_effect_calls == ()

async def test_tv_restart_terminalizes_attempted_action_once_at_deadline(
    tv_runtime, dispatching_tv_action,
) -> None:
    restarted = await tv_runtime.crash_and_restart_at_reconciliation_deadline()
    receipt = await restarted.core_unknown_terminal(dispatching_tv_action)
    assert isinstance(receipt, TVDispatchUnknownTerminalV1)
    assert receipt.dispatch_attempt == 1
    assert receipt.terminal_at == receipt.reconciliation_deadline
    assert restarted.new_adapter_effect_calls == ()

@pytest.mark.parametrize("field", [
    "action_id", "request_id", "idempotency_key", "request_binding_commitment",
    "signed_action_digest", "tv_endpoint_id", "endpoint_generation",
    "control_adapter_id", "operation", "desired_power", "desired_input_id",
    "desired_volume_percent", "desired_muted", "desired_key", "desired_app_id",
    "controller_epoch",
    "topology_generation", "binding_generation", "capability_generation",
    "control_generation", "authorization_generation", "enforcement_generation",
    "policy_version", "authorization_commitment", "authorized_at", "issued_at",
    "expires_at", "reconciliation_deadline",
])
def test_tv_receipt_exactly_binds_immutable_signed_action_before_reads(
    stored_signed_tv_action, tv_control_receipt_fixture, field, tv_receipt_verifier,
) -> None:
    with pytest.raises(TVReceiptBindingError):
        tv_receipt_verifier.verify(
            stored_signed_tv_action,
            substitute_valid_value(tv_control_receipt_fixture, field),
        )
    assert tv_receipt_verifier.registry_reads == []
    assert tv_receipt_verifier.adapter_calls == []

def test_tv_observation_dimension_is_closed_and_unique(tv_observation_fixture) -> None:
    observed = tv_observation_fixture["dimensions"][0]
    with pytest.raises(ValidationError):
        TVObservedDimensionV1.model_validate({
            **observed,
            "dimension": "power",
            "state": "observed",
            "power": "ON",
            "muted": False,
        })
    with pytest.raises(ValidationError):
        WholeHomeTVObservationV1.model_validate({
            **tv_observation_fixture,
            "dimensions": (observed, observed),
        })

def test_endpoint_registration_rejects_sensitive_commissioning(endpoint_registration_fixture) -> None:
    with pytest.raises(ValidationError):
        SpeechEndpointRegistrationV1.model_validate({
            **endpoint_registration_fixture,
            "room_class": "prohibited",
            "lifecycle_state": "commissioned",
        })

def test_hardware_mute_is_observation_only_and_never_a_remote_control(endpoint_control_fixture) -> None:
    with pytest.raises(ValidationError):
        EndpointControlV1.model_validate({
            **endpoint_control_fixture,
            "control": "hardware_mute",
            "desired_state": "muted",
        })

def test_capture_frame_is_binary_only_and_exact_length(speech_frame_fixture) -> None:
    with pytest.raises(ValidationError):
        SpeechFrameV1.model_validate({
            **speech_frame_fixture,
            "payload_length": len(speech_frame_fixture["payload"]) + 1,
        })
    assert "payload" not in SpeechFrameV1.model_json_schema()["properties"]

def test_handoff_must_change_exact_endpoint(handoff_token_fixture) -> None:
    with pytest.raises(ValidationError):
        HandoffTokenV1.model_validate({
            **handoff_token_fixture,
            "target_endpoint_id": handoff_token_fixture["source_endpoint_id"],
        })

def test_player_binding_rejects_duplicate_provider_and_false_volume_semantics(media_player_binding_fixture) -> None:
    provider = media_player_binding_fixture["provider_binding_ids"][0]
    for mutation in (
        {"provider_binding_ids": (provider, provider)},
        {"absolute_volume_semantics": "unavailable", "safe_start_volume_percent": 20},
    ):
        with pytest.raises(ValidationError):
            MediaPlayerBindingV1.model_validate({**media_player_binding_fixture, **mutation})

@pytest.mark.parametrize("field", [
    "provider_binding_id", "provider_generation", "adapter_generation",
    "entitlement_generation",
])
def test_catalog_handle_exactly_binds_current_provider_authority(
    media_catalog_result_fixture, field,
) -> None:
    handle = media_catalog_result_fixture["handles"][0]
    changed = substitute_valid_value(handle, field)
    with pytest.raises(ValidationError, match="catalog_result_handle_binding_invalid"):
        MediaCatalogResultV1.model_validate({
            **media_catalog_result_fixture,
            "handles": (changed, *media_catalog_result_fixture["handles"][1:]),
        })

async def test_catalog_handle_provider_generation_drift_fails_after_restart(
    catalog_service, opaque_catalog_handle_fixture,
) -> None:
    await catalog_service.provider_registry.advance_generation(
        opaque_catalog_handle_fixture["provider_binding_id"],
    )
    restarted = await catalog_service.restart()
    with pytest.raises(CatalogHandleAuthorityError):
        await restarted.resolve_handle(opaque_catalog_handle_fixture)
    assert restarted.provider_adapter_calls == []

def test_group_manifest_is_exact_and_has_no_selector(media_group_manifest_fixture) -> None:
    member = media_group_manifest_fixture["members"][0]
    with pytest.raises(ValidationError):
        MediaGroupManifestV1.model_validate({
            **media_group_manifest_fixture,
            "members": (member, member),
        })
    with pytest.raises(ValidationError):
        MediaGroupManifestV1.model_validate({
            **media_group_manifest_fixture,
            "target_selector": "all_speakers",
        })
    with pytest.raises(ValidationError, match="canonically_ordered"):
        MediaGroupManifestV1.model_validate({
            **media_group_manifest_fixture,
            "members": tuple(reversed(media_group_manifest_fixture["members"])),
        })

@pytest.mark.parametrize("mutation", [
    {"action_type": "media.play_catalog_item.v1", "target_kind": "group_manifest"},
    {"action_type": "media.play_group_manifest.v1", "target_kind": "player", "group_manifest_version": None,
     "group_manifest_digest": None, "group_members": ()},
    {"target_kind": "player", "group_manifest_version": 7},
    {"target_kind": "group_manifest", "group_manifest_digest": None},
    {"action_type": "media.pause.v1", "requested_absolute_volume_percent": 35},
    {"actor_class": "guest", "actor_subject_id": uuid4()},
    {"actor_class": "designated_guest", "designated_guest_session_id": None},
    {"actor_class": "designated_guest", "designated_guest_session_generation": None},
    {"actor_class": "designated_guest", "designated_guest_owner_coapproval_commitment": None},
    {"actor_class": "guest", "designated_guest_session_id": uuid4()},
])
def test_authorized_media_request_cannot_widen_action_target_or_actor(authorized_media_request_fixture, mutation) -> None:
    with pytest.raises(ValidationError):
        AuthorizedMediaRequestV1.model_validate({**authorized_media_request_fixture, **mutation})

@pytest.mark.parametrize("mutation", [
    {"effect": "allow", "authorization_class": None},
    {"effect": "deny", "authorization_class": "adult_reversible_immediate"},
    {"effect": "step_up", "required_assurance": None},
])
def test_media_authorization_decision_has_exact_authority_shape(media_authorization_decision_fixture, mutation) -> None:
    with pytest.raises(ValidationError):
        MediaAuthorizationDecisionV1.model_validate({**media_authorization_decision_fixture, **mutation})

def test_child_media_allow_requires_one_atomic_current_rule_authority(
    child_media_authorization_decision_fixture,
) -> None:
    decision = MediaAuthorizationDecisionV1.model_validate(
        child_media_authorization_decision_fixture,
    )
    assert decision.authorization_class == "child_rule_guardian_approved"
    assert decision.child_rule_authority is not None
    with pytest.raises(ValidationError, match="child_rule_authority"):
        MediaAuthorizationDecisionV1.model_validate({
            **child_media_authorization_decision_fixture,
            "child_rule_authority": None,
        })
    with pytest.raises(ValidationError, match="child_rule_authority"):
        MediaAuthorizationDecisionV1.model_validate({
            **child_media_authorization_decision_fixture,
            "authorization_class": "exact_confirmation",
        })

@pytest.mark.parametrize("field", [
    "rule_id", "rule_version", "proposal_digest", "rule_digest",
    "lifecycle_generation", "lifecycle_receipt_commitment", "child_subject_id",
    "child_profile_id", "child_profile_generation", "content_basis",
    "matched_content_class", "matched_item_identity_commitment",
])
def test_child_media_rule_authority_substitution_fails_across_entire_operation_chain(
    child_media_operation_chain, field,
) -> None:
    with pytest.raises(ChildRuleBindingRejected):
        verify_child_media_operation_chain(
            child_media_operation_chain.substitute_authority_field(field),
        )
    assert child_media_operation_chain.provider_reads == 0
    assert child_media_operation_chain.player_reads == 0
    assert child_media_operation_chain.bridge_calls == 0

@pytest.mark.parametrize("field", [
    "action_type", "target_kind", "target_player_or_group_id", "catalog_handle_id",
    "requested_absolute_volume_percent", "requested_seek_position_seconds",
    "group_manifest_version", "group_manifest_digest", "group_members",
    "designated_guest_session_id", "designated_guest_session_generation",
    "designated_guest_owner_coapproval_commitment", "topology_generation",
    "binding_generation", "capability_generation", "provider_binding_id",
    "provider_generation", "adapter_generation", "entitlement_generation", "policy_version",
])
def test_media_decision_cannot_authorize_same_id_substituted_request(
    authorized_media_request_fixture, media_authorization_decision_fixture,
    canonical_request_store, field,
) -> None:
    request = substitute_valid_value(authorized_media_request_fixture, field)
    with pytest.raises(MediaDecisionRequestBindingError):
        require_exact_media_decision_request_binding(
            request,
            media_authorization_decision_fixture,
            canonical_request_store,
        )
    assert canonical_request_store.catalog_reads == 0
    assert canonical_request_store.player_reads == 0

def test_media_operation_result_requires_manifest_order_and_derived_aggregate(media_operation_result_payload) -> None:
    with pytest.raises(ValidationError):
        MediaOperationResultV1.model_validate(media_operation_result_payload(
            states=("VERIFIED_PLAYING", "FAILED"),
            aggregate_state="VERIFIED",
        ))
    with pytest.raises(ValidationError):
        MediaOperationResultV1.model_validate(media_operation_result_payload(
            states=("VERIFIED_PLAYING", "VERIFIED_PLAYING"),
            aggregate_state="VERIFIED",
            reverse_manifest_order=True,
        ))

@pytest.mark.parametrize(("states", "aggregate"), [
    (("UNKNOWN", "UNKNOWN"), "UNKNOWN"),
    (("ACCEPTED_UNVERIFIED", "FAILED"), "UNKNOWN"),
    (("ACCEPTED_UNVERIFIED", "UNKNOWN"), "UNKNOWN"),
    (("FAILED", "FAILED"), "FAILED"),
    (("VERIFIED_PLAYING", "FAILED"), "PARTIAL"),
    (("VERIFIED_PLAYING", "UNKNOWN"), "PARTIAL"),
    (("VERIFIED_PLAYING", "ACCEPTED_UNVERIFIED"), "PARTIAL"),
    (("ACCEPTED_UNVERIFIED", "ACCEPTED_UNVERIFIED"), "ACCEPTED_UNVERIFIED"),
])
def test_media_aggregate_requires_actual_verified_effect_for_partial(
    media_operation_result_payload, states, aggregate,
) -> None:
    result = MediaOperationResultV1.model_validate(media_operation_result_payload(
        states=states, aggregate_state=aggregate,
    ))
    assert result.aggregate_state == aggregate

def test_all_unknown_and_definitive_mixed_unknown_have_distinct_terminal_lineage(
    media_operation_result_payload,
) -> None:
    all_unknown = MediaOperationResultV1.model_validate(media_operation_result_payload(
        states=("UNKNOWN", "UNKNOWN"),
        aggregate_state="UNKNOWN",
        complete_at_reconciliation_deadline=True,
    ))
    assert all(
        target.core_unknown_terminal_commitment is not None
        for target in all_unknown.target_results
    )
    definitive_mix = MediaOperationResultV1.model_validate(media_operation_result_payload(
        states=("ACCEPTED_UNVERIFIED", "FAILED"),
        aggregate_state="UNKNOWN",
        complete_at_reconciliation_deadline=False,
    ))
    assert all(
        target.core_unknown_terminal_commitment is None
        for target in definitive_mix.target_results
    )

@pytest.mark.parametrize("fault", [
    "wrong_item", "manual_item_change_after_dispatch", "prior_playing_state",
    "missing_action_correlation", "wrong_group_member_item",
])
def test_media_play_verification_requires_exact_item_and_action_correlation(
    media_operation_result_payload, fault,
) -> None:
    candidate = media_operation_result_payload(
        action_type="media.play_catalog_item.v1",
        states=("VERIFIED_PLAYING",),
        aggregate_state="VERIFIED",
        observation_fault=fault,
    )
    with pytest.raises(ValidationError, match="verified_media|action_correlation"):
        MediaOperationResultV1.model_validate(candidate)

@pytest.mark.parametrize(("action_type", "fault"), [
    ("media.set_volume_absolute.v1", "wrong_volume"),
    ("media.seek_absolute.v1", "position_outside_tolerance"),
    ("media.pause.v1", "still_playing"),
    ("media.stop.v1", "still_playing"),
    ("media.resume.v1", "still_paused"),
])
def test_media_verified_effect_requires_exact_action_specific_observation(
    media_operation_result_payload, action_type, fault,
) -> None:
    with pytest.raises(ValidationError, match="verified_media"):
        MediaOperationResultV1.model_validate(media_operation_result_payload(
            action_type=action_type,
            verified_effect_fault=fault,
        ))

def test_player_without_item_or_action_correlation_cannot_upgrade_play_truth(
    media_reconciliation_service, player_observation_fixture,
) -> None:
    observation = PlayerObservationV1.model_validate({
        **player_observation_fixture,
        "playback_state": "playing",
        "observed_item_identity_commitment": None,
        "control_correlation_id": None,
    })
    result = media_reconciliation_service.reconcile_observation(observation)
    assert result.state in {"ACCEPTED_UNVERIFIED", "UNKNOWN"}

@pytest.mark.parametrize("field", [
    "operation_id", "request_id", "action_id", "idempotency_key", "action_type", "target_kind",
    "target_player_or_group_id", "catalog_item_identity_commitment",
    "absolute_volume_percent", "seek_position_seconds",
    "seek_verification_tolerance_seconds", "signed_envelope_digest", "controller_epoch",
    "topology_generation", "binding_generation", "capability_generation",
    "capability_digest", "provider_binding_id", "provider_generation", "adapter_generation",
    "entitlement_generation",
    "policy_version", "request_binding_commitment", "authorization_class",
    "child_rule_authority", "authorization_commitment",
    "authorized_at", "request_expires_at", "decision_valid_until", "issued_at",
    "expires_at", "reconciliation_deadline", "manifest_order_target_ids",
])
def test_media_operation_result_exactly_binds_stored_envelope_before_serving(
    media_result_verifier, stored_signed_media_envelope, media_operation_result_fixture, field,
) -> None:
    with pytest.raises(MediaResultBindingError):
        media_result_verifier.verify(
            stored_signed_media_envelope,
            substitute_valid_value(media_operation_result_fixture, field),
        )
    assert media_result_verifier.projection_writes == []
    assert media_result_verifier.api_reads == []

@pytest.mark.parametrize("stored_fault", [
    "deleted_envelope", "replaced_same_action_id", "stale_generation_after_restart",
    "deleted_operation_row", "replaced_operation_row", "deleted_target_transition_record",
    "replaced_target_transition_record", "same_target_prior_operation_record",
    "deleted_source_receipt", "replaced_source_receipt",
])
async def test_media_result_rejects_missing_replaced_or_stale_operation_lineage(
    media_result_service, media_operation_result_fixture, stored_fault,
) -> None:
    runtime = await media_result_service.with_fault(stored_fault).restart()
    with pytest.raises(MediaResultBindingError):
        await runtime.publish(media_operation_result_fixture)
    assert runtime.public_results == []

@pytest.mark.parametrize("field", [
    "operation_id", "request_id", "action_id", "idempotency_key",
    "signed_envelope_digest", "target_transition_kind",
    "target_transition_record_commitment",
    "dispatch_started_at", "dispatch_context_commitment", "effect_commitment",
    "source_receipt_commitment", "core_unknown_terminal_commitment",
])
def test_media_child_result_exactly_binds_this_operation_dispatch_record(
    media_result_verifier, stored_signed_media_envelope,
    media_operation_result_fixture, field,
) -> None:
    substituted = substitute_target_result_field(
        media_operation_result_fixture,
        target_index=0,
        field=field,
    )
    with pytest.raises(MediaResultBindingError):
        media_result_verifier.verify(stored_signed_media_envelope, substituted)
    assert media_result_verifier.projection_writes == []

@pytest.mark.parametrize("mutation", [
    "different_single_player", "different_canonical_group", "omitted_group_member",
    "extra_group_member", "permuted_group_members",
])
def test_media_result_targets_are_derived_from_the_stored_envelope(
    media_result_verifier, stored_signed_media_envelope,
    media_operation_result_fixture, mutation,
) -> None:
    with pytest.raises(MediaResultBindingError):
        media_result_verifier.verify(
            stored_signed_media_envelope,
            mutate_result_target_tuple_coherently(media_operation_result_fixture, mutation),
        )

def test_media_result_reconciliation_window_is_closed(
    media_operation_result_fixture,
) -> None:
    at_deadline = {
        **media_operation_result_fixture,
        "completed_at": media_operation_result_fixture["reconciliation_deadline"],
    }
    MediaOperationResultV1.model_validate(at_deadline)
    with pytest.raises(ValidationError, match="outside_reconciliation_window"):
        MediaOperationResultV1.model_validate({
            **at_deadline,
            "completed_at": at_deadline["reconciliation_deadline"] + timedelta(microseconds=1),
        })
    assert reconcile_after_deadline(at_deadline) == "UNKNOWN"

def test_media_unknown_target_requires_core_terminal_and_exact_deadline(
    media_operation_result_with_unknown_target,
) -> None:
    payload = media_operation_result_with_unknown_target
    deadline = payload["reconciliation_deadline"]
    assert MediaOperationResultV1.model_validate({
        **payload, "completed_at": deadline,
    }).target_results[0].core_unknown_terminal_commitment is not None
    with pytest.raises(ValidationError, match="before_reconciliation_deadline"):
        MediaOperationResultV1.model_validate({
            **payload, "completed_at": deadline - timedelta(microseconds=1),
        })
    target = payload["target_results"][0]
    with pytest.raises(ValidationError, match="unknown_terminal_binding"):
        MediaTargetOperationResultV1.model_validate({
            **target, "core_unknown_terminal_commitment": None,
        })

def test_media_result_cannot_use_pre_dispatch_observation_or_missing_effect_evidence(
    media_target_result_fixture,
) -> None:
    for mutation in (
        {"dispatch_context_commitment": None},
        {"effect_commitment": None},
        {"observed_at": media_target_result_fixture["dispatch_started_at"] - timedelta(microseconds=1)},
    ):
        with pytest.raises(ValidationError):
            MediaTargetOperationResultV1.model_validate({**media_target_result_fixture, **mutation})
    with pytest.raises(ValidationError):
        MediaTargetOperationResultV1.model_validate({
            **media_target_result_fixture,
            "state": "ACCEPTED_UNVERIFIED",
            "observation_strength": "command_ack_only",
            "observed_at": media_target_result_fixture["dispatch_started_at"] - timedelta(microseconds=1),
        })

@pytest.mark.parametrize(("state", "attempt", "strength", "terminal_bound", "accepted"), [
    ("FAILED", 0, "none", False, True),
    ("FAILED", 0, "independence_proven", False, False),
    ("FAILED", 1, "none", False, True),
    ("UNKNOWN", 0, "none", True, False),
    ("UNKNOWN", 1, "none", False, False),
    ("UNKNOWN", 1, "none", True, True),
    ("ACCEPTED_UNVERIFIED", 0, "none", False, False),
    ("ACCEPTED_UNVERIFIED", 1, "none", False, False),
    ("ACCEPTED_UNVERIFIED", 1, "mirrored_optimistic", False, False),
    ("ACCEPTED_UNVERIFIED", 1, "command_ack_only", False, True),
    ("VERIFIED_PLAYING", 0, "same_adapter_observed", False, False),
    ("VERIFIED_PLAYING", 1, "same_adapter_observed", False, True),
])
def test_media_target_state_attempt_and_strength_matrix_is_exact(
    media_target_result_payload, valid_hmac_commitment,
    state, attempt, strength, terminal_bound, accepted,
) -> None:
    payload = media_target_result_payload(
        state=state,
        dispatch_attempt=attempt,
        observation_strength=strength,
        core_unknown_terminal_commitment=(valid_hmac_commitment if terminal_bound else None),
    )
    if accepted:
        MediaTargetOperationResultV1.model_validate(payload)
    else:
        with pytest.raises(ValidationError):
            MediaTargetOperationResultV1.model_validate(payload)

async def test_attempt_zero_failure_has_one_immutable_not_dispatched_record(
    media_reconciliation_service, failed_before_dispatch_operation,
) -> None:
    result = await media_reconciliation_service.reconcile(failed_before_dispatch_operation)
    target = result.target_results[0]
    assert target.state == "FAILED"
    assert target.dispatch_attempt == 0
    assert target.target_transition_kind == "not_dispatched"
    assert target.dispatch_started_at is None
    restarted = await media_reconciliation_service.restart()
    assert await restarted.verify_and_publish(result) == result
    assert await restarted.transition_record(target.target_transition_record_commitment) == {
        "operation_id": result.operation_id,
        "target_id": target.target_id,
        "kind": "not_dispatched",
        "dispatch_evidence": None,
    }

def test_media_dispatch_receipt_cannot_claim_result_truth_or_expire_early(
    media_dispatch_receipt_fixture,
) -> None:
    for state in ("verified", "partial"):
        with pytest.raises(ValidationError):
            MediaDispatchReceiptV1.model_validate({
                **media_dispatch_receipt_fixture,
                "state": state,
            })
    with pytest.raises(ValidationError, match="expired_before_deadline"):
        MediaDispatchReceiptV1.model_validate({
            **media_dispatch_receipt_fixture,
            "state": "expired",
            "dispatch_attempt": 0,
            "dispatch_started_at": None,
            "dispatch_context_commitment": None,
            "effect_commitment": None,
            "terminal_at": media_dispatch_receipt_fixture["expires_at"] - timedelta(microseconds=1),
            "observed_at": media_dispatch_receipt_fixture["expires_at"],
        })
    with pytest.raises(ValidationError, match="observation_predates_issue"):
        MediaDispatchReceiptV1.model_validate({
            **media_dispatch_receipt_fixture,
            "observed_at": media_dispatch_receipt_fixture["issued_at"] - timedelta(microseconds=1),
        })
    with pytest.raises(ValidationError, match="terminal_predates_dispatch"):
        MediaDispatchReceiptV1.model_validate({
            **media_dispatch_receipt_fixture,
            "state": "accepted_unverified",
            "terminal_at": media_dispatch_receipt_fixture["dispatch_started_at"] - timedelta(microseconds=1),
        })
    with pytest.raises(ValidationError, match="undispatched_media_state_claims_attempt"):
        MediaDispatchReceiptV1.model_validate({
            **media_dispatch_receipt_fixture,
            "state": "expired",
            "terminal_at": media_dispatch_receipt_fixture["expires_at"],
            "observed_at": media_dispatch_receipt_fixture["expires_at"],
        })
    exact_expiry = {
        **media_dispatch_receipt_fixture,
        "state": "expired",
        "dispatch_attempt": 0,
        "dispatch_started_at": None,
        "dispatch_context_commitment": None,
        "effect_commitment": None,
        "terminal_at": media_dispatch_receipt_fixture["expires_at"],
        "observed_at": media_dispatch_receipt_fixture["expires_at"],
    }
    assert MediaDispatchReceiptV1.model_validate(exact_expiry).state == "expired"

def test_media_adapter_receipt_cannot_claim_core_unknown(
    media_dispatch_receipt_fixture,
) -> None:
    with pytest.raises(ValidationError):
        MediaDispatchReceiptV1.model_validate({
            **media_dispatch_receipt_fixture,
            "state": "unknown",
            "terminal_at": media_dispatch_receipt_fixture["reconciliation_deadline"],
            "observed_at": media_dispatch_receipt_fixture["reconciliation_deadline"],
        })

def test_media_unknown_terminal_has_one_core_owned_deadline(
    media_unknown_terminal_fixture,
) -> None:
    terminal = MediaDispatchUnknownTerminalV1.model_validate(media_unknown_terminal_fixture)
    deadline = terminal.reconciliation_deadline
    assert terminal.record_kind == "core_unknown_terminal"
    assert terminal.terminal_at == deadline
    assert terminal.materialized_at >= deadline
    assert terminal.terminal_id == deterministic_media_terminal_id(
        terminal.operation_id,
        terminal.signed_envelope_digest,
        terminal.target_transition_set_commitment,
    )
    for terminal_at in (
        deadline - timedelta(microseconds=1),
        deadline + timedelta(microseconds=1),
    ):
        with pytest.raises(ValidationError, match="not_at_reconciliation_deadline"):
            MediaDispatchUnknownTerminalV1.model_validate({
                **media_unknown_terminal_fixture, "terminal_at": terminal_at,
            })

async def test_media_core_terminal_and_timestamps_are_not_network_constructible(
    media_adapter_ingress, media_unknown_terminal_fixture, media_terminal_repository,
) -> None:
    with pytest.raises(MediaReceiptBindingError, match="adapter_receipt_only"):
        await media_adapter_ingress.accept(media_unknown_terminal_fixture)
    assert media_terminal_repository.writes == []

def test_media_terminal_cross_domain_and_wrong_purpose_replay_rejects(
    media_unknown_terminal_fixture, media_signature_verifier,
) -> None:
    for domain, purpose in (
        ("tuntun-media-v1", "media_action"),
        ("tuntun-media-group-v1", "media_group_manifest"),
        ("tuntun-child-media-rule-v1", "child_media_rule"),
        (
            "tuntun-media-dispatch-unknown-terminal-v1",
            "media_action",
        ),
    ):
        with pytest.raises(SignatureVerificationError):
            media_signature_verifier.verify(
                media_unknown_terminal_fixture, domain, purpose,
            )

def test_adapter_key_cannot_mint_core_media_unknown_terminal(
    media_unknown_terminal_fixture, adapter_test_signer, media_terminal_verifier,
) -> None:
    forged = resign_with_key(
        media_unknown_terminal_fixture,
        adapter_test_signer,
        domain="tuntun-media-dispatch-unknown-terminal-v1",
        purpose="core_media_dispatch_unknown_terminal",
    )
    with pytest.raises(SignatureVerificationError, match="key_role_or_purpose"):
        media_terminal_verifier.verify(forged)

def test_media_terminal_rejects_future_materialization(
    media_unknown_terminal_fixture, media_terminal_verifier,
) -> None:
    terminal = MediaDispatchUnknownTerminalV1.model_validate(media_unknown_terminal_fixture)
    with pytest.raises(MediaResultBindingError, match="future_materialization"):
        media_terminal_verifier.verify(
            terminal,
            trusted_verification_time=terminal.materialized_at - timedelta(microseconds=1),
        )

@pytest.mark.parametrize("field", [
    "terminal_id", "operation_id", "request_id", "action_id", "idempotency_key",
    "action_type", "target_kind", "target_player_or_group_id", "target_ids",
    "signed_envelope_digest", "dispatch_started_at", "dispatch_context_commitment",
    "effect_commitment", "target_transition_set_commitment", "controller_epoch",
    "topology_generation", "binding_generation", "provider_binding_id",
    "provider_generation", "adapter_generation", "capability_generation",
    "capability_digest", "entitlement_generation", "policy_version",
    "request_binding_commitment", "authorization_class", "child_rule_authority",
    "authorization_commitment", "authorized_at", "request_expires_at",
    "decision_valid_until", "issued_at", "expires_at", "reconciliation_deadline",
    "terminal_at", "materialized_at", "terminal_commitment", "core_key_id",
    "core_signature",
])
def test_media_core_terminal_substitution_rejects_before_publication(
    media_unknown_terminal_fixture, media_terminal_verifier,
    field, media_public_projection,
) -> None:
    with pytest.raises(MediaResultBindingError):
        media_terminal_verifier.verify(
            substitute_valid_value(media_unknown_terminal_fixture, field),
        )
    assert media_public_projection.writes == []

@pytest.mark.parametrize(("state", "boundary_field", "error"), [
    ("authorized_committed", "expires_at", "undispatched_media_nonterminal_at_deadline"),
    ("dispatching", "reconciliation_deadline", "attempted_media_nonterminal_at_reconciliation_deadline"),
    ("reconciling", "reconciliation_deadline", "attempted_media_nonterminal_at_reconciliation_deadline"),
])
def test_media_nonterminal_state_cannot_survive_its_deadline(
    media_dispatch_receipt_for_state, state, boundary_field, error,
) -> None:
    before = media_dispatch_receipt_for_state(state)
    boundary = before[boundary_field]
    MediaDispatchReceiptV1.model_validate({
        **before, "observed_at": boundary - timedelta(microseconds=1),
    })
    with pytest.raises(ValidationError, match=error):
        MediaDispatchReceiptV1.model_validate({**before, "observed_at": boundary})

def test_undispatched_media_failure_uses_terminal_time_not_late_receipt_time(
    media_dispatch_receipt_for_state,
) -> None:
    failure = media_dispatch_receipt_for_state("failed")
    before_expiry = failure["expires_at"] - timedelta(microseconds=1)
    delayed_but_bounded = {
        **failure,
        "terminal_at": before_expiry,
        "observed_at": failure["expires_at"] + timedelta(microseconds=1),
    }
    assert MediaDispatchReceiptV1.model_validate(delayed_but_bounded).state == "failed"
    with pytest.raises(
        ValidationError, match="undispatched_media_failure_at_deadline_must_expire",
    ):
        MediaDispatchReceiptV1.model_validate({
            **failure,
            "terminal_at": failure["expires_at"],
            "observed_at": failure["expires_at"],
        })

async def test_media_deadline_recovery_terminalizes_once_without_redispatch(
    media_bridge_runtime, authorized_committed_operation, dispatching_operation,
) -> None:
    restarted = await media_bridge_runtime.crash_and_restart_at_deadlines()
    undispatched = await restarted.receipt(authorized_committed_operation)
    attempted = await restarted.core_unknown_terminal(dispatching_operation)
    assert (undispatched.state, undispatched.dispatch_attempt) == ("expired", 0)
    assert isinstance(attempted, MediaDispatchUnknownTerminalV1)
    assert attempted.dispatch_attempt == 1
    assert attempted.terminal_at == attempted.reconciliation_deadline
    assert restarted.new_player_effect_calls == ()

@pytest.mark.parametrize("offset", [
    -timedelta(microseconds=1), timedelta(0), timedelta(microseconds=1),
])
async def test_media_core_unknown_finalizer_boundary_is_idempotent(
    media_deadline_finalizer, dispatching_operation, offset,
) -> None:
    deadline = dispatching_operation.reconciliation_deadline
    media_deadline_finalizer.clock.set(deadline + offset)
    terminal = await media_deadline_finalizer.finalize(dispatching_operation.operation_id)
    if offset < timedelta(0):
        assert terminal is None
        return
    assert terminal.terminal_at == deadline
    restarted = await media_deadline_finalizer.restart()
    assert await restarted.finalize(dispatching_operation.operation_id) == terminal
    assert restarted.new_player_effect_calls == ()

async def test_late_media_adapter_evidence_cannot_replace_core_terminal(
    media_deadline_finalizer, dispatching_operation, delayed_adapter_receipt,
) -> None:
    terminal = await media_deadline_finalizer.finalize_at_deadline(
        dispatching_operation.operation_id,
    )
    with pytest.raises(MediaReceiptBindingError, match="late_receiver_ingress"):
        await media_deadline_finalizer.accept_adapter_receipt(delayed_adapter_receipt)
    assert await media_deadline_finalizer.current_terminal(
        dispatching_operation.operation_id,
    ) == terminal
    retained = await media_deadline_finalizer.late_evidence_for(
        dispatching_operation.operation_id,
    )
    assert retained.adapter_receipt_digest == canonical_digest(delayed_adapter_receipt)
    assert retained.disposition == "retained_not_authoritative"
    assert media_deadline_finalizer.new_player_effect_calls == ()

@pytest.mark.parametrize("deadline_field", ["request_expires_at", "decision_valid_until"])
def test_media_envelope_and_receipt_reject_authority_deadline_equality(
    signed_media_envelope_fixture, media_dispatch_receipt_fixture, deadline_field,
) -> None:
    for model, fixture in (
        (SignedMediaEnvelopeV1, signed_media_envelope_fixture),
        (MediaDispatchReceiptV1, media_dispatch_receipt_fixture),
    ):
        with pytest.raises(ValidationError, match="outlives_request_or_decision"):
            model.model_validate({**fixture, deadline_field: fixture["issued_at"]})

@pytest.mark.parametrize("field", [
    "operation_id", "request_id", "action_id", "idempotency_key", "action_type",
    "target_kind", "target_player_or_group_id", "target_ids",
    "signed_envelope_digest", "controller_epoch",
    "topology_generation", "binding_generation", "capability_generation",
    "capability_digest", "provider_binding_id", "provider_generation", "adapter_generation",
    "entitlement_generation",
    "policy_version", "request_binding_commitment", "authorization_class",
    "child_rule_authority", "authorization_commitment",
    "authorized_at", "request_expires_at", "decision_valid_until", "issued_at",
    "expires_at", "reconciliation_deadline", "effect_commitment",
])
def test_media_receipt_must_exact_match_stored_signed_envelope(
    stored_signed_media_envelope, media_dispatch_receipt_fixture, field,
) -> None:
    with pytest.raises(MediaReceiptBindingError):
        validate_media_dispatch_receipt_binding(
            stored_signed_media_envelope,
            substitute_valid_value(media_dispatch_receipt_fixture, field),
        )

def test_ephemeral_learning_summary_cannot_outlive_five_minutes(ephemeral_summary_fields) -> None:
    with pytest.raises(ValueError):
        EphemeralLearningSummary(**{
            **ephemeral_summary_fields,
            "expires_at": ephemeral_summary_fields["created_at"] + timedelta(minutes=5, microseconds=1),
        })

def test_tv_binding_and_evidence_cannot_overclaim_routes(tv_binding_fixture, tv_capability_evidence_fixture) -> None:
    power = tv_binding_fixture["screen_time_power_eligibility"]
    with pytest.raises(ValidationError):
        TelevisionBindingV1.model_validate({
            **tv_binding_fixture,
            "screen_time_power_eligibility": {
                **power,
                "endpoint_id": "tv_synth_substituted",
            },
        })
    with pytest.raises(ValidationError):
        TVCapabilityEvidenceV1.model_validate({
            **tv_capability_evidence_fixture,
            "evidence_kind": "observation",
            "operation": "tv.set_power.v1",
        })

@pytest.mark.parametrize("mutation", [
    substitute_power_endpoint_generation_only,
    substitute_standby_control_generation_only,
    substitute_power_observation_generation_only,
])
def test_tv_power_eligibility_uses_distinct_generation_dimensions(
    tv_binding_fixture, mutation,
) -> None:
    binding = TelevisionBindingV1.model_validate(tv_binding_fixture)
    power = binding.screen_time_power_eligibility
    assert len({
        binding.endpoint_generation,
        binding.binding_generation,
        binding.capability_generation,
        power.standby_control_generation,
        power.power_observation_generation,
    }) == 5
    with pytest.raises(ValidationError):
        TelevisionBindingV1.model_validate(mutation(tv_binding_fixture))

def test_generic_tv_capability_does_not_confer_screen_time_power_eligibility(tv_binding_fixture) -> None:
    binding = TelevisionBindingV1.model_validate(generic_input_only_tv_binding(tv_binding_fixture))
    assert tuple(item.operation for item in binding.control_bindings) == ("tv.select_input.v1",)
    assert binding.screen_time_power_eligibility.state == "DISPLAY_ONLY_MANUAL"
    with pytest.raises(ValidationError):
        TelevisionBindingV1.model_validate(power_eligibility_without_matching_power_route(tv_binding_fixture))

@pytest.mark.parametrize(("lifecycle_state", "power_state"), (
    ("candidate", "DISPLAY_ONLY_MANUAL"),
    ("commissioned", "UNCOMMISSIONED"),
    ("degraded", "STRICT_ELIGIBLE"),
    ("commissioned", "DEGRADED"),
    ("quarantined", "DEGRADED"),
    ("retired", "QUARANTINED"),
    ("commissioned", "QUARANTINED"),
    ("commissioned", "RETIRED"),
))
def test_tv_lifecycle_and_persisted_power_state_cannot_diverge(
    tv_binding_fixture, lifecycle_state, power_state,
) -> None:
    with pytest.raises(ValidationError):
        TelevisionBindingV1.model_validate(
            tv_binding_for_lifecycle_and_power_state(
                tv_binding_fixture,
                lifecycle_state=lifecycle_state,
                power_state=power_state,
            )
        )

@pytest.mark.parametrize(("lifecycle_state", "power_state"), (
    ("candidate", "UNCOMMISSIONED"),
    ("commissioned", "DISPLAY_ONLY_MANUAL"),
    ("commissioned", "OBSERVE_ONLY"),
    ("commissioned", "COOPERATIVE_ELIGIBLE"),
    ("commissioned", "STRICT_ELIGIBLE"),
    ("degraded", "DEGRADED"),
    ("quarantined", "QUARANTINED"),
    ("retired", "RETIRED"),
))
def test_tv_lifecycle_accepts_each_coherent_persisted_power_state(
    tv_binding_fixture, lifecycle_state, power_state,
) -> None:
    TelevisionBindingV1.model_validate(
        tv_binding_for_lifecycle_and_power_state(
            tv_binding_fixture,
            lifecycle_state=lifecycle_state,
            power_state=power_state,
        )
    )

def test_manual_override_contract_has_no_person_identity(manual_override_event_fixture) -> None:
    with pytest.raises(ValidationError):
        ManualOverrideEventV1.model_validate({
            **manual_override_event_fixture,
            "subject_id": uuid4(),
        })

@pytest.mark.parametrize(("source", "observation_adapter_id"), [
    ("contrary_observation", None),
    ("input_change", None),
    ("power_change", None),
    ("physical_remote", "observer_synth_01"),
    ("physical_button", "observer_synth_01"),
    ("renderer_stop", "observer_synth_01"),
])
def test_manual_override_source_requires_exact_adapter_shape(
    manual_override_event_fixture, source, observation_adapter_id,
) -> None:
    with pytest.raises(ValidationError):
        ManualOverrideEventV1.model_validate({
            **manual_override_event_fixture,
            "source": source,
            "observation_adapter_id": observation_adapter_id,
        })

def test_teaching_audience_and_decision_cannot_widen_child_or_guest(
    teaching_audience_fixture, authorized_child_teaching_request_fixture,
    teaching_authorization_decision_fixture,
) -> None:
    with pytest.raises(ValidationError):
        TeachingAudienceBindingV1.model_validate({
            **teaching_audience_fixture,
            "audience_class": "guest",
            "identity_mode": "identified",
            "memory_audience": "household",
        })
    for forbidden_audience in ("owner_private", "adult_private", "household", "public_only", "household_shared"):
        with pytest.raises(ValidationError):
            TeachingAudienceBindingV1.model_validate({
                **teaching_audience_fixture,
                "memory_audience": forbidden_audience,
            })
    child_request = AuthorizedTeachingRequestV1.model_validate(authorized_child_teaching_request_fixture)
    assert child_request.web_mode == "no_web"
    with pytest.raises(ValidationError):
        AuthorizedTeachingRequestV1.model_validate({
            **authorized_child_teaching_request_fixture,
            "web_mode": "controlled",
            "controlled_web_authorization_commitment": SYNTHETIC_COMMITMENT,
        })
    with pytest.raises(ValidationError):
        TeachingAuthorizationDecisionV1.model_validate({
            **teaching_authorization_decision_fixture,
            "effect": "allow",
            "authorized_request": None,
        })

def test_authorized_teaching_privacy_generation_matches_audience_binding(
    authorized_child_teaching_request_fixture,
) -> None:
    with pytest.raises(ValidationError, match="authorized_teaching_privacy_generation_mismatch"):
        AuthorizedTeachingRequestV1.model_validate({
            **authorized_child_teaching_request_fixture,
            "privacy_generation": (
                authorized_child_teaching_request_fixture["audience_binding"]["privacy_generation"] + 1
            ),
        })

@pytest.mark.parametrize("field", [
    "display_endpoint_generation",
    "display_binding_generation",
    "display_capability_generation",
    "display_capability_evidence_digest",
    "renderer_endpoint_generation",
    "renderer_binding_generation",
    "renderer_capability_generation",
    "renderer_capability_evidence_digest",
    "privacy_generation",
])
def test_resigned_teaching_manifest_with_stale_endpoint_or_privacy_authority_is_rejected(
    display_agent, teaching_manifest_fixture, current_display_authority, field,
) -> None:
    stale = resign_teaching_manifest(mutate_authority(teaching_manifest_fixture, field))
    with pytest.raises(StaleDisplayAuthority):
        display_agent.validate(stale, current_display_authority)

def test_display_reboot_rejects_pre_privacy_shield_text_only_manifest(
    display_agent_factory, text_only_teaching_manifest, signed_privacy_controls,
) -> None:
    agent = display_agent_factory()
    agent.apply_privacy_control(signed_privacy_controls.on)
    agent = display_agent_factory(restart=True)
    with pytest.raises(StaleDisplayAuthority):
        agent.validate(text_only_teaching_manifest, signed_privacy_controls.current_authority)

def test_teaching_memory_audience_round_trip_is_phase1_canonical(
    child_teaching_audience_fixture, teaching_manifest_fixture,
) -> None:
    audience = TeachingAudienceBindingV1.model_validate({
        **child_teaching_audience_fixture,
        "memory_audience": "household_all",
        "child_safe_household_approval_grant_id": uuid4(),
    })
    assert audience.model_dump(mode="json")["memory_audience"] == "household_all"
    with pytest.raises(ValidationError, match="household_approval"):
        TeachingSessionManifestV1.model_validate({
            **teaching_manifest_fixture,
            "audience_class": "k2_child",
            "memory_audience": "household_all",
            "child_safe_household_approval_commitment": None,
        })

def test_guest_teaching_has_no_memory_audience_or_retrieval(
    teaching_audience_fixture, memory_reader,
) -> None:
    guest = TeachingAudienceBindingV1.model_validate(guest_teaching_audience(teaching_audience_fixture))
    assert guest.memory_audience is None
    assert guest.presentation_policy == "generic_guest_public"
    assert memory_reader.calls == []

def test_valid_guest_teaching_manifest_round_trips_without_adult_or_child_authority(
    guest_teaching_manifest_fixture,
) -> None:
    manifest = TeachingSessionManifestV1.model_validate(guest_teaching_manifest_fixture)
    assert manifest.audience_class == "guest"
    assert manifest.memory_audience is None
    assert manifest.presentation_policy == "generic_guest_public"
    assert manifest.web_mode == "no_web"
    assert manifest.child_extended_duration_commitment is None
    assert manifest.child_safe_household_approval_commitment is None

def test_system_tv_request_requires_enforcement_and_no_human_subject(authorized_tv_request_fixture) -> None:
    for mutation in (
        {"actor_class": "system_screen_time", "actor_subject_id": uuid4()},
        {"actor_class": "system_screen_time", "enforcement_generation": None},
        {"actor_class": "owner", "authorization_class": "system_enforcement"},
        {"actor_class": "owner", "actor_subject_id": uuid4(),
         "authorization_class": "owner_passkey", "enforcement_generation": 4},
        {"actor_class": "adult", "actor_subject_id": uuid4(),
         "authorization_class": "exact_confirmation", "enforcement_generation": 4},
        {"actor_class": "current_guardian", "actor_subject_id": uuid4(),
         "authorization_class": "exact_confirmation", "enforcement_generation": None},
        {"actor_class": "adult", "actor_subject_id": uuid4(),
         "authorization_class": "owner_passkey", "enforcement_generation": None},
        {"actor_class": "system_screen_time", "actor_subject_id": None,
         "authorization_class": "system_enforcement", "enforcement_generation": 4,
         "operation": "tv.mute.v1", "desired_power": None, "desired_muted": True},
        {"actor_class": "system_screen_time", "actor_subject_id": None,
         "authorization_class": "system_enforcement", "enforcement_generation": 4,
         "operation": "tv.set_power.v1", "desired_power": "ON"},
    ):
        with pytest.raises(ValidationError):
            AuthorizedTVRequestV1.model_validate({**authorized_tv_request_fixture, **mutation})

@pytest.mark.parametrize(("actor_class", "authorization_class"), [
    ("owner", "owner_passkey"),
    ("adult", "exact_confirmation"),
])
def test_human_tv_requests_require_subject_and_forbid_enforcement_generation(
    authorized_tv_request_fixture, actor_class, authorization_class,
) -> None:
    request = AuthorizedTVRequestV1.model_validate({
        **authorized_tv_request_fixture,
        "actor_class": actor_class,
        "actor_subject_id": uuid4(),
        "authorization_class": authorization_class,
        "enforcement_generation": None,
    })
    assert request.enforcement_generation is None

@pytest.mark.parametrize(("operation", "desired_field", "desired_value"), [
    ("tv.set_power.v1", "desired_power", "ON"),
    ("tv.set_power.v1", "desired_power", "STANDBY"),
    ("tv.select_input.v1", "desired_input_id", "hdmi_1"),
    ("tv.set_volume.v1", "desired_volume_percent", 25),
    ("tv.send_key.v1", "desired_key", "select"),
    ("tv.launch_app.v1", "desired_app_id", "app_synth_01"),
])
def test_human_tv_risky_actions_reject_immediate_under_assurance(
    authorized_tv_request_for_operation, operation, desired_field, desired_value,
) -> None:
    payload = clear_other_tv_desired_fields(
        authorized_tv_request_for_operation(operation), desired_field, desired_value,
    )
    with pytest.raises(ValidationError, match="under_assured"):
        AuthorizedTVRequestV1.model_validate({
            **payload,
            "actor_class": "adult",
            "actor_subject_id": uuid4(),
            "authorization_class": "adult_reversible_immediate",
            "enforcement_generation": None,
        })

@pytest.mark.parametrize(("operation", "desired_field", "desired_value"), [
    ("tv.mute.v1", "desired_muted", True),
    ("tv.mute.v1", "desired_muted", False),
    ("tv.send_key.v1", "desired_key", "home"),
    ("tv.send_key.v1", "desired_key", "back"),
    ("tv.send_key.v1", "desired_key", "up"),
    ("tv.send_key.v1", "desired_key", "down"),
    ("tv.send_key.v1", "desired_key", "left"),
    ("tv.send_key.v1", "desired_key", "right"),
])
def test_human_tv_immediate_class_is_closed_to_reversible_controls(
    authorized_tv_request_for_operation, operation, desired_field, desired_value,
) -> None:
    payload = clear_other_tv_desired_fields(
        authorized_tv_request_for_operation(operation), desired_field, desired_value,
    )
    request = AuthorizedTVRequestV1.model_validate({
        **payload,
        "actor_class": "adult",
        "actor_subject_id": uuid4(),
        "authorization_class": "adult_reversible_immediate",
        "enforcement_generation": None,
    })
    assert request.authorization_class == "adult_reversible_immediate"

@pytest.mark.parametrize("operation", [
    "tv.set_power.v1", "tv.select_input.v1", "tv.set_volume.v1",
    "tv.mute.v1", "tv.send_key.v1", "tv.launch_app.v1",
])
def test_guardian_rule_cannot_serialize_a_generic_tv_action(
    authorized_tv_request_for_operation, operation, tv_adapter_spy,
) -> None:
    payload = authorized_tv_request_for_operation(operation)
    with pytest.raises(ValidationError):
        AuthorizedTVRequestV1.model_validate({
            **payload,
            "actor_class": "current_guardian",
            "actor_subject_id": uuid4(),
            "authorization_class": "guardian_screen_time_rule",
            "enforcement_generation": None,
        })
    assert tv_adapter_spy.calls == []

def test_phase4_maintenance_record_separates_ordinary_and_excluded_time(phase4_maintenance_fixture) -> None:
    with pytest.raises(ValidationError):
        Phase4MaintenanceRecordV1.model_validate({
            **phase4_maintenance_fixture,
            "record_class": "ordinary",
            "excluded_event_class": "incident",
        })
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/whole_home/test_phase4_contracts.py tests/property/whole_home/test_contract_rejection.py tests/contract/whole_home/test_area_id_only.py -q`
Expected: collection fails with `ModuleNotFoundError: No module named 'tuntun_contracts.whole_home'`.

- [ ] **Step 3: Implement the complete models and exact bounds**

Implement every contract as a frozen discriminated model, not an open attribute map. Use an exact `Literal["1.0"]` major/minor version, bounded tuples, validated stable IDs, integer confidence/SNR buckets, and aware UTC. Keep `SpeechFrameV1.payload` out of JSON/OpenAPI; its binary header declares exact payload length and remaining lease quota. Add validators for:

- 3–5-second endpoint pre-roll configuration and 90-second/8-MiB leased maxima;
- claim expiry, lease single-use binding, strict monotonic sequence, and generation equality;
- 350 ms decision window, 1.5-second correlation window, and exactly one winner;
- exact control/playback byte and receipt shapes, one-slot admission, reply-route endpoint/volume coherence, and all port-authority lifetimes;
- mute/egress health coherence, arbitration winner/reason/time coherence, and cancellation/result receipt truth;
- credential-free provider bindings, 90-day entitlement reviews, exact player capability/freshness/volume semantics, immutable media groups, and per-player volume ceilings;
- catalog result state/handle cardinality, exact request/decision/action-specific media fields, unknown-observation truth, manifest-ordered result aggregation, and handles that contain no URL/path/provider credential and expire;
- display manifest session/display/audience/policy binding, two-hour absolute maximum, child default 30 minutes, component/asset quotas, and closed MIME types;
- exact-unit TV binding/eligibility and capability-evidence shapes, desired-state-only television actions, exact control receipt evidence, identity-free manual override, registered closed observation dimensions, and five-second observation freshness;
- screen-time attempt ordinal `1|2` and an enforcement generation;
- canonical `area_id` and optional same-area nested `zone_id` only.

- [ ] **Step 4: Generate deterministic artifacts and prove no forbidden alias**

Run:

```bash
uv run python scripts/phase4/generate_schemas.py --check
rg -n -i 'room_id|roomId|"room"[[:space:]]*:' packages/contracts/src/tuntun_contracts/whole_home schemas/whole-home fixtures/synthetic/whole-home fixtures/synthetic/ui/phase4
```

Expected: generator reports `phase4 schema drift: none`; `rg` exits 1 with no matches. Human prose labels may say “room,” but no machine contract key may do so.

- [ ] **Step 5: Run green, property, type, and dependency checks**

Run:

```bash
uv run pytest tests/contract/whole_home tests/property/whole_home/test_contract_rejection.py -q
uv run ruff format --check packages/contracts/src/tuntun_contracts/whole_home scripts/phase4/generate_schemas.py tests/contract/whole_home tests/property/whole_home
uv run ruff check packages/contracts/src/tuntun_contracts/whole_home scripts/phase4/generate_schemas.py tests/contract/whole_home tests/property/whole_home
uv run mypy packages/contracts/src
uv run pytest tests/contract/test_dependency_direction.py -q
```

Expected: PASS; unknown versions/fields/variants/enums, duplicate keys, wrong signature domain, naive/noncanonical time, over-bounds audio/assets/text, stale generations, `room_id`, cross-area zones, URL/path/HTML/script/service/key/code/account fields, and false result aggregation are rejected.

- [ ] **Step 6: Commit exact contract paths**

```bash
git add packages/contracts/src/tuntun_contracts/whole_home packages/contracts/src/tuntun_contracts/home/topology.py packages/contracts/src/tuntun_contracts/home/screen_time.py packages/contracts/src/tuntun_contracts/ui.py scripts/phase4/generate_schemas.py schemas/whole-home/v1 fixtures/synthetic/whole-home/contracts fixtures/synthetic/ui/phase4 tests/contract/whole_home tests/property/whole_home/test_contract_rejection.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(whole-home): freeze Phase 4 contracts"
```

### Task 02: Build deterministic Phase 4 fakes, corpora, and fault points

**Depends on:** Task 01.
**Gate contribution:** P4-E0 and every P4-0–P4-7 simulator gate.
**Estimated effort:** 2.5 person-days.

**Files:**

- Create `packages/testing/src/tuntun_testing/whole_home/{__init__,fake_clock,fake_endpoint,fake_player,fake_renderer,fake_tv,fault_points,scenario}.py`.
- Create `scripts/phase4/build_corpora.py`.
- Create `fixtures/synthetic/whole-home/policy-corpus-v1.jsonl`.
- Create `fixtures/synthetic/whole-home/duplicate-wake-corpus-v1.jsonl`, `routing-corpus-v1.jsonl`, `media-adversarial-corpus-v1.jsonl`, `display-manifest-corpus-v1.jsonl`, and `television-fault-corpus-v1.jsonl`.
- Create `fixtures/synthetic/whole-home/fault-matrix-v1.json`.
- Test `tests/unit/testing/whole_home/test_phase4_scenario.py`.
- Test `tests/contract/whole_home/test_phase4_corpora.py`.
- Test `tests/security/whole_home/test_simulator_has_no_external_io.py`.

**Interfaces:** `WholeHomeScenario.run(events: tuple[ScenarioEvent, ...]) -> ScenarioResult`; `Phase4FaultPlan.hit(point: Phase4FaultPoint)`; deterministic seed `240827`; at least 500 duplicate-wake cases, 1,000 routing/audience cases, 500 adversarial media cases, 500 display manifests, the unchanged 720 screen-time oracle rows loaded from their canonical Phase 2 fixture, and 10,000 generated screen-time sequences. The exact Phase 4 policy corpus is generated and structurally validated here, but is not evaluated until Task 05 has Task 04's Phase 4 policy amendments; it contains only Phase 4 amendment/cross-domain cases and never copies or forks the Phase 2 oracle rows. The exact fault-matrix fixture contains one canonical row per `Phase4FaultPoint` plus required cross-component outage row, with unique IDs and closed expected safe terminals; later runners may consume but not synthesize or weaken it.

- [ ] **Step 1: Write red count, determinism, and no-I/O tests**

```python
def test_required_phase4_corpus_counts() -> None:
    policy_rows = load_jsonl("policy-corpus-v1.jsonl")
    assert required_phase4_amendment_ids() <= amendment_ids(policy_rows)
    assert_no_copied_phase2_oracle_rows(policy_rows)
    assert len(load_jsonl("duplicate-wake-corpus-v1.jsonl")) >= 500
    assert len(load_jsonl("routing-corpus-v1.jsonl")) >= 1_000
    assert len(load_jsonl("media-adversarial-corpus-v1.jsonl")) >= 500
    assert len(load_jsonl("display-manifest-corpus-v1.jsonl")) >= 500
    assert exact_fault_rows("fault-matrix-v1.json") == required_phase4_fault_rows()

def test_scenario_is_deterministic_and_offline(no_external_io: None) -> None:
    events = seeded_phase4_events(seed=240827, count=1_000)
    assert WholeHomeScenario.synthetic().run(events) == WholeHomeScenario.synthetic().run(events)
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/testing/whole_home tests/contract/whole_home/test_phase4_corpora.py tests/security/whole_home/test_simulator_has_no_external_io.py -q`
Expected: collection fails because `tuntun_testing.whole_home` and the corpora do not exist.

- [ ] **Step 3: Implement closed fakes and crash boundaries**

```python
class Phase4FaultPoint(StrEnum):
    AFTER_CLAIM_BEFORE_LEASE = "speech.after_claim_before_lease"
    AFTER_LEASE_BEFORE_FIRST_FRAME = "speech.after_lease_before_first_frame"
    AFTER_AUTH_COMMIT_BEFORE_MEDIA_SIGN = "media.after_auth_commit_before_sign"
    HA_AFTER_RECEIPT_BEFORE_MEDIA_IO = "ha.after_receipt_before_media_io"
    AFTER_DISPLAY_COMMIT_BEFORE_MANIFEST = "display.after_commit_before_manifest"
    RENDERER_AFTER_RENDER_BEFORE_RECEIPT = "display.after_render_before_receipt"
    AFTER_TV_COMMIT_BEFORE_DISPATCH = "tv.after_commit_before_dispatch"
    TV_AFTER_CONTROL_BEFORE_OBSERVATION = "tv.after_control_before_observation"
    AFTER_SCREEN_ATTEMPT_BEFORE_TERMINAL = "screen.after_attempt_before_terminal"

@dataclass(slots=True)
class FakeEndpoint:
    endpoint_id: str
    area_id: str
    area_generation: int
    hardware_muted: bool = False
    indicator_ready: bool = True
    frames_sent: list[int] = field(default_factory=list)
    candidate_bytes: bytearray = field(default_factory=bytearray)
```

Corpus generation must include tied receipt order, skew, duplicate/replayed claims, mute races, stale generations, two simultaneous speakers, wrong-room reply, private/child/Guest audiences, handoff expiry/substitution, arbitrary media inputs, display injection/compression bombs, TV ACK-without-effect, stale mirrored state, manual override, restart, network loss, and attempt-three attacks. Import the Phase 2 720-row corpus; do not fork its expected policy transitions.

- [ ] **Step 4: Generate twice and run green**

Run:

```bash
uv run python scripts/phase4/build_corpora.py --check
uv run python scripts/phase4/build_corpora.py --check
uv run pytest tests/unit/testing/whole_home tests/contract/whole_home/test_phase4_corpora.py tests/security/whole_home/test_simulator_has_no_external_io.py -q
uv run ruff check packages/testing/src/tuntun_testing/whole_home scripts/phase4/build_corpora.py tests/unit/testing/whole_home tests/contract/whole_home/test_phase4_corpora.py tests/security/whole_home/test_simulator_has_no_external_io.py
uv run mypy packages/testing/src
```

Expected: both builds are byte-identical; no socket, subprocess, hardware, Keychain, HA/MA, browser, or paid-provider call occurs; losing fake endpoints finish with zero candidate bytes.

- [ ] **Step 5: Commit fake and corpus paths**

```bash
git add packages/testing/src/tuntun_testing/whole_home scripts/phase4/build_corpora.py fixtures/synthetic/whole-home/policy-corpus-v1.jsonl fixtures/synthetic/whole-home/duplicate-wake-corpus-v1.jsonl fixtures/synthetic/whole-home/routing-corpus-v1.jsonl fixtures/synthetic/whole-home/media-adversarial-corpus-v1.jsonl fixtures/synthetic/whole-home/display-manifest-corpus-v1.jsonl fixtures/synthetic/whole-home/television-fault-corpus-v1.jsonl fixtures/synthetic/whole-home/fault-matrix-v1.json tests/unit/testing/whole_home tests/contract/whole_home/test_phase4_corpora.py tests/security/whole_home/test_simulator_has_no_external_io.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(whole-home): add deterministic Phase 4 simulators"
```

### Task 03: Add encrypted endpoint, media/display, television, and real-adapter persistence

**Depends on:** Tasks 01–02 and the exact canonical core head `0015_presence_checkpoint`. Phase 4 refuses startup if the linear core graph or any one exact predecessor differs.
**Gate contribution:** P4-E0, P4-0, crash recovery for P4-2–P4-6.
**Estimated effort:** 5 person-days.

**Files:**

- Create `apps/core/migrations/versions/0016_whole_home_endpoints.py` through `0019_screen_time_real_adapter.py`.
- Create `apps/core/src/tuntun_core/domain/whole_home/{__init__,rooms,speech,media,display,television}.py`.
- Modify `apps/core/src/tuntun_core/adapters/sqlcipher/models.py`.
- Create `apps/core/src/tuntun_core/adapters/sqlcipher/whole_home_repository.py`.
- Create `apps/core/src/tuntun_core/services/transactions/whole_home_uow.py`.
- Modify `apps/core/src/tuntun_core/adapters/sqlcipher/async_unit_of_work.py`.
- Create `docs/operations/phase4-update-rollback.md`.
- Test `tests/integration/whole_home/test_phase4_migrations.py`.
- Test `tests/integration/whole_home/test_phase2_phase4_core_graph.py`.
- Test `tests/integration/whole_home/test_phase4_repository_invariants.py`.
- Test `tests/integration/whole_home/test_whole_home_uow_registration.py`.
- Test `tests/security/whole_home/test_phase4_schema_minimization.py`.

**Interfaces:** The canonical implementations live in `adapters/sqlcipher/whole_home_repository.py`, use the existing SQLCipher models/session, and are exposed only through the typed `WholeHomeUnitOfWork` view registered on the existing serialized `AsyncUnitOfWork`; there is no parallel engine, session maker, or transaction manager. They provide methods for registrations, current privacy/capability generations, one-slot admission, minimized immutable playback-terminal evidence, immutable media actions/per-target transitions/Core deadline terminals/results, minimized teaching-manifest authority, signed display-clear requests/lifecycle receipts, exact TV action/Core deadline-terminal/observation evidence, and two-attempt enforcement. `test_whole_home_uow_registration.py` proves every promised repository is registered once, shares the caller's transaction, rolls back atomically, and is unreachable outside the UoW. No repository exists for raw claims, ordinary frames, audio bytes, query text, display bodies/components/assets, pixels, or ephemeral learning summaries.

- [ ] **Step 1: Write red migration and forbidden-column tests**

```python
def test_only_one_nonterminal_conversation_slot(uow: AsyncUnitOfWork) -> None:
    uow.conversations.add(active_admission(slot=0, conversation_id=UUID(int=1)))
    with pytest.raises(IntegrityError):
        uow.conversations.add(active_admission(slot=0, conversation_id=UUID(int=2)))

def test_conversation_slot_other_than_zero_is_rejected(uow: AsyncUnitOfWork) -> None:
    with pytest.raises((ValidationError, IntegrityError)):
        uow.conversations.add(active_admission(slot=1, conversation_id=UUID(int=3)))

def test_phase4_schema_has_no_payload_or_parallel_location(sqlcipher_schema: Schema) -> None:
    forbidden = {
        "room_id", "audio", "waveform", "transcript", "embedding", "query_text",
        "provider_uri", "html", "javascript", "asset_bytes", "screenshot",
        "learning_summary", "lesson_text", "credential", "serial_number", "mac_address",
    }
    assert forbidden.isdisjoint(sqlcipher_schema.column_names())

def test_phase4_lineage_tables_exist_and_are_immutable_minimized_authority(
    sqlcipher_schema: Schema,
) -> None:
    required = {
        "speech_playback_terminal_frames", "media_target_transition_records",
        "media_dispatch_unknown_terminals", "media_late_dispatch_evidence",
        "tv_dispatch_unknown_terminals", "tv_late_dispatch_evidence",
        "teaching_manifest_authority_records", "display_clear_requests",
    }
    assert required <= sqlcipher_schema.table_names()
    for table in required:
        assert sqlcipher_schema.rejects_semantic_update(table)
        assert sqlcipher_schema.rejects_delete_before_retention_deadline(table)
        assert sqlcipher_schema.allows_fk_safe_purge_at_retention_deadline(table)
    forbidden_payload = {
        "component_text", "lesson_body", "asset_bytes", "asset_fetch_handle",
        "frame_bytes", "audio_bytes",
    }
    for table in required:
        assert forbidden_payload.isdisjoint(sqlcipher_schema.columns_for(table))
    assert sqlcipher_schema.has_unique_key(
        "media_target_transition_records", ("operation_id", "target_id"),
    )
    assert sqlcipher_schema.has_unique_key(
        "media_dispatch_unknown_terminals", ("operation_id",),
    )
    assert sqlcipher_schema.has_unique_key(
        "media_late_dispatch_evidence", ("operation_id", "adapter_receipt_digest"),
    )
    assert sqlcipher_schema.has_unique_key(
        "tv_dispatch_unknown_terminals", ("action_id",),
    )
    assert sqlcipher_schema.has_unique_key(
        "tv_late_dispatch_evidence", ("action_id", "signed_adapter_receipt_digest"),
    )
    assert sqlcipher_schema.has_unique_key(
        "display_receipts", ("renderer_endpoint_id", "renderer_endpoint_generation", "receipt_sequence"),
    )

def test_each_core_table_has_exactly_one_migration_owner(core_graph: MigrationGraph) -> None:
    owners = core_graph.table_owners()
    duplicates = {table: revisions for table, revisions in owners.items() if len(revisions) != 1}
    assert duplicates == {}
    assert owners["tv_capability_evidence"] == {"0012_screen_time"}
    assert owners["whole_home_tv_capability_evidence"] == {"0018_television_capabilities"}
    assert owners["media_dispatch_unknown_terminals"] == {"0017_media_and_display"}
    assert owners["media_late_dispatch_evidence"] == {"0017_media_and_display"}
    assert owners["tv_dispatch_unknown_terminals"] == {"0018_television_capabilities"}
    assert owners["tv_late_dispatch_evidence"] == {"0018_television_capabilities"}

@pytest.mark.parametrize("table", [
    "speech_playback_terminal_frames", "media_target_transition_records",
    "media_dispatch_unknown_terminals", "media_late_dispatch_evidence",
    "tv_dispatch_unknown_terminals", "tv_late_dispatch_evidence",
    "teaching_manifest_authority_records", "display_clear_requests",
])
def test_minimized_lineage_purge_has_exact_boundary_and_preserves_dependencies(
    phase4_repository, table, retention_deadline,
) -> None:
    with pytest.raises(RetentionNotElapsed):
        phase4_repository.purge(table, now=retention_deadline - timedelta(microseconds=1))
    assert phase4_repository.purge(table, now=retention_deadline) == "purged_or_tombstoned"
    assert phase4_repository.foreign_keys_are_valid()

def test_every_located_phase4_table_has_exact_composite_area_foreign_key(
    sqlcipher_schema: Schema,
) -> None:
    located_tables={
        "speech_endpoint_registrations","area_voice_policies",
        "area_occupant_consents","child_room_voice_approvals",
        "endpoint_commissioning_evidence","conversation_admissions",
        "media_player_bindings", "media_group_members", "child_media_rules",
        "display_endpoint_bindings", "teaching_sessions",
        "teaching_manifest_authority_records", "display_clear_requests",
        "display_receipts",
        "television_inventory","tv_adapter_bindings","screen_time_adapter_bindings",
        "screen_time_enforcement_generations",
    }
    assert sqlcipher_schema.phase4_tables_with_area_authority() == (
        located_tables | {"handoff_tokens"}
    )
    expected=(
        ("area_id","area_generation"),"home_areas",("area_id","generation"),
    )
    for table in located_tables:
        assert expected in sqlcipher_schema.foreign_keys(table)
        assert not sqlcipher_schema.has_single_column_foreign_key(
            table,"area_id","home_areas","area_id",
        )
    for columns in (
        ("source_area_id", "source_area_generation"),
        ("target_area_id", "target_area_generation"),
    ):
        assert (
            columns, "home_areas", ("area_id", "generation"),
        ) in sqlcipher_schema.foreign_keys("handoff_tokens")
        assert not sqlcipher_schema.has_single_column_foreign_key(
            "handoff_tokens", columns[0], "home_areas", "area_id",
        )

def test_old_area_generation_row_cannot_authorize_after_reclassification(
    migrated_uow: AsyncUnitOfWork,media_adapter_spy,
) -> None:
    area=migrated_uow.home.add_area(area_fixture(generation=1,room_class="common"))
    binding=migrated_uow.media.add_player(
        media_player_fixture(area_id=area.area_id,area_generation=1)
    )
    migrated_uow.home.reclassify(
        area.area_id,expected_generation=1,new_class="adult_private",
    )
    with pytest.raises(StaleAreaAuthority):
        migrated_uow.media.require_current_authority(binding.player_id)
    assert media_adapter_spy.calls==[]

@pytest.mark.parametrize("cycle",("restart","restore"))
async def test_stale_located_authority_never_resurrects_after_restart_or_restore(
    phase4_runtime,cycle,
) -> None:
    authorities=await phase4_runtime.persist_one_of_each_located_authority(
        area_generation=7,
    )
    await phase4_runtime.home.reclassify_all(
        authorities.area_id,expected_generation=7,new_class="prohibited",
    )
    recovered=await getattr(phase4_runtime,cycle)()
    for authority in authorities:
        with pytest.raises(StaleAreaAuthority):
            await recovered.require_current_for_dispatch(authority)
    assert recovered.endpoint_adapter_calls==[]
    assert recovered.media_adapter_calls==[]
    assert recovered.display_adapter_calls==[]
    assert recovered.tv_adapter_calls==[]

def test_phase2_through_phase4_core_graph_is_one_exact_line(core_graph: MigrationGraph) -> None:
    assert core_graph.edges_from("0008_prepared_mutations") == {
        "0009_home_topology_policy": "0008_prepared_mutations",
        "0010_home_actions": "0009_home_topology_policy",
        "0011_home_automation": "0010_home_actions",
        "0012_screen_time": "0011_home_automation",
        "0013_camera_policy": "0012_screen_time",
        "0014_camera_alerts": "0013_camera_policy",
        "0015_presence_checkpoint": "0014_camera_alerts",
        "0016_whole_home_endpoints": "0015_presence_checkpoint",
        "0017_media_and_display": "0016_whole_home_endpoints",
        "0018_television_capabilities": "0017_media_and_display",
        "0019_screen_time_real_adapter": "0018_television_capabilities",
    }
    assert core_graph.heads == {"0019_screen_time_real_adapter"}
    assert not core_graph.forks and not core_graph.merges and not core_graph.orphans

@pytest.mark.parametrize("search_enabled", [False, True])
def test_feature_version_tables_never_change_core_lineage(search_enabled: bool, installation: Installation) -> None:
    graph = installation.upgrade(search_enabled=search_enabled).migration_inventory()
    assert graph.core.heads == {"0019_screen_time_real_adapter"}
    assert graph.core.version_table == "alembic_version"
    assert "search_0001_experimental_search" not in graph.core.revisions
    assert graph.features["search"].version_table == "alembic_version_experimental_search"
    assert graph.catalogs["vision"].version_table == "vision_catalog_alembic_version"
    assert graph.catalogs["vision"].edges == {
        "0001_media_catalog": None,
        "0002_media_operations": "0001_media_catalog",
        "0003_measurement_health": "0002_media_operations",
    }
    assert graph.catalogs["vision"].heads == {"0003_measurement_health"}
    assert not graph.catalogs["vision"].forks_or_merges_or_orphans
    if search_enabled:
        assert graph.features["search"].heads == {"search_0001_experimental_search"}
    else:
        assert graph.features["search"].heads == set()
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/whole_home/test_phase4_migrations.py tests/integration/whole_home/test_phase2_phase4_core_graph.py tests/integration/whole_home/test_phase4_repository_invariants.py tests/integration/whole_home/test_whole_home_uow_registration.py tests/security/whole_home/test_phase4_schema_minimization.py -q`
Expected: FAIL because revision `0016_whole_home_endpoints` is absent.

- [ ] **Step 3: Implement migrations, constraints, triggers, and repositories**

Implement the Durable State and Migration Map exactly. Set `0016.down_revision = "0015_presence_checkpoint"`, then the exact one-parent `0017 → 0016`, `0018 → 0017`, and `0019 → 0018` line. Reject any fork, merge, orphan, alternative parent, extra core head, or duplicate table owner across the complete core revision history. Experimental search and the recorder catalog remain separately upgraded feature/catalog graphs with separate version tables and never appear in `alembic_version`. Use partial unique indexes for one active slot and one current binding; exact composite foreign keys `(area_id, area_generation) -> home_areas(area_id, generation)` on every located Phase 4 endpoint/player/group-member/display/teaching/TV/screen-time row, with no single-column `area_id` authority; generation/CAS columns; check constraints for area class, lifecycle state, action type, result strength, target-transition kind/evidence shape, attempt ordinal, receipt sequence, and terminal immutability; and triggers that reject illegal state transitions or insertion after manual/unknown terminal state. Every repository/dispatch path reopens the current `AreaV1`, so a historically valid FK at a stale generation still denies before adapter read or I/O. Store keyed content/authority commitments, not private bodies. Ensure `0019` references existing Phase 2 screen-time sessions without changing its allowance arithmetic.

- [ ] **Step 4: Prove forward, restart, downgrade/isolated restore, and no-resurrection behavior**

Run:

```bash
uv run pytest tests/integration/whole_home/test_phase4_migrations.py tests/integration/whole_home/test_phase2_phase4_core_graph.py tests/integration/whole_home/test_phase4_repository_invariants.py tests/integration/whole_home/test_whole_home_uow_registration.py tests/security/whole_home/test_phase4_schema_minimization.py -q
uv run alembic upgrade head
uv run python scripts/check_migration_ownership.py --revisions 0016 0017 0018 0019
uv run python scripts/check_migration_graph.py --core-version-table alembic_version --exact-head 0019_screen_time_real_adapter --exact-edge 0009_home_topology_policy:0008_prepared_mutations --exact-edge 0010_home_actions:0009_home_topology_policy --exact-edge 0011_home_automation:0010_home_actions --exact-edge 0012_screen_time:0011_home_automation --exact-edge 0013_camera_policy:0012_screen_time --exact-edge 0014_camera_alerts:0013_camera_policy --exact-edge 0015_presence_checkpoint:0014_camera_alerts --exact-edge 0016_whole_home_endpoints:0015_presence_checkpoint --exact-edge 0017_media_and_display:0016_whole_home_endpoints --exact-edge 0018_television_capabilities:0017_media_and_display --exact-edge 0019_screen_time_real_adapter:0018_television_capabilities --forbid-forks --forbid-merges --forbid-orphans
uv run python scripts/scan_sql_schema.py --db-kind canonical --forbid room_id,audio,waveform,transcript,embedding,query_text,provider_uri,html,javascript,asset_bytes,screenshot,learning_summary,lesson_text,credential,serial_number,mac_address
```

Expected: PASS; restart cancels nonterminal admission/leases rather than resuming capture, leaves uncertain external effects reconcilable, and never restores a consumed handoff/catalog handle or a deleted/revoked consent as current.

- [ ] **Step 5: Document rollback**

Add the migration section to `docs/operations/phase4-update-rollback.md`: take/verify encrypted pre-migration backup; migrate in quarantine; on failure restore the prior compatible schema/package into isolated paths; rotate controller/session epochs; keep endpoints/media/displays/TV enforcement disabled until reconciliation. A downgrade never truncates live unknown actions.

- [ ] **Step 6: Commit exact persistence paths**

```bash
git add apps/core/migrations/versions/0016_whole_home_endpoints.py apps/core/migrations/versions/0017_media_and_display.py apps/core/migrations/versions/0018_television_capabilities.py apps/core/migrations/versions/0019_screen_time_real_adapter.py apps/core/src/tuntun_core/domain/whole_home apps/core/src/tuntun_core/adapters/sqlcipher/models.py apps/core/src/tuntun_core/adapters/sqlcipher/whole_home_repository.py apps/core/src/tuntun_core/services/transactions/whole_home_uow.py apps/core/src/tuntun_core/adapters/sqlcipher/async_unit_of_work.py tests/integration/whole_home/test_phase4_migrations.py tests/integration/whole_home/test_phase2_phase4_core_graph.py tests/integration/whole_home/test_phase4_repository_invariants.py tests/integration/whole_home/test_whole_home_uow_registration.py tests/security/whole_home/test_phase4_schema_minimization.py docs/operations/phase4-update-rollback.md
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(whole-home): persist Phase 4 authority state"
```

### Task 04: Register Phase 4 policy amendments and prove conditional feature absence

**Depends on:** Tasks 01 and 03; accepted shared feature registry; and the accepted Phase 3 Task 17 owner-ingress takeover plus signed route-manifest infrastructure. This is an infrastructure dependency only and does not require enabling any camera feature. This task is the first repository owner of the policy distribution described by the Phase 4 design.
**Gate contribution:** P4-E0, every conditional gate.
**Estimated effort:** 2.5 person-days.

**Files:**

- Modify `pyproject.toml`, `uv.lock`, and `apps/core/pyproject.toml`.
- Create `packages/policy/pyproject.toml` and `packages/policy/src/tuntun_policy/{__init__,registry,corpora}.py`.
- Modify `apps/core/src/tuntun_core/services/features/registry.py` and `apps/core/src/tuntun_core/api/routes/features.py`.
- Modify `apps/core/src/tuntun_core/api/app.py` and `apps/core/src/tuntun_core/bootstrap/container.py`.
- Modify `apps/owner-ingress/src/tuntun_owner_ingress/router.py` and `ops/routes/owner-ingress-routes.v1.json`.
- Create `fixtures/synthetic/features/phase4-whole-home-manifest-v1.json`.
- Create `apps/admin/src/features/media-learning/index.ts` as the manifest-gated barrel; it exports no enabled Phase 4 screen in the empty default manifest.
- Create `tests/unit/policy/test_policy_package_bootstrap.py`.
- Create `tests/unit/policy/test_phase4_amendments.py`.
- Create `tests/acceptance/whole_home/test_phase4_feature_absence.py`.
- Create `tests/security/whole_home/test_phase4_negative_reachability.py`.
- Create `tests/integration/whole_home/test_phase4_boot_composition.py`.
- Modify `tests/integration/deploy/test_owner_ingress_route_manifest.py`.
- Modify `apps/admin/src/app/feature-registry.ts` only to register manifest-backed loaders.

**Interfaces:** First owns standalone leaf distribution `tuntun-policy`: register exact root workspace member `packages/policy` once, expose `tuntun_policy.__version__: str = "0.1.0.dev0"`, and regenerate the root `uv.lock`. The leaf depends only on `tuntun-contracts` plus directly imported policy primitives and never imports an app, integration, adapter, or provider. Merge one-way `tuntun-policy = { workspace = true }` into core's dependency/source tables; policy evaluation receives contracts and facts through arguments rather than reaching into core. Five exact amendment IDs from Authority rule 4. Feature IDs are `phase4.whole_home_voice.v1`, `phase4.media_single_player.v1`, conditional `phase4.media_groups.v1`, conditional `phase4.child_guarded_media.v1`, conditional `phase4.music_assistant.v1`, `phase4.teaching_display.v1`, per-deployment conditional `phase4.television_control.v1`, `phase4.screen_time_real_adapter.v1`, and conditional `phase4.private_room_rollout.v1`. `api/app.py`, `bootstrap/container.py`, owner-ingress's closed router, and the signed route manifest are generated from that same accepted feature manifest: no route, port, worker, service, adapter, consumer, admin loader, or ingress row may be registered by import side effect. `test_phase4_boot_composition.py` boots the installed candidate and exact-compares every registered element with the signed feature manifest; `test_owner_ingress_route_manifest.py` drives each enabled listener→owner-ingress→Core UDS row and requires 404 for unknown/disabled paths. Group and child routes/action enum exposure remain absent until their separate registry/evidence gates pass. No two-session feature ID exists in this release.

- [ ] **Step 1: Write red amendment and absence tests**

```python
def test_phase4_features_require_policy_schema_migration_and_evidence() -> None:
    with pytest.raises(FeatureRegistrationDenied, match="missing whole_home_single_session_v1"):
        registry.register(synthetic_whole_home_voice_feature(amendments=()))

@pytest.mark.parametrize(
    "feature_id,direct_path",
    [
        ("phase4.music_assistant.v1", "/api/v1/media/music-assistant"),
        ("phase4.media_groups.v1", "/api/v1/media/groups"),
        ("phase4.child_guarded_media.v1", "/api/v1/media/child-rules"),
        ("phase4.television_control.v1", "/api/v1/televisions/action"),
        ("phase4.screen_time_real_adapter.v1", "/api/v1/screen-time/enforce"),
        ("phase4.private_room_rollout.v1", "/api/v1/whole-home/private-areas"),
        ("phase4.two_conversations.v1", "/api/v1/whole-home/concurrency"),
    ],
)
def test_unaccepted_feature_is_absent(feature_id: str, direct_path: str, clean_client: TestClient) -> None:
    assert feature_id not in clean_client.get("/api/v1/features").json()["features"]
    assert clean_client.post(direct_path, json={}).status_code == 404
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/policy/test_policy_package_bootstrap.py tests/unit/policy/test_phase4_amendments.py tests/acceptance/whole_home/test_phase4_feature_absence.py tests/security/whole_home/test_phase4_negative_reachability.py tests/integration/whole_home/test_phase4_boot_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py -q`
Expected: FAIL because the policy distribution/workspace link and amendments/feature manifests are absent.

- [ ] **Step 3: Implement evidence-bound registration**

Require contract/schema/policy/migration/build/evidence digests and exact adapter deployment bindings. Feature registration must be server-side, signed, and fail on missing/expired entitlement, consent, hardware evidence, firmware drift, TV generation change, MA gate failure, or renderer pairing loss. Build admin chunks behind dynamic imports keyed only by the signed feature manifest. Reject unknown Phase 4 IDs. Keep the production manifest empty by default.

Bootstrap policy before core imports it: use the foundation Python/Hatchling/version pins, merge `packages/policy` into the current workspace without deleting or duplicating a member, declare `tuntun-contracts = { workspace = true }`, add the one-way core workspace dependency, and regenerate `uv.lock`. The permanent bootstrap test parses root/policy/core TOML, imports the installed package, proves both workspace links, and rejects any policy dependency or source on `tuntun-core`, room/display agents, or integrations.

- [ ] **Step 4: Prove absence at every surface**

Run:

```bash
uv lock
uv sync --all-packages --locked
uv run --locked --offline --no-sync python -c 'import tuntun_policy; assert tuntun_policy.__version__ == "0.1.0.dev0"'
uv run --locked --offline --no-sync pytest tests/unit/policy/test_policy_package_bootstrap.py tests/unit/policy/test_phase4_amendments.py tests/acceptance/whole_home/test_phase4_feature_absence.py tests/security/whole_home/test_phase4_negative_reachability.py tests/integration/whole_home/test_phase4_boot_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py -q
uv run --locked --offline --no-sync python scripts/check_feature_absence.py --manifest fixtures/synthetic/features/phase4-whole-home-manifest-v1.json --features phase4.whole_home_voice.v1,phase4.media_single_player.v1,phase4.media_groups.v1,phase4.child_guarded_media.v1,phase4.music_assistant.v1,phase4.teaching_display.v1,phase4.television_control.v1,phase4.screen_time_real_adapter.v1,phase4.private_room_rollout.v1
uv lock --check
uv build --offline --wheel --package tuntun-policy --out-dir var/build-smoke/phase4/policy
uv lock --check
pnpm --filter @tuntun/admin build
```

Expected: PASS; disabled feature code is not registered or bundled, direct routes return 404, prepared-action issuance denies, network listeners are absent, and `household_conversation_slots=2` is rejected as an unknown configuration key.

- [ ] **Step 5: Commit exact registry paths**

```bash
git add pyproject.toml uv.lock apps/core/pyproject.toml packages/policy/pyproject.toml packages/policy/src/tuntun_policy/__init__.py packages/policy/src/tuntun_policy/registry.py packages/policy/src/tuntun_policy/corpora.py apps/core/src/tuntun_core/services/features/registry.py apps/core/src/tuntun_core/api/routes/features.py apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json apps/admin/src/app/feature-registry.ts apps/admin/src/features/media-learning/index.ts fixtures/synthetic/features/phase4-whole-home-manifest-v1.json tests/unit/policy/test_policy_package_bootstrap.py tests/unit/policy/test_phase4_amendments.py tests/acceptance/whole_home/test_phase4_feature_absence.py tests/security/whole_home/test_phase4_negative_reachability.py tests/integration/whole_home/test_phase4_boot_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(policy): register gated Phase 4 amendments"
```

### Task 05: Implement area voice policy, commissioning, occupant consent, and guardian co-approval

**Depends on:** Tasks 03–04 and the Phase 1 subject/guardian ceremony plus Phase 2 topology registry.
**Gate contribution:** P4-0, P4-2, P4-7.
**Estimated effort:** 5 person-days.

**Files:**

- Create `apps/core/src/tuntun_core/services/whole_home/{endpoint_registry,room_policy}.py`.
- Modify `apps/core/src/tuntun_core/services/identity/consent.py`, the canonical `SubjectGuardianPreparedDecisionService`, to accept `child_room_voice_coapprove` and `child_media_teaching_coapprove` exact commitments; do not create another ceremony service.
- Create `apps/core/src/tuntun_core/api/routes/whole_home.py` and add only read/prepare/decision endpoints backed by the feature registry.
- Create `apps/core/src/tuntun_core/api/phase4_dtos.py`.
- Modify `apps/core/src/tuntun_core/api/app.py`, `apps/core/src/tuntun_core/bootstrap/container.py`, `apps/owner-ingress/src/tuntun_owner_ingress/router.py`, `ops/routes/owner-ingress-routes.v1.json`, and `ops/services/phase3-owner-ingress.v1.json`.
- Create `apps/admin/src/features/media-learning/room-nodes.tsx`, `apps/admin/src/features/media-learning/phase4-health.tsx`, and `apps/admin/src/routes/media-learning-rooms.tsx` as manifest-gated, quarantine-safe shells consumed by UI Task U17; the empty/default manifest registers no route or chunk.
- Create `packages/policy/scripts/run_corpus.py`.
- Test `tests/unit/whole_home/test_area_voice_policy.py`.
- Test `tests/integration/whole_home/test_area_commissioning.py`.
- Test `tests/security/whole_home/test_subject_guardian_ceremonies.py`.
- Test `tests/property/whole_home/test_area_policy_generations.py`.
- Test `tests/unit/policy/test_phase4_policy_corpus_runner.py`.
- Test `tests/contract/api/test_phase4_dtos.py`.
- Modify `tests/integration/whole_home/test_phase4_boot_composition.py` and `tests/integration/deploy/test_owner_ingress_route_manifest.py`.
- Modify `tests/integration/vision/test_deployed_process_entrypoints.py`, `tests/integration/deploy/test_phase3_side_process_lifecycle.py`, `tests/integration/vision/test_owner_ingress_takeover.py`, and `tests/fault/vision/test_owner_ingress_takeover_rollback.py` for the exact Task 05 checkpoint.

**Interfaces:** `AreaVoicePolicyDecision evaluate(AreaVoicePolicyRequest)`; `EndpointRegistry.register(Registration, OwnerGrant)`; one exact prepared commitment binds `area_id`, endpoint, room class, occupant set, child, guardian generation, privacy policy generation, quiet hours, speech/music volume limits, expiry, and evidence digest. The Phase 1-owned `SubjectGuardianPreparedDecisionService` remains the only ceremony implementation and gains two closed purpose branches; it reuses the existing prepared row, current subject/guardian resolution, distinct-principal rule, expiry, one-use decision, commitment, audit, and transaction machinery. `phase4_dtos.py` is the sole Phase 4 owner-API DTO module and contains closed bounded shapes only. The whole-home route and its exact read/prepare/decision ingress rows are registered only through the signed feature manifest; installed-candidate tests prove listener→owner-ingress→Core UDS reachability for enabled rows and 404/absence for all others. `run_corpus.py` uses the shared descriptor-bound JSONL reader and duplicate-key/UTF-8/depth/token/count budgets, validates every Phase 4 row against the closed Task 02 case schema, loads the unchanged 720 screen-time rows only from the canonical Phase 2 corpus path/digest, and evaluates both through Task 04's pinned policy registry with no external I/O. It exits nonzero for a missing/extra/duplicate/unknown/incomplete case, copied/forked Phase 2 row, expected/actual mismatch, parser/race/limit failure, or canonical Phase 2 oracle drift.

- [ ] **Step 1: Write red closed-class and principal-separation tests**

```python
def test_child_private_requires_distinct_current_guardian(
    owner: Principal, guardian: Principal, policy: AreaVoicePolicy
) -> None:
    request = child_private_enable_request(owner=owner, guardian=guardian, policy=policy)
    assert evaluate(request).effect is PolicyEffect.ALLOW
    assert evaluate(replace(request, guardian=owner)).effect is PolicyEffect.DENY

@pytest.mark.parametrize("room_class", ["prohibited", "prohibited_sensitive", "temporary_guest", "unknown", "bathroom"])
def test_sensitive_or_unknown_area_class_cannot_enable_microphone(room_class: str) -> None:
    assert evaluate(synthetic_enable_request(room_class=room_class)).effect is PolicyEffect.DENY

def test_area_change_revokes_current_lease(area_policy: AreaPolicyHarness) -> None:
    lease = area_policy.issue_current_lease()
    area_policy.revoke_occupant_consent()
    assert area_policy.accept_frame(lease, sequence=1) is FrameDecision.STALE_PRIVACY_GENERATION
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/whole_home/test_area_voice_policy.py tests/integration/whole_home/test_area_commissioning.py tests/security/whole_home/test_subject_guardian_ceremonies.py tests/property/whole_home/test_area_policy_generations.py tests/unit/policy/test_phase4_policy_corpus_runner.py tests/contract/api/test_phase4_dtos.py tests/integration/whole_home/test_phase4_boot_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py -q`
Expected: FAIL because `room_policy` and the Phase 4 decision types are absent.

- [ ] **Step 3: Implement restrictive commissioning**

Use the canonical topology `area_id` and current generation. Enforce:

- canonical `common` owner commissioning plus household notice;
- adult-private opt-in by every recorded adult occupant through their own subject-bound passkey;
- child-private owner configuration plus a distinct current primary guardian decision for the exact child/area/endpoint/policy;
- Guest/Designated Guest remains an actor/session restriction and never becomes an area class; legacy `temporary_guest` rejects;
- permanent denial for canonical `prohibited` (and rejection of legacy `prohibited_sensitive`);
- immediate generation increment/cancel on class, microphone, occupant, guardian, endpoint, quiet-hour, or consent change;
- physical mute is always accepted; software unmute is impossible;
- generic provider area descriptors only, never a person's name or sensitive area nickname.

The owner can inspect consent status and content-minimized commitments but cannot act as another adult or guardian. The child cannot satisfy any guardian slot.

- [ ] **Step 4: Run policy corpus and API object-authorization checks**

Run:

```bash
uv run pytest tests/unit/whole_home/test_area_voice_policy.py tests/integration/whole_home/test_area_commissioning.py tests/security/whole_home/test_subject_guardian_ceremonies.py tests/property/whole_home/test_area_policy_generations.py tests/unit/policy/test_phase4_policy_corpus_runner.py tests/contract/api/test_phase4_dtos.py tests/integration/whole_home/test_phase4_boot_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py -q
uv run python packages/policy/scripts/run_corpus.py fixtures/synthetic/whole-home/policy-corpus-v1.jsonl
uv run pytest tests/security/api/test_object_authorization.py -q
uv run ruff check apps/core/src/tuntun_core/services/whole_home/endpoint_registry.py apps/core/src/tuntun_core/services/whole_home/room_policy.py apps/core/src/tuntun_core/services/identity/consent.py apps/core/src/tuntun_core/api/phase4_dtos.py apps/core/src/tuntun_core/api/routes/whole_home.py apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/owner-ingress/src/tuntun_owner_ingress/router.py packages/policy/scripts/run_corpus.py tests/unit/whole_home/test_area_voice_policy.py tests/integration/whole_home/test_area_commissioning.py tests/security/whole_home/test_subject_guardian_ceremonies.py tests/property/whole_home/test_area_policy_generations.py tests/unit/policy/test_phase4_policy_corpus_runner.py tests/contract/api/test_phase4_dtos.py tests/integration/whole_home/test_phase4_boot_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py
uv run mypy apps/core/src packages/policy/scripts/run_corpus.py
```

Expected: PASS; stale/reassigned/revoked guardian, same-principal substitution, cross-child/cross-area/cross-endpoint substitution, expired ceremony, replay, unknown/legacy class, canonical `prohibited`, and missing consent deny and cancel active eligibility.

- [ ] **Refresh and qualify the Task 05 owner-ingress checkpoint before P4-0 or Task 16.** After the Task 04/05 Core/router/manifest bytes are final, rebuild the locked `tuntun-owner-ingress` wheel, refresh and externally re-sign the canonical `ops/services/phase3-owner-ingress.v1.json`, and run `uv build --offline --wheel --package tuntun-owner-ingress --out-dir var/build-smoke/phase4/owner-ingress-task05 && uv lock --check && uv run --locked --offline --no-sync pytest tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/whole_home/test_phase4_boot_composition.py -q`. Require installed listener-to-Core dispatch for every enabled row, bounded not-found without Core dispatch for every absent row, the full lifecycle protocol from Global Constraint 40, and rejection of the Phase 3 predecessor row/receipt.

- [ ] **Step 5: Commit exact policy paths**

```bash
git add apps/core/src/tuntun_core/services/whole_home/endpoint_registry.py apps/core/src/tuntun_core/services/whole_home/room_policy.py apps/core/src/tuntun_core/services/identity/consent.py apps/core/src/tuntun_core/api/phase4_dtos.py apps/core/src/tuntun_core/api/routes/whole_home.py apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json ops/services/phase3-owner-ingress.v1.json apps/admin/src/features/media-learning/room-nodes.tsx apps/admin/src/features/media-learning/phase4-health.tsx apps/admin/src/routes/media-learning-rooms.tsx packages/policy/scripts/run_corpus.py tests/unit/whole_home/test_area_voice_policy.py tests/integration/whole_home/test_area_commissioning.py tests/security/whole_home/test_subject_guardian_ceremonies.py tests/property/whole_home/test_area_policy_generations.py tests/unit/policy/test_phase4_policy_corpus_runner.py tests/contract/api/test_phase4_dtos.py tests/integration/whole_home/test_phase4_boot_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(whole-home): govern area voice commissioning"
```

**Checkpoint P4-E0/P4-0:** Pause household enablement. Review schema/policy/migration/feature digests, no-`room_id` scan, simulator coverage, subject/guardian ceremony isolation, and production feature absence. Only simulator and hardware-probe tooling may proceed until the checkpoint is accepted.

---

## Wave 1 — P4-1/P4-2 Room Endpoint Safety, Bakeoff, Arbitration, and Routing

### Task 06: Scaffold the least-privilege room-node agent and local safety state machine

**Depends on:** Tasks 01–02 and Task 04's accepted Python workspace/lock bootstrap. This serializes the next root `pyproject.toml`/`uv.lock` mutation.
**Gate contribution:** P4-0, P4-1.
**Estimated effort:** 2.5 person-days.

**Files:** Modify `pyproject.toml` and `uv.lock`; create `apps/room-node/pyproject.toml` and `apps/room-node/src/tuntun_room_node/{__init__,main,agent,config,protocol,health,update}.py`; create `ops/room-node/{tuntun-room-node.service,room-node.toml.example,firewall.example.nft,tmpfiles.conf}` and `ops/services/phase4-room-node.v1.json`; create `scripts/phase4/manage_target_service.py` and `docs/evidence/phase4-target-service-lifecycle.schema.json`; test `apps/room-node/tests/unit/test_package_bootstrap.py`, `apps/room-node/tests/unit/test_service_entrypoint.py`, `apps/room-node/tests/unit/test_agent_state.py`, `tests/integration/whole_home/test_room_node_service_lifecycle.py`, `tests/integration/whole_home/test_phase4_target_service_lifecycle.py`, and `tests/security/whole_home/test_room_node_privileges.py`.

**Interfaces:** First owns standalone distribution `tuntun-room-node`: register exact root workspace member `apps/room-node` once, expose `tuntun_room_node.__version__: str = "0.1.0.dev0"`, and regenerate the root lock. Its only workspace dependency is `tuntun-contracts`; target-only libraries use explicit Linux/Python/platform markers so the universal lock still resolves and the package imports/builds on the Intel Mac control host. It must not depend on or import core, edge, policy, display, or integration implementations. `[project.scripts]` owns exactly `tuntun-room-node = tuntun_room_node.main:main`, with injectable `run(argv, runtime) -> int`; help/version have zero effects, `start` verifies exact effective UID and root-owned configuration before key/audio/device/network/runtime writes, and health is bounded/read-only. The rendered systemd unit uses `ExecStart=/opt/tuntun/current/.venv/bin/tuntun-room-node start --config /etc/tuntun/room-node.toml`, with root-owned `/opt/tuntun/current` resolving inside one immutable release, `User=tuntun-room-node`, `Group=tuntun-room-node`, `RuntimeDirectory=tuntun-room-node`, strict runtime/config/key modes, `Restart=on-failure`, and a bounded restart rate; it never uses a shell, PATH lookup, `python -m`, or a writable executable. Packaging installs `ops/room-node/room-node.toml.example` atomically as root-owned mode `0640` `/etc/tuntun/room-node.toml`, replacing only an explicitly migrated managed file and preserving a locally modified file by failing closed for owner review. `ops/services/phase4-room-node.v1.json` is the sole signed release inventory row and binds distribution/wheel digest, entry point, unit/config template and installed digest/account/mode, runtime/key directories, outbound firewall profile, health deadline, restart policy, and exact owned cleanup paths; later packaging consumes this row rather than rediscovering the service. `scripts/phase4/manage_target_service.py` is the single owner-gated target lifecycle orchestrator for Phase 4 Linux services. It accepts one signed `ops/services/*.v1.json`, an immutable candidate release digest, pinned host identity, and exact `install|update|rollback|uninstall|verify` operation; under an idempotent journal it provisions only the declared account, root-owned config, firewall, tmpfiles, unit, install root, and cleanup paths, then emits a signed content-safe receipt conforming to `phase4-target-service-lifecycle.schema.json`. Missing/extra paths, account/config/unit/firewall drift, digest mismatch, partial prior operation, wrong host, or failed health blocks commissioning. Real mutations require explicit owner/hardware gates; dry-run and disposable-image verification remain non-mutating. `RoomNodeAgent.run()`; closed lifecycle `BOOTING -> UNPAIRED -> IDLE_LOCAL_WAKE -> CLAIM_PENDING -> LEASED_CAPTURE -> PLAYING -> IDLE_LOCAL_WAKE`, with any uncertainty to `MUTED` or `ERROR_SAFE`. The agent owns no identity, policy, memory, provider, HA/MA, TV, owner API, or durable audio capability.

- [ ] Write red tests proving forbidden transition denial, zero inbound listener, owner-only config/key permissions, no swap/core dump for audio memory, and `ERROR_SAFE` on supervisor loss.
- [ ] Run `uv run pytest apps/room-node/tests/unit/test_package_bootstrap.py apps/room-node/tests/unit/test_service_entrypoint.py apps/room-node/tests/unit/test_agent_state.py tests/integration/whole_home/test_room_node_service_lifecycle.py tests/security/whole_home/test_room_node_privileges.py -q`; expect missing distribution/workspace/entrypoint/service-config inventory and import failures.
- [ ] Bootstrap with the foundation Python/Hatchling/version pins, merge `apps/room-node` into the current root workspace, declare `tuntun-contracts = { workspace = true }`, add the exact console script above, and regenerate `uv.lock`. The permanent package test parses both TOML files, AST-scans every package import, rejects duplicate membership plus forbidden dependencies/imports, imports the installed package, verifies the exact entry-point target, and checks all target-only dependencies have explicit platform markers. The service-entrypoint test drives `--help`, `--version`, `start`, `health`, SIGTERM, crash/restart, stale runtime state, wrong config owner/mode, and wrong effective UID with injected resources; every rejection must precede keys, audio, device, network, listener, or runtime-file effects.
- [ ] Implement a systemd service with `NoNewPrivileges=yes`, a dedicated account, read-only root, bounded memory/tasks/files, private temporary directory, core dumps disabled, and only the paired outbound Mac destination. Keep runtime state in `/run/tuntun-room-node` and keys in an owner-unreadable service directory; never mount household storage.
- [ ] Implement state transitions as a pure reducer and make `MUTED`/`ERROR_SAFE` preempt every normal event. On restart, clear candidate/lease/playback state and return to local safety discovery before `IDLE_LOCAL_WAKE`.
- [ ] Render and validate the systemd unit, root-owned config, and signed `ops/services` inventory against the installed wheel: exact executable/digest containment, account, config template/installed digest/mode, runtime directory/modes, restart bounds, environment allowlist, firewall profile, cleanup set, and no inherited writable path. In a disposable Linux image, install the candidate release at `/opt/tuntun/current`, install the config at the exact path/mode, and exercise start, bounded read-only health, SIGTERM, crash/restart, restart-rate exhaustion, wrong account/config owner/config mode, stale runtime cleanup, upgrade rollback, and uninstall. A restart must create a new boot/session epoch, clear audio/candidate/lease/playback state, re-prove local mute/indicator safety, and remain `ERROR_SAFE` until that proof succeeds. Missing/extra service artifacts or unit/inventory drift fail packaging.
- [ ] Run the locked import/test/build gate; expect PASS and no lock mutation:

```bash
uv lock
uv sync --all-packages --locked
uv run --locked --offline --no-sync python -c 'import tuntun_room_node; assert tuntun_room_node.__version__ == "0.1.0.dev0"'
uv run --locked --offline --no-sync tuntun-room-node --help
uv run --locked --offline --no-sync tuntun-room-node --version
uv run --locked --offline --no-sync pytest apps/room-node/tests tests/integration/whole_home/test_room_node_service_lifecycle.py tests/integration/whole_home/test_phase4_target_service_lifecycle.py tests/security/whole_home/test_room_node_privileges.py -q
uv run --locked --offline --no-sync ruff check apps/room-node tests/integration/whole_home/test_room_node_service_lifecycle.py tests/security/whole_home/test_room_node_privileges.py
uv run --locked --offline --no-sync mypy apps/room-node/src
systemd-analyze verify ops/room-node/tuntun-room-node.service
uv lock --check
uv build --offline --wheel --package tuntun-room-node --out-dir var/build-smoke/phase4/room-node
uv lock --check
```

- [ ] Commit only the first-owner paths:

```bash
git add pyproject.toml uv.lock apps/room-node/pyproject.toml apps/room-node/src/tuntun_room_node/__init__.py apps/room-node/src/tuntun_room_node/main.py apps/room-node/src/tuntun_room_node/agent.py apps/room-node/src/tuntun_room_node/config.py apps/room-node/src/tuntun_room_node/protocol.py apps/room-node/src/tuntun_room_node/health.py apps/room-node/src/tuntun_room_node/update.py apps/room-node/tests/unit/test_package_bootstrap.py apps/room-node/tests/unit/test_service_entrypoint.py apps/room-node/tests/unit/test_agent_state.py tests/integration/whole_home/test_room_node_service_lifecycle.py tests/integration/whole_home/test_phase4_target_service_lifecycle.py tests/security/whole_home/test_room_node_privileges.py ops/room-node/tuntun-room-node.service ops/room-node/room-node.toml.example ops/room-node/firewall.example.nft ops/room-node/tmpfiles.conf ops/services/phase4-room-node.v1.json scripts/phase4/manage_target_service.py docs/evidence/phase4-target-service-lifecycle.schema.json
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(room-node): scaffold fail-safe endpoint agent"
```

### Task 07: Implement endpoint-owned keys, pairing, mTLS WebSocket, registration, and revocation

**Depends on:** Tasks 03, 05–06 and the Phase 1 pairing/CA ports.
**Gate contribution:** P4-0, P4-1, P4-2.
**Estimated effort:** 3 person-days.

**Files:** Create `apps/room-node/src/tuntun_room_node/{pairing,keys}.py`, `apps/core/src/tuntun_core/services/whole_home/endpoint_gateway.py`, `apps/core/src/tuntun_core/adapters/room_endpoints/websocket.py`, and `apps/core/src/tuntun_core/adapters/room_endpoints/multiplexer.py`; modify the canonical Phase 1 listener/composition paths `apps/core/src/tuntun_core/adapters/reachy/{wss_server,gateway,session}.py` and `apps/core/src/tuntun_core/bootstrap/container.py`; create `scripts/phase4/pair_endpoint.py`; test `tests/contract/whole_home/test_endpoint_channel.py`, `tests/integration/whole_home/test_endpoint_pairing.py`, `tests/integration/whole_home/test_single_wss_listener_composition.py`, `tests/security/whole_home/test_endpoint_replay_revocation.py`, and modify `tests/integration/whole_home/test_phase4_boot_composition.py` plus the accepted Phase 1 Reachy WSS regression suite.

**Interfaces:** Endpoint creates TLS-client and Ed25519 event-signing private keys locally; pairing sends public CSR/material only. Mac issues a household client certificate and separately rotatable commitment secret over the authenticated channel. `EndpointGateway.accept_registration` stores only public identity, evidence digests, and generations. The accepted Phase 1 `wss_server.py` remains the sole Mac WebSocket listener/socket owner. Its closed multiplexer admits only Reachy control on `/v1/reachy` with subprotocol `tuntun.reachy.v1`, Reachy time on `/v1/reachy/time` with `tuntun.reachy.time.v1`, and room-node traffic on `/v1/room-node` with `tuntun.room-node.v1`; it binds each certificate purpose, frame schema, limits, gateway, and session epoch before decoding an application frame. Cross-path/subprotocol/certificate substitution fails before either gateway, and no room-endpoint module may bind another socket. The installed-process test proves exactly one private-interface listener, exact manifest-backed protocol registration, and unchanged Reachy pairing/control/time behavior.

- [ ] Write red tests for private-key non-export, wrong CA/EKU/SAN, clone, nonce replay, stale sequence/session epoch, expired cert, revoked endpoint, changed firmware/model digest, and browser/HA-originated CSR denial.
- [ ] Run `uv run pytest tests/contract/whole_home/test_endpoint_channel.py tests/integration/whole_home/test_endpoint_pairing.py tests/integration/whole_home/test_single_wss_listener_composition.py tests/security/whole_home/test_endpoint_replay_revocation.py tests/integration/reachy/test_wss_lifecycle.py tests/integration/whole_home/test_phase4_boot_composition.py -q`; expect missing gateway/pairing/multiplexer failures.
- [ ] Reuse Phase 1 bounded WebSocket framing and certificate rotation semantics inside the one canonical listener. Add the closed path/subprotocol/certificate-purpose multiplexer, endpoint-protocol negotiation, clock/sequence diagnostics, heartbeats, max message/frame/queue/rate limits, and registration quarantine when any exact digest changes. Private key bytes must never cross the process boundary or be serializable.
- [ ] Verify `wss` is endpoint-initiated, binds only the configured private interface on the Mac edge gateway, rejects redirects/compression negotiation surprises, and exposes no room-node HTTP/debug listener.
- [ ] Run narrow tests plus `uv run pytest tests/security/test_channel_security.py tests/integration/reachy/test_wss_lifecycle.py tests/integration/whole_home/test_single_wss_listener_composition.py tests/integration/whole_home/test_phase4_boot_composition.py -q` and `uv run python scripts/verify_private_data.py apps/room-node tests`; expect PASS, one installed listener, unchanged Reachy behavior, and zero test key outside synthetic fixtures.
- [ ] Document revoke/re-pair/retire and certificate rotation in `docs/operations/phase4-endpoint-pairing.md`. Stage the exact paths with `git add apps/room-node/src/tuntun_room_node/pairing.py apps/room-node/src/tuntun_room_node/keys.py apps/core/src/tuntun_core/services/whole_home/endpoint_gateway.py apps/core/src/tuntun_core/adapters/room_endpoints/websocket.py apps/core/src/tuntun_core/adapters/room_endpoints/multiplexer.py apps/core/src/tuntun_core/adapters/reachy/wss_server.py apps/core/src/tuntun_core/adapters/reachy/gateway.py apps/core/src/tuntun_core/adapters/reachy/session.py apps/core/src/tuntun_core/bootstrap/container.py scripts/phase4/pair_endpoint.py tests/contract/whole_home/test_endpoint_channel.py tests/integration/whole_home/test_endpoint_pairing.py tests/integration/whole_home/test_single_wss_listener_composition.py tests/security/whole_home/test_endpoint_replay_revocation.py tests/integration/whole_home/test_phase4_boot_composition.py docs/operations/phase4-endpoint-pairing.md`, then commit with `git commit -m "feat(whole-home): pair and revoke speech endpoints"`.

### Task 08: Implement local wake, VAD, bounded RAM pre-roll, and lease-gated capture

**Depends on:** Tasks 01–02 and 06–07.
**Gate contribution:** P4-1, P4-2.
**Estimated effort:** 3.5 person-days.

**Files:** Create `apps/room-node/src/tuntun_room_node/{audio,wake,vad,ram_buffer}.py`; add `models/manifest.yaml` entries for candidate wake/VAD artifacts only after licence/provenance review; test `apps/room-node/tests/unit/test_ram_audio.py`, `apps/room-node/tests/property/test_capture_lease.py`, `tests/privacy/whole_home/test_no_pre_wake_egress.py`, and `tests/performance/whole_home/test_audio_backpressure.py`.

**Interfaces:** `WakeDetector.feed(frame) -> WakeCandidate | None`; `VoiceActivityDetector.feed(frame) -> VADState`; `RamAudioRing` capped to configured 3–5 seconds; `LeasedCaptureStream` emits only frames whose lease, sequence, format, time, privacy/capability generation, duration, and byte budget remain current.

- [ ] Write red tests that fill/overwrite the ring, lose arbitration, mute/restart/cancel, exceed 90 seconds/8 MiB, reorder/duplicate frames, induce backpressure, and request pre-wake bytes. Assert zero pre-wake or losing-candidate network bytes.
- [ ] Run the four tests; expect missing audio modules.
- [ ] Implement pinned local models behind ports and normalize audio using explicitly measured native format. Retain a wake-boundary index so the winner flushes only post-wake bytes; the ring destroys all content on loss/timeout/mute/error/restart. Disable swap/core-dump paths for audio buffers and overwrite buffers before release where the runtime permits.
- [ ] Couple stream admission to a current lease check on every frame, not only stream open. On queue pressure or clock/generation uncertainty, cancel and clear; never spool to disk or extend a lease.
- [ ] Run `uv run pytest apps/room-node/tests tests/privacy/whole_home/test_no_pre_wake_egress.py tests/performance/whole_home/test_audio_backpressure.py -q` plus memory/file/socket sentinel scans. Expect zero durable sentinel and bounded RSS/queue.
- [ ] Commit exact audio/model/test paths with `git commit -m "feat(room-node): gate post-wake audio with capture leases"`.

### Task 09: Couple hardware mute, truthful indicator, and local stop through a safety supervisor

**Depends on:** Tasks 06 and 08.
**Gate contribution:** mandatory P4-1 physical safety gate, P4-2, P4-7.
**Estimated effort:** 3.5 person-days plus physical trials.

**Files:** Create `apps/room-node/src/tuntun_room_node/{safety_supervisor,physical_mute,indicator,stop,playback}.py`; create `ops/room-node/safety-supervisor-contract.md`; test `apps/room-node/tests/unit/test_safety_supervisor.py`, `tests/fault/whole_home/test_indicator_fail_closed.py`, and `tests/hardware/whole_home/test_endpoint_physical_safety.py`.

**Interfaces:** `SafetySupervisor.authorize_egress(lease, mute_probe, indicator_probe) -> EgressPermit`; a permit is valid only while hardware mute is definitively open, indicator is locally observed on, supervisor heartbeat is fresh, and privacy/lease generations match. Local stop revokes permit and playback independently of the Mac.

- [ ] Write red simulated tests that crash/freeze the agent, driver, GPIO/USB probe, indicator process, network process, and playback process at every boundary. Any absent/stale mute or indicator fact must produce zero next frame and `ERROR_SAFE`. Schema and gateway tests send `hardware_mute`, `unmute`, `muted`, and `unmuted` as forged control/state values from a compromised core and prove rejection before GPIO/USB/driver/audio/network I/O; repeat after room-node reboot and reconnect.
- [ ] Run simulated red tests; expect the supervisor API to be absent.
- [ ] Implement the safety supervisor as the sole holder of the endpoint network-audio send capability. Require `indicator.on_and_observed()` before granting a send permit; revoke permits synchronously on mute edge, stop, Privacy Shield, heartbeat loss, lease expiry, or probe uncertainty. Physical mute is an observation/input only. Software “mute” or “unmute” has no command, parser branch, driver handle, startup replay, or reconnect path; the only remote capture operation is the tightening `block_capture(blocked)` action.
- [ ] Add a marker-gated physical sentinel test that plays a known synthetic acoustic signal while muted and proves zero network frame and zero usable captured waveform across reboot, application crash, reconnect, update rollback, and malicious unmute request. Add indicator removal/freeze tests proving no egress without visible indication.
- [ ] Run `uv run pytest apps/room-node/tests/unit/test_safety_supervisor.py tests/fault/whole_home/test_indicator_fail_closed.py -q`, then on each exact candidate `TUNTUN_ALLOW_PHASE4_HARDWARE=1 uv run pytest tests/hardware/whole_home/test_endpoint_physical_safety.py -q`. Synthetic tests must pass before physical execution.
- [ ] Store real waveform/packet captures only in encrypted ignored evidence and delete working captures after aggregate/digest evidence. Any single physical privacy failure marks the candidate `REJECTED_PRIVACY` with no override.
- [ ] Commit code/tooling/runbook before the physical run using `git commit -m "feat(room-node): enforce physical mute and capture indication"`; never commit generated evidence.

### Task 10: Adapt Reachy to the common speech-endpoint contract without weakening Phase 1

**Depends on:** Tasks 01, 07–09 and the accepted Phase 1 Reachy transport/safety implementation.
**Gate contribution:** P4-0, P4-2.
**Estimated effort:** 2.5 person-days.

**Files:** Create `apps/core/src/tuntun_core/adapters/room_endpoints/reachy.py`; modify only the Phase 1 edge gateway seams required to emit the common logical events plus `apps/core/src/tuntun_core/bootstrap/container.py`; test `tests/contract/whole_home/test_reachy_endpoint_adapter.py`, `tests/integration/whole_home/test_reachy_room_interop.py`, `tests/privacy/whole_home/test_reachy_caps_preserved.py`, and modify `tests/integration/whole_home/test_phase4_boot_composition.py`.

**Interfaces:** `ReachySpeechEndpointAdapter` maps accepted Phase 1 wake, capture, playback, stop, privacy, sequence, and health events to `SpeechEndpointPort`. It does not claim a room-node physical mute if delivered Reachy hardware did not prove one; its distinct accepted Phase 1 safety facts remain truthful.

- [ ] Write red tests comparing pre/post-adapter Phase 1 caps, stop priority, camera isolation, audio retention, session sequence, gesture bounds, and Guest behavior. A common interface must not manufacture `hardware_muted=true`.
- [ ] Run red; expect missing adapter.
- [ ] Implement a translation layer only. Reuse the existing Reachy transport/keys and area binding; do not make Reachy re-pair as a generic Linux node or route its camera through Phase 4.
- [ ] Run `uv run pytest tests/contract/whole_home/test_reachy_endpoint_adapter.py tests/integration/whole_home/test_reachy_room_interop.py tests/privacy/whole_home/test_reachy_caps_preserved.py tests/integration/whole_home/test_phase4_boot_composition.py tests/unit/reachy tests/integration/reachy -q`; expect all Phase 1 regression tests unchanged and the installed manifest to register exactly one Reachy adapter.
- [ ] Stage `apps/core/src/tuntun_core/adapters/room_endpoints/reachy.py apps/core/src/tuntun_core/bootstrap/container.py tests/contract/whole_home/test_reachy_endpoint_adapter.py tests/integration/whole_home/test_reachy_room_interop.py tests/privacy/whole_home/test_reachy_caps_preserved.py tests/integration/whole_home/test_phase4_boot_composition.py`, then commit with `git commit -m "feat(whole-home): adapt Reachy to room arbitration"`.

### Task 11: Implement deterministic duplicate-wake arbitration and loser destruction

**Depends on:** Tasks 02, 05, 07, and 10.
**Gate contribution:** P4-2.
**Estimated effort:** 3 person-days.

**Files:** Create `apps/core/src/tuntun_core/services/whole_home/wake_arbiter.py`; modify `apps/core/src/tuntun_core/bootstrap/container.py` and `tests/integration/whole_home/test_phase4_boot_composition.py`; test `tests/unit/whole_home/test_wake_arbiter.py`, `tests/property/whole_home/test_duplicate_wake_arbitration.py`, and `tests/fault/whole_home/test_arbiter_restart.py`.

**Interfaces:** `WakeArbiter.arbitrate` consumes the complete deduplicated set of signed metadata claims admitted during the 350 ms window and correlates possible duplicates within 1.5 seconds. It canonicalizes one `WakeArbitrationMemberV1` per endpoint, including the digest of the exact signed claim and its session/privacy/capability generations; persistence and admission reopen those claims and reject any omitted, added, reordered, remapped, or changed member. Winner and loser fields are derived from that canonical tuple, never supplied independently. Stable order: valid continuation token; confidence/SNR beyond calibrated hysteresis; earliest gateway receipt; stable endpoint ID.

- [ ] Write red tests for the entire 500-case corpus plus ties, skew, an omitted/added/reordered member, duplicate claim ID, duplicate endpoint ID, claim-to-endpoint remapping, wrong winner pair, incomplete/extra loser tuple, zero-winner all-loser outcomes, replayed claims, stale session/privacy/capability generation, muted/indicator-unready/unhealthy endpoints, late claims, active-session other-area wake, and Mac restart.
- [ ] Run red; expect missing arbiter.
- [ ] Implement one deterministic pure decision function and a bounded decision-window coordinator. Reopen every considered claim by digest before admission and require the persisted canonical member tuple to equal the complete admitted claim set. Room label, identity, profile permission, memory, or response sensitivity must not enter its score. Issue one single-use lease; send explicit cancel to every exactly derived loser and wait only for bounded acknowledgements without delaying winner capture.
- [ ] Assert loser fakes clear candidate RAM even when cancel acknowledgement is lost; late frames are rejected at the gateway before provider authorization.
- [ ] Run `uv run pytest tests/unit/whole_home/test_wake_arbiter.py tests/property/whole_home/test_duplicate_wake_arbitration.py tests/fault/whole_home/test_arbiter_restart.py tests/integration/whole_home/test_phase4_boot_composition.py -q`; expect at least 500 cases with exactly one lease/stream/response, zero loser persistence, and exact manifest-backed worker/service registration.
- [ ] Stage `apps/core/src/tuntun_core/services/whole_home/wake_arbiter.py apps/core/src/tuntun_core/bootstrap/container.py tests/unit/whole_home/test_wake_arbiter.py tests/property/whole_home/test_duplicate_wake_arbitration.py tests/fault/whole_home/test_arbiter_restart.py tests/integration/whole_home/test_phase4_boot_composition.py`, then commit with `git commit -m "feat(whole-home): arbitrate duplicate room wakes"`.

### Task 12: Enforce the single durable household conversation admission slot

**Depends on:** Tasks 03 and 11 plus the Phase 1 turn coordinator.
**Gate contribution:** P4-2 and negative Section 22.8 reachability.
**Estimated effort:** 3 person-days.

**Files:** Create `apps/core/src/tuntun_core/services/whole_home/conversation_admission.py`; extend the Phase 1 conversation coordinator only through the declared port; modify `apps/core/src/tuntun_core/bootstrap/container.py` and `tests/integration/whole_home/test_phase4_boot_composition.py`; test `tests/integration/whole_home/test_single_conversation_admission.py`, `tests/property/whole_home/test_concurrent_admission.py`, and `tests/security/whole_home/test_second_slot_unreachable.py`.

**Interfaces:** `ConversationAdmissionService.admit` atomically inserts singleton slot `0` with winning endpoint/area, turn, effective identity mode, privacy generation, reservations, and expiry. It consumes the winning claim once. `cancel_all_on_startup` terminalizes stale admissions and sends cancellation; it never resumes listening/speech.

- [ ] Write red simultaneous-transaction tests, process-crash tests at every insert/outbox boundary, duplicate winner/replay tests, and direct attempts to use slot 1 or set capacity 2.
- [ ] Run red; expect missing service.
- [ ] Implement admission inside the serialized SQLCipher UoW with a partial unique index and audit/outbox. Provider budget reservation remains per admitted turn and occurs before provider egress. Release the slot only after capture/workflow/playback cancellation has settled or timed out truthfully.
- [ ] Do not add a concurrency setting. Add source/OpenAPI/config/UI/package assertions that `phase4.two_conversations.v1` and a slot-count mutation do not exist.
- [ ] Run all three tests plus `tests/integration/whole_home/test_phase4_boot_composition.py` with at least 10,000 concurrent seeded schedules; expect no double admission, no stale crash resume, and exact manifest-backed service registration.
- [ ] Stage `apps/core/src/tuntun_core/services/whole_home/conversation_admission.py apps/core/src/tuntun_core/bootstrap/container.py tests/integration/whole_home/test_single_conversation_admission.py tests/property/whole_home/test_concurrent_admission.py tests/security/whole_home/test_second_slot_unreachable.py tests/integration/whole_home/test_phase4_boot_composition.py`, then commit with `git commit -m "feat(whole-home): enforce one household conversation"`.

### Task 13: Route speech only to the current lease endpoint with audience-safe failure

**Depends on:** Tasks 05, 10, and 12 plus Phase 1 identity/policy/language services.
**Gate contribution:** P4-2.
**Estimated effort:** 3 person-days.

**Files:** Create `apps/core/src/tuntun_core/services/whole_home/reply_router.py`; modify `apps/core/src/tuntun_core/bootstrap/container.py` and `tests/integration/whole_home/test_phase4_boot_composition.py`; test `tests/unit/whole_home/test_reply_router.py`, `tests/property/whole_home/test_private_reply_isolation.py`, and `tests/integration/whole_home/test_reply_delivery_cancellation.py`.

**Interfaces:** `RoomReplyRouter.resolve(ReplyRoutingRequestV1)` first recomputes and constant-time compares the request commitment, requires trusted `now < request.expires_at`, then reopens and exact-compares the current endpoint plus canonical `(area_id, area_generation)`, privacy generation, physical mute/playback health, answer sensitivity, subject/profile version, imported `MemoryAudience`, current audience-policy generation, effective Guest/profile, consent, quiet hours, volume cap, conversation/turn UUIDs, exact capture-lease ID/commitment, and cancellation generation before any memory lookup or playback. Guest or uncertain identity requires `profile_class=guest`, absent subject/profile/audience-policy authority, `memory_audience=None`, `generic_guest_public`, and zero memory read. Identified owner/adult replies permit only `subject_private|household_adults|household_all`, never `guardian_child`; K2/N1 `household_all` requires the exact current guardian generation plus the existing child-safe household approval grant. It returns one exact endpoint or a no-speech decision whose endpoint/location/volume fields are atomically absent. Every decision repeats the complete request/lease/cancellation binding and is capped by the request deadline. Every short-lived playback frame and endpoint-signed receipt repeats request, conversation, turn, lease, decision commitment, cancellation generation, privacy generation, and capability generation; the sender and endpoint exact-compare them against current state before the first and every subsequent frame. Frames also carry a contiguous byte offset and commitment. The final frame alone commits the exact terminal sequence and total byte count and is durably recorded before it is sent. A `completed` receipt must repeat that final-frame commitment and exact terminal totals; the verifier reloads the stored frame and rejects truncation, a fabricated final frame, a gap/overlap, or a receipt for another playback. `partial|stopped|unverified|error_safe` never upgrade to complete merely because some bytes were accepted.

- [ ] Write red tests for the 1,000-case routing corpus: wrong/losing/stale/uncommissioned/muted/revoked endpoint, substituted/stale area generation, stale subject/profile/audience-policy generation, private answer, child disclosure, auth prompt, security response, Guest/uncertain downgrade, endpoint disconnect, area consent change, quiet hours, and media group availability. Independently substitute request commitment/deadline, conversation, turn, lease ID/commitment, cancellation generation, decision commitment, privacy generation, capability generation, frame offset/commitment/final flag/terminal total, or receipt terminal sequence/bytes/commitment at every frame position and receipt; omit/reorder/duplicate a middle or final frame; equality at expiry and any stale cancellation must yield zero next bytes. A receipt after frame zero or any truncated stream cannot claim `completed`. Add the closed identity/profile/audience combination matrix, serialization/authorization rejection for `owner_private|adult_private|household|public_only|household_shared`, owner/adult `guardian_child`, child `household_all` without exact grant/current guardian generation, atomic no-speech absence, and Guest/uncertain memory-read sentinels proving zero calls.
- [ ] Run red; expect missing router.
- [ ] Implement deny-by-default routing. If the endpoint cannot safely speak, use a bounded local nonverbal error where available and make the answer available only in the authenticated owner console; never search for another endpoint.
- [ ] Ensure old TTS frames contain the exact request/conversation/turn/lease commitment, decision commitment, cancellation/privacy/capability generations, and a two-second maximum frame window; discard them on cancel, handoff, expiry, privacy, mute, identity downgrade, or newer barge-in. Do not persist answer text in routing audit.
- [ ] Run the three narrow suites plus `tests/integration/whole_home/test_phase4_boot_composition.py`; expect zero private reply on any wrong route, complete rejection of media group/TV speaker targets, and exact manifest-backed router-service registration.
- [ ] Stage `apps/core/src/tuntun_core/services/whole_home/reply_router.py apps/core/src/tuntun_core/bootstrap/container.py tests/unit/whole_home/test_reply_router.py tests/property/whole_home/test_private_reply_isolation.py tests/integration/whole_home/test_reply_delivery_cancellation.py tests/integration/whole_home/test_phase4_boot_composition.py`, then commit with `git commit -m "feat(whole-home): bind replies to the capture endpoint"`.

### Task 14: Add explicit handoff and endpoint-independent language following

**Depends on:** Tasks 05 and 12–13 plus the Phase 1 language tracker.
**Gate contribution:** P4-2 and P4-7.
**Estimated effort:** 2.5 person-days.

**Files:** Create `apps/core/src/tuntun_core/services/whole_home/handoff.py`; extend the closed offline/intent grammar with exact handoff intents; create `fixtures/synthetic/whole-home/language-room-corpus-v1.jsonl`; modify `apps/core/src/tuntun_core/bootstrap/container.py` and `tests/integration/whole_home/test_phase4_boot_composition.py`; test `tests/unit/whole_home/test_handoff.py`, `tests/integration/whole_home/test_handoff_identity_policy.py`, and `tests/acceptance/whole_home/test_multilingual_room_prompts.py`.

**Interfaces:** `HandoffService.prepare_exact_target` returns a 30-second single-use token after exact target resolution and current-source announcement. Target wake consumes it only after fresh area/identity/consent checks. `LanguageTracker` remains keyed to conversation/turn, never endpoint/area.

- [ ] Write red tests for ambiguous alias, target offline/muted, expiry/replay, Guest, child-private guardian mismatch, identity conflict, source cancellation, policy generation change, and attempted transfer of auth/action grant.
- [ ] Add English/Hindi/Hinglish switch cases and human-reviewed fixed message IDs for wake/busy/privacy/stop/handoff/error/media ambiguity/teaching/screen-time. Short ambiguous utterances must preserve last stable mode.
- [ ] Run red; expect missing handoff service/message IDs.
- [ ] Implement exact target resolution through Phase 2 topology. Target receives no prior private content; a failed handoff becomes a new Guest turn only after a new wake. There is no passive microphone/camera/presence follow-me process.
- [ ] Run the three tests, Phase 1 language corpus, and `tests/integration/whole_home/test_phase4_boot_composition.py`. Expect zero transferred authentication/approval/child authority, no endpoint-driven language change, and exact manifest-backed handoff-service registration.
- [ ] Stage `apps/core/src/tuntun_core/services/whole_home/handoff.py apps/core/src/tuntun_core/bootstrap/container.py fixtures/synthetic/whole-home/language-room-corpus-v1.jsonl tests/unit/whole_home/test_handoff.py tests/integration/whole_home/test_handoff_identity_policy.py tests/acceptance/whole_home/test_multilingual_room_prompts.py tests/integration/whole_home/test_phase4_boot_composition.py`, then commit with `git commit -m "feat(whole-home): add explicit multilingual handoff"`.

### Task 15: Build purchased and DIY candidate adapters plus identical bakeoff tooling

**Depends on:** Tasks 06–09 and accepted procurement records.
**Gate contribution:** P4-1.
**Estimated effort:** 4.5 person-days before elapsed campaign.

**Files:** Create `scripts/phase4/{probe_purchased_endpoint,probe_diy_endpoint,run_endpoint_bakeoff,verify_endpoint_bakeoff}.py`; create candidate adapter modules under `apps/room-node/src/tuntun_room_node/adapters/` only for exact acquired revisions; modify and re-sign `ops/services/phase4-room-node.v1.json`; create `fixtures/synthetic/whole-home/endpoint-candidates-v1.json`; create `docs/procurement/phase4-room-endpoint-bakeoff.md`, `docs/operations/phase4-endpoint-bakeoff.md`, and `docs/evidence/phase4-endpoint-bakeoff.schema.json`; modify `tests/integration/whole_home/test_phase4_target_service_lifecycle.py`; create `tests/acceptance/whole_home/test_endpoint_bakeoff_feature_authority.py`; test `tests/unit/whole_home/test_bakeoff_scoring.py`, `tests/security/whole_home/test_purchased_firmware_target_absence.py`, and `tests/hardware/whole_home/test_endpoint_candidate.py`.

**Interfaces:** Candidate record binds exact pseudonymous SKU/revision, signed stock firmware version/digest, `firmware_mode="stock_supported_transport"`, supported transport/API evidence, wake/VAD source/licence/hash, audio formats, physical cutoff, indicator path, stop, power, enclosure, vendor update/rollback, SBOM, acoustic placement, and evidence digest. The purchased-appliance branch is eligible only when the unmodified signed stock firmware exposes a proved supported transport that implements `SpeechEndpointPort` without delegating Tuntun policy to Assist. Phase 4 owns no replacement-firmware build, flash, signing, update, or rollback target: a candidate requiring, proposing, detecting, or having replacement/custom firmware is marked `INELIGIBLE_UNOWNED_FIRMWARE_TARGET`, and its package adapter, feature row, pairing route, and commissioning path must be absent. Scoring may compare only candidates that pass every privacy/safety gate. `verify_endpoint_bakeoff.py` is the task-local verifier for this schema; it does not depend on Task 36 acceptance tooling. Its authority section is the unchanged Phase 2 `FeatureAuthorityCampaignEvidenceV1` validated by the Phase 2-owned schema, not a Phase 4 copy. Purchased and DIY hardware/configuration commitments are part of the frozen candidate; unless byte-identical, their runners/verifiers require separate external chains and reject a chain ID, candidate digest, registration set, receipt, or sample log from the other candidate. `test_endpoint_bakeoff_feature_authority.py` adapts runner and verifier to Phase 2 Task 13's shared downstream harness and proves every closed authority fault stops the next audio/network/device/evidence operation, invalidates the candidate run, and cannot be hidden by caller-authored zero counters. Because Tasks 07–09 and this task change the `tuntun-room-node` wheel after Task 06 first creates its inventory, this task is the mandatory final room-node packaging freeze before physical use: rebuild the locked wheel, update and re-sign `phase4.room_node.v1` with the final wheel plus unchanged exact unit/config/firewall/tmpfiles/account/install-root digests, and reject any prior lifecycle receipt as stale. For each candidate host, the Task 06-owned lifecycle orchestrator must then produce a fresh signed install/update/rollback/uninstall/verify receipt against that final manifest before Task 16 may capture evidence.

- [ ] Write red tests proving a candidate with superior acoustics but failed mute/indicator/licence/rollback is ineligible; marketing names such as “ReSpeaker” or “Voice Preview Edition” provide zero capability.
- [ ] Implement purchased-appliance probing for the exact unmodified signed stock firmware and its documented/proved supported transport. Stock Assist behavior alone never passes, and any replacement/custom firmware requirement or observation makes the purchased branch ineligible and absent.
- [ ] Implement DIY probing for exact SBC, microphone front end, amplifier/speaker, hardware cutoff circuit, indicator, stop input, supply, storage, enclosure, drivers, thermal/power, and rollback. No microphone board is selected by brand.
- [ ] Use the same calibrated synthetic/physical corpus, placement, volume/noise conditions, packet/content scans, energy meter, and owner-maintenance timer for both candidates. Probe scripts refuse real serial/MAC/IP output and write only pseudonymous encrypted ignored evidence.
- [ ] Run unit/security tests and a dry-run with synthetic candidates, including the replacement-firmware negative case. Expect deterministic ineligible/pass results, no import/route/feature registration for an unowned firmware target, and no purchase recommendation from incomplete evidence.
- [ ] Run `uv run pytest tests/support/test_feature_authority_campaign.py tests/acceptance/whole_home/test_endpoint_bakeoff_feature_authority.py -q`. The test covers missing/stale initial activation or nonzero initial index; missing/extra/reordered/late/signature-invalid successors; candidate/registration drift; future activation; wall equality/rollback; monotonic equality; stale composition; and restart on both sides of rollover CAS with missing/duplicate/substituted receipts; every case has zero post-fault admission/preparation/provider-call/trigger/effect delta and verifier rejection.
- [ ] Build `tuntun-room-node` from the final locked source, recompute the wheel digest, update/re-sign the one service row, and run `uv run --locked --offline --no-sync pytest apps/room-node/tests/unit/test_package_bootstrap.py apps/room-node/tests/unit/test_service_entrypoint.py tests/integration/whole_home/test_phase4_target_service_lifecycle.py -q`, `uv build --offline --wheel --package tuntun-room-node --out-dir var/build-smoke/phase4/room-node-final`, and `uv lock --check`. The lifecycle test must reject the Task 06 digest/receipt and accept only a receipt whose manifest and wheel digest match this final build.
- [ ] Stage `scripts/phase4/probe_purchased_endpoint.py scripts/phase4/probe_diy_endpoint.py scripts/phase4/run_endpoint_bakeoff.py scripts/phase4/verify_endpoint_bakeoff.py apps/room-node/src/tuntun_room_node/adapters ops/services/phase4-room-node.v1.json fixtures/synthetic/whole-home/endpoint-candidates-v1.json docs/procurement/phase4-room-endpoint-bakeoff.md docs/operations/phase4-endpoint-bakeoff.md docs/evidence/phase4-endpoint-bakeoff.schema.json tests/integration/whole_home/test_phase4_target_service_lifecycle.py tests/acceptance/whole_home/test_endpoint_bakeoff_feature_authority.py tests/unit/whole_home/test_bakeoff_scoring.py tests/security/whole_home/test_purchased_firmware_target_absence.py tests/hardware/whole_home/test_endpoint_candidate.py`, then commit tooling/docs/fixtures/tests and the final signed inventory before hardware use with `git commit -m "test(room-node): prepare purchased versus DIY bakeoff"`.

### Task 16: Run the physical common-area bakeoff, select/quarantine, and commission one winner

**Depends on:** Task 15, the committed and installed Task 05 owner-ingress checkpoint with its current canonical row/lifecycle receipt, a fresh accepted signed room-node target lifecycle receipt produced by the Task 06-owned orchestrator for the exact candidate host/release and Task 15-finalized service manifest, exact landed quotes/return terms, and owner authorization to operate the two candidate devices in one common area.
**Gate contribution:** P4-1, P4-2.
**Estimated effort:** 2.5 person-days plus two seven-day candidate runs and an eight-hour stress run each.

**Files:** Modify no production source unless a failed probe produces a separately reviewed task. Execute `scripts/phase4/run_endpoint_bakeoff.py`; validate with the Task 15-owned `scripts/phase4/verify_endpoint_bakeoff.py`; document procedure in `docs/operations/phase4-endpoint-bakeoff.md`. Generated evidence stays ignored. Each physical runner consumes its own Phase 2 canonical pre-issued rollover chain and exact `FeatureAuthorityCampaignEvidenceV1`; its evidence schema binds the chain ID/digest, frozen hardware/configuration candidate, ordered signed-envelope and transition/restart-receipt digests, admission-sample-log digest, exact candidate interval, and every canonical literal-zero counter. Every admission/background sample checks the current half-open wall validity and monotonic lease, no Phase 4 code signs or renews authority, and purchased/DIY evidence or chain reuse fails before capture.

- [ ] Before pairing or microphone use, verify the current signed `phase4.room_node.v1` target lifecycle receipt against the installed host identity, release/wheel/unit/config/firewall/tmpfiles/account digests and successful install/update/rollback/uninstall rehearsal. Capture that receipt with the exact candidate records, same placement, room privacy notice, synthetic marker schedule, owner/operator, build/config digests, network capture point, plug meter, and rollback image before the first run.
- [ ] Re-run `uv run pytest tests/support/test_feature_authority_campaign.py tests/acceptance/whole_home/test_endpoint_bakeoff_feature_authority.py -q` against the frozen Task 15 runner/verifier before either physical candidate starts. Any failure leaves both candidates unrun and P4-1 blocked.
- [ ] For each candidate, run seven elapsed days in the common area and one continuous eight-hour television/music/fan/cooking/family-noise stress window. Required thresholds: wake acknowledgement P95 ≤500 ms; family false rejects ≤5%; no more than one false wake per eight representative hours; stop/privacy P95 ≤250 ms; bounded CPU/RAM/thermal/queue/reconnect.
- [ ] Run at least 240 accepted-quality English/Hindi/Hinglish requests and publish aggregate error by language/noise/distance, target at least 95% correct completion. Family speech needed for acoustic validation remains encrypted local evidence and is deleted according to the campaign runbook; Git gets only aggregates/commitments.
- [ ] Repeat hardware mute across reboot, agent crash, reconnect, update/rollback, and malicious unmute; repeat indicator fail-safe by crashing/freezing every user-space layer; scan files, swap awareness, logs, crash reports, backups, and packet captures for durable audio.
- [ ] Execute:

```bash
TUNTUN_ALLOW_ENDPOINT_PROBE=1 uv run python scripts/phase4/run_endpoint_bakeoff.py --candidate purchased --feature-manifest-chain var/evidence/phase4/feature-authority/task16/purchased/PURCHASED_CANDIDATE_DIGEST/signed-rollover-chain.json --duration-seconds 604800 --stress-seconds 28800 --evidence-root var/evidence/phase4/endpoints/purchased/PURCHASED_CANDIDATE_DIGEST
TUNTUN_ALLOW_ENDPOINT_PROBE=1 uv run python scripts/phase4/run_endpoint_bakeoff.py --candidate diy --feature-manifest-chain var/evidence/phase4/feature-authority/task16/diy/DIY_CANDIDATE_DIGEST/signed-rollover-chain.json --duration-seconds 604800 --stress-seconds 28800 --evidence-root var/evidence/phase4/endpoints/diy/DIY_CANDIDATE_DIGEST
uv run python scripts/phase4/verify_endpoint_bakeoff.py --candidate purchased --evidence-root var/evidence/phase4/endpoints/purchased/PURCHASED_CANDIDATE_DIGEST --feature-manifest-chain var/evidence/phase4/feature-authority/task16/purchased/PURCHASED_CANDIDATE_DIGEST/signed-rollover-chain.json --require-target-lifecycle-receipt --require-zero-expired-authority
uv run python scripts/phase4/verify_endpoint_bakeoff.py --candidate diy --evidence-root var/evidence/phase4/endpoints/diy/DIY_CANDIDATE_DIGEST --feature-manifest-chain var/evidence/phase4/feature-authority/task16/diy/DIY_CANDIDATE_DIGEST/signed-rollover-chain.json --require-target-lifecycle-receipt --require-zero-expired-authority
```

- [ ] Record `SELECTED`, `BOTH_ELIGIBLE`, or `NO_ELIGIBLE_CANDIDATE`. Select on privacy truthfulness, acoustics, recoverability, updates, idle power, and maintenance—not customization preference. A loser is unpaired and removed or retained as a synthetic-only developer fixture.
- [ ] Pair only one winning candidate to one common `area_id`, run Tasks 11–14 physical interop with Reachy, and keep every private/additional room feature absent.
- [ ] No source/evidence commit is made here. If tooling changed, stop, commit/review it separately, invalidate the prior run, and repeat from the clean commit.

**Checkpoint P4-1/P4-2:** Owner reviews the physical evidence and selects the accepted endpoint type. No fleet replication occurs. A failed bakeoff leaves Reachy as the only endpoint and permits only explicitly non-promotable simulator/manual-display learning; P4-1/P4-2 and the mandatory Phase 4 exit remain failed, so Phase 5/6 entry and any Phase 4 promotion are blocked until one common-room candidate passes and is selected.

---

## Wave 2 — P4-3 Entitled Media, Signed Bridge, and Optional Music Assistant

### Task 17: Implement legal-provider reviews, player bindings, and opaque catalog handles

**Depends on:** Tasks 01, 03–05 and accepted Phase 2 topology.
**Gate contribution:** P4-3.
**Estimated effort:** 5 person-days.

**Files:** Create `apps/core/src/tuntun_core/services/whole_home/{media_catalog,media_policy,media_player_registry,media_group_registry}.py` and `apps/core/src/tuntun_core/api/routes/media.py`; modify `apps/core/src/tuntun_core/api/app.py`, `apps/core/src/tuntun_core/bootstrap/container.py`, `apps/owner-ingress/src/tuntun_owner_ingress/router.py`, `ops/routes/owner-ingress-routes.v1.json`, `tests/integration/whole_home/test_phase4_boot_composition.py`, and `tests/integration/deploy/test_owner_ingress_route_manifest.py`; create `fixtures/synthetic/whole-home/players-providers-v1.json`; test `tests/unit/whole_home/test_media_entitlement.py`, `tests/unit/whole_home/test_catalog_handles.py`, `tests/integration/whole_home/test_media_player_registry.py`, `tests/integration/whole_home/test_media_group_registry.py`, `tests/security/whole_home/test_media_input_boundary.py`, and `tests/privacy/whole_home/test_media_credential_absence.py`.

**Interfaces:** `ProviderRegistry.enable(binding, entitlement_review, owner_grant)`; `MediaPlayerRegistry.prepare|activate|retire` consumes the shared owner-passkey prepared-mutation protocol and exact current-generation CAS; `MediaGroupRegistry.prepare|activate|retire` does the same for a signed immutable canonical member manifest under distinct domain `tuntun-media-group-v1`. Each provider binding owns explicit independently advancing provider, adapter, and entitlement generations. Every query/handle, request, decision, envelope, receipt, result, and player observation carries the exact `(provider_binding_id, provider_generation, adapter_generation, entitlement_generation)` tuple; a verifier reloads that row before using a player's candidate-provider list. Adapter/account/region/terms/lifecycle changes advance their relevant counter plus provider generation and invalidate all dependent authority. Player activation reloads current canonical area/provider/adapter plus exact commissioning evidence for available operations, ≤5-second observation freshness, reliable/bounded absolute safe volume, manual fallback, exact firmware/config digest, and lifecycle generation. Drift or retirement advances generation and immediately invalidates handles, prepared actions, group memberships, and feature evidence. Group activation reloads every current player/area/binding/capability generation and cap before committing one new version; edit creates a new version, never updates members in place. `MediaCatalogService.search` returns bounded opaque handles bound to provider/account/item/classification/authority/result generation/expiry; `resolve_handle` is single-purpose, current-policy checked, and never returns a URI to model/browser code. `phase4.media_single_player.v1` requires one accepted current player; `phase4.media_groups.v1` is independently absent until the group registry, signature, CAS, restart, UI, and physical multi-player gates pass.

- [ ] Write red tests for missing/expired/region-changed/legal-unclear/unofficial/scraping/credential-exporting providers; arbitrary URL/redirect/private address/path/provider URI; oversized query; expired/replayed/substituted handle; exact provider-binding ID or provider/adapter/entitlement generation substitution; same-generation provider-row replacement; and child explicit/unknown classification. Add player tests for stale/wrong area/provider/protocol/firmware/evidence/generation, absent safe absolute volume/manual fallback, reused prepared mutation, owner mismatch, crash before/after CAS, restart/restore, retirement, and drift invalidation. Add group tests for zero/duplicate/omitted/extra/reordered/wildcard members, stale player/area/binding/capability/cap, signature/domain, version/CAS, same-ID replacement, delete/retire/restart, and every member substitution; no failed case may expose a group route/action.
- [ ] Run `uv run pytest tests/unit/whole_home/test_media_entitlement.py tests/unit/whole_home/test_catalog_handles.py tests/integration/whole_home/test_media_player_registry.py tests/integration/whole_home/test_media_group_registry.py tests/security/whole_home/test_media_input_boundary.py tests/privacy/whole_home/test_media_credential_absence.py -q`; expect missing services.
- [ ] Implement 90-day maximum entitlement review, immediate invalidation on adapter/account/terms/region change, and no silent provider substitution. Store only opaque provider binding and capability digest. A normalized catalog query and raw results live in bounded process memory; ordinary audit stores keyed commitments and result count/class only.
- [ ] Implement player commissioning/retirement with exact evidence and serialized owner-passkey CAS. Then implement immutable group versioning/signing only over already-current players. Registry APIs accept stable IDs and closed DTOs, never entity names, selectors, arbitrary player URLs, dynamic “all speakers,” or caller-created evidence.
- [ ] Require a short spoken choice for ambiguity and mint a handle only from an adapter-returned registered result. Models cannot construct, edit, broaden, or refresh handles.
- [ ] Run the six suites plus `tests/integration/whole_home/test_phase4_boot_composition.py`, `tests/integration/deploy/test_owner_ingress_route_manifest.py`, and `uv run python scripts/verify_private_data.py apps/core fixtures/synthetic/whole-home`. Expect no reusable provider/MA/HA credential, query text, URI, account ID, or real entitlement data. Unless the separate group gate passes, assert the group feature, route, UI loader, and `media.play_group_manifest.v1` action registration are absent.
- [ ] Stage the services/route/fixture/tests plus `apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json tests/integration/whole_home/test_phase4_boot_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py`, then commit with `git commit -m "feat(media): gate entitled catalog handles"`.

### Task 18: Implement exact adult, child, Guest, confirmation, and passkey media policy

**Depends on:** Tasks 04–05 and 17 plus Phase 1 identity/auth and Phase 2 Designated Guest semantics.
**Gate contribution:** P4-3.
**Estimated effort:** 4 person-days.

**Files:** Extend `apps/core/src/tuntun_core/services/whole_home/media_policy.py`; create `apps/core/src/tuntun_core/services/whole_home/child_media_rule_registry.py`; reuse the shared prepared-action and subject/guardian ceremony services; modify `apps/core/src/tuntun_core/bootstrap/container.py` and `tests/integration/whole_home/test_phase4_boot_composition.py`; create `tests/unit/whole_home/test_media_policy_matrix.py`, `tests/property/whole_home/test_media_authorization.py`, `tests/integration/whole_home/test_child_media_rule_registry.py`, and `tests/security/whole_home/test_child_media_guardian_slots.py`.

**Interfaces:** `MediaPolicyService.authorize(AuthorizedMediaRequestV1) -> MediaAuthorizationDecisionV1`. `ChildMediaRuleRegistry.prepare|approve|activate|replace` uses the shared owner-passkey prepared-mutation protocol, a separate current-primary-guardian one-use approval slot, and an exact expected-generation CAS. First activation is `draft -> active`; an approved edit creates a new immutable version and atomically performs `active -> active` at generation+1, so two versions can never be current. The proposal/final rule signs the expected pre-CAS generation; the lifecycle receipt and downstream authority carry the observed/resulting post-CAS generation, avoiding an impossible pre-signed future generation. `revoke_immediately` is a safety reduction: it works on the LAN while auth/cloud are unavailable, requires no new passkey or guardian ceremony, and atomically advances `active -> revoked` within two seconds. Its lifecycle receipt repeats the current rule version's preparation/owner/guardian ceremony commitments only as immutable provenance and carries a distinct local revocation request/source/time; those references are never consumed again or interpreted as fresh revoke authority. Server persists the canonical request bytes under their exact `request_binding_commitment`; every allow/deny/step-up decision repeats that commitment. A consumer reloads and constant-time compares the stored canonical request and recomputed commitment before any catalog/player read, so request ID or equal generations alone confer no authority. An allow selects one authorization class: adult reversible immediate, exact confirmation, owner passkey, Designated Guest owner co-approval, or one current preconfigured child rule.

The child ceremony is acyclic and exact: owner preparation commits `ChildMediaRuleProposalV1`; the distinct guardian's five-minute, one-use approval binds its `proposal_digest`; the finalized signed `ChildMediaRuleV1` repeats that proposal digest plus the exact approval ID/principal/generation/commitment and receives a separate final `rule_digest`. Activation/replacement recomputes both digests, verifies the owner and guardian commitments, reloads every current child/profile/area/player/provider/adapter/entitlement/policy fact, atomically consumes both authority records, and emits one total CAS receipt. Only an `APPLIED` receipt for `draft -> active` or an approved new-version `active -> active` can authorize playback; `REJECTED` repeats the unchanged observed state/generation and can never be interpreted as active. Revocation is the legal immediate `active -> revoked` generation transition, needs no fresh ceremony, records its distinct local safety source, is immediately durable, and survives restart/restore.

An active rule binds child/profile, one exact `(area_id, area_generation)` shared by every canonical player, player binding/capability generations, provider/adapter/entitlement generations, permitted content classes or durable keyed item/playlist identity commitments, maximum absolute volume, non-overlapping canonical hours, exact IANA timezone plus approved tzdata version/digest and `instant_to_local_window.v1`, policy generation, owner preparation, distinct guardian approval, issue/expiry, and expected pre-CAS lifecycle generation. Each canonical hour is a half-open local-minute interval `[start_local_minute, end_local_minute)` with `0 <= start < end <= 1440`; `[1439, 1440)` covers the final minute of a civil day, adjacent intervals may share an endpoint, and an overnight allowance is represented as two weekday-bound intervals rather than a wrapping interval. Activation resolves the name with `ZoneInfo` from that exact approved artifact; a missing/invalid zone or artifact mismatch rejects. Authorization converts trusted UTC `now` to one unique local instant using the bound artifact, so a fall-back fold is evaluated by its actual UTC instant and a nonexistent spring wall time is never synthesized. It also consumes the Phase 2 trusted-clock high-water state: any unresolved wall-clock rollback denies new child playback until reconciliation advances beyond the durable high-water mark, so an allowed window cannot replay. A tzdata artifact change advances policy/rule lifecycle and invalidates the old rule before use. The rule never stores a short-lived catalog handle. Every execution obtains a fresh, single-use handle and requires its exact provider authority and item-identity commitment to match the still-active rule. Each child allow creates a `ChildMediaAuthorizationAuthorityV1` naming the exact rule/proposal/final digest, resulting active lifecycle generation and lifecycle-receipt commitment plus the one matched content basis. That atomic tuple is required iff the allow class is `child_rule_guardian_approved`, is repeated unchanged by the signed envelope, dispatch receipt, and operation result, and is exact-compared with the immutable operation/decision row. Before catalog/player/bridge I/O, authorization and dispatch both reload the signed rule, its applied lifecycle receipt, current lifecycle state/generation, exact request/player/provider/content/hour/volume facts, and the fresh handle. Edit/revoke invalidates already minted decisions and undispatched envelopes, not only future handles.

A Designated Guest is deliberately not identified and has no subject ID; authorization reopens the exact active bounded guest session, generation, permitted common area/target/action/content class, expiry, and one-use owner co-approval commitment. It atomically consumes that co-approval before returning allow. Missing, partial, stale, cross-session, already-consumed, or ordinary-Guest authority denies before catalog/player lookup. `phase4.child_guarded_media.v1` remains absent until the registry, distinct-principal ceremony, restart/revoke, UI, and physical child-safe playback gates all pass.

- [ ] Write red corpus tests for actor/evidence, item/transport/provider/group/volume/persistence risk, room/player binding, quiet hours, content class, stale observation, owner/guardian generations, same-principal substitution, and restrictive identity conflict. Add registry cases for missing/expired/replayed owner preparation or guardian approval; same-principal owner/guardian; proposal-field mutation; final approval ID/principal/generation/commitment mutation; cross-area player or area-generation mismatch; invalid/missing IANA zone, tzdata version/digest substitution, artifact drift, DST fall-back folds, spring gap, overlapping hours, trusted-clock rollback/high-water/restart; wrong child/profile/player/provider/content class/durable item identity/volume/hour/policy/generation; reordered or wildcard player set; stale entitlement; illegal or rejected activation transition; crash before/after each consume/CAS; restart/restore; revoke; and area reclassification. Prove revoke works offline without passkey/guardian approval, persists within two seconds, and remains revoked after a crash before/after commit; substituted revocation source/time or original activation provenance fails verification without restoring authority. Prove a fresh handle for the same approved durable identity succeeds, while a rotated handle for another item fails; no handle is persisted in a standing rule. Independently substitute every `ChildMediaAuthorizationAuthorityV1` field between decision, operation row, signed envelope, receipt, and result; use a rejected activation receipt; or revoke after allow but before dispatch. Each fails before catalog/player/bridge I/O and cannot publish an allow/result after restart. Cover each missing/partial Designated Guest field, cross-session/generation/area/target/action substitution, expired/cancelled session, co-approval replay, and every consume/authorize crash boundary; all reject before catalog/player lookup and leave the child feature/route/action enum absent.
- [ ] Implement `home_reversible_media_v1` only for one identified adult, one unambiguous registered single-player pause/resume/stop or small configured transport/volume operation, with fresh evidence and no provider/item/area/group/persistence change.
- [ ] Require exact confirmation for starting a new item, provider change, transfer, material volume, and immutable group. Require owner passkey for provider/account, group definition, child rule, binding/adapter, queue/routine/policy changes.
- [ ] Guest/anonymous media remains disabled. A Designated Guest request may be held only by an owner-created bounded common-area session and still needs a fresh owner passkey for that exact action.
- [ ] Implement immutable child-rule versions and serialized `prepare proposal -> distinct guardian approve proposal digest -> finalize/sign -> activate|replace` CAS. Sign the expected pre-CAS generation, permit only `draft -> active` first activation or `active -> active` replacement with one new current version, and carry the resulting generation in activation authority. Reopen current child/profile/area/player/provider/adapter/entitlement/policy facts both at activation/replacement and every authorization; resolve a fresh single-use handle and match only its durable keyed item identity or an allowed trustworthy classification. Purchases, explicit/unknown content without an exact approved identity, broad groups, accounts, policy, and persistent routines deny. Revocation is immediate, advances generation, invalidates pre-dispatch authority, and survives restart/restore without resurrection.
- [ ] Run `uv run pytest tests/unit/whole_home/test_media_policy_matrix.py tests/property/whole_home/test_media_authorization.py tests/integration/whole_home/test_child_media_rule_registry.py tests/security/whole_home/test_child_media_guardian_slots.py tests/integration/whole_home/test_phase4_boot_composition.py -q` and the Phase 4 policy corpus; expect zero over-broad grant, an absent child route until all gate evidence is current, and exact manifest-backed service registration.
- [ ] Stage `apps/core/src/tuntun_core/services/whole_home/media_policy.py apps/core/src/tuntun_core/services/whole_home/child_media_rule_registry.py apps/core/src/tuntun_core/bootstrap/container.py tests/unit/whole_home/test_media_policy_matrix.py tests/property/whole_home/test_media_authorization.py tests/integration/whole_home/test_child_media_rule_registry.py tests/security/whole_home/test_child_media_guardian_slots.py tests/integration/whole_home/test_phase4_boot_composition.py`, then commit with `git commit -m "feat(media): enforce household media policy"`.

### Task 19: Extend the signed Home Assistant bridge with closed media receipts and dispatch

**Depends on:** Tasks 01, 03, 17–18 and the accepted Phase 2 bridge channel/key/receipt store.
**Gate contribution:** P4-3 and P4-7 recovery.
**Estimated effort:** 3.5 person-days.

**Files:** Create `integrations/home-assistant/custom_components/tuntun_bridge/{media,media_schema}.py`; modify `const.py`, `http.py`, `store.py`, and `backup.py` additively; create `apps/core/src/tuntun_core/adapters/media/home_assistant.py`; modify `apps/core/src/tuntun_core/bootstrap/container.py` and `tests/integration/whole_home/test_phase4_boot_composition.py`; test `integrations/home-assistant/tests/test_media_route.py`, `integrations/home-assistant/tests/test_media_receipts.py`, `tests/integration/whole_home/test_signed_media_bridge.py`, and `tests/security/whole_home/test_no_general_ha_media_route.py`.

**Interfaces:** Separate media-action signature domain/route `tuntun-media-v1` with key purpose `media_action`, plus the Core-only deadline-terminal domain `tuntun-media-dispatch-unknown-terminal-v1`/`core_media_dispatch_unknown_terminal`; compiled provider/player/catalog binding IDs; adapter dispatch receipt lifecycle `AUTHORIZED_COMMITTED -> DISPATCHING -> RECONCILING -> ACCEPTED_UNVERIFIED | FAILED`, plus `EXPIRED` only when the envelope deadline passes before dispatch. Adapter `MediaDispatchReceiptV1` cannot claim `unknown`; the closed `MediaDispatchControlRecordV1` adds the distinct Core terminal branch. The HA media route imports and calls the accepted Phase 2 bridge-store `advance_to_dispatching_if_fresh(..., begin_after_commit_no_yield)` serialized dispatch-admission primitive; media and TV share that one implementation rather than copying its clock/CAS logic. The primitive accepts no caller dispatch time. Under the same serialized writer as epoch, topology, binding, capability, provider, entitlement, policy, gate, quota, and lifecycle changes, it reloads all current authority, samples trusted `dispatch_started_at` only after acquiring the writer, and permits the CAS only while `dispatch_started_at < envelope.expires_at`. After the dispatch-proof/target-record `COMMIT` returns and the writer is released, the same call performs no `await`, yield, task scheduling, or caller handoff: it resamples trusted `actual_call_started_at`, requires that sample still be before expiry, and only then invokes the synchronous `begin_after_commit_no_yield` capability, which begins the internally compiled effect before returning its awaitable completion handle. If the second sample reaches expiry, the capability is not invoked; the committed attempt-one proof remains potentially in flight and is never replayed after restart. The exact provider authority tuple is reloaded everywhere; neither a bare scalar generation nor a player's list of candidate providers can select authority. For play, resolving the opaque handle copies its keyed item-identity commitment into the signed envelope; the playable URI never leaves the adapter. Seek additionally signs the exact commissioned verification tolerance. The operation ID is generated and durably committed before signing, then repeated by the signed envelope, adapter receipt, Core terminal, result, and every target result. `MediaOperationResultV1` is the only contract that can later assert derived `VERIFIED` or `PARTIAL` truth from manifest-ordered post-dispatch observations. A durable pre-dispatch receipt precedes service I/O and retains Phase 2 timing/idempotency/epoch rules. Every adapter receipt carries operation/request/action/idempotency/target authority, the digest of the exact stored canonical signed envelope, controller/topology/binding/capability/provider-binding/provider/adapter/entitlement/policy authority, authorization class plus the optional atomic child-rule authority, request and authorization commitments, request/decision deadlines, and authorization/issue/envelope-expiry/reconciliation/terminal times. The bridge reloads the immutable operation row, decision, exact provider binding, and envelope by digest and exact-compares every repeated field before accepting the receipt. For a child-rule action it additionally verifies `media_action` signature purpose, reloads the exact signed rule and `APPLIED` lifecycle receipt by commitment, and requires that rule to remain active at the repeated resulting lifecycle generation before any provider/player/adapter read. Receipt parsing also takes trusted receiver time, rejects a future `observed_at`, and rejects adapter ingress or any claimed observation/terminal after the signed reconciliation deadline. Each canonical target gets exactly one immutable terminal lineage record: a pre-dispatch failure atomically persists `kind=not_dispatched` with no dispatch evidence, while the `PRE_DISPATCH -> DISPATCHING` CAS persists `kind=dispatch_started` with operation/action/request/idempotency/envelope lineage, dispatch start, and commitments over the exact HA context and desired effect. Its keyed commitment and kind are repeated by that target's result. Every attempted/possibly-in-flight/accepted or post-dispatch terminal result retains this evidence. `EXPIRED` is exclusively adapter attempt `0`, has no dispatch evidence, and is valid only at/after the signed-envelope deadline. Adapter-ingress acceptance and `MediaDispatchDeadlineFinalizer.finalize(operation_id)` share the same authority writer, so equality races have one serialized winner and one immutable terminal. At or after the trusted Core reconciliation deadline, the finalizer reloads the exact stored envelope, operation, and complete immutable attempt-one target proof set, and—only if no valid terminal adapter receipt was durably ingested by the deadline—atomically inserts one replay-unique `MediaDispatchUnknownTerminalV1` plus outbox record. It fixes `terminal_at=reconciliation_deadline`, records actual `materialized_at >= terminal_at`, signs only under the Core media-terminal domain/purpose, returns none before the deadline, and returns the same durable terminal at equality or later across crash/restart. Late adapter evidence cannot replace it. A pre-dispatch `FAILED` uses attempt `0`, `not_dispatched`, and observation strength `none`; every `UNKNOWN` target/result requires attempt `1`, `dispatch_started`, and the verified Core terminal lineage. No acknowledgement alone can become verified/partial, no observation sampled before dispatch start can verify the effect, and no observation after the signed reconciliation deadline can be attached to that operation. For a group target, the bridge must load the one current immutable manifest and constant-time compare the envelope's target kind, manifest ID/version/digest, canonical ordered members, every player binding/capability generation, and every per-member maximum-volume cap before any player/domain read or adapter I/O.

A child target may enter `state="UNKNOWN"` only at `completed_at=reconciliation_deadline` and must carry the exact Core terminal commitment. An aggregate may still be `UNKNOWN` without a Core terminal when all child targets are already definitive but their mix—such as acknowledgement-only plus failed—cannot truthfully be called partial; that aggregate must contain no child `UNKNOWN` and cannot invent a deadline-terminal commitment.

A cryptographically valid definitive media adapter receipt that loses the deadline race is retained once in encrypted `media_late_dispatch_evidence` with complete canonical typed bytes, digest, trusted ingress, terminal ID, `retained_not_authoritative` disposition, and retention deadline. It is audit/adapter-quality evidence only: result verification, UI truth, and dispatch admission exclude it, and it cannot replace the Core terminal or authorize replay. Invalid or oversized late payloads retain only bounded rejection metadata and a keyed digest.

- [ ] Write red tests for wrong signature domain/key purpose and independently substituted operation/request/action/idempotency/target/envelope digest/controller epoch/topology/binding/capability/provider/entitlement/policy generation, authorization class/child-rule authority, request/authorization/effect commitment, request/decision/authorization/issue/expiry/reconciliation/terminal time, stale/expired envelope, nonce replay, unknown action/target, caller-supplied entity/service/URI/path, duplicate dispatch, crash at every receipt/target-record transition, quota pressure, and restore. Hold the shared serialized writer, queue dispatch, move its trusted clock to expiry equality and then expiry plus one microsecond before release, and require attempt-zero `EXPIRED`, one `not_dispatched` record, zero begin/effect calls, and the same terminal after restart. Separately inject expiry equality and plus one microsecond exactly when the successful dispatch-proof `COMMIT` returns; require the attempt-one proof/`dispatch_started` record to remain, zero `begin_after_commit_no_yield`/effect calls, Core-terminal-bound `UNKNOWN` at the reconciliation boundary, and zero redispatch after restart. Trace assertions must prove the writer-owned sample follows lock acquisition and the second trusted sample follows `COMMIT` but precedes the synchronous begin callback with no await/yield between them. For child authority, independently change rule ID/version/proposal digest/final digest/lifecycle generation/activation commitment/child/profile/content basis, delete or replace the active rule/receipt, or revoke between decision and dispatch; each must cause zero provider/player/adapter reads. Prove an early `expired` receipt fails, a no-dispatch expiry at the deadline succeeds, and every post-dispatch deadline timeout is Core-terminal-bound `UNKNOWN` with complete proof. Exercise the complete target state×attempt×transition-kind×observation-strength matrix. Remove or substitute a target transition-record kind/commitment or dispatch start/context/effect one at a time, reuse an old record for the same player, attach evidence to attempt `0`, or supply an observation one microsecond before dispatch or after reconciliation deadline; each rejects and cannot produce accepted/possibly-in-flight/verified truth. Prove a genuine attempt-0 failure atomically persists and survives restart with exactly one `not_dispatched` record, and no dispatch record/evidence. Prove `MediaDispatchReceiptV1` cannot express `unknown`/`verified`/`partial`, and that only `MediaOperationResultV1` derives result truth from complete manifest-ordered evidence. For groups, substitute target kind, manifest ID, version, digest, member order/ID, player binding generation, capability generation, or member cap one at a time; each must fail before any player lookup or adapter I/O. A changed/replaced manifest, operation row, target transition record, or signed envelope replay after restart fails closed.
- [ ] Add explicit terminal-boundary tests: adapter `state="unknown"` fails schema validation; the Core finalizer returns no record at deadline minus one microsecond, creates one exact terminal at equality, and returns the identical terminal at plus one microsecond and after restart. Cover delayed adapter/network evidence, trusted ingress after deadline, crash before terminal commit, crash after terminal/outbox commit, group-proof set substitution, `materialized_at` after a delayed restart, and zero redispatch. Replay the terminal across every media action/group/child-rule domain and wrong purpose; all reject. Prove `MediaDispatchReceiptV1` cannot express `unknown`, `verified`, or `partial`, and that only the verified Core-terminal lineage can support a timed-out attempt-one `UNKNOWN` result.
- [ ] Run red; expect route/schema/store support absent.
- [ ] Implement only the seven initial media actions. Translation uses a compiled binding and Home Assistant system context; request fields cannot select entity/service/template/event. Add the Core deadline-terminal store/finalizer with a unique `operation_id`, exact immutable envelope/proof-set commitments, and transactional outbox; sign it only under `tuntun-media-dispatch-unknown-terminal-v1`/`core_media_dispatch_unknown_terminal`. Store minimized action/target commitments and result facts, never actor, transcript, catalog query, provider result body, or credential.
- [ ] Preserve the Phase 2 100 MiB quota/retention/nonterminal rules and backup disclosure. A potentially dispatched uncertain row is reconciled, never redispatched. Failed primary provider/player path does not call another path.
- [ ] Run `uv run pytest integrations/home-assistant/tests/test_media_route.py integrations/home-assistant/tests/test_media_receipts.py tests/integration/whole_home/test_signed_media_bridge.py tests/security/whole_home/test_no_general_ha_media_route.py tests/integration/whole_home/test_phase4_boot_composition.py -q` and full Phase 2 bridge regression tests.
- [ ] Stage the exact HA/Mac adapter paths plus `apps/core/src/tuntun_core/bootstrap/container.py tests/integration/whole_home/test_phase4_boot_composition.py`, then commit with `git commit -m "feat(ha-bridge): add closed signed media actions"`.

### Task 20: Gate the optional Music Assistant adapter on exact deployment evidence

**Depends on:** Tasks 06 and 19; exact owner-approved MA/HA versions and one legal provider/player candidate. Task 06 serializes the preceding root workspace/lock mutation.
**Gate contribution:** optional part of P4-3.
**Estimated effort:** 3 person-days plus physical/elapsed tests.

**Files:** Modify `pyproject.toml` and `uv.lock`; create `integrations/music-assistant/pyproject.toml`, `integrations/music-assistant/README.md`, and `integrations/music-assistant/src/tuntun_ma_adapter/{__init__,capabilities,catalog,playback}.py`; modify `apps/core/src/tuntun_core/bootstrap/container.py` only for manifest-driven optional entry-point loading; create `scripts/phase4/qualify_music_assistant.py` and `docs/evidence/phase4-music-assistant.schema.json`; test `integrations/music-assistant/tests/test_package_bootstrap.py`, `integrations/music-assistant/tests/test_closed_adapter.py`, `tests/security/whole_home/test_ma_admin_unreachable.py`, `tests/acceptance/whole_home/test_music_assistant_composition_absence.py`, `tests/hardware/whole_home/test_music_assistant_gate.py`, and modify `tests/integration/whole_home/test_phase4_boot_composition.py`.

**Interfaces:** First owns optional standalone library distribution `tuntun-ma-adapter`: register exact root workspace member `integrations/music-assistant` once, expose `tuntun_ma_adapter.__version__: str = "0.1.0.dev0"`, and regenerate the root lock. It depends on `tuntun-contracts` plus only directly imported transport primitives and never imports core, Home Assistant custom-component internals, room/display agents, or policy implementation. It publishes no console script or server. It exposes exactly one non-executable plugin entry point, `[project.entry-points."tuntun.media_adapters"] music_assistant = "tuntun_ma_adapter.playback:build_adapter"`; the bounded owner-gated executable remains `scripts/phase4/qualify_music_assistant.py`. Core never imports `tuntun_ma_adapter` by module path. Only when `phase4.music_assistant.v1` is present in the accepted signed feature manifest may the container load that exact entry-point name from the exact signed wheel digest, verify it implements the closed `MediaCatalogPort`/`MediaPlaybackPort`, and register it through the HA bridge's compiled binding. In the default/failed/omitted branch, the distribution, entry point, config, adapter registration, route, and UI chunk are absent, and mandatory media tasks depend only on the port. Tuntun never stores or sends a general MA API key/admin credential. Production registration requires a signed evidence digest for exact MA application/integration, Green resources/storage/backups, provider/player adapters, ports/discovery/cloud dependencies, history/scrobbling setting, and rollback.

- [ ] Write red tests proving no general MA HTTP/WebSocket/admin/library-management/provider-enrollment route, credential field, arbitrary URI, queue mutation, account switch, history fetch, or redirect.
- [ ] Run `uv run pytest integrations/music-assistant/tests/test_package_bootstrap.py integrations/music-assistant/tests/test_closed_adapter.py tests/security/whole_home/test_ma_admin_unreachable.py -q`; expect missing package/workspace registration and adapter failures.
- [ ] Bootstrap with the foundation Python/Hatchling/version pins, merge `integrations/music-assistant` into the current root workspace, declare `tuntun-contracts = { workspace = true }`, declare only the exact `tuntun.media_adapters` entry point above, and regenerate `uv.lock`. The permanent bootstrap test parses both TOML files, AST-scans every package import, imports the installed library, rejects duplicate membership/forbidden dependencies or imports, proves no `project.scripts`/server entry point exists, and proves no other plugin entry point is published.
- [ ] Implement capability translation and stable opaque bindings. Default optional history/scrobbling off; inventory unavoidable provider history/telemetry and backup scope. Keep MA unavailable when absolute safe volume or truthful player state cannot be obtained.
- [ ] Run the locked import/build and synthetic gates first:

```bash
uv lock
uv sync --all-packages --locked
uv run --locked --offline --no-sync python -c 'import tuntun_ma_adapter; assert tuntun_ma_adapter.__version__ == "0.1.0.dev0"'
uv run --locked --offline --no-sync pytest integrations/music-assistant/tests/test_package_bootstrap.py integrations/music-assistant/tests/test_closed_adapter.py tests/security/whole_home/test_ma_admin_unreachable.py tests/acceptance/whole_home/test_music_assistant_composition_absence.py tests/integration/whole_home/test_phase4_boot_composition.py -q
uv lock --check
uv build --offline --wheel --package tuntun-ma-adapter --out-dir var/build-smoke/phase4/music-assistant
uv lock --check
```

- [ ] Then owner-gated qualification covers catalog, ambiguity, play/pause/resume/stop, absolute volume, queue, reboot, Green backup/restore, WAN loss, MA outage, player manual control, token revocation, provider expiry, upgrade/rollback, and resource/thermal/storage measurements.
- [ ] Execute `TUNTUN_ALLOW_MEDIA_PROBE=1 uv run --locked --no-sync python scripts/phase4/qualify_music_assistant.py --evidence-root var/evidence/phase4/media/music-assistant` and verify content-safe evidence.
- [ ] If any gate fails, keep `phase4.music_assistant.v1` absent and use only the accepted HA single-player path or no media. Do not weaken the boundary with a direct token.
- [ ] Commit adapter/tooling/tests before the hardware run; never commit owner evidence:

```bash
git add pyproject.toml uv.lock integrations/music-assistant/pyproject.toml integrations/music-assistant/README.md integrations/music-assistant/src/tuntun_ma_adapter/__init__.py integrations/music-assistant/src/tuntun_ma_adapter/capabilities.py integrations/music-assistant/src/tuntun_ma_adapter/catalog.py integrations/music-assistant/src/tuntun_ma_adapter/playback.py integrations/music-assistant/tests/test_package_bootstrap.py integrations/music-assistant/tests/test_closed_adapter.py apps/core/src/tuntun_core/bootstrap/container.py scripts/phase4/qualify_music_assistant.py docs/evidence/phase4-music-assistant.schema.json tests/security/whole_home/test_ma_admin_unreachable.py tests/acceptance/whole_home/test_music_assistant_composition_absence.py tests/integration/whole_home/test_phase4_boot_composition.py tests/hardware/whole_home/test_music_assistant_gate.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(media): add gated Music Assistant adapter"
```

### Task 21: Commit, sign, dispatch, and truthfully reconcile media actions and groups

**Depends on:** Tasks 03 and 17–19. Task 20 is an additional dependency only when `phase4.music_assistant.v1` is selected and accepted; the mandatory branch must build and pass with Task 20 omitted.
**Gate contribution:** P4-3.
**Estimated effort:** 3.5 person-days.

**Files:** Create `apps/core/src/tuntun_core/services/whole_home/{media_coordinator,media_reconciliation}.py`; modify `apps/core/src/tuntun_core/bootstrap/container.py` and `tests/integration/whole_home/test_phase4_boot_composition.py`; test `tests/integration/whole_home/test_media_action_lifecycle.py`, `tests/property/whole_home/test_media_groups.py`, `tests/fault/whole_home/test_media_crash_recovery.py`, and `tests/performance/whole_home/test_safe_start_volume.py`. Do not create a Core Music Assistant adapter module.

**Interfaces:** `MediaCoordinator` consumes only registered `MediaCatalogPort`/`MediaPlaybackPort` instances; it never imports or type-checks against the optional MA distribution. Installed composition proves the absent branch contains no MA distribution/entry point/config/adapter/route, while the selected branch loads only the exact accepted entry-point/wheel digest. `MediaCoordinator.execute(AuthorizedMediaRequestV1, MediaAuthorizationDecisionV1, AuthContext) -> UUID` consumes the canonical Phase 1 `AuthContext`, first reloads and exact-compares the stored canonical request bytes and recomputed `request_binding_commitment` to both request and decision, then obtains trusted `now` and requires `now < request.expires_at` and `now < decision.valid_until` before any catalog, player, group, or bridge read. It then requires the exact action binding to match the still-current allow decision and commits the immutable operation/action/audit/outbox before signing or I/O. `MediaAuthorityCompiler.compile_current(operation_id, request, decision, uow, now) -> SignedMediaEnvelopeV1` repeats the committed operation ID, source request ID, request commitment/deadline, authorization class and optional atomic child-rule authority, fixes `authorized_at=decision.decided_at`, carries the decision deadline, and signs a fixed reconciliation deadline no later than five seconds after envelope expiry. It reopens and exact-compares the current provider tuple, player or immutable group manifest, resolves an exact current handle to its item-identity commitment, and requires `issued_at < min(request.expires_at, decision.valid_until)` with envelope expiry no later than that same minimum. For a child allow it also reopens the signed active rule plus applied activation receipt, exact-compares every authority field and rule constraint, and confirms the resolved handle's durable item identity or trustworthy classification before committing the operation. A group envelope carries the full target kind, manifest ID/version/digest, canonical ordered members, each member's current player binding/capability generation, and its exact volume cap. Any expired/equality boundary, request-byte/commitment, operation-row, child-rule, or target difference denies before catalog/player read. `MediaReconciliationService.reconcile(operation_id: UUID, observations: tuple[PlayerObservationV1, ...], now: datetime) -> MediaOperationResultV1` accepts trusted `now`, maps only source-receipt-bound observations within `[target_dispatch_started_at, reconciliation_deadline]` to complete manifest-ordered per-player results, and returns `UNKNOWN` for evidence arriving later rather than attributing a later manual state to the old action. A verified target requires adequate non-optimistic strength plus `control_correlation_id == action_id`. `ACCEPTED_UNVERIFIED` requires at least an exact bound adapter acknowledgement or stronger non-mirrored observation and repeats its source-receipt commitment; attempt-one with no such evidence or only mirrored optimism remains `UNKNOWN`. Play also requires exact item-identity commitment and `playing`; pause/resume/stop require the exact state; volume requires exact absolute value; seek requires position within the signed commissioned tolerance. If a player cannot expose item identity/action correlation, play caps at `ACCEPTED_UNVERIFIED` or `UNKNOWN`. Aggregate `PARTIAL` requires at least one actually verified target and at least one non-verified target; acknowledgement-only mixed with failed/unknown is `UNKNOWN`, never partial. The result repeats the immutable operation/request/action/idempotency/target/envelope digest, desired item/value authority, complete controller/topology/binding/capability/provider/adapter/entitlement/policy authority, authorization class/child-rule authority, request/authorization commitments and deadlines, and action/reconciliation window. Before persistence or serving, `MediaResultVerifier` reloads the immutable operation row, decision, stored canonical signed envelope by digest, current child-rule authority when present, every immutable per-target transition record by commitment, and each claimed source receipt/observation by commitment; verifies record kind (`not_dispatched` iff attempt 0, otherwise `dispatch_started`), domains, and commitments; derives expected target IDs as the single player ID or exact envelope group-member order; and constant-time compares all repeated fields, both result target tuples, record evidence, and time bounds. Missing/replaced/stale/revoked lineage or a same-target prior-operation record rejects after restart with no projection/API publication.

For any timed-out attempt-one target, `MediaResultVerifier` also reloads and verifies the one Core `MediaDispatchUnknownTerminalV1`, its domain/purpose, terminal commitment, fixed logical deadline, actual materialization time, exact operation/envelope/proof-set lineage, and durable uniqueness row. Missing, late, replaced, adapter-authored, wrong-domain, or partial-group terminal evidence cannot produce or publish an `UNKNOWN` result.

- [ ] Write red tests for crash before/after auth commit, sign, HA receipt, target transition-record commit, player call, observation, and Core deadline-terminal commit/outbox; duplicate submit; changed group/provider/binding; partial group; stale/unknown volume; manual changes; quiet hours; unsupported seek; result timeout; and alternate-protocol retry attempt. Test request-expiry, decision-deadline, and reconciliation-deadline equality plus one microsecond after. Independently substitute operation ID, action/request/idempotency, envelope digest, result target tuple, every child lineage/transition/dispatch field, Core-terminal commitment/domain/purpose/materialization/proof set, or reuse a prior operation's valid record against the same target; publication must fail. Include attempt-0 failure commit/restart/replay with exact `not_dispatched` record. Derive and test single-player and exact group target order, including entirely different, missing, extra, and permuted targets. Add one-field substitution tests for group target kind/ID/version/digest/member order/member ID/player binding generation/player capability generation/cap and prove zero catalog, player, or bridge reads occur before the exact current group comparison passes. Restart/replay with a replaced manifest, operation row, envelope, target record, or Core terminal must not resurrect old authority.
- [ ] Implement UoW commit and grant consumption, then sign outside the writer lock. Freshly observe target state and set absolute bounded start volume before play. If absolute volume is unsupported/unknown, deny new playback.
- [ ] Groups are 1..configured maximum immutable members in canonical `member_index` order, with exact manifest digest, player binding/capability generation, and per-member cap. Confirmation names every canonical `(area_id, area_generation)`. The signed envelope is built only from the reloaded current manifest; callers cannot supply or reorder members. A group never receives private speech/auth/child/security content.
- [ ] Reconcile `VERIFIED_PLAYING` only from adequate fresh observation. `PARTIAL` requires complete ordered members with mixed terminal outcomes. Unknown never collapses to success or triggers another provider/protocol.
- [ ] Run the four tests plus `tests/integration/whole_home/test_phase4_boot_composition.py` and 500 adversarial media corpus cases. Expect zero unauthorized fetch/playback, double start, wildcard expansion, loud unknown-volume start, credential disclosure, private broadcast, false atomic success, or manifest/composition drift in both optional-MA branches.
- [ ] Stage `apps/core/src/tuntun_core/services/whole_home/media_coordinator.py apps/core/src/tuntun_core/services/whole_home/media_reconciliation.py apps/core/src/tuntun_core/bootstrap/container.py tests/integration/whole_home/test_media_action_lifecycle.py tests/property/whole_home/test_media_groups.py tests/fault/whole_home/test_media_crash_recovery.py tests/performance/whole_home/test_safe_start_volume.py tests/integration/whole_home/test_phase4_boot_composition.py`, then commit with `git commit -m "feat(media): reconcile deterministic playback"`.

### Task 22: Add owner media/provider/player/group UI and truthful operation results

**Depends on:** Tasks 04, 17–19, and 21 plus the shared admin shell/design system. Task 20 is required only when the Music Assistant branch is selected.
**Gate contribution:** P4-3 and UI acceptance.
**Estimated effort:** 4 person-days.

**Files:** Modify the Task 04-owned `apps/admin/src/features/media-learning/index.ts`; create `apps/admin/src/features/media-learning/media.tsx` and `apps/admin/src/routes/media-learning-media.tsx`; modify `apps/core/src/tuntun_core/api/phase4_dtos.py`, `apps/core/src/tuntun_core/api/routes/media.py`, `apps/core/src/tuntun_core/api/app.py`, `apps/core/src/tuntun_core/bootstrap/container.py`, `apps/owner-ingress/src/tuntun_owner_ingress/router.py`, `ops/routes/owner-ingress-routes.v1.json`, `ops/services/phase3-owner-ingress.v1.json`, `tests/integration/whole_home/test_phase4_boot_composition.py`, `tests/integration/deploy/test_owner_ingress_route_manifest.py`, `tests/integration/vision/test_deployed_process_entrypoints.py`, `tests/integration/deploy/test_phase3_side_process_lifecycle.py`, `tests/integration/vision/test_owner_ingress_takeover.py`, and `tests/fault/vision/test_owner_ingress_takeover_rollback.py`; generate UI contracts; create `tests/ui/media-learning/media.spec.tsx` and `tests/ui/e2e/media-learning-media.spec.ts`.

**Interfaces:** Bounded read models expose entitlement state/expiry, capability digest, player `area_id`/freshness/volume semantics/manual fallback, immutable groups, child-rule lifecycle/generation/approval state, safe current queue summary, operation result strength, and no secret/query/private title beyond current audience. Mutations use server-prepared exact summaries and the shared `428 step_up_required` flow. Player and group creation/retirement use owner-passkey ceremonies; child-rule activation visibly separates the owner's prepared configuration from the distinct current guardian's one-use approval and never exposes a reusable approval token to the browser.

- [ ] Write red route, direct-API, prepared-action, stale/multi-tab/replay, player/group commissioning, group-version replacement, child-rule owner/guardian same-principal and cross-tab substitution, revoke/restart, child/Guest access, result-correlation, and absent-MA tests. Add English/Hindi, 320 px, 200% zoom, keyboard, VoiceOver/axe, light/dark, and reduced-motion fixtures.
- [ ] Implement feature-gated navigation and separate transport/provider/account truth. Provide explicit player commissioning/retirement, immutable group versioning/retirement, and child-rule prepare/guardian-approve/activate/revoke views with exact summaries and current-generation conflict recovery. Never show optimistic playback; show request sent, then verified/accepted-unverified/partial/failed/unknown with source/freshness. Keep group and child UI routes/chunks absent until their independent gates pass.
- [ ] Run `uv run pytest tests/integration/whole_home/test_phase4_boot_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py -q && pnpm --filter @tuntun/admin test -- tests/ui/media-learning/media.spec.tsx && pnpm --filter @tuntun/admin e2e -- tests/ui/e2e/media-learning-media.spec.ts && pnpm --filter @tuntun/admin lint && pnpm --filter @tuntun/admin typecheck && pnpm --filter @tuntun/admin build`.
- [ ] Run browser storage/cache/history/log scans; expect no provider credential, query text, reusable URI, private title leak, or absent-feature chunk.
- [ ] Rebuild the locked owner-ingress wheel, refresh/re-sign `ops/services/phase3-owner-ingress.v1.json`, and execute the complete Global Constraint 40 installed lifecycle suite. The Task 05 row/receipt must fail against this media graph; no P4-3 physical enablement or accepted owner flow may use that stale generation.
- [ ] Stage the API/generated/UI/test paths plus `apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json ops/services/phase3-owner-ingress.v1.json tests/integration/whole_home/test_phase4_boot_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py`, then commit with `git commit -m "feat(admin): add truthful media management"`.

**Checkpoint P4-3:** Enable one provider and one player only after exact physical qualification. Manual player controls remain. Music Assistant is either separately accepted and registered or provably absent.

---

## Wave 3 — P4-4 Signed Closed Teaching Renderer and Guarded Learning

### Task 23: Build audience-bound teaching policy and closed manifest construction

**Depends on:** Tasks 01, 03–05 and accepted Phase 1 audience/child-safety/DLP/memory services plus Phase 2 screen-time policy.
**Gate contribution:** P4-4.
**Estimated effort:** 3.5 person-days.

**Files:** Create `apps/core/src/tuntun_core/services/whole_home/{teaching_policy,teaching_content,display_sessions}.py` and `apps/core/src/tuntun_core/api/routes/teaching.py`; modify `apps/core/src/tuntun_core/api/app.py`, `apps/core/src/tuntun_core/bootstrap/container.py`, `apps/owner-ingress/src/tuntun_owner_ingress/router.py`, `ops/routes/owner-ingress-routes.v1.json`, `tests/integration/whole_home/test_phase4_boot_composition.py`, and `tests/integration/deploy/test_owner_ingress_route_manifest.py`; test `tests/unit/whole_home/test_teaching_policy.py`, `tests/unit/whole_home/test_manifest_builder.py`, `tests/security/whole_home/test_teaching_injection.py`, and `tests/privacy/whole_home/test_display_minimization.py`.

**Interfaces:** `TeachingPolicyService.authorize(TeachingRequestV1) -> TeachingAuthorizationDecisionV1`; the service first reloads the stored canonical request bytes, recomputes and constant-time compares `request_content_commitment`, and requires trusted current time before the request deadline, all before endpoint/content reads. It reopens the exact current canonical `(area_id, area_generation)` and returns a populated `AuthorizedTeachingRequestV1` only for an allow; that DTO and every allow/deny decision repeat the original request commitment/deadline, while the authorized maximum can never exceed the requested duration. Its `TeachingAudienceBindingV1` imports Phase 1 `MemoryAudience`: Guest has `None` plus `generic_guest_public` and triggers zero memory read; identified sessions use `personalized`; K2/N1 `household_all` requires the exact current guardian generation and existing child-safe household approval. Every K2/N1 request must name exactly one Phase 2 screen-time session; non-child requests cannot. Before display/content reads, policy reloads that immutable current session, requires the same child/profile, area, current guardian approval generation and screen-time policy, checks that it is active, and carries its reference, keyed commitment, deadline, and policy version through authorization, draft, and signed manifest. The teaching authorization commitment covers that full tuple, and manifest expiry is capped by the current screen-time deadline. Missing, stale, ended, or cross-child sessions deny. `TeachingContentBuilder.build(AuthorizedTeachingRequestV1) -> UnsignedTeachingSessionDraft`; `DisplaySessionService.prepare(draft) -> TeachingSessionManifestV1` atomically commits session/audit/outbox before constructing and signing the final wire manifest with the exact audience commitment and authorized maximum duration. The builder accepts already authorized derived content, never a memory repository or general prompt/tool.

`web_mode` reuses the canonical Phase 1 wire values `no_web | controlled`; Phase 4 does not introduce another alias and never accepts `experimental_multi_pass` for teaching. Child and Guest requests/manifests are immutably `no_web`. An adult `controlled` request requires the exact current single-use Phase 1 controlled-web authorization commitment, consumed before content construction; only its normalized cited output may become closed components. The display agent itself performs zero web requests in every mode.

```python
@dataclass(frozen=True, slots=True)
class UnsignedTeachingSessionDraft:
    request_id: UUID
    request_content_commitment: HmacCommitment
    request_expires_at: datetime
    correlation_id: UUID
    display_endpoint_id: StableEndpointId
    display_endpoint_generation: int
    display_binding_generation: int
    display_capability_generation: int
    display_capability_evidence_digest: Sha256Digest
    renderer_endpoint_id: StableEndpointId
    renderer_endpoint_generation: int
    renderer_binding_generation: int
    renderer_capability_generation: int
    renderer_capability_evidence_digest: Sha256Digest
    area_id: StableHomeId
    area_generation: int
    audience_binding: TeachingAudienceBindingV1
    privacy_generation: int
    policy_version: PolicyVersion
    teaching_authorization_commitment: HmacCommitment
    topic_code: TeachingTopicCode
    requested_duration_minutes: int
    maximum_duration_minutes: int
    child_safe_household_approval_commitment: HmacCommitment | None
    child_extended_duration_commitment: HmacCommitment | None
    language_mode: Literal["en", "hi", "hinglish"]
    web_mode: Literal["no_web", "controlled"]
    controlled_web_authorization_commitment: HmacCommitment | None
    approved_source_pack_commitments: tuple[HmacCommitment, ...]
    screen_time_session_ref: UUID | None
    screen_time_session_commitment: HmacCommitment | None
    screen_time_session_expires_at: datetime | None
    screen_time_policy_version: int | None
    components: tuple[TeachingComponentV1, ...]
    assets: tuple[TeachingAssetV1, ...]
    expires_at: datetime
```

```python
async def test_guarded_child_teaching_is_fixed_no_web_and_never_searches(
    teaching_policy, content_builder, child_teaching_request, search_spy,
) -> None:
    decision = await teaching_policy.authorize(child_teaching_request)
    assert decision.effect == "allow"
    assert decision.authorized_request is not None
    assert decision.authorized_request.web_mode == "no_web"
    draft = await content_builder.build(decision.authorized_request)
    assert draft.audience_binding.audience_class in {"k2_child", "n1_child"}
    assert search_spy.calls == []

@pytest.mark.parametrize("field", [
    "request_content_commitment", "topic_code", "requested_duration_minutes",
    "maximum_duration_minutes", "controlled_web_authorization_commitment",
    "approved_source_pack_commitments", "screen_time_session_ref",
    "screen_time_session_commitment", "screen_time_session_expires_at",
    "screen_time_policy_version",
])
async def test_teaching_draft_substitution_rejects_before_content_asset_or_signer_access(
    display_sessions, valid_draft, field,
) -> None:
    with pytest.raises(TeachingAuthorizationStale):
        await display_sessions.prepare(substitute_valid_value(valid_draft, field))
    assert display_sessions.content_reads == []
    assert display_sessions.asset_reads == []
    assert display_sessions.signer.calls == []

def test_teaching_manifest_cannot_outlive_authorized_maximum(teaching_manifest_fixture) -> None:
    issued = teaching_manifest_fixture["issued_at"]
    maximum = teaching_manifest_fixture["maximum_duration_minutes"]
    with pytest.raises(ValidationError, match="teaching_manifest_window_invalid"):
        TeachingSessionManifestV1.model_validate({
            **teaching_manifest_fixture,
            "expires_at": issued + timedelta(minutes=maximum, microseconds=1),
        })

def test_teaching_authorization_cannot_expand_requested_duration(authorized_teaching_fixture) -> None:
    with pytest.raises(ValidationError, match="duration_exceeds_request"):
        AuthorizedTeachingRequestV1.model_validate({
            **authorized_teaching_fixture,
            "requested_duration_minutes": 1,
            "maximum_duration_minutes": 2,
        })
```

`UnsignedTeachingSessionDraft` is process-internal and cannot parse as or be passed to `TeachingSessionManifestV1`/`DisplaySessionPort`. It carries every authorization input needed to construct the closed manifest: original request commitment/deadline, topic, requested and authorized maximum duration, explicit language, exact screen-time session reference/commitment/deadline/policy tuple, controlled-web and approved-source-pack commitments, privacy generation, the exact teaching authorization commitment, and any child household-sharing or extended-duration commitment. These values are copied from the stored canonical `AuthorizedTeachingRequestV1`; the builder cannot synthesize or broaden them. Its explicit privacy generation must equal the audience binding and current core privacy authority. Before endpoint, content, asset, renderer, or signer access, `prepare` reloads the canonical teaching request and authorized-request bytes, recomputes and constant-time compares both commitments, requires trusted `now` strictly before the request, authorization, decision, and—for child—screen-time deadlines, and exact-compares every draft field. It then reopens the current child screen-time session, display and renderer endpoint/binding/capability generations and accepted evidence digests, validates current child/profile/guardian/policy authority, positive generations, component/asset caps and current audience/policy again, and enforces `manifest.expires_at <= min(manifest.issued_at + maximum_duration_minutes, screen_time_session_expires_at)` for child. It persists the canonical draft commitment, then signs the final manifest only after the transaction commit callback.

- [ ] Write red tests for adult/child/Guest audiences, identity downgrade, wrong display/renderer/area, independently substituted or stale display/renderer endpoint, binding, or capability generation/evidence digest, renderer re-pair/quarantine after authorization, stale/deleted/replaced request or authorization record, stale area/guardian/screen-time policy, missing/stale/ended/cross-child screen-time session, canonical fixed/read-only child `web_mode=no_web`, zero child search calls, live-web child request, adult-private memory injection, arbitrary markup/URL/path, scriptable SVG, MIME mismatch, oversize/decompression bomb, missing provenance, and expiry over the exact requested/authorized/session-screen-time maximum. Add one-field substitutions for original request commitment/deadline, topic, requested/maximum duration, controlled-web commitment, approved source packs, and every screen-time reference/commitment/deadline/policy field; each must produce zero endpoint/content/asset/signer reads. Test exact screen-time deadline and one microsecond after, one-minute duration overrun, and the child 30-minute/no-extension and >30-minute/exact-extension boundaries. Add schema/authorization/serialization rejection for a child without screen-time authority, a non-child carrying it, `owner_private|adult_private|household|public_only|household_shared`, child `household_all` without exact approval/current guardian generation, and Guest with any memory audience/read attempt.
- [ ] Run `uv run pytest tests/unit/whole_home/test_teaching_policy.py tests/unit/whole_home/test_manifest_builder.py tests/security/whole_home/test_teaching_injection.py tests/privacy/whole_home/test_display_minimization.py -q`; expect missing services.
- [ ] Implement adult cited explanations and owner material within current audience; K2/N1 use the Phase 1 guarded-learning policy and closed child-safe component subset; Guest gets generic unpersonalized content. Child live search is absent; a guardian/owner may select only preapproved local teaching packs with provenance/expiry.
- [ ] Build an internal frozen `UnsignedTeachingSessionDraft` containing only request/correlation IDs, exact display and renderer endpoint/binding/capability generations and evidence digests, target area generation, authorization/audience/policy binding, closed component tuple, hash-addressed asset descriptors, and bounded expiry after DLP/child-safety/type/size/provenance checks. It has no signing fields and is not accepted by `DisplaySessionPort`. Do not serialize profile, memory record, prompt, transcript, child response, browser credential, action grant, or television-control authority.
- [ ] `DisplaySessionService.prepare` reopens every display/renderer generation and evidence digest, derives the final session ID and draft commitment, and commits the authorized pending session/audit/outbox in one transaction. It then constructs the full manifest, recomputes its body-inclusive digest, and signs only `{domain, manifest_digest, complete non-content authority header}` under `tuntun-display-manifest-v1`. A second serialized transaction persists the immutable minimized `TeachingManifestAuthorityRecordV1` (header, digest, signing key/signature, HMAC, retention deadline; no component/asset/body) and advances `READY_TO_PRESENT`; only its post-commit callback may call `present`. A test spy must prove the signer is unreachable before the first commit and presentation is unreachable before the authority-record commit; commit/sign failure yields no present call. Reusing a session ID with another digest/audience/display/renderer/generation/asset denies. Voice, display, and TV control retain separate operation IDs under one correlation ID.
- [ ] Run the four tests plus `tests/integration/whole_home/test_phase4_boot_composition.py`, `tests/integration/deploy/test_owner_ingress_route_manifest.py`, and the child-safety corpus; expect all critical cases pass, no private sentinel in serialized manifest, and exact manifest-backed route/service composition.
- [ ] Stage the exact service/API/tests plus `apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json tests/integration/whole_home/test_phase4_boot_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py`, then commit with `git commit -m "feat(teaching): build closed audience-bound manifests"`.

### Task 24: Pair and harden the local display agent and kiosk boundary

**Depends on:** Tasks 07 and 23, plus Task 20 when the optional Music Assistant package is selected; otherwise Task 06 supplies the latest accepted workspace lock. Never mutate the root lock concurrently with Task 20.
**Gate contribution:** P4-4.
**Estimated effort:** 3.5 person-days.

**Files:** Modify `pyproject.toml` and `uv.lock`; create `apps/display-agent/pyproject.toml` and `apps/display-agent/src/tuntun_display_agent/{__init__,agent,config,pairing,manifest,assets,clear,hdmi,health,kiosk}.py`; create `ops/display-agent/{tuntun-display-agent.service,display-agent.toml.example,kiosk-policy.json,firewall.example.nft}`; create `scripts/phase4/pair_display.py`; test `apps/display-agent/tests/test_package_bootstrap.py`, `apps/display-agent/tests/test_service_entrypoint.py`, `apps/display-agent/tests/test_pairing_and_manifest.py`, `tests/integration/whole_home/test_display_agent_service_lifecycle.py`, `tests/security/whole_home/test_display_process_boundary.py`, and `tests/privacy/whole_home/test_display_filesystem_empty.py`.

**Interfaces:** First owns standalone distribution `tuntun-display-agent`: register exact root workspace member `apps/display-agent` once, expose `tuntun_display_agent.__version__: str = "0.1.0.dev0"`, and regenerate the root lock. Its only workspace dependency is `tuntun-contracts`; Linux/browser-control dependencies carry explicit platform markers so the universal lock imports/builds on the Intel Mac and target Linux. It never imports core, room-node, policy, or integration implementations. `[project.scripts]` owns exactly `tuntun-display-agent = tuntun_display_agent.agent:main`, with injectable `run(argv, runtime) -> int`; help/version have zero effects, `start` verifies exact effective UID and root-owned configuration before paired-key/profile/browser/network/runtime access, and health is bounded/read-only. The rendered systemd unit has `ExecStart=/opt/tuntun/current/.venv/bin/tuntun-display-agent start --config /etc/tuntun/display-agent.toml`, with root-owned `/opt/tuntun/current` resolving inside one immutable release, `User=tuntun-display`, `Group=tuntun-display`, `RuntimeDirectory=tuntun-display-agent`, a dedicated sealed state directory for only its paired key/counters, `Restart=on-failure`, bounded restart rate, and no shell, PATH lookup, `python -m`, writable executable, or inherited environment. Packaging installs `ops/display-agent/display-agent.toml.example` atomically as root-owned mode `0640` `/etc/tuntun/display-agent.toml`, replacing only an explicitly migrated managed file and preserving a locally modified file by failing closed for owner review. Task 24 deliberately creates **no final signed display service manifest** because the renderer production bundle does not exist until Task 25. The unit/config/package may be linted and exercised in a disposable image, but `manage_target_service.py` and commissioning must reject it as `service_inventory_incomplete`; `test_display_agent_service_lifecycle.py` proves no physical install or signed lifecycle receipt can be produced yet. Display agent generates its own paired receipt key, initiates outbound pinned TLS to Tuntun Core, recomputes the full manifest digest, verifies the signature over `{tuntun-display-manifest-v1, manifest_digest, complete non-content authority header}`, and validates session, exact display and renderer endpoint/binding/capability generations/evidence digests, area/audience/policy/authorization binding, explicit privacy generation, expiry, maximum duration, and quota before fetching each single-use asset and validating type/length/hash. It signs lifecycle/HDMI receipts only under `tuntun-display-receipt-v1`, with an fsync-before-sign monotonic `receipt_sequence`, the manifest `(session_id, version, digest, issued_at, expires_at)`, and exact repeated endpoint/area/privacy fields. `DisplayReceiptVerifier.verify(receipt, now)` first obtains trusted `now`, rejects a future `observed_at`, verifies the receipt domain and paired key purpose, reloads the immutable minimized `TeachingManifestAuthorityRecordV1` by the manifest triple, verifies its HMAC and manifest signature over the stored `{domain,digest,authority}`, exact-compares every repeated receipt field including manifest issue/expiry, and then reloads current endpoint/binding/capability/area/privacy authority before any state or UI write. A render must occur strictly before the stored manifest expiry; an automatic `expired` clear must occur at or after it. The manifest digest binds the absent body/components/assets while the stored authority header binds audience, memory, teaching/screen-time authorization, policies, language, duration, and timing without persisting lesson content. Missing/replaced/same-version-different-digest/retention-expired records and stale generations reject after reboot. Outside the ephemeral browser profile the agent maintains only its paired private key plus sealed, fsync-before-ack monotonic receipt/privacy counters learned from signed core control; it rejects manifests and clear requests below those counters after disconnect or reboot. Privacy on/off each advances generation; the agent persists the new generation before neutralizing output and acknowledging. A privacy, generation/evidence, re-pair, degradation, quarantine, or retirement change invalidates pending manifests before render.

- [ ] Write red tests for wrong CA/key/domain/key-purpose/display/renderer/session/manifest version/digest/issue/expiry, receipt-sequence replay, render at expiry, expired-clear one microsecond before expiry, future observed time, each independently stale endpoint/binding/capability generation or evidence digest, privacy on/off generation replay, process/host reboot with a missing/replaced/same-version-different-digest/retention-expired authority record or older text-only manifest, body tampering against the stored digest, failure before/after authority-record or monotonic counter fsync, re-pair/quarantine replay, maximum-duration overrun, expired handle, second fetch, changed asset, redirect, public/private alternate origin, browser permission, inbound listener, writable persistent profile/cache, screenshot, camera/mic, shell, extension, and crash dump. Mutate each receipt repetition individually and prove no state/UI write; prove restart verification uses no persisted lesson/component/asset body.
- [ ] Run `uv run pytest apps/display-agent/tests/test_package_bootstrap.py apps/display-agent/tests/test_service_entrypoint.py apps/display-agent/tests/test_pairing_and_manifest.py tests/integration/whole_home/test_display_agent_service_lifecycle.py tests/security/whole_home/test_display_process_boundary.py tests/privacy/whole_home/test_display_filesystem_empty.py -q`; expect missing distribution/workspace/entrypoint/service inventory and agent failures.
- [ ] Bootstrap with the foundation Python/Hatchling/version pins, merge `apps/display-agent` into the current root workspace, declare `tuntun-contracts = { workspace = true }`, add the exact side-effect-free console script above, and regenerate `uv.lock`. The permanent bootstrap test parses both TOML files, AST-scans every package import, imports the installed package, invokes `--help`/`--version` with network/filesystem/listener spies, rejects duplicate membership/forbidden dependencies or imports, and validates platform markers. The service-entrypoint test drives help/version/start/health/SIGTERM/wrong account and wrong config owner/mode; rejection must precede every key/profile/browser/network/runtime effect.
- [ ] Implement the exact dedicated systemd account/unit and root-owned config above, ephemeral Chromium profile under tmpfs, read-only root, no password manager/sync/extensions/downloads/devtools/remote debugging, camera/mic/WebRTC/geolocation/notifications/clipboard/file permissions denied, no public DNS route for lesson rendering, and one pinned local origin. Validate unit/config/wheel agreement in a disposable image, and prove production install remains blocked until Task 25 signs the complete Python-plus-renderer inventory.
- [ ] Use CSP baseline `default-src 'none'` and only the minimum hash/non-network sources needed by compiled code and in-memory blob-free assets. Do not use data URLs or service workers. Disable disk HTTP cache, browser history persistence, screenshots, screen recording, and crash upload.
- [ ] Clear keys only through device retirement, but clear every session asset/profile object on end/expiry/privacy/reboot. A disconnect never creates an owner API or offline content-browsing route.
- [ ] Fault-test start/health, crash before/after profile creation/render/clear/counter fsync, systemd restart-rate exhaustion, power loss, wrong UID, and disposable cleanup. Every restart advances boot/session epoch, neutralizes output before reconnect, deletes all ephemeral profile/assets/session state, preserves only the sealed paired key/counters, rejects old manifests/receipts, and stays safe when cleanup or health is uncertain. Missing/extra artifacts or unit/config drift block the Task 25 final packaging step.
- [ ] Run the locked package gate plus listener/filesystem/network scans in the Linux test image:

```bash
uv lock
uv sync --all-packages --locked
uv run --locked --offline --no-sync python -c 'import tuntun_display_agent; assert tuntun_display_agent.__version__ == "0.1.0.dev0"'
uv run --locked --offline --no-sync tuntun-display-agent --help
uv run --locked --offline --no-sync tuntun-display-agent --version
uv run --locked --offline --no-sync pytest apps/display-agent/tests tests/integration/whole_home/test_display_agent_service_lifecycle.py tests/security/whole_home/test_display_process_boundary.py tests/privacy/whole_home/test_display_filesystem_empty.py -q
uv run --locked --offline --no-sync ruff check apps/display-agent/src apps/display-agent/tests tests/integration/whole_home/test_display_agent_service_lifecycle.py tests/security/whole_home/test_display_process_boundary.py tests/privacy/whole_home/test_display_filesystem_empty.py
uv run --locked --offline --no-sync mypy apps/display-agent/src
systemd-analyze verify ops/display-agent/tuntun-display-agent.service
uv lock --check
uv build --offline --wheel --package tuntun-display-agent --out-dir var/build-smoke/phase4/display-agent
uv lock --check
```

- [ ] Document pairing/retirement and manual recovery in `docs/operations/phase4-display-agent.md`, then commit exact paths:

```bash
git add pyproject.toml uv.lock apps/display-agent/pyproject.toml apps/display-agent/src/tuntun_display_agent/__init__.py apps/display-agent/src/tuntun_display_agent/agent.py apps/display-agent/src/tuntun_display_agent/config.py apps/display-agent/src/tuntun_display_agent/pairing.py apps/display-agent/src/tuntun_display_agent/manifest.py apps/display-agent/src/tuntun_display_agent/assets.py apps/display-agent/src/tuntun_display_agent/clear.py apps/display-agent/src/tuntun_display_agent/hdmi.py apps/display-agent/src/tuntun_display_agent/health.py apps/display-agent/src/tuntun_display_agent/kiosk.py apps/display-agent/tests/test_package_bootstrap.py apps/display-agent/tests/test_service_entrypoint.py apps/display-agent/tests/test_pairing_and_manifest.py ops/display-agent/tuntun-display-agent.service ops/display-agent/display-agent.toml.example ops/display-agent/kiosk-policy.json ops/display-agent/firewall.example.nft scripts/phase4/pair_display.py tests/integration/whole_home/test_display_agent_service_lifecycle.py tests/security/whole_home/test_display_process_boundary.py tests/privacy/whole_home/test_display_filesystem_empty.py docs/operations/phase4-display-agent.md
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(display): pair hardened local kiosk agent"
```

### Task 25: Implement the finite renderer, asset verifier, expiry supervisor, and neutral clear

**Depends on:** Task 24 and the shared design system's display-safe primitives.
**Gate contribution:** P4-4.
**Estimated effort:** 3.5 person-days.

**Files:** Create `apps/display-agent/package.json`, `index.html`, `tsconfig.json`, `vite.config.ts`, `eslint.config.js`, `playwright.config.ts`, and `src-ui/test-setup.ts`; modify `pnpm-lock.yaml`; create `apps/display-agent/src-ui/main.tsx`, `manifest-validator.tsx`, `expiry-supervisor.tsx`, `neutral-screen.tsx`, and the nine non-conflicting closed components `components/{heading,paragraph,bullets,number-line,choice,image,lesson-timer,lesson-progress,lesson-citation}.tsx`; create `ops/services/phase4-display-agent.v1.json`; modify `scripts/phase4/manage_target_service.py` and `tests/integration/whole_home/test_display_agent_service_lifecycle.py`; create `apps/display-agent/tests/renderer.spec.tsx` and `tests/ui/e2e/display-agent-security.spec.ts`.

**Interfaces:** `renderManifest(manifest: TeachingSessionManifestV1)` dispatches only exhaustive discriminated variants. Unknown variant/version fails to the locally bundled neutral screen before any asset fetch. `ExpirySupervisor` clears at the earliest session/manifest/privacy/identity/screen-time deadline.

This task is the final service-inventory freeze. `ops/services/phase4-display-agent.v1.json` binds the Python wheel digest **and** the production renderer bundle/asset/CSP digests, exact immutable renderer install root `/opt/tuntun/current/share/tuntun-display-agent/renderer`, entry point, unit/config/kiosk/firewall digests, account/modes, runtime/sealed/ephemeral roots, health/restart policy, and complete cleanup set. The lifecycle orchestrator rejects a missing renderer digest/root or any file outside that manifest. Its installed-target test performs install/start/health/crash-restart/update/rollback/uninstall on the complete candidate and emits the signed lifecycle receipt required by Tasks 27 and 36.

The renderer is the workspace package `@tuntun/display-agent` under the foundation-owned `apps/*` glob. It owns the binaries behind every public command:

```json
{
  "name": "@tuntun/display-agent",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite --host 127.0.0.1 --port 4175",
    "lint": "eslint src-ui tests --max-warnings 0",
    "typecheck": "tsc --noEmit",
    "test": "vitest run",
    "build": "pnpm run typecheck && vite build",
    "e2e": "playwright test"
  },
  "dependencies": {"@tuntun/design-system":"workspace:*","@tuntun/ui-contracts":"workspace:*","react":"19.1.1","react-dom":"19.1.1"},
  "devDependencies": {"@axe-core/playwright":"4.10.2","@eslint/js":"9.34.0","@playwright/test":"1.55.0","@testing-library/jest-dom":"6.8.0","@testing-library/react":"16.3.0","@types/react":"19.1.10","@types/react-dom":"19.1.7","@vitejs/plugin-react":"5.0.2","eslint":"9.34.0","eslint-plugin-react-hooks":"5.2.0","eslint-plugin-react-refresh":"0.4.20","globals":"16.3.0","jsdom":"26.1.0","typescript":"5.9.2","typescript-eslint":"8.41.0","vite":"7.1.3","vitest":"3.2.4"}
}
```

Use the same strict TypeScript, flat-ESLint, Vite/Vitest jsdom, and React test-setup baseline as the admin app, scoped to `src-ui` and TS/TSX tests. `playwright.config.ts` sets `testDir: "../../tests"`, matches `**/ui/e2e/display-agent-*.spec.ts`, `**/ui/**/*display*.spec.ts`, and `**/e2e/**/*display*.spec.ts`, starts only `127.0.0.1:4175` through `pnpm run dev`, and declares one Chromium project. The app owns Playwright and axe dependencies; it must not inherit them accidentally from admin. Regenerate `pnpm-lock.yaml` after creating the workspace importer and prove a subsequent frozen install is unchanged.

- [ ] Write red component tests for all valid variants and at least 500 invalid manifests: unknown/extra field, HTML/script/event handler/style injection, URL/path/iframe/form/download, SVG script, malformed Unicode, huge text/list, asset hash/type/length/decompression failure, replay, identity downgrade, stop/privacy, and renderer restart.
- [ ] Implement each component with React text nodes and fixed design-system classes only. No `dangerouslySetInnerHTML`, runtime CSS, dynamic component name, eval/function constructor, external font/icon, or browser navigation. Multiple choice returns only a closed option index under the current session channel.
- [ ] Verify assets into bounded memory before render and revoke their handles. Enforce aggregate manifest/asset quotas before allocating/decompressing. The neutral screen contains no subject/lesson detail and is available without Mac/network.
- [ ] Add local labelled stop/pause controls, large child type, keyboard/touch reachability, reduced motion, high contrast, English/Hindi strings, and 320 px/200% zoom behavior. Stop sends a signed event but clears locally even if disconnected.
- [ ] Run `pnpm install --lockfile-only && pnpm install --frozen-lockfile && pnpm --filter @tuntun/display-agent test && pnpm --filter @tuntun/display-agent e2e -- tests/ui/e2e/display-agent-security.spec.ts && pnpm --filter @tuntun/display-agent lint && pnpm --filter @tuntun/display-agent typecheck && pnpm --filter @tuntun/display-agent build`, then run `uv run pytest tests/integration/whole_home/test_display_agent_service_lifecycle.py tests/integration/whole_home/test_phase4_target_service_lifecycle.py -q` against the signed complete manifest.
- [ ] Inspect the production bundle for forbidden network/navigation/dangerous APIs; verify and sign its complete digest/install-root inventory; stage all Task 25 files plus `ops/services/phase4-display-agent.v1.json scripts/phase4/manage_target_service.py tests/integration/whole_home/test_display_agent_service_lifecycle.py`; then commit with `git commit -m "feat(display): render finite teaching components"`.

### Task 26: Implement display lifecycle, Privacy Shield clear truth, and RAM-only learning summary

**Depends on:** Tasks 03, 23–25 and the canonical Privacy Shield effect registry.
**Gate contribution:** P4-4, privacy and memory gates.
**Estimated effort:** 3 person-days.

**Files:** Create `apps/core/src/tuntun_core/services/whole_home/{ephemeral_learning_summary,privacy_effects}.py` and `scripts/phase4/check_ephemeral_summary_imports.py`; extend `display_sessions.py`; modify the shared `p4.room_media_display` and `shared_display_projection` effect handlers, `apps/core/src/tuntun_core/bootstrap/container.py`, and `tests/integration/whole_home/test_phase4_boot_composition.py`; test `tests/unit/whole_home/test_ephemeral_learning_summary.py`, `tests/integration/whole_home/test_display_lifecycle.py`, `tests/privacy/whole_home/test_display_clear_truth.py`, and `tests/security/whole_home/test_no_learning_summary_persistence.py`.

**Interfaces:** `EphemeralLearningSummaryStore` is a process-local capped map with fake-clock expiry; it has no serialization/repository/back-up hook. `DisplaySessionService.clear` revokes asset handles first, durably commits and signs a five-second `DisplayClearRequestV1` under `tuntun-display-clear-request-v1`, sends it, and records acknowledged/unverified separately. A `cleared` receipt must repeat the exact request ID, issuer, reason, issue/expiry, commitment, current privacy generation, and manifest authority; `DisplayReceiptVerifier` reloads and verifies both immutable minimized manifest-authority record and clear request before accepting it. A renderer-local owner-stop or renderer-error creates the same bounded request shape with `issuer=renderer_local_safety`, renderer key purpose, and the same clear-request domain; no other local reason is valid. It submits `(signed_local_clear_request, signed_receipt)` through the closed renderer-to-core lifecycle ingress. Core verifies both signatures/current generations, inserts the immutable clear request, receipt inbox key, receipt sequence, and state transition atomically, then publishes only after commit; crash/retry reuses the same pair and cannot reorder it across a newer render/privacy generation. Every other clear request requires the core key purpose and already exists durably before send. The durable receipt-sequence/inbox transition makes retries idempotent and rejects an old cleared receipt after another render, request, re-pair, privacy generation, or restart. Display clear acknowledgement target is P95 ≤1 second; a missing, stale, replaced, expired, or unbound receipt never claims pixels disappeared.

- [ ] Write red tests for completion, dismissal, five-minute expiry, session end, identity downgrade, Privacy Shield, process restart, memory pressure eviction, and attempts to include free-form notes/raw child speech. For clear truth, mutate request ID/issuer/reason/issue/expiry/commitment and manifest/privacy authority individually; replay an old clear after re-render/re-pair/restart; delete or replace the stored request or manifest; use the wrong signature domain/key purpose; and cross the expiry boundary. Every case remains `unverified` with no acknowledged projection. Search DB/audit/backup/browser/display disk for a summary sentinel.
- [ ] Implement broad topic code, bounded duration bucket, and broad completion class only. Expose the end card to the current paired display for at most five minutes or until the earlier terminating event. Do not include a free-form notes field.
- [ ] A durable-learning request creates a new minimized `MemoryProposalDraft` through the Phase 1 child-memory service; it is not a conversion or copy of the cache and remains uncommitted until current `child_durable_memory_v1` consent plus exact guardian proposal approval. Raw child speech is invalid proposal content.
- [ ] On Privacy Shield, atomically revoke display authority/fetch handles with the shared privacy generation, then request clear. Show `authority_revoked`, `acknowledged`, or `unverified` independently. Independently controlled TV pixels/input may require physical action.
- [ ] Run the four tests plus `tests/integration/whole_home/test_phase4_boot_composition.py` and `uv run python scripts/phase4/check_ephemeral_summary_imports.py`. The checker permits only the service/composition root and forbids repository, migration, audit, backup, API persistence, and browser-storage imports. Expect no persistence path or manifest/composition drift.
- [ ] Stage the exact paths plus `apps/core/src/tuntun_core/bootstrap/container.py tests/integration/whole_home/test_phase4_boot_composition.py`, then commit with `git commit -m "feat(teaching): keep learning summaries ephemeral"`.

### Task 27: Add teaching setup, guardian ceremony, display status UI, and manual-HDMI acceptance

**Depends on:** Tasks 05 and 23–26, plus an accepted signed display-agent target lifecycle receipt from Task 25 for the exact host/release/service manifest.
**Gate contribution:** P4-4 and UI/physical acceptance.
**Estimated effort:** 3 person-days plus both-TV manual display checks.

**Files:** Create `apps/admin/src/features/media-learning/teaching.tsx` and `apps/admin/src/routes/media-learning-teaching.tsx`; extend `apps/core/src/tuntun_core/api/routes/teaching.py` and generated UI contracts; modify `apps/core/src/tuntun_core/api/app.py`, `apps/core/src/tuntun_core/bootstrap/container.py`, `apps/owner-ingress/src/tuntun_owner_ingress/router.py`, `ops/routes/owner-ingress-routes.v1.json`, `ops/services/phase3-owner-ingress.v1.json`, `tests/integration/whole_home/test_phase4_boot_composition.py`, `tests/integration/deploy/test_owner_ingress_route_manifest.py`, `tests/integration/vision/test_deployed_process_entrypoints.py`, `tests/integration/deploy/test_phase3_side_process_lifecycle.py`, `tests/integration/vision/test_owner_ingress_takeover.py`, and `tests/fault/vision/test_owner_ingress_takeover_rollback.py`; create `tests/ui/media-learning/teaching.spec.tsx`, `tests/ui/e2e/media-learning-teaching.spec.ts`, and `tests/hardware/whole_home/test_manual_hdmi_teaching.py`.

**Interfaces:** Owner prepares exact display session/rule; distinct current guardian uses the existing one-use local ceremony and `child_media_teaching_coapprove` for child, subject/topic pack, duration, display, canonical `web_mode=no_web` fixed and read-only for child, content policy, screen-time rule, and stop parameters. The display read model contains manifest/session policy, audience/language, HDMI readiness, expiry, and clear truth—not lesson/memory bodies.

- [ ] Write red owner/guardian distinctness, stale ceremony, cross-child/display/area/topic substitution, child self-approval, Guest personalization, absent renderer, stale HDMI, missing/mismatched target lifecycle receipt, missing clear receipt, and direct route/API tests.
- [ ] Implement setup/review/status screens with safe immutable summary, no owner authority on the shared display, and no non-owner navigation from the one-use guardian ceremony. Display the RAM-only end card as ephemeral and explain the separate durable-memory proposal.
- [ ] Add loading/empty/error/stale/degraded/privacy/manual-input states; keyboard/axe/VoiceOver; English/Hindi/mixed-script; light/dark; reduced motion; 320 px and 200% zoom.
- [ ] Run UI tests/build, `uv run pytest tests/integration/whole_home/test_phase4_boot_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py -q`, and the browser persistence scan. Rebuild the locked owner-ingress wheel, refresh/re-sign `ops/services/phase3-owner-ingress.v1.json`, and execute the complete Global Constraint 40 installed lifecycle suite; reject the Task 22 row/receipt against this teaching graph.
- [ ] Stage the UI/API/tests plus `apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json ops/services/phase3-owner-ingress.v1.json tests/integration/whole_home/test_phase4_boot_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py`, then commit with `git commit -m "feat(admin): add guarded teaching sessions"`; evidence remains ignored.
- [ ] After that commit, require a clean worktree, install and re-verify the exact Task 27 owner-ingress and display-agent rows/receipts without changing bytes, then physically connect the paired renderer to each Samsung and TCL via labelled HDMI and test manual power/input, unplug/replug, resolution/overscan, audio routing, sleep, renderer reboot, and TV restart. Do not invoke TV control. Expected: a valid lesson works on each TV while each remains `DISPLAY_ONLY_MANUAL`; no UI/audit evidence claims TV power/input control; stop/privacy neutralizes renderer at P95 ≤1 second or displays unverified with physical instructions.

**Checkpoint P4-4:** The renderer may serve one manual-input teaching surface only after closed-manifest, no-public-network, child-safety, volatile-cache, clear-truth, guardian, accessibility, and physical HDMI gates pass.

---

## Wave 4 — P4-5/P4-6 Exact Television Qualification and Real Screen-Time Enforcement

### Task 28: Inventory and separately probe both exact physical televisions

**Depends on:** Task 03, manual HDMI acceptance from Task 27, and owner authorization for read-only/local pairing probes.
**Gate contribution:** P4-5.
**Estimated effort:** 3 person-days plus physical probes.

**Files:** Create `apps/core/src/tuntun_core/services/whole_home/tv_registry.py`; create `scripts/phase4/probe_television.py`; create `fixtures/synthetic/whole-home/televisions-v1.json`; create `docs/operations/phase4-tv-qualification.md`, `docs/procurement/phase4-tv-adapters.md`, and `docs/evidence/phase4-tv-inventory.schema.json`; test `tests/unit/whole_home/test_tv_inventory.py` and `tests/hardware/whole_home/test_tv_read_only_probe.py`.

**Interfaces:** Two deployment inventory entries are required: `tv_samsung_neoled_49` and `tv_tcl_42`. Source fixtures use synthetic IDs. Each local record captures full model code, year, OS/platform, firmware, network integration/pairing, HDMI ports/CEC configuration, IR profile, Wake-on-LAN, manual-control behavior, candidate control/observation paths, and capability generation. Serial/MAC/account/pairing secrets remain encrypted deployment data.

- [ ] Write red tests proving the household description, brand, diagonal, network reachability, HDMI hotplug alone, or HA discovery leaves a TV `UNCOMMISSIONED`; only exact-unit identity plus successful manual-HDMI acceptance may promote that unit to `DISPLAY_ONLY_MANUAL`.
- [ ] Implement a read-only-first probe. Native API, CEC, IR, and observation findings are separate tri-state records: supported, unsupported, or unknown. Do not send mutations during inventory.
- [ ] Execute both exact commands from Standard Commands. Capture each unit independently; a result for one cannot populate the other. Record exact firmware/config but output only pseudonymous commitments and safe capability facts.
- [ ] Validate that any firmware/OS/pairing/network/HDMI/CEC/IR/observation change increments generation, invalidates prepared actions, and returns the unit to its last truthfully supported lower state.
- [ ] Run unit and marker-gated read-only tests. Expected: both inventory entries exist and remain `UNCOMMISSIONED` until exact-unit identity plus successful manual-HDMI evidence is committed; that evidence promotes only the matching unit to `DISPLAY_ONLY_MANUAL`, never to a control or enforcement state.
- [ ] Commit tooling/fixtures/docs/tests before physical use with `git commit -m "feat(television): inventory exact household units"`; never commit real identifiers/evidence.

### Task 29: Add signed closed television actions and independently selectable adapter implementations

**Depends on:** Tasks 01, 03, and 28 plus the accepted Phase 2 signed bridge lifecycle.
**Gate contribution:** P4-5.
**Estimated effort:** 4.5 person-days.

**Files:** Create `integrations/home-assistant/custom_components/tuntun_bridge/{television,television_schema,observations}.py`; create `apps/core/src/tuntun_core/services/whole_home/{tv_policy,tv_coordinator}.py`; create `apps/core/src/tuntun_core/adapters/television/{__init__,home_assistant,cec,ir}.py`; extend `apps/display-agent/src/tuntun_display_agent/hdmi.py` only for qualified CEC; modify and re-sign `ops/services/phase4-display-agent.v1.json`; modify `apps/core/src/tuntun_core/bootstrap/container.py`, `apps/display-agent/tests/test_package_bootstrap.py`, `tests/integration/whole_home/test_phase4_target_service_lifecycle.py`, and `tests/integration/whole_home/test_phase4_boot_composition.py`; test `tests/unit/whole_home/test_tv_policy_matrix.py`, `tests/integration/whole_home/test_signed_tv_lifecycle.py`, `tests/security/whole_home/test_tv_action_allowlist.py`, `tests/fault/whole_home/test_no_cross_protocol_spray.py`, and corresponding HA integration tests.

**Interfaces:** `TVPolicyService.authorize(...) -> AuthorizedTVRequestV1` is the only human constructor and enforces a closed risk matrix before signing: `adult_reversible_immediate` permits only desired mute/unmute and the non-committing navigation keys `home|back|up|down|left|right`; exact confirmation is required for power on/standby, exact input, every absolute volume, `select`, and every commissioned app launch; an owner passkey may satisfy those action confirmations as stronger authority and remains mandatory for separate binding/adapter/capability registration or mutation. Adults cannot use `owner_passkey`; no amount of assurance admits an uncommissioned input/app/key or another desired-state variant. `AuthorizedTVRequestV1` repeats this matrix as a defense-in-depth shape validator, so an under-assured request cannot be signed even if a caller bypasses the policy service.

`TVCoordinator.execute(AuthorizedTVRequestV1, AuthContext | EnforcementIntentV1) -> UUID` imports `EnforcementIntentV1` only from `tuntun_contracts.home.screen_time`, consumes either the canonical Phase 1 human `AuthContext` or that exact committed Phase 2 intent, recomputes and constant-time compares the request binding, and requires it to match every authorization/enforcement/TV/adapter generation before any registry/adapter read. It re-evaluates the exact risk matrix and commits `SignedTVActionV1` plus audit/outbox before I/O; the signed action repeats the request binding and fixes a reconciliation deadline in `[expires_at, expires_at + 5s]`. `system_tv_request_from_intent(intent)` is a fields-only mapping: request ID, TV endpoint and its distinct endpoint generation, control adapter, epoch/topology/binding/capability/control/authorization/enforcement/policy generations, times, idempotency key, and commitment come from the intent; actor/authorization/operation/power are fixed to `system_screen_time`/`system_enforcement`/`tv.set_power.v1`/`STANDBY`; every other desired-state field is `None`. Each adapter implements one closed operation against one compiled binding. Runtime binding selects one primary adapter per operation; optional observation is configured separately with its own observation generation. The television route reuses the same imported Phase 2 bridge-store `advance_to_dispatching_if_fresh(..., begin_after_commit_no_yield)` serialized dispatch-admission primitive required by media; it has no second or locally copied clock path and accepts no caller timestamp. Under the shared authority writer, the primitive reloads every current TV/control/gate fact, samples trusted `dispatch_started_at` only after acquiring the writer, and commits exact adapter-context/effect proof only if that sample is strictly before expiry. After `COMMIT` returns and writer release, the same call performs no await/yield/handoff, resamples trusted `actual_call_started_at`, and invokes the synchronous compiled-adapter begin capability only while that second sample is still before expiry. Crossing expiry at commit return invokes no adapter; the durable attempt-one proof remains potentially in flight and recovery never redispatches it. Adapter `TVActionDispatchReceiptV1` has no `unknown` state. Every adapter receipt carries the signed-action digest and repeats action/request/idempotency, request and authorization commitments, operation/desired state, complete authority generations, and authorization/issue/expiry/reconciliation times. Before mapper, registry, or adapter reads, the receipt verifier reloads the immutable stored signed action by digest, verifies its signature/domain, exact-compares every repeated field, and rejects `observed_at` later than trusted receiver ingress or receiver ingress after the signed reconciliation deadline. A pre-expiry dispatch may complete only within that bounded window. At or after the trusted Core deadline, `TVDispatchDeadlineFinalizer.finalize(action_id)` runs under the authority writer, reloads the exact signed action plus immutable attempt-one proof, and—only if no accepted terminal adapter receipt was durably ingested by the deadline—atomically inserts one replay-unique `TVDispatchUnknownTerminalV1` and outbox record. The terminal repeats the immutable proof/action fields, fixes `terminal_at=reconciliation_deadline`, records actual `materialized_at >= terminal_at`, and is signed only under `tuntun-tv-dispatch-unknown-terminal-v1`/`core_tv_dispatch_unknown_terminal`. Before the deadline it returns no terminal; at equality or later it returns the same durable record across restart. Late adapter evidence remains rejected and cannot replace the Core terminal. A pre-dispatch observation can never prove the action.

Adapter-receipt ingress and `TVDispatchDeadlineFinalizer` use the same authority writer. At exact deadline equality, their transaction order chooses one immutable outcome: a valid terminal adapter receipt committed first suppresses Core unknown; a Core terminal committed first makes that and every later adapter receipt ineligible. The finalizer condition means no valid terminal adapter receipt—not merely no `state="accepted"` receipt—and the uniqueness constraint prevents both branches from becoming terminal.

A cryptographically valid definitive adapter receipt that loses this deadline race is still retained once in encrypted `tv_late_dispatch_evidence` with its complete canonical signed bytes, digest, trusted ingress, terminal ID, `retained_not_authoritative` disposition, and retention deadline. It remains available for owner audit and adapter-quality analysis but is excluded from mapper/session/UI truth, cannot replace the terminal, cannot trigger observation credit, and cannot authorize redispatch. Invalid or oversized late payloads retain only bounded rejection metadata and a keyed digest.

`hdmi.py` is part of the signed `tuntun-display-agent` wheel. Therefore any Task 29 CEC change advances that wheel digest and invalidates the Task 25 service inventory plus every earlier installed-target receipt. Before any CEC probe, rebuild the locked display-agent wheel, update and re-sign `phase4.display_agent.v1` with the new wheel/HDMI digest while preserving the exact renderer bundle/install-root, unit/config/firewall/kiosk/account, runtime, and cleanup digests, then use the Task 06-owned lifecycle orchestrator to produce a fresh install/update/rollback/uninstall/verify receipt on the exact display host. The new digest also invalidates Task 27's prior display-agent/HDMI physical evidence; rerun its pairing, manual-HDMI, renderer, restart, privacy-clear, and teaching regressions from the new installed receipt before Tasks 30, 32, 35, or 36 may consume that evidence. Unchanged renderer bytes may retain their independently verified digest, but no prior whole-service receipt remains current.

```python
from tuntun_contracts.home.screen_time import EnforcementIntentV1

def system_tv_request_from_intent(intent: EnforcementIntentV1) -> AuthorizedTVRequestV1:
    return AuthorizedTVRequestV1(
        schema_version="1.0",
        request_id=intent.intent_id,
        tv_endpoint_id=intent.endpoint_id,
        endpoint_generation=intent.endpoint_generation,
        control_adapter_id=intent.control_adapter_id,
        operation="tv.set_power.v1",
        desired_power="STANDBY",
        desired_input_id=None,
        desired_volume_percent=None,
        desired_muted=None,
        desired_key=None,
        desired_app_id=None,
        actor_class="system_screen_time",
        actor_subject_id=None,
        authorization_class="system_enforcement",
        controller_epoch=intent.controller_epoch,
        topology_generation=intent.topology_generation,
        binding_generation=intent.binding_generation,
        capability_generation=intent.capability_generation,
        control_generation=intent.control_generation,
        authorization_generation=intent.authorization_generation,
        enforcement_generation=intent.enforcement_generation,
        policy_version=intent.policy_version,
        authorized_at=intent.issued_at,
        issued_at=intent.issued_at,
        expires_at=intent.expires_at,
        idempotency_key=intent.idempotency_key,
        request_binding_commitment=intent.intent_commitment,
    )
```

- [ ] Write red tests for wrong TV/adapter/operation/signature/epoch/expiry/reconciliation deadline and independently substituted endpoint, topology, binding, capability, control, observation, authorization, enforcement, or policy generation; same-ID request mutation, request/action commitment, signed-action digest, operation/desired state, idempotency, or action-time substitution; deleted/replaced stored action; system enforcement mapped to anything except standby; human actor/authorization matrix mismatch or non-null enforcement generation; and every operation × desired-state × actor × assurance combination. Prove immediate mute/non-committing navigation only, and prove immediate power/input/volume/select/app requests fail before registry/adapter reads even for an owner; adults cannot serialize owner-passkey authority. Also reject arbitrary key/code/macro/app/URI/service/entity, toggle, relative volume, smart-plug relay, caller-selected fallback, duplicate dispatch, ACK-without-effect, and every crash boundary. Use unequal-but-valid counters in positive fixtures so an accidental alias is visible. Hold the shared authority writer, queue TV dispatch, move trusted time to expiry equality and plus one microsecond before release, and require attempt-zero `expired`, no proof/begin/effect, and identical state after restart. Separately move trusted time to equality and plus one microsecond exactly as the proof `COMMIT` returns; require the attempt-one proof to remain, no synchronous begin/effect, and no redispatch after restart. Trace assertions prove the first clock sample follows writer acquisition and the second follows `COMMIT` but immediately precedes the synchronous begin callback with no await/yield. Exercise accepted/unverified/rejected/expired plus pre-dispatch and post-dispatch `error_safe` adapter state×attempt combinations, with expiry and reconciliation equality ±1 microsecond; adapter `unknown` must fail schema validation. Prove a pre-expiry adapter receipt is accepted only through trusted ingress at the signed reconciliation deadline and that receipt time or ingress one microsecond later is rejected. Drive the Core deadline finalizer at one microsecond before, equality, and one microsecond after; before returns none, while equality and later yield the same core-signed terminal with fixed logical deadline. Cover delayed network evidence, crash before terminal commit, crash after terminal/outbox commit, restart materialization after the deadline, immutable proof/action substitution, and no redispatch or late publication. Replay all four TV signed types across all other domains and wrong purposes. Remove dispatch-start/adapter-context/effect evidence individually, attach it to attempt `0`, and supply a same-generation observation sampled before dispatch start; none may yield accepted/unverified/verified truth. A failed policy, assurance, intent commitment, stored-canonical-byte, or signed-action comparison performs no topology/session/adapter read and no dispatch.
- [ ] Extend the HA receipt store with the Phase 2 timing/idempotency/quota rules, and add the Core deadline-terminal store/finalizer with a unique `action_id`, exact immutable action/proof commitments, and transactional outbox. Core signs actions only under `tuntun-tv-action-v1`/`tv_action` and unknown terminals only under `tuntun-tv-dispatch-unknown-terminal-v1`/`core_tv_dispatch_unknown_terminal`; the paired adapter signs dispatch receipts only under `tuntun-tv-dispatch-receipt-v1`/`tv_dispatch_receipt` and observations only under `tuntun-tv-observation-v1`/`tv_observation`. Each verifier checks the exact type domain and key purpose before parsing or state reads. HA native adapter translates only compiled exact desired states through system context.
- [ ] CEC adapter accepts only an owner-commissioned exact operation mapping proved for the exact HDMI topology. IR adapter accepts only hash-pinned exact-model desired-state code or minimal deterministic sequence and exposes no learn/send/raw-code method to core/model/UI.
- [ ] Rebuild `tuntun-display-agent`, update/re-sign the service row, and run `uv run --locked --offline --no-sync pytest apps/display-agent/tests/test_package_bootstrap.py apps/display-agent/tests/test_service_entrypoint.py tests/integration/whole_home/test_phase4_target_service_lifecycle.py tests/integration/whole_home/test_display_agent_service_lifecycle.py -q`, `uv build --offline --wheel --package tuntun-display-agent --out-dir var/build-smoke/phase4/display-agent-tv`, and `uv lock --check`. Prove the old wheel/receipt is rejected, the final row still binds the Task 25 renderer digest/install root, and the fresh target receipt covers update, rollback, uninstall, restart, health, and cleanup.
- [ ] `tv.send_key.v1` and `tv.launch_app.v1` remain absent unless each exact operation/state is individually proved and registered. Power is `ON|STANDBY`, input is an exact binding, volume is absolute bounded, and mute is a desired boolean.
- [ ] On primary failure, return failed/unknown and stop. Tests must prove native failure does not invoke CEC/IR, CEC failure does not invoke native/IR, and IR failure does not invoke anything else. Switching primary needs a new owner-passkey binding generation and acceptance run.
- [ ] Run narrow/HA/Phase 2 action lifecycle regressions plus `tests/integration/whole_home/test_phase4_boot_composition.py`, the Task 27 display/HDMI regressions, and the target-lifecycle suites. Expect zero arbitrary mutation, intent/request substitution, duplicate effect, fallback spray, smart-plug cut, optimistic success, stale service receipt, or manifest/composition drift.
- [ ] Stage the exact TV service/adapter/integration paths plus `apps/display-agent/src/tuntun_display_agent/hdmi.py ops/services/phase4-display-agent.v1.json apps/display-agent/tests/test_package_bootstrap.py apps/core/src/tuntun_core/bootstrap/container.py tests/integration/whole_home/test_phase4_target_service_lifecycle.py tests/integration/whole_home/test_phase4_boot_composition.py`, then commit with `git commit -m "feat(television): add signed desired-state adapters"`.

### Task 30: Qualify observation strength and promote each television only to evidenced eligibility

**Depends on:** Tasks 28–29 and any exact observation-only hardware purchase separately authorized after the probe.
**Gate contribution:** P4-5.
**Estimated effort:** 3.5 person-days plus 50/100-cycle campaigns.

**Files:** Create `apps/core/src/tuntun_core/services/whole_home/tv_eligibility.py`; create `scripts/phase4/qualify_tv_adapter.py`; create `docs/evidence/phase4-tv-qualification.schema.json`; test `tests/unit/whole_home/test_tv_eligibility.py`, `tests/property/whole_home/test_observation_strength.py`, and `tests/hardware/whole_home/test_exact_tv_adapter.py`.

**Interfaces:** `TVEligibilityService.evaluate_power(binding: TelevisionBindingV1, control_evidence, observation_evidence) -> TVPowerEligibilityV1` returns the imported canonical Phase 2 power-enforcement model and nothing else. Generic TV lifecycle/capability inventory remains in `TelevisionBindingV1`; it cannot manufacture screen-time eligibility. The evaluator can populate standby control only from the exact registered `tv.set_power.v1` binding with desired `STANDBY`, and power observation only from the exact registered `power` dimension. Strength order is not a numeric shortcut: `COMMAND_ACK_ONLY` never verifies; `MIRRORED_OPTIMISTIC` is UI hint only; `SAME_ADAPTER_OBSERVED` may qualify Cooperative after failures; `OUT_OF_BAND_OBSERVED` plus proved distinct failure domains/common-mode independence may qualify Strict.

- [ ] Write red tests for acknowledgement with no physical change, stale mirrored state, network reachability used as power, HDMI source used as viewer/playback, adapter/TV/router restart, cold boot, standby, source/manual remote change, network loss, common-mode failure, and observation sensor relay-action attempt. Prove generic input/volume/mute/key/app control, generic playback observation, and a merely `commissioned` lifecycle do not promote Phase 2 power eligibility. Substitute endpoint/binding/capability/control/observation generation or either failure-domain ID and require rejection before dispatch.
- [ ] Implement current-generation evidence evaluation with explicit source/sample/ingest/freshness. Observation-only power hardware exposes no relay capability in contracts, registry, bridge, or feature manifest.
- [ ] For each exact registered desired state, run at least 50 control/observation cycles with zero wrong operation/false verified result for Cooperative. Test native, CEC, and IR paths separately; do not combine their successes.
- [ ] For Strict, run at least 100 enforcement-observation cycles and all common-mode independence cases. One false verified-off result blocks Strict. If independence is not proved, cap at Cooperative or weaker.
- [ ] Execute separately:

```bash
TUNTUN_ALLOW_TV_PROBE=1 uv run python scripts/phase4/qualify_tv_adapter.py --inventory-id tv_samsung_neoled_49 --cycles 50 --strict-cycles 100 --evidence-root var/evidence/phase4/televisions
TUNTUN_ALLOW_TV_PROBE=1 uv run python scripts/phase4/qualify_tv_adapter.py --inventory-id tv_tcl_42 --cycles 50 --strict-cycles 100 --evidence-root var/evidence/phase4/televisions
```

- [ ] Persist and verify each unit independently across restart/restore in exactly one complete imported Phase 2 power state: `UNCOMMISSIONED`, `DISPLAY_ONLY_MANUAL`, `OBSERVE_ONLY`, `COOPERATIVE_ELIGIBLE`, `STRICT_ELIGIBLE`, `DEGRADED`, `QUARANTINED`, or `RETIRED`, coherent with generic lifecycle (`candidate`, `commissioned`, `degraded`, `quarantined`, or `retired`). A failed TV does not block the other's manual display or qualified level.
- [ ] Commit service/tooling/tests/schema before physical runs with `git commit -m "test(television): qualify control and observation strength"`; generated evidence remains ignored.

### Task 31: Bind the unchanged Phase 2 screen-time state machine to eligible real adapters

**Depends on:** Task 30 and accepted Phase 2 `screen_time` corpus/services.
**Gate contribution:** P4-6.
**Estimated effort:** 4.5 person-days.

**Files:** Create `apps/core/src/tuntun_core/services/whole_home/screen_time_adapter.py`; modify the canonical Phase 2 files `apps/core/src/tuntun_core/services/home/screen_time_enforcement.py` and `apps/core/src/tuntun_core/services/home/tv_eligibility.py` only through additive adapter injection—these are distinct from Task 30's new `apps/core/src/tuntun_core/services/whole_home/tv_eligibility.py`; modify `apps/core/src/tuntun_core/bootstrap/container.py` and `tests/integration/whole_home/test_phase4_boot_composition.py`; create `scripts/phase4/run_screen_time_adapter.py`; test `tests/integration/whole_home/test_real_screen_time_adapter.py`, `tests/property/whole_home/test_screen_time_attempt_ceiling.py`, `tests/fault/whole_home/test_no_hostile_tv_loop.py`, and `tests/hardware/whole_home/test_screen_time_physical_override.py`.

**Interfaces:** `RealScreenTimeAdapter.enforce(EnforcementIntentV1)` imports and accepts the already-authorized exact Phase 2 enforcement generation. It reloads the exact current `TVPowerEligibilityV1` alongside the generic `TelevisionBindingV1`, then revalidates child/profile, viewer/session commitment and generations, clock reconciliation/epoch, TV endpoint, primary standby-control and power-observation adapters, topology/binding/capability/control/observation/authorization/manual-override generations, mode/eligibility/strength/failure domains, attempt evidence, expiry, stored canonical bytes, and HMAC commitment; writes one attempt row; dispatches one primary desired state; evaluates fresh observation; and returns exact truth. Generic non-power capability is ignored for eligibility. `Phase2ScreenTimeTVMapper.to_control_receipt(intent, action_id, TVDispatchControlRecordV1) -> TVControlReceiptV1` accepts the closed discriminated union of an adapter `TVActionDispatchReceiptV1` or Core `TVDispatchUnknownTerminalV1` and constructs the imported Phase 2 `TVDispatchProofV1`; `.to_observation(intent, TVDispatchProofV1, WholeHomeTVObservationV1) -> TVObservationV1` requires that proof before accepting off truth. These are the only cross-contract mappings. They reject rather than default any missing/mismatched endpoint, adapter, generation, action/request correlation, time, dimension, strength, signature, or failure-domain registry fact.

The control mapper first reloads the immutable signed action by `signed_action_digest`, verifies `tuntun-tv-action-v1`/`tv_action`, parses only the closed `record_kind` union, and verifies the exact branch domain and purpose: adapter receipt under `tuntun-tv-dispatch-receipt-v1`/`tv_dispatch_receipt`, or Core deadline terminal under `tuntun-tv-dispatch-unknown-terminal-v1`/`core_tv_dispatch_unknown_terminal`. It exact-compares canonical bytes plus every record repetition and, for the Core branch, the immutable stored attempt-one proof from which the terminal was derived; failure performs no screen-time read/write. It then reconstructs Phase 2 request/idempotency/endpoint/control/attempt/window fields only from the committed intent. For either attempted branch it creates `TVDispatchProofV1` from the intent's exact request/idempotency, endpoint/generation, control adapter, shared opaque `ControllerEpoch`, topology/binding/capability/control generations, operation, desired standby state, request/session commitments, policy/mode, attempt kind/number, request window, and correlation plus the record's exact `dispatch_started_at`, `adapter_context_commitment`, and `effect_commitment`; no caller default or integer epoch conversion is permitted.

The outer imported `TVControlReceiptV1` is also a total deterministic mapping, not a partly filled projection. For an adapter branch, Core first durably records one replay-unique ingress tuple `(signed_adapter_receipt_digest, trusted_received_at)`; restart reuses it. Its `receipt_id` is UUIDv5 over the fixed namespace plus `(intent_id, action_id, signed_adapter_receipt_digest)`, and `received_at=terminal_at=trusted_received_at`, which must be at or after signed `observed_at`. For a Core terminal branch, `receipt_id` uses the signed `terminal_commitment`; `received_at=terminal_at=TVDispatchUnknownTerminalV1.terminal_at`, the Core-owned logical deadline, while the separately signed `materialized_at >= terminal_at` records delayed scheduling or crash recovery and is never substituted for Phase 2 terminal time. `adapter_receipt_commitment` is the verified P4 `evidence_commitment` only for adapter `accepted`, and is absent otherwise. For adapter ingress strictly before intent expiry, the fixed state map is: `accepted/1 -> ACCEPTED_UNVERIFIED, accepted, COMMAND_ACCEPTED`; `unverified/1 -> UNKNOWN, possibly_in_flight, OUTCOME_UNKNOWN`; `error_safe/1 -> UNKNOWN, possibly_in_flight, OUTCOME_UNKNOWN`; `rejected/0 -> FAILED, rejected, COMMAND_REJECTED`; and `error_safe/0 -> FAILED, not_dispatched, ADAPTER_ERROR_SAFE`. The Core-terminal branch alone maps to `UNKNOWN, possibly_in_flight, OUTCOME_UNKNOWN`. `expired/0 -> EXPIRED, not_dispatched, ACTION_EXPIRED` requires both the adapter observation and trusted ingress at or after intent expiry. Independently, any valid `rejected/0` or `error_safe/0` receipt first ingested at or after intent expiry maps to that same `EXPIRED/not_dispatched/ACTION_EXPIRED` outer result, because the trusted Phase 2 terminal time has crossed the no-dispatch boundary; it carries no dispatch proof/context/effect/adapter commitment. An attempted action admitted just before expiry remains attempted if its signed receipt arrives just after expiry; proof `dispatch_started_at < intent.expires_at` is the admission boundary. No record can map to `VERIFIED`, and a potentially in-flight effect can never map to `FAILED` or end a session. The observation mapper verifies `tuntun-tv-observation-v1`/`tv_observation`, accepts exactly one registered `power` dimension and, when present, one `playback` dimension, requires an exact matching dispatch proof and a power sample at or after `dispatch_started_at`, and maps raw `ON|STANDBY|OFF` to Phase 2 `on|off|off`: `STANDBY` is the exact commanded screen-time terminal state and is therefore screen-off, while `OFF` is also screen-off when independently observed. It derives Phase 2 source/failure-domain only from the current server registry and emits `truthfulness="proved"` only for the intent's currently eligible observation strength. Unknown/missing/pre-dispatch dimensions remain unknown and never prove off.

```python
from tuntun_contracts.home.screen_time import (
    EnforcementIntentV1,
    TVControlReceiptV1,
    TVDispatchProofV1,
    TVObservationV1,
    TVPowerEligibilityV1,
)
from tuntun_contracts.whole_home import television

def test_phase4_uses_phase2_types_without_duplicate_public_names() -> None:
    assert EnforcementIntentV1.__module__ == "tuntun_contracts.home.screen_time"
    assert TVControlReceiptV1.__module__ == "tuntun_contracts.home.screen_time"
    assert TVDispatchProofV1.__module__ == "tuntun_contracts.home.screen_time"
    assert TVObservationV1.__module__ == "tuntun_contracts.home.screen_time"
    assert TVPowerEligibilityV1.__module__ == "tuntun_contracts.home.screen_time"
    assert not hasattr(television, "EnforcementIntentV1")
    assert not hasattr(television, "TVControlReceiptV1")
    assert not hasattr(television, "TVDispatchProofV1")
    assert not hasattr(television, "TVObservationV1")
    assert not hasattr(television, "TVPowerEligibilityV1")

def test_adapter_records_map_to_exact_phase2_shapes_only(
    mapper, enforcement_intent, signed_action_id,
    accepted_dispatch_receipt, proved_standby_observation,
) -> None:
    control = mapper.to_control_receipt(
        enforcement_intent, signed_action_id, accepted_dispatch_receipt,
    )
    proof = control.dispatch_proof
    observation = mapper.to_observation(enforcement_intent, proof, proved_standby_observation)
    assert type(control) is TVControlReceiptV1
    assert control.outcome == "ACCEPTED_UNVERIFIED"
    assert control.request_id == enforcement_intent.intent_id
    assert control.attempt_number == enforcement_intent.attempt_number
    ingress = mapper.persisted_ingress_for(accepted_dispatch_receipt)
    assert control.receipt_id == deterministic_phase2_tv_receipt_id(
        enforcement_intent.intent_id, signed_action_id, ingress.signed_adapter_receipt_digest,
    )
    assert control.safe_code == "COMMAND_ACCEPTED"
    assert control.adapter_receipt_commitment == accepted_dispatch_receipt.evidence_commitment
    assert control.received_at == ingress.trusted_received_at
    assert control.terminal_at == ingress.trusted_received_at
    assert type(proof) is TVDispatchProofV1
    assert proof.request_id == enforcement_intent.intent_id
    assert proof.idempotency_key == enforcement_intent.idempotency_key
    assert proof.request_commitment == enforcement_intent.intent_commitment
    assert proof.session_commitment == enforcement_intent.session_commitment
    assert proof.endpoint_id == enforcement_intent.endpoint_id
    assert proof.endpoint_generation == enforcement_intent.endpoint_generation
    assert proof.control_adapter_id == enforcement_intent.control_adapter_id
    assert proof.controller_epoch == enforcement_intent.controller_epoch
    assert type(proof.controller_epoch) is type(enforcement_intent.controller_epoch)
    assert proof.topology_generation == enforcement_intent.topology_generation
    assert proof.binding_generation == enforcement_intent.binding_generation
    assert proof.capability_generation == enforcement_intent.capability_generation
    assert proof.control_generation == enforcement_intent.control_generation
    assert proof.operation == enforcement_intent.operation == "tv.set_power.v1"
    assert proof.desired_power == enforcement_intent.desired_power == "STANDBY"
    assert proof.policy_version == enforcement_intent.policy_version
    assert proof.mode == enforcement_intent.mode
    assert proof.attempt_kind == enforcement_intent.attempt_kind
    assert proof.attempt_number == enforcement_intent.attempt_number
    assert proof.requested_at == enforcement_intent.issued_at
    assert proof.expires_at == enforcement_intent.expires_at
    assert proof.correlation_id == enforcement_intent.intent_id
    assert proof.dispatch_started_at == accepted_dispatch_receipt.dispatch_started_at
    assert proof.adapter_context_commitment == accepted_dispatch_receipt.adapter_context_commitment
    assert proof.effect_commitment == accepted_dispatch_receipt.effect_commitment
    assert type(observation) is TVObservationV1
    assert observation.endpoint_id == enforcement_intent.endpoint_id
    assert observation.power_state == "off"
    assert observation.playback_state == "stopped"
    assert proved_standby_observation.sampled_at >= proof.dispatch_started_at

@pytest.mark.parametrize(("raw_power", "phase2_power"), [
    ("ON", "on"),
    ("STANDBY", "off"),
    ("OFF", "off"),
])
def test_tv_power_normalization_matches_screen_time_terminal_semantics(
    mapper, enforcement_intent, dispatch_proof, tv_power_observation, raw_power, phase2_power,
) -> None:
    observation = mapper.to_observation(
        enforcement_intent,
        dispatch_proof,
        tv_power_observation(raw_power, sampled_at=dispatch_proof.dispatch_started_at),
    )
    assert observation.power_state == phase2_power

@pytest.mark.parametrize(("state", "attempt", "outcome", "dispatch_status", "safe_code", "has_ack"), [
    ("accepted", 1, "ACCEPTED_UNVERIFIED", "accepted", "COMMAND_ACCEPTED", True),
    ("unverified", 1, "UNKNOWN", "possibly_in_flight", "OUTCOME_UNKNOWN", False),
    ("error_safe", 1, "UNKNOWN", "possibly_in_flight", "OUTCOME_UNKNOWN", False),
    ("rejected", 0, "FAILED", "rejected", "COMMAND_REJECTED", False),
    ("error_safe", 0, "FAILED", "not_dispatched", "ADAPTER_ERROR_SAFE", False),
    ("expired", 0, "EXPIRED", "not_dispatched", "ACTION_EXPIRED", False),
])
async def test_tv_control_mapping_freezes_every_outer_field_across_restart(
    mapper, enforcement_intent, signed_action_id, tv_dispatch_receipt_factory,
    state, attempt, outcome, dispatch_status, safe_code, has_ack,
) -> None:
    receipt = tv_dispatch_receipt_factory(state=state, dispatch_attempt=attempt)
    first = mapper.to_control_receipt(enforcement_intent, signed_action_id, receipt)
    restarted = await mapper.restart()
    replay = restarted.to_control_receipt(enforcement_intent, signed_action_id, receipt)
    assert replay == first
    assert (first.outcome, first.dispatch_status, first.safe_code) == (
        outcome, dispatch_status, safe_code,
    )
    assert (first.adapter_receipt_commitment is not None) is has_ack
    assert first.received_at == first.terminal_at
    assert first.receipt_id == deterministic_phase2_tv_receipt_id(
        enforcement_intent.intent_id,
        signed_action_id,
        mapper.persisted_ingress_for(receipt).signed_adapter_receipt_digest,
    )

async def test_core_unknown_terminal_maps_to_phase2_unknown_across_restart(
    mapper, enforcement_intent, signed_action_id, tv_unknown_terminal,
) -> None:
    first = mapper.to_control_receipt(
        enforcement_intent, signed_action_id, tv_unknown_terminal,
    )
    assert (first.outcome, first.dispatch_status, first.safe_code) == (
        "UNKNOWN", "possibly_in_flight", "OUTCOME_UNKNOWN",
    )
    assert first.dispatch_proof is not None
    assert first.adapter_receipt_commitment is None
    assert first.received_at == first.terminal_at == tv_unknown_terminal.terminal_at
    assert first.receipt_id == deterministic_phase2_tv_receipt_id(
        enforcement_intent.intent_id,
        signed_action_id,
        tv_unknown_terminal.terminal_commitment,
    )
    restarted = await mapper.restart()
    assert restarted.to_control_receipt(
        enforcement_intent, signed_action_id, tv_unknown_terminal,
    ) == first

@pytest.mark.parametrize("field", [
    "terminal_id", "action_id", "request_id", "idempotency_key",
    "signed_action_digest", "request_binding_commitment", "tv_endpoint_id",
    "endpoint_generation", "control_adapter_id", "operation", "desired_power",
    "dispatch_started_at", "adapter_context_commitment", "effect_commitment",
    "dispatch_proof_commitment", "controller_epoch", "topology_generation",
    "binding_generation", "capability_generation", "control_generation",
    "authorization_generation", "enforcement_generation", "policy_version",
    "authorization_commitment", "authorized_at", "issued_at", "expires_at",
    "reconciliation_deadline", "terminal_at", "materialized_at",
    "terminal_commitment", "core_key_id", "core_signature",
])
def test_core_tv_terminal_substitution_fails_before_screen_time_state_access(
    mapper, enforcement_intent, signed_action_id, tv_unknown_terminal,
    field, screen_time_repository,
) -> None:
    with pytest.raises(ScreenTimeTVMappingError):
        mapper.to_control_receipt(
            enforcement_intent,
            signed_action_id,
            substitute_valid_value(tv_unknown_terminal, field),
        )
    assert screen_time_repository.read_count == 0
    assert screen_time_repository.write_count == 0

@pytest.mark.parametrize("state", ["rejected", "error_safe"])
@pytest.mark.parametrize("ingress_delta", [timedelta(0), timedelta(microseconds=1)])
async def test_delayed_no_dispatch_tv_receipt_maps_to_expired_at_ingress_boundary(
    mapper, enforcement_intent, signed_action_id, tv_dispatch_receipt_factory,
    state, ingress_delta,
) -> None:
    deadline = enforcement_intent.expires_at
    receipt = tv_dispatch_receipt_factory(
        state=state,
        dispatch_attempt=0,
        observed_at=deadline - timedelta(microseconds=1),
    )
    trusted_ingress = deadline + ingress_delta
    mapper.clock.set(trusted_ingress)
    first = mapper.to_control_receipt(enforcement_intent, signed_action_id, receipt)
    assert (first.outcome, first.dispatch_status, first.safe_code) == (
        "EXPIRED", "not_dispatched", "ACTION_EXPIRED",
    )
    assert first.received_at == first.terminal_at == trusted_ingress
    assert first.dispatch_proof is None
    assert first.adapter_receipt_commitment is None
    restarted = await mapper.restart()
    assert restarted.to_control_receipt(
        enforcement_intent, signed_action_id, receipt,
    ) == first

async def test_tv_expired_mapping_has_exact_boundary_and_never_ends_session_as_failure(
    mapper, enforcement_intent, signed_action_id, tv_dispatch_receipt_factory,
    screen_time_session,
) -> None:
    deadline = enforcement_intent.expires_at
    for observed_at in (deadline, deadline + timedelta(microseconds=1)):
        receipt = tv_dispatch_receipt_factory(
            state="expired", dispatch_attempt=0, observed_at=observed_at,
        )
        control = mapper.to_control_receipt(enforcement_intent, signed_action_id, receipt)
        assert control.outcome == "EXPIRED"
        assert control.dispatch_status == "not_dispatched"
        assert control.dispatch_proof is None
        assert control.adapter_receipt_commitment is None
        assert await screen_time_session.apply_control_only(control) == "still_unverified_active"
    with pytest.raises((ValidationError, ScreenTimeTVMappingError)):
        mapper.to_control_receipt(
            enforcement_intent,
            signed_action_id,
            tv_dispatch_receipt_factory(
                state="expired", dispatch_attempt=0,
                observed_at=deadline - timedelta(microseconds=1),
            ),
        )

@pytest.mark.parametrize("substitution", [
    substitute_tv_endpoint,
    substitute_endpoint_generation,
    substitute_control_adapter,
    substitute_controller_epoch,
    substitute_topology_generation,
    substitute_binding_generation,
    substitute_capability_generation,
    substitute_control_generation,
    substitute_authorization_generation,
    substitute_enforcement_generation,
    substitute_policy_version,
    substitute_action_or_request_correlation,
    substitute_action_id,
    substitute_request_id,
    substitute_idempotency_key,
    substitute_signed_action_digest,
    substitute_request_binding_commitment,
    substitute_operation_or_desired_state,
    substitute_authorization_commitment,
    substitute_action_time,
    remove_dispatch_context_evidence,
])
def test_control_mapping_substitution_fails_before_screen_time_state_read_or_write(
    mapper, enforcement_intent, signed_action_id, accepted_dispatch_receipt,
    substitution, screen_time_repository,
) -> None:
    with pytest.raises(ScreenTimeTVMappingError):
        mapper.to_control_receipt(
            enforcement_intent,
            signed_action_id,
            substitution(accepted_dispatch_receipt),
        )
    assert screen_time_repository.read_count == 0
    assert screen_time_repository.write_count == 0

@pytest.mark.parametrize("model,fixture_name", (
    (SignedMediaEnvelopeV1, "signed_media_envelope_fixture"),
    (AuthorizedTVRequestV1, "authorized_tv_request_fixture"),
    (SignedTVActionV1, "signed_tv_action_fixture"),
))
def test_phase4_authority_uses_the_shared_opaque_controller_epoch(
    model, fixture_name, request, enforcement_intent,
) -> None:
    payload = request.getfixturevalue(fixture_name)
    value = model.model_validate(payload)
    assert type(value.controller_epoch) is type(enforcement_intent.controller_epoch)
    with pytest.raises(ValidationError):
        model.model_validate({**payload, "controller_epoch": 1})

@pytest.mark.parametrize("substitution", (
    substitute_tv_endpoint,
    substitute_endpoint_generation,
    substitute_control_adapter,
    substitute_controller_epoch,
    substitute_topology_generation,
    substitute_binding_generation,
    substitute_capability_generation,
    substitute_control_generation,
    remove_dispatch_context_evidence,
))
def test_dispatch_proof_substitution_cannot_authorize_observed_off(
    mapper, enforcement_intent, dispatch_proof, proved_off_observation, substitution,
    screen_time_repository,
) -> None:
    with pytest.raises(ScreenTimeTVMappingError):
        mapper.to_observation(
            enforcement_intent,
            substitution(dispatch_proof),
            proved_off_observation,
        )
    assert screen_time_repository.read_count == 0
    assert screen_time_repository.write_count == 0

@pytest.mark.parametrize("substitution", [
    substitute_tv_endpoint,
    substitute_observation_adapter,
    substitute_capability_generation,
    substitute_action_or_request_correlation,
    remove_power_dimension,
    downgrade_strict_observation_strength,
    move_sample_before_dispatch_start,
])
def test_observation_mapping_substitution_fails_before_screen_time_state_read_or_write(
    mapper, enforcement_intent, dispatch_proof, proved_off_observation, substitution,
    screen_time_repository,
) -> None:
    with pytest.raises(ScreenTimeTVMappingError):
        mapper.to_observation(
            enforcement_intent, dispatch_proof, substitution(proved_off_observation),
        )
    assert screen_time_repository.read_count == 0
    assert screen_time_repository.write_count == 0

def test_failure_domain_is_derived_from_current_registry_or_mapping_fails_closed(
    mapper_with_registry, enforcement_intent, dispatch_proof, proved_off_observation,
    current_mapping_registry, screen_time_repository,
) -> None:
    mapper = mapper_with_registry(substitute_failure_domain(current_mapping_registry))
    with pytest.raises(ScreenTimeTVMappingError):
        mapper.to_observation(enforcement_intent, dispatch_proof, proved_off_observation)
    assert screen_time_repository.read_count == 0
    assert screen_time_repository.write_count == 0
```

- [ ] Write red tests that rerun all 720 Phase 2 oracle cases unchanged and 10,000 seeded sequences with duplicate event, crash, delayed observation, restore, manual remote/button/input/renderer stop, repeated power-on, adapter failover, network flap, viewer/clock uncertainty, teaching-display ambiguity, attempt-three insertion, every intent/request/adapter-record substitution above, and a public-contract duplicate-name scan.
- [ ] Implement Advisory with no mutation; Cooperative only at current Cooperative/Strict TV eligibility; Strict only at current Strict eligibility. Unknown viewer/clock/display/control/observation enters `UNKNOWN`, debits no unobserved time, and sends no further control.
- [ ] Preserve warning/grace and exact child extension ceremony. At expiry commit the intent/outbox, then dispatch outside the writer lock. A command receipt alone cannot end a session; only adequate fresh observation may record verified ended.
- [ ] Permit one initial attempt and one qualifying re-enforcement only when fresh trustworthy evidence within two minutes shows the same authorized child session resumed and no manual override occurred. Every other contrary fact sets `MANUAL_OVERRIDE` or `UNKNOWN` and permanently closes that generation.
- [ ] Recovery never polls into a late shutdown. Restart/restore marks uncertain generations unknown, rotates epoch as required, and waits for a fresh owner/current-guardian exact re-arm. Physical remote/buttons/renderer stop are bypasses available to any holder, never adult authentication.
- [ ] Run the four suites and `uv run python scripts/phase4/run_screen_time_adapter.py --simulated --sequences 10000`. Expected: unchanged oracle results, exact Phase 2 output model identity, zero duplicate public TV-screen-time V1 names, zero invented debit/enforcement or mapping default, at most two total attempts, and zero third/delayed command.
- [ ] Run `uv run ruff check apps/core/src/tuntun_core/services/whole_home/screen_time_adapter.py apps/core/src/tuntun_core/services/home/screen_time_enforcement.py apps/core/src/tuntun_core/services/home/tv_eligibility.py apps/core/src/tuntun_core/bootstrap/container.py scripts/phase4/run_screen_time_adapter.py tests/integration/whole_home/test_phase4_boot_composition.py`, then `git add apps/core/src/tuntun_core/services/whole_home/screen_time_adapter.py apps/core/src/tuntun_core/services/home/screen_time_enforcement.py apps/core/src/tuntun_core/services/home/tv_eligibility.py apps/core/src/tuntun_core/bootstrap/container.py scripts/phase4/run_screen_time_adapter.py tests/integration/whole_home/test_phase4_boot_composition.py tests/integration/whole_home/test_real_screen_time_adapter.py tests/property/whole_home/test_screen_time_attempt_ceiling.py tests/fault/whole_home/test_no_hostile_tv_loop.py tests/hardware/whole_home/test_screen_time_physical_override.py`; no basename-only staging is permitted.
- [ ] Only after simulator pass run marker-gated physical override on each eligible exact unit. Commit code/tooling/tests before physical run with `git commit -m "feat(screen-time): bind qualified television adapters"`.

### Task 32: Add exact-TV capability, screen-time confidence, attempt, and manual-override UI

**Depends on:** Tasks 28–31 and the Phase 2 screen-time UI.
**Gate contribution:** P4-5, P4-6, UI acceptance.
**Estimated effort:** 3 person-days.

**Files:** Create `apps/admin/src/features/media-learning/televisions.tsx` and `apps/admin/src/routes/media-learning-televisions.tsx`; extend `apps/admin/src/features/home/screen-time.tsx`; create `apps/core/src/tuntun_core/api/routes/televisions.py` and Phase 4 read models; modify `apps/core/src/tuntun_core/api/app.py`, `apps/core/src/tuntun_core/bootstrap/container.py`, `apps/owner-ingress/src/tuntun_owner_ingress/router.py`, `ops/routes/owner-ingress-routes.v1.json`, `ops/services/phase3-owner-ingress.v1.json`, `tests/integration/whole_home/test_phase4_boot_composition.py`, `tests/integration/deploy/test_owner_ingress_route_manifest.py`, `tests/integration/vision/test_deployed_process_entrypoints.py`, `tests/integration/deploy/test_phase3_side_process_lifecycle.py`, `tests/integration/vision/test_owner_ingress_takeover.py`, and `tests/fault/vision/test_owner_ingress_takeover_rollback.py`; create `tests/ui/media-learning/televisions.spec.tsx` and `tests/ui/e2e/media-learning-televisions.spec.ts`.

**Interfaces:** One row per exact deployment TV shows safe household description, exact model/OS/firmware commitment, control adapter/generation, available and absent operations, observation strength/freshness, current eligibility, known bypass/manual fallback, current screen-time session/attempt count/manual override, and last failure. Secrets/serial/MAC/account/token are absent.

- [ ] Write red tests for both inventory entries, asymmetric capabilities, manual-only/observe-only/Cooperative/Strict/degraded states, stale evidence, false green from ACK, firmware invalidation, attempt count 0/1/2, manual override, unknown viewer, absent action route, and no hostile retry control.
- [ ] Implement no optimistic authoritative state. Prepare adapter selection/promotion, Strict enablement, and enforcement re-arm with exact owner passkey summaries; child rule/extension uses separate current-guardian ceremony and distinct slots.
- [ ] State explicitly that physical remote/vendor app/HDMI/manual controls may bypass Tuntun and that a physical intervention is not authenticated identity. Never label unobserved/offline as enforced.
- [ ] Run unit/e2e accessibility/localization/responsive/build suites, direct API/object-authorization tests, and `uv run pytest tests/integration/whole_home/test_phase4_boot_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py -q`. Inspect absent operation controls/chunks and unknown/disabled ingress paths.
- [ ] Expected: each Samsung/TCL unit displays only its own evidence, a degraded unit immediately shows Advisory/manual behavior, and no button/API exists for an unproved operation or third attempt.
- [ ] Rebuild the locked owner-ingress wheel, refresh/re-sign `ops/services/phase3-owner-ingress.v1.json`, and execute the complete Global Constraint 40 installed lifecycle suite. Reject the Task 27 row/receipt against this television graph before accepting P4-5/P4-6.
- [ ] Stage the exact API/generated/UI/tests plus `apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json ops/services/phase3-owner-ingress.v1.json tests/integration/whole_home/test_phase4_boot_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py`, then commit with `git commit -m "feat(admin): show truthful television enforcement"`.

**Checkpoint P4-5/P4-6:** Record an independent decision for each physical television. Manual display is a valid final result. Cooperative/Strict appears only for the exact current generation. Advisory remains available without control; no real enforcement route exists for an ineligible/degraded unit.

---

## Wave 5 — P4-7 Privacy, Recovery, Additional Rooms, Acceptance, and Maintenance

### Task 33: Complete Phase 4 Privacy Shield effects, health, backup, restore, update, and retirement

**Depends on:** every enabled service from Tasks 06–32 and the canonical Phase 1/2 lifecycle services.
**Gate contribution:** P4-7, Section 22.9.
**Estimated effort:** 3.5 person-days.

**Files:** Create `apps/core/src/tuntun_core/services/whole_home/{restore,health}.py` and complete `privacy_effects.py`; modify the exact Phase 1/2 lifecycle paths `apps/core/src/tuntun_core/services/data_lifecycle/backup_format.py`, `apps/core/src/tuntun_core/deploy/lifecycle.py`, `apps/core/src/tuntun_core/bootstrap/lifecycle.py`, `integrations/home-assistant/custom_components/tuntun_bridge/backup.py`, `integrations/home-assistant/custom_components/tuntun_bridge/store.py`, `ops/home-assistant/green-backup-catchup.example.yaml`, and `deploy/macos/{install,preflight,upgrade,rollback,uninstall}.sh`; create `ops/lifecycle/phase4-backup-manifest.v1.json`, `ops/lifecycle/phase4-update-manifest.v1.json`, and `ops/lifecycle/phase4-retirement-manifest.v1.json`; create `docs/operations/phase4-backup-restore.md` and `docs/operations/phase4-incident-retirement.md`, but modify the Task 03-owned `docs/operations/phase4-update-rollback.md`; modify `apps/core/src/tuntun_core/bootstrap/container.py` and `tests/integration/whole_home/test_phase4_boot_composition.py`; test `tests/integration/whole_home/test_phase4_privacy_shield.py`, `tests/integration/whole_home/test_phase4_restore_quarantine.py`, `tests/integration/whole_home/test_phase4_lifecycle_manifests.py`, `tests/fault/whole_home/test_phase4_update_rollback.py`, `tests/privacy/whole_home/test_phase4_backup_minimization.py`, and the exact accepted Phase 1/2 backup/update/retirement regression suites.

**Interfaces:** The existing `p4.room_media_display` effect atomically revokes room capture/display/media authority at a new privacy generation before fan-out. Per-effect states remain authority revoked, stop requested, acknowledged, physically verified, or unverified. Restore creates fresh controller/session epochs and quarantines every endpoint/media/display/TV/screen-time route until exact reconciliation.

- [ ] Write red tests at every active/commit/dispatch/receipt/clear/attempt state for Privacy Shield, Mac/Green/endpoint/renderer/player/TV restart, key/cert rotation, backup restore, rollback, disk/key failure, and device retirement.
- [ ] Implement canonical authority revocation before I/O. Cancel room leases/STT/search/LLM/TTS and Tuntun speech; call `SpeechEndpointPort.send_control` only for capture-block/indicator/stop/error-safe effects and verify each signed `PhysicalSafetyReceiptV1` against control ID, endpoint, privacy/capability generations, endpoint signature domain/key, timestamps, and requested effect before advancing that effect to acknowledged or physically verified. Hardware mute remains a local observed cancellation reason and is never an outbound control. A `SafetyTransportFailureV1` is independently core-signed, exact-request-bound, and advances only to unverified; timeout, invalid/missing receipt, or disconnect can never manufacture an endpoint signature. Request Tuntun-initiated media stop; revoke display handles and request clear. Report independently controlled/already-running music and disconnected display/TV truth as verified/unverified/unknown. Never claim prior provider egress or pixels undone.
- [ ] Backup only canonical registrations, policies, consents, immutable manifests, operation state, minimized receipts/evidence commitments, and audit. Exclude provider/TV/endpoint live credentials, raw audio/transcript/query, display assets/pixels/summary, and MA/provider history bodies. Document HA/MA backups separately.
- [ ] Restore into isolated paths, verify SQLCipher/audit/deletion tombstones, mark nonterminal actions unknown, clear admissions/leases/handles/summaries, rotate epochs, re-pair secrets, reconcile bindings, and enable one feature at a time after owner review. Restored MA/TV/room evidence is stale until re-proved.
- [ ] Update is owner-visible and hash/version pinned; pre-update backup, migration quarantine, targeted physical mute/indicator/renderer/TV/manual-override probes, and rollback are mandatory. An endpoint/renderer digest change re-quarantines only that exact binding.
- [ ] Retirement revokes certificate/keys/session/grants/bindings, stops dependent features, resets hardware where supported, clears Tuntun-managed storage, records unverifiable residual flash, and proves reconnect/replay denial.
- [ ] Run the five Phase 4 suites plus the exact Phase 1/2 backup/privacy/update/rollback/uninstall regressions. Validate that the three signed `ops/lifecycle` manifests enumerate every added metadata class and exclusion, and that restore/update/retirement consume those exact digests rather than directory discovery.
- [ ] Stage `apps/core/src/tuntun_core/services/whole_home/restore.py apps/core/src/tuntun_core/services/whole_home/health.py apps/core/src/tuntun_core/services/whole_home/privacy_effects.py apps/core/src/tuntun_core/services/data_lifecycle/backup_format.py apps/core/src/tuntun_core/deploy/lifecycle.py apps/core/src/tuntun_core/bootstrap/lifecycle.py apps/core/src/tuntun_core/bootstrap/container.py integrations/home-assistant/custom_components/tuntun_bridge/backup.py integrations/home-assistant/custom_components/tuntun_bridge/store.py ops/home-assistant/green-backup-catchup.example.yaml deploy/macos/install.sh deploy/macos/preflight.sh deploy/macos/upgrade.sh deploy/macos/rollback.sh deploy/macos/uninstall.sh ops/lifecycle/phase4-backup-manifest.v1.json ops/lifecycle/phase4-update-manifest.v1.json ops/lifecycle/phase4-retirement-manifest.v1.json docs/operations/phase4-backup-restore.md docs/operations/phase4-update-rollback.md docs/operations/phase4-incident-retirement.md tests/integration/whole_home/test_phase4_privacy_shield.py tests/integration/whole_home/test_phase4_restore_quarantine.py tests/integration/whole_home/test_phase4_lifecycle_manifests.py tests/integration/whole_home/test_phase4_boot_composition.py tests/fault/whole_home/test_phase4_update_rollback.py tests/privacy/whole_home/test_phase4_backup_minimization.py`, then commit with `git commit -m "feat(whole-home): recover and retire Phase 4 safely"`.

### Task 34: Run Phase 4 security, privacy, network, content, fault, and resource campaigns

**Depends on:** Task 33 and all enabled paths.
**Gate contribution:** P4-7, Section 22.9.
**Estimated effort:** 3.5 person-days plus controlled drills.

**Files:** Create `scripts/phase4/{run_fault_matrix,verify_network_exposure,verify_update_rollback}.py`; create `docs/evidence/phase4-fault-gate.schema.json` and `docs/operations/phase4-failure-recovery.md`; create `tests/fault/whole_home/test_phase4_fault_matrix.py`, `tests/security/whole_home/test_phase4_lateral_reachability.py`, `tests/privacy/whole_home/test_phase4_content_scan.py`, and `tests/performance/whole_home/test_phase4_resource_bounds.py`.

**Interfaces:** Fault evidence binds build/schema/policy/feature/hardware/firmware/config digests, seed, exact fault point, expected/actual terminal truth, privacy/manual fallback, resource maxima, operator, time, and expiry. It contains no payload/secret/identifier.

- [ ] Write red schema and simulator tests for every failure row in Phase 4 design Section 21 plus Mac/Green/room-node/renderer/player/TV/WAN/inner-router/power/disk/update/restore transitions.
- [ ] Implement deterministic injection before/after every durable state and external I/O boundary. Assert no self-election, stale resume, private reroute, provider fallback, cross-protocol TV spray, third screen attempt, delayed surprise command, false clear/play/TV success, or loss of physical/manual recovery.
- [ ] Scan endpoint/Mac/HA/MA/renderer/TV control listeners from inner and outer router sides and an external vantage point. No unauthenticated endpoint/debug/display/TV/MA/HA/Tuntun route, public forward, UPnP/NAT-PMP/PCP mapping, WAN admin, or remote renderer may appear.
- [ ] Attempt direct HA REST/WebSocket, MA admin/API, native TV API, CEC, IR, display, and endpoint escapes. They must yield no reusable credential and no off-registry action. Verify room/display host firewalls where actual discovery requirements allow; do not claim VLAN isolation.
- [ ] Scan source, logs, SQLite/HA stores, browser/renderer state, crashes, backups, evidence, packets, and artifacts for synthetic raw audio/transcript/biometric/memory/provider credential/TV token/display content/learning summary/catalog query/private address sentinels.
- [ ] Run:

```bash
uv run python scripts/phase4/run_fault_matrix.py --simulated --fixture fixtures/synthetic/whole-home/fault-matrix-v1.json
TUNTUN_ALLOW_PHASE4_HARDWARE=1 uv run python scripts/phase4/run_fault_matrix.py --physical --evidence-root var/evidence/phase4/fault
TUNTUN_ALLOW_PHASE4_HARDWARE=1 uv run python scripts/phase4/verify_network_exposure.py --evidence-root var/evidence/phase4/network
uv run python scripts/verify_private_data.py var/evidence/phase4
```

- [ ] Expected: all mandatory rows pass; any high/critical privacy/security failure quarantines the affected feature and blocks Phase 4 promotion. Commit tooling/schemas/tests/runbook before controlled runs with `git commit -m "test(whole-home): exercise Phase 4 failure boundaries"`.

### Task 35: Deliver room-node/voice-session/privacy UI and commission additional areas one at a time

**Depends on:** Tasks 05, 16, 22, 27, 32–34 and accepted UI Task U17, which consumes the Task 05-owned manifest-gated shells.
**Gate contribution:** P4-7 and owner-console acceptance.
**Estimated effort:** 3.5 person-days plus one seven-day soak per added area.

**Files:** Modify the Task 05/UI-U17-owned `apps/admin/src/features/media-learning/room-nodes.tsx`, `apps/admin/src/features/media-learning/phase4-health.tsx`, and `apps/admin/src/routes/media-learning-rooms.tsx`; extend `apps/admin/src/features/privacy/plane-cards.tsx` and Home/device area inventory; extend `apps/core/src/tuntun_core/api/routes/whole_home.py`; modify `apps/core/src/tuntun_core/api/app.py`, `apps/core/src/tuntun_core/bootstrap/container.py`, `apps/owner-ingress/src/tuntun_owner_ingress/router.py`, `ops/routes/owner-ingress-routes.v1.json`, `ops/services/phase3-owner-ingress.v1.json`, `tests/integration/whole_home/test_phase4_boot_composition.py`, `tests/integration/deploy/test_owner_ingress_route_manifest.py`, `tests/integration/vision/test_deployed_process_entrypoints.py`, `tests/integration/deploy/test_phase3_side_process_lifecycle.py`, `tests/integration/vision/test_owner_ingress_takeover.py`, and `tests/fault/vision/test_owner_ingress_takeover_rollback.py`; create `scripts/phase4/run_area_rollout.py`, `scripts/phase4/verify_area_rollout.py`, `docs/evidence/phase4-area-rollout.schema.json`, `tests/acceptance/whole_home/test_area_rollout_authority.py`, `tests/ui/media-learning/room-nodes.spec.tsx`, `tests/ui/e2e/media-learning-rooms.spec.ts`, and `tests/hardware/whole_home/test_area_rollout.py`.

**Interfaces:** Read models expose canonical `area_id`/safe label, class, endpoint, local wake, hardware mute, leased transmission, capture indicator, stop, firmware/model/evidence digest, privacy/consent generation, quiet hours/volume caps, bakeoff status, one active slot/winner, busy/handoff/cancellation, language, latency, and content-free health. No audio/transcript/identity confidence/memory body/private question appears. The per-area physical runner consumes a newly externally signed Phase 2 chain plus exact `FeatureAuthorityCampaignEvidenceV1` for that frozen `(area_id, area_generation, endpoint_id, endpoint_generation, placement/configuration/consent generation)` candidate; its receipt binds chain ID/digest, frozen candidate, exact generations, ordered signed-envelope and transition/restart-receipt digests, admission-sample-log digest, interval, and every canonical literal-zero counter. Every admission/background sample checks the current wall and monotonic lease; missing/invalid successor, cross-area/endpoint chain reuse, or any generation/candidate drift revokes the endpoint generation and invalidates the run rather than pausing or crediting it. `test_area_rollout_authority.py` adapts runner/verifier to the Phase 2 Task 13 shared harness, snapshots counters at each injected boundary, and proves zero post-fault pairing/capture/network/device/evidence effect plus semantic rejection.

- [ ] Write red UI/API tests for every class/state, stale/unknown facts, current slot, losing busy event, handoff, mute/indicator test, revoke/quarantine, consent status, subject/guardian exact decisions, absent private-room feature, and direct `room_id` payload/query.
- [ ] In `test_area_rollout_authority.py`, parameterize the complete shared downstream fault set. Exercise initial index-zero activation, pre-admission, post-writer-lock, rollover CAS/restart, and pre-device-I/O pause points; require barrier closure, stale-preparation invalidation, endpoint-generation revocation, zero post-fault admission/preparation/provider-call/trigger/effect delta, and verifier rejection even when a fixture claims zero expired authority.
- [ ] Implement separate truthful cards for hardware mute, local wake listening, and leased network/cloud capture. Explain that an idle indicator may be off while local wake processing is active. Privacy Shield shows independent media/display acknowledgement and recorder/manual device continuations.
- [ ] Prepare commissioning/revoke/quarantine mutations server-side. Owner passkey binds exact endpoint/`area_id`/class/policy/evidence. Adult occupants use their own subject passkeys; child-private uses distinct current guardian. No owner impersonation or batch “all rooms” enablement.
- [ ] Run UI accessibility/localization/responsive/browser-storage suites plus `uv run pytest tests/support/test_feature_authority_campaign.py tests/acceptance/whole_home/test_area_rollout_authority.py tests/integration/whole_home/test_phase4_boot_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py -q`. Direct URL/API/client bundle and owner-ingress row for private-area rollout remain absent until feature evidence is registered.
- [ ] Rebuild the locked owner-ingress wheel, refresh/re-sign `ops/services/phase3-owner-ingress.v1.json`, and execute the complete Global Constraint 40 installed lifecycle suite. Reject the Task 32 row/receipt against this area-management graph.
- [ ] Stage the UI/API/runner/schema/tests plus `apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json ops/services/phase3-owner-ingress.v1.json scripts/phase4/run_area_rollout.py scripts/phase4/verify_area_rollout.py docs/evidence/phase4-area-rollout.schema.json tests/acceptance/whole_home/test_area_rollout_authority.py tests/integration/whole_home/test_phase4_boot_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py`, then commit with `git commit -m "feat(admin): manage whole-home voice areas"`; generated per-area evidence remains ignored.
- [ ] After that commit, require an empty worktree, rebuild/install and lifecycle-verify the resolved Task 35 candidate without changing bytes, then prepare a new externally signed candidate-specific chain. Commission one additional area/endpoint generation at a time with `TUNTUN_ALLOW_PHASE4_HARDWARE=1 uv run python scripts/phase4/run_area_rollout.py --area-id AREA_ID --area-generation AREA_GENERATION --endpoint-id ENDPOINT_ID --endpoint-generation ENDPOINT_GENERATION --placement-generation PLACEMENT_GENERATION --configuration-generation CONFIGURATION_GENERATION --consent-generation CONSENT_GENERATION --feature-manifest-chain var/evidence/phase4/feature-authority/task35/AREA_ID/AREA_GENERATION/ENDPOINT_ID/ENDPOINT_GENERATION/PLACEMENT_GENERATION/CONFIGURATION_GENERATION/CONSENT_GENERATION/signed-rollover-chain.json --duration-seconds 604800 --output var/evidence/phase4/areas/AREA_ID/AREA_GENERATION/ENDPOINT_ID/ENDPOINT_GENERATION/PLACEMENT_GENERATION/CONFIGURATION_GENERATION/CONSENT_GENERATION.json`, then run `uv run python scripts/phase4/verify_area_rollout.py var/evidence/phase4/areas/AREA_ID/AREA_GENERATION/ENDPOINT_ID/ENDPOINT_GENERATION/PLACEMENT_GENERATION/CONFIGURATION_GENERATION/CONSENT_GENERATION.json --feature-manifest-chain var/evidence/phase4/feature-authority/task35/AREA_ID/AREA_GENERATION/ENDPOINT_ID/ENDPOINT_GENERATION/PLACEMENT_GENERATION/CONFIGURATION_GENERATION/CONSENT_GENERATION/signed-rollover-chain.json --require-physical --require-zero-expired-authority`. Verify placement, physical mute/stop reachability, visible indicator, quiet hours, acoustic thresholds, occupant notice/consent, child guardian binding where applicable, wrong-area/private reply corpus, network exposure, and seven elapsed days. Any generation/configuration/placement/consent change needs another chain and full run. Never commission canonical `prohibited`.
- [ ] On any failure, revoke that endpoint generation, unpair/quarantine it, retain Reachy/other accepted areas, and provide physical recovery. Do not copy a passing evidence digest from another placement.

### Task 36: Freeze Phase 4 acceptance evidence, seven-day family soak, maintenance handoff, and rollback decision

**Depends on:** Tasks 01–35, accepted UI checkpoint U5 (UI Tasks U17–U19), the accepted Phase 3 Task 32 final service-inventory freeze, and only the exact frozen candidate/hardware set covered by its complete externally pre-issued feature-manifest chain.
**Gate contribution:** final P4-7 promotion.
**Estimated effort:** 4.5 person-days plus elapsed soak and later rolling maintenance measurement.

**Files:** Create `scripts/phase4/{measure_maintenance,run_acceptance,verify_acceptance}.py`; create `docs/evidence/{phase4-acceptance,phase4-soak,phase4-maintenance}.schema.json` and `docs/operations/phase4-acceptance-runbook.md`; create `tests/acceptance/whole_home/test_phase4_acceptance_gate.py`, `test_phase4_evidence_schema.py`, `test_phase4_soak_oracles.py`, `test_phase4_feature_authority_campaign.py`, and `test_phase4_maintenance_handoff.py`; modify the Task 04-owned `tests/acceptance/whole_home/test_phase4_feature_absence.py` to cover the final installed candidate; modify and re-sign `ops/services/phase3-owner-ingress.v1.json`; modify `tests/integration/vision/test_deployed_process_entrypoints.py`, `tests/integration/deploy/test_phase3_side_process_lifecycle.py`, `tests/integration/vision/test_owner_ingress_takeover.py`, and `tests/fault/vision/test_owner_ingress_takeover_rollback.py` for the final Phase 4 owner-ingress wheel and route manifest.

**Interfaces:** Phase evidence packet uses the Program I–S evidence fields and binds exact enabled/absent features. It stores aggregate metrics/commitments only. The real-campaign schemas consume Phase 2's canonical pre-issued rollover chain and exact `FeatureAuthorityCampaignEvidenceV1`, binding its chain ID/digest, frozen candidate digest, complete ordered signed-envelope and transition/restart-receipt digests, admission-sample-log digest, applicable interval, and every literal-zero counter; neither Phase 4 runner signs, renews, substitutes, or extends authority. `test_phase4_feature_authority_campaign.py` adapts final runner/verifier to the Phase 2 Task 13 shared harness at initial index-zero activation, startup, every loop, both sides of rollover CAS, restart activation, and completion; every fault yields zero post-fault admission/preparation/provider-call/trigger/effect delta and prevents acceptance or maintenance-eligible output. It must include current verified signed target lifecycle receipts for every commissioned room-node and display-agent host, each exact-matched to the accepted `ops/services` manifest, release/wheel and any renderer digest, install root, host identity, and every service-applicable manifest-declared account/config/unit/firewall/tmpfiles/kiosk/runtime/cleanup artifact plus successful update/rollback/uninstall rehearsal. Room-node does not invent a kiosk artifact; display-agent does not invent a tmpfiles artifact. A missing, extra, stale, or mismatched declared artifact/receipt blocks soak and promotion. Because Tasks 04/05/17/22/23/27/32/35 change the P3-owned `tuntun-owner-ingress` router after the Phase 3 freeze, this task rebuilds the final locked owner-ingress wheel, preserves exact manifest ID `phase3.owner_ingress.v1`, refreshes and re-signs that canonical row with the final wheel and signed route-manifest digest, and repeats the P3 atomic takeover/start/health/restart/wrong-account/update/rollback/uninstall lifecycle before Phase 4 acceptance. It creates no parallel Phase 4 ingress service row. The Phase 4 packet binds the refreshed row and lifecycle receipt; any Phase 3-era owner-ingress digest, generic forwarding path, direct-Core listener, mixed route/wheel generation, or feature-authority gap blocks soak. `Phase4MaintenanceRecordV1` records ordinary minutes by subsystem and excluded-event class for later consumption by the single Phase 6 `FullSystemMaintenanceGate`; an eligible contribution also binds the applicable chain/candidate/steady-state generation and authority-interval evidence. Phase 4 defines no independent maintenance pass/fail gate.

- [ ] Write red evidence-schema tests requiring build/commit, feature/schema/policy/migration versions, hardware/firmware/config commitments, corpus/seed, commands/times, metrics/thresholds, fault/recovery/negative-reachability/content scan, limitations/absent features, hashes, operator/reviewer/expiry, and owner accept/reject commitment. Parameterize `test_phase4_feature_authority_campaign.py` over the complete shared authority fault set—including initial index-zero activation faults—and require zero post-fault admission/preparation/provider-call/trigger/effect delta, barrier closure, stale-preparation invalidation, semantic rejection, and zero acceptance/maintenance-eligible record.
- [ ] Aggregate Tasks 16, 20, 27, 30–31, and 34–35 without copying raw family media/identifiers/secrets. Verify minimum counts and thresholds: candidate physical safety; ≥500 arbitration; ≥1,000 routing; language/child corpus; ≥500 media adversarial; ≥500 display manifests; exact-TV 50/100 cycles as applicable; 720/10,000 screen-time; network/content/recovery results.
- [ ] Prove every omitted optional feature across package/config/environment/manifest/API/OpenAPI/prepared-action/UI bundle/runtime/listener: Music Assistant if failed, every unproved TV operation/adapter, Cooperative/Strict per unit, real screen-time per unit, private/additional room, and any second conversation.
- [ ] Before freezing the acceptance commit, build `tuntun-owner-ingress` from the final Phase 4 source, refresh/re-sign only `ops/services/phase3-owner-ingress.v1.json`, and run `uv build --offline --wheel --package tuntun-owner-ingress --out-dir var/build-smoke/phase4/owner-ingress-final`, `uv lock --check`, and `uv run --locked --offline --no-sync pytest tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/whole_home/test_phase4_boot_composition.py -q`. Rehearse atomic update, crash/restart, rollback, uninstall, and reinstall on the exact final release; retain only the signed content-safe receipt. The prior row/receipt must fail the same verifier.
- [ ] From one unchanged clean commit and one externally pre-issued canonical feature-manifest chain for that frozen candidate, run a seven-day family soak:

```bash
uv run pytest tests/support/test_feature_authority_campaign.py tests/acceptance/whole_home/test_phase4_feature_authority_campaign.py -q
TUNTUN_ALLOW_ELAPSED_PHASE4=1 uv run python scripts/phase4/run_acceptance.py household-soak --feature-manifest-chain var/evidence/phase4/feature-authority/task36/signed-rollover-chain.json --duration-seconds 604800 --sample-seconds 60 --commit "$(git rev-parse HEAD)" --evidence-root var/evidence/phase4/acceptance --output var/evidence/phase4/acceptance/household-soak.json
uv run python scripts/phase4/verify_acceptance.py var/evidence/phase4/acceptance --feature-manifest-chain var/evidence/phase4/feature-authority/task36/signed-rollover-chain.json --commit "$(git rev-parse HEAD)" --require-physical-gates --require-negative-reachability
uv run python scripts/verify_private_data.py var/evidence/phase4
```

Expected: monotonic and wall elapsed ≥604,800 seconds; the canonical same-candidate rollover chain covers the complete interval, every transition and wall/monotonic lease check passes, and the receipt records zero expired-authority interval; zero double response, wrong-area/private broadcast, unbounded retry, false media/display/TV result, silent provider/policy change, lost physical mute/remote/manual recovery, third/delayed TV attempt, persistent audio/display/summary, or post-disable route.

- [ ] Begin recording Phase 4 ordinary owner minutes by subsystem when steady household use starts; exclude initial commissioning, incidents, repairs/hardware replacement, major migrations, and scheduled quarterly restore/security/physical-safety drills as Program I–S requires. Validate record completeness and export the content-safe monthly contribution for later Phase 6 aggregation. Each steady-state generation intended for the counted 60-/90-day window uses its own newly externally signed chain at `var/evidence/phase4/feature-authority/maintenance/STEADY_STATE_GENERATION/signed-rollover-chain.json` and binds that chain/candidate/generation to the contribution; the Task 36 soak chain may be reused only when the candidate and steady-state generation are exactly unchanged. Observations across closed authority remain recorded but ineligible, and controlled recovery or any candidate/configuration mutation starts a new eligible window with a new chain.
- [ ] Treat **one to two hours/month** as the Phase 4 planning allocation only. Do not delay or declare P4-7 on a Phase 4-only maintenance threshold. Phase 6 logging may begin after 60 steady-state days, but Phase 6 alone evaluates for promotion—after at least 90 steady-state days and three complete monthly buckets—the **rolling three-month median of ordinary full-system owner maintenance at no more than eight hours/month**; three consecutive months above eight hours then freeze optional expansion and trigger simplification/retirement.
- [ ] Run `uv run pytest tests/acceptance/whole_home -q`, full affected suites, format/lint/mypy, UI/display tests/builds, contract generation, private-data scan, and `git diff --check`. Any tracked source/policy/schema/UI/integration/firmware/router/area placement/hardware change invalidates dependent evidence and restarts the affected campaign.
- [ ] Commit evidence tooling/runbook/schema/tests before the frozen run:

```bash
git add ops/services/phase3-owner-ingress.v1.json scripts/phase4/measure_maintenance.py scripts/phase4/run_acceptance.py scripts/phase4/verify_acceptance.py docs/evidence/phase4-acceptance.schema.json docs/evidence/phase4-soak.schema.json docs/evidence/phase4-maintenance.schema.json docs/operations/phase4-acceptance-runbook.md tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py tests/acceptance/whole_home
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(whole-home): freeze Phase 4 acceptance gate"
```

After that commit, rerun the complete frozen campaign from its beginning. Generated owner evidence remains ignored and is never committed.

## Dependency and Parallelization Map

```text
01 contracts → 02 fakes/corpora → 03 persistence
01/03 + accepted P3 Task 17 ingress → 04 amendments/feature absence → 05 area policy/ceremonies

01/02/04 → 06 room-node scaffold; 05/06 → 07 pairing → 08 audio lease path → 09 physical safety
07/09 + accepted P1 Reachy → 10 Reachy adapter
02/05/07/10 → 11 wake arbiter → 12 one-slot admission → 13 reply routing → 14 handoff/language
06–09 → 15 candidate adapters/tooling → 16 physical bakeoff and one common-area winner

03/04/05 → 17 provider/player/catalog → 18 media policy
17/18 + accepted P2 bridge → 19 signed HA media route
06/19 → 20 optional Music Assistant gate
03/17–19 + (20 only when selected) → 21 coordinator/reconciliation → 22 media UI

03/04/05 → 23 teaching policy/manifest
07/23 + (20 when selected, otherwise 06) → 24 paired display agent → 25 finite renderer/final service inventory
23–25 + canonical Privacy Shield/memory → 26 lifecycle/ephemeral summary → 27 teaching UI/manual HDMI

03/27 → 28 exact TV inventory → 29 signed adapters → 30 observation/eligibility
accepted P2 screen-time + 30 → 31 real adapter → 32 TV/screen-time UI

all enabled paths → 33 privacy/recovery/update/retirement → 34 security/fault/network/resource
16/22/27/32/34 → 35 area UI and one-at-a-time rollout; 35 + accepted P3 Task 32 service freeze → 36 frozen acceptance/soak/maintenance
```

Tasks 06–09, 17–18, and 23 may proceed in separate clean worktrees only after their displayed prerequisites freeze. Task 04 and every later Phase 4 owner-HTTP mutation wait for the accepted Phase 3 Task 17 owner-ingress takeover/route manifest; this shared infrastructure edge does not enable camera features. Tasks 15, 20, and 28 may gather read-only procurement/capability information in parallel, but physical mutations are serialized against the household estate. Tasks 23–27 do not wait for automated TV control; manual HDMI is the required first display path. Phase 3 and Phase 4 may otherwise run in parallel only after their separate contracts are frozen and while they do not edit the same migration head, feature registry, Privacy Shield registry, generated UI contract, owner-ingress route manifest/router, or owner-console route.

## Effort and Calendar Envelope

The mechanically normalized estimates on Tasks 01–36 sum to a **116-person-day task-point total**. That point estimate sits inside, and does not replace, the normative Phase 4 uncertainty range of **88–130 engineering person-days**, approximately **18–26 focused one-developer weeks** at five engineering days per week, after the Phase 2 bridge and screen-time simulator are stable. Task estimates are engineering effort; hardware lead time, two seven-day endpoint runs, per-area seven-day soaks, seven-day family soak, the 60-day maintenance-logging start, the minimum-90-day/three-complete-month promotion evaluation, and exact-TV investigation extend calendar time and cannot be compressed into person-days.

| Work package | Tasks | Normative person-days |
|---|---:|---:|
| Contracts, registry, simulator, policy amendments | 01–05 | 8–12 |
| Room-node firmware/agent and two-candidate bakeoff | 06–10, 15–16 | 18–26 |
| Wake arbitration, routing, handoff, multilingual endpoint integration | 11–14 | 10–15 |
| Signed media/provider/player and optional Music Assistant | 17–22 | 10–16 |
| Renderer, teaching manifests, child/display security | 23–27 | 12–18 |
| Two exact-TV probes and adapters | 28–30, 32 | 10–18 |
| Real screen-time adapter and hostile-loop evidence | 31–32 | 8–12 |
| Failure injection, security, recovery, soak, owner docs | 33–36 | 12–13 |
| **Total** | **01–36** | **116 task-point total; 88–130 normative range** |

When an individual task estimate, the 116-person-day task-point total, and this work-package envelope differ after implementation decomposition, the **88–130 normative range** controls planning. A safety/evidence gate never changes to fit the estimate.

## Hardware and Physical Gate Ledger

| Gate | Exact subject | Minimum physical evidence | Promotion | Failure/rollback |
|---|---|---|---|---|
| Endpoint candidate privacy | Purchased candidate and DIY candidate separately | Hardware-cutoff sentinel through reboot/crash/reconnect/update rollback/malicious unmute; zero egress/waveform; indicator fail-safe at every user-space layer; local stop P95 ≤250 ms | Candidate may enter acoustic bakeoff | `REJECTED_PRIVACY`; unpair and remove, no override |
| Endpoint acoustic/reliability | Same placement/corpus for each candidate | Seven elapsed days; eight-hour noise run; wake ACK P95 ≤500 ms; false reject ≤5%; ≤1 false wake/8 representative hours; ≥240 EN/HI/Hinglish accepted-quality requests, ≥95% completion; bounded CPU/RAM/thermal/queues/power | Select evidence winner; one common-area commissioning | Reject or rework exact revision, repeat complete run |
| Reachy plus winner | One common `area_id` | ≥500 duplicate-wake cases; one lease/stream/reply; ≥1,000 audience routes; physical simultaneous speakers, mute/stop, handoff, WAN/Mac restart, language switch | P4-2 voice registration | Unregister winner; Reachy remains primary |
| First media path | One entitled provider and one exact player | Catalog ambiguity, closed actions, absolute safe volume, state freshness, reboot/WAN/manual control/token revoke/entitlement expiry; no credential in Tuntun | P4-3 single-player | Disable provider/player; manual control remains |
| Optional Music Assistant | Exact MA/HA/Green/provider/player versions | Resource/storage/backup, ports/discovery/cloud, history/scrobbling, actions/queue, upgrade/rollback, credential revoke, failure truth | Register `phase4.music_assistant.v1` | Package/config/API/UI/runtime route absent |
| Manual teaching renderer | One paired renderer, each physical TV via HDMI | 500 manifest cases; zero public request in child lesson; no open browser; clear P95 ≤1 s or unverified truth; unplug/overscan/audio/sleep/restarts | P4-4, TVs still manual | Unpair renderer; voice-only/owner-console teaching |
| Samsung exact TV | `tv_samsung_neoled_49` current model/firmware/config | Independent native/CEC/IR probes; ≥50 cycles per registered desired state for Cooperative; ≥100 and common-mode independence for Strict | Strongest proved state only | Degrade to last truthful state/manual; no fallback spraying |
| TCL exact TV | `tv_tcl_42` current model/firmware/config | Same independent gates; never infer platform from brand/size | Strongest proved state only | Same independent degradation |
| Real screen time | Each exact eligible TV separately | Unchanged 720 oracle + 10,000 sequences; warning/grace/extension; viewer/clock uncertainty; physical remote/button/input/renderer stop; crash/restart/restore/network; ≤2 attempts | Per-unit Cooperative/Strict adapter | Advisory/manual; route absent until fresh re-arm/evidence |
| Additional area | One exact endpoint placement at a time | Correct class/consents, mute/stop access, visible indicator, acoustic/routing/privacy/network, quiet hours, seven-day soak | Register exact area/endpoint generation | Revoke/unpair that endpoint only |

No hardware order is authorized by this plan. Purchase sequence remains: exact dated quotes/return terms → one purchased/DIY endpoint bakeoff → manual HDMI pilot → only the adapter/sensor that closes a measured exact-TV gap → additional winner endpoints one area at a time.

## Rollback and Quarantine Matrix

| Trigger | Immediate deterministic action | Preserved fallback | Re-entry requirement |
|---|---|---|---|
| Endpoint mute/indicator/supervisor uncertainty | Revoke egress permit/lease, clear buffers, `ERROR_SAFE`, quarantine binding | Physical mute/stop; Reachy or other accepted endpoint | Exact physical safety gate rerun on current digest |
| Endpoint firmware/model/wake/VAD/audio/placement change | Increment capability/privacy generation, cancel leases, unpair from production arbitration | Local muted state; other endpoints | Owner review plus affected privacy/acoustic/update campaign |
| Area class/occupant/guardian/consent change | Increment privacy generation, block next claim, cancel active capture at authoritative time | Physical mute and other approved areas | New exact owner/subject/guardian ceremony |
| Arbiter/core restart | Cancel every lease/admission; reject late frames/playback; require new wake | Local endpoint safety, fixed status/offline grammar if separately eligible | Fresh session epoch and health |
| HA/MA/provider/player failure or expiry | Stop new media action; report exact unavailable/unknown; no alternate source | Manual player/provider controls, voice Q&A | Current entitlement/binding/state/volume and gate |
| Display validation/clear failure | Revoke handles; neutral clear locally if possible; report unverified | Voice-only/owner console; manual TV input/power | Pairing/current digest plus manifest/clear gate |
| TV firmware/API/CEC/IR/observation change | Invalidate capability generation/actions; stop mutations/enforcement; degrade | `DISPLAY_ONLY_MANUAL` or last supported observation; ordinary remote | Fresh exact adapter cycles and owner promotion |
| TV primary action failure | Record failed/unknown; no other protocol call | Manual remote; teaching manifest may remain ready | Owner-selected new binding generation and full gate |
| Screen-time uncertainty/manual intervention | `UNKNOWN`/`MANUAL_OVERRIDE`; terminate generation; prevent third/delayed command | Advisory warnings and manual guardian action | Fresh exact owner/current-guardian authenticated re-arm |
| Privacy Shield | Revoke authority first; request room/media/display stop; show downstream truth separately | Physical mute/stop/remotes; independent systems disclosed | Owner passkey off ceremony; each feature revalidates |
| Backup restore/update rollback | Fresh epochs, clear ephemeral state, quarantine all external effects | Read-only local recovery and manual devices | Integrity/deletion reconciliation, re-pair, owner one-by-one enable |
| Future Phase 6 full-system maintenance gate breach | Freeze optional expansion after the specified three consecutive months | Mandatory accepted subset and manual paths | Simplification/retirement and full-system gate recovery |

Rollback never sends a compensating toggle, alternate provider/protocol, broad group stop, smart-plug mains cut, or stale action replay. Uncertainty is preserved for reconciliation or ends the operation.

## Negative-Reachability Acceptance Matrix

Every row must fail at package/install registration, configuration/environment parsing, signed feature manifest, API/OpenAPI, prepared-action issuance, UI navigation/direct URL/client bundle, IPC/network listener, and runtime dispatch as applicable.

| Forbidden/conditional capability | Required proof of absence |
|---|---|
| Parallel `room_id` location model | Exact-source/schema/migration/OpenAPI/generated-client/fixture/SQL/UI scan has zero key/field/table/alias/mapping; payload/query attempts reject |
| Second active conversation | No feature/config/UI/API; compiled capacity 1; slot 1 and simultaneous transaction tests deny before egress; no two-session package ID |
| Passive follow-me/broadcast | No ambient tracking subscription or route; handoff requires exact token/new wake; private reply rejects groups/other endpoints |
| Pre-wake/loser/ambient audio egress or durability | Packet/file/swap-aware/log/crash/backup scans; lease/generation/sequence tests; no storage column/path |
| Software unmute or capture without indicator | No command/voice/API method; malicious call denies; safety supervisor owns send capability; indicator failure produces zero frame |
| Endpoint identity/policy/memory/provider/HA/MA authority | Dependency/import/secret/route scans; stolen endpoint cannot access any such data/service |
| Microphone in canonical `prohibited` area | Commissioning/API/fixture/feature tests reject; network inventory finds zero endpoint; legacy `prohibited_sensitive`/`temporary_guest` classes reject |
| General HA/MA token/API/service/entity/admin | No credential/config field; direct routes deny; arbitrary service/entity/provider/URI inputs reject |
| Unentitled/expired/unclear media provider | Feature/provider binding disabled; no silent substitute; catalog/action route denies |
| Arbitrary media URL/URI/path/redirect/queue/account | Contract/parser/fetch tests produce zero DNS/network/file access and zero playback |
| Dynamic/wildcard player group or private speech group | Immutable enumerated members only; wildcard/all-area queries reject; reply router cannot target group |
| Open browser/display markup/network | Manifest schema rejects; CSP/process/network scan; no HTML/JS/CSS/SVG script/URL/path/iframe/form/download/WebRTC/permission |
| Durable display pixels/assets/learning summary | DB/schema/audit/history/backup/browser/disk/crash scans; RAM fake-clock expiry; no repository port |
| Child live web or silent durable learning memory | Child web route absent; only separate minimized Phase 1 proposal with current guardian approval can persist |
| Assumed TV control from description/discovery/ACK | Both start manual; promotion needs exact cycles; ACK-only never verifies |
| Arbitrary TV key/code/macro/app/service or smart-plug relay | Closed enum/compiled binding; action/provider/bridge/direct API tests; observation relay absent |
| Runtime cross-protocol retry/spraying | Fault tests assert exactly one primary adapter call per action |
| Viewer/educational inference from TV/area/input/programme/camera | No contract/field/service; screen-time tests enter unknown rather than debit/enforce |
| Third/delayed screen-time attempt | DB constraint, state machine/property/restart/restore/network/manual tests; no background delayed poll |
| Unproved Music Assistant/TV/Strict/private-room feature | Signed manifest/route/config/UI/bundle/runtime absent for each failed gate |
| Public/outer/WAN/debug/remote display route | Router mapping/listener/outer/external scans and endpoint/display host firewall probes |

## Requirements Traceability

| Phase 4 requirement | Primary tasks |
|---|---|
| Canonical `area_id` and no `room_id` | 01, 03, 05, 28, 35–36 |
| One active conversation and later concurrency absent | 01–04, 11–13, 16, 36 |
| Purchased-versus-DIY room endpoint | 06–09, 15–16 |
| Physical mute, capture indicator, local stop | 06, 08–09, 16, 33–36 |
| Metadata-only wake, lease, duplicate arbitration | 01–03, 07–08, 11–12, 16 |
| Same-endpoint private reply, busy, explicit handoff | 10, 13–14, 16 |
| English/Hindi/Hinglish following | 10, 14, 16, 35–36 |
| Room class, adult subject, child guardian ceremonies | 05, 18, 27, 35 |
| Legal media, opaque handles, exact policy | 17–18 |
| Signed HA bridge, media lifecycle, truthful result | 19, 21 |
| Music Assistant optional positive/absence gate | 04, 20, 22, 36 |
| Player safe volume and immutable groups | 18, 21–22 |
| Signed closed display renderer | 23–25 |
| Child teaching, no live web, manual HDMI | 23, 27 |
| Ephemeral five-minute learning summary and separate memory proposal | 26–27, 33, 36 |
| Samsung Neo LED 49 and TCL 42 exact-unit truth | 28, 30, 32, 36 |
| Native/CEC/IR separate, no fallback spraying | 29–30, 34, 36 |
| Explicit observation strength and degradation | 28–30, 32–34 |
| Unchanged Phase 2 screen-time semantics and real adapter | 03, 18, 27, 31–32 |
| Two-attempt ceiling, physical/manual override | 29–32, 34, 36 |
| Privacy Shield independent truth | 09, 26, 33, 35–36 |
| LAN-only/no raw retention/credential minimization | 07–09, 17, 19–20, 24–26, 33–36 |
| Backup/restore/update/retirement and failure behavior | 03, 19, 21, 29, 31, 33–34 |
| Accessibility/localization/truthful owner UI | 22, 25, 27, 32, 35 |
| Seven-day soak and Phase 6 full-system maintenance handoff | 16, 35–36 |

## Final Phase 4 Go/No-Go Checklist

- [ ] Phase 1 `FB0` and every consumed Phase 1 identity/policy/auth/memory/privacy/audit/edge contract are current; Phase 2 signed bridge/topology/action/screen-time simulator contracts and evidence are current.
- [ ] All five Phase 4 amendments, contract/schema/migration/UI generations, feature manifest, policy corpora, and evidence digests agree.
- [ ] Source, schema, migration, OpenAPI, generated client, fixtures, SQL, configuration, and UI contain canonical `area_id` only; no `room_id` compatibility path exists.
- [ ] Exactly one active conversation can be admitted; a second endpoint gets neutral busy behavior; no two-session configuration, API, UI, package registration, or runtime path exists.
- [ ] One selected common-room endpoint has passed P4-1/P4-2 with Reachy; `NO_ELIGIBLE_CANDIDATE` is a safe stop and learning result, never Phase 4 acceptance or permission to enter later phases.
- [ ] Reachy and the selected common-area endpoint pass duplicate arbitration, lease/media bounds, wrong-area/private reply, cancellation, restart, handoff, and English/Hindi/Hinglish gates.
- [ ] The selected purchased/DIY exact endpoint passes physical hardware mute, truthful capture indicator, local stop, no-durable-audio, seven-day/eight-hour acoustic/reliability, update/rollback, power, and SBOM/licence gates; its owner-maintenance time is measured and disclosed for the later full-system gate.
- [ ] Every enabled area has current owner/occupant/guardian consent and privacy generations; canonical `prohibited` has zero endpoint; private/additional areas have independent placement/soak evidence.
- [ ] One entitled provider/player passes closed catalog/action, safe absolute volume, truthful observation/result, manual control, expiry/revocation, reboot/WAN, credential minimization, and no-fallback gates.
- [ ] Music Assistant either passes its complete exact Green/provider/player/credential/history/backup/update gate or is absent at every surface.
- [ ] Adult/child/Guest/anonymous media and teaching policies match exact confirmation/passkey/distinct-guardian rules; no purchase, unknown/explicit child content, broad group, account, or persistent child authority leaks.
- [ ] Paired display accepts only signed closed components/hash assets, makes zero public request in child lessons, retains no screenshot/content/history, clears truthfully, works by manual HDMI on both TVs, and passes accessibility/localization.
- [ ] Ephemeral learning summary lasts at most five minutes and is absent from DB/audit/history/backup/corpus/browser/disk; any durable child note uses the separate Phase 1 guardian-approved proposal.
- [ ] Both `tv_samsung_neoled_49` and `tv_tcl_42` have exact current model/OS/firmware/port/control/observation/manual evidence and show only their independently proved state.
- [ ] Native, CEC, and IR paths are individually qualified; runtime uses exactly one primary path; arbitrary operations and cross-protocol spraying are unreachable; manual remote/buttons always win.
- [ ] Real screen-time reruns the unchanged 720 oracle and 10,000 sequence corpus, never infers viewer/education, stops on uncertainty/manual action, never exceeds two attempts, and has no delayed surprise command.
- [ ] Privacy Shield revokes room/media/display authority canonically and reports stop/acknowledgement/physical truth separately; independent music/TV/manual systems and prior egress are not overstated.
- [ ] Mac/Green/endpoint/renderer/player/TV/WAN/router/power/disk/update/restore failures, key/cert rotation, backup/restore quarantine, retirement, and no-unsafe-replay gates pass.
- [ ] Inner/outer/external scans show no public/forwarded/debug/direct HA/MA/TV/display/endpoint escape route and no unapproved router mapping.
- [ ] Source/log/browser/renderer/SQLite/HA/MA/backup/crash/evidence/packet scans contain no forbidden content, credential, household identifier, or private network value.
- [ ] Every failed/omitted optional feature passes package/config/environment/manifest/API/OpenAPI/prepared-action/UI bundle/runtime/listener negative reachability.
- [ ] Seven elapsed household-soak days pass on one unchanged commit/manifest with zero double response, private broadcast, false result, unbounded retry, hostile TV loop, silent policy/provider change, or lost physical/manual recovery.
- [ ] Phase 4 ordinary owner time is recorded by subsystem against the one-to-two-hour planning allocation and handed to Phase 6; P4-7 has no separate maintenance pass/fail threshold. Phase 6 logging may begin after 60 steady-state days, but promotion evaluation of the rolling three-month full-system median ≤8 hours/month requires at least 90 steady-state days and three complete monthly buckets.
- [ ] Owner records exact accepted, degraded/manual, quarantined, and absent features. Phase 4 promotion does not claim Phase 5/6, two-conversation, public remote, NAS, or open-source whole-program release readiness.

## Implementation Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-27-tuntun-phase4-voice-media-displays-execution.md`.

Execute Tasks 01–36 with `superpowers:subagent-driven-development` for fresh bounded task workers and review, or `superpowers:executing-plans` for checkpointed inline batches. Stop at P4-E0/P4-0, P4-1/P4-2, P4-3, P4-4, P4-5/P4-6, and final P4-7. Start no room capture, media, renderer, TV mutation, real enforcement, or private-area rollout before its exact positive gate. Conditional manual/absent outcomes are valid only for independently optional TV, additional/private-room, second-slot, or other explicitly optional features after the mandatory common-room endpoint exit passes; weaker hidden paths are not.
