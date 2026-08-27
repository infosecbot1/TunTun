# Tuntun Phase 4 Whole-Home Voice, Media, and Displays Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver one safe household conversation across Reachy and evidence-winning room speech endpoints, deterministic entitled media, a signed closed teaching renderer, exact-unit television qualification for the household's Samsung Neo LED 49-inch and TCL 42-inch televisions, and real screen-time enforcement only at the strength each exact television proves.

**Architecture:** Extend the Phase 1 Mac modular monolith and the Phase 2 topology/signed Home Assistant boundary. Every room endpoint performs wake/VAD locally, obtains a single-use capture lease before post-wake audio leaves, and has locally authoritative physical mute, capture indication, and stop. The Mac remains the sole identity, policy, consent, memory, budget, conversation, media, teaching, and screen-time authority. Home Assistant and optionally Music Assistant receive only signed closed media/TV operations. A paired local HDMI/browser agent accepts only signed, audience-bound components and volatile hashed assets. Both televisions begin as `DISPLAY_ONLY_MANUAL` and gain no control or enforcement route until exact control and observation evidence passes.

**Tech Stack:** Python 3.12, `asyncio`, Pydantic v2, SQLAlchemy 2/Alembic over SQLCipher, FastAPI, paired mTLS WebSockets, Ed25519 endpoint events, the existing Secure Enclave-backed P-256 Home Assistant signer, RFC 8785/JCS, JSON Schema 2020-12; local wake/VAD and audio backends behind ports; Home Assistant Core custom-integration APIs; optional official Music Assistant integration; a Linux kiosk agent with Chromium, React 19/TypeScript/Vite, strict CSP and hash-checked assets; optional libCEC and bounded IR adapters behind exact TV ports; pytest, pytest-asyncio, Hypothesis, Ruff, strict mypy, Vitest, Testing Library, Playwright, axe, packet/content scanners, and owner-gated hardware/fault/elapsed campaigns.

**Normative design:** [Phase 4 Whole-Home Voice, Media, and Displays](../specs/2026-08-27-tuntun-phase4-voice-media-displays-design.md), [Program A–H](../specs/2026-08-27-tuntun-program-architecture-a-h.md), [Program I–S](../specs/2026-08-27-tuntun-program-assurance-delivery-i-s.md), [Six-Phase UI/UX](../specs/2026-08-27-tuntun-six-phase-ui-ux-design.md), and [Six-Phase Master Roadmap](./2026-08-27-tuntun-six-phase-master-roadmap.md).

## Authority and Upstream Reconciliation

1. The Phase 4 design controls Phase 4 behavior, gates, thresholds, and conditional absence. Program A–H controls shared composition/contracts; Program I–S controls repository, assurance, evidence, operations, procurement, and maintenance; UI/UX controls truthful read models, ceremonies, accessibility, and feature registration.
2. Phase 4 household activation requires the accepted Phase 1 `FB0` services it consumes and a stable accepted Phase 2 signed bridge, topology registry, transaction/outbox lifecycle, subject/guardian ceremonies, and screen-time simulator. Phase-1-only `P1R0/P1R1` and Phase 3 camera features are not Phase 4 entry gates.
3. The current Phase 3 plan reserves canonical migrations `0013`–`0015`. This plan reserves `0016`–`0019`. Phase 4 simulator, endpoint, and renderer work may proceed in parallel with Phase 3, but migration merge/rebase must preserve one Alembic head before Task 03 closes.
4. Register `whole_home_single_session_v1`, `home_reversible_media_v1`, `child_guarded_media_v1`, `guarded_teaching_display_v1`, and `screen_time_real_adapter_v1` before the matching production feature is registered. These are exact amendments, not broad role grants.
5. `area_id` is the sole room/location identifier in every contract, migration, API, fixture, generated client, renderer manifest, audit commitment, and adapter binding. A `zone_id` is an optional stable versioned child of exactly one `area_id`. There is no `room_id` field, table, alias, mapping, compatibility adapter, or migration.
6. Extend the existing Phase 1 edge/session and Phase 2 Home Assistant/screen-time interfaces. Do not create a second identity engine, policy engine, subject ceremony, topology registry, action lifecycle, or screen-time state machine.
7. The browser, room endpoint, display agent, television, Home Assistant, and Music Assistant are untrusted presenters/adapters. None can construct actor authority, guardian consent, memory audience, an action binding, or an enforcement decision.
8. If any plan instruction appears less restrictive than a normative design, stop and reconcile the design, contract, policy corpus, migration, generated client, feature manifest, tests, and documentation together before implementing.

## Global Constraints

1. `household_conversation_slots` is compiled to exactly `1` for this release. There is no setting, environment variable, owner API, UI control, or adapter command that raises it. Attempts to configure or admit `2` fail before capture/provider work. A future two-slot feature needs the separate Phase 4 Section 22.8 design gate and a new reviewed contract.
2. Every Phase 4 wire and persistence model uses `area_id` only. Property tests scan source, schemas, migrations, generated clients, fixtures, OpenAPI, SQL, UI bundles, and configuration for forbidden `room_id`.
3. Local wake and VAD run on each commissioned speech endpoint. Only bounded three-to-five-second pre-roll exists, in endpoint RAM. No always-on room audio, pre-wake sample, losing candidate buffer, voice embedding, fine-grained acoustic feature, or ambient transcript reaches the Mac, Home Assistant, Music Assistant, a television, a provider, or durable storage.
4. A metadata-only wake claim precedes arbitration. Post-wake audio cannot leave until a current signed `CaptureLeaseV1` binds the winning claim, endpoint, `area_id`, turn, session epoch, privacy/capability generations, duration/byte quota, and the one household slot.
5. Endpoint capture retains the Phase 1 maximum of 90 seconds or 8 MiB per turn, whichever closes first. Bounded queues cancel on congestion rather than accumulating late audio or replies.
6. A real physical microphone cutoff is locally authoritative. Software and voice cannot unmute it. A visible capture indicator is active before the first leased frame may leave and remains truthful through the complete egress interval. Mute/indicator/supervisor uncertainty closes the network audio path and sets `ERROR_SAFE`.
7. Local stop/privacy remains available without Mac, Home Assistant, or WAN. Recognized stop/privacy blocks new media egress and stops local Tuntun playback at P95 no more than 250 ms. Privacy Shield revokes all room capture leases and signed display fetch handles through the shared canonical privacy generation.
8. Room classes are closed: `common_shared`, `adult_private`, `child_private`, `temporary_guest`, and `prohibited_sensitive`. No speech endpoint can be commissioned in `prohibited_sensitive`. Adult-private enablement requires every recorded adult occupant's current subject consent. Child-private enablement requires owner configuration and a distinct current-primary-guardian exact approval for the same child/area/endpoint/policy generations.
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
19. A new catalog item/provider, material volume change, transfer, immutable group, persistent queue/routine, account, or policy change requires the specified stronger confirmation/passkey. Child playback requires exact owner-configured and distinct-guardian-approved area/player/provider/content/volume/hour generations. Unknown/explicit content denies unless a guardian-selected exact handle is allowed.
20. A player must expose fresh trustworthy state and safe absolute starting volume before Tuntun may start it. Results remain `VERIFIED_PLAYING`, `ACCEPTED_UNVERIFIED`, `PARTIAL`, `FAILED`, or `UNKNOWN`. No automatic provider/protocol fallback or blind retry is permitted.
21. Music Assistant is optional. Until its exact Home Assistant application/integration, Green resource/backup, one provider/player, ports/discovery, history/scrobbling, upgrade/rollback, credential revocation, and failure gates pass, every Tuntun MA package registration, configuration route, API route, UI control, and runtime call is absent.
22. A teaching display is a paired local browser/HDMI agent using pinned TLS, a locked kiosk origin, and a signed closed manifest. It receives no general HTML, CSS, JavaScript, SVG script, iframe, URL, path, form, download, WebRTC, browser permission, prompt, memory store, credential, shell, camera, or microphone.
23. Display text/assets pass identity audience, child safety, DLP, provenance, type, size, decompression, hash, session, policy, binding, generation, and expiry validation. A child lesson performs zero live web request. A TV receives pixels and bounded desired-state control only; it never receives family memory or supplies identity.
24. Teaching session assets and the end-card learning summary are RAM-only. The broad topic/duration/completion summary expires at the earliest of five minutes, dismissal, Privacy Shield, or session end policy and is absent from SQL, audit, history, backups, corpus, logs, screenshots, and browser persistence. A durable note can be created only as a separately minimized Phase 1 child-memory proposal awaiting exact current-guardian approval.
25. Both `tv_samsung_neoled_49` (“Samsung Neo LED 49-inch”) and `tv_tcl_42` (“TCL 42-inch”) begin `DISPLAY_ONLY_MANUAL`. Their household descriptions prove no model, OS, firmware, API, CEC, IR, Wake-on-LAN, app, source, power, volume, or observation capability.
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
│   ├── manifest-validator.ts
│   ├── expiry-supervisor.ts
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
├── tuntun_ma_adapter/
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
ops/display-agent/
ops/whole-home/
docs/operations/phase4-*.md
docs/privacy/phase4-*.md
docs/procurement/phase4-*.md
docs/evidence/phase4-*.schema.json
tests/{unit,contract,property,integration,security,privacy,ui,fault,performance,hardware,acceptance}/whole_home/
```

## Frozen Contract and Port Baseline

The strict public models are frozen Pydantic models with `extra="forbid"`, immutable nested collections, NFC text, aware six-fraction UTC timestamps, bounded sizes, and explicit `schema_version`. Signed objects use their own signature domain; a signature is never valid across domains.

### Speech contracts

- `SpeechEndpointRegistrationV1`: `endpoint_id`, `area_id`, room class, exact pseudonymous hardware/firmware/wake/VAD/audio/mute/indicator/stop evidence digests, protocol version, privacy/capability generations, and lifecycle state.
- `WakeClaimV1`: metadata-only Phase 4 claim fields; no audio, embedding, fine acoustic vector, subject, identity, or memory field.
- `CaptureLeaseV1`: claim/endpoint/area/turn/slot/session-epoch/privacy/capability/format/quota/time binding and Mac signature.
- `SpeechFrameV1`: lease/stream/turn, monotonic sequence/time, exact format/duration/length, and bytes under remaining lease quota.
- `WakeArbitrationV1`: deterministic winner, loser endpoint IDs, decision reason, decision/correlation windows, and one cancellation generation.
- `EndpointHealthV1` and `PhysicalSafetyReceiptV1`: separate hardware mute, local wake, leased egress, indicator, stop, queues, clock, model hashes, thermal, and error-safe facts.
- `HandoffTokenV1`: current endpoint/area, exact target endpoint/area, source turn, privacy/policy generations, 30-second maximum expiry, single-use commitment, and no auth grant.

```python
class SpeechAudioFormatV1(WholeHomeContract):
    sample_rate_hz: Literal[16_000, 24_000, 48_000]
    channels: Literal[1]
    sample_format: Literal["pcm_s16le"]
    frame_duration_ms: Literal[10, 20, 30, 40, 50, 100, 200]

class SpeechEndpointRegistrationV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    endpoint_id: StableEndpointId
    area_id: StableHomeId
    room_class: Literal[
        "common_shared", "adult_private", "child_private", "temporary_guest",
        "prohibited_sensitive",
    ]
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
        if self.room_class == "prohibited_sensitive" and self.lifecycle_state == "commissioned":
            raise ValueError("sensitive_area_endpoint_cannot_be_commissioned")
        return self

class CaptureLeaseV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    lease_id: UUID
    claim_id: UUID
    endpoint_id: StableEndpointId
    area_id: StableHomeId
    conversation_id: UUID
    turn_id: UUID
    household_slot: Literal[1]
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
    target_endpoint_id: StableEndpointId
    target_area_id: StableHomeId
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
    control: Literal["hardware_mute", "privacy_indicator", "stop_playback", "enter_error_safe"]
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
    control: Literal["hardware_mute", "privacy_indicator", "stop_playback", "enter_error_safe"]
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

class WakeArbitrationV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    arbitration_id: UUID
    state: Literal["winner", "busy", "no_eligible_claim"]
    considered_claim_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=16)]
    winner_claim_id: UUID | None
    winner_endpoint_id: StableEndpointId | None
    loser_endpoint_ids: Annotated[tuple[StableEndpointId, ...], Field(max_length=15)]
    decision_reason: Literal["continuation", "confidence_hysteresis", "gateway_order", "stable_id_tiebreak", "slot_busy", "all_ineligible"]
    decision_window_opened_at: AwareDatetime
    decided_at: AwareDatetime
    acoustic_correlation_valid_until: AwareDatetime
    cancellation_generation: Annotated[int, Field(ge=1)]
    decision_commitment: HmacCommitment

    @model_validator(mode="after")
    def coherent_arbitration(self) -> "WakeArbitrationV1":
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
        if self.winner_claim_id is not None and self.winner_claim_id not in self.considered_claim_ids:
            raise ValueError("wake_winner_not_considered")
        if self.winner_endpoint_id is not None and self.winner_endpoint_id in self.loser_endpoint_ids:
            raise ValueError("wake_winner_listed_as_loser")
        if not self.decision_window_opened_at <= self.decided_at <= self.decision_window_opened_at + timedelta(milliseconds=350):
            raise ValueError("wake_decision_window_invalid")
        if not self.decided_at < self.acoustic_correlation_valid_until <= self.decision_window_opened_at + timedelta(seconds=1.5):
            raise ValueError("wake_correlation_window_invalid")
        if len(set(self.considered_claim_ids)) != len(self.considered_claim_ids) or len(set(self.loser_endpoint_ids)) != len(self.loser_endpoint_ids):
            raise ValueError("duplicate_wake_arbitration_member")
        return self

CancellationReason = Literal[
    "privacy_shield", "owner_stop", "barge_in", "hardware_mute", "disconnect",
    "timeout", "newer_turn", "policy_change", "error_safe",
]

class EndpointControlV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    control_id: UUID
    endpoint_id: StableEndpointId
    control: Literal["hardware_mute", "privacy_indicator", "stop_playback", "enter_error_safe"]
    desired_state: Literal["enabled", "disabled", "stopped", "error_safe"]
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
            "hardware_mute": {"enabled", "disabled"},
            "privacy_indicator": {"enabled", "disabled"},
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
    turn_id: UUID
    endpoint_id: StableEndpointId
    sequence: Annotated[int, Field(ge=0)]
    sample_rate_hz: Literal[16_000, 24_000, 48_000]
    channels: Literal[1]
    sample_format: Literal["pcm_s16le"]
    duration_ms: Annotated[int, Field(ge=10, le=200)]
    byte_count: Annotated[int, Field(ge=1, le=64 * 1024)]
    frame_bytes: bytes
    final_frame: bool
    privacy_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]

    @model_validator(mode="after")
    def exact_playback_frame_length(self) -> "SpeechPlaybackFrameV1":
        if len(self.frame_bytes) != self.byte_count:
            raise ValueError("speech_playback_frame_length_mismatch")
        return self

class PlaybackReceiptV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    playback_id: UUID
    endpoint_id: StableEndpointId
    outcome: Literal["completed", "stopped", "partial", "unverified", "error_safe"]
    last_sequence: Annotated[int, Field(ge=0)] | None
    bytes_accepted: Annotated[int, Field(ge=0)]
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
        if self.outcome in {"completed", "stopped", "partial"} and self.started_at is None:
            raise ValueError("playback_outcome_without_start")
        if self.outcome == "completed" and (self.started_at is None or self.last_sequence is None or self.bytes_accepted == 0):
            raise ValueError("completed_playback_without_evidence")
        return self

class ConversationAdmissionV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    conversation_id: UUID
    turn_id: UUID
    winning_claim_id: UUID
    endpoint_id: StableEndpointId
    area_id: StableHomeId
    household_slot: Literal[1]
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
    source_endpoint_id: StableEndpointId
    source_area_id: StableHomeId
    identity_mode: Literal["identified", "guest", "uncertain"]
    audience: Literal["owner_private", "adult_private", "guardian_child", "household", "guest_safe"]
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
        return self

class ReplyRouteDecisionV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    request_id: UUID
    decision: Literal["speak_at_source", "no_speech"]
    endpoint_id: StableEndpointId | None
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
        if speaking != (self.endpoint_id is not None and self.maximum_volume_percent is not None):
            raise ValueError("reply_route_decision_shape_invalid")
        if not self.decided_at < self.valid_until <= self.decided_at + timedelta(seconds=2):
            raise ValueError("reply_route_decision_window_invalid")
        return self
```

### Media contracts

- `MediaProviderBindingV1` and `ProviderEntitlementReviewV1` contain opaque binding, adapter/version/source, account class, region, entitlement/expiry, egress/history disclosures, content classification capability, and no credential.
- `MediaPlayerBindingV1` binds one player to one `area_id`, exact provider/protocol, capabilities, state freshness, absolute-volume semantics, manual fallback, and generation.
- `MediaGroupManifestV1` is owner-passkey-approved, immutable, enumerates each player and per-member maximum volume, and never contains a selector/wildcard.
- `AuthorizedCatalogQueryV1` is an internal ephemeral bounded query. `OpaqueCatalogHandleV1` binds provider/account/item/classification/adapter/result generations and short expiry without a playable URL.
- `AuthorizedMediaRequestV1` and `MediaAuthorizationDecisionV1` remain inside Tuntun and bind exact actor/target/action/policy/generation/assurance facts. `SignedMediaEnvelopeV1` is the minimized outbound closed action described by the Phase 4 design and uses signature domain `tuntun-media-v1`.
- `PlayerObservationV1`, `MediaTargetOperationResultV1`, and `MediaOperationResultV1` preserve source/freshness/generation, manifest order, per-target evidence, action-specific verified states, and an exactly derived verified/unverified/partial/failure/unknown aggregate.

```python
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
    adapter_generation: Annotated[int, Field(ge=1)]
    entitlement_generation: Annotated[int, Field(ge=1)]
    current_review_id: UUID
    lifecycle_state: Literal["candidate", "enabled", "quarantined", "disabled", "retired"]
    binding_commitment: HmacCommitment

class ProviderEntitlementReviewV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    review_id: UUID
    provider_binding_id: StableEndpointId
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

MediaActionType = Literal[
    "media.play_catalog_item.v1", "media.pause.v1", "media.resume.v1", "media.stop.v1",
    "media.set_volume_absolute.v1", "media.seek_absolute.v1", "media.play_group_manifest.v1",
]

class MediaPlayerBindingV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    player_id: StableEndpointId
    area_id: StableHomeId
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
    player_id: StableEndpointId
    player_binding_generation: Annotated[int, Field(ge=1)]
    maximum_volume_percent: Annotated[int, Field(ge=0, le=100)]

class MediaGroupManifestV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    group_manifest_id: StableEndpointId
    manifest_version: Annotated[int, Field(ge=1)]
    members: Annotated[tuple[MediaGroupMemberV1, ...], Field(min_length=2, max_length=8)]
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
        return self

class AuthorizedMediaRequestV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    request_id: UUID
    action_type: MediaActionType
    target_kind: Literal["player", "group_manifest"]
    target_player_or_group_id: StableEndpointId
    actor_class: Literal["owner", "adult", "child", "designated_guest", "guest", "uncertain"]
    actor_subject_id: UUID | None
    catalog_handle_id: UUID | None
    content_classification: Literal["child_safe", "non_explicit", "explicit", "unknown"] | None
    requested_absolute_volume_percent: Annotated[int, Field(ge=0, le=100)] | None
    requested_seek_position_seconds: Annotated[int, Field(ge=0, le=86_400)] | None
    group_manifest_version: Annotated[int, Field(ge=1)] | None
    topology_generation: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    provider_generation: Annotated[int, Field(ge=1)]
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
        if (self.target_kind == "group_manifest") != (self.group_manifest_version is not None):
            raise ValueError("media_request_group_shape_invalid")
        if self.action_type == "media.play_group_manifest.v1" and self.target_kind != "group_manifest":
            raise ValueError("group_play_requires_group_manifest_target")
        if self.action_type == "media.play_catalog_item.v1" and self.target_kind != "player":
            raise ValueError("single_player_play_requires_player_target")
        identified = self.actor_class in {"owner", "adult", "child", "designated_guest"}
        if identified != (self.actor_subject_id is not None):
            raise ValueError("media_request_actor_shape_invalid")
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("media_request_window_invalid")
        return self

class MediaAuthorizationDecisionV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    request_id: UUID
    effect: Literal["allow", "deny", "step_up"]
    authorization_class: Literal[
        "adult_reversible_immediate", "exact_confirmation", "owner_passkey",
        "designated_guest_owner_coapproval", "child_rule_guardian_approved",
    ] | None
    required_assurance: Literal["confirmed", "passkey_verified"] | None
    reason_code: SafeReasonCode
    policy_version: Annotated[int, Field(ge=1)]
    topology_generation: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    provider_generation: Annotated[int, Field(ge=1)]
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
        if not self.decided_at < self.valid_until <= self.decided_at + timedelta(seconds=5):
            raise ValueError("media_decision_window_invalid")
        return self

class MediaTargetOperationResultV1(WholeHomeContract):
    target_id: StableEndpointId
    state: Literal[
        "VERIFIED_PLAYING", "VERIFIED_PAUSED", "VERIFIED_STOPPED", "VERIFIED_VOLUME",
        "VERIFIED_POSITION", "ACCEPTED_UNVERIFIED", "FAILED", "UNKNOWN",
    ]
    dispatch_attempt: Literal[0, 1]
    observation_strength: Literal[
        "none", "command_ack_only", "mirrored_optimistic", "same_adapter_observed",
        "out_of_band_observed", "independence_proven",
    ]
    observed_at: AwareDatetime
    evidence_commitment: HmacCommitment

    @model_validator(mode="after")
    def exact_target_result_evidence(self) -> "MediaTargetOperationResultV1":
        if self.state not in {"FAILED", "UNKNOWN"} and self.dispatch_attempt != 1:
            raise ValueError("media_target_result_without_dispatch")
        if self.state.startswith("VERIFIED_") and self.observation_strength in {"none", "command_ack_only", "mirrored_optimistic"}:
            raise ValueError("verified_media_result_without_observation")
        return self

class MediaOperationResultV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    operation_id: UUID
    request_id: UUID
    action_type: MediaActionType
    manifest_order_target_ids: Annotated[tuple[StableEndpointId, ...], Field(min_length=1, max_length=8)]
    target_results: Annotated[tuple[MediaTargetOperationResultV1, ...], Field(min_length=1, max_length=8)]
    aggregate_state: Literal["VERIFIED", "ACCEPTED_UNVERIFIED", "PARTIAL", "FAILED", "UNKNOWN"]
    topology_generation: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    provider_generation: Annotated[int, Field(ge=1)]
    completed_at: AwareDatetime
    result_commitment: HmacCommitment

    @model_validator(mode="after")
    def exact_manifest_order_and_aggregate(self) -> "MediaOperationResultV1":
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
        states = tuple(result.state for result in self.target_results)
        success = tuple(state.startswith("VERIFIED_") or state == "ACCEPTED_UNVERIFIED" for state in states)
        if all(state.startswith("VERIFIED_") for state in states):
            expected_aggregate = "VERIFIED"
        elif all(success):
            expected_aggregate = "ACCEPTED_UNVERIFIED"
        elif any(success):
            expected_aggregate = "PARTIAL"
        elif all(state == "FAILED" for state in states):
            expected_aggregate = "FAILED"
        else:
            expected_aggregate = "UNKNOWN"
        if self.aggregate_state != expected_aggregate:
            raise ValueError("media_result_aggregate_invalid")
        return self

class OpaqueCatalogHandleV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    handle_id: UUID
    provider_binding_id: StableEndpointId
    account_class: Literal["owner_entitled", "household_entitled", "child_rule_entitled"]
    item_identity_commitment: HmacCommitment
    content_classification: Literal["child_safe", "non_explicit", "explicit", "unknown"]
    adapter_generation: Annotated[int, Field(ge=1)]
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
    provider_binding_ids: Annotated[tuple[StableEndpointId, ...], Field(min_length=1, max_length=8)]
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
        if len(set(self.provider_binding_ids)) != len(self.provider_binding_ids):
            raise ValueError("duplicate_catalog_provider_binding")
        return self

class MediaCatalogResultV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    query_id: UUID
    state: Literal["exact", "ambiguous", "no_match", "denied", "error_safe"]
    handles: Annotated[tuple[OpaqueCatalogHandleV1, ...], Field(max_length=12)]
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
        return self

class MediaDispatchReceiptV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    action_id: UUID
    target_ids: Annotated[tuple[StableEndpointId, ...], Field(min_length=1, max_length=8)]
    state: Literal["authorized_committed", "dispatching", "reconciling", "verified", "accepted_unverified", "partial", "failed", "unknown", "expired"]
    dispatch_attempt: Literal[0, 1]
    provider_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    observed_at: AwareDatetime
    receipt_commitment: HmacCommitment

    @model_validator(mode="after")
    def coherent_media_dispatch(self) -> "MediaDispatchReceiptV1":
        if self.state in {"dispatching", "reconciling", "verified", "accepted_unverified", "partial", "unknown"} and self.dispatch_attempt != 1:
            raise ValueError("media_dispatch_state_without_attempt")
        if len(set(self.target_ids)) != len(self.target_ids):
            raise ValueError("duplicate_media_dispatch_target")
        return self

class SignedMediaEnvelopeV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    action_id: UUID
    action_type: MediaActionType
    target_player_or_group_id: StableEndpointId
    catalog_handle_id: UUID | None
    absolute_volume_percent: Annotated[int, Field(ge=0, le=100)] | None
    seek_position_seconds: Annotated[int, Field(ge=0, le=86_400)] | None
    controller_epoch: Annotated[int, Field(ge=1)]
    topology_generation: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_digest: Sha256Digest
    provider_generation: Annotated[int, Field(ge=1)]
    entitlement_generation: Annotated[int, Field(ge=1)]
    policy_version: Annotated[int, Field(ge=1)]
    authorization_commitment: HmacCommitment
    idempotency_key: UUID
    authorized_at: AwareDatetime
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    key_id: KeyId
    signature: P256Signature

    @model_validator(mode="after")
    def exact_media_action_shape(self) -> "SignedMediaEnvelopeV1":
        play = self.action_type in {"media.play_catalog_item.v1", "media.play_group_manifest.v1"}
        volume = self.action_type == "media.set_volume_absolute.v1"
        seek = self.action_type == "media.seek_absolute.v1"
        if play != (self.catalog_handle_id is not None):
            raise ValueError("media_catalog_handle_shape_invalid")
        if volume != (self.absolute_volume_percent is not None):
            raise ValueError("media_volume_shape_invalid")
        if seek != (self.seek_position_seconds is not None):
            raise ValueError("media_seek_shape_invalid")
        if not self.authorized_at <= self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("media_envelope_window_invalid")
        return self

class PlayerObservationV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    player_id: StableEndpointId
    source: Literal["native_player", "home_assistant", "music_assistant", "out_of_band"]
    playback_state: Literal["idle", "playing", "paused", "stopped", "buffering", "unavailable", "unknown"]
    volume_percent: Annotated[int, Field(ge=0, le=100)] | None
    position_seconds: Annotated[int, Field(ge=0, le=86_400)] | None
    observation_strength: Literal["command_ack_only", "mirrored_optimistic", "same_adapter_observed", "out_of_band_observed", "independence_proven"]
    binding_generation: Annotated[int, Field(ge=1)]
    provider_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    sampled_at: AwareDatetime
    ingested_at: AwareDatetime
    valid_until: AwareDatetime
    source_receipt_commitment: HmacCommitment

    @model_validator(mode="after")
    def coherent_player_observation(self) -> "PlayerObservationV1":
        if not self.sampled_at <= self.ingested_at < self.valid_until <= self.ingested_at + timedelta(seconds=5):
            raise ValueError("player_observation_window_invalid")
        if self.playback_state in {"unavailable", "unknown"} and (self.volume_percent is not None or self.position_seconds is not None):
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
    TVObservationV1,
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
- `TelevisionBindingV1` and `TVCapabilityEvidenceV1` bind one exact deployment TV, primary control/optional distinct observation adapters, available operations, strength, generation, test digest, and eligibility state.
- `SignedTVActionV1` uses `tuntun-tv-v1` and one closed desired state. Adapter-side `WholeHomeTVObservationV1` carries source/sample/ingest/freshness/generation/strength and registered closed observed dimensions only; `TVActionDispatchReceiptV1` reports that action's dispatch truth. The canonical names `TVObservationV1` and `TVControlReceiptV1` remain owned exclusively by the Phase 2 screen-time contract.
- `ManualOverrideEventV1` identifies a local physical/renderer/contrary-observation source and enforcement generation, but never identifies the person using the remote/button.

```python
TeachingTopicCode = Literal[
    "literacy", "numeracy", "general_knowledge", "creative",
    "language_practice", "other",
]

class TeachingAudienceBindingV1(WholeHomeContract):
    audience_class: Literal["adult", "k2_child", "n1_child", "guest"]
    subject_id: UUID | None
    profile_version: Annotated[int, Field(ge=1)] | None
    identity_mode: Literal["identified", "guest", "uncertain"]
    memory_audience: Literal["subject_private", "guardian_child", "household", "public_only"]
    guardian_approval_generation: Annotated[int, Field(ge=1)] | None
    consent_generation: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    screen_time_policy_generation: Annotated[int, Field(ge=1)]
    binding_commitment: HmacCommitment

    @model_validator(mode="after")
    def exact_teaching_audience(self) -> "TeachingAudienceBindingV1":
        identified = self.audience_class != "guest"
        if identified != (self.subject_id is not None and self.profile_version is not None):
            raise ValueError("teaching_audience_subject_shape_invalid")
        child = self.audience_class in {"k2_child", "n1_child"}
        if child != (self.guardian_approval_generation is not None):
            raise ValueError("teaching_audience_guardian_shape_invalid")
        if self.audience_class == "guest":
            if self.identity_mode != "guest" or self.memory_audience != "public_only":
                raise ValueError("guest_teaching_audience_widened")
        elif child and self.memory_audience != "guardian_child":
            raise ValueError("child_teaching_audience_invalid")
        return self

class TeachingRequestV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    request_id: UUID
    display_endpoint_id: StableEndpointId
    renderer_endpoint_id: StableEndpointId
    area_id: StableHomeId
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
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("teaching_request_window_invalid")
        return self

class AuthorizedTeachingRequestV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    request_id: UUID
    display_endpoint_id: StableEndpointId
    renderer_endpoint_id: StableEndpointId
    area_id: StableHomeId
    audience_binding: TeachingAudienceBindingV1
    language_mode: Literal["en", "hi", "hinglish"]
    topic_code: TeachingTopicCode
    maximum_duration_minutes: Annotated[int, Field(ge=1, le=120)]
    web_mode: Literal["no_web", "controlled"]
    controlled_web_authorization_commitment: HmacCommitment | None
    approved_source_pack_commitments: Annotated[tuple[HmacCommitment, ...], Field(max_length=16)]
    screen_time_session_ref: UUID | None
    teaching_policy_version: Annotated[int, Field(ge=1)]
    authorized_at: AwareDatetime
    expires_at: AwareDatetime
    authorization_commitment: HmacCommitment

    @model_validator(mode="after")
    def exact_authorized_teaching_request(self) -> "AuthorizedTeachingRequestV1":
        if self.audience_binding.audience_class in {"k2_child", "n1_child", "guest"} and self.web_mode != "no_web":
            raise ValueError("nonadult_teaching_web_mode_invalid")
        controlled = self.web_mode == "controlled"
        if controlled != (self.controlled_web_authorization_commitment is not None):
            raise ValueError("authorized_teaching_web_authority_shape_invalid")
        if len(set(self.approved_source_pack_commitments)) != len(self.approved_source_pack_commitments):
            raise ValueError("duplicate_teaching_source_pack")
        if not self.authorized_at < self.expires_at <= self.authorized_at + timedelta(seconds=5):
            raise ValueError("authorized_teaching_request_window_invalid")
        return self

class TeachingAuthorizationDecisionV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    request_id: UUID
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
        if not self.decided_at < self.valid_until <= self.decided_at + timedelta(seconds=5):
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
    display_endpoint_id: StableEndpointId
    area_id: StableHomeId
    audience_class: Literal["adult", "k2_child", "n1_child", "guest"]
    language_mode: Literal["en", "hi", "hinglish"]
    web_mode: Literal["no_web", "controlled"]
    teaching_policy_version: Annotated[int, Field(ge=1)]
    screen_time_session_ref: UUID | None
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
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(hours=2):
            raise ValueError("teaching_manifest_window_invalid")
        if self.audience_class in {"k2_child", "n1_child"}:
            if self.web_mode != "no_web":
                raise ValueError("child_teaching_manifest_web_mode_invalid")
            if self.expires_at > self.issued_at + timedelta(minutes=30) and self.child_extended_duration_commitment is None:
                raise ValueError("child_teaching_extension_unbound")
        elif self.audience_class == "guest" and self.web_mode != "no_web":
            raise ValueError("guest_teaching_manifest_web_mode_invalid")
        elif self.child_extended_duration_commitment is not None:
            raise ValueError("nonchild_teaching_extension_invalid")
        component_ids = tuple(component.component_id for component in self.components)
        asset_ids = tuple(asset.asset_id for asset in self.assets)
        if len(set(component_ids)) != len(component_ids) or len(set(asset_ids)) != len(asset_ids):
            raise ValueError("duplicate_teaching_component_or_asset")
        referenced_assets = {component.asset_id for component in self.components if isinstance(component, ImageAssetComponentV1)}
        if not referenced_assets.issubset(set(asset_ids)):
            raise ValueError("teaching_component_references_unknown_asset")
        return self

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
    capability_evidence_id: UUID

class TVObservationBindingV1(WholeHomeContract):
    dimension: TVObservationDimension
    observation_adapter_id: StableEndpointId
    observation_strength: Literal[
        "command_ack_only", "mirrored_optimistic", "same_adapter_observed",
        "out_of_band_observed", "independence_proven",
    ]
    capability_generation: Annotated[int, Field(ge=1)]
    capability_evidence_id: UUID

class TelevisionBindingV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    tv_endpoint_id: StableEndpointId
    inventory_id: StableEndpointId
    area_id: StableHomeId
    safe_household_label: Annotated[TeachingText, Field(max_length=80)]
    exact_model_commitment: HmacCommitment
    platform_version_commitment: HmacCommitment
    firmware_commitment: HmacCommitment
    control_bindings: Annotated[tuple[TVControlBindingV1, ...], Field(max_length=6)]
    observation_bindings: Annotated[tuple[TVObservationBindingV1, ...], Field(max_length=5)]
    eligibility_state: Literal[
        "DISPLAY_ONLY_MANUAL", "OBSERVE_ONLY", "COOPERATIVE_ELIGIBLE",
        "STRICT_ELIGIBLE", "QUARANTINED", "RETIRED",
    ]
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
        if self.eligibility_state == "DISPLAY_ONLY_MANUAL" and (controls or observations):
            raise ValueError("manual_tv_cannot_have_active_adapter_route")
        if self.eligibility_state == "OBSERVE_ONLY" and (controls or not observations):
            raise ValueError("observe_only_tv_binding_shape_invalid")
        if self.eligibility_state == "COOPERATIVE_ELIGIBLE" and (not controls or not observations):
            raise ValueError("cooperative_tv_binding_shape_invalid")
        if self.eligibility_state == "STRICT_ELIGIBLE":
            if not controls or not any(binding.observation_strength == "independence_proven" for binding in self.observation_bindings):
                raise ValueError("strict_tv_binding_lacks_independent_observation")
        if self.eligibility_state in {"QUARANTINED", "RETIRED"} and (controls or observations):
            raise ValueError("inactive_tv_cannot_have_active_adapter_route")
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

class DisplayReceiptV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    session_id: UUID
    renderer_endpoint_id: StableEndpointId
    display_endpoint_id: StableEndpointId
    state: Literal["validated", "ready", "rendered", "cleared", "expired", "error_safe", "unverified"]
    manifest_digest: Sha256Digest
    rendered_at: AwareDatetime | None
    cleared_at: AwareDatetime | None
    hdmi_evidence: Literal["connected", "disconnected", "unknown"]
    privacy_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    observed_at: AwareDatetime
    evidence_commitment: HmacCommitment
    renderer_key_id: KeyId
    renderer_signature: P256Signature

    @model_validator(mode="after")
    def coherent_display_receipt(self) -> "DisplayReceiptV1":
        if self.state == "rendered" and (self.rendered_at is None or self.cleared_at is not None):
            raise ValueError("rendered_display_evidence_invalid")
        if self.state in {"cleared", "expired"} and self.cleared_at is None:
            raise ValueError("terminal_display_missing_clear_time")
        if self.state not in {"cleared", "expired"} and self.cleared_at is not None:
            raise ValueError("nonterminal_display_claims_clear_time")
        if self.cleared_at is not None and self.rendered_at is not None and self.cleared_at < self.rendered_at:
            raise ValueError("display_clear_time_invalid")
        return self

class DisplayClearRequestV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    request_id: UUID
    teaching_session_id: UUID
    renderer_endpoint_id: StableEndpointId
    display_endpoint_id: StableEndpointId
    reason: Literal["owner_stop", "privacy_shield", "identity_downgrade", "expiry", "screen_time_end", "renderer_error"]
    manifest_generation: Annotated[int, Field(ge=1)]
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
        return self

class AuthorizedTVRequestV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    request_id: UUID
    tv_endpoint_id: StableEndpointId
    control_adapter_id: StableEndpointId
    operation: TVOperation
    desired_power: Literal["ON", "STANDBY"] | None
    desired_input_id: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")] | None
    desired_volume_percent: Annotated[int, Field(ge=0, le=100)] | None
    desired_muted: bool | None
    desired_key: Literal["home", "back", "up", "down", "left", "right", "select"] | None
    desired_app_id: Annotated[str, Field(min_length=1, max_length=96, pattern=r"^[A-Za-z0-9_.:-]+$")] | None
    actor_class: Literal["owner", "adult", "current_guardian", "system_screen_time"]
    actor_subject_id: UUID | None
    authorization_class: Literal[
        "adult_reversible_immediate", "exact_confirmation", "owner_passkey",
        "guardian_screen_time_rule", "system_enforcement",
    ]
    controller_epoch: Annotated[int, Field(ge=1)]
    topology_generation: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    authorization_generation: Annotated[int, Field(ge=1)]
    enforcement_generation: Annotated[int, Field(ge=1)] | None
    policy_version: Annotated[int, Field(ge=1)]
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
        elif self.actor_subject_id is None or self.authorization_class == "system_enforcement":
            raise ValueError("human_tv_request_authority_shape_invalid")
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("authorized_tv_request_window_invalid")
        return self

class SignedTVActionV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    action_id: UUID
    tv_endpoint_id: StableEndpointId
    control_adapter_id: StableEndpointId
    operation: TVOperation
    desired_power: Literal["ON", "STANDBY"] | None
    desired_input_id: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")] | None
    desired_volume_percent: Annotated[int, Field(ge=0, le=100)] | None
    desired_muted: bool | None
    desired_key: Literal["home", "back", "up", "down", "left", "right", "select"] | None
    desired_app_id: Annotated[str, Field(min_length=1, max_length=96, pattern=r"^[A-Za-z0-9_.:-]+$")] | None
    controller_epoch: Annotated[int, Field(ge=1)]
    topology_generation: Annotated[int, Field(ge=1)]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    authorization_generation: Annotated[int, Field(ge=1)]
    enforcement_generation: Annotated[int, Field(ge=1)] | None
    idempotency_key: UUID
    authorized_at: AwareDatetime
    issued_at: AwareDatetime
    expires_at: AwareDatetime
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
        if not self.authorized_at <= self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("tv_action_window_invalid")
        return self

class TVActionDispatchReceiptV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    action_id: UUID
    tv_endpoint_id: StableEndpointId
    control_adapter_id: StableEndpointId
    state: Literal["accepted", "rejected", "unverified", "error_safe"]
    dispatch_attempt: Literal[0, 1]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    observed_at: AwareDatetime
    evidence_commitment: HmacCommitment
    adapter_key_id: KeyId
    adapter_signature: P256Signature

    @model_validator(mode="after")
    def coherent_tv_control_receipt(self) -> "TVActionDispatchReceiptV1":
        if self.state in {"accepted", "unverified"} and self.dispatch_attempt != 1:
            raise ValueError("tv_control_receipt_without_attempt")
        return self

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
    observation_adapter_id: StableEndpointId
    dimensions: Annotated[tuple[TVObservedDimensionV1, ...], Field(min_length=1, max_length=5)]
    observation_strength: Literal[
        "command_ack_only", "mirrored_optimistic", "same_adapter_observed",
        "out_of_band_observed", "independence_proven",
    ]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    sampled_at: AwareDatetime
    ingested_at: AwareDatetime
    valid_until: AwareDatetime
    source_receipt_commitment: HmacCommitment
    adapter_key_id: KeyId
    adapter_signature: P256Signature

    @model_validator(mode="after")
    def coherent_tv_observation(self) -> "WholeHomeTVObservationV1":
        if not self.sampled_at <= self.ingested_at < self.valid_until <= self.ingested_at + timedelta(seconds=5):
            raise ValueError("tv_observation_window_invalid")
        names = tuple(dimension.dimension for dimension in self.dimensions)
        if len(set(names)) != len(names):
            raise ValueError("duplicate_tv_observed_dimension")
        return self

class TVObservationRequestV1(WholeHomeContract):
    schema_version: Literal["1.0"]
    request_id: UUID
    tv_endpoint_id: StableEndpointId
    observation_adapter_id: StableEndpointId
    dimensions: Annotated[
        tuple[Literal["power", "input", "volume", "mute", "playback"], ...],
        Field(min_length=1, max_length=5),
    ]
    binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
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

class TVControlPort(Protocol):
    async def dispatch(self, action: SignedTVActionV1) -> TVActionDispatchReceiptV1: ...

class TVObservationPort(Protocol):
    async def observe(self, request: TVObservationRequestV1) -> WholeHomeTVObservationV1: ...
```

No port accepts `dict[str, Any]`, a provider credential, a Home Assistant service/entity name, a playable URL, browser markup, arbitrary television key/code, subject identity, memory object, or general adapter token.

## Durable State and Migration Map

| Revision | Tables and invariants |
|---|---|
| `0016_whole_home_endpoints` | `speech_endpoint_registrations`, `area_voice_policies`, `area_occupant_consents`, `child_room_voice_approvals`, `endpoint_commissioning_evidence`, `conversation_admissions`, `conversation_transitions`, `handoff_tokens`; canonical `area_id` foreign keys only, no `room_id`; one nonterminal household slot row; no claim/frame/audio/transcript/embedding; current exact privacy/capability generations; distinct owner/current-guardian approval constraint |
| `0017_media_and_display` | `media_provider_bindings`, `provider_entitlement_reviews`, `media_player_bindings`, `media_group_manifests`, `media_group_members`, `media_actions`, `media_action_transitions`, `media_results`, `display_endpoint_bindings`, `teaching_sessions`, `teaching_session_transitions`, `display_receipts`; no secret/query text/URL/path/lesson body/asset bytes/screenshot/learning-summary column; immutable groups/actions, one terminal result, bounded expiry |
| `0018_television_capabilities` | `television_inventory`, `tv_adapter_bindings`, `tv_capability_evidence`, `tv_actions`, `tv_action_transitions`, `tv_observations`; exact stable TV endpoint, one primary control binding per operation, optional distinct observation binding, generation invalidation, closed dimensions, no MAC/serial/token/account/arbitrary key map |
| `0019_screen_time_real_adapter` | additive `screen_time_adapter_bindings`, `screen_time_enforcement_generations`, `screen_time_control_attempts`, `screen_time_manual_overrides`; existing Phase 2 policy/ledger/session authority is unchanged; attempt number constrained to 1 or 2 and unique per generation; manual/unknown terminal states block further insertion; no programme/viewer inference |

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
pnpm --filter @tuntun/admin exec playwright test tests/e2e/media-learning-*.spec.ts
pnpm --filter @tuntun/display-agent test
pnpm --filter @tuntun/display-agent build
```

Owner-gated commands write only to ignored `var/evidence/phase4/`:

```bash
TUNTUN_ALLOW_PHASE4_HARDWARE=1 uv run pytest -m phase4_hardware tests/hardware/whole_home -q
TUNTUN_ALLOW_ENDPOINT_PROBE=1 uv run python scripts/phase4/run_endpoint_bakeoff.py --evidence-root var/evidence/phase4/endpoints
TUNTUN_ALLOW_MEDIA_PROBE=1 uv run python scripts/phase4/qualify_media.py --evidence-root var/evidence/phase4/media
TUNTUN_ALLOW_DISPLAY_PROBE=1 uv run python scripts/phase4/pair_display.py --evidence-root var/evidence/phase4/display
TUNTUN_ALLOW_TV_PROBE=1 uv run python scripts/phase4/probe_television.py --inventory-id tv_samsung_neoled_49 --evidence-root var/evidence/phase4/televisions
TUNTUN_ALLOW_TV_PROBE=1 uv run python scripts/phase4/probe_television.py --inventory-id tv_tcl_42 --evidence-root var/evidence/phase4/televisions
TUNTUN_ALLOW_ELAPSED_PHASE4=1 uv run python scripts/phase4/run_acceptance.py --evidence-root var/evidence/phase4/acceptance
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

**Interfaces:** Produces the complete Frozen Contract and Port Baseline above; schema IDs `tuntun.whole-home.speech-endpoint.v1`, `tuntun.whole-home.wake-lease.v1`, `tuntun.whole-home.media.v1`, `tuntun.whole-home.teaching-manifest.v1`, `tuntun.whole-home.television.v1`, and `tuntun.whole-home.ui.v1`; signature domains `tuntun-endpoint-event-v1`, `tuntun-capture-lease-v1`, `tuntun-media-v1`, `tuntun-display-manifest-v1`, and `tuntun-tv-v1`. Phase 4 imports `EnforcementIntentV1`, `TVObservationV1`, and `TVControlReceiptV1` from `tuntun_contracts.home.screen_time`; it defines no local alias or model under any of those three names.

- [ ] **Step 1: Write red strictness, signature-domain, and location tests**

```python
def test_wake_claim_is_metadata_only(valid_claim: dict[str, object]) -> None:
    claim = WakeClaimV1.model_validate(valid_claim)
    assert claim.area_id == "area_synth_common_01"
    forbidden = {"audio", "samples", "embedding", "speaker_id", "profile_id", "room_id"}
    assert forbidden.isdisjoint(claim.model_dump())

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
    signature = signer.sign("tuntun-media-v1", canonical_phase4_bytes(media.unsigned()))
    assert signer.verify("tuntun-media-v1", media.unsigned(), signature)
    assert not signer.verify("tuntun-tv-v1", media.unsigned(), signature)

def test_speech_playback_frame_declares_exact_bytes(speech_playback_frame_fixture) -> None:
    with pytest.raises(ValidationError):
        SpeechPlaybackFrameV1.model_validate({
            **speech_playback_frame_fixture,
            "byte_count": len(speech_playback_frame_fixture["frame_bytes"]) + 1,
        })

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

def test_reply_route_cannot_claim_speech_without_exact_endpoint_and_volume(reply_route_fixture) -> None:
    for mutation in (
        {"decision": "speak_at_source", "endpoint_id": None},
        {"decision": "no_speech", "endpoint_id": "endpoint_synth_01", "maximum_volume_percent": 20},
    ):
        with pytest.raises(ValidationError):
            ReplyRouteDecisionV1.model_validate({**reply_route_fixture, **mutation})

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
    {"action_type": "media.pause.v1", "catalog_handle_id": uuid4()},
    {"action_type": "media.play_catalog_item.v1", "catalog_handle_id": None},
    {"action_type": "media.set_volume_absolute.v1", "absolute_volume_percent": None},
    {"action_type": "media.seek_absolute.v1", "seek_position_seconds": None},
])
def test_media_envelope_requires_one_action_specific_value(signed_media_envelope_fixture, mutation) -> None:
    with pytest.raises(ValidationError):
        SignedMediaEnvelopeV1.model_validate({**signed_media_envelope_fixture, **mutation})

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

def test_teaching_manifest_rejects_unknown_asset_and_markup(teaching_manifest_fixture) -> None:
    with pytest.raises(ValidationError):
        TeachingSessionManifestV1.model_validate(
            manifest_with_unknown_image_asset(teaching_manifest_fixture)
        )
    with pytest.raises(ValidationError):
        TeachingSessionManifestV1.model_validate(
            manifest_with_paragraph(teaching_manifest_fixture, '<script src="https://evil.invalid/x.js">')
        )

@pytest.mark.parametrize("mutation", [
    {"state": "rendered", "rendered_at": None},
    {"state": "rendered", "cleared_at": SYNTHETIC_NOW},
    {"state": "cleared", "cleared_at": None},
    {"state": "ready", "cleared_at": SYNTHETIC_NOW},
])
def test_display_receipt_state_requires_exact_render_clear_evidence(display_receipt_fixture, mutation) -> None:
    with pytest.raises(ValidationError):
        DisplayReceiptV1.model_validate({**display_receipt_fixture, **mutation})

@pytest.mark.parametrize("mutation", [
    {"operation": "tv.set_power.v1", "desired_power": None},
    {"operation": "tv.set_power.v1", "desired_power": "ON", "desired_muted": False},
    {"operation": "tv.send_key.v1", "desired_key": None},
])
def test_tv_action_has_exactly_one_operation_specific_desired_state(signed_tv_action_fixture, mutation) -> None:
    with pytest.raises(ValidationError):
        SignedTVActionV1.model_validate({**signed_tv_action_fixture, **mutation})

def test_tv_receipt_cannot_claim_acceptance_without_dispatch(tv_control_receipt_fixture) -> None:
    with pytest.raises(ValidationError):
        TVActionDispatchReceiptV1.model_validate({
            **tv_control_receipt_fixture,
            "state": "accepted",
            "dispatch_attempt": 0,
        })

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
            "room_class": "prohibited_sensitive",
            "lifecycle_state": "commissioned",
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

@pytest.mark.parametrize("mutation", [
    {"action_type": "media.play_catalog_item.v1", "target_kind": "group_manifest"},
    {"action_type": "media.play_group_manifest.v1", "target_kind": "player", "group_manifest_version": None},
    {"action_type": "media.pause.v1", "requested_absolute_volume_percent": 35},
    {"actor_class": "guest", "actor_subject_id": uuid4()},
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

def test_ephemeral_learning_summary_cannot_outlive_five_minutes(ephemeral_summary_fields) -> None:
    with pytest.raises(ValueError):
        EphemeralLearningSummary(**{
            **ephemeral_summary_fields,
            "expires_at": ephemeral_summary_fields["created_at"] + timedelta(minutes=5, microseconds=1),
        })

def test_tv_binding_and_evidence_cannot_overclaim_routes(tv_binding_fixture, tv_capability_evidence_fixture) -> None:
    with pytest.raises(ValidationError):
        TelevisionBindingV1.model_validate({
            **tv_binding_fixture,
            "eligibility_state": "DISPLAY_ONLY_MANUAL",
            "control_bindings": tv_binding_fixture["control_bindings"],
        })
    with pytest.raises(ValidationError):
        TVCapabilityEvidenceV1.model_validate({
            **tv_capability_evidence_fixture,
            "evidence_kind": "observation",
            "operation": "tv.set_power.v1",
        })

def test_manual_override_contract_has_no_person_identity(manual_override_event_fixture) -> None:
    with pytest.raises(ValidationError):
        ManualOverrideEventV1.model_validate({
            **manual_override_event_fixture,
            "subject_id": uuid4(),
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

def test_system_tv_request_requires_enforcement_and_no_human_subject(authorized_tv_request_fixture) -> None:
    for mutation in (
        {"actor_class": "system_screen_time", "actor_subject_id": uuid4()},
        {"actor_class": "system_screen_time", "enforcement_generation": None},
        {"actor_class": "owner", "authorization_class": "system_enforcement"},
        {"actor_class": "system_screen_time", "actor_subject_id": None,
         "authorization_class": "system_enforcement", "enforcement_generation": 4,
         "operation": "tv.mute.v1", "desired_power": None, "desired_muted": True},
        {"actor_class": "system_screen_time", "actor_subject_id": None,
         "authorization_class": "system_enforcement", "enforcement_generation": 4,
         "operation": "tv.set_power.v1", "desired_power": "ON"},
    ):
        with pytest.raises(ValidationError):
            AuthorizedTVRequestV1.model_validate({**authorized_tv_request_fixture, **mutation})

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
- Create all corpus/registry/fault fixtures under `fixtures/synthetic/whole-home/` named in the repository map.
- Test `tests/unit/testing/whole_home/test_phase4_scenario.py`.
- Test `tests/contract/whole_home/test_phase4_corpora.py`.
- Test `tests/security/whole_home/test_simulator_has_no_external_io.py`.

**Interfaces:** `WholeHomeScenario.run(events: tuple[ScenarioEvent, ...]) -> ScenarioResult`; `Phase4FaultPlan.hit(point: Phase4FaultPoint)`; deterministic seed `240827`; at least 500 duplicate-wake cases, 1,000 routing/audience cases, 500 adversarial media cases, 500 display manifests, the unchanged 720 screen-time oracle rows, and 10,000 generated screen-time sequences.

- [ ] **Step 1: Write red count, determinism, and no-I/O tests**

```python
def test_required_phase4_corpus_counts() -> None:
    assert len(load_jsonl("duplicate-wake-corpus-v1.jsonl")) >= 500
    assert len(load_jsonl("routing-corpus-v1.jsonl")) >= 1_000
    assert len(load_jsonl("media-adversarial-corpus-v1.jsonl")) >= 500
    assert len(load_jsonl("display-manifest-corpus-v1.jsonl")) >= 500

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
```

Expected: both builds are byte-identical; no socket, subprocess, hardware, Keychain, HA/MA, browser, or paid-provider call occurs; losing fake endpoints finish with zero candidate bytes.

- [ ] **Step 5: Commit fake and corpus paths**

```bash
git add packages/testing/src/tuntun_testing/whole_home scripts/phase4/build_corpora.py fixtures/synthetic/whole-home tests/unit/testing/whole_home tests/contract/whole_home/test_phase4_corpora.py tests/security/whole_home/test_simulator_has_no_external_io.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(whole-home): add deterministic Phase 4 simulators"
```

### Task 03: Add encrypted endpoint, media/display, television, and real-adapter persistence

**Depends on:** Tasks 01–02; one current Alembic head including Phase 3's reserved `0013`–`0015` or an explicit merge revision if Phase 3 landed independently.
**Gate contribution:** P4-E0, P4-0, crash recovery for P4-2–P4-6.
**Estimated effort:** 3 person-days.

**Files:**

- Create `apps/core/migrations/versions/0016_whole_home_endpoints.py` through `0019_screen_time_real_adapter.py`.
- Create `apps/core/src/tuntun_core/domain/whole_home/{__init__,rooms,speech,media,display,television}.py`.
- Test `tests/integration/whole_home/test_phase4_migrations.py`.
- Test `tests/integration/whole_home/test_phase4_repository_invariants.py`.
- Test `tests/security/whole_home/test_phase4_schema_minimization.py`.

**Interfaces:** Typed repositories and serialized `AsyncUnitOfWork` methods for registrations, current privacy/capability generations, one-slot admission, immutable actions/transitions/results, teaching lifecycle receipts, exact TV evidence, and two-attempt enforcement. No repository exists for raw claims, frames, query text, display bodies/assets, pixels, or ephemeral learning summaries.

- [ ] **Step 1: Write red migration and forbidden-column tests**

```python
def test_only_one_nonterminal_conversation_slot(uow: AsyncUnitOfWork) -> None:
    uow.conversations.add(active_admission(slot=0, conversation_id=UUID(int=1)))
    with pytest.raises(IntegrityError):
        uow.conversations.add(active_admission(slot=0, conversation_id=UUID(int=2)))

def test_phase4_schema_has_no_payload_or_parallel_location(sqlcipher_schema: Schema) -> None:
    forbidden = {
        "room_id", "audio", "waveform", "transcript", "embedding", "query_text",
        "provider_uri", "html", "javascript", "asset_bytes", "screenshot",
        "learning_summary", "lesson_text", "credential", "serial_number", "mac_address",
    }
    assert forbidden.isdisjoint(sqlcipher_schema.column_names())
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/whole_home/test_phase4_migrations.py tests/integration/whole_home/test_phase4_repository_invariants.py tests/security/whole_home/test_phase4_schema_minimization.py -q`
Expected: FAIL because revision `0016_whole_home_endpoints` is absent.

- [ ] **Step 3: Implement migrations, constraints, triggers, and repositories**

Implement the Durable State and Migration Map exactly. Use partial unique indexes for one active slot and one current binding; foreign keys to Phase 2 `home_areas.area_id`; generation/CAS columns; check constraints for room class, lifecycle state, action type, result strength, attempt ordinal, and terminal immutability; and triggers that reject illegal state transitions or insertion after manual/unknown terminal state. Store keyed content commitments, not private bodies. Ensure `0019` references existing Phase 2 screen-time sessions without changing its allowance arithmetic.

- [ ] **Step 4: Prove forward, restart, downgrade/isolated restore, and no-resurrection behavior**

Run:

```bash
uv run pytest tests/integration/whole_home tests/security/whole_home/test_phase4_schema_minimization.py -q
uv run alembic upgrade head
uv run python scripts/check_migration_ownership.py --revisions 0016 0017 0018 0019
uv run python scripts/scan_sql_schema.py --db-kind canonical --forbid room_id,audio,waveform,transcript,embedding,query_text,provider_uri,html,javascript,asset_bytes,screenshot,learning_summary,lesson_text,credential,serial_number,mac_address
```

Expected: PASS; restart cancels nonterminal admission/leases rather than resuming capture, leaves uncertain external effects reconcilable, and never restores a consumed handoff/catalog handle or a deleted/revoked consent as current.

- [ ] **Step 5: Document rollback**

Add the migration section to `docs/operations/phase4-update-rollback.md`: take/verify encrypted pre-migration backup; migrate in quarantine; on failure restore the prior compatible schema/package into isolated paths; rotate controller/session epochs; keep endpoints/media/displays/TV enforcement disabled until reconciliation. A downgrade never truncates live unknown actions.

- [ ] **Step 6: Commit exact persistence paths**

```bash
git add apps/core/migrations/versions/0016_whole_home_endpoints.py apps/core/migrations/versions/0017_media_and_display.py apps/core/migrations/versions/0018_television_capabilities.py apps/core/migrations/versions/0019_screen_time_real_adapter.py apps/core/src/tuntun_core/domain/whole_home tests/integration/whole_home tests/security/whole_home/test_phase4_schema_minimization.py docs/operations/phase4-update-rollback.md
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(whole-home): persist Phase 4 authority state"
```

### Task 04: Register Phase 4 policy amendments and prove conditional feature absence

**Depends on:** Tasks 01 and 03; accepted shared feature/policy registries.
**Gate contribution:** P4-E0, every conditional gate.
**Estimated effort:** 2.5 person-days.

**Files:**

- Modify `packages/policy/src/tuntun_policy/registry.py` and `packages/policy/src/tuntun_policy/corpora.py`.
- Modify `apps/core/src/tuntun_core/services/features/registry.py` and `apps/core/src/tuntun_core/api/routes/features.py`.
- Create `fixtures/synthetic/features/phase4-whole-home-manifest-v1.json`.
- Create `tests/unit/policy/test_phase4_amendments.py`.
- Create `tests/acceptance/whole_home/test_phase4_feature_absence.py`.
- Create `tests/security/whole_home/test_phase4_negative_reachability.py`.
- Modify `apps/admin/src/app/feature-registry.ts` only to register manifest-backed loaders.

**Interfaces:** Five exact amendment IDs from Authority rule 4. Feature IDs are `phase4.whole_home_voice.v1`, `phase4.media_single_player.v1`, conditional `phase4.music_assistant.v1`, `phase4.teaching_display.v1`, per-deployment conditional `phase4.television_control.v1`, `phase4.screen_time_real_adapter.v1`, and conditional `phase4.private_room_rollout.v1`. No two-session feature ID exists in this release.

- [ ] **Step 1: Write red amendment and absence tests**

```python
def test_phase4_features_require_policy_schema_migration_and_evidence() -> None:
    with pytest.raises(FeatureRegistrationDenied, match="missing whole_home_single_session_v1"):
        registry.register(synthetic_whole_home_voice_feature(amendments=()))

@pytest.mark.parametrize(
    "feature_id,direct_path",
    [
        ("phase4.music_assistant.v1", "/api/v1/media/music-assistant"),
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

Run: `uv run pytest tests/unit/policy/test_phase4_amendments.py tests/acceptance/whole_home/test_phase4_feature_absence.py tests/security/whole_home/test_phase4_negative_reachability.py -q`
Expected: FAIL because amendments/feature manifests are unknown.

- [ ] **Step 3: Implement evidence-bound registration**

Require contract/schema/policy/migration/build/evidence digests and exact adapter deployment bindings. Feature registration must be server-side, signed, and fail on missing/expired entitlement, consent, hardware evidence, firmware drift, TV generation change, MA gate failure, or renderer pairing loss. Build admin chunks behind dynamic imports keyed only by the signed feature manifest. Reject unknown Phase 4 IDs. Keep the production manifest empty by default.

- [ ] **Step 4: Prove absence at every surface**

Run:

```bash
uv run pytest tests/unit/policy/test_phase4_amendments.py tests/acceptance/whole_home/test_phase4_feature_absence.py tests/security/whole_home/test_phase4_negative_reachability.py -q
uv run python scripts/verify_feature_absence.py --phase 4 --surfaces package,config,environment,manifest,openapi,prepared-action,ui-bundle,runtime,listener
pnpm --filter @tuntun/admin build
```

Expected: PASS; disabled feature code is not registered or bundled, direct routes return 404, prepared-action issuance denies, network listeners are absent, and `household_conversation_slots=2` is rejected as an unknown configuration key.

- [ ] **Step 5: Commit exact registry paths**

```bash
git add packages/policy/src/tuntun_policy/registry.py packages/policy/src/tuntun_policy/corpora.py apps/core/src/tuntun_core/services/features/registry.py apps/core/src/tuntun_core/api/routes/features.py apps/admin/src/app/feature-registry.ts fixtures/synthetic/features/phase4-whole-home-manifest-v1.json tests/unit/policy/test_phase4_amendments.py tests/acceptance/whole_home/test_phase4_feature_absence.py tests/security/whole_home/test_phase4_negative_reachability.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(policy): register gated Phase 4 amendments"
```

### Task 05: Implement area voice policy, commissioning, occupant consent, and guardian co-approval

**Depends on:** Tasks 03–04 and the Phase 1 subject/guardian ceremony plus Phase 2 topology registry.
**Gate contribution:** P4-0, P4-2, P4-7.
**Estimated effort:** 3 person-days.

**Files:**

- Create `apps/core/src/tuntun_core/services/whole_home/{endpoint_registry,room_policy}.py`.
- Modify the existing subject/guardian prepared-decision service to accept `child_room_voice_coapprove` and `child_media_teaching_coapprove` exact commitments; do not create another ceremony service.
- Create `apps/core/src/tuntun_core/api/routes/whole_home.py` and add only read/prepare/decision endpoints backed by the feature registry.
- Test `tests/unit/whole_home/test_area_voice_policy.py`.
- Test `tests/integration/whole_home/test_area_commissioning.py`.
- Test `tests/security/whole_home/test_subject_guardian_ceremonies.py`.
- Test `tests/property/whole_home/test_area_policy_generations.py`.

**Interfaces:** `AreaVoicePolicyDecision evaluate(AreaVoicePolicyRequest)`; `EndpointRegistry.register(Registration, OwnerGrant)`; one exact prepared commitment binds `area_id`, endpoint, room class, occupant set, child, guardian generation, privacy policy generation, quiet hours, speech/music volume limits, expiry, and evidence digest.

- [ ] **Step 1: Write red closed-class and principal-separation tests**

```python
def test_child_private_requires_distinct_current_guardian(
    owner: Principal, guardian: Principal, policy: AreaVoicePolicy
) -> None:
    request = child_private_enable_request(owner=owner, guardian=guardian, policy=policy)
    assert evaluate(request).effect is PolicyEffect.ALLOW
    assert evaluate(replace(request, guardian=owner)).effect is PolicyEffect.DENY

@pytest.mark.parametrize("room_class", ["prohibited_sensitive", "unknown", "bathroom"])
def test_sensitive_or_unknown_area_class_cannot_enable_microphone(room_class: str) -> None:
    assert evaluate(synthetic_enable_request(room_class=room_class)).effect is PolicyEffect.DENY

def test_area_change_revokes_current_lease(area_policy: AreaPolicyHarness) -> None:
    lease = area_policy.issue_current_lease()
    area_policy.revoke_occupant_consent()
    assert area_policy.accept_frame(lease, sequence=1) is FrameDecision.STALE_PRIVACY_GENERATION
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/whole_home/test_area_voice_policy.py tests/integration/whole_home/test_area_commissioning.py tests/security/whole_home/test_subject_guardian_ceremonies.py tests/property/whole_home/test_area_policy_generations.py -q`
Expected: FAIL because `room_policy` and the Phase 4 decision types are absent.

- [ ] **Step 3: Implement restrictive commissioning**

Use the canonical topology `area_id` and current generation. Enforce:

- common-shared owner commissioning plus household notice;
- adult-private opt-in by every recorded adult occupant through their own subject-bound passkey;
- child-private owner configuration plus a distinct current primary guardian decision for the exact child/area/endpoint/policy;
- temporary-guest fixed expiry no later than seven days, no profile enrollment/private memory/unattended always-on;
- permanent denial for prohibited-sensitive;
- immediate generation increment/cancel on class, microphone, occupant, guardian, endpoint, quiet-hour, or consent change;
- physical mute is always accepted; software unmute is impossible;
- generic provider area descriptors only, never a person's name or sensitive area nickname.

The owner can inspect consent status and content-minimized commitments but cannot act as another adult or guardian. The child cannot satisfy any guardian slot.

- [ ] **Step 4: Run policy corpus and API object-authorization checks**

Run:

```bash
uv run pytest tests/unit/whole_home/test_area_voice_policy.py tests/integration/whole_home/test_area_commissioning.py tests/security/whole_home/test_subject_guardian_ceremonies.py tests/property/whole_home/test_area_policy_generations.py -q
uv run python packages/policy/scripts/run_corpus.py fixtures/synthetic/whole-home/policy-corpus-v1.jsonl
uv run pytest tests/security/api/test_object_authorization.py -q
```

Expected: PASS; stale/reassigned/revoked guardian, same-principal substitution, cross-child/cross-area/cross-endpoint substitution, expired ceremony, replay, unknown class, prohibited-sensitive, and missing consent deny and cancel active eligibility.

- [ ] **Step 5: Commit exact policy paths**

```bash
git add apps/core/src/tuntun_core/services/whole_home/endpoint_registry.py apps/core/src/tuntun_core/services/whole_home/room_policy.py apps/core/src/tuntun_core/api/routes/whole_home.py packages/policy/src tests/unit/whole_home/test_area_voice_policy.py tests/integration/whole_home/test_area_commissioning.py tests/security/whole_home/test_subject_guardian_ceremonies.py tests/property/whole_home/test_area_policy_generations.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(whole-home): govern area voice commissioning"
```

**Checkpoint P4-E0/P4-0:** Pause household enablement. Review schema/policy/migration/feature digests, no-`room_id` scan, simulator coverage, subject/guardian ceremony isolation, and production feature absence. Only simulator and hardware-probe tooling may proceed until the checkpoint is accepted.

---

## Wave 1 — P4-1/P4-2 Room Endpoint Safety, Bakeoff, Arbitration, and Routing

### Task 06: Scaffold the least-privilege room-node agent and local safety state machine

**Depends on:** Tasks 01–02.
**Gate contribution:** P4-0, P4-1.
**Estimated effort:** 2.5 person-days.

**Files:** Create `apps/room-node/pyproject.toml` and `apps/room-node/src/tuntun_room_node/{__init__,agent,config,protocol,health,update}.py`; create `ops/room-node/tuntun-room-node.service`, `ops/room-node/firewall.example.nft`, and `ops/room-node/tmpfiles.conf`; test `apps/room-node/tests/unit/test_agent_state.py` and `tests/security/whole_home/test_room_node_privileges.py`.

**Interfaces:** `RoomNodeAgent.run()`; closed lifecycle `BOOTING -> UNPAIRED -> IDLE_LOCAL_WAKE -> CLAIM_PENDING -> LEASED_CAPTURE -> PLAYING -> IDLE_LOCAL_WAKE`, with any uncertainty to `MUTED` or `ERROR_SAFE`. The agent owns no identity, policy, memory, provider, HA/MA, TV, owner API, or durable audio capability.

- [ ] Write red tests proving forbidden transition denial, zero inbound listener, owner-only config/key permissions, no swap/core dump for audio memory, and `ERROR_SAFE` on supervisor loss.
- [ ] Run `uv run pytest apps/room-node/tests/unit/test_agent_state.py tests/security/whole_home/test_room_node_privileges.py -q`; expect import failure.
- [ ] Implement a systemd service with `NoNewPrivileges=yes`, a dedicated account, read-only root, bounded memory/tasks/files, private temporary directory, core dumps disabled, and only the paired outbound Mac destination. Keep runtime state in `/run/tuntun-room-node` and keys in an owner-unreadable service directory; never mount household storage.
- [ ] Implement state transitions as a pure reducer and make `MUTED`/`ERROR_SAFE` preempt every normal event. On restart, clear candidate/lease/playback state and return to local safety discovery before `IDLE_LOCAL_WAKE`.
- [ ] Run `uv run pytest apps/room-node/tests tests/security/whole_home/test_room_node_privileges.py -q && uv run ruff check apps/room-node tests/security/whole_home/test_room_node_privileges.py && uv run mypy apps/room-node/src`; expect PASS.
- [ ] Commit with exact paths and `git commit -m "feat(room-node): scaffold fail-safe endpoint agent"`.

### Task 07: Implement endpoint-owned keys, pairing, mTLS WebSocket, registration, and revocation

**Depends on:** Tasks 03, 05–06 and the Phase 1 pairing/CA ports.
**Gate contribution:** P4-0, P4-1, P4-2.
**Estimated effort:** 3 person-days.

**Files:** Create `apps/room-node/src/tuntun_room_node/{pairing,keys}.py`, `apps/core/src/tuntun_core/services/whole_home/endpoint_gateway.py`, and `apps/core/src/tuntun_core/adapters/room_endpoints/websocket.py`; create `scripts/phase4/pair_endpoint.py`; test `tests/contract/whole_home/test_endpoint_channel.py`, `tests/integration/whole_home/test_endpoint_pairing.py`, and `tests/security/whole_home/test_endpoint_replay_revocation.py`.

**Interfaces:** Endpoint creates TLS-client and Ed25519 event-signing private keys locally; pairing sends public CSR/material only. Mac issues a household client certificate and separately rotatable commitment secret over the authenticated channel. `EndpointGateway.accept_registration` stores only public identity, evidence digests, and generations.

- [ ] Write red tests for private-key non-export, wrong CA/EKU/SAN, clone, nonce replay, stale sequence/session epoch, expired cert, revoked endpoint, changed firmware/model digest, and browser/HA-originated CSR denial.
- [ ] Run `uv run pytest tests/contract/whole_home/test_endpoint_channel.py tests/integration/whole_home/test_endpoint_pairing.py tests/security/whole_home/test_endpoint_replay_revocation.py -q`; expect missing gateway/pairing failures.
- [ ] Reuse Phase 1 bounded WebSocket framing and certificate rotation semantics. Add endpoint-protocol negotiation, clock/sequence diagnostics, heartbeats, max message/frame/queue/rate limits, and registration quarantine when any exact digest changes. Private key bytes must never cross the process boundary or be serializable.
- [ ] Verify `wss` is endpoint-initiated, binds only the configured private interface on the Mac edge gateway, rejects redirects/compression negotiation surprises, and exposes no room-node HTTP/debug listener.
- [ ] Run narrow tests plus `uv run pytest tests/security/test_channel_security.py -q` and `uv run python scripts/verify_private_data.py apps/room-node tests`; expect PASS and zero test key outside synthetic fixtures.
- [ ] Document revoke/re-pair/retire and certificate rotation in `docs/operations/phase4-endpoint-pairing.md`. Commit exact paths with `git commit -m "feat(whole-home): pair and revoke speech endpoints"`.

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

- [ ] Write red simulated tests that crash/freeze the agent, driver, GPIO/USB probe, indicator process, network process, and playback process at every boundary. Any absent/stale mute or indicator fact must produce zero next frame and `ERROR_SAFE`.
- [ ] Run simulated red tests; expect the supervisor API to be absent.
- [ ] Implement the safety supervisor as the sole holder of the endpoint network-audio send capability. Require `indicator.on_and_observed()` before granting a send permit; revoke permits synchronously on mute edge, stop, Privacy Shield, heartbeat loss, lease expiry, or probe uncertainty. Software “unmute” has no implementation.
- [ ] Add a marker-gated physical sentinel test that plays a known synthetic acoustic signal while muted and proves zero network frame and zero usable captured waveform across reboot, application crash, reconnect, update rollback, and malicious unmute request. Add indicator removal/freeze tests proving no egress without visible indication.
- [ ] Run `uv run pytest apps/room-node/tests/unit/test_safety_supervisor.py tests/fault/whole_home/test_indicator_fail_closed.py -q`, then on each exact candidate `TUNTUN_ALLOW_PHASE4_HARDWARE=1 uv run pytest tests/hardware/whole_home/test_endpoint_physical_safety.py -q`. Synthetic tests must pass before physical execution.
- [ ] Store real waveform/packet captures only in encrypted ignored evidence and delete working captures after aggregate/digest evidence. Any single physical privacy failure marks the candidate `REJECTED_PRIVACY` with no override.
- [ ] Commit code/tooling/runbook before the physical run using `git commit -m "feat(room-node): enforce physical mute and capture indication"`; never commit generated evidence.

### Task 10: Adapt Reachy to the common speech-endpoint contract without weakening Phase 1

**Depends on:** Tasks 01, 07–09 and the accepted Phase 1 Reachy transport/safety implementation.
**Gate contribution:** P4-0, P4-2.
**Estimated effort:** 2.5 person-days.

**Files:** Create `apps/core/src/tuntun_core/adapters/room_endpoints/reachy.py`; modify only the Phase 1 edge gateway seams required to emit the common logical events; test `tests/contract/whole_home/test_reachy_endpoint_adapter.py`, `tests/integration/whole_home/test_reachy_room_interop.py`, and `tests/privacy/whole_home/test_reachy_caps_preserved.py`.

**Interfaces:** `ReachySpeechEndpointAdapter` maps accepted Phase 1 wake, capture, playback, stop, privacy, sequence, and health events to `SpeechEndpointPort`. It does not claim a room-node physical mute if delivered Reachy hardware did not prove one; its distinct accepted Phase 1 safety facts remain truthful.

- [ ] Write red tests comparing pre/post-adapter Phase 1 caps, stop priority, camera isolation, audio retention, session sequence, gesture bounds, and Guest behavior. A common interface must not manufacture `hardware_muted=true`.
- [ ] Run red; expect missing adapter.
- [ ] Implement a translation layer only. Reuse the existing Reachy transport/keys and area binding; do not make Reachy re-pair as a generic Linux node or route its camera through Phase 4.
- [ ] Run `uv run pytest tests/contract/whole_home/test_reachy_endpoint_adapter.py tests/integration/whole_home/test_reachy_room_interop.py tests/privacy/whole_home/test_reachy_caps_preserved.py tests/unit/reachy tests/integration/reachy -q`; expect all Phase 1 regression tests unchanged.
- [ ] Commit exact adapter/tests with `git commit -m "feat(whole-home): adapt Reachy to room arbitration"`.

### Task 11: Implement deterministic duplicate-wake arbitration and loser destruction

**Depends on:** Tasks 02, 05, 07, and 10.
**Gate contribution:** P4-2.
**Estimated effort:** 3 person-days.

**Files:** Create `apps/core/src/tuntun_core/services/whole_home/wake_arbiter.py`; test `tests/unit/whole_home/test_wake_arbiter.py`, `tests/property/whole_home/test_duplicate_wake_arbitration.py`, and `tests/fault/whole_home/test_arbiter_restart.py`.

**Interfaces:** `WakeArbiter.arbitrate` consumes eligible metadata claims received within 350 ms and correlates possible duplicates within 1.5 seconds. Stable order: valid continuation token; confidence/SNR beyond calibrated hysteresis; earliest gateway receipt; stable endpoint ID.

- [ ] Write red tests for the entire 500-case corpus plus ties, skew, reordered/duplicated/replayed claims, stale generation, muted/indicator-unready/unhealthy endpoints, late claims, active-session other-area wake, and Mac restart.
- [ ] Run red; expect missing arbiter.
- [ ] Implement one deterministic pure decision function and a bounded decision-window coordinator. Room label, identity, profile permission, memory, or response sensitivity must not enter its score. Issue one single-use lease; send explicit cancel to every loser and wait only for bounded acknowledgements without delaying winner capture.
- [ ] Assert loser fakes clear candidate RAM even when cancel acknowledgement is lost; late frames are rejected at the gateway before provider authorization.
- [ ] Run `uv run pytest tests/unit/whole_home/test_wake_arbiter.py tests/property/whole_home/test_duplicate_wake_arbitration.py tests/fault/whole_home/test_arbiter_restart.py -q`; expect at least 500 cases with exactly one lease/stream/response and zero loser persistence.
- [ ] Commit with `git commit -m "feat(whole-home): arbitrate duplicate room wakes"`.

### Task 12: Enforce the single durable household conversation admission slot

**Depends on:** Tasks 03 and 11 plus the Phase 1 turn coordinator.
**Gate contribution:** P4-2 and negative Section 22.8 reachability.
**Estimated effort:** 3 person-days.

**Files:** Create `apps/core/src/tuntun_core/services/whole_home/conversation_admission.py`; extend the Phase 1 conversation coordinator only through the declared port; test `tests/integration/whole_home/test_single_conversation_admission.py`, `tests/property/whole_home/test_concurrent_admission.py`, and `tests/security/whole_home/test_second_slot_unreachable.py`.

**Interfaces:** `ConversationAdmissionService.admit` atomically inserts singleton slot `0` with winning endpoint/area, turn, effective identity mode, privacy generation, reservations, and expiry. It consumes the winning claim once. `cancel_all_on_startup` terminalizes stale admissions and sends cancellation; it never resumes listening/speech.

- [ ] Write red simultaneous-transaction tests, process-crash tests at every insert/outbox boundary, duplicate winner/replay tests, and direct attempts to use slot 1 or set capacity 2.
- [ ] Run red; expect missing service.
- [ ] Implement admission inside the serialized SQLCipher UoW with a partial unique index and audit/outbox. Provider budget reservation remains per admitted turn and occurs before provider egress. Release the slot only after capture/workflow/playback cancellation has settled or timed out truthfully.
- [ ] Do not add a concurrency setting. Add source/OpenAPI/config/UI/package assertions that `phase4.two_conversations.v1` and a slot-count mutation do not exist.
- [ ] Run all three tests with at least 10,000 concurrent seeded schedules; expect no double admission and no stale crash resume.
- [ ] Commit exact service/tests with `git commit -m "feat(whole-home): enforce one household conversation"`.

### Task 13: Route speech only to the current lease endpoint with audience-safe failure

**Depends on:** Tasks 05, 10, and 12 plus Phase 1 identity/policy/language services.
**Gate contribution:** P4-2.
**Estimated effort:** 3 person-days.

**Files:** Create `apps/core/src/tuntun_core/services/whole_home/reply_router.py`; test `tests/unit/whole_home/test_reply_router.py`, `tests/property/whole_home/test_private_reply_isolation.py`, and `tests/integration/whole_home/test_reply_delivery_cancellation.py`.

**Interfaces:** `RoomReplyRouter.resolve(ReplyRoutingRequestV1)` evaluates current endpoint/area/privacy generations, physical mute/playback health, answer sensitivity/audience, effective Guest/profile, consent, quiet hours, volume cap, turn UUID, lease, and cancellation. It returns one endpoint or a no-speech decision.

- [ ] Write red tests for the 1,000-case routing corpus: wrong/losing/stale/uncommissioned/muted/revoked endpoint, private answer, child disclosure, auth prompt, security response, Guest downgrade, endpoint disconnect, room consent change, quiet hours, and media group availability.
- [ ] Run red; expect missing router.
- [ ] Implement deny-by-default routing. If the endpoint cannot safely speak, use a bounded local nonverbal error where available and make the answer available only in the authenticated owner console; never search for another endpoint.
- [ ] Ensure old TTS frames contain turn/lease generation and are discarded on cancel, handoff, privacy, mute, identity downgrade, or newer barge-in. Do not persist answer text in routing audit.
- [ ] Run narrow tests; expected zero private reply on any wrong route and complete rejection of media group/TV speaker targets.
- [ ] Commit with `git commit -m "feat(whole-home): bind replies to the capture endpoint"`.

### Task 14: Add explicit handoff and endpoint-independent language following

**Depends on:** Tasks 05 and 12–13 plus the Phase 1 language tracker.
**Gate contribution:** P4-2 and P4-7.
**Estimated effort:** 2.5 person-days.

**Files:** Create `apps/core/src/tuntun_core/services/whole_home/handoff.py`; extend the closed offline/intent grammar with exact handoff intents; create `fixtures/synthetic/whole-home/language-room-corpus-v1.jsonl`; test `tests/unit/whole_home/test_handoff.py`, `tests/integration/whole_home/test_handoff_identity_policy.py`, and `tests/acceptance/whole_home/test_multilingual_room_prompts.py`.

**Interfaces:** `HandoffService.prepare_exact_target` returns a 30-second single-use token after exact target resolution and current-source announcement. Target wake consumes it only after fresh area/identity/consent checks. `LanguageTracker` remains keyed to conversation/turn, never endpoint/area.

- [ ] Write red tests for ambiguous alias, target offline/muted, expiry/replay, Guest, child-private guardian mismatch, identity conflict, source cancellation, policy generation change, and attempted transfer of auth/action grant.
- [ ] Add English/Hindi/Hinglish switch cases and human-reviewed fixed message IDs for wake/busy/privacy/stop/handoff/error/media ambiguity/teaching/screen-time. Short ambiguous utterances must preserve last stable mode.
- [ ] Run red; expect missing handoff service/message IDs.
- [ ] Implement exact target resolution through Phase 2 topology. Target receives no prior private content; a failed handoff becomes a new Guest turn only after a new wake. There is no passive microphone/camera/presence follow-me process.
- [ ] Run the three tests plus Phase 1 language corpus. Expect zero transferred authentication/approval/child authority and no endpoint-driven language change.
- [ ] Commit with `git commit -m "feat(whole-home): add explicit multilingual handoff"`.

### Task 15: Build purchased and DIY candidate adapters plus identical bakeoff tooling

**Depends on:** Tasks 06–09 and accepted procurement records.
**Gate contribution:** P4-1.
**Estimated effort:** 4.5 person-days before elapsed campaign.

**Files:** Create `scripts/phase4/{probe_purchased_endpoint,probe_diy_endpoint,run_endpoint_bakeoff}.py`; create candidate adapter modules under `apps/room-node/src/tuntun_room_node/adapters/` only for exact acquired revisions; create `fixtures/synthetic/whole-home/endpoint-candidates-v1.json`; create `docs/procurement/phase4-room-endpoint-bakeoff.md`, `docs/operations/phase4-endpoint-bakeoff.md`, and `docs/evidence/phase4-endpoint-bakeoff.schema.json`; test `tests/unit/whole_home/test_bakeoff_scoring.py` and `tests/hardware/whole_home/test_endpoint_candidate.py`.

**Interfaces:** Candidate record binds exact pseudonymous SKU/revision, firmware, replacement-firmware/transport method, wake/VAD source/licence/hash, audio formats, physical cutoff, indicator path, stop, power, enclosure, update/rollback, SBOM, acoustic placement, and evidence digest. Scoring may compare only candidates that pass every privacy/safety gate.

- [ ] Write red tests proving a candidate with superior acoustics but failed mute/indicator/licence/rollback is ineligible; marketing names such as “ReSpeaker” or “Voice Preview Edition” provide zero capability.
- [ ] Implement purchased-appliance probing that records whether stock or reproducibly reversible replacement firmware can satisfy `SpeechEndpointPort` without routing policy through Assist. Stock Assist behavior alone never passes.
- [ ] Implement DIY probing for exact SBC, microphone front end, amplifier/speaker, hardware cutoff circuit, indicator, stop input, supply, storage, enclosure, drivers, thermal/power, and rollback. No microphone board is selected by brand.
- [ ] Use the same calibrated synthetic/physical corpus, placement, volume/noise conditions, packet/content scans, energy meter, and owner-maintenance timer for both candidates. Probe scripts refuse real serial/MAC/IP output and write only pseudonymous encrypted ignored evidence.
- [ ] Run unit tests and a dry-run with synthetic candidates. Expect deterministic ineligible/pass results and no purchase recommendation from incomplete evidence.
- [ ] Commit tooling/docs/fixtures/tests before hardware use with `git commit -m "test(room-node): prepare purchased versus DIY bakeoff"`.

### Task 16: Run the physical common-area bakeoff, select/quarantine, and commission one winner

**Depends on:** Task 15, exact landed quotes/return terms, and owner authorization to operate the two candidate devices in one common area.
**Gate contribution:** P4-1, P4-2.
**Estimated effort:** 2.5 person-days plus two seven-day candidate runs and an eight-hour stress run each.

**Files:** Modify no production source unless a failed probe produces a separately reviewed task. Execute `scripts/phase4/run_endpoint_bakeoff.py`; validate with `scripts/phase4/verify_acceptance.py`; document procedure in `docs/operations/phase4-endpoint-bakeoff.md`. Generated evidence stays ignored.

- [ ] Capture the exact candidate records, same placement, room privacy notice, synthetic marker schedule, owner/operator, build/config digests, network capture point, plug meter, and rollback image before the first run.
- [ ] For each candidate, run seven elapsed days in the common area and one continuous eight-hour television/music/fan/cooking/family-noise stress window. Required thresholds: wake acknowledgement P95 ≤500 ms; family false rejects ≤5%; no more than one false wake per eight representative hours; stop/privacy P95 ≤250 ms; bounded CPU/RAM/thermal/queue/reconnect.
- [ ] Run at least 240 accepted-quality English/Hindi/Hinglish requests and publish aggregate error by language/noise/distance, target at least 95% correct completion. Family speech needed for acoustic validation remains encrypted local evidence and is deleted according to the campaign runbook; Git gets only aggregates/commitments.
- [ ] Repeat hardware mute across reboot, agent crash, reconnect, update/rollback, and malicious unmute; repeat indicator fail-safe by crashing/freezing every user-space layer; scan files, swap awareness, logs, crash reports, backups, and packet captures for durable audio.
- [ ] Execute:

```bash
TUNTUN_ALLOW_ENDPOINT_PROBE=1 uv run python scripts/phase4/run_endpoint_bakeoff.py --candidate purchased --duration-seconds 604800 --stress-seconds 28800 --evidence-root var/evidence/phase4/endpoints
TUNTUN_ALLOW_ENDPOINT_PROBE=1 uv run python scripts/phase4/run_endpoint_bakeoff.py --candidate diy --duration-seconds 604800 --stress-seconds 28800 --evidence-root var/evidence/phase4/endpoints
uv run python scripts/phase4/verify_acceptance.py endpoint-bakeoff --evidence-root var/evidence/phase4/endpoints
```

- [ ] Record `SELECTED`, `BOTH_ELIGIBLE`, or `NO_ELIGIBLE_CANDIDATE`. Select on privacy truthfulness, acoustics, recoverability, updates, idle power, and maintenance—not customization preference. A loser is unpaired and removed or retained as a synthetic-only developer fixture.
- [ ] Pair only one winning candidate to one common `area_id`, run Tasks 11–14 physical interop with Reachy, and keep every private/additional room feature absent.
- [ ] No source/evidence commit is made here. If tooling changed, stop, commit/review it separately, invalidate the prior run, and repeat from the clean commit.

**Checkpoint P4-1/P4-2:** Owner reviews the physical evidence and selects the accepted endpoint type. No fleet replication occurs. A failed bakeoff leaves Reachy as the only endpoint and does not block later simulator/manual-display work.

---

## Wave 2 — P4-3 Entitled Media, Signed Bridge, and Optional Music Assistant

### Task 17: Implement legal-provider reviews, player bindings, and opaque catalog handles

**Depends on:** Tasks 01, 03–05 and accepted Phase 2 topology.
**Gate contribution:** P4-3.
**Estimated effort:** 3 person-days.

**Files:** Create `apps/core/src/tuntun_core/services/whole_home/{media_catalog,media_policy}.py`; create `apps/core/src/tuntun_core/api/routes/media.py`; create `fixtures/synthetic/whole-home/players-providers-v1.json`; test `tests/unit/whole_home/test_media_entitlement.py`, `tests/unit/whole_home/test_catalog_handles.py`, `tests/security/whole_home/test_media_input_boundary.py`, and `tests/privacy/whole_home/test_media_credential_absence.py`.

**Interfaces:** `ProviderRegistry.enable(binding, entitlement_review, owner_grant)`; `MediaCatalogService.search` returns bounded opaque handles bound to provider/account/item/classification/adapter/result generation/expiry; `resolve_handle` is single-purpose, current-policy checked, and never returns a URI to model/browser code.

- [ ] Write red tests for missing/expired/region-changed/legal-unclear/unofficial/scraping/credential-exporting providers; arbitrary URL/redirect/private address/path/provider URI; oversized query; expired/replayed/substituted handle; and child explicit/unknown classification.
- [ ] Run `uv run pytest tests/unit/whole_home/test_media_entitlement.py tests/unit/whole_home/test_catalog_handles.py tests/security/whole_home/test_media_input_boundary.py tests/privacy/whole_home/test_media_credential_absence.py -q`; expect missing services.
- [ ] Implement 90-day maximum entitlement review, immediate invalidation on adapter/account/terms/region change, and no silent provider substitution. Store only opaque provider binding and capability digest. A normalized catalog query and raw results live in bounded process memory; ordinary audit stores keyed commitments and result count/class only.
- [ ] Require a short spoken choice for ambiguity and mint a handle only from an adapter-returned registered result. Models cannot construct, edit, broaden, or refresh handles.
- [ ] Run the four tests and `uv run python scripts/verify_private_data.py apps/core fixtures/synthetic/whole-home`. Expect no reusable provider/MA/HA credential, query text, URI, account ID, or real entitlement data.
- [ ] Commit exact paths with `git commit -m "feat(media): gate entitled catalog handles"`.

### Task 18: Implement exact adult, child, Guest, confirmation, and passkey media policy

**Depends on:** Tasks 04–05 and 17 plus Phase 1 identity/auth and Phase 2 Designated Guest semantics.
**Gate contribution:** P4-3.
**Estimated effort:** 3 person-days.

**Files:** Extend `apps/core/src/tuntun_core/services/whole_home/media_policy.py`; reuse the shared prepared-action and subject/guardian ceremony services; create `tests/unit/whole_home/test_media_policy_matrix.py`, `tests/property/whole_home/test_media_authorization.py`, and `tests/security/whole_home/test_child_media_guardian_slots.py`.

**Interfaces:** `MediaPolicyService.authorize(AuthorizedMediaRequestV1) -> MediaAuthorizationDecisionV1`. Server constructs the exact request binding and returns only the frozen allow/deny/step-up shape. An allow selects one authorization class: adult reversible immediate, exact confirmation, owner passkey, Designated Guest owner co-approval, or preconfigured child rule with distinct guardian approval.

- [ ] Write red corpus tests for actor/evidence, item/transport/provider/group/volume/persistence risk, room/player binding, quiet hours, content class, stale observation, owner/guardian generations, same-principal substitution, and restrictive identity conflict.
- [ ] Implement `home_reversible_media_v1` only for one identified adult, one unambiguous registered single-player pause/resume/stop or small configured transport/volume operation, with fresh evidence and no provider/item/area/group/persistence change.
- [ ] Require exact confirmation for starting a new item, provider change, transfer, material volume, and immutable group. Require owner passkey for provider/account, group definition, child rule, binding/adapter, queue/routine/policy changes.
- [ ] Guest/anonymous media remains disabled. A Designated Guest request may be held only by an owner-created bounded common-area session and still needs a fresh owner passkey for that exact action.
- [ ] Enforce child rule commitment over child, exact `area_id`, players, providers/content classes or exact guardian-selected handles, volume, hours, policy generation, owner configuration, and distinct current guardian approval. Purchases, explicit/unknown content, broad groups, accounts, policy, and persistent routines deny.
- [ ] Run `uv run pytest tests/unit/whole_home/test_media_policy_matrix.py tests/property/whole_home/test_media_authorization.py tests/security/whole_home/test_child_media_guardian_slots.py -q` and the Phase 4 policy corpus; expect zero over-broad grant.
- [ ] Commit with `git commit -m "feat(media): enforce household media policy"`.

### Task 19: Extend the signed Home Assistant bridge with closed media receipts and dispatch

**Depends on:** Tasks 01, 03, 17–18 and the accepted Phase 2 bridge channel/key/receipt store.
**Gate contribution:** P4-3 and P4-7 recovery.
**Estimated effort:** 3.5 person-days.

**Files:** Create `integrations/home-assistant/custom_components/tuntun_bridge/{media,media_schema}.py`; modify `const.py`, `http.py`, `store.py`, and `backup.py` additively; create `apps/core/src/tuntun_core/adapters/media/home_assistant.py`; test `integrations/home-assistant/tests/test_media_route.py`, `integrations/home-assistant/tests/test_media_receipts.py`, `tests/integration/whole_home/test_signed_media_bridge.py`, and `tests/security/whole_home/test_no_general_ha_media_route.py`.

**Interfaces:** Separate signature domain/route `tuntun-media-v1`; compiled provider/player/catalog binding IDs; HA lifecycle `PRE_DISPATCH -> DISPATCHING -> RECONCILING -> VERIFIED | ACCEPTED_UNVERIFIED | PARTIAL | FAILED | UNKNOWN | EXPIRED`; pre-dispatch durable receipt before service I/O and Phase 2 timing/idempotency/epoch rules.

- [ ] Write red tests for wrong signature domain/key/controller epoch/topology/binding/provider generation, stale/expired envelope, nonce/idempotency replay, unknown action/target, caller-supplied entity/service/URI/path, duplicate dispatch, crash at every receipt transition, quota pressure, and restore.
- [ ] Run red; expect route/schema/store support absent.
- [ ] Implement only the seven initial media actions. Translation uses a compiled binding and Home Assistant system context; request fields cannot select entity/service/template/event. Store minimized action/target commitments and result facts, never actor, transcript, catalog query, provider result body, or credential.
- [ ] Preserve the Phase 2 100 MiB quota/retention/nonterminal rules and backup disclosure. A potentially dispatched uncertain row is reconciled, never redispatched. Failed primary provider/player path does not call another path.
- [ ] Run `uv run pytest integrations/home-assistant/tests/test_media_route.py integrations/home-assistant/tests/test_media_receipts.py tests/integration/whole_home/test_signed_media_bridge.py tests/security/whole_home/test_no_general_ha_media_route.py -q` and full Phase 2 bridge regression tests.
- [ ] Commit exact HA/Mac adapter paths with `git commit -m "feat(ha-bridge): add closed signed media actions"`.

### Task 20: Gate the optional Music Assistant adapter on exact deployment evidence

**Depends on:** Task 19; exact owner-approved MA/HA versions and one legal provider/player candidate.
**Gate contribution:** optional part of P4-3.
**Estimated effort:** 3 person-days plus physical/elapsed tests.

**Files:** Create `integrations/music-assistant/README.md` and `integrations/music-assistant/tuntun_ma_adapter/{__init__,capabilities,catalog,playback}.py`; create `scripts/phase4/qualify_music_assistant.py` and `docs/evidence/phase4-music-assistant.schema.json`; test `integrations/music-assistant/tests/test_closed_adapter.py`, `tests/security/whole_home/test_ma_admin_unreachable.py`, and `tests/hardware/whole_home/test_music_assistant_gate.py`.

**Interfaces:** The optional adapter exposes only the closed `MediaCatalogPort`/`MediaPlaybackPort` through the HA bridge's compiled binding. Tuntun never stores or sends a general MA API key/admin credential. Production registration requires a signed evidence digest for exact MA application/integration, Green resources/storage/backups, provider/player adapters, ports/discovery/cloud dependencies, history/scrobbling setting, and rollback.

- [ ] Write red tests proving no general MA HTTP/WebSocket/admin/library-management/provider-enrollment route, credential field, arbitrary URI, queue mutation, account switch, history fetch, or redirect.
- [ ] Implement capability translation and stable opaque bindings. Default optional history/scrobbling off; inventory unavoidable provider history/telemetry and backup scope. Keep MA unavailable when absolute safe volume or truthful player state cannot be obtained.
- [ ] Run synthetic tests first. Then owner-gated qualification covers catalog, ambiguity, play/pause/resume/stop, absolute volume, queue, reboot, Green backup/restore, WAN loss, MA outage, player manual control, token revocation, provider expiry, upgrade/rollback, and resource/thermal/storage measurements.
- [ ] Execute `TUNTUN_ALLOW_MEDIA_PROBE=1 uv run python scripts/phase4/qualify_music_assistant.py --evidence-root var/evidence/phase4/media/music-assistant` and verify content-safe evidence.
- [ ] If any gate fails, keep `phase4.music_assistant.v1` absent and use only the accepted HA single-player path or no media. Do not weaken the boundary with a direct token.
- [ ] Commit adapter/tooling/tests before the hardware run with `git commit -m "feat(media): add gated Music Assistant adapter"`; never commit owner evidence.

### Task 21: Commit, sign, dispatch, and truthfully reconcile media actions and groups

**Depends on:** Tasks 03 and 17–20.
**Gate contribution:** P4-3.
**Estimated effort:** 3.5 person-days.

**Files:** Create `apps/core/src/tuntun_core/services/whole_home/{media_coordinator,media_reconciliation}.py`; create `apps/core/src/tuntun_core/adapters/media/music_assistant.py`; test `tests/integration/whole_home/test_media_action_lifecycle.py`, `tests/property/whole_home/test_media_groups.py`, `tests/fault/whole_home/test_media_crash_recovery.py`, and `tests/performance/whole_home/test_safe_start_volume.py`.

**Interfaces:** `MediaCoordinator.execute(AuthorizedMediaRequestV1, MediaAuthorizationDecisionV1, AuthContext) -> UUID` consumes the canonical Phase 1 `AuthContext`, requires its exact action binding to match the still-current allow decision, and commits the immutable operation/action/audit/outbox before signing or I/O. `MediaReconciliationService.reconcile(operation_id: UUID, observations: tuple[PlayerObservationV1, ...]) -> MediaOperationResultV1` maps fresh observations to complete manifest-ordered per-player results and the exactly derived aggregate outcome.

- [ ] Write red tests for crash before/after auth commit, sign, HA receipt, player call, and observation; duplicate submit; changed group/provider/binding; partial group; stale/unknown volume; manual changes; quiet hours; unsupported seek; result timeout; and alternate-protocol retry attempt.
- [ ] Implement UoW commit and grant consumption, then sign outside the writer lock. Freshly observe target state and set absolute bounded start volume before play. If absolute volume is unsupported/unknown, deny new playback.
- [ ] Groups are 1..configured maximum immutable members, exact generation and per-member cap. Confirmation names every `area_id`. A group never receives private speech/auth/child/security content.
- [ ] Reconcile `VERIFIED_PLAYING` only from adequate fresh observation. `PARTIAL` requires complete ordered members with mixed terminal outcomes. Unknown never collapses to success or triggers another provider/protocol.
- [ ] Run the four tests plus 500 adversarial media corpus cases. Expect zero unauthorized fetch/playback, double start, wildcard expansion, loud unknown-volume start, credential disclosure, private broadcast, or false atomic success.
- [ ] Commit with `git commit -m "feat(media): reconcile deterministic playback"`.

### Task 22: Add owner media/provider/player/group UI and truthful operation results

**Depends on:** Tasks 04 and 17–21 plus the shared admin shell/design system.
**Gate contribution:** P4-3 and UI acceptance.
**Estimated effort:** 3 person-days.

**Files:** Create `apps/admin/src/features/media-learning/{index,media}.tsx` and `apps/admin/src/routes/media-learning-media.tsx`; modify `apps/core/src/tuntun_core/api/phase4_dtos.py` and `apps/core/src/tuntun_core/api/routes/media.py`; generate UI contracts; create `tests/ui/media-learning/media.spec.tsx` and `tests/ui/e2e/media-learning-media.spec.ts`.

**Interfaces:** Bounded read models expose entitlement state/expiry, capability digest, player `area_id`/freshness/volume semantics/manual fallback, immutable groups, safe current queue summary, operation result strength, and no secret/query/private title beyond current audience. Mutations use server-prepared exact summaries and the shared `428 step_up_required` flow.

- [ ] Write red route, direct-API, prepared-action, stale/multi-tab/replay, child/Guest access, result-correlation, and absent-MA tests. Add English/Hindi, 320 px, 200% zoom, keyboard, VoiceOver/axe, light/dark, and reduced-motion fixtures.
- [ ] Implement feature-gated navigation and separate transport/provider/account truth. Never show optimistic playback; show request sent, then verified/accepted-unverified/partial/failed/unknown with source/freshness.
- [ ] Render MA as absent with an evidence reason, not as a disabled setup shortcut. Provider credentials link only to the independently owner-controlled HA/MA admin instructions; they never enter a Tuntun form.
- [ ] Run `pnpm --filter @tuntun/admin test -- media-learning/media.spec.tsx && pnpm --filter @tuntun/admin exec playwright test tests/e2e/media-learning-media.spec.ts && pnpm --filter @tuntun/admin lint && pnpm --filter @tuntun/admin typecheck && pnpm --filter @tuntun/admin build`.
- [ ] Run browser storage/cache/history/log scans; expect no provider credential, query text, reusable URI, private title leak, or absent-feature chunk.
- [ ] Commit API/generated/UI/test exact paths with `git commit -m "feat(admin): add truthful media management"`.

**Checkpoint P4-3:** Enable one provider and one player only after exact physical qualification. Manual player controls remain. Music Assistant is either separately accepted and registered or provably absent.

---

## Wave 3 — P4-4 Signed Closed Teaching Renderer and Guarded Learning

### Task 23: Build audience-bound teaching policy and closed manifest construction

**Depends on:** Tasks 01, 03–05 and accepted Phase 1 audience/child-safety/DLP/memory services plus Phase 2 screen-time policy.
**Gate contribution:** P4-4.
**Estimated effort:** 3.5 person-days.

**Files:** Create `apps/core/src/tuntun_core/services/whole_home/{teaching_policy,teaching_content,display_sessions}.py`; create `apps/core/src/tuntun_core/api/routes/teaching.py`; test `tests/unit/whole_home/test_teaching_policy.py`, `tests/unit/whole_home/test_manifest_builder.py`, `tests/security/whole_home/test_teaching_injection.py`, and `tests/privacy/whole_home/test_display_minimization.py`.

**Interfaces:** `TeachingPolicyService.authorize(TeachingRequestV1) -> TeachingAuthorizationDecisionV1`; the service returns a populated `AuthorizedTeachingRequestV1` only for an allow. `TeachingContentBuilder.build(AuthorizedTeachingRequestV1) -> UnsignedTeachingSessionDraft`; `DisplaySessionService.prepare(draft) -> TeachingSessionManifestV1` atomically commits session/audit/outbox before constructing and signing the final wire manifest. The builder accepts already authorized derived content, never a memory repository or general prompt/tool.

`web_mode` reuses the canonical Phase 1 wire values `no_web | controlled`; Phase 4 does not introduce another alias and never accepts `experimental_multi_pass` for teaching. Child and Guest requests/manifests are immutably `no_web`. An adult `controlled` request requires the exact current single-use Phase 1 controlled-web authorization commitment, consumed before content construction; only its normalized cited output may become closed components. The display agent itself performs zero web requests in every mode.

```python
@dataclass(frozen=True, slots=True)
class UnsignedTeachingSessionDraft:
    request_id: UUID
    correlation_id: UUID
    display_id: StableEndpointId
    area_id: StableHomeId
    display_generation: int
    audience_binding: TeachingAudienceBindingV1
    policy_version: PolicyVersion
    web_mode: Literal["no_web", "controlled"]
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
```

`UnsignedTeachingSessionDraft` is process-internal and cannot parse as or be passed to `TeachingSessionManifestV1`/`DisplaySessionPort`. `prepare` validates positive generation, aware bounded expiry, component/asset caps and current audience/policy again, persists the canonical draft commitment, then signs the final manifest only after the transaction commit callback.

- [ ] Write red tests for adult/child/Guest audiences, identity downgrade, wrong display/area, stale guardian/screen-time policy, canonical fixed/read-only child `web_mode=no_web`, zero child search calls, live-web child request, adult-private memory injection, arbitrary markup/URL/path, scriptable SVG, MIME mismatch, oversize/decompression bomb, missing provenance, and expiry over session/two hours.
- [ ] Run `uv run pytest tests/unit/whole_home/test_teaching_policy.py tests/unit/whole_home/test_manifest_builder.py tests/security/whole_home/test_teaching_injection.py tests/privacy/whole_home/test_display_minimization.py -q`; expect missing services.
- [ ] Implement adult cited explanations and owner material within current audience; K2/N1 use the Phase 1 guarded-learning policy and closed child-safe component subset; Guest gets generic unpersonalized content. Child live search is absent; a guardian/owner may select only preapproved local teaching packs with provenance/expiry.
- [ ] Build an internal frozen `UnsignedTeachingSessionDraft` containing only request/correlation IDs, target display/area and generation, audience/policy binding, closed component tuple, hash-addressed asset descriptors, and bounded expiry after DLP/child-safety/type/size/provenance checks. It has no signing fields and is not accepted by `DisplaySessionPort`. Do not serialize profile, memory record, prompt, transcript, child response, browser credential, action grant, or television authority.
- [ ] `DisplaySessionService.prepare` derives the final session ID and draft commitment, commits session/audit/outbox in one transaction, then constructs and signs `TeachingSessionManifestV1` under `tuntun-display-manifest-v1`. A test spy must prove the signer is unreachable before commit and that commit/sign failure yields no present call. Reusing a session ID with another digest/audience/display/asset denies. Voice, display, and TV control retain separate operation IDs under one correlation ID.
- [ ] Run the four tests plus child-safety corpus; expect all critical cases pass and no private sentinel in serialized manifest.
- [ ] Commit exact service/API/tests with `git commit -m "feat(teaching): build closed audience-bound manifests"`.

### Task 24: Pair and harden the local display agent and kiosk boundary

**Depends on:** Tasks 01, 07, and 23.
**Gate contribution:** P4-4.
**Estimated effort:** 3.5 person-days.

**Files:** Create `apps/display-agent/pyproject.toml` and `apps/display-agent/src/tuntun_display_agent/{__init__,agent,config,pairing,manifest,assets,clear,hdmi,health,kiosk}.py`; create `ops/display-agent/{tuntun-display-agent.service,kiosk-policy.json,firewall.example.nft}`; create `scripts/phase4/pair_display.py`; test `apps/display-agent/tests/test_pairing_and_manifest.py`, `tests/security/whole_home/test_display_process_boundary.py`, and `tests/privacy/whole_home/test_display_filesystem_empty.py`.

**Interfaces:** Display agent generates its own paired keys, initiates outbound pinned TLS to Tuntun Core, validates manifest signature/session/display/audience/policy/generation/expiry/quota, fetches each asset once through a single-use local handle, validates type/length/hash, and reports signed lifecycle/HDMI receipts.

- [ ] Write red tests for wrong CA/key/display/session/audience/policy/generation, replay, expired handle, second fetch, changed asset, redirect, public/private alternate origin, browser permission, inbound listener, writable persistent profile/cache, screenshot, camera/mic, shell, extension, and crash dump.
- [ ] Implement a dedicated service account, ephemeral Chromium profile under tmpfs, read-only root, no password manager/sync/extensions/downloads/devtools/remote debugging, camera/mic/WebRTC/geolocation/notifications/clipboard/file permissions denied, no public DNS route for lesson rendering, and one pinned local origin.
- [ ] Use CSP baseline `default-src 'none'` and only the minimum hash/non-network sources needed by compiled code and in-memory blob-free assets. Do not use data URLs or service workers. Disable disk HTTP cache, browser history persistence, screenshots, screen recording, and crash upload.
- [ ] Clear keys only through device retirement, but clear every session asset/profile object on end/expiry/privacy/reboot. A disconnect never creates an owner API or offline content-browsing route.
- [ ] Run `uv run pytest apps/display-agent/tests tests/security/whole_home/test_display_process_boundary.py tests/privacy/whole_home/test_display_filesystem_empty.py -q` plus listener/filesystem/network scans in the Linux test image.
- [ ] Document pairing/retirement and manual recovery in `docs/operations/phase4-display-agent.md`. Commit exact paths with `git commit -m "feat(display): pair hardened local kiosk agent"`.

### Task 25: Implement the finite renderer, asset verifier, expiry supervisor, and neutral clear

**Depends on:** Task 24 and the shared design system's display-safe primitives.
**Gate contribution:** P4-4.
**Estimated effort:** 3.5 person-days.

**Files:** Create `apps/display-agent/package.json` and `apps/display-agent/src-ui/{main,manifest-validator,expiry-supervisor,neutral-screen}.tsx` plus exact files under `components/` for the nine component variants; create `apps/display-agent/tests/renderer.spec.tsx` and `tests/ui/e2e/display-agent-security.spec.ts`.

**Interfaces:** `renderManifest(manifest: TeachingSessionManifestV1)` dispatches only exhaustive discriminated variants. Unknown variant/version fails to the locally bundled neutral screen before any asset fetch. `ExpirySupervisor` clears at the earliest session/manifest/privacy/identity/screen-time deadline.

- [ ] Write red component tests for all valid variants and at least 500 invalid manifests: unknown/extra field, HTML/script/event handler/style injection, URL/path/iframe/form/download, SVG script, malformed Unicode, huge text/list, asset hash/type/length/decompression failure, replay, identity downgrade, stop/privacy, and renderer restart.
- [ ] Implement each component with React text nodes and fixed design-system classes only. No `dangerouslySetInnerHTML`, runtime CSS, dynamic component name, eval/function constructor, external font/icon, or browser navigation. Multiple choice returns only a closed option index under the current session channel.
- [ ] Verify assets into bounded memory before render and revoke their handles. Enforce aggregate manifest/asset quotas before allocating/decompressing. The neutral screen contains no subject/lesson detail and is available without Mac/network.
- [ ] Add local labelled stop/pause controls, large child type, keyboard/touch reachability, reduced motion, high contrast, English/Hindi strings, and 320 px/200% zoom behavior. Stop sends a signed event but clears locally even if disconnected.
- [ ] Run `pnpm --filter @tuntun/display-agent test && pnpm --filter @tuntun/display-agent exec playwright test tests/e2e/display-agent-security.spec.ts && pnpm --filter @tuntun/display-agent lint && pnpm --filter @tuntun/display-agent typecheck && pnpm --filter @tuntun/display-agent build`.
- [ ] Inspect production bundle for forbidden network/navigation/dangerous APIs and commit with `git commit -m "feat(display): render finite teaching components"`.

### Task 26: Implement display lifecycle, Privacy Shield clear truth, and RAM-only learning summary

**Depends on:** Tasks 03, 23–25 and the canonical Privacy Shield effect registry.
**Gate contribution:** P4-4, privacy and memory gates.
**Estimated effort:** 3 person-days.

**Files:** Create `apps/core/src/tuntun_core/services/whole_home/{ephemeral_learning_summary,privacy_effects}.py` and `scripts/phase4/check_ephemeral_summary_imports.py`; extend `display_sessions.py`; modify the shared `p4.room_media_display` and `shared_display_projection` effect handlers; test `tests/unit/whole_home/test_ephemeral_learning_summary.py`, `tests/integration/whole_home/test_display_lifecycle.py`, `tests/privacy/whole_home/test_display_clear_truth.py`, and `tests/security/whole_home/test_no_learning_summary_persistence.py`.

**Interfaces:** `EphemeralLearningSummaryStore` is a process-local capped map with fake-clock expiry; it has no serialization/repository/back-up hook. `DisplaySessionService.clear` revokes asset handles first, sends clear, and records acknowledged/unverified separately. Display clear acknowledgement target is P95 ≤1 second; missing receipt never claims pixels disappeared.

- [ ] Write red tests for completion, dismissal, five-minute expiry, session end, identity downgrade, Privacy Shield, process restart, memory pressure eviction, and attempts to include free-form notes/raw child speech. Search DB/audit/backup/browser/display disk for a summary sentinel.
- [ ] Implement broad topic code, bounded duration bucket, and broad completion class only. Expose the end card to the current paired display for at most five minutes or until the earlier terminating event. Do not include a free-form notes field.
- [ ] A durable-learning request creates a new minimized `MemoryProposalDraft` through the Phase 1 child-memory service; it is not a conversion or copy of the cache and remains uncommitted until current `child_durable_memory_v1` consent plus exact guardian proposal approval. Raw child speech is invalid proposal content.
- [ ] On Privacy Shield, atomically revoke display authority/fetch handles with the shared privacy generation, then request clear. Show `authority_revoked`, `acknowledged`, or `unverified` independently. Independently controlled TV pixels/input may require physical action.
- [ ] Run the four tests plus `uv run python scripts/phase4/check_ephemeral_summary_imports.py`. The checker permits only the service/composition root and forbids repository, migration, audit, backup, API persistence, and browser-storage imports. Expect no persistence path.
- [ ] Commit exact paths with `git commit -m "feat(teaching): keep learning summaries ephemeral"`.

### Task 27: Add teaching setup, guardian ceremony, display status UI, and manual-HDMI acceptance

**Depends on:** Tasks 05 and 23–26.
**Gate contribution:** P4-4 and UI/physical acceptance.
**Estimated effort:** 3 person-days plus both-TV manual display checks.

**Files:** Create `apps/admin/src/features/media-learning/teaching.tsx` and `apps/admin/src/routes/media-learning-teaching.tsx`; extend `apps/core/src/tuntun_core/api/routes/teaching.py` and generated UI contracts; create `tests/ui/media-learning/teaching.spec.tsx`, `tests/ui/e2e/media-learning-teaching.spec.ts`, and `tests/hardware/whole_home/test_manual_hdmi_teaching.py`.

**Interfaces:** Owner prepares exact display session/rule; distinct current guardian uses the existing one-use local ceremony and `child_media_teaching_coapprove` for child, subject/topic pack, duration, display, canonical `web_mode=no_web` fixed and read-only for child, content policy, screen-time rule, and stop parameters. The display read model contains manifest/session policy, audience/language, HDMI readiness, expiry, and clear truth—not lesson/memory bodies.

- [ ] Write red owner/guardian distinctness, stale ceremony, cross-child/display/area/topic substitution, child self-approval, Guest personalization, absent renderer, stale HDMI, missing clear receipt, and direct route/API tests.
- [ ] Implement setup/review/status screens with safe immutable summary, no owner authority on the shared display, and no non-owner navigation from the one-use guardian ceremony. Display the RAM-only end card as ephemeral and explain the separate durable-memory proposal.
- [ ] Add loading/empty/error/stale/degraded/privacy/manual-input states; keyboard/axe/VoiceOver; English/Hindi/mixed-script; light/dark; reduced motion; 320 px and 200% zoom.
- [ ] Run UI tests/build and browser persistence scan. Then physically connect the paired renderer to each Samsung and TCL via labelled HDMI and test manual power/input, unplug/replug, resolution/overscan, audio routing, sleep, renderer reboot, and TV restart. Do not invoke TV control.
- [ ] Expected: a valid lesson works on each TV while each remains `DISPLAY_ONLY_MANUAL`; no UI/audit evidence claims TV power/input control; stop/privacy neutralizes renderer at P95 ≤1 second or displays unverified with physical instructions.
- [ ] Commit code/tests/runbook before physical execution with `git commit -m "feat(admin): add guarded teaching sessions"`; evidence remains ignored.

**Checkpoint P4-4:** The renderer may serve one manual-input teaching surface only after closed-manifest, no-public-network, child-safety, volatile-cache, clear-truth, guardian, accessibility, and physical HDMI gates pass.

---

## Wave 4 — P4-5/P4-6 Exact Television Qualification and Real Screen-Time Enforcement

### Task 28: Inventory and separately probe both exact physical televisions

**Depends on:** Task 03, manual HDMI acceptance from Task 27, and owner authorization for read-only/local pairing probes.
**Gate contribution:** P4-5.
**Estimated effort:** 3 person-days plus physical probes.

**Files:** Create `apps/core/src/tuntun_core/services/whole_home/tv_registry.py`; create `scripts/phase4/probe_television.py`; create `fixtures/synthetic/whole-home/televisions-v1.json`; create `docs/operations/phase4-tv-qualification.md`, `docs/procurement/phase4-tv-adapters.md`, and `docs/evidence/phase4-tv-inventory.schema.json`; test `tests/unit/whole_home/test_tv_inventory.py` and `tests/hardware/whole_home/test_tv_read_only_probe.py`.

**Interfaces:** Two deployment inventory entries are required: `tv_samsung_neoled_49` and `tv_tcl_42`. Source fixtures use synthetic IDs. Each local record captures full model code, year, OS/platform, firmware, network integration/pairing, HDMI ports/CEC configuration, IR profile, Wake-on-LAN, manual-control behavior, candidate control/observation paths, and capability generation. Serial/MAC/account/pairing secrets remain encrypted deployment data.

- [ ] Write red tests proving the household description, brand, diagonal, network reachability, HDMI hotplug, or HA discovery cannot advance a TV beyond `DISPLAY_ONLY_MANUAL`.
- [ ] Implement a read-only-first probe. Native API, CEC, IR, and observation findings are separate tri-state records: supported, unsupported, or unknown. Do not send mutations during inventory.
- [ ] Execute both exact commands from Standard Commands. Capture each unit independently; a result for one cannot populate the other. Record exact firmware/config but output only pseudonymous commitments and safe capability facts.
- [ ] Validate that any firmware/OS/pairing/network/HDMI/CEC/IR/observation change increments generation, invalidates prepared actions, and returns the unit to its last truthfully supported lower state.
- [ ] Run unit and marker-gated read-only tests. Expected: both inventory entries exist and remain `DISPLAY_ONLY_MANUAL` unless a later task supplies positive mutation/observation evidence.
- [ ] Commit tooling/fixtures/docs/tests before physical use with `git commit -m "feat(television): inventory exact household units"`; never commit real identifiers/evidence.

### Task 29: Add signed closed television actions and independently selectable adapter implementations

**Depends on:** Tasks 01, 03, and 28 plus the accepted Phase 2 signed bridge lifecycle.
**Gate contribution:** P4-5.
**Estimated effort:** 4.5 person-days.

**Files:** Create `integrations/home-assistant/custom_components/tuntun_bridge/{television,television_schema,observations}.py`; create `apps/core/src/tuntun_core/services/whole_home/tv_coordinator.py`; create `apps/core/src/tuntun_core/adapters/television/{__init__,home_assistant,cec,ir}.py`; extend `apps/display-agent/src/tuntun_display_agent/hdmi.py` only for qualified CEC; test `tests/integration/whole_home/test_signed_tv_lifecycle.py`, `tests/security/whole_home/test_tv_action_allowlist.py`, `tests/fault/whole_home/test_no_cross_protocol_spray.py`, and corresponding HA integration tests.

**Interfaces:** `TVCoordinator.execute(AuthorizedTVRequestV1, AuthContext | EnforcementIntentV1) -> UUID` imports `EnforcementIntentV1` only from `tuntun_contracts.home.screen_time`, consumes either the canonical Phase 1 human `AuthContext` or that exact committed Phase 2 intent, requires it to match the request binding and every authorization/enforcement/TV/adapter generation, then commits `SignedTVActionV1` plus audit/outbox before I/O. `system_tv_request_from_intent(intent)` is a fields-only mapping: request ID, TV/control adapter, epoch/topology/binding/capability/authorization/enforcement/policy generations, times, idempotency key, and commitment come from the intent; actor/authorization/operation/power are fixed to `system_screen_time`/`system_enforcement`/`tv.set_power.v1`/`STANDBY`; every other desired-state field is `None`. Each adapter implements one closed operation against one compiled binding. Runtime binding selects one primary adapter per operation; optional observation is configured separately.

```python
from tuntun_contracts.home.screen_time import EnforcementIntentV1

def system_tv_request_from_intent(intent: EnforcementIntentV1) -> AuthorizedTVRequestV1:
    return AuthorizedTVRequestV1(
        schema_version="1.0",
        request_id=intent.intent_id,
        tv_endpoint_id=intent.endpoint_id,
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
        authorization_generation=intent.authorization_generation,
        enforcement_generation=intent.enforcement_generation,
        policy_version=intent.policy_version,
        issued_at=intent.issued_at,
        expires_at=intent.expires_at,
        idempotency_key=intent.idempotency_key,
        request_binding_commitment=intent.intent_commitment,
    )
```

- [ ] Write red tests for wrong TV/adapter/operation/generation/signature/epoch/expiry, an intent/request substitution under the original intent commitment, system enforcement mapped to anything except standby, arbitrary key/code/macro/app/URI/service/entity, toggle, relative volume, smart-plug relay, caller-selected fallback, duplicate dispatch, ACK-without-effect, and crash at every receipt transition. A failed intent commitment or stored-canonical-byte comparison performs no topology/session/adapter read and no dispatch.
- [ ] Extend the HA receipt store with the Phase 2 timing/idempotency/quota rules and signature domain `tuntun-tv-v1`. HA native adapter translates only compiled exact desired states through system context.
- [ ] CEC adapter accepts only an owner-commissioned exact operation mapping proved for the exact HDMI topology. IR adapter accepts only hash-pinned exact-model desired-state code or minimal deterministic sequence and exposes no learn/send/raw-code method to core/model/UI.
- [ ] `tv.send_key.v1` and `tv.launch_app.v1` remain absent unless each exact operation/state is individually proved and registered. Power is `ON|STANDBY`, input is an exact binding, volume is absolute bounded, and mute is a desired boolean.
- [ ] On primary failure, return failed/unknown and stop. Tests must prove native failure does not invoke CEC/IR, CEC failure does not invoke native/IR, and IR failure does not invoke anything else. Switching primary needs a new owner-passkey binding generation and acceptance run.
- [ ] Run narrow/HA/Phase 2 action lifecycle regressions. Expect zero arbitrary mutation, intent/request substitution, duplicate effect, fallback spray, smart-plug cut, or optimistic success.
- [ ] Commit exact paths with `git commit -m "feat(television): add signed desired-state adapters"`.

### Task 30: Qualify observation strength and promote each television only to evidenced eligibility

**Depends on:** Tasks 28–29 and any exact observation-only hardware purchase separately authorized after the probe.
**Gate contribution:** P4-5.
**Estimated effort:** 3.5 person-days plus 50/100-cycle campaigns.

**Files:** Create `apps/core/src/tuntun_core/services/whole_home/tv_eligibility.py`; create `scripts/phase4/qualify_tv_adapter.py`; create `docs/evidence/phase4-tv-qualification.schema.json`; test `tests/unit/whole_home/test_tv_eligibility.py`, `tests/property/whole_home/test_observation_strength.py`, and `tests/hardware/whole_home/test_exact_tv_adapter.py`.

**Interfaces:** `TVEligibilityService.evaluate(control_evidence, observation_evidence) -> TVEligibilityDecision`. Strength order is not a numeric shortcut: `COMMAND_ACK_ONLY` never verifies; `MIRRORED_OPTIMISTIC` is UI hint only; `SAME_ADAPTER_OBSERVED` may qualify Cooperative after failures; `OUT_OF_BAND_OBSERVED` plus proved common-mode independence may qualify Strict.

- [ ] Write red tests for acknowledgement with no physical change, stale mirrored state, network reachability used as power, HDMI source used as viewer/playback, adapter/TV/router restart, cold boot, standby, source/manual remote change, network loss, common-mode failure, and observation sensor relay-action attempt.
- [ ] Implement current-generation evidence evaluation with explicit source/sample/ingest/freshness. Observation-only power hardware exposes no relay capability in contracts, registry, bridge, or feature manifest.
- [ ] For each exact registered desired state, run at least 50 control/observation cycles with zero wrong operation/false verified result for Cooperative. Test native, CEC, and IR paths separately; do not combine their successes.
- [ ] For Strict, run at least 100 enforcement-observation cycles and all common-mode independence cases. One false verified-off result blocks Strict. If independence is not proved, cap at Cooperative or weaker.
- [ ] Execute separately:

```bash
TUNTUN_ALLOW_TV_PROBE=1 uv run python scripts/phase4/qualify_tv_adapter.py --inventory-id tv_samsung_neoled_49 --cycles 50 --strict-cycles 100 --evidence-root var/evidence/phase4/televisions
TUNTUN_ALLOW_TV_PROBE=1 uv run python scripts/phase4/qualify_tv_adapter.py --inventory-id tv_tcl_42 --cycles 50 --strict-cycles 100 --evidence-root var/evidence/phase4/televisions
```

- [ ] Record each unit independently as `DISPLAY_ONLY_MANUAL`, `OBSERVE_ONLY`, `COOPERATIVE_ELIGIBLE`, or `STRICT_ELIGIBLE`. A failed TV does not block the other's manual display or qualified level.
- [ ] Commit service/tooling/tests/schema before physical runs with `git commit -m "test(television): qualify control and observation strength"`; generated evidence remains ignored.

### Task 31: Bind the unchanged Phase 2 screen-time state machine to eligible real adapters

**Depends on:** Task 30 and accepted Phase 2 `screen_time` corpus/services.
**Gate contribution:** P4-6.
**Estimated effort:** 4.5 person-days.

**Files:** Create `apps/core/src/tuntun_core/services/whole_home/screen_time_adapter.py`; modify Phase 2 `screen_time_enforcement.py` and `tv_eligibility.py` only through additive adapter injection; create `scripts/phase4/run_screen_time_adapter.py`; test `tests/integration/whole_home/test_real_screen_time_adapter.py`, `tests/property/whole_home/test_screen_time_attempt_ceiling.py`, `tests/fault/whole_home/test_no_hostile_tv_loop.py`, and `tests/hardware/whole_home/test_screen_time_physical_override.py`.

**Interfaces:** `RealScreenTimeAdapter.enforce(EnforcementIntentV1)` imports and accepts the already-authorized exact Phase 2 enforcement generation. It revalidates child/profile, viewer/session commitment and generations, clock reconciliation/epoch, TV endpoint, primary control and observation adapters, topology/binding/capability/control/observation/authorization/manual-override generations, mode/eligibility/strength, attempt evidence, expiry, stored canonical bytes, and HMAC commitment; writes one attempt row; dispatches one primary desired state; evaluates fresh observation; and returns exact truth. `Phase2ScreenTimeTVMapper.to_control_receipt(intent, action_id, TVActionDispatchReceiptV1) -> TVControlReceiptV1` and `.to_observation(intent, WholeHomeTVObservationV1) -> TVObservationV1` import the return types from Phase 2 and are the only cross-contract mappings. They reject rather than default any missing/mismatched endpoint, adapter, generation, action/request correlation, time, dimension, strength, signature, or failure-domain registry fact.

The control mapper reconstructs Phase 2 request/idempotency/endpoint/control/attempt/time fields only from the committed intent. Adapter `accepted` maps to `ACCEPTED_UNVERIFIED`, `rejected` to `FAILED`, and an attempted `unverified`/`error_safe` result to `UNKNOWN`; no dispatch receipt can map to `VERIFIED` or end a session. The observation mapper accepts exactly one registered `power` dimension and, when present, one `playback` dimension, maps `ON|STANDBY|OFF` to `on|on|off`, derives Phase 2 source/failure-domain only from the current server registry, and emits `truthfulness="proved"` only for the intent's currently eligible observation strength. Unknown/missing dimensions remain unknown and never prove off.

```python
from tuntun_contracts.home.screen_time import (
    EnforcementIntentV1,
    TVControlReceiptV1,
    TVObservationV1,
)
from tuntun_contracts.whole_home import television

def test_phase4_uses_phase2_types_without_duplicate_public_names() -> None:
    assert EnforcementIntentV1.__module__ == "tuntun_contracts.home.screen_time"
    assert TVControlReceiptV1.__module__ == "tuntun_contracts.home.screen_time"
    assert TVObservationV1.__module__ == "tuntun_contracts.home.screen_time"
    assert not hasattr(television, "EnforcementIntentV1")
    assert not hasattr(television, "TVControlReceiptV1")
    assert not hasattr(television, "TVObservationV1")

def test_adapter_records_map_to_exact_phase2_shapes_only(
    mapper, enforcement_intent, signed_action_id,
    accepted_dispatch_receipt, proved_off_observation,
) -> None:
    control = mapper.to_control_receipt(
        enforcement_intent, signed_action_id, accepted_dispatch_receipt,
    )
    observation = mapper.to_observation(enforcement_intent, proved_off_observation)
    assert type(control) is TVControlReceiptV1
    assert control.outcome == "ACCEPTED_UNVERIFIED"
    assert control.request_id == enforcement_intent.intent_id
    assert control.attempt_number == enforcement_intent.attempt_number
    assert type(observation) is TVObservationV1
    assert observation.endpoint_id == enforcement_intent.endpoint_id
    assert observation.power_state == "off"
    assert observation.playback_state == "stopped"

@pytest.mark.parametrize("substitution", [
    substitute_tv_endpoint,
    substitute_control_adapter,
    substitute_capability_generation,
    substitute_action_or_request_correlation,
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

@pytest.mark.parametrize("substitution", [
    substitute_tv_endpoint,
    substitute_observation_adapter,
    substitute_capability_generation,
    substitute_action_or_request_correlation,
    remove_power_dimension,
    downgrade_strict_observation_strength,
])
def test_observation_mapping_substitution_fails_before_screen_time_state_read_or_write(
    mapper, enforcement_intent, proved_off_observation, substitution,
    screen_time_repository,
) -> None:
    with pytest.raises(ScreenTimeTVMappingError):
        mapper.to_observation(enforcement_intent, substitution(proved_off_observation))
    assert screen_time_repository.read_count == 0
    assert screen_time_repository.write_count == 0

def test_failure_domain_is_derived_from_current_registry_or_mapping_fails_closed(
    mapper_with_registry, enforcement_intent, proved_off_observation,
    current_mapping_registry, screen_time_repository,
) -> None:
    mapper = mapper_with_registry(substitute_failure_domain(current_mapping_registry))
    with pytest.raises(ScreenTimeTVMappingError):
        mapper.to_observation(enforcement_intent, proved_off_observation)
    assert screen_time_repository.read_count == 0
    assert screen_time_repository.write_count == 0
```

- [ ] Write red tests that rerun all 720 Phase 2 oracle cases unchanged and 10,000 seeded sequences with duplicate event, crash, delayed observation, restore, manual remote/button/input/renderer stop, repeated power-on, adapter failover, network flap, viewer/clock uncertainty, teaching-display ambiguity, attempt-three insertion, every intent/request/adapter-record substitution above, and a public-contract duplicate-name scan.
- [ ] Implement Advisory with no mutation; Cooperative only at current Cooperative/Strict TV eligibility; Strict only at current Strict eligibility. Unknown viewer/clock/display/control/observation enters `UNKNOWN`, debits no unobserved time, and sends no further control.
- [ ] Preserve warning/grace and exact child extension ceremony. At expiry commit the intent/outbox, then dispatch outside the writer lock. A command receipt alone cannot end a session; only adequate fresh observation may record verified ended.
- [ ] Permit one initial attempt and one qualifying re-enforcement only when fresh trustworthy evidence within two minutes shows the same authorized child session resumed and no manual override occurred. Every other contrary fact sets `MANUAL_OVERRIDE` or `UNKNOWN` and permanently closes that generation.
- [ ] Recovery never polls into a late shutdown. Restart/restore marks uncertain generations unknown, rotates epoch as required, and waits for a fresh owner/current-guardian exact re-arm. Physical remote/buttons/renderer stop are bypasses available to any holder, never adult authentication.
- [ ] Run the four suites and `uv run python scripts/phase4/run_screen_time_adapter.py --simulated --sequences 10000`. Expected: unchanged oracle results, exact Phase 2 output model identity, zero duplicate public TV-screen-time V1 names, zero invented debit/enforcement or mapping default, at most two total attempts, and zero third/delayed command.
- [ ] Only after simulator pass run marker-gated physical override on each eligible exact unit. Commit code/tooling/tests before physical run with `git commit -m "feat(screen-time): bind qualified television adapters"`.

### Task 32: Add exact-TV capability, screen-time confidence, attempt, and manual-override UI

**Depends on:** Tasks 28–31 and the Phase 2 screen-time UI.
**Gate contribution:** P4-5, P4-6, UI acceptance.
**Estimated effort:** 3 person-days.

**Files:** Create `apps/admin/src/features/media-learning/televisions.tsx` and `apps/admin/src/routes/media-learning-televisions.tsx`; extend `apps/admin/src/features/home/screen-time.tsx`; create `apps/core/src/tuntun_core/api/routes/televisions.py` and Phase 4 read models; create `tests/ui/media-learning/televisions.spec.tsx` and `tests/ui/e2e/media-learning-televisions.spec.ts`.

**Interfaces:** One row per exact deployment TV shows safe household description, exact model/OS/firmware commitment, control adapter/generation, available and absent operations, observation strength/freshness, current eligibility, known bypass/manual fallback, current screen-time session/attempt count/manual override, and last failure. Secrets/serial/MAC/account/token are absent.

- [ ] Write red tests for both inventory entries, asymmetric capabilities, manual-only/observe-only/Cooperative/Strict/degraded states, stale evidence, false green from ACK, firmware invalidation, attempt count 0/1/2, manual override, unknown viewer, absent action route, and no hostile retry control.
- [ ] Implement no optimistic authoritative state. Prepare adapter selection/promotion, Strict enablement, and enforcement re-arm with exact owner passkey summaries; child rule/extension uses separate current-guardian ceremony and distinct slots.
- [ ] State explicitly that physical remote/vendor app/HDMI/manual controls may bypass Tuntun and that a physical intervention is not authenticated identity. Never label unobserved/offline as enforced.
- [ ] Run unit/e2e accessibility/localization/responsive/build suites and direct API/object-authorization tests. Inspect absent operation controls and chunks.
- [ ] Expected: each Samsung/TCL unit displays only its own evidence, a degraded unit immediately shows Advisory/manual behavior, and no button/API exists for an unproved operation or third attempt.
- [ ] Commit exact API/generated/UI/tests with `git commit -m "feat(admin): show truthful television enforcement"`.

**Checkpoint P4-5/P4-6:** Record an independent decision for each physical television. Manual display is a valid final result. Cooperative/Strict appears only for the exact current generation. Advisory remains available without control; no real enforcement route exists for an ineligible/degraded unit.

---

## Wave 5 — P4-7 Privacy, Recovery, Additional Rooms, Acceptance, and Maintenance

### Task 33: Complete Phase 4 Privacy Shield effects, health, backup, restore, update, and retirement

**Depends on:** every enabled service from Tasks 06–32 and the canonical Phase 1/2 lifecycle services.
**Gate contribution:** P4-7, Section 22.9.
**Estimated effort:** 3.5 person-days.

**Files:** Create `apps/core/src/tuntun_core/services/whole_home/{restore,health}.py` and complete `privacy_effects.py`; extend backup/update/retirement manifests with Phase 4 metadata-only state; create `docs/operations/phase4-{backup-restore,update-rollback,incident-retirement}.md`; test `tests/integration/whole_home/test_phase4_privacy_shield.py`, `tests/integration/whole_home/test_phase4_restore_quarantine.py`, `tests/fault/whole_home/test_phase4_update_rollback.py`, and `tests/privacy/whole_home/test_phase4_backup_minimization.py`.

**Interfaces:** The existing `p4.room_media_display` effect atomically revokes room capture/display/media authority at a new privacy generation before fan-out. Per-effect states remain authority revoked, stop requested, acknowledged, physically verified, or unverified. Restore creates fresh controller/session epochs and quarantines every endpoint/media/display/TV/screen-time route until exact reconciliation.

- [ ] Write red tests at every active/commit/dispatch/receipt/clear/attempt state for Privacy Shield, Mac/Green/endpoint/renderer/player/TV restart, key/cert rotation, backup restore, rollback, disk/key failure, and device retirement.
- [ ] Implement canonical authority revocation before I/O. Cancel room leases/STT/search/LLM/TTS and Tuntun speech; call `SpeechEndpointPort.send_control` for mute/indicator/stop/error-safe effects and verify each signed `PhysicalSafetyReceiptV1` against control ID, endpoint, privacy/capability generations, endpoint signature domain/key, timestamps, and requested effect before advancing that effect to acknowledged or physically verified. A `SafetyTransportFailureV1` is independently core-signed, exact-request-bound, and advances only to unverified; timeout, invalid/missing receipt, or disconnect can never manufacture an endpoint signature. Request Tuntun-initiated media stop; revoke display handles and request clear. Report independently controlled/already-running music and disconnected display/TV truth as verified/unverified/unknown. Never claim prior provider egress or pixels undone.
- [ ] Backup only canonical registrations, policies, consents, immutable manifests, operation state, minimized receipts/evidence commitments, and audit. Exclude provider/TV/endpoint live credentials, raw audio/transcript/query, display assets/pixels/summary, and MA/provider history bodies. Document HA/MA backups separately.
- [ ] Restore into isolated paths, verify SQLCipher/audit/deletion tombstones, mark nonterminal actions unknown, clear admissions/leases/handles/summaries, rotate epochs, re-pair secrets, reconcile bindings, and enable one feature at a time after owner review. Restored MA/TV/room evidence is stale until re-proved.
- [ ] Update is owner-visible and hash/version pinned; pre-update backup, migration quarantine, targeted physical mute/indicator/renderer/TV/manual-override probes, and rollback are mandatory. An endpoint/renderer digest change re-quarantines only that exact binding.
- [ ] Retirement revokes certificate/keys/session/grants/bindings, stops dependent features, resets hardware where supported, clears Tuntun-managed storage, records unverifiable residual flash, and proves reconnect/replay denial.
- [ ] Run the four suites plus full Phase 1/2 backup/privacy regressions. Commit with `git commit -m "feat(whole-home): recover and retire Phase 4 safely"`.

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

**Depends on:** Tasks 05, 16, 22, 27, 32–34.
**Gate contribution:** P4-7 and owner-console acceptance.
**Estimated effort:** 3.5 person-days plus one seven-day soak per added area.

**Files:** Create `apps/admin/src/features/media-learning/{room-nodes,phase4-health}.tsx` and `apps/admin/src/routes/media-learning-rooms.tsx`; extend `apps/admin/src/features/privacy/plane-cards.tsx` and Home/device area inventory; extend `apps/core/src/tuntun_core/api/routes/whole_home.py`; create `tests/ui/media-learning/room-nodes.spec.tsx`, `tests/ui/e2e/media-learning-rooms.spec.ts`, and `tests/hardware/whole_home/test_area_rollout.py`.

**Interfaces:** Read models expose canonical `area_id`/safe label, class, endpoint, local wake, hardware mute, leased transmission, capture indicator, stop, firmware/model/evidence digest, privacy/consent generation, quiet hours/volume caps, bakeoff status, one active slot/winner, busy/handoff/cancellation, language, latency, and content-free health. No audio/transcript/identity confidence/memory body/private question appears.

- [ ] Write red UI/API tests for every class/state, stale/unknown facts, current slot, losing busy event, handoff, mute/indicator test, revoke/quarantine, consent status, subject/guardian exact decisions, absent private-room feature, and direct `room_id` payload/query.
- [ ] Implement separate truthful cards for hardware mute, local wake listening, and leased network/cloud capture. Explain that an idle indicator may be off while local wake processing is active. Privacy Shield shows independent media/display acknowledgement and recorder/manual device continuations.
- [ ] Prepare commissioning/revoke/quarantine mutations server-side. Owner passkey binds exact endpoint/`area_id`/class/policy/evidence. Adult occupants use their own subject passkeys; child-private uses distinct current guardian. No owner impersonation or batch “all rooms” enablement.
- [ ] Run UI accessibility/localization/responsive/browser-storage suites. Direct URL/API/client bundle for private-area rollout remains absent until feature evidence is registered.
- [ ] Commission one additional area at a time. Verify placement, physical mute/stop reachability, visible indicator, quiet hours, acoustic thresholds, occupant notice/consent, child guardian binding where applicable, wrong-area/private reply corpus, network exposure, and seven elapsed days. Never commission `prohibited_sensitive`.
- [ ] On any failure, revoke that endpoint generation, unpair/quarantine it, retain Reachy/other accepted areas, and provide physical recovery. Do not copy a passing evidence digest from another placement.
- [ ] Commit UI/API/tests before physical rollout with `git commit -m "feat(admin): manage whole-home voice areas"`; generated per-area evidence remains ignored.

### Task 36: Freeze Phase 4 acceptance evidence, seven-day family soak, maintenance handoff, and rollback decision

**Depends on:** Tasks 01–35 and only the exact accepted feature manifest/hardware set.
**Gate contribution:** final P4-7 promotion.
**Estimated effort:** 4.5 person-days plus elapsed soak and later rolling maintenance measurement.

**Files:** Create `scripts/phase4/{measure_maintenance,run_acceptance,verify_acceptance}.py`; create `docs/evidence/{phase4-acceptance,phase4-soak,phase4-maintenance}.schema.json` and `docs/operations/phase4-acceptance-runbook.md`; create `tests/acceptance/whole_home/test_phase4_acceptance_gate.py`, `test_phase4_evidence_schema.py`, `test_phase4_feature_absence.py`, `test_phase4_soak_oracles.py`, and `test_phase4_maintenance_handoff.py`.

**Interfaces:** Phase evidence packet uses the Program I–S evidence fields and binds exact enabled/absent features. It stores aggregate metrics/commitments only. `Phase4MaintenanceRecordV1` records ordinary minutes by subsystem and excluded-event class for later consumption by the single Phase 6 `FullSystemMaintenanceGate`; Phase 4 defines no independent maintenance pass/fail gate.

- [ ] Write red evidence-schema tests requiring build/commit, feature/schema/policy/migration versions, hardware/firmware/config commitments, corpus/seed, commands/times, metrics/thresholds, fault/recovery/negative-reachability/content scan, limitations/absent features, hashes, operator/reviewer/expiry, and owner accept/reject commitment.
- [ ] Aggregate Tasks 16, 20, 27, 30–31, and 34–35 without copying raw family media/identifiers/secrets. Verify minimum counts and thresholds: candidate physical safety; ≥500 arbitration; ≥1,000 routing; language/child corpus; ≥500 media adversarial; ≥500 display manifests; exact-TV 50/100 cycles as applicable; 720/10,000 screen-time; network/content/recovery results.
- [ ] Prove every omitted optional feature across package/config/environment/manifest/API/OpenAPI/prepared-action/UI bundle/runtime/listener: Music Assistant if failed, every unproved TV operation/adapter, Cooperative/Strict per unit, real screen-time per unit, private/additional room, and any second conversation.
- [ ] From one unchanged clean commit and feature manifest, run a seven-day family soak:

```bash
TUNTUN_ALLOW_ELAPSED_PHASE4=1 uv run python scripts/phase4/run_acceptance.py household-soak --duration-seconds 604800 --sample-seconds 60 --commit "$(git rev-parse HEAD)" --evidence-root var/evidence/phase4/acceptance --output var/evidence/phase4/acceptance/household-soak.json
uv run python scripts/phase4/verify_acceptance.py var/evidence/phase4/acceptance --commit "$(git rev-parse HEAD)" --require-physical-gates --require-negative-reachability
uv run python scripts/verify_private_data.py var/evidence/phase4
```

Expected: monotonic and wall elapsed ≥604,800 seconds; zero double response, wrong-area/private broadcast, unbounded retry, false media/display/TV result, silent provider/policy change, lost physical mute/remote/manual recovery, third/delayed TV attempt, persistent audio/display/summary, or post-disable route.

- [ ] Begin recording Phase 4 ordinary owner minutes by subsystem when steady household use starts; exclude initial commissioning, incidents, repairs/hardware replacement, major migrations, and scheduled quarterly restore/security/physical-safety drills as Program I–S requires. Validate record completeness and export the content-safe monthly contribution for later Phase 6 aggregation.
- [ ] Treat **one to two hours/month** as the Phase 4 planning allocation only. Do not delay or declare P4-7 on a Phase 4-only maintenance threshold. Phase 6 logging may begin after 60 steady-state days, but Phase 6 alone evaluates for promotion—after at least 90 steady-state days and three complete monthly buckets—the **rolling three-month median of ordinary full-system owner maintenance at no more than eight hours/month**; three consecutive months above eight hours then freeze optional expansion and trigger simplification/retirement.
- [ ] Run `uv run pytest tests/acceptance/whole_home -q`, full affected suites, format/lint/mypy, UI/display tests/builds, contract generation, private-data scan, and `git diff --check`. Any tracked source/policy/schema/UI/integration/firmware/router/area placement/hardware change invalidates dependent evidence and restarts the affected campaign.
- [ ] Commit evidence tooling/runbook/schema/tests before the frozen run:

```bash
git add scripts/phase4/measure_maintenance.py scripts/phase4/run_acceptance.py scripts/phase4/verify_acceptance.py docs/evidence/phase4-acceptance.schema.json docs/evidence/phase4-soak.schema.json docs/evidence/phase4-maintenance.schema.json docs/operations/phase4-acceptance-runbook.md tests/acceptance/whole_home
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(whole-home): freeze Phase 4 acceptance gate"
```

After that commit, rerun the complete frozen campaign from its beginning. Generated owner evidence remains ignored and is never committed.

## Dependency and Parallelization Map

```text
01 contracts → 02 fakes/corpora → 03 persistence
01/03 → 04 amendments/feature absence → 05 area policy/ceremonies

01/02 → 06 room-node scaffold → 07 pairing → 08 audio lease path → 09 physical safety
07/09 + accepted P1 Reachy → 10 Reachy adapter
02/05/07/10 → 11 wake arbiter → 12 one-slot admission → 13 reply routing → 14 handoff/language
06–09 → 15 candidate adapters/tooling → 16 physical bakeoff and one common-area winner

03/04/05 → 17 provider/player/catalog → 18 media policy
17/18 + accepted P2 bridge → 19 signed HA media route
19 → 20 optional Music Assistant gate
03/17–20 → 21 coordinator/reconciliation → 22 media UI

03/04/05 → 23 teaching policy/manifest → 24 paired display agent → 25 finite renderer
23–25 + canonical Privacy Shield/memory → 26 lifecycle/ephemeral summary → 27 teaching UI/manual HDMI

03/27 → 28 exact TV inventory → 29 signed adapters → 30 observation/eligibility
accepted P2 screen-time + 30 → 31 real adapter → 32 TV/screen-time UI

all enabled paths → 33 privacy/recovery/update/retirement → 34 security/fault/network/resource
16/22/27/32/34 → 35 area UI and one-at-a-time rollout → 36 frozen acceptance/soak/maintenance
```

Tasks 06–09, 17–18, and 23 may proceed in separate clean worktrees after Task 01 freezes contracts. Tasks 15, 20, and 28 may gather read-only procurement/capability information in parallel, but physical mutations are serialized against the household estate. Tasks 23–27 do not wait for automated TV control; manual HDMI is the required first display path. Phase 3 and Phase 4 may run in parallel only after their separate contracts are frozen and while they do not edit the same migration head, feature registry, Privacy Shield registry, generated UI contract, or owner-console route.

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
| Microphone in `prohibited_sensitive` | Commissioning/API/fixture/feature tests reject; network inventory finds zero endpoint |
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
- [ ] Reachy and the selected common-area endpoint pass duplicate arbitration, lease/media bounds, wrong-area/private reply, cancellation, restart, handoff, and English/Hindi/Hinglish gates.
- [ ] The selected purchased/DIY exact endpoint passes physical hardware mute, truthful capture indicator, local stop, no-durable-audio, seven-day/eight-hour acoustic/reliability, update/rollback, power, and SBOM/licence gates; its owner-maintenance time is measured and disclosed for the later full-system gate.
- [ ] Every enabled area has current owner/occupant/guardian consent and privacy generations; prohibited-sensitive has zero endpoint; private/additional areas have independent placement/soak evidence.
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

Execute Tasks 01–36 with `superpowers:subagent-driven-development` for fresh bounded task workers and review, or `superpowers:executing-plans` for checkpointed inline batches. Stop at P4-E0/P4-0, P4-1/P4-2, P4-3, P4-4, P4-5/P4-6, and final P4-7. Start no room capture, media, renderer, TV mutation, real enforcement, or private-area rollout before its exact positive gate. Conditional manual/absent outcomes are valid Phase 4 results; weaker hidden paths are not.
