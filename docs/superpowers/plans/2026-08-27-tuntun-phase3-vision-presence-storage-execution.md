# Tuntun Phase 3 Vision, Presence, and Storage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver an owner-only, local camera recorder and evidence plane for the hall TrackMix WiFi and two independently qualified kitchen E1-family cameras, with exact 7-day low-resolution continuous and 90-day full-resolution native-event retention, truthful storage/playback health, calibrated local security alerts, and anonymous expiring occupancy without creating a camera identity, audio, model, memory, Home Assistant media, or public-access path.

**Architecture:** Add four least-privilege Mac side processes—`tuntun-camera-source`, `tuntun-recorder`, `tuntun-media-proxy`, and `tuntun-owner-ingress`—beside the Phase 1/2 modular monolith. Camera credentials and network connections terminate only in the source process; audio-free stream-copy media and native events cross bounded authenticated Unix-domain IPC; raw media and a separate SQLCipher vision catalog stay on the dedicated encrypted `TUNTUN_VIDEO` volume; only strict metadata events, health, owner-safe opaque event-clip and low-wide segment references, and current anonymous presence cross into `tuntun-core`. Owner ingress is the sole network-facing HTTP process: it always owns loopback-only `127.0.0.1:8787`, and only an independently commissioned current private-LAN binding may additionally own its exact address on `:8443`. It sends the one exact authenticated media path directly to media-proxy UDS and generated non-media routes to core UDS, so core never relays media bytes and media proxy never listens on TCP. The initial store is the existing external SSD, and no NAS, NVR, Home Hub, larger disk, new sensor, or CV appliance is purchased or registered until its named evidence gate passes.

**Tech Stack:** Python 3.12, `asyncio`, Pydantic v2, SQLAlchemy 2/Alembic over SQLCipher, `cryptography`, macOS Keychain/FileVault/APFS, authenticated Unix-domain sockets and Darwin peer credentials, pinned PyAV/FFmpeg libraries used without routine decode, FastAPI/SSE, RFC 8785/JCS, JSON Schema 2020-12; React 19, TypeScript, Vite, React Router, TanStack Query; pytest, pytest-asyncio, Hypothesis, Ruff, strict mypy, Vitest, Testing Library, Playwright, axe, parser fuzzing, and owner-gated camera/network/storage campaigns.

**Normative design:** [Phase 3 Vision, Presence & Storage](../specs/2026-08-27-tuntun-phase3-vision-presence-storage-design.md), [Program A–H](../specs/2026-08-27-tuntun-program-architecture-a-h.md), [Program I–S](../specs/2026-08-27-tuntun-program-assurance-delivery-i-s.md), and [Six-Phase UI/UX](../specs/2026-08-27-tuntun-six-phase-ui-ux-design.md).

## Authority and Upstream Reconciliation

1. The Phase 3 design is normative for camera, retention, playback, alert, occupancy, source-eligibility, and procurement gates. Program A–H owns cross-phase architecture/contracts; Program I–S owns repository, evidence, assurance, operations, and synthetic-fixture rules; the UI/UX design owns surface truth, same-origin SSE, prepared-mutation, and feature-registration behavior.
2. Phase 1 remains the only identity, profile, consent, passkey, policy, memory, privacy-generation, and canonical audit authority. Reolink data never calls `IdentityPort`, becomes an unknown-person candidate, selects a speaker, retrieves memory, or triggers Reachy.
3. Phase 2 `AreaV1` and `CanonicalLocationRefV1` are the only household location authority. Every Phase 3 camera binding, zone, evidence, event, manifest, request, checkpoint, and projection carries and reopens the exact `(area_id, area_generation)` pair; `camera_zone.v1` is additionally a versioned/CAS child of one camera-binding generation. A label such as “hall,” “kitchen,” “room,” or a translated label is presentation only, and Guest is an orthogonal narrowing policy rather than a room class.
4. The UI design's durable owner-console inbox plus authenticated same-origin SSE is the exact Phase 3 alert transport. The earlier word “Companion” does not authorize a native app, service worker, background push, SMS, email, vendor cloud, or public notification endpoint.
5. Privacy Shield revokes Tuntun camera outcomes, alert/presence processing, playback/export grants, and selected-frame requests while the independent recorder and its 7/90 retention continue. Recorder pause/resume is a separate owner-passkey operation and never claims physical camera power-off.
6. `selected_frame_request.v1` and `anonymous_visual_observation.v1` are contract-only in Phase 3. No `SelectedFrameVisionPort`, broker route, CV dependency, frame API, model/VLM/LLM path, UI route, or feature registration exists until Phase 5. The future result is advisory only; `count_band` cannot alter Phase 3 alert or presence state.
7. The three real placements are fixed inputs to owner evidence: TrackMix in the hall covering the bedroom pathway, E1-family camera A in the kitchen view A, and E1-family camera B in kitchen view B. Git fixtures use synthetic IDs and never encode household aliases, serials, addresses, frames, or credentials.
8. Each E1 remains `E1-family unknown` until its exact unit proves model/revision/firmware/local protocol/event/audio behavior. A source whose vendor cloud, UID/P2P, outbound DNS/control/metadata/thumbnail/audio/media paths cannot be disabled or blocked and independently verified is `vendor_native_only` and absent from every Phase 3 runtime route.
9. The fixed recording policy is one low-resolution wide stream per eligible physical camera for exactly seven days plus approved native-event full-resolution clips for exactly 90 days. TrackMix tracking-view event media is independently conditional; failure leaves only the wide event clip.
10. Camera audio is disabled at the device where supported and rejected again before durable storage. A source that cannot produce provably audio-free stored media is ineligible.

## Global Constraints

1. The accepted Phase 2 baseline plus the stable Phase 1 `FB0` services consumed by Phase 3—owner/passkey authorization, policy/privacy generation, serialized SQLCipher unit of work, content-minimized audit/outbox, owner API, feature registry, backup/restore quarantine, Guest denial, and memory/identity isolation—must pass before Phase 3 source enablement. Phase 1-only `P1R0/P1R1` standalone-preview hardening may continue in parallel and is not a Phase 2/3 entry gate.
2. The owner-approved Darwin `arm64` Core Mac from ADR 0001, three current Reolink cameras, and encrypted external SSD are reused. Intel macOS remains a supported-distribution target and future household-transition candidate only after fresh real-host probes. Phase 3 incremental acquisition is S$0 until measured evidence opens a separately approved procurement record.
3. No NAS, NVR, Reolink Home Hub, larger SSD, accelerator, non-imaging presence sensor, surveillance licence, or camera replacement is ordered by this plan. P3-6 produces one evidence-bound storage decision; purchasing is a later explicit owner action.
4. Raw camera frames, thumbnails, clips, audio, stream URLs, credentials, IP/MAC addresses, filenames, OCR, captions, free detector labels, or parser errors never enter `tuntun-core` storage, canonical memory, Home Assistant, audit bodies, logs, browser persistence, crash reports, backups, cloud AI, an LLM/VLM, source control, CI artifacts, or public evidence.
5. The video catalog has a separate SQLCipher database and Keychain namespace. It contains no family name, profile ID, child/guardian ID, biometric, conversation ID, memory ID, transcript, provider key, HA key, or joinable identity field.
6. The camera-source process can open only commissioned local camera destinations and its own Keychain items. The recorder has no camera credential, provider/identity/memory/HA key, general network route, or Mac-root fallback. The media proxy has read-only opaque media access and a Unix socket, not a camera route or TCP listener. Owner ingress alone binds `127.0.0.1:8787` and, when current optional commissioning permits, one exact RFC1918 address on `:8443`; it has no video-volume mount, catalog key, camera route, provider key, or reusable playback credential. Port 8787 never binds a LAN, wildcard, or IPv6 address.
7. Routine ingest is packet/codec stream-copy. It performs no continuous decode, object detection, recognition, tracking inference, captioning, OCR, model call, or transcoding. One owner-requested playback transcode is bounded, audio-free, lower priority than an active voice turn, RAM/temporary-only, and destroyed on completion, cancellation, expiry, privacy, or crash.
8. Each trust-boundary DTO is frozen, rejects duplicate/unknown fields and enum values, bounds every string/list/body, uses Unicode NFC and aware UTC, and uses RFC 8785/JCS for commitments. Unknown versions, stale generations, untrusted clocks, and cross-area/zone bindings quarantine before policy.
9. The Phase 2 cross-domain event envelope is reused unchanged. Events are observations, never authorization. No camera or presence event can call a Home Assistant action, light routine, greeting, memory write, desktop job, media action, or robot route directly.
10. Playback is owner-only and same-origin. Second adult, K2 child, N1 child, Designated Guest, anonymous Guest, HA user, Reachy turn, an inner compromised client, and a client on the disabled or separately gated outer interface of the same single Mac receive no recording list, metadata, distinguishing existence signal, grant, media bytes, URL, or credential.
11. Every P3 playback byte-range grant is one exact event-clip view or 7-day low-wide segment subject/operation/range/session, single-use, and expires within 60 seconds. Export and early delete always consume a fresh exact-scope owner-passkey grant.
12. No public listener, router port forward, DMZ, UPnP, NAT-PMP/PCP mapping, public camera URL, vendor relay, direct RTSP/ONVIF exposure, remote playback, or Home Assistant camera/media entity is created. Phase 6 owns a future VPN owner route.
13. Privacy Shield activation preserves the Phase 1 canonical authority-revocation and Reachy-local P95 ≤250 ms gate. Camera effect acknowledgement is reported independently; it never changes or delays the independent recorder truth.
14. Continuous segments expire exactly seven days after immutable segment end; event clips expire exactly 90 days after final clip/event end; unpromoted event-ring media becomes inaccessible within 60 seconds plus a 15-second cleanup bound. The first normal expiry pass is no later than 15 minutes. Clock rollback, restart, restore, or low space cannot extend or shorten these values.
15. Runtime free-space behavior is fixed: above 25% normal; 20–25% warn; 15–20% `retention_at_risk` and block export/transcode; 10–15% stop new continuous admission at a segment boundary; below 10%, read-only, wrong mount, or uncertain catalog stops all writes. Unexpired media is never deleted early and video never spills to the Mac root disk.
16. The seven-day campaign uses final settings and must achieve at least 99.5% segment coverage per eligible camera, surface every gap longer than five seconds within 30 seconds, preserve Phase 1 first-audio P95 at no more than four seconds and no more than 10% regression, and preserve Phase 2 Green backup objectives.
17. Camera-native person evidence can assert `occupied` for no more than five minutes. Event absence, expiry, source outage, stale clock, restart uncertainty, or contradictory evidence becomes `unknown`, never `vacant`. `vacant` and `one/multiple` stay absent until a separately commissioned non-imaging rule passes 100 seeded sequences with zero false vacancy and at least 95% occupied detection.
18. Every enabled alert camera/class/zone has at least 30 scripted positive traversals, at least 95% accepted-event recall, no more than one owner-visible false alert per representative 24 hours over seven days, zero duplicates, and reachable-console event-to-SSE P95 at most five seconds.
19. Ordinary tests use synthetic media, fake clocks, fake camera sources, temporary encrypted roots, and no paid API, hardware, Keychain, WAN, router mutation, household media, or privileged packet capture. Hardware/elapsed tests require explicit flags, named operator, bounded target list, and owner-only evidence destinations.
20. Committed examples, screenshots, evidence schemas, and fixtures are synthetic. Real evidence is ignored under `var/evidence/phase3/` and contains only pseudonymous IDs, safe reason codes, counts, timings, hashes, versions, and decisions; raw PCAP/media stays in a separately declared owner-only capture root and is represented by a digest.
21. Project-wide branch coverage remains at least 85%; authorization, playback-grant, zone-CAS, retention, alert policy, privacy, and presence modules remain at least 95%. Each implementation task follows red → green → refactor → affected suite → static/security checks → exact-path commit.
22. Phase 3 imports Phase 2's canonical externally signed, pre-issued `SignedFeatureManifestRolloverChainV1`, `FeatureManifestLeaseSupervisor`, per-admission `FeatureAuthorityLease`, and `FeatureAuthorityCampaignEvidenceV1`/generated schema unchanged; it creates no signer, renewal service, fallback manifest, local evidence alias, or grace extension. Before the Task 19 48-hour pilot, Task 20 and Task 26 seven-day campaigns, Task 32 seven-day soak, or conditional P3-F 30-day parallel run, the complete ordered chain must bind one frozen candidate and exact registrations, cover the planned wall-time interval, and install each valid successor before its predecessor expires. The counted clock starts only after a current index-zero controlled-restart activation receipt exact-matches the live candidate/composition. Tasks use candidate-specific owner-only chain paths. A code, package, feature registration, route, policy/configuration, physical binding/generation, firmware, volume, or other candidate commitment change requires a newly externally signed chain and fresh campaign; an old path may be atomically overwritten only after prior evidence is closed and can never preserve, widen, merge, or copy authority/evidence from the earlier candidate. Every admission and background-work iteration checks both `valid_from <= trusted_now < expires_at` and `monotonic_now < monotonic_deadline_ns`. A missing/stale initial activation receipt, nonzero initial index, missing, extra, late, reordered, widened, rollback, signature-invalid, candidate-drifted, or expired current/next authority, either exact deadline equality, wall rollback, stale composition, or a missing/duplicated/substituted rollover/restart receipt closes affected capture, media, alert, presence, selected-frame, and owner-route work before preparation or I/O, invalidates the campaign, and enters controlled whole-composition recovery. Gate evidence binds the chain ID/digest, ordered signed-envelope and transition/restart-receipt digests, admission-sample-log digest, exact interval, and every canonical literal-zero counter; the shared downstream harness proves zero post-fault admission/preparation/provider-call/trigger/effect delta and semantic rejection.
23. Tasks 17, 26, and 32 are the serialized Phase 3 owner-ingress service checkpoints. Task 17 creates the sole owner-ingress wheel, signed route manifest, and canonical service row. After Tasks 21, 23, and 24 mutate that graph, Task 26 must rebuild the locked wheel, refresh and externally re-sign the same `ops/services/phase3-owner-ingress.v1.json` against the exact route-manifest digest, and rerun installed dispatch, negative reachability, takeover, start/health, deliberate crash/restart, wrong-account/config denial, update, rollback, preserve/destroy uninstall, cleanup, and reinstall before committing and before its seven-day calibration. Task 32 repeats the protocol after Task 28's final route change. Every predecessor row/receipt must fail the current verifier and is valid only with its complete matching rollback set. A campaign starts only after its checkpoint commit, a clean-worktree check, installed-candidate verification, and a newly externally signed exact-candidate chain.

## Definition of Done for Every Task

- The named failing test is observed before implementation and fails for the intended missing contract or behavior.
- Narrow and affected Python suites pass with Ruff format/check and strict mypy; touched UI passes lint, TypeScript, Vitest, Playwright, axe, and production build.
- Contract changes regenerate and diff-clean Python/JSON/OpenAPI/TypeScript artifacts and include valid plus adversarial fixtures.
- Database changes prove encrypted creation, forward migration, restart/corruption behavior, and downgrade-or-isolated-restore strategy; no video/catalog data enters the canonical backup.
- Media code proves no audio track, no path escape, no credential/error leakage, bounded input/resource use, and no output outside the exact temporary or video root.
- External effects have fault injection before and after every durable transition. No file/network/camera effect occurs while the canonical core SQLCipher writer lock is held.
- Logs, browser storage, screenshots, reports, evidence, and backup roots are scanned for synthetic video, credential, address, name, transcript, memory, and raw-error sentinels.
- `git status --short` contains only task-owned paths; only exact files are staged; `git diff --cached --name-only`, `git diff --cached --check`, and `git diff --cached` are reviewed before the task commit.

## Phase Entry, Promotion, and Exit Gates

| Gate | Entry requirement | Positive exit | Disabled/failed exit |
|---|---|---|---|
| P3-E0 | Accepted Phase 2 baseline plus stable consumed Phase 1 FB0 services | Contracts, separate stores, synthetic media, process boundaries, feature absence, and migrations pass | Phase 3 routes/processes remain absent |
| P3-0 | P3-E0 | All three exact units/placements/copies are inventoried; egress, audio, area/zone, TrackMix arc, E1 path, SSD mount/encryption evidence is current | Camera remains `inventory_only` or `vendor_native_only`; no central recording |
| P3-1 | P3-0 and eligible TrackMix fixed-wide path | One source completes 48 hours of audio-free stream-copy, event promotion, 7/90 simulation, playback, gap/crash/WAN-off/egress tests | Source stays native-only; no recording claim |
| P3-2 | P3-1 | Every eligible camera runs final settings for seven representative days and capacity/resource/reconnect gates pass | Central recording is explicitly partial; storage/source decision opens |
| P3-3 | P3-2 or explicitly partial eligible set | Owner-only health/timeline/playback/export/delete/storage/privacy controls pass; alerts/presence/CV remain absent | Recorder may continue pilot-only; family dashboard promotion blocked |
| P3-4 | P3-3 | Exact enabled native event classes pass quality, local durable inbox, SSE, dedupe, privacy, and owner-only gates | That class/source has no alert route; recording continues |
| P3-5 | P3-3 | Current anonymous `occupied → unknown` passes; optional vacancy-capable rule passes its own 100-sequence gate | `vacant`/count/area route is absent or state remains `unknown` |
| P3-6 | All enabled gates | Seven-day household soak, accelerated 90-day retention, security/privacy/failure matrix, complete signed feature-manifest rollover-chain evidence, and one storage decision receipt pass | Affected feature is quarantined/absent; no NAS/NVR purchase is implied |
| P3-F | P3-2 produced an evidence-backed blocker and owner separately approved a pilot purchase | One camera/view passes a 30-day parallel bridge/NVR/NAS migration with rollback | SSD/native path is retained; no bulk migration/decommission |

## Planned Repository Map

~~~text
packages/contracts/src/tuntun_contracts/vision/
├── __init__.py
├── base.py                  # strict vision model, bounded IDs, safe enums
├── topology.py              # camera binding, camera_zone.v1, commissioning
├── evidence.py              # egress, TrackMix arc, storage/capacity evidence
├── events.py                # camera.security_event.v1, presence.changed.v1
├── media.py                 # segment, clip, playback/export/delete contracts
├── health.py                # source and recording health
├── selected_frame.py        # contract-only Phase 5 request/observation
├── ui.py                    # owner-safe Phase 3 read models
├── ipc.py                   # authenticated metadata-only process envelope
└── ports.py                 # source/recorder/catalog/policy/media protocols
schemas/vision/v1/                           # generated strict JSON Schemas
fixtures/synthetic/vision/                   # generated bars/events, no household media
fixtures/adversarial/vision/                 # hostile metadata/container/event corpora

apps/recorder/pyproject.toml
apps/recorder/src/tuntun_recorder/__init__.py
apps/recorder/src/tuntun_recorder/
├── config.py
├── volume.py
├── entrypoints/
│   ├── __init__.py
│   ├── recorder.py
│   └── media_proxy.py
├── ipc/
│   ├── envelope.py
│   ├── peer.py
│   ├── client.py
│   └── server.py
├── source/
│   ├── service.py
│   ├── eligibility.py
│   ├── relay.py
│   └── credentials.py
├── recording/
│   ├── service.py
│   ├── segmenter.py
│   ├── event_ring.py
│   ├── promotion.py
│   ├── reconciliation.py
│   ├── retention.py
│   └── pressure.py
├── events/
│   ├── normalizer.py
│   ├── dedupe.py
│   └── clock.py
├── catalog/
│   ├── database.py
│   ├── models.py
│   ├── repository.py
│   └── migrations/
│       ├── 0001_media_catalog.py
│       ├── 0002_media_operations.py
│       └── 0003_measurement_health.py
├── media/
│   ├── grants.py
│   ├── proxy.py
│   ├── range_reader.py
│   ├── transcode.py
│   └── export.py
├── capacity.py
├── health.py
└── cli.py

apps/owner-ingress/pyproject.toml
apps/owner-ingress/src/tuntun_owner_ingress/__init__.py
apps/owner-ingress/src/tuntun_owner_ingress/entrypoint.py
apps/owner-ingress/src/tuntun_owner_ingress/listeners.py

packages/secure-archive/pyproject.toml
packages/secure-archive/src/tuntun_secure_archive/
├── __init__.py
└── writer.py

integrations/reolink/pyproject.toml
integrations/reolink/src/tuntun_reolink/__init__.py
integrations/reolink/src/tuntun_reolink/
├── entrypoint.py
├── adapter.py
├── capabilities.py
├── direct.py
├── native_events.py
├── bridge.py
├── clock.py
└── sanitized_errors.py

apps/core/src/tuntun_core/domain/vision/
├── commissioning.py
├── zones.py
├── event_delivery.py
├── alerts.py
└── presence.py
apps/core/src/tuntun_core/services/vision/
├── commissioning.py
├── event_ingress.py
├── privacy_policy.py
├── playback_broker.py
├── alerting.py
├── presence.py
├── projections.py
└── health.py
apps/core/src/tuntun_core/api/routes/cameras.py
apps/core/src/tuntun_core/api/routes/camera_alerts.py
apps/core/src/tuntun_core/api/routes/camera_presence.py
apps/core/src/tuntun_core/api/vision_dtos.py
apps/core/migrations/versions/
├── 0013_camera_policy.py
├── 0014_camera_alerts.py
└── 0015_presence_checkpoint.py

apps/admin/src/features/cameras/
├── index.ts
├── overview.tsx
├── inventory.tsx
├── recordings.tsx
├── playback.tsx
├── storage.tsx
├── alerts.tsx
├── presence.tsx
└── privacy-map.tsx
apps/admin/src/routes/cameras-overview.tsx
apps/admin/src/routes/cameras-inventory.tsx
apps/admin/src/routes/cameras-recordings.tsx
apps/admin/src/routes/cameras-storage.tsx
apps/admin/src/routes/cameras-alerts.tsx
apps/admin/src/routes/cameras-presence.tsx
apps/admin/src/routes/cameras-privacy.tsx

packages/testing/src/tuntun_testing/vision/
├── fake_source.py
├── fake_recorder.py
├── fake_volume.py
├── fake_media.py
├── fault_points.py
└── scenario.py
scripts/phase3/
├── generate_vision_schemas.py
├── build_media_corpus.py
├── inventory_cameras.py
├── verify_camera_egress.py
├── qualify_trackmix_arc.py
├── probe_reolink.py
├── qualify_video_volume.py
├── run_one_camera_pilot.py
├── run_retention_simulation.py
├── run_resource_simulation.py
├── run_capacity_campaign.py
├── calibrate_alerts.py
├── calibrate_presence.py
├── run_fault_matrix.py
├── run_acceptance.py
└── verify_acceptance.py
ops/launchd/phase3/
├── com.tuntun.camera-source.plist
├── com.tuntun.recorder.plist
├── com.tuntun.media-proxy.plist
└── com.tuntun.owner-ingress.plist
docs/operations/phase3-camera-commissioning.md
docs/operations/phase3-trackmix-privacy.md
docs/operations/phase3-e1-source-gate.md
docs/operations/phase3-video-volume.md
docs/operations/phase3-recorder.md
docs/operations/phase3-one-camera-pilot.md
docs/operations/phase3-playback-export-delete.md
docs/operations/phase3-alerts-presence.md
docs/operations/phase3-failure-recovery.md
docs/operations/phase3-observability.md
docs/operations/phase3-acceptance.md
docs/privacy/phase3-camera-data.md
docs/procurement/phase3-storage-decision.md
docs/evidence/phase3-evidence-schema.json
docs/evidence/phase3-one-camera-pilot-schema.json
docs/evidence/phase3-soak-schema.json
~~~

## Frozen Contract Baseline

All fields are required unless explicitly optional. Implementations may add private helpers but may not rename, loosen, enrich, or join these public contracts.

~~~python
# packages/contracts/src/tuntun_contracts/vision/base.py
from tuntun_contracts.base import ContractModel,canonical_mapping_bytes

class VisionContract(ContractModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, validate_assignment=True, str_strip_whitespace=True,
    )

CameraEventClass = Literal["person", "vehicle", "pet", "package", "motion", "unknown"]
CameraStreamRole = Literal["low_wide", "event_wide", "event_tracking"]
CameraCodec = Literal["h264", "h265"]
ClipView = Literal["wide", "tracking"]
NativeDetectorCode = Literal["person", "vehicle", "pet", "package", "motion", "unknown"]
PresenceSourceKind = Literal[
    "camera_native_person", "commissioned_non_imaging", "system_timeout", "source_health", "privacy_shield",
]
CameraEgressCase = Literal[
    "boot", "steady_state", "retry", "wan_restore", "vendor_app_poll", "control", "uid_p2p", "dns",
    "telemetry", "thumbnail", "audio", "raw_media",
]
TrackMixDoorway = Literal["hall_entry", "bedroom_pathway"]
TrackMixMotionMode = Literal[
    "fixed_wide", "digital_tracking", "auto_tracking", "monitor_point", "patrol", "manual_ptz",
]
TrackMixCondition = Literal[
    "day", "infrared_night", "spotlight", "reboot", "power_loss",
    "calibration", "firmware", "monitor_point", "patrol", "manual_ptz",
]
REQUIRED_CAMERA_EGRESS_CASES: frozenset[CameraEgressCase] = frozenset({
    "boot", "steady_state", "retry", "wan_restore", "vendor_app_poll", "control", "uid_p2p", "dns",
    "telemetry", "thumbnail", "audio", "raw_media",
})
REQUIRED_TRACKMIX_DOORWAYS: frozenset[TrackMixDoorway] = frozenset({"hall_entry", "bedroom_pathway"})
REQUIRED_TRACKMIX_MOTION_MODES: frozenset[TrackMixMotionMode] = frozenset({
    "fixed_wide", "digital_tracking", "auto_tracking", "monitor_point", "patrol", "manual_ptz",
})
REQUIRED_TRACKMIX_CONDITIONS: frozenset[TrackMixCondition] = frozenset({
    "day", "infrared_night", "spotlight", "reboot", "power_loss",
    "calibration", "firmware", "monitor_point", "patrol", "manual_ptz",
})
VisionIpcMessageType = Literal[
    "camera_probe", "camera_capability_evidence", "open_camera_stream", "read_only_media_handle",
    "native_camera_event", "source_health", "camera_security_event", "recording_health",
    "recorder_start", "recorder_pause", "recorder_resume", "recorder_receipt",
    "owner_clip_query", "clip_page", "owner_segment_query", "segment_page",
    "media_grant_register", "media_grant_register_receipt", "media_grant_claim",
    "media_grant_claim_receipt", "clip_export_request", "clip_export_receipt",
    "clip_delete_request", "clip_delete_receipt", "owner_pre_session_request",
    "owner_pre_session_result", "event_ingress_receipt",
]
VisionProcess = Literal["core", "camera_source", "recorder", "media_proxy", "owner_ingress"]
SafeUiLabel = Annotated[
    str, Field(min_length=1, max_length=96, pattern=r"^[^\x00-\x1f\x7f\r\n]+$"),
]
SafeUiMessage = Annotated[
    str, Field(min_length=1, max_length=240, pattern=r"^[^\x00-\x1f\x7f\r\n]+$"),
]
OpaqueRelayId = Annotated[str, Field(min_length=43, max_length=43, pattern=r"^[A-Za-z0-9_-]{43}$")]
OpaqueStagingToken = Annotated[str, Field(min_length=43, max_length=43, pattern=r"^[A-Za-z0-9_-]{43}$")]
OpaqueCursor = Annotated[str, Field(min_length=43, max_length=256, pattern=r"^[A-Za-z0-9_-]+$")]

class OpaqueStorageToken(RootModel[Annotated[str, Field(
    min_length=43, max_length=43, pattern=r"^[A-Za-z0-9_-]{43}$",
)]]):
    model_config = ConfigDict(frozen=True, strict=True)

    @classmethod
    def random(cls) -> "OpaqueStorageToken":
        return cls(secrets.token_urlsafe(32))

    def __str__(self) -> str:
        return self.root

class ExpectedVideoVolume(VisionContract):
    schema_id: Literal["expected_video_volume.v1"] = "expected_video_volume.v1"
    apfs_container_uuid: UUID
    video_volume_uuid: UUID
    mount_point: Literal["/Volumes/TUNTUN_VIDEO"]
    video_quota_bytes: Annotated[int, Field(ge=64 * 1024 * 1024 * 1024)]
    minimum_ha_backup_reserve_bytes: Annotated[int, Field(ge=8 * 1024 * 1024 * 1024)]
    recorder_uid: Annotated[int, Field(ge=1)]
    qualification_generation: Annotated[int, Field(ge=1)]
    qualification_digest: Sha256Digest

class VideoVolumeHandle(VisionContract):
    schema_id: Literal["video_volume_handle.v1"] = "video_volume_handle.v1"
    apfs_container_uuid: UUID
    video_volume_uuid: UUID
    mount_point: Literal["/Volumes/TUNTUN_VIDEO"]
    video_quota_bytes: Annotated[int, Field(ge=64 * 1024 * 1024 * 1024)]
    minimum_ha_backup_reserve_bytes: Annotated[int, Field(ge=8 * 1024 * 1024 * 1024)]
    recorder_uid: Annotated[int, Field(ge=1)]
    qualification_generation: Annotated[int, Field(ge=1)]
    qualification_digest: Sha256Digest
    mount_epoch: UUID
    opened_at: AwareDatetime
~~~

`OpaqueStorageToken`, relay IDs, staging tokens, and cursors are random base64url values, never encoded paths, camera IDs, names, or reusable browser capabilities. Every enum used by a frozen contract is a closed alias or inline `Literal`; adapter-private vendor strings must be compiled to one of those values before crossing a port.

~~~python
# packages/contracts/src/tuntun_contracts/vision/topology.py
# Imported unchanged; Phase 3 defines no alternate location or room-class vocabulary.
from tuntun_contracts.home.topology import AreaV1, CanonicalLocationRefV1

class CameraProbeTarget(VisionContract):
    schema_id: Literal["camera_probe_target.v1"] = "camera_probe_target.v1"
    probe_id: UUID
    source_endpoint_id: StableHomeId
    source_endpoint_generation: Annotated[int, Field(ge=1)]
    expected_physical_device_commitment: HmacCommitment
    purpose: Literal["exact_unit_local_capability_probe"]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    single_use: Literal[True]
    authorization_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_probe_window(self) -> "CameraProbeTarget":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=30):
            raise ValueError("camera_probe_window_invalid")
        return self

class CameraStreamCapabilityV1(VisionContract):
    schema_id: Literal["camera_stream_capability.v1"] = "camera_stream_capability.v1"
    stream_role: CameraStreamRole
    codec: CameraCodec
    width: Annotated[int, Field(ge=1, le=7680)]
    height: Annotated[int, Field(ge=1, le=4320)]
    fps_milli: Annotated[int, Field(ge=1, le=120_000)]
    time_base_numerator: Annotated[int, Field(ge=1, le=1_000_000)]
    time_base_denominator: Annotated[int, Field(ge=1, le=1_000_000_000)]
    proved_peak_bytes_per_second: Annotated[int, Field(ge=1, le=64 * 1024 * 1024)]
    proved_max_packet_bytes: Annotated[int, Field(ge=1, le=16 * 1024 * 1024)]

    @model_validator(mode="after")
    def coherent_stream_bounds(self) -> "CameraStreamCapabilityV1":
        if self.proved_max_packet_bytes > self.proved_peak_bytes_per_second:
            raise ValueError("camera_stream_packet_rate_invalid")
        return self

class CameraCapabilityEvidenceV1(VisionContract):
    schema_id: Literal["camera_capability_evidence.v1"] = "camera_capability_evidence.v1"
    probe_id: UUID
    source_endpoint_id: StableHomeId
    source_endpoint_generation: Annotated[int, Field(ge=1)]
    physical_device_commitment: HmacCommitment
    capability_generation: Annotated[int, Field(ge=1)]
    exact_model_code: BoundedSafeCode
    hardware_revision: BoundedSafeCode
    firmware_revision: BoundedSafeCode
    source_path: Literal["direct_local", "proved_bridge", "native_sd_only", "inventory_only", "vendor_native_only"]
    direct_streams: Annotated[tuple[CameraStreamCapabilityV1, ...], Field(max_length=3)]
    native_event_classes: Annotated[tuple[CameraEventClass, ...], Field(max_length=6)]
    native_event_channel_state: Literal["proved", "unsupported", "ineligible"]
    audio_state: Literal["disabled_and_rejected", "ineligible"]
    egress_state: Literal["verified_blocked", "ineligible_unverified"]
    clock_quality: Literal["synchronized", "degraded", "untrusted"]
    observed_at: AwareDatetime
    valid_until: AwareDatetime
    capability_digest: Sha256Digest
    reason_codes: Annotated[tuple[SafeReasonCode, ...], Field(max_length=16)]

    @model_validator(mode="after")
    def coherent_capability_state(self) -> "CameraCapabilityEvidenceV1":
        if not self.observed_at < self.valid_until <= self.observed_at + timedelta(hours=24):
            raise ValueError("camera_capability_lifetime_invalid")
        stream_roles = tuple(stream.stream_role for stream in self.direct_streams)
        if len(stream_roles) != len(set(stream_roles)) or len(self.native_event_classes) != len(set(self.native_event_classes)):
            raise ValueError("camera_capability_duplicate_entry")
        runnable = self.source_path in {"direct_local", "proved_bridge"}
        if runnable != bool(self.direct_streams):
            raise ValueError("camera_capability_source_path_invalid")
        if runnable and (self.audio_state != "disabled_and_rejected" or self.egress_state != "verified_blocked"):
            raise ValueError("camera_capability_safety_state_invalid")
        if (self.native_event_channel_state == "proved") != bool(self.native_event_classes):
            raise ValueError("camera_capability_event_state_invalid")
        if not runnable and self.native_event_channel_state == "proved":
            raise ValueError("camera_capability_ineligible_event_route")
        if not runnable and not self.reason_codes:
            raise ValueError("camera_capability_ineligible_reason_required")
        return self

class OpenCameraStreamV1(VisionContract):
    schema_id: Literal["open_camera_stream.v1"] = "open_camera_stream.v1"
    request_id: UUID
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    stream_role: CameraStreamRole
    expected_capability_digest: Sha256Digest
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    single_use: Literal[True]
    authorization_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_open_window(self) -> "OpenCameraStreamV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("open_camera_stream_window_invalid")
        return self

class ReadOnlyMediaHandle(VisionContract):
    schema_id: Literal["read_only_media_handle.v1"] = "read_only_media_handle.v1"
    request_id: UUID
    relay_id: OpaqueRelayId
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    capability_digest: Sha256Digest
    stream_role: CameraStreamRole
    codec: CameraCodec
    width: Annotated[int, Field(ge=1, le=7680)]
    height: Annotated[int, Field(ge=1, le=4320)]
    time_base_numerator: Annotated[int, Field(ge=1, le=1_000_000)]
    time_base_denominator: Annotated[int, Field(ge=1, le=1_000_000_000)]
    sequence_start: Annotated[int, Field(ge=0)]
    max_bytes_per_second: Annotated[int, Field(ge=1, le=64 * 1024 * 1024)]
    max_packet_bytes: Annotated[int, Field(ge=1, le=16 * 1024 * 1024)]
    issued_at: AwareDatetime
    attach_by: AwareDatetime
    transport: Literal["scm_rights"]
    media_state: Literal["video_only_ready"]
    single_attach: Literal[True]

    @model_validator(mode="after")
    def coherent_attach_authority(self) -> "ReadOnlyMediaHandle":
        if not self.issued_at < self.attach_by <= self.issued_at + timedelta(seconds=5):
            raise ValueError("media_handle_attach_window_invalid")
        if self.max_packet_bytes > self.max_bytes_per_second:
            raise ValueError("media_handle_packet_rate_invalid")
        return self

class CameraZoneV1(VisionContract):
    schema_id: Literal["camera_zone.v1"] = "camera_zone.v1"
    zone_id: StableVisionId
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    polygon_normalized: Annotated[tuple[NormalizedPoint, ...], Field(min_length=3, max_length=64)]
    exclusion_mask_commitment: Sha256Digest
    privacy_class: Literal["approved_common", "boundary_exclusion", "prohibited_private"]
    zone_generation: Annotated[int, Field(ge=1)]
    status: Literal["commissioned", "disabled", "retired"]

class CameraBindingV1(VisionContract):
    schema_id: Literal["camera_binding.v1"] = "camera_binding.v1"
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    source_endpoint_id: StableHomeId
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    device_commitment: HmacCommitment
    capability_digest: Sha256Digest
    source_path: Literal["direct_local", "proved_bridge", "native_sd_only", "inventory_only", "vendor_native_only"]
    egress_state: Literal["verified_blocked", "ineligible_unverified"]
    audio_state: Literal["disabled_and_rejected", "ineligible"]
    lifecycle: Literal["quarantined", "commissioned", "disabled", "retired"]

    @model_validator(mode="after")
    def coherent_binding_state(self) -> "CameraBindingV1":
        runnable = self.source_path in {"direct_local", "proved_bridge"}
        if self.lifecycle == "commissioned" and (
            not runnable
            or self.egress_state != "verified_blocked"
            or self.audio_state != "disabled_and_rejected"
        ):
            raise ValueError("camera_binding_commissioned_state_invalid")
        return self
~~~

~~~python
# packages/contracts/src/tuntun_contracts/vision/evidence.py
class CameraEgressCaseV1(VisionContract):
    schema_id: Literal["camera_egress_case.v1"] = "camera_egress_case.v1"
    case_class: CameraEgressCase
    result: Literal["verified_blocked_or_approved_local", "unverified", "observed_unapproved_egress"]
    attempt_count: Annotated[int, Field(ge=1, le=1_000_000)]
    blocked_count: Annotated[int, Field(ge=0, le=1_000_000)]
    approved_local_count: Annotated[int, Field(ge=0, le=1_000_000)]
    unapproved_count: Annotated[int, Field(ge=0, le=1_000_000)]
    started_at: AwareDatetime
    ended_at: AwareDatetime
    evidence_digest: Sha256Digest

    @model_validator(mode="after")
    def coherent_case_result(self) -> "CameraEgressCaseV1":
        if not self.started_at < self.ended_at <= self.started_at + timedelta(minutes=30):
            raise ValueError("camera_egress_case_window_invalid")
        if self.blocked_count + self.approved_local_count + self.unapproved_count != self.attempt_count:
            raise ValueError("camera_egress_case_count_invalid")
        if self.result == "verified_blocked_or_approved_local" and self.unapproved_count != 0:
            raise ValueError("camera_egress_verified_case_has_unapproved_flow")
        if self.result == "observed_unapproved_egress" and self.unapproved_count == 0:
            raise ValueError("camera_egress_unapproved_result_without_flow")
        return self

class CameraEgressEvidenceV1(VisionContract):
    schema_id: Literal["camera_egress_evidence.v1"] = "camera_egress_evidence.v1"
    evidence_id: UUID
    evidence_generation: Annotated[int, Field(ge=1)]
    source_endpoint_id: StableHomeId
    source_endpoint_generation: Annotated[int, Field(ge=1)]
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    physical_device_commitment: HmacCommitment
    credential_handle_id: StableVisionId
    egress_policy_generation: Annotated[int, Field(ge=1)]
    network_ruleset_generation: Annotated[int, Field(ge=1)]
    compiled_camera_destination_commitment: HmacCommitment
    approved_local_ntp_commitment: HmacCommitment | None
    device_remote_features_state: Literal["disabled", "unavailable_boundary_blocked"]
    network_boundary_state: Literal["enforced", "unverified"]
    cases: Annotated[tuple[CameraEgressCaseV1, ...], Field(min_length=12, max_length=12)]
    capture_started_at: AwareDatetime
    capture_ended_at: AwareDatetime
    observed_at: AwareDatetime
    valid_until: AwareDatetime
    device_config_digest: Sha256Digest
    network_ruleset_digest: Sha256Digest
    capture_digest: Sha256Digest
    evidence_state: Literal["eligible_local_only", "ineligible_unverified"]
    reason_codes: Annotated[tuple[SafeReasonCode, ...], Field(max_length=16)]

    @model_validator(mode="after")
    def coherent_egress_evidence(self) -> "CameraEgressEvidenceV1":
        case_names = tuple(case.case_class for case in self.cases)
        if set(case_names) != REQUIRED_CAMERA_EGRESS_CASES or len(case_names) != len(set(case_names)):
            raise ValueError("camera_egress_cases_incomplete_or_duplicate")
        if not self.capture_started_at < self.capture_ended_at <= self.capture_started_at + timedelta(hours=24):
            raise ValueError("camera_egress_capture_window_invalid")
        if not self.capture_ended_at <= self.observed_at <= self.capture_ended_at + timedelta(minutes=5):
            raise ValueError("camera_egress_observation_time_invalid")
        if not self.observed_at < self.valid_until <= self.observed_at + timedelta(days=30):
            raise ValueError("camera_egress_evidence_lifetime_invalid")
        if any(
            case.started_at < self.capture_started_at or case.ended_at > self.capture_ended_at
            for case in self.cases
        ):
            raise ValueError("camera_egress_case_outside_capture")
        eligible = (
            self.network_boundary_state == "enforced"
            and all(case.result == "verified_blocked_or_approved_local" for case in self.cases)
        )
        if eligible != (self.evidence_state == "eligible_local_only"):
            raise ValueError("camera_egress_evidence_state_invalid")
        if eligible == bool(self.reason_codes):
            raise ValueError("camera_egress_evidence_reason_state_invalid")
        return self

class TrackMixArcTrialV1(VisionContract):
    schema_id: Literal["trackmix_arc_trial.v1"] = "trackmix_arc_trial.v1"
    doorway: TrackMixDoorway
    motion_mode: TrackMixMotionMode
    condition: TrackMixCondition
    traversal_count: Annotated[int, Field(ge=30, le=10_000)]
    prohibited_target_visible: bool
    control_survived: bool
    evidence_digest: Sha256Digest

class TrackMixArcEvidenceV1(VisionContract):
    schema_id: Literal["trackmix_arc_evidence.v1"] = "trackmix_arc_evidence.v1"
    evidence_id: UUID
    arc_generation: Annotated[int, Field(ge=1)]
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    source_eligibility_generation: Annotated[int, Field(ge=1)]
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    zone_id: StableVisionId
    zone_generation: Annotated[int, Field(ge=1)]
    privacy_policy_version: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    doorways: Annotated[tuple[TrackMixDoorway, ...], Field(min_length=2, max_length=2)]
    enabled_motion_modes: Annotated[tuple[TrackMixMotionMode, ...], Field(min_length=6, max_length=6)]
    covered_conditions: Annotated[tuple[TrackMixCondition, ...], Field(min_length=10, max_length=10)]
    trials: Annotated[tuple[TrackMixArcTrialV1, ...], Field(min_length=120, max_length=120)]
    fixed_wide_zero_visibility: bool
    digital_fixed_guard_point_pass: bool
    physical_all_conditions_pass: bool
    decision: Literal[
        "fixed_wide_eligible", "digital_tracking_eligible", "physical_tracking_eligible", "camera_excluded",
    ]
    qualified_at: AwareDatetime
    valid_until: AwareDatetime
    build_digest: Sha256Digest
    config_digest: Sha256Digest
    evidence_hashes: Annotated[tuple[Sha256Digest, ...], Field(min_length=1, max_length=32)]
    reason_codes: Annotated[tuple[SafeReasonCode, ...], Field(max_length=16)]

    @model_validator(mode="after")
    def coherent_trackmix_arc(self) -> "TrackMixArcEvidenceV1":
        if set(self.doorways) != REQUIRED_TRACKMIX_DOORWAYS or len(self.doorways) != len(set(self.doorways)):
            raise ValueError("trackmix_doorway_set_invalid")
        if (
            set(self.enabled_motion_modes) != REQUIRED_TRACKMIX_MOTION_MODES
            or len(self.enabled_motion_modes) != len(set(self.enabled_motion_modes))
        ):
            raise ValueError("trackmix_motion_mode_set_invalid")
        if (
            set(self.covered_conditions) != REQUIRED_TRACKMIX_CONDITIONS
            or len(self.covered_conditions) != len(set(self.covered_conditions))
        ):
            raise ValueError("trackmix_condition_set_invalid")
        keys = tuple((trial.doorway, trial.motion_mode, trial.condition) for trial in self.trials)
        required_keys = {
            (doorway, mode, condition)
            for doorway in self.doorways
            for mode in self.enabled_motion_modes
            for condition in self.covered_conditions
        }
        if len(keys) != len(set(keys)) or set(keys) != required_keys:
            raise ValueError("trackmix_trial_matrix_invalid")
        if (
            len(self.evidence_hashes) != len(set(self.evidence_hashes))
            or any(trial.evidence_digest not in self.evidence_hashes for trial in self.trials)
        ):
            raise ValueError("trackmix_evidence_hash_binding_invalid")
        # Every matrix cell is an independently exercised lighting/reset case.
        # The field-level lower bound requires >=30 traversals for each exact
        # (doorway, motion_mode, condition), never an aggregate across cells.
        if not self.qualified_at < self.valid_until <= self.qualified_at + timedelta(days=365):
            raise ValueError("trackmix_arc_lifetime_invalid")

        def mode_safe(mode: TrackMixMotionMode) -> bool:
            selected = tuple(trial for trial in self.trials if trial.motion_mode == mode)
            return bool(selected) and all(
                not trial.prohibited_target_visible and trial.control_survived for trial in selected
            )

        fixed_trials = tuple(trial for trial in self.trials if trial.motion_mode == "fixed_wide")
        fixed_zero = bool(fixed_trials) and all(not trial.prohibited_target_visible for trial in fixed_trials)
        fixed_pass = fixed_zero and all(trial.control_survived for trial in fixed_trials)
        digital_pass = fixed_pass and mode_safe("digital_tracking")
        physical_pass = digital_pass and all(
            mode_safe(mode) for mode in self.enabled_motion_modes if mode not in {"fixed_wide", "digital_tracking"}
        )
        expected_decision = (
            "physical_tracking_eligible" if physical_pass
            else "digital_tracking_eligible" if digital_pass
            else "fixed_wide_eligible" if fixed_pass
            else "camera_excluded"
        )
        if (
            self.fixed_wide_zero_visibility != fixed_zero
            or self.digital_fixed_guard_point_pass != digital_pass
            or self.physical_all_conditions_pass != physical_pass
            or self.decision != expected_decision
        ):
            raise ValueError("trackmix_arc_decision_invalid")
        if (self.decision == "camera_excluded") != bool(self.reason_codes):
            raise ValueError("trackmix_arc_reason_state_invalid")
        return self

class CapacityCampaignCameraV1(VisionContract):
    schema_id: Literal["capacity_campaign_camera.v1"] = "capacity_campaign_camera.v1"
    source_endpoint_id: StableHomeId
    source_endpoint_generation: Annotated[int, Field(ge=1)]
    physical_device_commitment: HmacCommitment
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    profile_generation: Annotated[int, Field(ge=1)]
    source_eligibility_generation: Annotated[int, Field(ge=1)]
    egress_evidence_generation: Annotated[int, Field(ge=1)]
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    zone_id: StableVisionId
    zone_generation: Annotated[int, Field(ge=1)]
    privacy_policy_version: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    source_path: Literal["direct_local", "proved_bridge", "native_sd_only", "inventory_only", "vendor_native_only"]
    physical_class: Literal["trackmix", "e1_family"]
    disposition: Literal["eligible_measured", "ineligible_explicit"]
    required_views: tuple[Literal["wide"]]
    selected_views: Annotated[tuple[ClipView, ...], Field(min_length=1, max_length=2)]
    trackmix_dual_view_generation: Annotated[int | None, Field(ge=1)]
    trackmix_dual_view_evidence_digest: Sha256Digest | None

    @model_validator(mode="after")
    def exact_campaign_view_selection(self) -> "CapacityCampaignCameraV1":
        if self.required_views != ("wide",) or "wide" not in self.selected_views:
            raise ValueError("capacity_campaign_wide_view_required")
        if len(set(self.selected_views)) != len(self.selected_views):
            raise ValueError("capacity_campaign_duplicate_selected_view")
        selects_tracking = "tracking" in self.selected_views
        expected_view_order = ("wide", "tracking") if selects_tracking else ("wide",)
        if self.selected_views != expected_view_order:
            raise ValueError("capacity_campaign_selected_views_not_canonical")
        tracking_authority = (
            self.trackmix_dual_view_generation,
            self.trackmix_dual_view_evidence_digest,
        )
        if selects_tracking != (
            self.physical_class == "trackmix"
            and self.disposition == "eligible_measured"
            and all(value is not None for value in tracking_authority)
        ):
            raise ValueError("capacity_campaign_tracking_view_not_authorized")
        if not selects_tracking and any(value is not None for value in tracking_authority):
            raise ValueError("capacity_campaign_unused_tracking_authority")
        if self.disposition == "ineligible_explicit" and self.selected_views != ("wide",):
            raise ValueError("ineligible_camera_requires_only_explicit_wide_rows")
        runnable = self.source_path in {"direct_local", "proved_bridge"}
        if runnable != (self.disposition == "eligible_measured"):
            raise ValueError("capacity_campaign_camera_disposition_invalid")
        return self

class StorageMeasurementV1(VisionContract):
    schema_id: Literal["storage_measurement.v1"] = "storage_measurement.v1"
    measurement_id: UUID
    measurement_generation: Annotated[int, Field(ge=1)]
    campaign_id: UUID
    campaign_generation: Annotated[int, Field(ge=1)]
    source_endpoint_id: StableHomeId
    source_endpoint_generation: Annotated[int, Field(ge=1)]
    physical_device_commitment: HmacCommitment
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    profile_generation: Annotated[int, Field(ge=1)]
    source_eligibility_generation: Annotated[int, Field(ge=1)]
    egress_evidence_generation: Annotated[int, Field(ge=1)]
    volume_qualification_generation: Annotated[int, Field(ge=1)]
    catalog_generation: Annotated[int, Field(ge=1)]
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    zone_id: StableVisionId
    zone_generation: Annotated[int, Field(ge=1)]
    privacy_policy_version: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    source_path: Literal["direct_local", "proved_bridge", "native_sd_only", "inventory_only", "vendor_native_only"]
    view: ClipView
    day_index: Annotated[int, Field(ge=1, le=7)]
    day_started_at: AwareDatetime
    day_ended_at: AwareDatetime
    central_recording: Literal["available", "unavailable"]
    measurement_basis: Literal["measured", "none_ineligible"]
    complete_continuous_bytes: Annotated[int, Field(ge=0)]
    event_bytes: Annotated[int, Field(ge=0)]
    highest_fifteen_minute_bytes: Annotated[int, Field(ge=0)]
    coverage_ratio: Annotated[Decimal, Field(ge=Decimal("0"), le=Decimal("1"))]
    gap_seconds: Annotated[int, Field(ge=0, le=86_400)]
    longest_gap_detection_seconds: Annotated[int, Field(ge=0, le=86_400)]
    corrupt_segment_count: Annotated[int, Field(ge=0)]
    stored_audio_stream_count: Literal[0]
    finalized_at: AwareDatetime
    valid_until: AwareDatetime
    measurement_digest: Sha256Digest
    reason_codes: Annotated[tuple[SafeReasonCode, ...], Field(max_length=16)]

    @model_validator(mode="after")
    def coherent_storage_measurement(self) -> "StorageMeasurementV1":
        if self.day_ended_at - self.day_started_at != timedelta(hours=24):
            raise ValueError("storage_measurement_day_window_invalid")
        if not self.day_ended_at <= self.finalized_at <= self.day_ended_at + timedelta(hours=1):
            raise ValueError("storage_measurement_finalization_invalid")
        if not self.finalized_at < self.valid_until <= self.finalized_at + timedelta(days=90):
            raise ValueError("storage_measurement_lifetime_invalid")
        runnable = self.source_path in {"direct_local", "proved_bridge"}
        available = self.central_recording == "available"
        if available != runnable or available != (self.measurement_basis == "measured"):
            raise ValueError("storage_measurement_eligibility_state_invalid")
        if not available:
            measured_values = (
                self.complete_continuous_bytes, self.event_bytes, self.highest_fifteen_minute_bytes,
                self.coverage_ratio, self.gap_seconds, self.longest_gap_detection_seconds,
                self.corrupt_segment_count,
            )
            if any(value != 0 for value in measured_values) or not self.reason_codes:
                raise ValueError("storage_measurement_ineligible_value_invalid")
        elif self.view == "wide" and self.complete_continuous_bytes == 0:
            raise ValueError("storage_measurement_wide_continuous_missing")
        if self.view == "tracking" and self.complete_continuous_bytes != 0:
            raise ValueError("storage_measurement_tracking_continuous_forbidden")
        if self.measurement_digest != storage_measurement_digest(self):
            raise ValueError("storage_measurement_digest_mismatch")
        return self

def storage_measurement_digest(measurement: StorageMeasurementV1) -> Sha256Digest:
    payload = measurement.model_dump(mode="python", exclude={"measurement_digest"})
    return sha256(canonical_mapping_bytes(payload)).hexdigest()

class CapacityCampaignV1(VisionContract):
    schema_id: Literal["capacity_campaign.v1"] = "capacity_campaign.v1"
    campaign_id: UUID
    campaign_generation: Annotated[int, Field(ge=1)]
    expected_cameras: Annotated[tuple[CapacityCampaignCameraV1, ...], Field(min_length=3, max_length=3)]
    measurements: Annotated[tuple[StorageMeasurementV1, ...], Field(min_length=21, max_length=42)]
    volume_qualification_generation: Annotated[int, Field(ge=1)]
    catalog_generation: Annotated[int, Field(ge=1)]
    campaign_started_at: AwareDatetime
    campaign_ended_at: AwareDatetime
    manifest_digest: Sha256Digest

    @model_validator(mode="after")
    def exact_semantic_measurement_matrix(self) -> "CapacityCampaignV1":
        if self.campaign_ended_at != self.campaign_started_at + timedelta(days=7):
            raise ValueError("capacity_campaign_must_be_exactly_seven_contiguous_days")
        camera_ids = tuple(row.source_endpoint_id for row in self.expected_cameras)
        physical_devices = tuple(
            row.physical_device_commitment for row in self.expected_cameras
        )
        if len(set(camera_ids)) != 3 or len(set(physical_devices)) != 3:
            raise ValueError("capacity_campaign_expected_camera_set_invalid")
        if camera_ids != tuple(sorted(camera_ids)):
            raise ValueError("capacity_campaign_camera_order_not_canonical")
        if len({row.privacy_generation for row in self.expected_cameras}) != 1:
            raise ValueError("capacity_campaign_global_privacy_generation_mismatch")
        expected_keys = tuple(
            (camera.source_endpoint_id, view, day_index)
            for camera in self.expected_cameras
            for view in camera.selected_views
            for day_index in range(1, 8)
        )
        actual_keys = tuple(
            (row.source_endpoint_id, row.view, row.day_index)
            for row in self.measurements
        )
        if actual_keys != expected_keys:
            raise ValueError("capacity_campaign_matrix_missing_duplicate_or_extra_row")
        camera_by_id = {row.source_endpoint_id: row for row in self.expected_cameras}
        for row in self.measurements:
            camera = camera_by_id[row.source_endpoint_id]
            expected_start = self.campaign_started_at + timedelta(days=row.day_index - 1)
            if (
                row.campaign_id != self.campaign_id
                or row.campaign_generation != self.campaign_generation
                or row.source_endpoint_generation != camera.source_endpoint_generation
                or row.physical_device_commitment != camera.physical_device_commitment
                or row.camera_binding_id != camera.camera_binding_id
                or row.camera_binding_generation != camera.camera_binding_generation
                or row.capability_generation != camera.capability_generation
                or row.profile_generation != camera.profile_generation
                or row.source_eligibility_generation != camera.source_eligibility_generation
                or row.egress_evidence_generation != camera.egress_evidence_generation
                or row.volume_qualification_generation != self.volume_qualification_generation
                or row.catalog_generation != self.catalog_generation
                or row.area_id != camera.area_id
                or row.area_generation != camera.area_generation
                or row.zone_id != camera.zone_id
                or row.zone_generation != camera.zone_generation
                or row.privacy_policy_version != camera.privacy_policy_version
                or row.privacy_generation != camera.privacy_generation
                or row.source_path != camera.source_path
                or row.day_started_at != expected_start
                or row.day_ended_at != expected_start + timedelta(days=1)
            ):
                raise ValueError("capacity_campaign_row_authority_or_window_mismatch")
            available = row.central_recording == "available"
            if available != (camera.disposition == "eligible_measured"):
                raise ValueError("capacity_campaign_disposition_row_mismatch")
        if self.manifest_digest != capacity_campaign_manifest_digest(self):
            raise ValueError("capacity_campaign_manifest_digest_mismatch")
        return self

class GreenBackupReceiptV1(VisionContract):
    schema_id: Literal["green_backup_receipt.v1"] = "green_backup_receipt.v1"
    receipt_id: UUID
    receipt_generation: Annotated[int, Field(ge=1)]
    backup_run_id: UUID
    backup_policy_generation: Annotated[int, Field(ge=1)]
    green_objective_generation: Annotated[int, Field(ge=1)]
    campaign_id: UUID
    campaign_generation: Annotated[int, Field(ge=1)]
    campaign_manifest_digest: Sha256Digest
    campaign_started_at: AwareDatetime
    campaign_ended_at: AwareDatetime
    volume_handle: VideoVolumeHandle
    volume_handle_commitment: HmacCommitment
    bound_video_quota_bytes: Annotated[int, Field(ge=1)]
    minimum_ha_backup_reserve_bytes: Annotated[int, Field(ge=1)]
    load_snapshot_id: UUID
    load_snapshot_at: AwareDatetime
    concurrent_load_digest: Sha256Digest
    backup_started_at: AwareDatetime
    backup_finished_at: AwareDatetime
    status: Literal["completed", "failed", "cancelled"]
    objective_state: Literal["met", "missed"]
    receipt_digest: Sha256Digest

    @model_validator(mode="after")
    def exact_minimized_backup_receipt(self) -> "GreenBackupReceiptV1":
        if (
            self.campaign_ended_at != self.campaign_started_at + timedelta(days=7)
            or not self.campaign_started_at <= self.load_snapshot_at
            <= self.backup_started_at < self.backup_finished_at <= self.campaign_ended_at
        ):
            raise ValueError("green_backup_receipt_time_or_preload_invalid")
        if (
            self.bound_video_quota_bytes != self.volume_handle.video_quota_bytes
            or self.minimum_ha_backup_reserve_bytes
            != self.volume_handle.minimum_ha_backup_reserve_bytes
        ):
            raise ValueError("green_backup_receipt_quota_binding_invalid")
        if self.status != "completed" and self.objective_state != "missed":
            raise ValueError("green_backup_receipt_status_invalid")
        if self.receipt_digest != green_backup_receipt_digest(self):
            raise ValueError("green_backup_receipt_digest_invalid")
        return self

class SignedGreenBackupReceiptV1(VisionContract):
    schema_id: Literal["signed_green_backup_receipt.v1"] = "signed_green_backup_receipt.v1"
    receipt: GreenBackupReceiptV1
    algorithm: Literal["Ed25519"]
    signing_key_id: Annotated[str, Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")]
    signature_b64url: Annotated[str, Field(min_length=86, max_length=86, pattern=r"^[A-Za-z0-9_-]+$")]

def green_backup_receipt_digest(receipt: GreenBackupReceiptV1) -> Sha256Digest:
    payload = receipt.model_dump(mode="python", exclude={"receipt_digest"})
    return sha256(canonical_mapping_bytes(payload)).hexdigest()

class CapacityOperationalEvidenceV1(VisionContract):
    schema_id: Literal["capacity_operational_evidence.v1"] = "capacity_operational_evidence.v1"
    evidence_id: UUID
    campaign_id: UUID
    campaign_generation: Annotated[int, Field(ge=1)]
    volume_handle: VideoVolumeHandle
    volume_handle_commitment: HmacCommitment
    measured_catalog_and_filesystem_overhead: Annotated[int, Field(ge=0)]
    voice_p95_seconds: Annotated[Decimal, Field(ge=Decimal("0"))]
    voice_regression_percent: Annotated[Decimal, Field(ge=Decimal("0"))]
    green_backup_receipt: SignedGreenBackupReceiptV1
    observed_at: AwareDatetime
    evidence_digest: Sha256Digest

    @model_validator(mode="after")
    def exact_operational_backup_binding(self) -> "CapacityOperationalEvidenceV1":
        receipt = self.green_backup_receipt.receipt
        if (
            receipt.campaign_id != self.campaign_id
            or receipt.campaign_generation != self.campaign_generation
            or receipt.volume_handle != self.volume_handle
            or receipt.volume_handle_commitment != self.volume_handle_commitment
            or receipt.status != "completed"
            or receipt.objective_state != "met"
            or self.observed_at < receipt.backup_finished_at
        ):
            raise ValueError("capacity_operational_backup_binding_invalid")
        if self.evidence_digest != capacity_operational_evidence_digest(self):
            raise ValueError("capacity_operational_evidence_digest_invalid")
        return self

def capacity_operational_evidence_digest(evidence: CapacityOperationalEvidenceV1) -> Sha256Digest:
    payload = evidence.model_dump(mode="python", exclude={"evidence_digest"})
    return sha256(canonical_mapping_bytes(payload)).hexdigest()

class CapacityProjectionV1(VisionContract):
    schema_id: Literal["capacity_projection.v1"] = "capacity_projection.v1"
    projection_id: UUID
    projection_generation: Annotated[int, Field(ge=1)]
    campaign_id: UUID
    campaign_generation: Annotated[int, Field(ge=1)]
    campaign: CapacityCampaignV1
    operational_evidence: CapacityOperationalEvidenceV1
    measurement_ids: Annotated[tuple[UUID, ...], Field(min_length=7, max_length=128)]
    volume_qualification_generation: Annotated[int, Field(ge=1)]
    catalog_generation: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    eligible_camera_count: Annotated[int, Field(ge=0, le=3)]
    ineligible_camera_count: Annotated[int, Field(ge=0, le=3)]
    selected_view_set: Annotated[tuple[ClipView, ...], Field(min_length=1, max_length=2)]
    campaign_started_at: AwareDatetime
    campaign_ended_at: AwareDatetime
    continuous_policy_bytes: Annotated[int, Field(ge=0)]
    event_policy_bytes: Annotated[int, Field(ge=0)]
    measured_catalog_and_filesystem_overhead: Annotated[int, Field(ge=0)]
    policy_bytes: Annotated[int, Field(ge=0)]
    reserve_basis_points: Literal[2000]
    required_usable_capacity: Annotated[int, Field(ge=0)]
    bound_video_quota_bytes: Annotated[int, Field(ge=1)]
    minimum_ha_backup_reserve_bytes: Annotated[int, Field(ge=1)]
    minimum_coverage_ratio: Annotated[Decimal, Field(ge=Decimal("0"), le=Decimal("1"))]
    longest_gap_detection_seconds: Annotated[int, Field(ge=0, le=86_400)]
    voice_p95_seconds: Annotated[Decimal, Field(ge=Decimal("0"))]
    voice_regression_percent: Annotated[Decimal, Field(ge=Decimal("0"))]
    stored_audio_stream_count: Literal[0]
    claim: Literal["complete_eligible_camera_set", "partial_eligible_camera_set"]
    decision: Literal[
        "p3_2_pass", "p3_2_partial", "p3_2_blocked_no_eligible_sources",
        "p3_2_blocked_capacity", "p3_2_blocked_reliability",
    ]
    projected_at: AwareDatetime
    valid_until: AwareDatetime
    measurement_digest: Sha256Digest
    reason_codes: Annotated[tuple[SafeReasonCode, ...], Field(max_length=16)]

    @model_validator(mode="after")
    def coherent_capacity_projection(self) -> "CapacityProjectionV1":
        derived_eligible = sum(
            row.disposition == "eligible_measured" for row in self.campaign.expected_cameras
        )
        backup_receipt = self.operational_evidence.green_backup_receipt.receipt
        expected_overhead = (
            self.operational_evidence.measured_catalog_and_filesystem_overhead
            if derived_eligible > 0 else 0
        )
        if (
            self.campaign_id != self.campaign.campaign_id
            or self.campaign_generation != self.campaign.campaign_generation
            or self.campaign_started_at != self.campaign.campaign_started_at
            or self.campaign_ended_at != self.campaign.campaign_ended_at
            or self.measurement_ids != tuple(row.measurement_id for row in self.campaign.measurements)
            or self.volume_qualification_generation != self.campaign.volume_qualification_generation
            or self.catalog_generation != self.campaign.catalog_generation
            or self.operational_evidence.campaign_id != self.campaign_id
            or self.operational_evidence.campaign_generation != self.campaign_generation
            or self.volume_qualification_generation
            != self.operational_evidence.volume_handle.qualification_generation
            or self.bound_video_quota_bytes != self.operational_evidence.volume_handle.video_quota_bytes
            or self.minimum_ha_backup_reserve_bytes
            != self.operational_evidence.volume_handle.minimum_ha_backup_reserve_bytes
            or self.measured_catalog_and_filesystem_overhead != expected_overhead
            or self.voice_p95_seconds != self.operational_evidence.voice_p95_seconds
            or self.voice_regression_percent != self.operational_evidence.voice_regression_percent
            or backup_receipt.campaign_manifest_digest != self.campaign.manifest_digest
            or backup_receipt.campaign_started_at != self.campaign.campaign_started_at
            or backup_receipt.campaign_ended_at != self.campaign.campaign_ended_at
            or backup_receipt.concurrent_load_digest != capacity_campaign_load_digest(self.campaign)
            or any(
                camera.privacy_generation != self.privacy_generation
                for camera in self.campaign.expected_cameras
            )
        ):
            raise ValueError("capacity_projection_campaign_binding_invalid")
        if len(self.measurement_ids) != len(set(self.measurement_ids)):
            raise ValueError("capacity_measurement_duplicate")
        derived_views = tuple(sorted({
            view for row in self.campaign.expected_cameras for view in row.selected_views
        }))
        if (
            self.eligible_camera_count != derived_eligible
            or self.ineligible_camera_count != 3 - derived_eligible
        ):
            raise ValueError("capacity_camera_set_invalid")
        if self.selected_view_set != derived_views:
            raise ValueError("capacity_view_set_invalid")
        measured = tuple(
            row for row in self.campaign.measurements if row.measurement_basis == "measured"
        )
        derived_continuous = 7 * sum(
            max(
                row.complete_continuous_bytes
                for row in measured
                if row.source_endpoint_id == camera.source_endpoint_id and row.view == "wide"
            )
            for camera in self.campaign.expected_cameras
            if camera.disposition == "eligible_measured"
        )
        derived_event_daily = sum(
            max(
                Decimal(max(values := [
                    row.event_bytes for row in measured
                    if row.source_endpoint_id == camera.source_endpoint_id and row.view == view
                ])),
                Decimal("1.5") * sum(Decimal(value) for value in values) / Decimal(7),
            )
            for camera in self.campaign.expected_cameras
            if camera.disposition == "eligible_measured"
            for view in camera.selected_views
        )
        derived_event = ceil_decimal(Decimal(90) * derived_event_daily)
        continuous_reliability_rows = tuple(row for row in measured if row.view == "wide")
        derived_coverage = min(
            (row.coverage_ratio for row in continuous_reliability_rows),
            default=Decimal("0"),
        )
        derived_gap = max(
            (row.longest_gap_detection_seconds for row in continuous_reliability_rows),
            default=0,
        )
        if (
            self.continuous_policy_bytes != derived_continuous
            or self.event_policy_bytes != derived_event
            or self.minimum_coverage_ratio != derived_coverage
            or self.longest_gap_detection_seconds != derived_gap
            or self.measurement_digest != capacity_campaign_measurement_digest(self.campaign)
        ):
            raise ValueError("capacity_projection_derived_evidence_mismatch")
        elapsed = self.campaign_ended_at - self.campaign_started_at
        if elapsed < timedelta(days=7) or elapsed > timedelta(days=8):
            raise ValueError("capacity_campaign_window_invalid")
        if not self.campaign_ended_at <= self.projected_at <= self.campaign_ended_at + timedelta(hours=1):
            raise ValueError("capacity_projection_time_invalid")
        if (
            self.projection_generation != self.campaign_generation
            or self.projected_at != self.operational_evidence.observed_at
            or self.projection_id != capacity_projection_id(
                self.campaign, self.operational_evidence, self.projection_generation
            )
        ):
            raise ValueError("capacity_projection_identity_not_evidence_derived")
        if self.valid_until != self.projected_at + timedelta(days=90):
            raise ValueError("capacity_projection_lifetime_invalid")
        expected_policy = (
            self.continuous_policy_bytes
            + self.event_policy_bytes
            + self.measured_catalog_and_filesystem_overhead
        )
        if self.policy_bytes != expected_policy or self.required_usable_capacity != (5 * expected_policy + 3) // 4:
            raise ValueError("capacity_projection_formula_invalid")
        partial = self.ineligible_camera_count > 0
        if partial != (self.claim == "partial_eligible_camera_set"):
            raise ValueError("capacity_projection_claim_invalid")
        expected_decision = classify_p3_2_from_derived(
            eligible_camera_count=derived_eligible,
            required_usable_capacity=self.required_usable_capacity,
            bound_video_quota_bytes=self.bound_video_quota_bytes,
            minimum_coverage_ratio=self.minimum_coverage_ratio,
            longest_gap_detection_seconds=self.longest_gap_detection_seconds,
            voice_p95_seconds=self.voice_p95_seconds,
            voice_regression_percent=self.voice_regression_percent,
        )
        if (
            self.decision != expected_decision
            or self.reason_codes != capacity_reason_codes(expected_decision)
        ):
            raise ValueError("capacity_projection_decision_or_reason_invalid")
        if derived_eligible == 0 and any((
            self.continuous_policy_bytes,
            self.event_policy_bytes,
            self.measured_catalog_and_filesystem_overhead,
            self.policy_bytes,
            self.required_usable_capacity,
        )):
            raise ValueError("capacity_no_eligible_policy_bytes_must_be_zero")
        return self

def capacity_campaign_measurement_digest(campaign: CapacityCampaignV1) -> Sha256Digest:
    return sha256(canonical_vision_bytes(campaign)).hexdigest()

def capacity_campaign_load_digest(campaign: CapacityCampaignV1) -> Sha256Digest:
    payload = campaign.model_dump(
        mode="python",
        include={
            "campaign_id", "campaign_generation", "expected_cameras",
            "volume_qualification_generation", "catalog_generation",
            "campaign_started_at", "campaign_ended_at", "manifest_digest",
        },
    )
    return sha256(canonical_mapping_bytes(payload)).hexdigest()

CAPACITY_PROJECTION_NAMESPACE = UUID("9946442f-21f9-4a51-bdd0-2dd00e0aa53d")

def capacity_projection_id(
    campaign: CapacityCampaignV1,
    evidence: CapacityOperationalEvidenceV1,
    projection_generation: int,
) -> UUID:
    return uuid5(
        CAPACITY_PROJECTION_NAMESPACE,
        ":".join((
            str(campaign.campaign_id), str(campaign.campaign_generation),
            campaign.manifest_digest, capacity_campaign_measurement_digest(campaign),
            str(evidence.evidence_id), evidence.evidence_digest,
            evidence.volume_handle_commitment,
            str(projection_generation),
        )),
    )

def classify_p3_2_from_derived(
    *,eligible_camera_count:int,required_usable_capacity:int,
    bound_video_quota_bytes:int,minimum_coverage_ratio:Decimal,
    longest_gap_detection_seconds:int,voice_p95_seconds:Decimal,
    voice_regression_percent:Decimal,
) -> Literal[
    "p3_2_pass","p3_2_partial","p3_2_blocked_no_eligible_sources",
    "p3_2_blocked_capacity","p3_2_blocked_reliability",
]:
    reliability_ok=(
        minimum_coverage_ratio>=Decimal("0.995")
        and longest_gap_detection_seconds<=30
        and voice_p95_seconds<=Decimal("4")
        and voice_regression_percent<=Decimal("10")
    )
    if eligible_camera_count==0: return "p3_2_blocked_no_eligible_sources"
    if not reliability_ok: return "p3_2_blocked_reliability"
    if bound_video_quota_bytes<required_usable_capacity:
        return "p3_2_blocked_capacity"
    if eligible_camera_count<3: return "p3_2_partial"
    return "p3_2_pass"

def capacity_reason_codes(decision:str) -> tuple[SafeReasonCode,...]:
    return {
        "p3_2_pass":(),
        "p3_2_partial":("partial_eligible_camera_set",),
        "p3_2_blocked_no_eligible_sources":("no_eligible_camera_source",),
        "p3_2_blocked_capacity":("video_quota_below_required_capacity",),
        "p3_2_blocked_reliability":("capacity_reliability_gate_failed",),
    }[decision]

def capacity_campaign_manifest_digest(campaign: CapacityCampaignV1) -> Sha256Digest:
    payload = campaign.model_dump(
        mode="python",
        include={
            "campaign_id", "campaign_generation", "expected_cameras",
            "volume_qualification_generation", "catalog_generation",
            "campaign_started_at", "campaign_ended_at",
        },
    )
    return sha256(canonical_mapping_bytes(payload)).hexdigest()
~~~

~~~python
# packages/contracts/src/tuntun_contracts/vision/events.py
class NativeCameraEventV1(VisionContract):
    schema_id: Literal["native_camera_event.v1"] = "native_camera_event.v1"
    native_event_id: UUID
    source_endpoint_id: StableHomeId
    source_endpoint_generation: Annotated[int, Field(ge=1)]
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    zone_id: StableVisionId
    zone_generation: Annotated[int, Field(ge=1)]
    detector_code: NativeDetectorCode
    event_state: Literal["started", "updated", "ended"]
    started_at: AwareDatetime
    ended_at: AwareDatetime | None
    observed_at: AwareDatetime
    confidence_band: Literal["unavailable", "low", "medium", "high"]
    native_sequence: Annotated[int, Field(ge=0)]
    deduplication_key: HmacCommitment

    @model_validator(mode="after")
    def coherent_native_event(self) -> "NativeCameraEventV1":
        if self.started_at > self.observed_at or self.observed_at - self.started_at > timedelta(minutes=5):
            raise ValueError("native_camera_event_window_invalid")
        if self.event_state == "ended":
            if self.ended_at is None or not self.started_at <= self.ended_at <= self.observed_at:
                raise ValueError("native_camera_event_end_invalid")
        elif self.ended_at is not None:
            raise ValueError("native_camera_event_open_state_has_end")
        return self

class CameraSecurityEventV1(VisionContract):
    schema_id: Literal["camera.security_event.v1"] = "camera.security_event.v1"
    event_id: UUID
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    zone_id: StableVisionId
    zone_generation: Annotated[int, Field(ge=1)]
    event_class: CameraEventClass
    detector_basis: Literal["device_native", "hub_native"]
    detector_version: BoundedSafeCode
    started_at: AwareDatetime
    ended_at: AwareDatetime | None
    observed_at: AwareDatetime
    confidence_band: Literal["unavailable", "low", "medium", "high"]
    verification: Literal["native", "corroborated", "uncertain"]
    clock_quality: Literal["synchronized", "degraded", "untrusted"]
    clip_ref: UUID | None
    view_set: Literal["wide", "wide_and_tracking"]
    privacy_policy_version: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]

    @model_validator(mode="after")
    def coherent_window(self) -> "CameraSecurityEventV1":
        if (
            self.started_at > self.observed_at
            or self.observed_at - self.started_at > timedelta(minutes=5)
        ):
            raise ValueError("camera_event_observation_window_invalid")
        if self.ended_at is not None and (
            self.ended_at < self.started_at
            or self.ended_at > self.observed_at
            or self.ended_at - self.started_at > timedelta(minutes=5)
        ):
            raise ValueError("camera_event_window_invalid")
        return self

class PresenceChangedV1(VisionContract):
    schema_id: Literal["presence.changed.v1"] = "presence.changed.v1"
    event_id: UUID
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    state: Literal["vacant", "occupied", "unknown"]
    count_band: Literal["zero", "one", "multiple", "unknown"]
    source_kinds: Annotated[tuple[PresenceSourceKind, ...], Field(min_length=1, max_length=4)]
    evidence_policy_version: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    confidence_band: Literal["low", "medium", "high"]
    observed_at: AwareDatetime
    valid_until: AwareDatetime
    transition_reason: SafeReasonCode

    @model_validator(mode="after")
    def coherent_presence(self) -> "PresenceChangedV1":
        if not self.observed_at < self.valid_until <= self.observed_at + timedelta(minutes=5):
            raise ValueError("presence_validity_invalid")
        if len(self.source_kinds) != len(set(self.source_kinds)):
            raise ValueError("presence_source_duplicate")
        if self.state == "unknown" and (self.count_band != "unknown" or self.confidence_band != "low"):
            raise ValueError("unknown_presence_shape_invalid")
        if self.state == "vacant":
            if (
                self.count_band != "zero"
                or self.source_kinds != ("commissioned_non_imaging",)
            ):
                raise ValueError("vacant_presence_requires_non_imaging")
        if self.state == "occupied" and self.count_band == "zero":
            raise ValueError("occupied_presence_zero_invalid")
        if self.state == "occupied" and "camera_native_person" in self.source_kinds and "commissioned_non_imaging" not in self.source_kinds:
            if self.count_band != "unknown":
                raise ValueError("camera_presence_count_forbidden")
        return self

class AnonymousPresenceEvidenceV1(VisionContract):
    schema_id: Literal["anonymous_presence_evidence.v1"] = "anonymous_presence_evidence.v1"
    evidence_id: UUID
    kind: Literal["camera_native_person", "commissioned_non_imaging"]
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    asserted_state: Literal["occupied", "vacant"]
    count_band: Literal["zero", "one", "multiple", "unknown"]
    event_id: UUID | None
    camera_binding_id: StableVisionId | None
    camera_binding_generation: Annotated[int | None, Field(ge=1)]
    capability_generation: Annotated[int | None, Field(ge=1)]
    zone_id: StableVisionId | None
    zone_generation: Annotated[int | None, Field(ge=1)]
    non_imaging_rule_id: StableVisionId | None
    non_imaging_rule_generation: Annotated[int | None, Field(ge=1)]
    policy_version: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    confidence_band: Literal["low", "medium", "high"]
    observed_at: AwareDatetime
    max_valid_until: AwareDatetime
    commitment: HmacCommitment

    @model_validator(mode="after")
    def coherent_presence_evidence(self) -> "AnonymousPresenceEvidenceV1":
        if not self.observed_at < self.max_valid_until <= self.observed_at + timedelta(minutes=5):
            raise ValueError("presence_evidence_lifetime_invalid")
        camera_fields = (
            self.event_id, self.camera_binding_id, self.camera_binding_generation,
            self.capability_generation, self.zone_id, self.zone_generation,
        )
        rule_fields = (self.non_imaging_rule_id, self.non_imaging_rule_generation)
        if self.kind == "camera_native_person":
            if any(value is None for value in camera_fields) or any(value is not None for value in rule_fields):
                raise ValueError("camera_presence_binding_invalid")
            if self.asserted_state != "occupied" or self.count_band != "unknown":
                raise ValueError("camera_presence_assertion_invalid")
        else:
            if any(value is not None for value in camera_fields) or any(value is None for value in rule_fields):
                raise ValueError("non_imaging_presence_binding_invalid")
            if (self.asserted_state == "vacant") != (self.count_band == "zero"):
                raise ValueError("non_imaging_presence_state_invalid")
        return self

# Exact accepted tuntun_contracts.home.events definition; vision.events imports/re-exports it and MUST NOT redefine it.
from tuntun_contracts.home.events import CrossDomainEventV1

class CameraSecurityEventEnvelopeV1(CrossDomainEventV1[CameraSecurityEventV1]):
    """Closed camera observation route; a fresh wrapper cannot revive a stale payload."""

    event_type: Literal["camera.security_event.v1"]
    payload: CameraSecurityEventV1

    @model_validator(mode="after")
    def coherent_camera_payload_time(self) -> "CameraSecurityEventEnvelopeV1":
        if self.observed_at != self.payload.observed_at:
            raise ValueError("camera_event_observed_at_mismatch")
        return self

class PresenceChangedEventV1(CrossDomainEventV1[PresenceChangedV1]):
    """Closed observation route; this is not an HA entity or action command."""
    event_type: Literal["presence.changed.v1"]
    payload: PresenceChangedV1

    @model_validator(mode="after")
    def coherent_presence_payload_window(self) -> "PresenceChangedEventV1":
        if self.observed_at != self.payload.observed_at:
            raise ValueError("presence_event_observed_at_mismatch")
        if self.expires_at > self.payload.valid_until:
            raise ValueError("presence_event_expiry_exceeds_payload_validity")
        return self

class EventIngressReceiptV1(VisionContract):
    schema_id: Literal["event_ingress_receipt.v1"] = "event_ingress_receipt.v1"
    receipt_id: UUID
    event_id: UUID
    state: Literal["accepted", "duplicate", "quarantined"]
    dispatched_to_alerts: bool
    dispatched_to_presence: bool
    processed_at: AwareDatetime
    event_commitment: HmacCommitment
    reason_codes: Annotated[tuple[SafeReasonCode, ...], Field(max_length=8)]

    @model_validator(mode="after")
    def coherent_ingress_state(self) -> "EventIngressReceiptV1":
        if self.state in {"duplicate", "quarantined"} and (self.dispatched_to_alerts or self.dispatched_to_presence):
            raise ValueError("event_ingress_nonaccepted_dispatch_forbidden")
        if (self.state == "quarantined") != bool(self.reason_codes):
            raise ValueError("event_ingress_reason_state_invalid")
        return self
~~~

~~~python
# packages/contracts/src/tuntun_contracts/vision/media.py
class OpaqueMediaManifestV1(VisionContract):
    schema_id: Literal["opaque_media_manifest.v1"] = "opaque_media_manifest.v1"
    manifest_id: UUID
    manifest_generation: Annotated[int, Field(ge=1)]
    media_kind: Literal["segment", "clip_view"]
    storage_token: OpaqueStorageToken
    segment_id: UUID | None
    clip_id: UUID | None
    clip_generation: Annotated[int | None, Field(ge=1)]
    view: ClipView | None
    source_endpoint_id: StableHomeId
    source_endpoint_generation: Annotated[int, Field(ge=1)]
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    profile_generation: Annotated[int, Field(ge=1)]
    source_eligibility_generation: Annotated[int, Field(ge=1)]
    egress_evidence_generation: Annotated[int, Field(ge=1)]
    volume_qualification_generation: Annotated[int, Field(ge=1)]
    catalog_generation: Annotated[int, Field(ge=1)]
    catalog_transaction_id: UUID
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    zone_id: StableVisionId
    zone_generation: Annotated[int, Field(ge=1)]
    event_id: UUID | None
    event_class: CameraEventClass | None
    stream_role: Literal["low_wide", "event_wide", "event_tracking", "transient_event_ring"]
    started_at: AwareDatetime
    ended_at: AwareDatetime
    byte_count: Annotated[int, Field(ge=1, le=4 * 1024 * 1024 * 1024)]
    sha256: Sha256Digest
    retention_class: Literal["continuous_7d", "event_90d", "transient_60s"]
    immutable_expires_at: AwareDatetime
    container: Literal["matroska"]
    audio_stream_count: Literal[0]
    video_stream_count: Literal[1]
    manifested_at: AwareDatetime
    media_state: Literal["rebuild_only_not_playback_authority"]
    manifest_commitment: HmacCommitment

    @model_validator(mode="after")
    def coherent_opaque_manifest(self) -> "OpaqueMediaManifestV1":
        if self.ended_at <= self.started_at:
            raise ValueError("media_manifest_window_invalid")
        maximum_duration = (
            timedelta(seconds=60)
            if self.stream_role in {"low_wide", "transient_event_ring"}
            else timedelta(minutes=5)
        )
        if self.ended_at - self.started_at > maximum_duration:
            raise ValueError("media_manifest_duration_invalid")
        lifetime = {
            "continuous_7d": timedelta(days=7),
            "event_90d": timedelta(days=90),
            "transient_60s": timedelta(seconds=60),
        }[self.retention_class]
        if self.immutable_expires_at != self.ended_at + lifetime:
            raise ValueError("media_manifest_retention_invalid")
        expected_retention = {
            "low_wide": "continuous_7d",
            "event_wide": "event_90d",
            "event_tracking": "event_90d",
            "transient_event_ring": "transient_60s",
        }[self.stream_role]
        if self.retention_class != expected_retention:
            raise ValueError("media_manifest_stream_retention_invalid")
        if not self.ended_at <= self.manifested_at <= self.ended_at + timedelta(minutes=5):
            raise ValueError("media_manifest_creation_time_invalid")
        location_fields = (
            self.area_id, self.area_generation, self.zone_id, self.zone_generation,
        )
        event_fields = (self.event_id, self.event_class)
        if not all(value is not None for value in location_fields):
            raise ValueError("media_manifest_location_authority_missing")
        if self.media_kind == "segment":
            if self.segment_id is None or any(
                value is not None for value in (self.clip_id, self.clip_generation, self.view)
            ):
                raise ValueError("media_manifest_segment_identity_invalid")
            event_stream = self.stream_role in {"event_wide", "event_tracking"}
            if event_stream != all(value is not None for value in event_fields):
                raise ValueError("media_manifest_segment_event_binding_invalid")
            if not event_stream and any(value is not None for value in event_fields):
                raise ValueError("media_manifest_non_event_metadata_forbidden")
        else:
            if (
                self.segment_id is not None
                or self.clip_id is None
                or self.clip_generation is None
                or self.view is None
                or not all(value is not None for value in event_fields)
            ):
                raise ValueError("media_manifest_clip_identity_invalid")
            expected_role = "event_wide" if self.view == "wide" else "event_tracking"
            if self.stream_role != expected_role or self.retention_class != "event_90d":
                raise ValueError("media_manifest_clip_view_invalid")
        return self

class RecordingProfileV1(VisionContract):
    schema_id: Literal["recording_profile.v1"] = "recording_profile.v1"
    activation_id: UUID
    profile_id: StableVisionId
    profile_generation: Annotated[int, Field(ge=1)]
    supersedes_profile_generation: Annotated[int | None, Field(ge=1)]
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    stream_role: Literal["low_wide"]
    container: Literal["matroska"]
    segment_seconds: Literal[60]
    retention_class: Literal["continuous_7d"]
    retention_seconds: Literal[604800]
    media_mode: Literal["stream_copy_only"]
    audio_policy: Literal["reject"]
    max_segment_bytes: Annotated[int, Field(ge=1, le=4 * 1024 * 1024 * 1024)]
    profile_state: Literal["commissioned"]

    @model_validator(mode="after")
    def coherent_profile_lineage(self) -> "RecordingProfileV1":
        if self.profile_generation == 1 and self.supersedes_profile_generation is not None:
            raise ValueError("recording_profile_initial_lineage_invalid")
        if self.profile_generation > 1 and self.supersedes_profile_generation != self.profile_generation - 1:
            raise ValueError("recording_profile_lineage_invalid")
        return self

class RecorderStartV1(VisionContract):
    schema_id: Literal["recorder_start.v1"] = "recorder_start.v1"
    command_id: UUID
    operation: Literal["recorder.start.camera"]
    binding: CameraBindingV1
    profile: RecordingProfileV1
    zone_id: StableVisionId
    zone_generation: Annotated[int, Field(ge=1)]
    source_eligibility_generation: Annotated[int, Field(ge=1)]
    egress_evidence_generation: Annotated[int, Field(ge=1)]
    volume_qualification_generation: Annotated[int, Field(ge=1)]
    policy_version: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    single_use: Literal[True]
    authorization_commitment: HmacCommitment

    @model_validator(mode="after")
    def exact_start_authority(self) -> "RecorderStartV1":
        if self.command_id != self.profile.activation_id:
            raise ValueError("recorder_start_activation_mismatch")
        if (
            self.profile.camera_binding_id != self.binding.camera_binding_id
            or self.profile.camera_binding_generation != self.binding.camera_binding_generation
        ):
            raise ValueError("recorder_start_profile_binding_mismatch")
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("recorder_start_window_invalid")
        return self

class RecorderPauseV1(VisionContract):
    schema_id: Literal["recorder_pause.v1"] = "recorder_pause.v1"
    command_id: UUID
    operation: Literal["recorder.pause.camera"]
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    profile_generation: Annotated[int, Field(ge=1)]
    expected_recorder_generation: Annotated[int, Field(ge=1)]
    policy_version: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    single_use: Literal[True]
    authorization_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_pause_window(self) -> "RecorderPauseV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("recorder_pause_window_invalid")
        return self

class RecorderResumeV1(VisionContract):
    schema_id: Literal["recorder_resume.v1"] = "recorder_resume.v1"
    command_id: UUID
    operation: Literal["recorder.resume.camera"]
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    zone_id: StableVisionId
    zone_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    profile_generation: Annotated[int, Field(ge=1)]
    source_eligibility_generation: Annotated[int, Field(ge=1)]
    volume_qualification_generation: Annotated[int, Field(ge=1)]
    expected_recorder_generation: Annotated[int, Field(ge=1)]
    policy_version: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    resume_evidence_digest: Sha256Digest
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    single_use: Literal[True]
    authorization_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_resume_window(self) -> "RecorderResumeV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("recorder_resume_window_invalid")
        return self

class RecorderReceiptV1(VisionContract):
    schema_id: Literal["recorder_receipt.v1"] = "recorder_receipt.v1"
    receipt_id: UUID
    causation_id: UUID
    operation: Literal["start", "pause", "resume"]
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    profile_generation: Annotated[int, Field(ge=1)]
    recorder_generation: Annotated[int, Field(ge=1)]
    outcome: Literal["applied", "already_applied", "rejected"]
    recorder_state: Literal["running", "paused", "failed"]
    processed_at: AwareDatetime
    effective_at: AwareDatetime | None
    gap_started_at: AwareDatetime | None
    receipt_commitment: HmacCommitment
    reason_codes: Annotated[tuple[SafeReasonCode, ...], Field(max_length=8)]

    @model_validator(mode="after")
    def coherent_receipt_state(self) -> "RecorderReceiptV1":
        if self.outcome == "rejected":
            if not self.reason_codes:
                raise ValueError("recorder_rejection_reason_required")
            if self.effective_at is not None or self.gap_started_at is not None:
                raise ValueError("recorder_rejection_effect_forbidden")
            return self
        if (
            self.recorder_state == "failed"
            or self.reason_codes
            or self.effective_at is None
            or self.effective_at > self.processed_at
        ):
            raise ValueError("recorder_success_state_invalid")
        if self.operation == "pause":
            if self.recorder_state != "paused" or self.gap_started_at is None or self.gap_started_at > self.effective_at:
                raise ValueError("recorder_pause_receipt_invalid")
        elif self.recorder_state != "running" or self.gap_started_at is not None:
            raise ValueError("recorder_running_receipt_invalid")
        return self

class StagedSegment(VisionContract):
    schema_id: Literal["staged_segment.v1"] = "staged_segment.v1"
    segment_id: UUID
    staging_token: OpaqueStagingToken
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    profile_generation: Annotated[int, Field(ge=1)]
    stream_role: Literal["low_wide", "event_wide", "event_tracking", "transient_event_ring"]
    started_at: AwareDatetime
    ended_at: AwareDatetime
    sequence_start: Annotated[int, Field(ge=0)]
    sequence_end: Annotated[int, Field(ge=0)]
    codec: CameraCodec
    width: Annotated[int, Field(ge=1, le=7680)]
    height: Annotated[int, Field(ge=1, le=4320)]
    fps_band: Literal["low", "standard", "high"]
    byte_count: Annotated[int, Field(ge=1, le=4 * 1024 * 1024 * 1024)]
    sha256: Sha256Digest
    completeness: Literal["complete", "truncated", "corrupt"]
    retention_class: Literal["continuous_7d", "event_90d", "transient_60s"]
    immutable_expires_at: AwareDatetime
    container: Literal["matroska"]
    audio_stream_count: Literal[0]
    video_stream_count: Literal[1]
    stage_state: Literal["staged_checksummed"]

    @model_validator(mode="after")
    def coherent_staged_segment(self) -> "StagedSegment":
        if self.ended_at <= self.started_at or self.sequence_end < self.sequence_start:
            raise ValueError("staged_segment_window_or_sequence_invalid")
        maximum_duration = (
            timedelta(seconds=60)
            if self.stream_role in {"low_wide", "transient_event_ring"}
            else timedelta(minutes=5)
        )
        if self.ended_at - self.started_at > maximum_duration:
            raise ValueError("staged_segment_duration_invalid")
        lifetime = {
            "continuous_7d": timedelta(days=7),
            "event_90d": timedelta(days=90),
            "transient_60s": timedelta(seconds=60),
        }[self.retention_class]
        if self.immutable_expires_at != self.ended_at + lifetime:
            raise ValueError("staged_segment_retention_invalid")
        expected_class = {
            "low_wide": "continuous_7d",
            "event_wide": "event_90d",
            "event_tracking": "event_90d",
            "transient_event_ring": "transient_60s",
        }[self.stream_role]
        if self.retention_class != expected_class:
            raise ValueError("staged_segment_stream_retention_invalid")
        return self

class SegmentV1(VisionContract):
    schema_id: Literal["segment.v1"] = "segment.v1"
    segment_id: UUID
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    stream_role: Literal["low_wide", "event_wide", "event_tracking", "transient_event_ring"]
    started_at: AwareDatetime
    ended_at: AwareDatetime
    sequence_start: Annotated[int, Field(ge=0)]
    sequence_end: Annotated[int, Field(ge=0)]
    codec: CameraCodec
    width: Annotated[int, Field(ge=1)]
    height: Annotated[int, Field(ge=1)]
    fps_band: Literal["low", "standard", "high"]
    byte_count: Annotated[int, Field(ge=0)]
    sha256: Sha256Digest
    completeness: Literal["complete", "truncated", "corrupt", "missing"]
    retention_class: Literal["continuous_7d", "event_90d", "transient_60s"]
    immutable_expires_at: AwareDatetime
    opaque_storage_token: OpaqueStorageToken

    @model_validator(mode="after")
    def coherent_segment(self) -> "SegmentV1":
        if self.ended_at <= self.started_at or self.sequence_end < self.sequence_start:
            raise ValueError("segment_window_or_sequence_invalid")
        maximum_duration = (
            timedelta(seconds=60)
            if self.stream_role in {"low_wide", "transient_event_ring"}
            else timedelta(minutes=5)
        )
        if self.ended_at - self.started_at > maximum_duration:
            raise ValueError("segment_duration_invalid")
        lifetime = {
            "continuous_7d": timedelta(days=7),
            "event_90d": timedelta(days=90),
            "transient_60s": timedelta(seconds=60),
        }[self.retention_class]
        if self.immutable_expires_at != self.ended_at + lifetime:
            raise ValueError("segment_retention_invalid")
        expected_class = {
            "low_wide": "continuous_7d",
            "event_wide": "event_90d",
            "event_tracking": "event_90d",
            "transient_event_ring": "transient_60s",
        }[self.stream_role]
        if self.retention_class != expected_class:
            raise ValueError("segment_stream_retention_invalid")
        return self

class ClipV1(VisionContract):
    schema_id: Literal["clip.v1"] = "clip.v1"
    clip_id: UUID
    clip_generation: Annotated[int, Field(ge=1)]
    catalog_generation: Annotated[int, Field(ge=1)]
    event_id: UUID
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    zone_id: StableVisionId
    zone_generation: Annotated[int, Field(ge=1)]
    event_class: CameraEventClass
    started_at: AwareDatetime
    ended_at: AwareDatetime
    view_refs: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=2)]
    completeness: Literal["complete", "partial", "corrupt"]
    immutable_expires_at: AwareDatetime
    playback_capability_state: Literal["eligible", "blocked", "expired"]

    @model_validator(mode="after")
    def coherent_clip(self) -> "ClipV1":
        if (
            self.ended_at <= self.started_at
            or self.ended_at - self.started_at > timedelta(minutes=5)
            or self.immutable_expires_at != self.ended_at + timedelta(days=90)
        ):
            raise ValueError("clip_window_invalid")
        if len(self.view_refs) != len(set(self.view_refs)):
            raise ValueError("clip_view_ref_duplicate")
        if self.completeness == "corrupt" and self.playback_capability_state == "eligible":
            raise ValueError("corrupt_clip_playback_eligible")
        return self

class ClipUnavailableV1(VisionContract):
    schema_id: Literal["clip_unavailable.v1"] = "clip_unavailable.v1"
    event_id: UUID
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    zone_id: StableVisionId
    zone_generation: Annotated[int, Field(ge=1)]
    catalog_generation: Annotated[int, Field(ge=1)]
    state: Literal["unavailable"]
    reason: Literal[
        "stream_unavailable", "event_channel_untrusted", "storage_write_blocked",
        "media_corrupt", "generation_stale", "promotion_window_missed",
    ]
    event_started_at: AwareDatetime
    event_ended_at: AwareDatetime | None
    determined_at: AwareDatetime
    retryable: Literal[False]
    reason_commitment: HmacCommitment

    @model_validator(mode="after")
    def coherent_unavailable_event(self) -> "ClipUnavailableV1":
        event_end = self.event_ended_at or self.event_started_at
        if (
            event_end < self.event_started_at
            or event_end - self.event_started_at > timedelta(minutes=5)
            or self.determined_at < event_end
        ):
            raise ValueError("clip_unavailable_window_invalid")
        return self

class StagedClipViewV1(VisionContract):
    schema_id: Literal["staged_clip_view.v1"] = "staged_clip_view.v1"
    view: ClipView
    staging_token: OpaqueStagingToken
    started_at: AwareDatetime
    ended_at: AwareDatetime
    codec: CameraCodec
    byte_count: Annotated[int, Field(ge=1, le=4 * 1024 * 1024 * 1024)]
    sha256: Sha256Digest
    audio_stream_count: Literal[0]
    video_stream_count: Literal[1]
    stage_state: Literal["staged_checksummed"]

    @model_validator(mode="after")
    def coherent_view_window(self) -> "StagedClipViewV1":
        if self.ended_at <= self.started_at:
            raise ValueError("staged_clip_view_window_invalid")
        return self

class StagedClip(VisionContract):
    schema_id: Literal["staged_clip.v1"] = "staged_clip.v1"
    clip_id: UUID
    clip_generation: Annotated[int, Field(ge=1)]
    catalog_generation: Annotated[int, Field(ge=1)]
    event_id: UUID
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    zone_id: StableVisionId
    zone_generation: Annotated[int, Field(ge=1)]
    event_class: CameraEventClass
    started_at: AwareDatetime
    ended_at: AwareDatetime
    views: Annotated[tuple[StagedClipViewV1, ...], Field(min_length=1, max_length=2)]
    completeness: Literal["complete", "partial", "corrupt"]
    immutable_expires_at: AwareDatetime
    stage_state: Literal["staged_checksummed"]

    @model_validator(mode="after")
    def coherent_staged_clip(self) -> "StagedClip":
        if (
            self.ended_at <= self.started_at
            or self.ended_at - self.started_at > timedelta(minutes=5)
            or self.immutable_expires_at != self.ended_at + timedelta(days=90)
        ):
            raise ValueError("staged_clip_window_invalid")
        view_names = tuple(view.view for view in self.views)
        if len(view_names) != len(set(view_names)) or "wide" not in view_names:
            raise ValueError("staged_clip_view_set_invalid")
        if any(view.started_at < self.started_at or view.ended_at > self.ended_at for view in self.views):
            raise ValueError("staged_clip_view_outside_clip")
        if len(self.views) == 2:
            wide = next(view for view in self.views if view.view == "wide")
            tracking = next(view for view in self.views if view.view == "tracking")
            if max(
                abs(wide.started_at - tracking.started_at),
                abs(wide.ended_at - tracking.ended_at),
            ) > timedelta(seconds=2):
                raise ValueError("staged_clip_dual_view_alignment_invalid")
        return self

class OwnerClipQueryV1(VisionContract):
    schema_id: Literal["owner_clip_query.v1"] = "owner_clip_query.v1"
    query_id: UUID
    owner_subject_id: StableSubjectId
    owner_session_id: UUID
    area_id: StableHomeId | None
    area_generation: Annotated[int | None, Field(ge=1)]
    camera_binding_id: StableVisionId | None
    camera_binding_generation: Annotated[int | None, Field(ge=1)]
    zone_id: StableVisionId | None
    zone_generation: Annotated[int | None, Field(ge=1)]
    event_classes: Annotated[tuple[CameraEventClass, ...], Field(max_length=6)]
    view: ClipView | None
    started_at: AwareDatetime
    ended_before: AwareDatetime
    page_size: Annotated[int, Field(ge=1, le=100)]
    cursor: OpaqueCursor | None
    expected_catalog_generation: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    query_commitment: HmacCommitment

    @model_validator(mode="after")
    def coherent_owner_query(self) -> "OwnerClipQueryV1":
        if not self.started_at < self.ended_before <= self.started_at + timedelta(days=90):
            raise ValueError("owner_clip_query_range_invalid")
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("owner_clip_query_window_invalid")
        if (self.camera_binding_id is None) != (self.camera_binding_generation is None):
            raise ValueError("owner_clip_query_camera_binding_invalid")
        if (self.area_id is None) != (self.area_generation is None):
            raise ValueError("owner_clip_query_area_binding_invalid")
        if (self.zone_id is None) != (self.zone_generation is None):
            raise ValueError("owner_clip_query_zone_binding_invalid")
        if self.zone_id is not None and self.area_id is None:
            raise ValueError("owner_clip_query_zone_without_area")
        if len(self.event_classes) != len(set(self.event_classes)):
            raise ValueError("owner_clip_query_event_duplicate")
        return self

class OwnerSegmentQueryV1(VisionContract):
    schema_id: Literal["owner_segment_query.v1"] = "owner_segment_query.v1"
    query_id: UUID
    owner_subject_id: StableSubjectId
    owner_session_id: UUID
    area_id: StableHomeId | None
    area_generation: Annotated[int | None, Field(ge=1)]
    camera_binding_id: StableVisionId | None
    camera_binding_generation: Annotated[int | None, Field(ge=1)]
    started_at: AwareDatetime
    ended_before: AwareDatetime
    page_size: Annotated[int, Field(ge=1, le=100)]
    cursor: OpaqueCursor | None
    expected_catalog_generation: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    query_commitment: HmacCommitment

    @model_validator(mode="after")
    def coherent_segment_query(self) -> "OwnerSegmentQueryV1":
        if not self.started_at < self.ended_before <= self.started_at + timedelta(days=7):
            raise ValueError("owner_segment_query_range_invalid")
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("owner_segment_query_window_invalid")
        if (self.camera_binding_id is None) != (self.camera_binding_generation is None):
            raise ValueError("owner_segment_query_camera_binding_invalid")
        if (self.area_id is None) != (self.area_generation is None):
            raise ValueError("owner_segment_query_area_binding_invalid")
        return self

class OwnerSegmentTimelineItemV1(VisionContract):
    schema_id: Literal["owner_segment_timeline_item.v1"] = "owner_segment_timeline_item.v1"
    segment_id: UUID
    catalog_generation: Annotated[int, Field(ge=1)]
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    zone_id: StableVisionId
    zone_generation: Annotated[int, Field(ge=1)]
    stream_role: Literal["low_wide"]
    started_at: AwareDatetime
    ended_at: AwareDatetime
    completeness: Literal["complete", "truncated"]
    immutable_expires_at: AwareDatetime
    playback_capability_state: Literal["eligible", "blocked", "expired"]

    @model_validator(mode="after")
    def coherent_owner_segment_item(self) -> "OwnerSegmentTimelineItemV1":
        if (
            not self.started_at < self.ended_at <= self.started_at + timedelta(seconds=60)
            or self.immutable_expires_at != self.ended_at + timedelta(days=7)
        ):
            raise ValueError("owner_segment_timeline_window_invalid")
        return self

PageItemT = TypeVar("PageItemT", bound=VisionContract)

class OpaquePage(VisionContract, Generic[PageItemT]):
    schema_id: Literal["opaque_page.v1"] = "opaque_page.v1"
    query_id: UUID
    query_commitment: HmacCommitment
    catalog_generation: Annotated[int, Field(ge=1)]
    items: Annotated[tuple[PageItemT, ...], Field(max_length=100)]
    page_state: Literal["complete", "more"]
    next_cursor: OpaqueCursor | None
    issued_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def coherent_page(self) -> "OpaquePage[PageItemT]":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=30):
            raise ValueError("opaque_page_window_invalid")
        if (self.page_state == "more") != (self.next_cursor is not None):
            raise ValueError("opaque_page_cursor_state_invalid")
        if any(
            getattr(item, "catalog_generation", self.catalog_generation) != self.catalog_generation
            for item in self.items
        ):
            raise ValueError("opaque_page_catalog_generation_mismatch")
        return self

class InclusiveByteRangeV1(VisionContract):
    start: Annotated[int, Field(ge=0)]
    end_inclusive: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def bounded_ordered_range(self) -> "InclusiveByteRangeV1":
        if self.end_inclusive < self.start or self.end_inclusive - self.start + 1 > 8 * 1024 * 1024:
            raise ValueError("playback_byte_range_invalid")
        return self

class ClipPlaybackSubjectV1(VisionContract):
    kind: Literal["event_clip"] = "event_clip"
    clip_id: UUID
    clip_generation: Annotated[int, Field(ge=1)]
    catalog_generation: Annotated[int, Field(ge=1)]
    view: ClipView

class SegmentPlaybackSubjectV1(VisionContract):
    kind: Literal["continuous_segment"] = "continuous_segment"
    segment_id: UUID
    catalog_generation: Annotated[int, Field(ge=1)]
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    stream_role: Literal["low_wide"] = "low_wide"

PlaybackSubjectV1 = Annotated[
    ClipPlaybackSubjectV1 | SegmentPlaybackSubjectV1,
    Field(discriminator="kind"),
]

class PlaybackRangeRequestV1(VisionContract):
    schema_id: Literal["playback_range_request.v1"] = "playback_range_request.v1"
    request_id: UUID
    subject: PlaybackSubjectV1
    byte_range: InclusiveByteRangeV1
    expected_catalog_generation: Annotated[int, Field(ge=1)]
    expected_privacy_generation: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    request_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_request_window(self) -> "PlaybackRangeRequestV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("playback_range_request_window_invalid")
        if self.subject.catalog_generation != self.expected_catalog_generation:
            raise ValueError("playback_range_request_catalog_binding_invalid")
        return self

OpaquePlaybackRouteToken = Annotated[
    str,
    Field(min_length=43, max_length=43, pattern=r"^[A-Za-z0-9_-]{43}$"),
]

class MediaPlaybackGrantV1(VisionContract):
    grant_id: UUID
    route_token_digest: Sha256Digest
    owner_subject_id: StableSubjectId
    owner_session_id: UUID
    owner_session_generation: Annotated[int, Field(ge=1)]
    owner_session_binding_commitment: HmacCommitment
    subject: PlaybackSubjectV1
    allowed_operation: Literal["playback"]
    allowed_range_bytes: InclusiveByteRangeV1
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    single_use: Literal[True]
    policy_version: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    parameter_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_lifetime(self) -> "MediaPlaybackGrantV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=60):
            raise ValueError("media_playback_grant_window_invalid")
        return self

class SignedMediaPlaybackGrantV1(VisionContract):
    schema_id: Literal["signed_media_playback_grant.v1"] = "signed_media_playback_grant.v1"
    grant: MediaPlaybackGrantV1
    algorithm: Literal["Ed25519"]
    signing_key_id: Annotated[str, Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")]
    signature_b64url: Annotated[str, Field(min_length=86, max_length=86, pattern=r"^[A-Za-z0-9_-]+$")]

class MediaGrantRegisterV1(VisionContract):
    schema_id: Literal["media_grant_register.v1"] = "media_grant_register.v1"
    registration_id: UUID
    signed_grant: SignedMediaPlaybackGrantV1
    signed_grant_digest: Sha256Digest
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    registration_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_registration(self) -> "MediaGrantRegisterV1":
        if (
            self.issued_at != self.signed_grant.grant.issued_at
            or self.expires_at != self.signed_grant.grant.expires_at
            or self.signed_grant_digest
            != hashlib.sha256(canonical_vision_bytes(self.signed_grant)).hexdigest()
        ):
            raise ValueError("media_grant_registration_window_mismatch")
        return self

class MediaGrantRegisterReceiptV1(VisionContract):
    schema_id: Literal["media_grant_register_receipt.v1"] = "media_grant_register_receipt.v1"
    registration_id: UUID
    grant_id: UUID
    signed_grant_digest: Sha256Digest
    grant_expires_at: AwareDatetime
    outcome: Literal["registered", "already_registered", "rejected"]
    recorder_generation: Annotated[int, Field(ge=1)]
    processed_at: AwareDatetime
    receipt_commitment: HmacCommitment
    reason_codes: Annotated[tuple[SafeReasonCode, ...], Field(max_length=8)]

    @model_validator(mode="after")
    def coherent_registration_receipt(self) -> "MediaGrantRegisterReceiptV1":
        if (self.outcome == "rejected") != bool(self.reason_codes):
            raise ValueError("media_grant_registration_reason_state_invalid")
        if self.outcome != "rejected" and self.processed_at >= self.grant_expires_at:
            raise ValueError("media_grant_registration_expired")
        return self

class MediaGrantClaimV1(VisionContract):
    schema_id: Literal["media_grant_claim.v1"] = "media_grant_claim.v1"
    claim_id: UUID
    route_token_digest: Sha256Digest
    requested_range_bytes: InclusiveByteRangeV1
    owner_session_id: UUID
    owner_session_generation: Annotated[int, Field(ge=1)]
    owner_session_binding_commitment: HmacCommitment
    session_derivation_id: UUID
    session_derivation_commitment: HmacCommitment
    ingress_request_id: UUID
    ingress_context_commitment: HmacCommitment
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    claim_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_claim(self) -> "MediaGrantClaimV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=2):
            raise ValueError("media_grant_claim_window_invalid")
        return self

def canonical_media_grant_claim_unsigned_bytes(claim: MediaGrantClaimV1) -> bytes:
    payload = claim.model_dump(mode="python", exclude={"claim_commitment"})
    return canonical_mapping_bytes(payload)

class MediaGrantClaimReceiptV1(VisionContract):
    schema_id: Literal["media_grant_claim_receipt.v1"] = "media_grant_claim_receipt.v1"
    claim_id: UUID
    ingress_context_commitment: HmacCommitment
    claim_issued_at: AwareDatetime
    claim_expires_at: AwareDatetime
    claim_commitment: HmacCommitment
    grant_id: UUID | None
    route_token_digest: Sha256Digest
    requested_range_bytes: InclusiveByteRangeV1
    signed_grant_digest: Sha256Digest | None
    outcome: Literal["claimed", "rejected"]
    subject: PlaybackSubjectV1 | None
    allowed_range_bytes: InclusiveByteRangeV1 | None
    opaque_storage_token: OpaqueStorageToken | None
    expires_at: AwareDatetime | None
    processed_at: AwareDatetime
    receipt_commitment: HmacCommitment
    reason_codes: Annotated[tuple[SafeReasonCode, ...], Field(max_length=8)]

    @model_validator(mode="after")
    def coherent_claim_receipt(self) -> "MediaGrantClaimReceiptV1":
        if (
            not self.claim_issued_at < self.claim_expires_at
            <= self.claim_issued_at + timedelta(seconds=2)
        ):
            raise ValueError("media_grant_claim_receipt_window_invalid")
        authority = (
            self.grant_id, self.signed_grant_digest, self.subject,
            self.allowed_range_bytes, self.opaque_storage_token, self.expires_at,
        )
        if self.outcome == "claimed":
            if (
                any(value is None for value in authority)
                or self.reason_codes
            ):
                raise ValueError("media_grant_claim_success_invalid")
            assert self.expires_at is not None
            assert self.allowed_range_bytes is not None
            if (
                not self.claim_issued_at <= self.processed_at < self.claim_expires_at
                or self.expires_at <= self.processed_at
                or self.requested_range_bytes != self.allowed_range_bytes
            ):
                raise ValueError("media_grant_claim_success_invalid")
        elif any(value is not None for value in authority) or not self.reason_codes:
            raise ValueError("media_grant_claim_rejection_invalid")
        return self

class PreparedPlaybackRangeV1(VisionContract):
    schema_id: Literal["prepared_playback_range.v1"] = "prepared_playback_range.v1"
    grant_id: UUID
    opaque_grant_id: OpaquePlaybackRouteToken
    route_token_digest: Sha256Digest
    signed_grant_digest: Sha256Digest
    issued_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def exact_route_token_window(self) -> "PreparedPlaybackRangeV1":
        if self.route_token_digest != hashlib.sha256(
            self.opaque_grant_id.encode("ascii")
        ).hexdigest():
            raise ValueError("prepared_playback_route_token_digest_mismatch")
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=60):
            raise ValueError("prepared_playback_window_invalid")
        return self

class ClipExportRequestV1(VisionContract):
    schema_id: Literal["clip_export_request.v1"] = "clip_export_request.v1"
    command_id: UUID
    operation: Literal["camera.clip.export"]
    clip_id: UUID
    clip_generation: Annotated[int, Field(ge=1)]
    catalog_generation: Annotated[int, Field(ge=1)]
    views: Annotated[tuple[ClipView, ...], Field(min_length=1, max_length=2)]
    expected_managed_byte_count: Annotated[int, Field(ge=1)]
    expected_immutable_expires_at: AwareDatetime
    recipient_key_id: BoundedSafeCode
    recipient_public_key_b64url: Annotated[
        str, Field(min_length=43, max_length=4096, pattern=r"^[A-Za-z0-9_-]+$")
    ]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    single_use: Literal[True]
    authorization_commitment: HmacCommitment
    request_commitment: HmacCommitment
    request_digest: Sha256Digest

    @model_validator(mode="after")
    def exact_export_authority(self) -> "ClipExportRequestV1":
        if len(self.views) != len(set(self.views)):
            raise ValueError("clip_export_view_duplicate")
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("clip_export_window_invalid")
        if self.request_digest != clip_export_request_digest(self):
            raise ValueError("clip_export_request_digest_invalid")
        return self

class ClipExportReceiptV1(VisionContract):
    schema_id: Literal["clip_export_receipt.v1"] = "clip_export_receipt.v1"
    command_id: UUID
    clip_id: UUID
    clip_generation: Annotated[int, Field(ge=1)]
    catalog_generation: Annotated[int, Field(ge=1)]
    views: Annotated[tuple[ClipView, ...], Field(min_length=1, max_length=2)]
    recipient_key_id: BoundedSafeCode
    recipient_public_key_digest: Sha256Digest
    request_commitment: HmacCommitment
    request_digest: Sha256Digest
    outcome: Literal["applied", "already_applied", "rejected"]
    ciphertext_handle: OpaqueStorageToken | None
    ciphertext_byte_count: Annotated[int | None, Field(ge=1)]
    ciphertext_sha256: Sha256Digest | None
    download_expires_at: AwareDatetime | None
    download_single_use: Literal[True] | None
    processed_at: AwareDatetime
    receipt_commitment: HmacCommitment
    reason_codes: Annotated[tuple[SafeReasonCode, ...], Field(max_length=8)]

    @model_validator(mode="after")
    def coherent_export_receipt(self) -> "ClipExportReceiptV1":
        output = (
            self.ciphertext_handle, self.ciphertext_byte_count,
            self.ciphertext_sha256, self.download_expires_at, self.download_single_use,
        )
        if self.outcome == "rejected":
            if any(value is not None for value in output) or not self.reason_codes:
                raise ValueError("clip_export_rejection_invalid")
        else:
            if any(value is None for value in output) or self.reason_codes:
                raise ValueError("clip_export_success_invalid")
            assert self.download_expires_at is not None
            if (
                not self.processed_at < self.download_expires_at
                <= self.processed_at + timedelta(minutes=5)
                or len(self.views) != len(set(self.views))
            ):
                raise ValueError("clip_export_success_invalid")
        return self

class ClipDeleteRequestV1(VisionContract):
    schema_id: Literal["clip_delete_request.v1"] = "clip_delete_request.v1"
    command_id: UUID
    operation: Literal["camera.clip.delete"]
    clip_id: UUID
    clip_generation: Annotated[int, Field(ge=1)]
    catalog_generation: Annotated[int, Field(ge=1)]
    views: Annotated[tuple[ClipView, ...], Field(min_length=1, max_length=2)]
    expected_view_count: Annotated[int, Field(ge=1, le=2)]
    expected_managed_byte_count: Annotated[int, Field(ge=1)]
    expected_immutable_expires_at: AwareDatetime
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    single_use: Literal[True]
    authorization_commitment: HmacCommitment
    request_commitment: HmacCommitment
    request_digest: Sha256Digest

    @model_validator(mode="after")
    def exact_delete_authority(self) -> "ClipDeleteRequestV1":
        if self.expected_view_count != len(self.views) or len(self.views) != len(set(self.views)):
            raise ValueError("clip_delete_view_set_invalid")
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("clip_delete_window_invalid")
        if self.request_digest != clip_delete_request_digest(self):
            raise ValueError("clip_delete_request_digest_invalid")
        return self

class ClipDeleteReceiptV1(VisionContract):
    schema_id: Literal["clip_delete_receipt.v1"] = "clip_delete_receipt.v1"
    command_id: UUID
    clip_id: UUID
    clip_generation: Annotated[int, Field(ge=1)]
    catalog_generation: Annotated[int, Field(ge=1)]
    views: Annotated[tuple[ClipView, ...], Field(min_length=1, max_length=2)]
    expected_view_count: Annotated[int, Field(ge=1, le=2)]
    expected_managed_byte_count: Annotated[int, Field(ge=1)]
    expected_immutable_expires_at: AwareDatetime
    request_commitment: HmacCommitment
    request_digest: Sha256Digest
    outcome: Literal["applied", "already_applied", "rejected"]
    managed_media_deleted: bool
    deleted_view_count: Annotated[int, Field(ge=0, le=2)]
    deleted_byte_count: Annotated[int, Field(ge=0)]
    physical_flash_erasure_claimed: Literal[False]
    external_copies: Annotated[
        tuple[Literal["camera_microsd", "hub_nvr", "vendor_cloud", "diagnostic", "restore", "owner_export"], ...],
        Field(max_length=6),
    ]
    processed_at: AwareDatetime
    receipt_commitment: HmacCommitment
    reason_codes: Annotated[tuple[SafeReasonCode, ...], Field(max_length=8)]

    @model_validator(mode="after")
    def coherent_delete_receipt(self) -> "ClipDeleteReceiptV1":
        if self.outcome == "rejected":
            if self.managed_media_deleted or self.deleted_view_count or self.deleted_byte_count or not self.reason_codes:
                raise ValueError("clip_delete_rejection_invalid")
        elif (
            not self.managed_media_deleted
            or self.reason_codes
            or self.deleted_view_count != self.expected_view_count
            or self.deleted_byte_count != self.expected_managed_byte_count
            or self.expected_view_count != len(self.views)
            or len(self.views) != len(set(self.views))
        ):
            raise ValueError("clip_delete_success_invalid")
        return self

def clip_export_request_digest(request: ClipExportRequestV1) -> Sha256Digest:
    payload = request.model_dump(mode="python", exclude={"request_digest", "request_commitment"})
    return sha256(canonical_mapping_bytes(payload)).hexdigest()

def clip_delete_request_digest(request: ClipDeleteRequestV1) -> Sha256Digest:
    payload = request.model_dump(mode="python", exclude={"request_digest", "request_commitment"})
    return sha256(canonical_mapping_bytes(payload)).hexdigest()

def canonical_clip_export_request_unsigned_bytes(request: ClipExportRequestV1) -> bytes:
    payload = request.model_dump(mode="python", exclude={"request_commitment"})
    return canonical_mapping_bytes(payload)

def canonical_clip_delete_request_unsigned_bytes(request: ClipDeleteRequestV1) -> bytes:
    payload = request.model_dump(mode="python", exclude={"request_commitment"})
    return canonical_mapping_bytes(payload)
~~~

~~~python
# packages/contracts/src/tuntun_contracts/vision/health.py
class SourceHealthV1(VisionContract):
    schema_id: Literal["source_health.v1"] = "source_health.v1"
    source_endpoint_id: StableHomeId
    source_endpoint_generation: Annotated[int, Field(ge=1)]
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    source_state: Literal["online", "degraded", "offline", "ineligible"]
    stream_state: Literal["ready", "degraded", "closed", "unsupported"]
    event_channel_state: Literal["online", "degraded", "offline", "unsupported"]
    audio_state: Literal["disabled_and_rejected", "ineligible"]
    egress_state: Literal["verified_blocked", "ineligible_unverified"]
    clock_quality: Literal["synchronized", "degraded", "untrusted"]
    observed_at: AwareDatetime
    valid_until: AwareDatetime
    reason_codes: Annotated[tuple[SafeReasonCode, ...], Field(max_length=16)]

    @model_validator(mode="after")
    def coherent_source_health(self) -> "SourceHealthV1":
        if not self.observed_at < self.valid_until <= self.observed_at + timedelta(seconds=60):
            raise ValueError("source_health_window_invalid")
        safe_online = self.audio_state == "disabled_and_rejected" and self.egress_state == "verified_blocked"
        if self.source_state == "online" and (self.stream_state != "ready" or not safe_online):
            raise ValueError("source_health_online_state_invalid")
        if self.source_state == "ineligible":
            if self.stream_state != "closed" or not self.reason_codes:
                raise ValueError("source_health_ineligible_state_invalid")
        elif self.source_state in {"offline", "degraded"} and not self.reason_codes:
            raise ValueError("source_health_reason_required")
        return self

class RecordingHealthV1(VisionContract):
    schema_id: Literal["recording_health.v1"] = "recording_health.v1"
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    profile_generation: Annotated[int, Field(ge=1)]
    recorder_generation: Annotated[int, Field(ge=1)]
    catalog_generation: Annotated[int, Field(ge=1)]
    volume_qualification_generation: Annotated[int, Field(ge=1)]
    stream_role: CameraStreamRole
    source_state: Literal["online", "degraded", "offline", "ineligible"]
    event_channel_state: Literal["online", "degraded", "offline", "unsupported"]
    recorder_state: Literal["running", "paused", "failed"]
    last_complete_segment_at: AwareDatetime | None
    current_gap_seconds: Annotated[int, Field(ge=0)]
    storage_state: Literal["healthy", "warning", "retention_at_risk", "write_blocked"]
    projected_days_continuous: Annotated[Decimal | None, Field(ge=0)]
    projected_days_events: Annotated[Decimal | None, Field(ge=0)]
    clock_skew_seconds: Decimal | None
    observed_at: AwareDatetime
    valid_until: AwareDatetime
    health_reason_codes: Annotated[tuple[SafeReasonCode, ...], Field(max_length=16)]

    @model_validator(mode="after")
    def coherent_recording_health(self) -> "RecordingHealthV1":
        if not self.observed_at < self.valid_until <= self.observed_at + timedelta(seconds=60):
            raise ValueError("recording_health_window_invalid")
        if self.last_complete_segment_at is not None and self.last_complete_segment_at > self.observed_at:
            raise ValueError("recording_health_future_segment")
        if self.recorder_state == "running" and (
            self.source_state in {"offline", "ineligible"} or self.storage_state == "write_blocked"
        ):
            raise ValueError("recording_health_running_state_invalid")
        if self.recorder_state == "failed" and not self.health_reason_codes:
            raise ValueError("recording_health_failure_reason_required")
        return self
~~~

~~~python
# packages/contracts/src/tuntun_contracts/vision/ui.py
class CameraOverviewFactV1(VisionContract):
    schema_id: Literal["camera_overview_fact.v1"] = "camera_overview_fact.v1"
    fact_id: UUID
    source_endpoint_id: StableHomeId
    source_endpoint_generation: Annotated[int, Field(ge=1)]
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    source_eligibility_generation: Annotated[int, Field(ge=1)]
    profile_generation: Annotated[int | None, Field(ge=1)]
    recorder_generation: Annotated[int | None, Field(ge=1)]
    volume_qualification_generation: Annotated[int | None, Field(ge=1)]
    catalog_generation: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    privacy_shield_state: Literal["active", "inactive"]
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    zone_id: StableVisionId
    zone_generation: Annotated[int, Field(ge=1)]
    area_safe_label: SafeUiLabel
    zone_safe_label: SafeUiLabel
    model_state: Literal["exact", "family_unknown"]
    exact_model_code: BoundedSafeCode | None
    firmware_state: Literal["known", "unknown"]
    firmware_revision: BoundedSafeCode | None
    source_disposition: Literal[
        "direct_local", "proved_bridge", "native_sd_only", "inventory_only", "vendor_native_only",
    ]
    source_state: Literal["online", "degraded", "offline", "unknown", "ineligible"]
    egress_state: Literal["verified_blocked", "ineligible_unverified"]
    audio_state: Literal["disabled_and_rejected", "ineligible"]
    clock_quality: Literal["synchronized", "degraded", "untrusted"]
    recorder_state: Literal["running", "paused", "failed", "unavailable"]
    last_complete_segment_at: AwareDatetime | None
    current_gap_seconds: Annotated[int, Field(ge=0)]
    coverage_ratio: Annotated[Decimal | None, Field(ge=Decimal("0"), le=Decimal("1"))]
    storage_state: Literal["healthy", "warning", "retention_at_risk", "write_blocked", "unavailable"]
    continuous_retention_days: Literal[7] | None
    event_retention_days: Literal[90] | None
    verified_copy_count: Annotated[int, Field(ge=0, le=16)]
    arc_state: Literal["not_applicable", "fixed_wide", "digital_tracking", "physical_tracking", "excluded"]
    arc_generation: Annotated[int | None, Field(ge=1)]
    view_set: Annotated[tuple[ClipView, ...], Field(max_length=2)]
    truth_state: Literal["current", "stale", "unknown", "ineligible"]
    observed_at: AwareDatetime
    valid_until: AwareDatetime
    rendered_at: AwareDatetime
    reason_codes: Annotated[tuple[SafeReasonCode, ...], Field(max_length=16)]

    @model_validator(mode="after")
    def coherent_overview_fact(self) -> "CameraOverviewFactV1":
        if not self.observed_at < self.valid_until <= self.observed_at + timedelta(seconds=60):
            raise ValueError("camera_overview_fact_lifetime_invalid")
        if self.rendered_at < self.observed_at:
            raise ValueError("camera_overview_fact_render_time_invalid")
        if (self.model_state == "exact") != (self.exact_model_code is not None):
            raise ValueError("camera_overview_model_state_invalid")
        if (self.firmware_state == "known") != (self.firmware_revision is not None):
            raise ValueError("camera_overview_firmware_state_invalid")
        runnable = self.source_disposition in {"direct_local", "proved_bridge"}
        runtime_generations = (
            self.profile_generation, self.recorder_generation, self.volume_qualification_generation,
        )
        if runnable:
            if (
                any(value is None for value in runtime_generations)
                or self.egress_state != "verified_blocked"
                or self.audio_state != "disabled_and_rejected"
                or "wide" not in self.view_set
                or self.recorder_state == "unavailable"
                or self.coverage_ratio is None
                or self.continuous_retention_days != 7
                or self.event_retention_days != 90
            ):
                raise ValueError("camera_overview_runnable_state_invalid")
        elif (
            any(value is not None for value in runtime_generations)
            or self.view_set
            or self.recorder_state != "unavailable"
            or self.coverage_ratio is not None
            or self.continuous_retention_days is not None
            or self.event_retention_days is not None
        ):
            raise ValueError("camera_overview_ineligible_media_state_invalid")
        if len(self.view_set) != len(set(self.view_set)):
            raise ValueError("camera_overview_view_duplicate")
        if (self.arc_state == "not_applicable") != (self.arc_generation is None):
            raise ValueError("camera_overview_arc_generation_invalid")
        if self.last_complete_segment_at is not None and self.last_complete_segment_at > self.observed_at:
            raise ValueError("camera_overview_future_segment")
        expected_truth = (
            "stale" if self.rendered_at >= self.valid_until
            else "ineligible" if not runnable or self.source_state == "ineligible"
            else "unknown" if self.source_state == "unknown"
            else "current"
        )
        if self.truth_state != expected_truth:
            raise ValueError("camera_overview_truth_state_invalid")
        if self.truth_state in {"stale", "unknown", "ineligible"} and not self.reason_codes:
            raise ValueError("camera_overview_reason_required")
        return self

class CameraOverviewUIV1(VisionContract):
    schema_id: Literal["camera_overview_ui.v1"] = "camera_overview_ui.v1"
    projection_id: UUID
    projection_generation: Annotated[int, Field(ge=1)]
    catalog_generation: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    generated_at: AwareDatetime
    expires_at: AwareDatetime
    facts: Annotated[tuple[CameraOverviewFactV1, ...], Field(max_length=16)]
    projection_state: Literal["current", "partial", "unknown"]
    recorder_independent_from_privacy: Literal[True]
    selected_frame_perception: Literal["absent"]

    @model_validator(mode="after")
    def coherent_camera_overview(self) -> "CameraOverviewUIV1":
        if not self.generated_at < self.expires_at <= self.generated_at + timedelta(seconds=30):
            raise ValueError("camera_overview_window_invalid")
        binding_ids = tuple(fact.camera_binding_id for fact in self.facts)
        if len(binding_ids) != len(set(binding_ids)):
            raise ValueError("camera_overview_binding_duplicate")
        if any(
            fact.rendered_at != self.generated_at
            or fact.catalog_generation != self.catalog_generation
            or fact.privacy_generation != self.privacy_generation
            for fact in self.facts
        ):
            raise ValueError("camera_overview_fact_generation_or_time_invalid")
        current_fact_deadlines = tuple(
            fact.valid_until for fact in self.facts if fact.truth_state == "current"
        )
        if current_fact_deadlines and self.expires_at > min(current_fact_deadlines):
            raise ValueError("camera_overview_outlives_current_fact")
        expected_state = (
            "unknown" if not self.facts
            else "current" if all(fact.truth_state == "current" for fact in self.facts)
            else "partial"
        )
        if self.projection_state != expected_state:
            raise ValueError("camera_overview_projection_state_invalid")
        return self

class SafeAlertSSEV1(VisionContract):
    schema_id: Literal["safe_alert_sse.v1"] = "safe_alert_sse.v1"
    event_id: UUID
    delivery_sequence: Annotated[int, Field(ge=1)]
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    zone_id: StableVisionId
    zone_generation: Annotated[int, Field(ge=1)]
    privacy_policy_version: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    alert_policy_generation: Annotated[int, Field(ge=1)]
    quality_evidence_generation: Annotated[int, Field(ge=1)]
    event_class: CameraEventClass
    verification: Literal["native", "corroborated", "uncertain"]
    confidence_band: Literal["unavailable", "low", "medium", "high"]
    zone_safe_label: SafeUiLabel
    safe_title: Literal["Camera activity detected"]
    safe_body: SafeUiMessage
    clip_state: Literal["available", "unavailable"]
    clip_id: UUID | None
    clip_generation: Annotated[int | None, Field(ge=1)]
    catalog_generation: Annotated[int | None, Field(ge=1)]
    clip_reason_code: SafeReasonCode | None
    original_event_at: AwareDatetime
    enqueued_at: AwareDatetime
    emitted_at: AwareDatetime
    valid_until: AwareDatetime
    inbox_expires_at: AwareDatetime
    delivery_state: Literal["live_active_page", "delayed_inbox_replay"]
    read_state: Literal["unread"]
    delivery_class: Literal["local_owner_inbox_sse_v1"]
    transport_state: Literal["active_authenticated_owner_page"]
    reason_codes: Annotated[tuple[SafeReasonCode, ...], Field(max_length=8)]

    @model_validator(mode="after")
    def coherent_safe_alert(self) -> "SafeAlertSSEV1":
        if self.safe_body != f"{self.event_class} activity in {self.zone_safe_label}":
            raise ValueError("safe_alert_body_template_invalid")
        if not self.original_event_at <= self.enqueued_at <= self.original_event_at + timedelta(seconds=30):
            raise ValueError("safe_alert_enqueue_window_invalid")
        if not self.enqueued_at <= self.emitted_at < self.inbox_expires_at:
            raise ValueError("safe_alert_emit_window_invalid")
        if self.inbox_expires_at != self.original_event_at + timedelta(hours=24):
            raise ValueError("safe_alert_inbox_retention_invalid")
        if not self.emitted_at < self.valid_until <= min(
            self.emitted_at + timedelta(seconds=30), self.inbox_expires_at,
        ):
            raise ValueError("safe_alert_sse_lifetime_invalid")
        clip_fields = (self.clip_id, self.clip_generation, self.catalog_generation)
        if (self.clip_state == "available") != all(value is not None for value in clip_fields):
            raise ValueError("safe_alert_clip_state_invalid")
        if self.clip_state == "unavailable" and any(value is not None for value in clip_fields):
            raise ValueError("safe_alert_unavailable_clip_reference_forbidden")
        if (self.clip_state == "unavailable") != (self.clip_reason_code is not None):
            raise ValueError("safe_alert_clip_reason_state_invalid")
        delayed = self.emitted_at > self.original_event_at + timedelta(seconds=5)
        if delayed != (self.delivery_state == "delayed_inbox_replay"):
            raise ValueError("safe_alert_delivery_state_invalid")
        if delayed != bool(self.reason_codes):
            raise ValueError("safe_alert_delivery_reason_state_invalid")
        return self
~~~

~~~python
# packages/contracts/src/tuntun_contracts/vision/selected_frame.py
class SelectedFrameRequestV1(VisionContract):
    schema_id: Literal["selected_frame_request.v1"] = "selected_frame_request.v1"
    request_id: UUID
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    zone_id: StableVisionId
    zone_generation: Annotated[int, Field(ge=1)]
    purpose: Literal["local_anonymous_cv_observation"]
    model_manifest_digest: Sha256Digest
    privacy_policy_version: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    max_frames: Annotated[int, Field(ge=1, le=3)]
    max_total_bytes: Annotated[int, Field(ge=1, le=3 * 1024 * 1024)]
    max_dimension: Annotated[int, Field(ge=1, le=1920)]
    not_before: AwareDatetime
    expires_at: AwareDatetime
    output_schema_id: Literal["anonymous_visual_observation.v1"]
    single_use: Literal[True]
    authorization_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_window(self) -> "SelectedFrameRequestV1":
        if self.expires_at <= self.not_before or self.expires_at - self.not_before > timedelta(seconds=5):
            raise ValueError("selected_frame_window_invalid")
        return self

class AnonymousVisualObservationV1(VisionContract):
    schema_id: Literal["anonymous_visual_observation.v1"] = "anonymous_visual_observation.v1"
    request_id: UUID
    state: Literal["observed", "not_observed", "uncertain", "rejected"]
    approved_class: Literal["person", "vehicle", "pet", "package", "motion", "unknown"]
    count_band: Literal["zero", "one", "multiple", "unknown"]
    zone_id: StableVisionId
    confidence_band: Literal["low", "medium", "high", "unavailable"]
    evaluated_at: AwareDatetime
    valid_until: AwareDatetime
    model_artifact_id: StableModelId
    model_digest: Sha256Digest
    calibration_digest: Sha256Digest
    reason_codes: Annotated[tuple[SafeReasonCode, ...], Field(max_length=8)]

    @model_validator(mode="after")
    def coherent_observation(self) -> "AnonymousVisualObservationV1":
        if self.valid_until <= self.evaluated_at:
            raise ValueError("anonymous_observation_validity_invalid")
        shape = (self.approved_class, self.count_band, self.confidence_band)
        if self.state == "observed":
            if self.approved_class == "unknown" or self.count_band not in {"one", "multiple"} or self.confidence_band == "unavailable":
                raise ValueError("observed_visual_shape_invalid")
        elif self.state == "not_observed" and shape != ("unknown", "zero", "unavailable"):
            raise ValueError("not_observed_visual_shape_invalid")
        elif self.state == "uncertain" and shape != ("unknown", "unknown", "low"):
            raise ValueError("uncertain_visual_shape_invalid")
        elif self.state == "rejected":
            if shape != ("unknown", "unknown", "unavailable") or not self.reason_codes:
                raise ValueError("rejected_visual_shape_invalid")
        return self

class SignedSelectedFrameRequestV1(VisionContract):
    schema_id: Literal["signed_selected_frame_request.v1"] = "signed_selected_frame_request.v1"
    request: SelectedFrameRequestV1
    algorithm: Literal["Ed25519"]
    signing_key_id: Annotated[str, Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")]
    signature_b64url: Annotated[str, Field(min_length=86, max_length=86, pattern=r"^[A-Za-z0-9_-]+$")]

class SignedAnonymousVisualObservationV1(VisionContract):
    schema_id: Literal["signed_anonymous_visual_observation.v1"] = "signed_anonymous_visual_observation.v1"
    observation: AnonymousVisualObservationV1
    algorithm: Literal["Ed25519"]
    signing_key_id: Annotated[str, Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")]
    signature_b64url: Annotated[str, Field(min_length=86, max_length=86, pattern=r"^[A-Za-z0-9_-]+$")]
~~~

The selected-frame validator requires `expires_at - not_before <= 5 seconds`. Core signs the request as domain `tuntun.selected-frame-request.v1`; the isolated proxy signs the result as domain `tuntun.anonymous-visual-observation.v1`. Verifiers resolve pinned key IDs and verify the exact canonical inner DTO before reading authority-bearing fields; missing/unknown keys, malformed signatures, inner-field mutation, wrong domain, or replay fail closed. Its pure binding validator rejects unless the live canonical `(area_id, area_generation)`, `zone_id`, `zone_generation`, camera-binding generation, privacy-policy and Privacy Shield generations, request ID, model manifest, model artifact ID/digest, calibration digest, response zone, and trusted current time all still match the single live request. Phase 3 ships these schemas/validators but deliberately defines no runtime `SelectedFrameVisionPort`.

~~~python
# packages/contracts/src/tuntun_contracts/vision/ipc.py
class Phase1OwnerAuthMaterialV1(VisionContract):
    schema_id: Literal["phase1_owner_auth_material.v1"] = "phase1_owner_auth_material.v1"
    mode: Literal["session_bootstrap", "loopback_dpop", "lan_cookie_csrf"]
    authorization: Annotated[str | None, Field(min_length=1, max_length=4096)]
    dpop_proof: Annotated[str | None, Field(min_length=1, max_length=8192)]
    session_cookie: Annotated[str | None, Field(min_length=1, max_length=4096)]
    csrf_token: Annotated[str | None, Field(min_length=1, max_length=4096)]

    @model_validator(mode="after")
    def exact_phase1_auth_shape(self) -> "Phase1OwnerAuthMaterialV1":
        carried = (
            self.authorization is not None, self.dpop_proof is not None,
            self.session_cookie is not None, self.csrf_token is not None,
        )
        expected = {
            "session_bootstrap": (False, False, False, False),
            "loopback_dpop": (True, True, False, False),
            "lan_cookie_csrf": (False, False, True, True),
        }[self.mode]
        if carried != expected:
            raise ValueError("phase1_owner_auth_material_invalid")
        return self

class OwnerIngressPreSessionRequestV1(VisionContract):
    schema_id: Literal["owner_ingress_pre_session_request.v1"] = "owner_ingress_pre_session_request.v1"
    request_id: UUID
    listener_kind: Literal["loopback_http", "commissioned_lan_https"]
    listener_binding_generation: Annotated[int, Field(ge=1)]
    listener_binding_commitment: HmacCommitment
    source_peer_commitment: HmacCommitment
    method: Literal["GET", "HEAD", "POST", "PUT", "DELETE"]
    request_target_form: Literal["origin_form"]
    normalized_host: Annotated[str, Field(min_length=1, max_length=253)]
    normalized_origin: Annotated[str, Field(min_length=1, max_length=512)]
    normalized_path: Annotated[str, Field(min_length=1, max_length=512, pattern=r"^/[A-Za-z0-9._~/-]*$")]
    normalized_query_b64url: Annotated[
        str, Field(max_length=5462, pattern=r"^[A-Za-z0-9_-]*$")
    ]
    normalized_query_digest: Sha256Digest
    client_range_bytes: InclusiveByteRangeV1 | None
    framing: Literal["bodyless", "content_length"]
    content_length: Annotated[int, Field(ge=0, le=1024 * 1024)]
    body_b64url: Annotated[str, Field(max_length=1_398_104, pattern=r"^[A-Za-z0-9_-]*$")]
    body_digest: Sha256Digest
    auth_material: Phase1OwnerAuthMaterialV1
    generated_route_id: BoundedSafeCode
    generated_route_generation: Annotated[int, Field(ge=1)]
    ingress_process_generation: Annotated[int, Field(ge=1)]
    ingress_incarnation_id: UUID
    core_incarnation_id: UUID
    sequence: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def bounded_pre_session_forward(self) -> "OwnerIngressPreSessionRequestV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=2):
            raise ValueError("owner_ingress_pre_session_window_invalid")
        raw_body = base64.urlsafe_b64decode(
            self.body_b64url + "=" * (-len(self.body_b64url) % 4)
        )
        raw_query = base64.urlsafe_b64decode(
            self.normalized_query_b64url
            + "=" * (-len(self.normalized_query_b64url) % 4)
        )
        if (
            len(raw_query) > 4096
            or hashlib.sha256(raw_query).hexdigest() != self.normalized_query_digest
        ):
            raise ValueError("owner_ingress_pre_session_query_invalid")
        if (
            len(raw_body) != self.content_length
            or len(raw_body) > 1024 * 1024
            or hashlib.sha256(raw_body).hexdigest() != self.body_digest
            or (self.framing == "bodyless" and raw_body)
        ):
            raise ValueError("owner_ingress_pre_session_body_invalid")
        is_media = re.fullmatch(
            r"/api/v1/media/[A-Za-z0-9_-]{43}", self.normalized_path,
        ) is not None
        is_media_route = self.generated_route_id == "media.playback_range.v1"
        if is_media != is_media_route or is_media != (self.client_range_bytes is not None):
            raise ValueError("owner_ingress_pre_session_range_shape_invalid")
        expected_listener = {
            "loopback_dpop": "loopback_http",
            "lan_cookie_csrf": "commissioned_lan_https",
        }.get(self.auth_material.mode)
        if expected_listener is not None and self.listener_kind != expected_listener:
            raise ValueError("owner_ingress_pre_session_auth_listener_invalid")
        return self

class DerivedOwnerSessionTupleV1(VisionContract):
    schema_id: Literal["derived_owner_session_tuple.v1"] = "derived_owner_session_tuple.v1"
    derivation_id: UUID
    request_id: UUID
    listener_binding_generation: Annotated[int, Field(ge=1)]
    listener_binding_commitment: HmacCommitment
    source_peer_commitment: HmacCommitment
    generated_route_id: BoundedSafeCode
    generated_route_generation: Annotated[int, Field(ge=1)]
    normalized_query_digest: Sha256Digest
    client_range_bytes: InclusiveByteRangeV1 | None
    body_digest: Sha256Digest
    owner_session_id: UUID
    owner_session_generation: Annotated[int, Field(ge=1)]
    owner_session_binding_commitment: HmacCommitment
    core_process_generation: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    tuple_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_session_derivation(self) -> "DerivedOwnerSessionTupleV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=2):
            raise ValueError("derived_owner_session_window_invalid")
        if (
            self.generated_route_id == "media.playback_range.v1"
        ) != (self.client_range_bytes is not None):
            raise ValueError("derived_owner_session_range_shape_invalid")
        return self

class Phase1PreSessionResponseV1(VisionContract):
    schema_id: Literal["phase1_pre_session_response.v1"] = "phase1_pre_session_response.v1"
    status_code: Literal[200, 201, 204, 400, 401, 403, 409, 422, 429, 503]
    content_type: Literal["application/json", "none"]
    body_b64url: Annotated[str, Field(max_length=1_398_104, pattern=r"^[A-Za-z0-9_-]*$")]
    body_digest: Sha256Digest
    set_cookie: Annotated[str | None, Field(min_length=1, max_length=4096)]
    loopback_authorization: Annotated[str | None, Field(min_length=1, max_length=4096)]
    cache_control: Literal["no-store"]

    @model_validator(mode="after")
    def bounded_phase1_response(self) -> "Phase1PreSessionResponseV1":
        raw_body = base64.urlsafe_b64decode(
            self.body_b64url + "=" * (-len(self.body_b64url) % 4)
        )
        if len(raw_body) > 1024 * 1024 or hashlib.sha256(raw_body).hexdigest() != self.body_digest:
            raise ValueError("phase1_pre_session_response_body_invalid")
        if self.status_code == 204 and (self.content_type != "none" or self.body_b64url):
            raise ValueError("phase1_pre_session_empty_response_invalid")
        if self.content_type == "none" and self.body_b64url:
            raise ValueError("phase1_pre_session_content_type_invalid")
        if self.set_cookie is not None and self.loopback_authorization is not None:
            raise ValueError("phase1_pre_session_dual_credential_response_forbidden")
        return self

class OwnerIngressPreSessionResultV1(VisionContract):
    schema_id: Literal["owner_ingress_pre_session_result.v1"] = "owner_ingress_pre_session_result.v1"
    result_id: UUID
    request_id: UUID
    disposition: Literal["forward_authenticated_session", "return_phase1_response", "rejected"]
    session_tuple: DerivedOwnerSessionTupleV1 | None
    phase1_response: Phase1PreSessionResponseV1 | None
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    result_commitment: HmacCommitment

    @model_validator(mode="after")
    def coherent_pre_session_result(self) -> "OwnerIngressPreSessionResultV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=2):
            raise ValueError("owner_ingress_pre_session_result_window_invalid")
        if self.session_tuple is not None and (
            self.session_tuple.request_id != self.request_id
            or self.session_tuple.issued_at < self.issued_at
            or self.session_tuple.expires_at > self.expires_at
        ):
            raise ValueError("owner_ingress_pre_session_tuple_binding_invalid")
        if self.disposition == "forward_authenticated_session":
            if self.session_tuple is None or self.phase1_response is not None:
                raise ValueError("owner_ingress_pre_session_dispatch_invalid")
        elif self.disposition == "return_phase1_response":
            if self.session_tuple is not None or self.phase1_response is None:
                raise ValueError("owner_ingress_pre_session_response_missing")
        elif self.session_tuple is not None or self.phase1_response is None:
            raise ValueError("owner_ingress_pre_session_rejection_invalid")
        return self

VisionIpcPayloadV1 = (
    CameraProbeTarget
    | CameraCapabilityEvidenceV1
    | OpenCameraStreamV1
    | ReadOnlyMediaHandle
    | NativeCameraEventV1
    | SourceHealthV1
    | CameraSecurityEventEnvelopeV1
    | RecordingHealthV1
    | RecorderStartV1
    | RecorderPauseV1
    | RecorderResumeV1
    | RecorderReceiptV1
    | OwnerClipQueryV1
    | OpaquePage[ClipV1]
    | OwnerSegmentQueryV1
    | OpaquePage[OwnerSegmentTimelineItemV1]
    | MediaGrantRegisterV1
    | MediaGrantRegisterReceiptV1
    | MediaGrantClaimV1
    | MediaGrantClaimReceiptV1
    | ClipExportRequestV1
    | ClipExportReceiptV1
    | ClipDeleteRequestV1
    | ClipDeleteReceiptV1
    | OwnerIngressPreSessionRequestV1
    | OwnerIngressPreSessionResultV1
    | EventIngressReceiptV1
)
IpcPayloadT = TypeVar("IpcPayloadT", bound=ContractModel)

class VisionIpcEnvelopeV1(VisionContract, Generic[IpcPayloadT]):
    schema_id: Literal["vision_ipc_envelope.v1"] = "vision_ipc_envelope.v1"
    envelope_id: UUID
    message_type: VisionIpcMessageType
    sender_process: VisionProcess
    recipient_process: VisionProcess
    sender_registration_generation: Annotated[int, Field(ge=1)]
    recipient_registration_generation: Annotated[int, Field(ge=1)]
    sequence: Annotated[int, Field(ge=1)]
    correlation_id: UUID
    causation_id: UUID | None
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    payload_schema_id: Literal[
        "camera_probe_target.v1", "camera_capability_evidence.v1", "open_camera_stream.v1",
        "read_only_media_handle.v1", "native_camera_event.v1", "source_health.v1",
        "camera.security_event.v1", "recording_health.v1", "recorder_start.v1",
        "recorder_pause.v1", "recorder_resume.v1", "recorder_receipt.v1",
        "owner_clip_query.v1", "owner_segment_query.v1", "opaque_page.v1",
        "media_grant_register.v1", "media_grant_register_receipt.v1",
        "media_grant_claim.v1", "media_grant_claim_receipt.v1", "clip_export_request.v1",
        "clip_export_receipt.v1", "clip_delete_request.v1", "clip_delete_receipt.v1",
        "owner_ingress_pre_session_request.v1", "owner_ingress_pre_session_result.v1",
        "event_ingress_receipt.v1",
    ]
    payload_digest: Sha256Digest
    payload: IpcPayloadT
    envelope_commitment: HmacCommitment

    @model_validator(mode="after")
    def coherent_ipc_envelope(self) -> "VisionIpcEnvelopeV1[IpcPayloadT]":
        if self.sender_process == self.recipient_process:
            raise ValueError("vision_ipc_loopback_forbidden")
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=2):
            raise ValueError("vision_ipc_lifetime_invalid")
        expected_direction = {
            "camera_probe": ("core", "camera_source"),
            "camera_capability_evidence": ("camera_source", "core"),
            "open_camera_stream": ("recorder", "camera_source"),
            "read_only_media_handle": ("camera_source", "recorder"),
            "native_camera_event": ("camera_source", "recorder"),
            "source_health": ("camera_source", "recorder"),
            "camera_security_event": ("recorder", "core"),
            "recording_health": ("recorder", "core"),
            "recorder_start": ("core", "recorder"),
            "recorder_pause": ("core", "recorder"),
            "recorder_resume": ("core", "recorder"),
            "recorder_receipt": ("recorder", "core"),
            "owner_clip_query": ("core", "recorder"),
            "clip_page": ("recorder", "core"),
            "owner_segment_query": ("core", "recorder"),
            "segment_page": ("recorder", "core"),
            "media_grant_register": ("core", "recorder"),
            "media_grant_register_receipt": ("recorder", "core"),
            "media_grant_claim": ("media_proxy", "recorder"),
            "media_grant_claim_receipt": ("recorder", "media_proxy"),
            "clip_export_request": ("core", "recorder"),
            "clip_export_receipt": ("recorder", "core"),
            "clip_delete_request": ("core", "recorder"),
            "clip_delete_receipt": ("recorder", "core"),
            "owner_pre_session_request": ("owner_ingress", "core"),
            "owner_pre_session_result": ("core", "owner_ingress"),
            "event_ingress_receipt": ("core", "recorder"),
        }[self.message_type]
        if (self.sender_process, self.recipient_process) != expected_direction:
            raise ValueError("vision_ipc_direction_invalid")
        expected_schema = {
            "camera_probe": "camera_probe_target.v1",
            "camera_capability_evidence": "camera_capability_evidence.v1",
            "open_camera_stream": "open_camera_stream.v1",
            "read_only_media_handle": "read_only_media_handle.v1",
            "native_camera_event": "native_camera_event.v1",
            "source_health": "source_health.v1",
            "camera_security_event": "camera.security_event.v1",
            "recording_health": "recording_health.v1",
            "recorder_start": "recorder_start.v1",
            "recorder_pause": "recorder_pause.v1",
            "recorder_resume": "recorder_resume.v1",
            "recorder_receipt": "recorder_receipt.v1",
            "owner_clip_query": "owner_clip_query.v1",
            "clip_page": "opaque_page.v1",
            "owner_segment_query": "owner_segment_query.v1",
            "segment_page": "opaque_page.v1",
            "media_grant_register": "media_grant_register.v1",
            "media_grant_register_receipt": "media_grant_register_receipt.v1",
            "media_grant_claim": "media_grant_claim.v1",
            "media_grant_claim_receipt": "media_grant_claim_receipt.v1",
            "clip_export_request": "clip_export_request.v1",
            "clip_export_receipt": "clip_export_receipt.v1",
            "clip_delete_request": "clip_delete_request.v1",
            "clip_delete_receipt": "clip_delete_receipt.v1",
            "owner_pre_session_request": "owner_ingress_pre_session_request.v1",
            "owner_pre_session_result": "owner_ingress_pre_session_result.v1",
            "event_ingress_receipt": "event_ingress_receipt.v1",
        }[self.message_type]
        if self.message_type == "camera_security_event":
            nested = getattr(self.payload, "payload", None)
            actual_schema = (
                "camera.security_event.v1"
                if getattr(self.payload, "event_type", None) == "camera.security_event.v1"
                and getattr(nested, "schema_id", None) == "camera.security_event.v1"
                else None
            )
        else:
            actual_schema = getattr(self.payload, "schema_id", None)
        if self.payload_schema_id != expected_schema or actual_schema != expected_schema:
            raise ValueError("vision_ipc_payload_schema_invalid")
        return self

class OwnerIngressRequestContextV1(VisionContract):
    schema_id: Literal["owner_ingress_request_context.v1"] = "owner_ingress_request_context.v1"
    request_id: UUID
    listener_kind: Literal["loopback_http", "commissioned_lan_https"]
    listener_binding_generation: Annotated[int, Field(ge=1)]
    listener_binding_commitment: HmacCommitment
    source_peer_commitment: HmacCommitment
    owner_session_id: UUID
    owner_session_generation: Annotated[int, Field(ge=1)]
    owner_session_binding_commitment: HmacCommitment
    session_derivation_id: UUID
    session_derivation_commitment: HmacCommitment
    method: Literal["GET", "HEAD", "POST", "PUT", "DELETE"]
    request_target_form: Literal["origin_form"]
    normalized_host: Annotated[str, Field(min_length=1, max_length=253)]
    normalized_origin: Annotated[str, Field(min_length=1, max_length=512)]
    normalized_path: Annotated[str, Field(min_length=1, max_length=512, pattern=r"^/[A-Za-z0-9._~/-]*$")]
    normalized_query_digest: Sha256Digest
    client_range_bytes: InclusiveByteRangeV1 | None
    framing: Literal["bodyless", "content_length"]
    content_length: Annotated[int, Field(ge=0, le=1024 * 1024)]
    body_digest: Sha256Digest
    destination: Literal["core", "media_proxy"]
    generated_route_id: BoundedSafeCode
    generated_route_generation: Annotated[int, Field(ge=1)]
    ingress_process_generation: Annotated[int, Field(ge=1)]
    ingress_incarnation_id: UUID
    recipient_incarnation_id: UUID
    sequence: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def exact_listener_route_and_window(self) -> "OwnerIngressRequestContextV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=2):
            raise ValueError("owner_ingress_context_window_invalid")
        is_media = re.fullmatch(r"/api/v1/media/[A-Za-z0-9_-]{43}", self.normalized_path) is not None
        if is_media != (self.destination == "media_proxy"):
            raise ValueError("owner_ingress_destination_path_invalid")
        if is_media and (
            self.method != "GET"
            or self.normalized_query_digest != hashlib.sha256(b"").hexdigest()
            or self.client_range_bytes is None
            or self.framing != "bodyless"
            or self.content_length != 0
            or self.body_digest != hashlib.sha256(b"").hexdigest()
            or self.generated_route_id != "media.playback_range.v1"
        ):
            raise ValueError("owner_ingress_media_route_shape_invalid")
        if not is_media and self.client_range_bytes is not None:
            raise ValueError("owner_ingress_nonmedia_range_forbidden")
        if self.listener_kind == "loopback_http" and (
            self.normalized_host != "127.0.0.1:8787"
            or self.normalized_origin != "http://127.0.0.1:8787"
        ):
            raise ValueError("owner_ingress_loopback_origin_invalid")
        if self.framing == "bodyless" and self.content_length != 0:
            raise ValueError("owner_ingress_bodyless_length_invalid")
        return self

class AuthenticatedOwnerIngressRequestV1(VisionContract):
    schema_id: Literal["authenticated_owner_ingress_request.v1"] = "authenticated_owner_ingress_request.v1"
    context: OwnerIngressRequestContextV1
    algorithm: Literal["HMAC-SHA256"]
    ingress_key_id: KeyId
    context_mac: HmacCommitment

@dataclass(frozen=True)
class VisionIpcLiveBinding:
    sender_process: VisionProcess
    recipient_process: VisionProcess
    sender_registration_generation: int
    recipient_registration_generation: int
    expected_sequence: int
    claimed_envelope_ids: frozenset[UUID]

def validate_vision_ipc_envelope_binding(
    envelope: VisionIpcEnvelopeV1[IpcPayloadT],
    live: VisionIpcLiveBinding,
    now: datetime,
    actual_payload_digest: Sha256Digest,
    authenticated_commitment: bool,
) -> None:
    expected = (
        live.sender_process,
        live.recipient_process,
        live.sender_registration_generation,
        live.recipient_registration_generation,
        live.expected_sequence,
    )
    carried = (
        envelope.sender_process,
        envelope.recipient_process,
        envelope.sender_registration_generation,
        envelope.recipient_registration_generation,
        envelope.sequence,
    )
    if (
        carried != expected
        or envelope.envelope_id in live.claimed_envelope_ids
        or not envelope.issued_at <= now < envelope.expires_at
        or envelope.payload_digest != actual_payload_digest
        or not authenticated_commitment
    ):
        raise PermissionError("vision_ipc_binding_invalid")
~~~

~~~python
# packages/contracts/src/tuntun_contracts/vision/ports.py
class CameraSourcePort(Protocol):
    async def probe(self, target: CameraProbeTarget) -> CameraCapabilityEvidenceV1: ...
    async def open_stream(self, request: OpenCameraStreamV1) -> ReadOnlyMediaHandle: ...
    def native_events(
        self, binding: CameraBindingV1, capability: CameraCapabilityEvidenceV1,
    ) -> AsyncIterator[NativeCameraEventV1]: ...
    async def health(self, binding: CameraBindingV1, capability: CameraCapabilityEvidenceV1) -> SourceHealthV1: ...

class RecorderPort(Protocol):
    async def start(self, command: RecorderStartV1) -> RecorderReceiptV1: ...
    async def promote(self, event: CameraSecurityEventV1) -> ClipV1 | ClipUnavailableV1: ...
    async def pause(self, command: RecorderPauseV1) -> RecorderReceiptV1: ...
    async def resume(self, command: RecorderResumeV1) -> RecorderReceiptV1: ...
    async def status(self, binding: CameraBindingV1, profile: RecordingProfileV1) -> RecordingHealthV1: ...
    async def export_clip(self, command: ClipExportRequestV1) -> ClipExportReceiptV1: ...
    async def delete_clip(self, command: ClipDeleteRequestV1) -> ClipDeleteReceiptV1: ...

class VisionCatalogPort(Protocol):
    async def commit_segment(self, staged: StagedSegment) -> SegmentV1: ...
    async def commit_clip(self, staged: StagedClip) -> ClipV1: ...
    async def find_clips(self, query: OwnerClipQueryV1) -> OpaquePage[ClipV1]: ...
    async def find_segments(self, query: OwnerSegmentQueryV1) -> OpaquePage[OwnerSegmentTimelineItemV1]: ...
    async def resolve_storage_token(self, subject: PlaybackSubjectV1) -> OpaqueStorageToken: ...

class RecorderGrantLedgerPort(Protocol):
    async def register(self, command: MediaGrantRegisterV1) -> MediaGrantRegisterReceiptV1: ...
    async def claim(self, command: MediaGrantClaimV1) -> MediaGrantClaimReceiptV1: ...

class CameraOutcomePort(Protocol):
    async def ingest_security_event(
        self, envelope: CameraSecurityEventEnvelopeV1,
    ) -> EventIngressReceiptV1: ...
    async def ingest_health(self, health: RecordingHealthV1) -> None: ...

class AnonymousPresencePort(Protocol):
    async def apply(self, evidence: AnonymousPresenceEvidenceV1) -> PresenceChangedV1: ...
    async def current(self, location: CanonicalLocationRefV1) -> PresenceChangedV1: ...

class HomePresenceObservationPort(Protocol):
    """One-way vision-presence -> home-policy observation seam; never an HA action port."""
    async def publish(self, event: PresenceChangedEventV1) -> None: ...
~~~

The Pydantic validators above own closed shape, strict scalar types, positive generations, bounded lifetimes, and self-consistent states. They do not turn signed or well-formed data into authority. Each port implementation must then atomically compare every carried source-endpoint, camera-binding, capability, profile, recorder, area, zone, catalog, policy, privacy, source-eligibility, and volume-qualification generation relevant to that call against live canonical state immediately before effect. It must also compare request/causation IDs, commitments, stream/view roles, and trusted time. A missing live row, expired DTO, generation mismatch, state transition mismatch, duplicate single-use ID, or signature/IPC failure rejects before opening a descriptor, reading a storage token, committing media, dispatching an event, changing presence, or changing recorder state. `RecorderReceiptV1.causation_id` is the exact `RecorderStartV1.command_id` (which equals `RecordingProfileV1.activation_id`) for `start` and the exact command ID for `pause` or `resume`. `recorder.pause.all` and `recorder.resume.all` are core operations only: after one exact owner authorization, core snapshots the bounded eligible set and emits one frozen per-camera `RecorderPauseV1` or `RecorderResumeV1` for each member; the recorder never accepts an unbounded wildcard command.

## Durable State and Migration Map

### Canonical core SQLCipher migrations

The canonical core graph is frozen and linear. Phase 3 consumes Phase 2 head `0012_screen_time`, then owns exactly `0013_camera_policy -> 0014_camera_alerts -> 0015_presence_checkpoint`; their exact `down_revision` values are respectively `0012_screen_time`, `0013_camera_policy`, and `0014_camera_alerts`. No merge, branch, orphan, alternate parent, or extra core head is permitted. Optional experimental search remains in its independent `alembic_version_experimental_search` feature namespace at `search_0001_experimental_search` and is never a parent, child, or merge input in this graph.

| Revision | Exact `down_revision` | Tables and critical invariants |
|---|---|---|
| `0013_camera_policy` | `0012_screen_time` | `camera_inventory`, `camera_bindings`, `camera_zones`, `camera_commissioning_generations`, `camera_source_eligibility`, `camera_privacy_policies`, `camera_copy_disclosures`; one current binding per source endpoint, one zone belongs to one canonical area/binding generation, strict CAS/generation, real identifiers represented only by HMAC commitments, no credential/media/profile/name field |
| `0014_camera_alerts` | `0013_camera_policy` | `camera_event_ingress_cursors`, `camera_event_ingress_receipts`, `camera_event_dispatch_outbox`, `camera_alert_policies`, `camera_alert_quality_evidence`, `camera_alert_inbox`, `camera_alert_delivery_receipts`, `camera_alert_cooldowns`; ingress cursor is unique per `(source_endpoint_id, source_generation)` and advances monotonically, event ID and deduplication commitment claim one prior receipt, and the content-minimized per-consumer dispatch row commits atomically with that receipt. Alert scope binds exact camera/class/zone/schedule/policy generation, singleton owner recipient is implicit, metadata only, delivery queue expires at 24 hours, and no table admits a full event body, thumbnail, token, person/profile, or address field |
| `0015_presence_checkpoint` | `0014_camera_alerts` | `presence_policies`, `presence_checkpoints`, `presence_evidence_receipts`, `presence_publisher_cursors`, `presence_event_outbox`, `presence_home_consumer_cursors`; exactly one replace-in-place current row per `(area_id, area_generation)`, exact policy/privacy generations, evidence commitment and original expiry remain replay-safe without a presence timeline, publisher sequence and complete closed observation outbox commit atomically with replacement/expiry, and the home-policy consumer cursor binds source generation/sequence plus event/payload time and expiry. Camera evidence cannot write vacant/count; no history/subject/viewer/clip relation exists; expiry removes the checkpoint and checkpoints/outbox bodies are excluded from long-lived audit/backup projections |

### Separate vision-catalog SQLCipher migrations

The recorder owns `$TUNTUN_VIDEO/catalog/vision.sqlite3` under its own Keychain key, migration lock, and `vision_catalog_alembic_version` table. It is never attached to the canonical database and is excluded from Phase 1 portable backups. This separate graph has exactly one linear head: `0001_media_catalog` is the base (`down_revision = None`), `0002_media_operations` descends only from `0001_media_catalog`, and `0003_measurement_health` descends only from `0002_media_operations`; it admits no branch, merge, orphan, alternate parent, or second head.

| Catalog revision | Exact `down_revision` | Tables and critical invariants |
|---|---|---|
| `0001_media_catalog` | `None` | `source_state`, `segments`, `gaps`, `native_events`, `camera_event_publishers`, `camera_event_ipc_outbox`, `clips`, `clip_views`, `clip_event_refs`; one durable publisher cursor per `(source_endpoint_id, source_generation)` and the complete closed metadata-only camera-event envelope/outbox row commit in the same transaction as native-event dedupe. Opaque random file tokens, exact immutable expiry, segment/file digest and size, one primary plus bounded coalesced event references; no raw media/event body, family/room-label/address/path/credential/identity field |
| `0002_media_operations` | `0001_media_catalog` | recorder-owned `grant_consumptions`, `export_jobs`, `delete_jobs`, `retention_journal`, `reconciliation_claims`; the grant ledger stores grant/route/signature digests, compiled media subject/range, HMAC session-binding commitment, expiry, and one-consumption state only; the signed envelope and raw owner subject/session are verified during registration then discarded; crash-safe operation state |
| `0003_measurement_health` | `0002_media_operations` | `daily_stream_measurements`, `event_measurements`, `volume_health`, `copy_registry`, `catalog_integrity`; safe counts/timings/digests only, no media sample or raw device error |

The media write lifecycle is:

~~~text
ALLOCATED -> WRITING -> STAGED_CHECKSUMMED -> CATALOG_COMMITTED -> PUBLISHED
ALLOCATED | WRITING | STAGED_CHECKSUMMED -> ABORTED
CATALOG_COMMITTED -> PUBLISHED | RECONCILIATION_REQUIRED
PUBLISHED -> EXPIRY_CLAIMED -> FILE_UNLINKED -> TOMBSTONED
~~~

Only `PUBLISHED` media is playable. A crash after catalog commit but before atomic rename is reconciled by exact staging token/digest; it is never guessed from a human filename.

## Standard Commands

~~~bash
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
uv run pytest -m "not camera_hardware and not camera_network and not elapsed" -q
uv run pytest apps/recorder/tests integrations/reolink/tests -q
pnpm --filter @tuntun/admin e2e -- tests/e2e/cameras-*.spec.ts
~~~

Owner-gated commands write only safe evidence to ignored `var/evidence/phase3/`:

~~~bash
TUNTUN_ALLOW_CAMERA_HARDWARE=1 uv run python scripts/phase3/inventory_cameras.py --output var/evidence/phase3/inventory.json
TUNTUN_ALLOW_CAMERA_NETWORK=1 uv run python scripts/phase3/verify_camera_egress.py --capture-root "$TUNTUN_OWNER_CAPTURE_ROOT" --output var/evidence/phase3/egress.json
TUNTUN_ALLOW_TRACKMIX_ARC=1 uv run python scripts/phase3/qualify_trackmix_arc.py --output var/evidence/phase3/trackmix-arc.json
TUNTUN_ALLOW_VIDEO_VOLUME=1 uv run python scripts/phase3/qualify_video_volume.py --output var/evidence/phase3/video-volume.json
TUNTUN_ALLOW_ELAPSED_PHASE3=1 uv run python scripts/phase3/run_one_camera_pilot.py household --feature-manifest-chain var/evidence/phase3/feature-authority/task19/signed-rollover-chain.json --duration-seconds 172800 --sample-seconds 30 --commit "$(git rev-parse HEAD)" --output var/evidence/phase3/one-camera-pilot.json
TUNTUN_ALLOW_ELAPSED_PHASE3=1 uv run python scripts/phase3/run_capacity_campaign.py household --feature-manifest-chain var/evidence/phase3/feature-authority/task20/signed-rollover-chain.json --duration-seconds 604800 --sample-seconds 60 --commit "$(git rev-parse HEAD)" --output var/evidence/phase3/capacity.json
TUNTUN_ALLOW_ELAPSED_PHASE3=1 uv run python scripts/phase3/run_acceptance.py household-soak --feature-manifest-chain var/evidence/phase3/feature-authority/task32/signed-rollover-chain.json --duration-seconds 604800 --sample-seconds 60 --simulate-retention-days 100 --commit "$(git rev-parse HEAD)" --evidence-root var/evidence/phase3 --output var/evidence/phase3/household-soak.json
~~~

---

## Wave 0 — Contracts, Synthetic Media, Persistence, and Isolation

### Task 01: Freeze strict Phase 3 contracts and generated schemas

**Depends on:** accepted Phase 1/2 contract packages.
**Gate contribution:** P3-E0.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `packages/contracts/src/tuntun_contracts/vision/__init__.py`
- Create: `packages/contracts/src/tuntun_contracts/vision/base.py`
- Create: `packages/contracts/src/tuntun_contracts/vision/topology.py`
- Create: `packages/contracts/src/tuntun_contracts/vision/evidence.py`
- Create: `packages/contracts/src/tuntun_contracts/vision/events.py`
- Create: `packages/contracts/src/tuntun_contracts/vision/media.py`
- Create: `packages/contracts/src/tuntun_contracts/vision/health.py`
- Create: `packages/contracts/src/tuntun_contracts/vision/selected_frame.py`
- Create: `packages/contracts/src/tuntun_contracts/vision/ui.py`
- Create: `packages/contracts/src/tuntun_contracts/vision/ipc.py`
- Create: `packages/contracts/src/tuntun_contracts/vision/ports.py`
- Create: `scripts/phase3/generate_vision_schemas.py`
- Create: `schemas/vision/v1/*.schema.json`
- Create: `fixtures/synthetic/vision/contracts/*.json`
- Test: `tests/contract/vision/test_vision_contracts.py`
- Test: `tests/property/vision/test_contract_rejection.py`

**Interfaces:** Consumes the unchanged generic Phase 2 `CrossDomainEventV1`, Phase 2 `AreaV1`/`CanonicalLocationRefV1`, the Phase 1 `canonical_mapping_bytes` encoder, shared strict contract bases, safe reason codes, commitments, and UI primitives. No Phase 3-local JCS stack or timestamp normalizer exists. The camera and presence specializations narrow only the frozen `event_type` and payload type; dispatch reopens current publisher/source/location binding metadata and does not add envelope fields. Produces every frozen contract above, including the source/probe/media-handle, native-event/ingress, recorder start/control/catalog, owner-safe clip and 7-day low-wide segment queries, playback-subject union, grant register/claim, export/delete request/receipt, immutable manifest, egress/arc/capacity evidence, anonymous-presence, opaque-token/page, `PreparedPlaybackRangeV1`, health/UI/SSE, pre-session/core-derived-session and authenticated owner-ingress DTOs, and authenticated IPC DTOs used by every public protocol; `canonical_vision_bytes(value: VisionContract) -> bytes` plus the fixed-exclusion `canonical_playback_range_request_unsigned_bytes(request)`, `canonical_media_grant_claim_unsigned_bytes(claim)`, `canonical_clip_export_request_unsigned_bytes(request)`, `canonical_clip_delete_request_unsigned_bytes(request)`, `canonical_anonymous_presence_evidence_unsigned_bytes(evidence)`, `storage_measurement_digest(measurement)`, `green_backup_receipt_digest(receipt)`, and `capacity_operational_evidence_digest(evidence)` helpers; schema bundle ID `tuntun.vision.v1`; generated TypeScript/OpenAPI-ready schema artifacts; and the pure boundary helpers `validate_selected_frame_result_binding(request, observation, live, now) -> None` and `validate_vision_ipc_envelope_binding(envelope, live, now, actual_payload_digest, authenticated_commitment) -> None`. Every whole-model or exclusion helper serializes `model_dump(mode="python")` through the one shared encoder. Each boundary implementation attaches its frozen model validator and a live-state validator that compares every carried generation, lifetime, state, ID, role, digest, sequence, IPC direction, and commitment before effect. The selected-frame helper receives trusted current time and rechecks exact current location, zone, camera, privacy, model and calibration authority immediately before a future Phase 5 consumer may accept a result. It deliberately produces no runtime selected-frame port.

- [ ] **Step 1: Write red public-port, IPC, zone-binding, retention, and selected-frame limit tests**

~~~python
def test_zone_is_bound_to_exact_area_camera_and_cas(zone_fixture: dict[str, object]) -> None:
    zone = CameraZoneV1.model_validate(zone_fixture)
    assert (zone.area_id, zone.area_generation) == ("area_common_synth_01", 4)
    assert zone.camera_binding_generation == 3
    assert zone.zone_generation == 7

@pytest.mark.parametrize("model,fixture_name", [
    (CameraZoneV1, "zone_fixture"),
    (CameraBindingV1, "camera_binding_fixture"),
    (CameraSecurityEventV1, "camera_event_fixture"),
    (PresenceChangedV1, "presence_fixture"),
    (SelectedFrameRequestV1, "selected_frame_fixture"),
])
def test_location_authority_rejects_missing_zero_or_guest_area_generation(request, model, fixture_name) -> None:
    fixture = request.getfixturevalue(fixture_name)
    for mutation in ({"area_generation": 0}, {"area_generation": None}, {"room_class": "guest"}):
        with pytest.raises(ValidationError):
            model.model_validate({**fixture, **mutation})

def test_capacity_physical_unit_commitment_round_trips_and_rejects_substitution(capacity_campaign_fixture) -> None:
    campaign = CapacityCampaignV1.model_validate(capacity_campaign_fixture)
    assert CapacityCampaignV1.model_validate_json(campaign.model_dump_json()) == campaign
    changed = campaign.measurements[0].model_copy(
        update={"physical_device_commitment": different_hmac_commitment()}
    )
    with pytest.raises(ValidationError, match="capacity_campaign_row_authority_or_window_mismatch"):
        CapacityCampaignV1.model_validate({
            **campaign.model_dump(),
            "measurements": (changed, *campaign.measurements[1:]),
        })

@pytest.mark.parametrize("required_views", [(), ("wide", "wide")])
def test_capacity_camera_required_views_has_exactly_one_wide_entry(
    capacity_campaign_fixture, required_views,
) -> None:
    camera = capacity_campaign_fixture["expected_cameras"][0]
    with pytest.raises(ValidationError):
        CapacityCampaignCameraV1.model_validate({
            **camera, "required_views": required_views,
        })

def test_capacity_camera_required_views_schema_has_exact_cardinality() -> None:
    field = CapacityCampaignCameraV1.model_json_schema()["properties"]["required_views"]
    assert field["minItems"] == field["maxItems"] == 1
    assert len(field["prefixItems"]) == 1
    item = field["prefixItems"][0]
    assert item["type"] == "string"
    assert item.get("const") == "wide" or item.get("enum") == ["wide"]

@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_frames", 4),
        ("max_frames", 0),
        ("max_total_bytes", 3 * 1024 * 1024 + 1),
        ("max_total_bytes", 0),
        ("max_dimension", 1921),
        ("max_dimension", 0),
        ("camera_binding_generation", 0),
        ("zone_generation", 0),
        ("privacy_policy_version", 0),
        ("privacy_generation", 0),
    ],
)
def test_selected_frame_caps_are_closed(selected_frame_fixture, field, value) -> None:
    with pytest.raises(ValidationError):
        SelectedFrameRequestV1.model_validate({**selected_frame_fixture, field: value})

def test_selected_frame_window_is_at_most_five_seconds(selected_frame_fixture) -> None:
    selected_frame_fixture["expires_at"] = "2026-08-27T10:00:05.000001Z"
    with pytest.raises(ValidationError):
        SelectedFrameRequestV1.model_validate(selected_frame_fixture)

@pytest.mark.parametrize(
    "stale",
    [
        "area_id", "area_generation", "zone_id", "zone_generation", "camera_binding_generation",
        "privacy_policy_version", "privacy_generation", "model_manifest_digest",
        "model_artifact_id", "model_artifact_digest", "calibration_digest",
    ],
)
def test_selected_frame_result_binding_rechecks_every_live_generation(request, observation, current_binding, clock, stale) -> None:
    current_binding = current_binding.mutate(stale)
    with pytest.raises(ValueError, match="selected_frame_binding_stale"):
        validate_selected_frame_result_binding(request, observation, current_binding, clock.now())

@pytest.mark.parametrize(("state", "approved_class", "count_band", "confidence_band", "reason_codes"), [
    ("observed", "person", "one", "high", ()),
    ("observed", "person", "multiple", "medium", ()),
    ("not_observed", "unknown", "zero", "unavailable", ()),
    ("uncertain", "unknown", "unknown", "low", ("below_threshold",)),
])
def test_selected_frame_count_is_accepted_but_ignored_by_binding_policy(
    request, observation, current_binding, clock,
    state, approved_class, count_band, confidence_band, reason_codes,
) -> None:
    candidate = observation.model_copy(update={
        "state": state,
        "approved_class": approved_class,
        "count_band": count_band,
        "confidence_band": confidence_band,
        "reason_codes": reason_codes,
    })
    candidate = AnonymousVisualObservationV1.model_validate(candidate.model_dump())
    validate_selected_frame_result_binding(request, candidate, current_binding, clock.now())
    assert not hasattr(candidate, "security_event")
    assert not hasattr(candidate, "presence_transition")

@pytest.mark.parametrize(("state", "approved_class", "count_band", "confidence_band", "reason_codes"), [
    ("not_observed", "person", "zero", "unavailable", ()),
    ("not_observed", "unknown", "one", "unavailable", ()),
    ("uncertain", "person", "unknown", "low", ("below_threshold",)),
    ("uncertain", "unknown", "zero", "unavailable", ("below_threshold",)),
    ("rejected", "person", "multiple", "high", ("policy_rejected",)),
    ("rejected", "unknown", "unknown", "unavailable", ()),
])
def test_no_observation_states_cannot_assert_observation_truth(
    observation_fixture, state, approved_class, count_band, confidence_band, reason_codes,
) -> None:
    with pytest.raises(ValidationError):
        AnonymousVisualObservationV1.model_validate({
            **observation_fixture,
            "state": state,
            "approved_class": approved_class,
            "count_band": count_band,
            "confidence_band": confidence_band,
            "reason_codes": reason_codes,
        })

def test_anonymous_observation_rejects_identity_or_free_text(observation_fixture) -> None:
    for forbidden in ("caption", "name", "profile_candidate", "embedding", "ocr_text", "memory_proposal", "action"):
        with pytest.raises(ValidationError):
            AnonymousVisualObservationV1.model_validate({**observation_fixture, forbidden: "forbidden"})

@pytest.mark.parametrize("fault", [
    "evaluated_before_request", "evaluated_after_now", "expired_now",
    "observation_expires_exactly_now", "request_expires_exactly_now", "inverted_validity",
])
def test_selected_frame_rejects_stale_or_inverted_observation(request, observation, current_binding, clock, fault) -> None:
    candidate = mutate_observation_time(observation, request, clock.now(), fault)
    with pytest.raises((ValidationError, ValueError)):
        validate_selected_frame_result_binding(request, candidate, current_binding, clock.now())

@pytest.mark.parametrize("contract_fixture,field", [
    ("zone_fixture", "camera_binding_generation"),
    ("zone_fixture", "zone_generation"),
    ("camera_binding_fixture", "camera_binding_generation"),
    ("camera_probe_target_fixture", "source_endpoint_generation"),
    ("camera_capability_fixture", "source_endpoint_generation"),
    ("camera_capability_fixture", "capability_generation"),
    ("camera_egress_fixture", "evidence_generation"),
    ("camera_egress_fixture", "source_endpoint_generation"),
    ("camera_egress_fixture", "camera_binding_generation"),
    ("camera_egress_fixture", "egress_policy_generation"),
    ("camera_egress_fixture", "network_ruleset_generation"),
    ("trackmix_arc_fixture", "arc_generation"),
    ("trackmix_arc_fixture", "camera_binding_generation"),
    ("trackmix_arc_fixture", "capability_generation"),
    ("trackmix_arc_fixture", "source_eligibility_generation"),
    ("trackmix_arc_fixture", "zone_generation"),
    ("trackmix_arc_fixture", "privacy_policy_version"),
    ("trackmix_arc_fixture", "privacy_generation"),
    ("storage_measurement_fixture", "measurement_generation"),
    ("storage_measurement_fixture", "camera_binding_generation"),
    ("storage_measurement_fixture", "capability_generation"),
    ("storage_measurement_fixture", "profile_generation"),
    ("storage_measurement_fixture", "source_eligibility_generation"),
    ("storage_measurement_fixture", "egress_evidence_generation"),
    ("storage_measurement_fixture", "volume_qualification_generation"),
    ("storage_measurement_fixture", "catalog_generation"),
    ("storage_measurement_fixture", "zone_generation"),
    ("storage_measurement_fixture", "privacy_policy_version"),
    ("storage_measurement_fixture", "privacy_generation"),
    ("capacity_projection_fixture", "projection_generation"),
    ("capacity_projection_fixture", "volume_qualification_generation"),
    ("capacity_projection_fixture", "catalog_generation"),
    ("capacity_projection_fixture", "privacy_generation"),
    ("open_camera_stream_fixture", "camera_binding_generation"),
    ("open_camera_stream_fixture", "capability_generation"),
    ("read_only_media_handle_fixture", "camera_binding_generation"),
    ("read_only_media_handle_fixture", "capability_generation"),
    ("native_event_fixture", "source_endpoint_generation"),
    ("native_event_fixture", "camera_binding_generation"),
    ("native_event_fixture", "capability_generation"),
    ("native_event_fixture", "zone_generation"),
    ("source_health_fixture", "source_endpoint_generation"),
    ("source_health_fixture", "camera_binding_generation"),
    ("source_health_fixture", "capability_generation"),
    ("recording_profile_fixture", "profile_generation"),
    ("recording_profile_fixture", "supersedes_profile_generation"),
    ("recording_profile_fixture", "camera_binding_generation"),
    ("recording_profile_fixture", "capability_generation"),
    ("recorder_pause_fixture", "expected_recorder_generation"),
    ("recorder_pause_fixture", "camera_binding_generation"),
    ("recorder_pause_fixture", "capability_generation"),
    ("recorder_pause_fixture", "profile_generation"),
    ("recorder_pause_fixture", "policy_version"),
    ("recorder_pause_fixture", "privacy_generation"),
    ("recorder_resume_fixture", "camera_binding_generation"),
    ("recorder_resume_fixture", "zone_generation"),
    ("recorder_resume_fixture", "capability_generation"),
    ("recorder_resume_fixture", "profile_generation"),
    ("recorder_resume_fixture", "source_eligibility_generation"),
    ("recorder_resume_fixture", "volume_qualification_generation"),
    ("recorder_resume_fixture", "expected_recorder_generation"),
    ("recorder_resume_fixture", "policy_version"),
    ("recorder_resume_fixture", "privacy_generation"),
    ("recorder_receipt_fixture", "camera_binding_generation"),
    ("recorder_receipt_fixture", "capability_generation"),
    ("recorder_receipt_fixture", "profile_generation"),
    ("recorder_receipt_fixture", "recorder_generation"),
    ("clip_unavailable_fixture", "camera_binding_generation"),
    ("clip_unavailable_fixture", "zone_generation"),
    ("clip_unavailable_fixture", "catalog_generation"),
    ("staged_segment_fixture", "camera_binding_generation"),
    ("staged_segment_fixture", "profile_generation"),
    ("staged_segment_fixture", "capability_generation"),
    ("opaque_media_manifest_fixture", "manifest_generation"),
    ("opaque_media_manifest_fixture", "clip_generation"),
    ("opaque_media_manifest_fixture", "source_endpoint_generation"),
    ("opaque_media_manifest_fixture", "camera_binding_generation"),
    ("opaque_media_manifest_fixture", "capability_generation"),
    ("opaque_media_manifest_fixture", "profile_generation"),
    ("opaque_media_manifest_fixture", "source_eligibility_generation"),
    ("opaque_media_manifest_fixture", "egress_evidence_generation"),
    ("opaque_media_manifest_fixture", "volume_qualification_generation"),
    ("opaque_media_manifest_fixture", "catalog_generation"),
    ("opaque_media_manifest_fixture", "zone_generation"),
    ("staged_clip_fixture", "clip_generation"),
    ("staged_clip_fixture", "catalog_generation"),
    ("staged_clip_fixture", "camera_binding_generation"),
    ("staged_clip_fixture", "capability_generation"),
    ("staged_clip_fixture", "zone_generation"),
    ("owner_clip_query_fixture", "camera_binding_generation"),
    ("owner_clip_query_fixture", "zone_generation"),
    ("owner_clip_query_fixture", "expected_catalog_generation"),
    ("owner_clip_query_fixture", "privacy_generation"),
    ("opaque_clip_page_fixture", "catalog_generation"),
    ("camera_presence_evidence_fixture", "policy_version"),
    ("camera_presence_evidence_fixture", "privacy_generation"),
    ("camera_presence_evidence_fixture", "camera_binding_generation"),
    ("camera_presence_evidence_fixture", "capability_generation"),
    ("camera_presence_evidence_fixture", "zone_generation"),
    ("camera_presence_evidence_fixture", "non_imaging_rule_generation"),
    ("camera_event_fixture", "camera_binding_generation"),
    ("camera_event_fixture", "capability_generation"),
    ("camera_event_fixture", "zone_generation"),
    ("camera_event_fixture", "privacy_policy_version"),
    ("camera_event_fixture", "privacy_generation"),
    ("presence_fixture", "evidence_policy_version"),
    ("presence_fixture", "privacy_generation"),
    ("segment_fixture", "camera_binding_generation"),
    ("clip_fixture", "camera_binding_generation"),
    ("clip_fixture", "zone_generation"),
    ("clip_fixture", "clip_generation"),
    ("clip_fixture", "catalog_generation"),
    ("media_grant_fixture", "policy_version"),
    ("media_grant_fixture", "privacy_generation"),
    ("recording_health_fixture", "capability_generation"),
    ("recording_health_fixture", "camera_binding_generation"),
    ("recording_health_fixture", "profile_generation"),
    ("recording_health_fixture", "recorder_generation"),
    ("recording_health_fixture", "catalog_generation"),
    ("recording_health_fixture", "volume_qualification_generation"),
    ("camera_overview_fact_fixture", "camera_binding_generation"),
    ("camera_overview_fact_fixture", "source_endpoint_generation"),
    ("camera_overview_fact_fixture", "capability_generation"),
    ("camera_overview_fact_fixture", "source_eligibility_generation"),
    ("camera_overview_fact_fixture", "profile_generation"),
    ("camera_overview_fact_fixture", "recorder_generation"),
    ("camera_overview_fact_fixture", "volume_qualification_generation"),
    ("camera_overview_fact_fixture", "catalog_generation"),
    ("camera_overview_fact_fixture", "privacy_generation"),
    ("camera_overview_fact_fixture", "zone_generation"),
    ("camera_overview_fact_fixture", "arc_generation"),
    ("camera_overview_fixture", "projection_generation"),
    ("camera_overview_fixture", "catalog_generation"),
    ("camera_overview_fixture", "privacy_generation"),
    ("safe_alert_sse_fixture", "camera_binding_generation"),
    ("safe_alert_sse_fixture", "capability_generation"),
    ("safe_alert_sse_fixture", "zone_generation"),
    ("safe_alert_sse_fixture", "privacy_policy_version"),
    ("safe_alert_sse_fixture", "privacy_generation"),
    ("safe_alert_sse_fixture", "alert_policy_generation"),
    ("safe_alert_sse_fixture", "quality_evidence_generation"),
    ("safe_alert_sse_fixture", "clip_generation"),
    ("safe_alert_sse_fixture", "catalog_generation"),
    ("vision_ipc_envelope_fixture", "sender_registration_generation"),
    ("vision_ipc_envelope_fixture", "recipient_registration_generation"),
])
def test_every_generation_rejects_zero(request, contract_fixture, field) -> None:
    models = {
        "zone_fixture": CameraZoneV1,
        "camera_binding_fixture": CameraBindingV1,
        "camera_probe_target_fixture": CameraProbeTarget,
        "camera_capability_fixture": CameraCapabilityEvidenceV1,
        "camera_egress_fixture": CameraEgressEvidenceV1,
        "trackmix_arc_fixture": TrackMixArcEvidenceV1,
        "storage_measurement_fixture": StorageMeasurementV1,
        "capacity_projection_fixture": CapacityProjectionV1,
        "open_camera_stream_fixture": OpenCameraStreamV1,
        "read_only_media_handle_fixture": ReadOnlyMediaHandle,
        "native_event_fixture": NativeCameraEventV1,
        "source_health_fixture": SourceHealthV1,
        "recording_profile_fixture": RecordingProfileV1,
        "recorder_pause_fixture": RecorderPauseV1,
        "recorder_resume_fixture": RecorderResumeV1,
        "recorder_receipt_fixture": RecorderReceiptV1,
        "clip_unavailable_fixture": ClipUnavailableV1,
        "staged_segment_fixture": StagedSegment,
        "opaque_media_manifest_fixture": OpaqueMediaManifestV1,
        "staged_clip_fixture": StagedClip,
        "owner_clip_query_fixture": OwnerClipQueryV1,
        "opaque_clip_page_fixture": OpaquePage[ClipV1],
        "camera_presence_evidence_fixture": AnonymousPresenceEvidenceV1,
        "camera_event_fixture": CameraSecurityEventV1,
        "presence_fixture": PresenceChangedV1,
        "segment_fixture": SegmentV1,
        "clip_fixture": ClipV1,
        "media_grant_fixture": MediaPlaybackGrantV1,
        "recording_health_fixture": RecordingHealthV1,
        "camera_overview_fact_fixture": CameraOverviewFactV1,
        "camera_overview_fixture": CameraOverviewUIV1,
        "safe_alert_sse_fixture": SafeAlertSSEV1,
        "vision_ipc_envelope_fixture": VisionIpcEnvelopeV1[VisionIpcPayloadV1],
    }
    fixture = request.getfixturevalue(contract_fixture)
    with pytest.raises(ValidationError):
        models[contract_fixture].model_validate({**fixture, field: 0})

@pytest.mark.parametrize(("fixture_name", "model", "start_field", "end_field", "maximum"), [
    ("camera_probe_target_fixture", CameraProbeTarget, "issued_at", "expires_at", timedelta(seconds=30)),
    ("camera_capability_fixture", CameraCapabilityEvidenceV1, "observed_at", "valid_until", timedelta(hours=24)),
    ("camera_egress_fixture", CameraEgressEvidenceV1, "observed_at", "valid_until", timedelta(days=30)),
    ("trackmix_arc_fixture", TrackMixArcEvidenceV1, "qualified_at", "valid_until", timedelta(days=365)),
    ("storage_measurement_fixture", StorageMeasurementV1, "finalized_at", "valid_until", timedelta(days=90)),
    ("capacity_projection_fixture", CapacityProjectionV1, "projected_at", "valid_until", timedelta(days=90)),
    ("open_camera_stream_fixture", OpenCameraStreamV1, "issued_at", "expires_at", timedelta(seconds=5)),
    ("read_only_media_handle_fixture", ReadOnlyMediaHandle, "issued_at", "attach_by", timedelta(seconds=5)),
    ("source_health_fixture", SourceHealthV1, "observed_at", "valid_until", timedelta(seconds=60)),
    ("recording_health_fixture", RecordingHealthV1, "observed_at", "valid_until", timedelta(seconds=60)),
    ("recorder_pause_fixture", RecorderPauseV1, "issued_at", "expires_at", timedelta(seconds=5)),
    ("recorder_resume_fixture", RecorderResumeV1, "issued_at", "expires_at", timedelta(seconds=5)),
    ("owner_clip_query_fixture", OwnerClipQueryV1, "issued_at", "expires_at", timedelta(seconds=5)),
    ("opaque_clip_page_fixture", OpaquePage[ClipV1], "issued_at", "expires_at", timedelta(seconds=30)),
    ("camera_presence_evidence_fixture", AnonymousPresenceEvidenceV1, "observed_at", "max_valid_until", timedelta(minutes=5)),
    ("camera_overview_fixture", CameraOverviewUIV1, "generated_at", "expires_at", timedelta(seconds=30)),
    ("safe_alert_sse_fixture", SafeAlertSSEV1, "emitted_at", "valid_until", timedelta(seconds=30)),
    ("vision_ipc_envelope_fixture", VisionIpcEnvelopeV1[VisionIpcPayloadV1], "issued_at", "expires_at", timedelta(seconds=2)),
])
def test_every_ephemeral_port_authority_has_a_positive_bounded_lifetime(
    request, fixture_name, model, start_field, end_field, maximum,
) -> None:
    fixture = request.getfixturevalue(fixture_name)
    for invalid_end in (fixture[start_field], fixture[start_field] + maximum + timedelta(microseconds=1)):
        with pytest.raises(ValidationError):
            model.model_validate({**fixture, end_field: invalid_end})

@pytest.mark.parametrize(("fixture_name", "model", "field"), [
    ("camera_capability_fixture", CameraCapabilityEvidenceV1, "source_path"),
    ("camera_egress_fixture", CameraEgressEvidenceV1, "evidence_state"),
    ("trackmix_arc_fixture", TrackMixArcEvidenceV1, "decision"),
    ("storage_measurement_fixture", StorageMeasurementV1, "measurement_basis"),
    ("capacity_projection_fixture", CapacityProjectionV1, "decision"),
    ("open_camera_stream_fixture", OpenCameraStreamV1, "stream_role"),
    ("read_only_media_handle_fixture", ReadOnlyMediaHandle, "media_state"),
    ("native_event_fixture", NativeCameraEventV1, "detector_code"),
    ("source_health_fixture", SourceHealthV1, "source_state"),
    ("recording_profile_fixture", RecordingProfileV1, "media_mode"),
    ("recorder_receipt_fixture", RecorderReceiptV1, "outcome"),
    ("clip_unavailable_fixture", ClipUnavailableV1, "reason"),
    ("staged_segment_fixture", StagedSegment, "stage_state"),
    ("opaque_media_manifest_fixture", OpaqueMediaManifestV1, "media_kind"),
    ("staged_clip_fixture", StagedClip, "completeness"),
    ("owner_clip_query_fixture", OwnerClipQueryV1, "view"),
    ("opaque_clip_page_fixture", OpaquePage[ClipV1], "page_state"),
    ("camera_presence_evidence_fixture", AnonymousPresenceEvidenceV1, "kind"),
    ("event_ingress_receipt_fixture", EventIngressReceiptV1, "state"),
    ("camera_overview_fixture", CameraOverviewUIV1, "projection_state"),
    ("safe_alert_sse_fixture", SafeAlertSSEV1, "delivery_state"),
    ("vision_ipc_envelope_fixture", VisionIpcEnvelopeV1[VisionIpcPayloadV1], "message_type"),
])
def test_every_new_port_enum_rejects_extension(request, fixture_name, model, field) -> None:
    fixture = request.getfixturevalue(fixture_name)
    with pytest.raises(ValidationError):
        model.model_validate({**fixture, field: "future_unreviewed_value"})

def test_port_authority_contracts_do_not_coerce_scalar_types(
    open_camera_stream_fixture, recorder_pause_fixture, event_ingress_receipt_fixture,
    capacity_projection_fixture, safe_alert_sse_fixture, vision_ipc_envelope_fixture,
) -> None:
    for model, fixture, mutation in (
        (OpenCameraStreamV1, open_camera_stream_fixture, {"camera_binding_generation": "1"}),
        (RecorderPauseV1, recorder_pause_fixture, {"single_use": 1}),
        (EventIngressReceiptV1, event_ingress_receipt_fixture, {"dispatched_to_alerts": 0}),
        (CapacityProjectionV1, capacity_projection_fixture, {"eligible_camera_count": "3"}),
        (SafeAlertSSEV1, safe_alert_sse_fixture, {"delivery_sequence": "1"}),
        (
            VisionIpcEnvelopeV1[VisionIpcPayloadV1],
            vision_ipc_envelope_fixture,
            {"sender_registration_generation": "1"},
        ),
    ):
        with pytest.raises(ValidationError):
            model.model_validate({**fixture, **mutation})

def test_capability_state_cannot_claim_a_nonrunnable_path_with_streams(camera_capability_fixture) -> None:
    with pytest.raises(ValidationError, match="camera_capability_source_path_invalid"):
        CameraCapabilityEvidenceV1.model_validate({
            **camera_capability_fixture,
            "source_path": "inventory_only",
            "reason_codes": ("local_stream_unproved",),
        })

def test_handle_profile_and_health_states_reject_internal_contradictions(
    read_only_media_handle_fixture, recording_profile_fixture, source_health_fixture, recording_health_fixture,
) -> None:
    with pytest.raises(ValidationError, match="media_handle_packet_rate_invalid"):
        ReadOnlyMediaHandle.model_validate({
            **read_only_media_handle_fixture,
            "max_bytes_per_second": 1024,
            "max_packet_bytes": 1025,
        })
    with pytest.raises(ValidationError, match="recording_profile_lineage_invalid"):
        RecordingProfileV1.model_validate({
            **recording_profile_fixture,
            "profile_generation": 3,
            "supersedes_profile_generation": 1,
        })
    with pytest.raises(ValidationError, match="source_health_online_state_invalid"):
        SourceHealthV1.model_validate({
            **source_health_fixture,
            "source_state": "online",
            "stream_state": "closed",
        })
    with pytest.raises(ValidationError, match="recording_health_running_state_invalid"):
        RecordingHealthV1.model_validate({
            **recording_health_fixture,
            "recorder_state": "running",
            "storage_state": "write_blocked",
        })

def test_native_event_end_state_and_envelope_payload_are_bound(native_event_fixture, event_envelope_fixture) -> None:
    with pytest.raises(ValidationError, match="native_camera_event_end_invalid"):
        NativeCameraEventV1.model_validate({**native_event_fixture, "event_state": "ended", "ended_at": None})
    with pytest.raises(ValidationError, match="native_camera_event_window_invalid"):
        NativeCameraEventV1.model_validate({
            **native_event_fixture,
            "observed_at": native_event_fixture["started_at"] + timedelta(minutes=5, microseconds=1),
        })
    with pytest.raises(ValidationError, match="cross_domain_event_payload_binding_invalid"):
        CameraSecurityEventEnvelopeV1.model_validate({
            **event_envelope_fixture,
            "event_type": "presence.changed.v1",
        })
    with pytest.raises(ValidationError):
        CameraSecurityEventEnvelopeV1.model_validate({
            **event_envelope_fixture,
            "schema_version": 2,
        })
    with pytest.raises(ValidationError, match="cross_domain_event_ingress_window_invalid"):
        CameraSecurityEventEnvelopeV1.model_validate({
            **event_envelope_fixture,
            "ingested_at": event_envelope_fixture["observed_at"] + timedelta(seconds=30, microseconds=1),
        })

def test_camera_event_rejects_fresh_wrapper_over_stale_or_future_payload(
    event_envelope_fixture,
) -> None:
    payload = event_envelope_fixture["payload"]
    fresh_observed_at = payload["observed_at"] + timedelta(seconds=10)
    with pytest.raises(ValidationError, match="camera_event_observed_at_mismatch"):
        CameraSecurityEventEnvelopeV1.model_validate({
            **event_envelope_fixture,
            "observed_at": fresh_observed_at,
            "ingested_at": fresh_observed_at + timedelta(microseconds=1),
            "expires_at": fresh_observed_at + timedelta(seconds=1),
        })
    with pytest.raises(ValidationError, match="camera_event_observation_window_invalid"):
        CameraSecurityEventEnvelopeV1.model_validate({
            **event_envelope_fixture,
            "payload": {
                **payload,
                "started_at": payload["observed_at"] + timedelta(microseconds=1),
            },
        })

@pytest.mark.parametrize("mutation", [
    {"event_type": "presence.changed.v1"},
    {"event_id": uuid4()},
])
def test_camera_event_specialization_rejects_type_or_id_substitution(
    event_envelope_fixture, mutation,
) -> None:
    candidate = {**event_envelope_fixture, **mutation}
    with pytest.raises(ValidationError):
        CameraSecurityEventEnvelopeV1.model_validate(candidate)

@pytest.mark.parametrize("mutation", [
    {"event_type": "camera.security_event.v1"},
    {"event_id": uuid4()},
])
def test_presence_event_specialization_rejects_type_or_id_substitution(
    presence_event_fixture, mutation,
) -> None:
    candidate = {**presence_event_fixture, **mutation}
    with pytest.raises(ValidationError):
        PresenceChangedEventV1.model_validate(candidate)

def test_phase3_event_specializations_do_not_extend_phase2_envelope_shape() -> None:
    frozen_fields = set(CrossDomainEventV1.model_fields)
    assert set(CameraSecurityEventEnvelopeV1.model_fields) == frozen_fields
    assert set(PresenceChangedEventV1.model_fields) == frozen_fields
    assert "payload_schema_id" not in frozen_fields
    assert "direction" not in frozen_fields

@pytest.mark.parametrize("source_kinds", [
    ("commissioned_non_imaging",),
    ("camera_native_person", "commissioned_non_imaging"),
])
def test_occupied_presence_rejects_zero_for_non_imaging_and_cross_source_aggregation(
    presence_fixture, source_kinds,
) -> None:
    with pytest.raises(ValidationError, match="occupied_presence_zero_invalid"):
        PresenceChangedV1.model_validate({
            **presence_fixture,
            "state": "occupied",
            "count_band": "zero",
            "source_kinds": source_kinds,
        })

def test_cross_source_occupied_presence_accepts_a_nonzero_aggregate(presence_fixture) -> None:
    aggregate = PresenceChangedV1.model_validate({
        **presence_fixture,
        "state": "occupied",
        "count_band": "one",
        "source_kinds": ("camera_native_person", "commissioned_non_imaging"),
    })
    assert aggregate.count_band == "one"
    assert set(aggregate.source_kinds) == {"camera_native_person", "commissioned_non_imaging"}

@pytest.mark.parametrize("source_kinds", [
    ("camera_native_person", "commissioned_non_imaging"),
    ("commissioned_non_imaging", "system_timeout"),
    ("commissioned_non_imaging", "source_health"),
    ("commissioned_non_imaging", "privacy_shield"),
])
def test_vacancy_rejects_camera_or_uncertainty_sources(presence_fixture, source_kinds) -> None:
    with pytest.raises(ValidationError, match="vacant_presence_requires_non_imaging"):
        PresenceChangedV1.model_validate({
            **presence_fixture,
            "state": "vacant",
            "count_band": "zero",
            "source_kinds": source_kinds,
        })

def test_presence_event_rejects_fresh_wrapper_over_stale_payload(presence_event_fixture) -> None:
    payload = presence_event_fixture["payload"]
    fresh_observed_at = payload["observed_at"] + timedelta(seconds=10)
    with pytest.raises(ValidationError, match="presence_event_observed_at_mismatch"):
        PresenceChangedEventV1.model_validate({
            **presence_event_fixture,
            "observed_at": fresh_observed_at,
            "ingested_at": fresh_observed_at + timedelta(microseconds=1),
            "expires_at": fresh_observed_at + timedelta(seconds=1),
        })

def test_presence_event_expiry_cannot_outlive_payload_validity(presence_event_fixture) -> None:
    payload = presence_event_fixture["payload"]
    payload_valid_until = payload["observed_at"] + timedelta(seconds=30)
    with pytest.raises(ValidationError, match="presence_event_expiry_exceeds_payload_validity"):
        PresenceChangedEventV1.model_validate({
            **presence_event_fixture,
            "payload": {**payload, "valid_until": payload_valid_until},
            "ingested_at": payload["observed_at"] + timedelta(microseconds=1),
            "expires_at": payload_valid_until + timedelta(microseconds=1),
        })

def test_recorder_receipt_cannot_report_success_in_the_wrong_state(recorder_receipt_fixture) -> None:
    with pytest.raises(ValidationError, match="recorder_pause_receipt_invalid"):
        RecorderReceiptV1.model_validate({
            **recorder_receipt_fixture,
            "operation": "pause",
            "outcome": "applied",
            "recorder_state": "running",
            "gap_started_at": None,
            "reason_codes": (),
        })
    with pytest.raises(ValidationError, match="recorder_rejection_reason_required"):
        RecorderReceiptV1.model_validate({
            **recorder_receipt_fixture,
            "outcome": "rejected",
            "reason_codes": (),
        })

def test_staged_media_rejects_retention_drift_or_duplicate_views(staged_segment_fixture, staged_clip_fixture) -> None:
    with pytest.raises(ValidationError, match="staged_segment_retention_invalid"):
        StagedSegment.model_validate({
            **staged_segment_fixture,
            "immutable_expires_at": staged_segment_fixture["immutable_expires_at"] + timedelta(microseconds=1),
        })
    duplicate = (staged_clip_fixture["views"][0], staged_clip_fixture["views"][0])
    with pytest.raises(ValidationError, match="staged_clip_view_set_invalid"):
        StagedClip.model_validate({**staged_clip_fixture, "views": duplicate})

def test_staged_dual_view_clip_rejects_more_than_two_second_edge_offset(staged_clip_fixture) -> None:
    wide, tracking = staged_clip_fixture["views"]
    for changed_tracking in (
        {**tracking, "started_at": wide["started_at"] + timedelta(seconds=2, microseconds=1)},
        {**tracking, "ended_at": wide["ended_at"] + timedelta(seconds=2, microseconds=1)},
    ):
        with pytest.raises(ValidationError, match="staged_clip_dual_view_alignment_invalid"):
            StagedClip.model_validate({
                **staged_clip_fixture,
                "views": (wide, changed_tracking),
            })

def test_unavailable_clip_cannot_precede_its_event(clip_unavailable_fixture) -> None:
    with pytest.raises(ValidationError, match="clip_unavailable_window_invalid"):
        ClipUnavailableV1.model_validate({
            **clip_unavailable_fixture,
            "determined_at": clip_unavailable_fixture["event_started_at"] - timedelta(microseconds=1),
        })

def test_catalog_query_page_and_storage_tokens_are_not_ambient_authority(
    owner_clip_query_fixture, opaque_clip_page_fixture, read_only_media_handle_fixture, staged_segment_fixture,
) -> None:
    with pytest.raises(ValidationError, match="owner_clip_query_camera_binding_invalid"):
        OwnerClipQueryV1.model_validate({
            **owner_clip_query_fixture,
            "camera_binding_id": None,
            "camera_binding_generation": 3,
        })
    with pytest.raises(ValidationError, match="opaque_page_cursor_state_invalid"):
        OpaquePage[ClipV1].model_validate({
            **opaque_clip_page_fixture,
            "page_state": "complete",
            "next_cursor": "A" * 43,
        })
    for token in ("", "../catalog/clip.mkv", "A" * 42, "A" * 44, "camera_01_clip_01"):
        with pytest.raises(ValidationError):
            OpaqueStorageToken.model_validate(token)
    for model, fixture, field in (
        (ReadOnlyMediaHandle, read_only_media_handle_fixture, "relay_id"),
        (StagedSegment, staged_segment_fixture, "staging_token"),
        (OwnerClipQueryV1, owner_clip_query_fixture, "cursor"),
    ):
        with pytest.raises(ValidationError):
            model.model_validate({**fixture, field: "../not-opaque"})

def test_owner_segment_timeline_is_low_wide_seven_day_and_storage_opaque(
    owner_segment_item_fixture,
) -> None:
    item = OwnerSegmentTimelineItemV1.model_validate(owner_segment_item_fixture)
    assert item.stream_role == "low_wide"
    assert item.immutable_expires_at == item.ended_at + timedelta(days=7)
    assert "opaque_storage_token" not in OwnerSegmentTimelineItemV1.model_fields

def test_playback_subject_union_rejects_clip_segment_field_splicing(playback_range_request_fixture) -> None:
    subject = playback_range_request_fixture["subject"]
    with pytest.raises(ValidationError):
        PlaybackRangeRequestV1.model_validate({
            **playback_range_request_fixture,
            "subject": {**subject, "kind": "continuous_segment", "stream_role": "low_wide"},
        })

def test_ingress_and_presence_states_cannot_overclaim(
    event_ingress_receipt_fixture, camera_presence_evidence_fixture,
) -> None:
    with pytest.raises(ValidationError, match="event_ingress_nonaccepted_dispatch_forbidden"):
        EventIngressReceiptV1.model_validate({
            **event_ingress_receipt_fixture,
            "state": "quarantined",
            "dispatched_to_alerts": True,
            "reason_codes": ("generation_stale",),
        })
    with pytest.raises(ValidationError, match="camera_presence_assertion_invalid"):
        AnonymousPresenceEvidenceV1.model_validate({
            **camera_presence_evidence_fixture,
            "asserted_state": "vacant",
            "count_band": "zero",
        })

def test_egress_evidence_requires_every_case_and_cannot_self_declare_eligible(camera_egress_fixture) -> None:
    with pytest.raises(ValidationError):
        CameraEgressEvidenceV1.model_validate({
            **camera_egress_fixture,
            "cases": camera_egress_fixture["cases"][:-1],
        })
    cases = list(camera_egress_fixture["cases"])
    cases[0] = {**cases[0], "result": "unverified"}
    with pytest.raises(ValidationError, match="camera_egress_evidence_state_invalid"):
        CameraEgressEvidenceV1.model_validate({**camera_egress_fixture, "cases": tuple(cases)})

def test_trackmix_decision_is_recomputed_from_content_safe_trials(trackmix_arc_fixture) -> None:
    trials = list(trackmix_arc_fixture["trials"])
    trials[-1] = {**trials[-1], **{
        key: trials[0][key] for key in ("doorway", "motion_mode", "condition")
    }}
    with pytest.raises(ValidationError, match="trackmix_trial_matrix_invalid"):
        TrackMixArcEvidenceV1.model_validate({**trackmix_arc_fixture, "trials": tuple(trials)})
    trials = list(trackmix_arc_fixture["trials"])
    fixed_index = next(index for index, trial in enumerate(trials) if trial["motion_mode"] == "fixed_wide")
    trials[fixed_index] = {**trials[fixed_index], "prohibited_target_visible": True}
    with pytest.raises(ValidationError, match="trackmix_arc_decision_invalid"):
        TrackMixArcEvidenceV1.model_validate({**trackmix_arc_fixture, "trials": tuple(trials)})

def test_ineligible_storage_is_zero_not_estimated(storage_measurement_fixture) -> None:
    with pytest.raises(ValidationError):
        StorageMeasurementV1.model_validate({**storage_measurement_fixture, "estimated_bytes": 1})
    with pytest.raises(ValidationError, match="storage_measurement_ineligible_value_invalid"):
        StorageMeasurementV1.model_validate({
            **storage_measurement_fixture,
            "source_path": "inventory_only",
            "central_recording": "unavailable",
            "measurement_basis": "none_ineligible",
            "reason_codes": ("source_ineligible",),
        })
    with pytest.raises(ValidationError, match="storage_measurement_tracking_continuous_forbidden"):
        StorageMeasurementV1.model_validate({**storage_measurement_fixture, "view": "tracking"})

def test_capacity_formula_claim_and_decision_cannot_drift(capacity_projection_fixture) -> None:
    with pytest.raises(ValidationError, match="capacity_projection_formula_invalid"):
        CapacityProjectionV1.model_validate({
            **capacity_projection_fixture,
            "policy_bytes": capacity_projection_fixture["policy_bytes"] + 1,
        })
    with pytest.raises(ValidationError, match="capacity_projection_claim_invalid"):
        CapacityProjectionV1.model_validate({
            **capacity_projection_fixture,
            "claim": (
                "partial_eligible_camera_set"
                if capacity_projection_fixture["claim"] == "complete_eligible_camera_set"
                else "complete_eligible_camera_set"
            ),
        })

def test_media_manifest_is_opaque_authenticated_and_retention_exact(opaque_media_manifest_fixture) -> None:
    with pytest.raises(ValidationError):
        OpaqueMediaManifestV1.model_validate({**opaque_media_manifest_fixture, "path": "/video/camera-name.mkv"})
    with pytest.raises(ValidationError, match="media_manifest_retention_invalid"):
        OpaqueMediaManifestV1.model_validate({
            **opaque_media_manifest_fixture,
            "immutable_expires_at": opaque_media_manifest_fixture["immutable_expires_at"] + timedelta(microseconds=1),
        })
    with pytest.raises(ValidationError):
        OpaqueMediaManifestV1.model_validate({**opaque_media_manifest_fixture, "manifest_commitment": "not-a-commitment"})
    for field in ("area_id", "area_generation", "zone_id", "zone_generation"):
        with pytest.raises(ValidationError):
            OpaqueMediaManifestV1.model_validate({
                **opaque_media_manifest_fixture,
                "media_kind": "segment",
                "stream_role": "low_wide",
                field: None,
            })

def test_camera_overview_cannot_refresh_a_stale_nested_fact(
    camera_overview_fact_fixture, camera_overview_fixture,
) -> None:
    stale_render = camera_overview_fact_fixture["valid_until"] + timedelta(microseconds=1)
    with pytest.raises(ValidationError, match="camera_overview_truth_state_invalid"):
        CameraOverviewFactV1.model_validate({
            **camera_overview_fact_fixture,
            "rendered_at": stale_render,
            "truth_state": "current",
        })
    facts = list(camera_overview_fixture["facts"])
    facts[0] = {**facts[0], "rendered_at": facts[0]["rendered_at"] - timedelta(microseconds=1)}
    with pytest.raises(ValidationError, match="camera_overview_fact_generation_or_time_invalid"):
        CameraOverviewUIV1.model_validate({**camera_overview_fixture, "facts": tuple(facts)})

def test_camera_overview_expiry_cannot_extend_current_child_fact(
    camera_overview_fixture,
) -> None:
    facts = list(camera_overview_fixture["facts"])
    facts[0] = {
        **facts[0],
        "valid_until": camera_overview_fixture["generated_at"] + timedelta(seconds=1),
        "truth_state": "current",
    }
    with pytest.raises(ValidationError, match="camera_overview_outlives_current_fact"):
        CameraOverviewUIV1.model_validate({
            **camera_overview_fixture,
            "facts": tuple(facts),
            "expires_at": camera_overview_fixture["generated_at"] + timedelta(seconds=30),
        })

def test_safe_alert_cannot_false_claim_clip_or_live_delivery(safe_alert_sse_fixture) -> None:
    with pytest.raises(ValidationError, match="safe_alert_body_template_invalid"):
        SafeAlertSSEV1.model_validate({**safe_alert_sse_fixture, "safe_body": "Free-form camera text"})
    with pytest.raises(ValidationError, match="safe_alert_clip_state_invalid"):
        SafeAlertSSEV1.model_validate({**safe_alert_sse_fixture, "clip_state": "available", "clip_id": None})
    with pytest.raises(ValidationError, match="safe_alert_clip_reason_state_invalid"):
        SafeAlertSSEV1.model_validate({
            **safe_alert_sse_fixture,
            "clip_state": "unavailable",
            "clip_id": None,
            "clip_generation": None,
            "catalog_generation": None,
            "clip_reason_code": None,
        })
    with pytest.raises(ValidationError, match="safe_alert_delivery_state_invalid"):
        SafeAlertSSEV1.model_validate({**safe_alert_sse_fixture, "delivery_state": "delayed_inbox_replay"})
    with pytest.raises(ValidationError, match="safe_alert_inbox_retention_invalid"):
        SafeAlertSSEV1.model_validate({
            **safe_alert_sse_fixture,
            "inbox_expires_at": safe_alert_sse_fixture["inbox_expires_at"] + timedelta(microseconds=1),
        })
    for forbidden in ("thumbnail", "media_token", "person_name", "address"):
        with pytest.raises(ValidationError):
            SafeAlertSSEV1.model_validate({**safe_alert_sse_fixture, forbidden: "forbidden"})

def test_delayed_safe_alert_sse_cannot_outlive_inbox_authority(safe_alert_sse_fixture) -> None:
    inbox_expires_at = safe_alert_sse_fixture["inbox_expires_at"]
    delayed = {
        **safe_alert_sse_fixture,
        "emitted_at": inbox_expires_at - timedelta(seconds=1),
        "valid_until": inbox_expires_at,
        "delivery_state": "delayed_inbox_replay",
        "reason_codes": ("delayed_inbox_replay",),
    }
    assert SafeAlertSSEV1.model_validate(delayed).valid_until == inbox_expires_at
    with pytest.raises(ValidationError, match="safe_alert_sse_lifetime_invalid"):
        SafeAlertSSEV1.model_validate({
            **delayed,
            "valid_until": inbox_expires_at + timedelta(microseconds=1),
        })

def test_ipc_envelope_binds_route_direction_generation_sequence_deadline_and_payload(
    vision_ipc_envelope_fixture,
) -> None:
    model = VisionIpcEnvelopeV1[VisionIpcPayloadV1]
    wrong_payload_schema = (
        "recorder_pause.v1"
        if vision_ipc_envelope_fixture["payload_schema_id"] != "recorder_pause.v1"
        else "recording_health.v1"
    )
    wrong_recipient = next(
        process
        for process in ("core", "camera_source", "recorder", "media_proxy", "owner_ingress")
        if process not in {
            vision_ipc_envelope_fixture["sender_process"], vision_ipc_envelope_fixture["recipient_process"],
        }
    )
    for mutation in (
        {"recipient_process": vision_ipc_envelope_fixture["sender_process"]},
        {"recipient_process": wrong_recipient},
        {"payload_schema_id": wrong_payload_schema},
        {"sequence": 0},
        {"expires_at": vision_ipc_envelope_fixture["issued_at"] + timedelta(seconds=2, microseconds=1)},
    ):
        with pytest.raises(ValidationError):
            model.model_validate({**vision_ipc_envelope_fixture, **mutation})
    with pytest.raises(ValidationError):
        model.model_validate({
            **vision_ipc_envelope_fixture,
            "payload": {**vision_ipc_envelope_fixture["payload"], "frame_bytes": "forbidden"},
        })
    envelope = model.model_validate(vision_ipc_envelope_fixture)
    live = VisionIpcLiveBinding(
        sender_process=envelope.sender_process,
        recipient_process=envelope.recipient_process,
        sender_registration_generation=envelope.sender_registration_generation,
        recipient_registration_generation=envelope.recipient_registration_generation,
        expected_sequence=envelope.sequence,
        claimed_envelope_ids=frozenset(),
    )
    claimed = VisionIpcLiveBinding(
        sender_process=live.sender_process,
        recipient_process=live.recipient_process,
        sender_registration_generation=live.sender_registration_generation,
        recipient_registration_generation=live.recipient_registration_generation,
        expected_sequence=live.expected_sequence,
        claimed_envelope_ids=frozenset({envelope.envelope_id}),
    )
    stale_generation = VisionIpcLiveBinding(
        sender_process=live.sender_process,
        recipient_process=live.recipient_process,
        sender_registration_generation=live.sender_registration_generation + 1,
        recipient_registration_generation=live.recipient_registration_generation,
        expected_sequence=live.expected_sequence,
        claimed_envelope_ids=frozenset(),
    )
    wrong_sequence = VisionIpcLiveBinding(
        sender_process=live.sender_process,
        recipient_process=live.recipient_process,
        sender_registration_generation=live.sender_registration_generation,
        recipient_registration_generation=live.recipient_registration_generation,
        expected_sequence=live.expected_sequence + 1,
        claimed_envelope_ids=frozenset(),
    )
    for binding, now, digest, authenticated in (
        (live, envelope.issued_at, "0" * 64, True),
        (live, envelope.issued_at, envelope.payload_digest, False),
        (claimed, envelope.issued_at, envelope.payload_digest, True),
        (stale_generation, envelope.issued_at, envelope.payload_digest, True),
        (wrong_sequence, envelope.issued_at, envelope.payload_digest, True),
        (live, envelope.expires_at, envelope.payload_digest, True),
    ):
        with pytest.raises(PermissionError, match="vision_ipc_binding_invalid"):
            validate_vision_ipc_envelope_binding(
                envelope, binding, now, digest, authenticated_commitment=authenticated,
            )

@pytest.mark.parametrize(("message_type", "sender", "recipient"), [
    ("camera_probe", "core", "camera_source"),
    ("camera_capability_evidence", "camera_source", "core"),
    ("open_camera_stream", "recorder", "camera_source"),
    ("read_only_media_handle", "camera_source", "recorder"),
    ("native_camera_event", "camera_source", "recorder"),
    ("source_health", "camera_source", "recorder"),
    ("camera_security_event", "recorder", "core"),
    ("recording_health", "recorder", "core"),
    ("recorder_start", "core", "recorder"),
    ("recorder_pause", "core", "recorder"),
    ("recorder_resume", "core", "recorder"),
    ("recorder_receipt", "recorder", "core"),
    ("owner_clip_query", "core", "recorder"),
    ("clip_page", "recorder", "core"),
    ("owner_segment_query", "core", "recorder"),
    ("segment_page", "recorder", "core"),
    ("media_grant_register", "core", "recorder"),
    ("media_grant_register_receipt", "recorder", "core"),
    ("media_grant_claim", "media_proxy", "recorder"),
    ("media_grant_claim_receipt", "recorder", "media_proxy"),
    ("clip_export_request", "core", "recorder"),
    ("clip_export_receipt", "recorder", "core"),
    ("clip_delete_request", "core", "recorder"),
    ("clip_delete_receipt", "recorder", "core"),
    ("owner_pre_session_request", "owner_ingress", "core"),
    ("owner_pre_session_result", "core", "owner_ingress"),
    ("event_ingress_receipt", "core", "recorder"),
])
def test_every_ipc_message_has_one_closed_payload_and_direction(
    ipc_fixture_for, message_type, sender, recipient,
) -> None:
    model = VisionIpcEnvelopeV1[VisionIpcPayloadV1]
    wire = ipc_fixture_for(message_type, sender, recipient)
    envelope = model.model_validate(wire)
    assert (envelope.sender_process, envelope.recipient_process) == (sender, recipient)
    wrong_recipient = next(
        process
        for process in ("core", "camera_source", "recorder", "media_proxy", "owner_ingress")
        if process not in {sender, recipient}
    )
    with pytest.raises(ValidationError, match="vision_ipc_direction_invalid"):
        model.model_validate({**wire, "recipient_process": wrong_recipient})

def test_media_grant_rejects_nonpositive_or_over_sixty_second_lifetime(media_grant_fixture) -> None:
    for expires_at in (
        media_grant_fixture["issued_at"],
        media_grant_fixture["issued_at"] + timedelta(seconds=60, microseconds=1),
    ):
        with pytest.raises(ValidationError):
            MediaPlaybackGrantV1.model_validate({**media_grant_fixture, "expires_at": expires_at})
    for operation in ("export", "delete", "share", "transcode"):
        with pytest.raises(ValidationError):
            MediaPlaybackGrantV1.model_validate({
                **media_grant_fixture,
                "allowed_operation": operation,
            })

def test_prepared_playback_route_token_has_exact_encoding_and_digest(
    prepared_playback_range_fixture,
) -> None:
    for mutation in (
        {"opaque_grant_id": "short"},
        {"opaque_grant_id": "!" * 43},
        {"route_token_digest": OTHER_SHA256},
    ):
        with pytest.raises(ValidationError):
            PreparedPlaybackRangeV1.model_validate({
                **prepared_playback_range_fixture,
                **mutation,
            })

def test_playback_range_request_is_bounded_and_generation_bound(playback_range_request_fixture) -> None:
    for mutation in (
        {"subject": {**playback_range_request_fixture["subject"], "clip_generation": 0}},
        {"expected_catalog_generation": 0},
        {"expected_privacy_generation": 0},
        {"expires_at": playback_range_request_fixture["issued_at"]},
        {"expires_at": playback_range_request_fixture["issued_at"] + timedelta(seconds=5, microseconds=1)},
    ):
        with pytest.raises(ValidationError):
            PlaybackRangeRequestV1.model_validate({**playback_range_request_fixture, **mutation})

def test_playback_byte_range_rejects_inversion_and_oversize(playback_range_request_fixture) -> None:
    for byte_range in (
        {"start": 10, "end_inclusive": 9},
        {"start": 0, "end_inclusive": 8 * 1024 * 1024},
    ):
        with pytest.raises(ValidationError):
            PlaybackRangeRequestV1.model_validate({**playback_range_request_fixture, "byte_range": byte_range})

@pytest.mark.parametrize("envelope_fixture,field", [
    ("signed_selected_frame_request_fixture", "signature_b64url"),
    ("signed_anonymous_observation_fixture", "signature_b64url"),
    ("signed_media_playback_grant_fixture", "signature_b64url"),
])
def test_vision_wire_envelopes_require_exact_signatures(request, envelope_fixture, field) -> None:
    model = {
        "signed_selected_frame_request_fixture": SignedSelectedFrameRequestV1,
        "signed_anonymous_observation_fixture": SignedAnonymousVisualObservationV1,
        "signed_media_playback_grant_fixture": SignedMediaPlaybackGrantV1,
    }[envelope_fixture]
    payload = request.getfixturevalue(envelope_fixture)
    payload.pop(field)
    with pytest.raises(ValidationError):
        model.model_validate(payload)

def test_selected_frame_request_or_result_mutation_invalidates_signature(selected_frame_verifier, signed_request, signed_observation) -> None:
    changed_request = signed_request.model_copy(update={
        "request": signed_request.request.model_copy(update={"privacy_generation": signed_request.request.privacy_generation + 1}),
    })
    changed_result = signed_observation.model_copy(update={
        "observation": signed_observation.observation.model_copy(update={"model_artifact_id": "model_other_synth_01"}),
    })
    for candidate in (changed_request, changed_result):
        with pytest.raises(PermissionError, match="selected_frame_signature_invalid"):
            selected_frame_verifier.verify_and_claim_once(candidate)
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/vision/test_vision_contracts.py tests/property/vision/test_contract_rejection.py -q`
Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_contracts.vision'`.

- [ ] **Step 3: Implement complete frozen models, cross-field validators, schema generation, and synthetic fixtures**

~~~python
def canonical_vision_bytes(value: VisionContract) -> bytes:
    return canonical_mapping_bytes(value.model_dump(mode="python"))

def canonical_playback_range_request_unsigned_bytes(request: PlaybackRangeRequestV1) -> bytes:
    return canonical_mapping_bytes(
        request.model_dump(mode="python", exclude={"request_commitment"}),
    )

def canonical_anonymous_presence_evidence_unsigned_bytes(
    evidence: AnonymousPresenceEvidenceV1,
) -> bytes:
    return canonical_mapping_bytes(
        evidence.model_dump(mode="python", exclude={"commitment"}),
    )

@dataclass(frozen=True)
class SelectedFrameLiveBinding:
    camera_binding_id: str
    camera_binding_generation: int
    area_id: str
    area_generation: int
    zone_id: str
    zone_generation: int
    privacy_policy_version: int
    privacy_generation: int
    model_manifest_digest: str
    model_artifact_id: str
    model_artifact_digest: str
    calibration_digest: str

def validate_selected_frame_result_binding(
    request: SelectedFrameRequestV1,
    observation: AnonymousVisualObservationV1,
    live: SelectedFrameLiveBinding,
    now: datetime,
) -> None:
    request_binding = (
        request.camera_binding_id, request.camera_binding_generation,
        request.area_id, request.area_generation, request.zone_id, request.zone_generation,
        request.privacy_policy_version, request.privacy_generation, request.model_manifest_digest,
    )
    current_binding = (
        live.camera_binding_id, live.camera_binding_generation,
        live.area_id, live.area_generation, live.zone_id, live.zone_generation,
        live.privacy_policy_version, live.privacy_generation, live.model_manifest_digest,
    )
    observation_binding_is_current = (
        observation.request_id == request.request_id
        and observation.zone_id == live.zone_id
        and observation.model_artifact_id == live.model_artifact_id
        and observation.model_digest == live.model_artifact_digest
        and observation.calibration_digest == live.calibration_digest
        and request.not_before <= observation.evaluated_at <= now
        and now < observation.valid_until
        and now < request.expires_at
        and observation.valid_until <= request.expires_at
    )
    if request_binding != current_binding or not observation_binding_is_current:
        raise ValueError("selected_frame_binding_stale")
~~~

The selected-frame request and anonymous-observation time validators are attached directly to their Pydantic models. The live binding keeps the approved manifest digest and approved model-artifact digest distinct: the request binds the former and the result binds the latter. The immediate acceptance helper receives trusted current time and rejects pre-window, future-evaluated, inverted, expired, or stale `(area_id, area_generation)` results. Import and re-export the accepted Phase 2 generic `CrossDomainEventV1` without changing its field names or canonical encoding; generate the closed `CameraSecurityEventEnvelopeV1` and `PresenceChangedEventV1` specializations over it. Both narrow only the frozen `event_type` and payload type and exact-bind envelope/payload `event_id` and `observed_at`; the presence specialization also caps envelope expiry at payload `valid_until`. Current publisher/source/location binding metadata supplies dispatch authority without adding `direction`, `payload_schema_id`, or any other field to the Phase 2 envelope. A fresh wrapper can never revive either stale payload, and neither is an HA action route. Generate recursively closed schemas, reject duplicate JSON keys before Pydantic, and add property mutations for unknown version/field/enum, unsafe IDs, malformed opaque tokens/cursors, cross-area or area-generation substitution, Guest-as-room-class, every zero/negative generation, overlong or inverted authority/evidence/SSE/IPC windows, incomplete or contradictory egress/TrackMix evidence, incomplete or semantically duplicated capacity matrix rows, estimated bytes for ineligible sources, capacity formula/claim/decision drift, manifest identity/retention/path injection, stale nested UI facts, false clip/live alert state, IPC direction/schema/header-sequence/payload-digest/HMAC/replay drift, camera/presence type/ID/wrapper-time/reorder/expiry drift, occupied-plus-zero cross-source aggregation, incompatible capability/source/receipt/presence states, duplicate page/view/stream/trial entries, more than two clip views, non-single-use commands/grants, wrong retention expiry, grant lifetime over 60 seconds, selected-frame purpose/schema changes, and free-form observation classes.

- [ ] **Step 4: Run green and schema-drift checks**

Run: `uv run python scripts/phase3/generate_vision_schemas.py --check && uv run pytest tests/contract/vision tests/property/vision/test_contract_rejection.py -q && uv run ruff check packages/contracts/src/tuntun_contracts/vision scripts/phase3/generate_vision_schemas.py tests/contract/vision tests/property/vision && uv run mypy packages/contracts/src`
Expected: PASS; generator prints `vision schema drift: none`; `CapacityCampaignCameraV1.required_views` emits `minItems=maxItems=1` with the sole `wide` prefix item, and every unsupported version/field/enum, scalar coercion, malformed opaque value, stale/zero generation, incompatible state, range, and lifetime window is rejected.

- [ ] **Step 5: Commit exact contract paths**

~~~bash
git add packages/contracts/src/tuntun_contracts/vision scripts/phase3/generate_vision_schemas.py schemas/vision/v1 fixtures/synthetic/vision/contracts tests/contract/vision tests/property/vision/test_contract_rejection.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(vision): freeze Phase 3 contracts"
~~~

### Task 02: Build deterministic synthetic media, source fakes, and fault points

**Depends on:** Task 01.
**Gate contribution:** P3-E0 and every later non-hardware test.
**Estimated effort:** 1 person-day.

**Files:**
- Create: `packages/testing/src/tuntun_testing/vision/fake_source.py`
- Create: `packages/testing/src/tuntun_testing/vision/fake_recorder.py`
- Create: `packages/testing/src/tuntun_testing/vision/fake_volume.py`
- Create: `packages/testing/src/tuntun_testing/vision/fake_media.py`
- Create: `packages/testing/src/tuntun_testing/vision/fault_points.py`
- Create: `packages/testing/src/tuntun_testing/vision/scenario.py`
- Create: `scripts/phase3/build_media_corpus.py`
- Create: `fixtures/synthetic/vision/media-manifest.json`
- Create: `fixtures/adversarial/vision/event-cases.json`
- Test: `tests/unit/testing/vision/test_vision_fakes.py`
- Test: `tests/privacy/vision/test_synthetic_only.py`

**Interfaces:** Produces `FakeCameraSource`, `FakeRecorder`, `FakeVideoVolume`, `VisionScenario`, deterministic `FaultPoint` names, and generated H.264/H.265 color-bar streams with optional synthetic event markers, clock skew, sequence loss, corruption, oversize metadata, and deliberately present audio tracks. Every generated frame carries a test sentinel and contains no photograph/person/household scene.

- [ ] **Step 1: Write red determinism and privacy tests**

~~~python
def test_media_corpus_is_deterministic(tmp_path: Path) -> None:
    first = build_synthetic_media(tmp_path / "a", seed=31027)
    second = build_synthetic_media(tmp_path / "b", seed=31027)
    assert first.sha256_by_case == second.sha256_by_case

def test_fault_script_replays_exact_transition() -> None:
    scenario = VisionScenario(seed=9, faults={"after_catalog_commit": 1})
    with pytest.raises(InjectedVisionFault):
        scenario.recorder.commit_one_segment()
    assert scenario.faults.hits("after_catalog_commit") == 1
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/testing/vision/test_vision_fakes.py tests/privacy/vision/test_synthetic_only.py -q`
Expected: FAIL during collection because `tuntun_testing.vision` does not exist.

- [ ] **Step 3: Implement bounded generators and deterministic fakes**

~~~python
SYNTHETIC_VIDEO_SENTINEL = b"TUNTUN_SYNTHETIC_VIDEO_ONLY_31027"

@dataclass(frozen=True)
class FaultPoint:
    name: Literal[
        "before_file_open", "during_segment_write", "after_fsync_before_catalog",
        "after_catalog_commit", "after_publish_before_receipt", "during_unlink",
        "source_disconnect", "clock_rollback", "volume_substitution",
    ]
    occurrence: int

class FakeVideoVolume:
    def assert_beneath_root(self, token: OpaqueStorageToken) -> Path:
        candidate = (self.root / str(token)).resolve()
        if not candidate.is_relative_to(self.root.resolve()):
            raise ValueError("media_path_rejected")
        return candidate
~~~

The corpus builder invokes the pinned test-only media tool with an argument list and no shell, writes into a temporary root, records codec/duration/audio/sentinel/digest metadata, and commits only the manifest plus generator. Cases include low-wide, event-wide, tracking, audio-present rejection, truncated container, corrupt extradata, long GOP, timestamp rollback, duplicated packets, and oversized strings.

- [ ] **Step 4: Run green and private-data scan**

Run: `uv run python scripts/phase3/build_media_corpus.py --check && uv run pytest tests/unit/testing/vision/test_vision_fakes.py tests/privacy/vision/test_synthetic_only.py -q && uv run ruff check packages/testing/src/tuntun_testing/vision scripts/phase3/build_media_corpus.py tests/unit/testing/vision tests/privacy/vision && uv run mypy packages/testing/src && make verify-private-data`
Expected: PASS; repeat generation has identical hashes; committed bytes contain no configured household/private-data sentinel.

- [ ] **Step 5: Commit**

~~~bash
git add packages/testing/src/tuntun_testing/vision scripts/phase3/build_media_corpus.py fixtures/synthetic/vision/media-manifest.json fixtures/adversarial/vision/event-cases.json tests/unit/testing/vision tests/privacy/vision/test_synthetic_only.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(vision): add synthetic media and fault fakes"
~~~

### Task 03: Persist camera policy, ingress/alert delivery, canonical zones, and current-only presence

**Depends on:** Tasks 01–02 and accepted Phase 2 topology migrations.
**Gate contribution:** P3-E0.
**Estimated effort:** 2 person-days.

**Files:**
- Create: `apps/core/migrations/versions/0013_camera_policy.py`
- Create: `apps/core/migrations/versions/0014_camera_alerts.py`
- Create: `apps/core/migrations/versions/0015_presence_checkpoint.py`
- Create: `apps/core/src/tuntun_core/domain/vision/commissioning.py`
- Create: `apps/core/src/tuntun_core/domain/vision/zones.py`
- Create: `apps/core/src/tuntun_core/domain/vision/event_delivery.py`
- Create: `apps/core/src/tuntun_core/domain/vision/alerts.py`
- Create: `apps/core/src/tuntun_core/domain/vision/presence.py`
- Modify: `apps/core/src/tuntun_core/adapters/sqlcipher/models.py`
- Create: `apps/core/src/tuntun_core/adapters/sqlcipher/vision_repository.py`
- Create: `apps/core/src/tuntun_core/services/transactions/vision_uow.py`
- Modify: `apps/core/src/tuntun_core/adapters/sqlcipher/async_unit_of_work.py`
- Test: `tests/integration/vision/test_core_vision_migrations.py`
- Test: `tests/integration/vision/test_core_phase2_phase3_graph.py`
- Test: `tests/integration/vision/test_vision_uow_registration.py`
- Test: `tests/unit/vision/test_zone_cas.py`
- Test: `tests/unit/vision/test_presence_checkpoint_shape.py`

**Interfaces:** Consumes the shared serialized `UnitOfWork`, `TopologyRegistryPort`, exact current `CanonicalLocationRefV1`, Phase 1 audit outbox, policy version, and action-grant primitives. Produces the exact core revisions `0013_camera_policy(down=0012_screen_time)`, `0014_camera_alerts(down=0013_camera_policy)`, and `0015_presence_checkpoint(down=0014_camera_alerts)`, plus the canonical SQLCipher implementations in `vision_repository.py`, their typed `VisionUnitOfWork` view in `services/transactions/vision_uow.py`, and explicit registration on the existing `AsyncUnitOfWork`—not a parallel database/session abstraction. That registered view exposes `CameraPolicyRepository`, `CameraZoneRepository.compare_and_swap`, `CameraEventIngressStore.claim_sequence_dedupe_and_enqueue_once`, `AlertPolicyRepository`, `AlertInboxRepository`, `PresenceCheckpointRepository.replace_and_enqueue_once`, the presence-publisher cursor/outbox, and the durable home-policy presence consumer cursor. It stores the adjacent `(area_id, area_generation)` pair wherever location affects authority. Ingress/outbox rows contain only the minimum closed observation fields and commitments needed to resume registered alert/presence delivery—never a raw media body or an extensible event blob—and no table relates to profiles, identity, memory, conversations, or HA entities. The optional search feature is inspected through exact version table `alembic_version_experimental_search` and never enters the core graph.

- [ ] **Step 1: Write red migration, cross-area substitution, and no-history tests**

~~~python
async def test_zone_update_rejects_area_or_binding_substitution(repos, commissioned_zone) -> None:
    for mutation in ({"area_id": "area_other_synth"}, {"area_generation": commissioned_zone.area_generation + 1}):
        edited = commissioned_zone.model_copy(update=mutation)
        with pytest.raises(ZoneConflict, match="zone_binding_mismatch"):
            async with repos.serialized_uow() as uow:
                await repos.zones.compare_and_swap(
                    edited,
                    expected_generation=commissioned_zone.zone_generation,
                    uow=uow,
                )

async def test_presence_repository_has_one_current_row_and_no_history(db, repos) -> None:
    await repos.presence.replace_current(occupied_checkpoint(version=1))
    await repos.presence.replace_current(unknown_checkpoint(version=2))
    assert await db.scalar("select count(*) from presence_checkpoints") == 1
    assert not await db.table_exists("presence_history")

async def test_migrations_own_every_declared_crash_safe_cursor_receipt_and_outbox(db) -> None:
    assert await db.tables_owned_by("0014_camera_alerts") >= {
        "camera_event_ingress_cursors",
        "camera_event_ingress_receipts",
        "camera_event_dispatch_outbox",
        "camera_alert_inbox",
        "camera_alert_delivery_receipts",
    }
    assert await db.tables_owned_by("0015_presence_checkpoint") >= {
        "presence_checkpoints",
        "presence_evidence_receipts",
        "presence_publisher_cursors",
        "presence_event_outbox",
        "presence_home_consumer_cursors",
    }
    await db.assert_unique_key(
        "camera_event_ingress_cursors", ("source_endpoint_id", "source_generation"),
    )
    await db.assert_unique_key(
        "presence_publisher_cursors", ("source_endpoint_id", "source_generation"),
    )
    await db.assert_unique_key(
        "presence_home_consumer_cursors",
        ("consumer_id", "source_endpoint_id", "source_generation"),
    )

@pytest.mark.parametrize("search_enabled", [False, True])
async def test_phase3_extends_one_linear_core_head_without_search_namespace_fork(database_factory, search_enabled) -> None:
    db = await database_factory(search_enabled=search_enabled)
    graph = await inspect_migration_graph(db, version_table="alembic_version")
    assert graph.edges_through("0015_presence_checkpoint")[-3:] == (
        ("0012_screen_time", "0013_camera_policy"),
        ("0013_camera_policy", "0014_camera_alerts"),
        ("0014_camera_alerts", "0015_presence_checkpoint"),
    )
    assert graph.heads == ("0015_presence_checkpoint",)
    assert not graph.branches_or_merges_or_orphans
    search = await inspect_migration_graph(db, version_table="alembic_version_experimental_search")
    assert search.heads == (("search_0001_experimental_search",) if search_enabled else ())

async def test_area_reclassification_invalidates_zone_and_presence_through_restart_restore(system) -> None:
    stale = await system.commission_area_camera(area_generation=4)
    await system.topology.reclassify(stale.area_id, expected_generation=4)
    for runtime in (system, await system.restart(), await system.restore_from_backup()):
        with pytest.raises(ZoneConflict, match="area_generation_stale"):
            async with runtime.serialized_uow() as uow:
                await runtime.zones.compare_and_swap(
                    stale.zone,
                    expected_generation=stale.zone.zone_generation,
                    uow=uow,
                )
        assert await runtime.presence.current(stale.location) == "unknown"
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/vision/test_core_vision_migrations.py tests/integration/vision/test_core_phase2_phase3_graph.py tests/integration/vision/test_vision_uow_registration.py tests/unit/vision/test_zone_cas.py tests/unit/vision/test_presence_checkpoint_shape.py -q`
Expected: FAIL because revision `0013_camera_policy` and vision repositories are absent.

- [ ] **Step 3: Implement encrypted migrations, database constraints, and repository CAS**

~~~python
async def compare_and_swap(self, candidate: CameraZoneV1, expected_generation: int, uow: UnitOfWork) -> CameraZoneV1:
    current = await self.get_for_update(candidate.zone_id, uow)
    if current.zone_generation != expected_generation:
        raise ZoneConflict("zone_generation_stale")
    current_area = await self._topology.require_current_area(candidate.area_id, uow)
    candidate_binding = (
        candidate.area_id, candidate.area_generation,
        candidate.camera_binding_id, candidate.camera_binding_generation,
    )
    if candidate_binding != (
        current.area_id, current.area_generation,
        current.camera_binding_id, current.camera_binding_generation,
    ) or (candidate.area_id, candidate.area_generation) != (current_area.area_id, current_area.generation):
        raise ZoneConflict("zone_binding_mismatch")
    next_zone = candidate.model_copy(update={"zone_generation": current.zone_generation + 1})
    await self._write_and_invalidate_dependents(next_zone, uow)
    return next_zone
~~~

Add SQL constraints/triggers for one active binding, unique current zone version, distinct alert policy scope, alert queue expiry, one monotonic ingress cursor per source generation, unique event-ID and deduplication-commitment receipts, one dispatch row per `(event_id, registered_consumer)`, one presence row per exact `(area_id, area_generation)`, `valid_until > observed_at`, camera-only occupied/count unknown, unique evidence receipt, one monotonic presence publisher cursor, one event outbox row per emitted event, one monotonic home-policy consumer cursor, and deletion on expiry. Cursor/receipt/outbox mutations share the same serializable unit of work as their owning effect; a crash cannot leave a claimed sequence or accepted observation without a dispatchable row. Reclassification invalidates dependent current rows atomically. Migration tests inspect every column and foreign key to prove forbidden full-event/media/profile/path/name/address fields are absent, inventory every core edge and head with search absent and enabled, and prove search remains isolated in `alembic_version_experimental_search`.

- [ ] **Step 4: Run green, forward/restart, and downgrade-isolation checks**

Run: `uv run pytest tests/integration/vision/test_core_vision_migrations.py tests/integration/vision/test_core_phase2_phase3_graph.py tests/integration/vision/test_vision_uow_registration.py tests/unit/vision/test_zone_cas.py tests/unit/vision/test_presence_checkpoint_shape.py -q && uv run alembic upgrade head && uv run python scripts/check_migration_ownership.py --revisions 0013 0014 0015 --exact-head 0015_presence_checkpoint --forbid-branch-merge-orphan && uv run ruff check apps/core/migrations/versions/0013_camera_policy.py apps/core/migrations/versions/0014_camera_alerts.py apps/core/migrations/versions/0015_presence_checkpoint.py apps/core/src/tuntun_core/domain/vision apps/core/src/tuntun_core/adapters/sqlcipher/vision_repository.py apps/core/src/tuntun_core/services/transactions/vision_uow.py apps/core/src/tuntun_core/adapters/sqlcipher/async_unit_of_work.py tests/integration/vision tests/unit/vision && uv run mypy apps/core/src`
Expected: PASS; exact parent/head inspection reports one linear core graph and isolated optional-search graph, every promised cursor/receipt/outbox has one migration owner, no forbidden column exists, and restart/restore preserves only current-generation state and undelivered minimized work.

- [ ] **Step 5: Commit**

~~~bash
git add apps/core/migrations/versions/0013_camera_policy.py apps/core/migrations/versions/0014_camera_alerts.py apps/core/migrations/versions/0015_presence_checkpoint.py apps/core/src/tuntun_core/domain/vision apps/core/src/tuntun_core/adapters/sqlcipher/models.py apps/core/src/tuntun_core/adapters/sqlcipher/vision_repository.py apps/core/src/tuntun_core/services/transactions/vision_uow.py apps/core/src/tuntun_core/adapters/sqlcipher/async_unit_of_work.py tests/integration/vision/test_core_vision_migrations.py tests/integration/vision/test_core_phase2_phase3_graph.py tests/integration/vision/test_vision_uow_registration.py tests/unit/vision/test_zone_cas.py tests/unit/vision/test_presence_checkpoint_shape.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(vision): persist camera policy and current presence"
~~~

### Task 04: Build the separate encrypted vision catalog and crash-safe media lifecycle

**Depends on:** Tasks 01–02.
**Gate contribution:** P3-E0/P3-1.
**Estimated effort:** 2 person-days.

**Files:**
- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Create: `apps/recorder/pyproject.toml`
- Create: `apps/recorder/src/tuntun_recorder/__init__.py`
- Create: `apps/recorder/src/tuntun_recorder/catalog/database.py`
- Create: `apps/recorder/src/tuntun_recorder/catalog/models.py`
- Create: `apps/recorder/src/tuntun_recorder/catalog/manifest.py`
- Create: `apps/recorder/src/tuntun_recorder/catalog/repository.py`
- Create: `apps/recorder/src/tuntun_recorder/catalog/migrations/0001_media_catalog.py`
- Create: `apps/recorder/src/tuntun_recorder/catalog/migrations/0002_media_operations.py`
- Create: `apps/recorder/src/tuntun_recorder/catalog/migrations/0003_measurement_health.py`
- Create: `apps/recorder/src/tuntun_recorder/recording/reconciliation.py`
- Test: `apps/recorder/tests/integration/test_catalog_migrations.py`
- Test: `apps/recorder/tests/integration/test_catalog_migration_graph.py`
- Test: `apps/recorder/tests/integration/test_media_commit_crash.py`
- Test: `apps/recorder/tests/security/test_catalog_schema_isolation.py`
- Test: `tests/unit/vision/test_recorder_package_bootstrap.py`

**Interfaces:** This is the first owner of the standalone `tuntun-recorder` distribution. It registers exact workspace member `apps/recorder` once, uses the foundation Python/Hatchling/version conventions, exposes `tuntun_recorder.__version__: str = "0.1.0.dev0"`, and regenerates the root `uv.lock`. Its direct workspace dependency is `tuntun-contracts`; add only third-party libraries actually imported by recorder code and reuse their existing root constraints. The recorder may import contracts but never `tuntun_core` or `tuntun_reolink`; a later one-way dependency on leaf package `tuntun-secure-archive` is owned only by Task 18. Produces `VisionCatalog` implementing `VisionCatalogPort`, `CatalogMigrator.upgrade/downgrade`, exact recorder-local graph `0001_media_catalog(base) -> 0002_media_operations -> 0003_measurement_health` in `vision_catalog_alembic_version`, `MediaCommitter.commit(staged)`, durable per-source-generation camera-event publisher cursors and authenticated IPC outbox rows, authenticated `OpaqueMediaManifestV1` sidecars, and `CatalogReconciler.run_once(limit)`. The `0001_media_catalog` transaction can claim native-event dedupe, allocate the next publisher sequence, and enqueue the complete closed metadata-only event envelope without an unowned side database or in-memory cursor. Consumes a verified `VideoVolumeHandle` and a dedicated catalog-key handle; never uses the core/search version tables or opens the canonical database.

- [ ] **Step 1: Write red separate-key, opaque-name, and every-boundary crash tests**

~~~python
@pytest.mark.parametrize("fault", ["during_segment_write", "after_fsync_before_catalog", "after_catalog_commit", "after_publish_before_receipt"])
async def test_media_commit_recovers_without_false_playable_state(catalog_fixture, fault) -> None:
    catalog_fixture.faults.arm(fault)
    with pytest.raises(InjectedVisionFault):
        await catalog_fixture.commit_one()
    await catalog_fixture.restart_and_reconcile()
    assert await catalog_fixture.assert_no_false_playable_or_orphan()

async def test_catalog_key_cannot_open_core_database(catalog_fixture) -> None:
    with pytest.raises(DatabaseError):
        await catalog_fixture.open_core_with_catalog_key()

async def test_base_catalog_migration_owns_camera_event_publisher_and_outbox(catalog) -> None:
    assert await catalog.tables_owned_by("0001_media_catalog") >= {
        "native_events", "camera_event_publishers", "camera_event_ipc_outbox",
    }
    await catalog.assert_unique_key(
        "camera_event_publishers", ("source_endpoint_id", "source_generation"),
    )
    assert await catalog.forbidden_columns("camera_event_ipc_outbox") == set()

async def test_catalog_graph_has_exact_edges_one_head_and_restart_downgrade(catalog_factory) -> None:
    catalog = await catalog_factory()
    await catalog.migrator.upgrade("0003_measurement_health")
    graph = await catalog.migrator.inspect_graph()
    assert graph.version_table == "vision_catalog_alembic_version"
    assert graph.edges == (
        (None, "0001_media_catalog"),
        ("0001_media_catalog", "0002_media_operations"),
        ("0002_media_operations", "0003_measurement_health"),
    )
    assert graph.heads == ("0003_measurement_health",)
    assert not graph.branches_or_merges_or_orphans
    restarted = await catalog.restart()
    assert await restarted.migrator.current() == "0003_measurement_health"
    await restarted.migrator.downgrade("0002_media_operations")
    assert await restarted.migrator.current() == "0002_media_operations"
    await restarted.migrator.upgrade("0003_measurement_health")
    assert await restarted.migrator.current() == "0003_measurement_health"

def test_recorder_is_an_importable_one_way_workspace_member() -> None:
    root = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    package = tomllib.loads(Path("apps/recorder/pyproject.toml").read_text(encoding="utf-8"))
    members = root["tool"]["uv"]["workspace"]["members"]
    dependencies = tuple(package["project"].get("dependencies", ()))
    sources = set(package["tool"]["uv"]["sources"])
    assert members.count("apps/recorder") == 1
    assert package["project"]["name"] == "tuntun-recorder"
    assert importlib.import_module("tuntun_recorder").__version__ == "0.1.0.dev0"
    assert any(value.startswith("tuntun-contracts") for value in dependencies)
    assert {"tuntun-contracts"} <= sources <= {
        "tuntun-contracts", "tuntun-secure-archive",
    }
    assert not any(value.startswith(("tuntun-core", "tuntun-reolink")) for value in dependencies)
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/vision/test_recorder_package_bootstrap.py apps/recorder/tests/integration/test_catalog_migrations.py apps/recorder/tests/integration/test_catalog_migration_graph.py apps/recorder/tests/integration/test_media_commit_crash.py apps/recorder/tests/security/test_catalog_schema_isolation.py -q`
Expected: FAIL because `apps/recorder/pyproject.toml`, workspace membership, and `tuntun_recorder.catalog` are absent.

- [ ] **Step 3: Implement the catalog, fsync/rename protocol, and bounded reconciliation**

~~~python
async def commit(self, staged: StagedSegment) -> SegmentV1:
    staged_path = self._volume.require_staging_path(staged.staging_token)
    digest, byte_count = await self._files.sha256_and_size(staged_path)
    if (digest, byte_count) != (staged.sha256, staged.byte_count):
        raise MediaCommitRejected("staged_segment_digest_or_size_mismatch")
    token = OpaqueStorageToken.random()
    row = await self._catalog.insert_catalog_committed(staged.to_row(token, digest, byte_count))
    manifest: OpaqueMediaManifestV1 = self._manifests.build_authenticated(
        row=row, token=token, manifest_generation=row.catalog_generation,
    )
    await self._manifests.write_verified(manifest)
    await self._files.atomic_publish_and_fsync_parent(staged_path, self._volume.media_path(token))
    return await self._catalog.mark_published(row.segment_id)
~~~

All queries are bounded and use opaque tokens. Set the recorder catalog migrator's version table explicitly to `vision_catalog_alembic_version`; each revision has the exact parent above, and startup rejects any branch, merge, orphan, extra head, unknown revision, or collision with the core/search version mechanisms before opening media. Each published media object has a separately opaque, HMAC-authenticated `OpaqueMediaManifestV1` containing only schema version, token, media digest/size, source/binding/generation, exact area/area-generation and zone/generation where applicable, stream/clip/event metadata, immutable expiry, and catalog transaction ID—never a human name, address, credential, absolute path, or identity. Its only state is `rebuild_only_not_playback_authority`: the writer and reconciler revalidate the canonical HMAC, storage token, exact catalog/source/capability/profile/eligibility/volume/location generations, digest, size, retention, and catalog transaction against live rows before use, and only the catalog `PUBLISHED` transition makes bytes playable. Reconciliation handles only declared lifecycle states, checks path containment and digest before publication, marks uncertain media unavailable, and never searches by camera-supplied filename. Apply SQLCipher, WAL, `synchronous=FULL`, `foreign_keys=ON`, file `0600`, directory `0700`, and the separate migration lock.

Bootstrap the distribution before implementing catalog modules: merge `apps/recorder` into `[tool.uv.workspace].members` without replacing earlier members; set package name/version/Python/build backend to `tuntun-recorder`/`0.1.0.dev0`/`==3.12.*`/the foundation Hatchling range; declare `tuntun-contracts` with `{ workspace = true }`; and keep test-only helpers out of runtime dependencies. The permanent bootstrap test parses both TOML files, rejects duplicate members and forbidden app/integration dependencies, imports the installed package, and therefore continues to protect this boundary after later tasks extend recorder code.

- [ ] **Step 4: Run green and forbidden-schema scan**

Run:

~~~bash
uv lock
uv sync --all-packages --locked
uv run --locked --offline --no-sync python -c 'import tuntun_recorder; assert tuntun_recorder.__version__ == "0.1.0.dev0"'
uv run --locked --offline --no-sync pytest tests/unit/vision/test_recorder_package_bootstrap.py apps/recorder/tests/integration/test_catalog_migrations.py apps/recorder/tests/integration/test_catalog_migration_graph.py apps/recorder/tests/integration/test_media_commit_crash.py apps/recorder/tests/security/test_catalog_schema_isolation.py -q
uv run --locked --offline --no-sync ruff check apps/recorder/src/tuntun_recorder/catalog apps/recorder/src/tuntun_recorder/recording/reconciliation.py apps/recorder/tests tests/unit/vision/test_recorder_package_bootstrap.py
uv run --locked --offline --no-sync mypy apps/recorder/src
uv run --locked --offline --no-sync python scripts/scan_sql_schema.py --db-kind vision --forbid profile,identity,memory,conversation,credential,ip,mac,path,filename
uv lock --check
uv build --offline --wheel --package tuntun-recorder --out-dir var/build-smoke/phase3/recorder
uv lock --check
~~~

Expected: PASS; the separate catalog has one exact head, `0001_media_catalog` owns the promised camera-event publisher cursor/outbox, and restart/downgrade/re-upgrade preserves ownership while each crash settles into one playable exact file or one unavailable/tombstoned row, never an orphan or false claim.

- [ ] **Step 5: Commit**

~~~bash
git add pyproject.toml uv.lock apps/recorder/pyproject.toml apps/recorder/src/tuntun_recorder/__init__.py apps/recorder/src/tuntun_recorder/catalog apps/recorder/src/tuntun_recorder/recording/reconciliation.py apps/recorder/tests/integration/test_catalog_migrations.py apps/recorder/tests/integration/test_catalog_migration_graph.py apps/recorder/tests/integration/test_media_commit_crash.py apps/recorder/tests/security/test_catalog_schema_isolation.py tests/unit/vision/test_recorder_package_bootstrap.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(recorder): add isolated encrypted vision catalog"
~~~

### Task 05: Enforce process, IPC, dependency, and selected-frame absence boundaries

**Depends on:** Tasks 01–04.
**Gate contribution:** P3-E0.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `apps/recorder/src/tuntun_recorder/ipc/envelope.py`
- Create: `apps/recorder/src/tuntun_recorder/ipc/peer.py`
- Create: `apps/recorder/src/tuntun_recorder/ipc/client.py`
- Create: `apps/recorder/src/tuntun_recorder/ipc/server.py`
- Create: `apps/recorder/src/tuntun_recorder/config.py`
- Modify: `apps/core/src/tuntun_core/services/features/registry.py`
- Create: `tests/contract/vision/test_ipc_boundary.py`
- Create: `tests/security/vision/test_process_import_boundary.py`
- Create: `tests/security/vision/test_selected_frame_absent.py`
- Create: `tests/security/vision/test_vision_feature_absence.py`

**Interfaces:** Produces authenticated bounded `VisionIpcEnvelopeV1` framing across the closed five-process `core`/`camera_source`/`recorder`/`media_proxy`/`owner_ingress` peer registry and exact message-direction matrix, `DarwinPeerCredentialVerifier`, video-to-core `CameraOutcomePort` client, and closed clients for recorder start/control, clip/segment queries, recorder-owned playback-grant register/claim, export/delete request/receipt, and owner-ingress pre-session/core-derived-session exchange. After that exchange, `owner_ingress` uses the separate session-bound `AuthenticatedOwnerIngressRequestV1` peer-auth UDS protocol defined in Task 01; core and media proxy reject direct network requests, missing/stale session derivations, and unauthenticated/raw proxy headers. It also produces feature IDs `camera_storage`, `camera_alerts`, `anonymous_presence`, and `selected_frame_perception`. Only accepted features register routes; selected-frame remains `absent`.

- [ ] **Step 1: Write red peer, oversize, forbidden-import, and negative-reachability tests**

~~~python
def test_wrong_uid_or_schema_is_rejected_before_body_dispatch(ipc_server) -> None:
    with pytest.raises(IpcRejected, match="peer_not_authorized"):
        ipc_server.accept(fake_peer(uid=99999), valid_health_envelope())

def test_phase3_has_no_selected_frame_runtime(feature_app) -> None:
    assert feature_app.manifest.state("selected_frame_perception") == "absent"
    assert feature_app.route("/api/v1/cameras/selected-frames") is None
    assert not feature_app.container.can_resolve("SelectedFrameVisionPort")
    assert "cv2" not in installed_runtime_modules("apps/recorder")

def test_only_owner_ingress_is_network_facing(process_matrix) -> None:
    assert process_matrix.processes == {"core", "camera_source", "recorder", "media_proxy", "owner_ingress"}
    assert process_matrix.tcp_listeners("core") == ()
    assert process_matrix.tcp_listeners("media_proxy") == ()
    assert process_matrix.tcp_listeners("owner_ingress") == (("127.0.0.1", 8787),)

async def test_ipc_body_caps_admit_bounded_pre_session_but_not_large_metadata(ipc_client) -> None:
    raw_body = b"x" * (1024 * 1024)
    await ipc_client.round_trip(owner_pre_session_request(raw_body))
    with pytest.raises(IpcRejected, match="ipc_message_body_limit_rejected"):
        await ipc_client.send(ordinary_health_envelope_wire_size(64 * 1024 + 1))
    with pytest.raises(IpcRejected, match="ipc_header_rejected"):
        await ipc_client.send_header(body_len=2 * 1024 * 1024 + 1)
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/vision/test_ipc_boundary.py tests/security/vision/test_process_import_boundary.py tests/security/vision/test_selected_frame_absent.py tests/security/vision/test_vision_feature_absence.py -q`
Expected: FAIL because IPC and Phase 3 feature declarations do not exist.

- [ ] **Step 3: Implement length-prefixed IPC, peer checks, import rules, and fail-closed feature registration**

~~~python
HEADER = struct.Struct("!4sHII")
MAGIC = b"TVI1"
MAX_ENVELOPE_BODY = 2 * 1024 * 1024
MAX_ORDINARY_MESSAGE_BODY = 64 * 1024
LARGE_BOUNDED_MESSAGE_TYPES = frozenset({
    "owner_pre_session_request", "owner_pre_session_result",
})

async def receive(
    reader: asyncio.StreamReader, peer: PeerIdentity,
) -> VisionIpcEnvelopeV1[VisionIpcPayloadV1]:
    raw = await reader.readexactly(HEADER.size)
    magic, version, body_len, sequence = HEADER.unpack(raw)
    if magic != MAGIC or version != 1 or body_len > MAX_ENVELOPE_BODY:
        raise IpcRejected("ipc_header_rejected")
    await peer_verifier.require_registered(peer)
    body = await asyncio.wait_for(reader.readexactly(body_len), timeout=1.0)
    wire = reject_duplicate_keys(body)
    message_type = require_closed_ipc_message_type(wire)
    if message_type not in LARGE_BOUNDED_MESSAGE_TYPES and body_len > MAX_ORDINARY_MESSAGE_BODY:
        raise IpcRejected("ipc_message_body_limit_rejected")
    envelope = IPC_ENVELOPE_ADAPTERS[message_type].validate_python(wire)
    if envelope.sequence != sequence:
        raise IpcRejected("ipc_header_body_sequence_mismatch")
    await peer_verifier.verify_and_claim_once(
        peer=peer,
        envelope=envelope,
        actual_payload_digest=sha256(canonical_contract_bytes(envelope.payload)).hexdigest(),
        now=trusted_clock.now(),
    )
    return envelope
~~~

`IPC_ENVELOPE_ADAPTERS` is an exhaustive map from the closed message enum to an exact `VisionIpcEnvelopeV1[PayloadModel]` specialization; route peeking selects a validator but grants no authority. `verify_and_claim_once` calls `validate_vision_ipc_envelope_binding` and atomically verifies the canonical payload digest/HMAC, both live process-registration generations, direction, header/body sequence, deadline, and unused envelope ID before advancing the peer sequence. The global 2 MiB allocation ceiling exists only so the two pre-session message types can carry their DTO-enforced at-most-1 MiB raw body after base64/JSON framing; every other metadata message remains capped at 64 KiB after route peeking, and the exact DTO is still validated before dispatch. Add a dependency-rule check: `apps/recorder` and `integrations/reolink` may import contracts/testing only, never core internals; core vision modules never import recorder/reolink internals. IPC sockets are `0600` in owner-only runtime directories. No frame/media bytes are accepted on the metadata channel.

- [ ] **Step 4: Run green, route/package absence, and import graph checks**

Run: `uv run pytest tests/contract/vision/test_ipc_boundary.py tests/security/vision/test_process_import_boundary.py tests/security/vision/test_selected_frame_absent.py tests/security/vision/test_vision_feature_absence.py -q && uv run python scripts/check_import_boundaries.py --domain vision && uv run python scripts/check_feature_absence.py --feature selected_frame_perception --phase 3 && uv run ruff check apps/recorder/src/tuntun_recorder/ipc apps/recorder/src/tuntun_recorder/config.py apps/core/src/tuntun_core/services/features/registry.py tests/contract/vision tests/security/vision && uv run mypy apps/recorder/src apps/core/src`
Expected: PASS; selected-frame route/API/config/container/dependency/client bundle is absent while its schema files remain available for Phase 5.

- [ ] **Step 5: Commit**

~~~bash
git add apps/recorder/src/tuntun_recorder/ipc apps/recorder/src/tuntun_recorder/config.py apps/core/src/tuntun_core/services/features/registry.py tests/contract/vision/test_ipc_boundary.py tests/security/vision/test_process_import_boundary.py tests/security/vision/test_selected_frame_absent.py tests/security/vision/test_vision_feature_absence.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "security(vision): isolate Phase 3 processes and absent seams"
~~~

## Wave 1 — P3-0 Inventory, Privacy, Source Eligibility, and SSD Gate

### Task 06: Implement immutable camera commissioning and canonical area/zone policy

**Depends on:** Tasks 01, 03, and 05.
**Gate contribution:** P3-0.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/services/vision/commissioning.py`
- Create: `apps/core/src/tuntun_core/services/vision/privacy_policy.py`
- Create: `apps/core/src/tuntun_core/services/vision/projections.py`
- Create: `scripts/phase3/inventory_cameras.py`
- Create: `docs/operations/phase3-camera-commissioning.md`
- Create: `docs/privacy/phase3-camera-data.md`
- Test: `tests/unit/vision/test_commissioning_service.py`
- Test: `tests/integration/vision/test_commissioning_invalidation.py`
- Test: `tests/security/vision/test_prohibited_area_registration.py`

**Interfaces:** Consumes owner-prepared mutation/passkey grants, Phase 2 `TopologyRegistryPort`, exact `CanonicalLocationRefV1`, current privacy generation, camera probe digests, and content-safe evidence digests. Produces `CameraCommissioningService.prepare/approve/disable`, immutable `CameraCommissioningGeneration`, `AreaCameraPrivacyPolicy`, and owner-safe inventory projections. It never accepts a room display label where the exact `(area_id, area_generation)` authority is required.

- [ ] **Step 1: Write red exact-scope, prohibited-area, and drift invalidation tests**

~~~python
async def test_approve_binds_exact_unit_area_zones_copies_and_evidence(service, owner_passkey) -> None:
    prepared = await service.prepare(synthetic_trackmix_commissioning())
    receipt = await service.approve(prepared.id, owner_passkey.for_binding(prepared.binding))
    assert receipt.camera_binding_generation == 1
    assert (receipt.area_id, receipt.area_generation) == ("area_common_synth_01", 4)
    assert receipt.zone_generations == {"zone_boundary_synth_01": 1}

@pytest.mark.parametrize("room_class", ["adult_private", "child_private", "prohibited", "unknown"])
async def test_imaging_camera_registration_rejects_non_common_area(service, room_class) -> None:
    with pytest.raises(PolicyDenied, match="camera_area_prohibited"):
        await service.prepare(camera_request(area=area_fixture(room_class=room_class)))

async def test_orientation_change_revokes_all_dependent_routes(service, commissioned_camera) -> None:
    await service.record_capability_drift(commissioned_camera.id, reason="orientation_changed")
    assert await service.lifecycle(commissioned_camera.id) == "quarantined"
    assert await service.dependent_states(commissioned_camera.id) == {
        "recording": "disabled", "alerts": "disabled", "presence": "disabled", "playback": "disabled",
    }

async def test_area_reclassification_revokes_camera_routes_immediately_and_after_restart_restore(system) -> None:
    camera = await system.commission(area_generation=4)
    await system.topology.reclassify(camera.area_id, expected_generation=4)
    for runtime in (system, await system.restart(), await system.restore_from_backup()):
        assert await runtime.dependent_states(camera.id) == {
            "recording": "disabled", "alerts": "disabled", "presence": "disabled", "playback": "disabled",
        }
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/vision/test_commissioning_service.py tests/integration/vision/test_commissioning_invalidation.py tests/security/vision/test_prohibited_area_registration.py -q`
Expected: FAIL because `CameraCommissioningService` is absent.

- [ ] **Step 3: Implement the commissioning state machine and owner evidence capture**

~~~python
class CameraCommissioningService:
    async def approve(self, prepared_id: UUID, grant: ActionGrant) -> CommissioningReceipt:
        async with self._uow.serialized() as uow:
            prepared = await self._prepared.require_current(prepared_id, uow)
            grant.require_exact_binding(prepared.binding)
            area = await self._topology.require_current_area(prepared.area_id, uow)
            if area.generation != prepared.area_generation:
                raise PolicyDenied("camera_area_generation_stale")
            if area.room_class != "common":
                raise PolicyDenied("camera_area_prohibited")
            self._validator.require_exact_evidence(prepared)
            generation = await self._repo.install_generation(prepared, uow)
            await self._audit.append_commitment("camera.commission.approve", generation.commitment(), uow)
            await self._grants.consume(grant, uow)
            return generation.to_receipt()
~~~

The inventory command records three distinct pseudonymous physical records with exact model/revision/firmware/config, source protocols, stream roles/codecs/rates, native event classes, audio controls, microSD/vendor/cloud copies, reset/update behavior, simultaneous-stream limit, placement/visible-field commitments, canonical `(area_id, area_generation)`, versioned zones, notice state, source/capability/policy generations, and evidence digest. It writes no raw frame: the owner reviews a live local sample outside evidence, and the record retains only its digest plus pass/fail. Firmware, reset, source path, orientation, mount, privilege-changing credential rotation, area reclassification, zone mutation, or capability drift increments the generation and atomically disables downstream eligibility; restart/restore never resurrects a stale area generation.

- [ ] **Step 4: Run green and owner-evidence dry run**

Run: `uv run pytest tests/unit/vision/test_commissioning_service.py tests/integration/vision/test_commissioning_invalidation.py tests/security/vision/test_prohibited_area_registration.py -q && uv run python scripts/phase3/inventory_cameras.py --synthetic --output var/evidence/phase3/synthetic-inventory.json && uv run python scripts/verify_private_data.py var/evidence/phase3/synthetic-inventory.json && uv run ruff check apps/core/src/tuntun_core/services/vision scripts/phase3/inventory_cameras.py tests/unit/vision tests/integration/vision tests/security/vision && uv run mypy apps/core/src`
Expected: PASS; synthetic evidence has exactly three distinct units/placements and no raw/private identifier.

- [ ] **Step 5: Commit**

~~~bash
git add apps/core/src/tuntun_core/services/vision/commissioning.py apps/core/src/tuntun_core/services/vision/privacy_policy.py apps/core/src/tuntun_core/services/vision/projections.py scripts/phase3/inventory_cameras.py docs/operations/phase3-camera-commissioning.md docs/privacy/phase3-camera-data.md tests/unit/vision/test_commissioning_service.py tests/integration/vision/test_commissioning_invalidation.py tests/security/vision/test_prohibited_area_registration.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(vision): add camera commissioning policy"
~~~

### Task 07: Prove vendor egress fail-closed and constrain local source destinations

**Depends on:** Tasks 05–06.
**Gate contribution:** P3-0, `T05`/`T14`.
**Estimated effort:** 1.5 person-days plus owner network observation.

**Files:**
- Create: `apps/recorder/src/tuntun_recorder/source/eligibility.py`
- Create: `apps/recorder/src/tuntun_recorder/source/credentials.py`
- Create: `scripts/phase3/verify_camera_egress.py`
- Create: `fixtures/synthetic/vision/network/blocked-flows.json`
- Create: `docs/operations/phase3-network-egress.md`
- Test: `apps/recorder/tests/unit/test_source_eligibility.py`
- Test: `tests/security/vision/test_camera_destination_guard.py`
- Test: `tests/security/vision/test_camera_egress_evidence.py`
- Test: `tests/security/vision/test_public_camera_surface.py`

**Interfaces:** Produces `CameraSourceEligibility.evaluate(evidence) -> EligibleLocalSource | IneligibleVendorNativeOnly`, `CameraDestinationGuard.open`, and a sanitized egress evidence receipt. Consumes exact commissioned binding generation, inner-LAN destination commitments, allowed local NTP endpoint where configured, device-side cloud/UID/P2P state, router-boundary capture digest, and credential-handle ID. The committed `blocked-flows.json` is a deterministic synthetic positive/negative flow-class oracle with generated endpoint commitments only; the verifier rejects missing, duplicate, unknown, over-limit, or contradictory rows.

- [ ] **Step 1: Write red fail-closed matrix and address-leak tests**

~~~python
@pytest.mark.parametrize(
    "unproved",
    ["control", "uid_p2p", "dns", "telemetry", "thumbnail", "audio", "raw_media", "wan_restore", "vendor_app_poll"],
)
def test_any_unproved_outbound_class_makes_source_vendor_native_only(eligibility, evidence, unproved) -> None:
    evidence = mutate_egress_case_and_recompute_state(evidence, unproved, "unverified")
    assert eligibility.evaluate(evidence).source_path == "vendor_native_only"

def test_destination_guard_denies_dns_public_and_uncommissioned_targets(destination_guard) -> None:
    for target in [public_ip(), dns_name(), other_inner_client(), outer_router_address()]:
        with pytest.raises(NetworkDenied, match="camera_destination_not_compiled"):
            destination_guard.open(target)
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/recorder/tests/unit/test_source_eligibility.py tests/security/vision/test_camera_destination_guard.py tests/security/vision/test_camera_egress_evidence.py tests/security/vision/test_public_camera_surface.py -q`
Expected: FAIL because `CameraSourceEligibility` and the probe verifier are absent.

- [ ] **Step 3: Implement complete evidence evaluation and sanitized capture analysis**

~~~python
REQUIRED_EGRESS_CASES = REQUIRED_CAMERA_EGRESS_CASES

def evaluate(self, evidence: CameraEgressEvidenceV1) -> SourceDisposition:
    if (
        not evidence.observed_at <= self._clock.now() < evidence.valid_until
        or not self._live_bindings.matches_exact_egress_generations(evidence)
    ):
        return IneligibleVendorNativeOnly("camera_egress_generation_or_lifetime_stale")
    cases = {case.case_class: case for case in evidence.cases}
    if set(cases) != REQUIRED_EGRESS_CASES or evidence.evidence_state != "eligible_local_only":
        return IneligibleVendorNativeOnly("egress_cases_incomplete")
    if any(case.result != "verified_blocked_or_approved_local" for case in cases.values()):
        return IneligibleVendorNativeOnly("camera_egress_unverified")
    return EligibleLocalSource(
        evidence.camera_binding_generation, evidence.evidence_generation, evidence.capture_digest,
    )
~~~

The owner runbook first disables every available cloud/UID/P2P/push/email/FTP/telemetry/remote option, then applies an exact network-boundary block if device controls are insufficient. It observes boot, repeated retry, WAN restoration, DNS, time/update lookup, and vendor-app polling. Raw capture files remain under `$TUNTUN_OWNER_CAPTURE_ROOT` with owner-only permissions; the script emits only pseudonymous flow classes, counts, time bounds, rule/config digest, capture digest, and pass/fail. A missing switch is not a waiver. The source process resolves no DNS and opens only compiled local numeric endpoints; credential material stays in Keychain handles and sanitized errors.

- [ ] **Step 4: Run green, synthetic PCAP oracle, and local listener scan**

Run: `uv run pytest apps/recorder/tests/unit/test_source_eligibility.py tests/security/vision/test_camera_destination_guard.py tests/security/vision/test_camera_egress_evidence.py tests/security/vision/test_public_camera_surface.py -q && uv run python scripts/phase3/verify_camera_egress.py --synthetic fixtures/synthetic/vision/network/blocked-flows.json --output var/evidence/phase3/synthetic-egress.json && uv run python scripts/verify_private_data.py var/evidence/phase3/synthetic-egress.json && uv run ruff check apps/recorder/src/tuntun_recorder/source scripts/phase3/verify_camera_egress.py tests/security/vision apps/recorder/tests/unit && uv run mypy apps/recorder/src`
Expected: PASS; any public/unclassified flow yields `vendor_native_only` and no camera/RTSP/ONVIF/media listener is visible outside the approved local process boundary.

- [ ] **Step 5: Commit**

~~~bash
git add apps/recorder/src/tuntun_recorder/source/eligibility.py apps/recorder/src/tuntun_recorder/source/credentials.py scripts/phase3/verify_camera_egress.py fixtures/synthetic/vision/network/blocked-flows.json docs/operations/phase3-network-egress.md apps/recorder/tests/unit/test_source_eligibility.py tests/security/vision/test_camera_destination_guard.py tests/security/vision/test_camera_egress_evidence.py tests/security/vision/test_public_camera_surface.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "security(vision): fail closed on camera vendor egress"
~~~

### Task 08: Qualify the TrackMix hall and bedroom-pathway physical arc

**Depends on:** Tasks 06–07.
**Gate contribution:** P3-0 TrackMix privacy gate.
**Estimated effort:** 1 person-day plus owner day/night ceremonies.

**Files:**
- Create: `scripts/phase3/qualify_trackmix_arc.py`
- Create: `fixtures/synthetic/vision/evidence/trackmix-fixed-wide-pass.json`
- Create: `fixtures/synthetic/vision/evidence/trackmix-bedroom-visible-fail.json`
- Create: `docs/operations/phase3-trackmix-privacy.md`
- Create: `docs/evidence/phase3-trackmix-arc-schema.json`
- Test: `tests/contract/vision/test_trackmix_arc_evidence.py`
- Test: `tests/acceptance/vision/test_trackmix_arc_gate.py`
- Test: `tests/security/vision/test_tracking_absence_on_failure.py`

**Interfaces:** Produces a content-safe `TrackMixArcEvidenceV1` and one of `fixed_wide_eligible`, `digital_tracking_eligible`, `physical_tracking_eligible`, or `camera_excluded`. It consumes owner-observed live tests but persists only mode/reset/lighting/traversal counts, target visibility Boolean, control survival, timestamps, build/config digest, and evidence hashes. The two committed synthetic fixtures are canonical opposite oracles: one proves fixed-wide-only eligibility and one proves bedroom visibility forces exclusion; their contract tests reject any decision/row/count/digest drift.

- [ ] **Step 1: Write red minimum-traversal, every-mode/reset, and zero-visibility tests**

~~~python
def test_tracking_gate_requires_zero_prohibited_target_visibility(arc_evidence) -> None:
    failed = mutate_arc_trial_and_recompute_decision(
        arc_evidence, motion_mode="auto_tracking", prohibited_target_visible=True,
    )
    assert verify_trackmix_arc(failed).physical_tracking == "disabled"

def test_each_doorway_mode_and_reset_has_thirty_adversarial_traversals(arc_evidence) -> None:
    for doorway in arc_evidence.doorways:
        for mode in arc_evidence.enabled_motion_modes:
            for condition in arc_evidence.covered_conditions:
                trial = next(
                    trial
                    for trial in arc_evidence.trials
                    if trial.doorway == doorway
                    and trial.motion_mode == mode
                    and trial.condition == condition
                )
                assert trial.traversal_count >= 30
    under_tested = mutate_arc_trial_and_recompute_decision(
        arc_evidence,
        doorway=arc_evidence.doorways[0],
        motion_mode=arc_evidence.enabled_motion_modes[0],
        condition=arc_evidence.covered_conditions[0],
        traversal_count=29,
    )
    with pytest.raises(ValidationError):
        TrackMixArcEvidenceV1.model_validate(under_tested)
    assert set(arc_evidence.covered_conditions) == {
        "day", "infrared_night", "spotlight", "reboot", "power_loss",
        "calibration", "firmware", "monitor_point", "patrol", "manual_ptz",
    }
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/vision/test_trackmix_arc_evidence.py tests/acceptance/vision/test_trackmix_arc_gate.py tests/security/vision/test_tracking_absence_on_failure.py -q`
Expected: FAIL because the TrackMix arc schema/verifier is absent.

- [ ] **Step 3: Implement the ceremony, evidence verifier, and deterministic fallback**

~~~python
def decide_trackmix_mode(
    evidence: TrackMixArcEvidenceV1, live: CurrentTrackMixBinding, now: datetime,
) -> TrackMixModeDecision:
    if not evidence.qualified_at <= now < evidence.valid_until or not live.matches_exact_generations(evidence):
        return TrackMixModeDecision(camera="excluded", physical_tracking="disabled", digital_tracking="disabled")
    if evidence.decision == "camera_excluded":
        return TrackMixModeDecision(camera="excluded", physical_tracking="disabled", digital_tracking="disabled")
    if evidence.decision == "physical_tracking_eligible":
        return TrackMixModeDecision(camera="fixed_wide", physical_tracking="eligible", digital_tracking="eligible")
    if evidence.decision == "digital_tracking_eligible":
        return TrackMixModeDecision(camera="fixed_wide", physical_tracking="disabled", digital_tracking="eligible")
    return TrackMixModeDecision(camera="fixed_wide", physical_tracking="disabled", digital_tracking="disabled")
~~~

The runbook opens each bedroom door, places high-contrast privacy targets at threshold/deeper points, sweeps the complete manual arc, tests wide and tracking lenses independently, and performs at least 30 adversarial traversals per doorway/mode across the required lighting/reset states. Static privacy masks are evidence annotations only. Before this ceremony, patrol/auto-tracking/tracking recording are absent. Failure order is physical tracking off → proved fixed-guard digital tracking only → remount/physical field barrier → camera exclusion. Any mount/layout/firmware/calibration change invalidates the result.

- [ ] **Step 4: Run green and synthetic pass/fail evidence verification**

Run: `uv run pytest tests/contract/vision/test_trackmix_arc_evidence.py tests/acceptance/vision/test_trackmix_arc_gate.py tests/security/vision/test_tracking_absence_on_failure.py -q && uv run python scripts/phase3/qualify_trackmix_arc.py verify fixtures/synthetic/vision/evidence/trackmix-fixed-wide-pass.json && uv run python scripts/phase3/qualify_trackmix_arc.py verify fixtures/synthetic/vision/evidence/trackmix-bedroom-visible-fail.json && uv run ruff check scripts/phase3/qualify_trackmix_arc.py tests/contract/vision tests/acceptance/vision tests/security/vision`
Expected: PASS; the first fixture permits fixed-wide only and the second excludes the camera; no test can enable tracking from a static-mask claim.

- [ ] **Step 5: Commit**

~~~bash
git add scripts/phase3/qualify_trackmix_arc.py docs/operations/phase3-trackmix-privacy.md docs/evidence/phase3-trackmix-arc-schema.json tests/contract/vision/test_trackmix_arc_evidence.py tests/acceptance/vision/test_trackmix_arc_gate.py tests/security/vision/test_tracking_absence_on_failure.py fixtures/synthetic/vision/evidence/trackmix-fixed-wide-pass.json fixtures/synthetic/vision/evidence/trackmix-bedroom-visible-fail.json
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(vision): gate TrackMix hall privacy arc"
~~~

### Task 09: Implement exact-capability Reolink adapters and E1 deterministic fallback

**Depends on:** Tasks 01–02 and 06–08.
**Gate contribution:** P3-0/P3-1 source path.
**Estimated effort:** 2.5 person-days plus three physical probes.

**Files:**
- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Create: `integrations/reolink/pyproject.toml`
- Create: `integrations/reolink/src/tuntun_reolink/__init__.py`
- Create: `integrations/reolink/src/tuntun_reolink/adapter.py`
- Create: `integrations/reolink/src/tuntun_reolink/capabilities.py`
- Create: `integrations/reolink/src/tuntun_reolink/direct.py`
- Create: `integrations/reolink/src/tuntun_reolink/native_events.py`
- Create: `integrations/reolink/src/tuntun_reolink/bridge.py`
- Create: `integrations/reolink/src/tuntun_reolink/clock.py`
- Create: `integrations/reolink/src/tuntun_reolink/sanitized_errors.py`
- Create: `integrations/reolink/src/tuntun_reolink/entrypoint.py`
- Create: `apps/recorder/src/tuntun_recorder/source/service.py`
- Create: `apps/recorder/src/tuntun_recorder/source/relay.py`
- Create: `scripts/phase3/probe_reolink.py`
- Create: `fixtures/synthetic/vision/reolink-probe.json`
- Create: `docs/operations/phase3-e1-source-gate.md`
- Test: `integrations/reolink/tests/test_capability_probe.py`
- Test: `integrations/reolink/tests/test_direct_source.py`
- Test: `integrations/reolink/tests/test_native_events.py`
- Test: `integrations/reolink/tests/test_bridge_absence.py`
- Test: `tests/hardware/vision/test_reolink_units.py`
- Test: `tests/unit/vision/test_reolink_package_bootstrap.py`
- Test: `tests/unit/vision/test_camera_source_entrypoint.py`

**Interfaces:** This is the first owner of standalone distribution `tuntun-reolink`: register exact root workspace member `integrations/reolink` once, expose `tuntun_reolink.__version__: str = "0.1.0.dev0"`, and update the one root lock. Its only workspace dependency is `tuntun-contracts`; it may not depend on or import `tuntun-core` or `tuntun-recorder`. Composition with recorder occurs through the Task 05 contract/IPC boundary, not implementation imports. Its exact executable is `[project.scripts] tuntun-camera-source = tuntun_reolink.entrypoint:main`; `run(argv, runtime) -> int` is the injectable composition root used by tests. `--help`/`--version` have zero device/network/keychain/config effects; `start` verifies the provisioned camera-source effective UID and peer/config permissions before Keychain, camera, or socket access; `health` is bounded/read-only and reveals no endpoint or credential. Implements `CameraSourcePort` for positively proved direct local streams/native events and defines an unregistered bridge adapter for a future separately procured hub/NVR. Produces one `CameraCapabilityEvidenceV1` per physical unit and read-only low-wide/event-wide/conditional-event-tracking relays. It exposes no PTZ, talkback, microphone, snapshot, cloud, face, playback, or camera-administration operation. The committed Reolink probe fixture contains three generated physical-unit commitments and bounded pass/fail capability cases; the probe rejects missing units, family-name inference, duplicate commitments, unknown fields, and contradictory stream/event claims.

- [ ] **Step 1: Write red exact-unit and fallback tests**

~~~python
def test_marketing_family_name_cannot_enable_direct_source(adapter) -> None:
    evidence = adapter.classify(device_info={"product_family": "E1"})
    assert evidence.source_path == "inventory_only"
    assert evidence.direct_streams == ()

def test_two_e1_units_are_never_collapsed_by_model(adapter, e1a_probe, e1b_probe) -> None:
    a = adapter.probe_result(e1a_probe)
    b = adapter.probe_result(e1b_probe)
    assert a.physical_device_commitment != b.physical_device_commitment
    assert a.capability_digest != b.capability_digest

def test_tracking_event_view_requires_every_dual_view_gate(trackmix_probe) -> None:
    trackmix_probe.event_alignment_seconds = Decimal("2.001")
    assert decide_tracking_event_view(trackmix_probe) == "wide_only"

@pytest.mark.parametrize("mutation", [
    "expired", "replayed_request_id", "bad_authorization_commitment",
    "binding_substitution", "capability_substitution", "stream_role_substitution",
])
async def test_open_stream_authority_rejects_before_secret_or_relay_effect(
    adapter, open_stream_request, mutation,
) -> None:
    request = mutate_open_stream_authority(open_stream_request, mutation)
    with pytest.raises(StreamOpenRejected):
        await adapter.open_stream(request)
    assert adapter.keychain.open_count == 0
    assert adapter.relay.start_count == 0
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/vision/test_reolink_package_bootstrap.py tests/unit/vision/test_camera_source_entrypoint.py integrations/reolink/tests/test_capability_probe.py integrations/reolink/tests/test_direct_source.py integrations/reolink/tests/test_native_events.py integrations/reolink/tests/test_bridge_absence.py -q`
Expected: FAIL because the Reolink distribution, workspace member, and adapter are absent.

- [ ] **Step 3: Implement bounded probes, programmatic credential handling, and packet relays**

~~~python
async def open_stream(self, request: OpenCameraStreamV1) -> ReadOnlyMediaHandle:
    binding, capabilities = await self._stream_authority.verify_live_and_claim_once(
        request=request,
        now=self._clock.now(),
        eligibility=self._eligibility,
        capability_registry=self._capabilities,
    )
    capability = capabilities.require_stream(request.stream_role)
    secret = await self._keychain.open_handle(capability.credential_handle_id)
    relay = await self._relay.start_programmatic(
        numeric_local_endpoint=capability.endpoint,
        credential=secret,
        stream=capability.stream,
        reject_audio=True,
        max_bytes_per_second=capability.proved_peak_bytes_per_second,
    )
    return relay.read_only_handle_without_endpoint_or_secret(
        request=request, binding=binding, capability=capability,
    )
~~~

The request arrives only as the payload of a separately claimed `open_camera_stream` `VisionIpcEnvelopeV1[OpenCameraStreamV1]`. `verify_live_and_claim_once` then runs under the source authority lock: it verifies the canonical request authorization commitment, `single_use is True`, trusted `issued_at <= now < expires_at`, the unused request ID, current binding/capability generations and digest, and the requested proved stream role, then durably consumes the request ID before returning. A failure or concurrent replay occurs before Keychain access, camera connection, or relay allocation. Use programmatic PyAV/libav options so credentials are never process arguments, environment variables, logs, returned URLs, or recorder configuration. The source process demuxes without decode, discards every audio stream/packet, remuxes bounded video packets into a local stream-copy relay, and emits sanitized errors. Probe exact model/hardware/firmware, direct RTSP/ONVIF/vendor-event behavior, codec/bitrate/GOP/time, simultaneous streams, audio-off, reboot/WAN-off, and native event relationship. A failed/unsupported E1 becomes `inventory_only` or `native_sd_only`. `bridge.py` compiles but is omitted from the production feature manifest and cannot connect without a future exact bridge binding/evidence. TrackMix continuous is always one low wide view; event tracking is enabled only when separate addressability, ≤2-second alignment, audio, arc, load, playback, and channel-count gates all pass.

Before adding adapter modules, create the package with the foundation's Python/Hatchling/version pins, merge `integrations/reolink` into the root workspace without removing any member, declare `tuntun-contracts = { workspace = true }`, add only the exact `tuntun-camera-source` script above, and regenerate `uv.lock`. `test_reolink_package_bootstrap.py` parses the root and member TOML, proves exactly one member entry and one-way dependencies, imports the installed package, verifies the exact entry-point target, and invokes the Phase 3 import-boundary checker after the new integration exists. `test_camera_source_entrypoint.py` drives `help`, `version`, `start`, `health`, SIGTERM, and a wrong-effective-UID case through an injected runtime; wrong account or bad config ownership must exit nonzero before Keychain, device, network, UDS, or log creation.

- [ ] **Step 4: Run green, hostile-source tests, and marker-gated probe dry run**

Run:

~~~bash
uv lock
uv sync --all-packages --locked
uv run --locked --offline --no-sync python -c 'import tuntun_reolink; assert tuntun_reolink.__version__ == "0.1.0.dev0"'
uv run --locked --offline --no-sync tuntun-camera-source --help
uv run --locked --offline --no-sync tuntun-camera-source --version
uv run --locked --offline --no-sync pytest tests/unit/vision/test_reolink_package_bootstrap.py tests/unit/vision/test_camera_source_entrypoint.py integrations/reolink/tests apps/recorder/tests -q
uv run --locked --offline --no-sync pytest tests/hardware/vision/test_reolink_units.py --collect-only -q
uv run --locked --offline --no-sync python scripts/phase3/probe_reolink.py --synthetic fixtures/synthetic/vision/reolink-probe.json --output var/evidence/phase3/synthetic-reolink.json
uv run --locked --offline --no-sync python scripts/verify_private_data.py var/evidence/phase3/synthetic-reolink.json
uv run --locked --offline --no-sync python scripts/check_import_boundaries.py --domain vision
uv run --locked --offline --no-sync ruff check integrations/reolink apps/recorder/src/tuntun_recorder/source scripts/phase3/probe_reolink.py tests/hardware/vision tests/unit/vision/test_reolink_package_bootstrap.py
uv run --locked --offline --no-sync mypy integrations/reolink/src apps/recorder/src
uv lock --check
uv build --offline --wheel --package tuntun-reolink --out-dir var/build-smoke/phase3/reolink
uv lock --check
~~~

Expected: PASS; the two E1 fixtures retain independent outcomes, unsupported routes stay absent, and no error/output contains an address or credential.

- [ ] **Step 5: Commit**

~~~bash
git add pyproject.toml uv.lock integrations/reolink/pyproject.toml integrations/reolink/src/tuntun_reolink/__init__.py integrations/reolink/src/tuntun_reolink/adapter.py integrations/reolink/src/tuntun_reolink/capabilities.py integrations/reolink/src/tuntun_reolink/direct.py integrations/reolink/src/tuntun_reolink/native_events.py integrations/reolink/src/tuntun_reolink/bridge.py integrations/reolink/src/tuntun_reolink/clock.py integrations/reolink/src/tuntun_reolink/sanitized_errors.py integrations/reolink/src/tuntun_reolink/entrypoint.py integrations/reolink/tests/test_capability_probe.py integrations/reolink/tests/test_direct_source.py integrations/reolink/tests/test_native_events.py integrations/reolink/tests/test_bridge_absence.py apps/recorder/src/tuntun_recorder/source/service.py apps/recorder/src/tuntun_recorder/source/relay.py scripts/phase3/probe_reolink.py fixtures/synthetic/vision/reolink-probe.json docs/operations/phase3-e1-source-gate.md tests/hardware/vision/test_reolink_units.py tests/unit/vision/test_reolink_package_bootstrap.py tests/unit/vision/test_camera_source_entrypoint.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(reolink): add exact-capability local source adapters"
~~~

### Task 10: Qualify the encrypted SSD boundary and install least-privilege launchd services

**Depends on:** Tasks 04–05 and 09 so every active plist target is an installed, locked console script rather than a future filename.
**Gate contribution:** P3-0 storage/process prerequisite.
**Estimated effort:** 1.5 person-days plus cold-boot/power checks.

**Files:**
- Modify: `apps/recorder/pyproject.toml`
- Modify: `uv.lock`
- Create: `apps/recorder/src/tuntun_recorder/entrypoints/__init__.py`
- Create: `apps/recorder/src/tuntun_recorder/entrypoints/recorder.py`
- Create: `apps/recorder/src/tuntun_recorder/entrypoints/media_proxy.py`
- Create: `apps/recorder/src/tuntun_recorder/volume.py`
- Create: `scripts/phase3/qualify_video_volume.py`
- Create: `fixtures/synthetic/vision/volume-qualified.json`
- Create: `fixtures/synthetic/vision/process-entrypoints.json`
- Create: `ops/launchd/phase3/com.tuntun.camera-source.plist`
- Create: `ops/launchd/phase3/com.tuntun.recorder.plist`
- Create: `ops/launchd/phase3/com.tuntun.media-proxy.plist`
- Create: `ops/launchd/phase3/com.tuntun.owner-ingress.plist`
- Create: `docs/operations/phase3-video-volume.md`
- Create: `docs/operations/phase3-recorder.md`
- Test: `apps/recorder/tests/unit/test_volume_gate.py`
- Test: `apps/recorder/tests/integration/test_mount_substitution.py`
- Test: `tests/security/vision/test_launchd_separation.py`
- Test: `apps/recorder/tests/unit/test_process_entrypoints.py`
- Test: `tests/integration/vision/test_launchd_entrypoint_binding.py`
- Test: `tests/integration/vision/test_phase3_services_absent_before_takeover.py`
- Test: `tests/hardware/vision/test_video_volume.py`

**Interfaces:** Adds exact scripts `[project.scripts] tuntun-recorder = tuntun_recorder.entrypoints.recorder:main` and `tuntun-media-proxy = tuntun_recorder.entrypoints.media_proxy:main`; each exposes injectable `run(argv, runtime) -> int`. Help/version have no effects, `start` verifies its exact provisioned effective UID and owned configuration before opening a catalog, mount, UDS, listener, or log, and `health` is bounded/read-only. Media-proxy `start` remains fail-closed/disabled until Task 17 supplies its complete playback composition; it is never a health-only listener. Produces `VideoVolumeGate.open(expected: ExpectedVideoVolume) -> VideoVolumeHandle`, invalidatable mount-epoch handles, a read-only qualification report, and four candidate side-process launchd definitions. Each rendered plist has `ProgramArguments == [<canonical absolute current-release .venv>/bin/<exact script>, "start", "--config", <canonical absolute owner-controlled config>]`, uses no shell, `python -m`, PATH lookup, unresolved token, writable release path, or environment secret, and pins its exact future service account. **All four plists are rendered with `Disabled=true` and remain unbootstrapped/unloaded in this task.** This task creates no service account, installed config, launchd override, active socket, mount entitlement, or Keychain entitlement. Task 17 alone owns the atomic installer/lifecycle transition that provisions, validates, bootstraps, and enables the exact signed service set; `test_phase3_services_absent_before_takeover.py` proves clean install and upgrade candidates have no Phase 3 launchd label/process/socket before that transition. The expectation and returned handle both bind APFS container UUID, exact `TUNTUN_VIDEO` volume UUID/mount/quota, minimum `HA_BACKUPS` reserve, recorder UID, and qualification generation/digest. Only the gate-generated handle carries a fresh random mount epoch and trusted open time; neither is caller authority. Consumes the existing owner-created APFS encrypted `TUNTUN_VIDEO` and separate `HA_BACKUPS` volume/quota; it never formats, erases, repartitions, or silently creates a volume. The committed qualified-volume fixture is synthetic and deterministic, covers the exact positive identity plus every rejection mutation, and contains no real mount UUID, user ID, path, or hardware serial.

- [ ] **Step 1: Write red encryption, UUID, ownership, root-fallback, and process-entitlement tests**

~~~python
@pytest.mark.parametrize("mutation", [
    "unencrypted", "wrong_container_uuid", "wrong_video_volume_uuid", "wrong_video_quota",
    "insufficient_ha_backup_reserve", "stale_qualification_generation", "wrong_qualification_digest",
    "read_only", "wrong_owner", "unexpected_filesystem", "root_disk_symlink",
])
def test_volume_gate_blocks_unsafe_mount(volume_gate, qualified_volume, mutation) -> None:
    with pytest.raises(VolumeIneligible):
        volume_gate.open(qualified_volume.mutate(mutation))

def test_volume_gate_accepts_exact_fresh_current_volume(volume_gate, qualified_volume) -> None:
    first = volume_gate.open(qualified_volume)
    second = volume_gate.open(qualified_volume)
    assert first.apfs_container_uuid == qualified_volume.apfs_container_uuid
    assert first.video_volume_uuid == qualified_volume.video_volume_uuid
    assert first.qualification_generation == qualified_volume.qualification_generation
    assert first.qualification_digest == qualified_volume.qualification_digest
    assert isinstance(first.mount_epoch, UUID)
    assert second.mount_epoch != first.mount_epoch
    assert first.opened_at <= second.opened_at
    assert not volume_gate.is_current(first)
    assert volume_gate.is_current(second)

def test_recorder_never_falls_back_when_video_volume_disappears(recorder, volume) -> None:
    volume.disconnect()
    recorder.write_next_segment()
    assert recorder.health.storage_state == "write_blocked"
    assert not recorder.mac_root_written()

@pytest.mark.parametrize("transition", ["cold_start", "reconnect", "cable_flap", "mount_epoch_change"])
def test_start_and_every_reconnect_require_fresh_full_volume_binding(recorder, volume, transition) -> None:
    stale_handle = recorder.volume_handle
    volume.transition(transition)
    recorder.resume()
    assert not recorder.accepts(stale_handle)
    assert recorder.health.storage_state == "write_blocked"
    recorder.open_volume(volume.expected_current())
    assert recorder.volume_handle.mount_epoch != stale_handle.mount_epoch

def test_four_side_processes_have_exact_disjoint_listener_mount_and_key_entitlements(launchd_matrix) -> None:
    assert launchd_matrix.names == {
        "tuntun-camera-source", "tuntun-recorder", "tuntun-media-proxy", "tuntun-owner-ingress",
    }
    ingress = launchd_matrix.only("tuntun-owner-ingress")
    assert ingress.loopback_binds == {("127.0.0.1", 8787)}
    assert ingress.optional_lan_binds == {("exact_current_commissioned_rfc1918", 8443)}
    assert 8787 not in ingress.lan_ports
    assert not launchd_matrix.only("tuntun-owner-ingress").video_mount_or_catalog_key

@pytest.mark.parametrize("process", ["camera_source", "recorder", "media_proxy"])
def test_entrypoint_wrong_account_rejects_before_any_effect(process_runtime, process) -> None:
    result = process_runtime.run(process, ["start"], effective_uid=process_runtime.wrong_uid)
    assert result.exit_code != 0
    assert process_runtime.effects == []

def test_rendered_plists_resolve_exact_locked_console_scripts(rendered_launchd_matrix) -> None:
    assert rendered_launchd_matrix.program_arguments == {
        "tuntun-camera-source": ("tuntun-camera-source", "start"),
        "tuntun-recorder": ("tuntun-recorder", "start"),
        "tuntun-media-proxy": ("tuntun-media-proxy", "start"),
        "tuntun-owner-ingress": ("tuntun-owner-ingress", "start"),
    }
    assert rendered_launchd_matrix.all_executables_are_absolute_current_release_venv
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/recorder/tests/unit/test_process_entrypoints.py apps/recorder/tests/unit/test_volume_gate.py apps/recorder/tests/integration/test_mount_substitution.py tests/security/vision/test_launchd_separation.py tests/integration/vision/test_launchd_entrypoint_binding.py tests/integration/vision/test_phase3_services_absent_before_takeover.py -q`
Expected: FAIL because the recorder/media-proxy composition roots, `VideoVolumeGate`, and bound Phase 3 launchd definitions are absent.

- [ ] **Step 3: Implement the volume gate, account matrix, and non-destructive qualification**

~~~python
def open(self, expected: ExpectedVideoVolume) -> VideoVolumeHandle:
    observed = self._probe.inspect(expected.mount_point)
    exact_identity = (
        observed.apfs_container_uuid,
        observed.video_volume_uuid,
        observed.mount_point,
        observed.video_quota_bytes,
        observed.ha_backup_reserve_bytes,
        observed.qualification_generation,
        observed.qualification_digest,
    )
    expected_identity = (
        expected.apfs_container_uuid,
        expected.video_volume_uuid,
        Path(expected.mount_point),
        expected.video_quota_bytes,
        expected.minimum_ha_backup_reserve_bytes,
        expected.qualification_generation,
        expected.qualification_digest,
    )
    if exact_identity != expected_identity or observed.filesystem != "apfs":
        raise VolumeIneligible("video_volume_identity_mismatch")
    if not observed.encrypted or observed.read_only or observed.owner_uid != expected.recorder_uid:
        raise VolumeIneligible("video_volume_protection_failed")
    root = observed.mount_point.resolve()
    if root == Path("/") or root.stat().st_dev == Path("/").stat().st_dev:
        raise VolumeIneligible("video_volume_root_fallback_forbidden")
    return VideoVolumeHandle(
        apfs_container_uuid=expected.apfs_container_uuid,
        video_volume_uuid=expected.video_volume_uuid,
        mount_point=str(root),
        video_quota_bytes=expected.video_quota_bytes,
        minimum_ha_backup_reserve_bytes=expected.minimum_ha_backup_reserve_bytes,
        recorder_uid=expected.recorder_uid,
        qualification_generation=expected.qualification_generation,
        qualification_digest=expected.qualification_digest,
        mount_epoch=uuid4(),
        opened_at=self._clock.now(),
    )
~~~

The qualification records exact SSD/enclosure/firmware, nominal/usable capacity, APFS encryption, container/volume/quota identity, minimum separately reserved `HA_BACKUPS` bytes, qualification generation/digest, SMART/endurance visibility, sustained write, temperature, cable flap/reconnect, wrong mount, cold-boot unlock, FileVault/Keychain behavior, recorder-user ownership, Time Machine/cloud-sync/Spotlight exclusion, and sleep policy. Startup and every reconnect invalidate the prior mount epoch and rerun the full gate before a catalog/file descriptor can open. Capacity uses the exact bound video quota, never container free space. The source account gets local camera network plus its Keychain namespace and no video mount; recorder gets `TUNTUN_VIDEO`/catalog and IPC but no camera/provider/core/HA keys or LAN listener; media proxy gets read-only media/catalog and its Unix socket; owner ingress gets only exact inner binds plus authenticated core/media UDS clients. The script defaults to inspect-only; its write probe requires `TUNTUN_ALLOW_VIDEO_VOLUME=1` and writes one bounded synthetic file beneath the already qualified video root.

Merge the two recorder scripts into the existing package metadata and regenerate `uv.lock`; do not add a recorder→Reolink dependency. Render each plist from owner-controlled install-time roots, canonicalize and containment-check those roots before substitution, then lint the rendered artifact—not only the tokenized template. The entrypoint suite invokes `--help`, `--version`, `start`, `health`, SIGTERM, missing/stale config, wrong file owner/mode, and wrong effective UID under the locked environment. It asserts the UID/config gate precedes logging and all Keychain, APFS, database, UDS, network, and camera calls; the media-proxy start case must return a stable feature-absent failure until Task 17, not bind or sleep indefinitely.

- [ ] **Step 4: Run green, plist lint, and marker-gated collection**

Run:

~~~bash
uv lock
uv sync --all-packages --locked
uv run --locked --offline --no-sync tuntun-camera-source --help
uv run --locked --offline --no-sync tuntun-recorder --help
uv run --locked --offline --no-sync tuntun-recorder --version
uv run --locked --offline --no-sync tuntun-media-proxy --help
uv run --locked --offline --no-sync pytest apps/recorder/tests/unit/test_process_entrypoints.py apps/recorder/tests/unit/test_volume_gate.py apps/recorder/tests/integration/test_mount_substitution.py tests/security/vision/test_launchd_separation.py tests/integration/vision/test_launchd_entrypoint_binding.py tests/integration/vision/test_phase3_services_absent_before_takeover.py -q
plutil -lint ops/launchd/phase3/com.tuntun.camera-source.plist ops/launchd/phase3/com.tuntun.recorder.plist ops/launchd/phase3/com.tuntun.media-proxy.plist ops/launchd/phase3/com.tuntun.owner-ingress.plist
uv run --locked --offline --no-sync python scripts/phase3/qualify_video_volume.py --synthetic fixtures/synthetic/vision/volume-qualified.json --output var/evidence/phase3/synthetic-volume.json
uv run --locked --offline --no-sync pytest tests/hardware/vision/test_video_volume.py --collect-only -q
uv run --locked --offline --no-sync ruff check apps/recorder/src/tuntun_recorder/entrypoints apps/recorder/src/tuntun_recorder/volume.py scripts/phase3/qualify_video_volume.py apps/recorder/tests/unit/test_process_entrypoints.py tests/security/vision tests/integration/vision/test_launchd_entrypoint_binding.py tests/hardware/vision
uv run --locked --offline --no-sync mypy apps/recorder/src
uv lock --check
uv build --offline --wheel --package tuntun-recorder --out-dir var/build-smoke/phase3/recorder-entrypoints
uv lock --check
~~~

Expected: PASS; all four side-process definitions expose no credential/address, wrong/missing/stale volume authority blocks writes, and voice/core/Green paths remain available.

- [ ] **Step 5: Commit**

~~~bash
git add apps/recorder/pyproject.toml uv.lock apps/recorder/src/tuntun_recorder/entrypoints/__init__.py apps/recorder/src/tuntun_recorder/entrypoints/recorder.py apps/recorder/src/tuntun_recorder/entrypoints/media_proxy.py apps/recorder/src/tuntun_recorder/volume.py scripts/phase3/qualify_video_volume.py fixtures/synthetic/vision/volume-qualified.json fixtures/synthetic/vision/process-entrypoints.json ops/launchd/phase3/com.tuntun.camera-source.plist ops/launchd/phase3/com.tuntun.recorder.plist ops/launchd/phase3/com.tuntun.media-proxy.plist ops/launchd/phase3/com.tuntun.owner-ingress.plist docs/operations/phase3-video-volume.md docs/operations/phase3-recorder.md apps/recorder/tests/unit/test_process_entrypoints.py apps/recorder/tests/unit/test_volume_gate.py apps/recorder/tests/integration/test_mount_substitution.py tests/security/vision/test_launchd_separation.py tests/integration/vision/test_launchd_entrypoint_binding.py tests/integration/vision/test_phase3_services_absent_before_takeover.py tests/hardware/vision/test_video_volume.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "ops(vision): qualify encrypted video volume and services"
~~~

## Wave 2 — P3-1 Audio-Free Recording, Retention, Playback, and One-Camera Pilot

### Task 11: Complete the credential-free source-to-recorder media handle

**Depends on:** Tasks 05, 07, 09, and 10.
**Gate contribution:** P3-1 process/credential boundary.
**Estimated effort:** 1.5 person-days.

**Files:**
- Modify: `apps/recorder/src/tuntun_recorder/source/service.py`
- Modify: `apps/recorder/src/tuntun_recorder/source/relay.py`
- Modify: `apps/recorder/src/tuntun_recorder/source/credentials.py`
- Create: `apps/recorder/src/tuntun_recorder/recording/ingest.py`
- Create: `scripts/scan_process_artifacts.py`
- Create: `apps/recorder/tests/integration/test_media_handle.py`
- Create: `apps/recorder/tests/security/test_recorder_has_no_camera_secret.py`
- Create: `apps/recorder/tests/fault/test_source_backpressure.py`
- Create: `apps/recorder/tests/fault/test_credential_rotation.py`
- Create: `tests/security/vision/test_process_artifact_scanner.py`

**Interfaces:** Produces a single-generation `ReadOnlyMediaHandle` backed by a bounded Unix-domain stream/file descriptor. The handle exposes only request/opaque relay IDs, exact camera-binding and capability generation/digest, stream role, codec/dimensions, sequence/time base, proved byte/packet bounds, and its five-second attach deadline; it contains no address, URL, username, secret, vendor account, or administrative operation. `scan_process_artifacts.py` exposes `main(argv) -> int`, takes one explicit nofollow artifact root, one exact process identity, and a nonempty duplicate-free forbidden-name CSV, and uses the shared bounded assurance primitives to inspect the test harness's frozen complete point-in-time argv/environment/config/log/crash inventory. It exits `0` only when exactly the requested process inventory is complete and clean, `1` on a finding, and `2` on missing/ambiguous/changing/truncated/unreadable inventory or invalid arguments; findings print reason codes and safe artifact classes, never captured values.

- [ ] **Step 1: Write red secret-isolation, backpressure, stale-handle, and rotation tests**

~~~python
async def test_recorder_receives_no_camera_endpoint_or_credential(media_handle_fixture) -> None:
    handle = await media_handle_fixture.source.open_stream(media_handle_fixture.request)
    serialized = handle.model_dump_json()
    assert media_handle_fixture.camera_address not in serialized
    assert media_handle_fixture.secret not in serialized
    assert media_handle_fixture.recorder.keychain_items() == ()

async def test_rotation_closes_old_stream_and_requires_new_generation(media_handle_fixture) -> None:
    active_session = await media_handle_fixture.open_attached_session()
    stale_handle, stale_fd = await media_handle_fixture.open_unattached_descriptor_pair()
    await media_handle_fixture.rotate_credential()
    assert await active_session.read() == b""
    with pytest.raises(StaleGeneration):
        await media_handle_fixture.recorder.attach(stale_handle, stale_fd)
    assert stale_fd.closed
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/recorder/tests/integration/test_media_handle.py apps/recorder/tests/security/test_recorder_has_no_camera_secret.py apps/recorder/tests/fault/test_source_backpressure.py apps/recorder/tests/fault/test_credential_rotation.py tests/security/vision/test_process_artifact_scanner.py -q`
Expected: FAIL because recorder ingest and generation-bound relay admission are absent.

- [ ] **Step 3: Implement bounded descriptor transfer, backpressure, and rotation**

~~~python
async def attach(self, handle: ReadOnlyMediaHandle, fd: ReceivedFileDescriptor) -> IngestSession:
    current = await self._bindings.require_current(handle.camera_binding_id)
    if (
        handle.attach_by <= self._clock.now()
        or handle.media_state != "video_only_ready"
        or handle.camera_binding_generation != current.camera_binding_generation
        or handle.capability_generation != current.capability_generation
        or handle.capability_digest != current.capability_digest
    ):
        fd.close()
        raise StaleGeneration("camera_handle_authority_stale")
    if (
        handle.max_bytes_per_second > current.proved_peak_bytes_per_second
        or handle.max_packet_bytes > current.proved_max_packet_bytes
    ):
        fd.close()
        raise IngestRejected("camera_handle_rate_unproved")
    await self._single_attach_ids.claim(handle.request_id, handle.relay_id)
    return IngestSession(fd=fd, descriptor=handle, byte_bucket=TokenBucket.from_proved_peak(current))
~~~

Transfer the already authenticated, audio-filtered packet relay with `SCM_RIGHTS` over a `0600` Unix socket alongside the exact `read_only_media_handle` `VisionIpcEnvelopeV1[ReadOnlyMediaHandle]`; the receiver must claim the envelope and then the handle's separate single-attach `(request_id, relay_id)` before accepting the descriptor. Apply bounded queue bytes, wall time, reconnect rate, packet size, and idle timeout. Backpressure closes the relay and creates a gap instead of allocating unbounded RAM. Credential rotation closes the source connection, increments the source binding generation, destroys the prior handle, and leaves recording/events/alerts/presence disabled until the new generation is commissioned.

- [ ] **Step 4: Run green and process secret scan**

Run: `uv run pytest apps/recorder/tests/integration/test_media_handle.py apps/recorder/tests/security/test_recorder_has_no_camera_secret.py apps/recorder/tests/fault/test_source_backpressure.py apps/recorder/tests/fault/test_credential_rotation.py tests/security/vision/test_process_artifact_scanner.py -q && uv run python scripts/scan_process_artifacts.py --artifact-root var/test-artifacts/processes --process tuntun-recorder --forbid credential,url,address,vendor_account && uv run ruff check apps/recorder/src/tuntun_recorder/source apps/recorder/src/tuntun_recorder/recording/ingest.py apps/recorder/tests scripts/scan_process_artifacts.py tests/security/vision/test_process_artifact_scanner.py && uv run mypy apps/recorder/src scripts/scan_process_artifacts.py`
Expected: PASS; bounded overload yields a truthful gap and zero secret/address in recorder arguments, environment, config, logs, crash fixture, or catalog.

- [ ] **Step 5: Commit**

~~~bash
git add apps/recorder/src/tuntun_recorder/source/service.py apps/recorder/src/tuntun_recorder/source/relay.py apps/recorder/src/tuntun_recorder/source/credentials.py apps/recorder/src/tuntun_recorder/recording/ingest.py scripts/scan_process_artifacts.py apps/recorder/tests/integration/test_media_handle.py apps/recorder/tests/security/test_recorder_has_no_camera_secret.py apps/recorder/tests/fault/test_source_backpressure.py apps/recorder/tests/fault/test_credential_rotation.py tests/security/vision/test_process_artifact_scanner.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(recorder): pass bounded credential-free media handles"
~~~

### Task 12: Record audio-free 60-second low-wide segments by stream copy

**Depends on:** Tasks 04, 10, and 11.
**Gate contribution:** P3-1 recorder baseline.
**Estimated effort:** 2 person-days.

**Files:**
- Create: `apps/recorder/src/tuntun_recorder/recording/segmenter.py`
- Create: `apps/recorder/src/tuntun_recorder/recording/service.py`
- Create: `apps/recorder/src/tuntun_recorder/media_probe.py`
- Create: `scripts/fuzz_media_parser.py`
- Modify: `apps/recorder/src/tuntun_recorder/catalog/repository.py`
- Create: `apps/recorder/tests/unit/test_segment_boundaries.py`
- Create: `apps/recorder/tests/integration/test_stream_copy.py`
- Create: `apps/recorder/tests/security/test_audio_rejection.py`
- Create: `apps/recorder/tests/security/test_hostile_media_bounds.py`
- Create: `tests/security/vision/test_media_fuzz_driver.py`

**Interfaces:** Implements `RecorderPort.start(RecorderStartV1)` for `low_wide` only. Core sends the exact binding/profile/zone/source-eligibility/egress/volume/policy/privacy authority only as a claimed `recorder_start` IPC envelope; recorder returns the existing causation-bound `recorder_receipt`. It produces 60-second `continuous_7d` `SegmentV1` rows through `MediaCommitter`, consumes a `ReadOnlyMediaHandle` and qualified volume, and rejects stale/profile-spliced starts before asking camera-source for a handle. No input stream can choose a destination filename/path/container command. `fuzz_media_parser.py` exposes a deterministic, seed-recording CLI over a nofollow corpus root with exact case, input-byte, metadata, wall-time, CPU, memory, stdout/stderr, and output-byte ceilings. It invokes only the pinned parser with an argument vector and sanitized environment; `--assert-no-decode` and `--assert-no-audio-output` are enforced observations, and missing/corrupt/changing corpus inventory, timeout, crash, limit exhaustion, or an unclassified parser result fails closed.

- [ ] **Step 1: Write red segment duration, stream-copy, and double audio rejection tests**

~~~python
async def test_low_wide_segments_are_stream_copy_and_sixty_seconds(recorder, low_wide_fixture) -> None:
    segments = await recorder.record_for(low_wide_fixture, seconds=181)
    assert [s.ended_at - s.started_at for s in segments[:3]] == [timedelta(seconds=60)] * 3
    assert all(s.retention_class == "continuous_7d" for s in segments)
    assert all(await recorder.probe(s).decode_count == 0 for s in segments)

async def test_audio_present_source_is_rejected_before_published_segment(recorder, audio_fixture) -> None:
    with pytest.raises(SourceIneligible, match="camera_audio_present"):
        await recorder.start(audio_fixture.start_command)
    assert await recorder.catalog.count_published() == 0

async def test_start_rejects_profile_binding_splice_before_source_open(recorder, start_command) -> None:
    with pytest.raises(RecorderCommandRejected):
        await recorder.start(start_command.mutate("profile_binding_generation"))
    assert recorder.camera_source.calls == []
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/recorder/tests/unit/test_segment_boundaries.py apps/recorder/tests/integration/test_stream_copy.py apps/recorder/tests/security/test_audio_rejection.py apps/recorder/tests/security/test_hostile_media_bounds.py tests/security/vision/test_media_fuzz_driver.py -q`
Expected: FAIL because `StreamCopySegmenter` and `MediaProbe` are absent.

- [ ] **Step 3: Implement packet-copy segmentation with pre/post audio checks**

~~~python
async def write_segment(self, source: PacketStream, boundary: SegmentBoundary) -> SegmentV1:
    if source.streams.audio or source.streams.video_count != 1:
        raise SourceIneligible("camera_audio_present_or_video_shape_invalid")
    staged = await self._muxer.remux_video_only(
        source=source,
        container="matroska",
        codec_copy=True,
        end_at=boundary.end_at,
        max_bytes=boundary.proved_max_bytes,
        decode=False,
    )
    probe = await self._probe.inspect_staging(staged.staging_token)
    if probe.audio_streams != 0 or probe.video_streams != 1 or probe.decoded_frames != 0:
        await self._staging.destroy(staged.staging_token)
        raise SourceIneligible("stored_media_audio_or_shape_invalid")
    return await self._committer.commit(staged)
~~~

Permit only proved H.264/H.265 video, bounded resolution/rate/GOP/timestamp metadata, and a project-selected container. Sanitize all library errors to safe reason codes. Segment tokens are random; owner area/camera labels never enter file metadata. A short final segment on stop is marked complete/truncated truthfully and never stretched to a false 60-second claim.

- [ ] **Step 4: Run green, media fuzz, and no-audio probe**

Run: `uv run pytest apps/recorder/tests/unit/test_segment_boundaries.py apps/recorder/tests/integration/test_stream_copy.py apps/recorder/tests/security/test_audio_rejection.py apps/recorder/tests/security/test_hostile_media_bounds.py tests/security/vision/test_media_fuzz_driver.py -q && uv run python scripts/fuzz_media_parser.py --corpus fixtures/adversarial/vision --max-cases 5000 --assert-no-decode --assert-no-audio-output && uv run ruff check apps/recorder/src/tuntun_recorder/recording apps/recorder/src/tuntun_recorder/media_probe.py apps/recorder/tests scripts/fuzz_media_parser.py tests/security/vision/test_media_fuzz_driver.py && uv run mypy apps/recorder/src scripts/fuzz_media_parser.py`
Expected: PASS; every published test segment has one video/no audio, routine decode count zero, bounded resources, exact duration metadata, and no path/error leak.

- [ ] **Step 5: Commit**

~~~bash
git add apps/recorder/src/tuntun_recorder/recording/segmenter.py apps/recorder/src/tuntun_recorder/recording/service.py apps/recorder/src/tuntun_recorder/media_probe.py scripts/fuzz_media_parser.py apps/recorder/src/tuntun_recorder/catalog/repository.py apps/recorder/tests/unit/test_segment_boundaries.py apps/recorder/tests/integration/test_stream_copy.py apps/recorder/tests/security/test_audio_rejection.py apps/recorder/tests/security/test_hostile_media_bounds.py tests/security/vision/test_media_fuzz_driver.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(recorder): write audio-free stream-copy segments"
~~~

### Task 13: Detect gaps and reconcile segment/catalog failures truthfully

**Depends on:** Tasks 04 and 12.
**Gate contribution:** P3-1/P3-2 recording truth.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `apps/recorder/src/tuntun_recorder/recording/gaps.py`
- Modify: `apps/recorder/src/tuntun_recorder/recording/reconciliation.py`
- Create: `apps/recorder/src/tuntun_recorder/health.py`
- Create: `apps/recorder/tests/unit/test_gap_detector.py`
- Create: `apps/recorder/tests/fault/test_segment_transition_matrix.py`
- Create: `apps/recorder/tests/integration/test_catalog_file_reconciliation.py`
- Create: `tests/contract/vision/test_recording_health.py`

**Interfaces:** Produces `GapDetector.observe`, `CatalogReconciler`, and `RecordingHealthV1` IPC updates. A gap is source/binding/stream/time bounded; it contains no file path or raw source error.

- [ ] **Step 1: Write red sequence/time-gap and crash-boundary tests**

~~~python
def test_gap_over_five_seconds_is_visible_within_thirty_seconds(fake_clock, detector) -> None:
    detector.observe(complete_segment(end=fake_clock.now_utc()), now_mono=fake_clock.now_mono())
    fake_clock.advance(seconds=6)
    first = detector.tick(now_utc=fake_clock.now_utc(), now_mono=fake_clock.now_mono())
    assert first.current_gap_seconds == 6
    assert first.health_reason_codes == ("segment_gap",)
    fake_clock.advance(seconds=24)
    health = detector.tick(now_utc=fake_clock.now_utc(), now_mono=fake_clock.now_mono())
    assert health.current_gap_seconds >= 30
    assert health.health_reason_codes == ("segment_gap",)

@pytest.mark.parametrize("transition", MEDIA_COMMIT_FAULT_BOUNDARIES)
async def test_no_crash_produces_false_complete_or_duplicate_segment(campaign, transition) -> None:
    await campaign.crash_at(transition)
    await campaign.restart()
    assert await campaign.assert_exactly_once_or_explicit_gap()
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/recorder/tests/unit/test_gap_detector.py apps/recorder/tests/fault/test_segment_transition_matrix.py apps/recorder/tests/integration/test_catalog_file_reconciliation.py tests/contract/vision/test_recording_health.py -q`
Expected: FAIL because gap/health services are absent.

- [ ] **Step 3: Implement monotonic gap observation and bounded reconciliation**

~~~python
def tick(self, now_utc: datetime, now_mono: float) -> RecordingHealthV1:
    gap = max(0, floor(now_mono - self._last_complete_mono))
    return self._health.with_gap(
        seconds=gap,
        reason="segment_gap" if gap > 5 else None,
        observed_at=now_utc,
    )
~~~

On startup reconcile `WRITING` temp files, `CATALOG_COMMITTED` unpublished files, digest mismatches, truncated segments, duplicate sequence ranges, missing storage tokens, catalog corruption, and interrupted expiry. Mark exact media incomplete/corrupt/missing; preserve neighboring valid files. Health separates source/event/recorder/storage/clock state. Emit a gap notification within 30 seconds of a >5-second gap, and never claim later camera-native backfill unless separately implemented and proved.

- [ ] **Step 4: Run green and full transition matrix**

Run: `uv run pytest apps/recorder/tests/unit/test_gap_detector.py apps/recorder/tests/fault/test_segment_transition_matrix.py apps/recorder/tests/integration/test_catalog_file_reconciliation.py tests/contract/vision/test_recording_health.py -q && uv run ruff check apps/recorder/src/tuntun_recorder/recording apps/recorder/src/tuntun_recorder/health.py apps/recorder/tests tests/contract/vision && uv run mypy apps/recorder/src`
Expected: PASS; all durable boundaries settle without duplicate/false-complete media and gaps meet the five/30-second truth gate.

- [ ] **Step 5: Commit**

~~~bash
git add apps/recorder/src/tuntun_recorder/recording/gaps.py apps/recorder/src/tuntun_recorder/recording/reconciliation.py apps/recorder/src/tuntun_recorder/health.py apps/recorder/tests/unit/test_gap_detector.py apps/recorder/tests/fault/test_segment_transition_matrix.py apps/recorder/tests/integration/test_catalog_file_reconciliation.py tests/contract/vision/test_recording_health.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(recorder): reconcile media gaps truthfully"
~~~

### Task 14: Normalize native events and promote bounded full-resolution clips

**Depends on:** Tasks 09, 11–13.
**Gate contribution:** P3-1 recording events; prerequisite for P3-4 alerts.
**Estimated effort:** 2 person-days.

**Files:**
- Create: `apps/recorder/src/tuntun_recorder/events/normalizer.py`
- Create: `apps/recorder/src/tuntun_recorder/events/dedupe.py`
- Create: `apps/recorder/src/tuntun_recorder/events/clock.py`
- Create: `apps/recorder/src/tuntun_recorder/recording/event_ring.py`
- Create: `apps/recorder/src/tuntun_recorder/recording/promotion.py`
- Modify: `apps/recorder/src/tuntun_recorder/catalog/repository.py`
- Test: `apps/recorder/tests/unit/test_event_normalizer.py`
- Test: `apps/recorder/tests/unit/test_event_dedupe.py`
- Test: `apps/recorder/tests/integration/test_event_promotion.py`
- Test: `apps/recorder/tests/integration/test_event_outbox_restart.py`
- Test: `apps/recorder/tests/integration/test_trackmix_dual_view.py`

**Interfaces:** Produces strict `CameraSecurityEventEnvelopeV1` over the imported canonical `CrossDomainEventV1`, a maximum-60-second full-resolution transient ring, and one wide or wide-plus-tracking `ClipV1`. The specialization exact-binds payload observation time to the envelope, so a stale or future payload cannot be revived by a fresh wrapper. It consumes only compiled native detector mappings and the exact current area/zone/binding/capability/privacy generations.

- [ ] **Step 1: Write red malformed/stale event, pre/post roll, coalescing, and dual-view tests**

~~~python
@pytest.mark.parametrize("mutation", [
    "free_label", "stale_binding", "stale_capability", "wrong_area", "wrong_zone",
    "untrusted_clock", "oversize", "duplicate_new_key",
])
async def test_invalid_native_event_never_promotes_or_crosses_policy(normalizer, mutation) -> None:
    receipt = await normalizer.ingest(native_event_fixture().mutate(mutation))
    assert receipt.state == "quarantined"
    assert receipt.promoted_clip is None

async def test_event_clip_has_ten_second_preroll_thirty_second_postroll_and_five_minute_cap(promotion) -> None:
    clip = await promotion.run(event_fixture(duration_seconds=400))
    assert clip.started_at == event_fixture().started_at - timedelta(seconds=10)
    assert clip.ended_at - clip.started_at <= timedelta(minutes=5)

async def test_overlapping_events_share_clip_and_bounded_event_refs(promotion) -> None:
    first, second = overlapping_events_same_camera_zone()
    assert (await promotion.run(first)).clip_id == (await promotion.run(second)).clip_id
    assert await promotion.catalog.event_ref_count(first.camera_binding_id) == 2

@pytest.mark.parametrize("fault", [
    "camera_counter_reset", "camera_counter_wrap", "recorder_sigkill",
    "recorder_power_loss", "mac_restart", "retry_after_commit",
])
async def test_published_camera_event_sequence_survives_native_and_process_restarts(
    normalizer, native_event_stream, fault,
) -> None:
    await normalizer.publish(native_event_stream.first())
    restarted = await normalizer.inject_and_restart(fault)
    await restarted.publish(native_event_stream.after_fault(fault))
    envelopes = await restarted.event_outbox.committed_envelopes()
    source_sequences = tuple(envelope.source_sequence for envelope in envelopes)
    assert source_sequences == tuple(sorted(set(source_sequences)))
    assert all(right == left + 1 for left, right in pairwise(source_sequences))
    assert restarted.event_outbox.effectively_once_per_native_event()

async def test_committed_camera_event_drains_once_after_crash_before_ipc_publish(
    normalizer, native_event_stream,
) -> None:
    event = native_event_stream.first()
    normalizer.faults.arm("after_outbox_commit_before_ipc_publish")
    with pytest.raises(SimulatedCrash):
        await normalizer.publish(event)
    restarted = await normalizer.restart()
    await restarted.event_outbox.drain()
    first = await restarted.ipc.deliveries_for(event.native_event_id)
    assert len(first) == 1
    committed = await restarted.event_outbox.committed_for(event.native_event_id)
    assert first[0].source_sequence == committed.source_sequence
    duplicate = await restarted.publish(event)
    await restarted.event_outbox.drain()
    assert duplicate == committed
    assert len(await restarted.ipc.deliveries_for(event.native_event_id)) == 1
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/recorder/tests/unit/test_event_normalizer.py apps/recorder/tests/unit/test_event_dedupe.py apps/recorder/tests/integration/test_event_promotion.py apps/recorder/tests/integration/test_event_outbox_restart.py apps/recorder/tests/integration/test_trackmix_dual_view.py -q`
Expected: FAIL because event normalizer/ring/promotion modules are absent.

- [ ] **Step 3: Implement closed native mapping, dedupe, clock gate, ring, and promotion**

~~~python
async def normalize(self, native: NativeCameraEventV1) -> CameraSecurityEventEnvelopeV1:
    binding = await self._bindings.require_current_source(
        source_endpoint_id=native.source_endpoint_id,
        source_endpoint_generation=native.source_endpoint_generation,
        camera_binding_id=native.camera_binding_id,
        camera_binding_generation=native.camera_binding_generation,
        capability_generation=native.capability_generation,
    )
    event_class = binding.compiled_native_event_map.get(native.detector_code, "unknown")
    zone = await self._zones.require_same_generation(binding, native.zone_id, native.zone_generation)
    privacy = await self._privacy.require_current(
        CanonicalLocationRefV1(area_id=binding.area_id, area_generation=binding.area_generation), zone.zone_id,
    )
    ingested_at = self._clock.now()
    clock = self._clock.classify(native.observed_at, ingested_at)
    if (
        clock == "untrusted"
        or not native.observed_at <= ingested_at <= native.observed_at + timedelta(seconds=30)
    ):
        raise EventQuarantined("camera_clock_untrusted")
    payload = CameraSecurityEventV1(
        event_id=native.native_event_id,
        camera_binding_id=binding.id, camera_binding_generation=binding.generation,
        capability_generation=native.capability_generation,
        area_id=binding.area_id, area_generation=binding.area_generation,
        zone_id=zone.zone_id, zone_generation=zone.zone_generation, event_class=event_class,
        detector_basis=binding.detector_basis, detector_version=binding.detector_version,
        started_at=native.started_at, ended_at=native.ended_at,
        observed_at=native.observed_at,
        confidence_band=native.confidence_band,
        verification="native", clock_quality=clock, clip_ref=None,
        view_set="wide", privacy_policy_version=privacy.policy_version,
        privacy_generation=privacy.privacy_generation,
    )
    # One recorder-catalog transaction claims the native event identity,
    # allocates the next durable publisher sequence for the current source
    # generation, constructs the complete closed envelope, and inserts its IPC
    # outbox row. Native camera counters are dedupe evidence only and may reset;
    # they never become the cross-domain publisher cursor.
    return await self._event_outbox.claim_native_allocate_sequence_and_enqueue_once(
        publisher_source_endpoint_id=native.source_endpoint_id,
        publisher_source_generation=native.source_endpoint_generation,
        native_event_id=native.native_event_id,
        native_sequence=native.native_sequence,
        native_deduplication_key=native.deduplication_key,
        payload=payload,
        observed_at=payload.observed_at,
        ingested_at=ingested_at,
        expires_at=payload.observed_at + timedelta(seconds=60),
        correlation_id=native.native_event_id,
        causation_id=None,
    )
~~~

Keep a full-resolution wide ring no longer than 60 seconds; destroy unpromoted fragments within the cleanup bound. Accepted events promote up to 10 seconds before, continue 30 seconds after the last accepted update, cap one clip at five minutes, and coalesce overlaps for the same camera/zone into bounded `clip_event_refs`. The optional tracking ring/promotion runs only when the full dual-view gate is current; alignment must be ≤2 seconds. Catalog/UI labels each view separately and never asserts atomicity across files. An untrusted clock may still preserve raw recorder time metadata but cannot create an alert/presence event. The recorder owns a durable monotonic publisher sequence per exact `(source_endpoint_id, source_endpoint_generation)` and allocates it in the same transaction as native-event dedupe and the IPC outbox. Camera-native sequence/reset/wrap is never the consumer cursor. Crash/retry returns the existing envelope, and a source-generation change starts a separately registered sequence namespace without accepting the old one.

- [ ] **Step 4: Run green and replay/reorder/flood matrix**

Run: `uv run pytest apps/recorder/tests/unit/test_event_normalizer.py apps/recorder/tests/unit/test_event_dedupe.py apps/recorder/tests/integration/test_event_promotion.py apps/recorder/tests/integration/test_event_outbox_restart.py apps/recorder/tests/integration/test_trackmix_dual_view.py -q && uv run pytest tests/property/vision/test_event_replay_reorder.py -q && uv run ruff check apps/recorder/src/tuntun_recorder/events apps/recorder/src/tuntun_recorder/recording/event_ring.py apps/recorder/src/tuntun_recorder/recording/promotion.py apps/recorder/tests && uv run mypy apps/recorder/src`
Expected: PASS; no duplicate/replayed/reordered/flooded event extends the ring, duplicates media, or crosses an invalid binding; tracking failure leaves wide-only.

- [ ] **Step 5: Commit**

~~~bash
git add apps/recorder/src/tuntun_recorder/events apps/recorder/src/tuntun_recorder/recording/event_ring.py apps/recorder/src/tuntun_recorder/recording/promotion.py apps/recorder/src/tuntun_recorder/catalog/repository.py apps/recorder/tests/unit/test_event_normalizer.py apps/recorder/tests/unit/test_event_dedupe.py apps/recorder/tests/integration/test_event_promotion.py apps/recorder/tests/integration/test_event_outbox_restart.py apps/recorder/tests/integration/test_trackmix_dual_view.py tests/property/vision/test_event_replay_reorder.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(recorder): promote bounded native-event clips"
~~~

### Task 15: Enforce exact 7/90/60 retention without clock extension

**Depends on:** Tasks 04 and 12–14.
**Gate contribution:** P3-1/P3-2/P3-6 retention.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `apps/recorder/src/tuntun_recorder/recording/retention.py`
- Modify: `apps/recorder/src/tuntun_recorder/catalog/repository.py`
- Create: `apps/recorder/tests/unit/test_retention_deadlines.py`
- Create: `apps/recorder/tests/property/test_retention_clock.py`
- Create: `apps/recorder/tests/fault/test_retention_unlink.py`
- Create: `apps/recorder/tests/integration/test_retention_restart_restore.py`

**Interfaces:** Produces `RetentionPlanner.deadline` and `RetentionWorker.run_bounded(now, limit)`. It consumes immutable end times, retention class, trusted UTC floor, monotonic runtime reference, and a maximum 15-minute maintenance interval.

- [ ] **Step 1: Write red exact-deadline, rollback, restart, and crash tests**

~~~python
@pytest.mark.parametrize(
    ("retention_class", "delta"),
    [("continuous_7d", timedelta(days=7)), ("event_90d", timedelta(days=90)), ("transient_60s", timedelta(seconds=60))],
)
def test_deadline_is_exact_immutable_end_plus_policy(planner, retention_class, delta) -> None:
    segment = segment_fixture(retention_class=retention_class)
    assert planner.deadline(segment) == segment.ended_at + delta

async def test_clock_rollback_and_restart_never_extend_expiry(retention_campaign) -> None:
    original = retention_campaign.deadline
    await retention_campaign.rollback_wall_clock(hours=12)
    await retention_campaign.restart()
    assert retention_campaign.deadline == original
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/recorder/tests/unit/test_retention_deadlines.py apps/recorder/tests/property/test_retention_clock.py apps/recorder/tests/fault/test_retention_unlink.py apps/recorder/tests/integration/test_retention_restart_restore.py -q`
Expected: FAIL because `RetentionPlanner` is absent.

- [ ] **Step 3: Implement immutable expiry and crash-safe unlink/tombstone**

~~~python
POLICY_DELTAS = {
    "continuous_7d": timedelta(days=7),
    "event_90d": timedelta(days=90),
    "transient_60s": timedelta(seconds=60),
}

def deadline(self, media: RetainedMedia) -> datetime:
    expected = media.ended_at + POLICY_DELTAS[media.retention_class]
    if media.immutable_expires_at != expected:
        raise CatalogIntegrityError("retention_deadline_mismatch")
    return expected
~~~

The worker claims bounded expired rows in SQLCipher, makes them unavailable, unlinks only exact contained/digest-matching files, fsyncs the directory, and tombstones the row. A crash is reconciled without early delete or revival. Active wall-clock rollback uses the monotonic floor; restart revalidates against trusted UTC and never sets a later deadline. The UI/audit says flash deletion is logical/cryptographic inaccessibility, not guaranteed physical byte erasure. Owner exports are separate unmanaged copies.

- [ ] **Step 4: Run green and accelerated 90-day simulation**

Run: `uv run pytest apps/recorder/tests/unit/test_retention_deadlines.py apps/recorder/tests/property/test_retention_clock.py apps/recorder/tests/fault/test_retention_unlink.py apps/recorder/tests/integration/test_retention_restart_restore.py -q && uv run python scripts/phase3/run_retention_simulation.py --days 100 --maintenance-seconds 900 --assert-continuous-days 7 --assert-event-days 90 --assert-no-extension && uv run ruff check apps/recorder/src/tuntun_recorder/recording/retention.py apps/recorder/tests && uv run mypy apps/recorder/src`
Expected: PASS; no item is inaccessible early, every item expires by deadline plus the ≤15-minute pass, and rollback/restart/restore never extends it.

- [ ] **Step 5: Commit**

~~~bash
git add apps/recorder/src/tuntun_recorder/recording/retention.py apps/recorder/src/tuntun_recorder/catalog/repository.py apps/recorder/tests/unit/test_retention_deadlines.py apps/recorder/tests/property/test_retention_clock.py apps/recorder/tests/fault/test_retention_unlink.py apps/recorder/tests/integration/test_retention_restart_restore.py scripts/phase3/run_retention_simulation.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(recorder): enforce exact camera retention"
~~~

### Task 16: Enforce storage-pressure thresholds and protect voice/Green workloads

**Depends on:** Tasks 10, 12–15.
**Gate contribution:** P3-1/P3-2 capacity and failure behavior.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `apps/recorder/src/tuntun_recorder/recording/pressure.py`
- Create: `apps/recorder/src/tuntun_recorder/capacity.py`
- Create: `apps/recorder/src/tuntun_recorder/workload.py`
- Create: `apps/recorder/tests/unit/test_storage_pressure.py`
- Create: `apps/recorder/tests/fault/test_full_disk.py`
- Create: `apps/recorder/tests/performance/test_voice_priority.py`
- Create: `apps/recorder/tests/integration/test_green_backup_contention.py`

**Interfaces:** Produces `StoragePressurePolicy.decide(free_fraction)`, `RecordingAdmission`, `WorkloadGovernor`, and capacity/health measurements. It consumes the current `VideoVolumeHandle`, computes all video fractions/capacity only against its exact `video_quota_bytes`, preserves its separately bound `minimum_ha_backup_reserve_bytes`, plus catalog integrity, active voice priority, and Phase 2 Green-backup window state; physical APFS container free space is never substituted for quota authority.

- [ ] **Step 1: Write red exact-threshold and no-early-delete/spill tests**

~~~python
@pytest.mark.parametrize(
    ("free", "continuous", "events", "export", "state"),
    [
        (Decimal("0.26"), True, True, True, "healthy"),
        (Decimal("0.22"), True, True, True, "warning"),
        (Decimal("0.17"), True, True, False, "retention_at_risk"),
        (Decimal("0.12"), False, True, False, "retention_at_risk"),
        (Decimal("0.09"), False, False, False, "write_blocked"),
    ],
)
def test_exact_pressure_matrix(policy, free, continuous, events, export, state) -> None:
    decision = policy.decide(free_fraction=free, mount_integrity=True, catalog_integrity=True)
    assert (decision.admit_continuous, decision.admit_events, decision.admit_export, decision.storage_state) == (
        continuous, events, export, state,
    )

async def test_full_disk_never_deletes_unexpired_or_spills_to_root(campaign) -> None:
    await campaign.fill_to(Decimal("0.09"))
    assert await campaign.unexpired_media_unchanged()
    assert campaign.mac_root_write_count == 0

async def test_green_backup_succeeds_when_video_reaches_exact_quota(campaign) -> None:
    await campaign.fill_video_to_bound_quota()
    assert campaign.video_bytes == campaign.volume_handle.video_quota_bytes
    receipt = await campaign.run_green_backup()
    assert receipt.state == "verified"
    assert receipt.used_ha_backup_reserve_bytes <= campaign.volume_handle.minimum_ha_backup_reserve_bytes
    assert campaign.video_bytes == campaign.volume_handle.video_quota_bytes

def test_pressure_fraction_uses_bound_video_quota_not_container_free_space(policy, volume_handle) -> None:
    decision = policy.decide_from_bytes(
        used_video_bytes=volume_handle.video_quota_bytes * 9 // 10,
        volume_handle=volume_handle,
        physical_container_free_bytes=10 * volume_handle.video_quota_bytes,
    )
    assert decision.storage_state == "retention_at_risk"
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/recorder/tests/unit/test_storage_pressure.py apps/recorder/tests/fault/test_full_disk.py apps/recorder/tests/performance/test_voice_priority.py apps/recorder/tests/integration/test_green_backup_contention.py -q`
Expected: FAIL because pressure/workload modules are absent.

- [ ] **Step 3: Implement deterministic admission and priority scheduling**

~~~python
def decide(self, free_fraction: Decimal, mount_integrity: bool, catalog_integrity: bool) -> RecordingAdmission:
    if not mount_integrity or not catalog_integrity or free_fraction < Decimal("0.10"):
        return RecordingAdmission.block_all("write_blocked")
    if free_fraction < Decimal("0.15"):
        return RecordingAdmission(events=True, continuous=False, export=False, transcode=False, state="retention_at_risk")
    if free_fraction < Decimal("0.20"):
        return RecordingAdmission(events=True, continuous=True, export=False, transcode=False, state="retention_at_risk")
    if free_fraction <= Decimal("0.25"):
        return RecordingAdmission.normal(state="warning")
    return RecordingAdmission.normal(state="healthy")
~~~

At 10–15%, finish the current continuous segment, stop admission, and open an explicit gap while still attempting event clips. Below 10% or on read-only/mount/catalog uncertainty, stop all writes and preserve existing media. Never shrink retention. The fraction denominator is the handle's exact video quota; container capacity/free space cannot inflate it. CPU/I/O controls bound recorder concurrency; voice capture/TTS playback preempts on-demand transcode; Green backup has an explicit I/O window and physically separate minimum reserve. The full-quota test fills `TUNTUN_VIDEO` to its bound quota and proves a verified Green backup completes without reclaiming video or violating either quota. Record peak CPU/RAM/disk/network/temperature and first-audio/backup deltas.

- [ ] **Step 4: Run green and resource/failure matrix**

Run: `uv run pytest apps/recorder/tests/unit/test_storage_pressure.py apps/recorder/tests/fault/test_full_disk.py apps/recorder/tests/performance/test_voice_priority.py apps/recorder/tests/integration/test_green_backup_contention.py -q && uv run python scripts/phase3/run_resource_simulation.py --assert-first-audio-max-seconds 4 --assert-regression-max-percent 10 --assert-no-root-spill && uv run ruff check apps/recorder/src/tuntun_recorder/recording/pressure.py apps/recorder/src/tuntun_recorder/capacity.py apps/recorder/src/tuntun_recorder/workload.py apps/recorder/tests && uv run mypy apps/recorder/src`
Expected: PASS; threshold states match exactly, no early delete/spill occurs, voice and Green objectives remain within bounds, and a stopped policy is labelled unsatisfied.

- [ ] **Step 5: Commit**

~~~bash
git add apps/recorder/src/tuntun_recorder/recording/pressure.py apps/recorder/src/tuntun_recorder/capacity.py apps/recorder/src/tuntun_recorder/workload.py apps/recorder/tests/unit/test_storage_pressure.py apps/recorder/tests/fault/test_full_disk.py apps/recorder/tests/performance/test_voice_priority.py apps/recorder/tests/integration/test_green_backup_contention.py scripts/phase3/run_resource_simulation.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(recorder): enforce storage and workload admission"
~~~

### Task 17: Mint owner-only byte-range grants and serve same-origin playback

**Depends on:** Tasks 03–05 and 12–16.
**Gate contribution:** P3-1/P3-3 playback.
**Estimated effort:** 2 person-days.

**Files:**
- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Create: `apps/owner-ingress/pyproject.toml`
- Create: `apps/owner-ingress/src/tuntun_owner_ingress/__init__.py`
- Create: `apps/owner-ingress/src/tuntun_owner_ingress/parser.py`
- Create: `apps/owner-ingress/src/tuntun_owner_ingress/request_context.py`
- Create: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Create: `apps/owner-ingress/src/tuntun_owner_ingress/streaming.py`
- Create: `apps/owner-ingress/src/tuntun_owner_ingress/listeners.py`
- Create: `apps/owner-ingress/src/tuntun_owner_ingress/service.py`
- Create: `apps/owner-ingress/src/tuntun_owner_ingress/entrypoint.py`
- Modify: `apps/recorder/src/tuntun_recorder/entrypoints/media_proxy.py`
- Modify: `ops/launchd/phase3/com.tuntun.media-proxy.plist`
- Modify: `ops/launchd/phase3/com.tuntun.owner-ingress.plist`
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `deploy/macos/com.tuntun.core.plist`
- Create: `ops/services/phase3-camera-source.v1.json`
- Create: `ops/services/phase3-recorder.v1.json`
- Create: `ops/services/phase3-media-proxy.v1.json`
- Create: `ops/services/phase3-owner-ingress.v1.json`
- Create: `ops/routes/owner-ingress-routes.v1.json`
- Modify: `deploy/macos/install.sh`
- Modify: `deploy/macos/preflight.sh`
- Modify: `deploy/macos/upgrade.sh`
- Modify: `deploy/macos/rollback.sh`
- Modify: `deploy/macos/uninstall.sh`
- Modify: `apps/core/src/tuntun_core/deploy/lifecycle.py`
- Create: `apps/core/src/tuntun_core/services/vision/playback_broker.py`
- Create: `apps/recorder/src/tuntun_recorder/media/grants.py`
- Create: `apps/recorder/src/tuntun_recorder/media/range_reader.py`
- Create: `apps/recorder/src/tuntun_recorder/media/proxy.py`
- Create: `apps/recorder/src/tuntun_recorder/media/transcode.py`
- Create: `apps/core/src/tuntun_core/api/routes/cameras.py`
- Create: `apps/core/src/tuntun_core/api/vision_dtos.py`
- Create: `tests/security/vision/test_playback_object_auth.py`
- Create: `tests/security/vision/test_playback_grants.py`
- Create: `tests/integration/vision/test_same_origin_playback.py`
- Create: `tests/integration/vision/test_owner_ingress_routing.py`
- Create: `tests/integration/deploy/test_owner_ingress_route_manifest.py`
- Create: `tests/integration/vision/test_phase3_boot_composition.py`
- Create: `tests/integration/vision/test_owner_ingress_takeover.py`
- Create: `tests/fault/vision/test_owner_ingress_takeover_rollback.py`
- Create: `tests/security/vision/test_owner_ingress_request_context.py`
- Create: `tests/security/vision/test_owner_ingress_network_surface.py`
- Create: `tests/performance/vision/test_owner_ingress_backpressure.py`
- Create: `apps/recorder/tests/fault/test_transcode_cleanup.py`
- Create: `tests/unit/vision/test_owner_ingress_package_bootstrap.py`
- Create: `tests/integration/vision/test_deployed_process_entrypoints.py`
- Create: `tests/integration/deploy/test_phase3_side_process_lifecycle.py`

**Interfaces:** This is the first owner of standalone distribution `tuntun-owner-ingress`: register exact root workspace member `apps/owner-ingress` once, expose `tuntun_owner_ingress.__version__: str = "0.1.0.dev0"`, and update the root lock. It depends on `tuntun-contracts` plus only directly imported, already constrained HTTP/TLS primitives. It must not depend on or import `tuntun-core`, `tuntun-recorder`, or `tuntun-reolink`; all application communication crosses the closed peer-authenticated UDS contracts below. It owns exact script `[project.scripts] tuntun-owner-ingress = tuntun_owner_ingress.entrypoint:main`, while the existing `tuntun-media-proxy` script now receives its complete composition. Both expose injectable `run(argv, runtime) -> int`; help/version have no effects, `start` checks exact effective UID and owner-controlled config before log/key/catalog/UDS/listener access, and health is bounded/read-only. `listeners.py` is the sole owner of loopback/commissioned-LAN socket construction; the network-surface and deployed-entrypoint tests import it directly and reject any second listener factory, wildcard/IPv6 bind, or bind before the account/config gate. Only after their locked start/health/wrong-account tests pass may deployment atomically render and enable the two previously disabled plists. Produces hardened `OwnerIngressService`, closed `OwnerIngressPreSessionRequestV1 -> OwnerIngressPreSessionResultV1` (containing either the bounded Phase 1 response or a fresh `DerivedOwnerSessionTupleV1`) and session-bound `AuthenticatedOwnerIngressRequestV1`, owner-only event-clip plus 7-day low-wide segment timeline/query projections, `PlaybackBroker.prepare_range(...) -> PreparedPlaybackRangeV1` over `PlaybackSubjectV1`, recorder-owned durable `RecorderGrantLedger.register/claim`, exact same-origin `GET /api/v1/media/{opaque_grant_id}`, and an optional bounded `PlaybackTranscoder`. The broker generates exactly 32 random bytes and unpadded-base64url encodes them as the 43-character `OpaquePlaybackRouteToken`; the signed `MediaPlaybackGrantV1` carries SHA-256 of the ASCII token plus the exact owner session ID/generation/binding commitment and one exact clip-view or continuous-segment subject, while the browser response carries the raw one-use token plus its digest and the signed-grant digest. Owner ingress is the only HTTP process: it binds `127.0.0.1:8787` unconditionally and may bind exactly one currently commissioned RFC1918 address on `:8443`, but it does not terminate Phase 1 authentication or create sessions. It first forwards the bounded exact normalized query/body, normalized single inclusive client byte range when and only when the route is media, and loopback Authorization+DPoP, LAN cookie+CSRF, or session-bootstrap material to core through `owner_pre_session_request`; core alone runs the unchanged Phase 1 verifier/WebAuthn/session creation and returns `owner_pre_session_result`. Challenge/login/refresh/logout results carry the exact bounded no-store Phase 1 HTTP response (including bounded Set-Cookie or loopback authorization only when produced by core) straight back to the same connection; protected-route results instead carry a ≤2-second tuple bound to that exact listener, peer, route, query digest, client range, body digest, and request. Ingress dispatches an application route only from that fresh core-derived tuple, destroys forwarded credentials/query/body after return or dispatch, places the tuple plus derivation commitment—not a cookie or bearer credential—inside the MACed session-bound context, and routes only the exact bodyless/queryless media GET with one closed `Range: bytes=start-end` to media-proxy UDS and generated non-media routes to core UDS. Before returning the browser response, core sends `media_grant_register` to recorder; recorder verifies the core signature and live subject, durably stores only compiled grant/route/signature digests, media subject/range, session-binding HMAC, expiry and unclaimed state, discards the signed envelope/raw session identity, and acknowledges. On media GET, read-only media proxy first validates the fresh MACed ingress context and its core-derived session tuple, then sends a ≤2-second commitment-bound `media_grant_claim`, capped by the owner-context deadline, carrying that exact client range to recorder; recorder checks the inner claim deadline with trusted time before any ledger/storage read, exact-compares the stored route/session/range commitments, atomically claims once, and returns one authenticated claim receipt echoing the exact claim commitment/deadline and carrying only the exact storage token/subject/range needed for the read. Media proxy rechecks that inner deadline after IPC and the range reader rechecks at first media read; the proxy has no writable catalog or grant ledger. Core and the ingress/proxy boundary consume current owner assurance/session, listener/origin/derivation binding, exact playback subject/range, privacy generation, catalog integrity, and domain-separated core/ingress keys pinned by key ID.

The only Phase 3 service inventories are the four signed closed manifests `ops/services/phase3-camera-source.v1.json`, `phase3-recorder.v1.json`, `phase3-media-proxy.v1.json`, and `phase3-owner-ingress.v1.json`, with exact manifest IDs `phase3.camera_source.v1`, `phase3.recorder.v1`, `phase3.media_proxy.v1`, and `phase3.owner_ingress.v1`. There is no parallel aggregate under `deploy/macos`. Each manifest binds one label, console-script name and expected distribution/wheel digest, rendered plist, service account, config path/digest/mode, executable containment root, enabled gate, health deadline, listener/mount/key entitlement class, start/stop order, cleanup set, and rollback predecessor. These Task 17 rows describe the first takeover-capable candidate, not a permanent digest exemption: any later change to `tuntun-reolink`, `tuntun-recorder` (including `tuntun-secure-archive` dependency changes), `tuntun-owner-ingress`, a bound plist/config, or the closed ingress router makes the affected row and installed lifecycle receipt stale. Task 32 must rebuild the final Phase 3 wheels, refresh and re-sign all four rows, and repeat the installed lifecycle/takeover gate before its soak; a later phase that changes owner ingress must do the same for `phase3.owner_ingress.v1`. Install/preflight/upgrade/rollback/uninstall derive the exact duplicate-free set from these signed manifests and reject missing/extra/unknown manifests, a script absent from locked candidate metadata, unresolved paths, wrong account, plist/manifest drift, or health from another release. Clean install and upgrade render disabled artifacts first, verify all scripts with side-effect-free help/version, then atomically provision and start camera-source→recorder→media-proxy→owner-ingress; each reports the same release/build/config generation. Only after fresh health and takeover probes does one lifecycle record enable the exact set and retire the old core listener. Failure, restart during transition, or rollback stops the reverse order, proves ports/UDS closed, restores the prior listener/manifest generation, and never leaves two HTTP owners. Uninstall unloads all signed rows while preserving separately governed data.

`ops/routes/owner-ingress-routes.v1.json` is the sole signed/generated ingress allowlist. Task 17 freezes the already accepted Phase 1 authentication/session routes plus the exact camera timeline/playback routes available at this point. Every row binds method, normalized path template, query/body/range policy, owner-assurance class, feature ID/generation, target Core or media-proxy UDS, response limits, and route digest. `router.py` may dispatch only a matched row; it has no generic prefix, arbitrary upstream, caller-selected socket, or catch-all forwarding. `api/app.py` and `bootstrap/container.py` consume the same signed feature and route manifests. The installed-candidate composition test boots the locked wheels/plists/config, proves listener → owner-ingress → exact peer-authenticated Core/media UDS routing for every enabled row, proves unknown/disabled/direct-Core routes return 404 or have no listener, and exact-compares enabled routes, ports, workers, adapters, and consumers with the signed feature manifest.

- [ ] **Step 1: Write red actor/range/replay/expiry/path/privacy tests**

~~~python
@pytest.mark.parametrize("actor", ["second_adult", "k2_child", "n1_child", "designated_guest", "anonymous", "ha_user"])
@pytest.mark.parametrize("subject_kind", ["event_clip", "continuous_segment"])
async def test_non_owner_gets_indistinguishable_not_found(playback_api, actor, subject_kind) -> None:
    response = await playback_api.as_actor(actor).prepare_range(synthetic_subject(subject_kind), 0, 1023)
    assert response.status_code == 404
    assert response.json()["reason_code"] == "resource_unavailable"

async def test_owner_timeline_has_seven_day_low_wide_segments_and_separate_ninety_day_clips(recordings_api) -> None:
    timeline = await recordings_api.as_owner().list_timeline()
    assert all(item.stream_role == "low_wide" for item in timeline.segments)
    assert all(item.immutable_expires_at == item.ended_at + timedelta(days=7) for item in timeline.segments)
    assert all(clip.immutable_expires_at == clip.ended_at + timedelta(days=90) for clip in timeline.event_clips)
    assert all("opaque_storage_token" not in item.model_fields for item in timeline.segments)

@pytest.mark.parametrize("mutation", ["replay", "cross_subject_kind", "cross_subject_id", "cross_view", "edited_range", "wrong_session", "wrong_operation", "expired", "privacy_generation"])
async def test_mutated_or_replayed_grant_returns_no_bytes(media_proxy, valid_grant, mutation) -> None:
    response = await media_proxy.get(valid_grant.mutate(mutation))
    assert response.body == b""
    assert response.status_code in {401, 404, 409, 410}

@pytest.mark.parametrize("mutation", [
    "expired_request", "expiry_equal_to_now", "tampered_request_commitment",
    "replayed_request_id",
])
async def test_prepare_range_rejects_stale_tampered_or_replayed_request_before_reads(
    playback_broker, prepared_request, mutation,
) -> None:
    with pytest.raises(PlaybackRequestRejected):
        await playback_broker.prepare_range(prepared_request.mutate(mutation), owner_actor())
    assert playback_broker.catalog_projection.calls == []
    assert playback_broker.recorder_ipc.calls == []

def test_signed_grant_envelope_is_exact_and_tamper_evident(recorder_grant_ledger, valid_signed_grant) -> None:
    assert set(SignedMediaPlaybackGrantV1.model_fields) == {
        "schema_id", "grant", "algorithm", "signing_key_id", "signature_b64url",
    }
    tampered = valid_signed_grant.model_copy(update={
        "grant": valid_signed_grant.grant.model_copy(update={
            "subject": valid_signed_grant.grant.subject.model_copy(update={"kind": "continuous_segment"}),
        }),
    })
    result = recorder_grant_ledger.verify_without_registering(tampered)
    assert result.reason_code == "media_grant_signature_invalid"
    assert result.bytes_read == 0

async def test_register_receipt_grant_id_substitution_blocks_prepared_response(
    playback_broker, prepared_request, recorder_ipc,
) -> None:
    recorder_ipc.replace_next_register_receipt(grant_id=uuid4())
    with pytest.raises(PlaybackRequestRejected, match="media_grant_registration_receipt_mismatch"):
        await playback_broker.prepare_range(prepared_request, owner_actor())
    assert playback_broker.public_prepared_responses == []

async def test_register_receipt_expiry_substitution_blocks_prepared_response(
    playback_broker, prepared_request, recorder_ipc,
) -> None:
    recorder_ipc.shift_next_register_receipt_grant_expiry(microseconds=1)
    with pytest.raises(PlaybackRequestRejected, match="media_grant_registration_receipt_mismatch"):
        await playback_broker.prepare_range(prepared_request, owner_actor())
    assert playback_broker.public_prepared_responses == []

@pytest.mark.parametrize("processed_delta", [timedelta(0), timedelta(microseconds=1)])
def test_successful_register_receipt_must_be_processed_strictly_before_grant_expiry(
    media_grant_register_receipt_fixture, processed_delta,
) -> None:
    grant_expires_at = media_grant_register_receipt_fixture["grant_expires_at"]
    with pytest.raises(ValidationError, match="media_grant_registration_expired"):
        MediaGrantRegisterReceiptV1.model_validate({
            **media_grant_register_receipt_fixture,
            "processed_at": grant_expires_at + processed_delta,
        })

@pytest.mark.parametrize(("post_ipc_time", "restart"), [
    ("grant_expiry", False),
    ("after_grant_expiry", False),
    ("after_grant_expiry", True),
])
async def test_delayed_register_receipt_never_publishes_expired_grant_even_after_restart(
    playback_broker, prepared_request, post_ipc_time, restart,
) -> None:
    broker = await playback_broker.restart() if restart else playback_broker
    broker.recorder_ipc.advance_trusted_clock_after_next_receipt(to=post_ipc_time)
    with pytest.raises(PlaybackRequestRejected, match="media_grant_registration_expired"):
        await broker.prepare_range(prepared_request, owner_actor())
    assert broker.public_prepared_responses == []

@pytest.mark.parametrize("mutation", [
    "unknown_route_token", "substituted_route_token", "wrong_token_length",
    "wrong_token_digest", "wrong_signed_grant_digest", "replay",
    "replay_after_proxy_restart", "replay_after_core_restart",
])
async def test_playback_route_token_is_exactly_bound_and_claimed_once(
    playback, prepared_range, mutation,
) -> None:
    result = await playback.request(mutate_prepared_route(prepared_range, mutation))
    assert result.body == b""
    assert result.status_code in {401, 404, 409, 410}
    assert result.media_bytes_read == 0

@pytest.mark.parametrize("range_case", [
    "missing", "multiple", "suffix", "open_ended", "closed_but_mismatched",
])
async def test_media_get_requires_one_exact_closed_grant_range(
    playback, prepared_range, range_case,
) -> None:
    result = await playback.request_with_client_range(prepared_range, range_case)
    assert result.body == b""
    assert result.status_code in {400, 404, 409, 416}
    assert result.media_bytes_read == 0
    assert playback.media_proxy.storage_reads == []

async def test_exact_closed_range_is_unchanged_through_every_owner_boundary(
    playback, prepared_range,
) -> None:
    result = await playback.request_with_client_range(prepared_range, "exact_closed")
    assert result.status_code == 206
    assert (
        playback.owner_pre_session_request.client_range_bytes
        == playback.derived_session_tuple.client_range_bytes
        == playback.owner_request_context.client_range_bytes
        == playback.media_grant_claim.requested_range_bytes
        == playback.registered_grant.allowed_range_bytes
    )
    assert (
        playback.media_grant_claim.expires_at
        <= playback.owner_request_context.expires_at
        <= playback.derived_session_tuple.expires_at
    )

@pytest.mark.parametrize(("trusted_now", "accepted"), [
    ("issued_minus_1us", False),
    ("issued_at", True),
    ("expires_minus_1us", True),
    ("expires_at", False),
    ("expires_plus_1us", False),
])
async def test_recorder_claim_uses_inner_deadline_before_ledger_or_storage_read(
    recorder_claim_rig, valid_media_grant_claim, trusted_now, accepted,
) -> None:
    envelope = fresh_ipc_envelope(
        valid_media_grant_claim,
        envelope_issued_at=recorder_claim_rig.clock.at(trusted_now),
    )
    result = await recorder_claim_rig.accept(envelope, trusted_now=trusted_now)
    assert (result.outcome == "claimed") is accepted
    if not accepted:
        assert recorder_claim_rig.grant_ledger.reads == []
        assert recorder_claim_rig.storage_reads == []

async def test_stale_inner_claim_in_fresh_envelope_stays_rejected_after_restart(
    recorder_claim_rig, valid_media_grant_claim,
) -> None:
    for runtime in (recorder_claim_rig, await recorder_claim_rig.restart()):
        stale_at = valid_media_grant_claim.expires_at + timedelta(microseconds=1)
        runtime.clock.set(stale_at)
        envelope = fresh_ipc_envelope(
            valid_media_grant_claim, envelope_issued_at=stale_at,
        )
        result = await runtime.accept(envelope)
        assert result.outcome == "rejected"
        assert runtime.grant_ledger.reads == []
        assert runtime.storage_reads == []

async def test_claim_expiring_after_atomic_claim_is_consumed_without_media_resolution(
    recorder_claim_rig, valid_media_grant_claim,
) -> None:
    recorder_claim_rig.clock.advance_after_ledger_claim(to=valid_media_grant_claim.expires_at)
    result = await recorder_claim_rig.accept(fresh_ipc_envelope(valid_media_grant_claim))
    assert result.outcome == "rejected"
    assert await recorder_claim_rig.grant_ledger.claim_count(valid_media_grant_claim.claim_id) == 1
    assert recorder_claim_rig.catalog_reads == []
    assert recorder_claim_rig.storage_reads == []

@pytest.mark.parametrize("mutation", [
    "route_token_digest", "requested_range_bytes", "owner_session_generation",
    "session_derivation_commitment", "ingress_context_commitment",
    "issued_at", "expires_at",
])
async def test_inner_claim_mutation_without_new_commitment_fails_before_ledger_read(
    recorder_claim_rig, valid_media_grant_claim, mutation,
) -> None:
    tampered = valid_media_grant_claim.mutate_without_recommitting(mutation)
    with pytest.raises(PlaybackRequestRejected, match="media_grant_claim_commitment_invalid"):
        await recorder_claim_rig.accept(fresh_ipc_envelope(tampered))
    assert recorder_claim_rig.grant_ledger.reads == []
    assert recorder_claim_rig.storage_reads == []

@pytest.mark.parametrize("mutation", [
    "claim_issued_at", "claim_expires_at", "claim_commitment", "requested_range_bytes",
])
async def test_proxy_rejects_claim_receipt_not_exactly_bound_to_inner_claim(
    media_proxy, valid_media_grant_claim, valid_media_grant_claim_receipt, mutation,
) -> None:
    with pytest.raises(PlaybackRequestRejected):
        await media_proxy.accept_claim_receipt(
            valid_media_grant_claim,
            valid_media_grant_claim_receipt.mutate(mutation),
        )
    assert media_proxy.storage_reads == []

@pytest.mark.parametrize(("post_receipt_now", "accepted"), [
    ("claim_expires_minus_1us", True),
    ("claim_expires_at", False),
    ("claim_expires_plus_1us", False),
])
async def test_proxy_rechecks_inner_claim_deadline_after_ipc_before_storage_read(
    media_proxy, valid_media_grant_claim, valid_media_grant_claim_receipt,
    post_receipt_now, accepted,
) -> None:
    media_proxy.clock.advance_after_next_receipt(to=post_receipt_now)
    result = await media_proxy.accept_claim_receipt(
        valid_media_grant_claim, valid_media_grant_claim_receipt,
    )
    assert (result.status_code == 206) is accepted
    if not accepted:
        assert media_proxy.storage_reads == []

async def test_proxy_is_read_only_and_recorder_claim_survives_restart(playback, prepared_range) -> None:
    await playback.recorder.restart()
    result = await playback.request(prepared_range)
    assert result.status_code == 206
    assert playback.media_proxy.catalog_writes == []
    assert playback.media_proxy.grant_ledger_writes == []
    assert playback.media_proxy.durable_writes == []
    assert await playback.recorder.grant_ledger.claim_count(prepared_range.route_token_digest) == 1
    replay = await playback.request(prepared_range)
    assert replay.body == b""

def test_ingress_bind_matrix_has_no_lan_8787_or_uncommissioned_8443(network_rig) -> None:
    assert network_rig.listener("127.0.0.1", 8787) == "owner_ingress"
    for address in network_rig.inner_and_outer_interface_addresses:
        assert network_rig.closed(address, 8787)
    for address in ("0.0.0.0", "::", "::1", *network_rig.inner_and_outer_interface_addresses):
        assert network_rig.closed(address, 8443)
    network_rig.commission_private_lan_https(address="192.168.50.20", generation=7)
    assert network_rig.listener("192.168.50.20", 8443) == "owner_ingress"
    assert network_rig.listener("127.0.0.1", 8787) == "owner_ingress"

@pytest.mark.parametrize("mutation", [
    "forwarded", "x_forwarded_host", "x_forwarded_proto", "connection_named_header",
    "duplicate_host", "conflicting_origin", "obs_fold", "cl_te", "duplicate_content_length",
    "absolute_form", "percent_encoded_separator", "double_decode", "path_dot_segment",
    "host_spoof", "origin_spoof", "oversize_header", "oversize_body",
    "missing_media_range", "multiple_media_ranges", "suffix_media_range", "open_ended_media_range",
])
async def test_request_parser_rejects_ambiguous_authority_or_framing_before_uds(ingress, mutation) -> None:
    response = await ingress.request(hostile_request(mutation))
    assert response.status_code == 400
    assert ingress.core_uds.calls == []
    assert ingress.media_uds.calls == []

def test_pre_session_normalized_query_bytes_are_bounded_and_digest_bound(
    owner_pre_session_request_fixture,
) -> None:
    original = decode_b64url(owner_pre_session_request_fixture["normalized_query_b64url"])
    with pytest.raises(ValidationError, match="owner_ingress_pre_session_query_invalid"):
        OwnerIngressPreSessionRequestV1.model_validate({
            **owner_pre_session_request_fixture,
            "normalized_query_b64url": encode_b64url(original + b"&tampered=1"),
        })
    with pytest.raises(ValidationError):
        OwnerIngressPreSessionRequestV1.model_validate({
            **owner_pre_session_request_fixture,
            "normalized_query_b64url": encode_b64url(b"q" * 4097),
        })

@pytest.mark.parametrize("auth_case", ["loopback_dpop", "lan_cookie_csrf"])
async def test_post_takeover_phase1_auth_terminates_at_core_and_derives_exact_tuple(
    ingress, core, auth_case,
) -> None:
    request = phase1_request(auth_case)
    response = await ingress.request(request)
    assert response.status_code in {200, 204}
    assert core.phase1_auth.calls == [request.exact_auth_case]
    assert ingress.created_sessions == []
    assert ingress.last_session_tuple.request_id == request.request_id
    assert (
        ingress.last_session_tuple.normalized_query_digest
        == ingress.last_pre_session_request.normalized_query_digest
    )
    assert ingress.last_session_tuple.expires_at <= ingress.last_session_tuple.issued_at + timedelta(seconds=2)

async def test_post_takeover_phase1_session_bootstrap_returns_only_core_response(ingress, core) -> None:
    request = phase1_request("session_bootstrap")
    response = await ingress.request(request)
    assert response.status_code == 200
    assert response.headers.get("Set-Cookie") == core.last_phase1_response.set_cookie
    assert response.headers["Cache-Control"] == "no-store"
    assert ingress.created_sessions == []
    assert ingress.session_bound_dispatches == []

@pytest.mark.parametrize("status_code", [409, 422, 429, 503])
async def test_post_takeover_phase1_error_status_is_returned_unchanged_without_dispatch(
    ingress, core, status_code,
) -> None:
    core.phase1_auth.return_next_error(status_code=status_code)
    response = await ingress.request(phase1_request("session_bootstrap"))
    assert response.status_code == status_code
    assert response.body == decode_b64url(core.last_phase1_response.body_b64url)
    assert ingress.created_sessions == []
    assert ingress.session_bound_dispatches == []

@pytest.mark.parametrize(
    ("disposition", "tuple_present", "response_present", "valid"),
    [
        (disposition, tuple_present, response_present, (
            (disposition == "forward_authenticated_session" and tuple_present and not response_present)
            or (disposition in {"return_phase1_response", "rejected"} and not tuple_present and response_present)
        ))
        for disposition in ("forward_authenticated_session", "return_phase1_response", "rejected")
        for tuple_present in (False, True)
        for response_present in (False, True)
    ],
)
def test_pre_session_result_disposition_tuple_response_truth_table(
    pre_session_result_fixture, disposition, tuple_present, response_present, valid,
) -> None:
    candidate = pre_session_result_fixture.with_shape(
        disposition=disposition,
        session_tuple=derived_tuple() if tuple_present else None,
        phase1_response=phase1_response() if response_present else None,
    )
    if valid:
        OwnerIngressPreSessionResultV1.model_validate(candidate)
    else:
        with pytest.raises(ValidationError):
            OwnerIngressPreSessionResultV1.model_validate(candidate)

async def test_invalid_pre_session_xor_never_reaches_application_dispatch(
    ingress, pre_session_result_fixture,
) -> None:
    invalid = pre_session_result_fixture.with_shape(
        disposition="return_phase1_response",
        session_tuple=derived_tuple(),
        phase1_response=phase1_response(),
    )
    with pytest.raises(IngressRequestRejected):
        await ingress.accept_pre_session_result_wire(invalid)
    assert ingress.session_bound_dispatches == []

@pytest.mark.parametrize("disposition", [
    "forward_authenticated_session", "return_phase1_response", "rejected",
])
async def test_pre_session_result_is_claimed_once_and_replay_after_restart_never_dispatches(
    ingress, pre_session_result_fixture, disposition,
) -> None:
    result = pre_session_result_fixture.valid_for(disposition)
    first = await ingress.accept_pre_session_result(result)
    expected_dispatches = 1 if disposition == "forward_authenticated_session" else 0
    assert first.session_bound_dispatch_count == expected_dispatches
    restarted = await ingress.restart()
    with pytest.raises(IngressRequestRejected):
        await restarted.accept_pre_session_result(result)
    assert restarted.session_bound_dispatches == []

@pytest.mark.parametrize("fault", [
    "wrong_request", "wrong_listener", "wrong_peer", "wrong_route", "wrong_query_digest",
    "wrong_client_range", "wrong_body_digest",
    "stale_tuple", "replayed_tuple", "forged_tuple_commitment",
])
async def test_ingress_rejects_nonfresh_or_cross_request_core_session_tuple(ingress, core, fault) -> None:
    with pytest.raises(IngressRequestRejected):
        await ingress.accept_derived_tuple(core.derived_tuple().mutate(fault))
    assert ingress.session_bound_dispatches == []

@pytest.mark.parametrize("mutation", [
    "stale_listener_generation", "wrong_listener_kind", "wrong_source_peer", "wrong_route_generation",
    "wrong_query_digest", "wrong_client_range", "wrong_destination", "wrong_uds_peer", "bad_mac",
    "replayed_request_id", "replayed_sequence", "expired",
    "stale_ingress_incarnation", "stale_recipient_incarnation", "replay_after_ingress_restart",
    "replay_after_core_restart_while_ingress_survives", "wrong_owner_session",
    "stale_owner_session_generation", "wrong_owner_session_binding", "revoked_owner_session",
])
async def test_core_and_media_proxy_reject_mutated_or_replayed_ingress_context(recipient, context, mutation) -> None:
    with pytest.raises(IngressRequestRejected):
        await recipient.accept(context.mutate(mutation))
    assert recipient.application_calls == []

@pytest.mark.parametrize("case", [
    "single_closed_range", "partial_write", "slow_reader", "client_disconnect",
    "caller_cancel", "privacy_transition", "grant_expiry", "proxy_restart", "ingress_restart",
])
async def test_media_stream_is_bounded_cancel_safe_no_store_and_never_crosses_core(playback, case) -> None:
    result = await playback.run(case)
    assert result.max_buffered_bytes <= playback.config.max_buffered_bytes
    assert result.core_media_bytes == 0
    assert result.media_proxy_tcp_listeners == ()
    assert result.cache_files == ()
    assert result.body_log_matches == ()
    assert result.finished_or_cancelled_without_orphan

@pytest.mark.parametrize("fault", [
    "core_uds_before_health", "after_core_uds_health", "during_session_revoke", "before_core_tcp_stop",
    "after_core_tcp_stop", "before_ingress_bind", "after_loopback_bind", "after_lan_bind", "route_probe_failure",
])
async def test_takeover_or_rollback_has_exactly_one_complete_listener_owner(upgrade, fault) -> None:
    result = await upgrade.inject_and_recover(fault)
    assert result.listener_owners in {
        frozenset({("core", "127.0.0.1:8787")}),
        frozenset({("owner_ingress", "127.0.0.1:8787")}),
    }
    assert not result.two_listener_window
    assert not result.wildcard_or_direct_core_tcp_after_takeover
    assert result.api_surface_is_complete_or_unavailable_never_partial

async def test_disable_rolls_back_to_prior_core_listener_only_after_ingress_quiesces(installation) -> None:
    await installation.enable_owner_ingress()
    await installation.disable_phase3_playback_and_rollback()
    assert installation.listeners == {("core", "127.0.0.1:8787")}
    assert installation.core.health_ok and not installation.owner_ingress.running

async def test_fresh_login_and_session_refresh_work_after_takeover(installation) -> None:
    await installation.enable_owner_ingress()
    login = await installation.browser.complete_phase1_owner_login()
    assert login.session_created_by == "core"
    assert login.session_tuple_accepted_by == "owner_ingress"
    refreshed = await installation.browser.refresh_phase1_session()
    assert refreshed.session_generation == login.session_generation + 1
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/vision/test_owner_ingress_package_bootstrap.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/security/vision/test_playback_object_auth.py tests/security/vision/test_playback_grants.py tests/security/vision/test_owner_ingress_request_context.py tests/security/vision/test_owner_ingress_network_surface.py tests/integration/vision/test_same_origin_playback.py tests/integration/vision/test_owner_ingress_routing.py tests/performance/vision/test_owner_ingress_backpressure.py apps/recorder/tests/fault/test_transcode_cleanup.py -q`
Expected: FAIL because the owner-ingress package/workspace registration and playback broker/proxy routes are absent.

- [ ] **Step 3: Implement per-range single-use grants and bounded transcode**

Before implementing the listener, bootstrap `tuntun-owner-ingress` with the foundation Python/Hatchling/version pins, merge `apps/owner-ingress` into the current root workspace, declare `tuntun-contracts = { workspace = true }`, add only the exact owner-ingress script, regenerate `uv.lock`, and keep all core/recorder/Reolink packages out of its dependency table. The permanent bootstrap test parses both TOML files, proves the exact member appears once, verifies the exact entry-point target, imports the installed package, and reruns the vision import-boundary checker after this fifth process becomes concrete. Complete the media-proxy composition root without adding cross-package implementation imports. The deployed-entrypoint test runs all four scripts' help/version/start/health/SIGTERM and wrong-account cases with injected resources, verifies wrong account/config rejects before every side effect, verifies rendered `ProgramArguments[0]` resolves inside the exact locked current release, and proves media-proxy/owner-ingress are enabled only within the successful atomic takeover/rollback transition. The lifecycle test fault-injects before/after inventory render, load, each start/health, disabled→enabled transition, core-listener close, durable takeover mark, restart recovery, rollback, and uninstall; every terminal has exactly one listener owner and one inventory generation.

~~~python
async def prepare_range(self, request: PlaybackRangeRequestV1, actor: ActorContext) -> PreparedPlaybackRangeV1:
    actor.require_owner()
    now = self._clock.now()
    if not request.issued_at <= now < request.expires_at:
        raise PlaybackRequestRejected("playback_request_expired")
    self._request_verifier.require_exact_hmac(
        domain="tuntun.playback-range-request.v1",
        canonical_bytes=canonical_playback_range_request_unsigned_bytes(request),
        supplied_commitment=request.request_commitment,
        actor=actor,
    )
    # This durable CAS exact-compares the request ID, commitment, owner session,
    # and deadline. A consumed ID is never reissued, including after restart.
    await self._request_claims.claim_once_exact(
        request_id=request.request_id,
        request_commitment=request.request_commitment,
        owner_session_id=actor.session_id,
        owner_session_generation=actor.session_generation,
        owner_session_binding_commitment=actor.session_binding_commitment,
        expires_at=request.expires_at,
        claimed_at=now,
    )
    await self._privacy.require_camera_outcomes_eligible(
        expected_generation=request.expected_privacy_generation,
    )
    media = await self._catalog_projection.require_owner_visible(request.subject)
    require(media.subject == request.subject)
    require(media.catalog_generation == request.expected_catalog_generation)
    byte_range = request.byte_range.require_within(media.byte_count)
    privacy_generation = await self._privacy.current_generation()
    opaque_grant_id = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    route_token_digest = hashlib.sha256(opaque_grant_id.encode("ascii")).hexdigest()
    grant = MediaPlaybackGrantV1(
        grant_id=uuid4(), route_token_digest=route_token_digest,
        owner_subject_id=actor.subject_id, owner_session_id=actor.session_id,
        owner_session_generation=actor.session_generation,
        owner_session_binding_commitment=actor.session_binding_commitment,
        subject=media.subject, allowed_operation="playback",
        allowed_range_bytes=byte_range, issued_at=now, expires_at=now + timedelta(seconds=60),
        single_use=True, policy_version=actor.policy_version,
        privacy_generation=privacy_generation,
        parameter_commitment=self._commitments.for_playback(
            actor, media, byte_range, privacy_generation,
        ),
    )
    signature = await self._signer.sign(
        domain="tuntun.media-playback-grant.v1",
        payload=canonical_vision_bytes(grant),
    )
    signed_grant = SignedMediaPlaybackGrantV1(
        grant=grant,
        algorithm="Ed25519",
        signing_key_id=signature.key_id,
        signature_b64url=signature.value_b64url,
    )
    signed_grant_digest = hashlib.sha256(canonical_vision_bytes(signed_grant)).hexdigest()
    register = MediaGrantRegisterV1(
        registration_id=uuid4(),
        signed_grant_digest=signed_grant_digest,
        signed_grant=signed_grant,
        issued_at=grant.issued_at,
        expires_at=grant.expires_at,
        registration_commitment=self._commitments.for_grant_registration(signed_grant_digest, grant),
    )
    receipt = await self._recorder_ipc.register_grant(register)
    post_registration_now = self._clock.now()
    if (
        receipt.outcome not in {"registered", "already_registered"}
        or receipt.registration_id != register.registration_id
        or receipt.grant_id != signed_grant.grant.grant_id
        or receipt.signed_grant_digest != signed_grant_digest
        or receipt.grant_expires_at != signed_grant.grant.expires_at
    ):
        raise PlaybackRequestRejected("media_grant_registration_receipt_mismatch")
    if not receipt.processed_at <= post_registration_now < receipt.grant_expires_at:
        raise PlaybackRequestRejected("media_grant_registration_expired")
    return PreparedPlaybackRangeV1(
        grant_id=grant.grant_id,
        opaque_grant_id=opaque_grant_id,
        route_token_digest=route_token_digest,
        signed_grant_digest=signed_grant_digest,
        issued_at=grant.issued_at,
        expires_at=grant.expires_at,
    )

async def recorder_claim_registered_range(
    self, envelope: VisionIpcEnvelopeV1,
) -> MediaGrantClaimReceiptV1:
    claim = require_payload(envelope, MediaGrantClaimV1)
    # Envelope freshness is independent: inspect the inner deadline with a trusted
    # clock before the durable grant ledger, catalog, or storage can be touched.
    now = self._clock.now()
    if not claim.issued_at <= now < claim.expires_at:
        return self._rejected_claim_receipt_echoing_request(claim, "media_claim_expired", now)
    self._claim_verifier.require_exact_hmac(
        domain="tuntun.media-grant-claim.v1",
        canonical_bytes=canonical_media_grant_claim_unsigned_bytes(claim),
        supplied_commitment=claim.claim_commitment,
    )
    claim_now = self._clock.now()
    if not claim.issued_at <= claim_now < claim.expires_at:
        return self._rejected_claim_receipt_echoing_request(claim, "media_claim_expired", claim_now)
    row = await self._grant_ledger.claim_once_exact(
        route_token_digest=claim.route_token_digest,
        owner_session_id=claim.owner_session_id,
        owner_session_generation=claim.owner_session_generation,
        owner_session_binding_commitment=claim.owner_session_binding_commitment,
        session_derivation_id=claim.session_derivation_id,
        session_derivation_commitment=claim.session_derivation_commitment,
        ingress_request_id=claim.ingress_request_id,
        ingress_context_commitment=claim.ingress_context_commitment,
        requested_range_bytes=claim.requested_range_bytes,
        claim_id=claim.claim_id,
        claim_commitment=claim.claim_commitment,
        claim_issued_at=claim.issued_at,
        claim_expires_at=claim.expires_at,
        trusted_clock=self._clock,
    )
    require(row.allowed_range_bytes == claim.requested_range_bytes)
    before_resolution = self._clock.now()
    if not claim.issued_at <= before_resolution < claim.expires_at:
        # The durable one-use claim remains consumed, but no catalog/storage token
        # or media bytes are resolved after the inner authority expires.
        return self._rejected_claim_receipt_echoing_request(
            claim, "media_claim_expired_after_claim", before_resolution,
        )
    media = await self._catalog.resolve_claimed_subject(row.subject, row.catalog_generation)
    require(media.subject == row.subject)
    after_resolution = self._clock.now()
    if not claim.issued_at <= after_resolution < claim.expires_at:
        return self._rejected_claim_receipt_echoing_request(
            claim, "media_claim_expired_after_resolution", after_resolution,
        )
    return self._claimed_receipt(
        claim=claim,
        row=row,
        opaque_storage_token=media.opaque_storage_token,
        processed_at=after_resolution,
    )

async def proxy_claim_and_read_exact_range(
    self, context: OwnerIngressRequestContextV1, raw_route_token: str,
) -> AsyncIterator[bytes]:
    requested_range = require_not_none(context.client_range_bytes)
    claim_issued_at = self._clock.now()
    if not context.issued_at <= claim_issued_at < context.expires_at:
        raise PlaybackRequestRejected("owner_ingress_context_expired")
    claim = self._claim_factory.for_authenticated_context(
        context=context,
        route_token_digest=hashlib.sha256(raw_route_token.encode("ascii")).hexdigest(),
        requested_range_bytes=requested_range,
        issued_at=claim_issued_at,
        expires_at=min(claim_issued_at + timedelta(seconds=2), context.expires_at),
    )
    send_now = self._clock.now()
    if not claim.issued_at <= send_now < claim.expires_at:
        raise PlaybackRequestRejected("media_claim_expired")
    receipt = await self._recorder_ipc.claim_grant(claim)
    post_receipt_now = self._clock.now()
    self._receipt_verifier.require_exact_commitment(receipt)
    expected = (
        claim.claim_id, claim.ingress_context_commitment,
        claim.issued_at, claim.expires_at, claim.claim_commitment,
        claim.route_token_digest, claim.requested_range_bytes,
    )
    carried = (
        receipt.claim_id, receipt.ingress_context_commitment,
        receipt.claim_issued_at, receipt.claim_expires_at, receipt.claim_commitment,
        receipt.route_token_digest, receipt.requested_range_bytes,
    )
    require(carried == expected)
    require(receipt.outcome == "claimed")
    require(receipt.allowed_range_bytes == requested_range)
    require(receipt.processed_at <= post_receipt_now < receipt.claim_expires_at)
    assert receipt.expires_at is not None
    require(post_receipt_now < receipt.expires_at)
    # No media read is reachable until the client range, inner claim deadline,
    # grant range/expiry, exact receipt echo, and authenticated commitment agree.
    return self._range_reader.read(
        require_not_none(receipt.opaque_storage_token), requested_range,
        require_first_read_before=min(receipt.claim_expires_at, receipt.expires_at),
        trusted_clock=self._clock,
    )
~~~

The core never opens or relays media. Owner ingress strips and rejects every `Forwarded`, `X-Forwarded-*`, proxy, and client-nominated hop-by-hop header; rejects duplicates/conflicts, obs-fold, CL/TE ambiguity, absolute-form targets, dot segments, percent/double-decode ambiguity, and unbounded fields; then parses and normalizes Host, Origin, path, query, framing, body, and any media `Range` exactly once. A media route requires exactly one closed inclusive `Range: bytes=start-end`; a missing, multiple, suffix, open-ended, malformed, or overflowed range is rejected before either UDS, while any Range on a non-media route is rejected. It classifies the accepted listener as `loopback_http` or `commissioned_lan_https`, binds its current listener generation/commitment and source-peer commitment, resolves one generated route ID/generation, and first sends a claimed `owner_pre_session_request` over pinned peer-auth UDS. That closed forward carries only the bounded exact Phase 1 Authorization+DPoP, cookie+CSRF, or bootstrap material, at-most-4 KiB normalized query bytes plus digest, the optional normalized inclusive client range, and exact bounded body required by the already-accepted Phase 1 auth/session implementation; it is never logged, persisted, sent to recorder/media proxy, or interpreted as authority by ingress. Core reconstructs WebAuthn/RP/origin authority from the server-derived listener context, terminates authentication, and returns a claimed `owner_pre_session_result`. For Phase 1 challenge/login/refresh/logout, the result contains the bounded no-store core response so ingress can return the core-created cookie/token/body without recreating auth behavior; for a protected application request, it contains only a ≤2-second `DerivedOwnerSessionTupleV1` bound to the exact request/listener/peer/route/query digest/client range/body digest. Only the latter disposition may construct `AuthenticatedOwnerIngressRequestV1` with that exact tuple, exact client range, and derivation commitment, fresh ingress/recipient boot-incarnation UUIDs, and an atomically claimed sequence. Core or media proxy rechecks the derivation, listener generation, incarnations, query digest, client range, body digest, session generation and prepared mutation before dispatch. Wrong peer, generation, incarnation, route, query, range, MAC, sequence, request ID, body digest, tuple, or deadline—including replay after either side restarts—rejects before application dispatch. Direct network access to core/media proxy is absent.

For a protected route, core retains the already-forwarded normalized query and bounded body only in a per-request RAM slot keyed by the request/query/body commitments until the matching session-bound context arrives; dispatch atomically claims and drains that slot, while rejection, timeout, disconnect, or either process restart destroys it. Auth/bootstrap responses bypass application dispatch and are returned exactly once. Thus ingress never recreates Phase 1 authentication and core never processes the same login or mutation twice.

Takeover from an accepted Phase 1/2 installation is a reversible serialized deployment transition, never two independently started listeners. Upgrade first provisions peer-auth core non-media UDS, the closed pre-session/session-tuple exchange, pinned ingress keys/incarnations, and complete bootstrap/login/refresh/logout plus protected-route health probes while core still owns its old TCP listeners. It then quiesces admission, drains bounded requests, revokes active HTTP/LAN sessions, atomically marks the takeover generation, stops and proves closure of core 8787/8443, starts owner ingress on loopback 8787 and only the still-current commissioned 8443 binding, and proves a fresh post-takeover Phase 1 owner session can be created at core before probing every generated non-media route plus exact media separation and enabling playback/readiness. Any failure before the takeover mark leaves core unchanged; any later failure keeps admission closed and either completes ingress or first closes every ingress handle and then restores the prior core listener/config. Crash/restart consults the durable generation under one lifecycle lock, so two listener owners, wildcard binds, direct core TCP after takeover, partially routed APIs, and a deployment that can validate only revoked pre-takeover sessions are unreachable. Disabling Phase 3 playback performs the inverse drain/close/prove sequence before restoring the Phase 1 core listener.

Core authorizes one exact `PlaybackSubjectV1` range, signs the domain-separated canonical `MediaPlaybackGrantV1`, sends it only inside `media_grant_register` to recorder, and returns `PreparedPlaybackRangeV1` only after a matching receipt echoes the exact grant expiry and a trusted post-IPC time sample remains strictly before it. Recorder verifies the pinned core key/domain/signature, exact current clip-view or unexpired `low_wide` segment, catalog/privacy/session-binding commitments and range; it then compiles the minimal durable ledger row and discards the signed envelope/raw owner session identity. A later exact `/api/v1/media/{opaque_grant_id}` request is mapped by owner ingress directly to media-proxy UDS with the authenticated request context; no other media-like path is accepted and no media body crosses core UDS. Read-only proxy validates that fresh context and its derivation commitment, binds the normalized client range into the claim, hashes the exact path token, constructs a commitment-bound inner claim whose expiry is the earlier of two seconds and the owner-context deadline, samples trusted time again immediately before IPC, and sends `media_grant_claim` with the exact range and ingress request/session-binding commitments. Independently fresh outer-envelope time cannot revive the inner claim: recorder first requires `claim.issued_at <= trusted_now < claim.expires_at` before any ledger, catalog, or storage read, verifies the claim commitment over its canonical unsigned bytes, rechecks the inner deadline, constant-time compares the requested range with the stored grant-authorized range and the stored route/session commitments, and atomically claims the durable row. If time crosses the inner deadline after the one-use CAS, the claim remains consumed but no catalog/storage token or media bytes are resolved. Otherwise recorder returns one authenticated `media_grant_claim_receipt` echoing the exact inner issued time, expiry, commitment and requested range and containing the opaque storage token, exact subject/grant range and original grant expiry; restart preserves claimed/unclaimed truth and never reconstructs or reissues a token. Proxy exact-compares every echo, requires the receipt's grant range to equal the normalized client range, verifies the receipt commitment and samples trusted time after IPC, requiring both claim and grant still live, while the range reader repeats the same trusted deadline check at its first media read, then streams only that exact closed inclusive range through a fixed bounded backpressure window without any durable write. A missing/multiple/suffix/open-ended/mismatched range, unknown/substituted/malformed token, key, receipt, signature replay, cross-subject/path/query mutation, or any authority-field mutation returns zero bytes. Slow readers, disconnect, caller cancellation, privacy transition, expiry, ingress/proxy/recorder crash, and partial writes cancel/drain owned work and delete transient output; they do not make the one-use token reusable. Responses are `Cache-Control: no-store` with nosniff/CSP; body bytes, tokens, and paths never enter cache/log/metrics/crash output. The player requests a new grant for each later range. If the browser cannot play the native codec, an explicit owner operation starts one lower-priority, audio-free transcode in an owner-only temporary root; active voice, privacy, cancellation, expiry, quota, or crash destroys it.

- [ ] **Step 4: Run green, route-origin scan, and transcode cleanup matrix**

Run:

~~~bash
uv lock
uv sync --all-packages --locked
uv run --locked --offline --no-sync python -c 'import tuntun_owner_ingress; assert tuntun_owner_ingress.__version__ == "0.1.0.dev0"'
uv run --locked --offline --no-sync tuntun-camera-source --help
uv run --locked --offline --no-sync tuntun-recorder --help
uv run --locked --offline --no-sync tuntun-media-proxy --help
uv run --locked --offline --no-sync tuntun-media-proxy --version
uv run --locked --offline --no-sync tuntun-owner-ingress --help
uv run --locked --offline --no-sync tuntun-owner-ingress --version
uv run --locked --offline --no-sync pytest tests/unit/vision/test_owner_ingress_package_bootstrap.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_phase3_boot_composition.py tests/security/vision/test_playback_object_auth.py tests/security/vision/test_playback_grants.py tests/security/vision/test_owner_ingress_request_context.py tests/security/vision/test_owner_ingress_network_surface.py tests/integration/vision/test_same_origin_playback.py tests/integration/vision/test_owner_ingress_routing.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py tests/performance/vision/test_owner_ingress_backpressure.py apps/recorder/tests/fault/test_transcode_cleanup.py -q
plutil -lint ops/launchd/phase3/com.tuntun.camera-source.plist ops/launchd/phase3/com.tuntun.recorder.plist ops/launchd/phase3/com.tuntun.media-proxy.plist ops/launchd/phase3/com.tuntun.owner-ingress.plist
shellcheck deploy/macos/install.sh deploy/macos/preflight.sh deploy/macos/upgrade.sh deploy/macos/rollback.sh deploy/macos/uninstall.sh
uv run --locked --offline --no-sync python scripts/scan_network_surface.py --require-listener 127.0.0.1:8787=owner_ingress --forbid-lan-port 8787 --optional-exact-commissioned-private-lan-port 8443=owner_ingress --forbid-wildcard --forbid-ipv6 --forbid-core-tcp --forbid-media-proxy-tcp --forbid-camera-ports
uv run --locked --offline --no-sync python scripts/scan_browser_artifacts.py --forbid media_url,credential,stream_url,storage_path,reusable_token
uv run --locked --offline --no-sync python scripts/check_import_boundaries.py --domain vision
uv run --locked --offline --no-sync ruff check apps/owner-ingress/src apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/services/vision/playback_broker.py apps/recorder/src/tuntun_recorder/media apps/core/src/tuntun_core/api/routes/cameras.py apps/core/src/tuntun_core/api/vision_dtos.py tests/unit/vision/test_owner_ingress_package_bootstrap.py tests/security/vision tests/integration/vision tests/fault/vision tests/performance/vision
uv run --locked --offline --no-sync mypy apps/owner-ingress/src apps/core/src apps/recorder/src
uv lock --check
uv build --offline --wheel --package tuntun-owner-ingress --out-dir var/build-smoke/phase3/owner-ingress
uv lock --check
~~~

Expected: PASS; loopback remains available without LAN mode, only an exact commissioned private-LAN 8443 bind may appear, owner playback succeeds range by range through bounded ingress, every other actor/origin/parser/context mutation receives zero bytes/existence detail, core/media proxy own no TCP listener or media-byte path, and transcode leaves no durable cache.

- [ ] **Step 5: Commit**

~~~bash
git add pyproject.toml uv.lock apps/owner-ingress/pyproject.toml apps/owner-ingress/src/tuntun_owner_ingress/__init__.py apps/owner-ingress/src/tuntun_owner_ingress/parser.py apps/owner-ingress/src/tuntun_owner_ingress/request_context.py apps/owner-ingress/src/tuntun_owner_ingress/router.py apps/owner-ingress/src/tuntun_owner_ingress/streaming.py apps/owner-ingress/src/tuntun_owner_ingress/listeners.py apps/owner-ingress/src/tuntun_owner_ingress/service.py apps/owner-ingress/src/tuntun_owner_ingress/entrypoint.py apps/recorder/src/tuntun_recorder/entrypoints/media_proxy.py ops/launchd/phase3/com.tuntun.media-proxy.plist ops/launchd/phase3/com.tuntun.owner-ingress.plist ops/services/phase3-camera-source.v1.json ops/services/phase3-recorder.v1.json ops/services/phase3-media-proxy.v1.json ops/services/phase3-owner-ingress.v1.json ops/routes/owner-ingress-routes.v1.json apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/deploy/lifecycle.py deploy/macos/com.tuntun.core.plist deploy/macos/install.sh deploy/macos/preflight.sh deploy/macos/upgrade.sh deploy/macos/rollback.sh deploy/macos/uninstall.sh apps/core/src/tuntun_core/services/vision/playback_broker.py apps/recorder/src/tuntun_recorder/media apps/core/src/tuntun_core/api/routes/cameras.py apps/core/src/tuntun_core/api/vision_dtos.py tests/unit/vision/test_owner_ingress_package_bootstrap.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_phase3_boot_composition.py tests/security/vision/test_playback_object_auth.py tests/security/vision/test_playback_grants.py tests/security/vision/test_owner_ingress_request_context.py tests/security/vision/test_owner_ingress_network_surface.py tests/integration/vision/test_same_origin_playback.py tests/integration/vision/test_owner_ingress_routing.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py tests/performance/vision/test_owner_ingress_backpressure.py apps/recorder/tests/fault/test_transcode_cleanup.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(vision): add owner-only same-origin playback"
~~~

### Task 18: Add encrypted incident export, exact early deletion, and copy disclosure

**Depends on:** Tasks 03–05 and 15–17.
**Gate contribution:** P3-3 data lifecycle.
**Estimated effort:** 1.5 person-days.

**Files:**
- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Modify: `apps/core/pyproject.toml`
- Modify: `apps/recorder/pyproject.toml`
- Create: `packages/secure-archive/pyproject.toml`
- Create: `packages/secure-archive/src/tuntun_secure_archive/__init__.py`
- Create: `packages/secure-archive/src/tuntun_secure_archive/writer.py`
- Modify: `apps/core/src/tuntun_core/services/data_lifecycle/backup_format.py`
- Create: `apps/recorder/src/tuntun_recorder/media/export.py`
- Modify: `apps/core/src/tuntun_core/services/vision/playback_broker.py`
- Create: `scripts/scan_export_artifacts.py`
- Create: `tests/integration/vision/test_clip_export_delete.py`
- Create: `tests/security/vision/test_export_encryption.py`
- Create: `tests/fault/vision/test_export_delete_transitions.py`
- Create: `tests/unit/vision/test_copy_disclosure.py`
- Create: `tests/security/vision/test_export_artifact_scanner.py`
- Create: `tests/unit/vision/test_secure_archive_package_bootstrap.py`
- Create: `docs/operations/phase3-playback-export-delete.md`

**Interfaces:** This is the first owner of leaf distribution `tuntun-secure-archive`: register exact root workspace member `packages/secure-archive` once, expose `tuntun_secure_archive.__version__: str = "0.1.0.dev0"`, and update the root lock. The leaf has no app/integration workspace dependency and imports only directly required cryptographic/container primitives under their established constraints. Add one-way `tuntun-secure-archive = { workspace = true }` dependencies to core and recorder by merging, never replacing, their dependency/source tables; the leaf must never import either consumer. Extracts the already-tested Phase 1 bounded recipient-encrypted archive primitive into `tuntun_secure_archive` without changing `TTBK1` behavior. Produces recorder-local `VisionExportWriter.write(clip, views, recipient_public_key)`, exact `camera.clip.export` and `camera.clip.delete` prepared operations compiled by core into commitment-bound `ClipExportRequestV1`/`ClipDeleteRequestV1` with their own ≤5-second inner deadlines, their content-minimized receipts, one-time ciphertext download, and `EffectiveCopyProjection`. The only cross-process authority paths are `clip_export_request -> clip_export_receipt` and `clip_delete_request -> clip_delete_receipt`; recorder owns all catalog/job/media effects. Both core sender and recorder receiver require `issued_at <= trusted_now < expires_at`; the recorder performs that inner check before any command/catalog/media I/O and rechecks at the first media read or atomic unlink, so outer-envelope freshness, IPC delay, or restart cannot revive expired authority. `scan_export_artifacts.py` exposes a nofollow, bounded scanner over one explicit test-artifact root. It rejects missing, extra, symlink/special, changing, duplicate, unmanifested, plaintext-sentinel, malformed-container, digest-mismatched, or authentication-failing artifacts; it validates `TTBK1` authentication with the fixed synthetic test recipient and prints paths/reason codes only, never keys or decrypted content.

- [ ] **Step 1: Write red fresh-passkey, encrypted-only, crash, and residual-copy tests**

~~~python
async def test_export_is_bound_to_clip_views_recipient_and_fresh_passkey(export_service, clip, passkey) -> None:
    prepared = await export_service.prepare(clip.id, views=("wide",), recipient_id="recipient_synth_01")
    result = await export_service.execute(prepared.id, passkey.for_binding(prepared.binding))
    assert result.content_type == "application/vnd.tuntun.vision-export"
    assert clip.synthetic_plaintext_sentinel not in result.download_bytes

async def test_early_delete_does_not_claim_owner_export_removed(delete_service, exported_clip, passkey) -> None:
    receipt = await delete_service.delete(exported_clip.delete_request(), passkey)
    assert receipt.managed_media_deleted is True
    assert receipt.external_copies == ("owner_export",)
    assert receipt.physical_flash_erasure_claimed is False

async def test_export_and_delete_use_closed_recorder_ipc_authority(operation_rig, authorized_clip) -> None:
    await operation_rig.export(authorized_clip)
    await operation_rig.delete(authorized_clip)
    assert operation_rig.ipc.message_types == (
        "clip_export_request", "clip_export_receipt",
        "clip_delete_request", "clip_delete_receipt",
    )
    assert operation_rig.core.catalog_writes == []

@pytest.mark.parametrize(("operation", "mutation"), [
    ("export", "command_id"), ("export", "clip_id"), ("export", "clip_generation"),
    ("export", "catalog_generation"), ("export", "views"), ("export", "recipient_key_id"),
    ("export", "recipient_public_key_digest"), ("export", "request_commitment"),
    ("export", "request_digest"), ("export", "download_expiry_policy"),
    ("delete", "command_id"), ("delete", "clip_id"), ("delete", "clip_generation"),
    ("delete", "catalog_generation"), ("delete", "views"), ("delete", "expected_view_count"),
    ("delete", "expected_managed_byte_count"), ("delete", "expected_immutable_expires_at"),
    ("delete", "request_commitment"), ("delete", "request_digest"),
])
async def test_receipt_substitution_replay_or_restart_never_creates_public_result(
    operation_rig, authorized_clip, operation, mutation,
) -> None:
    request, receipt = await operation_rig.recorder_only_result(authorized_clip, operation)
    candidate = receipt.mutate(mutation)
    for runtime in (operation_rig, await operation_rig.restart()):
        with pytest.raises(OperationReceiptRejected):
            await runtime.accept_receipt(request, candidate)
        assert runtime.public_downloads == []
        assert runtime.public_delete_receipts == []
    await operation_rig.accept_receipt(request, receipt)
    with pytest.raises(OperationReceiptRejected):
        await operation_rig.accept_receipt(request, receipt)
    assert operation_rig.public_result_count(request.command_id) == 1

@pytest.mark.parametrize(("post_receipt_time", "accepted"), [
    ("download_expires_minus_1us", True),
    ("download_expires_at", False),
    ("download_expires_plus_1us", False),
])
async def test_delayed_export_receipt_cannot_publish_expired_download_after_restart(
    operation_rig, authorized_clip, post_receipt_time, accepted,
) -> None:
    request, receipt = await operation_rig.recorder_only_result(authorized_clip, "export")
    runtime = await operation_rig.restart()
    runtime.core_clock.set_relative_to(receipt, post_receipt_time)
    if accepted:
        await runtime.accept_receipt(request, receipt)
        assert runtime.public_downloads != []
    else:
        with pytest.raises(OperationReceiptRejected, match="clip_export_download_expired"):
            await runtime.accept_receipt(request, receipt)
        assert runtime.public_downloads == []

@pytest.mark.parametrize("operation", ["export", "delete"])
@pytest.mark.parametrize(("trusted_now", "accepted"), [
    ("issued_minus_1us", False),
    ("issued_at", True),
    ("expires_minus_1us", True),
    ("expires_at", False),
    ("expires_plus_1us", False),
])
async def test_core_checks_inner_operation_deadline_before_recorder_ipc(
    operation_rig, authorized_clip, operation, trusted_now, accepted,
) -> None:
    request = operation_rig.request_for(authorized_clip, operation)
    operation_rig.core_clock.set_relative_to(request, trusted_now)
    if accepted:
        result = await operation_rig.core_execute(request)
        assert result.outcome in {"applied", "already_applied"}
    else:
        with pytest.raises(OperationRequestExpired):
            await operation_rig.core_execute(request)
        assert operation_rig.recorder_ipc.calls == []

@pytest.mark.parametrize("operation", ["export", "delete"])
async def test_sender_rechecks_deadline_after_authorization_immediately_before_ipc(
    operation_rig, authorized_clip, operation,
) -> None:
    request = operation_rig.request_for(authorized_clip, operation)
    operation_rig.core_clock.advance_after_authorization(to=request.expires_at)
    with pytest.raises(OperationRequestExpired):
        await operation_rig.core_execute(request)
    assert operation_rig.recorder_ipc.calls == []

@pytest.mark.parametrize("operation", ["export", "delete"])
@pytest.mark.parametrize(("trusted_now", "accepted"), [
    ("issued_minus_1us", False),
    ("issued_at", True),
    ("expires_minus_1us", True),
    ("expires_at", False),
    ("expires_plus_1us", False),
])
async def test_recorder_checks_inner_operation_deadline_before_catalog_or_media_io(
    operation_rig, authorized_clip, operation, trusted_now, accepted,
) -> None:
    request = operation_rig.request_for(authorized_clip, operation)
    envelope = fresh_ipc_envelope(request, envelope_issued_at=operation_rig.recorder_clock.now())
    receipt = await operation_rig.recorder_accept(envelope, trusted_now=trusted_now)
    assert (receipt.outcome in {"applied", "already_applied"}) is accepted
    if not accepted:
        assert operation_rig.recorder.catalog_reads == []
        assert operation_rig.recorder.media_reads == []
        assert operation_rig.recorder.unlink_calls == []
        assert operation_rig.recorder.command_claim_writes == []

@pytest.mark.parametrize("operation", ["export", "delete"])
async def test_delayed_ipc_with_stale_inner_request_and_fresh_envelope_fails_after_restart(
    operation_rig, authorized_clip, operation,
) -> None:
    request = operation_rig.request_for(authorized_clip, operation)
    for runtime in (operation_rig, await operation_rig.restart_recorder()):
        stale_at = request.expires_at + timedelta(microseconds=1)
        runtime.recorder_clock.set(stale_at)
        envelope = fresh_ipc_envelope(request, envelope_issued_at=stale_at)
        receipt = await runtime.recorder_accept(envelope)
        assert receipt.outcome == "rejected"
        assert runtime.recorder.catalog_reads == []
        assert runtime.recorder.media_reads == []
        assert runtime.recorder.unlink_calls == []
        assert runtime.recorder.command_claim_writes == []

@pytest.mark.parametrize("operation", ["export", "delete"])
async def test_deadline_crossing_during_receiver_validation_has_no_media_effect(
    operation_rig, authorized_clip, operation,
) -> None:
    request = operation_rig.request_for(authorized_clip, operation)
    operation_rig.recorder_clock.advance_after_initial_deadline_check(to=request.expires_at)
    receipt = await operation_rig.recorder_accept(fresh_ipc_envelope(request))
    assert receipt.outcome == "rejected"
    assert operation_rig.recorder.catalog_reads == []
    assert operation_rig.recorder.media_reads == []
    assert operation_rig.recorder.unlink_calls == []
    assert operation_rig.recorder.command_claim_writes == []
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/vision/test_secure_archive_package_bootstrap.py tests/integration/vision/test_clip_export_delete.py tests/security/vision/test_export_encryption.py tests/fault/vision/test_export_delete_transitions.py tests/unit/vision/test_copy_disclosure.py tests/security/vision/test_export_artifact_scanner.py -q`
Expected: FAIL because the secure-archive distribution/workspace links and vision export/delete services are absent.

- [ ] **Step 3: Extract the bounded writer and implement exact operations**

Bootstrap the leaf before moving imports: create its foundation-aligned Python/Hatchling/version metadata, merge its root workspace member, add the two consumer dependencies/workspace-source entries, and regenerate `uv.lock`. `test_secure_archive_package_bootstrap.py` parses all four TOML files, imports the installed leaf, proves the member appears once, proves both consumers point to the workspace leaf, rejects any reverse app/integration dependency, and verifies the Phase 1 backup module and recorder export module import the shared leaf rather than copy its implementation.

~~~python
async def export(self, request: ClipExportRequestV1, grant: ActionGrant) -> ClipExportReceiptV1:
    now = self._clock.now()
    if not request.issued_at <= now < request.expires_at:
        raise OperationRequestExpired("clip_export_request_expired")
    grant.require_exact_binding(request.binding())
    self._request_verifier.require_exact_hmac(
        domain="tuntun.clip-export-request.v1",
        canonical_bytes=canonical_clip_export_request_unsigned_bytes(request),
        supplied_commitment=request.request_commitment,
    )
    if not request.issued_at <= self._clock.now() < request.expires_at:
        raise OperationRequestExpired("clip_export_request_expired")
    receipt = await self._recorder_ipc.export_clip(request)
    expected = (
        request.command_id, request.clip_id, request.clip_generation, request.catalog_generation,
        request.views, request.recipient_key_id,
        hashlib.sha256(decode_b64url(request.recipient_public_key_b64url)).hexdigest(),
        request.request_commitment, request.request_digest,
    )
    carried = (
        receipt.command_id, receipt.clip_id, receipt.clip_generation, receipt.catalog_generation,
        receipt.views, receipt.recipient_key_id, receipt.recipient_public_key_digest,
        receipt.request_commitment, receipt.request_digest,
    )
    require(carried == expected)
    require(receipt.outcome in {"applied", "already_applied"})
    require(receipt.download_single_use is True)
    assert receipt.download_expires_at is not None
    post_receipt_now = self._clock.now()
    require(
        receipt.processed_at <= post_receipt_now < receipt.download_expires_at
        <= receipt.processed_at + timedelta(minutes=5),
        "clip_export_download_expired",
    )
    await self._receipt_claims.claim_once(request.command_id, request.request_digest, receipt.receipt_commitment)
    return receipt

async def early_delete(self, request: ClipDeleteRequestV1, grant: ActionGrant) -> ClipDeleteReceiptV1:
    now = self._clock.now()
    if not request.issued_at <= now < request.expires_at:
        raise OperationRequestExpired("clip_delete_request_expired")
    grant.require_exact_binding(request.binding_with_count_size_expiry())
    self._request_verifier.require_exact_hmac(
        domain="tuntun.clip-delete-request.v1",
        canonical_bytes=canonical_clip_delete_request_unsigned_bytes(request),
        supplied_commitment=request.request_commitment,
    )
    if not request.issued_at <= self._clock.now() < request.expires_at:
        raise OperationRequestExpired("clip_delete_request_expired")
    receipt = await self._recorder_ipc.delete_clip(request)
    expected = (
        request.command_id, request.clip_id, request.clip_generation, request.catalog_generation,
        request.views, request.expected_view_count, request.expected_managed_byte_count,
        request.expected_immutable_expires_at, request.request_commitment, request.request_digest,
    )
    carried = (
        receipt.command_id, receipt.clip_id, receipt.clip_generation, receipt.catalog_generation,
        receipt.views, receipt.expected_view_count, receipt.expected_managed_byte_count,
        receipt.expected_immutable_expires_at, receipt.request_commitment, receipt.request_digest,
    )
    require(carried == expected)
    require(receipt.outcome in {"applied", "already_applied"})
    require(receipt.deleted_view_count == request.expected_view_count)
    require(receipt.deleted_byte_count == request.expected_managed_byte_count)
    await self._receipt_claims.claim_once(request.command_id, request.request_digest, receipt.receipt_commitment)
    return receipt

async def recorder_accept_export(
    self, envelope: VisionIpcEnvelopeV1,
) -> ClipExportReceiptV1:
    request = require_payload(envelope, ClipExportRequestV1)
    # A fresh outer IPC envelope does not extend the five-second inner authority.
    received_at = self._clock.now()
    if not request.issued_at <= received_at < request.expires_at:
        return self._rejected_export_receipt_without_io(request, received_at)
    self._request_verifier.require_exact_hmac(
        domain="tuntun.clip-export-request.v1",
        canonical_bytes=canonical_clip_export_request_unsigned_bytes(request),
        supplied_commitment=request.request_commitment,
    )
    before_catalog = self._clock.now()
    if not request.issued_at <= before_catalog < request.expires_at:
        return self._rejected_export_receipt_without_io(request, before_catalog)
    clip = await self._catalog.require_exact_export_source(
        request.clip_id, request.clip_generation, request.catalog_generation,
        request.views, request.expected_managed_byte_count,
        request.expected_immutable_expires_at,
    )
    before_media_read = self._clock.now()
    if not request.issued_at <= before_media_read < request.expires_at:
        return self._rejected_export_receipt_without_media(request, before_media_read)
    job = await self._export_jobs.begin_once_exact(
        command_id=request.command_id,
        request_digest=request.request_digest,
        request_commitment=request.request_commitment,
        authorized_at=before_media_read,
        authority_expires_at=request.expires_at,
        trusted_clock=self._clock,
    )
    return await self._export_writer.write_encrypted_exact(
        job, clip, request,
        require_first_read_before=request.expires_at,
        trusted_clock=self._clock,
    )

async def recorder_accept_delete(
    self, envelope: VisionIpcEnvelopeV1,
) -> ClipDeleteReceiptV1:
    request = require_payload(envelope, ClipDeleteRequestV1)
    received_at = self._clock.now()
    if not request.issued_at <= received_at < request.expires_at:
        # This branch constructs an authenticated in-memory rejection only: no
        # command ledger, catalog/media read, journal write, or unlink is allowed.
        return self._rejected_delete_receipt_without_io(request, received_at)
    self._request_verifier.require_exact_hmac(
        domain="tuntun.clip-delete-request.v1",
        canonical_bytes=canonical_clip_delete_request_unsigned_bytes(request),
        supplied_commitment=request.request_commitment,
    )
    before_catalog = self._clock.now()
    if not request.issued_at <= before_catalog < request.expires_at:
        return self._rejected_delete_receipt_without_io(request, before_catalog)
    clip = await self._catalog.require_exact_delete_target(
        request.clip_id, request.clip_generation, request.catalog_generation,
        request.views, request.expected_view_count,
        request.expected_managed_byte_count, request.expected_immutable_expires_at,
    )
    before_unlink = self._clock.now()
    if not request.issued_at <= before_unlink < request.expires_at:
        return self._rejected_delete_receipt_without_unlink(request, before_unlink)
    return await self._retention_journal.delete_once_exact(
        command_id=request.command_id,
        request_digest=request.request_digest,
        request_commitment=request.request_commitment,
        clip=clip,
        authorized_at=before_unlink,
        authority_expires_at=request.expires_at,
        trusted_clock=self._clock,
    )
~~~

The shared writer keeps Phase 1's authenticated bounded-header/chunk/EOF/digest behavior and moves only reusable crypto/container code; its original backup tests must remain byte-compatible. Core consumes the fresh passkey grant, constructs the frozen request with exact clip/catalog generations, views, expected count/size/expiry and recipient key (export), verifies the request commitment over the canonical request excluding only that commitment, and samples trusted time both before authorization and immediately before authenticated IPC. Recorder validates the outer envelope but treats its time only as transport authority: before command-ledger/catalog/media access it independently requires the inner request's `issued_at <= trusted_now < expires_at`, verifies its exact request digest/commitment, and repeats the deadline check before catalog access and inside the first-read or atomic-unlink primitive. A stale inner request in a fresh envelope, arrival exactly at expiry, delayed dispatch, or restart returns an in-memory authenticated rejection with no command write, catalog/media read, or unlink; if time crosses after a valid catalog read, no media read or unlink occurs. Only while that authority remains live may recorder reopen every carried value against its catalog and atomically claim the command as part of the crash-safe export job or retention-journal unlink before emitting the matching receipt. Core exact-compares every echoed request-authority field and request digest/commitment, enforces the bounded export-output expiry policy, and durably claims the receipt before constructing any public download or delete projection. A mismatch, replay, or restart yields only generic unavailability and no public result. Recorder reads raw clip bytes and emits only recipient-encrypted ciphertext—raw media never enters core. The no-store one-time download is bound to the receipt's opaque handle and expires after first use. Early delete atomically blocks playback, verifies exact clip/view/count/size/expiry, unlinks through the retention journal, and leaves only an HMAC/content-minimized receipt. Show camera microSD, hub/NVR, SSD, vendor cloud, diagnostic copy, restore copy, and owner export as independent copy rows with separate authority/retention; never claim deletion outside Tuntun control.

- [ ] **Step 4: Run green, Phase 1 archive regression, and plaintext scan**

Run:

~~~bash
uv lock
uv sync --all-packages --locked
uv run --locked --offline --no-sync python -c 'import tuntun_secure_archive; assert tuntun_secure_archive.__version__ == "0.1.0.dev0"'
uv run --locked --offline --no-sync pytest tests/unit/vision/test_secure_archive_package_bootstrap.py tests/integration/vision/test_clip_export_delete.py tests/security/vision/test_export_encryption.py tests/fault/vision/test_export_delete_transitions.py tests/unit/vision/test_copy_disclosure.py tests/security/vision/test_export_artifact_scanner.py tests/unit/data_lifecycle/test_backup_format.py tests/property/test_backup_parser_fuzz.py -q
uv run --locked --offline --no-sync python scripts/scan_export_artifacts.py --root var/test-artifacts --forbid-plaintext-sentinel --require-authenticated-ciphertext
uv run --locked --offline --no-sync python scripts/check_import_boundaries.py --domain vision
uv run --locked --offline --no-sync ruff check packages/secure-archive apps/recorder/src/tuntun_recorder/media/export.py apps/core/src/tuntun_core/services/data_lifecycle/backup_format.py apps/core/src/tuntun_core/services/vision/playback_broker.py scripts/scan_export_artifacts.py tests/unit/vision/test_secure_archive_package_bootstrap.py tests/integration/vision tests/security/vision tests/fault/vision tests/unit/vision
uv run --locked --offline --no-sync mypy packages/secure-archive/src apps/core/src apps/recorder/src scripts/scan_export_artifacts.py
uv lock --check
uv build --offline --wheel --package tuntun-secure-archive --out-dir var/build-smoke/phase3/secure-archive
uv lock --check
~~~

Expected: PASS; Phase 1 archive behavior is unchanged, exports are ciphertext-only, delete is idempotent/crash-safe, and copy disclosure remains truthful.

- [ ] **Step 5: Commit**

~~~bash
git add pyproject.toml uv.lock apps/core/pyproject.toml apps/recorder/pyproject.toml packages/secure-archive/pyproject.toml packages/secure-archive/src/tuntun_secure_archive/__init__.py packages/secure-archive/src/tuntun_secure_archive/writer.py apps/core/src/tuntun_core/services/data_lifecycle/backup_format.py apps/recorder/src/tuntun_recorder/media/export.py apps/core/src/tuntun_core/services/vision/playback_broker.py scripts/scan_export_artifacts.py tests/unit/vision/test_secure_archive_package_bootstrap.py tests/integration/vision/test_clip_export_delete.py tests/security/vision/test_export_encryption.py tests/security/vision/test_export_artifact_scanner.py tests/fault/vision/test_export_delete_transitions.py tests/unit/vision/test_copy_disclosure.py docs/operations/phase3-playback-export-delete.md
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(vision): add encrypted export and exact deletion"
~~~

### Task 19: Prove the TrackMix fixed-wide one-camera 48-hour pilot

**Depends on:** Tasks 06–18 and positive TrackMix/SSD/egress evidence.
**Gate contribution:** P3-1 exit.
**Estimated effort:** 1 person-day plus 48 elapsed hours.

**Files:**
- Create: `scripts/phase3/run_one_camera_pilot.py`
- Create: `docs/evidence/phase3-one-camera-pilot-schema.json`
- Create: `docs/operations/phase3-one-camera-pilot.md`
- Create: `tests/acceptance/vision/test_one_camera_pilot_schema.py`
- Create: `tests/acceptance/vision/test_one_camera_pilot_oracle.py`
- Create: `tests/acceptance/vision/test_one_camera_disabled_exit.py`

**Interfaces:** Produces an evidence-bound `P3OneCameraPilotReceipt` for the TrackMix fixed-wide path only. It consumes the exact clean build, commissioning/arc/egress/volume/capability digests, synthetic preflight, owner operator, and monotonic plus wall elapsed measurements. The physical runner also consumes the complete Phase 2 canonical pre-issued rollover chain, and the receipt embeds the unchanged Phase 2 `FeatureAuthorityCampaignEvidenceV1` projection and binds its chain ID/digest, frozen candidate, ordered signed-envelope and transition/restart-receipt digests, complete interval, admission-sample-log digest, and literal-zero early/expired/gap/stale-generation/runtime-signer/runtime-renewal counts. `schemas/features/v1/feature-authority-campaign-evidence-v1.schema.json` remains Phase 2's sole schema owner; Phase 3 evidence schemas reference/validate that exact contract and define no copy or alias. The runner checks the current half-open wall validity and process-local monotonic lease at every admission/background sample; it has no signer or renewal path.

Phase 2 Task 13 is the sole owner of `tests/support/feature_authority_campaign.py` and its self-test. Phase 3 imports that harness unchanged. It adapts a campaign runner and semantic verifier to the Phase 2 contract, pauses immediately before the injected boundary, snapshots admission/preparation/provider-call/trigger/effect counters, injects one closed fault, and proves no counter advances after the fault, the composition barrier closes, stale prepared work is invalidated, controlled recovery is requested, and the complete campaign/verifier result rejects. Its fixed fault set is: missing/stale initial activation receipt or nonzero initial index; missing, extra, reordered, late, or signature-invalid successor; candidate or registration drift; future activation; exact wall-expiry equality; wall rollback; exact monotonic-expiry equality; stale composition generation; and restart before or after the rollover CAS with a missing/duplicated/substituted transition or restart receipt. The Phase 2 self-test uses a deliberately dishonest adapter that reports zero expired intervals while attempting I/O. Tasks 19, 20, 26, and 32 plus Phase 4 Tasks 16, 35, and 36 reuse this harness without changing it.

- [ ] **Step 1: Write red evidence oracle and disabled-exit tests**

~~~python
def test_pilot_requires_two_elapsed_days_and_every_failure_case(verifier, receipt) -> None:
    assert receipt.monotonic_elapsed_seconds >= 172800
    assert receipt.wall_elapsed_seconds >= 172800
    assert set(receipt.failure_cases) == REQUIRED_ONE_CAMERA_FAILURE_CASES
    assert verifier.verify(receipt).decision == "p3_1_pass"

@pytest.mark.parametrize("fault", DOWNSTREAM_FEATURE_AUTHORITY_FAULTS)
async def test_pilot_feature_authority_fault_closes_before_more_io(
    feature_authority_campaign_harness, pilot_runner, verifier, fault,
) -> None:
    result = await feature_authority_campaign_harness.exercise(
        runner=pilot_runner,
        verifier=verifier,
        fault=fault,
    )
    assert result.campaign_invalid
    assert result.post_fault_admission_delta == 0
    assert result.post_fault_preparation_delta == 0
    assert result.post_fault_provider_call_delta == 0
    assert result.post_fault_trigger_delta == 0
    assert result.post_fault_effect_delta == 0
    assert result.stale_preparations_invalidated
    assert result.semantic_verifier_rejected

def test_ineligible_trackmix_cannot_be_silently_replaced_by_e1(verifier, receipt) -> None:
    receipt.primary_camera_class = "e1_family"
    assert verifier.verify(receipt).decision == "p3_1_blocked_trackmix_source"
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/support/test_feature_authority_campaign.py tests/acceptance/vision/test_one_camera_pilot_schema.py tests/acceptance/vision/test_one_camera_pilot_oracle.py tests/acceptance/vision/test_one_camera_disabled_exit.py -q`
Expected: FAIL because the pilot runner/verifier does not exist.

- [ ] **Step 3: Implement a non-bypassable campaign and semantic verifier**

The runner records audio-free low-wide segments, full-resolution ring/promotion, checksums, gaps, event timing, playback, encrypted export, early delete, exact retention simulation, crash/restart before and after each media transition, SSD disconnect/reconnect, wrong mount, camera/router/Mac restart, WAN off/restore, credential rotation, source/event split failures, clock skew/rollback, full-disk thresholds, Green backup contention, active voice latency, resource bounds, public/listener scan, egress capture digest, private-data sentinel scan, and selected-frame/identity/HA media/greeting/action negative reachability.

~~~python
def verify_p3_1(receipt: P3OneCameraPilotReceipt) -> PilotDecision:
    require_complete_campaign_feature_authority(
        evidence=receipt.feature_authority,
        expected_candidate_digest=receipt.candidate_digest,
        expected_interval=(receipt.started_at, receipt.ended_at),
    )
    require(receipt.camera_class == "trackmix_wifi")
    require(receipt.stream_role == "low_wide")
    require(receipt.monotonic_elapsed_seconds >= 172800 and receipt.wall_elapsed_seconds >= 172800)
    require(receipt.stored_audio_streams == 0)
    require(receipt.unapproved_egress_flows == 0)
    require(receipt.unauthorized_media_copies == 0)
    require(receipt.duplicate_or_false_complete == 0)
    require(receipt.required_failure_cases == REQUIRED_ONE_CAMERA_FAILURE_CASES)
    return PilotDecision("p3_1_pass")
~~~

`require_complete_campaign_feature_authority` receives the canonical signed chain loaded from the required `--feature-manifest-chain` input, verifies it with Phase 2's trusted signer registry and exact installed candidate/package/registrations, recomputes the complete `FeatureAuthorityCampaignEvidenceV1` from the ordered chain, transition/restart receipts, and bounded admission log, and byte-compares that result with the carried projection. It never accepts the projection's zero counters, chain digest, or candidate claim as self-authenticating. The runner parser accepts only `--feature-manifest-chain` and rejects every alias plus every signer, renew, fetch, or grace option.

- [ ] **Step 4: Freeze a clean build, run synthetic acceptance, then run the owner-gated pilot**

~~~bash
test -z "$(git status --porcelain)"
make check
make test-security
make verify-private-data
uv run pytest tests/support/test_feature_authority_campaign.py tests/acceptance/vision/test_one_camera_pilot_oracle.py -q
uv run python scripts/phase3/run_one_camera_pilot.py synthetic --commit "$(git rev-parse HEAD)" --output var/evidence/phase3/synthetic-one-camera.json
uv run python scripts/phase3/run_one_camera_pilot.py verify var/evidence/phase3/synthetic-one-camera.json --commit "$(git rev-parse HEAD)"
TUNTUN_ALLOW_ELAPSED_PHASE3=1 uv run python scripts/phase3/run_one_camera_pilot.py household --feature-manifest-chain var/evidence/phase3/feature-authority/task19/signed-rollover-chain.json --duration-seconds 172800 --sample-seconds 30 --commit "$(git rev-parse HEAD)" --output var/evidence/phase3/one-camera-pilot.json
uv run python scripts/phase3/run_one_camera_pilot.py verify var/evidence/phase3/one-camera-pilot.json --feature-manifest-chain var/evidence/phase3/feature-authority/task19/signed-rollover-chain.json --commit "$(git rev-parse HEAD)" --require-physical
uv run python scripts/verify_private_data.py var/evidence/phase3
~~~

Expected: synthetic verification passes first; physical elapsed is at least 172,800 seconds by both clocks; the canonical same-candidate rollover chain covers the full interval with every transition/lease check and zero expired-authority interval; stored audio/unapproved egress/unauthorized copy/identity/model/HA media/greeting/action routes and duplicate/false-complete outcomes are zero. A failure leaves P3-1 blocked and opens a source/placement decision; it does not silently use an E1 or purchase a bridge.

- [ ] **Step 5: Commit tooling before the clean physical run; never commit generated owner evidence**

~~~bash
git add scripts/phase3/run_one_camera_pilot.py docs/evidence/phase3-one-camera-pilot-schema.json docs/operations/phase3-one-camera-pilot.md tests/acceptance/vision/test_one_camera_pilot_schema.py tests/acceptance/vision/test_one_camera_pilot_oracle.py tests/acceptance/vision/test_one_camera_disabled_exit.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(vision): gate one-camera recorder pilot"
~~~

After this tooling commit, restart Step 4 from the new clean commit. Owner evidence remains ignored under `var/evidence/phase3/`.

## Wave 3 — P3-2 Three-Camera Capacity and P3-3 Owner Storage Dashboard

### Task 20: Run the eligible-camera seven-day capacity and reliability campaign

**Depends on:** P3-1 and Tasks 09–16.
**Gate contribution:** P3-2.
**Estimated effort:** 1.5 person-days plus seven elapsed days.

**Files:**
- Modify: `apps/recorder/src/tuntun_recorder/capacity.py`
- Create: `scripts/phase3/run_capacity_campaign.py`
- Create: `docs/evidence/phase3-capacity-schema.json`
- Create: `tests/unit/vision/test_capacity_formula.py`
- Create: `tests/acceptance/vision/test_capacity_campaign_schema.py`
- Create: `tests/acceptance/vision/test_capacity_campaign_oracle.py`
- Create: `tests/acceptance/vision/test_capacity_feature_authority.py`
- Create: `tests/acceptance/vision/test_partial_camera_truth.py`
- Create: `tests/security/vision/test_capacity_authority.py`

**Interfaces:** Produces one `CapacityCampaignV1`, exactly one `StorageMeasurementV1` for each expected physical camera/selected view/day 1–7 semantic key, a minimized signed `GreenBackupReceiptV1`, `CapacityProjectionV1`, and `P3CapacityDecision`. The backup receipt carries immutable receipt/run IDs and digest, signer, status/objective result, load-snapshot and backup times, exact campaign manifest/generation/window, current volume handle/commitment/quota/HA reserve, backup-policy/objective generations, and the canonical final camera/profile load digest—never a path, archive name, or payload. It snapshots exactly three physical-unit HMAC commitments and current source/binding/location/zone authorities. Eligible units have measured rows for `wide` and, only when current TrackMix dual-view evidence permits, `tracking`; every excluded unit still has seven explicit `wide` rows with `none_ineligible`, zero measured values, and a reason. Counts and view sets are derived from the closed campaign, never caller-authored. Capacity compares only with the current handle's exact video quota, not physical free space, and no decision may rely on a commitment without reloading and verifying the signed receipt. The physical campaign consumes the complete Phase 2 canonical pre-issued rollover chain and exact `FeatureAuthorityCampaignEvidenceV1`; its schema binds chain ID/digest, frozen candidate, ordered signed-envelope and transition/restart-receipt digests, admission-sample-log digest, complete interval, and the canonical literal-zero counters, with half-open wall and monotonic lease checks on every admission/background sample and no Phase 3 signer or renewal path. `test_capacity_feature_authority.py` adapts both the runner and capacity semantic verifier to the Phase 2 Task 13-owned shared adversarial harness; every injected authority fault prevents the next segment/measurement/catalog/backup/camera operation and invalidates rather than pauses or credits the campaign.

- [ ] **Step 1: Write red exact formula, reserve, coverage, and partial-source tests**

~~~python
@pytest.mark.parametrize("fault", DOWNSTREAM_FEATURE_AUTHORITY_FAULTS)
async def test_capacity_campaign_authority_fault_has_no_post_fault_io(
    feature_authority_campaign_harness, capacity_runner, capacity_verifier, fault,
) -> None:
    result = await feature_authority_campaign_harness.exercise(
        runner=capacity_runner,
        verifier=capacity_verifier,
        fault=fault,
    )
    assert result.post_fault_admission_delta == 0
    assert result.post_fault_preparation_delta == 0
    assert result.post_fault_provider_call_delta == 0
    assert result.post_fault_trigger_delta == 0
    assert result.post_fault_effect_delta == 0
    assert result.campaign_invalid and result.semantic_verifier_rejected

def test_capacity_uses_worst_daily_continuous_and_event_rule(measurements) -> None:
    projection = project_capacity(measurements)
    expected_policy = (
        7 * sum(m.max_complete_continuous_24h for m in measurements.streams)
        + ceil_decimal(90 * sum(max(m.max_event_24h, Decimal("1.5") * m.mean_event_7d) for m in measurements.streams))
        + measurements.catalog_filesystem_overhead
    )
    assert projection.policy_bytes == expected_policy
    assert projection.required_usable_capacity == (5 * expected_policy + 3) // 4

def test_event_capacity_uses_one_point_five_mean_when_it_exceeds_max_and_ceils_once(campaign) -> None:
    campaign.set_event_daily_bytes([1, 1, 1, 1, 1, 1, 1])
    projection = project_capacity(campaign)
    # One view: max day=1; 1.5 * mean=1.5; 90 days=135 exactly.
    assert projection.event_policy_bytes == 135
    campaign.set_event_daily_bytes([1, 1, 1, 1, 1, 1, 2])
    projection = project_capacity(campaign)
    expected = ceil_decimal(Decimal(90) * Decimal("1.5") * Decimal(8) / Decimal(7))
    assert projection.event_policy_bytes == expected

def test_trackmix_event_only_rows_cannot_define_continuous_reliability(campaign) -> None:
    campaign.set_wide_reliability(coverage_ratio=Decimal("0.999"), longest_gap_detection_seconds=10)
    campaign.set_tracking_event_reliability(coverage_ratio=Decimal("0"), longest_gap_detection_seconds=86_400)
    projection = project_capacity(campaign)
    assert projection.minimum_coverage_ratio == Decimal("0.999")
    assert projection.longest_gap_detection_seconds == 10

def test_ineligible_e1_is_reported_partial_not_estimated(campaign) -> None:
    result = campaign.with_camera("e1_synth_b", disposition="inventory_only").project()
    assert result.camera_results["e1_synth_b"].central_recording == "unavailable"
    assert result.camera_results["e1_synth_b"].estimated_bytes is None
    assert result.claim == "partial_eligible_camera_set"

@pytest.mark.parametrize("mutation", [
    "fresh_id_duplicate_semantic_day", "missing_day", "missing_view", "missing_camera",
    "permuted_camera_order", "permuted_measurement_order",
    "shifted_window", "noncontiguous_window", "stale_campaign_generation",
    "tracking_on_non_trackmix", "tracking_without_current_dual_view_evidence",
    "ineligible_wide_row_nonzero", "physical_device_commitment_substitution",
    "duplicate_physical_device_commitment",
    "capability_generation_drift", "profile_generation_drift", "source_eligibility_generation_drift",
    "egress_evidence_generation_drift", "volume_qualification_generation_drift",
    "catalog_generation_drift", "area_generation_drift", "zone_generation_drift",
    "privacy_policy_version_drift", "privacy_generation_drift",
])
def test_campaign_rejects_incomplete_substituted_or_nonsemantic_matrix(campaign_fixture, mutation) -> None:
    with pytest.raises(ValidationError):
        CapacityCampaignV1.model_validate(campaign_fixture.mutate(mutation))

def test_campaign_rejects_unequal_camera_privacy_generations_before_projection(campaign_fixture) -> None:
    with pytest.raises(ValidationError, match="capacity_campaign_global_privacy_generation_mismatch"):
        CapacityCampaignV1.model_validate(
            campaign_fixture.with_camera_privacy_generation("e1_synth_b", generation=99)
        )

def test_excluded_camera_has_seven_explicit_zero_wide_rows(campaign_fixture) -> None:
    campaign = CapacityCampaignV1.model_validate(campaign_fixture.with_excluded_camera("e1_synth_b"))
    excluded = next(camera for camera in campaign.expected_cameras if camera.source_endpoint_id == "e1_synth_b")
    rows = [row for row in campaign.measurements if row.source_endpoint_id == excluded.source_endpoint_id]
    assert [(row.view, row.day_index) for row in rows] == [("wide", day) for day in range(1, 8)]
    assert all(row.measurement_basis == "none_ineligible" and row.complete_continuous_bytes == 0 for row in rows)

def test_all_three_ineligible_is_representable_and_explicitly_blocked(campaign_fixture) -> None:
    run = campaign_fixture.with_all_cameras_ineligible(
        measured_catalog_and_filesystem_overhead=64 * 1024 * 1024,
    )
    projection = project_capacity(run)
    assert (projection.eligible_camera_count, projection.ineligible_camera_count) == (0, 3)
    assert projection.decision == "p3_2_blocked_no_eligible_sources"
    assert projection.claim == "partial_eligible_camera_set"
    assert projection.policy_bytes == projection.required_usable_capacity == 0
    assert projection.measured_catalog_and_filesystem_overhead == 0
    assert projection.operational_evidence.measured_catalog_and_filesystem_overhead == 64 * 1024 * 1024

async def test_projection_identity_and_time_recompute_identically_after_restart(capacity_campaign) -> None:
    first = project_capacity(capacity_campaign)
    await capacity_campaign.restart_process_and_reload_signed_evidence()
    second = project_capacity(capacity_campaign)
    assert canonical_vision_bytes(first) == canonical_vision_bytes(second)
    assert first.projection_id == capacity_projection_id(
        first.campaign, first.operational_evidence, first.projection_generation,
    )
    for mutation in (
        {"projection_id": uuid4()},
        {"projected_at": first.projected_at + timedelta(microseconds=1)},
        {"valid_until": first.valid_until - timedelta(microseconds=1)},
    ):
        with pytest.raises(ValidationError, match="identity_not_evidence_derived|lifetime"):
            CapacityProjectionV1.model_validate({**first.model_dump(), **mutation})

def test_projection_identity_cannot_collide_after_measurement_content_change(
    capacity_campaign,
) -> None:
    first = project_capacity(capacity_campaign)
    changed = capacity_campaign.with_remeasured_event_bytes_and_recomputed_digests(
        measurement_index=0,
        event_bytes=capacity_campaign.measurements[0].event_bytes + 1,
    )
    second = project_capacity(changed)
    assert first.campaign_id == second.campaign_id
    assert first.campaign_generation == second.campaign_generation
    assert first.projection_id != second.projection_id
    assert first.measurement_digest != second.measurement_digest

def test_storage_measurement_digest_rejects_one_field_mutation(capacity_campaign) -> None:
    row = next(
        measurement
        for measurement in capacity_campaign.measurements
        if measurement.measurement_basis == "measured"
    )
    with pytest.raises(ValidationError, match="storage_measurement_digest_mismatch"):
        StorageMeasurementV1.model_validate({
            **row.model_dump(),
            "event_bytes": row.event_bytes + 1,
        })

async def test_same_manifest_measurement_replacement_rejects_after_restart_or_restore(
    verifier, projection,
) -> None:
    measurement_index = next(
        index
        for index, measurement in enumerate(projection.campaign.measurements)
        if measurement.measurement_basis == "measured"
    )
    original = projection.campaign.measurements[measurement_index]
    replacement = projection.campaign.with_remeasured_event_bytes_and_recomputed_digests(
        measurement_index=measurement_index,
        event_bytes=original.event_bytes + 1,
    )
    assert replacement.manifest_digest == projection.campaign.manifest_digest
    assert (
        capacity_campaign_measurement_digest(replacement)
        != capacity_campaign_measurement_digest(projection.campaign)
    )
    verifier.campaigns.replace_same_identity_and_manifest(replacement)
    for runtime in (verifier, await verifier.restart(), await verifier.restore()):
        with pytest.raises(CapacityEvidenceRejected):
            await runtime.verify(projection)
        assert runtime.accepted_decisions == []

@pytest.mark.parametrize("field", ["campaign_started_at", "campaign_ended_at"])
def test_projection_rejects_nested_campaign_window_substitution(capacity_projection_fixture, field) -> None:
    campaign = capacity_projection_fixture["campaign"]
    changed = {**campaign, field: campaign[field] + timedelta(microseconds=1)}
    with pytest.raises(ValidationError, match="capacity_projection_campaign_binding_invalid"):
        CapacityProjectionV1.model_validate({**capacity_projection_fixture, "campaign": changed})

@pytest.mark.parametrize("mutation", [
    "low_continuous_bytes", "low_event_bytes", "high_coverage", "low_gap", "low_voice_p95",
    "low_voice_regression", "measurement_digest", "campaign_manifest_digest",
    "same_generation_other_container_uuid", "same_generation_other_volume_uuid", "same_generation_larger_quota",
    "same_generation_smaller_ha_reserve", "qualification_digest", "volume_handle_commitment",
    "operational_evidence_digest",
    "green_backup_signature", "green_backup_receipt_digest", "green_backup_status",
    "green_backup_times", "green_backup_quota", "green_backup_load_digest",
])
async def test_capacity_decision_recomputes_nested_evidence_and_current_volume_before_pass(
    verifier, projection, mutation,
) -> None:
    with pytest.raises(CapacityEvidenceRejected):
        await verifier.verify(projection.mutate(mutation))

@pytest.mark.parametrize("fault", [
    "missing_receipt", "same_id_replaced_digest", "cross_campaign_receipt", "pre_load_receipt",
])
async def test_capacity_rejects_missing_replaced_cross_campaign_or_preload_backup_receipt(
    verifier, projection, fault,
) -> None:
    verifier.backup_receipts.mutate(fault, projection.operational_evidence.green_backup_receipt)
    for runtime in (verifier, await verifier.restart(), await verifier.restore()):
        with pytest.raises(CapacityEvidenceRejected):
            await runtime.verify(projection)
        assert runtime.accepted_decisions == []

@pytest.mark.parametrize("fault", [
    "missing_operational_evidence", "same_id_replaced_digest", "same_digest_replaced_content",
])
async def test_capacity_reloads_exact_operational_evidence_after_restart_or_restore(
    verifier, projection, fault,
) -> None:
    verifier.operational_evidence.mutate(fault, projection.operational_evidence)
    for runtime in (verifier, await verifier.restart(), await verifier.restore()):
        with pytest.raises(CapacityEvidenceRejected):
            await runtime.verify(projection)
        assert runtime.accepted_decisions == []

@pytest.mark.parametrize("drift", [
    "expired_projection", "source_endpoint_generation", "physical_device_commitment",
    "camera_binding_generation", "capability_generation", "profile_generation",
    "source_eligibility_generation", "egress_evidence_generation",
    "catalog_generation", "area_generation", "zone_generation",
    "privacy_policy_version", "privacy_generation",
])
async def test_capacity_decision_rejects_current_authority_drift_before_acceptance(
    verifier, projection, drift,
) -> None:
    verifier.live_authority.mutate(drift)
    for runtime in (verifier, await verifier.restart(), await verifier.restore()):
        with pytest.raises(CapacityEvidenceRejected):
            await runtime.verify(projection)
        assert runtime.accepted_decisions == []
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/support/test_feature_authority_campaign.py tests/unit/vision/test_capacity_formula.py tests/acceptance/vision/test_capacity_campaign_schema.py tests/acceptance/vision/test_capacity_campaign_oracle.py tests/acceptance/vision/test_capacity_feature_authority.py tests/acceptance/vision/test_partial_camera_truth.py tests/security/vision/test_capacity_authority.py -q`
Expected: FAIL because the final capacity projection/campaign verifier is absent.

- [ ] **Step 3: Implement exact daily buckets, projections, and semantic gate**

~~~python
def project_capacity(run: SevenDayMeasurements) -> CapacityProjectionV1:
    operational = run.signed_operational_evidence
    campaign = CapacityCampaignV1(
        campaign_id=run.campaign_id,
        campaign_generation=run.campaign_generation,
        expected_cameras=run.exact_expected_camera_snapshot,
        measurements=run.measurements,
        volume_qualification_generation=operational.volume_handle.qualification_generation,
        catalog_generation=run.catalog_generation,
        campaign_started_at=run.started_at,
        campaign_ended_at=run.ended_at,
        manifest_digest=run.manifest_digest,
    )
    eligible = tuple(camera for camera in campaign.expected_cameras if camera.disposition == "eligible_measured")
    measured = tuple(row for row in campaign.measurements if row.measurement_basis == "measured")
    continuous = sum(max(row.complete_continuous_bytes for row in measured if row.source_endpoint_id == camera.source_endpoint_id and row.view == "wide") for camera in eligible)
    event_daily = sum(
        max(
            Decimal(max(rows := [
                row.event_bytes for row in measured
                if row.source_endpoint_id == camera.source_endpoint_id and row.view == view
            ])),
            Decimal("1.5") * sum(Decimal(value) for value in rows) / Decimal(7),
        )
        for camera in eligible
        for view in camera.selected_views
    )
    continuous_policy_bytes = 7 * continuous
    event_policy_bytes = ceil_decimal(Decimal(90) * event_daily)
    measured_overhead = (
        operational.measured_catalog_and_filesystem_overhead if eligible else 0
    )
    continuous_reliability_rows = tuple(row for row in measured if row.view == "wide")
    policy_bytes = continuous_policy_bytes + event_policy_bytes + measured_overhead
    required = (5 * policy_bytes + 3) // 4
    claim = "partial_eligible_camera_set" if len(eligible) < 3 else "complete_eligible_camera_set"
    projection_generation = campaign.campaign_generation
    projected_at = operational.observed_at
    decision = classify_p3_2_from_derived(
        eligible_camera_count=len(eligible),
        required_usable_capacity=required,
        bound_video_quota_bytes=operational.volume_handle.video_quota_bytes,
        minimum_coverage_ratio=min(
            (row.coverage_ratio for row in continuous_reliability_rows),
            default=Decimal("0"),
        ),
        longest_gap_detection_seconds=max(
            (row.longest_gap_detection_seconds for row in continuous_reliability_rows),
            default=0,
        ),
        voice_p95_seconds=operational.voice_p95_seconds,
        voice_regression_percent=operational.voice_regression_percent,
    )
    return CapacityProjectionV1(
        projection_id=capacity_projection_id(campaign, operational, projection_generation),
        projection_generation=projection_generation,
        campaign_id=campaign.campaign_id,
        campaign_generation=campaign.campaign_generation,
        campaign=campaign,
        operational_evidence=operational,
        measurement_ids=tuple(measurement.measurement_id for measurement in campaign.measurements),
        volume_qualification_generation=operational.volume_handle.qualification_generation,
        catalog_generation=campaign.catalog_generation,
        privacy_generation=campaign.expected_cameras[0].privacy_generation,
        eligible_camera_count=len(eligible),
        ineligible_camera_count=3 - len(eligible),
        campaign_started_at=run.started_at,
        campaign_ended_at=run.ended_at,
        continuous_policy_bytes=continuous_policy_bytes,
        event_policy_bytes=event_policy_bytes,
        measured_catalog_and_filesystem_overhead=measured_overhead,
        policy_bytes=policy_bytes,
        reserve_basis_points=2000,
        required_usable_capacity=required,
        bound_video_quota_bytes=operational.volume_handle.video_quota_bytes,
        minimum_ha_backup_reserve_bytes=operational.volume_handle.minimum_ha_backup_reserve_bytes,
        minimum_coverage_ratio=min(
            (row.coverage_ratio for row in continuous_reliability_rows),
            default=Decimal("0"),
        ),
        longest_gap_detection_seconds=max(
            (row.longest_gap_detection_seconds for row in continuous_reliability_rows),
            default=0,
        ),
        voice_p95_seconds=operational.voice_p95_seconds,
        voice_regression_percent=operational.voice_regression_percent,
        stored_audio_stream_count=0,
        selected_view_set=tuple(sorted({view for camera in campaign.expected_cameras for view in camera.selected_views})),
        claim=claim,
        decision=decision,
        projected_at=projected_at,
        valid_until=projected_at + timedelta(days=90),
        measurement_digest=capacity_campaign_measurement_digest(campaign),
        reason_codes=capacity_reason_codes(decision),
    )

async def verify_capacity_decision(
    supplied: CapacityProjectionV1,
    campaigns: CapacityCampaignRepository,
    evidence: CapacityOperationalEvidenceRepository,
    backup_receipts: GreenBackupReceiptRepository,
    backup_signatures: GreenBackupReceiptSignatureVerifier,
    volume_gate: VideoVolumeGate,
    authority: CurrentCapacityAuthorityRegistry,
    clock: TrustedClock,
) -> CapacityProjectionV1:
    now = clock.now()
    if not supplied.projected_at <= now < supplied.valid_until:
        raise CapacityEvidenceRejected("capacity_projection_not_current")
    stored_campaign = await campaigns.require_exact(
        supplied.campaign_id, supplied.campaign_generation, supplied.campaign.manifest_digest,
    )
    stored_evidence = await evidence.require_exact(
        supplied.operational_evidence.evidence_id,
        supplied.operational_evidence.evidence_digest,
    )
    require(
        stored_evidence.evidence_digest == capacity_operational_evidence_digest(stored_evidence)
    )
    require(
        canonical_vision_bytes(stored_evidence)
        == canonical_vision_bytes(supplied.operational_evidence)
    )
    carried_backup = supplied.operational_evidence.green_backup_receipt
    stored_backup = await backup_receipts.require_exact(
        carried_backup.receipt.receipt_id,
        carried_backup.receipt.receipt_generation,
        carried_backup.receipt.receipt_digest,
    )
    backup_signatures.verify_exact(
        domain="tuntun.green-backup-receipt.v1",
        signed=stored_backup,
        canonical_bytes=canonical_vision_bytes(stored_backup.receipt),
    )
    require(canonical_vision_bytes(stored_backup) == canonical_vision_bytes(carried_backup))
    await authority.require_current_backup_authority(
        backup_policy_generation=stored_backup.receipt.backup_policy_generation,
        green_objective_generation=stored_backup.receipt.green_objective_generation,
        signing_key_id=stored_backup.signing_key_id,
        at=now,
    )
    require(stored_backup.receipt.status == "completed")
    require(stored_backup.receipt.objective_state == "met")
    require(stored_backup.receipt.campaign_id == stored_campaign.campaign_id)
    require(stored_backup.receipt.campaign_generation == stored_campaign.campaign_generation)
    require(stored_backup.receipt.campaign_manifest_digest == stored_campaign.manifest_digest)
    require(stored_backup.receipt.concurrent_load_digest == capacity_campaign_load_digest(stored_campaign))
    require(stored_backup.receipt.campaign_started_at <= stored_backup.receipt.load_snapshot_at)
    require(stored_backup.receipt.load_snapshot_at <= stored_backup.receipt.backup_started_at)
    live_handle = volume_gate.require_current(stored_evidence.volume_handle)
    require(stored_evidence.volume_handle_commitment == volume_handle_commitment(live_handle))
    require(stored_backup.receipt.volume_handle == live_handle)
    require(stored_backup.receipt.volume_handle_commitment == volume_handle_commitment(live_handle))
    require(stored_backup.receipt.bound_video_quota_bytes == live_handle.video_quota_bytes)
    require(
        stored_backup.receipt.minimum_ha_backup_reserve_bytes
        == live_handle.minimum_ha_backup_reserve_bytes
    )
    await authority.require_current_catalog_generation(stored_campaign.catalog_generation)
    for camera in stored_campaign.expected_cameras:
        current = await authority.snapshot_camera(camera.source_endpoint_id, at=now)
        carried = (
            camera.source_endpoint_id, camera.source_endpoint_generation,
            camera.physical_device_commitment,
            camera.camera_binding_id, camera.camera_binding_generation,
            camera.capability_generation, camera.profile_generation,
            camera.source_eligibility_generation, camera.egress_evidence_generation,
            camera.area_id, camera.area_generation, camera.zone_id, camera.zone_generation,
            camera.privacy_policy_version, camera.privacy_generation,
            camera.source_path, camera.disposition,
            camera.trackmix_dual_view_generation,
            camera.trackmix_dual_view_evidence_digest,
        )
        observed = (
            current.source_endpoint_id, current.source_endpoint_generation,
            current.physical_device_commitment,
            current.camera_binding_id, current.camera_binding_generation,
            current.capability_generation, current.profile_generation,
            current.source_eligibility_generation, current.egress_evidence_generation,
            current.area_id, current.area_generation, current.zone_id, current.zone_generation,
            current.privacy_policy_version, current.privacy_generation,
            current.source_path, current.disposition,
            current.trackmix_dual_view_generation,
            current.trackmix_dual_view_evidence_digest,
        )
        if carried != observed:
            raise CapacityEvidenceRejected("capacity_camera_authority_stale")
    recomputed = project_capacity(SevenDayMeasurements.from_verified(stored_campaign, stored_evidence))
    if canonical_vision_bytes(recomputed) != canonical_vision_bytes(supplied):
        raise CapacityEvidenceRejected("capacity_projection_substituted")
    return recomputed
~~~

**Green backup receipt authority:** A Green result never follows from a lone commitment. The verifier reloads the exact signed receipt by `(receipt_id, receipt_generation, receipt_digest)`, verifies its pinned signer/domain/canonical bytes, and exact-compares stored and carried envelopes. It rejects a missing or same-ID replaced receipt, revoked/stale signer, policy/objective-generation drift, non-completed status, missed objective, cross-campaign manifest, pre-campaign/pre-load timing, load-digest substitution, or volume/quota/reserve mismatch on first run, restart, and restore. Receipt persistence is content-minimized: no archive path, filename, payload, family/profile identifier, or backup contents.

The DTO's derived fields never confer authority. The decision verifier reloads the exact campaign manifest and signed operational evidence by ID/digest, validates three distinct physical-device commitments in one-to-one correspondence with three distinct source endpoints, requires canonical source/view/day ordering, rejects missing/extra semantic keys or a duplicate `(source_endpoint_id, view, day_index)` even under a fresh measurement ID, proves seven adjacent 24-hour windows anchored at campaign start, and recomputes continuous/event bytes, the 1.5×mean rule and single ceiling, counts, views, wide-stream reliability, voice metrics, overhead, manifest and measurement digests. Coverage and gap acceptance use only each eligible camera's continuous `wide` rows; event-only TrackMix `tracking` rows contribute event capacity but cannot falsely lower or improve continuous-recording reliability. If no source is eligible, the signed operational evidence is retained but every policy byte component—including operational overhead—is exactly zero and the decision is explicitly blocked. Projection ID includes the canonical campaign manifest digest, canonical measurement digest, operational evidence ID/digest, and exact volume-handle commitment; a permutation is invalid and any remeasured content produces a different identity even if caller IDs/generations are reused. Projection generation, projected time, validity, reason codes, and every derived field are deterministic functions of the stored signed campaign/evidence; a process restart recomputes identical canonical bytes and caller-supplied identity/time never becomes authority. It calls `VideoVolumeGate.require_current` on the exact stored handle and byte-compares APFS container UUID, video-volume UUID, quota, HA reserve, recorder UID, qualification generation/digest, mount epoch, and handle commitment; a same-generation substitute fails. It then compares every current physical/source/binding/capability/profile/source-eligibility/egress/catalog/location/zone/privacy generation plus trusted time and requires canonical equality with the supplied projection before accepting a decision. Run all eligible cameras at final intended stream/event/night settings for seven representative consecutive days during normal Tuntun voice use and Green backups. Record complete bytes, event duty, highest 15-minute rate, segment coverage/gaps/corruption, Wi-Fi loss, clock skew, SSD health/temperature, CPU/RAM/network, first-audio regression, backup timing, disconnect/reconnect, camera/router/Mac reboot, event-channel loss, full-disk thresholds, and conditional TrackMix wide-plus-tracking separately. Require `bound_video_quota_bytes >= required_usable_capacity`, ≥99.5% continuous-wide coverage per eligible camera, every >5-second continuous-wide gap visible within 30 seconds, voice ≤4 seconds and ≤10% regression, and current Green objectives. A failure never shrinks 7/90; it opens the storage/source decision with evidence.

- [ ] **Step 4: Run green, synthetic seven-day oracle, then owner-gated elapsed campaign**

~~~bash
uv run pytest tests/support/test_feature_authority_campaign.py tests/unit/vision/test_capacity_formula.py tests/acceptance/vision/test_capacity_campaign_schema.py tests/acceptance/vision/test_capacity_campaign_oracle.py tests/acceptance/vision/test_capacity_feature_authority.py tests/acceptance/vision/test_partial_camera_truth.py tests/security/vision/test_capacity_authority.py -q
uv run python scripts/phase3/run_capacity_campaign.py synthetic --days 7 --output var/evidence/phase3/synthetic-capacity.json
uv run python scripts/phase3/run_capacity_campaign.py verify var/evidence/phase3/synthetic-capacity.json
TUNTUN_ALLOW_ELAPSED_PHASE3=1 uv run python scripts/phase3/run_capacity_campaign.py household --feature-manifest-chain var/evidence/phase3/feature-authority/task20/signed-rollover-chain.json --duration-seconds 604800 --sample-seconds 60 --commit "$(git rev-parse HEAD)" --output var/evidence/phase3/capacity.json
uv run python scripts/phase3/run_capacity_campaign.py verify var/evidence/phase3/capacity.json --feature-manifest-chain var/evidence/phase3/feature-authority/task20/signed-rollover-chain.json --commit "$(git rev-parse HEAD)" --require-physical
uv run python scripts/verify_private_data.py var/evidence/phase3
~~~

Expected: software/synthetic checks pass first; physical elapsed is at least 604,800 seconds; the canonical same-candidate rollover chain covers the full interval with every transition/lease check and zero expired-authority interval; every camera has an exact eligible or absent result; no vendor estimate substitutes for bytes; all thresholds are recomputed by the verifier.

- [ ] **Step 5: Commit tooling before the physical run; never commit owner evidence**

~~~bash
git add apps/recorder/src/tuntun_recorder/capacity.py scripts/phase3/run_capacity_campaign.py docs/evidence/phase3-capacity-schema.json tests/unit/vision/test_capacity_formula.py tests/acceptance/vision/test_capacity_campaign_schema.py tests/acceptance/vision/test_capacity_campaign_oracle.py tests/acceptance/vision/test_capacity_feature_authority.py tests/acceptance/vision/test_partial_camera_truth.py tests/security/vision/test_capacity_authority.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(vision): gate seven-day camera capacity"
~~~

Restart Step 4 from the committed clean candidate. A passing or failing report is evidence, not purchase approval.

### Task 21: Expose owner-safe camera, health, gap, and privacy read models

**Depends on:** Tasks 03, 05–06, 13, 16, and 20.
**Gate contribution:** P3-3 API/read foundation.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/services/vision/health.py`
- Modify: `apps/core/src/tuntun_core/services/vision/projections.py`
- Modify: `apps/core/src/tuntun_core/api/routes/cameras.py`
- Modify: `apps/core/src/tuntun_core/api/vision_dtos.py`
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Modify: `tests/integration/deploy/test_owner_ingress_route_manifest.py`
- Modify: `tests/integration/vision/test_phase3_boot_composition.py`
- Modify: `packages/contracts/src/tuntun_contracts/vision/ui.py`
- Modify: `packages/contracts/openapi/admin-v1.yaml`
- Modify: `apps/admin/src/api/generated/admin-v1.ts`
- Create: `scripts/scan_api_responses.py`
- Create: `tests/contract/api/test_vision_openapi.py`
- Create: `tests/integration/api/test_camera_read_routes.py`
- Create: `tests/security/vision/test_camera_read_authorization.py`
- Create: `tests/security/vision/test_api_response_scanner.py`

**Interfaces:** Produces bounded owner-only endpoints `GET /api/v1/ui/cameras/overview`, `/inventory`, `/recordings`, `/storage`, and `/privacy-map` with opaque cursors, per-fact freshness, and safe reason codes. It consumes only metadata projections over authenticated IPC—never media paths/bytes or camera credentials. Each exact method/path/query/body row is added to the signed owner-ingress manifest and closed router; the canonical app/container and installed-candidate tests prove listener→ingress→Core UDS reachability for all five enabled rows, 404 for unknown/disabled variants, and exact feature-manifest equality. `scan_api_responses.py` runs the exact registered domain routes through the synthetic in-process ASGI client for owner, non-owner, malformed, pagination, empty, degraded, and error cases; it bounds route count, response bytes, JSON depth/tokens, pages, and wall time, rejects duplicate keys or an incomplete/changed OpenAPI-route inventory, and scans normalized keys and string values for the closed forbidden CSV without printing response bodies.

- [ ] **Step 1: Write red projection minimization, actor matrix, and stale-fact tests**

~~~python
async def test_inventory_projection_contains_exact_capability_but_no_raw_identifier(owner_client) -> None:
    body = (await owner_client.get("/api/v1/ui/cameras/inventory")).json()
    assert body["items"][0]["model_state"] in {"exact", "family_unknown"}
    forbidden = {"serial", "ip", "mac", "stream_url", "credential", "vendor_account", "raw_error"}
    assert forbidden.isdisjoint(deep_keys(body))

@pytest.mark.parametrize("actor", ["second_adult", "k2_child", "n1_child", "designated_guest", "anonymous"])
async def test_camera_read_routes_are_owner_only(client_for, actor) -> None:
    response = await client_for(actor).get("/api/v1/ui/cameras/overview")
    assert response.status_code == 404

def test_global_generated_at_cannot_extend_stale_camera_fact(camera_fact) -> None:
    rendered = render_camera_overview_fact(camera_fact, camera_fact.valid_until)
    assert rendered.truth_state == "stale"
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/api/test_vision_openapi.py tests/integration/api/test_camera_read_routes.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_phase3_boot_composition.py tests/security/vision/test_camera_read_authorization.py tests/security/vision/test_api_response_scanner.py -q`
Expected: FAIL with 404/missing vision UI contracts.

- [ ] **Step 3: Implement server-filtered read services and generated clients**

~~~python
@router.get("/ui/cameras/overview", response_model=CameraOverviewUIV1)
async def camera_overview(actor: OwnerActor = Depends(require_owner), service: VisionProjectionService = Depends()) -> CameraOverviewUIV1:
    return await service.overview(actor=actor, now=database_time())

async def overview(self, actor: OwnerActor, now: datetime) -> CameraOverviewUIV1:
    actor.require_owner()
    snapshot = await self._health.current_safe_facts()
    facts = tuple(render_camera_overview_fact(fact, now) for fact in snapshot.facts)
    return CameraOverviewUIV1(
        projection_id=uuid4(),
        projection_generation=snapshot.projection_generation,
        catalog_generation=snapshot.catalog_generation,
        privacy_generation=snapshot.privacy_generation,
        generated_at=now,
        expires_at=min((
            now + timedelta(seconds=30),
            *(fact.valid_until for fact in facts if fact.truth_state == "current"),
        )),
        facts=facts,
        projection_state=overview_projection_state(facts),
        recorder_independent_from_privacy=True,
        selected_frame_perception="absent",
    )
~~~

Inventory distinguishes TrackMix hall/bedroom-pathway, kitchen view A, and kitchen view B only in the owner-local projection; committed fixtures remain synthetic. Show exact/family-unknown model, firmware, area/zone ID plus safe label, source disposition, capability generation, local-only/egress proof, audio-off, clock, last segment, gaps, coverage, copies, storage/retention, arc/dual-view evidence, and absent/degraded states. Register APIs only when `camera_storage` has accepted evidence; alert/presence endpoints remain absent until their later gates. Regenerate OpenAPI and TypeScript.

- [ ] **Step 4: Run green, generation drift, and response scan**

Run: `sh scripts/generate_openapi_client.sh && git diff --exit-code -- packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts && uv run pytest tests/contract/api/test_vision_openapi.py tests/integration/api/test_camera_read_routes.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_phase3_boot_composition.py tests/security/vision/test_camera_read_authorization.py tests/security/vision/test_api_response_scanner.py -q && uv run python scripts/scan_api_responses.py --domain cameras --forbid stream_url,credential,address,path,raw_error,profile_id && uv run ruff check apps/core/src/tuntun_core/services/vision apps/core/src/tuntun_core/api apps/core/src/tuntun_core/bootstrap/container.py apps/owner-ingress/src/tuntun_owner_ingress/router.py packages/contracts/src/tuntun_contracts/vision/ui.py scripts/scan_api_responses.py tests/contract/api tests/integration/api tests/security/vision && uv run mypy apps/core/src packages/contracts/src scripts/scan_api_responses.py`
Expected: PASS; generated clients are diff-clean; every non-owner gets no existence signal; stale/unknown never renders green.

- [ ] **Step 5: Commit**

~~~bash
git add apps/core/src/tuntun_core/services/vision/health.py apps/core/src/tuntun_core/services/vision/projections.py apps/core/src/tuntun_core/api/routes/cameras.py apps/core/src/tuntun_core/api/vision_dtos.py apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json packages/contracts/src/tuntun_contracts/vision/ui.py packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts scripts/scan_api_responses.py tests/contract/api/test_vision_openapi.py tests/integration/api/test_camera_read_routes.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_phase3_boot_composition.py tests/security/vision/test_camera_read_authorization.py tests/security/vision/test_api_response_scanner.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(vision): expose owner-safe camera read models"
~~~

### Task 22: Build camera overview, inventory, recordings, and explicit playback UI

**Depends on:** Tasks 17 and 21 plus shared console/design-system/auth clients.
**Gate contribution:** P3-3 owner console.
**Estimated effort:** 2 person-days.

**Files:**
- Create: `apps/admin/src/features/cameras/index.ts`
- Create: `apps/admin/src/features/cameras/overview.tsx`
- Create: `apps/admin/src/features/cameras/inventory.tsx`
- Create: `apps/admin/src/features/cameras/recordings.tsx`
- Create: `apps/admin/src/features/cameras/playback.tsx`
- Create: `apps/admin/src/features/cameras/privacy-map.tsx`
- Create: `apps/admin/src/routes/cameras-overview.tsx`
- Create: `apps/admin/src/routes/cameras-inventory.tsx`
- Create: `apps/admin/src/routes/cameras-recordings.tsx`
- Create: `apps/admin/src/routes/cameras-privacy.tsx`
- Create: `tests/e2e/cameras-overview.spec.ts`
- Create: `tests/e2e/cameras-recordings.spec.ts`
- Create: `tests/ui/cameras-accessibility.spec.ts`

**Interfaces:** Consumes generated Phase 3 UI DTOs, owner-safe `OwnerSegmentTimelineItemV1` plus event-clip pages, shared `TruthState`, `PreparedMutation`, and the `PlaybackSubjectV1` per-range playback client. Produces owner routes `/cameras`, `/cameras/inventory`, `/cameras/recordings`, and `/cameras/privacy`. It owns no authorization, camera credential, stream URL, filesystem path/storage token, policy generation, or grant construction.

- [ ] **Step 1: Write red route, no-autoplay, explicit range, and truthful-state tests**

~~~typescript
test("recording page never autoplays and requests one range grant after owner action", async ({page}) => {
  await page.goto("/cameras/recordings");
  await expect(page.locator("video[autoplay]")).toHaveCount(0);
  await page.getByRole("button", {name: "Open clip"}).click();
  await expect(page.getByText("Preparing one-time playback access")).toBeVisible();
  expect(await capturedRequests(page, "/playback-ranges")).toHaveLength(1);
});

test("recording timeline exposes seven-day low-wide segments separately from ninety-day event clips", async ({page}) => {
  await page.goto("/cameras/recordings");
  await expect(page.getByRole("heading", {name: "Continuous — 7 days"})).toBeVisible();
  await expect(page.getByRole("heading", {name: "Events — 90 days"})).toBeVisible();
  await page.getByRole("button", {name: "Open continuous segment"}).first().click();
  expect((await lastPlaybackRangeRequest(page)).subject.kind).toBe("continuous_segment");
});

test("Privacy Shield does not imply recorder stopped", async ({page}) => {
  await seedCameraPosture(page, {privacyShield: "active", recorder: "recording"});
  await page.goto("/cameras");
  await expect(page.getByText("Privacy Shield on — cameras still recording")).toBeVisible();
});
~~~

- [ ] **Step 2: Run red**

Run: `pnpm --filter @tuntun/admin e2e -- tests/e2e/cameras-overview.spec.ts tests/e2e/cameras-recordings.spec.ts`
Expected: FAIL with 404 for `/cameras`.

- [ ] **Step 3: Implement accessible routes and chunked same-origin playback**

~~~tsx
export function RecordingClip({clip}: {clip: ClipProjection}) {
  const player = useOneTimeRangePlayer({
    kind: "event_clip", clipId: clip.clipId,
    clipGeneration: clip.clipGeneration, catalogGeneration: clip.catalogGeneration,
  }, clip.availableViews);
  return (
    <article aria-labelledby={`clip-${clip.clipId}`}>
      <h2 id={`clip-${clip.clipId}`}>{clip.safeEventLabel}</h2>
      <TruthState state={clip.completeness} observedAt={clip.observedAt}/>
      <p>{clip.expiresAtLabel}</p>
      <Button onClick={() => player.open("wide")}>Open clip</Button>
      {player.active ? <BoundedMediaPlayer source={player.nextSingleUseRange} autoPlay={false}/> : null}
    </article>
  );
}

export function RecordingSegment({segment}: {segment: SegmentTimelineProjection}) {
  const subject = {
    kind: "continuous_segment" as const,
    segmentId: segment.segmentId,
    catalogGeneration: segment.catalogGeneration,
    cameraBindingId: segment.cameraBindingId,
    cameraBindingGeneration: segment.cameraBindingGeneration,
    streamRole: "low_wide" as const,
  };
  const player = useOneTimeRangePlayer(subject, ["wide"]);
  return <Button onClick={() => player.open()}>Open continuous segment</Button>;
}
~~~

Use cards/table alternatives for health/inventory; keep two E1 units separate; show TrackMix fixed-wide/tracking/arc truth; make gaps, audio-off, clock, source, retention, copies, and unavailable capabilities textual. The recordings route renders only owner-safe `low_wide` segment timeline items for their immutable 7-day window and separately renders 90-day native-event clips; neither projection contains an opaque storage token. Event rows never name people. Segment and clip details are reveal-on-demand with no prefetch/autoplay. Range grants stay in memory and clear on navigation, expiry, logout, privacy, or error. No `localStorage`, `sessionStorage`, IndexedDB, Cache API, service worker, screenshot, direct media URL, or browser history query contains a grant or recording metadata. Provide English/Hindi/mixed-script safe labels, keyboard control, focus restoration, captions saying audio is absent, 320 px/200% zoom, dark/light/high-contrast/reduced-motion.

- [ ] **Step 4: Run green, accessibility/localization, and browser-artifact scans**

Run: `pnpm --filter @tuntun/admin test && pnpm --filter @tuntun/admin lint && pnpm --filter @tuntun/admin typecheck && pnpm --filter @tuntun/admin build && pnpm --filter @tuntun/admin e2e -- tests/e2e/cameras-overview.spec.ts tests/e2e/cameras-recordings.spec.ts tests/ui/cameras-accessibility.spec.ts && uv run python scripts/scan_browser_artifacts.py --playwright-output test-results --forbid media_url,grant,credential,address,path,identity`
Expected: PASS in English/Hindi, narrow/wide, light/dark/high-contrast/reduced-motion; no autoplay/prefetch/persistent grant/private media detail.

- [ ] **Step 5: Commit**

~~~bash
git add apps/admin/src/features/cameras apps/admin/src/routes/cameras-overview.tsx apps/admin/src/routes/cameras-inventory.tsx apps/admin/src/routes/cameras-recordings.tsx apps/admin/src/routes/cameras-privacy.tsx tests/e2e/cameras-overview.spec.ts tests/e2e/cameras-recordings.spec.ts tests/ui/cameras-accessibility.spec.ts
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(admin): add owner camera and playback UI"
~~~

### Task 23: Add storage, copy, and measured NAS/NVR decision UI

**Depends on:** Tasks 18, 20–22.
**Gate contribution:** P3-3 and P3-6 storage-decision preparation.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/services/vision/storage_decision.py`
- Modify: `apps/core/src/tuntun_core/api/routes/cameras.py`
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Modify: `tests/integration/deploy/test_owner_ingress_route_manifest.py`
- Modify: `tests/integration/vision/test_phase3_boot_composition.py`
- Create: `apps/admin/src/features/cameras/storage.tsx`
- Create: `apps/admin/src/routes/cameras-storage.tsx`
- Create: `docs/procurement/phase3-storage-decision.md`
- Create: `tests/unit/vision/test_storage_decision.py`
- Create: `tests/integration/api/test_storage_decision_route.py`
- Create: `tests/e2e/cameras-storage.spec.ts`

**Interfaces:** Produces a read-only measured recommendation plus exact owner-passkey `camera.storage_decision.sign` operation choosing `retain_external_ssd`, `open_hub_nvr_procurement`, or `open_nas_vms_procurement`. The exact read and prepared-mutation rows are registered in the signed ingress manifest/router and canonical app/container; installed-candidate tests exercise them through owner ingress and require unknown/disabled/purchase-like paths to return 404. It creates no order, vendor login, payment, quote acceptance, filesystem migration, or recorder change.

- [ ] **Step 1: Write red no-premature-purchase and evidence-binding tests**

~~~python
def test_storage_recommendation_cannot_exist_without_seven_measured_days(service) -> None:
    with pytest.raises(EvidenceInsufficient, match="seven_day_measurement_required"):
        service.prepare_decision(measurement_fixture(elapsed_days=6))

async def test_signed_decision_binds_measurement_and_revisit_triggers(service, measurement, owner_passkey) -> None:
    prepared = await service.prepare("retain_external_ssd", measurement.digest)
    receipt = await service.execute(prepared.id, owner_passkey.for_binding(prepared.binding))
    assert receipt.measurement_digest == measurement.digest
    assert "camera_count_change" in receipt.revisit_triggers
    assert receipt.purchase_authorized is False
~~~

~~~typescript
test("storage screen shows two independent retention commitments and no selected NAS", async ({page}) => {
  await page.goto("/cameras/storage");
  await expect(page.getByText("7 days · low-resolution continuous")).toBeVisible();
  await expect(page.getByText("90 days · full-resolution native events")).toBeVisible();
  await expect(page.getByText("NAS decision pending measured evidence")).toBeVisible();
  await expect(page.getByRole("button", {name: /Buy|Order|Checkout/})).toHaveCount(0);
});
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/vision/test_storage_decision.py tests/integration/api/test_storage_decision_route.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_phase3_boot_composition.py -q && pnpm --filter @tuntun/admin e2e -- tests/e2e/cameras-storage.spec.ts`
Expected: FAIL because storage decision service/route/UI is absent.

- [ ] **Step 3: Implement measured projection, separate-copy truth, and signed decision**

Show physical SSD/volume identity commitment, encryption/health/temperature, usable/reserve, daily/event bytes, coverage/gaps, projected continuous/event days, `policy_bytes`, selected TrackMix view set, Green-backup separation, Mac impact, and every independent copy. Before seven measured days, show `measurement incomplete` only. Afterward compare retain SSD vs camera appliance vs general NAS/VMS on exact blocker, 3/4/6/8 streams, usable capacity/RAID, included/additional surveillance licences, TrackMix channel interpretation, UPS, power, 1/3/5-year cost, recovery, maintenance, warranty/return, and quote age. Quotes over 30 days or without landed Singapore cost remain comparison-only. Signing records evidence/revisit triggers but keeps procurement a future exact owner action.

~~~tsx
export const StorageRoute = () => (
  <Page title="Camera storage">
    <RetentionCommitment kind="continuous" days={7} resolution="low"/>
    <RetentionCommitment kind="native-event" days={90} resolution="full"/>
    <CapacityEvidence/>
    <EffectiveCopies/>
    <StorageDecisionPanel purchaseControls="absent"/>
  </Page>
);
~~~

- [ ] **Step 4: Run green and purchase-route negative scan**

Run: `uv run pytest tests/unit/vision/test_storage_decision.py tests/integration/api/test_storage_decision_route.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_phase3_boot_composition.py -q && pnpm --filter @tuntun/admin test && pnpm --filter @tuntun/admin lint && pnpm --filter @tuntun/admin typecheck && pnpm --filter @tuntun/admin build && pnpm --filter @tuntun/admin e2e -- tests/e2e/cameras-storage.spec.ts && uv run python scripts/check_feature_absence.py --feature phase3_hardware_purchase --phase 3`
Expected: PASS; measurement/decision values recompute; no purchase/order/payment route/config/client exists.

- [ ] **Step 5: Commit**

~~~bash
git add apps/core/src/tuntun_core/services/vision/storage_decision.py apps/core/src/tuntun_core/api/routes/cameras.py apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json apps/admin/src/features/cameras/storage.tsx apps/admin/src/routes/cameras-storage.tsx docs/procurement/phase3-storage-decision.md tests/unit/vision/test_storage_decision.py tests/integration/api/test_storage_decision_route.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_phase3_boot_composition.py tests/e2e/cameras-storage.spec.ts
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(vision): add measured storage decision UI"
~~~

### Task 24: Integrate Privacy Shield and separate recorder pause/resume controls

**Depends on:** Tasks 03, 05, 12–18, and Phase 1 privacy supervisor.
**Gate contribution:** P3-3/P3-6 privacy truth.
**Estimated effort:** 1.5 person-days.

**Files:**
- Modify: `apps/core/src/tuntun_core/services/privacy/supervisor.py`
- Create: `apps/core/src/tuntun_core/services/vision/privacy_effect.py`
- Modify: `apps/core/src/tuntun_core/services/vision/playback_broker.py`
- Modify: `apps/recorder/src/tuntun_recorder/recording/service.py`
- Modify: `apps/core/src/tuntun_core/api/routes/cameras.py`
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Modify: `tests/integration/deploy/test_owner_ingress_route_manifest.py`
- Modify: `tests/integration/vision/test_phase3_boot_composition.py`
- Modify: `apps/admin/src/features/cameras/overview.tsx`
- Create: `scripts/run_privacy_latency.py`
- Create: `tests/integration/vision/test_privacy_recorder_matrix.py`
- Create: `tests/security/vision/test_recorder_control_auth.py`
- Create: `tests/performance/vision/test_privacy_authority_deadline.py`
- Create: `tests/performance/vision/test_privacy_latency_runner.py`
- Create: `tests/e2e/cameras-privacy-controls.spec.ts`

**Interfaces:** Registers privacy effect `p3.camera_outcomes` and exact owner operations `recorder.pause.camera`, `recorder.pause.all`, `recorder.resume.camera`, and `recorder.resume.all`. Their exact prepared-mutation/API rows are added to the signed ingress manifest/router and canonical app/container; installed-candidate tests prove enabled owner-ingress traversal and 404/absence for voice, unknown, or disabled variants. Privacy effect consumes the canonical privacy generation; recorder operations consume fresh passkey grants bound to exact endpoints/current state/consequences/policy generation/expiry. `run_privacy_latency.py` resolves only a closed registered synthetic component ID, performs a fixed warm-up followed by the requested measured iterations with `perf_counter_ns`, records every sample and terminal effect, and computes nearest-rank p95 itself. Unknown components, nonpositive/over-limit iterations, clock anomalies, missing samples, handler errors, incomplete terminal effects, or p95 above the inclusive threshold fail closed; the tool performs no hardware, LAN, provider, or owner-data I/O.

- [ ] **Step 1: Write red four-state matrix, stale-event, passkey, and deadline tests**

~~~python
@pytest.mark.parametrize(
    ("shield", "recorder", "recording", "outcomes"),
    [
        ("off", "running", True, True),
        ("on", "running", True, False),
        ("off", "paused", False, False),
        ("on", "paused", False, False),
    ],
)
async def test_privacy_and_recorder_are_independent(system, shield, recorder, recording, outcomes) -> None:
    await system.set_state(shield=shield, recorder=recorder)
    assert system.new_recording_allowed is recording
    assert system.alert_presence_playback_allowed is outcomes

async def test_event_recorded_while_shielded_is_not_replayed_as_outcome_after_off(system) -> None:
    await system.privacy_on()
    clip = await system.native_event()
    assert clip.recorded is True
    await system.privacy_off_with_passkey()
    assert system.alerts_for(clip.event_id) == ()
    assert system.presence_for(clip.event_id) == ()

async def test_voice_cannot_pause_or_resume_recorder(system) -> None:
    for operation in ["recorder.pause.all", "recorder.resume.all"]:
        assert (await system.voice_request(operation)).outcome == "denied"
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/vision/test_privacy_recorder_matrix.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_phase3_boot_composition.py tests/security/vision/test_recorder_control_auth.py tests/performance/vision/test_privacy_authority_deadline.py tests/performance/vision/test_privacy_latency_runner.py -q && pnpm --filter @tuntun/admin e2e -- tests/e2e/cameras-privacy-controls.spec.ts`
Expected: FAIL because the Phase 3 privacy effect and recorder action registry are absent.

- [ ] **Step 3: Implement canonical revocation, per-effect truth, and recorder actions**

~~~python
async def on_privacy_generation(self, generation: int, committed_at: datetime) -> PrivacyEffectReceipt:
    self._eligibility.revoke_before(generation)
    await self._playback.revoke_all(reason="privacy_shield")
    await self._outcomes.close_generation(generation)
    acknowledgement = await self._video_ipc.request_outcome_stop(generation)
    return PrivacyEffectReceipt(
        effect_id="p3.camera_outcomes",
        privacy_generation=generation,
        authority_state="authority_revoked",
        downstream_state=acknowledgement.state_or_unverified(),
        recorder_continues=True,
    )
~~~

Privacy activation commits authority revocation/audit/outbox before fan-out and meets the existing ≤250 ms core/Reachy local deadline. It closes alert/presence emission, playback/export grants, uncommitted outcomes, and any future selected-frame request; the independent recorder continues event promotion/retention and its UI fact stays separate. Events created under a shielded generation never replay after deactivation. Recorder pause closes stream/event handles at a segment boundary, creates an explicit gap, and says the camera may remain powered/native recording may continue. Resume revalidates volume/source/egress/audio/arc/zone/capability/privacy generations before opening handles. Privacy off and every pause/resume require server-prepared exact binding plus fresh owner passkey; voice and ordinary session auth cannot execute them.

- [ ] **Step 4: Run green, latency, stale-generation, and UI truth checks**

Run: `uv run pytest tests/integration/vision/test_privacy_recorder_matrix.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_phase3_boot_composition.py tests/security/vision/test_recorder_control_auth.py tests/performance/vision/test_privacy_authority_deadline.py tests/performance/vision/test_privacy_latency_runner.py -q && pnpm --filter @tuntun/admin e2e -- tests/e2e/cameras-privacy-controls.spec.ts && uv run python scripts/run_privacy_latency.py --component p3.camera_outcomes --iterations 1000 --assert-core-p95-ms 250 && uv run python scripts/check_feature_absence.py --feature recorder_voice_control --phase 3 && uv run ruff check apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/owner-ingress/src/tuntun_owner_ingress/router.py scripts/run_privacy_latency.py tests/performance/vision/test_privacy_latency_runner.py && uv run mypy scripts/run_privacy_latency.py`
Expected: PASS; authority revocation P95 ≤250 ms, downstream timeout shows `unverified`, recorder truth remains independent, stale events/grants do not revive, and voice recorder control is absent.

- [ ] **Step 5: Commit**

~~~bash
git add apps/core/src/tuntun_core/services/privacy/supervisor.py apps/core/src/tuntun_core/services/vision/privacy_effect.py apps/core/src/tuntun_core/services/vision/playback_broker.py apps/recorder/src/tuntun_recorder/recording/service.py apps/core/src/tuntun_core/api/routes/cameras.py apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json apps/admin/src/features/cameras/overview.tsx scripts/run_privacy_latency.py tests/integration/vision/test_privacy_recorder_matrix.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_phase3_boot_composition.py tests/security/vision/test_recorder_control_auth.py tests/performance/vision/test_privacy_authority_deadline.py tests/performance/vision/test_privacy_latency_runner.py tests/e2e/cameras-privacy-controls.spec.ts
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(privacy): separate camera outcomes from recorder state"
~~~

## Wave 4 — P3-4 Native-Event Policy, Durable Owner Inbox, and Local Alerts

### Task 25: Validate camera events again at the video-to-policy boundary

**Depends on:** Tasks 03, 05–06, 14, and 24.
**Gate contribution:** P3-4 event-policy prerequisite.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/services/vision/event_ingress.py`
- Modify: `apps/core/src/tuntun_core/services/vision/privacy_policy.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/recorder/src/tuntun_recorder/events/normalizer.py`
- Modify: `tests/integration/vision/test_phase3_boot_composition.py`
- Create: `scripts/check_event_consumers.py`
- Create: `tests/contract/vision/test_event_ingress.py`
- Create: `tests/integration/vision/test_event_ingress_restart.py`
- Create: `tests/property/vision/test_event_boundary_rejection.py`
- Create: `tests/security/vision/test_event_has_no_authority.py`
- Create: `tests/security/vision/test_event_identity_memory_isolation.py`
- Create: `tests/security/vision/test_event_consumer_scanner.py`

**Interfaces:** Implements `CameraOutcomePort.ingest_security_event`. It consumes an authenticated IPC `CameraSecurityEventEnvelopeV1`, whose base is the canonical Phase 2 cross-domain envelope, and reopens the current camera binding, exact canonical `(area_id, area_generation)`, zone/`zone_generation`, source/capability, privacy policy, and privacy-generation state before dispatching an in-process observation. It produces only `EventIngressReceiptV1` and a validated ephemeral `CameraSecurityObservation`. The canonical Core container registers this exact worker/outbox consumer only when its signed feature row is enabled; the installed-candidate boot test exact-compares workers/consumers/adapters/routes/ports with the manifest and proves absence otherwise. `check_event_consumers.py` accepts one canonical event type plus nonempty, duplicate-free, disjoint allow/forbid consumer-class CSVs. It compares a bounded AST registration graph, generated event registry, feature manifest, and synthetic runtime registry snapshot; every observed consumer must be in the allowed set, but an allowed later-phase consumer need not yet be registered. Unresolved/dynamic registration, unknown classes, graph/runtime disagreement, any forbidden reachability, duplicate routes, parse/race/limit failure, or an incomplete inventory blocks rather than passing.

- [ ] **Step 1: Write red stale-generation, cross-zone, duplicate, and no-authority tests**

~~~python
@pytest.mark.parametrize(
    "mutation",
    [
        "area_id", "area_generation", "zone_id", "zone_generation", "camera_binding_generation",
        "capability_generation", "privacy_policy_version", "privacy_generation",
    ],
)
async def test_every_stale_or_substituted_binding_is_quarantined(ingress, event_envelope, mutation) -> None:
    receipt = await ingress.ingest_security_event(event_envelope.mutate(mutation))
    assert receipt.state == "quarantined"
    assert receipt.dispatched_to_alerts is False
    assert receipt.dispatched_to_presence is False

async def test_camera_event_cannot_reach_identity_memory_greeting_or_action(system, event_envelope) -> None:
    await system.camera_ingress.ingest_security_event(event_envelope)
    assert system.identity.calls == []
    assert system.memory.calls == []
    assert system.reachy_greeting.calls == []
    assert system.home_actions.calls == []

@pytest.mark.parametrize("fault", [
    "expired_at_receiver", "future_ingested_at", "untrusted_payload_clock",
])
async def test_camera_event_time_or_clock_failure_has_zero_reads_or_side_effects(
    ingress, event_envelope, fault,
) -> None:
    with pytest.raises((ValueError, EventQuarantined)):
        await ingress.ingest_security_event(event_envelope.mutate(fault))
    assert ingress.registry_reads == []
    assert ingress.cursor_writes == []
    assert ingress.outbox_writes == []
    assert ingress.router.calls == []

@pytest.mark.parametrize("fault", [
    "after_ingress_commit_before_dispatch",
    "after_first_consumer_before_outbox_ack",
])
async def test_committed_ingress_receipt_and_dispatch_survive_restart_exactly_once(
    system, event_envelope, fault,
) -> None:
    system.faults.arm(fault)
    with pytest.raises(SimulatedCrash):
        await system.camera_ingress.ingest_security_event(event_envelope)
    restarted = await system.restart()
    await restarted.camera_event_dispatch_outbox.drain()
    assert await restarted.ingress_store.cursor_for(
        event_envelope.source_endpoint_id, event_envelope.source_generation,
    ) == event_envelope.source_sequence
    assert await restarted.ingress_store.receipt_count(event_envelope.event_id) == 1
    assert await restarted.test_consumers.delivery_count(
        "alerting", event_envelope.event_id,
    ) == 1
    assert await restarted.test_consumers.delivery_count(
        "presence", event_envelope.event_id,
    ) == 1
    duplicate = await restarted.camera_ingress.ingest_security_event(event_envelope)
    assert duplicate.state == "duplicate"
    assert await restarted.test_consumers.delivery_count(
        "alerting", event_envelope.event_id,
    ) == 1
    assert await restarted.test_consumers.delivery_count(
        "presence", event_envelope.event_id,
    ) == 1
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/vision/test_event_ingress.py tests/integration/vision/test_event_ingress_restart.py tests/integration/vision/test_phase3_boot_composition.py tests/property/vision/test_event_boundary_rejection.py tests/security/vision/test_event_has_no_authority.py tests/security/vision/test_event_identity_memory_isolation.py tests/security/vision/test_event_consumer_scanner.py -q`
Expected: FAIL because `VisionEventIngress` is absent.

- [ ] **Step 3: Implement strict revalidation, dedupe, and observation-only dispatch**

~~~python
async def ingest_security_event(
    self, envelope: CameraSecurityEventEnvelopeV1,
) -> EventIngressReceiptV1:
    event = require_payload(envelope, "camera.security_event.v1", CameraSecurityEventV1)
    now = self._clock.now()
    validate_cross_domain_event_at_ingress(envelope, now=now)
    if event.clock_quality == "untrusted":
        raise EventQuarantined("camera_clock_untrusted")
    binding = await self._bindings.require_current(event.camera_binding_id, event.camera_binding_generation)
    if (
        envelope.source_endpoint_id != binding.source_endpoint_id
        or envelope.source_generation != binding.source_endpoint_generation
    ):
        raise EventQuarantined("camera_event_source_binding_mismatch")
    await self._topology.require_current_location(CanonicalLocationRefV1(
        area_id=event.area_id, area_generation=event.area_generation,
    ))
    await self._capabilities.require_current(binding, event.capability_generation)
    zone = await self._zones.require_current(
        area_id=event.area_id,
        area_generation=event.area_generation,
        zone_id=event.zone_id,
        zone_generation=event.zone_generation,
        camera_binding_id=binding.camera_binding_id,
        camera_binding_generation=binding.camera_binding_generation,
    )
    await self._privacy.require_current(
        policy_version=event.privacy_policy_version,
        privacy_generation=event.privacy_generation,
        at=now,
    )
    await self._privacy_shield.require_generation_eligible(
        event.privacy_generation, now,
    )
    observation = CameraSecurityObservation(event=event, zone=zone)
    # One serializable transaction validates/advances the per-source sequence,
    # claims both dedupe identities, stores the receipt, and writes the durable
    # alert/presence outbox row. A duplicate returns the prior receipt while an
    # undelivered outbox row remains dispatchable after any crash.
    receipt = await self._ingress_store.claim_sequence_dedupe_and_enqueue_once(
        source_endpoint_id=envelope.source_endpoint_id,
        source_generation=envelope.source_generation,
        source_sequence=envelope.source_sequence,
        event_id=envelope.event_id,
        deduplication_key=envelope.deduplication_key,
        observation=observation,
        envelope_commitment=commit_cross_domain_event(envelope),
        now=now,
    )
    await self._outbox.kick()
    return receipt
~~~

Reject unknown fields/version/type, unregistered endpoint, wrong area/zone/`zone_generation`, stale camera/capability/privacy generation, oversized payload, clock-untrusted event, duplicate content under a new key, shielded generation, pause, and disabled policy. The in-process router registers only alert and presence consumers; it has no IdentityPort, MemoryPort, Reachy wake/greeting, provider/model, HA action/routine, screen-time, desktop, or robot consumer. Logs/audit contain safe reason/commitment only; core does not persist the full camera event body.

- [ ] **Step 4: Run green, randomized boundary corpus, and import/reachability scan**

Run: `uv run pytest tests/contract/vision/test_event_ingress.py tests/integration/vision/test_event_ingress_restart.py tests/integration/vision/test_phase3_boot_composition.py tests/property/vision/test_event_boundary_rejection.py tests/security/vision/test_event_has_no_authority.py tests/security/vision/test_event_identity_memory_isolation.py tests/security/vision/test_event_consumer_scanner.py -q && uv run pytest tests/property/vision/test_event_boundary_rejection.py --hypothesis-seed=31025 -q && uv run python scripts/check_event_consumers.py --event camera.security_event.v1 --allow alerting,presence --forbid identity,memory,greeting,provider,home_action,screen_time,desktop,robot && uv run ruff check apps/core/src/tuntun_core/services/vision/event_ingress.py apps/core/src/tuntun_core/services/vision/privacy_policy.py apps/core/src/tuntun_core/bootstrap/container.py scripts/check_event_consumers.py tests/contract/vision tests/integration/vision/test_event_ingress_restart.py tests/integration/vision/test_phase3_boot_composition.py tests/property/vision tests/security/vision && uv run mypy apps/core/src scripts/check_event_consumers.py`
Expected: PASS; every stale/substituted generation quarantines, and no event-to-authority path exists.

- [ ] **Step 5: Commit**

~~~bash
git add apps/core/src/tuntun_core/services/vision/event_ingress.py apps/core/src/tuntun_core/services/vision/privacy_policy.py apps/core/src/tuntun_core/bootstrap/container.py apps/recorder/src/tuntun_recorder/events/normalizer.py scripts/check_event_consumers.py tests/contract/vision/test_event_ingress.py tests/integration/vision/test_event_ingress_restart.py tests/integration/vision/test_phase3_boot_composition.py tests/property/vision/test_event_boundary_rejection.py tests/security/vision/test_event_has_no_authority.py tests/security/vision/test_event_identity_memory_isolation.py tests/security/vision/test_event_consumer_scanner.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "security(vision): validate camera event policy boundary"
~~~

### Task 26: Calibrate alert classes and deliver a durable local owner inbox with SSE

**Depends on:** Tasks 03, 17, 24–25.
**Gate contribution:** P3-4.
**Estimated effort:** 2 person-days plus seven elapsed calibration days.

**Files:**
- Create: `apps/core/src/tuntun_core/services/vision/alerting.py`
- Create: `apps/core/src/tuntun_core/api/routes/camera_alerts.py`
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Modify: `ops/services/phase3-owner-ingress.v1.json`
- Modify: `tests/integration/deploy/test_owner_ingress_route_manifest.py`
- Modify: `tests/integration/vision/test_phase3_boot_composition.py`
- Modify: `tests/integration/vision/test_deployed_process_entrypoints.py`
- Modify: `tests/integration/deploy/test_phase3_side_process_lifecycle.py`
- Modify: `tests/integration/vision/test_owner_ingress_takeover.py`
- Modify: `tests/fault/vision/test_owner_ingress_takeover_rollback.py`
- Create: `scripts/phase3/calibrate_alerts.py`
- Create: `fixtures/synthetic/vision/alert-calibration.json`
- Create: `docs/evidence/phase3-alert-quality-schema.json`
- Create: `docs/operations/phase3-alerts-presence.md`
- Create: `tests/unit/vision/test_alert_policy.py`
- Create: `tests/unit/vision/test_alert_dedupe_cooldown.py`
- Create: `tests/integration/vision/test_alert_inbox_sse.py`
- Create: `tests/security/vision/test_alert_minimization.py`
- Create: `tests/acceptance/vision/test_alert_quality_gate.py`
- Create: `tests/acceptance/vision/test_alert_feature_authority.py`

**Interfaces:** Produces exact owner-passkey alert-policy preparation/installation, `OwnerAlertService.consume`, the closed `SafeAlertSSEV1` delivery class `local_owner_inbox_sse_v1`, a metadata-only 24-hour delivery queue, durable local event inbox projection, authenticated `GET /api/v1/ui/cameras/alerts/stream` SSE, and content-minimized delivery receipts. It consumes only validated observations from Task 25 and opaque clip availability—not playback grants. The task adds the exact SSE/read/mutation rows to the signed ingress route manifest, registers them in the canonical ASGI app/container, and updates the installed-candidate test to prove listener→owner-ingress→Core UDS reachability for each enabled alert route, 404 for unknown/disabled routes, and exact manifest equality for routes/workers/consumers. The committed calibration fixture is a deterministic, generated-ID-only matrix with the exact positive, negative, duplicate, cooldown, stale, unavailable-clip, and privacy cases required by the quality oracle; missing, extra, duplicate, contradictory, or label-bearing rows invalidate calibration. A physical seven-day calibration consumes the complete Phase 2 canonical pre-issued rollover chain and exact `FeatureAuthorityCampaignEvidenceV1`, binding its chain/candidate/ordered manifest/transition/restart/sample-log/interval facts and canonical zero counters; no Phase 3 code signs or renews authority.

The immutable composition constructor injects `FeatureManifestLeaseSupervisor` plus that generation's exact authority digest into `OwnerAlertService`. `consume` checks the half-open wall and monotonic lease before topology, catalog, policy, inbox, or outbox access; the serialized inbox/outbox transaction repeats the same current-generation check after acquiring the writer and before its first write. The outbox worker checks again before every dequeue and SSE send. Equality, rollback, rollover/restart fault, missing receipt, or generation drift leaves the row undelivered, advances no cursor/cooldown/inbox/outbox state after the fault boundary, closes the composition barrier, invalidates the calibration, and enters controlled recovery. `test_alert_feature_authority.py` imports the Phase 2 Task 13-owned shared harness at preflight, post-writer-lock, and pre-SSE-send pause points, so a caller-authored zero-gap claim cannot bypass live authority or semantic verification.

- [ ] **Step 1: Write red quality, dedupe, owner-only, queue, and content tests**

~~~python
@pytest.mark.parametrize("fault", DOWNSTREAM_FEATURE_AUTHORITY_FAULTS)
async def test_alert_authority_fault_has_no_post_fault_inbox_or_delivery(
    feature_authority_campaign_harness, alert_campaign_adapter, alert_verifier, fault,
) -> None:
    result = await feature_authority_campaign_harness.exercise(
        runner=alert_campaign_adapter,
        verifier=alert_verifier,
        fault=fault,
    )
    assert result.post_fault_admission_delta == 0
    assert result.post_fault_preparation_delta == 0
    assert result.post_fault_provider_call_delta == 0
    assert result.post_fault_trigger_delta == 0
    assert result.post_fault_effect_delta == 0
    assert result.campaign_invalid and result.semantic_verifier_rejected

def test_alert_policy_requires_exact_quality_evidence(policy_service, evidence) -> None:
    evidence.accepted_recall = Decimal("0.949")
    with pytest.raises(EvidenceInsufficient, match="alert_recall_below_gate"):
        policy_service.prepare_enable(evidence)

async def test_updates_and_sixty_second_cooldown_create_one_owner_alert(alerts) -> None:
    for event in repeated_same_camera_class_zone_updates(within_seconds=60):
        await alerts.consume(event)
    assert await alerts.inbox.count() == 1
    assert await alerts.sse.deliveries() == 1

async def test_alert_payload_has_no_media_identity_address_or_reusable_token(alerts, valid_event) -> None:
    payload = await alerts.consume(valid_event)
    forbidden = {"thumbnail", "media_bytes", "playback_token", "name", "profile_id", "child_id", "camera_address", "stream_url"}
    assert forbidden.isdisjoint(deep_keys(payload.model_dump()))

@pytest.mark.parametrize("fault", [
    "expired", "area_generation", "camera_binding_generation",
    "capability_generation", "zone_generation", "privacy_policy_version",
    "privacy_generation", "privacy_shield_enabled",
])
async def test_alert_revalidates_every_current_authority_before_durable_effect(
    alerts, valid_observation, fault,
) -> None:
    with pytest.raises(AlertRejected):
        await alerts.consume(valid_observation.mutate_or_drift_live(fault))
    assert await alerts.inbox.count() == 0
    assert await alerts.sse_outbox.count() == 0

@pytest.mark.parametrize("crash_at", [
    "before_transaction", "after_cooldown_before_inbox", "after_inbox_before_outbox",
    "after_commit_before_delivery",
])
async def test_alert_claim_inbox_and_sse_outbox_reconcile_exactly_once(
    alerts, valid_observation, crash_at,
) -> None:
    with suppress(SimulatedCrash):
        await alerts.consume_with_crash(valid_observation, crash_at)
    restarted = await alerts.restart_and_drain()
    assert await restarted.inbox.count_for(valid_observation) in {0, 1}
    assert await restarted.sse_outbox.delivered_count_for(valid_observation) in {0, 1}
    assert (
        await restarted.inbox.count_for(valid_observation)
        == await restarted.sse_outbox.delivered_count_for(valid_observation)
    )

async def test_alert_enqueue_uses_original_event_deadlines(alerts, valid_observation) -> None:
    alerts.clock.set(valid_observation.event.observed_at + timedelta(seconds=30))
    receipt = await alerts.consume(valid_observation)
    row = await alerts.inbox.require(receipt.alert_id)
    assert row.enqueued_at == valid_observation.event.observed_at + timedelta(seconds=30)
    assert row.inbox_expires_at == valid_observation.event.observed_at + timedelta(hours=24)
    replayed = await (await alerts.restart()).sse_outbox.serialize(row.id)
    assert replayed.inbox_expires_at == row.inbox_expires_at
    alerts.clock.advance(microseconds=1)
    with pytest.raises(AlertRejected, match="observation_expired"):
        await alerts.consume(valid_observation.with_new_event_id())
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/support/test_feature_authority_campaign.py tests/unit/vision/test_alert_policy.py tests/unit/vision/test_alert_dedupe_cooldown.py tests/integration/vision/test_alert_inbox_sse.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_phase3_boot_composition.py tests/security/vision/test_alert_minimization.py tests/acceptance/vision/test_alert_quality_gate.py tests/acceptance/vision/test_alert_feature_authority.py -q`
Expected: FAIL because alert service/route/calibration is absent.

- [ ] **Step 3: Implement exact policy, durable inbox, dedupe, SSE, and quality verifier**

~~~python
async def consume(self, observation: CameraSecurityObservation) -> AlertReceipt:
    event = observation.event
    now = self._clock.now()
    monotonic_ns = self._clock.monotonic_ns()
    self._feature_authority.require_admission(
        authority_digest=self._composition_authority_digest,
        now=now,
        monotonic_ns=monotonic_ns,
    )
    if not event.observed_at <= now <= event.observed_at + timedelta(seconds=30):
        raise AlertRejected("camera_alert_observation_expired")
    binding = await self._bindings.require_current(
        event.camera_binding_id, event.camera_binding_generation,
    )
    await self._topology.require_current_location(CanonicalLocationRefV1(
        area_id=event.area_id, area_generation=event.area_generation,
    ))
    await self._capabilities.require_current(binding, event.capability_generation)
    await self._zones.require_current(
        area_id=event.area_id, area_generation=event.area_generation,
        zone_id=event.zone_id, zone_generation=event.zone_generation,
        camera_binding_id=event.camera_binding_id,
        camera_binding_generation=event.camera_binding_generation,
    )
    await self._privacy.require_current(
        policy_version=event.privacy_policy_version,
        privacy_generation=event.privacy_generation,
        at=now,
    )
    await self._privacy_shield.require_generation_eligible(event.privacy_generation, now)
    policy = await self._policies.require_enabled(
        camera_binding_id=event.camera_binding_id,
        camera_generation=event.camera_binding_generation,
        capability_generation=event.capability_generation,
        area_id=event.area_id,
        area_generation=event.area_generation,
        zone_id=event.zone_id,
        zone_generation=event.zone_generation,
        event_class=event.event_class,
        privacy_policy_version=event.privacy_policy_version,
        privacy_generation=event.privacy_generation,
        at=now,
    )
    key = policy.cooldown_key(event)
    # Cooldown claim, metadata-only inbox row, receipt, and SSE outbox row are
    # one serializable transaction. Duplicate delivery returns the stored
    # receipt and preserves any committed-but-undelivered SSE outbox work.
    receipt = await self._alerts.claim_commit_and_enqueue_once(
        cooldown_key=key,
        cooldown_seconds=60,
        event=event,
        policy=policy,
        inbox_expires_at=event.observed_at + timedelta(hours=24),
        accepted_at=now,
        expected_authority_digest=self._composition_authority_digest,
        feature_authority=self._feature_authority,
    )
    self._feature_authority.require_admission(
        authority_digest=self._composition_authority_digest,
        now=self._clock.now(),
        monotonic_ns=self._clock.monotonic_ns(),
    )
    await self._sse_outbox.kick()
    return receipt
~~~

An enable request binds exact camera/class/area/zone/`zone_generation`/schedule/60-second cooldown/the closed `local_owner_inbox_sse_v1` delivery class/privacy/capability/policy generations and quality digest. `person` is the first candidate; every other class remains separately absent until it passes. Calibration requires ≥30 positive traversals across day/IR/ordinary light, ≥95% accepted recall, seven representative days, ≤1 false owner alert per 24 hours, zero duplicate on replay/reconnect/restart, and reachable-page local event-to-SSE P95 ≤5 seconds. A high-risk deviation requires a separate fresh owner-passkey record bound to exact measured failures, risk text, policy, and expiry. Queue only one implicit owner recipient, expires delivery rows at 24 hours, and records original event/delayed time. The SSE serializer sets `valid_until = min(emitted_at + 30 seconds, inbox_expires_at)`; an exact inbox-expiry boundary is valid, while one microsecond beyond it rejects, so delayed replay cannot refresh inbox authority. With no authenticated page, it makes no immediate-delivery claim. Privacy/pause/revocation/stale/clock-untrusted/excluded class/zone yields zero new alert. No alert wakes/speaks through Reachy or calls HA.

- [ ] **Step 4: Run green, synthetic calibration, SSE reconnect, and absence checks**

Run: `uv run pytest tests/support/test_feature_authority_campaign.py tests/unit/vision/test_alert_policy.py tests/unit/vision/test_alert_dedupe_cooldown.py tests/integration/vision/test_alert_inbox_sse.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_phase3_boot_composition.py tests/security/vision/test_alert_minimization.py tests/acceptance/vision/test_alert_quality_gate.py tests/acceptance/vision/test_alert_feature_authority.py -q && uv run python scripts/phase3/calibrate_alerts.py synthetic --events fixtures/synthetic/vision/alert-calibration.json --output var/evidence/phase3/synthetic-alert-quality.json && uv run python scripts/phase3/calibrate_alerts.py verify var/evidence/phase3/synthetic-alert-quality.json && uv run python scripts/check_feature_absence.py --features background_push,native_companion,sms,email,vendor_cloud_alert,camera_greeting,camera_home_action --phase 3 && uv run ruff check apps/core/src/tuntun_core/services/vision/alerting.py apps/core/src/tuntun_core/api/routes/camera_alerts.py apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/owner-ingress/src/tuntun_owner_ingress/router.py scripts/phase3/calibrate_alerts.py tests/unit/vision tests/integration/vision tests/security/vision tests/acceptance/vision && uv run mypy apps/core/src`
Expected: PASS; reconnect from last accepted event ID creates no duplicate, closed-page state is delayed/unread rather than delivered, and every prohibited transport/action is absent.

- [ ] **Refresh and qualify the Task 26 owner-ingress checkpoint before the calibration commit.** After the Tasks 21/23/24/26 Core/router/manifest bytes are final, rebuild the locked `tuntun-owner-ingress` wheel, refresh and externally re-sign the canonical `ops/services/phase3-owner-ingress.v1.json`, and run `uv build --offline --wheel --package tuntun-owner-ingress --out-dir var/build-smoke/phase3/owner-ingress-task26 && uv lock --check && uv run --locked --offline --no-sync pytest tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_phase3_boot_composition.py -q`. Require the full Global Constraint 23 lifecycle, exact listener-to-Core dispatch for every alert/read/privacy row, and rejection of the Task 17 row/receipt.

- [ ] **Step 5: Commit tooling and service before any physical calibration; never commit owner evidence**

~~~bash
git add apps/core/src/tuntun_core/services/vision/alerting.py apps/core/src/tuntun_core/api/routes/camera_alerts.py apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json ops/services/phase3-owner-ingress.v1.json scripts/phase3/calibrate_alerts.py fixtures/synthetic/vision/alert-calibration.json docs/evidence/phase3-alert-quality-schema.json docs/operations/phase3-alerts-presence.md tests/unit/vision/test_alert_policy.py tests/unit/vision/test_alert_dedupe_cooldown.py tests/integration/vision/test_alert_inbox_sse.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_phase3_boot_composition.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py tests/security/vision/test_alert_minimization.py tests/acceptance/vision/test_alert_quality_gate.py tests/acceptance/vision/test_alert_feature_authority.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(vision): add calibrated local owner alerts"
~~~

After the commit, require an empty worktree, rebuild/install and lifecycle-verify the exact resolved Task 26 candidate without changing bytes, and only then obtain its new externally signed chain. Run one exact camera/class/zone calibration at a time with `TUNTUN_ALLOW_ELAPSED_PHASE3=1 uv run python scripts/phase3/calibrate_alerts.py household --feature-manifest-chain var/evidence/phase3/feature-authority/task26/CAMERA_BINDING_ID/CAMERA_BINDING_GENERATION/EVENT_CLASS/ZONE_ID/ZONE_GENERATION/signed-rollover-chain.json --duration-seconds 604800 --camera-binding-id CAMERA_BINDING_ID --camera-binding-generation CAMERA_BINDING_GENERATION --event-class EVENT_CLASS --zone-id ZONE_ID --zone-generation ZONE_GENERATION --output var/evidence/phase3/alerts/CAMERA_BINDING_ID/CAMERA_BINDING_GENERATION/EVENT_CLASS/ZONE_ID/ZONE_GENERATION/alert-quality.json`, then verify it with `uv run python scripts/phase3/calibrate_alerts.py verify var/evidence/phase3/alerts/CAMERA_BINDING_ID/CAMERA_BINDING_GENERATION/EVENT_CLASS/ZONE_ID/ZONE_GENERATION/alert-quality.json --feature-manifest-chain var/evidence/phase3/feature-authority/task26/CAMERA_BINDING_ID/CAMERA_BINDING_GENERATION/EVENT_CLASS/ZONE_ID/ZONE_GENERATION/signed-rollover-chain.json --require-physical --require-zero-expired-authority`. Each changed candidate/registration/service-row/binding/zone generation gets a new directory and externally signed chain; failed classes, feature-authority gaps, or candidate drift stay absent.

### Task 27: Build alert policy, event inbox, SSE, and truthful delayed-delivery UI

**Depends on:** Tasks 22 and 26.
**Gate contribution:** P3-4 UI.
**Estimated effort:** 1.5 person-days.

**Files:**
- Modify: `packages/contracts/openapi/admin-v1.yaml`
- Modify: `apps/admin/src/api/generated/admin-v1.ts`
- Modify: `apps/admin/src/api/bounded-event-stream.ts`
- Modify: `apps/admin/src/api/bounded-json.ts`
- Create: `scripts/scan_web_bundle.py`
- Create: `apps/admin/src/features/cameras/alerts.tsx`
- Create: `apps/admin/src/features/cameras/use-owner-alert-stream.ts`
- Create: `apps/admin/src/routes/cameras-alerts.tsx`
- Modify: `tests/contract/api/test_vision_openapi.py`
- Create: `tests/unit/admin/cameras/owner-alert-stream.test.ts`
- Create: `tests/e2e/cameras-alerts.spec.ts`
- Create: `tests/e2e/cameras-alerts-reconnect.spec.ts`
- Create: `tests/ui/cameras-alerts-accessibility.spec.ts`
- Create: `tests/security/ui/test_no_background_alert_transport.py`
- Create: `tests/security/ui/test_phase3_web_bundle_scanner.py`

**Interfaces:** Produces owner route `/cameras/alerts`, exact policy/calibration prepared mutations, durable inbox, and active-page notification mirror. It consumes same-origin SSE safe summaries through the shared authenticated fetch-stream client with a 16-KiB max-plus-one frame bound and uses clip references only to navigate to Task 22's separately authorized playback flow. `scan_web_bundle.py` is a thin Phase 3 wrapper over the canonical `scan_browser_artifacts.py` bounded/nofollow implementation: it requires the current admin production manifest, every emitted chunk and source map to form one complete stable inventory, normalizes identifier/property spellings, and applies a nonempty duplicate-free forbidden CSV. A missing build/manifest/chunk/map, corrupt compression/map, symlink/special/change, decode/limit failure, or forbidden token blocks; JavaScript is never executed.

- [ ] **Step 1: Write red reconnect/dedupe, closed-page truth, no-thumbnail, and no-service-worker tests**

~~~typescript
test("SSE reconnect resumes after last accepted ID without duplicate card", async ({page}) => {
  const eventId = "018f6d41-7b0d-7bb7-8c2a-64e7cbf2588b";
  await page.goto("/cameras/alerts");
  await emitSafeAlert(page, {id: eventId});
  await disconnectSSE(page);
  await reconnectSSE(page, {lastEventId: eventId});
  await expectLastAlertStreamRequestHeader(page, "Last-Event-ID", eventId);
  await emitSafeAlert(page, {id: eventId});
  await expect(page.getByTestId(eventId)).toHaveCount(1);
});

test("closed owner page never claims immediate delivery", async ({page}) => {
  await seedDelayedAlert(page, {originalTime: "10:00", firstViewedTime: "10:30"});
  await page.goto("/cameras/alerts");
  await expect(page.getByText("First shown 30 minutes after the event")).toBeVisible();
  await expect(page.getByText("Delivered immediately")).toHaveCount(0);
});
~~~

~~~typescript
// tests/unit/admin/cameras/owner-alert-stream.test.ts
import {expect, test, vi} from "vitest";
import safeAlertSseFixture from "../../../../fixtures/synthetic/vision/contracts/safe-alert-sse-v1.json";
import {
  consumeOwnerAlertBody, MAX_SAFE_ALERT_EVENT_BYTES,
} from "../../../../apps/admin/src/features/cameras/use-owner-alert-stream";

const utf8 = new TextEncoder();
function streamOf(...parts: string[]): ReadableStream<Uint8Array> {
  return new ReadableStream({start(controller) {
    for (const part of parts) controller.enqueue(utf8.encode(part));
    controller.close();
  }});
}

const hostileFrames: Array<[string, string[]]> = [
  ["malformed JSON", ['id: 018f6d41-7b0d-7bb7-8c2a-64e7cbf2588b\ndata: {"event_id":\n\n']],
  ["schema-invalid JSON", ['id: 018f6d41-7b0d-7bb7-8c2a-64e7cbf2588b\ndata: {"event_id":"018f6d41-7b0d-7bb7-8c2a-64e7cbf2588b","unknown":true}\n\n']],
  ["duplicate JSON key", ['id: 018f6d41-7b0d-7bb7-8c2a-64e7cbf2588b\ndata: {"event_id":"018f6d41-7b0d-7bb7-8c2a-64e7cbf2588b","event_id":"018f6d41-7b0d-7bb7-8c2a-64e7cbf2588b"}\n\n']],
  ["overdeep JSON", [`id: 018f6d41-7b0d-7bb7-8c2a-64e7cbf2588b\ndata: ${"[".repeat(33)}0${"]".repeat(33)}\n\n`]],
  ["excessive JSON structure tokens", [`id: 018f6d41-7b0d-7bb7-8c2a-64e7cbf2588b\ndata: [${"0,".repeat(1_024)}0]\n\n`]],
  ["unsafe JSON integer", ['id: 018f6d41-7b0d-7bb7-8c2a-64e7cbf2588b\ndata: {"event_id":9007199254740992}\n\n']],
];
test.each(hostileFrames)("%s closes the stream without inbox, cursor, or notification mutation", async (_case, parts) => {
  const previous = "018f6d41-7b0d-7bb7-8c2a-64e7cbf25880";
  const cursor = {current: previous};
  const accept = vi.fn();
  const notify = vi.fn();
  await expect(consumeOwnerAlertBody(
    streamOf(...parts), cursor, {accept, notify}, new AbortController().signal,
  )).rejects.toThrow();
  expect(cursor.current).toBe(previous);
  expect(accept).not.toHaveBeenCalled();
  expect(notify).not.toHaveBeenCalled();
});

test("a split oversize frame is rejected by the byte boundary before visible effects", async () => {
  const cursor = {current: "018f6d41-7b0d-7bb7-8c2a-64e7cbf25880"};
  const accept = vi.fn();
  const notify = vi.fn();
  const prefix = 'id: 018f6d41-7b0d-7bb7-8c2a-64e7cbf2588b\ndata: ';
  await expect(consumeOwnerAlertBody(streamOf(
    prefix,
    "x".repeat(MAX_SAFE_ALERT_EVENT_BYTES / 2),
    `${"x".repeat(MAX_SAFE_ALERT_EVENT_BYTES / 2 + 1)}\n\n`,
  ), cursor, {accept, notify}, new AbortController().signal)).rejects.toMatchObject({
    code: "sse_event_too_large",
  });
  expect(cursor.current).toBe("018f6d41-7b0d-7bb7-8c2a-64e7cbf25880");
  expect(accept).not.toHaveBeenCalled();
  expect(notify).not.toHaveBeenCalled();
});

test("mismatched SSE and body IDs are rejected before any visible effect", async () => {
  const cursor = {current: null};
  const accept = vi.fn();
  const notify = vi.fn();
  const body = JSON.stringify({
    ...safeAlertSseFixture,
    event_id: "018f6d41-7b0d-7bb7-8c2a-64e7cbf2588c",
  });
  await expect(consumeOwnerAlertBody(
    streamOf(`id: 018f6d41-7b0d-7bb7-8c2a-64e7cbf2588b\ndata: ${body}\n\n`),
    cursor, {accept, notify}, new AbortController().signal,
  )).rejects.toThrow("alert stream event ID mismatch");
  expect(cursor.current).toBeNull();
  expect(accept).not.toHaveBeenCalled();
  expect(notify).not.toHaveBeenCalled();
});

test("a valid replay of the last accepted ID has no duplicate visible effect", async () => {
  const eventId = "018f6d41-7b0d-7bb7-8c2a-64e7cbf2588b";
  const cursor = {current: eventId};
  const accept = vi.fn();
  const notify = vi.fn();
  const body = JSON.stringify({...safeAlertSseFixture, event_id: eventId});
  await consumeOwnerAlertBody(
    streamOf(`id: ${eventId}\ndata: ${body}\n\n`),
    cursor, {accept, notify}, new AbortController().signal,
  );
  expect(cursor.current).toBe(eventId);
  expect(accept).not.toHaveBeenCalled();
  expect(notify).not.toHaveBeenCalled();
});
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/security/ui/test_phase3_web_bundle_scanner.py -q && pnpm --filter @tuntun/admin test -- tests/unit/admin/cameras/owner-alert-stream.test.ts && pnpm --filter @tuntun/admin e2e -- tests/e2e/cameras-alerts.spec.ts tests/e2e/cameras-alerts-reconnect.spec.ts`
Expected: FAIL because the bounded alert-stream consumer and `/cameras/alerts` route do not exist.

- [ ] **Step 3: Implement active-page SSE, optional browser mirror, and exact policy UI**

~~~typescript
import {useEffect, useRef} from "react";
import type {TuntunClient} from "../../api/client";
import {abortableDelay, parseBoundedEventStream} from "../../api/bounded-event-stream";
import {parseCanonicalJson} from "../../api/bounded-json";
import {
  SafeAlertSSEV1Schema, type SafeAlertSSEV1,
} from "../../api/generated/admin-v1";
import {requireAuthenticatedClient} from "../auth";
import {alertInbox} from "./alerts";

export const MAX_SAFE_ALERT_EVENT_BYTES = 16_384;
type AlertCursor = {current: string | null};
type AlertEffects = {
  accept: (safe: SafeAlertSSEV1) => void;
  notify: (safe: SafeAlertSSEV1) => void;
};

export async function consumeOwnerAlertBody(
  body: ReadableStream<Uint8Array>, cursor: AlertCursor, effects: AlertEffects, signal: AbortSignal,
): Promise<void> {
  await parseBoundedEventStream(body, {
    signal,
    maxEventBytes: MAX_SAFE_ALERT_EVENT_BYTES,
    onMessage(data, sseEventId) {
      const decoded = parseCanonicalJson(data, {
        maxBytes: MAX_SAFE_ALERT_EVENT_BYTES,
        maxDepth: 32,
        maxContainers: 256,
        maxStructureTokens: 1_024,
      });
      const safe = SafeAlertSSEV1Schema.parse(decoded);
      if (!sseEventId || sseEventId !== safe.event_id) {
        throw new Error("alert stream event ID mismatch");
      }
      if (cursor.current === sseEventId) return;
      effects.accept(safe);
      cursor.current = sseEventId;
      effects.notify(safe);
    },
  });
}

function subscribeOwnerAlerts(
  client: TuntunClient, cursor: AlertCursor, effects: AlertEffects,
): () => void {
  const controller = new AbortController();
  void (async () => {
    let delay = 1_000;
    while (!controller.signal.aborted) {
      try {
        const headers: Record<string, string> = {Accept: "text/event-stream"};
        if (cursor.current) headers["Last-Event-ID"] = cursor.current;
        const response = await client.raw(
          "GET", "/api/v1/ui/cameras/alerts/stream", undefined, headers,
        );
        if (!response.ok || !response.body) throw new Error("alert stream rejected");
        await consumeOwnerAlertBody(response.body, cursor, effects, controller.signal);
        if (!controller.signal.aborted) throw new Error("alert stream ended");
      } catch {
        if (controller.signal.aborted) return;
        try { await abortableDelay(delay, controller.signal); }
        catch { return; }
        delay = Math.min(delay * 2, 30_000);
      }
    }
  })();
  return () => controller.abort();
}

export function useOwnerAlertStream(enabled: boolean) {
  const cursor = useRef<string | null>(null);
  useEffect(() => {
    if (!enabled) return;
    const client = requireAuthenticatedClient();
    let stop: (() => void) | undefined;
    const synchronizeVisibility = () => {
      stop?.();
      stop = undefined;
      if (document.visibilityState !== "visible") return;
      stop = subscribeOwnerAlerts(client, cursor, {
        accept: safe => alertInbox.accept(safe),
        notify: safe => {
          if (document.visibilityState === "visible" && Notification.permission === "granted") {
            new Notification(safe.safe_title, {body: safe.safe_body, tag: safe.event_id});
          }
        },
      });
    };
    document.addEventListener("visibilitychange", synchronizeVisibility);
    synchronizeVisibility();
    return () => {
      document.removeEventListener("visibilitychange", synchronizeVisibility);
      stop?.();
    };
  }, [enabled]);
}
~~~

The shared `parseBoundedEventStream` is a byte-oriented, fatal-UTF-8 SSE state machine, not an alias for native `EventSource`. It allocates one reusable `maxEventBytes + 1` frame buffer, processes arbitrarily split/coalesced chunks without concatenating an unbounded string, counts `id`, `data`, comments, separators, and line endings toward the ceiling, and raises `BoundedEventStreamError(code="sse_event_too_large")` immediately when the max-plus-one byte is observed, before decoding, growing a buffer, or invoking a callback. Other closed error codes cover duplicate/empty/NUL or data-less event IDs, unknown fields, invalid line endings, malformed UTF-8, and an incomplete EOF frame. It permits comment-only heartbeats, emits only a complete blank-line-terminated message, joins bounded repeated `data` lines per the SSE rule, cancels/releases the reader on abort or any parser/callback error, and never invokes `onMessage` for a partial/rejected frame. Its callback signature is `(data: string, eventId: string | null) => void`; each canonical JSON body then crosses Phase 1's shared byte/depth/container/token/number/Unicode boundary before the generated alert schema and exact SSE/body-ID binding. Duplicate keys and last-key-wins projection are impossible. Every reconnect above obtains a fresh loopback proof through `TuntunClient.raw`, sends the last ID only in `Last-Event-ID`, and never uses query credentials, cookies, or native `EventSource`.

Show class, safe zone label, original local time, verification, clip availability, read/delayed/delivery state, and policy/quality evidence. Never render thumbnail/audio/identity/address/token. Advance the in-memory cursor only after the generated schema and SSE/body-ID binding pass and the inbox accepts the event; only then may the best-effort browser mirror run. A malformed, schema-invalid, mismatched, duplicate, or oversized frame mutates neither inbox nor cursor and raises no notification. Browser Notification API is offered only while the paired authenticated page is visible and after explicit permission; `visibilitychange` aborts the stream immediately and a visible page reconnects with a fresh proof. Do not register a service worker, Push API subscription, background sync, native bridge, analytics, SMS/email, or vendor cloud. Security containment may disable future external adapters but must leave the local inbox/SSE critical banner visible.

- [ ] **Step 4: Run green, UI/accessibility, bundle, and background-transport scans**

Run: `sh scripts/generate_openapi_client.sh && git diff --exit-code -- packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts && uv run pytest tests/contract/api/test_vision_openapi.py tests/security/ui/test_no_background_alert_transport.py tests/security/ui/test_phase3_web_bundle_scanner.py -q && pnpm --filter @tuntun/admin test -- tests/unit/admin/cameras/owner-alert-stream.test.ts && pnpm --filter @tuntun/admin lint && pnpm --filter @tuntun/admin typecheck && pnpm --filter @tuntun/admin build && pnpm --filter @tuntun/admin e2e -- tests/e2e/cameras-alerts.spec.ts tests/e2e/cameras-alerts-reconnect.spec.ts tests/ui/cameras-alerts-accessibility.spec.ts && uv run python scripts/scan_web_bundle.py --forbid EventSource,serviceWorker,PushManager,backgroundSync,thumbnailUrl,cameraAddress && uv run ruff check scripts/scan_web_bundle.py tests/security/ui/test_phase3_web_bundle_scanner.py && uv run mypy scripts/scan_web_bundle.py`
Expected: PASS; malformed, duplicate-key, overdeep, excessive-token, unsafe-number, schema-invalid, mismatched, or split-oversized frames produce zero inbox, cursor, or notification mutation; reconnect sends the last accepted ID in the authenticated header without a duplicate; delayed state is truthful; the hidden page closes its stream; and native/background/external transports are absent.

- [ ] **Step 5: Commit**

~~~bash
git add packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts apps/admin/src/api/bounded-event-stream.ts apps/admin/src/api/bounded-json.ts apps/admin/src/features/cameras/alerts.tsx apps/admin/src/features/cameras/use-owner-alert-stream.ts apps/admin/src/routes/cameras-alerts.tsx scripts/scan_web_bundle.py tests/contract/api/test_vision_openapi.py tests/unit/admin/cameras/owner-alert-stream.test.ts tests/e2e/cameras-alerts.spec.ts tests/e2e/cameras-alerts-reconnect.spec.ts tests/ui/cameras-alerts-accessibility.spec.ts tests/security/ui/test_no_background_alert_transport.py tests/security/ui/test_phase3_web_bundle_scanner.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(admin): add local camera alert inbox"
~~~

## Wave 5 — P3-5 Anonymous Current Presence, Never Camera Identity

### Task 28: Implement expiring occupied-to-unknown presence with vacancy absent

**Depends on:** Tasks 03, 24–25, and an enabled/calibrated native person event path.
**Gate contribution:** P3-5.
**Estimated effort:** 2 person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/services/vision/presence.py`
- Create: `apps/core/src/tuntun_core/api/routes/camera_presence.py`
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Modify: `tests/integration/deploy/test_owner_ingress_route_manifest.py`
- Modify: `tests/integration/vision/test_phase3_boot_composition.py`
- Create: `scripts/phase3/calibrate_presence.py`
- Create: `scripts/scan_database_schema.py`
- Create: `tests/unit/vision/test_presence_state_machine.py`
- Create: `tests/property/vision/test_presence_sequences.py`
- Create: `tests/integration/vision/test_presence_restart_expiry.py`
- Create: `tests/security/vision/test_presence_has_no_history_identity_or_action.py`
- Create: `tests/security/vision/test_selected_frame_count_ignored.py`
- Create: `tests/acceptance/vision/test_vacancy_feature_absence.py`
- Create: `tests/acceptance/vision/test_presence_home_route_absence.py`
- Create: `tests/security/vision/test_presence_schema_scanner.py`

**Interfaces:** Implements `AnonymousPresencePort`, owner-safe current-state projection, and the one-way `HomePresenceObservationPort` using the unchanged Phase 2 envelope specialized only as `PresenceChangedEventV1(event_type="presence.changed.v1", payload=...)`. The publisher registry and consumer route by frozen `event_type` and exact current publisher/source sequence plus `(area_id, area_generation)` binding metadata; no Phase 3 `direction` or `payload_schema_id` field is added. It consumes validated current `person` observations and exact current `CanonicalLocationRefV1`; consumer state deduplicates event ID/source sequence, rejects replay/reorder/expiry and any fresh wrapper over stale payload time, leaves its cursor unchanged on rejection, and can update only home-policy observations. The task registers the exact presence publisher/consumer/worker in the canonical container and the exact owner-safe current-state route in `api/app.py` plus the signed ingress manifest/router. Installed-candidate tests prove only enabled rows traverse listener→owner-ingress→Core UDS, all unknown/vacancy/HA routes return 404, and enabled routes/ports/workers/consumers equal the signed feature manifest. Cross-source aggregation can preserve a nonzero commissioned non-imaging count but can never emit `state="occupied"` with `count_band="zero"`. The current household build registers camera `occupied → unknown` only; `vacant`, `zero/one/multiple`, HA presence projection/entity/action/route, and vacancy-capable sensor routes are absent. `scan_database_schema.py` builds a temporary database from the exact migration head, freezes and bounds `sqlite_schema`, foreign-key, index, trigger, and generated-column inventories for the named domain, and scans normalized identifiers plus DDL tokens against a nonempty duplicate-free forbidden CSV. Missing/extra migrations, invalid/duplicate SQL, cross-domain objects, virtual/extension tables, unreadable/changing inventory, parse/limit failure, or a forbidden token blocks; the scanner reads no household database or row value.

- [ ] **Step 1: Write red state/expiry/replay/outage/no-history tests**

~~~python
async def test_camera_person_event_can_only_assert_five_minute_occupied(service, person_event, fake_clock) -> None:
    state = await service.apply(person_event)
    assert state.state == "occupied"
    assert state.count_band == "unknown"
    assert state.valid_until <= person_event.observed_at + timedelta(minutes=5)
    fake_clock.advance_to(state.valid_until)
    location = CanonicalLocationRefV1(area_id=state.area_id, area_generation=state.area_generation)
    assert (await service.current(location)).state == "unknown"

@pytest.mark.parametrize("cause", ["no_event", "timeout", "source_outage", "clock_untrusted", "restart_uncertain", "privacy_on"])
async def test_uncertainty_never_becomes_vacant(service, cause) -> None:
    location = CanonicalLocationRefV1(area_id="area_common_synth_01", area_generation=4)
    assert (await service.apply_uncertainty(location=location, cause=cause)).state == "unknown"

async def test_replayed_evidence_cannot_extend_original_expiry(service, person_event) -> None:
    first = await service.apply(person_event)
    second = await service.apply(person_event)
    assert second.valid_until == first.valid_until

@pytest.mark.parametrize("fault", ["bad_commitment", "expired", "expiry_equal_to_now"])
async def test_presence_rejects_untrusted_or_stale_evidence_before_state(
    service, person_event, fault,
) -> None:
    with pytest.raises(PresenceEvidenceRejected):
        await service.apply(person_event.mutate(fault))
    assert service.repository.writes == []
    assert service.presence_outbox.writes == []

@pytest.mark.parametrize("crash_at", [
    "before_transaction", "after_replace_before_sequence", "after_sequence_before_outbox",
    "after_commit_before_publish",
])
async def test_presence_checkpoint_sequence_and_outbox_reconcile_atomically(
    service, person_event, crash_at,
) -> None:
    with suppress(SimulatedCrash):
        await service.apply_with_crash(person_event, crash_at)
    restarted = await service.restart_and_drain()
    assert restarted.repository.current_row_count(person_event.location) in {0, 1}
    assert restarted.presence_outbox.event_count_for(person_event) in {0, 1}
    assert (
        restarted.repository.current_row_count(person_event.location)
        == restarted.presence_outbox.event_count_for(person_event)
    )
    assert restarted.presence_outbox.source_sequences_are_unique_and_monotonic()

def test_future_selected_frame_count_has_no_presence_consumer(feature_graph) -> None:
    assert feature_graph.consumers("anonymous_visual_observation.v1") == ()

@pytest.mark.parametrize("fault", [
    "wrong_event_type", "stale_source_generation", "wrong_area_generation",
    "envelope_payload_id_mismatch", "expired",
])
async def test_presence_home_observation_route_rejects_mismatch_or_expiry(consumer, event, fault) -> None:
    with pytest.raises(PresenceObservationRejected):
        await consumer.ingest(event.mutate(fault))
    assert consumer.home_actions.calls == []
    assert consumer.ha.calls == []

@pytest.mark.parametrize("fault", [
    "stale_payload_fresh_wrapper", "replay_event_id", "replayed_source_sequence", "observed_time_reorder",
])
async def test_stale_payload_replay_or_reorder_cannot_advance_presence_cursor(
    consumer, event, fault,
) -> None:
    cursor_before = await consumer.cursor()
    with pytest.raises(PresenceObservationRejected):
        await consumer.ingest(event.mutate(fault))
    assert await consumer.cursor() == cursor_before
    assert consumer.home_actions.calls == []
    assert consumer.ha.calls == []

async def test_area_reclassification_revokes_presence_through_restart_and_restore(system, person_event) -> None:
    state = await system.presence.apply(person_event)
    await system.topology.reclassify(state.area_id, expected_generation=state.area_generation)
    stale = CanonicalLocationRefV1(area_id=state.area_id, area_generation=state.area_generation)
    for runtime in (system, await system.restart(), await system.restore_from_backup()):
        assert (await runtime.presence.current(stale)).state == "unknown"
        assert runtime.presence_events.published_for(stale) == ()

def test_baseline_has_no_ha_presence_package_config_route_entity_or_network_surface(build_graph, network_scan) -> None:
    assert build_graph.find_any("ha_presence_projection", "presence_entity", "presence_to_ha_action") == ()
    assert network_scan.routes_matching("*presence*") == ()
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/vision/test_presence_state_machine.py tests/property/vision/test_presence_sequences.py tests/integration/vision/test_presence_restart_expiry.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_phase3_boot_composition.py tests/security/vision/test_presence_has_no_history_identity_or_action.py tests/security/vision/test_selected_frame_count_ignored.py tests/acceptance/vision/test_vacancy_feature_absence.py tests/security/vision/test_presence_schema_scanner.py -q`
Expected: FAIL because `AnonymousPresenceService` and presence route are absent.

- [ ] **Step 3: Implement current-only state, original expiry, and absent conditional routes**

~~~python
async def apply(self, evidence: AnonymousPresenceEvidenceV1) -> PresenceChangedV1:
    now = self._clock.now()
    if not evidence.observed_at <= now < evidence.max_valid_until:
        raise PresenceEvidenceRejected("presence_evidence_not_fresh")
    self._evidence_verifier.require_exact_hmac(
        domain="tuntun.anonymous-presence-evidence.v1",
        canonical_bytes=canonical_anonymous_presence_evidence_unsigned_bytes(evidence),
        supplied_commitment=evidence.commitment,
    )
    if evidence.kind != "camera_native_person":
        return await self._apply_only_if_commissioned_vacancy_rule(evidence, now=now)
    assert evidence.event_id is not None
    assert evidence.camera_binding_id is not None and evidence.camera_binding_generation is not None
    assert evidence.capability_generation is not None
    assert evidence.zone_id is not None and evidence.zone_generation is not None
    await self._policies.require_camera_occupied_enabled(
        area_id=evidence.area_id,
        area_generation=evidence.area_generation,
        policy_version=evidence.policy_version,
        privacy_generation=evidence.privacy_generation,
        event_id=evidence.event_id,
        camera_binding_id=evidence.camera_binding_id,
        camera_binding_generation=evidence.camera_binding_generation,
        capability_generation=evidence.capability_generation,
        zone_id=evidence.zone_id,
        zone_generation=evidence.zone_generation,
    )
    valid_until = min(evidence.observed_at + timedelta(minutes=5), evidence.max_valid_until)
    location = CanonicalLocationRefV1(area_id=evidence.area_id, area_generation=evidence.area_generation)
    await self._topology.require_current_location(location)
    checkpoint = PresenceCheckpoint.occupied_unknown_count(evidence, valid_until=valid_until)
    event = checkpoint.to_event(event_id=uuid4())
    # The replace, evidence-dedupe claim, original-expiry guard, durable source
    # sequence allocation, complete envelope construction, and outbox insert
    # are one serializable transaction. A duplicate returns the stored event
    # and never removes an undelivered outbox row.
    stored_event = await self._repo.replace_and_enqueue_once(
        checkpoint=checkpoint,
        evidence_commitment=evidence.commitment,
        payload=event,
        publisher=self._registered_presence_publisher,
        accepted_at=now,
    )
    await self._presence_outbox.kick()
    return stored_event

async def expire(self, location: CanonicalLocationRefV1, now: datetime) -> PresenceChangedV1:
    expired = await self._repo.require_current_expired(location, now)
    policy = await self._policies.require_current_location_policy(location, at=now)
    privacy = await self._privacy.require_current_generation(at=now)
    event = PresenceChangedV1(
        event_id=uuid4(), area_id=location.area_id,
        area_generation=location.area_generation, state="unknown",
        count_band="unknown", source_kinds=expired.source_kinds,
        evidence_policy_version=policy.policy_version,
        privacy_generation=privacy.privacy_generation,
        confidence_band="low", observed_at=now,
        valid_until=now + timedelta(seconds=30),
        transition_reason="evidence_expired",
    )
    expired_event = await self._repo.delete_expired_and_enqueue_unknown_once(
        location=location,
        expected_evidence_commitment=expired.last_evidence_commitment,
        now=now,
        payload=event,
        publisher=self._registered_presence_publisher,
    )
    await self._presence_outbox.kick()
    return expired_event
~~~

The encrypted checkpoint is one replace-in-place row containing exact `(area_id, area_generation)`, anonymous state/count, source-kind enum, exact evidence-policy and privacy generations, evidence commitment, observed time, original expiry, and reason. It creates no timeline, heatmap, person/child/viewer relation, cross-room join, clip link, memory proposal, screen-time debit, or audit body; expiry removes it and checkpoints are omitted from normal backups/history. Restart preserves only an unexpired original deadline under the still-current area generation; otherwise unknown. A source outage, area reclassification, or Privacy Shield immediately makes the projection unknown. The repository owns the registered presence-publisher identity and atomically allocates its monotonic source sequence while constructing every complete `PresenceChangedEventV1` and durable outbox row; callers can supply only the validated payload. Concurrent publication, crash, restart, or retry therefore cannot reuse a sequence or leave a claimed event without a dispatchable outbox row. Publish the closed observation specialization only to the home-policy consumer; its durable cursor binds source generation/sequence, event ID, payload/envelope observation time, and payload-bounded envelope expiry. The consumer invokes `validate_cross_domain_event_at_ingress(event, now=trusted_now)` immediately after parse and authentication and before registry reads, cursor advancement, persistence, or dispatch. Validation precedes cursor advancement, so stale-payload/fresh-wrapper, receiver-future/expired envelope, replay, and reorder rejection cannot consume sequence state. No HA package/config/entity/Recorder/state/action/network route is registered in the baseline. The conditional non-imaging simulator can evaluate `vacant` only after a separately procured exact sensor rule passes ≥100 entry/exit/dwell/two-person/re-entry/door-open/outage/clock/restart/reorder sequences, zero false vacancy, and ≥95% occupied detection. Since no such sensor is approved, production vacancy/count routes must pass negative reachability.

- [ ] **Step 4: Run green, 10,000 randomized sequences, and absence/history scans**

Run: `uv run pytest tests/unit/vision/test_presence_state_machine.py tests/property/vision/test_presence_sequences.py tests/integration/vision/test_presence_restart_expiry.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_phase3_boot_composition.py tests/security/vision/test_presence_has_no_history_identity_or_action.py tests/security/vision/test_selected_frame_count_ignored.py tests/acceptance/vision/test_vacancy_feature_absence.py tests/acceptance/vision/test_presence_home_route_absence.py tests/security/vision/test_presence_schema_scanner.py -q && uv run pytest tests/property/vision/test_presence_sequences.py --hypothesis-seed=31028 -q && uv run python scripts/phase3/calibrate_presence.py synthetic --sequences 10000 --mode camera-occupied-only --output var/evidence/phase3/synthetic-presence.json && uv run python scripts/check_feature_absence.py --features presence_vacant,presence_count,ha_presence_projection,selected_frame_perception --phase 3 && uv run python scripts/scan_database_schema.py --domain presence --forbid history,person,profile,child,viewer,clip,memory,screen_time && uv run ruff check apps/core/src/tuntun_core/services/vision/presence.py apps/core/src/tuntun_core/api/routes/camera_presence.py apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/owner-ingress/src/tuntun_owner_ingress/router.py scripts/phase3/calibrate_presence.py scripts/scan_database_schema.py tests/unit/vision tests/property/vision tests/integration/vision tests/security/vision tests/acceptance/vision && uv run mypy apps/core/src scripts/scan_database_schema.py`
Expected: PASS; zero false vacancy, no replay extension, every unreliable path becomes unknown, and conditional/selected-frame/HA routes remain absent.

- [ ] **Step 5: Commit**

~~~bash
git add apps/core/src/tuntun_core/services/vision/presence.py apps/core/src/tuntun_core/api/routes/camera_presence.py apps/core/src/tuntun_core/api/app.py apps/core/src/tuntun_core/bootstrap/container.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json scripts/phase3/calibrate_presence.py scripts/scan_database_schema.py tests/unit/vision/test_presence_state_machine.py tests/property/vision/test_presence_sequences.py tests/integration/vision/test_presence_restart_expiry.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_phase3_boot_composition.py tests/security/vision/test_presence_has_no_history_identity_or_action.py tests/security/vision/test_selected_frame_count_ignored.py tests/acceptance/vision/test_vacancy_feature_absence.py tests/acceptance/vision/test_presence_home_route_absence.py tests/security/vision/test_presence_schema_scanner.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(vision): add anonymous expiring presence"
~~~

### Task 29: Build anonymous presence UI with unavailable-transition truth

**Depends on:** Tasks 21–22 and 28.
**Gate contribution:** P3-5 UI.
**Estimated effort:** 1 person-day.

**Files:**
- Create: `apps/admin/src/features/cameras/presence.tsx`
- Create: `apps/admin/src/routes/cameras-presence.tsx`
- Create: `tests/e2e/cameras-presence.spec.ts`
- Create: `tests/ui/cameras-presence-accessibility.spec.ts`
- Create: `tests/security/ui/test_presence_projection_minimization.py`

**Interfaces:** Produces owner route `/cameras/presence` only when `anonymous_presence` is accepted. It consumes current-state projections and never requests camera video, event history, identity, or cross-room movement.

- [ ] **Step 1: Write red anonymous/current-only/unavailable-transition tests**

~~~typescript
test("camera-only area shows occupied then unknown and labels vacancy unavailable", async ({page}) => {
  await seedPresence(page, {state: "occupied", count: "unknown", source: "camera_native_person", validForSeconds: 300});
  await page.goto("/cameras/presence");
  await expect(page.getByText("Occupied · anonymous")).toBeVisible();
  await expect(page.getByText("Vacant unavailable — no qualified sensor")).toBeVisible();
  await advanceServerClock(page, 301);
  await expect(page.getByText("Unknown · evidence expired")).toBeVisible();
});

test("presence page has no person history, clip, face, viewer, or count claim", async ({page}) => {
  await page.goto("/cameras/presence");
  for (const text of ["Who", "Person name", "Timeline", "View clip", "One person", "Multiple people"]) {
    await expect(page.getByText(text, {exact: false})).toHaveCount(0);
  }
});
~~~

- [ ] **Step 2: Run red**

Run: `pnpm --filter @tuntun/admin e2e -- tests/e2e/cameras-presence.spec.ts`
Expected: FAIL with 404 for `/cameras/presence`.

- [ ] **Step 3: Implement current-state cards and evidence/expiry disclosure**

~~~tsx
export function PresenceCard({state}: {state: PresenceProjection}) {
  return (
    <StatusCard title={state.areaSafeLabel} state={state.truthState}>
      <p>{state.anonymousStateLabel}</p>
      <p>{state.sourceKindLabel} · valid until {state.validUntilLabel}</p>
      <UnavailableCapabilities items={state.unavailableTransitions}/>
      <p>No identity or movement history is stored.</p>
    </StatusCard>
  );
}
~~~

Show `occupied`, `vacant`, `unknown`, `stale`, or `unavailable` with source kind/freshness/expiry/policy generation and explicitly unavailable transitions. The initial hall/kitchen camera paths may show only occupied/unknown. Private-room rows are absent unless a future approved non-imaging policy exists. No clip link, video, person, child, viewer, count, history, automation-success, memory, or selected-frame route appears. Preserve English/Hindi/mixed-script, keyboard, VoiceOver live state, 320 px/200% zoom, and non-colour truth.

- [ ] **Step 4: Run green, accessibility, and minimization scans**

Run: `pnpm --filter @tuntun/admin test && pnpm --filter @tuntun/admin lint && pnpm --filter @tuntun/admin typecheck && pnpm --filter @tuntun/admin build && pnpm --filter @tuntun/admin e2e -- tests/e2e/cameras-presence.spec.ts tests/ui/cameras-presence-accessibility.spec.ts && uv run pytest tests/security/ui/test_presence_projection_minimization.py -q && uv run python scripts/scan_browser_artifacts.py --playwright-output test-results --forbid person,profile,child,viewer,clip,history,frame`
Expected: PASS; expiry becomes unknown, unavailable vacancy is explicit, and no identity/history/media data reaches the browser.

- [ ] **Step 5: Commit**

~~~bash
git add apps/admin/src/features/cameras/presence.tsx apps/admin/src/routes/cameras-presence.tsx tests/e2e/cameras-presence.spec.ts tests/ui/cameras-presence-accessibility.spec.ts tests/security/ui/test_presence_projection_minimization.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(admin): show anonymous current presence"
~~~

## Wave 6 — P3-6 Security, Recovery, Soak, and Storage Decision

### Task 30: Add content-safe observability, camera-compromise tests, and operational runbooks

**Depends on:** Tasks 05–29.
**Gate contribution:** P3-6 security/privacy/operations.
**Estimated effort:** 1.5 person-days.

**Files:**
- Modify: `apps/core/src/tuntun_core/services/health.py`
- Modify: `apps/core/src/tuntun_core/services/audit/privacy_receipts.py`
- Modify: `apps/recorder/src/tuntun_recorder/health.py`
- Create: `scripts/scan_logs_and_crashes.py`
- Create: `tests/security/vision/test_raw_media_sentinel.py`
- Create: `tests/security/vision/test_camera_lateral_movement.py`
- Create: `tests/security/vision/test_camera_secret_and_log_scan.py`
- Create: `tests/property/vision/test_media_parser_fuzz.py`
- Create: `tests/property/vision/test_event_parser_fuzz.py`
- Create: `tests/performance/vision/test_recorder_resource_bounds.py`
- Create: `tests/security/vision/test_log_crash_scanner.py`
- Create: `docs/operations/phase3-observability.md`
- Modify: `docs/privacy/phase3-camera-data.md`

**Interfaces:** Produces safe recording/source/event/storage/retention/alert/presence health facts and content-minimized audit receipts. It consumes counts, latencies, pseudonymous endpoint commitments, generations, and reason codes only. `scan_logs_and_crashes.py` inventories one explicit nofollow synthetic artifact root containing the exact core/source/recorder/proxy/ingress log and crash subtrees through the shared descriptor-bound scanner, expands only bounded supported text/archive formats, normalizes keys/literals, and applies a nonempty duplicate-free forbidden CSV. Missing expected process roots, unreadable/changing/symlink/special inputs, corrupt archives, truncation, decode/recursion/size/count exhaustion, or a forbidden sentinel blocks; output contains only relative artifact class and reason code.

- [ ] **Step 1: Write red sentinel, lateral-reachability, and log-content tests**

~~~python
async def test_video_sentinel_exists_only_in_video_root_and_authorized_playback(system, synthetic_sentinel) -> None:
    await system.record_synthetic(synthetic_sentinel)
    allowed = {system.video_root, system.one_authorized_playback_capture}
    findings = scan_all_runtime_storage(system.runtime_roots, synthetic_sentinel)
    assert findings == allowed

def test_compromised_camera_cannot_reach_authority_or_tools(network_rig) -> None:
    assert network_rig.reachable_from_camera() == {
        "compiled_source_listener": "bounded_authenticated_input_only",
        "local_time_if_approved": "time_only",
    }
    assert network_rig.unreachable_from_camera() >= {
        "core_db", "identity", "memory", "provider_keys", "ha_signer", "owner_api",
        "media_proxy", "desktop_helper", "shell", "internet",
    }
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/security/vision/test_raw_media_sentinel.py tests/security/vision/test_camera_lateral_movement.py tests/security/vision/test_camera_secret_and_log_scan.py tests/security/vision/test_log_crash_scanner.py tests/property/vision/test_media_parser_fuzz.py tests/property/vision/test_event_parser_fuzz.py tests/performance/vision/test_recorder_resource_bounds.py -q`
Expected: FAIL because full Phase 3 scans/health projections are not registered.

- [ ] **Step 3: Implement safe metrics/audit and complete runbooks**

Expose source online/degraded/offline/ineligible, event channel, recorder running/paused/failed, last complete segment, current gap, storage/reserve, projected days, clock skew band, capability generation, alert queue/latency, and anonymous-state expiry. Never expose raw error, media/path, address, credential, event body, identity, or timeline. Audit stores operation/outcome/safe reason/HMAC commitment for commissioning, zone changes, playback, export/delete, recorder controls, policy, alert delivery, storage decision, and recovery; it stores no clip/event/presence body. Daily checks cover integrity, reserve, gaps/retention, egress drift, and keys; weekly owner summary targets the Phase 3 steady-state 30–60 minutes/month; monthly playback/export sample and quarterly retention/capacity/recovery drill are exact. Parser fuzz applies byte/frame/container/metadata/time/CPU/RAM limits.

- [ ] **Step 4: Run green, security/privacy scans, and resource test**

Run: `uv run pytest tests/security/vision tests/property/vision/test_media_parser_fuzz.py tests/property/vision/test_event_parser_fuzz.py tests/performance/vision/test_recorder_resource_bounds.py -q && make test-security && make verify-private-data && uv run python scripts/scan_network_surface.py --require-listener 127.0.0.1:8787=owner_ingress --forbid-lan-port 8787 --optional-exact-commissioned-private-lan-port 8443=owner_ingress --forbid-wildcard --forbid-ipv6 --forbid-core-tcp --forbid-media-proxy-tcp --forbid-camera-public && uv run python scripts/scan_logs_and_crashes.py --root var/test-artifacts/logs-crashes --forbid-media,credential,address,raw_error,identity,profile,memory && uv run ruff check apps/core/src/tuntun_core/services/health.py apps/core/src/tuntun_core/services/audit/privacy_receipts.py apps/recorder/src/tuntun_recorder/health.py scripts/scan_logs_and_crashes.py tests/security/vision tests/property/vision tests/performance/vision && uv run mypy apps/core/src apps/recorder/src scripts/scan_logs_and_crashes.py`
Expected: PASS; sentinel appears only in approved video/playback locations; no high/critical finding, lateral authority path, public listener, secret, or content log remains.

- [ ] **Step 5: Commit**

~~~bash
git add apps/core/src/tuntun_core/services/health.py apps/core/src/tuntun_core/services/audit/privacy_receipts.py apps/recorder/src/tuntun_recorder/health.py scripts/scan_logs_and_crashes.py tests/security/vision/test_raw_media_sentinel.py tests/security/vision/test_camera_lateral_movement.py tests/security/vision/test_camera_secret_and_log_scan.py tests/security/vision/test_log_crash_scanner.py tests/property/vision/test_media_parser_fuzz.py tests/property/vision/test_event_parser_fuzz.py tests/performance/vision/test_recorder_resource_bounds.py docs/operations/phase3-observability.md docs/privacy/phase3-camera-data.md
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "security(vision): add safe observability and isolation evidence"
~~~

### Task 31: Implement restore quarantine, update invalidation, rollback, and retirement

**Depends on:** Tasks 04, 06–10, 13–18, 24–30 and Phase 1/2 recovery coordinators.
**Gate contribution:** P3-6 failure/recovery.
**Estimated effort:** 2 person-days.

**Files:**
- Create: `apps/recorder/src/tuntun_recorder/recovery.py`
- Modify: `apps/recorder/src/tuntun_recorder/recording/reconciliation.py`
- Modify: `apps/core/src/tuntun_core/services/data_lifecycle/recovery.py`
- Create: `scripts/phase3/run_fault_matrix.py`
- Create: `docs/operations/phase3-failure-recovery.md`
- Create: `tests/integration/vision/test_restore_quarantine.py`
- Create: `tests/integration/vision/test_catalog_rebuild.py`
- Create: `tests/fault/vision/test_phase3_failure_matrix.py`
- Create: `tests/security/vision/test_firmware_drift_quarantine.py`
- Create: `tests/security/vision/test_camera_retirement.py`

**Interfaces:** Produces `VisionRecoveryCoordinator.enter/reconcile/promote`, bounded catalog reconstruction from authenticated opaque media manifests, firmware/update invalidation, and exact retirement. It consumes no canonical raw-video backup because routine camera media is deliberately excluded from that backup.

- [ ] **Step 1: Write red restore, catalog, retention, firmware, and retirement tests**

~~~python
async def test_restore_starts_every_phase3_route_quarantined(recovered_system) -> None:
    await recovered_system.restore_core_backup()
    assert recovered_system.feature_states() == {
        "recording": "quarantined", "alerts": "quarantined", "presence": "quarantined",
        "playback": "quarantined", "selected_frame_perception": "absent",
    }

async def test_catalog_rebuild_uses_only_authenticated_opaque_manifests_and_original_expiry(catalog_recovery) -> None:
    rebuilt = await catalog_recovery.rebuild()
    assert rebuilt.rejected_tampered_manifests > 0
    assert all(item.expires_at == item.original_manifest_expires_at for item in rebuilt.accepted)

async def test_firmware_change_revokes_source_until_full_recommission(system) -> None:
    await system.observe_firmware_digest("new-digest")
    assert system.source_state == "ineligible"
    assert system.alerts_enabled is False
    assert system.presence_enabled is False
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/vision/test_restore_quarantine.py tests/integration/vision/test_catalog_rebuild.py tests/fault/vision/test_phase3_failure_matrix.py tests/security/vision/test_firmware_drift_quarantine.py tests/security/vision/test_camera_retirement.py -q`
Expected: FAIL because Phase 3 recovery coordinator/fault runner is absent.

- [ ] **Step 3: Implement quarantined recovery and every specified failure behavior**

Restore sequence is verify core archive → restore core in quarantine → keep source/recorder/outcome/media routes closed → mount expected SSD by UUID read-only → recover its APFS/catalog key through owner-custodied local material → verify SQLCipher/catalog/HMAC chain and every authenticated opaque media manifest → reject tampered/unknown files → preserve original expiry → reconcile current source/area/zone/`zone_generation`/capability/egress/audio/arc/clock/privacy generations → rotate IPC/session/grant generations → owner approves one source at a time → enable recording, then playback, then alerts, then presence. If key/catalog/media integrity cannot be proved, preserve bytes read-only and state unavailable; never guess/reformat/extend retention.

The fault runner injects camera/source/event/recorder/SSD/catalog/Mac/router/WAN/clock/credential/firmware/privacy/owner-endpoint failures from Phase 3 Section 18. It proves continuous-vs-event split behavior, no false recorded/clear/vacant/delivered claim, no unsafe replay, no root spill, and unaffected Phase 1/2 paths remain. Firmware/update/placement/reset/credential privilege drift quarantines exact dependencies. Retirement disables routes, revokes credentials/bindings/grants, stops processes, removes source registration, exports only explicit owner-approved ciphertext, crypto-shreds Tuntun keys/catalog where selected, records unverifiable camera/microSD/vendor residuals, and proves reconnection/replay denial.

- [ ] **Step 4: Run green, full synthetic fault matrix, and isolated restore**

Run: `uv run pytest tests/integration/vision/test_restore_quarantine.py tests/integration/vision/test_catalog_rebuild.py tests/fault/vision/test_phase3_failure_matrix.py tests/security/vision/test_firmware_drift_quarantine.py tests/security/vision/test_camera_retirement.py -q && uv run python scripts/phase3/run_fault_matrix.py --synthetic --all-section-18 --output var/evidence/phase3/synthetic-fault-matrix.json && uv run python scripts/phase3/run_fault_matrix.py verify var/evidence/phase3/synthetic-fault-matrix.json && uv run python scripts/verify_private_data.py var/evidence/phase3/synthetic-fault-matrix.json && uv run ruff check apps/recorder/src/tuntun_recorder/recovery.py apps/recorder/src/tuntun_recorder/recording/reconciliation.py apps/core/src/tuntun_core/services/data_lifecycle/recovery.py scripts/phase3/run_fault_matrix.py tests/integration/vision tests/fault/vision tests/security/vision && uv run mypy apps/core/src apps/recorder/src`
Expected: PASS; every fault has its exact safe state, restore cannot auto-enable/replay/extend expiry, and retired sources cannot reconnect.

- [ ] **Step 5: Commit**

~~~bash
git add apps/recorder/src/tuntun_recorder/recovery.py apps/recorder/src/tuntun_recorder/recording/reconciliation.py apps/core/src/tuntun_core/services/data_lifecycle/recovery.py scripts/phase3/run_fault_matrix.py docs/operations/phase3-failure-recovery.md tests/integration/vision/test_restore_quarantine.py tests/integration/vision/test_catalog_rebuild.py tests/fault/vision/test_phase3_failure_matrix.py tests/security/vision/test_firmware_drift_quarantine.py tests/security/vision/test_camera_retirement.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(vision): quarantine camera restore and failures"
~~~

### Task 32: Freeze Phase 3 acceptance, seven-day soak, 90-day simulation, and storage decision

**Depends on:** Every enabled Task 01–31 output, current physical evidence, and accepted UI checkpoint U4 (UI Tasks U15–U16).
**Gate contribution:** P3-6 final.
**Estimated effort:** 2 person-days plus seven elapsed soak days.

**Files:**
- Modify: `ops/services/phase3-camera-source.v1.json`
- Modify: `ops/services/phase3-recorder.v1.json`
- Modify: `ops/services/phase3-media-proxy.v1.json`
- Modify: `ops/services/phase3-owner-ingress.v1.json`
- Modify: `tests/integration/vision/test_deployed_process_entrypoints.py`
- Modify: `tests/integration/deploy/test_phase3_side_process_lifecycle.py`
- Modify: `tests/integration/vision/test_owner_ingress_takeover.py`
- Modify: `tests/fault/vision/test_owner_ingress_takeover_rollback.py`
- Create: `scripts/phase3/run_acceptance.py`
- Create: `scripts/phase3/verify_acceptance.py`
- Create: `docs/evidence/phase3-evidence-schema.json`
- Create: `docs/evidence/phase3-soak-schema.json`
- Create: `docs/operations/phase3-acceptance.md`
- Create: `tests/acceptance/vision/test_phase3_evidence_schema.py`
- Create: `tests/acceptance/vision/test_phase3_acceptance_gate.py`
- Create: `tests/acceptance/vision/test_phase3_feature_absence.py`
- Create: `tests/acceptance/vision/test_phase3_soak_oracles.py`
- Create: `tests/acceptance/vision/test_phase3_feature_authority_campaign.py`
- Create: `tests/acceptance/vision/test_phase3_storage_decision.py`

**Interfaces:** Produces a signed content-safe `tuntun.phase3.acceptance.v1`, `tuntun.phase3.soak.v1`, signed feature-manifest evidence, and exactly one `retain_external_ssd` / `open_hub_nvr_procurement` / `open_nas_vms_procurement` decision. No schema has a caller-authored pass Boolean; the verifier recomputes thresholds, hashes, durations, feature dependencies, and positive/absent routes. The real-campaign schemas consume Phase 2's canonical pre-issued rollover chain and exact `FeatureAuthorityCampaignEvidenceV1`, binding its chain ID/digest, frozen candidate digest, complete ordered signed-envelope and transition/restart-receipt digests, admission-sample-log digest, applicable interval, and every literal-zero counter; neither Phase 3 runner signs, renews, substitutes, or extends authority. `test_phase3_feature_authority_campaign.py` adapts the final soak runner and verifier to the Phase 2 Task 13 shared harness at initial index-zero activation, startup, every sample, both sides of rollover CAS, restart activation, and completion; any injected fault produces zero post-fault admission/preparation/provider-call/trigger/effect delta and prevents both the acceptance packet and storage decision. Before either acceptance packet can be minted, rebuild the locked final `tuntun-reolink`, `tuntun-recorder`, and `tuntun-owner-ingress` wheels after every Task 01–31 change; refresh and re-sign the four canonical service rows without changing their manifest IDs; and atomically install/upgrade, health-check, crash/restart, roll back, uninstall, and reinstall that exact set through the Task 17 lifecycle. Recorder and media-proxy intentionally bind the same final recorder wheel but different scripts, plists, accounts, configurations, entitlements, and cleanup sets. The acceptance packet binds each current manifest digest, wheel digest, plist/config digest, installed release, account/UID, route-manifest digest, and the final takeover/lifecycle receipt. A Task 17-era digest, mixed release, missing/extra row, wrong UID, direct-Core listener, stale router, receipt from another candidate, or any feature-authority gap blocks the synthetic run and soak.

- [ ] **Step 1: Write red complete-evidence, absent-feature, and storage-decision oracles**

~~~python
@pytest.mark.parametrize("fault", DOWNSTREAM_FEATURE_AUTHORITY_FAULTS)
async def test_final_soak_feature_authority_fault_blocks_acceptance_and_decision(
    feature_authority_campaign_harness, phase3_soak_runner, verifier, fault,
) -> None:
    result = await feature_authority_campaign_harness.exercise(
        runner=phase3_soak_runner,
        verifier=verifier,
        fault=fault,
    )
    assert result.post_fault_admission_delta == 0
    assert result.post_fault_preparation_delta == 0
    assert result.post_fault_provider_call_delta == 0
    assert result.post_fault_trigger_delta == 0
    assert result.post_fault_effect_delta == 0
    assert result.campaign_invalid and result.semantic_verifier_rejected
    assert result.acceptance_packets_minted == 0
    assert result.storage_decisions_minted == 0

def test_acceptance_requires_every_enabled_positive_and_disabled_negative_gate(verifier, receipt) -> None:
    decision = verifier.verify(receipt)
    assert decision.required_suites == REQUIRED_PHASE3_SUITES
    assert decision.feature_manifest["selected_frame_perception"] == "absent"
    assert decision.feature_manifest["reolink_identity"] == "absent"
    assert decision.feature_manifest["camera_audio"] == "absent"

@pytest.mark.parametrize("decision", ["retain_external_ssd", "open_hub_nvr_procurement", "open_nas_vms_procurement"])
def test_exactly_one_storage_decision_is_bound_to_capacity_evidence(verifier, receipt, decision) -> None:
    receipt.storage_decisions = [storage_decision(decision, receipt.capacity_digest)]
    assert verifier.verify(receipt).storage_decision == decision

def test_two_or_zero_storage_decisions_fail(verifier, receipt) -> None:
    for values in [[], [storage_decision("retain_external_ssd"), storage_decision("open_nas_vms_procurement")]]:
        receipt.storage_decisions = values
        assert "storage_decision_count" in verifier.verify(receipt).failures
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/support/test_feature_authority_campaign.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py tests/acceptance/vision/test_phase3_evidence_schema.py tests/acceptance/vision/test_phase3_acceptance_gate.py tests/acceptance/vision/test_phase3_feature_absence.py tests/acceptance/vision/test_phase3_soak_oracles.py tests/acceptance/vision/test_phase3_feature_authority_campaign.py tests/acceptance/vision/test_phase3_storage_decision.py -q`
Expected: FAIL because final acceptance schemas/semantic verifier are absent.

- [ ] **Step 3: Implement recursively closed schemas and semantic verifier**

The verifier requires:

- the final four canonical signed service inventories and one current installed lifecycle/takeover receipt exact-matching the final locked wheels, plists, configs, accounts, route manifest, release, and listener ownership;

- exact three-camera inventory/placement records with each unit `eligible`, `inventory_only`, `native_sd_only`, or `vendor_native_only` for an explicit reason;
- canonical `(area_id, area_generation)` plus current `zone_id`/`zone_generation`/camera/privacy generations and stale-generation rejection;
- TrackMix fixed-field gate and, for every enabled motion/tracking mode, ≥30 adversarial traversals per doorway across day/night/reset conditions with zero prohibited target;
- device plus ingest audio-off and zero audio in every stored/playback sample;
- complete vendor-egress boot/retry/WAN-restore/vendor-app evidence and zero unapproved flow for enabled sources;
- 48-hour TrackMix one-camera pilot and seven-day final eligible-camera campaign with ≥99.5% per-camera coverage, >5-second gap reporting within 30 seconds, capacity formula/reserve, voice ≤4 seconds and ≤10% regression, and Green objectives;
- exact 7/90/60 retention, ≤15-minute cleanup, no early deletion/clock extension/root spill, pressure matrix, disconnect/restart/catalog corruption;
- owner-only same-origin playback, single-use ≤60-second range grants, encrypted export, exact deletion/copy truth, and zero non-owner/outer/remote bytes;
- alert positive/false/latency/dedupe/metadata/privacy/closed-page gates for every enabled class; absent routes for each disabled class/transport;
- camera presence occupied≤5m→unknown, zero false vacancy, no history/identity/action; absent vacancy/count/HA projection/selected-frame routes unless separately accepted;
- four Privacy Shield/recorder states, ≤250 ms canonical authority revocation, independent recorder truth, no stale replay;
- raw-media/credential/private-data sentinel, parser fuzz, lateral movement, no-public-route, feature/import/dependency, backup exclusion, restore/update/retirement, and every Section 18 fault;
- no high/critical unmitigated security finding and one evidence-bound storage decision.

The seven-day household soak covers day/night family use, WAN/router/camera/source/event/recorder/Mac/SSD/Green failures, Privacy Shield, recorder pause, alert connected/disconnected delivery, presence expiry, retention, update, resource pressure, playback/export/delete, and restart. The accelerated 100-day clock simulation proves 90-day expiry without extension and bounded catalog size. Feature evidence marks every source/view/event class/alert/presence/selected-frame capability `enabled` or `absent` with exact schema/policy/build/config/evidence digests. Real media/PCAP/identifiers never enter the signed packet.

- [ ] **Step 4: Freeze one clean candidate, run all software gates, then run physical soak**

~~~bash
test -z "$(git status --porcelain)"
make bootstrap
make check
make test-security
make test-contract
make web-test
make web-build
make verify-private-data
uv build --offline --wheel --package tuntun-reolink --out-dir var/build-smoke/phase3/final
uv build --offline --wheel --package tuntun-recorder --out-dir var/build-smoke/phase3/final
uv build --offline --wheel --package tuntun-owner-ingress --out-dir var/build-smoke/phase3/final
uv lock --check
uv run --locked --offline --no-sync pytest tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py -q
uv run pytest tests/support/test_feature_authority_campaign.py tests/acceptance/vision/test_phase3_feature_authority_campaign.py -q
uv run pytest -m "not camera_hardware and not camera_network and not elapsed" -q
uv run pytest apps/recorder/tests integrations/reolink/tests -q
pnpm --filter @tuntun/admin e2e -- tests/e2e/cameras-*.spec.ts
uv run python scripts/phase3/run_acceptance.py synthetic --commit "$(git rev-parse HEAD)" --output var/evidence/phase3/synthetic-acceptance.json
uv run python scripts/phase3/verify_acceptance.py var/evidence/phase3/synthetic-acceptance.json --commit "$(git rev-parse HEAD)"
TUNTUN_ALLOW_ELAPSED_PHASE3=1 uv run python scripts/phase3/run_acceptance.py household-soak --feature-manifest-chain var/evidence/phase3/feature-authority/task32/signed-rollover-chain.json --duration-seconds 604800 --sample-seconds 60 --simulate-retention-days 100 --commit "$(git rev-parse HEAD)" --evidence-root var/evidence/phase3 --output var/evidence/phase3/household-soak.json
uv run python scripts/phase3/verify_acceptance.py var/evidence/phase3/household-soak.json --feature-manifest-chain var/evidence/phase3/feature-authority/task32/signed-rollover-chain.json --commit "$(git rev-parse HEAD)" --require-physical-gates
uv run python scripts/verify_private_data.py var/evidence/phase3
~~~

Expected: clean candidate; software/UI/security/content suites pass; soak monotonic and wall elapsed are each ≥604,800 seconds; the canonical same-candidate rollover chain covers the complete interval, every transition and wall/monotonic lease check passes, and the receipt records zero expired-authority interval; the verifier recomputes every threshold/hash; enabled features have positive gates; disabled features are unreachable; one storage decision is signed. Phase 3 itself authorizes S$0 of new acquisition.

- [ ] **Step 5: Commit evidence tooling before the frozen run; never commit generated owner evidence**

~~~bash
git add ops/services/phase3-camera-source.v1.json ops/services/phase3-recorder.v1.json ops/services/phase3-media-proxy.v1.json ops/services/phase3-owner-ingress.v1.json scripts/phase3/run_acceptance.py scripts/phase3/verify_acceptance.py docs/evidence/phase3-evidence-schema.json docs/evidence/phase3-soak-schema.json docs/operations/phase3-acceptance.md tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py tests/acceptance/vision/test_phase3_evidence_schema.py tests/acceptance/vision/test_phase3_acceptance_gate.py tests/acceptance/vision/test_phase3_feature_absence.py tests/acceptance/vision/test_phase3_soak_oracles.py tests/acceptance/vision/test_phase3_feature_authority_campaign.py tests/acceptance/vision/test_phase3_storage_decision.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(vision): freeze Phase 3 acceptance gate"
~~~

After this commit, restart Step 4 against the new clean commit. Generated evidence remains ignored under `var/evidence/phase3/`.

## Conditional P3-F Bridge/NVR/NAS Pilot Stop Rule

P3-F is not a baseline implementation task and cannot be made exact while the owner has selected no product. It may start only when Task 32 signs `open_hub_nvr_procurement` or `open_nas_vms_procurement`, identifies the exact failed requirement, and the owner separately approves one dated candidate quote. Before any order or code change:

1. Freeze the exact chassis/bridge/drive/UPS/licence SKU, hardware revision, firmware/OS/VMS version, warranty/return route, usable RAID capacity, included/additional channel count, TrackMix one-vs-two-channel behavior, power, Singapore landed cost, and 1/3/5-year TCO in a candidate-specific design amendment.
2. Map that candidate to existing `CameraSourcePort`, `RecorderPort`, `VisionCatalogPort`, and media-proxy contracts. The candidate receives no identity, memory, provider, HA action, owner-passkey, or general core credential.
3. Preserve all baseline invariants: camera vendor egress fail-closed; audio off/rejected; one exact canonical `(area_id, area_generation)` plus current zone/binding generations; no raw media to general core consumers, HA, an LLM, VLM, generative model, or cloud; exact 7/90 retention; owner-only grants; separate copy truth; no public route. The only model exception remains the separately gated Phase 5 RAM-only local non-generative anonymous-CV selected-frame seam.
4. Procure at most the approved pilot units/licences within the return window. Do not bulk-buy drives/licences or decommission the SSD/native path.
5. Migrate one recoverable camera/view first and run a 30-day parallel campaign covering local protocol, native events, audio, egress, dual view, channel licensing, retention, capacity, playback, power loss, update, backup/recovery, and rollback. The candidate-specific runner must consume a complete canonical same-candidate feature-manifest rollover chain, verify the Phase 2 wall/monotonic lease at every admission and background iteration, bind every ordered transition receipt, and prove zero expired-authority interval; an authority gap invalidates the run rather than pausing or crediting it.
6. Promote only if the candidate-specific verifier passes and the owner signs the migration decision. Failure restores the SSD/native source path, revokes candidate credentials/bindings, preserves truthful gaps/copies, and ends the pilot without further purchase.

This stop rule is intentionally not a generic “NAS adapter” coding task: choosing APIs, migrations, licence units, or rollback commands before an exact candidate would violate the no-assumption procurement gate.

## Dependency and Parallelization Map

~~~text
01 contracts ─────> 02 synthetic media/faults
01/02 ────────────> 03 core policy/zone/alert/presence persistence
01/02 ────────────> 04 isolated vision catalog
02/03/04 ───────> 05 IPC/process/feature absence
03/05 ──────────> 06 commissioning
05/06 ──────────> 07 egress eligibility
06/07 ──────────> 08 TrackMix arc
01/02/06/07/08 ─> 09 exact Reolink adapters
04/05/09 ───────> 10 SSD/launchd gate
05/07/09/10 ────> 11 media handle
04/10/11 ───────> 12 segmenter
04/12 ──────────> 13 gaps/reconciliation
09/11/12/13 ────> 14 native event promotion
04/12/13/14 ────> 15 retention
10/12/13/14/15 ─> 16 pressure/workload
03/04/15/16 ────> 17 playback
03/15/17 ───────> 18 export/delete/copies
06–18 ──────────> 19 one-camera 48h pilot
19 + eligible set ─> 20 seven-day capacity
03/06/13/16/20 ─> 21 owner read API
17/21 ──────────> 22 camera/playback UI
18/20/21/22 ────> 23 storage decision UI
03/12–18 ───────> 24 Privacy Shield/recorder
14/24 ──────────> 25 policy event ingress
17/24/25 ───────> 26 alerts/SSE
22/26 ──────────> 27 alert UI
24/25 ──────────> 28 anonymous presence
21/22/28 ───────> 29 presence UI
all enabled paths ─> 30 security/observability
04/06–30 ───────> 31 recovery/failure/retirement
all accepted outputs ─> 32 final soak/decision
~~~

Tasks 03 and 04 may proceed in separate clean worktrees only after Tasks 01–02 have both frozen contracts plus deterministic fixtures/fault points. Tasks 06 and 10 may proceed in parallel after their dependencies. UI Task 22 can start against Task 21 fixtures while Task 20's real elapsed campaign runs, but its production feature manifest remains absent until P3-2 evidence is accepted. Alert and presence software may be developed in parallel after Task 25; physical alert traversals and the one shared camera/network/SSD campaigns are serialized. No two worktrees may connect to, rotate, move, update, or control the same physical camera/volume concurrently.

## Effort and Calendar Envelope

The 32 task estimates total **52 focused engineering person-days**, or **10.4 five-day one-developer weeks**, inside the locked **7–11 focused-week** range.

| Wave | Tasks | Focused person-days |
|---|---:|---:|
| Contracts/isolation | 01–05 | 8.0 |
| Inventory/source/SSD | 06–10 | 8.0 |
| Recording/retention/playback/pilot | 11–19 | 14.5 |
| Capacity/dashboard/privacy | 20–24 | 8.0 |
| Alerts | 25–27 | 5.0 |
| Anonymous current presence | 28–29 | 3.0 |
| Security/recovery/final acceptance | 30–32 | 5.5 |
| **Total** | **01–32** | **52.0** |

Calendar evidence is separate and cannot be compressed into those estimates: Task 19 needs 48 real hours; Task 20 needs seven representative days; Task 26 needs seven elapsed calibration days; and Task 32 needs a later seven-day same-candidate household soak. Parallel documentation/UI/security work is allowed only when it cannot change the frozen camera/media build or evidence inputs. P3-F adds a separate optional 30-day parallel migration only after a measured storage decision, exact product amendment, owner approval, delivery and installation. Camera/SSD replacement lead time, an approved NAS/NVR/drive/UPS/licence order and return window, owner availability for day/night ceremonies, and firmware/router/provider availability extend calendar time without changing engineering effort. A code, firmware, router, placement, zone, policy, volume or hardware revision change restarts its affected evidence.

## Requirements Traceability

| Requirement | Primary tasks |
|---|---|
| Exact TrackMix hall/bedroom-pathway plus two distinct kitchen E1 records | 06, 08–09, 19–20, 32 |
| E1 exact-model gate and inventory/native/vendor-only fallback | 06–07, 09, 20–23, 32 |
| Vendor cloud/UID/P2P/DNS/control/metadata/media fail-closed | 07, 09, 19–20, 30–32 |
| Canonical `area_id` and versioned/CAS `zone_generation` | 01, 03, 06, 14, 25, 28, 32 |
| Reolink never identity/greeting/memory/action | 01, 05, 09, 25, 28, 30, 32 |
| Camera audio disabled and rejected twice | 06–07, 09, 11–12, 19–20, 30, 32 |
| Separate source/recorder/proxy processes, keys, IPC, catalog | 04–05, 09–13, 17, 30–31 |
| Existing encrypted SSD first; HA backup separation; no root spill | 10, 16, 19–20, 23, 31–32 |
| Seven-day low-wide continuous recording | 12–13, 15–16, 19–20, 32 |
| Ninety-day full-resolution native-event clips | 14–16, 19–20, 32 |
| TrackMix event tracking view conditional, wide fallback | 08–09, 14, 20–23, 32 |
| Exact retention/no early delete/no clock extension | 15–16, 18–20, 31–32 |
| Owner-only search/playback/export/delete and 60-second grants | 17–18, 21–24, 30–32 |
| Separate effective copies and deliberate encrypted incident export | 18, 21–23, 30–32 |
| Storage/health/dashboard before alerts before presence | 19–24, 25–27, 28–29 |
| Metadata-only durable local alert inbox and authenticated SSE | 25–27, 30, 32 |
| No service worker/native/SMS/email/vendor push baseline | 05, 26–27, 30, 32 |
| Anonymous occupied≤5m→unknown; no false vacancy/history | 03, 25, 28–29, 31–32 |
| No Home Assistant media/action; optional presence projection absent | 05, 25, 28, 30, 32 |
| Privacy Shield and recorder are independent truthful states | 21–24, 27–32 |
| Selected-frame schema only; no Phase 3 runtime; advisory/count ignored | 01, 05, 24–25, 28, 30, 32 |
| No public/remote camera/media path | 05, 07, 17, 21–22, 26–27, 30–32 |
| Seven-day capacity evidence and one SSD/hub/NAS decision | 20, 23, 32 |
| Synthetic-only Apache-2.0-compatible public repository | 01–05, 19–20, 26, 28, 30–32 |
| Failure, restore quarantine, update, retirement, 90-day simulation | 13, 15–16, 24, 30–32 |

## Physical Campaign Order and Evidence Custody

1. Commit and pass P3-E0 software with synthetic fixtures.
2. Run read-only inventory; create three distinct owner-local records.
3. Configure/verify egress and audio off without enabling Tuntun recording.
4. Run TrackMix physical arc/doorway ceremonies; keep physical tracking off unless every mode passes.
5. Probe TrackMix and each E1 independently; approve only current local source generations.
6. Qualify existing encrypted SSD, cold boot, mount identity, HA backup separation, and launchd accounts.
7. Freeze one clean commit and run the 48-hour TrackMix fixed-wide pilot.
8. If P3-1 passes, add each eligible E1 separately and run final seven-day capacity campaign.
9. Accept P3-3 dashboard/playback before enabling any alert.
10. Calibrate one exact camera/class/zone alert policy at a time; failed classes stay absent.
11. Enable only camera occupied→unknown presence; vacancy/count stay absent.
12. Freeze the final candidate, run the seven-day household soak and accelerated retention simulation, then sign one storage decision.

Raw camera test media and packet captures live only in the owner-designated `$TUNTUN_OWNER_CAPTURE_ROOT` with restrictive permissions and declared deletion. `var/evidence/phase3/` holds safe reports/digests only. Neither directory is staged. A reviewer verifies `git check-ignore` and the private-data scanner before and after every physical campaign.

## Final Phase 3 Go/No-Go Checklist

- [ ] Accepted Phase 2 baseline and consumed Phase 1 FB0 services are current; Phase 1 P1R0/P1R1 is not incorrectly required.
- [ ] Exactly three physical camera records exist: hall TrackMix, kitchen E1 view A, kitchen E1 view B; each has an explicit eligible/absent disposition.
- [ ] Every enabled source has current exact model/revision/firmware/capability, canonical area, zone/`zone_generation`, binding, privacy, egress, audio, and evidence digests.
- [ ] Unknown E1 capability remains disabled; no vendor app scraping, cloud fallback, or silent bridge purchase occurs.
- [ ] TrackMix fixed field cannot see a bedroom interior; every enabled movement/tracking mode has complete zero-visibility evidence.
- [ ] Vendor control/P2P/DNS/telemetry/thumbnail/audio/media egress is disabled/blocked and verified across boot/retry/WAN restore/app polling.
- [ ] Stored media and playback responses have exactly zero audio streams.
- [ ] Source, recorder, media proxy, owner ingress, core, HA, and browser boundaries expose only their declared minimum data/keys/listeners; only owner ingress owns loopback 8787 and optional exact commissioned private-LAN 8443.
- [ ] Routine ingest is stream-copy with zero routine inference/decode/transcode; optional playback transcode is bounded and cleaned.
- [ ] Continuous low-wide coverage is ≥99.5% per eligible camera and every >5-second gap appears within 30 seconds.
- [ ] Continuous retention is exactly seven days; event retention exactly 90 days; transient ring ≤60 seconds plus cleanup bound.
- [ ] Clock rollback/restart/restore cannot extend expiry; low space never deletes unexpired media or spills to root.
- [ ] Capacity uses seven measured representative days and 20% reserve; voice and Green backup objectives pass.
- [ ] TrackMix tracking event view either passes every dual-view gate or is absent and labelled wide-only.
- [ ] Only the owner can list/search/play/export/delete/configure/pause/resume/receive alerts; all other actors/origins receive no existence signal/media.
- [ ] Each playback range grant is exact, single-use, freshly derived session plus clip-view-or-low-wide-segment subject/operation/range bound, and ≤60 seconds; only recorder owns the durable claim ledger.
- [ ] Export is recipient-encrypted and exact-passkey bound; deletion/copy disclosure never claims external-copy or physical-flash erasure.
- [ ] Privacy Shield revokes camera outcomes/grants within the canonical deadline while the independent recorder truth remains visible.
- [ ] Recorder pause/resume is separate, fresh-passkey bound, never voice-controlled, and never described as physical camera power-off.
- [ ] Every enabled alert class passes traversal/recall/false/latency/dedupe gates and sends metadata only to the local owner inbox/SSE.
- [ ] Closed/asleep/unpaired browser state makes no immediate-delivery claim; no service worker/background/native/SMS/email/vendor push exists.
- [ ] No event/alert/presence route reaches identity, memory, Reachy greeting, model, HA action, desktop, screen time, or robot authority.
- [ ] Camera presence is current anonymous occupied/unknown only; replay cannot extend it; outage/expiry/privacy becomes unknown.
- [ ] Vacancy, count, HA projection, movement history, viewer/child state, and selected-frame runtime are absent in the production manifest.
- [ ] Selected-frame contracts enforce 1–3 frames, ≤3 MiB, ≤1920 px, ≤5 seconds, exact live generations, local non-generative CV only; Phase 3 has no implementation or consumer.
- [ ] Raw-media and secret sentinels appear only in the video root and one authorized playback capture, nowhere else.
- [ ] Camera compromise cannot reach core authority, keys, HA signer, owner API, arbitrary tool execution, or internet.
- [ ] Every Section 18 fault, restore quarantine, catalog rebuild, firmware drift, rollback, and retirement test passes.
- [ ] UI passes owner authorization, no-prefetch/no-autoplay/no-persistence, English/Hindi/mixed-script, keyboard, VoiceOver, 320 px/200% zoom, theme, contrast, and reduced-motion gates.
- [ ] No high/critical finding, private repository byte, public listener, raw identifier/media in evidence, or undocumented flow remains.
- [ ] Feature manifest binds every source/view/class/alert/presence/selected-frame capability to `enabled` or `absent` evidence.
- [ ] Exactly one storage decision is signed from the measured evidence; no purchase is implied, and Phase 3 incremental acquisition remains S$0.
- [ ] Generated owner evidence is ignored and not staged; repository status is clean before the final evidence ceremony.

## Implementation Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-27-tuntun-phase3-vision-presence-storage-execution.md`. Two execution options:

1. **Subagent-Driven (recommended)** — dispatch a fresh subagent per task, review contract/spec compliance and code quality between tasks, and serialize all physical camera/storage campaigns.
2. **Inline Execution** — use `superpowers:executing-plans` in batches, stopping at P3-E0, P3-0, P3-1, P3-2, P3-3, P3-4, P3-5, and P3-6 for evidence review.

Do not begin either path in the documentation-planning session. The implementation session first creates an isolated worktree with `superpowers:using-git-worktrees`, confirms the accepted Phase 2/Phase 1 FB0 dependencies, and starts Task 01 with synthetic fixtures only.
