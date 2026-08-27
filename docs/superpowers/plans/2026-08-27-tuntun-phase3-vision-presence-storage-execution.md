# Tuntun Phase 3 Vision, Presence, and Storage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver an owner-only, local camera recorder and evidence plane for the hall TrackMix WiFi and two independently qualified kitchen E1-family cameras, with exact 7-day low-resolution continuous and 90-day full-resolution native-event retention, truthful storage/playback health, calibrated local security alerts, and anonymous expiring occupancy without creating a camera identity, audio, model, memory, Home Assistant media, or public-access path.

**Architecture:** Add three least-privilege Mac processes—`tuntun-camera-source`, `tuntun-recorder`, and `tuntun-media-proxy`—beside the Phase 1/2 modular monolith. Camera credentials and network connections terminate only in the source process; audio-free stream-copy media and native events cross bounded authenticated Unix-domain IPC; raw media and a separate SQLCipher vision catalog stay on the dedicated encrypted `TUNTUN_VIDEO` volume; only strict metadata events, health, opaque clip references, and current anonymous presence cross into `tuntun-core`. The initial store is the existing external SSD, and no NAS, NVR, Home Hub, larger disk, new sensor, or CV appliance is purchased or registered until its named evidence gate passes.

**Tech Stack:** Python 3.12, `asyncio`, Pydantic v2, SQLAlchemy 2/Alembic over SQLCipher, `cryptography`, macOS Keychain/FileVault/APFS, authenticated Unix-domain sockets and Darwin peer credentials, pinned PyAV/FFmpeg libraries used without routine decode, FastAPI/SSE, RFC 8785/JCS, JSON Schema 2020-12; React 19, TypeScript, Vite, React Router, TanStack Query; pytest, pytest-asyncio, Hypothesis, Ruff, strict mypy, Vitest, Testing Library, Playwright, axe, parser fuzzing, and owner-gated camera/network/storage campaigns.

**Normative design:** [Phase 3 Vision, Presence & Storage](../specs/2026-08-27-tuntun-phase3-vision-presence-storage-design.md), [Program A–H](../specs/2026-08-27-tuntun-program-architecture-a-h.md), [Program I–S](../specs/2026-08-27-tuntun-program-assurance-delivery-i-s.md), and [Six-Phase UI/UX](../specs/2026-08-27-tuntun-six-phase-ui-ux-design.md).

## Authority and Upstream Reconciliation

1. The Phase 3 design is normative for camera, retention, playback, alert, occupancy, source-eligibility, and procurement gates. Program A–H owns cross-phase architecture/contracts; Program I–S owns repository, evidence, assurance, operations, and synthetic-fixture rules; the UI/UX design owns surface truth, same-origin SSE, prepared-mutation, and feature-registration behavior.
2. Phase 1 remains the only identity, profile, consent, passkey, policy, memory, privacy-generation, and canonical audit authority. Reolink data never calls `IdentityPort`, becomes an unknown-person candidate, selects a speaker, retrieves memory, or triggers Reachy.
3. Phase 2 `area_id` is the only canonical household location ID. `camera_zone.v1` is a versioned/CAS child of one `area_id` and one camera-binding generation. A label such as “hall,” “kitchen,” “room,” or a translated label is presentation only.
4. The UI design's durable owner-console inbox plus authenticated same-origin SSE is the exact Phase 3 alert transport. The earlier word “Companion” does not authorize a native app, service worker, background push, SMS, email, vendor cloud, or public notification endpoint.
5. Privacy Shield revokes Tuntun camera outcomes, alert/presence processing, playback/export grants, and selected-frame requests while the independent recorder and its 7/90 retention continue. Recorder pause/resume is a separate owner-passkey operation and never claims physical camera power-off.
6. `selected_frame_request.v1` and `anonymous_visual_observation.v1` are contract-only in Phase 3. No `SelectedFrameVisionPort`, broker route, CV dependency, frame API, model/VLM/LLM path, UI route, or feature registration exists until Phase 5. The future result is advisory only; `count_band` cannot alter Phase 3 alert or presence state.
7. The three real placements are fixed inputs to owner evidence: TrackMix in the hall covering the bedroom pathway, E1-family camera A in the kitchen view A, and E1-family camera B in kitchen view B. Git fixtures use synthetic IDs and never encode household aliases, serials, addresses, frames, or credentials.
8. Each E1 remains `E1-family unknown` until its exact unit proves model/revision/firmware/local protocol/event/audio behavior. A source whose vendor cloud, UID/P2P, outbound DNS/control/metadata/thumbnail/audio/media paths cannot be disabled or blocked and independently verified is `vendor_native_only` and absent from every Phase 3 runtime route.
9. The fixed recording policy is one low-resolution wide stream per eligible physical camera for exactly seven days plus approved native-event full-resolution clips for exactly 90 days. TrackMix tracking-view event media is independently conditional; failure leaves only the wide event clip.
10. Camera audio is disabled at the device where supported and rejected again before durable storage. A source that cannot produce provably audio-free stored media is ineligible.

## Global Constraints

1. The accepted Phase 2 baseline plus the stable Phase 1 `FB0` services consumed by Phase 3—owner/passkey authorization, policy/privacy generation, serialized SQLCipher unit of work, content-minimized audit/outbox, owner API, feature registry, backup/restore quarantine, Guest denial, and memory/identity isolation—must pass before Phase 3 source enablement. Phase 1-only `P1R0/P1R1` standalone-preview hardening may continue in parallel and is not a Phase 2/3 entry gate.
2. The existing 2020 Intel Mac with 16 GB RAM, three current Reolink cameras, and encrypted external SSD are reused. Phase 3 incremental acquisition is S$0 until measured evidence opens a separately approved procurement record.
3. No NAS, NVR, Reolink Home Hub, larger SSD, accelerator, non-imaging presence sensor, surveillance licence, or camera replacement is ordered by this plan. P3-6 produces one evidence-bound storage decision; purchasing is a later explicit owner action.
4. Raw camera frames, thumbnails, clips, audio, stream URLs, credentials, IP/MAC addresses, filenames, OCR, captions, free detector labels, or parser errors never enter `tuntun-core` storage, canonical memory, Home Assistant, audit bodies, logs, browser persistence, crash reports, backups, cloud AI, an LLM/VLM, source control, CI artifacts, or public evidence.
5. The video catalog has a separate SQLCipher database and Keychain namespace. It contains no family name, profile ID, child/guardian ID, biometric, conversation ID, memory ID, transcript, provider key, HA key, or joinable identity field.
6. The camera-source process can open only commissioned local camera destinations and its own Keychain items. The recorder has no camera credential, provider/identity/memory/HA key, general network route, or Mac-root fallback. The media proxy has read-only opaque media access and a Unix socket, not a camera route or LAN listener.
7. Routine ingest is packet/codec stream-copy. It performs no continuous decode, object detection, recognition, tracking inference, captioning, OCR, model call, or transcoding. One owner-requested playback transcode is bounded, audio-free, lower priority than an active voice turn, RAM/temporary-only, and destroyed on completion, cancellation, expiry, privacy, or crash.
8. Each trust-boundary DTO is frozen, rejects duplicate/unknown fields and enum values, bounds every string/list/body, uses Unicode NFC and aware UTC, and uses RFC 8785/JCS for commitments. Unknown versions, stale generations, untrusted clocks, and cross-area/zone bindings quarantine before policy.
9. The Phase 2 cross-domain event envelope is reused unchanged. Events are observations, never authorization. No camera or presence event can call a Home Assistant action, light routine, greeting, memory write, desktop job, media action, or robot route directly.
10. Playback is owner-only and same-origin. Second adult, K2 child, N1 child, Designated Guest, anonymous Guest, HA user, Reachy turn, inner compromised client, and outer/office-laptop client receive no clip list, metadata, distinguishing existence signal, grant, media bytes, URL, or credential.
11. Every P3 playback byte-range grant is one clip/view/operation/range/session, single-use, and expires within 60 seconds. Export and early delete always consume a fresh exact-scope owner-passkey grant.
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
| P3-6 | All enabled gates | Seven-day household soak, accelerated 90-day retention, security/privacy/failure matrix, signed feature manifest, and one storage decision receipt pass | Affected feature is quarantined/absent; no NAS/NVR purchase is implied |
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

apps/recorder/src/tuntun_recorder/
├── config.py
├── volume.py
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

packages/secure-archive/src/tuntun_secure_archive/
├── __init__.py
└── writer.py

integrations/reolink/src/tuntun_reolink/
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
└── com.tuntun.media-proxy.plist
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
    "recorder_pause", "recorder_resume", "recorder_receipt", "owner_clip_query", "clip_page",
    "media_playback_grant", "event_ingress_receipt",
]
VisionProcess = Literal["core", "camera_source", "recorder", "media_proxy"]
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
~~~

`OpaqueStorageToken`, relay IDs, staging tokens, and cursors are random base64url values, never encoded paths, camera IDs, names, or reusable browser capabilities. Every enum used by a frozen contract is a closed alias or inline `Literal`; adapter-private vendor strings must be compiled to one of those values before crossing a port.

~~~python
# packages/contracts/src/tuntun_contracts/vision/topology.py
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
    traversal_count: Annotated[int, Field(ge=1, le=10_000)]
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
        if any(
            sum(
                trial.traversal_count
                for trial in self.trials
                if trial.doorway == doorway and trial.motion_mode == mode
            ) < 30
            for doorway in self.doorways
            for mode in self.enabled_motion_modes
        ):
            raise ValueError("trackmix_traversal_minimum_not_met")
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

class StorageMeasurementV1(VisionContract):
    schema_id: Literal["storage_measurement.v1"] = "storage_measurement.v1"
    measurement_id: UUID
    measurement_generation: Annotated[int, Field(ge=1)]
    campaign_id: UUID
    camera_binding_id: StableVisionId
    camera_binding_generation: Annotated[int, Field(ge=1)]
    capability_generation: Annotated[int, Field(ge=1)]
    profile_generation: Annotated[int, Field(ge=1)]
    source_eligibility_generation: Annotated[int, Field(ge=1)]
    egress_evidence_generation: Annotated[int, Field(ge=1)]
    volume_qualification_generation: Annotated[int, Field(ge=1)]
    catalog_generation: Annotated[int, Field(ge=1)]
    area_id: StableHomeId
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
        return self

class CapacityProjectionV1(VisionContract):
    schema_id: Literal["capacity_projection.v1"] = "capacity_projection.v1"
    projection_id: UUID
    projection_generation: Annotated[int, Field(ge=1)]
    campaign_id: UUID
    measurement_ids: Annotated[tuple[UUID, ...], Field(min_length=7, max_length=128)]
    volume_qualification_generation: Annotated[int, Field(ge=1)]
    catalog_generation: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    eligible_camera_count: Annotated[int, Field(ge=1, le=3)]
    ineligible_camera_count: Annotated[int, Field(ge=0, le=2)]
    selected_view_set: Annotated[tuple[ClipView, ...], Field(min_length=1, max_length=2)]
    campaign_started_at: AwareDatetime
    campaign_ended_at: AwareDatetime
    continuous_policy_bytes: Annotated[int, Field(ge=1)]
    event_policy_bytes: Annotated[int, Field(ge=0)]
    measured_catalog_and_filesystem_overhead: Annotated[int, Field(ge=0)]
    policy_bytes: Annotated[int, Field(ge=1)]
    reserve_basis_points: Literal[2000]
    required_usable_capacity: Annotated[int, Field(ge=1)]
    usable_capacity: Annotated[int, Field(ge=0)]
    minimum_coverage_ratio: Annotated[Decimal, Field(ge=Decimal("0"), le=Decimal("1"))]
    longest_gap_detection_seconds: Annotated[int, Field(ge=0, le=86_400)]
    voice_p95_seconds: Annotated[Decimal, Field(ge=Decimal("0"))]
    voice_regression_percent: Annotated[Decimal, Field(ge=Decimal("0"))]
    stored_audio_stream_count: Literal[0]
    claim: Literal["complete_eligible_camera_set", "partial_eligible_camera_set"]
    decision: Literal["p3_2_pass", "p3_2_partial", "p3_2_blocked_capacity", "p3_2_blocked_reliability"]
    projected_at: AwareDatetime
    valid_until: AwareDatetime
    measurement_digest: Sha256Digest
    reason_codes: Annotated[tuple[SafeReasonCode, ...], Field(max_length=16)]

    @model_validator(mode="after")
    def coherent_capacity_projection(self) -> "CapacityProjectionV1":
        if len(self.measurement_ids) != len(set(self.measurement_ids)):
            raise ValueError("capacity_measurement_duplicate")
        if self.eligible_camera_count + self.ineligible_camera_count != 3:
            raise ValueError("capacity_camera_set_invalid")
        if len(self.selected_view_set) != len(set(self.selected_view_set)) or "wide" not in self.selected_view_set:
            raise ValueError("capacity_view_set_invalid")
        elapsed = self.campaign_ended_at - self.campaign_started_at
        if elapsed < timedelta(days=7) or elapsed > timedelta(days=8):
            raise ValueError("capacity_campaign_window_invalid")
        if not self.campaign_ended_at <= self.projected_at <= self.campaign_ended_at + timedelta(hours=1):
            raise ValueError("capacity_projection_time_invalid")
        if not self.projected_at < self.valid_until <= self.projected_at + timedelta(days=90):
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
        reliability_ok = (
            self.minimum_coverage_ratio >= Decimal("0.995")
            and self.longest_gap_detection_seconds <= 30
            and self.voice_p95_seconds <= Decimal("4")
            and self.voice_regression_percent <= Decimal("10")
        )
        expected_decision = (
            "p3_2_blocked_reliability" if not reliability_ok
            else "p3_2_blocked_capacity" if self.usable_capacity < self.required_usable_capacity
            else "p3_2_partial" if partial
            else "p3_2_pass"
        )
        if self.decision != expected_decision:
            raise ValueError("capacity_projection_decision_invalid")
        if (self.decision == "p3_2_pass") == bool(self.reason_codes):
            raise ValueError("capacity_projection_reason_state_invalid")
        return self
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
    zone_id: StableVisionId
    zone_generation: Annotated[int, Field(ge=1)]
    event_class: CameraEventClass
    detector_basis: Literal["device_native", "hub_native"]
    detector_version: BoundedSafeCode
    started_at: AwareDatetime
    ended_at: AwareDatetime | None
    confidence_band: Literal["unavailable", "low", "medium", "high"]
    verification: Literal["native", "corroborated", "uncertain"]
    clock_quality: Literal["synchronized", "degraded", "untrusted"]
    clip_ref: UUID | None
    view_set: Literal["wide", "wide_and_tracking"]
    privacy_policy_version: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]

    @model_validator(mode="after")
    def coherent_window(self) -> "CameraSecurityEventV1":
        if self.ended_at is not None and (
            self.ended_at < self.started_at or self.ended_at - self.started_at > timedelta(minutes=5)
        ):
            raise ValueError("camera_event_window_invalid")
        return self

class PresenceChangedV1(VisionContract):
    schema_id: Literal["presence.changed.v1"] = "presence.changed.v1"
    area_id: StableHomeId
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
            if self.count_band != "zero" or "commissioned_non_imaging" not in self.source_kinds:
                raise ValueError("vacant_presence_requires_non_imaging")
        if self.state == "occupied" and "camera_native_person" in self.source_kinds and "commissioned_non_imaging" not in self.source_kinds:
            if self.count_band != "unknown":
                raise ValueError("camera_presence_count_forbidden")
        return self

class AnonymousPresenceEvidenceV1(VisionContract):
    schema_id: Literal["anonymous_presence_evidence.v1"] = "anonymous_presence_evidence.v1"
    evidence_id: UUID
    kind: Literal["camera_native_person", "commissioned_non_imaging"]
    area_id: StableHomeId
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
EventPayloadT = TypeVar("EventPayloadT", bound=ContractModel)

class CrossDomainEventV1(ContractModel, Generic[EventPayloadT]):
    event_id: UUID
    schema_version: Literal[1]
    event_type: BoundedSafeCode
    source_endpoint_id: StableHomeId
    observed_at: AwareDatetime
    ingested_at: AwareDatetime
    correlation_id: UUID
    causation_id: UUID | None
    deduplication_key: HmacCommitment
    sensitivity_class: Literal["household_private_metadata"]
    payload: EventPayloadT

    @model_validator(mode="after")
    def coherent_envelope(self) -> "CrossDomainEventV1[EventPayloadT]":
        payload_schema = getattr(self.payload, "schema_id", None)
        payload_event_id = getattr(self.payload, "event_id", None)
        if self.event_type != payload_schema or self.event_id != payload_event_id:
            raise ValueError("cross_domain_event_payload_binding_invalid")
        if not self.observed_at <= self.ingested_at <= self.observed_at + timedelta(seconds=30):
            raise ValueError("cross_domain_event_ingress_window_invalid")
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
    area_id: StableHomeId | None
    zone_id: StableVisionId | None
    zone_generation: Annotated[int | None, Field(ge=1)]
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
        event_fields = (self.area_id, self.zone_id, self.zone_generation, self.event_id, self.event_class)
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
        return self

class OwnerClipQueryV1(VisionContract):
    schema_id: Literal["owner_clip_query.v1"] = "owner_clip_query.v1"
    query_id: UUID
    owner_subject_id: StableSubjectId
    owner_session_id: UUID
    area_id: StableHomeId | None
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
        if (self.zone_id is None) != (self.zone_generation is None):
            raise ValueError("owner_clip_query_zone_binding_invalid")
        if self.zone_id is not None and self.area_id is None:
            raise ValueError("owner_clip_query_zone_without_area")
        if len(self.event_classes) != len(set(self.event_classes)):
            raise ValueError("owner_clip_query_event_duplicate")
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

class PlaybackRangeRequestV1(VisionContract):
    schema_id: Literal["playback_range_request.v1"] = "playback_range_request.v1"
    request_id: UUID
    clip_id: UUID
    view: Literal["wide", "tracking"]
    byte_range: InclusiveByteRangeV1
    expected_clip_generation: Annotated[int, Field(ge=1)]
    expected_catalog_generation: Annotated[int, Field(ge=1)]
    expected_privacy_generation: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    request_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_request_window(self) -> "PlaybackRangeRequestV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=5):
            raise ValueError("playback_range_request_window_invalid")
        return self

class MediaPlaybackGrantV1(VisionContract):
    grant_id: UUID
    owner_subject_id: StableSubjectId
    owner_session_id: UUID
    clip_id: UUID
    allowed_view: Literal["wide", "tracking"]
    allowed_operation: Literal["playback", "export", "delete"]
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
        if not self.emitted_at < self.valid_until <= self.emitted_at + timedelta(seconds=30):
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

The selected-frame validator requires `expires_at - not_before <= 5 seconds`. Core signs the request as domain `tuntun.selected-frame-request.v1`; the isolated proxy signs the result as domain `tuntun.anonymous-visual-observation.v1`. Verifiers resolve pinned key IDs and verify the exact canonical inner DTO before reading authority-bearing fields; missing/unknown keys, malformed signatures, inner-field mutation, wrong domain, or replay fail closed. Its pure binding validator rejects unless the live canonical `area_id`, `zone_id`, `zone_generation`, camera-binding generation, privacy-policy and Privacy Shield generations, request ID, model manifest, model artifact ID/digest, calibration digest, response zone, and trusted current time all still match the single live request. Phase 3 ships these schemas/validators but deliberately defines no runtime `SelectedFrameVisionPort`.

~~~python
# packages/contracts/src/tuntun_contracts/vision/ipc.py
VisionIpcPayloadV1 = (
    CameraProbeTarget
    | CameraCapabilityEvidenceV1
    | OpenCameraStreamV1
    | ReadOnlyMediaHandle
    | NativeCameraEventV1
    | SourceHealthV1
    | CrossDomainEventV1[CameraSecurityEventV1]
    | RecordingHealthV1
    | RecorderPauseV1
    | RecorderResumeV1
    | RecorderReceiptV1
    | OwnerClipQueryV1
    | OpaquePage[ClipV1]
    | SignedMediaPlaybackGrantV1
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
        "cross_domain.camera_security_event.v1", "recording_health.v1", "recorder_pause.v1",
        "recorder_resume.v1", "recorder_receipt.v1", "owner_clip_query.v1", "opaque_page.v1",
        "signed_media_playback_grant.v1", "event_ingress_receipt.v1",
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
            "recorder_pause": ("core", "recorder"),
            "recorder_resume": ("core", "recorder"),
            "recorder_receipt": ("recorder", "core"),
            "owner_clip_query": ("core", "recorder"),
            "clip_page": ("recorder", "core"),
            "media_playback_grant": ("core", "media_proxy"),
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
            "camera_security_event": "cross_domain.camera_security_event.v1",
            "recording_health": "recording_health.v1",
            "recorder_pause": "recorder_pause.v1",
            "recorder_resume": "recorder_resume.v1",
            "recorder_receipt": "recorder_receipt.v1",
            "owner_clip_query": "owner_clip_query.v1",
            "clip_page": "opaque_page.v1",
            "media_playback_grant": "signed_media_playback_grant.v1",
            "event_ingress_receipt": "event_ingress_receipt.v1",
        }[self.message_type]
        if self.message_type == "camera_security_event":
            nested = getattr(self.payload, "payload", None)
            actual_schema = (
                "cross_domain.camera_security_event.v1"
                if getattr(self.payload, "event_type", None) == "camera.security_event.v1"
                and getattr(nested, "schema_id", None) == "camera.security_event.v1"
                else None
            )
        else:
            actual_schema = getattr(self.payload, "schema_id", None)
        if self.payload_schema_id != expected_schema or actual_schema != expected_schema:
            raise ValueError("vision_ipc_payload_schema_invalid")
        return self

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
    async def start(self, binding: CameraBindingV1, profile: RecordingProfileV1) -> RecorderReceiptV1: ...
    async def promote(self, event: CameraSecurityEventV1) -> ClipV1 | ClipUnavailableV1: ...
    async def pause(self, command: RecorderPauseV1) -> RecorderReceiptV1: ...
    async def resume(self, command: RecorderResumeV1) -> RecorderReceiptV1: ...
    async def status(self, binding: CameraBindingV1, profile: RecordingProfileV1) -> RecordingHealthV1: ...

class VisionCatalogPort(Protocol):
    async def commit_segment(self, staged: StagedSegment) -> SegmentV1: ...
    async def commit_clip(self, staged: StagedClip) -> ClipV1: ...
    async def find_clips(self, query: OwnerClipQueryV1) -> OpaquePage[ClipV1]: ...
    async def resolve_storage_token(self, clip: ClipV1, view: ClipView) -> OpaqueStorageToken: ...

class CameraOutcomePort(Protocol):
    async def ingest_security_event(
        self, envelope: CrossDomainEventV1[CameraSecurityEventV1],
    ) -> EventIngressReceiptV1: ...
    async def ingest_health(self, health: RecordingHealthV1) -> None: ...

class AnonymousPresencePort(Protocol):
    async def apply(self, evidence: AnonymousPresenceEvidenceV1) -> PresenceChangedV1: ...
    async def current(self, area_id: StableHomeId) -> PresenceChangedV1: ...
~~~

The Pydantic validators above own closed shape, strict scalar types, positive generations, bounded lifetimes, and self-consistent states. They do not turn signed or well-formed data into authority. Each port implementation must then atomically compare every carried source-endpoint, camera-binding, capability, profile, recorder, area, zone, catalog, policy, privacy, source-eligibility, and volume-qualification generation relevant to that call against live canonical state immediately before effect. It must also compare request/causation IDs, commitments, stream/view roles, and trusted time. A missing live row, expired DTO, generation mismatch, state transition mismatch, duplicate single-use ID, or signature/IPC failure rejects before opening a descriptor, reading a storage token, committing media, dispatching an event, changing presence, or changing recorder state. `RecorderReceiptV1.causation_id` is `RecordingProfileV1.activation_id` for `start` and the exact command ID for `pause` or `resume`. `recorder.pause.all` and `recorder.resume.all` are core operations only: after one exact owner authorization, core snapshots the bounded eligible set and emits one frozen per-camera `RecorderPauseV1` or `RecorderResumeV1` for each member; the recorder never accepts an unbounded wildcard command.

## Durable State and Migration Map

### Canonical core SQLCipher migrations

| Revision | Tables and critical invariants |
|---|---|
| `0013_camera_policy` | `camera_inventory`, `camera_bindings`, `camera_zones`, `camera_commissioning_generations`, `camera_source_eligibility`, `camera_privacy_policies`, `camera_copy_disclosures`; one current binding per source endpoint, one zone belongs to one canonical area/binding generation, strict CAS/generation, real identifiers represented only by HMAC commitments, no credential/media/profile/name field |
| `0014_camera_alerts` | `camera_alert_policies`, `camera_alert_quality_evidence`, `camera_alert_inbox`, `camera_alert_delivery_receipts`, `camera_alert_cooldowns`; exact camera/class/zone/schedule/policy generation, singleton owner recipient implicit, metadata only, delivery queue expires at 24 hours, no thumbnail/token/person/profile/address field |
| `0015_presence_checkpoint` | `presence_policies`, `presence_checkpoints`; exactly one replace-in-place current row per area, exact policy/privacy generations, original expiry cannot be extended by replay, camera evidence cannot write vacant/count, no history/subject/viewer/clip relation, expiry removes the checkpoint and checkpoints are excluded from long-lived audit/backup projections |

### Separate vision-catalog SQLCipher migrations

The recorder owns `$TUNTUN_VIDEO/catalog/vision.sqlite3` under its own Keychain key and migration lock. It is never attached to the canonical database and is excluded from Phase 1 portable backups.

| Catalog revision | Tables and critical invariants |
|---|---|
| `0001_media_catalog` | `source_state`, `segments`, `gaps`, `native_events`, `clips`, `clip_views`, `clip_event_refs`; opaque random file tokens, exact immutable expiry, segment/file digest and size, one primary plus bounded coalesced event references, no family/room-label/address/path/credential/identity field |
| `0002_media_operations` | `grant_consumptions`, `export_jobs`, `delete_jobs`, `retention_journal`, `reconciliation_claims`; grant digest/ID only, one consumption, crash-safe operation state, no owner subject/session stored after verification |
| `0003_measurement_health` | `daily_stream_measurements`, `event_measurements`, `volume_health`, `copy_registry`, `catalog_integrity`; safe counts/timings/digests only, no media sample or raw device error |

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
pnpm --filter @tuntun/admin exec playwright test tests/e2e/cameras-*.spec.ts
~~~

Owner-gated commands write only safe evidence to ignored `var/evidence/phase3/`:

~~~bash
TUNTUN_ALLOW_CAMERA_HARDWARE=1 uv run python scripts/phase3/inventory_cameras.py --output var/evidence/phase3/inventory.json
TUNTUN_ALLOW_CAMERA_NETWORK=1 uv run python scripts/phase3/verify_camera_egress.py --capture-root "$TUNTUN_OWNER_CAPTURE_ROOT" --output var/evidence/phase3/egress.json
TUNTUN_ALLOW_TRACKMIX_ARC=1 uv run python scripts/phase3/qualify_trackmix_arc.py --output var/evidence/phase3/trackmix-arc.json
TUNTUN_ALLOW_VIDEO_VOLUME=1 uv run python scripts/phase3/qualify_video_volume.py --output var/evidence/phase3/video-volume.json
TUNTUN_ALLOW_ELAPSED_PHASE3=1 uv run python scripts/phase3/run_one_camera_pilot.py --duration-seconds 172800 --output var/evidence/phase3/one-camera-pilot.json
TUNTUN_ALLOW_ELAPSED_PHASE3=1 uv run python scripts/phase3/run_capacity_campaign.py --duration-seconds 604800 --output var/evidence/phase3/capacity.json
TUNTUN_ALLOW_ELAPSED_PHASE3=1 uv run python scripts/phase3/run_acceptance.py household-soak --duration-seconds 604800 --output var/evidence/phase3/household-soak.json
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

**Interfaces:** Consumes the unchanged generic Phase 2 `CrossDomainEventV1`, Phase 2 stable home IDs/topology generation, shared strict contract bases, safe reason codes, commitments, and UI primitives. Produces every frozen contract above, including the source/probe/media-handle, native-event/ingress, recorder-control/catalog, immutable manifest, egress/arc/capacity evidence, anonymous-presence, opaque-token/page, health/UI/SSE, and authenticated IPC DTOs used by every public protocol; `canonical_vision_bytes(value: VisionContract) -> bytes`; schema bundle ID `tuntun.vision.v1`; generated TypeScript/OpenAPI-ready schema artifacts; and the pure boundary helpers `validate_selected_frame_result_binding(request, observation, live) -> None` and `validate_vision_ipc_envelope_binding(envelope, live, now, actual_payload_digest, authenticated_commitment) -> None`. Each boundary implementation attaches its frozen model validator and a live-state validator that compares every carried generation, lifetime, state, ID, role, digest, sequence, direction, and commitment before effect. The selected-frame helper rechecks the current area, zone, zone generation, camera generation, privacy generation, approved model digest, and calibration digest immediately before a future Phase 5 consumer may accept a result. It deliberately produces no runtime selected-frame port.

- [ ] **Step 1: Write red public-port, IPC, zone-binding, retention, and selected-frame limit tests**

~~~python
def test_zone_is_bound_to_exact_area_camera_and_cas(zone_fixture: dict[str, object]) -> None:
    zone = CameraZoneV1.model_validate(zone_fixture)
    assert zone.area_id == "area_common_synth_01"
    assert zone.camera_binding_generation == 3
    assert zone.zone_generation == 7

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
        "area_id", "zone_id", "zone_generation", "camera_binding_generation",
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

@pytest.mark.parametrize("fault", ["evaluated_before_request", "evaluated_after_now", "expired_now", "inverted_validity"])
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
        CrossDomainEventV1[CameraSecurityEventV1].model_validate({
            **event_envelope_fixture,
            "event_type": "presence.changed.v1",
        })
    with pytest.raises(ValidationError):
        CrossDomainEventV1[CameraSecurityEventV1].model_validate({
            **event_envelope_fixture,
            "schema_version": 2,
        })
    with pytest.raises(ValidationError, match="cross_domain_event_ingress_window_invalid"):
        CrossDomainEventV1[CameraSecurityEventV1].model_validate({
            **event_envelope_fixture,
            "ingested_at": event_envelope_fixture["observed_at"] + timedelta(seconds=30, microseconds=1),
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
        for process in ("core", "camera_source", "recorder", "media_proxy")
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
    ("recorder_pause", "core", "recorder"),
    ("recorder_resume", "core", "recorder"),
    ("recorder_receipt", "recorder", "core"),
    ("owner_clip_query", "core", "recorder"),
    ("clip_page", "recorder", "core"),
    ("media_playback_grant", "core", "media_proxy"),
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
        for process in ("core", "camera_source", "recorder", "media_proxy")
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

def test_playback_range_request_is_bounded_and_generation_bound(playback_range_request_fixture) -> None:
    for mutation in (
        {"expected_clip_generation": 0},
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
    return jcs.canonicalize(normalize_nfc_and_utc(value.model_dump(mode="json")))

@dataclass(frozen=True)
class SelectedFrameLiveBinding:
    camera_binding_id: str
    camera_binding_generation: int
    area_id: str
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
        request.area_id, request.zone_id, request.zone_generation,
        request.privacy_policy_version, request.privacy_generation, request.model_manifest_digest,
    )
    current_binding = (
        live.camera_binding_id, live.camera_binding_generation,
        live.area_id, live.zone_id, live.zone_generation,
        live.privacy_policy_version, live.privacy_generation, live.model_manifest_digest,
    )
    observation_binding_is_current = (
        observation.request_id == request.request_id
        and observation.zone_id == live.zone_id
        and observation.model_artifact_id == live.model_artifact_id
        and observation.model_digest == live.model_artifact_digest
        and observation.calibration_digest == live.calibration_digest
        and request.not_before <= observation.evaluated_at <= now
        and now <= observation.valid_until
        and observation.valid_until <= request.expires_at
    )
    if request_binding != current_binding or not observation_binding_is_current:
        raise ValueError("selected_frame_binding_stale")
~~~

The selected-frame request and anonymous-observation time validators are attached directly to their Pydantic models. The live binding keeps the approved manifest digest and approved model-artifact digest distinct: the request binds the former and the result binds the latter. The immediate acceptance helper receives the trusted current time and rejects pre-window, future-evaluated, inverted, or expired results. Import and re-export the accepted Phase 2 generic `CrossDomainEventV1` without changing its field names or canonical encoding; generate the closed `CrossDomainEventV1[CameraSecurityEventV1]` specialization for Phase 3. Generate recursively closed schemas, reject duplicate JSON keys before Pydantic, and add property mutations for unknown version/field/enum, unsafe IDs, malformed opaque tokens/cursors, cross-area zone substitution, every zero/negative generation, overlong or inverted authority/evidence/SSE/IPC windows, incomplete or contradictory egress/TrackMix evidence, estimated bytes for ineligible sources, capacity formula/claim/decision drift, manifest identity/retention/path injection, stale nested UI facts, false clip/live alert state, IPC direction/schema/header-sequence/payload-digest/HMAC/replay drift, incompatible capability/source/receipt/presence states, duplicate page/view/stream/trial/measurement entries, more than two clip views, non-single-use commands/grants, wrong retention expiry, grant lifetime over 60 seconds, selected-frame purpose/schema changes, and free-form observation classes.

- [ ] **Step 4: Run green and schema-drift checks**

Run: `uv run python scripts/phase3/generate_vision_schemas.py --check && uv run pytest tests/contract/vision tests/property/vision/test_contract_rejection.py -q && uv run ruff check packages/contracts/src/tuntun_contracts/vision scripts/phase3/generate_vision_schemas.py tests/contract/vision tests/property/vision && uv run mypy packages/contracts/src`
Expected: PASS; generator prints `vision schema drift: none`; every unsupported version/field/enum, scalar coercion, malformed opaque value, stale/zero generation, incompatible state, range, and lifetime window is rejected.

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

### Task 03: Persist camera policy, canonical zones, alerts, and current-only presence

**Depends on:** Tasks 01–02 and accepted Phase 2 topology migrations.
**Gate contribution:** P3-E0.
**Estimated effort:** 2 person-days.

**Files:**
- Create: `apps/core/migrations/versions/0013_camera_policy.py`
- Create: `apps/core/migrations/versions/0014_camera_alerts.py`
- Create: `apps/core/migrations/versions/0015_presence_checkpoint.py`
- Create: `apps/core/src/tuntun_core/domain/vision/commissioning.py`
- Create: `apps/core/src/tuntun_core/domain/vision/zones.py`
- Create: `apps/core/src/tuntun_core/domain/vision/alerts.py`
- Create: `apps/core/src/tuntun_core/domain/vision/presence.py`
- Test: `tests/integration/vision/test_core_vision_migrations.py`
- Test: `tests/unit/vision/test_zone_cas.py`
- Test: `tests/unit/vision/test_presence_checkpoint_shape.py`

**Interfaces:** Consumes the shared serialized `UnitOfWork`, `TopologyRegistryPort`, Phase 1 audit outbox, policy version, and action-grant primitives. Produces `CameraPolicyRepository`, `CameraZoneRepository.compare_and_swap`, `AlertPolicyRepository`, `AlertInboxRepository`, and `PresenceCheckpointRepository.replace_current`. It stores no raw event/media body and creates no relation to profiles, identity, memory, conversations, or HA entities.

- [ ] **Step 1: Write red migration, cross-area substitution, and no-history tests**

~~~python
async def test_zone_update_rejects_area_or_binding_substitution(repos, commissioned_zone) -> None:
    edited = commissioned_zone.model_copy(update={"area_id": "area_other_synth"})
    with pytest.raises(ZoneConflict, match="zone_binding_mismatch"):
        await repos.zones.compare_and_swap(edited, expected_generation=commissioned_zone.zone_generation)

async def test_presence_repository_has_one_current_row_and_no_history(db, repos) -> None:
    await repos.presence.replace_current(occupied_checkpoint(version=1))
    await repos.presence.replace_current(unknown_checkpoint(version=2))
    assert await db.scalar("select count(*) from presence_checkpoints") == 1
    assert not await db.table_exists("presence_history")
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/vision/test_core_vision_migrations.py tests/unit/vision/test_zone_cas.py tests/unit/vision/test_presence_checkpoint_shape.py -q`
Expected: FAIL because revision `0013_camera_policy` and vision repositories are absent.

- [ ] **Step 3: Implement encrypted migrations, database constraints, and repository CAS**

~~~python
async def compare_and_swap(self, candidate: CameraZoneV1, expected_generation: int, uow: UnitOfWork) -> CameraZoneV1:
    current = await self.get_for_update(candidate.zone_id, uow)
    if current.zone_generation != expected_generation:
        raise ZoneConflict("zone_generation_stale")
    if (candidate.area_id, candidate.camera_binding_id, candidate.camera_binding_generation) != (
        current.area_id, current.camera_binding_id, current.camera_binding_generation
    ):
        raise ZoneConflict("zone_binding_mismatch")
    next_zone = candidate.model_copy(update={"zone_generation": current.zone_generation + 1})
    await self._write_and_invalidate_dependents(next_zone, uow)
    return next_zone
~~~

Add SQL constraints/triggers for one active binding, unique current zone version, distinct alert policy scope, alert queue expiry, one presence row per area, `valid_until > observed_at`, camera-only occupied/count unknown, and deletion on expiry. Migration tests inspect every column and foreign key to prove forbidden profile/media/path/name/address fields are absent.

- [ ] **Step 4: Run green, forward/restart, and downgrade-isolation checks**

Run: `uv run pytest tests/integration/vision/test_core_vision_migrations.py tests/unit/vision/test_zone_cas.py tests/unit/vision/test_presence_checkpoint_shape.py -q && uv run alembic upgrade head && uv run python scripts/check_migration_ownership.py --revisions 0013 0014 0015 && uv run ruff check apps/core/migrations/versions/0013_camera_policy.py apps/core/migrations/versions/0014_camera_alerts.py apps/core/migrations/versions/0015_presence_checkpoint.py apps/core/src/tuntun_core/domain/vision tests/integration/vision tests/unit/vision && uv run mypy apps/core/src`
Expected: PASS; migration inspection reports no forbidden column and restart preserves only current state.

- [ ] **Step 5: Commit**

~~~bash
git add apps/core/migrations/versions/0013_camera_policy.py apps/core/migrations/versions/0014_camera_alerts.py apps/core/migrations/versions/0015_presence_checkpoint.py apps/core/src/tuntun_core/domain/vision tests/integration/vision/test_core_vision_migrations.py tests/unit/vision/test_zone_cas.py tests/unit/vision/test_presence_checkpoint_shape.py
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
- Create: `apps/recorder/src/tuntun_recorder/catalog/database.py`
- Create: `apps/recorder/src/tuntun_recorder/catalog/models.py`
- Create: `apps/recorder/src/tuntun_recorder/catalog/manifest.py`
- Create: `apps/recorder/src/tuntun_recorder/catalog/repository.py`
- Create: `apps/recorder/src/tuntun_recorder/catalog/migrations/0001_media_catalog.py`
- Create: `apps/recorder/src/tuntun_recorder/catalog/migrations/0002_media_operations.py`
- Create: `apps/recorder/src/tuntun_recorder/catalog/migrations/0003_measurement_health.py`
- Create: `apps/recorder/src/tuntun_recorder/recording/reconciliation.py`
- Test: `apps/recorder/tests/integration/test_catalog_migrations.py`
- Test: `apps/recorder/tests/integration/test_media_commit_crash.py`
- Test: `apps/recorder/tests/security/test_catalog_schema_isolation.py`

**Interfaces:** Produces `VisionCatalog` implementing `VisionCatalogPort`, `CatalogMigrator.upgrade`, `MediaCommitter.commit(staged)`, authenticated `OpaqueMediaManifestV1` sidecars, and `CatalogReconciler.run_once(limit)`. Consumes a verified `VideoVolumeHandle` and a dedicated catalog-key handle; never imports `tuntun_core` or opens the canonical database.

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
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/recorder/tests/integration/test_catalog_migrations.py apps/recorder/tests/integration/test_media_commit_crash.py apps/recorder/tests/security/test_catalog_schema_isolation.py -q`
Expected: FAIL during collection because `tuntun_recorder.catalog` is absent.

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

All queries are bounded and use opaque tokens. Each published media object has a separately opaque, HMAC-authenticated `OpaqueMediaManifestV1` containing only schema version, token, media digest/size, source/binding/generation, area/zone/generation where applicable, stream/clip/event metadata, immutable expiry, and catalog transaction ID—never a human name, address, credential, absolute path, or identity. Its only state is `rebuild_only_not_playback_authority`: the writer and reconciler revalidate the canonical HMAC, storage token, exact catalog/source/capability/profile/eligibility/volume generations, digest, size, retention, and catalog transaction against live rows before use, and only the catalog `PUBLISHED` transition makes bytes playable. Reconciliation handles only declared lifecycle states, checks path containment and digest before publication, marks uncertain media unavailable, and never searches by camera-supplied filename. Apply SQLCipher, WAL, `synchronous=FULL`, `foreign_keys=ON`, file `0600`, directory `0700`, and a separate migration lock.

- [ ] **Step 4: Run green and forbidden-schema scan**

Run: `uv run pytest apps/recorder/tests/integration/test_catalog_migrations.py apps/recorder/tests/integration/test_media_commit_crash.py apps/recorder/tests/security/test_catalog_schema_isolation.py -q && uv run ruff check apps/recorder/src/tuntun_recorder/catalog apps/recorder/src/tuntun_recorder/recording/reconciliation.py apps/recorder/tests && uv run mypy apps/recorder/src && uv run python scripts/scan_sql_schema.py --db-kind vision --forbid profile,identity,memory,conversation,credential,ip,mac,path,filename`
Expected: PASS; each crash settles into one playable exact file or one unavailable/tombstoned row, never an orphan or false claim.

- [ ] **Step 5: Commit**

~~~bash
git add apps/recorder/src/tuntun_recorder/catalog apps/recorder/src/tuntun_recorder/recording/reconciliation.py apps/recorder/tests/integration/test_catalog_migrations.py apps/recorder/tests/integration/test_media_commit_crash.py apps/recorder/tests/security/test_catalog_schema_isolation.py
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
- Modify: `apps/core/src/tuntun_core/features/manifest.py`
- Create: `tests/contract/vision/test_ipc_boundary.py`
- Create: `tests/security/vision/test_process_import_boundary.py`
- Create: `tests/security/vision/test_selected_frame_absent.py`
- Create: `tests/security/vision/test_vision_feature_absence.py`

**Interfaces:** Produces authenticated bounded `VisionIpcEnvelopeV1` framing across the closed `core`/`camera_source`/`recorder`/`media_proxy` peer and message-direction matrix, `DarwinPeerCredentialVerifier`, video-to-core `CameraOutcomePort` client, core-to-video grant/control client, and feature IDs `camera_storage`, `camera_alerts`, `anonymous_presence`, and `selected_frame_perception`. Only accepted features register routes; selected-frame remains `absent`.

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
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/vision/test_ipc_boundary.py tests/security/vision/test_process_import_boundary.py tests/security/vision/test_selected_frame_absent.py tests/security/vision/test_vision_feature_absence.py -q`
Expected: FAIL because IPC and Phase 3 feature declarations do not exist.

- [ ] **Step 3: Implement length-prefixed IPC, peer checks, import rules, and fail-closed feature registration**

~~~python
HEADER = struct.Struct("!4sHII")
MAGIC = b"TVI1"
MAX_BODY = 64 * 1024

async def receive(
    reader: asyncio.StreamReader, peer: PeerIdentity,
) -> VisionIpcEnvelopeV1[VisionIpcPayloadV1]:
    raw = await reader.readexactly(HEADER.size)
    magic, version, body_len, sequence = HEADER.unpack(raw)
    if magic != MAGIC or version != 1 or body_len > MAX_BODY:
        raise IpcRejected("ipc_header_rejected")
    await peer_verifier.require_registered(peer)
    body = await asyncio.wait_for(reader.readexactly(body_len), timeout=1.0)
    wire = reject_duplicate_keys(body)
    message_type = require_closed_ipc_message_type(wire)
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

`IPC_ENVELOPE_ADAPTERS` is an exhaustive map from the closed message enum to an exact `VisionIpcEnvelopeV1[PayloadModel]` specialization; route peeking selects a validator but grants no authority. `verify_and_claim_once` calls `validate_vision_ipc_envelope_binding` and atomically verifies the canonical payload digest/HMAC, both live process-registration generations, direction, header/body sequence, deadline, and unused envelope ID before advancing the peer sequence. Add a dependency-rule check: `apps/recorder` and `integrations/reolink` may import contracts/testing only, never core internals; core vision modules never import recorder/reolink internals. IPC sockets are `0600` in owner-only runtime directories. No frame/media bytes are accepted on the metadata channel.

- [ ] **Step 4: Run green, route/package absence, and import graph checks**

Run: `uv run pytest tests/contract/vision/test_ipc_boundary.py tests/security/vision/test_process_import_boundary.py tests/security/vision/test_selected_frame_absent.py tests/security/vision/test_vision_feature_absence.py -q && uv run python scripts/check_import_boundaries.py --domain vision && uv run python scripts/check_feature_absence.py --feature selected_frame_perception --phase 3 && uv run ruff check apps/recorder/src/tuntun_recorder/ipc apps/recorder/src/tuntun_recorder/config.py apps/core/src/tuntun_core/features/manifest.py tests/contract/vision tests/security/vision && uv run mypy apps/recorder/src apps/core/src`
Expected: PASS; selected-frame route/API/config/container/dependency/client bundle is absent while its schema files remain available for Phase 5.

- [ ] **Step 5: Commit**

~~~bash
git add apps/recorder/src/tuntun_recorder/ipc apps/recorder/src/tuntun_recorder/config.py apps/core/src/tuntun_core/features/manifest.py tests/contract/vision/test_ipc_boundary.py tests/security/vision/test_process_import_boundary.py tests/security/vision/test_selected_frame_absent.py tests/security/vision/test_vision_feature_absence.py
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

**Interfaces:** Consumes owner-prepared mutation/passkey grants, Phase 2 `TopologyRegistryPort`, current privacy generation, camera probe digests, and content-safe evidence digests. Produces `CameraCommissioningService.prepare/approve/disable`, immutable `CameraCommissioningGeneration`, `AreaCameraPrivacyPolicy`, and owner-safe inventory projections. It never accepts a room display label where `area_id` is required.

- [ ] **Step 1: Write red exact-scope, prohibited-area, and drift invalidation tests**

~~~python
async def test_approve_binds_exact_unit_area_zones_copies_and_evidence(service, owner_passkey) -> None:
    prepared = await service.prepare(synthetic_trackmix_commissioning())
    receipt = await service.approve(prepared.id, owner_passkey.for_binding(prepared.binding))
    assert receipt.camera_binding_generation == 1
    assert receipt.area_id == "area_common_synth_01"
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
            if area.room_class != "common":
                raise PolicyDenied("camera_area_prohibited")
            self._validator.require_exact_evidence(prepared)
            generation = await self._repo.install_generation(prepared, uow)
            await self._audit.append_commitment("camera.commission.approve", generation.commitment(), uow)
            await self._grants.consume(grant, uow)
            return generation.to_receipt()
~~~

The inventory command records three distinct pseudonymous physical records with exact model/revision/firmware/config, source protocols, stream roles/codecs/rates, native event classes, audio controls, microSD/vendor/cloud copies, reset/update behavior, simultaneous-stream limit, placement/visible-field commitments, canonical `area_id`, versioned zones, notice state, source/capability/policy generations, and evidence digest. It writes no raw frame: the owner reviews a live local sample outside evidence, and the record retains only its digest plus pass/fail. Firmware, reset, source path, orientation, mount, privilege-changing credential rotation, area/zone mutation, or capability drift increments the generation and atomically disables downstream eligibility.

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
- Create: `docs/operations/phase3-network-egress.md`
- Test: `apps/recorder/tests/unit/test_source_eligibility.py`
- Test: `tests/security/vision/test_camera_destination_guard.py`
- Test: `tests/security/vision/test_camera_egress_evidence.py`
- Test: `tests/security/vision/test_public_camera_surface.py`

**Interfaces:** Produces `CameraSourceEligibility.evaluate(evidence) -> EligibleLocalSource | IneligibleVendorNativeOnly`, `CameraDestinationGuard.open`, and a sanitized egress evidence receipt. Consumes exact commissioned binding generation, inner-LAN destination commitments, allowed local NTP endpoint where configured, device-side cloud/UID/P2P state, router-boundary capture digest, and credential-handle ID.

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
git add apps/recorder/src/tuntun_recorder/source/eligibility.py apps/recorder/src/tuntun_recorder/source/credentials.py scripts/phase3/verify_camera_egress.py docs/operations/phase3-network-egress.md apps/recorder/tests/unit/test_source_eligibility.py tests/security/vision/test_camera_destination_guard.py tests/security/vision/test_camera_egress_evidence.py tests/security/vision/test_public_camera_surface.py
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
- Create: `docs/operations/phase3-trackmix-privacy.md`
- Create: `docs/evidence/phase3-trackmix-arc-schema.json`
- Test: `tests/contract/vision/test_trackmix_arc_evidence.py`
- Test: `tests/acceptance/vision/test_trackmix_arc_gate.py`
- Test: `tests/security/vision/test_tracking_absence_on_failure.py`

**Interfaces:** Produces a content-safe `TrackMixArcEvidenceV1` and one of `fixed_wide_eligible`, `digital_tracking_eligible`, `physical_tracking_eligible`, or `camera_excluded`. It consumes owner-observed live tests but persists only mode/reset/lighting/traversal counts, target visibility Boolean, control survival, timestamps, build/config digest, and evidence hashes.

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
            assert sum(
                trial.traversal_count
                for trial in arc_evidence.trials
                if trial.doorway == doorway and trial.motion_mode == mode
            ) >= 30
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
- Create: `integrations/reolink/src/tuntun_reolink/adapter.py`
- Create: `integrations/reolink/src/tuntun_reolink/capabilities.py`
- Create: `integrations/reolink/src/tuntun_reolink/direct.py`
- Create: `integrations/reolink/src/tuntun_reolink/native_events.py`
- Create: `integrations/reolink/src/tuntun_reolink/bridge.py`
- Create: `integrations/reolink/src/tuntun_reolink/clock.py`
- Create: `integrations/reolink/src/tuntun_reolink/sanitized_errors.py`
- Create: `apps/recorder/src/tuntun_recorder/source/service.py`
- Create: `apps/recorder/src/tuntun_recorder/source/relay.py`
- Create: `scripts/phase3/probe_reolink.py`
- Create: `docs/operations/phase3-e1-source-gate.md`
- Test: `integrations/reolink/tests/test_capability_probe.py`
- Test: `integrations/reolink/tests/test_direct_source.py`
- Test: `integrations/reolink/tests/test_native_events.py`
- Test: `integrations/reolink/tests/test_bridge_absence.py`
- Test: `tests/hardware/vision/test_reolink_units.py`

**Interfaces:** Implements `CameraSourcePort` for positively proved direct local streams/native events and defines an unregistered bridge adapter for a future separately procured hub/NVR. Produces one `CameraCapabilityEvidenceV1` per physical unit and read-only low-wide/event-wide/conditional-event-tracking relays. It exposes no PTZ, talkback, microphone, snapshot, cloud, face, playback, or camera-administration operation.

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

Run: `uv run pytest integrations/reolink/tests/test_capability_probe.py integrations/reolink/tests/test_direct_source.py integrations/reolink/tests/test_native_events.py integrations/reolink/tests/test_bridge_absence.py -q`
Expected: FAIL because `tuntun_reolink` is absent.

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

- [ ] **Step 4: Run green, hostile-source tests, and marker-gated probe dry run**

Run: `uv run pytest integrations/reolink/tests apps/recorder/tests -q && uv run pytest tests/hardware/vision/test_reolink_units.py --collect-only -q && uv run python scripts/phase3/probe_reolink.py --synthetic fixtures/synthetic/vision/reolink-probe.json --output var/evidence/phase3/synthetic-reolink.json && uv run python scripts/verify_private_data.py var/evidence/phase3/synthetic-reolink.json && uv run ruff check integrations/reolink apps/recorder/src/tuntun_recorder/source scripts/phase3/probe_reolink.py tests/hardware/vision && uv run mypy integrations/reolink/src apps/recorder/src`
Expected: PASS; the two E1 fixtures retain independent outcomes, unsupported routes stay absent, and no error/output contains an address or credential.

- [ ] **Step 5: Commit**

~~~bash
git add integrations/reolink apps/recorder/src/tuntun_recorder/source/service.py apps/recorder/src/tuntun_recorder/source/relay.py scripts/phase3/probe_reolink.py docs/operations/phase3-e1-source-gate.md tests/hardware/vision/test_reolink_units.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(reolink): add exact-capability local source adapters"
~~~

### Task 10: Qualify the encrypted SSD boundary and install least-privilege launchd services

**Depends on:** Tasks 04–05.
**Gate contribution:** P3-0 storage/process prerequisite.
**Estimated effort:** 1.5 person-days plus cold-boot/power checks.

**Files:**
- Create: `apps/recorder/src/tuntun_recorder/volume.py`
- Create: `scripts/phase3/qualify_video_volume.py`
- Create: `ops/launchd/phase3/com.tuntun.camera-source.plist`
- Create: `ops/launchd/phase3/com.tuntun.recorder.plist`
- Create: `ops/launchd/phase3/com.tuntun.media-proxy.plist`
- Create: `docs/operations/phase3-video-volume.md`
- Create: `docs/operations/phase3-recorder.md`
- Test: `apps/recorder/tests/unit/test_volume_gate.py`
- Test: `apps/recorder/tests/integration/test_mount_substitution.py`
- Test: `tests/security/vision/test_launchd_separation.py`
- Test: `tests/hardware/vision/test_video_volume.py`

**Interfaces:** Produces `VideoVolumeGate.open(expected_uuid, expected_root) -> VideoVolumeHandle`, a read-only qualification report, and three launchd service definitions. Consumes the existing owner-created APFS encrypted `TUNTUN_VIDEO` and separate `HA_BACKUPS` volume/quota; it never formats, erases, repartitions, or silently creates a volume.

- [ ] **Step 1: Write red encryption, UUID, ownership, root-fallback, and process-entitlement tests**

~~~python
@pytest.mark.parametrize("mutation", ["unencrypted", "wrong_uuid", "read_only", "wrong_owner", "unexpected_filesystem", "root_disk_symlink"])
def test_volume_gate_blocks_unsafe_mount(volume_gate, qualified_volume, mutation) -> None:
    with pytest.raises(VolumeIneligible):
        volume_gate.open(qualified_volume.mutate(mutation))

def test_recorder_never_falls_back_when_video_volume_disappears(recorder, volume) -> None:
    volume.disconnect()
    recorder.write_next_segment()
    assert recorder.health.storage_state == "write_blocked"
    assert not recorder.mac_root_written()
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/recorder/tests/unit/test_volume_gate.py apps/recorder/tests/integration/test_mount_substitution.py tests/security/vision/test_launchd_separation.py -q`
Expected: FAIL because `VideoVolumeGate` and Phase 3 launchd definitions are absent.

- [ ] **Step 3: Implement the volume gate, account matrix, and non-destructive qualification**

~~~python
def open(self, expected: ExpectedVideoVolume) -> VideoVolumeHandle:
    observed = self._probe.inspect(expected.mount_point)
    if observed.volume_uuid != expected.volume_uuid or observed.filesystem != "apfs":
        raise VolumeIneligible("video_volume_identity_mismatch")
    if not observed.encrypted or observed.read_only or observed.owner_uid != expected.recorder_uid:
        raise VolumeIneligible("video_volume_protection_failed")
    root = observed.mount_point.resolve()
    if root == Path("/") or root.stat().st_dev == Path("/").stat().st_dev:
        raise VolumeIneligible("video_volume_root_fallback_forbidden")
    return VideoVolumeHandle(root=root, volume_uuid=observed.volume_uuid)
~~~

The qualification records exact SSD/enclosure/firmware, nominal/usable capacity, APFS encryption, volume/quota identity, SMART/endurance visibility, sustained write, temperature, cable flap/reconnect, wrong mount, cold-boot unlock, FileVault/Keychain behavior, recorder-user ownership, `HA_BACKUPS` separation, Time Machine/cloud-sync/Spotlight exclusion, and sleep policy. The source account gets local camera network plus its Keychain namespace and no video mount; recorder gets `TUNTUN_VIDEO`/catalog and IPC but no camera/provider/core/HA keys or LAN listener; media proxy gets read-only media/catalog and its Unix socket. The script defaults to inspect-only; its write probe requires `TUNTUN_ALLOW_VIDEO_VOLUME=1` and writes one bounded synthetic file beneath the already qualified video root.

- [ ] **Step 4: Run green, plist lint, and marker-gated collection**

Run: `uv run pytest apps/recorder/tests/unit/test_volume_gate.py apps/recorder/tests/integration/test_mount_substitution.py tests/security/vision/test_launchd_separation.py -q && plutil -lint ops/launchd/phase3/*.plist && uv run python scripts/phase3/qualify_video_volume.py --synthetic fixtures/synthetic/vision/volume-qualified.json --output var/evidence/phase3/synthetic-volume.json && uv run pytest tests/hardware/vision/test_video_volume.py --collect-only -q && uv run ruff check apps/recorder/src/tuntun_recorder/volume.py scripts/phase3/qualify_video_volume.py tests/security/vision tests/hardware/vision && uv run mypy apps/recorder/src`
Expected: PASS; launchd definitions expose no credential/address, wrong/missing volume blocks writes, and voice/core/Green paths remain available.

- [ ] **Step 5: Commit**

~~~bash
git add apps/recorder/src/tuntun_recorder/volume.py scripts/phase3/qualify_video_volume.py ops/launchd/phase3 docs/operations/phase3-video-volume.md docs/operations/phase3-recorder.md apps/recorder/tests/unit/test_volume_gate.py apps/recorder/tests/integration/test_mount_substitution.py tests/security/vision/test_launchd_separation.py tests/hardware/vision/test_video_volume.py
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
- Create: `apps/recorder/tests/integration/test_media_handle.py`
- Create: `apps/recorder/tests/security/test_recorder_has_no_camera_secret.py`
- Create: `apps/recorder/tests/fault/test_source_backpressure.py`
- Create: `apps/recorder/tests/fault/test_credential_rotation.py`

**Interfaces:** Produces a single-generation `ReadOnlyMediaHandle` backed by a bounded Unix-domain stream/file descriptor. The handle exposes only request/opaque relay IDs, exact camera-binding and capability generation/digest, stream role, codec/dimensions, sequence/time base, proved byte/packet bounds, and its five-second attach deadline; it contains no address, URL, username, secret, vendor account, or administrative operation.

- [ ] **Step 1: Write red secret-isolation, backpressure, stale-handle, and rotation tests**

~~~python
async def test_recorder_receives_no_camera_endpoint_or_credential(media_handle_fixture) -> None:
    handle = await media_handle_fixture.source.open_stream(media_handle_fixture.request)
    serialized = handle.model_dump_json()
    assert media_handle_fixture.camera_address not in serialized
    assert media_handle_fixture.secret not in serialized
    assert media_handle_fixture.recorder.keychain_items() == ()

async def test_rotation_closes_old_stream_and_requires_new_generation(media_handle_fixture) -> None:
    old = await media_handle_fixture.open()
    await media_handle_fixture.rotate_credential()
    assert await old.read() == b""
    with pytest.raises(StaleGeneration):
        await media_handle_fixture.recorder.attach(old)
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/recorder/tests/integration/test_media_handle.py apps/recorder/tests/security/test_recorder_has_no_camera_secret.py apps/recorder/tests/fault/test_source_backpressure.py apps/recorder/tests/fault/test_credential_rotation.py -q`
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

Run: `uv run pytest apps/recorder/tests/integration/test_media_handle.py apps/recorder/tests/security/test_recorder_has_no_camera_secret.py apps/recorder/tests/fault/test_source_backpressure.py apps/recorder/tests/fault/test_credential_rotation.py -q && uv run python scripts/scan_process_artifacts.py --process tuntun-recorder --forbid credential,url,address,vendor_account && uv run ruff check apps/recorder/src/tuntun_recorder/source apps/recorder/src/tuntun_recorder/recording/ingest.py apps/recorder/tests && uv run mypy apps/recorder/src`
Expected: PASS; bounded overload yields a truthful gap and zero secret/address in recorder arguments, environment, config, logs, crash fixture, or catalog.

- [ ] **Step 5: Commit**

~~~bash
git add apps/recorder/src/tuntun_recorder/source/service.py apps/recorder/src/tuntun_recorder/source/relay.py apps/recorder/src/tuntun_recorder/source/credentials.py apps/recorder/src/tuntun_recorder/recording/ingest.py apps/recorder/tests/integration/test_media_handle.py apps/recorder/tests/security/test_recorder_has_no_camera_secret.py apps/recorder/tests/fault/test_source_backpressure.py apps/recorder/tests/fault/test_credential_rotation.py
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
- Modify: `apps/recorder/src/tuntun_recorder/catalog/repository.py`
- Create: `apps/recorder/tests/unit/test_segment_boundaries.py`
- Create: `apps/recorder/tests/integration/test_stream_copy.py`
- Create: `apps/recorder/tests/security/test_audio_rejection.py`
- Create: `apps/recorder/tests/security/test_hostile_media_bounds.py`

**Interfaces:** Implements `RecorderPort.start` for `low_wide` only and produces 60-second `continuous_7d` `SegmentV1` rows through `MediaCommitter`. Consumes a `ReadOnlyMediaHandle` and qualified volume. No input stream can choose a destination filename/path/container command.

- [ ] **Step 1: Write red segment duration, stream-copy, and double audio rejection tests**

~~~python
async def test_low_wide_segments_are_stream_copy_and_sixty_seconds(recorder, low_wide_fixture) -> None:
    segments = await recorder.record_for(low_wide_fixture, seconds=181)
    assert [s.ended_at - s.started_at for s in segments[:3]] == [timedelta(seconds=60)] * 3
    assert all(s.retention_class == "continuous_7d" for s in segments)
    assert all(await recorder.probe(s).decode_count == 0 for s in segments)

async def test_audio_present_source_is_rejected_before_published_segment(recorder, audio_fixture) -> None:
    with pytest.raises(SourceIneligible, match="camera_audio_present"):
        await recorder.start(audio_fixture.binding, audio_fixture.profile)
    assert await recorder.catalog.count_published() == 0
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/recorder/tests/unit/test_segment_boundaries.py apps/recorder/tests/integration/test_stream_copy.py apps/recorder/tests/security/test_audio_rejection.py apps/recorder/tests/security/test_hostile_media_bounds.py -q`
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

Run: `uv run pytest apps/recorder/tests/unit/test_segment_boundaries.py apps/recorder/tests/integration/test_stream_copy.py apps/recorder/tests/security/test_audio_rejection.py apps/recorder/tests/security/test_hostile_media_bounds.py -q && uv run python scripts/fuzz_media_parser.py --corpus fixtures/adversarial/vision --max-cases 5000 --assert-no-decode --assert-no-audio-output && uv run ruff check apps/recorder/src/tuntun_recorder/recording apps/recorder/src/tuntun_recorder/media_probe.py apps/recorder/tests && uv run mypy apps/recorder/src`
Expected: PASS; every published test segment has one video/no audio, routine decode count zero, bounded resources, exact duration metadata, and no path/error leak.

- [ ] **Step 5: Commit**

~~~bash
git add apps/recorder/src/tuntun_recorder/recording/segmenter.py apps/recorder/src/tuntun_recorder/recording/service.py apps/recorder/src/tuntun_recorder/media_probe.py apps/recorder/src/tuntun_recorder/catalog/repository.py apps/recorder/tests/unit/test_segment_boundaries.py apps/recorder/tests/integration/test_stream_copy.py apps/recorder/tests/security/test_audio_rejection.py apps/recorder/tests/security/test_hostile_media_bounds.py
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
    detector.observe(complete_segment(end=fake_clock.now()))
    fake_clock.advance(seconds=6)
    detector.tick()
    fake_clock.advance(seconds=24)
    assert detector.health().current_gap_seconds >= 30
    assert detector.health().health_reason_codes == ("segment_gap",)

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
    expected = self._last_complete_mono + self._profile.segment_seconds
    gap = max(0, floor(now_mono - expected))
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
- Test: `apps/recorder/tests/integration/test_trackmix_dual_view.py`

**Interfaces:** Produces strict `CrossDomainEventV1[CameraSecurityEventV1]`, a maximum-60-second full-resolution transient ring, and one wide or wide-plus-tracking `ClipV1`. Consumes only compiled native detector mappings and the exact current area/zone/binding/capability/privacy generations.

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
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest apps/recorder/tests/unit/test_event_normalizer.py apps/recorder/tests/unit/test_event_dedupe.py apps/recorder/tests/integration/test_event_promotion.py apps/recorder/tests/integration/test_trackmix_dual_view.py -q`
Expected: FAIL because event normalizer/ring/promotion modules are absent.

- [ ] **Step 3: Implement closed native mapping, dedupe, clock gate, ring, and promotion**

~~~python
async def normalize(self, native: NativeCameraEventV1) -> CameraSecurityEventV1:
    binding = await self._bindings.require_current_source(
        source_endpoint_id=native.source_endpoint_id,
        source_endpoint_generation=native.source_endpoint_generation,
        camera_binding_id=native.camera_binding_id,
        camera_binding_generation=native.camera_binding_generation,
        capability_generation=native.capability_generation,
    )
    event_class = binding.compiled_native_event_map.get(native.detector_code, "unknown")
    zone = await self._zones.require_same_generation(binding, native.zone_id, native.zone_generation)
    privacy = await self._privacy.require_current(binding.area_id, zone.zone_id)
    clock = self._clock.classify(native.observed_at, self._clock.now())
    if clock == "untrusted":
        raise EventQuarantined("camera_clock_untrusted")
    return CameraSecurityEventV1(
        event_id=native.native_event_id,
        camera_binding_id=binding.id, camera_binding_generation=binding.generation,
        capability_generation=native.capability_generation,
        area_id=binding.area_id, zone_id=zone.zone_id, zone_generation=zone.zone_generation, event_class=event_class,
        detector_basis=binding.detector_basis, detector_version=binding.detector_version,
        started_at=native.started_at, ended_at=native.ended_at,
        confidence_band=native.confidence_band,
        verification="native", clock_quality=clock, clip_ref=None,
        view_set="wide", privacy_policy_version=privacy.policy_version,
        privacy_generation=privacy.privacy_generation,
    )
~~~

Keep a full-resolution wide ring no longer than 60 seconds; destroy unpromoted fragments within the cleanup bound. Accepted events promote up to 10 seconds before, continue 30 seconds after the last accepted update, cap one clip at five minutes, and coalesce overlaps for the same camera/zone into bounded `clip_event_refs`. The optional tracking ring/promotion runs only when the full dual-view gate is current; alignment must be ≤2 seconds. Catalog/UI labels each view separately and never asserts atomicity across files. An untrusted clock may still preserve raw recorder time metadata but cannot create an alert/presence event.

- [ ] **Step 4: Run green and replay/reorder/flood matrix**

Run: `uv run pytest apps/recorder/tests/unit/test_event_normalizer.py apps/recorder/tests/unit/test_event_dedupe.py apps/recorder/tests/integration/test_event_promotion.py apps/recorder/tests/integration/test_trackmix_dual_view.py -q && uv run pytest tests/property/vision/test_event_replay_reorder.py -q && uv run ruff check apps/recorder/src/tuntun_recorder/events apps/recorder/src/tuntun_recorder/recording/event_ring.py apps/recorder/src/tuntun_recorder/recording/promotion.py apps/recorder/tests && uv run mypy apps/recorder/src`
Expected: PASS; no duplicate/replayed/reordered/flooded event extends the ring, duplicates media, or crosses an invalid binding; tracking failure leaves wide-only.

- [ ] **Step 5: Commit**

~~~bash
git add apps/recorder/src/tuntun_recorder/events apps/recorder/src/tuntun_recorder/recording/event_ring.py apps/recorder/src/tuntun_recorder/recording/promotion.py apps/recorder/src/tuntun_recorder/catalog/repository.py apps/recorder/tests/unit/test_event_normalizer.py apps/recorder/tests/unit/test_event_dedupe.py apps/recorder/tests/integration/test_event_promotion.py apps/recorder/tests/integration/test_trackmix_dual_view.py tests/property/vision/test_event_replay_reorder.py
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

**Interfaces:** Produces `StoragePressurePolicy.decide(free_fraction)`, `RecordingAdmission`, `WorkloadGovernor`, and capacity/health measurements. It consumes qualified-volume usable bytes, catalog integrity, active voice priority, and Phase 2 backup window state.

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

At 10–15%, finish the current continuous segment, stop admission, and open an explicit gap while still attempting event clips. Below 10% or on read-only/mount/catalog uncertainty, stop all writes and preserve existing media. Never shrink retention. CPU/I/O controls bound recorder concurrency; voice capture/TTS playback preempts on-demand transcode; Green backup has an explicit I/O window/reserve. Record peak CPU/RAM/disk/network/temperature and first-audio/backup deltas.

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
- Create: `apps/recorder/tests/fault/test_transcode_cleanup.py`

**Interfaces:** Produces `PlaybackBroker.prepare_range(...) -> SignedMediaPlaybackGrantV1`, `MediaGrantVerifier.consume`, same-origin `GET /api/v1/media/{opaque_grant_id}`, and an optional bounded `PlaybackTranscoder`. The signed envelope carries the frozen grant, algorithm, key ID, and base64url signature; the proxy verifies domain-separated canonical grant bytes before reading any grant field. It consumes current owner session/assurance policy, exact clip/view/range, privacy generation, catalog integrity, and a domain-separated core public key pinned by key ID at the proxy.

- [ ] **Step 1: Write red actor/range/replay/expiry/path/privacy tests**

~~~python
@pytest.mark.parametrize("actor", ["second_adult", "k2_child", "n1_child", "designated_guest", "anonymous", "ha_user"])
async def test_non_owner_gets_indistinguishable_not_found(playback_api, actor, clip_id) -> None:
    response = await playback_api.as_actor(actor).prepare_range(clip_id, "wide", 0, 1023)
    assert response.status_code == 404
    assert response.json()["reason_code"] == "resource_unavailable"

@pytest.mark.parametrize("mutation", ["replay", "cross_clip", "cross_view", "edited_range", "wrong_session", "wrong_operation", "expired", "privacy_generation"])
async def test_mutated_or_replayed_grant_returns_no_bytes(media_proxy, valid_grant, mutation) -> None:
    response = await media_proxy.get(valid_grant.mutate(mutation))
    assert response.body == b""
    assert response.status_code in {401, 404, 409, 410}

def test_signed_grant_envelope_is_exact_and_tamper_evident(media_proxy, valid_signed_grant) -> None:
    assert set(SignedMediaPlaybackGrantV1.model_fields) == {
        "schema_id", "grant", "algorithm", "signing_key_id", "signature_b64url",
    }
    tampered = valid_signed_grant.model_copy(update={
        "grant": valid_signed_grant.grant.model_copy(update={"clip_id": uuid4()}),
    })
    result = media_proxy.verify_without_reading_media(tampered)
    assert result.reason_code == "media_grant_signature_invalid"
    assert result.bytes_read == 0
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/security/vision/test_playback_object_auth.py tests/security/vision/test_playback_grants.py tests/integration/vision/test_same_origin_playback.py apps/recorder/tests/fault/test_transcode_cleanup.py -q`
Expected: FAIL because playback broker/proxy routes are absent.

- [ ] **Step 3: Implement per-range single-use grants and bounded transcode**

~~~python
async def prepare_range(self, request: PlaybackRangeRequestV1, actor: ActorContext) -> SignedMediaPlaybackGrantV1:
    actor.require_owner()
    await self._privacy.require_camera_outcomes_eligible(
        expected_generation=request.expected_privacy_generation,
    )
    clip = await self._catalog_projection.require_owner_visible(request.clip_id)
    require(clip.clip_generation == request.expected_clip_generation)
    require(clip.catalog_generation == request.expected_catalog_generation)
    byte_range = request.byte_range.require_within(clip.view_size(request.view))
    now = self._clock.now()
    privacy_generation = await self._privacy.current_generation()
    grant = MediaPlaybackGrantV1(
        grant_id=uuid4(), owner_subject_id=actor.subject_id, owner_session_id=actor.session_id,
        clip_id=clip.clip_id, allowed_view=request.view, allowed_operation="playback",
        allowed_range_bytes=byte_range, issued_at=now, expires_at=now + timedelta(seconds=60),
        single_use=True, policy_version=actor.policy_version,
        privacy_generation=privacy_generation,
        parameter_commitment=self._commitments.for_playback(
            actor, clip, byte_range, privacy_generation,
        ),
    )
    signature = await self._signer.sign(
        domain="tuntun.media-playback-grant.v1",
        payload=canonical_vision_bytes(grant),
    )
    return SignedMediaPlaybackGrantV1(
        grant=grant,
        algorithm="Ed25519",
        signing_key_id=signature.key_id,
        signature_b64url=signature.value_b64url,
    )
~~~

The core never opens media. It authorizes one exact range, signs the domain-separated canonical `MediaPlaybackGrantV1`, sends the complete `SignedMediaPlaybackGrantV1` to the same-origin browser, and forwards it as the payload of a `media_playback_grant` `VisionIpcEnvelopeV1[SignedMediaPlaybackGrantV1]` addressed only from `core` to `media_proxy`. The proxy claims the IPC envelope, then resolves the pinned `signing_key_id` and verifies `algorithm`, domain, canonical grant bytes, and `signature_b64url`; an unknown key, malformed envelope, signature replay, or any grant-field mutation returns zero bytes. Only then does it validate session/clip/view/range/operation/policy/privacy/expiry, atomically record the canonical signed-envelope digest as consumed, resolve one opaque path beneath the fixed root, verify catalog/file integrity, and serve exact bytes with `Cache-Control: no-store`, `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, and no reusable URL. The player requests a new grant for each later range. If the browser cannot play the native codec, an explicit owner operation starts one lower-priority, audio-free transcode in an owner-only temporary root; active voice, privacy, cancellation, expiry, quota, or crash destroys it.

- [ ] **Step 4: Run green, route-origin scan, and transcode cleanup matrix**

Run: `uv run pytest tests/security/vision/test_playback_object_auth.py tests/security/vision/test_playback_grants.py tests/integration/vision/test_same_origin_playback.py apps/recorder/tests/fault/test_transcode_cleanup.py -q && uv run python scripts/scan_network_surface.py --expect-owner-api-only --forbid-media-proxy-lan --forbid-camera-ports && uv run python scripts/scan_browser_artifacts.py --forbid media_url,credential,stream_url,storage_path,reusable_token && uv run ruff check apps/core/src/tuntun_core/services/vision/playback_broker.py apps/recorder/src/tuntun_recorder/media apps/core/src/tuntun_core/api/routes/cameras.py apps/core/src/tuntun_core/api/vision_dtos.py tests/security/vision tests/integration/vision && uv run mypy apps/core/src apps/recorder/src`
Expected: PASS; owner local playback succeeds range by range; all other actors/origins and mutations receive zero bytes/existence detail; transcode leaves no durable cache.

- [ ] **Step 5: Commit**

~~~bash
git add apps/core/src/tuntun_core/services/vision/playback_broker.py apps/recorder/src/tuntun_recorder/media apps/core/src/tuntun_core/api/routes/cameras.py apps/core/src/tuntun_core/api/vision_dtos.py tests/security/vision/test_playback_object_auth.py tests/security/vision/test_playback_grants.py tests/integration/vision/test_same_origin_playback.py apps/recorder/tests/fault/test_transcode_cleanup.py
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
- Create: `packages/secure-archive/src/tuntun_secure_archive/__init__.py`
- Create: `packages/secure-archive/src/tuntun_secure_archive/writer.py`
- Modify: `apps/core/src/tuntun_core/services/data_lifecycle/backup_format.py`
- Create: `apps/recorder/src/tuntun_recorder/media/export.py`
- Modify: `apps/core/src/tuntun_core/services/vision/playback_broker.py`
- Create: `tests/integration/vision/test_clip_export_delete.py`
- Create: `tests/security/vision/test_export_encryption.py`
- Create: `tests/fault/vision/test_export_delete_transitions.py`
- Create: `tests/unit/vision/test_copy_disclosure.py`
- Create: `docs/operations/phase3-playback-export-delete.md`

**Interfaces:** Extracts the already-tested Phase 1 bounded recipient-encrypted archive primitive into `tuntun_secure_archive` without changing `TTBK1` behavior. Produces recorder-local `VisionExportWriter.write(clip, views, recipient_public_key)`, exact `camera.clip.export` and `camera.clip.delete` prepared operations, one-time ciphertext download, and `EffectiveCopyProjection`.

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
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/vision/test_clip_export_delete.py tests/security/vision/test_export_encryption.py tests/fault/vision/test_export_delete_transitions.py tests/unit/vision/test_copy_disclosure.py -q`
Expected: FAIL because shared secure archive extraction and vision export/delete services are absent.

- [ ] **Step 3: Extract the bounded writer and implement exact operations**

~~~python
async def export(self, request: ClipExportRequest, grant: ActionGrant) -> OneTimeCiphertext:
    grant.require_exact_binding(request.binding())
    clip = await self._catalog.require_integrity(request.clip_id, request.views)
    recipient = await self._recipients.require_public_only(request.recipient_id)
    job = await self._jobs.commit_authorized(request, grant)
    return await self._recorder_exports.write_encrypted(job, clip, recipient.public_key)

async def early_delete(self, request: ClipDeleteRequest, grant: ActionGrant) -> ClipDeleteReceipt:
    grant.require_exact_binding(request.binding_with_count_size_expiry())
    job = await self._jobs.commit_authorized(request, grant)
    return await self._recorder_deletes.execute_idempotent(job)
~~~

The shared writer keeps Phase 1's authenticated bounded-header/chunk/EOF/digest behavior and moves only reusable crypto/container code; its original backup tests must remain byte-compatible. The recorder process reads raw clip bytes and emits only recipient-encrypted ciphertext—raw media never enters core. The no-store one-time download is bound to the prepared operation and expires after first use. Early delete atomically blocks playback, verifies exact clip/view/count/size/expiry, unlinks through the retention journal, and leaves only an HMAC/content-minimized receipt. Show camera microSD, hub/NVR, SSD, vendor cloud, diagnostic copy, restore copy, and owner export as independent copy rows with separate authority/retention; never claim deletion outside Tuntun control.

- [ ] **Step 4: Run green, Phase 1 archive regression, and plaintext scan**

Run: `uv run pytest tests/integration/vision/test_clip_export_delete.py tests/security/vision/test_export_encryption.py tests/fault/vision/test_export_delete_transitions.py tests/unit/vision/test_copy_disclosure.py tests/unit/data_lifecycle/test_backup_format.py tests/property/test_backup_parser_fuzz.py -q && uv run python scripts/scan_export_artifacts.py --root var/test-artifacts --forbid-plaintext-sentinel --require-authenticated-ciphertext && uv run ruff check packages/secure-archive apps/recorder/src/tuntun_recorder/media/export.py apps/core/src/tuntun_core/services/data_lifecycle/backup_format.py apps/core/src/tuntun_core/services/vision/playback_broker.py tests/integration/vision tests/security/vision tests/fault/vision tests/unit/vision && uv run mypy packages/secure-archive/src apps/core/src apps/recorder/src`
Expected: PASS; Phase 1 archive behavior is unchanged, exports are ciphertext-only, delete is idempotent/crash-safe, and copy disclosure remains truthful.

- [ ] **Step 5: Commit**

~~~bash
git add packages/secure-archive apps/core/src/tuntun_core/services/data_lifecycle/backup_format.py apps/recorder/src/tuntun_recorder/media/export.py apps/core/src/tuntun_core/services/vision/playback_broker.py tests/integration/vision/test_clip_export_delete.py tests/security/vision/test_export_encryption.py tests/fault/vision/test_export_delete_transitions.py tests/unit/vision/test_copy_disclosure.py docs/operations/phase3-playback-export-delete.md
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

**Interfaces:** Produces an evidence-bound `P3OneCameraPilotReceipt` for the TrackMix fixed-wide path only. It consumes the exact clean build, commissioning/arc/egress/volume/capability digests, synthetic preflight, owner operator, and monotonic plus wall elapsed measurements.

- [ ] **Step 1: Write red evidence oracle and disabled-exit tests**

~~~python
def test_pilot_requires_two_elapsed_days_and_every_failure_case(verifier, receipt) -> None:
    assert receipt.monotonic_elapsed_seconds >= 172800
    assert receipt.wall_elapsed_seconds >= 172800
    assert set(receipt.failure_cases) == REQUIRED_ONE_CAMERA_FAILURE_CASES
    assert verifier.verify(receipt).decision == "p3_1_pass"

def test_ineligible_trackmix_cannot_be_silently_replaced_by_e1(verifier, receipt) -> None:
    receipt.primary_camera_class = "e1_family"
    assert verifier.verify(receipt).decision == "p3_1_blocked_trackmix_source"
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/acceptance/vision/test_one_camera_pilot_schema.py tests/acceptance/vision/test_one_camera_pilot_oracle.py tests/acceptance/vision/test_one_camera_disabled_exit.py -q`
Expected: FAIL because the pilot runner/verifier does not exist.

- [ ] **Step 3: Implement a non-bypassable campaign and semantic verifier**

The runner records audio-free low-wide segments, full-resolution ring/promotion, checksums, gaps, event timing, playback, encrypted export, early delete, exact retention simulation, crash/restart before and after each media transition, SSD disconnect/reconnect, wrong mount, camera/router/Mac restart, WAN off/restore, credential rotation, source/event split failures, clock skew/rollback, full-disk thresholds, Green backup contention, active voice latency, resource bounds, public/listener scan, egress capture digest, private-data sentinel scan, and selected-frame/identity/HA media/greeting/action negative reachability.

~~~python
def verify_p3_1(receipt: P3OneCameraPilotReceipt) -> PilotDecision:
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

- [ ] **Step 4: Freeze a clean build, run synthetic acceptance, then run the owner-gated pilot**

~~~bash
test -z "$(git status --porcelain)"
make check
make test-security
make verify-private-data
uv run python scripts/phase3/run_one_camera_pilot.py synthetic --commit "$(git rev-parse HEAD)" --output var/evidence/phase3/synthetic-one-camera.json
uv run python scripts/phase3/run_one_camera_pilot.py verify var/evidence/phase3/synthetic-one-camera.json --commit "$(git rev-parse HEAD)"
TUNTUN_ALLOW_ELAPSED_PHASE3=1 uv run python scripts/phase3/run_one_camera_pilot.py household --duration-seconds 172800 --sample-seconds 30 --commit "$(git rev-parse HEAD)" --output var/evidence/phase3/one-camera-pilot.json
uv run python scripts/phase3/run_one_camera_pilot.py verify var/evidence/phase3/one-camera-pilot.json --commit "$(git rev-parse HEAD)" --require-physical
uv run python scripts/verify_private_data.py var/evidence/phase3
~~~

Expected: synthetic verification passes first; physical elapsed is at least 172,800 seconds by both clocks; stored audio/unapproved egress/unauthorized copy/identity/model/HA media/greeting/action routes and duplicate/false-complete outcomes are zero. A failure leaves P3-1 blocked and opens a source/placement decision; it does not silently use an E1 or purchase a bridge.

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
- Create: `tests/acceptance/vision/test_partial_camera_truth.py`

**Interfaces:** Produces `StorageMeasurementV1` per camera/view/day, `CapacityProjectionV1`, and `P3CapacityDecision`. Consumes only cameras whose exact source/egress/audio/area/zone/privacy generations pass. An ineligible E1 remains separately visible and contributes zero bytes—not a guessed bitrate—to the central-retention claim.

- [ ] **Step 1: Write red exact formula, reserve, coverage, and partial-source tests**

~~~python
def test_capacity_uses_worst_daily_continuous_and_event_rule(measurements) -> None:
    projection = project_capacity(measurements)
    expected_policy = (
        7 * sum(m.max_complete_continuous_24h for m in measurements.streams)
        + ceil_decimal(90 * sum(max(m.max_event_24h, Decimal("1.5") * m.mean_event_7d) for m in measurements.streams))
        + measurements.catalog_filesystem_overhead
    )
    assert projection.policy_bytes == expected_policy
    assert projection.required_usable_capacity == (5 * expected_policy + 3) // 4

def test_ineligible_e1_is_reported_partial_not_estimated(campaign) -> None:
    result = campaign.with_camera("e1_synth_b", disposition="inventory_only").project()
    assert result.camera_results["e1_synth_b"].central_recording == "unavailable"
    assert result.camera_results["e1_synth_b"].estimated_bytes is None
    assert result.claim == "partial_eligible_camera_set"
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/vision/test_capacity_formula.py tests/acceptance/vision/test_capacity_campaign_schema.py tests/acceptance/vision/test_capacity_campaign_oracle.py tests/acceptance/vision/test_partial_camera_truth.py -q`
Expected: FAIL because the final capacity projection/campaign verifier is absent.

- [ ] **Step 3: Implement exact daily buckets, projections, and semantic gate**

~~~python
def project_capacity(run: SevenDayMeasurements) -> CapacityProjectionV1:
    continuous = sum(stream.maximum_complete_bucket(timedelta(hours=24)) for stream in run.streams)
    events = sum(max(stream.maximum_event_bucket(timedelta(hours=24)), Decimal("1.5") * stream.mean_event_per_day) for stream in run.streams)
    continuous_policy_bytes = 7 * continuous
    event_policy_bytes = ceil_decimal(90 * events)
    policy_bytes = continuous_policy_bytes + event_policy_bytes + run.measured_catalog_and_filesystem_overhead
    required = (5 * policy_bytes + 3) // 4
    claim = "partial_eligible_camera_set" if run.ineligible_camera_count else "complete_eligible_camera_set"
    return CapacityProjectionV1(
        projection_id=uuid4(),
        projection_generation=run.projection_generation,
        campaign_id=run.campaign_id,
        measurement_ids=tuple(measurement.measurement_id for measurement in run.measurements),
        volume_qualification_generation=run.volume_qualification_generation,
        catalog_generation=run.catalog_generation,
        privacy_generation=run.privacy_generation,
        eligible_camera_count=run.eligible_camera_count,
        ineligible_camera_count=run.ineligible_camera_count,
        campaign_started_at=run.started_at,
        campaign_ended_at=run.ended_at,
        continuous_policy_bytes=continuous_policy_bytes,
        event_policy_bytes=event_policy_bytes,
        measured_catalog_and_filesystem_overhead=run.measured_catalog_and_filesystem_overhead,
        policy_bytes=policy_bytes,
        reserve_basis_points=2000,
        required_usable_capacity=required,
        usable_capacity=run.usable_capacity,
        minimum_coverage_ratio=run.minimum_coverage_ratio,
        longest_gap_detection_seconds=run.longest_gap_detection_seconds,
        voice_p95_seconds=run.voice_p95_seconds,
        voice_regression_percent=run.voice_regression_percent,
        stored_audio_stream_count=0,
        selected_view_set=tuple(sorted(run.selected_view_set)),
        claim=claim,
        decision=classify_p3_2(run, required, claim),
        projected_at=run.projected_at,
        valid_until=run.projected_at + timedelta(days=90),
        measurement_digest=run.measurement_digest,
        reason_codes=run.safe_reason_codes,
    )
~~~

The verifier reloads every declared `StorageMeasurementV1`, rejects a missing/duplicate ID or campaign mismatch, recomputes the measurement digest and formula, and compares all current binding/capability/profile/source-eligibility/egress/volume/catalog/zone/privacy generations plus trusted time before accepting the projection. Run all eligible cameras at final intended stream/event/night settings for seven representative consecutive days during normal Tuntun voice use and Green backups. Record complete bytes, event duty, highest 15-minute rate, segment coverage/gaps/corruption, Wi-Fi loss, clock skew, SSD health/temperature, CPU/RAM/network, first-audio regression, backup timing, disconnect/reconnect, camera/router/Mac reboot, event-channel loss, full-disk thresholds, and conditional TrackMix wide-plus-tracking separately. Require `usable_capacity >= required_usable_capacity`, ≥99.5% coverage per eligible camera, every >5-second gap visible within 30 seconds, voice ≤4 seconds and ≤10% regression, and current Green objectives. A failure never shrinks 7/90; it opens the storage/source decision with evidence.

- [ ] **Step 4: Run green, synthetic seven-day oracle, then owner-gated elapsed campaign**

~~~bash
uv run pytest tests/unit/vision/test_capacity_formula.py tests/acceptance/vision/test_capacity_campaign_schema.py tests/acceptance/vision/test_capacity_campaign_oracle.py tests/acceptance/vision/test_partial_camera_truth.py -q
uv run python scripts/phase3/run_capacity_campaign.py synthetic --days 7 --output var/evidence/phase3/synthetic-capacity.json
uv run python scripts/phase3/run_capacity_campaign.py verify var/evidence/phase3/synthetic-capacity.json
TUNTUN_ALLOW_ELAPSED_PHASE3=1 uv run python scripts/phase3/run_capacity_campaign.py household --duration-seconds 604800 --sample-seconds 60 --commit "$(git rev-parse HEAD)" --output var/evidence/phase3/capacity.json
uv run python scripts/phase3/run_capacity_campaign.py verify var/evidence/phase3/capacity.json --commit "$(git rev-parse HEAD)" --require-physical
uv run python scripts/verify_private_data.py var/evidence/phase3
~~~

Expected: software/synthetic checks pass first; physical elapsed is at least 604,800 seconds; every camera has an exact eligible or absent result; no vendor estimate substitutes for bytes; all thresholds are recomputed by the verifier.

- [ ] **Step 5: Commit tooling before the physical run; never commit owner evidence**

~~~bash
git add apps/recorder/src/tuntun_recorder/capacity.py scripts/phase3/run_capacity_campaign.py docs/evidence/phase3-capacity-schema.json tests/unit/vision/test_capacity_formula.py tests/acceptance/vision/test_capacity_campaign_schema.py tests/acceptance/vision/test_capacity_campaign_oracle.py tests/acceptance/vision/test_partial_camera_truth.py
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
- Modify: `packages/contracts/src/tuntun_contracts/vision/ui.py`
- Modify: `packages/contracts/openapi/admin-v1.yaml`
- Modify: `apps/admin/src/api/generated/admin-v1.ts`
- Create: `tests/contract/api/test_vision_openapi.py`
- Create: `tests/integration/api/test_camera_read_routes.py`
- Create: `tests/security/vision/test_camera_read_authorization.py`

**Interfaces:** Produces bounded owner-only endpoints `GET /api/v1/ui/cameras/overview`, `/inventory`, `/recordings`, `/storage`, and `/privacy-map` with opaque cursors, per-fact freshness, and safe reason codes. It consumes only metadata projections over authenticated IPC—never media paths/bytes or camera credentials.

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

Run: `uv run pytest tests/contract/api/test_vision_openapi.py tests/integration/api/test_camera_read_routes.py tests/security/vision/test_camera_read_authorization.py -q`
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
        expires_at=now + timedelta(seconds=30),
        facts=facts,
        projection_state=overview_projection_state(facts),
        recorder_independent_from_privacy=True,
        selected_frame_perception="absent",
    )
~~~

Inventory distinguishes TrackMix hall/bedroom-pathway, kitchen view A, and kitchen view B only in the owner-local projection; committed fixtures remain synthetic. Show exact/family-unknown model, firmware, area/zone ID plus safe label, source disposition, capability generation, local-only/egress proof, audio-off, clock, last segment, gaps, coverage, copies, storage/retention, arc/dual-view evidence, and absent/degraded states. Register APIs only when `camera_storage` has accepted evidence; alert/presence endpoints remain absent until their later gates. Regenerate OpenAPI and TypeScript.

- [ ] **Step 4: Run green, generation drift, and response scan**

Run: `uv run python scripts/generate_openapi_client.sh --check && uv run pytest tests/contract/api/test_vision_openapi.py tests/integration/api/test_camera_read_routes.py tests/security/vision/test_camera_read_authorization.py -q && uv run python scripts/scan_api_responses.py --domain cameras --forbid stream_url,credential,address,path,raw_error,profile_id && uv run ruff check apps/core/src/tuntun_core/services/vision apps/core/src/tuntun_core/api packages/contracts/src/tuntun_contracts/vision/ui.py tests/contract/api tests/integration/api tests/security/vision && uv run mypy apps/core/src packages/contracts/src`
Expected: PASS; generated clients are diff-clean; every non-owner gets no existence signal; stale/unknown never renders green.

- [ ] **Step 5: Commit**

~~~bash
git add apps/core/src/tuntun_core/services/vision/health.py apps/core/src/tuntun_core/services/vision/projections.py apps/core/src/tuntun_core/api/routes/cameras.py apps/core/src/tuntun_core/api/vision_dtos.py packages/contracts/src/tuntun_contracts/vision/ui.py packages/contracts/openapi/admin-v1.yaml apps/admin/src/api/generated/admin-v1.ts tests/contract/api/test_vision_openapi.py tests/integration/api/test_camera_read_routes.py tests/security/vision/test_camera_read_authorization.py
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

**Interfaces:** Consumes generated Phase 3 UI DTOs, shared `TruthState`, `PreparedMutation`, and per-range playback client. Produces owner routes `/cameras`, `/cameras/inventory`, `/cameras/recordings`, and `/cameras/privacy`. It owns no authorization, camera credential, stream URL, filesystem path, policy generation, or grant construction.

- [ ] **Step 1: Write red route, no-autoplay, explicit range, and truthful-state tests**

~~~typescript
test("recording page never autoplays and requests one range grant after owner action", async ({page}) => {
  await page.goto("/cameras/recordings");
  await expect(page.locator("video[autoplay]")).toHaveCount(0);
  await page.getByRole("button", {name: "Open clip"}).click();
  await expect(page.getByText("Preparing one-time playback access")).toBeVisible();
  expect(await capturedRequests(page, "/playback-ranges")).toHaveLength(1);
});

test("Privacy Shield does not imply recorder stopped", async ({page}) => {
  await seedCameraPosture(page, {privacyShield: "active", recorder: "recording"});
  await page.goto("/cameras");
  await expect(page.getByText("Privacy Shield on — cameras still recording")).toBeVisible();
});
~~~

- [ ] **Step 2: Run red**

Run: `pnpm --filter @tuntun/admin exec playwright test tests/e2e/cameras-overview.spec.ts tests/e2e/cameras-recordings.spec.ts`
Expected: FAIL with 404 for `/cameras`.

- [ ] **Step 3: Implement accessible routes and chunked same-origin playback**

~~~tsx
export function RecordingClip({clip}: {clip: ClipProjection}) {
  const player = useOneTimeRangePlayer(clip.clipId, clip.availableViews);
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
~~~

Use cards/table alternatives for health/inventory; keep two E1 units separate; show TrackMix fixed-wide/tracking/arc truth; make gaps, audio-off, clock, source, retention, copies, and unavailable capabilities textual. Event rows never name people. Clip details are reveal-on-demand with no prefetch/autoplay. Range grants stay in memory and clear on navigation, expiry, logout, privacy, or error. No `localStorage`, `sessionStorage`, IndexedDB, Cache API, service worker, screenshot, direct media URL, or browser history query contains a grant or clip metadata. Provide English/Hindi/mixed-script safe labels, keyboard control, focus restoration, captions saying audio is absent, 320 px/200% zoom, dark/light/high-contrast/reduced-motion.

- [ ] **Step 4: Run green, accessibility/localization, and browser-artifact scans**

Run: `pnpm --filter @tuntun/admin exec vitest run && pnpm --filter @tuntun/admin exec lint && pnpm --filter @tuntun/admin exec tsc --noEmit && pnpm --filter @tuntun/admin exec vite build && pnpm --filter @tuntun/admin exec playwright test tests/e2e/cameras-overview.spec.ts tests/e2e/cameras-recordings.spec.ts tests/ui/cameras-accessibility.spec.ts && uv run python scripts/scan_browser_artifacts.py --playwright-output test-results --forbid media_url,grant,credential,address,path,identity`
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
- Create: `apps/admin/src/features/cameras/storage.tsx`
- Create: `apps/admin/src/routes/cameras-storage.tsx`
- Create: `docs/procurement/phase3-storage-decision.md`
- Create: `tests/unit/vision/test_storage_decision.py`
- Create: `tests/integration/api/test_storage_decision_route.py`
- Create: `tests/e2e/cameras-storage.spec.ts`

**Interfaces:** Produces a read-only measured recommendation plus exact owner-passkey `camera.storage_decision.sign` operation choosing `retain_external_ssd`, `open_hub_nvr_procurement`, or `open_nas_vms_procurement`. It creates no order, vendor login, payment, quote acceptance, filesystem migration, or recorder change.

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

Run: `uv run pytest tests/unit/vision/test_storage_decision.py tests/integration/api/test_storage_decision_route.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/cameras-storage.spec.ts`
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

Run: `uv run pytest tests/unit/vision/test_storage_decision.py tests/integration/api/test_storage_decision_route.py -q && pnpm --filter @tuntun/admin exec vitest run && pnpm --filter @tuntun/admin exec lint && pnpm --filter @tuntun/admin exec tsc --noEmit && pnpm --filter @tuntun/admin exec vite build && pnpm --filter @tuntun/admin exec playwright test tests/e2e/cameras-storage.spec.ts && uv run python scripts/check_feature_absence.py --feature phase3_hardware_purchase --phase 3`
Expected: PASS; measurement/decision values recompute; no purchase/order/payment route/config/client exists.

- [ ] **Step 5: Commit**

~~~bash
git add apps/core/src/tuntun_core/services/vision/storage_decision.py apps/core/src/tuntun_core/api/routes/cameras.py apps/admin/src/features/cameras/storage.tsx apps/admin/src/routes/cameras-storage.tsx docs/procurement/phase3-storage-decision.md tests/unit/vision/test_storage_decision.py tests/integration/api/test_storage_decision_route.py tests/e2e/cameras-storage.spec.ts
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
- Modify: `apps/admin/src/features/cameras/overview.tsx`
- Create: `tests/integration/vision/test_privacy_recorder_matrix.py`
- Create: `tests/security/vision/test_recorder_control_auth.py`
- Create: `tests/performance/vision/test_privacy_authority_deadline.py`
- Create: `tests/e2e/cameras-privacy-controls.spec.ts`

**Interfaces:** Registers privacy effect `p3.camera_outcomes` and exact owner operations `recorder.pause.camera`, `recorder.pause.all`, `recorder.resume.camera`, and `recorder.resume.all`. Privacy effect consumes the canonical privacy generation; recorder operations consume fresh passkey grants bound to exact endpoints/current state/consequences/policy generation/expiry.

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

Run: `uv run pytest tests/integration/vision/test_privacy_recorder_matrix.py tests/security/vision/test_recorder_control_auth.py tests/performance/vision/test_privacy_authority_deadline.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/cameras-privacy-controls.spec.ts`
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

Run: `uv run pytest tests/integration/vision/test_privacy_recorder_matrix.py tests/security/vision/test_recorder_control_auth.py tests/performance/vision/test_privacy_authority_deadline.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/cameras-privacy-controls.spec.ts && uv run python scripts/run_privacy_latency.py --component p3.camera_outcomes --iterations 1000 --assert-core-p95-ms 250 && uv run python scripts/check_feature_absence.py --feature recorder_voice_control --phase 3`
Expected: PASS; authority revocation P95 ≤250 ms, downstream timeout shows `unverified`, recorder truth remains independent, stale events/grants do not revive, and voice recorder control is absent.

- [ ] **Step 5: Commit**

~~~bash
git add apps/core/src/tuntun_core/services/privacy/supervisor.py apps/core/src/tuntun_core/services/vision/privacy_effect.py apps/core/src/tuntun_core/services/vision/playback_broker.py apps/recorder/src/tuntun_recorder/recording/service.py apps/core/src/tuntun_core/api/routes/cameras.py apps/admin/src/features/cameras/overview.tsx tests/integration/vision/test_privacy_recorder_matrix.py tests/security/vision/test_recorder_control_auth.py tests/performance/vision/test_privacy_authority_deadline.py tests/e2e/cameras-privacy-controls.spec.ts
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
- Modify: `apps/recorder/src/tuntun_recorder/events/normalizer.py`
- Create: `tests/contract/vision/test_event_ingress.py`
- Create: `tests/property/vision/test_event_boundary_rejection.py`
- Create: `tests/security/vision/test_event_has_no_authority.py`
- Create: `tests/security/vision/test_event_identity_memory_isolation.py`

**Interfaces:** Implements `CameraOutcomePort.ingest_security_event`. It consumes an authenticated IPC `CrossDomainEventV1[CameraSecurityEventV1]` and reopens the current camera binding, canonical area, zone/`zone_generation`, source/capability, privacy policy, and privacy-generation state before dispatching an in-process observation. It produces only `EventIngressReceiptV1` and a validated ephemeral `CameraSecurityObservation`.

- [ ] **Step 1: Write red stale-generation, cross-zone, duplicate, and no-authority tests**

~~~python
@pytest.mark.parametrize(
    "mutation",
    [
        "area_id", "zone_id", "zone_generation", "camera_binding_generation",
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
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/vision/test_event_ingress.py tests/property/vision/test_event_boundary_rejection.py tests/security/vision/test_event_has_no_authority.py tests/security/vision/test_event_identity_memory_isolation.py -q`
Expected: FAIL because `VisionEventIngress` is absent.

- [ ] **Step 3: Implement strict revalidation, dedupe, and observation-only dispatch**

~~~python
async def ingest_security_event(
    self, envelope: CrossDomainEventV1[CameraSecurityEventV1],
) -> EventIngressReceiptV1:
    event = require_payload(envelope, "camera.security_event.v1", CameraSecurityEventV1)
    binding = await self._bindings.require_current(event.camera_binding_id, event.camera_binding_generation)
    await self._capabilities.require_current(binding, event.capability_generation)
    zone = await self._zones.require_current(
        area_id=event.area_id,
        zone_id=event.zone_id,
        zone_generation=event.zone_generation,
        camera_binding_id=binding.camera_binding_id,
        camera_binding_generation=binding.camera_binding_generation,
    )
    await self._privacy.require_current(
        policy_version=event.privacy_policy_version,
        privacy_generation=event.privacy_generation,
        at=envelope.ingested_at,
    )
    await self._privacy_shield.require_generation_eligible(
        event.privacy_generation, envelope.ingested_at,
    )
    await self._dedupe.claim(envelope.deduplication_key, envelope.event_id)
    return await self._router.publish_observation(CameraSecurityObservation(event=event, zone=zone))
~~~

Reject unknown fields/version/type, unregistered endpoint, wrong area/zone/`zone_generation`, stale camera/capability/privacy generation, oversized payload, clock-untrusted event, duplicate content under a new key, shielded generation, pause, and disabled policy. The in-process router registers only alert and presence consumers; it has no IdentityPort, MemoryPort, Reachy wake/greeting, provider/model, HA action/routine, screen-time, desktop, or robot consumer. Logs/audit contain safe reason/commitment only; core does not persist the full camera event body.

- [ ] **Step 4: Run green, randomized boundary corpus, and import/reachability scan**

Run: `uv run pytest tests/contract/vision/test_event_ingress.py tests/property/vision/test_event_boundary_rejection.py tests/security/vision/test_event_has_no_authority.py tests/security/vision/test_event_identity_memory_isolation.py -q && uv run pytest tests/property/vision/test_event_boundary_rejection.py --hypothesis-seed=31025 -q && uv run python scripts/check_event_consumers.py --event camera.security_event.v1 --allow alerting,presence --forbid identity,memory,greeting,provider,home_action,screen_time,desktop,robot && uv run ruff check apps/core/src/tuntun_core/services/vision/event_ingress.py apps/core/src/tuntun_core/services/vision/privacy_policy.py tests/contract/vision tests/property/vision tests/security/vision && uv run mypy apps/core/src`
Expected: PASS; every stale/substituted generation quarantines, and no event-to-authority path exists.

- [ ] **Step 5: Commit**

~~~bash
git add apps/core/src/tuntun_core/services/vision/event_ingress.py apps/core/src/tuntun_core/services/vision/privacy_policy.py apps/recorder/src/tuntun_recorder/events/normalizer.py tests/contract/vision/test_event_ingress.py tests/property/vision/test_event_boundary_rejection.py tests/security/vision/test_event_has_no_authority.py tests/security/vision/test_event_identity_memory_isolation.py
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
- Create: `scripts/phase3/calibrate_alerts.py`
- Create: `docs/evidence/phase3-alert-quality-schema.json`
- Create: `docs/operations/phase3-alerts-presence.md`
- Create: `tests/unit/vision/test_alert_policy.py`
- Create: `tests/unit/vision/test_alert_dedupe_cooldown.py`
- Create: `tests/integration/vision/test_alert_inbox_sse.py`
- Create: `tests/security/vision/test_alert_minimization.py`
- Create: `tests/acceptance/vision/test_alert_quality_gate.py`

**Interfaces:** Produces exact owner-passkey alert-policy preparation/installation, `OwnerAlertService.consume`, the closed `SafeAlertSSEV1` delivery class `local_owner_inbox_sse_v1`, a metadata-only 24-hour delivery queue, durable local event inbox projection, authenticated `GET /api/v1/ui/cameras/alerts/stream` SSE, and content-minimized delivery receipts. It consumes only validated observations from Task 25 and opaque clip availability—not playback grants.

- [ ] **Step 1: Write red quality, dedupe, owner-only, queue, and content tests**

~~~python
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
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/vision/test_alert_policy.py tests/unit/vision/test_alert_dedupe_cooldown.py tests/integration/vision/test_alert_inbox_sse.py tests/security/vision/test_alert_minimization.py tests/acceptance/vision/test_alert_quality_gate.py -q`
Expected: FAIL because alert service/route/calibration is absent.

- [ ] **Step 3: Implement exact policy, durable inbox, dedupe, SSE, and quality verifier**

~~~python
async def consume(self, observation: CameraSecurityObservation) -> AlertReceipt:
    policy = await self._policies.require_enabled(
        camera_binding_id=observation.event.camera_binding_id,
        camera_generation=observation.event.camera_binding_generation,
        area_id=observation.event.area_id,
        zone_id=observation.event.zone_id,
        zone_generation=observation.event.zone_generation,
        event_class=observation.event.event_class,
        privacy_policy_version=observation.event.privacy_policy_version,
        observed_at=observation.event.started_at,
    )
    key = policy.cooldown_key(observation.event)
    if not await self._cooldowns.claim(key, seconds=60):
        return AlertReceipt.duplicate()
    row = await self._inbox.commit_metadata_only(observation.event, expires_in=timedelta(hours=24))
    await self._sse.emit_if_authenticated_owner_connected(
        lambda emitted_at: SafeAlertSSEV1.model_validate(row.safe_sse_payload(emitted_at)),
    )
    return AlertReceipt.accepted(row.id)
~~~

An enable request binds exact camera/class/area/zone/`zone_generation`/schedule/60-second cooldown/the closed `local_owner_inbox_sse_v1` delivery class/privacy/capability/policy generations and quality digest. `person` is the first candidate; every other class remains separately absent until it passes. Calibration requires ≥30 positive traversals across day/IR/ordinary light, ≥95% accepted recall, seven representative days, ≤1 false owner alert per 24 hours, zero duplicate on replay/reconnect/restart, and reachable-page local event-to-SSE P95 ≤5 seconds. A high-risk deviation requires a separate fresh owner-passkey record bound to exact measured failures, risk text, policy, and expiry. Queue only one implicit owner recipient, expires delivery rows at 24 hours, and records original event/delayed time. With no authenticated page, it makes no immediate-delivery claim. Privacy/pause/revocation/stale/clock-untrusted/excluded class/zone yields zero new alert. No alert wakes/speaks through Reachy or calls HA.

- [ ] **Step 4: Run green, synthetic calibration, SSE reconnect, and absence checks**

Run: `uv run pytest tests/unit/vision/test_alert_policy.py tests/unit/vision/test_alert_dedupe_cooldown.py tests/integration/vision/test_alert_inbox_sse.py tests/security/vision/test_alert_minimization.py tests/acceptance/vision/test_alert_quality_gate.py -q && uv run python scripts/phase3/calibrate_alerts.py synthetic --events fixtures/synthetic/vision/alert-calibration.json --output var/evidence/phase3/synthetic-alert-quality.json && uv run python scripts/phase3/calibrate_alerts.py verify var/evidence/phase3/synthetic-alert-quality.json && uv run python scripts/check_feature_absence.py --features background_push,native_companion,sms,email,vendor_cloud_alert,camera_greeting,camera_home_action --phase 3 && uv run ruff check apps/core/src/tuntun_core/services/vision/alerting.py apps/core/src/tuntun_core/api/routes/camera_alerts.py scripts/phase3/calibrate_alerts.py tests/unit/vision tests/integration/vision tests/security/vision tests/acceptance/vision && uv run mypy apps/core/src`
Expected: PASS; reconnect from last accepted event ID creates no duplicate, closed-page state is delayed/unread rather than delivered, and every prohibited transport/action is absent.

- [ ] **Step 5: Commit tooling and service before any physical calibration; never commit owner evidence**

~~~bash
git add apps/core/src/tuntun_core/services/vision/alerting.py apps/core/src/tuntun_core/api/routes/camera_alerts.py scripts/phase3/calibrate_alerts.py docs/evidence/phase3-alert-quality-schema.json docs/operations/phase3-alerts-presence.md tests/unit/vision/test_alert_policy.py tests/unit/vision/test_alert_dedupe_cooldown.py tests/integration/vision/test_alert_inbox_sse.py tests/security/vision/test_alert_minimization.py tests/acceptance/vision/test_alert_quality_gate.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(vision): add calibrated local owner alerts"
~~~

After the commit, run one exact camera/class/zone calibration at a time with `TUNTUN_ALLOW_ELAPSED_PHASE3=1`. Failed classes stay absent.

### Task 27: Build alert policy, event inbox, SSE, and truthful delayed-delivery UI

**Depends on:** Tasks 22 and 26.
**Gate contribution:** P3-4 UI.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `apps/admin/src/features/cameras/alerts.tsx`
- Create: `apps/admin/src/features/cameras/use-owner-alert-stream.ts`
- Create: `apps/admin/src/routes/cameras-alerts.tsx`
- Create: `tests/e2e/cameras-alerts.spec.ts`
- Create: `tests/e2e/cameras-alerts-reconnect.spec.ts`
- Create: `tests/ui/cameras-alerts-accessibility.spec.ts`
- Create: `tests/security/ui/test_no_background_alert_transport.py`

**Interfaces:** Produces owner route `/cameras/alerts`, exact policy/calibration prepared mutations, durable inbox, and active-page notification mirror. It consumes same-origin SSE safe summaries and uses clip references only to navigate to Task 22's separately authorized playback flow.

- [ ] **Step 1: Write red reconnect/dedupe, closed-page truth, no-thumbnail, and no-service-worker tests**

~~~typescript
test("SSE reconnect resumes after last accepted ID without duplicate card", async ({page}) => {
  await page.goto("/cameras/alerts");
  await emitSafeAlert(page, {id: "alert-synth-01"});
  await disconnectSSE(page);
  await reconnectSSE(page, {lastEventId: "alert-synth-01"});
  await emitSafeAlert(page, {id: "alert-synth-01"});
  await expect(page.getByTestId("alert-synth-01")).toHaveCount(1);
});

test("closed owner page never claims immediate delivery", async ({page}) => {
  await seedDelayedAlert(page, {originalTime: "10:00", firstViewedTime: "10:30"});
  await page.goto("/cameras/alerts");
  await expect(page.getByText("First shown 30 minutes after the event")).toBeVisible();
  await expect(page.getByText("Delivered immediately")).toHaveCount(0);
});
~~~

- [ ] **Step 2: Run red**

Run: `pnpm --filter @tuntun/admin exec playwright test tests/e2e/cameras-alerts.spec.ts tests/e2e/cameras-alerts-reconnect.spec.ts`
Expected: FAIL with 404 for `/cameras/alerts`.

- [ ] **Step 3: Implement active-page SSE, optional browser mirror, and exact policy UI**

~~~typescript
export function useOwnerAlertStream(enabled: boolean) {
  const [lastAcceptedId, setLastAcceptedId] = useState<string | null>(null);
  useEffect(() => {
    if (!enabled || document.visibilityState !== "visible") return;
    const source = new EventSource("/api/v1/ui/cameras/alerts/stream", {withCredentials: true});
    source.onmessage = event => {
      const safe = SafeAlertSSEV1.parse(JSON.parse(event.data));
      if (safe.eventId === lastAcceptedId) return;
      alertInbox.accept(safe);
      if (Notification.permission === "granted") new Notification(safe.safeTitle, {body: safe.safeBody, tag: safe.eventId});
      setLastAcceptedId(safe.eventId);
    };
    return () => source.close();
  }, [enabled, lastAcceptedId]);
}
~~~

Show class, safe zone label, original local time, verification, clip availability, read/delayed/delivery state, and policy/quality evidence. Never render thumbnail/audio/identity/address/token. Browser Notification API is offered only while the paired authenticated page is active and after explicit permission; it mirrors the same safe summary. Do not register a service worker, Push API subscription, background sync, native bridge, analytics, SMS/email, or vendor cloud. Security containment may disable future external adapters but must leave the local inbox/SSE critical banner visible.

- [ ] **Step 4: Run green, UI/accessibility, bundle, and background-transport scans**

Run: `pnpm --filter @tuntun/admin exec vitest run && pnpm --filter @tuntun/admin exec lint && pnpm --filter @tuntun/admin exec tsc --noEmit && pnpm --filter @tuntun/admin exec vite build && pnpm --filter @tuntun/admin exec playwright test tests/e2e/cameras-alerts.spec.ts tests/e2e/cameras-alerts-reconnect.spec.ts tests/ui/cameras-alerts-accessibility.spec.ts && uv run pytest tests/security/ui/test_no_background_alert_transport.py -q && uv run python scripts/scan_web_bundle.py --forbid serviceWorker,PushManager,backgroundSync,thumbnailUrl,cameraAddress`
Expected: PASS; duplicate suppression/reconnect/delayed state are truthful, active-page notification is opt-in, and no background/external transport exists.

- [ ] **Step 5: Commit**

~~~bash
git add apps/admin/src/features/cameras/alerts.tsx apps/admin/src/features/cameras/use-owner-alert-stream.ts apps/admin/src/routes/cameras-alerts.tsx tests/e2e/cameras-alerts.spec.ts tests/e2e/cameras-alerts-reconnect.spec.ts tests/ui/cameras-alerts-accessibility.spec.ts tests/security/ui/test_no_background_alert_transport.py
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
- Create: `scripts/phase3/calibrate_presence.py`
- Create: `tests/unit/vision/test_presence_state_machine.py`
- Create: `tests/property/vision/test_presence_sequences.py`
- Create: `tests/integration/vision/test_presence_restart_expiry.py`
- Create: `tests/security/vision/test_presence_has_no_history_identity_or_action.py`
- Create: `tests/security/vision/test_selected_frame_count_ignored.py`
- Create: `tests/acceptance/vision/test_vacancy_feature_absence.py`

**Interfaces:** Implements `AnonymousPresencePort` and owner-safe current-state read projection. It consumes validated current `person` observations and optional future commissioned non-imaging evidence. The current household build registers camera `occupied → unknown` only; `vacant`, `zero/one/multiple`, HA presence projection, and vacancy-capable sensor routes are absent.

- [ ] **Step 1: Write red state/expiry/replay/outage/no-history tests**

~~~python
async def test_camera_person_event_can_only_assert_five_minute_occupied(service, person_event, fake_clock) -> None:
    state = await service.apply(person_event)
    assert state.state == "occupied"
    assert state.count_band == "unknown"
    assert state.valid_until <= person_event.observed_at + timedelta(minutes=5)
    fake_clock.advance_to(state.valid_until)
    assert (await service.current(state.area_id)).state == "unknown"

@pytest.mark.parametrize("cause", ["no_event", "timeout", "source_outage", "clock_untrusted", "restart_uncertain", "privacy_on"])
async def test_uncertainty_never_becomes_vacant(service, cause) -> None:
    assert (await service.apply_uncertainty(area_id="area_common_synth_01", cause=cause)).state == "unknown"

async def test_replayed_evidence_cannot_extend_original_expiry(service, person_event) -> None:
    first = await service.apply(person_event)
    second = await service.apply(person_event)
    assert second.valid_until == first.valid_until

def test_future_selected_frame_count_has_no_presence_consumer(feature_graph) -> None:
    assert feature_graph.consumers("anonymous_visual_observation.v1") == ()
~~~

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/vision/test_presence_state_machine.py tests/property/vision/test_presence_sequences.py tests/integration/vision/test_presence_restart_expiry.py tests/security/vision/test_presence_has_no_history_identity_or_action.py tests/security/vision/test_selected_frame_count_ignored.py tests/acceptance/vision/test_vacancy_feature_absence.py -q`
Expected: FAIL because `AnonymousPresenceService` and presence route are absent.

- [ ] **Step 3: Implement current-only state, original expiry, and absent conditional routes**

~~~python
async def apply(self, evidence: AnonymousPresenceEvidenceV1) -> PresenceChangedV1:
    if evidence.kind != "camera_native_person":
        return await self._apply_only_if_commissioned_vacancy_rule(evidence)
    assert evidence.event_id is not None
    assert evidence.camera_binding_id is not None and evidence.camera_binding_generation is not None
    assert evidence.capability_generation is not None
    assert evidence.zone_id is not None and evidence.zone_generation is not None
    await self._policies.require_camera_occupied_enabled(
        area_id=evidence.area_id,
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
    current = await self._repo.current(evidence.area_id)
    if current and current.last_evidence_commitment == evidence.commitment:
        return current.to_event()
    checkpoint = PresenceCheckpoint.occupied_unknown_count(evidence, valid_until=valid_until)
    await self._repo.replace_current(checkpoint)
    return checkpoint.to_event()

async def expire(self, area_id: StableHomeId, now: datetime) -> PresenceChangedV1:
    await self._repo.delete_if_expired(area_id, now)
    return PresenceChangedV1.unknown(area_id=area_id, reason="evidence_expired", observed_at=now)
~~~

The encrypted checkpoint is one replace-in-place row containing area, anonymous state/count, source-kind enum, exact evidence-policy and privacy generations, evidence commitment, observed time, original expiry, and reason. It creates no timeline, heatmap, person/child/viewer relation, cross-room join, clip link, memory proposal, screen-time debit, or audit body; expiry removes it and checkpoints are omitted from normal backups/history. Restart preserves only an unexpired original deadline; otherwise unknown. A source outage/Privacy Shield immediately makes the projection unknown. Publish a closed internal `presence.changed.v1` observation only; no HA entity/Recorder/state route is registered in the baseline. The conditional non-imaging simulator can evaluate `vacant` only after a separately procured exact sensor rule passes ≥100 entry/exit/dwell/two-person/re-entry/door-open/outage/clock/restart/reorder sequences, zero false vacancy, and ≥95% occupied detection. Since no such sensor is approved, production vacancy/count routes must pass negative reachability.

- [ ] **Step 4: Run green, 10,000 randomized sequences, and absence/history scans**

Run: `uv run pytest tests/unit/vision/test_presence_state_machine.py tests/property/vision/test_presence_sequences.py tests/integration/vision/test_presence_restart_expiry.py tests/security/vision/test_presence_has_no_history_identity_or_action.py tests/security/vision/test_selected_frame_count_ignored.py tests/acceptance/vision/test_vacancy_feature_absence.py -q && uv run pytest tests/property/vision/test_presence_sequences.py --hypothesis-seed=31028 -q && uv run python scripts/phase3/calibrate_presence.py synthetic --sequences 10000 --mode camera-occupied-only --output var/evidence/phase3/synthetic-presence.json && uv run python scripts/check_feature_absence.py --features presence_vacant,presence_count,ha_presence_projection,selected_frame_perception --phase 3 && uv run python scripts/scan_database_schema.py --domain presence --forbid history,person,profile,child,viewer,clip,memory,screen_time && uv run ruff check apps/core/src/tuntun_core/services/vision/presence.py apps/core/src/tuntun_core/api/routes/camera_presence.py scripts/phase3/calibrate_presence.py tests/unit/vision tests/property/vision tests/integration/vision tests/security/vision tests/acceptance/vision && uv run mypy apps/core/src`
Expected: PASS; zero false vacancy, no replay extension, every unreliable path becomes unknown, and conditional/selected-frame/HA routes remain absent.

- [ ] **Step 5: Commit**

~~~bash
git add apps/core/src/tuntun_core/services/vision/presence.py apps/core/src/tuntun_core/api/routes/camera_presence.py scripts/phase3/calibrate_presence.py tests/unit/vision/test_presence_state_machine.py tests/property/vision/test_presence_sequences.py tests/integration/vision/test_presence_restart_expiry.py tests/security/vision/test_presence_has_no_history_identity_or_action.py tests/security/vision/test_selected_frame_count_ignored.py tests/acceptance/vision/test_vacancy_feature_absence.py
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

Run: `pnpm --filter @tuntun/admin exec playwright test tests/e2e/cameras-presence.spec.ts`
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

Run: `pnpm --filter @tuntun/admin exec vitest run && pnpm --filter @tuntun/admin exec lint && pnpm --filter @tuntun/admin exec tsc --noEmit && pnpm --filter @tuntun/admin exec vite build && pnpm --filter @tuntun/admin exec playwright test tests/e2e/cameras-presence.spec.ts tests/ui/cameras-presence-accessibility.spec.ts && uv run pytest tests/security/ui/test_presence_projection_minimization.py -q && uv run python scripts/scan_browser_artifacts.py --playwright-output test-results --forbid person,profile,child,viewer,clip,history,frame`
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
- Create: `tests/security/vision/test_raw_media_sentinel.py`
- Create: `tests/security/vision/test_camera_lateral_movement.py`
- Create: `tests/security/vision/test_camera_secret_and_log_scan.py`
- Create: `tests/property/vision/test_media_parser_fuzz.py`
- Create: `tests/property/vision/test_event_parser_fuzz.py`
- Create: `tests/performance/vision/test_recorder_resource_bounds.py`
- Create: `docs/operations/phase3-observability.md`
- Modify: `docs/privacy/phase3-camera-data.md`

**Interfaces:** Produces safe recording/source/event/storage/retention/alert/presence health facts and content-minimized audit receipts. It consumes counts, latencies, pseudonymous endpoint commitments, generations, and reason codes only.

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

Run: `uv run pytest tests/security/vision/test_raw_media_sentinel.py tests/security/vision/test_camera_lateral_movement.py tests/security/vision/test_camera_secret_and_log_scan.py tests/property/vision/test_media_parser_fuzz.py tests/property/vision/test_event_parser_fuzz.py tests/performance/vision/test_recorder_resource_bounds.py -q`
Expected: FAIL because full Phase 3 scans/health projections are not registered.

- [ ] **Step 3: Implement safe metrics/audit and complete runbooks**

Expose source online/degraded/offline/ineligible, event channel, recorder running/paused/failed, last complete segment, current gap, storage/reserve, projected days, clock skew band, capability generation, alert queue/latency, and anonymous-state expiry. Never expose raw error, media/path, address, credential, event body, identity, or timeline. Audit stores operation/outcome/safe reason/HMAC commitment for commissioning, zone changes, playback, export/delete, recorder controls, policy, alert delivery, storage decision, and recovery; it stores no clip/event/presence body. Daily checks cover integrity, reserve, gaps/retention, egress drift, and keys; weekly owner summary targets the Phase 3 steady-state 30–60 minutes/month; monthly playback/export sample and quarterly retention/capacity/recovery drill are exact. Parser fuzz applies byte/frame/container/metadata/time/CPU/RAM limits.

- [ ] **Step 4: Run green, security/privacy scans, and resource test**

Run: `uv run pytest tests/security/vision tests/property/vision/test_media_parser_fuzz.py tests/property/vision/test_event_parser_fuzz.py tests/performance/vision/test_recorder_resource_bounds.py -q && make test-security && make verify-private-data && uv run python scripts/scan_network_surface.py --expect-owner-api-only --forbid-camera-public --forbid-media-proxy-lan && uv run python scripts/scan_logs_and_crashes.py --forbid-media,credential,address,raw_error,identity,profile,memory && uv run ruff check apps/core/src/tuntun_core/services/health.py apps/core/src/tuntun_core/services/audit/privacy_receipts.py apps/recorder/src/tuntun_recorder/health.py tests/security/vision tests/property/vision tests/performance/vision && uv run mypy apps/core/src apps/recorder/src`
Expected: PASS; sentinel appears only in approved video/playback locations; no high/critical finding, lateral authority path, public listener, secret, or content log remains.

- [ ] **Step 5: Commit**

~~~bash
git add apps/core/src/tuntun_core/services/health.py apps/core/src/tuntun_core/services/audit/privacy_receipts.py apps/recorder/src/tuntun_recorder/health.py tests/security/vision/test_raw_media_sentinel.py tests/security/vision/test_camera_lateral_movement.py tests/security/vision/test_camera_secret_and_log_scan.py tests/property/vision/test_media_parser_fuzz.py tests/property/vision/test_event_parser_fuzz.py tests/performance/vision/test_recorder_resource_bounds.py docs/operations/phase3-observability.md docs/privacy/phase3-camera-data.md
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

**Depends on:** Every enabled Task 01–31 output and current physical evidence.
**Gate contribution:** P3-6 final.
**Estimated effort:** 2 person-days plus seven elapsed soak days.

**Files:**
- Create: `scripts/phase3/run_acceptance.py`
- Create: `scripts/phase3/verify_acceptance.py`
- Create: `docs/evidence/phase3-evidence-schema.json`
- Create: `docs/evidence/phase3-soak-schema.json`
- Create: `docs/operations/phase3-acceptance.md`
- Create: `tests/acceptance/vision/test_phase3_evidence_schema.py`
- Create: `tests/acceptance/vision/test_phase3_acceptance_gate.py`
- Create: `tests/acceptance/vision/test_phase3_feature_absence.py`
- Create: `tests/acceptance/vision/test_phase3_soak_oracles.py`
- Create: `tests/acceptance/vision/test_phase3_storage_decision.py`

**Interfaces:** Produces a signed content-safe `tuntun.phase3.acceptance.v1`, `tuntun.phase3.soak.v1`, signed feature-manifest evidence, and exactly one `retain_external_ssd` / `open_hub_nvr_procurement` / `open_nas_vms_procurement` decision. No schema has a caller-authored pass Boolean; the verifier recomputes thresholds, hashes, durations, feature dependencies, and positive/absent routes.

- [ ] **Step 1: Write red complete-evidence, absent-feature, and storage-decision oracles**

~~~python
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

Run: `uv run pytest tests/acceptance/vision/test_phase3_evidence_schema.py tests/acceptance/vision/test_phase3_acceptance_gate.py tests/acceptance/vision/test_phase3_feature_absence.py tests/acceptance/vision/test_phase3_soak_oracles.py tests/acceptance/vision/test_phase3_storage_decision.py -q`
Expected: FAIL because final acceptance schemas/semantic verifier are absent.

- [ ] **Step 3: Implement recursively closed schemas and semantic verifier**

The verifier requires:

- exact three-camera inventory/placement records with each unit `eligible`, `inventory_only`, `native_sd_only`, or `vendor_native_only` for an explicit reason;
- canonical `area_id` plus current `zone_id`/`zone_generation`/camera/privacy generations and stale-generation rejection;
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
uv run pytest -m "not camera_hardware and not camera_network and not elapsed" -q
uv run pytest apps/recorder/tests integrations/reolink/tests -q
pnpm --filter @tuntun/admin exec playwright test tests/e2e/cameras-*.spec.ts
uv run python scripts/phase3/run_acceptance.py synthetic --commit "$(git rev-parse HEAD)" --output var/evidence/phase3/synthetic-acceptance.json
uv run python scripts/phase3/verify_acceptance.py var/evidence/phase3/synthetic-acceptance.json --commit "$(git rev-parse HEAD)"
TUNTUN_ALLOW_ELAPSED_PHASE3=1 uv run python scripts/phase3/run_acceptance.py household-soak --duration-seconds 604800 --sample-seconds 60 --simulate-retention-days 100 --commit "$(git rev-parse HEAD)" --evidence-root var/evidence/phase3 --output var/evidence/phase3/household-soak.json
uv run python scripts/phase3/verify_acceptance.py var/evidence/phase3/household-soak.json --commit "$(git rev-parse HEAD)" --require-physical-gates
uv run python scripts/verify_private_data.py var/evidence/phase3
~~~

Expected: clean candidate; software/UI/security/content suites pass; soak monotonic and wall elapsed are each ≥604,800 seconds; the verifier recomputes every threshold/hash; enabled features have positive gates; disabled features are unreachable; one storage decision is signed. Phase 3 itself authorizes S$0 of new acquisition.

- [ ] **Step 5: Commit evidence tooling before the frozen run; never commit generated owner evidence**

~~~bash
git add scripts/phase3/run_acceptance.py scripts/phase3/verify_acceptance.py docs/evidence/phase3-evidence-schema.json docs/evidence/phase3-soak-schema.json docs/operations/phase3-acceptance.md tests/acceptance/vision/test_phase3_evidence_schema.py tests/acceptance/vision/test_phase3_acceptance_gate.py tests/acceptance/vision/test_phase3_feature_absence.py tests/acceptance/vision/test_phase3_soak_oracles.py tests/acceptance/vision/test_phase3_storage_decision.py
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
3. Preserve all baseline invariants: camera vendor egress fail-closed; audio off/rejected; one canonical `area_id` plus current zone/binding generations; no raw media to general core consumers, HA, an LLM, VLM, generative model, or cloud; exact 7/90 retention; owner-only grants; separate copy truth; no public route. The only model exception remains the separately gated Phase 5 RAM-only local non-generative anonymous-CV selected-frame seam.
4. Procure at most the approved pilot units/licences within the return window. Do not bulk-buy drives/licences or decommission the SSD/native path.
5. Migrate one recoverable camera/view first and run a 30-day parallel campaign covering local protocol, native events, audio, egress, dual view, channel licensing, retention, capacity, playback, power loss, update, backup/recovery, and rollback.
6. Promote only if the candidate-specific verifier passes and the owner signs the migration decision. Failure restores the SSD/native source path, revokes candidate credentials/bindings, preserves truthful gaps/copies, and ends the pilot without further purchase.

This stop rule is intentionally not a generic “NAS adapter” coding task: choosing APIs, migrations, licence units, or rollback commands before an exact candidate would violate the no-assumption procurement gate.

## Dependency and Parallelization Map

~~~text
01 contracts ─┬─> 02 synthetic media/faults
              ├─> 03 core policy/zone/alert/presence persistence
              └─> 04 isolated vision catalog
02/03/04 ───────> 05 IPC/process/feature absence
03/05 ──────────> 06 commissioning
05/06 ──────────> 07 egress eligibility
06/07 ──────────> 08 TrackMix arc
01/02/06/07/08 ─> 09 exact Reolink adapters
04/05 ──────────> 10 SSD/launchd gate
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

Tasks 03 and 04 may proceed in separate clean worktrees after Task 01 freezes. Tasks 06 and 10 may proceed in parallel after their dependencies. UI Task 22 can start against Task 21 fixtures while Task 20's real elapsed campaign runs, but its production feature manifest remains absent until P3-2 evidence is accepted. Alert and presence software may be developed in parallel after Task 25; physical alert traversals and the one shared camera/network/SSD campaigns are serialized. No two worktrees may connect to, rotate, move, update, or control the same physical camera/volume concurrently.

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
- [ ] Source, recorder, media proxy, core, HA, and browser boundaries expose only their declared minimum data/keys/listeners.
- [ ] Routine ingest is stream-copy with zero routine inference/decode/transcode; optional playback transcode is bounded and cleaned.
- [ ] Continuous low-wide coverage is ≥99.5% per eligible camera and every >5-second gap appears within 30 seconds.
- [ ] Continuous retention is exactly seven days; event retention exactly 90 days; transient ring ≤60 seconds plus cleanup bound.
- [ ] Clock rollback/restart/restore cannot extend expiry; low space never deletes unexpired media or spills to root.
- [ ] Capacity uses seven measured representative days and 20% reserve; voice and Green backup objectives pass.
- [ ] TrackMix tracking event view either passes every dual-view gate or is absent and labelled wide-only.
- [ ] Only the owner can list/search/play/export/delete/configure/pause/resume/receive alerts; all other actors/origins receive no existence signal/media.
- [ ] Each playback range grant is exact, single-use, session/clip/view/operation/range bound, and ≤60 seconds.
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
