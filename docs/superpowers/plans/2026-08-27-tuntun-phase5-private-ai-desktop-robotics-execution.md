# Tuntun Phase 5 Private AI, Desktop Assistance, and Robotics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver evidence-gated task-cell local inference, a separate owner-governed knowledge corpus, owner-only bounded desktop assistance, advisory selected-frame local perception, and physically supervised Raspbot operation without moving household authority, private media, identity, or unrestricted execution into a model or endpoint.

**Architecture:** The independently owner-approved opaque Core inventory target from ADR 0001, currently verified as Darwin `arm64`, is both the office-use machine and the canonical policy, identity, memory, authorization, audit, budget, routing, and recovery host; no second office laptop or ambient cross-network helper exists. Architecture/model/product/year strings are descriptive and never authority. The family-ready baseline single-homes that Mac on the inner ASUS/AiMesh network with its direct BE800 link disconnected. Intel macOS remains a mandatory supported-distribution target and future household-transition candidate only after fresh trusted owner approval plus real-host probes. Any optional dual-homed mode is a separately signed network qualification and grants no forwarding, bridging, outer-network ingress, or additional desktop authority. Model runtimes, the desktop helper, the Phase 3 frame broker/perception service, and the Raspbot edge are replaceable least-privilege workers behind closed signed contracts; each conditional capability is independently registered only after its positive evidence gate. Knowledge uses one identity-bound canonical SQLCipher/object root plus a separately bound encrypted recovery copy, while desktop code execution is confined to D4 disposable sandboxes and robot motion is confined to short signed leases under local physical safety.

**Tech Stack:** Python 3.12, `asyncio`, Pydantic v2, SQLAlchemy 2/Alembic over SQLCipher, SQLite FTS5, application-envelope encryption, macOS Keychain/Secure Enclave ports, FastAPI, Unix-domain sockets with peer credentials, mTLS/JCS signatures, `llama.cpp`/vLLM/MLX-compatible adapters behind ports, isolated non-generative CV, React 19/TypeScript/Vite/TanStack Query, pytest/pytest-asyncio/Hypothesis, Ruff, strict mypy, Vitest, Playwright/axe, marker-gated Mac/appliance/storage/robot campaigns, and content-safe signed evidence.

**Normative design:** [Phase 5 Private AI, Desktop Assistance & Robotics](../specs/2026-08-27-tuntun-phase5-private-ai-desktop-robotics-design.md), [Program A–H](../specs/2026-08-27-tuntun-program-architecture-a-h.md), [Program I–S](../specs/2026-08-27-tuntun-program-assurance-delivery-i-s.md), [Phase 3 Vision, Presence & Storage](../specs/2026-08-27-tuntun-phase3-vision-presence-storage-design.md), [Phase 4 Whole-Home Voice, Media & Displays](../specs/2026-08-27-tuntun-phase4-voice-media-displays-design.md), and [Six-Phase UI/UX](../specs/2026-08-27-tuntun-six-phase-ui-ux-design.md).

## Authority and Upstream Reconciliation

1. The Phase 5 design owns Phase 5 values, contracts, limits, stages, and gates. Program A–H supplies shared topology/API contracts, Program I–S supplies repository/assurance/operations rules, and the UI design supplies presentation and signed feature-registration truth. A more restrictive current safety/privacy rule wins.
2. Phase 5 consumes the Phase 3 `selected_frame_request.v1` and `anonymous_visual_observation.v1` schema IDs unchanged. Before Task 34, the shared generated contract must include the normative `zone_generation` field alongside canonical `area_id`, `zone_id`, `camera_binding_generation`, and `privacy_policy_version`; any inherited execution-plan schema missing it is stale and must be reconciled in the shared Phase 3 contract/schema/client fixture commit.
3. `area_id` remains the sole canonical household location key. `zone_id` is a versioned child of exactly one `area_id` and owning camera/robot binding generation. Phase 5 introduces no `room_id`, parallel location map, display-label targeting, cross-area zone move, or ambiguity-widening zone behavior.
4. Phase 5 consumes the shared signed feature seam at `apps/core/src/tuntun_core/services/features/registry.py` and `apps/admin/src/app/feature-registry.ts`. No task creates a parallel registry, client-only entitlement, global “local AI” switch, or disabled-but-reachable route.
5. Phase 5 uses the current shared `EvidenceSigner`/`SignerRegistry`, `ActionBinding`, prepared-mutation/428 flow, `ui.operation_result.v1`, `ui.plane_fact.v1`, and Privacy Shield effect registry. Any additive contract change regenerates JSON Schema, OpenAPI, TypeScript, fixtures, feature digests, and negative-reachability evidence in the same commit.
6. The Phase 5 estimate of two to four owner hours per month is planning attribution only. It is never an independent promotion threshold. All ordinary subsystem time contributes to the single full-system rule: logging may begin after 60 steady-state days, but promotion evaluation requires at least 90 steady-state days and three complete monthly buckets. At that point, rolling three-month median ordinary owner maintenance is at most eight hours/month; three consecutive months above eight hours freeze optional expansion and trigger simplification or retirement review.

## Global Constraints

1. P5-E0 requires accepted Phase 1 `FB0`, current accepted Phase 2 topology/action contracts, the accepted Phase 3 camera/zone/frame contract and privacy boundary, and stable accepted Phase 4 endpoint/conversation contracts. A failed optional upstream camera, media, television, or room feature remains absent and does not authorize a substitute.
2. The independently owner-approved opaque active-Core inventory target, currently verified as Darwin `arm64`, remains the sole canonical identity, family policy, authorization, seven-kind memory, audit, cloud-budget, routing, signing, feature, and recovery authority. No model/proxy/helper/robot stores or decides those authorities; Intel macOS support remains a distribution obligation, not active household authority, and no architecture/model/product/year string can select a target.
3. Staged task-cell local migration is per exact `(task_class, capability, language_mode, profile_class, sensitivity_class)` cell through M0–M5. A global model-family or “local AI enabled” switch is invalid.
4. M0 is the accepted cloud/offline baseline; M1 permits only individually passed bounded Mac cells; M2 appliance shadow uses synthetic or explicitly de-identified cases only; M3 is a 14-day owner opt-in; M4 requires 30-day adult/local-knowledge evidence; M5 requires the complete Phase 1 child corpus, Phase 5 injection/RAG gates, and distinct current owner/guardian approval bound to exact artefact/evaluation/policy digests.
5. The independently owner-approved opaque active-Core target, currently observed as Darwin `arm64`, must be benchmarked before any M1 promotion. The listed 4 GiB RSS, 3.5 GiB artefact, 6 GiB pre-launch availability, two-logical-core average, one-job concurrency, and 4 GiB background headroom values are provisional conservative planning ceilings, not copied host evidence. A clean exact-candidate simultaneous-load campaign derives a signed safe operating envelope; every runtime gate uses the stricter of that measured envelope and these ceilings, and measurements may only tighten them without a new reviewed design decision. Background work yields to voice, privacy, recording, database, backup, and console work. Moving household inference back to Intel requires new trusted owner approval plus the full real-host campaign on that opaque target; architecture/model/year text is never authority.
6. Candidate Mac work passes a two-hour simultaneous-load soak, an eight-hour idle/periodic soak, and a seven-day mixed workload with no OOM, swap storm, thermal runaway, unbounded queue/cache, Phase 3 recording gap, Green-backup failure, or greater than 10% regression in accepted Phase 1 wake/stop/privacy/first-audio P95 without explicit owner review.
7. A model/runtime/template/tokenizer/quantization/evaluation digest change revokes activation and re-enters evaluation. Model names and API compatibility are never evidence inheritance.
8. Model weights, tokenizers, runtimes, parsers, containers, prompt templates, and CV artefacts are independently hash/licence/provenance/SBOM bound. Unknown custom code and `trust_remote_code` equivalents are prohibited.
9. Ordinary inference accepts only `SanitizedInferenceRequestV1` and returns `InferenceResultV1`. It receives no stable family/database ID, biometric, credential, filesystem path, camera URL/frame, HA entity, desktop grant token, robot credential, raw canonical-memory record, tool handle, or arbitrary action/memory schema.
10. Only locally pinned policy/system templates are instructions. Documents, web text, filenames, source comments/instruction files, command output, model output, frames, and robot telemetry are untrusted data and cannot create a higher-priority role or authority.
11. Cloud/VPS remains an outbound Phase 1 provider boundary with current consent, privacy, DLP, provider review, region, budget reservation, and audit. Owner-operated VPS is still cloud. No local-only content falls back to cloud for availability.
12. Desktop-selected material and command/workflow output are local-only unless one exact current `DesktopModelEgressAuthorizationV1` is transactionally consumed for one provider attempt. Every Phase 5 D4 grant/workflow has `execution_network_policy="none"`; a non-`none` value is invalid, while the independent model-egress authorization opens only its one committed provider attempt and never helper/workflow network.
13. One `KnowledgeStorageBindingV1` is canonical at a time. The default identity-bound internal root is `~/Library/Application Support/Tuntun/knowledge/`; an external root must be a separate encrypted APFS volume named `TUNTUN_KNOWLEDGE`. It is never `TUNTUN_VIDEO`, `HA_BACKUPS`, an alias/subdirectory of either, or an automatic fallback/spill destination.
14. The canonical knowledge root is opened by commissioned volume/filesystem identity and directory handle, not path text alone. Wrong/missing UUID, mount, filesystem, encryption, ownership, quota, reserve, read/write state, binding version, or CAS generation disables import, retrieval, indexing, export, and restore.
15. Knowledge recovery uses a separate `KnowledgeRecoveryPolicyV1`, key bundle, destination binding/UUID, quota, schedule, retention, and deletion generation on a different owner-controlled encrypted failure domain. It is never queried as the live root or the canonical root's own recovery destination.
16. Knowledge recovery retains seven daily and four weekly generations with a 24-hour RPO/prune/deletion-reconciliation bound and quarterly offline restore. Recovery ineligibility blocks new imports; source deletion/consent revocation blocks affected generations immediately and destroys/rekeys them plus creates a clean generation within 24 hours.
17. Canonical memory and the knowledge corpus never merge. Import creates no memory; retrieval schemas have no memory/action/tool/desktop/robot field; source deletion and memory deletion remain independent with explicit provenance review.
18. Knowledge import is owner-only. Non-owner adult, child, Guest, anonymous, subject-ceremony, remote, model, plugin, and endpoint routes have no picker, upload, source title, corpus administration, export, or deletion capability.
19. Parser jobs have no network/credentials, one read-only object mount, 512 MiB RAM, one CPU, 60-second deadline, 25 MiB extracted-text cap, and archive recursion depth at most two. Macros, active content, embedded executables, and external references are rejected.
20. FTS5 is mandatory baseline. Retrieval returns at most eight authorized current-version excerpts and 12,000 aggregate document tokens. Every excerpt carries its own positive token count, the bundle carries the checked sum, and both bounds are enforced before decrypting an object, materializing plaintext, or serializing to any model/provider. Optional embeddings are encrypted rebuildable derived data and activate only after a measured gain with equal ACL/deletion/backup/reproducibility behavior.
21. Desktop D0 has no computer access. D1 is owner-selected bounded read. D2 proposes only. D3 runs one exact confirmed pinned non-code inspection. Every repository/project code, binary, script, hook, plugin, test, lint, build, format, generator, compiler, interpreter, package command, or application entry point is D4. D0, D1, D2, D3 and D4 are independently feature-gated; failure of a higher level cannot remove a safe lower level or expose a partial higher route.
22. D3 contains only bounded registered `git status --porcelain=v2`, safe `git diff`, bounded `git log --max-count <= 200`, and bounded `rg` inspection. It has a controlled empty home/config, exact executable digest/argv grammar, read-only roots, network off, and no shell expansion, hooks, filters, pagers, helpers, textconv, preprocessors, package manager, or ambient `PATH`.
23. Every D3 job uses a two-minute exact confirmation bound to owner/session, grant/generation, executable digest, argv, cwd/filesystem identity, repository head/dirty state, environment, declared effects, limits, and network-off policy. `AUTHORIZED_COMMITTED` is durable before helper I/O; state drift invalidates the job.
24. D4 is absent unless one exact backend passes filesystem/process/network/device/IPC escape, secret, resource, cancellation, cleanup, malicious-build, and undeclared-write tests. A container/VM label is not proof. Any escape quarantines output, revokes the grant, and disables the backend.
25. D4 defaults to a read-only source mount plus disposable write layer, no network, host home, Docker/host socket, SSH agent, Keychain, device, host PID namespace, Tuntun production socket/data, camera, robot, or HA route; limits are two CPUs, 4 GiB RAM, 20 processes, 15 minutes, 100 MiB output, and 1 GiB disposable disk.
26. D4 `apply_patch_in_isolated_copy.v1` may produce a reviewed patch/evidence from a disposable copy only. Host write-back, commit, push, arbitrary workflow, and office-laptop execution are absent.
27. Phase 3 selected frames use only exact `selected_frame_request.v1`: one to three JPEG/PNG frames, at most 3 MiB total, at most 1920 px, single-use, at most five seconds, purpose `local_anonymous_cv_observation`, exact canonical area/zone/camera/privacy/model bindings, audio/EXIF/URL/credential free, RAM-only, local-only.
28. Selected frames reach a separate activated non-generative CV runtime through `PerceptionGatewayPort`, never `LanguageModelPort`, an LLM, VLM, captioner, OCR, general video mount, cloud, or VPS. No media, embedding, feature vector, crash body, or reusable handle persists.
29. `anonymous_visual_observation.v1` remains advisory. Phase 3 validates request, area, zone/generation, camera-binding generation, privacy generation, model/calibration and expiry; ignores `count_band` for occupancy/alerts; and makes native `camera.security_event.v1`, `presence.changed.v1`, alerts, occupancy, and HA state byte-for-byte unchanged except content-minimized quality metrics.
30. Raspbot floor motion is absent until exact delivered hardware/software, directional sensors, battery/charger, motor-enable path, independent physical e-stop, indicator, ports, vendor dependencies, stopping distances, barriers, and common-area zone evidence pass. Wheels-raised bench/simulator is the fallback.
31. The primary latching physical e-stop removes motor power/enable independently of Linux, Wi-Fi, Mac, and model; software cannot clear it. Physical disable P95 is at most 250 ms across 100 trials including failures. Reset requires inspection and local manual re-arm.
32. Raspbot motion is owner-only local manual input under adult physical supervision in surveyed common areas. Voice, child, Guest, model, HA, camera event, routine, Phase 6 remote session, and LILYGO cannot start, extend, or resume motion.
33. `RobotMotionLeaseV1` expires within 250 ms and binds robot/session/sequence/epoch, canonical area/robot-binding/zone generations, activation commitment, zone-bound safety digest, direction/velocities, owner, and signature. Local clamps, watchdog, sensor freshness, obstacle/cliff stops, 0.15 m/s translation and 0.5 rad/s rotation ceilings, and physical barriers override Mac input.
34. Bedrooms, bathrooms, kitchen, balcony, wet/utility/private areas, stairs, water/heat, exterior exits, unclassified areas, following, exploration, mapping beyond assisted commissioning, carrying, docking search, and restart resume are absent. Any uncertainty latches stop.
35. Raspbot video is owner-session-bound LAN live-only, no-store, no audio, no identity/memory/cloud/recorder path, and requires a truthfully hardware-tied or fail-closed monitored visible indicator. Phase 6 remote may view health only and cannot drive or open video.
36. The LILYGO experiment is optional, non-authoritative, USB-updated/hash-pinned, and limited to signed status, secondary stop, or short-lived provisioning. It is never the primary e-stop, authenticator, voice node, policy authority, credential vault, motion authority, or media store.
37. Ordinary tests use synthetic fixtures, temporary keys/stores, fake clocks/providers/devices, and no paid API, household data/media, WAN, hardware, Keychain, native picker, model download, Mac resource probe, appliance, storage mount, or robot motor I/O. Family data is never used for model training, public evaluation fixtures, CI, bug reports or examples. Explicit markers and environment flags write content-safe evidence only under ignored `var/evidence/phase5/`.
38. Privacy Shield atomically revokes Phase 5 authority before fan-out, cancels inference/knowledge/desktop/selected-frame/robot work, sends robot stop, clears ephemeral buffers, and reports prior egress/write plus unverified physical stop truthfully. Independent Reolink recording continues unless separately paused.
39. Restore keeps model routes, corpus retrieval, desktop grants/jobs, selected-frame requests, robot sessions/motion, and LILYGO pairing disabled until integrity, deletion, key, version, binding, capability, privacy, and new-generation reconciliation finishes.
40. Project branch coverage remains at least 85%; policy, route, DLP, ACL, grant, egress, sandbox, selected-frame, safety, lease, restore, and feature-registration modules remain at least 95%. Every task follows red → green → refactor → affected suite → static/security checks → exact-path review → commit.
41. Every Phase 5 campaign longer than 24 hours—the Task 12 seven-day Mac run, Task 16 M3/M4 runs, Task 44 seven-day robot soak, optional Task 45 fourteen-day LILYGO trial, and Task 48 thirty-day release run—consumes the inherited Phase 2 `SignedFeatureManifestRolloverChainV1` and `FeatureManifestLeaseSupervisor`. The runtime never signs or renews authority. Before a run, the existing external acceptance workflow pre-issues a complete at-most-24-hour hash chain for one frozen candidate/package/registration set; every admission requires the active wall expiry and process-local monotonic lease. Evidence binds the chain commitment and ordered activations with zero expired-authority interval. A missing, stale, late, reordered, widened, rollback, invalid, drifted, wall-expired, or monotonic-expired successor closes admission before work and invalidates the uninterrupted run; Phase 5 defines no second renewal mechanism.
42. An elapsed Phase 5 runner refuses to start until its runner, verifier, schemas, tests, route/service rows, and every candidate byte they bind are committed, the worktree is clean, and the complete canonical chain is externally signed for that resolved commit. Pre-commit validation is limited to bounded synthetic, fake-clock, and lifecycle tests that produce no elapsed evidence. After each task's tooling commit, the physical elapsed step starts from zero against the immutable commit; any later source, registration, route, service, configuration, artifact, firmware, or hardware change invalidates the affected evidence. Task 48 repeats the final 30-day non-robot campaign and, when floor motion is enabled, a fresh seven-day supervised robot soak against the exact final release candidate; earlier Task 44/45 evidence is qualification input, never a substitute for final-candidate evidence.

## Definition of Done for Every Task

- The named test is observed failing for the intended missing behavior before implementation.
- Narrow and affected Python suites pass with Ruff format/check and strict mypy; touched UI/firmware passes its lint, type, unit, Playwright/axe, and production-build commands.
- Contract changes regenerate JSON Schema/OpenAPI/TypeScript and diff clean; positive and adversarial fixtures reject unknown field/version/enum/discriminator, duplicate keys, oversize, replay, expiry, stale generation, cross-profile, and forbidden data/authority.
- Persistence changes include encrypted pre-migration backup, upgrade, downgrade-or-isolated-restore strategy, interruption/corruption tests, exact table/index/trigger ownership, and forbidden-content column scans.
- Every cross-process effect persists receiver idempotency/admission before I/O, injects crash on both sides of transitions, and never performs model/network/filesystem/motor I/O while the canonical writer lock is held.
- Conditional capability work proves either its positive gate or source/package/config/API/prepared-action/UI/client-bundle/IPC/network/runtime absence.
- Logs, browser/cache/storage, parser/sandbox workspaces, process arguments, model caches, crash bundles, packet captures, backups, evidence, and source/public artifacts pass synthetic secret/content/media/path sentinels.
- Hardware evidence binds pseudonymous exact SKU/revision/firmware/configuration, commands, operator, times, digests, measured values, fallback, and invalidation triggers; real identifiers/content stay outside Git.
- `git status --short` contains only task-owned paths; exact paths are staged; `git diff --cached --name-only`, `git diff --cached --check`, and `git diff --cached` are reviewed before the task commit.

## Phase Entry, Promotion, and Exit Gates

| Gate | Entry requirement | Positive exit | Disabled/failed exit |
|---|---|---|---|
| P5-E0 | Phase 1 `FB0`; accepted Phase 2 topology/action; accepted Phase 3 area/zone/camera/privacy and selected-frame contracts; stable accepted Phase 4 endpoint/one-slot contracts; migration head `0019_screen_time_real_adapter` | Shared contracts reconciled, migrations/fakes/corpora pass, threat/privacy amendments pass, and every Phase 5 feature is negatively reachable as absent | All Phase 5 routes/packages/client chunks remain unregistered |
| P5-0 | P5-E0 software baseline | Exact Mac/Raspbot/LILYGO/storage/network/sandbox/runtime inventory, simulator, contract, feature-absence, and threat evidence pass without model download, document import, desktop grant, frame, or motor motion | Only simulator and content-safe inventory remain |
| P5-1 | P5-0 plus active approved Core Mac availability | Individually named M1 cells pass quality and exact resource/preemption/two-hour/eight-hour/seven-day gates | Cell remains deterministic or on its prior eligible route; no global local route |
| P5-2 | P5-0 plus canonical and independent recovery storage bindings | Owner import, encrypted object/catalog/FTS/ACL/citation/deletion/recovery/restore gates pass | Corpus routes/import are absent; canonical memory unchanged |
| P5-3 | P5-1/P5-2 benchmark and owner procurement decision | `no_purchase` is valid evidence, or one candidate passes isolation/M2 then exact M3–M5 task-cell promotion gates | No appliance traffic/route/package registration; prior routes remain |
| P5-4 | P5-0 and eligible local model route | D0, then owner-only D1/D2 grants/read/proposals/DLP/local-only and exact egress ceremony pass; no execution route | Failed level absent; lower passed levels remain |
| P5-5 | P5-4 | Exact D3 non-code inspections pass; D4 activates only if one backend and signed workflow set pass all sandbox gates | D0–D2 and passed D3 remain; D4 and every repository-code route absent |
| P5-6 | Accepted Phase 3 source/zone/broker seam plus activated local non-generative CV runtime | Exact selected-frame/privacy/calibration/no-egress/no-promotion gate passes | Perception route/package/UI absent; native Phase 3 unchanged |
| P5-7 | P5-0 and competent delivered-board/e-stop review | Exact Raspbot inventory, independent e-stop, wheels-raised watchdog/sensors/speed/battery/indicator/network and physical-barrier evidence pass | Simulator/wheels-raised bench only; floor/telepresence routes absent |
| P5-8 | P5-7 plus one commissioned common-area zone and adult supervisor | Owner-local manual then optional indicator-proved video pass 10,000 lease cases, 100 boundary runs per reachable boundary, and seven-day supervised soak | Affected direction/video/floor mode absent; no weaker motion mode |
| P5-9 | All enabled gates | Thirty-day non-robot trial, separate robot soak, recovery/update/privacy/fault/network/security evidence, signed feature manifest, and full-system maintenance accounting pass; LILYGO independently kept or removed | Failed capability independently absent/quarantined; accepted prior phases continue |

## Planned Repository Map

```text
packages/contracts/src/tuntun_contracts/private_ai/
├── __init__.py
├── base.py                 # strict models, bounded IDs, canonical bytes
├── inference.py            # sanitized request/result and task-cell route
├── artifacts.py            # model/runtime/evaluation manifests
├── procurement.py          # closed no-purchase/purchase-candidate evidence
├── knowledge.py            # storage/recovery/source/query/citation contracts
├── desktop.py              # grants, model egress, commands, workflows, jobs
├── robotics.py             # session, motion lease, safety state
├── lilygo.py               # optional narrow status/stop/provisioning contracts
├── ui.py                   # Phase 5 owner-safe projections
└── ports.py                # inference/knowledge/helper/perception/robot protocols
packages/contracts/src/tuntun_contracts/vision/selected_frame.py
packages/contracts/src/tuntun_contracts/features.py
packages/contracts/src/tuntun_contracts/ui.py
packages/contracts/openapi/admin-v1.yaml
packages/ui-contracts/src/generated/private-ai-v1.ts
schemas/private-ai/v1/
├── inference-v1.schema.json
├── model-artifact-v1.schema.json
├── appliance-decision-v1.schema.json
├── knowledge-v1.schema.json
├── desktop-v1.schema.json
├── robotics-v1.schema.json
├── lilygo-v1.schema.json
└── ui-v1.schema.json
schemas/vision/v1/selected-frame-v1.schema.json
fixtures/synthetic/private-ai/
├── contracts/
├── route-corpus-v1.jsonl
├── model-manifests-v1.json
├── knowledge-sources-v1.json
├── desktop-registry-v1.json
├── robot-capabilities-v1.json
├── lilygo-states-v1.json
└── fault-matrix-v1.json
fixtures/adversarial/private-ai/
├── knowledge-injection-v1.jsonl
├── desktop-output-v1.jsonl
├── selected-frame-v1.jsonl
└── model-output-v1.jsonl
fixtures/synthetic/features/phase5-private-ai-manifest-v1.json
fixtures/synthetic/ui/phase5/

apps/core/src/tuntun_core/domain/
├── private_ai.py
├── knowledge.py
├── desktop.py
└── robotics.py
apps/core/src/tuntun_core/services/private_ai/
├── artifact_registry.py
├── artifact_acquisition.py
├── artifact_verifier.py
├── inference_gateway.py
├── inference_validation.py
├── inference_budget.py
├── task_cells.py
├── route_registry.py
├── route_policy.py
├── knowledge_binding.py
├── knowledge_import.py
├── knowledge_index.py
├── knowledge_acl.py
├── knowledge_retrieval.py
├── knowledge_lifecycle.py
├── knowledge_recovery.py
├── knowledge_vectors.py
├── desktop_authority.py
├── desktop_assistance.py
├── desktop_dlp.py
├── desktop_egress.py
├── desktop_jobs.py
├── desktop_workflows.py
├── perception_gateway.py
├── perception_policy.py
├── robot_policy.py
├── privacy_effects.py
├── restore.py
└── health.py
apps/core/src/tuntun_core/adapters/inference/
├── local_mac.py
├── appliance.py
└── cloud.py
apps/core/src/tuntun_core/adapters/knowledge/
├── root.py
├── objects.py
├── parser.py
├── recovery.py
└── catalog/
    ├── database.py
    ├── models.py
    ├── repository.py
    └── migrations/
        ├── 0001_knowledge_sources.py
        ├── 0002_knowledge_fts.py
        ├── 0003_knowledge_embeddings.py
        └── 0004_knowledge_recovery.py
apps/core/src/tuntun_core/adapters/desktop/helper_client.py
apps/core/src/tuntun_core/adapters/perception/appliance.py
apps/core/src/tuntun_core/adapters/robot/edge_client.py
apps/core/src/tuntun_core/adapters/sqlcipher/
├── private_ai_registry_repository.py
├── desktop_authority_repository.py
└── robotics_repository.py
apps/core/src/tuntun_core/services/vision/
├── selected_frame_broker.py
└── observation_consumer.py
apps/core/src/tuntun_core/api/routes/private_ai.py
apps/core/src/tuntun_core/api/routes/knowledge.py
apps/core/src/tuntun_core/api/routes/desktop.py
apps/core/src/tuntun_core/api/routes/perception.py
apps/core/src/tuntun_core/api/routes/robotics.py
apps/core/src/tuntun_core/api/phase5_dtos.py
apps/core/src/tuntun_core/api/app.py
apps/core/src/tuntun_core/bootstrap/container.py
apps/owner-ingress/src/tuntun_owner_ingress/router.py
ops/routes/owner-ingress-routes.v1.json
ops/services/phase3-owner-ingress.v1.json
apps/core/migrations/versions/
├── 0020_private_ai_registry.py
├── 0021_desktop_authority.py
└── 0022_robotics.py

apps/inference-proxy/src/tuntun_inference_proxy/
├── server.py
├── verifier.py
├── quotas.py
├── runtime.py
├── cancellation.py
└── health.py
apps/perception-proxy/src/tuntun_perception_proxy/
├── server.py
├── verifier.py
├── frames.py
├── runtime.py
└── cleanup.py
apps/desktop-helper/src/tuntun_desktop_helper/
├── server.py
├── peer.py
├── grants.py
├── paths.py
├── command_registry.py
├── executor.py
├── sandbox.py
├── receipts.py
└── health.py
apps/robot-edge/src/tuntun_robot_edge/
├── agent.py
├── pairing.py
├── protocol.py
├── safety_supervisor.py
├── estop.py
├── motor.py
├── sensors.py
├── geofence.py
├── watchdog.py
├── camera.py
├── battery.py
└── health.py
firmware/lilygo-status/

apps/admin/src/features/ai-workspace/
├── index.ts
├── models.tsx
├── knowledge.tsx
├── desktop.tsx
├── desktop-grant.tsx
├── desktop-egress.tsx
├── desktop-job-result.tsx
├── perception.tsx
├── robotics.tsx
├── lilygo.tsx
└── health.tsx
apps/admin/src/routes/ai-workspace-models.tsx
apps/admin/src/routes/ai-workspace-knowledge.tsx
apps/admin/src/routes/ai-workspace-desktop.tsx
apps/admin/src/routes/ai-workspace-perception.tsx
apps/admin/src/routes/ai-workspace-robotics.tsx
apps/admin/src/api/generated/admin-v1.ts
apps/admin/src/app/feature-registry.ts
apps/admin/src/app/router.tsx

packages/testing/src/tuntun_testing/private_ai/
├── fake_clock.py
├── fake_runtime.py
├── fake_knowledge.py
├── fake_desktop.py
├── fake_perception.py
├── fake_robot.py
├── fault_points.py
└── scenario.py
scripts/phase5/
├── generate_schemas.py
├── build_corpora.py
├── inventory.py
├── benchmark_control_host.py
├── evaluate_task_cells.py
├── verify_model_artifact.py
├── evaluate_appliance.py
├── verify_appliance_network.py
├── qualify_knowledge_root.py
├── verify_knowledge_recovery.py
├── evaluate_vectors.py
├── qualify_desktop_helper.py
├── qualify_d4_sandbox.py
├── run_selected_frame_gate.py
├── inventory_raspbot.py
├── qualify_estop.py
├── run_robot_floor.py
├── run_lilygo_trial.py
├── run_fault_matrix.py
├── measure_maintenance.py
├── run_acceptance.py
└── verify_acceptance.py
ops/launchd/phase5/
ops/services/phase5-*.v1.json
ops/inference-appliance/
ops/knowledge/
ops/desktop/
ops/robot-edge/
docs/operations/phase5-*.md
docs/privacy/phase5-*.md
docs/procurement/phase5-*.md
docs/evidence/phase5-*.schema.json
tests/{unit,contract,property,integration,security,privacy,ui,fault,performance,hardware,acceptance}/private_ai/
```

## Frozen Phase 5 Service Deployment Baseline

Every separately packaged Phase 5 process exposes injectable `run(argv, runtime) -> int` plus side-effect-free `--help` and `--version`, a `start --config <absolute-path>` command, and a bounded read-only `health --config <same-path> --json` command. `start` rejects root, the wrong effective account, a missing/non-regular/symlinked configuration, or wrong owner/mode before opening a key, model, selected file, media buffer, device, runtime path, socket, listener, or log. Every macOS plist uses `WorkingDirectory=/`, an empty nonessential environment, no shell, `python -m`, `PATH` lookup, writable executable, or unresolved install token, `KeepAlive={SuccessfulExit=false}`, `ThrottleInterval=10`, and core dumps disabled. Configuration parents are root-owned mode `0755`; each configuration is root-owned, group-readable only by its named service account, and mode `0640`. Runtime parents are root-created/no-follow; service sockets are mode `0660` and admit only the named account plus the pinned Core peer.

The installed commands and service identities are exact:

| Signed inventory ID | Job/target | Exact installed start command | Account | Config and runtime boundary |
|---|---|---|---|---|
| `phase5-inference-proxy.v1` | `com.tuntun.inference-proxy` / macOS | `/Applications/Tuntun.app/Contents/Resources/venv/bin/tuntun-inference-proxy start --config /Library/Application Support/Tuntun/phase5/inference-proxy.v1.json` | `_tuntun_inference` | config above; `/private/var/run/tuntun/inference-proxy.sock` |
| `phase5-desktop-helper.v1` | `com.tuntun.desktop-helper` / macOS | `/Applications/Tuntun.app/Contents/Resources/venv/bin/tuntun-desktop-helper start --config /Library/Application Support/Tuntun/phase5/desktop-helper.v1.json` | `_tuntun_desktop` | config above; `/private/var/run/tuntun/desktop-helper.sock` |
| `phase5-perception-proxy.v1` | `perception-proxy` / isolated appliance Compose | `/opt/tuntun/current/.venv/bin/tuntun-perception-proxy start --config /etc/tuntun/perception-proxy.toml` | `tuntun-perception:tuntun-perception` | root-owned mode-`0640` config; `/run/tuntun-perception-proxy`; mTLS TCP `9444` from pinned Mac only |
| `phase5-robot-edge.v1` | `tuntun-robot-edge.service` / Raspbot Linux | `/opt/tuntun/current/.venv/bin/tuntun-robot-edge start --config /etc/tuntun/robot-edge.toml` | `tuntun-robot-edge:tuntun-robot-edge` | root-owned mode-`0640` config; `/run/tuntun-robot-edge`; paired state `/var/lib/tuntun-robot-edge` |

If and only if Task 15's delivered appliance gate is positive, `phase5-inference-proxy.v1` gains a second target record named `appliance_compose`: compose service `inference-proxy`, exact command `/opt/tuntun/current/.venv/bin/tuntun-inference-proxy start --config /etc/tuntun/inference-proxy.toml`, account `tuntun-inference:tuntun-inference`, root-owned mode-`0640` config, runtime `/run/tuntun-inference-proxy`, and mTLS TCP `9443` admitted only from the pinned Mac identity/address. The Mac and appliance target records have different service certificates, configuration/job digests, health evidence, and cleanup sets. A release may carry either or both only when the corresponding signed task-cell feature facts are enabled; neither target inherits the other's identity or lifecycle result.

The robot unit additionally freezes `RuntimeDirectory=tuntun-robot-edge`, `Restart=on-failure`, `RestartSec=5s`, `StartLimitIntervalSec=60`, `StartLimitBurst=3`, `NoNewPrivileges=yes`, read-only system roots, bounded memory/tasks/files, private temporary storage, disabled core dumps, and only the paired outbound Mac destination. It never binds a vendor control port to a non-loopback address.

Each `ops/services/phase5-*.v1.json` row is covered by the release signature and binds the distribution/wheel digest, exact entry point, target architecture/platform, plist or unit digest, account/group, configuration path/owner/mode/digest, socket/listener or runtime directory/mode, restart policy, health deadline, firewall profile where applicable, and exact service-owned cleanup paths. The cleanup set never includes a model artifact, knowledge object, owner document, camera recording, vendor file, or unrelated account. A release includes a target record and all of its package/job/config/account artifacts only when the signed Phase 5 feature manifest enables that service on that target; otherwise those production artifacts and that target record are absent, and the absence probe must pass. If a service family has no enabled targets, its whole row is absent. Simulator source alone is not a packaged service.

Every service lifecycle test renders the installed artifact and proves exact argv/executable containment in the signed release, start, bounded health, SIGTERM, deliberate crash/restart with a strictly newer boot generation and no authority replay, wrong-account and wrong-config rejection before effects, stale-socket/listener/runtime cleanup, and both preserve-data and destroy-managed-data uninstall cleanup. Package, job, manifest, feature state, and target must be a one-to-one set: any missing/extra row or artifact, digest/path/account drift, failed health, restart resurrection, or owned residue blocks Phase 5 acceptance and the later Phase 6 install/update/uninstall gate.

A signed side-process row is usable only for the exact bytes it binds, and freshness is required before—not after—actual gated use. Task 26 makes the Task 25 desktop-helper row stale; Task 28 rebuilds/re-signs it and reruns installed lifecycle before P5-4 owner use. Task 29 makes that row stale again; Task 30 refreshes it after the Task 29 registry plus Task 30 executor before D3 execution. Task 31 refreshes it again after adding the sandbox and before actual D4 qualification; Task 32 refreshes it after final executor/sandbox changes before any actual D4 workflow; Task 33 verifies the applicable current D3-only or D3+D4 row before its UI gate. Likewise, every edge-code mutation in Tasks 39, 40, 42, and 43 rebuilds/re-signs `phase5-robot-edge.v1` and reruns the target lifecycle before that task's physical/effect campaign; Tasks 41 and 44 independently verify the current row before session and soak use. A stale interval permits only source/unit tests that cannot reach files, processes, devices, media, or motion; actual helper/robot execution is denied. Task 48 still rescans and regenerates all four Phase 5 families from final bytes.

Phase 3's `tuntun-owner-ingress` remains the sole owner-facing HTTP process and LAN listener. Core remains reachable from it only over the existing authenticated Core Unix-domain socket; Phase 5 never starts another HTTP listener. Route modules export pure injected factories: no import may call `include_router`, append a route, resolve a dependency, read feature state, or open a socket. Owner-route checkpoint Tasks 07, 13, 24, 28, 30, 33, 36, 41, 42, 45, and 46 each own one atomic production composition delta because their installed owner flow or physical/elapsed gate depends on it. Each checkpoint updates `bootstrap/container.py`, `api/app.py`, the owner-ingress allowlist router and signed route manifest; rebuilds the final candidate `tuntun-owner-ingress` wheel; refreshes/re-signs `phase3-owner-ingress.v1` against that wheel and manifest; proves an enabled route through listener -> ingress -> authenticated Core UDS; proves unknown/disabled routes return indistinguishable `404` without Core dispatch; and completes takeover/start/health/crash-restart/update/rollback/preserve-uninstall/destroy-uninstall before collecting checkpoint evidence. The change is staged as one immutable candidate set and never exposes a mixed graph. Task 35 is explicitly not an owner-route checkpoint: selected frames travel through the dedicated outbound perception gateway/proxy protocol, not an inbound Core HTTP route; `perception.py` is first created and exposed by Task 36. Task 48 repeats the same procedure after all route and optional-family changes and owns the final candidate composition; external P5-9 release-manifest publication remains post-commit and post-campaign.

The shared checkpoint test is first-created in Task 07 as `tests/integration/private_ai/test_phase5_owner_ingress_composition.py` and extended by every later owner-route checkpoint. Its mandatory regression set is `tests/integration/deploy/test_owner_ingress_route_manifest.py`, `tests/integration/vision/test_deployed_process_entrypoints.py`, `tests/integration/deploy/test_phase3_side_process_lifecycle.py`, `tests/integration/vision/test_owner_ingress_takeover.py`, and `tests/fault/vision/test_owner_ingress_takeover_rollback.py`. Every checkpoint runs those tests against its exact candidate row before accepting UI, physical, soak, or elapsed evidence; a stale previous row is expected to fail. Logical feature registration can happen before composition, but the route is not called enabled for a checkpoint until this installed-chain gate passes.

## Frozen Contract and Port Baseline

All fields below are required unless explicitly optional. Models are frozen, `extra="forbid"`, NFC-normalized, aware UTC with six fractional digits, collection/string/body bounded, and JCS canonical where signed. Implementers may add private helpers but cannot rename, widen, or add authority-bearing public fields.

```python
# packages/contracts/src/tuntun_contracts/private_ai/base.py
from tuntun_contracts.base import ContractModel,canonical_mapping_bytes

class PrivateAIContract(ContractModel):
    model_config=ConfigDict(
        extra="forbid",frozen=True,strict=True,validate_assignment=True,
        str_strip_whitespace=True,
    )

def canonical_private_ai_bytes(value:PrivateAIContract) -> bytes:
    return canonical_mapping_bytes(value.model_dump(mode="python"))
```

```python
# packages/contracts/src/tuntun_contracts/private_ai/inference.py
from tuntun_contracts.identity import PersonaProjection

class InferenceSegmentV1(PrivateAIContract):
    segment_id: UUID
    kind: Literal["user_text", "approved_memory_excerpt", "knowledge_excerpt", "command_output"]
    trust_class: Literal["user_statement", "untrusted_retrieval", "untrusted_tool_output"]
    content_or_single_use_ref: BoundedContentOrSingleUseRef
    token_or_byte_count: NonNegativeBoundedCount
    provenance_commitment: HmacCommitment

    @model_validator(mode="after")
    def exact_kind_to_trust_class(self) -> "InferenceSegmentV1":
        expected = {
            "user_text": "user_statement",
            "approved_memory_excerpt": "untrusted_retrieval",
            "knowledge_excerpt": "untrusted_retrieval",
            "command_output": "untrusted_tool_output",
        }[self.kind]
        if self.trust_class != expected:
            raise ValueError("inference_segment_trust_class_mismatch")
        return self

class SanitizedInferenceRequestV1(PrivateAIContract):
    request_id: UUID
    schema_version: Literal["1.0"]
    household_session_pseudonym: OpaquePurposeScopedId
    turn_id: UUID
    task_class: RegisteredTaskClass
    capability_required: RegisteredModelCapability
    sensitivity_class: RegisteredSensitivity
    allowed_execution_zone: Literal["local_mac", "local_appliance", "approved_cloud"]
    persona_descriptor: PersonaProjection
    language_mode: Literal["en", "hi", "hinglish"]
    input_segments: Annotated[tuple[InferenceSegmentV1, ...], Field(min_length=1, max_length=32)]
    response_schema_id: RegisteredResponseSchemaId
    max_input_tokens: PositiveBoundedTokenCount
    max_output_tokens: PositiveBoundedTokenCount
    deadline_at: AwareDatetime
    cancellation_id: UUID
    policy_version: PolicyVersion
    prompt_template_digest: Sha256Digest
    model_route_policy_digest: Sha256Digest
    consent_receipt_commitments: Annotated[tuple[HmacCommitment, ...], Field(max_length=16)]
    desktop_model_egress_authorization_commitment: HmacCommitment | None
    budget_or_power_reservation_id: UUID
    key_id: KeyId
    signature: P256Signature

    @model_validator(mode="after")
    def unique_inference_segments_and_consents(self) -> "SanitizedInferenceRequestV1":
        if len({segment.segment_id for segment in self.input_segments}) != len(self.input_segments):
            raise ValueError("duplicate_inference_segment")
        if len(set(self.consent_receipt_commitments)) != len(self.consent_receipt_commitments):
            raise ValueError("duplicate_inference_consent_receipt")
        return self

class BoundedSafeRefusalV1(PrivateAIContract):
    reason_code: Literal["policy_refusal", "model_refusal"]
    message_id: Literal["inference.refused.policy", "inference.refused.model"]

    @model_validator(mode="after")
    def exact_reason_message_pair(self) -> "BoundedSafeRefusalV1":
        expected = {
            "policy_refusal": "inference.refused.policy",
            "model_refusal": "inference.refused.model",
        }[self.reason_code]
        if self.message_id != expected:
            raise ValueError("inference_refusal_reason_message_mismatch")
        return self

class InferenceResultBaseV1(PrivateAIContract):
    request_id: UUID
    schema_version: Literal["1.0"]
    response_schema_id: RegisteredResponseSchemaId
    request_commitment: HmacCommitment
    model_artifact_id: StableModelId
    model_digest: Sha256Digest
    tokenizer_digest: Sha256Digest
    quantization: BoundedSafeCode
    runtime_name: BoundedSafeCode
    runtime_version: BoundedSafeCode
    prompt_template_digest: Sha256Digest
    input_tokens: NonNegativeBoundedTokenCount
    output_tokens: NonNegativeBoundedTokenCount
    first_token_ms: NonNegativeMilliseconds
    total_ms: NonNegativeMilliseconds
    safety_flags: Annotated[tuple[RegisteredSafetyFlag, ...], Field(max_length=16)]
    server_receipt_id: UUID
    proxy_key_id: KeyId
    signature: P256Signature

    @model_validator(mode="after")
    def unique_bounded_safety_flags(self) -> "InferenceResultBaseV1":
        if len(set(self.safety_flags)) != len(self.safety_flags):
            raise ValueError("duplicate_inference_safety_flag")
        return self

class CompletedInferenceResultV1(InferenceResultBaseV1):
    status: Literal["completed"]
    output: RegisteredSuccessfulInferenceOutput
    finish_reason: Literal["completed"]

class RefusedInferenceResultV1(InferenceResultBaseV1):
    status: Literal["refused"]
    output: BoundedSafeRefusalV1
    finish_reason: Literal["policy_refusal", "model_refusal"]

    @model_validator(mode="after")
    def exact_refusal_reason(self) -> "RefusedInferenceResultV1":
        if self.output.reason_code != self.finish_reason:
            raise ValueError("inference_refusal_finish_reason_mismatch")
        return self

class CancelledInferenceResultV1(InferenceResultBaseV1):
    status: Literal["cancelled"]
    output: None = None
    finish_reason: Literal["cancelled"]

class TimedOutInferenceResultV1(InferenceResultBaseV1):
    status: Literal["timed_out"]
    output: None = None
    finish_reason: Literal["deadline_exceeded"]

class FailedInferenceResultV1(InferenceResultBaseV1):
    status: Literal["failed"]
    output: None = None
    finish_reason: Literal["runtime_failure", "schema_failure", "integrity_failure"]

InferenceResultV1 = Annotated[
    CompletedInferenceResultV1
    | RefusedInferenceResultV1
    | CancelledInferenceResultV1
    | TimedOutInferenceResultV1
    | FailedInferenceResultV1,
    Field(discriminator="status"),
]

class CancellationReceiptV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    cancellation_id: UUID
    generation: Annotated[int, Field(ge=1)]
    state: Literal["cancelled", "already_terminal", "unknown"]
    work_started: bool
    result_discarded: bool
    occurred_at: AwareDatetime
    receipt_commitment: HmacCommitment

class RouteDecisionV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    decision_id: UUID
    request_id: UUID
    request_commitment: HmacCommitment
    task_class: RegisteredTaskClass
    capability_required: RegisteredModelCapability
    response_schema_id: RegisteredResponseSchemaId
    language_mode: Literal["en", "hi", "hinglish"]
    profile_class: Literal["owner", "adult", "k2", "n1", "guest"]
    sensitivity_class: RegisteredSensitivity
    traffic_class: Literal["live_household", "synthetic_or_deidentified_evaluation"]
    data_egress_class: Literal["local_only", "approved_cloud_eligible"]
    raw_media_present: bool
    task_cell_stage: Literal["M0", "M1", "M2", "M3", "M4", "M5"]
    model_artifact_id: StableModelId
    model_artifact_digest: Sha256Digest
    tokenizer_digest: Sha256Digest
    runtime_artifact_digest: Sha256Digest
    prompt_template_digest: Sha256Digest
    evaluation_bundle_digest: Sha256Digest
    route_policy_digest: Sha256Digest
    task_cell_activation_generation: Annotated[int, Field(ge=1)]
    profile_eligibility: Literal["eligible", "ineligible"]
    child_eligibility: Literal["not_applicable", "eligible", "ineligible"]
    consent_receipt_commitments: Annotated[tuple[HmacCommitment, ...], Field(max_length=16)]
    privacy_generation: Annotated[int, Field(ge=1)]
    policy_version: PolicyVersion
    preemption_state: Literal["clear", "privacy", "voice", "recording", "backup"]
    local_execution_zone_assessed: Literal["local_mac", "local_appliance", "not_applicable"]
    local_health: Literal["eligible", "pressured", "preempted", "unavailable", "not_applicable"]
    local_available_memory_mib: Annotated[int, Field(ge=0)]
    local_queue_depth: Annotated[int, Field(ge=0, le=32)]
    local_temperature_state: Literal["normal", "warm", "hot", "unknown", "not_applicable"]
    local_deadline_feasible: bool
    cloud_eligibility: Literal[
        "eligible", "consent_denied", "provider_unreviewed", "wan_unavailable",
        "egress_denied", "budget_denied", "not_applicable",
    ]
    selected_route: Literal["local_mac", "local_appliance", "approved_cloud", "no_eligible_route"]
    reservation_id: UUID | None
    reservation_generation: Annotated[int | None, Field(ge=1)]
    cancellation_id: UUID
    cancellation_generation: Annotated[int, Field(ge=1)]
    reason_code: BoundedSafeCode
    request_deadline_at: AwareDatetime
    decided_at: AwareDatetime
    valid_until: AwareDatetime
    decision_commitment: HmacCommitment

    @model_validator(mode="after")
    def exact_route_authority_and_evidence(self) -> "RouteDecisionV1":
        if len(set(self.consent_receipt_commitments)) != len(self.consent_receipt_commitments):
            raise ValueError("duplicate_route_consent_commitment")
        child_profile = self.profile_class in {"k2", "n1"}
        if child_profile != (self.child_eligibility != "not_applicable"):
            raise ValueError("route_child_eligibility_shape_invalid")
        route_selected = self.selected_route != "no_eligible_route"
        reservation_present = self.reservation_id is not None and self.reservation_generation is not None
        if (self.reservation_id is None) != (self.reservation_generation is None):
            raise ValueError("route_reservation_pair_incomplete")
        if route_selected != reservation_present:
            raise ValueError("route_reservation_shape_invalid")
        hard_denial = (
            self.profile_eligibility == "ineligible"
            or self.child_eligibility == "ineligible"
            or self.raw_media_present
            or self.preemption_state != "clear"
        )
        if hard_denial and route_selected:
            raise ValueError("hard_policy_denial_cannot_select_route")
        local_assessed = self.local_execution_zone_assessed != "not_applicable"
        local_fact_shape = (
            self.local_health != "not_applicable"
            and self.local_temperature_state != "not_applicable"
        )
        if local_assessed != local_fact_shape:
            raise ValueError("local_route_assessment_shape_invalid")
        if not local_assessed and (
            self.local_available_memory_mib != 0
            or self.local_queue_depth != 0
            or self.local_deadline_feasible
        ):
            raise ValueError("unassessed_local_route_has_resource_claim")
        if self.selected_route in {"local_mac", "local_appliance"}:
            if self.profile_class == "guest":
                raise ValueError("guest_local_route_requires_explicit_future_promotion")
            if child_profile and self.task_cell_stage != "M5":
                raise ValueError("child_local_route_requires_m5")
            if child_profile and not self.consent_receipt_commitments:
                raise ValueError("child_local_route_requires_current_consent")
            if self.local_execution_zone_assessed != self.selected_route:
                raise ValueError("selected_local_route_not_assessed")
            if (
                self.local_health != "eligible"
                or self.local_available_memory_mib == 0
                or not self.local_deadline_feasible
            ):
                raise ValueError("selected_local_route_not_healthy")
            if self.task_cell_stage == "M0":
                raise ValueError("m0_cannot_select_local_route")
        if self.selected_route == "local_appliance":
            if self.task_cell_stage == "M1":
                raise ValueError("m1_cannot_select_appliance")
            if self.task_cell_stage == "M2" and self.traffic_class != "synthetic_or_deidentified_evaluation":
                raise ValueError("m2_appliance_route_is_shadow_only")
            if self.task_cell_stage == "M3" and self.profile_class != "owner":
                raise ValueError("m3_appliance_route_is_owner_only")
            if self.task_cell_stage == "M4" and self.profile_class not in {"owner", "adult"}:
                raise ValueError("m4_appliance_route_is_adult_only")
        if self.selected_route == "approved_cloud":
            if self.data_egress_class != "approved_cloud_eligible":
                raise ValueError("local_only_cannot_select_cloud")
            if self.cloud_eligibility != "eligible" or not self.consent_receipt_commitments:
                raise ValueError("cloud_route_lacks_current_eligibility")
        if not (
            self.decided_at
            < self.valid_until
            <= min(self.decided_at + timedelta(seconds=5), self.request_deadline_at)
        ):
            raise ValueError("route_decision_window_invalid")
        return self

# packages/contracts/src/tuntun_contracts/private_ai/artifacts.py
class RuntimeRequirementV1(PrivateAIContract):
    runtime_name: BoundedSafeCode
    runtime_version: BoundedSafeCode
    runtime_artifact_digest: Sha256Digest
    supported_host_architectures: Annotated[
        tuple[Literal["x86_64", "arm64"], ...],
        Field(min_length=1, max_length=2),
    ]
    accelerator_policy: Literal["cpu_only", "metal_optional", "metal_required"]
    required_cpu_features: Annotated[
        tuple[Literal["avx2", "fma"], ...],
        Field(max_length=2),
    ]
    maximum_worker_threads: Annotated[int, Field(ge=1, le=16)]

    @model_validator(mode="after")
    def exact_runtime_requirement(self) -> "RuntimeRequirementV1":
        if len(set(self.supported_host_architectures)) != len(self.supported_host_architectures):
            raise ValueError("duplicate_runtime_host_architecture")
        if len(set(self.required_cpu_features)) != len(self.required_cpu_features):
            raise ValueError("duplicate_runtime_cpu_feature")
        if "x86_64" not in self.supported_host_architectures and self.required_cpu_features:
            raise ValueError("arm_only_runtime_cannot_require_x86_cpu_features")
        return self

class ModelArtifactManifestV1(PrivateAIContract):
    model_artifact_id: StableModelId
    upstream_name_and_revision: BoundedProvenanceCode
    source_urls: Annotated[tuple[HttpsUrl, ...], Field(min_length=1, max_length=8)]
    licence_ids: Annotated[tuple[SpdxLicenceId, ...], Field(min_length=1, max_length=8)]
    redistribution_allowed: bool
    weights_digest: Sha256Digest
    tokenizer_digest: Sha256Digest
    prompt_template_digest: Sha256Digest
    architecture: BoundedSafeCode
    parameter_count: PositiveBoundedCount
    quantization_and_calibration: BoundedSafeCode
    context_limit: PositiveBoundedTokenCount
    required_runtime_and_accelerator: RuntimeRequirementV1
    minimum_memory_evidence: EvidenceReference
    supported_task_classes: Annotated[tuple[RegisteredTaskClass, ...], Field(min_length=1, max_length=32)]
    prohibited_task_classes: Annotated[tuple[RegisteredTaskClass, ...], Field(max_length=32)]
    evaluation_bundle_digest: Sha256Digest
    approved_routes: Annotated[tuple[RegisteredExecutionZone, ...], Field(min_length=1, max_length=3)]
    activated_at: AwareDatetime | None
    revoked_at: AwareDatetime | None

    @model_validator(mode="after")
    def unique_disjoint_bounded_manifest(self) -> "ModelArtifactManifestV1":
        for values, code in (
            (self.source_urls, "duplicate_model_source_url"),
            (self.licence_ids, "duplicate_model_licence"),
            (self.supported_task_classes, "duplicate_supported_model_task"),
            (self.prohibited_task_classes, "duplicate_prohibited_model_task"),
            (self.approved_routes, "duplicate_approved_model_route"),
        ):
            if len(set(values)) != len(values):
                raise ValueError(code)
        if set(self.supported_task_classes) & set(self.prohibited_task_classes):
            raise ValueError("model_task_supported_and_prohibited")
        if self.revoked_at is not None and (
            self.activated_at is None or self.revoked_at <= self.activated_at
        ):
            raise ValueError("model_artifact_revocation_timeline_invalid")
        return self
```

Camera frames are invalid language segments. Knowledge/web/desktop-output response schemas contain no action or memory proposal. The runtime resolves the digest-pinned prompt template locally and supplies its policy/system instructions out-of-band; no caller segment kind or trust class can represent policy/system text. `user_text -> user_statement`, both approved-memory and knowledge excerpts `-> untrusted_retrieval`, and `command_output -> untrusted_tool_output` are the complete mapping. Route verification rejects cross-kind elevation before signing or serialization and binds the exact activated artefact/runtime/tokenizer/template/evaluation cell, deadline, cancellation generation, policy, consent, reservation, and optional desktop-egress consumption. Guest and child restrictions added by Phase 5 apply only to promoted local routes: an M0/approved-cloud attempt continues to use the canonical Phase 1 exact-disclosure and current guardian-consent gateway, while child web remains denied. `InferenceResultV1` is a discriminated closed union: only `completed` carries a registered successful output; `refused` carries only its bounded safe-refusal variant; cancelled, timed-out, and failed results carry no content. No variant can contain a tool, memory, action, desktop, media, or robot proposal.

```python
# packages/contracts/src/tuntun_contracts/private_ai/procurement.py
from datetime import date
from zoneinfo import ZoneInfo

SINGAPORE = ZoneInfo("Asia/Singapore")

class NoPurchaseDecisionV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    decision_id: UUID
    decision: Literal["no_purchase"]
    rationale_code: Literal[
        "mac_sufficient", "quality_gap_unproved", "tco_unfavorable",
        "compatibility_unproved", "ups_unproved", "candidate_blocked", "deferred",
    ]
    mac_benchmark_evidence_digest: Sha256Digest
    task_cell_evaluation_digest: Sha256Digest
    actual_mac_gap: Literal["none", "bounded", "material", "unproved"]
    decided_at: AwareDatetime
    decision_commitment: HmacCommitment

class PurchaseCandidateDecisionV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    decision_id: UUID
    decision: Literal["purchase_candidate"]
    candidate_sku_and_revision_commitment: HmacCommitment
    quote_commitment: HmacCommitment
    quote_collected_at: AwareDatetime
    quote_local_date: date
    currency: Literal["SGD"]
    base_price_cents: Annotated[int, Field(ge=1)]
    shipping_cents: Annotated[int, Field(ge=0)]
    gst_basis_points: Literal[900]
    tax_cents: Annotated[int, Field(ge=0)]
    delivered_total_cents: Annotated[int, Field(ge=1)]
    annual_energy_kwh_milli: Annotated[int, Field(ge=0)]
    energy_tariff_micros_per_kwh: Annotated[int, Field(ge=1)]
    energy_36_month_cents: Annotated[int, Field(ge=0)]
    support_36_month_cents: Annotated[int, Field(ge=0)]
    support_and_warranty_commitment: HmacCommitment
    warranty_months: Annotated[int, Field(ge=12, le=60)]
    return_window_days: Annotated[int, Field(ge=1, le=90)]
    expected_owner_time_36_month_minutes: Annotated[int, Field(ge=0, le=36_000)]
    owner_time_rate_cents_per_hour: Annotated[int, Field(ge=0)]
    exit_cost_cents: Annotated[int, Field(ge=0)]
    tco_36_month_cents: Annotated[int, Field(ge=1)]
    improved_task_cell_commitments: Annotated[tuple[HmacCommitment, ...], Field(min_length=1, max_length=64)]
    model_artifact_digest: Sha256Digest
    runtime_artifact_digest: Sha256Digest
    model_runtime_compatible: Literal[True]
    usable_ram_mib: Annotated[int, Field(ge=1)]
    required_ram_mib: Annotated[int, Field(ge=1)]
    minimum_ram_headroom_mib: Annotated[int, Field(ge=1)]
    usable_storage_mib: Annotated[int, Field(ge=1)]
    required_storage_mib: Annotated[int, Field(ge=1)]
    minimum_storage_headroom_mib: Annotated[int, Field(ge=1)]
    update_path_evidence_digest: Sha256Digest
    update_path_supported: Literal[True]
    nic_firewall_mtls_isolation_evidence_digest: Sha256Digest
    nic_firewall_mtls_isolation_supported: Literal[True]
    ups_compatibility_evidence_digest: Sha256Digest
    ups_signalling_verified: Literal[True]
    ups_load_verified: Literal[True]
    ups_runtime_verified: Literal[True]
    ups_recovery_verified: Literal[True]
    risk_class: Literal["low", "bounded"]
    actual_mac_gap: Literal["material"]
    delivery_validation_required: Literal[True]
    order_authorized: Literal[False]
    decided_at: AwareDatetime
    decision_commitment: HmacCommitment

    @model_validator(mode="after")
    def exact_current_purchase_candidate(self) -> "PurchaseCandidateDecisionV1":
        local_quote_date = self.quote_collected_at.astimezone(SINGAPORE).date()
        local_decision_date = self.decided_at.astimezone(SINGAPORE).date()
        if self.quote_collected_at > self.decided_at or not (
            self.quote_local_date == local_quote_date == local_decision_date
        ):
            raise ValueError("appliance_quote_not_from_current_local_day")
        taxable_cents = self.base_price_cents + self.shipping_cents
        expected_tax = (taxable_cents * self.gst_basis_points + 5_000) // 10_000
        if self.tax_cents != expected_tax:
            raise ValueError("appliance_tax_calculation_mismatch")
        if self.delivered_total_cents != taxable_cents + self.tax_cents:
            raise ValueError("appliance_delivered_total_mismatch")
        energy_denominator = 1_000 * 10_000
        expected_energy = (
            self.annual_energy_kwh_milli * 3 * self.energy_tariff_micros_per_kwh
            + energy_denominator - 1
        ) // energy_denominator
        if self.energy_36_month_cents != expected_energy:
            raise ValueError("appliance_energy_calculation_mismatch")
        owner_time_cost = (
            self.expected_owner_time_36_month_minutes * self.owner_time_rate_cents_per_hour + 59
        ) // 60
        expected_tco = (
            self.delivered_total_cents
            + self.energy_36_month_cents
            + self.support_36_month_cents
            + owner_time_cost
            + self.exit_cost_cents
        )
        if self.tco_36_month_cents != expected_tco:
            raise ValueError("appliance_tco_calculation_mismatch")
        if self.usable_ram_mib < self.required_ram_mib + self.minimum_ram_headroom_mib:
            raise ValueError("appliance_ram_headroom_insufficient")
        if self.usable_storage_mib < self.required_storage_mib + self.minimum_storage_headroom_mib:
            raise ValueError("appliance_storage_headroom_insufficient")
        if len(set(self.improved_task_cell_commitments)) != len(self.improved_task_cell_commitments):
            raise ValueError("duplicate_appliance_task_cell_commitment")
        return self

ApplianceDecisionV1 = Annotated[
    NoPurchaseDecisionV1 | PurchaseCandidateDecisionV1,
    Field(discriminator="decision"),
]
```

```python
# packages/contracts/src/tuntun_contracts/private_ai/knowledge.py
KnowledgeAudience = Literal[
    "subject_private", "guardian_child", "household_adults", "household_all",
]

class KnowledgeAudienceBindingV1(PrivateAIContract):
    subject_id: StableSubjectId
    subject_class: Literal["owner", "adult", "k2", "n1", "guest"]
    audience: KnowledgeAudience
    audience_generation: Annotated[int, Field(ge=1)]
    guardian_generation: Annotated[int | None, Field(ge=1)]
    consent_generation: Annotated[int, Field(ge=1)]
    child_safe_classification: Literal["approved", "not_applicable"]
    child_safe_approval_generation: Annotated[int | None, Field(ge=1)]

    @model_validator(mode="after")
    def exact_subject_audience_authority(self) -> "KnowledgeAudienceBindingV1":
        if self.subject_class == "guest":
            raise ValueError("guest_knowledge_audience_forbidden")
        if self.audience == "guardian_child":
            if (
                self.subject_class not in {"k2", "n1"}
                or self.guardian_generation is None
                or self.child_safe_classification != "approved"
                or self.child_safe_approval_generation is None
            ):
                raise ValueError("guardian_child_audience_authority_invalid")
        elif self.audience == "household_all":
            if self.child_safe_classification != "approved" or self.child_safe_approval_generation is None:
                raise ValueError("household_all_missing_child_safe_approval")
            if self.subject_class in {"k2", "n1"} and self.guardian_generation is None:
                raise ValueError("child_household_all_missing_guardian_generation")
            if self.subject_class in {"owner", "adult"} and self.guardian_generation is not None:
                raise ValueError("adult_household_all_cannot_claim_child_guardian")
        elif self.audience == "household_adults":
            if self.subject_class not in {"owner", "adult"}:
                raise ValueError("household_adults_subject_class_invalid")
            if (
                self.guardian_generation is not None
                or self.child_safe_classification != "not_applicable"
                or self.child_safe_approval_generation is not None
            ):
                raise ValueError("household_adults_authority_shape_invalid")
        elif self.audience == "subject_private":
            if self.subject_class not in {"owner", "adult"}:
                raise ValueError("subject_private_subject_class_invalid")
            if (
                self.guardian_generation is not None
                or self.child_safe_classification != "not_applicable"
                or self.child_safe_approval_generation is not None
            ):
                raise ValueError("subject_private_authority_shape_invalid")
        return self

class KnowledgeStorageBindingV1(PrivateAIContract):
    binding_id: UUID
    storage_tier: Literal["internal_default", "external_named"]
    canonical_root: BoundLocalRoot
    expected_mount_point: BoundLocalMount
    expected_volume_uuid: VolumeUUID
    expected_filesystem: Literal["apfs_encrypted"]
    encryption_evidence_commitment: HmacCommitment
    quota_bytes: PositiveByteCount
    reserve_bytes: PositiveByteCount
    recovery_policy_id: UUID
    version: Annotated[int, Field(ge=1)]
    compare_and_swap_generation: Annotated[int, Field(ge=1)]
    status: Literal["commissioned", "disabled", "retired"]

class KnowledgeRecoveryPolicyV1(PrivateAIContract):
    recovery_policy_id: UUID
    destination_binding_id: UUID
    destination_volume_uuid: VolumeUUID
    encryption_key_bundle_id: KeyId
    quota_bytes: PositiveByteCount
    schedule: Literal["daily_with_weekly_rollup"]
    daily_generations: Literal[7]
    weekly_generations: Literal[4]
    rpo_hours: Literal[24]
    deletion_generation: Annotated[int, Field(ge=1)]
    policy_generation: Annotated[int, Field(ge=1)]
    last_offline_restore_at: AwareDatetime | None
    status: Literal["eligible", "ineligible", "disabled"]

    @model_validator(mode="after")
    def eligible_only_after_verified_restore(self) -> "KnowledgeRecoveryPolicyV1":
        if self.status == "eligible" and self.last_offline_restore_at is None:
            raise ValueError("eligible_knowledge_recovery_without_offline_restore")
        return self

class OwnerImportSelectionV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    import_id: UUID
    owner_subject_id: StableSubjectId
    source_kind: Literal["file", "directory"]
    source_selection_commitment: HmacCommitment
    selected_entry_count: Annotated[int, Field(ge=1, le=250)]
    selected_total_bytes: Annotated[int, Field(ge=1, le=50 * 1024 * 1024)]
    single_use_local_handle: OpaquePurposeScopedId
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    authorization_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_selection_window(self) -> "OwnerImportSelectionV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(minutes=5):
            raise ValueError("knowledge_import_selection_window_invalid")
        return self

class KnowledgeImportPolicyV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    policy_version: PolicyVersion
    audience_binding: KnowledgeAudienceBindingV1
    sensitivity_class: RegisteredSensitivity
    allowed_media_types: Annotated[
        tuple[Literal["text/plain", "text/markdown", "application/pdf", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"], ...],
        Field(min_length=1, max_length=4),
    ]
    max_files: Annotated[int, Field(ge=1, le=250)]
    max_total_bytes: Annotated[int, Field(ge=1, le=50 * 1024 * 1024)]
    retention_class: Literal["knowledge_until_deleted"]
    policy_commitment: HmacCommitment

    @model_validator(mode="after")
    def unique_import_media_types(self) -> "KnowledgeImportPolicyV1":
        if len(set(self.allowed_media_types)) != len(self.allowed_media_types):
            raise ValueError("duplicate_knowledge_import_media_type")
        return self

class KnowledgeImportReceiptV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    import_id: UUID
    state: Literal["published", "rejected", "cancelled", "failed"]
    source_id: UUID | None
    object_count: Annotated[int, Field(ge=0, le=250)]
    chunk_count: Annotated[int, Field(ge=0)]
    imported_content_commitment: HmacCommitment
    occurred_at: AwareDatetime

    @model_validator(mode="after")
    def truthful_import_terminal_shape(self) -> "KnowledgeImportReceiptV1":
        if self.state == "published":
            if self.source_id is None or self.object_count == 0:
                raise ValueError("published_knowledge_import_missing_source_or_object")
        elif self.source_id is not None or self.object_count != 0 or self.chunk_count != 0:
            raise ValueError("nonpublished_knowledge_import_claims_content")
        return self

class AuthorizedKnowledgeQueryV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    query_id: UUID
    subject_id: StableSubjectId
    session_id: UUID
    turn_id: UUID
    query_content_or_single_use_ref: BoundedContentOrSingleUseRef
    audience_binding: KnowledgeAudienceBindingV1
    sensitivity_ceiling: RegisteredSensitivity
    result_cap: Annotated[int, Field(ge=1, le=8)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    authorization_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_query_window(self) -> "AuthorizedKnowledgeQueryV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(seconds=60):
            raise ValueError("knowledge_query_window_invalid")
        return self

class KnowledgeExcerptV1(PrivateAIContract):
    excerpt_id: UUID
    source_version_commitment: HmacCommitment
    content_or_single_use_ref: BoundedContentOrSingleUseRef
    citation_location: Annotated[str, Field(min_length=1, max_length=256)]
    audience_binding: KnowledgeAudienceBindingV1
    sensitivity_class: RegisteredSensitivity
    token_count: Annotated[int, Field(ge=1, le=12_000)]
    valid_until: AwareDatetime

class KnowledgeExcerptBundleV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    query_id: UUID
    excerpts: Annotated[tuple[KnowledgeExcerptV1, ...], Field(max_length=8)]
    total_token_count: Annotated[int, Field(ge=0, le=12_000)]
    result_commitment: HmacCommitment
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def exact_bounded_retrieval_accounting(self) -> "KnowledgeExcerptBundleV1":
        if self.total_token_count != sum(item.token_count for item in self.excerpts):
            raise ValueError("knowledge_excerpt_token_total_mismatch")
        if len({item.excerpt_id for item in self.excerpts}) != len(self.excerpts):
            raise ValueError("duplicate_knowledge_excerpt")
        if any(item.valid_until < self.expires_at for item in self.excerpts):
            raise ValueError("knowledge_excerpt_expires_before_bundle")
        return self

class DeleteKnowledgeSourceV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    command_id: UUID
    owner_subject_id: StableSubjectId
    source_id: UUID
    expected_deletion_generation: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    authorization_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_delete_window(self) -> "DeleteKnowledgeSourceV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(minutes=2):
            raise ValueError("knowledge_delete_window_invalid")
        return self

class KnowledgeDeletionReceiptV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    command_id: UUID
    source_id: UUID
    deletion_generation: Annotated[int, Field(ge=1)]
    state: Literal["eligibility_revoked", "deleted", "recovery_pending", "reconciled", "failed"]
    deleted_object_count: Annotated[int, Field(ge=0)]
    deletion_commitment: HmacCommitment
    occurred_at: AwareDatetime
```

```python
# packages/contracts/src/tuntun_contracts/private_ai/desktop.py
class FilesystemIdentityV1(PrivateAIContract):
    volume_uuid: VolumeUUID
    persistent_file_id: Annotated[int, Field(ge=1)]
    birthtime_ns: Annotated[int, Field(ge=0)]
    object_type: Literal["directory"]
    snapshot_generation: Annotated[int, Field(ge=1)]
    observed_at: AwareDatetime

class DesktopRootGrantV1(PrivateAIContract):
    canonical_root_commitment: HmacCommitment
    filesystem_identity: FilesystemIdentityV1
    read_or_sandbox_write: Literal["read_only", "sandbox_write"]
    include_globs: Annotated[tuple[SafeBoundedGlob, ...], Field(min_length=1, max_length=32)]
    exclude_globs: Annotated[tuple[SafeBoundedGlob, ...], Field(max_length=32)]

    @model_validator(mode="after")
    def unique_bounded_globs(self) -> "DesktopRootGrantV1":
        if len(set(self.include_globs)) != len(self.include_globs):
            raise ValueError("duplicate_desktop_include_glob")
        if len(set(self.exclude_globs)) != len(self.exclude_globs):
            raise ValueError("duplicate_desktop_exclude_glob")
        return self

class DesktopGrantV1(PrivateAIContract):
    grant_id: UUID
    schema_version: Literal["1.0"]
    generation: Annotated[int, Field(ge=1)]
    revocation_generation: Annotated[int, Field(ge=1)]
    subject_id: StableSubjectId
    device_id: StableDeviceId
    level: Literal["D1", "D2", "D3", "D4"]
    roots: Annotated[tuple[DesktopRootGrantV1, ...], Field(min_length=1, max_length=8)]
    max_files: Annotated[int, Field(ge=1, le=250)]
    max_bytes_per_file: Annotated[int, Field(ge=1, le=5 * 1024 * 1024)]
    max_total_bytes: Annotated[int, Field(ge=1, le=50 * 1024 * 1024)]
    allowed_command_registry_ids: Annotated[tuple[RegisteredCommandId, ...], Field(max_length=16)]
    allowed_workflow_ids: Annotated[tuple[RegisteredWorkflowId, ...], Field(max_length=16)]
    execution_network_policy: Literal["none"]
    desktop_model_egress_policy: Literal["local_only", "exact_owner_exception"]
    created_at: AwareDatetime
    expires_at: AwareDatetime
    policy_version: PolicyVersion
    authorization_commitment: HmacCommitment
    revoked_at: AwareDatetime | None

    @model_validator(mode="after")
    def bounded_grant_and_level_shape(self) -> "DesktopGrantV1":
        if not self.created_at < self.expires_at <= self.created_at + timedelta(minutes=60):
            raise ValueError("desktop_grant_window_invalid")
        if self.revoked_at is not None and self.revoked_at < self.created_at:
            raise ValueError("desktop_grant_revocation_invalid")
        if any(root.read_or_sandbox_write != "read_only" for root in self.roots):
            raise ValueError("desktop_host_root_must_be_read_only")
        if self.max_bytes_per_file > self.max_total_bytes:
            raise ValueError("desktop_per_file_limit_exceeds_total")
        if self.level in {"D1", "D2"}:
            if self.allowed_command_registry_ids or self.allowed_workflow_ids or self.execution_network_policy != "none":
                raise ValueError("desktop_read_or_propose_grant_widens_authority")
        elif self.level == "D3":
            if not self.allowed_command_registry_ids or self.allowed_workflow_ids or self.execution_network_policy != "none":
                raise ValueError("desktop_d3_grant_shape_invalid")
        elif self.level == "D4":
            if self.allowed_command_registry_ids or not self.allowed_workflow_ids:
                raise ValueError("desktop_d4_grant_shape_invalid")
        if len(set(self.allowed_command_registry_ids)) != len(self.allowed_command_registry_ids):
            raise ValueError("duplicate_desktop_command_registry_id")
        if len(set(self.allowed_workflow_ids)) != len(self.allowed_workflow_ids):
            raise ValueError("duplicate_desktop_workflow_id")
        return self

class DesktopModelEgressAuthorizationV1(PrivateAIContract):
    authorization_id: UUID
    schema_version: Literal["1.0"]
    owner_subject_id: StableSubjectId
    desktop_grant_id: UUID
    desktop_grant_generation: Annotated[int, Field(ge=1)]
    selected_file_identity_commitments: Annotated[tuple[HmacCommitment, ...], Field(max_length=250)]
    selected_content_commitments: Annotated[tuple[HmacCommitment, ...], Field(max_length=250)]
    selected_command_or_workflow_output_commitments: Annotated[tuple[HmacCommitment, ...], Field(max_length=20)]
    provider_attempt_id: UUID
    exact_serialized_payload_commitment: HmacCommitment
    exact_serialized_payload_bytes: Annotated[int, Field(ge=1, le=50 * 1024 * 1024)]
    exact_serialized_payload_tokens: Annotated[int, Field(ge=1, le=120_000)]
    provider_id: RegisteredProviderId
    provider_account_id_commitment: HmacCommitment
    model_id: RegisteredModelId
    model_version_or_route_digest: Sha256Digest
    purpose: RegisteredDesktopEgressPurpose
    sensitivity_class: RegisteredSensitivity
    disclosure_text_digest: Sha256Digest
    provider_data_use_and_retention_policy_digest: Sha256Digest
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    single_use: Literal[True]
    revocation_generation: Annotated[int, Field(ge=1)]
    revoked_at: AwareDatetime | None
    authorization_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_egress_window(self) -> "DesktopModelEgressAuthorizationV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(minutes=15):
            raise ValueError("desktop_egress_window_invalid")
        if self.revoked_at is not None and self.revoked_at < self.issued_at:
            raise ValueError("desktop_egress_revocation_invalid")
        collections = (
            self.selected_file_identity_commitments,
            self.selected_content_commitments,
            self.selected_command_or_workflow_output_commitments,
        )
        flattened = tuple(item for values in collections for item in values)
        if not flattened:
            raise ValueError("desktop_egress_selection_empty")
        if any(len(set(values)) != len(values) for values in collections):
            raise ValueError("duplicate_desktop_egress_commitment")
        if len(set(flattened)) != len(flattened):
            raise ValueError("cross_collection_desktop_egress_commitment_duplicate")
        return self

class DesktopCommandProposalV1(PrivateAIContract):
    proposal_id: UUID
    registry_command_id: RegisteredCommandId
    executable_digest: Sha256Digest
    argv: Annotated[tuple[BoundedArg, ...], Field(min_length=1, max_length=64)]
    cwd_relative_to_grant: SafeRelativePath
    environment_profile_id: RegisteredEnvironmentProfile
    declared_reads: Annotated[tuple[SafeRelativePath, ...], Field(min_length=1, max_length=250)]
    declared_writes: Annotated[tuple[SafeRelativePath, ...], Field(max_length=250)]
    execution_network_policy: Literal["none"]
    timeout_seconds: PositiveBoundedSeconds
    stdout_limit_bytes: PositiveByteCount
    stderr_limit_bytes: PositiveByteCount
    purpose_summary: RegisteredMessageId
    input_state_commitment: HmacCommitment

class DesktopWorkflowStepV1(PrivateAIContract):
    step_id: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_.-]*$")]
    ordinal: Annotated[int, Field(ge=1, le=20)]
    command_registry_id: RegisteredCommandId
    argv: Annotated[tuple[BoundedArg, ...], Field(max_length=64)]
    cwd_relative_to_disposable_root: SafeRelativePath
    read_input_root_indices: Annotated[tuple[Annotated[int, Field(ge=0, le=7)], ...], Field(max_length=8)]
    disposable_write_root_indices: Annotated[tuple[Annotated[int, Field(ge=0, le=7)], ...], Field(min_length=1, max_length=8)]
    execution_network_policy: Literal["none"]
    timeout_seconds: Annotated[int, Field(ge=1, le=15 * 60)]
    stdout_limit_bytes: Annotated[int, Field(ge=0, le=50 * 1024 * 1024)]
    stderr_limit_bytes: Annotated[int, Field(ge=0, le=50 * 1024 * 1024)]
    expected_exit_codes: Annotated[tuple[Literal[0], ...], Field(min_length=1, max_length=1)]

    @model_validator(mode="after")
    def unique_step_mount_references(self) -> "DesktopWorkflowStepV1":
        if len(set(self.read_input_root_indices)) != len(self.read_input_root_indices):
            raise ValueError("duplicate_desktop_step_read_root")
        if len(set(self.disposable_write_root_indices)) != len(self.disposable_write_root_indices):
            raise ValueError("duplicate_desktop_step_write_root")
        if self.expected_exit_codes != (0,):
            raise ValueError("desktop_step_exit_codes_must_be_zero_only")
        return self

class DesktopInputRootCommitmentV1(PrivateAIContract):
    root_index: Annotated[int, Field(ge=0, le=7)]
    mounted_read_only_root: SafeRelativePath
    filesystem_identity: FilesystemIdentityV1
    content_state_commitment: HmacCommitment
    maximum_input_bytes: Annotated[int, Field(ge=1, le=50 * 1024 * 1024)]

class RegisteredOutputArtifactV1(PrivateAIContract):
    artifact_id: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_.-]*$")]
    disposable_root_index: Annotated[int, Field(ge=0, le=7)]
    relative_path: SafeRelativePath
    media_type: Literal["text/plain", "application/json", "text/csv", "application/octet-stream"]
    maximum_bytes: Annotated[int, Field(ge=1, le=100 * 1024 * 1024)]
    required: bool

class DesktopWorkflowManifestV1(PrivateAIContract):
    workflow_id: RegisteredWorkflowId
    version: Annotated[int, Field(ge=1)]
    digest: Sha256Digest
    display_name: RegisteredMessageId
    steps: Annotated[tuple[DesktopWorkflowStepV1, ...], Field(min_length=1, max_length=20)]
    command_registry_ids: Annotated[tuple[RegisteredCommandId, ...], Field(min_length=1, max_length=20)]
    input_roots_and_commitments: Annotated[tuple[DesktopInputRootCommitmentV1, ...], Field(min_length=1, max_length=8)]
    read_only_roots: Annotated[tuple[SafeRelativePath, ...], Field(min_length=1, max_length=8)]
    disposable_write_roots: Annotated[tuple[SafeRelativePath, ...], Field(min_length=1, max_length=8)]
    output_artifacts: Annotated[tuple[RegisteredOutputArtifactV1, ...], Field(max_length=20)]
    execution_network_policy: Literal["none"]
    cpu_limit: PositiveBoundedCpuCount
    memory_limit_mib: PositiveBoundedMebibytes
    wall_time_limit_seconds: PositiveBoundedSeconds
    process_limit: PositiveBoundedProcessCount
    combined_output_limit_bytes: Annotated[int, Field(ge=1, le=100 * 1024 * 1024)]
    disposable_disk_limit_bytes: Annotated[int, Field(ge=1, le=1024 * 1024 * 1024)]
    rollback_or_discard_behavior: RegisteredDiscardBehavior
    required_sandbox_backend: RegisteredSandboxBackend
    owner_authorization_commitment: HmacCommitment
    issued_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def exact_initial_d4_shape(self) -> "DesktopWorkflowManifestV1":
        if (
            self.execution_network_policy != "none"
            or self.cpu_limit != 2
            or self.memory_limit_mib != 4096
            or self.wall_time_limit_seconds != 15 * 60
            or self.process_limit != 20
            or self.combined_output_limit_bytes != 100 * 1024 * 1024
            or self.disposable_disk_limit_bytes != 1024 * 1024 * 1024
        ):
            raise ValueError("desktop_initial_d4_limits_invalid")
        if not self.input_roots_and_commitments or not self.command_registry_ids:
            raise ValueError("desktop_d4_inputs_or_commands_missing")
        if not self.read_only_roots or not self.disposable_write_roots:
            raise ValueError("desktop_d4_mount_sets_incomplete")
        if set(self.read_only_roots) & set(self.disposable_write_roots):
            raise ValueError("desktop_d4_read_write_roots_overlap")
        if len(set(self.read_only_roots)) != len(self.read_only_roots) or len(set(self.disposable_write_roots)) != len(self.disposable_write_roots):
            raise ValueError("duplicate_desktop_d4_mount_root")
        if self.rollback_or_discard_behavior != "discard_disposable_copy":
            raise ValueError("desktop_d4_discard_behavior_invalid")
        if len(set(self.command_registry_ids)) != len(self.command_registry_ids):
            raise ValueError("duplicate_desktop_d4_command_registry_id")
        step_ids = tuple(step.step_id for step in self.steps)
        ordinals = tuple(step.ordinal for step in self.steps)
        if len(set(step_ids)) != len(step_ids) or ordinals != tuple(range(1, len(self.steps) + 1)):
            raise ValueError("desktop_d4_step_identity_or_order_invalid")
        step_commands = tuple(dict.fromkeys(step.command_registry_id for step in self.steps))
        if step_commands != self.command_registry_ids:
            raise ValueError("desktop_d4_step_command_registry_mismatch")
        input_indices = tuple(root.root_index for root in self.input_roots_and_commitments)
        if input_indices != tuple(range(len(self.input_roots_and_commitments))):
            raise ValueError("desktop_d4_input_root_indices_invalid")
        if tuple(root.mounted_read_only_root for root in self.input_roots_and_commitments) != self.read_only_roots:
            raise ValueError("desktop_d4_input_mount_manifest_mismatch")
        for step in self.steps:
            if any(index >= len(self.input_roots_and_commitments) for index in step.read_input_root_indices):
                raise ValueError("desktop_d4_step_read_root_out_of_range")
            if any(index >= len(self.disposable_write_roots) for index in step.disposable_write_root_indices):
                raise ValueError("desktop_d4_step_write_root_out_of_range")
            if step.timeout_seconds > self.wall_time_limit_seconds:
                raise ValueError("desktop_d4_step_timeout_exceeds_workflow")
        artifact_ids = tuple(artifact.artifact_id for artifact in self.output_artifacts)
        artifact_paths = tuple((artifact.disposable_root_index, artifact.relative_path) for artifact in self.output_artifacts)
        if len(set(artifact_ids)) != len(artifact_ids) or len(set(artifact_paths)) != len(artifact_paths):
            raise ValueError("duplicate_desktop_d4_output_artifact")
        if any(artifact.disposable_root_index >= len(self.disposable_write_roots) for artifact in self.output_artifacts):
            raise ValueError("desktop_d4_output_root_out_of_range")
        if sum(artifact.maximum_bytes for artifact in self.output_artifacts) > self.combined_output_limit_bytes:
            raise ValueError("desktop_d4_declared_outputs_exceed_combined_limit")
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(minutes=60):
            raise ValueError("desktop_d4_manifest_window_invalid")
        return self

class DesktopReadRequestV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    request_id: UUID
    grant_id: UUID
    grant_generation: Annotated[int, Field(ge=1)]
    revocation_generation: Annotated[int, Field(ge=1)]
    root_index: Annotated[int, Field(ge=0, le=7)]
    relative_paths: Annotated[tuple[SafeRelativePath, ...], Field(min_length=1, max_length=250)]
    max_total_bytes: Annotated[int, Field(ge=1, le=50 * 1024 * 1024)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    input_state_commitment: HmacCommitment

    @model_validator(mode="after")
    def bounded_read_window(self) -> "DesktopReadRequestV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(minutes=2):
            raise ValueError("desktop_read_window_invalid")
        return self

class AuthorizedD3JobV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    job_id: UUID
    grant_id: UUID
    grant_generation: Annotated[int, Field(ge=1)]
    revocation_generation: Annotated[int, Field(ge=1)]
    command: DesktopCommandProposalV1
    confirmation_commitment: HmacCommitment
    authorized_at: AwareDatetime
    expires_at: AwareDatetime
    idempotency_key: UUID

    @model_validator(mode="after")
    def bounded_confirmation_window(self) -> "AuthorizedD3JobV1":
        if not self.authorized_at < self.expires_at <= self.authorized_at + timedelta(minutes=2):
            raise ValueError("desktop_d3_confirmation_window_invalid")
        if self.command.declared_writes:
            raise ValueError("desktop_d3_job_declares_write")
        return self

class AuthorizedD4JobV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    job_id: UUID
    grant_id: UUID
    grant_generation: Annotated[int, Field(ge=1)]
    revocation_generation: Annotated[int, Field(ge=1)]
    workflow: DesktopWorkflowManifestV1
    qualified_backend_evidence_digest: Sha256Digest
    confirmation_commitment: HmacCommitment
    authorized_at: AwareDatetime
    expires_at: AwareDatetime
    idempotency_key: UUID

    @model_validator(mode="after")
    def bounded_confirmation_window(self) -> "AuthorizedD4JobV1":
        if not self.authorized_at < self.expires_at <= self.authorized_at + timedelta(minutes=2):
            raise ValueError("desktop_d4_confirmation_window_invalid")
        return self

class SignedDesktopGrantV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    grant: DesktopGrantV1
    signature_domain: Literal["tuntun.desktop-grant.v1"]
    key_id: KeyId
    signature: P256Signature

class SignedDesktopReadRequestV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    request: DesktopReadRequestV1
    signature_domain: Literal["tuntun.desktop-read.v1"]
    key_id: KeyId
    signature: P256Signature

class SignedAuthorizedD3JobV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    job: AuthorizedD3JobV1
    signature_domain: Literal["tuntun.desktop-d3-job.v1"]
    key_id: KeyId
    signature: P256Signature

class SignedAuthorizedD4JobV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    job: AuthorizedD4JobV1
    signature_domain: Literal["tuntun.desktop-d4-job.v1"]
    key_id: KeyId
    signature: P256Signature

class HelperGrantReceiptV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    grant_id: UUID
    generation: Annotated[int, Field(ge=1)]
    revocation_generation: Annotated[int, Field(ge=1)]
    state: Literal["installed", "rejected", "expired", "revoked"]
    canonical_grant_commitment: HmacCommitment
    observed_at: AwareDatetime

class DesktopReadResultV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    request_id: UUID
    status: Literal["completed", "denied", "expired", "cancelled", "failed"]
    file_count: Annotated[int, Field(ge=0, le=250)]
    total_bytes: Annotated[int, Field(ge=0, le=50 * 1024 * 1024)]
    content_or_single_use_refs: Annotated[tuple[BoundedContentOrSingleUseRef, ...], Field(max_length=250)]
    result_commitment: HmacCommitment
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def coherent_read_result(self) -> "DesktopReadResultV1":
        if self.file_count != len(self.content_or_single_use_refs):
            raise ValueError("desktop_read_result_count_mismatch")
        if self.status == "completed":
            if self.file_count == 0:
                raise ValueError("completed_desktop_read_without_files")
        elif self.file_count != 0 or self.total_bytes != 0 or self.content_or_single_use_refs:
            raise ValueError("noncompleted_desktop_read_has_content")
        return self

class SignedDesktopAcceptedUnverifiedEvidenceV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    job_id: UUID
    canonical_job_digest: Sha256Digest
    helper_admission_commitment: HmacCommitment
    terminal_execution_receipt_commitment: HmacCommitment
    acceptance_kind: Literal["helper_observed_process_exit"]
    isolation_state: Literal["outputs_quarantined"]
    relaunch_allowed: Literal[False]
    observed_at: AwareDatetime
    signature_domain: Literal["tuntun.desktop-accepted-unverified.v1"]
    key_id: KeyId
    signature: P256Signature

class DesktopJobResultV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    job_id: UUID
    terminal_state: Literal["VERIFIED", "ACCEPTED_UNVERIFIED", "FAILED", "UNKNOWN", "EXPIRED"]
    started: bool
    stdout_ref: BoundedContentOrSingleUseRef | None
    stderr_ref: BoundedContentOrSingleUseRef | None
    output_artifact_commitments: Annotated[tuple[HmacCommitment, ...], Field(max_length=20)]
    cleanup_state: Literal["verified", "unverified", "not_applicable"]
    accepted_unverified_evidence: SignedDesktopAcceptedUnverifiedEvidenceV1 | None
    result_commitment: HmacCommitment
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def coherent_job_result(self) -> "DesktopJobResultV1":
        has_output = self.stdout_ref is not None or self.stderr_ref is not None or bool(self.output_artifact_commitments)
        has_acceptance_evidence = self.accepted_unverified_evidence is not None
        if len(set(self.output_artifact_commitments)) != len(self.output_artifact_commitments):
            raise ValueError("duplicate_desktop_output_artifact_commitment")
        if self.terminal_state == "VERIFIED":
            valid = self.started and self.cleanup_state == "verified" and not has_acceptance_evidence
        elif self.terminal_state == "ACCEPTED_UNVERIFIED":
            valid = self.started and self.cleanup_state == "unverified" and has_acceptance_evidence
        elif self.terminal_state == "UNKNOWN":
            valid = self.started and self.cleanup_state == "unverified" and not has_acceptance_evidence
        elif self.terminal_state == "FAILED":
            valid = (
                (self.started and self.cleanup_state == "verified")
                or (not self.started and not has_output and self.cleanup_state == "not_applicable")
            ) and not has_acceptance_evidence
        else:  # EXPIRED
            valid = not self.started and not has_output and self.cleanup_state == "not_applicable" and not has_acceptance_evidence
        if not valid:
            raise ValueError("desktop_job_terminal_started_output_cleanup_matrix_invalid")
        if self.accepted_unverified_evidence is not None and (
            self.accepted_unverified_evidence.job_id != self.job_id
            or self.accepted_unverified_evidence.observed_at > self.completed_at
        ):
            raise ValueError("desktop_job_accepted_unverified_evidence_binding_invalid")
        return self
```

Grant validators enforce an owner-only maximum of 60 minutes, eight roots, 250 regular files, 50 MiB extracted total and 5 MiB per file. Initial workflow validators enforce the default D4 limits and exact reviewed-diff/disposable-copy semantics. No desktop contract accepts a shell string, arbitrary executable/path, ambient environment, provider key, browser cookie, passkey, or host-write capability.

```python
# packages/contracts/src/tuntun_contracts/private_ai/perception.py
from tuntun_contracts.vision.selected_frame import (
    AnonymousVisualObservationV1,
    SelectedFrameRequestV1,
    SignedAnonymousVisualObservationV1,
    SignedSelectedFrameRequestV1,
)
```

Phase 5 imports these four canonical Phase 3 types directly and may not redeclare, alias, or widen them. It therefore inherits positive camera/zone/privacy generations, positive frame byte/dimension bounds, the five-second request window, positive observation validity, distinct manifest/artifact identity and digest bindings, Privacy Shield generation, and exact signed request/result envelopes. `AnonymousVisualObservationV1` supplies no `area_id`, caption, OCR, identity/demographic/health field, action, memory, raw-media reference, alert, occupancy, or HA authority. Phase 3 takes canonical area and all generations from the live request record.

```python
# packages/contracts/src/tuntun_contracts/private_ai/robotics.py
class RobotMotionLeaseV1(PrivateAIContract):
    lease_id: UUID
    schema_version: Literal["1.0"]
    robot_endpoint_id: StableEndpointId
    telepresence_session_id: UUID
    sequence: Annotated[int, Field(ge=1)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    robot_binding_id: UUID
    robot_binding_generation: Annotated[int, Field(ge=1)]
    zone_id: StableZoneId
    zone_generation: Annotated[int, Field(ge=1)]
    activation_commitment: HmacCommitment
    safety_capability_digest: Sha256Digest
    linear_x_mps: BoundedVelocity
    linear_y_mps: BoundedVelocity
    angular_z_radps: BoundedAngularVelocity
    allowed_direction: RegisteredDirection
    owner_authorization_commitment: HmacCommitment
    controller_epoch: ControllerEpoch
    signature_domain: Literal["tuntun.robot.motion-lease.v1"]
    core_key_generation: Annotated[int, Field(ge=1)]
    key_id: KeyId
    signature: P256Signature

    @model_validator(mode="after")
    def bounded_motion_window(self) -> "RobotMotionLeaseV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(milliseconds=250):
            raise ValueError("robot_motion_lease_window_invalid")
        return self

class RobotSessionActivationV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    session_id: UUID
    owner_subject_id: StableSubjectId
    robot_endpoint_id: StableEndpointId
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    robot_binding_id: UUID
    robot_binding_generation: Annotated[int, Field(ge=1)]
    zone_id: StableZoneId
    zone_generation: Annotated[int, Field(ge=1)]
    zone_binding_commitment: HmacCommitment
    capability_generation: Annotated[int, Field(ge=1)]
    privacy_generation: Annotated[int, Field(ge=1)]
    safety_capability_digest: Sha256Digest
    controller_epoch: ControllerEpoch
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    owner_authorization_commitment: HmacCommitment
    signature_domain: Literal["tuntun.robot.activation.v1"]
    core_key_generation: Annotated[int, Field(ge=1)]
    key_id: KeyId
    signature: P256Signature

    @model_validator(mode="after")
    def bounded_activation_window(self) -> "RobotSessionActivationV1":
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(minutes=10):
            raise ValueError("robot_activation_window_invalid")
        return self

class RobotReadinessV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    session_id: UUID
    robot_endpoint_id: StableEndpointId
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    robot_binding_id: UUID
    robot_binding_generation: Annotated[int, Field(ge=1)]
    zone_id: StableZoneId
    zone_generation: Annotated[int, Field(ge=1)]
    activation_commitment: HmacCommitment
    state: Literal["ready", "degraded", "denied", "error_safe"]
    physical_stop_state: Literal["verified", "unverified", "triggered"]
    geofence_state: Literal["verified", "violated", "unverified"]
    battery_percent: Annotated[int, Field(ge=0, le=100)]
    charging_state: Literal["disconnected", "charging", "full", "fault", "unknown"]
    controller_health: Literal["healthy", "degraded", "failed", "unknown"]
    directional_sensor_health: Literal["healthy", "degraded", "failed", "unknown"]
    camera_state: Literal["disabled", "indicator_verified", "indicator_unverified", "fault"]
    indicator_state: Literal["off", "on_verified", "unverified", "fault"]
    last_valid_lease_id: UUID | None
    last_valid_lease_expires_at: AwareDatetime | None
    controller_epoch: ControllerEpoch
    capability_generation: Annotated[int, Field(ge=1)]
    observed_at: AwareDatetime
    valid_until: AwareDatetime
    signature_domain: Literal["tuntun.robot.readiness.v1"]
    edge_key_generation: Annotated[int, Field(ge=1)]
    edge_key_id: KeyId
    signature: P256Signature

    @model_validator(mode="after")
    def bounded_validity(self) -> "RobotReadinessV1":
        if not self.observed_at < self.valid_until <= self.observed_at + timedelta(seconds=2):
            raise ValueError("robot_readiness_validity_invalid")
        lease_pair = (self.last_valid_lease_id, self.last_valid_lease_expires_at)
        if (lease_pair[0] is None) != (lease_pair[1] is None):
            raise ValueError("robot_readiness_last_lease_pair_incomplete")
        if (self.camera_state, self.indicator_state) not in {
            ("disabled", "off"), ("indicator_verified", "on_verified"),
        }:
            raise ValueError("robot_camera_indicator_pair_invalid")
        unsafe = (
            self.physical_stop_state != "verified"
            or self.geofence_state != "verified"
            or self.battery_percent < 25
            or self.charging_state != "disconnected"
            or self.controller_health != "healthy"
            or self.directional_sensor_health != "healthy"
        )
        if self.state == "ready" and unsafe:
            raise ValueError("robot_ready_with_unsafe_or_contradictory_fact")
        return self

class RobotSafetyStateV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    session_id: UUID
    lease_id: UUID | None
    area_id: StableHomeId
    area_generation: Annotated[int, Field(ge=1)]
    robot_binding_id: UUID
    robot_binding_generation: Annotated[int, Field(ge=1)]
    zone_id: StableZoneId
    zone_generation: Annotated[int, Field(ge=1)]
    activation_commitment: HmacCommitment
    sequence: Annotated[int, Field(ge=0)]
    motion_state: Literal["stopped", "moving", "stopping", "error_safe"]
    stop_input: Literal["clear", "triggered", "unverified"]
    geofence_state: Literal["inside", "violated", "unverified"]
    battery_percent: Annotated[int, Field(ge=0, le=100)]
    charging_state: Literal["disconnected", "charging", "full", "fault", "unknown"]
    controller_health: Literal["healthy", "degraded", "failed", "unknown"]
    directional_sensor_health: Literal["healthy", "degraded", "failed", "unknown"]
    camera_state: Literal["disabled", "indicator_verified", "indicator_unverified", "fault"]
    indicator_state: Literal["off", "on_verified", "unverified", "fault"]
    last_valid_lease_id: UUID | None
    last_valid_lease_expires_at: AwareDatetime | None
    controller_epoch: ControllerEpoch
    capability_generation: Annotated[int, Field(ge=1)]
    observed_at: AwareDatetime
    valid_until: AwareDatetime
    signature_domain: Literal["tuntun.robot.safety-state.v1"]
    edge_key_generation: Annotated[int, Field(ge=1)]
    edge_key_id: KeyId
    signature: P256Signature

    @model_validator(mode="after")
    def coherent_safety_state(self) -> "RobotSafetyStateV1":
        if not self.observed_at < self.valid_until <= self.observed_at + timedelta(milliseconds=250):
            raise ValueError("robot_safety_state_window_invalid")
        if (self.last_valid_lease_id is None) != (self.last_valid_lease_expires_at is None):
            raise ValueError("robot_safety_last_lease_pair_incomplete")
        if (self.camera_state, self.indicator_state) not in {
            ("disabled", "off"), ("indicator_verified", "on_verified"),
        }:
            raise ValueError("robot_camera_indicator_pair_invalid")
        unsafe = (
            self.stop_input != "clear"
            or self.geofence_state != "inside"
            or self.battery_percent < 15
            or self.charging_state != "disconnected"
            or self.controller_health != "healthy"
            or self.directional_sensor_health != "healthy"
            or self.last_valid_lease_id != self.lease_id
            or self.last_valid_lease_expires_at is None
            or self.last_valid_lease_expires_at <= self.observed_at
        )
        if self.motion_state == "moving" and unsafe:
            raise ValueError("robot_motion_with_unsafe_or_contradictory_fact")
        return self

class RobotStopV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    command_id: UUID
    session_id: UUID
    robot_endpoint_id: StableEndpointId
    reason: Literal["owner_stop", "privacy_shield", "lease_expired", "geofence", "watchdog", "fault"]
    controller_epoch: ControllerEpoch
    issued_at: AwareDatetime
    signature_domain: Literal["tuntun.robot.stop.v1"]
    core_key_generation: Annotated[int, Field(ge=1)]
    key_id: KeyId
    signature: P256Signature

class RobotStopReceiptV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    command_id: UUID
    session_id: UUID
    robot_endpoint_id: StableEndpointId
    state: Literal["physically_stopped", "already_stopped", "unverified"]
    controller_epoch: ControllerEpoch
    capability_generation: Annotated[int, Field(ge=1)]
    observed_at: AwareDatetime
    signature_domain: Literal["tuntun.robot.stop-receipt.v1"]
    edge_key_generation: Annotated[int, Field(ge=1)]
    edge_key_id: KeyId
    signature: P256Signature

class TransientFrameV1(PrivateAIContract):
    schema_version: Literal["1.0"]
    request_id: UUID
    frame_index: Annotated[int, Field(ge=0, le=2)]
    media_type: Literal["image/jpeg", "image/png"]
    width: Annotated[int, Field(ge=1, le=1920)]
    height: Annotated[int, Field(ge=1, le=1920)]
    byte_count: Annotated[int, Field(ge=1, le=3 * 1024 * 1024)]
    frame_bytes: bytes

    @model_validator(mode="after")
    def exact_byte_count(self) -> "TransientFrameV1":
        if len(self.frame_bytes) != self.byte_count:
            raise ValueError("transient_frame_byte_count_mismatch")
        return self
```

### Frozen ports

```python
class InferenceGatewayPort(Protocol):
    async def infer(self, request: SanitizedInferenceRequestV1) -> InferenceResultV1: ...
    async def cancel(self, cancellation_id: UUID, generation: int) -> CancellationReceiptV1: ...

class KnowledgeCorpusPort(Protocol):
    async def import_source(self, selection: OwnerImportSelectionV1, policy: KnowledgeImportPolicyV1) -> KnowledgeImportReceiptV1: ...
    async def query(self, request: AuthorizedKnowledgeQueryV1) -> KnowledgeExcerptBundleV1: ...
    async def delete(self, command: DeleteKnowledgeSourceV1) -> KnowledgeDeletionReceiptV1: ...

class DesktopHelperPort(Protocol):
    async def install_grant(self, grant: SignedDesktopGrantV1) -> HelperGrantReceiptV1: ...
    async def read(self, request: SignedDesktopReadRequestV1) -> DesktopReadResultV1: ...
    async def inspect(self, job: SignedAuthorizedD3JobV1) -> DesktopJobResultV1: ...
    async def run_workflow(self, job: SignedAuthorizedD4JobV1) -> DesktopJobResultV1: ...
    async def cancel(self, job_id: UUID, generation: int) -> DesktopJobResultV1: ...

class DesktopAcceptanceEvidenceVerifierPort(Protocol):
    async def require_exact_current(
        self,
        evidence: SignedDesktopAcceptedUnverifiedEvidenceV1,
        *,
        job_id: UUID,
        canonical_job_digest: Sha256Digest,
        helper_admission_commitment: HmacCommitment,
        terminal_execution_receipt_commitment: HmacCommitment,
        current_helper_key_id: KeyId,
        completed_at: AwareDatetime,
    ) -> SignedDesktopAcceptedUnverifiedEvidenceV1: ...

class PerceptionGatewayPort(Protocol):
    async def observe(
        self,
        request: SignedSelectedFrameRequestV1,
        frames: AsyncIterator[TransientFrameV1],
    ) -> SignedAnonymousVisualObservationV1: ...

class RobotEdgePort(Protocol):
    async def activate(self, session: RobotSessionActivationV1) -> RobotReadinessV1: ...
    async def send_lease(self, lease: RobotMotionLeaseV1) -> RobotSafetyStateV1: ...
    async def stop(self, command: RobotStopV1) -> RobotStopReceiptV1: ...
    def telemetry(self, session_id: UUID) -> AsyncIterator[RobotSafetyStateV1]: ...
```

## Durable State and Migration Map

### Canonical core SQLCipher migrations

The canonical core Alembic configuration has exactly one linear head and one version table. Phase 5 appends, without editing an applied revision, `0020_private_ai_registry.down_revision = 0019_screen_time_real_adapter`, `0021_desktop_authority.down_revision = 0020_private_ai_registry`, and `0022_robotics.down_revision = 0021_desktop_authority`. Branch labels, `depends_on`, multi-parent/merge revisions, orphan files, hidden second heads, and conditional feature heads in this graph are invalid.

| Revision | Exact parent | Tables and critical invariants |
|---|---|---|
| `0020_private_ai_registry` | `0019_screen_time_real_adapter` | `model_artifacts`, `model_runtime_bindings`, `evaluation_bundles`, `task_cell_routes`, `task_cell_trials`, `inference_receipts`, `knowledge_storage_bindings`, `knowledge_recovery_policies`, `knowledge_root_migrations`, `perception_quality_receipts`; immutable exact digests, one current route per task cell, legal M0–M5 transitions, no prompt/result/document/frame/path/credential body, one canonical knowledge binding and distinct recovery destination |
| `0021_desktop_authority` | `0020_private_ai_registry` | `desktop_grants`, `desktop_grant_roots`, `desktop_model_egress_authorizations`, `desktop_command_proposals`, `desktop_workflow_manifests`, `desktop_jobs`, `desktop_job_transitions`, `desktop_job_results`; owner-only, exact generations/commitments, egress single-use trigger, legal action lifecycle, D3/D4 separation, no raw file/output/secret/path text/passkey/provider credential |
| `0022_robotics` | `0021_desktop_authority` | `robot_inventory`, `robot_capability_evidence`, `robot_zone_safety_bindings`, `robot_sessions`, `robot_session_transitions`, `robot_safety_receipts`, `lilygo_inventory`, `lilygo_pairing_receipts`; canonical area plus versioned binding-owned zone, one active owner-local supervised session, no parallel geofence registry, no lease replay/motion resume, no video/audio/map/identity/provider secret |

Desktop jobs reuse the Phase 2 post-commit lifecycle exactly: `PREPARED -> AUTHORIZED_COMMITTED -> SIGNED -> DISPATCHING -> RECONCILING -> VERIFIED | ACCEPTED_UNVERIFIED | FAILED | UNKNOWN | EXPIRED`, with `AUTHORIZED_COMMITTED -> FAILED` for a signing failure before helper I/O. A prepared request may be cancelled before commitment; after commitment, cancellation is recorded as an outcome/reason without inventing a new terminal state or claiming that a started process was undone. D3/D4 helper I/O begins only after the exact confirmation/passkey and job commitment commit plus signed envelope persistence. The helper durably admits `(job_id, grant_generation, canonical_job_digest)` before process launch; a mismatched duplicate is a security failure, and an uncertain started process is reconciled or becomes `UNKNOWN`, never relaunched under a new ID.

### Separate knowledge-catalog SQLCipher migrations

The canonical root owns `catalog.db` with its own 256-bit Keychain root, explicit `alembic-knowledge.ini`/script directory, and version table `knowledge_alembic_version`. It never attaches to the canonical database, imports the core migration environment, writes `alembic_version`, or contributes to the canonical core head. Its exact graph is linear: `0001_knowledge_sources` has no parent, `0002_knowledge_fts -> 0001_knowledge_sources`, `0003_knowledge_embeddings -> 0002_knowledge_fts`, and `0004_knowledge_recovery -> 0003_knowledge_embeddings`; it has no branch labels, `depends_on`, merge, fork, orphan, or extra revision.

| Revision | Exact parent | Tables and critical invariants |
|---|---|---|
| `0001_knowledge_sources` | base | `knowledge_sources`, `knowledge_object_versions`, `knowledge_acls`, `object_publish_journal`; exact source/version/provenance/audience/sensitivity/egress/retention, opaque encrypted object ref, no plaintext title/path/body |
| `0002_knowledge_fts` | `0001_knowledge_sources` | `knowledge_chunks`, SQLCipher FTS5 table, `knowledge_citations`, `index_rebuilds`; current authorized version only, bounded tokens/locations, citation expiry turn+5m, crash-safe publish, no cross-ACL title/snippet |
| `0003_knowledge_embeddings` | `0002_knowledge_fts` | `knowledge_embeddings`, `embedding_rebuilds`, `vector_evaluation_bindings`; encrypted vector, exact local artefact/dimensions/normalization, derived/rebuildable, disabled by default |
| `0004_knowledge_recovery` | `0003_knowledge_embeddings` | `knowledge_deletion_generations`, `managed_recovery_generations`, `recovery_reconciliations`, `export_receipts`; deletion immediately blocks old generations, seven daily/four weekly and 24-hour bounds, no recovery-as-live-root |

Object publish is `QUARANTINED -> PARSED -> ENCRYPTED_STAGED -> CATALOG_COMMITTED -> PUBLISHED`; any pre-publish failure destroys partial object/chunk/FTS data. Deletion is `ELIGIBILITY_REVOKED -> KEYS_DESTROYED -> CHUNKS_FTS_VECTORS_REMOVED -> RECOVERY_RECONCILED -> TOMBSTONED`; retrieval is denied from the first transition.

### Mandatory audited contract, migration, and fault tests

These are acceptance work inside the existing task count, not optional follow-up:

- **Task 01 / 09 — inference trust and result closure:** generate every `kind × trust_class` pair and require only the four mappings above; reject `trusted_policy`, `system`, and caller prompt-template text before request signing and before provider serialization. Injection fixtures in user text, approved memory, knowledge, filenames, and command output must remain quoted inert data under the locally loaded template. For every result status, reject all other variant fields, duplicate/17th safety flags, unbounded refusal text, wrong response schema/model/template/request commitment, and any tool, memory, action, desktop, media, or robot proposal. A successful M0 Guest exact-disclosure cloud fixture and a successful pre-M5 guardian-consented child cloud fixture must pass; the same identities must fail promoted local routing until their local gate is eligible, and child web remains denied.
- **Task 01 / 25 / 29 / 30 — collection allocation and D3 write closure:** test every empty/minimum/maximum/maximum-plus-one boundary for inference consent commitments, knowledge media types, desktop include/exclude globs, allowed command/workflow IDs, command argv/read/write declarations, workflow exit-code tuple, and result artifact commitments before service/helper I/O. Duplicate segment/consent/media/grant/output IDs fail. An `AuthorizedD3JobV1` carrying any declared write fails contract validation even when all other command fields and confirmation are valid.
- **Task 01 / 20 — audience and retrieval closure:** enumerate only `subject_private|guardian_child|household_adults|household_all`; reject legacy aliases as unknown at model, JSON Schema, generated TypeScript, API, import, restore, and database boundaries. Audience-driven invariants require `guardian_child` to bind a child subject plus current guardian and child-safe approval generations; `household_all` always binds explicit approved child-safe classification plus its current approval generation and also a current guardian generation for a child-origin record; `household_adults` rejects child/Guest; `subject_private` is exact-subject and never widens. Test impossible subject/audience combinations and current subject/audience/guardian/consent/child-safe-approval generations before rank, before decrypt, before serialization, and after restore; owner-not-subject cannot read a `subject_private` body, and cross-subject/household/Guest cases reveal neither body, title, count, nor timing. Test 0/8/9 excerpts, per-excerpt zero/overflow, aggregate 11,999/12,000/12,001, dishonest totals, and a rank-to-decrypt race; overage is rejected before object decryption or model/provider serialization.
- **Tasks 03–06 — migration graph closure:** inspect the actual script directories and version tables, not a declared head string. Fresh install, sequential upgrade, interruption/restart at every revision, downgrade-or-clean-restore, and restore from every prior accepted head must verify the exact core `0019_screen_time_real_adapter -> 0020_private_ai_registry -> 0021_desktop_authority -> 0022_robotics` chain and separate knowledge `0001 -> 0002 -> 0003 -> 0004` chain. Mutated applied files, wrong/missing parents, hidden forks, merge/multi-parent revisions, multiple heads, extra orphans, cross-imported environments, or either graph writing the other's version table fail closed. A downgrade/restore may never reopen a model route, corpus query, desktop grant/job, or robot session/lease.
- **Task 12 — one-Mac topology:** inventory proves the office-use Mac and Core share one immutable hardware identity. The family-ready positive test has only the inner ASUS interface eligible and the BE800 link disconnected. A separately labelled dual-home campaign must fail on forwarding, bridging, Internet Sharing, proxying, outer ingress, route/DNS/firewall/interface-order drift, and may not create a second helper/device record.
- **Tasks 20 / 22 — catalog lifecycle:** test clean catalog creation, all sequential upgrades, SIGKILL/restart around DDL and object-publish transitions, corrupt catalog/version rows, clean restore, and source deletion racing both attached and recovery generations. No old affected generation becomes queryable after its deletion generation is raised.
- **Task 27 — desktop egress exactness:** test empty collections, 251st file/content, 21st output, duplicates within/across collections, reordering after approval, content mutation, wrong grant/generation/revocation, wrong provider/account/model, wrong attempt ID, byte/token mismatch, serialization mismatch, partial consumption, replay, and expiry. The authorizer and gateway compare the exact canonical ordered tuple and exact serialized bytes for one provider attempt immediately before network I/O. D4 workflow network remains `none` and is neither a prerequisite for nor a consequence of this authorization.
- **Task 31 / U21 consumer — D4 network absence:** the sole positive workflow fixture has `execution_network_policy="none"`. Construction through API, UI, configuration, imported workflow, restore, or direct model object with any non-`none` value is a negative test; it must be rejected before sandbox launch.
- **Tasks 37–44 — robot authority and signed safety:** activation verifies `(area_id, area_generation, robot_binding_id, robot_binding_generation, zone_id, zone_generation)` against the Phase 2 authority and recomputes `zone_binding_commitment` to prove that zone belongs to that area and robot binding. Every lease/readiness/safety fact binds that exact location plus activation commitment; `RobotMotionLeaseV1` uses canonical `zone_id`/`zone_generation`, while `geofence_state` is only the evaluated safety label for that zone and never a second registry. Reject every `room_id`/location alias. Area/zone/binding drift, reclassification, restart, restore, controller-epoch change, activation-commitment change, edge/core signing-key-generation change, or stale safety fact atomically revokes the session and all leases before motion. Activation, motion lease, readiness, safety state, stop, and stop receipt use distinct literal signature domains; cross-type/domain replay denies. Property/fault tests cover every battery/charging/controller/sensor/camera×indicator/last-lease contradiction, signature mutation, expiry boundary, stale observation, and motion-without-current-lease; only `disabled↔off` and `indicator_verified↔on_verified` are valid camera/indicator pairs, and no invalid pair may project `ready`/green or energize motors.

Each fault test records a pre-I/O spy assertion: rejected inference never serializes to a runtime/provider, rejected corpus work never decrypts an object, rejected desktop egress never opens a network socket, and rejected robot state never dispatches a lease.

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
uv run pytest -m "not phase5_hardware and not phase5_elapsed and not live_cloud" -q
pnpm --filter @tuntun/admin e2e -- tests/ui/ai-workspace-*.spec.ts tests/accessibility/ai-workspace-*.spec.ts
```

Owner-gated commands use synthetic/de-identified inputs and ignored evidence destinations. The elapsed examples below may be invoked only by their task's explicit post-commit workflow: each runner resolves the committed candidate, requires a clean worktree, and rejects a chain signed for any other commit/candidate before starting the clock.

```bash
TUNTUN_ALLOW_CONTROL_HOST_BENCHMARK=1 uv run python scripts/phase5/benchmark_control_host.py --feature-manifest-chain var/evidence/phase5/feature-authority/signed-rollover-chain.json --duration-seconds 604800 --evidence-root var/evidence/phase5/control-host
TUNTUN_ALLOW_PHASE5_STORAGE=1 uv run python scripts/phase5/qualify_knowledge_root.py --evidence-root var/evidence/phase5/knowledge
TUNTUN_ALLOW_PHASE5_APPLIANCE=1 uv run python scripts/phase5/evaluate_appliance.py --evidence-root var/evidence/phase5/appliance
TUNTUN_ALLOW_PHASE5_DESKTOP=1 uv run python scripts/phase5/qualify_d4_sandbox.py --evidence-root var/evidence/phase5/desktop
TUNTUN_ALLOW_PHASE5_PERCEPTION=1 uv run python scripts/phase5/run_selected_frame_gate.py --evidence-root var/evidence/phase5/perception
TUNTUN_ALLOW_PHASE5_ROBOT=1 uv run python scripts/phase5/qualify_estop.py --evidence-root var/evidence/phase5/robot
TUNTUN_ALLOW_PHASE5_ELAPSED=1 uv run python scripts/phase5/run_acceptance.py --feature-manifest-chain var/evidence/phase5/feature-authority/signed-rollover-chain.json --duration-seconds 2592000 --evidence-root var/evidence/phase5/acceptance
```

---

## Wave 0 — P5-E0/P5-0 Contracts, Persistence, Simulation, and Negative Baseline

### Task 01: Freeze Phase 5 contracts and reconcile the shared Phase 3 selected-frame contract

**Depends on:** P5-E0 upstream artifacts available; no Phase 5 implementation.

**Gate contribution:** P5-E0 contract half; no runtime or feature registration.

**Estimated effort:** 3–4 engineering person-days.

**Files:**

- Create: `packages/contracts/src/tuntun_contracts/private_ai/__init__.py`
- Create: `packages/contracts/src/tuntun_contracts/private_ai/base.py`
- Create: `packages/contracts/src/tuntun_contracts/private_ai/inference.py`
- Create: `packages/contracts/src/tuntun_contracts/private_ai/artifacts.py`
- Create: `packages/contracts/src/tuntun_contracts/private_ai/procurement.py`
- Create: `packages/contracts/src/tuntun_contracts/private_ai/knowledge.py`
- Create: `packages/contracts/src/tuntun_contracts/private_ai/desktop.py`
- Create: `packages/contracts/src/tuntun_contracts/private_ai/robotics.py`
- Create: `packages/contracts/src/tuntun_contracts/private_ai/lilygo.py`
- Create: `packages/contracts/src/tuntun_contracts/private_ai/ui.py`
- Create: `packages/contracts/src/tuntun_contracts/private_ai/ports.py`
- Create: `schemas/private-ai/v1/inference-v1.schema.json`
- Create: `schemas/private-ai/v1/model-artifact-v1.schema.json`
- Create: `schemas/private-ai/v1/appliance-decision-v1.schema.json`
- Create: `schemas/private-ai/v1/knowledge-v1.schema.json`
- Create: `schemas/private-ai/v1/desktop-v1.schema.json`
- Create: `schemas/private-ai/v1/robotics-v1.schema.json`
- Create: `schemas/private-ai/v1/lilygo-v1.schema.json`
- Create: `schemas/private-ai/v1/ui-v1.schema.json`
- Create: `fixtures/synthetic/private-ai/contracts/inference-request-v1.json`
- Create: `fixtures/synthetic/private-ai/contracts/inference-result-v1.json`
- Create: `fixtures/synthetic/private-ai/contracts/route-decision-v1.json`
- Create: `fixtures/synthetic/private-ai/contracts/model-artifact-v1.json`
- Create: `fixtures/synthetic/private-ai/contracts/appliance-no-purchase-v1.json`
- Create: `fixtures/synthetic/private-ai/contracts/appliance-purchase-candidate-v1.json`
- Create: `fixtures/synthetic/private-ai/contracts/knowledge-v1.json`
- Create: `fixtures/synthetic/private-ai/contracts/desktop-v1.json`
- Create: `fixtures/synthetic/private-ai/contracts/robotics-v1.json`
- Create: `fixtures/synthetic/private-ai/contracts/lilygo-v1.json`
- Create: `fixtures/adversarial/private-ai/contracts-v1.jsonl`
- Consume: `packages/contracts/src/tuntun_contracts/vision/selected_frame.py`
- Consume: `schemas/vision/v1/selected-frame-v1.schema.json`
- Consume: `fixtures/synthetic/vision/contracts/selected-frame-request-v1.json`
- Consume: `fixtures/synthetic/vision/contracts/anonymous-visual-observation-v1.json`
- Consume: `docs/superpowers/specs/2026-08-27-tuntun-phase5-private-ai-desktop-robotics-design.md`
- Create: `packages/ui-contracts/src/generated/private-ai-v1.ts`
- Consume: `scripts/phase3/generate_vision_schemas.py`
- Create: `scripts/phase5/generate_schemas.py`
- Test: `tests/contract/private_ai/test_phase5_contracts.py`
- Test: `tests/contract/vision/test_vision_contracts.py`
- Test: `tests/property/private_ai/test_contract_roundtrip.py`
- Test: `tests/property/vision/test_contract_rejection.py`

**Interfaces:** Implement the frozen private-AI contract baseline above, including closed `RouteDecisionV1` and discriminated `ApplianceDecisionV1`. Import and reuse the Phase 1 `PersonaProjection` directly for `SanitizedInferenceRequestV1.persona_descriptor`; its exact five fields and closed enums must remain schema/model/generated-client identical, with no Phase 5 alias or extension. Consume, without editing, the accepted Phase 3 selected-frame request/result and their signed envelopes; verify their required zone/privacy/model/time bindings at the seam. Delegate every signed whole-model encoding to Phase 1 `canonical_mapping_bytes` through `canonical_private_ai_bytes`; no Phase 5-local JCS dependency, key coercion, or timestamp normalizer exists. Reject `room_id`, unknown fields, unknown discriminators, non-canonical timestamps, duplicate JSON keys, unsafe identifiers, oversized collections, missing signatures, stale/zero generations, frame/media fields in inference contracts, route evidence/authority substitutions, and cross-variant appliance fields.

- [ ] **Step 1 — Write failing contract and parity tests.** Add parametrized valid/invalid fixture tests, schema/model/generated-TypeScript parity, and this specific upstream regression:

  ```python
def test_selected_frame_requires_zone_generation() -> None:
    payload = load_fixture("vision/contracts/selected-frame-request-v1.json")
    payload.pop("zone_generation")
    with pytest.raises(ValidationError):
        SelectedFrameRequestV1.model_validate(payload)

def test_inference_reuses_exact_phase1_persona_projection() -> None:
    assert SanitizedInferenceRequestV1.model_fields["persona_descriptor"].annotation is PersonaProjection
    assert tuple(PersonaProjection.model_fields) == ("role", "context", "tone", "depth", "learning_level")

@pytest.mark.parametrize("mutation", [
    {"subject_class": "child", "audience": "guardian_child"},
    {"selected_route": "approved_cloud", "data_egress_class": "local_only"},
    {"profile_class": "guest"},
    {"profile_class": "k2", "child_eligibility": "not_applicable"},
    {"profile_class": "k2", "child_eligibility": "eligible", "task_cell_stage": "M4"},
    {"profile_class": "k2", "child_eligibility": "eligible", "task_cell_stage": "M5",
     "consent_receipt_commitments": ()},
    {"preemption_state": "privacy"},
    {"raw_media_present": True},
    {"local_health": "pressured"},
    {"local_execution_zone_assessed": "local_appliance"},
    {"local_available_memory_mib": 0},
    {"selected_route": "local_appliance", "local_execution_zone_assessed": "local_appliance",
     "task_cell_stage": "M2", "traffic_class": "live_household"},
    {"reservation_generation": None},
    {"provider_url": "https://unreviewed.invalid"},
])
def test_route_decision_rejects_policy_evidence_or_authority_substitution(
    route_decision_fixture, mutation,
) -> None:
    with pytest.raises(ValidationError):
        RouteDecisionV1.model_validate({**route_decision_fixture, **mutation})

def test_route_decision_rejects_duplicate_consent_commitment(route_decision_fixture) -> None:
    commitment = route_decision_fixture["consent_receipt_commitments"][0]
    with pytest.raises(ValidationError):
        RouteDecisionV1.model_validate({
            **route_decision_fixture,
            "consent_receipt_commitments": (commitment, commitment),
        })

def test_route_decision_cannot_outlive_exact_request_deadline(route_decision_fixture) -> None:
    with pytest.raises(ValidationError):
        RouteDecisionV1.model_validate({
            **route_decision_fixture,
            "request_deadline_at": route_decision_fixture["decided_at"],
        })

@pytest.mark.parametrize("field", [
    "task_cell_activation_generation", "privacy_generation",
    "reservation_generation", "cancellation_generation",
])
def test_route_decision_generations_reject_zero(route_decision_fixture, field) -> None:
    with pytest.raises(ValidationError):
        RouteDecisionV1.model_validate({**route_decision_fixture, field: 0})

def test_appliance_decision_variants_reject_substitution_and_sensitive_fields(
    no_purchase_decision_fixture, purchase_candidate_decision_fixture,
) -> None:
    adapter = TypeAdapter(ApplianceDecisionV1)
    invalid = (
        {**no_purchase_decision_fixture,
         "candidate_sku_and_revision_commitment": SYNTHETIC_COMMITMENT},
        {**no_purchase_decision_fixture, "decision": "candidate_blocked"},
        {**purchase_candidate_decision_fixture, "gst_basis_points": 800},
        {**purchase_candidate_decision_fixture,
         "tax_cents": purchase_candidate_decision_fixture["tax_cents"] + 1},
        {**purchase_candidate_decision_fixture, "ups_signalling_verified": False},
        {**purchase_candidate_decision_fixture, "order_authorized": True},
        {**purchase_candidate_decision_fixture, "usable_ram_mib": 1},
        {**purchase_candidate_decision_fixture, "shipping_address": "private"},
        {**purchase_candidate_decision_fixture, "payment_token": "private"},
    )
    for payload in invalid:
        with pytest.raises(ValidationError):
            adapter.validate_python(payload)

def test_purchase_candidate_quote_must_be_same_singapore_day(
    purchase_candidate_decision_fixture,
) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(ApplianceDecisionV1).validate_python({
            **purchase_candidate_decision_fixture,
            "quote_collected_at": purchase_candidate_decision_fixture["decided_at"] - timedelta(days=1),
        })

@pytest.mark.parametrize("model", [
    SanitizedInferenceRequestV1, RouteDecisionV1,
    NoPurchaseDecisionV1, PurchaseCandidateDecisionV1, DesktopGrantV1,
    DesktopModelEgressAuthorizationV1, RobotMotionLeaseV1,
])
def test_every_versioned_phase5_dto_uses_string_version_1_0(model) -> None:
    assert model.model_fields["schema_version"].annotation == Literal["1.0"]

def test_every_inference_result_variant_uses_string_version_1_0() -> None:
    for model in (
        CompletedInferenceResultV1, RefusedInferenceResultV1,
        CancelledInferenceResultV1, TimedOutInferenceResultV1,
        FailedInferenceResultV1,
    ):
        assert model.model_fields["schema_version"].annotation == Literal["1.0"]

def test_design_inference_result_listing_matches_frozen_contract() -> None:
    listing = documented_contract_listing(
        "docs/superpowers/specs/2026-08-27-tuntun-phase5-private-ai-desktop-robotics-design.md",
        "InferenceResultV1",
    )
    assert listing.schema_version_literal == "1.0"
    assert set(listing.field_names) == {
        "request_id", "schema_version", "status", "response_schema_id", "request_commitment",
        "output", "finish_reason", "model_artifact_id", "model_digest", "tokenizer_digest",
        "quantization", "runtime_name", "runtime_version", "prompt_template_digest",
        "input_tokens", "output_tokens", "first_token_ms", "total_ms", "safety_flags",
        "server_receipt_id", "proxy_key_id", "signature",
    }

def test_phase1_cloud_routes_are_not_blocked_by_phase5_local_promotion(
    guest_cloud_route_fixture, child_cloud_route_fixture,
) -> None:
    assert RouteDecisionV1.model_validate(guest_cloud_route_fixture).selected_route == "approved_cloud"
    assert RouteDecisionV1.model_validate(child_cloud_route_fixture).selected_route == "approved_cloud"

def test_every_phase_contract_family_uses_the_one_shared_canonical_encoder(
    cross_phase_canonical_probe,
) -> None:
    expected=canonical_mapping_bytes(cross_phase_canonical_probe.python_mapping)
    assert expected==cross_phase_canonical_probe.phase1_bytes
    assert expected==canonical_home_bytes(cross_phase_canonical_probe.home)
    assert expected==canonical_vision_bytes(cross_phase_canonical_probe.vision)
    assert expected==canonical_whole_home_bytes(cross_phase_canonical_probe.whole_home)
    assert expected==canonical_private_ai_bytes(cross_phase_canonical_probe.private_ai)
    assert b'"time":"2026-08-27T01:02:03.000004Z"' in expected
    assert b'"text":"\xc3\xa9"' in expected

def test_refusal_output_is_closed_and_matches_finish_reason(refused_inference_fixture) -> None:
    RefusedInferenceResultV1.model_validate(refused_inference_fixture)
    with pytest.raises(ValidationError):
        RefusedInferenceResultV1.model_validate({
            **refused_inference_fixture,
            "output": {"reason_code": "policy_refusal", "message_id": "inference.refused.model"},
        })
    with pytest.raises(ValidationError):
        RefusedInferenceResultV1.model_validate({
            **refused_inference_fixture,
            "output": {**refused_inference_fixture["output"], "free_text": "caller controlled"},
        })

@pytest.mark.parametrize("field", ["desktop_grant_generation", "revocation_generation"])
def test_desktop_egress_generations_reject_zero(desktop_egress_fixture, field) -> None:
    with pytest.raises(ValidationError):
        DesktopModelEgressAuthorizationV1.model_validate({**desktop_egress_fixture, field: 0})

@pytest.mark.parametrize(("level", "mutation"), [
    ("D1", {"allowed_command_registry_ids": ("git.status.v1",)}),
    ("D2", {"allowed_workflow_ids": ("test.v1",)}),
    ("D3", {"allowed_command_registry_ids": (), "allowed_workflow_ids": ()}),
    ("D3", {"allowed_workflow_ids": ("test.v1",)}),
    ("D3", {"execution_network_policy": "signed_workflow_allowlist"}),
    ("D4", {"allowed_command_registry_ids": ("git.status.v1",)}),
    ("D4", {"allowed_workflow_ids": ()}),
    ("D4", {"execution_network_policy": "signed_workflow_allowlist"}),
])
def test_desktop_grant_level_shape_cannot_widen_authority(desktop_grant_payload_for_level, level, mutation) -> None:
    with pytest.raises(ValidationError):
        DesktopGrantV1.model_validate({**desktop_grant_payload_for_level(level), **mutation})

def test_desktop_grant_rejects_host_write_and_over_five_mib_per_file(desktop_grant_fixture) -> None:
    writable_root = {**desktop_grant_fixture["roots"][0], "read_or_sandbox_write": "sandbox_write"}
    for mutation in (
        {"roots": (writable_root,)},
        {"max_bytes_per_file": 5 * 1024 * 1024 + 1},
    ):
        with pytest.raises(ValidationError):
            DesktopGrantV1.model_validate({**desktop_grant_fixture, **mutation})

def test_private_ai_contract_module_imports_and_manifest_schema_is_not_recursive() -> None:
    from tuntun_contracts.private_ai.desktop import DesktopWorkflowManifestV1, DesktopWorkflowStepV1

    schema = DesktopWorkflowManifestV1.model_json_schema()
    assert DesktopWorkflowManifestV1 is not DesktopWorkflowStepV1
    assert schema["properties"]["steps"]
    assert "steps" not in DesktopWorkflowStepV1.model_fields

def test_d3_proposal_itself_rejects_non_none_network(desktop_command_proposal_fixture) -> None:
    with pytest.raises(ValidationError):
        DesktopCommandProposalV1.model_validate({
            **desktop_command_proposal_fixture,
            "execution_network_policy": "signed_workflow_allowlist",
        })

@pytest.mark.parametrize("mutation", [
    {"subject_class": "owner", "audience": "guardian_child", "guardian_generation": None},
    {"subject_class": "adult", "audience": "household_all", "child_safe_classification": "not_applicable", "child_safe_approval_generation": None},
    {"subject_class": "k2", "audience": "household_all", "guardian_generation": None},
    {"subject_class": "n1", "audience": "household_adults"},
    {"subject_class": "guest", "audience": "subject_private"},
])
def test_knowledge_audience_impossible_combinations_are_rejected(knowledge_audience_fixture, mutation) -> None:
    with pytest.raises(ValidationError):
        KnowledgeAudienceBindingV1.model_validate({**knowledge_audience_fixture, **mutation})

@pytest.mark.parametrize("mutation", [
    {"cpu_limit": 3}, {"memory_limit_mib": 4097}, {"wall_time_limit_seconds": 901},
    {"process_limit": 21}, {"combined_output_limit_bytes": 100 * 1024 * 1024 + 1},
    {"disposable_disk_limit_bytes": 1024 * 1024 * 1024 + 1},
    {"read_only_roots": ()}, {"disposable_write_roots": ()},
    {"rollback_or_discard_behavior": "preserve_host_changes"},
    {"expires_at": "issued_at"},
])
def test_initial_d4_manifest_rejects_limit_or_mount_widening(d4_workflow_fixture, mutation) -> None:
    if mutation.get("expires_at") == "issued_at":
        mutation = {"expires_at": d4_workflow_fixture["issued_at"]}
    with pytest.raises(ValidationError):
        DesktopWorkflowManifestV1.model_validate({**d4_workflow_fixture, **mutation})

def test_runtime_requirement_is_closed_and_architecture_coherent(runtime_requirement_fixture) -> None:
    for mutation in (
        {"supported_host_architectures": ("x86_64", "x86_64")},
        {"supported_host_architectures": ("arm64",), "required_cpu_features": ("avx2",)},
    ):
        with pytest.raises(ValidationError):
            RuntimeRequirementV1.model_validate({**runtime_requirement_fixture, **mutation})

def test_filesystem_identity_cannot_carry_a_host_path(filesystem_identity_fixture) -> None:
    with pytest.raises(ValidationError):
        FilesystemIdentityV1.model_validate({
            **filesystem_identity_fixture,
            "absolute_path": "/Users/example/private",
        })

@pytest.mark.parametrize("mutation_builder", [
    d4_with_duplicate_step_ordinal,
    d4_with_unregistered_step_command,
    d4_with_out_of_range_read_root,
    d4_with_out_of_range_write_root,
    d4_with_nonzero_expected_exit,
    d4_with_duplicate_output_path,
    d4_with_out_of_range_output_root,
    d4_with_declared_outputs_over_combined_limit,
    d4_with_input_mount_not_in_manifest,
])
def test_d4_nested_steps_inputs_outputs_and_mounts_are_exact(d4_workflow_fixture, mutation_builder) -> None:
    with pytest.raises(ValidationError):
        DesktopWorkflowManifestV1.model_validate(mutation_builder(d4_workflow_fixture))

def test_desktop_results_cannot_claim_content_or_verified_state_incoherently(
    desktop_read_result_fixture, desktop_job_result_fixture,
) -> None:
    with pytest.raises(ValidationError):
        DesktopReadResultV1.model_validate({
            **desktop_read_result_fixture,
            "status": "denied",
            "file_count": 1,
        })
    with pytest.raises(ValidationError):
        DesktopJobResultV1.model_validate({
            **desktop_job_result_fixture,
            "terminal_state": "VERIFIED",
            "started": False,
        })
    with pytest.raises(ValidationError):
        DesktopJobResultV1.model_validate({
            **desktop_job_result_fixture,
            "terminal_state": "EXPIRED",
            "started": True,
        })

@pytest.mark.parametrize(
    ("terminal_state", "started", "has_output", "cleanup_state", "has_acceptance_evidence"),
    product(
        ("VERIFIED", "ACCEPTED_UNVERIFIED", "FAILED", "UNKNOWN", "EXPIRED"),
        (False, True), (False, True), ("verified", "unverified", "not_applicable"), (False, True),
    ),
)
def test_desktop_job_result_complete_state_matrix(
    desktop_job_result_fixture, desktop_accepted_unverified_evidence_fixture,
    terminal_state, started, has_output, cleanup_state, has_acceptance_evidence,
) -> None:
    expected_valid = (
        (terminal_state == "VERIFIED" and started and cleanup_state == "verified" and not has_acceptance_evidence)
        or (terminal_state == "ACCEPTED_UNVERIFIED" and started and cleanup_state == "unverified" and has_acceptance_evidence)
        or (terminal_state == "UNKNOWN" and started and cleanup_state == "unverified" and not has_acceptance_evidence)
        or (terminal_state == "FAILED" and not has_acceptance_evidence and (
            (started and cleanup_state == "verified")
            or (not started and not has_output and cleanup_state == "not_applicable")
        ))
        or (terminal_state == "EXPIRED" and not started and not has_output
            and cleanup_state == "not_applicable" and not has_acceptance_evidence)
    )
    payload = {
        **desktop_job_result_fixture,
        "terminal_state": terminal_state,
        "started": started,
        "stdout_ref": SYNTHETIC_CONTENT_REF if has_output else None,
        "stderr_ref": None,
        "output_artifact_commitments": (),
        "cleanup_state": cleanup_state,
        "accepted_unverified_evidence": {
            **desktop_accepted_unverified_evidence_fixture,
            "job_id": desktop_job_result_fixture["job_id"],
        } if has_acceptance_evidence else None,
    }
    if expected_valid:
        DesktopJobResultV1.model_validate(payload)
    else:
        with pytest.raises(ValidationError, match="terminal_started_output_cleanup_matrix_invalid"):
            DesktopJobResultV1.model_validate(payload)

def test_robot_motion_lease_rejects_nonpositive_and_over_250ms(robot_lease_fixture) -> None:
    for expiry in (
        robot_lease_fixture["issued_at"],
        robot_lease_fixture["issued_at"] + timedelta(milliseconds=250, microseconds=1),
    ):
        with pytest.raises(ValidationError):
            RobotMotionLeaseV1.model_validate({**robot_lease_fixture, "expires_at": expiry})

@pytest.mark.parametrize("camera_state", ["disabled", "indicator_verified", "indicator_unverified", "fault"])
@pytest.mark.parametrize("indicator_state", ["off", "on_verified", "unverified", "fault"])
def test_robot_camera_indicator_cross_product_is_exact(
    robot_readiness_fixture, robot_safety_fixture, camera_state, indicator_state,
) -> None:
    pair = (camera_state, indicator_state)
    valid = pair in {("disabled", "off"), ("indicator_verified", "on_verified")}
    for model, fixture in (
        (RobotReadinessV1, robot_readiness_fixture), (RobotSafetyStateV1, robot_safety_fixture),
    ):
        if valid:
            model.model_validate({**fixture, "camera_state": camera_state, "indicator_state": indicator_state})
        else:
            with pytest.raises(ValidationError, match="robot_camera_indicator_pair_invalid"):
                model.model_validate({**fixture, "camera_state": camera_state, "indicator_state": indicator_state})

def test_robot_battery_boundaries_distinguish_session_start_from_active_motion(
    robot_readiness_fixture, robot_safety_fixture,
) -> None:
    with pytest.raises(ValidationError, match="robot_ready_with_unsafe_or_contradictory_fact"):
        RobotReadinessV1.model_validate({**robot_readiness_fixture, "state": "ready", "battery_percent": 24})
    RobotReadinessV1.model_validate({**robot_readiness_fixture, "state": "ready", "battery_percent": 25})

    with pytest.raises(ValidationError, match="robot_motion_with_unsafe_or_contradictory_fact"):
        RobotSafetyStateV1.model_validate({**robot_safety_fixture, "motion_state": "moving", "battery_percent": 14})
    RobotSafetyStateV1.model_validate({**robot_safety_fixture, "motion_state": "moving", "battery_percent": 15})
    RobotSafetyStateV1.model_validate({**robot_safety_fixture, "motion_state": "moving", "battery_percent": 24})

@pytest.mark.parametrize("drift", [
    "area_generation", "robot_binding_generation", "zone_generation",
    "activation_commitment", "controller_epoch", "edge_key_generation",
])
async def test_robot_signed_fact_cannot_cross_activation_restore_or_reclassification(robot_harness, drift) -> None:
    result = await robot_harness.verify_signed_fact_after_drift(drift)
    assert result.state == "error_safe"
    assert result.motor_energy_enabled is False

@pytest.mark.parametrize(("source_type", "target_domain"), [
    ("activation", "tuntun.robot.motion-lease.v1"),
    ("motion_lease", "tuntun.robot.readiness.v1"),
    ("readiness", "tuntun.robot.safety-state.v1"),
    ("safety_state", "tuntun.robot.stop.v1"),
    ("stop", "tuntun.robot.stop-receipt.v1"),
    ("stop_receipt", "tuntun.robot.activation.v1"),
])
async def test_robot_signature_cannot_replay_across_type_or_domain(robot_harness, source_type, target_domain) -> None:
    assert await robot_harness.replay_signature(source_type, target_domain) == "signature_domain_invalid"

@pytest.mark.parametrize(("model", "fixture_name", "start_field", "end_field", "limit"), [
    (OwnerImportSelectionV1, "owner_import_selection", "issued_at", "expires_at", timedelta(minutes=5)),
    (AuthorizedKnowledgeQueryV1, "authorized_knowledge_query", "issued_at", "expires_at", timedelta(seconds=60)),
    (DeleteKnowledgeSourceV1, "delete_knowledge_source", "issued_at", "expires_at", timedelta(minutes=2)),
    (DesktopGrantV1, "desktop_grant", "created_at", "expires_at", timedelta(minutes=60)),
    (DesktopModelEgressAuthorizationV1, "desktop_egress", "issued_at", "expires_at", timedelta(minutes=15)),
    (DesktopWorkflowManifestV1, "desktop_workflow_manifest", "issued_at", "expires_at", timedelta(minutes=60)),
    (DesktopReadRequestV1, "desktop_read_request", "issued_at", "expires_at", timedelta(minutes=2)),
    (AuthorizedD3JobV1, "authorized_d3_job", "authorized_at", "expires_at", timedelta(minutes=2)),
    (AuthorizedD4JobV1, "authorized_d4_job", "authorized_at", "expires_at", timedelta(minutes=2)),
    (RobotSessionActivationV1, "robot_session_activation", "issued_at", "expires_at", timedelta(minutes=10)),
    (RobotReadinessV1, "robot_readiness", "observed_at", "valid_until", timedelta(seconds=2)),
])
def test_wire_authorities_reject_inverted_and_overlong_windows(
    model, fixture_name, start_field, end_field, limit, request,
) -> None:
    payload = request.getfixturevalue(f"{fixture_name}_fixture")
    start = payload[start_field]
    for expiry in (start, start - timedelta(microseconds=1), start + limit + timedelta(microseconds=1)):
        with pytest.raises(ValidationError):
            model.model_validate({**payload, end_field: expiry})

@pytest.mark.parametrize(("model", "fixture_name"), [
    (SignedDesktopGrantV1, "signed_desktop_grant"),
    (SignedDesktopReadRequestV1, "signed_desktop_read_request"),
    (SignedAuthorizedD3JobV1, "signed_authorized_d3_job"),
    (SignedAuthorizedD4JobV1, "signed_authorized_d4_job"),
])
def test_desktop_boundary_envelopes_require_signature(model, fixture_name, request) -> None:
    payload = request.getfixturevalue(f"{fixture_name}_fixture")
    payload.pop("signature")
    with pytest.raises(ValidationError):
        model.model_validate(payload)

def test_transient_frame_declares_exact_bytes(transient_frame_fixture) -> None:
    with pytest.raises(ValidationError):
        TransientFrameV1.model_validate({**transient_frame_fixture, "byte_count": len(transient_frame_fixture["frame_bytes"]) + 1})

@pytest.mark.parametrize(("model", "fixture_name", "field"), [
    (RobotSessionActivationV1, "robot_session_activation", "zone_generation"),
    (RobotSessionActivationV1, "robot_session_activation", "privacy_generation"),
    (RobotSessionActivationV1, "robot_session_activation", "core_key_generation"),
    (RobotMotionLeaseV1, "robot_lease", "area_generation"),
    (RobotMotionLeaseV1, "robot_lease", "robot_binding_generation"),
    (RobotMotionLeaseV1, "robot_lease", "zone_generation"),
    (RobotMotionLeaseV1, "robot_lease", "core_key_generation"),
    (RobotReadinessV1, "robot_readiness", "capability_generation"),
    (RobotReadinessV1, "robot_readiness", "edge_key_generation"),
    (RobotSafetyStateV1, "robot_safety", "edge_key_generation"),
    (RobotStopReceiptV1, "robot_stop_receipt", "capability_generation"),
    (RobotStopReceiptV1, "robot_stop_receipt", "edge_key_generation"),
])
def test_robot_boundary_generations_reject_zero(model, fixture_name, field, request) -> None:
    payload = request.getfixturevalue(f"{fixture_name}_fixture")
    with pytest.raises(ValidationError):
        model.model_validate({**payload, field: 0})
  ```

- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/contract/private_ai tests/contract/vision/test_vision_contracts.py tests/property/private_ai/test_contract_roundtrip.py tests/property/vision/test_contract_rejection.py -q`; expect import/schema failures for the new private-AI package. The selected-frame regression must already pass on the current Phase 3 contract; if it fails, that failure identifies the required shared `zone_generation` reconciliation before Phase 5 proceeds.
- [ ] **Step 3 — Implement the smallest frozen models and generated artifacts.** Use shared bounded primitives, import the canonical Phase 1 `PersonaProjection` without wrapping or widening it, apply `ConfigDict(frozen=True, extra="forbid")`, discriminated closed unions, attached positive bounded-lifetime validators, JCS-signable fields, exact schema IDs/versions, and synthetic values. Register `RouteDecisionV1` directly and register `ApplianceDecisionV1` through `TypeAdapter` so the generated schema retains its `decision` discriminator and forbids cross-variant fields. Verify every signed desktop/robot envelope over its canonical payload and fixed signature domain at the receiving port before consulting any payload field; reject missing, unknown-key, invalid, tampered, expired or replayed envelopes. Regenerate JSON Schema and TypeScript; retain `count_band` only as the Phase 3 advisory observation field.
- [ ] **Step 4 — Prove GREEN and deterministic generation.** Run `uv run python scripts/phase3/generate_vision_schemas.py --check && uv run python scripts/phase5/generate_schemas.py --check && uv run pytest tests/contract/private_ai tests/contract/vision/test_vision_contracts.py tests/property/private_ai/test_contract_roundtrip.py tests/property/vision/test_contract_rejection.py -q && pnpm --filter @tuntun/ui-contracts typecheck && make test-contract`; expect all tests to pass, both generators to report no diff, and no `room_id` or added observation authority.
- [ ] **Step 5 — Commit the contract seam.** Run `git add packages/contracts/src/tuntun_contracts/private_ai packages/ui-contracts/src/generated/private-ai-v1.ts schemas/private-ai/v1 fixtures/synthetic/private-ai/contracts fixtures/adversarial/private-ai/contracts-v1.jsonl scripts/phase5/generate_schemas.py tests/contract/private_ai tests/property/private_ai docs/superpowers/specs/2026-08-27-tuntun-phase5-private-ai-desktop-robotics-design.md && git diff --cached --check && git diff --cached --name-only`; verify that no Phase 3 contract/schema/fixture was restaged or changed, then commit with `git commit -m "feat(phase5): freeze private ai contracts"`.

### Task 02: Build deterministic synthetic Phase 5 fakes and adversarial corpora

**Depends on:** Task 01.

**Gate contribution:** P5-E0 synthetic-only testing foundation.

**Estimated effort:** 1–2 engineering person-days.

**Files:**

- Create: `packages/testing/src/tuntun_testing/private_ai/__init__.py`
- Create: `packages/testing/src/tuntun_testing/private_ai/fake_clock.py`
- Create: `packages/testing/src/tuntun_testing/private_ai/fake_runtime.py`
- Create: `packages/testing/src/tuntun_testing/private_ai/fake_knowledge.py`
- Create: `packages/testing/src/tuntun_testing/private_ai/fake_desktop.py`
- Create: `packages/testing/src/tuntun_testing/private_ai/fake_perception.py`
- Create: `packages/testing/src/tuntun_testing/private_ai/fake_robot.py`
- Create: `packages/testing/src/tuntun_testing/private_ai/fault_points.py`
- Create: `packages/testing/src/tuntun_testing/private_ai/scenario.py`
- Create: `scripts/phase5/build_corpora.py`
- Create: `fixtures/synthetic/private-ai/corpus-manifest-v1.json`
- Create: `fixtures/synthetic/private-ai/route-corpus-v1.jsonl`
- Create: `fixtures/synthetic/private-ai/model-manifests-v1.json`
- Create: `fixtures/synthetic/private-ai/knowledge-sources-v1.json`
- Create: `fixtures/synthetic/private-ai/desktop-registry-v1.json`
- Create: `fixtures/synthetic/private-ai/robot-capabilities-v1.json`
- Create: `fixtures/synthetic/private-ai/lilygo-states-v1.json`
- Create: `fixtures/synthetic/private-ai/fault-matrix-v1.json`
- Create: `fixtures/adversarial/private-ai/knowledge-injection-v1.jsonl`
- Create: `fixtures/adversarial/private-ai/desktop-output-v1.jsonl`
- Create: `fixtures/adversarial/private-ai/selected-frame-v1.jsonl`
- Create: `fixtures/adversarial/private-ai/model-output-v1.jsonl`
- Test: `tests/unit/private_ai/test_synthetic_fakes.py`
- Test: `tests/security/private_ai/test_synthetic_corpora.py`

**Interfaces:** `Phase5Scenario(seed, clock)` constructs temporary keys, stores, task cells, model responses, document bytes, desktop trees, anonymous frames, sensors, battery, and fault injection. `build_corpora.py --check` deterministically verifies exactly 1,000 route cases, 500 document-injection cases, 500 hostile desktop-output cases, and 500 selected-frame prohibited-schema/adversarial-image cases without real names, paths, media, credentials, household IDs, or copyrighted document bodies.

- [ ] **Step 1 — Write failing determinism and privacy tests.** Assert same seed produces byte-identical fixtures, different seeds remain schema-valid, fake process/motor/network calls require explicit enablement, every sentinel is synthetic, and corpus count/digest matches the checked-in manifest.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/unit/private_ai/test_synthetic_fakes.py tests/security/private_ai/test_synthetic_corpora.py -q`; expect missing fake modules and corpus builder.
- [ ] **Step 3 — Implement bounded fakes and manifest generation.** Generate cases in memory during tests, check in only the manifest/seeds, use recognizable `example.invalid`/`synthetic-*` identifiers, and make every I/O fake record admission, cancellation, fault point, and attempted forbidden field.
- [ ] **Step 4 — Prove GREEN and reproducibility.** Run `uv run python scripts/phase5/build_corpora.py --check && uv run pytest tests/unit/private_ai/test_synthetic_fakes.py tests/security/private_ai/test_synthetic_corpora.py -q`; expect exact counts/digests and zero private-data scanner findings.
- [ ] **Step 5 — Commit test infrastructure.** Run `git add packages/testing/src/tuntun_testing/private_ai scripts/phase5/build_corpora.py fixtures/synthetic/private-ai fixtures/adversarial/private-ai tests/unit/private_ai/test_synthetic_fakes.py tests/security/private_ai/test_synthetic_corpora.py && git diff --cached --check && make verify-private-data`; inspect corpus counts/digests and representative generated cases, then commit with `git commit -m "test(phase5): add deterministic private ai fakes"`.

### Task 03: Persist model artifacts, task cells, staged routes, and inference receipts

**Depends on:** Tasks 01–02; canonical migration head `0019_screen_time_real_adapter` verified.

**Gate contribution:** P5-E0 persistence; supports P5-1/P5-3 but activates no route.

**Estimated effort:** 1–2 engineering person-days.

**Files:**

- Create: `apps/core/migrations/versions/0020_private_ai_registry.py`
- Create: `apps/core/src/tuntun_core/domain/private_ai.py`
- Create: `apps/core/src/tuntun_core/services/private_ai/artifact_registry.py`
- Create: `apps/core/src/tuntun_core/services/private_ai/task_cells.py`
- Create: `apps/core/src/tuntun_core/services/private_ai/route_registry.py`
- Modify: `apps/core/src/tuntun_core/adapters/sqlcipher/models.py`
- Create: `apps/core/src/tuntun_core/adapters/sqlcipher/private_ai_registry_repository.py`
- Test: `tests/unit/private_ai/test_task_cell_state.py`
- Test: `tests/integration/private_ai/test_0020_model_route_migration.py`
- Test: `tests/fault/private_ai/test_task_cell_transition_crashes.py`

**Interfaces:** `TaskCellKey(task_class, capability, language_mode, profile_class, sensitivity_class)` is the sole migration unit. Legal stages are `M0_BASELINE -> M1_MAC_ELIGIBLE -> M2_SHADOW -> M3_OWNER_OPT_IN -> M4_ADULT_KNOWLEDGE -> M5_CHILD_ELIGIBLE`; skips and global activation are rejected. Store immutable artifact/runtime/tokenizer/template/evaluation/policy digests, trial/evidence refs, activation/revocation generations, cancellation and content-free receipts. The same `0020` revision creates only the core knowledge binding/recovery/root-migration metadata tables described in the durable map so Task 04 never edits an applied revision; it contains no corpus catalog/content. Extend the already-owned canonical SQLCipher ORM registry in `adapters/sqlcipher/models.py`; `private_ai_registry_repository.py` is the first and only feature repository for these rows. No parallel `adapters/database` package or generic catch-all repository is introduced.

- [ ] **Step 1 — Write failing migration/state-machine tests.** Cover empty migration, upgrade/downgrade/restore, interruption at every DDL boundary, forbidden plaintext columns, unique current route per task cell, one canonical knowledge binding with distinct recovery destination, illegal stage skip, digest mutation revocation, idempotent transition, and crash before/after activation commit.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/unit/private_ai/test_task_cell_state.py tests/integration/private_ai/test_0020_model_route_migration.py tests/fault/private_ai/test_task_cell_transition_crashes.py -q`; expect the missing revision, canonical model additions, repository, and services.
- [ ] **Step 3 — Implement migration and pure transition services.** Extend the existing `adapters/sqlcipher/models.py`, implement the feature-specific repository, use compare-and-swap generations and durable evidence bindings. Default every cell to accepted M0; make activation a transaction that cannot leave two current routes and never stores prompts/results/private identifiers.
- [ ] **Step 4 — Prove GREEN and migration reversibility.** Run `uv run pytest tests/unit/private_ai/test_task_cell_state.py tests/integration/private_ai/test_0020_model_route_migration.py tests/fault/private_ai/test_task_cell_transition_crashes.py -q && uv run alembic upgrade head && uv run python scripts/check_migration_ownership.py --revisions 0020 && uv run alembic downgrade 0019_screen_time_real_adapter && uv run alembic upgrade head && uv run ruff check apps/core/src/tuntun_core/domain/private_ai.py apps/core/src/tuntun_core/services/private_ai/artifact_registry.py apps/core/src/tuntun_core/services/private_ai/task_cells.py apps/core/src/tuntun_core/services/private_ai/route_registry.py apps/core/src/tuntun_core/adapters/sqlcipher/models.py apps/core/src/tuntun_core/adapters/sqlcipher/private_ai_registry_repository.py tests/unit/private_ai/test_task_cell_state.py tests/integration/private_ai/test_0020_model_route_migration.py tests/fault/private_ai/test_task_cell_transition_crashes.py && uv run mypy apps/core/src`; expect all cases, static checks, ownership and the clean round trip to pass.
- [ ] **Step 5 — Commit persistence.** Run `git add apps/core/migrations/versions/0020_private_ai_registry.py apps/core/src/tuntun_core/domain/private_ai.py apps/core/src/tuntun_core/services/private_ai/artifact_registry.py apps/core/src/tuntun_core/services/private_ai/task_cells.py apps/core/src/tuntun_core/services/private_ai/route_registry.py apps/core/src/tuntun_core/adapters/sqlcipher/models.py apps/core/src/tuntun_core/adapters/sqlcipher/private_ai_registry_repository.py tests/unit/private_ai/test_task_cell_state.py tests/integration/private_ai/test_0020_model_route_migration.py tests/fault/private_ai/test_task_cell_transition_crashes.py && git diff --cached --check`; inspect SQL for body/path fields, and commit with `git commit -m "feat(phase5): persist staged task cell routes"`.

### Task 04: Persist canonical knowledge binding and separate catalog lifecycle

**Depends on:** Task 03.

**Gate contribution:** P5-E0/P5-2 durable knowledge foundation; import remains unreachable.

**Estimated effort:** 1–2 engineering person-days.

**Files:**

- Create: `apps/core/src/tuntun_core/domain/knowledge.py`
- Create: `apps/core/src/tuntun_core/services/private_ai/knowledge_binding.py`
- Create: `apps/core/src/tuntun_core/adapters/knowledge/catalog/database.py`
- Create: `apps/core/src/tuntun_core/adapters/knowledge/catalog/models.py`
- Create: `apps/core/src/tuntun_core/adapters/knowledge/catalog/repository.py`
- Create: `apps/core/src/tuntun_core/adapters/knowledge/catalog/migrations/0001_knowledge_sources.py`
- Create: `apps/core/src/tuntun_core/adapters/knowledge/catalog/migrations/0002_knowledge_fts.py`
- Create: `apps/core/src/tuntun_core/adapters/knowledge/catalog/migrations/0003_knowledge_embeddings.py`
- Create: `apps/core/src/tuntun_core/adapters/knowledge/catalog/migrations/0004_knowledge_recovery.py`
- Test: `tests/integration/private_ai/test_knowledge_catalog_migrations.py`
- Test: `tests/property/private_ai/test_knowledge_publish_lifecycle.py`
- Test: `tests/security/private_ai/test_knowledge_catalog_columns.py`

**Interfaces:** Core stores binding/recovery policy metadata only; the separately keyed `catalog.db` lives under the commissioned canonical root and is never SQLite-attached to core. Enforce one current canonical binding, distinct recovery UUID/key/failure domain, exact publish/deletion lifecycles, FTS baseline, embeddings off, and no plaintext title/path/body/secret in core.

- [ ] **Step 1 — Write failing dual-database tests.** Assert independent keys and transactions, migration interruption recovery, one canonical binding, recovery alias/self-destination rejection, catalog upgrade/rebuild/downgrade-or-clean-restore, publish crash matrix, immediate deletion denial, and forbidden schema columns.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/integration/private_ai/test_knowledge_catalog_migrations.py tests/property/private_ai/test_knowledge_publish_lifecycle.py tests/security/private_ai/test_knowledge_catalog_columns.py -q`; expect missing catalog and binding persistence.
- [ ] **Step 3 — Implement minimal migrations and repositories.** Keep opaque object references and commitments in tables, use explicit journal transitions and fsync/transaction boundaries, prohibit cross-database transactions, and make `0003` create inactive derived-data structures only.
- [ ] **Step 4 — Prove GREEN under crash injection.** Run the three narrow suites plus `uv run pytest tests/fault/private_ai -k knowledge -q`; expect every interruption to recover to pre-publish cleanup or one committed current version, never a half-visible source.
- [ ] **Step 5 — Commit knowledge persistence.** Stage the exact migration/domain/catalog/test paths, run `git diff --cached --check && make verify-private-data`, review catalog/core separation, and commit with `git commit -m "feat(phase5): add isolated knowledge catalog"`.

### Task 05: Persist owner desktop grants, exact egress authorization, and D3/D4 jobs

**Depends on:** Tasks 01–03.

**Gate contribution:** P5-E0/P5-4/P5-5 authority state; helper remains unregistered.

**Estimated effort:** 1–2 engineering person-days.

**Files:**

- Create: `apps/core/migrations/versions/0021_desktop_authority.py`
- Create: `apps/core/src/tuntun_core/domain/desktop.py`
- Create: `apps/core/src/tuntun_core/services/private_ai/desktop_authority.py`
- Create: `apps/core/src/tuntun_core/services/private_ai/desktop_jobs.py`
- Modify: `apps/core/src/tuntun_core/adapters/sqlcipher/models.py`
- Create: `apps/core/src/tuntun_core/adapters/sqlcipher/desktop_authority_repository.py`
- Test: `tests/integration/private_ai/test_0021_desktop_migration.py`
- Test: `tests/property/private_ai/test_desktop_job_state.py`
- Test: `tests/security/private_ai/test_desktop_authority_storage.py`

**Interfaces:** Persist `DesktopGrantV1`, `DesktopModelEgressAuthorizationV1`, D3 proposals/confirmations, signed D4 manifests, receiver admission, transitions and content-free receipts. Only owner-local sessions issue grants/egress/confirmation. Egress is exact, at most 15 minutes and never beyond its bound grant, single-use, provider-bound and transactionally consumed; execution-network policy is an independent column and invariant. Extend the canonical SQLCipher model module and first-own `desktop_authority_repository.py`; do not invent `adapters/database` or reuse a generic repository with a wider authority surface.

- [ ] **Step 1 — Write failing migration and state tests.** Cover upgrade/restore, owner-role trigger, egress duplicate/replay/expiry/revocation/provider mismatch, network/egress independence, D3/D4 discriminator, legal job lifecycle, pre-I/O commit, helper mismatch, uncertain reconciliation, and forbidden raw path/content/secret columns.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/integration/private_ai/test_0021_desktop_migration.py tests/property/private_ai/test_desktop_job_state.py tests/security/private_ai/test_desktop_authority_storage.py -q`; expect the missing revision, canonical model additions, feature repository, and authority services.
- [ ] **Step 3 — Implement transactional authority and jobs.** Extend the canonical SQLCipher models, implement `desktop_authority_repository.py`, use root/file commitments and opaque display-message IDs, CAS generation/revocation, one egress-consumption row per authorization, and durable `AUTHORIZED_COMMITTED` before returning a dispatchable job.
- [ ] **Step 4 — Prove GREEN and fail closed.** Run `uv run pytest tests/integration/private_ai/test_0021_desktop_migration.py tests/property/private_ai/test_desktop_job_state.py tests/security/private_ai/test_desktop_authority_storage.py tests/fault/private_ai -k desktop -q && uv run python scripts/check_migration_ownership.py --revisions 0021 && uv run ruff check apps/core/src/tuntun_core/domain/desktop.py apps/core/src/tuntun_core/services/private_ai/desktop_authority.py apps/core/src/tuntun_core/services/private_ai/desktop_jobs.py apps/core/src/tuntun_core/adapters/sqlcipher/models.py apps/core/src/tuntun_core/adapters/sqlcipher/desktop_authority_repository.py tests/integration/private_ai/test_0021_desktop_migration.py tests/property/private_ai/test_desktop_job_state.py tests/security/private_ai/test_desktop_authority_storage.py && uv run mypy apps/core/src`; expect migration ownership and all crash/replay cases to remain denied or reconcilable without re-execution.
- [ ] **Step 5 — Commit desktop authority persistence.** Run `git add apps/core/migrations/versions/0021_desktop_authority.py apps/core/src/tuntun_core/domain/desktop.py apps/core/src/tuntun_core/services/private_ai/desktop_authority.py apps/core/src/tuntun_core/services/private_ai/desktop_jobs.py apps/core/src/tuntun_core/adapters/sqlcipher/models.py apps/core/src/tuntun_core/adapters/sqlcipher/desktop_authority_repository.py tests/integration/private_ai/test_0021_desktop_migration.py tests/property/private_ai/test_desktop_job_state.py tests/security/private_ai/test_desktop_authority_storage.py && git diff --cached --check && make verify-private-data`; inspect that no shell/body/path/provider credential is stored, and commit with `git commit -m "feat(phase5): persist bounded desktop authority"`.

### Task 06: Persist robot inventory, safety evidence, geofences, and sessions

**Depends on:** Tasks 01–03.

**Gate contribution:** P5-E0/P5-7 durable robotics foundation; motion remains absent.

**Estimated effort:** 1 engineering person-day.

**Files:**

- Create: `apps/core/migrations/versions/0022_robotics.py`
- Create: `apps/core/src/tuntun_core/domain/robotics.py`
- Create: `apps/core/src/tuntun_core/services/private_ai/robot_policy.py`
- Modify: `apps/core/src/tuntun_core/adapters/sqlcipher/models.py`
- Create: `apps/core/src/tuntun_core/adapters/sqlcipher/robotics_repository.py`
- Test: `tests/integration/private_ai/test_0022_robotics_migration.py`
- Test: `tests/property/private_ai/test_robot_session_state.py`
- Test: `tests/security/private_ai/test_robotics_storage.py`

**Interfaces:** Persist pseudonymous exact hardware/software inventory and capability-evidence digest, canonical `area_id`, versioned `zone_id` owned by one robot-binding generation, surveyed geofence, owner-local-supervised session, controller epoch, stop/safety receipts, and optional LILYGO pairing. Do not persist video/audio/map/identity/lease stream or a resumable motion bit. Extend the canonical SQLCipher models and first-own `robotics_repository.py`; no alternate database adapter or generic repository is permitted.

- [ ] **Step 1 — Write failing schema/state tests.** Assert `room_id` rejection, cross-area/cross-binding zone rejection, one supervised session, owner/local-role constraints, boot/controller-epoch invalidation, no restart resume, safety-evidence invalidation, legal stop-first transitions, and forbidden media/identity/credential columns.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/integration/private_ai/test_0022_robotics_migration.py tests/property/private_ai/test_robot_session_state.py tests/security/private_ai/test_robotics_storage.py -q`; expect the missing revision, canonical model additions, feature repository, and policy service.
- [ ] **Step 3 — Implement migration and pure policy transitions.** Extend the canonical SQLCipher models, implement `robotics_repository.py`, default every capability to absent, require surveyed-common-area classification and exact binding generations, rotate epoch on start/reconnect, and persist content-safe stop truth without claiming physical confirmation from network receipt alone.
- [ ] **Step 4 — Prove GREEN.** Run `uv run pytest tests/integration/private_ai/test_0022_robotics_migration.py tests/property/private_ai/test_robot_session_state.py tests/security/private_ai/test_robotics_storage.py -q && uv run alembic upgrade head && uv run python scripts/check_migration_ownership.py --revisions 0022 && uv run ruff check apps/core/src/tuntun_core/domain/robotics.py apps/core/src/tuntun_core/services/private_ai/robot_policy.py apps/core/src/tuntun_core/adapters/sqlcipher/models.py apps/core/src/tuntun_core/adapters/sqlcipher/robotics_repository.py tests/integration/private_ai/test_0022_robotics_migration.py tests/property/private_ai/test_robot_session_state.py tests/security/private_ai/test_robotics_storage.py && uv run mypy apps/core/src`; expect head `0022`, exact migration ownership, all illegal topology/session transitions denied, and no motion activation path.
- [ ] **Step 5 — Commit robotics persistence.** Run `git add apps/core/migrations/versions/0022_robotics.py apps/core/src/tuntun_core/domain/robotics.py apps/core/src/tuntun_core/services/private_ai/robot_policy.py apps/core/src/tuntun_core/adapters/sqlcipher/models.py apps/core/src/tuntun_core/adapters/sqlcipher/robotics_repository.py tests/integration/private_ai/test_0022_robotics_migration.py tests/property/private_ai/test_robot_session_state.py tests/security/private_ai/test_robotics_storage.py && git diff --cached --check && make verify-private-data`; inspect location and no-resume invariants, and commit with `git commit -m "feat(phase5): persist robot safety authority"`.

### Task 07: Register fail-closed Phase 5 feature families and Privacy Shield effects

**Depends on:** Tasks 01–06.

**Gate contribution:** P5-E0 negative reachability and shared contract seam.

**Estimated effort:** 1–2 engineering person-days.

**Files:**

- Modify: `apps/core/src/tuntun_core/services/features/registry.py`
- Modify: `apps/admin/src/app/feature-registry.ts`
- Create: `apps/core/src/tuntun_core/services/private_ai/privacy_effects.py`
- Create: `apps/core/src/tuntun_core/api/routes/private_ai.py`
- Create: `apps/core/src/tuntun_core/api/phase5_dtos.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Modify: `ops/services/phase3-owner-ingress.v1.json`
- Modify: `packages/contracts/src/tuntun_contracts/features.py`
- Modify: `schemas/features/v1/feature-manifest-v1.schema.json`
- Create: `fixtures/synthetic/features/phase5-private-ai-manifest-v1.json`
- Modify: `packages/contracts/openapi/admin-v1.yaml`
- Modify: `apps/admin/src/api/generated/admin-v1.ts`
- Modify: `apps/admin/src/app/router.tsx`
- Test: `tests/integration/private_ai/test_phase5_feature_absence.py`
- Create: `tests/integration/private_ai/test_phase5_owner_ingress_composition.py`
- Test: `tests/integration/deploy/test_owner_ingress_route_manifest.py`
- Test: `tests/integration/vision/test_deployed_process_entrypoints.py`
- Test: `tests/integration/deploy/test_phase3_side_process_lifecycle.py`
- Test: `tests/integration/vision/test_owner_ingress_takeover.py`
- Test: `tests/fault/vision/test_owner_ingress_takeover_rollback.py`
- Test: `tests/contract/private_ai/test_phase5_feature_manifest.py`
- Test: `apps/admin/src/app/feature-registry.test.ts`

**Interfaces:** Add independent signed families `private_ai.models`, `private_ai.knowledge`, `private_ai.desktop_d0`, `private_ai.desktop_d1`, `private_ai.desktop_d2`, `private_ai.desktop_d3`, `private_ai.desktop_d4`, `private_ai.perception`, `private_ai.robotics`, and `private_ai.lilygo`. The initial manifest has every family `absent` with reason/evidence/invalidation digest. Register Privacy Shield cancellation effects but no capability endpoint until the exact family gate passes. `private_ai.py` exports only a pure `build_router(dependencies, enabled_facts)` factory. This first owner-route checkpoint composes only its signed availability endpoint into the canonical Core app and exact owner-ingress manifest; every capability route remains omitted/`404`. It rebuilds and re-signs the canonical Phase 3 owner-ingress row before the P5-E0 installed negative baseline is accepted.

- [ ] **Step 1 — Write failing direct-reachability and installed-composition tests.** For every absent family test direct URL, API, prepared-action type, client bundle import, background worker, IPC socket, network listener, and runtime package registration. Test unknown/stale/unsigned manifest rejection, Privacy Shield effect enumeration, import-side-effect absence, exactly one listener, availability positive through listener -> ingress -> Core UDS, unknown/disabled `404` without Core dispatch, route/manifest/wheel/row digest mismatch, and old Phase 4 row rejection under the new candidate.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/integration/private_ai/test_phase5_feature_absence.py tests/contract/private_ai/test_phase5_feature_manifest.py tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py -q && pnpm --filter @tuntun/admin test -- feature-registry.test.ts`; expect missing family definitions/effects and the uncomposed candidate availability route.
- [ ] **Step 3 — Implement metadata, pure factory, and the first atomic owner-route candidate.** Bind each family to its own gate/evidence digest, register atomic revocation/cancellation hooks, and ensure tree-shaking/lazy-loading omits absent client chunks. Explicitly construct only the availability factory from the canonical container, compose it into the Core app, add only its exact method/path upstream to owner ingress, sign the route manifest, rebuild the ingress wheel and refresh/re-sign `phase3-owner-ingress.v1`. Install the complete candidate disabled, verify exact bytes, then atomically take over; never expose a mixed route/wheel/row generation.
- [ ] **Step 4 — Prove GREEN, absence, and installed lifecycle.** Run the narrow suites plus `uv run pytest tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py -q && make test-contract && pnpm --filter @tuntun/admin build`; expect the signed availability route through the sole listener, every absent/unknown route `404` without Core dispatch, current takeover/start/health/crash-restart/update/rollback/both-uninstall evidence, and no absent client chunk. The previous Phase 4 row must fail the current verifier but remain a valid complete rollback set.
- [ ] **Step 5 — Commit the shared feature and installed-ingress seam.** Stage the listed registry/effect/contract/API/test paths plus `apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/api/app.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json ops/services/phase3-owner-ingress.v1.json tests/integration/private_ai/test_phase5_owner_ingress_composition.py`, run `git diff --cached --check`, inspect signed absence and the candidate digest graph, and commit with `git commit -m "feat(phase5): register fail closed feature families"`.

### Task 08: Capture content-safe inventory and approve the Phase 5 threat/privacy baseline

**Depends on:** Tasks 02 and 07; owner can inspect hardware/software without downloading or activating it.

**Gate contribution:** Completes P5-E0 and P5-0 architecture baseline.

**Estimated effort:** 1 engineering person-day plus owner hardware/software inspection time.

**Files:**

- Create: `scripts/phase5/inventory.py`
- Create: `docs/security/phase5-threat-model.md`
- Create: `docs/privacy/phase5-data-flow.md`
- Create: `docs/operations/phase5-inventory.md`
- Create: `docs/evidence/phase5-inventory.schema.json`
- Test: `tests/security/private_ai/test_phase5_inventory.py`
- Test: `tests/privacy/private_ai/test_phase5_data_flow.py`

**Interfaces:** Inventory captures pseudonymous Mac CPU/RAM/OS/disk, candidate runtimes and artifact provenance, storage UUID classes, appliance/NIC/firewall claims, desktop-helper/sandbox backends, exact delivered Raspbot/LILYGO revisions and ports/dependencies, physical e-stop/sensors/charger/indicator, trust boundaries, data classes, failure modes and invalidation triggers. Output omits serials, MAC/IP addresses, usernames, paths, SSIDs, document names, media and credentials.

- [ ] **Step 1 — Write failing schema/redaction/threat-coverage tests.** Require every Phase 5 asset, actor, boundary, abuse path, mitigation, gate owner, rollback and privacy retention/egress row; inject synthetic serial/path/IP/secret/media sentinels and assert rejection.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/security/private_ai/test_phase5_inventory.py tests/privacy/private_ai/test_phase5_data_flow.py -q`; expect missing script/schema/doc coverage.
- [ ] **Step 3 — Implement read-only collection and signed review documents.** `inventory.py --synthetic` produces a fixture; owner mode requires explicit flag, hashes stable identities with an evidence-only salt, executes no repo or downloaded code, opens no network, and records `unknown` as a disabling fact rather than an assumption.
- [ ] **Step 4 — Prove GREEN and perform owner inspection.** Run `uv run python scripts/phase5/inventory.py --synthetic --output /tmp/phase5-inventory.json && uv run pytest tests/security/private_ai/test_phase5_inventory.py tests/privacy/private_ai/test_phase5_data_flow.py -q && make verify-private-data`; expect schema-valid content-safe evidence and complete threat/privacy matrices. Run owner inventory separately only when available; a missing physical fact leaves its dependent family absent without blocking unrelated software work.
- [ ] **Step 5 — Commit the P5-0 baseline.** Stage exact script/docs/schema/tests, run `git diff --cached --check`, inspect that evidence values are synthetic or pseudonymous, and commit with `git commit -m "docs(phase5): establish inventory threat privacy baseline"`.

---

## Wave 1 — P5-1 Mac Task-Cell Inference and Measured Routing

### Task 09: Implement the closed inference gateway and local-runtime boundary

**Depends on:** Tasks 01–03 and 08.

**Gate contribution:** P5-1 functional inference boundary; routes remain M0.

**Estimated effort:** 2–3 engineering person-days.

**Files:**

- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Create: `apps/inference-proxy/pyproject.toml`
- Create: `apps/inference-proxy/src/tuntun_inference_proxy/__init__.py`
- Create: `apps/core/src/tuntun_core/services/private_ai/inference_gateway.py`
- Create: `apps/core/src/tuntun_core/services/private_ai/inference_validation.py`
- Create: `apps/core/src/tuntun_core/adapters/inference/local_mac.py`
- Create: `apps/inference-proxy/src/tuntun_inference_proxy/server.py`
- Create: `apps/inference-proxy/src/tuntun_inference_proxy/verifier.py`
- Create: `apps/inference-proxy/src/tuntun_inference_proxy/runtime.py`
- Create: `apps/inference-proxy/src/tuntun_inference_proxy/cancellation.py`
- Create: `apps/inference-proxy/src/tuntun_inference_proxy/health.py`
- Test: `tests/unit/private_ai/test_inference_gateway.py`
- Test: `tests/contract/private_ai/test_inference_proxy_protocol.py`
- Test: `tests/security/private_ai/test_closed_inference_boundary.py`
- Create: `tests/unit/private_ai/test_phase5_package_smoke.py`

**Interfaces:** Core signs `SanitizedInferenceRequestV1`; proxy verifies the exact activated cell/digests, deadline, cancellation, token/size limits and local peer, then returns signed `InferenceResultV1`. The runtime adapter receives a locally pinned template and bounded typed segments, invokes an argv array without shell, accepts only a registered output schema, and exposes no tool/action/memory/filesystem/media/identity/network authority. This task also registers the independently packaged `tuntun-inference-proxy` root-workspace member, with `tuntun-inference-proxy = tuntun_inference_proxy.server:main`; `server.py` owns injectable `run(argv, runtime) -> int`, side-effect-free `--help`/`--version`, fail-closed `start --config`, and bounded read-only `health --config ... --json`. The package depends only on `tuntun-contracts`, never `tuntun-core`.

- [ ] **Step 1 — Write failing boundary tests.** Cover valid synthetic request/result, unknown schema/field/task cell, forged/stale signature, deadline/cancellation race, token overflow, camera bytes/URLs/paths/IDs/credentials/tool call in input or output, prompt injection in retrieval/tool-output segments, malformed runtime JSON, process crash, and duplicate request idempotency. The package-smoke test imports `tuntun_inference_proxy`, asserts version `0.1.0.dev0`, resolves its installed entry point, and rejects any `tuntun_core` import edge.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/unit/private_ai/test_phase5_package_smoke.py tests/unit/private_ai/test_inference_gateway.py tests/contract/private_ai/test_inference_proxy_protocol.py tests/security/private_ai/test_closed_inference_boundary.py -q`; expect missing project metadata and gateway/proxy modules.
- [ ] **Step 3 — Implement core/proxy validation and fake-backed runtime.** Add `apps/inference-proxy` to the existing root `[tool.uv.workspace].members` without replacing prior members, update `uv.lock`, and create a Hatchling `apps/inference-proxy/pyproject.toml` with Python `==3.12.*`, project/version above, workspace dependency `tuntun-contracts`, and the frozen script entry point. Define `__version__ = "0.1.0.dev0"`. Verify before deserialization beyond the bounded envelope, build prompts only from pinned template roles, parse against the named closed output model, persist content-free receipt/admission before runtime I/O, zero transient buffers, and fail closed on cancellation ambiguity.
- [ ] **Step 4 — Prove GREEN and no authority widening.** Run `uv lock && uv sync --all-packages && uv run pytest tests/unit/private_ai/test_phase5_package_smoke.py tests/unit/private_ai/test_inference_gateway.py tests/contract/private_ai/test_inference_proxy_protocol.py tests/security/private_ai/test_closed_inference_boundary.py tests/property/private_ai -k inference -q && uv build apps/inference-proxy && uv run tuntun-inference-proxy --help && uv run ruff check apps/core/src/tuntun_core/services/private_ai apps/inference-proxy tests/unit/private_ai/test_phase5_package_smoke.py && uv run mypy apps/inference-proxy/src`; expect the locked workspace/build/entry point to pass, every adversarial value rejected, and no runtime call for invalid input.
- [ ] **Step 5 — Commit the inference boundary.** Stage `pyproject.toml uv.lock apps/inference-proxy/pyproject.toml apps/inference-proxy/src/tuntun_inference_proxy apps/core/src/tuntun_core/services/private_ai/inference_gateway.py apps/core/src/tuntun_core/services/private_ai/inference_validation.py apps/core/src/tuntun_core/adapters/inference/local_mac.py tests/unit/private_ai/test_phase5_package_smoke.py tests/unit/private_ai/test_inference_gateway.py tests/contract/private_ai/test_inference_proxy_protocol.py tests/security/private_ai/test_closed_inference_boundary.py`, run `git diff --cached --check && make verify-private-data`, inspect subprocess and schema handling, and commit with `git commit -m "feat(phase5): add closed inference gateway"`.

### Task 10: Quarantine and verify model/runtime supply-chain artifacts

**Depends on:** Tasks 03, 08 and 09.

**Gate contribution:** P5-1 artifact eligibility; no cell activation.

**Estimated effort:** 1 engineering person-day plus owner-approved acquisition-window time.

**Files:**

- Create: `apps/core/src/tuntun_core/services/private_ai/artifact_verifier.py`
- Create: `apps/core/src/tuntun_core/services/private_ai/artifact_acquisition.py`
- Create: `scripts/phase5/verify_model_artifact.py`
- Create: `docs/operations/phase5-model-artifacts.md`
- Create: `docs/evidence/phase5-model-artifact.schema.json`
- Test: `tests/unit/private_ai/test_artifact_verifier.py`
- Test: `tests/security/private_ai/test_model_artifact_supply_chain.py`
- Test: `tests/fault/private_ai/test_artifact_quarantine.py`

**Interfaces:** Owner-approved maintenance-window acquisition streams only an exact pinned HTTPS source into quarantine; it never activates or loads during download. Verify the model, tokenizer, quantization/calibration, runtime binary/libraries, prompt templates, parser/container and evaluation bundle independently against `ModelArtifactManifestV1`. Evidence binds SHA-256, source URL commitment, acquisition time, licence, SBOM, signature/checksum source, architecture, declared size, scanner versions, runtime flags and approval identity. Unknown licence/provenance/custom code, symlink/device/archive escape, executable model payload, digest drift, `trust_remote_code`, network-dependent load, sample server/UI/telemetry/plugin loader or unsupported format stays quarantined. Model caches never enter source control or ordinary family backups.

- [ ] **Step 1 — Write failing verifier tests.** Use synthetic tiny artifact bytes and archives to test all required evidence, size/hash mismatch, path traversal, symlink, nested archive, executable bit/header, mutable tag, unsafe loader flag, malicious metadata, TOCTOU replacement, interrupted promotion and immutable accepted copy. Parameterize empty/oversized/duplicate source, licence, supported-task, prohibited-task and route collections; every supported/prohibited overlap; revocation without activation; and revocation at/before activation. Each fails contract validation before acquisition, registry or artifact I/O.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/unit/private_ai/test_artifact_verifier.py tests/security/private_ai/test_model_artifact_supply_chain.py tests/fault/private_ai/test_artifact_quarantine.py -q`; expect missing verifier/script.
- [ ] **Step 3 — Implement separately authorized acquisition, offline verification and atomic promotion.** Acquisition requires an owner-approved maintenance window and exact pinned source/size/digest, has no provider/family credential, and writes quarantine only. Verification otherwise accepts a resolved local descriptor with network disabled, hashes while copying to mode-restricted staging, inspects through pinned least-privilege parsers, fsyncs and atomically publishes under digest, then binds the registry row. Keep weights/caches outside Git and ordinary backups.
- [ ] **Step 4 — Prove GREEN.** Run the narrow suites and `uv run python scripts/phase5/verify_model_artifact.py --synthetic --evidence-root /tmp/phase5-artifact-evidence`; expect one schema-valid synthetic pass and each malicious fixture quarantined with a bounded reason code.
- [ ] **Step 5 — Commit artifact verification.** Stage exact files, run `git diff --cached --check && make verify-private-data`, confirm no artifact binaries/source URLs/host paths entered Git, and commit with `git commit -m "feat(phase5): verify model artifact provenance"`.

### Task 11: Route each task cell through consent, privacy, budget, and preemption policy

**Depends on:** Tasks 03, 07, 09 and 10.

**Gate contribution:** P5-1 policy path; default route remains M0.

**Estimated effort:** 1–2 engineering person-days.

**Files:**

- Create: `apps/core/src/tuntun_core/services/private_ai/route_policy.py`
- Create: `apps/core/src/tuntun_core/services/private_ai/inference_budget.py`
- Create: `apps/core/src/tuntun_core/adapters/inference/cloud.py`
- Modify: `apps/core/src/tuntun_core/services/private_ai/privacy_effects.py`
- Modify: `apps/core/src/tuntun_core/services/private_ai/task_cells.py`
- Test: `tests/unit/private_ai/test_route_policy.py`
- Test: `tests/property/private_ai/test_task_cell_routing.py`
- Test: `tests/privacy/private_ai/test_inference_consent_and_egress.py`
- Test: `tests/fault/private_ai/test_inference_preemption.py`

**Interfaces:** The frozen `RouteDecisionV1` binds a purpose-separated HMAC commitment over the canonical JCS bytes of the complete signed `SanitizedInferenceRequestV1`, including its key ID/signature, plus the exact task cell key, request/capability/response schema, current M0–M5 stage and activation generation, model/tokenizer/runtime/template/evaluation/policy digests, exact request deadline, sensitivity and egress class, profile/child eligibility, consent receipts, privacy/preemption state, local zone health/headroom/queue/temperature/deadline facts, cloud eligibility, paired reservation ID/generation, and cancellation ID/generation. Dispatch recomputes that full request commitment and verifies the decision commitment/current generations before any artifact registry, budget consumption, runtime, provider, or task-cell I/O. Evaluate in the normative order: privacy/consent/child-Guest/sensitivity/raw-media; required capability/schema; exact cell activation; local health/headroom/queue/temperature/deadline; cloud review/WAN/egress/budget; then quality, latency and measured energy/cost. Local-only never falls back to cloud. Privacy/voice/recording/backup pressure preempts inference. An owner-operated GPU VPS is cloud: only synthetic/de-identified evaluation or a separately approved low-sensitivity cell, outbound Mac TLS/workload identity, encrypted ephemeral volume, no body logs/ambient admin UI, region review, S$150-cap reservation including storage/snapshot/egress, deadline termination, forensic deletion evidence and no 24×7 instance.

- [ ] **Step 1 — Write failing route matrix tests.** Generate at least 10,000 task-cell/state combinations with Hypothesis: stage/digest/profile/language/sensitivity mismatch, M5 child approval loss, expired consent, local pressure, cloud budget denial, local-only, privacy activation, timeout and simultaneous route revocation. Mutate each bound field after decision while retaining the original commitment and assert `RouteDecisionV1` or commitment verification fails before any artifact registry, runtime, provider, budget-consumption, or task-cell domain read. Add GPU-VPS region/reservation/deadline/ephemeral-disk/body-log/admin-channel/forensic-delete/24×7 denial cases. Assert exactly one decision and no data sent before reservation/consent commit.

```python
@pytest.mark.parametrize("field", [
    "persona_descriptor", "input_segments", "max_input_tokens", "max_output_tokens",
])
async def test_decision_cannot_authorize_mutated_exact_request(route_service, signed_request, field, io_spies) -> None:
    decision = await route_service.decide(signed_request)
    mutated = mutate_valid_request_field(signed_request, field, preserve_request_id=True)
    with pytest.raises(RouteDenied, match="exact_request_commitment_mismatch"):
        await route_service.dispatch(mutated, decision)
    assert io_spies.artifact_registry_reads == io_spies.budget_consumptions == 0
    assert io_spies.runtime_calls == io_spies.provider_calls == io_spies.task_cell_reads == 0

async def test_route_decision_replay_against_another_signed_request_denies_before_io(
    route_service, signed_request, another_same_id_request, io_spies,
) -> None:
    decision = await route_service.decide(signed_request)
    assert decision.request_commitment == purpose_hmac(
        "phase5.sanitized-inference-request.v1", canonical_private_ai_bytes(signed_request),
    )
    with pytest.raises(RouteDenied, match="exact_request_commitment_mismatch"):
        await route_service.dispatch(another_same_id_request, decision)
    assert io_spies.total_reads_and_calls == 0
```
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/unit/private_ai/test_route_policy.py tests/property/private_ai/test_task_cell_routing.py tests/privacy/private_ai/test_inference_consent_and_egress.py tests/fault/private_ai/test_inference_preemption.py -q`; expect missing route/budget policy.
- [ ] **Step 3 — Implement pure decision order and cancellation fan-out.** Keep cloud/VPS adapters behind the existing approved provider/DLP port, consume full cost/region/time reservations idempotently, bind every decision to current generations, terminate ephemeral VPS work at reservation deadline, require deletion evidence and make preemption revoke admission before cancelling worker execution.
- [ ] **Step 4 — Prove GREEN and existing-latency safety.** Run the narrow suites plus `uv run pytest tests/integration -k "privacy or budget or conversation" -q`; expect route properties to pass and existing privacy/voice behavior unchanged.
- [ ] **Step 5 — Commit routing policy.** Stage exact paths, run `git diff --cached --check`, inspect local-only/cloud and child handling, and commit with `git commit -m "feat(phase5): route inference by exact task cell"`.

### Task 12: Benchmark the active approved Core Mac under canonical household load

**Depends on:** Tasks 08–11; the independently owner-approved opaque active-Core inventory target, currently verified as Darwin `arm64`, and a locally verified candidate artifact/runtime are physically available. If the owner later chooses an Intel Mac as household target, trusted approval and this full real-host campaign must be repeated for that opaque target before any Intel household-performance claim.

**Gate contribution:** P5-1 measured hardware gate; absence evidence is the only valid result without the actual Mac campaign.

**Estimated effort:** 4–7 engineering person-days plus non-compressible two-hour, eight-hour, and seven-day hardware evidence.

**Files:**

- Create: `scripts/phase5/benchmark_control_host.py`
- Create: `docs/operations/phase5-control-host-benchmark.md`
- Create: `docs/evidence/phase5-control-host-benchmark.schema.json`
- Create: `ops/launchd/phase5/com.tuntun.inference-proxy.plist`
- Create: `ops/services/phase5-inference-proxy.v1.json`
- Test: `tests/unit/private_ai/test_control_host_benchmark_harness.py`
- Test: `tests/performance/private_ai/test_control_host_limits.py`
- Test: `tests/hardware/private_ai/test_control_host_campaign.py`
- Test: `tests/integration/private_ai/test_inference_proxy_service_lifecycle.py`

**Interfaces:** The marker-gated harness binds pseudonymous exact CPU/GPU/RAM/macOS/free-disk/thermal/power/runtime/artifact/configuration and measures pre-launch available memory, peak RSS, artifact size, sustained logical-core use, concurrency, p50/p95/first/total token latency, fan/noise, power, disk I/O, model-load, cancellation, cold/restart, swap/thermal/queue/cache, background headroom, and Phase 1 wake/stop/privacy/first-audio plus Phase 3 recording/Green-backup effects. It includes one worst-case 90-second voice turn plus candidate workload and runs two-hour simultaneous, eight-hour idle/periodic, and seven-day mixed campaigns using synthetic/de-identified prompts only. The seven-day runner consumes the canonical Phase 2 pre-issued chain through `FeatureManifestLeaseSupervisor`; its receipt binds one frozen candidate, chain ID, ordered signed-envelope and transition-receipt digests, interval, and zero expired-authority interval, and every job/background sample checks the half-open wall and monotonic lease. The rendered launch daemon and `phase5-inference-proxy.v1` row implement the frozen service baseline exactly: absolute app-bundle executable, `start` plus the exact root-owned configuration path, `_tuntun_inference`, mode-`0660` `/private/var/run/tuntun/inference-proxy.sock`, bounded health, crash-only restart, and exact owned cleanup. The service has no TCP listener, ambient home, provider credential, corpus mount, camera access, unregistered model path, acceptance signer, or renewal service.

- [ ] **Step 1 — Write failing harness, threshold, lifecycle, and authority tests.** Feed synthetic metric traces at every boundary and assert: artefact ≤3.5 GiB, process RSS ≤4 GiB, pre-launch available ≥6 GiB, average ≤2 logical cores, concurrency exactly one, background headroom ≥4 GiB, no forbidden failure, and no accepted latency P95 regression over 10%. Assert interruption resumes evidence collection but never fabricates elapsed duration. Reject missing/extra/reordered/late successors, bad signature/hash link, candidate/package/registration drift, future activation, wall or monotonic equality, rollback, restart lease reuse, missing transition receipt, and any metric/job admission after authority closes; prove zero inference I/O for each. Parse the installed plist/inventory and assert the exact command/account/config/socket/restart/cleanup row; drive help/version/start/health/SIGTERM, wrong account/config, deliberate crash/restart, old-generation request replay, stale socket, and both uninstall modes with injected resources.
- [ ] **Step 2 — Prove RED without touching hardware.** Run `uv run pytest tests/unit/private_ai/test_control_host_benchmark_harness.py tests/performance/private_ai/test_control_host_limits.py tests/integration/private_ai/test_inference_proxy_service_lifecycle.py -q`; expect the missing harness/schema/plist/service row/lifecycle. Confirm `uv run pytest tests/hardware/private_ai/test_control_host_campaign.py -q` skips with the exact missing flag/hardware reason.
- [ ] **Step 3 — Implement the read-only metric harness and exact preemptible service.** Use argv-only local runtime launch, one-job semaphore, OS-native process metrics, monotonic timestamps, baseline snapshots, signal-safe cancellation and signed append-only evidence. Render the plist and service row from one typed description, verify executable containment/digests and root-owned configuration before bind, rotate a durable boot generation before accepting work, remove only a proved stale owned socket, and make health read-only. Never install/download a model or change production routes.
- [ ] **Step 4 — Prove GREEN and lifecycle without starting the physical clock.** Run `uv run pytest tests/unit/private_ai/test_control_host_benchmark_harness.py tests/performance/private_ai/test_control_host_limits.py tests/integration/private_ai/test_inference_proxy_service_lifecycle.py -q && plutil -lint ops/launchd/phase5/com.tuntun.inference-proxy.plist`; use fake-clock traces and signed fixture chains to prove all duration, threshold, transition, expiry and zero-I/O failure behavior. Confirm the hardware suite still skips without a committed clean candidate and matching owner flag. Do not start the two-hour, eight-hour, or seven-day campaign before Step 5 commits the complete harness/service/schema/test bytes.
- [ ] **Step 5 — Commit harness and service contract, not local evidence.** Run `git add scripts/phase5/benchmark_control_host.py docs/operations/phase5-control-host-benchmark.md docs/evidence/phase5-control-host-benchmark.schema.json ops/launchd/phase5/com.tuntun.inference-proxy.plist ops/services/phase5-inference-proxy.v1.json tests/unit/private_ai/test_control_host_benchmark_harness.py tests/performance/private_ai/test_control_host_limits.py tests/hardware/private_ai/test_control_host_campaign.py tests/integration/private_ai/test_inference_proxy_service_lifecycle.py && git status --short var/evidence/phase5 && git diff --cached --check`; require evidence status empty/ignored, then commit with `git commit -m "test(phase5): qualify control-host inference limits"`.

After that commit, verify the worktree is clean, rebuild and lifecycle-qualify the resolved bytes without changing them, and prepare a new externally signed canonical chain for that exact commit/candidate. Only then run `TUNTUN_ALLOW_CONTROL_HOST_BENCHMARK=1 uv run python scripts/phase5/benchmark_control_host.py --feature-manifest-chain var/evidence/phase5/feature-authority/signed-rollover-chain.json --duration-seconds 604800 --evidence-root var/evidence/phase5/control-host`; require schema-valid signed evidence for the two-hour, eight-hour, and seven-day intervals, every resource threshold, ordered transitions, and zero expired-authority interval. Verify it with `TUNTUN_ALLOW_CONTROL_HOST_BENCHMARK=1 uv run pytest tests/hardware/private_ai/test_control_host_campaign.py -q`. Any missing/failed interval or authority fault records `mac_cell_ineligible`, closes inference admission, unloads/removes the production service artifacts for that feature, and keeps the cell M0. Only this clean-commit run may promote a Mac task cell; any later bound-byte change invalidates it. Intel may be promoted only by repeating this real-host procedure on the Intel target.

### Task 13: Evaluate and expose only individually promoted M1 task cells

**Depends on:** Tasks 02, 03 and 09–12; one or more actual Mac evidence bundles may pass.

**Gate contribution:** Completes P5-1 per-cell; failed cells retain prior eligible behavior.

**Estimated effort:** 3–5 engineering person-days.

**Files:**

- Create: `scripts/phase5/evaluate_task_cells.py`
- Create: `docs/evidence/phase5-task-cell-evaluation.schema.json`
- Create: `apps/admin/src/features/ai-workspace/index.ts`
- Create: `apps/admin/src/features/ai-workspace/models.tsx`
- Create: `apps/admin/src/routes/ai-workspace-models.tsx`
- Modify: `packages/contracts/openapi/admin-v1.yaml`
- Modify: `apps/admin/src/api/generated/admin-v1.ts`
- Modify: `apps/admin/src/app/router.tsx`
- Modify: `apps/core/src/tuntun_core/api/routes/private_ai.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Modify: `ops/services/phase3-owner-ingress.v1.json`
- Modify: `apps/core/src/tuntun_core/services/features/registry.py`
- Modify: `apps/admin/src/app/feature-registry.ts`
- Test: `tests/acceptance/private_ai/test_p5_1_task_cell_gate.py`
- Test: `tests/security/private_ai/test_task_cell_promotion.py`
- Test: `apps/admin/src/features/ai-workspace/models.test.tsx`
- Test: `tests/ui/ai-workspace-models.spec.ts`
- Test: `tests/integration/private_ai/test_phase5_owner_ingress_composition.py`

**Interfaces:** Evaluation records exact route/corpus/artifact/runtime/tokenizer/template/policy/hardware digests and per-cell quality, refusal, injection, privacy, latency, load and rollback results. English, Hindi and Hinglish corpora compare the candidate with the current cloud baseline for correctness, instruction following, language matching, child safety, privacy, hallucination/citation behavior, latency and refusal quality against predeclared floors. Promotion uses CAS to M1 only for an exact passing cell. UI read model shows stage, eligible route, quality/resource evidence age, current fallback and invalidation reason; it offers no global toggle, model download, provider key, raw prompt/result or child override. Before actual P5-1 UI evidence, this checkpoint atomically adds only the enabled/readable model routes to Core/owner ingress, re-signs the route manifest and refreshed owner-ingress row, and keeps every non-promoted route `404`.

- [ ] **Step 1 — Write failing promotion/UI/composition tests.** Assert exact-cell pass can promote, neighboring language/profile/sensitivity/capability cannot inherit, digest/evidence expiry revokes, failed route preserves M0 behavior, signed manifest registers `private_ai.models` only when at least one safe UI-readable cell exists, and absent/forged facts make the route/chunk unreachable. Extend the shared installed test for the exact enabled model methods/paths, disabled-cell/unknown `404` without Core dispatch, no import mutation, manifest/wheel/row mismatch and rejection of the Task 07 row after this route delta.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/acceptance/private_ai/test_p5_1_task_cell_gate.py tests/security/private_ai/test_task_cell_promotion.py tests/integration/private_ai/test_phase5_owner_ingress_composition.py -q && pnpm --filter @tuntun/admin test -- models.test.tsx`; expect the evaluator/read model/UI and current installed route generation to be missing.
- [ ] **Step 3 — Implement evaluator, transactional promotion, read-only UI, and atomic route delta.** Use the deterministic 1,000-case route corpus plus exact actual-Mac evidence; sign evaluation bundles; expose content-free cells and fallback truth; integrate Privacy Shield state and accessible evidence/revocation labels. Explicitly recompose the canonical container/app and exact ingress allowlist from the new signed facts, re-sign the route manifest, rebuild the ingress wheel, refresh/re-sign its canonical row and atomically take over only after the shared candidate checks pass.
- [ ] **Step 4 — Prove P5-1 GO/NO-GO on the installed candidate.** Run `uv run python scripts/phase5/evaluate_task_cells.py --synthetic --check && uv run pytest tests/acceptance/private_ai/test_p5_1_task_cell_gate.py tests/security/private_ai/test_task_cell_promotion.py tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py -q && pnpm --filter @tuntun/admin e2e -- tests/ui/ai-workspace-models.spec.ts && pnpm --filter @tuntun/admin build`; expect synthetic policy and installed lifecycle tests to pass. GO requires an actual Task 12 evidence digest, per-cell quality pass and matching current ingress row; otherwise keep signed absence/M0 with the route omitted.
- [ ] **Step 5 — Commit per-cell evaluation, UI, and route checkpoint.** Stage exact Task 13 paths plus `apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/api/app.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json ops/services/phase3-owner-ingress.v1.json tests/integration/private_ai/test_phase5_owner_ingress_composition.py`, run `git diff --cached --check`, inspect manifest/route gating and row freshness, and commit with `git commit -m "feat(phase5): promote measured mac task cells"`.

---

## Optional Branch — P5-3 Inference Appliance and M2–M5 Promotion (complete after P5-2)

Tasks 14–16 define the optional branch beside the Mac work, but their owner decision/purchase/promotion checkboxes are not executable until Task 24 has positively completed P5-2. A `no_purchase` decision after P5-2 completes this branch without Tasks 15–16; implementers proceeding linearly skip the conditional branch, complete Tasks 17–24, then return here only if the owner still has a measured appliance need.

### Task 14: Record the appliance procurement/TCO decision without assuming purchase

**Depends on:** Tasks 08, 12, 13 and 24; current household workload/corpus evidence. The decision cannot be recorded before P5-2.

**Gate contribution:** P5-3 decision gate; `no_purchase` is a complete valid outcome.

**Estimated effort:** 1–2 engineering person-days plus same-day owner quote/compatibility review.

**Files:**

- Consume: `packages/contracts/src/tuntun_contracts/private_ai/procurement.py`
- Consume: `schemas/private-ai/v1/appliance-decision-v1.schema.json`
- Create: `scripts/phase5/evaluate_appliance.py`
- Create: `docs/procurement/phase5-inference-appliance.md`
- Create: `docs/evidence/phase5-appliance-decision.schema.json`
- Test: `tests/unit/private_ai/test_appliance_decision.py`
- Test: `tests/security/private_ai/test_appliance_evidence_redaction.py`

**Interfaces:** The frozen discriminated `ApplianceDecisionV1` is exactly `NoPurchaseDecisionV1 | PurchaseCandidateDecisionV1` on `decision = no_purchase | purchase_candidate`. `no_purchase` binds rationale, current Mac benchmark/task-cell evidence, actual Mac gap, time, and commitment and cannot carry any candidate/quote/SKU field. `purchase_candidate` binds a same-Singapore-day committed delivered quote, deterministic 9% GST/shipping total, 36-month energy at the bound tariff, support/warranty/return window, expected owner-time and exit cost, recomputable TCO, exact improved task cells and model/runtime digests, RAM/storage/headroom, update path, NIC/firewall/mTLS/isolation evidence, UPS signalling/load/runtime/recovery evidence, bounded risk, material actual Mac gap, and `delivery_validation_required=true`; it always has `order_authorized=false`. Before ordering a selected model, independently validate the delivered unit and repeat supported UPS signalling/load/recovery behavior; an unverified claim yields `no_purchase` with `rationale_code="candidate_blocked"`, never a third decision variant.

- [ ] **Step 1 — Write failing decision tests.** Validate through `TypeAdapter(ApplianceDecisionV1)`. Assert `no_purchase` requires rationale/current Mac evidence and rejects SKU/quote/candidate fields; purchase requires every current quote/TCO/compatibility field, exact tax/landed/energy/owner-time/TCO arithmetic, quote and decision within the same Singapore local day, unique nonempty improved-cell commitments, sufficient RAM/storage headroom, all four UPS proofs, no serial/address/payment data, no unsupported capability claim, and an explicit independent gate for delivery validation. Reject `candidate_blocked` as a discriminator and accept it only as the closed no-purchase rationale.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/unit/private_ai/test_appliance_decision.py tests/security/private_ai/test_appliance_evidence_redaction.py -q`; expect missing script/schema.
- [ ] **Step 3 — Implement deterministic calculator and signed decision record.** Synthetic mode uses fixture prices; owner mode accepts manually entered current values, performs no purchase, scrapes no account, stores commitments rather than quote/customer details, and resolves uncertainty to `NoPurchaseDecisionV1(decision="no_purchase", rationale_code="candidate_blocked")`. The public decision discriminator never gains a `candidate_blocked` variant.
- [ ] **Step 4 — Prove GREEN and record the owner decision.** Run `uv run python scripts/phase5/evaluate_appliance.py --synthetic --evidence-root /tmp/phase5-appliance && uv run pytest tests/unit/private_ai/test_appliance_decision.py tests/security/private_ai/test_appliance_evidence_redaction.py -q`; expect schema-valid `no_purchase`. If procurement is considered, run the owner-gated standard command on the quote date and expect either a fully eligible candidate or `candidate_blocked`, never implicit approval.
- [ ] **Step 5 — Commit the decision mechanism.** Stage exact script/doc/schema/tests, exclude `var/evidence`, run `git diff --cached --check`, and commit with `git commit -m "docs(phase5): define appliance procurement gate"`.

### Task 15: Isolate and mutually authenticate an optional inference appliance

**Depends on:** Task 14 resulted in a delivered candidate; Tasks 09–11.

**Gate contribution:** P5-3 transport/isolation gate; skip entirely after `no_purchase`.

**Estimated effort:** 3–5 engineering person-days plus delivered-hardware network/isolation commissioning if purchased.

**Files:**

- Create: `apps/core/src/tuntun_core/adapters/inference/appliance.py`
- Create: `apps/inference-proxy/src/tuntun_inference_proxy/quotas.py`
- Create: `ops/inference-appliance/compose.yaml`
- Create: `ops/inference-appliance/firewall.nft`
- Create: `ops/inference-appliance/README.md`
- Modify: `ops/services/phase5-inference-proxy.v1.json`
- Create: `scripts/phase5/verify_appliance_network.py`
- Test: `tests/contract/private_ai/test_appliance_mtls.py`
- Test: `tests/security/private_ai/test_appliance_isolation.py`
- Test: `tests/fault/private_ai/test_appliance_partition.py`
- Test: `tests/integration/private_ai/test_inference_appliance_service_lifecycle.py`

**Interfaces:** Dedicated non-admin worker accepts only mTLS/JCS-signed closed inference requests from the Mac on exact TCP `9443` and returns signed results. It enforces a 2 MiB text request cap, one active household generation, at most 32 queued evaluation jobs, per-task deadlines/output/token limits and cancellation. Bodies are RAM-only; logs are content-free; swap is encrypted or disabled; core dumps/crash upload are off. It uses full-disk encryption and secure boot where supported and has no Internet route during runtime, inbound management from household/guest VLANs, family identity/database, HA, camera, robot, desktop, knowledge-root or canonical-memory access. Updates are separate owner-maintenance mode with inference disabled and re-verification required. The compose target extends, rather than replaces, `phase5-inference-proxy.v1` with the frozen `appliance_compose` record; it runs the exact installed command/account/config/runtime above, has bounded read-only health, rotates its service/request generation on crash restart, and owns only its container, config, runtime, certificate and content-free log paths. Preserve uninstall removes all runnable authority but may retain only the explicitly disclosed encrypted model cache; destroy uninstall removes that cache and service identity too.

- [ ] **Step 1 — Write failing network/protocol/lifecycle tests.** Cover untrusted/revoked cert, wrong household/service identity, replay, request quota, port scan, DNS/Internet/default-route attempt, lateral LAN/HA/camera/robot reach, management/inference overlap, update-mode inference, partition/reconnect, clock skew and content-safe logs. Render compose plus the second target record and drive help/version/start/health/SIGTERM, wrong UID/config, deliberate crash/restart, stale request generation, config/certificate drift, preserve uninstall and destroy uninstall; reject any other bind, account, command, mount, capability, environment, port or cleanup path.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/contract/private_ai/test_appliance_mtls.py tests/security/private_ai/test_appliance_isolation.py tests/fault/private_ai/test_appliance_partition.py tests/integration/private_ai/test_inference_appliance_service_lifecycle.py -q`; expect missing adapter/quota/config verifier plus the target lifecycle.
- [ ] **Step 3 — Implement mTLS adapter, quota, declarative isolation, and exact compose lifecycle.** Pin exact CA/service identity and certificate generation, persist proxy admission before runtime, keep no request/result body after response, reject partition ambiguity, and require owner-signed update-to-runtime transition evidence. Render compose/firewall and the manifest target from one typed description; use read-only root/image, capability drop, no-new-privileges, bounded resources/PIDs/files, tmpfs runtime/body buffers, encrypted-or-disabled swap, no core dumps, a fixed non-root UID/GID and no environment secret.
- [ ] **Step 4 — Prove GREEN in simulation, then on delivered hardware.** Run `uv run pytest tests/contract/private_ai/test_appliance_mtls.py tests/security/private_ai/test_appliance_isolation.py tests/fault/private_ai/test_appliance_partition.py tests/integration/private_ai/test_inference_appliance_service_lifecycle.py -q && uv run python scripts/phase5/verify_appliance_network.py --synthetic --config ops/inference-appliance`; expect every forbidden edge denied and the rendered service row exact. If hardware exists, run the owner-gated appliance command, container health/crash-restart/cleanup suite and external deny probes; expect only pinned Mac mTLS on `9443`. Without delivered hardware, the appliance target record and package/config/service activation remain absent and this task is not marked complete.
- [ ] **Step 5 — Commit isolated appliance support.** Run `git add apps/core/src/tuntun_core/adapters/inference/appliance.py apps/inference-proxy/src/tuntun_inference_proxy/quotas.py ops/inference-appliance/compose.yaml ops/inference-appliance/firewall.nft ops/inference-appliance/README.md ops/services/phase5-inference-proxy.v1.json scripts/phase5/verify_appliance_network.py tests/contract/private_ai/test_appliance_mtls.py tests/security/private_ai/test_appliance_isolation.py tests/fault/private_ai/test_appliance_partition.py tests/integration/private_ai/test_inference_appliance_service_lifecycle.py && git diff --cached --check && make verify-private-data`; inspect firewall/defaults/lifecycle/secret handling, and commit with `git commit -m "feat(phase5): isolate inference appliance"`.

### Task 16: Promote appliance task cells through M2, M3, M4, and M5

**Depends on:** Tasks 13–15; delivered appliance passes isolation and supply-chain gates.

**Gate contribution:** Completes P5-3 per task cell; no appliance is required for Phase 5 success.

**Estimated effort:** 1–3 engineering person-days plus non-compressible 14-day and 30-day evidence windows.

**Files:**

- Modify: `scripts/phase5/evaluate_task_cells.py`
- Modify: `apps/core/src/tuntun_core/services/private_ai/task_cells.py`
- Modify: `apps/core/src/tuntun_core/services/private_ai/route_policy.py`
- Modify: `apps/admin/src/features/ai-workspace/models.tsx`
- Create: `docs/operations/phase5-appliance-promotion.md`
- Test: `tests/acceptance/private_ai/test_p5_3_appliance_promotion.py`
- Test: `tests/privacy/private_ai/test_appliance_shadow.py`
- Test: `tests/ui/ai-workspace-appliance.spec.ts`

**Interfaces:** M2 shadow receives synthetic or explicitly de-identified inputs and never serves a user. M3 is exact 14-day owner opt-in; M4 requires 30-day adult/local-knowledge gates; M5 additionally requires the complete accepted Phase 1 child corpus, Phase 5 injection/RAG gates and a distinct current owner/guardian approval bound to all digests. Each M3/M4 elapsed runner consumes a canonical Phase 2 `SignedFeatureManifestRolloverChainV1` through `FeatureManifestLeaseSupervisor`; its receipt binds one frozen cell/appliance/artifact/runtime/policy candidate, chain ID, ordered signed-envelope and transition-receipt digests, exact interval, and zero expired-authority interval. M3 promotion changes stage/activation/evidence authority, so M4 requires a separately externally signed chain for the newly frozen post-M3 candidate/registration set; an M3 chain is never reused or widened. Chains and evidence are namespaced by the canonical path-safe cell ID and stage, and cross-cell or cross-stage substitution fails before appliance I/O. Every admission/background sample checks the half-open wall and monotonic lease; runtime has no acceptance signer, renewal, fallback, or grace path. Rollback is per cell and preserves prior eligible route.

- [ ] **Step 1 — Write failing stage-evidence and authority tests.** Test every legal/illegal transition, elapsed-clock fraud, shadow output leak, digest drift, adult-to-child inheritance, stale/copy-pasted guardian approval, cancellation/quality/privacy/resource failure, rollback and UI truth for mixed-stage cells. Reject missing/extra/reordered/late successors, bad signature/hash link, candidate/package/registration drift, future activation, wall or monotonic equality, rollback, restart lease reuse, missing transition receipt, M3-chain use for M4, M4-chain use for M3, another cell's chain, and any appliance admission after authority closes; prove zero appliance I/O for each authority fault.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/acceptance/private_ai/test_p5_3_appliance_promotion.py tests/privacy/private_ai/test_appliance_shadow.py -q && pnpm --filter @tuntun/admin e2e -- tests/ui/ai-workspace-appliance.spec.ts`; expect missing M2–M5 evidence logic/UI.
- [ ] **Step 3 — Implement stage-specific evaluators and CAS promotion.** Bind monotonic signed observations to exact cell/appliance/artifact/runtime/template/policy/corpus digests, store no content, require separate adult/child decisions, and make any invalidation atomically revert the cell before worker cancellation. Before Step 5, exercise transitions only with fake clocks and signed fixtures in disposable namespaces; they never mutate an accepted production stage or supply promotion evidence.
- [ ] **Step 4 — Prove GREEN without starting M3 or M4 elapsed evidence.** Run `uv run python scripts/phase5/evaluate_task_cells.py --synthetic --check && uv run pytest tests/acceptance/private_ai/test_p5_3_appliance_promotion.py tests/privacy/private_ai/test_appliance_shadow.py -q && pnpm --filter @tuntun/admin e2e -- tests/ui/ai-workspace-appliance.spec.ts`. Use per-cell/per-stage fixture chains to prove ordered transitions, exact CAS behavior, zero expired-authority interval, and rejection of cross-cell/cross-stage substitution. Confirm each physical `promote` invocation refuses an uncommitted or dirty candidate; do not start either elapsed interval before Step 5.
- [ ] **Step 5 — Commit promotion machinery.** Stage exact files, run `git diff --cached --check`, inspect M5 approvals and rollback, and commit with `git commit -m "feat(phase5): stage appliance task cell promotion"`.

After that commit, discard every synthetic candidate namespace, verify the worktree is clean, and begin each eligible appliance cell at its last accepted authoritative pre-trial stage (M2 for its first M3 trial). Derive the canonical path-safe `CELL_ID`, freeze that cell's candidate, obtain a candidate-specific external M3 chain for the resolved commit, and run `TUNTUN_ALLOW_PHASE5_ELAPSED=1 uv run python scripts/phase5/evaluate_task_cells.py promote --stage M3 --duration-seconds 1209600 --feature-manifest-chain var/evidence/phase5/feature-authority/task16/CELL_ID/m3/signed-rollover-chain.json --evidence-root var/evidence/phase5/appliance/CELL_ID/m3`. Verify it with `uv run python scripts/phase5/evaluate_task_cells.py verify --stage M3 --feature-manifest-chain var/evidence/phase5/feature-authority/task16/CELL_ID/m3/signed-rollover-chain.json --evidence-root var/evidence/phase5/appliance/CELL_ID/m3 --require-physical --require-zero-expired-authority` before the exact CAS promotion. Then freeze the resulting post-M3 stage/activation generation and proposed M4 registration authority, obtain a separate external M4 chain for those bytes, run `TUNTUN_ALLOW_PHASE5_ELAPSED=1 uv run python scripts/phase5/evaluate_task_cells.py promote --stage M4 --duration-seconds 2592000 --feature-manifest-chain var/evidence/phase5/feature-authority/task16/CELL_ID/m4/signed-rollover-chain.json --evidence-root var/evidence/phase5/appliance/CELL_ID/m4`, and verify it with `uv run python scripts/phase5/evaluate_task_cells.py verify --stage M4 --feature-manifest-chain var/evidence/phase5/feature-authority/task16/CELL_ID/m4/signed-rollover-chain.json --evidence-root var/evidence/phase5/appliance/CELL_ID/m4 --require-physical --require-zero-expired-authority`. GO is per-cell only after both applicable clean-commit receipts pass; incomplete duration, authority fault, cross-cell/stage substitution, or later bound-byte/generation change invalidates that cell's affected evidence without changing other routing.

---

## Wave 2 — P5-2 One Identity-Bound Knowledge Root and Independent Recovery

### Task 17: Commission exactly one canonical knowledge root by storage identity

**Depends on:** Tasks 04 and 08; eligible internal storage or a separately encrypted `TUNTUN_KNOWLEDGE` volume.

**Gate contribution:** P5-2 storage prerequisite; retrieval/import remain absent until commissioned.

**Estimated effort:** 3–4 engineering person-days plus owner storage commissioning and any hardware lead time.

**Files:**

- Create: `apps/core/src/tuntun_core/adapters/knowledge/root.py`
- Create: `scripts/phase5/qualify_knowledge_root.py`
- Create: `ops/knowledge/root-policy.yaml`
- Create: `docs/operations/phase5-knowledge-storage.md`
- Create: `docs/evidence/phase5-knowledge-root.schema.json`
- Test: `tests/unit/private_ai/test_knowledge_root_binding.py`
- Test: `tests/security/private_ai/test_knowledge_root_identity.py`
- Test: `tests/hardware/private_ai/test_knowledge_root_qualification.py`

**Interfaces:** Internal default is `~/Library/Application Support/Tuntun/knowledge/`; external is an encrypted APFS volume named `TUNTUN_KNOWLEDGE`. Open by commissioned filesystem/volume identity plus directory handle, ownership/mode/encryption/quota/reserve and CAS binding generation. Reject `TUNTUN_VIDEO`, `HA_BACKUPS`, recovery destination, aliases/subdirectories, symlink/bind remount, wrong UUID/mount/filesystem, read-only/full/unmounted state and path-text substitution.

- [ ] **Step 1 — Write failing identity/adversarial filesystem tests.** Use temporary fake mount tables/descriptors for right path-wrong UUID, right UUID-wrong path, symlink swap, rename, remount, alias to video/backup/recovery, quota/reserve boundaries, stale handle/generation and concurrent commission.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/unit/private_ai/test_knowledge_root_binding.py tests/security/private_ai/test_knowledge_root_identity.py -q`; expect missing root adapter/qualifier. Confirm hardware test skips without storage flag.
- [ ] **Step 3 — Implement descriptor-first qualification and atomic binding.** Resolve once without following unsafe links, verify mount identity through an injected OS port, create mode-restricted layout and independent catalog/object keys, fsync, then CAS the binding. Any later mismatch disables every corpus operation.
- [ ] **Step 4 — Prove GREEN, then qualify the owner-selected root.** Run synthetic suites and `TUNTUN_ALLOW_PHASE5_STORAGE=1 uv run python scripts/phase5/qualify_knowledge_root.py --evidence-root var/evidence/phase5/knowledge`; expect signed pass only for one exact eligible root. Run the marker-gated hardware test; a missing/failed root leaves P5-2 absent.
- [ ] **Step 5 — Commit root qualification.** Stage exact adapter/script/ops/doc/schema/tests, exclude local evidence, run `git diff --cached --check && make verify-private-data`, and commit with `git commit -m "feat(phase5): bind canonical knowledge storage"`.

### Task 18: Import owner-selected objects through a networkless parser quarantine

**Depends on:** Tasks 02, 04 and 17.

**Gate contribution:** P5-2 import pipeline; source is not queryable until publish.

**Estimated effort:** 4–5 engineering person-days.

**Files:**

- Create: `apps/core/src/tuntun_core/adapters/knowledge/objects.py`
- Create: `apps/core/src/tuntun_core/adapters/knowledge/parser.py`
- Create: `apps/core/src/tuntun_core/services/private_ai/knowledge_import.py`
- Create: `ops/knowledge/parser-sandbox.yaml`
- Test: `tests/unit/private_ai/test_knowledge_import.py`
- Test: `tests/security/private_ai/test_parser_sandbox.py`
- Test: `tests/fault/private_ai/test_import_publish_crashes.py`

**Interfaces:** Only an owner-local native selection becomes `OwnerImportSelectionV1`; service copies through an already-open descriptor into quarantine, checks type/size/hash/policy, invokes a networkless parser with one read-only object mount, 512 MiB RAM, one CPU, 60 seconds, 25 MiB extracted text, archive depth two, no credentials/home/external reference, then envelope-encrypts staged object/chunks. Macros, active content, embedded executable and device/symlink/archive escape are rejected. Unsupported media is destroyed unless the owner explicitly chooses encrypted unindexed archival storage. Local DLP/classification proposes sensitivity/audience/retention/egress defaults; the owner reviews every document above household-public sensitivity and every child-audience document. Failed pending imports expire within 24 hours.

- [ ] **Step 1 — Write failing import/parser tests.** Use synthetic PDF/text/office/archive bytes plus zip bomb, recursion, macro, embedded executable, external link, polyglot, malformed encoding, symlink/device, descriptor-swap, timeout/OOM/output overflow and injected crash at every publish state. Assert no import by non-owner/remote/model/endpoint. Contract tests reject `published` without both a source and nonzero object count, and reject every rejected/cancelled/failed receipt carrying a source or nonzero object/chunk count.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/unit/private_ai/test_knowledge_import.py tests/security/private_ai/test_parser_sandbox.py tests/fault/private_ai/test_import_publish_crashes.py -q`; expect missing import/object/parser services.
- [ ] **Step 3 — Implement streaming encrypted import and sandbox adapter.** Bound before allocation, strip metadata from stored search representation, assign opaque source/version IDs, write/fsync encrypted staged objects, persist journal transitions without private text, and destroy all partials on pre-publish failure.
- [ ] **Step 4 — Prove GREEN and isolation.** Run the narrow suites plus `uv run pytest tests/security/private_ai -k "archive or parser or import" -q`; expect valid synthetic sources staged and every hostile source rejected with no network/credential/path/content leak.
- [ ] **Step 5 — Commit import quarantine.** Stage exact paths, run `git diff --cached --check && make verify-private-data`, inspect sandbox mounts/limits and cleanup, and commit with `git commit -m "feat(phase5): quarantine owner knowledge imports"`.

### Task 19: Publish encrypted versions into FTS5 with crash-safe consistency

**Depends on:** Task 18.

**Gate contribution:** P5-2 mandatory lexical index; API remains absent.

**Estimated effort:** 3–5 engineering person-days.

**Files:**

- Create: `apps/core/src/tuntun_core/services/private_ai/knowledge_index.py`
- Modify: `apps/core/src/tuntun_core/adapters/knowledge/catalog/repository.py`
- Test: `tests/integration/private_ai/test_knowledge_fts.py`
- Test: `tests/property/private_ai/test_knowledge_versioning.py`
- Test: `tests/fault/private_ai/test_knowledge_index_recovery.py`

**Interfaces:** Deterministically chunk the sanitized text, encrypt source/chunk payloads, and index only the current `PUBLISHED` version in SQLCipher FTS5. One source update creates a new immutable version, atomically switches current visibility, expires citations, then reclaims old derived rows. Search ranking is deterministic and bounded; object/catalog disagreement makes the source unavailable and schedules reconciliation.

- [ ] **Step 1 — Write failing version/index tests.** Cover deterministic chunk boundaries, current-only visibility, exact duplicate/idempotency, update interruption at every journal/FTS/object boundary, corrupt/missing object, FTS rebuild, database lock/power loss, Unicode/token limits and no plaintext in WAL/temp/error/evidence.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/integration/private_ai/test_knowledge_fts.py tests/property/private_ai/test_knowledge_versioning.py tests/fault/private_ai/test_knowledge_index_recovery.py -q`; expect missing index service/current-version logic.
- [ ] **Step 3 — Implement transactional catalog publish and deterministic rebuild.** Keep object fsync outside the catalog lock, commit encrypted metadata/chunks/current pointer/FTS as one catalog transaction, make replay inspect journal/digests, and rebuild only from authorized current encrypted objects.
- [ ] **Step 4 — Prove GREEN under faults.** Run narrow suites with `--count=3`; expect either old or new complete current version after every interruption and byte scans to find no synthetic plaintext sentinel outside encrypted test payloads.
- [ ] **Step 5 — Commit FTS/versioning.** Stage exact service/repository/tests, run `git diff --cached --check && make verify-private-data`, inspect journal boundaries, and commit with `git commit -m "feat(phase5): publish encrypted knowledge index"`.

### Task 20: Enforce source, chunk, and turn ACLs with bounded citations

**Depends on:** Task 19; accepted Phase 1 profile/consent/memory authority available.

**Gate contribution:** P5-2 retrieval security; UI remains absent.

**Estimated effort:** 3–5 engineering person-days.

**Files:**

- Create: `apps/core/src/tuntun_core/services/private_ai/knowledge_acl.py`
- Create: `apps/core/src/tuntun_core/services/private_ai/knowledge_retrieval.py`
- Modify: `apps/core/src/tuntun_core/adapters/knowledge/catalog/repository.py`
- Test: `tests/security/private_ai/test_knowledge_acl.py`
- Test: `tests/property/private_ai/test_authorized_retrieval.py`
- Test: `tests/privacy/private_ai/test_knowledge_citations.py`

**Interfaces:** Every query performs independent source-version, chunk, and current-turn subject/profile/audience/consent checks before rank, immediately before decrypt, and again before local/provider serialization. Return at most eight chunks and 12,000 document tokens with opaque source/version/chunk IDs, bounded owner-safe citation labels/locations, expiry at turn end plus five minutes, sensitivity/egress restrictions and injection classification. No unauthorized title/snippet/count/existence/timing leak; no action/memory/tool/desktop/robot output and no invented answer below the score/evidence threshold.

- [ ] **Step 1 — Write failing ACL/retrieval tests.** Generate owner/adult/child/Guest/anonymous/cross-household/revoked/expired/updated/deleted cases; mutate ACL between rank and decrypt; test timing/count padding, malicious instructions, citation replay, over-budget rank, model route mismatch and canonical-memory independence. Substitute every excerpt expiry before/equal/after the bundle expiry and prove that a fresh wrapper cannot freshen an expired member. Every quoted/derived synthetic assertion must resolve to its authorized current source/version/chunk; missing evidence must yield an explicit no-evidence result rather than an invented citation/answer.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/security/private_ai/test_knowledge_acl.py tests/property/private_ai/test_authorized_retrieval.py tests/privacy/private_ai/test_knowledge_citations.py -q`; expect missing ACL/retrieval services.
- [ ] **Step 3 — Implement deny-first retrieval.** Filter authorized current IDs before FTS, revalidate generations immediately before decrypt, cap/rerank deterministically, label retrieved text `untrusted_retrieval`, create expiring citation commitments, and normalize unauthorized/no-match externally.
- [ ] **Step 4 — Prove GREEN and isolation.** Run the narrow suites plus `uv run pytest tests/security/private_ai/test_closed_inference_boundary.py -q`; expect all ACL races denied, hard caps observed and injection text unable to create action or memory authority.
- [ ] **Step 5 — Commit secure retrieval.** Stage exact paths, run `git diff --cached --check && make verify-private-data`, inspect all three ACL checks, and commit with `git commit -m "feat(phase5): enforce knowledge retrieval acls"`.

### Task 21: Delete, reconcile, and export corpus data without weakening eligibility

**Depends on:** Tasks 19–20.

**Gate contribution:** P5-2 lifecycle/privacy prerequisite.

**Estimated effort:** 3–4 engineering person-days.

**Files:**

- Create: `apps/core/src/tuntun_core/services/private_ai/knowledge_lifecycle.py`
- Modify: `apps/core/src/tuntun_core/adapters/knowledge/objects.py`
- Modify: `apps/core/src/tuntun_core/adapters/knowledge/catalog/repository.py`
- Test: `tests/privacy/private_ai/test_knowledge_deletion.py`
- Test: `tests/fault/private_ai/test_knowledge_reconciliation.py`
- Test: `tests/security/private_ai/test_knowledge_export.py`

**Interfaces:** Owner delete immediately advances deletion generation and blocks source/chunk/citation eligibility before key destruction, FTS/vector removal, object reclaim, recovery reconciliation and tombstone. Superseded versions are inaccessible and default to deletion after 30 days unless the owner pins one for provenance. Owner export requires a fresh passkey/prepared mutation and an explicitly selected encrypted destination distinct from canonical/recovery/video/HA backup roots; its import round trip preserves authorized provenance/ACL/versions/keys/citations, never memory or hidden sources, and labels the external copy with sensitivity, source/version, export time and the owner’s recovery responsibility because it is outside Tuntun revocation control.

- [ ] **Step 1 — Write failing lifecycle tests.** Cover delete while query/import/backup/export is active, crash at every deletion transition, consent-revocation batch, stale citation/cache/model buffer, missing/corrupt object reconciliation, export role/confirmation/destination/space/interruption, and proof that recovery lag cannot restore eligibility.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/privacy/private_ai/test_knowledge_deletion.py tests/fault/private_ai/test_knowledge_reconciliation.py tests/security/private_ai/test_knowledge_export.py -q`; expect missing lifecycle service.
- [ ] **Step 3 — Implement eligibility-first deletion and encrypted export.** Commit denial generation before cleanup I/O, cancel affected inference, make cleanup/retry idempotent, shred per-source keys, emit content-free signed receipts, and stream export through a new export key without plaintext temporary files.
- [ ] **Step 4 — Prove GREEN under concurrency/faults.** Run the narrow suites plus `uv run pytest tests/property/private_ai -k knowledge -q`; expect zero deleted-version retrieval and either a complete verifiable export or no published export after interruption.
- [ ] **Step 5 — Commit lifecycle controls.** Stage exact files, run `git diff --cached --check && make verify-private-data`, inspect denial-before-cleanup, and commit with `git commit -m "feat(phase5): enforce knowledge deletion lifecycle"`.

### Task 22: Back up, restore, and migrate the knowledge root independently

**Depends on:** Tasks 17–21; a different owner-controlled encrypted recovery failure domain.

**Gate contribution:** P5-2 recovery and storage-migration gate.

**Estimated effort:** 3–5 engineering person-days plus non-compressible quarterly offline-restore evidence.

**Files:**

- Create: `apps/core/src/tuntun_core/adapters/knowledge/recovery.py`
- Create: `apps/core/src/tuntun_core/services/private_ai/knowledge_recovery.py`
- Create: `scripts/phase5/verify_knowledge_recovery.py`
- Create: `docs/operations/phase5-knowledge-recovery.md`
- Create: `docs/evidence/phase5-knowledge-recovery.schema.json`
- Test: `tests/integration/private_ai/test_knowledge_recovery.py`
- Test: `tests/fault/private_ai/test_knowledge_root_migration.py`
- Test: `tests/acceptance/private_ai/test_knowledge_offline_restore.py`

**Interfaces:** Recovery binding has distinct destination UUID/key/failure domain, seven daily/four weekly generations, 24-hour RPO/prune/deletion-reconciliation, no live queries and quarterly offline restore. Migration is staged `SOURCE_QUIESCED -> TARGET_QUALIFIED -> ENCRYPTED_COPY_VERIFIED -> CATALOG_REOPENED -> BINDING_CAS_COMMITTED -> SOURCE_RETIREMENT_ELIGIBLE`; failure before CAS reopens source, after CAS never falls back automatically. Restore creates a disabled candidate generation and enables only after object/catalog/key/ACL/deletion/binding/version checks.

- [ ] **Step 1 — Write failing recovery/migration tests.** Cover alias/same-volume/self-destination, wrong key/UUID, partial/corrupt/stale generation, RPO/retention, deletion during backup, 24-hour clean-generation deadline, full disk, unplug at each migration step, simultaneous import/query, rollback boundaries and recovery-root query attempts. Contract and service tests prove `status="eligible"` is impossible without a non-null, independently verified offline-restore timestamp; missing/future/stale evidence keeps the policy ineligible.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/integration/private_ai/test_knowledge_recovery.py tests/fault/private_ai/test_knowledge_root_migration.py tests/acceptance/private_ai/test_knowledge_offline_restore.py -q`; expect missing recovery services/script.
- [ ] **Step 3 — Implement separately keyed encrypted generations and CAS migration.** Snapshot only a reconciled catalog/object generation, bind manifests/signatures/deletion generations, verify before prune, never mount recovery as canonical, quiesce imports for migration, and keep both copies until explicit verified retirement.
- [ ] **Step 4 — Prove GREEN and perform offline restore.** Run the narrow suites, then owner-gated `TUNTUN_ALLOW_PHASE5_STORAGE=1 uv run python scripts/phase5/verify_knowledge_recovery.py --evidence-root var/evidence/phase5/knowledge`; expect a restored temporary root to match current authorized synthetic manifests and remain disabled until reconciliation. Missing quarterly evidence makes corpus recovery health degraded and blocks new imports.
- [ ] **Step 5 — Commit recovery/migration.** Stage exact paths, exclude evidence, run `git diff --cached --check && make verify-private-data`, inspect separate keys/destinations and no fallback, and commit with `git commit -m "feat(phase5): recover and migrate knowledge safely"`.

### Task 23: Gate optional local embeddings behind measured lexical improvement

**Depends on:** Tasks 10 and 19–22.

**Gate contribution:** Optional P5-2 quality enhancement; FTS5 remains complete baseline.

**Estimated effort:** 6–12 engineering person-days; optional implementation does not shorten its acceptance gate.

**Files:**

- Create: `apps/core/src/tuntun_core/services/private_ai/knowledge_vectors.py`
- Create: `scripts/phase5/evaluate_vectors.py`
- Modify: `apps/core/src/tuntun_core/adapters/knowledge/catalog/repository.py`
- Create: `docs/evidence/phase5-vector-evaluation.schema.json`
- Test: `tests/acceptance/private_ai/test_vector_gate.py`
- Test: `tests/security/private_ai/test_vector_acl_deletion.py`

**Interfaces:** Embeddings are local-only encrypted derived data, exact source/version/chunk and local artifact/dimension/normalization/evaluation bound, reproducibly rebuildable and disabled by default. Activation requires a predeclared statistically meaningful gain over FTS on the synthetic/de-identified retrieval corpus with equal or better ACL, deletion, backup/restore, latency, resource and injection behavior. No vector or query leaves the Mac/appliance.

- [ ] **Step 1 — Write failing vector-gate tests.** Assert off-by-default, artifact/dimension/source drift invalidation, unauthorized vector timing/count denial, source deletion/rekey/rebuild, backup omission/rebuild, no network/cloud route and failure/no-gain fallback to unchanged FTS.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/acceptance/private_ai/test_vector_gate.py tests/security/private_ai/test_vector_acl_deletion.py -q`; expect missing vector evaluator/service.
- [ ] **Step 3 — Implement derived-data lifecycle and offline evaluator.** Reuse Task 10 artifacts, embed only authorized current sanitized chunks, encrypt per row, retrieve candidates only after ACL prefilter, recheck ACL before result and atomically disable on any digest/generation drift.
- [ ] **Step 4 — Prove optional GO/NO-GO.** Run `uv run python scripts/phase5/evaluate_vectors.py --synthetic --check && uv run pytest tests/acceptance/private_ai/test_vector_gate.py tests/security/private_ai/test_vector_acl_deletion.py -q`; expect deterministic evidence. Activate only on an actual accepted artifact/corpus run; otherwise FTS stays registered and complete.
- [ ] **Step 5 — Commit optional vector gate.** Stage exact files, run `git diff --cached --check && make verify-private-data`, inspect local-only and deletion paths, and commit with `git commit -m "feat(phase5): gate optional local retrieval vectors"`.

### Task 24: Expose owner-only knowledge administration and citation health

**Depends on:** Tasks 17–22; optional Task 23 does not block.

**Gate contribution:** Completes P5-2 only after root/recovery/import/retrieval/lifecycle gates pass.

**Estimated effort:** 3–4 engineering person-days.

**Files:**

- Create: `apps/core/src/tuntun_core/api/routes/knowledge.py`
- Modify: `apps/core/src/tuntun_core/api/phase5_dtos.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Modify: `ops/services/phase3-owner-ingress.v1.json`
- Create: `apps/admin/src/features/ai-workspace/knowledge.tsx`
- Create: `apps/admin/src/routes/ai-workspace-knowledge.tsx`
- Modify: `packages/contracts/openapi/admin-v1.yaml`
- Modify: `apps/admin/src/api/generated/admin-v1.ts`
- Modify: `apps/admin/src/app/router.tsx`
- Modify: `apps/core/src/tuntun_core/services/features/registry.py`
- Modify: `apps/admin/src/app/feature-registry.ts`
- Test: `tests/integration/private_ai/test_knowledge_api_authorization.py`
- Test: `apps/admin/src/features/ai-workspace/knowledge.test.tsx`
- Test: `tests/ui/ai-workspace-knowledge.spec.ts`
- Test: `tests/accessibility/ai-workspace-knowledge.spec.ts`
- Test: `tests/integration/private_ai/test_phase5_owner_ingress_composition.py`

**Interfaces:** Owner-local UI shows binding health, quota/reserve, recovery RPO/last verified restore, source count/status, opaque safe source labels, versions, audiences, sensitivity/egress/retention, indexing/deletion/export receipts and citation status. Native picker/import, ACL edit, delete, export, root migration and recovery commissioning are prepared owner mutations with passkey where destructive/sensitive. Other roles receive feature absence with no titles/counts/route/chunk. The P5-2 checkpoint composes the knowledge router only after Tasks 17–22 are current, refreshes the signed ingress row, and requires the real installed owner path before import/admin/recovery UI evidence; an in-memory router is not sufficient.

- [ ] **Step 1 — Write failing API/UI authorization and installed-route tests.** Probe owner/non-owner adult/child/Guest/anonymous/remote/model/endpoint direct URL/API/prepared action/client bundle; test stale manifest, binding/recovery unhealthy, Privacy Shield, picker cancellation, optimistic race, delete/export confirmation, accessible focus/error/live-region and no path/title leakage. Extend the shared composition suite with installed knowledge read/prepared-mutation positives, role/disabled/unknown `404` without Core dispatch, and stale Task 13 ingress-row rejection.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/integration/private_ai/test_knowledge_api_authorization.py tests/integration/private_ai/test_phase5_owner_ingress_composition.py -q && pnpm --filter @tuntun/admin test -- knowledge.test.tsx && pnpm --filter @tuntun/admin e2e -- tests/ui/ai-workspace-knowledge.spec.ts tests/accessibility/ai-workspace-knowledge.spec.ts`; expect the knowledge route/components and current installed generation to be missing.
- [ ] **Step 3 — Implement signed owner read model, prepared mutations, and atomic route checkpoint.** Resolve roles server-side, issue short-lived native selection handles rather than browser paths, revalidate binding/recovery/generations on execute, render source-safe message IDs, integrate Privacy Shield/recovery truth, and register only after current P5-2 evidence. Recompose the canonical app/container and ingress allowlist, sign the new manifest, rebuild the ingress wheel, refresh/re-sign its row and activate the immutable candidate only after the shared installed tests pass.
- [ ] **Step 4 — Prove P5-2 GO/NO-GO through the real owner listener.** Run the narrow suites plus `uv run pytest tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py -q && pnpm --filter @tuntun/admin build`. GO requires Tasks 17–22 positive evidence, the full installed owner flow and current row; any failed binding/recovery/restore/ACL/deletion condition omits the route/API/prepared actions/chunk and preserves canonical memory unchanged.
- [ ] **Step 5 — Commit owner knowledge UI and route checkpoint.** Stage the exact API/UI/registry/tests plus `apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/api/app.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json ops/services/phase3-owner-ingress.v1.json tests/integration/private_ai/test_phase5_owner_ingress_composition.py`, run `git diff --cached --check`, inspect non-owner absence, destructive confirmation and row freshness, and commit with `git commit -m "feat(phase5): add owner knowledge workspace"`.

---

## Wave 4 — P5-4/P5-5 Bounded Desktop Assistance and Fail-Closed Execution

### Task 25: Establish the desktop helper UDS, peer identity, grants, and descriptor-bound roots

**Depends on:** Tasks 01, 05, 07 and 08; helper host is the family Mac only.

**Gate contribution:** P5-4 helper trust boundary; D1–D4 remain unregistered.

**Estimated effort:** 4–6 engineering person-days.

**Files:**

- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Create: `apps/desktop-helper/pyproject.toml`
- Create: `apps/desktop-helper/src/tuntun_desktop_helper/__init__.py`
- Create: `apps/desktop-helper/src/tuntun_desktop_helper/server.py`
- Create: `apps/desktop-helper/src/tuntun_desktop_helper/peer.py`
- Create: `apps/desktop-helper/src/tuntun_desktop_helper/grants.py`
- Create: `apps/desktop-helper/src/tuntun_desktop_helper/paths.py`
- Create: `apps/desktop-helper/src/tuntun_desktop_helper/health.py`
- Create: `apps/core/src/tuntun_core/adapters/desktop/helper_client.py`
- Create: `ops/launchd/phase5/com.tuntun.desktop-helper.plist`
- Create: `ops/services/phase5-desktop-helper.v1.json`
- Test: `tests/contract/private_ai/test_desktop_helper_protocol.py`
- Test: `tests/security/private_ai/test_desktop_helper_peer.py`
- Test: `tests/property/private_ai/test_desktop_root_resolution.py`
- Test: `tests/integration/private_ai/test_desktop_helper_service_lifecycle.py`
- Modify: `tests/unit/private_ai/test_phase5_package_smoke.py`

**Interfaces:** Mode-0660 Unix socket accepts only `_tuntun_desktop` plus the pinned Core code identity/UID and signed, generation-bound helper envelopes. Grants bind owner/device, D-level, one to eight owner-selected root descriptors/filesystem identities, at most 60 minutes, 250 regular files, 50 MiB extracted total, 5 MiB per file, command/workflow IDs, independent execution-network and model-egress policies, expiry and revocation. Resolution is beneath already-open roots; reject absolute/parent traversal, symlink/reparse/device/socket/FIFO, mount/hard-link identity swap, world-writable executable search and grant widening. `.ssh`, `.gnupg`, Keychain, browser profile/cookies, password/cloud-credential stores, `.env*`, private keys, other-user system logs and Tuntun production/key roots are excluded; keys/cookies/tokens/Keychain/Tuntun key roots remain ungrantable even by exception. This task registers `tuntun-desktop-helper` as an independently packaged root-workspace member with script `tuntun-desktop-helper = tuntun_desktop_helper.server:main`, contracts-only dependency, and no import of core authority. `server.py` owns injectable `run(argv, runtime) -> int`, side-effect-free help/version, fail-closed start and read-only health. The rendered launch daemon and `phase5-desktop-helper.v1` row use the frozen exact executable, `_tuntun_desktop`, root-owned configuration, `/private/var/run/tuntun/desktop-helper.sock`, crash-only restart, and exact owned cleanup; there is no TCP listener, ambient home, shell, provider/model key, or broad filesystem entitlement.

- [ ] **Step 1 — Write failing protocol/path/lifecycle tests.** Cover wrong UID/code identity/socket mode, forged/replayed/stale envelope, revoked/expired grant, descriptor rename, symlink race, hardlink outside root, mount swap, Unicode/case collision, special file, over-count/bytes and helper restart generation. Extend package smoke with version/entry-point resolution and a forbidden-core-import assertion. Parse the installed plist/service row; drive help/version/start/health/SIGTERM, wrong account/config, deliberate crash/restart, old grant/envelope replay, stale socket, and both uninstall modes with injected descriptors, proving every rejection precedes file/key/socket effects.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/unit/private_ai/test_phase5_package_smoke.py tests/contract/private_ai/test_desktop_helper_protocol.py tests/security/private_ai/test_desktop_helper_peer.py tests/property/private_ai/test_desktop_root_resolution.py tests/integration/private_ai/test_desktop_helper_service_lifecycle.py -q`; expect missing helper project metadata/client modules plus the plist/service row/lifecycle.
- [ ] **Step 3 — Implement length-prefixed closed messages, descriptor-first resolver, and exact service wrapper.** Add `apps/desktop-helper` to the existing root workspace without removing members, update `uv.lock`, and create its Hatchling project with Python `==3.12.*`, version `0.1.0.dev0`, workspace `tuntun-contracts` dependency, frozen script entry point, matching `__version__`, and the frozen CLI lifecycle. Render plist and manifest from one typed service description. Verify account/config and peer before body read, cap envelope before allocation, durably admit grant generation, use no ambient home/PATH/config, open beneath root with no-follow semantics, return commitments/safe relative display tokens only, and clear grants on every unverified restart.
- [ ] **Step 4 — Prove GREEN and restart safety.** Run `uv lock && uv sync --all-packages && uv run pytest tests/unit/private_ai/test_phase5_package_smoke.py tests/contract/private_ai/test_desktop_helper_protocol.py tests/security/private_ai/test_desktop_helper_peer.py tests/property/private_ai/test_desktop_root_resolution.py tests/integration/private_ai/test_desktop_helper_service_lifecycle.py tests/fault/private_ai -k helper -q && uv build apps/desktop-helper && uv run tuntun-desktop-helper --help && uv run tuntun-desktop-helper --version && plutil -lint ops/launchd/phase5/com.tuntun.desktop-helper.plist && uv run ruff check apps/desktop-helper tests/unit/private_ai/test_phase5_package_smoke.py tests/integration/private_ai/test_desktop_helper_service_lifecycle.py && uv run mypy apps/desktop-helper/src`; expect locked import/build/entry point success, exact installed lifecycle, every confused-deputy case denied, and helper restart to require Core reconciliation before any access.
- [ ] **Step 5 — Commit helper boundary.** Run `git add pyproject.toml uv.lock apps/desktop-helper apps/core/src/tuntun_core/adapters/desktop/helper_client.py ops/launchd/phase5/com.tuntun.desktop-helper.plist ops/services/phase5-desktop-helper.v1.json tests/unit/private_ai/test_phase5_package_smoke.py tests/contract/private_ai/test_desktop_helper_protocol.py tests/security/private_ai/test_desktop_helper_peer.py tests/property/private_ai/test_desktop_root_resolution.py tests/integration/private_ai/test_desktop_helper_service_lifecycle.py && git diff --cached --check && make verify-private-data`; inspect peer/path/lifecycle logic, and commit with `git commit -m "feat(phase5): constrain desktop helper roots"`.

### Task 26: Implement D0–D2 read/propose flow with hostile-output DLP

**Depends on:** Tasks 09–11 and 25.

**Gate contribution:** P5-4 bounded read/proposal engine; UI remains absent.

**Estimated effort:** 4–6 engineering person-days.

**Files:**

- Create: `apps/core/src/tuntun_core/services/private_ai/desktop_assistance.py`
- Create: `apps/core/src/tuntun_core/services/private_ai/desktop_dlp.py`
- Create: `apps/desktop-helper/src/tuntun_desktop_helper/receipts.py`
- Test: `tests/unit/private_ai/test_desktop_d0_d2.py`
- Test: `tests/security/private_ai/test_desktop_hostile_output.py`
- Test: `tests/privacy/private_ai/test_desktop_dlp.py`

**Interfaces:** D0 accepts user conversation only and has no helper/grant. D1 reads only owner-selected files within exact grant/count/byte/type bounds and labels all content untrusted. D2 returns `DesktopCommandProposalV1` or bounded file-change proposal but performs no command/write/network action. Model/tool/document output is rendered inert; DLP blocks credentials, tokens, cookies, SSH/Keychain/passkey/provider secrets, private path/identity and disallowed sensitivity/egress. Adding `receipts.py` changes the desktop-helper wheel and makes Task 25's signed row unusable; this task runs only fake/no-effect helper tests, and Task 28 must refresh the row before any owner file read.

- [ ] **Step 1 — Write failing level/DLP tests.** Use at least 500 deterministic hostile outputs: shell/HTML/Markdown/ANSI/OSC/control/BiDi, instruction-file text, malicious source comment, fake confirmation, secret exfiltration, hidden path, tool/action/memory schema and output claiming completion. Assert D0 never calls helper, D1 never proposes effects and D2 never executes.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/unit/private_ai/test_desktop_d0_d2.py tests/security/private_ai/test_desktop_hostile_output.py tests/privacy/private_ai/test_desktop_dlp.py -q`; expect missing service/DLP behavior.
- [ ] **Step 3 — Implement level-specific closed functions.** Build bounded sanitized segments from helper receipts, preserve source/line provenance commitments, escape output for every renderer/log, validate proposals against registered schemas, and return refusal plus content-free audit on any secret or authority attempt.
- [ ] **Step 4 — Prove GREEN and no side effects.** Run narrow suites and assert fake helper process/write/network counters remain zero for all D0–D2 cases; run `make verify-private-data` and expect no sentinel in logs/evidence.
- [ ] **Step 5 — Commit D0–D2 assistance.** Stage exact services/receipt/tests, run `git diff --cached --check`, inspect no execution path, and commit with `git commit -m "feat(phase5): add bounded desktop read proposals"`.

### Task 27: Consume exact owner DesktopModelEgressAuthorizationV1 independently

**Depends on:** Tasks 05, 11, 25 and 26; approved Phase 1 cloud provider/DLP boundary.

**Gate contribution:** P5-4 explicit one-attempt exception; local-only remains default.

**Estimated effort:** 3–4 engineering person-days.

**Files:**

- Create: `apps/core/src/tuntun_core/services/private_ai/desktop_egress.py`
- Modify: `apps/core/src/tuntun_core/services/private_ai/route_policy.py`
- Modify: `apps/core/src/tuntun_core/services/private_ai/inference_gateway.py`
- Test: `tests/security/private_ai/test_desktop_model_egress.py`
- Test: `tests/privacy/private_ai/test_desktop_egress_disclosure.py`
- Test: `tests/fault/private_ai/test_desktop_egress_consumption.py`

**Interfaces:** Issue only after owner-local passkey confirmation of the bounded, canonical ordered, non-empty exact selected file/content/command-or-workflow-output commitments, byte/token totals, serialization commitment, provider attempt/account/model/route, purpose, sensitivity, disclosure and provider data-use/retention policy digests. Authorization expires within 15 minutes and never after its `DesktopGrantV1`, is revocation-generation bound and single-use for one provider attempt. Consumption commits before provider I/O; retry needs a new authorization. Phase 5 D4 remains network-off; the positive separation fixture uses `execution_network_policy="none"`, and every non-`none` API/UI/config/import value is rejected.

- [ ] **Step 1 — Write failing egress tests.** Cover every field mismatch, omitted selected commitment, added byte after disclosure, stale provider policy, passkey/session mismatch, replay/concurrency, crash before/after consumption, provider timeout, local route, D4 network-only grant, model-egress-only grant and Privacy Shield race.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/security/private_ai/test_desktop_model_egress.py tests/privacy/private_ai/test_desktop_egress_disclosure.py tests/fault/private_ai/test_desktop_egress_consumption.py -q`; expect missing egress service/route integration.
- [ ] **Step 3 — Implement exact issuance/consumption.** Recompute commitments from open descriptors and bounded output, show data-category/provider/retention disclosure, persist passkey/prepared authorization and single-use consume atomically, place only its HMAC commitment in `SanitizedInferenceRequestV1`, and cancel before network on revocation.
- [ ] **Step 4 — Prove GREEN and independence.** Run narrow suites plus route property tests; expect exactly one provider call only for an exact live authorization and zero workflow/helper network change.
- [ ] **Step 5 — Commit egress authorization.** Stage exact services/tests, run `git diff --cached --check && make verify-private-data`, inspect transactional consume and policy independence, and commit with `git commit -m "feat(phase5): authorize exact desktop model egress"`.

### Task 28: Add owner-only D0–D2 desktop workspace and exact egress disclosure

**Depends on:** Tasks 25–27.

**Gate contribution:** Completes P5-4 if owner flow and absence probes pass.

**Estimated effort:** 3–4 engineering person-days.

**Files:**

- Create: `apps/core/src/tuntun_core/api/routes/desktop.py`
- Modify: `apps/core/src/tuntun_core/api/phase5_dtos.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Modify: `ops/services/phase3-owner-ingress.v1.json`
- Modify: `ops/services/phase5-desktop-helper.v1.json`
- Create: `apps/admin/src/features/ai-workspace/desktop.tsx`
- Create: `apps/admin/src/features/ai-workspace/desktop-grant.tsx`
- Create: `apps/admin/src/features/ai-workspace/desktop-egress.tsx`
- Create: `apps/admin/src/routes/ai-workspace-desktop.tsx`
- Modify: `packages/contracts/openapi/admin-v1.yaml`
- Modify: `apps/admin/src/api/generated/admin-v1.ts`
- Modify: `apps/admin/src/app/router.tsx`
- Modify: `apps/core/src/tuntun_core/services/features/registry.py`
- Modify: `apps/admin/src/app/feature-registry.ts`
- Test: `tests/integration/private_ai/test_desktop_d0_d2_api.py`
- Test: `apps/admin/src/features/ai-workspace/desktop.test.tsx`
- Test: `tests/ui/ai-workspace-desktop-d0-d2.spec.ts`
- Test: `tests/accessibility/ai-workspace-desktop.spec.ts`
- Test: `tests/integration/private_ai/test_phase5_owner_ingress_composition.py`
- Test: `tests/integration/private_ai/test_desktop_helper_service_lifecycle.py`

**Interfaces:** Owner-local route supports D0 conversation, native root/file selection, visible D1 read limits/provenance, inert D2 proposals, grant expiry/revoke and optional exact cloud-egress disclosure/passkey. It never shows a shell, free-form command, arbitrary path, blanket folder/egress/network permission, provider secret, execution claim or control to non-owner/remote roles. Before P5-4 owner use, the exact D0–D2 methods/paths are atomically added to the sole ingress candidate and its refreshed signed row; D3/D4 paths remain omitted/`404`. This same pre-use checkpoint rebuilds desktop-helper after Task 26, refreshes/re-signs `phase5-desktop-helper.v1` from its exact final wheel/plist/config/socket bytes, and reruns installed lifecycle before any D1 file access.

- [ ] **Step 1 — Write failing auth/state/UI, installed-route, and helper-row tests.** Probe every non-owner/direct route/API/prepared action/bundle, D0 no-helper, expired/revoked/drifted root, D1 limit, D2 review-only, hostile output rendering, egress disclosure deltas/cancel/replay, Privacy Shield, focus management, keyboard use and live-region status. Extend the shared suite with installed D0–D2 positives, D3/D4/unknown/disabled `404` without Core dispatch, stale Task 24 ingress-row rejection, Task 25 helper-row rejection after `receipts.py`, exact current helper start/health/crash-restart and both cleanup modes.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/integration/private_ai/test_desktop_d0_d2_api.py tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/private_ai/test_desktop_helper_service_lifecycle.py -q && pnpm --filter @tuntun/admin test -- desktop.test.tsx && pnpm --filter @tuntun/admin e2e -- tests/ui/ai-workspace-desktop-d0-d2.spec.ts tests/accessibility/ai-workspace-desktop.spec.ts`; expect the API/UI and both current installed generations to be missing.
- [ ] **Step 3 — Implement read models, prepared egress, atomic route delta, and refreshed helper row.** Use short-lived opaque picker handles, render commitments as safe labels, separate grant/network/model-egress panels, show proposal as untrusted data, register `private_ai.desktop_d0`, `private_ai.desktop_d1` and `private_ai.desktop_d2` independently only after each exact gate, and atomically revoke on Privacy Shield. Recompose/sign/rebuild/refresh the owner-ingress candidate. Separately rebuild desktop-helper from the Task 26 bytes and refresh/re-sign its row; no D1 helper I/O occurs until both candidate lifecycles pass.
- [ ] **Step 4 — Prove P5-4 GO/NO-GO on current installed candidates.** Run the narrow suites plus `uv run pytest tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py tests/integration/private_ai/test_desktop_helper_service_lifecycle.py -q && pnpm --filter @tuntun/admin build`. GO requires owner D0–D2, DLP, grant/revocation, exact-egress, current ingress evidence and current helper install/start/health/SIGTERM/crash-restart/update/rollback/preserve/destroy evidence; otherwise those methods/paths/chunks and helper use remain absent.
- [ ] **Step 5 — Commit D0–D2 UI, route checkpoint, and refreshed helper row.** Stage the exact Task 28 paths plus `apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/api/app.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json ops/services/phase3-owner-ingress.v1.json ops/services/phase5-desktop-helper.v1.json tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/private_ai/test_desktop_helper_service_lifecycle.py`, run `git diff --cached --check`, inspect owner-only/absence, inert rendering and both row digests, and commit with `git commit -m "feat(phase5): expose owner desktop proposals"`.

### Task 29: Pin the D3 non-code inspection command registry

**Depends on:** Tasks 05, 25 and 28.

**Gate contribution:** P5-5 D3 command eligibility; execution remains unregistered.

**Estimated effort:** 3–5 engineering person-days.

**Files:**

- Create: `apps/desktop-helper/src/tuntun_desktop_helper/command_registry.py`
- Create: `docs/operations/phase5-d3-command-registry.md`
- Test: `tests/unit/private_ai/test_d3_command_registry.py`
- Test: `tests/security/private_ai/test_d3_repo_traps.py`

**Interfaces:** The complete D3 registry is bounded inspection only: pinned-digest `git --no-pager status --porcelain=v2` for one granted repository; `git --no-pager diff --no-ext-diff --no-textconv --` with explicit granted paths and bounded output; `git --no-pager log --oneline --max-count N` where `1 <= N <= 200` with signature rendering disabled; and pinned-digest `rg` with literal/regex pattern, explicit granted paths, no preprocessor and bounded results. Use an empty controlled HOME/config, fixed minimal environment, no shell, ambient PATH, hooks, aliases, filters, filesystem monitor, pager, helper, signing, external diff, textconv, optional object/program helper, config include, package manager or repo executable. All tests/lints/builds/formatters/generators/compilers/interpreters/scripts/binaries/hooks/plugins and app entry points are D4 regardless of read-only intent. Adding `command_registry.py` makes the Task 28 helper row stale; this task performs no actual helper process, and Task 30 must rebuild/re-sign before D3 execution.

- [ ] **Step 1 — Write failing allow/deny grammar tests.** Enumerate exact valid argv and deny shell operators, response files, `-c` override except hardcoded safe options, external diff/textconv, pager/editor, config include, revision/path ambiguity, unsafe `rg --pre`, hidden/unbounded traversal, executable lookup drift and every representative repo-code command (`pytest`, `npm test`, `make lint`, script, binary).
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/unit/private_ai/test_d3_command_registry.py tests/security/private_ai/test_d3_repo_traps.py -q`; expect missing registry.
- [ ] **Step 3 — Implement closed argv constructors and digest verification.** Resolve executables by pinned absolute path/descriptor, construct rather than sanitize argv, use fixed Git config disabling hooks/helpers/filters/external execution, cap files/bytes/time and classify anything not exactly constructible as D4.
- [ ] **Step 4 — Prove GREEN against hostile repositories.** Run narrow suites over synthetic repos containing malicious hooks/config/attributes/textconv/filenames/symlinks and fake executables; expect bounded inert output and zero repository code process.
- [ ] **Step 5 — Commit D3 registry.** Stage exact registry/doc/tests, run `git diff --cached --check`, inspect the exhaustive deny boundary, and commit with `git commit -m "feat(phase5): pin non code d3 inspections"`.

### Task 30: Execute one exactly confirmed D3 inspection through the durable action lifecycle

**Depends on:** Tasks 25, 28 and 29; accepted Phase 2 prepared-mutation/confirmation/action contracts. Task 28 owns the desktop router and prior installed owner-ingress generation that this task extends.

**Gate contribution:** P5-5 D3 positive gate.

**Estimated effort:** 4–7 engineering person-days.

**Files:**

- Create: `apps/desktop-helper/src/tuntun_desktop_helper/executor.py`
- Modify: `apps/core/src/tuntun_core/services/private_ai/desktop_jobs.py`
- Modify: `apps/core/src/tuntun_core/api/routes/desktop.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Modify: `ops/services/phase3-owner-ingress.v1.json`
- Modify: `ops/services/phase5-desktop-helper.v1.json`
- Test: `tests/integration/private_ai/test_d3_job_execution.py`
- Test: `tests/fault/private_ai/test_d3_action_state_machine.py`
- Test: `tests/fault/private_ai/test_desktop_job_result_reconciliation.py`
- Test: `tests/security/private_ai/test_d3_confirmation_binding.py`
- Test: `tests/integration/private_ai/test_phase5_owner_ingress_composition.py`
- Test: `tests/integration/private_ai/test_desktop_helper_service_lifecycle.py`

**Interfaces:** Prepare displays exact command, arguments, safe relative root/cwd, executable digest, environment, repository head/dirty commitment, declared reads/no writes, limits, network off and effects. Owner-local passkey confirmation expires within two minutes. Core commits `AUTHORIZED_COMMITTED`, signs and persists the exact envelope before helper I/O; helper durably admits exact job digest before process launch. In result reconciliation, `started=true` means process start was proved or conservatively could have occurred after a durable launch admission. Result is bounded/inert and uses the shared verified/accepted-unverified/failed/unknown/expired terminals with the exact started/output/cleanup/evidence matrix and a separate cancellation outcome reason. `ACCEPTED_UNVERIFIED` requires a current pinned-helper signature over the exact job digest, durable admission, observed terminal process receipt, quarantined outputs and no-relaunch bit. `DesktopAcceptanceEvidenceVerifierPort` reloads the stored signed authorized job, durable helper-admission receipt and terminal-execution receipt; it exact-compares their job ID/digest/commitments, current helper key/domain, closed acceptance/isolation/no-relaunch fields and observation/completion order before the reconciler may construct that result. Any verifier miss yields `UNKNOWN` with no evidence and keeps outputs quarantined. Drift, mismatch, replay or ambiguous launch never silently retries. The exact D3 prepare/confirm/result methods are added to the installed owner path only with current Task 30 code and refreshed ingress row; D4 remains omitted. Because Tasks 29–30 change the helper wheel, this same checkpoint rebuilds desktop-helper, refreshes/re-signs its row and reruns installed lifecycle before the first D3 process.

- [ ] **Step 1 — Write failing confirmation/state, installed-route, and helper-row tests.** Cover all prepare/confirm field drift, repo head/dirty/config/filesystem/grant/executable changes, expired/passkey mismatch, double click, core/helper crash before/after admission/launch/result, cancellation/Privacy Shield, timeout/output overflow and process-child escape. Inject restart before admission, after durable admission, after launch, after process exit, before cleanup, and after cleanup but before result persistence. Assert no `DISPATCHING` before durable authorization, at most one start, and that every started job without verified cleanup returns `UNKNOWN` (or `ACCEPTED_UNVERIFIED` only with its separately verified evidence), never `FAILED`. Extend the shared ingress suite with D3 positive, D4/unknown/disabled `404` without Core dispatch, stale Task 28 ingress-row rejection, and stale Task 28 helper-row rejection after Tasks 29–30.

```python
@pytest.mark.parametrize(("boundary", "expected"), [
    ("before_helper_admission", (False, False, "not_applicable", "FAILED")),
    ("after_admission_before_launch", (False, False, "not_applicable", "FAILED")),
    ("after_launch_admission_before_start_receipt", (True, False, "unverified", "UNKNOWN")),
    ("after_process_start_before_exit", (True, False, "unverified", "UNKNOWN")),
    ("after_signed_exit_before_cleanup", (True, True, "unverified", "ACCEPTED_UNVERIFIED")),
    ("after_cleanup_before_result_commit", (True, True, "verified", "VERIFIED")),
])
async def test_restart_reconciliation_uses_complete_started_output_cleanup_matrix(
    restart_harness, boundary, expected,
) -> None:
    await restart_harness.crash_at(boundary)
    result = await restart_harness.restart_and_reconcile_same_job()
    expected_started, expected_output, expected_cleanup, expected_terminal = expected
    assert (result.started, result.has_output, result.cleanup_state, result.terminal_state) == expected
    assert restart_harness.process_start_count <= 1
    assert restart_harness.relaunch_count == 0

@pytest.mark.parametrize("field", [
    "schema_version", "job_id", "canonical_job_digest", "helper_admission_commitment",
    "terminal_execution_receipt_commitment", "acceptance_kind", "isolation_state",
    "relaunch_allowed", "observed_at", "signature_domain", "key_id", "signature",
])
async def test_accepted_unverified_requires_exact_current_signed_evidence(
    restart_harness, signed_acceptance_evidence, field,
) -> None:
    await restart_harness.crash_at("after_signed_exit_before_cleanup")
    result = await restart_harness.restart_and_reconcile_same_job(
        acceptance_evidence=mutate_one_field(signed_acceptance_evidence, field),
    )
    assert result.terminal_state == "UNKNOWN"
    assert result.accepted_unverified_evidence is None
    assert restart_harness.relaunch_count == 0

@pytest.mark.parametrize("stored_binding", [
    "authorized_job_digest", "helper_admission_commitment",
    "terminal_execution_receipt_commitment", "current_helper_key_id",
])
async def test_restart_never_trusts_self_asserted_acceptance_over_stored_authority(
    restart_harness, signed_acceptance_evidence, stored_binding,
) -> None:
    await restart_harness.crash_at("after_signed_exit_before_cleanup")
    await restart_harness.drift_stored_authority(stored_binding)
    result = await restart_harness.restart_and_reconcile_same_job(
        acceptance_evidence=signed_acceptance_evidence,
    )
    assert result.terminal_state == "UNKNOWN"
    assert result.accepted_unverified_evidence is None
    assert restart_harness.outputs_remain_quarantined
    assert restart_harness.relaunch_count == 0
```

- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/integration/private_ai/test_d3_job_execution.py tests/fault/private_ai/test_d3_action_state_machine.py tests/fault/private_ai/test_desktop_job_result_reconciliation.py tests/security/private_ai/test_d3_confirmation_binding.py tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/private_ai/test_desktop_helper_service_lifecycle.py -q`; expect missing executor/dispatch logic and both current signed generations.
- [ ] **Step 3 — Implement pre-I/O authorization, bounded execution, atomic D3 route delta, and refreshed helper row.** Re-resolve every bound fact at confirmation and helper admission, launch exact argv with read-only roots/controlled empty home/network off/process group, stream-capped output, kill group on deadline/revocation and reconcile uncertain jobs by same ID only. Before `ACCEPTED_UNVERIFIED`, call `DesktopAcceptanceEvidenceVerifierPort.require_exact_current` against the reloaded signed job plus durable admission/terminal receipts and current helper key; never trust fields repeated only inside the proposed result/evidence. Recompose/sign/rebuild/refresh the owner-ingress candidate; separately rebuild desktop-helper after the registry/executor changes, refresh/re-sign its row, and deny all D3 effect I/O until both installed lifecycles pass.
- [ ] **Step 4 — Prove GREEN, at-most-once start, and both installed lifecycles.** Run narrow suites repeatedly with fault injection, including `tests/fault/private_ai/test_desktop_job_result_reconciliation.py`, plus `uv run pytest tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py tests/integration/private_ai/test_desktop_helper_service_lifecycle.py -q`; expect each synthetic job starts zero or one time, no write/network/repo-code process, every ambiguity `UNKNOWN`, and the exact D3 flow through current ingress/helper rows including update/rollback and both cleanup modes.
- [ ] **Step 5 — Commit D3 execution, route checkpoint, and refreshed helper row.** Stage the exact helper/core/API/tests plus `apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/api/app.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json ops/services/phase3-owner-ingress.v1.json ops/services/phase5-desktop-helper.v1.json tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/private_ai/test_desktop_helper_service_lifecycle.py`, run `git diff --cached --check && make verify-private-data`, inspect durable ordering and both row digests, and commit with `git commit -m "feat(phase5): execute confirmed d3 inspections"`.

### Task 31: Qualify one D4 sandbox backend or keep all repo code execution absent

**Depends on:** Tasks 08, 25 and 30; a candidate local sandbox backend is installed and owner-inspectable.

**Gate contribution:** P5-5 D4 fail-closed prerequisite; no qualifying backend means D4 stays absent.

**Estimated effort:** 5–9 engineering person-days plus owner-gated actual-backend qualification time.

**Files:**

- Create: `apps/desktop-helper/src/tuntun_desktop_helper/sandbox.py`
- Modify: `ops/services/phase5-desktop-helper.v1.json`
- Create: `scripts/phase5/qualify_d4_sandbox.py`
- Create: `docs/operations/phase5-d4-sandbox.md`
- Create: `docs/evidence/phase5-d4-sandbox.schema.json`
- Test: `tests/unit/private_ai/test_d4_sandbox_policy.py`
- Test: `tests/security/private_ai/test_d4_sandbox_escape.py`
- Test: `tests/hardware/private_ai/test_d4_sandbox_backend.py`
- Test: `tests/integration/private_ai/test_desktop_helper_service_lifecycle.py`

**Interfaces:** Default sandbox is read-only source plus disposable write layer; no network, host home, Docker/host socket, SSH agent, Keychain, device, host PID namespace, Tuntun production socket/data, HA, camera or robot route. Limits: two CPUs, 4 GiB RAM, 20 processes, 15 minutes, 100 MiB combined output, 1 GiB disposable disk. Backend/version/config/evidence is pinned. Any filesystem/process/network/device/IPC/secret/resource/cancellation/cleanup/malicious-build/undeclared-write escape fails closed, quarantines outputs, revokes grant and disables backend. Adding `sandbox.py` makes the Task 30 helper row stale; this task rebuilds/re-signs the helper row and passes installed lifecycle before the real backend qualifier may execute repository code.

- [ ] **Step 1 — Write failing policy/escape and helper-row tests.** Build synthetic malicious projects probing parent/symlink/mount escape, proc/sys/dev, host PID, fork bomb, memory/disk/output bomb, lingering process, UNIX/TCP/UDP/DNS/IPv6/metadata, Docker/SSH/Keychain/env/home, production sockets, signals/cancellation, undeclared writes, compiler/build scripts and artifact smuggling. Reject the Task 30 helper row against the sandbox-added wheel and require restart to clear all grants/jobs/instances.
- [ ] **Step 2 — Prove RED without executing repository code outside D4.** Run only the harness unit tests against a fake sandbox adapter plus `uv run pytest tests/integration/private_ai/test_desktop_helper_service_lifecycle.py -q`; expect missing policy/qualifier and a stale helper row. The real backend marker test must skip with `D4 backend unqualified` unless the explicit flag, candidate and refreshed row exist.
- [ ] **Step 3 — Implement backend adapter, evidence verifier, and refreshed helper deployment.** Admission checks exact backend binary/config digest and current evidence; create a fresh disposable instance per job, materialize only declared roots, apply kernel/runtime controls before project mount, collect a manifest of writes/processes/network denials, destroy the instance and mark any unverifiable cleanup as failure. Rebuild helper from these final bytes, refresh/re-sign its row and keep D4 actual execution disabled until installed lifecycle/update/rollback/cleanup passes.
- [ ] **Step 4 — Prove helper lifecycle before the actual backend.** First run `uv run pytest tests/integration/private_ai/test_desktop_helper_service_lifecycle.py -q` against the refreshed row, including install/start/health/SIGTERM/crash-restart/update/rollback/preserve/destroy and stale-row rejection. Only then run `TUNTUN_ALLOW_PHASE5_DESKTOP=1 uv run python scripts/phase5/qualify_d4_sandbox.py --evidence-root var/evidence/phase5/desktop` and the marker-gated hardware test. Expect every escape denied, limits enforced, complete cleanup and signed current evidence. A single failure keeps `private_ai.desktop_d4` absent and forbids all repo code/test/lint/build/format/generator execution.
- [ ] **Step 5 — Commit qualification machinery and refreshed row, not evidence.** Stage the exact helper/script/doc/schema/tests plus `ops/services/phase5-desktop-helper.v1.json tests/integration/private_ai/test_desktop_helper_service_lifecycle.py`, exclude evidence, run `git diff --cached --check && make verify-private-data`, inspect deny defaults and row freshness, and commit with `git commit -m "test(phase5): qualify fail closed d4 sandbox"`.

### Task 32: Run signed D4 workflows and produce patches only in disposable copies

**Depends on:** Task 31 has current positive backend evidence; Tasks 05, 27 and 30.

**Gate contribution:** P5-5 D4 workflow gate.

**Estimated effort:** 4–7 engineering person-days.

**Files:**

- Modify: `apps/desktop-helper/src/tuntun_desktop_helper/executor.py`
- Modify: `apps/desktop-helper/src/tuntun_desktop_helper/sandbox.py`
- Modify: `ops/services/phase5-desktop-helper.v1.json`
- Create: `apps/core/src/tuntun_core/services/private_ai/desktop_workflows.py`
- Create: `ops/desktop/phase5-d4-workflow-policy.yaml`
- Test: `tests/integration/private_ai/test_d4_workflow.py`
- Test: `tests/security/private_ai/test_d4_patch_isolation.py`
- Test: `tests/fault/private_ai/test_d4_workflow_crashes.py`
- Modify test: `tests/fault/private_ai/test_desktop_job_result_reconciliation.py`
- Test: `tests/integration/private_ai/test_desktop_helper_service_lifecycle.py`

**Interfaces:** `DesktopWorkflowManifestV1` is owner-signed and exact. Initially register only `apply_patch_in_isolated_copy.v1`: copy declared source into disposable D4, apply one exact owner-reviewed unified diff there, run only the manifest’s registered already-installed tests, produce the resulting bounded patch plus content-safe process/write/resource/network-denial evidence, then destroy. Host source is never written; host patch publication/apply, commit/push, package installation with WAN, arbitrary workflow and office-laptop execution remain absent. Phase 5 has no workflow-network exception: every non-`none` value is rejected before sandbox launch. A future exception would require a new contract and threat/evidence gate and still could not inherit authority from model egress. Changes to executor/sandbox make the Task 31 row stale; refresh and installed lifecycle precede the first actual workflow.

- [ ] **Step 1 — Write failing workflow/isolation and helper-row tests.** Cover unsigned/stale/modified manifest, undeclared step/input/output/write/process, backend evidence drift, host tree before/after identity, malicious build, patch path escape/binary/oversize/secret, D4 network versus model-egress combinations, crash at every action transition and cleanup failure. Reuse the restart-boundary state-matrix suite with the D4 adapter so a surviving/unclean sandbox is always `UNKNOWN` (or separately evidenced `ACCEPTED_UNVERIFIED`), never `FAILED`/`VERIFIED`, and is never relaunched. Reject the Task 31 row after executor/sandbox mutation.
- [ ] **Step 2 — Prove RED.** Run service tests with fake sandbox results plus `uv run pytest tests/integration/private_ai/test_desktop_helper_service_lifecycle.py -q`; expect the workflow service and refreshed row to be missing. Actual workflow tests remain denied until the qualified D4 runner and current row both exist.
- [ ] **Step 3 — Implement workflow and refresh helper before effect I/O.** Commit exact reviewed-diff/workflow authorization before helper I/O, verify backend evidence at admission, reconstruct argv from registered already-installed workflow steps, hash input/output trees, apply only the committed unified diff in the disposable copy, validate resulting patch paths/content/DLP, return the review artefact only, and destroy/quarantine before final `VERIFIED`. Rebuild helper, refresh/re-sign its row and pass lifecycle before admitting an actual workflow.
- [ ] **Step 4 — Prove current helper lifecycle, then GREEN host immutability.** First run `uv run pytest tests/integration/private_ai/test_desktop_helper_service_lifecycle.py -q` with install/start/health/SIGTERM/crash-restart/update/rollback/preserve/destroy. Then run `TUNTUN_ALLOW_PHASE5_DESKTOP=1 uv run pytest tests/integration/private_ai/test_d4_workflow.py tests/security/private_ai/test_d4_patch_isolation.py tests/fault/private_ai/test_d4_workflow_crashes.py tests/fault/private_ai/test_desktop_job_result_reconciliation.py -q`; expect all repo code inside D4, identical host source digest, bounded patch/evidence, exact terminal truth and no persistent instance. Without the flag/current evidence/row, expect denial, not fallback execution.
- [ ] **Step 5 — Commit D4 workflow and refreshed helper row.** Stage the exact helper/service/policy/tests plus `ops/services/phase5-desktop-helper.v1.json tests/integration/private_ai/test_desktop_helper_service_lifecycle.py`, run `git diff --cached --check && make verify-private-data`, inspect no host write-back/commit/push and row freshness, and commit with `git commit -m "feat(phase5): run isolated d4 patch workflows"`.

### Task 33: Add separately gated D3 and D4 owner job UI with truthful results

**Depends on:** Tasks 29–32; D3 can pass independently of D4.

**Gate contribution:** Completes P5-5 per subfamily.

**Estimated effort:** 2–4 engineering person-days.

**Files:**

- Modify: `apps/core/src/tuntun_core/api/routes/desktop.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Modify: `ops/services/phase3-owner-ingress.v1.json`
- Consume: `ops/services/phase5-desktop-helper.v1.json`
- Modify: `apps/admin/src/features/ai-workspace/desktop.tsx`
- Create: `apps/admin/src/features/ai-workspace/desktop-job-result.tsx`
- Modify: `packages/contracts/openapi/admin-v1.yaml`
- Modify: `apps/admin/src/api/generated/admin-v1.ts`
- Modify: `apps/core/src/tuntun_core/services/features/registry.py`
- Modify: `apps/admin/src/app/feature-registry.ts`
- Test: `tests/integration/private_ai/test_desktop_jobs_api.py`
- Test: `apps/admin/src/features/ai-workspace/desktop-jobs.test.tsx`
- Test: `tests/ui/ai-workspace-desktop-jobs.spec.ts`
- Test: `tests/accessibility/ai-workspace-desktop-jobs.spec.ts`
- Test: `tests/integration/private_ai/test_phase5_owner_ingress_composition.py`
- Test: `tests/integration/private_ai/test_desktop_helper_service_lifecycle.py`

**Interfaces:** UI separates D3 “inspect” from D4 “run isolated workflow,” shows exact command/workflow, root/cwd, input-state digest change, read/write/network/model-egress/limits, backend evidence age and two-minute confirmation. Result uses `ui.operation_result.v1` states including `UNKNOWN`, shows inert bounded stdout/stderr/patch and verified cleanup, and never claims host changes. D3 and D4 have independent signed feature registrations. This checkpoint recomposes the installed desktop route from those independent facts, refreshes the ingress row, and omits every ineligible D4 method/path rather than leaving a handler that denies late. It does not mutate helper bytes; it must verify the current Task 30 D3-only row or Task 32 D3+D4 row before exposing the matching UI.

- [ ] **Step 1 — Write failing UI/state, installed-route, and helper-binding tests.** Probe owner/non-owner/remote and direct URL/API/prepared action/bundle; D3/D4 mislabeled command; expired/drifted confirmation; absent D4 backend; double-submit; cancel/Privacy Shield; unknown/reconcile; hostile output/patch; accessible modal focus/countdown/error/status and no automatic retry. Extend the shared ingress suite for independently enabled D3/D4 positives and ineligible D4/unknown `404` without Core dispatch, plus stale prior ingress-row rejection. Require exact-match to the current Task 30 or Task 32 helper row/lifecycle and reject UI capability facts bound to the other generation.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/integration/private_ai/test_desktop_jobs_api.py tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/private_ai/test_desktop_helper_service_lifecycle.py -q && pnpm --filter @tuntun/admin test -- desktop-jobs.test.tsx && pnpm --filter @tuntun/admin e2e -- tests/ui/ai-workspace-desktop-jobs.spec.ts tests/accessibility/ai-workspace-desktop-jobs.spec.ts`; expect the job read model/UI, current route generation or exact helper binding to be missing.
- [ ] **Step 3 — Implement server-authoritative jobs, result views, and atomic route delta.** Classify every selected command server-side, require exact passkey for D3/D4, stream only bounded escaped result frames, disable interactions during reconciliation, register D3 after Task 30 evidence and D4 only after current Tasks 31–32 evidence. Recompose the candidate app/container/allowlist from those exact facts, sign its manifest, rebuild ingress, refresh/re-sign the row and take over as one generation.
- [ ] **Step 4 — Prove P5-5 GO/NO-GO on the installed candidate.** Run narrow suites plus production build, feature-absence probes and `uv run pytest tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py tests/integration/private_ai/test_desktop_helper_service_lifecycle.py -q`. D3 may register with D4 absent. D4 GO requires current backend/host-immutability/cleanup, ingress lifecycle and exact current helper row; any escape/evidence/row drift atomically removes D4 route/API/action/chunk and revokes jobs/grants.
- [ ] **Step 5 — Commit desktop job UI and route checkpoint.** Stage the exact API/UI/registry/tests plus `apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/api/app.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json ops/services/phase3-owner-ingress.v1.json tests/integration/private_ai/test_phase5_owner_ingress_composition.py`, run `git diff --cached --check`, inspect separate registrations, truthful `UNKNOWN` and row freshness, and commit with `git commit -m "feat(phase5): expose gated desktop jobs"`.

---

## Wave 5 — P5-6 Local Non-Generative Selected-Frame Perception

### Task 34: Build a separate local-only non-generative perception gateway

**Depends on:** Tasks 01–02, 07–10, 13 and the post-P5-2 Task 14 host decision; an eligible pinned non-generative CV artifact. A positive appliance path also requires Task 15 isolation evidence; otherwise only simulator/absence work executes.

**Gate contribution:** P5-6 isolated CV boundary; Phase 3 does not yet send frames.

**Estimated effort:** 4–6 engineering person-days.

**Files:**

- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Create: `apps/perception-proxy/pyproject.toml`
- Create: `apps/perception-proxy/src/tuntun_perception_proxy/__init__.py`
- Create: `apps/core/src/tuntun_core/services/private_ai/perception_gateway.py`
- Create: `apps/core/src/tuntun_core/adapters/perception/appliance.py`
- Create: `apps/perception-proxy/src/tuntun_perception_proxy/server.py`
- Create: `apps/perception-proxy/src/tuntun_perception_proxy/verifier.py`
- Create: `apps/perception-proxy/src/tuntun_perception_proxy/frames.py`
- Create: `apps/perception-proxy/src/tuntun_perception_proxy/runtime.py`
- Create: `apps/perception-proxy/src/tuntun_perception_proxy/cleanup.py`
- Create: `ops/inference-appliance/perception.compose.yaml`
- Create: `ops/inference-appliance/perception-firewall.nft`
- Create: `ops/services/phase5-perception-proxy.v1.json`
- Test: `tests/contract/private_ai/test_perception_proxy.py`
- Test: `tests/security/private_ai/test_perception_non_generative.py`
- Test: `tests/privacy/private_ai/test_perception_media_lifecycle.py`
- Test: `tests/integration/private_ai/test_perception_proxy_service_lifecycle.py`
- Modify: `tests/unit/private_ai/test_phase5_package_smoke.py`

**Interfaces:** `PerceptionGatewayPort.observe(SignedSelectedFrameRequestV1, frames) -> SignedAnonymousVisualObservationV1` verifies the core signature over domain `tuntun.selected-frame-request.v1` before accepting bytes and returns one proxy signature over domain `tuntun.anonymous-visual-observation.v1`. `state=not_observed|uncertain|rejected` represents every no-observation outcome; no undefined parallel DTO exists. Proxy is a separate local appliance process/service with an allowlisted activated non-generative classifier/detector artifact and the exact class union `person | vehicle | pet | package | motion | unknown`; no alias/free label, `LanguageModelPort`, LLM/VLM/captioner/OCR/generative runtime, Internet/cloud/VPS, filesystem/media mount, identity/memory/action/HA path, browse/pan/fetch/general camera access or continuous stream. This task registers the contracts-only `tuntun-perception-proxy` root-workspace package and `tuntun-perception-proxy = tuntun_perception_proxy.server:main` entry point; it cannot import core or inference-proxy code. `server.py` owns injectable `run(argv, runtime) -> int`, side-effect-free help/version, fail-closed start, and bounded read-only health. The isolated compose service and `phase5-perception-proxy.v1` row use the frozen exact executable, `tuntun-perception:tuntun-perception`, root-owned configuration, RAM-only `/run/tuntun-perception-proxy`, and mTLS TCP `9444` admitted only from the separately pinned Mac perception identity/address. It shares no container, UID, certificate, port, queue, runtime or model mount with inference. Restart rotates the request generation and clears every frame buffer before health. Without a delivered Task 15-isolated appliance, the production service/package/config/port/row remain absent and Task 34 can complete only simulator/absence work.

- [ ] **Step 1 — Write failing protocol/media/lifecycle tests.** Cover schema/signature/replay/deadline/digest/class mismatch; 0/4 frames, >3 MiB, >1920 px, non-JPEG/PNG, audio/EXIF/URL/credential; partial upload/cancel/crash; generative model/interface/import/config/network attempt; output caption/OCR/identity/demographic/health/action/memory/media fields and crash/log/cache persistence. Extend package smoke for version/entry-point resolution and forbidden imports from both core and inference proxy. Parse the installed compose/firewall/service row; drive help/version/start/health/SIGTERM, wrong account/config, deliberate crash/restart, old request replay, stale runtime, buffer clearing, and both uninstall modes with injected resources.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/unit/private_ai/test_phase5_package_smoke.py tests/contract/private_ai/test_perception_proxy.py tests/security/private_ai/test_perception_non_generative.py tests/privacy/private_ai/test_perception_media_lifecycle.py tests/integration/private_ai/test_perception_proxy_service_lifecycle.py -q`; expect missing proxy project metadata/gateway and service lifecycle.
- [ ] **Step 3 — Implement bounded RAM-only decode, closed classification, and exact service wrapper.** Add `apps/perception-proxy` to the existing root workspace, update `uv.lock`, and create its Hatchling project with Python `==3.12.*`, version `0.1.0.dev0`, workspace `tuntun-contracts` dependency, frozen script entry point, matching `__version__`, and frozen CLI lifecycle. Render the isolated compose/firewall target and manifest from one typed description with read-only root/image, all capabilities dropped, no-new-privileges, fixed non-root UID/GID, bounded resources/PIDs/files, tmpfs runtime/body buffers, encrypted-or-disabled swap, no core dumps and no environment secret. Verify account/config/peer metadata before bytes, stream into a locked bounded buffer, strip/deny metadata, invoke only the pinned local CV adapter, validate approved class/reason/confidence/calibration, sign a content-free result and zero buffers in success/failure/cancel/restart paths.
- [ ] **Step 4 — Prove GREEN, lifecycle, and no egress/persistence.** Always run `uv lock && uv sync --all-packages && uv run pytest tests/unit/private_ai/test_phase5_package_smoke.py tests/contract/private_ai/test_perception_proxy.py tests/security/private_ai/test_perception_non_generative.py tests/privacy/private_ai/test_perception_media_lifecycle.py tests/integration/private_ai/test_perception_proxy_service_lifecycle.py -q && uv build apps/perception-proxy && uv run tuntun-perception-proxy --help && uv run tuntun-perception-proxy --version && uv run ruff check apps/perception-proxy tests/unit/private_ai/test_phase5_package_smoke.py tests/integration/private_ai/test_perception_proxy_service_lifecycle.py && uv run mypy apps/perception-proxy/src`; add process import/packet/file-open spies and expect no language-model call, Internet/lateral socket, media file, reusable handle, embedding, feature vector, crash body or frame-derived log. For a delivered Task 15 appliance, additionally run `uv run python scripts/phase5/verify_appliance_network.py --synthetic --config ops/inference-appliance` followed by the same lifecycle and external packet/file probes on that appliance. Without Task 15, run `uv run python scripts/check_feature_absence.py --feature phase5_perception_proxy --phase 5` and require the production package/config/service/port/target row absent.
- [ ] **Step 5 — Commit perception boundary.** Run `git add pyproject.toml uv.lock apps/perception-proxy apps/core/src/tuntun_core/services/private_ai/perception_gateway.py apps/core/src/tuntun_core/adapters/perception/appliance.py ops/inference-appliance/perception.compose.yaml ops/inference-appliance/perception-firewall.nft ops/services/phase5-perception-proxy.v1.json tests/unit/private_ai/test_phase5_package_smoke.py tests/contract/private_ai/test_perception_proxy.py tests/security/private_ai/test_perception_non_generative.py tests/privacy/private_ai/test_perception_media_lifecycle.py tests/integration/private_ai/test_perception_proxy_service_lifecycle.py && git diff --cached --check && make verify-private-data`; inspect runtime allowlist/isolation/lifecycle cleanup, and commit with `git commit -m "feat(phase5): add local anonymous cv gateway"`.

### Task 35: Integrate the exact Phase 3 frame broker and ignore advisory count for authority

**Depends on:** Task 34; accepted current Phase 3 selected-frame contracts, bounded validators, canonical topology, and privacy policy. Phase 3 deliberately proved the perception runtime absent and did not create a frame broker or observation consumer.

**Gate contribution:** P5-6 end-to-end advisory observation path.

**Estimated effort:** 4–7 engineering person-days plus owner calibration evidence time.

**Files:**

- Create: `apps/core/src/tuntun_core/services/private_ai/perception_policy.py`
- Modify: `apps/core/src/tuntun_core/services/private_ai/privacy_effects.py`
- Create: `apps/core/src/tuntun_core/services/vision/selected_frame_broker.py`
- Create: `apps/core/src/tuntun_core/services/vision/observation_consumer.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Create: `scripts/phase5/run_selected_frame_gate.py`
- Test: `tests/integration/private_ai/test_phase3_selected_frame_bridge.py`
- Test: `tests/security/private_ai/test_selected_frame_bindings.py`
- Test: `tests/privacy/private_ai/test_advisory_count_non_authority.py`
- Test: `tests/fault/private_ai/test_selected_frame_cancellation.py`
- Test: `tests/security/private_ai/test_perception_route_container_absence.py`

**Interfaces:** Phase 3 alone validates and issues exact `selected_frame_request.v1`: `camera_binding_id`, `camera_binding_generation`, canonical `area_id`, subordinate `zone_id`, `zone_generation`, purpose, model manifest digest, `privacy_policy_version`, caps/window/output ID/single-use/commitment. Before accepting observation it rechecks the live request, exact area/zone/generations, camera binding, privacy generation, model/calibration, time and one-use. `count_band` is recorded only in content-minimized quality metrics and is ignored for occupancy, alerts, routines, actions, presence and HA state.

- [ ] **Step 1 — Write failing binding/non-authority/internal-boundary tests.** Mutate each exact field/generation and topology ownership; test zone moved across area/binding, privacy change, model/calibration drift, replay/late result, Privacy Shield/camera policy during transfer and advisory count variation. Snapshot native `camera.security_event.v1`, `presence.changed.v1`, alerts, occupancy, routines and HA outputs before/after all count bands. Prove the internal container provider, broker, consumer, and authenticated outbound proxy transport target are all absent before the signed P5-6 bridge gate; after one atomic enable they appear together, and every failed/stale gate removes them together. Prove no Core HTTP route, owner-ingress method/path, or route-manifest entry is created here. Task 36 first-owns the owner-facing status router.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/integration/private_ai/test_phase3_selected_frame_bridge.py tests/security/private_ai/test_selected_frame_bindings.py tests/privacy/private_ai/test_advisory_count_non_authority.py tests/fault/private_ai/test_selected_frame_cancellation.py tests/security/private_ai/test_perception_route_container_absence.py -q`; expect the first-owned broker/consumer/container wiring and policy to be absent while the consumed Phase 3 contract/validator fixtures still pass and owner HTTP remains unchanged.
- [ ] **Step 3 — Implement broker-owned one-shot transfer, consumer validation, and atomic internal registration.** First-own the runtime modules above; keep frame selection in Phase 3 RAM, use a five-second maximum authorization, stream directly through the dedicated outbound perception gateway/proxy protocol, zero on every exit, admit observation only after all current-generation checks, and expose `count_band` to evaluation metrics—not any authority interface. Wire only internal providers behind one signed feature-generation transaction; create no API router, owner-ingress allowlist change, or inbound listener.
- [ ] **Step 4 — Prove GREEN and run the internal owner-gated calibration.** Run `uv run pytest tests/integration/private_ai/test_phase3_selected_frame_bridge.py tests/security/private_ai/test_selected_frame_bindings.py tests/privacy/private_ai/test_advisory_count_non_authority.py tests/fault/private_ai/test_selected_frame_cancellation.py tests/security/private_ai/test_perception_route_container_absence.py -q && uv run ruff check apps/core/src/tuntun_core/services/private_ai/perception_policy.py apps/core/src/tuntun_core/services/vision/selected_frame_broker.py apps/core/src/tuntun_core/services/vision/observation_consumer.py apps/core/src/tuntun_core/bootstrap/container.py scripts/phase5/run_selected_frame_gate.py tests/integration/private_ai/test_phase3_selected_frame_bridge.py tests/security/private_ai/test_selected_frame_bindings.py tests/privacy/private_ai/test_advisory_count_non_authority.py tests/fault/private_ai/test_selected_frame_cancellation.py tests/security/private_ai/test_perception_route_container_absence.py && uv run mypy apps/core/src scripts/phase5/run_selected_frame_gate.py`; then run `TUNTUN_ALLOW_PHASE5_PERCEPTION=1 uv run python scripts/phase5/run_selected_frame_gate.py --evidence-root var/evidence/phase5/perception` using synthetic test cards/approved de-identified calibration only. Expect exact-cap enforcement, zero retained media/egress, current binding evidence, byte-for-byte unchanged native event/occupancy/HA outputs, and no new owner HTTP path.
- [ ] **Step 5 — Commit the non-HTTP Phase 3/P5 bridge.** Run `git add apps/core/src/tuntun_core/services/private_ai/perception_policy.py apps/core/src/tuntun_core/services/private_ai/privacy_effects.py apps/core/src/tuntun_core/services/vision/selected_frame_broker.py apps/core/src/tuntun_core/services/vision/observation_consumer.py apps/core/src/tuntun_core/bootstrap/container.py scripts/phase5/run_selected_frame_gate.py tests/integration/private_ai/test_phase3_selected_frame_bridge.py tests/security/private_ai/test_selected_frame_bindings.py tests/privacy/private_ai/test_advisory_count_non_authority.py tests/fault/private_ai/test_selected_frame_cancellation.py tests/security/private_ai/test_perception_route_container_absence.py && git diff --cached --check && make verify-private-data`; exclude evidence, inspect every generation/non-authority snapshot and route-manifest non-change, and commit with `git commit -m "feat(phase5): consume bounded phase3 frames"`.

### Task 36: Expose calibration/quality status without media, identity, or action authority

**Depends on:** Tasks 34–35.

**Gate contribution:** Completes P5-6 after positive local evidence; otherwise full feature absence.

**Estimated effort:** 2–3 engineering person-days.

**Files:**

- Create: `apps/core/src/tuntun_core/api/routes/perception.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Modify: `ops/services/phase3-owner-ingress.v1.json`
- Create: `apps/admin/src/features/ai-workspace/perception.tsx`
- Create: `apps/admin/src/routes/ai-workspace-perception.tsx`
- Modify: `packages/contracts/openapi/admin-v1.yaml`
- Modify: `apps/admin/src/api/generated/admin-v1.ts`
- Modify: `apps/admin/src/app/router.tsx`
- Modify: `apps/core/src/tuntun_core/services/features/registry.py`
- Modify: `apps/admin/src/app/feature-registry.ts`
- Create: `docs/evidence/phase5-perception.schema.json`
- Test: `tests/integration/private_ai/test_perception_status_api.py`
- Test: `apps/admin/src/features/ai-workspace/perception.test.tsx`
- Test: `tests/ui/ai-workspace-perception.spec.ts`
- Test: `tests/integration/private_ai/test_phase5_owner_ingress_composition.py`

**Interfaces:** Owner-only read model shows the exact current request ID, camera-binding pseudonym/generation, canonical `area_id` display resolved by core, `zone_id`/`zone_generation`, privacy generation, purpose, frame caps, distinct `model_manifest_digest`, `model_artifact_id`, `model_artifact_digest` and `calibration_digest` bindings, request/result times, state, approved class, advisory `count_band`, confidence and bounded reasons plus aggregate precision/recall/unknown/latency/drop/cleanup metrics and local-only/no-store truth. It labels the entire result non-authoritative and `count_band` ignored for Phase 3 alerts/occupancy. It shows no frame/thumbnail/raw handle/caption/OCR/name/face/profile/demographic/clothing/emotion/health/free prose, action or HA control. Calibration uses synthetic test cards or an explicit local owner procedure and cannot label household members. This task first-owns the owner-facing perception router; the Task 35 proxy flow remains a separate outbound non-HTTP boundary. The status route is installed only through the atomic refreshed-ingress checkpoint.

- [ ] **Step 1 — Write failing status/UI/absence and installed-route tests.** Probe non-owner/remote/direct URL/API/action/bundle; stale area/zone/camera/privacy/model/calibration evidence; media/identity leakage or count authority/history beyond the bounded current advisory result; attempt to configure alert/routine/occupancy/HA use; Privacy Shield; accessible status and explicit native-detection independence. Extend the shared suite with an installed owner-status positive, disabled/unknown `404` without Core dispatch, no exposure of the Task 35 proxy protocol, and stale Task 33 row rejection.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/integration/private_ai/test_perception_status_api.py tests/integration/private_ai/test_phase5_owner_ingress_composition.py -q && pnpm --filter @tuntun/admin test -- perception.test.tsx && pnpm --filter @tuntun/admin e2e -- tests/ui/ai-workspace-perception.spec.ts`; expect the read model/UI and current owner-route generation to be missing.
- [ ] **Step 3 — Implement aggregate read model and atomic first owner route.** Derive current names from topology without persisting them in evidence, enforce owner role, render no media, register only on current Tasks 34–35 evidence, and atomically unregister/cancel/clear buffers on Privacy Shield or any binding drift. Construct the pure router from explicit container dependencies, add only its exact status methods/paths to the canonical app/allowlist, sign the manifest, rebuild ingress, refresh/re-sign its row and take over as one candidate.
- [ ] **Step 4 — Prove P5-6 GO/NO-GO through the installed listener.** Run narrow suites, production build and `uv run pytest tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py -q`. GO requires local non-generative artifact, exact Phase 3 bindings, calibration/quality, zero-egress/no-store, non-authority and current ingress lifecycle evidence; otherwise URL/API/client/action remain absent and native Phase 3 detections continue unchanged.
- [ ] **Step 5 — Commit perception UI/gate and route checkpoint.** Stage the exact API/UI/registry/schema/tests plus `apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/api/app.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json ops/services/phase3-owner-ingress.v1.json tests/integration/private_ai/test_phase5_owner_ingress_composition.py`, run `git diff --cached --check`, inspect media/identity/action absence, advisory count-ignore labeling and row freshness, and commit with `git commit -m "feat(phase5): expose anonymous cv health"`.

---

## Wave 6 — P5-7 Supervised Common-Area Raspbot

### Task 37: Implement the robot-edge simulator, closed protocol, and paired identity

**Depends on:** Tasks 01–02, 06–08; no motor power.

**Gate contribution:** P5-7 simulation/transport baseline; all physical capabilities absent.

**Estimated effort:** 3–5 engineering person-days.

**Files:**

- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Create: `apps/robot-edge/pyproject.toml`
- Create: `apps/robot-edge/src/tuntun_robot_edge/__init__.py`
- Create: `apps/robot-edge/src/tuntun_robot_edge/agent.py`
- Create: `apps/robot-edge/src/tuntun_robot_edge/pairing.py`
- Create: `apps/robot-edge/src/tuntun_robot_edge/protocol.py`
- Create: `apps/robot-edge/src/tuntun_robot_edge/health.py`
- Create: `apps/core/src/tuntun_core/adapters/robot/edge_client.py`
- Test: `tests/contract/private_ai/test_robot_edge_protocol.py`
- Test: `tests/property/private_ai/test_robot_lease_protocol.py`
- Test: `tests/security/private_ai/test_robot_pairing.py`
- Modify: `tests/unit/private_ai/test_phase5_package_smoke.py`

**Interfaces:** Robot initiates paired mTLS/WSS to the Mac with a distinct device certificate/signing key. Closed messages are activation/readiness, `RobotMotionLeaseV1`, high-priority stop, content-free `robot.safety_state.v1` and camera capability negotiation. Edge has no family/profile/memory/provider/HA/passkey/inference/desktop/knowledge credential. Pairing is owner-local physical ceremony; restore/restart/revocation requires a new epoch/reconciliation. Simulator never invokes a real motor/camera. This task registers the contracts-only `tuntun-robot-edge` root-workspace package and `tuntun-robot-edge = tuntun_robot_edge.agent:main` entry point; `agent.py` owns injectable `run(argv, runtime) -> int`, side-effect-free help/version, fail-closed start, and bounded read-only health. Root smoke validates the installed package, while edge deployment later builds the same lock-defined artifact.

- [ ] **Step 1 — Write failing protocol/property tests.** Generate at least 10,000 lease/sequence/epoch/expiry/geofence/capability/direction/controller/reconnect cases; cover forged/replayed/out-of-order messages, cert rotation/revocation, competing controller, pairing reset, oversized/unknown payload and attempts by voice/child/Guest/model/HA/camera/routine/remote/LILYGO identities. Extend package smoke for version/entry-point resolution and forbidden imports from core/household/provider packages.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/unit/private_ai/test_phase5_package_smoke.py tests/contract/private_ai/test_robot_edge_protocol.py tests/property/private_ai/test_robot_lease_protocol.py tests/security/private_ai/test_robot_pairing.py -q`; expect missing edge project metadata/client protocol.
- [ ] **Step 3 — Implement closed transports against `FakeRobot`.** Add `apps/robot-edge` to the existing root workspace, update `uv.lock`, and create its Hatchling project with Python `==3.12.*`, version `0.1.0.dev0`, workspace `tuntun-contracts` dependency, frozen script entry point, and matching `__version__`. Verify bounded envelope/cert/signature before dispatch, persist pairing and receiver admission without leases/media, rotate controller epoch on reconnect/restart, expose stop as priority lane, and default simulated supervisor to latched stopped/not-ready.
- [ ] **Step 4 — Prove GREEN and zero simulated unsafe motion.** Run `uv lock && uv sync --all-packages && uv run pytest tests/unit/private_ai/test_phase5_package_smoke.py tests/contract/private_ai/test_robot_edge_protocol.py tests/property/private_ai/test_robot_lease_protocol.py tests/security/private_ai/test_robot_pairing.py -q && uv build apps/robot-edge && uv run tuntun-robot-edge --help && uv run ruff check apps/robot-edge tests/unit/private_ai/test_phase5_package_smoke.py && uv run mypy apps/robot-edge/src`; require at least 10,000 generated cases plus packet/content scanners and expect zero accepted lease without every current binding, zero auto-resume and no forbidden credential/data in edge state.
- [ ] **Step 5 — Commit simulator/protocol.** Stage `pyproject.toml uv.lock apps/robot-edge apps/core/src/tuntun_core/adapters/robot/edge_client.py tests/unit/private_ai/test_phase5_package_smoke.py tests/contract/private_ai/test_robot_edge_protocol.py tests/property/private_ai/test_robot_lease_protocol.py tests/security/private_ai/test_robot_pairing.py`, run `git diff --cached --check && make verify-private-data`, inspect identities/replay/epoch, and commit with `git commit -m "feat(phase5): add paired robot edge simulator"`.

### Task 38: Probe the exact delivered Raspbot with wheels raised and isolate its ports

**Depends on:** Tasks 08 and 37; delivered Raspbot, owner present, wheels physically raised, motor power physically controllable.

**Gate contribution:** P5-7 hardware capability inventory; unknown facts remove capabilities.

**Estimated effort:** 3–4 engineering person-days plus owner/delivered-hardware inspection time.

**Files:**

- Create: `scripts/phase5/inventory_raspbot.py`
- Create: `ops/robot-edge/firewall.nft`
- Create: `ops/robot-edge/tuntun-robot-edge.service`
- Create: `ops/robot-edge/tmpfiles.conf`
- Create: `ops/robot-edge/README.md`
- Create: `ops/services/phase5-robot-edge.v1.json`
- Create: `docs/operations/phase5-raspbot-inventory.md`
- Create: `docs/evidence/phase5-raspbot-inventory.schema.json`
- Test: `tests/unit/private_ai/test_raspbot_inventory_harness.py`
- Test: `tests/hardware/private_ai/test_raspbot_capability_probe.py`
- Test: `tests/security/private_ai/test_robot_edge_ports.py`
- Test: `tests/integration/private_ai/test_robot_edge_service_lifecycle.py`

**Interfaces:** Record pseudonymous exact kit/board/SKU/Pi RAM/motor controller/firmware/vendor image/source availability, motor API/stop/boot/rate/stale/recovery, encoders/odometry/IMU/line/ultrasonic/bump/cliff directional coverage, battery/charger/thermal/brownout, camera/indicator, motor-enable/e-stop feasibility, ROS/DDS/hotspot/SSH/web/cloud/control ports and dependencies. Vendor control stays loopback-only behind edge; if isolation cannot be verified, floor capability is absent. The rendered unit and `phase5-robot-edge.v1` row implement the frozen service baseline exactly: `/opt/tuntun/current/.venv/bin/tuntun-robot-edge start --config /etc/tuntun/robot-edge.toml`, `tuntun-robot-edge:tuntun-robot-edge`, root-owned mode-`0640` config, `/run/tuntun-robot-edge`, paired state `/var/lib/tuntun-robot-edge`, bounded restart, outbound-only paired Mac transport, and exact cleanup. `health` never enables motor power or opens camera/vendor control. Startup rotates the boot/controller epoch and proves motor-disable/e-stop before any outbound ready state; crash/restart cannot reuse a lease or resume motion.

- [ ] **Step 1 — Write failing harness/port/lifecycle tests.** Feed complete/incomplete synthetic probes; require provenance/hash/version for every executable/firmware, explicit unknown/unsupported, no marketing-inferred capability, deny non-loopback vendor ports/outbound cloud/default credentials, and redact serial/MAC/IP/SSID/user/path. Parse the installed unit/tmpfiles/service row and drive help/version/start/health/SIGTERM, wrong account/config, deliberate crash/restart, stale runtime, old lease/controller epoch replay, preserve uninstall and destroy uninstall. Assert every start failure and health call leaves motor enable off, and preserve uninstall retains only disclosed encrypted pairing state with no runnable authority.
- [ ] **Step 2 — Prove RED without hardware.** Run `uv run pytest tests/unit/private_ai/test_raspbot_inventory_harness.py tests/security/private_ai/test_robot_edge_ports.py tests/integration/private_ai/test_robot_edge_service_lifecycle.py -q`; expect missing harness/unit/manifest/lifecycle. Confirm hardware test skips without the exact flag/device.
- [ ] **Step 3 — Implement read-only probe and deny-default service/firewall.** Every vendor interaction is an explicit bounded adapter call; probe never enables wheels-down motion, face recognition/tracking/large model or vendor cloud. Hash local dependencies, enumerate sockets, disable unused services and record any non-reproducible component as residual risk. Render the unit, tmpfiles rule, firewall and signed service row from one typed description; verify effective account/config/runtime/paired-state ownership before keys/devices/network, rotate boot/controller epochs, and require motor-disable/e-stop proof before readiness.
- [ ] **Step 4 — Run static lifecycle and the actual wheels-raised probe.** First run `uv run pytest tests/unit/private_ai/test_raspbot_inventory_harness.py tests/security/private_ai/test_robot_edge_ports.py tests/integration/private_ai/test_robot_edge_service_lifecycle.py -q && uv run ruff check scripts/phase5/inventory_raspbot.py apps/robot-edge tests/unit/private_ai/test_raspbot_inventory_harness.py tests/security/private_ai/test_robot_edge_ports.py tests/integration/private_ai/test_robot_edge_service_lifecycle.py`. On the target Pi after installing the signed executable/unit but before loading it, run `systemd-analyze verify /etc/systemd/system/tuntun-robot-edge.service`; with an adult, wheels raised, and physical motor cutoff, run `TUNTUN_ALLOW_PHASE5_ROBOT=1 uv run python scripts/phase5/inventory_raspbot.py --wheels-raised --evidence-root var/evidence/phase5/robot`, then the marker-gated hardware/port/lifecycle tests. Expect exact signed inventory, exact unit behavior and only the paired Mac edge; any unknown motor-enable, failed service lifecycle, required safety direction, or unisolated port keeps floor motion and the packaged robot service absent.
- [ ] **Step 5 — Commit probe/service contract, not evidence.** Run `git add scripts/phase5/inventory_raspbot.py ops/robot-edge/firewall.nft ops/robot-edge/tuntun-robot-edge.service ops/robot-edge/tmpfiles.conf ops/robot-edge/README.md ops/services/phase5-robot-edge.v1.json docs/operations/phase5-raspbot-inventory.md docs/evidence/phase5-raspbot-inventory.schema.json tests/unit/private_ai/test_raspbot_inventory_harness.py tests/hardware/private_ai/test_raspbot_capability_probe.py tests/security/private_ai/test_robot_edge_ports.py tests/integration/private_ai/test_robot_edge_service_lifecycle.py && git diff --cached --check && make verify-private-data`; exclude device evidence/identifiers, and commit with `git commit -m "test(phase5): inventory delivered raspbot"`.

### Task 39: Install and qualify the independent latching physical e-stop

**Depends on:** Task 38 exact motor-enable engineering evidence; owner-approved safety parts and protected power arrangement installed by a competent person.

**Gate contribution:** Mandatory P5-7 physical-safety gate; failure permanently limits current hardware to simulator/wheels-raised bench.

**Estimated effort:** 4–6 engineering person-days plus physical parts/installation lead time and 100 owner-supervised trials.

**Files:**

- Create: `apps/robot-edge/src/tuntun_robot_edge/estop.py`
- Create: `apps/robot-edge/src/tuntun_robot_edge/motor.py`
- Modify: `ops/services/phase5-robot-edge.v1.json`
- Create: `scripts/phase5/qualify_estop.py`
- Create: `docs/operations/phase5-raspbot-estop.md`
- Create: `docs/evidence/phase5-raspbot-estop.schema.json`
- Test: `tests/unit/private_ai/test_estop_latch.py`
- Test: `tests/hardware/private_ai/test_physical_estop.py`
- Test: `tests/fault/private_ai/test_estop_failure_matrix.py`
- Test: `tests/integration/private_ai/test_robot_edge_service_lifecycle.py`

**Interfaces:** Conspicuous latching physical control cuts/disables motor power independently of Linux, Wi-Fi, Mac, model and vendor process. Software reads but cannot clear the latch. Reset is physical inspection plus local manual re-arm that rotates controller epoch and invalidates every session/lease. Evidence measures switch actuation to motor-current disable; P95 ≤250 ms across 100 trials including Linux lockup, Wi-Fi/Mac loss, command flood and vendor crash. Authenticated software stop is separately measured ≤250 ms after local receipt and never labeled equivalent. Adding the e-stop/motor adapters makes Task 38's robot row stale; rebuild/re-sign and installed lifecycle are prerequisites to energizing even wheels-raised trials.

- [ ] **Step 1 — Write failing latch/evidence and stale-row tests.** Model boot active/unknown, wiring fault, bounced/stuck input, power cycle, software-clear attempt, reset without inspection/re-arm, stale status, command flood and evidence with fewer than 100 trials/missing failure modes/bad P95. Assert motor adapter defaults disabled and the Task 38 row is rejected against these new bytes.
- [ ] **Step 2 — Prove RED without energizing floor motion.** Run unit/fault tests against a fake current sensor plus `uv run pytest tests/integration/private_ai/test_robot_edge_service_lifecycle.py -q`; expect missing latch/motor/harness and stale row. Confirm hardware test skips without owner flag/current inventory/current lifecycle.
- [ ] **Step 3 — Implement latch state, motor gate, harness, and refreshed edge row.** Physical cutoff remains outside software; code can only require it as a prerequisite and record current-sensor evidence. Re-arm is local physical input plus owner confirmation; unknown/open telemetry means disabled. Rebuild robot-edge after these changes, refresh/re-sign its row from exact wheel/unit/config/firewall/runtime/cleanup bytes and keep motor effects denied until installed lifecycle passes.
- [ ] **Step 4 — Prove lifecycle, then run 100 actual wheels-raised trials.** First run `uv run pytest tests/integration/private_ai/test_robot_edge_service_lifecycle.py -q` including install/start/health/SIGTERM/crash-restart/update/rollback/preserve/destroy and no lease resurrection. Only then use the owner-gated e-stop command under the documented setup and execute all failure modes. Expect independent current disable P95 ≤250 ms, zero software clear, manual re-arm each time and a distinct network-stop metric. Any failure records `physical_estop_ineligible` and prohibits wheels-down use.
- [ ] **Step 5 — Commit e-stop support and refreshed row, not physical evidence.** Stage the exact edge/script/doc/schema/tests plus `ops/services/phase5-robot-edge.v1.json tests/integration/private_ai/test_robot_edge_service_lifecycle.py`, exclude evidence, run `git diff --cached --check`, inspect that no software bypass exists and the row is current, and commit with `git commit -m "feat(phase5): enforce independent robot estop"`.

### Task 40: Enforce local watchdog, signed leases, directional sensors, geofence, and speed clamps

**Depends on:** Tasks 37–39; exact fresh sensor/motor capability evidence and physical barriers.

**Gate contribution:** Completes P5-7 bench/safety commissioning before wheels-down.

**Estimated effort:** 4–7 engineering person-days plus controlled directional and boundary hardware trials.

**Files:**

- Create: `apps/robot-edge/src/tuntun_robot_edge/safety_supervisor.py`
- Create: `apps/robot-edge/src/tuntun_robot_edge/sensors.py`
- Create: `apps/robot-edge/src/tuntun_robot_edge/geofence.py`
- Create: `apps/robot-edge/src/tuntun_robot_edge/watchdog.py`
- Modify: `apps/robot-edge/src/tuntun_robot_edge/motor.py`
- Modify: `ops/services/phase5-robot-edge.v1.json`
- Create: `docs/operations/phase5-raspbot-safety-commissioning.md`
- Create: `docs/evidence/phase5-raspbot-safety.schema.json`
- Test: `tests/property/private_ai/test_robot_safety_supervisor.py`
- Test: `tests/hardware/private_ai/test_robot_stopping_distance.py`
- Test: `tests/fault/private_ai/test_robot_safety_faults.py`
- Test: `tests/integration/private_ai/test_robot_edge_service_lifecycle.py`

**Interfaces:** Local supervisor accepts a lease only for the current session/sequence/epoch, canonical area/robot-binding/zone generations, activation commitment, zone-bound safety digest, direction, signature, and ≤250 ms expiry; applies stricter 0.15 m/s translation and 0.5 rad/s rotation ceilings. Each enabled direction requires fresh obstacle/cliff coverage and worst-case stopping distance plus ≥0.20 m threshold. Stale/contradictory sensor, lease/heartbeat/cert/sequence/canonical-zone uncertainty, competing controller, low battery, indicator/controller fault or e-stop latches stop. `geofence_state` is only a safety label evaluated against that canonical binding-owned `zone_id`, never a second registry. Physical barriers protect stairs/water/heat/balcony/exterior exits and every prohibited room. Each reachable restricted boundary requires 100 adversarial runs with zero entry or near miss. These edge additions stale Task 39's row; refresh and lifecycle precede directional/boundary effects and become the row Task 41 must verify.

- [ ] **Step 1 — Write failing safety properties and stale-row tests.** Generate ≥10,000 lease/sensor/battery/geofence/reconnect combinations, including clock/sequence wrap, full/low battery, carpet/threshold, low light, reflective/dark obstacles and direction-specific stale sensors. Assert no motion without one current valid lease and no resume. Test ceiling cannot be raised, unsupported direction is removed and the Task 39 row rejects these changed bytes.
- [ ] **Step 2 — Prove RED in simulator/wheels-raised mode.** Run property/fault suites plus `uv run pytest tests/integration/private_ai/test_robot_edge_service_lifecycle.py -q`; expect the supervisor and current row to be missing. Hardware stopping-distance test skips until exact e-stop/inventory/barrier/current-lifecycle evidence is present.
- [ ] **Step 3 — Implement safety loop and refresh the edge row.** Keep safety evaluation/motor clamp local and allocation-bounded, prioritize stop/e-stop over telemetry, require monotonic freshness, derive a signed capability digest from exact allowed directions/thresholds/geofence/barriers and rotate epoch on every fault/reconnect/re-arm. Rebuild robot-edge, refresh/re-sign its row and deny physical effects until installed lifecycle passes.
- [ ] **Step 4 — Prove lifecycle and GREEN, then run controlled trials.** Pass ≥10,000 properties/fault tests and `uv run pytest tests/integration/private_ai/test_robot_edge_service_lifecycle.py -q` including update/rollback and both cleanup modes before any physical trial. Under documented barriers/adult spotter/low initial speed, measure every direction at full permitted ceiling across surface/light/obstacle/battery cases and run 100 adversarial approaches per reachable restricted boundary; expect required margin/stops and zero entry/near miss. Remove any failing direction. Household floor use remains absent until Tasks 42–43 also prove indicator-or-camera-removal and battery/charging safety.
- [ ] **Step 5 — Commit safety supervisor and refreshed row.** Stage the exact edge/docs/schema/tests plus `ops/services/phase5-robot-edge.v1.json tests/integration/private_ai/test_robot_edge_service_lifecycle.py`, exclude evidence, run `git diff --cached --check`, inspect stop priority/direction removal and row freshness, and commit with `git commit -m "feat(phase5): supervise bounded robot motion"`.

### Task 41: Authorize owner-held local manual sessions in surveyed common areas only

**Depends on:** Task 40 positive safety capability; physically present adult supervisor and cleared commissioned common-area zone.

**Gate contribution:** P5-8 manual control engine; household floor pilot remains blocked until Tasks 42–44.

**Estimated effort:** 3–5 engineering person-days plus owner-supervised wheels-raised sessions.

**Files:**

- Modify: `apps/core/src/tuntun_core/services/private_ai/robot_policy.py`
- Modify: `apps/core/src/tuntun_core/adapters/robot/edge_client.py`
- Create: `apps/core/src/tuntun_core/api/routes/robotics.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Modify: `ops/services/phase3-owner-ingress.v1.json`
- Consume: `ops/services/phase5-robot-edge.v1.json`
- Modify: `packages/contracts/openapi/admin-v1.yaml`
- Modify: `apps/admin/src/api/generated/admin-v1.ts`
- Create: `scripts/phase5/run_robot_floor.py`
- Test: `tests/integration/private_ai/test_robot_manual_session.py`
- Test: `tests/security/private_ai/test_robot_motion_authorization.py`
- Test: `tests/fault/private_ai/test_robot_session_recovery.py`
- Test: `tests/integration/private_ai/test_phase5_owner_ingress_composition.py`
- Test: `tests/integration/private_ai/test_robot_edge_service_lifecycle.py`

**Interfaces:** Owner on the local authenticated console prepares the exact robot, current canonical `area_id`, robot-binding and binding-owned `zone_id` generations, zone-binding commitment, zone-bound safety digest, directions, speeds, and duration; acknowledges e-stop/barriers/battery/sensors/child-pet clearance and confirms with passkey. Core commits one supervised session/controller epoch before edge activation. Motion leases derive only from a continuously held owner control; release/blur/session loss sends stop and watchdog independently stops. No voice, child, Guest, model, HA, camera event, routine, Phase 6 remote or LILYGO motion authority. The exact local owner session/hold/stop methods must pass the refreshed installed-ingress checkpoint before the wheels-raised session or later floor evidence is collected; video methods remain omitted until Task 42. Task 41 changes no edge bytes and must exact-match the Task 40 robot row/lifecycle before sending a session or lease.

- [ ] **Step 1 — Write failing authorization/session, installed-route, and edge-binding tests.** Probe every forbidden actor/channel through UI/API/config/replay/restore/direct protocol; private/prohibited/unclassified/cross-area zone, stale safety/geofence/battery/indicator, missing adult checklist, control not held, browser blur/disconnect, Mac/Wi-Fi/edge restart, competing controller and stop loss. Assert no session resurrection. Extend the shared suite with installed prepare/hold/stop positives, video/remote/unknown/disabled `404` without Core dispatch, previous ingress-row rejection after this delta, and rejection of any edge row other than the exact current Task 40 generation.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/integration/private_ai/test_robot_manual_session.py tests/security/private_ai/test_robot_motion_authorization.py tests/fault/private_ai/test_robot_session_recovery.py tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/private_ai/test_robot_edge_service_lifecycle.py -q`; expect the session/API/floor runner, current owner-route generation or exact edge binding to be missing.
- [ ] **Step 3 — Implement prepared session, hold-to-move loop, and atomic route checkpoint.** Recheck all physical/topology/security generations after passkey, persist `AUTHORIZED_COMMITTED`, activate edge and require signed readiness, deterministically clamp input, issue monotonically sequenced leases only while held, and stop/revoke before reconciling any uncertainty. Compose only the eligible manual methods from explicit dependencies, update/sign the exact app/allowlist/manifest, rebuild ingress, refresh/re-sign its row and take over as one verified candidate.
- [ ] **Step 4 — Prove installed lifecycles, then run the wheels-raised session matrix.** Pass narrow suites and `uv run pytest tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py tests/integration/private_ai/test_robot_edge_service_lifecycle.py -q` first. Only then, with an adult, physical cutoff and current Tasks 38–40 evidence, run `TUNTUN_ALLOW_PHASE5_ROBOT=1 uv run python scripts/phase5/run_robot_floor.py --evidence-root var/evidence/phase5/robot --mode wheels-raised-session`. Expect only allowed commands/directions, every release/fault disables output, no uncommanded/resumed command and content-safe signed results. Do not begin household floor use in this task.
- [ ] **Step 5 — Commit manual-session control and route checkpoint.** Stage the exact service/client/API/script/tests plus `apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/api/app.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json ops/services/phase3-owner-ingress.v1.json tests/integration/private_ai/test_phase5_owner_ingress_composition.py`, exclude evidence, run `git diff --cached --check`, inspect actor/channel denies, hold-to-move and row freshness, and commit with `git commit -m "feat(phase5): authorize supervised robot sessions"`.

### Task 42: Add indicator-bound local live video with no audio or storage

**Depends on:** Tasks 38–41; exact camera and truthful indicator/interlock evidence.

**Gate contribution:** Optional P5-8 telepresence-video capability; manual motion can remain separately eligible.

**Estimated effort:** 3–5 engineering person-days plus physical indicator and view-sweep evidence.

**Files:**

- Create: `apps/robot-edge/src/tuntun_robot_edge/camera.py`
- Modify: `apps/robot-edge/src/tuntun_robot_edge/agent.py`
- Modify: `apps/core/src/tuntun_core/api/routes/robotics.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Modify: `ops/services/phase3-owner-ingress.v1.json`
- Modify: `ops/services/phase5-robot-edge.v1.json`
- Create: `docs/operations/phase5-raspbot-camera.md`
- Create: `docs/evidence/phase5-raspbot-camera.schema.json`
- Test: `tests/privacy/private_ai/test_robot_live_video.py`
- Test: `tests/security/private_ai/test_robot_camera_indicator.py`
- Test: `tests/hardware/private_ai/test_robot_camera_view_sweep.py`
- Test: `tests/integration/private_ai/test_phase5_owner_ingress_composition.py`
- Test: `tests/integration/private_ai/test_robot_edge_service_lifecycle.py`

**Interfaces:** Owner-session-bound LAN media uses short-lived authenticated no-store capability, bounded bitrate/resolution and no reusable camera URL/browser frame receipt. It has no audio, cloud/VPS, identity/memory/model, Phase 3 recorder, Reolink recorder, file/cache/crash/screenshot/analytics path. Capture requires a visible indicator tied to the same enable path or fail-closed monitored interlock. Pan/tilt is separately bounded; mechanical limit/removal prevents views toward private/prohibited zones. Before the physical view sweep, this task refreshes both signed deployment boundaries changed by its code: the exact local video methods in the owner-ingress candidate and the `phase5-robot-edge.v1` row against the new edge wheel/agent/camera bytes. Manual control remains independently available if video is omitted.

- [ ] **Step 1 — Write failing media/indicator, installed-route, and edge-row tests.** Cover non-owner/remote/stale session, reusable/replayed URL, browser/cache/service-worker/recording/screenshot API, audio track/device, network egress/recorder/model route, indicator unplug/stuck/desync, camera crash/restart, pan/tilt limit and private doorway view. Extend installed tests with eligible video positive, ineligible/unknown `404` without Core dispatch, stale Task 41 ingress row, stale pre-camera robot row, restart buffer/lease non-replay and both cleanup modes.
- [ ] **Step 2 — Prove RED.** Run privacy/security suites plus `uv run pytest tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/private_ai/test_robot_edge_service_lifecycle.py -q`; expect the camera adapter and both current signed deployment generations to be missing. Confirm physical view-sweep skips without current hardware evidence.
- [ ] **Step 3 — Implement ephemeral media capability, interlock, and both atomic deployment deltas.** Enable indicator before opening capture, continuously monitor, stop/zero stream on any mismatch/session/privacy fault, send only volatile media frames, disable audio devices/tracks, avoid application response bodies/logs and clamp pan/tilt locally. Recompose/sign/rebuild/refresh the owner-ingress candidate, and separately rebuild robot-edge then refresh/re-sign its row from the final agent/camera/unit/config/firewall bytes; neither candidate activates before its lifecycle checks pass.
- [ ] **Step 4 — Prove installed lifecycles, then conduct the physical view sweep.** Pass synthetic tests, `uv run pytest tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py tests/integration/private_ai/test_robot_edge_service_lifecycle.py -q`, and the target robot update/rollback/preserve/destroy lifecycle before the owner-gated view sweep under commissioned barriers. Expect capture iff indicator truth is current, no audio/storage/egress, and no reachable private/prohibited view. If truthful indicator or mechanical privacy cannot be proven, publish the no-video route set while eligible manual controls remain unchanged.
- [ ] **Step 5 — Commit camera boundary and refreshed rows.** Stage the exact edge/API/docs/schema/tests plus `apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/api/app.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json ops/services/phase3-owner-ingress.v1.json ops/services/phase5-robot-edge.v1.json tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/private_ai/test_robot_edge_service_lifecycle.py`, exclude evidence/media, run `git diff --cached --check && make verify-private-data`, and commit with `git commit -m "feat(phase5): gate live only robot video"`.

### Task 43: Calibrate battery safety and retain manual charging with motors disabled

**Depends on:** Tasks 38–41; exact battery/charger telemetry and protected charging procedure.

**Gate contribution:** Mandatory P5-8 battery gate; automatic docking remains absent.

**Estimated effort:** 2–3 engineering person-days plus non-compressible discharge/charge observation.

**Files:**

- Create: `apps/robot-edge/src/tuntun_robot_edge/battery.py`
- Modify: `apps/robot-edge/src/tuntun_robot_edge/safety_supervisor.py`
- Modify: `ops/services/phase5-robot-edge.v1.json`
- Create: `docs/operations/phase5-raspbot-battery-charging.md`
- Create: `docs/evidence/phase5-raspbot-battery.schema.json`
- Test: `tests/unit/private_ai/test_robot_battery_policy.py`
- Test: `tests/hardware/private_ai/test_robot_battery_calibration.py`
- Test: `tests/security/private_ai/test_robot_docking_absence.py`
- Test: `tests/integration/private_ai/test_robot_edge_service_lifecycle.py`

**Interfaces:** Calibrated voltage/current/percentage under load blocks new sessions below 25% and stops at the current safe common-area position below 15%; brownout/inconsistent/stale telemetry stops immediately. Without reliable percentage, cap sessions at ten minutes, require physical voltage/charge check and stop at first low-voltage warning. Charging is manual with motors disabled. Dock/search/approach routes, commands, UI and dependencies remain absent unless a separate future exact-dock design and 100-cycle zero-failure campaign are approved. Battery/supervisor changes stale the Task 42 row (or Task 40 row when video is absent); this task refreshes the applicable no-video/video robot row and lifecycle before physical calibration, and Task 44 must verify that exact generation.

- [ ] **Step 1 — Write failing battery/docking and stale-row tests.** Test calibrated/uncalibrated thresholds, hysteresis without threshold widening, load sag, stale/conflicting sensor, brownout, clock/session cap, charger insert/remove/interlock/thermal, boot while charging and direct docking URL/API/command/config/dependency absence. Reject the applicable Task 40/42 row after battery/supervisor mutation.
- [ ] **Step 2 — Prove RED.** Run unit/security tests against synthetic traces plus `uv run pytest tests/integration/private_ai/test_robot_edge_service_lifecycle.py -q`; expect missing battery policy, docking-negative evidence and current row. Confirm calibration test skips without physical flag/current lifecycle.
- [ ] **Step 3 — Implement battery interlock, manual-charge state, and refreshed edge row.** Treat unknown as unsafe, compute conservative bands from an exact calibration digest, latch stop before telemetry/audit, disable motor gate while charger state is present/uncertain and expose no docking action. Rebuild the applicable final robot-edge target, refresh/re-sign its row and deny calibration/device effects until installed lifecycle passes.
- [ ] **Step 4 — Prove lifecycle and GREEN before physical calibration.** Pass synthetic boundary tests and `uv run pytest tests/integration/private_ai/test_robot_edge_service_lifecycle.py -q` including update/rollback and both cleanup modes. Only then run marker-gated controlled calibration with owner/thermal monitoring; expect signed thresholds and safe stop. If reliable percentage is not demonstrated, record ten-minute/manual-check mode—not an estimated percentage.
- [ ] **Step 5 — Commit battery policy and refreshed row.** Stage the exact edge/docs/schema/tests plus `ops/services/phase5-robot-edge.v1.json tests/integration/private_ai/test_robot_edge_service_lifecycle.py`, exclude evidence, run `git diff --cached --check`, inspect conservative fallback, docking absence and row freshness, and commit with `git commit -m "feat(phase5): enforce manual robot charging"`.

### Task 44: Add the local owner robot console and complete the seven-day supervised soak

**Depends on:** Tasks 41 and 43, plus either current Task 42 camera/indicator evidence or verified physical camera removal/disablement; current P5-7 evidence.

**Gate contribution:** Completes P5-8 per manual/video capability.

**Estimated effort:** 2–3 engineering person-days plus a non-compressible seven-day owner-supervised common-area soak.

**Files:**

- Create: `apps/admin/src/features/ai-workspace/robotics.tsx`
- Create: `apps/admin/src/routes/ai-workspace-robotics.tsx`
- Modify: `packages/contracts/openapi/admin-v1.yaml`
- Modify: `apps/admin/src/api/generated/admin-v1.ts`
- Modify: `apps/admin/src/app/router.tsx`
- Modify: `apps/core/src/tuntun_core/services/features/registry.py`
- Modify: `apps/admin/src/app/feature-registry.ts`
- Modify: `scripts/phase5/run_robot_floor.py`
- Consume: `ops/services/phase5-robot-edge.v1.json`
- Create: `docs/evidence/phase5-robot-soak.schema.json`
- Test: `apps/admin/src/features/ai-workspace/robotics.test.tsx`
- Test: `tests/ui/ai-workspace-robotics.spec.ts`
- Test: `tests/accessibility/ai-workspace-robotics.spec.ts`
- Test: `tests/acceptance/private_ai/test_p5_8_robot_soak.py`
- Test: `tests/integration/private_ai/test_phase5_owner_ingress_composition.py`
- Test: `tests/integration/private_ai/test_robot_edge_service_lifecycle.py`

**Interfaces:** Local owner console shows exact robot/pairing, canonical area/zone/generations, safety digest/allowed directions/speed, e-stop/readiness/sensors/barriers/battery/charging, adult checklist and current video/indicator truth. Controls are hold-to-move with prominent stop; loss of focus/pointer/key/session stops. Phase 6 remote sees health only. Seven-day supervised common-area soak requires no uncommanded motion, missed local stop, prohibited view/area, session resurrection or unsafe battery state; every session has a physically present adult and recorded maintenance time. This task mutates no server/edge route bytes: before the soak it verifies the current Task 41/42 owner-ingress generation and exact Task 43 robot row; any mismatch invalidates the candidate rather than being repaired after the seven-day evidence. It then freezes that exact route/edge/feature candidate and consumes a complete externally pre-issued inherited rollover chain for the whole soak. Soak evidence binds the chain digest and each wall/monotonic lease transition with zero expired-authority interval; a missing/stale successor stops new motion admission and invalidates the uninterrupted seven-day run, while the physical e-stop, local watchdog, and fail-safe stop remain independent.

- [ ] **Step 1 — Write failing UI/soak, installed-generation, and rollover tests.** Probe child/Guest/non-owner/remote/voice/model/HA/camera/routine/LILYGO and direct API/protocol; stale safety/zone/battery/indicator, confirmation race, key/pointer/touch/focus loss, accessibility/alternative stop, page reload/back, Privacy Shield and elapsed-evidence tamper. Video control is absent independently when Task 42 fails. Reject any soak start whose current ingress route set or robot row/lifecycle differs from the exact manual/no-video-or-video candidate. Reject incomplete chain coverage, wrong/reordered successor, candidate/route/edge/registration drift, wall/monotonic expiry, restart lease reuse, any post-expiry motion admission, or soak evidence without the exact chain commitment and a zero-gap activation sequence.
- [ ] **Step 2 — Prove RED.** Run UI/component/acceptance tests plus `uv run pytest tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/private_ai/test_robot_edge_service_lifecycle.py -q`; expect the console/soak verifier to be missing and soak to skip on missing/stale evidence or rows.
- [ ] **Step 3 — Implement local signed read model, hold controls, and chain-bound soak recorder.** Render safety before media, keep stop always reachable, drive no motion from UI timers alone, require edge readiness for each press, revoke on any stale fact, register manual and video capabilities independently and record content-safe session/fault/maintenance metrics. Freeze the accepted ingress/edge/feature candidate, require the existing external workflow's complete inherited chain before the soak starts, stage it only through `FeatureManifestLeaseSupervisor`, and record content-safe chain/activation/lease commitments on every session; runtime has no signer. A disabled/removed camera is an explicit no-video safety configuration; an installed camera with unproved indicator blocks floor use.
- [ ] **Step 4 — Prove installed readiness and chain behavior without starting the soak.** Pass UI/axe/build tests and `uv run pytest tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py tests/integration/private_ai/test_robot_edge_service_lifecycle.py tests/acceptance/private_ai/test_p5_8_robot_soak.py -q` against the exact candidate. Use fake clocks and signed fixture chains to prove the complete Section 15.6 safety oracle, transition/expiry behavior, and zero post-expiry motion admission. Confirm the physical soak command refuses an uncommitted or dirty candidate; do not start the seven-day clock before Step 5.
- [ ] **Step 5 — Commit robot console/soak gate.** Stage exact UI/registry/script/schema/tests, exclude evidence, run `git diff --cached --check`, inspect local-only/hold/stop/remote-health behavior, and commit with `git commit -m "feat(phase5): gate supervised raspbot console"`.

After that commit, verify the worktree is clean, rebuild and lifecycle-qualify the exact ingress/edge/feature candidate without changing bytes, and prepare a new externally signed canonical chain for the resolved commit. Only then run `TUNTUN_ALLOW_PHASE5_ROBOT=1 TUNTUN_ALLOW_PHASE5_ELAPSED=1 uv run python scripts/phase5/run_robot_floor.py soak --duration-seconds 604800 --feature-manifest-chain var/evidence/phase5/feature-authority/signed-rollover-chain.json --evidence-root var/evidence/phase5/robot/floor-soak` and verify it with `uv run python scripts/phase5/run_robot_floor.py verify --feature-manifest-chain var/evidence/phase5/feature-authority/signed-rollover-chain.json --evidence-root var/evidence/phase5/robot/floor-soak --require-physical --require-zero-expired-authority`. GO requires every Section 15.6 safety case, exact unchanged route/edge/feature and chain digests throughout, ordered wall/monotonic lease transitions with zero expired-authority interval, and zero named incident. Missing/stale rollover or any candidate change invalidates the full seven-day run; other failure returns the affected capability to simulator/bench, never a weaker floor setting. Only this clean-commit run is Task 44 qualification evidence, and Task 48 must still repeat it against the later final release candidate when floor motion remains enabled.

---

## Wave 7 — P5-9 Optional LILYGO Experiment and Household Release

### Task 45: Run the optional non-authoritative LILYGO experiment and keep/remove decision

**Depends on:** Tasks 07–08; Task 44 only if evaluating secondary robot stop. The experiment is skipped when no unique safe use remains.

**Gate contribution:** Optional P5-9 capability; `remove`/`not_run` are valid complete outcomes.

**Estimated effort:** 2–3 engineering person-days plus a non-compressible 14-day owner trial if run.

**Files:**

- Create: `firmware/lilygo-status/platformio.ini`
- Create: `firmware/lilygo-status/src/main.cpp`
- Create: `firmware/lilygo-status/include/protocol.h`
- Create: `apps/core/src/tuntun_core/services/private_ai/lilygo.py`
- Create: `apps/admin/src/features/ai-workspace/lilygo.tsx`
- Modify: `apps/core/src/tuntun_core/api/routes/private_ai.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Modify: `ops/services/phase3-owner-ingress.v1.json`
- Modify: `packages/contracts/openapi/admin-v1.yaml`
- Modify: `apps/admin/src/api/generated/admin-v1.ts`
- Create: `scripts/phase5/run_lilygo_trial.py`
- Create: `docs/operations/phase5-lilygo-experiment.md`
- Create: `docs/evidence/phase5-lilygo-trial.schema.json`
- Test: `tests/contract/private_ai/test_lilygo_protocol.py`
- Test: `tests/security/private_ai/test_lilygo_authority_absence.py`
- Test: `tests/fault/private_ai/test_lilygo_lost_device.py`
- Test: `tests/integration/private_ai/test_phase5_owner_ingress_composition.py`

**Interfaces:** Candidate roles are signed non-sensitive status (`PRIVACY`, inference health/route, robot `SAFE/STOPPED/FAULT`), nonce-protected secondary robot stop, or short-lived provisioning ceremony. Firmware is hash-pinned and USB-updated. It stores only its narrow paired-device key; no family profile/memory, passkey/recovery/provider key, long-lived provisioning/robot authority, primary e-stop state, camera/media or broad private-network credential. Status is visibly stale/non-authoritative when disconnected. Secondary stop never starts/extends/resumes motion or substitutes for physical e-stop/watchdog. If an experiment runs, its exact owner status/provision/revoke/stop methods must pass a refreshed installed-ingress checkpoint before the 14-day clock starts. That exact candidate is frozen under a complete externally pre-issued inherited rollover chain, and trial evidence binds its chain/ordered wall-and-monotonic lease transitions with zero expired-authority interval; a missing/stale successor closes experiment admission and invalidates the uninterrupted trial. For `not_run`/`remove`, those methods remain omitted and their direct paths return `404`; no empty handler is retained.

- [ ] **Step 1 — Write failing protocol/authority, installed-route, and rollover tests.** Cover replay/nonce/expiry/spoof, stale/disconnected display, Wi-Fi/BLE/battery/power/firmware crash, reset/factory wipe/lost device, update downgrade/digest mismatch, extracted storage, start/lease/re-arm attempt and failures while physical e-stop/watchdog continue independently. Extend the shared ingress suite with exact retained-role positives, `not_run`/`remove`/unknown/disabled `404` without Core dispatch, and rejection of the previous row after any selected route delta. For a selected trial reject incomplete coverage, reordered/wrong successor, candidate/firmware/route/registration drift, wall/monotonic expiry, restart lease reuse, post-expiry admission, and evidence without the exact chain commitment and zero-gap activation sequence.
- [ ] **Step 2 — Prove RED.** Run Python contract/security/fault tests, `uv run pytest tests/integration/private_ai/test_phase5_owner_ingress_composition.py -q`, and `pio test -d firmware/lilygo-status -e native`; expect missing protocol/service/firmware behavior and current route generation. Hardware trial skips without explicit flag/device/current ingress row.
- [ ] **Step 3 — Implement one protocol, USB flow, decision-specific atomic route set, and inherited chain binding.** Compile roles out unless selected, pin keys/firmware digest, enforce nonce/freshness/minimal display, and wipe on owner revoke/reset. For a selected experiment, compose only its exact eligible owner methods; for `not_run`/`remove`, omit them. Sign the manifest, rebuild ingress, refresh/re-sign its row and take over only after installed positive/negative/lifecycle tests. Freeze that accepted candidate, require the existing external workflow's complete pre-issued chain before trial start, stage it only through `FeatureManifestLeaseSupervisor`, and record content-safe chain/activation/lease commitments; runtime never signs or renews.
- [ ] **Step 4 — Prove the installed checkpoint and chain behavior without starting the optional trial.** Run synthetic/firmware tests and `uv run pytest tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py -q`. Use fake clocks and signed fixtures to prove the 14-day verifier, ordered wall/monotonic transitions, expiry closure, cross-candidate rejection and zero post-expiry admission. Confirm the physical trial command refuses an uncommitted or dirty selected candidate; do not start the optional 14-day clock before Step 5. For `not_run`, carry only the tested route-absent candidate into Step 5 and request no elapsed chain.
- [ ] **Step 5 — Commit experiment machinery/absence and route checkpoint.** Stage only exact decision-included firmware/service/UI/script/docs/schema/tests plus `apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/api/app.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json ops/services/phase3-owner-ingress.v1.json tests/integration/private_ai/test_phase5_owner_ingress_composition.py`, exclude evidence/keys, run `git diff --cached --check && make verify-private-data`, inspect decision-specific route absence/presence and row freshness, and commit with `git commit -m "feat(phase5): gate optional lilygo experiment"`.

If an experiment candidate is selected, verify the worktree is clean after this commit, rebuild and lifecycle-qualify that exact firmware/route/feature candidate without changing bytes, and prepare a new externally signed canonical chain for the resolved commit. Only then run `TUNTUN_ALLOW_PHASE5_ELAPSED=1 uv run python scripts/phase5/run_lilygo_trial.py --duration-seconds 1209600 --feature-manifest-chain var/evidence/phase5/feature-authority/signed-rollover-chain.json --evidence-root var/evidence/phase5/lilygo` and verify it with `uv run python scripts/phase5/run_lilygo_trial.py verify --feature-manifest-chain var/evidence/phase5/feature-authority/signed-rollover-chain.json --evidence-root var/evidence/phase5/lilygo --require-physical --require-zero-expired-authority`. The verifier requires the exact candidate/chain, ordered wall/monotonic transitions, unique retained value, and projected maintenance under 15 minutes/quarter. Only this clean-commit 14-day result can support `keep`, and Task 48's later final 30-day non-robot campaign must also include the retained role on the exact final release candidate. If the trial does not support `keep`, return to Steps 3–5, revoke/wipe the device, commit and lifecycle-verify the route-absent `remove` candidate, and do not claim the failed elapsed interval as release evidence.

### Task 46: Integrate Privacy Shield, content-safe observability, and health degradation

**Depends on:** Tasks 09–45 for every implemented family; absent families still expose signed absence health.

**Gate contribution:** P5-9 cross-cutting privacy/operations prerequisite.

**Estimated effort:** 3–5 engineering person-days.

**Files:**

- Modify: `apps/core/src/tuntun_core/services/private_ai/privacy_effects.py`
- Create: `apps/core/src/tuntun_core/services/private_ai/health.py`
- Modify: `apps/core/src/tuntun_core/api/routes/private_ai.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Modify: `ops/services/phase3-owner-ingress.v1.json`
- Create: `docs/operations/phase5-observability.md`
- Create: `docs/evidence/phase5-health.schema.json`
- Test: `tests/integration/private_ai/test_phase5_privacy_shield.py`
- Test: `tests/privacy/private_ai/test_phase5_observability.py`
- Test: `tests/fault/private_ai/test_phase5_health_degradation.py`
- Test: `tests/integration/private_ai/test_phase5_owner_ingress_composition.py`

**Interfaces:** Privacy Shield transactionally revokes new inference/corpus/desktop/frame/robot/LILYGO authority before fan-out; cancels active work, clears ephemeral buffers and sends robot stop. It reports prior provider egress, file/write/process start and unverified physical stop truthfully; it does not claim undo or stop independent Reolink recording. Metrics/logs contain task-cell hashes, status/reason/latency/resource bands, binding/evidence generations and pseudonymous endpoint—not prompt/result/document/path/frame/video/identity/lease coordinates/secret. Health invalidates capabilities on stale evidence, backup/RPO, root/helper/proxy/sandbox/sensor/indicator/battery/cert/disk/quota failures. Runbooks bind daily automated model/corpus/index/disk/helper/sandbox/robot/audit/backup checks; weekly failed-import/job/route/grant/robot/firmware/quarantine review; monthly cloud/provider/region/storage/advisory/maintenance review; and quarterly restore/model-rollback/key-rotation sample/sandbox-escape/e-stop/boundary/indicator/lost-device drills. The final health/Privacy Shield owner methods are atomically installed with a refreshed ingress row before Task 47 drills or the 30-day campaign; disabled-family details remain non-enumerable.

- [ ] **Step 1 — Write failing atomicity/redaction and installed-route tests.** Inject Privacy Shield at every state-machine boundary and component failure/partition; require authorization revoked before any new admission, bounded cancellation/stop attempts, honest unknown side effects and no automatic restart. Inject private sentinels into every input/error/argv/cache/trace/metric/crash/evidence path and assert scanner rejection. Extend the shared suite with installed health/Shield positives, disabled-family/unknown `404` without Core dispatch and prior-row rejection.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/integration/private_ai/test_phase5_privacy_shield.py tests/privacy/private_ai/test_phase5_observability.py tests/fault/private_ai/test_phase5_health_degradation.py tests/integration/private_ai/test_phase5_owner_ingress_composition.py -q`; expect incomplete effects/health/read model and current route generation.
- [ ] **Step 3 — Implement effect fan-out, health aggregation, and atomic route delta.** Commit global privacy generation first, reject at every worker admission, cancel inference/desktop/frame, block corpus decrypt/import, stop/revoke robot session, stale LILYGO, zero buffers and independently reconcile receipts. Emit only allowlisted bounded measurements and family-specific invalidation facts. Recompose/sign/rebuild/refresh the owner-ingress candidate and activate no new method/path until the complete lifecycle passes.
- [ ] **Step 4 — Prove GREEN under faults on the installed candidate.** Run narrow suites plus `uv run pytest tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py -q && make verify-private-data`; expect no post-shield admissions, all reachable workers cancel/stop or surface `unknown`, independent camera recording unchanged, zero sentinel leakage and a current exact ingress row.
- [ ] **Step 5 — Commit privacy/health integration and route checkpoint.** Stage the exact service/API/docs/schema/tests plus `apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/api/app.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json ops/services/phase3-owner-ingress.v1.json tests/integration/private_ai/test_phase5_owner_ingress_composition.py`, run `git diff --cached --check`, inspect transaction-before-fan-out, truthful unknowns and row freshness, and commit with `git commit -m "feat(phase5): integrate private ai privacy health"`.

### Task 47: Verify backup, restore, update, rollback, network isolation, and fault recovery

**Depends on:** Tasks 03–46; accepted Phase 1 core/Green backup and UPS/power-protection path.

**Gate contribution:** P5-9 recovery/rollback prerequisite.

**Estimated effort:** 3–5 engineering person-days plus owner offline/power/network drills and any replacement-hardware lead time.

**Files:**

- Create: `apps/core/src/tuntun_core/services/private_ai/restore.py`
- Create: `scripts/phase5/run_fault_matrix.py`
- Create: `docs/operations/phase5-backup-restore.md`
- Create: `docs/operations/phase5-update-rollback.md`
- Create: `docs/operations/phase5-network-recovery.md`
- Create: `docs/evidence/phase5-recovery.schema.json`
- Test: `tests/fault/private_ai/test_phase5_fault_matrix.py`
- Test: `tests/acceptance/private_ai/test_phase5_backup_restore.py`
- Test: `tests/security/private_ai/test_phase5_network_boundaries.py`
- Test: `tests/acceptance/private_ai/test_phase5_update_rollback.py`

**Interfaces:** Core/Green backup reproduces canonical model registry/routes/evaluations, knowledge binding policy, desktop workflow manifests, robot/LILYGO inventory and audit receipts; separately managed knowledge recovery reproduces encrypted catalog/objects. It never restores grants, egress authorizations, jobs, routes as active, selected-frame requests/observations, robot sessions/leases/motion or LILYGO pairing. Re-enable only after key/version/digest/deletion/binding/capability/privacy/network/current-evidence reconciliation and new generations. Model/runtime/proxy/helper/edge/firmware updates quarantine first; rollback is one owner action to last accepted immutable version with route/capability revocation before process/device change. Internet forwarding and UPnP/NAT-PMP/PCP remain disabled; scans from an untrusted inner client, BE800 outer office network and an external network prove no Phase 5 public listener or new outer-to-inner route.

- [ ] **Step 1 — Write failing recovery matrix.** Cover Mac/Green/UPS outage and unclean shutdown, DB/catalog/object corruption, wrong/missing knowledge/recovery volume, appliance/desktop/perception/robot partition, cert/key rotation, disk/quota exhaustion, model/parser/sandbox/firmware compromise, restore rollback, deletion generation, update interruption and old-client/worker replay. Assert no permissive fallback or auto-reactivation.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/fault/private_ai/test_phase5_fault_matrix.py tests/acceptance/private_ai/test_phase5_backup_restore.py tests/security/private_ai/test_phase5_network_boundaries.py tests/acceptance/private_ai/test_phase5_update_rollback.py -q`; expect missing restore/fault runner/runbooks.
- [ ] **Step 3 — Implement restore quarantine and deterministic reconciliation.** Inventory restored state without worker I/O, rotate sessions/cancellations/epochs, compare all signed digests/generations, reconcile knowledge separately, issue signed absence facts until each capability passes and support idempotent rollback/cleanup with content-safe evidence.
- [ ] **Step 4 — Prove GREEN with actual drills.** Run the synthetic matrix and owner-gated offline restore/update/rollback/network/power-loss drills. Expect canonical state recovered, knowledge independently verified, all live authorities initially disabled, selected capabilities re-enabled only through current gates, and mandatory UPS/power recovery evidence current. Before any replacement power hardware is ordered, verify supported signalling and recovery compatibility for the selected exact model.
- [ ] **Step 5 — Commit recovery controls.** Stage exact restore/script/docs/schema/tests, exclude local backups/evidence, run `git diff --cached --check && make verify-private-data`, inspect no authority resurrection, and commit with `git commit -m "feat(phase5): restore private ai fail closed"`.

### Task 48: Run the 30-day release campaign and publish the signed Phase 5 release manifest

**Depends on:** Tasks 01–47 for implemented families and accepted UI checkpoint U6 (UI Tasks U20–U22); optional gates may validly end absent.

**Gate contribution:** Completes P5-9 and Phase 5 household release.

**Estimated effort:** 2–3 engineering person-days plus a non-compressible 30-day non-robot trial and, when floor motion is eligible, a fresh seven-day supervised robot soak on the final release candidate; Task 44 evidence is an earlier qualification prerequisite only.

**Files:**

- Create: `scripts/phase5/measure_maintenance.py`
- Create: `scripts/phase5/run_acceptance.py`
- Create: `scripts/phase5/verify_acceptance.py`
- Create: `docs/evidence/phase5-acceptance.schema.json`
- Create: `docs/operations/phase5-household-release.md`
- Modify: `apps/core/src/tuntun_core/services/features/registry.py`
- Modify: `apps/core/src/tuntun_core/bootstrap/container.py`
- Modify: `apps/core/src/tuntun_core/api/app.py`
- Modify: `apps/owner-ingress/src/tuntun_owner_ingress/router.py`
- Modify: `apps/admin/src/app/feature-registry.ts`
- Modify: `ops/routes/owner-ingress-routes.v1.json`
- Modify: `ops/services/phase3-owner-ingress.v1.json`
- Modify: `ops/services/phase5-inference-proxy.v1.json`
- Modify: `ops/services/phase5-desktop-helper.v1.json`
- Modify: `ops/services/phase5-perception-proxy.v1.json`
- Modify: `ops/services/phase5-robot-edge.v1.json`
- Test: `tests/acceptance/private_ai/test_phase5_release.py`
- Test: `tests/acceptance/private_ai/test_phase5_manifest_rollover.py`
- Test: `tests/security/private_ai/test_phase5_negative_reachability.py`
- Test: `tests/privacy/private_ai/test_phase5_release_evidence.py`
- Test: `tests/integration/private_ai/test_phase5_owner_ingress_composition.py`
- Test: `tests/integration/private_ai/test_phase5_final_service_inventory.py`
- Test: `tests/integration/private_ai/test_inference_proxy_service_lifecycle.py`
- Test: `tests/integration/private_ai/test_desktop_helper_service_lifecycle.py`
- Test: `tests/integration/private_ai/test_perception_proxy_service_lifecycle.py`
- Test: `tests/integration/private_ai/test_robot_edge_service_lifecycle.py`
- Test: `tests/performance/private_ai/test_phase5_ui_budgets.py`
- Test: `tests/ui/ai-workspace-feature-manifest.spec.ts`

**Interfaces:** Signed release manifest independently lists every exact task cell/stage/route/artifact, knowledge/FTS/vector capability, each desktop level D0/D1/D2/D3 and exact D4 workflow, selected-frame purpose/model/calibration, robot bench/manual/video/direction/zone capability and LILYGO role as `enabled` or `absent`, with evidence digest/age/invalidation/rollback. Task 48 owns final candidate composition and eventual post-campaign publication: it rebases on every accepted incremental checkpoint, builds the final dependency container explicitly, passes those dependencies into side-effect-free router factories, preserves every still-enabled Phase 5 router in the canonical Core app, updates the Phase 3 owner-ingress proxy allowlist, and signs the exact `ops/routes/owner-ingress-routes.v1.json` bytes. It then refreshes and re-signs `phase3-owner-ingress.v1` against the final owner-ingress distribution/job/configuration and new route-manifest digest. The prior Phase 4 row, and every earlier Phase 5 row, is invalid with the final Phase 5 app/route bytes and is accepted only as part of a complete signed rollback to its matching app/route-manifest set. The installed positive test traverses the real owner listener -> owner-ingress -> authenticated Core UDS for every enabled Phase 5 route; unknown and disabled routes return indistinguishable `404` at ingress without Core dispatch, and no second HTTP listener exists.

The release also binds the exact target set and digest of each applicable signed Phase 5 service inventory row: `phase5-inference-proxy.v1`, `phase5-desktop-helper.v1`, `phase5-perception-proxy.v1`, and `phase5-robot-edge.v1`. Immediately before signing, regenerate every enabled row from the final distribution/wheel, entry point, job/unit/Compose, configuration, firewall, account, runtime and cleanup bytes; remove an absent target/row instead of carrying a stale record. This final scan is mandatory for all four families, not only changed rows: it catches the desktop-helper mutations in Tasks 26 and 29–32 and robot-edge mutations in Tasks 39–43, while independently revalidating the Task 15 inference and Task 34 perception rows. Reject every earlier row whose bound digest differs, including the initial Task 25 desktop-helper and Task 38 robot-edge rows, then rerun each enabled target's complete installed lifecycle and update/rollback matrix against the refreshed row. For every enabled target the package, job/unit, configuration, account, socket/listener/runtime path, target record and current lifecycle evidence are all present and one-to-one; for every absent target all production artifacts and its target record are absent, and a family with no enabled target has no row. The final-candidate 30-day owner trial covers every enabled non-robot capability, including a retained LILYGO role; when robot floor motion is enabled, a new final-candidate seven-day supervised soak reruns Task 44's complete safety oracle rather than reusing its earlier receipt. Both can run concurrently only where physical supervision and resource-isolation gates permit, and both bind the same immutable final candidate/route/service graph. No high/critical unresolved issue, unauthorized flow, policy downgrade or canonical-state loss. Phase 5 two-to-four-hour/month estimate is attribution only; all ordinary work enters the single Phase 1–6 maintenance ledger and does not independently promote anything.

The final 30-day campaign and any required final seven-day robot soak consume the inherited Phase 2 `SignedFeatureManifestRolloverChainV1` and `FeatureManifestLeaseSupervisor`; Phase 5 creates no signer or second renewal mechanism. After the final candidate/package/registration bytes are frozen, the existing external acceptance-signing workflow pre-issues one complete hash-chained set of `SignedFeatureManifestV1` envelopes, each valid for at most 24 hours, covering the union of both planned intervals with unchanged authority and no validity gap. Core stages only that complete verified chain and, before every foreground or background admission, requires both the active manifest's wall-clock expiry and its process-local monotonic expiry lease. The acceptance commitment records the exact chain digest and activation sequence and requires zero interval under expired authority across both receipts. A missing, late, reordered, widened, rollback, signature-invalid, candidate-drifted, wall-expired, or monotonic-expired link closes admission before preparation or work, triggers the inherited controlled whole-composition recovery, and invalidates every overlapping final-candidate campaign.

- [ ] **Step 1 — Write failing composition, release, inventory, and rollover tests.** Require every family/subcapability and direct URL/API/prepared-action/client-bundle/IPC/network/runtime negative probe for absent values; reject unsigned/stale/incomplete/evidence-mismatched manifests, elapsed-time fabrication, private evidence, missing recovery/rollback/Privacy Shield/child gates and hidden maintenance. Build a test installation with the real owner listener, owner-ingress proxy and Core UDS; require one positive request through the complete installed chain for each enabled Phase 5 route, non-enumerating `404` without Core dispatch for every unknown/disabled route, no import-time route mutation and no second HTTP listener. Reject a changed route after signing, a mismatched route-manifest/service-row pair, and the previous Phase 4 owner-ingress row under the Phase 5 app; accept it only when the whole matching Phase 4 rollback set is restored. For each of the four frozen Phase 5 service IDs and every declared target, reject feature/package/job/config/account/socket/unit/inventory target or digest mismatch, any pre-final row after later package/config changes, missing install/start/health/SIGTERM/crash-restart/update/rollback/wrong-account/cleanup evidence, extra packaged service, and residue after either uninstall mode; specifically reject the Task 25 desktop-helper row after Tasks 26/29–32 and the Task 38 robot-edge row after Tasks 39–43. Accept an absent target only when every target production artifact/record is absent, and accept a wholly absent family only when its row is absent. Exercise the inherited rollover supervisor with an exact continuous pre-issued chain and reject signer access in runtime, incomplete coverage, more-than-24-hour envelope, wrong chain/index/previous digest, gap, overlap activated out of order, authority widening, candidate/package/registration drift, rollback, late activation, wall expiry, monotonic expiry, restart lease reuse, and any admission during an expired-authority interval. Test optional `no_purchase`, FTS without vectors, D3 without D4, manual without video and no LILYGO as successful explicit absence states. Under household load require authenticated localhost shell interactive ≤2 seconds, cached non-sensitive navigation P95 ≤250 ms, fresh local API view P95 ≤1 second and visibility-aware/jittered polling that yields to voice.
- [ ] **Step 2 — Prove RED.** Run `uv run pytest tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/private_ai/test_phase5_final_service_inventory.py tests/acceptance/private_ai/test_phase5_release.py tests/acceptance/private_ai/test_phase5_manifest_rollover.py tests/security/private_ai/test_phase5_negative_reachability.py tests/privacy/private_ai/test_phase5_release_evidence.py -q && pnpm --filter @tuntun/admin e2e -- tests/ui/ai-workspace-feature-manifest.spec.ts`; expect the final composition, refreshed signed rows, inherited rollover admission binding, release runner/verifier, and complete manifest to be missing.
- [ ] **Step 3 — Finalize composition, refresh exact service rows, and build the immutable candidate.** Verify rather than trust every referenced evidence bundle/signature/duration/digest, compute candidate feature facts from exact current gates, include fallback and invalidation, and record ordinary/emergency/quarterly maintenance separately. In an immutable candidate release slot, rebase on the latest accepted route set, construct every enabled router explicitly from the final container, update the Core app and owner-ingress allowlist without import side effects, render/sign the route manifest, then regenerate/sign `phase3-owner-ingress.v1` from the final owner-ingress job/config/distribution plus that manifest digest. Regenerate each enabled Phase 5 service row only after all source, job, configuration and firewall bytes are final; remove absent targets/rows. Freeze the candidate commitment and exercise `FeatureManifestLeaseSupervisor` only with signed synthetic fixture chains before Step 5; do not request or stage a real campaign chain for uncommitted bytes. Run negative reachability, the full candidate installed-chain probe, lifecycle/update/rollback, rollover fail-closed tests, and inventory one-to-one checks against disposable candidate sockets/listeners. On failure, retain the prior complete signed app/route/service set rather than mixing generations. Export only the signed row IDs/digests/targets needed by the later Phase 6 package lifecycle; never rediscover jobs by scanning a live host. This step may materialize a content-safe unsigned release-manifest draft/commitment, but it neither activates the household release nor signs/publishes the P5-9 release manifest.
- [ ] **Step 4 — Prove the complete candidate and elapsed-control machinery without starting either final clock.** Run `uv run pytest tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/private_ai/test_phase5_final_service_inventory.py tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py tests/integration/private_ai/test_inference_proxy_service_lifecycle.py tests/integration/private_ai/test_desktop_helper_service_lifecycle.py tests/integration/private_ai/test_perception_proxy_service_lifecycle.py tests/integration/private_ai/test_robot_edge_service_lifecycle.py tests/acceptance/private_ai/test_phase5_manifest_rollover.py tests/acceptance/private_ai/test_phase5_release.py tests/security/private_ai/test_phase5_negative_reachability.py tests/privacy/private_ai/test_phase5_release_evidence.py -q`; require the final owner-ingress and every enabled Phase 5 target's takeover/start/health/deliberate crash-restart/update/rollback/both-uninstall matrix, explicit rejection of stale rows, and full signed-fixture rollover/adversarial coverage. Run performance, the full standard non-hardware command set, UI/axe/build, coverage, private-data and git-diff checks. Confirm both elapsed runners refuse uncommitted or dirty bytes and no elapsed evidence exists; do not start the 30-day campaign or optional final robot soak before Step 5.
- [ ] **Step 5 — Commit final composition, refreshed inventories, release machinery, and signed public fixture only.** Stage `apps/core/src/tuntun_core/bootstrap/container.py apps/core/src/tuntun_core/api/app.py apps/owner-ingress/src/tuntun_owner_ingress/router.py ops/routes/owner-ingress-routes.v1.json ops/services/phase3-owner-ingress.v1.json`, then stage only each applicable final Phase 5 service-row path listed above (including a tracked deletion for an absent row), plus the exact Task 48 scripts/docs/schema/registries/tests and a content-safe synthetic manifest fixture. Exclude owner evidence, run `git diff --cached --check && git diff --cached --name-only && make verify-private-data`, inspect the final signed digest graph and rollback pairing, and commit with `git commit -m "test(phase5): gate private ai household release"`.

After that commit, verify the worktree is clean, rebuild and lifecycle-qualify the resolved commit without changing bytes, atomically install that exact app/route/service candidate, and repeat bounded post-takeover health/digest checks. Prepare one new externally signed canonical chain covering the union of the full 30-day interval and any concurrent/contained final robot interval, verify its unchanged authority and linkage, and stage it only through `FeatureManifestLeaseSupervisor`. Then run `TUNTUN_ALLOW_PHASE5_ELAPSED=1 uv run python scripts/phase5/run_acceptance.py --feature-manifest-chain var/evidence/phase5/feature-authority/signed-rollover-chain.json --duration-seconds 2592000 --evidence-root var/evidence/phase5/acceptance`; if floor motion is enabled, also run `TUNTUN_ALLOW_PHASE5_ROBOT=1 TUNTUN_ALLOW_PHASE5_ELAPSED=1 uv run python scripts/phase5/run_robot_floor.py soak --duration-seconds 604800 --feature-manifest-chain var/evidence/phase5/feature-authority/signed-rollover-chain.json --candidate-manifest var/evidence/phase5/acceptance/final-candidate.json --evidence-root var/evidence/phase5/acceptance/final-robot-soak`. Verify both applicable receipts with `uv run python scripts/phase5/verify_acceptance.py --evidence-root var/evidence/phase5/acceptance --require-final-candidate --require-zero-expired-authority`, then rerun performance, security/privacy, UI/axe/build, coverage, private-data and worktree checks. GO requires valid uninterrupted final-candidate 30-day non-robot evidence, a fresh final-candidate seven-day robot receipt only for enabled floor capabilities, the current restore/rollback/security/privacy evidence, the final route/service digest graph, and every capability explicitly enabled/absent. No tracked change is allowed between either elapsed run and final verification; a candidate change invalidates both overlapping receipts and requires a new chain/full restart. Any failed optional capability is removed under a new committed candidate and the affected final campaign is rerun rather than widening or mislabelling another capability. Only after all required receipts and final verifiers pass may the existing external release-signing workflow sign and atomically publish the P5-9 release manifest from the committed generator/schema, binding the resolved commit, final candidate/route/service graph, exact receipt digests, chain commitment, and enabled/absent facts. Publication output remains in the ignored evidence/release channel and changes no candidate or tracked byte; a signing, binding, or publication failure leaves P5-9 unpublished.

---

## Effort and Calendar Envelope

The normative Phase 5 estimate remains **130–210 engineering person-days**, exactly **26–42 focused one-developer weeks** at five engineering days per week, after the Phase 3 frame boundary and Phase 4 endpoint contracts are stable. The individual task ranges above sum to this same envelope; they size engineering implementation/review work, not owner operating burden and not permission to compress a safety or evidence gate.

| Work package | Tasks | Engineering person-days |
|---|---:|---:|
| Contracts, registries, simulators, routing/evaluation foundation | 01–11 | 14–22 |
| Active control-host benchmark and optional appliance isolation/promotion | 12–16 | 12–22 |
| Knowledge catalog, object store, FTS, citations, deletion, backup and UI | 17–22, 24 | 22–32 |
| Optional embeddings/vector evaluation | 23 | 6–12 |
| Desktop D0–D2 grants, read, proposal and exact model egress | 25–28 | 14–20 |
| Desktop D3 registry and conditional fail-closed D4 sandbox/workflows | 29–33 | 18–32 |
| Selected-frame local non-generative perception | 34–36 | 10–16 |
| Raspbot inventory, safety hardware, edge, bench, floor and telepresence | 37–44 | 24–38 |
| Optional LILYGO, privacy/fault/recovery and release evidence | 45–48 | 10–16 |
| **Total** | **01–48** | **130–210** |

The calendar is longer than person-day arithmetic because these intervals are non-compressible and evidence-bound:

- active control host: one worst-case 90-second voice turn, two-hour concurrent soak, eight-hour idle/periodic soak and seven-day mixed workload;
- optional appliance: same-day quote/compatibility evidence and procurement/delivery/return-window lead time, followed by 14-day M3 and 30-day M4 evidence; M5 waits for the full child corpus and distinct current guardian approval;
- storage/recovery: encrypted-volume acquisition/commissioning when needed, a 24-hour recovery/deletion reconciliation bound and quarterly offline restore;
- D4/perception: actual installed-backend qualification and current hardware/model/calibration evidence, with no simulated substitute for a positive gate;
- Raspbot: safety-part acquisition/installation, 100 physical e-stop trials, direction/boundary/battery/view-sweep campaigns and a separate seven-day physically supervised common-area soak;
- optional LILYGO: a 14-day owner trial if run; household release: a separate 30-day non-robot campaign; maintenance logging may begin after 60 steady-state days, while the rolling three-month program-wide promotion calculation requires at least 90 steady-state days and three complete monthly buckets.

The Phase 5 two-to-four-hour monthly owner figure is planning attribution only. Commissioning, quarterly restore/security/physical-safety drills, incidents, repairs, hardware replacement and major migrations are measured separately rather than hidden. When a task estimate and this envelope differ after decomposition, the work-package and total normative ranges govern planning; a failed or incomplete evidence window leaves the capability absent.

---

## Dependency and Gate Sequence

```text
FB0 + accepted P2 topology/actions + accepted P3 vision + stable P4 endpoints
  -> 01 contracts -> 02 synthetic fakes
  -> 03–08 persistence, absence, inventory/threat baseline                 [P5-E0/P5-0]
  -> 09–13 Mac gateway, artifact, routing, actual Mac evidence, M1 cells  [P5-1]
  -> 17–22 canonical corpus + separate recovery -> 23 optional -> 24 UI  [P5-2]
  -> 14 decision -> (15–16 only if purchased; return to optional branch)  [P5-3]
  -> 25–28 D0–D2 -> 29–30 D3 -> (31–32 D4 only if qualified) -> 33 UI    [P5-4/P5-5]
  -> 34–36 exact P3 selected-frame local CV                               [P5-6]
  -> 37–40 simulator/bench/e-stop/safety -> 41–44 supervised pilot       [P5-7/P5-8]
  -> 45 optional LILYGO -> 46–48 privacy/recovery/release                 [P5-9]
```

Parallel execution is allowed only after the named dependencies: Wave 1, Wave 3 and the helper foundation may progress after P5-0; appliance work is optional; perception waits for its exact Phase 3 seam; robot wheels-down work is strictly sequential through Tasks 38–40. Tasks sharing `0020`, feature registries, Privacy Shield effects, route modules or generated contracts must serialize and rebase on the preceding task rather than merge competing edits. Owner-route checkpoint Tasks 07, 13, 24, 28, 30, 33, 36, 41, 42, 45, and 46 additionally serialize under one composition lock, rebase on the latest accepted app/router/manifest/row generation, preserve every still-enabled earlier route, and activate one complete immutable candidate before their installed evidence; Task 35 remains the explicit non-HTTP internal exception. Task 48 repeats that protocol as the final candidate-composition owner after all route-module work has converged; its external P5-9 manifest is published only after the clean-commit final campaigns pass.

## Requirements Traceability

| Requirement | Owning tasks | Release proof |
|---|---|---|
| Per-task-cell M0–M5 migration and active control-host limits | 03, 09–13, 16 | Exact-cell evaluation plus two-hour/eight-hour/seven-day Mac evidence; no global switch |
| Optional appliance/no-purchase and isolated M2–M5 | 14–16 | Same-day TCO decision, isolation/packet evidence, stage-specific elapsed evidence or signed absence |
| Closed inference and no cloud authority/media/identity | 01, 09–11, 27, 34–36, 46 | Contract/property/DLP/network/no-store tests and current route evidence |
| One identity-bound knowledge root plus separate recovery | 04, 17–24 | UUID/handle binding, ACL/deletion, 24-hour RPO, quarterly offline restore and non-queryable recovery proof |
| Owner-only import/corpus administration | 18, 21, 24 | Role/direct-reachability matrix and native-picker prepared mutations |
| Desktop D0–D4 and exact egress exception | 05, 25–33 | D3 registry negative corpus, exact egress consumption, D4 escape/host-immutability evidence |
| Exact Phase 3 selected frames, local non-generative CV, advisory count only | 01, 34–36 | Generation/binding tests, no-egress/no-store, native event/occupancy/HA snapshot equality |
| Independent e-stop and supervised common-area Raspbot | 06, 37–44 | 100-trial ≤250 ms e-stop, ≥10,000 safety cases, directional stopping/barriers and seven-day supervised soak |
| Deployable least-privilege side services and signed inventory | 12, 15, 25, 28, 30–34, 38–44, 48 | Exact current target package/job/argv/account/config/socket-or-listener-or-runtime/start/health/restart/update/rollback/wrong-account/cleanup bijection before each gated effect, or complete target absence |
| Sole owner HTTP ingress and incremental/final signed route composition | 07, 13, 24, 28, 30, 33, 36, 41–42, 45–46, 48 | Pure injected factories and an installed listener -> owner-ingress -> Core UDS positive plus unknown/disabled `404`, refreshed route manifest/row, takeover/update/rollback/uninstall at every checkpoint, final candidate composition, and post-campaign release publication |
| Optional non-authoritative LILYGO | 45 | 14-day keep/remove evidence, ≤15-minute/quarter projection, lost-device and no-authority proof |
| Privacy, observability, restore, rollback and truthful feature absence | 07, 46–48 | Fault/privacy/recovery matrix and independently signed Phase 5 release manifest |
| Continuous inherited authority for every campaign longer than 24 hours | 12, 16, 44–45, 48 | Externally pre-issued frozen-candidate rollover-chain commitment, ordered wall/monotonic lease transitions, zero expired-authority interval, and fail-closed run invalidation on any missing/stale successor |
| Single full-system maintenance rule | 48 | Phase 5 attribution exported to shared ledger; logging may begin after 60 steady-state days, while program-wide promotion evaluation requires at least 90 steady-state days and three complete monthly buckets |

## Phase 5 Milestone GO/NO-GO Checklist

### Entry and P5-0

- [ ] Phase 1 `FB0` is accepted; named Phase 1 identity/policy/memory/audit/budget/signing/recovery services are current.
- [ ] Phase 2 canonical topology/action/prepared-mutation contracts, Phase 3 camera/zone/privacy/selected-frame contracts and validators, and stable Phase 4 endpoint/conversation contracts pass their consumer suites; no Phase 3 runtime frame broker is assumed.
- [ ] `selected_frame_request.v1` includes `zone_generation`; `area_id` is canonical and no `room_id` exists.
- [ ] Migrations `0020`–`0022` and separate knowledge `0001`–`0004` pass backup/upgrade/interruption/restore checks.
- [ ] All Phase 5 capabilities begin signed absent and direct URL/API/action/bundle/IPC/network/runtime probes confirm absence.

### P5-1/P5-3 inference

- [ ] Closed request/result contracts reject identity, secrets, media, paths and authority/tool/memory output.
- [ ] Every artifact/runtime/tokenizer/template/evaluation bundle has independent immutable supply-chain evidence.
- [ ] At least one M1 cell, if enabled, has independently owner-approved opaque active-Core target evidence for all exact resource, preemption and duration limits; the receipt records the actual Darwin `arm64` observation but does not derive authority from it. Its seven-day run has the inherited continuous rollover-chain/lease proof, and neighboring cells do not inherit it. Intel macOS can inherit none of this evidence until requalified by a fresh trusted approval and real-host campaign.
- [ ] Appliance decision is current `no_purchase` or exact eligible candidate; purchase/promotion is never assumed.
- [ ] M2–M5 transitions, if used, have exact shadow/14-day/30-day/child evidence and rollback; every longer-than-24-hour run has the inherited continuous rollover-chain/lease proof.

### P5-2 knowledge

- [ ] Exactly one canonical identity-bound root is commissioned, with no automatic fallback/spill and no alias to video/HA backup/recovery.
- [ ] Separate encrypted recovery binding/key/failure domain retains seven daily/four weekly generations, meets 24-hour RPO/deletion reconciliation and passes quarterly offline restore.
- [ ] Owner-only import, parser isolation, encrypted object/catalog/FTS, triple ACL checks, bounded citations, immediate deletion denial, export and root migration pass faults.
- [ ] Canonical memory remains independent; optional vectors are either measured eligible or explicitly absent with FTS complete.

### P5-4/P5-5 desktop

- [ ] D0 has no helper, D1 reads exact selections and D2 proposes without effects; 500 hostile outputs remain inert and DLP-clean.
- [ ] `DesktopModelEgressAuthorizationV1` is exact/current/single-use and independent of workflow network permission.
- [ ] D3 accepts only pinned bounded non-code Git/`rg` inspections with fresh exact confirmation and durable at-most-once action handling.
- [ ] Every repo code/test/lint/build/format/generator/compiler/interpreter/script/binary execution is D4.
- [ ] D4 is enabled only with current complete escape/resource/cancellation/cleanup evidence; source is read-only, writes disposable, network/secrets/devices/sockets absent and host write-back/commit/push absent.

### P5-6 perception

- [ ] Only exact current Phase 3 requests reach the separate local non-generative CV proxy; frames meet count/size/dimension/time/purpose/generation constraints.
- [ ] Frames/features/embeddings never persist or egress; no identity/caption/OCR/language model exists on the path.
- [ ] `count_band` is ignored for occupancy, alerts, routines, actions, presence and HA; native outputs remain unchanged.

### P5-7/P5-8 robotics

- [ ] Exact delivered robot/firmware/dependencies/ports/motor/sensors/battery/camera/indicator are inventoried; vendor control is isolated.
- [ ] Physical latching e-stop independently disables motor enable ≤250 ms P95 over 100 failure-inclusive trials and software cannot clear it.
- [ ] ≥10,000 lease/safety cases, every enabled-direction stopping/margin/surface/light/battery case, barriers and stale-sensor failures pass before wheels-down.
- [ ] Only a physically supervised owner-local held control moves within surveyed common-area zones; every other actor/channel and all prohibited/private/unclassified areas are denied.
- [ ] Video, if enabled, is indicator-bound LAN live-only/no-store/no-audio/no-cloud/no-identity/no-recorder with physical view limits.
- [ ] Battery/charging is conservative and manual; automatic docking remains absent; the seven-day supervised soak has its exact inherited chain commitment, zero expired-authority interval, and zero named safety/privacy incident.

### P5-9 release

- [ ] Optional LILYGO is explicitly `not_run`, `remove`, or retained after its full 14-day security/value/maintenance gate and exact continuous rollover-chain proof; it is never primary authority or safety.
- [ ] Privacy Shield, backup/restore, update/rollback, network partition, power/UPS, key/cert rotation, deletion and component-compromise drills pass with truthful unknown states.
- [ ] Thirty-day enabled non-robot trial binds its externally pre-issued frozen-candidate chain, proves ordered wall/monotonic transitions with zero expired-authority interval, and has no unresolved high/critical finding, unauthorized flow, policy downgrade or canonical-state loss.
- [ ] When floor motion is enabled, a fresh post-commit seven-day supervised robot soak reruns the complete Task 44 safety oracle against the same final candidate/route/service graph; Task 44's earlier receipt is not reused.
- [ ] Signed feature manifest independently marks every cell/capability/workflow/purpose/direction/role enabled or absent, and all absent reachability probes pass.
- [ ] The final installed owner path is exactly one LAN listener -> Phase 3 owner-ingress -> authenticated Core UDS; every enabled Phase 5 route passes through it, unknown/disabled paths return non-enumerating `404` without Core dispatch, and the final signed route manifest plus refreshed `phase3-owner-ingress.v1` row pass takeover/start/health/crash-restart/update/rollback/preserve-uninstall/destroy-uninstall.
- [ ] Each enabled Phase 5 side-process target has a row regenerated from its final bytes plus current install/start/health/SIGTERM/crash-restart/update/rollback/wrong-account/preserve-uninstall/destroy-uninstall evidence; each stale earlier row is rejected, each absent target has no production package/job/config/account/socket/unit/target record, a wholly absent family has no row, and no service-owned residue remains.
- [ ] Phase 5 ordinary owner effort is recorded only as subsystem attribution in the shared Phase 1–6 ledger. Logging may begin after 60 steady-state days, but program-wide promotion evaluation requires at least 90 steady-state days and three complete monthly buckets; at that point, the rolling three-month median is ≤8 hours/month. Three consecutive months above eight freeze optional expansion and trigger simplification/retirement review.

## Final Verification Commands

Run from repository root after all implemented tasks; hardware/elapsed suites remain explicit and never convert a skip into a pass:

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
uv run pytest -m "not phase5_hardware and not phase5_elapsed and not live_cloud" --cov=apps/core/src/tuntun_core --cov=packages/contracts/src/tuntun_contracts --cov-fail-under=85 -q
uv run python scripts/phase5/generate_schemas.py --check
uv run python scripts/phase5/build_corpora.py --check
uv run pytest tests/integration/private_ai/test_phase5_owner_ingress_composition.py tests/integration/private_ai/test_phase5_final_service_inventory.py -q
uv run pytest tests/integration/deploy/test_owner_ingress_route_manifest.py tests/integration/vision/test_deployed_process_entrypoints.py tests/integration/deploy/test_phase3_side_process_lifecycle.py tests/integration/vision/test_owner_ingress_takeover.py tests/fault/vision/test_owner_ingress_takeover_rollback.py -q
uv run pytest tests/acceptance/private_ai/test_phase5_manifest_rollover.py -q
uv run pytest tests/integration/private_ai/test_inference_proxy_service_lifecycle.py tests/integration/private_ai/test_desktop_helper_service_lifecycle.py tests/integration/private_ai/test_perception_proxy_service_lifecycle.py tests/integration/private_ai/test_robot_edge_service_lifecycle.py -q
plutil -lint ops/launchd/phase5/com.tuntun.inference-proxy.plist ops/launchd/phase5/com.tuntun.desktop-helper.plist
uv run python scripts/phase5/verify_acceptance.py --evidence-root var/evidence/phase5/acceptance --require-final-candidate --require-zero-expired-authority
pnpm --filter @tuntun/admin e2e -- tests/ui/ai-workspace-*.spec.ts tests/accessibility/ai-workspace-*.spec.ts
git diff --check
git status --short
```

Expected result: every ordinary suite and baseline synthetic service lifecycle passes; generated artifacts/plists are clean; project coverage is at least 85% and named policy/security branches at least 95%; private-data scan is empty; the installed owner-listener chain, route-manifest digest and refreshed owner-ingress row are exact; every longer-than-24-hour Phase 5 run binds one externally pre-issued frozen-candidate rollover chain with ordered wall/monotonic transitions and zero expired-authority interval; acceptance reports every conditional capability and service target either current enabled with a final-byte signed row/lifecycle/update/rollback proof or completely absent; only task-owned implementation/evidence-schema/public synthetic-fixture paths are modified. Hardware/elapsed evidence is then verified with its exact owner flag and current signed bundle. An enabled robot target also requires `systemd-analyze verify /etc/systemd/system/tuntun-robot-edge.service` plus the target lifecycle test on the Pi. An enabled inference appliance additionally requires `tests/integration/private_ai/test_inference_appliance_service_lifecycle.py`, its container lifecycle and external deny probes on that appliance; after `no_purchase`, that optional test/config/target record is absent and the feature-absence verifier substitutes for it. The executor must stop on any failed command, stale evidence, missing/stale rollover authority, unexpected tracked evidence/private data, service inventory mismatch/residue, route/service digest mismatch, second HTTP listener, or capability registered without its positive gate.

## Implementation Handoff

Execute dependency order with `superpowers:subagent-driven-development` in the current session or `superpowers:executing-plans` in a separate session. Follow numbered order except that the explicitly optional Tasks 14–16 branch is skipped, P5-2 Tasks 17–24 complete, and only then is Task 14’s owner decision recorded; `no_purchase` ends the branch, while an eligible purchase continues through Tasks 15–16. One task equals one reviewed commit. Before each task, confirm its dependencies and gate state; after it, run the narrow and affected suites, inspect exact staged paths, and record whether the gate is positive or safely absent. Never combine an optional hardware/elapsed decision with an unrelated software commit, never commit owner evidence/keys/media/documents/paths/identifiers, and never weaken a failed gate to keep a capability visible.
