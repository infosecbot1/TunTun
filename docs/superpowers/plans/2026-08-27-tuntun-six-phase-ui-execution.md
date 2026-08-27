# Tuntun Six-Phase UI Execution Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the complete six-phase Tuntun presentation layer as four deliberately separate surfaces: the owner console, the Reachy family presenter, the local adult/guardian exact-decision and subject-privacy zone, and the closed shared-display client. Every surface must remain truthful, bilingual, accessible, feature-gated, locally operable, and incapable of creating domain authority in the client.

**Architecture:** Keep the browser, Reachy, ceremony zone, and display renderer as untrusted presenters over strict versioned UI contracts. Canonical services authorize and filter before projection, prepare immutable actions, enforce current generations and distinct principal slots, and return complete correlated results. A signed feature manifest controls server registration, OpenAPI exposure, dynamic imports, route registration, and production chunks; an absent feature is absent rather than hidden. The owner console runs on loopback by default, the ceremony zone has no owner bearer or owner-console imports, Reachy uses a bounded cue/prompt catalogue, and the display agent accepts only signed closed projection variants.

**Tech Stack:** Python 3.12, Pydantic v2, FastAPI, SQLAlchemy/Alembic over SQLCipher, JSON Schema 2020-12, OpenAPI, RFC 8785/JCS, Ed25519/P-256 signatures, React 19, TypeScript strict mode, Vite, React Router, TanStack Query, FormatJS/ICU, Vitest, Testing Library, Playwright, axe-core, Storybook-compatible static stories, Lighthouse/Playwright trace budgets, pytest, Hypothesis, Ruff, strict mypy, and the existing synthetic/hardware evidence runners.

**Normative design:** [Six-Phase UI/UX Architecture Specification](../specs/2026-08-27-tuntun-six-phase-ui-ux-design.md), [Phase 1 Anchor](../specs/2026-08-27-tuntun-phase1-anchor-design.md), [Phase 2 Home Automation](../specs/2026-08-27-tuntun-phase2-home-automation-design.md), [Phase 3 Vision, Presence & Storage](../specs/2026-08-27-tuntun-phase3-vision-presence-storage-design.md), [Phase 4 Whole-Home Voice, Media & Displays](../specs/2026-08-27-tuntun-phase4-voice-media-displays-design.md), [Phase 5 Private AI, Desktop & Robotics](../specs/2026-08-27-tuntun-phase5-private-ai-desktop-robotics-design.md), [Phase 6 Remote Access & Product Hardening](../specs/2026-08-27-tuntun-phase6-remote-access-product-hardening-design.md), [Program A–H](../specs/2026-08-27-tuntun-program-architecture-a-h.md), [Program I–S](../specs/2026-08-27-tuntun-program-assurance-delivery-i-s.md), and [Six-Phase Master Roadmap](./2026-08-27-tuntun-six-phase-master-roadmap.md).

## Global Constraints

1. The current normative specifications control. If an implementation step is less restrictive, stop and reconcile the design, contract, policy, migrations, generated clients, feature manifest, evidence, and tests before proceeding.
2. Domain authorization is exclusively server-side. React, Reachy, the subject zone, and the display client may render safe summaries and return opaque IDs or signed responses; they never construct an actor, policy binding, risk tier, assurance, guardian relation, audience, entitlement, result, or success claim.
3. The owner console is an untrusted presenter at `127.0.0.1:8787` by default. Paired private-LAN HTTPS is explicit; Phase 6 VPN access is `surface=owner`, `origin=remote` under its own origin class and operation matrix, never a fifth surface. No task binds a public or wildcard interface.
4. The four surfaces are exactly `owner`, `reachy`, `subject`, and `display`, and they remain separate trust zones. The subject-decision application imports no owner-console feature package and receives no owner bearer. The display client imports no owner API client. Reachy receives no admin DTO. The owner console cannot synthesize subject or guardian approvals. Remote origin cannot be paired with the other three surfaces.
5. `area_id` is the only canonical household location identifier in every UI contract, filter, fixture, URL parameter, component prop, test, and evidence record. `zone_id` is a versioned child of a camera binding and one `area_id`. There is no `room_id`, alias, compatibility field, mapping table, or migration.
6. Exactly one household conversation is active initially. No UI implies concurrent conversations, passive follow-me, identity authority from a room, or authentication transfer during handoff.
7. Face/voice evidence personalizes only during explicit enrollment or active interaction. There is no passive identity discovery, unknown-candidate queue, re-encounter workflow, durable unknown biometric record, live browser camera stream, stored portrait, or biometric authorization control.
8. Every sensitive body is reveal-on-demand, never prefetched, and returned only after server-side object/audience/subject/guardian/assurance checks. Opaque administration never becomes a body/title/source/provenance/commitment/search/count oracle. Anonymous and Designated Guests receive no memory object at all.
9. Every mutation follows `prepare -> render immutable server summary -> satisfy exact principal slots -> consume once -> render correlated result`. Editing, expiry, replay, resource/policy/privacy/guardian-generation drift, idempotency mismatch, subject substitution, or slot substitution invalidates the action.
10. Multi-principal actions use `all_named_distinct_principals`; each required slot is named `owner`, `subject_adult`, or `current_primary_guardian`, and distinctness is enforced by the server against one immutable prepared commitment. The browser cannot collapse or satisfy slots.
11. Operation results are complete and manifest-ordered. `partial` requires at least two targets with mixed terminal outcomes. `verified` requires every target to be freshly verified at the required strength. Unknown or unobserved physical state never appears as success.
12. Signed feature registration controls backend route, OpenAPI operation, prepared-action issuance, console navigation/direct URL, dynamic import, client chunk, display variant, Reachy intent/prompt, configuration, IPC/listener, and runtime dispatch. A disabled control or hidden navigation link is not absence.
13. Unknown schema major versions, enum members, discriminators, decision types, action names, plane IDs, result kinds, observation states, or display variants fail closed to a localized safe incompatibility surface and never mutate or render untrusted content.
14. Private payload responses use `Cache-Control: no-store`. No service worker, analytics SDK, error body telemetry, browser persistent private storage, IndexedDB, local/session storage, background push, reusable media URL, secret in query strings, or private history entry is permitted.
15. Global search is server-filtered and limited to safe navigation/configuration labels. It never searches transcripts, another subject's private memory, biometric/person candidates, camera media, document bodies, audit bodies, secrets, or hidden feature metadata.
16. The UI distinguishes `healthy/available`, `active`, `disabled`, `absent`, `degraded`, `stale`, `unknown`, `suspended/quarantined`, and `error-safe`; it never collapses these into a composite security score or optimistic device state.
17. Privacy Shield reports canonical authority revocation independently from downstream stop/clear acknowledgement and physical verification. The independent Reolink recorder, Home Assistant/manual controls, already-running media, completed writes, exported copies, and provider/VPN metadata remain separately truthful.
18. Privacy activation and other reductions are immediate governed local operations. Privacy off requires a server-prepared action bound to the current generation plus a fresh owner passkey and required local presence; voice-only deactivation is absent.
19. Reachy never speaks a PIN, recovery secret, private adult memory, camera detail, audit body, hidden approval, desktop content, or administrative diagnosis. Fixed safety and disclosure prompts have human-reviewed English, Hindi, and common Hinglish variants.
20. Shared displays accept only the closed signed `ui.display_projection.v1` variants and the separately signed Phase 4 teaching manifest. They have no owner API, expansion route, camera media, memory body, identity confidence, approval/budget/network/audit/recovery content, or action authority.
21. Designated Guest is distinct from anonymous/uncertain Guest. Anonymous Guest remains offline-only unless each exact Reachy-local STT, reasoning, and TTS disclosure is separately accepted for the current session/purpose. Designated Guest has only exact pending common-area light/media requests that require a fresh owner co-approval.
22. Camera playback uses a current owner session plus a single-clip, short-lived, same-origin capability. It exposes no credential, source URL, direct path, reusable token, autoplay, enumeration, or browser cache. Export separately warns that owner copies leave managed retention.
23. The Phase 3 owner alert path is a durable local inbox plus authenticated same-origin SSE with `Last-Event-ID` replay/deduplication. Browser Notifications exist only while an active paired page has permission. Closed/asleep pages create local unread state, never an immediate-delivery claim.
24. The Phase 4 room-node UI always separates hardware mute, local wake listening, leased capture/network transmission, and indicator evidence. Purchased and DIY candidates use one bakeoff contract; an unevidenced endpoint is quarantined/absent.
25. Music Assistant is optional and absent unless its exact deployment, legal-provider, least-privilege, resource, backup, playback, reboot, WAN, and credential-revocation gates pass. Media controls use only closed handles/actions and truthful player observations.
26. The household televisions are the exact Samsung Neo LED 49-inch and TCL 42-inch units. Each begins `DISPLAY_ONLY_MANUAL`; no generic brand/model promise, control route, screen-time strength, or strict enforcement appears until exact physical adapter and observation evidence passes.
27. The Phase 4 guarded-child teaching UI renders the canonical wire value `web_mode=no_web` as a fixed, read-only policy fact. It exposes no enable-web/search control or API/prepared-action mutation and produces zero child search calls. Its end summary is RAM-only and expires within five minutes. It is not memory, audit content, progress history, or a durable learning profile. Any durable learning item is a separate proposal and guardian ceremony.
28. Corpus import, native picker, corpus administration, desktop grants/jobs/output, selected-frame perception administration/calibration views, and robot supervision are owner-only. The locked Phase 5 selected-frame runtime may still be invoked by its commissioned native-event broker or explicit owner calibration path; this grants no child, Guest, other-adult, or remote UI/control authority. For unauthorized actors and absent features, the picker/API/prepared action/route/chunk is absent rather than hidden.
29. Desktop execution-network authority and model-egress authority are separate. The UI shows exact roots/files/content/output commitments, provider/model, purpose, sensitivity, disclosure/policy, writes, limits, expiry, and rollback; neither grant implies the other.
30. Selected-frame CV displays the request-bound `area_id`, `zone_id` and generation, camera-binding generation, privacy generation, purpose, model artifact/digest, calibration digest, request/result times, cap, state/class/confidence, and reason codes. It explicitly labels the observation advisory and states that `count_band` is ignored for Phase 3 alerts and occupancy. No frame, thumbnail, caption, OCR, identity, demographic, handle, free prose, VLM, or cloud route is rendered.
31. Robot UI is owner-only supervised setup/health/safety, never a general joystick. Floor motion requires exact physical e-stop, directional sensor/geofence, local-supervisor, lease/watchdog, battery, indicator, and exact hardware evidence. Remote driving remains absent.
32. Phase 6 ships remote access disabled and Tailscale as the sole adapter. Remote UI mirrors the exact state machine and operation matrix; local-only recovery, export, identity, policy, plugin permission, desktop execution, and robot driving routes are absent from remote bundles and APIs.
33. The initial plugin registry is exactly `phase6.initial.1` with `system.health.render.v1` and `notification.local_alert.render.v1`. Plugin renderings are isolated, labelled third-party, closed plain text, optional beside authoritative core UI, and cannot suppress or mutate anything.
34. Accessibility is WCAG 2.2 AA: keyboard complete, VoiceOver meaningful, non-color state, visible focus, 44-by-44 CSS-pixel touch targets, reduced motion, 200% zoom and 320 CSS-pixel width without page-level two-dimensional scrolling. Light/dark, normal/high contrast, English/Hindi, and mixed-script fixtures are mandatory.
35. UI strings use stable message IDs and ICU parameters. English and Hindi convey equivalent safety meaning. Conversational Hinglish follows the speaker per turn; the management UI does not manufacture a third artificial Hinglish locale. Stable identifiers remain unchanged across languages.
36. No real household name, face, voice, transcript, memory, document, camera image, credential, address, device serial, network address, provider response, or private evidence enters source, fixtures, screenshots, traces, CI, docs, SBOM, or public artifacts. Synthetic fixtures use visibly fictional labels.
37. Ordinary UI tests use fake clocks, synthetic principals/devices/media/documents and no hardware, paid API, Keychain, Tailscale account, camera, TV, robot, or family data. Hardware/elapsed tests require explicit flags and write content-safe signed evidence under ignored `var/evidence/ui/`.
38. Each task follows red -> green -> affected suite -> lint/type/build -> accessibility/security where applicable -> exact-path review -> one independently reviewable commit. Implementers must observe the named red failure; a pre-existing green test means the test is inadequate.
39. Before any commit, `git status --short` must contain only the task-owned paths. Stage exact files, inspect `git diff --cached --name-only`, run `git diff --cached --check`, inspect `git diff --cached`, then commit. Never stage a broad dirty directory.
40. No paid UI runtime, hosted frontend, native app, app-store account, analytics platform, push service, or dedicated tablet is introduced. Open-source UI dependencies must pass the Phase 6 licence/SBOM gate.

## Frozen UI Contracts and Authority Boundaries

The implementation freezes and generates these exact public presentation contracts from the Python source-of-truth and JSON Schemas:

- `ui.household_posture.v1`
- `ui.plane_fact.v1`
- `ui.privacy_effect_status.v1`
- `ui.prepared_action.v1`
- `ui.subject_self_service.v1`
- `ui.guardian_exact_decision.v1`
- `ui.operation_result.v1`
- `ui.operation_target_result.v1`
- `ui.display_projection.v1`

`ui.prepared_action.v1.authorization_policy` is exactly `one_principal | all_named_distinct_principals`; roles are exactly `owner | subject_adult | current_primary_guardian`. `ui.subject_self_service.v1.operation` is exactly `consent_revoke | memory_reveal_one | memory_export_one | memory_delete_one | persona_replace | persona_clear`. Guardian decision types are exactly:

```text
child_consent
child_persona_replace
child_persona_clear
child_memory_proposal_approve
child_memory_proposal_edit_approve
child_memory_proposal_reject
child_memory_delete_one
child_home_rule_coapprove
child_room_voice_coapprove
child_media_teaching_coapprove
child_screen_time_coapprove
child_local_ai_route_coapprove
```

The two persona operations retain this closed-contract model: replace requires an exact profile/version and closed `context|tone|depth|learning_level` object; clear forbids a traits object. Adult self-service permits only the authenticated owner/adult's own profile. Guardian variants permit only a current-primary-guardian-bound K2/N1 profile and current guardian generation. No owner-to-other-adult operation exists, and clear remains available after personalization-consent revocation. This is folded into U01/U10 with no task or effort change and does not alter the four-surface set.

`ui.operation_result.v1.outcome` is exactly `verified | accepted_unverified | partial | denied | duplicate | failed | unknown | expired | cancelled`. Target kinds are exactly `light_v1 | player_v1 | television_v1 | display_v1 | clip_v1 | document_v1 | desktop_step_v1 | robot_v1`. Display projection variants are exactly `timer_status_v1 | media_status_v1 | teaching_session_v1 | family_safe_reminder_v1 | household_status_v1`.

`ui.plane_fact.v1.plane` is exactly `reachy_mic | reachy_identity_camera | room_mic | reolink_recorder | camera_outcomes | selected_frame_perception | cloud_egress | durable_memory | home_action_dispatch | home_assistant_independent | media_control | independent_media | display_projection | local_inference | desktop | robot | plugin | lan_admin | vpn_remote`. Fact states are exactly `healthy | active | disabled | absent | degraded | stale | unknown | suspended | quarantined | error_safe`; each fact carries its own evidence generation, source, strength, observation time, and validity rather than inheriting global freshness.

Cross-surface authorization code and fixtures use closed types `UISurface = owner | reachy | subject | display` and `UIOrigin = local | remote`. The only valid remote pairing is `surface=owner`, `origin=remote`, which maps to wire value `route_origin_class=owner_vpn`; `remote` is never accepted as a `UISurface`, and the other three surfaces retain only their local trust-zone origins.

The server performs authentication, object/audience filtering, body decryption eligibility, feature and origin authorization, resource/policy/privacy/guardian generation checks, action preparation, risk/assurance selection, slot distinctness, idempotency, dispatch, observation correlation, aggregate-result derivation, and audit emission. UI code may only validate the transport shape more restrictively and present it.

## Planned Repository Map

```text
packages/contracts/src/tuntun_contracts/ui.py
schemas/ui/v1/
packages/contracts/openapi/admin-v1.yaml
packages/contracts/openapi/subject-privacy-v1.yaml
packages/ui-contracts/
├── package.json
├── src/generated/ui-v1.ts
├── src/strict-decoders.ts
└── tests/{contracts,unknown-values}.test.ts
packages/design-system/
├── package.json
├── src/{tokens,theme,typography,icons,index}.ts
├── src/components/
└── tests/

apps/core/src/tuntun_core/api/ui/
├── projectors/
├── prepared_actions.py
├── operation_results.py
└── no_store.py
apps/core/src/tuntun_core/api/routes/{features,subject_privacy}.py

apps/admin/src/
├── app/{router,providers,feature-registry,shell,session-context}.tsx
├── api/{client,query-client,status-events,no-store,generated/}.ts
├── auth/
├── components/{prepared-action,principal-slots,operation-result,plane-fact}.tsx
├── features/{home,family,cameras,media-learning,ai-workspace,privacy,system}/
├── i18n/{catalog,en,hi}.ts
├── routes/
└── styles/

apps/subject-privacy/
├── package.json
├── src/{main,router,api-client,session}.tsx
├── src/api/generated/subject-privacy-v1.ts
├── src/features/{subject-consent,self-service,guardian-decision}.tsx
├── src/i18n/{en,hi}.ts
└── tests/

apps/edge/src/tuntun_edge/presentation/
├── presenter.py
├── cue_catalog.py
├── prompt_catalog.py
└── language_following.py

apps/display-agent/src-ui/
├── main.tsx
├── projection-validator.ts
├── expiry-supervisor.ts
├── neutral-screen.tsx
└── components/

fixtures/synthetic/ui/{contracts,principals,features,states,failures,locales}/
fixtures/adversarial/ui/
tests/{contract,integration,security,privacy,performance,ui,e2e}/ui/
scripts/ui/{generate_contracts,check_feature_absence,scan_browser_artifacts,capture_visuals,verify_budgets,verify_acceptance}.py
docs/operations/ui/{owner-console,subject-privacy,reachy-presenter,display-client,accessibility,incident}.md
```

Existing phase-owned paths remain canonical where their plans already create them, including `apps/admin/src/features/home/`, `apps/admin/src/features/cameras/`, `apps/admin/src/features/media-learning/`, `apps/admin/src/features/ai-workspace/`, `apps/admin/src/features/system/`, and `apps/display-agent/`. This plan adds shared UI foundations and completes cross-surface behavior; it does not create a parallel domain service, topology registry, identity engine, action lifecycle, privacy coordinator, alert store, screen-time engine, or feature registry.

## Delivery Sequence and Checkpoints

| Wave | Tasks | Promotion checkpoint |
|---|---|---|
| U0 contracts and foundations | U01–U05 | Strict contracts/codegen, synthetic fixtures, signed absence, design system, localization/a11y harness pass |
| U1 shared owner/ceremony mechanics | U06–U07 | Shell/auth, immutable prepared actions, multi-principal slots, and exact results pass |
| U2 Phase 1 surfaces | U08–U12 | Owner console, memory/identity, subject/guardian zone, Reachy/Guest, Privacy Shield, and P1 system UI pass |
| U3 Phase 2 surfaces | U13–U14 | Canonical areas, exact home results, routines, Designated Guest, and screen time pass |
| U4 Phase 3 surfaces | U15–U16 | Camera truth, inbox/SSE, playback/storage, anonymous presence and absence gates pass |
| U5 Phase 4 surfaces | U17–U19 | Room voice, media, signed display/teaching, exact TVs and real screen time pass physical gates |
| U6 Phase 5 surfaces | U20–U22 | Local AI/corpus, desktop/egress, advisory CV, and supervised robot boundaries pass |
| U7 Phase 6 surfaces | U23–U25 | Tailscale, exact plugins, recovery/update/release/incident surfaces pass |
| U8 whole-system assurance | U26–U28 | Security/no-store/negative reachability, accessibility/visual/performance, fault/maintenance/release evidence pass |

---

### Task U01: Freeze strict UI contracts and deterministic TypeScript code generation

**Depends on:** Accepted shared Phase 1 contract foundation.
**Checkpoint:** U0.
**Estimated effort:** 2 person-days.

**Files:**
- Modify: `packages/contracts/src/tuntun_contracts/ui.py`
- Create: `schemas/ui/v1/household-posture-v1.schema.json`
- Create: `schemas/ui/v1/plane-fact-v1.schema.json`
- Create: `schemas/ui/v1/privacy-effect-status-v1.schema.json`
- Create: `schemas/ui/v1/prepared-action-v1.schema.json`
- Create: `schemas/ui/v1/subject-self-service-v1.schema.json`
- Create: `schemas/ui/v1/guardian-exact-decision-v1.schema.json`
- Create: `schemas/ui/v1/operation-result-v1.schema.json`
- Create: `schemas/ui/v1/operation-target-result-v1.schema.json`
- Create: `schemas/ui/v1/display-projection-v1.schema.json`
- Modify: `packages/contracts/openapi/admin-v1.yaml`
- Create: `packages/contracts/openapi/subject-privacy-v1.yaml`
- Create: `packages/ui-contracts/package.json`
- Create: `packages/ui-contracts/src/generated/ui-v1.ts`
- Create: `packages/ui-contracts/src/strict-decoders.ts`
- Modify: `apps/admin/src/api/generated/admin-v1.ts`
- Create: `apps/subject-privacy/src/api/generated/subject-privacy-v1.ts`
- Create: `scripts/ui/generate_contracts.py`
- Test: `tests/contract/ui/test_ui_contracts.py`
- Test: `packages/ui-contracts/tests/contracts.test.ts`
- Test: `packages/ui-contracts/tests/unknown-values.test.ts`

**Interfaces:** Produces the nine frozen UI DTO families above, strict `additionalProperties: false` schemas, deterministic JSON Schema/OpenAPI/TypeScript artifacts, and decoders that return a safe incompatible result without rendering an unknown payload.

- [ ] **Step 1: Write the failing schema and decoder tests**

```python
def test_ui_contracts_are_closed_and_have_no_room_id(ui_schemas) -> None:
    assert all(schema["additionalProperties"] is False for schema in ui_schemas.values())
    text = canonical_json(ui_schemas)
    assert '"room_id"' not in text
    assert set(GuardianExactDecision.model_fields["decision_type"].annotation.__args__) == EXPECTED_GUARDIAN_TYPES
    assert set(SubjectSelfService.model_fields["operation"].annotation.__args__) == {
        "consent_revoke", "memory_reveal_one", "memory_export_one", "memory_delete_one", "persona_replace", "persona_clear"
    }

def test_persona_ui_variants_have_exact_conditional_shape(subject_operation_factory) -> None:
    subject_operation_factory(operation="persona_replace", profile_expected_version=3, persona_traits={"context":"general", "tone":"neutral", "depth":"standard", "learning_level":"none"})
    subject_operation_factory(operation="persona_clear", profile_expected_version=3, persona_traits=None)
    with pytest.raises(ValidationError):
        subject_operation_factory(operation="persona_clear", profile_expected_version=3, persona_traits={"context":"general", "tone":"neutral", "depth":"standard", "learning_level":"none"})

def test_subject_privacy_openapi_has_only_exact_persona_ceremonies(subject_privacy_openapi) -> None:
    expected = {
        "/api/v1/subject-privacy/self-service/persona/replace/prepare",
        "/api/v1/subject-privacy/self-service/persona/clear/prepare",
        "/api/v1/subject-privacy/self-service/{ceremony_id}/decide",
        "/api/v1/subject-privacy/guardian/persona/replace/prepare",
        "/api/v1/subject-privacy/guardian/persona/clear/prepare",
        "/api/v1/subject-privacy/guardian/{ceremony_id}/decide",
    }
    assert expected <= set(subject_privacy_openapi["paths"])

def test_operation_result_cannot_invent_verified(result_factory) -> None:
    with pytest.raises(ValidationError):
        result_factory(outcome="verified", target_results=[{"outcome": "unknown"}])
```

```ts
it.each(["new_plane", "new_decision", "html_card"])("fails closed for %s", (value) => {
  expect(() => decodeUiContract(adversarial(value))).toThrow(UnsupportedUiContractError);
});
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/ui/test_ui_contracts.py -q && pnpm --dir packages/ui-contracts exec vitest run`
Expected: FAIL because the UI schema module, generated package, and strict decoders do not exist.

- [ ] **Step 3: Implement and generate**

Define every field and exact enum from UI/UX Section 21. Add Pydantic validators for complete ordered target results, legal aggregate outcomes, one matching closed display payload, slot distinctness shape, per-fact expiry, and `area_id`-only location. Generate schemas and clients in byte-stable sorted order. Keep canonical entities out of public DTO modules.

- [ ] **Step 4: Run green and drift checks**

Run: `uv run python scripts/ui/generate_contracts.py --check && uv run pytest tests/contract/ui/test_ui_contracts.py -q && pnpm --dir packages/ui-contracts exec vitest run && pnpm --dir packages/ui-contracts exec tsc --noEmit && git diff --exit-code -- schemas/ui/v1 packages/ui-contracts/src/generated packages/contracts/openapi apps/admin/src/api/generated/admin-v1.ts apps/subject-privacy/src/api/generated/subject-privacy-v1.ts`
Expected: PASS; regeneration is empty, exact enums match, unknown values fail closed, and no generated artifact contains `room_id`.

- [ ] **Step 5: Commit checkpoint**

```bash
git add packages/contracts/src/tuntun_contracts/ui.py schemas/ui/v1 packages/contracts/openapi/admin-v1.yaml packages/contracts/openapi/subject-privacy-v1.yaml packages/ui-contracts apps/admin/src/api/generated/admin-v1.ts apps/subject-privacy/src/api/generated/subject-privacy-v1.ts scripts/ui/generate_contracts.py tests/contract/ui/test_ui_contracts.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(ui-contracts): freeze strict six-phase presentation schemas"
```

### Task U02: Build synthetic read models, principal matrices, and a contract-faithful UI fake

**Depends on:** U01.
**Checkpoint:** U0.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `fixtures/synthetic/ui/contracts/valid-contracts.jsonl`
- Create: `fixtures/synthetic/ui/principals/actor-matrix.yaml`
- Create: `fixtures/synthetic/ui/states/all-truth-states.json`
- Create: `fixtures/synthetic/ui/failures/all-failure-states.json`
- Create: `fixtures/synthetic/ui/features/all-feature-manifests.json`
- Create: `fixtures/synthetic/ui/features/absent-all.json`
- Create: `fixtures/synthetic/ui/features/phase1-only.json`
- Create: `fixtures/synthetic/ui/features/no-d4.json`
- Create: `fixtures/adversarial/ui/invalid-contracts.jsonl`
- Create: `packages/testing/src/tuntun_testing/ui_fake.py`
- Create: `apps/subject-privacy/package.json`
- Create: `apps/subject-privacy/tsconfig.json`
- Create: `apps/subject-privacy/vitest.config.ts`
- Create: `apps/admin/src/test/ui-server.ts`
- Create: `apps/subject-privacy/src/test/ceremony-server.ts`
- Create: `scripts/ui/validate_fixtures.py`
- Create: `scripts/ui/scan_browser_artifacts.py`
- Test: `tests/contract/ui/test_ui_fixtures.py`
- Test: `tests/privacy/ui/test_fixture_sentinel.py`

**Interfaces:** Produces deterministic fake clocks, opaque identifiers, eight actor/guardian/origin states, all truth/failure states, every exact guardian decision, every result kind/outcome, every display variant, and installed/absent feature manifests without real household data.

- [ ] **Step 1: Write failing completeness and privacy tests**

```python
def test_fixture_cross_product_is_complete(ui_fixture_index) -> None:
    assert ui_fixture_index.guardian_decisions == EXPECTED_GUARDIAN_TYPES
    assert ui_fixture_index.memory_views == {"body", "opaque", "no_object"}
    assert ui_fixture_index.locales >= {"en", "hi", "mixed_script"}

def test_fixture_tree_contains_no_private_sentinel(private_scanner) -> None:
    assert private_scanner.scan("fixtures/synthetic/ui").findings == []
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/ui/test_ui_fixtures.py tests/privacy/ui/test_fixture_sentinel.py -q`
Expected: FAIL because the fixture index and UI fake do not exist.

- [ ] **Step 3: Implement fixtures and fake servers**

Use visibly synthetic labels, monotonic fake time, deterministic SSE IDs, single-use capabilities, and explicit server outcomes. Include stale/unknown/error-safe/Privacy Shield, subject/guardian drift, duplicate submit, closed/asleep console, disk pressure, split recorder/camera, display disconnect, VPN drift, audit break, and every feature-absence fixture.

- [ ] **Step 4: Run green**

Run: `uv run python scripts/ui/validate_fixtures.py && uv run pytest tests/contract/ui/test_ui_fixtures.py tests/privacy/ui/test_fixture_sentinel.py -q && pnpm --filter @tuntun/admin exec vitest run src/test && pnpm --filter @tuntun/subject-privacy exec vitest run src/test`
Expected: PASS with complete deterministic fixture coverage and zero sentinel findings.

- [ ] **Step 5: Commit checkpoint**

```bash
git add fixtures/synthetic/ui fixtures/adversarial/ui packages/testing/src/tuntun_testing/ui_fake.py apps/subject-privacy/package.json apps/subject-privacy/tsconfig.json apps/subject-privacy/vitest.config.ts apps/admin/src/test/ui-server.ts apps/subject-privacy/src/test/ceremony-server.ts scripts/ui/validate_fixtures.py scripts/ui/scan_browser_artifacts.py tests/contract/ui/test_ui_fixtures.py tests/privacy/ui/test_fixture_sentinel.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(ui): add deterministic six-phase presentation fixtures"
```

### Task U03: Enforce signed feature-manifest registration and route/bundle absence

**Depends on:** U01–U02 and the existing shared feature registry.
**Checkpoint:** U0.
**Estimated effort:** 2 person-days.

**Files:**
- Modify: `apps/core/src/tuntun_core/services/features/registry.py`
- Modify: `apps/core/src/tuntun_core/api/routes/features.py`
- Modify: `apps/admin/src/app/feature-registry.ts`
- Modify: `apps/admin/src/app/router.tsx`
- Create: `apps/admin/src/app/lazy-feature.ts`
- Create: `scripts/ui/check_feature_absence.py`
- Test: `tests/contract/ui/test_feature_manifest.py`
- Test: `tests/security/ui/test_feature_absence.py`
- Test: `apps/admin/src/app/feature-registry.test.ts`
- Test: `tests/e2e/ui/feature-absence.spec.ts`

**Interfaces:** Consumes the signed feature manifest and registers only features whose backend, policy, migration, API, tests, and evidence digests match. Produces manifest-keyed dynamic imports and content-safe unavailable/not-found pages; no client-side entitlement override exists.

- [ ] **Step 1: Write failing negative-reachability tests**

```python
@pytest.mark.parametrize("surface", ["api", "openapi", "prepared_action", "config", "ipc"])
def test_absent_feature_has_no_reachability(absence_probe, surface) -> None:
    assert absence_probe.probe("phase5.desktop", surface).is_absent
```

```ts
it("does not register or import an absent feature", async () => {
  const registry = buildRegistry(signedManifest({"phase5.desktop": "absent"}));
  expect(registry.route("/ai-workspace/desktop")).toBeUndefined();
  expect(await emittedChunks()).not.toContainEqual(expect.stringContaining("desktop"));
});
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/ui/test_feature_manifest.py tests/security/ui/test_feature_absence.py -q && pnpm --filter @tuntun/admin exec vitest run src/app/feature-registry.test.ts`
Expected: FAIL because the existing registry does not yet prove the full server/OpenAPI/prepared-action/route/chunk absence chain.

- [ ] **Step 3: Implement fail-closed registration**

Verify manifest signature, candidate/build digest, policy/schema/migration generations, feature dependencies, evidence expiry, route origin, and exact loader ID before registration. Keep the production manifest minimal. Make each phase feature a literal dynamic import selected only after verified registration. Unknown/expired/mismatched entries remain absent.

- [ ] **Step 4: Run green and inspect production chunks**

Run: `uv run pytest tests/contract/ui/test_feature_manifest.py tests/security/ui/test_feature_absence.py -q && pnpm --filter @tuntun/admin exec vitest run src/app/feature-registry.test.ts && pnpm --filter @tuntun/admin exec vite build && uv run python scripts/ui/check_feature_absence.py --dist apps/admin/dist --manifest fixtures/synthetic/ui/features/absent-all.json && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/feature-absence.spec.ts`
Expected: PASS; absent features are absent from navigation, direct URL, API/OpenAPI, preparation, configuration, registration, and emitted chunks.

- [ ] **Step 5: Commit checkpoint**

```bash
git add apps/core/src/tuntun_core/services/features/registry.py apps/core/src/tuntun_core/api/routes/features.py apps/admin/src/app/feature-registry.ts apps/admin/src/app/router.tsx apps/admin/src/app/lazy-feature.ts scripts/ui/check_feature_absence.py tests/contract/ui/test_feature_manifest.py tests/security/ui/test_feature_absence.py apps/admin/src/app/feature-registry.test.ts tests/e2e/ui/feature-absence.spec.ts
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(ui): gate routes and bundles with the signed feature manifest"
```

### Task U04: Create the shared household design system and truthful state primitives

**Depends on:** U01–U02.
**Checkpoint:** U0.
**Estimated effort:** 2.5 person-days.

**Files:**
- Create: `packages/design-system/package.json`
- Create: `packages/design-system/src/tokens.ts`
- Create: `packages/design-system/src/tokens.css`
- Create: `packages/design-system/src/theme.tsx`
- Create: `packages/design-system/src/typography.ts`
- Create: `packages/design-system/src/icons.tsx`
- Create: `packages/design-system/src/components/button.tsx`
- Create: `packages/design-system/src/components/link.tsx`
- Create: `packages/design-system/src/components/state-fact.tsx`
- Create: `packages/design-system/src/components/plane-card.tsx`
- Create: `packages/design-system/src/components/attention-card.tsx`
- Create: `packages/design-system/src/components/responsive-table.tsx`
- Create: `packages/design-system/src/components/drawer.tsx`
- Create: `packages/design-system/src/components/dialog.tsx`
- Create: `packages/design-system/src/components/disclosure.tsx`
- Create: `packages/design-system/src/components/countdown.tsx`
- Create: `packages/design-system/src/components/safe-parameter-table.tsx`
- Create: `packages/design-system/src/components/live-region.tsx`
- Modify: `apps/admin/src/styles/tokens.css`
- Modify: `apps/admin/src/styles/global.css`
- Test: `packages/design-system/tests/components.test.tsx`
- Test: `tests/ui/design-system-accessibility.spec.ts`
- Test: `tests/ui/design-system-visual.spec.ts`

**Interfaces:** Produces warm household-appliance tokens and accessible primitives: shell landmarks, buttons, links, status facts, plane cards, stale badges, attention cards, tables/card alternatives, drawers, dialogs, disclosures, countdowns, progress, safe parameter rows, principal slots, operation results, toasts/live regions, and destructive confirmation. It owns no phase policy.

- [ ] **Step 1: Write failing semantic and accessibility tests**

```ts
it.each(TRUTH_STATES)("renders %s with text, icon, and non-color meaning", (state) => {
  const view = render(<StateFact state={state} messageId={`state.${state}`} />);
  expect(view.getByRole("status")).toHaveAccessibleName();
  expect(view.getByTestId("state-icon")).toBeVisible();
});

it("keeps destructive confirmation focus trapped and cancellable", async () => {
  const view = render(<PreparedActionDialog fixture="delete-one" />);
  expect(await axe(view.container)).toHaveNoViolations();
});
```

- [ ] **Step 2: Run red**

Run: `pnpm --dir packages/design-system exec vitest run && pnpm --filter @tuntun/admin exec playwright test tests/ui/design-system-accessibility.spec.ts`
Expected: FAIL because the shared package and primitives do not exist.

- [ ] **Step 3: Implement tokens and primitives**

Use system fonts with Devanagari coverage, 4px spacing, visible focus, 44px targets, reduced-motion media queries, non-color semantics, high contrast, and light/dark themes. Keep motion short and optional. Components accept already-authorized DTOs and stable message IDs only.

- [ ] **Step 4: Run green and visual review**

Run: `pnpm --dir packages/design-system exec vitest run && pnpm --dir packages/design-system exec tsc --noEmit && pnpm --filter @tuntun/admin exec playwright test tests/ui/design-system-accessibility.spec.ts tests/ui/design-system-visual.spec.ts`
Expected: PASS; axe reports zero serious/critical violations and reference images cover every truth state in both themes and contrast modes.

- [ ] **Step 5: Commit checkpoint**

```bash
git add packages/design-system apps/admin/src/styles/tokens.css apps/admin/src/styles/global.css tests/ui/design-system-accessibility.spec.ts tests/ui/design-system-visual.spec.ts
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(ui): add accessible household design system"
```

### Task U05: Add English/Hindi catalogs, mixed-script fixtures, and the accessibility harness

**Depends on:** U02 and U04.
**Checkpoint:** U0.
**Estimated effort:** 2 person-days.

**Files:**
- Create: `apps/admin/src/i18n/catalog.ts`
- Create: `apps/admin/src/i18n/en.ts`
- Create: `apps/admin/src/i18n/hi.ts`
- Create: `apps/subject-privacy/src/i18n/en.ts`
- Create: `apps/subject-privacy/src/i18n/hi.ts`
- Create: `fixtures/synthetic/ui/locales/mixed-script.json`
- Create: `scripts/ui/check_message_catalogs.py`
- Create: `tests/ui/accessibility-matrix.spec.ts`
- Create: `tests/ui/localization-matrix.spec.ts`
- Create: `docs/operations/ui/accessibility.md`

**Interfaces:** Produces stable ICU message IDs, equivalent safety/consequence strings in English and Hindi, locale persistence limited to non-sensitive preference, and a matrix runner for width/theme/contrast/motion/locale/zoom. Conversational Hinglish remains in the Reachy prompt catalogue, not a console locale.

- [ ] **Step 1: Write failing catalog-equivalence and layout tests**

```python
def test_catalogs_have_identical_ids_and_required_safety_review(catalogs) -> None:
    assert catalogs["en"].keys() == catalogs["hi"].keys()
    assert catalogs.unreviewed_safety_ids == set()
```

```ts
for (const locale of ["en", "hi", "mixed-script"]) {
  test(`${locale} has no clipping at 320px and 200%`, async ({ page }) => {
    await assertNoPageHorizontalOverflow(page, locale, { width: 320, zoom: 2 });
  });
}
```

- [ ] **Step 2: Run red**

Run: `uv run python scripts/ui/check_message_catalogs.py && pnpm --filter @tuntun/admin exec playwright test tests/ui/accessibility-matrix.spec.ts tests/ui/localization-matrix.spec.ts`
Expected: FAIL because catalogs, review metadata, and the matrix harness do not exist.

- [ ] **Step 3: Implement catalogs and matrix runner**

Define stable IDs for shell, truth states, every prepared action/consequence, every guardian decision, Privacy Shield, Guest disclosures, operation failures, display states, remote/plugin/recovery states, and safe incompatibility. Add punctuation/mixed-script fixtures without translating identifiers or exposing private parameters.

- [ ] **Step 4: Run green**

Run: `uv run python scripts/ui/check_message_catalogs.py && pnpm --filter @tuntun/admin exec playwright test tests/ui/accessibility-matrix.spec.ts tests/ui/localization-matrix.spec.ts && pnpm --filter @tuntun/admin exec lint && pnpm --filter @tuntun/admin exec tsc --noEmit`
Expected: PASS across English/Hindi, mixed-script, light/dark, normal/high contrast, reduced motion, narrow/wide, 200% zoom, and keyboard-only smoke paths.

- [ ] **Step 5: Commit checkpoint**

```bash
git add apps/admin/src/i18n apps/subject-privacy/src/i18n fixtures/synthetic/ui/locales scripts/ui/check_message_catalogs.py tests/ui/accessibility-matrix.spec.ts tests/ui/localization-matrix.spec.ts docs/operations/ui/accessibility.md
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(ui): add bilingual accessible presentation catalogs"
```

### Task U06: Build the owner shell, origin-aware authentication, and memory-only browser session

**Depends on:** U03–U05 and the existing Phase 1 API/session boundary.
**Checkpoint:** U1.
**Estimated effort:** 2.5 person-days.

**Files:**
- Modify: `apps/admin/src/app/router.tsx`
- Modify: `apps/admin/src/app/providers.tsx`
- Create: `apps/admin/src/app/shell.tsx`
- Create: `apps/admin/src/app/session-context.tsx`
- Modify: `apps/admin/src/api/client.ts`
- Modify: `apps/admin/src/api/query-client.ts`
- Create: `apps/admin/src/api/no-store.ts`
- Create: `apps/core/src/tuntun_core/api/ui/no_store.py`
- Modify: `apps/admin/src/routes/login.tsx`
- Create: `apps/admin/src/components/global-search.tsx`
- Test: `apps/admin/src/app/shell.test.tsx`
- Test: `tests/e2e/ui/shell-auth.spec.ts`
- Test: `tests/security/ui/test_admin_browser_boundary.py`

**Interfaces:** Renders wordmark/environment, route/breadcrumb, signed-manifest and stale information, session/origin class, attention, persistent Privacy Shield affordance, filtered global search, help, compact Phase 1 four-tab navigation, and manifest-backed eight-group navigation. Auth presents loopback proof, paired-LAN passkey, PIN/recovery distinctions, and Phase 6 VPN origin without treating a session as mutation authority.

- [ ] **Step 1: Write failing shell and browser-boundary tests**

```ts
it("shows four Phase 1 groups until an installed phase expands navigation", async () => {
  renderShell({ manifest: phase1OnlyManifest });
  expect(screen.getAllByRole("link", { name: /Home|Family|Privacy|System/ })).toHaveLength(4);
  expect(screen.queryByText("AI workspace")).not.toBeInTheDocument();
});

it("does not persist an authenticated or private query", async () => {
  await loginAndNavigate("/family/memory");
  expect(localStorage.length + sessionStorage.length).toBe(0);
});
```

- [ ] **Step 2: Run red**

Run: `pnpm --filter @tuntun/admin exec vitest run src/app/shell.test.tsx && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/shell-auth.spec.ts && uv run pytest tests/security/ui/test_admin_browser_boundary.py -q`
Expected: FAIL because the manifest-aware shell, origin presentation, safe search, and storage guard are incomplete.

- [ ] **Step 3: Implement shell and auth presentation**

Keep access proof/cookies memory-only or HttpOnly as designed; disable query persistence and prefetch for private routes. Enforce exact Host/Origin/CSRF handling in the server wrapper. Use one labelled recovery flow rather than a generic passkey modal. Developer mode uses a separate origin, data root, warning, and synthetic-only fixtures.

- [ ] **Step 4: Run green**

Run: `pnpm --filter @tuntun/admin exec vitest run src/app/shell.test.tsx && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/shell-auth.spec.ts && uv run pytest tests/security/ui/test_admin_browser_boundary.py -q && pnpm --filter @tuntun/admin exec lint && pnpm --filter @tuntun/admin exec tsc --noEmit && pnpm --filter @tuntun/admin exec vite build`
Expected: PASS; session/origin truth is visible, private state is not persisted, and absent navigation/chunks stay absent.

- [ ] **Step 5: Commit checkpoint**

```bash
git add apps/admin/src/app/router.tsx apps/admin/src/app/providers.tsx apps/admin/src/app/shell.tsx apps/admin/src/app/session-context.tsx apps/admin/src/api/client.ts apps/admin/src/api/query-client.ts apps/admin/src/api/no-store.ts apps/core/src/tuntun_core/api/ui/no_store.py apps/admin/src/routes/login.tsx apps/admin/src/components/global-search.tsx apps/admin/src/app/shell.test.tsx tests/e2e/ui/shell-auth.spec.ts tests/security/ui/test_admin_browser_boundary.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(admin): add origin-aware owner console shell"
```

### Task U07: Implement immutable prepared actions, distinct principal slots, and exact operation results

**Depends on:** U01, U04, U06 and the canonical action coordinator.
**Checkpoint:** U1.
**Estimated effort:** 3 person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/api/ui/prepared_actions.py`
- Create: `apps/core/src/tuntun_core/api/ui/operation_results.py`
- Create: `apps/admin/src/components/prepared-action.tsx`
- Create: `apps/admin/src/components/principal-slots.tsx`
- Create: `apps/admin/src/components/operation-result.tsx`
- Create: `apps/admin/src/components/target-result-list.tsx`
- Test: `tests/unit/api/ui/test_prepared_actions.py`
- Test: `tests/unit/api/ui/test_operation_results.py`
- Test: `apps/admin/src/components/prepared-action.test.tsx`
- Test: `tests/e2e/ui/prepared-actions.spec.ts`

**Interfaces:** Projects server-built safe parameter rows/consequences and opaque prepared IDs; renders `one_principal` or all named distinct slots; submits only opaque action/grant/idempotency identifiers; and renders complete manifest-ordered per-target outcomes from server-derived aggregates.

- [ ] **Step 1: Write failing binding, slot, replay, and aggregation tests**

```python
def test_same_subject_cannot_satisfy_distinct_owner_and_guardian_slots(coordinator) -> None:
    prepared = coordinator.prepare(screen_time_rule_fixture())
    coordinator.satisfy(prepared.id, slot="owner", subject="adult-a")
    with pytest.raises(DistinctPrincipalRequired):
        coordinator.satisfy(prepared.id, slot="current_primary_guardian", subject="adult-a")

def test_partial_requires_mixed_ordered_targets(projector) -> None:
    with pytest.raises(InvalidAggregateResult):
        projector.result("partial", [verified_light("a"), verified_light("b")])
```

```ts
it("never sends a browser-authored summary or policy binding", async () => {
  await submitPreparedAction(fixture);
  expect(lastRequestBody()).toEqual({ prepared_action_id: fixture.id, grant_id: "opaque", idempotency_key: fixture.idempotency_key });
});
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/api/ui/test_prepared_actions.py tests/unit/api/ui/test_operation_results.py -q && pnpm --filter @tuntun/admin exec vitest run src/components/prepared-action.test.tsx`
Expected: FAIL because the shared projectors/components and slot/aggregate invariants do not exist.

- [ ] **Step 3: Implement shared mechanics**

Reject changed parameters, stale generations, wrong slots, same-principal substitution, replay, double submit, late result, unknown result kind/schema/state, and target reordering. Announce pending/expired/revoked slots accessibly. Disable only the local submit while awaiting; do not invent completion or auto-retry a mutation.

- [ ] **Step 4: Run green**

Run: `uv run pytest tests/unit/api/ui/test_prepared_actions.py tests/unit/api/ui/test_operation_results.py -q && pnpm --filter @tuntun/admin exec vitest run src/components/prepared-action.test.tsx && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/prepared-actions.spec.ts`
Expected: PASS for refresh, back/forward, multi-tab, duplicate, expiry, policy/resource drift, privacy activation, distinct slots, complete target results, and late-result isolation.

- [ ] **Step 5: Commit checkpoint**

```bash
git add apps/core/src/tuntun_core/api/ui/prepared_actions.py apps/core/src/tuntun_core/api/ui/operation_results.py apps/admin/src/components/prepared-action.tsx apps/admin/src/components/principal-slots.tsx apps/admin/src/components/operation-result.tsx apps/admin/src/components/target-result-list.tsx tests/unit/api/ui/test_prepared_actions.py tests/unit/api/ui/test_operation_results.py apps/admin/src/components/prepared-action.test.tsx tests/e2e/ui/prepared-actions.spec.ts
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(ui): render immutable actions and correlated results"
```

### Task U08: Deliver Phase 1 Home posture, attention, safe activity, and explicit identity management

**Depends on:** U06–U07 and accepted Phase 1 projectors.
**Checkpoint:** U2.
**Estimated effort:** 3 person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/api/ui/projectors/household_posture.py`
- Create: `apps/core/src/tuntun_core/api/ui/projectors/identity.py`
- Modify: `apps/admin/src/routes/overview.tsx`
- Modify: `apps/admin/src/routes/people-identity.tsx`
- Create: `apps/admin/src/features/home/posture-ribbon.tsx`
- Create: `apps/admin/src/features/home/attention-inbox.tsx`
- Create: `apps/admin/src/features/home/safe-activity.tsx`
- Modify: `apps/admin/src/features/identity/index.ts`
- Test: `tests/privacy/ui/test_home_projection.py`
- Test: `tests/e2e/ui/home-identity.spec.ts`
- Test: `tests/security/ui/test_passive_identity_absent.py`

**Interfaces:** Projects separate microphone, Reachy identity-camera, cloud, recorder, remote, memory, and controller facts with evidence/freshness. Identity cards show profile class, permitted modalities, consent/calibration age, guardian relation, fallback, and active-ceremony quality words without confidence scores or passive discovery.

- [ ] **Step 1: Write failing minimization and passive-identity absence tests**

```python
def test_safe_activity_omits_private_fields(home_projection) -> None:
    assert forbidden_fields(home_projection.activity) == set()
    assert {"speech", "memory_body", "image", "biometric_score", "camera_url"}.isdisjoint(serialized_keys(home_projection))

def test_passive_identity_surfaces_do_not_exist(route_and_bundle_probe) -> None:
    for token in ("candidate-queue", "re-encounter", "unknown-person", "live-camera"):
        assert route_and_bundle_probe.absent(token)
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/privacy/ui/test_home_projection.py tests/security/ui/test_passive_identity_absent.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/home-identity.spec.ts`
Expected: FAIL because the complete posture/safe-activity projections and explicit absence assertions are missing.

- [ ] **Step 3: Implement truthful Home and identity flows**

Order attention by criticality and freshness; dismissal never changes the underlying state. Render `personalized`, `guest fallback`, `conflicting evidence`, `liveness failed`, `calibration required`, or `disabled`. Enrollment starts only from the local owner route and directs the participant to Reachy. Revoke/re-enroll/delete use exact prepared actions.

- [ ] **Step 4: Run green**

Run: `uv run pytest tests/privacy/ui/test_home_projection.py tests/security/ui/test_passive_identity_absent.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/home-identity.spec.ts && pnpm --filter @tuntun/admin exec vite build`
Expected: PASS; no composite score, private feed field, passive identity route, candidate chunk, or browser media surface exists.

- [ ] **Step 5: Commit checkpoint**

```bash
git add apps/core/src/tuntun_core/api/ui/projectors/household_posture.py apps/core/src/tuntun_core/api/ui/projectors/identity.py apps/admin/src/routes/overview.tsx apps/admin/src/routes/people-identity.tsx apps/admin/src/features/home/posture-ribbon.tsx apps/admin/src/features/home/attention-inbox.tsx apps/admin/src/features/home/safe-activity.tsx apps/admin/src/features/identity/index.ts tests/privacy/ui/test_home_projection.py tests/e2e/ui/home-identity.spec.ts tests/security/ui/test_passive_identity_absent.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(admin): add truthful posture and explicit identity management"
```

### Task U09: Enforce the memory body, opaque-administration, and no-object matrix

**Depends on:** U07–U08 and the Phase 1 canonical memory authorization service.
**Checkpoint:** U2.
**Estimated effort:** 3.5 person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/api/ui/projectors/memory.py`
- Modify: `apps/core/src/tuntun_core/api/routes/memories.py`
- Modify: `apps/admin/src/routes/memory.tsx`
- Modify: `apps/admin/src/features/memory/index.ts`
- Create: `apps/admin/src/features/memory/memory-list.tsx`
- Create: `apps/admin/src/features/memory/memory-detail.tsx`
- Create: `apps/admin/src/features/memory/opaque-administration.tsx`
- Test: `tests/security/ui/test_memory_projection_matrix.py`
- Test: `tests/security/ui/test_memory_oracles.py`
- Test: `tests/e2e/ui/memory-matrix.spec.ts`

**Interfaces:** Server-projects one of three disjoint shapes: authorized body, opaque administration, or no object. Seven kinds remain `working`, `episodic`, `semantic`, `preference`, `procedural`, `relational`, `policy`. Body-hidden projections expose only opaque ID, kind, lifecycle state, sensitivity band, created/review/expiry times, storage/count impact, and consent health.

- [ ] **Step 1: Write the failing actor/audience matrix**

```python
@pytest.mark.parametrize(("actor", "record", "shape"), [
    ("owner_self", "owner_private", "body"),
    ("adult_subject", "adult_private", "body"),
    ("owner_admin_other_adult", "adult_private", "opaque"),
    ("current_guardian", "guardian_child", "body"),
    ("stale_guardian", "guardian_child", "opaque"),
    ("other_adult", "adult_private", "no_object"),
    ("child", "guardian_child", "no_object"),
    ("anonymous_guest", "any", "no_object"),
    ("designated_guest", "any", "no_object"),
])
def test_memory_projection_shape(projector, actor, record, shape):
    assert projector.project(actor, record).shape == shape
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/security/ui/test_memory_projection_matrix.py tests/security/ui/test_memory_oracles.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/memory-matrix.spec.ts`
Expected: FAIL because filters, counts, search, detail, and export do not yet share one server-side body-visibility matrix.

- [ ] **Step 3: Implement matrix and UI**

Authorize before list, predicate, sort, count, decrypt, serialize, export, or approval. Omit hidden fields entirely; reject hidden predicates such as audience/title/source/provenance/commitment/precise sensitivity. Policy-memory bodies are owner-only. The owner cannot approve/edit another adult's private body; blind lifecycle actions use exact count/set commitment. Guests receive 404/empty non-oracle behavior per endpoint policy, never an opaque row.

- [ ] **Step 4: Run green and body-prefetch scan**

Run: `uv run pytest tests/security/ui/test_memory_projection_matrix.py tests/security/ui/test_memory_oracles.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/memory-matrix.spec.ts && uv run python scripts/ui/scan_browser_artifacts.py --scenario memory-matrix --forbid memory_body,title,source,commitment,ciphertext_size`
Expected: PASS across all actors/guardian generations; unauthorized bodies, derived lengths, filter/count oracles, prefetches, exports, and browser artifacts are absent.

- [ ] **Step 5: Commit checkpoint**

```bash
git add apps/core/src/tuntun_core/api/ui/projectors/memory.py apps/core/src/tuntun_core/api/routes/memories.py apps/admin/src/routes/memory.tsx apps/admin/src/features/memory tests/security/ui/test_memory_projection_matrix.py tests/security/ui/test_memory_oracles.py tests/e2e/ui/memory-matrix.spec.ts
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(memory-ui): enforce body opaque and no-object projections"
```

### Task U10: Build the isolated adult self-service and closed guardian decision zone

**Depends on:** U01–U07, U09 and canonical subject/guardian/passkey services.
**Checkpoint:** U2.
**Estimated effort:** 4 person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/api/routes/subject_privacy.py`
- Create: `apps/core/src/tuntun_core/api/ui/projectors/subject_privacy.py`
- Modify: `apps/subject-privacy/package.json`
- Create: `apps/subject-privacy/src/main.tsx`
- Create: `apps/subject-privacy/src/router.tsx`
- Create: `apps/subject-privacy/src/api-client.ts`
- Create: `apps/subject-privacy/src/session.ts`
- Create: `apps/subject-privacy/src/features/subject-consent.tsx`
- Create: `apps/subject-privacy/src/features/self-service.tsx`
- Create: `apps/subject-privacy/src/features/persona-editor.tsx`
- Create: `apps/subject-privacy/src/features/guardian-decision.tsx`
- Modify: `apps/subject-privacy/src/api/generated/subject-privacy-v1.ts`
- Test: `tests/security/ui/test_subject_privacy_zone.py`
- Test: `apps/subject-privacy/tests/self-service.test.tsx`
- Test: `apps/subject-privacy/tests/guardian-decisions.test.tsx`
- Test: `tests/e2e/ui/subject-privacy.spec.ts`

**Interfaces:** Local-only, no-owner-bearer zone. An adult exact `subject_consent` ceremony supports grant or refuse for the one prepared purpose/disclosure; self-service supports exact consent revoke, one own-memory reveal/export/delete, and one own-profile typed persona replace/clear without an operation invitation. Current primary guardian supports exact child consent/revoke and the twelve closed decision types, including child-safe persona replace/clear for only a current-generation K2/N1 relation. Persona replace requires current personalization consent and commits the exact profile/version plus closed `context|tone|depth|learning_level`; persona clear forbids traits and remains available after consent revocation. The owner has no path to act for another adult. Exact generated routes are `POST /api/v1/subject-privacy/self-service/persona/replace/prepare`, `POST /api/v1/subject-privacy/self-service/persona/clear/prepare`, `POST /api/v1/subject-privacy/self-service/{ceremony_id}/decide`, `POST /api/v1/subject-privacy/guardian/persona/replace/prepare`, `POST /api/v1/subject-privacy/guardian/persona/clear/prepare`, and `POST /api/v1/subject-privacy/guardian/{ceremony_id}/decide`. Sessions idle at five minutes, end absolutely at ten minutes, use `no-store`, persist nothing, and end on decision/expiry/cancel/generation/disclosure/privacy change. This addition is folded into U10's existing four person-days and does not change task or effort totals.

- [ ] **Step 1: Write failing closed-type, passkey-owner, and isolation tests**

```python
@pytest.mark.parametrize("decision_type", EXPECTED_GUARDIAN_TYPES)
def test_each_closed_guardian_decision_is_single_use(ceremony_client, decision_type) -> None:
    ceremony = ceremony_client.prepare(decision_type)
    assert ceremony_client.decide(ceremony, guardian_passkey()).status_code == 200
    assert ceremony_client.decide(ceremony, guardian_passkey()).status_code in {409, 410}

def test_unknown_or_substituted_guardian_decision_denies(ceremony_client) -> None:
    assert ceremony_client.prepare("approve_everything").status_code == 422
    assert ceremony_client.substitute(child="other-child", area_id="other-area", model="other-model").status_code in {409, 410}

def test_adult_subject_consent_uses_the_adult_passkey(ceremony_client) -> None:
    ceremony = ceremony_client.prepare_subject_consent(subject="adult-b", purpose="cloud_reasoning")
    assert ceremony_client.grant(ceremony, passkey_of="adult-a").status_code == 403
    assert ceremony_client.refuse(ceremony, passkey_of="adult-b").status_code == 200

@pytest.mark.parametrize("operation", ["persona_replace", "persona_clear"])
@pytest.mark.parametrize("outsider", ["adult-a", "owner"])
def test_adult_persona_operation_is_self_only_and_exact(ceremony_client, operation, outsider) -> None:
    ceremony = ceremony_client.prepare_subject_operation(operation, subject="adult-b", expected_version=4, traits=valid_adult_traits() if operation == "persona_replace" else None)
    assert ceremony_client.decide(ceremony, passkey_of=outsider).status_code == 403
    assert ceremony_client.decide(ceremony, passkey_of="adult-b").status_code == 200

@pytest.mark.parametrize("profile_class", ["k2", "n1"])
@pytest.mark.parametrize("decision_type", ["child_persona_replace", "child_persona_clear"])
def test_current_guardian_persona_decision_is_child_safe_and_generation_bound(ceremony_client, profile_class, decision_type) -> None:
    ceremony = ceremony_client.prepare_guardian_persona(decision_type, profile_class=profile_class, expected_version=2, traits=valid_child_traits(profile_class) if decision_type.endswith("replace") else None)
    assert ceremony_client.decide(ceremony.with_guardian_generation("stale"), passkey_of="current-guardian").status_code in {409, 410}
    fresh = ceremony_client.prepare_guardian_persona(decision_type, profile_class=profile_class, expected_version=2, traits=valid_child_traits(profile_class) if decision_type.endswith("replace") else None)
    assert ceremony_client.decide(fresh, passkey_of="current-guardian").status_code == 200

def test_persona_clear_remains_available_after_consent_revocation(ceremony_client, adult_with_revoked_personalization) -> None:
    ceremony = ceremony_client.prepare_subject_operation("persona_clear", subject=adult_with_revoked_personalization, expected_version=7, traits=None)
    assert ceremony_client.decide(ceremony, passkey_of=adult_with_revoked_personalization).status_code == 200

@pytest.mark.parametrize("substitution", ["target", "expected_version", "traits", "operation"])
def test_persona_binding_substitution_denies(ceremony_client, prepared_persona_replace, substitution) -> None:
    assert ceremony_client.substitute(prepared_persona_replace, field=substitution).status_code in {409, 410, 422}
```

```ts
it("has no owner-console navigation or imports", async () => {
  expect(await emittedImports("@tuntun/subject-privacy")).not.toContain("@tuntun/admin");
  expect(screen.queryByRole("link", { name: /owner console/i })).not.toBeInTheDocument();
});
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/security/ui/test_subject_privacy_zone.py -q && pnpm --filter @tuntun/subject-privacy exec vitest run && pnpm --filter @tuntun/subject-privacy exec playwright test tests/e2e/ui/subject-privacy.spec.ts`
Expected: FAIL because the isolated app, exact endpoints, full decision enum, and session destruction are missing.

- [ ] **Step 3: Implement ceremonies**

The invitation contains only one subject, one exact operation/decision, immutable server summary/commitment, current resource/policy/guardian/disclosure generations, expiry, and one-use commitment. Adult subjects use their own subject passkey to grant or refuse only the prepared `subject_consent`. Persona prepare routes accept only the generated replace/clear union, reconstruct the foundation `ProfileActionDraft(action_name="profile.edit")`, and start the corresponding action-bound passkey ceremony; the decide route consumes the exact single-use grant and calls canonical `ProfileService.update_persona_traits`. Adult authority is self-only. Guardian passkey ownership and current relation/generation are rechecked at both prepare and decision time, and child traits pass the K2/N1-safe validator. Replace calls the current personalization-consent check; clear deliberately skips that check while retaining all identity, profile-version, capability, and guardian-authority checks. Consent and exact approval remain separate records. No batch approval/delete, guardian change, audience broaden, owner cross-adult edit, policy/routine/purchase/device enrollment, or substitution path exists. Revocation requires no owner invitation and increments consent generation synchronously.

- [ ] **Step 4: Run green and forbidden-route scan**

Run: `uv run pytest tests/security/ui/test_subject_privacy_zone.py -q && pnpm --filter @tuntun/subject-privacy exec vitest run && pnpm --filter @tuntun/subject-privacy exec tsc --noEmit && pnpm --filter @tuntun/subject-privacy exec vite build && pnpm --filter @tuntun/subject-privacy exec playwright test tests/e2e/ui/subject-privacy.spec.ts && uv run python scripts/ui/check_feature_absence.py --dist apps/subject-privacy/dist --forbid owner,camera,device,policy,audit,backup,provider,remote,desktop,robot`
Expected: PASS for adult revocation without invitation, one-memory operations, adult-self persona replace/clear, all twelve guardian types including K2/N1 child-safe persona replace/clear, clear after personalization-consent revocation, current-generation enforcement, cross-adult/substitution denial, and zero owner/unrelated routes or chunks.

- [ ] **Step 5: Commit checkpoint**

```bash
git add apps/core/src/tuntun_core/api/routes/subject_privacy.py apps/core/src/tuntun_core/api/ui/projectors/subject_privacy.py apps/subject-privacy tests/security/ui/test_subject_privacy_zone.py tests/e2e/ui/subject-privacy.spec.ts packages/contracts/openapi/subject-privacy-v1.yaml apps/subject-privacy/src/api/generated/subject-privacy-v1.ts
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(subject-ui): add isolated self-service and guardian ceremonies"
```

### Task U11: Implement the Reachy family presenter and three-purpose Anonymous Guest disclosure

**Depends on:** U01–U05 and the accepted Phase 1/4 edge protocol.
**Checkpoint:** U2.
**Estimated effort:** 3 person-days.

**Files:**
- Create: `apps/edge/src/tuntun_edge/presentation/presenter.py`
- Create: `apps/edge/src/tuntun_edge/presentation/cue_catalog.py`
- Create: `apps/edge/src/tuntun_edge/presentation/prompt_catalog.py`
- Create: `apps/edge/src/tuntun_edge/presentation/language_following.py`
- Modify: `apps/edge/src/tuntun_edge/runtime.py`
- Test: `tests/unit/edge/test_family_presenter.py`
- Test: `tests/unit/edge/test_language_following.py`
- Test: `tests/privacy/ui/test_guest_disclosure.py`
- Test: `tests/hardware/bench_reachy_presenter.py`

**Interfaces:** Maps signed bounded states to available audio/motion cues for wake/listen/think/speak/stopped/privacy/offline/error-safe and one-conversation busy. Presents STT, reasoning, and TTS Guest disclosures separately; exact bounded yes/no creates only a current-session/current-purpose receipt while that challenge is active.

- [ ] **Step 1: Write failing prompt, language, and non-authority tests**

```python
@pytest.mark.parametrize("purpose", ["cloud_stt", "cloud_reasoning", "cloud_tts"])
def test_guest_yes_is_only_current_purpose_receipt(presenter, purpose) -> None:
    receipt = presenter.answer_disclosure(purpose, "हाँ")
    assert receipt.purpose == purpose and receipt.session_id == presenter.session_id
    assert not receipt.has_any("identity", "memory", "action", "guardian_consent")

def test_language_switch_affects_next_prompt_without_changing_identifiers(tracker) -> None:
    tracker.observe("Can you explain this? अब हिंदी में बताओ")
    assert tracker.next_mode == "hi"
    assert tracker.area_id == "area-common-1"
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/edge/test_family_presenter.py tests/unit/edge/test_language_following.py tests/privacy/ui/test_guest_disclosure.py -q`
Expected: FAIL because the bounded presenter/catalogue and per-purpose Guest receipt flow do not exist.

- [ ] **Step 3: Implement presenter and disclosures**

Use only delivered-hardware-proved cues; do not assume a screen or LED. Preserve the last stable language for ambiguous short utterances and follow clear English/Hindi switches per turn. Silence, ambiguity, or no remains offline; stop/no revokes further egress. Guest web search is disabled. Receipts expire with the session and never authorize a follow-up, memory, identity, or action. Spoken assent never creates adult/guardian consent.

- [ ] **Step 4: Run green and owner-gated hardware presentation probe**

Run: `uv run pytest tests/unit/edge/test_family_presenter.py tests/unit/edge/test_language_following.py tests/privacy/ui/test_guest_disclosure.py -q && uv run python tests/hardware/bench_reachy_presenter.py --synthetic`
Expected: PASS; fixed prompts cover English/Hindi/Hinglish, unsafe spoken content is absent, one-conversation busy/stop/privacy paths are deterministic, and hardware evidence remains a separate owner-gated run.

- [ ] **Step 5: Commit checkpoint**

```bash
git add apps/edge/src/tuntun_edge/presentation apps/edge/src/tuntun_edge/runtime.py tests/unit/edge/test_family_presenter.py tests/unit/edge/test_language_following.py tests/privacy/ui/test_guest_disclosure.py tests/hardware/bench_reachy_presenter.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(reachy): add bilingual family presenter and guest disclosure"
```

### Task U12: Complete Phase 1 Privacy Shield, independent planes, approvals, AI/cost, access, audit, backup, and recovery UI

**Depends on:** U06–U11 and accepted Phase 1 services.
**Checkpoint:** U2.
**Estimated effort:** 4 person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/api/ui/projectors/privacy.py`
- Modify: `apps/admin/src/features/privacy/index.ts`
- Create: `apps/admin/src/features/privacy/plane-cards.tsx`
- Modify: `apps/admin/src/components/privacy-shield.tsx`
- Modify: `apps/admin/src/routes/approvals.tsx`
- Modify: `apps/admin/src/routes/ai-budget.tsx`
- Modify: `apps/admin/src/routes/reachy-offline.tsx`
- Modify: `apps/admin/src/routes/privacy-access.tsx`
- Modify: `apps/admin/src/routes/backups.tsx`
- Modify: `apps/admin/src/routes/audit.tsx`
- Test: `tests/privacy/ui/test_privacy_effect_registry.py`
- Test: `tests/e2e/ui/phase1-system.spec.ts`
- Test: `tests/performance/ui/test_privacy_feedback.py`

**Interfaces:** Registers exactly `p1.conversation_capture`, `p2.tuntun_home_dispatch`, `p3.camera_outcomes`, `p4.room_media_display`, `p5.private_ai_desktop_robot`, `p6.remote_plugin`, and `shared_display_projection`; projects each effect as `authority_revoked`, `stop_requested`, `acknowledged`, `physically_verified`, or `unverified`; and provides all independent plane cards from UI/UX Section 13.2.

- [ ] **Step 1: Write failing Privacy Shield and system-truth tests**

```python
def test_privacy_activation_does_not_claim_independent_recorder_stopped(ui_after_shield) -> None:
    assert ui_after_shield.shield.authority_state == "authority_revoked"
    assert ui_after_shield.fact("reolink_recorder").state in {"active", "unknown", "degraded"}
    assert ui_after_shield.effect("p3.camera_outcomes").state != "physically_verified"

def test_privacy_off_requires_current_generation_owner_passkey_and_presence(api) -> None:
    assert api.prepare_privacy_off(stale_generation()).status_code == 409
    assert api.execute_privacy_off(voice_only()).status_code == 403
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/privacy/ui/test_privacy_effect_registry.py tests/performance/ui/test_privacy_feedback.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase1-system.spec.ts`
Expected: FAIL because the complete effect/plane registry and truthful independent continuations are not yet projected together.

- [ ] **Step 3: Implement Phase 1 system surfaces**

Shield input feedback is immediate; `activating` lasts only until canonical revocation commits, then each effect follows its own deadline. Failure to commit shows `error-safe — shield authority unconfirmed`. Keep recorder, HA/manual controls, independent media, completed egress/writes, exports, and VPN-provider metadata separate. Complete approvals by category; integer-derived actual/reserved/projected S$ plus soft/hard caps and price/FX versions; Reachy/offline state; passkey/PIN/recovery/LAN sessions; 180-day content-minimized audit/chain; backup/restore status; exact no-store export previews. Hard-cap/restore/key/bind/deletion actions use their required step-up/local presence.

- [ ] **Step 4: Run green and latency test**

Run: `uv run pytest tests/privacy/ui/test_privacy_effect_registry.py tests/performance/ui/test_privacy_feedback.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase1-system.spec.ts && pnpm --filter @tuntun/admin exec vite build`
Expected: PASS; canonical shield authority and Reachy-local stop meet the Phase 1 P95 <=250 ms evidence gate, downstream uncertainty stays visible, and no voice-only privacy reduction exists.

- [ ] **Step 5: Commit checkpoint**

```bash
git add apps/core/src/tuntun_core/api/ui/projectors/privacy.py apps/admin/src/features/privacy apps/admin/src/components/privacy-shield.tsx apps/admin/src/routes/approvals.tsx apps/admin/src/routes/ai-budget.tsx apps/admin/src/routes/reachy-offline.tsx apps/admin/src/routes/privacy-access.tsx apps/admin/src/routes/backups.tsx apps/admin/src/routes/audit.tsx tests/privacy/ui/test_privacy_effect_registry.py tests/e2e/ui/phase1-system.spec.ts tests/performance/ui/test_privacy_feedback.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(admin): complete Phase 1 privacy and system surfaces"
```

### Task U13: Deliver canonical-area inventory, exact light/scene controls, and complete target results

**Depends on:** U03, U07, U12 and accepted Phase 2 Tasks 01–23.
**Checkpoint:** U3.
**Estimated effort:** 3 person-days.

**Files:**
- Modify: `apps/admin/src/features/home/index.ts`
- Modify: `apps/admin/src/features/home/inventory.tsx`
- Modify: `apps/admin/src/features/home/permissions.tsx`
- Modify: `apps/admin/src/features/home/health.tsx`
- Modify: `apps/admin/src/features/home/lights-scenes.tsx`
- Modify: `apps/admin/src/routes/home-inventory.tsx`
- Modify: `apps/admin/src/routes/home-lights.tsx`
- Create: `tests/e2e/ui/phase2-areas-lights.spec.ts`
- Create: `tests/contract/ui/test_phase2_location_projection.py`
- Create: `tests/security/ui/test_phase2_results.py`

**Interfaces:** Projects versioned `area_id` inventory, controller/capability/firmware/freshness/manual-fallback/privacy/segmentation evidence, immutable scene manifests, and exact `light_v1` target results. Area CAS changes invalidate prepared actions; no `room_id` is accepted or emitted.

- [ ] **Step 1: Write failing canonical-location and no-optimism tests**

```python
def test_phase2_ui_schema_has_area_only(phase2_ui_schema) -> None:
    assert "area_id" in canonical_json(phase2_ui_schema)
    assert "room_id" not in canonical_json(phase2_ui_schema)

def test_scene_result_has_every_manifest_target_in_order(projector) -> None:
    result = projector(scene_with_three_targets(), observations_for_two())
    assert [row.target_id for row in result.target_results] == ["l1", "l2", "l3"]
    assert result.outcome != "verified"
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/contract/ui/test_phase2_location_projection.py tests/security/ui/test_phase2_results.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase2-areas-lights.spec.ts`
Expected: FAIL because canonical area enforcement and shared complete-result rendering are not wired through every Phase 2 page.

- [ ] **Step 3: Implement inventory and control presentation**

Render uncommissioned/unsupported/quarantined/unavailable distinctly. Show current observation and freshness before desired state; use `request sent` until a correlated result, timeout, or unknown. Scene preview names every affected endpoint and missing/stale binding. Do not claim isolation merely from the ASUS/AiMesh topology. All commands remain server-authorized and signed through the existing action lifecycle.

- [ ] **Step 4: Run green and absence scan**

Run: `uv run pytest tests/contract/ui/test_phase2_location_projection.py tests/security/ui/test_phase2_results.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase2-areas-lights.spec.ts && uv run python scripts/ui/check_feature_absence.py --feature phase2.home --manifest fixtures/synthetic/ui/features/phase1-only.json`
Expected: PASS; installed controls are truthful and the same route/API/prepared action/chunks are absent in Phase 1-only builds.

- [ ] **Step 5: Commit checkpoint**

```bash
git add apps/admin/src/features/home apps/admin/src/routes/home-inventory.tsx apps/admin/src/routes/home-lights.tsx tests/e2e/ui/phase2-areas-lights.spec.ts tests/contract/ui/test_phase2_location_projection.py tests/security/ui/test_phase2_results.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(admin): add canonical-area home controls"
```

### Task U14: Add routine governance, Designated Guest, and distinct-principal screen-time flows

**Depends on:** U10 and U13 plus accepted Phase 2 automation/screen-time services.
**Checkpoint:** U3.
**Estimated effort:** 4 person-days.

**Files:**
- Modify: `apps/admin/src/features/home/automations.tsx`
- Create: `apps/admin/src/features/home/designated-guest.tsx`
- Modify: `apps/admin/src/features/home/screen-time.tsx`
- Modify: `apps/admin/src/routes/home-automations.tsx`
- Create: `apps/admin/src/routes/home-designated-guest.tsx`
- Modify: `apps/admin/src/routes/home-screen-time.tsx`
- Create: `tests/e2e/ui/phase2-routines-guest.spec.ts`
- Create: `tests/e2e/ui/phase2-screen-time.spec.ts`
- Create: `tests/security/ui/test_designated_guest_boundary.py`
- Create: `tests/security/ui/test_screen_time_slots.py`

**Interfaces:** Renders Manual/Assisted/Learning governance, closed routine drafts/simulation/evidence/rollback; owner-created bounded Designated Guest common-area light/media request sessions; and screen-time allowance/session/evidence/warning/grace/extension/override/manual intervention/30-day history with owner plus distinct current-primary-guardian slots.

- [ ] **Step 1: Write failing Guest-separation and screen-time truth tests**

```python
def test_uncertain_identity_never_creates_designated_guest_session(api) -> None:
    assert api.resolve_identity("uncertain").guest_session is None
    assert api.create_designated_guest(actor="uncertain").status_code == 403

def test_unknown_tv_evidence_invents_no_allowance_or_enforcement(screen_time_ui) -> None:
    view = screen_time_ui(evidence="unknown")
    assert view.remaining_observed is None
    assert view.mode not in {"Cooperative", "Strict"}
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/security/ui/test_designated_guest_boundary.py tests/security/ui/test_screen_time_slots.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase2-routines-guest.spec.ts tests/e2e/ui/phase2-screen-time.spec.ts`
Expected: FAIL because Designated Guest and exact screen-time authority/evidence flows are incomplete.

- [ ] **Step 3: Implement the three flows**

Separate trigger/conditions/actions/quiet hours/eligibility/expiry/fallback. Designated Guest creation requires owner passkey and exact request class/`area_id`/targets/start/expiry; every request stays pending until a fresh owner passkey approves exactly that request. Expiry, cancellation, restrictive evidence, binding/policy drift, shield, or owner absence denies. It carries no identity, memory, camera, corpus, desktop, robot, routine, policy, or console access. Screen-time configuration and guardian co-approval are different immutable slots; same-principal substitution fails. A child may request an extension through Reachy but never approve it.

- [ ] **Step 4: Run green**

Run: `uv run pytest tests/security/ui/test_designated_guest_boundary.py tests/security/ui/test_screen_time_slots.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase2-routines-guest.spec.ts tests/e2e/ui/phase2-screen-time.spec.ts`
Expected: PASS for exact request/session expiry, no batch/voice approval, current guardian generation, 30-day minimized history, and evidence-qualified Advisory/Cooperative/Strict labels only.

- [ ] **Step 5: Commit checkpoint**

```bash
git add apps/admin/src/features/home/automations.tsx apps/admin/src/features/home/designated-guest.tsx apps/admin/src/features/home/screen-time.tsx apps/admin/src/routes/home-automations.tsx apps/admin/src/routes/home-designated-guest.tsx apps/admin/src/routes/home-screen-time.tsx tests/e2e/ui/phase2-routines-guest.spec.ts tests/e2e/ui/phase2-screen-time.spec.ts tests/security/ui/test_designated_guest_boundary.py tests/security/ui/test_screen_time_slots.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(admin): add governed routines guest requests and screen time"
```

### Task U15: Build owner-only camera health, exact playback, storage, retention, and NAS-decision UI

**Depends on:** U03, U07, U12 and accepted Phase 3 Tasks 01–24.
**Checkpoint:** U4.
**Estimated effort:** 4 person-days.

**Files:**
- Modify: `apps/admin/src/features/cameras/index.ts`
- Modify: `apps/admin/src/features/cameras/overview.tsx`
- Modify: `apps/admin/src/features/cameras/inventory.tsx`
- Modify: `apps/admin/src/features/cameras/recordings.tsx`
- Modify: `apps/admin/src/features/cameras/playback.tsx`
- Modify: `apps/admin/src/features/cameras/storage.tsx`
- Modify: `apps/admin/src/features/cameras/privacy-map.tsx`
- Modify: `apps/admin/src/routes/cameras-overview.tsx`
- Modify: `apps/admin/src/routes/cameras-inventory.tsx`
- Modify: `apps/admin/src/routes/cameras-recordings.tsx`
- Modify: `apps/admin/src/routes/cameras-storage.tsx`
- Modify: `apps/admin/src/routes/cameras-privacy.tsx`
- Create: `tests/e2e/ui/phase3-cameras-playback.spec.ts`
- Create: `tests/security/ui/test_camera_owner_boundary.py`
- Create: `tests/security/ui/test_playback_browser_capability.py`

**Interfaces:** Shows exact TrackMix hall/bedroom-pathway arc and two separate kitchen E1 sources, `area_id`/nested `zone_id`, audio-off, egress/P2P state, source/recorder split health, gaps, measured 7-day low-resolution/90-day event retention, storage pressure, copy disclosure, and evidence-driven `retain_external_ssd | open_hub_nvr_procurement | open_nas_vms_procurement` decision. Playback remains same-origin and single-clip.

- [ ] **Step 1: Write failing owner-only and media-capability tests**

```python
@pytest.mark.parametrize("actor", ["adult_partner", "child", "guest", "anonymous", "home_assistant"])
def test_non_owner_has_zero_camera_route(api, actor) -> None:
    assert api.as_actor(actor).get("/api/v1/cameras").status_code in {403, 404}

def test_playback_projection_has_no_credential_url_or_path(playback_dto) -> None:
    assert forbidden_fields(playback_dto) == set()
    assert playback_dto.capability.expires_in_seconds <= 60
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/security/ui/test_camera_owner_boundary.py tests/security/ui/test_playback_browser_capability.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase3-cameras-playback.spec.ts`
Expected: FAIL because complete owner/object isolation, clip-capability expiry, storage truth, and copy disclosures are not jointly tested.

- [ ] **Step 3: Implement camera/storage presentation**

No autoplay, direct RTSP/ONVIF/vendor URL, credential, filesystem path, reusable token, face/person search, identity label, or non-owner route. Byte ranges validate the same current clip capability. Export is a separate passkey action and explains that copied media leaves managed retention. Recorder pause/resume is separately labelled from `p3.camera_outcomes`; Privacy Shield does not imply recording stopped. NAS remains a measured decision, never an assumed purchase.

- [ ] **Step 4: Run green and browser artifact scan**

Run: `uv run pytest tests/security/ui/test_camera_owner_boundary.py tests/security/ui/test_playback_browser_capability.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase3-cameras-playback.spec.ts && uv run python scripts/ui/scan_browser_artifacts.py --scenario camera-playback --forbid rtsp,onvif,credential,direct_path,reusable_token`
Expected: PASS; exact sources/storage are truthful and every media capability expires/revokes without cache or cross-clip enumeration.

- [ ] **Step 5: Commit checkpoint**

```bash
git add apps/admin/src/features/cameras apps/admin/src/routes/cameras-overview.tsx apps/admin/src/routes/cameras-inventory.tsx apps/admin/src/routes/cameras-recordings.tsx apps/admin/src/routes/cameras-storage.tsx apps/admin/src/routes/cameras-privacy.tsx tests/e2e/ui/phase3-cameras-playback.spec.ts tests/security/ui/test_camera_owner_boundary.py tests/security/ui/test_playback_browser_capability.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(admin): add owner-only camera playback and storage truth"
```

### Task U16: Add the durable local alert inbox/SSE path and anonymous presence states

**Depends on:** U15 and accepted Phase 3 alert/presence services.
**Checkpoint:** U4.
**Estimated effort:** 3 person-days.

**Files:**
- Modify: `apps/admin/src/features/cameras/alerts.tsx`
- Modify: `apps/admin/src/features/cameras/use-owner-alert-stream.ts`
- Modify: `apps/admin/src/routes/cameras-alerts.tsx`
- Modify: `apps/admin/src/features/cameras/presence.tsx`
- Modify: `apps/admin/src/routes/cameras-presence.tsx`
- Modify: `apps/admin/src/api/status-events.ts`
- Create: `tests/e2e/ui/phase3-alerts-sse.spec.ts`
- Create: `tests/e2e/ui/phase3-presence.spec.ts`
- Create: `tests/security/ui/test_no_background_delivery_claim.py`
- Create: `tests/privacy/ui/test_presence_projection.py`

**Interfaces:** Durable local unread inbox with authenticated same-origin SSE, monotonic IDs, `Last-Event-ID`, bounded dedupe and five-second target only for an active paired page. Presence is only `occupied | vacant | unknown | stale | unavailable`, never named; absent evidence expires to unknown.

- [ ] **Step 1: Write failing reconnect and no-background-claim tests**

```ts
test("reconnects from last accepted event and suppresses duplicates", async ({ page }) => {
  await deliverEvents(page, [41, 42, 42]);
  await disconnectAndReconnect(page);
  expect(lastEventIdHeader()).toBe("42");
  expect(await visibleEventIds(page)).toEqual([41, 42]);
});
```

```python
def test_closed_page_reports_local_unread_not_immediate_delivery(alert_state) -> None:
    result = alert_state(page="closed", event="critical")
    assert result.local_unread is True
    assert result.immediate_delivery is False
    assert result.transport not in {"service_worker", "push", "sms", "email", "vendor_cloud"}
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/security/ui/test_no_background_delivery_claim.py tests/privacy/ui/test_presence_projection.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase3-alerts-sse.spec.ts tests/e2e/ui/phase3-presence.spec.ts`
Expected: FAIL because reconnect/dedup/delayed truth and closed presence-state handling are incomplete.

- [ ] **Step 3: Implement alert and presence presentation**

Browser Notifications require an active paired page and explicit permission; no service worker/background push. Show connected/delayed/stale truth and local unread count. Containment keeps mandatory local inbox/SSE/banner. Presence shows evidence source/freshness/expiry and no person/profile inference; unknown does not become vacant and never drives a named household timeline.

- [ ] **Step 4: Run green**

Run: `uv run pytest tests/security/ui/test_no_background_delivery_claim.py tests/privacy/ui/test_presence_projection.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase3-alerts-sse.spec.ts tests/e2e/ui/phase3-presence.spec.ts`
Expected: PASS for reconnect, duplicate, closed/asleep page, permission denial, containment, stale source, unknown expiry, and no identity leakage.

- [ ] **Step 5: Commit checkpoint**

```bash
git add apps/admin/src/features/cameras/alerts.tsx apps/admin/src/features/cameras/use-owner-alert-stream.ts apps/admin/src/routes/cameras-alerts.tsx apps/admin/src/features/cameras/presence.tsx apps/admin/src/routes/cameras-presence.tsx apps/admin/src/api/status-events.ts tests/e2e/ui/phase3-alerts-sse.spec.ts tests/e2e/ui/phase3-presence.spec.ts tests/security/ui/test_no_background_delivery_claim.py tests/privacy/ui/test_presence_projection.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(admin): add durable local alerts and anonymous presence"
```

### Task U17: Deliver room-node commissioning, one-conversation voice truth, and physical mute/indicator UI

**Depends on:** U03, U07, U11–U14 and accepted Phase 4 Tasks 01–16.
**Checkpoint:** U5.
**Estimated effort:** 4 person-days plus owner-gated bakeoff.

**Files:**
- Modify: `apps/admin/src/features/media-learning/index.ts`
- Modify: `apps/admin/src/features/media-learning/room-nodes.tsx`
- Modify: `apps/admin/src/features/media-learning/phase4-health.tsx`
- Modify: `apps/admin/src/routes/media-learning-rooms.tsx`
- Modify: `apps/admin/src/features/privacy/plane-cards.tsx`
- Create: `tests/e2e/ui/phase4-room-voice.spec.ts`
- Create: `tests/security/ui/test_phase4_area_only.py`
- Create: `tests/hardware/whole_home/test_room_endpoint_ui_evidence.py`

**Interfaces:** Shows purchased-vs-DIY candidate class through one common bakeoff result; exact endpoint/firmware/generation/`area_id`/privacy class; hardware mute, local wake, leased capture/transmission, indicator test, quiet hours, consent and revocation; one active conversation slot, winning endpoint/area, claim/lease/language/busy/handoff/cancel without audio or transcript.

- [ ] **Step 1: Write failing physical-truth and one-slot tests**

```python
def test_room_endpoint_ui_never_collapses_mic_planes(room_ui) -> None:
    assert room_ui.fields >= {"hardware_mute", "local_wake_listening", "leased_capture", "cloud_transmission", "indicator_evidence"}

def test_conversation_slots_is_exactly_one(config_and_ui) -> None:
    assert config_and_ui.prepare(slots=2).status_code == 422
    assert config_and_ui.active_slots == 1
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/security/ui/test_phase4_area_only.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase4-room-voice.spec.ts`
Expected: FAIL because physical mute/indicator evidence, shared bakeoff shape, and complete single-slot state are not exposed.

- [ ] **Step 3: Implement room voice presentation**

Purchased and DIY endpoints render identical required capability/latency/privacy/restore evidence. Hardware mute has a persistent local indication and remains authoritative offline; post-wake capture uses a distinct conspicuous state. Handoff is explicit, one target, 30-second token, new wake/identity/policy check, and no authentication/private-content transfer. Private child areas require exact guardian co-approval. Unproved endpoint/private-area routes stay absent.

- [ ] **Step 4: Run green and physical gate**

Run synthetic: `uv run pytest tests/security/ui/test_phase4_area_only.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase4-room-voice.spec.ts`
Owner-gated: `TUNTUN_HARDWARE=1 uv run pytest tests/hardware/whole_home/test_room_endpoint_ui_evidence.py -q --evidence-dir var/evidence/ui/phase4-room-bakeoff`
Expected: Synthetic PASS. Production registration requires signed evidence from the chosen exact common-area endpoint; failed candidates remain quarantined/absent.

- [ ] **Step 5: Commit checkpoint**

```bash
git add apps/admin/src/features/media-learning/index.ts apps/admin/src/features/media-learning/room-nodes.tsx apps/admin/src/features/media-learning/phase4-health.tsx apps/admin/src/routes/media-learning-rooms.tsx apps/admin/src/features/privacy/plane-cards.tsx tests/e2e/ui/phase4-room-voice.spec.ts tests/security/ui/test_phase4_area_only.py tests/hardware/whole_home/test_room_endpoint_ui_evidence.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(admin): add truthful room voice commissioning"
```

### Task U18: Add gated media/Music Assistant, exact televisions, and real screen-time truth

**Depends on:** U14, U17 and accepted Phase 4 Tasks 17–22 and 28–32.
**Checkpoint:** U5.
**Estimated effort:** 4 person-days plus exact-TV physical gates.

**Files:**
- Modify: `apps/admin/src/features/media-learning/media.tsx`
- Modify: `apps/admin/src/routes/media-learning-media.tsx`
- Modify: `apps/admin/src/features/media-learning/televisions.tsx`
- Modify: `apps/admin/src/routes/media-learning-televisions.tsx`
- Modify: `apps/admin/src/features/home/screen-time.tsx`
- Create: `tests/e2e/ui/phase4-media-tv.spec.ts`
- Create: `tests/security/ui/test_music_assistant_absence.py`
- Create: `tests/hardware/whole_home/test_exact_tv_ui_evidence.py`

**Interfaces:** Shows legal provider/entitlement/expiry, player binding/capabilities/freshness, absolute volume safety, child rule, immutable group members, queue summary, exact `player_v1` results, and separate independent media. Television rows bind the exact Samsung Neo LED 49-inch and TCL 42-inch units to model/OS/firmware/adapter generations, available/absent actions, native/CEC/IR evidence, observation strength, eligibility, manual bypass, attempts and last failure.

- [ ] **Step 1: Write failing gate and exact-unit tests**

```python
def test_music_assistant_missing_gate_is_route_and_bundle_absent(absence_probe) -> None:
    assert absence_probe.feature("music_assistant").all_surfaces_absent

@pytest.mark.parametrize("tv", ["samsung-neo-led-49-exact", "tcl-42-exact"])
def test_tv_starts_display_only_manual(tv_ui, tv) -> None:
    row = tv_ui(tv, evidence=None)
    assert row.capability == "DISPLAY_ONLY_MANUAL"
    assert row.enforcement_mode not in {"Cooperative", "Strict"}
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/security/ui/test_music_assistant_absence.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase4-media-tv.spec.ts`
Expected: FAIL because optional MA absence and exact-unit TV promotion evidence are not completely reflected in UI registration.

- [ ] **Step 3: Implement media and TV presentation**

No arbitrary URL/URI/path/service name, toggle, account switch, or dynamic all-speaker group. Starting/changing/transferring/high-delta/group actions require exact policy confirmation; player results remain verified/accepted-unverified/partial/failed/unknown. MA only registers after exact legal/deployment/least-privilege/resource/backup/playback/reboot/WAN/revocation evidence. Each TV independently promotes only proved operations and observation strength. Screen time reuses the Phase 2 state machine; unknown viewer/power/source means no invented consumption or enforcement and bounded attempts prevent hostile loops.

- [ ] **Step 4: Run green and exact physical gates**

Run synthetic: `uv run pytest tests/security/ui/test_music_assistant_absence.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase4-media-tv.spec.ts`
Owner-gated: `TUNTUN_HARDWARE=1 uv run pytest tests/hardware/whole_home/test_exact_tv_ui_evidence.py -q --tv samsung-neo-led-49-exact --tv tcl-42-exact --evidence-dir var/evidence/ui/phase4-tv`
Expected: Synthetic PASS. Each physical TV independently produces signed promotion/absence evidence; a failure cannot borrow the other TV's capability.

- [ ] **Step 5: Commit checkpoint**

```bash
git add apps/admin/src/features/media-learning/media.tsx apps/admin/src/routes/media-learning-media.tsx apps/admin/src/features/media-learning/televisions.tsx apps/admin/src/routes/media-learning-televisions.tsx apps/admin/src/features/home/screen-time.tsx tests/e2e/ui/phase4-media-tv.spec.ts tests/security/ui/test_music_assistant_absence.py tests/hardware/whole_home/test_exact_tv_ui_evidence.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(admin): add gated media exact TVs and screen-time truth"
```

### Task U19: Build guarded teaching setup and the signed closed shared-display client

**Depends on:** U01, U04–U05, U10, U14, U17 and accepted Phase 4 Tasks 23–27.
**Checkpoint:** U5.
**Estimated effort:** 4 person-days plus manual-HDMI evidence.

**Files:**
- Modify: `apps/admin/src/features/media-learning/teaching.tsx`
- Modify: `apps/admin/src/routes/media-learning-teaching.tsx`
- Modify: `apps/display-agent/src-ui/main.tsx`
- Create: `apps/display-agent/src-ui/projection-validator.ts`
- Modify: `apps/display-agent/src-ui/expiry-supervisor.tsx`
- Modify: `apps/display-agent/src-ui/neutral-screen.tsx`
- Create: `apps/display-agent/src-ui/components/timer.tsx`
- Create: `apps/display-agent/src-ui/components/media.tsx`
- Create: `apps/display-agent/src-ui/components/teaching.tsx`
- Create: `apps/display-agent/src-ui/components/reminder.tsx`
- Create: `apps/display-agent/src-ui/components/status.tsx`
- Create: `apps/display-agent/tests/projection-security.spec.tsx`
- Create: `tests/e2e/ui/phase4-teaching-display.spec.ts`
- Create: `tests/privacy/ui/test_ephemeral_learning_summary.py`
- Create: `tests/security/ui/test_child_teaching_no_web.py`
- Modify: `tests/hardware/whole_home/test_manual_hdmi_teaching.py`

**Interfaces:** Owner/guardian setup renders paired renderer/display, `area_id`, manifest/policy versions, audience/language, HDMI readiness, expiry, clear truth, manual-input instruction, and current screen-time binding. Display accepts only signed closed `ui.display_projection.v1` payloads and separately signed teaching manifests; content/cache clears on stop/privacy/identity downgrade/expiry/loss/screen-time end.

For every child session, setup also renders the canonical policy fact `web_mode=no_web` as fixed/read-only. There is no enable-web/search control, route, OpenAPI operation, prepared action, configuration field, client registration, or mutation endpoint; the child path makes zero search calls.

- [ ] **Step 1: Write failing closed-renderer and ephemeral-summary tests**

```ts
it.each(["<script>", "https://example.invalid", "file:///tmp/x", "data:text/html,x", "<svg onload=x>"])("rejects %s", (value) => {
  expect(() => validateProjection(maliciousProjection(value))).toThrow();
  expect(screen.getByTestId("neutral-screen")).toBeVisible();
});
```

```python
def test_learning_summary_is_ram_only_and_expires_within_five_minutes(summary_service, durable_stores) -> None:
    summary = summary_service.finish(teaching_session())
    assert summary.expires_at - summary.created_at <= timedelta(minutes=5)
    assert all(not store.contains(summary.id) for store in durable_stores)

def test_child_teaching_web_mode_is_fixed_no_web(teaching_ui_probe) -> None:
    result = teaching_ui_probe.open_child_setup()
    assert result.web_mode == "no_web"
    assert result.web_mode_read_only
    assert result.search_controls == []
    assert result.web_mode_mutation_operations == []
    assert result.outbound_search_calls == 0
```

- [ ] **Step 2: Run red**

Run: `pnpm --dir apps/display-agent exec vitest run tests/projection-security.spec.tsx && uv run pytest tests/privacy/ui/test_ephemeral_learning_summary.py tests/security/ui/test_child_teaching_no_web.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase4-teaching-display.spec.ts`
Expected: FAIL because the full projection dispatcher, hostile variants, RAM-only summary guarantee, and fixed no-web child path are missing.

- [ ] **Step 3: Implement closed display and teaching UI**

Validate signer, digest, display binding, audience, session, policy, expiry, projection kind, and exact payload before render. Render child `web_mode=no_web` from canonical policy as read-only text and do not implement a web-mode/search mutation or child search call. No HTML/CSS/JS/SVG script/URL/path/iframe/form/download/WebRTC/credential/private memory/camera/auth prompt. Idle reveals no exact profile; a child-safe name/avatar exists only inside an active guardian-approved session. Uncertain identity clears to neutral. A disconnected clear becomes unverified and never claims pixels are blank. Durable learning requires a separate proposal and guardian ceremony.

- [ ] **Step 4: Run green and physical HDMI gate**

Run synthetic: `pnpm --dir apps/display-agent exec vitest run && uv run pytest tests/privacy/ui/test_ephemeral_learning_summary.py tests/security/ui/test_child_teaching_no_web.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase4-teaching-display.spec.ts`
Owner-gated: `TUNTUN_HARDWARE=1 uv run pytest tests/hardware/whole_home/test_manual_hdmi_teaching.py -q --evidence-dir var/evidence/ui/phase4-display`
Expected: PASS; all five projection variants render safely, child web mode is fixed `no_web` with no control/mutation/search call, unknown/hostile payloads clear neutral, display clear target is <=1 second when connected, and manual HDMI truth is recorded.

- [ ] **Step 5: Commit checkpoint**

```bash
git add apps/admin/src/features/media-learning/teaching.tsx apps/admin/src/routes/media-learning-teaching.tsx apps/display-agent/src-ui apps/display-agent/tests/projection-security.spec.tsx tests/e2e/ui/phase4-teaching-display.spec.ts tests/privacy/ui/test_ephemeral_learning_summary.py tests/security/ui/test_child_teaching_no_web.py tests/hardware/whole_home/test_manual_hdmi_teaching.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(display): add signed closed teaching and household projections"
```

### Task U20: Add model-route and owner-only knowledge-corpus administration

**Depends on:** U03, U07, U12 and accepted Phase 5 Tasks 01–24.
**Checkpoint:** U6.
**Estimated effort:** 3.5 person-days.

**Files:**
- Modify: `apps/admin/src/features/ai-workspace/index.ts`
- Modify: `apps/admin/src/features/ai-workspace/models.tsx`
- Modify: `apps/admin/src/routes/ai-workspace-models.tsx`
- Modify: `apps/admin/src/features/ai-workspace/knowledge.tsx`
- Modify: `apps/admin/src/routes/ai-workspace-knowledge.tsx`
- Create: `tests/e2e/ui/phase5-models-corpus.spec.ts`
- Create: `tests/security/ui/test_corpus_owner_only.py`
- Create: `tests/privacy/ui/test_corpus_projection.py`

**Interfaces:** Shows per-task-cell route state, local/cloud eligibility, model/artifact/calibration/benchmark/resource/cost evidence, staged migration and rollback. Corpus UI exposes one owner-selected root, native picker/import quarantine, object/version/index/citation health, retention/deletion/backup reconciliation, bounded server-filtered titles, and exact `document_v1` results; it never treats canonical family memory as corpus storage.

- [ ] **Step 1: Write failing owner-only picker/route tests**

```python
@pytest.mark.parametrize("actor", ["adult_partner", "guardian", "child", "guest", "remote_owner_without_class"])
def test_non_owner_corpus_picker_and_api_are_absent(absence_probe, actor) -> None:
    assert absence_probe.as_actor(actor).all_absent("phase5.corpus_import")

def test_server_filters_document_titles_before_projection(corpus_projector) -> None:
    assert corpus_projector(actor="owner", object=private_doc()).title == "Restricted document"
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/security/ui/test_corpus_owner_only.py tests/privacy/ui/test_corpus_projection.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase5-models-corpus.spec.ts`
Expected: FAIL because owner-only picker/API/bundle absence and content-safe title projection are not fully enforced.

- [ ] **Step 3: Implement AI/corpus presentation**

Do not present a global `local AI` success switch: show task-cell state and evidence. Local/cloud changes use exact prepared actions and preserve privacy/budget policy. Native file selection never sends paths in URLs; import status/results are opaque and bounded. Deletion shows index/chunk/source/backup reconciliation and no resurrection. Non-owner UI/API/OpenAPI/preparation/chunks remain absent.

- [ ] **Step 4: Run green**

Run: `uv run pytest tests/security/ui/test_corpus_owner_only.py tests/privacy/ui/test_corpus_projection.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase5-models-corpus.spec.ts && uv run python scripts/ui/check_feature_absence.py --feature phase5.corpus_import --actors adult_partner,guardian,child,guest`
Expected: PASS; staged route truth and corpus lifecycle are owner-only, minimized, bounded, and independently removable.

- [ ] **Step 5: Commit checkpoint**

```bash
git add apps/admin/src/features/ai-workspace/index.ts apps/admin/src/features/ai-workspace/models.tsx apps/admin/src/routes/ai-workspace-models.tsx apps/admin/src/features/ai-workspace/knowledge.tsx apps/admin/src/routes/ai-workspace-knowledge.tsx tests/e2e/ui/phase5-models-corpus.spec.ts tests/security/ui/test_corpus_owner_only.py tests/privacy/ui/test_corpus_projection.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(admin): add owner-only model and corpus workspace"
```

### Task U21: Build owner-only desktop grants, exact diffs/jobs, and separate model-egress consent

**Depends on:** U07, U20 and accepted Phase 5 Tasks 25–33.
**Checkpoint:** U6.
**Estimated effort:** 4 person-days.

**Files:**
- Modify: `apps/admin/src/features/ai-workspace/desktop.tsx`
- Modify: `apps/admin/src/routes/ai-workspace-desktop.tsx`
- Create: `apps/admin/src/features/ai-workspace/desktop-grant.tsx`
- Create: `apps/admin/src/features/ai-workspace/desktop-egress.tsx`
- Create: `apps/admin/src/features/ai-workspace/desktop-job-result.tsx`
- Create: `tests/e2e/ui/phase5-desktop.spec.ts`
- Create: `tests/security/ui/test_desktop_owner_only.py`
- Create: `tests/security/ui/test_desktop_egress_separation.py`
- Create: `tests/privacy/ui/test_desktop_output_rendering.py`

**Interfaces:** Renders owner/device, exact root/repository commitments, D0–D4 level, include/exclude and quotas, command/workflow registry, execution network, writes, expiry/revocation, exact argv/cwd/effects/state digest, reviewed diff, limits, rollback/discard, and per-step `desktop_step_v1` results. A separate single-use egress ceremony shows exact selected content/output commitments, bytes/tokens, provider/account/model/version, purpose, sensitivity, disclosure, provider data policy, and <=15-minute expiry.

- [ ] **Step 1: Write failing authority-separation and hostile-output tests**

```python
def test_execution_network_never_authorizes_model_egress(desktop_api) -> None:
    grant = desktop_api.create_grant(execution_network="registry.example:443", model_egress="local_only")
    assert desktop_api.send_to_model(grant, cloud_model()).status_code == 403

def test_model_egress_never_authorizes_helper_network(desktop_api) -> None:
    egress = desktop_api.authorize_egress(exact_content(), cloud_model())
    assert desktop_api.run_job(egress, network="registry.example:443").status_code == 403
```

```ts
it("renders terminal escapes and prompt injection as inert bounded text", () => {
  render(<DesktopJobResult value={hostileOutputFixture} />);
  expect(document.querySelector("script, a[href], iframe")).toBeNull();
});
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/security/ui/test_desktop_owner_only.py tests/security/ui/test_desktop_egress_separation.py tests/privacy/ui/test_desktop_output_rendering.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase5-desktop.spec.ts`
Expected: FAIL because exact grant/egress separation, hostile-output rendering, and D3/D4 absence behavior are incomplete.

- [ ] **Step 3: Implement desktop presentation**

Owner-only native selection; forbidden secrets remain ungrantable. Read-only/local-only are defaults. D3 shows one pinned non-code inspection command; D4 shows the complete signed workflow and disposable-copy semantics. No shell string, auto-chain, live repository write/commit/push, remote helper, or broad terminal. Any edit/state drift invalidates confirmation. If no sandbox passes, D4 route/preparation/chunk is absent. Cancel/Shield revokes authority and late output cannot update a new job.

- [ ] **Step 4: Run green and negative-reachability checks**

Run: `uv run pytest tests/security/ui/test_desktop_owner_only.py tests/security/ui/test_desktop_egress_separation.py tests/privacy/ui/test_desktop_output_rendering.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase5-desktop.spec.ts && uv run python scripts/ui/check_feature_absence.py --feature phase5.desktop_d4 --manifest fixtures/synthetic/ui/features/no-d4.json`
Expected: PASS; non-owner/remote routes and absent D4 are unreachable, exact egress is single-use, and hostile output remains inert/minimized.

- [ ] **Step 5: Commit checkpoint**

```bash
git add apps/admin/src/features/ai-workspace/desktop.tsx apps/admin/src/features/ai-workspace/desktop-grant.tsx apps/admin/src/features/ai-workspace/desktop-egress.tsx apps/admin/src/features/ai-workspace/desktop-job-result.tsx apps/admin/src/routes/ai-workspace-desktop.tsx tests/e2e/ui/phase5-desktop.spec.ts tests/security/ui/test_desktop_owner_only.py tests/security/ui/test_desktop_egress_separation.py tests/privacy/ui/test_desktop_output_rendering.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(admin): add exact desktop grants jobs and egress consent"
```

### Task U22: Add generation-bound advisory CV and owner-supervised robot safety UI

**Depends on:** U15–U16, U20 and accepted Phase 5 selected-frame/robot tasks.
**Checkpoint:** U6.
**Estimated effort:** 4 person-days plus robot physical gate.

**Files:**
- Modify: `apps/admin/src/features/ai-workspace/perception.tsx`
- Modify: `apps/admin/src/routes/ai-workspace-perception.tsx`
- Create: `apps/admin/src/features/ai-workspace/robotics.tsx`
- Create: `apps/admin/src/routes/ai-workspace-robotics.tsx`
- Create: `tests/e2e/ui/phase5-perception-robot.spec.ts`
- Create: `tests/privacy/ui/test_cv_projection.py`
- Create: `tests/security/ui/test_cv_advisory_non_authority.py`
- Create: `tests/security/ui/test_robot_owner_local_only.py`
- Create: `tests/hardware/robot/test_robot_ui_safety_evidence.py`

**Interfaces:** CV shows exact request, `area_id`, `zone_id`/zone generation, camera-binding generation, privacy generation, purpose, artifact/digest/calibration, request/result times, 1–3 frame cap, state/class/confidence/reasons, and explicit advisory/non-authoritative status. Robot shows exact hardware/firmware, paired status, e-stop/motor-enable, directional sensors/freshness, geofence, allowed directions/speed, stop-distance margin, watchdog/lease, battery/thermal/camera indicator, local adult supervisor, and last safety latch.

- [ ] **Step 1: Write failing CV minimization/non-authority and robot-route tests**

```python
def test_cv_projection_is_bound_and_contains_no_media_or_identity(cv_ui) -> None:
    assert cv_ui.fields >= {"area_id", "zone_id", "zone_generation", "camera_binding_generation", "privacy_generation"}
    assert forbidden_fields(cv_ui) == set()
    assert cv_ui.advisory is True
    assert cv_ui.count_policy == "ignored_for_phase3_alerts_and_occupancy"

def test_cv_result_cannot_change_phase3_state(phase3, cv_result) -> None:
    before = phase3.snapshot()
    phase3.receive(cv_result.replace(count_band="multiple"))
    assert phase3.snapshot() == before
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/privacy/ui/test_cv_projection.py tests/security/ui/test_cv_advisory_non_authority.py tests/security/ui/test_robot_owner_local_only.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase5-perception-robot.spec.ts`
Expected: FAIL because exact generation display, count-ignore disclosure, forbidden media fields, and locally supervised robot route are incomplete.

- [ ] **Step 3: Implement CV and robot presentation**

CV administration and calibration views render no frame/thumbnail/raw handle/caption/OCR/name/face/demographic/clothing/emotion/health/free prose/VLM/cloud option. They do not block the locked commissioned native-event broker from invoking the Phase 5 runtime, but they grant no runtime-trigger authority to a child, Guest, other adult, or remote session. Denied/unknown/stale/malformed results clear transient content and never create a camera event, alert, presence assertion, action, or HA value. Robot is setup/health/session supervision, not a joystick. It has no autonomous child/pet claim or private-area route. Floor controls appear only after exact independent physical e-stop, allowed-direction obstacle/cliff path, 250ms lease, watchdog, local supervisor and common-area evidence; remote route remains absent.

- [ ] **Step 4: Run green and physical robot gate**

Run synthetic: `uv run pytest tests/privacy/ui/test_cv_projection.py tests/security/ui/test_cv_advisory_non_authority.py tests/security/ui/test_robot_owner_local_only.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase5-perception-robot.spec.ts`
Owner-gated: `TUNTUN_HARDWARE=1 uv run pytest tests/hardware/robot/test_robot_ui_safety_evidence.py -q --evidence-dir var/evidence/ui/phase5-robot`
Expected: Synthetic PASS. Physical failure keeps floor-motion UI/API/preparation/chunk absent while simulator and wheels-raised evidence remain available.

- [ ] **Step 5: Commit checkpoint**

```bash
git add apps/admin/src/features/ai-workspace/perception.tsx apps/admin/src/routes/ai-workspace-perception.tsx apps/admin/src/features/ai-workspace/robotics.tsx apps/admin/src/routes/ai-workspace-robotics.tsx tests/e2e/ui/phase5-perception-robot.spec.ts tests/privacy/ui/test_cv_projection.py tests/security/ui/test_cv_advisory_non_authority.py tests/security/ui/test_robot_owner_local_only.py tests/hardware/robot/test_robot_ui_safety_evidence.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(admin): add advisory CV and supervised robot safety UI"
```

### Task U23: Implement the Phase 6 Tailscale remote-access state and exact operation matrix

**Depends on:** U03, U06–U07, U12 and accepted Phase 1–5 gates plus Phase 6 remote services.
**Checkpoint:** U7.
**Estimated effort:** 4 person-days plus seven-day read-only soak.

**Files:**
- Create: `apps/admin/src/features/system/remote-access.tsx`
- Create: `apps/admin/src/routes/system-remote-access.tsx`
- Modify: `apps/admin/src/app/session-context.tsx`
- Create: `tests/e2e/ui/phase6-remote.spec.ts`
- Create: `tests/security/ui/test_remote_operation_matrix.py`
- Create: `tests/security/ui/test_remote_bundle_absence.py`
- Create: `tests/acceptance/ui/test_remote_read_only_soak.py`

**Interfaces:** Reuses the owner console as `surface=owner`, `origin=remote` (wire `route_origin_class=owner_vpn`); it does not register a remote surface. Presents exact `DISABLED -> COMMISSIONING -> READ_ONLY -> SCOPED_ACTIONS`, any-state `SUSPENDED`, approved node pseudonym, route/ACL/Tailnet Lock/app-passkey posture, idle/absolute expiry, assurance age, operation classes, last access, revoke/disable, and local-only limitations. Tailscale is the only named adapter; default install has no route.

- [ ] **Step 1: Write failing local/remote matrix and bundle tests**

```python
@pytest.mark.parametrize("operation", [
    "export", "identity_enroll", "guardian_change", "base_policy_change", "hard_cap_change",
    "plugin_permission", "recovery_import", "restore", "bulk_delete", "developer_mode",
    "desktop_execute", "robot_drive", "remote_shell",
])
def test_remote_denied_operation_is_absent_everywhere(remote_absence, operation) -> None:
    assert remote_absence.probe_all(operation) == "absent"

def test_vpn_membership_without_app_passkey_reveals_nothing(remote_client) -> None:
    assert remote_client(vpn=True, app_passkey=False).get("/api/v1/ui/posture").status_code in {401, 403}
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/security/ui/test_remote_operation_matrix.py tests/security/ui/test_remote_bundle_absence.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase6-remote.spec.ts`
Expected: FAIL because remote origin filtering and local-only chunk/API/preparation absence are not fully proved.

- [ ] **Step 3: Implement remote UI**

Default disabled; no direct WireGuard, relay, Funnel, subnet/exit route, public Serve, SSH, wildcard bind, or public tunnel option. First production class is read-only health/availability/minimized alerts/cost/approval metadata. Each optional private detail, reversible light/media stop, camera metadata, or single-clip playback class is separately local-enabled and freshness-gated. Playback uses <=10-minute remote media session plus <=60-second Phase 3 grants and `no-store`. Lost device/drift/auth failure suspends and revokes; local operation remains unchanged.

- [ ] **Step 4: Run green and soak gate**

Run synthetic: `uv run pytest tests/security/ui/test_remote_operation_matrix.py tests/security/ui/test_remote_bundle_absence.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase6-remote.spec.ts`
Owner-gated: `TUNTUN_ELAPSED=1 uv run pytest tests/acceptance/ui/test_remote_read_only_soak.py -q --duration 7d --evidence-dir var/evidence/ui/phase6-remote`
Expected: Synthetic PASS; read-only promotion requires the full seven-day route/theft/revoke/drift evidence and failed optional classes stay absent.

- [ ] **Step 5: Commit checkpoint**

```bash
git add apps/admin/src/features/system/remote-access.tsx apps/admin/src/routes/system-remote-access.tsx apps/admin/src/app/session-context.tsx tests/e2e/ui/phase6-remote.spec.ts tests/security/ui/test_remote_operation_matrix.py tests/security/ui/test_remote_bundle_absence.py tests/acceptance/ui/test_remote_read_only_soak.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(admin): add exact Tailscale remote-access UI"
```

### Task U24: Render the exact closed plugin registry without granting plugin authority

**Depends on:** U03–U07, U12 and accepted Phase 6 plugin supervisor.
**Checkpoint:** U7.
**Estimated effort:** 3 person-days.

**Files:**
- Create: `apps/admin/src/features/system/plugins.tsx`
- Create: `apps/admin/src/features/system/plugin-render-panel.tsx`
- Create: `apps/admin/src/routes/system-plugins.tsx`
- Create: `tests/e2e/ui/phase6-plugins.spec.ts`
- Create: `tests/security/ui/test_plugin_render_boundary.py`
- Create: `tests/security/ui/test_plugin_unknown_capability.py`

**Interfaces:** Shows publisher, signature/digest, SBOM/licence, exact requested/granted IDs, frozen platform policy, five-second/128MiB/50%-CPU/64KiB limits, no storage/network/DNS/redirect, grant generation, enable/disable/remove, last content-minimized outcome. Only `system.health.render.v1` and `notification.local_alert.render.v1` exist.

- [ ] **Step 1: Write failing closed-registry and core-alert independence tests**

```python
def test_unknown_plugin_capability_has_no_install_control(plugin_ui) -> None:
    view = plugin_ui(manifest_with("speech.capture.v1"))
    assert view.outcome == "denied_unknown_capability"
    assert view.prepared_action is None

def test_plugin_cannot_suppress_authoritative_alert(plugin_fault) -> None:
    view = plugin_fault("notification.local_alert.render.v1", result="timeout")
    assert view.core_alert.visible is True
    assert view.plugin_panel.state == "unavailable"
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/security/ui/test_plugin_render_boundary.py tests/security/ui/test_plugin_unknown_capability.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase6-plugins.spec.ts`
Expected: FAIL because the labelled isolated render panels and exact registry denial are missing.

- [ ] **Step 3: Implement plugin presentation**

Health rendering is explicit local-owner click; local alert rendering is optional beside mandatory core alert. Render plugin text as bounded plain text in a labelled isolated region; reject markup, URL, image, action, hidden/bidi content and unknown labels. Plugin cannot suppress, downgrade, acknowledge, close, forward, delay, or replace the core alert. Permission changes/install/remove are owner-local exact prepared actions; remote sessions, partners, guardians, children, Guests, plugins and maintainers cannot grant them.

- [ ] **Step 4: Run green**

Run: `uv run pytest tests/security/ui/test_plugin_render_boundary.py tests/security/ui/test_plugin_unknown_capability.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase6-plugins.spec.ts && uv run python scripts/ui/scan_browser_artifacts.py --scenario plugins --forbid markup,url,action,identifier,diagnostic_detail`
Expected: PASS for both exact capabilities, all malicious/unknown manifests/results, crash/timeout/revoke/remove, and mandatory alert independence.

- [ ] **Step 5: Commit checkpoint**

```bash
git add apps/admin/src/features/system/plugins.tsx apps/admin/src/features/system/plugin-render-panel.tsx apps/admin/src/routes/system-plugins.tsx tests/e2e/ui/phase6-plugins.spec.ts tests/security/ui/test_plugin_render_boundary.py tests/security/ui/test_plugin_unknown_capability.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(admin): add closed isolated plugin presentation"
```

### Task U25: Add recovery quarantine, incidents, updates, maintenance, and release-gate UI

**Depends on:** U12, U23–U24 and accepted Phase 6 recovery/release services.
**Checkpoint:** U7.
**Estimated effort:** 4 person-days.

**Files:**
- Create: `apps/admin/src/features/system/recovery.tsx`
- Create: `apps/admin/src/features/system/incidents.tsx`
- Create: `apps/admin/src/features/system/updates.tsx`
- Create: `apps/admin/src/features/system/maintenance.tsx`
- Create: `apps/admin/src/features/system/release.tsx`
- Create: `apps/admin/src/routes/system-recovery.tsx`
- Create: `apps/admin/src/routes/system-incidents.tsx`
- Create: `apps/admin/src/routes/system-updates.tsx`
- Create: `apps/admin/src/routes/system-maintenance.tsx`
- Create: `apps/admin/src/routes/system-release.tsx`
- Create: `tests/e2e/ui/phase6-recovery-release.spec.ts`
- Create: `tests/security/ui/test_recovery_local_owner_only.py`
- Create: `tests/security/ui/test_c0_c1_ui_bindings.py`

**Interfaces:** Shows backup tiers/age/verification/key availability/restore drill, exact `NORMAL | CONTAINED_REMOTE | CONTAINED_EGRESS | RECOVERY_QUARANTINE`, local critical-alert preservation, device retirement, signed update signer/digest/SBOM/compatibility/pre-backup/restart/rollback, weekly health and subsystem maintenance, and distinct P1 `P1R0/P1R1` versus whole-program `C0/C1` evidence/approvals.

- [ ] **Step 1: Write failing quarantine, containment, and gate-name tests**

```python
def test_restore_starts_with_every_action_surface_closed(recovery_ui) -> None:
    assert recovery_ui.state == "RECOVERY_QUARANTINE"
    assert recovery_ui.open_routes == {"local_read", "integrity_verify", "reconcile"}

def test_phase1_preview_gates_never_alias_whole_program_gates(release_ui) -> None:
    assert release_ui.gate("P1R0").id != release_ui.gate("C0").id
    assert release_ui.gate("P1R1").cannot_satisfy("C1")
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/security/ui/test_recovery_local_owner_only.py tests/security/ui/test_c0_c1_ui_bindings.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase6-recovery-release.spec.ts`
Expected: FAIL because quarantined route closure, incident truth, and distinct gate binding are not yet fully presented.

- [ ] **Step 3: Implement recovery/release presentation**

Recovery key display/import, restore, reconciliation exit, retirement, incident exit, update approval, C0 and C1 are separate owner-only local-presence prepared ceremonies. Portable recovery explicitly excludes provider/VPN/TLS/device/release-signing credentials and action routes reopen one phase at a time after new generations. `CONTAINED_EGRESS` keeps mandatory local critical alerts visible while external adapters stop. Updates never silently install or continue after signer/provenance/SBOM/compatibility/backup/health failure. C0 binds one immutable same-candidate Phase 1–6 evidence set; C1 is a second fresh approval; publication is a third manual action.

- [ ] **Step 4: Run green**

Run: `uv run pytest tests/security/ui/test_recovery_local_owner_only.py tests/security/ui/test_c0_c1_ui_bindings.py -q && pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui/phase6-recovery-release.spec.ts`
Expected: PASS for clean restore/no resurrection, containment enter/exit, failed update rollback, retired-device denial, C0/C1 invalidation on change, and local-only absence from remote UI/API/bundles.

- [ ] **Step 5: Commit checkpoint**

```bash
git add apps/admin/src/features/system/recovery.tsx apps/admin/src/features/system/incidents.tsx apps/admin/src/features/system/updates.tsx apps/admin/src/features/system/maintenance.tsx apps/admin/src/features/system/release.tsx apps/admin/src/routes/system-recovery.tsx apps/admin/src/routes/system-incidents.tsx apps/admin/src/routes/system-updates.tsx apps/admin/src/routes/system-maintenance.tsx apps/admin/src/routes/system-release.tsx tests/e2e/ui/phase6-recovery-release.spec.ts tests/security/ui/test_recovery_local_owner_only.py tests/security/ui/test_c0_c1_ui_bindings.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "feat(admin): add recovery incident update and release gates"
```

### Task U26: Prove cross-surface authorization, no-store, minimization, and negative reachability

**Depends on:** U01–U25.
**Checkpoint:** U8.
**Estimated effort:** 4 person-days.

**Files:**
- Create: `tests/security/ui/test_cross_surface_authorization.py`
- Create: `tests/security/ui/test_origin_host_csrf_replay.py`
- Create: `tests/security/ui/test_object_authorization_matrix.py`
- Create: `tests/security/ui/test_no_store_headers.py`
- Create: `tests/security/ui/test_negative_reachability_matrix.py`
- Create: `tests/privacy/ui/test_browser_artifact_scan.py`
- Modify: `scripts/ui/scan_browser_artifacts.py`
- Modify: `scripts/ui/check_feature_absence.py`
- Create: `docs/operations/ui/incident.md`

**Interfaces:** Whole-program matrix across the exact four-value surface type, actor, subject, guardian generation, audience, local/remote origin, assurance age, privacy generation, feature state, route, API/OpenAPI, prepared action, bundle, display, Reachy, IPC/listener, replay, and direct request. Remote owner access is an origin context of the owner surface, not another surface type.

- [ ] **Step 1: Write failing comprehensive probes**

```python
UISurface = Literal["owner", "reachy", "subject", "display"]
UIOrigin = Literal["local", "remote"]
SURFACE_ORIGIN_CASES: tuple[tuple[UISurface, UIOrigin], ...] = (
    ("owner", "local"),
    ("owner", "remote"),
    ("reachy", "local"),
    ("subject", "local"),
    ("display", "local"),
)

@pytest.mark.parametrize(("surface", "origin"), SURFACE_ORIGIN_CASES)
@pytest.mark.parametrize("actor", ACTOR_FIXTURES)
def test_surface_matrix_is_server_authorized(matrix_probe, surface, origin, actor) -> None:
    result = matrix_probe(surface=surface, origin=origin, actor=actor)
    assert result.actual_routes == result.expected_routes
    assert result.private_artifact_findings == []

def test_remote_is_an_owner_origin_never_a_fifth_surface(matrix_probe) -> None:
    assert "remote" not in get_args(UISurface)
    assert matrix_probe(surface="owner", origin="remote").route_origin_class == "owner_vpn"
    for surface in ("reachy", "subject", "display"):
        assert matrix_probe(surface=surface, origin="remote").is_absent

def test_private_responses_are_no_store(header_probe) -> None:
    for route in PRIVATE_ROUTES:
        assert header_probe(route)["cache-control"] == "no-store"
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/security/ui tests/privacy/ui/test_browser_artifact_scan.py -q`
Expected: FAIL on unimplemented cross-surface cases or missing artifact/absence probes; do not weaken expectations to obtain green.

- [ ] **Step 3: Close gaps without moving domain policy client-side**

Exercise CSRF, Host/Origin, rate, cursor, content type/size, object IDs, session theft/revocation, fresh assurance, duplicate/replay, stale generations, cross-child/area/target/model substitution, subject-zone owner-route access, display owner API access, Reachy admin content, remote local-only routes, absent feature config/registration/bundle/listener/runtime, and direct API calls. Scan caches, URLs/history, storage, service workers, logs, screenshots, traces, downloads, crash bundles, SSE buffers, display cache and evidence for forbidden content.

- [ ] **Step 4: Run green and production builds**

Run: `uv run pytest tests/security/ui tests/privacy/ui/test_browser_artifact_scan.py -q && pnpm --filter @tuntun/admin exec vite build && pnpm --filter @tuntun/subject-privacy exec vite build && pnpm --dir apps/display-agent exec vite build && uv run python scripts/ui/check_feature_absence.py --all-production-dist && uv run python scripts/ui/scan_browser_artifacts.py --all-surfaces`
Expected: PASS with zero unauthorized object/body, secret/private artifact, missing `no-store`, dormant route, absent-feature chunk, cross-surface import, or direct-request bypass.

- [ ] **Step 5: Commit checkpoint**

```bash
git add tests/security/ui tests/privacy/ui/test_browser_artifact_scan.py scripts/ui/scan_browser_artifacts.py scripts/ui/check_feature_absence.py docs/operations/ui/incident.md
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(ui): prove cross-surface privacy and negative reachability"
```

### Task U27: Prove accessibility, localization, visual states, and performance budgets

**Depends on:** U01–U26.
**Checkpoint:** U8.
**Estimated effort:** 4 person-days.

**Files:**
- Expand: `tests/ui/accessibility-matrix.spec.ts`
- Expand: `tests/ui/localization-matrix.spec.ts`
- Create: `tests/ui/visual-state-matrix.spec.ts`
- Create: `tests/ui/subject-accessibility.spec.ts`
- Create: `tests/ui/display-accessibility.spec.ts`
- Create: `tests/ui/voiceover-checklist.md`
- Create: `tests/ui/reference/ui-reference-manifest.json`
- Create: `tests/performance/ui/test_shell_budgets.py`
- Create: `tests/performance/ui/navigation.spec.ts`
- Create: `scripts/ui/capture_visuals.py`
- Create: `scripts/ui/verify_budgets.py`
- Create: `docs/operations/ui/owner-console.md`
- Create: `docs/operations/ui/subject-privacy.md`
- Create: `docs/operations/ui/reachy-presenter.md`
- Create: `docs/operations/ui/display-client.md`

**Interfaces:** Runs every installed owner and subject-zone route plus every display projection/default-loading-empty-error-stale-degraded-privacy-on-authorization state across supported widths/themes/locales/contrast/motion; keyboard and VoiceOver cover login/navigation/filter/detail/approval/Shield/destructive confirmation/playback/logout; Reachy fixed prompts/cues retain their separate human/hardware review; performance binds the 2020 Intel Mac household-load baseline.

- [ ] **Step 1: Write failing matrix completeness and budget tests**

```python
def test_visual_matrix_covers_every_registered_route_and_state(visual_index, feature_manifest) -> None:
    assert visual_index.routes == feature_manifest.installed_routes
    assert visual_index.states_per_route >= REQUIRED_VISUAL_STATES

def test_performance_budgets(measurements) -> None:
    assert measurements.localhost_shell_interactive_p95_ms <= 2_000
    assert measurements.cached_navigation_p95_ms <= 250
    assert measurements.fresh_api_view_p95_ms <= 1_000
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/performance/ui/test_shell_budgets.py -q && pnpm --filter @tuntun/admin exec playwright test tests/ui/accessibility-matrix.spec.ts tests/ui/localization-matrix.spec.ts tests/ui/visual-state-matrix.spec.ts tests/performance/ui/navigation.spec.ts && pnpm --filter @tuntun/subject-privacy exec playwright test tests/ui/subject-accessibility.spec.ts && pnpm --dir apps/display-agent exec playwright test tests/ui/display-accessibility.spec.ts`
Expected: FAIL with the exact missing route/state/matrix/budget evidence; do not update references until human visual review.

- [ ] **Step 3: Fix presentation-only accessibility/performance gaps**

Ensure landmarks, headings, live announcements, focus restoration/trap, table/card alternatives, countdown meaning, non-color states, 44px targets, reduced motion, 200%/320px layout, Devanagari glyphs/punctuation, and equivalent safety copy. Bound and paginate lists; visibility-aware polling uses validity windows/jitter/backoff and cannot compete with voice. Absent chunks stay excluded. Review screenshots for hierarchy/spacing/type/focus/truncation/contrast/motion/safe-summary legibility rather than snapshot equality alone.

- [ ] **Step 4: Run green on the Intel baseline**

Run: `uv run python scripts/ui/capture_visuals.py --all-matrix && uv run python scripts/ui/verify_budgets.py --target intel-2020 --household-load && uv run pytest tests/performance/ui/test_shell_budgets.py -q && pnpm --filter @tuntun/admin exec playwright test tests/ui tests/performance/ui/navigation.spec.ts && pnpm --filter @tuntun/subject-privacy exec playwright test tests/ui/subject-accessibility.spec.ts && pnpm --dir apps/display-agent exec playwright test tests/ui/display-accessibility.spec.ts`
Expected: PASS with reviewed visual evidence, zero serious/critical axe findings, completed keyboard/VoiceOver checklist, no clipped mixed-script fixture, and all three performance budgets met. Paired-LAN results are reported separately.

- [ ] **Step 5: Commit checkpoint**

```bash
git add tests/ui tests/performance/ui scripts/ui/capture_visuals.py scripts/ui/verify_budgets.py docs/operations/ui
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(ui): prove accessible localized and responsive performance"
```

### Task U28: Run fault campaigns, unified maintenance gate, and final UI acceptance

**Depends on:** U01–U27 and the exact accepted feature manifest/hardware set.
**Checkpoint:** U8 final.
**Estimated effort:** 3 person-days plus non-compressible soak and maintenance windows.

**Files:**
- Create: `tests/fault/ui/test_failure_matrix.py`
- Create: `tests/acceptance/ui/test_ui_acceptance.py`
- Create: `tests/acceptance/ui/test_full_system_maintenance.py`
- Create: `schemas/evidence/ui/ui-acceptance-v1.schema.json`
- Create: `schemas/evidence/ui/ui-maintenance-v1.schema.json`
- Create: `scripts/ui/verify_acceptance.py`
- Create: `docs/operations/ui/acceptance.md`

**Interfaces:** Produces signed content-safe `tuntun.ui.acceptance.v1` bound to one immutable commit/version/feature manifest, schemas/policies/migrations/builds, exact enabled hardware/firmware/config, commands/times/results, accessibility/visual/performance/security/fault/negative-reachability evidence, limitations, operator/reviewer, and expiry. Maintenance consumes the unified full-system Phase 1–6 owner-work record rather than a UI-only denominator.

- [ ] **Step 1: Write failing fault and evidence-verifier tests**

```python
@pytest.mark.parametrize("fault", [
    "api_restart", "database_key_unavailable", "cloud_outage", "home_assistant_outage",
    "camera_recorder_split", "disk_pressure", "display_disconnect", "vpn_drift",
    "plugin_timeout", "audit_chain_break", "update_rollback", "privacy_stop_timeout",
])
def test_fault_surfaces_remain_truthful_and_non_authorizing(fault_harness, fault) -> None:
    result = fault_harness.inject(fault)
    assert result.no_invented_success
    assert result.no_replayed_action
    assert result.safe_recovery_action_or_absence

def test_ui_acceptance_recomputes_not_trusts_pass_flag(verifier, forged_evidence) -> None:
    with pytest.raises(EvidenceRejected):
        verifier.verify(forged_evidence | {"pass": True})
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/fault/ui/test_failure_matrix.py tests/acceptance/ui/test_ui_acceptance.py tests/acceptance/ui/test_full_system_maintenance.py -q`
Expected: FAIL because the signed evidence schema/verifier and complete fault/maintenance bindings do not exist.

- [ ] **Step 3: Implement evidence recomputation and rollback rules**

The verifier rejects caller-authored pass flags, missing suites, expired evidence, mismatched candidate/feature/schema/policy/migration/build/hardware digests, unreviewed screenshots, absent negative-reachability rows, compressed elapsed gates, or private content. Any feature-specific failure removes that feature's manifest entry and proves absence; shared shell/auth/privacy/subject/display contract failure blocks UI promotion. Rollback preserves the prior accepted build and manifest; it never downgrades data without the phase-owned recovery path.

Ordinary owner-work logging by subsystem may begin after at least 60 steady-state days. Evaluate the rolling three-month median for promotion only after at least 90 steady-state days and three complete monthly buckets. The median for the complete Phase 1–6 system—not UI alone—must be <=8 hours/month. Include ordinary health, backup, certificate/key, storage, device, plugin, and update work. Record commissioning, quarterly restore/security/physical-safety drills, incidents, hardware replacement, unplanned repair, and major migrations separately; they cannot lower the ordinary metric. Three consecutive months over eight hours freeze optional expansion and require simplification or retirement review.

- [ ] **Step 4: Run final green gates from one clean candidate**

```bash
uv run pytest tests/contract/ui tests/security/ui tests/privacy/ui tests/fault/ui tests/acceptance/ui -q
pnpm --filter @tuntun/admin exec vitest run
pnpm --filter @tuntun/subject-privacy exec vitest run
pnpm --dir apps/display-agent exec vitest run
pnpm --filter @tuntun/admin exec playwright test tests/e2e/ui tests/ui tests/performance/ui/navigation.spec.ts
uv run ruff format --check apps packages tests scripts/ui
uv run ruff check apps packages tests scripts/ui
uv run mypy apps/core/src apps/edge/src packages/contracts/src packages/testing/src
pnpm --filter @tuntun/admin exec lint
pnpm --filter @tuntun/admin exec tsc --noEmit
pnpm --filter @tuntun/admin exec vite build
pnpm --filter @tuntun/subject-privacy exec vite build
pnpm --dir apps/display-agent exec vite build
uv run python scripts/ui/check_feature_absence.py --all-production-dist
uv run python scripts/ui/scan_browser_artifacts.py --all-surfaces
uv run python scripts/ui/verify_acceptance.py var/evidence/ui/acceptance --commit "$(git rev-parse HEAD)" --require-physical-gates --require-negative-reachability --require-full-system-maintenance
```

Expected: PASS against one unchanged candidate. Owner-gated hardware/elapsed rows must already be valid; synthetic output cannot substitute. All absent features are negatively unreachable and every enabled feature has current exact evidence.

- [ ] **Step 5: Commit final plan implementation checkpoint**

```bash
git add tests/fault/ui tests/acceptance/ui schemas/evidence/ui scripts/ui/verify_acceptance.py docs/operations/ui/acceptance.md
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(ui): freeze six-phase presentation acceptance evidence"
```

## Effort and Calendar Envelope

The task estimates total **92.5 focused person-days**, but this is a work-allocation ledger inside the owning Phase 1–6 estimates—not 92.5 additional days appended to the master roadmap. The phase execution plans already allocate owner API, console, ceremony, Reachy, display, feature-registration, evidence, security, and release work. During scheduling, replace or refine those UI line items with the tasks below; do not count both estimates.

| Allocation | Tasks | Focused effort | Owning schedule/checkpoint |
|---|---|---:|---|
| Shared contract/design foundation | U01–U05 | 10 days | Phase 1 foundation/control-console allocation; reused by all later phase UI |
| Shared shell/action mechanics | U06–U07 | 5.5 days | Phase 1 owner API/console allocation and U1 checkpoint |
| Phase 1 surfaces | U08–U12 | 17.5 days | Phase 1 control-console, identity/memory, Reachy, privacy, lifecycle and release allocations |
| Phase 2 surfaces | U13–U14 | 7 days | Phase 2 UI Tasks 13, 23, 27, 30 and owning acceptance work |
| Phase 3 surfaces | U15–U16 | 7 days | Phase 3 UI Tasks 22, 23, 24, 27, 29 and owning acceptance work |
| Phase 4 surfaces | U17–U19 | 12 days | Phase 4 UI Tasks 22, 25, 27, 32, 35 and owning acceptance work |
| Phase 5 surfaces | U20–U22 | 11.5 days | Phase 5 UI Tasks 13, 24, 28, 33, 36 and robot UI work |
| Phase 6 surfaces | U23–U25 | 11 days | Phase 6 remote/plugin/recovery/update/release UI and hardening allocation |
| Whole-system UI assurance | U26–U28 | 11 days | Distributed phase security/accessibility/evidence work plus Phase 6 C0/C1 preparation |
| **Total allocated UI effort** | **U01–U28** | **92.5 days** | **Already contained within the corresponding phase/program estimates** |

The U0–U8 checkpoints remain sequential for authority/schema stability, but task branches within an accepted checkpoint may run in parallel when they share no files or physical devices. This effort total is not a delivery promise and does not compress physical or elapsed acceptance gates.

Elapsed gates are tracked separately from hands-on UI effort:

- U17 consumes the exact purchased-vs-DIY common-area endpoint bakeoff and physical mute/indicator evidence.
- U18 independently qualifies the exact Samsung Neo LED 49-inch and TCL 42-inch televisions and any Music Assistant deployment; one unit or adapter cannot lend evidence to another.
- U19 consumes the paired renderer/manual-HDMI/display-clear physical gate.
- U22 consumes the Raspbot bench/e-stop/directional-safety/floor-motion gate; failure keeps floor control absent.
- U23 requires the non-compressible seven-day remote read-only soak before any scoped remote action promotion.
- The owning phase plans retain their camera, family, storage, media, robot, release, stress, and other elapsed campaigns. UI work may proceed against synthetic fixtures while production routes/chunks remain absent.
- U28 consumes, rather than restarts, the unified full-system maintenance record: logging may begin after 60 steady-state days, while promotion evaluation of the rolling three-month median requires at least 90 steady-state days and three complete monthly buckets. Quarterly drills, incidents, commissioning and hardware work stay separate.

Calendar reporting must show hands-on engineering, physical bakeoff time, unattended soak time, external prerequisites, and maintenance observation as different fields. A calendar estimate may overlap unattended elapsed gates with safe development, but it may never claim a promotion before the exact gate matures.

## Cross-Phase Acceptance Checklist

### Four surfaces and authority

- [ ] Owner console exposes only manifest-installed, origin-authorized, server-projected routes and never authors domain authority.
- [ ] Surface identity is exactly owner/Reachy/subject/display; Phase 6 remote access is `surface=owner`, `origin=remote`, never a fifth surface, and no remote origin exists for the other three trust zones.
- [ ] Reachy presents bounded cues and English/Hindi/Hinglish prompts, enforces one conversation, and speaks no administrative/private secret.
- [ ] The subject/guardian zone is local-only, no-store, no owner bearer/import/navigation, five-minute idle/ten-minute absolute, and one exact operation or decision.
- [ ] The display client accepts only signed closed projections, expires/clears safely, exposes no owner API, and cannot cause an action.

### Identity, memory, ceremonies, and Guest

- [ ] Explicit active/enrollment identity exists; passive candidate, unknown-person, re-encounter, stored portrait, and live browser camera surfaces are absent.
- [ ] Memory body/opaque/no-object behavior matches every matrix row before filter/count/search/decrypt/export; Guest receives no memory object.
- [ ] Adult self-revocation needs no owner invitation; one-memory reveal/export/delete and own-profile persona replace/clear are subject-bound and single-use; no owner cross-adult persona authority exists and clear remains available after personalization-consent revocation.
- [ ] All twelve exact guardian decision types pass, including current-generation K2/N1 child-safe persona replace/clear; unknown/batch/substituted child/profile version/traits/`area_id`/target/model/policy/generation fails closed.
- [ ] Anonymous Guest receives three separate current-session STT/reasoning/TTS disclosures; Designated Guest remains a distinct owner-created pending-request session.

### Phase features

- [ ] Phase 2 uses only `area_id`; light/scene/routine results are observed and complete, Designated Guest has no independent authority, and screen-time owner/guardian slots are distinct.
- [ ] Phase 3 camera routes are owner-only, playback is same-origin/single-clip/no-store, storage truth is measured, alerts use durable inbox/SSE, and anonymous presence never names a person.
- [ ] Phase 4 room endpoints separate physical mute/wake/capture/cloud/indicator facts; one conversation and explicit handoff hold; MA and exact TVs are evidence-gated.
- [ ] Phase 4 guarded-child teaching renders fixed/read-only `web_mode=no_web`, has no enable/search control or mutation and makes zero child search calls; its summary is RAM-only <=5 minutes; shared display payloads are signed/closed; Samsung Neo LED 49-inch and TCL 42-inch capabilities never borrow evidence from each other.
- [ ] Phase 5 corpus/picker/desktop, selected-frame administration/calibration, and robot routes are owner-only; the commissioned native-event broker can still invoke the constrained CV runtime; desktop execution network and model egress are separate; CV shows every bound generation and states advisory/count ignored; robot is locally supervised and not a remote joystick.
- [ ] Phase 6 remote starts disabled, uses Tailscale only, mirrors the exact operation matrix, registers exactly two closed plugin capabilities, and keeps recovery/update/release actions owner-local.

### Privacy, results, accessibility, and operations

- [ ] Privacy Shield reports canonical authority separately from acknowledgement/physical verification and shows independent recorder/HA/media/VPN truths.
- [ ] Every targeted result is complete and ordered; `partial` and `verified` are server-derived and physically truthful.
- [ ] Private routes and downloads are `no-store`; browser artifacts, storage, cache, URLs, history, logs, traces, screenshots, display cache and evidence contain no forbidden content.
- [ ] Every absent feature is absent from navigation, direct URL, API/OpenAPI, preparation, config, registration, bundle, IPC/listener and runtime.
- [ ] WCAG 2.2 AA, keyboard, VoiceOver, non-color, 44px targets, reduced motion, 200%/320px, light/dark/high-contrast and English/Hindi/mixed-script gates pass for every route/state.
- [ ] Localhost shell <=2s interactive, cached navigation p95 <=250ms and fresh local API p95 <=1s on the 2020 Intel Mac under household load.
- [ ] Fault campaigns never invent success or replay authority; rollback preserves the prior accepted candidate.
- [ ] After at least 90 steady-state days and three complete monthly buckets, full-system rolling three-month median maintenance is <=8 hours/month, or optional expansion freezes after three consecutive breaches.
- [ ] Final signed UI evidence binds one unchanged candidate and is eligible for the owning phase gates and whole-program C0; it never aliases P1R0/P1R1 with C0/C1.

## Implementation Handoff

Execute U01–U28 sequentially at the stated checkpoints. Work inside isolated task branches/worktrees, use the exact red tests before implementation, and stop at each checkpoint for spec/security/UX review. Hardware and elapsed gates are promotion gates, not ordinary development blockers: keep the gated feature absent while synthetic code and fixtures are reviewed, then register it only after exact signed physical/elapsed evidence passes. No implementation task may weaken server-side authorization, substitute UI hiding for absence, or use documentation as evidence of runtime behavior.
