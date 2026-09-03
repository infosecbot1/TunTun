# Reachy Canonical A0.5 Supervised Push-to-Talk Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a disposable, owner-supervised Reachy Mini push-to-talk loop that completes one bounded English, Hindi, or Hinglish turn without application-managed conversation retention.

**Architecture:** A robot-local Edge worker owns Reachy media and immediate cleanup. Core launches it through host-key-pinned SSH stdio and runs a one-turn in-memory STT-to-LLM-to-TTS coordinator. A shared strict framing codec is the only wire-format source of truth.

**Tech Stack:** Python 3.11/3.12, Pydantic v2 contracts, asyncio, Typer, OpenAI SDK after current official review, delivered `reachy_mini` SDK after probe, pytest/Hypothesis, Ruff, mypy

**Spec:** `docs/superpowers/specs/2026-08-31-reachy-a05-supervised-ptt-design.md`

**Canonical alignment:** This plan implements, rather than renames, Phase-1 checkpoint `A0.5` from
the anchor's delivered-Reachy probe/disposable-loop task and the conversation plan's hardware
stop/go gate. A simulator or media-only run is progress, not accepted A0.5.

## Global Constraints

- This is the canonical `A0.5` disposable supervised compatibility diagnostic; never label it completed POC, family beta, or Phase 1.
- A proved Reachy-local input may use hold/release. The terminal fallback is press-once-to-start,
  press-again-to-submit and never depends on key-up or macOS Accessibility permission. Cancel/stop
  preempts every stage.
- Default to fake providers; live cloud is absent until Checkpoint A0's durable route authorization, consent/privacy, budget, provider-review, and enforcing-project-limit gates pass.
- Use no wake word, child profile, identity, memory, camera workflow, web lookup, tool, home action, gesture, or durable conversation record.
- Add no Tuntun LAN listener; use fixed host-key-pinned SSH stdio and treat reconnect as a new turn.
- Keep owned audio, transcript, prompt, response, and provider bodies in RAM only and never log or print them.
- Enforce 4,096-byte control, 65,536-byte PCM-frame, 200-ms PCM-frame, 8,388,608-byte per-direction media, 90-second per-direction media, and 50-PCM-frame/rolling-second limits before allocation or provider I/O.
- Carry PCM as signed 16-bit little-endian, 16 kHz, mono; convert explicitly at each native media boundary.
- Give Core and Edge exactly one bounded outbound writer/sequence allocator each. Producers never
  assign wire sequences or write bytes; cleanup/ack has a reserved priority lane, one due heartbeat
  is coalesced, and normal drafts are FIFO/backpressured under a 64-item bound.
- Freeze 5-second session-ready, 2-second capture-open/close, 90-second capture, 30-second STT,
  45-second reasoning, 30-second TTS, 120-second aggregate provider, 90-second playback, and
  310-second complete-turn bounds. Core heartbeats every second and Edge cleans up after 5 seconds
  without a valid Core frame. On a valid stream, stop observations finish/time out by T+2 seconds,
  truthful receipt send finishes by T+2.5, and acknowledgement by T+3.5. Admission remains closed
  while Core supervisor/pipeline teardown finishes by T+4.0. A poisoned stream follows only Task
  2's terminal emergency rule and never waits for an acknowledgement. At the same cleanup T0, Core
  enqueues `abort` on the reserved priority lane and concurrently starts provider cancellation;
  provider-transport close is 0.5 seconds, provider join is 1 second, and Core supervisor/pipeline
  quarantine remains bounded by T0+4. SSH connect is 5 seconds and server-alive is 2 seconds/count
  2. The first synchronous transport close fixes a separate S0; stdin, TERM, and KILL/reap end at
  S0+1, S0+2, and S0+3 respectively, without renewing S0. An already-fenced transport may outlive
  T0+4 only while that S0 escalation completes; it cannot reopen admission or extend Core's cleanup
  bound.
- The mode matrix is exactly fake/simulated, fake/ssh, and—only after Checkpoint A0—live-cloud/
  simulated and live-cloud/ssh. No fallback changes mode or transport.
- Core remains Python `==3.12.*`; Edge and Contracts remain `>=3.11,<3.13` compatible.
- No production code is written before its focused test has failed for the expected missing behavior.

---

### Task 0: Delivered Reachy discovery and stop/go record

**Files:**
- Create: `apps/edge/src/tuntun_edge/diagnostics/capability.py`
- Create: `apps/core/src/tuntun_core/adapters/reachy/commissioning.py`
- Create: `scripts/reachy_a05_forced_dispatcher.py`
- Create: `tests/unit/edge/test_capability_report.py`
- Create: `tests/unit/poc/test_reachy_commissioning.py`
- Create: `tests/unit/poc/test_reachy_a05_dispatcher.py`
- Create: `tests/hardware/test_reachy_capability_probe.py`
- Create: `docs/evidence/reachy-a05-capability.schema.json`
- Create: `docs/evidence/reachy-a05-operator-state.schema.json`
- Create: `docs/evidence/reachy-a05-remote-state.schema.json`
- Create: `docs/operations/reachy-a05-discovery.md`

**Interfaces:**
- Consumes: the delivered Reachy daemon `/docs` and status endpoints, installed SDK metadata, exact on-robot interpreter, and physically supervised read-only observations.
- Produces: `ReachyCapabilityReportV1`,
  `CapabilityDecision(accepted|conditional_mac_key|rejected)`, a sanitized local
  `var/hardware/reachy-a05-capability.json`, private commissioning material under the login home's
  `.local/share/tuntun/reachy-a05/`, and the exact facts Tasks 2, 4, and 7 may use.

Limitation codes are exactly
`aec_unavailable|doa_unavailable|local_input_unavailable|rtc_unqualified`. Rejection reason codes
are exactly
`network_topology_failed|daemon_unavailable|sdk_daemon_mismatch|unsupported_interpreter|media_capture_failed|media_playback_failed|playback_stop_failed|motion_stop_unavailable|controller_detection_unavailable|controller_collision|unsafe_bind_surface|ssh_boundary_failed|resource_limit_failed|report_privacy_failed`.
`conditional_mac_key` requires every hard check to pass, requires
`local_input_unavailable` (one or both required Reachy-local capture/independent-stop inputs absent
or unqualified), permits only the four limitation codes, forces `core_terminal_toggle`, and blocks
wake/barge-in/Reachy-local-stop/unsupervised claims. `accepted` requires both proved local inputs.
Unknown or mixed-severity facts reject.

- [ ] **Step 1: Write failing strict report and private-state tests.** Require exact SDK/daemon/
  Python/ABI/dependency hashes, native input/output formats, microphone/speaker, one RAM-only camera
  capability observation, playback stop, movement enumeration/stop, app lock, unmanaged-controller
  detection, local input, AEC/DoA, bind surface, CPU/RAM/temperature, and the closed decision rules
  above. The private commissioning model binds schema version, commissioning UUID, monotonic state
  generation, closed `commissioned|staged|active|removed|revoked` status, maximum 24-hour freshness,
  Reachy boot identity, capability digest, numeric RFC1918 address, port 22, non-root principal and
  remote home, absolute key/known-host paths and commitments, dispatcher path/protocol/hash,
  authorized-key commitment, accepted interpreter/ABI/tags/SDK/daemon/runtime-inventory facts,
  fixed remote root, and optional staged/active content-addressed generations. Reject hostnames,
  IP/MAC, serials,
  SSH principals/keys, SSIDs, images, or PCM from the sanitized report.
- [ ] **Step 2: Run and confirm RED because the diagnostics model is absent, then implement the immutable bounded report and JSON-schema renderer.**
- [ ] **Step 3: Put the approved Mac and Reachy on the same ASUS/AiMesh L2 for the supervised probe.** Disconnect the Mac's direct BE800 link; disable forwarding, Internet Sharing, and bridging; prove both devices are single-homed. If reachability or supervision is absent, leave hardware steps pending without weakening them.
- [ ] **Step 4: Inspect the delivered daemon `/docs`, status schema, installed SDK metadata, interpreter/ABI, media formats, stop APIs, app lock, and controller behavior before pinning or installing anything.** Store identifiers only in owner-local commissioning state; write only the sanitized report to `var/hardware/`.
- [ ] **Step 5: Run bounded synthetic microphone/speaker, one discarded camera frame, and playback-stop observations with no motion command.** Deliberately introduce a competing unmanaged controller and require detection; inability to stop playback, enumerate/stop movement, or detect controller collision rejects both usable decisions. Missing local input yields only `conditional_mac_key`; AEC/DoA/RTC limitations remain explicit and block later claims.
- [ ] **Step 6: Write and test the minimal forced-command dispatcher before commissioning.** It is
  standard-library-only, requires an empty `SSH_ORIGINAL_COMMAND`, owns one fixed remote root, and
  accepts exactly one canonical request: unsigned 32-bit big-endian JSON length `1..65,536`, then
  UTF-8 JSON with exactly version, `operation_id`, `verb`, commissioning ID, expected state
  generation, and closed payload. Verbs are exactly
  `status|stage|activate|run_ptt|remove|verify_absent`; the response is similarly framed and at most
  4,096 bytes. Stage then reads only manifest-declared artifacts under 32-file/32-MiB-each/256-MiB-
  total bounds. Exact lengths, SHA-256 hashes, generation/path validation, owner/no-follow ancestry,
  atomic staging/activation, and rollback are mandatory. It never interprets a shell token or
  package-index request. Mutations are content-addressed and CAS-idempotent; after uncertain EOF/
  timeout Core calls status and reconciles digests before any retry. `status` requires the exact
  commissioning ID but ignores a stale expected generation and returns only the current generation,
  closed status, and staged/active/capability/runtime/dispatcher commitments.
- [ ] **Step 7: Prove recovery first, then prepare the diagnostic SSH boundary while physically
  present, without enabling the Tuntun key yet.** Before changing a credential, authentication
  method, authorized-key file, or SSH configuration, prove an independent vendor-supported owner
  admin/recovery path that uses no Tuntun key or state and can undo the proposed changes. Discover
  rather than assume the non-root account; pin the host key out of band; create one dedicated Mac
  identity; install the reviewed dispatcher by that attended recovery/admin path; change any default
  credential; and require password plus keyboard-interactive login to be disabled before either
  usable decision. Compute, but do not yet append, the exact
  `restrict,command="<accepted-python> <absolute-dispatcher>"` public-key line. Do not accept an
  unsupported password-disable path as a warning.
- [ ] **Step 8: Re-prove the independent attended owner admin/recovery path after SSH hardening.** It
  must still work with password and keyboard-interactive login disabled, use no Tuntun key/state,
  and remain capable of removing the exact forced-key line and dispatcher after the demo. Tuntun
  stores none of its credentials. Any failed pre-hardening proof, failed post-hardening re-proof, or
  commissioning state with only the temporary forced key returns `ssh_boundary_failed`; do not
  continue to remote-state seeding.
- [ ] **Step 9: During that attended ceremony, seed remote-state v1 before enabling the forced key.**
  Atomically bind exact schema/protocol version, commissioning ID, monotonic generation,
  `commissioned` status, boot/capability/interpreter/runtime/dispatcher/authorized-key commitments,
  fixed owner/root, and empty staged/active generations. Fsync/rename under owner-only no-follow
  ancestry and require its generation/digests to match the pending Mac state. Only then append the
  exact forced-key line, reopen through that key, and prove arbitrary commands, forwarding, PTY,
  agent, shell data, and stale/wrong commissioning requests are rejected.
- [ ] **Step 10: Resolve the private state root from `pwd.getpwuid(os.geteuid()).pw_dir`, never an
  environment variable, and atomically publish under its owner-only `0700` parent with `0600`
  nonsymlink state/lock/key/known-host files.** Use an exclusive lock and expected-generation CAS;
  fsync the same-directory temp file and parent before/after replace. Validate through an open file
  descriptor immediately before every use and reject noncanonical/oversized state, staleness,
  boot/digest drift, owner/mode/symlink races, named-inode drift, or post-validation replacement.
- [ ] **Step 11: Verify all three schemas, privacy scan, exact decision, independent recovery path,
  seeded-state reconciliation, key-only forced-command boundary,
  dispatcher negative cases, and focused hardware marker.**

Run:
```bash
.venv/bin/pytest tests/unit/edge/test_capability_report.py -q
.venv/bin/pytest tests/unit/poc/test_reachy_commissioning.py tests/unit/poc/test_reachy_a05_dispatcher.py -q
.venv/bin/pytest tests/hardware/test_reachy_capability_probe.py -m reachy_hardware -q
.venv/bin/ruff check apps/edge/src/tuntun_edge/diagnostics apps/core/src/tuntun_core/adapters/reachy scripts/reachy_a05_forced_dispatcher.py tests/unit/edge/test_capability_report.py tests/unit/poc/test_reachy_commissioning.py tests/unit/poc/test_reachy_a05_dispatcher.py tests/hardware/test_reachy_capability_probe.py
.venv/bin/mypy --python-version 3.11 apps/edge/src/tuntun_edge/diagnostics scripts/reachy_a05_forced_dispatcher.py
.venv/bin/mypy apps/core/src/tuntun_core/adapters/reachy/commissioning.py
git diff --check
```

Commit: `feat(edge): record delivered Reachy capabilities`

Task 1 may proceed while physical reachability is pending because it contains no SDK/media assumption. Real adapter composition and physical acceptance remain blocked on this task.

---

### Task 1: Shared bounded PTT frame codec

**Files:**
- Create: `packages/contracts/src/tuntun_contracts/poc/__init__.py`
- Create: `packages/contracts/src/tuntun_contracts/poc/framing.py`
- Create: `tests/unit/poc/test_framing.py`
- Modify: `.github/workflows/ci.yml`
- Modify: `tests/ci/test_workflow_policy.py`

**Interfaces:**
- Consumes: `tuntun_contracts.base.ContractModel`, `canonical_bytes`, `parse_contract_json`; `tuntun_contracts.speech.AudioFormat`.
- Produces: `TRANSPORT_AUDIO_FORMAT`, `FrameProtocolError`, `FrameErrorCode`, `FrameKind`,
  `ControlKind`, `PttInputMode`, `StreamDirection`, `GuardDisposition`, `PttStopSource`,
  `PttErrorReason`, `PttSessionOutcome`, `PttSafetyReceipt`, `PttControl` and closed payload models,
  keyword-only `FrameHeader`, `ControlFrame`, `PcmFrame`, `WireFrame`, `GuardedFrame`,
  `encode_control_frame`, `encode_pcm_frame`, `FrameDecoder`, and `PttDuplexGuard`.

`ControlKind` is exactly
`session_open|session_ready|ptt_start|ptt_submit|heartbeat|capture_start|capture_end|playback_start|playback_end|stop|cancel|abort|safety_receipt|safety_ack|error`.
`PttInputMode` is exactly `reachy_local|core_terminal_toggle`; `StreamDirection` is exactly
`edge_to_core|core_to_edge`; `GuardDisposition` is exactly `accepted|late_discarded`.
`PttStopSource` is exactly
`supervisor_input|core_abort|peer_eof|watchdog|protocol_rejected`. `PttSessionOutcome` is exactly
`completed|cancelled|peer_closed|protocol_rejected|capture_failed|provider_failed|playback_failed|cleanup_incomplete|session_timeout`.
`TRANSPORT_AUDIO_FORMAT` is exactly
`AudioFormat(sample_format="s16le", sample_rate_hz=16000, channels=1, interleaved=False, channel_layout="mono")`.

- [ ] **Step 1: Write failing happy-path codec tests.** Assert the exact 32-byte `>4sBBHII16s` prefix, canonical JSON control round-trip, sample-aligned nonempty PCM through `encode_pcm_frame(*, turn_id, sequence, pcm)`, explicit turn binding on both frame kinds, and fragmentation/coalescing through `FrameDecoder.feed(bytes) -> tuple[WireFrame, ...]` with each feed bounded to 65,536 bytes.

```python
def test_control_frame_round_trip_has_exact_prefix() -> None:
    control = PttControl.capture_start(TURN_ID, AUDIO_FORMAT)
    encoded = encode_control_frame(sequence=0, control=control)
    assert encoded[:32] == PREFIX.pack(
        b"TTPT", 1, FrameKind.CONTROL, 0, 0, len(encoded) - 32, TURN_ID.bytes
    )
    decoder = FrameDecoder()
    assert decoder.feed(encoded[:7]) == ()
    assert decoder.feed(encoded[7:]) == (
        ControlFrame(turn_id=TURN_ID, sequence=0, control=control),
    )
```

- [ ] **Step 2: Run the focused test and confirm RED.**

Run: `.venv/bin/pytest tests/unit/poc/test_framing.py -q`
Expected: collection fails because `tuntun_contracts.poc.framing` does not exist.

- [ ] **Step 3: Implement the immutable keyword-only frame values, strict prefix parser, canonical control parser, encoders, and incremental decoder.** The decoder processes a bounded input `memoryview` incrementally, checks length from the prefix before accepting payload bytes, buffers no more than one frame, returns no more than 64 frames, never resynchronizes, clears its buffer on `abort()`, and permanently rejects reuse after any protocol error.

```python
PREFIX = Struct(">4sBBHII16s")
MAX_CONTROL_BYTES = 4_096
MAX_PCM_BYTES = 65_536
MAX_FEED_BYTES = 65_536
MAX_FRAMES_PER_FEED = 64

class FrameDecoder:
    def feed(self, data: bytes) -> tuple[WireFrame, ...]:
        self._require_open()
        self._require_bounded_feed(data)
        pending = memoryview(data)
        staged: list[WireFrame] = []
        try:
            while pending:
                pending, completed = self._consume_incrementally(pending)
                if completed is not None:
                    staged.append(completed)
                    if len(staged) > MAX_FRAMES_PER_FEED:
                        raise FrameProtocolError(FrameErrorCode.TOO_MANY_FRAMES)
        except FrameProtocolError:
            self._poison()
            raise
        return tuple(staged)
```

- [ ] **Step 4: Add failing hostile-input, lifecycle, atomicity, and representation tests.** Cover every bad prefix field; zero/oversized PCM; oversized control declared before body arrival; invalid UTF-8/JSON; duplicate keys; noncanonical JSON; extra/wrong fields; unknown controls; empty-feed no-op; clean `finish()`; truncation on `finish()`; reuse after finish/error/abort; valid-then-invalid frames in one feed returning no partial tuple; 65,537-byte feed; 65 coalesced frames; and sentinels absent from `repr(error)`, `repr(frame)`, and `str(error)`.

- [ ] **Step 5: Run the new cases and confirm the intended RED failures, then implement the smallest closed validations.** `PttControl` is one immutable envelope with
  `payload: EmptyPayload|SessionPayload|StartPayload|SafetyPayload|AckPayload|ErrorPayload`; a
  validator requires the exact payload selected by kind, so serialization is exactly
  `{"kind", "turn_id", "payload"}` without nullable fields. Session payload carries only input mode;
  media start carries only audio format; safety carries only the disposable receipt; ack carries
  only accepted; abort/error carry one registered reason; all other controls carry `{}`. Parse with
  `parse_contract_json(PttControl, raw, max_bytes=4096, require_canonical=True)`.
  `PttErrorReason` is exactly
  `protocol_rejected|turn_cancelled|capture_failed|provider_failed|playback_failed|cleanup_incomplete|peer_closed|session_timeout`.

`FrameProtocolError` accepts only `FrameErrorCode` values `closed|feed_too_large|too_many_frames|invalid_prefix|invalid_length|invalid_control|turn_mismatch|truncated|invalid_sequence|invalid_direction|invalid_order|pcm_limit|duration_limit|rate_limit|invalid_clock`; it exposes no arbitrary message or chained parser exception. `PcmFrame.__repr__` shows turn ID, sequence, and byte count only.

- [ ] **Step 6: Add failing duplex-order and aggregate-limit tests.** Cover Core sequence zero
  `session_open`, Edge sequence zero `session_ready`, exact mode echo, PTT-before-ready, both input
  modes, start/submit toggle, submit while Edge is arming, duplicate/start-before-submit cases,
  capture before ready, forbidden Core PTT in local mode, alternate start format, empty capture,
  capture/playback order, Edge stop racing submit/playback, Core abort racing capture-start/PCM/end,
  repeated same/opposite-direction cleanup requests, valid late-frame discard followed by receipt/
  ack, both orders of abort/receipt, heartbeat/receipt, and abort/session-ready crossings,
  malformed/wrong-turn/wrong-sequence after cleanup, required receipt/ack, and post-ack input.
  Also cover separate exact sequences/no wrap; all turn-ID bindings; 8 MiB per direction; alignment;
  6,400-byte/200-ms frame; exactly 90 seconds; monotonic wall deadline; overdue cleanup controls still
  admitted; heartbeat without media/turn extension; boolean/non-finite/decreasing time; the exact
  rolling 50-frame window; valid finish; invalid premature finish; and idempotent abort.

- [ ] **Step 7: Implement `PttDuplexGuard`.** Its constructor requires keyword-only turn ID and input
  mode. `accept(direction, frame, *, now) -> GuardedFrame` owns separate sequence, bytes, samples,
  media wall, and rate state. It enforces the design's exact handshake and FSM, exact transport format,
  terminal submit-before-capture-end, local-mode ownership, and capture-before-playback. Heartbeat
  leaves state unchanged and extends no deadline. First cleanup permanently closes admissions;
  later valid current-turn cleanup controls are idempotent, and correctly sequenced in-flight input/
  media returns `late_discarded` without state change. Cleanup phase is monotonic: after receipt,
  repeated cleanup stays receipt-received and correctly sequenced in-flight heartbeat/session-ready/
  input/media is late-discarded until ack, while receipt/ack are the only advances. Framing/turn/
  sequence/limit errors still poison
  the guard; cleanup execution is independently owned by Task 2. Receipt then ack closes transport;
  false/incomplete receipt yields `cleanup_incomplete`. `finish()` accepts only acknowledged and
  `abort()` is idempotent from every state.

The closed duplex states are exactly
`wait_session_open|wait_session_ready|ready|arming|arming_submit_pending|capturing|capture_submit_pending|capture_closed|playing|playback_closed|cleanup_required|receipt_received|acknowledged|aborted`.
Legal normal transitions are:

```text
wait_session_open --Core session_open(mode)--> wait_session_ready
wait_session_ready --Edge session_ready(same mode)--> ready

core_terminal_toggle:
ready --Core ptt_start--> arming
arming --Core ptt_submit--> arming_submit_pending
arming --Edge capture_start--> capturing
arming_submit_pending --Edge capture_start--> capture_submit_pending
capturing --Core ptt_submit--> capture_submit_pending
capturing|capture_submit_pending --Edge PCM+--> same state
capture_submit_pending --Edge capture_end--> capture_closed

reachy_local:
ready --Edge capture_start--> capturing
capturing --Edge PCM+--> capturing
capturing --Edge capture_end--> capture_closed

capture_closed --Core playback_start--> playing
playing --Core PCM+--> playing
playing --Core playback_end--> playback_closed
playback_closed --Edge safety_receipt--> receipt_received
cleanup_required --Edge safety_receipt--> receipt_received
receipt_received --Core safety_ack--> acknowledged
```

Edge stop/cancel/error or Core abort/error from every pre-receipt nonterminal state enters cleanup;
in `receipt_received` it is idempotent and state-preserving. Heartbeat keeps any post-open/pre-receipt
state unchanged and is late-discarded after receipt until ack. Every omitted transition rejects. Capture and
playback end each require media; terminal capture end also requires submit. A positive
acknowledgement requires all six receipt booleans to be true. A false acknowledgement is a valid
conservative rejection regardless of the receipt booleans and closes transport with
`cleanup_incomplete`.

```python
guard = PttDuplexGuard(turn_id=TURN_ID, input_mode=PttInputMode.REACHY_LOCAL)
guard.accept(
    StreamDirection.CORE_TO_EDGE,
    ControlFrame(
        turn_id=TURN_ID,
        sequence=0,
        control=PttControl.session_open(TURN_ID, PttInputMode.REACHY_LOCAL),
    ),
    now=10.0,
)
guard.accept(
    StreamDirection.EDGE_TO_CORE,
    ControlFrame(
        turn_id=TURN_ID,
        sequence=0,
        control=PttControl.session_ready(TURN_ID, PttInputMode.REACHY_LOCAL),
    ),
    now=10.1,
)
guard.accept(
    StreamDirection.EDGE_TO_CORE,
    ControlFrame(
        turn_id=TURN_ID,
        sequence=1,
        control=PttControl.capture_start(TURN_ID, AUDIO_FORMAT),
    ),
    now=10.2,
)
```

- [ ] **Step 8: Add Hypothesis stateful/property tests.** Generate bounded arbitrary fragmentation, header fields, valid/invalid duplex transitions, sequence/turn substitutions, and poison/reuse paths; any input produces a valid closed transition or one `FrameProtocolError`, never an uncontrolled exception or unbounded allocation.

- [ ] **Step 9: Deliberately evolve the locked CI policy and its test.** Rename the current job to
  `contracts-edge-python311`; build Contracts and Edge wheels, create a clean 3.11 venv, install the
  wheels plus `pytest>=8.4,<9`, `pytest-asyncio>=1.1,<2`, and `hypothesis>=6.138,<7`, with
  `PYTHONPATH` unset. Run the frozen contract test and framing test. Prove `tuntun_core`,
  `tuntun_testing`, and `reachy_mini` are not importable. Update exact `CONTRACT_STEPS`/job-name
  expectations in `tests/ci/test_workflow_policy.py`; use no root sync and no real Reachy SDK.

- [ ] **Step 10: Verify and commit Task 1.**

Run:
```bash
.venv/bin/pytest tests/unit/poc/test_framing.py tests/contract/test_strict_models.py tests/contract/test_v1_types_and_ports.py tests/contract/test_v1_fixtures.py tests/contract/test_contract_generators.py tests/ci/test_workflow_policy.py -q
.venv/bin/ruff check --target-version py311 packages/contracts/src/tuntun_contracts/poc tests/unit/poc
.venv/bin/ruff format --check packages/contracts/src/tuntun_contracts/poc tests/unit/poc
.venv/bin/mypy --python-version 3.11 packages/contracts/src/tuntun_contracts/poc
git diff --check
```
Expected: all pass; frozen v1 fixtures and root exports are unchanged.

Commit: `feat(poc): add bounded Reachy PTT framing`

---

### Task 2: Robot-local edge PTT safety state machine

**Files:**
- Modify: `apps/edge/pyproject.toml`
- Create: `apps/edge/src/tuntun_edge/poc/__init__.py`
- Create: `apps/edge/src/tuntun_edge/poc/ports.py`
- Create: `apps/edge/src/tuntun_edge/poc/reachy_ptt.py`
- Create: `apps/edge/src/tuntun_edge/cli/__init__.py`
- Create: `apps/edge/src/tuntun_edge/cli/main.py`
- Create: `apps/edge/src/tuntun_edge/cli/ptt.py`
- Create: `tests/unit/edge/test_reachy_ptt.py`
- Modify: `packages/contracts/src/tuntun_contracts/poc/framing.py`
- Modify: `tests/unit/poc/test_framing.py`
- Modify: `.github/workflows/ci.yml`
- Modify: `tests/ci/test_workflow_policy.py`
- Modify: `uv.lock`

**Interfaces:**
- Consumes: Task 1 frames/duplex guard, fixed `PttInputMode`, and injected async
  `ReachyLocalMediaPort`, `EdgeTransportPort`, optional `EdgeCaptureInputPort`, optional independent
  `EdgeStopInputPort`, two distinct `MutableAudioBuffer` instances, a cancellation-cooperative task
  spawner, and `MonotonicClock(now, sleep_until)`; no real SDK choice is made before Task 0. The raw
  byte transport owns bounded receive, full-frame send, and close. The media port accepts the exact
  transport format when capture opens and yields only already-converted PCM; the supervisor still
  validates and rechunks it. Every injected async operation must propagate cancellation promptly.
- Produces: `async ReachyPttSession.run() -> PttSessionOutcome`, async
  `ReachyPttSession.stop(source: PttStopSource) -> PttSafetyReceipt`, and console script
  `tuntun-edge ptt`.

The Task 2 ports have this exact minimum surface; implementations may add no control, gesture, or
motion-command method:

```python
class MonotonicClock(Protocol):
    def now(self) -> float: ...
    async def sleep_until(self, deadline: float) -> None: ...

class EdgeTransportPort(Protocol):
    async def receive(self, max_bytes: int) -> bytes: ...  # b"" is EOF; never oversized
    async def send(self, frame: bytes) -> None: ...  # full drain or raise
    async def close(self) -> None: ...

class EdgeCaptureInputPort(Protocol):
    async def wait_for_start(self) -> None: ...
    async def wait_for_submit(self) -> None: ...

class EdgeStopInputPort(Protocol):
    async def wait_for_stop(self) -> None: ...

class ReachyLocalMediaPort(Protocol):
    async def open_capture(self, *, output_format: AudioFormat, max_frame_bytes: int) -> None: ...
    async def read_capture(self) -> bytes | None: ...
    async def close_capture(self) -> bool: ...
    async def open_playback(self, *, input_format: AudioFormat) -> None: ...
    async def write_playback(self, pcm: bytes) -> None: ...
    async def close_playback(self) -> bool: ...
    async def stop_recording(self) -> bool: ...
    async def stop_playback(self) -> bool: ...
    async def stop_motion(self) -> bool: ...
    async def disable_audio_reactive(self) -> bool: ...

class MutableAudioBuffer(Protocol):
    def append(self, data: bytes) -> None: ...
    def take(self, max_bytes: int) -> bytes: ...
    def clear(self) -> bool: ...
    def is_empty(self) -> bool: ...

class CleanupTaskSpawner(Protocol):
    def start(
        self, operation: Coroutine[Any, Any, bool], *, name: str
    ) -> asyncio.Task[bool]: ...
```

`CleanupTaskSpawner` is injected only for the four independent boolean cleanup observations; it
accepts one coroutine and a content-free name and returns an owned `asyncio.Task[bool]`. The session
uses the runtime's task creation for its coordinator and ordinary children.

**Frozen Task 2 lifecycle and failure rulings:**
- Construction is keyword-only and fixes one mode, turn, port set, two non-aliased buffers, and all
  production deadlines. `run()` is one-shot; concurrent or repeated calls fail before effects.
  At `run()` T0, Edge clears and verifies both owned buffers before creating a runtime child or
  touching the guard, transport, or media ports; stale bytes can never resume into a new turn. A
  clear/verification failure runs bounded local-only cleanup and ends `cleanup_incomplete`.
  `stop()` before `run()` clears buffers and runs the same local stop observations only: it creates
  no reader/writer, performs no transport or guard call, makes no error/receipt/ack attempt, caches
  the receipt, marks the session terminal, and permanently rejects a later run. During or after a
  run, every caller adopts the same shielded cleanup task and receives the cached receipt. Caller
  cancellation while acquiring the lifecycle lock, latching cleanup, handling any post-startup
  exit, or rolling back partial startup is remembered and re-raised only after bounded cleanup and
  owned-task joins finish.
- The 5-second handshake and 310-second turn deadlines start at `run()` T0. Once open, the heartbeat
  deadline is five seconds after the last guard-accepted Core frame. Reaching a deadline exactly is
  expired; heartbeats extend no other deadline. All tests use the injected absolute `sleep_until`.
  A sleeper exception, self-cancellation, or successful return before its requested deadline is an internal clock fault
  and closes `cleanup_incomplete`, never a timeout or a heartbeat busy-loop. Every `now()` sample
  must be finite and nondecreasing; a raise, nonfinite value, or reversal synchronously closes media
  gates/buffers/admission and latches `cleanup_incomplete`. Core and local cleanup triggers retain
  their sampled acceptance timestamp while waiting for locks, so T0+310 wins at equality without
  stealing a valid predeadline trigger. After a clock fault, only local stop observations, owned-task
  joins, and transport teardown remain admissible. Their existing absolute bounds switch to an
  event-loop monotonic fallback anchored to the loop timestamp paired with the last advancing valid
  clock sample; a mid-wait fault cancels and joins the injected sleeper before switching, and never
  restarts or extends the remaining cleanup budget.
- Normal drafts are FIFO through a 64-item backpressured queue. A single writer lock linearizes
  cleanup latch, normal-admission closure, dequeue recheck, sequence allocation, and the active-send
  marker. A dequeued draft is dropped if cleanup won before allocation; once allocated it is the
  active send. The terminal lane holds at most two drafts, deduplicates repeated cleanup, and wakes
  blocked producers with a content-free failure while dropping every queued normal draft. Reader
  and writer also share one guard lock and call `clock.now()` inside it immediately before each
  `PttDuplexGuard.accept`.
- Each send uses `min(send_started + 0.5, active absolute cleanup deadline)`. Guard/encode rejection
  before bytes are attempted does not consume the writer's next sequence. Only a positively
  completed full send advances it. Any send exception, timeout, cancellation, or ambiguous/partial
  completion permanently makes the transport unwritable; no later sequence is emitted. Admission
  rechecks the clock-fault generation after joining send deadline/fault owners and immediately before
  reporting success, so a fault in that completion window leaves the sequence unchanged. Admission
  remains closed while every Core-owned supervisor/pipeline join finishes by the separate T0+4.0
  teardown deadline, with no Core await after it. Bridge close is synchronously fenced within that
  teardown, then its nonrenewable S0 escalation may finish afterward under the separate S0+3 bound.
- Clean EOF and a receive exception preserve `peer_closed` as the first semantic reason on a
  still-valid stream. Because the terminal reader cannot receive an acknowledgement afterward, the
  universal missing-ack rule makes the final public outcome `cleanup_incomplete`. A non-bytes or
  oversized receive result breaches the local transport-port contract and is semantically
  `cleanup_incomplete`. Neither class poisons the decoder/guard; both use the ordinary guarded
  error/receipt path. EOF with buffered truncated framing remains protocol poison.
- False receipt evidence overrides every earlier outcome with `cleanup_incomplete`. On an otherwise
  valid stream, receipt-send failure, a missing acknowledgement, or any negative acknowledgement
  also yields `cleanup_incomplete`. The acknowledgement truth table is: complete/true preserves the
  first semantic outcome; complete/false and incomplete/false are acknowledged
  `cleanup_incomplete`; incomplete/true is a protocol violation but the already-false receipt still
  wins as `cleanup_incomplete`.
- Decoder or guard poison never creates a new decoder/guard and never reads an acknowledgement.
  The guard is aborted and never finished or reused. Local cleanup remains authoritative. A
  monotonic `receipt_attempted` latch is set before a normal receipt send or before an emergency pair
  starts; poison after that latch closes without a second receipt. Emergency output is suppressed
  whenever any send was active when poison latched. An unsent guarded terminal cleanup draft is
  atomically removed and failed before an eligible emergency pair is admitted, so it cannot strand
  the bypass lane. Otherwise, while local stop observations run,
  the idle writer immediately attempts
  `error(protocol_rejected)` from the existing Edge sequence. A failed, partial, or timed-out error
  closes transport and suppresses the receipt. After truthful observations finish, the writer may
  send the one receipt, and both emergency sends share the single T0+2.5 deadline. Neither frame
  enters the poisoned guard; no ack is read; the session closes `cleanup_incomplete`.
- The cleanup coordinator is installed before runtime effects. If its creation fails, gates/buffers
  close and bounded local cleanup runs inline while no runtime child starts. If one injected cleanup
  operation spawn fails, the other observations still start and a reliable built-in fallback starts
  that operation or records it false. Partial-startup rollback owner allocation has one fresh adopted
  attempt, then a cancellation-shieldable direct owner, and only then the same bounded inline
  rollback; it never recurses or skips physical cleanup.
  Every Core-owned supervisor/pipeline child must terminate by T0+4.0 and nothing is
  awaited afterward. Task 7 must explicitly qualify real adapters for this cancellation contract;
  deliberately cancellation-suppressing ports cannot be bounded or certified orphan-free.
- Only the `ptt` execution path reserves stdout for the future binary channel: it emits zero stdout,
  has no mode or motion override, imports no Reachy SDK, and until Task 7 fails closed with one exact
  content-free stderr code and a nonzero exit. Ordinary Typer help remains outside binary mode.

- [ ] **Step 1: Write failing mode/handshake/capture tests with injected fakes.** In
  `reachy_local`, require capture and stop input ports and forbid wire PTT controls. In
  `core_terminal_toggle`, require no Edge capture input, consume Core start/submit controls, allow
  submit while media is still arming, and keep any proved local stop independently optional. Reject
  both/no capture owners, mode echo drift, and configuration override. Assert Edge opens capture
  before `capture_start`, closes it before `capture_end`, sends only converted/sample-aligned PCM of
  at most 200 ms, and exposes no gesture/motion command. A native capture read is accepted only when
  it is an exact `bytes` value of 1 through 65,536 even bytes; larger input is rejected before any
  buffer copy or wire effect, and accepted input is losslessly rechunked to the transport ceiling.
  `capture_start`, every PCM draft, and `capture_end` carry their absolute capture/turn deadline;
  capture close is bounded by both submit+2 seconds and the original 90-second capture wall.
  First correct the Task 1 acknowledgement
  truth table under RED/GREEN tests: false is a valid conservative terminal acknowledgement for a
  complete or incomplete receipt, while true remains illegal for an incomplete receipt.
- [ ] **Step 2: Run the focused test and confirm RED because the edge PTT module is absent.**
- [ ] **Step 3: Implement the smallest single-turn supervisor and Edge dependency on Contracts.**
  Install one shared exactly-once cleanup task before creating capture/playback tasks. Concurrently
  own transport, mode-specific input, media, one-second heartbeat watchdog, 310-second absolute turn
  watchdog, one bounded outbound writer/sequence allocator, and every child task. Only that writer
  assigns sequences/writes complete frames; its reserved cleanup lane preempts and drops queued
  normal drafts while normal admission remains FIFO/backpressured. Session ready is 5 seconds;
  capture open/close is 2 seconds; capture/playback are 90 seconds. Lazy-load a real SDK only in
  Task 7.
- [ ] **Step 4: Write failing cleanup tests for every state, race, and component failure.** Assert
  capture/output gates close and buffers drop synchronously. Simultaneous local stop, submit, Core
  abort, EOF, malformed input, and watchdog all adopt the same cleanup task. Recording, playback,
  motion, and audio-reactive stops start independently under one 2-second absolute deadline; one
  raise, hang, repeated cancellation, or task-factory failure never suppresses siblings. Correctly
  sequenced late frames are discarded; malformed/wrong-turn/wrong-sequence frames fail protocol but
  cannot cancel local cleanup. Force capture-vs-error/receipt races and prove contiguous Edge
  sequences, noninterleaved frames, cleanup priority, and no receipt starvation. Receipt fields
  without positive observation stay false.
- [ ] **Step 5: Implement bounded cancellation-resistant cleanup.** Stop operations finish or time
  out by T+2 seconds; on a valid stream encode/send the resulting truthful receipt by T+2.5 and
  finish ack wait by T+3.5; keep admission closed and bound all Core-owned supervisor/pipeline task
  joins by the separate T+4.0 teardown deadline. Synchronously fence bridge close within that
  teardown, then let only its nonrenewable S0 escalation continue through S0+3. Missing/
  negative ack or any false field is `cleanup_incomplete`; it never delays local shutdown or prints
  exception payloads. Heartbeat loss after 5 seconds, Edge watchdog, EOF, and unwritable transport
  still run the same local path. Protocol poison follows only the frozen terminal emergency rule;
  it never attempts to parse the acknowledgement.
- [ ] **Step 6: Add Core-abort, half-open link, repeated cleanup, acknowledgement timeout, late
  playback, turn substitution, and no-orphan tests.** Prove no capture/playback admission reopens,
  one receipt at most is attempted, all owned tasks terminate within their bounds, and content-free
  failure exits nonzero.
- [ ] **Step 7: Deliberately update the Python 3.11 workflow and locked policy test.** Build and
  install Edge with Contracts in the clean wheel venv, run the async Edge test with the already
  pinned `pytest-asyncio`, and retain the assertions that Core, testing, and real Reachy SDK imports
  are absent. Ordinary CI never installs hardware extras.

- [ ] **Step 8: Verify and commit Task 2.**

Run:
```bash
.venv/bin/pytest tests/unit/edge/test_reachy_ptt.py tests/unit/poc/test_framing.py tests/ci/test_workflow_policy.py -q
.venv/bin/ruff check --target-version py311 apps/edge packages/contracts/src/tuntun_contracts/poc tests/unit/edge
.venv/bin/ruff format --check apps/edge packages/contracts/src/tuntun_contracts/poc tests/unit/edge
.venv/bin/mypy --python-version 3.11 apps/edge/src packages/contracts/src/tuntun_contracts/poc
uv lock --check --offline
git diff --check
```

Commit: `feat(edge): add supervised Reachy PTT safety loop`

---

### Task 3: In-memory Core voice-turn coordinator

**Files:**
- Create: `apps/core/src/tuntun_core/services/poc/ports.py`
- Create: `apps/core/src/tuntun_core/services/poc/voice_turn.py`
- Create: `apps/core/src/tuntun_core/services/poc/session_supervisor.py`
- Create: `apps/core/src/tuntun_core/adapters/poc/pcm16_converter.py`
- Create: `tests/unit/poc/test_voice_turn.py`
- Create: `tests/unit/poc/test_session_supervisor.py`
- Create: `tests/unit/poc/test_pcm16_converter.py`

**Interfaces:**
- Consumes: fixed input mode; optional `CorePttInputPort`; injected `SpeechToTextPort`,
  `LanguageModelPort`, `TextToSpeechPort`, immutable reviewed `tts_source_format`,
  `AudioConverterPort`, `ProviderCancellationPort`, `PttBridgePort`, `VoiceAttemptAuthorizerPort`,
  and `MonotonicClock`. Fake voice-attempt authorizations are used until Checkpoint A0's durable
  route and budget gates exist. `PttBridgePort.send()` and `close()` are synchronous factories
  returning bounded awaitables; `send()` resolves to `PttSendCommit`.
- Produces: redacting `CapturedTurn`, `CorePttEvent(start|submit|cancel)`,
  `VoiceTurnPipeline.run(...) -> AsyncIterator[SpeechChunk]`,
  `VoiceTurnPipeline.observe_quarantine(deadline=...) -> Awaitable[bool]`,
  `async CorePttSessionSupervisor.run(turn_id) -> PttSessionOutcome`, and bounded cancel. The outcome
  carries no content.

- [ ] **Step 1: Write failing fake-provider pipeline and conversion tests for English, Hindi, and
  Hinglish.** Assert stage order, response/request-ID matching, language propagation, no tools, NFC
  1..4,096-character answer, one TTS request, and a complete valid source chunk stream. Require the
  exact reviewed source format and `TRANSPORT_AUDIO_FORMAT` arguments to `AudioConverterPort`.
  Buffer/validate all source audio before playback, convert once, validate/rechunk converted PCM as
  nonempty even chunks of at most 6,400 bytes with fresh contiguous sequences and one final chunk,
  then send exactly one exact-format playback. Raw provider PCM must never reach the bridge.
- [ ] **Step 2: Run and confirm RED because the coordinator is absent.**
- [ ] **Step 3: Implement the minimal one-turn pipeline and bounded PCM16 converter.** Keep input,
  source TTS, converted TTS, and text in separate mutable holders; clear all on every exit. Use only
  injected canonical voice-attempt authorization ports; fakes provide exact fake authorizations and
  production DTOs are never invented. Converter tests cover alignment, duration, a known tone
  resampled from the reviewed source rate to 16 kHz, identity conversion, overflow, cancellation,
  and deterministic chunking.
- [ ] **Step 4: Write failing input-mode and supervisor tests.** Core sends session-open and waits at
  most 5 seconds for the exact mode echo before enabling input. Terminal-toggle requires one
  `CorePttInputPort`, maps START/SUBMIT to wire controls, latches rapid submit while arming, and maps
  CANCEL to abort/turn-cancelled. Reachy-local forbids a Core input. Construction with both/no input
  owner rejects. A bridge reader, one-second heartbeat scheduler, and one bounded outbound writer/
  sequence allocator run before input/provider work; no producer writes directly.
- [ ] **Step 5: Add paused-stage/race tests at capture, STT, LLM, TTS, conversion, and playback.**
  Inject Edge stop/cancel, terminal cancel, heartbeat failure, or Core timeout and prove admission
  closes before releasing paused work, downstream stages never start, late results are dropped, raw
  source audio never plays, and all mutable holders clear. Malformed/late source chunks or converter
  failure produce zero playback. Force heartbeat-vs-playback/abort/ack races and prove contiguous
  Core sequences, noninterleaved frames, due-heartbeat fairness, cleanup priority, and no abort/ack
  starvation.
- [ ] **Step 6: Implement `CorePttSessionSupervisor`.** Concurrently own reader, heartbeat, input,
  provider pipeline, playback writer, cancellation event, receipt/ack, and all tasks. Enforce 30/45/
  30-second stage and 120-second pipeline bounds. The first cleanup trigger defines one monotonic T0:
  immediately close admission and enqueue `abort` on the reserved priority lane while concurrently
  closing the active provider transport within 0.5 seconds and joining it within 1 second. Do not
  delay `abort` behind provider teardown. Complete the same T0-based receipt/ack path within the
  3.5-second outer bound, then allow Task 4 escalation. Every configured provider adapter must pass cancellation-
  cooperation qualification: swallowing `CancelledError` or remaining live after transport close/
  join makes that adapter unavailable to live mode. The runtime does not claim to contain arbitrary
  cancellation-suppressing coroutines. Cancellation fans out to every owned sibling before any
  bounded join; incomplete work remains owned in its originating deadline quarantine. Core observes
  both its supervisor quarantine and the pipeline quarantine through T0+4, and any live/error/false
  result forces `cleanup_incomplete`. Mixed exception groups are contained at adapter/provider
  boundaries; nested cleanup incompleteness dominates ordinary members. Unclaimed provider audio is
  wiped exactly once, and abandoned late provider results plus source/converted audio destinations
  are re-wiped when their owning work settles. Incomplete cleanup cannot be downgraded by a later
  iterator-close failure. Before the final `safety_ack`, Core fences normal/heartbeat admission and
  makes terminal input final; exact committed ACK is the clean-EOF boundary, and no frame is emitted
  afterward. Truncated or malformed bytes still poison the session. Only bounded cleanup is
  shielded. `PttBridgePort.send(...)` and `PttBridgePort.close()` are synchronous factories that
  return the awaitable send/close commitment, with `close()` fencing future sends and fixing one
  nonrenewable transport epoch S0. Start `bridge.close()` at the beginning of teardown (or earlier
  on hard failure), then observe that transport only through S0+3 so Task 4's stdin/TERM/KILL
  sequence cannot be truncated by the Core deadline. S0 may outlive T0+4 only for transport already
  fenced by that first close; it never reopens admission, extends the Core cleanup bound, emits a
  later frame, or weakens a poisoned-stream outcome.
- [ ] **Step 7: Add timeout, provider error, transcript/request mismatch, wrong language, oversized/
  non-NFC answer, source and converted chunk/final/aggregate errors, alternate source format,
  converted misalignment/duration drift, duplicate turn, negative/missing ack, and no-orphan tests;
  implement the exact closed outcomes.**
- [ ] **Step 8: Verify dependency direction, type checks, and commit Task 3.**

Run:
```bash
.venv/bin/pytest tests/unit/poc/test_voice_turn.py tests/unit/poc/test_session_supervisor.py tests/unit/poc/test_pcm16_converter.py tests/contract/test_dependency_direction.py -q
.venv/bin/ruff check apps/core/src/tuntun_core/services/poc apps/core/src/tuntun_core/adapters/poc tests/unit/poc
.venv/bin/ruff format --check apps/core/src/tuntun_core/services/poc apps/core/src/tuntun_core/adapters/poc tests/unit/poc
.venv/bin/mypy apps/core/src/tuntun_core/services/poc apps/core/src/tuntun_core/adapters/poc
git diff --check
```

Commit: `feat(core): coordinate ephemeral PTT voice turns`

---

### Task 4: Host-key-pinned SSH stdio bridge

**Files:**
- Create: `apps/core/src/tuntun_core/adapters/reachy/ssh_forced.py`
- Create: `apps/core/src/tuntun_core/adapters/reachy/ssh_ptt.py`
- Create: `tests/unit/poc/test_ssh_forced.py`
- Create: `tests/unit/poc/test_ssh_ptt.py`
- Create: `tests/integration/test_ssh_forced_command_local.py`
- Create: `tests/integration/test_poc_stop_cleanup.py`
- Create: `.github/ci/openssh-ubuntu-24.04.lock`
- Modify: `.github/workflows/ci.yml`
- Modify: `tests/ci/test_workflow_policy.py`

**Interfaces:**
- Consumes: Task 0's validated commissioning-state descriptor, Task 0 dispatcher protocol, Task 1
  frames, and Task 3 `PttBridgePort`.
- Produces: a bounded `SshForcedCommandProcess` for one dispatcher request and `SshPttBridge` that
  sends `run_ptt`, validates its ready response, then switches the same stdio to Task 1 frames.

- [ ] **Step 1: Write failing state/target/file/argv tests.** Reopen the exact private state under its
  lock and validate generation, status, boot/capability/runtime digests, numeric RFC1918 target,
  non-root user, port 22, key/known-host commitments, owner/mode/no-follow ancestry, and inode
  stability. Reject DNS, user options, environment-supplied paths, arbitrary command strings, and
  state replacement between validation and spawn.
- [ ] **Step 2: Run RED, then freeze exact argv and subprocess semantics.** Argv is `/usr/bin/ssh`,
  `-4`, `-T`, `-F`, `/dev/null`, `-p`, `22`, then separate `-o` pairs for BatchMode,
  IdentitiesOnly, bound IdentityFile, IdentityAgent=none, StrictHostKeyChecking, bound
  UserKnownHostsFile, GlobalKnownHostsFile=/dev/null, UpdateHostKeys=no, VerifyHostKeyDNS=no, the
  accepted HostKeyAlgorithms, PasswordAuthentication=no, KbdInteractiveAuthentication=no,
  NumberOfPasswordPrompts=0, PreferredAuthentications=publickey, ProxyCommand/ProxyJump=none,
  ClearAllForwardings, ForwardAgent/X11=no, PermitLocalCommand=no, ControlMaster=no, RequestTTY=no,
  Tunnel=no, ConnectTimeout=5, ServerAliveInterval=2, ServerAliveCountMax=2, TCPKeepAlive=no, and
  LogLevel=ERROR; then `--` and exactly `<validated-user>@<numeric-address>`. Supply no remote command
  token. Use pipes, `start_new_session=True`, no shell/preexec, and a closed C locale environment.
- [ ] **Step 3: Write failing dispatcher and PTT lifecycle tests.** Cover canonical request/response
  bounds, operation ID and expected-generation binding, status reconciliation after uncertain
  mutation, run-ready then wire framing, EOF, stderr flood, malformed frame, Edge stop, Core abort,
  negative/missing ack, cancellation, timeout, Ctrl-C, child exit, and process-group escalation.
  Assert protocol cleanup precedes stdin close/TERM/KILL and stderr is drained into a fixed-size
  content-free classifier.
- [ ] **Step 4: Implement bounded I/O and idempotent close.** The first synchronous close call
  atomically fences sends and fixes a nonrenewable transport epoch S0. Close stdin immediately and
  wait only through S0+1; if still alive and still the validated process-group leader, TERM its group
  and wait only through S0+2, then KILL and observe/reap only through S0+3. Core starts this close at
  the beginning of final teardown after the safety path, concurrently with its remaining joins, or
  earlier on hard transport failure. Never surface stderr bytes or content; never resume a
  disconnected turn.
- [ ] **Step 5: Add a real loopback OpenSSH integration contract.** Start a non-root temporary sshd
  on a high loopback port with generated host/key files and the same forced-command restriction;
  prove argv order, no remote shell command, exact stdin dispatch, host-key failure, and TERM/KILL
  behavior without mocking subprocess composition. Absence of the required local sshd binary is a CI
  prerequisite failure, not a passed/accepted test. Add a committed OpenSSH package lock containing
  the reviewed signed Ubuntu origin, complete OpenSSH package closure, exact versions, and archive
  SHA-256 digests. A dedicated Ubuntu job downloads only that locked closure, verifies its signed
  origin and every digest before installation, installs no unconstrained latest package, verifies
  installed client/server versions and binary paths, and runs only this bounded contract. If a locked
  package is no longer available or the rolling runner changes incompatibly, fail closed and update
  the lock in a reviewed change; do not assume `sshd` is preinstalled or silently download a
  replacement.
- [ ] **Step 6: Verify the local contract and workflow policy, then commit Task 4.**

Run:
```bash
.venv/bin/pytest tests/unit/poc/test_ssh_forced.py tests/unit/poc/test_ssh_ptt.py tests/integration/test_ssh_forced_command_local.py tests/integration/test_poc_stop_cleanup.py tests/ci/test_workflow_policy.py -q
.venv/bin/ruff check apps/core/src/tuntun_core/adapters/reachy tests/unit/poc/test_ssh_forced.py tests/unit/poc/test_ssh_ptt.py tests/integration/test_ssh_forced_command_local.py tests/integration/test_poc_stop_cleanup.py
.venv/bin/mypy apps/core/src/tuntun_core/adapters/reachy
git diff --check
```

Commit: `feat(core): bridge Reachy PTT over pinned SSH`

---

### Task 5: Fake end-to-end loop and non-retention gate

**Files:**
- Create: `apps/core/src/tuntun_core/cli/commands/talk.py`
- Create: `apps/core/src/tuntun_core/adapters/poc/fake_voice.py`
- Create: `apps/core/src/tuntun_core/adapters/poc/terminal_ptt.py`
- Modify: `apps/core/src/tuntun_core/cli/main.py`
- Create: `apps/edge/src/tuntun_edge/poc/simulator.py`
- Modify: `apps/edge/src/tuntun_edge/cli/main.py`
- Create: `tests/integration/test_poc_ptt_loop.py`
- Create: `tests/security/test_poc_nonretention.py`
- Create: `tests/unit/poc/test_terminal_ptt.py`
- Create: `tests/unit/poc/test_mode_matrix.py`
- Modify: `tests/unit/test_cli.py`
- Create: `docs/operations/reachy-ptt-a05.md`

**Interfaces:**
- Consumes: Tasks 2–4 plus minimal deterministic runtime fakes; `tuntun-testing` remains test/
  optional rather than a normal runtime dependency.
- Produces: `tuntunctl talk --mode fake --transport simulated`, a separate SDK-free
  `tuntun-edge simulate-ptt` process, the Core terminal-toggle adapter, and the supervised runbook.

- [ ] **Step 1: Write failing terminal, mode-matrix, CLI, and integration tests.** Terminal fallback
  maps Space to START then SUBMIT and Escape to CANCEL, emits nothing else, debounces locally, needs
  no key-up/Accessibility hook, never logs keys, and restores prior terminal mode in `finally` after
  success, error, timeout, or Ctrl-C.
  `fake/simulated` is the only available cell at this task and unsupported cells reject before
  Keychain, budget, audio, network, or SSH effects.
- [ ] **Step 2: Run RED, then compose the fake CLI and standalone Edge simulator.** Simulated Core
  spawns the Edge executable over bounded stdio; production Core never imports Edge. Add no listener,
  storage, hardware SDK, or normal dependency on `tuntun-testing`. The default simulated mode is
  `core_terminal_toggle`; a scripted Core input is the sole capture owner.
- [ ] **Step 3: Add direct integration of the real Task-2 Edge session and Task-3 Core supervisor
  through a test-only bounded byte-duplex fixture.** Exercise terminal-toggle and reachy-local modes,
  fragmentation, coalescing, backpressure, rapid submit while arming, stop/abort races, and
  constructor rejection when both/neither side owns capture. Test code may import both packages;
  production dependency direction remains unchanged.
- [ ] **Step 4: Add a 50-turn scenario with English/Hindi/Hinglish and reconnect only between
  turns.** Require exactly one session handshake, capture, submit where applicable, playback,
  receipt, and acknowledgement per turn with no duplicate playback.
- [ ] **Step 5: Inject failure at capture/STT/LLM/TTS/conversion/playback plus owned process/task
  cleanup and repeated warm-state descriptor bounds.** Avoid brittle global equality across unrelated
  runtime activity. Scan the application-managed test tree for raw sentinels after every run.
- [ ] **Step 6: Document exact toggle behavior, diagnostic boundary, commands, mode matrix, fixed
  statuses, cleanup, and the prohibition on A0.5/POC/Phase-1-complete claims from simulator evidence.**
- [ ] **Step 7: Verify and commit Task 5.**

Run:
```bash
.venv/bin/pytest tests/integration/test_poc_ptt_loop.py tests/integration/test_poc_stop_cleanup.py tests/security/test_poc_nonretention.py tests/unit/poc/test_terminal_ptt.py tests/unit/poc/test_mode_matrix.py tests/unit/test_cli.py -q
.venv/bin/ruff check apps/core apps/edge packages/contracts tests/integration/test_poc_ptt_loop.py tests/security/test_poc_nonretention.py
.venv/bin/mypy apps/core/src apps/edge/src packages/contracts/src
git diff --check
```

Commit: `feat(poc): integrate non-retaining supervised voice loop`

---

### Task 6: Current OpenAI adapters behind the durable cloud gate

**Depends on:** The canonical conversation plan's Checkpoint A0: purpose-specific consent/privacy receipts, production `RouteAuthorizerPort`, atomic SQLCipher `BudgetPort` reserve/settle/release and reconciliation, current provider review/pricing, dedicated project-scoped non-admin key, and an enforcing provider project limit at or below the approved threshold.

**Files:**
- Modify: `apps/core/pyproject.toml`
- Create: `apps/core/src/tuntun_core/adapters/openai/poc_voice.py`
- Modify: `apps/core/src/tuntun_core/cli/commands/talk.py`
- Create: `tests/contract/poc/test_openai_voice_requests.py`
- Create: `tests/security/test_poc_cloud_boundary.py`
- Create: `tests/live_cloud/test_poc_voice.py`
- Modify: `tests/unit/poc/test_mode_matrix.py`
- Modify: `uv.lock`

**Interfaces:**
- Consumes: current official OpenAI SDK/API documentation, Keychain provider, existing authorized speech/provider contracts, and Task 3 ports.
- Produces: Keychain-backed STT, Responses, TTS, and provider-cancellation adapters plus only
  `live-cloud/simulated`; Task 7 adds the SSH intersection after hardware commissioning.

- [ ] **Step 1: Re-check current official OpenAI API, SDK, model, retention, pricing, retry, timeout,
  redirect, telemetry, and TTS output-format behavior; record exact decisions in the runbook before
  pinning.** Bind the reviewed TTS encoding/rate/channels to Task 3's immutable source format; startup
  rejects drift. Do not infer unstable facts from memory.
- [ ] **Step 2: Write failing request-capture tests.** Assert Keychain-only dedicated project
  credential loading; route/consent/privacy/budget/provider-review evidence before each attempt;
  separate STT/reasoning/TTS authorization/reservation; provider/model/host allowlist; exact TTS
  source format; `store=false`; no tools; retries zero; bounded timeouts; no redirects/telemetry; and
  no sensitive payload in exceptions/logs. Assert cancellation closes the provider transport within
  the Task-3 bound, propagates `CancelledError`, terminates within the join bound, and raw provider
  PCM cannot reach playback. A cancellation-suppressing adapter fails qualification and is not
  composable.
- [ ] **Step 3: Run and confirm RED, then implement the smallest adapters behind the Task 3 ports.** Copy provider results immediately into bounded mutable holders and discard SDK response objects after extracting the needed field.
- [ ] **Step 4: Write failing gate/reconciliation tests.** Require an explicit interactive disclosure, current purpose-specific consent, one atomic reservation per STT/reasoning/TTS attempt, S$100 soft warning, Asia/Singapore S$150 hard monthly ceiling across restart/concurrency, enforcing provider project limit, transport proof, exact settlement/release, and fail-closed startup reconciliation. Missing Checkpoint A0 services makes `--mode live-cloud` absent rather than degraded.
- [ ] **Step 5: Compose only production route/budget services; add no diagnostic substitute.** Add
  only `live-cloud/simulated`; unsupported matrix cells reject before Keychain access, reservation,
  capture, network, or SSH spawn and never fall back. Live mode refuses noninteractive/background
  startup and remains absent from ordinary tests.
- [ ] **Step 6: Run `tests/live_cloud/test_poc_voice.py -m live_cloud` only when the owner Keychain credential, `TUNTUN_ALLOW_LIVE_CLOUD=1`, current provider evidence, and explicit paid-test approval are all present; otherwise report it as not run, not passed.** The smoke uses synthetic audio/text and verifies route consumption, transport proof, settlement, and content-free output.
- [ ] **Step 7: Verify and commit Task 6.**

Run:
```bash
.venv/bin/pytest tests/contract/poc/test_openai_voice_requests.py tests/security/test_poc_cloud_boundary.py tests/unit/poc/test_mode_matrix.py -q
.venv/bin/ruff check apps/core/src/tuntun_core/adapters/openai apps/core/src/tuntun_core/services/poc tests/contract/poc tests/security/test_poc_cloud_boundary.py
.venv/bin/mypy apps/core/src/tuntun_core/adapters/openai apps/core/src/tuntun_core/services/poc
uv lock --check --offline
git diff --check
```

Paid opt-in command after every named gate is present:
```bash
TUNTUN_ALLOW_LIVE_CLOUD=1 .venv/bin/pytest tests/live_cloud/test_poc_voice.py -m live_cloud -q
```

Commit: `feat(poc): add guarded cloud voice adapters`

---

### Task 7: Delivered Reachy adapter, deployment, and physical evidence

**Files:**
- Create: `apps/edge/src/tuntun_edge/adapters/reachy/local_sdk.py`
- Create: `apps/core/src/tuntun_core/adapters/reachy/deploy_a05.py`
- Create: `apps/core/src/tuntun_core/services/poc/reachy_evidence.py`
- Modify: `apps/core/src/tuntun_core/cli/main.py`
- Modify: `apps/core/src/tuntun_core/cli/commands/talk.py`
- Create: `apps/core/src/tuntun_core/cli/commands/reachy.py`
- Create: `scripts/build_reachy_a05_bundle.py`
- Create: `scripts/verify_reachy_a05_evidence.py`
- Create: `tests/ci/test_reachy_a05_bundle.py`
- Create: `tests/ci/test_reachy_a05_evidence.py`
- Create: `tests/unit/edge/test_reachy_local_sdk.py`
- Create: `tests/unit/poc/test_reachy_a05_deploy.py`
- Create: `tests/hardware/test_reachy_ptt_loop.py`
- Create: `tests/hardware/test_reachy_a05_removal.py`
- Modify: `tests/unit/poc/test_mode_matrix.py`
- Create: `docs/evidence/reachy-a05-result.schema.json`
- Modify: `docs/operations/reachy-ptt-a05.md`

**Interfaces:**
- Consumes: Task 0 `accepted|conditional_mac_key` report and commissioning state, exact onboard
  SDK/daemon/Python/runtime inventory, Task 2 facade, Task 4 forced-command boundary, and Task 6 live
  gate.
- Produces: drift-rejecting local adapter, two-project-wheel deployment bundle,
  `tuntunctl reachy deploy-a05|remove-a05|decommission-a05`, SSH mode-matrix cells, strict sanitized
  evidence, and opt-in hardware tests.

- [ ] **Step 1: Revalidate Task 0 immediately before code and each physical run.** Require the
  approved single-homed ASUS/AiMesh topology, fresh boot/capability/commissioning digests, exact
  SDK/daemon/interpreter/runtime facts, playback/movement stop, controller detection, and forced
  command. `accepted` binds `reachy_local`; `conditional_mac_key` binds
  `core_terminal_toggle`. Reject every mode override and every rejected/unknown/drifted report.
- [ ] **Step 2: Write failing adapter tests against an injected SDK double.** Cover
  `connection_mode="localhost_only"`, robot-local media, observed native formats, bounded conversion,
  playback stop, movement enumeration/per-UUID stop/reinventory, audio-reactive disable, controller
  collision, local-input ownership, independent exactly-once cleanup, and no motion command.
- [ ] **Step 3: Implement the lazy adapter against the externally provided exact runtime.** Record
  accepted `reachy_mini`/vendor/native names, versions, ABI and artifact hashes in capability/bundle
  manifests, not as wheel dependencies to install. Reject SDK/daemon/runtime drift; never replace the
  official daemon, SDK, or native dependency.
- [ ] **Step 4: Write failing bundle/deployment tests.** Build only Contracts and Edge project wheels
  and require both `py3-none-any`, `Root-Is-Purelib: true`, expected archive members, and no
  `.so|.dylib|.pyd|.dll`. The complete third-party/native closure must already exist exactly in the
  qualified onboard interpreter. Missing/drifted dependency blocks; never download/transfer a
  support/native wheel, install an sdist, compile, or access an index.
- [ ] **Step 5: Implement content-addressed staging and activation through Task 0's dispatcher, not
  the PTT codec.** The fixed remote root contains `bootstrap/v1`, `state.json`, `.staging/<uuid>`, and
  `generations/<full-bundle-sha256>/{manifest.json,wheels,venv}` on one filesystem with owner-only
  ancestry. Stage creates a venv from the exact accepted base interpreter with
  `--system-site-packages`, installs the two project wheels offline with `--no-index --no-deps`, and
  verifies imports, entrypoint, SDK closure, manifest, and no network attempt. Activation atomically
  CAS-updates state; there is no mutable current symlink. `run_ptt` reads/validates active state and
  execs that generation's interpreter/module without a client path. Interrupted/uncertain mutation
  rolls back or reconciles status before idempotent retry.
- [ ] **Step 6: Implement deploy/remove CLI and the remaining matrix cells.** Add `fake/ssh` only
  when deployment is active and `live-cloud/ssh` only when both hardware and Task 6 gates pass;
  unsupported cells reject before Keychain, budget, capture, network, or SSH effects. Freeze a clean
  committed source and exact capability/commissioning/bundle digests before physical evidence.
- [ ] **Step 7: Write strict evidence model/schema/verifier tests.** `ReachyA05EvidenceV1` uses only
  closed bounded fields: source/capability/commissioning/bundle/runtime commitments; exact input mode;
  media/EOF/abort/cancel outcomes; exactly 20 stop records with latency and all receipt/ack facts;
  recomputed min/median/P95/max; English/Hindi/Hinglish closed outcomes; live-cloud status
  `not_run|failed|passed`; removal/decommission/daemon-health status; and bounded limitation codes.
  It has no hostname, address, principal, serial, key, SSID, audio, transcript, response, screenshot,
  provider body, or free-form note. The verifier parses canonical bounded JSON, recomputes all
  commitments/statistics, binds the expected clean commit and generation, and exits nonzero unless
  every mandatory fact including `live-cloud=passed`, removal, decommission, and daemon health
  passes. The owner-local canonical artifact is `var/hardware/reachy-a05-result.json`, mode `0600`,
  and ignored by Git; only its schema and synthetic fixtures are committed.
- [ ] **Step 8: Run all non-hardware verification and commit the complete Task-7 implementation.**
  Require a clean worktree after the commit; build and deploy only that exact HEAD and bind its commit
  plus bundle digest into evidence. Any later tracked code/config change invalidates all physical
  evidence and requires rebuild, redeploy, and retest. Only ignored sanitized runtime evidence and
  the content-minimized revoked tombstone may change afterward.
- [ ] **Step 9: While the exact generation is active, run required physical tests.** With
  `TUNTUN_ALLOW_REACHY_HARDWARE=1` and `TUNTUN_REQUIRE_REACHY_A05=1`, missing supervision/hardware/
  evidence or any skip calls `pytest.fail`. Run microphone/speaker, EOF, Core abort, terminal/local
  cancel, half-open heartbeat, and 20 stop-during-playback trials. Every local cleanup must finish
  within 2 seconds, receipt/ack within 3.5 seconds, every field true, and audio stop after receipt;
  any miss fails. Save no household recording.
- [ ] **Step 10: After Task 6 is green and paid-test approval is current, run one owner-spoken
  English, Hindi, and Hinglish `live-cloud/ssh` turn.** Each must use the durable authorizer/budget
  gates and pass; not-run/failed remain truthful partial evidence but cannot accept A0.5. Verify the
  pre-removal evidence for the exact active commit/generation and commission final code review now,
  before destroying the executable evidence target.
- [ ] **Step 11: Remove and decommission in the safe order.** `remove-a05` CAS-removes only the exact
  generation, then dispatcher `verify_absent` proves no stage/generation residue and official daemon/
  media health. In a physically supervised vendor/local session, remove the exact committed
  authorized-key line, prove the dedicated key can no longer authenticate, remove the dispatcher/
  remote root, verify the official daemon again, delete the Mac identity/known-host files, and mark
  local state revoked. Never re-enable a weaker default/password setting.
- [ ] **Step 12: Finalize and verify evidence, then run non-hardware verification.** The completion
  verifier requires the non-skipped physical result, three passed language outcomes, removal,
  decommission, and daemon health. Do not rerun the Reachy PTT hardware test after removal; run only
  the distinct absence/health check before decommission and then ordinary local `make check`.

Run:
```bash
.venv/bin/pytest tests/unit/poc tests/unit/edge tests/integration/test_poc_ptt_loop.py tests/integration/test_poc_stop_cleanup.py tests/security/test_poc_nonretention.py tests/security/test_poc_cloud_boundary.py -q
.venv/bin/pytest tests/ci/test_reachy_a05_bundle.py tests/ci/test_reachy_a05_evidence.py -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy apps/core/src apps/edge/src packages/contracts/src packages/testing/src
make check
git diff --check
```

Implementation commit before any physical evidence:
```bash
git add apps/edge/src/tuntun_edge/adapters/reachy/local_sdk.py apps/core/src/tuntun_core/adapters/reachy/deploy_a05.py apps/core/src/tuntun_core/services/poc/reachy_evidence.py apps/core/src/tuntun_core/cli/main.py apps/core/src/tuntun_core/cli/commands/talk.py apps/core/src/tuntun_core/cli/commands/reachy.py scripts/build_reachy_a05_bundle.py scripts/verify_reachy_a05_evidence.py tests/ci/test_reachy_a05_bundle.py tests/ci/test_reachy_a05_evidence.py tests/unit/edge/test_reachy_local_sdk.py tests/unit/poc/test_reachy_a05_deploy.py tests/hardware/test_reachy_ptt_loop.py tests/hardware/test_reachy_a05_removal.py tests/unit/poc/test_mode_matrix.py docs/evidence/reachy-a05-result.schema.json docs/operations/reachy-ptt-a05.md
git diff --cached --check
git commit -m "feat(edge): qualify delivered Reachy PTT path"
```

Continue only from that clean commit:
```bash
.venv/bin/python scripts/build_reachy_a05_bundle.py --require-clean --source-commit HEAD
.venv/bin/tuntunctl reachy deploy-a05
TUNTUN_ALLOW_REACHY_HARDWARE=1 TUNTUN_REQUIRE_REACHY_A05=1 TUNTUN_ALLOW_LIVE_CLOUD=1 .venv/bin/pytest tests/hardware/test_reachy_ptt_loop.py -m reachy_hardware -q
.venv/bin/python scripts/verify_reachy_a05_evidence.py --require-physical
.venv/bin/tuntunctl reachy remove-a05
TUNTUN_ALLOW_REACHY_HARDWARE=1 TUNTUN_REQUIRE_REACHY_A05=1 .venv/bin/pytest tests/hardware/test_reachy_a05_removal.py -m reachy_hardware -q
.venv/bin/tuntunctl reachy decommission-a05
.venv/bin/python scripts/verify_reachy_a05_evidence.py --require-complete
make check
```

---

## Completion boundary

Task 7 completes only the canonical A0.5 supervised diagnostic. Tasks 1–5 may progress now, but real
Q&A and A0.5 acceptance remain blocked until canonical Checkpoint A0's production route authorizer,
atomic SQLCipher budget services, purpose receipts, provider review, and enforcing project limit
exist. The next implementation plan starts governed
local wake/VAD, physical stop/privacy latency evidence, and the accepted 30-turn physical POC gate.
No task in this plan authorizes identity, memory, child use, camera recognition, tools, home actions,
or unsupervised family operation.
