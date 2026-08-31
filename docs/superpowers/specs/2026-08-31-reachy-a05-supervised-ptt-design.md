# Reachy A0.5 Supervised Push-to-Talk Design

**Status:** Approved implementation slice within the already approved two-stage Phase-1 program
**Scope:** Disposable, owner-supervised Reachy Mini WiFi compatibility diagnostic
**Not a claim of:** completed POC, family-ready beta, or completed Phase 1

This document implements the canonical Phase-1 `A0.5` checkpoint: the delivered-hardware stop/go
record plus one disposable push-to-talk loop over the probed Reachy path. It does not rename or add
a checkpoint. Acceptance requires the capability record, the supervised physical loop, and removal
of the temporary generation and dedicated SSH access; simulator-only evidence is not A0.5.

## Outcome

An adult owner uses a supervised push-to-talk input and hears one answer through Reachy's speaker.
A proved Reachy-local input may provide true hold/release. The exact `conditional_mac_key` fallback
uses a terminal toggle: press once to start capture and press again to submit, because a normal
terminal cannot observe key-up without a privileged macOS event hook. The design never invents a
robot button or asks for Accessibility permission. Core transmits bounded start/submit controls, and
Edge alone starts/stops robot capture. The turn may be English, Hindi, or natural Hinglish. The robot
owns microphone, speaker, EOF/watchdog cleanup, and any proved local stop input; the Mac owns the
ephemeral speech-to-text, reasoning, and text-to-speech pipeline.

This slice exists to learn the delivered Reachy hardware and media behavior quickly without allowing
diagnostic shortcuts to become production architecture.

## User-visible behavior

- In proved Reachy-local mode, hold/release controls capture. In the terminal fallback, one Space
  starts and the next Space submits exactly one turn; Escape cancels. Terminal mode is restored on
  every exit, and no key value is logged.
- A separate supervised cancel/stop action works during capture, transcription, reasoning,
  synthesis, or playback. Reachy-local physical stop is claimed only if the delivered probe proves
  it; EOF/watchdog cleanup is always Edge-local.
- The answer follows the current utterance's English, Hindi, or Hinglish usage.
- The persona is neutral and adult-facing. It does not claim to recognize a family member.
- Motion and gestures are disabled until the delivered robot's stop behavior is qualified.
- Fixed, content-free status codes may be shown to the supervising owner. Audio, transcript, prompt,
  response, and provider bodies are never printed or logged.

## Excluded behavior

The slice has no wake word, child use, face or voice identity, family enrollment, durable memory,
web lookup, tools, home automation, camera workflow, owner console, remote access, or release claim.
Those remain later Phase-1 work. The governed local `Hello Tuntun` wake path is required before the
first POC can be called complete.

## Runtime boundary

```text
Reachy Mini WiFi                                      Core Mac
-----------------                                    --------
official daemon                                      tuntunctl talk
robot-local media                                    one supervised turn
Tuntun edge worker  <== pinned SSH stdio framing ==> in-memory coordinator
local stop/cleanup                                   STT -> LLM -> TTS
no provider key                                      OpenAI key in Keychain
no Tuntun listener                                   outbound cloud calls only
```

- The edge worker runs beside, and never replaces, the official Reachy daemon.
- Robot media uses the delivered SDK's robot-local backend. The exact SDK, daemon, Python ABI,
  formats, and stop APIs are discovered before the dependency is pinned.
- The Mac launches a fixed SSH argv to the commissioned numeric RFC1918 address with dedicated
  owner-only identity and `known_hosts` files, `-F /dev/null`, all forwarding/agent/password/
  keyboard-interactive/proxy/local-command/control-master paths disabled, bounded liveness settings,
  and no remote command token. The dedicated public key is installed with OpenSSH
  `restrict,command="<accepted-python> <commissioned-dispatcher>"`; the pure-standard-library dispatcher
  accepts one canonical bounded stdin request with only the closed
  `status|stage|activate|run_ptt|remove|verify_absent` verb set and takes variable data only through
  that hash-checked protocol. A new Tuntun
  LAN listener is forbidden; the existing SSH listener remains an explicit diagnostic boundary.
  mDNS is discovery-only.
- Client argv is exactly options, `--`, then destination. OpenSSH remote arguments are
  shell-concatenated, so none are supplied; the forced command owns dispatch. The subprocess starts a
  new process session so TERM/KILL escalation targets only its process group.
- Private commissioning material lives under the login home resolved with `pwd.getpwuid`, never an
  environment variable: `~/.local/share/tuntun/reachy-a05/`. The `0700` root contains
  `0600` state, lock, identity, and `known_hosts` files. The atomically published state binds a
  commissioning UUID, monotonic CAS generation/status, current Reachy boot identity, capability
  digest, numeric address, non-root principal, key/host-key/dispatcher commitments, accepted Python/
  SDK/daemon/runtime inventory, fixed remote root, and staged/active deployment digests. Consumers
  reject noncanonical/oversized, stale, symlinked, non-owner, permissive, changed-between-validation-
  and-use, boot-mismatched, or digest-mismatched state.
- A capability is `accepted`, `conditional_mac_key`, or `rejected`. `accepted` requires proved local
  capture and independent local stop inputs. `conditional_mac_key` is legal only when every hard
  media/cleanup/controller/network/SSH/resource check passed but the Reachy-local capture/stop input
  is absent or unqualified; it forces `core_terminal_toggle` and blocks wake, barge-in,
  Reachy-local-stop, and unsupervised claims. Missing AEC/DoA/RTC are recorded limitations but do not
  by themselves choose the input mode. Every unknown fact or hard-check failure rejects.
- EOF, process exit, timeout, Ctrl-C, provider failure, and protocol rejection all converge on the
  same idempotent cleanup path on both sides.
- A disconnected turn is terminal. Reconnect starts a new turn and never resumes prior audio or
  playback.

## Shared framing protocol

Core and Edge share one codec under `tuntun_contracts.poc`; Core must never import Edge.
The disposable types are intentionally omitted from the frozen v1 contract registry and root
`tuntun_contracts` exports.

Every frame begins with this 32-byte big-endian prefix:

```text
magic[4] = "TTPT"
version[1] = 1
kind[1] = 1(control) | 2(PCM)
flags[2] = 0
sequence[4]
payload_length[4]
turn_id[16] = UUID bytes
```

Limits are checked from the prefix before payload allocation:

- control payload: 4,096 bytes maximum;
- PCM payload: 1 through 65,536 bytes and no more than 200 ms;
- each decoder feed: 65,536 bytes maximum, with larger wire frames arriving in bounded chunks;
- PCM per direction: 8,388,608 bytes maximum;
- sample-derived media duration per direction: 90 seconds maximum;
- monotonic media wall time per direction: 90 seconds maximum from start through end/stop;
- PCM ingress rate: 50 frames in any rolling second maximum;
- sequence: starts at zero and increments exactly by one without wrap.

Each side has exactly one bounded outbound writer and sequence allocator. Producers enqueue
unsequenced semantic drafts; only that writer selects a draft, assigns the next sequence, encodes the
complete frame, and writes/drains it. A reserved cleanup lane preempts and drops queued normal media
after cleanup latches; a single coalesced heartbeat becomes due at its one-second deadline; remaining
input/media drafts stay FIFO under a 64-item bound. No producer writes bytes directly. This prevents
heartbeat/media/abort and capture/receipt races from duplicating a sequence, interleaving bytes, or
starving cleanup/ack.

The diagnostic transport format is
`AudioFormat(sample_format="s16le", sample_rate_hz=16000, channels=1, interleaved=False,
channel_layout="mono")`. Edge performs an explicit bounded conversion from the probed native capture
format; Core converts synthesized audio to the same transport format before framing. At 32,000 bytes
per second, a 90-second utterance fits inside the independent 8 MiB ceiling. No code assumes that
Reachy's native format already matches. PCM must be sample-aligned; each frame is therefore at most
6,400 bytes in this format, and media duration is derived from sample count rather than network time.

Control payloads are canonical UTF-8 JSON envelopes with exactly `kind`, `turn_id`, and `payload`.
The closed kind selects one closed payload model: `session_open|session_ready` use
`{"input_mode": "reachy_local"|"core_terminal_toggle"}`, media start controls use
`{"audio_format": AudioFormat}`, `safety_receipt` uses `{"receipt": PttSafetyReceipt}`, `safety_ack`
uses `{"accepted": bool}`, `abort|error` use `{"reason_code": registered_code}`, and
`ptt_start|ptt_submit|heartbeat|capture_end|playback_end|stop|cancel` use `{}`. The prefix, envelope,
and nested safety receipt turn IDs must agree. Unknown, noncanonical, duplicated-key, reordered,
truncated, oversized, old-turn, post-final, or direction-invalid data poisons the stream. The
implementation never scans for a later magic value.

The first closed control set is:

- `session_open`, `ptt_start`, `ptt_submit`, `heartbeat`, `playback_start`, `playback_end`, `abort`,
  and `safety_ack` from Core to Edge;
- `session_ready`, `capture_start`, `capture_end` from Edge to Core;
- `stop`, `cancel` from Edge to Core;
- `safety_receipt` from Edge to Core after local cleanup;
- `error` in either direction with a registered content-free reason code.

`PttSafetyReceipt` is disposable and does not alter the frozen v1 model. It reports the current turn
and all six local cleanup facts: new capture rejected, recording stopped, playback stopped, motion
stopped, audio-reactive behavior disabled, and owned buffers cleared. A false field remains truthful
failure evidence. `safety_ack` reports whether Core accepted the receipt as complete; it acknowledges
receipt delivery even when the diagnostic outcome is failure. A positive acknowledgement is legal
only when all six receipt facts are true. A negative acknowledgement is always conservative,
closes the turn as `cleanup_incomplete`, and is valid even when the receipt itself reports six true
facts.

A malformed frame or a duplex violation permanently poisons and aborts the affected decoder/guard;
it is never finished, reused, replaced, or resynchronized, and no further inbound acknowledgement
is parsed. Local cleanup still runs from the same monotonic T0. A monotonic receipt-attempt latch is
set before an ordinary receipt send or before an emergency pair starts, so at most one receipt can
ever be attempted. Poison after that latch, or poison while any send is active, closes the transport
without emergency output. Before an eligible emergency pair, the writer atomically removes and
fails any unsent guarded terminal cleanup draft so that draft cannot strand the bypass lane.
Otherwise the idle sole sequence-owning writer immediately attempts
`error(protocol_rejected)` while local observations run. Only a positive full send advances its Edge
sequence; any exception, timeout, cancellation, or ambiguous/partial send permanently closes the
transport and suppresses the receipt. When observations finish, the writer may follow with one
truthful `safety_receipt`. The two canonical current-turn frames share the single T0+2.5 deadline
and deliberately bypass only the poisoned guard. The stream is never treated as acknowledged and
the result is `cleanup_incomplete`. This is the only post-poison wire exception.

Both media start controls must carry `TRANSPORT_AUDIO_FORMAT` exactly. Cleanup controls and the
receipt/ack handshake remain admissible after media byte/sample/rate/wall limits have expired; an
expired media lane can never disable stop. If Edge stop/cancel/error and Core abort/error cross in
flight, the first latches cleanup permanently and every later valid current-turn cleanup request is
idempotent. No cleanup request can reopen capture, provider, or playback admission.

Each direction has an explicit closed grammar:

- Core creates the turn and sends `session_open` as Core sequence zero. Edge echoes the exact
  commissioned input mode in `session_ready` as Edge sequence zero. No input or media is admitted
  before the handshake.
- In `core_terminal_toggle` mode, Core sends exactly one `ptt_start`; Edge answers with
  `capture_start` only after robot capture is open. A fast second keypress is latched while Edge arms;
  Core may send `ptt_submit` before or after `capture_start`. Edge closes capture before sending
  `capture_end`. In `reachy_local` mode, `ptt_start|ptt_submit` are forbidden and Edge begins directly
  with `capture_start`/`capture_end` from the proved local input.
- Edge accepts PCM only while capturing. A normal capture sends `capture_end`; the Edge later sends
  one `safety_receipt` after normal playback cleanup.
  `stop|cancel` may preempt capture or the later STT/LLM/TTS/playback wait and must be followed by one
  `safety_receipt`. An Edge `error` also requires a receipt.
- Core to Edge starts playback only after `capture_end`: `playback_start`, one or more PCM frames,
  `playback_end`. `abort|error` may instead request Edge cleanup from any nonfinal state.
- `safety_receipt` must be followed by exactly one Core `safety_ack`; only then is the duplex turn
  normally closed. Input after the acknowledgement is rejected.
- One duplex supervisor owns both sequence spaces and enforces handshake, input-mode, and
  capture-end-before-playback ordering. Its `finish()` succeeds only after `safety_ack` with no
  partial frame.
  `abort()` is idempotent from every state, clears owned framing buffers, and permits no reuse.

The closed duplex states are
`wait_session_open|wait_session_ready|ready|arming|arming_submit_pending|capturing|capture_submit_pending|capture_closed|playing|playback_closed|cleanup_required|receipt_received|acknowledged|aborted`.
The exact normal transitions are:

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
receipt_received --Core safety_ack--> acknowledged
```

Core `heartbeat` keeps every state from `wait_session_ready` through `cleanup_required` unchanged.
Before a receipt, Edge `stop|cancel|error` or Core `abort|error` latches `cleanup_required`; only a
safety receipt then advances state. Cleanup phase is monotonic: in `receipt_received`, another valid
current-turn cleanup request keeps `receipt_received`, and a correctly framed/sequenced in-flight
heartbeat, session-ready, input, or media frame is returned as `late_discarded` until ack. It extends
no deadline and cannot regress or advance state. The same late-discard rule applies in
`cleanup_required`. Receipt and ack are the only cleanup-phase advances; all input after
`acknowledged` rejects. Late media remains subject to framing/byte/rate/duration limits.
Malformed, wrong-turn, or wrong-sequence data remains a protocol failure while the independent local
cleanup task continues. Duplicate start/submit, submit-before-start, Core PTT controls in local mode,
Edge capture before ready, mode mismatch, and empty capture reject. If submit arrives before useful
PCM, Edge reports `capture_failed` and cleans up rather than sending an empty `capture_end`.

The incremental decoder accepts empty input as a no-op and at most 65,536 input bytes per `feed()`.
It supports fragmented and coalesced frames within that bound, returns at most 64 frames per call,
and never buffers more than one bounded wire frame. `finish()` closes only an empty partial buffer;
truncation, invalid data, or reuse after finish/error is rejected with one closed content-free error
code. A feed containing a valid frame followed by invalid data returns no partial result, clears the
decoder's owned bytes, and permanently poisons that decoder.

## Turn state and safety

Only one turn may be active. Every media/control item is bound to its turn ID and sequence. The
supervisor is constructed with exactly one input mode and cannot change it during a turn.

At `run()` T0, before creating a runtime child or touching the guard, transport, or media ports,
Edge clears and verifies its two distinct owned media buffers. Stale capture or playback bytes can
never resume into a new turn. A clear or verification failure runs bounded local-only cleanup and
ends `cleanup_incomplete`.

1. The supervisor completes the mode handshake. In terminal mode Core sends start/submit as above;
   in proved local mode Edge reads local capture and stop inputs. Edge opens capture in a mutable
   owned buffer.
2. Edge accepts each native capture read only as an exact `bytes` value of 1 through 65,536 even
   bytes, rejects a larger read before a buffer copy or wire effect, and losslessly rechunks accepted
   audio while converting the probed native format into the bounded transport format.
   `capture_start`, every PCM draft, and `capture_end` carry their absolute capture/turn deadline;
   capture close is bounded by both submit+2 seconds and the original 90-second capture wall.
3. Release or submit causes Edge to close input before sending `capture_end`; Core invokes no STT
   until that control arrives.
4. Core invokes STT, LLM, and TTS sequentially with one cancellation scope.
5. Edge plays only frames for the still-current turn and rejects late output.
6. Normal completion and every non-protocol failure run the receipt/ack cleanup handshake, clear
   owned mutable buffers, join owned tasks, and close the turn. Protocol poison uses only the
   terminal best-effort emergency path defined above; it never resumes inbound parsing.

Clean EOF and transport receive exceptions preserve `peer_closed` as their first semantic reason.
The terminal reader cannot then receive an acknowledgement, so the universal missing-ack rule
makes the final public outcome `cleanup_incomplete`. A non-bytes or oversized receive result is a
local transport-adapter contract failure whose semantic and final outcome is `cleanup_incomplete`.
Those cases retain the ordinary guarded error/receipt path and never poison the decoder or guard;
EOF with buffered truncated framing still poisons.

Edge cleanup is authoritative once requested. Stop/abort has permanent precedence: after cleanup is
latched, correctly framed current-turn in-flight input/media controls are bounded, consumed, and
discarded without reopening an admission gate. Repeated current-turn cleanup requests are
idempotent. Edge synchronously closes capture and playback gates and
drops owned buffers first, then attempts recording, playback, motion, and audio-reactive stops
independently under one absolute deadline so one hung component cannot suppress siblings. On a
still-valid stream it emits a truthful `safety_receipt` and waits boundedly for `safety_ack`; a
poisoned stream follows only the terminal emergency rule and reads no acknowledgement. Core
continuously reads controls while provider work runs; `stop|cancel` cancels the active
provider/playback task immediately. Core-origin
failure, timeout, or Ctrl-C closes admission and sends `abort` immediately on the reserved priority
lane while provider cancellation runs concurrently from the same monotonic cleanup T0. It drops late
results, acknowledges the safety receipt, joins owned tasks within their separate bound, and only
then escalates the SSH process group. A partial receipt is failed evidence.

The diagnostic freezes these outer bounds: 5 seconds for session ready; 2 seconds for capture open
after start and capture close after submit; 90 seconds capture; 30 seconds STT, 45 seconds reasoning,
30 seconds TTS, 120 seconds total post-capture provider work; 90 seconds playback; and 310 seconds for
the complete turn. Core sends `heartbeat` every second; Edge invokes local cleanup after 5 seconds
without any valid Core frame, and heartbeats extend neither media nor turn limits. An injected
absolute sleeper that raises, self-cancels, or returns before the requested deadline is an internal clock fault
ending `cleanup_incomplete`, never a timeout or heartbeat busy-loop. Every `now()` sample is finite
and nondecreasing; a raise, nonfinite value, or reversal synchronously closes media gates, owned
buffers, and admission as `cleanup_incomplete`. Core and local cleanup triggers retain their sampled
acceptance timestamp across lock waits, so the exact T0+310 turn deadline wins while a valid
predeadline trigger keeps its original outcome. After such a fault, ordinary media and wire effects
remain forbidden, while local stop observations, owned-task joins, and transport teardown retain
their original bounds through an event-loop monotonic fallback anchored to the last advancing valid
clock sample. A fault during an injected sleep cancels and joins that sleeper before switching; it
never grants a fresh cleanup interval. Cleanup is one
exactly-once shared task: stop observations finish or time out by T+2 seconds under simultaneous
local stop, EOF, watchdog, and Core abort. On a still-valid stream the truthful receipt is
encoded/sent by T+2.5 and acknowledgement finishes by T+3.5. On a poisoned stream the emergency
error starts immediately at T0 while observations run; if it completes, the truthful receipt follows
and both sends share T+2.5, with no acknowledgement read. Core enqueues `abort` at T0 while
concurrently closing provider transports within 0.5 seconds and joining them within 1 second;
provider teardown never delays the 3.5-second abort/receipt/ack path. Admission stays closed while
transport close and owned-task joins finish by the separate T+4.0 teardown deadline. SSH connect is
5 seconds, server-alive is
2 seconds with count 2, stdin-close grace is 1 second, TERM grace is 1 second, and KILL observation
is 1 second. Timing failure yields content-free failed evidence and no unbounded join or retry.
Caller cancellation while acquiring the lifecycle lock, adopting cleanup, handling any
post-startup exit, or rolling back a partially created runtime is remembered; the same bounded
cleanup/rollback ownership finishes before cancellation is re-raised.

Python, the SDK, operating system, and provider may retain copies outside Tuntun's owned buffers;
buffer clearing is therefore best-effort cleanup, not cryptographic erasure.

## Cloud boundary

- Fake providers are the default and are required for deterministic tests.
- Live cloud is absent until the already approved durable Phase-1 route-authorizer, purpose-specific
  consent/privacy receipts, atomic SQLCipher budget reserve/settle/release path, current provider
  review, and enforcing project limit are implemented and pass Checkpoint A0.
- Once those gates exist, live cloud is a separate explicit owner-supervised mode with a disclosure
  at session start; this diagnostic adds no substitute authorization or in-memory monthly cap.
- The OpenAI credential is read from macOS Keychain via `SECRET_IDS["openai"]`; it is never placed in
  environment variables, argv, config files, logs, or sent to Reachy.
- Provider/model/host are allowlisted, TLS verification is enabled, redirects and telemetry are
  disabled, timeouts are bounded, SDK retries are disabled, and Responses requests use
  `store=false`.
- Every STT, reasoning, and TTS attempt consumes a real purpose-bound route authorization and atomic
  durable reservation. The Asia/Singapore S$100 soft and S$150 hard monthly limits remain
  authoritative across restart and concurrent processes.
- No tool definitions are sent. No transcript, answer, or provider body becomes a live receipt.
- The only mode/transport combinations are `fake/simulated`, `fake/ssh`, and, after Checkpoint A0's
  gates pass, `live-cloud/simulated` and `live-cloud/ssh`. No option silently substitutes another.

## Acceptance evidence

The simulator gate requires:

- 50 fake turns with no duplicate playback;
- English, Hindi, and Hinglish turn routing;
- cancellation during capture, STT, LLM, TTS, and playback;
- malformed, duplicate, reordered, truncated, oversized, post-final, and old-turn frame rejection;
- disconnect/reconnect, child exit, timeout, WAN/provider error, and late-result injection;
- no orphan tasks/processes and no growing file-descriptor count;
- a scan proving no application-managed audio, transcript, prompt, answer, or provider body was
  written.

Physical evidence requires the Mac and Reachy on the same trusted home LAN and records only
sanitized capability facts: exact version/dependency commitments, observed media formats, exactly
20 stop records and recomputed latency distribution, EOF/abort/cancel results, three closed language
outcomes, live-cloud/removal/decommission/daemon-health status, source commit, and closed limitations.
It must not contain hostname, IP/MAC, principal, serial, key, SSID, audio, transcript, answer,
screenshot, provider body, or free-form note. Completion mode converts every hardware skip, missing
result, or absent live-cloud run into failure rather than acceptance.

Before the physical turn, the approved Mac and Reachy are single-homed on the same ASUS/AiMesh L2;
the Mac's direct BE800 link, forwarding, Internet Sharing, and bridging are off. The delivered SDK,
daemon, interpreter, media, stop, app-lock, and competing-controller behavior are probed first. Exact
accepted versions and dependency hashes are pinned. A generation venv uses the exact qualified base
interpreter with `--system-site-packages`; every vendor/native/third-party dependency must already be
present in the accepted onboard runtime. Only the Contracts and Edge `py3-none-any` project wheels
are transferred, hash-verified, and installed offline with `--no-deps`. A missing or drifted onboard
dependency rejects the device; the bundle never supplies a native or support wheel.

Deployment uses the forced command's bounded, content-addressed stdin protocol rather than the PTT
codec. Stage/activate/remove requests carry an operation UUID and expected commissioning-state
generation. Mutations are CAS-idempotent; after an uncertain EOF/timeout, Core reads status and
reconciles exact digests before retry. The remote root has fixed owner-only `bootstrap`, `.staging`,
and `generations/<bundle-sha256>` locations on one filesystem, no client path and no mutable current
symlink. `run_ptt` reads the atomically published active digest and execs only that validated
generation.

Before any authentication setting or credential is changed, commissioning proves an independent
vendor-supported owner admin/recovery path that uses no Tuntun key or state and can undo the planned
hardening. It re-proves that path after password and keyboard-interactive login are disabled; either
failed proof rejects the SSH boundary before remote-state seeding. Before the forced key is accepted,
the attended ceremony seeds an atomic remote-state-v1 record bound
to the commissioning ID, state generation, boot/capability/runtime/dispatcher/authorized-key
commitments, fixed root, and empty staged/active generations. `status` authenticates the
commissioning ID but deliberately returns current generation/status/digests even when the caller's
expected generation is stale, enabling safe reconciliation. Without both recovery proofs, the
disposable SSH path is rejected because it could not later decommission itself safely.

All physical tests and the verified sanitized result run while that generation is active. Cleanup
then removes the exact generation and proves absence plus official-daemon health while the restricted
dispatcher remains. In an attended vendor/local session it removes the exact authorized-key line,
proves that identity can no longer authenticate, removes the dispatcher/root, verifies the daemon
again, deletes the Mac identity/known-host files, and retains only a content-minimized revoked local
state tombstone. It never restores a weaker default/password SSH setting.

The A0.5 slice is accepted only when the canonical hardware stop/go facts, non-skipped physical
result, owner/synthetic language loop through the real durable cloud gates, and complete disposable
rollback all verify. Until Checkpoint A0's production authorizer/budget prerequisites exist, the
fake simulator and physical media work are useful progress but not accepted A0.5. The next gate remains the
governed local `Hello Tuntun` wake/VAD path, local acknowledgement P95 at or below 500 ms, and
stop/privacy P95 at or below 250 ms.
