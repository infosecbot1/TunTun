# Reachy A0.5 Fake PTT Loop Runbook

This runbook covers the Task 5 fake end-to-end push-to-talk loop. It is diagnostic evidence for the supervised protocol and cleanup path only. It is not evidence that A0.5, the full POC, Phase 1, cloud voice, or physical Reachy operation is complete.

## Commands

Run one SDK-free fake turn:

```bash
.venv/bin/tuntunctl talk --mode fake --transport simulated
```

Run the Edge simulator directly. This command reserves stdout for binary PTT frames:

```bash
.venv/bin/tuntun-edge simulate-ptt --turn-id 81000000-0000-4000-8000-000000000001 --input-mode core_terminal_toggle
```

## Mode Matrix

| Mode | Transport | Status | Input owner |
| --- | --- | --- | --- |
| `fake` | `simulated` | available in Task 5 | Core terminal toggle |
| `fake` | `ssh` | unavailable until Task 7 hardware commissioning | none |
| `live-cloud` | `simulated` | unavailable until Task 6 cloud gate | none |
| `live-cloud` | `ssh` | unavailable until Tasks 6 and 7 | none |

Unsupported cells fail with `unsupported-talk-mode` before Keychain, budget, audio, network, SSH, or simulator process effects.

## Terminal Toggle

The Core terminal adapter reads one byte at a time while temporarily placing the terminal in cbreak mode. Space toggles `START` then `SUBMIT`; Escape emits `CANCEL`; every other byte is ignored. Repeated Space bytes inside the local debounce interval are ignored. The adapter does not use key-up events, Accessibility APIs, platform keyboard hooks, or key logging, and restores the previous terminal mode in `finally` after success, timeout, error, or Ctrl-C.

## Diagnostic Boundary

The fake loop composes:

- the real Task 1 PTT frame encoding and duplex guard;
- the real Task 2 Edge `ReachyPttSession`;
- the Task 3 `CorePttSessionSupervisor` and ephemeral `VoiceTurnPipeline`;
- an SDK-free Edge simulator with fake media;
- a Core subprocess bridge over bounded stdio.

The fake loop does not import the Edge package into production Core, open a listener, persist audio/transcript/answer content, import a hardware SDK, or make a cloud/provider call. Test code may import Core and Edge together for direct byte-duplex fixtures; production code may not.

## Cleanup And Non-Retention

Each turn is one disposable session. Normal completion performs one session handshake, one capture, one playback, one safety receipt, and one acknowledgement. Failure at capture, STT, LLM, TTS, conversion, or playback closes admission, sends content-free cleanup status, closes provider transport where applicable, restores terminal mode, clears mutable buffers, and tears down owned process/task resources within bounded waits.

The fixed PTT outcome vocabulary is `completed`, `cancelled`, `peer_closed`, `protocol_rejected`, `capture_failed`, `provider_failed`, `playback_failed`, `session_timeout`, and `cleanup_incomplete`. A missing or incomplete safety receipt reports `cleanup_incomplete` even when the original semantic failure was known.

After fake runs, scan only the application-managed test tree for raw sentinel transcript, answer, and PCM bytes. Do not assert brittle global descriptor equality across unrelated runtime activity; use a small bounded-growth check for repeated warm runs.
