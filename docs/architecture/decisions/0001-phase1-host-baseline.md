# ADR 0001: Phase 1 Host Baseline

**Status:** Accepted

**Date:** 2026-08-30

## Context

The Phase 1 plans previously treated the 2020 Intel Mac as the current household Core host and mixed three different meanings: the active development machine, the active household-validation machine, and Intel macOS distribution support. The owner independently approved the current Darwin arm64 Mac as the active Phase 1 development and household-validation host. A reviewed temporary Keychain probe informed that baseline selection, but neither that result nor any replacement diagnostic receipt grants commissioning authority.

This record contains no username, hostname, serial number, hardware UUID, provisioning UDID, account name, generated Keychain value, absolute home path, or Keychain path.

## Decision

Phase 1 uses these four distinct qualification classes:

1. Active Phase 1 development host: the owner-approved inventory target currently observed as Darwin arm64. Its `Mac15,7`, Apple M3 Pro class, 12 CPU cores, 36 GB RAM, and macOS 26.6.1 build 25G76 values are descriptive inventory only.
2. Active Phase 1 household-validation and deployment host: that same independently owner-approved inventory target. The reviewed temporary Keychain probe is baseline-selection evidence only; a later content-safe receipt remains diagnostic evidence only.
3. Supported-distribution CI target: Intel macOS remains mandatory. Hosted Intel CI proves build, install, and test portability only.
4. Future host transition: moving household deployment back to the 2020 Intel Mac is a new target qualification and requires a fresh trusted owner approval bound to an opaque inventory target plus real-host probes bound to that target, OS, runtime, source commit, locks, artifacts, and receipt set.

There is still exactly one canonical household Core at a time. Hosted CI never commissions a household Core, and the 2020 Intel Mac is not the active household Core unless independent owner approval and the full transition probe set pass. Architecture, model class, product name, and model year are never commissioning-authority identifiers.

## CI Policy

The `check` job uses only this fixed matrix:

| Runner label | Expected architecture | Purpose |
|---|---|---|
| `ubuntu-24.04` | `x86_64` | Deterministic Linux checks, contracts, lint, typecheck, tests, builds, and private-data scans |
| `macos-26` | `arm64` | Current macOS arm64 distribution build, lock resolution, native imports, and common suite |
| `macos-15-intel` | `x86_64` | Mandatory Intel macOS distribution build, lock resolution, native imports, and common suite |

The workflow's first matrix-job step has the exact reviewed key set (`name`, `shell`, `run`), uses `/bin/bash --noprofile --norc -p -euo pipefail {0}`, and executes the exact `/usr/bin/uname -m` assertion before checkout, any third-party action, setup, or dependency installation. Workflow/job/step `env`, job/step `if`, `continue-on-error`, extra step keys, comment-only/no-op, altered-command, reordered, relative-`uname`, and matrix skip/neutralization mutations are rejected by full-policy tests. Mutable runner labels, Rosetta substitution, self-hosted labels, matrix `include`/`exclude`, extra axes, provider secrets, and hardware markers are not accepted as ordinary CI evidence.

## Keychain Receipt Policy

The Keychain probe keeps its dual acknowledgement and default content-free `PASS`/`FAIL` output. When diagnostic evidence is needed, it first claims a previously absent unique destination with a fresh run UUIDv4, attempt UUIDv4, and completion binding, fsyncs that fail-closed claim, and only then opens the Keychain provider. A completed run consists of the closed receipt at that path plus its closed `docs/evidence/phase1-host-probe-completion.schema.json` companion; the acceptance verifier requires both. Publication is exclusive; an older receipt is never overwritten, and a failed attempt remains occupied so the same path cannot be retried or mistaken for a pass. Receipt version 1 is deliberately an active-target Darwin arm64 diagnostic and cannot be reused as Intel-transition evidence; a later Intel household transition requires a new reviewed versioned target probe plus the independent approval and lifecycle receipts in this ADR.

That receipt records only content-safe metadata: receipt ID, diagnostic-only evidence use, fresh UUIDv4 run and attempt IDs, a real canonical RFC 3339 UTC time, pass/fail, cleanup verification, Darwin arm64 host class, OS product/build, Python version, keyring version, backend class, clean script-repository commit, probe-script digest, optional named artifact digests, an opaque SHA-256 commitment to an external owner-approval record, and the completion binding. The external commitment is domain-separated and includes an independently stored random nonce so predictable approval text cannot be enumerated. Before Keychain access and again after cleanup immediately before receipt finalization, the probe captures a bounded content-safe source snapshot from the script-derived repository root. Git starts through a fixed isolated Python `-I -S` helper that inherits the retained repository descriptor, calls `fchdir`, and immediately `execve`s `/usr/bin/git`; a lexical-root ABA swap therefore cannot redirect it. The proof requires exact HEAD, clean tracked/untracked status, stage-zero inventory, default assume-unchanged/skip-worktree/fsmonitor flags, no local filters or attributes, recursively retained submodule roots/commits/states, and a nofollow descriptor read of every stage-zero working object whose actual bytes, executable/symlink mode, and locally computed Git blob OID match the index. Replacement refs and lazy fetch are disabled, and one shared entry/byte/repository/time budget covers the recursive proof. The two snapshots must compare exactly. A failed cleanup or source re-proof can never produce a passing receipt.

The receipt is not self-authorizing. `validate_phase1_host_probe_receipt` performs structural validation only and can never accept evidence or authorize commissioning. `verify_phase1_host_probe_receipt` additionally requires the closed completion companion and compares the expected run ID, attempt ID, external owner-approval commitment, source commit, probe-script digest, receipt digest, and completion binding, but its successful result is still diagnostic evidence only. Acceptance requires an independent trusted verifier to authenticate the external approval record and supply every expected binding.

The durable completion companion's exclusive publication and parent-directory fsync are the operation commit point. The winning invocation retains both the original receipt claim and its exclusively published completion descriptor through final path-based acceptance and rechecks their exact identities afterward. A single-name identical foreign swap forces `main()` to fail, restores the owned receipt claim or retires the owned completion, and preserves the unrelated foreign artifact. If both names are replaced with a byte-identical, independently acceptable copy of this exact invocation, failure cleanup uses the private expected-binding verifier, opens the currently named owner-only completion nofollow, and truncates or unlinks only that matching companion; it then re-verifies that the pair rejects. Invalid or differently bound foreign data is never modified, and a cleanup-operation failure is propagated only after the named pair has been shown rejected. A process crash after the completion fsync but before the caller observes exit `0` can nevertheless leave valid diagnostic evidence; the verifier treats the durable completion record, not observation of process exit, as authoritative completion. Every deterministic exception before that commit point lacks an acceptable passing receipt/completion pair, and every deterministic `main()` return `1` is rejected even when it durably records a completed failing probe. Eliminating the narrow post-commit/pre-return crash ambiguity, or an active same-user adversary replacing both names after the final bounded observation, would require a separately trusted supervisor-signed exit receipt, which this diagnostic probe does not claim to provide.

Unique physical-host identity is intentionally absent from this diagnostic receipt for privacy. Consequently, the receipt cannot prove which physical Mac ran it. Later commissioning must independently bind an opaque host record and target-held public key to the authenticated owner approval and lifecycle evidence; architecture, model, product, and year observations cannot replace that binding.

## Consequences

- Phase 1 implementation, household validation, POC, preflight, performance, backup/restore, lifecycle, soak, and release evidence run against the approved Darwin arm64 host unless a later ADR changes the active host.
- Intel macOS stays a required distribution target in CI and remains a later public-compatibility responsibility.
- Phase 6 public Intel compatibility still requires real final-artifact lifecycle receipts on a declared Intel target.
- The active 36 GB M3 Pro class host does not satisfy the separate Phase 5 48-64 GB private-inference appliance requirement.
- SQLCipher, native model runtimes, packaging, lifecycle receipts, and performance thresholds remain host, OS, architecture, runtime, lock, and artifact bound.
- The concurrent conversation-plan repair lane owns `docs/superpowers/plans/2026-08-27-tuntun-phase1-conversation-reachy-execution.md`; this ADR records the handoff, and this branch does not edit that file.
