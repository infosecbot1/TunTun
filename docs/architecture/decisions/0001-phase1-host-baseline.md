# ADR 0001: Phase 1 Host Baseline

**Status:** Accepted

**Date:** 2026-08-30

## Context

The Phase 1 plans previously treated the 2020 Intel Mac as the current household Core host and mixed three different meanings: the active development machine, the active household-validation machine, and Intel macOS distribution support. The owner has approved the current Darwin arm64 Mac as the active Phase 1 development and household-validation host after a reviewed temporary Keychain probe passed.

This record contains no username, hostname, serial number, hardware UUID, provisioning UDID, account name, generated Keychain value, absolute home path, or Keychain path.

## Decision

Phase 1 uses these four distinct qualification classes:

1. Active Phase 1 development host: an owner-approved Darwin arm64 MacBook Pro model class `Mac15,7`, Apple M3 Pro class, 12 CPU cores, 36 GB RAM, macOS 26.6.1 build 25G76.
2. Active Phase 1 household-validation and deployment host: the same owner-approved Darwin arm64 Mac. The reviewed temporary Keychain probe is accepted only as baseline-selection evidence until a content-safe receipt is recorded.
3. Supported-distribution CI target: Intel macOS remains mandatory. Hosted Intel CI proves build, install, and test portability only.
4. Future host transition: moving household deployment back to the 2020 Intel Mac is a new target qualification and requires fresh real-host probes bound to the target host, OS, runtime, source commit, locks, artifacts, and receipt set.

There is still exactly one canonical household Core at a time. Hosted CI never commissions a household Core, and the 2020 Intel Mac is not the active household Core unless the full transition probe set passes.

## CI Policy

The `check` job uses only this fixed matrix:

| Runner label | Expected architecture | Purpose |
|---|---|---|
| `ubuntu-24.04` | `x86_64` | Deterministic Linux checks, contracts, lint, typecheck, tests, builds, and private-data scans |
| `macos-26` | `arm64` | Current macOS arm64 distribution build, lock resolution, native imports, and common suite |
| `macos-15-intel` | `x86_64` | Mandatory Intel macOS distribution build, lock resolution, native imports, and common suite |

The workflow must assert `uname -m` before dependency installation. Mutable runner labels, Rosetta substitution, self-hosted labels, matrix `include`/`exclude`, extra axes, provider secrets, and hardware markers are not accepted as ordinary CI evidence.

## Keychain Receipt Policy

The Keychain probe keeps its dual acknowledgement and default content-free `PASS`/`FAIL` output. When release-attributable evidence is needed, it writes a closed JSON receipt conforming to `docs/evidence/phase1-host-probe.schema.json`.

That receipt records only content-safe metadata: receipt ID, UTC time, pass/fail, cleanup verification, Darwin arm64 host class, OS product/build, Python version, keyring version, backend class, source commit, probe-script digest, optional named artifact digests, and an owner-review reference. A failed cleanup can never produce a passing receipt.

## Consequences

- Phase 1 implementation, household validation, POC, preflight, performance, backup/restore, lifecycle, soak, and release evidence run against the approved Darwin arm64 host unless a later ADR changes the active host.
- Intel macOS stays a required distribution target in CI and remains a later public-compatibility responsibility.
- Phase 6 public Intel compatibility still requires real final-artifact lifecycle receipts on a declared Intel target.
- The active 36 GB M3 Pro class host does not satisfy the separate Phase 5 48-64 GB private-inference appliance requirement.
- SQLCipher, native model runtimes, packaging, lifecycle receipts, and performance thresholds remain host, OS, architecture, runtime, lock, and artifact bound.
- The concurrent conversation-plan repair lane owns `docs/superpowers/plans/2026-08-27-tuntun-phase1-conversation-reachy-execution.md`; this ADR records the handoff, and this branch does not edit that file.
