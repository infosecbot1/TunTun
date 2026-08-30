# SQLCipher compatibility checkpoint

Status date: 2026-08-30

## Stop/go decision

**PENDING for the household Intel target.** The implementation behavior gate passes on the
available macOS arm64 host with an ephemeral synthetic 32-byte key, but this host is not the
household Intel Mac required by the release checkpoint. The production CLI also correctly
failed closed because its permanent `tuntun.database` / `root-v1` Keychain item has not yet
been provisioned. That permanent root must be created only by the later owner bootstrap and
runtime ceremony; this probe does not create, replace, print, or persist it.

Hosted Ubuntu and Intel-macOS jobs remain portability evidence to collect in CI. Neither may
replace the physical household Intel-Mac run.

| Gate | Result | Evidence / required follow-up |
| --- | --- | --- |
| Local macOS arm64, direct storage behavior with an ephemeral synthetic key | PASS | Sanitized result below; focused security gate passed 73 tests. |
| Production `tuntunctl storage probe --path … --json` | FAIL CLOSED / PENDING | Keychain returned the public error `missing secret` before the database was opened. Run again after owner bootstrap provisions the exact 32-byte database root. |
| `macos-15-intel` hosted job | PENDING | Run the same unskipped security gate against the locked wheel. |
| `ubuntu-24.04` hosted job | PENDING | Run the same unskipped security gate against the locked wheel. |
| Physical household Intel Mac | PENDING / release blocker | Run the production CLI probe after owner bootstrap and record only its sanitized JSON. |

The local sanitized result was:

```json
{"architecture": "arm64", "cipher": "4.12.0 community", "driver": "sqlcipher3==0.6.2", "integrity_ok": true, "mode": "0o600", "open_flags": 17104898, "operating_system": "macOS-26.6.1-arm64-arm-64bit", "python": "3.12.11", "sqlite": "3.51.1"}
```

Locked dependency evidence:

- Driver: `sqlcipher3==0.6.2`
- Cryptography: `cryptography>=45,<46` (resolved to `45.0.7`)
- `uv.lock` SHA-256: `dc1bd9beb50987fb484ef9a24169c91505e5942fe23d17c9c16dc874ad8fe7c1`
- Probe mode: owner-only database file (`0o600`)
- SQLite open flags: `17104898`

The probe result intentionally contains no key, account name, username, database path,
hardware serial, or other host identifier. The committed tests use only a synthetic key.

## Encrypted-open contract

The adapter accepts exactly 32 immutable key bytes. It performs a fresh no-follow walk of the
owner-private parent, validates or exclusively creates an owner-only regular single-link main
file, qualifies pre-existing sidecars, reserves the canonical path, and then gives SQLCipher
the ordinary absolute pathname with exactly
`READWRITE | FULLMUTEX | PRIVATECACHE | SQLITE_OPEN_NOFOLLOW`. It does not pass `CREATE`, a
URI, a custom VFS, or a qualified file descriptor. The key PRAGMA is the first SQL statement;
a keyed schema read must then succeed before any settings or WAL initialization.

Startup refuses a missing or wrong key, absent SQLCipher support, failed keyed read, failed WAL
activation, unsafe main/WAL/SHM metadata, path drift, or cipher-integrity error. Per the
[SQLCipher API](https://www.zetetic.net/sqlcipher/sqlcipher-api/#pragma-cipher_integrity_check),
`PRAGMA cipher_integrity_check` returns one row per error and no rows on success. Therefore
`integrity_ok=true` means the result set was empty; it does not depend on an invented `"ok"`
row.

WAL and SHM are SQLCipher-managed same-directory sidecars. SQLCipher alone owns every
lock-bearing main/WAL/SHM descriptor while a connection is active or initializing. The
adapter retains only the qualified parent-directory descriptor and immutable metadata
identities. Successful close is ordered SQLCipher/base close, registry release, then parent
close. This avoids an adapter-side descriptor close canceling a healthy peer's POSIX locks.
A SQLCipher close failure retains the lease and parent for explicit retry or process abort and
blocks a newly returned connection.

Maintenance must checkpoint WAL before taking a backup, then verify the encrypted backup
through the governed backup procedure. It must not copy only the main file while live WAL
content is outstanding.

## Concurrency and residual boundary

The process-local open lock covers metadata qualification, reservation, connect,
initialization, publication, close-failure publication, and rollback. It prevents cooperative
races only inside one process. Production startup must acquire the later lifecycle-owned
singleton-instance lock before opening storage; this Foundation task neither implements nor
claims that cross-process protection.

Within that lock, only one lexical path may represent a live main device/inode identity. A
parent rename, alternate case spelling on a case-insensitive filesystem, or other path alias to
an initializing/active identity is rejected. An alias to an identity whose SQLCipher close has
failed receives the same retry-or-abort block; it cannot create a second registry lease.

The DB-API receives a pathname, not a qualified main-file descriptor. The retained parent
descriptor, immutable no-follow metadata identities, registry, and bracket checks detect stale
entries and one-way/non-ABA substitutions, while SQLite `NOFOLLOW` rejects symlink components.
They do not defeat a hostile same-EUID or root process that can perform an undetectable
swap-and-restore between checks. A process able to read this process's memory may also obtain
key material.

This adapter therefore does **not** claim descriptor-relative SQLite open or perfect inode
binding. If protection from that attacker becomes mandatory, stop and require a native
registered VFS or a different driver with a real file-handle API before proceeding.

## Physical-target completion record

After owner bootstrap on the household Intel Mac:

1. Run `uv run pytest tests/security/test_sqlcipher.py -q` with no platform skip.
2. Run `uv run tuntunctl storage probe --path var/probe/foundation.db --json`.
3. Confirm the output has only the nine documented probe fields, reports `architecture` as
   Intel (`x86_64`), has non-empty `cipher`, exact locked `sqlite` and numeric flags,
   `integrity_ok=true`, and `mode="0o600"`.
4. Record the sanitized JSON, date, `uv.lock` SHA-256, hosted Ubuntu result, and PASS decision
   here. Never record the key, username, absolute path, hardware serial, or Keychain details.
