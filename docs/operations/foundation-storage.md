# Foundation Storage Runbook

This runbook is for the `0001_foundation` SQLCipher schema and the Task 15
tamper-evident audit chain.

## Startup Order

1. Resolve Keychain roots and storage paths before opening the database.
2. Open the SQLCipher key first; never probe or migrate the file through a
   plaintext SQLite connection.
3. Verify SQLCipher availability, storage path identity, owner-only file
   permissions, WAL sidecar identity, and `PRAGMA cipher_integrity_check`.
4. For an existing non-empty database, create the encrypted pre-migration backup
   before any Alembic migration runs.
5. Run Alembic only on the already-keyed SQLCipher connection.
6. Verify the schema marker in `alembic_version`.
7. Verify the complete audit receipt chain and every retained audit segment.
8. Start application services only after storage and audit verification both pass.

## Fail-Closed Outcomes

Startup stops before service activation when any storage identity, permission,
SQLCipher, integrity, migration, schema-marker, audit-chain, or audit-key check
fails. A missing HMAC key for any retained receipt or segment is a startup
failure, even if newer audit writes use a rotated key.

Audit receipts are append-only. The `audit_receipts_no_update` and
`audit_receipts_no_delete` triggers must remain installed; verifier checks are
for offline tamper detection and do not relax trigger enforcement.

## WAL Checkpoint Rule

After migrations and before declaring storage ready, run a truncating WAL
checkpoint on the keyed SQLCipher connection and require the exact successful
checkpoint result. Do not copy, inspect, or delete WAL/SHM sidecars outside the
qualified storage path guard.

## Key Retention

Keep every audit HMAC key version referenced by any retained `audit_receipts` or
`audit_segments` row. Rotation may change the key ID for new appends, but chain
verification requires all historical key IDs until the corresponding retained
rows are removed by an approved retention process.

## Migration Recovery

For a failed upgrade, leave application services stopped and preserve the failed
candidate, WAL/SHM sidecars, logs, and encrypted pre-migration backup as
evidence. The current foundation storage API provides guarded
`encrypted_backup(source, destination, key)` and `upgrade_encrypted(path, key,
backup)` primitives, and the CLI exposes `tuntunctl storage probe --path
<database>` for sanitized SQLCipher verification. It does not yet provide a
safe migration downgrade or restore command.

Do not put SQLCipher key bytes in shell arguments, environment variables, logs,
or runbooks. Recovery must resolve the database key through the approved
Keychain-backed storage lifecycle, restore only under the qualified storage path
guard, and then rerun the ordinary startup verification path from the beginning.
The missing primitive is an owner-approved restore operation that holds the
ordinary service-stop/core-lease boundary, opens both the primary database and
selected encrypted backup through the qualified SQLCipher path guard, verifies
backup integrity without exposing key bytes, atomically restores encrypted pages
to the primary path with owner-only permissions and sidecar identity checks,
runs the truncating WAL checkpoint, and reruns schema-marker plus complete
audit-chain verification. Until that primitive is implemented and exercised, a
failed migration is a fail-closed operator recovery event rather than an
automated rollback.

Do not run `alembic downgrade` directly against the production database. The
Alembic environment requires a qualified SQLCipher connection, and recovery must
not silently roll storage back through a plaintext, partial-file, or unqualified
path.

## Foundation Tables

The exact `0001_foundation` application table list is:

- `households`
- `devices`
- `sessions`
- `event_receipts`
- `idempotency_receipts`
- `audit_receipts`
- `audit_segments`
- `redaction_receipts`
- `provider_calls`
- `provider_response_receipts`
- `provider_prices`
- `budget_reservations`
- `cost_ledger`
- `runtime_settings`
- `reachy_core_tx_sequences`
- `reachy_duplex_correlations`

The complete migrated SQLite inventory also contains Alembic's
`alembic_version` table. No other non-`sqlite_` tables belong to foundation
storage.
