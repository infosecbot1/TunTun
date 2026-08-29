# Foundation Privacy Threat Model

## Assets

- SQLCipher database and Keychain roots.
- Consent, budget, provider, memory, identity, action, and audit receipts.
- Synthetic contract fixtures and their deterministic generator.

## Actors

- The owner, family subject, and Guest.
- A local attacker under a different EUID with filesystem access but no Keychain authorization.
- A dependency, model, provider, or LAN peer that may be malicious.

## Trust boundaries

- Reachy ↔ LAN ↔ Mac.
- browser ↔ owner API.
- Mac ↔ provider.
- build ↔ dependency and model sources.

## Foundation mitigations

- Task 3 private-data and structural scans fail closed on unsafe paths and artifacts.
- Strict contracts, explicit authorization receipts, manifest hashes and audit triggers constrain every boundary.
- SQLCipher and Keychain ownership keep durable private data encrypted and secrets out of repository artifacts.
- The maintainer-only fixture writer rejects group/world-writable creation parents (and therefore non-owner write ACLs), proves a stable process umask against each exact bound creation parent, and retains that parent descriptor and lock throughout publication.
- On Darwin, the writer rejects `ACL_TYPE_EXTENDED` ACLs. On Linux, it permits only the explicit ext-family/XFS/Btrfs/tmpfs/overlayfs/F2FS filesystem set, rejects POSIX access/default ACLs and recognized alternative ACL attributes, and fails closed when filesystem or attribute semantics cannot be inspected; NFSv4, CIFS, rich-ACL, and other non-POSIX ACL filesystems are unsupported.

## Out of scope

- Runtime features, provider integrations, robot behaviors, and persistence beyond the Foundation tasks.
- Production incident response and household policy choices implemented by later phases.
- Concurrent noncooperative same-EUID filesystem mutation or process-umask changes during one fixture-writer invocation; creation parents must have no non-owner write ACLs, and cooperating fixture writers must honor the retained parent-directory flock.
