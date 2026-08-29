# Foundation Privacy Threat Model

## Assets

- SQLCipher database and Keychain roots.
- Consent, budget, provider, memory, identity, action, and audit receipts.
- Synthetic contract fixtures and their deterministic generator.

## Actors

- The owner, family subject, and Guest.
- A local attacker with filesystem access but no Keychain authorization.
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

## Out of scope

- Runtime features, provider integrations, robot behaviors, and persistence beyond the Foundation tasks.
- Production incident response and household policy choices implemented by later phases.
