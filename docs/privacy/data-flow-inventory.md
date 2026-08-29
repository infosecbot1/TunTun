# Foundation Data-Flow Inventory

| Data class | Source | Purpose | Processor | Durable location | Egress | Retention/deletion | Key |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Configuration | owner | local settings | core | protected config file | none | owner deletion | none |
| Secrets | owner and platform | authentication and encryption | Keychain | Keychain only | none | explicit revocation | Keychain access control |
| Event receipts | core | replay and state transitions | core | SQLCipher | none | household policy | database key |
| Audit receipts | core | accountability | core | SQLCipher | none | household policy | database key |
| Provider price and budget metadata | manifest and provider | budget authorization | core | SQLCipher | authorized provider metadata only | household policy | database key |
| Model metadata | signed manifest | local model governance | core | repository manifest and local registry | approved model source | manifest replacement | manifest hash |
| Synthetic contract fixtures | deterministic generator | compatibility verification | build and tests | repository | source repository | versioned with contracts | none |
| Raw audio | Reachy microphone | not owned by foundation | not processed by foundation | none | none | not retained | none |
| Conversation transcripts | later-phase speech service | not owned by foundation | not processed by foundation | none | none | not retained | none |
| Camera frames | Reachy camera | not owned by foundation | not processed by foundation | none | none | not retained | none |
