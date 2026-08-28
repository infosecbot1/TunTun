# Tuntun

Tuntun is a local-authority, bilingual family-assistant framework designed around a Reachy Mini Wireless, an owner-managed Intel Mac, and explicitly bounded integrations for home automation, cameras, media, private AI, desktop assistance, robotics, and remote access.

## Project status

The repository currently contains the reviewed six-phase architecture, UI/UX specification, security/privacy assurance package, and executable implementation plans. It does **not** yet contain the production runtime. Start with the disposable Reachy voice proof of concept, then promote only capabilities whose named evidence gates pass.

## Start here

1. Read the [six-phase master roadmap](docs/superpowers/plans/2026-08-27-tuntun-six-phase-master-roadmap.md).
2. Use the [Phase 1 anchor plan](docs/superpowers/plans/2026-08-27-tuntun-phase1-anchor.md) as the implementation index.
3. Begin with the Mac and delivered-Reachy inventory, then the isolated 10-working-day voice POC in [deliverable S](docs/superpowers/specs/2026-08-27-tuntun-program-assurance-delivery-i-s.md#s-first-proof-of-concept-plan--mac--reachy-voice-loop).
4. Do not commission lights, cameras, private AI, desktop control, robots, plugins, or remote access ahead of their phase entry and hardware gates.

## Architecture specifications

| Scope | Specification |
|---|---|
| Phase 1 — family assistant anchor | [Architecture](docs/superpowers/specs/2026-08-27-tuntun-phase1-anchor-design.md) |
| Phase 2 — home automation | [Architecture](docs/superpowers/specs/2026-08-27-tuntun-phase2-home-automation-design.md) |
| Phase 3 — vision, presence, and storage | [Architecture](docs/superpowers/specs/2026-08-27-tuntun-phase3-vision-presence-storage-design.md) |
| Phase 4 — whole-home voice, media, and displays | [Architecture](docs/superpowers/specs/2026-08-27-tuntun-phase4-voice-media-displays-design.md) |
| Phase 5 — private AI, desktop assistance, and robotics | [Architecture](docs/superpowers/specs/2026-08-27-tuntun-phase5-private-ai-desktop-robotics-design.md) |
| Phase 6 — remote access and product hardening | [Architecture](docs/superpowers/specs/2026-08-27-tuntun-phase6-remote-access-product-hardening-design.md) |
| Program architecture and contracts | [Deliverables A–H](docs/superpowers/specs/2026-08-27-tuntun-program-architecture-a-h.md) |
| Security, privacy, operations, cost, and POC | [Deliverables I–S](docs/superpowers/specs/2026-08-27-tuntun-program-assurance-delivery-i-s.md) |
| All four product surfaces | [Six-phase UI/UX](docs/superpowers/specs/2026-08-27-tuntun-six-phase-ui-ux-design.md) |

## Implementation plans

| Workstream | Plan |
|---|---|
| Phase 1 coordination | [Anchor](docs/superpowers/plans/2026-08-27-tuntun-phase1-anchor.md) |
| Phase 1 foundations | [Foundation](docs/superpowers/plans/2026-08-27-tuntun-phase1-foundation-execution.md) |
| Phase 1 Reachy and conversation | [Conversation and Reachy](docs/superpowers/plans/2026-08-27-tuntun-phase1-conversation-reachy-execution.md) |
| Phase 1 controlled web/search | [Controlled web](docs/superpowers/plans/2026-08-27-tuntun-phase1-controlled-web-execution.md) |
| Phase 1 identity and seven memories | [Identity and memory](docs/superpowers/plans/2026-08-27-tuntun-phase1-identity-memory-execution.md) |
| Phase 1 owner console | [Control console](docs/superpowers/plans/2026-08-27-tuntun-phase1-control-console-execution.md) |
| Phase 1 release | [Release](docs/superpowers/plans/2026-08-27-tuntun-phase1-release-execution.md) |
| Phase 2 | [Home automation](docs/superpowers/plans/2026-08-27-tuntun-phase2-home-automation-execution.md) |
| Phase 3 | [Vision, presence, and storage](docs/superpowers/plans/2026-08-27-tuntun-phase3-vision-presence-storage-execution.md) |
| Phase 4 | [Voice, media, and displays](docs/superpowers/plans/2026-08-27-tuntun-phase4-voice-media-displays-execution.md) |
| Phase 5 | [Private AI, desktop assistance, and robotics](docs/superpowers/plans/2026-08-27-tuntun-phase5-private-ai-desktop-robotics-execution.md) |
| Phase 6 | [Remote access and product hardening](docs/superpowers/plans/2026-08-27-tuntun-phase6-remote-access-product-hardening-execution.md) |
| Cross-phase UI | [UI execution](docs/superpowers/plans/2026-08-27-tuntun-six-phase-ui-execution.md) |

## Locked household baseline

- Reachy Mini Wireless with “Hello Tuntun,” English, Hindi, and natural Hinglish switching.
- 2020 Intel MacBook Pro with 16 GB RAM as the initial local authority host.
- Canonical family policy classes are owner, adult, K2, N1, and Guest; guarded-child rules and locally encrypted typed persona traits drive age- and context-appropriate answers.
- Home Assistant Green; twelve MOES Zigbee ceiling lights; existing MZHUB tested first as a local Matter bridge.
- Reolink TrackMix in the hall/bedroom pathway and two exact-model-pending E1-family kitchen cameras; camera audio off, no Reolink-derived identity, and no raw-media path to an LLM, VLM, memory, Home Assistant, or cloud. Any later selected-frame seam is RAM-only, local, non-generative anonymous CV behind its Phase 5 gate.
- Existing encrypted external SSD first; seven-day low-resolution continuous camera retention and 90-day full-resolution native-event retention; NAS decision deferred until measured evidence.
- Privacy Shield stops Tuntun application processing but truthfully leaves the independently controlled Reolink recorder running unless the owner separately pauses it.
- Samsung Neo LED 49-inch and TCL 42-inch televisions start as manual HDMI displays; exact-unit control remains evidence-gated.
- Archer BE800 outer/primary router with downstream ASUS GT-AX6000 and three AX5400 AiMesh nodes. The inventoried office Mac is the Tuntun Core host and, for the family-ready baseline, is single-homed on the trusted ASUS/AiMesh LAN with its direct BE800 cable disconnected while Tuntun runs. No public inbound service is allowed; any later dual-homed mode requires its separate fail-closed qualification.
- LAN-only through Phase 5. Phase 6 may add owner-only Tailscale access, disabled by default and still protected by application authentication.
- Phase 5 uses staged task-specific local migration; the existing Raspbot and LILYGO hardware remain supervised/optional and gain no model-generated motion authority.
- S$100 monthly cloud soft warning and S$150 hard stop.

The framework is intended for Apache-2.0 publication with synthetic fixtures only. Family data, credentials, biometric material, recordings, memories, private evidence, and household configuration never belong in the public repository.
