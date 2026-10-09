# Architecture (Draft)

## Scope v0.1

Build a **central controller**, without installing a proprietary agent on every desktop. v0.1 should accept normalized security events, evaluate immutable policy inputs, produce a proposed defensive action, and record structured audit evidence. Initial actions must be simulated/dry-run only.

## Modules

- Ingestion: Suricata EVE JSON and other log/API adapters (verify licenses before distribution).
- Normalization: event schema with source, confidence, timestamp, target asset and evidence references.
- Policy: deterministic deny-by-default authorization; allowlists, asset ownership, approval gates and expiry.
- Nemesys Engine: **capability-driven orchestration of existing systems**: discover adapter capabilities, select supported actions, compose workflows, execute authorized API operations, and verify/rollback results. It does not implement its own IDS/IPS, honeypot, firewall or attack techniques.
- Evidence: append-only audit references, redaction, retention and export.
- Presentation: CLI first, management API/UI later.

## Deployment

- Linux-native service; no mandatory Docker/Podman.
- A management server alone cannot intercept or inspect arbitrary switched/encrypted traffic.
- Optional SPAN/TAP, network sensors, router/FW integration or existing EDR/MDM as needed.
- Fail-open vs fail-closed is **explicitly configurable by action type** with documented tradeoffs, never silently assumed.

## Non-goals

- Unpermitted penetration of an alleged attack source.
- Deletion or sabotage of third-party systems.
- Attribution of people based solely on IP.
- Endpoint malware removal without explicit endpoint management authority.

## Exit criteria for v0.1

- Deterministic event-to-proposed-action tests and negative authorization tests.
- Zero real network changes by default.
- Clear diagnostic records and reproducible local simulator.
- Dependency license/provenance inventory reviewed.

## Nemesys Engine — orchestration-first design

Nemesys is primarily about **how existing security systems are used together**, not replacing their implementations. It is a coordination plane, not a packet processing plane.

1. **Capability registry**: each connector declares supported actions, target ownership requirements, prerequisites, result verification, expiry/rollback, and health.
2. **Strategy catalog**: declarative strategies map normalized events and authorization context into one or more existing system capabilities. They must be versioned and testable.
3. **Policy gate**: deny by default; every step verifies owned assets, explicit authority, least privilege and approvals.
4. **Executor**: operate through supported APIs/log streams under bounded timeouts; never silently fall back to intrusive techniques.
5. **Feedback loop**: verify actual defensive effects, capture audit/evidence, expire and roll back changes, distinguish estimates from observed consequences.

### Example (conceptual; no live actions in v0.1)

Suricata alert → normalize → Policy gate → Nemesys strategy → propose OPNsense alias change → dry-run audit. Later versions can perform preauthorized reversible actions after extensive testing.

### Explicit non-goal

Do not develop home-grown scanners, packet inspection engines, firewall rule engines or honeypot servers when well-maintained OSS can be integrated. Any exception needs a documented capability or license gap.
