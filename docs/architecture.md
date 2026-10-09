# Architecture (Draft)

## Scope v0.1

Build a **central controller**, without installing a proprietary agent on every desktop. v0.1 should accept normalized security events, evaluate immutable policy inputs, produce a proposed defensive action, and record structured audit evidence. Initial actions must be simulated/dry-run only.

## Modules

- Ingestion: Suricata EVE JSON and other log/API adapters (verify licenses before distribution).
- Normalization: event schema with source, confidence, timestamp, target asset and evidence references.
- Policy: deterministic deny-by-default authorization; allowlists, asset ownership, approval gates and expiry.
- Nemesys Engine: action planning/orchestration; later, authorized firewall rules, controlled decoys and provider reports.
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
