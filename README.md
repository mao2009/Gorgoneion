# Gorgoneion

**Active cyber defense orchestration — make attacks costly, without attacking systems you do not control.**

> **Status:** Early design / pre-alpha. Not production-ready. No detection or mitigation capability is currently shipped.

Gorgoneion is a planned **server-centric, agentless-first** cybersecurity platform. It will integrate established open-source detectors and network controls to orchestrate authorized defensive responses, deception, evidence preservation, and evaluation of attacker effort.

The countermeasure subsystem is named **Nemesys Engine** (pronounced "Nemesis"). **It primarily orchestrates existing security systems rather than implementing its own counterattack or security primitives.** It discovers adapter capabilities, chooses permitted workflows, checks authorization, invokes supported APIs, and verifies their effects.

## Principles

- **OSS-first (mandatory design gate).** Before implementing a subsystem, inventory existing maintained OSS and evaluate integration, embedding, and adaptation. Prefer proven existing implementations unless documented evidence shows they cannot meet requirements. A new implementation requires a recorded justification (license, security, functionality, performance, or maintenance). See [OSS reuse policy](docs/oss-candidates.md).
- **Agentless first.** Prefer central-server deployment and existing network appliances and telemetry. Optional sensors or integrations may be necessary for visibility and host-level actions.
- **Authorization before action.** Deny by default, verify asset ownership and authority, log decisions, and require explicit approval for disruptive operations.
- **No unauthorized hack-back.** No intrusion, destructive payloads, denial-of-service or access to external systems without authorization. An apparent source IP may belong to an innocent compromised host.
- **Measurable outcomes.** Separate *estimated attacker cost* from *verified operational effects*; measure defender costs and false positives too.
- **Fail safe.** Dry-run, rate limits, bounded rules, automatic rollback, emergency stop, audit trails and reproducible tests.
- **Reuse carefully.** Keep third-party copyright/license notices, provenance, version, and security advisories.

## Conceptual architecture

```text
Network / firewall / IDS / existing EDR telemetry
                     |
              Detection adapters
                     |
             Correlation & evidence
                     |
          Authorization / Policy Engine
                     |
                Nemesys Engine
          /          |            \
  FW adapters   decoy adapters   reporting adapters
  (owned FW)    (owned decoys)    (human-reviewed)
                     |
                Audit / CLI / UI
```

A management server does **not** automatically see all network traffic. Visibility may require SPAN/TAP, firewall log forwarding, sensor deployment, or integrations. Endpoint internals cannot be reliably inspected without an appropriate management interface or endpoint agent.

## Development and verification

The v0.1 CLI and smoke suite are in [Gorgoneion.sln](Gorgoneion.sln). See the [acceptance matrix](docs/v0.1-acceptance-matrix.md) and the [CLI prototype guide](docs/v0.1-implementation.md) for reproducible checks and explicit limitations. None of these imply a production security control.

## Planned milestones

- **v0.1:** Architecture, license review, event ingestion, policy evaluation, dry-run CLI, simulated test cases.
- **v0.2:** Authorized firewall integration, expiration and rollback, evidence handling.
- **v0.3:** Controlled deception adapters and attacker/defender cost measurement.
- **v1.0:** Documented deployment, safe operational defaults, security review, support policy and repeatable acceptance tests.
- **Beyond v1.0:** Multi-site orchestration, additional integrations and advanced analysis. Planned, not promised.

## Funding and commercialization

Gorgoneion is developed with **future commercial operation in mind**. During independent development, releases are intended to be freely available, with voluntary funding through **GitHub Sponsors** once sponsorship is configured.

If adoption and sustainability justify establishing a company, **paid plans are intended to be introduced around that transition**. Timing, scope, pricing, support commitments and licensing terms will be disclosed in advance. The project may remain free longer if sponsorship is sufficient.

**Rights granted by an already published OSS license cannot be retroactively withdrawn.** Future licensing decisions must respect third-party licenses and contributor rights. Sponsorship is *not* a support agreement.

See [COMMERCIAL.md](COMMERCIAL.md) for the funding roadmap, [docs/architecture.md](docs/architecture.md) for the initial technical scope, and [docs/strategy-catalog.md](docs/strategy-catalog.md) for versioned, dry-run-only orchestration rules.

## Current limitations and security

This repository is in its planning stage. Do not deploy it as a security control. See [SECURITY.md](SECURITY.md) for private vulnerability reporting guidance and [CONTRIBUTING.md](CONTRIBUTING.md) for contribution conditions.

## License status

**The repository's code license has not yet been finalized.** Apache-2.0 is under consideration for original code, subject to commercial strategy, contributor-rights review and dependency compatibility. Until a LICENSE file is committed, do **not** assume source code is open-source-licensed or available for redistribution. No third-party code should be imported before the license audit is complete.
