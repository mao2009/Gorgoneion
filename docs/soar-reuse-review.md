# SOAR and workflow OSS reuse assessment (2026-10-09)

**Preliminary assessment only.** This document is neither a legal review nor proof that the project is safe for production use.

| Candidate | Primary role | Upstream license indication | Recommendation |
| --- | --- | --- | --- |
| [StackStorm](https://github.com/StackStorm/st2) | Event-driven automation / actions / workflows / API | Apache-2.0 in upstream repo | Preferred **optional external orchestration backend** for evaluating a reusable workflow runtime. Test a small action integration; no bundled code yet. |
| [Shuffle](https://github.com/Shuffle/Shuffle) | Security operations automation and integrations | AGPL-3.0 backend, MIT components per upstream | Optional external SOAR integration. Check legal and deployment obligations before any redistribution or commercial hosting. |
| [Cortex](https://github.com/TheHive-Project/Cortex) | Observable analysis and active response | AGPL per upstream | Optional analyzer responder integration. Not a general replacement for Nemesys authorization and evidence requirements. |

**Source references:**
- https://github.com/StackStorm/st2
- https://docs.stackstorm.com/sensors.html
- https://github.com/Shuffle/Shuffle
- https://github.com/TheHive-Project/Cortex

## Design choice

Do **not** build a general-purpose workflow platform in Gorgoneion. Retain a **small policy/approval/capability boundary** as Nemesys and delegate complex workflows to external SOAR runtimes when their license and deployment fit.

- Initial capability providers are **preview descriptors**, never live clients.
- All action plans must be based on the independent local authorization decision.
- Workflow APIs will not be invoked by v0.1.
- Review actual endpoints, credentials storage, rollback semantics, idempotency, audit trails and security before enabling any write operation.
- No Docker/Podman dependency is imposed on the core Gorgoneion server, though optional external systems may need their own runtime.

## Acceptance work still outstanding

- [ ] Pin upstream versions and license text / transitive dependencies.
- [ ] Validate StackStorm action packs in a separately owned lab.
- [ ] Confirm Shuffle's AGPL obligations for target commercial models.
- [ ] Compare real operational footprint for small server deployments.
- [ ] Add asynchronous jobs, retries, reconciliation and audit before production.
