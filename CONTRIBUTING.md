# Contributing

Thanks for your interest. Before implementing major features, open an issue describing the proposal, security boundaries, dependencies and acceptance tests.

## Design expectations

- **OSS-first is a prerequisite, not an option.** Before new implementations, investigate reusable upstream projects and link the evaluation in the issue/PR. Document third-party license, upstream URL, version/commit, maintenance and any modifications.
- Prefer (1) upstream integration via stable API/protocol, (2) compatible library reuse, (3) fork/adaptation, (4) a clean-room implementation when necessary, and only then (5) greenfield implementation. This ordering is guidance, not permission to bypass technical, security, or licensing constraints.
- If implementing from scratch, include a brief **Why not reuse OSS?** decision and evidence. The reviewer should reject submissions that duplicate suitable OSS without justification.
- Do not submit copied code without explicit redistribution rights and attribution.
- Favor centralized, agentless-first deployment and safe defaults.
- Every response action must have explicit authorization checks, audit logging, dry-run support and rollback or expiry where meaningful.
- Include automated unit/integration tests, including refusal/negative cases.
- No unauthorized external access, destructive counterattack or attack amplification.
- Avoid collecting private customer traffic in public issues.

## Intellectual property and future commercialization

Gorgoneion intends to explore commercial operation. **No contributor license agreement or copyright assignment is currently established.** Contributions will not be treated as an automatic transfer of copyright or as consent to future proprietary relicensing. Before accepting substantive outside contributions, maintainers should establish and publish an appropriate contribution and licensing policy; obtain legal review if needed.

## Current license status

The initial license audit is pending. Do not import third-party implementations before the license policy has been confirmed.
