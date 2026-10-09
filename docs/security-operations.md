# Security operations baseline — pre-alpha

This is an **operations plan**, not a statement that the software is production-safe.

## Vulnerability reporting

- Prefer GitHub **private vulnerability reporting** if repository administrators have enabled it.
- Do **not** post exploit samples, unpublished vulnerabilities, credentials or real customer logs to public Issues/PRs.
- If the private channel is not available, contact the maintainer via a verified private contact method on the GitHub profile. Do not assume that automated email or 24/7 response is configured.
- The project currently offers **no supported production release or response-time SLA**.

## Dependencies

- GitHub Dependabot config tracks `github-actions` and NuGet dependencies weekly.
- No third-party binaries or packages are currently vendored in the repository.
- GitHub Actions revisions are not yet pinned by commit SHA; pinning and allowed-actions policy remain a release-hardening task.
- A full SPDX/CycloneDX SBOM **has not been generated or verified**. The current `docs/oss-candidates.md` is a selection matrix, not an SBOM.
- Check exact upstream versions, transitive dependency licenses, CVE advisories and component provenance **before integration or distribution**.

## Sensitive information

- Do not place passwords, API keys, bearer tokens, private key files or real attack logs in commits or CI artifacts.
- The example `authorization.example.json` has synthetic operator identity and documentation-only IPs; it is not proof of asset ownership.
- CLI stdout may include source/target addresses; route it through access-controlled logging. The audit ledger intentionally minimizes stored data but still exposes decisions and policy metadata.
- No telemetry collection mechanism is planned for the core.
- Protect CI logs and generated archives with least privilege; treat any exposed token as compromised and rotate it.

## Release gates

Before public stable/security deployments, require documented threat modeling, immutable/externally anchored audit retention, authenticated sensor provenance, operator RBAC, verified device enrollment, independently reviewed real-API transports (redirect/proxy/TLS/SSRF safety), signed releases and SBOM, incident response testing, vulnerability disclosure policy, and support-window commitments.

The presence of a CI green check or a hash-chain audit does not satisfy these gates.
