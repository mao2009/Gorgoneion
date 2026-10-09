# Integration contracts (v0.1, preview-only)

Nemesys can describe upstream capabilities and validate configuration **without performing any remote action**. This is not a substitute for authorization, endpoint authentication, or secure network operation.

## Contract boundary

- Provider IDs: `opnsense.preview`, `stackstorm.preview`, `shuffle.preview`.
- Only explicit owned/enabled targets are accepted by the configuration validator.
- Only HTTPS URLs with a literal private IPv4 or loopback host, no path, query, fragment or embedded credentials, are accepted.
- No DNS names or public internet hosts in this *preview contract*, because names can be rebound and external destinations need a separate verified authorization mechanism.
- Even private IP addresses do not prove ownership; real adapters will need administrative enrollment, scoped credentials, network routing protections, certificate verification, auditable approvals, and revalidation before execution.
- **There is no HTTP client, credential handling, network connection, write endpoint or actual defensive operation in these adapters.**

## Planned real integration workflow

1. Register a managed asset using operator-controlled proof of authorization.
2. Validate a pinned upstream API contract against a local mock service.
3. Implement read-only discovery with strict authentication and transport controls.
4. Add signed approvals and audit retention with strict role separation.
5. Verify bounded, reversible actions using a disposable lab.
6. Only then consider a production adapter, with a kill switch and recovery plan.

## Review gate

Commercial use, third-party dependency licensing and production security review remain outstanding. See [SOAR reuse assessment](soar-reuse-review.md).
