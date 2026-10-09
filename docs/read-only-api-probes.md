# Read-only API probe vertical slice (v0.1 prototype)

**Status:** Mock-verified request format only. This is not production connectivity, a deployment credential manager, an ownership verification system, or a mitigation feature.

## Why these APIs?

- OPNsense: `GET /api/core/system/status` for an object-shaped response; HTTP Basic auth with OPNsense API key and secret.
- StackStorm: `GET /api/v1/actions?limit=1` for a list-shaped response; `St2-Api-Key` in the HTTP header.

Sources:
- https://docs.opnsense.org/development/api/core/core.html
- https://docs.opnsense.org/development/api.html
- https://docs.stackstorm.com/authentication.html
- https://api.stackstorm.com/api/v1/actions/

## Design and safety

The library class `ReadOnlyApiProbe` assembles GET-only `HttpRequestMessage` objects and invokes **only a caller-supplied `HttpMessageInvoker`**. The executable CLI does not call these probes, create an HTTP client, open a socket, or accept credentials.

The integration target must already pass `IntegrationContracts.Validate` (enabled, asserted owned, known preview adapter, HTTPS, literal private IPv4/loopback endpoint, no user info, query, fragment or path). These checks are *configuration hygiene*, **not proof of authorization**.

Credentials are provided as method parameters, never in URLs. OPNsense uses Basic `key:secret`; StackStorm uses the documented `St2-Api-Key` header. Probe results contain only target ID, adapter, status code and a coarse result code; **no raw response body or credential value**.

Response handling:

- Five-second linked cancellation budget.
- Maximum 16 KiB payload, enforced even if Content-Length is absent or misleading.
- JSON depth limit of 16.
- Only the documented broad expected JSON shape is accepted (OPNsense object, StackStorm array).
- 401/403, 429, redirects, other non-success, malformed JSON, shape mismatch, transport errors and cancellation return sanitized result codes.
- No POST, PUT, DELETE, shell command, firewall reconfiguration or action execution.

## Mock HTTP contract tests

The tests inject `StubHandler : HttpMessageHandler` to emulate API responses **entirely in memory**. They check exact GET URI, authentication header placement, parsed response shape, size limit, fail-closed contract validation and error codes. No real OPNsense, StackStorm or SSH/FW target is required or contacted.

```sh
dotnet run --project tests/Gorgoneion.SmokeTests/Gorgoneion.SmokeTests.csproj -c Release
```

## Important remaining security gaps

- An injected live HTTP handler may redirect automatically; before any approved live implementation, **force redirects off** (`HttpClientHandler.AllowAutoRedirect = false`), prevent proxies and DNS rebinding, and enforce destination IP/certificate binding. This prototype only rejects 3xx responses it actually receives.
- Private networks can contain devices you do not own; enrollment/authorization still needs externally verified proof.
- A trusted TLS certificate and least-privileged API credentials are required. **Do not disable TLS certificate validation.**
- No secrets manager, credentials rotation, test environment enrollment, API schema version pinning, retry policy, state reconciliation, approval workflow or durable audit trail exists yet.
- The current tests verify mock protocol handling, **not live upstream compatibility**. Verify endpoints against pinned actual releases in an authorized isolated lab prior to enabling live calls.

## Licensing

No upstream source or binary has been vendored. Only documented HTTP API shapes and client calls have been independently implemented using the .NET standard library. Full redistribution and dependency license review remains tracked in Issue #2 and #3.
