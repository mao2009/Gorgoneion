# Nemesys strategy selection (prototype)

Gorgoneion delegates detection, firewall operations and workflows to **existing OSS**. This early implementation selects among predefined provider capability descriptors: it is **not a replacement for StackStorm, Shuffle or another mature SOAR platform**.

## Evaluation flow

Suricata alert → normalized event → declarative strategy selection → event/asset allowlist → independently versioned asset enrollment and per-operation approval → read-only action plan → per-run hash-chain audit → CLI output.

Supply `--strategies examples/strategies.example.json` as an optional final argument to `evaluate`. Without it, the existing `firewall.mock` policy adapter is used. Strategy rules carry an ID, exact event type, maximum accepted Suricata severity (1 is most severe), adapter ID and enabled flag. The entire book has a version.

## Safety

- Only capabilities predeclared in the code's `CapabilityCatalog` are selectable.
- All currently supported capabilities are **dry-run and require explicit approval**.
- Invalid book, unknown adapter, duplicate rule IDs, no matching rule or multiple matching rules **fail closed**.
- Strategy selection cannot grant permissions. An independent `AuthorizationSnapshot` must match the **selected capability's exact operation**; authorizing mock firewall is not equivalent to authorizing an OPNsense preview.
- The CLI contains no live-firewall or remote workflow execution pathway.
- Audits now record strategy version metadata, but not the source event payload.

## Deferred

No workflow engine, dynamic scripts, retries, real API calls, results reconciliation, costs, effect measurement or persistent signed provenance yet. Evaluate StackStorm and other OSS for those functions instead of rebuilding them.
