# Authorization gate (design-stage prototype)

This is a fail-closed deterministic **additional policy decision API** designed for a future independent approval workflow. It is now **required by the CLI planning pipeline** via the separate `--authorization` JSON file. The original `--policy` allowlist is also checked. This remains a local unsigned authorization assertion, NOT administrator ownership proof or approval for live enforcement.

## Inputs

- Versioned `AuthorizationSnapshot` supplied independently of alert/event data.
- One uniquely enrolled IP asset with explicit scope and unexpired enrollment.
- One uniquely matching action approval, with operator identity and expiry.
- Injected current timestamp, so tests do not depend on system clock.
- Emergency-stop bit that always denies plans.

## Security boundaries and missing work

- This is **planning authorization only**, never authorization for real external write operations.
- JSON-sourced claims, IP scopes, and identities are not independently verified. Production enrollment must prove administrator authority and use authenticated identity/permissions.
- The CLI pipeline now combines the gate with event-policy validation. A persisted, integrity-verifiable audit record is still necessary before any adapter execution.
- Production implementation needs persistent policy versions, signature verification, approval provenance and replay prevention, expiry handling, audit retention and revocation.
- Existing CLI remains `firewall.mock` and dry-run only. `examples/authorization.example.json` is deliberately a synthetic fixture, not permission to access systems.

## Test conditions

15 positive and negative smoke assertions cover explicit approval, unknown/ambiguous assets, expiry, missing operator, emergency stop, unsupported actions and loopback refusal.
