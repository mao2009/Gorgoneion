# Authorization gate (design-stage prototype)

This is a fail-closed deterministic **additional policy decision API** designed for a future independent approval workflow. It is currently tested as a library component and is **not connected to the legacy CLI policy file**, so deploying the CLI does not yet enforce this additional gate.

## Inputs

- Versioned `AuthorizationSnapshot` supplied independently of alert/event data.
- One uniquely enrolled IP asset with explicit scope and unexpired enrollment.
- One uniquely matching action approval, with operator identity and expiry.
- Injected current timestamp, so tests do not depend on system clock.
- Emergency-stop bit that always denies plans.

## Security boundaries and missing work

- This is **planning authorization only**, never authorization for real external write operations.
- JSON-sourced claims, IP scopes, and identities are not independently verified. Production enrollment must prove administrator authority and use authenticated identity/permissions.
- A caller must combine this gate with event-policy validation and persist an append-only audit record before considering any adapter execution.
- Production implementation needs persistent policy versions, signature verification, approval provenance and replay prevention, expiry handling, audit retention and revocation.
- Existing CLI remains `firewall.mock` and dry-run only.

## Test conditions

15 positive and negative smoke assertions cover explicit approval, unknown/ambiguous assets, expiry, missing operator, emergency stop, unsupported actions and loopback refusal.
