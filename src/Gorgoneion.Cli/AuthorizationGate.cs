using System.Net;

namespace Gorgoneion;

/// <summary>
/// A local policy snapshot describing enrolled assets. This is *not* a cryptographic proof
/// of ownership; production enrollment must be independently attested.
/// </summary>
public sealed record AuthorizedAsset(string Address, string Scope, DateTimeOffset ExpiresAt);
public sealed record ApprovalTicket(string AssetAddress, string Action, DateTimeOffset ExpiresAt, string ApprovedBy);
public sealed record AuthorizationSnapshot(string Version, IReadOnlyList<AuthorizedAsset> Assets,
    IReadOnlyList<ApprovalTicket> Approvals, bool EmergencyStop = false);
public sealed record AuthorizationResult(bool Allowed, string Reason, string PolicyVersion);

/// <summary>Deterministic, fail-closed policy evaluation with an injected time source.</summary>
public static class AuthorizationGate
{
    public static AuthorizationResult Evaluate(
        AuthorizationSnapshot? snapshot, string? target, string? action, DateTimeOffset now)
    {
        AuthorizationResult Reject(string reason) =>
            new(false, reason, snapshot?.Version ?? "unknown");

        if (snapshot is null || string.IsNullOrWhiteSpace(snapshot.Version)
            || snapshot.Assets is null || snapshot.Approvals is null)
            return Reject("invalid_policy");
        if (snapshot.EmergencyStop) return Reject("emergency_stop");
        if (!IPAddress.TryParse(target, out var parsedTarget)
            || IPAddress.IsLoopback(parsedTarget))
            return Reject("invalid_target");
        if (action is not ("propose_block_source" or "propose_alias_block" or "propose_workflow"))
            return Reject("unsupported_action");
        var assets = snapshot.Assets.Where(a =>
            IPAddress.TryParse(a.Address, out var candidate) && candidate.Equals(parsedTarget) &&
            !string.IsNullOrWhiteSpace(a.Scope) && a.ExpiresAt > now).ToArray();
        if (assets.Length != 1) return Reject("asset_not_enrolled_or_expired");

        // Explicit approval is required even in the planning contract. Separate records
        // prevent an untrusted event from providing its own authorization.
        var approvals = snapshot.Approvals.Where(a =>
            IPAddress.TryParse(a.AssetAddress, out var candidate) && candidate.Equals(parsedTarget) &&
            a.Action == action && a.ExpiresAt > now && !string.IsNullOrWhiteSpace(a.ApprovedBy)).ToArray();
        if (approvals.Length != 1) return Reject("missing_or_expired_approval");

        return new(true, "approved_for_dry_run_only", snapshot.Version);
    }
}
