namespace Gorgoneion;

/// <summary>Declared capabilities of existing systems, not permission to execute them.</summary>
public sealed record Capability(
    string Adapter,
    string Operation,
    bool SupportsDryRun,
    bool RequiresExplicitApproval,
    bool CanRollback,
    string Upstream);

public sealed record ProposedStep(string Adapter, string Operation, string Source, string Target,
    string EvidenceId, bool DryRun, bool RequiresExplicitApproval);

/// <summary>
/// Creates plans only. No I/O, process execution, HTTP clients or firewall writes.
/// </summary>
public static class CapabilityCatalog
{
    private static readonly Capability[] Known =
    [
        new("firewall.mock", "propose_block_source", true, true, true, "internal-test-double"),
        new("opnsense.preview", "propose_alias_block", true, true, true, "https://docs.opnsense.org/development/api.html"),
        new("stackstorm.preview", "propose_workflow", true, true, false, "https://docs.stackstorm.com/"),
        new("shuffle.preview", "propose_workflow", true, true, false, "https://shuffler.io/")
    ];

    public static IReadOnlyList<Capability> All => Array.AsReadOnly(Known);

    public static ProposedStep? Plan(Decision decision, string adapter)
    {
        if (decision.Outcome != "proposed" || !decision.DryRun
            || string.IsNullOrWhiteSpace(decision.Source) || string.IsNullOrWhiteSpace(decision.Target))
            return null;
        // Explicit adapter registry. A caller cannot pick a live-capable backend via policy.
        var capability = Known.FirstOrDefault(x => x.Adapter == adapter && x.SupportsDryRun);
        if (capability is null) return null;
        return new ProposedStep(capability.Adapter, capability.Operation,
            decision.Source, decision.Target, decision.EventId ?? "unknown",
            true, capability.RequiresExplicitApproval);
    }
}
