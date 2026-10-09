namespace Gorgoneion;

/// <summary>Pure event-to-plan decision. There is no execution capability.</summary>
public sealed record PipelineResult(Decision Decision, ProposedStep? Step, string PolicyVersion);

public static class DryRunPipeline
{
    public static PipelineResult Evaluate(
        SecurityEvent securityEvent, Policy policy,
        AuthorizationSnapshot? authorization, DateTimeOffset now)
    {
        var initial = Nemesys.Evaluate(securityEvent, policy);
        var version = authorization?.Version ?? "missing";
        if (initial.Outcome != "proposed")
            return new PipelineResult(initial, null, version);

        // A workflow may only be proposed if the selected existing capability is registered.
        var step = CapabilityCatalog.Plan(initial, policy.Adapter);
        if (step is null || !step.DryRun || !step.RequiresExplicitApproval)
            return new PipelineResult(Deny(initial, "unsupported_or_unsafe_capability"), null, version);

        // This authorization snapshot is supplied independently of the untrusted EVE event.
        var permission = AuthorizationGate.Evaluate(authorization, step.Target, step.Operation, now);
        if (!permission.Allowed)
            return new PipelineResult(Deny(initial, permission.Reason), null, permission.PolicyVersion);

        return new PipelineResult(initial with { Reason = "approved_plan_dry_run_only" },
            step, permission.PolicyVersion);
    }

    private static Decision Deny(Decision proposal, string reason) =>
        proposal with { Outcome = "denied", Reason = reason, Action = null };
}
