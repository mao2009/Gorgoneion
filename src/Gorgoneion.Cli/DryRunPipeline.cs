namespace Gorgoneion;

/// <summary>Pure event-to-plan decision. There is no execution capability.</summary>
public sealed record PipelineResult(Decision Decision, ProposedStep? Step, string PolicyVersion,
    string StrategyVersion = "none");

public static class DryRunPipeline
{
    public static PipelineResult Evaluate(
        SecurityEvent securityEvent, Policy policy,
        AuthorizationSnapshot? authorization, DateTimeOffset now, StrategyBook? strategies = null)
    {
        var version = authorization?.Version ?? "missing";
        var strategyVersion = strategies?.Version ?? "none";
        if (strategies is not null)
        {
            var choice = StrategySelector.Select(securityEvent, strategies);
            if (!choice.Selected || choice.Adapter is null)
                return new PipelineResult(
                    new Decision("denied", choice.Reason, policy.Adapter, null,
                        securityEvent.Source, securityEvent.Target, securityEvent.EventId),
                    null, version, strategyVersion);
            policy = policy with { Adapter = choice.Adapter };
        }
        var initial = Nemesys.Evaluate(securityEvent, policy);
        if (initial.Outcome != "proposed")
            return new PipelineResult(initial, null, version, strategyVersion);

        // A workflow may only be proposed if the selected existing capability is registered.
        var step = CapabilityCatalog.Plan(initial, policy.Adapter);
        if (step is null || !step.DryRun || !step.RequiresExplicitApproval)
            return new PipelineResult(Deny(initial, "unsupported_or_unsafe_capability"), null, version, strategyVersion);

        // This authorization snapshot is supplied independently of the untrusted EVE event.
        var permission = AuthorizationGate.Evaluate(authorization, step.Target, step.Operation, now);
        if (!permission.Allowed)
            return new PipelineResult(Deny(initial, permission.Reason), null, permission.PolicyVersion, strategyVersion);

        return new PipelineResult(initial with { Reason = "approved_plan_dry_run_only" },
            step, permission.PolicyVersion, strategyVersion);
    }

    private static Decision Deny(Decision proposal, string reason) =>
        proposal with { Outcome = "denied", Reason = reason, Action = null };
}
