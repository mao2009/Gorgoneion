using Gorgoneion;

public static class PipelineTests
{
    public static int Run()
    {
        int tests = 0;
        void Check(bool condition, string name)
        {
            tests++;
            if (!condition) throw new Exception("FAIL: " + name);
        }

        var now = new DateTimeOffset(2026, 10, 9, 0, 0, 0, TimeSpan.Zero);
        var asset = new AuthorizedAsset("192.0.2.10", "test", now.AddMinutes(30));
        var approval = new ApprovalTicket("192.0.2.10", "propose_block_source",
            now.AddMinutes(5), "test-operator");
        var snapshot = new AuthorizationSnapshot("v1", new[] { asset }, new[] { approval });
        var policy = new Policy(new[] { "192.0.2.10" });
        var evt = new SecurityEvent("alert", "198.51.100.1", "192.0.2.10",
            1, "lab synthetic", "event-1");
        PipelineResult Eval(AuthorizationSnapshot? authorization, SecurityEvent? input = null) =>
            DryRunPipeline.Evaluate(input ?? evt, policy, authorization, now);

        var success = Eval(snapshot);
        Check(success.Decision.Outcome == "proposed", "authorized proposal is allowed");
        Check(success.Step is not null && success.Step.DryRun, "proposal is dry-run");
        Check(success.Step?.RequiresExplicitApproval == true, "approval is required");
        Check(success.PolicyVersion == "v1", "policy version propagated");
        Check(Eval(null).Decision.Reason == "invalid_policy", "missing authorization rejected");
        Check(Eval(snapshot with { EmergencyStop = true }).Decision.Reason == "emergency_stop",
            "kill switch denies");
        Check(Eval(snapshot with { Approvals = Array.Empty<ApprovalTicket>() }).Step is null,
            "no approval means no proposed step");
        Check(Eval(snapshot with { Assets = Array.Empty<AuthorizedAsset>() }).Decision.Reason
            == "asset_not_enrolled_or_expired", "no enrollment denied");
        Check(Eval(snapshot with { Approvals = new[]
            { approval with { ExpiresAt = now } } }).Decision.Reason
            == "missing_or_expired_approval", "expired approval denied");
        Check(Eval(snapshot, evt with { Target = "192.0.2.99" }).Step is null,
            "out of scope event produces no step");
        Check(Eval(snapshot, evt with { EventType = "dns" }).Step is null,
            "non alert produces no step");
        Check(Eval(snapshot).Decision.Action == "propose_block_source", "action remains proposal");
        Console.WriteLine($"PASS: {tests} pipeline assertions.");
        return tests;
    }
}
