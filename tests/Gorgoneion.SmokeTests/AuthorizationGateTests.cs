using Gorgoneion;

public static class AuthorizationGateTests
{
    public static int Run()
    {
        int count = 0;
        void Check(bool condition, string name)
        {
            count++;
            if (!condition) throw new Exception("FAIL: " + name);
        }

        var now = new DateTimeOffset(2026, 10, 9, 0, 0, 0, TimeSpan.Zero);
        var asset = new AuthorizedAsset("192.0.2.10", "lab", now.AddMinutes(15));
        var approval = new ApprovalTicket("192.0.2.10", "propose_block_source",
            now.AddMinutes(5), "lab-operator");
        var policy = new AuthorizationSnapshot("v1", new[] { asset }, new[] { approval });
        AuthorizationResult Test(AuthorizationSnapshot snapshot, string target = "192.0.2.10",
            string action = "propose_block_source") =>
            AuthorizationGate.Evaluate(snapshot, target, action, now);

        Check(Test(policy).Allowed, "explicitly authorized plan");
        Check(Test(policy).Reason == "approved_for_dry_run_only", "approval never grants live execution");
        Check(Test(policy, "192.0.2.11").Reason == "asset_not_enrolled_or_expired", "unknown target rejected");
        Check(Test(policy with { EmergencyStop = true }).Reason == "emergency_stop", "emergency stop");
        Check(Test(policy with { Version = "" }).Reason == "invalid_policy", "policy revision required");
        Check(Test(policy with { Assets = Array.Empty<AuthorizedAsset>() }).Reason == "asset_not_enrolled_or_expired",
            "deny without enrollment");
        Check(Test(policy with { Assets = new[] { asset with { ExpiresAt = now } } }).Reason
            == "asset_not_enrolled_or_expired", "expiry is exclusive");
        Check(Test(policy with { Approvals = Array.Empty<ApprovalTicket>() }).Reason
            == "missing_or_expired_approval", "deny without approval");
        Check(Test(policy with { Approvals = new[] { approval with { ExpiresAt = now } } }).Reason
            == "missing_or_expired_approval", "expired approval");
        Check(Test(policy with { Approvals = new[] { approval with { ApprovedBy = "" } } }).Reason
            == "missing_or_expired_approval", "anonymous approval refused");
        Check(Test(policy, action: "execute_shell").Reason == "unsupported_action", "unsupported action");
        Check(Test(policy, "127.0.0.1").Reason == "invalid_target", "loopback denied");
        Check(Test(policy with { Assets = new[] { asset, asset } }).Reason
            == "asset_not_enrolled_or_expired", "ambiguous enrollment denied");
        Check(Test(policy with { Approvals = new[] { approval, approval } }).Reason
            == "missing_or_expired_approval", "ambiguous approval denied");
        Check(Test(policy with { Assets = new[] { asset with { Scope = "" } } }).Reason
            == "asset_not_enrolled_or_expired", "missing asset scope denied");
        Console.WriteLine($"PASS: {count} authorization tests.");
        return count;
    }
}
