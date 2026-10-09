using Gorgoneion;

public static class StrategyTests
{
    public static int Run()
    {
        var count = 0;
        void Check(bool ok, string name)
        {
            count++;
            if (!ok) throw new Exception("FAIL: " + name);
        }
        var now = new DateTimeOffset(2026, 10, 9, 0, 0, 0, TimeSpan.Zero);
        var target = "192.0.2.10";
        var evt = new SecurityEvent("alert", "198.51.100.1", target, 1, "synthetic", "evt-1");
        var policy = new Policy(new[] { target }, MinimumSeverity: 2);
        var approval = new ApprovalTicket(target, "propose_block_source", now.AddMinutes(10), "operator");
        var auth = new AuthorizationSnapshot("enrollment-v1",
            new[] { new AuthorizedAsset(target, "test", now.AddMinutes(20)) }, new[] { approval });
        var rule = new StrategyRule("s1", "alert", 2, "firewall.mock", true);
        var book = new StrategyBook("strategy-v1", new[] { rule });
        Check(StrategySelector.Select(evt, book).Selected, "matching declared strategy");
        Check(StrategySelector.Select(evt, null).Reason == "invalid_strategy_book",
            "null book rejected");
        Check(StrategySelector.Select(evt, book with { Version = "" }).Reason == "invalid_strategy_book",
            "missing strategy version");
        Check(StrategySelector.Select(evt, book with { Rules = Array.Empty<StrategyRule>() }).Reason
            == "invalid_strategy_rules", "empty strategy book denied");
        Check(StrategySelector.Select(evt, book with { Rules = new[] { rule, rule } }).Reason
            == "invalid_strategy_rules", "duplicate IDs denied");
        Check(StrategySelector.Select(evt, book with { Rules =
            new[] { rule, rule with { Id = "s2" } } }).Reason
            == "ambiguous_strategies", "multiple matching strategies denied");
        Check(StrategySelector.Select(evt, book with { Rules =
            new[] { rule with { Adapter = "shell.live" } } }).Reason
            == "invalid_strategy_rules", "unregistered adapter rejected");
        Check(StrategySelector.Select(evt, book with { Rules =
            new[] { rule with { MaximumSeverity = 5 } } }).Reason
            == "invalid_strategy_rules", "severity out of range");
        Check(StrategySelector.Select(evt, book with { Rules =
            new[] { rule with { Enabled = false } } }).Reason
            == "no_matching_strategy", "disabled strategy not selected");
        Check(StrategySelector.Select(evt with { EventType = "dns" }, book).Reason
            == "unsupported_event", "other event types not admitted");
        Check(StrategySelector.Select(evt with { Severity = 3 }, book).Reason
            == "no_matching_strategy", "low severity rejected");

        var good = DryRunPipeline.Evaluate(evt, policy, auth, now, book);
        Check(good.Decision.Outcome == "proposed" && good.Step?.DryRun == true,
            "authorized versioned strategy creates dry-run proposal");
        Check(good.StrategyVersion == "strategy-v1", "strategy version recorded");
        Check(DryRunPipeline.Evaluate(evt, policy, auth, now, book with { Rules =
            new[] { rule, rule with { Id = "s2" } } }).Step is null,
            "ambiguous strategies never execute");
        Check(DryRunPipeline.Evaluate(evt, policy, auth with { Approvals =
            Array.Empty<ApprovalTicket>() }, now, book).Step is null,
            "strategy cannot bypass approval");
        var opn = new StrategyRule("opn", "alert", 2, "opnsense.preview", true);
        var opnBook = new StrategyBook("opn-v1", new[] { opn });
        var opnAuth = auth with { Approvals = new[] { approval with { Action = "propose_alias_block" } } };
        var opnResult = DryRunPipeline.Evaluate(evt, policy, opnAuth, now, opnBook);
        Check(opnResult.Step?.Adapter == "opnsense.preview" && opnResult.Step.DryRun,
            "OPNsense preview plans without network requests");
        Check(opnResult.Decision.Action == "propose_alias_block", "operation matches chosen capability");
        Check(DryRunPipeline.Evaluate(evt, policy, auth, now, opnBook).Step is null,
            "approval for firewall mock does not authorize OPNsense preview");
        Console.WriteLine($"PASS: {count} strategy assertions.");
        return count;
    }
}
