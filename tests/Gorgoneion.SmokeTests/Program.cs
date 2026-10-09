using Gorgoneion;

var tests = 0;
void Assert(bool ok, string name)
{
    tests++;
    if (!ok) throw new Exception("FAIL: " + name);
}
var policy = new Policy(new[] { "192.0.2.10" }, 2);
var good = new SecurityEvent("alert", "198.51.100.20", "192.0.2.10", 1, "Synthetic test", "case-1");
Assert(Nemesys.Evaluate(good, policy).Outcome == "proposed", "authorized alert proposed");
Assert(Nemesys.Evaluate(good with { Target = "192.0.2.11" }, policy).Reason == "target_not_authorized", "unknown target denied");
Assert(Nemesys.Evaluate(good with { EventType = "dns" }, policy).Outcome == "denied", "unsupported event denied");
Assert(Nemesys.Evaluate(good with { Severity = 3 }, policy).Reason == "below_severity_threshold", "low priority denied");
Assert(Nemesys.Evaluate(good with { Source = "not-an-ip" }, policy).Reason == "invalid_ip_address", "malformed source denied");
Assert(Nemesys.Evaluate(good with { Source = "192.0.2.10" }, policy).Reason == "unsafe_source_or_target", "self blocking prevented");
Assert(Nemesys.Evaluate(good, policy with { Adapter = "firewall.real" }).Reason == "unsupported_adapter", "real adapter prohibited");
Assert(Nemesys.Evaluate(good, new Policy(Array.Empty<string>())).Outcome == "denied", "deny by default");
var json = "{\"event_type\":\"alert\",\"src_ip\":\"198.51.100.20\",\"dest_ip\":\"192.0.2.10\",\"alert\":{\"severity\":1,\"signature\":\"synthetic\"}}";
Assert(EveParser.Parse(json)?.Severity == 1, "Suricata event parsed");
Assert(EveParser.Parse("{}") is null, "missing fields rejected");
Console.WriteLine($"PASS: {tests} smoke tests. All actions remain dry-run.");
