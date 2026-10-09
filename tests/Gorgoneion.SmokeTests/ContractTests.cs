using Gorgoneion;

public static class ContractTests
{
    public static int Run()
    {
        var count = 0;
        void Check(bool condition, string name)
        {
            count++;
            if (!condition) throw new Exception("FAIL: " + name);
        }
        var valid = new IntegrationTarget("lab-1", "opnsense.preview", "https://192.168.1.1/", true, true);
        Check(IntegrationContracts.Validate(valid).Valid, "owned private lab endpoint");
        Check(IntegrationContracts.Validate(valid with { Owned = false }).Reason == "target_not_enabled_or_owned", "no ownership denied");
        Check(IntegrationContracts.Validate(valid with { Enabled = false }).Reason == "target_not_enabled_or_owned", "disabled denied");
        Check(IntegrationContracts.Validate(valid with { Adapter = "live.shell" }).Reason == "unsupported_adapter", "unknown adapter denied");
        Check(!IntegrationContracts.Validate(valid with { BaseUrl = "http://192.168.1.1/" }).Valid, "no http");
        Check(!IntegrationContracts.Validate(valid with { BaseUrl = "https://user:pass@192.168.1.1/" }).Valid, "no credentials in url");
        Check(!IntegrationContracts.Validate(valid with { BaseUrl = "https://8.8.8.8/" }).Valid, "no external public endpoint");
        Check(!IntegrationContracts.Validate(valid with { BaseUrl = "https://example.org/" }).Valid, "no dns names");
        Check(!IntegrationContracts.Validate(valid with { BaseUrl = "https://192.168.1.1/command" }).Valid, "no path");
        Check(!IntegrationContracts.Validate(valid with { BaseUrl = "https://192.168.1.1/?token=x" }).Valid, "no query secrets");
        Check(IntegrationContracts.Validate(valid with { Adapter = "stackstorm.preview", BaseUrl = "https://127.0.0.1/" }).Valid, "loopback stackstorm");
        Check(IntegrationContracts.Validate(valid with { Adapter = "shuffle.preview", BaseUrl = "https://10.0.0.1/" }).Valid, "private shuffle");
        Check(IntegrationManifest.Parse("[{\"id\":\"lab-1\",\"adapter\":\"opnsense.preview\",\"baseUrl\":\"https://192.168.1.1/\",\"owned\":true,\"enabled\":true}]").Count == 1, "manifest parsed");
        try { IntegrationManifest.Parse("{}"); throw new Exception("FAIL: object manifest accepted"); }
        catch (System.Text.Json.JsonException) { count++; }
        Console.WriteLine($"PASS: {count} contract tests. No connections attempted.");
        return count;
    }
}
