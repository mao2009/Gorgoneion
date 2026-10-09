using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Gorgoneion;

public sealed record Policy(string[] AuthorizedTargets, int MinimumSeverity = 2, string Adapter = "firewall.mock");
public sealed record SecurityEvent(string EventType, string Source, string Target, int Severity, string? Signature, string? EventId);
public sealed record Decision(string Outcome, string Reason, string Adapter, string? Action, string? Source, string? Target,
    string? EventId, bool DryRun = true);

public static class Nemesys
{
    public static Decision Evaluate(SecurityEvent evt, Policy policy)
    {
        // An independent, explicitly registered target is required. Never take authorization from alert content.
        if (!TryAddress(evt.Source, out var source) || !TryAddress(evt.Target, out var target))
            return Deny(evt, policy, "invalid_ip_address");
        if (IPAddress.IsLoopback(target) || IPAddress.IsLoopback(source) || source.Equals(target))
            return Deny(evt, policy, "unsafe_source_or_target");
        var authorized = policy.AuthorizedTargets.Any(x => TryAddress(x, out var approved) && approved.Equals(target));
        if (!authorized) return Deny(evt, policy, "target_not_authorized");
        if (evt.EventType != "alert") return Deny(evt, policy, "unsupported_event_type");
        if (evt.Severity < 1 || evt.Severity > 4) return Deny(evt, policy, "invalid_severity");
        if (evt.Severity > policy.MinimumSeverity) return Deny(evt, policy, "below_severity_threshold");
        if (policy.Adapter != "firewall.mock") return Deny(evt, policy, "unsupported_adapter");
        return new Decision("proposed", "authorized_dry_run_only", policy.Adapter,
            "propose_block_source", source.ToString(), target.ToString(), evt.EventId);
    }

    private static Decision Deny(SecurityEvent evt, Policy policy, string reason) =>
        new("denied", reason, policy.Adapter, null, evt.Source, evt.Target, evt.EventId);

    private static bool TryAddress(string? value, out IPAddress address)
    {
        // Only literal IP addresses accepted: no DNS lookup, no CIDR ambiguity.
        return IPAddress.TryParse(value, out address!);
    }
}

public static class EveParser
{
    public static SecurityEvent? Parse(string line)
    {
        using var document = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 16 });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object) return null;
        string? GetString(JsonElement obj, string key) =>
            obj.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
        var type = GetString(root, "event_type");
        var src = GetString(root, "src_ip");
        var dest = GetString(root, "dest_ip");
        if (type is null || src is null || dest is null) return null;
        var severity = 0;
        string? signature = null;
        if (root.TryGetProperty("alert", out var alert) && alert.ValueKind == JsonValueKind.Object)
        {
            if (alert.TryGetProperty("severity", out var number) && number.ValueKind == JsonValueKind.Number)
                number.TryGetInt32(out severity);
            signature = GetString(alert, "signature");
        }
        var id = GetString(root, "flow_id") ?? GetString(root, "timestamp");
        return new SecurityEvent(type, src, dest, severity, signature, id);
    }
}

public static class Program
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    public static int Main(string[] args)
    {
        if (args.Length != 5 || args[0] != "evaluate" || args[1] != "--policy" || args[3] != "--input")
        {
            Console.Error.WriteLine("Usage: gorgoneion evaluate --policy policy.json --input eve.jsonl");
            return 2;
        }

        try
        {
            var policy = JsonSerializer.Deserialize<Policy>(File.ReadAllText(args[2]), new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
            if (policy is null || policy.AuthorizedTargets is null || policy.MinimumSeverity is < 1 or > 4)
                throw new InvalidDataException("Invalid policy: targets and minimum severity are required.");
            var rejected = 0;
            var lineNo = 0;
            foreach (var line in File.ReadLines(args[4]))
            {
                lineNo++;
                if (string.IsNullOrWhiteSpace(line)) continue;
                Decision result;
                try
                {
                    var evt = EveParser.Parse(line);
                    result = evt is null
                        ? new("denied", "invalid_event_schema", policy.Adapter, null, null, null, null)
                        : Nemesys.Evaluate(evt, policy);
                }
                catch (JsonException)
                {
                    result = new("denied", "invalid_json", policy.Adapter, null, null, null, null);
                }
                if (result.Outcome == "denied") rejected++;
                Console.WriteLine(JsonSerializer.Serialize(new { line = lineNo, result }, JsonOptions));
            }
            // Denied events are normal security decisions, not process failures.
            Console.Error.WriteLine($"Evaluated {lineNo} lines; denied {rejected}; no operations executed.");
            return 0;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
        {
            Console.Error.WriteLine($"Input error: {e.Message}");
            return 2;
        }
    }
}
