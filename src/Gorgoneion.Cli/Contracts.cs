using System.Net;
using System.Text.Json;

namespace Gorgoneion;

// Explicitly non-executable interfaces: a provider validates its contract,
// and the controller emits a plan. No HTTP, shell, firewall or process invocation.
public sealed record IntegrationTarget(string Id, string Adapter, string BaseUrl, bool Owned, bool Enabled);
public sealed record ContractResult(bool Valid, string Reason, string Adapter, string TargetId);

public static class IntegrationContracts
{
    private static readonly HashSet<string> Supported = new(StringComparer.Ordinal)
    {
        "opnsense.preview", "stackstorm.preview", "shuffle.preview"
    };

    public static ContractResult Validate(IntegrationTarget? target)
    {
        if (target is null) return new(false, "missing_target", "", "");
        if (!target.Owned || !target.Enabled)
            return new(false, "target_not_enabled_or_owned", target.Adapter, target.Id);
        if (!Supported.Contains(target.Adapter))
            return new(false, "unsupported_adapter", target.Adapter, target.Id);
        if (!Uri.TryCreate(target.BaseUrl, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Fragment) ||
            !string.IsNullOrEmpty(uri.Query) ||
            uri.AbsolutePath != "/" ||
            uri.HostNameType == UriHostNameType.Unknown)
            return new(false, "invalid_endpoint", target.Adapter, target.Id);

        // Avoid encouraging credentials in URLs or permissive arbitrary Internet targets.
        // DNS names are rejected at this stage; name resolution can change after approval.
        if (!IPAddress.TryParse(uri.Host, out var address) ||
            !(IPAddress.IsLoopback(address) || IsPrivateV4(address)))
            return new(false, "endpoint_not_lab_or_private", target.Adapter, target.Id);
        return new(true, "contract_only_no_connection", target.Adapter, target.Id);
    }

    private static bool IsPrivateV4(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return bytes.Length == 4 && (bytes[0] == 10
            || bytes[0] == 172 && bytes[1] is >= 16 and <= 31
            || bytes[0] == 192 && bytes[1] == 168);
    }
}

public static class IntegrationManifest
{
    public static IReadOnlyList<IntegrationTarget> Parse(string json)
    {
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 10 });
        if (doc.RootElement.ValueKind != JsonValueKind.Array)
            throw new JsonException("Manifest must be an array.");
        var list = new List<IntegrationTarget>();
        foreach (var element in doc.RootElement.EnumerateArray())
        {
            if (element.ValueKind != JsonValueKind.Object)
                throw new JsonException("Manifest entry must be an object.");
            var item = JsonSerializer.Deserialize<IntegrationTarget>(element.GetRawText(),
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (item is null) throw new JsonException("Null manifest entry.");
            list.Add(item);
        }
        return list;
    }
}
