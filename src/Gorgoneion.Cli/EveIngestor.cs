using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Gorgoneion;

/// <summary>Safe bounded ingestion of local Suricata-style EVE JSON lines.</summary>
public sealed class EveIngestor
{
    public const int MaximumLineBytes = 64 * 1024;
    private const int MaximumRememberedEvents = 10_000;
    private readonly HashSet<string> _seen = new(StringComparer.Ordinal);

    /// <summary>
    /// Returns either a normalized alert, or a rejected decision with no action.
    /// Identical lines within the current bounded window are considered duplicate events.
    /// </summary>
    public (SecurityEvent? Event, string? Rejection) Read(string line)
    {
        if (Encoding.UTF8.GetByteCount(line) > MaximumLineBytes)
            return (null, "event_too_large");

        try
        {
            using var document = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 16 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return (null, "invalid_event_schema");

            if (root.TryGetProperty("timestamp", out var timestamp))
            {
                if (timestamp.ValueKind != JsonValueKind.String ||
                    !DateTimeOffset.TryParse(timestamp.GetString(),
                        System.Globalization.CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.None, out _))
                    return (null, "invalid_timestamp");
            }

            var normalized = EveParser.Parse(line);
            if (normalized is null)
                return (null, "invalid_event_schema");

            // Fingerprint the *whole* event: Suricata flow_id alone is not unique
            // across events in the same flow. Dedupe applies only to exact repeats.
            var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(line)));
            if (!_seen.Add(fingerprint))
                return (null, "duplicate_event");
            if (_seen.Count >= MaximumRememberedEvents)
                _seen.Clear();

            return (normalized, null);
        }
        catch (JsonException)
        {
            return (null, "invalid_json");
        }
    }
}
