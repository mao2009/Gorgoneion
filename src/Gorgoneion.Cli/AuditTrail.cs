using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Gorgoneion;

// Minimal, privacy-conscious decision ledger. It records neither event content nor credentials.
// A hash chain detects edits/reordering within a retained file, not removal of a complete suffix.
public sealed record AuditPayload(int Line, string PolicyVersion, string Outcome,
    string Reason, string Adapter, string? Action, bool DryRun);
public sealed record AuditEntry(int Sequence, string PreviousHash, AuditPayload Payload, string Hash);

public sealed class AuditTrail : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions =
        new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private readonly FileStream _stream;
    private readonly StreamWriter _writer;
    private int _sequence;
    private string _previous = new string('0', 64);

    private AuditTrail(FileStream stream)
    {
        _stream = stream;
        _writer = new StreamWriter(stream, new UTF8Encoding(false), leaveOpen: true);
    }

    public static AuditTrail CreateNew(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            throw new InvalidDataException("Audit path is required.");
        // Never silently overwrite or append to a preexisting ledger.
        var options = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
            Options = FileOptions.WriteThrough
        };
        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        return new AuditTrail(new FileStream(filePath, options));
    }

    public AuditEntry Append(AuditPayload payload)
    {
        if (_sequence == int.MaxValue)
            throw new InvalidDataException("Audit sequence overflow.");
        var sequence = _sequence + 1;
        var hash = Calculate(sequence, _previous, payload);
        var entry = new AuditEntry(sequence, _previous, payload, hash);
        _writer.WriteLine(JsonSerializer.Serialize(entry, JsonOptions));
        _writer.Flush();
        _stream.Flush(flushToDisk: true);
        _sequence = sequence;
        _previous = hash;
        return entry;
    }

    private static string Calculate(int sequence, string previousHash, AuditPayload payload)
    {
        var canonical = JsonSerializer.Serialize(new
        {
            Sequence = sequence,
            PreviousHash = previousHash,
            Payload = payload
        }, JsonOptions);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    public static bool Verify(string filePath, out string reason)
    {
        reason = "verified";
        int expectedSequence = 1;
        string previous = new string('0', 64);
        try
        {
            foreach (var line in File.ReadLines(filePath))
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    reason = "empty_or_truncated_entry";
                    return false;
                }
                var entry = JsonSerializer.Deserialize<AuditEntry>(line,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true, MaxDepth = 16 });
                if (entry?.Payload is null || entry.Sequence != expectedSequence ||
                    !string.Equals(entry.PreviousHash, previous, StringComparison.Ordinal) ||
                    !string.Equals(entry.Hash,
                        Calculate(entry.Sequence, entry.PreviousHash, entry.Payload),
                        StringComparison.Ordinal))
                {
                    reason = "audit_chain_mismatch";
                    return false;
                }
                previous = entry.Hash;
                expectedSequence++;
            }
            if (expectedSequence == 1)
            {
                reason = "empty_audit";
                return false;
            }
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException
                                   or ArgumentException or OverflowException)
        {
            reason = "invalid_or_unreadable_audit";
            return false;
        }
    }

    public void Dispose()
    {
        _writer.Dispose();
        _stream.Dispose();
    }
}
