using System.Text;

namespace Gorgoneion;

public sealed record BoundedEveLine(string Line, bool TooLarge);

/// <summary>
/// Reads newline-delimited events with bounded in-memory line storage.
/// Oversized lines are drained and rejected without retaining their full payload.
/// </summary>
public static class BoundedEveReader
{
    public static IEnumerable<BoundedEveLine> ReadLines(string path)
    {
        using var reader = new StreamReader(path,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true),
            detectEncodingFromByteOrderMarks: true);
        var buffer = new StringBuilder();
        var overflowing = false;
        int character;
        while ((character = reader.Read()) >= 0)
        {
            if (character == '\n')
            {
                if (!overflowing && buffer.Length > 0 && buffer[buffer.Length - 1] == '\r')
                    buffer.Length--;
                yield return new BoundedEveLine(overflowing ? "" : buffer.ToString(), overflowing);
                buffer.Clear();
                overflowing = false;
                continue;
            }

            if (overflowing) continue;
            if (buffer.Length == EveIngestor.MaximumLineBytes)
            {
                buffer.Clear();
                overflowing = true;
                continue;
            }
            buffer.Append((char)character);
        }

        if (overflowing || buffer.Length > 0)
        {
            if (!overflowing && buffer.Length > 0 && buffer[buffer.Length - 1] == '\r')
                buffer.Length--;
            yield return new BoundedEveLine(overflowing ? "" : buffer.ToString(), overflowing);
        }
    }
}
