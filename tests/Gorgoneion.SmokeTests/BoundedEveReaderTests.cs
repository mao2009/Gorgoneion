using System.Text;
using Gorgoneion;

public static class BoundedEveReaderTests
{
    public static int Run()
    {
        var tests = 0;
        void Check(bool value, string name)
        {
            tests++;
            if (!value) throw new Exception("FAIL: " + name);
        }
        var file = Path.Combine(Path.GetTempPath(), "gorgoneion-eve-" +
            Guid.NewGuid().ToString("N") + ".jsonl");
        try
        {
            var valid = "{\"event_type\":\"alert\",\"src_ip\":\"198.51.100.1\",\"dest_ip\":\"192.0.2.10\"}";
            File.WriteAllText(file, new string('X', 70000) + "\n" + valid + "\n",
                new UTF8Encoding(false));
            var lines = BoundedEveReader.ReadLines(file).ToArray();
            Check(lines.Length == 2, "oversized event does not suppress following event");
            Check(lines[0].TooLarge && lines[0].Line.Length == 0,
                "oversized input dropped without retaining payload");
            Check(!lines[1].TooLarge && lines[1].Line == valid, "following event remains intact");
            Check(new EveIngestor().Read(lines[1].Line).Event is not null,
                "subsequent event remains parseable");
            File.WriteAllText(file, valid + "\r\n" + valid, new UTF8Encoding(false));
            lines = BoundedEveReader.ReadLines(file).ToArray();
            Check(lines.Length == 2 && lines[0].Line == valid && lines[1].Line == valid,
                "CRLF and missing final newline supported");
            File.WriteAllBytes(file, new byte[] { 0x7b, 0xff, 0x7d });
            try
            {
                _ = BoundedEveReader.ReadLines(file).ToArray();
                throw new Exception("FAIL: invalid UTF-8 accepted");
            }
            catch (DecoderFallbackException)
            {
                tests++;
            }
            Console.WriteLine($"PASS: {tests} bounded streaming assertions.");
            return tests;
        }
        finally
        {
            if (File.Exists(file)) File.Delete(file);
        }
    }
}
