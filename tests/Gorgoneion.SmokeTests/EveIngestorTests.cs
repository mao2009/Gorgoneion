using Gorgoneion;

public static class EveIngestorTests
{
    public static int Run()
    {
        var tests = 0;
        void Check(bool condition, string name)
        {
            tests++;
            if (!condition) throw new Exception("FAIL: " + name);
        }
        var line = "{\"timestamp\":\"2026-10-09T00:00:00Z\",\"event_type\":\"alert\",\"src_ip\":\"198.51.100.20\",\"dest_ip\":\"192.0.2.10\",\"alert\":{\"severity\":1}}";
        var ingest = new EveIngestor();
        var first = ingest.Read(line);
        Check(first.Event is not null && first.Rejection is null, "valid EVE accepted");
        Check(first.Event!.Target == "192.0.2.10", "target normalized");
        Check(ingest.Read(line).Rejection == "duplicate_event", "same event deduplicated");
        Check(ingest.Read(line.Replace("00:00:00", "00:00:01")).Event is not null,
            "same flow with different timestamp preserved");
        Check(ingest.Read("not-json").Rejection == "invalid_json", "bad JSON denied");
        Check(ingest.Read("{}").Rejection == "invalid_event_schema", "missing fields denied");
        Check(ingest.Read(line.Replace("2026-10-09T00:00:00Z", "not-a-timestamp")).Rejection == "invalid_timestamp",
            "bad timestamp denied");
        Check(ingest.Read(line.Replace("2026-10-09T00:00:00Z", "2026-10-09T00:00:02Z") + new string(' ', 70_000))
            .Rejection == "event_too_large", "oversized input denied before parsing");
        Check(ingest.Read("[]").Rejection == "invalid_event_schema", "non-object rejected");
        var distinct = line.Replace("198.51.100.20", "198.51.100.21");
        Check(ingest.Read(distinct).Event is not null, "different source retained");
        Console.WriteLine($"PASS: {tests} EVE ingestion assertions.");
        return tests;
    }
}
