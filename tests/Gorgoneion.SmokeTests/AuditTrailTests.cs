using Gorgoneion;

public static class AuditTrailTests
{
    public static int Run()
    {
        var tests = 0;
        void Check(bool condition, string name)
        {
            tests++;
            if (!condition) throw new Exception("FAIL: " + name);
        }

        var file = Path.Combine(Path.GetTempPath(), "gorgoneion-audit-" +
            Guid.NewGuid().ToString("N") + ".jsonl");
        try
        {
            Check(!AuditTrail.Verify(file, out _), "missing file fails verification");
            using (var trail = AuditTrail.CreateNew(file))
            {
                var entry1 = trail.Append(new AuditPayload(1, "v1", "proposed",
                    "approved_plan_dry_run_only", "firewall.mock", "propose_block_source", true));
                Check(entry1.Sequence == 1 && entry1.PreviousHash == new string('0', 64),
                    "audit starts with genesis hash");
                var entry2 = trail.Append(new AuditPayload(2, "v1", "denied",
                    "target_not_authorized", "firewall.mock", null, true));
                Check(entry2.Sequence == 2 && entry2.PreviousHash == entry1.Hash,
                    "hash chain links sequential entries");
                trail.Append(new AuditPayload(3, "v1", "denied",
                    "duplicate_event", "firewall.mock", null, true));
            }
            Check(AuditTrail.Verify(file, out var reason) && reason == "verified",
                "complete audit verifies");
            var original = File.ReadAllText(file);
            Check(!original.Contains("198.51.100", StringComparison.Ordinal),
                "no source address in minimal ledger");
            Check(!original.Contains("secret", StringComparison.OrdinalIgnoreCase),
                "no credentials in minimal ledger");
            try
            {
                using var ignored = AuditTrail.CreateNew(file);
                throw new Exception("FAIL: existing audit overwritten");
            }
            catch (IOException) { tests++; }

            File.WriteAllText(file, original.Replace("target_not_authorized",
                "approved_plan_dry_run_only", StringComparison.Ordinal));
            Check(!AuditTrail.Verify(file, out _), "tampering detected");
            File.WriteAllText(file, original);
            var lines = File.ReadAllLines(file);
            File.WriteAllLines(file, new[] { lines[0], lines[2] });
            Check(!AuditTrail.Verify(file, out _), "middle-record removal detected");
            File.WriteAllText(file, original);
            Check(AuditTrail.Verify(file, out _), "restored audit verifies");
            File.WriteAllText(file, "");
            Check(!AuditTrail.Verify(file, out _), "empty audit refused");
            Console.WriteLine($"PASS: {tests} audit chain assertions.");
            return tests;
        }
        finally
        {
            if (File.Exists(file)) File.Delete(file);
        }
    }
}
