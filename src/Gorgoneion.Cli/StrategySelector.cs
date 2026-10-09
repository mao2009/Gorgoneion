namespace Gorgoneion;

/// <summary>
/// A restrictive, declarative choice of already registered *preview-only* capabilities.
/// This is not a general-purpose script or workflow execution engine.
/// </summary>
public sealed record StrategyRule(string Id, string EventType, int MaximumSeverity,
    string Adapter, bool Enabled);
public sealed record StrategyBook(string Version, IReadOnlyList<StrategyRule> Rules);
public sealed record StrategySelection(bool Selected, string Reason, string? Adapter, string StrategyVersion);

public static class StrategySelector
{
    public static StrategySelection Select(SecurityEvent evt, StrategyBook? book)
    {
        var version = book?.Version ?? "missing";
        StrategySelection Deny(string reason) => new(false, reason, null, version);

        if (book is null || string.IsNullOrWhiteSpace(book.Version) || book.Rules is null)
            return Deny("invalid_strategy_book");

        // Invalid or conflicting books fail completely, not only the affected event.
        if (book.Rules.Count is 0 or > 128 || book.Rules.Any(rule =>
                rule is null || string.IsNullOrWhiteSpace(rule.Id) ||
                rule.EventType != "alert" ||
                rule.MaximumSeverity is < 1 or > 4 ||
                !CapabilityCatalog.All.Any(cap => cap.Adapter == rule.Adapter &&
                    cap.SupportsDryRun && cap.RequiresExplicitApproval)) ||
            book.Rules.GroupBy(x => x.Id, StringComparer.Ordinal).Any(g => g.Count() != 1))
            return Deny("invalid_strategy_rules");

        if (evt.EventType != "alert" || evt.Severity is < 1 or > 4)
            return Deny("unsupported_event");

        var candidates = book.Rules.Where(r => r.Enabled &&
            r.EventType == evt.EventType && evt.Severity <= r.MaximumSeverity).ToArray();

        if (candidates.Length == 0) return Deny("no_matching_strategy");
        if (candidates.Length > 1) return Deny("ambiguous_strategies");

        return new(true, "matched", candidates[0].Adapter, version);
    }
}
