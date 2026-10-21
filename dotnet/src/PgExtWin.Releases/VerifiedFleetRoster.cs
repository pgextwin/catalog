namespace PgExtWin.Releases;

/// <summary>
/// Trusted live Catalog intake roster. The original 14 public distributions
/// remain mandatory; only the three Wave 3 repositories may join them after
/// the independently protected Catalog index includes their verified Releases.
/// This does NOT modify historical P1 fixed pins or grant promotion authority.
/// </summary>
internal static class VerifiedFleetRoster
{
    private static readonly string[] Historical =
    [
        "hypopg", "orafce", "pg_bigm", "pg_cron", "pg_hint_plan",
        "pg_ivm", "pg_partman", "pg_qualstats", "pg_repack",
        "pg_stat_monitor", "pgaudit", "plpgsql_check", "set_user", "wal2json"
    ];

    private static readonly HashSet<string> Additional = new(StringComparer.Ordinal)
    {
        "pgtap", "pg_variables", "pg_store_plans"
    };

    // One authoritative compiled roster. All public-intake and download
    // capacity guards derive from this allowlist, not duplicate 14/17/70/85.
    internal static int MinimumCount => Historical.Length;
    internal static int MaximumCount => Historical.Length + Additional.Count;

    internal static int Require(IEnumerable<string> items)
    {
        var names = items.ToArray();
        if (names.Length < MinimumCount ||
            names.Length > MaximumCount ||
            !names.SequenceEqual(names.Order(StringComparer.Ordinal)) ||
            names.Distinct(StringComparer.Ordinal).Count() != names.Length ||
            Historical.Any(name => !names.Contains(name, StringComparer.Ordinal)) ||
            names.Any(name => !Historical.Contains(name, StringComparer.Ordinal) &&
                              !Additional.Contains(name)))
            throw new InvalidDataException("Unexpected authenticated Catalog fleet roster");
        return names.Length;
    }
}
