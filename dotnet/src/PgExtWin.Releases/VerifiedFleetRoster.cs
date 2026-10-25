using System.Text.RegularExpressions;

namespace PgExtWin.Releases;

/// <summary>
/// Historical public cohort remains mandatory. New extensions are admitted
/// only from the independently authenticated protected Catalog index, or a
/// signer-verified feed cryptographically bound to immutable Catalog records.
/// This guard alone never grants publication, signing or installation rights.
/// </summary>
internal static class VerifiedFleetRoster
{
    private static readonly string[] Historical =
    [
        "hypopg", "orafce", "pg_bigm", "pg_cron", "pg_hint_plan",
        "pg_ivm", "pg_partman", "pg_qualstats", "pg_repack",
        "pg_stat_monitor", "pgaudit", "plpgsql_check", "set_user", "wal2json"
    ];

    // Independent resource ceiling, NOT a list of automatically approved repos.
    // New members require successful protected-main CI and byte/signer bindings.
    internal static int MinimumCount => Historical.Length;
    internal static int MaximumCount => 128;

    internal static int Require(IEnumerable<string> items)
    {
        var names = items.ToArray();
        if (names.Length < MinimumCount || names.Length > MaximumCount ||
            !names.SequenceEqual(names.Order(StringComparer.Ordinal)) ||
            names.Distinct(StringComparer.Ordinal).Count() != names.Length ||
            Historical.Any(name => !names.Contains(name, StringComparer.Ordinal)) ||
            names.Any(name => name.Length > 64 ||
                         !Regex.IsMatch(name, @"\A[a-z][a-z0-9_]*\z", RegexOptions.CultureInvariant)))
            throw new InvalidDataException("Unexpected authenticated Catalog fleet roster");
        return names.Length;
    }
}
