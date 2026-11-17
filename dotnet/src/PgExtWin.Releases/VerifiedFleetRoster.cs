using System.Text.RegularExpressions;

namespace PgExtWin.Releases;

/// <summary>
/// Membership comes from the independently authenticated protected Catalog
/// index, or a signer-verified feed cryptographically bound to immutable
/// Catalog records.
/// This guard alone never grants publication, signing or installation rights.
/// </summary>
internal static class VerifiedFleetRoster
{
    // Independent resource ceiling, NOT a list of automatically approved repos.
    // Every member requires successful protected-main CI and byte/signer bindings.
    // A retired member may be absent when the authenticated index and feed agree.
    internal static int MinimumCount => 1;
    internal static int MaximumCount => 128;

    internal static int Require(IEnumerable<string> items)
    {
        var names = items.ToArray();
        if (names.Length < MinimumCount || names.Length > MaximumCount ||
            !names.SequenceEqual(names.Order(StringComparer.Ordinal)) ||
            names.Distinct(StringComparer.Ordinal).Count() != names.Length ||
            names.Any(name => name.Length > 64 ||
                         !Regex.IsMatch(name, @"\A[a-z][a-z0-9_]*\z", RegexOptions.CultureInvariant)))
            throw new InvalidDataException("Unexpected authenticated Catalog fleet roster");
        return names.Length;
    }
}
