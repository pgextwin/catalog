using System.Text.RegularExpressions;

namespace PgExtWin.Releases;

/// <summary>
/// Membership comes from the independently authenticated protected Catalog
/// index, or a signer-verified feed generated from the protected Catalog.
/// This guard alone never grants publication, signing or installation rights.
/// </summary>
internal static class VerifiedFleetRoster
{
    // Independent resource ceiling, NOT a list of automatically approved repos.
    // Every member requires successful protected-main CI and byte/signer bindings.
    // A retired member may be absent after the protected Catalog removes it.
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
