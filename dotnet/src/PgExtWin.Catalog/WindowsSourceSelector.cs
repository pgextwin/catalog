using System.Text.RegularExpressions;

namespace PgExtWin.Catalog;

/// <summary>
/// Pure selection contract. Inputs must come from an independently authenticated
/// Catalog snapshot before any real download; local registry files are untrusted.
/// This selector performs NO network access and NEVER retries a lower priority
/// source after an accepted candidate's download or signature failure.
/// </summary>
public sealed record WindowsSourceCandidate(
    string Extension, string UpstreamVersion, string PgMajor, string Architecture,
    string PgDistribution, string Abi, string BuildMethod, string ProviderType,
    string Provider, string SourceRepo, string ReleaseTag, string AssetVersion, string? SourceCommitSha,
    long ReleaseId, long AssetId, string AssetUrl, string? OriginalSha256,
    string Lifecycle, bool Historical, bool CompatibilityVerified,
    bool DependenciesVerified, bool RightsReviewed, bool ProvenanceVerified,
    bool DownloadAuthorized);

public static class WindowsSourceSelector
{
    private static readonly Regex Stable = new(
        @"\A(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){1,3}\z",
        RegexOptions.CultureInvariant);
    private static readonly Regex Sha40 = new(@"\A[0-9a-f]{40}\z", RegexOptions.CultureInvariant);
    private static readonly Regex Sha64 = new(@"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant);
    private static readonly Regex SafeName = new(@"\A[a-z][a-z0-9_]*\z", RegexOptions.CultureInvariant);

    public static WindowsSourceCandidate Select(
        IEnumerable<WindowsSourceCandidate> candidates, string extension, string pgMajor,
        string architecture, string pgDistribution, string abi, string source = "all",
        string? requestedVersion = null, bool includeHistorical = false)
    {
        if (source is not ("all" or "external" or "pgextwin"))
            throw new ArgumentException("Unknown source group");
        if (!SafeName.IsMatch(extension) || !Regex.IsMatch(pgMajor, @"\A[1-9][0-9]*\z") ||
            string.IsNullOrWhiteSpace(architecture) || string.IsNullOrWhiteSpace(pgDistribution) ||
            string.IsNullOrWhiteSpace(abi))
            throw new ArgumentException("Invalid target environment");
        if (requestedVersion is not null && !Stable.IsMatch(requestedVersion))
            throw new ArgumentException("Only an exact stable upstream version may be pinned");
        var eligible = candidates
            .Where(c => c.Extension == extension && c.PgMajor == pgMajor &&
                        c.Architecture == architecture && c.PgDistribution == pgDistribution &&
                        c.Abi == abi)
            .Where(c => source == "all" || (source == "external"
                ? c.BuildMethod == "external" : c.BuildMethod is "adapted" or "native"))
            .Where(IsAdmissible)
            .Where(c => requestedVersion is null
                ? (!c.Historical && c.Lifecycle == "supported")
                : c.UpstreamVersion == requestedVersion && (c.Lifecycle == "supported" ||
                    (includeHistorical && c.Lifecycle == "eol")))
            .OrderByDescending(c => ParseVersion(c.UpstreamVersion))
            .ThenBy(c => Rank(c.BuildMethod))
            .ThenBy(c => c.ProviderType == "upstream-official" ? 0 : 1)
            .ThenBy(c => c.Provider, StringComparer.Ordinal)
            .ThenBy(c => c.ReleaseId)
            .ThenBy(c => c.AssetId)
            .ToArray();
        if (eligible.Length == 0)
            throw new InvalidDataException("No independently approved candidate for exact target; no fallback");
        // The result is immutable for the transaction. Transport, SHA or Sigstore
        // failures MUST abort; callers must not catch and select again.
        return eligible[0];
    }

    public static bool IsAdmissible(WindowsSourceCandidate c)
    {
        if (!SafeName.IsMatch(c.Extension) || !Stable.IsMatch(c.UpstreamVersion) ||
            c.UpstreamVersion != c.AssetVersion ||
            c.BuildMethod is not ("external" or "adapted" or "native") ||
            c.ProviderType is not ("upstream-official" or "community" or "pgextwin") ||
            (c.BuildMethod == "external" && c.ProviderType == "pgextwin") ||
            (c.BuildMethod != "external" && c.ProviderType != "pgextwin") ||
            !Regex.IsMatch(c.SourceRepo, @"\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\z") ||
            (c.BuildMethod != "external" && c.SourceRepo != "pgextwin/" + c.Extension) ||
            !Sha40.IsMatch(c.SourceCommitSha ?? "") ||
            !Sha64.IsMatch(c.OriginalSha256 ?? "") ||
            c.ReleaseId <= 0 || c.AssetId <= 0 ||
            c.Lifecycle is not ("supported" or "eol") ||
            !c.CompatibilityVerified || !c.DependenciesVerified ||
            !c.RightsReviewed || !c.ProvenanceVerified || !c.DownloadAuthorized)
            return false;
        // Only HTTPS release URLs tied to the declared provider repository
        // are eligible for *selection*. The actual transport must independently
        // bind authenticated repository/release/asset identity and original bytes.
        if (!Uri.TryCreate(c.AssetUrl, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps || uri.Host != "github.com" ||
            !uri.AbsolutePath.StartsWith("/" + c.SourceRepo + "/releases/download/",
                StringComparison.Ordinal) ||
            uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0)
            return false;
        return true;
    }

    private static Version ParseVersion(string value) => Version.Parse(value);
    private static int Rank(string buildMethod) => buildMethod switch
    {
        "external" => 0,
        "adapted" => 1,
        "native" => 2,
        _ => 3
    };
}
