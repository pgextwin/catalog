using PgExtWin.Catalog;

internal static class WindowsSourceSelectorTests
{
    public static void Run(Action<bool, string> check, Action<Action, string> denies)
    {
        const string sha40 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const string sha64 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        WindowsSourceCandidate Candidate(string version, string method, string providerType,
            string provider = "pgextwin") => new(
                "hypopg", version, "18", "x64", "standard-postgresql", "msvc-x64",
                method, providerType, provider, "release-tag-" + version, version,
                sha40, 100, 200, "https://github.com/pgextwin/hypopg/releases/download/v1/hypopg.zip",
                sha64, "supported", false, true, true, true, true, true);

        var native = Candidate("1.4.5", "native", "pgextwin");
        var adapted = Candidate("1.4.5", "adapted", "pgextwin");
        var officialOld = Candidate("1.4.1", "external", "upstream-official", "HypoPG");
        var officialCurrent = Candidate("1.4.5", "external", "upstream-official", "HypoPG");
        var communityCurrent = Candidate("1.4.5", "external", "community", "community");
        WindowsSourceCandidate Select(params WindowsSourceCandidate[] inputs) =>
            WindowsSourceSelector.Select(inputs, "hypopg", "18", "x64",
                "standard-postgresql", "msvc-x64");

        check(Select(native, officialOld) == native, "old official must not mask latest native");
        check(Select(native, officialCurrent) == officialCurrent, "later official wins identical version");
        check(Select(native, adapted) == adapted, "adapted wins identical version over native");
        check(Select(native, adapted, officialCurrent) == officialCurrent,
            "same-version precedence external adapted native");
        check(Select(communityCurrent, officialCurrent) == officialCurrent,
            "official beats community at same version/environment");
        check(WindowsSourceSelector.Select(new[] { native, officialCurrent }, "hypopg", "18",
            "x64", "standard-postgresql", "msvc-x64", "pgextwin") == native,
            "explicit pgextwin source isolates external");
        check(WindowsSourceSelector.Select(new[] { native, officialCurrent }, "hypopg", "18",
            "x64", "standard-postgresql", "msvc-x64", "external") == officialCurrent,
            "explicit external source isolates pgextwin");
        check(Select(native, officialCurrent with { PgMajor = "17" }) == native,
            "PG-major isolation");
        check(Select(native, officialCurrent with { Abi = "mingw" }) == native,
            "ABI isolation");
        check(Select(native, officialCurrent with { PgDistribution = "vendor-postgresql" }) == native,
            "PostgreSQL distribution isolation");
        check(Select(native, officialCurrent with { DependenciesVerified = false }) == native,
            "missing runtime dependency excluded before selection");
        check(Select(native, officialCurrent with { RightsReviewed = false }) == native,
            "unknown rights excluded before selection");
        check(Select(native, officialCurrent with { ProvenanceVerified = false }) == native,
            "unknown provenance excluded before selection");
        check(Select(native, officialCurrent with { DownloadAuthorized = false }) == native,
            "non-authorized external asset excluded");
        check(Select(native, officialCurrent with { OriginalSha256 = null }) == native,
            "unknown byte digest excluded");
        check(Select(native, officialCurrent with { SourceCommitSha = "fake" }) == native,
            "unfixed source ref excluded");
        check(Select(native, officialCurrent with { ProviderType = "pgextwin" }) == native,
            "spoofed provider class rejected");
        check(Select(native, officialCurrent with { AssetVersion = "1.4.4" }) == native,
            "asset version mismatch excluded even if Release tag differs");
        check(Select(native, officialCurrent with { AssetUrl = "http://evil.test/x" }) == native,
            "untrusted transport scheme rejected");
        check(Select(native, officialCurrent with { AssetUrl = "https://evil.test/releases/download/1/x.zip" }) == native,
            "untrusted asset host rejected");
        check(Select(native, officialCurrent with { UpstreamVersion = "1.4.6-rc1" }) == native,
            "prerelease version cannot displace stable");
        check(Select(native, officialCurrent with { CompatibilityVerified = false }) == native,
            "unknown target compatibility excluded");
        var eol = officialOld with { Lifecycle = "eol", Historical = true, PgMajor = "13" };
        denies(() => WindowsSourceSelector.Select(new[] { eol }, "hypopg", "13", "x64",
            "standard-postgresql", "msvc-x64"), "EOL never silently selected");
        check(WindowsSourceSelector.Select(new[] { eol }, "hypopg", "13", "x64",
            "standard-postgresql", "msvc-x64", requestedVersion: "1.4.1",
            includeHistorical: true) == eol, "EOL requires exact version and historical opt-in");
        denies(() => WindowsSourceSelector.Select(new[] { eol }, "hypopg", "13", "x64",
            "standard-postgresql", "msvc-x64", requestedVersion: "1.4.1"),
            "EOL exact pin still requires historical opt-in");
        var supportedOld = officialOld with { Historical = true };
        denies(() => Select(supportedOld), "historical supported-major upstream version requires explicit pin");
        check(WindowsSourceSelector.Select(new[] { supportedOld }, "hypopg", "18", "x64",
            "standard-postgresql", "msvc-x64", requestedVersion: "1.4.1") == supportedOld,
            "explicit historical upstream pin allowed for supported PG");
        denies(() => WindowsSourceSelector.Select(new[] { officialCurrent }, "hypopg", "18", "x64",
            "standard-postgresql", "msvc-x64", source: "wrong"), "source option fail closed");
        denies(() => WindowsSourceSelector.Select(new[] { officialCurrent with
            { OriginalSha256 = null } }, "hypopg", "18", "x64", "standard-postgresql",
            "msvc-x64"), "selected candidate has no implicit downgrade fallback");
        // This pure selector never performs any fetch/retry; callers must terminate
        // a transaction when a selected artifact's hash/signature/GET fails.
    }
}
