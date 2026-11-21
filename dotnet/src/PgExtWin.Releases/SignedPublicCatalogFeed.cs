using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using PgExtWin.Core;
using Sigstore;

namespace PgExtWin.Releases;

/// <summary>
/// REST-quota-independent, cryptographically verified Catalog ZIP selector.
/// Validates the actual GitHub Actions Sigstore signed metadata against the
/// pinned workflow/repository/main identity before accepting ANY pins.
/// Original extension ZIP signatures are NOT verified by the feed signature.
/// </summary>
public static class SignedPublicCatalogFeed
{
    private const string ReleaseRoot = "https://github.com/pgextwin/catalog/releases/";
    private const string TagPrefix = "catalog-feed-";
    private const string SignerSan =
        "https://github.com/pgextwin/catalog/.github/workflows/cli-signed-catalog-feed.yml@refs/heads/main";
    private const int MaxBytes = 2 * 1024 * 1024;
    private static readonly Regex Sha40 = new(@"\A[0-9a-f]{40}\z", RegexOptions.CultureInvariant);
    private static readonly Regex Sha64 = new(@"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant);
    private const string Schema = "pgextwin-signed-catalog-zip-feed/v3";

    public sealed record Selection(string Commit, string SourceReleaseTag,
        IReadOnlyList<ReleasePins> Pins, IReadOnlyList<string> ApprovedMajors);

    public static async Task<Selection> AcquireAsync(string pgSelection,
        string? extension = null, string? version = null,
        HttpMessageHandler? handler = null, CancellationToken token = default,
        Action<string>? progress = null)
    {
        if (pgSelection != "all" &&
            (!int.TryParse(pgSelection, out var requested) ||
             requested < PostgresqlFeedCohort.FirstSupportedMajor || requested > PostgresqlFeedCohort.HighestPermittedMajor ||
             requested.ToString(System.Globalization.CultureInfo.InvariantCulture) != pgSelection))
            throw new InvalidDataException("Unsupported signed Catalog PG selection");
        using var owned = handler is null ? new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None
        } : null;
        using var http = new HttpClient(handler ?? owned!, disposeHandler: false)
        { Timeout = TimeSpan.FromMinutes(3) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("pgextwin-signed-catalog-feed/0.3");

        var (feedBytes, bundleBytes, tag) = await FetchFeedAsync(http, token, progress);

        // Never use Catalog or Release-provided keys. Sigstore's TUF public-good
        // trust root is independent; OIDC issuer, SAN and repository/main are fixed here.
        using var feed = StrictJson.Parse(feedBytes);
        var root = feed.RootElement;
        var commit = root.GetProperty("catalogCommit").GetString() ?? "";
        if (root.GetProperty("schemaVersion").GetString() != Schema)
            throw new InvalidDataException("Unknown signed Catalog feed schema");
        if (!Sha40.IsMatch(commit) ||
            root.GetProperty("repository").GetString() != "pgextwin/catalog" ||
            root.GetProperty("verificationLevel").GetString() != "CATALOG_FEED_SIGNED_CLAIM_ONLY" ||
            root.GetProperty("extensionSignatureVerified").ValueKind != JsonValueKind.False ||
            root.GetProperty("publicationAuthorized").ValueKind != JsonValueKind.False ||
            root.GetProperty("installAuthorized").ValueKind != JsonValueKind.False ||
            tag != TagPrefix + commit)
            throw new InvalidDataException("Signed Catalog feed identity or trust boundary invalid");

        progress?.Invoke("FEED_SIGSTORE_VERIFY_START signer=pinned-workflow");
        VerificationResult proof;
        try
        {
            var bundle = SigstoreBundle.Deserialize(Encoding.UTF8.GetString(bundleBytes).Trim());
            var verifier = new SigstoreVerifier();
            proof = await verifier.VerifyAsync(feedBytes, bundle, new VerificationPolicy
            {
                RequireTransparencyLog = true,
                CertificateIdentity = new CertificateIdentity
                {
                    SubjectAlternativeName = SignerSan,
                    Issuer = "https://token.actions.githubusercontent.com",
                    Extensions = new CertificateExtensionPolicy
                    {
                        SourceRepositoryUri = "https://github.com/pgextwin/catalog",
                        SourceRepositoryRef = "refs/heads/main",
                        SourceRepositoryIdentifier = "1405939279",
                        RunnerEnvironment = "github-hosted"
                    }
                }
            }, token);
        }
        catch (Exception ex) when (ex is VerificationException or JsonException or
                                   FormatException or InvalidOperationException or
                                   HttpRequestException or IOException)
        {
            throw new InvalidDataException("Independent Catalog feed Sigstore verification failed", ex);
        }
        var ext = proof.SignerIdentity?.Extensions;
        var sourceDigest = ext?.SourceRepositoryDigest ?? "";
        if (proof.SignerIdentity?.SubjectAlternativeName != SignerSan ||
            (sourceDigest != commit && sourceDigest != "sha1:" + commit) ||
            proof.Statement?.PredicateType != "https://slsa.dev/provenance/v1" ||
            proof.VerifiedTimestamps.Count == 0)
            throw new InvalidDataException("Sigstore certificate source SHA, SLSA or time mismatches signed Catalog");

        progress?.Invoke($"FEED_SIGSTORE_VERIFIED catalog_commit={commit} trust=CATALOG_ONLY");
        var cohort = PostgresqlFeedCohort.Parse(root);
        var pins = SelectPins(root, cohort, pgSelection, extension, version);
        progress?.Invoke($"CATALOG_PINS_SELECTED count={pins.Count} pg={pgSelection} extension_auth=INTEGRITY_ONLY");
        return new Selection(commit, tag, pins, cohort.Majors);
    }

    // Called only on the inventory authenticated by the pinned feed signer.
    internal static IReadOnlyList<ReleasePins> SelectPins(JsonElement root,
        PostgresqlFeedCohort cohort, string pgSelection, string? extension = null, string? version = null)
    {
        if (pgSelection != "all" && !cohort.Majors.Contains(pgSelection, StringComparer.Ordinal))
            throw new InvalidDataException("Requested PG major is not in signer-approved Catalog cohort");
        if ((extension is not null && pgSelection == "all") || (version is not null && extension is null))
            throw new ArgumentException("An exact signed Catalog selection requires an item and a PG major");

        var commit = root.GetProperty("catalogCommit").GetString()!;
        var extensions = root.GetProperty("extensions").EnumerateArray().ToArray();
        VerifiedFleetRoster.Require(extensions.Select(e => e.GetProperty("extension").GetString() ?? ""));
        var pins = new List<ReleasePins>();
        var optionalLatest = false;
        foreach (var info in extensions)
        {
            var name = info.GetProperty("extension").GetString()!;
            var repoId = info.GetProperty("repositoryId").GetInt64();
            var latest = info.GetProperty("latestReleaseTag").GetString();
            var tags = new HashSet<string>(StringComparer.Ordinal);
            var keys = new HashSet<(string Major, string Version)>();
            if (repoId <= 0)
                throw new InvalidDataException("Invalid signed Catalog repository identity");

            foreach (var release in info.GetProperty("releases").EnumerateArray())
            {
                var tag = release.GetProperty("releaseTag").GetString() ?? "";
                var id = release.GetProperty("releaseId").GetInt64();
                var admission = release.GetProperty("admission").GetProperty("catalogCommit").GetString() ?? "";
                var isLatest = tag == latest;
                var packages = release.GetProperty("packages");
                if (!PinnedReleaseSelector.SafeAssetName(tag) || !tags.Add(tag) || id <= 0 ||
                    !Sha40.IsMatch(admission) || (isLatest && admission != commit) ||
                    packages.GetArrayLength() == 0)
                    throw new InvalidDataException("Invalid signed Catalog Release or admission");

                var covered = new HashSet<string>(StringComparer.Ordinal);
                foreach (var row in packages.EnumerateArray())
                {
                    var major = row.GetProperty("pgMajor").GetString() ?? "";
                    var packageVersion = row.GetProperty("version").GetString() ?? "";
                    var asset = row.GetProperty("asset").GetString() ?? "";
                    var sha = row.GetProperty("sha256").GetString() ?? "";
                    var assetId = row.GetProperty("assetId").GetInt64();
                    var license = row.GetProperty("license");
                    var licenseName = license.GetProperty("name").GetString() ?? "";
                    var evidence = license.GetProperty("evidenceUrls").EnumerateArray()
                        .Select(url => url.GetString() ?? "").ToArray();
                    if (!cohort.Majors.Contains(major, StringComparer.Ordinal) || !covered.Add(major) ||
                        string.IsNullOrWhiteSpace(packageVersion) || !keys.Add((major, packageVersion)) ||
                        !Sha64.IsMatch(sha) || assetId <= 0 ||
                        !PinnedReleaseSelector.SafeAssetName(asset) ||
                        !asset.StartsWith(name + "-", StringComparison.Ordinal) ||
                        !asset.EndsWith("-pg" + major + "-windows-x64.zip", StringComparison.Ordinal) ||
                        string.IsNullOrWhiteSpace(licenseName) || evidence.Length == 0 ||
                        evidence.Any(url => !Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
                                            uri.Scheme != Uri.UriSchemeHttps))
                        throw new InvalidDataException("Invalid or duplicate signed Catalog ZIP");

                    if ((extension is null || name.Equals(extension, StringComparison.OrdinalIgnoreCase)) &&
                        (pgSelection == "all" || major == pgSelection) &&
                        (version is null ? isLatest : string.Equals(version, packageVersion, StringComparison.Ordinal)))
                        pins.Add(new ReleasePins(name, major, tag, asset, sha, repoId, id,
                            new Dictionary<string, long> { [asset] = assetId }, commit)
                        {
                            Version = packageVersion,
                            License = new ReleasePackageLicense(licenseName, evidence)
                        });
                }
                if (isLatest && !cohort.Required.All(covered.Contains))
                    throw new InvalidDataException("Signed Catalog latest PG inventory incomplete");
                if (isLatest && cohort.Optional is not null && covered.Contains(cohort.Optional))
                    optionalLatest = true;
            }
            if (latest is null || !tags.Contains(latest))
                throw new InvalidDataException("Signed Catalog latest tag is absent from inventory");
        }
        if (cohort.Optional is not null && !optionalLatest)
            throw new InvalidDataException("Signed Catalog optional major lacks a latest ZIP");
        if (pins.Count == 0)
            throw new InvalidDataException("No signed Catalog download matches the item, PostgreSQL major and version selection");
        return pins;
    }

    // The feed JSON is resolved exactly once through releases/latest. The exact
    // Release tag is taken from that redirect chain and the Sigstore bundle GET
    // is pinned to it, so a latest advance mid-fetch cannot mix two Releases.
    // There is no discovery ref, no alternate stem and no fallback: a 404, a
    // different tag or a verification failure is a fetch failure.
    internal static async Task<(byte[] Feed, byte[] Bundle, string Tag)> FetchFeedAsync(
        HttpClient http, CancellationToken token = default, Action<string>? progress = null)
    {
        const string stem = "catalog-latest";
        progress?.Invoke($"FEED_FETCH_START asset={stem}.json");
        var (feedBytes, tag) = await GetReleaseAssetAsync(http, stem + ".json", null, token);
        progress?.Invoke($"FEED_FETCH_OK bytes={feedBytes.Length}");
        progress?.Invoke($"FEED_BUNDLE_FETCH_START asset={stem}.sigstore.json");
        var (bundleBytes, bundleTag) = await GetReleaseAssetAsync(
            http, stem + ".sigstore.json", tag, token);
        progress?.Invoke($"FEED_BUNDLE_FETCH_OK bytes={bundleBytes.Length}");
        if (tag != bundleTag)
            throw new InvalidDataException("Signed feed and Sigstore bundle originate from different Releases");
        return (feedBytes, bundleBytes, tag);
    }

    private static async Task<(byte[] Bytes, string Tag)> GetReleaseAssetAsync(
        HttpClient http, string asset, string? pinnedTag, CancellationToken token)
    {
        var path = (pinnedTag is null ? "latest/download/" : "download/" + pinnedTag + "/") + asset;
        var next = new Uri(ReleaseRoot + path);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var release = pinnedTag;
        for (var hop = 0; hop < 6; hop++)
        {
            if (next.Scheme != Uri.UriSchemeHttps || next.Port != 443 ||
                !string.IsNullOrEmpty(next.UserInfo) || !string.IsNullOrEmpty(next.Fragment) ||
                !seen.Add(next.AbsoluteUri))
                throw new InvalidDataException("Unsafe feed redirect");
            if (hop == 0)
            {
                if (next.Host != "github.com" || next.AbsolutePath != "/pgextwin/catalog/releases/" + path)
                    throw new InvalidDataException("Wrong Catalog feed public URI");
            }
            else if (next.Host == "github.com")
            {
                var match = Regex.Match(next.AbsolutePath,
                    @"\A/pgextwin/catalog/releases/download/(catalog-feed-[0-9a-f]{40})/" +
                    Regex.Escape(asset) + @"\z", RegexOptions.CultureInvariant);
                if (!match.Success)
                    throw new InvalidDataException("Feed asset escaped its exact Release tag");
                if (release is null)
                    release = match.Groups[1].Value;
                else if (release != match.Groups[1].Value)
                    throw new InvalidDataException("Feed asset escaped its exact Release tag");
            }
            else if (release is null ||
                     next.Host is not ("release-assets.githubusercontent.com" or
                         "objects.githubusercontent.com" or "github-releases.githubusercontent.com"))
                throw new InvalidDataException("Unapproved Catalog feed CDN");

            using var req = new HttpRequestMessage(HttpMethod.Get, next);
            using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, token);
            if (resp.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.MovedPermanently
                or HttpStatusCode.RedirectMethod or HttpStatusCode.TemporaryRedirect
                or HttpStatusCode.PermanentRedirect)
            {
                var location = resp.Headers.Location;
                if (location is null || !location.IsAbsoluteUri)
                    throw new InvalidDataException("Relative or missing feed redirect");
                next = location;
                continue;
            }
            if (resp.StatusCode != HttpStatusCode.OK)
                throw new HttpRequestException("Catalog signed feed HTTP " + (int)resp.StatusCode);
            if (release is null || next.Host == "github.com" ||
                resp.Content.Headers.ContentType?.MediaType == "text/html")
                throw new InvalidDataException("Catalog feed not returned from approved CDN");
            return (await ReadBoundedAsync(resp.Content, token), release);
        }
        throw new InvalidDataException("Too many signed feed redirects");
    }

    private static async Task<byte[]> ReadBoundedAsync(
        HttpContent content, CancellationToken token)
    {
        if (content.Headers.ContentLength is long len && (len <= 0 || len > MaxBytes))
            throw new InvalidDataException("Signed Catalog payload exceeds 2MiB cap");
        await using var stream = await content.ReadAsStreamAsync(token);
        using var mem = new MemoryStream();
        var buffer = new byte[81920];
        while (true)
        {
            int count = await stream.ReadAsync(buffer, token);
            if (count == 0) break;
            if (mem.Length + count > MaxBytes)
                throw new InvalidDataException("Signed Catalog payload exceeds 2MiB cap");
            mem.Write(buffer, 0, count);
        }
        if (mem.Length == 0) throw new InvalidDataException("Empty signed Catalog payload");
        return mem.ToArray();
    }
}
