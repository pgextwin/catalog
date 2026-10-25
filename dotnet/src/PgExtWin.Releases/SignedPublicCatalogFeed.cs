using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using PgExtWin.Catalog;
using PgExtWin.Core;
using Sigstore;

namespace PgExtWin.Releases;

/// <summary>
/// REST-quota-independent, cryptographically verified Catalog latest selector.
/// Validates the actual GitHub Actions Sigstore signed metadata against the
/// pinned workflow/repository/main identity before accepting ANY pins.
/// Original extension ZIP signatures are NOT verified by the feed signature.
/// </summary>
public static class SignedPublicCatalogFeed
{
    private const string Root = "https://github.com/pgextwin/catalog/releases/latest/download/";
    private const string SignerSan =
        "https://github.com/pgextwin/catalog/.github/workflows/cli-signed-catalog-feed.yml@refs/heads/main";
    private const int MaxBytes = 2 * 1024 * 1024;
    private static readonly Regex Sha40 = new(@"\A[0-9a-f]{40}\z", RegexOptions.CultureInvariant);
    private static readonly Regex Sha64 = new(@"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant);
    private static readonly Regex SafeName = new(@"\A[a-z][a-z0-9_]*\z", RegexOptions.CultureInvariant);
    private const int FirstSupportedMajor = 14;
    private const int HighestPermittedMajor = 32;
    private const int MaxSupportedCohort = 12;

    private static string[] RequireSignedMajors(JsonElement root)
    {
        var raw = root.GetProperty("postgresqlMajors");
        if (raw.ValueKind != JsonValueKind.Array ||
            raw.GetArrayLength() is < 1 or > MaxSupportedCohort)
            throw new InvalidDataException("Invalid signed-feed PG cohort");
        var majors = raw.EnumerateArray().Select(item =>
        {
            if (item.ValueKind != JsonValueKind.String)
                throw new InvalidDataException("Nonstring signed PG major");
            return item.GetString() ?? "";
        }).ToArray();
        if (majors.Any(item => !Regex.IsMatch(item, @"\A[1-9][0-9]*\z")) ||
            majors.Any(item => !int.TryParse(item, out var n) ||
                               n < FirstSupportedMajor || n > HighestPermittedMajor))
            throw new InvalidDataException("Unsupported signed PG major");
        var start = int.Parse(majors[0]);
        if (!majors.SequenceEqual(Enumerable.Range(start, majors.Length)
                                  .Select(n => n.ToString(System.Globalization.CultureInfo.InvariantCulture))))
            throw new InvalidDataException("Signed PG cohort has gaps or duplicates");
        return majors;
    }

    public sealed class Session : IDisposable
    {
        public string Commit { get; }
        public string SourceReleaseTag { get; }
        public IReadOnlyList<ReleasePins> Pins { get; }
        public IReadOnlyList<string> ApprovedMajors { get; }
        public string Directory { get; }
        public string CatalogPath => Path.Combine(Directory, "catalog");
        internal Session(string directory, string commit, string tag, IReadOnlyList<ReleasePins> pins,
            IReadOnlyList<string> approvedMajors)
        {
            Directory = directory;
            Commit = commit;
            SourceReleaseTag = tag;
            Pins = pins;
            ApprovedMajors = approvedMajors;
        }
        public void Dispose()
        {
            if (System.IO.Directory.Exists(Directory))
                System.IO.Directory.Delete(Directory, recursive: true);
        }
    }

    public static async Task<Session> AcquireAsync(string outputParent, string pgSelection,
        HttpMessageHandler? handler = null, CancellationToken token = default,
        Action<string>? progress = null)
    {
        if (pgSelection != "all" &&
            (!int.TryParse(pgSelection, out var requested) ||
             requested < FirstSupportedMajor || requested > HighestPermittedMajor ||
             requested.ToString(System.Globalization.CultureInfo.InvariantCulture) != pgSelection))
            throw new InvalidDataException("Unsupported signed Catalog PG selection");
        var parent = Path.GetFullPath(outputParent);
        if (!System.IO.Directory.Exists(parent))
            throw new DirectoryNotFoundException("Output directory missing");
        for (DirectoryInfo? d = new(parent); d is not null; d = d.Parent)
            if ((d.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Output contains a filesystem link");

        using var owned = handler is null ? new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None
        } : null;
        using var http = new HttpClient(handler ?? owned!, disposeHandler: false)
        { Timeout = TimeSpan.FromMinutes(3) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("pgextwin-signed-catalog-feed/0.3");

        progress?.Invoke("FEED_FETCH_START asset=catalog-latest.json");
        var (feedBytes, tag) = await GetReleaseAssetAsync(http, "catalog-latest.json", token);
        progress?.Invoke($"FEED_FETCH_OK bytes={feedBytes.Length}");
        progress?.Invoke("FEED_BUNDLE_FETCH_START asset=catalog-latest.sigstore.json");
        var (bundleBytes, secondTag) = await GetReleaseAssetAsync(http, "catalog-latest.sigstore.json", token);
        progress?.Invoke($"FEED_BUNDLE_FETCH_OK bytes={bundleBytes.Length}");
        if (tag != secondTag)
            throw new InvalidDataException("Signed feed and Sigstore bundle originate from different Releases");

        // Never use Catalog or Release-provided keys. Sigstore's TUF public-good
        // trust root is independent; OIDC issuer, SAN and repository/main are fixed here.
        using var feed = StrictJson.Parse(feedBytes);
        var root = feed.RootElement;
        var commit = root.GetProperty("catalogCommit").GetString() ?? "";
        var expectedCount = root.GetProperty("extensionCount").GetInt32();
        var majors = RequireSignedMajors(root);
        if (pgSelection != "all" && !majors.Contains(pgSelection, StringComparer.Ordinal))
            throw new InvalidDataException("Requested PG major is not in signer-approved Catalog cohort");
        if (!Sha40.IsMatch(commit) ||
            root.GetProperty("schemaVersion").GetString() != "pgextwin-signed-catalog-zip-feed/v1" ||
            root.GetProperty("repository").GetString() != "pgextwin/catalog" ||
            (expectedCount < VerifiedFleetRoster.MinimumCount ||
             expectedCount > VerifiedFleetRoster.MaximumCount) ||
            root.GetProperty("zipCount").GetInt32() != expectedCount * majors.Length ||
            root.GetProperty("extensionSignatureVerified").ValueKind != JsonValueKind.False ||
            root.GetProperty("publicationAuthorized").ValueKind != JsonValueKind.False ||
            root.GetProperty("installAuthorized").ValueKind != JsonValueKind.False ||
            tag != "catalog-feed-" + commit)
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
        var stage = Path.Combine(parent, ".pgextwin-signed-catalog-" + Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(Path.Combine(stage, "catalog", "extensions"));
        try
        {
            var catalogue = Path.Combine(stage, "catalog");
            var hashes = root.GetProperty("catalogSha256");
            var entries = hashes.EnumerateObject().ToArray();
            if (entries.Length != expectedCount + 1)
                throw new InvalidDataException("Signed Catalog byte digest inventory incomplete");
            var paths = new List<string> { "index.json" };
            var releaseArray = root.GetProperty("releases").EnumerateArray().ToArray();
            if (releaseArray.Length != expectedCount)
                throw new InvalidDataException("Signed latest Release inventory incomplete");
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var rec in releaseArray)
            {
                var name = rec.GetProperty("extension").GetString() ?? "";
                if (!SafeName.IsMatch(name) || !names.Add(name))
                    throw new InvalidDataException("Signed feed contains unknown/duplicate extension");
                paths.Add("extensions/" + name + ".json");
            }
            VerifiedFleetRoster.Require(names.Order(StringComparer.Ordinal));
            if (paths.Count != expectedCount + 1 || entries.Any(x =>
                !paths.Contains(x.Name, StringComparer.Ordinal) ||
                !Sha64.IsMatch(x.Value.GetString() ?? "")))
                throw new InvalidDataException("Signed feed contains unsafe Catalog paths or raw digests");

            foreach (var path in paths)
            {
                var bytes = await GetImmutableRecordAsync(http, commit, path, token);
                if (StrictJson.Sha256(bytes) != hashes.GetProperty(path).GetString())
                    throw new InvalidDataException("Immutable Catalog record differs from Sigstore-signed digest");
                var file = Path.Combine(catalogue, path.Replace('/', Path.DirectorySeparatorChar));
                await File.WriteAllBytesAsync(file, bytes, token);
                progress?.Invoke($"CATALOG_RECORD_VERIFIED path={path} bytes={bytes.Length}");
            }
            var loaded = CatalogReader.LoadLocal(catalogue);
            if (loaded.Count != expectedCount || loaded.Any(x => x.Versions.Count != majors.Length ||
                                  !x.Versions.Select(v => v.Major).SequenceEqual(majors)) ||
                !loaded.Select(x => x.Name).SequenceEqual(
                    names.Order(StringComparer.Ordinal)))
                throw new InvalidDataException("Signed Catalog fleet is incomplete");

            var selected = pgSelection == "all" ? majors : [pgSelection];
            var pins = new List<ReleasePins>();
            foreach (var info in releaseArray)
            {
                var name = info.GetProperty("extension").GetString()!;
                using var record = StrictJson.Parse(
                    await File.ReadAllBytesAsync(Path.Combine(catalogue, "extensions", name + ".json"), token));
                var catalog = record.RootElement;
                var tagValue = info.GetProperty("releaseTag").GetString() ?? "";
                var repoId = info.GetProperty("repositoryId").GetInt64();
                var releaseId = info.GetProperty("releaseId").GetInt64();
                var sumId = info.GetProperty("checksumsAssetId").GetInt64();
                if (repoId <= 0 || releaseId <= 0 || sumId <= 0 ||
                    !PinnedReleaseSelector.SafeAssetName(tagValue) ||
                    tagValue != catalog.GetProperty("latest").GetProperty("releaseTag").GetString())
                    throw new InvalidDataException("Signed Catalog release identity invalid");

                var zipRows = info.GetProperty("packages").EnumerateArray().ToArray();
                if (zipRows.Length != majors.Length ||
                    !zipRows.Select(x => x.GetProperty("pgMajor").GetString())
                        .SequenceEqual(majors))
                    throw new InvalidDataException("Signed Catalog PG inventory incomplete");
                foreach (var row in zipRows)
                {
                    var major = row.GetProperty("pgMajor").GetString()!;
                    var asset = row.GetProperty("asset").GetString() ?? "";
                    var sha = row.GetProperty("sha256").GetString() ?? "";
                    var url = row.GetProperty("downloadUrl").GetString() ?? "";
                    var assetId = row.GetProperty("assetId").GetInt64();
                    var expectedUrl = "https://github.com/pgextwin/" + name +
                        "/releases/download/" + tagValue + "/" + asset;
                    var pg = catalog.GetProperty("postgresql").GetProperty(major);
                    if (!pg.GetProperty("available").GetBoolean() ||
                        !Sha64.IsMatch(sha) || assetId <= 0 ||
                        !PinnedReleaseSelector.SafeAssetName(asset) ||
                        !asset.StartsWith(name + "-", StringComparison.Ordinal) ||
                        !asset.EndsWith("-pg" + major + "-windows-x64.zip", StringComparison.Ordinal) ||
                        url != expectedUrl ||
                        pg.GetProperty("asset").GetString() != asset ||
                        pg.GetProperty("downloadUrl").GetString() != url ||
                        pg.GetProperty("sha256").GetString() != sha)
                        throw new InvalidDataException("Signed feed differs from immutable Catalog ZIP");
                    if (selected.Contains(major, StringComparer.Ordinal))
                        pins.Add(new ReleasePins(name, major, tagValue, asset, sha,
                            repoId, releaseId,
                            new Dictionary<string, long>
                            {
                                [asset] = assetId,
                                ["SHA256SUMS.txt"] = sumId
                            }, commit));
                }
            }
            if (pins.Count != selected.Length * expectedCount)
                throw new InvalidDataException("Incomplete Sigstore-signed Catalog selection");
            progress?.Invoke($"CATALOG_PINS_SELECTED count={pins.Count} pg={pgSelection} extension_auth=INTEGRITY_ONLY");
            return new Session(stage, commit, tag, pins, majors);
        }
        catch
        {
            if (System.IO.Directory.Exists(stage))
                System.IO.Directory.Delete(stage, recursive: true);
            throw;
        }
    }

    private static async Task<(byte[] Bytes, string Tag)> GetReleaseAssetAsync(
        HttpClient http, string asset, CancellationToken token)
    {
        if (asset is not ("catalog-latest.json" or "catalog-latest.sigstore.json"))
            throw new InvalidDataException("Unsupported signed Catalog feed asset");
        var next = new Uri(Root + asset);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        string? release = null;
        for (var hop = 0; hop < 6; hop++)
        {
            if (next.Scheme != Uri.UriSchemeHttps || next.Port != 443 ||
                !string.IsNullOrEmpty(next.UserInfo) || !string.IsNullOrEmpty(next.Fragment) ||
                !seen.Add(next.AbsoluteUri))
                throw new InvalidDataException("Unsafe feed redirect");
            if (hop == 0)
            {
                if (next.Host != "github.com" ||
                    next.AbsolutePath != "/pgextwin/catalog/releases/latest/download/" + asset)
                    throw new InvalidDataException("Wrong Catalog feed public URI");
            }
            else if (next.Host == "github.com")
            {
                var match = Regex.Match(next.AbsolutePath,
                    @"\A/pgextwin/catalog/releases/download/(catalog-feed-[0-9a-f]{40})/" +
                    Regex.Escape(asset) + @"\z", RegexOptions.CultureInvariant);
                if (!match.Success || release is not null)
                    throw new InvalidDataException("Feed latest escaped its exact Release tag");
                release = match.Groups[1].Value;
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

    private static async Task<byte[]> GetImmutableRecordAsync(
        HttpClient http, string commit, string path, CancellationToken token)
    {
        if (!Sha40.IsMatch(commit) ||
            path != "index.json" && !Regex.IsMatch(path,
                @"\Aextensions/[a-z][a-z0-9_]*\.json\z", RegexOptions.CultureInvariant))
            throw new InvalidDataException("Invalid immutable Catalog request");
        var url = new Uri("https://raw.githubusercontent.com/pgextwin/catalog/" +
                          commit + "/" + path);
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token);
        if (response.StatusCode != HttpStatusCode.OK ||
            response.Content.Headers.ContentType?.MediaType == "text/html")
            throw new HttpRequestException("Immutable Catalog JSON GET failed");
        return await ReadBoundedAsync(response.Content, token);
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
