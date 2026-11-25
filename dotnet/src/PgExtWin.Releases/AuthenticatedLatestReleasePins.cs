using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using PgExtWin.Catalog;
using PgExtWin.Core;

namespace PgExtWin.Releases;

/// <summary>
/// Resolve EXACT Catalog-selected published Release assets against authenticated
/// GitHub API metadata. No API 'latest' inference; no candidate assets;
/// the protected-main Catalog's tag, URL and SHA256 remain authoritative.
/// This is metadata/byte integrity, never extension Sigstore verification.
/// </summary>
public static class AuthenticatedLatestReleasePins
{
    private static readonly Regex Hex64 = new(@"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant);
    public static async Task<IReadOnlyList<ReleasePins>> ResolveAsync(
        AuthenticatedCatalogHead.Session snapshot, string selection,
        HttpMessageHandler? handler = null, CancellationToken cancellationToken = default)
    {
        if (selection != "all" &&
            !snapshot.ApprovedMajors.Contains(selection, StringComparer.Ordinal))
            throw new InvalidDataException("Selection is outside approved PostgreSQL cohort");
        var names = CatalogReader.LoadLocal(snapshot.CatalogPath);
        VerifiedFleetRoster.Require(names.Select(x => x.Name));
        var approved = snapshot.ApprovedMajors;
        if (names.Any(x => approved.Any(major =>
                !x.Versions.Any(version => version.Major == major))))
            throw new InvalidDataException("Latest fleet is incomplete for approved cohort");
        var majors = selection == "all" ? approved.ToArray() : new[] { selection };
        using var ownedHandler = handler is null ? new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None
        } : null;
        using var http = new HttpClient(handler ?? ownedHandler!, disposeHandler: false)
        { Timeout = TimeSpan.FromSeconds(45) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("pgextwin-cli-latest-release-identity/1");
        var token = Environment.GetEnvironmentVariable("GH_TOKEN")
            ?? Environment.GetEnvironmentVariable("GITHUB_TOKEN");
        if (!string.IsNullOrWhiteSpace(token))
            http.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        var result = new List<ReleasePins>();
        foreach (var extension in names.OrderBy(x => x.Name, StringComparer.Ordinal))
        {
            var recordFile = Path.Combine(snapshot.CatalogPath, "packages", extension.Name + ".json");
            using var recordDoc = StrictJson.Parse(File.ReadAllBytes(recordFile));
            var (tag, packagesByMajor) = ReadLatestLedgerPackages(recordDoc.RootElement, extension.Name);
            if (!PinnedReleaseSelector.SafeAssetName(tag))
                throw new InvalidDataException("Unsafe Catalog-selected release tag");

            using var repo = await ApiAsync(http, extension.Name, "", cancellationToken);
            var repoRoot = repo.RootElement;
            var repoId = repoRoot.GetProperty("id").GetInt64();
            if (repoRoot.GetProperty("full_name").GetString() != "pgextwin/" + extension.Name || repoId <= 0)
                throw new InvalidDataException("Wrong published extension repository identity");

            using var release = await ApiAsync(http, extension.Name,
                "/releases/tags/" + tag, cancellationToken);
            var info = release.RootElement;
            if (info.GetProperty("tag_name").GetString() != tag ||
                info.GetProperty("draft").GetBoolean() ||
                info.GetProperty("published_at").ValueKind != JsonValueKind.String ||
                info.GetProperty("id").GetInt64() <= 0)
                throw new InvalidDataException("Catalog release is not a public exact-tag Release");
            var releaseId = info.GetProperty("id").GetInt64();
            var items = info.GetProperty("assets");
            if (items.ValueKind != JsonValueKind.Array || items.GetArrayLength() == 0 ||
                items.GetArrayLength() > 200)
                throw new InvalidDataException("Missing or oversized original asset list");
            var assets = new Dictionary<string, (long Id, string Digest)>(StringComparer.Ordinal);
            var usedIds = new HashSet<long>();
            foreach (var item in items.EnumerateArray())
            {
                var name = item.GetProperty("name").GetString() ?? "";
                var id = item.GetProperty("id").GetInt64();
                var expectedUrl = "https://github.com/pgextwin/" + extension.Name +
                    "/releases/download/" + tag + "/" + name;
                if (!PinnedReleaseSelector.SafeAssetName(name) || id <= 0 ||
                    !usedIds.Add(id) ||
                    item.GetProperty("state").GetString() != "uploaded" ||
                    item.GetProperty("browser_download_url").GetString() != expectedUrl ||
                    !assets.TryAdd(name, (id, item.GetProperty("digest").GetString() ?? "")))
                    throw new InvalidDataException("Invalid, duplicate or moved Release asset identity");
            }
            if (!assets.ContainsKey("SHA256SUMS.txt"))
                throw new InvalidDataException("Published SHA256SUMS inventory missing");

            foreach (var major in majors)
            {
                if (!packagesByMajor.TryGetValue(major, out var pkg))
                    throw new InvalidDataException("Catalog latest lacks PG" + major);
                var asset = pkg.Asset;
                var digest = pkg.Sha256;
                if (!PinnedReleaseSelector.SafeAssetName(asset) ||
                    !asset.StartsWith(extension.Name + "-", StringComparison.Ordinal) ||
                    !asset.EndsWith("-pg" + major + "-windows-x64.zip", StringComparison.Ordinal) ||
                    !Hex64.IsMatch(digest) ||
                    !assets.TryGetValue(asset, out var item) ||
                    item.Digest != "sha256:" + digest)
                    throw new InvalidDataException("Catalog ZIP SHA256 differs from public Release");
                result.Add(new ReleasePins(extension.Name, major, tag, asset,
                    digest, repoId, releaseId,
                    new Dictionary<string, long>(StringComparer.Ordinal)
                    {
                        [asset] = item.Id,
                        ["SHA256SUMS.txt"] = assets["SHA256SUMS.txt"].Id
                    }, snapshot.Commit));
            }
        }
        if (result.Count != names.Count * majors.Length ||
            result.Select(p => p.Extension + "/" + p.PgMajor).Distinct(StringComparer.Ordinal).Count() != result.Count)
            throw new InvalidDataException("Incomplete latest ZIP plan");
        return result;
    }

    private static (string Tag, Dictionary<string, (string Asset, string Sha256)> Packages)
        ReadLatestLedgerPackages(JsonElement record, string expectedName)
    {
        if (record.ValueKind != JsonValueKind.Object ||
            !record.TryGetProperty("schemaVersion", out var schema) ||
            schema.ValueKind != JsonValueKind.Number || !schema.TryGetInt32(out var ver) || ver != 1 ||
            !record.TryGetProperty("name", out var nameEl) || nameEl.GetString() != expectedName ||
            !record.TryGetProperty("repository", out var repoEl) || repoEl.GetString() != "pgextwin/" + expectedName ||
            !record.TryGetProperty("latestReleaseId", out var latestIdEl) ||
            latestIdEl.ValueKind != JsonValueKind.Number || !latestIdEl.TryGetInt64(out var latestId) || latestId <= 0 ||
            !record.TryGetProperty("unavailableMajors", out var unavailEl) || unavailEl.ValueKind != JsonValueKind.Array ||
            !record.TryGetProperty("releases", out var releasesEl) || releasesEl.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Invalid Catalog package ledger: " + expectedName);

        var unavailable = new HashSet<string>(StringComparer.Ordinal);
        foreach (var m in unavailEl.EnumerateArray())
        {
            var s = m.ValueKind == JsonValueKind.String ? m.GetString() ?? "" : "";
            if (string.IsNullOrEmpty(s) || !unavailable.Add(s))
                throw new InvalidDataException("Invalid unavailableMajors in Catalog ledger: " + expectedName);
        }

        JsonElement latest = default;
        var found = false;
        foreach (var rel in releasesEl.EnumerateArray())
        {
            if (rel.ValueKind != JsonValueKind.Object ||
                !rel.TryGetProperty("releaseId", out var relIdEl) ||
                relIdEl.ValueKind != JsonValueKind.Number || !relIdEl.TryGetInt64(out var relId) || relId <= 0)
                throw new InvalidDataException("Invalid release in Catalog ledger: " + expectedName);
            if (relId == latestId)
            {
                if (found)
                    throw new InvalidDataException("Duplicate latestReleaseId in Catalog ledger: " + expectedName);
                latest = rel;
                found = true;
            }
        }
        if (!found || latest.TryGetProperty("admission", out _) ||
            latest.TryGetProperty("legacyInventoryCommit", out _) ||
            !latest.TryGetProperty("releaseTag", out var tagEl) || tagEl.ValueKind != JsonValueKind.String ||
            !latest.TryGetProperty("packages", out var pkgsEl) || pkgsEl.ValueKind != JsonValueKind.Array ||
            pkgsEl.GetArrayLength() == 0)
            throw new InvalidDataException("Invalid latest release in Catalog ledger: " + expectedName);

        var tag = tagEl.GetString() ?? "";
        var packages = new Dictionary<string, (string Asset, string Sha256)>(StringComparer.Ordinal);
        foreach (var pkg in pkgsEl.EnumerateArray())
        {
            if (pkg.ValueKind != JsonValueKind.Object ||
                !pkg.TryGetProperty("pgMajor", out var majorEl) || majorEl.ValueKind != JsonValueKind.String ||
                !pkg.TryGetProperty("asset", out var assetEl) || assetEl.ValueKind != JsonValueKind.String ||
                !pkg.TryGetProperty("sha256", out var shaEl) || shaEl.ValueKind != JsonValueKind.String)
                throw new InvalidDataException("Invalid package entry in Catalog ledger: " + expectedName);
            var major = majorEl.GetString() ?? "";
            if (unavailable.Contains(major) ||
                !packages.TryAdd(major, (assetEl.GetString() ?? "", shaEl.GetString() ?? "")))
                throw new InvalidDataException("Conflicting or duplicate package major in Catalog ledger: " + expectedName);
        }
        return (tag, packages);
    }

    private static async Task<JsonDocument> ApiAsync(
        HttpClient http, string extension, string subpath, CancellationToken token)
    {
        if (!Regex.IsMatch(extension, @"\A[a-z][a-z0-9_]*\z") ||
            subpath != "" && !Regex.IsMatch(subpath,
                @"\A/releases/tags/[A-Za-z0-9][A-Za-z0-9._-]*\z"))
            throw new InvalidDataException("Unsafe GitHub Release API URI");
        var url = new Uri("https://api.github.com/repos/pgextwin/" + extension + subpath);
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Accept.ParseAdd("application/vnd.github+json");
        using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, token);
        if (resp.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException("Live GitHub Release metadata HTTP " + (int)resp.StatusCode);
        if (resp.Content.Headers.ContentLength is long count && (count < 1 || count > 2_000_000))
            throw new InvalidDataException("Live Release metadata oversized");
        if (resp.Content.Headers.ContentType?.MediaType == "text/html")
            throw new InvalidDataException("Received HTML instead of Release metadata");
        await using var stream = await resp.Content.ReadAsStreamAsync(token);
        using var mem = new MemoryStream();
        var buffer = new byte[81920];
        while (true)
        {
            var n = await stream.ReadAsync(buffer, token);
            if (n == 0) break;
            if (mem.Length + n > 2_000_000)
                throw new InvalidDataException("Live Release metadata exceeded cap");
            mem.Write(buffer, 0, n);
        }
        return StrictJson.Parse(mem.ToArray());
    }
}
