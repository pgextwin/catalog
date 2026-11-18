using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;
using PgExtWin.Core;

namespace PgExtWin.Releases;

/// <summary>
/// External Catalog selection and bulk staging. Direct GET uses license-reviewed
/// version records; the historical signed-admission resolver remains available.
/// </summary>
public static class ExternalSignedCatalogCohort
{
    private const string DirectPath = "external/direct-get.json";
    private static readonly Uri DirectUrl = new(
        "https://raw.githubusercontent.com/pgextwin/catalog/main/" + DirectPath);

    private static readonly Uri StandaloneUrl = new(
        "https://raw.githubusercontent.com/pgextwin/catalog/main/external/standalone-get.json");

    private const string LatestPath =
        "external/signed-direct-get/qualified_cohort/latest.json";
    private const string RunRoot = "external/signed-direct-get/qualified_cohort/";
    private const int MaxMetadataBytes = 2 * 1024 * 1024;
    private static readonly Regex RunName =
        new(@"\Arun-([1-9][0-9]{0,14})\z", RegexOptions.CultureInvariant);
    private static readonly Regex Sha40 =
        new(@"\A[0-9a-f]{40}\z", RegexOptions.CultureInvariant);

    internal static long LatestRunId(byte[] latestPins)
    {
        using var doc = StrictJson.Parse(latestPins);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            !root.EnumerateObject().Select(x => x.Name).ToHashSet(StringComparer.Ordinal)
                .SetEquals(["schemaVersion", "issuerRunId", "admissionSha256", "records"]) ||
            root.GetProperty("schemaVersion").GetString() !=
                "pgextwin-external-latest-original-pins/v1" ||
            root.GetProperty("issuerRunId").ValueKind != JsonValueKind.Number ||
            !root.GetProperty("issuerRunId").TryGetInt64(out var runId) || runId <= 0 ||
            root.GetProperty("admissionSha256").ValueKind != JsonValueKind.String ||
            !Regex.IsMatch(root.GetProperty("admissionSha256").GetString() ?? "",
                @"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant))
            throw new InvalidDataException("Invalid Catalog latest external pin index");
        var records = root.GetProperty("records");
        if (records.ValueKind != JsonValueKind.Array || records.GetArrayLength() is < 1 or > 20)
            throw new InvalidDataException("Catalog latest external pin set is empty or oversized");
        return runId;
    }

    private static Uri CatalogUrl(string commit, string relativePath)
    {
        if (!Sha40.IsMatch(commit) ||
            relativePath != LatestPath && !Regex.IsMatch(relativePath,
                @"\Aexternal/signed-direct-get/qualified_cohort/run-[1-9][0-9]{0,14}/(?:external-get-admission|attestation)\.json\z",
                RegexOptions.CultureInvariant))
            throw new InvalidDataException("Unapproved immutable Catalog external path");
        return new Uri("https://raw.githubusercontent.com/pgextwin/catalog/" +
            commit + "/" + relativePath);
    }

    private static async Task<byte[]> ReadAsync(HttpClient http, Uri url,
        CancellationToken token)
    {
        if (url.Scheme != Uri.UriSchemeHttps || url.Port != 443 ||
            !string.IsNullOrEmpty(url.UserInfo) || !string.IsNullOrEmpty(url.Fragment) ||
            url.Host != "raw.githubusercontent.com" ||
            url != DirectUrl && url != StandaloneUrl && !Regex.IsMatch(url.AbsolutePath,
                @"\A/pgextwin/catalog/[0-9a-f]{40}/external/signed-direct-get/qualified_cohort/(?:latest\.json|run-[1-9][0-9]{0,14}/(?:external-get-admission|attestation)\.json)\z",
                RegexOptions.CultureInvariant))
            throw new InvalidDataException("Unapproved Catalog external HTTPS request");
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Accept.ParseAdd("application/vnd.github+json");
        using var response = await http.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, token);
        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException(
                "Catalog external records unavailable (HTTP " +
                (int)response.StatusCode + ")");
        if (response.Content.Headers.ContentLength is long size &&
            size is <= 0 or > MaxMetadataBytes)
            throw new InvalidDataException("Oversized or empty Catalog external proof");
        if (response.Content.Headers.ContentType?.MediaType == "text/html")
            throw new InvalidDataException("Catalog returned HTML instead of external records");
        await using var stream = await response.Content.ReadAsStreamAsync(token);
        using var output = new MemoryStream();
        var block = new byte[16384];
        while (true)
        {
            var count = await stream.ReadAsync(block, token);
            if (count == 0) break;
            if (output.Length + count > MaxMetadataBytes)
                throw new InvalidDataException("Catalog external proof exceeds size bound");
            output.Write(block, 0, count);
        }
        if (output.Length == 0)
            throw new InvalidDataException("Empty Catalog external proof");
        return output.ToArray();
    }

    private static async Task ConfirmCatalogHeadAsync(HttpClient http,
        string expectedCommit, CancellationToken token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get,
            "https://api.github.com/repos/pgextwin/catalog/branches/main");
        request.Headers.Accept.ParseAdd("application/vnd.github+json");
        using var response = await http.SendAsync(request,
            HttpCompletionOption.ResponseHeadersRead, token);
        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException("Catalog main recheck failed (HTTP " +
                (int)response.StatusCode + ")");
        var bytes = await ReadBoundedAsync(response, token);
        using var doc = StrictJson.Parse(bytes);
        var root = doc.RootElement;
        if (root.GetProperty("protected").ValueKind != JsonValueKind.True ||
            root.GetProperty("commit").GetProperty("sha").GetString() != expectedCommit)
            throw new InvalidDataException(
                "Catalog latest source changed during external batch; retry against current main");
    }

    private static async Task<byte[]> ReadBoundedAsync(HttpResponseMessage response,
        CancellationToken token)
    {
        if (response.Content.Headers.ContentLength is long size &&
            size is <= 0 or > MaxMetadataBytes)
            throw new InvalidDataException("Oversized Catalog head response");
        await using var stream = await response.Content.ReadAsStreamAsync(token);
        using var output = new MemoryStream();
        var block = new byte[16384];
        while (true)
        {
            var count = await stream.ReadAsync(block, token);
            if (count == 0) break;
            if (output.Length + count > MaxMetadataBytes)
                throw new InvalidDataException("Catalog head response exceeds size bound");
            output.Write(block, 0, count);
        }
        return output.ToArray();
    }

    // External policy (2026-11-17): reviewed exact-version license + byte pins,
    // direct provider GET. No Build admission, Sigstore or native-feed trust path.
    public static async Task<BatchReleaseDownloader.BatchResult> StageDirectAsync(
        string pgSelection, string outputParent, CancellationToken token = default,
        HttpMessageHandler? handler = null,
        string? requestedExtension = null, string? requestedVersion = null)
    {
        if (!Directory.Exists(outputParent))
            throw new DirectoryNotFoundException("External batch output directory missing");
        using var owned = handler is null ? new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None
        } : null;
        var sharedHandler = handler ?? owned!;
        using var http = new HttpClient(sharedHandler, disposeHandler: false)
        { Timeout = TimeSpan.FromMinutes(3) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("pgextwin-external-direct-get/1");
        var records = await ReadAsync(http, DirectUrl, token);
        var pins = SelectDirect(records, pgSelection, requestedExtension, requestedVersion);
        using var transport = new ExternalProviderAssetTransport(sharedHandler);
        return await ExternalOriginalBatchStager.StageAsync(pins, pgSelection,
            outputParent, transport.DownloadAsync, token);
    }

    public static async Task<IReadOnlyList<ExternalDownloadItem>> ListDownloadsAsync(
        string pgSelection, string? category, string? query, CancellationToken token = default,
        HttpMessageHandler? handler = null)
    {
        using var http = CreateDirectClient(handler);
        var records = await LoadDownloadsAsync(http, category, token);
        return records.Where(x => x.Item.Latest && x.Item.MatchesMajor(pgSelection))
            .Select(x => x.Item)
            .Where(x => query is null ||
                x.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                x.Version.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                x.AssetName.Contains(query, StringComparison.OrdinalIgnoreCase))
            .OrderBy(x => x.Category, StringComparer.Ordinal)
            .ThenBy(x => x.Name, StringComparer.Ordinal)
            .ThenBy(x => x.PgMajor, StringComparer.Ordinal)
            .ToArray();
    }

    public static async Task<BatchReleaseDownloader.BatchResult> DownloadAsync(
        string pgSelection, string outputParent, string? category = null, string? item = null,
        string? version = null, CancellationToken token = default, HttpMessageHandler? handler = null)
    {
        if (!Directory.Exists(outputParent))
            throw new DirectoryNotFoundException("External batch output directory missing");
        using var http = CreateDirectClient(handler);
        var records = await LoadDownloadsAsync(http, category, token);
        var pins = SelectDownloads(records, pgSelection, item, version);
        var label = item is not null ? pins[0].Extension.Replace('_', '-') : category;
        using var transport = new ExternalProviderAssetTransport(handler);
        return await ExternalOriginalBatchStager.StageAsync(pins, pgSelection, outputParent,
            transport.DownloadAsync, token, outputLabel: label, standaloneSelection: true);
    }

    private static HttpClient CreateDirectClient(HttpMessageHandler? handler)
    {
        var http = new HttpClient(handler ?? new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None
        }, disposeHandler: handler is null) { Timeout = TimeSpan.FromMinutes(3) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("pgextwin-external-direct-get/1");
        return http;
    }

    private static async Task<IReadOnlyList<DownloadRecord>> LoadDownloadsAsync(
        HttpClient http, string? category, CancellationToken token)
    {
        var records = new List<DownloadRecord>();
        if (category is null or "extensions" or "spatial")
            records.AddRange(ParseDownloads(await ReadAsync(http, DirectUrl, token), standalone: false));
        if (category is not "extensions")
            records.AddRange(ParseDownloads(await ReadAsync(http, StandaloneUrl, token), standalone: true));
        return records.Where(x => category is null || x.Item.Category == category).ToArray();
    }

    internal static IReadOnlyList<ExternalOriginalPin> SelectDirect(byte[] records,
        string pgSelection, string? requestedExtension = null, string? requestedVersion = null)
    {
        if (pgSelection is not ("14" or "15" or "16" or "17" or "18" or "all"))
            throw new InvalidDataException("Expected PG14–18/all");
        return SelectDownloads(ParseDownloads(records, standalone: false),
            pgSelection, requestedExtension, requestedVersion);
    }

    private static IReadOnlyList<ExternalOriginalPin> SelectDownloads(
        IReadOnlyList<DownloadRecord> records, string pgSelection, string? item, string? version)
    {
        if (version is not null && item is null)
            throw new InvalidDataException("--version requires an item name");
        var pins = records
            .Where(x => x.Item.MatchesMajor(pgSelection) &&
                (item is null || x.Item.Name.Equals(item, StringComparison.OrdinalIgnoreCase)) &&
                (version is null ? x.Item.Latest : x.Item.Version == version))
            .Select(x => x.Pin).Distinct().ToArray();
        if (pins.Length == 0)
            throw new InvalidDataException("No external download matches the item, category, version or PostgreSQL major");
        return pins;
    }

    private static IReadOnlyList<DownloadRecord> ParseDownloads(byte[] bytes, bool standalone)
    {
        using var doc = StrictJson.Parse(bytes);
        var root = doc.RootElement;
        var schema = standalone ? "pgextwin-standalone-get/v1" : "pgextwin-external-direct-get/v1";
        if (root.GetProperty("schemaVersion").GetString() != schema)
            throw new InvalidDataException("Invalid external direct GET records");
        var records = new List<DownloadRecord>();
        var identities = new HashSet<(string, string?, string)>();
        foreach (var row in root.GetProperty("records").EnumerateArray())
        {
            string Text(string key) => row.GetProperty(key).GetString()
                ?? throw new InvalidDataException("Missing external record " + key);
            var name = Text(standalone ? "item" : "extension");
            var version = Text("upstreamVersion");
            var license = Text("license");
            var evidence = row.GetProperty("licenseEvidence");
            if (string.IsNullOrWhiteSpace(version) || string.IsNullOrWhiteSpace(license) ||
                evidence.GetArrayLength() == 0)
                throw new InvalidDataException("Missing exact-version license evidence");
            if (standalone)
                foreach (var proof in evidence.EnumerateArray())
                    if (!Uri.TryCreate(proof.GetProperty("url").GetString(), UriKind.Absolute, out var url) ||
                        url.Scheme != Uri.UriSchemeHttps ||
                        string.IsNullOrWhiteSpace(proof.GetProperty("file").GetString()) ||
                        !Regex.IsMatch(proof.GetProperty("sha256").GetString() ?? "", @"\A[0-9a-f]{64}\z"))
                        throw new InvalidDataException("Invalid exact-version license evidence");

            var major = row.GetProperty("pgMajor").GetString();
            var asset = Text("assetName");
            var size = row.GetProperty("originalBytes").GetInt64();
            var sha = Text("originalSha256");
            var providerUrl = Text("originalProviderUrl");
            var pin = standalone
                ? new ExternalOriginalPin(name, major ?? "any", "", 0, version, 0, asset, 0,
                    size, sha, providerUrl, ExternalProviderAssetTransport.StandaloneProvider)
                : new ExternalOriginalPin(name, major!, Text("sourceRepo"),
                    row.GetProperty("repositoryId").GetInt64(), Text("releaseTag"),
                    row.GetProperty("releaseId").GetInt64(), asset, row.GetProperty("assetId").GetInt64(),
                    size, sha, providerUrl, row.TryGetProperty("provider", out _) ? Text("provider") : null);
            ExternalProviderAssetTransport.ValidatePin(pin);
            var osgeo = pin.Provider == ExternalProviderAssetTransport.OsgeoProvider;
            var category = standalone ? Text("category") : osgeo ? "spatial" : "extensions";
            if (standalone && category is not ("spatial" or "tools" or "drivers"))
                throw new InvalidDataException("Invalid standalone download category");
            var latest = row.GetProperty("latest").GetBoolean();

            void Add(string item, string itemVersion)
            {
                if (string.IsNullOrWhiteSpace(itemVersion) || !identities.Add((item, major, itemVersion)))
                    throw new InvalidDataException("Invalid or duplicate external download record");
                records.Add(new DownloadRecord(new ExternalDownloadItem(item, category, major, itemVersion,
                    asset, license, size, sha, latest), pin));
            }

            Add(name, version);
            // Each extension name selects the same original bundle and destination.
            if (osgeo)
            {
                if (pin.Tag != version)
                    throw new InvalidDataException("Invalid OSGeo extension version");
                Add("pgrouting", Text("pgroutingVersion"));
            }
        }
        return records;
    }

    private sealed record DownloadRecord(ExternalDownloadItem Item, ExternalOriginalPin Pin);

    public static async Task<BatchReleaseDownloader.BatchResult> StageLatestVerifiedAsync(
        string pgSelection, string outputParent, CancellationToken token = default,
        HttpMessageHandler? handler = null,
        string? requestedExtension = null, string? requestedVersion = null)
    {
        if (!Directory.Exists(outputParent))
            throw new DirectoryNotFoundException("External batch output directory missing");
        using var owned = handler is null ? new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None
        } : null;
        var sharedHandler = handler ?? owned!;
        using var http = new HttpClient(sharedHandler, disposeHandler: false)
        { Timeout = TimeSpan.FromMinutes(3) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("pgextwin-external-latest-pins/1");
        var tokenValue = Environment.GetEnvironmentVariable("GH_TOKEN")
            ?? Environment.GetEnvironmentVariable("GITHUB_TOKEN");
        if (!string.IsNullOrWhiteSpace(tokenValue))
            http.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", tokenValue);

        // Reuse the native latest-release trust boundary: protected current
        // main, a verified GitHub merge, and successful exact-head Validate.
        using var snapshot = await AuthenticatedCatalogHead.AcquireAsync(
            outputParent, sharedHandler, token);
        var latestPins = await ReadAsync(http, CatalogUrl(snapshot.Commit, LatestPath), token);
        var runId = LatestRunId(latestPins);
        var runDirectory = "run-" + runId;
        if (!RunName.IsMatch(runDirectory))
            throw new InvalidDataException("Unsafe Catalog latest signed Run path");
        var prefix = RunRoot + runDirectory + "/";
        var admission = await ReadAsync(http,
            CatalogUrl(snapshot.Commit, prefix + "external-get-admission.json"), token);
        var bundle = await ReadAsync(http,
            CatalogUrl(snapshot.Commit, prefix + "attestation.json"), token);

        async Task ConfirmCurrent(CancellationToken cancellation) =>
            await ConfirmCatalogHeadAsync(http, snapshot.Commit, cancellation);

        return await ExternalSignedDirectGetAdmission.StageVerifiedBytesAsync(
            admission, bundle, pgSelection, outputParent, token,
            runId, latestPins, ConfirmCurrent, requestedExtension, requestedVersion);
    }
}
