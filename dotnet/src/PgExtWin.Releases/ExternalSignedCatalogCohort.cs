using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;
using PgExtWin.Core;

namespace PgExtWin.Releases;

/// <summary>
/// Resolve the Catalog's explicit latest external-original pin set from an
/// authenticated protected-main snapshot. The pointer chooses current source
/// versions; its exact admission digest and identities must match an owner-
/// signed Build subject before any provider GET can occur.
/// </summary>
public static class ExternalSignedCatalogCohort
{
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
            !Regex.IsMatch(url.AbsolutePath,
                @"\A/pgextwin/catalog/[0-9a-f]{40}/external/signed-direct-get/qualified_cohort/(?:latest\.json|run-[1-9][0-9]{0,14}/(?:external-get-admission|attestation)\.json)\z",
                RegexOptions.CultureInvariant))
            throw new InvalidDataException("Unapproved Catalog external HTTPS request");
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Accept.ParseAdd("application/vnd.github+json");
        using var response = await http.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, token);
        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException(
                "Immutable Catalog latest external pin unavailable (HTTP " +
                (int)response.StatusCode + ")");
        if (response.Content.Headers.ContentLength is long size &&
            size is <= 0 or > MaxMetadataBytes)
            throw new InvalidDataException("Oversized or empty Catalog external proof");
        if (response.Content.Headers.ContentType?.MediaType == "text/html")
            throw new InvalidDataException("Catalog returned HTML instead of signed metadata");
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

    public static async Task<BatchReleaseDownloader.BatchResult> StageLatestVerifiedAsync(
        string pgSelection, string outputParent, CancellationToken token = default,
        HttpMessageHandler? handler = null)
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
            runId, latestPins, ConfirmCurrent);
    }
}
