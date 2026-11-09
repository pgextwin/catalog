using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using PgExtWin.Core;

namespace PgExtWin.Releases;

/// <summary>
/// Find the newest Catalog-published, owner-signed external GET-only cohort.
/// Catalog directory metadata is solely a locator: neither it nor a provider
/// discovery record can authorize a download. The exact fetched subject and
/// Sigstore bundle must still pass the independent Build issuer verifier.
/// </summary>
public static class ExternalSignedCatalogCohort
{
    private const string DirectoryApi =
        "https://api.github.com/repos/pgextwin/catalog/contents/" +
        "external/signed-direct-get/qualified_cohort?ref=main";
    private const string RawRoot =
        "https://raw.githubusercontent.com/pgextwin/catalog/main/" +
        "external/signed-direct-get/qualified_cohort/";
    private const int MaxMetadataBytes = 2 * 1024 * 1024;
    private static readonly Regex RunName =
        new(@"\Arun-([1-9][0-9]{0,14})\z", RegexOptions.CultureInvariant);

    internal static long LatestRunId(byte[] listing)
    {
        using var doc = StrictJson.Parse(listing);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Array || root.GetArrayLength() is < 1 or > 1000)
            throw new InvalidDataException("No bounded Catalog signed external cohort archive");
        long latest = 0;
        foreach (var entry in root.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object ||
                !entry.TryGetProperty("name", out var name) ||
                name.ValueKind != JsonValueKind.String ||
                !entry.TryGetProperty("type", out var kind) ||
                kind.ValueKind != JsonValueKind.String ||
                kind.GetString() != "dir")
                continue;
            var match = RunName.Match(name.GetString() ?? "");
            if (match.Success && long.TryParse(match.Groups[1].Value, out var runId))
                latest = Math.Max(latest, runId);
        }
        if (latest == 0)
            throw new InvalidDataException(
                "No owner-signed external cohort is published in Catalog; download denied");
        return latest;
    }

    private static async Task<byte[]> ReadAsync(
        HttpClient http, string url, CancellationToken token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        using var response = await http.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, token);
        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException(
                "Catalog external cohort unavailable (HTTP " + (int)response.StatusCode + ")");
        if (response.Content.Headers.ContentLength is long size &&
            size is <= 0 or > MaxMetadataBytes)
            throw new InvalidDataException("Oversized or empty Catalog external proof");
        await using var stream = await response.Content.ReadAsStreamAsync(token);
        using var buffer = new MemoryStream();
        var block = new byte[16384];
        while (true)
        {
            int count = await stream.ReadAsync(block, token);
            if (count == 0) break;
            if (buffer.Length + count > MaxMetadataBytes)
                throw new InvalidDataException("Catalog external proof exceeds size bound");
            buffer.Write(block, 0, count);
        }
        if (buffer.Length == 0)
            throw new InvalidDataException("Empty Catalog external proof");
        return buffer.ToArray();
    }

    public static async Task<BatchReleaseDownloader.BatchResult> StageLatestVerifiedAsync(
        string pgSelection, string outputParent, CancellationToken token = default,
        HttpMessageHandler? handler = null)
    {
        using var owned = handler is null ? new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None
        } : null;
        using var http = new HttpClient(handler ?? owned!, disposeHandler: false)
        { Timeout = TimeSpan.FromMinutes(3) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("pgextwin-external-signed-catalog/1");
        var runId = LatestRunId(await ReadAsync(http, DirectoryApi, token));
        var prefix = RawRoot + "run-" + runId + "/";
        var admission = await ReadAsync(http, prefix + "external-get-admission.json", token);
        var bundle = await ReadAsync(http, prefix + "attestation.json", token);
        return await ExternalSignedDirectGetAdmission.StageVerifiedBytesAsync(
            admission, bundle, pgSelection, outputParent, token, runId);
    }
}
