using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;
using PgExtWin.Core;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("PgExtWin.Contract.Tests")]

namespace PgExtWin.Releases;

// NONAUTHORIZING transport primitive. Only a future independently signed
// source-specific admission path may invoke it. No CLI command calls this type.
// Never construct these pins from local discovery/review JSON.
internal sealed record ExternalOriginalPin(
    string Extension, string PgMajor, string SourceRepo, long RepositoryId,
    string Tag, long ReleaseId, string AssetName, long AssetId,
    long OriginalBytes, string OriginalSha256, string OriginalProviderUrl);

internal sealed class ExternalProviderAssetTransport : IDisposable
{
    private readonly HttpClient http;
    private static readonly Regex Repo = new(
        @"\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\z", RegexOptions.CultureInvariant);
    private static readonly Regex Extension = new(
        @"\A[a-z][a-z0-9_]*\z", RegexOptions.CultureInvariant);
    private static readonly Regex Hash = new(
        @"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant);

    internal ExternalProviderAssetTransport(HttpMessageHandler? handler = null)
    {
        http = new HttpClient(handler ?? new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None
        }, disposeHandler: true) { Timeout = TimeSpan.FromMinutes(5) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("pgextwin-external-original-nonpublishing/1");
    }

    // Reused by the all-or-nothing external batch preflight. This is pin
    // shape validation only, NEVER independent signed admission.
    internal static void ValidatePin(ExternalOriginalPin pin)
    {
        if (!Extension.IsMatch(pin.Extension) ||
            !Regex.IsMatch(pin.PgMajor, @"\A1[4-8]\z") ||
            !Repo.IsMatch(pin.SourceRepo) ||
            pin.SourceRepo.StartsWith("pgextwin/", StringComparison.OrdinalIgnoreCase) ||
            !PinnedReleaseSelector.SafeAssetName(pin.Tag) ||
            !PinnedReleaseSelector.SafeAssetName(pin.AssetName) ||
            !pin.AssetName.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) ||
            !Hash.IsMatch(pin.OriginalSha256) ||
            pin.RepositoryId <= 0 || pin.ReleaseId <= 0 || pin.AssetId <= 0 ||
            pin.OriginalBytes is < 4 or > ExternalOriginalZipIntegrity.MaxOriginalBytes ||
            pin.OriginalProviderUrl != "https://github.com/" + pin.SourceRepo +
                "/releases/download/" + pin.Tag + "/" + pin.AssetName)
            throw new InvalidDataException("Invalid or unpinned external original asset");
    }

    internal async Task<DownloadReceipt> DownloadAsync(
        ExternalOriginalPin pin, string outputDirectory, CancellationToken token = default)
    {
        ValidatePin(pin);

        var folder = Path.GetFullPath(outputDirectory);
        if (!Directory.Exists(folder))
            throw new DirectoryNotFoundException("External output folder must already exist");
        for (DirectoryInfo? d = new(folder); d is not null; d = d.Parent)
            if ((d.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("External output folder contains a link");
        var final = Path.Combine(folder, pin.AssetName);
        RequireAbsent(folder, pin.AssetName);

        var baseUrl = "https://api.github.com/repos/" + pin.SourceRepo;
        using (var repo = await JsonAsync(baseUrl, token))
        {
            var root = repo.RootElement;
            if (root.GetProperty("full_name").GetString() != pin.SourceRepo ||
                root.GetProperty("id").GetInt64() != pin.RepositoryId)
                throw new InvalidDataException("External repository identity mismatch");
        }
        using (var release = await JsonAsync(baseUrl + "/releases/tags/" + pin.Tag, token))
        {
            var root = release.RootElement;
            if (root.GetProperty("id").GetInt64() != pin.ReleaseId ||
                root.GetProperty("tag_name").GetString() != pin.Tag ||
                root.GetProperty("draft").ValueKind != JsonValueKind.False ||
                root.GetProperty("published_at").ValueKind != JsonValueKind.String)
                throw new InvalidDataException("External Release identity/state mismatch");

            var items = root.GetProperty("assets");
            if (items.ValueKind != JsonValueKind.Array ||
                items.GetArrayLength() is < 1 or > 200)
                throw new InvalidDataException("Invalid external Release asset inventory");
            var ids = new HashSet<long>();
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            bool matched = false;
            foreach (var item in items.EnumerateArray())
            {
                var id = item.GetProperty("id").GetInt64();
                var name = item.GetProperty("name").GetString() ?? "";
                if (id <= 0 || !PinnedReleaseSelector.SafeAssetName(name) ||
                    !ids.Add(id) || !names.Add(name))
                    throw new InvalidDataException("Duplicate/unsafe external Release asset");
                if (id == pin.AssetId || name == pin.AssetName)
                {
                    // GitHub's older Release assets often expose digest: null.
                    // Never invent a provider digest or treat absence as a
                    // successful hash: the *separately signed* admission pins
                    // SHA256 and we verify the full actual ZIP bytes below.
                    // A present, conflicting API digest always DENIES.
                    var digest = item.GetProperty("digest");
                    var digestMatches = digest.ValueKind switch
                    {
                        JsonValueKind.Null => true, // Independent signed byte pin required.
                        JsonValueKind.String =>
                            digest.GetString() == "sha256:" + pin.OriginalSha256,
                        _ => false
                    };
                    if (id != pin.AssetId || name != pin.AssetName ||
                        item.GetProperty("size").GetInt64() != pin.OriginalBytes ||
                        !digestMatches ||
                        item.GetProperty("state").GetString() != "uploaded" ||
                        item.GetProperty("browser_download_url").GetString() != pin.OriginalProviderUrl)
                        throw new InvalidDataException("External Release asset pin mismatch");
                    matched = true;
                }
            }
            if (!matched)
                throw new InvalidDataException("External Release asset ID absent");
        }

        // Only the immutable numeric provider asset endpoint; never follow
        // arbitrary redirect hosts or substitute a different asset on failure.
        var url = new Uri(baseUrl + "/releases/assets/" + pin.AssetId);
        using var response = await OriginalAsync(url, token);
        if (response.Content.Headers.ContentLength is long size && size != pin.OriginalBytes)
            throw new InvalidDataException("External original HTTP length mismatch");
        if (response.Content.Headers.ContentType?.MediaType is
            "application/json" or "text/html" or "text/plain")
            throw new InvalidDataException("External provider returned metadata instead of ZIP");
        await using var stream = await response.Content.ReadAsStreamAsync(token);
        using var buffer = new MemoryStream();
        var block = new byte[81920];
        while (true)
        {
            int n = await stream.ReadAsync(block, token);
            if (n == 0) break;
            if (buffer.Length + n > pin.OriginalBytes)
                throw new InvalidDataException("External original exceeds pinned byte size");
            await buffer.WriteAsync(block.AsMemory(0, n), token);
        }
        // Reuse the strict original ZIP digest, size, traversal, links,
        // decompression bounds and CRC verification already used offline.
        var bytes = buffer.ToArray();
        ExternalOriginalZipIntegrity.Verify(bytes, pin.OriginalBytes, pin.OriginalSha256);
        RequireAbsent(folder, pin.AssetName);
        var temporary = Path.Combine(folder, "." + pin.AssetName + "." +
            Guid.NewGuid().ToString("N") + ".part");
        try
        {
            await using (var file = new FileStream(temporary, FileMode.CreateNew,
                FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous))
                await file.WriteAsync(bytes, token);
            RequireAbsent(folder, pin.AssetName);
            File.Move(temporary, final, overwrite: false);
            return new DownloadReceipt(final, pin.OriginalSha256, bytes.LongLength,
                pin.RepositoryId, pin.ReleaseId, pin.AssetId);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private async Task<JsonDocument> JsonAsync(string url, CancellationToken token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        using var response = await http.SendAsync(request,
            HttpCompletionOption.ResponseHeadersRead, token);
        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException("External metadata HTTP " + (int)response.StatusCode);
        if (response.Content.Headers.ContentLength is long declared && declared > 2_000_000)
            throw new InvalidDataException("External metadata oversized");
        await using var input = await response.Content.ReadAsStreamAsync(token);
        using var buffer = new MemoryStream();
        var block = new byte[16384];
        while (true)
        {
            int n = await input.ReadAsync(block, token);
            if (n == 0) break;
            if (buffer.Length + n > 2_000_000)
                throw new InvalidDataException("External metadata exceeds bound");
            await buffer.WriteAsync(block.AsMemory(0, n), token);
        }
        return StrictJson.Parse(buffer.ToArray());
    }

    private async Task<HttpResponseMessage> OriginalAsync(Uri initial, CancellationToken token)
    {
        var url = initial;
        var visited = new HashSet<string>(StringComparer.Ordinal);
        for (int hop = 0; hop < 5; hop++)
        {
            if (url.Scheme != Uri.UriSchemeHttps || !url.IsDefaultPort ||
                url.UserInfo.Length != 0 || url.Fragment.Length != 0 ||
                (hop == 0 ? url != initial :
                    url.Host is not ("release-assets.githubusercontent.com" or
                        "objects.githubusercontent.com" or "github-releases.githubusercontent.com")) ||
                !visited.Add(url.AbsoluteUri))
                throw new InvalidDataException("Untrusted external original redirect");
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));
            var response = await http.SendAsync(request,
                HttpCompletionOption.ResponseHeadersRead, token);
            if (response.StatusCode is HttpStatusCode.MovedPermanently or
                HttpStatusCode.Redirect or HttpStatusCode.RedirectMethod or
                HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect)
            {
                var next = response.Headers.Location;
                response.Dispose();
                if (next is null || !next.IsAbsoluteUri)
                    throw new InvalidDataException("Relative external redirect rejected");
                url = next;
                continue;
            }
            if (response.StatusCode != HttpStatusCode.OK)
            {
                int status = (int)response.StatusCode;
                response.Dispose();
                throw new HttpRequestException("External original HTTP " + status);
            }
            return response;
        }
        throw new InvalidDataException("External original redirect limit reached");
    }

    private static void RequireAbsent(string parent, string name)
    {
        if (Directory.EnumerateFileSystemEntries(parent).Any(x =>
                string.Equals(Path.GetFileName(x), name, StringComparison.OrdinalIgnoreCase)))
            throw new IOException("External original destination exists; no overwrite");
    }

    public void Dispose() => http.Dispose();
}
