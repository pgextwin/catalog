using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using PgExtWin.Core;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("PgExtWin.Contract.Tests")]

namespace PgExtWin.Releases;

// Original provider byte pins selected by the external Catalog fetch path.
// Historical signed-admission callers reuse the same transport and staging.
internal sealed record ExternalOriginalPin(
    string Extension, string PgMajor, string SourceRepo, long RepositoryId,
    string Tag, long ReleaseId, string AssetName, long AssetId,
    long OriginalBytes, string OriginalSha256, string OriginalProviderUrl,
    string? Provider = null);

internal sealed class ExternalProviderAssetTransport : IDisposable
{
    internal const string StandaloneProvider = "standalone";
    internal const string OsgeoProvider = "osgeo";

    internal static bool IsExternalZipMajor(string? major) =>
        major is "14" or "15" or "16" or "17" or "18" or "19";

    // Direct HTTPS provider assets use no synthetic GitHub identities.
    internal static bool IsCybertec(ExternalOriginalPin pin) =>
        pin.SourceRepo == "cybertec-postgresql/" + pin.Extension &&
        pin.RepositoryId == 0 && pin.ReleaseId == 0 && pin.AssetId == 0 &&
        pin.PgMajor is "15" or "16" or "17" or "18" &&
        pin.OriginalProviderUrl == "https://repository.cybertec.at/windows/public/" +
            pin.PgMajor + "/extension/" + pin.AssetName;

    internal static bool IsDirectHttps(ExternalOriginalPin pin) =>
        pin.Provider is OsgeoProvider or StandaloneProvider || IsCybertec(pin);

    private static bool IsOsgeoBundle(ExternalOriginalPin pin) =>
        pin.Extension == "postgis" && pin.SourceRepo == "postgis/postgis" &&
        pin.PgMajor != "14" && // ValidatePin checks the shared range; OSGeo starts at PG15.
        pin.RepositoryId == 0 && pin.ReleaseId == 0 && pin.AssetId == 0 &&
        OsgeoVersion.IsMatch(pin.Tag) &&
        pin.AssetName == $"postgis-bundle-pg{pin.PgMajor}-{pin.Tag}x64.zip" &&
        pin.OriginalProviderUrl ==
            $"https://download-cache.osgeo.org/postgis/windows/pg{pin.PgMajor}/{pin.AssetName}";

    private readonly HttpClient http;
    // One transport per atomic CLI batch. Cache GitHub metadata in memory;
    // verify the Catalog byte pin against every downloaded original.
    private readonly Dictionary<string, JsonElement> metadataSnapshots = new(StringComparer.Ordinal);
    private static readonly Regex Repo = new(
        @"\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\z", RegexOptions.CultureInvariant);
    private static readonly Regex Extension = new(
        @"\A[a-z][a-z0-9_]*\z", RegexOptions.CultureInvariant);
    private static readonly Regex Hash = new(
        @"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant);
    private static readonly Regex OsgeoVersion = new(
        @"\A[0-9]+\.[0-9]+\.[0-9]+\z", RegexOptions.CultureInvariant);

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

    // Shared pin shape validation for the all-or-nothing external batch.
    internal static void ValidatePin(ExternalOriginalPin pin)
    {
        if (pin.Provider == StandaloneProvider)
        {
            if (!Extension.IsMatch(pin.Extension) || !PinnedReleaseSelector.SafeAssetName(pin.Extension) ||
                (pin.PgMajor != "any" && !Regex.IsMatch(pin.PgMajor, @"\A[1-9][0-9]*\z")) ||
                !PinnedReleaseSelector.SafeAssetName(pin.AssetName) ||
                !Hash.IsMatch(pin.OriginalSha256) || pin.OriginalBytes <= 0 ||
                !Uri.TryCreate(pin.OriginalProviderUrl, UriKind.Absolute, out var url) ||
                url.Scheme != Uri.UriSchemeHttps || !url.IsDefaultPort ||
                url.UserInfo.Length != 0 || url.Fragment.Length != 0)
                throw new InvalidDataException("Invalid standalone original asset pin");
            return;
        }

        var validProvider = pin.Provider switch
        {
            OsgeoProvider => IsOsgeoBundle(pin),
            null => IsCybertec(pin) ||
                (pin.RepositoryId > 0 && pin.ReleaseId > 0 && pin.AssetId > 0 &&
                 pin.OriginalProviderUrl == "https://github.com/" + pin.SourceRepo +
                    "/releases/download/" + pin.Tag + "/" + pin.AssetName),
            _ => false
        };
        if (!Extension.IsMatch(pin.Extension) ||
            !IsExternalZipMajor(pin.PgMajor) ||
            !Repo.IsMatch(pin.SourceRepo) ||
            pin.SourceRepo.StartsWith("pgextwin/", StringComparison.OrdinalIgnoreCase) ||
            !PinnedReleaseSelector.SafeAssetName(pin.Tag) ||
            !PinnedReleaseSelector.SafeAssetName(pin.AssetName) ||
            !pin.AssetName.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) ||
            !Hash.IsMatch(pin.OriginalSha256) ||
            pin.OriginalBytes < 4 ||
            pin.OriginalBytes > ExternalOriginalZipIntegrity.ProfileFor(pin).MaxCompressedOriginalBytes ||
            !validProvider)
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

        var directHttps = IsDirectHttps(pin);
        if (!directHttps)
        {
            var baseUrl = "https://api.github.com/repos/" + pin.SourceRepo;
            {
                var root = await CachedMetadataAsync(baseUrl, token);
                if (root.GetProperty("full_name").GetString() != pin.SourceRepo ||
                    root.GetProperty("id").GetInt64() != pin.RepositoryId)
                    throw new InvalidDataException("External repository identity mismatch");
            }
            {
                var root = await CachedMetadataAsync(baseUrl + "/releases/tags/" + pin.Tag, token);
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
                        // successful hash: the Catalog record (or historical admission) pins
                        // SHA256 and we verify the full actual ZIP bytes below.
                        // A present, conflicting API digest always DENIES.
                        var digest = item.GetProperty("digest");
                        var digestMatches = digest.ValueKind switch
                        {
                            JsonValueKind.Null => true, // Full byte pin verified below.
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

        }

        // Direct provider originals retain the Catalog SHA256/ZIP checks.
        // OSGeo and Cybertec use their exact HTTPS URLs without redirects.
        var url = new Uri(pin.OriginalProviderUrl);
        using var response = !directHttps || pin.Provider == StandaloneProvider && url.Host == "github.com"
            ? await OriginalAsync(url, token)
            : await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, token);
        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException("External original HTTP " + (int)response.StatusCode);
        if (response.Content.Headers.ContentLength is long size && size != pin.OriginalBytes)
            throw new InvalidDataException("External original HTTP length mismatch");
        if (pin.Provider == StandaloneProvider)
            return await SaveStandaloneAsync(response.Content, pin, folder, final, token);
        if (response.Content.Headers.ContentType?.MediaType is
            "application/json" or "text/html" or "text/plain")
            throw new InvalidDataException("External provider returned metadata instead of ZIP");
        await using var stream = await response.Content.ReadAsStreamAsync(token);
        var bytes = new byte[(int)pin.OriginalBytes];
        try { await stream.ReadExactlyAsync(bytes, token); }
        catch (EndOfStreamException e)
        { throw new InvalidDataException("External original shorter than pinned byte size", e); }
        if (await stream.ReadAsync(new byte[1], token) != 0)
            throw new InvalidDataException("External original exceeds pinned byte size");
        // Reuse the strict original ZIP digest, size, traversal, links,
        // decompression bounds and CRC verification already used offline.
        ExternalOriginalZipIntegrity.Verify(bytes, pin);
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

    private static async Task<DownloadReceipt> SaveStandaloneAsync(
        HttpContent content, ExternalOriginalPin pin, string folder, string final, CancellationToken token)
    {
        var temporary = final + "." + Guid.NewGuid().ToString("N") + ".part";
        try
        {
            await using var input = await content.ReadAsStreamAsync(token);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[81920];
            long bytes = 0;
            await using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, buffer.Length, FileOptions.Asynchronous))
            {
                int read;
                while ((read = await input.ReadAsync(buffer, token)) != 0)
                {
                    if (read > pin.OriginalBytes - bytes)
                        throw new InvalidDataException("External original exceeds pinned byte size");
                    bytes += read;
                    hash.AppendData(buffer.AsSpan(0, read));
                    await output.WriteAsync(buffer.AsMemory(0, read), token);
                }
            }
            if (bytes != pin.OriginalBytes ||
                Convert.ToHexStringLower(hash.GetHashAndReset()) != pin.OriginalSha256)
                throw new InvalidDataException("External original differs from pinned SHA256 or size");

            RequireAbsent(folder, pin.AssetName);
            File.Move(temporary, final, overwrite: false);
            return new DownloadReceipt(final, pin.OriginalSha256, bytes,
                pin.RepositoryId, pin.ReleaseId, pin.AssetId);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private async Task<JsonElement> CachedMetadataAsync(string url, CancellationToken token)
    {
        if (metadataSnapshots.TryGetValue(url, out var snapshot))
            return snapshot;
        // JsonElement.Clone owns its backing data after JsonDocument disposal.
        using var document = await JsonAsync(url, token);
        snapshot = document.RootElement.Clone();
        metadataSnapshots.Add(url, snapshot);
        return snapshot;
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
        // The initial URL is derived only from ValidatePin's canonical
        // https://github.com/REPO/releases/download/TAG/ASSET identity.
        // Never accept another host as an original-provider starting point.
        if (initial.Host != "github.com" || initial.Scheme != Uri.UriSchemeHttps ||
            !initial.IsDefaultPort || initial.UserInfo.Length != 0 ||
            initial.Fragment.Length != 0)
            throw new InvalidDataException("Untrusted signed provider URL");
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
