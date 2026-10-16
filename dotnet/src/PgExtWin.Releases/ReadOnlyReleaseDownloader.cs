using System.Buffers;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace PgExtWin.Releases;

/// <summary>SHA-256 byte match only: never signature-verified, never publishing authorization.</summary>
public sealed record DownloadReceipt(string FilePath, string Sha256, long Size,
    long RepositoryId, long ReleaseId, long AssetId, string VerificationLevel = "INTEGRITY_ONLY");

/// <summary>
/// Explicit GET-only API/asset transport. All network interaction is initiated by the operator,
/// bounded and simulated in PR CI. Accepts externally pinned P1 identifiers but does NOT
/// independently authenticate that policy or perform Sigstore verification.
/// </summary>
public sealed class ReadOnlyReleaseDownloader : IDisposable
{
    public const long MaxAssetBytes = 64 * 1024 * 1024;
    private const long MaxJsonBytes = 2 * 1024 * 1024;
    private readonly HttpClient http;
    private static readonly Regex Digest = new(@"\Asha256:[0-9a-f]{64}\z", RegexOptions.CultureInvariant);
    private static readonly Regex Commit = new(@"\A[0-9a-f]{40}\z", RegexOptions.CultureInvariant);

    // The supplied handler must not auto-follow redirects. The default CLI handler sets
    // AllowAutoRedirect=false, UseCookies=false and AutomaticDecompression=None.
    public ReadOnlyReleaseDownloader(HttpMessageHandler handler)
    {
        http = new HttpClient(handler, disposeHandler: true) { Timeout = TimeSpan.FromMinutes(5) };
    }

    public async Task<DownloadReceipt> DownloadAsync(ReleasePins pin, string outputDirectory,
        CancellationToken cancellationToken = default)
    {
        if (!PinnedReleaseSelector.SafeAssetName(pin.Extension) ||
            !PinnedReleaseSelector.SafeAssetName(pin.AssetName) ||
            !PinnedReleaseSelector.SafeAssetName(pin.Tag) ||
            pin.RepositoryId <= 0 || pin.ReleaseId <= 0 ||
            pin.AssetIds.Count == 0 || !pin.AssetIds.TryGetValue(pin.AssetName, out var assetId) ||
            assetId <= 0 || !Regex.IsMatch(pin.AssetSha256, @"\A[0-9a-f]{64}\z"))
            throw new InvalidDataException("Invalid/unpinned Release asset request");

        var path = CheckedOutputDirectory(outputDirectory);
        var final = Path.Combine(path, pin.AssetName);
        if (File.Exists(final) || Directory.Exists(final) ||
            Directory.EnumerateFileSystemEntries(path).Any(f =>
                string.Equals(Path.GetFileName(f), pin.AssetName, StringComparison.OrdinalIgnoreCase)))
            throw new IOException("Output asset already exists: refusing overwrite/case collision");

        // Repository numeric ID must match before accepting even the Release metadata.
        var apiBase = "https://api.github.com/repos/pgextwin/" + pin.Extension;
        using (var repository = await ApiJsonAsync(apiBase, cancellationToken))
        {
            var doc = repository.RootElement;
            if (RequiredString(doc, "full_name") != "pgextwin/" + pin.Extension ||
                RequiredPositiveId(doc, "id") != pin.RepositoryId)
                throw new InvalidDataException("Repository numeric ID/name substitution");
        }

        long expectedSize = 0;
        using (var release = await ApiJsonAsync(apiBase + "/releases/tags/" + pin.Tag, cancellationToken))
        {
            var data = release.RootElement;
            if (RequiredPositiveId(data, "id") != pin.ReleaseId ||
                data.GetProperty("draft").ValueKind != JsonValueKind.False ||
                data.GetProperty("prerelease").ValueKind != JsonValueKind.False ||
                RequiredString(data, "tag_name") != pin.Tag ||
                !Commit.IsMatch(RequiredString(data, "target_commitish")))
                throw new InvalidDataException("Unexpected formal Release identity/state");
            var members = data.GetProperty("assets");
            if (members.ValueKind != JsonValueKind.Array ||
                members.GetArrayLength() != pin.AssetIds.Count)
                throw new InvalidDataException("Release asset inventory differs from P1 pin");
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var ids = new HashSet<long>();
            foreach (var member in members.EnumerateArray())
            {
                var name = RequiredString(member, "name");
                var id = RequiredPositiveId(member, "id");
                var declaredDigest = RequiredString(member, "digest");
                var size = member.GetProperty("size").GetInt64();
                if (!PinnedReleaseSelector.SafeAssetName(name) || !seen.Add(name) || !ids.Add(id) ||
                    !pin.AssetIds.TryGetValue(name, out var pinnedId) || pinnedId != id ||
                    !Digest.IsMatch(declaredDigest) ||
                    size <= 0 || size > MaxAssetBytes ||
                    RequiredString(member, "state") != "uploaded")
                    throw new InvalidDataException("Asset ID/size/digest/duplicate substitution");
                var expectedBrowserUrl = "https://github.com/pgextwin/" + pin.Extension +
                    "/releases/download/" + pin.Tag + "/" + name;
                if (RequiredString(member, "browser_download_url") != expectedBrowserUrl)
                    throw new InvalidDataException("Unexpected Release asset URL");
                if (name == pin.AssetName)
                {
                    if (declaredDigest != "sha256:" + pin.AssetSha256)
                        throw new InvalidDataException("Catalog/Release SHA256 mismatch");
                    expectedSize = size;
                }
            }
            if (expectedSize == 0 || !seen.Contains("SHA256SUMS.txt"))
                throw new InvalidDataException("Missing original ZIP/checksums");
        }

        // API asset ID address, not untrusted metadata URL. No automatic cross-origin redirect.
        var initial = new Uri(apiBase + "/releases/assets/" + assetId);
        var temporary = Path.Combine(path, "." + pin.AssetName + "." + Guid.NewGuid().ToString("N") + ".part");
        try
        {
            using var response = await GetAssetAsync(initial, cancellationToken);
            if (response.Content.Headers.ContentLength is long length && length != expectedSize)
                throw new InvalidDataException("Asset HTTP Content-Length differs from Release");
            var media = response.Content.Headers.ContentType?.MediaType;
            if (media is "application/json" or "text/html" or "text/plain")
                throw new InvalidDataException("Asset API returned metadata or HTML, not ZIP bytes");

            await using var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 81920, FileOptions.Asynchronous | FileOptions.SequentialScan);
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = ArrayPool<byte>.Shared.Rent(81920);
            long count = 0;
            try
            {
                while (true)
                {
                    var amount = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);
                    if (amount == 0) break;
                    if (count + amount > expectedSize || count + amount > MaxAssetBytes)
                        throw new InvalidDataException("Asset exceeds pinned size / download cap");
                    hash.AppendData(buffer, 0, amount);
                    await file.WriteAsync(buffer.AsMemory(0, amount), cancellationToken);
                    count += amount;
                }
            }
            finally { ArrayPool<byte>.Shared.Return(buffer); }
            await file.FlushAsync(cancellationToken);
            if (count != expectedSize ||
                Convert.ToHexStringLower(hash.GetHashAndReset()) != pin.AssetSha256)
                throw new InvalidDataException("Actual original ZIP bytes do not match pinned SHA256");

            // ZIP begins with a local-file header. Never extract, install or execute bytes here.
            // Close staged file before reopening for magic inspection.
            file.Dispose();
            using (var verifyZip = new FileStream(temporary, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                Span<byte> magic = stackalloc byte[4];
                if (verifyZip.Read(magic) != 4 || magic[0] != 0x50 || magic[1] != 0x4b ||
                    magic[2] != 0x03 || magic[3] != 0x04)
                    throw new InvalidDataException("Downloaded data is not a regular ZIP file");
            }

            // Re-check before atomic publication into the user-selected staging directory.
            CheckedOutputDirectory(path);
            File.Move(temporary, final, overwrite: false);
            return new DownloadReceipt(final, pin.AssetSha256, count, pin.RepositoryId,
                pin.ReleaseId, assetId);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private async Task<JsonDocument> ApiJsonAsync(string url, CancellationToken token)
    {
        using var response = await GetNoRedirectAsync(new Uri(url), binary: false, token);
        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException("Release metadata HTTP status " + (int)response.StatusCode);
        await using var input = await response.Content.ReadAsStreamAsync(token);
        using var output = new MemoryStream();
        var bytes = new byte[16384];
        while (true)
        {
            var n = await input.ReadAsync(bytes, token);
            if (n == 0) break;
            if (output.Length + n > MaxJsonBytes)
                throw new InvalidDataException("Oversized GitHub metadata response");
            output.Write(bytes, 0, n);
        }
        // Duplicate-key checks must match existing strict JSON parser.
        return PgExtWin.Core.StrictJson.Parse(output.ToArray());
    }

    private async Task<HttpResponseMessage> GetAssetAsync(Uri initial, CancellationToken token)
    {
        var uri = initial;
        var visited = new HashSet<string>(StringComparer.Ordinal);
        for (var hop = 0; hop < 4; hop++)
        {
            ValidateTransportUri(uri);
            if (!visited.Add(uri.AbsoluteUri))
                throw new InvalidDataException("Redirect cycle");
            var response = await GetNoRedirectAsync(uri, binary: true, token);
            if (response.StatusCode is HttpStatusCode.MovedPermanently or HttpStatusCode.Redirect
                or HttpStatusCode.RedirectMethod or HttpStatusCode.TemporaryRedirect
                or HttpStatusCode.PermanentRedirect)
            {
                var next = response.Headers.Location;
                response.Dispose();
                if (next is null || !next.IsAbsoluteUri)
                    throw new InvalidDataException("Invalid asset redirect");
                uri = next;
                continue;
            }
            if (response.StatusCode != HttpStatusCode.OK)
            {
                var status = (int)response.StatusCode;
                response.Dispose();
                throw new HttpRequestException("Release asset HTTP status " + status);
            }
            return response;
        }
        throw new InvalidDataException("Too many asset redirects");
    }

    private async Task<HttpResponseMessage> GetNoRedirectAsync(Uri uri, bool binary, CancellationToken token)
    {
        ValidateTransportUri(uri);
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.UserAgent.ParseAdd("pgextwin-cli-readonly/0.2");
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(binary
            ? "application/octet-stream" : "application/vnd.github+json"));
        return await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token);
    }

    private static void ValidateTransportUri(Uri uri)
    {
        if (!uri.IsAbsoluteUri || uri.Scheme != Uri.UriSchemeHttps || !uri.IsDefaultPort ||
            uri.UserInfo.Length > 0 || uri.Fragment.Length > 0 ||
            !new[] { "api.github.com", "github.com", "release-assets.githubusercontent.com" }
                .Contains(uri.Host, StringComparer.Ordinal))
            throw new InvalidDataException("Off-domain/insecure Release redirect denied");
    }

    private static string CheckedOutputDirectory(string value)
    {
        var full = Path.GetFullPath(value);
        if (!Directory.Exists(full)) throw new DirectoryNotFoundException("Output directory must already exist");
        for (DirectoryInfo? current = new(full); current is not null; current = current.Parent)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Output destination contains a directory link/reparse point");
        }
        return full;
    }

    private static string RequiredString(JsonElement obj, string key)
    {
        var p = obj.GetProperty(key);
        if (p.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(p.GetString()))
            throw new InvalidDataException("Missing/invalid GitHub field: " + key);
        return p.GetString()!;
    }

    private static long RequiredPositiveId(JsonElement obj, string key)
    {
        var p = obj.GetProperty(key);
        if (p.ValueKind != JsonValueKind.Number || !p.TryGetInt64(out var value) || value <= 0)
            throw new InvalidDataException("Missing/invalid GitHub numeric identity: " + key);
        return value;
    }

    public void Dispose() => http.Dispose();
}
