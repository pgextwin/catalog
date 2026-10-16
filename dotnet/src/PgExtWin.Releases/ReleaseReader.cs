using System.Buffers;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using PgExtWin.Core;

namespace PgExtWin.Releases;

/// <summary>
/// Caller must authenticate ALL pin fields out of band, through P1 policy.
/// A pin or a hash originating solely from the Release API is not trusted.
/// </summary>
public sealed record ReleasePin(
    string Extension, string Tag, string PackagingSha,
    long RepositoryId, long ReleaseId, long AssetId,
    string AssetName, string Sha256, long ExpectedSize);

public sealed record DownloadReceipt(
    string Path, string Sha256, long Size,
    string VerificationLevel = "INTEGRITY_ONLY",
    bool SignatureVerified = false,
    bool PublicationAuthorized = false);

/// <summary>GET-only public release reader. No signing, attestation trust or publishing.</summary>
public sealed class ReleaseReader : IDisposable
{
    private const long MaxAssetSize = 64L * 1024 * 1024;
    private const long MaxJsonBytes = 2L * 1024 * 1024;
    private static readonly Regex Component = new(
        @"\A[A-Za-z0-9][A-Za-z0-9._-]*\z", RegexOptions.CultureInvariant);
    private static readonly Regex Extension = new(
        @"\A[a-z][a-z0-9_]*\z", RegexOptions.CultureInvariant);
    private static readonly Regex Hex40 = new(
        @"\A[a-f0-9]{40}\z", RegexOptions.CultureInvariant);
    private static readonly Regex Hex64 = new(
        @"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant);
    private readonly HttpClient _client;

    public ReleaseReader() : this(new HttpClientHandler {
        AllowAutoRedirect = false, AutomaticDecompression = DecompressionMethods.None,
        UseCookies = false, UseProxy = true
    }) { }

    // Only synthetic tests should inject a custom handler: no default redirect behavior.
    public ReleaseReader(HttpMessageHandler handler)
    {
        _client = new HttpClient(handler, disposeHandler: true) { Timeout = TimeSpan.FromSeconds(60) };
        _client.DefaultRequestHeaders.UserAgent.ParseAdd("pgextwin-cli-pr2-readonly/0");
        _client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
    }

    public void Dispose() => _client.Dispose();

    public async Task<DownloadReceipt> DownloadAsync(
        ReleasePin pin, string outputDirectory, CancellationToken cancellationToken = default)
    {
        ValidatePin(pin);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);
        var expectedUrl = $"https://github.com/pgextwin/{pin.Extension}/releases/download/{pin.Tag}/{pin.AssetName}";
        var repoUrl = $"https://api.github.com/repos/pgextwin/{pin.Extension}";
        var releaseUrl = repoUrl + $"/releases/tags/{pin.Tag}";

        using (var repo = await ReadJsonAsync(new Uri(repoUrl), cancellationToken))
        {
            var root = repo.RootElement;
            Require(root.GetProperty("id").GetInt64() == pin.RepositoryId &&
                root.GetProperty("full_name").GetString() == $"pgextwin/{pin.Extension}",
                "Repository identity mismatch");
        }
        long metadataSize;
        using (var release = await ReadJsonAsync(new Uri(releaseUrl), cancellationToken))
        {
            var r = release.RootElement;
            Require(r.GetProperty("id").GetInt64() == pin.ReleaseId &&
                r.GetProperty("tag_name").GetString() == pin.Tag &&
                r.GetProperty("target_commitish").GetString() == pin.PackagingSha &&
                r.GetProperty("draft").ValueKind == JsonValueKind.False &&
                r.GetProperty("prerelease").ValueKind == JsonValueKind.False,
                "Formal Release identity/status mismatch");
            var assets = r.GetProperty("assets");
            Require(assets.ValueKind == JsonValueKind.Array, "Missing formal Release assets");
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var matched = false;
            metadataSize = -1;
            foreach (var asset in assets.EnumerateArray())
            {
                var name = asset.GetProperty("name").GetString();
                Require(name is not null && names.Add(name), "Duplicate/case-colliding asset");
                if (!string.Equals(name, pin.AssetName, StringComparison.Ordinal)) continue;
                Require(!matched, "Duplicate asset");
                matched = true;
                Require(asset.GetProperty("id").GetInt64() == pin.AssetId &&
                    asset.GetProperty("state").GetString() == "uploaded" &&
                    asset.GetProperty("digest").GetString() == "sha256:" + pin.Sha256 &&
                    asset.GetProperty("browser_download_url").GetString() == expectedUrl,
                    "Pinned original asset mismatch");
                metadataSize = asset.GetProperty("size").GetInt64();
            }
            Require(matched && metadataSize == pin.ExpectedSize, "Pinned asset absent/size changed");
        }

        var output = Path.GetFullPath(outputDirectory);
        Directory.CreateDirectory(output);
        CheckDirectoryChain(output);
        var destination = Path.Combine(output, pin.AssetName);
        Require(!File.Exists(destination) && !Directory.Exists(destination),
            "Refuse to overwrite existing target");

        var staging = Path.Combine(output, ".pgextwin-pr2-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using var response = await DownloadResponseAsync(new Uri(expectedUrl), cancellationToken);
            Require(response.Content.Headers.ContentEncoding.Count == 0,
                "Encoded asset payload forbidden");
            if (response.Content.Headers.ContentLength is long declared)
                Require(declared == pin.ExpectedSize, "HTTP Content-Length mismatch");

            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long count = 0;
            await using (var target = new FileStream(staging, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 65536, FileOptions.Asynchronous))
            await using (var body = await response.Content.ReadAsStreamAsync(cancellationToken))
            {
                var buffer = ArrayPool<byte>.Shared.Rent(65536);
                try
                {
                    while (true)
                    {
                        var n = await body.ReadAsync(buffer.AsMemory(0, 65536), cancellationToken);
                        if (n == 0) break;
                        count += n;
                        Require(count <= pin.ExpectedSize && count <= MaxAssetSize, "Oversized asset stream");
                        hasher.AppendData(buffer, 0, n);
                        await target.WriteAsync(buffer.AsMemory(0, n), cancellationToken);
                    }
                    await target.FlushAsync(cancellationToken);
                }
                finally { ArrayPool<byte>.Shared.Return(buffer); }
            }
            var digest = Convert.ToHexStringLower(hasher.GetHashAndReset());
            Require(count == pin.ExpectedSize && digest == pin.Sha256,
                "Truncated/tampered original ZIP bytes");
            CheckDirectoryChain(output);
            Require(!File.Exists(destination) && !Directory.Exists(destination),
                "Target appeared during download");
            File.Move(staging, destination, overwrite: false);
            return new DownloadReceipt(destination, digest, count);
        }
        finally
        {
            if (File.Exists(staging)) File.Delete(staging);
        }
    }

    private async Task<JsonDocument> ReadJsonAsync(Uri uri, CancellationToken ct)
    {
        using var response = await SendGetAsync(uri, ct);
        Require(response.IsSuccessStatusCode && !IsRedirect(response.StatusCode),
            "GitHub API GET failed or redirected");
        if (response.Content.Headers.ContentLength is long len)
            Require(len <= MaxJsonBytes, "Oversized JSON metadata");
        await using var input = await response.Content.ReadAsStreamAsync(ct);
        using var output = new MemoryStream();
        var buffer = new byte[16384];
        while (true)
        {
            var n = await input.ReadAsync(buffer.AsMemory(), ct);
            if (n == 0) break;
            Require(output.Length + n <= MaxJsonBytes, "Oversized metadata stream");
            output.Write(buffer, 0, n);
        }
        return StrictJson.Parse(output.ToArray());
    }

    private async Task<HttpResponseMessage> DownloadResponseAsync(Uri original, CancellationToken ct)
    {
        var uri = original;
        for (var hop = 0; hop <= 3; hop++)
        {
            var response = await SendGetAsync(uri, ct);
            if (!IsRedirect(response.StatusCode))
            {
                if (response.IsSuccessStatusCode && response.StatusCode == HttpStatusCode.OK)
                    return response;
                response.Dispose();
                throw new InvalidDataException("Release asset GET failed");
            }
            var location = response.Headers.Location;
            response.Dispose();
            Require(hop < 3 && location is not null &&
                location.IsAbsoluteUri && IsAllowedAssetRedirect(location),
                "Untrusted or excessive Release redirect");
            uri = location!; // Require above rejects null; keep compiler flow analysis strict.
        }
        throw new InvalidDataException("Redirect exhaustion");
    }

    private async Task<HttpResponseMessage> SendGetAsync(Uri uri, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        return await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
    }

    private static bool IsAllowedAssetRedirect(Uri uri) =>
        uri.Scheme == Uri.UriSchemeHttps && uri.Port == 443 &&
        string.IsNullOrEmpty(uri.UserInfo) && string.IsNullOrEmpty(uri.Fragment) &&
        (uri.Host == "release-assets.githubusercontent.com" ||
         uri.Host == "objects.githubusercontent.com");

    private static bool IsRedirect(HttpStatusCode status) => (int)status is 301 or 302 or 303 or 307 or 308;

    private static void ValidatePin(ReleasePin p)
    {
        Require(p is not null &&
            Extension.IsMatch(p.Extension) && SafeComponent(p.Tag) &&
            SafeComponent(p.AssetName) && p.AssetName.EndsWith("-windows-x64.zip", StringComparison.Ordinal) &&
            p.AssetName.StartsWith(p.Extension + "-", StringComparison.Ordinal) &&
            Hex40.IsMatch(p.PackagingSha) && Hex64.IsMatch(p.Sha256) &&
            p.RepositoryId > 0 && p.ReleaseId > 0 && p.AssetId > 0 &&
            p.ExpectedSize > 0 && p.ExpectedSize <= MaxAssetSize,
            "Incomplete/untrusted exact asset pin");
    }

    private static bool SafeComponent(string value)
    {
        if (!Component.IsMatch(value) || value.EndsWith('.') || value.Length > 160) return false;
        var first = value.Split('.')[0].ToUpperInvariant();
        return first is not ("CON" or "PRN" or "AUX" or "NUL") &&
               !Regex.IsMatch(first, @"\A(?:COM|LPT)[1-9]\z");
    }

    private static void CheckDirectoryChain(string directory)
    {
        var current = Path.GetFullPath(directory);
        while (true)
        {
            var info = new DirectoryInfo(current);
            Require(info.Exists && (info.Attributes & FileAttributes.ReparsePoint) == 0,
                "Unsafe directory/reparse-point output path");
            var parent = info.Parent;
            if (parent is null) break;
            current = parent.FullName;
        }
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidDataException(message);
    }
}
