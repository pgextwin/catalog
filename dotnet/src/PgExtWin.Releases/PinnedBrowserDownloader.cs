using System.Buffers;
using System.Net;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace PgExtWin.Releases;

/// <summary>
/// Alternative GitHub public Release browser transport: uses ONLY the exact
/// asset URL and SHA256 from the independently baked immutable P1 policy.
/// GitHub REST rate limits cannot block it. Numeric IDs are policy PINNED,
/// not live REST verified: the manifest must explicitly report that boundary.
/// Original extension Sigstore signatures are NOT verified.
/// </summary>
public sealed class PinnedBrowserDownloader : IDisposable
{
    private readonly HttpClient http;
    public PinnedBrowserDownloader(HttpMessageHandler? handler = null)
    {
        http = new HttpClient(handler ?? new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None
        }, disposeHandler: true) { Timeout = TimeSpan.FromMinutes(5) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("pgextwin-cli-frozen-browser/0.2.2");
    }

    public async Task<DownloadReceipt> DownloadAsync(ReleasePins pin,
        string outputDirectory, CancellationToken cancellationToken = default)
    {
        if (!Regex.IsMatch(pin.Extension, @"\A[a-z][a-z0-9_]*\z",
                RegexOptions.CultureInvariant) ||
            !Regex.IsMatch(pin.PgMajor, @"\A1[4-8]\z") ||
            !PinnedReleaseSelector.SafeAssetName(pin.Tag) ||
            !PinnedReleaseSelector.SafeAssetName(pin.AssetName) ||
            !pin.AssetName.StartsWith(pin.Extension + "-", StringComparison.Ordinal) ||
            !pin.AssetName.EndsWith("-pg" + pin.PgMajor + "-windows-x64.zip",
                StringComparison.Ordinal) ||
            !Regex.IsMatch(pin.AssetSha256, @"\A[0-9a-f]{64}\z") ||
            pin.RepositoryId <= 0 || pin.ReleaseId <= 0 ||
            !pin.AssetIds.TryGetValue(pin.AssetName, out var assetId) || assetId <= 0)
            throw new InvalidDataException("Unpinned ZIP browser request");

        var directory = Path.GetFullPath(outputDirectory);
        if (!Directory.Exists(directory))
            throw new DirectoryNotFoundException("Original ZIP output directory missing");
        for (DirectoryInfo? d = new(directory); d is not null; d = d.Parent)
            if ((d.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Output path contains a link");
        var final = Path.Combine(directory, pin.AssetName);
        if (Directory.EnumerateFileSystemEntries(directory).Any(x =>
            string.Equals(Path.GetFileName(x), pin.AssetName,
                StringComparison.OrdinalIgnoreCase)))
            throw new IOException("ZIP destination already exists; no overwrite");
        var source = new Uri("https://github.com/pgextwin/" + pin.Extension +
            "/releases/download/" + pin.Tag + "/" + pin.AssetName);
        var temp = Path.Combine(directory, "." + pin.AssetName + "." +
            Guid.NewGuid().ToString("N") + ".part");
        try
        {
            using var response = await GetPublicAssetAsync(source, cancellationToken);
            var media = response.Content.Headers.ContentType?.MediaType;
            if (media is "application/json" or "text/html" or "text/plain")
                throw new InvalidDataException("GitHub browser asset is not ZIP bytes");
            if (response.Content.Headers.ContentLength is long length &&
                (length < 4 || length > ReadOnlyReleaseDownloader.MaxAssetBytes))
                throw new InvalidDataException("ZIP browser Content-Length exceeds bound");
            await using var file = new FileStream(temp, FileMode.CreateNew,
                FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous);
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var bytes = ArrayPool<byte>.Shared.Rent(81920);
            long count = 0;
            try
            {
                while (true)
                {
                    var n = await stream.ReadAsync(bytes.AsMemory(0, bytes.Length),
                        cancellationToken);
                    if (n == 0) break;
                    if (count + n > ReadOnlyReleaseDownloader.MaxAssetBytes)
                        throw new InvalidDataException("ZIP exceeds 64MiB download cap");
                    hash.AppendData(bytes, 0, n);
                    await file.WriteAsync(bytes.AsMemory(0, n), cancellationToken);
                    count += n;
                }
            }
            finally { ArrayPool<byte>.Shared.Return(bytes); }
            await file.FlushAsync(cancellationToken);
            if (count < 4 ||
                (response.Content.Headers.ContentLength is long declared && count != declared) ||
                Convert.ToHexStringLower(hash.GetHashAndReset()) != pin.AssetSha256)
                throw new InvalidDataException("Original browser ZIP SHA256 or size mismatch");
            await file.DisposeAsync();
            using (var zip = new FileStream(temp, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                Span<byte> magic = stackalloc byte[4];
                if (zip.Read(magic) != 4 || magic[0] != 0x50 || magic[1] != 0x4b ||
                    magic[2] != 0x03 || magic[3] != 0x04)
                    throw new InvalidDataException("Published asset lacks ZIP local header");
            }
            if (Directory.EnumerateFileSystemEntries(directory).Any(x =>
                string.Equals(Path.GetFileName(x), pin.AssetName,
                    StringComparison.OrdinalIgnoreCase)))
                throw new IOException("ZIP output created concurrently; no overwrite");
            File.Move(temp, final, overwrite: false);
            return new DownloadReceipt(final, pin.AssetSha256, count, pin.RepositoryId,
                pin.ReleaseId, assetId);
        }
        finally
        {
            if (File.Exists(temp)) File.Delete(temp);
        }
    }

    private async Task<HttpResponseMessage> GetPublicAssetAsync(Uri initial,
        CancellationToken cancellationToken)
    {
        Uri next = initial;
        var visited = new HashSet<string>(StringComparer.Ordinal);
        for (var hop = 0; hop < 5; hop++)
        {
            if (next.Scheme != Uri.UriSchemeHttps || next.Port != 443 ||
                !string.IsNullOrEmpty(next.UserInfo) || !string.IsNullOrEmpty(next.Fragment) ||
                !(next.Host == "github.com" && hop == 0 ||
                  hop > 0 && (next.Host == "release-assets.githubusercontent.com" ||
                    next.Host == "objects.githubusercontent.com" ||
                    next.Host == "github-releases.githubusercontent.com")))
                throw new InvalidDataException("Untrusted original Release browser redirect");
            if (!visited.Add(next.AbsoluteUri))
                throw new InvalidDataException("ZIP browser redirect cycle");
            using var request = new HttpRequestMessage(HttpMethod.Get, next);
            var response = await http.SendAsync(request,
                HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (response.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.MovedPermanently
                or HttpStatusCode.RedirectMethod or HttpStatusCode.TemporaryRedirect
                or HttpStatusCode.PermanentRedirect)
            {
                var location = response.Headers.Location;
                response.Dispose();
                if (location is null || !location.IsAbsoluteUri)
                    throw new InvalidDataException("Relative or absent ZIP redirect forbidden");
                next = location;
                continue;
            }
            if (response.StatusCode != HttpStatusCode.OK)
            {
                var status = (int)response.StatusCode;
                response.Dispose();
                throw new HttpRequestException("Public ZIP asset HTTP status " + status);
            }
            return response;
        }
        throw new InvalidDataException("Too many ZIP browser redirects");
    }

    public void Dispose() => http.Dispose();
}
