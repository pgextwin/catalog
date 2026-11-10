using System.Net;

namespace PgExtWin.Releases;

// NONPUBLISHING transport-only candidate. No CLI command calls this type.
// A fresh owner-authenticated signed Build issuer and rights/provenance gates
// must be added independently before a user-facing OSGeo GET exists.
internal sealed record OsgeoOriginalCandidatePin(string PgMajor, string Version,
    string AssetName, string OriginalUrl, long OriginalBytes, string OriginalSha256);

internal sealed record OsgeoCandidateReceipt(string Path, long OriginalBytes,
    string OriginalSha256, string Scope = "CANDIDATE_INTEGRITY_ONLY_NOT_AUTHORIZED");

internal sealed class OsgeoOriginalCandidateTransport : IDisposable
{
    internal static readonly OsgeoOriginalCandidatePin Pinned = new(
        "18", "3.7.0", "postgis-bundle-pg18-3.7.0x64.zip",
        "https://download-cache.osgeo.org/postgis/windows/pg18/postgis-bundle-pg18-3.7.0x64.zip",
        83_320_975L,
        "fa3db8060d8d376e869d961659bf4eff326c0d99a731396701af61a13dc12a40");

    private readonly HttpClient http;

    internal OsgeoOriginalCandidateTransport(HttpMessageHandler? handler = null)
    {
        http = new HttpClient(handler ?? new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None,
        }, disposeHandler: true) { Timeout = TimeSpan.FromMinutes(5) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("pgextwin-osgeo-nonpublishing/1");
    }

    internal static void ValidatePin(OsgeoOriginalCandidatePin pin)
    {
        if (pin != Pinned)
            throw new InvalidDataException("Unreviewed OSGeo HTTPS original candidate");
    }

    internal async Task<OsgeoCandidateReceipt> DownloadAsync(
        OsgeoOriginalCandidatePin pin, string outputDir,
        CancellationToken token = default)
    {
        ValidatePin(pin);
        var folder = Path.GetFullPath(outputDir);
        if (!Directory.Exists(folder))
            throw new DirectoryNotFoundException("OSGeo output folder absent");
        for (DirectoryInfo? d = new(folder); d is not null; d = d.Parent)
            if ((d.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("OSGeo output directory is linked");
        RequireAbsent(folder, pin.AssetName);

        using var request = new HttpRequestMessage(HttpMethod.Get, pin.OriginalUrl);
        request.Headers.Accept.ParseAdd("application/octet-stream");
        using var response = await http.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, token);
        // Strictly no redirect, alternate origin, mirror, HEAD substitution or
        // retry when the exact approved origin fails.
        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException("OSGeo original HTTP " +
                (int)response.StatusCode);
        if (response.Content.Headers.ContentLength is long length &&
            length != pin.OriginalBytes)
            throw new InvalidDataException("Wrong OSGeo original length");
        if (response.Content.Headers.ContentType?.MediaType is
            "text/html" or "text/plain" or "application/json")
            throw new InvalidDataException("Non-ZIP OSGeo response");
        await using var input = await response.Content.ReadAsStreamAsync(token);
        using var memory = new MemoryStream();
        var chunk = new byte[81920];
        while (true)
        {
            int n = await input.ReadAsync(chunk, token);
            if (n == 0) break;
            if (memory.Length + n > pin.OriginalBytes)
                throw new InvalidDataException("OSGeo ZIP exceeds pinned bytes");
            await memory.WriteAsync(chunk.AsMemory(0, n), token);
        }
        var exact = memory.ToArray();
        ExternalOriginalZipIntegrity.VerifyOsgeoExactCandidate(
            exact, pin.OriginalBytes, pin.OriginalSha256);
        RequireAbsent(folder, pin.AssetName);
        var temp = Path.Combine(folder, "." + pin.AssetName + "." +
            Guid.NewGuid().ToString("N") + ".part");
        try
        {
            await using (var output = new FileStream(temp, FileMode.CreateNew,
                FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous))
                await output.WriteAsync(exact, token);
            RequireAbsent(folder, pin.AssetName);
            var final = Path.Combine(folder, pin.AssetName);
            File.Move(temp, final, overwrite: false);
            return new OsgeoCandidateReceipt(final, exact.LongLength, pin.OriginalSha256);
        }
        finally
        {
            if (File.Exists(temp)) File.Delete(temp);
        }
    }

    private static void RequireAbsent(string folder, string file)
    {
        if (Directory.EnumerateFileSystemEntries(folder).Any(path =>
            string.Equals(Path.GetFileName(path), file, StringComparison.OrdinalIgnoreCase)))
            throw new IOException("OSGeo ZIP destination already exists");
    }

    public void Dispose() => http.Dispose();
}
