using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PgExtWin.Releases;

// No live provider GET: all providers below are synthetic byte fixtures.
// These tests exercise transport mechanics, NOT authorization or Publisher.
internal static class ExternalProviderAssetTransportTests
{
    private sealed class FakeNetwork(Func<HttpRequestMessage, HttpResponseMessage> responder)
        : HttpMessageHandler
    {
        public int Requests { get; private set; }
        public List<string> Paths { get; } = [];
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            Paths.Add(request.RequestUri!.AbsoluteUri);
            return Task.FromResult(responder(request));
        }
    }

    private static byte[] Zip()
    {
        using var buffer = new MemoryStream();
        using (var archive = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = archive.CreateEntry("README.txt");
            using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
            writer.Write("synthetic original bytes, never a provider package");
        }
        return buffer.ToArray();
    }

    private static ExternalOriginalPin Pin(string repo, string extension,
        string name, long id, byte[] bytes) =>
        new(extension, "18", repo, 12345, "v1.2.3", 45678, name, id,
            bytes.Length, Convert.ToHexStringLower(SHA256.HashData(bytes)),
            "https://github.com/" + repo + "/releases/download/v1.2.3/" + name);

    private static HttpResponseMessage Json(object value) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8,
                "application/json")
        };

    private static FakeNetwork Network(ExternalOriginalPin pin, byte[] content,
        string? substitutedRepo = null, bool wrongAssetId = false,
        HttpStatusCode? binaryStatus = null, string? redirect = null)
    {
        return new FakeNetwork(request =>
        {
            var url = request.RequestUri!.AbsoluteUri;
            var prefix = "https://api.github.com/repos/" + pin.SourceRepo;
            if (url == prefix)
                return Json(new { full_name = substitutedRepo ?? pin.SourceRepo,
                    id = pin.RepositoryId });
            if (url == prefix + "/releases/tags/" + pin.Tag)
                return Json(new
                {
                    id = pin.ReleaseId, tag_name = pin.Tag, draft = false,
                    published_at = "2026-11-01T00:00:00Z",
                    assets = new[] { new
                    {
                        id = wrongAssetId ? pin.AssetId + 1 : pin.AssetId,
                        name = pin.AssetName, size = pin.OriginalBytes,
                        digest = "sha256:" + pin.OriginalSha256, state = "uploaded",
                        browser_download_url = pin.OriginalProviderUrl
                    } }
                });
            if (url == prefix + "/releases/assets/" + pin.AssetId)
            {
                if (redirect is not null)
                {
                    var r = new HttpResponseMessage(HttpStatusCode.Redirect);
                    r.Headers.Location = new Uri(redirect);
                    return r;
                }
                return new HttpResponseMessage(binaryStatus ?? HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(content)
                    {
                        Headers = { ContentType =
                            new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream") }
                    }
                };
            }
            throw new InvalidOperationException("Unexpected network request " + url);
        });
    }

    private static async Task<bool> DeniedAsync(
        ExternalProviderAssetTransport transport, ExternalOriginalPin pin, string directory)
    {
        try { await transport.DownloadAsync(pin, directory); return false; }
        catch (Exception e) when (e is InvalidDataException or IOException or HttpRequestException)
        { return true; }
    }

    public static async Task RunAsync(Action<bool, string> check)
    {
        var folder = Path.Combine(Path.GetTempPath(),
            "pgextwin-external-transport-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            var bytes = Zip();
            var candidates = new[]
            {
                ("laurenz/oracle_fdw", "oracle_fdw", "oracle_fdw-1.2.3-pg18-win64.zip", 1L),
                ("andreiramani/pgvector_pgsql_windows", "pgvector", "vector.v1.2.3-pg18.zip", 2L),
                ("trickle-labs/pg-trickle", "pg_trickle", "pg_trickle-1.2.3-pg18-windows-amd64.zip", 3L),
                ("portalcorp/pgvector_compiled", "pgvector", "pgvector-Windows-pg16.zip", 4L)
            };
            foreach (var (repo, extension, name, id) in candidates)
            {
                var pin = Pin(repo, extension, name, id, bytes);
                var fake = Network(pin, bytes);
                using (var transport = new ExternalProviderAssetTransport(fake))
                {
                    var receipt = await transport.DownloadAsync(pin, folder);
                    check(receipt.RepositoryId == pin.RepositoryId &&
                          receipt.ReleaseId == pin.ReleaseId &&
                          receipt.AssetId == pin.AssetId &&
                          receipt.Size == bytes.Length &&
                          receipt.Sha256 == pin.OriginalSha256 &&
                          File.ReadAllBytes(receipt.FilePath).SequenceEqual(bytes) &&
                          fake.Requests == 3,
                        "Synthetic original provider ID/size/SHA256/ZIP validated: " + repo);
                }
                File.Delete(Path.Combine(folder, name));
            }

            var original = Pin("laurenz/oracle_fdw", "oracle_fdw",
                "oracle_fdw-1.2.3-pg18-win64.zip", 100L, bytes);
            var forged = original with
            {
                OriginalProviderUrl = "https://example.invalid/forged.zip"
            };
            var noRequests = Network(forged, bytes);
            using (var transport = new ExternalProviderAssetTransport(noRequests))
                check(await DeniedAsync(transport, forged, folder) && noRequests.Requests == 0,
                    "Forged provider URL denied before GET");

            var wrongRepo = Network(original, bytes, substitutedRepo: "attacker/replacement");
            using (var transport = new ExternalProviderAssetTransport(wrongRepo))
                check(await DeniedAsync(transport, original, folder) &&
                      wrongRepo.Requests == 1,
                    "Repository identity substitution denied before Release/asset GET");

            var wrongAsset = Network(original, bytes, wrongAssetId: true);
            using (var transport = new ExternalProviderAssetTransport(wrongAsset))
                check(await DeniedAsync(transport, original, folder) &&
                      wrongAsset.Requests == 2,
                    "Asset ID substitution denied before original-byte GET");

            var tamperedBytes = bytes.ToArray();
            tamperedBytes[^9] ^= 0x01;
            var corrupt = Network(original, tamperedBytes);
            using (var transport = new ExternalProviderAssetTransport(corrupt))
                check(await DeniedAsync(transport, original, folder) &&
                      corrupt.Requests == 3 && Directory.GetFileSystemEntries(folder).Length == 0,
                    "Tampered original ZIP rejects and leaves no output");

            var offsite = Network(original, bytes,
                redirect: "https://example.invalid/asset.zip");
            using (var transport = new ExternalProviderAssetTransport(offsite))
                check(await DeniedAsync(transport, original, folder) &&
                      offsite.Requests == 3 &&
                      Directory.GetFileSystemEntries(folder).Length == 0,
                    "Off-host redirect denied without following");

            var forbidden = Network(original, bytes, binaryStatus: HttpStatusCode.Forbidden);
            using (var transport = new ExternalProviderAssetTransport(forbidden))
                check(await DeniedAsync(transport, original, folder) &&
                      forbidden.Requests == 3,
                    "HTTP 403 fails closed without retry or fallback");

            File.WriteAllText(Path.Combine(folder, original.AssetName), "existing file");
            var collision = Network(original, bytes);
            using (var transport = new ExternalProviderAssetTransport(collision))
                check(await DeniedAsync(transport, original, folder) &&
                      collision.Requests == 0 &&
                      File.ReadAllText(Path.Combine(folder, original.AssetName)) == "existing file",
                    "Existing destination denied before GET; no overwrite");
            File.Delete(Path.Combine(folder, original.AssetName));
            check(Directory.GetFileSystemEntries(folder).Length == 0,
                "Synthetic provider suite leaves no original ZIP or part files");
        }
        finally { Directory.Delete(folder, recursive: true); }
    }
}
