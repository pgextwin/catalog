using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PgExtWin.Releases;

internal static class PinnedBrowserDownloadTests
{
    public static async Task RunAsync(Action<bool, string> check)
    {
        byte[] bytes;
        using (var ms = new MemoryStream())
        {
            using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, true))
            {
                var entry = zip.CreateEntry("fixture.txt");
                using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
                writer.Write("not a real extension ZIP");
            }
            bytes = ms.ToArray();
        }
        var sha = Convert.ToHexStringLower(SHA256.HashData(bytes));
        var name = "pg_cron-v1-pg18-windows-x64.zip";
        var pin = new ReleasePins("pg_cron", "18", "v1-windows.1", name,
            sha, 100001, 100002, new Dictionary<string, long> { [name] = 100003 },
            new string('a', 40));
        var root = Path.Combine(Path.GetTempPath(),
            "pgextwin-browser-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            async Task<(bool rejected, string directory)> TryDownload(
                string label, Scenario scenario)
            {
                var folder = Path.Combine(root, "case-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(folder);
                using var client = new PinnedBrowserDownloader(new FakeHandler(bytes, scenario));
                bool rejected = false;
                try
                {
                    var receipt = await client.DownloadAsync(pin, folder);
                    check(scenario == Scenario.Success &&
                          receipt.Sha256 == sha && receipt.RepositoryId == 100001 &&
                          receipt.ReleaseId == 100002 && receipt.AssetId == 100003 &&
                          receipt.VerificationLevel == "INTEGRITY_ONLY" &&
                          File.ReadAllBytes(receipt.FilePath).SequenceEqual(bytes),
                          "Pinned public browser transport returns original ZIP bytes only");
                }
                catch (Exception e) when (e is InvalidDataException or IOException
                    or HttpRequestException or OperationCanceledException) { rejected = true; }
                check((scenario == Scenario.Success && !rejected) ||
                      (scenario != Scenario.Success && rejected &&
                       Directory.GetFiles(folder).Length == 0),
                      label + " strictly accepts/rejects and cleans partial ZIP files");
                return (rejected, folder);
            }
            await TryDownload("Github browser 302 to approved CDN", Scenario.Success);
            await TryDownload("Changed final original ZIP SHA256", Scenario.Corrupt);
            await TryDownload("Hostile external CDN redirect", Scenario.EvilRedirect);
            await TryDownload("Metadata JSON not accepted as binary ZIP", Scenario.JsonBody);
            await TryDownload("Binary HTTP 403 fails closed", Scenario.Deny);
            await TryDownload("HTTP 302 redirect loop fails closed", Scenario.Loop);

            var dest = Path.Combine(root, "final-batch");
            Directory.CreateDirectory(dest);
            using var browser = new PinnedBrowserDownloader(new FakeHandler(bytes, Scenario.Success));
            var batch = await BatchReleaseDownloader.StageAsync(
                new[] { pin }, "18", dest,
                (p, folder, token) => browser.DownloadAsync(p, folder, token),
                metadataVerified: false);
            using var manifest = JsonDocument.Parse(File.ReadAllText(
                Path.Combine(batch.Directory, "DOWNLOAD-INFO.json")));
            var record = manifest.RootElement;
            check(!record.GetProperty("releaseMetadataVerified").GetBoolean() &&
                record.GetProperty("source").GetString() == "CLI_PINNED_HISTORICAL_CANDIDATE_POLICY" &&
                record.GetProperty("verificationLevel").GetString() == "INTEGRITY_ONLY" &&
                !record.GetProperty("signatureVerified").GetBoolean(),
                "API-free manifest does not misrepresent live REST ID verification or original signatures");
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    private enum Scenario { Success, Corrupt, EvilRedirect, JsonBody, Deny, Loop }
    private sealed class FakeHandler(byte[] expected, Scenario scenario) : HttpMessageHandler
    {
        private static readonly Uri Target = new(
            "https://release-assets.githubusercontent.com/synthetic/original.zip");
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage req,
            CancellationToken token)
        {
            if (req.Method != HttpMethod.Get)
                throw new InvalidDataException("Browser transport used a non-GET request");
            var url = req.RequestUri!;
            if (url.Host == "github.com")
            {
                if (url.AbsolutePath !=
                    "/pgextwin/pg_cron/releases/download/v1-windows.1/pg_cron-v1-pg18-windows-x64.zip")
                    throw new InvalidDataException("Browser URL is not exact pinned source");
                var result = new HttpResponseMessage(HttpStatusCode.Redirect);
                result.Headers.Location = scenario switch
                {
                    Scenario.EvilRedirect => new Uri("https://evil.example.invalid/steal"),
                    Scenario.Loop => new Uri(url.AbsoluteUri),
                    _ => Target
                };
                return Task.FromResult(result);
            }
            if (url != Target) throw new InvalidDataException("Unknown redirected CDN");
            if (scenario == Scenario.Deny)
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden));
            if (scenario == Scenario.JsonBody)
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) {
                    Content = new StringContent("{\"wrong\":true}", Encoding.UTF8, "application/json")
                });
            var bytes = scenario == Scenario.Corrupt ? (byte[])expected.Clone() : expected;
            if (scenario == Scenario.Corrupt) bytes[5] ^= 0x7f;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) {
                Content = new ByteArrayContent(bytes)
            });
        }
    }
}
