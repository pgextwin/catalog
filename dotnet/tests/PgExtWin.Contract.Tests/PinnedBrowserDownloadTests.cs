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
                var fake = new FakeHandler(bytes, scenario);
                using var client = new PinnedBrowserDownloader(fake);
                bool rejected = false;
                try
                {
                    var receipt = await client.DownloadAsync(pin, folder);
                    check(scenario is Scenario.Success or Scenario.TransientGateway or Scenario.ApiRecover &&
                          receipt.Sha256 == sha && receipt.RepositoryId == 100001 &&
                          receipt.ReleaseId == 100002 && receipt.AssetId == 100003 &&
                          receipt.VerificationLevel == "INTEGRITY_ONLY" &&
                          File.ReadAllBytes(receipt.FilePath).SequenceEqual(bytes),
                          "Pinned public browser transport returns original ZIP bytes only");
                }
                catch (Exception e) when (e is InvalidDataException or IOException
                    or HttpRequestException or OperationCanceledException) { rejected = true; }
                var shouldPass = scenario is Scenario.Success or Scenario.TransientGateway or Scenario.ApiRecover;
                check((shouldPass && !rejected) ||
                      (!shouldPass && rejected && Directory.GetFiles(folder).Length == 0),
                      label + " strictly accepts/rejects and cleans partial ZIP files");
                if (scenario is Scenario.TransientGateway or Scenario.PersistentGateway or
                    Scenario.ApiRecover or Scenario.ApiJson or Scenario.ApiEvilRedirect)
                    check(fake.AssetRequests == 3,
                          "Browser CDN transient GET remains bounded to three attempts");
                if (scenario is Scenario.PersistentGateway or Scenario.ApiRecover or
                    Scenario.ApiJson or Scenario.ApiEvilRedirect)
                    check(fake.ApiRequests == 1, "Only one pinned native API asset-ID GET");
                if (scenario is Scenario.Deny or Scenario.TransientGateway)
                    check(fake.ApiRequests == 0, "No fallback on 403 or recovered transient");
                if (scenario == Scenario.Deny)
                    check(fake.AssetRequests == 1, "HTTP 403 is never retried");
                return (rejected, folder);
            }
            await TryDownload("Github browser 302 to approved CDN", Scenario.Success);
            await TryDownload("Changed final original ZIP SHA256", Scenario.Corrupt);
            await TryDownload("Hostile external CDN redirect", Scenario.EvilRedirect);
            await TryDownload("Metadata JSON not accepted as binary ZIP", Scenario.JsonBody);
            await TryDownload("Binary HTTP 403 fails closed", Scenario.Deny);
            await TryDownload("Two transient HTTP 504 replies recover on same verified URL", Scenario.TransientGateway);
            await TryDownload("Three persistent HTTP 504 replies fail closed", Scenario.PersistentGateway);
            await TryDownload("Verified native API asset-ID fallback obtains exact original ZIP", Scenario.ApiRecover);
            await TryDownload("API metadata JSON cannot masquerade as ZIP", Scenario.ApiJson);
            await TryDownload("API fallback never follows an untrusted redirect", Scenario.ApiEvilRedirect);
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

    private enum Scenario { Success, Corrupt, EvilRedirect, JsonBody, Deny, Loop, TransientGateway, PersistentGateway, ApiRecover, ApiJson, ApiEvilRedirect }
    private sealed class FakeHandler(byte[] expected, Scenario scenario) : HttpMessageHandler
    {
        private static readonly Uri Target = new(
            "https://release-assets.githubusercontent.com/synthetic/original.zip");
        private static readonly Uri ApiAsset = new(
            "https://api.github.com/repos/pgextwin/pg_cron/releases/assets/100003");
        private static readonly Uri ApiTarget = new(
            "https://release-assets.githubusercontent.com/synthetic/via-api.zip");
        public int AssetRequests { get; private set; }
        public int ApiRequests { get; private set; }
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
            if (url == ApiAsset)
            {
                ApiRequests++;
                if (!req.Headers.Accept.Any(x => x.MediaType == "application/octet-stream"))
                    throw new InvalidDataException("API fallback did not request binary bytes");
                if (scenario == Scenario.ApiRecover)
                {
                    var redirect = new HttpResponseMessage(HttpStatusCode.Redirect);
                    redirect.Headers.Location = ApiTarget;
                    return Task.FromResult(redirect);
                }
                if (scenario == Scenario.ApiJson)
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) {
                        Content = new StringContent("{\"metadata\":true}", Encoding.UTF8, "application/json")
                    });
                if (scenario == Scenario.ApiEvilRedirect)
                {
                    var redirect = new HttpResponseMessage(HttpStatusCode.Redirect);
                    redirect.Headers.Location = new Uri("https://evil.example.invalid/asset");
                    return Task.FromResult(redirect);
                }
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.GatewayTimeout));
            }
            if (url == ApiTarget)
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) {
                    Content = new ByteArrayContent(expected)
                });
            if (url != Target) throw new InvalidDataException("Unknown redirected CDN");
            AssetRequests++;
            if (scenario is Scenario.PersistentGateway or Scenario.ApiRecover or Scenario.ApiJson or
                Scenario.ApiEvilRedirect ||
                (scenario == Scenario.TransientGateway && AssetRequests <= 2))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.GatewayTimeout));
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
