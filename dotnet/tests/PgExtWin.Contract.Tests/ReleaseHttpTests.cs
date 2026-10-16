using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PgExtWin.Core;
using PgExtWin.Releases;

internal static class ReleaseHttpTests
{
    private const string Repo = "testext";
    private const string Tag = "v1.0-windows.1";
    private const string Name = "testext-v1-pg18-windows-x64.zip";
    private const long RepoId = 1234001, ReleaseId = 1234002, AssetId = 1234003, SumId = 1234004;
    private static readonly Uri Cdn = new("https://release-assets.githubusercontent.com/testing/original.zip");

    public static async Task RunAsync(Action<bool, string> check)
    {
        var zip = MakeZip();
        var digest = StrictJson.Sha256(zip);
        using var fixture = new Fixture(digest);
        var selected = PinnedReleaseSelector.FromLocalFiles(fixture.CatalogPath,
            fixture.PolicyFile, fixture.PolicyDigest, Repo, "18");
        check(selected.AssetIds[Name] == AssetId && selected.AssetSha256 == digest,
            "P1 policy/catalog pin fixture");

        async Task<(DownloadReceipt receipt, string output)> Success(FakeOptions? opts = null)
        {
            var folder = fixture.NewOutput();
            using var client = new ReadOnlyReleaseDownloader(new FakeHandler(zip, digest, opts));
            return (await client.DownloadAsync(selected, folder), folder);
        }

        var ok = await Success();
        check(ok.receipt.VerificationLevel == "INTEGRITY_ONLY" &&
              ok.receipt.RepositoryId == RepoId && ok.receipt.ReleaseId == ReleaseId &&
              ok.receipt.AssetId == AssetId && ok.receipt.Size == zip.Length,
              "Original ZIP SHA256 matched but integrity-only never signature-verified");
        check(File.ReadAllBytes(ok.receipt.FilePath).SequenceEqual(zip),
              "Streamed original ZIP saved byte-identically");
        check(Directory.GetFiles(ok.output).Length == 1, "Atomic final file with no .part");

        // All tests use an in-memory HTTP fake. No real Release/network/attestation.
        async Task Failure(string name, FakeOptions opts)
        {
            var folder = fixture.NewOutput();
            using var client = new ReadOnlyReleaseDownloader(new FakeHandler(zip, digest, opts));
            var rejected = false;
            try { await client.DownloadAsync(selected, folder); }
            catch (Exception e) when (e is InvalidDataException or IOException or HttpRequestException
                or OperationCanceledException or JsonException) { rejected = true; }
            check(rejected && Directory.GetFiles(folder).Length == 0, name + " fails closed and cleans staging");
        }
        await Failure("wrong repository numeric ID", new FakeOptions(RepoId: 999));
        await Failure("wrong Release numeric ID", new FakeOptions(ReleaseId: 999));
        await Failure("wrong Asset ID", new FakeOptions(AssetId: 999));
        await Failure("mismatched Release digest", new FakeOptions(MetadataDigest: new string('f', 64)));
        await Failure("modified actual bytes", new FakeOptions(CorruptBytes: true));
        await Failure("HTTP 403 rate-limit/authorization", new FakeOptions(DenyApi: true));
        await Failure("untrusted redirect host", new FakeOptions(EvilRedirect: true));
        await Failure("duplicate asset identity", new FakeOptions(DuplicateAsset: true));
        await Failure("declared asset size mismatch", new FakeOptions(IncorrectSize: true));
        await Failure("truncated HTTP asset bytes", new FakeOptions(Truncated: true));
        await Failure("HTML response rather than ZIP", new FakeOptions(HtmlBody: true));

        {
            var dir = fixture.NewOutput();
            File.WriteAllText(Path.Combine(dir, Name), "KEEP");
            using var client = new ReadOnlyReleaseDownloader(new FakeHandler(zip, digest, null));
            var failed = false;
            try { await client.DownloadAsync(selected, dir); }
            catch (IOException) { failed = true; }
            check(failed && File.ReadAllText(Path.Combine(dir, Name)) == "KEEP",
                  "Existing destination cannot be overwritten");
        }

        {
            // Catalog tampering after P1 pin acquisition must be rejected at request construction.
            File.AppendAllText(Path.Combine(fixture.CatalogPath, "extensions", Repo + ".json"), " ");
            var rejected = false;
            try { PinnedReleaseSelector.FromLocalFiles(fixture.CatalogPath, fixture.PolicyFile,
                fixture.PolicyDigest, Repo, "18"); }
            catch (InvalidDataException) { rejected = true; }
            check(rejected, "Tampered Catalog raw bytes denied");
            fixture.RestoreCatalog();
        }

        {
            var rejected = false;
            try { PinnedReleaseSelector.FromLocalFiles(fixture.CatalogPath, fixture.PolicyFile,
                new string('0', 64), Repo, "18"); }
            catch (InvalidDataException) { rejected = true; }
            check(rejected, "Changed external P1 policy digest denied");
        }
        {
            var rejected = false;
            try { PinnedReleaseSelector.FromLocalFiles(fixture.CatalogPath, fixture.PolicyFile,
                fixture.PolicyDigest, Repo, "19"); }
            catch (Exception e) when (e is InvalidDataException or KeyNotFoundException) { rejected = true; }
            check(rejected, "Unapproved PG19 denied");
        }
    }

    private static byte[] MakeZip()
    {
        using var output = new MemoryStream();
        using (var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry("README.txt", CompressionLevel.NoCompression);
            using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
            writer.Write("Synthetic ZIP bytes for tests ONLY.");
        }
        return output.ToArray();
    }

    private sealed record FakeOptions(long? RepoId = null, long? ReleaseId = null, long? AssetId = null,
        string? MetadataDigest = null, bool CorruptBytes = false, bool DenyApi = false,
        bool EvilRedirect = false, bool DuplicateAsset = false, bool IncorrectSize = false,
        bool Truncated = false, bool HtmlBody = false);

    private sealed class FakeHandler(byte[] zip, string digest, FakeOptions? opts) : HttpMessageHandler
    {
        private readonly FakeOptions options = opts ?? new FakeOptions();
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            if (request.Method != HttpMethod.Get)
                throw new Exception("GET-only violation");
            var uri = request.RequestUri!;
            if (uri.AbsoluteUri == "https://api.github.com/repos/pgextwin/" + Repo)
            {
                if (options.DenyApi) return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden));
                return Json(new { full_name = "pgextwin/" + Repo, id = options.RepoId ?? RepoId });
            }
            if (uri.AbsoluteUri == "https://api.github.com/repos/pgextwin/" + Repo +
                    "/releases/tags/" + Tag)
            {
                var selected = new
                {
                    name = Name, id = options.AssetId ?? AssetId,
                    size = zip.Length + (options.IncorrectSize ? 1 : 0), state = "uploaded",
                    digest = "sha256:" + (options.MetadataDigest ?? digest),
                    browser_download_url = "https://github.com/pgextwin/" + Repo +
                        "/releases/download/" + Tag + "/" + Name
                };
                var sums = new
                {
                    name = "SHA256SUMS.txt", id = SumId, size = 80, state = "uploaded",
                    digest = "sha256:" + new string('a', 64),
                    browser_download_url = "https://github.com/pgextwin/" + Repo +
                        "/releases/download/" + Tag + "/SHA256SUMS.txt"
                };
                var assets = options.DuplicateAsset ? new object[] { selected, sums, selected } :
                    new object[] { selected, sums };
                return Json(new { id = options.ReleaseId ?? ReleaseId, draft = false,
                    prerelease = false, tag_name = Tag, target_commitish = new string('a', 40),
                    assets });
            }
            if (uri.AbsoluteUri == "https://api.github.com/repos/pgextwin/" + Repo +
                    "/releases/assets/" + AssetId)
            {
                var response = new HttpResponseMessage(HttpStatusCode.Redirect);
                response.Headers.Location = options.EvilRedirect
                    ? new Uri("https://evil.example.invalid/steal") : Cdn;
                return Task.FromResult(response);
            }
            if (uri == Cdn)
            {
                var bytes = options.CorruptBytes ? (byte[])zip.Clone() :
                    options.Truncated ? zip[..^1] : zip;
                if (options.CorruptBytes) bytes[8] ^= 0x20;
                var response = new HttpResponseMessage(HttpStatusCode.OK);
                if (options.HtmlBody)
                {
                    response.Content = new StringContent("<html>blocked</html>");
                }
                else response.Content = new ByteArrayContent(bytes);
                return Task.FromResult(response);
            }
            throw new Exception("Unexpected fixture URI: " + uri);
        }

        private static Task<HttpResponseMessage> Json(object value) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json")
            });
    }

    private sealed class Fixture : IDisposable
    {
        public string CatalogPath { get; }
        public string PolicyFile { get; }
        public string PolicyDigest { get; }
        private readonly string root;
        private readonly string record;

        public Fixture(string digest)
        {
            root = Path.Combine(Path.GetTempPath(), "pgextwin-pr2-fixture-" + Guid.NewGuid().ToString("N"));
            CatalogPath = Path.Combine(root, "catalog");
            Directory.CreateDirectory(Path.Combine(CatalogPath, "extensions"));
            var index = "{\"schemaVersion\":2,\"extensions\":[\"testext\"]}";
            record = JsonSerializer.Serialize(new
            {
                schemaVersion = 2, name = Repo, repository = "pgextwin/" + Repo,
                architecture = "x64", displayName = "testext", description = "synthetic",
                latest = new { releaseTag = Tag },
                upstream = new { version = "1.0" },
                postgresql = new Dictionary<string, object> { ["18"] = new
                    { available = true, asset = Name, sha256 = digest } }
            });
            File.WriteAllText(Path.Combine(CatalogPath, "index.json"), index);
            RestoreCatalog();
            var catalogDigests = new Dictionary<string, string>
            {
                ["index.json"] = StrictJson.Sha256(Encoding.UTF8.GetBytes(index)),
                ["extensions/" + Repo + ".json"] = StrictJson.Sha256(Encoding.UTF8.GetBytes(record))
            };
            PolicyFile = Path.Combine(root, "policy.json");
            var policy = new
            {
                schemaVersion = "pgextwin-p1-readonly-policy/v1",
                catalogCommitSha = new string('a', 40),
                catalogDigests,
                signerRepositoryId = 1405931353,
                rootSha256 = new string('b', 64),
                approvedMajors = new[] { 18 },
                pgEol = new Dictionary<string, string> { ["18"] = "2030-11-14" },
                repoIds = new Dictionary<string, long> { [Repo] = RepoId },
                releaseIds = new Dictionary<string, long> { [Repo] = ReleaseId },
                assetIds = new Dictionary<string, Dictionary<string, long>> {
                    [Repo] = new() { [Name] = AssetId, ["SHA256SUMS.txt"] = SumId } }
            };
            var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(policy));
            File.WriteAllBytes(PolicyFile, bytes);
            PolicyDigest = StrictJson.Sha256(bytes);
        }

        public void RestoreCatalog() =>
            File.WriteAllText(Path.Combine(CatalogPath, "extensions", Repo + ".json"), record);

        public string NewOutput()
        {
            var output = Path.Combine(root, "output-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(output);
            return output;
        }

        public void Dispose() => Directory.Delete(root, recursive: true);
    }
}
