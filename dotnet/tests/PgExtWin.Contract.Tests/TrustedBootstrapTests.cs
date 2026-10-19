using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using PgExtWin.Catalog;
using PgExtWin.Releases;

internal static class TrustedBootstrapTests
{
    private static readonly string PolicySource = TrustedCatalogBootstrap.PolicySourceCommit;
    private static readonly string Snapshot = TrustedCatalogBootstrap.CatalogSnapshotCommit;
    private static readonly string PolicyPath = TrustedCatalogBootstrap.PolicyPath;

    public static async Task RunAsync(Action<bool, string> check)
    {
        // Fully synthetic transport, but real immutable Git originals from a
        // full read-only CI checkout. No external GET, Release, or signing.
        var policy = File.ReadAllBytes(Path.Combine("config",
            "issue112-p1-fleet-pins-20261017.json"));
        var paths = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            [Url(PolicySource, PolicyPath)] = policy
        };
        using (var doc = JsonDocument.Parse(policy))
        {
            foreach (var row in doc.RootElement.GetProperty("catalogDigests").EnumerateObject())
                paths[Url(Snapshot, row.Name)] = GitOriginal(Snapshot, row.Name);
        }
        check(paths.Count == 16, "One-command bootstrap pins 1 policy + 15 immutable Catalog files");

        var root = Path.Combine(Path.GetTempPath(),
            "pgextwin-boot-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using (var fake = new GitOriginalHandler(paths))
            using (var session = await TrustedCatalogBootstrap.AcquireAsync(root, fake))
            {
                var records = CatalogReader.LoadLocal(session.CatalogPath);
                check(records.Count == 14 && records.All(x => x.Versions.Count == 5),
                    "One-command genuine pinned historical Catalog covers all 70 original ZIP rows");
                var pin = PinnedReleaseSelector.FromLocalFiles(
                    session.CatalogPath, session.PolicyFile,
                    TrustedCatalogBootstrap.PolicySha256, "pg_cron", "18");
                check(pin.RepositoryId > 0 && pin.ReleaseId > 0 &&
                    pin.AssetIds.ContainsKey(pin.AssetName),
                    "One-command produces policy/catalog files accepted by existing strict numeric pin checker");
                check(fake.Requests.Count == 16 &&
                    fake.Requests.All(x => paths.ContainsKey(x)),
                    "Bootstrap never uses mutable main, non-HTTPS or foreign URLs");
            }
            check(Directory.GetFileSystemEntries(root).Length == 0,
                "Temporary pinned bootstrap removed after successful use");

            async Task Denied(string label, string alteredUrl, byte[]? altered,
                HttpStatusCode status = HttpStatusCode.OK)
            {
                var tampered = new Dictionary<string, byte[]>(paths);
                if (altered is not null) tampered[alteredUrl] = altered;
                using var fake = new GitOriginalHandler(tampered, alteredUrl, status);
                var rejected = false;
                try
                {
                    using var session = await TrustedCatalogBootstrap.AcquireAsync(root, fake);
                }
                catch (Exception ex) when (ex is InvalidDataException or HttpRequestException
                    or IOException or JsonException)
                {
                    rejected = true;
                }
                check(rejected && Directory.GetFileSystemEntries(root).Length == 0,
                    label + " fail-closed without temporary output");
            }
            var poisoned = (byte[])policy.Clone();
            poisoned[10] ^= 1;
            await Denied("Edited policy cannot replace embedded SHA256",
                Url(PolicySource, PolicyPath), poisoned);
            var index = (byte[])paths[Url(Snapshot, "index.json")].Clone();
            index[0] ^= 1;
            await Denied("Changed immutable Catalog original bytes rejected",
                Url(Snapshot, "index.json"), index);
            await Denied("Redirect not followed", Url(PolicySource, PolicyPath), null,
                HttpStatusCode.Redirect);
            await Denied("HTTP missing pin input", Url(PolicySource, PolicyPath), null,
                HttpStatusCode.NotFound);
            await Denied("Oversized remote policy is rejected",
                Url(PolicySource, PolicyPath), new byte[2 * 1024 * 1024 + 1]);
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    private static string Url(string commit, string path) =>
        "https://raw.githubusercontent.com/pgextwin/catalog/" + commit + "/" + path;

    private static byte[] GitOriginal(string commit, string path)
    {
        var info = new ProcessStartInfo("git")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        info.ArgumentList.Add("show");
        info.ArgumentList.Add(commit + ":" + path);
        using var process = Process.Start(info) ??
            throw new InvalidDataException("Failed to run git show");
        using var output = new MemoryStream();
        process.StandardOutput.BaseStream.CopyTo(output);
        process.WaitForExit();
        if (process.ExitCode != 0)
            throw new InvalidDataException("Historical blob unavailable in complete CI checkout: " + path);
        return output.ToArray();
    }

    private sealed class GitOriginalHandler(
        Dictionary<string, byte[]> files, string? overrideUrl = null,
        HttpStatusCode overrideStatus = HttpStatusCode.OK) : HttpMessageHandler
    {
        public List<string> Requests { get; } = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage req,
            CancellationToken token)
        {
            if (req.Method != HttpMethod.Get ||
                req.RequestUri is null || req.RequestUri.Scheme != "https")
                throw new InvalidDataException("Unsafe synthetic bootstrap method/URL");
            var url = req.RequestUri.AbsoluteUri;
            Requests.Add(url);
            if (!files.TryGetValue(url, out var data))
                throw new InvalidDataException("Unpinned bootstrap path");
            var response = new HttpResponseMessage(url == overrideUrl
                ? overrideStatus : HttpStatusCode.OK);
            response.Content = new ByteArrayContent(data);
            if (response.StatusCode == HttpStatusCode.Redirect)
                response.Headers.Location = new Uri("https://evil.example.invalid/changed");
            return Task.FromResult(response);
        }
    }
}
