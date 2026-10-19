using System.Net;
using System.Text;
using System.Text.Json;
using PgExtWin.Releases;

internal static class AuthenticatedCatalogHeadTests
{
    private const string Head = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private sealed class FixtureHandler : HttpMessageHandler
    {
        public bool Protected = true;
        public bool Signed = true;
        public bool CiSuccess = true;
        public bool MutateHead = false;
        public bool BadRecord = false;
        public bool RateLimit = false;
        public bool WrongReleaseDigest = false;
        public bool DraftRelease = false;
        public int HeadReads = 0;
        private static readonly string[] Names = new[]
        {
            "hypopg", "orafce", "pg_bigm", "pg_cron", "pg_hint_plan",
            "pg_ivm", "pg_partman", "pg_qualstats", "pg_repack",
            "pg_stat_monitor", "pgaudit", "plpgsql_check", "set_user", "wal2json"
        };
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage req,
            CancellationToken cancellationToken)
        {
            var path = req.RequestUri!.AbsolutePath;
            var body = "";
            if (path.EndsWith("/branches/main", StringComparison.Ordinal))
            {
                HeadReads++;
                var sha = MutateHead && HeadReads >= 2
                    ? "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" : Head;
                body = JsonSerializer.Serialize(new
                {
                    @protected = Protected,
                    commit = new { sha }
                });
            }
            else if (path.EndsWith("/commits/" + Head, StringComparison.Ordinal))
            {
                body = JsonSerializer.Serialize(new
                {
                    sha = Head,
                    committer = new { login = Signed ? "web-flow" : "attacker" },
                    commit = new
                    {
                        verification = new { verified = Signed, reason = Signed ? "valid" : "unsigned" },
                        committer = new { email = "noreply@github.com" }
                    }
                });
            }
            else if (path.Contains("/actions/workflows/validate.yml/runs", StringComparison.Ordinal))
            {
                body = JsonSerializer.Serialize(new
                {
                    workflow_runs = new[]
                    {
                        new { head_sha = Head, head_branch = "main", @event = "push",
                            status = "completed", conclusion = CiSuccess ? "success" : "failure",
                            run_attempt = 1 }
                    }
                });
            }
            else if (path.StartsWith("/repos/pgextwin/", StringComparison.Ordinal) &&
                !path.StartsWith("/repos/pgextwin/catalog/", StringComparison.Ordinal))
            {
                var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
                var extension = parts[2];
                if (parts.Length == 3)
                    body = JsonSerializer.Serialize(new { id = 4242, full_name = "pgextwin/" + extension });
                else if (parts.Length == 6 && parts[3] == "releases" &&
                         parts[4] == "tags" && parts[5] == "v1")
                {
                    var assets = new List<object>();
                    long assetId = 100;
                    foreach (var major in new[] { "14", "15", "16", "17", "18" })
                    {
                        var asset = extension + "-v1-pg" + major + "-windows-x64.zip";
                        assets.Add(new
                        {
                            id = ++assetId,
                            name = asset,
                            state = "uploaded",
                            browser_download_url = "https://github.com/pgextwin/" + extension +
                                "/releases/download/v1/" + asset,
                            digest = "sha256:" + new string(WrongReleaseDigest ? 'b' : 'a', 64)
                        });
                    }
                    assets.Add(new
                    {
                        id = ++assetId,
                        name = "SHA256SUMS.txt",
                        state = "uploaded",
                        browser_download_url = "https://github.com/pgextwin/" + extension +
                            "/releases/download/v1/SHA256SUMS.txt",
                        digest = "sha256:" + new string('c', 64)
                    });
                    body = JsonSerializer.Serialize(new
                    {
                        id = 5678,
                        tag_name = "v1",
                        draft = DraftRelease,
                        published_at = "2026-10-19T00:00:00Z",
                        assets
                    });
                }
                else
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            }
            else if (path.EndsWith("/index.json", StringComparison.Ordinal))
            {
                body = JsonSerializer.Serialize(new { schemaVersion = 2, extensions = Names });
            }
            else
            {
                var name = Path.GetFileNameWithoutExtension(path);
                if (!Names.Contains(name, StringComparer.Ordinal))
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
                var pg = new Dictionary<string, object>();
                foreach (var major in new[] { "14", "15", "16", "17", "18" })
                    pg.Add(major, new
                    {
                        available = true,
                        asset = name + "-v1-pg" + major + "-windows-x64.zip",
                        downloadUrl = "https://github.com/pgextwin/" + name +
                            "/releases/download/v1/" + name + "-v1-pg" + major + "-windows-x64.zip",
                        sha256 = new string('a', 64)
                    });
                body = JsonSerializer.Serialize(new
                {
                    schemaVersion = 2,
                    name = BadRecord ? "not_" + name : name,
                    displayName = name,
                    description = "synthetic",
                    repository = "pgextwin/" + name,
                    architecture = "x64",
                    latest = new { releaseTag = "v1" },
                    upstream = new { version = "1.0" },
                    postgresql = pg
                });
            }
            return Task.FromResult(new HttpResponseMessage(
                RateLimit ? HttpStatusCode.Forbidden : HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            });
        }
    }

    public static async Task RunAsync(Action<bool, string> check)
    {
        var parent = Path.Combine(Path.GetTempPath(), "pgextwin-latest-contract-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(parent);
        try
        {
            using (var fixture = new FixtureHandler())
            {
                using var session = await AuthenticatedCatalogHead.AcquireAsync(parent, fixture);
                check(session.Commit == Head, "latest immutable commit selected");
                check(File.Exists(Path.Combine(session.CatalogPath, "extensions", "pg_cron.json")),
                    "exact immutable Catalog record fetched");
                check(fixture.HeadReads == 2, "latest head verified before and after");
                var latest = await AuthenticatedLatestReleasePins.ResolveAsync(session, "all", fixture);
                check(latest.Count == 70, "latest 14x5 release asset mapping");
                check(latest.All(x => x.CatalogCommit == Head && x.RepositoryId == 4242
                                    && x.ReleaseId == 5678 && x.AssetSha256 == new string('a', 64)),
                    "latest immutable Catalog and live numeric IDs bound to 70 ZIPs");
                fixture.WrongReleaseDigest = true;
                var hashDenied = false;
                try { await AuthenticatedLatestReleasePins.ResolveAsync(session, "18", fixture); }
                catch (InvalidDataException) { hashDenied = true; }
                check(hashDenied, "Catalog/public Release digest mismatch fails closed");
                fixture.WrongReleaseDigest = false;
                fixture.DraftRelease = true;
                var draftDenied = false;
                try { await AuthenticatedLatestReleasePins.ResolveAsync(session, "18", fixture); }
                catch (InvalidDataException) { draftDenied = true; }
                check(draftDenied, "draft unpublished Release fails closed");
            }
            check(Directory.GetFileSystemEntries(parent).Length == 0,
                "latest verified snapshot disposed without leftovers");
            foreach (var fault in new[] { "branch", "signature", "ci", "race", "record", "403" })
            {
                using var fixture = new FixtureHandler
                {
                    Protected = fault != "branch",
                    Signed = fault != "signature",
                    CiSuccess = fault != "ci",
                    MutateHead = fault == "race",
                    BadRecord = fault == "record",
                    RateLimit = fault == "403"
                };
                var denied = false;
                try
                {
                    using var result = await AuthenticatedCatalogHead.AcquireAsync(parent, fixture);
                }
                catch (Exception e) when (e is InvalidDataException or HttpRequestException)
                { denied = true; }
                check(denied, "latest fail-closed: " + fault);
                check(Directory.GetFileSystemEntries(parent).Length == 0,
                    "latest staging cleaned: " + fault);
            }
        }
        finally { Directory.Delete(parent, recursive: true); }
    }
}
