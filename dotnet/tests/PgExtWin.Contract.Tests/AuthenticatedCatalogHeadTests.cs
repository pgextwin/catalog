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
        public bool BadIdentity = false;
        public bool ResearchOnlyIdentity = false;
        public bool RateLimit = false;
        public bool WrongReleaseDigest = false;
        public bool DraftRelease = false;
        public int HeadReads = 0;
        public int WaveThreeCount = 0;
        public bool DropHistorical = false;
        public bool AddUnknown = false;
        public bool InvalidName = false;
        public string[]? RosterOverride;
        public string[] Majors = ["14", "15", "16", "17", "18"];
        public bool OptionalPg19;
        public List<string> RequestedRawPaths = [];
        private static readonly string[] Wave3 = ["pgtap", "pg_variables", "pg_store_plans"];
        private string[] Inventory => RosterOverride ?? Names
            .Concat(Wave3.Take(WaveThreeCount))
            .Where(n => !DropHistorical || n != "hypopg")
            .Concat(AddUnknown ? ["future_registered"] : Array.Empty<string>())
            .Concat(InvalidName ? ["../bad"] : Array.Empty<string>())
            .Order(StringComparer.Ordinal).ToArray();
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
            if (req.RequestUri.Host == "raw.githubusercontent.com")
                RequestedRawPaths.Add(path);
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
            else if (path == "/pgextwin/catalog/" + Head + "/config/cli-feed-majors.json")
            {
                body = OptionalPg19
                    ? JsonSerializer.Serialize(new
                        { schemaVersion = 1, postgresqlMajors = Majors, optionalPostgresqlMajor = "19" })
                    : JsonSerializer.Serialize(new { schemaVersion = 1, postgresqlMajors = Majors });
            }
            else if (path == "/pgextwin/catalog/" + Head + "/identities/index.candidate.json")
            {
                var identityEntries = Inventory
                    .Distinct(StringComparer.Ordinal)
                    .Select(n => (object)new
                    {
                        name = n,
                        path = "identities/" + n + ".json",
                        intakeClass = "distributed",
                        ledgerPath = "packages/" + n + ".json"
                    })
                    .ToList();
                if (RosterOverride is null)
                {
                    identityEntries.Add(new
                    {
                        name = "postgis",
                        path = "identities/postgis.json",
                        intakeClass = "research-only"
                    });
                }
                body = JsonSerializer.Serialize(new
                {
                    schemaVersion = 3,
                    identitiesDir = "identities",
                    packagesDir = "packages",
                    extensions = Inventory,
                    identities = identityEntries
                });
            }
            else if (path.StartsWith("/pgextwin/catalog/" + Head + "/identities/", StringComparison.Ordinal))
            {
                var name = Path.GetFileNameWithoutExtension(path);
                if (!Inventory.Contains(name, StringComparer.Ordinal))
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
                var identityName = BadIdentity ? "not_" + name : name;
                body = ResearchOnlyIdentity
                    ? JsonSerializer.Serialize(new
                    {
                        schemaVersion = 1,
                        name = identityName,
                        upstreamRepository = "example/" + name,
                        description = "synthetic",
                        intake = new
                        {
                            @class = "research-only",
                            distributionAllowed = false
                        }
                    })
                    : JsonSerializer.Serialize(new
                    {
                        schemaVersion = 1,
                        name = identityName,
                        upstreamRepository = "example/" + name,
                        description = "synthetic",
                        intake = new
                        {
                            @class = "distributed",
                            distributionAllowed = true,
                            registrationSource = "historical-core",
                            expectedUpstreamRepository = "example/" + name,
                            sealedUpstream = true
                        },
                        distribution = new
                        {
                            repository = "pgextwin/" + name,
                            license = "PostgreSQL",
                            ledgerPath = "packages/" + name + ".json"
                        }
                    });
            }
            else if (path.StartsWith("/pgextwin/catalog/" + Head + "/packages/", StringComparison.Ordinal))
            {
                var name = Path.GetFileNameWithoutExtension(path);
                if (!Inventory.Contains(name, StringComparer.Ordinal))
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
                string[] recordMajors = OptionalPg19 && name == "wal2json"
                    ? ["14", "15", "16", "17", "18", "19"] : ["14", "15", "16", "17", "18"];
                var packages = recordMajors.Select(major => new
                {
                    pgMajor = major,
                    version = "1.0",
                    asset = name + "-v1-pg" + major + "-windows-x64.zip",
                    assetId = 100L + long.Parse(major),
                    sha256 = new string('a', 64),
                    license = new
                    {
                        name = "PostgreSQL",
                        evidenceUrls = new[] { "https://github.com/pgextwin/" + name + "/blob/main/LICENSE" }
                    }
                }).ToArray();
                body = JsonSerializer.Serialize(new
                {
                    schemaVersion = 1,
                    name = BadRecord ? "not_" + name : name,
                    displayName = name,
                    description = "synthetic",
                    repository = "pgextwin/" + name,
                    license = "PostgreSQL",
                    architecture = "x64",
                    upstream = new { repository = "example/" + name },
                    repositoryId = 4242L,
                    latestReleaseId = 5678L,
                    unavailableMajors = Array.Empty<string>(),
                    releases = new[]
                    {
                        new
                        {
                            releaseTag = "v1",
                            releaseId = 5678L,
                            publishedAt = "2026-10-19T00:00:00Z",
                            checksumsAsset = "SHA256SUMS.txt",
                            packages
                        }
                    }
                });
            }
            else
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
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
        check(AuthenticatedCatalogHead.IsApprovedCatalogUri(
                new Uri($"https://raw.githubusercontent.com/pgextwin/catalog/{Head}/config/cli-feed-majors.json")),
            "raw allowlist permits config/cli-feed-majors.json");
        check(AuthenticatedCatalogHead.IsApprovedCatalogUri(
                new Uri($"https://raw.githubusercontent.com/pgextwin/catalog/{Head}/identities/index.candidate.json")),
            "raw allowlist permits identities/index.candidate.json");
        check(AuthenticatedCatalogHead.IsApprovedCatalogUri(
                new Uri($"https://raw.githubusercontent.com/pgextwin/catalog/{Head}/identities/pg_cron.json")),
            "raw allowlist permits identities/<name>.json");
        check(AuthenticatedCatalogHead.IsApprovedCatalogUri(
                new Uri($"https://raw.githubusercontent.com/pgextwin/catalog/{Head}/packages/pg_cron.json")),
            "raw allowlist permits packages/<name>.json");
        foreach (var deniedRaw in new[]
        {
            $"https://raw.githubusercontent.com/pgextwin/catalog/{Head}/index.json",
            $"https://raw.githubusercontent.com/pgextwin/catalog/{Head}/extensions/pg_cron.json",
            $"https://raw.githubusercontent.com/pgextwin/catalog/{Head}/packages/index.candidate.json",
            $"https://raw.githubusercontent.com/pgextwin/catalog/{Head}/landscape/index.json",
            "https://raw.githubusercontent.com/pgextwin/catalog/main/identities/index.candidate.json",
            $"http://raw.githubusercontent.com/pgextwin/catalog/{Head}/packages/pg_cron.json",
            $"https://raw.githubusercontent.com/pgextwin/catalog/{Head}/identities/../secrets.json"
        })
        {
            check(!AuthenticatedCatalogHead.IsApprovedCatalogUri(new Uri(deniedRaw)),
                "raw allowlist denies disallowed URL: " + deniedRaw);
        }

        var parent = Path.Combine(Path.GetTempPath(), "pgextwin-latest-contract-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(parent);
        try
        {
            using (var fixture = new FixtureHandler())
            {
                using var session = await AuthenticatedCatalogHead.AcquireAsync(parent, fixture);
                check(session.Commit == Head, "latest immutable commit selected");
                check(File.Exists(Path.Combine(session.CatalogPath, "config", "cli-feed-majors.json")),
                    "exact immutable feed cohort fetched");
                check(File.Exists(Path.Combine(session.CatalogPath, "identities", "index.candidate.json")),
                    "exact immutable candidate index fetched");
                check(File.Exists(Path.Combine(session.CatalogPath, "identities", "pg_cron.json")),
                    "exact immutable Catalog identity fetched");
                check(File.Exists(Path.Combine(session.CatalogPath, "packages", "pg_cron.json")),
                    "exact immutable Catalog package ledger fetched");
                check(!Directory.Exists(Path.Combine(session.CatalogPath, "extensions")) &&
                      !File.Exists(Path.Combine(session.CatalogPath, "index.json")),
                    "authenticated head session excludes legacy v2 files");
                check(fixture.RequestedRawPaths.All(p =>
                    !p.EndsWith("/index.json", StringComparison.Ordinal) &&
                    !p.Contains("/extensions/", StringComparison.Ordinal)),
                    "authenticated head fetches only new-format raw paths");
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
            // The EOL Catalog retains historical PG14 in each immutable record,
            // but post-EOL approved selections include only PG15-18.
            using (var postEol = new FixtureHandler { Majors = ["15", "16", "17", "18"] })
            {
                using var session = await AuthenticatedCatalogHead.AcquireAsync(parent, postEol);
                check(session.ApprovedMajors.SequenceEqual(new[] { "15", "16", "17", "18" }),
                    "protected approved PG cohort is sourced from immutable config");
                var plan = await AuthenticatedLatestReleasePins.ResolveAsync(session, "all", postEol);
                check(plan.Count == 56 && plan.All(x => x.PgMajor != "14"),
                    "PG14 remains in Catalog but is excluded from latest ZIP selection");
                var denied = false;
                try { await AuthenticatedLatestReleasePins.ResolveAsync(session, "14", postEol); }
                catch (InvalidDataException) { denied = true; }
                check(denied, "Post-EOL PG14 latest selection fails closed");
            }
            using (var malformed = new FixtureHandler { Majors = ["15", "17", "18"] })
            {
                var denied = false;
                try { using var session = await AuthenticatedCatalogHead.AcquireAsync(parent, malformed); }
                catch (InvalidDataException) { denied = true; }
                check(denied, "noncontiguous approved cohort fails closed");
            }
            using (var optional = new FixtureHandler { Majors = ["15", "16", "17", "18"], OptionalPg19 = true })
            {
                using var snapshot = await AuthenticatedCatalogHead.AcquireAsync(parent, optional);
                var plan = await AuthenticatedLatestReleasePins.ResolveAsync(snapshot, "all", optional);
                check(plan.Count == 56 && plan.All(pin => pin.PgMajor is not ("14" or "19")),
                    "authenticated HEAD admits optional Catalog rows while its legacy resolver keeps the required cohort");
            }

            // All synthetic: the live Catalog still indexes only 14 signed public Releases.
            for (var extra = 1; extra <= 3; extra++)
            {
                using var expanding = new FixtureHandler { WaveThreeCount = extra };
                using var staged = await AuthenticatedCatalogHead.AcquireAsync(parent, expanding);
                var rows = await AuthenticatedLatestReleasePins.ResolveAsync(staged, "all", expanding);
                check(rows.Count == (14 + extra) * 5,
                    "staged authenticated Catalog accepts only exact 14+" + extra + " ZIP cohort");
                check(rows.Count(x => x.Extension == "pgtap") == 5,
                    "staged candidate name has exact PG14-18 public-Release metadata fixture");
            }
            // Future identities are authenticated by the protected Catalog main,
            // not forbidden just because the CLI binary predates them.
            using (var registered = new FixtureHandler { WaveThreeCount = 3, AddUnknown = true })
            {
                using var staged = await AuthenticatedCatalogHead.AcquireAsync(parent, registered);
                var rows = await AuthenticatedLatestReleasePins.ResolveAsync(staged, "all", registered);
                check(rows.Count == 90 && rows.Count(x => x.Extension == "future_registered") == 5,
                    "protected Catalog index authorizes an 18th entry");
            }
            // A protected roster may retire old members. Resolve every selected
            // name against that same authenticated snapshot and its Release bytes.
            using (var retired = new FixtureHandler { DropHistorical = true })
            {
                using var staged = await AuthenticatedCatalogHead.AcquireAsync(parent, retired);
                var rows = await AuthenticatedLatestReleasePins.ResolveAsync(staged, "all", retired);
                check(rows.Count == 13 * 5 && rows.All(x => x.Extension != "hypopg"),
                    "retired historical member does not block exact authenticated roster");
            }
            foreach (var roster in new[]
            {
                new[] { "pg_cron" },
                Enumerable.Range(0, 128).Select(i => "extension_" + i.ToString("D3")).ToArray(),
                new[] { new string('x', 64) }
            })
            {
                using var authorized = new FixtureHandler { RosterOverride = roster };
                using var staged = await AuthenticatedCatalogHead.AcquireAsync(parent, authorized);
                var rows = await AuthenticatedLatestReleasePins.ResolveAsync(staged, "18", authorized);
                check(rows.Select(x => x.Extension).SequenceEqual(roster) &&
                      rows.All(x => x.CatalogCommit == Head && x.PgMajor == "18"),
                    "exact authenticated roster accepted at count/name boundary " + roster.Length);
            }
            foreach (var roster in new[]
            {
                Array.Empty<string>(),
                Enumerable.Range(0, 129).Select(i => "extension_" + i.ToString("D3")).ToArray(),
                new[] { "../bad" }, new[] { "Upper" }, new[] { new string('x', 65) },
                new[] { "pg_cron", "pg_cron" }, new[] { "wal2json", "pg_cron" }
            })
            {
                using var invalid = new FixtureHandler { RosterOverride = roster };
                var denied = false;
                try { using var staged = await AuthenticatedCatalogHead.AcquireAsync(parent, invalid); }
                catch (InvalidDataException) { denied = true; }
                check(denied, "unsafe, empty, oversized, duplicate or unsorted roster rejected");
            }
            check(Directory.GetFileSystemEntries(parent).Length == 0,
                "latest verified snapshot disposed without leftovers");
            foreach (var fault in new[] { "branch", "signature", "ci", "race", "record", "identity", "research-only", "403" })
            {
                using var fixture = new FixtureHandler
                {
                    Protected = fault != "branch",
                    Signed = fault != "signature",
                    CiSuccess = fault != "ci",
                    MutateHead = fault == "race",
                    BadRecord = fault == "record",
                    BadIdentity = fault == "identity",
                    ResearchOnlyIdentity = fault == "research-only",
                    RateLimit = fault == "403"
                };
                var denied = false;
                Exception? failure = null;
                try
                {
                    using var result = await AuthenticatedCatalogHead.AcquireAsync(parent, fixture);
                }
                catch (Exception e) when (e is InvalidDataException or HttpRequestException)
                { denied = true; failure = e; }
                check(denied, "latest fail-closed: " + fault);
                if (fault == "403")
                    check(failure?.Message.Contains(
                        "TARGET=GITHUB_API PATH=/repos/pgextwin/catalog/branches/main RATE_REMAINING=absent",
                        StringComparison.Ordinal) == true,
                        "anonymous 403 reports allowlisted endpoint and safe rate header without bypass");
                check(Directory.GetFileSystemEntries(parent).Length == 0,
                    "latest staging cleaned: " + fault);
            }
        }
        finally { Directory.Delete(parent, recursive: true); }
    }
}
