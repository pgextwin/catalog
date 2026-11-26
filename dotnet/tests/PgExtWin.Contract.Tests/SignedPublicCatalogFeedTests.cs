using System.Diagnostics;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using PgExtWin.Releases;

internal static class SignedPublicCatalogFeedTests
{
    private static readonly string[] Required = ["15", "16", "17", "18"];
    private static readonly string[] Names = ["hypopg", "pg_ivm", "wal2json"];
    private const string Repo = "https://github.com/pgextwin/catalog/";
    private const string Latest = Repo + "releases/latest/download/";
    private const string Tagged = Repo + "releases/download/";
    private const string Cdn = "https://release-assets.githubusercontent.com/";

    private static readonly string Commit = new('a', 40);
    private const string LatestHypopg = "v1.4.5-windows.2";
    private const string OlderHypopg = "v1.4.4-windows.1";
    private const string CurrentDigest = "540141c9ac9d2fb5b230589e47ef3ee0ac4beba638504083600ec84d21286ab4";
    private const string OldDigest = "12bba2aec37a46b191f63eba624bbe9ddd168baabaf8d622fb8f5f55fdf88ba9";

    public static async Task RunAsync(Action<bool, string> check)
    {
        var extensions = new JsonArray();
        var feed = new JsonObject
        {
            ["schemaVersion"] = "pgextwin-signed-catalog-zip-feed/v3",
            ["catalogCommit"] = Commit,
            ["repository"] = "pgextwin/catalog",
            ["verificationLevel"] = "CATALOG_FEED_SIGNED_CLAIM_ONLY",
            ["extensionSignatureVerified"] = false,
            ["publicationAuthorized"] = false,
            ["installAuthorized"] = false,
            ["postgresqlMajors"] = JsonSerializer.SerializeToNode(Required),
            ["extensions"] = extensions
        };
        foreach (var name in Names)
        {
            var hypopg = name == "hypopg";
            var tag = hypopg ? LatestHypopg : "v1";
            var packages = Required.Select(major => (JsonNode?)Package(name, major,
                hypopg ? "1.4.5" : "1.0",
                hypopg && major == "15" ? 770933732 : 10L + int.Parse(major),
                hypopg && major == "15" ? CurrentDigest : new string('b', 64),
                hypopg ? "62158f77bf1d1f369ca9ad5486833890a7b11003" : Commit)).ToArray();
            var releases = new JsonArray();
            if (hypopg)
                releases.Add(Release(OlderHypopg, 424739121, "edb355a78558aa0e848861de04ba6dd406117b18",
                    [Package(name, "15", "1.4.4", 679393427, OldDigest, "771ef1c84db382d070b22d03c22be142f24c7fee")]));
            releases.Add(Release(tag, hypopg ? 452400206 : 2L, Commit, packages));
            extensions.Add(new JsonObject
            {
                ["extension"] = name, ["repositoryId"] = 1L,
                ["latestReleaseTag"] = tag, ["releases"] = releases
            });
        }

        IReadOnlyList<ReleasePins> Select(string major, string? name = null, string? version = null)
        {
            var root = JsonSerializer.SerializeToElement(feed);
            return SignedPublicCatalogFeed.SelectPins(root, PostgresqlFeedCohort.Parse(root), major, name, version);
        }
        void Reject(string description, string major = "15", string? name = null, string? version = null)
        {
            var denied = false;
            try { Select(major, name, version); }
            catch (InvalidDataException) { denied = true; }
            check(denied, description);
        }

        var baseline = Select("all");
        check(baseline.Count == 12 && baseline.All(pin => pin.PgMajor != "14"),
            "signed v3 bulk uses the required-only latest selection");
        var complete = JsonSerializer.SerializeToUtf8Bytes(feed);
        var latest = Select("15", "HyPoPg").Single();
        var exactLatest = Select("15", "hypopg", "1.4.5").Single();
        var exactOld = Select("15", "hypopg", "1.4.4").Single();
        check(Identity(latest) == ("hypopg", "15", LatestHypopg,
            "hypopg-1.4.5-pg15-windows-x64.zip", CurrentDigest, 770933732), "HypoPG PG15 latest is 1.4.5, asset 770933732");
        check(Identity(latest) == Identity(exactLatest), "HypoPG PG15 exact 1.4.5 selects the same asset");
        check(Identity(exactOld) == ("hypopg", "15", OlderHypopg,
            "hypopg-1.4.4-pg15-windows-x64.zip", OldDigest, 679393427), "HypoPG PG15 exact 1.4.4 selects asset 679393427");
        check(latest.Version == "1.4.5" && exactOld.Version == "1.4.4" &&
              latest.License?.Name == "PostgreSQL" && exactOld.License?.Name == "PostgreSQL" &&
              latest.License.EvidenceUrls.Single() != exactOld.License.EvidenceUrls.Single(),
            "each selected HypoPG version reports its own pinned license evidence");
        Reject("HypoPG PG15 1.4.3 is absent", "15", "hypopg", "1.4.3");
        Reject("HypoPG PG16 does not match PG15 history", "16", "hypopg", "1.4.4");
        Reject("partial version rejects instead of matching a prefix", "15", "hypopg", "1.4");
        Reject("release tag rejects as a version", "15", "hypopg", OlderHypopg);
        check(Identity(Select("15").Single(pin => pin.Extension == "hypopg")) == Identity(latest),
            "download-all PG15 selects exactly one HypoPG package, the latest");
        Console.WriteLine("HYPOPG_V3_PG15 latest=1.4.5/770933732 exact=1.4.5/770933732,1.4.4/679393427 absent=1.4.3 bulk=1.4.5/770933732");

        var wal2jsonRows = extensions[2]!["releases"]![0]!["packages"]!.AsArray();
        var pg19 = Package("wal2json", "19", "1.0", 29, new string('b', 64), Commit);
        wal2jsonRows.Add(pg19);
        feed["optionalPostgresqlMajor"] = "19";
        await CheckFeedFetchAsync(complete, JsonSerializer.SerializeToUtf8Bytes(feed), check);
        check(Select("all").Where(pin => pin.PgMajor != "19").Select(Identity).SequenceEqual(baseline.Select(Identity)),
            "signed v3 retains required-major latest pins when an optional major is added");
        check(Select("19").Single().Extension == "wal2json", "signed PG19 selection uses the latest subset");
        check(Select("18").Count == Names.Length, "signed PG18 selection retains complete coverage");
        await CheckCliAsync(check);

        var missing = wal2jsonRows[0]!;
        wal2jsonRows.RemoveAt(0);
        Reject("signed v3 rejects a missing required latest package");
        wal2jsonRows.Insert(0, missing);
        wal2jsonRows.Remove(pg19);
        Reject("optional PG19 requires a latest row");
        wal2jsonRows.Add(pg19);
        pg19["sha256"] = "invalid";
        Reject("malformed PG19 digest is denied before PG15 selection");
        pg19["sha256"] = new string('b', 64);

        // Consumer-side unknown majors: a package row for a major the
        // signed cohort does not declare, and a request for such a major,
        // are both rejected even though every other field is well-formed.
        var pg20 = Package("wal2json", "20", "1.0", 30, new string('b', 64), Commit);
        wal2jsonRows.Add(pg20);
        Reject("signed v3 consumer rejects a package row for an undeclared PG20 major");
        wal2jsonRows.Remove(pg20);
        Reject("requesting an undeclared PG20 major is denied", "20");

        var hypopgReleases = extensions[0]!["releases"]!.AsArray();
        var latestHypopgRows = hypopgReleases[1]!["packages"]!.AsArray();
        var originalPg16 = latestHypopgRows[1]!;
        latestHypopgRows[1] = Package("hypopg", "16", "1.4.6", 102, CurrentDigest, Commit);
        var priorRevision = Release("v1.4.5-windows.1", 3, new string('c', 40),
            [Package("hypopg", "16", "1.4.5", 101, OldDigest, new string('d', 40))]);
        hypopgReleases.Add(priorRevision);
        var retainedPg16 = Select("16", "hypopg", "1.4.5").Single();
        check(Identity(Select("15", "hypopg", "1.4.5").Single()) == Identity(latest) &&
              Identity(retainedPg16) == ("hypopg", "16", "v1.4.5-windows.1",
                  "hypopg-1.4.5-pg16-windows-x64.zip", OldDigest, 101),
            "same-version reissue replaces PG15 while PG16 still selects the prior revision");
        hypopgReleases.Remove(priorRevision);
        latestHypopgRows[1] = originalPg16;

        var history = hypopgReleases[0]!;
        var historyRow = history["packages"]![0]!;
        historyRow["version"] = "1.4.5";
        Reject("duplicate extension, major and version is denied");
        historyRow["version"] = "1.4.4";
        hypopgReleases.Add(history.DeepClone());
        Reject("duplicate Release tag is denied");
        hypopgReleases.RemoveAt(hypopgReleases.Count - 1);
        hypopgReleases.RemoveAt(0);
        Reject("withdrawn HypoPG 1.4.4 produces a selection error", "15", "hypopg", "1.4.4");
        extensions[0]!["latestReleaseTag"] = OlderHypopg;
        Reject("missing latest pointer target fails closed");

        await CheckZipDigestAsync(exactOld, check);
    }

    private static async Task CheckFeedFetchAsync(byte[] complete, byte[] optional,
        Action<bool, string> check)
    {
        var commit = new string('a', 40);
        var tag = "catalog-feed-" + commit;
        const string stem = "catalog-latest";
        var bundle = "{}"u8.ToArray();

        using var handler = new FeedHandler();
        using var http = new HttpClient(handler);
        // The JSON is resolved through latest/download; the bundle GET is pinned
        // to the exact tag taken from that redirect chain.
        void QueuePair(byte[] feed)
        {
            var asset = stem + ".json";
            var tagged = Tagged + tag + "/" + asset;
            handler.Redirect(Latest + asset, tagged);
            handler.Redirect(tagged, Cdn + asset);
            handler.Bytes(Cdn + asset, feed);
            var bundleAsset = stem + ".sigstore.json";
            var taggedBundle = Tagged + tag + "/" + bundleAsset;
            handler.Redirect(taggedBundle, Cdn + bundleAsset);
            handler.Bytes(Cdn + bundleAsset, bundle);
        }

        QueuePair(optional);
        var fetched = await SignedPublicCatalogFeed.FetchFeedAsync(http);
        using var fetchedJson = JsonDocument.Parse(fetched.Feed);
        var cohort = PostgresqlFeedCohort.Parse(fetchedJson.RootElement);
        check(fetched.Tag == tag && fetched.Feed.SequenceEqual(optional) &&
              fetched.Bundle.SequenceEqual(bundle) && cohort.Optional == "19" && handler.Remaining == 0,
            "signed reader resolves the single latest v3 feed and pins the bundle to its tag");

        QueuePair(complete);
        fetched = await SignedPublicCatalogFeed.FetchFeedAsync(http);
        using var completeJson = JsonDocument.Parse(fetched.Feed);
        var completeCohort = PostgresqlFeedCohort.Parse(completeJson.RootElement);
        check(fetched.Tag == tag && fetched.Feed.SequenceEqual(complete) &&
              fetched.Bundle.SequenceEqual(bundle) && completeCohort.Optional is null && handler.Remaining == 0,
            "signed reader accepts the required-only v2 feed from latest");

        handler.Status(Latest + stem + ".json", HttpStatusCode.NotFound);
        var denied = false;
        try { await SignedPublicCatalogFeed.FetchFeedAsync(http); }
        catch (HttpRequestException) { denied = true; }
        check(denied && handler.Remaining == 0, "missing latest feed fails closed without searching elsewhere");

        var assetOnly = stem + ".json";
        var taggedOnly = Tagged + tag + "/" + assetOnly;
        handler.Redirect(Latest + assetOnly, taggedOnly);
        handler.Redirect(taggedOnly, Cdn + assetOnly);
        handler.Bytes(Cdn + assetOnly, optional);
        handler.Status(Tagged + tag + "/" + stem + ".sigstore.json", HttpStatusCode.NotFound);
        denied = false;
        try { await SignedPublicCatalogFeed.FetchFeedAsync(http); }
        catch (HttpRequestException) { denied = true; }
        check(denied && handler.Remaining == 0, "missing bundle for the pinned tag fails closed");

        var otherTag = "catalog-feed-" + new string('b', 40);
        handler.Redirect(Latest + assetOnly, taggedOnly);
        handler.Redirect(taggedOnly, Cdn + assetOnly);
        handler.Bytes(Cdn + assetOnly, optional);
        var bundleAssetOnly = stem + ".sigstore.json";
        handler.Redirect(Tagged + tag + "/" + bundleAssetOnly, Tagged + otherTag + "/" + bundleAssetOnly);
        denied = false;
        try { await SignedPublicCatalogFeed.FetchFeedAsync(http); }
        catch (InvalidDataException) { denied = true; }
        check(denied && handler.Remaining == 0, "bundle redirect to a different Release tag is rejected");

        var wrongCommit = JsonNode.Parse(optional)!.AsObject();
        wrongCommit["catalogCommit"] = new string('b', 40);
        QueuePair(JsonSerializer.SerializeToUtf8Bytes(wrongCommit));
        denied = false;
        try { await SignedPublicCatalogFeed.AcquireAsync("19", handler: handler); }
        catch (InvalidDataException ex) when (ex.Message.Contains("identity", StringComparison.Ordinal)) { denied = true; }
        check(denied && handler.Remaining == 0, "feed tag must match the claimed Catalog commit");

        var legacySchema = JsonNode.Parse(complete)!.AsObject();
        legacySchema["schemaVersion"] = "pgextwin-signed-catalog-zip-feed/v2";
        QueuePair(JsonSerializer.SerializeToUtf8Bytes(legacySchema));
        denied = false;
        try { await SignedPublicCatalogFeed.AcquireAsync("18", handler: handler); }
        catch (InvalidDataException ex) when (ex.Message.Contains("schema", StringComparison.Ordinal)) { denied = true; }
        check(denied && handler.Remaining == 0, "a v2 feed is rejected");

        QueuePair(optional);
        denied = false;
        try { await SignedPublicCatalogFeed.AcquireAsync("15", "hypopg", "1.4.4", handler); }
        catch (InvalidDataException ex) when (ex.Message.Contains("Sigstore verification failed", StringComparison.Ordinal))
        { denied = true; }
        check(denied && handler.Remaining == 0, "invalid signature bundle fails before version selection");

        // Post-publication tampering: the feed bytes no longer match the
        // bundle that was issued for them. Identity fields and JSON shape
        // stay intact, so only the Sigstore verification over the exact
        // bytes can (and must) reject this before any pin is selected.
        var tamperedFeed = JsonNode.Parse(optional)!.AsObject();
        var tamperedPackage = tamperedFeed["extensions"]![0]!["releases"]![1]!["packages"]![0]!;
        tamperedPackage["sha256"] = new string('e', 64);
        QueuePair(JsonSerializer.SerializeToUtf8Bytes(tamperedFeed));
        denied = false;
        try { await SignedPublicCatalogFeed.AcquireAsync("15", handler: handler); }
        catch (InvalidDataException ex) when (ex.Message.Contains("Sigstore verification failed", StringComparison.Ordinal))
        { denied = true; }
        check(denied && handler.Remaining == 0, "tampered published feed bytes fail Sigstore verification before selection");

    }

    private sealed class FeedHandler : HttpMessageHandler
    {
        private readonly Queue<(Uri Request, HttpResponseMessage Response)> exchanges = new();
        internal int Remaining => exchanges.Count;

        internal void Status(string url, HttpStatusCode status) =>
            exchanges.Enqueue((new Uri(url), new HttpResponseMessage(status)));

        internal void Redirect(string url, string target) =>
            exchanges.Enqueue((new Uri(url), new HttpResponseMessage(HttpStatusCode.Redirect)
                { Headers = { Location = new Uri(target) } }));

        internal void Bytes(string url, byte[] bytes) =>
            exchanges.Enqueue((new Uri(url), new HttpResponseMessage(HttpStatusCode.OK)
                { Content = new ByteArrayContent(bytes) }));

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            if (!exchanges.TryDequeue(out var exchange) || request.Method != HttpMethod.Get ||
                request.RequestUri != exchange.Request)
                throw new InvalidOperationException("Unexpected signed feed GET " + request.RequestUri);
            return Task.FromResult(exchange.Response);
        }
    }

    private static (string, string, string, string, string, long) Identity(ReleasePins pin) =>
        (pin.Extension, pin.PgMajor, pin.Tag, pin.AssetName, pin.AssetSha256, pin.AssetIds[pin.AssetName]);

    private static JsonObject Release(string tag, long id, string admission, JsonNode?[] packages) => new()
    {
        ["releaseTag"] = tag, ["releaseId"] = id,
        ["admission"] = new JsonObject { ["catalogCommit"] = admission },
        ["packages"] = new JsonArray(packages)
    };

    private static JsonObject Package(string name, string major, string version, long id, string sha, string source) => new()
    {
        ["pgMajor"] = major, ["version"] = version,
        ["asset"] = name + "-" + version + "-pg" + major + "-windows-x64.zip",
        ["sha256"] = sha, ["assetId"] = id,
        ["license"] = new JsonObject
        {
            ["name"] = "PostgreSQL",
            ["evidenceUrls"] = new JsonArray($"https://github.com/pgextwin/{name}/blob/{source}/LICENSE")
        }
    };

    private static async Task CheckZipDigestAsync(ReleasePins pin, Action<bool, string> check)
    {
        var output = Directory.CreateTempSubdirectory("pgextwin-feed-");
        try
        {
            using var handler = new FeedHandler();
            var browserUrl = $"https://github.com/pgextwin/{pin.Extension}/releases/download/{pin.Tag}/{pin.AssetName}";
            handler.Redirect(browserUrl, Cdn + pin.AssetName);
            handler.Bytes(Cdn + pin.AssetName, [0x50, 0x4b, 0x03, 0x04, 0x00]);
            using var browser = new PinnedBrowserDownloader(handler);
            var denied = false;
            try { await browser.DownloadAsync(pin, output.FullName); }
            catch (InvalidDataException ex) when (ex.Message.Contains("SHA256", StringComparison.Ordinal))
            { denied = true; }
            check(denied && handler.Remaining == 0 && !output.EnumerateFileSystemInfos().Any(),
                "historical ZIP digest mismatch leaves no output and never selects a fallback");
        }
        finally { output.Delete(recursive: true); }
    }

    private static async Task CheckCliAsync(Action<bool, string> check)
    {
        var version = await InvokeCliAsync("--version");
        check(version.ExitCode == 0 && version.Output.Trim() == "0.6.0", "CLI reports 0.6.0");
        var help = await InvokeCliAsync("download", "--help");
        check(help.ExitCode == 0 && help.Error.Contains("--source pgextwin --pg MAJOR [--version EXACT]", StringComparison.Ordinal),
            "named internal help documents exact download");
        var bulk = await InvokeCliAsync("download-all", "--pg", "15", "--version", "1.4.4");
        check(bulk.ExitCode == 2 && bulk.Error.Contains("--version requires download ITEM --source pgextwin"),
            "internal bulk exact version is an input error before network");
        var fixedMode = await InvokeCliAsync("download-all", "--fixed", "--pg", "14");
        check(fixedMode.ExitCode == 2 && fixedMode.Error.Contains("Unknown option: --fixed"),
            "fixed PG14 retrieval is no longer accepted");
        var local = await InvokeCliAsync("download", "hypopg", "--source", "pgextwin", "--pg", "15",
            "--catalog-dir", ".", "--policy", "policy.json", "--policy-sha256", new string('a', 64));
        check(local.ExitCode == 2 && local.Error.Contains("Unexpected/duplicate --catalog-dir"),
            "download refuses local catalog policy options");
        var legacyExternal = await InvokeCliAsync("download-all", "--source", "external",
            "--extension", "postgis", "--pg", "15");
        check(legacyExternal.ExitCode == 2 && legacyExternal.Error.Contains("Unknown option: --extension"),
            "external item selection requires download ITEM");
        var all = await InvokeCliAsync("download", "hypopg", "--source", "pgextwin", "--pg", "all", "--version", "1.4.4");
        check(all.ExitCode == 2 && all.Error.Contains("download requires --pg MAJOR"),
            "internal named exact selection requires one major");

        var catalog = Directory.CreateTempSubdirectory("pgextwin-feed-list-");
        try
        {
            Directory.CreateDirectory(Path.Combine(catalog.FullName, "extensions"));
            File.WriteAllText(Path.Combine(catalog.FullName, "index.json"),
                JsonSerializer.Serialize(new { schemaVersion = 2, extensions = Names }));
            foreach (var name in Names)
            {
                object? row = name switch
                {
                    "wal2json" => new { available = true, asset = "wal2json-1.0-pg19-windows-x64.zip",
                        sha256 = new string('b', 64), downloadUrl =
                        "https://github.com/pgextwin/wal2json/releases/download/v1/wal2json-1.0-pg19-windows-x64.zip" },
                    "hypopg" => new { available = false },
                    _ => null
                };
                var pg = new Dictionary<string, object> { ["18"] = new { available = false } };
                if (row is not null) pg["19"] = row;
                File.WriteAllText(Path.Combine(catalog.FullName, "extensions", name + ".json"), JsonSerializer.Serialize(new
                {
                    schemaVersion = 2, name, repository = "pgextwin/" + name, architecture = "x64",
                    latest = new { releaseTag = "v1" }, upstream = new { version = "1.0" }, postgresql = pg
                }));
            }
            var listing = await InvokeCliAsync("list", "--catalog-dir", catalog.FullName, "--pg", "19", "--format", "json");
            check(listing.ExitCode == 0, "CLI lists available PG19 metadata: " + listing.Error);
            using var result = JsonDocument.Parse(listing.Output);
            var rows = result.RootElement.GetProperty("records").EnumerateArray().ToArray();
            check(rows.Length == 1 && rows[0].GetProperty("extension").GetString() == "wal2json",
                "CLI PG19 listing omits absent and explicitly unavailable rows");
        }
        finally { catalog.Delete(recursive: true); }
    }

    private static async Task<(int ExitCode, string Output, string Error)> InvokeCliAsync(params string[] args)
    {
        var info = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet")
        {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true
        };
        info.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "pgextwin.dll"));
        foreach (var arg in args) info.ArgumentList.Add(arg);
        using var cli = Process.Start(info) ?? throw new InvalidOperationException("CLI process did not start");
        var stdout = cli.StandardOutput.ReadToEndAsync();
        var stderr = cli.StandardError.ReadToEndAsync();
        await cli.WaitForExitAsync();
        return (cli.ExitCode, await stdout, await stderr);
    }
}
