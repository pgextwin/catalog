using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using PgExtWin.Releases;

internal static class SignedPublicCatalogFeedTests
{
    private static readonly string[] Required = ["15", "16", "17", "18"];
    private static readonly string[] Names = ["hypopg", "pg_ivm", "wal2json"];

    public static async Task RunAsync(Action<bool, string> check)
    {
        var catalog = Path.Combine(Path.GetTempPath(), "pgextwin-feed-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(catalog, "extensions"));
        try
        {
            var feed = new JsonObject
            {
                ["schemaVersion"] = "pgextwin-signed-catalog-zip-feed/v1",
                ["catalogCommit"] = new string('a', 40),
                ["extensionCount"] = Names.Length,
                ["postgresqlMajors"] = JsonSerializer.SerializeToNode(Required),
                ["zipCount"] = Names.Length * Required.Length,
                ["releases"] = new JsonArray()
            };
            File.WriteAllText(Path.Combine(catalog, "index.json"),
                JsonSerializer.Serialize(new { schemaVersion = 2, extensions = Names }));
            var records = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
            var releases = feed["releases"]!.AsArray();
            foreach (var name in Names)
            {
                var matrix = new JsonObject();
                var packages = new JsonArray();
                foreach (var major in new[] { "14" }.Concat(Required))
                {
                    var pin = Package(name, major);
                    matrix[major] = new JsonObject
                    {
                        ["available"] = true,
                        ["asset"] = pin["asset"]!.DeepClone(),
                        ["sha256"] = pin["sha256"]!.DeepClone(),
                        ["downloadUrl"] = pin["downloadUrl"]!.DeepClone()
                    };
                    if (major != "14") packages.Add(pin);
                }
                records.Add(name, matrix);
                WriteRecord(name);
                releases.Add(new JsonObject
                {
                    ["extension"] = name, ["releaseTag"] = "v1",
                    ["repositoryId"] = 1L, ["releaseId"] = 2L, ["checksumsAssetId"] = 3L,
                    ["packages"] = packages
                });
            }

            async Task<IReadOnlyList<ReleasePins>> Select(string major)
            {
                var root = JsonSerializer.SerializeToElement(feed);
                var cohort = SignedPublicCatalogFeed.ReadFeedCohort(root);
                return await SignedPublicCatalogFeed.SelectPinsAsync(root, catalog, cohort, major);
            }
            async Task Reject(string description)
            {
                var denied = false;
                try { await Select("15"); }
                catch (InvalidDataException) { denied = true; }
                check(denied, description);
            }
            void WriteRecord(string name) => File.WriteAllText(
                Path.Combine(catalog, "extensions", name + ".json"),
                JsonSerializer.Serialize(new
                {
                    schemaVersion = 2, name, repository = "pgextwin/" + name, architecture = "x64",
                    latest = new { releaseTag = "v1" }, upstream = new { version = "1" },
                    postgresql = records[name]
                }));

            var baseline = await Select("all");
            check(baseline.Count == 12 && baseline.All(pin => pin.PgMajor != "14"),
                "signed v1 cohort retains its required-only selection");

            var pg19 = Package("wal2json", "19");
            records["wal2json"]["19"] = new JsonObject
            {
                ["available"] = true,
                ["asset"] = pg19["asset"]!.DeepClone(),
                ["sha256"] = pg19["sha256"]!.DeepClone(),
                ["downloadUrl"] = pg19["downloadUrl"]!.DeepClone()
            };
            records["hypopg"]["19"] = new JsonObject { ["available"] = false };
            WriteRecord("wal2json");
            WriteRecord("hypopg");
            var ready = releases[2]!["packages"]!.AsArray();
            ready.Add(pg19);
            feed["schemaVersion"] = "pgextwin-signed-catalog-zip-feed/v2";
            feed["optionalPostgresqlMajor"] = "19";
            feed["zipCount"] = 13;

            var all = await Select("all");
            check(all.Where(pin => pin.PgMajor != "19").Select(Identity).SequenceEqual(baseline.Select(Identity)),
                "signed v2 keeps all original required-major pins in order");
            var optional = await Select("19");
            check(optional.Count == 1 && optional[0].Extension == "wal2json" && optional[0].PgMajor == "19",
                "signed PG19 selection contains only the available extension");
            check((await Select("18")).Count == Names.Length,
                "signed PG18 selection retains complete coverage");
            await CheckCliListAsync(catalog, check);

            var missing = ready[0]!;
            ready.RemoveAt(0);
            await Reject("signed v2 feed rejects a missing required package row");
            ready.Insert(0, missing);

            var pg15 = records["wal2json"]["15"]!;
            records["wal2json"]["15"] = new JsonObject { ["available"] = false };
            WriteRecord("wal2json");
            await Reject("signed v2 feed rejects unavailable required Catalog major");
            records["wal2json"]["15"] = pg15;
            WriteRecord("wal2json");

            ready.RemoveAt(ready.Count - 1);
            await Reject("signed v2 feed rejects omission of an available PG19 row even for a PG15 request");
            ready.Add(pg19);
            var unavailable = releases[0]!["packages"]!.AsArray();
            unavailable.Add(Package("hypopg", "19"));
            await Reject("signed v2 feed rejects package for unavailable PG19");
            unavailable.RemoveAt(unavailable.Count - 1);

            feed["zipCount"] = 14;
            await Reject("signed v2 feed rejects incorrect ZIP total within the allowed range");
            feed["zipCount"] = 13;
            pg19["sha256"] = new string('c', 64);
            await Reject("signed PG19 ZIP digest is checked even for a PG15 request");
        }
        finally { Directory.Delete(catalog, recursive: true); }
    }

    private static (string, string, string, string, string, long) Identity(ReleasePins pin) =>
        (pin.Extension, pin.PgMajor, pin.Tag, pin.AssetName, pin.AssetSha256, pin.AssetIds[pin.AssetName]);

    private static JsonObject Package(string name, string major)
    {
        var asset = name + "-v1-pg" + major + "-windows-x64.zip";
        return new JsonObject
        {
            ["pgMajor"] = major, ["asset"] = asset, ["sha256"] = new string('b', 64),
            ["downloadUrl"] = "https://github.com/pgextwin/" + name + "/releases/download/v1/" + asset,
            ["assetId"] = 10L + int.Parse(major)
        };
    }

    private static async Task CheckCliListAsync(string catalog, Action<bool, string> check)
    {
        var info = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet")
        {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true
        };
        foreach (var arg in new[] { Path.Combine(AppContext.BaseDirectory, "pgextwin.dll"),
                     "list", "--catalog-dir", catalog, "--pg", "19", "--format", "json" })
            info.ArgumentList.Add(arg);
        using var cli = Process.Start(info) ?? throw new InvalidOperationException("CLI process did not start");
        var stdout = cli.StandardOutput.ReadToEndAsync();
        var stderr = cli.StandardError.ReadToEndAsync();
        await cli.WaitForExitAsync();
        check(cli.ExitCode == 0, "CLI lists available PG19 metadata: " + await stderr);
        using var result = JsonDocument.Parse(await stdout);
        var rows = result.RootElement.GetProperty("records").EnumerateArray().ToArray();
        check(rows.Length == 1 && rows[0].GetProperty("extension").GetString() == "wal2json",
            "CLI PG19 listing omits absent and explicitly unavailable rows");
    }
}
