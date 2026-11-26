using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using PgExtWin.Releases;

internal static class StandaloneDownloadTests
{
    private const string RawCatalog = "https://raw.githubusercontent.com/pgextwin/catalog/main/external/";
    private const string Driver = "https://ftp.postgresql.org/example-driver.zip";
    private const string Tool = "https://github.com/example/tool/releases/download/v1/tool.zip";
    private const string ToolCdn = "https://release-assets.githubusercontent.com/tool.zip";
    private const string Spatial = "https://ftp.postgresql.org/postgis-setup.exe";
    private static readonly byte[] Original = [0x4d, 0x5a, 0x01, 0x02, 0x00];

    private static byte[] Manifest(bool includeLicense)
    {
        var sha256 = Convert.ToHexStringLower(SHA256.HashData(Original));
        object Row(string name, string category, string? pg, string url,
            string version, bool latest = true, string? pgroutingVersion = null) => new
        {
            item = name,
            category,
            pgMajor = pg,
            upstreamVersion = version,
            pgroutingVersion,
            assetName = url.Split('/')[^1],
            originalBytes = Original.Length,
            originalSha256 = sha256,
            originalProviderUrl = url,
            license = "Synthetic test license",
            latest,
            licenseEvidence = includeLicense ? new[]
            {
                new { url = "https://example.invalid/releases/v1/LICENSE", file = "LICENSE", sha256 }
            } : []
        };
        return JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = "pgextwin-standalone-get/v1",
            records = new[]
            {
                Row("postgis", "spatial", "14", Spatial, "3.6.2", pgroutingVersion: "4.0.1"),
                Row("pgbouncer", "tools", null, Tool, "1.0"),
                Row("psqlodbc", "drivers", null, Driver, "13.02.0000"),
                Row("psqlodbc", "drivers", null, Driver, "12.0", latest: false)
            }
        });
    }

    private static byte[] MultiArchManifest(bool duplicateAsset = false)
    {
        var sha256 = Convert.ToHexStringLower(SHA256.HashData(Original));
        object Row(string asset) => new
        {
            item = "psqlodbc",
            category = "drivers",
            pgMajor = (string?)null,
            upstreamVersion = "18.00.0006",
            assetName = asset,
            originalBytes = Original.Length,
            originalSha256 = sha256,
            originalProviderUrl =
                "https://github.com/postgresql-interfaces/psqlodbc/releases/download/REL-18_00_0006/" + asset,
            license = "Synthetic test license",
            latest = true,
            licenseEvidence = new[]
            {
                new { url = "https://example.invalid/releases/v1/LICENSE", file = "LICENSE", sha256 }
            }
        };
        return JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = "pgextwin-standalone-get/v1",
            records = duplicateAsset
                ? new[] { Row("psqlodbc_x64.msi"), Row("psqlodbc_x64.msi") }
                : new[] { Row("psqlodbc_x64.msi"), Row("psqlodbc_x86.msi") }
        });
    }

    private sealed class Network(byte[] manifest, string? fault = null) : HttpMessageHandler
    {
        internal List<string> Requests { get; } = [];
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken token)
        {
            var url = request.RequestUri!.AbsoluteUri;
            Requests.Add(url);
            if (request.Method != HttpMethod.Get || request.Headers.Authorization is not null)
                throw new Exception("Standalone downloads must use anonymous GET");
            if (url == Tool)
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Redirect)
                {
                    Headers = { Location = new Uri(ToolCdn) }
                });
            var bytes = url switch
            {
                RawCatalog + "standalone-get.json" => manifest,
                RawCatalog + "direct-get.json" => """{"schemaVersion":"pgextwin-external-direct-get/v1","records":[]}"""u8.ToArray(),
                Spatial or ToolCdn => Original,
                Driver when fault == "hash" => new byte[Original.Length],
                Driver when fault == "short" => Original[..^1],
                Driver when fault == "long" => [.. Original, 0x08],
                Driver => Original,
                _ => throw new Exception("Unexpected request: " + url)
            };
            var content = new ByteArrayContent(bytes);
            if (url == Driver) content.Headers.ContentLength = Original.Length;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content });
        }
    }

    public static async Task RunAsync(Action<bool, string> check)
    {
        var manifest = Manifest(includeLicense: true);
        using (var network = new Network(manifest))
        {
            var listed = await ExternalSignedCatalogCohort.ListDownloadsAsync("18", "drivers", "ODBC",
                handler: network);
            check(listed.Count == 1 && listed[0].PgMajor is null && listed[0].Version == "13.02.0000",
                "Category, case-insensitive search, latest and major-independent matching apply together");
            check(network.Requests.SequenceEqual([RawCatalog + "standalone-get.json"]),
                "Driver browsing reads catalog pins without requesting originals or PostgreSQL");
        }

        var multiArch = ExternalSignedCatalogCohort.ParseDownloads(MultiArchManifest(), standalone: true);
        check(multiArch.Count == 2,
            "Two same-item same-version standalone records with distinct assets parse");
        var selected = ExternalSignedCatalogCohort.SelectDownloads(multiArch, "all", "psqlodbc", null);
        check(selected.Count == 2 &&
            selected.Select(pin => pin.AssetName).Distinct().Count() == 2,
            "Selecting the multi-architecture item returns both architecture pins");
        var selectedByVersion = ExternalSignedCatalogCohort.SelectDownloads(
            multiArch, "all", "psqlodbc", "18.00.0006");
        check(selectedByVersion.Count == 2,
            "Exact-version selection also returns both architecture pins");
        try
        {
            ExternalSignedCatalogCohort.ParseDownloads(
                MultiArchManifest(duplicateAsset: true), standalone: true);
            check(false, "A true duplicate standalone record (same asset) must fail");
        }
        catch (InvalidDataException)
        {
            check(true, "A true duplicate standalone record (same asset) must fail");
        }

        var parent = Path.Combine(Path.GetTempPath(), "pgextwin-standalone-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(parent);
        try
        {
            using (var network = new Network(manifest))
            {
                var result = await ExternalSignedCatalogCohort.DownloadAsync("14", parent, handler: network);
                check(result.Count == 3 && result.Bytes == 3 * Original.Length,
                    "Bulk saves the spatial bundle once alongside its major-independent tool and driver");
                var relative = Directory.EnumerateFiles(result.Directory, "*", SearchOption.AllDirectories)
                    .Select(file => Path.GetRelativePath(result.Directory, file).Replace('\\', '/'))
                    .Order(StringComparer.Ordinal);
                check(relative.SequenceEqual([
                    "any/pgbouncer/tool.zip", "any/psqlodbc/example-driver.zip", "pg14/postgis/postgis-setup.exe"]),
                    "Mixed batches preserve original names and use a distinct major-independent path");
                check(Directory.EnumerateFiles(result.Directory, "*", SearchOption.AllDirectories)
                    .All(file => File.ReadAllBytes(file).SequenceEqual(Original)),
                    "The staged files preserve the exact input bytes");
                check(network.Requests.Count == 6 && network.Requests.Contains(ToolCdn),
                    "A GitHub project package follows its normal asset CDN redirect");
                Directory.Delete(result.Directory, recursive: true);
            }

            using (var network = new Network(manifest))
            {
                var result = await ExternalSignedCatalogCohort.DownloadAsync("14", parent, "spatial",
                    "PGROUTING", "4.0.1", handler: network);
                check(result.Count == 1 && Path.GetFileName(result.Directory) == "pgextwin-external-postgis-pg14",
                    "Exact pgRouting version selects the same original PostGIS installer");
                Directory.Delete(result.Directory, recursive: true);
            }

            foreach (var fault in new[] { "hash", "short", "long", "license", "version" })
            {
                using var network = new Network(fault == "license" ? Manifest(false) : manifest, fault);
                try
                {
                    await ExternalSignedCatalogCohort.DownloadAsync("14", parent,
                        item: fault == "version" ? "psqlodbc" : null,
                        version: fault == "version" ? "99.0" : null, handler: network);
                    check(false, "Standalone fault must fail: " + fault);
                }
                catch (InvalidDataException)
                {
                    check(!Directory.EnumerateFileSystemEntries(parent).Any(),
                        "Standalone fault leaves no committed or partial batch: " + fault);
                    if (fault is "license" or "version")
                        check(network.Requests.All(url => url.StartsWith(RawCatalog, StringComparison.Ordinal)),
                            "Missing license or exact version fails before provider GET");
                }
            }
        }
        finally { Directory.Delete(parent, recursive: true); }
    }
}
