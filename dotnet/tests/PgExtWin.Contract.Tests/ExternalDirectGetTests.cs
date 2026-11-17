using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using PgExtWin.Releases;

internal static class ExternalDirectGetTests
{
    private sealed class Network(Func<HttpRequestMessage, HttpResponseMessage> reply)
        : HttpMessageHandler
    {
        internal List<string> Requests { get; } = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests.Add(request.RequestUri!.AbsoluteUri);
            if (request.Headers.Authorization is not null)
                throw new Exception("Provider GET must not carry a GitHub credential");
            return Task.FromResult(reply(request));
        }
    }

    public static async Task RunAsync(Action<bool, string> check)
    {
        using var memory = new MemoryStream();
        using (var zip = new ZipArchive(memory, ZipArchiveMode.Create, leaveOpen: true))
        using (var writer = new StreamWriter(zip.CreateEntry("lib/pg_crash.dll").Open()))
            writer.Write("synthetic DLL fixture");
        var original = memory.ToArray();
        var hash = Convert.ToHexStringLower(SHA256.HashData(original));
        JsonObject Row(string major, string version, bool latest) => new()
        {
            ["extension"] = "pg_crash", ["pgMajor"] = major,
            ["upstreamVersion"] = version, ["latest"] = latest,
            ["sourceRepo"] = "cybertec-postgresql/pg_crash", ["repositoryId"] = 0,
            ["releaseTag"] = "v" + version, ["releaseId"] = 0,
            ["assetName"] = $"pg_crash-{major}-public-v{version}-1.zip", ["assetId"] = 0,
            ["originalBytes"] = original.Length, ["originalSha256"] = hash,
            ["originalProviderUrl"] = $"https://repository.cybertec.at/windows/public/{major}/extension/pg_crash-{major}-public-v{version}-1.zip",
            ["license"] = "BSD-3-Clause",
            ["licenseEvidence"] = new JsonArray("https://example.invalid/exact/v" + version + "/LICENSE")
        };
        var rows = new JsonArray(Row("15", "0.3", true), Row("18", "0.3", true),
            Row("18", "0.2", false));
        var doc = new JsonObject
        {
            ["schemaVersion"] = "pgextwin-external-direct-get/v1", ["records"] = rows
        };
        byte[] Bytes() => Encoding.UTF8.GetBytes(doc.ToJsonString());
        var latestPins = ExternalSignedCatalogCohort.SelectDirect(Bytes(), "all");
        check(latestPins.Count == 2, "Relaxed bulk fetch selects latest on all recorded PG majors");
        check(ExternalSignedCatalogCohort.SelectDirect(Bytes(), "18", "pg_crash", "0.2")
            .Single().Tag == "v0.2", "Exact historical version selection does not use filename guessing");
        foreach (var selection in new[] { ("18", "0.3.0"), ("14", "0.3"), ("19", "0.3") })
        {
            var denied = false;
            try { ExternalSignedCatalogCohort.SelectDirect(Bytes(), selection.Item1, "pg_crash", selection.Item2); }
            catch (InvalidDataException) { denied = true; }
            check(denied, "Absent exact version or unsupported major fails before provider GET");
        }
        var license = rows[0]!["licenseEvidence"]!.DeepClone();
        rows[0]!["licenseEvidence"] = new JsonArray();
        var missingLicenseDenied = false;
        try { ExternalSignedCatalogCohort.SelectDirect(Bytes(), "all"); }
        catch (InvalidDataException) { missingLicenseDenied = true; }
        check(missingLicenseDenied, "Missing exact-version license bookkeeping is rejected");
        rows[0]!["licenseEvidence"] = license;

        var parent = Path.Combine(Path.GetTempPath(), "pgextwin-direct-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(parent);
        try
        {
            foreach (var fault in new[] { "none", "hash", "redirect" })
            {
                using var network = new Network(request =>
                {
                    var url = request.RequestUri!.AbsoluteUri;
                    if (url == "https://raw.githubusercontent.com/pgextwin/catalog/main/external/direct-get.json")
                        return new(HttpStatusCode.OK) { Content = new ByteArrayContent(Bytes()) };
                    if (!latestPins.Any(pin => pin.OriginalProviderUrl == url))
                        throw new Exception("Unexpected admission, signature, issuer or metadata request: " + url);
                    if (url.Contains("/18/") && fault == "redirect")
                    {
                        var response = new HttpResponseMessage(HttpStatusCode.Redirect);
                        response.Headers.Location = new Uri("https://example.invalid/other.zip");
                        return response;
                    }
                    return new(HttpStatusCode.OK)
                    {
                        Content = new ByteArrayContent(url.Contains("/18/") && fault == "hash"
                            ? new byte[original.Length] : original)
                    };
                });
                var denied = false;
                try
                {
                    var result = await ExternalSignedCatalogCohort.StageDirectAsync("all", parent,
                        handler: network, requestedExtension: "pg_crash");
                    check(result.Count == 2 && result.Bytes == 2 * original.Length,
                        "Two unsigned provider originals commit in one existing atomic batch");
                    foreach (var pin in latestPins)
                        check(File.ReadAllBytes(Path.Combine(result.Directory, "pg" + pin.PgMajor,
                            pin.Extension, pin.AssetName)).SequenceEqual(original),
                            "Committed provider bytes are unmodified");
                    Directory.Delete(result.Directory, recursive: true);
                }
                catch (Exception e) when (e is InvalidDataException or HttpRequestException)
                { denied = true; }
                check(denied == (fault != "none"), "Hash/HTTP failure rejects entire relaxed batch");
                check(!Directory.EnumerateFileSystemEntries(parent).Any(), "Failed batch leaves no partial output");
                check(network.Requests.Count == 3, "Only Catalog records and two direct GETs; no issuer/admission");
            }
        }
        finally { Directory.Delete(parent, recursive: true); }

        if (File.Exists("external/direct-get.json"))
        {
            var actual = File.ReadAllBytes("external/direct-get.json");
            var pins = ExternalSignedCatalogCohort.SelectDirect(actual, "all");
            foreach (var extension in new[] { "pglogical", "pg_crash" })
                check(pins.Count(pin => pin.Extension == extension) == 4,
                    "Catalog latest external support covers PG15–18: " + extension);
            check(pins.All(pin => pin.PgMajor != "14"), "New direct records exclude EOL PG14");
        }
    }
}
