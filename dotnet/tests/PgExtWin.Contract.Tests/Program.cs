using System.Text;
using System.Text.Json;
using PgExtWin.Core;
using PgExtWin.Catalog;

var cases = 0;
void Check(bool condition, string name)
{
    ++cases;
    if (!condition) throw new Exception("FAILED: " + name);
}
void Denies(Action action, string name)
{
    var rejected = false;
    try { action(); }
    catch (Exception e) when (e is InvalidDataException or JsonException or InvalidOperationException or KeyNotFoundException)
    { rejected = true; }
    Check(rejected, name);
}

// The golden vector is Python P0's canonical(json) output, calculated with
// json.dumps(ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n'.
const string source = "{\"b\":2,\"a\":{\"z\":false,\"x\":\"日本語\"},\"arr\":[1,{\"b\":null,\"a\":true}]}";
const string golden = "{\"a\":{\"x\":\"日本語\",\"z\":false},\"arr\":[1,{\"a\":true,\"b\":null}],\"b\":2}\n";
using (var doc = StrictJson.Parse(Encoding.UTF8.GetBytes(source)))
{
    var canonical = StrictJson.CanonicalBytes(doc.RootElement);
    Check(Encoding.UTF8.GetString(canonical) == golden, "P0 golden canonical bytes including UTF-8/LF");
    Check(StrictJson.Sha256(canonical) == "f549d3d13ff8cd753fac9e53cc966d7d9e15d6496846dac28cad750ccda90fb3", "P0 golden SHA256");
}
Denies(() => { using var d = StrictJson.Parse("{\"a\":1,\"a\":2}"u8); }, "duplicate JSON root key");
Denies(() => { using var d = StrictJson.Parse("{\"x\":{\"a\":1,\"a\":2}}"u8); }, "duplicate nested key");
Denies(() => { using var d = StrictJson.Parse("{\"a\":NaN}"u8); }, "NaN rejected");
Denies(() => { using var d = StrictJson.Parse("{\"a\":1,}"u8); }, "trailing comma rejected");
Denies(() => { using var d = StrictJson.Parse("{\"a\":1.5}"u8); StrictJson.CanonicalBytes(d.RootElement); }, "non-integer canonicalization fail-closed");

const string unsignedEnvelope = "{\"schemaVersion\":\"pgextwin-distribution-manifest/v1\",\"trust\":{\"offlineTrustRoot\":\"EXTERNAL_REQUIRED\",\"outerArchiveSigned\":false},\"publicationAuthorized\":false,\"generatorVersion\":\"pgextwin-manifest-p0/1\",\"packages\":[],\"coverage\":[]}";
using (var doc = StrictJson.Parse(Encoding.UTF8.GetBytes(unsignedEnvelope)))
{
    var snapshotId = StrictJson.Sha256(StrictJson.CanonicalBytes(doc.RootElement));
    Check(snapshotId == "3f92e48464dfab030beead6ceaba94da124fb563458cd05c00e83f89b438eddb", "P0 manifest snapshot hash golden");
    var json = unsignedEnvelope.TrimEnd('}') + ",\"snapshotId\":\"" + snapshotId + "\"}";
    ManifestV1.CheckStructuralEnvelope(Encoding.UTF8.GetBytes(json));
    Check(true, "P0 nonpublishing envelope accepted structurally");
    Denies(() => ManifestV1.CheckStructuralEnvelope(Encoding.UTF8.GetBytes(json.Replace(snapshotId, new string('0',64)))), "P0 snapshot tampering");
    Denies(() => ManifestV1.CheckStructuralEnvelope(Encoding.UTF8.GetBytes(json.Replace("\"publicationAuthorized\":false", "\"publicationAuthorized\":true"))), "publicationAuthorization tampering");
    Denies(() => ManifestV1.CheckStructuralEnvelope(Encoding.UTF8.GetBytes(json.Replace("EXTERNAL_REQUIRED", "BUNDLED"))), "bundled root not authenticated");
}

// All test Catalog bytes are synthetic. Neither a signed manifest nor published Release is claimed.
var path = Path.Combine(Path.GetTempPath(), "pgextwin-pr1-tests-" + Guid.NewGuid().ToString("N"));
try
{
    Directory.CreateDirectory(Path.Combine(path, "extensions"));
    var index = "{\"schemaVersion\":2,\"extensions\":[\"pg_cron\",\"pg_hint_plan\"]}";
    File.WriteAllText(Path.Combine(path,"index.json"),index);
    string Make(string name, bool perMajor) => """
        {"schemaVersion":2,"name":"NAME","displayName":"NAME","description":"Synthetic test extension","repository":"pgextwin/NAME","architecture":"x64","latest":{"releaseTag":"v1.0-windows.1"},"upstream":UPSTREAM,"postgresql":{"14":{"available":true,"asset":"foo14.zip"},"18":{"available":true,"asset":"foo18.zip"}},"runtime":{"requirements":{"preload":"optional"}}}
        """.Replace("NAME",name).Replace("UPSTREAM",perMajor ? "{\"perPostgresql\":{\"14\":{\"version\":\"1.14\"},\"18\":{\"version\":\"1.18\"}}}" : "{\"version\":\"1.0\"}");
    File.WriteAllText(Path.Combine(path,"extensions","pg_cron.json"),Make("pg_cron",false));
    File.WriteAllText(Path.Combine(path,"extensions","pg_hint_plan.json"),Make("pg_hint_plan",true));
    var records = CatalogReader.LoadLocal(path);
    Check(records.Count == 2, "dynamic Catalog index fixture");
    Check(records.Single(r => r.Name == "pg_hint_plan").Versions.Single(v => v.Major == "18").Version == "1.18", "per-PG upstream version");
    Check(records.Single(r => r.Name == "pg_cron").Preload == "optional", "preload reported without applying");
    File.WriteAllText(Path.Combine(path,"index.json"),"{\"schemaVersion\":2,\"extensions\":[\"pg_cron\",\"pg_cron\"]}");
    Denies(() => CatalogReader.LoadLocal(path), "duplicated extension index denied");
    File.WriteAllText(Path.Combine(path,"index.json"),index);
    File.WriteAllText(Path.Combine(path,"extensions","pg_cron.json"),Make("pg_cron",false).Replace("\"architecture\":\"x64\"","\"architecture\":\"arm64\""));
    Denies(() => CatalogReader.LoadLocal(path), "wrong architecture denied");
    File.WriteAllText(Path.Combine(path,"extensions","pg_cron.json"),Make("pg_cron",false));
    File.WriteAllText(Path.Combine(path,"extensions","extra.json"),Make("extra",false));
    Denies(() => CatalogReader.LoadLocal(path), "unindexed record denied");
}
finally { Directory.Delete(path, recursive:true); }

// Check the actual checkout in CI (no network/cryptographic trust claims).
if (File.Exists(Path.Combine(Directory.GetCurrentDirectory(), "index.json")))
{
    var records = CatalogReader.LoadLocal(Directory.GetCurrentDirectory());
    Check(records.Count == 14, "actual local Catalog contains 14 records (untrusted)");
    Check(records.All(r => r.Versions.Count == 5), "local Catalog has 5 available majors each");
}


// PR-2 fake HTTP responses. Every payload, pin and "Release" here is synthetic;
// no request leaves the process, and hashes do NOT prove Sigstore provenance.
{
    var zip = new byte[] { 0x50, 0x4b, 0x03, 0x04, 2, 4, 6, 8, 10, 12 };
    var digest = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(zip));
    var pin = new PgExtWin.Releases.ReleasePin(
        "pg_cron", "v1.6.8-windows.2", new string('a', 40),
        1001, 2001, 3001, "pg_cron-v1.6.8-pg18-windows-x64.zip", digest, zip.Length);
    var destinationRoot = Path.Combine(Path.GetTempPath(), "pgextwin-pr2-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(destinationRoot);
    HttpResponseMessage Mock(Uri uri, string scenario, List<string> seen)
    {
        seen.Add(uri.ToString());
        if (uri.Host == "api.github.com" && uri.AbsolutePath == "/repos/pgextwin/pg_cron")
        {
            var repoId = scenario == "wrongRepo" ? 9999 : 1001;
            return new(System.Net.HttpStatusCode.OK)
            { Content = new StringContent(System.Text.Json.JsonSerializer.Serialize(
                new { id = repoId, full_name = "pgextwin/pg_cron" })) };
        }
        if (uri.Host == "api.github.com" && uri.AbsolutePath.EndsWith("/releases/tags/v1.6.8-windows.2", StringComparison.Ordinal))
        {
            var assetId = scenario == "wrongAsset" ? 3002 : 3001;
            var assetDigest = scenario == "wrongDigest" ? new string('0', 64) : digest;
            var releaseId = scenario == "wrongRelease" ? 2002 : 2001;
            var assetName = scenario == "wrongAssetName" ? "evil.zip" : pin.AssetName;
            var size = scenario == "wrongMetadataSize" ? pin.ExpectedSize + 1 : pin.ExpectedSize;
            var assets = new List<object>
            {
                new { id = assetId, name = assetName, state = "uploaded",
                    size, digest = "sha256:" + assetDigest,
                    browser_download_url = $"https://github.com/pgextwin/pg_cron/releases/download/{pin.Tag}/{pin.AssetName}" }
            };
            if (scenario == "duplicateAsset")
                assets.Add(new { id = 9999, name = assetName.ToUpperInvariant(), state = "uploaded",
                    size, digest = "sha256:" + assetDigest, browser_download_url = "https://invalid.invalid/bad" });
            return new(System.Net.HttpStatusCode.OK)
            { Content = new StringContent(System.Text.Json.JsonSerializer.Serialize(new
              { id = releaseId, tag_name = pin.Tag, target_commitish = pin.PackagingSha,
                draft = scenario == "draft", prerelease = false, assets })) };
        }
        if (uri.Host == "github.com" && uri.AbsolutePath.StartsWith("/pgextwin/pg_cron/releases/download/", StringComparison.Ordinal))
        {
            if (scenario is "maliciousRedirect" or "safeRedirect")
            {
                var r = new HttpResponseMessage(System.Net.HttpStatusCode.Redirect);
                r.Headers.Location = new Uri(scenario == "maliciousRedirect"
                    ? "https://evil.example/steal" : "https://release-assets.githubusercontent.com/synthetic");
                return r;
            }
            if (scenario == "serverFailure") return new(System.Net.HttpStatusCode.ServiceUnavailable);
            return new(System.Net.HttpStatusCode.OK)
            { Content = new ByteArrayContent(scenario == "alteredBody"
                ? new byte[] { 0x50, 0x4b, 0, 0, 2, 4, 6, 8, 10, 12 }
                : scenario == "truncatedBody" ? zip[..^1] : zip) };
        }
        if (uri.Host == "release-assets.githubusercontent.com" && scenario == "safeRedirect")
            return new(System.Net.HttpStatusCode.OK) { Content = new ByteArrayContent(zip) };
        throw new InvalidDataException("Unexpected attempted outbound URL: " + uri);
    }
    async Task RunSuccess(string scenario)
    {
        var seen = new List<string>();
        using var reader = new PgExtWin.Releases.ReleaseReader(new FixtureHandler(u => Mock(u, scenario, seen)));
        var dir = Path.Combine(destinationRoot, scenario);
        var receipt = await reader.DownloadAsync(pin, dir);
        Check(receipt.VerificationLevel == "INTEGRITY_ONLY" &&
            !receipt.SignatureVerified && !receipt.PublicationAuthorized, "Never self-authorize Sigstore proof");
        Check(File.ReadAllBytes(receipt.Path).SequenceEqual(zip), "Original bytes staged and saved unmodified");
        Check(receipt.Sha256 == digest && receipt.Size == zip.Length, "Exact SHA256/size receipt");
        Check(seen.Count == (scenario == "safeRedirect" ? 4 : 3), "GET-only exact bounded request sequence");
        Check(seen.All(u => Uri.TryCreate(u, UriKind.Absolute, out var x) && x.Scheme == "https"), "Only HTTPS GET routes");
        if (scenario == "good")
        {
            await Rejects(async () => { await reader.DownloadAsync(pin, dir); }, "Refuse to overwrite original ZIP");
        }
    }
    async Task RunFailure(string scenario)
    {
        var seen = new List<string>();
        using var reader = new PgExtWin.Releases.ReleaseReader(new FixtureHandler(u => Mock(u, scenario, seen)));
        var dir = Path.Combine(destinationRoot, scenario);
        await Rejects(async () => { await reader.DownloadAsync(pin, dir); }, scenario + " fail-closed");
        Check(!Directory.Exists(dir) || !Directory.EnumerateFileSystemEntries(dir).Any(),
            scenario + " cannot leave a partial/success file");
    }
    async Task Rejects(Func<Task> action, string name)
    {
        var denied = false;
        try { await action(); }
        catch (InvalidDataException) { denied = true; }
        Check(denied, name);
    }
    try
    {
        await RunSuccess("good");
        await RunSuccess("safeRedirect");
        foreach (var scenario in new[] { "wrongRepo", "wrongRelease", "wrongAsset",
            "wrongDigest", "wrongAssetName", "wrongMetadataSize", "duplicateAsset",
            "draft", "serverFailure", "alteredBody", "truncatedBody", "maliciousRedirect" })
            await RunFailure(scenario);
        using var reader = new PgExtWin.Releases.ReleaseReader(new FixtureHandler(
            _ => throw new InvalidDataException("Invalid pin reached HTTP")));
        var badName = pin with { AssetName = "../escape.zip" };
        await Rejects(async () => { await reader.DownloadAsync(badName, destinationRoot); },
            "Reject path traversal before HTTP");
        var huge = pin with { ExpectedSize = 1024L * 1024 * 1024 };
        await Rejects(async () => { await reader.DownloadAsync(huge, destinationRoot); },
            "Reject oversized pin before HTTP");
    }
    finally { Directory.Delete(destinationRoot, recursive: true); }
}

Console.WriteLine($"PASS: {cases} local read-only contract checks. SIGNATURE_VERIFIED=0 PUBLISH=DENY");

sealed class FixtureHandler(Func<Uri, HttpResponseMessage> response) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        if (request.Method != HttpMethod.Get || request.RequestUri is null)
            throw new InvalidDataException("Only mocked GET requests allowed");
        return Task.FromResult(response(request.RequestUri));
    }
}
