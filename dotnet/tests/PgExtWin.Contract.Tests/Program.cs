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
await ReleaseHttpTests.RunAsync(Check);
SyntheticBundleTests.Run(Check);
P1HandoffTests.Run(Check);
Console.WriteLine($"PASS: {cases} local read-only contract checks. SIGNATURE_VERIFIED=0 PUBLISH=DENY");
