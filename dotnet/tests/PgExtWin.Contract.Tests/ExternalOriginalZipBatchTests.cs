using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PgExtWin.Releases;

internal static class ExternalOriginalZipBatchTests
{
    public static void Run(Action<bool, string> check)
    {
        var root = Path.Combine(Path.GetTempPath(), "pgextwin-external-batch-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            byte[] original;
            using (var buffer = new MemoryStream())
            {
                using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
                {
                    var member = zip.CreateEntry("extension/README.txt");
                    using var writer = new StreamWriter(member.Open(), Encoding.UTF8);
                    writer.Write("synthetic external archive; never an approved release");
                }
                original = buffer.ToArray();
            }
            var sha = Convert.ToHexStringLower(SHA256.HashData(original));
            var files = Path.Combine(root, "originals");
            Directory.CreateDirectory(files);
            var review = Path.Combine(root, "review.json");
            var oracle = Row("oracle_fdw", "laurenz/oracle_fdw", "ORACLE_FDW_2_9_0",
                "oracle_fdw-2.9.0-pg18-win64.zip", 14332609, 335861225, 442625860, sha, original.Length);
            var vector = Row("pgvector", "andreiramani/pgvector_pgsql_windows", "0.8.7",
                "vector.v0.8.7-pg18.zip", 838202416, 419235203, 661612613, sha, original.Length);
            WriteReview(oracle, vector);
            foreach (var row in new[] { oracle, vector })
            {
                var directory = Path.Combine(files, "pg18", (string)row["extension"]);
                Directory.CreateDirectory(directory);
                File.WriteAllBytes(Path.Combine(directory, (string)row["assetName"]), original);
            }

            var success = ExternalOriginalZipBatch.VerifyLocal(review, files, "18");
            check(success.Count == 2 && success.Bytes == original.Length * 2 &&
                  success.Members == 2 &&
                  success.Scope == "INTEGRITY_ONLY_NOT_AUTHORIZED",
                  "Offline external batch checks both untouched provider ZIPs without granting authority");
            check(ExternalOriginalZipBatch.VerifyLocal(review, files, "all").Count == 2,
                "Offline external batch supports all majors without a hardcoded extension roster");
            check(Directory.GetFiles(files, "*", SearchOption.AllDirectories).Length == 2 &&
                  File.ReadAllBytes(Path.Combine(files, "pg18", "oracle_fdw",
                      "oracle_fdw-2.9.0-pg18-win64.zip")).SequenceEqual(original),
                "Offline external batch never stages, modifies, downloads or republishes originals");

            void Deny(string label, Action action)
            {
                var rejected = false;
                try { action(); }
                catch (Exception ex) when (ex is InvalidDataException or IOException or
                                           ArgumentException or KeyNotFoundException)
                { rejected = true; }
                check(rejected, label + " fails closed");
            }

            Deny("Unreviewed PG17", () => ExternalOriginalZipBatch.VerifyLocal(review, files, "17"));
            Deny("Invalid major", () => ExternalOriginalZipBatch.VerifyLocal(review, files, "../18"));
            var secondFile = Path.Combine(files, "pg18", "pgvector", "vector.v0.8.7-pg18.zip");
            File.AppendAllText(secondFile, "tamper");
            Deny("Tampered bytes/size", () => ExternalOriginalZipBatch.VerifyLocal(review, files, "18"));
            File.WriteAllBytes(secondFile, original);
            File.WriteAllBytes(secondFile, original.Select((b, i) => i == 0 ? (byte)(b ^ 1) : b).ToArray());
            Deny("Same length wrong SHA256", () => ExternalOriginalZipBatch.VerifyLocal(review, files, "18"));
            File.WriteAllBytes(secondFile, original);
            vector["downloadAuthorized"] = true;
            WriteReview(oracle, vector);
            Deny("Forged per-provider download authority", () => ExternalOriginalZipBatch.VerifyLocal(review, files, "18"));
            vector["downloadAuthorized"] = false;
            WriteReview(oracle, vector, publicationAuthorized: true);
            Deny("Forged root publication authority", () => ExternalOriginalZipBatch.VerifyLocal(review, files, "18"));
            WriteReview(oracle, vector);
            var swapped = vector["originalProviderUrl"];
            vector["originalProviderUrl"] = "https://evil.example/download.zip";
            WriteReview(oracle, vector);
            Deny("Provider URL substitution", () => ExternalOriginalZipBatch.VerifyLocal(review, files, "18"));
            vector["originalProviderUrl"] = swapped;
            WriteReview(oracle, vector, extra: oracle);
            Deny("Duplicated release asset identity", () => ExternalOriginalZipBatch.VerifyLocal(review, files, "18"));
            WriteReview(oracle, vector);
            File.Delete(secondFile);
            Deny("Partial local original set", () => ExternalOriginalZipBatch.VerifyLocal(review, files, "all"));

            void WriteReview(Dictionary<string, object> a, Dictionary<string, object> b,
                bool publicationAuthorized = false, Dictionary<string, object>? extra = null)
            {
                var document = new Dictionary<string, object>
                {
                    ["schemaVersion"] = "pgextwin-external-original-link-review/v1",
                    ["scope"] = "REFERENCE_TO_UNMODIFIED_PROVIDER_RELEASE_ASSET_ONLY",
                    ["rightsReview"] = "SOURCE_AND_NOTICE_REFERENCES_REVIEWED_NOT_DISTRIBUTION_APPROVAL",
                    ["publicationAuthorized"] = publicationAuthorized,
                    ["downloadAuthorized"] = false,
                    ["mirrorAuthorized"] = false,
                    ["redistributionAuthorized"] = false,
                    ["signedExternalCatalogPin"] = false,
                    ["records"] = extra is null ? new[] { a, b } : new[] { a, b, extra }
                };
                File.WriteAllText(review, JsonSerializer.Serialize(document));
            }
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private static Dictionary<string, object> Row(string extension, string repository,
        string tag, string asset, long repositoryId, long releaseId, long assetId,
        string sha, long size)
        => new()
        {
            ["extension"] = extension,
            ["pgMajor"] = "18",
            ["sourceRepo"] = repository,
            ["repositoryId"] = repositoryId,
            ["releaseId"] = releaseId,
            ["releaseTag"] = tag,
            ["assetId"] = assetId,
            ["assetName"] = asset,
            ["originalProviderUrl"] = "https://github.com/" + repository +
                "/releases/download/" + tag + "/" + asset,
            ["originalBytes"] = size,
            ["originalSha256"] = sha,
            ["referenceLinkReviewed"] = true,
            ["downloadAuthorized"] = false,
            ["mirrorAuthorized"] = false
        };
}
