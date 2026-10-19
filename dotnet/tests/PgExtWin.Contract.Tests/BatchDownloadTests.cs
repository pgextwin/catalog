using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PgExtWin.Releases;

internal static class BatchDownloadTests
{
    public static async Task RunAsync(Action<bool, string> check)
    {
        var root = Path.Combine(Path.GetTempPath(), "pgextwin-batch-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var bytes = SyntheticZip();
            var hash = Convert.ToHexStringLower(SHA256.HashData(bytes));
            ReleasePins Pin(string extension, string pg) {
                var name = extension + "-v1-pg" + pg + "-windows-x64.zip";
                return new ReleasePins(extension, pg, "v1-windows.1", name, hash,
                    101, 202, new Dictionary<string, long> { [name] = 303 },
                    new string('a', 40));
            }
            var a = Pin("pg_cron", "18");
            var b = Pin("pg_bigm", "18");
            var all = new[] { a, b };

            Task<DownloadReceipt> Download(ReleasePins pin, string folder, CancellationToken token)
            {
                var path = Path.Combine(folder, pin.AssetName);
                File.WriteAllBytes(path, bytes);
                return Task.FromResult(new DownloadReceipt(
                    path, pin.AssetSha256, bytes.Length,
                    pin.RepositoryId, pin.ReleaseId, pin.AssetIds[pin.AssetName]));
            }
            var result = await BatchReleaseDownloader.StageAsync(all, "18", root, Download);
            check(result.Count == 2 && result.Bytes == bytes.Length * 2 &&
                  result.VerificationLevel == "INTEGRITY_ONLY",
                  "Batch original ZIP count, byte sum and integrity-only verdict");
            check(Directory.Exists(Path.Combine(root, "pgextwin-pg18")) &&
                  Directory.GetFiles(root, "*.part", SearchOption.AllDirectories).Length == 0 &&
                  Directory.GetDirectories(root).Length == 1,
                  "Successful batch atomically exposes only final named folder");
            foreach (var pin in all)
                check(File.ReadAllBytes(Path.Combine(result.Directory, "pg18", pin.AssetName))
                    .SequenceEqual(bytes), "Batch retains original ZIP exact bytes");
            using (var doc = JsonDocument.Parse(File.ReadAllText(
                       Path.Combine(result.Directory, "DOWNLOAD-INFO.json"))))
            {
                var value = doc.RootElement;
                check(value.GetProperty("schemaVersion").GetString() == "pgextwin-cli-batch-download/v1" &&
                      value.GetProperty("verificationLevel").GetString() == "INTEGRITY_ONLY" &&
                      !value.GetProperty("signatureVerified").GetBoolean() &&
                      !value.GetProperty("provenanceVerified").GetBoolean() &&
                      !value.GetProperty("distributionAuthorized").GetBoolean() &&
                      !value.GetProperty("installAuthorized").GetBoolean() &&
                      value.GetProperty("zipCount").GetInt32() == 2 &&
                      value.GetProperty("packages").GetArrayLength() == 2,
                      "Batch receipt explicitly forbids signature/install/distribution claims");
            }

            async Task Deny(string label, IReadOnlyList<ReleasePins> pins, string major,
                Func<ReleasePins, string, CancellationToken, Task<DownloadReceipt>> operation)
            {
                var outDir = Path.Combine(root, "case-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(outDir);
                File.WriteAllText(Path.Combine(outDir, "existing.txt"), "KEEP");
                var failed = false;
                try { await BatchReleaseDownloader.StageAsync(pins, major, outDir, operation); }
                catch (Exception e) when (e is InvalidDataException or IOException or
                        ArgumentException or OperationCanceledException or HttpRequestException) { failed = true; }
                check(failed && Directory.GetDirectories(outDir).Length == 0 &&
                      File.ReadAllText(Path.Combine(outDir, "existing.txt")) == "KEEP",
                      label + " denied without partial output or deleting user files");
            }
            await Deny("Second download HTTP failure", all, "18",
                (pin, folder, token) => pin.Extension == "pg_bigm"
                    ? Task.FromException<DownloadReceipt>(new HttpRequestException("synthetic 403"))
                    : Download(pin, folder, token));
            await Deny("Original second ZIP tampered", all, "18",
                async (pin, folder, token) => {
                    var receipt = await Download(pin, folder, token);
                    if (pin.Extension == "pg_bigm")
                        File.AppendAllText(receipt.FilePath, "tampered");
                    return receipt;
                });
            await Deny("Forged signature verification receipt", all, "18",
                async (pin, folder, token) => {
                    var receipt = await Download(pin, folder, token);
                    return receipt with { VerificationLevel = "SIGNATURE_VERIFIED" };
                });
            await Deny("Forged numeric asset identity", all, "18",
                async (pin, folder, token) => {
                    var receipt = await Download(pin, folder, token);
                    return receipt with { AssetId = 999 };
                });
            await Deny("Duplicate case-insensitive asset names", new[] { a, a }, "18", Download);
            await Deny("Unapproved PG19", new[] { Pin("pg_cron", "19") }, "all", Download);
            await Deny("PG major mismatched selected", new[] { Pin("pg_cron", "14") }, "18", Download);
            await Deny("Invalid ZIP basename traversal", new[] { a with { AssetName = "../escape.zip" } }, "18", Download);
            await Deny("Duplicate already-published destination", all, "18", Download);

            // The 'all' option preserves each version's ZIP in its own PG subdirectory.
            var multiDir = Path.Combine(root, "cross-major");
            Directory.CreateDirectory(multiDir);
            var multi = await BatchReleaseDownloader.StageAsync(
                new[] { Pin("pg_cron", "14"), Pin("pg_cron", "18") }, "all", multiDir, Download);
            check(multi.Count == 2 &&
                  File.Exists(Path.Combine(multi.Directory, "pg14", Pin("pg_cron", "14").AssetName)) &&
                  File.Exists(Path.Combine(multi.Directory, "pg18", Pin("pg_cron", "18").AssetName)),
                  "Batch --pg all segregates original ZIPs by PostgreSQL version");
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    private static byte[] SyntheticZip()
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, true))
        {
            var entry = archive.CreateEntry("SYNTHETIC-DO-NOT-DISTRIBUTE.txt");
            using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
            writer.Write("Only synthetic input; no real extension Release or Sigstore proof");
        }
        return stream.ToArray();
    }
}
