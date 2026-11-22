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
            var evidence = new[] { "https://github.com/pgextwin/pg_cron/blob/" + new string('a', 40) + "/LICENSE" };
            var a = Pin("pg_cron", "18") with
            {
                Version = "1.0",
                License = new ReleasePackageLicense("PostgreSQL", evidence)
            };
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
            string[] feedMajors = ["15", "16", "17", "18"];
            var diagnostics = new List<string>();
            var result = await BatchReleaseDownloader.StageAsync(
                all, "18", root, Download, feedMajors, progress: diagnostics.Add);
            check(diagnostics.Count(x => x.StartsWith("ZIP_START ", StringComparison.Ordinal)) == 2 &&
                  diagnostics.Count(x => x.StartsWith("ZIP_VERIFIED ", StringComparison.Ordinal)) == 2 &&
                  diagnostics[0] == "BATCH_START pg=18 zip_count=2 trust=INTEGRITY_ONLY" &&
                  diagnostics[^1].StartsWith("BATCH_COMPLETE zip_count=2 ", StringComparison.Ordinal) &&
                  diagnostics.All(x => !x.Contains("SIGNATURE_VERIFIED", StringComparison.Ordinal)),
                  "Opt-in batch diagnostic event ordering never upgrades trust");
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
                var package = value.GetProperty("packages")[0];
                check(package.GetProperty("version").GetString() == a.Version &&
                      package.GetProperty("license").GetProperty("name").GetString() == a.License.Name &&
                      package.GetProperty("license").GetProperty("evidenceUrls")[0].GetString() == evidence[0],
                      "Batch receipt preserves the selected version and license evidence");
            }

            async Task Deny(string label, IReadOnlyList<ReleasePins> pins, string major,
                Func<ReleasePins, string, CancellationToken, Task<DownloadReceipt>> operation)
            {
                var outDir = Path.Combine(root, "case-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(outDir);
                File.WriteAllText(Path.Combine(outDir, "existing.txt"), "KEEP");
                var failed = false;
                try { await BatchReleaseDownloader.StageAsync(pins, major, outDir, operation, feedMajors); }
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
            {
                var repeatRejected = false;
                try { await BatchReleaseDownloader.StageAsync(all, "18", root, Download, feedMajors); }
                catch (IOException) { repeatRejected = true; }
                check(repeatRejected &&
                      File.Exists(Path.Combine(result.Directory, "pg18", a.AssetName)) &&
                      Directory.GetDirectories(root).Count(d => Path.GetFileName(d).StartsWith(
                          ".pgextwin-batch-", StringComparison.Ordinal)) == 0,
                      "Pre-existing completed batch is not overwritten or partially recreated");
            }

            // The 'all' option preserves each version's ZIP in its own PG subdirectory.
            var multiDir = Path.Combine(root, "cross-major");
            Directory.CreateDirectory(multiDir);
            var multi = await BatchReleaseDownloader.StageAsync(
                new[] { Pin("pg_cron", "15"), Pin("pg_cron", "18") }, "all", multiDir, Download, feedMajors);
            check(multi.Count == 2 &&
                  File.Exists(Path.Combine(multi.Directory, "pg15", Pin("pg_cron", "15").AssetName)) &&
                  File.Exists(Path.Combine(multi.Directory, "pg18", Pin("pg_cron", "18").AssetName)),
                  "Batch --pg all segregates original ZIPs by PostgreSQL version");

            // The signed feed determines the fleet size and major cohort.
            var fleetParent = Path.Combine(root, "expanded-signed-fleet");
            Directory.CreateDirectory(fleetParent);
            var fleetPins = Enumerable.Range(0, 17)
                .SelectMany(n => feedMajors
                    .Select(m => Pin("signedext" + n, m))).ToArray();
            var fleet = await BatchReleaseDownloader.StageAsync(
                fleetPins, "all", fleetParent, Download, feedMajors);
            using (var receipt = JsonDocument.Parse(File.ReadAllText(
                       Path.Combine(fleet.Directory, "DOWNLOAD-INFO.json"))))
                check(fleet.Count == 68 &&
                      receipt.RootElement.GetProperty("zipCount").GetInt32() == 68 &&
                      receipt.RootElement.GetProperty("packages").GetArrayLength() == 68 &&
                      !receipt.RootElement.GetProperty("signatureVerified").GetBoolean(),
                      "Original signed-Catalog fleet 17 x PG15-18 stages 68 integrity-only ZIPs");
            // Historical PG14 pins are outside the signed-feed cohort.
            var currentParent = Path.Combine(root, "pg15-18-signed-feed");
            Directory.CreateDirectory(currentParent);
            var currentPins = feedMajors
                .Select(pg => Pin("pg_cron", pg)).ToArray();
            var currentBatch = await BatchReleaseDownloader.StageAsync(
                currentPins, "all", currentParent, Download,
                approvedMajors: feedMajors);
            check(currentBatch.Count == 4 &&
                  !Directory.Exists(Path.Combine(currentBatch.Directory, "pg14")) &&
                  File.Exists(Path.Combine(currentBatch.Directory, "pg18", currentPins[^1].AssetName)),
                "signed PG15-18 cohort selects four ZIPs, never PG14");
            var eolDenied = false;
            try
            {
                await BatchReleaseDownloader.StageAsync(
                    new[] { Pin("pg_cron", "14") }, "14", currentParent, Download,
                    approvedMajors: feedMajors);
            }
            catch (InvalidDataException) { eolDenied = true; }
            check(eolDenied, "PG14 denied by signed cohort even though historical pin exists");
            // An 18th extension joins only through the signed Catalog intake.
            // This adapter does not independently promote its Release or signature.
            var expandedRoot = Path.Combine(root, "signed-fleet-18");
            Directory.CreateDirectory(expandedRoot);
            var expanded = await BatchReleaseDownloader.StageAsync(
                fleetPins.Concat(feedMajors
                    .Select(pg => Pin("signedext17", pg))).ToArray(),
                "all", expandedRoot, Download, feedMajors);
            check(expanded.Count == 72, "Signer-approved 18th extension capacity is not hardcoded at 17");
            await Deny("Reject fleet resource ceiling above 128 identities",
                Enumerable.Range(0, 129).Select(n => Pin("synthetic" + n, "18")).ToArray(),
                "18", Download);
            var pg19Dir = Path.Combine(root, "signed-pg19-cohort");
            Directory.CreateDirectory(pg19Dir);
            var pg19 = await BatchReleaseDownloader.StageAsync(
                new[] { Pin("futureext", "19") }, "19", pg19Dir, Download,
                approvedMajors: new[] { "15", "16", "17", "18", "19" });
            check(pg19.Count == 1 && File.Exists(Path.Combine(pg19.Directory, "pg19",
                Pin("futureext", "19").AssetName)),
                "Future PG19 succeeds only with an explicitly supplied verified major cohort");

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
