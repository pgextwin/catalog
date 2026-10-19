using System.Security.Cryptography;
using System.Text.Json;
using PgExtWin.Catalog;

namespace PgExtWin.Releases;

/// <summary>
/// Downloads all selected ORIGINAL ZIP assets without repackaging, installing,
/// signing, attesting or granting trust. A staging folder is published by one
/// directory rename only after every exact-byte SHA256 check succeeds.
/// </summary>
public static class BatchReleaseDownloader
{
    public sealed record BatchResult(string Directory, int Count, long Bytes,
        string VerificationLevel = "INTEGRITY_ONLY");

    public static async Task<BatchResult> RunAsync(
        string catalogDirectory, string policyFile, string policyDigest,
        string pgSelection, string outputParent, ReadOnlyReleaseDownloader downloader,
        CancellationToken cancellationToken = default, bool usePinnedBrowserTransport = false)
    {
        if (pgSelection is not ("14" or "15" or "16" or "17" or "18" or "all"))
            throw new InvalidDataException("Batch PG selection must be 14, 15, 16, 17, 18 or all");
        var records = CatalogReader.LoadLocal(catalogDirectory);
        // v0.2 operates on the exact 14-extension production fleet. Never silently
        // make a partial 'all' selection from a broken or incomplete Catalog.
        if (records.Count != 14 || records.Select(r => r.Name).Distinct(StringComparer.Ordinal).Count() != 14)
            throw new InvalidDataException("Batch requires an intact 14-extension Catalog");
        var majors = pgSelection == "all"
            ? new[] { "14", "15", "16", "17", "18" } : new[] { pgSelection };
        var pins = new List<ReleasePins>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var major in majors)
        {
            foreach (var record in records.OrderBy(r => r.Name, StringComparer.Ordinal))
            {
                var pin = PinnedReleaseSelector.FromLocalFiles(
                    catalogDirectory, policyFile, policyDigest, record.Name, major);
                if (pin.PgMajor != major || pin.Extension != record.Name ||
                    !seen.Add("pg" + major + "/" + pin.AssetName))
                    throw new InvalidDataException("Batch contains substituted or duplicate ZIP entry");
                pins.Add(pin);
            }
        }
        if (pins.Count != records.Count * majors.Length)
            throw new InvalidDataException("Incomplete batch selection");
        // In one-line mode only, original ZIP bytes are fetched from the exact
        // fixed GitHub browser URLs instead of mutable/rate-limited REST calls.
        // Numeric IDs remain pinned by the cryptographically hashed baked policy
        // but are explicitly NOT asserted to have been re-queried from the API.
        using var browser = usePinnedBrowserTransport ? new PinnedBrowserDownloader() : null;
        return await StageAsync(pins, pgSelection, outputParent,
            (pin, folder, token) => usePinnedBrowserTransport
                ? browser!.DownloadAsync(pin, folder, token)
                : downloader.DownloadAsync(pin, folder, token),
            cancellationToken, metadataVerified: !usePinnedBrowserTransport);
    }

    // Pure transaction adapter: production always calls the existing strict
    // Release downloader; tests supply only synthetic bytes and receipts.
    public static async Task<BatchResult> StageAsync(
        IReadOnlyList<ReleasePins> pins, string pgSelection, string outputParent,
        Func<ReleasePins, string, CancellationToken, Task<DownloadReceipt>> downloadOne,
        CancellationToken cancellationToken = default, bool metadataVerified = true)
    {
        if (pgSelection is not ("14" or "15" or "16" or "17" or "18" or "all") ||
            pins.Count == 0 || pins.Count > 70 || downloadOne is null)
            throw new InvalidDataException("Invalid batch selection");
        var majors = pgSelection == "all"
            ? new HashSet<string>(new[] { "14", "15", "16", "17", "18" }, StringComparer.Ordinal)
            : new HashSet<string>(new[] { pgSelection }, StringComparer.Ordinal);
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pin in pins)
        {
            if (!majors.Contains(pin.PgMajor) ||
                !System.Text.RegularExpressions.Regex.IsMatch(
                    pin.Extension, @"\A[a-z][a-z0-9_]*\z") ||
                !PinnedReleaseSelector.SafeAssetName(pin.AssetName) ||
                !pin.AssetName.StartsWith(pin.Extension + "-", StringComparison.Ordinal) ||
                !pin.AssetName.EndsWith("-pg" + pin.PgMajor + "-windows-x64.zip", StringComparison.Ordinal) ||
                !System.Text.RegularExpressions.Regex.IsMatch(pin.AssetSha256, @"\A[0-9a-f]{64}\z") ||
                !keys.Add("pg" + pin.PgMajor + "/" + pin.AssetName))
                throw new InvalidDataException("Unsafe, duplicate, or mismatched batch ZIP");
        }

        var parent = Path.GetFullPath(outputParent);
        if (!System.IO.Directory.Exists(parent))
            throw new DirectoryNotFoundException("Batch output parent must already exist");
        for (DirectoryInfo? dir = new(parent); dir is not null; dir = dir.Parent)
            if ((dir.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Batch output path may not contain links");
        var outputName = pgSelection == "all" ? "pgextwin-pg14-18" : "pgextwin-pg" + pgSelection;
        var final = Path.Combine(parent, outputName);
        if (System.IO.Directory.EnumerateFileSystemEntries(parent).Any(
            path => string.Equals(Path.GetFileName(path), outputName,
                StringComparison.OrdinalIgnoreCase)))
            throw new IOException("Batch output already exists; no overwrite");

        var stage = Path.Combine(parent, ".pgextwin-batch-" + Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(stage);
        try
        {
            var rows = new List<object>();
            long total = 0;
            foreach (var pin in pins)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var majorDir = Path.Combine(stage, "pg" + pin.PgMajor);
                System.IO.Directory.CreateDirectory(majorDir);
                var receipt = await downloadOne(pin, majorDir, cancellationToken);
                var expected = Path.Combine(majorDir, pin.AssetName);
                if (!string.Equals(Path.GetFullPath(receipt.FilePath),
                        Path.GetFullPath(expected), StringComparison.OrdinalIgnoreCase) ||
                    receipt.Sha256 != pin.AssetSha256 ||
                    receipt.VerificationLevel != "INTEGRITY_ONLY" ||
                    receipt.RepositoryId != pin.RepositoryId ||
                    receipt.ReleaseId != pin.ReleaseId ||
                    !pin.AssetIds.TryGetValue(pin.AssetName, out var assetId) ||
                    receipt.AssetId != assetId)
                    throw new InvalidDataException("Batch download receipt identity mismatch");
                var file = new FileInfo(expected);
                if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0 ||
                    file.Length <= 0 || file.Length > ReadOnlyReleaseDownloader.MaxAssetBytes ||
                    file.Length != receipt.Size)
                    throw new InvalidDataException("Invalid batch ZIP size or link");
                await using var stream = new FileStream(expected, FileMode.Open, FileAccess.Read, FileShare.Read);
                var rehash = Convert.ToHexStringLower(
                    await SHA256.HashDataAsync(stream, cancellationToken));
                if (rehash != pin.AssetSha256)
                    throw new InvalidDataException("Original ZIP changed after download");
                total = checked(total + file.Length);
                rows.Add(new {
                    extension = pin.Extension,
                    pgMajor = pin.PgMajor,
                    relativePath = "pg" + pin.PgMajor + "/" + pin.AssetName,
                    sha256 = rehash,
                    bytes = file.Length,
                    repositoryId = pin.RepositoryId,
                    releaseId = pin.ReleaseId,
                    assetId
                });
            }
            var info = new {
                schemaVersion = "pgextwin-cli-batch-download/v1",
                source = metadataVerified ? "EXTERNALLY_PINNED_LOCAL_CATALOG" : "CLI_PINNED_HISTORICAL_CANDIDATE_POLICY",
                releaseMetadataVerified = metadataVerified,
                verificationLevel = "INTEGRITY_ONLY",
                signatureVerified = false,
                provenanceVerified = false,
                publicationAuthorized = false,
                distributionAuthorized = false,
                installAuthorized = false,
                zipCount = rows.Count,
                packages = rows
            };
            var receiptPath = Path.Combine(stage, "DOWNLOAD-INFO.json");
            await File.WriteAllTextAsync(receiptPath, JsonSerializer.Serialize(info), cancellationToken);
            // Directory rename on the same volume: no partially visible final batch.
            if (File.Exists(final) || System.IO.Directory.Exists(final))
                throw new IOException("Batch output was created concurrently; no overwrite");
            System.IO.Directory.Move(stage, final);
            return new BatchResult(final, rows.Count, total);
        }
        finally
        {
            if (System.IO.Directory.Exists(stage))
                System.IO.Directory.Delete(stage, recursive: true);
        }
    }
}
