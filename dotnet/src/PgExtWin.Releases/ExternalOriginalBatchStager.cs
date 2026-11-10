using System.Security.Cryptography;

namespace PgExtWin.Releases;

/// <summary>
/// Nonpublishing external original ZIP batch engine. The caller must first
/// establish independent signed Catalog admission; this internal type does
/// NOT authenticate caller-supplied pins. The CLI reaches it only through the
/// current Catalog latest-pin resolver and signed-admission verifier.
/// </summary>
internal static class ExternalOriginalBatchStager
{
    internal static async Task<BatchReleaseDownloader.BatchResult> StageAsync(
        IReadOnlyList<ExternalOriginalPin> pins, string pgSelection, string outputParent,
        Func<ExternalOriginalPin, string, CancellationToken, Task<DownloadReceipt>> downloadOne,
        CancellationToken token = default,
        Func<CancellationToken, Task>? confirmAdmissionFresh = null)
    {
        if (pgSelection is not ("14" or "15" or "16" or "17" or "18" or "all") ||
            pins is null || pins.Count is < 1 or > 1000 || downloadOne is null)
            throw new InvalidDataException("Invalid external batch selection");

        // Preflight every original pin before staging or any network request.
        // One failed/unauthorized future admission MUST fail the entire batch;
        // there is never a silent lower-priority fallback.
        var identities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var destinations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pin in pins)
        {
            ExternalProviderAssetTransport.ValidatePin(pin);
            if (pgSelection != "all" && pin.PgMajor != pgSelection)
                throw new InvalidDataException("Unrequested external PostgreSQL major");
            if (!identities.Add(pin.SourceRepo + ":" + pin.ReleaseId + ":" + pin.AssetId) ||
                !destinations.Add("pg" + pin.PgMajor + "/" + pin.Extension + "/" +
                    pin.AssetName))
                throw new InvalidDataException("Duplicate external original asset or destination");
        }

        var outputName = pgSelection == "all" ? "pgextwin-external-all"
            : "pgextwin-external-pg" + pgSelection;
        var transaction = new AtomicOriginalBatchDirectory(outputParent, outputName);
        try
        {
            long bytes = 0;
            foreach (var pin in pins)
            {
                token.ThrowIfCancellationRequested();
                // The signed permission can expire while an earlier asset is fetched.
                // Recheck immediately before each new original-provider GET.
                if (confirmAdmissionFresh is not null)
                    await confirmAdmissionFresh(token);
                var directory = Path.Combine(transaction.StageDirectory,
                    "pg" + pin.PgMajor, pin.Extension);
                Directory.CreateDirectory(directory);
                var receipt = await downloadOne(pin, directory, token);
                var expected = Path.Combine(directory, pin.AssetName);
                if (receipt.VerificationLevel != "INTEGRITY_ONLY" ||
                    receipt.RepositoryId != pin.RepositoryId ||
                    receipt.ReleaseId != pin.ReleaseId ||
                    receipt.AssetId != pin.AssetId ||
                    receipt.Sha256 != pin.OriginalSha256 ||
                    receipt.Size != pin.OriginalBytes ||
                    !string.Equals(Path.GetFullPath(receipt.FilePath),
                        Path.GetFullPath(expected), StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("External original batch receipt substitution");
                var file = new FileInfo(expected);
                if (!file.Exists ||
                    (file.Attributes & FileAttributes.ReparsePoint) != 0 ||
                    file.Length != pin.OriginalBytes)
                    throw new InvalidDataException("External original batch missing/linked/wrong length");
                // Rehash the actual file at the stage path, even after a
                // downloader returned a successful receipt.
                var actual = await File.ReadAllBytesAsync(expected, token);
                ExternalOriginalZipIntegrity.Verify(actual, pin.OriginalBytes,
                    pin.OriginalSha256);
                bytes = checked(bytes + file.Length);
            }

            // A long final GET may cross the admission deadline. Never commit
            // partially or wholly expired source bytes to the user-visible path.
            token.ThrowIfCancellationRequested();
            if (confirmAdmissionFresh is not null)
                await confirmAdmissionFresh(token);
            var completed = transaction.Commit();
            return new BatchReleaseDownloader.BatchResult(completed, pins.Count, bytes);
        }
        finally { transaction.Dispose(); }
    }
}
