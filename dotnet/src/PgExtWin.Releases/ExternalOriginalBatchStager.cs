using System.Security.Cryptography;

namespace PgExtWin.Releases;

/// <summary>
/// Nonpublishing external original file batch engine. The caller must first
/// select license-reviewed Catalog byte pins (or historical signed admission).
/// This internal type does not authenticate caller-supplied pins.
/// </summary>
internal static class ExternalOriginalBatchStager
{
    internal static async Task<BatchReleaseDownloader.BatchResult> StageAsync(
        IReadOnlyList<ExternalOriginalPin> pins, string pgSelection, string outputParent,
        Func<ExternalOriginalPin, string, CancellationToken, Task<DownloadReceipt>> downloadOne,
        CancellationToken token = default,
        Func<CancellationToken, Task>? confirmAdmissionFresh = null,
        string? outputLabel = null, bool standaloneSelection = false)
    {
        if (pins is null || downloadOne is null)
            throw new InvalidDataException("Invalid external batch selection");

        // Preflight every original pin before staging or any network request.
        // One failed/unauthorized future admission MUST fail the entire batch;
        // there is never a silent lower-priority fallback.
        ValidateBatchPins(pins, pgSelection, standaloneSelection);

        var outputName = "pgextwin-external-" +
            (outputLabel is null ? "" : outputLabel + "-") +
            (pgSelection == "all" ? "all" : "pg" + pgSelection);
        var transaction = new AtomicOriginalBatchDirectory(outputParent, outputName);
        var staged = new List<(ExternalOriginalPin Pin, string Path, FileStream Stream, AtomicStageGuard.FileIdentity Identity)>(pins.Count);
        var expectedDirectories = new HashSet<string>(AtomicStageGuard.PathComparer);
        var expectedFiles = new Dictionary<string, AtomicStageGuard.StagedFileExpectation>(AtomicStageGuard.PathComparer);
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

                var pgDirectory = Path.GetFullPath(
                    Path.Combine(transaction.StageDirectory, MajorDirectory(pin)));
                var directory = Path.GetFullPath(
                    Path.Combine(pgDirectory, pin.Extension));
                AtomicStageGuard.CreateOwnerOnlySubdirectory(transaction.StageDirectory, directory);
                expectedDirectories.Add(pgDirectory);
                expectedDirectories.Add(directory);

                var receipt = await downloadOne(pin, directory, token);
                var expected = Path.GetFullPath(Path.Combine(directory, pin.AssetName));
                if (receipt.VerificationLevel != "INTEGRITY_ONLY" ||
                    receipt.RepositoryId != pin.RepositoryId ||
                    receipt.ReleaseId != pin.ReleaseId ||
                    receipt.AssetId != pin.AssetId ||
                    receipt.Sha256 != pin.OriginalSha256 ||
                    receipt.Size != pin.OriginalBytes ||
                    !AtomicStageGuard.PathComparer.Equals(
                        Path.GetFullPath(receipt.FilePath), expected))
                    throw new InvalidDataException("External original batch receipt substitution");

                var file = new FileInfo(expected);
                if (!file.Exists ||
                    (file.Attributes & FileAttributes.ReparsePoint) != 0 ||
                    file.Length != pin.OriginalBytes)
                    throw new InvalidDataException("External original batch missing/linked/wrong length");

                // Lock file ACL/mode and retain an exclusive read handle with
                // volume/file-ID binding before verifying its staged bytes.
                AtomicStageGuard.LockStagedFile(expected);
                var (stream, identity) = AtomicStageGuard.OpenAndVerifyIdentity(
                    expected, transaction.StageDirectory);
                staged.Add((pin, expected, stream, identity));
                if (!expectedFiles.TryAdd(expected,
                        new AtomicStageGuard.StagedFileExpectation(pin.OriginalBytes, stream, identity)))
                    throw new InvalidDataException("Duplicate staged destination path");

                if (pin.Provider != ExternalProviderAssetTransport.StandaloneProvider)
                {
                    var actual = await ReadHeldStreamExactAsync(stream, pin.OriginalBytes, token);
                    ExternalOriginalZipIntegrity.Verify(actual, pin);
                }
                bytes = checked(bytes + pin.OriginalBytes);
            }

            // Pre-commit full re-verification:
            // 1. Re-validate all batch pins and lock stage directories against mutation.
            // 2. Re-scan the entire stage tree (file IDs, volume IDs, hardlinks,
            //    reparse points, ACLs/modes, and absence of extra files/directories).
            // 3. Re-verify SHA256, ZIP structure, and CRC32 across every staged file.
            // 4. Re-confirm admission pre-authorization, expiry, and Catalog HEAD.
            // 5. Re-verify stage invariants across handle release until create-only rename.
            token.ThrowIfCancellationRequested();
            ValidateBatchPins(pins, pgSelection, standaloneSelection);
            AtomicStageGuard.LockStageDirectoriesForCommit(
                transaction.StageDirectory, expectedDirectories);
            AtomicStageGuard.VerifyStageTreeAndIdentities(
                transaction.StageDirectory, outputParent, expectedFiles, expectedDirectories,
                directoriesLocked: true, verifyOpenHandles: true);

            long reverifiedBytes = 0;
            foreach (var (pin, _, stream, _) in staged)
            {
                token.ThrowIfCancellationRequested();
                if (pin.Provider == ExternalProviderAssetTransport.StandaloneProvider)
                {
                    if (stream.Length != pin.OriginalBytes ||
                        Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, token)) != pin.OriginalSha256)
                        throw new InvalidDataException("Staged original differs from pinned SHA256 or size");
                }
                else
                {
                    var reverified = await ReadHeldStreamExactAsync(stream, pin.OriginalBytes, token);
                    ExternalOriginalZipIntegrity.Verify(reverified, pin);
                }
                reverifiedBytes = checked(reverifiedBytes + pin.OriginalBytes);
            }
            if (reverifiedBytes != bytes || staged.Count != pins.Count)
                throw new InvalidDataException("Staged batch byte sum or count mismatch before commit");

            // A long final GET may cross the admission deadline or Catalog HEAD.
            // Never commit partially, tampered, or expired source bytes.
            token.ThrowIfCancellationRequested();
            if (confirmAdmissionFresh is not null)
                await confirmAdmissionFresh(token);

            token.ThrowIfCancellationRequested();
            AtomicStageGuard.VerifyStageTreeAndIdentities(
                transaction.StageDirectory, outputParent, expectedFiles, expectedDirectories,
                directoriesLocked: true, verifyOpenHandles: true);

            // Release held file handles so Windows Directory.Move can rename the
            // stage root while locked stage ACLs continue protecting its contents.
            foreach (var entry in staged)
                entry.Stream.Dispose();

            AtomicStageGuard.VerifyStageTreeAndIdentities(
                transaction.StageDirectory, outputParent, expectedFiles, expectedDirectories,
                directoriesLocked: true, verifyOpenHandles: false);

            var completed = transaction.Commit();
            AtomicStageGuard.RestoreWritablePermissions(completed, writableFiles: true);
            return new BatchReleaseDownloader.BatchResult(completed, pins.Count, bytes);
        }
        finally
        {
            foreach (var entry in staged)
                entry.Stream.Dispose();
            transaction.Dispose();
        }
    }

    private static string MajorDirectory(ExternalOriginalPin pin) =>
        pin.PgMajor == "any" ? "any" : "pg" + pin.PgMajor;

    private static void ValidateBatchPins(IReadOnlyList<ExternalOriginalPin> pins, string pgSelection,
        bool standaloneSelection)
    {
        if ((!standaloneSelection && pgSelection != "all" &&
                !ExternalProviderAssetTransport.IsExternalZipMajor(pgSelection)) ||
            pins.Count is < 1 or > 1000)
            throw new InvalidDataException("Invalid external batch selection");

        var identities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var destinations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pin in pins)
        {
            ExternalProviderAssetTransport.ValidatePin(pin);
            if (pgSelection != "all" && pin.PgMajor != pgSelection && pin.PgMajor != "any")
                throw new InvalidDataException("Unrequested external PostgreSQL major");
            if (!identities.Add(ExternalProviderAssetTransport.IsDirectHttps(pin) ? pin.OriginalProviderUrl
                    : pin.SourceRepo + ":" + pin.ReleaseId + ":" + pin.AssetId) ||
                !destinations.Add(MajorDirectory(pin) + "/" + pin.Extension + "/" +
                    pin.AssetName))
                throw new InvalidDataException("Duplicate external original asset or destination");
        }
    }

    private static async Task<byte[]> ReadHeldStreamExactAsync(
        FileStream stream, long expectedBytes, CancellationToken token)
    {
        if (stream.Length != expectedBytes)
            throw new InvalidDataException("Staged original ZIP length changed");
        if (expectedBytes is < 4 or > int.MaxValue)
            throw new InvalidDataException("Invalid staged original ZIP length");
        stream.Position = 0;
        var buffer = new byte[(int)expectedBytes];
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(offset), token);
            if (read == 0)
                throw new InvalidDataException("Staged original ZIP truncated during read");
            offset += read;
        }
        var extra = new byte[1];
        if (await stream.ReadAsync(extra.AsMemory(), token) != 0)
            throw new InvalidDataException("Staged original ZIP grew during read");
        return buffer;
    }
}
