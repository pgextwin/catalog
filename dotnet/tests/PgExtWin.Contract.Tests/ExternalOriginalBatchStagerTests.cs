using System.IO.Compression;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using PgExtWin.Releases;

// All ZIPs here are synthetic, no provider HTTP/authorization is exercised.
internal static class ExternalOriginalBatchStagerTests
{
    private static byte[] SyntheticZip()
    {
        using var stream = new MemoryStream();
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry("README.txt");
            using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
            writer.Write("synthetic external original bytes");
        }
        return stream.ToArray();
    }

    private static ExternalOriginalPin Pin(string extension, string repo, string asset,
        long assetId, byte[] bytes)
    {
        const string tag = "v1.2.3";
        return new ExternalOriginalPin(extension, "18", repo, 12345, tag,
            56789, asset, assetId, bytes.LongLength,
            Convert.ToHexStringLower(SHA256.HashData(bytes)),
            "https://github.com/" + repo + "/releases/download/" + tag + "/" + asset);
    }

    private static async Task<DownloadReceipt> Save(
        ExternalOriginalPin pin, string folder, byte[] bytes, CancellationToken token)
    {
        var path = Path.Combine(folder, pin.AssetName);
        await File.WriteAllBytesAsync(path, bytes, token);
        return new DownloadReceipt(path, pin.OriginalSha256, pin.OriginalBytes,
            pin.RepositoryId, pin.ReleaseId, pin.AssetId);
    }

    private static async Task<bool> Rejects(Func<Task> action)
    {
        try { await action(); return false; }
        catch (Exception ex) when (ex is InvalidDataException or IOException
            or ArgumentException or UnauthorizedAccessException)
        { return true; }
    }

    public static async Task RunAsync(Action<bool, string> check)
    {
        var root = Path.Combine(Path.GetTempPath(),
            "pgextwin-external-atomic-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var bytes = SyntheticZip();
            var pins = new[]
            {
                Pin("oracle_fdw", "laurenz/oracle_fdw",
                    "oracle_fdw-1.2.3-pg18-win64.zip", 11, bytes),
                Pin("pgvector", "andreiramani/pgvector_pgsql_windows",
                    "vector.v1.2.3-pg18.zip", 22, bytes),
                Pin("pg_trickle", "trickle-labs/pg-trickle",
                    "pg_trickle-1.2.3-pg18-windows-amd64.zip", 33, bytes)
            };
            int transferred = 0;
            int permissionChecks = 0;
            var result = await ExternalOriginalBatchStager.StageAsync(
                pins, "18", root, async (p, d, t) =>
                {
                    transferred++;
                    return await Save(p, d, bytes, t);
                }, confirmAdmissionFresh: _ =>
                {
                    permissionChecks++;
                    return Task.CompletedTask;
                });
            check(result.Count == 3 && result.Bytes == bytes.LongLength * 3 &&
                  transferred == 3 && permissionChecks == pins.Length + 1 &&
                  pins.All(p =>
                  {
                      var file = Path.Combine(result.Directory,
                          "pg18", p.Extension, p.AssetName);
                      return File.Exists(file) && File.ReadAllBytes(file).SequenceEqual(bytes);
                  }), "Three provider originals atomically committed without repackaging");
            Directory.Delete(result.Directory, recursive: true);

            // A stale signing window must stop a later provider GET; the
            // earlier verified asset remains hidden in temporary staging.
            int expiredChecks = 0;
            int expiredDownloads = 0;
            check(await Rejects(async () =>
                await ExternalOriginalBatchStager.StageAsync(
                    pins, "18", root, (p, d, t) =>
                    {
                        expiredDownloads++;
                        return Save(p, d, bytes, t);
                    }, confirmAdmissionFresh: _ =>
                    {
                        if (++expiredChecks == 2)
                            throw new InvalidDataException("Synthetic admission expired before next GET");
                        return Task.CompletedTask;
                    })) && expiredChecks == 2 && expiredDownloads == 1 &&
                  Directory.GetFileSystemEntries(root).Length == 0,
                "Expired admission between provider GETs blocks next ZIP and rolls back all");

            // Expiry during the last download must deny the atomic commit.
            int finalChecks = 0;
            int finalDownloads = 0;
            check(await Rejects(async () =>
                await ExternalOriginalBatchStager.StageAsync(
                    pins, "18", root, (p, d, t) =>
                    {
                        finalDownloads++;
                        return Save(p, d, bytes, t);
                    }, confirmAdmissionFresh: _ =>
                    {
                        if (++finalChecks == pins.Length + 1)
                            throw new InvalidDataException("Synthetic admission expired before commit");
                        return Task.CompletedTask;
                    })) && finalChecks == pins.Length + 1 &&
                  finalDownloads == pins.Length &&
                  Directory.GetFileSystemEntries(root).Length == 0,
                "Expired admission before atomic commit rolls back all original ZIPs");

            int attempted = 0;
            check(await Rejects(async () =>
                await ExternalOriginalBatchStager.StageAsync(pins, "18", root,
                    async (p, d, t) =>
                    {
                        attempted++;
                        if (attempted == 2)
                            throw new InvalidDataException("Synthetic provider GET failure");
                        return await Save(p, d, bytes, t);
                    })) && attempted == 2 &&
                  Directory.GetFileSystemEntries(root).Length == 0,
                "Second provider failure rolls back all prior original ZIPs");

            int duplicateAttempts = 0;
            check(await Rejects(async () =>
                await ExternalOriginalBatchStager.StageAsync(
                    new[] { pins[0], pins[0] }, "18", root,
                    (p, d, t) =>
                    {
                        duplicateAttempts++;
                        return Save(p, d, bytes, t);
                    })) && duplicateAttempts == 0 &&
                  Directory.GetFileSystemEntries(root).Length == 0,
                "Duplicate provider asset identity rejected before any staging");

            int forgedAttempts = 0;
            var forged = pins[0] with { OriginalProviderUrl =
                "https://example.invalid/binary.zip" };
            check(await Rejects(async () =>
                await ExternalOriginalBatchStager.StageAsync(
                    new[] { pins[0], forged }, "18", root,
                    (p, d, t) =>
                    {
                        forgedAttempts++;
                        return Save(p, d, bytes, t);
                    })) && forgedAttempts == 0,
                "Whole batch preflight rejects forged URL before transfer");

            check(await Rejects(async () =>
                await ExternalOriginalBatchStager.StageAsync(
                    pins, "17", root, (p, d, t) => Save(p, d, bytes, t))) &&
                  Directory.GetFileSystemEntries(root).Length == 0,
                "Unrequested PG major is denied before touching output");

            check(await Rejects(async () =>
                await ExternalOriginalBatchStager.StageAsync(
                    pins, "18", root, async (p, d, t) =>
                    {
                        var receipt = await Save(p, d, bytes, t);
                        return receipt with { AssetId = receipt.AssetId + 10 };
                    })) && Directory.GetFileSystemEntries(root).Length == 0,
                "Wrong asset ID receipt rolls back stage without visible output");

            var altered = bytes.ToArray();
            altered[^8] ^= 0x01;
            check(await Rejects(async () =>
                await ExternalOriginalBatchStager.StageAsync(
                    pins, "18", root, (p, d, t) => Save(p, d, altered, t))) &&
                  Directory.GetFileSystemEntries(root).Length == 0,
                "ZIP digest mismatch rolls back entire stage");

            var existing = Path.Combine(root, "pgextwin-external-pg18");
            Directory.CreateDirectory(existing);
            File.WriteAllText(Path.Combine(existing, "KEEP.txt"), "unchanged");
            int collisionAttempts = 0;
            check(await Rejects(async () =>
                await ExternalOriginalBatchStager.StageAsync(
                    pins, "18", root, (p, d, t) =>
                    {
                        collisionAttempts++;
                        return Save(p, d, bytes, t);
                    })) && collisionAttempts == 0 &&
                  File.ReadAllText(Path.Combine(existing, "KEEP.txt")) == "unchanged",
                "Existing destination denied without network or overwrite");
            Directory.Delete(existing, recursive: true);

            // Mandatory adversarial test: tampering with the 1st staged ZIP during the 2nd GET
            // (atomic path replacement of same length) must result in full DENY and 0 published items.
            {
                var caseRoot = Path.Combine(root, "adv-tamper-during-second-get-replace");
                Directory.CreateDirectory(caseRoot);
                string? firstStagedPath = null;
                var tamperedSameLength = bytes.ToArray();
                tamperedSameLength[^8] ^= 0x01;
                var tempTampered = Path.Combine(root, "tampered-swap.zip");
                await File.WriteAllBytesAsync(tempTampered, tamperedSameLength);
                int gets = 0;
                check(await Rejects(async () =>
                    await ExternalOriginalBatchStager.StageAsync(
                        pins, "18", caseRoot, async (p, d, t) =>
                        {
                            gets++;
                            var receipt = await Save(p, d, bytes, t);
                            if (gets == 1)
                                firstStagedPath = receipt.FilePath;
                            else if (gets == 2 && firstStagedPath is not null)
                                File.Move(tempTampered, firstStagedPath, overwrite: true);
                            return receipt;
                        })) && Directory.GetFileSystemEntries(caseRoot).Length == 0,
                    "Adversarial: modifying 1st staged ZIP during 2nd GET denies entire batch with 0 published");
                if (File.Exists(tempTampered)) File.Delete(tempTampered);
            }

            // Adversarial: direct overwrite attempt on 1st staged ZIP during 2nd GET is blocked/denied.
            {
                var caseRoot = Path.Combine(root, "adv-tamper-during-second-get-write");
                Directory.CreateDirectory(caseRoot);
                string? firstStagedPath = null;
                var tampered = bytes.ToArray();
                tampered[^8] ^= 0x01;
                int gets = 0;
                check(await Rejects(async () =>
                    await ExternalOriginalBatchStager.StageAsync(
                        pins, "18", caseRoot, async (p, d, t) =>
                        {
                            gets++;
                            var receipt = await Save(p, d, bytes, t);
                            if (gets == 1)
                                firstStagedPath = receipt.FilePath;
                            else if (gets == 2 && firstStagedPath is not null)
                                await File.WriteAllBytesAsync(firstStagedPath, tampered, t);
                            return receipt;
                        })) && Directory.GetFileSystemEntries(caseRoot).Length == 0,
                    "Adversarial: overwriting 1st staged ZIP during 2nd GET denies entire batch with 0 published");
            }

            // Adversarial: tampering during pre-commit Catalog HEAD / admission recheck window
            // (after all GETs completed) must still be caught before directory rename.
            {
                var caseRoot = Path.Combine(root, "adv-tamper-during-precommit-recheck");
                Directory.CreateDirectory(caseRoot);
                string? firstStagedPath = null;
                var tamperedSameLength = bytes.ToArray();
                tamperedSameLength[^8] ^= 0x01;
                var tempTampered = Path.Combine(root, "tampered-precommit.zip");
                await File.WriteAllBytesAsync(tempTampered, tamperedSameLength);
                int gets = 0;
                int checks = 0;
                check(await Rejects(async () =>
                    await ExternalOriginalBatchStager.StageAsync(
                        pins, "18", caseRoot, async (p, d, t) =>
                        {
                            gets++;
                            var receipt = await Save(p, d, bytes, t);
                            if (gets == 1)
                                firstStagedPath = receipt.FilePath;
                            return receipt;
                        },
                        confirmAdmissionFresh: _ =>
                        {
                            if (++checks == pins.Length + 1 && firstStagedPath is not null)
                                File.Move(tempTampered, firstStagedPath, overwrite: true);
                            return Task.CompletedTask;
                        })) && Directory.GetFileSystemEntries(caseRoot).Length == 0,
                    "Adversarial: tampering 1st staged ZIP during pre-commit recheck denies with 0 published");
                if (File.Exists(tempTampered)) File.Delete(tempTampered);
            }

            // Adversarial: extra file planted in stage directory during 2nd GET -> DENY, 0 published.
            {
                var caseRoot = Path.Combine(root, "adv-extra-file");
                Directory.CreateDirectory(caseRoot);
                int gets = 0;
                check(await Rejects(async () =>
                    await ExternalOriginalBatchStager.StageAsync(
                        pins, "18", caseRoot, async (p, d, t) =>
                        {
                            gets++;
                            var receipt = await Save(p, d, bytes, t);
                            if (gets == 2)
                                await File.WriteAllTextAsync(Path.Combine(d, "extra.dll"), "malicious", t);
                            return receipt;
                        })) && Directory.GetFileSystemEntries(caseRoot).Length == 0,
                    "Adversarial: extra file in stage directory denies entire batch with 0 published");
            }

            // Adversarial: extra directory planted in stage directory during 2nd GET -> DENY, 0 published.
            {
                var caseRoot = Path.Combine(root, "adv-extra-dir");
                Directory.CreateDirectory(caseRoot);
                int gets = 0;
                check(await Rejects(async () =>
                    await ExternalOriginalBatchStager.StageAsync(
                        pins, "18", caseRoot, async (p, d, t) =>
                        {
                            gets++;
                            var receipt = await Save(p, d, bytes, t);
                            if (gets == 2)
                                Directory.CreateDirectory(Path.Combine(d, "unexpected-subdir"));
                            return receipt;
                        })) && Directory.GetFileSystemEntries(caseRoot).Length == 0,
                    "Adversarial: extra directory in stage denies entire batch with 0 published");
            }

            // Adversarial: hardlink to staged ZIP created outside stage -> LinkCount > 1 DENY, 0 published.
            {
                var caseRoot = Path.Combine(root, "adv-hardlink");
                Directory.CreateDirectory(caseRoot);
                var hardlinkOutside = Path.Combine(root, "hardlink-alias.zip");
                int gets = 0;
                check(await Rejects(async () =>
                    await ExternalOriginalBatchStager.StageAsync(
                        pins, "18", caseRoot, async (p, d, t) =>
                        {
                            gets++;
                            var receipt = await Save(p, d, bytes, t);
                            if (gets == 1)
                                File.CreateHardLink(hardlinkOutside, receipt.FilePath);
                            return receipt;
                        })) && Directory.GetFileSystemEntries(caseRoot).Length == 0,
                    "Adversarial: hardlinked staged ZIP denies entire batch with 0 published");
                if (File.Exists(hardlinkOutside)) File.Delete(hardlinkOutside);
            }

            // Adversarial: symbolic link planted in stage directory -> DENY, 0 published.
            {
                var caseRoot = Path.Combine(root, "adv-symlink");
                Directory.CreateDirectory(caseRoot);
                var targetFile = Path.Combine(root, "symlink-target.zip");
                await File.WriteAllBytesAsync(targetFile, bytes);
                int gets = 0;
                bool canCreateSymlink = true;
                var rejected = await Rejects(async () =>
                    await ExternalOriginalBatchStager.StageAsync(
                        pins, "18", caseRoot, async (p, d, t) =>
                        {
                            gets++;
                            var receipt = await Save(p, d, bytes, t);
                            if (gets == 2)
                            {
                                try
                                {
                                    File.CreateSymbolicLink(Path.Combine(d, "link.zip"), targetFile);
                                }
                                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
                                {
                                    canCreateSymlink = false;
                                    throw;
                                }
                            }
                            return receipt;
                        }));
                check(rejected && Directory.GetFileSystemEntries(caseRoot).Length == 0,
                    canCreateSymlink
                        ? "Adversarial: symbolic link in stage denies entire batch with 0 published"
                        : "Adversarial: symlink creation blocked by OS privilege without leaking stage");
                if (File.Exists(targetFile)) File.Delete(targetFile);
            }

            // Adversarial: ACL / permission anomaly on staged ZIP -> DENY, 0 published.
            {
                var caseRoot = Path.Combine(root, "adv-acl-anomaly");
                Directory.CreateDirectory(caseRoot);
                string? firstStagedPath = null;
                int gets = 0;
                check(await Rejects(async () =>
                    await ExternalOriginalBatchStager.StageAsync(
                        pins, "18", caseRoot, async (p, d, t) =>
                        {
                            gets++;
                            var receipt = await Save(p, d, bytes, t);
                            if (gets == 1)
                            {
                                firstStagedPath = receipt.FilePath;
                            }
                            else if (gets == 2 && firstStagedPath is not null)
                            {
                                if (OperatingSystem.IsWindows())
                                {
                                    var security = new FileInfo(firstStagedPath).GetAccessControl();
                                    security.AddAccessRule(new FileSystemAccessRule(
                                        new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                                        FileSystemRights.Read,
                                        AccessControlType.Allow));
                                    new FileInfo(firstStagedPath).SetAccessControl(security);
                                }
                                else
                                {
                                    File.SetUnixFileMode(firstStagedPath,
                                        UnixFileMode.UserRead | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
                                }
                            }
                            return receipt;
                        })) && Directory.GetFileSystemEntries(caseRoot).Length == 0,
                    "Adversarial: ACL/permission anomaly on staged ZIP denies entire batch with 0 published");
            }

            // Adversarial: destination created concurrently during 2nd GET -> create-only commit denies without overwrite.
            {
                var caseRoot = Path.Combine(root, "adv-concurrent-destination");
                Directory.CreateDirectory(caseRoot);
                var raceDest = Path.Combine(caseRoot, "pgextwin-external-pg18");
                int gets = 0;
                check(await Rejects(async () =>
                    await ExternalOriginalBatchStager.StageAsync(
                        pins, "18", caseRoot, async (p, d, t) =>
                        {
                            gets++;
                            var receipt = await Save(p, d, bytes, t);
                            if (gets == 2)
                            {
                                Directory.CreateDirectory(raceDest);
                                await File.WriteAllTextAsync(Path.Combine(raceDest, "KEEP.txt"), "race", t);
                            }
                            return receipt;
                        })) &&
                      File.ReadAllText(Path.Combine(raceDest, "KEEP.txt")) == "race" &&
                      Directory.GetDirectories(caseRoot).Count(d =>
                          Path.GetFileName(d).StartsWith(".pgextwin-batch-", StringComparison.Ordinal)) == 0,
                    "Adversarial: concurrent destination collision refuses overwrite and cleans stage");
            }

            // Windows-native adversarial verification: verify held FileShare.None + locked DACLs
            // block in-place overwrite, delete, and atomic replace during 2nd GET and verify-to-rename.
            if (OperatingSystem.IsWindows())
            {
                var caseRoot = Path.Combine(root, "adv-windows-native-protection");
                Directory.CreateDirectory(caseRoot);
                string? firstStagedPath = null;
                string? stageSubdir = null;
                bool writeBlocked = false;
                bool deleteBlocked = false;
                bool moveBlocked = false;
                bool lockedDirCreateBlocked = false;
                var swapSrc = Path.Combine(root, "win-swap.zip");
                await File.WriteAllBytesAsync(swapSrc, bytes);
                int gets = 0;
                int checks = 0;
                var resultWin = await ExternalOriginalBatchStager.StageAsync(
                    pins, "18", caseRoot, async (p, d, t) =>
                    {
                        gets++;
                        var receipt = await Save(p, d, bytes, t);
                        if (gets == 1)
                        {
                            firstStagedPath = receipt.FilePath;
                            stageSubdir = d;
                        }
                        else if (gets == 2 && firstStagedPath is not null)
                        {
                            try { await File.WriteAllBytesAsync(firstStagedPath, bytes, t); }
                            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                            { writeBlocked = true; }
                            try { File.Delete(firstStagedPath); }
                            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                            { deleteBlocked = true; }
                            try { File.Move(swapSrc, firstStagedPath, overwrite: true); }
                            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                            { moveBlocked = true; }
                        }
                        return receipt;
                    },
                    confirmAdmissionFresh: _ =>
                    {
                        if (++checks == pins.Length + 1 && stageSubdir is not null)
                        {
                            try { File.WriteAllText(Path.Combine(stageSubdir, "inject.txt"), "x"); }
                            catch (UnauthorizedAccessException)
                            { lockedDirCreateBlocked = true; }
                        }
                        return Task.CompletedTask;
                    });
                check(writeBlocked && deleteBlocked && moveBlocked && lockedDirCreateBlocked,
                    "Windows native: handle share-mode + stage ACL block overwrite, delete, swap, and locked-dir injection");
                Directory.Delete(resultWin.Directory, recursive: true);
                if (File.Exists(swapSrc)) File.Delete(swapSrc);
            }
        }
        finally { Directory.Delete(root, recursive: true); }
    }
}
