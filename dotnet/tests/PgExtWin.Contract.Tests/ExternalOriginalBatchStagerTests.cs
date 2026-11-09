using System.IO.Compression;
using System.Security.Cryptography;
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
        catch (Exception ex) when (ex is InvalidDataException or IOException or ArgumentException)
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
        }
        finally { Directory.Delete(root, recursive: true); }
    }
}
