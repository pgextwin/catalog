using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using PgExtWin.Releases;

// Offline synthetic original bytes only: no HTTP, authentic signed source,
// formal Publisher admission, installation or external download permissions.
internal static class ExternalOriginalZipIntegrityTests
{
    private static byte[] Zip(params (string Name, string Content)[] files)
    {
        using var output = new MemoryStream();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, body) in files)
            {
                var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
                if (!name.EndsWith("/", StringComparison.Ordinal))
                {
                    using var writer = new StreamWriter(entry.Open(), Encoding.UTF8, leaveOpen: false);
                    writer.Write(body);
                }
            }
        }
        return output.ToArray();
    }

    private static byte[] ZipWithEntryAttributes(
        params (string Name, string Content, byte HostOs, uint ExternalAttributes)[] entries)
    {
        using var output = new MemoryStream();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, body, _, extAttr) in entries)
            {
                var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
                entry.ExternalAttributes = unchecked((int)extAttr);
                if (!name.EndsWith("/", StringComparison.Ordinal))
                {
                    using var writer = new StreamWriter(entry.Open(), Encoding.UTF8, leaveOpen: false);
                    writer.Write(body);
                }
            }
        }
        var bytes = output.ToArray();
        // Patch Central Directory File Header versionMadeBy upper byte (creating OS)
        // and externalAttributes for each entry in order.
        int index = 0;
        for (int i = 0; i <= bytes.Length - 46 && index < entries.Length; i++)
        {
            if (bytes[i] == 0x50 && bytes[i + 1] == 0x4b &&
                bytes[i + 2] == 0x01 && bytes[i + 3] == 0x02)
            {
                bytes[i + 5] = entries[index].HostOs;
                BinaryPrimitives.WriteUInt32LittleEndian(
                    bytes.AsSpan(i + 38, 4), entries[index].ExternalAttributes);
                index++;
            }
        }
        if (index != entries.Length)
            throw new InvalidOperationException("Failed to patch all central directory entries");
        return bytes;
    }

    private static byte[] PatchFirstEntryCrc32(byte[] original, uint newCrc32)
    {
        var mutated = (byte[])original.Clone();
        // Patch Local File Header CRC32 (offset +14).
        if (mutated.Length < 30 ||
            mutated[0] != 0x50 || mutated[1] != 0x4b ||
            mutated[2] != 0x03 || mutated[3] != 0x04)
            throw new InvalidOperationException("Expected local file header");
        BinaryPrimitives.WriteUInt32LittleEndian(mutated.AsSpan(14, 4), newCrc32);

        // Patch first Central Directory File Header CRC32 (offset +16).
        for (int i = 0; i <= mutated.Length - 46; i++)
        {
            if (mutated[i] == 0x50 && mutated[i + 1] == 0x4b &&
                mutated[i + 2] == 0x01 && mutated[i + 3] == 0x02)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(mutated.AsSpan(i + 16, 4), newCrc32);
                return mutated;
            }
        }
        throw new InvalidOperationException("Missing central directory header");
    }

    private static string Hash(byte[] bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static void Verify(byte[] bytes, long? size = null, string? sha = null) =>
        ExternalOriginalZipIntegrity.Verify(bytes, size ?? bytes.Length, sha ?? Hash(bytes));

    public static void Run(Action<bool, string> check, Action<Action, string> denies)
    {
        var normal = Zip(
            ("oracle_fdw.dll", "synthetic-original-test-binary"),
            ("sql/oracle_fdw--2.9.0.sql", "SELECT 1;"));
        var receipt = ExternalOriginalZipIntegrity.Verify(normal, normal.Length, Hash(normal));
        check(receipt.OriginalBytes == normal.Length &&
              receipt.OriginalSha256 == Hash(normal) && receipt.ArchiveMembers == 2 &&
              receipt.Scope == "INTEGRITY_ONLY_NOT_AUTHORIZED",
              "External original ZIP offline exact byte and member read succeeds without authority");

        // CRC32 standard vector (123456789 -> 0xCBF43926) and empty (0).
        check(ExternalOriginalZipIntegrity.ComputeCrc32("123456789"u8) == 0xCBF43926u,
            "IEEE CRC32 standard vector '123456789' equals 0xCBF43926");
        check(ExternalOriginalZipIntegrity.ComputeCrc32(ReadOnlySpan<byte>.Empty) == 0u,
            "IEEE CRC32 empty vector equals 0");

        var crcVectorZip = Zip(("vector.txt", "123456789"), ("empty.txt", ""), ("emptydir/", ""));
        Verify(crcVectorZip);
        check(true, "ZIP containing CRC32 standard vector, empty file, and empty directory passes");

        var tamperedCrcVector = PatchFirstEntryCrc32(crcVectorZip, 0xCBF43927u);
        denies(() => Verify(tamperedCrcVector),
            "External original ZIP entry CRC32 mismatch denied even when outer SHA256 matches");
        var emptyFileBadCrc = PatchFirstEntryCrc32(Zip(("empty.txt", "")), 1u);
        denies(() => Verify(emptyFileBadCrc),
            "External original ZIP empty file with non-zero CRC32 denied");
        var emptyDirBadCrc = PatchFirstEntryCrc32(Zip(("emptydir/", ""), ("ok.txt", "ok")), 1u);
        denies(() => Verify(emptyDirBadCrc),
            "External original ZIP empty directory with non-zero CRC32 denied");

        denies(() => Verify(normal, normal.Length + 1), "External original ZIP wrong pinned size denied");
        denies(() => Verify(normal, null, new string('0', 64)), "External original ZIP SHA substitution denied");
        denies(() => Verify(normal, null, "ABC"), "External original ZIP invalid digest denied");
        denies(() => Verify(normal, ExternalOriginalZipIntegrity.MaxOriginalBytes + 1),
            "External original ZIP oversized declared original denied");
        var tampered = (byte[])normal.Clone();
        tampered[20] ^= 0x10;
        denies(() => Verify(tampered, null, Hash(normal)), "External original ZIP corrupted original bytes denied");

        var html = Encoding.UTF8.GetBytes("<html>not a zip</html>");
        denies(() => Verify(html), "External original ZIP HTML replacement denied even with matching SHA");
        var broken = Encoding.UTF8.GetBytes("PK\u0003\u0004not-a-real-central-directory");
        denies(() => Verify(broken), "External original ZIP fake local header denied");
        denies(() => Verify(Zip(("../escape.dll", "malicious"))),
            "External original ZIP traversal member denied");
        denies(() => Verify(Zip(("/absolute.dll", "malicious"))),
            "External original ZIP absolute path denied");
        denies(() => Verify(Zip(("path\\escape.dll", "malicious"))),
            "External original ZIP Windows backslash traversal denied");
        denies(() => Verify(Zip(("file:stream", "malicious"))),
            "External original ZIP device/ADS path denied");
        denies(() => Verify(Zip(("dir/file.txt:Zone.Identifier", "malicious"))),
            "External original ZIP nested ADS path denied");
        denies(() => Verify(Zip(("SQL/EXT.sql", "a"), ("sql/ext.SQL", "b"))),
            "External original ZIP case-insensitive member collision denied");
        denies(() => Verify(Zip(("directory/", ""))),
            "External original ZIP directory-only payload denied");
        denies(() => Verify(Zip(("a/./b.sql", "a"))),
            "External original ZIP dot-segment path denied");

        // Additional path hardening fixtures.
        denies(() => Verify(Zip(("folder//", ""), ("ok.txt", "ok"))),
            "External original ZIP double trailing slash 'folder//' denied");
        denies(() => Verify(Zip(("a//b.txt", "a"))),
            "External original ZIP empty intermediate segment 'a//b.txt' denied");
        denies(() => Verify(Zip(("a", "file"), ("a/b", "child"))),
            "External original ZIP parent-child file collision ('a' then 'a/b') denied");
        denies(() => Verify(Zip(("a/b", "child"), ("a", "file"))),
            "External original ZIP reverse-order parent-child file collision ('a/b' then 'a') denied");
        denies(() => Verify(Zip(("a", "file"), ("a/b/", ""))),
            "External original ZIP file colliding with child directory denied");
        Verify(Zip(("a/", ""), ("a/b", "child")));
        Verify(Zip(("a/b", "child"), ("a/", "")));
        check(true, "Valid directory entry and child file pass in either order");
        denies(() => Verify(Zip(("NUL.txt", "bad"))),
            "External original ZIP Windows reserved device name NUL.txt denied");
        denies(() => Verify(Zip(("sub/CON/file.txt", "bad"))),
            "External original ZIP Windows reserved device name in directory component denied");
        denies(() => Verify(Zip(("com1.dll", "bad"))),
            "External original ZIP Windows reserved device name com1.dll denied");
        denies(() => Verify(Zip(("trailing.", "bad"))),
            "External original ZIP trailing dot denied");
        denies(() => Verify(Zip(("dir./file.txt", "bad"))),
            "External original ZIP trailing dot in directory component denied");
        denies(() => Verify(Zip(("trailing ", "bad"))),
            "External original ZIP trailing space denied");
        denies(() => Verify(Zip(("dir /file.txt", "bad"))),
            "External original ZIP trailing space in directory component denied");
        denies(() => Verify(Zip(("caf\u00e9.txt", "nfc"), ("cafe\u0301.txt", "nfd"))),
            "External original ZIP Unicode normalization alias (NFC vs NFD) denied");
        denies(() => Verify(Zip(("dir/が.txt", "nfc"), ("dir/か\u3099.txt", "nfd"))),
            "External original ZIP Unicode normalization alias (voiced kana) denied");
        denies(() => Verify(Zip(("CAF\u00c9.txt", "upper-nfc"), ("cafe\u0301.txt", "lower-nfd"))),
            "External original ZIP case + Unicode normalization alias denied");

        // Creating OS and attribute checks (Unix non-regular files denied; normal DOS attributes allowed).
        Verify(ZipWithEntryAttributes(
            ("dosdir/", "", 0, 0x00000010u),
            ("normal.dll", "ok", 0, 0x00000020u),
            ("readonly.txt", "ok", 10, 0x00000021u),
            ("notindexed.txt", "ok", 0, 0x00002020u),
            ("doslowbits.txt", "ok", 0, 0x0000A000u)));
        check(true, "Normal DOS/NTFS attributes (directory, archive, readonly, low-16 bits) are accepted");

        Verify(ZipWithEntryAttributes(
            ("unixdir/", "", 3, 0x41ED0000u),
            ("unixfile.dll", "ok", 3, 0x81A40000u),
            ("pyfile.txt", "ok", 3, 0x01800000u)));
        check(true, "Normal Unix regular files and directories are accepted");

        denies(() => Verify(ZipWithEntryAttributes(("link.dll", "target", 3, 0xA1FF0000u))),
            "External original ZIP Unix symlink denied");
        denies(() => Verify(ZipWithEntryAttributes(("pipe.fifo", "", 3, 0x11800000u))),
            "External original ZIP Unix FIFO denied");
        denies(() => Verify(ZipWithEntryAttributes(("sock", "", 3, 0xC1FF0000u))),
            "External original ZIP Unix socket denied");
        denies(() => Verify(ZipWithEntryAttributes(("chrdev", "", 3, 0x21B60000u))),
            "External original ZIP Unix char device denied");
        denies(() => Verify(ZipWithEntryAttributes(("blkdev", "", 3, 0x61B60000u))),
            "External original ZIP Unix block device denied");
        denies(() => Verify(ZipWithEntryAttributes(("fileasdir", "x", 3, 0x41ED0000u))),
            "External original ZIP Unix S_IFDIR on file entry denied");
        denies(() => Verify(ZipWithEntryAttributes(("dirasfile/", "", 3, 0x81A40000u), ("ok.txt", "x", 3, 0x81A40000u))),
            "External original ZIP Unix S_IFREG on directory entry denied");
        denies(() => Verify(ZipWithEntryAttributes(("reparse.dll", "x", 10, 0x00000420u))),
            "External original ZIP NTFS reparse point attribute denied");

        // Independent single-entry uncompressed limit via OriginalZipResourceProfile.
        var twoEntries = Zip(("a.bin", new string('A', 60)), ("b.bin", new string('B', 60)));
        var smallEntryProfile = new OriginalZipResourceProfile(
            MaxCompressedOriginalBytes: 4096,
            MaxEntryUncompressedBytes: 50,
            MaxTotalUncompressedBytes: 200,
            MaxEntries: 10);
        denies(() => ExternalOriginalZipIntegrity.VerifyWithProfile(
            twoEntries, twoEntries.Length, Hash(twoEntries), smallEntryProfile),
            "OriginalZipResourceProfile enforces independent single-entry uncompressed limit");

        var tightCountProfile = new OriginalZipResourceProfile(
            MaxCompressedOriginalBytes: 4096,
            MaxEntryUncompressedBytes: 200,
            MaxTotalUncompressedBytes: 400,
            MaxEntries: 1);
        denies(() => ExternalOriginalZipIntegrity.VerifyWithProfile(
            twoEntries, twoEntries.Length, Hash(twoEntries), tightCountProfile),
            "OriginalZipResourceProfile enforces MaxEntries limit");
        check(normal.Length > 4, "External original ZIP positive fixture truly contains bytes");
    }
}
