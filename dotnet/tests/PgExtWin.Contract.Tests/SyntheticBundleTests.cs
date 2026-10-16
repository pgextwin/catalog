using System.IO.Compression;
using System.Text;
using PgExtWin.Bundles;

internal static class SyntheticBundleTests
{
    private const string Marker = "SYNTHETIC-FIXTURE.txt";
    private const string Proof = "pgextwin Issue 112 synthetic fixture - not a real Release\n";
    private static readonly DateTimeOffset Timestamp = new(1980, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public static void Run(Action<bool, string> check)
    {
        void Reject(Action action, string description)
        {
            var denied = false;
            try { action(); }
            catch (InvalidDataException) { denied = true; }
            check(denied, description);
        }

        var first = new FixturePackage("pg_cron", "18", "1.6.8",
            "pg_cron-1.6.8-pg18-windows-x64.zip", Inner());
        var second = new FixturePackage("pg_hint_plan", "14", "1.4.4",
            "pg_hint_plan-1.4.4-pg14-windows-x64.zip", Inner());
        var one = SyntheticBundle.Create([second, first]);
        var two = SyntheticBundle.Create([first, second]);
        check(one.AsSpan().SequenceEqual(two), "Deterministic synthetic ZIP sorting and bytes");
        var verdict = SyntheticBundle.Verify(one);
        check(verdict.PackageCount == 2 && verdict.VerificationLevel == "UNVERIFIED" &&
            !verdict.PublicationAuthorized && !verdict.OuterArchiveSigned,
            "Never promote fixture to authentic/signed/publication");
        using (var archive = Open(one))
        {
            check(archive.Entries.All(e => !e.FullName.Equals("manifest.json", StringComparison.Ordinal)),
                "Synthetic fixture does not impersonate actual P0 manifest");
            check(archive.Entries.Any(e => e.FullName ==
                "packages/pg18/pg_cron/1.6.8/pg_cron-1.6.8-pg18-windows-x64.zip"),
                "Existing P0 package-relative-path layout");
        }

        Reject(() => SyntheticBundle.Create([]), "Empty fixture rejected");
        Reject(() => SyntheticBundle.Create([first, first]), "Duplicate fixture matrix rejected");
        Reject(() => SyntheticBundle.Create([first with { Extension = "../evil" }]),
            "Source path traversal rejected");
        Reject(() => SyntheticBundle.Create([first with { PackageVersion = "CON" }]),
            "Windows reserved package component rejected");
        Reject(() => SyntheticBundle.Create([first with { PgMajor = "019" }]),
            "Malformed PostgreSQL major rejected");
        Reject(() => SyntheticBundle.Create([first with { AssetName = "evil.zip" }]),
            "Noncanonical original asset path rejected");
        Reject(() => SyntheticBundle.Create([first with { OriginalZip = Inner(marker: false) }]),
            "Original non-synthetic Release ZIP rejected");
        Reject(() => SyntheticBundle.Create([first with { OriginalZip = Inner(proof: "forged") }]),
            "Changed synthetic proof rejected");
        Reject(() => SyntheticBundle.Create([first with { OriginalZip = Inner(includePackageInfo: true) }]),
            "Real PACKAGE-INFO provenance is forbidden in synthetic fixture");
        Reject(() => SyntheticBundle.Create([first with { OriginalZip = Inner(extraMember: "../escape") }]),
            "ZIP Slip in nested ZIP rejected");
        Reject(() => SyntheticBundle.Create([first with { OriginalZip = Inner(extraMember: "CON") }]),
            "Reserved Windows filename in nested ZIP rejected");
        Reject(() => SyntheticBundle.Create([first with { OriginalZip = Inner(extraMember: "large.bin", extraData: new string('X', 500000)) }]),
            "Nested ZIP compression bomb rejected");

        Reject(() => SyntheticBundle.Verify(one[..^8]), "Truncated outer ZIP rejected");
        Reject(() => SyntheticBundle.Verify(Repack(one, (n,b) => (n, n == "SYNTHETIC-DO-NOT-DISTRIBUTE.txt" ? "tamper"u8.ToArray() : b))),
            "Tampered synthetic warning rejected");
        Reject(() => SyntheticBundle.Verify(Repack(one, (n,b) => (n, n.EndsWith(".zip", StringComparison.Ordinal) ? Inner(proof: "forged") : b))),
            "Tampered inner original bytes rejected");
        Reject(() => SyntheticBundle.Verify(Repack(one, (n,b) => (n, n == "fixture-manifest.json"
                ? Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(b).Replace("\"verificationLevel\":\"UNVERIFIED\"",
                    "\"verificationLevel\":\"SIGNATURE_VERIFIED\"", StringComparison.Ordinal)) : b))),
            "False signature VERIFIED status rejected");
        Reject(() => SyntheticBundle.Verify(Repack(one, (n,b) => (n, n == "fixture-manifest.json"
                ? Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(b).Replace("\"publicationAuthorized\":false",
                    "\"publicationAuthorized\":true", StringComparison.Ordinal)) : b))),
            "False publicationAuthorized status rejected");
        Reject(() => SyntheticBundle.Verify(Repack(one, (n,b) => (n, n == "fixture-manifest.json"
                ? Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(b).Replace("\"snapshotId\":\"",
                    "\"snapshotId\":\"0", StringComparison.Ordinal)) : b))),
            "Changed manifest snapshot rejected");
        Reject(() => SyntheticBundle.Verify(Repack(one, (n,b) => (n,
                n == "fixture-manifest.json" ? Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(b)
                    .Replace("\"purpose\":", "\"purpose\":\"forged\",\"purpose\":", StringComparison.Ordinal)) : b))),
            "Duplicate JSON key rejected");
        Reject(() => SyntheticBundle.Verify(Repack(one, (n,b) => (n, b),
                extraName: "unexpected.txt", extraBytes: "extra"u8.ToArray())),
            "Unlisted archive member rejected");
        Reject(() => SyntheticBundle.Verify(Repack(one, (n,b) => (n, b),
                extraName: "../escape.txt", extraBytes: "bad"u8.ToArray())),
            "Outer ZIP Slip denied");
        Reject(() => SyntheticBundle.Verify(Repack(one, (n,b) => (n,b),
                extraName: "FIXTURE-MANIFEST.JSON", extraBytes: "duplicate"u8.ToArray())),
            "Windows case-insensitive duplicate rejected");
        Reject(() => SyntheticBundle.Verify(Repack(one, (n,b) => (n,b),
                extraName: "symlink", extraBytes: "link"u8.ToArray(), special: true)),
            "Outer symlink rejected");
        Reject(() => SyntheticBundle.Verify(Repack(one, (n,b) => (n,b),
                extraName: "bomb.txt", extraBytes: Encoding.UTF8.GetBytes(new string('x', 600000)),
                compressExtra: true)), "Outer compression bomb rejected");
        Reject(() => SyntheticBundle.Verify(Repack(one, (n,b) => (n,b),
                extraName: "large.txt", extraBytes: new byte[4 * 1024 * 1024 + 1], compressExtra: true)),
            "Oversized ZIP member rejected");
        check(SyntheticBundle.Verify(two).PackageCount == 2, "Repeat verification in-memory without network");
    }

    private static byte[] Inner(bool marker = true, string proof = Proof, bool includePackageInfo = false,
        string? extraMember = null, string? extraData = null)
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, true))
        {
            if (marker) Add(archive, Marker, Encoding.UTF8.GetBytes(proof));
            if (includePackageInfo) Add(archive, "PACKAGE-INFO.json", "{}"u8.ToArray());
            if (extraMember is not null)
                Add(archive, extraMember, Encoding.UTF8.GetBytes(extraData ?? "test"),
                    extraData is null ? CompressionLevel.NoCompression : CompressionLevel.Optimal);
        }
        return stream.ToArray();
    }

    private static ZipArchive Open(byte[] data) => new(new MemoryStream(data, false), ZipArchiveMode.Read, false);

    private static byte[] Repack(byte[] original, Func<string, byte[], (string, byte[])> mutation,
        string? extraName = null, byte[]? extraBytes = null, bool special = false, bool compressExtra = false)
    {
        using var src = Open(original);
        using var result = new MemoryStream();
        using (var dest = new ZipArchive(result, ZipArchiveMode.Create, true))
        {
            foreach (var entry in src.Entries)
            {
                using var input = entry.Open();
                using var copy = new MemoryStream();
                input.CopyTo(copy);
                var item = mutation(entry.FullName, copy.ToArray());
                Add(dest, item.Item1, item.Item2);
            }
            if (extraName is not null)
            {
                var entry = Add(dest, extraName, extraBytes ?? [], compressExtra
                    ? CompressionLevel.Optimal : CompressionLevel.NoCompression);
                if (special) entry.ExternalAttributes = unchecked((int)(0xA000u << 16));
            }
        }
        return result.ToArray();
    }

    private static ZipArchiveEntry Add(ZipArchive archive, string name, byte[] data,
        CompressionLevel compression = CompressionLevel.NoCompression)
    {
        var entry = archive.CreateEntry(name, compression);
        entry.LastWriteTime = Timestamp;
        using var output = entry.Open();
        output.Write(data);
        return entry;
    }
}
