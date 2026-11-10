using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace PgExtWin.Releases;

/// <summary>
/// Offline, non-authorizing check of original provider ZIP bytes.
/// Caller-supplied size/hash are NOT a trust anchor. A separately authenticated
/// signed external feed AND formal source-specific Publisher admission must
/// precede any network download or user-facing distribution.
/// </summary>
public static class ExternalOriginalZipIntegrity
{
    public const long MaxOriginalBytes = 64L * 1024 * 1024;
    private const long MaxUncompressedBytes = 256L * 1024 * 1024;
    private const int MaxEntries = 1000;
    private static readonly Regex Hex64 = new(@"\A[0-9a-f]{64}\z",
        RegexOptions.CultureInvariant);

    public sealed record Receipt(long OriginalBytes, string OriginalSha256,
        int ArchiveMembers, string Scope = "INTEGRITY_ONLY_NOT_AUTHORIZED");

    public static Receipt Verify(byte[] original, long expectedSize, string expectedSha256) =>
        VerifyCore(original, expectedSize, expectedSha256, MaxOriginalBytes,
            MaxUncompressedBytes, MaxEntries);

    // Exact OSGeo PG18 original ONLY. This does not authorize a GET or a
    // Publisher; ordinary GitHub Release ZIP limits remain unchanged.
    internal static Receipt VerifyOsgeoExactCandidate(
        byte[] original, long expectedSize, string expectedSha256)
    {
        if (expectedSize != 83_320_975L ||
            expectedSha256 != "fa3db8060d8d376e869d961659bf4eff326c0d99a731396701af61a13dc12a40")
            throw new InvalidDataException("Different OSGeo candidate original DENY");
        return VerifyCore(original, expectedSize, expectedSha256,
            96L * 1024 * 1024, 2L * 1024 * 1024 * 1024, 25_000);
    }

    private static Receipt VerifyCore(byte[] original, long expectedSize,
        string expectedSha256, long maxOriginalBytes, long maxUncompressedBytes,
        int maxEntries)
    {
        ArgumentNullException.ThrowIfNull(original);
        if ((expectedSize < 4 || expectedSize > maxOriginalBytes) ||
            original.LongLength != expectedSize ||
            expectedSha256 is null || !Hex64.IsMatch(expectedSha256))
            throw new InvalidDataException("Missing, invalid or oversized exact original ZIP pin");

        string actual = Convert.ToHexStringLower(SHA256.HashData(original));
        if (actual != expectedSha256)
            throw new InvalidDataException("Original ZIP SHA256 differs from authenticated expectation");
        if (original[0] != 0x50 || original[1] != 0x4b ||
            original[2] != 0x03 || original[3] != 0x04)
            throw new InvalidDataException("Expected original provider ZIP local file header");

        using var stream = new MemoryStream(original, writable: false);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false);
        if (archive.Entries.Count < 1 || archive.Entries.Count > maxEntries)
            throw new InvalidDataException("Original ZIP archive has invalid member count");

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var expanded = 0L;
        var actualFiles = 0;
        var buffer = new byte[32768];
        foreach (var entry in archive.Entries)
        {
            var name = entry.FullName;
            var path = name.TrimEnd('/');
            if (name.Length is < 1 or > 512 ||
                path.Length == 0 || name.StartsWith("/", StringComparison.Ordinal) ||
                name.Contains('\\') || name.Contains(':') || name.Contains('\0') ||
                path.Split('/').Any(part => part is "" or "." or "..") ||
                !seen.Add(path))
                throw new InvalidDataException("Unsafe or duplicate original ZIP member path");
            // ZIP unix external file type 0120000 is a symbolic link.
            if (((entry.ExternalAttributes >> 16) & 0xF000) == 0xA000)
                throw new InvalidDataException("Original ZIP contains a symbolic link");
            if (name.EndsWith("/", StringComparison.Ordinal))
            {
                if (entry.Length != 0)
                    throw new InvalidDataException("Directory entry carries unexpected data");
                continue;
            }
            actualFiles++;
            if (entry.Length < 0 || entry.Length > maxOriginalBytes ||
                entry.Length > maxUncompressedBytes - expanded)
                throw new InvalidDataException("Original ZIP uncompressed payload is oversized");

            using var payload = entry.Open();
            long read = 0;
            while (true)
            {
                var n = payload.Read(buffer, 0, buffer.Length);
                if (n == 0) break;
                read += n;
                if (read > entry.Length)
                    throw new InvalidDataException("Original ZIP decompression exceeded declared length");
            }
            if (read != entry.Length)
                throw new InvalidDataException("Original ZIP member decompression was incomplete");
            expanded += read;
        }
        if (actualFiles == 0)
            throw new InvalidDataException("Original ZIP contains no payload files");
        return new Receipt(expectedSize, actual, archive.Entries.Count);
    }
}
