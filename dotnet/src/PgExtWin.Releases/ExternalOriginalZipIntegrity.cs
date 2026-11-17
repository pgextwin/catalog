using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace PgExtWin.Releases;

/// <summary>
/// Resource bounds enforced by the shared original ZIP verifier.
/// </summary>
public sealed record OriginalZipResourceProfile(
    long MaxCompressedOriginalBytes,
    long MaxEntryUncompressedBytes,
    long MaxTotalUncompressedBytes,
    int MaxEntries);

/// <summary>
/// Offline, non-authorizing check of original provider ZIP bytes.
/// Caller-supplied size/hash do not establish a license or publication rights.
/// External direct GET selects exact-version license-reviewed Catalog byte pins.
/// </summary>
public static class ExternalOriginalZipIntegrity
{
    public const long MaxOriginalBytes = 64L * 1024 * 1024;
    private const long MaxUncompressedBytes = 256L * 1024 * 1024;
    private const int MaxEntries = 1000;
    private static readonly Regex Hex64 = new(@"\A[0-9a-f]{64}\z",
        RegexOptions.CultureInvariant);
    private static readonly uint[] Crc32Table = CreateCrc32Table();
    private static readonly HashSet<string> ReservedWindowsDeviceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        "CONIN$", "CONOUT$"
    };

    internal static readonly OriginalZipResourceProfile DefaultOriginalProfile = new(
        MaxCompressedOriginalBytes: MaxOriginalBytes,
        MaxEntryUncompressedBytes: MaxOriginalBytes,
        MaxTotalUncompressedBytes: MaxUncompressedBytes,
        MaxEntries: MaxEntries);

    // OSGeo PG18 design profile: 96 MiB original / 96 MiB single entry / 2 GiB total / 25,000 entries.
    internal static readonly OriginalZipResourceProfile OsgeoPg18Profile = new(
        MaxCompressedOriginalBytes: 96L * 1024 * 1024,
        MaxEntryUncompressedBytes: 96L * 1024 * 1024,
        MaxTotalUncompressedBytes: 2L * 1024 * 1024 * 1024,
        MaxEntries: 25_000);

    public sealed record Receipt(long OriginalBytes, string OriginalSha256,
        int ArchiveMembers, string Scope = "INTEGRITY_ONLY_NOT_AUTHORIZED");

    public static Receipt Verify(byte[] original, long expectedSize, string expectedSha256) =>
        VerifyWithProfile(original, expectedSize, expectedSha256, DefaultOriginalProfile);

    // Exact OSGeo PG18 original ONLY (replaced in place upstream on 2026-11-14,
    // re-verified 2026-11-15; prior audits on the previous bytes do not carry over).
    // This does not authorize a GET or a Publisher; ordinary GitHub Release ZIP limits remain unchanged.
    internal static Receipt VerifyOsgeoExactCandidate(
        byte[] original, long expectedSize, string expectedSha256)
    {
        if (expectedSize != 83_739_256L ||
            expectedSha256 != "ac9e9486b3f9161ad86aea948c99b34ca67438f59263f91d2bcb961b51c7a419")
            throw new InvalidDataException("Different OSGeo candidate original DENY");
        return VerifyWithProfile(original, expectedSize, expectedSha256, OsgeoPg18Profile);
    }

    internal static Receipt VerifyWithProfile(byte[] original, long expectedSize,
        string expectedSha256, OriginalZipResourceProfile profile,
        string scope = "INTEGRITY_ONLY_NOT_AUTHORIZED")
    {
        ArgumentNullException.ThrowIfNull(original);
        ArgumentNullException.ThrowIfNull(profile);
        if (profile.MaxCompressedOriginalBytes < 4 ||
            profile.MaxEntryUncompressedBytes <= 0 ||
            profile.MaxTotalUncompressedBytes <= 0 ||
            profile.MaxEntries <= 0)
            throw new InvalidDataException("Invalid original ZIP resource profile");
        if (expectedSize < 4 || expectedSize > profile.MaxCompressedOriginalBytes ||
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
        if (archive.Entries.Count < 1 || archive.Entries.Count > profile.MaxEntries)
            throw new InvalidDataException("Original ZIP archive has invalid member count");

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ancestorDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var expanded = 0L;
        var actualFiles = 0;
        var buffer = new byte[32768];
        foreach (var entry in archive.Entries)
        {
            var isDirectory = entry.FullName.EndsWith("/", StringComparison.Ordinal);
            var canonicalPath = ValidateAndCanonicalizeMemberPath(
                entry.FullName, isDirectory, seen, files, ancestorDirs);
            ValidateEntryAttributes(entry, isDirectory);

            if (isDirectory)
            {
                if (entry.Length != 0 || entry.Crc32 != 0u)
                    throw new InvalidDataException("Directory entry carries unexpected data or CRC32");
                continue;
            }
            actualFiles++;
            if (entry.Length < 0 ||
                entry.Length > profile.MaxEntryUncompressedBytes ||
                entry.Length > profile.MaxTotalUncompressedBytes - expanded)
                throw new InvalidDataException("Original ZIP uncompressed payload is oversized");
            if (entry.Length == 0 && entry.Crc32 != 0u)
                throw new InvalidDataException("Empty original ZIP member must have CRC32 0");

            uint crc = 0xFFFFFFFFu;
            long read = 0;
            using (var payload = entry.Open())
            {
                while (true)
                {
                    var n = payload.Read(buffer, 0, buffer.Length);
                    if (n == 0) break;
                    read += n;
                    if (read > entry.Length ||
                        read > profile.MaxTotalUncompressedBytes - expanded)
                        throw new InvalidDataException("Original ZIP decompression exceeded declared or total limit");
                    crc = UpdateCrc32(crc, buffer.AsSpan(0, n));
                }
            }
            if (read != entry.Length)
                throw new InvalidDataException("Original ZIP member decompression was incomplete");
            uint actualCrc = crc ^ 0xFFFFFFFFu;
            if (actualCrc != entry.Crc32)
                throw new InvalidDataException($"Original ZIP member CRC32 mismatch for '{canonicalPath}'");            expanded += read;
        }
        if (actualFiles == 0)
            throw new InvalidDataException("Original ZIP contains no payload files");
        return new Receipt(expectedSize, actual, archive.Entries.Count, scope);
    }

    internal static uint ComputeCrc32(ReadOnlySpan<byte> data) =>
        UpdateCrc32(0xFFFFFFFFu, data) ^ 0xFFFFFFFFu;

    private static uint[] CreateCrc32Table()
    {
        const uint polynomial = 0xEDB88320u;
        var table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint crc = i;
            for (int bit = 0; bit < 8; bit++)
                crc = (crc & 1u) != 0 ? (crc >> 1) ^ polynomial : (crc >> 1);
            table[i] = crc;
        }
        return table;
    }

    private static uint UpdateCrc32(uint crc, ReadOnlySpan<byte> data)
    {
        var table = Crc32Table;
        foreach (byte b in data)
            crc = table[(crc ^ b) & 0xFFu] ^ (crc >> 8);
        return crc;
    }

    private static string ValidateAndCanonicalizeMemberPath(
        string fullName,
        bool isDirectory,
        HashSet<string> seen,
        HashSet<string> files,
        HashSet<string> ancestorDirs)
    {
        if (fullName.Length is < 1 or > 512 ||
            fullName.StartsWith("/", StringComparison.Ordinal) ||
            fullName.Contains('\\') ||
            fullName.Contains(':') ||
            fullName.Contains('\0'))
            throw new InvalidDataException("Unsafe original ZIP member path");

        // Strip at most one trailing '/' so "folder//" leaves an empty final segment and fails closed.
        var path = isDirectory ? fullName[..^1] : fullName;
        if (path.Length == 0)
            throw new InvalidDataException("Empty original ZIP member path");

        var rawParts = path.Split('/');
        var canonicalParts = new string[rawParts.Length];
        for (int i = 0; i < rawParts.Length; i++)
        {
            var rawPart = rawParts[i];
            ValidatePathComponent(rawPart);
            string normalizedPart;
            try
            {
                normalizedPart = rawPart.Normalize(NormalizationForm.FormKC);
            }
            catch (ArgumentException ex)
            {
                throw new InvalidDataException("Invalid Unicode in original ZIP member path", ex);
            }
            ValidatePathComponent(normalizedPart);
            canonicalParts[i] = normalizedPart;
        }

        var canonicalPath = string.Join('/', canonicalParts);
        if (!seen.Add(canonicalPath))
            throw new InvalidDataException("Duplicate or Unicode-aliased original ZIP member path");

        // Order-independent parent-child file/directory collision detection.
        var prefixBuilder = new StringBuilder(canonicalPath.Length);
        for (int i = 0; i < canonicalParts.Length - 1; i++)
        {
            if (i > 0) prefixBuilder.Append('/');
            prefixBuilder.Append(canonicalParts[i]);
            var prefix = prefixBuilder.ToString();
            if (files.Contains(prefix))
                throw new InvalidDataException("Original ZIP member path collides with file parent");
            ancestorDirs.Add(prefix);
        }

        if (!isDirectory)
        {
            if (ancestorDirs.Contains(canonicalPath))
                throw new InvalidDataException("Original ZIP file member collides with directory prefix");
            files.Add(canonicalPath);
        }

        return canonicalPath;
    }

    private static void ValidatePathComponent(string part)
    {
        if (part.Length == 0 || part is "." or "..")
            throw new InvalidDataException("Unsafe original ZIP path component");

        if (char.IsWhiteSpace(part[^1]) || part[^1] == '.')
            throw new InvalidDataException("Original ZIP path component has trailing whitespace or dot");

        foreach (char c in part)
        {
            if (c < 0x20 || c == 0x7F ||
                c is '<' or '>' or ':' or '"' or '/' or '\\' or '|' or '?' or '*')
                throw new InvalidDataException("Original ZIP path component contains forbidden character");
            var category = CharUnicodeInfo.GetUnicodeCategory(c);
            if (category is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.Surrogate)
                throw new InvalidDataException("Original ZIP path component contains forbidden Unicode character");
        }

        var dot = part.IndexOf('.');
        var stem = (dot >= 0 ? part[..dot] : part).TrimEnd();
        if (ReservedWindowsDeviceNames.Contains(stem))
            throw new InvalidDataException("Original ZIP path component uses reserved Windows device name");
    }

    private static void ValidateEntryAttributes(ZipArchiveEntry entry, bool isDirectory)
    {
        var hostOs = (byte)(entry.VersionMadeBy >> 8);
        var externalAttributes = unchecked((uint)entry.ExternalAttributes);
        var dosAttributes = externalAttributes & 0xFFFFu;
        var unixFileType = (externalAttributes >> 16) & 0xF000u;

        // Distinguish creating OS: for DOS/OS2/NTFS/VFAT entries, allow normal DOS attributes
        // and reject Windows reparse points (0x0400) or device attributes (0x0040).
        if (hostOs is 0 or 6 or 10 or 14)
        {
            const uint ForbiddenDosAttributes = 0x0400u | 0x0040u;
            if ((dosAttributes & ForbiddenDosAttributes) != 0)
                throw new InvalidDataException("Original ZIP contains forbidden DOS/NTFS attribute");
        }

        // Reject Unix non-regular file types (symlink 0xA000, FIFO 0x1000, char 0x2000,
        // block 0x6000, socket 0xC000, etc.) and file/directory mode mismatches.
        if (unixFileType != 0)
        {
            var expectedUnixType = isDirectory ? 0x4000u : 0x8000u;
            if (unixFileType != expectedUnixType)
                throw new InvalidDataException("Original ZIP contains non-regular or mismatched Unix file type");
        }
    }

}

