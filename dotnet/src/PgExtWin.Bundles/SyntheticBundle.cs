using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using PgExtWin.Core;

namespace PgExtWin.Bundles;

/// <summary>Only in-memory, deliberately synthetic ZIPs. No real Release input or publishing path.</summary>
public sealed record FixturePackage(string Extension, string PgMajor, string PackageVersion,
    string AssetName, byte[] OriginalZip);

public sealed record FixtureBundleResult(int PackageCount, string VerificationLevel = "UNVERIFIED",
    bool PublicationAuthorized = false, bool OuterArchiveSigned = false);

internal sealed record FixtureEntry(string Extension, string PgMajor, string PackageVersion,
    string AssetName, string BundleRelativePath, string Sha256, long ByteSize);

internal sealed record FixtureDocument(string SchemaVersion, string Purpose,
    bool PublicationAuthorized, bool OuterArchiveSigned, string VerificationLevel,
    IReadOnlyList<FixtureEntry> Packages, string? SnapshotId = null);

/// <summary>
/// A test-fixture format, explicitly NOT pgextwin-distribution-manifest/v1.
/// Existing Python P0/P1 remain authoritative for real published releases and signatures.
/// </summary>
public static class SyntheticBundle
{
    private const string Version = "pgextwin-synthetic-bundle-fixture/v1";
    private const string Purpose = "SYNTHETIC_TEST_ONLY_DO_NOT_DISTRIBUTE";
    private const string Marker = "SYNTHETIC-FIXTURE.txt";
    private const string Proof = "pgextwin Issue 112 synthetic fixture - not a real Release\n";
    private const string Readme = "SYNTHETIC TEST FIXTURE ONLY - NOT AUTHENTICATED OR DISTRIBUTABLE\n";
    private const string ManifestName = "fixture-manifest.json";
    private const string BannerName = "SYNTHETIC-DO-NOT-DISTRIBUTE.txt";
    private const int MaxPackages = 30;
    private const int MaxMembers = 100;
    private const long MaxMemberBytes = 4 * 1024 * 1024;
    private const long MaxTotalBytes = 16 * 1024 * 1024;
    private const long MaxOuterBytes = 20 * 1024 * 1024;
    private const int MaxRatio = 200;
    private static readonly DateTimeOffset FixedTime = new(1980, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly Regex Component = new(@"\A[A-Za-z0-9][A-Za-z0-9._-]*\z",
        RegexOptions.CultureInvariant);
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static byte[] Create(IReadOnlyList<FixturePackage> inputs)
    {
        Require(inputs is { Count: > 0 and <= MaxPackages }, "Fixture package count outside bounds");
        var ordered = inputs.OrderBy(p => p.Extension, StringComparer.Ordinal)
            .ThenBy(p => Major(p.PgMajor)).ToArray();
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var entries = new List<FixtureEntry>(ordered.Length);
        long total = 0;
        foreach (var package in ordered)
        {
            var destination = ExpectedPath(package.Extension, package.PgMajor,
                package.PackageVersion, package.AssetName);
            Require(paths.Add(destination), "Duplicate/case-colliding synthetic package path");
            Require(package.OriginalZip is { Length: > 0 } &&
                package.OriginalZip.LongLength <= MaxMemberBytes, "Oversized synthetic source ZIP");
            total += package.OriginalZip.LongLength;
            Require(total <= MaxTotalBytes, "Synthetic fixture fleet is oversized");
            CheckSyntheticInnerZip(package.OriginalZip);
            entries.Add(new FixtureEntry(package.Extension, package.PgMajor,
                package.PackageVersion, package.AssetName, destination,
                StrictJson.Sha256(package.OriginalZip), package.OriginalZip.LongLength));
        }

        var body = new FixtureDocument(Version, Purpose, false, false, "UNVERIFIED", entries);
        var bodyBytes = Canonical(body);
        var document = body with { SnapshotId = StrictJson.Sha256(bodyBytes) };
        var manifest = Canonical(document);
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            Write(archive, BannerName, Encoding.UTF8.GetBytes(Readme));
            Write(archive, ManifestName, manifest);
            for (var i = 0; i < ordered.Length; i++)
                Write(archive, entries[i].BundleRelativePath, ordered[i].OriginalZip);
        }
        Require(stream.Length <= MaxOuterBytes, "Synthetic outer ZIP exceeds limit");
        return stream.ToArray();
    }

    public static FixtureBundleResult Verify(ReadOnlySpan<byte> content)
    {
        Require(content.Length > 0 && (long)content.Length <= MaxOuterBytes, "Invalid fixture outer ZIP size");
        using var archive = new ZipArchive(new MemoryStream(content.ToArray(), writable: false),
            ZipArchiveMode.Read, leaveOpen: false);
        var actual = Inspect(archive);
        Require(actual.Count >= 3 && actual.ContainsKey(ManifestName) &&
            actual.ContainsKey(BannerName), "Missing fixture markers/manifest");
        Require(Encoding.UTF8.GetString(ReadBounded(actual[BannerName])) == Readme,
            "Synthetic fixture warning was removed/changed");
        var manifestBytes = ReadBounded(actual[ManifestName]);
        using var parsed = StrictJson.Parse(manifestBytes);
        var root = parsed.RootElement;
        Require(root.ValueKind == JsonValueKind.Object &&
            root.EnumerateObject().Count() == 7, "Unknown/missing fixture manifest fields");
        var document = JsonSerializer.Deserialize<FixtureDocument>(manifestBytes, JsonOptions)
            ?? throw new InvalidDataException("Missing fixture manifest");
        Require(document.SchemaVersion == Version && document.Purpose == Purpose &&
            !document.PublicationAuthorized && !document.OuterArchiveSigned &&
            document.VerificationLevel == "UNVERIFIED" && document.Packages is { Count: > 0 and <= MaxPackages },
            "Not an unverified synthetic-only fixture manifest");
        Require(StrictJson.CanonicalBytes(root).AsSpan().SequenceEqual(manifestBytes),
            "Noncanonical fixture manifest");
        var canonicalBody = StrictJson.CanonicalBytes(root, "snapshotId");
        Require(document.SnapshotId == StrictJson.Sha256(canonicalBody), "Tampered fixture snapshotId");
        var listed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var previousName = "";
        var previousMajor = 0;
        foreach (var package in document.Packages)
        {
            if (package is null) throw new InvalidDataException("Null manifest package");
            var name = ExpectedPath(package.Extension, package.PgMajor,
                package.PackageVersion, package.AssetName);
            Require(package.BundleRelativePath == name && listed.Add(name),
                "Invalid/duplicate package destination");
            var major = Major(package.PgMajor);
            Require(string.CompareOrdinal(package.Extension, previousName) > 0 ||
                (package.Extension == previousName && major > previousMajor),
                "Unsorted/colliding synthetic package matrix");
            previousName = package.Extension;
            previousMajor = major;
            Require(Regex.IsMatch(package.Sha256, @"\A[0-9a-f]{64}\z") &&
                package.ByteSize is > 0 and <= MaxMemberBytes, "Invalid fixture package digest/size");
            Require(actual.TryGetValue(name, out var entry), "Fixture member missing");
            var bytes = ReadBounded(entry!);
            Require(bytes.LongLength == package.ByteSize &&
                StrictJson.Sha256(bytes) == package.Sha256, "Changed fixture source ZIP bytes");
            CheckSyntheticInnerZip(bytes);
        }
        Require(actual.Count == listed.Count + 2, "Unlisted member injected into synthetic ZIP");
        return new FixtureBundleResult(listed.Count);
    }

    private static byte[] Canonical(FixtureDocument doc)
    {
        using var parsed = StrictJson.Parse(JsonSerializer.SerializeToUtf8Bytes(doc, JsonOptions));
        return StrictJson.CanonicalBytes(parsed.RootElement);
    }

    private static void Write(ZipArchive archive, string name, byte[] bytes)
    {
        SafePath(name);
        var entry = archive.CreateEntry(name, CompressionLevel.NoCompression);
        entry.LastWriteTime = FixedTime;
        using var output = entry.Open();
        output.Write(bytes);
    }

    private static Dictionary<string, ZipArchiveEntry> Inspect(ZipArchive archive)
    {
        Require(archive.Entries.Count <= MaxMembers, "Too many ZIP members");
        var entries = new Dictionary<string, ZipArchiveEntry>(StringComparer.OrdinalIgnoreCase);
        long cumulative = 0;
        foreach (var entry in archive.Entries)
        {
            var name = SafePath(entry.FullName);
            var mode = (entry.ExternalAttributes >> 16) & 0xF000;
            Require((mode == 0 || mode == 0x8000) &&
                (entry.ExternalAttributes & 0x400) == 0, "Symlink or special ZIP member");
            Require(entry.Length >= 0 && entry.Length <= MaxMemberBytes,
                "Oversized ZIP member");
            Require(entry.Length == 0 || (entry.CompressedLength > 0 &&
                entry.Length <= entry.CompressedLength * MaxRatio), "Suspicious compression ratio");
            cumulative += entry.Length;
            Require(cumulative <= MaxTotalBytes, "ZIP total uncompressed limit exceeded");
            Require(entries.TryAdd(name, entry), "Duplicate/case-colliding ZIP member");
        }
        foreach (var key in entries.Keys)
        {
            Require(!entries.Keys.Any(other => other != key &&
                other.StartsWith(key + "/", StringComparison.OrdinalIgnoreCase)),
                "File/directory ZIP collision");
        }
        return entries;
    }

    private static byte[] ReadBounded(ZipArchiveEntry entry)
    {
        Require(entry.Length <= MaxMemberBytes, "Oversized ZIP member");
        using var input = entry.Open();
        using var output = new MemoryStream();
        var buffer = new byte[8192];
        long count = 0;
        while (true)
        {
            var n = input.Read(buffer, 0, buffer.Length);
            if (n == 0) break;
            count += n;
            Require(count <= MaxMemberBytes && count <= entry.Length, "ZIP decompression overrun");
            output.Write(buffer, 0, n);
        }
        Require(count == entry.Length, "Truncated ZIP member");
        return output.ToArray();
    }

    private static void CheckSyntheticInnerZip(byte[] bytes)
    {
        using var inner = new ZipArchive(new MemoryStream(bytes, writable: false),
            ZipArchiveMode.Read, leaveOpen: false);
        var members = Inspect(inner);
        Require(members.TryGetValue(Marker, out var marker), "Not a synthetic-only inner ZIP");
        Require(Encoding.UTF8.GetString(ReadBounded(marker!)) == Proof,
            "Synthetic source ZIP marker mismatch");
        Require(!members.ContainsKey("PACKAGE-INFO.json"), "Real Release package metadata forbidden");
    }

    private static string ExpectedPath(string extension, string major, string version, string name)
    {
        Require(SafeComponent(extension) && SafeComponent(version) && SafeComponent(name) &&
            Regex.IsMatch(extension, @"\A[a-z][a-z0-9_]*\z", RegexOptions.CultureInvariant) &&
            name.StartsWith(extension + "-", StringComparison.Ordinal) &&
            name.EndsWith("-pg" + major + "-windows-x64.zip", StringComparison.Ordinal) &&
            Major(major) > 0, "Unsafe fixture package identity");
        return SafePath("packages/pg" + major + "/" + extension + "/" + version + "/" + name);
    }

    private static int Major(string value)
    {
        if (string.IsNullOrEmpty(value) ||
            !Regex.IsMatch(value, @"\A[1-9][0-9]*\z", RegexOptions.CultureInvariant) ||
            !int.TryParse(value, out var parsed))
            throw new InvalidDataException("Invalid PG major");
        return parsed;
    }

    private static string SafePath(string value)
    {
        Require(!string.IsNullOrEmpty(value) && value.Length <= 768 &&
            !value.StartsWith('/') && !value.Contains('\\') && !value.Contains(':') &&
            !value.Contains('\0') && !value.EndsWith('/'), "Unsafe ZIP member path");
        foreach (var part in value.Split('/'))
            Require(SafeComponent(part), "Unsafe ZIP member path component");
        return value;
    }

    private static bool SafeComponent(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 160 ||
            value.EndsWith('.') || !Component.IsMatch(value) || value is "." or "..")
            return false;
        var stem = value.Split('.')[0].ToUpperInvariant();
        return stem is not ("CON" or "PRN" or "AUX" or "NUL") &&
            !Regex.IsMatch(stem, @"\A(?:COM|LPT)[1-9]\z", RegexOptions.CultureInvariant);
    }

    private static void Require(bool ok, string message)
    {
        if (!ok) throw new InvalidDataException(message);
    }
}
