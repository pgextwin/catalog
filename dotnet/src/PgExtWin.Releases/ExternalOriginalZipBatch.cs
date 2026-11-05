using System.Text.Json;
using System.Text.RegularExpressions;
using PgExtWin.Core;

namespace PgExtWin.Releases;

/// <summary>
/// Offline bulk verification of original external-provider ZIPs independently obtained
/// by the operator. Does NOT download, approve, distribute, publish or install anything.
/// A local review ledger is untrusted evidence, not an authenticated external feed.
/// </summary>
public static class ExternalOriginalZipBatch
{
    private static readonly Regex Hex64 = new(@"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant);
    private static readonly Regex Repo = new(@"\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\z",
        RegexOptions.CultureInvariant);
    private static readonly Regex Extension = new(@"\A[a-z][a-z0-9_]*\z",
        RegexOptions.CultureInvariant);
    private static readonly Regex Major = new(@"\A[1-9][0-9]*\z", RegexOptions.CultureInvariant);

    public sealed record Result(int Count, long Bytes, int Members,
        string Scope = "INTEGRITY_ONLY_NOT_AUTHORIZED");

    private sealed record Item(string Extension, string PgMajor, string AssetName,
        long Bytes, string Sha256);

    public static Result VerifyLocal(string reviewLedger, string originalFilesDirectory,
        string pgSelection)
    {
        if (pgSelection != "all" && !Major.IsMatch(pgSelection))
            throw new ArgumentException("Expected a PostgreSQL major or all");
        var ledger = new FileInfo(Path.GetFullPath(reviewLedger));
        if (!ledger.Exists || ledger.Length is < 1 or > 2_000_000 ||
            (ledger.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Missing, linked or oversized external review ledger");
        using var document = StrictJson.Parse(File.ReadAllBytes(ledger.FullName));
        var root = document.RootElement;
        if (Required(root, "schemaVersion") != "pgextwin-external-original-link-review/v1" ||
            Required(root, "scope") != "REFERENCE_TO_UNMODIFIED_PROVIDER_RELEASE_ASSET_ONLY" ||
            Required(root, "rightsReview") != "SOURCE_AND_NOTICE_REFERENCES_REVIEWED_NOT_DISTRIBUTION_APPROVAL" ||
            root.GetProperty("publicationAuthorized").ValueKind != JsonValueKind.False ||
            root.GetProperty("downloadAuthorized").ValueKind != JsonValueKind.False ||
            root.GetProperty("mirrorAuthorized").ValueKind != JsonValueKind.False ||
            root.GetProperty("redistributionAuthorized").ValueKind != JsonValueKind.False ||
            root.GetProperty("signedExternalCatalogPin").ValueKind != JsonValueKind.False)
            throw new InvalidDataException("External review does not establish download/distribution authority");

        var entries = root.GetProperty("records");
        if (entries.ValueKind != JsonValueKind.Array || entries.GetArrayLength() is < 1 or > 1000)
            throw new InvalidDataException("Invalid external review entry count");
        var selected = new List<Item>();
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries.EnumerateArray())
        {
            var extension = Required(entry, "extension");
            var major = Required(entry, "pgMajor");
            var repository = Required(entry, "sourceRepo");
            var tag = Required(entry, "releaseTag");
            var name = Required(entry, "assetName");
            var url = Required(entry, "originalProviderUrl");
            var sha = Required(entry, "originalSha256");
            var repoId = entry.GetProperty("repositoryId").GetInt64();
            var releaseId = entry.GetProperty("releaseId").GetInt64();
            var assetId = entry.GetProperty("assetId").GetInt64();
            var length = entry.GetProperty("originalBytes").GetInt64();
            if (!Extension.IsMatch(extension) || !Major.IsMatch(major) ||
                !Repo.IsMatch(repository) || repository.StartsWith("pgextwin/", StringComparison.OrdinalIgnoreCase) ||
                !PinnedReleaseSelector.SafeAssetName(tag) ||
                !PinnedReleaseSelector.SafeAssetName(name) ||
                !name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) ||
                !Hex64.IsMatch(sha) ||
                repoId <= 0 || releaseId <= 0 || assetId <= 0 ||
                length is < 4 or > ExternalOriginalZipIntegrity.MaxOriginalBytes ||
                url != "https://github.com/" + repository + "/releases/download/" + tag + "/" + name ||
                entry.GetProperty("referenceLinkReviewed").ValueKind != JsonValueKind.True ||
                entry.GetProperty("downloadAuthorized").ValueKind != JsonValueKind.False ||
                entry.GetProperty("mirrorAuthorized").ValueKind != JsonValueKind.False ||
                !ids.Add(repository + ":" + releaseId + ":" + assetId) ||
                !paths.Add("pg" + major + "/" + extension + "/" + name))
                throw new InvalidDataException("Unsafe, duplicate or elevated external review entry");
            if (pgSelection == "all" || pgSelection == major)
                selected.Add(new Item(extension, major, name, length, sha));
        }
        if (selected.Count == 0)
            throw new InvalidDataException("No reviewed ZIP for requested PostgreSQL major");

        var input = Path.GetFullPath(originalFilesDirectory);
        RequirePhysicalDirectory(input);
        long bytes = 0;
        var members = 0;
        // No stdout or success receipt is emitted until the entire selection verifies.
        foreach (var item in selected)
        {
            var pgDirectory = Path.Combine(input, "pg" + item.PgMajor);
            var extensionDirectory = Path.Combine(pgDirectory, item.Extension);
            RequirePhysicalDirectory(pgDirectory);
            RequirePhysicalDirectory(extensionDirectory);
            var original = new FileInfo(Path.Combine(extensionDirectory, item.AssetName));
            if (!original.Exists || (original.Attributes & FileAttributes.ReparsePoint) != 0 ||
                original.Length != item.Bytes)
                throw new InvalidDataException("Original provider ZIP missing, linked or wrong size: " + item.AssetName);
            var result = ExternalOriginalZipIntegrity.Verify(
                File.ReadAllBytes(original.FullName), item.Bytes, item.Sha256);
            bytes = checked(bytes + result.OriginalBytes);
            members = checked(members + result.ArchiveMembers);
        }
        return new Result(selected.Count, bytes, members);
    }

    private static string Required(JsonElement obj, string key)
    {
        var value = obj.GetProperty(key);
        if (value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(value.GetString()))
            throw new InvalidDataException("Missing external review property: " + key);
        return value.GetString()!;
    }

    private static void RequirePhysicalDirectory(string path)
    {
        if (!Directory.Exists(path))
            throw new DirectoryNotFoundException("Original ZIP folder is missing");
        for (DirectoryInfo? dir = new(path); dir is not null; dir = dir.Parent)
            if ((dir.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Original ZIP directory contains a symbolic link");
    }
}
