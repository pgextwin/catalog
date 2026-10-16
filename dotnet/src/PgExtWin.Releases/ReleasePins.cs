using System.Text.Json;
using System.Text.RegularExpressions;
using PgExtWin.Catalog;
using PgExtWin.Core;

namespace PgExtWin.Releases;

// These pins are INPUT from a separately authenticated P1 policy, NOT a signature verdict.
public sealed record ReleasePins(string Extension, string PgMajor, string Tag,
    string AssetName, string AssetSha256, long RepositoryId, long ReleaseId,
    IReadOnlyDictionary<string, long> AssetIds, string CatalogCommit);

public static class PinnedReleaseSelector
{
    private static readonly Regex Hex64 = new(@"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant);
    private static readonly Regex Hex40 = new(@"\A[0-9a-f]{40}\z", RegexOptions.CultureInvariant);

    public static ReleasePins FromLocalFiles(string catalogDirectory, string policyFile,
        string independentlyAuthenticatedPolicySha256, string extension, string pgMajor)
    {
        if (!Hex64.IsMatch(independentlyAuthenticatedPolicySha256))
            throw new InvalidDataException("An externally authenticated policy SHA256 is mandatory");
        if (!Regex.IsMatch(extension, @"\A[a-z][a-z0-9_]*\z", RegexOptions.CultureInvariant) ||
            !Regex.IsMatch(pgMajor, @"\A[1-9][0-9]*\z", RegexOptions.CultureInvariant))
            throw new InvalidDataException("Invalid extension or PostgreSQL major");

        var policyBytes = BoundedRead(policyFile);
        if (StrictJson.Sha256(policyBytes) != independentlyAuthenticatedPolicySha256)
            throw new InvalidDataException("P1 policy differs from separately supplied SHA256");
        using var policyDoc = StrictJson.Parse(policyBytes);
        var policy = policyDoc.RootElement;
        if (policy.GetProperty("schemaVersion").GetString() != "pgextwin-p1-readonly-policy/v1" ||
            !Hex40.IsMatch(policy.GetProperty("catalogCommitSha").GetString() ?? "") ||
            policy.GetProperty("signerRepositoryId").GetInt64() != 1405931353 ||
            !Hex64.IsMatch(policy.GetProperty("rootSha256").GetString() ?? ""))
            throw new InvalidDataException("Incomplete/unexpected P1 policy");

        // Check EVERY Catalog raw byte digest, not just the selected row. No mutable HEAD fetch.
        var root = Path.GetFullPath(catalogDirectory);
        var indexBytes = BoundedRead(Path.Combine(root, "index.json"));
        var hashes = policy.GetProperty("catalogDigests");
        RequireSha(hashes, "index.json", indexBytes);
        var entries = CatalogReader.LoadLocal(root);
        if (hashes.EnumerateObject().Count() != entries.Count + 1)
            throw new InvalidDataException("Unexpected P1 Catalog digest inventory");
        foreach (var entry in entries)
        {
            var name = "extensions/" + entry.Name + ".json";
            RequireSha(hashes, name, BoundedRead(Path.Combine(root, "extensions", entry.Name + ".json")));
        }
        if (!entries.Any(x => x.Name == extension))
            throw new InvalidDataException("Unknown extension");
        if (!policy.GetProperty("approvedMajors").EnumerateArray()
                .Any(v => v.ValueKind == JsonValueKind.Number && v.GetInt32().ToString() == pgMajor) ||
            !policy.GetProperty("pgEol").TryGetProperty(pgMajor, out _))
            throw new InvalidDataException("PG major not externally approved");

        // Confirm P1 numeric identity inventories have exactly the Catalog extensions.
        foreach (var key in new[] { "repoIds", "releaseIds", "assetIds" })
        {
            var block = policy.GetProperty(key);
            if (block.EnumerateObject().Count() != entries.Count ||
                entries.Any(x => !block.TryGetProperty(x.Name, out _)))
                throw new InvalidDataException("Incomplete P1 " + key);
        }
        var recordBytes = BoundedRead(Path.Combine(root, "extensions", extension + ".json"));
        using var recordDoc = StrictJson.Parse(recordBytes);
        var rec = recordDoc.RootElement;
        var info = rec.GetProperty("postgresql").GetProperty(pgMajor);
        if (info.GetProperty("available").ValueKind != JsonValueKind.True)
            throw new InvalidDataException("Unavailable PostgreSQL package");
        var nameValue = info.GetProperty("asset").GetString() ?? "";
        if (!SafeAssetName(nameValue) || !nameValue.EndsWith("-pg" + pgMajor + "-windows-x64.zip",
                StringComparison.Ordinal) || !nameValue.StartsWith(extension + "-", StringComparison.Ordinal))
            throw new InvalidDataException("Unexpected original ZIP asset name");
        var hash = info.GetProperty("sha256").GetString() ?? "";
        if (!Hex64.IsMatch(hash)) throw new InvalidDataException("Invalid Catalog asset digest");
        var tag = rec.GetProperty("latest").GetProperty("releaseTag").GetString() ?? "";
        if (!SafeAssetName(tag)) throw new InvalidDataException("Unsafe Release tag");
        var ids = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (var element in policy.GetProperty("assetIds").GetProperty(extension).EnumerateObject())
        {
            if (!SafeAssetName(element.Name) || !element.Value.TryGetInt64(out var number) || number <= 0 ||
                !ids.TryAdd(element.Name, number))
                throw new InvalidDataException("Invalid/duplicate P1 asset identity");
        }
        if (!ids.ContainsKey(nameValue) || !ids.ContainsKey("SHA256SUMS.txt") ||
            ids.Values.Distinct().Count() != ids.Count)
            throw new InvalidDataException("Missing/substituted P1 asset IDs");
        var repoId = policy.GetProperty("repoIds").GetProperty(extension).GetInt64();
        var releaseId = policy.GetProperty("releaseIds").GetProperty(extension).GetInt64();
        if (repoId <= 0 || releaseId <= 0) throw new InvalidDataException("Invalid P1 identity");
        return new ReleasePins(extension, pgMajor, tag, nameValue, hash, repoId, releaseId,
            ids, policy.GetProperty("catalogCommitSha").GetString()!);
    }

    private static void RequireSha(JsonElement digests, string name, byte[] bytes)
    {
        var expected = digests.GetProperty(name).GetString() ?? "";
        if (!Hex64.IsMatch(expected) || StrictJson.Sha256(bytes) != expected)
            throw new InvalidDataException("Catalog raw digest mismatch: " + name);
    }

    private static byte[] BoundedRead(string path)
    {
        var info = new FileInfo(path);
        if (!info.Exists || (info.Attributes & FileAttributes.ReparsePoint) != 0 ||
            info.Length > 2 * 1024 * 1024 || info.Length == 0)
            throw new InvalidDataException("Missing, linked or oversized policy/Catalog file");
        return File.ReadAllBytes(info.FullName);
    }

    public static bool SafeAssetName(string name) =>
        name.Length is > 0 and <= 160 &&
        Regex.IsMatch(name, @"\A[A-Za-z0-9][A-Za-z0-9._-]*\z", RegexOptions.CultureInvariant) &&
        !name.EndsWith(".", StringComparison.Ordinal) &&
        !name.Equals(".", StringComparison.Ordinal) && !name.Equals("..", StringComparison.Ordinal) &&
        !new[] { "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5",
                 "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4",
                 "LPT5", "LPT6", "LPT7", "LPT8", "LPT9" }
          .Contains(name.Split('.')[0], StringComparer.OrdinalIgnoreCase);
}
