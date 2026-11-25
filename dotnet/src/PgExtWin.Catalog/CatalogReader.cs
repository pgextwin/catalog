using System.Text.Json;
using System.Text.RegularExpressions;
using PgExtWin.Core;

namespace PgExtWin.Catalog;

public sealed record PgVersion(string Major, string Version, string Asset);
public sealed record CatalogEntry(string Name, string DisplayName, string Description,
    string ReleaseTag, string Preload, IReadOnlyList<PgVersion> Versions);

/// <summary>
/// Untrusted LOCAL Catalog metadata reader (identities+ledger and legacy v2 snapshots).
/// Not an independent verifier. Authenticating Catalog commit/digests and published
/// assets belongs to existing P1.
/// </summary>
public static class CatalogReader
{
    private static readonly Regex SafeName = new(@"\A[a-z][a-z0-9_]*\z", RegexOptions.CultureInvariant);
    private static readonly Regex SafeMajor = new(@"\A[1-9][0-9]*\z", RegexOptions.CultureInvariant);

    public static IReadOnlyList<CatalogEntry> LoadLocal(string directory)
    {
        var full = Path.GetFullPath(directory);
        using var index = Read(Path.Combine(full, "index.json"));
        var root = index.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("Invalid Catalog index");
        var version = Int(root, "schemaVersion");
        if (version == 3)
            return LoadIdentitiesAndLedgers(full, root);
        if (version == 2)
            return LoadLegacyV2(full, root);
        throw new InvalidDataException("Unsupported Catalog schemaVersion");
    }

    private static IReadOnlyList<CatalogEntry> LoadIdentitiesAndLedgers(string full, JsonElement root)
    {
        if (String(root, "identitiesDir") != "identities" || String(root, "packagesDir") != "packages")
            throw new InvalidDataException("Invalid Catalog v3 directories");
        var ordered = ParseOrderedExtensions(root);
        ValidateV3Identities(root, ordered);
        var pkgPath = Path.Combine(full, "packages");
        if (!Directory.Exists(pkgPath))
            throw new InvalidDataException("Catalog packages directory missing");
        var actual = Directory.EnumerateFiles(pkgPath, "*.json", SearchOption.TopDirectoryOnly)
            .Select(Path.GetFileNameWithoutExtension).Order(StringComparer.Ordinal).ToArray();
        if (!actual.SequenceEqual(ordered))
            throw new InvalidDataException("Catalog file inventory mismatch");

        var entries = new List<CatalogEntry>();
        foreach (var name in ordered)
        {
            using var record = Read(Path.Combine(pkgPath, name + ".json"));
            var r = record.RootElement;
            if (r.ValueKind != JsonValueKind.Object ||
                Int(r, "schemaVersion") != 1 || String(r, "name") != name ||
                String(r, "repository") != "pgextwin/" + name ||
                String(r, "architecture") != "x64")
                throw new InvalidDataException("Catalog record identity mismatch: " + name);

            var latest = SelectLatestRelease(r, name);
            var unavailable = ParseUnavailableMajors(r, name);
            var upstream = r.GetProperty("upstream");
            if (upstream.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("Missing upstream metadata: " + name);
            var perPostgresql = false;
            if (upstream.TryGetProperty("versionScheme", out var scheme))
            {
                if (scheme.ValueKind != JsonValueKind.String || scheme.GetString() != "perPostgresql")
                    throw new InvalidDataException("Invalid upstream versionScheme: " + name);
                perPostgresql = true;
            }

            var packages = latest.GetProperty("packages");
            if (packages.ValueKind != JsonValueKind.Array || packages.GetArrayLength() == 0)
                throw new InvalidDataException("Missing latest release packages: " + name);
            var versions = new List<PgVersion>();
            var seenMajors = new HashSet<string>(StringComparer.Ordinal);
            string? sharedVersion = null;
            foreach (var pkg in packages.EnumerateArray())
            {
                if (pkg.ValueKind != JsonValueKind.Object)
                    throw new InvalidDataException("Invalid package entry: " + name);
                var major = String(pkg, "pgMajor");
                if (!SafeMajor.IsMatch(major))
                    throw new InvalidDataException("Invalid PostgreSQL major");
                if (unavailable.Contains(major) || !seenMajors.Add(major))
                    throw new InvalidDataException("Conflicting or duplicate Catalog package availability");
                var version = String(pkg, "version");
                var asset = String(pkg, "asset");
                _ = String(pkg, "sha256");
                if (!perPostgresql)
                {
                    if (sharedVersion is null) sharedVersion = version;
                    else if (sharedVersion != version)
                        throw new InvalidDataException("Shared upstream version differs between latest packages: " + name);
                }
                versions.Add(new PgVersion(major, version, asset));
            }
            versions.Sort((a, b) => long.Parse(a.Major).CompareTo(long.Parse(b.Major)));
            entries.Add(BuildEntry(name, r, String(latest, "releaseTag"), versions));
        }
        return entries;
    }

    private static IReadOnlyList<CatalogEntry> LoadLegacyV2(string full, JsonElement root)
    {
        var extPath = Path.Combine(full, "extensions");
        if (!Directory.Exists(extPath)) throw new InvalidDataException("Catalog extensions directory missing");
        var ordered = ParseOrderedExtensions(root);
        var actual = Directory.EnumerateFiles(extPath, "*.json", SearchOption.TopDirectoryOnly)
            .Select(Path.GetFileNameWithoutExtension).Order(StringComparer.Ordinal).ToArray();
        if (!actual.SequenceEqual(ordered)) throw new InvalidDataException("Catalog file inventory mismatch");
        var entries = new List<CatalogEntry>();
        foreach (var name in ordered)
        {
            using var record = Read(Path.Combine(extPath, name + ".json"));
            var r = record.RootElement;
            if (Int(r, "schemaVersion") != 2 || String(r, "name") != name ||
                String(r, "repository") != "pgextwin/" + name ||
                String(r, "architecture") != "x64")
                throw new InvalidDataException("Catalog record identity mismatch: " + name);
            var latest = r.GetProperty("latest");
            var upstream = r.GetProperty("upstream");
            var postgres = r.GetProperty("postgresql");
            if (postgres.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Missing PG matrix");
            var versions = new List<PgVersion>();
            foreach (var pg in postgres.EnumerateObject())
            {
                if (!SafeMajor.IsMatch(pg.Name))
                    throw new InvalidDataException("Invalid PostgreSQL major");
                var info = pg.Value;
                var available = info.GetProperty("available");
                if (available.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                    throw new InvalidDataException("Invalid available value");
                if (available.ValueKind == JsonValueKind.False) continue;
                var version = upstream.TryGetProperty("perPostgresql", out var perPg)
                    ? String(perPg.GetProperty(pg.Name), "version") : String(upstream, "version");
                versions.Add(new PgVersion(pg.Name, version, String(info, "asset")));
            }
            versions.Sort((a, b) => long.Parse(a.Major).CompareTo(long.Parse(b.Major)));
            entries.Add(BuildEntry(name, r, String(latest, "releaseTag"), versions));
        }
        return entries;
    }

    private static List<string> ParseOrderedExtensions(JsonElement root)
    {
        var names = root.GetProperty("extensions");
        if (names.ValueKind != JsonValueKind.Array) throw new InvalidDataException("Invalid Catalog index");
        var ordered = new List<string>();
        foreach (var n in names.EnumerateArray())
        {
            var name = n.GetString() ?? "";
            if (!SafeName.IsMatch(name))
                throw new InvalidDataException("Unsafe extension name");
            ordered.Add(name);
        }
        if (ordered.Count == 0 || ordered.Count != ordered.Distinct(StringComparer.Ordinal).Count() ||
            !ordered.SequenceEqual(ordered.Order(StringComparer.Ordinal)))
            throw new InvalidDataException("Unsorted or duplicated Catalog index");
        return ordered;
    }

    private static void ValidateV3Identities(JsonElement root, IReadOnlyList<string> ordered)
    {
        var identities = root.GetProperty("identities");
        if (identities.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Invalid Catalog identities index");
        var seenIdentities = new HashSet<string>(StringComparer.Ordinal);
        var distributedIdentities = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in identities.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("Invalid Catalog identity entry");
            var entryName = String(item, "name");
            if (!SafeName.IsMatch(entryName))
                throw new InvalidDataException("Unsafe extension name");
            if (!seenIdentities.Add(entryName))
                throw new InvalidDataException("Duplicated Catalog identity entry");
            if (String(item, "path") != "identities/" + entryName + ".json")
                throw new InvalidDataException("Invalid Catalog identity path: " + entryName);
            var intakeClass = String(item, "intakeClass");
            if (intakeClass == "distributed")
            {
                if (String(item, "ledgerPath") != "packages/" + entryName + ".json")
                    throw new InvalidDataException("Invalid Catalog ledger path: " + entryName);
                distributedIdentities.Add(entryName);
            }
            else if (intakeClass == "research-only")
            {
                if (item.TryGetProperty("ledgerPath", out _))
                    throw new InvalidDataException("Unexpected ledgerPath for research-only identity: " + entryName);
            }
            else
            {
                throw new InvalidDataException("Invalid Catalog intakeClass: " + entryName);
            }
        }
        if (!distributedIdentities.Order(StringComparer.Ordinal).SequenceEqual(ordered))
            throw new InvalidDataException("Catalog identity index roster mismatch");
    }

    private static JsonElement SelectLatestRelease(JsonElement record, string name)
    {
        var latestReleaseId = PositiveLong(record, "latestReleaseId");
        var releases = record.GetProperty("releases");
        if (releases.ValueKind != JsonValueKind.Array || releases.GetArrayLength() == 0)
            throw new InvalidDataException("Missing Catalog releases: " + name);
        JsonElement latest = default;
        var foundLatest = false;
        foreach (var release in releases.EnumerateArray())
        {
            if (release.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("Invalid Catalog release: " + name);
            if (PositiveLong(release, "releaseId") == latestReleaseId)
            {
                if (foundLatest)
                    throw new InvalidDataException("Ledger latestReleaseId must identify exactly one Release: " + name);
                latest = release;
                foundLatest = true;
            }
        }
        if (!foundLatest)
            throw new InvalidDataException("Ledger latestReleaseId must identify exactly one Release: " + name);
        if (latest.TryGetProperty("admission", out _) || latest.TryGetProperty("legacyInventoryCommit", out _))
            throw new InvalidDataException("Latest Release must not carry historical admission: " + name);
        return latest;
    }

    private static HashSet<string> ParseUnavailableMajors(JsonElement record, string name)
    {
        var unavailableMajors = record.GetProperty("unavailableMajors");
        if (unavailableMajors.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Invalid unavailableMajors: " + name);
        var unavailable = new HashSet<string>(StringComparer.Ordinal);
        foreach (var m in unavailableMajors.EnumerateArray())
        {
            var major = m.ValueKind == JsonValueKind.String ? m.GetString() ?? "" : "";
            if (!SafeMajor.IsMatch(major) || !unavailable.Add(major))
                throw new InvalidDataException("Invalid PostgreSQL major");
        }
        return unavailable;
    }

    private static CatalogEntry BuildEntry(string name, JsonElement r, string releaseTag, List<PgVersion> versions)
    {
        var preload = r.TryGetProperty("runtime", out var runtime) &&
            runtime.TryGetProperty("requirements", out var req) &&
            req.TryGetProperty("preload", out var p) ? p.GetString() ?? "unknown" : "unknown";
        return new CatalogEntry(name,
            r.TryGetProperty("displayName", out var display) ? display.GetString() ?? name : name,
            r.TryGetProperty("description", out var desc) ? desc.GetString() ?? "" : "",
            releaseTag, preload, versions);
    }

    private static JsonDocument Read(string path)
    {
        if (!File.Exists(path)) throw new InvalidDataException("Missing Catalog file: " + Path.GetFileName(path));
        var fi = new FileInfo(path);
        if ((fi.Attributes & FileAttributes.ReparsePoint) != 0 || fi.Length > 2_000_000)
            throw new InvalidDataException("Catalog file is a link or oversized");
        return StrictJson.Parse(File.ReadAllBytes(path));
    }

    private static string String(JsonElement obj, string key)
    {
        var value = obj.GetProperty(key);
        if (value.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(value.GetString()))
            throw new InvalidDataException("Invalid Catalog field: " + key);
        return value.GetString()!;
    }

    private static int Int(JsonElement obj, string key)
    {
        var value = obj.GetProperty(key);
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var number))
            throw new InvalidDataException("Invalid Catalog field: " + key);
        return number;
    }

    private static long PositiveLong(JsonElement obj, string key)
    {
        var value = obj.GetProperty(key);
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out var number) || number <= 0)
            throw new InvalidDataException("Invalid Catalog field: " + key);
        return number;
    }
}
