using System.Text.Json;
using System.Text.RegularExpressions;
using PgExtWin.Core;

namespace PgExtWin.Catalog;

public sealed record PgVersion(string Major, string Version, string Asset);
public sealed record CatalogEntry(string Name, string DisplayName, string Description,
    string ReleaseTag, string Preload, IReadOnlyList<PgVersion> Versions);

/// <summary>
/// Untrusted LOCAL Catalog v2 metadata reader. Not an independent verifier.
/// Authenticating Catalog commit/digests and published assets belongs to existing P1.
/// </summary>
public static class CatalogReader
{
    public static IReadOnlyList<CatalogEntry> LoadLocal(string directory)
    {
        var full = Path.GetFullPath(directory);
        var extPath = Path.Combine(full, "extensions");
        if (!Directory.Exists(extPath)) throw new InvalidDataException("Catalog extensions directory missing");
        using var index = Read(Path.Combine(full, "index.json"));
        var root = index.RootElement;
        if (Int(root, "schemaVersion") != 2) throw new InvalidDataException("Catalog v2 required");
        var names = root.GetProperty("extensions");
        if (names.ValueKind != JsonValueKind.Array) throw new InvalidDataException("Invalid Catalog index");
        var ordered = new List<string>();
        foreach (var n in names.EnumerateArray())
        {
            var name = n.GetString() ?? "";
            if (!Regex.IsMatch(name, @"\A[a-z][a-z0-9_]*\z", RegexOptions.CultureInvariant))
                throw new InvalidDataException("Unsafe extension name");
            ordered.Add(name);
        }
        if (ordered.Count == 0 || ordered.Count != ordered.Distinct(StringComparer.Ordinal).Count() ||
            !ordered.SequenceEqual(ordered.Order(StringComparer.Ordinal)))
            throw new InvalidDataException("Unsorted or duplicated Catalog index");
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
                if (!Regex.IsMatch(pg.Name, @"\A[1-9][0-9]*\z"))
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
            var preload = r.TryGetProperty("runtime", out var runtime) &&
                runtime.TryGetProperty("requirements", out var req) &&
                req.TryGetProperty("preload", out var p) ? p.GetString() ?? "unknown" : "unknown";
            entries.Add(new CatalogEntry(name,
                r.TryGetProperty("displayName", out var display) ? display.GetString() ?? name : name,
                r.TryGetProperty("description", out var desc) ? desc.GetString() ?? "" : "",
                String(latest, "releaseTag"), preload, versions));
        }
        return entries;
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
}
